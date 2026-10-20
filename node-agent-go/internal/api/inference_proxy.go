// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package api — inference proxy.
//
// Exposes a generic OpenAI-compatible surface on the node-agent's mTLS
// port (8081) that transparently forwards to a locally-running backend
// (vllm / llamacpp / ollama) on this node's docker network. This lets
// the gateway address inference by NODE without knowing which backend
// the node runs or what port it uses, and without requiring the backend
// container to expose any host ports.
//
// Routing rules (executed in order):
//  1. If request carries `X-Noo-Backend: <type>` header AND that backend
//     is running locally → use it. (Gateway hint when a node has multiple.)
//  2. Else if any local backend's running model matches the `model` field
//     of the request body → use that backend. (Model-aware fallback.)
//  3. Else → first available local backend (vllm > llamacpp > ollama
//     priority). (Generic fallback for embeddings/etc that don't pin model.)
//  4. Else → 503 with a clear error.
//
// Streaming is preserved via httputil.ReverseProxy with FlushInterval=0.
//
// Security: all routes are wrapped in the existing mTLS auth middleware.
// The gateway's client cert is the only credential that can reach these
// endpoints from outside the node's docker network.

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
	"github.com/noomesh/noomesh/node-agent-go/internal/harnessprofile"
)

// Per-backend TLS env-var names. When set to a truthy value, node-agent
// proxies via HTTPS instead of HTTP and verifies the upstream cert
// against the cluster CA at /app/pki/ca.crt. Mirrors the existing
// NOO_VLLM_TLS used by the vllm container's startup script — pass the
// same env to the node-agent container so both sides agree.
// Per-backend TLS env flags now live in dockerpkg.SchemeFor (single
// source of truth shared with the jobs executor).

// containerCAPath is the cluster CA inside a CONTAINERISED node-agent
// (mounted ro from the host's NOO_PKI_DIR, docker-compose.cluster.yml). It
// is only the fallback: the CA the agent verifies its backend doors with is
// the one its config names (NOO_TLS_CA — /etc/noo/pki/ca.crt on a host
// install), the same file config.HTTPTransport trusts for the controller.
// Until 2026-09-29 this path was the ONLY one read, so a host-installed
// agent (every node since the host cutover) had no cluster CA for the
// inference proxy, fell back to system roots and would have refused every
// https door — vLLM's --ssl-cert-reqs 2 listener first (host3,
// noo-cli-v0.5.63/64: "cluster CA not loadable … ca_path /app/pki/ca.crt").
const containerCAPath = "/app/pki/ca.crt"

// backendScheme returns the scheme an agent-started backend's door serves
// (https for every fronted backend; the NOO_<TYPE>_TLS flags switch nothing
// any more — a false value refuses the agent's start). Delegates to the
// docker package, the single source of truth shared with the jobs executor.
func backendScheme(backendType string) string {
	return dockerpkg.SchemeFor(backendType)
}

// clusterCAPath is the CA file the inference proxy verifies backend doors
// against: the agent config's NOO_TLS_CA when set, else the container mount.
func clusterCAPath(cfg *config.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.TLSCA) != "" {
		return cfg.TLSCA
	}
	return containerCAPath
}

var caPools sync.Map // path -> *x509.CertPool (nil entries are not stored)

// clusterCAPool loads (once per path) the cluster CA. Nil if unreadable —
// the caller then leaves RootCAs nil, i.e. system roots, so a cluster-CA
// door FAILS verification rather than being trusted (fail-closed, H-S3).
func clusterCAPool(cfg *config.Config) (*x509.CertPool, string) {
	path := clusterCAPath(cfg)
	if v, ok := caPools.Load(path); ok {
		return v.(*x509.CertPool), path
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, path
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, path
	}
	caPools.Store(path, pool)
	return pool, path
}

// httpsTransport returns an http.Transport configured to verify the
// upstream backend's cert against the cluster CA. Used when proxying
// to a TLS-enabled backend (e.g. vllm with NOO_VLLM_TLS=true).
var caMissingWarn sync.Once

// BackendDialContext, when non-nil, replaces the dialer in every transport
// this file builds. Set once at startup by agent bootstrap via
// containerdial.Install: as a HOST process the docker-DNS backend names
// ("noo-reranker") resolve nowhere, so the dialer swaps them for container
// bridge IPs at socket level — URLs, Host headers, SNI and cluster-CA
// verification all stay exactly as they are. Inside a container it stays
// nil and nothing here changes.
var BackendDialContext func(ctx context.Context, network, addr string) (net.Conn, error)

func withBackendDial(t *http.Transport) *http.Transport {
	if BackendDialContext != nil {
		t.DialContext = BackendDialContext
	}
	return t
}

func httpsTransport(cfg *config.Config) *http.Transport {
	return httpsTransportWithFirstByte(cfg, backendFirstByteTimeout())
}

// httpsTransportWithFirstByte is httpsTransport with the response-header
// bound named by the caller (the proxy reads it once per request, so its
// error log names the bound that request actually had).
func httpsTransportWithFirstByte(cfg *config.Config, firstByte time.Duration) *http.Transport {
	pool, caPath := clusterCAPool(cfg)
	if pool == nil {
		caMissingWarn.Do(func() {
			slog.Error("cluster CA not loadable — TLS backend verification falls "+
				"back to system roots; cluster-CA backends will be REFUSED rather "+
				"than trusted insecurely (fail-closed, H-S3)", "ca_path", caPath)
		})
	}
	tlsConfig := &tls.Config{
		// Cluster CA verifies the backend's cert (H-S3). FAIL CLOSED: never
		// skip verification. If the CA wasn't loadable, RootCAs is nil → Go
		// verifies against the system roots, so a cluster-CA backend fails to
		// verify (connection refused) rather than being silently accepted over
		// an unverified / MITM-able channel. The docker network is NOT a trust
		// boundary on a shared/multi-tenant host.
		RootCAs:            pool,
		InsecureSkipVerify: false,
	}
	// Present the node leaf. The controller's compose vLLM
	// (--ssl-cert-reqs 2) and the llama.cpp sidecar (verify = 2) refuse a
	// caller without a cluster-CA client certificate; a backend that asks
	// for none ignores it. A configured-but-unloadable pair is logged and
	// the dial proceeds bare — the listener's refusal is then the visible
	// symptom, not a silent fallback to plaintext.
	if cfg != nil && cfg.TLSCert != "" && cfg.TLSKey != "" {
		if cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey); err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		} else {
			slog.Error("inference proxy: node leaf configured but not loadable — dialling TLS backends WITHOUT a client certificate; a listener that requires one will refuse",
				"cert", cfg.TLSCert, "key", cfg.TLSKey, "error", err)
		}
	}
	return withBackendDial(&http.Transport{
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: firstByte,
		TLSClientConfig:       tlsConfig,
	})
}

// Body filtering: allowlist-based.
//
// Old approach was a hardcoded "vllm-only keys" blacklist — fragile
// because it had to be updated every time vLLM added a new vendor
// extension, and treated llamacpp/ollama as if their union with
// portable keys was the right surface (it isn't — they have their
// own extensions too).
//
// New approach: define the OpenAI-portable key set + per-backend
// vendor extensions. When forwarding to a known backend, allow only
// the union (portable ∪ backend's extras). Unknown keys silently
// dropped — safer default than relying on each backend's strictness.
// Unknown backend type (future addition) → pass through unchanged
// so adding a backend doesn't break before its allowlist is added.

// portableOpenAIKeys: defined by the OpenAI API spec, supported by
// every OpenAI-compatible backend (vLLM, Ollama, llama.cpp, etc.).
// Spans /v1/chat/completions, /v1/completions, /v1/embeddings.
var portableOpenAIKeys = map[string]bool{
	// /v1/chat/completions core
	"model":                 true,
	"messages":              true,
	"temperature":           true,
	"top_p":                 true,
	"n":                     true,
	"stream":                true,
	"stream_options":        true, // include_usage: the harness translator meters streams by it (i147)
	"stop":                  true,
	"max_tokens":            true,
	"max_completion_tokens": true,
	"presence_penalty":      true,
	"frequency_penalty":     true,
	"logit_bias":            true,
	"user":                  true,
	"seed":                  true,
	"tools":                 true,
	"tool_choice":           true,
	"response_format":       true,
	"logprobs":              true,
	"top_logprobs":          true,
	// /v1/completions
	"prompt":  true,
	"suffix":  true,
	"echo":    true,
	"best_of": true,
	// /v1/embeddings
	"input":           true,
	"encoding_format": true,
	"dimensions":      true,
}

// backendExtraKeys: vendor extensions accepted IN ADDITION to the
// portable set. Keys here are passed through to the backend; keys
// outside (portable ∪ extras) are stripped before forwarding.
//
// Adding a new backend type means adding an entry here. Until the
// entry exists, requests pass through unchanged (filterBodyForBackend
// returns the body unmodified for unknown backend types).
var backendExtraKeys = map[string]map[string]bool{
	"vllm": {
		"chat_template_kwargs":    true,
		"guided_choice":           true,
		"guided_grammar":          true,
		"guided_json":             true,
		"guided_regex":            true,
		"guided_decoding_backend": true,
		"min_p":                   true,
		"use_beam_search":         true,
		"top_k":                   true,
		"repetition_penalty":      true,
		"min_tokens":              true,
		"skip_special_tokens":     true,
	},
	"ollama": {
		"format":     true, // ollama's JSON mode
		"keep_alive": true, // model-unload control
		"options":    true, // nested option dict (top_k, top_p, etc.)
		"raw":        true,
	},
	"llamacpp": {
		"n_predict":      true, // alias for max_tokens
		"min_p":          true,
		"top_k":          true,
		"min_keep":       true,
		"tfs_z":          true,
		"typical_p":      true,
		"repeat_penalty": true,
		"mirostat":       true,
		"mirostat_tau":   true,
		"mirostat_eta":   true,
		"grammar":        true,
		"cache_prompt":   true,
	},
}

// jsonError writes an OpenAI-shape error response so strict OpenAI
// clients (LangChain, LlamaIndex, etc.) can parse it.
func jsonError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "node_agent_proxy_error",
			"code":    code,
		},
	})
}

// filterBodyForBackend returns a body with only keys allowed for the
// target backend. Keeps portable OpenAI keys + the backend's vendor
// extras, drops everything else.
//
// Returns body unchanged if:
//   - body isn't valid JSON (forwarder will surface underlying 4xx)
//   - backend type isn't in backendExtraKeys (unknown / new backend —
//     pass through; safer than over-stripping for unknown configurations)
func filterBodyForBackend(body []byte, backendType string) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	extras, known := backendExtraKeys[backendType]
	if !known {
		return body
	}
	changed := false
	for k := range obj {
		if portableOpenAIKeys[k] || extras[k] {
			continue
		}
		delete(obj, k)
		changed = true
	}
	if !changed {
		return body
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// Preferred order when no backend hint + no model match — vllm wins
// because it's the fastest LLM server when present.
var inferenceBackendPreference = []string{"vllm", "llamacpp", "ollama"}

// pickInferenceBackend returns (backend_type, port) for the local backend
// best suited to handle this request, or ("", 0) if none available.
//
// `bodyHint` may be nil (non-JSON or unread); only the model field is
// inspected. `headerHint` is the value of X-Noo-Backend (may be "").
func pickInferenceBackend(
	running map[string]string,
	headerHint string,
	bodyHint []byte,
) (string, int) {
	// 1. Honour explicit gateway hint if the backend is actually here.
	if headerHint != "" {
		if _, ok := running[headerHint]; ok {
			if port, ok2 := dockerpkg.BackendPorts[headerHint]; ok2 {
				return headerHint, port
			}
		}
		// Hint missed (gateway thought we had it, we don't) — fall through
		// to model match rather than refusing. Common cause: node-agent
		// just stopped a backend and the gateway's KV view is stale.
	}

	// 2. Body model match — pick the backend whose loaded model name equals
	// the request's `model` field exactly.
	if len(bodyHint) > 0 {
		var probe struct {
			Model string `json:"model"`
		}
		if err := json.Unmarshal(bodyHint, &probe); err == nil && probe.Model != "" {
			for bt, m := range running {
				if m == probe.Model {
					if port, ok := dockerpkg.BackendPorts[bt]; ok {
						return bt, port
					}
				}
			}
		}
	}

	// 3. First-available fallback in preferred order.
	for _, bt := range inferenceBackendPreference {
		if _, ok := running[bt]; ok {
			if port, ok2 := dockerpkg.BackendPorts[bt]; ok2 {
				return bt, port
			}
		}
	}
	return "", 0
}

// handleInferenceProxy reverse-proxies an OpenAI-compat request to the
// chosen local backend. Streaming responses are passed through unchanged.
func (s *Server) handleInferenceProxy(w http.ResponseWriter, r *http.Request) {
	// Read body once so we can both peek (for model hint) and forward.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "read_body_failed", err.Error())
		return
	}
	_ = r.Body.Close()

	headerHint := r.Header.Get("X-Noo-Backend")
	running := s.docker.RunningBackends()
	// Backends served natively on this host (darwin/Metal) are reachable and
	// must be selectable. Docker's map wins a key collision: if something is
	// genuinely running in a container under that name, that is what the
	// reconciler manages and what the spec hash describes.
	native := s.nativeBackends()
	for b, m := range native {
		if _, taken := running[b]; !taken {
			running[b] = m
		}
	}

	backendType, port := pickInferenceBackend(running, headerHint, body)
	if backendType == "" {
		jsonError(w, http.StatusServiceUnavailable, "no_local_backend",
			fmt.Sprintf("no local backend available for this request (running=%v, hint=%q)",
				running, headerHint))
		return
	}

	// A caller that does not name a model, or names `auto`, gets the model
	// the picked backend actually serves (the harness
	// is placed as `auto` and follows this node's chat placement). The
	// backends validate `model` against what they loaded — vLLM 404s on
	// a name it does not serve — so `auto` must become the real name
	// here, where the pick was made, rather than at the backend as an
	// error. A named model that does not match is left alone: the
	// backend's refusal is the honest answer for that.
	body = substituteAutoModel(body, running[backendType])
	// Filter body to only keys the target backend accepts (portable
	// OpenAI keys + this backend's vendor extras). Catches vendor-key
	// mismatches across backends without hardcoding "vllm vs others".
	body = filterBodyForBackend(body, backendType)

	targetURL, scheme := s.inferenceTarget(backendType, port, native)
	target, err := url.Parse(targetURL)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "bad_backend_url", err.Error())
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	// Disable buffering so SSE / streaming responses pass through with
	// per-token latency intact.
	proxy.FlushInterval = -1
	// Bound first-byte wait per request — a hung backend used to pin the
	// connection forever. ResponseHeaderTimeout fires before the upstream
	// even starts sending; idle keepalives use IdleConnTimeout. Pool size
	// keeps connection reuse to the local backend efficient. The bound is
	// backendFirstByteTimeout, not 60 s: see its comment.
	// The proxy (and so its transport) is built per request: keep-alive
	// would only park the connection until IdleConnTimeout, never reuse it.
	//
	// Built per request is also what makes the bound LIVE: the harness
	// profile's first_byte_secs (desired-config) changes what
	// backendFirstByteTimeout answers, and the next request's transport is
	// built with the new value. No agent restart, no transport to rebuild;
	// a request already in flight keeps the bound it started with.
	firstByte := backendFirstByteTimeout()
	proxy.Transport = s.inferenceTransport(scheme, firstByte)
	// Surface upstream errors as OpenAI-shape JSON instead of the default
	// plain text "Bad Gateway".
	//
	// And LOG it. The caller gets `backend_unreachable`, the gateway records
	// it in its audit table and nothing lands in either process's log, so a
	// first-byte timeout — the failure most likely to be a slow backend
	// rather than a dead one — was diagnosable only by noticing that the
	// request took exactly backendFirstByteTimeout. Name the bound in the
	// line so the next reader does not have to.
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, err error) {
		slog.Warn("inference proxy could not complete the upstream request",
			"backend", backendType, "target", targetURL, "error", err,
			"first_byte_timeout_seconds", int(firstByte.Seconds()))
		jsonError(rw, http.StatusBadGateway, "backend_unreachable", err.Error())
	}

	// Restore the body we consumed for hint detection (now possibly
	// vllm-key-stripped).
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("X-Forwarded-By", "noo-node-agent-inference-proxy")
	// Strip the hint header before forwarding — backends would reject it.
	r.Header.Del("X-Noo-Backend")

	// Backend's host should be the docker DNS name, not whatever client sent.
	r.Host = target.Host

	proxy.ServeHTTP(w, r)
}

// inferenceTarget is where the proxy dials a local backend and with which
// transport scheme. The bench (POST /bench) dials the chat backend through
// this same resolution, so it measures the path a real request takes.
func (s *Server) inferenceTarget(backendType string, port int, native map[string]string) (targetURL, scheme string) {
	// Where to dial. A NATIVE backend is on loopback, not on the docker
	// network — `noo-ollama` does not resolve on a Mac, and this hardcoded
	// name is the one line that stood between a running native ollama and a
	// working request.
	//
	// Loopback deliberately: the backend is never exposed on the LAN, and the
	// gateway already addresses a placement by the AGENT's URL, so every
	// caller reaches it through this authenticated proxy.
	// The running containers' own declaration wins over this agent's env
	// flag (dockerpkg.BackendDialURL): the controller's compose vLLM
	// requires TLS + a client certificate whatever NOO_VLLM_TLS says here,
	// and its llama.cpp is dialled at the stunnel sidecar when that runs.
	targetURL = fmt.Sprintf("%s://noo-%s:%d", backendScheme(backendType), backendType, port)
	if s.docker != nil {
		targetURL = s.docker.BackendDialURL(backendType)
	}
	scheme = "http"
	if strings.HasPrefix(targetURL, "https://") {
		scheme = "https"
	}
	if _, isNative := native[backendType]; isNative {
		if base, ok := s.native.Endpoint(backendType); ok {
			// The scheme follows the URL we actually dial. A native ollama
			// on loopback is plaintext (http, bare transport); the
			// controller's self-node lane is its stunnel-ollama-embed door
			// (https://127.0.0.1:11434, verify = 2), which httpsTransport
			// dials with the node leaf. This line used to force "http" for
			// every native endpoint, so an https lane would have been
			// dialled with a transport that presents nothing.
			targetURL, scheme = base, nativeDialScheme(base)
		}
	}
	return targetURL, scheme
}

// inferenceTransport is the per-request transport to a local backend:
// the node-leaf mTLS transport for https, the bridge dialer otherwise, both
// one-shot and both bounded by firstByte for the response headers.
func (s *Server) inferenceTransport(scheme string, firstByte time.Duration) *http.Transport {
	if scheme == "https" {
		return oneShot(httpsTransportWithFirstByte(s.cfg, firstByte))
	}
	return oneShot(withBackendDial(&http.Transport{
		ResponseHeaderTimeout: firstByte,
	}))
}

// nativeDialScheme is the transport choice for an adopted lane's endpoint:
// "https" (httpsTransport, the node leaf presented) for the self-node's
// mTLS door, "http" (a bare transport) for a plaintext loopback ollama.
func nativeDialScheme(base string) string {
	if strings.HasPrefix(strings.ToLower(base), "https://") {
		return "https"
	}
	return "http"
}

// ─────────────────────────── rerank proxy ───────────────────────────
//
// The GATEWAY-facing rerank contract is fixed to the TEI shape:
//
//	POST /rerank {query, texts, ...}  →  [{index, score}, ...]  (score desc)
//
// but the LOCAL reranker container may speak one of two engines:
//
//   - TEI cross-encoder:  POST :80/rerank  {query, texts}      → [{index, score}]
//   - llama.cpp llama-server --reranking (hardened image, RERANK_ENGINE
//     default): POST :8085/v1/rerank {query, documents, model} →
//     {results: [{index, relevance_score}]}
//
// The proxy translates request+response so gateway/UI/CLI callers never see
// the difference. Engine detection keys on the PORT the candidate answers on
// (the backend specs pin TEI to :80 and llama.cpp to :8085 inside the
// container network), tried in order with a short-lived cache — NOT on a
// static env var, because the node-agent restarts/deploys independently of
// the reranker container: during the TEI→llamacpp flip the container can be
// either engine, and request-time detection keeps the contract stable with
// zero coordination. NOO_LOCAL_RERANK_URL still overrides the base URL
// (engine then via NOO_LOCAL_RERANK_ENGINE, or both shapes are attempted).

// rerankTarget is one candidate local reranker endpoint.
type rerankTarget struct {
	base   string // e.g. "http://noo-reranker:8085"
	engine string // "llamacpp" or "tei"
}

var (
	rerankTargetMu     sync.Mutex
	rerankTargetCached *rerankTarget
	rerankTargetAt     time.Time
)

const rerankTargetTTL = 60 * time.Second

// defaultBackendFirstByteTimeout bounds how long the proxy waits for a
// backend's response headers. It was 60 s, and a backend's COLD LOAD is the
// first legitimate case that exceeds it: the first request after a placement
// makes ollama page a 7.6 GB gemma4:12b into VRAM, which took over a
// minute on host3 (RTX 3080 laptop, WSL) — the proxy closed the
// connection, ollama logged "client connection closed before llama-server
// finished loading, aborting load", and every retry started the load over
// (2026-09-11). The gateway allows 300 s per backend call; the proxy sits
// inside that, so it waits up to 290 s and the gateway still decides.
//
// The second legitimate case is why this is now tunable. On a NON-STREAMING
// completion the upstream sends no headers until the whole answer is
// generated, so ResponseHeaderTimeout bounds the ENTIRE generation, not a
// first byte. A CPU-only box running a 12B model blows through 290 s on a
// long prompt and the caller sees
//
//	502 {"code":"backend_unreachable","message":"... timeout awaiting response headers"}
//
// which reads like a dead backend rather than a slow one (host7,
// 2026-09-12: persona generation). Raise it with
// NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS, and raise the gateway's
// NOO_BACKEND_TIMEOUT_SECS (default 300 s) ABOVE it in the same breath —
// the gateway's own client timeout is the outer bound, so lifting only this
// one just moves the failure to the other end of the wire.
const defaultBackendFirstByteTimeout = 290 * time.Second

// backendFirstByteTimeoutEnv is read once, on first use — NOT in a package
// initialiser. A package-level read ran before main(), so even
// `noo-node-agent --version` touched the environment (and could log);
// the version/help fast path must read nothing.
const backendFirstByteTimeoutEnv = "NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS"

// backendFirstByteEnvOverride is the env override, read (and logged) once.
var backendFirstByteEnvOverride = sync.OnceValues(func() (time.Duration, bool) {
	return parseFirstByteOverride(os.Getenv(backendFirstByteTimeoutEnv))
})

// backendFirstByteTimeout is the bound in force NOW, evaluated on every
// call (every proxied request builds its transport with it):
//
//	NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS  the operator's override on this box
//	> harness profile first_byte_secs    desired-config, changes live
//	> 290 s                              defaultBackendFirstByteTimeout
//
// The env wins because it is the one value set ON the box: an operator who
// set it there meant this box, whatever the controller resolves.
func backendFirstByteTimeout() time.Duration {
	d, set := backendFirstByteEnvOverride()
	return firstByteTimeoutFor(d, set, harnessprofile.Current())
}

// firstByteTimeoutFor is the pure precedence behind backendFirstByteTimeout.
func firstByteTimeoutFor(envD time.Duration, envSet bool, prof *harnessprofile.Profile) time.Duration {
	if envSet && envD > 0 {
		return envD
	}
	if prof != nil && prof.FirstByteSecs > 0 {
		return time.Duration(prof.FirstByteSecs) * time.Second
	}
	return defaultBackendFirstByteTimeout
}

// parseFirstByteOverride parses the env override: ("", false) when unset.
// Anything unparseable or non-positive is NOT an override (logged): an
// operator typo must not turn a hung backend into a pinned connection, so
// the bound falls through to the profile or the default instead.
func parseFirstByteOverride(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		slog.Warn("ignoring an unusable first-byte timeout override; the profile or the default applies",
			"env", backendFirstByteTimeoutEnv, "value", raw,
			"default_seconds", int(defaultBackendFirstByteTimeout.Seconds()))
		return 0, false
	}
	slog.Info("backend first-byte timeout overridden on this box",
		"env", backendFirstByteTimeoutEnv, "seconds", secs)
	return time.Duration(secs) * time.Second, true
}

// resolveBackendFirstByteTimeout is the env value alone with no profile:
// the override when usable, else the default.
func resolveBackendFirstByteTimeout(raw string) time.Duration {
	d, set := parseFirstByteOverride(raw)
	return firstByteTimeoutFor(d, set, nil)
}

// localRerankTargets returns candidate reranker endpoints in probe order.
// The cached last-working target (if fresh) is moved to the front.
//
// `door` is the reranker's dial URL from the running containers'
// declaration (dockerpkg.BackendDialURL("reranker")): the noo-stunnel-
// reranker sidecar (agent-run or compose) on :443 whatever the engine, or
// — for a pre-door container — the plain noo-reranker. A sidecar hides the
// engine, so both wire shapes are attempted at it, exactly as for a custom
// URL whose engine is unknown.
func localRerankTargets(door string) []rerankTarget {
	var cands []rerankTarget
	if u := strings.TrimSpace(os.Getenv("NOO_LOCAL_RERANK_URL")); u != "" {
		base := strings.TrimRight(u, "/")
		switch strings.ToLower(strings.TrimSpace(os.Getenv("NOO_LOCAL_RERANK_ENGINE"))) {
		case "llamacpp":
			cands = []rerankTarget{{base, "llamacpp"}}
		case "tei":
			cands = []rerankTarget{{base, "tei"}}
		default:
			// Engine unknown for a custom URL — attempt both shapes.
			cands = []rerankTarget{{base, "llamacpp"}, {base, "tei"}}
		}
	} else if strings.HasPrefix(door, "http://") {
		// Pre-door plain container (recorded as a backend_door refusal by
		// the docker package until the reconciler recreates it). noo-reranker
		// is the container name whether the reranker was started by the
		// node-agent or docker-compose; llama-server listens on :8085 (spec
		// PORT default), TEI plaintext on :80.
		host := strings.TrimPrefix(door, "http://")
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		cands = []rerankTarget{
			{"http://" + host + ":8085", "llamacpp"},
			{"http://" + host + ":80", "tei"},
		}
	} else {
		base := strings.TrimRight(door, "/")
		cands = []rerankTarget{{base, "llamacpp"}, {base, "tei"}}
	}

	rerankTargetMu.Lock()
	defer rerankTargetMu.Unlock()
	if rerankTargetCached != nil && time.Since(rerankTargetAt) < rerankTargetTTL {
		ordered := []rerankTarget{*rerankTargetCached}
		for _, c := range cands {
			if c != *rerankTargetCached {
				ordered = append(ordered, c)
			}
		}
		return ordered
	}
	return cands
}

func cacheRerankTarget(t rerankTarget) {
	rerankTargetMu.Lock()
	rerankTargetCached = &t
	rerankTargetAt = time.Now()
	rerankTargetMu.Unlock()
}

// buildRerankRequest translates the gateway's TEI-shape body for the target
// engine. Returns (payload, path). TEI passes through unchanged.
func buildRerankRequest(engine string, body []byte) ([]byte, string, error) {
	if engine == "tei" {
		return body, "/rerank", nil
	}
	var in struct {
		Query string   `json:"query"`
		Texts []string `json:"texts"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, "", fmt.Errorf("invalid rerank body: %w", err)
	}
	if in.Query == "" || len(in.Texts) == 0 {
		return nil, "", fmt.Errorf("rerank body needs non-empty query and texts")
	}
	out, err := json.Marshal(map[string]any{
		// llama-server ignores the model name (single loaded model) but the
		// Jina-style endpoint expects the field to exist.
		"model":     "reranker",
		"query":     in.Query,
		"documents": in.Texts,
		"top_n":     len(in.Texts),
	})
	if err != nil {
		return nil, "", err
	}
	return out, "/v1/rerank", nil
}

// normalizeRerankResponse converts an engine response into the TEI wire
// shape `[{index, score}]` sorted by score descending (what TEI emits and
// what the gateway's parser expects).
func normalizeRerankResponse(engine string, raw []byte) ([]byte, error) {
	type row struct {
		Index int     `json:"index"`
		Score float64 `json:"score"`
	}
	var rows []row
	if engine == "tei" {
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, fmt.Errorf("unexpected TEI rerank response: %w", err)
		}
	} else {
		var out struct {
			Results []struct {
				Index          int     `json:"index"`
				RelevanceScore float64 `json:"relevance_score"`
			} `json:"results"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || out.Results == nil {
			return nil, fmt.Errorf("unexpected llama.cpp rerank response")
		}
		rows = make([]row, 0, len(out.Results))
		for _, r := range out.Results {
			rows = append(rows, row{Index: r.Index, Score: r.RelevanceScore})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Score > rows[j].Score })
	return json.Marshal(rows)
}

// handleRerankProxy forwards a rerank request to this node's local reranker
// container, translating between the TEI wire contract and whatever engine
// the container actually speaks (see block comment above). It mirrors
// handleInferenceProxy but targets the reranker rather than an LLM backend,
// so the gateway can address rerank BY NODE — the gateway → node-agent hop is
// mTLS+HMAC, and node-agent → reranker is the node's own docker network.
// External consumers never reach the reranker container directly.
//
// The gateway routes here only for nodes that advertise the "rerank"
// capability; a missing reranker therefore means a stale gossip view and is
// surfaced as a clear 503 (OpenAI-shape JSON) instead of a refused connection.
func (s *Server) handleRerankProxy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "read_body_failed", err.Error())
		return
	}
	_ = r.Body.Close()

	// Guard: confirm a reranker container is actually running here before
	// proxying. Gives a precise 503 rather than a connection error when the
	// gateway's capability view is ahead of reality (just stopped, etc.).
	hasReranker := false
	for _, name := range s.docker.ContainerNames() {
		if strings.Contains(name, "rerank") {
			hasReranker = true
			break
		}
	}
	if !hasReranker {
		jsonError(w, http.StatusServiceUnavailable, "no_local_reranker",
			"no reranker container running on this node")
		return
	}

	var lastErr string
	for _, cand := range localRerankTargets(s.docker.BackendDialURL("reranker")) {
		payload, path, berr := buildRerankRequest(cand.engine, body)
		if berr != nil {
			// Body is malformed regardless of engine — reject once.
			jsonError(w, http.StatusBadRequest, "bad_rerank_body", berr.Error())
			return
		}
		req, rerr := http.NewRequestWithContext(r.Context(), http.MethodPost,
			cand.base+path, bytes.NewReader(payload))
		if rerr != nil {
			jsonError(w, http.StatusInternalServerError, "bad_rerank_url", rerr.Error())
			return
		}
		req.Header.Set("Content-Type", "application/json")

		// The door requires a client certificate: present the node leaf.
		resp, derr := s.backendClient(cand.base, 60*time.Second).Do(req)
		if derr != nil {
			lastErr = derr.Error()
			continue // engine not listening on this port — try next candidate
		}
		respBody, rderr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if rderr != nil {
			lastErr = rderr.Error()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Wrong engine guess (404/405) or a genuine upstream error —
			// either way try the other candidate, remembering the failure.
			lastErr = fmt.Sprintf("%s%s returned %d: %.300s",
				cand.base, path, resp.StatusCode, string(respBody))
			continue
		}
		norm, nerr := normalizeRerankResponse(cand.engine, respBody)
		if nerr != nil {
			lastErr = nerr.Error()
			continue // response didn't match this engine's shape — try next
		}
		cacheRerankTarget(cand)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(norm)
		return
	}
	jsonError(w, http.StatusBadGateway, "reranker_unreachable",
		"no local reranker endpoint answered: "+lastErr)
}

// ─────────────────────────── embed proxy ───────────────────────────

// localEmbedURL returns the node-local embedding endpoint base: the DOOR
// of the backend desired state declares as this node's embedder, as the
// running containers declare it (dockerpkg.BackendDialURL — the stunnel
// sidecar with a client certificate, or a pre-door container plain until
// the reconciler recreates it). Override with NOO_LOCAL_EMBED_URL if the
// embedder is exposed under a different service name/port.
func (s *Server) localEmbedURL() string {
	if u := strings.TrimSpace(os.Getenv("NOO_LOCAL_EMBED_URL")); u != "" {
		return strings.TrimRight(u, "/")
	}
	// Desired state is the authority on WHICH local backend serves
	// embeddings: the reconciler publishes the role=embed placement's
	// target here. This used to be hardcoded to noo-tei, which silently
	// returned bge 768-dim vectors on a node whose declared embedder was
	// harrier-on-ollama at 1024 dims — wrong answers, no error. Container
	// names cannot disambiguate this (ollama serves chat on some nodes and
	// embeddings on others), so role is the only sound signal.
	t := embedtarget.Get()
	if t.Backend != "" {
		return strings.TrimRight(s.docker.BackendDialURL(t.Backend), "/")
	}
	if u := strings.TrimSpace(t.BaseURL); u != "" {
		return strings.TrimRight(u, "/")
	}
	// No declared embedder yet (agent just started, gateway predates the
	// role field, or no embed placement on this node). TEI is the
	// historical default and the container the embedding backend spec
	// pins, so this preserves prior behaviour rather than failing closed —
	// at its door, never its plain port.
	return strings.TrimRight(s.docker.BackendDialURL("embedding"), "/")
}

// nativeEmbedURL is the endpoint of the declared embedder when that backend
// is served natively on this host (ok=false otherwise, or when no embed
// placement is declared yet). The scheme is the endpoint's own: plaintext
// loopback ollama, or the self-node's https door (backendClient picks the
// transport from it).
func (s *Server) nativeEmbedURL() (string, bool) {
	backend := embedtarget.Get().Backend
	if backend == "" || s.native == nil {
		return "", false
	}
	if _, running := s.nativeBackends()[backend]; !running {
		return "", false
	}
	base, ok := s.native.Endpoint(backend)
	if !ok || strings.TrimSpace(base) == "" {
		return "", false
	}
	return strings.TrimRight(base, "/"), true
}

// dockerContainerNames is the container list for the embed guard, skipped for
// a native embedder (a Mac has no Docker; the client exists but answers
// nothing) and safe when no Docker client was built.
func (s *Server) dockerContainerNames(native bool) []string {
	if native || s.docker == nil {
		return nil
	}
	return s.docker.ContainerNames()
}

// backendClient is an http.Client for one backend door: the node-leaf
// mTLS transport for an https door, the plain bridge dialer otherwise.
//
// The client is built per request, so its transport must not keep
// connections alive: a per-request transport's idle pool is never reused,
// and a bare &http.Transport{} has no IdleConnTimeout, so every embed or
// rerank call used to leave one connection open for the life of the agent.
// On a Mac serving /embed from native ollama that exhausted the ephemeral
// port range (~16k loopback connections) and cut the node off the network.
func (s *Server) backendClient(base string, timeout time.Duration) *http.Client {
	if strings.HasPrefix(base, "https://") {
		return &http.Client{Timeout: timeout, Transport: oneShot(httpsTransport(s.cfg))}
	}
	return &http.Client{Timeout: timeout, Transport: oneShot(withBackendDial(&http.Transport{}))}
}

// oneShot closes each connection after its response: for a transport that
// lives for one request, keep-alive only leaks. It mutates and returns t.
func oneShot(t *http.Transport) *http.Transport {
	t.DisableKeepAlives = true
	return t
}

// handleEmbedProxy forwards an OpenAI-shaped embeddings request to this
// node's local embedding container, mirroring handleRerankProxy — it lets the
// gateway mesh-route embeddings BY NODE (nodes advertising the `embed`
// capability) instead of requiring a controller-co-located TEI.
//
// Contract: POST /embed with an OpenAI `/v1/embeddings` body
// `{input, model?, ...}` → OpenAI embeddings response. TEI ≥1.2 serves
// `/v1/embeddings` natively, so the primary path is a passthrough; if the
// local container is TEI-native-only (404/405 on the OpenAI route), the
// proxy translates to TEI's native `POST /embed {inputs}` and reshapes the
// raw `[[..]]` reply into the OpenAI shape.
//
// Note: this is intentionally a separate route from the node-agent's
// /v1/embeddings, which targets LLM backends (vllm/llamacpp/ollama) via
// handleInferenceProxy and stays unchanged.
func (s *Server) handleEmbedProxy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "read_body_failed", err.Error())
		return
	}
	_ = r.Body.Close()

	// A NATIVE embedder (ollama served on this host, a Mac's Metal lane) is
	// on loopback, not on the docker network, and has no container for the
	// guard below to find. Same rule as the chat proxy above: the adopted
	// lane's own endpoint wins. Before this, every embed request to a Mac
	// whose embed placement was live answered 503 no_local_embedder while
	// ollama served the model fine.
	base, native := s.nativeEmbedURL()
	if !native {
		base = s.localEmbedURL()
	}

	// Guard: precise 503 when no embedding container is here (stale gossip).
	// Match against the container the resolved target actually names, not
	// just "tei"/"embed" substrings — a node serving embeddings from
	// harrier-on-ollama has a noo-ollama container and would otherwise be
	// declared embedder-less despite being the declared embedder.
	wantContainer := embedContainerFromURL(base)
	hasEmbedder := native
	for _, name := range s.dockerContainerNames(native) {
		if name == wantContainer ||
			strings.Contains(name, "tei") || strings.Contains(name, "embed") {
			hasEmbedder = true
			break
		}
	}
	if !hasEmbedder {
		jsonError(w, http.StatusServiceUnavailable, "no_local_embedder",
			"no embedding container running on this node (want "+wantContainer+")")
		return
	}
	// The door requires a client certificate: present the node leaf.
	client := s.backendClient(base, 120*time.Second)

	post := func(url string, payload []byte) (*http.Response, error) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return client.Do(req)
	}

	// Ensure the body names a model. TEI serves exactly one model and
	// ignores the field, so callers on the TEI path have always omitted it.
	// ollama serves many and rejects a request without one — that mismatch
	// is why a correctly-routed /embed still answered "404 page not found"
	// (ollama's own 404, copied straight through to the caller).
	body = ensureEmbedModel(body, embedtarget.Get().Model)
	// `options` is an ollama knob (the gateway sends num_ctx on every
	// embed). TEI and other OpenAI-compatible engines have no such field;
	// keep it from reaching them.
	if embedtarget.Get().Backend != backendOllama {
		body = stripEmbedOptions(body)
		body = stripEmbedKeepAlive(body)
	}

	// Primary: OpenAI-compatible passthrough (TEI ≥1.2 and ollama both
	// serve this).
	//
	// Skipped for ollama when the caller sent `options` (the gateway sends
	// num_ctx on every embed): ollama's /v1/embeddings drops them, so the
	// native /api/embed below is the only route that honours them.
	if !embedNativeFirst(embedtarget.Get().Backend, body) {
		resp, err := post(base+"/v1/embeddings", body)
		if err != nil {
			jsonError(w, http.StatusBadGateway, "embedder_unreachable", err.Error())
			return
		}
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			defer func() { _ = resp.Body.Close() }()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}
		_ = resp.Body.Close()
	}

	// Fallback: native dialects. Parse the OpenAI body once, then translate
	// to whichever native shape this backend speaks.
	var in struct {
		Input json.RawMessage `json:"input"`
		Model string          `json:"model"`
	}
	if err := json.Unmarshal(body, &in); err != nil || len(in.Input) == 0 {
		jsonError(w, http.StatusBadRequest, "bad_embed_body", "missing 'input'")
		return
	}
	var inputs []string
	var single string
	if err := json.Unmarshal(in.Input, &single); err == nil {
		inputs = []string{single}
	} else if err := json.Unmarshal(in.Input, &inputs); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_embed_body",
			"'input' must be a string or an array of strings")
		return
	}

	// Native fallback, driven by the dialect registry rather than a chain
	// of per-engine branches. The backend type comes from the role=embed
	// placement, so adding an engine is a table entry, not another `if`.
	d, ok := embedDialects[embedtarget.Get().Backend]
	if !ok {
		// Unknown/undeclared engine: TEI's dialect is the historical
		// default and the only one every existing deployment has spoken.
		d = embedDialects[backendTEI]
	}

	model := in.Model
	if model == "" {
		model = embedtarget.Get().Model
	}

	nativeReq, err := d.encode(inputs, model, embedOptions(body))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	if embedtarget.Get().Backend == backendOllama {
		nativeReq = withEmbedKeepAlive(nativeReq, embedKeepAlive(body))
	}
	nresp, err := post(base+d.path, nativeReq)
	if err != nil {
		jsonError(w, http.StatusBadGateway, "embedder_unreachable", err.Error())
		return
	}
	defer func() { _ = nresp.Body.Close() }()
	nativeBody, err := io.ReadAll(io.LimitReader(nresp.Body, 64<<20))
	if err != nil {
		jsonError(w, http.StatusBadGateway, "embedder_read_failed", err.Error())
		return
	}
	if nresp.StatusCode < 200 || nresp.StatusCode >= 300 {
		// Pass the engine's own error through, but say which dialect we
		// spoke — a bare upstream 404 here previously read as "the
		// node-agent has no /embed route" when the route was fine and the
		// DIALECT was wrong.
		slog.Warn("embed.native_dialect_failed",
			"backend", embedtarget.Get().Backend,
			"path", d.path,
			"status", nresp.StatusCode)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(nresp.StatusCode)
		_, _ = w.Write(nativeBody)
		return
	}
	vectors, err := d.decode(nativeBody)
	if err != nil {
		jsonError(w, http.StatusBadGateway, "embedder_bad_response", err.Error())
		return
	}
	if model == "" {
		model = embedtarget.Get().Backend
	}
	writeOpenAIEmbeddings(w, vectors, model)
}

// handleListModels returns the union of models that locally-running
// backends are currently serving. Shape matches OpenAI's `/v1/models`
// so existing OpenAI clients (LangChain, LlamaIndex, etc.) work
// unchanged when pointed at node-agent.
func (s *Server) handleListModels(w http.ResponseWriter, r *http.Request) {
	running := s.docker.RunningBackends()
	type modelEntry struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	}
	out := struct {
		Object string       `json:"object"`
		Data   []modelEntry `json:"data"`
	}{Object: "list", Data: []modelEntry{}}

	for bt, model := range running {
		if model == "" {
			continue
		}
		out.Data = append(out.Data, modelEntry{
			ID:      model,
			Object:  "model",
			OwnedBy: bt, // "vllm" / "llamacpp" / "ollama"
		})
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	// Encode errors here mean the client closed mid-write — nothing
	// useful to do. Log + drop on the floor.
	_ = enc.Encode(out)
}

// embedContainerFromURL extracts the container name from an embed base URL
// ("http://noo-ollama:11434" -> "noo-ollama") so the /embed guard can check
// for the container the resolved target actually names. Returns "" when the
// host cannot be parsed, which makes the guard fall back to its substring
// match rather than rejecting the request.
func embedContainerFromURL(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// ensureEmbedModel injects `model` into an embeddings body that omits it.
//
// The /embed contract grew up around TEI, which serves a single model and
// ignores the field, so every existing caller sends only `input`. ollama
// requires `model` and answers a request without one with a bare 404 that
// the proxy faithfully forwarded — a confusing failure that looks like a
// missing route rather than a missing field.
//
// Returns the body unchanged when it is not a JSON object, already names a
// model, or when desired state has not told us which model to name.
func ensureEmbedModel(body []byte, model string) []byte {
	if model == "" {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	if raw, ok := obj["model"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && strings.TrimSpace(s) != "" {
			return body
		}
	}
	enc, err := json.Marshal(model)
	if err != nil {
		return body
	}
	obj["model"] = enc
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// writeOpenAIEmbeddings renders vectors in the OpenAI /v1/embeddings shape,
// which is the contract every /embed caller already expects regardless of
// which dialect the backend actually spoke.
func writeOpenAIEmbeddings(w http.ResponseWriter, vectors [][]float64, model string) {
	data := make([]map[string]any, 0, len(vectors))
	for i, v := range vectors {
		data = append(data, map[string]any{
			"object":    "embedding",
			"index":     i,
			"embedding": v,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data":   data,
		"model":  model,
	})
}

// substituteAutoModel rewrites a request whose `model` is absent, empty or
// `auto` to name `served`, the model the picked backend loaded. Anything
// else — a named model, an unparseable body, no served name — is returned
// unchanged.
func substituteAutoModel(body []byte, served string) []byte {
	if served == "" || len(body) == 0 {
		return body
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	var cur string
	if raw, ok := m["model"]; ok {
		if err := json.Unmarshal(raw, &cur); err != nil {
			return body
		}
	}
	if cur != "" && cur != "auto" {
		return body
	}
	enc, err := json.Marshal(served)
	if err != nil {
		return body
	}
	m["model"] = enc
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// stripEmbedKeepAlive removes the top-level `keep_alive` key (ollama-only)
// from a JSON object body; anything else passes through unchanged.
func stripEmbedKeepAlive(body []byte) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	if _, ok := obj["keep_alive"]; !ok {
		return body
	}
	delete(obj, "keep_alive")
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// stripEmbedOptions removes the top-level `options` key from a JSON object
// body; anything else (including non-JSON) passes through unchanged.
func stripEmbedOptions(body []byte) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	if _, ok := obj["options"]; !ok {
		return body
	}
	delete(obj, "options")
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}
