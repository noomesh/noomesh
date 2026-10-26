// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package backendrt describes WHERE a backend runs on this node.
//
// Backends have always been Docker containers. On macOS that is a dead end:
// Docker Desktop runs a Linux VM and cannot pass the GPU through, so a
// containerised llama.cpp or ollama on an Apple Silicon box is CPU-only —
// the worst case for a machine whose whole value is unified memory reachable
// from Metal. `hardware.Capabilities.CanGPUPassthrough` has said so since the
// darwin lane was written ("on macOS a GPU is only usable by a native
// backend"); nothing implemented the way around it.
//
// This is the smallest honest step: ADOPT a native backend the operator is
// already running, rather than manage its lifecycle. Ollama on macOS installs
// as a native app and serves on 127.0.0.1:11434 with Metal, and the darwin
// enrollment guidance already tells operators to `brew services start ollama`.
// So the process exists; the agent simply never looked for it.
//
// What this package deliberately does NOT do: start, stop, or supervise
// anything. A backend it reports is one it found, and the API says so rather
// than accepting a start it cannot perform.
package backendrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelstats"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// Native probes locally-running backends over loopback.
//
// Loopback is deliberate: the backend is not exposed on the LAN, and every
// consumer reaches it through the node-agent's authenticated :8081 proxy,
// which is already how the gateway addresses a backend (it resolves a
// placement to the AGENT's address, not the backend's).
type Native struct {
	client *http.Client
	// clientErr is why this lane has no usable client: an https base whose
	// node PKI is missing or unreadable (see laneTransport). Every request
	// returns it instead of reaching the network — a configured-but-broken
	// leaf is an error, never a bare client (the preseed.go rule).
	clientErr error
	// ollamaBase is the base URL to probe. A field, not a constant, so tests
	// can point it at a stub server instead of the machine's real ollama.
	ollamaBase string
	// runtime names the lane in reports: "native" (a host process on
	// macOS) or "stack" (the controller's own ollama on the self-node).
	runtime string
}

// heldByBase records, per ollama BASE URL, the placed model that server holds:
// the reconciler saw it in /api/tags, pulling it first if it had to. It is
// reported as the running model whenever nothing is loaded, because an adopted
// ollama loads on first request and unloads after idle, so `/api/ps` is empty
// most of the time — and a heartbeat that says "ollama, no model" is dropped by
// the gateway's resolver, which then never sends the request that would load it.
//
// **Keyed by the server, not held on the struct.** It was a struct field, and
// that made the fix inert: `NewAdopted()` is called in THREE places — the
// Agent (whose instance the heartbeat reads), the API server, and inside the
// reconciler (whose instance calls SetHeld). So the reconciler recorded the
// model on an object nobody reporting ever looked at. The agent log said
// `running_model: gemma4:12b` on every tick while the heartbeat said "ollama"
// with no model, and the node was never routed to — host6 for a day, and then
// host8, where chat silently fell through to a Pi at 98% load.
//
// A process-wide map keyed by base URL is the honest shape: the fact is about
// the ollama server, not about a struct someone happened to construct. It also
// cannot be re-broken by a FOURTH constructor, which is exactly how the first
// attempt was broken.
var (
	heldMu sync.Mutex
	// heldByBase: base URL -> the placed models the server holds, PRIMARY
	// (chat, else first) first. Multi-role placements put several models in
	// one ollama; Running() still reports only the primary as `ollama`.
	heldByBase = map[string][]string{}
)

// SetHeld records the single placed model the server at this lane's base
// holds ("" clears). Equivalent to SetHeldModels(model).
func (n *Native) SetHeld(model string) { n.SetHeldModels(model) }

// SetHeldModels records every placed model the server holds, primary first
// (blank entries are dropped; none clears).
func (n *Native) SetHeldModels(models ...string) {
	if n == nil {
		return
	}
	var set []string
	seen := map[string]bool{}
	for _, m := range models {
		m = strings.TrimSpace(m)
		if m != "" && !seen[m] {
			seen[m] = true
			set = append(set, m)
		}
	}
	heldMu.Lock()
	defer heldMu.Unlock()
	if len(set) == 0 {
		delete(heldByBase, n.ollamaBase)
		return
	}
	heldByBase[n.ollamaBase] = set
}

// HeldModels returns the held set, primary first.
func (n *Native) HeldModels() []string {
	if n == nil {
		return nil
	}
	heldMu.Lock()
	defer heldMu.Unlock()
	return append([]string(nil), heldByBase[n.ollamaBase]...)
}

func (n *Native) heldModel() string {
	if h := n.HeldModels(); len(h) > 0 {
		return h[0]
	}
	return ""
}

// ModelStats is the heartbeat's measured `model_stats` for this lane's
// ollama (/api/tags merged with /api/ps). nil when unreachable.
func (n *Native) ModelStats(ctx context.Context) []modelstats.ModelStat {
	if n == nil {
		return nil
	}
	tags, err := n.get(ctx, n.ollamaBase+"/api/tags")
	if err != nil {
		return nil
	}
	ps, _ := n.get(ctx, n.ollamaBase+"/api/ps")
	return modelstats.Parse(tags, ps)
}

// Runtime is the label this lane's backends carry in `backend_runtimes`
// and the API's `runtime` field; "" for no lane.
func (n *Native) Runtime() string {
	if n == nil {
		return ""
	}
	return n.runtime
}

// NewAdopted returns the lane for backends this agent REPORTS but does not
// manage, or nil when the host has none:
//
//   - NOO_SELF_NODE=1 — the node on the controller's own device
//     (2026-09-11). The stack already runs an ollama (`noo-ollama-embed`,
//     reached on loopback at OLLAMA_URL — its
//     stunnel-ollama-embed door, https + the node leaf) that serves chat and embeddings
//     for the controller; a node-managed `noo-ollama` beside it would fight
//     for the same GPU. So on the self-node the "ollama" backend IS the
//     stack's, adopted exactly as a Mac's native ollama is: reported,
//     routed, models pulled into it, never started or stopped from here.
//     Runtime "stack".
//   - darwin — the native ollama on loopback (see the package doc).
//     Runtime "native".
//
// The self-node lane wins when both could apply: the stack's ollama is
// the one the controller is configured for.
func NewAdopted() *Native {
	if selfNodeFromEnv() {
		base := strings.TrimRight(os.Getenv("OLLAMA_URL"), "/")
		if base == "" {
			base = fmt.Sprintf("http://127.0.0.1:%d", OllamaPort)
		}
		return NewStackAt(base)
	}
	return NewNative()
}

// NewStackAt is the self-node lane at an explicit base (tests).
//
// The base decides the transport (laneTransport): `https://127.0.0.1:11434`
// is the controller's stunnel-ollama-embed door (verify = 2), dialled with
// the node leaf; `http://…` is a plaintext loopback server, dialled bare.
func NewStackAt(ollamaBase string) *Native {
	return newLane(ollamaBase, "stack")
}

// newLane builds a lane at base with the transport its scheme needs.
func newLane(ollamaBase, runtime string) *Native {
	n := &Native{ollamaBase: ollamaBase, runtime: runtime}
	tr, err := laneTransport(ollamaBase)
	if err != nil {
		n.clientErr = err
		slog.Error("ollama lane: no usable client — every probe, pull and inference on this lane refuses until the node PKI is fixed",
			"runtime", runtime, "base", ollamaBase, "error", err)
	}
	n.client = &http.Client{Timeout: 2 * time.Second, Transport: tr}
	return n
}

// laneTransport is the transport the ollama lane dials base with.
//
//   - https — the controller's own ollama-embed behind its stunnel sidecar,
//     published on loopback. The sidecar requires a cluster-CA client
//     certificate, so the lane presents the node leaf and verifies the
//     door's `ollama-embed` leaf (it carries 127.0.0.1 and localhost)
//     against the cluster CA — config.HTTPTransport, the same transport the
//     agent dials the controller with. All three of NOO_TLS_CA/CERT/KEY
//     must be set: without the CA the door fails verification against the
//     system roots, without the leaf the door refuses the handshake, and
//     neither should look like "no ollama here". A configured-but-
//     unreadable file is an error too (HTTPTransport's rule).
//   - http — a plaintext ollama on the host's loopback: the operator's own
//     native install (macOS Metal, the darwin lane), the one documented
//     plaintext backend door, and a self-node whose provision predates the
//     door. nil = http.DefaultTransport, exactly as before.
func laneTransport(base string) (http.RoundTripper, error) {
	if !strings.HasPrefix(strings.ToLower(base), "https://") {
		return nil, nil
	}
	cfg := config.Load()
	var missing []string
	for _, kv := range [][2]string{{"NOO_TLS_CA", cfg.TLSCA}, {"NOO_TLS_CERT", cfg.TLSCert}, {"NOO_TLS_KEY", cfg.TLSKey}} {
		if strings.TrimSpace(kv[1]) == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("OLLAMA_URL %s is an mTLS door but %s not set — the door requires the node leaf; "+
			"re-run `noo cluster provision <node> --local` on the controller to deliver this node's PKI", base, strings.Join(missing, ", "))
	}
	tr, err := cfg.HTTPTransport()
	if err != nil {
		return nil, fmt.Errorf("OLLAMA_URL %s: %w", base, err)
	}
	return tr, nil
}

func selfNodeFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NOO_SELF_NODE"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// NewNative returns a prober, or nil when this platform has no native lane.
//
// nil rather than a no-op value: an inert object that answers "nothing
// running" is indistinguishable from a platform that genuinely has no native
// backends, and this repo's convention is that absence is stated, not
// simulated.
func NewNative() *Native {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return newLane(fmt.Sprintf("http://127.0.0.1:%d", OllamaPort), "native")
}

// NewNativeAt returns a prober pointed at an explicit ollama base URL.
//
// The injection seam. NewNative is platform-gated, so on any non-darwin
// machine — including CI — the native lane cannot otherwise be exercised at
// all, and the behaviour that matters (a backend reported, routed to, and
// refused for start) would ship untested. Callers in production use
// NewNative; this exists so the tests are real.
func NewNativeAt(ollamaBase string) *Native {
	return newLane(ollamaBase, "native")
}

// OllamaPort is the port a native ollama serves on. Same value as the
// container's, deliberately: the backend KEY stays "ollama" and only the
// runtime differs, so nothing in the gateway, the scheduler or the placement
// path has to learn a new name.
const OllamaPort = 11434

// Endpoint returns the loopback base URL for a backend this prober owns, and
// false when it owns none.
func (n *Native) Endpoint(backend string) (string, bool) {
	if n == nil || backend != "ollama" {
		return "", false
	}
	return n.ollamaBase, true
}

// Running reports backends serving right now, as backend -> model.
//
// The model is the one the backend is placed to serve once the reconciler
// has confirmed the server holds it (SetHeld); before that, the one loaded
// from /api/ps. An ollama that is up with nothing held or loaded reports an
// empty model rather than being omitted: it IS running and can serve, and
// hiding it would make a reachable backend invisible. What is loaded right
// now is Loaded().
func (n *Native) Running(ctx context.Context) map[string]string {
	out := map[string]string{}
	if n == nil {
		return out
	}
	base, ok := n.Endpoint("ollama")
	if !ok {
		return out
	}
	if !n.alive(ctx, base) {
		return out
	}
	// The backend's identity is the model it was PLACED to serve, when the
	// reconciler has confirmed the server holds it. What the server happens
	// to have loaded is a different fact, reported by Loaded(): on the
	// self-node the same ollama serves chat and embeddings, so most of the
	// time the loaded model is the embedder — and a chat turn routed by
	// that report was sent to an embedding model and refused (host8,
	// 2026-09-22, `"harrier:latest" does not support chat`).
	if held := n.heldModel(); held != "" {
		out["ollama"] = held
		return out
	}
	// Nothing held: the loaded model is only an identity if it is not an
	// embedder. On the self-node the same ollama is the stack's embedder, and
	// its loaded model is usually harrier; reporting that as the backend's
	// model made it a chat candidate (rehearsal 0.6.7-rc.1 F1). The gateway
	// excludes it as well; this keeps the agent from saying it.
	if m := n.loadedModel(ctx, base); !looksLikeEmbedder(m) {
		out["ollama"] = m
	} else {
		out["ollama"] = ""
	}
	return out
}

// looksLikeEmbedder is the name test for an embedding/reranking model, the
// agent-side twin of the gateway's is_embedding_model_name.
func looksLikeEmbedder(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	if i := strings.LastIndex(m, "/"); i >= 0 {
		m = m[i+1:]
	}
	if strings.Contains(m, "embed") || strings.Contains(m, "rerank") {
		return true
	}
	for _, p := range []string{"harrier", "bge-", "bge:", "e5-", "gte-", "all-minilm", "minilm", "snowflake"} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return m == "bge" || m == "tei"
}

// Loaded reports what each backend this lane owns has in memory right now,
// as backend -> model, from /api/ps. Omits a backend with nothing loaded.
// This is the observation Running() used to conflate with identity; it
// stays visible so an operator can see an idle or busy server for what it
// is without the placement lying about what it serves.
func (n *Native) Loaded(ctx context.Context) map[string]string {
	out := map[string]string{}
	if n == nil {
		return out
	}
	base, ok := n.Endpoint("ollama")
	if !ok {
		return out
	}
	if m := n.loadedModel(ctx, base); m != "" {
		out["ollama"] = m
	}
	return out
}

// alive is the ownership signal: /api/tags answers only if a server is there.
func (n *Native) alive(ctx context.Context, base string) bool {
	body, err := n.get(ctx, base+"/api/tags")
	return err == nil && body != nil
}

// loadedModel reads /api/ps. Empty means "running, nothing loaded" — which is
// a true statement about a fresh install and must not read as "not running".
func (n *Native) loadedModel(ctx context.Context, base string) string {
	body, err := n.get(ctx, base+"/api/ps")
	if err != nil {
		return ""
	}
	var ps struct {
		Models []struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if json.Unmarshal(body, &ps) != nil || len(ps.Models) == 0 {
		return ""
	}
	if m := strings.TrimSpace(ps.Models[0].Model); m != "" {
		return m
	}
	return strings.TrimSpace(ps.Models[0].Name)
}

func (n *Native) get(ctx context.Context, url string) ([]byte, error) {
	if n.clientErr != nil {
		return nil, n.clientErr
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < 1<<20 {
		nr, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:nr]...)
		if rerr != nil {
			break
		}
	}
	return buf, nil
}

// Models lists the model names the lane's ollama holds (`/api/tags`), for
// the heartbeat's cached-model inventory. nil when the lane has no server
// or cannot reach it. The heartbeat used to probe `http://localhost:11434`
// with a bare client for this; on the self-node that is now the mTLS door,
// so it asks the lane, which dials with the transport its base needs.
func (n *Native) Models(ctx context.Context) []string {
	if n == nil {
		return nil
	}
	body, err := n.get(ctx, n.ollamaBase+"/api/tags")
	if err != nil {
		return nil
	}
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if json.Unmarshal(body, &tags) != nil {
		return nil
	}
	out := make([]string, 0, len(tags.Models))
	for _, m := range tags.Models {
		if m.Name != "" {
			out = append(out, m.Name)
		}
	}
	return out
}

// HasModel reports whether the native ollama already holds `name`
// (`/api/tags`; a bare name matches its `:latest`).
//
// A model pull is NOT lifecycle. The rule above — found, not managed —
// is about starting, stopping and recreating a process the operator owns.
// Adding a model to a server that is already running is the same "make
// the placement true" step the container path takes, and the operator's
// own guidance was to run `ollama pull` by hand on the Mac; the agent can
// do that over the same loopback API it probes with.
func (n *Native) HasModel(ctx context.Context, name string) (bool, error) {
	base, ok := n.Endpoint("ollama")
	if !ok {
		return false, fmt.Errorf("no native ollama lane on this host")
	}
	body, err := n.get(ctx, base+"/api/tags")
	if err != nil {
		return false, err
	}
	return tagsHave(body, name), nil
}

// Pull fetches `name` into the native ollama from its registry
// (`POST /api/pull`, non-streaming). Blocking for the length of the pull;
// the caller runs it off the reconcile tick.
func (n *Native) Pull(ctx context.Context, name string) (string, error) {
	base, ok := n.Endpoint("ollama")
	if !ok {
		return "", fmt.Errorf("no native ollama lane on this host")
	}
	if err := preseed.OllamaRegistryPullAllowed(name); err != nil {
		return "", err
	}
	if n.clientErr != nil {
		return "", n.clientErr
	}
	payload, _ := json.Marshal(map[string]any{"name": name, "stream": false})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/pull", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	// The probe client's 2 s timeout is for liveness; a pull takes minutes.
	// Same transport as the probes: an https base is the mTLS door, and a
	// bare client here pulled nothing on the self-node.
	pullClient := &http.Client{Timeout: 2 * time.Hour, Transport: n.client.Transport}
	resp, err := pullClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	dec := json.NewDecoder(resp.Body)
	if derr := dec.Decode(&out); derr != nil && !errors.Is(derr, io.EOF) {
		// An unreadable body is the only evidence the status/error below are
		// incomplete: a 2xx with a torn stream must not read as a clean pull.
		slog.Warn("ollama pull: response body unreadable", "model", name, "http_status", resp.StatusCode, "error", derr)
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			return out.Status, fmt.Errorf("ollama pull %s: response unreadable: %w", name, derr)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 || out.Error != "" {
		msg := out.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return out.Status, fmt.Errorf("ollama pull %s: %s", name, msg)
	}
	return out.Status, nil
}

// tagsHave matches a placement's model against an `/api/tags` body.
func tagsHave(body []byte, name string) bool {
	want := name
	if !strings.Contains(want, ":") {
		want += ":latest"
	}
	var tags struct {
		Models []struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if json.Unmarshal(body, &tags) != nil {
		return false
	}
	for _, m := range tags.Models {
		if m.Name == want || m.Model == want {
			return true
		}
	}
	return false
}
