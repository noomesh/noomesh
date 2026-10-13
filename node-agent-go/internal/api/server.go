// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package api provides the HTTP control API for the node agent.
//
// All endpoints match the Python node_agent.py contract so the gateway
// can talk to either implementation interchangeably.
package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/mcpsrv"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

// quietTLSLogger suppresses noisy TLS handshake errors from localhost
// (healthcheck hits HTTPS without a client cert every 30s).
type quietTLSLogger struct{}

func (q quietTLSLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	// Suppress localhost healthcheck TLS errors
	if strings.Contains(msg, "TLS handshake error") &&
		(strings.Contains(msg, "[::1]") || strings.Contains(msg, "127.0.0.1")) {
		return len(p), nil
	}
	// Log everything else
	slog.Info(strings.TrimSpace(msg))
	return len(p), nil
}

// Server is the HTTP control API server.
type Server struct {
	cfg       *config.Config
	docker    *dockerpkg.Client
	gpu       *hardware.GPUDetector
	collector *metrics.Collector
	mux       *http.ServeMux

	// native probes backends served outside Docker on this host — a Metal
	// ollama on darwin, which a container cannot reach. nil off darwin.
	native *backendrt.Native

	// busStatus reports the node's NATS connection state for /health. nil
	// until the messaging subsystem wires it in — and a nil provider is
	// reported as "unavailable", never as connected.
	busStatus func() BusStatus

	// mcp is the external-MCP supervisor: tool calls
	// from the controller land on it, and /health lists what is live. nil
	// until the agent installs it; a call then answers 503, never a panic.
	mcp *mcpsrv.Supervisor

	// gpuWatch reports the GPU watchdog's last cycle for /gpu.
	// nil on GPU-less nodes — the field is then omitted entirely, which
	// the controller treats as unknown, the same skew contract as
	// `available`.
	gpuWatch func() any
	// diskReclaim reports the node's own disk-reclaim state for /health.
	diskReclaim func() any
}

// nativeBackends is the set served natively on this host, backend -> model.
// Empty on every platform without a native lane; never nil-panics.
func (s *Server) nativeBackends() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.native.Running(ctx)
}

// BusStatus is the node's own view of its NATS bus, surfaced on /health and
// echoed to the gateway on every heartbeat.
//
// A node whose NATS client is dead keeps answering HTTP and keeps
// heartbeating, so nothing about the old /health payload could distinguish
// it from a healthy one — which is how two nodes stayed "online" for two
// days while every job dispatched to them stranded. The bus is
// a separate fact from the control API and now says so out loud.
type BusStatus struct {
	State     string `json:"state"`
	Connected bool   `json:"connected"`
	// nil (JSON null) means "never" — not zero, not now.
	LastConnectedAt    *string `json:"last_connected_at"`
	LastDisconnectedAt *string `json:"last_disconnected_at"`
	DisconnectedForSec *int64  `json:"disconnected_for_sec"`
	Connects           uint64  `json:"connects"`
	URL                string  `json:"url"`
	// JobDispatchBound is whether the tasks.dispatch.<node> durable is bound
	// right now. Connected-but-unbound is a real state (it is what the
	// 2026-07-03 stranded-jobs incident looked like), so it gets its own
	// field rather than being folded into Connected.
	JobDispatchBound bool `json:"job_dispatch_bound"`
	// Detail explains the state in words, per the honest-status convention
	// every derived verdict ships a
	// sibling string saying what was actually measured.
	Detail string `json:"detail"`
	// The principal this agent authenticates as: username only, never the
	// password. Role is "node" (its own per-principal credential), "shared"
	// (the fleet-wide fallback) or "anonymous".
	//
	// A node deliberately on the shared pair and a node whose per-principal
	// credential never arrived report identical `connected: true`. That
	// distinction was the entire diagnosis of the 2026-09-05 gossip outage
	// and had to be reconstructed from source, because nothing reported it.
	//
	// Omitted by agents predating this: absence is "not reported", never
	// "anonymous".
	User string `json:"user,omitempty"`
	Role string `json:"role,omitempty"`
}

// SetBusStatus installs the NATS status provider. Called once the messaging
// subsystem is wired (the API server starts first so the node is reachable
// during registration).
func (s *Server) SetBusStatus(f func() BusStatus) { s.busStatus = f }

// SetGPUWatch installs the GPU watchdog state provider (GPU nodes only).
func (s *Server) SetGPUWatch(f func() any) { s.gpuWatch = f }

// SetDiskReclaim installs the node disk-reclaim state provider.
func (s *Server) SetDiskReclaim(f func() any) { s.diskReclaim = f }

// SetMCP installs the external-MCP supervisor.
func (s *Server) SetMCP(m *mcpsrv.Supervisor) { s.mcp = m }

// BusStatusOrUnavailable returns the current bus status, or an explicit
// "unavailable" when no provider is installed.
func (s *Server) BusStatusOrUnavailable() BusStatus {
	if s.busStatus == nil {
		return BusStatus{
			State:  "unavailable",
			Detail: "no NATS client on this agent — messaging never initialised",
		}
	}
	return s.busStatus()
}

// NewServer creates a new API server wired with all dependencies.
func NewServer(
	cfg *config.Config,
	docker *dockerpkg.Client,
	gpu *hardware.GPUDetector,
	collector *metrics.Collector,
) *Server {
	s := &Server{
		cfg:       cfg,
		docker:    docker,
		gpu:       gpu,
		collector: collector,
		mux:       http.NewServeMux(),
		native:    backendrt.NewAdopted(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	// leafMW is the bearer check (auth.Middleware) that ALSO admits the
	// controller's verified leaf with no bearer: every route
	// below that the gateway calls is gated on that leaf anyway
	// (ControllerOnly), so the fleet-secret bearer it used to send proved
	// nothing the certificate did not. A request that carries a bearer is
	// judged by auth.Middleware exactly as before.
	leafMW := auth.ControllerLeafOrToken(s.cfg)

	// ctrlMW is leafMW plus "and the caller proved it is the controller".
	//
	// Work in this mesh flows controller → node. A route that changes what
	// this box runs, or hands back what it holds, is the controller's to
	// call; a peer node holding the same fleet secret is not entitled to
	// it. See internal/auth/principal.go for how the caller is identified
	// and when the check is enforced.
	ctrlMW := func(h http.Handler) http.Handler {
		return leafMW(auth.ControllerOnly(s.cfg)(h))
	}

	// metricsMW is authMW plus "and the caller proved it is the controller
	// OR a cluster sidecar". It exists for exactly one route.
	//
	// Prometheus is not the controller. Gating /metrics as controller-only
	// is what put gateway.crt AND gateway.key inside the monitoring
	// container — a scraper holding the one credential that
	// means "command this box". A service leaf lets it scrape and nothing
	// else. Do not reach for this anywhere but /metrics.
	//
	// The scraper authenticates by its service leaf alone; everyone else
	// still needs a bearer (auth.ServiceLeafOrToken).
	metricsMW := func(h http.Handler) http.Handler {
		return auth.ServiceLeafOrToken(s.cfg)(auth.MetricsReader(s.cfg)(h))
	}
	// modelMW is ctrlMW plus this node's OWN harness over loopback
	// the loop beside this node's model asks this
	// agent for that model, with this node's certificate, from 127.0.0.1.
	// Three inference routes and nothing else — a harness never starts,
	// stops, pulls or reads what this box holds; it asks for a completion.
	modelMW := func(h http.Handler) http.Handler {
		return leafMW(auth.ControllerOrOwnHarness(s.cfg)(h))
	}

	// Public endpoints (no auth required)
	s.mux.HandleFunc("GET /health", s.handleHealth)

	// Authenticated endpoints
	s.mux.Handle("POST /start", ctrlMW(http.HandlerFunc(s.handleStartBackend)))
	s.mux.Handle("POST /stop", ctrlMW(http.HandlerFunc(s.handleStopBackend)))
	s.mux.Handle("POST /restart", ctrlMW(http.HandlerFunc(s.handleRestart)))
	s.mux.Handle("POST /pull", ctrlMW(http.HandlerFunc(s.handlePull)))
	s.mux.Handle("POST /clean", ctrlMW(http.HandlerFunc(s.handleClean)))
	s.mux.Handle("GET /gpu", ctrlMW(http.HandlerFunc(s.handleGPUMetrics)))
	// Tailnet identity plane: whois + dialback for
	// tailnet-native enrollment — only meaningful on the controller's
	// self-agent, but harmless everywhere (authMW-gated, CGNAT-restricted).
	// Counted when served to a non-controller leaf — the
	// evidence for moving it behind ctrlMW.
	s.mux.Handle("GET /tailnet/whois", leafMW(auth.CountNonControllerWhois(http.HandlerFunc(s.handleTailnetWhois))))
	s.mux.Handle("POST /tailnet/dialback", ctrlMW(http.HandlerFunc(s.handleTailnetDialback)))
	s.mux.Handle("GET /metrics", metricsMW(http.HandlerFunc(s.handlePrometheusMetrics)))
	s.mux.Handle("GET /logs/containers", ctrlMW(http.HandlerFunc(s.handleListLogContainers)))
	s.mux.Handle("GET /logs/{container}", ctrlMW(http.HandlerFunc(s.handleContainerLogs)))
	s.mux.Handle("GET /stats/containers", ctrlMW(http.HandlerFunc(s.handleContainerStats)))

	// Skill execution endpoint (containerized skills)
	s.mux.Handle("POST /api/skills/run", ctrlMW(http.HandlerFunc(s.handleSkillRun)))

	// Disk cleanup (gateway heartbeat disk_cleanup action) and generic
	// container lifecycle (gateway browser tool). See api/containers.go.
	s.mux.Handle("POST /cleanup/images", ctrlMW(http.HandlerFunc(s.handleCleanupImages)))
	s.mux.Handle("POST /cleanup/logs", ctrlMW(http.HandlerFunc(s.handleCleanupLogs)))
	s.mux.Handle("POST /api/containers/start", ctrlMW(http.HandlerFunc(s.handleContainerStart)))
	s.mux.Handle("POST /api/containers/stop", ctrlMW(http.HandlerFunc(s.handleContainerStop)))

	// The work routes are the controller's too.
	//
	// They used to be authMW only — the fleet HMAC, which every node holds
	// — on the theory that running a prompt is not a "fleet command". But
	// the fleet secret proves only "a node", so any compromised node could
	// run prompts on any other node's GPU, read its container stats, scrape
	// its metrics and enumerate its MCP servers. And nothing legitimate
	// needed that: every shipped caller of these paths is the GATEWAY
	// process (routes/inference.rs for chat/models, embedding_client.rs for
	// /embed, routes/external.rs for /rerank, autonomy_evaluators.rs for
	// /gpu, routes/admin.rs for /stats/containers, mcp_bridge.rs for the
	// MCP routes), and Prometheus scrapes /metrics with the gateway's own
	// certificate. There is no node→node call in the tree; a node that
	// wants an embedding asks the GATEWAY, which mesh-routes it.
	//
	// Inference proxy — generic OpenAI-compatible surface.
	// Lets the gateway address inference by NODE without exposing backend
	// ports on the host. Routes to local vllm/llamacpp/ollama via this
	// node's docker network. See inference_proxy.go for routing rules.
	// All routes are mTLS-protected (same as other authenticated routes).
	// harnessMW is modelMW whose door ALSO admits this node's own harness
	// leaf over loopback with no bearer. Only the route the
	// harness calls: its coordinator speaks OpenAI chat to this proxy and
	// nothing else (the pinned :8081 URL always resolves the "openai" wire
	// format). /v1/completions and /v1/models keep the bearer for it.
	harnessMW := func(h http.Handler) http.Handler {
		return auth.OwnHarnessLeafOrToken(s.cfg)(auth.ControllerOrOwnHarness(s.cfg)(h))
	}
	s.mux.Handle("POST /v1/chat/completions", harnessMW(http.HandlerFunc(s.handleInferenceProxy)))
	s.mux.Handle("POST /v1/completions", modelMW(http.HandlerFunc(s.handleInferenceProxy)))
	s.mux.Handle("POST /v1/embeddings", ctrlMW(http.HandlerFunc(s.handleInferenceProxy)))
	s.mux.Handle("GET /v1/models", modelMW(http.HandlerFunc(s.handleListModels)))

	// Rerank proxy — forwards to this node's local reranker (TEI cross-encoder
	// or llama-server --reranking; the proxy translates request/response shape).
	// Lets the gateway mesh-route /api/external/rerank by NODE without exposing
	// the reranker on the host. See handleRerankProxy in inference_proxy.go.
	s.mux.Handle("POST /rerank", ctrlMW(http.HandlerFunc(s.handleRerankProxy)))
	s.mux.Handle("POST /v1/rerank", ctrlMW(http.HandlerFunc(s.handleRerankProxy)))

	// Embed proxy — forwards to this node's local embedding container (TEI)
	// in OpenAI /v1/embeddings shape. Lets the gateway mesh-route embeddings
	// by NODE (capability `embed`) without exposing the embedder on the host.
	// Distinct from POST /v1/embeddings above, which targets LLM backends.
	// See handleEmbedProxy in inference_proxy.go.
	s.mux.Handle("POST /embed", ctrlMW(http.HandlerFunc(s.handleEmbedProxy)))

	// Device sensor endpoints (companion / Tier 5)
	// External MCP servers placed here: the controller
	// calls a tool through the node that hosts the server; only the
	// controller may (it is the one that placed it).
	s.mux.Handle("POST /api/mcp/{server}/call", ctrlMW(http.HandlerFunc(s.handleMCPCall)))
	s.mux.Handle("GET /api/mcp/servers", ctrlMW(http.HandlerFunc(s.handleMCPServers)))
	s.mux.Handle("POST /api/device/camera_capture", ctrlMW(http.HandlerFunc(s.handleDeviceCamera)))
	s.mux.Handle("POST /api/device/location", ctrlMW(http.HandlerFunc(s.handleDeviceLocation)))
	s.mux.Handle("POST /api/device/clipboard", ctrlMW(http.HandlerFunc(s.handleDeviceClipboard)))
	s.mux.Handle("POST /api/device/screenshot", ctrlMW(http.HandlerFunc(s.handleDeviceScreenshot)))
	s.mux.Handle("POST /api/device/ambient_audio", ctrlMW(http.HandlerFunc(s.handleDeviceAudio)))
	s.mux.Handle("POST /api/device/battery_status", ctrlMW(http.HandlerFunc(s.handleDeviceBattery)))
}

// ListenAndServe starts the control API on the configured port (default
// 8081; see config.AgentPort — a host may run a second agent on another
// port for a separate node identity).
//
// mTLS only. There is no plaintext branch: config.TLSServerConfig either
// returns a config that requires a cluster-CA client certificate or an
// error naming the missing material and the command that delivers it, and
// that error is returned here BEFORE any socket is bound. A node with no
// certificate is not "reachable without TLS"; it is not listening. (The
// plaintext fallback this replaced served every route in the clear to
// any TCP peer whenever the env lacked NOO_TLS_CERT.)
func (s *Server) ListenAndServe() error {
	tlsCfg, err := s.cfg.TLSServerConfig()
	if err != nil {
		return err
	}
	port := s.cfg.AgentPort
	if port == 0 {
		port = 8081
	}
	addr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:      addr,
		Handler:   s.mux,
		ErrorLog:  log.New(quietTLSLogger{}, "", 0),
		TLSConfig: tlsCfg,
	}
	slog.Info("control API starting with TLS", "addr", addr, "cert", s.cfg.TLSCert, "client_auth", "RequireAndVerifyClientCert")
	// Cert/key are already loaded into TLSConfig.Certificates.
	return server.ListenAndServeTLS("", "")
}

// ListenAndServeTLS starts with an externally provided TLS config.
func (s *Server) ListenAndServeWithTLS(tlsCfg *tls.Config) error {
	port := s.cfg.AgentPort
	if port == 0 {
		port = 8081
	}
	addr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:      addr,
		Handler:   s.mux,
		TLSConfig: tlsCfg,
	}
	slog.Info("control API starting with TLS", "addr", addr)
	return server.ListenAndServeTLS("", "")
}
