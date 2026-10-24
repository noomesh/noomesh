// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package heartbeat handles node registration and periodic heartbeat reporting
// to the gateway controller.
package heartbeat

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelstats"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

// Reporter sends registration and heartbeat messages to the gateway controller.
type Reporter struct {
	cfg         *config.Config
	client      *http.Client
	collector   *metrics.Collector
	gpu         *hardware.GPUDetector
	getBackends func() map[string]string
	// dataMounts: managed backend containers' host mount sources (1253).
	dataMounts func() (map[string][]string, error)
	// getRuntimes reports WHICH runtime serves each running backend —
	// "docker" or "native". nil until the agent installs it, and the key is
	// then OMITTED rather than sent empty: absence means "this agent build
	// does not report it", which a controller must not read as "everything
	// is docker".
	getRuntimes func() map[string]string
	// getLoaded reports what an adopted backend has in memory right now
	// (backend -> model), as distinct from the model it is placed to serve.
	// nil until installed; the key is then omitted.
	getLoaded  func() map[string]string
	activeJobs func() int
	// ollamaDoor resolves the dockerised ollama's door for the model
	// inventory (docker.BackendDialURL("ollama")); nil until installed.
	ollamaDoor func() string
	// getModelStats is the adopted lane's measured per-model sizes; the
	// container lane is read through ollamaDoor when it returns nothing.
	getModelStats func() []ModelStat
	// adoptedModels lists what the agent's adopted ollama lane holds
	// (backendrt.Native.Models), dialled with the transport the lane's base
	// needs. nil = no lane on this host, and the plaintext loopback probe
	// below stands in for it (a Linux native install).
	adoptedModels func() []string

	// hostState reports what this node's HOST SERVICES are actually doing —
	// today the harness. The controller has the placement
	// (intent) and, since 219, a refusal when a start FAILS; it has never
	// had the plain answer to "is it running now". Absence of a refusal is
	// not evidence of running: a unit stopped by hand refuses nothing.
	// nil = this agent build does not report it, and the key is omitted.
	hostState func() map[string]any

	// modelBench is the last POST /bench result (api.Server.LastBench),
	// sent as `model_bench` beside host_services. nil provider, or a nil
	// answer (no bench has run), omits the key: absent until a bench runs.
	modelBench func() any

	// hostdState reports the confined-root daemon's liveness and the op
	// names it advertises. `noo-apply` already reads that heartbeat FILE on
	// the node to decide whether a swap took; nothing carried it up, so the
	// controller cannot tell a node whose privileged helper is dead from
	// one whose helper is merely idle — and every op the agent delegates
	// goes through it. nil = not reported; omitted, never faked.
	hostdState func() map[string]any

	// logShipState reports the log shipper (fleet logging phase 3):
	// enabled, queued, shipped_total, last_accepted_unix, last_error —
	// what `noo cluster verify` judges a node's log shipping by. nil =
	// this agent build has no shipper and the key is omitted; a shipper
	// that is OFF still reports {enabled:false, last_error:<why>}, so
	// "off by choice" and "too old to ship" never look alike.
	logShipState func() map[string]any

	// backendContainers reports each running backend container's start
	// time and health, so `noo
	// cluster verify` can tell a door still warming up from a broken one.
	// nil = not installed, and the key is omitted; a provider that returns
	// nil (docker unlistable) omits it too — never faked as "none starting".
	backendContainers func() map[string]any

	// busStatus reports this node's own view of its NATS connection, echoed
	// on every heartbeat so the gateway can distinguish a node that is
	// HTTP-alive but bus-deaf from one that is simply quiet. Without it the
	// gateway can only INFER deafness from missing gossip, which is
	// indistinguishable from the gateway's own gossip subscriber being
	// broken. nil = this agent has no messaging at all.
	busStatus func() any

	// pullEmbed reports the bulk-embedding pull worker's models and whether
	// its consumers are bound. Nil = this node does not run the worker; the
	// key is then omitted.
	pullEmbed func() any

	// natsRPC reports whether control over the bus is live on this node
	// (subscription accepted by the server, no later refusal). nil = false.
	natsRPC func() bool
	// tunnel reports whether the node-held tunnel to the controller is up
	// right now (internal/tunnel). nil = this build has none.
	tunnel func() bool

	// gpuContention is the shared-GPU yield's report (internal/gpuyield),
	// sent as `gpu_contention`. nil = not wired; the key is then omitted.
	gpuContention func() any

	// Capabilities as reported at registration, echoed on EVERY heartbeat.
	//
	// These used to be sent once, at Register, and the controller kept them
	// only in the NATS KV record. A node whose KV entry was later rebuilt by
	// plain heartbeats — which happens after a controller outage — lost its
	// capabilities permanently, and `Node.can_run_backend()` then evaluated
	// `backend in []` and silently excluded it from every backend-filtered
	// job while it kept heartbeating and looking healthy. Observed on host8
	// 2026-07-31. Echoing them makes the value self-healing.
	caps *hardware.Capabilities

	// Delivery bookkeeping for noteOutcome. Touched only from the Run
	// loop's goroutine (SendHeartbeat is not called concurrently).
	failStreak  int
	silentSince time.Time
}

// NewReporter creates a heartbeat reporter.
func NewReporter(
	cfg *config.Config,
	client *http.Client,
	collector *metrics.Collector,
	gpu *hardware.GPUDetector,
	getBackends func() map[string]string,
	activeJobs func() int,
) *Reporter {
	return &Reporter{
		cfg:         cfg,
		client:      client,
		collector:   collector,
		gpu:         gpu,
		getBackends: getBackends,
		activeJobs:  activeJobs,
	}
}

// SetBackendRuntimes installs the per-backend runtime provider, echoed on
// every heartbeat as `backend_runtimes`.
func (r *Reporter) SetBackendRuntimes(f func() map[string]string) { r.getRuntimes = f }

// SetBackendContainers installs the backend container life reporter,
// echoed on registration and every heartbeat as `backend_containers`.
func (r *Reporter) SetBackendContainers(f func() map[string]any) { r.backendContainers = f }

// backendContainersReport is the value to send, or nil to omit the key.
func (r *Reporter) backendContainersReport() map[string]any {
	if r.backendContainers == nil {
		return nil
	}
	return r.backendContainers()
}

// SetLoadedModels installs the loaded-model reporter, echoed on every
// heartbeat as `loaded_models` when non-empty.
func (r *Reporter) SetLoadedModels(f func() map[string]string) { r.getLoaded = f }

// SetOllamaDoor installs the resolver for the dockerised ollama's door,
// used by the model inventory (availableModels).
func (r *Reporter) SetOllamaDoor(f func() string) { r.ollamaDoor = f }

// ModelStat is the heartbeat's measured per-model size entry.
type ModelStat = modelstats.ModelStat

// SetModelStats installs the adopted-lane model-stats source (`model_stats`).
func (r *Reporter) SetModelStats(f func() []ModelStat) { r.getModelStats = f }

// modelStats is the measured truth for the controller's memory-fit check:
// the adopted lane's, else the dockerised ollama's door (same transport as
// availableModels). Nil when neither answers.
func (r *Reporter) modelStats() []ModelStat {
	if r.getModelStats != nil {
		if st := r.getModelStats(); len(st) > 0 {
			return st
		}
	}
	if r.ollamaDoor == nil {
		return nil
	}
	base := strings.TrimRight(r.ollamaDoor(), "/")
	if base == "" {
		return nil
	}
	client := &http.Client{Timeout: 2 * time.Second}
	if strings.HasPrefix(base, "https://") && r.client != nil {
		client.Transport = r.client.Transport
	}
	get := func(path string) []byte {
		resp, err := client.Get(base + path)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return b
	}
	tags := get("/api/tags")
	if tags == nil {
		return nil
	}
	return modelstats.Parse(tags, get("/api/ps"))
}

// SetAdoptedModels installs the adopted-lane inventory (the self-node's
// stack ollama behind its mTLS door, or a Mac's native ollama). When set,
// it replaces the bare `http://localhost:11434` probe in availableModels.
func (r *Reporter) SetAdoptedModels(f func() []string) { r.adoptedModels = f }

// SetDataMounts installs the provider of each managed backend container's
// host bind-mount sources. Without one, data_roots is still
// reported, with running_mounts_error set.
func (r *Reporter) SetDataMounts(f func() (map[string][]string, error)) { r.dataMounts = f }

// dataRoots is the heartbeat's `data_roots`.
func (r *Reporter) dataRoots() map[string]any {
	return dataroots.Report(dataroots.Resolve(os.Getenv), r.dataMounts)
}

// SetHostState installs the host-service reporter (harness state, runtime).
func (r *Reporter) SetHostState(f func() map[string]any) { r.hostState = f }

// SetModelBench installs the last-bench reporter, sent as `model_bench`.
func (r *Reporter) SetModelBench(f func() any) { r.modelBench = f }

// SetHostdState installs the confined-root daemon reporter.
func (r *Reporter) SetHostdState(f func() map[string]any) { r.hostdState = f }

// SetLogShipState installs the log shipper reporter, echoed on every
// heartbeat as `log_ship`.
func (r *Reporter) SetLogShipState(f func() map[string]any) { r.logShipState = f }

// SetGPUContention installs the shared-GPU yield reporter, echoed on
// registration and every heartbeat as `gpu_contention`.
func (r *Reporter) SetGPUContention(f func() any) { r.gpuContention = f }

func (r *Reporter) gpuContentionReport() any {
	if r.gpuContention == nil {
		return nil
	}
	return r.gpuContention()
}

// SetBusStatus installs the NATS status provider whose value is echoed on
// every heartbeat as `nats_status`.
func (r *Reporter) SetBusStatus(f func() any) { r.busStatus = f }

// SetPullEmbed installs the provider of the heartbeat's pull_embed field,
// {"models": [...], "bound": bool}. For humans and the console; the gateway
// routes on the consumer's own state, not on this claim.
func (r *Reporter) SetPullEmbed(f func() any) { r.pullEmbed = f }

// SetNatsRPC installs the probe behind control_transports.nats_rpc. The
// agent passes ctrlrpc.Service.Ready, so the field is true only while the
// node can actually answer a control call on the bus.
func (r *Reporter) SetNatsRPC(f func() bool) { r.natsRPC = f }

// SetTunnel installs the probe behind control_transports.tunnel. The agent
// passes tunnel.Client.Connected, so the field is true only while the tunnel
// is up and the controller can send streaming calls down it.
func (r *Reporter) SetTunnel(f func() bool) { r.tunnel = f }

// natsStatus returns the value to send. nil when no provider is installed —
// a heartbeat that omits the field means "this agent build does not report
// it", which the gateway must not read as either connected or disconnected.
func (r *Reporter) natsStatus() any {
	if r.busStatus == nil {
		return nil
	}
	return r.busStatus()
}

// Register sends a registration request to the controller.
func (r *Reporter) Register(caps hardware.Capabilities, hostIP string) bool {
	// Remember for the heartbeat echo (see Reporter.caps).
	r.caps = &caps
	selfURL := agentURL(r.cfg)
	payload := map[string]any{
		"node_id":    r.cfg.NodeID,
		"hostname":   r.cfg.NodeID,
		"ip_address": hostIP,
	}
	// The fields a registration shares with every beat are assembled by the
	// same sections the heartbeat runs, so each is built in exactly one place.
	for _, sec := range registerSections {
		sec.add(r, payload)
	}
	setDialableAddress(payload, hostIP, selfURL)

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("registration marshal failed", "error", err)
		return false
	}

	endpoint := fmt.Sprintf("%s/api/cluster/nodes/register", r.cfg.ControllerURL)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		slog.Error("registration request failed", "error", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	r.setAuthHeader(req)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Error("registration error", "error", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		slog.Info("registered with controller")
		return true
	}
	slog.Error("registration failed", "status", resp.StatusCode)
	return false
}

// stageClock times the stages of one heartbeat so a slow beat can name
// what was slow. The controller only ever sees the gap; the agent is the
// one place that can say which probe caused it.
type stageClock struct {
	start, last time.Time
	slowest     string
	slowestTook time.Duration
}

func newStageClock() *stageClock {
	now := time.Now()
	return &stageClock{start: now, last: now}
}

// mark closes the stage that just ran.
func (c *stageClock) mark(stage string) {
	now := time.Now()
	if took := now.Sub(c.last); took > c.slowestTook {
		c.slowest, c.slowestTook = stage, took
	}
	c.last = now
}

func (c *stageClock) total() time.Duration { return time.Since(c.start) }

// SendHeartbeat sends a heartbeat with current metrics.
//
// It is the only body the Run loop executes, so everything it waits on is
// time the controller sees as silence: a Go ticker drops the ticks a slow
// receiver misses, and a Reporter that spends four minutes in here has sent
// nothing for four minutes. Each stage is timed; a beat that outlives its
// own interval says so, naming the stage, at WARN — the outage this
// diagnoses is invisible from the controller and used to be invisible here
// too (the only log line on the failure path was DEBUG).
func (r *Reporter) SendHeartbeat() {
	clk := newStageClock()

	m := r.collector.Collect()
	clk.mark("metrics")

	gpuModel := r.cfg.GPUModel
	if gpuModel == "" {
		gpuModel = r.gpu.DetectModel()
	}
	vramGB := r.cfg.VRAMGB
	if vramGB == 0 {
		vramGB = r.gpu.DetectVRAM()
	}
	clk.mark("gpu_identity")
	power := hardware.ReadPowerStatus()
	clk.mark("power")
	backends := r.getBackends()
	clk.mark("backends")
	jobs := r.activeJobs()
	clk.mark("jobs")
	hostIP := DetectHostIP(r.cfg)
	selfURL := agentURL(r.cfg)
	clk.mark("host_ip")
	models := r.availableModels()
	clk.mark("models")
	sensors := hardware.DetectSensors()
	clk.mark("sensors")

	payload := map[string]any{
		"load":             m.Load,
		"running_backends": backends,
		"self_node":        r.cfg.SelfNode,
		"active_jobs":      jobs,
		"cpu_load":         m.CPULoad,
		"mem_used_gb":      m.MemUsedGB,
		"vram_used_gb":     m.VRAMUsedGB,
		"gpu_model":        gpuModel,
		"cpu_cores":        hardware.CPUCores(),
		"ram_gb":           hardware.TotalMemoryGB(),
		"vram_gb":          vramGB,
		"tier":             r.cfg.Tier,
		"ip_address":       hostIP,
		// Interface this node published its control API on. Empty
		// or 0.0.0.0 = all interfaces; a tailnet IP = confined to the overlay.
		// Broadcast so the controller/dashboard can verify each node's binding.
		"bind_addr": os.Getenv("NOO_BIND_ADDR"),
		// Geographic/site label for this node (NODE_LOCATION). Resolved on the
		// host launcher (explicit env or Tailscale DERP region) so the eval
		// report and dashboard show real locations instead of a placeholder.
		"location": os.Getenv("NODE_LOCATION"),
		// Models this node has locally (Ollama tags + GGUFs in MODELS_DIR), so
		// the controller can place models by availability, not just capability.
		"available_models": models,
		// Report our own control-API URL (see agentURL).
		"agent_url":      selfURL,
		"active_sensors": sensors,
	}
	r.companionTelemetry(payload, power)
	setDialableAddress(payload, hostIP, selfURL)

	for _, sec := range heartbeatSections {
		sec.add(r, payload)
		if sec.stage != "" {
			clk.mark(sec.stage)
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		r.noteOutcome(clk, fmt.Errorf("heartbeat marshal failed: %w", err))
		return
	}

	endpoint := fmt.Sprintf("%s/api/cluster/nodes/%s/heartbeat", r.cfg.ControllerURL, r.cfg.NodeID)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		r.noteOutcome(clk, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	r.setAuthHeader(req)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := r.client.Do(req)
	if err != nil {
		r.noteOutcome(clk, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		slog.Warn("heartbeat 404, re-registering")
		caps := hardware.Detect(r.cfg, r.gpu)
		hostIP := DetectHostIP(r.cfg)
		r.Register(caps, hostIP)
		r.noteOutcome(clk, nil)
	} else if resp.StatusCode != 200 {
		r.noteOutcome(clk, fmt.Errorf("controller answered HTTP %d", resp.StatusCode))
	} else {
		r.noteOutcome(clk, nil)
	}
}

// noteOutcome closes the beat: it records delivery or its failure, and it
// says so at a level someone will see.
//
// Failures log at WARN on the first miss and every tenth after, with the
// streak, so a controller that is down for an hour costs twelve lines, not
// a hundred and twenty; recovery logs once at INFO with how long the node
// was silent from the controller's point of view. A beat that took longer
// than the heartbeat interval logs at WARN whether or not it was delivered,
// because the controller saw silence for that long either way — and names
// the stage that spent the time, which is the fact nothing upstream can
// recover.
func (r *Reporter) noteOutcome(clk *stageClock, err error) {
	clk.mark("post")
	interval := time.Duration(r.cfg.HeartbeatInterval) * time.Second
	if took := clk.total(); interval > 0 && took > interval {
		slog.Warn("heartbeat took longer than its interval",
			"took", took.Round(time.Millisecond),
			"interval", interval,
			"slowest_stage", clk.slowest,
			"slowest_took", clk.slowestTook.Round(time.Millisecond),
			"effect", "the controller saw no heartbeat from this node for that long; "+
				"it reads as offline while the control API keeps answering")
	}

	if err != nil {
		if r.failStreak == 0 {
			r.silentSince = clk.start
		}
		r.failStreak++
		if r.failStreak == 1 || r.failStreak%10 == 0 {
			slog.Warn("heartbeat not delivered",
				"error", err,
				"streak", r.failStreak,
				"silent_for", time.Since(r.silentSince).Round(time.Second),
				"controller", r.cfg.ControllerURL)
		}
		return
	}
	if r.failStreak > 0 {
		slog.Info("heartbeat delivery resumed",
			"after_failures", r.failStreak,
			"silent_for", time.Since(r.silentSince).Round(time.Second))
		r.failStreak = 0
		r.silentSince = time.Time{}
	}
}

// Run starts the heartbeat loop. Blocks until ctx is cancelled.
func (r *Reporter) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(r.cfg.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.SendHeartbeat()
		}
	}
}

func (r *Reporter) setAuthHeader(req *http.Request) {
	if r.cfg.ClusterSecret != "" {
		auth.SetClusterAuth(req, r.cfg.NodeID, r.cfg.ClusterSecret)
	}
}

// agentURL builds this agent's control-API URL for registration.
//
// Always https — the cluster does not support plaintext between nodes.
func agentURL(cfg *config.Config) string {
	port := cfg.AgentPort
	if port == 0 {
		port = 8081
	}
	ip := DetectHostIP(cfg)
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("https://%s", net.JoinHostPort(ip, strconv.Itoa(port)))
}

// DialableAgentURL is the agent_url the heartbeat registers, or "" when this
// node has no address another host could dial (setDialableAddress registers
// none either). Mesh discovery offers this same value so the node names one
// address, not two.
func DialableAgentURL(cfg *config.Config) string {
	if usableHostIP([]string{DetectHostIP(cfg)}) == "" {
		return ""
	}
	return agentURL(cfg)
}

// DetectHostIP determines the host IP address for registration.
// Priority: NODE_IP env > UDP socket detection > hostname fallback.
func DetectHostIP(cfg *config.Config) string {
	if cfg.NodeIP != "" {
		return cfg.NodeIP
	}

	// Parse controller host:port for source IP detection
	parsed, err := url.Parse(cfg.ControllerURL)
	if err == nil {
		host := parsed.Hostname()
		port := parsed.Port()
		if port == "" {
			port = "80"
		}
		addr := net.JoinHostPort(host, port)
		// UDP dial doesn't send packets — it just resolves the route
		conn, err := net.DialTimeout("udp", addr, 2*time.Second)
		if err == nil {
			defer conn.Close()
			if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				return localAddr.IP.String()
			}
		}
	}

	// Fallback: the hostname's addresses — but ONLY one the controller can
	// dial. On Debian-family hosts the hostname resolves to 127.0.1.1 and to
	// nothing else; returning that (or a bare hostname, or 127.0.0.1) told
	// the controller to route this node's inference to itself. host3 did
	// exactly that on 2026-09-22 whenever the UDP detection above failed:
	// ~200 chat completions a minute came back 502. Empty means "no
	// dialable address known" and the caller OMITS the field, so the
	// controller keeps the last good one.
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return ""
	}
	return usableHostIP(addrs)
}

// setDialableAddress records where the controller may reach this node — or
// records NOTHING when no such address is known.
//
// Absent beats wrong. The controller seeds each heartbeat from the node's
// existing entry, so an omitted field keeps the last good address; a loopback
// or a bare hostname replaces it with one the controller then dials as if it
// were remote. host3's hostname resolves to 127.0.1.1 and nothing else, and on
// 2026-09-22 every heartbeat that fell back to it had the controller route
// this node's chat completions to itself: ~200 a minute answered 502.
func setDialableAddress(payload map[string]any, hostIP, selfURL string) {
	if hostIP == "" || usableHostIP([]string{hostIP}) == "" {
		delete(payload, "ip_address")
		delete(payload, "agent_url")
		return
	}
	payload["ip_address"] = hostIP
	if selfURL != "" {
		payload["agent_url"] = selfURL
	}
}

// usableHostIP picks the first address another host could dial, or "".
// Loopback, unspecified and link-local never name this machine to anyone
// else; a value that does not parse as an IP is not an address at all.
func usableHostIP(addrs []string) string {
	for _, a := range addrs {
		ip := net.ParseIP(strings.TrimSpace(a))
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			continue
		}
		return ip.String()
	}
	return ""
}

// availableModels lists model names this node has locally — Ollama tags plus
// GGUF files in MODELS_DIR — so the controller can place models by availability
// (cached-model reporting, the self-managing-fleet inventory). Best-effort and
// bounded; returns nil on failure.
func (r *Reporter) availableModels() []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		if s == "" || seen[s] || len(out) >= 200 {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	// 1. Ollama /api/tags — the container's door first (the stunnel sidecar,
	// a client certificate required: r.client's transport presents the node
	// leaf; the door resolver reads the running containers' declaration),
	// then the HOST-NATIVE ollama on loopback.
	//
	// localhost:11434 is the one plaintext backend door on a node, by
	// design: it is the operator's own ollama outside Docker (macOS Metal,
	// or a Linux native install the agent adopts — backendrt), bound to the
	// host's loopback, so the bytes never leave the host and no container
	// on the bridge can reach it. The agent does not own that process and
	// runs no listener in front of it.
	//
	// When the agent has an ADOPTED lane (the self-node's stack ollama, a
	// Mac's native one) the lane answers instead of the bare probe: on the
	// controller's own node localhost:11434 is the stunnel-ollama-embed
	// door (verify = 2), which a bare client cannot pass —
	// the lane dials it with the node leaf.
	bases := []string{"http://localhost:11434"}
	if r.adoptedModels != nil {
		bases = nil
	}
	if r.ollamaDoor != nil {
		if door := strings.TrimRight(r.ollamaDoor(), "/"); door != "" {
			bases = append([]string{door}, bases...)
		}
	}
	for _, base := range bases {
		client := &http.Client{Timeout: 2 * time.Second}
		if strings.HasPrefix(base, "https://") && r.client != nil {
			client.Transport = r.client.Transport
		}
		resp, err := client.Get(base + "/api/tags")
		if err != nil {
			continue
		}
		var body struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		for _, m := range body.Models {
			add(m.Name)
		}
		if len(body.Models) > 0 {
			break
		}
	}

	if r.adoptedModels != nil {
		for _, m := range r.adoptedModels() {
			add(m)
		}
	}

	// 2. GGUF files at the top level of MODELS_DIR.
	if dir := os.Getenv("MODELS_DIR"); dir != "" {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".gguf") {
					add(strings.TrimSuffix(e.Name(), ".gguf"))
				}
			}
		}
	}
	return out
}

// servedCertNotAfter reports the NotAfter (unix seconds) of the node cert
// this PROCESS is serving. Captured once at first use: the TLS listener
// loads the keypair at startup, so re-reading the file every beat would
// report a swapped-on-disk cert the running process is not actually
// presenting — the exact lie this field exists to prevent. 0 = unknown.
var servedCertOnce sync.Once
var servedCertExpiry int64

func servedCertNotAfter(certPath string) int64 {
	servedCertOnce.Do(func() {
		if certPath == "" {
			return
		}
		data, err := os.ReadFile(certPath)
		if err != nil {
			return
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return
		}
		servedCertExpiry = cert.NotAfter.Unix()
	})
	return servedCertExpiry
}

// UsableHostIP returns ip when it is an address the controller could dial
// (not loopback, unspecified, link-local or multicast), else "". The API
// listener uses it to decide whether it knows where to bind.
func UsableHostIP(ip string) string { return usableHostIP([]string{ip}) }

// controlTransports reports how the controller can reach this agent. The
// HTTPS listener is always offered; "nats_rpc" is true only while control
// over the bus is live (the subscription was accepted by the server and no
// permission refusal has been seen since); "tunnel" is true only while the
// node-held tunnel to the controller is connected, so a gateway never routes
// a stream into a tunnel that is not there.
func (r *Reporter) controlTransports() map[string]bool {
	rpc := r.natsRPC != nil && r.natsRPC()
	tun := r.tunnel != nil && r.tunnel()
	return map[string]bool{"https_listener": true, "nats_rpc": rpc, "tunnel": tun}
}
