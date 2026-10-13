// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package agent wires all node-agent subsystems together and runs the main loop.
//
// This is the top-level orchestrator, equivalent to Python's NodeAgent.run().
// It starts the HTTP API server, NATS messaging, heartbeat loop, mesh responder,
// and gossip announcer as concurrent goroutines.
package agent

import (
	"context"
	"fmt"
	"github.com/noomesh/noomesh/node-agent-go/internal/diskreclaim"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/api"
	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/containerdial"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/gpuwatch"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/heartbeat"
	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
	"github.com/noomesh/noomesh/node-agent-go/internal/hostsvc"
	"github.com/noomesh/noomesh/node-agent-go/internal/jobs"
	"github.com/noomesh/noomesh/node-agent-go/internal/logship"
	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
	"github.com/noomesh/noomesh/node-agent-go/internal/reconcile"
)

// Agent is the top-level node agent orchestrator.
type Agent struct {
	cfg    *config.Config
	docker *dockerpkg.Client
	gpu    *hardware.GPUDetector
	coll   *metrics.Collector
	http   *http.Client

	nats   *messaging.Client
	jobs   *jobs.Executor
	hb     *heartbeat.Reporter
	server *api.Server
	mesh   *messaging.MeshResponder
	gossip *messaging.GossipAnnouncer

	// native probes backends served outside Docker (darwin/Metal). nil off
	// darwin, where there is no native lane.
	native *backendrt.Native
	// ollama guards the Mac's brew-run native ollama against vendor
	// telemetry (backendrt/ollama_telemetry.go). nil off darwin.
	ollama *backendrt.OllamaGuard
	// harness is the host service this node regulates; the
	// reconciler drives it and the heartbeat reports it.
	harness hostsvc.Service
}

// runningBackends is what this node is ACTUALLY serving, from both runtimes.
//
// One function, used by the heartbeat, the mesh responder and gossip alike,
// so those three can never disagree about what is running — they previously
// each called docker.RunningBackends directly, and a second runtime would
// otherwise have had to be remembered at every one of them.
//
// Docker wins a key collision: a real container under that name is the thing
// the reconciler manages and the spec hash describes.
func (a *Agent) runningBackends() map[string]string {
	out, _ := a.runningBackendsWithRuntime()
	return out
}

// runningBackendsWithRuntime is the same map plus WHICH runtime serves each
// key: "docker" (this agent starts and stops it) or "native" (a host process
// this agent found and reports but does not manage).
//
// Both look identical in `running_backends` — one word, two relationships —
// and the difference decides whether a placement can ever converge. On a Mac
// `noo cluster place <node> ollama <model>` is accepted, recorded, skipped by
// the reconciler, and shows in `cluster desired` as a placement that will
// never happen. The only way to learn why was to try to start it and read a
// 501, or read the agent's log.
//
// So the runtime travels beside the map rather than being inferred from the
// platform: once a native llama-server exists, "managed" becomes a
// per-BACKEND fact on the same node, and a platform assumption would be
// wrong again.
func (a *Agent) runningBackendsWithRuntime() (map[string]string, map[string]string) {
	out := a.docker.RunningBackends()
	rt := make(map[string]string, len(out))
	for b := range out {
		rt[b] = "docker"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for b, m := range a.native.Running(ctx) {
		if _, taken := out[b]; !taken {
			out[b] = m
			rt[b] = a.native.Runtime()
		}
	}
	// The harness is a host service, reported from the init
	// system — never from `docker ps`, which is where it used to be
	// invisible for two days while crash-looping.
	if a.harness != nil && a.harness.State(ctx) == hostsvc.Running {
		out["harness"] = "auto"
		rt["harness"] = a.harness.Runtime()
	}
	return out, rt
}

// backendRuntimes is the runtime map alone, for the heartbeat.
func (a *Agent) backendRuntimes() map[string]string {
	_, rt := a.runningBackendsWithRuntime()
	return rt
}

// New creates and wires a new Agent from configuration.
func New(cfg *config.Config) (*Agent, error) {
	// Auto-detect node ID
	if cfg.NodeID == "auto" {
		hostname, err := os.Hostname()
		if err != nil {
			cfg.NodeID = "unknown"
		} else {
			cfg.NodeID = hostname
		}
	}

	// A secret the env points at but that cannot be read, or one set both
	// as NAME and NAME_FILE, is a broken delivery: refuse to start naming
	// it, rather than come up unauthenticated. The whole
	// manifest is checked, not only what Load read, so the NATS pair fails
	// here too and not later from the connect loop.
	if err := config.CheckSecrets(os.Getenv); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	slog.Info("secret reader", "capability", config.SecretFilesCapability)

	// The control API is mTLS-only: refuse here, before anything is wired,
	// rather than from a goroutine the caller cannot see. The error names
	// the missing material and `noo cluster provision <node>`.
	if _, err := cfg.TLSServerConfig(); err != nil {
		return nil, fmt.Errorf("control API: %w", err)
	}

	// Build HTTP transport with TLS
	transport, err := cfg.HTTPTransport()
	if err != nil {
		return nil, fmt.Errorf("http transport: %w", err)
	}
	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	// Docker client. Tier 5 = sensor proxy: no backend management, its
	// container has no docker.sock by design — the client degrades to
	// warn-and-fail-per-call instead of refusing to start.
	docker, err := dockerpkg.NewClient(httpClient, cfg.Scheme(), cfg.ComposeProject, cfg.Tier == 5)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}

	// Host-mode backend dialing: as a host process the
	// docker-DNS backend names resolve nowhere, so swap them for container
	// bridge IPs at the socket layer. Install is a no-op in a container
	// (returns nil), which keeps the containerised path byte-identical. It
	// also wraps http.DefaultTransport, covering the bare clients in the
	// tree; the shared transport and the api proxies adopt the same dialer.
	if dial := containerdial.Install(docker); dial != nil {
		transport.DialContext = dial
		api.BackendDialContext = dial
		slog.Info("host-mode container dialer installed — backend names resolve via docker inspect")
	}

	// Hardware detection
	gpu := hardware.NewGPUDetector(httpClient, cfg.Scheme())
	coll := metrics.NewCollector(gpu)

	// The Agent is referenced by the heartbeat's backend provider below, so
	// declare it before the closure and fill it in at the end. Passing
	// docker.RunningBackends directly is what kept a native backend out of
	// the heartbeat — the one report the controller actually routes from.
	var a *Agent

	// Heartbeat reporter
	hb := heartbeat.NewReporter(
		cfg, httpClient, coll, gpu,
		func() map[string]string { return a.runningBackends() },
		func() int { return 0 }, // updated after jobs executor is wired
	)
	hb.SetBackendContainers(backendContainersOf(docker, cfg.Tier))

	// API server
	server := api.NewServer(cfg, docker, gpu, coll)

	a = &Agent{
		cfg:     cfg,
		docker:  docker,
		gpu:     gpu,
		coll:    coll,
		http:    httpClient,
		hb:      hb,
		server:  server,
		native:  backendrt.NewAdopted(),
		ollama:  nativeOllamaGuard(),
		harness: hostsvc.New(),
	}

	slog.Info("node agent initialized",
		"node_id", cfg.NodeID,
		"controller", cfg.ControllerURL,
		"tier", cfg.Tier,
		"cluster_auth", cfg.ClusterSecret != "",
	)

	return a, nil
}

// Run starts all subsystems and blocks until interrupted.
func (a *Agent) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 1. Start HTTP API server (in background so node is reachable during
	//    registration). A listener that fails to come up is FATAL for the
	//    agent: it used to log and carry on, registering a node the
	//    controller could never dial.
	srvErr := make(chan error, 1)
	go func() {
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("control API failed", "error", err)
			srvErr <- err
		}
	}()
	slog.Info("control API started", "port", a.cfg.AgentPort)

	if a.ollama != nil {
		go a.convergeOllama(ctx)
	}

	// 2. Start NATS messaging
	a.startMessaging(ctx)
	time.Sleep(2 * time.Second) // give messaging time to connect

	// 3. Register with controller (retry until available)
	caps := hardware.Detect(a.cfg, a.gpu)
	hostIP := heartbeat.DetectHostIP(a.cfg)
	slog.Info("registering with controller", "ip", hostIP)

	for !a.hb.Register(caps, hostIP) {
		slog.Warn("waiting for controller")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}

	// Publish registration event
	if a.nats != nil {
		a.nats.PublishNodeEvent("node.registered", map[string]any{
			"hostname":     a.cfg.NodeID,
			"tier":         a.cfg.Tier,
			"capabilities": caps,
		})
	}

	// 4. Start heartbeat loop
	go a.hb.Run(ctx)

	// 4a. GPU watchdog — only where a GPU is actually detected.
	// Derives its watch list from container configs each cycle; verdicts
	// ride the /gpu payload for the controller's gpu_health evaluator.
	if caps.GPUCount > 0 {
		wd := gpuwatch.New(a.docker, func() bool { return a.gpu.DetectModel() != "" })
		// A backend that ANSWERS is never restarted on a GPU probe alone.
		// The container name is `noo-<backend>`, which is the same mapping
		// the inference proxy uses to address it.
		wd.SetServingProbe(func(ctx context.Context, container string) bool {
			backend := strings.TrimPrefix(container, "noo-")
			base := a.docker.BackendDialURL(backend)
			if base == "" {
				return false
			}
			return backendAnswers(ctx, a.http, base)
		})
		a.server.SetGPUWatch(func() any { return wd.State() })
		go wd.Run(ctx)
		slog.Info("GPU watchdog started", "interval", "5m")
	}

	// 4b. Desired-state reconcile loop — pulls DB-backed node config +
	// backend placements from the controller and converges (dirs via
	// helper containers, backends via StartBackendSDK). See
	// DESIRED_STATE_CONFIG.md.
	rec := reconcile.New(a.cfg, a.docker, a.http, a.harness)
	a.server.SetMCP(rec.MCP())

	// 4b'. Node disk reclaim: the controller's ladder cannot reach this
	// disk, so the agent queues the same ladder into its local hostd when
	// a disk crosses the watermark, under the controller's policy.
	reclaimer := diskreclaim.New(hostd.WorkerSpoolDir)
	rec.SetDiskReclaimSink(reclaimer.SetPolicy)
	a.server.SetDiskReclaim(func() any { return reclaimer.State() })
	go reclaimer.Run(ctx)
	go rec.Run(ctx)

	// 4c. Log shipping (fleet logging phase 3): container stdout/stderr
	// and, via hostd's journal-follow, the host units — pushed to the
	// controller's ingest route with the node leaf. Starts only once the
	// controller answers the route, so an agent rolled before its gateway
	// idles harmlessly. The heartbeat carries its state either way.
	a.startLogShip(ctx)

	// 5. Wait for shutdown signal
	select {
	case err := <-srvErr:
		cancel()
		a.shutdown()
		return fmt.Errorf("control API: %w", err)
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig)
	}
	cancel()

	// Cleanup
	a.shutdown()
	return nil
}

func (a *Agent) startMessaging(ctx context.Context) {
	// Connect no longer fails just because the bus is down: it returns a
	// client that keeps retrying in the background and fires the reconnect
	// hooks once it lands. An error here means the configuration itself is
	// unusable.
	natsClient, err := messaging.Connect(a.cfg.NATSURL, a.cfg.NodeID)
	if err != nil {
		slog.Error("NATS client could not be created — running without messaging",
			"error", err, "url", logship.ScrubURLUserinfo(a.cfg.NATSURL))
		return
	}
	a.nats = natsClient

	// Give the initial connect a moment to land so the common case binds its
	// subscriptions synchronously. If it doesn't, we carry on regardless —
	// the reconnect hooks bind whenever the bus comes back.
	if natsClient.WaitForConnection(ctx, 5*time.Second) {
		slog.Info("NATS connected", "url", logship.ScrubURLUserinfo(a.cfg.NATSURL))
	} else {
		slog.Warn("NATS not connected yet — subscriptions will bind on connect",
			"url", logship.ScrubURLUserinfo(a.cfg.NATSURL))
	}

	// Publish the bus state on /health as soon as the client exists, so a
	// node that never manages to connect is visible immediately.
	a.server.SetBusStatus(a.busStatus)

	// Wire up job executor with real active count
	a.jobs = jobs.NewExecutor(
		a.nats, a.docker, a.http, a.cfg.Scheme(),
		a.cfg.ControllerURL, a.cfg.NodeID,
	)

	// Re-wire heartbeat with job count + bus status
	a.hb = heartbeat.NewReporter(
		a.cfg, a.http, a.coll, a.gpu,
		a.runningBackends,
		a.jobs.ActiveCount,
	)
	a.hb.SetBusStatus(func() any { return a.busStatus() })
	a.hb.SetBackendRuntimes(a.backendRuntimes)
	a.hb.SetLoadedModels(func() map[string]string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return a.native.Loaded(ctx)
	})
	a.hb.SetDataMounts(a.docker.ManagedDataMounts)
	a.hb.SetHostState(a.hostServices)
	a.hb.SetHostdState(a.hostdStatus)
	a.hb.SetBackendContainers(a.backendContainers)
	a.hb.SetOllamaDoor(func() string { return a.docker.BackendDialURL("ollama") })
	if a.native != nil {
		a.hb.SetModelStats(func() []heartbeat.ModelStat {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return a.native.ModelStats(ctx)
		})
		a.hb.SetAdoptedModels(func() []string {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return a.native.Models(ctx)
		})
	}

	// Subscribe to job dispatches, then keep the binding repaired.
	if err := a.jobs.Subscribe(); err != nil {
		slog.Error("job subscription failed", "error", err)
	}
	go a.jobs.EnsureBound(ctx)

	// Start mesh responder
	scheme := a.cfg.Scheme()
	a.mesh = messaging.NewMeshResponder(
		a.nats, a.cfg.NodeID,
		func() map[string]messaging.BackendInfo {
			return meshBackendInfos(a.runningBackends(), heartbeat.DialableAgentURL(a.cfg), scheme)
		},
		func() float64 {
			return a.coll.Collect().Load
		},
	)
	if err := a.mesh.Start(); err != nil {
		slog.Warn("mesh responder failed to start", "error", err)
	}

	// Start gossip announcer
	interval := time.Duration(a.cfg.HeartbeatInterval) * time.Second
	rtCaps := &hardware.RuntimeCapabilityDetector{
		GetRunningBackends: a.runningBackends,
		ListContainers:     a.docker.ContainerNames,
	}

	a.gossip = messaging.NewGossipAnnouncer(
		a.nats, a.cfg.NodeID,
		func() map[string]any {
			backends := a.runningBackends()
			backendInfo := make(map[string]any)
			for bt, model := range backends {
				port := dockerpkg.BackendPorts[bt]
				if port > 0 {
					backendInfo[bt] = map[string]string{
						"model": model,
						"url":   dockerpkg.BackendURL(bt, scheme),
					}
				}
			}
			return map[string]any{
				"hostname":     a.cfg.NodeID,
				"backends":     backendInfo,
				"load":         a.coll.Collect().Load,
				"tier":         a.cfg.Tier,
				"vram_gb":      a.cfg.VRAMGB,
				"capabilities": rtCaps.Detect(),
			}
		},
		interval,
	)
	a.gossip.Start()
}

// busStatus builds the node's own view of its NATS bus for /health and the
// heartbeat. It combines the connection state with whether the job-dispatch
// durable is actually bound — connected-but-unbound is a distinct failure
// (the 2026-07-03 stranded-jobs shape) and must not read as healthy.
func (a *Agent) busStatus() api.BusStatus {
	st := a.nats.Status() // nil-safe: reports "unavailable"

	bound := false
	if a.jobs != nil {
		bound = a.jobs.Bound()
	}

	detail := ""
	switch {
	case st.State == messaging.StateUnavailable:
		detail = "no NATS client on this agent — messaging never initialised"
	case st.Connected && bound:
		detail = "connected; tasks.dispatch durable is bound"
	case st.Connected && !bound:
		detail = "connected but the tasks.dispatch durable is NOT bound — dispatched jobs will strand"
	case st.State == messaging.StateClosed:
		detail = "connection closed by the client library; the watchdog is rebuilding it"
	case st.State == messaging.StateConnecting:
		detail = "never connected since agent start — retrying"
	default:
		detail = "disconnected; nats.go is retrying. Jobs dispatched to this node will strand until it returns"
	}

	return api.BusStatus{
		State:              st.State,
		Connected:          st.Connected,
		LastConnectedAt:    st.LastConnectedAt,
		LastDisconnectedAt: st.LastDisconnectedAt,
		DisconnectedForSec: st.DisconnectedForSec,
		Connects:           st.Connects,
		URL:                st.URL,
		JobDispatchBound:   bound,
		Detail:             detail,
		User:               st.User,
		Role:               st.Role,
	}
}

func (a *Agent) shutdown() {
	if a.gossip != nil {
		a.gossip.Stop()
	}
	if a.mesh != nil {
		a.mesh.Stop()
	}
	if a.nats != nil {
		a.nats.Close()
	}
	if a.docker != nil {
		a.docker.Close()
	}
}

// backendAnswers reports whether a backend is serving, by asking it the
// cheapest question an OpenAI-shaped server can answer.
//
// Used by the GPU watchdog before it restarts anything: a container that is
// answering requests must not be recycled because a side-channel probe
// disagrees. The bar is deliberately low — any HTTP response at all, including
// a 404, proves a server is listening and handling requests. Only a transport
// failure counts as "not serving".
func backendAnswers(ctx context.Context, client *http.Client, base string) bool {
	for _, path := range []string{"/v1/models", "/health"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		return true
	}
	return false
}

// startLogShip wires the shipper's sources for this platform and starts
// it, or records why it is off. The heartbeat field is installed in both
// cases — see heartbeat.SetLogShipState for why "off" is still reported.
func (a *Agent) startLogShip(ctx context.Context) {
	if ok, why := a.cfg.LogShipEnabled(); !ok {
		slog.Info("log shipping off", "reason", why)
		a.hb.SetLogShipState(func() map[string]any { return logship.DisabledState(why) })
		return
	}
	s, err := logship.New(logship.Config{
		NodeID:        a.cfg.NodeID,
		ControllerURL: a.cfg.ControllerURL,
		Client:        a.http,
		Auth: func(req *http.Request) {
			if a.cfg.ClusterSecret != "" {
				req.Header.Set("Authorization", "Bearer "+auth.CreateClusterToken(a.cfg.NodeID, a.cfg.ClusterSecret))
			}
		},
		StateDir: a.cfg.StateDir,
	})
	if err != nil {
		slog.Error("log shipping not started", "error", err)
		msg := err.Error()
		a.hb.SetLogShipState(func() map[string]any { return logship.DisabledState(msg) })
		return
	}
	// Containers: every node with a docker socket (a tier-5 sensor proxy
	// has none and lists nothing — harmless).
	s.AddSource(logship.NewDockerSource(a.docker))

	var journal *logship.JournalSource
	if runtime.GOOS == "darwin" {
		// launchd jobs write files; tail those. Whatever is unreadable or
		// absent on this Mac simply never yields a line.
		//
		// The agent's own log first: provision.rs's plist sends its stdout
		// and stderr to /tmp/noomesh-agent.log. Without it a healthy, quiet
		// Mac shipped nothing — hostd and the harness are silent between
		// events — and `noo cluster verify` failed "logs last seen" on
		// host6 while every Linux node shipped its agent's
		// journal unit.
		s.AddSource(logship.NewFileSource("/tmp/noomesh-agent.log", "noo-agent", a.cfg.StateDir))
		s.AddSource(logship.NewFileSource("/var/log/noo-hostd.log", "noo-hostd", a.cfg.StateDir))
		s.AddSource(logship.NewFileSource("/tmp/noomesh-harness.log", "noo-harness", a.cfg.StateDir))
		// Tailscale's own log stays on the node now that its upload is off
		// (docs/security/telemetry.md): the brew formula's service writes it
		// here (Apple silicon, then Intel prefix); Loki name=tailscaled, the
		// same as the Linux journal unit. A path that does not exist yields nothing.
		s.AddSource(logship.NewFileSource("/opt/homebrew/var/log/tailscaled.log", "tailscaled", a.cfg.StateDir))
		s.AddSource(logship.NewFileSource("/usr/local/var/log/tailscaled.log", "tailscaled", a.cfg.StateDir))
	} else {
		// Empty = follow hostd's own allowlist (see JournalSource.check):
		// only an operator's explicit NOO_LOG_SHIP_UNITS narrows it.
		units := a.cfg.LogShipUnits
		journal = logship.NewJournalSource(hostd.WorkerSpoolDir, a.cfg.StateDir, units)
		s.AddSource(journal)
	}
	a.hb.SetLogShipState(func() map[string]any {
		st := s.State()
		if journal != nil {
			st["journal"] = journal.Status()
		}
		return st
	})
	go s.Run(ctx)
}

// hostServices is what this node's HOST services are actually doing, as
// opposed to what the controller placed. Today that is the harness
// Reported on every heartbeat so `noo cluster status` can
// print ACTUAL beside DESIRED instead of an operator
// inferring "running" from the absence of a refusal — which a unit stopped
// by hand, or never installed, also satisfies.
func (a *Agent) hostServices() map[string]any {
	if a.harness == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return map[string]any{
		"harness": map[string]any{
			"state":   string(a.harness.State(ctx)),
			"runtime": a.harness.Runtime(),
		},
	}
}

// hostdStatus is the confined-root daemon's own heartbeat, relayed up.
//
// `noo-apply` already reads this FILE on the node to decide whether a
// binary swap took, and the agent delegates every privileged op through
// the same daemon — but nothing carried any of it to the controller, so a
// node whose privileged helper is DEAD looked exactly like one whose
// helper was idle. `ops` travels too: it is how a caller learns whether
// this daemon is new enough for an op before trying it.
//
// `alive` is judged from the heartbeat's own timestamp against the
// interval it advertises, not from the file existing — a stale file from a
// daemon that died is the case worth catching, and it is the one a
// presence check would miss.
func (a *Agent) hostdStatus() map[string]any {
	hb, err := hostd.ReadHeartbeat(hostd.WorkerSpoolDir)
	if err != nil {
		// No file at all: either hostd was never installed here or it has
		// never run. Both are worth saying out loud, and neither is a
		// reason to withhold the rest of the heartbeat.
		return map[string]any{"alive": false, "detail": "no hostd heartbeat at " + hostd.WorkerSpoolDir}
	}
	out := map[string]any{"version": hb.Version, "ops": hb.Ops, "pid": hb.PID, "ts": hb.TS}
	if len(hb.Features) > 0 {
		out["features"] = hb.Features
	}
	// What the node's next boot will do. Forwarded
	// as written; `noo cluster verify` judges it.
	if hb.Host != nil {
		out["host"] = hb.Host
	}
	ts, perr := time.Parse(time.RFC3339, hb.TS)
	if perr != nil {
		out["alive"] = false
		out["detail"] = "hostd heartbeat has an unparseable timestamp: " + hb.TS
		return out
	}
	// Two missed beats is dead. One is a slow tick.
	grace := time.Duration(hb.Interval) * time.Second * 2
	if hb.Interval <= 0 {
		grace = 2 * hostd.DefaultHeartbeatInterval
	}
	age := time.Since(ts)
	out["age_secs"] = int(age.Seconds())
	if age > grace {
		out["alive"] = false
		out["detail"] = "hostd heartbeat is stale (" + age.Truncate(time.Second).String() + " old)"
		return out
	}
	out["alive"] = true
	return out
}

func nativeOllamaGuard() *backendrt.OllamaGuard {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return backendrt.NewOllamaGuard()
}

// backendContainers is the heartbeat's `backend_containers`: backendContainersOf
// plus the adopted lane's keys, so a docker container beside an adopted
// backend is reported as an orphan, plus, on a Mac, the native ollama's entry
// carrying its `telemetry_missing` (docs/security/telemetry.md). A Mac with no
// usable docker still sends the native entry; elsewhere nothing changes (a nil
// docker report stays nil, i.e. "not reported"). An orphan entry already under
// "ollama" wins the key: it is a FAIL the operator must see first.
func (a *Agent) backendContainers() map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	adoptedRunning := a.native.Running(ctx)
	var m map[string]any
	if f := backendContainersOf(a.docker, a.cfg.Tier); f != nil {
		adopted := map[string]bool{}
		for b := range adoptedRunning {
			adopted[b] = true
		}
		m = a.docker.BackendContainersBeside(adopted)
	}
	if a.ollama == nil {
		return m
	}
	if m == nil {
		m = map[string]any{}
	}
	if _, taken := m["ollama"]; !taken {
		_, running := adoptedRunning["ollama"]
		m["ollama"] = a.ollama.Report(running)
	}
	return m
}

// convergeOllama re-applies the switch every minute: a `brew services
// restart` or a formula upgrade regenerates the plist without it.
func (a *Agent) convergeOllama(ctx context.Context) {
	for {
		if _, restarted, err := a.ollama.Converge(); err != nil {
			slog.Error("ollama telemetry switch not applied", "error", err)
		} else if restarted {
			slog.Info("ollama restarted with OLLAMA_NO_CLOUD=1")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// backendContainersOf is the `backend_containers` provider:
// nil for a tier-5 sensor proxy, whose container has no docker.sock by
// design — the key is then omitted, not reported empty.
func backendContainersOf(d *dockerpkg.Client, tier int) func() map[string]any {
	if tier == 5 || d == nil {
		return nil
	}
	return d.BackendContainers
}

// meshBackendInfos builds what the node offers in answer to mesh discovery.
//
// The offered URL is the node agent's OWN dialable address (the same
// agent_url the heartbeat registers), because that is the only address of
// this node the controller can reach: every backend is dispatched through
// the agent's proxy, the gateway picks the backend by X-Noo-Backend. The
// backend's container-internal URL (noo-vllm:8000, noo-stunnel-ollama:11434)
// names a docker service on THIS host's network; offering it made the
// gateway warn ~740 times in 18 h and fall back to the registered address
// anyway. selfURL == "" (no dialable host IP: the heartbeat then registers
// none either) falls back to the container URL, which the gateway treats as
// advisory.
func meshBackendInfos(backends map[string]string, selfURL, scheme string) map[string]messaging.BackendInfo {
	result := make(map[string]messaging.BackendInfo)
	for bt, model := range backends {
		if dockerpkg.BackendPorts[bt] <= 0 {
			continue
		}
		url := dockerpkg.BackendURL(bt, scheme)
		if selfURL != "" {
			url = selfURL
		}
		result[bt] = messaging.BackendInfo{Model: model, URL: url, APIFormat: "openai"}
	}
	return result
}
