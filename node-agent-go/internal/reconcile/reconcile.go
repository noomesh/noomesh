// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package reconcile converges the node toward its DB-backed desired state.
//
// Postgres (via the gateway) holds DESIRED state: the node's models_dir and
// which backends should run with which model/port/tls. The agent pulls it
// at startup and on an interval, then:
//
//  1. ensures models_dir exists and is owned by the operator user — via a
//     helper container (Docker is root; no SSH/sudo on the node, ever);
//  2. diffs desired placements against RunningBackends() and starts /
//     restarts / stops backends through StartBackendSDK with placement
//     overrides (model, image, port, tls, env, models_dir).
//
// Placements whose model FILE is absent are skipped with a loud log
// (`reconcile.model_missing`) instead of starting a crash-looping
// container — the exact 2026-07-03 host8 failure mode.
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/noomesh/noomesh/node-agent-go/internal/diskreclaim"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
	"github.com/noomesh/noomesh/node-agent-go/internal/gpuyield"
	"github.com/noomesh/noomesh/node-agent-go/internal/hostsvc"
	"github.com/noomesh/noomesh/node-agent-go/internal/mcpsrv"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

const defaultInterval = 5 * time.Minute

type placement struct {
	Backend      string            `json:"backend"`
	Model        string            `json:"model"`
	Image        string            `json:"image"`
	Port         int               `json:"port"`
	TLS          bool              `json:"tls"`
	Env          map[string]string `json:"env"`
	DesiredState string            `json:"desired_state"`
	// Role is what this backend SERVES: chat (default) | embed | rerank.
	// Pre-role gateways omit the field; empty means chat, so a node pointed
	// at an older gateway behaves exactly as it did before.
	Role string `json:"role"`
	// Target is the hardware the placement runs on: "cpu" | "gpu" | ""
	// (undeclared — the agent decides as it always has). `noo cluster place
	// --on cpu` sets "cpu": the container then gets no GPU device at all
	// (dockerpkg.StartOverrides.Target). It is a field, not an env key: the
	// env allow-list is the backend's tuning vocabulary, and device
	// visibility is the agent's decision, never a container env value.
	Target string `json:"target"`
	// MemoryLimitBytes is the llama.cpp container's memory limit, derived by
	// the gateway at place time from the fit estimate (weights + KV +
	// overhead) and capped by the node's usage profile. 0 = the spec default.
	MemoryLimitBytes int64 `json:"memory_limit_bytes"`
}

type nodeConfig struct {
	NodeID    string `json:"node_id"`
	SSHUser   string `json:"ssh_user"`
	DataRoot  string `json:"data_root"`
	ModelsDir string `json:"models_dir"`
}

type desiredConfig struct {
	Node       *nodeConfig `json:"node"`
	Placements []placement `json:"placements"`
	// External MCP servers placed on this node. A
	// pre-registry gateway omits the field; nil means "none", and the
	// supervisor then stops anything it had running.
	MCPServers []mcpsrv.Placement `json:"mcp_servers"`
	// The controller's node reclaim policy (disk_watermark location). A
	// pre-policy gateway omits it; nil means "do not act".
	DiskReclaim *diskreclaim.Policy `json:"disk_reclaim"`
}

// Reconciler pulls desired config and converges the node toward it.
type Reconciler struct {
	nudge     chan struct{}
	nudgeOnce sync.Once
	cfg       *config.Config
	docker    *dockerpkg.Client
	client    *http.Client
	// onReclaimPolicy receives desired-config's disk_reclaim on every
	// successful fetch (nil when the gateway sends none).
	onReclaimPolicy func(*diskreclaim.Policy)
	// mcp supervises the external MCP servers placed here. nil when the
	// agent was built without one (tests); Apply is then skipped.
	mcp *mcpsrv.Supervisor
	// native probes backends served outside Docker on this host. nil off
	// darwin, where there is no native lane at all — nil rather than an
	// inert value so "no lane here" stays distinct from "lane found nothing".
	native *backendrt.Native
	// harnessRestarts is systemd's restart counter as of the last tick,
	// and whether we have seen one yet. A climbing value is how a crash
	// loop is detected without a timing window (crashLooping).
	harnessRestarts     uint64
	harnessRestartsSeen bool
	// harnessStartedKind is the kind the harness was last started with (or
	// first seen running with, after an agent restart); "" = unknown/not
	// running. A change in the desired kind restarts it (harnessKindDecision).
	// Written under harnessMu (setHarnessStartedKind), read by the
	// heartbeat through HarnessRunningKind.
	harnessStartedKind string
	// harnessDesired is the last desired harness placement the controller
	// answered with, for GET /harness/placement. Guarded by harnessMu.
	harnessMu      sync.RWMutex
	harnessDesired *placement
	// harness is the ONE host service this node regulates:
	// started and stopped per placement through the applier's sudoers
	// grant, never a container and never a child of this process.
	harness hostsvc.Service
	// runnerInstalled says whether a harness kind's runner executable is
	// on this node (runnerOnDisk in production, set by New). nil skips the
	// check: tests that build a bare Reconciler around a fake service.
	runnerInstalled func(runner string) bool
	// cliInstalled says whether a foreign kind's vendor CLI is on this
	// node's PATH (cliOnPath in production). nil skips the check.
	cliInstalled func(cli string) bool

	// driftRecreated records, per backend, the desired spec hash we last
	// recreated the container for on a spec-drift detection. It bounds the
	// absent/mismatched-label recreate to one attempt per (backend, hash):
	// a healthy recreate stamps the matching label and next tick converges
	// (the entry is cleared); a recreate that somehow fails to produce the
	// matching label is NOT retried forever — we log and wait for the
	// desired hash to change. Single-goroutine (ticker) access; no lock.
	driftRecreated map[string]string

	// ollamaPulls tracks the registry pull an ollama placement needs, per
	// model: one in flight at a time, and a failed pull waits before it is
	// retried (a tag that does not exist would otherwise be re-attempted
	// every tick). Written from the tick goroutine and the pull goroutine.
	pullMu      sync.Mutex
	ollamaPulls map[string]*ollamaPullState

	// storeHas says whether the controller's store publishes the model's
	// Modelfile, i.e. whether it reaches nodes only via `noo cluster
	// import-model`. (false, err) is "could not ask".
	// Injected so the decision is testable.
	storeHas func(context.Context, string) (bool, error)

	// importModel runs the import-model path (fetch the Modelfile and its
	// weight from the store, verify both, `ollama create`) for a placed
	// import-only model this node does not hold. Injected for tests.
	importModel func(context.Context, string) (string, error)

	// knownImportOnly remembers models the store has answered for, so a
	// later tick whose store check times out does not fall back to a
	// registry pull for a model already known to be import-only.
	// Guarded by pullMu.
	knownImportOnly map[string]bool

	// envConflicts are the placement_env_conflict refusal targets recorded
	// last pass, so ones that resolved are cleared.
	envConflicts map[string]bool
}

type ollamaPullState struct {
	inFlight   bool
	lastFailed time.Time
	failures   int
}

// ollamaPullRetryAfter is how long a failed pull is left alone.
const ollamaPullRetryAfter = 10 * time.Minute

// shouldStartOllamaPull is the decision behind ensureOllamaModel: not while
// one is running, not inside the backoff after a failure.
func shouldStartOllamaPull(st *ollamaPullState, now time.Time) bool {
	if st == nil {
		return true
	}
	if st.inFlight {
		return false
	}
	return st.lastFailed.IsZero() || now.Sub(st.lastFailed) >= ollamaPullRetryAfter
}

func New(cfg *config.Config, docker *dockerpkg.Client, client *http.Client, harness hostsvc.Service) *Reconciler {
	return &Reconciler{
		cfg:             cfg,
		docker:          docker,
		ollamaPulls:     map[string]*ollamaPullState{},
		storeHas:        dockerpkg.ModelInStore,
		importModel:     docker.ImportOllamaModel,
		client:          client,
		mcp:             mcpsrv.New(cfg, client, docker),
		native:          backendrt.NewAdopted(),
		harness:         harness,
		runnerInstalled: runnerOnDisk,
		cliInstalled:    cliOnPath,
		driftRecreated:  map[string]string{},
	}
}

// SetDiskReclaimSink installs the receiver for the controller's node reclaim
// policy (diskreclaim.Reclaimer.SetPolicy).
func (r *Reconciler) SetDiskReclaimSink(f func(*diskreclaim.Policy)) { r.onReclaimPolicy = f }

// MCP returns the external-MCP supervisor so the API server can route
// tool calls (phase C) and /health can show what is live.
func (r *Reconciler) MCP() *mcpsrv.Supervisor { return r.mcp }

// nativeBackends is the set this node serves outside Docker, backend -> model.
// Empty (never nil-panicking) on every platform without a native lane.
func (r *Reconciler) nativeBackends() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return r.native.Running(ctx)
}

// Run blocks until ctx cancels. First pass after a short delay (so
// registration/heartbeat win the race), then every interval.
func (r *Reconciler) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	r.Once(ctx)

	t := time.NewTicker(defaultInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Once(ctx)
		case <-r.nudgeCh():
			r.Once(ctx)
		}
	}
}

// Nudge asks for a reconcile pass now instead of at the next tick (the GPU
// yield, after resuming, so a placed backend it never started comes up).
// Non-blocking; nudges coalesce.
func (r *Reconciler) Nudge() {
	select {
	case r.nudgeCh() <- struct{}{}:
	default:
	}
}

func (r *Reconciler) nudgeCh() chan struct{} {
	r.nudgeOnce.Do(func() { r.nudge = make(chan struct{}, 1) })
	return r.nudge
}

// Once performs a single reconcile pass. Errors are logged, never fatal —
// the next tick retries.
func (r *Reconciler) Once(ctx context.Context) {
	desired, err := r.fetch(ctx)
	if err != nil {
		slog.Warn("reconcile.fetch_failed", "error", err)
		return
	}
	// Before the empty-state return below: a node with nothing placed still
	// has a disk to keep.
	if r.onReclaimPolicy != nil {
		r.onReclaimPolicy(desired.DiskReclaim)
	}
	// Publish the embed target as soon as desired state is known - before any
	// early return, so removing the last embed placement (or every placement)
	// stops the node advertising `embed`.
	r.publishEmbedTarget(desired.Placements)
	if desired.Node == nil && len(desired.Placements) == 0 && len(desired.MCPServers) == 0 {
		slog.Debug("reconcile.no_desired_state")
		// Nothing is placed: nothing is held, tuned, or in conflict.
		modelpresence.Retain(map[string]bool{})
		gpuyield.PublishPlacements(nil)
		backendrt.SetOllamaTuning(nil)
		r.surfaceEnvConflicts(nil)
		if r.mcp != nil {
			r.mcp.Apply(ctx, nil)
		}
		return
	}

	// External MCP servers: start/stop/rediscover.
	// Before backends on purpose — a discovery report is small and the
	// controller may be waiting on it; a backend pull can take minutes.
	if r.mcp != nil {
		r.mcp.Apply(ctx, desired.MCPServers)
	}

	modelsDir := ""
	owner := ""
	if desired.Node != nil {
		modelsDir = desired.Node.ModelsDir
		owner = desired.Node.SSHUser
	}

	// 1. Self-provision the models dir (root-owned parents are fine —
	// the helper container runs as root). This is what removes the
	// "ssh in and sudo install -d" manual step.
	//
	// A FAILURE HERE REFUSES THE MOUNT. It used to warn and keep going,
	// then hand the same unchecked string to StartBackend as the /models
	// bind source — so a models_dir the node had just refused to create
	// (because it named /etc, or a path outside this node's declared data
	// roots) was mounted into a controller-chosen image anyway. "Warn and
	// continue" on a security decision is how a guard becomes decorative.
	//
	// Refusing means: modelsDir goes back to "", the node falls through to
	// its OWN env-resolved /models source (MODELS_DIR / NOO_DATA_ROOT), and
	// GGUF placements that need the directory are skipped with a reason the
	// gateway is told about. Backends that do not need it still converge.
	if modelsDir != "" {
		if err := r.docker.EnsureHostDir(ctx, modelsDir, owner); err != nil {
			// Two very different failures reach here, and blaming the path
			// for the second one sent an operator hunting a permissions
			// problem that did not exist (host3, R50). A refused PATH is
			// this node declining the controller's instruction; a missing
			// HELPER IMAGE is this node not being finished being set up.
			// The refusal names whichever it is, with its own fix.
			if dockerpkg.IsHelperImageUnavailable(err) {
				slog.Error("reconcile.helper_image_missing",
					"dir", modelsDir, "error", err,
					"effect", "no host operation can run on this node: no models dir, no weight preseed")
				refusals.Record("helper_image", dockerpkg.HelperImageRef(),
					dockerpkg.HelperImageFix(r.cfg.NodeID))
			} else {
				slog.Error("reconcile.models_dir_refused",
					"dir", modelsDir, "owner", owner, "error", err,
					"effect", "this node will not mount the controller's models_dir; "+
						"gguf placements that depend on it are skipped")
				refusals.Record("models_dir", modelsDir, err.Error())
			}
			modelsDir = ""
		} else {
			refusals.Clear("models_dir", modelsDir)
			refusals.Clear("helper_image", dockerpkg.HelperImageRef())
		}
	}

	// 2. Converge placements.
	running := r.docker.RunningBackends()
	// Backends served NATIVELY on this node (darwin: an ollama the operator
	// runs for Metal access, which Docker on a Mac cannot reach). They are
	// reported to the controller and routed to like any other backend, but
	// this loop must not try to manage them:
	//
	// a native backend has no container, so BackendLabels returns no spec
	// hash for it, decideSpecDrift sees hasLabel=false and answers
	// driftRecreate, and the reconciler would call StartBackend ->
	// ContainerCreate -> dial error on EVERY tick, forever. The existing
	// drift-stuck guard happens to bound that to one attempt per spec, but
	// that is incidental protection, not a decision — so the skip is
	// explicit, and it is logged rather than silent, because "the controller
	// asked for this and the node did not do it" is exactly the kind of
	// divergence that must never be inferred from an absence of output.
	native := r.nativeBackends()
	// Spec-drift signal: the fingerprint we stamped on each running
	// backend's container (SpecHashLabel), so a changed placement env /
	// image / port / tls (not just model) triggers a recreate.
	specLabels := r.docker.BackendLabels(dockerpkg.SpecHashLabel)
	// Multi-role placements: ONE effective placement per backend (a lone
	// placement is passed through untouched; several running ollama rows
	// merge into one daemon spec - see multirole.go).
	r.recordHarnessPlacement(desired.Placements)
	effective, envWarnings := effectivePlacements(desired.Placements)
	r.surfaceEnvConflicts(envWarnings)
	ollamaRows := runningOllama(desired.Placements)
	// The shared-GPU yield sizes what the GPU backends need from these.
	gpuyield.PublishPlacements(gpuPlacements(effective))
	// Fetch the images this tick will start, concurrently, before the
	// ordered start loop below (which then finds them local).
	r.prefetchImages(ctx, effective, running, specLabels, native)
	for _, p := range effective {
		if p.Backend == "harness" {
			// Not a container: the host service, converged
			// through hostsvc — placed = running — and reported from
			// `is-active`, never from `docker ps`.
			r.convergeHarness(ctx, p, desired.Placements)
			continue
		}
		switch p.DesiredState {
		case "stopped":
			if _, ok := native[p.Backend]; ok {
				slog.Warn("reconcile.native_backend_not_stopped",
					"backend", p.Backend,
					"detail", "the controller asked for it to stop, but this node did not start it and will not stop a process it does not own")
				continue
			}
			if _, ok := running[p.Backend]; ok {
				slog.Info("reconcile.stopping_backend", "backend", p.Backend)
				if err := r.docker.StopBackend(p.Backend); err != nil {
					slog.Warn("reconcile.stop_failed", "backend", p.Backend, "error", err)
				}
			}
		case "running":
			if model, ok := native[p.Backend]; ok {
				slog.Info("reconcile.native_backend_unmanaged",
					"backend", p.Backend, "running_model", model,
					"desired_model", p.Model,
					"detail", "served natively on this host; the agent reports it but does not start, stop or converge it")
				if p.Backend == "ollama" && r.native != nil {
					// Not lifecycle: the server is the operator's, the
					// MODEL is the placement's. Pull it over the same
					// loopback API the probe uses.
					// Every role's model, not just the primary.
					r.ensureOllamaModels(r.cfg.NodeID, ollamaRows, r.native.HasModel, r.native.Pull)
					// Advertise what the server holds, not only what it
					// has loaded: an idle ollama has nothing loaded, and a
					// heartbeat with no model is never routed to.
					var held []string
					for _, row := range ollamaRows {
						hctx, hcancel := context.WithTimeout(context.Background(), 5*time.Second)
						if has, err := r.native.HasModel(hctx, row.Model); err == nil && has {
							held = append(held, row.Model)
						}
						hcancel()
					}
					r.native.SetHeldModels(held...)
					// A launchd-managed ollama gets the merged env through
					// its plist (OllamaGuard.Tuning); only when several
					// roles share the daemon - a lone placement's env is
					// left as it has always been.
					if len(ollamaRows) > 1 {
						env, _ := mergeOllamaEnv(ollamaRows)
						backendrt.SetOllamaTuning(buildPlacementEnv(placement{Backend: "ollama", Env: env}))
					} else {
						backendrt.SetOllamaTuning(nil)
					}
				}
				continue
			}
			// Paused for other work on the GPU (internal/gpuyield): the
			// container is stopped ON PURPOSE. Starting it here would fight
			// the yield every tick; the yield resumes it itself.
			if gpuHeld(p) {
				slog.Info("reconcile.backend_paused",
					"backend", p.Backend, "paused", gpuyield.PauseReason,
					"detail", "GPU in use by other work; not starting until the GPU frees (or `noo cluster gpu release`)")
				continue
			}
			curModel, isRunning := running[p.Backend]
			desiredHash := specHash(p)
			// Converged when running with the placement's model (compare
			// basenames — detection may report a bare filename) AND the
			// stamped spec hash matches the desired one.
			if isRunning && modelMatches(curModel, p.Model) {
				// Running as asked: an earlier start failure no longer
				// applies.
				refusals.Clear("backend_start", p.Backend)
				if p.Backend == "ollama" {
					// The container is up with OLLAMA_MODEL set; that says
					// nothing about whether the weights are there. Pull the
					// tag if the container lacks it (off-tick; see ollamaPulls).
					r.ensureOllamaModels(r.cfg.NodeID, ollamaRows, r.docker.OllamaHasModel, r.docker.OllamaPull)
				}
				curHash, hasLabel := specLabels[p.Backend]
				switch decideSpecDrift(hasLabel, curHash, desiredHash, r.driftRecreated[p.Backend]) {
				case driftConverged:
					// Fully converged — clear any prior drift bookkeeping.
					delete(r.driftRecreated, p.Backend)
					continue
				case driftStuck:
					// Recreated once for this exact spec, yet the label still
					// doesn't match — don't restart-loop; wait for the desired
					// hash to change (a fresh edit) before trying again.
					slog.Warn("reconcile.spec_drift_stuck",
						"backend", p.Backend,
						"hash", shortHash(desiredHash),
						"note", "recreated once for this spec but label still absent/mismatched; not looping")
					continue
				case driftRecreate:
					// Model matches but spec drifted (env/image/port/tls edit)
					// or the container predates the label. Recreate to converge.
					slog.Info("reconcile.spec_drift",
						"backend", p.Backend,
						"old_hash", shortHash(curHash),
						"new_hash", shortHash(desiredHash),
						"label_absent", !hasLabel)
					r.driftRecreated[p.Backend] = desiredHash
					// fall through to the shared start path (StartBackend
					// removes the old container and recreates it labeled).
				}
			}

			// Guard: a gguf-only engine given a NON-gguf model can never
			// start. This is the case the check below misses, because it
			// keys on the model ENDING in .gguf — so a HuggingFace repo id
			// (which is what an operator naturally types, and what the TEI
			// reranker legitimately takes) slips straight through to a
			// permanent restart loop:
			//
			//   gguf_init_from_file: failed to open GGUF file
			//     '/models/BAAI/bge-reranker-base'
			//
			// host8's reranker looped like this for hours. Fail loudly and
			// leave the backend stopped rather than burning restarts.
			if p.Model != "" && dockerpkg.ExpectsGGUFModel(p.Backend) &&
				!strings.HasSuffix(p.Model, ".gguf") {
				slog.Error("reconcile.model_not_gguf",
					"backend", p.Backend, "model", p.Model,
					"detail", "this engine loads a gguf FILE from the models dir, not a HuggingFace repo id",
					"fix", "set the placement model to a .gguf filename (noo cluster place "+
						r.cfg.NodeID+" "+p.Backend+" <file>.gguf), or set RERANK_ENGINE=tei for a repo id")
				// Skipping the start is not enough. If the container already
				// exists it carries a restart policy and Docker keeps cycling
				// it independently of this loop — which is exactly what
				// happened on host8: the guard logged correctly on every
				// tick while noo-reranker went right on restarting. Detection
				// without remediation just makes the loop legible.
				// Unconditional. Gating this on RunningBackends() did not
				// work: that lists RUNNING containers, and a crash-looping
				// one flickers in and out of that view, so the check raced
				// and the stop never fired — verified on host8, where
				// model_not_gguf logged on every tick and
				// stopping_misconfigured_backend logged zero times while the
				// container kept restarting.
				//
				// Stopping a backend that is not there is harmless and
				// already logged, so there is nothing to gain from asking
				// first and a race to lose.
				slog.Warn("reconcile.stopping_misconfigured_backend",
					"backend", p.Backend,
					"reason", "model is not a gguf file")
				if err := r.docker.StopBackend(p.Backend); err != nil {
					slog.Warn("reconcile.stop_failed",
						"backend", p.Backend, "error", err)
				}
				continue
			}

			// Guard: don't start a gguf backend whose model file is
			// missing — that's a guaranteed crash-loop. Surface it and
			// let the operator ship the file (noo cluster
			// sync-model-files) or Phase 2 auto-pull handle it.
			if modelsDir == "" && strings.HasSuffix(p.Model, ".gguf") && desired.Node != nil &&
				desired.Node.ModelsDir != "" {
				// The controller named a models_dir and this node refused
				// it (above). Starting anyway would mount the node's own
				// default models dir under a placement that was written
				// against a different one — a silently wrong model path.
				slog.Error("reconcile.placement_refused",
					"backend", p.Backend, "model", p.Model,
					"reason", "this node refused the controller's models_dir; see reconcile.models_dir_refused")
				refusals.Record("placement", p.Backend,
					"this node refused the controller's models_dir "+desired.Node.ModelsDir+
						", and this placement's model lives in it")
				continue
			}
			if modelsDir != "" && strings.HasSuffix(p.Model, ".gguf") {
				exists, err := r.docker.HostFileExists(ctx, modelsDir, p.Model)
				if err != nil {
					slog.Warn("reconcile.model_check_failed", "error", err)
				} else if !exists {
					slog.Error("reconcile.model_missing",
						"backend", p.Backend, "model", p.Model,
						"models_dir", modelsDir,
						"fix", "noo cluster sync-model-files "+r.cfg.NodeID+" -m "+p.Model)
					continue
				}
			}

			extraEnv := buildPlacementEnv(p)
			slog.Info("reconcile.starting_backend",
				"backend", p.Backend, "model", p.Model,
				"was_running", isRunning, "was_model", curModel)
			overrides := dockerpkg.StartOverrides{
				Image:       p.Image,
				ModelsDir:   modelsDir,
				ExtraEnv:    extraEnv,
				SpecHash:    desiredHash,
				Target:      p.Target,
				MemoryLimit: p.MemoryLimitBytes,
			}
			if err := r.docker.StartBackend(p.Backend, p.Model, 0, overrides); err != nil {
				slog.Error("reconcile.start_failed",
					"backend", p.Backend, "error", err)
				// A drift recreate that never happened must be retried:
				// the stuck guard exists for a recreate that SUCCEEDED and
				// still reads as drift, not for one the node refused
				// (2026-09-29: a door check refused before touching the
				// container — the old one keeps running plain, and the
				// next tick must try again once the leaf has arrived).
				delete(r.driftRecreated, p.Backend)
				// A start that fails is a desired-state instruction this
				// node could not honour, and until 2026-09-14 the only
				// record of it was the log line above: `noo cluster desired`
				// went on saying Running, `noo cluster status` simply
				// omitted the backend, and the operator read half an hour
				// of `unauthorized` pulls as "not reconciled yet"
				// Record it with the error verbatim so the
				// heartbeat carries it; cleared when the backend is next
				// seen running (above) or starts (below).
				refusals.Record("backend_start", p.Backend, err.Error())
				continue
			}
			refusals.Clear("backend_start", p.Backend)
		}
	}
	// A harness whose placement was REMOVED is never visited by the loop
	// above, which only walks placements that exist. Stop it here.
	r.reapUnplacedHarness(ctx, desired.Placements)
	// A placement that was removed or stopped must stop reporting a model
	// presence; only still-wanted ollama placements keep one.
	// Keys of every still-wanted ollama placement survive, including the
	// "ollama#<role>" ones; the primary keeps "ollama".
	keep := map[string]bool{}
	if len(ollamaRows) > 0 {
		primary := ollamaRows[0]
		for _, p := range ollamaRows {
			keep[presenceKey(p.Backend, p, primary)] = true
		}
	}
	modelpresence.Retain(keep)
}

// gpuHeld: the shared-GPU yield has this backend paused (or is about to),
// so the reconciler must not start it.
func gpuHeld(p placement) bool { return gpuyield.HoldsStart(p.Backend) }

// gpuPlacements is what the shared-GPU yield needs to know of the
// placements: the running ones, and how big they are.
func gpuPlacements(ps []placement) []gpuyield.Placed {
	var out []gpuyield.Placed
	for _, p := range ps {
		if p.DesiredState != "running" || p.Backend == "harness" {
			continue
		}
		out = append(out, gpuyield.Placed{Backend: p.Backend, Target: p.Target, Env: p.Env, MemoryLimitBytes: p.MemoryLimitBytes})
	}
	return out
}

// ensureOllamaModel makes the ollama container hold the placement's model.
// `ollama list` is cheap and runs on the tick; the pull itself can take many
// minutes and runs in its own goroutine, one per model at a time, with a
// backoff after failure. A model the container already has (harrier from
// import-model, a tag pulled earlier) costs one exec per tick and no pull.
//
// `has` and `pull` are the lane: the container's (`docker.OllamaHasModel` /
// `OllamaPull`, exec in noo-ollama) or the native one's (`backendrt.Native`,
// loopback API). The bookkeeping is shared — a model is one pull however it
// is served.
func (r *Reconciler) ensureOllamaModel(
	node string,
	key string,
	p placement,
	has func(context.Context, string) (bool, error),
	pull func(context.Context, string) (string, error),
) {
	model := strings.TrimSpace(p.Model)
	if model == "" || has == nil || pull == nil {
		return
	}
	role := p.Role
	if role == "" {
		role = "chat"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	hasIt, err := has(ctx, model)
	cancel()
	if err != nil {
		// Could not ask: unknown, not absent.
		modelpresence.Clear(key)
		slog.Warn("reconcile.ollama_model_check_failed", "model", model, "error", err)
		return
	}
	if hasIt {
		modelpresence.Set(key, modelpresence.Entry{Model: model, Role: role, Present: true})
		refusals.Clear("placement_model", key)
		return
	}
	// The container is up and the model is not in it. Report that, whatever
	// happens next: ACTUAL must not read Running for a node that 404s.
	importOnly := r.resolveImportOnly(model)
	modelpresence.Set(key, modelpresence.Entry{Model: model, Role: role, Present: false, ImportOnly: importOnly})
	if importOnly {
		// Published through the controller's store (harrier), not the public
		// registry: `ollama pull` would 404 forever, so it is never tried.
		// Import it from the store instead — the same fetch-verify-create
		// `noo cluster import-model` runs. Until 2026-10-10 reconcile only
		// logged the remedy every tick and left the placement stuck.
		r.startOllamaImport(node, key, model, role)
		return
	}
	r.pullMu.Lock()
	st := r.ollamaPulls[model]
	if !shouldStartOllamaPull(st, time.Now()) {
		r.pullMu.Unlock()
		return
	}
	if st == nil {
		st = &ollamaPullState{}
		r.ollamaPulls[model] = st
	}
	st.inFlight = true
	r.pullMu.Unlock()

	slog.Info("reconcile.ollama_pull_start", "model", model,
		"detail", "placement names a registry tag the container does not hold yet")
	go func() {
		out, err := pull(context.Background(), model)
		r.pullMu.Lock()
		defer r.pullMu.Unlock()
		st.inFlight = false
		if err != nil {
			st.failures++
			st.lastFailed = time.Now()
			slog.Error("reconcile.ollama_pull_failed", "model", model, "error", err,
				"failures", st.failures, "retry_after", ollamaPullRetryAfter.String())
			return
		}
		st.failures = 0
		st.lastFailed = time.Time{}
		slog.Info("reconcile.ollama_pull_done", "model", model, "detail", plainLastLine(out))
	}()
}

// resolveImportOnly asks the store whether `model` is import-only. A store
// that could not be asked (timeout, transport) falls back to what an
// earlier answer said, and otherwise to "not import-only" — the registry
// pull this node did before the store existed.
func (r *Reconciler) resolveImportOnly(model string) bool {
	if r.storeHas == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	in, err := r.storeHas(ctx, model)
	cancel()
	r.pullMu.Lock()
	defer r.pullMu.Unlock()
	if r.knownImportOnly == nil {
		r.knownImportOnly = map[string]bool{}
	}
	if err != nil {
		known := r.knownImportOnly[model]
		slog.Warn("reconcile.ollama_model_store_check_failed", "model", model, "error", err,
			"assumed_import_only", known,
			"detail", "could not ask the controller store whether it publishes this model; this is not an answer that it does not")
		return known
	}
	r.knownImportOnly[model] = in
	return in
}

// importRemedy is the operator's manual path for a model reconcile could
// not import.
func importRemedy(node, model, role string) string {
	return "noo cluster import-model " + node + " " + model + " --place --role " + role
}

// startOllamaImport imports a placed import-only model from the controller
// store, off the tick, with the same one-in-flight + backoff bookkeeping as
// a registry pull. A failure is recorded as a placement_model refusal with
// the reason and the manual remedy, and logged loudly every time it fails.
func (r *Reconciler) startOllamaImport(node, key, model, role string) {
	fix := importRemedy(node, model, role)
	if r.importModel == nil {
		slog.Error("reconcile.ollama_model_import_only_missing",
			"model", model, "backend", key, "fix", fix,
			"detail", "import-only model is absent and this agent has no import path; not pulling it from the public registry")
		refusals.Record("placement_model", key,
			model+" is import-only (not on the public registry) and this node's ollama does not hold it; run `"+fix+"`")
		return
	}
	r.pullMu.Lock()
	st := r.ollamaPulls[model]
	if !shouldStartOllamaPull(st, time.Now()) {
		r.pullMu.Unlock()
		return
	}
	if st == nil {
		st = &ollamaPullState{}
		r.ollamaPulls[model] = st
	}
	st.inFlight = true
	r.pullMu.Unlock()

	slog.Info("reconcile.ollama_import_start", "model", model, "backend", key,
		"detail", "placed import-only model is absent; importing it from the controller store (never the public registry)")
	go func() {
		// Bounded: the import's own fetch allows 60 min per file and the
		// create 30 min; this caps the whole thing so a wedged import
		// cannot hold the in-flight slot forever.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		out, err := r.importModel(ctx, model)
		r.pullMu.Lock()
		defer r.pullMu.Unlock()
		st.inFlight = false
		if err != nil {
			st.failures++
			st.lastFailed = time.Now()
			slog.Error("reconcile.ollama_import_failed", "model", model, "backend", key,
				"error", err, "failures", st.failures, "retry_after", ollamaPullRetryAfter.String(), "fix", fix)
			refusals.Record("placement_model", key,
				model+" is import-only and importing it from the controller store failed: "+err.Error()+
					"; reconcile retries every "+ollamaPullRetryAfter.String()+", or run `"+fix+"`")
			return
		}
		st.failures = 0
		st.lastFailed = time.Time{}
		// The next tick sees the model held and clears presence + refusal;
		// clearing the refusal now just keeps the window honest.
		refusals.Clear("placement_model", key)
		slog.Info("reconcile.ollama_import_done", "model", model, "backend", key, "detail", out)
	}()
}

// ansiEscapeRe matches the two escape-sequence shapes a TTY-aware CLI
// emits at the start of a session: OSC (`\x1b]...` terminated by BEL or
// ST/`\x1b\`), used for terminal queries like "what's your background
// color?", and CSI (`\x1b[...<letter>`), used for cursor moves and mode
// toggles. `ollama pull`'s progress bar also rewrites a line in place with
// bare `\r`, which is not an escape sequence and is handled separately in
// plainLastLine by splitting on it.
var ansiEscapeRe = regexp.MustCompile(`\x1b(?:\][^\x07]*(?:\x07|\x1b\\)|\[[0-9;?]*[a-zA-Z])`)

// plainLastLine is lastLine for output that may carry a TTY's escape
// sequences and carriage-return progress updates — the shape `ollama pull`
// produced when its exec ran with a TTY (fixed to run without one, but this
// stays defensive for anything upstream that still attaches one). It strips
// CSI/OSC escapes, treats both \r and \n as line breaks (a `\r`-updated
// progress bar is many "lines" sharing one terminal row), and returns the
// last non-empty one — e.g. "success" for a completed pull.
func plainLastLine(s string) string {
	clean := ansiEscapeRe.ReplaceAllString(s, "")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	lines := strings.Split(clean, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// placementEnvAllowed decides whether a CONTROLLER-supplied placement env
// key may reach a backend container.
//
// Placement `env` is a raw jsonb blob the gateway ships verbatim
// (routes/cluster.rs desired_config_get). It was merged into the container
// environment with no filter at all, which made it a general-purpose
// injection point into a root container: LD_PRELOAD, PATH,
// NVIDIA_VISIBLE_DEVICES, a backend's own credential variables. The
// placement's job is to TUNE a backend, so the allow-list is the tuning
// vocabulary and nothing else.
//
// The rule, in one line: a placement may set model/runtime tuning keys the
// backend specs already declare. It may never set a credential, a loader
// path, or anything the process environment interprets before main().
//
// Documented in docs/security/node-agent.md. Widening it is a code change
// in the agent — not a DB row, and not an env var, because "the controller
// can add keys to the allow-list" is not an allow-list.
func placementEnvAllowed(key string) bool {
	if _, ok := placementEnvExact[key]; ok {
		return true
	}
	for _, pfx := range placementEnvPrefixes {
		if strings.HasPrefix(key, pfx) {
			return true
		}
	}
	return false
}

// placementEnvExact are the single keys a placement may set.
var placementEnvExact = map[string]struct{}{
	// Model selection / paths inside the container's own mounts.
	"MODEL_PATH": {}, "MODEL_ID": {}, "MODEL_NAME": {},
	// Ports and bind address (also derived from placement.port).
	"PORT": {}, "HOST": {},
	// llama.cpp / GGUF runtime sizing.
	"N_GPU_LAYERS": {}, "N_CTX": {}, "N_THREADS": {}, "N_BATCH": {}, "N_PARALLEL": {},
	// GPU sizing shared by vLLM and friends.
	"GPU_MEMORY_UTILIZATION": {}, "TENSOR_PARALLEL_SIZE": {}, "GPU_COUNT": {},
	// ollama.
	"OLLAMA_MODEL": {}, "OLLAMA_HOST": {}, "OLLAMA_NUM_PARALLEL": {},
	"OLLAMA_KEEP_ALIVE": {}, "OLLAMA_MAX_LOADED_MODELS": {},
	// Log level of the served process. Not a secret, frequently needed.
	"LOG_LEVEL": {}, "RUST_LOG": {},
}

// placementEnvPrefixes are the families a placement may set. Each is a
// backend's own tuning namespace, and none of them is read by the dynamic
// loader or the C runtime.
//
// Deliberately NOT here: LD_*, PATH, HOME, PYTHON* (PYTHONPATH and
// PYTHONSTARTUP both execute attacker-chosen code at interpreter start),
// NVIDIA_* (device visibility is the node's decision), HF_TOKEN /
// HUGGING_FACE_HUB_TOKEN and every other credential, NOO_* (the agent's own
// namespace), NATS_* and DOCKER_HOST.
var placementEnvPrefixes = []string{
	"VLLM_",      // vLLM tuning (parsers, max-model-len, quantization, V2 runner…)
	"LLAMA_ARG_", // llama-server's own argument environment
	"TEI_",       // text-embeddings-inference
	"RERANK_",    // reranker engine/model/ctx/threads
}

// buildPlacementEnv translates placement port/tls/env into container env.
//
// Only allow-listed keys survive; a refused key is LOGGED, never silently
// dropped, because a placement whose env did not take effect is otherwise
// indistinguishable from one that did.
func buildPlacementEnv(p placement) map[string]string {
	env := map[string]string{}
	for k, v := range p.Env {
		if !placementEnvAllowed(k) {
			slog.Warn("reconcile.placement_env_refused",
				"backend", p.Backend, "key", k,
				"detail", "placement env may only carry model/runtime tuning keys; "+
					"credentials and loader variables are the node's, not the controller's",
				"fix", "set node-local values in /etc/noo-node-agent.env, or extend the "+
					"allow-list in reconcile.placementEnvExact/placementEnvPrefixes")
			refusals.Record("placement_env", p.Backend+"/"+k,
				"placement env key is not on this node's tuning allow-list")
			continue
		}
		env[k] = v
	}
	if p.Port > 0 {
		port := fmt.Sprintf("%d", p.Port)
		env["PORT"] = port
		env["LLAMA_ARG_PORT"] = port
	}
	// TLS flag is consumed by SchemeFor() on the *client* side; backends
	// that serve TLS natively read their own env (left to p.Env).
	return env
}

// volatileEnvKeys are env keys EXCLUDED from the spec hash because the agent
// injects or resolves them nondeterministically at start time — hashing them
// would report false drift on a placement that never changed:
//
//   - HF_HUB_OFFLINE  — set to "1" only when preseedModel() copied weights from
//     the controller store; depends on cache state, not on the placement.
//   - N_GPU_LAYERS    — the "auto" sentinel resolves to 999 (GPU) or 0 (CPU)
//     per node in buildEnvList, so the effective value is node-dependent.
//   - PORT / LLAMA_ARG_PORT / LLAMA_ARG_HOST / HOST — derived by
//     buildPlacementEnv / StartBackendSDK from the placement's Port (which is
//     hashed as its own field) and fixed host bindings, not free-form config.
//
// These are agent-side additions; the controller normally doesn't put them in
// placement.Env, but excluding them here is defense-in-depth so a hand-set one
// can't churn the hash.
var volatileEnvKeys = map[string]bool{
	"HF_HUB_OFFLINE": true,
	"N_GPU_LAYERS":   true,
	"PORT":           true,
	"LLAMA_ARG_PORT": true,
	"LLAMA_ARG_HOST": true,
	"HOST":           true,
}

// specHash is a stable fingerprint of a placement's effective, operator-facing
// spec: model + image + port + tls + the non-volatile env (sorted KEY=VALUE).
// It is stamped on the container (SpecHashLabel) at start and re-computed each
// reconcile pass; a difference means the desired spec changed (an env/image/
// port/tls edit that the model-name check alone misses) and the container must
// be recreated. MUST be deterministic across ticks for an unchanged placement.
func specHash(p placement) string {
	h := sha256.New()
	// Field-tagged, newline-delimited canonical form — tags prevent a value
	// from one field colliding with another (e.g. model="a\nimage=b").
	fmt.Fprintf(h, "model=%s\n", p.Model)
	fmt.Fprintf(h, "image=%s\n", p.Image)
	fmt.Fprintf(h, "port=%d\n", p.Port)
	fmt.Fprintf(h, "tls=%t\n", p.TLS)
	// The DOOR the agent creates a backend with is part of its spec: a
	// container created by an older agent (vLLM without --ssl-cert-reqs,
	// no stunnel sidecar) must be recreated once the binary rolls, with no
	// placement edit — the placement did not change, the agent did.
	fmt.Fprintf(h, "door=%d\n", dockerpkg.BackendDoorGeneration)
	// Likewise the env the agent stamps on every backend regardless of the
	// placement (the vendor telemetry switches, dockerpkg/telemetry.go): a
	// container created without them is recreated once when the agent rolls.
	fmt.Fprintf(h, "envgen=%d\n", dockerpkg.BackendEnvGeneration)
	// macOS publishes the door on host loopback (dockerpkg.LoopbackDoorPublish)
	// — a container created without that binding must be recreated once.
	// Folded in ONLY there, so a Linux node's hash (and its running
	// backends) is unchanged by this line.
	if dockerpkg.LoopbackDoorPublish() {
		fmt.Fprintf(h, "doorpublish=loopback\n")
	}
	// The hardware target decides the container's GPU device, so a change
	// must recreate it. Folded in ONLY when declared, so every placement
	// from before targets existed keeps the hash it had.
	if p.Target != "" {
		fmt.Fprintf(h, "target=%s\n", p.Target)
	}
	// Likewise the derived memory limit: a new limit needs a new container.
	if p.MemoryLimitBytes > 0 {
		fmt.Fprintf(h, "memlimit=%d\n", p.MemoryLimitBytes)
	}

	keys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		if volatileEnvKeys[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "env.%s=%s\n", k, p.Env[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// driftDecision is what to do for a running backend whose model already
// matches the placement, based on the stamped spec label and our per-backend
// recreate bookkeeping.
type driftDecision int

const (
	driftConverged driftDecision = iota // label present and matches desired
	driftRecreate                       // drift or absent label; recreate now
	driftStuck                          // already recreated for this hash; skip
)

// decideSpecDrift is the pure core of the drift check. curHash is the spec
// label read off the running container ("" when the label is absent — a
// container that predates this feature); lastRecreated is the desired hash we
// most recently recreated this backend for (empty when we never have).
//
// An absent-or-mismatched label is drift and triggers ONE recreate; if the
// next pass still shows a non-matching label for the SAME desired hash, we
// return driftStuck instead of looping. desiredHash is always a non-empty
// sha256 hex, so the lastRecreated=="" default never spuriously matches.
func decideSpecDrift(hasLabel bool, curHash, desiredHash, lastRecreated string) driftDecision {
	if hasLabel && curHash == desiredHash {
		return driftConverged
	}
	if lastRecreated == desiredHash {
		return driftStuck
	}
	return driftRecreate
}

// shortHash returns a log-friendly prefix of a hex hash ("" stays "").
func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

func modelMatches(current, desired string) bool {
	if current == "" || desired == "" {
		return current == desired
	}
	base := func(s string) string {
		if i := strings.LastIndex(s, "/"); i >= 0 {
			return s[i+1:]
		}
		return s
	}
	return base(current) == base(desired)
}

func (r *Reconciler) fetch(ctx context.Context) (*desiredConfig, error) {
	url := fmt.Sprintf("%s/api/cluster/nodes/%s/desired-config",
		r.cfg.ControllerURL, r.cfg.NodeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if r.cfg.ClusterSecret != "" {
		auth.SetClusterAuth(req, r.cfg.NodeID, r.cfg.ClusterSecret)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("desired-config HTTP %d: %s", resp.StatusCode, body)
	}
	var out desiredConfig
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// embedBackends are the backends that can serve this node's embeddings.
// Their door (container name, port, scheme) is the docker package's
// backendDoors table — one declaration, the same one the inference proxy
// dials; the /embed proxy resolves the URL from Target.Backend at request
// time (dockerpkg.BackendDialURL) so a pre-door container and a sidecar-
// fronted one are both reached as they run.
var embedBackends = map[string]bool{
	"embedding": true, // TEI
	"ollama":    true, // ollama's OpenAI-compatible /v1/embeddings
	"llamacpp":  true, // llama-server --embedding
}

// resolveEmbedTarget picks the backend this node is DECLARED to serve
// embeddings from, using the placement role rather than guessing from
// container names. BaseURL is the backend's door as an agent-started
// backend is created with it (informational; the proxy re-resolves).
//
// Returns the zero Target when no placement carries role=embed. Callers
// must treat that as unknown and fall back deliberately — an empty result
// is the honest answer for a node that has no declared embedder, and is
// also what a pre-role gateway produces (it omits `role`, so everything
// reads as chat).
func resolveEmbedTarget(placements []placement) embedtarget.Target {
	for _, p := range placements {
		if p.Role != "embed" || p.DesiredState == "stopped" {
			continue
		}
		if !embedBackends[p.Backend] {
			slog.Warn("reconcile.embed_backend_unmapped",
				"backend", p.Backend,
				"hint", "add it to embedBackends (and its door to the docker package's backendDoors)")
			continue
		}
		return embedtarget.Target{
			BaseURL: dockerpkg.BackendURL(p.Backend, ""),
			Backend: p.Backend,
			Model:   p.Model,
		}
	}
	return embedtarget.Target{}
}

// publishEmbedTarget records the node's declared embedder and logs when it
// changes. (No on-demand gossip hook exists: the announcer re-derives
// capabilities from embedtarget each of its own intervals.)
func (r *Reconciler) publishEmbedTarget(placements []placement) {
	prev := embedtarget.Get()
	next := resolveEmbedTarget(placements)
	embedtarget.Set(next)
	if prev != next {
		slog.Info("reconcile.embed_target_changed",
			"from_backend", prev.Backend, "from_model", prev.Model,
			"to_backend", next.Backend, "to_model", next.Model)
	}
}

// surfaceEnvConflicts logs and records each ollama env conflict
// (refusal placement_env_conflict, target "ollama/<KEY>") and clears the
// ones that no longer conflict.
func (r *Reconciler) surfaceEnvConflicts(warnings []string) {
	now := map[string]bool{}
	for _, w := range warnings {
		key := w
		if i := strings.Index(w, ":"); i > 0 {
			key = w[:i]
		}
		target := "ollama/" + key
		now[target] = true
		slog.Warn("reconcile.placement_env_conflict", "detail", w)
		refusals.Record("placement_env_conflict", target, w)
	}
	for target := range r.envConflicts {
		if !now[target] {
			refusals.Clear("placement_env_conflict", target)
		}
	}
	r.envConflicts = now
}
