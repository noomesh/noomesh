// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package gpuyield shares a node's GPU with work that is not noomesh's.
//
// Nodes are multipurpose: the same box plays VR, trains models and runs a
// realtime voice stack. When something OUTSIDE noomesh needs the GPU the
// agent stays up, gives the GPU back (stops — never removes — its own GPU
// backend containers), says so on every heartbeat (`gpu_contention`), and
// starts them again on its own once the GPU has stayed free. Before this,
// the only way to free host3's GPU was to stop the agent, and the node
// vanished from the mesh (2026-10-16).
//
// Attribution. A GPU process is OURS when it runs in ANY noomesh container on
// the host (the agent's backends, the compose-managed controller stack such
// as noo-ollama-embed, name-only orphans; matched by the container id in the
// process's cgroup, see attribute); a process that cannot be attributed is
// UNKNOWN and never yields; everything else is foreign and is only ever measured — never
// signalled, stopped or reconfigured. Where nvidia-smi cannot name PIDs
// (WSL2: "[Not Found]"), ours is the expected footprint of the GPU backends
// running and foreign is the rest of memory.used ("memory-accounting").
//
// Policy (automatic): pressure is foreign usage above NOO_GPU_YIELD_FOREIGN_MB,
// or too little GPU left for what the placed GPU backends need. Pressure
// held for NOO_GPU_YIELD_AFTER_S (60 s) yields; the GPU staying clear for
// NOO_GPU_RESUME_AFTER_S (120 s) resumes. NOO_GPU_YIELD=off never yields.
//
// Hold (operator): `noo cluster gpu hold <node>` pauses now and never
// auto-resumes; `release` hands the node back to the automatic policy. That
// is how the operator hands the GPU to a stack that refuses to start while
// the GPU is occupied (pai-voice): hold, start it, later stop it, release.
// A hold is an owned lease (operation id, owner, generation) and, by
// default, drains the GPU backends before it stops them: see lease.go.
package gpuyield

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// States reported in gpu_contention.state.
const (
	StateFree    = "free"    // no foreign GPU use worth naming
	StateShared  = "shared"  // foreign use present, our backends still fit and run
	StateYielded = "yielded" // automatic: our GPU backends are paused for foreign work
	StateHeld    = "held"    // operator hold: paused, no auto-resume until release
	// StateDraining: a hold in mode drain is waiting for the GPU backends'
	// requests in flight to finish; nothing new is admitted, nothing is
	// stopped yet. Ends in held, or the hold is aborted (needs_attention).
	StateDraining = "draining"
)

// Methods reported in gpu_contention.method.
const (
	MethodNVML       = "nvml" // reserved: a cgo build with NVML
	MethodSMI        = "nvidia-smi"
	MethodAccounting = "memory-accounting"
	// The *Unattributed methods: some GPU memory could not be assigned to
	// noomesh or to someone else (no docker access, PID gone, PIDs hidden and
	// a noomesh GPU container of unknown size). That memory is reported as
	// unknown_mb and NEVER counted as foreign: the node does not yield on it.
	MethodSMIUnattributed        = "nvidia-smi-unattributed"
	MethodAccountingUnattributed = "memory-accounting-unattributed"
	MethodNotMeasured            = "not-measured"
)

// PauseReason is what a paused backend is marked with.
const PauseReason = "gpu_in_use_by_other"

// idleResidueMB: foreign use at or below this is not contention. pai-voice
// drained to idle still holds ~113 MiB; a bare-metal driver/Xorg a few
// hundred. Neither is "the GPU is in use by something else".
const idleResidueMB = 256

// Docker is the container surface the yield needs (internal/docker.Client).
type Docker interface {
	GPUBackendContainers(ctx context.Context) ([]docker.GPUBackend, error)
	StopContainerGraceful(ctx context.Context, id string, timeoutS int) error
	StartContainer(ctx context.Context, id string) error
	// NoomeshContainers is every container that is noomesh's on this host
	// (stack, agent backends, orphans), for GPU attribution.
	NoomeshContainers(ctx context.Context) ([]docker.NoomeshContainer, error)
}

// Config is the operator's knobs (env, read once at start).
type Config struct {
	Enabled     bool          // NOO_GPU_YIELD != off
	ForeignMB   int           // NOO_GPU_YIELD_FOREIGN_MB, default 2048
	YieldAfter  time.Duration // NOO_GPU_YIELD_AFTER_S, default 60s
	ResumeAfter time.Duration // NOO_GPU_RESUME_AFTER_S, default 120s
	Interval    time.Duration // poll period, 15s
	StopTimeout int           // seconds of SIGTERM grace on a pause, 30
}

// ConfigFromEnv reads the knobs; bad values fall back to the defaults.
func ConfigFromEnv(getenv func(string) string) Config {
	c := Config{Enabled: true, ForeignMB: 2048, YieldAfter: 60 * time.Second,
		ResumeAfter: 120 * time.Second, Interval: 15 * time.Second, StopTimeout: 30}
	switch strings.ToLower(strings.TrimSpace(getenv("NOO_GPU_YIELD"))) {
	case "off", "0", "false", "no", "disabled":
		c.Enabled = false
	}
	if n, err := strconv.Atoi(strings.TrimSpace(getenv("NOO_GPU_YIELD_FOREIGN_MB"))); err == nil && n >= 0 {
		c.ForeignMB = n
	}
	if n, err := strconv.Atoi(strings.TrimSpace(getenv("NOO_GPU_YIELD_AFTER_S"))); err == nil && n >= 0 {
		c.YieldAfter = time.Duration(n) * time.Second
	}
	if n, err := strconv.Atoi(strings.TrimSpace(getenv("NOO_GPU_RESUME_AFTER_S"))); err == nil && n >= 0 {
		c.ResumeAfter = time.Duration(n) * time.Second
	}
	return c
}

// Placed is a placement the reconciler holds for this node, as far as GPU
// sizing goes.
type Placed struct {
	Backend          string
	Target           string // "gpu" | "cpu" | ""
	Env              map[string]string
	MemoryLimitBytes int64
}

// Contention is the heartbeat's `gpu_contention`. Field names are a
// contract with the gateway, the CLI and the router — keep them stable.
type Contention struct {
	State     string `json:"state"`
	ForeignMB int    `json:"foreign_mb"`
	// NoomeshMB: GPU memory held by noomesh's own containers (stack,
	// backends, orphans). Never contention.
	NoomeshMB int `json:"noomesh_mb"`
	// UnknownMB: GPU memory whose owner could not be determined. Never
	// counted as foreign, never yields.
	UnknownMB int `json:"unknown_mb"`
	// Orphan: noomesh containers holding the GPU that nothing current owns
	// (no stack/agent label; recognised by name) — clean these up.
	Orphan         []string `json:"orphan,omitempty"`
	TotalMB        int      `json:"total_mb"`
	FreeMB         int      `json:"free_mb"`
	Method         string   `json:"method"`
	Since          string   `json:"since"`
	PausedBackends []string `json:"paused_backends"`
	// NeedMB is what the placed GPU backends need (0 = unknown/none).
	NeedMB int `json:"need_mb"`
	// Reason: the hold's reason, or why the automatic policy yielded.
	Reason string `json:"reason,omitempty"`
	// Unmeasured: why the GPU is not measured (method "not-measured"):
	// unified-memory | no-nvidia | probe-timeout | driver-lost.
	Unmeasured string `json:"unmeasured,omitempty"`
	// UnmeasuredDetail: short first-line nvidia-smi error, for driver-lost.
	UnmeasuredDetail string `json:"unmeasured_detail,omitempty"`
	// Policy: "auto" | "off" (NOO_GPU_YIELD=off).
	Policy string `json:"policy"`
	// Generation counts accepted holds on this node (persisted; never
	// reset). A release must quote the generation its hold was given.
	Generation uint64 `json:"generation"`
	// Lease is the current hold's owner and ids while held or draining.
	Lease *Lease `json:"lease,omitempty"`
	// GPUBackends are the backends that use the GPU (running, or placed on
	// it): what a hold pauses. The gateway takes exactly these lanes out of
	// routing while a hold drains, leaving the node's CPU lanes serving.
	GPUBackends []string `json:"gpu_backends"`
}

// persisted is what survives an agent restart, so a restarted agent does
// not race its own reconciler into starting a backend it had paused.
type persisted struct {
	State      string            `json:"state"`
	Since      time.Time         `json:"since"`
	Reason     string            `json:"reason"`
	Stopped    map[string]string `json:"stopped"` // backend -> container id we stopped
	Paused     []string          `json:"paused"`
	Generation uint64            `json:"generation"`
	Lease      *Lease            `json:"lease,omitempty"`
}

// Controller runs the policy.
type Controller struct {
	cfg      Config
	probe    Probe
	docker   Docker
	now      func() time.Time
	cgroupOf func(pid int) string
	path     string // persistence file; "" = none

	mu          sync.Mutex
	state       string
	since       time.Time
	reason      string
	method      string
	last        Reading
	foreignMB   int
	noomeshMB   int
	unknownMB   int
	orphans     []string
	unknownNote string
	needMB      int
	pressureAt  time.Time // first tick of the current pressure run
	clearAt     time.Time // first tick of the current clear run
	stopped     map[string]string
	paused      map[string]bool // backends held down (reconcile must not start)
	gpuSet      map[string]bool // backends that use the GPU, last tick
	placed      []Placed
	measured    map[string]int // backend -> last measured MiB (PID method)
	onResume    func()
	lastNoMeter bool
	// unmeasured / unmeasuredDetail: the cause of the last unmeasured
	// reading; cleared on a measured one.
	unmeasured       string
	unmeasuredDetail string
	owned            []docker.NoomeshContainer // this tick's noomesh containers
	ownedErr         error                     // non-nil: docker could not list them
	// listErr is the last GPU-backend listing failure, so a host with no
	// docker (a Mac running a native ollama) warns once per cause, not
	// once per tick.
	listErr string

	// The hold lease (lease.go).
	generation uint64
	lease      *Lease
	// transition: a hold or release is in progress; a second one is
	// refused (ErrTransition) rather than interleaved.
	transition bool
	// drainer closes admission and waits for in-flight requests on a drain
	// hold; nil = no proxy on this agent, a drain is idle at once.
	drainer Drainer
	// drainTimeout bounds a drain whose request named none.
	drainTimeout time.Duration
}

// New builds a controller. stateDir may be "" (no persistence).
func New(cfg Config, probe Probe, d Docker, stateDir string) *Controller {
	c := &Controller{
		cfg: cfg, probe: probe, docker: d, now: time.Now, cgroupOf: procCgroup,
		state: StateFree, method: MethodNotMeasured,
		stopped: map[string]string{}, paused: map[string]bool{},
		gpuSet: map[string]bool{}, measured: map[string]int{},
		drainTimeout: DefaultDrainTimeout,
	}
	c.since = c.now()
	if stateDir != "" {
		c.path = filepath.Join(stateDir, "gpu-yield.json")
		c.load()
	}
	return c
}

// OnResume installs a hook run after a resume (the reconciler's nudge, so a
// placed backend that was never started comes up without waiting a tick).
func (c *Controller) OnResume(f func()) { c.onResume = f }

// SetPlacements records the node's placements (reconcile, every tick).
func (c *Controller) SetPlacements(p []Placed) {
	c.mu.Lock()
	c.placed = append([]Placed(nil), p...)
	c.mu.Unlock()
}

// Holds reports whether reconcile must NOT start backend now: it is paused
// (yielded or held), or the GPU is under pressure that is about to yield it.
// Not fighting the yield is the whole contract.
func (c *Controller) Holds(backend string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused[backend] {
		return true
	}
	if !c.isGPUBackendLocked(backend) {
		return false
	}
	if c.state == StateYielded || c.state == StateHeld || c.state == StateDraining {
		return true
	}
	return c.cfg.Enabled && !c.pressureAt.IsZero()
}

func (c *Controller) isGPUBackendLocked(backend string) bool {
	if c.gpuSet[backend] {
		return true
	}
	for _, p := range c.placed {
		if p.Backend == backend && placedOnGPU(p) {
			return true
		}
	}
	return false
}

// refreshGPUSetLocked rebuilds the set of GPU backends from this tick's
// containers and placements (an unplaced backend drops out of the need).
func (c *Controller) refreshGPUSetLocked(backends []docker.GPUBackend) {
	c.gpuSet = map[string]bool{}
	for _, b := range backends {
		c.gpuSet[b.Backend] = true
	}
	for _, p := range c.placed {
		if placedOnGPU(p) {
			c.gpuSet[p.Backend] = true
		}
	}
}

func placedOnGPU(p Placed) bool {
	if p.Target == "cpu" {
		return false
	}
	return p.Backend == "vllm" || p.Target == "gpu"
}

// Report is the heartbeat value.
func (c *Controller) Report() Contention {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := Contention{
		State: c.state, ForeignMB: c.foreignMB, NoomeshMB: c.noomeshMB, UnknownMB: c.unknownMB,
		Orphan: append([]string(nil), c.orphans...), TotalMB: c.last.TotalMB,
		Method: c.method, Since: c.since.UTC().Format(time.RFC3339),
		PausedBackends: sortedKeys(c.paused), NeedMB: c.needMB, Reason: c.reason, Policy: "auto",
		Generation: c.generation, Lease: c.lease.clone(), GPUBackends: sortedKeys(c.gpuSet),
		Unmeasured: c.unmeasured, UnmeasuredDetail: c.unmeasuredDetail,
	}
	if c.last.Measured {
		r.FreeMB = c.last.TotalMB - c.last.UsedMB
		if r.FreeMB < 0 {
			r.FreeMB = 0
		}
	}
	if !c.cfg.Enabled {
		r.Policy = "off"
	}
	if r.Reason == "" && c.unknownMB > 0 {
		r.Reason = c.unknownNote
	}
	return r
}

// Run polls until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	c.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Tick(ctx)
		}
	}
}

// noteListErr logs a GPU-backend listing failure when it starts or changes,
// and the recovery once; the same failure every tick is logged at debug.
func (c *Controller) noteListErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		if c.listErr != "" {
			slog.Info("gpuyield: listing GPU backend containers works again")
		}
		c.listErr = ""
		return
	}
	if err.Error() == c.listErr {
		slog.Debug("gpuyield: listing GPU backend containers still failing", "error", err)
		return
	}
	c.listErr = err.Error()
	slog.Warn("gpuyield: listing GPU backend containers failed (logged once per cause)", "error", err)
}

// Tick is one sample + decision.
func (c *Controller) Tick(ctx context.Context) {
	r := c.probe.Read(ctx)
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	backends, err := c.docker.GPUBackendContainers(lctx)
	cancel()
	c.noteListErr(err)
	if err != nil {
		backends = nil
	}

	octx, ocancel := context.WithTimeout(ctx, 20*time.Second)
	owned, oerr := c.docker.NoomeshContainers(octx)
	ocancel()
	if oerr != nil {
		slog.Warn("gpuyield: listing noomesh containers failed; GPU attribution unknown", "error", oerr)
	}

	c.mu.Lock()
	c.owned, c.ownedErr = owned, oerr
	act := c.decideLocked(r, backends)
	c.mu.Unlock()
	c.execute(ctx, act)
}

// actions are the docker calls a decision needs, run OUTSIDE the lock: a
// graceful stop can take half a minute, and the heartbeat's Report must not
// wait on it.
type actions struct {
	stop    []docker.GPUBackend
	start   map[string]string // backend -> container id
	resumed bool
	why     string
}

func (c *Controller) decideLocked(r Reading, backends []docker.GPUBackend) (act actions) {
	now := c.now()
	c.last = r
	c.refreshGPUSetLocked(backends)

	if !r.Measured {
		// Nothing to judge by. Never pause on no data; a node already
		// paused stays paused (freeness cannot be confirmed either).
		c.method = MethodNotMeasured
		if r.Unmeasured == UnmeasuredDriverLost && c.unmeasured != UnmeasuredDriverLost {
			slog.Warn("gpuyield: the NVIDIA driver lost the GPU; GPU backends cannot start",
				"detail", r.UnmeasuredDetail)
		}
		c.unmeasured, c.unmeasuredDetail = r.Unmeasured, r.UnmeasuredDetail
		c.foreignMB, c.noomeshMB, c.unknownMB, c.orphans = 0, 0, 0, nil
		c.pressureAt, c.clearAt = time.Time{}, time.Time{}
		if !c.lastNoMeter {
			slog.Info("gpuyield: GPU memory not measurable on this node; yield inactive")
			c.lastNoMeter = true
		}
		if !c.cfg.Enabled && c.state == StateYielded {
			return c.resumeLocked("NOO_GPU_YIELD=off")
		}
		return c.enforceLocked(backends)
	}
	c.lastNoMeter = false
	c.unmeasured, c.unmeasuredDetail = "", ""

	att := c.attribute(r, backends)
	c.foreignMB, c.method = att.foreignMB, att.method
	c.noomeshMB, c.unknownMB, c.orphans, c.unknownNote = att.noomeshMB, att.unknownMB, att.orphans, att.note
	c.needMB = c.needLocked(r.TotalMB)
	available := r.TotalMB - c.foreignMB
	pressure, why := false, ""
	switch {
	case c.foreignMB > c.cfg.ForeignMB:
		pressure = true
		why = fmt.Sprintf("foreign GPU use %s > %s threshold", gb(c.foreignMB), gb(c.cfg.ForeignMB))
	case c.needMB > 0 && available < c.needMB:
		pressure = true
		why = fmt.Sprintf("%s left for noomesh < %s the GPU backends need", gb(available), gb(c.needMB))
	}

	switch c.state {
	case StateHeld:
		// Operator hold: report, never auto-resume.
		return c.enforceLocked(backends)
	case StateDraining:
		// A hold waiting for the backends to go idle: the tick only
		// reports; Hold stops them once they are.
		return act
	case StateYielded:
		if !c.cfg.Enabled {
			return c.resumeLocked("NOO_GPU_YIELD=off")
		}
		if pressure {
			c.clearAt = time.Time{}
			c.reason = why
			return c.enforceLocked(backends)
		}
		if c.unknownMB > 0 {
			// Freeness cannot be confirmed while some GPU memory has no
			// owner: stay paused rather than resume into a possible clash.
			c.clearAt = time.Time{}
			return c.enforceLocked(backends)
		}
		if c.clearAt.IsZero() {
			c.clearAt = now
		}
		if now.Sub(c.clearAt) >= c.cfg.ResumeAfter {
			return c.resumeLocked(fmt.Sprintf("GPU clear for %s", c.cfg.ResumeAfter))
		}
		return c.enforceLocked(backends)
	}

	// free / shared
	next := StateFree
	if c.foreignMB > idleResidueMB {
		next = StateShared
	}
	if !c.cfg.Enabled || !pressure {
		c.pressureAt = time.Time{}
		c.setStateLocked(next, "")
		return act
	}
	if c.pressureAt.IsZero() {
		c.pressureAt = now
		slog.Info("gpuyield: GPU contention observed; yielding if it persists",
			"why", why, "after", c.cfg.YieldAfter)
	}
	c.setStateLocked(next, why)
	if now.Sub(c.pressureAt) >= c.cfg.YieldAfter {
		return c.pauseLocked(backends, StateYielded, why)
	}
	return act
}

// enforceLocked keeps a pause a pause: a paused backend found running again
// (a failed stop, a manual start, a restart policy) is stopped again.
func (c *Controller) enforceLocked(backends []docker.GPUBackend) (act actions) {
	if c.state != StateYielded && c.state != StateHeld {
		return act
	}
	for _, b := range backends {
		if b.Running && c.paused[b.Backend] {
			act.stop = append(act.stop, b)
			c.stopped[b.Backend] = b.ID
		}
	}
	act.why = c.reason
	return act
}

// execute performs a decision's docker calls.
func (c *Controller) execute(ctx context.Context, act actions) {
	for _, b := range act.stop {
		sctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.StopTimeout+15)*time.Second)
		err := c.docker.StopContainerGraceful(sctx, b.ID, c.cfg.StopTimeout)
		cancel()
		if err != nil {
			slog.Error("gpuyield: stopping backend failed; retrying next tick", "backend", b.Backend, "error", err)
			continue
		}
		slog.Warn("gpuyield: backend paused: GPU in use by other work",
			"backend", b.Backend, "container", b.Name, "paused", PauseReason, "reason", act.why)
	}
	for backend, id := range act.start {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.docker.StartContainer(sctx, id)
		cancel()
		if err != nil {
			// Gone or broken: the reconciler recreates it from the placement.
			slog.Warn("gpuyield: restarting paused backend failed; reconcile will recreate it",
				"backend", backend, "error", err)
		} else {
			slog.Info("gpuyield: backend resumed", "backend", backend, "why", act.why)
		}
	}
	if act.resumed && c.onResume != nil {
		go c.onResume()
	}
}

// attribution is one tick's split of memory.used.
type attribution struct {
	foreignMB, noomeshMB, unknownMB int
	method                          string
	orphans                         []string
	note                            string
}

// containerIDRe finds a container id in a cgroup path ("docker-<64 hex>.scope"
// on systemd hosts, "/docker/<64 hex>" on cgroupfs, "cri-containerd-" etc.).
var containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

// attribute splits memory.used into noomesh's, foreign and unknown.
//
// Chosen design: PID -> cgroup -> container id -> "is that container
// noomesh's" (labels first, `noo-` name as fallback; see
// docker.ClassifyNoomesh). The cgroup file is world-readable, so the
// unprivileged agent needs only the docker socket it already has. It covers
// every noomesh container on the host, not just the backends this agent
// starts: the compose-managed noo-ollama-embed / noo-tei / ... and
// older-image orphans hold GPU memory too, and counting them as foreign made
// a controller yield its own chat backend to its own embedder (pop-os,
// 2026-10-21).
//
// Fail-safe: a process that cannot be attributed (cgroup unreadable or PID
// gone, a container id with docker unable to say whose it is) is UNKNOWN,
// not foreign. Unknown memory never feeds the yield decision. The cost: if a
// foreign app starts while attribution is broken, the node does not yield to
// it until attribution works again (the operator can still `noo cluster gpu
// hold`). The alternative cost, pausing a healthy node on a guess, is a
// self-inflicted outage on the very nodes with the least visibility.
func (c *Controller) attribute(r Reading, backends []docker.GPUBackend) attribution {
	running := map[string]docker.GPUBackend{}
	for _, b := range backends {
		if b.Running {
			running[b.Backend] = b
		}
	}
	// Owned container lookup by full id. Backends are noomesh's by
	// definition even if the wider listing failed.
	ownedByID := map[string]docker.NoomeshContainer{}
	for _, o := range c.owned {
		ownedByID[o.ID] = o
	}
	for _, b := range backends {
		if _, ok := ownedByID[b.ID]; !ok {
			ownedByID[b.ID] = docker.NoomeshContainer{ID: b.ID, Name: b.Name, Running: b.Running}
		}
	}
	listOK := c.ownedErr == nil

	if r.AppsResolved {
		var att attribution
		oursByBackend := map[string]int{}
		orphan := map[string]bool{}
		var unknownPIDs []int
		for _, a := range r.Apps {
			cg := c.cgroupOf(a.PID)
			if cg == "" {
				att.unknownMB += a.UsedMB
				unknownPIDs = append(unknownPIDs, a.PID)
				continue
			}
			id := containerIDRe.FindString(cg)
			if id == "" {
				// Readable cgroup with no container in it: a host process.
				att.foreignMB += a.UsedMB
				continue
			}
			if o, ok := ownedByID[id]; ok {
				att.noomeshMB += a.UsedMB
				if o.Orphan {
					orphan[o.Name] = true
				}
				for name, b := range running {
					if b.ID == id {
						oursByBackend[name] += a.UsedMB
					}
				}
				continue
			}
			if !listOK {
				// A container, and docker cannot say whose.
				att.unknownMB += a.UsedMB
				unknownPIDs = append(unknownPIDs, a.PID)
				continue
			}
			att.foreignMB += a.UsedMB // someone else's container (pai-voice, ...)
		}
		// PIDs are trusted only if they can see our own processes: a running
		// GPU backend with no attributed process means this driver does not
		// list container PIDs, and treating its memory as foreign would make
		// the node yield to itself.
		believable := true
		for name := range running {
			if oursByBackend[name] == 0 {
				believable = false
			}
		}
		if believable {
			for k, v := range oursByBackend {
				c.measured[k] = v
			}
			att.method = MethodSMI
			att.orphans = sortedKeys(orphan)
			if att.unknownMB > 0 {
				att.method = MethodSMIUnattributed
				att.note = fmt.Sprintf("GPU attribution unknown for %s (pids %v, docker listing ok=%t): not counted as foreign, not yielding on it",
					gb(att.unknownMB), unknownPIDs, listOK)
			}
			return att
		}
	}
	// PIDs are not usable (WSL2 "[Not Found]", or a driver that hides
	// container PIDs): ours is the expected footprint of the GPU backends
	// running, the rest is foreign. That arithmetic is only sound if the
	// backends are all the noomesh GPU use there is.
	expected := 0
	for name := range running {
		expected += c.expectedLocked(name, r.TotalMB)
	}
	rest := clampMB(r.UsedMB - expected)
	att := attribution{method: MethodAccounting, noomeshMB: min(expected, r.UsedMB), foreignMB: rest}
	var extra []string
	for _, o := range c.owned {
		if !o.Running || !o.GPU {
			continue
		}
		known := false
		for _, b := range running {
			if b.ID == o.ID {
				known = true
			}
		}
		if !known {
			extra = append(extra, o.Name)
			if o.Orphan {
				att.orphans = append(att.orphans, o.Name)
			}
		}
	}
	sort.Strings(att.orphans)
	if !listOK || len(extra) > 0 {
		// The remainder may be a noomesh container whose size we cannot
		// know without PIDs (or docker could not even list them).
		att.method = MethodAccountingUnattributed
		att.unknownMB, att.foreignMB = rest, 0
		why := "docker listing failed"
		if listOK {
			why = fmt.Sprintf("noomesh GPU container(s) %s hold GPU memory and per-process figures are unavailable", strings.Join(extra, ", "))
		}
		att.note = fmt.Sprintf("GPU attribution unknown for %s (%s): not counted as foreign, not yielding on it", gb(rest), why)
	}
	return att
}

// expectedLocked is a running backend's GPU footprint when it cannot be
// measured: vLLM preallocates gpu_memory_utilization × total; a llama.cpp
// placement carries its fit estimate; else the last measured figure.
func (c *Controller) expectedLocked(backend string, totalMB int) int {
	if n := c.needForLocked(backend, totalMB); n > 0 {
		return n
	}
	return c.measured[backend]
}

// needLocked is the GPU memory the node's GPU backends need to run.
func (c *Controller) needLocked(totalMB int) int {
	need := 0
	for b := range c.gpuSet {
		n := c.needForLocked(b, totalMB)
		if n == 0 {
			n = c.measured[b]
		}
		need += n
	}
	return need
}

func (c *Controller) needForLocked(backend string, totalMB int) int {
	for _, p := range c.placed {
		if p.Backend != backend {
			continue
		}
		if backend == "vllm" {
			util := 0.9
			if v, err := strconv.ParseFloat(strings.TrimSpace(p.Env["GPU_MEMORY_UTILIZATION"]), 64); err == nil && v > 0 && v <= 1 {
				util = v
			}
			return int(util * float64(totalMB))
		}
		if p.MemoryLimitBytes > 0 {
			return int(p.MemoryLimitBytes / (1 << 20))
		}
	}
	if backend == "vllm" {
		return int(0.9 * float64(totalMB))
	}
	return 0
}

func (c *Controller) setStateLocked(s, reason string) {
	if c.state != s {
		c.state = s
		c.since = c.now()
	}
	c.reason = reason
}

// pauseLocked marks every GPU backend paused and returns the running ones
// to stop (graceful, never removed).
func (c *Controller) pauseLocked(backends []docker.GPUBackend, state, reason string) (act actions) {
	for _, b := range backends {
		c.paused[b.Backend] = true
		if b.Running {
			act.stop = append(act.stop, b)
			c.stopped[b.Backend] = b.ID
		}
	}
	for b := range c.gpuSet {
		c.paused[b] = true
	}
	c.pressureAt, c.clearAt = time.Time{}, time.Time{}
	c.state = state
	c.since = c.now()
	c.reason = reason
	c.saveLocked()
	act.why = reason
	return act
}

// resumeLocked clears the pause and returns what to start again: the
// containers the yield stopped, if they are still placed.
func (c *Controller) resumeLocked(why string) (act actions) {
	act.start = map[string]string{}
	for backend, id := range c.stopped {
		if !c.stillPlacedLocked(backend) {
			// Unplaced (or set to stopped) while paused: leave it down.
			slog.Info("gpuyield: paused backend no longer placed; not restarting", "backend", backend)
			continue
		}
		act.start[backend] = id
	}
	c.stopped = map[string]string{}
	c.paused = map[string]bool{}
	c.pressureAt, c.clearAt = time.Time{}, time.Time{}
	next := StateFree
	if c.foreignMB > idleResidueMB {
		next = StateShared
	}
	c.state = next
	c.since = c.now()
	c.reason = ""
	c.saveLocked()
	act.resumed = true
	act.why = why
	return act
}

func (c *Controller) stillPlacedLocked(backend string) bool {
	for _, p := range c.placed {
		if p.Backend == backend {
			return true
		}
	}
	return false
}

func (c *Controller) saveLocked() {
	if c.path == "" {
		return
	}
	p := persisted{State: c.state, Since: c.since, Reason: c.reason, Stopped: c.stopped, Paused: sortedKeys(c.paused),
		Generation: c.generation, Lease: c.lease}
	b, _ := json.Marshal(p)
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		slog.Warn("gpuyield: state not persisted", "error", err)
		return
	}
	_ = os.Rename(tmp, c.path)
}

func (c *Controller) load() {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var p persisted
	if json.Unmarshal(b, &p) != nil {
		return
	}
	// The generation outlives every state: a release quoting a hold from
	// before the restart must still be told apart from a fresh one.
	c.generation = p.Generation
	if p.State == StateDraining {
		// A drain that the restart cut short: nothing was stopped, so
		// nothing is restored; the caller saw its hold fail or time out.
		slog.Warn("gpuyield: a draining hold did not survive the agent restart; not held", "lease", p.Lease)
		return
	}
	if p.State != StateYielded && p.State != StateHeld {
		return
	}
	c.state, c.since, c.reason = p.State, p.Since, p.Reason
	if p.State == StateHeld {
		c.lease = p.Lease
	}
	for k, v := range p.Stopped {
		c.stopped[k] = v
	}
	for _, k := range p.Paused {
		c.paused[k] = true
	}
	slog.Info("gpuyield: restored pause across agent restart", "state", c.state, "paused", p.Paused)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func clampMB(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func gb(mb int) string { return fmt.Sprintf("%.1f GB", float64(mb)/1024) }

// ── package default, for the reconciler and heartbeat (wired in agent) ──

var (
	defMu sync.RWMutex
	def   *Controller
)

// SetDefault installs the node's controller.
func SetDefault(c *Controller) { defMu.Lock(); def = c; defMu.Unlock() }

// Default is the installed controller, or nil.
func Default() *Controller { defMu.RLock(); defer defMu.RUnlock(); return def }

// HoldsStart is Holds on the default controller; false when none is wired.
func HoldsStart(backend string) bool {
	if c := Default(); c != nil {
		return c.Holds(backend)
	}
	return false
}

// PublishPlacements forwards placements to the default controller.
func PublishPlacements(p []Placed) {
	if c := Default(); c != nil {
		c.SetPlacements(p)
	}
}
