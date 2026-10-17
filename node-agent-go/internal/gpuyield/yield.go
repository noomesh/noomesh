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
// Attribution. A GPU process is OURS when it runs in a container this agent
// manages (`noo-<backend>`, matched by the container id in the process's
// cgroup); everything else is foreign and is only ever measured — never
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
package gpuyield

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
)

// Methods reported in gpu_contention.method.
const (
	MethodNVML        = "nvml" // reserved: a cgo build with NVML
	MethodSMI         = "nvidia-smi"
	MethodAccounting  = "memory-accounting"
	MethodNotMeasured = "not-measured"
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
	State          string   `json:"state"`
	ForeignMB      int      `json:"foreign_mb"`
	TotalMB        int      `json:"total_mb"`
	FreeMB         int      `json:"free_mb"`
	Method         string   `json:"method"`
	Since          string   `json:"since"`
	PausedBackends []string `json:"paused_backends"`
	// NeedMB is what the placed GPU backends need (0 = unknown/none).
	NeedMB int `json:"need_mb"`
	// Reason: the hold's reason, or why the automatic policy yielded.
	Reason string `json:"reason,omitempty"`
	// Policy: "auto" | "off" (NOO_GPU_YIELD=off).
	Policy string `json:"policy"`
}

// persisted is what survives an agent restart, so a restarted agent does
// not race its own reconciler into starting a backend it had paused.
type persisted struct {
	State   string            `json:"state"`
	Since   time.Time         `json:"since"`
	Reason  string            `json:"reason"`
	Stopped map[string]string `json:"stopped"` // backend -> container id we stopped
	Paused  []string          `json:"paused"`
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
}

// New builds a controller. stateDir may be "" (no persistence).
func New(cfg Config, probe Probe, d Docker, stateDir string) *Controller {
	c := &Controller{
		cfg: cfg, probe: probe, docker: d, now: time.Now, cgroupOf: procCgroup,
		state: StateFree, method: MethodNotMeasured,
		stopped: map[string]string{}, paused: map[string]bool{},
		gpuSet: map[string]bool{}, measured: map[string]int{},
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
	if c.state == StateYielded || c.state == StateHeld {
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
		State: c.state, ForeignMB: c.foreignMB, TotalMB: c.last.TotalMB,
		Method: c.method, Since: c.since.UTC().Format(time.RFC3339),
		PausedBackends: sortedKeys(c.paused), NeedMB: c.needMB, Reason: c.reason, Policy: "auto",
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

// Tick is one sample + decision.
func (c *Controller) Tick(ctx context.Context) {
	r := c.probe.Read(ctx)
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	backends, err := c.docker.GPUBackendContainers(lctx)
	cancel()
	if err != nil {
		slog.Warn("gpuyield: listing GPU backend containers failed", "error", err)
		backends = nil
	}

	c.mu.Lock()
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
		c.foreignMB = 0
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

	c.foreignMB, c.method = c.attribute(r, backends)
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
	case StateYielded:
		if !c.cfg.Enabled {
			return c.resumeLocked("NOO_GPU_YIELD=off")
		}
		if pressure {
			c.clearAt = time.Time{}
			c.reason = why
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

// attribute splits memory.used into ours and foreign.
func (c *Controller) attribute(r Reading, backends []docker.GPUBackend) (int, string) {
	running := map[string]docker.GPUBackend{}
	for _, b := range backends {
		if b.Running {
			running[b.Backend] = b
		}
	}
	if r.AppsResolved {
		ours, oursByBackend := 0, map[string]int{}
		for _, a := range r.Apps {
			cg := c.cgroupOf(a.PID)
			for name, b := range running {
				if cg != "" && strings.Contains(cg, b.ID) {
					ours += a.UsedMB
					oursByBackend[name] += a.UsedMB
					break
				}
			}
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
			return clampMB(r.UsedMB - ours), MethodSMI
		}
	}
	expected := 0
	for name := range running {
		expected += c.expectedLocked(name, r.TotalMB)
	}
	return clampMB(r.UsedMB - expected), MethodAccounting
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

// Hold pauses the GPU backends now and keeps them paused until Release.
func (c *Controller) Hold(ctx context.Context, reason string) Contention {
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	backends, err := c.docker.GPUBackendContainers(lctx)
	cancel()
	if err != nil {
		slog.Warn("gpuyield: hold could not list GPU backends", "error", err)
	}
	c.mu.Lock()
	c.refreshGPUSetLocked(backends)
	if reason == "" {
		reason = "operator hold"
	}
	slog.Warn("gpuyield: operator GPU hold", "reason", reason)
	act := c.pauseLocked(backends, StateHeld, reason)
	c.mu.Unlock()
	c.execute(ctx, act)
	return c.Report()
}

// Release ends an operator hold: the node returns to the automatic policy,
// which resumes once the GPU has stayed clear for the resume window.
func (c *Controller) Release() Contention {
	c.mu.Lock()
	if c.state == StateHeld {
		slog.Info("gpuyield: operator GPU hold released; automatic policy resumes when the GPU is free")
		c.state = StateYielded
		c.since = c.now()
		c.reason = "hold released; resuming when the GPU is free"
		c.clearAt = time.Time{}
		if len(c.paused) == 0 {
			c.state = StateFree
			c.reason = ""
		}
		c.saveLocked()
	}
	c.mu.Unlock()
	return c.Report()
}

func (c *Controller) saveLocked() {
	if c.path == "" {
		return
	}
	p := persisted{State: c.state, Since: c.since, Reason: c.reason, Stopped: c.stopped, Paused: sortedKeys(c.paused)}
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
	if p.State != StateYielded && p.State != StateHeld {
		return
	}
	c.state, c.since, c.reason = p.State, p.Since, p.Reason
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
