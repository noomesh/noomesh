// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package gpuwatch keeps GPU-requesting containers actually able to reach
// the GPU.
//
// The predecessor was a crontab script on one node with a hardcoded watch
// list; the list went stale and the script no-opped silently for weeks.
// This version lives in the agent so it is versioned, fleet-wide, and
// upgraded over the binary rail — and it derives its watch list from each
// container's own config (DeviceRequests / nvidia runtime) every cycle, so
// there is no list to go stale.
//
// The check is device VISIBILITY, not utilization: `nvidia-smi -L` inside
// the container must succeed whenever the runtime granted a GPU, idle or
// not. Utilization/compute-apps checks are unsound as health (on-demand
// backends unload between requests) and are reported as telemetry only.
//
// Division of labour with the controller: the HARD wedge (host nvidia-smi
// dead, Xid 79 class) is the gpu_health autonomy location's — the /gpu
// probe reports available:false and recovery is a reboot, never automated.
// This watchdog owns the SOFT class: host GPU fine, container's grant
// broken (started before the driver, stale device refs after a driver
// bounce). There a restart genuinely heals, so it restarts once and
// escalates to a fault — surfaced via /gpu for the controller to alert on
// — only if the container still cannot see the GPU afterwards.
package gpuwatch

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// DockerAPI is the container surface the watchdog needs; the concrete
// implementation is internal/docker.Client.
type DockerAPI interface {
	GPUContainers(ctx context.Context) ([]docker.GPUContainer, error)
	ExecProbe(ctx context.Context, containerID string, cmd []string) (int, error)
	RestartContainer(ctx context.Context, containerID string) error
}

const (
	defaultInterval = 5 * time.Minute
	probeTimeout    = 30 * time.Second
	// restartCooldown bounds remediation: at most one restart per container
	// per cooldown, so a persistently broken container becomes a FAULT the
	// controller alerts on instead of a silent restart loop.
	restartCooldown = 30 * time.Minute
)

// probe status values, serialized into the /gpu payload.
const (
	statusOK           = "ok"
	statusSuspect      = "suspect"      // first failed probe — transient until confirmed
	statusRestarted    = "restarted"    // second failure, remediation attempted
	statusFault        = "fault"        // still failing after a restart — alert-worthy
	statusUnverifiable = "unverifiable" // image lacks nvidia-smi; probe impossible
	statusServing      = "serving"      // probe says no GPU, but the backend is answering
	statusUnmanaged    = "unmanaged"    // requests a GPU but is not the cluster's — observed, never touched
)

// ContainerStatus is the per-container verdict of the last cycle.
type ContainerStatus struct {
	Name          string     `json:"name"`
	Status        string     `json:"status"`
	Detail        string     `json:"detail,omitempty"`
	LastRestartAt *time.Time `json:"last_restart_at,omitempty"`
}

// State is the watchdog's report, embedded in the /gpu payload. Faults is
// the field the controller's gpu_health evaluator alerts on; agents older
// than this feature simply omit the whole object, which the evaluator
// treats as unknown — the same version-skew contract as `available`.
type State struct {
	LastRunAt  time.Time         `json:"last_run_at"`
	HostGPU    string            `json:"host_gpu"` // "ok" | "unavailable"
	Containers []ContainerStatus `json:"containers"`
	Faults     []string          `json:"faults"`
	Restarts   int               `json:"restarts_total"`
}

// Watchdog runs the periodic check.
type Watchdog struct {
	docker    DockerAPI
	hostProbe func() bool // host nvidia-smi reachable?
	// serving reports whether the backend in this container is actually
	// answering requests. nil means "cannot tell", which never blocks a
	// restart — absence of evidence is not evidence of health.
	serving  func(ctx context.Context, container string) bool
	interval time.Duration
	now      func() time.Time

	mu         sync.Mutex
	state      State
	failStreak map[string]int // container name -> consecutive failed probes
	// servingNoted marks containers whose "probe failed but the backend is
	// serving" verdict has already been logged once. Under WSL2 nvidia-smi can
	// fail inside a container for as long as it runs, so that verdict repeats
	// every cycle; logging it every time buried real faults (awolf, 2026-10).
	servingNoted map[string]bool
	lastRestart  map[string]time.Time
	restartTotal int
}

// New builds a watchdog. hostProbe reports whether the host itself can see
// the GPU (e.g. a cheap nvidia-smi query); when it cannot, container checks
// and restarts are skipped — restarting containers cannot heal a wedged bus.
func New(d DockerAPI, hostProbe func() bool) *Watchdog {
	return &Watchdog{
		docker:       d,
		hostProbe:    hostProbe,
		interval:     defaultInterval,
		now:          time.Now,
		failStreak:   map[string]int{},
		servingNoted: map[string]bool{},
		lastRestart:  map[string]time.Time{},
	}
}

// SetServingProbe supplies the "is this backend actually answering?" check.
//
// Without it the watchdog restarts on the GPU probe alone, and that is how it
// recycled a vLLM container that was serving chat normally: `nvidia-smi` inside
// the container exited non-zero twice while the GPU was demonstrably present —
// verified by hand afterwards, both inside the container and on the host, both
// listing the card. The restart then took the backend down for the length of a
// 9.6 GB weight reload and surfaced to the operator as "backend unreachable",
// which points at the wrong thing entirely.
func (w *Watchdog) SetServingProbe(f func(ctx context.Context, container string) bool) {
	w.serving = f
}

// State returns a copy of the last cycle's report.
func (w *Watchdog) State() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := w.state
	st.Containers = append([]ContainerStatus(nil), w.state.Containers...)
	st.Faults = append([]string(nil), w.state.Faults...)
	return st
}

// Run executes check cycles until ctx is cancelled. The first cycle runs
// immediately so a fresh agent reports within seconds, not minutes.
func (w *Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	w.Check(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Check(ctx)
		}
	}
}

// Check runs one watchdog cycle.
func (w *Watchdog) Check(ctx context.Context) {
	st := State{LastRunAt: w.now(), HostGPU: statusOK, Faults: []string{}}

	if !w.hostProbe() {
		// Hard-wedge territory: gpu_health owns the alert (via
		// available:false); nothing here can heal it.
		st.HostGPU = "unavailable"
		w.commit(st)
		return
	}

	cctx, cancel := context.WithTimeout(ctx, probeTimeout)
	containers, err := w.docker.GPUContainers(cctx)
	cancel()
	if err != nil {
		slog.Warn("gpuwatch: listing GPU containers failed", "error", err)
		w.commit(st)
		return
	}

	seen := map[string]bool{}
	for _, ctr := range containers {
		if !ctr.Managed {
			// Not ours (e.g. CI's buildx builder, which requests GPUs on
			// its own): visible in the report, but we do not exec into,
			// restart, or alert on containers the cluster does not own.
			st.Containers = append(st.Containers, ContainerStatus{Name: ctr.Name, Status: statusUnmanaged})
			continue
		}
		seen[ctr.Name] = true
		st.Containers = append(st.Containers, w.checkContainer(ctx, ctr, &st))
	}
	// Drop streak/restart bookkeeping for containers that no longer run.
	for name := range w.failStreak {
		if !seen[name] {
			delete(w.failStreak, name)
			delete(w.servingNoted, name)
			delete(w.lastRestart, name)
		}
	}
	w.commit(st)
}

func (w *Watchdog) checkContainer(ctx context.Context, ctr docker.GPUContainer, st *State) ContainerStatus {
	cs := ContainerStatus{Name: ctr.Name, Status: statusOK}
	if t, ok := w.lastRestart[ctr.Name]; ok {
		tt := t
		cs.LastRestartAt = &tt
	}

	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	code, err := w.docker.ExecProbe(pctx, ctr.ID, []string{"nvidia-smi", "-L"})
	cancel()

	if err != nil {
		// Probe impossible (no nvidia-smi in the image, container vanished
		// mid-probe): an explicit unknown, never a fault and never a reason
		// to restart. Real data or an explicit error — no guessing.
		cs.Status = statusUnverifiable
		cs.Detail = err.Error()
		w.failStreak[ctr.Name] = 0
		delete(w.servingNoted, ctr.Name)
		return cs
	}
	if code == 0 {
		w.failStreak[ctr.Name] = 0
		delete(w.servingNoted, ctr.Name)
		return cs
	}

	// The container requested a GPU and nvidia-smi inside it cannot reach
	// one while the host can — the soft-fallback class.
	w.failStreak[ctr.Name]++
	streak := w.failStreak[ctr.Name]
	if streak == 1 {
		cs.Status = statusSuspect
		cs.Detail = "nvidia-smi failed inside container; confirming next cycle"
		return cs
	}

	// A backend that is ANSWERING is not restarted, whatever the probe says.
	//
	// The remediation is a restart, and restarting a container that is serving
	// is strictly worse than the condition it claims to fix: for a large model
	// it means minutes of reload during which every request fails. `nvidia-smi`
	// exiting non-zero inside a busy container is not the same event as the
	// container having lost its GPU, and the two were treated identically.
	//
	// The probe stays: a container that is neither answering nor able to see a
	// GPU is exactly what this subsystem is for.
	if w.serving != nil {
		sctx, scancel := context.WithTimeout(ctx, probeTimeout)
		alive := w.serving(sctx, ctr.Name)
		scancel()
		if alive {
			cs.Status = statusServing
			cs.Detail = "nvidia-smi failed inside the container, but the backend is " +
				"answering — not restarting a working backend on a probe alone"
			// The backend's own answer is the authority on whether it works.
			// Hold the streak at the confirmation threshold instead of letting
			// it climb for as long as the probe keeps failing, and say so ONCE:
			// it is a standing condition, not a new event each cycle.
			w.failStreak[ctr.Name] = 2
			if !w.servingNoted[ctr.Name] {
				w.servingNoted[ctr.Name] = true
				slog.Warn("gpuwatch: GPU probe failed but the backend is serving; not restarting "+
					"(logged once; further cycles log at debug until the probe passes)",
					"container", ctr.Name)
			} else {
				slog.Debug("gpuwatch: GPU probe still failing, backend still serving",
					"container", ctr.Name)
			}
			return cs
		}
		// Not answering: whatever the serving verdict was, it is over.
		delete(w.servingNoted, ctr.Name)
	}

	last, restarted := w.lastRestart[ctr.Name]
	if !restarted || w.now().Sub(last) > restartCooldown {
		rctx, cancel := context.WithTimeout(ctx, probeTimeout)
		rerr := w.docker.RestartContainer(rctx, ctr.ID)
		cancel()
		if rerr != nil {
			cs.Status = statusFault
			cs.Detail = "GPU unreachable and restart failed: " + rerr.Error()
			st.Faults = append(st.Faults, ctr.Name+": "+cs.Detail)
			return cs
		}
		now := w.now()
		w.lastRestart[ctr.Name] = now
		w.restartTotal++
		w.failStreak[ctr.Name] = 0
		cs.Status = statusRestarted
		cs.LastRestartAt = &now
		cs.Detail = "GPU unreachable from container; restarted to re-grant devices"
		slog.Warn("gpuwatch: restarted container with broken GPU grant", "container", ctr.Name)
		return cs
	}

	// Already restarted within the cooldown and still broken: escalate.
	cs.Status = statusFault
	cs.Detail = "GPU still unreachable after restart (exit code from in-container nvidia-smi: nonzero)"
	st.Faults = append(st.Faults, ctr.Name+": "+cs.Detail)
	return cs
}

func (w *Watchdog) commit(st State) {
	w.mu.Lock()
	st.Restarts = w.restartTotal
	w.state = st
	w.mu.Unlock()
	if len(st.Faults) > 0 {
		slog.Error("gpuwatch: container GPU faults", "faults", st.Faults)
	}
}
