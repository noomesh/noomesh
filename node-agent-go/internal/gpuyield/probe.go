// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
)

// ComputeApp is one process nvidia-smi says holds GPU memory.
type ComputeApp struct {
	PID    int
	UsedMB int
}

// Reading is one sample of the GPU's memory.
type Reading struct {
	// Measured is false where this node cannot measure GPU memory at all:
	// macOS / unified memory, no NVIDIA driver, nvidia-smi failing. The
	// yield never acts on an unmeasured GPU.
	Measured bool
	TotalMB  int
	UsedMB   int
	// Apps are the compute processes, when nvidia-smi could name them.
	Apps []ComputeApp
	// AppsResolved is true only when EVERY compute-app row carried a real
	// PID and a real memory figure. Under WSL2 the rows read "[Not Found]"
	// / "[N/A]" (the Windows driver owns the processes), and PID
	// attribution is then impossible.
	AppsResolved bool
}

// Probe samples GPU memory.
type Probe interface {
	Read(ctx context.Context) Reading
}

// SMIProbe reads nvidia-smi on the host. NVML would need cgo; the agent is a
// static binary, so nvidia-smi is the one measurement it has (method
// "nvidia-smi", or "memory-accounting" when the PIDs are unresolvable).
type SMIProbe struct {
	// run is hardware.NvidiaSMI; a field so tests can feed canned output.
	run func(args ...string) (string, error)
	// goos is runtime.GOOS; darwin is never measured.
	goos string
}

// NewSMIProbe is the production probe.
func NewSMIProbe() *SMIProbe { return &SMIProbe{run: hardware.NvidiaSMI, goos: runtime.GOOS} }

func (p *SMIProbe) Read(ctx context.Context) Reading {
	if p.goos == "darwin" {
		// Unified memory: there is no separate GPU pool to contend for that
		// this agent can measure. Reported as "not-measured", never paused.
		return Reading{}
	}
	out, err := p.run("--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits")
	if err != nil {
		return Reading{}
	}
	used, total, ok := parseGPUMemory(out)
	if !ok {
		return Reading{}
	}
	r := Reading{Measured: true, TotalMB: total, UsedMB: used}
	apps, aerr := p.run("--query-compute-apps=pid,used_memory", "--format=csv,noheader,nounits")
	if aerr == nil {
		r.Apps, r.AppsResolved = parseComputeApps(apps)
	}
	return r
}

// parseGPUMemory sums `used, total` rows (one per GPU) in MiB.
func parseGPUMemory(out string) (used, total int, ok bool) {
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		u, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		t, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			continue
		}
		used += u
		total += t
		ok = true
	}
	return used, total, ok && total > 0
}

// parseComputeApps parses `pid, used_memory` rows. resolved is false when
// any row's PID or memory is not a number ("[Not Found]", "[N/A]" — WSL2).
// An empty listing parses as resolved with no apps; the controller then
// decides whether that is believable (it is not, while one of our own GPU
// backends runs — see attribute).
func parseComputeApps(out string) ([]ComputeApp, bool) {
	out = strings.TrimSpace(out)
	if out == "" || strings.HasPrefix(out, "No running") {
		return nil, true
	}
	var apps []ComputeApp
	resolved := true
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			resolved = false
			continue
		}
		pid, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		mb, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil || pid <= 0 {
			resolved = false
			continue
		}
		apps = append(apps, ComputeApp{PID: pid, UsedMB: mb})
	}
	return apps, resolved
}

// procCgroup reads /proc/<pid>/cgroup — world-readable, so the unprivileged
// agent can attribute a root-owned container process to its container.
func procCgroup(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	return string(b)
}
