// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	// Unmeasured says why Measured is false (one of the Unmeasured*
	// constants); empty when Measured.
	Unmeasured string
	// UnmeasuredDetail is a short first-line copy of the error text, set
	// for UnmeasuredDriverLost only.
	UnmeasuredDetail string
}

// Why a GPU is not measured. Values are a contract with `noo cluster verify`.
const (
	// UnmeasuredUnifiedMemory: macOS, no separate GPU pool.
	UnmeasuredUnifiedMemory = "unified-memory"
	// UnmeasuredNoNvidia: nvidia-smi is not installed.
	UnmeasuredNoNvidia = "no-nvidia"
	// UnmeasuredProbeTimeout: nvidia-smi missed its deadline (a saturated
	// GPU or slow driver), NOT a lost GPU.
	UnmeasuredProbeTimeout = "probe-timeout"
	// UnmeasuredDriverLost: nvidia-smi exists but fails, prints
	// "Unknown Error" / "Unable to determine", or prints nothing parseable
	// (Xid 79, "GPU has fallen off the bus").
	UnmeasuredDriverLost = "driver-lost"
)

const detailMax = 120

// classifyUnmeasured turns a failed or unparseable nvidia-smi call into a
// cause. out is stdout (may be empty), err the call error (may be nil).
func classifyUnmeasured(out string, err error) (cause, detail string) {
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return UnmeasuredProbeTimeout, ""
		case errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist):
			return UnmeasuredNoNvidia, ""
		}
		text := err.Error()
		var ee *exec.ExitError
		if errors.As(err, &ee) && strings.TrimSpace(string(ee.Stderr)) != "" {
			text = string(ee.Stderr)
		} else if strings.TrimSpace(out) != "" {
			text = out
		}
		return UnmeasuredDriverLost, shortDetail(text)
	}
	if strings.TrimSpace(out) == "" {
		return UnmeasuredDriverLost, "no output"
	}
	return UnmeasuredDriverLost, shortDetail(out)
}

// shortDetail is the first non-empty line, capped at detailMax bytes.
func shortDetail(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > detailMax {
			line = line[:detailMax]
		}
		return line
	}
	return ""
}

// smiFault mirrors the launcher's _compose_gpu_state: output naming
// "Unknown Error" / "Unable to determine" is a lost GPU even at exit 0.
func smiFault(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "unknown error") || strings.Contains(l, "unable to determine")
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
		return Reading{Unmeasured: UnmeasuredUnifiedMemory}
	}
	out, err := p.run("--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits")
	if err != nil {
		cause, detail := classifyUnmeasured(out, err)
		return Reading{Unmeasured: cause, UnmeasuredDetail: detail}
	}
	used, total, ok := parseGPUMemory(out)
	if smiFault(out) || !ok {
		_, detail := classifyUnmeasured(out, nil)
		return Reading{Unmeasured: UnmeasuredDriverLost, UnmeasuredDetail: detail}
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
