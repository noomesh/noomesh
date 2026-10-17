// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"sync"
	"time"
)

// nvidiaSmi resolves the nvidia-smi binary once per process. The service's
// PATH is not the operator's PATH: under systemd it is the distro default,
// which on WSL2 lacks /usr/lib/wsl/lib — the only place the Windows driver
// surfaces nvidia-smi. A host-process agent that trusts PATH therefore
// reports gpu_count=0 on a working GPU (the container agent never hit this;
// the NVIDIA runtime mounted the binary somewhere findable). Probing known
// locations in the binary keeps detection host-config-free on every
// platform; macOS never reaches this — Apple GPUs use the darwin
// unified-memory path in capabilities.go, not nvidia-smi.
func nvidiaSmi() string {
	nvidiaSmiOnce.Do(func() {
		nvidiaSmiPath = resolveNvidiaSmi(exec.LookPath, os.Stat)
	})
	return nvidiaSmiPath
}

var (
	nvidiaSmiOnce sync.Once
	nvidiaSmiPath string
)

func resolveNvidiaSmi(lookPath func(string) (string, error), stat func(string) (os.FileInfo, error)) string {
	if p, err := lookPath("nvidia-smi"); err == nil {
		return p
	}
	for _, p := range []string{
		"/usr/lib/wsl/lib/nvidia-smi", // WSL2 — never on the systemd PATH
		"/usr/bin/nvidia-smi",
		"/usr/local/bin/nvidia-smi",
		"/opt/nvidia/bin/nvidia-smi",
	} {
		if st, err := stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	// Nothing found: return the bare name so callers fail exactly the way a
	// missing binary always did (exec error → "no GPU").
	return "nvidia-smi"
}

// execTimeout runs a command with a 5-second timeout and returns its stdout.
// Sets LD_LIBRARY_PATH for NVIDIA runtime compatibility — in Alpine containers,
// nvidia-smi is mounted by the NVIDIA runtime but its libs are at a non-standard path.
func execTimeout(name string, args ...string) (string, error) {
	return execWithin(5*time.Second, name, args...)
}

// ErrProbeStuck: an earlier invocation of the same command passed its
// deadline and has still not been reaped. Wraps context.DeadlineExceeded,
// so every caller that already classifies a deadline miss as "busy, not
// broken" classifies this the same way without knowing it exists.
var ErrProbeStuck = errors.New("previous invocation still running past its deadline")

// stuck counts, per command name, the invocations that outlived their
// deadline. A child wedged in the kernel (nvidia-smi inside a driver ioctl
// on a saturated GPU — WSL2's dxg path is the known case) ignores SIGKILL
// until the syscall returns, and cmd.Wait blocks with it. Spawning another
// copy does not get past that; it joins it. So while one is outstanding,
// the next call for that name returns at once.
var stuck struct {
	mu sync.Mutex
	n  map[string]int
}

func stuckCount(name string) int {
	stuck.mu.Lock()
	defer stuck.mu.Unlock()
	return stuck.n[name]
}

func markStuck(name string, delta int) {
	stuck.mu.Lock()
	defer stuck.mu.Unlock()
	if stuck.n == nil {
		stuck.n = map[string]int{}
	}
	stuck.n[name] += delta
	if stuck.n[name] <= 0 {
		delete(stuck.n, name)
	}
}

// execWithin is execTimeout with the deadline injectable (tests). A command
// killed by the deadline surfaces context.DeadlineExceeded (errors.Is-able)
// instead of the opaque "signal: killed" — callers need to tell "the tool
// was too slow" apart from "the tool failed": on a saturated GPU nvidia-smi
// can miss the window, and that is busyness, not a wedge.
//
// The deadline is the deadline. exec.CommandContext only sends SIGKILL when
// the context ends; cmd.Output still waits for the process to be reaped and
// for its stdout pipe to close, and neither is guaranteed to follow the
// signal promptly — a child stuck in an uninterruptible syscall, or one
// whose own child inherited the pipe, held this call open for minutes on a
// five-second budget. Every liveness signal the agent emits (heartbeat,
// gossip announce, discovery offer) ran that probe inline, so a stuck
// nvidia-smi silenced the node while its control API kept answering
// (host3, 2026-09-21: 3–8 minute gaps, every one during an inference
// burst). Now the call returns when the deadline passes, whatever the
// child is doing; a goroutine reaps it when the kernel lets go.
func execWithin(d time.Duration, name string, args ...string) (string, error) {
	if stuckCount(name) > 0 {
		return "", fmt.Errorf("%s: %w: %w", name, ErrProbeStuck, context.DeadlineExceeded)
	}

	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu")
	// Once the context ends, stop waiting on an inherited pipe after this
	// long as well — covers the "grandchild holds stdout" shape without
	// leaking the copy goroutine for the grandchild's whole lifetime.
	cmd.WaitDelay = d

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := cmd.Output()
		done <- result{out, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return "", fmt.Errorf("%s: %w", name, context.DeadlineExceeded)
			}
			return "", r.err
		}
		return string(r.out), nil
	case <-ctx.Done():
	}

	// Deadline passed and the child is not back yet. Hand the wait to a
	// goroutine and answer the caller now — the caller's budget was the
	// contract, not the kernel's.
	markStuck(name, 1)
	go func() {
		<-done
		markStuck(name, -1)
	}()
	return "", fmt.Errorf("%s: %w", name, context.DeadlineExceeded)
}

// round rounds a float64 to n decimal places.
func round(val float64, places int) float64 {
	shift := math.Pow(10, float64(places))
	return math.Round(val*shift) / shift
}

// NvidiaSMI runs the resolved nvidia-smi with args under the probe deadline
// (execTimeout). Exported for the shared-GPU yield's contention probe
// (internal/gpuyield), which needs raw --query-gpu / --query-compute-apps
// output; an error means "not measurable here", never "no contention".
func NvidiaSMI(args ...string) (string, error) {
	return execTimeout(nvidiaSmi(), args...)
}
