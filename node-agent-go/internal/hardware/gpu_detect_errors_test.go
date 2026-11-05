// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// Followup i495 (noomesh-internal), item 2: a failed nvidia-smi is an error,
// not "no GPU". An absent binary is the only clean "no GPU".
//
// The host's real nvidia-smi is never run: PATH is replaced by a temp dir and
// the resolved path is pinned (it is resolved once per process and falls back
// to fixed locations such as /usr/lib/wsl/lib, which PATH cannot hide).

func pinSmi(t *testing.T, path string) {
	t.Helper()
	nvidiaSmiOnce.Do(func() {}) // consume the real resolution
	nvidiaSmiPath = path
	// Back to unresolved, so a later test resolves the real thing as usual.
	t.Cleanup(func() { nvidiaSmiOnce, nvidiaSmiPath = sync.Once{}, "" })
}

// fakeSmi installs an executable shell script named nvidia-smi as the only
// thing on PATH and returns the dir.
func fakeSmi(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "nvidia-smi")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	pinSmi(t, p)
}

func noSmi(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	pinSmi(t, "nvidia-smi") // bare name, nothing on PATH: exec.ErrNotFound
}

type probeResult struct {
	model string
	vram  float64
	count int
	errs  [3]error
}

func probeAll(g *GPUDetector) probeResult {
	var r probeResult
	r.model, r.errs[0] = g.DetectModel()
	r.vram, r.errs[1] = g.DetectVRAM()
	r.count, r.errs[2] = g.DetectCount()
	return r
}

func TestDetectAbsentBinaryIsACleanNoGPU(t *testing.T) {
	noSmi(t)
	r := probeAll(NewGPUDetector(nil, "http"))
	if r.model != "" || r.vram != 0 || r.count != 0 {
		t.Fatalf("absent binary: got %+v, want zeros", r)
	}
	for i, err := range r.errs {
		if err != nil {
			t.Fatalf("absent binary must be (zero, nil), probe %d returned %v", i, err)
		}
	}
}

func TestDetectHealthyFakeSmi(t *testing.T) {
	fakeSmi(t, `case "$1" in
--query-gpu=name) echo "NVIDIA GeForce RTX 4090";;
--query-gpu=memory.total) echo "24564";;
--query-gpu=count) echo "2";;
esac`)
	r := probeAll(NewGPUDetector(nil, "http"))
	if r.model != "NVIDIA GeForce RTX 4090" || r.vram != 24.0 || r.count != 2 {
		t.Fatalf("got %+v", r)
	}
	for i, err := range r.errs {
		if err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
	}
}

func TestDetectNonZeroExitIsAnError(t *testing.T) {
	fakeSmi(t, `echo "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver." >&2; exit 9`)
	r := probeAll(NewGPUDetector(nil, "http"))
	if r.model != "" || r.vram != 0 || r.count != 0 {
		t.Fatalf("values on error must be zero, got %+v", r)
	}
	for i, err := range r.errs {
		if err == nil {
			t.Fatalf("probe %d: a non-zero exit with the binary present must be an error", i)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("probe %d: an exit status is not a deadline: %v", i, err)
		}
	}
}

func TestDetectGarbageOutputIsAnError(t *testing.T) {
	fakeSmi(t, `echo "Failed to initialize NVML: Unknown Error"`)
	g := NewGPUDetector(nil, "http")
	if v, err := g.DetectVRAM(); err == nil || v != 0 {
		t.Fatalf("DetectVRAM on garbage: (%v, %v), want an error", v, err)
	}
	if n, err := g.DetectCount(); err == nil || n != 0 {
		t.Fatalf("DetectCount on garbage: (%v, %v), want an error", n, err)
	}
}

func TestDetectHangPastTheDeadlineIsADeadlineError(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the 5 s probe deadline")
	}
	fakeSmi(t, `exec sleep 30`)
	g := NewGPUDetector(nil, "http")
	start := time.Now()
	if _, err := g.DetectModel(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a hang must be a deadline error, got %v", err)
	}
	if took := time.Since(start); took > 8*time.Second {
		t.Fatalf("the probe deadline was not honoured: %v", took)
	}
}

// DetectCount no longer falls back to DetectModel (which failed the same way):
// a failing probe is reported, not turned into 0 or 1.
func TestDetectCountDoesNotInventAnAnswerOnError(t *testing.T) {
	fakeSmi(t, `exit 1`)
	n, err := NewGPUDetector(nil, "http").DetectCount()
	if err == nil || n != 0 {
		t.Fatalf("DetectCount = (%d, %v), want (0, error)", n, err)
	}
}

// Detect on a probe error keeps the configured GPU and so vllm/airllm; it
// reports the error and marks the capabilities incomplete.
func TestCapsDetectOnProbeErrorKeepsVLLM(t *testing.T) {
	boom := errors.New("nvidia-smi name: context deadline exceeded")
	caps, err := Detect(&config.Config{GPUModel: "RTX 4090"}, fakeGPU{err: boom}, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("Detect must return the probe error, got %v", err)
	}
	if caps.GPUModel != "RTX 4090" || caps.GPUCount != 1 || !caps.ProbeIncomplete {
		t.Fatalf("caps = model %q count %d incomplete %v", caps.GPUModel, caps.GPUCount, caps.ProbeIncomplete)
	}
	has := map[string]bool{}
	for _, b := range caps.Backends {
		has[b] = true
	}
	if !has["vllm"] || !has["airllm"] {
		t.Fatalf("vllm/airllm dropped on a probe error: %v", caps.Backends)
	}
}

// Previous capabilities (the 404 re-register path) are the fallback when
// nothing is configured.
func TestCapsDetectOnProbeErrorFallsBackToPrevious(t *testing.T) {
	prev := &Capabilities{GPUModel: "RTX 3090", VRAMGB: 24, GPUCount: 2}
	caps, err := Detect(&config.Config{}, fakeGPU{err: errors.New("timeout")}, prev)
	if err == nil {
		t.Fatal("want the probe error")
	}
	if caps.GPUModel != "RTX 3090" || caps.VRAMGB != 24 || caps.GPUCount != 2 {
		t.Fatalf("caps = %q %v %d", caps.GPUModel, caps.VRAMGB, caps.GPUCount)
	}
}

// With nothing configured and nothing previous, an error still must not claim
// a GPU: it is reported (error + incomplete) and the heartbeat re-detects.
func TestCapsDetectOnProbeErrorWithNoFallbackClaimsNoGPUButSaysSo(t *testing.T) {
	caps, err := Detect(&config.Config{}, fakeGPU{err: errors.New("timeout")}, nil)
	if err == nil || !caps.ProbeIncomplete || caps.GPUModel != "" {
		t.Fatalf("err=%v incomplete=%v model=%q", err, caps.ProbeIncomplete, caps.GPUModel)
	}
}
