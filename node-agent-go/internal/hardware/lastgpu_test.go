// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"errors"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// noomesh-internal i575: after an agent restart, a probe that times out at
// registration must register the GPU this node last had, not 0 GB. The
// controller derives the tier from vram_gb, and a 0 GB registration changed
// awolf's vLLM context and reloaded it twice.
func TestABootProbeThatFailsRegistersTheLastKnownGPU(t *testing.T) {
	cfg := &config.Config{GPUModel: "RTX 3080 Laptop", StateDir: t.TempDir()}
	if _, err := DetectAtBoot(cfg, fakeGPU{vram: 16, count: 1, model: "RTX 3080 Laptop"}); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	caps, err := DetectAtBoot(cfg, fakeGPU{err: errors.New("nvidia-smi: context deadline exceeded")})
	if err == nil || !caps.ProbeIncomplete {
		t.Fatalf("the failed probe must still be reported: err=%v incomplete=%v", err, caps.ProbeIncomplete)
	}
	if caps.VRAMGB != 16 || caps.GPUCount != 1 {
		t.Fatalf("a failed boot probe registered vram %v count %d; want the last known 16 GB, 1 GPU", caps.VRAMGB, caps.GPUCount)
	}
}

// A failed probe's values are fallbacks: saving them would turn one slow
// probe into the remembered truth.
func TestAFailedProbeNeverOverwritesTheLastKnownGPU(t *testing.T) {
	dir := t.TempDir()
	if err := SaveLastGPU(dir, Capabilities{GPUModel: "RTX 4090", VRAMGB: 24, GPUCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := SaveLastGPU(dir, Capabilities{GPUModel: "RTX 4090", VRAMGB: 0, ProbeIncomplete: true}); err != nil {
		t.Fatal(err)
	}
	if got := LoadLastGPU(dir); got == nil || got.VRAMGB != 24 {
		t.Fatalf("after a failed probe the saved GPU is %+v; want 24 GB kept", got)
	}
}

// A complete probe that finds no GPU replaces the saved one, so a GPU that
// was really removed does not come back on the next slow probe.
func TestACompleteProbeWithNoGPUForgetsTheLastOne(t *testing.T) {
	cfg := &config.Config{StateDir: t.TempDir()}
	if err := SaveLastGPU(cfg.StateDir, Capabilities{GPUModel: "RTX 4090", VRAMGB: 24, GPUCount: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := DetectAtBoot(cfg, fakeGPU{}); err != nil {
		t.Fatalf("a clean no-GPU probe: %v", err)
	}
	if got := LoadLastGPU(cfg.StateDir); got != nil {
		t.Fatalf("a removed GPU is still remembered: %+v", got)
	}
}
