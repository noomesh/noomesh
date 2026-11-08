// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// lastGPUFile holds the GPU fields of the last COMPLETE probe, in the
// agent's state dir. Registration happens before any heartbeat, so after an
// agent restart there are no previous capabilities in memory: a probe that
// was slow at that moment (WSL2, with our own vLLM loading) registered the
// node with 0 GB. The controller derives the tier from vram_gb, so that
// dropped awolf to the unknown tier, changed its harness profile's context
// from 32768 to 16384, and reloaded vLLM twice (noomesh-internal i575).
const lastGPUFile = "last-gpu.json"

type lastGPU struct {
	GPUModel string  `json:"gpu_model"`
	VRAMGB   float64 `json:"vram_gb"`
	GPUCount int     `json:"gpu_count"`
}

// LoadLastGPU returns the saved GPU fields as Detect's prev, or nil when
// nothing usable is saved (no file, unreadable, or a probe that found no
// GPU).
func LoadLastGPU(dir string) *Capabilities {
	if dir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dir, lastGPUFile))
	if err != nil {
		return nil
	}
	var g lastGPU
	if json.Unmarshal(b, &g) != nil || (g.GPUModel == "" && g.VRAMGB <= 0) {
		return nil
	}
	return &Capabilities{GPUModel: g.GPUModel, VRAMGB: g.VRAMGB, GPUCount: g.GPUCount}
}

// SaveLastGPU records c's GPU fields when c came from a complete probe. A
// failed probe's fields are fallbacks, never evidence, so they are not
// saved. A complete probe that finds no GPU is saved too: a GPU that was
// really removed must not come back on the next slow probe.
func SaveLastGPU(dir string, c Capabilities) error {
	if dir == "" || c.ProbeIncomplete {
		return nil
	}
	b, err := json.Marshal(lastGPU{GPUModel: c.GPUModel, VRAMGB: c.VRAMGB, GPUCount: c.GPUCount})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, lastGPUFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, lastGPUFile))
}

// DetectAtBoot is Detect for registration: prev is the last complete probe
// saved in the state dir, so a probe that fails at boot registers the GPU
// this node last had, not 0 GB. A complete probe is saved for next time.
func DetectAtBoot(cfg *config.Config, gpu GPUProbe) (Capabilities, error) {
	caps, err := Detect(cfg, gpu, LoadLastGPU(cfg.StateDir))
	if err == nil {
		_ = SaveLastGPU(cfg.StateDir, caps)
	}
	return caps, err
}
