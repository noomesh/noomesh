// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package metrics

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
)

func TestCollector_Collect(t *testing.T) {
	// GPU detector with no GPU (will return nil metrics — that's fine)
	gpu := hardware.NewGPUDetector(nil, "http")
	coll := NewCollector(gpu)

	m := coll.Collect()

	// Load should be between 0 and 1
	if m.Load < 0 || m.Load > 1.0 {
		t.Errorf("load should be 0-1, got %f", m.Load)
	}

	// CPU load should be populated
	if m.CPULoad == nil {
		t.Error("CPULoad should not be nil")
	} else if *m.CPULoad < 0 || *m.CPULoad > 1.0 {
		t.Errorf("CPULoad should be 0-1, got %f", *m.CPULoad)
	}

	// Memory used should be populated and reasonable
	if m.MemUsedGB == nil {
		t.Error("MemUsedGB should not be nil")
	} else if *m.MemUsedGB < 0 {
		t.Errorf("MemUsedGB should not be negative: %f", *m.MemUsedGB)
	}

	// VRAM should be nil without a GPU (no nvidia-smi)
	// (This is expected in CI/test environments)
}

func TestCompositeLoad_Formula(t *testing.T) {
	// The composite load formula is: min(cpu*0.6 + mem*0.4, 1.0)
	// We can't control /proc values, but we verify the result is bounded
	gpu := hardware.NewGPUDetector(nil, "http")
	coll := NewCollector(gpu)

	m := coll.Collect()

	if m.Load > 1.0 {
		t.Errorf("composite load should be capped at 1.0, got %f", m.Load)
	}
}
