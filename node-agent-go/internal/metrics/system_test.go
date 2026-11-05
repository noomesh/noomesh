// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package metrics

import (
	"encoding/json"
	"math"
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

func TestCompute_ZeroTotalIsNotNaN(t *testing.T) {
	load, used := compute(0.4, hardware.MemoryInfo{})
	if math.IsNaN(load) || math.IsInf(load, 0) {
		t.Fatalf("load = %v, want a finite number", load)
	}
	if load != 0.4 {
		t.Errorf("load = %v, want 0.4 (CPU only when memory is unknown)", load)
	}
	if used != nil {
		t.Errorf("mem_used_gb = %v, want nil (omitted)", *used)
	}
	// Total known but available not (vm_stat failed): the same.
	load, used = compute(0.4, hardware.MemoryInfo{TotalKB: 16 << 20})
	if load != 0.4 || used != nil {
		t.Errorf("available unknown: load=%v used=%v, want 0.4 and nil", load, used)
	}
	// A NaN CPU load falls back to today's 0, never NaN.
	load, _ = compute(math.NaN(), hardware.MemoryInfo{})
	if load != 0 {
		t.Errorf("NaN cpu: load = %v, want 0", load)
	}
}

func TestCompute_KnownMemory(t *testing.T) {
	// 16 GiB total, 4 GiB available: mem load 0.75, used 12.0 GB.
	mem := hardware.MemoryInfo{TotalKB: 16 << 20, AvailableKB: 4 << 20, AvailableKnown: true}
	load, used := compute(0.5, mem)
	if load != 0.6 { // 0.5*0.6 + 0.75*0.4
		t.Errorf("load = %v, want 0.6", load)
	}
	if used == nil || *used != 12.0 {
		t.Errorf("mem_used_gb = %v, want 12.0", used)
	}
}

func TestCollect_ZeroTotalMarshals(t *testing.T) {
	coll := NewCollectorWithSources(nil,
		func() float64 { return 0.25 },
		func() hardware.MemoryInfo { return hardware.MemoryInfo{} })
	m := coll.Collect()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"load":0.25,"cpu_load":0.25}` {
		t.Errorf("got %s, want load and cpu_load only (mem_used_gb omitted)", b)
	}
}
