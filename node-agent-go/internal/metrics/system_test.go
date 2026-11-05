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
	if m.Load != nil && (*m.Load < 0 || *m.Load > 1.0) {
		t.Errorf("load should be 0-1, got %f", *m.Load)
	}

	// CPU load is populated where the platform has a reader (linux, darwin).
	if m.CPULoad == nil {
		t.Log("CPULoad unknown on this platform")
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

	if m.Load != nil && *m.Load > 1.0 {
		t.Errorf("composite load should be capped at 1.0, got %f", *m.Load)
	}
}

func cpuOf(v float64, ok bool) func() (float64, bool) {
	return func() (float64, bool) { return v, ok }
}

func TestCompute_ZeroTotalIsNotNaN(t *testing.T) {
	load, used := compute(0.4, true, hardware.MemoryInfo{})
	if load == nil || math.IsNaN(*load) || math.IsInf(*load, 0) {
		t.Fatalf("load = %v, want a finite number", load)
	}
	if *load != 0.4 {
		t.Errorf("load = %v, want 0.4 (CPU only when memory is unknown)", *load)
	}
	if used != nil {
		t.Errorf("mem_used_gb = %v, want nil (omitted)", *used)
	}
	// Total known but available not (vm_stat failed): the same.
	load, used = compute(0.4, true, hardware.MemoryInfo{TotalKB: 16 << 20})
	if load == nil || *load != 0.4 || used != nil {
		t.Errorf("available unknown: load=%v used=%v, want 0.4 and nil", load, used)
	}
}

func TestCompute_KnownMemory(t *testing.T) {
	// 16 GiB total, 4 GiB available: mem load 0.75, used 12.0 GB.
	mem := hardware.MemoryInfo{TotalKB: 16 << 20, AvailableKB: 4 << 20, AvailableKnown: true}
	load, used := compute(0.5, true, mem)
	if load == nil || *load != 0.6 { // 0.5*0.6 + 0.75*0.4
		t.Errorf("load = %v, want 0.6", load)
	}
	if used == nil || *used != 12.0 {
		t.Errorf("mem_used_gb = %v, want 12.0", used)
	}
}

// Unknown CPU means unknown load, even with memory known: a load built from
// memory alone (0.4 x memLoad) would be a false low figure.
func TestCompute_UnknownCPUIsUnknownLoad(t *testing.T) {
	mem := hardware.MemoryInfo{TotalKB: 16 << 20, AvailableKB: 4 << 20, AvailableKnown: true}
	for name, c := range map[string]struct {
		v  float64
		ok bool
	}{"not ok": {0, false}, "NaN": {math.NaN(), true}, "Inf": {math.Inf(1), true}} {
		load, used := compute(c.v, c.ok, mem)
		if load != nil {
			t.Errorf("%s: load = %v, want nil", name, *load)
		}
		if used == nil || *used != 12.0 {
			t.Errorf("%s: mem_used_gb = %v, want 12.0 (memory is still known)", name, used)
		}
	}
}

func TestCollect_ZeroTotalMarshals(t *testing.T) {
	coll := NewCollectorWithSources(nil, cpuOf(0.25, true),
		func() hardware.MemoryInfo { return hardware.MemoryInfo{} })
	b, err := json.Marshal(coll.Collect())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"load":0.25,"cpu_load":0.25}` {
		t.Errorf("got %s, want load and cpu_load only (mem_used_gb omitted)", b)
	}
}

// Known CPU, unknown memory: load is the CPU value.
func TestCollect_KnownCPUUnknownMemoryLoadIsCPU(t *testing.T) {
	coll := NewCollectorWithSources(nil, cpuOf(0.37, true),
		func() hardware.MemoryInfo { return hardware.MemoryInfo{} })
	m := coll.Collect()
	if m.Load == nil || *m.Load != 0.37 {
		t.Errorf("load = %v, want 0.37", m.Load)
	}
}

// Unknown CPU: neither load nor cpu_load is in the JSON.
func TestCollect_UnknownCPUOmitsLoadAndCPULoad(t *testing.T) {
	mem := hardware.MemoryInfo{TotalKB: 16 << 20, AvailableKB: 4 << 20, AvailableKnown: true}
	coll := NewCollectorWithSources(nil, cpuOf(0, false),
		func() hardware.MemoryInfo { return mem })
	b, err := json.Marshal(coll.Collect())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"mem_used_gb":12}` {
		t.Errorf("got %s, want only mem_used_gb", b)
	}
}
