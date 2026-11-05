// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package metrics collects system metrics and computes composite load scores.
package metrics

import (
	"log/slog"
	"math"
	"sync"

	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
)

// SystemMetrics holds a point-in-time snapshot of node resource usage.
type SystemMetrics struct {
	Load       float64  `json:"load"`
	CPULoad    *float64 `json:"cpu_load,omitempty"`
	MemUsedGB  *float64 `json:"mem_used_gb,omitempty"`
	VRAMUsedGB *float64 `json:"vram_used_gb,omitempty"`
}

// Collector gathers system metrics from /proc and GPU.
type Collector struct {
	gpu *hardware.GPUDetector

	// Sources, swappable so a test can feed a machine that reports an
	// impossible memory read. NewCollector wires the real ones.
	cpuLoad func() float64
	memInfo func() hardware.MemoryInfo

	// memAvailLog is the last logged availability state, so the warning
	// fires once per change rather than once per beat.
	memMu       sync.Mutex
	memAvailLog string
}

// NewCollector creates a metrics collector.
func NewCollector(gpu *hardware.GPUDetector) *Collector {
	return &Collector{gpu: gpu, cpuLoad: hardware.CPULoad, memInfo: hardware.ReadMemoryInfo}
}

// NewCollectorWithSources is NewCollector with the CPU and memory readers
// supplied by the caller.
func NewCollectorWithSources(gpu *hardware.GPUDetector, cpu func() float64, mem func() hardware.MemoryInfo) *Collector {
	return &Collector{gpu: gpu, cpuLoad: cpu, memInfo: mem}
}

// finite reports whether v can be marshalled as JSON (not NaN, not Inf).
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// compute is the pure half of Collect: the composite load and the memory
// figure from a CPU load and a memory read. Every division is guarded, so a
// zero total gives no NaN: memory-used is nil (omitted) and the load is
// computed from the CPU alone. A non-finite CPU load falls back to 0, which
// is what a failed loadavg read has always reported.
func compute(cpuLoad float64, mem hardware.MemoryInfo) (load float64, memUsedGB *float64) {
	if !finite(cpuLoad) {
		cpuLoad = 0
	}
	if mem.TotalKB <= 0 || !mem.AvailableKnown {
		return math.Round(math.Min(math.Max(cpuLoad, 0), 1.0)*100) / 100, nil
	}
	avail := math.Min(float64(mem.AvailableKB), float64(mem.TotalKB))
	memLoad := 1.0 - avail/float64(mem.TotalKB)
	used := math.Round((float64(mem.TotalKB)-avail)/1048576.0*10) / 10
	memUsedGB = &used
	// Composite load: 60% CPU + 40% memory
	load = math.Round(math.Min(cpuLoad*0.6+memLoad*0.4, 1.0)*100) / 100
	return load, memUsedGB
}

// Collect gathers current system metrics.
// Matches Python _get_system_metrics().
func (c *Collector) Collect() SystemMetrics {
	m := SystemMetrics{Load: 0.5}

	cpuLoad := c.cpuLoad()
	if !finite(cpuLoad) {
		cpuLoad = 0
	}
	m.CPULoad = &cpuLoad

	mem := c.memInfo()
	m.Load, m.MemUsedGB = compute(cpuLoad, mem)
	c.noteMemory(mem)

	// VRAM usage
	if c.gpu != nil {
		if vramUsed := c.gpu.DetectVRAMUsed(); vramUsed > 0 && finite(vramUsed) {
			m.VRAMUsedGB = &vramUsed
		}
	}

	return m
}

// noteMemory warns when the memory read is incomplete, once per change.
func (c *Collector) noteMemory(mem hardware.MemoryInfo) {
	state := "ok"
	switch {
	case mem.TotalKB <= 0:
		state = "total unknown"
	case !mem.AvailableKnown:
		state = "available unknown"
	}
	c.memMu.Lock()
	changed := state != c.memAvailLog
	c.memAvailLog = state
	c.memMu.Unlock()
	if changed && state != "ok" {
		slog.Warn("memory read incomplete: mem_used_gb omitted, load computed from CPU only", "state", state)
	}
}
