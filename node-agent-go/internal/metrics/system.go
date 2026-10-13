// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package metrics collects system metrics and computes composite load scores.
package metrics

import (
	"math"

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
}

// NewCollector creates a metrics collector.
func NewCollector(gpu *hardware.GPUDetector) *Collector {
	return &Collector{gpu: gpu}
}

// Collect gathers current system metrics.
// Matches Python _get_system_metrics().
func (c *Collector) Collect() SystemMetrics {
	m := SystemMetrics{Load: 0.5}

	// CPU load (normalized)
	cpuLoad := hardware.CPULoad()
	m.CPULoad = &cpuLoad

	// Memory usage
	mem := hardware.ReadMemoryInfo()
	memLoad := 1.0 - float64(mem.AvailableKB)/float64(mem.TotalKB)
	memUsedGB := float64(mem.TotalKB-mem.AvailableKB) / 1048576.0
	memUsedGB = math.Round(memUsedGB*10) / 10
	m.MemUsedGB = &memUsedGB

	// Composite load: 60% CPU + 40% memory
	m.Load = math.Round(math.Min(cpuLoad*0.6+memLoad*0.4, 1.0)*100) / 100

	// VRAM usage
	if c.gpu != nil {
		if vramUsed := c.gpu.DetectVRAMUsed(); vramUsed > 0 {
			m.VRAMUsedGB = &vramUsed
		}
	}

	return m
}
