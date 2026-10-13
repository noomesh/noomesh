// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package hardware provides system hardware detection for node capabilities.
package hardware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GPUMetrics holds real-time GPU telemetry.
type GPUMetrics struct {
	GPUUtilizationPct    float64  `json:"gpu_utilization_percent"`
	MemoryUtilizationPct float64  `json:"memory_utilization_percent"`
	MemoryUsedMB         float64  `json:"memory_used_mb"`
	MemoryTotalMB        float64  `json:"memory_total_mb"`
	TemperatureC         float64  `json:"temperature_c"`
	PowerDrawW           *float64 `json:"power_draw_w,omitempty"`
}

// GPUDetector detects GPU hardware and collects metrics.
type GPUDetector struct {
	// httpClient is used for nvidia-exporter fallback
	httpClient *http.Client
	scheme     string // "http" or "https"

	// Cached availability flag: nil=unknown, true/false=determined
	available *bool

	// True when the most recent Metrics() came up empty because the
	// nvidia-smi probe hit its deadline (GPU saturated, driver slow)
	// rather than failing outright. Busyness is not a wedge: this must
	// never cache available=false, and /gpu reports it as "unknown" so
	// the controller's gpu_health evaluator (which alerts only on an
	// explicit false) does not page the operator for a loaded GPU.
	probeTimedOut bool
}

// NewGPUDetector creates a GPU detector with the given HTTP client for
// nvidia-exporter sidecar fallback.
func NewGPUDetector(client *http.Client, scheme string) *GPUDetector {
	return &GPUDetector{
		httpClient: client,
		scheme:     scheme,
	}
}

// DetectModel returns the GPU model name via nvidia-smi, or empty string if
// no GPU is available.
func (g *GPUDetector) DetectModel() string {
	out, err := execTimeout(nvidiaSmi(), "--query-gpu=name", "--format=csv,noheader,nounits")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > 0 && lines[0] != "" {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

// DetectVRAM returns total VRAM in GB via nvidia-smi.
func (g *GPUDetector) DetectVRAM() float64 {
	out, err := execTimeout(nvidiaSmi(), "--query-gpu=memory.total", "--format=csv,noheader,nounits")
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > 0 {
		if mb, err := strconv.ParseFloat(strings.TrimSpace(lines[0]), 64); err == nil {
			return round(mb/1024, 1)
		}
	}
	return 0
}

// DetectCount returns the number of GPUs available.
func (g *GPUDetector) DetectCount() int {
	out, err := execTimeout(nvidiaSmi(), "--query-gpu=count", "--format=csv,noheader,nounits")
	if err != nil {
		if g.DetectModel() != "" {
			return 1
		}
		return 0
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(lines[0])); err == nil {
			return n
		}
	}
	return 0
}

// DetectVRAMUsed returns currently used VRAM in GB across all GPUs.
func (g *GPUDetector) DetectVRAMUsed() float64 {
	out, err := execTimeout(nvidiaSmi(), "--query-gpu=memory.used", "--format=csv,noheader,nounits")
	if err != nil {
		return 0
	}
	var totalMB float64
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if mb, err := strconv.ParseFloat(strings.TrimSpace(line), 64); err == nil {
			totalMB += mb
		}
	}
	return round(totalMB/1024, 1)
}

// GPUComputeApp is one process currently holding the GPU.
type GPUComputeApp struct {
	PID          int     `json:"pid"`
	Name         string  `json:"name"`
	UsedMemoryMB float64 `json:"used_memory_mb"`
}

// ComputeApps returns the processes currently using the GPU. Empty is a
// normal answer (on-demand backends unload between requests), so callers
// must never treat "no compute apps" as a fault by itself.
func (g *GPUDetector) ComputeApps() []GPUComputeApp {
	out, err := execTimeout(nvidiaSmi(),
		"--query-compute-apps=pid,process_name,used_gpu_memory",
		"--format=csv,noheader,nounits")
	if err != nil {
		return nil
	}
	var apps []GPUComputeApp
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}
		app := GPUComputeApp{Name: strings.TrimSpace(parts[1])}
		app.PID, _ = strconv.Atoi(strings.TrimSpace(parts[0]))
		app.UsedMemoryMB, _ = strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
		if app.PID > 0 {
			apps = append(apps, app)
		}
	}
	return apps
}

// Metrics collects real-time GPU metrics.
// Strategy 1: nvidia-smi (direct GPU access).
// Strategy 2: nvidia-exporter sidecar on the Docker network.
// Returns nil if no GPU metrics source is available.
func (g *GPUDetector) Metrics() *GPUMetrics {
	g.probeTimedOut = false
	// Skip if we already know metrics are unavailable
	if g.available != nil && !*g.available {
		return nil
	}

	// Strategy 1: nvidia-smi
	if m := g.metricsFromSMI(); m != nil {
		t := true
		g.available = &t
		return m
	}

	// Strategy 2: nvidia-exporter sidecar
	if m := g.metricsFromExporter(); m != nil {
		t := true
		g.available = &t
		return m
	}

	// Neither available. A deadline miss must not decide "no GPU" — a
	// first probe against a saturated card would otherwise cache
	// available=false for the life of the process (sticky), turning one
	// busy moment into an hourly gpu_health page until the agent
	// restarts. Only an affirmative failure (binary missing, driver
	// error) is allowed to stick.
	if g.available == nil && !g.probeTimedOut {
		f := false
		g.available = &f
	}
	return nil
}

// ProbeTimedOut reports whether the last Metrics() returned nil because the
// nvidia-smi probe missed its deadline rather than failing affirmatively.
func (g *GPUDetector) ProbeTimedOut() bool {
	return g.probeTimedOut
}

func (g *GPUDetector) metricsFromSMI() *GPUMetrics {
	out, err := execTimeout(nvidiaSmi(),
		"--query-gpu=utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw",
		"--format=csv,noheader,nounits")
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			g.probeTimedOut = true
		}
		return nil
	}

	values := strings.Split(strings.TrimSpace(out), ",")
	if len(values) < 6 {
		return nil
	}

	m := &GPUMetrics{}
	m.GPUUtilizationPct, _ = strconv.ParseFloat(strings.TrimSpace(values[0]), 64)
	m.MemoryUtilizationPct, _ = strconv.ParseFloat(strings.TrimSpace(values[1]), 64)
	m.MemoryUsedMB, _ = strconv.ParseFloat(strings.TrimSpace(values[2]), 64)
	m.MemoryTotalMB, _ = strconv.ParseFloat(strings.TrimSpace(values[3]), 64)
	m.TemperatureC, _ = strconv.ParseFloat(strings.TrimSpace(values[4]), 64)

	powerStr := strings.TrimSpace(values[5])
	if powerStr != "[N/A]" {
		if pw, err := strconv.ParseFloat(powerStr, 64); err == nil {
			m.PowerDrawW = &pw
		}
	}

	return m
}

func (g *GPUDetector) metricsFromExporter() *GPUMetrics {
	if g.httpClient == nil {
		return nil
	}

	url := fmt.Sprintf("%s://nvidia-exporter:9400/metrics", g.scheme)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	resp, err := g.httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	// Parse Prometheus text format (simplified)
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	m := &GPUMetrics{}
	found := false

	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "nvidia_gpu_") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		metricName := strings.Split(parts[0], "{")[0]
		val, err := strconv.ParseFloat(parts[len(parts)-1], 64)
		if err != nil {
			continue
		}

		found = true
		switch {
		case strings.Contains(metricName, "temperature_celsius"):
			m.TemperatureC = val
		case strings.Contains(metricName, "power_draw_watts"):
			m.PowerDrawW = &val
		case strings.Contains(metricName, "memory_used_bytes"):
			m.MemoryUsedMB = val / (1024 * 1024)
		case strings.Contains(metricName, "memory_total_bytes"):
			m.MemoryTotalMB = val / (1024 * 1024)
		case strings.Contains(metricName, "utilization_gpu_ratio"):
			m.GPUUtilizationPct = val * 100
		case strings.Contains(metricName, "utilization_memory_ratio"):
			m.MemoryUtilizationPct = val * 100
		}
	}

	if !found {
		return nil
	}
	return m
}
