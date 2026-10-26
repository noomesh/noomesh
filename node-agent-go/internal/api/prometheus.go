// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
)

// handlePrometheusMetrics renders Prometheus text-format metrics.
// Matches Python api_prometheus_metrics().
func (s *Server) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	nodeID := s.cfg.NodeID

	// Node info
	b.WriteString("# HELP noo_node_info Node information\n")
	b.WriteString("# TYPE noo_node_info gauge\n")
	fmt.Fprintf(&b, "noo_node_info{node_id=%q} 1\n", nodeID)

	// System load
	m := s.collector.Collect()
	b.WriteString("# HELP noo_node_load Current node load (0-1)\n")
	b.WriteString("# TYPE noo_node_load gauge\n")
	fmt.Fprintf(&b, "noo_node_load{node_id=%q} %g\n", nodeID, m.Load)

	// GPU metrics
	gpuMetrics := s.gpu.Metrics()
	if gpuMetrics != nil {
		gpuModel := s.gpu.DetectModel()
		if gpuModel == "" {
			gpuModel = "unknown"
		}

		if gpuMetrics.GPUUtilizationPct != nil { // unknown is omitted, never exported as 0
			b.WriteString("# HELP noo_gpu_utilization_percent GPU utilization percentage\n")
			b.WriteString("# TYPE noo_gpu_utilization_percent gauge\n")
			fmt.Fprintf(&b, "noo_gpu_utilization_percent{node_id=%q,gpu=%q} %g\n",
				nodeID, gpuModel, *gpuMetrics.GPUUtilizationPct)
		}

		if gpuMetrics.MemoryUtilizationPct != nil { // unknown is omitted, never exported as 0
			b.WriteString("# HELP noo_gpu_memory_utilization_percent GPU memory utilization percentage\n")
			b.WriteString("# TYPE noo_gpu_memory_utilization_percent gauge\n")
			fmt.Fprintf(&b, "noo_gpu_memory_utilization_percent{node_id=%q,gpu=%q} %g\n",
				nodeID, gpuModel, *gpuMetrics.MemoryUtilizationPct)
		}

		if gpuMetrics.MemoryUsedMB != nil { // unknown is omitted, never exported as 0
			b.WriteString("# HELP noo_gpu_memory_used_mb GPU memory used in MB\n")
			b.WriteString("# TYPE noo_gpu_memory_used_mb gauge\n")
			fmt.Fprintf(&b, "noo_gpu_memory_used_mb{node_id=%q,gpu=%q} %g\n",
				nodeID, gpuModel, *gpuMetrics.MemoryUsedMB)
		}

		if gpuMetrics.MemoryTotalMB != nil { // unknown is omitted, never exported as 0
			b.WriteString("# HELP noo_gpu_memory_total_mb GPU memory total in MB\n")
			b.WriteString("# TYPE noo_gpu_memory_total_mb gauge\n")
			fmt.Fprintf(&b, "noo_gpu_memory_total_mb{node_id=%q,gpu=%q} %g\n",
				nodeID, gpuModel, *gpuMetrics.MemoryTotalMB)
		}

		if gpuMetrics.TemperatureC != nil { // unknown is omitted, never exported as 0
			b.WriteString("# HELP noo_gpu_temperature_celsius GPU temperature in Celsius\n")
			b.WriteString("# TYPE noo_gpu_temperature_celsius gauge\n")
			fmt.Fprintf(&b, "noo_gpu_temperature_celsius{node_id=%q,gpu=%q} %g\n",
				nodeID, gpuModel, *gpuMetrics.TemperatureC)
		}

		if gpuMetrics.PowerDrawW != nil {
			b.WriteString("# HELP noo_gpu_power_draw_watts GPU power draw in watts\n")
			b.WriteString("# TYPE noo_gpu_power_draw_watts gauge\n")
			fmt.Fprintf(&b, "noo_gpu_power_draw_watts{node_id=%q,gpu=%q} %g\n",
				nodeID, gpuModel, *gpuMetrics.PowerDrawW)
		}
	}

	// Legacy credential lanes admitted since this agent started. Two fixed lanes: the label set is closed.
	writeLegacyLanes(&b, nodeID, auth.LegacyLaneCounts())

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(b.String()))
}

// writeLegacyLanes renders noo_node_legacy_lane_uses_total, lanes sorted so
// the text is stable.
func writeLegacyLanes(b *strings.Builder, nodeID string, counts map[string]uint64) {
	lanes := make([]string, 0, len(counts))
	for l := range counts {
		lanes = append(lanes, l)
	}
	sort.Strings(lanes)
	b.WriteString("# HELP noo_node_legacy_lane_uses_total Requests admitted by a legacy credential lane since the agent started\n")
	b.WriteString("# TYPE noo_node_legacy_lane_uses_total counter\n")
	for _, l := range lanes {
		fmt.Fprintf(b, "noo_node_legacy_lane_uses_total{node_id=%q,lane=%q} %d\n", nodeID, l, counts[l])
	}
}
