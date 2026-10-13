// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hardware

import "syscall"

// DiskUsage is one filesystem's usage as the node sees it, reported on
// /health for the controller's disk_watermark evaluator (per-node probes).
type DiskUsage struct {
	Path        string  `json:"path"`
	UsedPercent float64 `json:"used_percent"`
	AvailGB     float64 `json:"avail_gb"`
	TotalGB     float64 `json:"total_gb"`
}

// DiskUsages stats each path that exists and returns df-comparable numbers.
// Paths that are absent or unstattable are silently skipped — a node
// without a separate containerd disk simply reports fewer entries, and the
// consumer treats a missing entry as unknown, never as full or empty.
func DiskUsages(paths []string) []DiskUsage {
	var out []DiskUsage
	seen := map[uint64]bool{}
	for _, p := range paths {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err != nil || st.Blocks == 0 {
			continue
		}
		// Dedup by filesystem id: "/" and "/var/lib/docker" are usually the
		// same fs, and reporting it twice would double-alert one disk.
		fsid := uint64(uint32(st.Fsid.X__val[0]))<<32 | uint64(uint32(st.Fsid.X__val[1]))
		if seen[fsid] {
			continue
		}
		seen[fsid] = true
		bs := float64(st.Bsize)
		total := float64(st.Blocks) * bs
		avail := float64(st.Bavail) * bs // what non-root can still write
		used := float64(st.Blocks-st.Bfree) * bs
		// df's percentage: used / (used + avail) — reserved blocks excluded,
		// so this matches what an operator sees at a shell.
		denom := used + avail
		if denom <= 0 {
			continue
		}
		out = append(out, DiskUsage{
			Path:        p,
			UsedPercent: 100.0 * used / denom,
			AvailGB:     avail / (1024 * 1024 * 1024),
			TotalGB:     total / (1024 * 1024 * 1024),
		})
	}
	return out
}
