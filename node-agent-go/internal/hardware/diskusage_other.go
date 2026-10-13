// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build !linux

package hardware

// DiskUsage — see diskusage_linux.go.
type DiskUsage struct {
	Path        string  `json:"path"`
	UsedPercent float64 `json:"used_percent"`
	AvailGB     float64 `json:"avail_gb"`
	TotalGB     float64 `json:"total_gb"`
}

// DiskUsages reports nothing off Linux — the consumer treats absence as
// unknown, never as healthy or full.
func DiskUsages(_ []string) []DiskUsage { return nil }
