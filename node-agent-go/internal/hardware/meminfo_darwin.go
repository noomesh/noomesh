// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build darwin

package hardware

import (
	"os/exec"
	"strconv"
	"strings"
)

// readMemory asks the kernel directly: macOS has no /proc/meminfo, which is
// exactly how a 24 GB Mac mini reported 8 GB for months
// — the old reader fell through to a hardcoded fallback that was
// indistinguishable from a real measurement.
//
// Total is `hw.memsize` (bytes). Available is derived from `vm_stat`: free +
// inactive + speculative pages, which is the closest analogue to Linux's
// MemAvailable — inactive pages are reclaimable under pressure, so counting
// only "free" would understate available memory on any Mac that has been up
// for more than a few minutes.
func readMemory() (totalKB int64, availKB int64, ok bool) {
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0, 0, false
	}
	bytes, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || bytes <= 0 {
		return 0, 0, false
	}
	totalKB = bytes / 1024
	// Available is best-effort: a total without it is still worth reporting,
	// so a vm_stat failure leaves availKB at 0 rather than failing the read.
	return totalKB, availableKBFromVMStat(), true
}

// availableKBFromVMStat runs `vm_stat`. Returns 0 when it cannot.
func availableKBFromVMStat() int64 {
	out, err := exec.Command("vm_stat").Output()
	if err != nil {
		return 0
	}
	return parseVMStat(string(out))
}

// parseVMStat is the parsing half, separated so it can be tested against real
// `vm_stat` output without a Mac.
func parseVMStat(out string) int64 {
	var pageSize int64 = 4096
	var pages int64
	for _, line := range strings.Split(out, "\n") {
		// The header names the page size: "Mach Virtual Memory Statistics:
		// (page size of 16384 bytes)" — 16K on Apple Silicon, not 4K.
		if strings.Contains(line, "page size of") {
			f := strings.Fields(line)
			for i, w := range f {
				if w == "of" && i+1 < len(f) {
					if v, err := strconv.ParseInt(f[i+1], 10, 64); err == nil && v > 0 {
						pageSize = v
					}
				}
			}
			continue
		}
		name, count, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(name) {
		case "Pages free", "Pages inactive", "Pages speculative":
			v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(count), ".")), 10, 64)
			if err == nil {
				pages += v
			}
		}
	}
	return pages * pageSize / 1024
}
