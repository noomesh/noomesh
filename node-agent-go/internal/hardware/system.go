// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// CPUCores returns the number of logical CPU cores.
func CPUCores() int {
	return runtime.NumCPU()
}

// TotalMemoryGB reports total system memory, or 0 when it cannot be measured.
//
// ZERO MEANS UNKNOWN, and callers must treat it that way. This used to return
// a hardcoded 8.0 on any read failure, which on macOS was EVERY call —
// /proc/meminfo does not exist there, so the fallback fired every time and was
// indistinguishable from a real reading. A 24 GB Mac mini reported 8 GB from
// the day it was enrolled, and because 8 is a plausible
// size for that machine nothing looked wrong.
//
// The knock-on was tiering: `detectUnifiedMemory` takes 75% of this figure as
// the GPU's usable share, so the ladder judged a 24 GB Metal box on 6 GB.
func TotalMemoryGB() float64 {
	totalKB, _, ok := readMemory()
	if !ok {
		return 0
	}
	return float64(totalKB) / (1024 * 1024)
}

// MemoryInfo holds memory figures in kB. Zero total = not measured.
type MemoryInfo struct {
	TotalKB     int64
	AvailableKB int64
}

// ReadMemoryInfo reports total and available memory, zeroed when unknown —
// same rule, and the same reason, as TotalMemoryGB above.
func ReadMemoryInfo() MemoryInfo {
	totalKB, availKB, ok := readMemory()
	if !ok {
		return MemoryInfo{}
	}
	return MemoryInfo{TotalKB: totalKB, AvailableKB: availKB}
}

// CPULoad returns the 1-minute load average normalized by core count (0.0–1.0).
func CPULoad() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	cores := float64(CPUCores())
	if cores < 1 {
		cores = 1
	}
	return math.Min(load1/cores, 1.0)
}

// IsARM returns true if running on ARM architecture.
func IsARM() bool {
	arch := runtime.GOARCH
	return arch == "arm" || arch == "arm64"
}
