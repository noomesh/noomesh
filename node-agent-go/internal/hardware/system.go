// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"math"
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
	// AvailableKnown is false when the total was read but the available
	// figure could not be (vm_stat failed on macOS, no MemAvailable line).
	// AvailableKB is then 0 and means NOTHING: 0 available would read as a
	// machine with every byte in use.
	AvailableKnown bool
}

// ReadMemoryInfo reports total and available memory, zeroed when unknown —
// same rule, and the same reason, as TotalMemoryGB above.
func ReadMemoryInfo() MemoryInfo {
	totalKB, availKB, ok := readMemory()
	if !ok {
		return MemoryInfo{}
	}
	return memoryInfoFrom(totalKB, availKB)
}

// memoryInfoFrom turns a raw read into a MemoryInfo. A negative availKB is
// the readers' "could not measure" marker; a total of zero or less is
// unknown as a whole.
func memoryInfoFrom(totalKB, availKB int64) MemoryInfo {
	if totalKB <= 0 {
		return MemoryInfo{}
	}
	if availKB < 0 {
		return MemoryInfo{TotalKB: totalKB}
	}
	return MemoryInfo{TotalKB: totalKB, AvailableKB: availKB, AvailableKnown: true}
}

// CPULoad returns the 1-minute load average normalized by core count
// (0.0-1.0), and whether it could be measured at all. ok=false means
// UNKNOWN (the read failed, or this platform has no reader): the value is
// then 0 and means nothing. Callers must omit it rather than report a 0,
// which the gateway would rank as an idle node.
func CPULoad() (v float64, ok bool) {
	load1, ok := readLoad1()
	if !ok {
		return 0, false
	}
	return normaliseLoad(load1, CPUCores()), true
}

// normaliseLoad turns a 1-minute load average into the 0..1 figure the
// heartbeat reports: divided by the core count, capped at 1.
func normaliseLoad(load1 float64, cores int) float64 {
	c := float64(cores)
	if c < 1 {
		c = 1
	}
	return math.Min(load1/c, 1.0)
}

// parseProcLoadavg reads the 1-minute figure from /proc/loadavg text
// ("0.52 0.58 0.59 1/467 12345").
func parseProcLoadavg(text string) (float64, bool) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return 0, false
	}
	return parseLoad(fields[0])
}

// parseDarwinLoadavg reads the 1-minute figure from `sysctl -n vm.loadavg`
// text ("{ 2.17 1.98 1.90 }").
func parseDarwinLoadavg(text string) (float64, bool) {
	fields := strings.Fields(strings.NewReplacer("{", " ", "}", " ").Replace(text))
	if len(fields) < 3 {
		return 0, false
	}
	return parseLoad(fields[0])
}

func parseLoad(f string) (float64, bool) {
	v, err := strconv.ParseFloat(f, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, false
	}
	return v, true
}

// IsARM returns true if running on ARM architecture.
func IsARM() bool {
	arch := runtime.GOARCH
	return arch == "arm" || arch == "arm64"
}
