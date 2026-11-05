// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"math"
	"runtime"
	"testing"
)

func TestCPUCores(t *testing.T) {
	cores := CPUCores()
	if cores < 1 {
		t.Errorf("expected at least 1 CPU core, got %d", cores)
	}
	if cores != runtime.NumCPU() {
		t.Errorf("expected %d cores, got %d", runtime.NumCPU(), cores)
	}
}

func TestTotalMemoryGB(t *testing.T) {
	mem := TotalMemoryGB()
	// Any reasonable machine has > 0.5GB
	if mem < 0.5 {
		t.Errorf("expected > 0.5 GB memory, got %.2f", mem)
	}
	// And less than 100TB (sanity check)
	if mem > 100000 {
		t.Errorf("unreasonable memory value: %.2f GB", mem)
	}
}

func TestReadMemoryInfo(t *testing.T) {
	info := ReadMemoryInfo()
	if info.TotalKB < 1024 { // at least 1MB
		t.Errorf("expected > 1MB total memory, got %d kB", info.TotalKB)
	}
	if info.AvailableKB < 0 {
		t.Errorf("available memory should not be negative: %d kB", info.AvailableKB)
	}
	if info.AvailableKB > info.TotalKB {
		t.Errorf("available (%d kB) > total (%d kB)", info.AvailableKB, info.TotalKB)
	}
}

func TestCPULoad(t *testing.T) {
	load, ok := CPULoad()
	if !ok {
		t.Skip("no CPU load reader on this platform")
	}
	if load < 0 {
		t.Errorf("CPU load should not be negative: %f", load)
	}
	if load > 1.0 {
		t.Errorf("CPU load should be capped at 1.0, got %f", load)
	}
}

func TestIsARM(t *testing.T) {
	isArm := IsARM()
	expected := runtime.GOARCH == "arm" || runtime.GOARCH == "arm64"
	if isArm != expected {
		t.Errorf("IsARM() = %v, expected %v for GOARCH=%s", isArm, expected, runtime.GOARCH)
	}
}

func TestMemoryInfoFrom(t *testing.T) {
	if got := memoryInfoFrom(0, 0); got != (MemoryInfo{}) {
		t.Errorf("zero total = %+v, want zero value", got)
	}
	// The darwin vm_stat failure: total known, available -1.
	got := memoryInfoFrom(16<<20, -1)
	if got.TotalKB != 16<<20 || got.AvailableKnown || got.AvailableKB != 0 {
		t.Errorf("vm_stat failure = %+v, want total set and AvailableKnown=false", got)
	}
	got = memoryInfoFrom(16<<20, 4<<20)
	if !got.AvailableKnown || got.AvailableKB != 4<<20 {
		t.Errorf("good read = %+v", got)
	}
	// A genuine 0 available is a measurement, not an unknown.
	if got = memoryInfoFrom(16<<20, 0); !got.AvailableKnown {
		t.Errorf("measured 0 must stay known: %+v", got)
	}
}

// The documented `sysctl -n vm.loadavg` form ("{ 2.17 1.98 1.90 }") is read
// as the 1-minute figure and normalised exactly like Linux: divided by the
// core count, capped at 1.
func TestParseDarwinLoadavg(t *testing.T) {
	for _, c := range []struct {
		in   string
		want float64
		ok   bool
	}{
		{"{ 2.17 1.98 1.90 }\n", 2.17, true},
		{"{ 0.00 0.01 0.05 }", 0, true},
		{"{ 12.50 9.00 7.25 }", 12.5, true},
		{"", 0, false},
		{"{ }", 0, false},
		{"{ x 1 2 }", 0, false},
		{"{ NaN 1 2 }", 0, false},
	} {
		got, ok := parseDarwinLoadavg(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseDarwinLoadavg(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
	// 8 cores: 2.17 -> 0.27125; 12.5 saturates at 1.
	if got := normaliseLoad(2.17, 8); got != 2.17/8 {
		t.Errorf("normaliseLoad(2.17, 8) = %v", got)
	}
	if got := normaliseLoad(12.5, 8); got != 1.0 {
		t.Errorf("normaliseLoad(12.5, 8) = %v, want 1", got)
	}
	if got := normaliseLoad(0.5, 0); got != 0.5 {
		t.Errorf("normaliseLoad(0.5, 0) = %v, want 0.5 (cores floor at 1)", got)
	}
}

// A real sample, captured on the mcmini fleet node (Apple silicon, macOS):
// `sysctl -n vm.loadavg` printed "{ 1.02 1.08 1.03 }" and `sysctl -n hw.ncpu`
// printed 10. The heartbeat's load is then 1.02/10 = 0.102.
func TestParseDarwinLoadavgCapturedSample(t *testing.T) {
	const captured = "{ 1.02 1.08 1.03 }\n"
	load1, ok := parseDarwinLoadavg(captured)
	if !ok || load1 != 1.02 {
		t.Fatalf("parseDarwinLoadavg(%q) = %v,%v want 1.02,true", captured, load1, ok)
	}
	if got := normaliseLoad(load1, 10); math.Abs(got-0.102) > 1e-12 {
		t.Errorf("normaliseLoad(1.02, 10) = %v, want 0.102", got)
	}
}

func TestParseProcLoadavg(t *testing.T) {
	if got, ok := parseProcLoadavg("0.52 0.58 0.59 1/467 12345\n"); !ok || got != 0.52 {
		t.Errorf("got %v,%v want 0.52,true", got, ok)
	}
	if _, ok := parseProcLoadavg(""); ok {
		t.Error("empty input reported ok")
	}
}
