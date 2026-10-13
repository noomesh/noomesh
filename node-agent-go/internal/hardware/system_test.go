// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
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
	load := CPULoad()
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
