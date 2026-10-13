// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hardware

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// TotalMemoryGB must be DERIVED from /proc/meminfo, not merely plausible.
//
// The test this strengthens (TestTotalMemoryGB) asserted only that the value
// sat between 0.5 GB and 100 TB — a range a hardcoded fallback satisfies. That
// is why the macOS bug went unnoticed for months: the assertion could not tell
// a measurement from a constant.
func TestTotalMemoryMatchesProcMeminfo(t *testing.T) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Skip("no /proc/meminfo")
	}
	var wantKB int64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				wantKB, _ = strconv.ParseInt(f[1], 10, 64)
			}
			break
		}
	}
	if wantKB == 0 {
		t.Skip("MemTotal not present")
	}
	want := float64(wantKB) / (1024 * 1024)
	if got := TotalMemoryGB(); got != want {
		t.Errorf("TotalMemoryGB() = %.4f, want %.4f (MemTotal)", got, want)
	}
}
