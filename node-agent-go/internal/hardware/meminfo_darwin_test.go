// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build darwin

package hardware

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// The regression, stated as a test: the figure must come from the kernel.
//
// The old reader parsed /proc/meminfo, which macOS does not have, and returned
// a hardcoded 8.0 on failure — so it returned 8.0 on EVERY call. A 24 GB Mac
// mini reported 8 GB from enrolment onward. The existing
// TestTotalMemoryGB passed throughout, because 8 is a perfectly reasonable
// number: it checked the value was plausible, never that it was measured.
func TestTotalMemoryMatchesSysctl(t *testing.T) {
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		t.Skip("sysctl unavailable")
	}
	want, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Skip("hw.memsize unparseable")
	}
	got := TotalMemoryGB()
	if wantGB := float64(want) / (1024 * 1024 * 1024); got < wantGB*0.99 || got > wantGB*1.01 {
		t.Errorf("TotalMemoryGB() = %.2f, want ~%.2f from hw.memsize", got, wantGB)
	}
}

// Apple Silicon pages are 16K, not the 4K default. Using the wrong size
// understates available memory by 4x, which would read as a machine under
// permanent memory pressure.
func TestParseVMStatUsesTheReportedPageSize(t *testing.T) {
	const sample = `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               100.
Pages active:                            5000.
Pages inactive:                            50.
Pages speculative:                         10.
Pages wired down:                        2000.
`
	// (100 + 50 + 10) pages * 16384 B / 1024 = 2560 kB
	if got := parseVMStat(sample); got != 2560 {
		t.Errorf("parseVMStat = %d kB, want 2560 (160 pages at 16K)", got)
	}
}

// Free alone is not "available": inactive pages are reclaimable, and counting
// only free would make any long-running Mac look full.
func TestParseVMStatCountsReclaimablePages(t *testing.T) {
	const sample = `Mach Virtual Memory Statistics: (page size of 4096 bytes)
Pages free:                                 1.
Pages inactive:                             2.
Pages speculative:                          3.
`
	if got := parseVMStat(sample); got != 6*4096/1024 {
		t.Errorf("parseVMStat = %d kB, want free+inactive+speculative", got)
	}
}

// Garbage in must not become a confident zero-page answer that later reads as
// "no memory available".
func TestParseVMStatOnJunk(t *testing.T) {
	if got := parseVMStat("not vm_stat output at all"); got != 0 {
		t.Errorf("parseVMStat on junk = %d, want 0", got)
	}
}
