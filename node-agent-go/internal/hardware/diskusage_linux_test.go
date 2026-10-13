// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hardware

import "testing"

// `/` always exists and is always mountable — exercises the real statfs
// path rather than a mock (same discipline as the gateway's fs_usage test).
func TestDiskUsagesPlausibleForRoot(t *testing.T) {
	got := DiskUsages([]string{"/"})
	if len(got) != 1 {
		t.Fatalf("expected one entry for /, got %+v", got)
	}
	d := got[0]
	if d.Path != "/" || d.UsedPercent < 0 || d.UsedPercent > 100 || d.TotalGB <= 0 || d.AvailGB < 0 || d.AvailGB > d.TotalGB {
		t.Fatalf("implausible usage: %+v", d)
	}
}

func TestDiskUsagesSkipsMissingAndDedupsSameFS(t *testing.T) {
	got := DiskUsages([]string{"/", "/does/not/exist", "/"})
	if len(got) != 1 {
		t.Fatalf("missing paths must be skipped and same-fs repeats deduped, got %+v", got)
	}
}
