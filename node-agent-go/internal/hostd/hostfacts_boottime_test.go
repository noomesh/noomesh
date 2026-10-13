// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import "testing"

func TestBootTimeReadsBtimeFromProcStat(t *testing.T) {
	stat := "cpu  1 2 3 4\nintr 5\nctxt 6\nbtime 1790861910\nprocesses 7\n"
	if got, want := bootTime(stat), "2026-10-01T13:38:30Z"; got != want {
		t.Fatalf("bootTime = %q, want %q", got, want)
	}
	for _, bad := range []string{"", "cpu 1 2\n", "btime nope\n", "btime 0\n"} {
		if got := bootTime(bad); got != "" {
			t.Errorf("bootTime(%q) = %q, want empty", bad, got)
		}
	}
}
