// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package main

import (
	"strings"
	"testing"
	"time"
)

// Every line of a multi-line entry carries the prefix: the boot step's stderr
// ("…namespace restore…" then "boot-restore: wrote the secret files and
// started 9 container(s)") is logged as ONE entry, and its second line used
// to come out bare.
func TestEveryLineOfAnEntryCarriesThePrefix(t *testing.T) {
	at := time.Date(2026, 11, 14, 3, 26, 0, 0, time.UTC)
	got := logLines(at, "netns-restore: noo-ollama-embed started\nboot-restore: wrote the secret files and started 9 container(s)\n")
	want := "[noo-hostd 2026-11-14T03:26:00Z] netns-restore: noo-ollama-embed started\n" +
		"[noo-hostd 2026-11-14T03:26:00Z] boot-restore: wrote the secret files and started 9 container(s)\n"
	if got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	if one := logLines(at, "boot-restore: done"); one != "[noo-hostd 2026-11-14T03:26:00Z] boot-restore: done\n" {
		t.Fatalf("a one-line entry changed: %q", one)
	}
	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		if !strings.HasPrefix(line, "[noo-hostd ") {
			t.Fatalf("a line without the prefix: %q", line)
		}
	}
}
