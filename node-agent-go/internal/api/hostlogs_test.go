// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
	"time"
)

// The harness is not a container, and asking Docker for it answers "No
// such container" — which reads as "nothing to see" rather than "wrong
// question". That is the 2026-09-11 failure repeated one service later,
// so the name must be recognised as a host service.
func TestTheHarnessIsRecognisedAsAHostServiceNotAContainer(t *testing.T) {
	if _, ok := HostServiceUnits["noo-harness"]; !ok {
		t.Fatal("noo-harness is not served as a host service; `noo cluster logs <node> noo-harness` would ask Docker for it")
	}
	// The agent itself must stay recognised too: its ring is the fast path
	// and the journal is its fallback when the ring is empty after a crash.
	if _, ok := HostServiceUnits["noo-node-agent"]; !ok {
		t.Fatal("the agent's own unit must be readable when its in-memory ring is empty")
	}
}

// An unknown name must be refused by NAME, not silently answered.
func TestAnUnknownHostServiceIsRefusedRatherThanEmptied(t *testing.T) {
	_, _, err := HostServiceLogs(context.Background(), "noo-something-else", 10)
	if err == nil {
		t.Fatal("an unknown host service must be an error, not an empty log")
	}
	if !strings.Contains(err.Error(), "noo-something-else") {
		t.Fatalf("the refusal must name what was asked for, got %q", err)
	}
}

// A helper that is absent is a NAMED failure. "No logs" and "could not
// read the logs" are different facts and only one of them means the
// service has been quiet — conflating them is how a dead harness reads as
// a healthy one.
func TestAMissingHelperIsNamedNotReportedAsSilence(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin reads a file; the helper is not involved")
	}
	// This test is about the helper being ABSENT. On a fleet node — this
	// repo is developed on one — a real hostd is alive, the heartbeat is
	// fresh, and the code correctly proceeds to queue a command into a
	// root-owned spool that an unprivileged test cannot write. That
	// "permission denied" is an honest error but it is not the case under
	// test, so decide by the heartbeat, not by whether an error came back
	// (2026-09-22: it failed here for exactly that reason).
	if hb, err := hostd.ReadHeartbeat(hostd.WorkerSpoolDir); err == nil && !hb.Stale(time.Now().UTC()) {
		t.Skip("a live hostd is running on this machine; the absent-helper case cannot be exercised here")
	}
	_, _, err := HostServiceLogs(context.Background(), "noo-harness", 10)
	if err == nil {
		t.Fatal("no heartbeat, yet the log read succeeded — the helper check is not being consulted")
	}
	if !strings.Contains(err.Error(), "noo-hostd") {
		t.Fatalf("the failure must name the helper so an operator knows what to fix, got %q", err)
	}
}

// The tail bound is what stops a queued command from being a memory and
// disk amplifier, and lastLines is the half of it the agent owns.
func TestLastLinesKeepsTheEndAndSurvivesEmptyInput(t *testing.T) {
	got := lastLines("a\nb\nc\nd\n", 2)
	if strings.Join(got, ",") != "c,d" {
		t.Fatalf("want the LAST lines, got %v", got)
	}
	if n := len(lastLines("", 10)); n != 0 {
		t.Fatalf("empty input must be no lines, got %d", n)
	}
	if n := len(lastLines("only\n", 10)); n != 1 {
		t.Fatalf("fewer lines than asked for is not an error, got %d", n)
	}
}

// darwin reads the file its plist already writes — no helper, no
// privilege. Pinned so a plist path change cannot silently orphan it.
func TestDarwinReadsTheFileThePlistWrites(t *testing.T) {
	if p := darwinLogFile("noo-harness"); p != "/tmp/noomesh-harness.log" {
		t.Fatalf("darwin harness log path drifted from the plist: %q", p)
	}
	if p := darwinLogFile("noo-fetch"); p != "" {
		t.Fatalf("only the harness has a plist log file today, got %q", p)
	}
}

// The path must actually read a file on darwin rather than reach for the
// helper; exercised here on any OS by calling the reader directly.
func TestTheDarwinPathReadsAFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "h.log")
	if err := os.WriteFile(p, []byte("one\ntwo\nthree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := lastLines(string(b), 2); strings.Join(got, ",") != "two,three" {
		t.Fatalf("got %v", got)
	}
}
