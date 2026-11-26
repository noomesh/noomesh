// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	fetchPrintRunning = "system/net.noomesh.fetch = {\n\tactive count = 1\n\tpath = /Library/LaunchDaemons/net.noomesh.fetch.plist\n\tstate = running\n\n\tpid = 412\n\tlast exit code = (never exited)\n}\n"
	fetchPrintIdleOK  = "system/net.noomesh.fetch = {\n\tactive count = 0\n\tpath = /Library/LaunchDaemons/net.noomesh.fetch.plist\n\tstate = not running\n\n\tlast exit code = 0\n\trun interval = 60 seconds\n}\n"
	fetchPrint78      = "system/net.noomesh.fetch = {\n\tactive count = 0\n\tpath = /Library/LaunchDaemons/net.noomesh.fetch.plist\n\tstate = not running\n\n\tlast exit code = 78\n\trun interval = 60 seconds\n}\n"
	fetchPrintLWCR    = "system/net.noomesh.fetch = {\n\tstate = not running\n\tlast exit status = (never exited)\n\treason = needs LWCR update\n}\n"
)

func TestParseFetchJob(t *testing.T) {
	for _, c := range []struct {
		name string
		rc   int
		out  string
		want fetchJobStatus
	}{
		{"running", 0, fetchPrintRunning, fetchJobRunning},
		{"loaded idle ok", 0, fetchPrintIdleOK, fetchJobIdle},
		{"loaded exit 78", 0, fetchPrint78, fetchJobSpawnRefused},
		{"loaded LWCR text", 0, fetchPrintLWCR, fetchJobSpawnRefused},
		{"not loaded", 113, "", fetchJobNotLoaded},
		{"no launchctl", 127, "", fetchJobUnknown},
		{"print failing for another reason", 1, "", fetchJobUnknown},
		{"not found by its words", 1, "Could not find service \"net.noomesh.fetch\" in domain for system", fetchJobNotLoaded},
		{"spawn scheduled with a stale 78", 0, "\tstate = spawn scheduled\n\tlast exit code = 78\n", fetchJobUnknown},
		{"idle state but a pid", 0, "\tstate = not running\n\tpid = 99\n\tlast exit code = 78\n", fetchJobUnknown},
		{"an unknown state", 0, "\tstate = xpcproxy\n\tlast exit code = 78\n", fetchJobUnknown},
		{"lwcr only in an unrelated line", 0, "\tstate = not running\n\tpath = /Library/lwcr/x.plist\n\tlast exit code = 0\n", fetchJobIdle},
		{"waiting with exit 78", 0, "\tstate = waiting\n\tlast exit code = 78: EX_CONFIG\n", fetchJobSpawnRefused},
		{"garbage", 0, "\x00\xff not launchd output at all", fetchJobUnknown},
		{"empty", 0, "", fetchJobUnknown},
		{"running with a stale 78", 0, "\tstate = running\n\tlast exit code = 78\n", fetchJobRunning},
		{"a nonzero exit that is not 78", 0, "\tstate = not running\n\tlast exit code = 1\n", fetchJobIdle},
		{"exit 780 is not 78", 0, "\tstate = not running\n\tlast exit code = 780\n", fetchJobIdle},
	} {
		if got := parseFetchJob(c.rc, c.out); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// fetchHarness pins the OS, the plist, the clock and the teardown sleep.
type fetchHarness struct {
	e      *Engine
	r      *fakeRunner
	logs   []string
	now    time.Time
	plist  string
	exists bool
	sleeps int
}

func newFetchHarness(t *testing.T) *fetchHarness {
	t.Helper()
	h := &fetchHarness{now: time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC), exists: true}
	h.plist = filepath.Join(t.TempDir(), "net.noomesh.fetch.plist")
	t.Setenv("NOO_FETCH_PLIST", h.plist)
	oldGOOS, oldExists, oldNow, oldSleep, oldLimit := fetchRearmGOOS, fetchPlistExists, nowUTC, bootstrapRetrySleep, fetchLaunchctlLimit
	t.Cleanup(func() {
		fetchRearmGOOS, fetchPlistExists, nowUTC, bootstrapRetrySleep, fetchLaunchctlLimit = oldGOOS, oldExists, oldNow, oldSleep, oldLimit
	})
	fetchRearmGOOS = "darwin"
	fetchPlistExists = func(string) bool { return h.exists }
	oldConfirm, oldKick := fetchConfirmSleep, fetchKickGOOS
	t.Cleanup(func() { fetchConfirmSleep, fetchKickGOOS = oldConfirm, oldKick })
	fetchConfirmSleep = func() { h.sleeps++ }
	nowUTC = func() time.Time { return h.now }
	bootstrapRetrySleep = func() {}
	h.r = &fakeRunner{rc: map[string]int{}, stdout: map[string]string{}}
	h.e = &Engine{Mode: ModeWorker, Runner: h.r, Logf: func(f string, a ...any) { h.logs = append(h.logs, strings.TrimSpace(fmt.Sprintf(f, a...))) }}
	return h
}

// launchctl is the joined argv of every launchctl call so far, one per line.
func (h *fetchHarness) launchctl() string { return strings.Join(h.r.joined(), "\n") }

func (h *fetchHarness) state() string {
	if f := h.e.fetchJobFact(); f != nil {
		return f.State
	}
	return ""
}

const fetchTarget = "system/net.noomesh.fetch"

func TestFetchJobStateMachineFromEveryState(t *testing.T) {
	t.Run("running is never touched", func(t *testing.T) {
		h := newFetchHarness(t)
		h.r.stdout["print "+fetchTarget] = fetchPrintRunning
		h.e.fetchJobCheck(context.Background(), true)
		if got := h.launchctl(); got != "launchctl print "+fetchTarget {
			t.Fatalf("a running job must only be read, got:\n%s", got)
		}
		if h.state() != FetchJobOK {
			t.Fatalf("fact = %q", h.state())
		}
	})
	t.Run("running with a refused-looking exit is still not touched", func(t *testing.T) {
		h := newFetchHarness(t)
		h.r.stdout["print "+fetchTarget] = "\tstate = running\n\tlast exit code = 78\n\treason = needs LWCR update\n"
		h.e.fetchJobCheck(context.Background(), true)
		if strings.Contains(h.launchctl(), "boot") || strings.Contains(h.launchctl(), "kickstart") {
			t.Fatalf("aborting a running apply:\n%s", h.launchctl())
		}
	})
	t.Run("loaded idle ok does nothing", func(t *testing.T) {
		h := newFetchHarness(t)
		h.r.stdout["print "+fetchTarget] = fetchPrintIdleOK
		h.e.fetchJobCheck(context.Background(), true)
		if h.launchctl() != "launchctl print "+fetchTarget || h.state() != FetchJobOK {
			t.Fatalf("calls:\n%s\nfact %q", h.launchctl(), h.state())
		}
	})
	t.Run("garbage does nothing", func(t *testing.T) {
		h := newFetchHarness(t)
		h.r.stdout["print "+fetchTarget] = "???"
		h.e.fetchJobCheck(context.Background(), true)
		if h.launchctl() != "launchctl print "+fetchTarget || h.state() != "" {
			t.Fatalf("calls:\n%s\nfact %q", h.launchctl(), h.state())
		}
	})
	t.Run("not loaded: bootstrap the existing plist then kickstart", func(t *testing.T) {
		h := newFetchHarness(t)
		h.r.rc["print "+fetchTarget] = 113
		h.e.fetchJobCheck(context.Background(), true)
		want := "launchctl print " + fetchTarget + "\nlaunchctl bootstrap system " + h.plist + "\nlaunchctl kickstart " + fetchTarget
		if h.launchctl() != want {
			t.Fatalf("got:\n%s\nwant:\n%s", h.launchctl(), want)
		}
		if h.state() != FetchJobRearmed || !hasLog(h.logs, "re-armed") {
			t.Fatalf("fact %q logs %v", h.state(), h.logs)
		}
	})
	t.Run("exit 78: bootout, bootstrap (outwaiting teardown), kickstart", func(t *testing.T) {
		h := newFetchHarness(t)
		h.r.stdout["print "+fetchTarget] = fetchPrint78
		h.e.Runner = &sequencedRunner{inner: h.r, printAnswers: []printAnswer{{0, fetchPrint78}}, bootstrapAnswers: []printAnswer{
			{5, "Bootstrap failed: 5: Input/output error"}, {5, "Bootstrap failed: 5: Input/output error"}, {0, ""}}}
		h.e.fetchJobCheck(context.Background(), true)
		want := []string{"launchctl print " + fetchTarget, "launchctl print " + fetchTarget, "launchctl print " + fetchTarget, "launchctl bootout " + fetchTarget,
			"launchctl bootstrap system " + h.plist, "launchctl bootstrap system " + h.plist, "launchctl bootstrap system " + h.plist,
			"launchctl kickstart " + fetchTarget}
		if got := h.r.joined(); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		if h.state() != FetchJobRearmed {
			t.Fatalf("fact %q", h.state())
		}
	})
	t.Run("plist missing: nothing but the fact and a log line", func(t *testing.T) {
		h := newFetchHarness(t)
		h.exists = false
		h.r.rc["print "+fetchTarget] = 113
		h.e.fetchJobCheck(context.Background(), true)
		if h.launchctl() != "launchctl print "+fetchTarget {
			t.Fatalf("must not bootstrap a missing plist:\n%s", h.launchctl())
		}
		if h.state() != FetchJobPlistMissing || !hasLog(h.logs, "does not exist") {
			t.Fatalf("fact %q logs %v", h.state(), h.logs)
		}
		if _, err := os.Stat(h.plist); err == nil {
			t.Fatal("a plist was written")
		}
	})
}

func TestFetchJobChecksAreSpacedAndRearmsRateLimited(t *testing.T) {
	h := newFetchHarness(t)
	h.r.stdout["print "+fetchTarget] = fetchPrint78
	ctx := context.Background()
	h.e.fetchJobCheck(ctx, false)
	n := len(h.r.calls)
	// Within 10 minutes the periodic check does not even print.
	h.now = h.now.Add(9 * time.Minute)
	h.e.fetchJobCheck(ctx, false)
	if len(h.r.calls) != n {
		t.Fatalf("periodic check ran inside 10 minutes: %v", h.r.joined())
	}
	// A forced (after-kick) check prints but a second re-arm inside 30 minutes does not happen.
	h.e.fetchJobCheck(ctx, true)
	if got := strings.Count(h.launchctl(), "bootout"); got != 1 {
		t.Fatalf("re-armed again inside 30 minutes (%d bootouts):\n%s", got, h.launchctl())
	}
	// After 30 minutes the job is still refused: a second re-arm runs.
	h.now = h.now.Add(31 * time.Minute)
	h.e.fetchJobCheck(ctx, false)
	if got := strings.Count(h.launchctl(), "bootout"); got != 2 {
		t.Fatalf("expected a second re-arm after 30 minutes, got %d:\n%s", got, h.launchctl())
	}
}

func TestFetchJobGivesUpAfterThreeFailuresAndSaysSo(t *testing.T) {
	h := newFetchHarness(t)
	h.r.rc["print "+fetchTarget] = 113
	h.r.rc["bootstrap"] = 5
	h.r.rcMsg = map[string]string{"bootstrap": "Bootstrap failed: 5: boom"}
	bootstrapRetries = 0
	t.Cleanup(func() { bootstrapRetries = 5 })
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		h.e.fetchJobCheck(ctx, true)
		h.now = h.now.Add(31 * time.Minute)
	}
	if got := strings.Count(h.launchctl(), "launchctl bootstrap"); got != 3 {
		t.Fatalf("expected exactly 3 attempts, got %d:\n%s", got, h.launchctl())
	}
	if h.state() != FetchJobRearmFailed || !hasLog(h.logs, "giving up") {
		t.Fatalf("fact %q logs %v", h.state(), h.logs)
	}
	if n := countLogs(h.logs, "giving up"); n != 1 {
		t.Fatalf("the give-up must be one line, got %d: %v", n, h.logs)
	}
}

func TestFetchJobAReArmThatDoesNotHoldCountsAsAFailure(t *testing.T) {
	h := newFetchHarness(t)
	h.r.stdout["print "+fetchTarget] = fetchPrint78 // every command succeeds, the job stays refused
	for i := 0; i < 6; i++ {
		h.e.fetchJobCheck(context.Background(), true)
		h.now = h.now.Add(31 * time.Minute)
	}
	if got := strings.Count(h.launchctl(), "bootout"); got != 3 {
		t.Fatalf("a re-arm that never fixes the job must stop after 3 tries, got %d", got)
	}
	if !hasLog(h.logs, "giving up") {
		t.Fatalf("logs %v", h.logs)
	}
}

func TestFetchJobRecoveryClearsTheFailureCount(t *testing.T) {
	h := newFetchHarness(t)
	h.r.stdout["print "+fetchTarget] = fetchPrint78
	h.e.fetchJobCheck(context.Background(), true)
	h.now = h.now.Add(31 * time.Minute)
	h.r.stdout["print "+fetchTarget] = fetchPrintIdleOK
	h.e.fetchJobCheck(context.Background(), true)
	if h.state() != FetchJobOK || h.e.fetch.failures != 0 || h.e.fetch.pendingVerify {
		t.Fatalf("fact %q failures %d pending %v", h.state(), h.e.fetch.failures, h.e.fetch.pendingVerify)
	}
}

// hungRunner never answers until its context ends.
type hungRunner struct{ calls []string }

func (h *hungRunner) Run(ctx context.Context, _ string, _ []string, name string, args ...string) (int, string) {
	h.calls = append(h.calls, name+" "+strings.Join(args, " "))
	<-ctx.Done()
	return 1, ""
}
func (h *hungRunner) Capture(ctx context.Context, _ string, name string, args ...string) (int, string) {
	h.calls = append(h.calls, name+" "+strings.Join(args, " "))
	<-ctx.Done()
	return 113, "" // what a killed print looks like: must NOT read as "not loaded"
}

func TestAHungLaunchctlIsBoundedAndNotReadAsNotLoaded(t *testing.T) {
	h := newFetchHarness(t)
	hr := &hungRunner{}
	h.e.Runner = hr
	fetchLaunchctlLimit = 50 * time.Millisecond
	done := make(chan struct{})
	go func() { h.e.fetchJobCheck(context.Background(), true); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a hung launchctl was not bounded")
	}
	if len(hr.calls) != 1 || !hasLog(h.logs, "timed out") {
		t.Fatalf("a timed-out print must end the check: calls %v logs %v", hr.calls, h.logs)
	}
}

func TestFetchJobDoesNothingOffDarwinOrOutsideWorkerMode(t *testing.T) {
	h := newFetchHarness(t)
	h.r.rc["print "+fetchTarget] = 113
	fetchRearmGOOS = "linux"
	h.e.fetchJobCheck(context.Background(), true)
	fetchRearmGOOS = "darwin"
	h.e.Mode = ModeController
	h.e.fetchJobCheck(context.Background(), true)
	if len(h.r.calls) != 0 || h.e.fetchJobFact() != nil {
		t.Fatalf("calls %v", h.r.joined())
	}
}

// The real op, with the kick's argv pinned to the Mac's. A kick that worked
// leaves launchd mid-spawn with the previous run's exit status on display:
// acting on it would bootout the fetch just started.
func TestFetchBundleOpChecksTheJobOnlyAfterAFailedKick(t *testing.T) {
	t.Setenv("NOO_CONF_DIR", t.TempDir())
	spawning := "system/net.noomesh.fetch = {\n\tstate = spawn scheduled\n\tlast exit code = 78\n}\n"

	h := newFetchHarness(t)
	fetchKickGOOS = "darwin"
	h.r.stdout["print "+fetchTarget] = spawning
	if rc, _ := opFetchBundle(context.Background(), h.e, "", nil); rc != 0 {
		t.Fatalf("rc=%d", rc)
	}
	if got := h.launchctl(); got != "launchctl kickstart "+fetchTarget {
		t.Fatalf("a successful kick must not be followed by a print, got:\n%s", got)
	}

	// The same mid-spawn answer after a FAILED kick is Unknown: still nothing.
	h = newFetchHarness(t)
	fetchKickGOOS = "darwin"
	h.r.rc["kickstart"] = 113
	h.r.stdout["print "+fetchTarget] = spawning
	opFetchBundle(context.Background(), h.e, "", nil)
	if strings.Contains(h.launchctl(), "bootout") || strings.Contains(h.launchctl(), "bootstrap") {
		t.Fatalf("a mid-spawn print must not be acted on:\n%s", h.launchctl())
	}
	if !strings.Contains(h.launchctl(), "print "+fetchTarget) {
		t.Fatalf("a failed kick must lead to a check:\n%s", h.launchctl())
	}

	// A failed kick of a job launchd does not have: bootstrap + kickstart.
	h = newFetchHarness(t)
	fetchKickGOOS = "darwin"
	h.r.rc["kickstart"] = 113
	h.r.rc["print "+fetchTarget] = 113
	opFetchBundle(context.Background(), h.e, "", nil)
	if !strings.Contains(h.launchctl(), "bootstrap system "+h.plist) {
		t.Fatalf("a failed kick of an unloaded job must re-arm it:\n%s", h.launchctl())
	}
}

// Idle-and-refused on the first print, running on a confirming one: left alone.
func TestAJobThatStartsRunningBetweenThePrintsIsLeftAlone(t *testing.T) {
	for _, at := range []int{1, 2} {
		h := newFetchHarness(t)
		answers := []printAnswer{{0, fetchPrint78}, {0, fetchPrint78}, {0, fetchPrint78}}
		answers[at] = printAnswer{0, fetchPrintRunning}
		h.e.Runner = &sequencedRunner{inner: h.r, printAnswers: answers}
		h.e.fetchJobCheck(context.Background(), true)
		if strings.Contains(h.launchctl(), "bootout") || strings.Contains(h.launchctl(), "bootstrap") || strings.Contains(h.launchctl(), "kickstart") {
			t.Fatalf("running on print %d: the job must be left alone:\n%s", at+1, h.launchctl())
		}
		if h.sleeps != at {
			t.Fatalf("expected %d confirming gap(s), got %d", at, h.sleeps)
		}
	}
	// And a refused job that stays refused is re-armed after two gaps.
	h := newFetchHarness(t)
	h.r.stdout["print "+fetchTarget] = fetchPrint78
	h.e.fetchJobCheck(context.Background(), true)
	if h.sleeps != 2 || !strings.Contains(h.launchctl(), "bootout") {
		t.Fatalf("sleeps=%d\n%s", h.sleeps, h.launchctl())
	}
}

func hasLog(logs []string, sub string) bool { return countLogs(logs, sub) > 0 }

func countLogs(logs []string, sub string) int {
	n := 0
	for _, l := range logs {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}
