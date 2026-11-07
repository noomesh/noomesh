// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// Single-check tests of the readiness watch, the actuator entry points and the
// small state helpers (see nodewl_lifecycle_checks_test.go).

const readyP = "/health/ready"

// quiesce ends the readiness watchers and waits for everything the lifecycle
// started. A test that wants "nothing was started" must not wait for a watcher
// that a wrong start would have left running forever.
func (h *lifeHarness) quiesce() {
	h.p.Close()
	h.p.Wait()
}

// settledQuietly is settled for a test that told the lifecycle `running` again
// in the middle of a release: a watcher that wrongly survives the release would
// keep that test waiting forever, so the watchers are ended rather than awaited.
func (h *lifeHarness) settledQuietly() {
	h.t.Helper()
	eventually(h.t, "the release to end", func() bool { return !h.p.lcReleasing("rhaddon", "worker") })
	h.quiesce()
}

func probes(h *lifeHarness) int { return countOf(h.api.callList(), "door:GET "+readyP) }

// stillFor fails if f keeps changing over d.
func stable(t *testing.T, what string, f func() int) {
	t.Helper()
	time.Sleep(40 * time.Millisecond) // let a loop that should end, end
	before := f()
	time.Sleep(60 * time.Millisecond)
	if after := f(); after != before {
		t.Fatalf("%s: %d -> %d", what, before, after)
	}
}

// Once ready the watch polls at the slow pace.
func TestTheWatchPollsSlowlyOnceReady(t *testing.T) {
	h := newLife(t)
	h.p.lc.pollSlow = 200 * time.Millisecond
	h.door.status("GET", readyP, 200)
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })
	before := probes(h)
	time.Sleep(300 * time.Millisecond)
	if got := probes(h) - before; got > 4 {
		t.Fatalf("%d probes in 300 ms at a 200 ms slow pace", got)
	}
}

func TestTheWatchEndsWhenTheWorkerIsNotOurs(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", readyP, 200)
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })
	h.api.setCtr(wName, func(c *ctrInfo) { delete(c.Labels, LabelManagedBy) })
	stable(t, "probes of a container that is not ours", func() int { return probes(h) })
}

func TestTheWatchEndsWhenAReleaseStarts(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 409)
	h.release()
	eventually(t, "the drain", func() bool { return h.row().State == nodewl.StateDraining })
	stable(t, "readiness probes during a drain", func() int { return probes(h) })
	h.settled()
}

// A worker still inside start_secs has no start_timeout, however long the
// probes have been failing.
func TestAWorkerInsideStartSecsHasNoTimeout(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", readyP, 503)
	e := h.running()
	e.StartSecs = 5
	h.p.Converge(context.Background(), e)
	eventually(t, "several probes", func() bool { return probes(h) >= 6 })
	if r := h.row(); r.Reason != "" || r.Ready {
		t.Fatalf("row = %+v: 5 s have not passed", r)
	}
}

// A start time the daemon did not report cannot be measured against.
func TestAnUnknownStartTimeNeverTimesOut(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", readyP, 503)
	e := h.running()
	e.StartSecs = 5
	h.p.Converge(context.Background(), e)
	h.api.setCtr(wName, func(c *ctrInfo) { c.StartedAt = time.Time{} })
	h.clock.advance(time.Hour)
	before := probes(h)
	eventually(t, "more probes", func() bool { return probes(h) >= before+6 })
	if r := h.row(); r.Reason != "" {
		t.Fatalf("row = %+v: a worker with no known start time timed out", r)
	}
}

// One watcher per workload, however often the start path is entered.
func TestOnlyOneWatcherRunsPerWorkload(t *testing.T) {
	h := newLife(t)
	var cur, max atomic.Int32
	h.p.lc.doorCall = func(context.Context, string, string, string, string) (int, error) {
		n := cur.Add(1)
		for {
			m := max.Load()
			if n <= m || max.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		cur.Add(-1)
		return 503, nil
	}
	e := h.running()
	h.p.Converge(context.Background(), e)
	eventually(t, "a probe", func() bool { return max.Load() >= 1 })
	h.p.goWatch(context.Background(), e)
	h.p.goWatch(context.Background(), e)
	time.Sleep(120 * time.Millisecond)
	if got := max.Load(); got != 1 {
		t.Fatalf("%d probes ran at once: more than one watcher for a workload", got)
	}
}

// ---- state helpers ---------------------------------------------------------

func TestLeavingRunningClearsReady(t *testing.T) {
	var p NodeWorkloads
	e := nodewl.Entry{Addon: "rhaddon", Name: "worker"}
	p.with("rhaddon", "worker", func(ls *lifeState) { ls.state, ls.ready = nodewl.StateRunning, true })
	p.setState(e, nodewl.StateRunning, "")
	if cur, _ := p.read("rhaddon", "worker"); !cur.ready {
		t.Fatal("a state that is still running lost its readiness")
	}
	p.setState(e, nodewl.StateProvisioned, "")
	if cur, _ := p.read("rhaddon", "worker"); cur.ready {
		t.Fatal("a workload that is no longer running is still ready")
	}
}

func TestRowsAreSortedByAddonThenName(t *testing.T) {
	var p NodeWorkloads
	for _, k := range [][2]string{{"zeta", "a"}, {"alpha", "z"}, {"alpha", "b"}, {"mid", "m"}, {"beta", "c"}, {"alpha", "a"}, {"zeta", "0"}} {
		p.with(k[0], k[1], func(ls *lifeState) { ls.state = nodewl.StateProvisioned })
	}
	var got []string
	for _, r := range p.Rows() {
		got = append(got, r.Addon+"/"+r.Name)
	}
	want := "alpha/a alpha/b alpha/z beta/c mid/m zeta/0 zeta/a"
	if strings.Join(got, " ") != want {
		t.Fatalf("rows = %v, want %s", got, want)
	}
}

func TestExitedMeansExitedOrDeadAndNothingElse(t *testing.T) {
	for status, want := range map[string]bool{"exited": true, "dead": true, "created": false, "running": false, "paused": false, "restarting": false, "removing": false, "": false} {
		if got := exited(&ctrInfo{Status: status}); got != want {
			t.Errorf("exited(%q) = %v, want %v", status, got, want)
		}
	}
	if exited(nil) {
		t.Error("exited(nil)")
	}
}

// ---- the actuator's entry points ----------------------------------------------

func TestStartManagedStopsWhereItCannotReadTheNode(t *testing.T) {
	h := newLife(t)
	cp := h.chaos()
	cp.inspectFail = func(_ string, n int) error {
		if n == 1 {
			return errDaemon
		}
		return nil
	}
	if err := h.p.StartManaged(context.Background(), h.running()); !errors.Is(err, errDaemon) {
		t.Fatalf("StartManaged = %v, want the read error", err)
	}
	h.noMutation("the node could not be read")
}

func TestStartManagedRefusesWhileAReleaseIsInFlight(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 409)
	h.release()
	eventually(t, "the drain", func() bool { return h.row().State == nodewl.StateDraining })
	if err := h.p.StartManaged(context.Background(), h.running()); !errors.Is(err, errReleaseBusy) {
		t.Fatalf("StartManaged = %v, want errReleaseBusy", err)
	}
	h.settledQuietly()
}

func TestAConvergeToRunningDoesNotUndoARelease(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 409)
	h.release()
	eventually(t, "the drain", func() bool { return h.row().State == nodewl.StateDraining })
	h.p.Converge(context.Background(), h.running())
	if r := h.row(); r.State != nodewl.StateDraining {
		t.Fatalf("a running pass in the middle of a drain left the row %+v", r)
	}
	h.settledQuietly()
}

func TestStartManagedReportsTheGateRefusalOnTheRow(t *testing.T) {
	h := newLife(t)
	h.p.SetAdmit(func(context.Context, nodewl.Entry) error {
		return &nodewl.Error{Code: nodewl.ReasonConsentUnapproved, Detail: "not approved"}
	})
	if err := h.p.StartManaged(context.Background(), h.running()); nodewl.CodeOf(err) != nodewl.ReasonConsentUnapproved {
		t.Fatalf("StartManaged = %v", err)
	}
	if r := h.row(); r.Reason != nodewl.ReasonConsentUnapproved {
		t.Fatalf("row = %+v; the refusal must show in the heartbeat too", r)
	}
}

func TestStartManagedReturnsTheProvisionFailureItself(t *testing.T) {
	h := newLife(t)
	cp := h.chaos()
	cp.createErr = errDaemon
	err := h.p.StartManaged(context.Background(), h.running())
	if !errors.Is(err, errDaemon) && !strings.Contains(err.Error(), errDaemon.Error()) {
		t.Fatalf("StartManaged = %v, want the provisioning error", err)
	}
	if countOf(h.api.callList(), "start:") != 0 {
		t.Fatalf("something was started after provisioning failed: %v", h.api.callList())
	}
}

// StopManaged on an `absent` entry removes the whole workload; on
// `provisioned` it recreates it stopped.
func TestStopManagedOfAnAbsentEntryRemovesEverything(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	creates := countOf(h.api.callList(), "create:")
	e := h.running()
	e.State, e.Reservation = nodewl.StateAbsent, nil
	if err := h.p.StopManaged(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if h.api.ctr(wName) != nil || h.api.ctr(dName) != nil {
		t.Fatal("the workload's containers remain")
	}
	if got := countOf(h.api.callList(), "create:"); got != creates {
		t.Fatalf("an absent workload was recreated (%d -> %d creates)", creates, got)
	}
	if r := h.row(); r.State != nodewl.StateAbsent {
		t.Fatalf("row = %+v", r)
	}
}
