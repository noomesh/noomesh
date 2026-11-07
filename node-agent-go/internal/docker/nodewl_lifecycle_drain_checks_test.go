// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// More single-check tests of the release and the drain (see
// nodewl_lifecycle_checks_test.go).

func (h *lifeHarness) assertWorkerUntouched(what string) {
	h.t.Helper()
	if c := h.api.ctr(wName); c == nil || !c.Running {
		h.t.Fatalf("%s: the worker is %+v", what, c)
	}
	if countOf(h.api.callList(), "stop:") != 0 || countOf(h.api.callList(), "rm:") != 0 {
		h.t.Fatalf("%s: the worker was stopped or removed: %v", what, h.api.callList())
	}
}

// Only a 200 from done_path is "drained".
func TestADrainIsOnlyDoneOnAnExact200(t *testing.T) {
	for _, code := range []int{202, 204} {
		h := newLife(t)
		runningReady(t, h)
		h.door.status("POST", drainPostP, 200)
		h.door.status("GET", doneP, code)
		h.release()
		h.settled()
		h.assertWorkerUntouched("done_path answered a 2xx that is not 200")
		if r := h.row(); r.State != nodewl.StateNeedsAttention || r.Reason != nodewl.ReasonDrainTimeout {
			t.Fatalf("HTTP %d: row = %+v", code, r)
		}
	}
}

// The drain POST is accepted only by a 2xx; a 1xx is not a final answer, so it
// is sent again and done_path is not asked.
func TestADrainPostAnsweredBelow200IsNotAccepted(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 199)
	h.door.status("GET", doneP, 200)
	h.release()
	h.settled()
	if n := countOf(h.api.callList(), "door:GET "+doneP); n != 0 {
		t.Fatalf("done_path was asked %d times although the POST was never accepted", n)
	}
	h.assertWorkerUntouched("a POST that was not accepted")
}

// Without a poll interval of its own the drain polls at drainPollEvery (2 s):
// a one second window holds one poll, not a thousand.
func TestTheDrainPollsAtItsDefaultPace(t *testing.T) {
	if drainPollEvery != 2*time.Second {
		t.Fatalf("drainPollEvery = %v; the contract polls every 2 s", drainPollEvery)
	}
	h := newLife(t)
	runningReady(t, h)
	h.p.lc.pollDrain = 0
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 409)
	h.release()
	h.settled()
	if n := countOf(h.api.callList(), "door:GET "+doneP); n < 1 || n > 3 {
		t.Fatalf("done_path polled %d times in a 1 s window at the default pace, want 1", n)
	}
}

// drain.timeout_secs bounds the POST and the polling together: a POST that
// takes most of the window leaves only the rest for the polling.
func TestTheDrainTimeoutBoundsThePostAndThePollingTogether(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	started := time.Now()
	h.door.set("POST", drainPostP, func(context.Context) (int, error) {
		if time.Since(started) < 700*time.Millisecond {
			return 409, nil
		}
		return 200, nil
	})
	h.door.status("GET", doneP, 409)
	started = time.Now()
	h.release()
	h.settled()
	if took := time.Since(started); took > 1350*time.Millisecond {
		t.Fatalf("a 1 s drain took %v: the timeout started over when the POST was accepted", took)
	}
	h.assertWorkerUntouched("a drain that did not finish")
}

// A worker that is no longer ours is not drained: nothing is sent to it.
func TestADrainEndsAtOnceWhenTheWorkerIsNoLongerOurs(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	h.api.setCtr(wName, func(c *ctrInfo) { delete(c.Labels, LabelManagedBy) })
	before := countOf(h.api.callList(), "door:")
	if err := h.p.drain(context.Background(), h.provisioned()); !errors.Is(err, errWorkerExited) {
		t.Fatalf("drain = %v, want errWorkerExited", err)
	}
	if got := countOf(h.api.callList(), "door:"); got != before {
		t.Fatalf("a container that is not ours was sent %d drain calls", got-before)
	}
}

// ---- release: each step stops where it fails ----------------------------------

func TestReleaseDoesNotRecreateWhenTheGateNowRefuses(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	creates := countOf(h.api.callList(), "create:")
	h.p.SetAdmit(func(context.Context, nodewl.Entry) error {
		return &nodewl.Error{Code: nodewl.ReasonConsentNone, Detail: "the owner changed the policy"}
	})
	h.release()
	h.settled()
	calls := h.api.callList()
	if indexOf(calls, "stop:"+wName) < 0 || indexOf(calls, "rm:"+wName) < 0 {
		t.Fatalf("the worker was drained and should be gone: %v", calls)
	}
	if got := countOf(calls, "create:"); got != creates {
		t.Fatalf("recreated although the gate refuses (%d -> %d creates)", creates, got)
	}
	if r := h.row(); r.State != nodewl.StateAbsent || r.Reason != nodewl.ReasonConsentNone {
		t.Fatalf("row = %+v", r)
	}
}

func TestReleaseReportsAFailedRecreateNotAProvisionedWorkload(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	cp := h.chaos()
	cp.createErr = errDaemon
	err := h.p.StopManaged(context.Background(), h.provisioned())
	if err == nil {
		t.Fatal("StopManaged reported success although the workload could not be recreated")
	}
	if r := h.row(); r.State == nodewl.StateProvisioned {
		t.Fatalf("row = %+v: nothing was provisioned", r)
	}
}

func TestReleaseRemovesNothingWhenTheWorkerWillNotStop(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	cp := h.chaos()
	cp.stopErr = errDaemon
	if err := h.p.StopManaged(context.Background(), h.provisioned()); err == nil {
		t.Fatal("StopManaged reported success although the worker did not stop")
	}
	if countOf(h.api.callList(), "rm:") != 0 {
		t.Fatalf("a running worker was removed after its stop failed: %v", h.api.callList())
	}
}

func TestReleaseDoesNotRecreateOverAWorkerItCouldNotRemove(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	cp := h.chaos()
	cp.removeErr = errDaemon
	creates := countOf(h.api.callList(), "create:")
	if err := h.p.StopManaged(context.Background(), h.provisioned()); err == nil {
		t.Fatal("StopManaged reported success although the worker was not removed")
	}
	if got := countOf(h.api.callList(), "create:"); got != creates {
		t.Fatalf("recreated over a worker that is still there (%d -> %d)", creates, got)
	}
	// The worker is still on the node, so the row must not say it is gone.
	if r := h.row(); r.State == nodewl.StateAbsent || r.State == nodewl.StateProvisioned {
		t.Fatalf("row = %+v: the containers are still there", r)
	}
}

func TestReleaseOfAnUnreadableNodeDrainsStopsAndRemovesNothing(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	cp := h.chaos()
	cp.inspectFail = func(string, int) error { return errDaemon }
	before := len(h.api.callList())
	if err := h.p.StopManaged(context.Background(), h.provisioned()); err == nil {
		t.Fatal("StopManaged reported success on a node it could not read")
	}
	for _, c := range h.api.callList()[before:] {
		if changesTheNode(c) {
			t.Fatalf("a worker was released although the daemon could not say what runs: %v", h.api.callList()[before:])
		}
	}
}

// The worker is not ready from the moment its release starts, not only from
// the moment the drain is accepted.
func TestAWorkloadBeingReleasedIsNotReadyEvenBeforeTheDrainIsAccepted(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 409) // never accepted
	h.door.status("GET", doneP, 200)
	h.release()
	eventually(t, "the release to start", func() bool { return h.p.lcReleasing("rhaddon", "worker") })
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if r := h.row(); r.Ready && h.p.lcReleasing("rhaddon", "worker") {
			t.Fatalf("a workload being released is reported ready: %+v", r)
		}
		time.Sleep(time.Millisecond)
	}
	h.settled()
}

// A second release of the same workload does not start while one is running.
func TestOnlyOneReleaseOfAWorkloadRunsAtATime(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	gate := make(chan struct{})
	var mu sync.Mutex
	posts := 0
	h.door.set("POST", drainPostP, func(ctx context.Context) (int, error) {
		mu.Lock()
		posts++
		mu.Unlock()
		select {
		case <-gate:
			return 200, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	h.door.status("GET", doneP, 200)
	first := make(chan error, 1)
	go func() { first <- h.p.StopManaged(context.Background(), h.provisioned()) }()
	eventually(t, "the first release to be in its drain", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return posts == 1
	})
	second := make(chan error, 1)
	go func() { second <- h.p.StopManaged(context.Background(), h.provisioned()) }()
	select {
	case err := <-second:
		if !errors.Is(err, errReleaseBusy) {
			t.Fatalf("second release = %v, want errReleaseBusy", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("a second release of the same workload started while one was in flight")
	}
	close(gate)
	if err := <-first; err != nil {
		t.Fatalf("first release: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 {
		t.Fatalf("the worker was sent %d drain POSTs", posts)
	}
}

// A converge during the last steps of a release (the worker stopped, being
// removed) leaves the release to finish: the gate is not asked, nothing is
// reported against the row.
func TestAConvergeDuringAReleaseDoesNotTouchTheRow(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	var once sync.Once
	var reasonDuring string
	h.api.onRemove = func(name string) {
		if name != wName {
			return
		}
		once.Do(func() {
			h.p.SetAdmit(func(context.Context, nodewl.Entry) error {
				return &nodewl.Error{Code: nodewl.ReasonConsentNone, Detail: "x"}
			})
			h.p.Converge(context.Background(), h.provisioned())
			reasonDuring = h.row().Reason
			h.p.SetAdmit(func(context.Context, nodewl.Entry) error { return nil })
		})
	}
	h.release()
	h.settled()
	if reasonDuring != "" {
		t.Fatalf("a converge in the middle of a release reported %q against the row", reasonDuring)
	}
	if r := h.row(); r.State != nodewl.StateProvisioned || r.Reason != "" {
		t.Fatalf("row after the release = %+v", r)
	}
}

// A desired `provisioned` whose spec equals what is already running (the same
// reservation) still releases the worker: it is drained and stopped, not left
// running under a row that says provisioned.
func TestProvisionedWithTheSameSpecStillReleasesARunningWorker(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	same := h.running()
	same.State = nodewl.StateProvisioned // reservation kept: the spec hash is the running one
	h.p.Converge(context.Background(), same)
	h.settled()
	calls := h.api.callList()
	if indexOf(calls, "door:POST "+drainPostP) < 0 || indexOf(calls, "stop:"+wName) < 0 {
		t.Fatalf("a running worker was not released: %v", calls)
	}
	if c := h.api.ctr(wName); c == nil || c.Running {
		t.Fatalf("worker = %+v, want recreated and stopped", c)
	}
}

// ---- running: the start sequence ----------------------------------------------

func TestARefusalIsClearedWhenTheWorkloadStarts(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 503) // never ready, so only the start can clear the reason
	h.p.SetAdmit(func(context.Context, nodewl.Entry) error {
		return &nodewl.Error{Code: nodewl.ReasonConsentNone, Detail: "policy is none"}
	})
	h.p.Converge(context.Background(), h.running()) // a refusal starts nothing, so there is nothing to wait for
	if r := h.row(); r.Reason != nodewl.ReasonConsentNone || countOf(h.api.callList(), "start:") != 0 {
		t.Fatalf("row = %+v, calls %v", r, h.api.callList())
	}
	h.p.SetAdmit(func(context.Context, nodewl.Entry) error { return nil })
	h.p.Converge(context.Background(), h.running())
	eventually(t, "running with no reason", func() bool { r := h.row(); return r.State == nodewl.StateRunning && r.Reason == "" })
	if r := h.row(); r.Ready {
		t.Fatalf("row = %+v: the door answers 503", r)
	}
}

func TestARunningDoorIsNotStartedAgain(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	h.p.Converge(context.Background(), h.provisioned())
	h.api.setCtr(dName, func(c *ctrInfo) { c.Running, c.Status = true, "running" })
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })
	calls := h.api.callList()
	if countOf(calls, "start:"+dName) != 0 || countOf(calls, "start:"+wName) != 1 {
		t.Fatalf("a running door must be left alone and the worker started once: %v", calls)
	}
}

func TestADoorThatHasExitedKeepsTheWorkerFromStarting(t *testing.T) {
	h := newLife(t)
	same := h.running()
	same.State = nodewl.StateProvisioned // provisioned to the running spec, so a running pass changes nothing
	h.p.Converge(context.Background(), same)
	h.api.setCtr(dName, func(c *ctrInfo) { c.Running, c.Status = false, "exited" })
	h.p.Converge(context.Background(), h.running())
	if countOf(h.api.callList(), "start:") != 0 {
		t.Fatalf("a worker was started behind a door that is down: %v", h.api.callList())
	}
	if r := h.row(); r.Reason != nodewl.ReasonCrashed {
		t.Fatalf("row = %+v, want crashed", r)
	}
}

// ---- rows -------------------------------------------------------------------

func TestARowIsNotReadyUnlessItIsRunning(t *testing.T) {
	var p NodeWorkloads
	p.with("rhaddon", "worker", func(ls *lifeState) { ls.state, ls.ready = nodewl.StateProvisioned, true })
	if rows := p.Rows(); len(rows) != 1 || rows[0].Ready {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestARowMidReleaseSurvivesRetain(t *testing.T) {
	var p NodeWorkloads
	p.with("rhaddon", "worker", func(ls *lifeState) { ls.state, ls.releasing = nodewl.StateRunning, true })
	p.with("rhaddon", "other", func(ls *lifeState) { ls.state = nodewl.StateProvisioned })
	p.Retain(map[string]bool{})
	rows := p.Rows()
	if len(rows) != 1 || rows[0].Name != "worker" {
		t.Fatalf("rows = %+v; the release in flight must stay reported, the idle row goes", rows)
	}
}

// removeWorkload holds the workload's provisioning lock while it tears down.
func TestRemoveWorkloadWaitsForTheWorkloadLock(t *testing.T) {
	h := newLife(t)
	h.p.Converge(context.Background(), h.provisioned())
	unlock := h.p.lock("rhaddon", "worker")
	done := make(chan error, 1)
	go func() { done <- h.p.removeWorkload(context.Background(), h.provisioned()) }()
	select {
	case <-done:
		t.Fatal("removeWorkload ran while another operation held the workload's lock")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("removeWorkload did not run once the lock was free")
	}
}
