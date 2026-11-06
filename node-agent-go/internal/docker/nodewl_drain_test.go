// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// The drain contract (docs/reference/node-workloads.md, "The worker's drain"):
// POST drain.path is only "accepted"; GET drain.done_path answering 200 is
// "drained"; timeout_secs bounds both together; and a workload that
// desired-config stops listing is `absent`.

const drainPostP = "/v1/lifecycle/drain"

// runningReady brings the fixture worker to running and ready.
func runningReady(t *testing.T, h *lifeHarness) {
	t.Helper()
	h.door.status("GET", "/health/ready", 200)
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })
}

func lastIndexOf(calls []string, want string) int {
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i] == want {
			return i
		}
	}
	return -1
}

func (h *lifeHarness) release() {
	h.p.Converge(context.Background(), h.provisioned())
}

func (h *lifeHarness) settled() {
	h.t.Helper()
	eventually(h.t, "the release to end", func() bool { return !h.p.lcReleasing("rhaddon", "worker") })
	h.p.Wait()
}

// (a) A 2xx on the drain POST means ACCEPTED, nothing more. With done_path
// answering 409 for the whole timeout the worker is never stopped.
func TestAnAcceptedDrainPostAloneNeverStopsTheWorker(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 202)
	h.door.status("GET", doneP, 409)

	h.release()
	eventually(t, "needs_attention", func() bool { return h.row().State == nodewl.StateNeedsAttention })
	h.settled()

	r := h.row()
	if r.Reason != nodewl.ReasonDrainTimeout || r.Ready {
		t.Fatalf("row = %+v", r)
	}
	calls := h.api.callList()
	if countOf(calls, "stop:") != 0 || countOf(calls, "rm:") != 0 {
		t.Fatalf("a worker whose drain was only accepted was stopped or removed: %v", calls)
	}
	if c := h.api.ctr(wName); c == nil || !c.Running {
		t.Fatalf("the worker is not running: %+v", c)
	}
	if n := countOf(calls, "door:POST "+drainPostP); n != 1 {
		t.Errorf("an accepted drain was POSTed %d times, want once", n)
	}
	if n := countOf(calls, "door:GET "+doneP); n < 2 {
		t.Errorf("done_path was polled %d times, want a poll loop", n)
	}
}

// (b) done_path answering 200 after N polls is the drain's end: stop, remove,
// recreate fresh and stopped. Every kind of "not yet" is just that.
func TestDoneAfterNPollsStopsAndRecreatesTheWorker(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	var polls atomic.Int32
	h.door.set("GET", doneP, func(context.Context) (int, error) {
		switch polls.Add(1) {
		case 1:
			return 409, nil
		case 2:
			return 0, errors.New("connection refused")
		case 3:
			return 503, nil
		}
		return 200, nil
	})

	h.release()
	h.settled()

	if got := polls.Load(); got != 4 {
		t.Fatalf("done_path polled %d times, want 4 (3 not yet, then 200)", got)
	}
	calls := h.api.callList()
	lastGet := -1
	for i, c := range calls {
		if c == "door:GET "+doneP {
			lastGet = i
		}
	}
	stop, rm, create := indexOf(calls, "stop:"+wName), indexOf(calls, "rm:"+wName), lastIndexOf(calls, "create:"+wName)
	if lastGet < 0 || stop < 0 || rm < 0 || create < 0 || !(lastGet < stop && stop < rm && rm < create) {
		t.Fatalf("want the 200 poll < stop < rm < create, got %v", calls)
	}
	if c := h.api.ctr(wName); c == nil || c.Running || c.Status != "created" {
		t.Fatalf("worker after the drain = %+v, want recreated and stopped", c)
	}
	if r := h.row(); r.State != nodewl.StateProvisioned || r.Reason != "" || r.Ready {
		t.Fatalf("row = %+v", r)
	}
}

// (c) A worker that exits during the drain is crashed: nothing is left to
// wait for, nothing is stopped, and it is recreated fresh and stopped.
func TestAWorkerExitingMidDrainIsCrashedThenRecreated(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	var polls atomic.Int32
	h.door.set("GET", doneP, func(context.Context) (int, error) {
		if polls.Add(1) == 2 {
			h.api.setCtr(wName, func(c *ctrInfo) { c.Running, c.Status = false, "exited" })
		}
		return 409, nil
	})
	var (
		mu       sync.Mutex
		atRemove *Row
	)
	h.api.onRemove = func(name string) {
		if name != wName {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if atRemove == nil {
			r := h.row()
			atRemove = &r
		}
	}

	h.release()
	h.settled()

	mu.Lock()
	got := atRemove
	mu.Unlock()
	if got == nil || got.State != nodewl.StateRunning || got.Reason != nodewl.ReasonCrashed || got.Ready {
		t.Fatalf("row when the worker was removed = %+v, want running / crashed", got)
	}
	calls := h.api.callList()
	if countOf(calls, "stop:") != 0 {
		t.Fatalf("a worker that had already exited was stopped: %v", calls)
	}
	if rm := indexOf(calls, "rm:"+wName); rm < 0 || !(rm < lastIndexOf(calls, "create:"+wName)) {
		t.Fatalf("want rm then create, got %v", calls)
	}
	if c := h.api.ctr(wName); c == nil || c.Running || c.Status != "created" {
		t.Fatalf("worker = %+v, want recreated and stopped", c)
	}
	if r := h.row(); r.State != nodewl.StateProvisioned || r.Reason != "" {
		t.Fatalf("row = %+v", r)
	}
}

// (d) The row says `draining` from the accepted POST until done. A POST that
// is refused is sent again and does not make the row draining.
func TestDrainingIsReportedFromTheAcceptedPostUntilDone(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	var (
		mu                 sync.Mutex
		atPost, atPoll     []string
		posts, polls       int
		sawReadyWhileDrain bool
	)
	h.door.set("POST", drainPostP, func(context.Context) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		posts++
		atPost = append(atPost, h.row().State)
		if posts < 3 {
			return 503, nil // not accepted yet: sent again
		}
		return 202, nil
	})
	h.door.set("GET", doneP, func(context.Context) (int, error) {
		r := h.row()
		mu.Lock()
		defer mu.Unlock()
		polls++
		atPoll = append(atPoll, r.State)
		sawReadyWhileDrain = sawReadyWhileDrain || r.Ready
		if polls < 4 {
			return 409, nil
		}
		return 200, nil
	})

	h.release()
	h.settled()

	mu.Lock()
	defer mu.Unlock()
	if posts != 3 {
		t.Fatalf("POSTed %d times, want 3 (two refused, one accepted)", posts)
	}
	for i, s := range atPost {
		if s != nodewl.StateRunning {
			t.Errorf("POST %d saw state %q, want running (not accepted yet)", i+1, s)
		}
	}
	if len(atPoll) != 4 {
		t.Fatalf("polled %d times, want 4", len(atPoll))
	}
	for i, s := range atPoll {
		if s != nodewl.StateDraining {
			t.Errorf("poll %d saw state %q, want draining", i+1, s)
		}
	}
	if sawReadyWhileDrain {
		t.Errorf("a draining workload was reported ready")
	}
	if r := h.row(); r.State != nodewl.StateProvisioned {
		t.Fatalf("row after the drain = %+v", r)
	}
}

// ---- orphans ------------------------------------------------------------

// forgetEverything is an agent restart: the process remembers no workload.
func (h *lifeHarness) forgetEverything() {
	h.p.lc.mu.Lock()
	h.p.lc.lives = nil
	h.p.lc.mu.Unlock()
}

// (e) After a read that succeeded, a workload this agent created that desired
// no longer lists is `absent`: drained first, then everything is removed.
// Found by label, so it works after a restart, and a container the agent did
// not create is never touched.
func TestAnOrphanAfterASuccessfulReadIsDrainedThenRemoved(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	h.api.mu.Lock()
	h.api.ctrs["someone-elses"] = &ctrInfo{ID: "x", Labels: map[string]string{"app": "mine"}, Running: true, Status: "running"}
	h.api.mu.Unlock()
	h.forgetEverything()

	h.p.ReleaseOrphans(context.Background(), map[string]bool{})
	h.p.Wait()

	calls := h.api.callList()
	drain, done, stop := indexOf(calls, "door:POST "+drainPostP), indexOf(calls, "door:GET "+doneP), indexOf(calls, "stop:"+wName)
	rmW, rmD := indexOf(calls, "rm:"+wName), indexOf(calls, "rm:"+dName)
	if drain < 0 || done < 0 || stop < 0 || rmW < 0 || rmD < 0 || !(drain < done && done < stop && stop < rmW) {
		t.Fatalf("want drain < done < stop < rm, got %v", calls)
	}
	if h.api.ctr(wName) != nil || h.api.ctr(dName) != nil {
		t.Errorf("the orphan's containers remain")
	}
	if _, there := h.api.nets[WorkloadNetworkName("rhaddon", "worker")]; there {
		t.Errorf("the orphan's network remains")
	}
	if h.api.ctr("someone-elses") == nil || countOf(calls, "rm:someone-elses") != 0 {
		t.Errorf("a container the agent did not create was touched: %v", calls)
	}
	if n := countOf(calls, "create:"); n != 2 {
		t.Errorf("an orphan was recreated (%d creates): %v", n, calls)
	}
}

func TestAListedWorkloadIsNotAnOrphan(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.forgetEverything()
	before := h.api.callList()
	h.p.ReleaseOrphans(context.Background(), map[string]bool{"rhaddon/worker": true})
	h.p.Wait()
	if got := h.api.callList(); len(got) != len(before) {
		t.Fatalf("a listed workload was touched: %v -> %v", before, got)
	}
}

func TestAnOrphanThatIsNotRunningIsRemovedWithoutADrain(t *testing.T) {
	h := newLife(t)
	h.p.Converge(context.Background(), h.provisioned())
	h.forgetEverything()
	h.p.ReleaseOrphans(context.Background(), map[string]bool{})
	h.p.Wait()
	if h.api.ctr(wName) != nil || h.api.ctr(dName) != nil {
		t.Fatalf("the orphan remains")
	}
	if countOf(h.api.callList(), "door:") != 0 {
		t.Fatalf("a stopped orphan was sent a drain: %v", h.api.callList())
	}
}

// An orphan whose drain does not finish is left running and stays reported.
func TestAnOrphanThatCannotDrainStaysAndIsReported(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 409)
	h.forgetEverything()

	h.p.ReleaseOrphans(context.Background(), map[string]bool{})
	h.settled()
	h.p.Retain(map[string]bool{}) // the pass's next step must not drop the report

	if c := h.api.ctr(wName); c == nil || !c.Running {
		t.Fatalf("an undrained orphan was stopped: %+v", c)
	}
	if countOf(h.api.callList(), "stop:") != 0 || countOf(h.api.callList(), "rm:") != 0 {
		t.Fatalf("an undrained orphan was touched: %v", h.api.callList())
	}
	if r := h.row(); r.State != nodewl.StateNeedsAttention || r.Reason != nodewl.ReasonDrainTimeout {
		t.Fatalf("row = %+v", r)
	}
}

// A worker with no drain config known (no memory, no labels) cannot be
// drained, so it is never stopped.
func TestAnOrphanWithNoKnownDrainIsNeverStopped(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	h.api.setCtr(wName, func(c *ctrInfo) {
		delete(c.Labels, LabelDrainPath)
		delete(c.Labels, LabelDrainDone)
		delete(c.Labels, LabelDrainTimeout)
	})
	h.forgetEverything()
	h.p.ReleaseOrphans(context.Background(), map[string]bool{})
	h.settled()
	if countOf(h.api.callList(), "stop:") != 0 || countOf(h.api.callList(), "rm:") != 0 {
		t.Fatalf("a worker with no drain config was stopped: %v", h.api.callList())
	}
}

// (f) A list of the node that fails removes nothing. (The reconciler never
// reaches ReleaseOrphans after a failed or unparseable desired-config read:
// see internal/reconcile.)
func TestAFailedListOfTheNodeRemovesNothing(t *testing.T) {
	h := newLife(t)
	runningReady(t, h)
	h.door.status("POST", drainPostP, 200)
	h.door.status("GET", doneP, 200)
	h.forgetEverything()
	h.api.listErr = errors.New("docker daemon unreachable")
	before := h.api.callList()
	h.p.ReleaseOrphans(context.Background(), map[string]bool{})
	h.p.Wait()
	if got := h.api.callList(); len(got) != len(before) {
		t.Fatalf("a failed list moved the node: %v -> %v", before, got)
	}
	if c := h.api.ctr(wName); c == nil || !c.Running {
		t.Fatalf("worker = %+v", c)
	}
}
