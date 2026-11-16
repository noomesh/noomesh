// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// ---- fakes: the door and the clock -------------------------------------

const testReservation = "0b1f5f0e-6a3e-4a54-9d3c-0a4e5b9c7d21"

// fakeDoor answers the agent's calls through the door. Every call is also
// logged into the fake daemon's call list, so tests can assert the ORDER of a
// door call against a docker call (the drain POST against the stop).
type fakeDoor struct {
	mu     sync.Mutex
	api    *fakeProv
	routes map[string]func(ctx context.Context) (int, error)
}

func (d *fakeDoor) set(method, path string, f func(ctx context.Context) (int, error)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.routes[method+" "+path] = f
}

func (d *fakeDoor) status(method, path string, code int) {
	d.set(method, path, func(context.Context) (int, error) { return code, nil })
}

func (d *fakeDoor) call(ctx context.Context, addr, serverName, method, path string) (int, error) {
	d.api.mu.Lock()
	d.api.calls = append(d.api.calls, "door:"+method+" "+path)
	d.api.mu.Unlock()
	if serverName != "noo-stunnel-rhaddon-worker" || !strings.HasSuffix(addr, ":8443") {
		return 0, errors.New("dialled the wrong door: " + addr + " as " + serverName)
	}
	d.mu.Lock()
	f := d.routes[method+" "+path]
	d.mu.Unlock()
	if f == nil {
		return http.StatusNotFound, nil
	}
	return f(ctx)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type lifeHarness struct {
	*harness
	door  *fakeDoor
	clock *fakeClock
}

func newLife(t *testing.T) *lifeHarness {
	t.Helper()
	h := newHarness(t)
	clk := &fakeClock{t: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	d := &fakeDoor{api: h.api, routes: map[string]func(context.Context) (int, error){}}
	h.api.clock = clk.now
	h.p.lc.doorCall = d.call
	h.p.lc.now = clk.now
	h.p.lc.pollFast, h.p.lc.pollSlow = time.Millisecond, 2*time.Millisecond
	h.p.lc.pollDrain = time.Millisecond
	h.entry.Drain.TimeoutSecs = 1 // a drain that must fail really waits this out
	h.p.SetAdmit(func(context.Context, nodewl.Entry) error { return nil })
	t.Cleanup(func() { h.p.Close(); h.p.Wait() })
	return &lifeHarness{harness: h, door: d, clock: clk}
}

func (h *lifeHarness) running() nodewl.Entry {
	e := h.entry
	r := testReservation
	e.Reservation = &r
	e.State = nodewl.StateRunning
	return e
}

func (h *lifeHarness) provisioned() nodewl.Entry {
	e := h.entry
	e.Reservation = nil
	e.State = nodewl.StateProvisioned
	return e
}

func (h *lifeHarness) row() Row {
	h.t.Helper()
	for _, r := range h.p.Rows() {
		if r.Addon == "rhaddon" && r.Name == "worker" {
			return r
		}
	}
	h.t.Fatalf("no row for rhaddon/worker in %v", h.p.Rows())
	return Row{}
}

func (p *NodeWorkloads) lcReleasing(addon, name string) bool {
	cur, _ := p.read(addon, name)
	return cur.releasing
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func indexOf(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

func countOf(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

const (
	doneP = "/v1/lifecycle/drain/done" // the fixture's drain.done_path
	wName = "noo-wl-rhaddon-worker"
	dName = "noo-stunnel-rhaddon-worker"
)

// ---- running -----------------------------------------------------------

func TestRunningProvisionsStartsTheSidecarThenTheWorkerAndWaitsForReady(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 503)
	h.p.Converge(context.Background(), h.running())

	calls := h.api.callList()
	if i, j := indexOf(calls, "start:"+dName), indexOf(calls, "start:"+wName); i < 0 || j < 0 || i > j {
		t.Fatalf("the sidecar must start before the worker: %v", calls)
	}
	r := h.row()
	if r.State != nodewl.StateRunning || r.Ready || r.Reason != "" {
		t.Fatalf("before ready: %+v", r)
	}
	h.door.status("GET", "/health/ready", 200)
	eventually(t, "ready", func() bool { return h.row().Ready })
	r = h.row()
	want := Row{Addon: "rhaddon", Name: "worker", State: "running", Ready: true, Model: "rh-s2s-7b", DoorPort: 8443, Reservation: testReservation}
	if r != want {
		t.Fatalf("row = %+v, want %+v", r, want)
	}
}

func TestOnlyA200IsReady(t *testing.T) {
	h := newLife(t)
	for _, code := range []int{204, 301, 500, 503} {
		h.door.status("GET", "/health/ready", code)
		if h.p.probeReady(context.Background(), mustRunning(h)) {
			t.Errorf("HTTP %d counted as ready", code)
		}
	}
}

func mustRunning(h *lifeHarness) nodewl.Entry {
	e := h.running()
	if err := h.p.Provision(context.Background(), e); err != nil {
		h.t.Fatal(err)
	}
	return e
}

func TestStartTimeoutLeavesTheWorkerRunningAndReported(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 503)
	e := h.running()
	e.StartSecs = 5
	h.p.Converge(context.Background(), e)
	if r := h.row(); r.Reason != "" {
		t.Fatalf("a worker still inside start_secs has no reason: %+v", r)
	}
	h.clock.advance(6 * time.Second)
	eventually(t, "start_timeout", func() bool { return h.row().Reason == nodewl.ReasonStartTimeout })
	r := h.row()
	if r.State != nodewl.StateRunning || r.Ready {
		t.Fatalf("row = %+v", r)
	}
	if got := h.api.callList(); countOf(got, "stop:") != 0 || countOf(got, "rm:") != 0 {
		t.Fatalf("a worker that missed start_secs was touched: %v", got)
	}
	// It may still come up; the reason then clears.
	h.door.status("GET", "/health/ready", 200)
	eventually(t, "ready after timeout", func() bool { r := h.row(); return r.Ready && r.Reason == "" })
}

func TestACrashedWorkerIsReportedAndNotRestarted(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	e := h.running()
	h.p.Converge(context.Background(), e)
	eventually(t, "ready", func() bool { return h.row().Ready })

	h.api.setCtr(wName, func(c *ctrInfo) { c.Running, c.Status = false, "exited" })
	eventually(t, "crashed", func() bool { return h.row().Reason == nodewl.ReasonCrashed })
	if r := h.row(); r.State != nodewl.StateRunning || r.Ready {
		t.Fatalf("row = %+v", r)
	}
	h.p.Wait()
	starts := countOf(h.api.callList(), "start:"+wName)
	// Further passes with the same desired state do not restart it.
	for i := 0; i < 3; i++ {
		h.p.Converge(context.Background(), e)
	}
	h.p.Wait()
	if got := countOf(h.api.callList(), "start:"+wName); got != starts || starts != 1 {
		t.Fatalf("worker started %d times (was %d): a crash must not restart in a loop", got, starts)
	}
	if r := h.row(); r.Reason != nodewl.ReasonCrashed {
		t.Fatalf("row = %+v", r)
	}
}

// ---- release -----------------------------------------------------------

func TestReleaseDrainsThenStopsThenRecreatesFreshAndStopped(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	h.door.status("POST", "/v1/lifecycle/drain", 200)
	h.door.status("GET", doneP, 200)
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })

	h.api.mu.Lock()
	h.api.calls = nil
	h.api.mu.Unlock()
	h.p.Converge(context.Background(), h.provisioned())
	eventually(t, "provisioned", func() bool {
		r := h.row()
		return r.State == nodewl.StateProvisioned && !h.p.lcReleasing("rhaddon", "worker")
	})
	h.p.Wait()

	calls := h.api.callList()
	drain, stop, rm, create := indexOf(calls, "door:POST /v1/lifecycle/drain"), indexOf(calls, "stop:"+wName), indexOf(calls, "rm:"+wName), indexOf(calls, "create:"+wName)
	if drain < 0 || stop < 0 || rm < 0 || create < 0 || !(drain < stop && stop < rm && rm < create) {
		t.Fatalf("want drain < stop < rm < create, got %v", calls)
	}
	// Fresh: the create call above came after the remove.
	if c := h.api.ctr(wName); c == nil || c.Running || c.Status != "created" {
		t.Fatalf("worker after release = %+v, want created and stopped", c)
	}
	if _, ok := h.api.created[wName].Config.Labels["noo.reservation"]; ok {
		t.Errorf("a released workload still carries a reservation label")
	}
	if r := h.row(); r.State != nodewl.StateProvisioned || r.Ready || r.Reservation != "" || r.Reason != "" {
		t.Fatalf("row = %+v", r)
	}
	if h.api.volumes == 0 {
		t.Errorf("scratch was not removed")
	}
}

// A drain that does not finish must never stop the worker. Each way a drain
// can fail to finish is a case.
func TestDrainThatDoesNotFinishNeverStopsTheWorker(t *testing.T) {
	cases := map[string]func(ctx context.Context) (int, error){
		"timeout":      func(ctx context.Context) (int, error) { <-ctx.Done(); return 0, ctx.Err() },
		"refused":      func(context.Context) (int, error) { return 0, errors.New("connection refused") },
		"server error": func(context.Context) (int, error) { return 503, nil },
		"rejected":     func(context.Context) (int, error) { return 404, nil },
	}
	for name, drain := range cases {
		t.Run(name, func(t *testing.T) {
			h := newLife(t)
			h.door.status("GET", "/health/ready", 200)
			h.door.set("POST", "/v1/lifecycle/drain", drain)
			h.p.Converge(context.Background(), h.running())
			eventually(t, "ready", func() bool { return h.row().Ready })

			rel := h.provisioned()
			rel.Drain.TimeoutSecs = 1 // the "timeout" case really waits this out
			h.p.Converge(context.Background(), rel)
			eventually(t, "needs_attention", func() bool { return h.row().State == nodewl.StateNeedsAttention })
			h.p.Wait()

			r := h.row()
			if r.Reason != nodewl.ReasonDrainTimeout || r.Ready {
				t.Fatalf("row = %+v", r)
			}
			calls := h.api.callList()
			if countOf(calls, "stop:") != 0 || countOf(calls, "rm:") != 0 {
				t.Fatalf("an undrained worker was stopped or removed: %v", calls)
			}
			if c := h.api.ctr(wName); c == nil || !c.Running {
				t.Fatalf("the worker is no longer running: %+v", c)
			}
		})
	}
}

func TestADrainThatFailedIsRetriedAndThenCompletes(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	h.door.status("POST", "/v1/lifecycle/drain", 503)
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })
	h.p.Converge(context.Background(), h.provisioned())
	eventually(t, "needs_attention", func() bool { return h.row().State == nodewl.StateNeedsAttention })
	h.p.Wait()

	h.door.status("POST", "/v1/lifecycle/drain", 200)
	h.door.status("GET", doneP, 200)
	h.p.Converge(context.Background(), h.provisioned())
	h.p.Wait()
	if r := h.row(); r.State != nodewl.StateProvisioned || r.Reason != "" {
		t.Fatalf("row = %+v", r)
	}
	if !h.api.has("stop:" + wName) {
		t.Fatalf("a drained worker was not stopped")
	}
}

func TestReleaseOfAWorkerThatIsNotRunningDoesNotDrain(t *testing.T) {
	h := newLife(t)
	h.p.Converge(context.Background(), h.provisioned())
	if r := h.row(); r.State != nodewl.StateProvisioned {
		t.Fatalf("row = %+v", r)
	}
	if countOf(h.api.callList(), "door:") != 0 {
		t.Fatalf("a stopped worker was sent a drain: %v", h.api.callList())
	}
	// A worker that ran and exited is recreated fresh and stopped.
	h.api.setCtr(wName, func(c *ctrInfo) { c.Running, c.Status = false, "exited" })
	h.p.Converge(context.Background(), h.provisioned())
	if c := h.api.ctr(wName); c == nil || c.Status != "created" {
		t.Fatalf("worker = %+v, want recreated and created", c)
	}
}

// ---- absent ------------------------------------------------------------

func TestAbsentRemovesEverything(t *testing.T) {
	h := newLife(t)
	h.p.Converge(context.Background(), h.provisioned())
	e := h.entry
	e.State = nodewl.StateAbsent
	h.p.Converge(context.Background(), e)
	if h.api.ctr(wName) != nil || h.api.ctr(dName) != nil {
		t.Errorf("containers remain after absent")
	}
	h.api.mu.Lock()
	_, netThere := h.api.nets[WorkloadNetworkName("rhaddon", "worker")]
	h.api.mu.Unlock()
	if netThere {
		t.Errorf("the network remains after absent")
	}
	if r := h.row(); r.State != nodewl.StateAbsent || r.Reason != "" {
		t.Fatalf("row = %+v", r)
	}
}

func TestAbsentFromRunningDrainsFirst(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	h.door.status("POST", "/v1/lifecycle/drain", 503)
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })
	e := h.entry
	e.State = nodewl.StateAbsent
	h.p.Converge(context.Background(), e)
	eventually(t, "needs_attention", func() bool { return h.row().State == nodewl.StateNeedsAttention })
	h.p.Wait()
	if h.api.ctr(wName) == nil || !h.api.ctr(wName).Running {
		t.Fatalf("an undrained worker was removed")
	}
	h.door.status("POST", "/v1/lifecycle/drain", 200)
	h.door.status("GET", doneP, 200)
	h.p.Converge(context.Background(), e)
	h.p.Wait()
	if h.api.ctr(wName) != nil || h.row().State != nodewl.StateAbsent {
		t.Fatalf("worker after a completed drain: %+v, row %+v", h.api.ctr(wName), h.row())
	}
}

// ---- refusals ----------------------------------------------------------

func TestAGateRefusalChangesNoContainerAndIsTheReason(t *testing.T) {
	for _, code := range []string{nodewl.ReasonConsentNone, nodewl.ReasonConsentUnapproved, nodewl.ReasonComputeCapLow, nodewl.ReasonNvidiaRuntimeMissing, nodewl.ReasonControllerHost} {
		t.Run(code, func(t *testing.T) {
			h := newLife(t)
			h.p.SetAdmit(func(context.Context, nodewl.Entry) error { return &nodewl.Error{Code: code} })
			for _, e := range []nodewl.Entry{h.running(), h.provisioned()} {
				h.p.Converge(context.Background(), e)
			}
			if h.api.mutated() || countOf(h.api.callList(), "start:") != 0 {
				t.Fatalf("a refused entry touched the node: %v", h.api.callList())
			}
			if r := h.row(); r.Reason != code || r.State != nodewl.StateAbsent || r.Ready {
				t.Fatalf("row = %+v", r)
			}
		})
	}
}

func TestNoGateWiredIsAClosedGate(t *testing.T) {
	h := newLife(t)
	h.p.SetAdmit(nil)
	h.p.Converge(context.Background(), h.running())
	if h.api.mutated() {
		t.Fatalf("an ungated entry was provisioned: %v", h.api.callList())
	}
	if r := h.row(); r.Reason != nodewl.ReasonConsentNone {
		t.Fatalf("row = %+v", r)
	}
}

func TestARefusalKeepsTheLastGoodStateOfARunningWorker(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })
	h.p.SetAdmit(func(context.Context, nodewl.Entry) error { return &nodewl.Error{Code: nodewl.ReasonConsentNone} })
	before := h.api.callList()
	h.p.Converge(context.Background(), h.running())
	// The worker stays running, so its readiness watcher keeps probing:
	// only a call that is not a probe is a change.
	if touched := touchesSince(h.api.callList(), len(before)); len(touched) != 0 {
		t.Fatalf("a refusal changed the node: %v", touched)
	}
	if r := h.row(); r.State != nodewl.StateRunning || r.Reason != nodewl.ReasonConsentNone {
		t.Fatalf("row = %+v", r)
	}
}

func TestAnInvalidRowIsReportedAndTouchesNothing(t *testing.T) {
	h := newLife(t)
	h.p.Refuse("rhaddon", "worker", &nodewl.Error{Code: nodewl.ReasonDesiredInvalid})
	if r := h.row(); r.Reason != nodewl.ReasonDesiredInvalid || r.State != nodewl.StateAbsent || r.DoorPort != 8443 {
		t.Fatalf("row = %+v", r)
	}
	if h.api.mutated() {
		t.Fatal("a refused row touched the node")
	}
}

// ---- rows --------------------------------------------------------------

func TestRowsAreUnknownUntilDesiredIsReadAndRetainDropsTheUnlisted(t *testing.T) {
	h := newLife(t)
	if h.p.Rows() != nil {
		t.Fatalf("rows before any desired-config read = %v, want nil (unknown)", h.p.Rows())
	}
	h.p.MarkRead()
	if rows := h.p.Rows(); rows == nil || len(rows) != 0 {
		t.Fatalf("a read with no workloads = %#v, want known-empty", rows)
	}
	h.p.Converge(context.Background(), h.provisioned())
	if len(h.p.Rows()) != 1 {
		t.Fatalf("rows = %v", h.p.Rows())
	}
	h.p.Retain(map[string]bool{})
	if len(h.p.Rows()) != 0 {
		t.Fatalf("an unlisted workload still has a row: %v", h.p.Rows())
	}
}

func TestAnAgentRestartAdoptsTheRunningState(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	mustRunning(h)
	h.api.setCtr(wName, func(c *ctrInfo) { c.Running, c.Status = true, "running" })
	h.api.setCtr(dName, func(c *ctrInfo) { c.Running, c.Status = true, "running" })
	h.p.Converge(context.Background(), h.running())
	eventually(t, "ready", func() bool { return h.row().Ready })
	if countOf(h.api.callList(), "start:") != 0 {
		t.Fatalf("a worker that was already running was started again: %v", h.api.callList())
	}
}

// ---- the actuator's entry points ---------------------------------------

func TestStartManagedStartsAndStopManagedReleases(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	h.door.status("POST", "/v1/lifecycle/drain", 200)
	h.door.status("GET", doneP, 200)
	if err := h.p.StartManaged(context.Background(), h.running()); err != nil {
		t.Fatal(err)
	}
	st, err := h.p.ManagedStatus(context.Background(), "rhaddon", "worker")
	if err != nil || st.State != nodewl.StateRunning || !st.Running {
		t.Fatalf("status = %+v, %v", st, err)
	}
	if ok, _ := h.p.IsManaged(context.Background(), "rhaddon", "worker"); !ok {
		t.Fatal("the agent's own workload is not managed")
	}
	if ok, _ := h.p.IsManaged(context.Background(), "other", "thing"); ok {
		t.Fatal("an unknown workload is managed")
	}
	if err := h.p.StopManaged(context.Background(), h.provisioned()); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.p.ManagedStatus(context.Background(), "rhaddon", "worker"); st.State != nodewl.StateProvisioned || st.Running {
		t.Fatalf("after stop: %+v", st)
	}
	calls := h.api.callList()
	if !(indexOf(calls, "door:POST /v1/lifecycle/drain") < indexOf(calls, "stop:"+wName)) {
		t.Fatalf("stop must come after the drain: %v", calls)
	}
}

func TestStopManagedWithAFailedDrainLeavesTheWorkerRunning(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	h.door.status("POST", "/v1/lifecycle/drain", 503)
	if err := h.p.StartManaged(context.Background(), h.running()); err != nil {
		t.Fatal(err)
	}
	if err := h.p.StopManaged(context.Background(), h.provisioned()); err == nil {
		t.Fatal("a failed drain returned success")
	}
	if countOf(h.api.callList(), "stop:") != 0 {
		t.Fatalf("an undrained worker was stopped: %v", h.api.callList())
	}
	if st, _ := h.p.ManagedStatus(context.Background(), "rhaddon", "worker"); st.State != nodewl.StateNeedsAttention || st.Reason != nodewl.ReasonDrainTimeout || !st.Running {
		t.Fatalf("status = %+v", st)
	}
}

func TestStartManagedIsRefusedByTheGate(t *testing.T) {
	h := newLife(t)
	h.p.SetAdmit(func(context.Context, nodewl.Entry) error { return &nodewl.Error{Code: nodewl.ReasonConsentNone} })
	err := h.p.StartManaged(context.Background(), h.running())
	if nodewl.CodeOf(err) != nodewl.ReasonConsentNone {
		t.Fatalf("err = %v", err)
	}
	if h.api.mutated() {
		t.Fatalf("a refused start touched the node: %v", h.api.callList())
	}
}

// 0.6.25-rc.2 rehearsal: a provisioning attempt that failed with an uncoded
// error left the row's EARLIER reason (door_leaf_missing) in place, so the
// node, the gateway and the reserve refusal named the wrong cause. A failed
// provision now says provision_failed; an uncoded error outside provisioning
// still never replaces a reason (TestOnlyAReasonCodeChangesTheReasonOfARow).
func TestAFailedProvisionReplacesTheEarlierReason(t *testing.T) {
	h := newLife(t)
	e := h.provisioned()
	h.p.with(e.Addon, e.Name, func(ls *lifeState) { ls.reason = nodewl.ReasonDoorLeafMissing })
	h.api.loadErr = errors.New("docker load: the daemon went away")
	h.p.Converge(context.Background(), e)
	cur, _ := h.p.read(e.Addon, e.Name)
	if cur.reason != nodewl.ReasonProvisionFailed {
		t.Fatalf("after a failed provision the row says %q, want provision_failed", cur.reason)
	}
	if got := provisionErr(errors.New(`fetch https://h:8443/x?token=T`)); nodewl.CodeOf(got) != nodewl.ReasonProvisionFailed || strings.Contains(got.Error(), "token=T") {
		t.Fatalf("provisionErr: %v", got)
	}
	if got := provisionErr(ErrSetsPending); !errors.Is(got, ErrSetsPending) {
		t.Fatal("a routine wait is not a provision failure")
	}
}

// The case that started this (0.6.25-rc.2, A-nodewl.reserve): the door leaf
// is ready but the rail the image comes from refuses the connection. The row
// must END saying image_unavailable: the stale door_leaf_missing from an
// earlier attempt is replaced, not kept.
func TestAReadyLeafAndAnUnreachableRailEndAsImageUnavailable(t *testing.T) {
	h := newLife(t)
	e := h.provisioned()
	h.p.with(e.Addon, e.Name, func(ls *lifeState) { ls.reason = nodewl.ReasonDoorLeafMissing })
	if !h.p.LeafReady(e.Addon, e.Name) {
		t.Fatal("the harness's door leaf must be ready for this case")
	}
	h.p.fetchTar = func(context.Context, string) (string, func(), error) {
		return "", nil, errors.New(`Get "https://noo-controller:8443/images/w.tar": dial tcp 172.31.250.10:8443: connect: connection refused`)
	}
	h.p.Converge(context.Background(), e)
	cur, _ := h.p.read(e.Addon, e.Name)
	if cur.reason != nodewl.ReasonImageUnavailable {
		t.Fatalf("a ready leaf and a refused rail left the row saying %q, want image_unavailable", cur.reason)
	}
}

// creates counts the container creates and removes in calls.
func creates(calls []string) (n int) {
	for _, c := range calls {
		if strings.HasPrefix(c, "create:") || strings.HasPrefix(c, "rm:") {
			n++
		}
	}
	return n
}

// 0.6.25-rc.3: the reservation id was a label, labels are in the spec hash,
// so every reserve tore down and rebuilt the door and the worker before
// starting them. A reserve after provision now only starts the pair: the
// same containers (no remove, no create) and the same spec hash.
func TestAReserveAfterProvisionOnlyStartsThePair(t *testing.T) {
	h := newLife(t)
	h.door.status("GET", "/health/ready", 200)
	h.p.Converge(context.Background(), h.provisioned())
	if r := h.row(); r.State != nodewl.StateProvisioned {
		t.Fatalf("not provisioned: %+v", r)
	}
	before := len(h.api.callList())
	hashW, hashD := h.api.ctr(wName).Labels[SpecHashLabel], h.api.ctr(dName).Labels[SpecHashLabel]
	if err := h.p.StartManaged(context.Background(), h.running()); err != nil {
		t.Fatal(err)
	}
	after := h.api.callList()[before:]
	if n := creates(after); n != 0 {
		t.Fatalf("the reserve removed or created containers: %v", after)
	}
	if indexOf(after, "start:"+dName) < 0 || indexOf(after, "start:"+wName) < 0 {
		t.Fatalf("the reserve did not start the pair: %v", after)
	}
	if h.api.ctr(wName).Labels[SpecHashLabel] != hashW || h.api.ctr(dName).Labels[SpecHashLabel] != hashD {
		t.Fatal("the spec hash changed on reserve")
	}
}

// The reservation is not part of what the pair is made from.
func TestTheReservationIsNotInTheSpecHash(t *testing.T) {
	h := newLife(t)
	in := func(e nodewl.Entry) string {
		s, err := buildWorkloadSpecs(specInput{Entry: e, WorkerImage: "sha256:w", DoorImage: "sha256:d"})
		if err != nil {
			t.Fatal(err)
		}
		return s.Hash
	}
	if in(h.running()) != in(h.provisioned()) {
		t.Fatal("a reservation id changes the spec hash")
	}
	// A real change still does.
	e := h.provisioned()
	e.Env = map[string]string{"RHADDON_SLOTS": "2"}
	if in(e) == in(h.provisioned()) {
		t.Fatal("an env change left the spec hash unchanged")
	}
}

// A real spec change on a stopped pair still rebuilds it.
func TestARealSpecChangeStillRebuildsAStoppedPair(t *testing.T) {
	h := newLife(t)
	h.p.Converge(context.Background(), h.provisioned())
	before := len(h.api.callList())
	e := h.provisioned()
	e.Env = map[string]string{"RHADDON_SLOTS": "2"}
	h.p.Converge(context.Background(), e)
	after := h.api.callList()[before:]
	if indexOf(after, "rm:"+wName) < 0 || indexOf(after, "create:"+wName) < 0 || indexOf(after, "create:"+dName) < 0 {
		t.Fatalf("a changed spec did not rebuild the pair: %v", after)
	}
}

// One failed start is retried once after a short wait; the workload runs.
func TestAFailedStartIsRetriedOnce(t *testing.T) {
	h := newLife(t)
	h.p.lc.startRetry = time.Millisecond
	h.door.status("GET", "/health/ready", 200)
	h.api.mu.Lock()
	h.api.startFail = map[string]int{dName: 1}
	h.api.mu.Unlock()
	if err := h.p.StartManaged(context.Background(), h.running()); err != nil {
		t.Fatalf("the retry should have started it: %v", err)
	}
	calls := h.api.callList()
	n := 0
	for _, c := range calls {
		if c == "start:"+dName {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("door starts = %d, want 2 (one retry): %v", n, calls)
	}
	if st, _ := h.p.ManagedStatus(context.Background(), "rhaddon", "worker"); !st.Running {
		t.Fatalf("not running after the retry: %+v", st)
	}
}

// A start that fails twice is refused (no third try), naming both errors.
func TestAStartThatFailsTwiceIsRefusedAfterOneRetry(t *testing.T) {
	h := newLife(t)
	h.p.lc.startRetry = time.Millisecond
	h.api.mu.Lock()
	h.api.startFail = map[string]int{wName: 5}
	h.api.mu.Unlock()
	err := h.p.StartManaged(context.Background(), h.running())
	if err == nil {
		t.Fatal("a start that failed twice was not refused")
	}
	if !strings.Contains(err.Error(), "retried once") || !strings.Contains(err.Error(), "cgroup") {
		t.Fatalf("error = %v", err)
	}
	n := 0
	for _, c := range h.api.callList() {
		if c == "start:"+wName {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("worker starts = %d, want exactly 2", n)
	}
}
