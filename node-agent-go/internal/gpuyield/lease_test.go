// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// fakeDrainer stands in for the inference proxy's admission: `inFlight`
// is what still runs per backend; `closed` records SetDraining calls.
type fakeDrainer struct {
	mu       sync.Mutex
	inFlight map[string]int
	closed   []string // "on:vllm" / "off:vllm" in order
	// release, when set, is run once WaitIdle is first called (a request
	// finishing while the drain waits).
	release func()
}

func (f *fakeDrainer) SetDraining(backends []string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range backends {
		if on {
			f.closed = append(f.closed, "on:"+b)
		} else {
			f.closed = append(f.closed, "off:"+b)
		}
	}
}

func (f *fakeDrainer) WaitIdle(ctx context.Context, backends []string) (bool, map[string]int) {
	if f.release != nil {
		r := f.release
		f.release = nil
		r()
	}
	for {
		f.mu.Lock()
		rem := map[string]int{}
		for _, b := range backends {
			if f.inFlight[b] > 0 {
				rem[b] = f.inFlight[b]
			}
		}
		f.mu.Unlock()
		if len(rem) == 0 {
			return true, nil
		}
		select {
		case <-ctx.Done():
			return false, rem
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (f *fakeDrainer) set(b string, n int) {
	f.mu.Lock()
	f.inFlight[b] = n
	f.mu.Unlock()
}

func heldRig(t *testing.T) (*Controller, *fakeProbe, *fakeDocker, *clock, *fakeDrainer) {
	t.Helper()
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	dr := &fakeDrainer{inFlight: map[string]int{}}
	c.SetDrainer(dr)
	return c, p, d, clk, dr
}

func TestHoldIsAnOwnedLeaseWithAGeneration(t *testing.T) {
	c, _, d, _, _ := heldRig(t)
	r, err := c.Hold(context.Background(), HoldRequest{Reason: "voice", Owner: "rbwolf", OperationID: "op-1", Workload: "pai-voice/voice-worker"})
	if err != nil || r.State != StateHeld || len(d.stops) != 1 {
		t.Fatalf("hold: %+v %v stops=%v", r, err, d.stops)
	}
	l := r.Lease
	if l == nil || l.Owner != "rbwolf" || l.OperationID != "op-1" || l.Generation != 1 || l.Mode != ModeDrain || l.DrainedAt == "" || l.Workload != "pai-voice/voice-worker" {
		t.Fatalf("lease: %+v", l)
	}
	if r.Generation != 1 {
		t.Fatalf("generation rides the report: %+v", r)
	}
	if len(r.GPUBackends) != 1 || r.GPUBackends[0] != "vllm" {
		t.Fatalf("the report names the GPU lanes a hold pauses: %+v", r.GPUBackends)
	}
	// The same operation asking again is its own hold, not a conflict.
	r2, err := c.Hold(context.Background(), HoldRequest{Reason: "voice", OperationID: "op-1"})
	if err != nil || r2.Lease.Generation != 1 {
		t.Fatalf("idempotent hold: %+v %v", r2, err)
	}
}

func TestAnotherOperationCannotTakeOrReleaseTheHold(t *testing.T) {
	c, _, _, _, _ := heldRig(t)
	if _, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-1", Owner: "a"}); err != nil {
		t.Fatal(err)
	}
	var held *ErrHeld
	_, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-2", Owner: "b"})
	if !errors.As(err, &held) || held.Current.OperationID != "op-1" || held.Current.Owner != "a" {
		t.Fatalf("a second operation must be refused with the current lease: %v", err)
	}
	// A release with the wrong operation id or a stale generation is refused.
	for _, req := range []ReleaseRequest{{OperationID: "op-2", Generation: 1}, {OperationID: "op-1", Generation: 0}} {
		if _, err := c.Release(context.Background(), req); !errors.As(err, &held) {
			t.Fatalf("release %+v must be refused: %v", req, err)
		}
	}
	if c.Report().State != StateHeld {
		t.Fatal("still held")
	}
	// The matching pair releases.
	r, err := c.Release(context.Background(), ReleaseRequest{OperationID: "op-1", Generation: 1})
	if err != nil || r.State == StateHeld || r.Lease != nil {
		t.Fatalf("CAS release: %+v %v", r, err)
	}
	// Releasing again with the same receipt: not held.
	if _, err := c.Release(context.Background(), ReleaseRequest{OperationID: "op-1", Generation: 1}); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("a used receipt: %v", err)
	}
}

func TestForceTakesOverAndForceReleasesAnyHold(t *testing.T) {
	c, _, d, _, _ := heldRig(t)
	c.Hold(context.Background(), HoldRequest{OperationID: "op-1", Owner: "a"})
	stops := len(d.stops)
	r, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-2", Owner: "b", Force: true})
	if err != nil || r.Lease.OperationID != "op-2" || r.Lease.Generation != 2 {
		t.Fatalf("force takeover: %+v %v", r, err)
	}
	if len(d.starts) != 0 || len(d.stops) != stops || r.State != StateHeld {
		t.Fatalf("a hand-over keeps the backends paused throughout: starts=%v stops=%v", d.starts, d.stops)
	}
	// A legacy hold (no operation id) is a force with a generated id.
	r, err = c.Hold(context.Background(), HoldRequest{Reason: "by hand"})
	if err != nil || r.Lease.Generation != 3 || r.Lease.OperationID == "" || r.Lease.Owner != "operator" {
		t.Fatalf("legacy hold: %+v %v", r, err)
	}
	// A force release ends it whatever the ids.
	r, err = c.Release(context.Background(), ReleaseRequest{Force: true})
	if err != nil || r.State == StateHeld {
		t.Fatalf("force release: %+v %v", r, err)
	}
	// A force release of a node that is not held is the legacy no-op.
	if _, err := c.Release(context.Background(), ReleaseRequest{Force: true}); err != nil {
		t.Fatalf("force release when free: %v", err)
	}
}

func TestDrainHoldWaitsForInFlightThenStops(t *testing.T) {
	c, _, d, _, dr := heldRig(t)
	dr.set("vllm", 2)
	// The request finishes while the drain waits.
	dr.release = func() {
		go func() { time.Sleep(20 * time.Millisecond); dr.set("vllm", 0) }()
	}
	r, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-1", Timeout: 2 * time.Second})
	if err != nil || r.State != StateHeld || len(d.stops) != 1 {
		t.Fatalf("drain then hold: %+v %v stops=%v", r, err, d.stops)
	}
	if len(dr.closed) != 2 || dr.closed[0] != "on:vllm" || dr.closed[1] != "off:vllm" {
		t.Fatalf("admission closed for the drain and reopened after the stop: %v", dr.closed)
	}
	if r.Lease.DrainStarted == "" || r.Lease.DrainedAt == "" {
		t.Fatalf("the lease brackets the drain: %+v", r.Lease)
	}
}

func TestDrainTimeoutAbortsTheHoldAndCutsNothing(t *testing.T) {
	c, _, d, _, dr := heldRig(t)
	dr.set("vllm", 1)
	before := c.Report()
	r, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-1", Timeout: 30 * time.Millisecond})
	var dt *ErrDrainTimeout
	if !errors.As(err, &dt) || dt.Remaining["vllm"] != 1 {
		t.Fatalf("want drain timeout naming what still runs: %v", err)
	}
	if len(d.stops) != 0 {
		t.Fatalf("nothing may be stopped on a timeout: %v", d.stops)
	}
	if r.State != before.State || r.Lease != nil || len(r.PausedBackends) != 0 || c.Holds("vllm") {
		t.Fatalf("the aborted hold must leave no trace: before=%+v after=%+v", before, r)
	}
	if last := dr.closed[len(dr.closed)-1]; last != "off:vllm" {
		t.Fatalf("admission reopened: %v", dr.closed)
	}
	if r.Generation != 1 {
		t.Fatalf("the accepted hold used a generation even though it was aborted: %+v", r)
	}
	// The node is free for the next hold.
	if _, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-2", Mode: ModeImmediate}); err != nil {
		t.Fatal(err)
	}
}

func TestImmediateModeSkipsTheDrain(t *testing.T) {
	c, _, d, _, dr := heldRig(t)
	dr.set("vllm", 3)
	r, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-1", Mode: ModeImmediate})
	if err != nil || r.State != StateHeld || len(d.stops) != 1 || len(dr.closed) != 0 {
		t.Fatalf("immediate: %+v %v stops=%v closed=%v", r, err, d.stops, dr.closed)
	}
	if r.Lease.Mode != ModeImmediate || r.Lease.DrainStarted != "" {
		t.Fatalf("lease says immediate: %+v", r.Lease)
	}
}

func TestOnlyOneTransitionAtATime(t *testing.T) {
	c, _, _, _, dr := heldRig(t)
	dr.set("vllm", 1)
	done := make(chan error, 1)
	go func() {
		_, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-1", Timeout: 200 * time.Millisecond})
		done <- err
	}()
	// Wait until the first hold is draining.
	deadline := time.Now().Add(time.Second)
	for c.Report().State != StateDraining {
		if time.Now().After(deadline) {
			t.Fatal("never draining")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := c.Hold(context.Background(), HoldRequest{OperationID: "op-2", Force: true}); !errors.Is(err, ErrTransition) {
		t.Fatalf("a second hold during a drain: %v", err)
	}
	if _, err := c.Release(context.Background(), ReleaseRequest{Force: true}); !errors.Is(err, ErrTransition) {
		t.Fatalf("a release during a drain: %v", err)
	}
	if c.Report().Lease == nil || c.Report().Lease.OperationID != "op-1" {
		t.Fatalf("the draining lease is reported: %+v", c.Report())
	}
	dr.set("vllm", 0)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReleaseResumeNowStartsAtOnce(t *testing.T) {
	c, _, d, _, _ := heldRig(t)
	c.Hold(context.Background(), HoldRequest{OperationID: "op-1"})
	r, err := c.Release(context.Background(), ReleaseRequest{OperationID: "op-1", Generation: 1, ResumeNow: true})
	if err != nil || r.State != StateFree || len(d.starts) != 1 || d.starts[0] != vllmID {
		t.Fatalf("resume now: %+v %v starts=%v", r, err, d.starts)
	}
}

func TestLeaseAndGenerationSurviveRestartButADrainDoesNot(t *testing.T) {
	dir := t.TempDir()
	p := &fakeProbe{r: pidReading(8000, 0)}
	d := &fakeDocker{ctrs: []docker.GPUBackend{{Backend: "vllm", ID: vllmID, Running: true}}}
	c := New(ConfigFromEnv(env(nil)), p, d, dir)
	c.Hold(context.Background(), HoldRequest{OperationID: "op-1", Owner: "a"})
	c2 := New(ConfigFromEnv(env(nil)), p, d, dir)
	r := c2.Report()
	if r.State != StateHeld || r.Lease == nil || r.Lease.OperationID != "op-1" || r.Generation != 1 {
		t.Fatalf("lease lost across restart: %+v", r)
	}
	if _, err := c2.Release(context.Background(), ReleaseRequest{OperationID: "op-1", Generation: 1}); err != nil {
		t.Fatalf("the receipt still releases after a restart: %v", err)
	}
	// The generation is kept while free, so an old receipt never matches a
	// new hold.
	c3 := New(ConfigFromEnv(env(nil)), p, d, dir)
	if c3.Report().Generation != 1 {
		t.Fatalf("generation must persist while free: %+v", c3.Report())
	}
	r3, _ := c3.Hold(context.Background(), HoldRequest{OperationID: "op-2"})
	if r3.Lease.Generation != 2 {
		t.Fatalf("next hold is generation 2: %+v", r3.Lease)
	}

	// A drain cut by a restart is not restored as a hold.
	c3.mu.Lock()
	c3.state = StateDraining
	c3.saveLocked()
	c3.mu.Unlock()
	c4 := New(ConfigFromEnv(env(nil)), p, d, dir)
	if r := c4.Report(); r.State == StateDraining || r.State == StateHeld || r.Lease != nil || r.Generation != 2 {
		t.Fatalf("a draining state must not be restored: %+v", r)
	}
}
