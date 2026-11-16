// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

import (
	"context"
	"testing"
	"time"
)

// A hold runs the pause hook (the warm keeper's keep_alive-0 unload) once,
// BEFORE the GPU backends stop: the adopted stack ollama is never stopped, so
// a warm model there is freed only by the unload.
func TestHoldRunsThePauseHookBeforeStopping(t *testing.T) {
	c, _, d, _, _ := heldRig(t)
	var calls []string
	stopsAtHook := -1
	c.OnPause(func(_ context.Context, why string) {
		calls = append(calls, why)
		stopsAtHook = len(d.stops)
	})
	if c.GPUFreed() {
		t.Fatal("free before the hold")
	}
	if _, err := c.Hold(context.Background(), HoldRequest{Reason: "voice", OperationID: "op-1"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != "voice" {
		t.Fatalf("pause hook: %v", calls)
	}
	if stopsAtHook != 0 || len(d.stops) != 1 {
		t.Fatalf("the unload runs before the stop: stops at hook %d, after %v", stopsAtHook, d.stops)
	}
	if !c.GPUFreed() {
		t.Fatal("held: the GPU is being given back, nothing may pin on it")
	}
}

// The automatic yield runs it too, once per pause (not on every tick that
// keeps the pause).
func TestYieldRunsThePauseHookOnce(t *testing.T) {
	c, p, _, clk := rig(t, nil)
	n := 0
	c.OnPause(func(context.Context, string) { n++ })
	p.r = pidReading(8000, 3000)
	tickFor(c, clk, 90*time.Second)
	if c.Report().State != StateYielded {
		t.Fatalf("not yielded: %+v", c.Report())
	}
	tickFor(c, clk, 60*time.Second) // still under pressure: the pause holds
	if n != 1 {
		t.Fatalf("pause hook ran %d times, want once", n)
	}
	if !c.GPUFreed() {
		t.Fatal("yielded: the GPU is being given back")
	}
}
