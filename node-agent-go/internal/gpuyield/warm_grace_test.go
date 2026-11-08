// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

import (
	"context"
	"testing"
	"time"
)

// awolf, 2026-11-07: every resume of vLLM was followed 2m19s later by
// nvidia-smi timing out (vLLM's own weight load stalls it on WSL2), read as
// a Windows program, and vLLM was paused again: a self-yield loop. A probe
// timeout within NOO_GPU_TIMEOUT_GRACE_S of one of our GPU backends starting
// is that backend warming up, not pressure.

func TestTimeoutsWhileOurBackendWarmsUpDoNotYield(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	d.ctrs[0].Running = false
	p.r = pidReading(0, 0)
	c.Tick(context.Background()) // baseline: vLLM stopped
	clk.advance(15 * time.Second)
	d.ctrs[0].Running = true // the reconciler starts it
	p.r = pidReading(3000, 0)
	c.Tick(context.Background())
	p.r = timedOut
	// 4 minutes of timeouts: four times the 60 s yield window, inside the
	// 300 s grace.
	tickFor(c, clk, 4*time.Minute)
	if r := c.Report(); r.State == StateYielded || len(d.stops) != 0 {
		t.Fatalf("our own backend warming up must not yield it: %+v stops=%v", r, d.stops)
	}
	// Past the grace, timeouts are pressure again (i396 still holds).
	tickFor(c, clk, 2*time.Minute)
	if r := c.Report(); r.State != StateYielded || len(d.stops) != 1 {
		t.Fatalf("timeouts outside the grace must still yield: %+v stops=%v", r, d.stops)
	}
}

func TestAResumeOpensTheGraceSoTheNodeDoesNotYieldToItself(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	clk.advance(15 * time.Second)
	p.r = timedOut
	tickFor(c, clk, 90*time.Second)
	if c.Report().State != StateYielded {
		t.Fatalf("setup: want yielded on timeouts: %+v", c.Report())
	}
	p.r = pidReading(0, 0)
	tickFor(c, clk, 150*time.Second) // measured clear past ResumeAfter
	if r := c.Report(); r.State == StateYielded || len(d.starts) != 1 {
		t.Fatalf("setup: want resumed: %+v starts=%v", r, d.starts)
	}
	// awolf's pattern: the probe stalls 2m19s after the resume, for minutes.
	p.r = pidReading(8000, 0)
	tickFor(c, clk, 135*time.Second)
	p.r = timedOut
	tickFor(c, clk, 2*time.Minute)
	if r := c.Report(); r.State == StateYielded || len(d.stops) != 1 {
		t.Fatalf("a resume followed by our own warm-up stall must not pause again: %+v stops=%v", r, d.stops)
	}
}

func TestMeasuredForeignUseIsNeverGraced(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	d.ctrs[0].Running = false
	p.r = pidReading(0, 0)
	c.Tick(context.Background())
	clk.advance(15 * time.Second)
	d.ctrs[0].Running = true
	p.r = pidReading(8000, 3000) // a real foreign 3000 MB > 2048
	tickFor(c, clk, 75*time.Second)
	if r := c.Report(); r.State != StateYielded || len(d.stops) != 1 {
		t.Fatalf("measured foreign use must yield even while we warm up: %+v stops=%v", r, d.stops)
	}
}

func TestAnAgentRestartIsNotABackendStart(t *testing.T) {
	// The first tick sees vLLM already running: no grace, so a real Windows
	// program stalling the probe still yields after the window.
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	clk.advance(15 * time.Second)
	p.r = timedOut
	tickFor(c, clk, 75*time.Second)
	if r := c.Report(); r.State != StateYielded || len(d.stops) != 1 {
		t.Fatalf("no grace without a start: %+v stops=%v", r, d.stops)
	}
}

func TestTimeoutGraceIsConfigurable(t *testing.T) {
	if got := ConfigFromEnv(env(nil)).TimeoutGrace; got != 300*time.Second {
		t.Fatalf("default grace: %v", got)
	}
	if got := ConfigFromEnv(env(map[string]string{"NOO_GPU_TIMEOUT_GRACE_S": "0"})).TimeoutGrace; got != 0 {
		t.Fatalf("0 disables the grace: %v", got)
	}
	if got := ConfigFromEnv(env(map[string]string{"NOO_GPU_TIMEOUT_GRACE_S": "x"})).TimeoutGrace; got != 300*time.Second {
		t.Fatalf("a bad value keeps the default: %v", got)
	}
}
