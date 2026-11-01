// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// i396: a probe that stops answering is pressure, not "no data".

var timedOut = Reading{Unmeasured: UnmeasuredProbeTimeout}

func TestTimeoutsAfterMeasuredReadingYieldAfterYieldWindow(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	clk.advance(15 * time.Second)
	p.r = timedOut
	// 60 s default window: ticks at +0, 15, 30, 45 are still short of it.
	for i := 0; i < 4; i++ {
		c.Tick(context.Background())
		if got := c.Report().State; got == StateYielded {
			t.Fatalf("tick %d: yielded before the window", i)
		}
		clk.advance(15 * time.Second)
	}
	if len(d.stops) != 0 {
		t.Fatalf("stopped early: %v", d.stops)
	}
	c.Tick(context.Background()) // +60 s of consecutive timeouts
	r := c.Report()
	if r.State != StateYielded || len(d.stops) != 1 {
		t.Fatalf("want yielded with vllm stopped, got %+v stops=%v", r, d.stops)
	}
	if !strings.Contains(r.Reason, "probe") || !c.Holds("vllm") {
		t.Fatalf("reason must name the probe timeout: %q", r.Reason)
	}
	if r.UnmeasuredForS < 60 || r.Unmeasured != UnmeasuredProbeTimeout {
		t.Fatalf("report must say how long the probe has been failing: %+v", r)
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"unmeasured_for_s":`) {
		t.Fatalf("json: %s", b)
	}
}

func TestShortTimeoutRunDoesNotYield(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	for round := 0; round < 3; round++ {
		p.r = timedOut
		for i := 0; i < 3; i++ { // 30 s of timeouts, under the window
			clk.advance(15 * time.Second)
			c.Tick(context.Background())
		}
		p.r = pidReading(8000, 0) // the probe answers: the run is broken
		clk.advance(15 * time.Second)
		c.Tick(context.Background())
	}
	if len(d.stops) != 0 || c.Report().State == StateYielded {
		t.Fatalf("short timeout runs must not yield: %+v", c.Report())
	}
}

func TestNeverMeasuredNeverYieldsOnTimeouts(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = timedOut
	tickFor(c, clk, 10*time.Minute)
	if len(d.stops) != 0 || c.Report().State == StateYielded {
		t.Fatalf("a node whose probe never answered must not yield: %+v", c.Report())
	}
}

func TestYieldedOnTimeoutsResumesOnlyOnMeasuredClear(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	p.r = timedOut
	tickFor(c, clk, 90*time.Second)
	if c.Report().State != StateYielded {
		t.Fatalf("want yielded: %+v", c.Report())
	}
	// Timeouts after the yield, far longer than ResumeAfter: stays yielded.
	tickFor(c, clk, 5*time.Minute)
	if c.Report().State != StateYielded || len(d.starts) != 0 {
		t.Fatalf("a timeout is never clear: %+v starts=%v", c.Report(), d.starts)
	}
	// Measured clear: the 120 s window starts at the first measured reading.
	p.r = pidReading(0, 0)
	c.Tick(context.Background())
	clk.advance(90 * time.Second)
	c.Tick(context.Background())
	if c.Report().State != StateYielded {
		t.Fatal("resumed before ResumeAfter of measured clear")
	}
	// A timeout in the middle of the clear run restarts it.
	p.r = timedOut
	clk.advance(15 * time.Second)
	c.Tick(context.Background())
	p.r = pidReading(0, 0)
	clk.advance(15 * time.Second)
	c.Tick(context.Background())
	clk.advance(90 * time.Second)
	c.Tick(context.Background())
	if c.Report().State != StateYielded {
		t.Fatal("a timeout must restart the clear window")
	}
	clk.advance(40 * time.Second)
	c.Tick(context.Background())
	if r := c.Report(); r.State == StateYielded || len(d.starts) != 1 {
		t.Fatalf("want resumed after measured clear: %+v starts=%v", r, d.starts)
	}
}

func TestOtherUnmeasuredCausesNeverYield(t *testing.T) {
	for _, cause := range []string{UnmeasuredNoNvidia, UnmeasuredUnifiedMemory, UnmeasuredDriverLost} {
		t.Run(cause, func(t *testing.T) {
			c, p, d, clk := rig(t, nil)
			p.r = pidReading(8000, 0) // measured once: the exception must not leak
			c.Tick(context.Background())
			p.r = Reading{Unmeasured: cause}
			tickFor(c, clk, 10*time.Minute)
			if len(d.stops) != 0 || c.Report().State == StateYielded {
				t.Fatalf("%s must never yield: %+v", cause, c.Report())
			}
		})
	}
}

func TestYieldOffIgnoresTimeouts(t *testing.T) {
	c, p, d, clk := rig(t, map[string]string{"NOO_GPU_YIELD": "off"})
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	p.r = timedOut
	tickFor(c, clk, 5*time.Minute)
	if len(d.stops) != 0 {
		t.Fatal("NOO_GPU_YIELD=off must not yield on timeouts")
	}
}

// blockingProbe never returns until released; it counts its starts.
type blockingProbe struct {
	starts  chan struct{}
	release chan Reading
}

func (b *blockingProbe) Read(context.Context) Reading {
	b.starts <- struct{}{}
	return <-b.release
}

func TestStuckProbeDoesNotBlockOrRunTwice(t *testing.T) {
	c, _, _, clk := rig(t, nil)
	bp := &blockingProbe{starts: make(chan struct{}, 8), release: make(chan Reading, 1)}
	c.probe = bp
	c.probeDeadline = 50 * time.Millisecond
	c.everMeasured = true

	done := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			c.Tick(context.Background())
			clk.advance(15 * time.Second)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a probe that never returns blocked the controller loop")
	}
	if n := len(bp.starts); n != 1 {
		t.Fatalf("a stuck probe must not be started again: %d starts", n)
	}
	if r := c.Report(); r.Unmeasured != UnmeasuredProbeTimeout {
		t.Fatalf("each tick counts as a timeout: %+v", r)
	}
	// Report (the heartbeat) is not blocked either, and the late answer is used.
	bp.release <- pidReading(0, 0)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.Tick(context.Background())
		if c.Report().Unmeasured == "" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the stuck probe's late answer was never picked up")
}
