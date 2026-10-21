// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package gpuyield

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// ── fakes ──

type fakeProbe struct{ r Reading }

func (f *fakeProbe) Read(context.Context) Reading { return f.r }

type fakeDocker struct {
	owned    []docker.NoomeshContainer // extra noomesh containers (stack, orphans)
	ownedErr error
	ctrs     []docker.GPUBackend
	stops    []string
	starts   []string
	listErr  error
}

func (f *fakeDocker) GPUBackendContainers(context.Context) ([]docker.GPUBackend, error) {
	return append([]docker.GPUBackend(nil), f.ctrs...), f.listErr
}

func (f *fakeDocker) NoomeshContainers(context.Context) ([]docker.NoomeshContainer, error) {
	if f.ownedErr != nil {
		return nil, f.ownedErr
	}
	out := append([]docker.NoomeshContainer(nil), f.owned...)
	have := map[string]bool{}
	for _, o := range out {
		have[o.ID] = true
	}
	for _, b := range f.ctrs {
		if have[b.ID] {
			continue
		}
		out = append(out, docker.NoomeshContainer{ID: b.ID, Name: b.Name, Running: b.Running, GPU: true})
	}
	return out, nil
}

func (f *fakeDocker) StopContainerGraceful(_ context.Context, id string, _ int) error {
	f.stops = append(f.stops, id)
	for i := range f.ctrs {
		if f.ctrs[i].ID == id {
			f.ctrs[i].Running = false
		}
	}
	return nil
}

func (f *fakeDocker) StartContainer(_ context.Context, id string) error {
	f.starts = append(f.starts, id)
	for i := range f.ctrs {
		if f.ctrs[i].ID == id {
			f.ctrs[i].Running = true
			return nil
		}
	}
	return errors.New("no such container")
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

const vllmID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// rig: a 16 GiB GPU, vLLM placed at 0.5 (8 GiB) and running.
func rig(t *testing.T, cfgEnv map[string]string) (*Controller, *fakeProbe, *fakeDocker, *clock) {
	t.Helper()
	p := &fakeProbe{}
	d := &fakeDocker{ctrs: []docker.GPUBackend{{Backend: "vllm", ID: vllmID, Name: "noo-vllm", Running: true}}}
	clk := &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	c := New(ConfigFromEnv(env(cfgEnv)), p, d, "")
	c.now = clk.now
	c.since = clk.now()
	c.cgroupOf = func(pid int) string {
		if pid == 100 {
			return "0::/system.slice/docker-" + vllmID + ".scope\n"
		}
		return "0::/user.slice\n"
	}
	c.SetPlacements([]Placed{{Backend: "vllm", Env: map[string]string{"GPU_MEMORY_UTILIZATION": "0.5"}}})
	return c, p, d, clk
}

// PID-resolvable reading: vLLM (pid 100) holds ourMB, a foreign pid holds foreignMB.
func pidReading(ourMB, foreignMB int) Reading {
	apps := []ComputeApp{}
	if ourMB > 0 {
		apps = append(apps, ComputeApp{PID: 100, UsedMB: ourMB})
	}
	if foreignMB > 0 {
		apps = append(apps, ComputeApp{PID: 200, UsedMB: foreignMB})
	}
	return Reading{Measured: true, TotalMB: 16384, UsedMB: ourMB + foreignMB, Apps: apps, AppsResolved: true}
}

func tickFor(c *Controller, clk *clock, d time.Duration) {
	for el := time.Duration(0); el <= d; el += 15 * time.Second {
		c.Tick(context.Background())
		clk.advance(15 * time.Second)
	}
}

// ── tests ──

func TestForeignOverThresholdPausesAfterSixtySeconds(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 3000) // foreign 3000 MB > 2048 default
	c.Tick(context.Background())
	if got := c.Report(); got.State != StateShared || got.Method != MethodSMI || got.ForeignMB != 3000 {
		t.Fatalf("first tick: want shared/nvidia-smi/3000, got %+v", got)
	}
	if !c.Holds("vllm") {
		t.Fatal("pressure pending: reconcile must already hold off starting vllm")
	}
	clk.advance(45 * time.Second)
	c.Tick(context.Background())
	if len(d.stops) != 0 {
		t.Fatalf("paused before 60 s: %v", d.stops)
	}
	clk.advance(15 * time.Second)
	c.Tick(context.Background())
	if len(d.stops) != 1 || d.stops[0] != vllmID {
		t.Fatalf("want vllm stopped at 60 s, stops=%v", d.stops)
	}
	r := c.Report()
	if r.State != StateYielded || len(r.PausedBackends) != 1 || r.PausedBackends[0] != "vllm" {
		t.Fatalf("want yielded with vllm paused, got %+v", r)
	}
	if !strings.Contains(r.Reason, "foreign") {
		t.Fatalf("reason should name the foreign use: %q", r.Reason)
	}
}

func TestShortSpikeDoesNotPause(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 3000)
	tickFor(c, clk, 30*time.Second)
	p.r = pidReading(8000, 100)
	tickFor(c, clk, 120*time.Second)
	if len(d.stops) != 0 {
		t.Fatalf("a 30 s spike must not pause: %v", d.stops)
	}
	if c.Holds("vllm") {
		t.Fatal("pressure over: no hold")
	}
}

func TestPausedBackendIsNotRestartedWhileForeignWorkRuns(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 11000)
	tickFor(c, clk, 60*time.Second)
	if c.Report().State != StateYielded {
		t.Fatal("setup: expected yielded")
	}
	// vLLM is down; the foreign 11 GB stays.
	p.r = pidReading(0, 11000)
	tickFor(c, clk, 10*time.Minute)
	if len(d.starts) != 0 {
		t.Fatalf("restarted a paused backend while the GPU is busy: %v", d.starts)
	}
	if !c.Holds("vllm") {
		t.Fatal("reconcile must respect the pause")
	}
	if c.Holds("ollama") {
		t.Fatal("a non-GPU backend is never held")
	}
}

func TestResumesAfterGPUFreeForResumeWindow(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 11000)
	tickFor(c, clk, 60*time.Second)
	nudged := make(chan struct{}, 1)
	c.OnResume(func() { nudged <- struct{}{} })
	// pai-voice disabled: drains to ~113 MiB residue — counts as free.
	p.r = pidReading(0, 113)
	c.Tick(context.Background())
	clk.advance(105 * time.Second)
	c.Tick(context.Background())
	if len(d.starts) != 0 {
		t.Fatalf("resumed before 120 s: %v", d.starts)
	}
	clk.advance(15 * time.Second)
	c.Tick(context.Background())
	if len(d.starts) != 1 || d.starts[0] != vllmID {
		t.Fatalf("want vllm restarted after 120 s clear, starts=%v", d.starts)
	}
	r := c.Report()
	if r.State != StateFree || len(r.PausedBackends) != 0 || c.Holds("vllm") {
		t.Fatalf("want free and unpaused, got %+v", r)
	}
	select {
	case <-nudged:
	case <-time.After(time.Second):
		t.Fatal("resume must nudge the reconciler")
	}
}

func TestClearWindowResetsOnRelapse(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 11000)
	tickFor(c, clk, 60*time.Second)
	p.r = pidReading(0, 100)
	tickFor(c, clk, 90*time.Second)
	p.r = pidReading(0, 11000) // back
	c.Tick(context.Background())
	p.r = pidReading(0, 100)
	tickFor(c, clk, 90*time.Second)
	if len(d.starts) != 0 {
		t.Fatalf("hysteresis must restart its window on relapse: %v", d.starts)
	}
}

func TestNeedExceedsAvailablePauses(t *testing.T) {
	// Foreign 1.5 GB is under the threshold, but vLLM at 0.95 needs
	// 15.2 GB of a 16 GB card: it cannot fit beside it.
	c, p, d, clk := rig(t, nil)
	c.SetPlacements([]Placed{{Backend: "vllm", Env: map[string]string{"GPU_MEMORY_UTILIZATION": "0.95"}}})
	p.r = pidReading(0, 1500)
	d.ctrs[0].Running = false
	tickFor(c, clk, 60*time.Second)
	r := c.Report()
	if r.State != StateYielded || !strings.Contains(r.Reason, "need") {
		t.Fatalf("want yielded for need > available, got %+v", r)
	}
}

func TestYieldOffNeverPauses(t *testing.T) {
	c, p, d, clk := rig(t, map[string]string{"NOO_GPU_YIELD": "off"})
	p.r = pidReading(8000, 12000)
	tickFor(c, clk, 10*time.Minute)
	if len(d.stops) != 0 || c.Holds("vllm") {
		t.Fatalf("NOO_GPU_YIELD=off must never pause: stops=%v", d.stops)
	}
	if r := c.Report(); r.Policy != "off" || r.State != StateShared {
		t.Fatalf("want policy off, state shared: %+v", r)
	}
}

func TestWSLNotFoundPIDsFallBackToMemoryAccounting(t *testing.T) {
	apps, resolved := parseComputeApps("[Not Found], [N/A]\n[Not Found], [N/A]\n")
	if resolved || len(apps) != 0 {
		t.Fatalf("[Not Found] rows must not resolve: %v %v", apps, resolved)
	}
	c, p, d, clk := rig(t, nil)
	// vLLM placed at 0.5 → expected 8192 MB; used 8192+11000.
	p.r = Reading{Measured: true, TotalMB: 16384, UsedMB: 8192 + 11000, AppsResolved: false}
	c.Tick(context.Background())
	r := c.Report()
	if r.Method != MethodAccounting || r.ForeignMB != 11000 {
		t.Fatalf("want memory-accounting with foreign 11000, got %+v", r)
	}
	tickFor(c, clk, 60*time.Second)
	if len(d.stops) != 1 {
		t.Fatalf("accounting must still yield: %v", d.stops)
	}
	// Yielded: nothing of ours runs, so all used memory is foreign.
	p.r = Reading{Measured: true, TotalMB: 16384, UsedMB: 11000}
	c.Tick(context.Background())
	if r := c.Report(); r.ForeignMB != 11000 || r.Method != MethodAccounting {
		t.Fatalf("yielded accounting: %+v", r)
	}
}

func TestEmptyPIDListWhileOurBackendRunsIsNotBelieved(t *testing.T) {
	// A driver that lists no compute apps although vLLM is running cannot
	// see container PIDs; believing it would call vLLM's own memory foreign.
	c, p, _, _ := rig(t, nil)
	p.r = Reading{Measured: true, TotalMB: 16384, UsedMB: 8192, AppsResolved: true}
	c.Tick(context.Background())
	if r := c.Report(); r.Method != MethodAccounting || r.ForeignMB != 0 {
		t.Fatalf("want accounting, foreign 0: %+v", r)
	}
}

func TestMacIsNotMeasuredAndNeverPauses(t *testing.T) {
	probe := &SMIProbe{goos: "darwin", run: func(...string) (string, error) {
		t.Fatal("nvidia-smi must not run on darwin")
		return "", nil
	}}
	if probe.Read(context.Background()).Measured {
		t.Fatal("darwin must be not-measured")
	}
	d := &fakeDocker{}
	c := New(ConfigFromEnv(env(nil)), probe, d, "")
	for i := 0; i < 20; i++ {
		c.Tick(context.Background())
	}
	r := c.Report()
	if r.Method != MethodNotMeasured || r.State != StateFree || len(d.stops) != 0 {
		t.Fatalf("mac: %+v stops=%v", r, d.stops)
	}
}

func TestNoNvidiaSMIIsNotMeasured(t *testing.T) {
	probe := &SMIProbe{goos: "linux", run: func(...string) (string, error) { return "", errors.New("exec: not found") }}
	if probe.Read(context.Background()).Measured {
		t.Fatal("missing nvidia-smi must be not-measured")
	}
}

func TestSMIProbeParses(t *testing.T) {
	probe := &SMIProbe{goos: "linux", run: func(args ...string) (string, error) {
		if strings.HasPrefix(args[0], "--query-gpu") {
			return "11520, 16376\n", nil
		}
		return "4242, 11264\n", nil
	}}
	r := probe.Read(context.Background())
	if !r.Measured || r.UsedMB != 11520 || r.TotalMB != 16376 || !r.AppsResolved || len(r.Apps) != 1 || r.Apps[0].PID != 4242 {
		t.Fatalf("parse: %+v", r)
	}
}

func TestOperatorHoldPausesNowAndNeverAutoResumes(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	r := c.Hold(context.Background(), "voice")
	if r.State != StateHeld || r.Reason != "voice" || len(d.stops) != 1 {
		t.Fatalf("hold must pause at once: %+v stops=%v", r, d.stops)
	}
	// GPU entirely free for an hour: still held.
	p.r = pidReading(0, 0)
	tickFor(c, clk, time.Hour)
	if len(d.starts) != 0 || c.Report().State != StateHeld || !c.Holds("vllm") {
		t.Fatalf("a hold must never auto-resume: starts=%v state=%s", d.starts, c.Report().State)
	}
}

func TestReleaseThenResumeWhenFree(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	c.Hold(context.Background(), "voice")
	// pai-voice enabled: 11 GiB foreign.
	p.r = pidReading(0, 11264)
	tickFor(c, clk, 5*time.Minute)
	if r := c.Release(); r.State != StateYielded {
		t.Fatalf("release with the GPU busy → yielded (automatic policy): %+v", r)
	}
	tickFor(c, clk, 5*time.Minute)
	if len(d.starts) != 0 {
		t.Fatalf("released but GPU still busy: must not resume: %v", d.starts)
	}
	// pai-voice disabled → 113 MiB residue.
	p.r = pidReading(0, 113)
	tickFor(c, clk, 2*time.Minute)
	if len(d.starts) != 1 || c.Report().State != StateFree {
		t.Fatalf("want resume after release + 120 s free: starts=%v %+v", d.starts, c.Report())
	}
}

func TestHoldSurvivesAgentRestart(t *testing.T) {
	dir := t.TempDir()
	p := &fakeProbe{r: pidReading(8000, 0)}
	d := &fakeDocker{ctrs: []docker.GPUBackend{{Backend: "vllm", ID: vllmID, Running: true}}}
	c := New(ConfigFromEnv(env(nil)), p, d, dir)
	c.Hold(context.Background(), "voice")
	c2 := New(ConfigFromEnv(env(nil)), p, d, dir)
	if r := c2.Report(); r.State != StateHeld || r.Reason != "voice" || !c2.Holds("vllm") {
		t.Fatalf("hold lost across restart: %+v", r)
	}
}

func TestResumeSkipsBackendNoLongerPlaced(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 11000)
	tickFor(c, clk, 60*time.Second)
	c.SetPlacements(nil) // unplaced while paused
	p.r = pidReading(0, 0)
	tickFor(c, clk, 3*time.Minute)
	if len(d.starts) != 0 {
		t.Fatalf("an unplaced backend must stay down: %v", d.starts)
	}
}

func TestReportJSONShape(t *testing.T) {
	c, p, _, _ := rig(t, nil)
	p.r = pidReading(8000, 3000)
	c.Tick(context.Background())
	b, _ := json.Marshal(c.Report())
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"state", "foreign_mb", "total_mb", "free_mb", "method", "since", "paused_backends"} {
		if _, ok := m[k]; !ok {
			t.Errorf("gpu_contention lacks %q: %s", k, b)
		}
	}
	if fmt.Sprint(m["paused_backends"]) != "[]" {
		t.Errorf("paused_backends must be [] (never null) when nothing is paused: %s", b)
	}
}

func TestConfigFromEnv(t *testing.T) {
	c := ConfigFromEnv(env(map[string]string{"NOO_GPU_YIELD_FOREIGN_MB": "4096", "NOO_GPU_RESUME_AFTER_S": "300"}))
	if !c.Enabled || c.ForeignMB != 4096 || c.ResumeAfter != 300*time.Second || c.YieldAfter != 60*time.Second {
		t.Fatalf("%+v", c)
	}
}

func TestPausedBackendFoundRunningIsStoppedAgain(t *testing.T) {
	c, p, d, clk := rig(t, nil)
	p.r = pidReading(8000, 0)
	c.Tick(context.Background())
	c.Hold(context.Background(), "voice")
	d.ctrs[0].Running = true // a manual start, or a stop that did not take
	clk.advance(15 * time.Second)
	c.Tick(context.Background())
	if len(d.stops) != 2 || d.ctrs[0].Running {
		t.Fatalf("a paused backend running again must be stopped again: stops=%v", d.stops)
	}
}
