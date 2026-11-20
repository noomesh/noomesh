// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

func backendStartRefusals() []refusals.Refusal {
	var out []refusals.Refusal
	for _, r := range refusals.List() {
		if r.Scope == "backend_start" && r.Target == "ollama" {
			out = append(out, r)
		}
	}
	return out
}

// A refused model is reported ONCE per state: re-checks that find the same
// refusal neither re-announce it nor restart its clock, and a tick that sees
// the container converged does not clear it.
func TestOllamaVerifyRefusalReportedOncePerState(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	state := dockerpkg.OllamaRefused
	l := newOllamaVerifyLoop(func(_ context.Context, model string, _ string) dockerpkg.OllamaVerifyResult {
		return dockerpkg.OllamaVerifyResult{Model: model, State: state, Anchor: dockerpkg.OllamaAnchorMirror,
			Blob: "sha256:aa", Reason: model + ": blob sha256:aa ... run `noo models pull " + model + "`"}
	}, nil)
	r := &Reconciler{ollamaVerify: l}

	l.runPass(context.Background(), []string{"llama3.2:1b"}, dockerpkg.OllamaLaneContainer)
	first := backendStartRefusals()
	if len(first) != 1 {
		t.Fatalf("want one backend_start refusal, got %+v", refusals.List())
	}
	for i := 0; i < 3; i++ {
		// A converged tick, then another check with the same verdict.
		r.clearBackendStart("ollama")
		l.runPass(context.Background(), []string{"llama3.2:1b"}, dockerpkg.OllamaLaneContainer)
	}
	again := backendStartRefusals()
	if len(again) != 1 || again[0].Since != first[0].Since {
		t.Fatalf("the refusal flapped or restarted: %+v then %+v", first, again)
	}
	if l.refusalsLogged != 1 {
		t.Fatalf("refusal announced %d times, want once", l.refusalsLogged)
	}

	// Fixed: the loop clears it, and the converged tick then clears too.
	state = dockerpkg.OllamaVerified
	l.runPass(context.Background(), []string{"llama3.2:1b"}, dockerpkg.OllamaLaneContainer)
	if got := backendStartRefusals(); len(got) != 0 {
		t.Fatalf("a verified model left the refusal standing: %+v", got)
	}
}

// A refused model is reported absent so the controller routes it elsewhere;
// the daemon (and the node's other models) keep running.
func TestOllamaVerifyRefusedModelReportedAbsent(t *testing.T) {
	refusals.Reset()
	modelpresence.Reset()
	t.Cleanup(func() { refusals.Reset(); modelpresence.Reset() })
	l := newOllamaVerifyLoop(func(_ context.Context, model string, _ string) dockerpkg.OllamaVerifyResult {
		st := dockerpkg.OllamaVerified
		if model == "bad:1b" {
			st = dockerpkg.OllamaRefused
		}
		return dockerpkg.OllamaVerifyResult{Model: model, State: st}
	}, nil)
	r := &Reconciler{ollamaVerify: l}
	rows := []placement{
		{Backend: "ollama", Model: "good:1b", Role: "chat", DesiredState: "running"},
		{Backend: "ollama", Model: "bad:1b", Role: "embed", DesiredState: "running"},
	}
	modelpresence.Set("ollama", modelpresence.Entry{Model: "good:1b", Role: "chat", Present: true})
	modelpresence.Set("ollama#embed", modelpresence.Entry{Model: "bad:1b", Role: "embed", Present: true})
	l.runPass(context.Background(), []string{"good:1b", "bad:1b"}, dockerpkg.OllamaLaneContainer)
	r.verifyOllamaModels(context.Background(), rows, dockerpkg.OllamaLaneContainer)
	p := modelpresence.Report()
	if !p["ollama"].Present {
		t.Errorf("the verified model was reported absent: %+v", p)
	}
	if p["ollama#embed"].Present {
		t.Errorf("the refused model is still reported present: %+v", p)
	}
}

// The tick only schedules: the pass runs in its own goroutine, and a slow
// one never blocks the tick or runs twice at once.
func TestOllamaVerifyRunsOffTick(t *testing.T) {
	release := make(chan struct{})
	calls := make(chan string, 4)
	l := newOllamaVerifyLoop(func(_ context.Context, model string, _ string) dockerpkg.OllamaVerifyResult {
		calls <- model
		<-release
		return dockerpkg.OllamaVerifyResult{Model: model, State: dockerpkg.OllamaVerified}
	}, nil)
	done := make(chan struct{})
	go func() {
		l.schedule(context.Background(), []string{"m:1b"}, dockerpkg.OllamaLaneContainer)
		l.schedule(context.Background(), []string{"m:1b"}, dockerpkg.OllamaLaneContainer)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("schedule blocked on the verification")
	}
	<-calls
	close(release)
	select {
	case m := <-calls:
		t.Fatalf("a second pass ran while one was in flight: %s", m)
	case <-time.After(50 * time.Millisecond):
	}
}

// The adopted lane's runtime reaches the verifier: the controller's own node
// ("stack") checks the stack's store, a Mac ("native") its host Ollama's, and
// an adopted lane is never checked as the agent's container (which repairs).
func TestOllamaVerifyAdoptedLaneIsTheRuntimes(t *testing.T) {
	for rt, want := range map[string]string{
		"stack":  dockerpkg.OllamaLaneStack,
		"native": dockerpkg.OllamaLaneNative,
		"":       dockerpkg.OllamaLaneNative,
	} {
		if got := adoptedLane(rt); got != want {
			t.Errorf("adoptedLane(%q) = %q, want %q", rt, got, want)
		}
	}
}

// reportedModels is the report's model names, in order.
func reportedModels(t *testing.T, l *ollamaVerifyLoop) []string {
	t.Helper()
	rows, _ := l.report().([]dockerpkg.OllamaVerifyResult)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Model)
	}
	return out
}

func reportedRow(t *testing.T, l *ollamaVerifyLoop, model string) dockerpkg.OllamaVerifyResult {
	t.Helper()
	rows, _ := l.report().([]dockerpkg.OllamaVerifyResult)
	for _, r := range rows {
		if r.Model == model {
			return r
		}
	}
	t.Fatalf("%s is not in the report: %+v", model, rows)
	return dockerpkg.OllamaVerifyResult{}
}

// blockedLoop is a loop whose checks never finish during the test: after an
// agent restart, nothing has a result yet.
func blockedLoop(t *testing.T) *ollamaVerifyLoop {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return newOllamaVerifyLoop(func(_ context.Context, model string, _ string) dockerpkg.OllamaVerifyResult {
		<-release
		return dockerpkg.OllamaVerifyResult{Model: model, State: dockerpkg.OllamaVerified}
	}, nil)
}

// i1067: after a restart (no results), every scheduled model is in the
// report, before its check has run.
func TestOllamaVerifyScheduledModelsAreReportedBeforeTheirCheck(t *testing.T) {
	l := blockedLoop(t)
	l.schedule(context.Background(), []string{"qwen2.5:0.5b", "harrier"}, dockerpkg.OllamaLaneStack)
	got := reportedModels(t, l)
	if len(got) != 2 || got[0] != "harrier" || got[1] != "qwen2.5:0.5b" {
		t.Fatalf("report = %v, want both scheduled models", got)
	}
}

// i1067: a model not checked yet is a pending row: its state, the reason,
// its lane, and no anchor or remedy.
func TestOllamaVerifyUncheckedModelIsAPendingRow(t *testing.T) {
	l := newOllamaVerifyLoop(nil, nil)
	l.list([]string{"harrier"}, dockerpkg.OllamaLaneStack)
	r := reportedRow(t, l, "harrier")
	if r.State != dockerpkg.OllamaPending || r.Reason != "not yet checked (the agent checks it on its next pass)" ||
		r.Lane != dockerpkg.OllamaLaneStack || r.Remedy != "" || r.Anchor != "" || r.CheckedAt != "" {
		t.Fatalf("pending row = %+v", r)
	}
}

// i1067: a model with a result shows the result, not a pending row.
func TestOllamaVerifyCheckedModelShowsItsResult(t *testing.T) {
	l := newOllamaVerifyLoop(func(_ context.Context, model string, _ string) dockerpkg.OllamaVerifyResult {
		return dockerpkg.OllamaVerifyResult{Model: model, State: dockerpkg.OllamaUnverified, Anchor: dockerpkg.OllamaAnchorNone, Reason: "no controller record"}
	}, nil)
	l.list([]string{"harrier", "qwen2.5:0.5b"}, dockerpkg.OllamaLaneStack)
	l.runPass(context.Background(), []string{"harrier"}, dockerpkg.OllamaLaneStack)
	if r := reportedRow(t, l, "harrier"); r.State != dockerpkg.OllamaUnverified || r.Reason != "no controller record" {
		t.Fatalf("harrier = %+v, want its result", r)
	}
}

// i1067: retain drops a model no longer placed from the report, checked
// or not.
func TestOllamaVerifyRetainDropsAnUnplacedModelFromTheReport(t *testing.T) {
	l := newOllamaVerifyLoop(nil, nil)
	l.list([]string{"harrier", "qwen2.5:0.5b"}, dockerpkg.OllamaLaneStack)
	l.retain([]string{"qwen2.5:0.5b"})
	if got := reportedModels(t, l); len(got) != 1 || got[0] != "qwen2.5:0.5b" {
		t.Fatalf("report = %v, want harrier dropped", got)
	}
}

// selfNodeRows is the controller's own node with an agent-run embedder: a
// chat model and harrier on the stack's Ollama.
var selfNodeRows = []placement{
	{Backend: "ollama", Model: "qwen2.5:0.5b", Role: "chat", DesiredState: "running"},
	{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running"},
}

// i1067, the source of the flap: each model's presence is its own
// /api/tags read, and a failed read clears it (unknown). A model unknown on
// a tick is not checked then, but stays in the report: the model set is the
// same on every pass, whichever reads failed.
func TestOllamaVerifyModelSetIsStableAcrossPasses(t *testing.T) {
	modelpresence.Reset()
	t.Cleanup(modelpresence.Reset)
	l := blockedLoop(t)
	r := &Reconciler{ollamaVerify: l}
	want := "harrier,qwen2.5:0.5b"
	for i, harrierKnown := range []bool{false, true, false} {
		modelpresence.Set("ollama", modelpresence.Entry{Model: "qwen2.5:0.5b", Role: "chat", Present: true})
		if harrierKnown {
			modelpresence.Set("ollama#embed", modelpresence.Entry{Model: "harrier", Role: "embed", Present: true})
		} else {
			modelpresence.Clear("ollama#embed")
		}
		r.verifyOllamaModels(context.Background(), selfNodeRows, dockerpkg.OllamaLaneStack)
		if got := strings.Join(reportedModels(t, l), ","); got != want {
			t.Fatalf("pass %d (harrier read ok=%v): report = %s, want %s", i, harrierKnown, got, want)
		}
	}
}

// i1067: a placed model the server answered it does NOT hold (and never
// checked) is not reported: only what the node holds, or may hold.
func TestOllamaVerifyKnownAbsentModelIsNotReported(t *testing.T) {
	modelpresence.Reset()
	t.Cleanup(modelpresence.Reset)
	l := blockedLoop(t)
	r := &Reconciler{ollamaVerify: l}
	modelpresence.Set("ollama", modelpresence.Entry{Model: "qwen2.5:0.5b", Role: "chat", Present: true})
	modelpresence.Set("ollama#embed", modelpresence.Entry{Model: "harrier", Role: "embed", Present: false})
	r.verifyOllamaModels(context.Background(), selfNodeRows, dockerpkg.OllamaLaneStack)
	if got := reportedModels(t, l); len(got) != 1 || got[0] != "qwen2.5:0.5b" {
		t.Fatalf("report = %v, want only the held model", got)
	}
}

// harrierPasses runs one verifyOllamaModels pass per entry on the self-node
// rows: qwen always read, harrier read (held) when the entry is "", else its
// read fails with that error.
func harrierPasses(t *testing.T, passes ...string) *ollamaVerifyLoop {
	t.Helper()
	modelpresence.Reset()
	t.Cleanup(modelpresence.Reset)
	l := blockedLoop(t)
	r := &Reconciler{ollamaVerify: l}
	for _, fail := range passes {
		modelpresence.Set("ollama", modelpresence.Entry{Model: "qwen2.5:0.5b", Role: "chat", Present: true})
		if fail == "" {
			modelpresence.Set("ollama#embed", modelpresence.Entry{Model: "harrier", Role: "embed", Present: true})
		} else {
			modelpresence.Clear("ollama#embed")
			l.notePresenceErr("harrier", errors.New(fail))
		}
		r.verifyOllamaModels(context.Background(), selfNodeRows, dockerpkg.OllamaLaneStack)
	}
	return l
}

// i1067: under the limit a model whose presence read failed is still
// "not yet": pending.
func TestOllamaVerifyTwoFailedReadsArePending(t *testing.T) {
	l := harrierPasses(t, "timeout", "timeout")
	if r := reportedRow(t, l, "harrier"); r.State != dockerpkg.OllamaPending {
		t.Fatalf("harrier after 2 failed reads = %+v, want pending", r)
	}
}

// i1067: pending is for "not yet", never "cannot": the third consecutive
// failed read is a could-not-be-checked row with the count and the last
// error.
func TestOllamaVerifyThreeFailedReadsAreCouldNotBeChecked(t *testing.T) {
	l := harrierPasses(t, "e1", "e2", "boom")
	r := reportedRow(t, l, "harrier")
	if r.State != dockerpkg.OllamaVerifyErr ||
		r.Reason != "could not be checked: its presence could not be read 3 times: boom" ||
		r.Lane != dockerpkg.OllamaLaneStack || r.Remedy != "" {
		t.Fatalf("harrier after 3 failed reads = %+v", r)
	}
}

// i1067: a successful read resets the count: only consecutive failures
// count.
func TestOllamaVerifyAReadResetsTheFailureCount(t *testing.T) {
	l := harrierPasses(t, "e1", "e2", "", "e3")
	if r := reportedRow(t, l, "harrier"); r.State != dockerpkg.OllamaPending {
		t.Fatalf("harrier = %+v, want pending (the read in between resets the count)", r)
	}
}

// i1067: the last error is kept bounded.
func TestOllamaVerifyTheReadErrorIsBounded(t *testing.T) {
	long := strings.Repeat("x", 300)
	l := harrierPasses(t, long, long, long)
	r := reportedRow(t, l, "harrier")
	want := "could not be checked: its presence could not be read 3 times: " + strings.Repeat("x", 200)
	if r.Reason != want {
		t.Fatalf("reason is %d bytes, want %d: %q", len(r.Reason), len(want), r.Reason)
	}
}
