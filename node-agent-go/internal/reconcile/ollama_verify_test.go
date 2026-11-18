// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
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
	l := newOllamaVerifyLoop(func(_ context.Context, model string, native bool) dockerpkg.OllamaVerifyResult {
		return dockerpkg.OllamaVerifyResult{Model: model, State: state, Anchor: dockerpkg.OllamaAnchorMirror,
			Blob: "sha256:aa", Reason: model + ": blob sha256:aa ... run `noo models pull " + model + "`"}
	})
	r := &Reconciler{ollamaVerify: l}

	l.runPass(context.Background(), []string{"llama3.2:1b"}, false)
	first := backendStartRefusals()
	if len(first) != 1 {
		t.Fatalf("want one backend_start refusal, got %+v", refusals.List())
	}
	for i := 0; i < 3; i++ {
		// A converged tick, then another check with the same verdict.
		r.clearBackendStart("ollama")
		l.runPass(context.Background(), []string{"llama3.2:1b"}, false)
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
	l.runPass(context.Background(), []string{"llama3.2:1b"}, false)
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
	l := newOllamaVerifyLoop(func(_ context.Context, model string, _ bool) dockerpkg.OllamaVerifyResult {
		st := dockerpkg.OllamaVerified
		if model == "bad:1b" {
			st = dockerpkg.OllamaRefused
		}
		return dockerpkg.OllamaVerifyResult{Model: model, State: st}
	})
	r := &Reconciler{ollamaVerify: l}
	rows := []placement{
		{Backend: "ollama", Model: "good:1b", Role: "chat", DesiredState: "running"},
		{Backend: "ollama", Model: "bad:1b", Role: "embed", DesiredState: "running"},
	}
	modelpresence.Set("ollama", modelpresence.Entry{Model: "good:1b", Role: "chat", Present: true})
	modelpresence.Set("ollama#embed", modelpresence.Entry{Model: "bad:1b", Role: "embed", Present: true})
	l.runPass(context.Background(), []string{"good:1b", "bad:1b"}, false)
	r.verifyOllamaModels(context.Background(), rows, false)
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
	l := newOllamaVerifyLoop(func(_ context.Context, model string, _ bool) dockerpkg.OllamaVerifyResult {
		calls <- model
		<-release
		return dockerpkg.OllamaVerifyResult{Model: model, State: dockerpkg.OllamaVerified}
	})
	done := make(chan struct{})
	go func() {
		l.schedule(context.Background(), []string{"m:1b"}, false)
		l.schedule(context.Background(), []string{"m:1b"}, false)
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
