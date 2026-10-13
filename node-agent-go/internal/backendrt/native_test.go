// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendrt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stub returns a Native pointed at a fake ollama, bypassing NewNative's
// platform gate so the behaviour is testable on the Linux CI runner. The gate
// itself is asserted separately below.
func stub(t *testing.T, h http.HandlerFunc) *Native {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Native{client: &http.Client{Timeout: 2 * time.Second}, ollamaBase: srv.URL}
}

// A native ollama with a model loaded is reported like any other backend.
// The KEY must be "ollama" — the same key the container runtime uses — or the
// gateway, the scheduler and every placement path would need to learn a second
// name for the same thing.
func TestRunningReportsTheLoadedModel(t *testing.T) {
	n := stub(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen3:8b","model":"qwen3:8b"}]}`))
		default:
			w.WriteHeader(404)
		}
	})
	got := n.Running(context.Background())
	if got["ollama"] != "qwen3:8b" {
		t.Errorf("Running = %v, want ollama -> qwen3:8b", got)
	}
}

// A fresh install serves with nothing loaded. That is RUNNING with an empty
// model, not absent: the backend is reachable and can serve, and omitting it
// would hide a usable backend — which is the bug this package exists to fix,
// reproduced one level down.
func TestAServerWithNoModelLoadedIsStillRunning(t *testing.T) {
	n := stub(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			w.WriteHeader(404)
		}
	})
	got := n.Running(context.Background())
	model, present := got["ollama"]
	if !present {
		t.Fatal("a running ollama with no model loaded must still be reported")
	}
	if model != "" {
		t.Errorf("model = %q, want empty (running, nothing loaded)", model)
	}
}

// Nothing listening must report nothing. An empty map, never a phantom entry:
// a backend claimed but absent is worse than one missed, because the scheduler
// would dispatch to it.
func TestNothingListeningReportsNothing(t *testing.T) {
	n := &Native{client: &http.Client{Timeout: 200 * time.Millisecond}, ollamaBase: "http://127.0.0.1:1"}
	if got := n.Running(context.Background()); len(got) != 0 {
		t.Errorf("Running = %v, want empty", got)
	}
}

// The platform gate returns nil off darwin rather than an inert prober, so
// "no native lane here" and "native lane found nothing" stay distinguishable.
func TestNewNativeIsDarwinOnly(t *testing.T) {
	got := NewNative()
	if runtime.GOOS == "darwin" && got == nil {
		t.Error("darwin must have a native lane")
	}
	if runtime.GOOS != "darwin" && got != nil {
		t.Errorf("%s must have no native lane, got %#v", runtime.GOOS, got)
	}
}

// Every method must tolerate the nil this returns off darwin, because callers
// hold it unconditionally and a platform check at each call site is exactly
// the sort of thing that gets forgotten once.
func TestNilProberIsSafe(t *testing.T) {
	var n *Native
	if got := n.Running(context.Background()); len(got) != 0 {
		t.Errorf("nil.Running = %v, want empty", got)
	}
	if _, ok := n.Endpoint("ollama"); ok {
		t.Error("nil.Endpoint must not claim ownership")
	}
}

// It owns ollama and nothing else. Claiming a backend it cannot reach would
// make the reconciler skip a container it should have started.
func TestOwnsOnlyOllama(t *testing.T) {
	n := &Native{client: http.DefaultClient, ollamaBase: "http://127.0.0.1:11434"}
	if _, ok := n.Endpoint("ollama"); !ok {
		t.Error("must own ollama")
	}
	for _, b := range []string{"llamacpp", "vllm", "airllm", "embedding", ""} {
		if _, ok := n.Endpoint(b); ok {
			t.Errorf("must not claim %q — nothing native serves it yet", b)
		}
	}
}

func TestHasModelAndPullOverTheLoopbackAPI(t *testing.T) {
	var pulled []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"harrier:latest","model":"harrier:latest"},{"name":"llama3.2:3b","model":"llama3.2:3b"}]}`))
		case "/api/pull":
			var req struct {
				Name   string `json:"name"`
				Stream bool   `json:"stream"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Stream {
				t.Errorf("pull must be non-streaming")
			}
			pulled = append(pulled, req.Name)
			if req.Name == "nope:1b" {
				w.WriteHeader(500)
				_, _ = w.Write([]byte(`{"error":"pull model manifest: file does not exist"}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"success"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	n := NewNativeAt(srv.URL)
	ctx := context.Background()

	for name, want := range map[string]bool{"harrier": true, "harrier:latest": true, "llama3.2:3b": true, "llama3.2": false, "gemma4:12b": false} {
		got, err := n.HasModel(ctx, name)
		if err != nil || got != want {
			t.Errorf("HasModel(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
	if st, err := n.Pull(ctx, "gemma4:12b"); err != nil || st != "success" {
		t.Fatalf("Pull = %q, %v", st, err)
	}
	if _, err := n.Pull(ctx, "nope:1b"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a failed pull must surface ollama's error, got %v", err)
	}
	if len(pulled) != 2 {
		t.Fatalf("expected 2 pulls, got %v", pulled)
	}
}

func TestNoNativeLaneRefusesModelOps(t *testing.T) {
	var n *Native
	if _, err := n.HasModel(context.Background(), "x"); err == nil {
		t.Fatal("nil lane must refuse HasModel")
	}
	if _, err := n.Pull(context.Background(), "x"); err == nil {
		t.Fatal("nil lane must refuse Pull")
	}
}

func TestAdoptedLaneIsTheStackOnTheSelfNode(t *testing.T) {
	t.Setenv("NOO_SELF_NODE", "1")
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:11434/")
	n := NewAdopted()
	if n == nil || n.Runtime() != "stack" {
		t.Fatalf("self-node must get the stack lane, got %+v", n)
	}
	if base, ok := n.Endpoint("ollama"); !ok || base != "http://127.0.0.1:11434" {
		t.Fatalf("stack lane endpoint = %q, %v", base, ok)
	}
	t.Setenv("NOO_SELF_NODE", "no")
	if n := NewAdopted(); n != nil && n.Runtime() == "stack" {
		t.Fatal("NOO_SELF_NODE=no must not select the stack lane")
	}
	var none *Native
	if none.Runtime() != "" {
		t.Fatal("no lane, no runtime label")
	}
}

func TestHeldModelIsReportedWhenNothingIsLoaded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"gemma4:12b","model":"gemma4:12b"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	n := NewNativeAt(srv.URL)
	if got := n.Running(context.Background())["ollama"]; got != "" {
		t.Fatalf("nothing held or loaded → empty, got %q", got)
	}
	n.SetHeld("gemma4:12b")
	if got := n.Running(context.Background())["ollama"]; got != "gemma4:12b" {
		t.Fatalf("held model must be advertised when nothing is loaded, got %q", got)
	}
	var none *Native
	none.SetHeld("x") // must not panic
}

// The defect this store exists for: the instance that RECORDS the held model
// and the instance that REPORTS it are different objects.
//
// `NewAdopted()` is called in three places — the Agent (whose instance the
// heartbeat reads), the API server, and inside the reconciler (whose instance
// calls SetHeld). With the model on a struct field, the reconciler wrote it
// where nothing reporting would look: the agent log said
// `running_model: gemma4:12b` every tick while the heartbeat said "ollama" with
// no model, so the gateway's resolver dropped the node and never routed to it.
func TestHeldModelIsVisibleToEveryInstanceOfTheSameServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"gemma4:12b"}]}`))
		case "/api/ps":
			// Idle: nothing loaded. This is the state most of the time, and
			// the state in which the held model is the only thing to report.
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	recorder := NewStackAt(srv.URL) // stands in for the reconciler's instance
	reporter := NewStackAt(srv.URL) // stands in for the Agent's

	if got := reporter.Running(context.Background())["ollama"]; got != "" {
		t.Fatalf("nothing placed yet, so nothing held: got %q", got)
	}

	recorder.SetHeld("gemma4:12b")

	if got := reporter.Running(context.Background())["ollama"]; got != "gemma4:12b" {
		t.Errorf("the heartbeat's instance must see what the reconciler recorded: got %q", got)
	}

	// Clearing is visible across instances too, or a stale model outlives the
	// placement that justified it.
	recorder.SetHeld("")
	if got := reporter.Running(context.Background())["ollama"]; got != "" {
		t.Errorf("a cleared placement must stop being advertised: got %q", got)
	}
}

// Two different servers must not share one another's held model: a Mac's native
// ollama and the controller's stack ollama are different machines' state.
func TestHeldModelsAreNotSharedBetweenDifferentServers(t *testing.T) {
	a := NewStackAt("http://127.0.0.1:59991")
	b := NewStackAt("http://127.0.0.1:59992")
	a.SetHeld("gemma4:12b")
	if got := b.heldModel(); got != "" {
		t.Errorf("a second server must not inherit the first's held model: got %q", got)
	}
	if got := a.heldModel(); got != "gemma4:12b" {
		t.Errorf("the first server kept its own: got %q", got)
	}
}

// the backend's identity is the model it was PLACED to serve, not
// whatever the server happens to have loaded. On the self-node one ollama
// serves chat and embeddings, so after an embedding batch /api/ps shows the
// embedder; a heartbeat that reported THAT as the chat backend's model sent
// a chat turn to an embedding model, which refused it.
func TestPlacedModelWinsOverALoadedOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3.2:3b"},{"name":"harrier:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"harrier:latest","model":"harrier:latest"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	n := NewNativeAt(srv.URL)
	n.SetHeld("")
	// Nothing placed yet: the loaded model is the best available answer.
	if got := n.Running(context.Background())["ollama"]; got != "harrier:latest" {
		t.Fatalf("nothing held → loaded model, got %q", got)
	}
	n.SetHeld("llama3.2:3b")
	defer n.SetHeld("")
	if got := n.Running(context.Background())["ollama"]; got != "llama3.2:3b" {
		t.Fatalf("placed model must be the backend's identity, got %q", got)
	}
	// The loaded model is still visible — as what it is.
	if got := n.Loaded(context.Background())["ollama"]; got != "harrier:latest" {
		t.Fatalf("Loaded must report /api/ps, got %q", got)
	}
	var none *Native
	if len(none.Loaded(context.Background())) != 0 {
		t.Fatal("nil lane reports nothing loaded")
	}
}
