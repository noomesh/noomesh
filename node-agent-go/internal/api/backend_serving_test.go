// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testServing is a tracker on a fake engine with a settable clock and
// nothing in flight unless the test says so.
func testServing(t *testing.T, f *fakeEngine) (*backendServing, func(time.Duration), *atomic.Int32) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	b := newBackendServing(func(context.Context, string) (warmTarget, error) {
		return warmTarget{base: srv.URL, client: srv.Client(), model: "served-model"}, nil
	})
	clock := time.Unix(1_790_000_000, 0)
	var mu sync.Mutex
	b.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); defer mu.Unlock(); clock = clock.Add(d) }
	var inFlight atomic.Int32
	b.inFlight = func(string) int { return int(inFlight.Load()) }
	b.timeout = 200 * time.Millisecond
	return b, advance, &inFlight
}

// vllmOnly is one heartbeat's backend_containers with one engine.
func vllmOnly(started int64) map[string]any {
	return map[string]any{"vllm": map[string]any{"running": true, "started_at": started, "health": "healthy"}}
}

// settle waits for the backend's probe to finish.
func settle(t *testing.T, b *backendServing, backend string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		st := b.state[backend]
		busy := st != nil && st.probing
		b.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("probe never finished")
}

// The V2-runner wedge: healthy container, every chat hangs. The probe marks
// it not serving with a reason; once it answers again, the next recovery
// probe puts it back. Absence before any evidence keeps "serving" unsaid.
func TestAWedgedEngineIsReportedNotServingAndRecovers(t *testing.T) {
	var wedged atomic.Bool
	wedged.Store(true)
	f := &fakeEngine{chat: func(w http.ResponseWriter, r *http.Request) {
		if wedged.Load() {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}}
	b, advance, _ := testServing(t, f)
	ctx := context.Background()

	m := vllmOnly(100)
	b.gate(ctx, m)
	if _, said := vllmLife(m)["serving"]; said {
		t.Fatalf("no evidence yet, but serving was reported: %v", vllmLife(m))
	}
	settle(t, b, "vllm")
	if f.chats.Load() != 1 {
		t.Fatalf("an engine with no evidence got %d probes, want 1", f.chats.Load())
	}

	m = vllmOnly(100)
	b.gate(ctx, m)
	if s, ok := vllmLife(m)["serving"].(bool); !ok || s {
		t.Fatalf("a hung engine does not read serving=false: %v", vllmLife(m))
	}
	if r, _ := vllmLife(m)["serving_reason"].(string); !strings.Contains(r, "no answer") {
		t.Fatalf("serving_reason = %q, want the probe's timeout named", r)
	}

	// Recovered, but the recovery probe is not due yet: still not serving.
	wedged.Store(false)
	b.gate(ctx, vllmOnly(100))
	settle(t, b, "vllm")
	if f.chats.Load() != 1 {
		t.Fatalf("re-probed before probeRecoverEvery: %d probes", f.chats.Load())
	}
	advance(probeRecoverEvery)
	b.gate(ctx, vllmOnly(100))
	settle(t, b, "vllm")
	m = vllmOnly(100)
	b.gate(ctx, m)
	if s, _ := vllmLife(m)["serving"].(bool); !s {
		t.Fatalf("an engine that answers again still reads not serving: %v", vllmLife(m))
	}
	if _, has := vllmLife(m)["serving_reason"]; has {
		t.Fatalf("a serving engine carries a reason: %v", vllmLife(m))
	}
}

// One relayed failure is one bad request; two in a row with no answer
// between mark the engine. An answer clears the count, and a 5xx counts.
func TestRelayedFailuresMarkOnlyInARow(t *testing.T) {
	b, _, inFlight := testServing(t, &fakeEngine{})
	inFlight.Store(1) // busy: no probes, only what the proxy relays
	ctx := context.Background()
	verdict := func() (any, any) {
		m := report(100)
		b.gate(ctx, m)
		return vllmLife(m)["serving"], vllmLife(m)["serving_reason"]
	}

	b.fail("vllm", "relayed request failed: timeout awaiting response headers", false)
	if s, _ := verdict(); s != true {
		t.Fatalf("one failure marked the engine: serving=%v", s)
	}
	body := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("data: x\n\n"))}
	b.observe("vllm", body)
	b.fail("vllm", "relayed request failed: x", false)
	if s, _ := verdict(); s != false {
		t.Fatal("headers alone counted as an answer: the body was never read, so this failure is the second in a row")
	}
	_, _ = io.ReadAll(body.Body) // the first byte: an answer, the count clears
	if s, _ := verdict(); s != true {
		t.Fatalf("an answer did not put the engine back: serving=%v", s)
	}
	b.fail("vllm", "relayed request failed: x", false)
	if s, _ := verdict(); s != true {
		t.Fatalf("an answer did not clear the failure count: serving=%v", s)
	}
	b.observe("vllm", &http.Response{StatusCode: 502, Body: http.NoBody})
	if s, r := verdict(); s != false || r != "answered 502" {
		t.Fatalf("two failures in a row (one a 5xx): serving=%v reason=%v", s, r)
	}
}

// No probe into an engine that is busy, still warming, or not an engine;
// a recreated container starts over.
func TestProbesSkipBusyWarmingAndOllama(t *testing.T) {
	f := &fakeEngine{}
	b, _, inFlight := testServing(t, f)
	ctx := context.Background()

	inFlight.Store(1)
	b.gate(ctx, map[string]any{"vllm": map[string]any{"running": true, "started_at": int64(100)}})
	inFlight.Store(0)
	b.gate(ctx, map[string]any{
		"vllm":   map[string]any{"running": true, "started_at": int64(100), "warmup": "running"},
		"ollama": map[string]any{"running": true, "started_at": int64(100)},
	})
	settle(t, b, "vllm")
	if n := f.chats.Load(); n != 0 {
		t.Fatalf("%d probe(s) sent to a busy, warming or ollama backend", n)
	}

	b.fail("vllm", "x", true)
	m := map[string]any{"vllm": map[string]any{"running": true, "started_at": int64(200)}}
	inFlight.Store(1)
	b.gate(ctx, m)
	if _, said := vllmLife(m)["serving"]; said {
		t.Fatalf("a recreated container inherited the old one's verdict: %v", vllmLife(m))
	}
}

// The proxy feeds the tracker and the heartbeat reads it after the warmup.
func TestTheProxyAndTheHeartbeatAreWired(t *testing.T) {
	proxy, err := os.ReadFile("inference_proxy.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"serving.observe(backendType, resp)", "serving.fail(backendType, \"relayed request failed: \"+err.Error(), false)", "if req.Context().Err() == nil"} {
		if !strings.Contains(string(proxy), want) {
			t.Errorf("inference_proxy.go lacks %q", want)
		}
	}
	agent, err := os.ReadFile("../agent/agent.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(agent)
	warm, serve := strings.Index(src, "GateBackendWarmup(a.lifeCtx(), m)"), strings.Index(src, "GateBackendServing(a.lifeCtx(), m)")
	if warm < 0 || serve < warm {
		t.Fatal("agent.go must call GateBackendServing after GateBackendWarmup: it reads `warmup`")
	}
}
