// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeChatBackend streams OpenAI chunks with fixed delays: the one-token
// load probe answers after loadDelay, the long run sends its first token
// after ttft and nine more 20 ms apart. withUsage controls the usage chunk.
func fakeChatBackend(t *testing.T, loadDelay, ttft time.Duration, withUsage bool, seen *atomic.Value) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if seen != nil {
			seen.Store(body)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		chunk := func(s string) {
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", s)
			fl.Flush()
		}
		usage := func(p, c int) {
			if withUsage {
				fmt.Fprintf(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":%d,\"completion_tokens\":%d}}\n\n", p, c)
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
			fl.Flush()
		}
		if body["max_tokens"] == float64(1) {
			time.Sleep(loadDelay)
			chunk("OK")
			usage(14, 1)
			return
		}
		// Headers out first (as a streaming backend sends them), then prefill.
		fmt.Fprint(w, ": prefill\n\n")
		fl.Flush()
		time.Sleep(ttft)
		chunk("The")
		for i := 0; i < 9; i++ {
			time.Sleep(20 * time.Millisecond)
			chunk(" word")
		}
		usage(8000, 10)
	}))
}

func benchServer(backend *httptest.Server) *Server {
	s := &Server{}
	s.benchResolve = func(context.Context) (benchTarget, error) {
		return benchTarget{
			backend: "ollama", model: "gemma4:12b", served: "gemma4:12b",
			url:    backend.URL + "/v1/chat/completions",
			client: &http.Client{Transport: s.inferenceTransport("http", benchBudget)},
		}, nil
	}
	return s
}

func postBench(s *Server) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handleBench(rec, httptest.NewRequest("POST", "/bench", nil))
	return rec
}

func TestBenchMeasuresLoadPrefillAndDecode(t *testing.T) {
	var seen atomic.Value
	backend := fakeChatBackend(t, 100*time.Millisecond, 300*time.Millisecond, true, &seen)
	defer backend.Close()
	s := benchServer(backend)
	if s.LastBench() != nil {
		t.Fatal("no bench before one has run")
	}
	rec := postBench(s)
	if rec.Code != 200 {
		t.Fatalf("bench: %d %s", rec.Code, rec.Body)
	}
	var b ModelBench
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Model != "gemma4:12b" || b.Backend != "ollama" || b.PromptTokens != 8000 {
		t.Errorf("identity/usage: %+v", b)
	}
	if b.LoadSecs < 0.09 || b.LoadSecs > 1 {
		t.Errorf("load_secs %v, want ~0.1", b.LoadSecs)
	}
	// 8000 tokens over ~0.3 s.
	if b.PrefillTPS < 8000/1.0 || b.PrefillTPS > 8000/0.29 {
		t.Errorf("prefill_tps %v, want ~26667", b.PrefillTPS)
	}
	// 9 tokens after the first over ~0.18 s.
	if b.DecodeTPS < 9/1.0 || b.DecodeTPS > 9/0.17 {
		t.Errorf("decode_tps %v, want ~50", b.DecodeTPS)
	}
	if _, err := time.Parse(time.RFC3339, b.At); err != nil || !strings.HasSuffix(b.At, "Z") {
		t.Errorf("at %q must be RFC 3339 UTC", b.At)
	}
	// The long run asked for usage, a 64-token answer and a stream.
	body := seen.Load().(map[string]any)
	so, _ := body["stream_options"].(map[string]any)
	if body["max_tokens"] != float64(64) || body["stream"] != true || so["include_usage"] != true || body["model"] != "gemma4:12b" {
		t.Errorf("long-run body: %v", body)
	}
	msgs := body["messages"].([]any)
	if n := len(msgs[0].(map[string]any)["content"].(string)); n < benchPromptChars {
		t.Errorf("synthetic prompt is %d chars, want >= %d", n, benchPromptChars)
	}
	// Kept for the heartbeat.
	if last := s.LastBench(); last == nil || *last != b {
		t.Errorf("LastBench = %+v, want %+v", last, b)
	}
	// The exact keys of the contract's model_bench, nothing more.
	var keys map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &keys)
	for _, k := range []string{"model", "backend", "load_secs", "prefill_tps", "decode_tps", "prompt_tokens", "at"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if len(keys) != 7 {
		t.Errorf("model_bench has extra keys: %v", keys)
	}
}

// No usage from the backend: prompt tokens are the chars/4 estimate and the
// completion count is the number of content chunks.
func TestBenchEstimatesTokensWithoutUsage(t *testing.T) {
	backend := fakeChatBackend(t, 10*time.Millisecond, 100*time.Millisecond, false, nil)
	defer backend.Close()
	rec := postBench(benchServer(backend))
	if rec.Code != 200 {
		t.Fatalf("bench: %d %s", rec.Code, rec.Body)
	}
	var b ModelBench
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if b.PromptTokens < benchPromptChars/4 || b.PromptTokens > benchPromptChars/4+100 {
		t.Errorf("prompt_tokens %d, want ~%d (chars/4)", b.PromptTokens, benchPromptChars/4)
	}
	if b.DecodeTPS <= 0 {
		t.Errorf("decode from chunk count: %v", b.DecodeTPS)
	}
}

func TestBenchRefusesWithoutAChatBackendAndWhileOneRuns(t *testing.T) {
	// No chat placement provider at all.
	if rec := postBench(&Server{}); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "no_chat_backend") {
		t.Errorf("no chat placement: %d %s", rec.Code, rec.Body)
	}
	s := &Server{}
	s.SetChatPlacement(func() (ChatPlacement, bool) { return ChatPlacement{}, false })
	if rec := postBench(s); rec.Code != http.StatusConflict {
		t.Errorf("no running chat placement: %d %s", rec.Code, rec.Body)
	}

	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer backend.Close()
	busy := benchServer(backend)
	done := make(chan int)
	go func() { done <- postBench(busy).Code }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		busy.benchMu.Lock()
		running := busy.benchRunning
		busy.benchMu.Unlock()
		if running || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if rec := postBench(busy); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "bench_busy") {
		t.Errorf("concurrent bench: %d %s", rec.Code, rec.Body)
	}
	close(release)
	if code := <-done; code != 200 {
		t.Errorf("the first bench: %d", code)
	}
}

func TestBenchReportsABackendError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"model not found"}`, http.StatusNotFound)
	}))
	defer backend.Close()
	s := benchServer(backend)
	rec := postBench(s)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "HTTP 404") {
		t.Errorf("backend error: %d %s", rec.Code, rec.Body)
	}
	if s.LastBench() != nil {
		t.Error("a failed bench must not replace the last result")
	}
}

func TestBenchRates(t *testing.T) {
	p, d := benchRates(8192, 64, 2*time.Second, 5*time.Second)
	if p != 4096 || d != 21 {
		t.Errorf("rates %v %v", p, d)
	}
	if p, d := benchRates(10, 1, 0, 0); p != 0 || d != 0 {
		t.Errorf("zero intervals must give 0, not Inf: %v %v", p, d)
	}
}

func TestBenchPromptIsDeterministicAfterTheNonce(t *testing.T) {
	a, b := benchPrompt(1), benchPrompt(2)
	strip := func(s string) string { return s[strings.Index(s, "\n"):] }
	if strip(a) != strip(b) || a == b {
		t.Error("the prompt must differ only in its nonce line")
	}
}
