// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// windowServer is a Server whose chat backend is `backend` (a backend type)
// served by srv.
func windowServer(backend string, srv *httptest.Server) *Server {
	s := &Server{}
	s.windowResolve = func(context.Context) (benchTarget, error) {
		return benchTarget{
			backend: backend, model: "m", served: "m",
			url:    srv.URL + "/v1/chat/completions",
			client: &http.Client{Transport: s.inferenceTransport("http", benchBudget)},
		}, nil
	}
	return s
}

func TestLiveChatContextAsksTheRunningBackend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"other","max_model_len":4096},{"id":"m","max_model_len":32768}]}`))
		case "/props":
			_, _ = w.Write([]byte(`{"default_generation_settings":{"n_ctx":8192},"total_slots":2}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	for backend, want := range map[string]int{"vllm": 32768, "llamacpp": 8192, "ollama": 0} {
		if got := windowServer(backend, srv).liveChatContext(context.Background()); got != want {
			t.Errorf("%s: window %d, want %d", backend, got, want)
		}
	}
}

func TestLiveChatContextIsUnknownWhenTheBackendCannotSay(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if got := windowServer("vllm", bad).liveChatContext(context.Background()); got != 0 {
		t.Errorf("a 500: window %d, want 0", got)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer slow.Close()
	start := time.Now()
	if got := windowServer("llamacpp", slow).liveChatContext(context.Background()); got != 0 {
		t.Errorf("a hung backend: window %d, want 0", got)
	}
	if d := time.Since(start); d > chatWindowTimeout+time.Second {
		t.Errorf("a hung backend held the read %v, past its %v bound", d, chatWindowTimeout)
	}
	s := &Server{}
	s.windowResolve = func(context.Context) (benchTarget, error) { return benchTarget{}, errors.New("no chat") }
	if got := s.liveChatContext(context.Background()); got != 0 {
		t.Errorf("no chat backend: window %d, want 0", got)
	}
}

func TestBackendWindowParsers(t *testing.T) {
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{"vllm served entry", vllmMaxModelLen([]byte(`{"data":[{"id":"a","max_model_len":1},{"id":"m","max_model_len":2}]}`), "m"), 2},
		{"vllm first with a window", vllmMaxModelLen([]byte(`{"data":[{"id":"a"},{"id":"b","max_model_len":7}]}`), "m"), 7},
		{"vllm no window", vllmMaxModelLen([]byte(`{"data":[{"id":"m"}]}`), "m"), 0},
		{"vllm not json", vllmMaxModelLen([]byte(`<html>`), "m"), 0},
		{"llama per slot", llamaSlotContext([]byte(`{"default_generation_settings":{"n_ctx":4096},"n_ctx":16384}`), ""), 4096},
		{"llama older build", llamaSlotContext([]byte(`{"n_ctx":2048}`), ""), 2048},
		{"llama none", llamaSlotContext([]byte(`{}`), ""), 0},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestHarnessPlacementFallsBackToTheLiveWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"m","max_model_len":16384}]}`))
	}))
	defer srv.Close()
	for _, c := range []struct {
		agent, want int
	}{{0, 16384}, {65536, 65536}} {
		s := windowServer("vllm", srv)
		agent := c.agent
		s.SetHarnessPlacement(func() HarnessPlacement {
			return HarnessPlacement{Kind: "claude-code", Placed: true, ModelContext: agent}
		})
		rec := httptest.NewRecorder()
		s.handleHarnessPlacement(rec, httptest.NewRequest("GET", "/harness/placement", nil))
		var hp HarnessPlacement
		if err := json.Unmarshal(rec.Body.Bytes(), &hp); err != nil {
			t.Fatalf("agent %d: %v (%s)", c.agent, err, rec.Body.String())
		}
		if hp.ModelContext != c.want {
			t.Errorf("agent %d: model_context %d, want %d", c.agent, hp.ModelContext, c.want)
		}
	}
}
