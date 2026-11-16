// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// recordingOllama is an ollama that answers the reads and records every
// request it is sent, so a test can say what the route never sent.
func recordingOllama(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/api/tags", "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func aliveRequest(s *Server, backend string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/backend-alive/"+backend, nil)
	req.SetPathValue("backend", backend)
	rec := httptest.NewRecorder()
	s.handleBackendAlive(rec, req)
	return rec
}

// The route reaches a running ollama with reads only: nothing it sends can
// load a model (no chat, no generate, no POST at all).
func TestBackendAliveReadsAnOllamaWithoutLoadingIt(t *testing.T) {
	srv, seen := recordingOllama(t)
	s := &Server{cfg: &config.Config{}, native: backendrt.NewNativeAt(srv.URL)}
	rec := aliveRequest(s, "ollama")
	if rec.Code != http.StatusOK {
		t.Fatalf("a reachable ollama: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Backend   string `json:"backend"`
		Reachable bool   `json:"reachable"`
		Status    int    `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !out.Reachable || out.Backend != "ollama" || out.Status != 200 {
		t.Fatalf("answer: %s (%v)", rec.Body.String(), err)
	}
	got := seen()
	if len(got) == 0 || got[len(got)-1] != "GET /api/tags" {
		t.Fatalf("the read the route sends is GET /api/tags: %v", got)
	}
	for _, r := range got {
		if !strings.HasPrefix(r, "GET /api/tags") && !strings.HasPrefix(r, "GET /api/ps") {
			t.Fatalf("the route sent %q to ollama; only reads (/api/tags, /api/ps) may reach it: %v", r, got)
		}
	}
}

// A dead ollama is the proxy's backend_unreachable (502), the shape the
// gateway reads as unreachable; any HTTP answer at all is reachable.
func TestWriteBackendAliveDeadAndAnsweringBackends(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL + "/api/tags"
	dead.Close() // connection refused from here on
	rec := httptest.NewRecorder()
	writeBackendAlive(t.Context(), rec, "ollama", &http.Client{}, url)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), `"backend_unreachable"`) {
		t.Fatalf("a dead ollama: %d %s", rec.Code, rec.Body.String())
	}

	sick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sick.Close()
	rec = httptest.NewRecorder()
	writeBackendAlive(t.Context(), rec, "ollama", sick.Client(), sick.URL+"/api/tags")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":500`) {
		t.Fatalf("an ollama that answered is reachable: %d %s", rec.Code, rec.Body.String())
	}
}

// Ollama only: the route is never a GET on an engine or an arbitrary name,
// and an ollama that is not running is said to be not running.
func TestBackendAliveRefusesOtherBackendsAndAbsentOllama(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	for _, b := range []string{"vllm", "llamacpp", "embedding", "../etc", ""} {
		if rec := aliveRequest(s, b); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown_backend") {
			t.Fatalf("%q: %d %s", b, rec.Code, rec.Body.String())
		}
	}
	if rec := aliveRequest(s, "ollama"); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "backend_not_running") {
		t.Fatalf("no ollama: %d %s", rec.Code, rec.Body.String())
	}
}

// Controller-only, registered once, like /backend-metrics.
func TestBackendAliveRouteIsControllerOnly(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	want := `s.mux.Handle("GET /backend-alive/{backend}", ctrlMW(http.HandlerFunc(s.handleBackendAlive)))`
	if strings.Count(string(src), `"GET /backend-alive/`) != 1 || !strings.Contains(string(src), want) {
		t.Fatalf("the backend-alive route must be registered once, behind ctrlMW")
	}
}
