// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestFetchBoundedReturnsTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" || r.Method != http.MethodGet {
			t.Errorf("asked %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte("vllm:num_requests_waiting 1\n"))
	}))
	defer srv.Close()
	body, status, err := fetchBounded(t.Context(), srv.Client(), srv.URL+"/metrics")
	if err != nil || status != 200 || string(body) != "vllm:num_requests_waiting 1\n" {
		t.Fatalf("%q %d %v", body, status, err)
	}
}

// Over the bound is an error, never a truncated page (a cut exposition parses
// as a different one).
func TestFetchBoundedRefusesAnOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", backendMetricsMaxBytes+1)))
	}))
	defer srv.Close()
	if body, _, err := fetchBounded(t.Context(), srv.Client(), srv.URL+"/metrics"); err != errTooLarge || body != nil {
		t.Fatalf("an oversized body was accepted (%d bytes, %v)", len(body), err)
	}
}

func TestFetchBoundedReportsTheStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, status, err := fetchBounded(t.Context(), srv.Client(), srv.URL+"/metrics"); err != nil || status != 503 {
		t.Fatalf("%d %v", status, err)
	}
}

// Only the vLLM backends: the route is never a GET on an arbitrary container.
func TestBackendMetricsRefusesAnUnlistedBackend(t *testing.T) {
	s := &Server{}
	for _, b := range []string{"ollama", "llamacpp", "embedding", "../etc", ""} {
		req := httptest.NewRequest(http.MethodGet, "/backend-metrics/x", nil)
		req.SetPathValue("backend", b)
		rec := httptest.NewRecorder()
		s.handleBackendMetrics(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown_backend") {
			t.Fatalf("%q: %d %s", b, rec.Code, rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/backend-metrics/vllm", nil)
	req.SetPathValue("backend", "vllm")
	rec := httptest.NewRecorder()
	s.handleBackendMetrics(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no docker client: %d %s", rec.Code, rec.Body.String())
	}
}

// The route is the controller's (ctrlMW), like every route that hands back
// what this node holds.
func TestBackendMetricsRouteIsControllerOnly(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	want := `s.mux.Handle("GET /backend-metrics/{backend}", ctrlMW(http.HandlerFunc(s.handleBackendMetrics)))`
	if strings.Count(string(src), "/backend-metrics/") != 1 || !strings.Contains(string(src), want) {
		t.Fatalf("the backend-metrics route must be registered once, behind ctrlMW")
	}
}
