// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// Followup i495 (noomesh-internal), item 1: when docker cannot be listed the
// model list and the proxy say "docker unavailable" (503), not `data: []` or
// "no backend running".

func listFailingDocker(t *testing.T) *dockerpkg.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"message":"daemon busy"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	dc, err := dockerpkg.NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return dc
}

func TestListModelsIs503WhenDockerCannotBeListed(t *testing.T) {
	s := &Server{docker: listFailingDocker(t)}
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/models", s.handleListModels)
	code, out := call(t, m, "GET", "/v1/models", "")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %v", code, out)
	}
	e, _ := out["error"].(map[string]any)
	if e["code"] != "docker_unavailable" || !strings.Contains(e["message"].(string), "daemon busy") {
		t.Fatalf("error = %v", e)
	}
	if _, has := out["data"]; has {
		t.Fatalf("must not return a model list: %v", out)
	}
}

func TestRunningAndNativeReportsDockerUnavailable(t *testing.T) {
	s := &Server{docker: listFailingDocker(t)}
	running, native, err := s.runningAndNative(t.Context())
	if err == nil || !strings.Contains(err.Error(), errDockerUnavailable.Error()) {
		t.Fatalf("err = %v, want docker unavailable", err)
	}
	if running != nil || native != nil {
		t.Fatalf("no maps on error: %v %v", running, native)
	}
}
