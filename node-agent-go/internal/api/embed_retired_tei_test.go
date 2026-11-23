// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
)

// The TEI engine is gone from core (0.6.30). /embed no longer falls back to
// its dialect for an engine it has no dialect for: it says which engine, that
// TEI was removed in 0.6.30, and what to place instead.

// embedDockerWithContainer is a docker daemon that lists one container, so
// the /embed guard sees an embedder container.
func embedDockerWithContainer(t *testing.T, name string) *dockerpkg.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/containers/json") {
			_, _ = w.Write([]byte(`[{"Id":"e1","Names":["/` + name + `"],"Image":"x/y:1","Labels":{}}]`))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	dc, err := dockerpkg.NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return dc
}

// errMessage is the proxy error's decoded message (the body JSON-escapes <, >).
func errMessage(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Error struct{ Message string }
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("not an error body: %s", body)
	}
	return e.Error.Message
}

// A placement left in desired state on the removed `embedding` backend: no
// door is dialled; the answer names the engine, TEI, and the replacement.
func TestEmbedForTheRemovedTEIBackendIsAClearError(t *testing.T) {
	withEmbedTarget(t, embedtarget.Target{Backend: "embedding", Model: "BAAI/bge-base-en-v1.5"})
	var calls int32
	s := &Server{cfg: &config.Config{NodeID: "node-a"}, mux: http.NewServeMux(), native: nativeEmbedder(t, &calls)}
	w := httptest.NewRecorder()
	s.handleEmbedProxy(w, httptest.NewRequest(http.MethodPost, "/embed", strings.NewReader(`{"input":["hello"]}`)))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "embedder_engine_unsupported") {
		t.Errorf("no error code: %s", w.Body.String())
	}
	msg := errMessage(t, w.Body.String())
	for _, want := range []string{`"embedding"`, "TEI", "was removed in 0.6.30", "noo cluster place node-a ollama <model> --role embed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Error("an embedder was called for the removed engine")
	}
}

// An engine with no dialect whose OpenAI route answers 404: not TEI's
// `POST /embed {inputs}` (what this used to send), a clear error naming the
// engine.
func TestEmbedWithAnUnknownEngineIsNotSpokenToInTEIsDialect(t *testing.T) {
	var embedHits int32
	emb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/embed" {
			atomic.AddInt32(&embedHits, 1) // TEI's native route
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(emb.Close)
	t.Setenv("NOO_LOCAL_EMBED_URL", emb.URL)
	withEmbedTarget(t, embedtarget.Target{Backend: "mystery-engine", Model: "m"})
	s := &Server{cfg: &config.Config{NodeID: "node-a"}, mux: http.NewServeMux(),
		docker: embedDockerWithContainer(t, "noo-embedder")}
	w := httptest.NewRecorder()
	s.handleEmbedProxy(w, httptest.NewRequest(http.MethodPost, "/embed", strings.NewReader(`{"input":["hello"]}`)))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "embedder_engine_unsupported") {
		t.Errorf("no error code: %s", w.Body.String())
	}
	msg := errMessage(t, w.Body.String())
	for _, want := range []string{`"mystery-engine"`, "no embed dialect", "TEI dialect is no longer a fallback"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	if atomic.LoadInt32(&embedHits) != 0 {
		t.Error("the TEI dialect (POST /embed) was spoken at an engine with no dialect")
	}
}

// No declared embedder is a 503 that says how to declare one, not a dial to a
// TEI door that no longer exists.
func TestEmbedWithNoDeclaredEmbedderIs503WithTheRemedy(t *testing.T) {
	withEmbedTarget(t, embedtarget.Target{})
	t.Setenv("NOO_LOCAL_EMBED_URL", "")
	s := &Server{cfg: &config.Config{NodeID: "node-a"}, mux: http.NewServeMux()}
	w := httptest.NewRecorder()
	s.handleEmbedProxy(w, httptest.NewRequest(http.MethodPost, "/embed", strings.NewReader(`{"input":["hello"]}`)))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "no_local_embedder") ||
		!strings.Contains(errMessage(t, w.Body.String()), "noo cluster place node-a ollama <model> --role embed") {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
}
