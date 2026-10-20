// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
)

// nativeEmbedder is a host ollama that serves the prober's endpoints and both
// embed routes, counting the embed calls it receives.
func nativeEmbedder(t *testing.T, calls *int32) *backendrt.Native {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags", "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"harrier:latest","model":"harrier:latest"}]}`))
		case "/v1/embeddings":
			atomic.AddInt32(calls, 1)
			_, _ = w.Write([]byte(`{"object":"list","model":"harrier","data":[{"object":"embedding","index":0,"embedding":[0.25,0.5]}]}`))
		case "/api/embed":
			atomic.AddInt32(calls, 1)
			_, _ = w.Write([]byte(`{"model":"harrier","embeddings":[[0.25,0.5]]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return backendrt.NewNativeAt(srv.URL)
}

func withEmbedTarget(t *testing.T, target embedtarget.Target) {
	t.Helper()
	prev := embedtarget.Get()
	embedtarget.Set(target)
	t.Cleanup(func() { embedtarget.Set(prev) })
}

// host6, 2026-10-10: the embed placement (ollama/harrier) was live and the
// host ollama answered /api/embed, yet every /embed through the agent was
// 503 no_local_embedder, because the guard looked for a Docker container
// and a Mac has none. A native embedder must be reached, with no Docker.
func TestEmbedReachesANativeEmbedderWithoutDocker(t *testing.T) {
	var calls int32
	withEmbedTarget(t, embedtarget.Target{Backend: "ollama", Model: "harrier"})
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: nativeEmbedder(t, &calls)}

	w := httptest.NewRecorder()
	s.handleEmbedProxy(w, httptest.NewRequest(http.MethodPost, "/embed", strings.NewReader(`{"input":["hello"]}`)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatal("the native embedder was never called")
	}
	if !strings.Contains(w.Body.String(), "0.25") {
		t.Errorf("the native embedder's vector is not in the answer: %s", w.Body.String())
	}
}

// The guard still holds where it means something: no native lane for the
// declared backend and no container -> the precise 503, not a dial to nowhere.
func TestEmbedStillRefusesWhenNothingServesTheDeclaredEmbedder(t *testing.T) {
	withEmbedTarget(t, embedtarget.Target{Backend: "embedding", Model: "harrier"})
	var calls int32
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: nativeEmbedder(t, &calls)}

	w := httptest.NewRecorder()
	s.handleEmbedProxy(w, httptest.NewRequest(http.MethodPost, "/embed", strings.NewReader(`{"input":["hello"]}`)))

	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "no_local_embedder") {
		t.Fatalf("status = %d body = %s, want 503 no_local_embedder", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Error("a native lane for a DIFFERENT backend must not be used")
	}
}

// A node serving two embedding spaces routes /embed by the body's model, and
// a body with no model (or an unknown one) goes to the primary target.
func TestEmbedTargetForRoutesByBodyModel(t *testing.T) {
	prev := embedtarget.All()
	t.Cleanup(func() { embedtarget.SetAll(prev) })
	embedtarget.SetAll([]embedtarget.Target{
		{Backend: "ollama", Model: "harrier"},
		{Backend: "embedding", Model: "nomic-embed-code"},
	})
	cases := map[string]string{
		`{"input":"x","model":"nomic-embed-code"}`:  "nomic-embed-code",
		`{"input":"x","model":"harrier:latest"}`:    "harrier",
		`{"input":"x"}`:                             "harrier",
		`{"input":"x","model":"something-unknown"}`: "harrier",
		`not json`: "harrier",
	}
	for body, want := range cases {
		if got := embedTargetFor([]byte(body)); got.Model != want {
			t.Errorf("embedTargetFor(%s) = %q, want %q", body, got.Model, want)
		}
	}
}

// End to end through the handler: the second space's model reaches the
// native embedder, not the primary's.
func TestEmbedHandlerUsesTheRequestedSpacesModel(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags", "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/v1/embeddings":
			b, _ := io.ReadAll(r.Body)
			var in struct {
				Model string `json:"model"`
			}
			_ = json.Unmarshal(b, &in)
			seen = append(seen, in.Model)
			_, _ = w.Write([]byte(`{"object":"list","model":"` + in.Model + `","data":[{"object":"embedding","index":0,"embedding":[1]}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	prev := embedtarget.All()
	t.Cleanup(func() { embedtarget.SetAll(prev) })
	embedtarget.SetAll([]embedtarget.Target{
		{Backend: "ollama", Model: "harrier"},
		{Backend: "ollama", Model: "nomic-embed-code"},
	})
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: backendrt.NewNativeAt(srv.URL)}
	for _, body := range []string{
		`{"input":["a"],"model":"nomic-embed-code"}`,
		`{"input":["a"]}`,
	} {
		w := httptest.NewRecorder()
		s.handleEmbedProxy(w, httptest.NewRequest(http.MethodPost, "/embed", strings.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d: %s", body, w.Code, w.Body.String())
		}
	}
	if len(seen) != 2 || seen[0] != "nomic-embed-code" || seen[1] != "harrier" {
		t.Errorf("backend saw models %v, want [nomic-embed-code harrier]", seen)
	}
}
