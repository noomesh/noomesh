// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/embedtarget"
	"github.com/noomesh/noomesh/node-agent-go/internal/occupancy"
)

// EmbedLocal (the pull worker's door) must be the /embed handler, not a copy
// of it: same target resolution, same native lane, same status and body.
func TestEmbedLocalRunsTheSameProxyInProcess(t *testing.T) {
	var calls int32
	withEmbedTarget(t, embedtarget.Target{Backend: "ollama", Model: "harrier"})
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: nativeEmbedder(t, &calls)}

	status, body, err := s.EmbedLocal(context.Background(), []byte(`{"input":["hello"]}`))
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", status, err, body)
	}
	if atomic.LoadInt32(&calls) == 0 || !strings.Contains(string(body), "0.25") {
		t.Errorf("the embedder was not reached through the shared path: calls=%d body=%s", calls, body)
	}

	// The proxy's own refusals come back as a status, not an error.
	withEmbedTarget(t, embedtarget.Target{Backend: "embedding", Model: "harrier"})
	status, body, err = s.EmbedLocal(context.Background(), []byte(`{"input":["hello"]}`))
	if err != nil || status != http.StatusServiceUnavailable || !strings.Contains(string(body), "no_local_embedder") {
		t.Errorf("status=%d err=%v body=%s", status, err, body)
	}
}

// A query-time /embed is counted in in_flight while it runs (so the pull
// worker sees it and keeps its reserved slot free) but never queued, even on
// a full backend. EmbedLocal is NOT counted here: the worker admits its own
// job, and counting it twice would starve it.
func TestEmbedRouteIsCountedWhileItRunsAndNeverQueued(t *testing.T) {
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	occupancy.SetSlots(map[string]int{"ollama": 1})
	hold, _ := occupancy.Admit(context.Background(), "ollama") // backend full
	defer hold()

	entered := make(chan struct{}, 4)
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags", "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"harrier:latest","model":"harrier:latest"}]}`))
		case "/v1/embeddings":
			entered <- struct{}{}
			<-unblock
			_, _ = w.Write([]byte(`{"object":"list","model":"harrier","data":[{"object":"embedding","index":0,"embedding":[0.25,0.5]}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	// Runs before srv.Close (cleanups are LIFO): a failed assertion must not
	// leave the handler parked on unblock and hang the server's shutdown.
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(release)
	withEmbedTarget(t, embedtarget.Target{Backend: "ollama", Model: "harrier"})
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: backendrt.NewNativeAt(srv.URL)}

	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		s.handleEmbedProxy(w, httptest.NewRequest(http.MethodPost, "/embed", strings.NewReader(`{"input":["hello"]}`)))
		done <- w.Code
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("/embed waited for a slot on a full backend; query-time embeds must never queue")
	}
	if n := occupancy.InFlight("ollama"); n != 2 {
		t.Fatalf("in_flight during /embed = %d, want 2 (held + the embed)", n)
	}
	release()
	if code := <-done; code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if n := occupancy.InFlight("ollama"); n != 1 {
		t.Fatalf("in_flight after /embed = %d, want 1", n)
	}

	// EmbedLocal goes through the same body but is not counted by it
	// (unblock is closed now, so the embedder answers at once).
	go func() { _, _, _ = s.EmbedLocal(context.Background(), []byte(`{"input":["x"]}`)) }()
	<-entered
	if n := occupancy.InFlight("ollama"); n != 1 {
		t.Errorf("EmbedLocal was counted by the route (in_flight = %d); the worker admits its own job", n)
	}
}
