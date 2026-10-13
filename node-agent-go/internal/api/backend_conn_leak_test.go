// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A per-request backend client must not leave its connection open: the agent
// built a fresh transport for every /embed and /rerank call, and a bare
// transport keeps idle connections forever, so a busy Mac embedder exhausted
// its ephemeral ports. Every connection the client opens must be closed once
// the response is read.
func TestBackendClientClosesEachConnection(t *testing.T) {
	var opened, closed atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		switch st {
		case http.StateNew:
			opened.Add(1)
		case http.StateClosed, http.StateHijacked:
			closed.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	s := &Server{}
	const n = 25
	for i := 0; i < n; i++ {
		resp, err := s.backendClient(srv.URL, 5*time.Second).Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for closed.Load() < opened.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if opened.Load() != n {
		t.Fatalf("opened %d connections for %d requests; want one each (the test must see real dials)", opened.Load(), n)
	}
	if got := opened.Load() - closed.Load(); got != 0 {
		t.Fatalf("%d of %d backend connections still open after their responses were read — the per-request transport leaks", got, n)
	}
}

func TestOneShotDisablesKeepAlive(t *testing.T) {
	if !oneShot(&http.Transport{}).DisableKeepAlives {
		t.Fatal("oneShot must disable keep-alive")
	}
	if !oneShot(httpsTransport(nil)).DisableKeepAlives {
		t.Fatal("oneShot over the https transport must disable keep-alive")
	}
}
