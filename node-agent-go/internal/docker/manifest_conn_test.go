// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// connWatch is a controller stand-in that answers a manifest (200) and
// records when each connection it accepted is closed. 200 is the case that
// leaked: the caller reads the body to EOF, so Go keeps the connection for
// reuse, in a pool nothing reuses. (A 404 closed unread is dropped by Go.)
type connWatch struct {
	mu     sync.Mutex
	open   map[net.Conn]bool
	srv    *httptest.Server
	served int
}

func newConnWatch(t *testing.T) *connWatch {
	w := &connWatch{open: map[net.Conn]bool{}}
	w.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		w.mu.Lock()
		w.served++
		w.mu.Unlock()
		rw.Header().Set("content-type", "application/json")
		_, _ = rw.Write([]byte(`{"sha256":"` + strings.Repeat("ab", 32) + `"}`))
	}))
	w.srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		w.mu.Lock()
		defer w.mu.Unlock()
		switch s {
		case http.StateNew:
			w.open[c] = true
		case http.StateClosed, http.StateHijacked:
			delete(w.open, c)
		}
	}
	w.srv.Start()
	t.Cleanup(w.srv.Close)
	t.Setenv("CONTROLLER_URL", w.srv.URL)
	t.Setenv("NOO_CLUSTER_SECRET", "")
	return w
}

// allClosedWithin is true when the server saw every connection close.
func (w *connWatch) allClosedWithin(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		n := len(w.open)
		w.mu.Unlock()
		if n == 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// 2026-11-02: each manifest lookup built its own transport with no idle
// timeout, so every request left its keep-alive connection open on both
// ends. robopi's retry loop held ~22 more an hour on the controller until
// the gateway ran out of file descriptors. A lookup now closes its
// connection when it returns.
func TestAManifestLookupLeavesNoConnectionOpen(t *testing.T) {
	w := newConnWatch(t)
	if m := fetchArtifactManifest(context.Background(), "image", "noomesh_stunnel_v0.6.15_arm64.tar"); m == nil {
		t.Fatal("fetchArtifactManifest: no manifest from a 200")
	}
	if _, err := lookupArtifactManifestWithin(context.Background(), "image", "noomesh_stunnel_v0.6.15_arm64.tar", 5*time.Second); err != nil {
		t.Fatalf("lookupArtifactManifestWithin: %v", err)
	}
	w.mu.Lock()
	served := w.served
	w.mu.Unlock()
	if served != 2 {
		t.Fatalf("both lookups should reach the controller, served %d", served)
	}
	if !w.allClosedWithin(2 * time.Second) {
		t.Fatal("a lookup left a connection open on the controller")
	}
}

// Every caller of HTTPTransport gets an idle bound, including the ones that
// build a transport per request and do not close it.
func TestTheControllerTransportDropsIdleConnections(t *testing.T) {
	tr, err := (&nodeconfig.Config{}).HTTPTransport()
	if err != nil {
		t.Fatal(err)
	}
	if tr.IdleConnTimeout != 90*time.Second || tr.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("idle %v, handshake %v", tr.IdleConnTimeout, tr.TLSHandshakeTimeout)
	}
}
