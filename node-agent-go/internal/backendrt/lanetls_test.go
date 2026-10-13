// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendrt

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// door is the controller's stunnel-ollama-embed in miniature: an ollama API
// behind TLS that REQUIRES a cluster-CA client certificate (verify = 2).
// hits counts requests that got past the handshake.
func door(t *testing.T, p *preseedtest.PKI) (string, *int64) {
	t.Helper()
	var hits int64
	srv := p.Store(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"harrier:latest","model":"harrier:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/pull":
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = w.Write([]byte(`{"status":"success"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv.URL, &hits
}

// the self-node lane at an https base dials the door with the
// node leaf — probes, the inventory, HasModel and Pull all pass verify = 2.
func TestStackLaneAtAnHTTPSDoorPresentsTheNodeLeaf(t *testing.T) {
	p := preseedtest.New(t)
	p.SetNodeEnv(t)
	base, hits := door(t, p)
	if !strings.HasPrefix(base, "https://127.0.0.1:") {
		t.Fatalf("door is not an https loopback URL: %s", base)
	}
	n := NewStackAt(base)
	if n.clientErr != nil {
		t.Fatalf("lane refused to build: %v", n.clientErr)
	}
	ctx := context.Background()
	if got := n.Running(ctx); len(got) != 1 {
		t.Fatalf("the door answered but the lane reports %v", got)
	}
	if m := n.Models(ctx); len(m) != 1 || m[0] != "harrier:latest" {
		t.Fatalf("inventory through the door = %v", m)
	}
	if has, err := n.HasModel(ctx, "harrier"); err != nil || !has {
		t.Fatalf("HasModel through the door = %v, %v", has, err)
	}
	if _, err := n.Pull(ctx, "gemma4:12b"); err != nil {
		t.Fatalf("Pull through the door: %v", err)
	}
	if atomic.LoadInt64(hits) < 4 {
		t.Fatalf("only %d requests reached the door — the assertions above did not use it", *hits)
	}
}

// The same door, dialled the way the lane dialled it before 1245 (a bare
// client, no leaf), is refused at the handshake. This is the other half of
// the proof: the door is not simply open, so the leaf is what passed it.
func TestTheDoorRefusesABareClient(t *testing.T) {
	p := preseedtest.New(t)
	base, hits := door(t, p)
	bare := &http.Client{Timeout: 2 * time.Second}
	if resp, err := bare.Get(base + "/api/tags"); err == nil {
		resp.Body.Close()
		t.Fatal("a client with no leaf and no CA got through the door")
	}
	// And a client that trusts the CA but presents no leaf: verify = 2.
	p.SetNodeEnv(t)
	t.Setenv("NOO_TLS_CERT", "")
	t.Setenv("NOO_TLS_KEY", "")
	n := NewStackAt(base)
	if n.clientErr == nil {
		t.Fatal("an https lane without the node leaf must refuse to build, not dial bare")
	}
	if atomic.LoadInt64(hits) != 0 {
		t.Fatalf("%d requests got past the handshake without a leaf", *hits)
	}
}

// Without the node PKI an https lane is an ERROR carried by the lane, named,
// and no request reaches the network — never a bare client that reads as
// "no ollama here" (the preseed.go rule).
func TestAnHTTPSLaneWithoutThePKIRefusesByName(t *testing.T) {
	var hits int64
	srv := preseedtest.New(t).Store(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
	}))
	t.Setenv("NOO_TLS_CA", "")
	t.Setenv("NOO_TLS_CERT", "")
	t.Setenv("NOO_TLS_KEY", "")
	n := NewStackAt(srv.URL)
	for _, want := range []string{"NOO_TLS_CA", "NOO_TLS_CERT", "NOO_TLS_KEY", "provision"} {
		if n.clientErr == nil || !strings.Contains(n.clientErr.Error(), want) {
			t.Fatalf("error does not name %s: %v", want, n.clientErr)
		}
	}
	ctx := context.Background()
	if _, err := n.HasModel(ctx, "x"); err == nil {
		t.Fatal("HasModel must return the lane's error")
	}
	if _, err := n.Pull(ctx, "x"); err == nil || !strings.Contains(err.Error(), "NOO_TLS_CERT") {
		t.Fatalf("Pull must return the lane's error, got %v", err)
	}
	if len(n.Running(ctx)) != 0 || n.Models(ctx) != nil {
		t.Fatal("a lane with no client reported a server")
	}
	if hits != 0 {
		t.Fatalf("%d requests reached the network from a lane that could not build a client", hits)
	}
}

// A configured-but-unreadable leaf is an error too, not a bare client.
func TestAnHTTPSLaneWithAnUnreadableLeafRefuses(t *testing.T) {
	p := preseedtest.New(t)
	p.SetNodeEnv(t)
	t.Setenv("NOO_TLS_CERT", filepath.Join(t.TempDir(), "missing.crt"))
	n := NewStackAt("https://127.0.0.1:1")
	if n.clientErr == nil || !strings.Contains(n.clientErr.Error(), "missing.crt") {
		t.Fatalf("unreadable leaf not refused by name: %v", n.clientErr)
	}
}

// http loopback — a native host ollama (the documented plaintext exception) —
// keeps the bare transport it always had, PKI or not.
func TestAnHTTPLaneStaysPlain(t *testing.T) {
	p := preseedtest.New(t)
	p.SetNodeEnv(t)
	for _, base := range []string{"http://127.0.0.1:11434", "http://localhost:11434"} {
		tr, err := laneTransport(base)
		if err != nil || tr != nil {
			t.Fatalf("%s: transport = %v, %v — want the default (plain) transport", base, tr, err)
		}
	}
	for _, base := range []string{"https://127.0.0.1:11434", "HTTPS://localhost:11434"} {
		tr, err := laneTransport(base)
		ht, ok := tr.(*http.Transport)
		if err != nil || !ok || ht.TLSClientConfig == nil || len(ht.TLSClientConfig.Certificates) != 1 || ht.TLSClientConfig.RootCAs == nil {
			t.Fatalf("%s: want a transport presenting the leaf and pinning the CA, got %#v, %v", base, tr, err)
		}
	}
}

// Roll-order hazard (the old agent against the moved publish): a plaintext
// dial at the mTLS door fails FAST and never hangs the 2 s probe budget, let
// alone the 2 h pull client. (Go's TLS test server answers the plaintext
// request with a 400; stunnel resets the connection — the real-stunnel proof
// in the PR covers that shape. Either way nothing reaches the upstream.)
func TestAPlainDialAtTheDoorFailsFast(t *testing.T) {
	p := preseedtest.New(t)
	base, hits := door(t, p)
	plain := "http://" + strings.TrimPrefix(base, "https://")
	n := NewStackAt(plain)
	start := time.Now()
	ctx := context.Background()
	if len(n.Running(ctx)) != 0 {
		t.Fatal("a plain dial at the TLS door reported a server")
	}
	if _, err := n.Pull(ctx, "x"); err == nil {
		t.Fatal("a plain pull at the TLS door succeeded")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("plain dials at the door took %v — must fail at once, not hang", d)
	}
	if h := atomic.LoadInt64(hits); h != 0 {
		t.Fatalf("%d plaintext requests reached the upstream", h)
	}
}
