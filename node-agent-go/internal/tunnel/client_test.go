// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
)

// echo answers with what it was asked, and says whether the request carried
// the tunnel principal.
var echo = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	w.Header().Set("X-Saw-Principal", map[bool]string{true: "tunnel", false: "none"}[auth.IsTunnelController(r)])
	w.Header().Set("X-Saw-Header", r.Header.Get(auth.TunnelPrincipalHeader)+"|"+r.Header.Get("Authorization")+"|"+r.Header.Get("X-Keep"))
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(r.Method + " " + r.URL.RequestURI() + "\n"))
	_, _ = w.Write(b)
})

func TestAStreamIsServedThroughTheHandlerAsTheController(t *testing.T) {
	rg := newRig(t, echo, nil)
	gc, _ := rg.run(t)

	gc.open(1, "POST", "/v1/chat/completions?x=1", [][2]string{
		{"X-Keep", "yes"},
		{"Content-Length", "5"},
		// A gateway must not be able to smuggle a principal in a header.
		{auth.TunnelPrincipalHeader, "controller"},
		{"X-Noo-Tunnel-Anything", "1"},
		{"Authorization", "Bearer leaked"},
	})
	gc.write(FrameData, 1, []byte("hello"))
	gc.write(FrameEnd, 1, nil)

	status, body, ended := gc.collect(t, 1)
	if status != 200 || ended != "end" {
		t.Fatalf("status %d, ended %q", status, ended)
	}
	if string(body) != "POST /v1/chat/completions?x=1\nhello" {
		t.Fatalf("body %q", body)
	}
}

func TestTheTunnelPrincipalComesFromTheSessionNotFromAHeader(t *testing.T) {
	var sawPrincipal, sawHeader atomic.Value
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPrincipal.Store(auth.IsTunnelController(r))
		sawHeader.Store(r.Header.Get(auth.TunnelPrincipalHeader) + "|" + r.Header.Get("Authorization") + "|" + r.Header.Get("X-Noo-Tunnel-Other"))
	})
	rg := newRig(t, h, nil)
	gc, _ := rg.run(t)
	gc.open(3, "GET", "/gpu", [][2]string{{auth.TunnelPrincipalHeader, "controller"}, {"Authorization", "Bearer x"}, {"X-Noo-Tunnel-Other", "1"}})
	gc.write(FrameEnd, 3, nil)
	gc.collect(t, 3)
	if sawPrincipal.Load() != true {
		t.Fatal("a stream on the node's own tunnel must be served as the tunnel controller")
	}
	if got := sawHeader.Load().(string); got != "||" {
		t.Fatalf("reserved and credential headers must not reach the handler, got %q", got)
	}
}

func TestAStreamThatNamesAnotherPrincipalIsReset(t *testing.T) {
	rg := newRig(t, echo, nil)
	gc, _ := rg.run(t)
	b, _ := json.Marshal(openMsg{Method: "GET", Path: "/gpu", Principal: "operator"})
	gc.write(FrameOpen, 5, b)
	_, _, ended := gc.collect(t, 5)
	if !strings.HasPrefix(ended, "reset") || !strings.Contains(ended, "operator") {
		t.Fatalf("expected a reset naming the principal, got %q", ended)
	}
}

func TestBackpressureAHandlerWritingToASlowReaderStopsAtTheWindow(t *testing.T) {
	var written atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte("x"), MaxData)
		for i := 0; i < 64; i++ { // 2 MiB
			if _, err := w.Write(chunk); err != nil {
				return
			}
			written.Add(int64(len(chunk)))
		}
	})
	rg := newRig(t, h, nil)
	gc, _ := rg.run(t)
	gc.open(1, "GET", "/big", nil)
	gc.write(FrameEnd, 1, nil)

	// The reader grants nothing. The handler must stall at the window.
	var got int
	sawHead := false
	deadline := time.After(400 * time.Millisecond)
loop:
	for {
		select {
		case f := <-gc.frames:
			if f.kind == FrameData {
				got += len(f.payload)
			}
			if f.kind == FrameHead {
				sawHead = true
			}
		case <-deadline:
			break loop
		}
	}
	if got > DefaultWindow {
		t.Fatalf("the node sent %d bytes with no credit; the window is %d", got, DefaultWindow)
	}
	if got < DefaultWindow-MaxData {
		t.Fatalf("the node sent only %d bytes; it should fill its window (%d)", got, DefaultWindow)
	}
	if w := written.Load(); w > int64(DefaultWindow) {
		t.Fatalf("the handler's writes returned for %d bytes against a %d window: the writer is buffering", w, DefaultWindow)
	}

	// Credit lets the rest through, byte for byte.
	gc.write(FrameCredit, 1, creditPayload(got))
	_, body, ended := gc.collect(t, 1)
	if !sawHead || ended != "end" {
		t.Fatalf("head seen %v ended %q", sawHead, ended)
	}
	if got+len(body) != 64*MaxData {
		t.Fatalf("expected %d bytes in all, got %d", 64*MaxData, got+len(body))
	}
}

func TestAGatewayThatSendsMoreThanTheWindowIsReset(t *testing.T) {
	block := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block })
	t.Cleanup(func() { close(block) })
	rg := newRig(t, h, nil)
	gc, _ := rg.run(t)
	gc.open(1, "POST", "/x", nil)
	chunk := bytes.Repeat([]byte("y"), MaxData)
	for i := 0; i < DefaultWindow/MaxData+2; i++ {
		gc.write(FrameData, 1, chunk)
	}
	_, _, ended := gc.collect(t, 1)
	if !strings.HasPrefix(ended, "reset") {
		t.Fatalf("expected the stream to be reset for overrunning its window, got %q", ended)
	}
}

func TestTheRequestBodyIsCreditedBackAsTheHandlerReadsIt(t *testing.T) {
	rg := newRig(t, echo, nil)
	gc, _ := rg.run(t)
	gc.open(1, "POST", "/x", [][2]string{{"Content-Length", "100000"}})
	gc.write(FrameData, 1, bytes.Repeat([]byte("a"), 20000))
	gc.write(FrameData, 1, bytes.Repeat([]byte("b"), 20000))
	var credited int
	for credited < 2*20000 {
		f := gc.next(t)
		if f.kind == FrameCredit && f.id == 1 {
			credited += int(uint32(f.payload[0])<<24 | uint32(f.payload[1])<<16 | uint32(f.payload[2])<<8 | uint32(f.payload[3]))
		}
	}
}

func TestStreamCapIsRefusedOnTheNode(t *testing.T) {
	block := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block })
	t.Cleanup(func() { close(block) })
	rg := newRig(t, h, nil)
	rg.gw.maxStrm = 2
	gc, _ := rg.run(t)
	gc.open(1, "GET", "/a", nil)
	gc.open(3, "GET", "/b", nil)
	gc.open(5, "GET", "/c", nil)
	_, _, ended := gc.collect(t, 5)
	if !strings.Contains(ended, "stream cap") {
		t.Fatalf("the third stream must be refused, got %q", ended)
	}
}

func TestAGatewayResetCancelsTheHandler(t *testing.T) {
	cancelled := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		cancelled <- context.Cause(r.Context())
	})
	rg := newRig(t, h, nil)
	gc, _ := rg.run(t)
	gc.open(1, "GET", "/slow", nil)
	gc.write(FrameReset, 1, []byte("client went away"))
	select {
	case err := <-cancelled:
		if err == nil || !strings.Contains(err.Error(), "client went away") {
			t.Fatalf("cause %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the handler's context was not cancelled")
	}
}

func TestAMidStreamDropCancelsInFlightHandlersAndTheClientReconnects(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	})
	rg := newRig(t, h, nil)
	gc, _ := rg.run(t)
	gc.open(1, "GET", "/sse", nil)
	<-started
	_ = gc.c.Close() // the connection dies under an in-flight stream
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("an in-flight handler outlived the tunnel")
	}
	waitFor(t, "the client to report disconnected", func() bool { return !rg.client.Connected() })
	// Backoff, then a new session.
	select {
	case <-rg.gw.conns:
	case <-time.After(5 * time.Second):
		t.Fatal("the client did not reconnect")
	}
	waitFor(t, "the client to report connected again", rg.client.Connected)
	if rg.client.Connects.Load() < 2 {
		t.Fatalf("connects %d", rg.client.Connects.Load())
	}
}

func TestKeepalivePingsAreSentAndADeadPeerIsDropped(t *testing.T) {
	oldP, oldD := PingEvery, DeadAfter
	PingEvery, DeadAfter = 40*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { PingEvery, DeadAfter = oldP, oldD })

	// A peer that answers: pings arrive, the session stays up.
	rg := newRig(t, echo, nil)
	rg.run(t)
	waitFor(t, "pings", func() bool { return rg.gw.pings.Load() >= 3 })
	time.Sleep(300 * time.Millisecond) // longer than DeadAfter
	if !rg.client.Connected() {
		t.Fatal("a peer that answers pings must not be dropped")
	}

	// A peer that goes silent: dropped inside DeadAfter (plus a ping interval).
	rg2 := newRig(t, echo, nil)
	rg2.gw.silent.Store(true)
	ctx, cancel := contextWithCancel()
	defer cancel()
	go rg2.client.Run(ctx)
	select {
	case <-rg2.gw.conns:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection")
	}
	waitFor(t, "connected", rg2.client.Connected)
	started := time.Now()
	waitFor(t, "a dead peer to be dropped", func() bool { return !rg2.client.Connected() })
	if d := time.Since(started); d > 2*time.Second {
		t.Fatalf("dead peer took %s to detect", d)
	}
}

func TestTheClientRefusesAGatewayCertThatIsNotTheControllers(t *testing.T) {
	ca := newTestCA(t)
	// Chains to the cluster CA, but is a service leaf, not the controller.
	svc := ca.leaf(t, "gateway", "Mesh Cluster Service")
	rg := newRigWith(t, ca, svc, echo, nil)
	_, err := rg.client.session(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not the controller's") {
		t.Fatalf("expected a refusal naming the controller, got %v", err)
	}
	if rg.client.Connected() {
		t.Fatal("must not report connected")
	}
	// The server must have seen no upgrade: the TLS handshake failed first.
	if n := rg.gw.dials.Load(); n != 0 {
		t.Fatalf("the client reached the server's handler %d times", n)
	}

	// A node leaf presented as the server is refused the same way.
	node := ca.leaf(t, "host3", "Mesh Cluster Node")
	rg = newRigWith(t, ca, node, echo, nil)
	if _, err := rg.client.session(context.Background()); err == nil || !strings.Contains(err.Error(), "not the controller's") {
		t.Fatalf("a node leaf as server: %v", err)
	}
}

func TestTheClientRefusesAChallengeThatIsNotSignedByTheController(t *testing.T) {
	ca := newTestCA(t)
	gw := ca.leaf(t, "gateway", "Mesh Cluster Gateway")
	rg := newRigWith(t, ca, gw, echo, nil)
	// The server's TLS cert is the real controller's, but the challenge is
	// signed by a node leaf: whoever holds the connection is not the
	// controller.
	rg.gw.signer = ca.leaf(t, "host3", "Mesh Cluster Node")
	_, err := rg.client.session(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not signed by the controller") {
		t.Fatalf("got %v", err)
	}
	if rg.client.Connected() {
		t.Fatal("must not report connected")
	}
}

func TestTheClientRefusesAChallengeNamingAnotherNode(t *testing.T) {
	rg := newRig(t, echo, nil)
	rg.gw.challengeFor = "host3"
	_, err := rg.client.session(context.Background())
	if err == nil || !strings.Contains(err.Error(), "names node") {
		t.Fatalf("got %v", err)
	}
}

func TestAnOldGatewayIsAskedOnceAndThenLeftAlone(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		rg := newRig(t, echo, func(o *Options) { o.NotOfferedRetry = 2 * time.Second })
		rg.gw.upgradeStatus.Store(int32(status))
		ctx, cancel := contextWithCancel()
		done := make(chan struct{})
		go func() { rg.client.Run(ctx); close(done) }()
		time.Sleep(300 * time.Millisecond)
		cancel()
		<-done
		if n := rg.gw.dials.Load(); n != 1 {
			t.Fatalf("status %d: the node dialled %d times in 300 ms; an old gateway is asked once, then after the long interval", status, n)
		}
		if rg.client.Connected() {
			t.Fatal("not connected to a gateway that has no tunnel")
		}
	}
}

func TestAnUnreachableGatewayIsRetriedWithBackoff(t *testing.T) {
	rg := newRig(t, echo, nil)
	rg.gw.upgradeStatus.Store(http.StatusBadGateway)
	ctx, cancel := contextWithCancel()
	done := make(chan struct{})
	go func() { rg.client.Run(ctx); close(done) }()
	time.Sleep(600 * time.Millisecond)
	cancel()
	<-done
	n := rg.gw.dials.Load()
	if n < 3 {
		t.Fatalf("a failing dial must be retried; got %d attempts", n)
	}
	if n > 40 {
		t.Fatalf("%d attempts in 600 ms is a storm, not a backoff", n)
	}
}

func TestNewRefusesWhatCannotRunSafely(t *testing.T) {
	ca := newTestCA(t)
	node := ca.leaf(t, "host9", "Mesh Cluster Node")
	rg := newRig(t, echo, nil)
	base := Options{NodeID: "host9", ControllerURL: "https://gw:8080", Handler: echo, Verifier: rg.client.opt.Verifier}
	base.TLS = rg.client.opt.TLS
	for name, mut := range map[string]func(*Options){
		"plain http":  func(o *Options) { o.ControllerURL = "http://gw:8080" },
		"no handler":  func(o *Options) { o.Handler = nil },
		"no verifier": func(o *Options) { o.Verifier = nil },
	} {
		o := base
		mut(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: New must refuse", name)
		}
	}
	o := base
	o.TLS = rg.client.opt.TLS.Clone()
	o.TLS.Certificates = nil
	if _, err := New(o); err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Errorf("no leaf: %v", err)
	}
	_ = node
}

func TestCanonicalStringsArePinned(t *testing.T) {
	// The same literals are asserted in gateway-rust/src/tunnel.rs.
	if got := ChallengeCanonical("host9", "n0nce", 1700000000); got != "noo-tunnel-v1\nchallenge\nhost9\nn0nce\n1700000000" {
		t.Fatalf("%q", got)
	}
	if got := HelloCanonical("host9", "n0nce", 1700000000); got != "noo-tunnel-v1\nhello\nhost9\nn0nce\n1700000000" {
		t.Fatalf("%q", got)
	}
}

// A canned SSE stream: event-per-flush, ending with [DONE]. The same handler
// is served over a plain HTTP server (what :8081 does) and over the tunnel;
// the bytes must be identical.
var cannedSSE = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	f := w.(http.Flusher)
	for i := 0; i < 50; i++ {
		_, _ = w.Write([]byte("data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"tok" + strings.Repeat("é", i%7) + "\"}}]}\n\n"))
		f.Flush()
	}
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	f.Flush()
})

func TestSSEBytesAreIdenticalOverTheTunnelAndOverHTTP(t *testing.T) {
	direct := httptest.NewServer(cannedSSE)
	defer direct.Close()
	resp, err := http.Post(direct.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	rg := newRig(t, cannedSSE, nil)
	gc, _ := rg.run(t)
	gc.open(1, "POST", "/v1/chat/completions", [][2]string{{"Content-Type", "application/json"}, {"Content-Length", "2"}})
	gc.write(FrameData, 1, []byte(`{}`))
	gc.write(FrameEnd, 1, nil)
	status, got, ended := gc.collect(t, 1)
	if status != 200 || ended != "end" {
		t.Fatalf("status %d ended %q", status, ended)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("tunnel bytes differ from HTTP bytes:\n tunnel %q\n http   %q", got, want)
	}
	if !bytes.HasSuffix(got, []byte("data: [DONE]\n\n")) {
		t.Fatalf("stream did not end with [DONE]: %q", got[len(got)-40:])
	}
}

func TestAWindowSmallerThanOneFrameIsRefused(t *testing.T) {
	rg := newRig(t, echo, nil)
	rg.gw.window = MaxData - 1
	_, err := rg.client.session(context.Background())
	if err == nil || !strings.Contains(err.Error(), "window") {
		t.Fatalf("a window below the maximum frame can never be satisfied; got %v", err)
	}
	if rg.client.Connected() {
		t.Fatal("must not report connected")
	}
}

func TestAnOversizedHandshakeMessageIsNotBuffered(t *testing.T) {
	rg := newRig(t, echo, nil)
	rg.gw.bigFirst.Store(true)
	_, err := rg.client.session(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no challenge") {
		t.Fatalf("got %v", err)
	}
}

func TestAnEmptyDataFrameResetsTheStreamWithoutSpawningAnything(t *testing.T) {
	block := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block })
	t.Cleanup(func() { close(block) })
	rg := newRig(t, h, nil)
	gc, _ := rg.run(t)
	gc.open(1, "POST", "/x", nil)
	gc.write(FrameData, 1, nil)
	_, _, ended := gc.collect(t, 1)
	if !strings.HasPrefix(ended, "reset") || !strings.Contains(ended, "empty DATA") {
		t.Fatalf("got %q", ended)
	}
}

func TestAHostileCreditGrantCannotOverflowTheWindow(t *testing.T) {
	w := newWindow(DefaultWindow)
	for i := 0; i < 1000; i++ {
		w.add(int(^uint32(0) >> 1)) // the largest a 32-bit int holds
	}
	w.add(-1)
	w.mu.Lock()
	avail := w.avail
	w.mu.Unlock()
	if avail != 2*DefaultWindow {
		t.Fatalf("credit must clamp at twice the window, got %d", avail)
	}
	// And through the wire: an enormous grant on a live stream leaves it working.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fine")) })
	rg := newRig(t, h, nil)
	gc, _ := rg.run(t)
	gc.open(1, "GET", "/x", nil)
	gc.write(FrameCredit, 1, []byte{0xff, 0xff, 0xff, 0xff})
	gc.write(FrameEnd, 1, nil)
	if _, body, ended := gc.collect(t, 1); ended != "end" || string(body) != "fine" {
		t.Fatalf("ended %q body %q", ended, body)
	}
}
