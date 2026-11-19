// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package containerdial

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A transport built BEFORE the host-mode dialer is installed still dials
// through it once it is: ApplyDial binds at dial time, not build time.
// agent.New builds its shared transport before Install runs; an eager bind
// left any transport built that early on the stock dialer for good.
func TestApplyDialBindsAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	backend := srv.Listener.Addr().String()

	t.Cleanup(SwapForTest(nil)) // container mode while the transport is built
	tr := ApplyDial(&http.Transport{})
	c := &http.Client{Timeout: 5 * time.Second, Transport: tr}

	var hostDials atomic.Int32
	SwapForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "noo-lazy-backend:80" {
			t.Errorf("host dialer got %q, want noo-lazy-backend:80", addr)
		}
		hostDials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, backend)
	})

	resp, err := c.Get("http://noo-lazy-backend:80/")
	if err != nil {
		t.Fatalf("a transport built before Install did not take the host dialer: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" || hostDials.Load() != 1 {
		t.Fatalf("body %q, host dials %d; want ok, 1", body, hostDials.Load())
	}
}

// Container mode (nothing installed): the dial goes to the transport's own
// dialer, untouched.
func TestApplyDialContainerModeUsesTheBaseDialer(t *testing.T) {
	t.Cleanup(SwapForTest(nil))
	sentinel := errors.New("base dialer")
	var baseDials atomic.Int32
	tr := ApplyDial(&http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		baseDials.Add(1)
		return nil, sentinel
	}})
	if _, err := tr.DialContext(context.Background(), "tcp", "noo-x:1"); !errors.Is(err, sentinel) || baseDials.Load() != 1 {
		t.Fatalf("container-mode dial: err %v, base dials %d; want the base dialer once", err, baseDials.Load())
	}
}

// Container mode, a transport that named no dialer: it dials as net/http
// would have (a plain dial to a real address works), and a transport that
// was eligible for automatic HTTP/2 stays eligible — a non-nil DialContext
// alone would have switched that off.
func TestApplyDialContainerModeBareTransportUnchanged(t *testing.T) {
	t.Cleanup(SwapForTest(nil))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()

	bare := ApplyDial(&http.Transport{})
	resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: bare}).Get(srv.URL)
	if err != nil {
		t.Fatalf("bare transport, container mode: %v", err)
	}
	resp.Body.Close()
	if !bare.ForceAttemptHTTP2 {
		t.Fatal("a bare transport lost automatic HTTP/2 eligibility under ApplyDial")
	}
	withTLS := ApplyDial(&http.Transport{TLSClientConfig: &tls.Config{}})
	if withTLS.ForceAttemptHTTP2 {
		t.Fatal("a transport with its own TLS config was not HTTP/2-eligible before; ApplyDial must not turn it on")
	}
	if ApplyDial(nil) != nil {
		t.Fatal("ApplyDial(nil) must return nil")
	}
}
