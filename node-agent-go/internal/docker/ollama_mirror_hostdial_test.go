// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/containerdial"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// doorResolver is the docker fact containerdial needs, faked: the door name
// maps to the test listener, anything else is "not a container".
type doorResolver map[string]string

func (d doorResolver) ContainerDialAddr(_ context.Context, name, _ string) (string, error) {
	if a, ok := d[name]; ok {
		return a, nil
	}
	return "", errors.New("no such container")
}

// The fake door name: single-label like a real docker-DNS door, resolvable
// by nothing but the host-mode dialer.
const testOllamaDoor = "noo-stunnel-ollama-hostdial-test"

func hostModeDialer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := containerdial.New(doorResolver{testOllamaDoor: u.Host})
	t.Cleanup(containerdial.SwapForTest(r.WrapDialContext((&net.Dialer{Timeout: 5 * time.Second}).DialContext)))
}

func blobHandler(hits *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		w.WriteHeader(http.StatusOK)
	})
}

// On a host-mode agent the Ollama store import dials the managed
// container's door by its docker-DNS name (BackendDialURL, since #1295).
// ollamaTransport builds its own transport, so it must carry the host-mode
// dialer itself — before this, both branches dialled through the system
// resolver: "lookup noo-stunnel-ollama on 127.0.0.11:53: no such host".
func TestOllamaImportTransportDialsDoorInHostMode(t *testing.T) {
	t.Run("https door (node leaf)", func(t *testing.T) {
		p := preseedtest.New(t)
		p.SetNodeEnv(t)
		hits := 0
		srv := p.Door(t, testOllamaDoor, blobHandler(&hits))
		hostModeDialer(t, srv)
		_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
		assertImportReaches(t, "https://"+net.JoinHostPort(testOllamaDoor, port), &hits)
	})
	t.Run("plaintext", func(t *testing.T) {
		hits := 0
		srv := httptest.NewServer(blobHandler(&hits))
		t.Cleanup(srv.Close)
		hostModeDialer(t, srv)
		_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
		assertImportReaches(t, "http://"+net.JoinHostPort(testOllamaDoor, port), &hits)
	})
}

func assertImportReaches(t *testing.T, base string, hits *int) {
	t.Helper()
	tr, err := ollamaTransport(base)
	if err != nil {
		t.Fatalf("ollamaTransport(%s): %v", base, err)
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ok, err := (&ollamaHTTP{base: base, transport: tr}).HasBlob(ctx, "00")
	if err != nil {
		t.Fatalf("the import could not reach %s through the host-mode dialer: %v", base, err)
	}
	if !ok || *hits != 1 {
		t.Fatalf("HasBlob = %v, door hits = %d; want true, 1", ok, *hits)
	}
}

// Container mode (no dialer installed): the same name does not resolve —
// pins that the test above passes because of the dialer.
func TestOllamaImportDoorNameUnresolvableWithoutHostDial(t *testing.T) {
	t.Cleanup(containerdial.SwapForTest(nil))
	tr, err := ollamaTransport("http://" + testOllamaDoor + ":11434")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := (&ollamaHTTP{base: "http://" + testOllamaDoor + ":11434", transport: tr}).HasBlob(ctx, "00"); err == nil {
		t.Fatalf("%s resolved without the host-mode dialer; the host-mode test proves nothing here", testOllamaDoor)
	}
}
