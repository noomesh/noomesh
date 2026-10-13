// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendrt"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// stubOllama serves the two endpoints the native prober reads.
func stubOllama(t *testing.T, loaded string) *backendrt.Native {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/ps":
			if loaded == "" {
				_, _ = w.Write([]byte(`{"models":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"models":[{"name":"` + loaded + `","model":"` + loaded + `"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return backendrt.NewNativeAt(srv.URL)
}

// A start that cannot happen must not answer 200.
//
// `s.docker != nil` never meant "Docker works" on a HOST — NewClient only
// WARNS there, deliberately, because the agent runs on macOS with no Docker at
// all and on Linux may start before dockerd. So the nil guard could not catch
// an absent daemon: the handler answered 200 {"status":"starting"}, launched a
// goroutine, and failed into a log nobody reads. On the live Mac that was
// EVERY start ever attempted — the controller was told "starting" each time
// and nothing ever ran.
func TestStartDoesNotClaimToStartWhatItCannot(t *testing.T) {
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux()}
	w := httptest.NewRecorder()
	s.handleStartBackend(w, httptest.NewRequest(
		http.MethodPost, "/backends/start", strings.NewReader(`{"backend":"llamacpp","model":"m.gguf"}`)))

	if w.Code == http.StatusOK {
		t.Fatalf("answered 200 for a start that cannot happen — the 200 IS the bug")
	}
	if strings.Contains(w.Body.String(), "starting") {
		t.Errorf("the response claims work was started: %s", w.Body.String())
	}
}

// A natively-served backend is reported and routable, but is not this agent's
// to start. 501 naming the runtime, never a 200 and never a Docker error.
func TestStartRefusesANativeBackendByName(t *testing.T) {
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: stubOllama(t, "qwen3:8b")}
	w := httptest.NewRecorder()
	s.handleStartBackend(w, httptest.NewRequest(
		http.MethodPost, "/backends/start", strings.NewReader(`{"backend":"ollama","model":"qwen3:8b"}`)))

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"backend_runtime_unmanaged", "native", "qwen3:8b"} {
		if !strings.Contains(body, want) {
			t.Errorf("response does not name %q: %s", want, body)
		}
	}
}

// A native ollama that is up with nothing loaded is a real state (a fresh
// install). The refusal must say so rather than printing an empty model, which
// reads as a bug in the message rather than a fact about the node.
func TestRefusalNamesAnEmptyModelHonestly(t *testing.T) {
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: stubOllama(t, "")}
	w := httptest.NewRecorder()
	s.handleStartBackend(w, httptest.NewRequest(
		http.MethodPost, "/backends/start", strings.NewReader(`{"backend":"ollama","model":"x"}`)))

	if !strings.Contains(w.Body.String(), "no model loaded") {
		t.Errorf("empty model not stated plainly: %s", w.Body.String())
	}
}

// Stop must not be answered with a Docker error for a process the agent never
// started — that reads as a broken node instead of the true answer.
func TestStopRefusesANativeBackend(t *testing.T) {
	s := &Server{cfg: &config.Config{}, mux: http.NewServeMux(), native: stubOllama(t, "qwen3:8b")}
	w := httptest.NewRecorder()
	s.handleStopBackend(w, httptest.NewRequest(
		http.MethodPost, "/backends/stop", strings.NewReader(`{"backend":"ollama"}`)))

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
	if !strings.Contains(w.Body.String(), "backend_runtime_unmanaged") {
		t.Errorf("refusal is not named: %s", w.Body.String())
	}
}

// an adopted lane at an https base (the self-node's
// stunnel-ollama-embed door) is dialled with httpsTransport — the node
// leaf presented — and a plaintext loopback base stays on a bare transport.
// Before, the scheme was forced to "http" for every native endpoint.
func TestNativeEndpointSchemeFollowsItsURL(t *testing.T) {
	for base, want := range map[string]string{
		"https://127.0.0.1:11434": "https",
		"HTTPS://localhost:11434": "https",
		"http://127.0.0.1:11434":  "http",
		"http://localhost:11434":  "http",
	} {
		if got := nativeDialScheme(base); got != want {
			t.Errorf("nativeDialScheme(%q) = %q, want %q", base, got, want)
		}
	}
}

// httpsTransport, the one the proxy picks for an https lane, passes a door
// that requires a client certificate — with the node leaf, and only with it.
func TestTheProxyTransportPassesTheSelfNodeDoor(t *testing.T) {
	p := preseedtest.New(t)
	srv := p.Store(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	cfg := &config.Config{
		TLSCA:   filepath.Join(p.Dir, "ca.crt"),
		TLSCert: filepath.Join(p.Dir, "node.crt"),
		TLSKey:  filepath.Join(p.Dir, "node.key"),
	}
	c := &http.Client{Transport: httpsTransport(cfg), Timeout: 5 * time.Second}
	resp, err := c.Get(srv.URL + "/api/tags")
	if err != nil {
		t.Fatalf("proxy transport with the node leaf refused at the door: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	bare := &http.Client{Transport: httpsTransport(&config.Config{TLSCA: cfg.TLSCA}), Timeout: 5 * time.Second}
	if resp, err := bare.Get(srv.URL + "/api/tags"); err == nil {
		resp.Body.Close()
		t.Fatal("the door admitted a transport with no leaf — the test proves nothing")
	}
}
