// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelstats"
)

// vLLM serves mTLS itself (--ssl-cert-reqs 2): there is no plaintext port on
// the bridge to fall back to. The agent's own reads of it — the live window
// (liveChatContext, /v1/models max_model_len) and the ceiling (#497,
// ChatModelStats, /v1/models root) — must reach it the way the inference
// proxy does: https to the door name, through the host dialer, presenting
// the node leaf. The other tests stub the target with a plain httptest
// server; these resolve it with chatTarget against a door that refuses any
// caller without a client certificate and has no plaintext listener at all.

// startVLLMDoor is a TLS-only vLLM: /v1/models answers only a caller that
// presented a cluster-CA client certificate.
func startVLLMDoor(t *testing.T, p *testPKI) string {
	t.Helper()
	pair, err := tls.X509KeyPair(p.srvCert, p.srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"m","root":"org/gemma-4-12B","max_model_len":16384}]}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.caPool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// doorServer is a Server whose one chat placement is vLLM serving "m",
// resolved by chatTarget (no docker client: the agent-started door URL).
func doorServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	s := &Server{cfg: cfg}
	cp := ChatPlacement{Backend: "vllm", Model: "m"}
	running := map[string]string{"vllm": "m"}
	target := func(ctx context.Context) (benchTarget, error) {
		return s.chatTarget(ctx, cp, running, nil)
	}
	s.windowResolve = target
	s.ceilingTargets = func(ctx context.Context) []benchTarget {
		bt, err := target(ctx)
		if err != nil {
			return nil
		}
		return []benchTarget{bt}
	}
	hf := t.TempDir()
	hfSnapshot(t, hf, "org/gemma-4-12B", "abc123", `{"text_config":{"max_position_embeddings":262144}}`)
	s.hfCacheDir = func() string { return hf }
	return s
}

func TestVLLMReadsDialTheDoorWithTheNodeLeaf(t *testing.T) {
	p := newTestPKI(t)
	door := startVLLMDoor(t, p)
	h := &hostDialer{doors: map[string]string{"noo-vllm:8000": door}}
	withHostDialer(t, h)
	s := doorServer(t, writePKI(t, p))

	bt, err := s.windowResolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bt.url, "https://noo-vllm:8000/") {
		t.Fatalf("vLLM target %q: want the https door", bt.url)
	}
	if got := s.liveChatContext(context.Background()); got != 16384 {
		t.Errorf("live window %d, want 16384 from the door's max_model_len", got)
	}
	want := modelstats.ModelStat{Name: "m", Loaded: true, ContextLength: 262144}
	if got := s.ChatModelStats(context.Background()); len(got) != 1 || got[0] != want {
		t.Errorf("ceiling %+v, want %+v", got, want)
	}
	for _, a := range h.dialed {
		if a != "noo-vllm:8000" {
			t.Errorf("dialled %q: every read goes to the vLLM door", a)
		}
	}
}

// Without the node leaf the door refuses the handshake: both reads come back
// unknown rather than finding some other way in.
func TestVLLMReadsWithoutTheNodeLeafAreRefused(t *testing.T) {
	p := newTestPKI(t)
	door := startVLLMDoor(t, p)
	withHostDialer(t, &hostDialer{doors: map[string]string{"noo-vllm:8000": door}})
	cfg := writePKI(t, p)
	cfg.TLSCert, cfg.TLSKey = "", ""
	s := doorServer(t, cfg)

	if got := s.liveChatContext(context.Background()); got != 0 {
		t.Errorf("live window %d without a client certificate, want 0 (refused)", got)
	}
	if got := s.ChatModelStats(context.Background()); len(got) != 0 {
		t.Errorf("ceiling %+v without a client certificate, want none (refused)", got)
	}
}
