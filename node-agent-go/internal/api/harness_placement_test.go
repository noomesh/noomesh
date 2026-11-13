// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

func placementServer(t *testing.T, f func() HarnessPlacement) http.Handler {
	t.Helper()
	s := placementServerRaw(t)
	if f != nil {
		s.SetHarnessPlacement(f)
	}
	return s.mux
}

func placementServerRaw(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{NodeID: "test-node", NodeAgentToken: "test-token", TLSCA: "ca.pem"}
	gpu := hardware.NewGPUDetector(nil, "http")
	return NewServer(cfg, nil, gpu, metrics.NewCollector(gpu))
}

func getPlacement(h http.Handler, peer *x509.Certificate, remote, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/harness/placement", nil)
	r.RemoteAddr = remote
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	r.TLS = &tls.ConnectionState{}
	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHarnessPlacementRouteAnswersPlacedAndUnplaced(t *testing.T) {
	own := testLeaf(t, "test-node", "Mesh Cluster Node")
	placed := placementServer(t, func() HarnessPlacement {
		return HarnessPlacement{Kind: "copilot", Env: map[string]string{"NOO_HARNESS_KIND": "copilot"}, DesiredState: "running", Placed: true}
	})
	rec := getPlacement(placed, own, "127.0.0.1:5000", "")
	if rec.Code != 200 {
		t.Fatalf("own harness over loopback, no bearer: %d %s", rec.Code, rec.Body)
	}
	body := strings.ReplaceAll(rec.Body.String(), " ", "")
	if strings.TrimSpace(body) != `{"kind":"copilot","env":{"NOO_HARNESS_KIND":"copilot"},"desired_state":"running","placed":true}` {
		t.Fatalf("body: %s", body)
	}
	// The chat backend's window rides along when the agent knows it (i147).
	windowed := placementServer(t, func() HarnessPlacement {
		return HarnessPlacement{Kind: "claude-code", DesiredState: "running", Placed: true, ModelContext: 32768}
	})
	rec = getPlacement(windowed, own, "127.0.0.1:5000", "")
	if body := strings.ReplaceAll(rec.Body.String(), " ", ""); strings.TrimSpace(body) != `{"kind":"claude-code","env":{},"desired_state":"running","placed":true,"model_context":32768}` {
		t.Fatalf("model_context body: %s", body)
	}
	unplaced := placementServer(t, func() HarnessPlacement { return HarnessPlacement{} })
	rec = getPlacement(unplaced, own, "127.0.0.1:5000", "")
	if rec.Code != 404 || strings.ReplaceAll(rec.Body.String(), " ", "") != `{"placed":false}` {
		t.Fatalf("unplaced: %d %s", rec.Code, rec.Body)
	}
}

// Before the agent installs its provider (it serves from step 1 and
// registers until it can), the placement is NOT KNOWN: 503 known:false with
// Retry-After, never the 404 "not placed" a harness would act on (rc.1
// rehearsal, A-placeknown.unknown).
func TestNoProviderYetIsUnknownNotUnplaced(t *testing.T) {
	own := testLeaf(t, "test-node", "Mesh Cluster Node")
	rec := getPlacement(placementServer(t, nil), own, "127.0.0.1:5000", "")
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "5" {
		t.Fatalf("no provider: %d retry-after=%q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	if body := strings.ReplaceAll(rec.Body.String(), " ", ""); body != `{"placed":false,"known":false}` {
		t.Fatalf("no provider body: %s", body)
	}
	// Installed later, the provider's own answer wins.
	s := placementServerRaw(t)
	s.SetHarnessPlacement(func() HarnessPlacement { return HarnessPlacement{} })
	if rec := getPlacement(s.mux, own, "127.0.0.1:5000", ""); rec.Code != 404 {
		t.Fatalf("installed, unplaced: %d", rec.Code)
	}
}

// The same door as the harness's chat route, narrowed to the harness: a
// peer's leaf, the controller's leaf, this node's leaf from off-box and a
// bearer with no certificate are all refused.
func TestHarnessPlacementRouteRefusesEveryoneButTheOwnHarness(t *testing.T) {
	h := placementServer(t, func() HarnessPlacement { return HarnessPlacement{Kind: "noo", Placed: true} })
	peer := testLeaf(t, "host3", "Mesh Cluster Node")
	own := testLeaf(t, "test-node", "Mesh Cluster Node")
	for name, c := range map[string]struct {
		cert           *x509.Certificate
		remote, bearer string
	}{
		"peer node leaf over loopback": {peer, "127.0.0.1:5000", ""},
		"own leaf from off-box":        {own, "10.0.0.9:5000", ""},
		"bearer, no certificate":       {nil, "127.0.0.1:5000", "test-token"},
		"no credentials":               {nil, "127.0.0.1:5000", ""},
	} {
		if rec := getPlacement(h, c.cert, c.remote, c.bearer); rec.Code == 200 {
			t.Errorf("%s: must be refused, got 200", name)
		}
	}
	// With a bearer the own harness is still admitted (an older harness).
	if rec := getPlacement(h, own, "127.0.0.1:5000", "test-token"); rec.Code != 200 {
		t.Errorf("own harness with bearer: %d %s", rec.Code, rec.Body)
	}
}

// The node's resolved harness profile rides along as `profile`, verbatim,
// and is omitted when the node has none.
func TestHarnessPlacementCarriesTheProfile(t *testing.T) {
	own := testLeaf(t, "test-node", "Mesh Cluster Node")
	prof := `{"tier":2,"first_byte_secs":600,"stream_idle_secs":300,"thinking":"off","claude_prompt":"slim"}`
	h := placementServer(t, func() HarnessPlacement {
		return HarnessPlacement{Kind: "noo", Env: map[string]string{"NOO_HARNESS_THINKING": "on"}, DesiredState: "running", Placed: true,
			Profile: []byte(prof)}
	})
	rec := getPlacement(h, own, "127.0.0.1:5000", "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if body := strings.TrimSpace(rec.Body.String()); body !=
		`{"kind":"noo","env":{"NOO_HARNESS_THINKING":"on"},"desired_state":"running","placed":true,"profile":`+prof+`}` {
		t.Fatalf("body: %s", body)
	}
	none := placementServer(t, func() HarnessPlacement {
		return HarnessPlacement{Kind: "noo", DesiredState: "running", Placed: true}
	})
	if rec := getPlacement(none, own, "127.0.0.1:5000", ""); strings.Contains(rec.Body.String(), "profile") {
		t.Fatalf("no profile must omit the key: %s", rec.Body)
	}
}

// i658: at a roll the agent and the harness restart in the same second. Until
// the agent has applied a desired-config it cannot say "not placed": it says
// "not known yet" (503, Retry-After) so the harness waits instead of running
// on its defaults. A known answer is unchanged: placed 200, unplaced 404.
func TestHarnessPlacementSaysNotKnownYetUntilTheFirstDesiredConfig(t *testing.T) {
	own := testLeaf(t, "test-node", "Mesh Cluster Node")
	unknown := placementServer(t, func() HarnessPlacement { return HarnessPlacement{Unknown: true} })
	rec := getPlacement(unknown, own, "127.0.0.1:5000", "")
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "5" {
		t.Fatalf("unknown: %d retry-after=%q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}
	if strings.ReplaceAll(rec.Body.String(), " ", "") != `{"placed":false,"known":false}` {
		t.Fatalf("unknown body: %s", rec.Body)
	}
	// Unknown wins even over a stale placed view.
	rec = getPlacement(placementServer(t, func() HarnessPlacement { return HarnessPlacement{Placed: true, Kind: "noo", Unknown: true} }), own, "127.0.0.1:5000", "")
	if rec.Code != 503 {
		t.Fatalf("unknown and placed: %d", rec.Code)
	}
	rec = getPlacement(placementServer(t, func() HarnessPlacement { return HarnessPlacement{Placed: true, Kind: "noo"} }), own, "127.0.0.1:5000", "")
	if rec.Code != 200 {
		t.Fatalf("known placed: %d", rec.Code)
	}
	rec = getPlacement(placementServer(t, func() HarnessPlacement { return HarnessPlacement{} }), own, "127.0.0.1:5000", "")
	if rec.Code != 404 {
		t.Fatalf("known unplaced: %d", rec.Code)
	}
}
