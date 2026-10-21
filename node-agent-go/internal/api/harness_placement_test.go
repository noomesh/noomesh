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
	cfg := &config.Config{NodeID: "test-node", NodeAgentToken: "test-token", TLSCA: "ca.pem"}
	gpu := hardware.NewGPUDetector(nil, "http")
	s := NewServer(cfg, nil, gpu, metrics.NewCollector(gpu))
	if f != nil {
		s.SetHarnessPlacement(f)
	}
	return s.mux
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
	// No provider installed: unplaced, never a panic.
	rec = getPlacement(placementServer(t, nil), own, "127.0.0.1:5000", "")
	if rec.Code != 404 {
		t.Fatalf("no provider: %d", rec.Code)
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
