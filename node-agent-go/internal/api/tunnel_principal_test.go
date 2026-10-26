// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
)

// The tunnel principal (followup i131 phase 2) is a value in the request
// context that only internal/tunnel sets. These tests run the REAL route
// table and prove both halves: a stream the tunnel client marks reaches the
// controller-gated routes with no bearer and no certificate, and nothing a
// TCP caller can write (a header, a node leaf, the fleet bearer) mints it.

var tunnelHeaders = []string{
	auth.TunnelPrincipalHeader,
	"X-Noo-Tunnel",
	"X-Noo-Tunnel-Controller",
	"X-Noo-Principal",
}

// gateRefusal reports whether a response is the authentication or controller
// gate speaking, as opposed to a handler that was reached and answered (these
// tests have no docker, so a reached handler may say 503 for its own reasons).
func gateRefusal(code int, body string) bool {
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return true
	}
	return code == http.StatusServiceUnavailable && (strings.Contains(body, "cannot identify its callers") || strings.Contains(body, "auth not configured"))
}

func callTunnel(t *testing.T, h http.Handler, method, path string, viaTunnel bool, headers map[string]string) (refused bool) {
	t.Helper()
	defer func() {
		if recover() != nil {
			refused = false // the gate let it through and the handler (no docker here) panicked
		}
	}()
	r := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	if viaTunnel {
		r = r.WithContext(auth.WithTunnelController(r.Context()))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return gateRefusal(rec.Code, rec.Body.String())
}

func TestATunnelStreamReachesTheControllerRoutesWithoutABearer(t *testing.T) {
	h := identifyingMux(t)
	routes := append([]struct{ method, path string }{
		{"POST", "/start"}, {"POST", "/stop"}, {"POST", "/pull"}, {"POST", "/clean"},
		{"GET", "/logs/containers"}, {"GET", "/logs/noo-gateway"},
		{"POST", "/api/skills/run"}, {"POST", "/api/device/screenshot"},
		{"POST", "/api/containers/start"},
	}, workRoutes...)
	for _, c := range routes {
		if callTunnel(t, h, c.method, c.path, true, nil) {
			t.Errorf("%s %s over the tunnel was refused by the gate; it is the controller's stream", c.method, c.path)
		}
	}
}

func TestATcpRequestCarryingTheTunnelPrincipalIsRefused(t *testing.T) {
	h := identifyingMux(t)
	node := testLeaf(t, "host3", "Mesh Cluster Node")
	hdrs := map[string]string{}
	for _, name := range tunnelHeaders {
		hdrs[name] = "controller"
	}
	routes := append([]struct{ method, path string }{
		{"POST", "/start"}, {"POST", "/pull"}, {"POST", "/clean"},
		{"GET", "/logs/containers"}, {"POST", "/api/skills/run"},
		{"POST", "/api/device/screenshot"}, {"POST", "/tailnet/dialback"},
	}, workRoutes...)
	for _, c := range routes {
		// No credential at all, with the headers.
		if !callTunnel(t, h, c.method, c.path, false, hdrs) {
			t.Errorf("%s %s: headers alone must not pass the gate", c.method, c.path)
		}
		// A peer node leaf with the fleet bearer AND the headers.
		h2 := map[string]string{}
		for k, v := range hdrs {
			h2[k] = v
		}
		h2["Authorization"] = "Bearer test-token"
		if code := callAs(t, withHeaders(h, h2), c.method, c.path, node); code != http.StatusForbidden {
			t.Errorf("%s %s: a node leaf plus the headers must stay refused, got %d", c.method, c.path, code)
		}
	}
}

// withHeaders adds fixed headers to every request before the handler sees it.
func withHeaders(next http.Handler, hdrs map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

func TestATunnelStreamIsNotTheHarnessAndGetsNoHarnessOnlyRoute(t *testing.T) {
	h := identifyingMux(t)
	// /harness/placement is the node's own harness alone; the controller has
	// the database and needs nothing from it, tunnel or not.
	if !callTunnel(t, h, "GET", "/harness/placement", true, nil) {
		t.Fatal("the tunnel principal must not open the harness-only route")
	}
}
