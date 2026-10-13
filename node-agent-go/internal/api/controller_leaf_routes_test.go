// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// the design, through the real route table: every route the gateway
// calls admits the controller's leaf with NO bearer, and still refuses a
// non-controller leaf. If a route is wired with the bare bearer middleware
// again, the controller-no-bearer row fails for it.

func callNoBearer(t *testing.T, h http.Handler, method, path string, peer *x509.Certificate) (code int) {
	t.Helper()
	defer func() {
		if recover() != nil {
			code = reached
		}
	}()
	r := httptest.NewRequest(method, path, nil)
	r.TLS = &tls.ConnectionState{}
	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

var gatewayCalledRoutes = append([]struct{ method, path string }{
	{"POST", "/start"},
	{"POST", "/stop"},
	{"POST", "/pull"},
	{"POST", "/clean"},
	{"POST", "/cleanup/images"},
	{"POST", "/cleanup/logs"},
	{"POST", "/api/containers/start"},
	{"POST", "/api/containers/stop"},
	{"POST", "/api/skills/run"},
	{"POST", "/tailnet/dialback"},
	{"GET", "/tailnet/whois"},
	{"GET", "/logs/containers"},
	{"GET", "/logs/noo-gateway"},
	{"POST", "/api/mcp/x/call"},
	{"POST", "/api/device/screenshot"},
}, workRoutes...)

func TestGatewayRoutesAdmitTheControllerLeafWithoutABearer(t *testing.T) {
	h := identifyingMux(t)
	ctrl := testLeaf(t, "host8", "Mesh Cluster Gateway")
	for _, c := range gatewayCalledRoutes {
		if got := callNoBearer(t, h, c.method, c.path, ctrl); got == http.StatusUnauthorized || got == http.StatusForbidden {
			t.Errorf("%s %s: the controller leaf with no bearer must be admitted, got %d", c.method, c.path, got)
		}
	}
}

func TestGatewayRoutesRefuseANonControllerLeafWithoutABearer(t *testing.T) {
	h := identifyingMux(t)
	for _, peer := range []*x509.Certificate{
		testLeaf(t, "host3", "Mesh Cluster Node"),
		testLeaf(t, "vllm", "Mesh Cluster Service"),
		nil,
	} {
		for _, c := range gatewayCalledRoutes {
			// 401 (no bearer), or 403 where a door admits the leaf and the
			// gate behind it refuses it (/metrics and a non-scraper service).
			if got := callNoBearer(t, h, c.method, c.path, peer); got != http.StatusUnauthorized && got != http.StatusForbidden {
				t.Errorf("%s %s: a non-controller caller with no bearer must be refused, got %d", c.method, c.path, got)
			}
		}
	}
}

// /health gives the controller's leaf the full detail without a bearer, and
// an anonymous or peer caller only liveness.
func TestHealthDetailForTheControllerLeaf(t *testing.T) {
	h := identifyingMux(t)
	detail := func(peer *x509.Certificate) bool {
		r := httptest.NewRequest("GET", "/health", nil)
		r.TLS = &tls.ConnectionState{}
		if peer != nil {
			r.TLS.PeerCertificates = []*x509.Certificate{peer}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		_, has := body["node_id"]
		return has
	}
	if !detail(testLeaf(t, "host8", "Mesh Cluster Gateway")) {
		t.Fatal("the controller leaf must get the full /health detail without a bearer")
	}
	if detail(testLeaf(t, "host3", "Mesh Cluster Node")) || detail(nil) {
		t.Fatal("a peer or anonymous caller must get liveness only")
	}
}

// ── the design: this node's own harness, leaf over loopback, no bearer ──

func callFrom(t *testing.T, h http.Handler, method, path, remote string, peer *x509.Certificate) (code int, body map[string]any) {
	t.Helper()
	defer func() {
		if recover() != nil {
			code = reached
		}
	}()
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = remote
	r.TLS = &tls.ConnectionState{}
	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// The harness's one route admits its own leaf over loopback with no bearer.
func TestOwnHarnessLeafOverLoopbackNeedsNoBearerOnChat(t *testing.T) {
	h := identifyingMux(t) // NodeID "test-node"
	own := testLeaf(t, "test-node", "Mesh Cluster Node")
	for _, remote := range []string{"127.0.0.1:41234", "[::1]:41234"} {
		if got, _ := callFrom(t, h, "POST", "/v1/chat/completions", remote, own); got == http.StatusUnauthorized || got == http.StatusForbidden {
			t.Fatalf("own harness leaf over %s, no bearer, on chat: got %d, want admitted", remote, got)
		}
	}
}

// Another node's leaf over loopback, this node's leaf from off-box, and
// this node's leaf on any route the harness does not call: all refused.
func TestOwnHarnessDoorRefusesEveryoneElse(t *testing.T) {
	h := identifyingMux(t)
	own := testLeaf(t, "test-node", "Mesh Cluster Node")
	peer := testLeaf(t, "host3", "Mesh Cluster Node")
	refused := func(got int) bool { return got == http.StatusUnauthorized || got == http.StatusForbidden }
	if got, _ := callFrom(t, h, "POST", "/v1/chat/completions", "127.0.0.1:41234", peer); !refused(got) {
		t.Fatalf("another node's leaf over loopback must be refused, got %d", got)
	}
	if got, _ := callFrom(t, h, "POST", "/v1/chat/completions", "100.64.0.11:41234", own); !refused(got) {
		t.Fatalf("this node's leaf from another host must be refused, got %d", got)
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/models"}, {"POST", "/v1/completions"}, {"POST", "/v1/embeddings"},
		{"POST", "/start"}, {"GET", "/gpu"}, {"GET", "/logs/containers"}, {"GET", "/tailnet/whois"},
	} {
		if got, _ := callFrom(t, h, c.method, c.path, "127.0.0.1:41234", own); !refused(got) {
			t.Errorf("%s %s: the own-harness leaf without a bearer must stay refused, got %d", c.method, c.path, got)
		}
	}
}

// /health tells only the own harness that the door is open — the field the
// harness reads before it drops the bearer.
func TestHealthAdvertisesTheHarnessDoorOnlyToTheHarness(t *testing.T) {
	h := identifyingMux(t)
	has := func(remote string, peer *x509.Certificate) bool {
		_, body := callFrom(t, h, "GET", "/health", remote, peer)
		return body["own_harness_leaf_only"] == true
	}
	if !has("127.0.0.1:5000", testLeaf(t, "test-node", "Mesh Cluster Node")) {
		t.Fatal("the own harness over loopback must read own_harness_leaf_only=true")
	}
	if has("127.0.0.1:5000", testLeaf(t, "host3", "Mesh Cluster Node")) ||
		has("100.64.0.11:5000", testLeaf(t, "test-node", "Mesh Cluster Node")) ||
		has("127.0.0.1:5000", testLeaf(t, "host8", "Mesh Cluster Gateway")) ||
		has("127.0.0.1:5000", nil) {
		t.Fatal("only the own harness over loopback is told the harness door is open")
	}
}
