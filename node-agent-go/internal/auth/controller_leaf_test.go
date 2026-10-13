// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// the controller's verified leaf is enough on the routes the
// gateway calls — the bearer it used to send was a fleet secret every node
// holds, so it never identified the controller; the certificate did.
func runLeafOrToken(t *testing.T, cfg *config.Config, peer *x509.Certificate, bearer string) int {
	t.Helper()
	h := ControllerLeafOrToken(cfg)(ControllerOnly(cfg)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	r := httptest.NewRequest("GET", "/gpu", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	r.TLS = &tls.ConnectionState{}
	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

func TestControllerLeafNeedsNoBearer(t *testing.T) {
	cfg := tokenCfg(t)
	ctrl := leaf(t, "gateway", "Mesh Cluster Gateway")
	before := laneCount(LaneStaticToken)
	if c := runLeafOrToken(t, cfg, ctrl, ""); c != http.StatusOK {
		t.Fatalf("controller leaf, no bearer: got %d, want 200", c)
	}
	if got := laneCount(LaneStaticToken) - before; got != 0 {
		t.Fatalf("a leaf-only admission moved the static-token count by %d", got)
	}
	// An old gateway that still sends the static token is still admitted —
	// and still counted, which is the evidence the lane reads.
	before = laneCount(LaneStaticToken)
	if c := runLeafOrToken(t, cfg, ctrl, "test-token"); c != http.StatusOK {
		t.Fatalf("controller leaf + static token: got %d, want 200", c)
	}
	if got := laneCount(LaneStaticToken) - before; got != 1 {
		t.Fatalf("static-token admission counted %d times, want 1", got)
	}
	// A bearer that is present but wrong is judged as before: refused.
	if c := runLeafOrToken(t, cfg, ctrl, "stale"); c != http.StatusForbidden {
		t.Fatalf("controller leaf + a wrong bearer: got %d, want 403", c)
	}
}

func TestNonControllerLeafStillNeedsTheBearerAndTheGate(t *testing.T) {
	cfg := tokenCfg(t)
	for _, peer := range []*x509.Certificate{
		leaf(t, "host3", "Mesh Cluster Node"),
		leaf(t, "prometheus", "Mesh Cluster Service"),
		nil,
	} {
		if c := runLeafOrToken(t, cfg, peer, ""); c != http.StatusUnauthorized {
			t.Fatalf("non-controller leaf %v, no bearer: got %d, want 401", peer != nil, c)
		}
	}
	// With the fleet token a node leaf passes the bearer check and is
	// still refused by the gate.
	if c := runLeafOrToken(t, cfg, leaf(t, "host3", "Mesh Cluster Node"), "test-token"); c != http.StatusForbidden {
		t.Fatalf("node leaf + fleet token: got %d, want 403", c)
	}
}

func TestAnAgentWithoutTheClusterCABelievesNoLeaf(t *testing.T) {
	blind := &config.Config{NodeAgentToken: "test-token"} // no cluster CA
	if c := runLeafOrToken(t, blind, leaf(t, "gateway", "Mesh Cluster Gateway"), ""); c != http.StatusUnauthorized {
		t.Fatalf("an agent without the cluster CA must not believe a leaf: got %d, want 401", c)
	}
	if ControllerLeafOnly(blind) {
		t.Fatal("an agent that cannot verify leaves must not report controller_leaf_only")
	}
}

func TestControllerLeafOnlyFollowsPeerIdentity(t *testing.T) {
	cfg := &config.Config{TLSCert: "c", TLSKey: "k", TLSCA: "ca"}
	if !ControllerLeafOnly(cfg) {
		t.Fatal("a fully configured mTLS agent must report controller_leaf_only")
	}
}

// The scraper door admits the controller leaf without a bearer too: the
// gateway reads /metrics on a flagged node with no token.
func TestMetricsDoorAdmitsTheControllerLeafWithoutABearer(t *testing.T) {
	cfg := tokenCfg(t)
	h := ServiceLeafOrToken(cfg)(MetricsReader(cfg)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf(t, "gateway", "Mesh Cluster Gateway")}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("controller leaf on /metrics, no bearer: got %d, want 200", rec.Code)
	}
}

// the own-harness door admits only this node's leaf, only
// over loopback, only without a bearer, and only when leaves are verified.
func TestOwnHarnessLeafWithoutBearerPredicate(t *testing.T) {
	cfg := tokenCfg(t)
	cfg.NodeID = "host3"
	req := func(remote, bearer string, peer *x509.Certificate) *http.Request {
		r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		r.RemoteAddr = remote
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		r.TLS = &tls.ConnectionState{}
		if peer != nil {
			r.TLS.PeerCertificates = []*x509.Certificate{peer}
		}
		return r
	}
	own := leaf(t, "host3", "Mesh Cluster Node")
	if !IsOwnHarnessLeafWithoutBearer(cfg, req("127.0.0.1:1", "", own)) {
		t.Fatal("own leaf over loopback with no bearer must qualify")
	}
	for name, r := range map[string]*http.Request{
		"peer leaf":        req("127.0.0.1:1", "", leaf(t, "host2", "Mesh Cluster Node")),
		"off loopback":     req("10.0.0.2:1", "", own),
		"bearer present":   req("127.0.0.1:1", "test-token", own),
		"no leaf":          req("127.0.0.1:1", "", nil),
		"service leaf, cn": req("127.0.0.1:1", "", leaf(t, "host3", "Mesh Cluster Service")),
		"controller leaf":  req("127.0.0.1:1", "", leaf(t, "host3", "Mesh Cluster Gateway")),
	} {
		if IsOwnHarnessLeafWithoutBearer(cfg, r) {
			t.Errorf("%s must not qualify", name)
		}
	}
	blind := &config.Config{NodeID: "host3", NodeAgentToken: "test-token"}
	if IsOwnHarnessLeafWithoutBearer(blind, req("127.0.0.1:1", "", own)) {
		t.Fatal("an agent without the cluster CA must not believe the leaf")
	}
}
