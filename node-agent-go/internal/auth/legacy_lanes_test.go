// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

func laneCount(lane string) uint64 { return LegacyLaneCounts()[lane] }

func admitted(t *testing.T, cfg *config.Config, bearer string, peer *x509.Certificate) {
	t.Helper()
	h := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	r := httptest.NewRequest("GET", "/gpu", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("want the request admitted (this lane counts, never refuses), got %d", rec.Code)
	}
}

// a request admitted by the static token is counted; one
// admitted by the HMAC cluster token is not.
func TestLegacyLane_StaticTokenIsCountedAndHMACIsNot(t *testing.T) {
	cfg := &config.Config{NodeAgentToken: "test-token", ClusterSecret: "s3cret", TLSCA: "ca.pem"}
	ctrl := leaf(t, "gateway", "Mesh Cluster Gateway")

	before := laneCount(LaneStaticToken)
	admitted(t, cfg, "test-token", ctrl)
	if got := laneCount(LaneStaticToken) - before; got != 1 {
		t.Fatalf("static-token admission counted %d times, want 1", got)
	}

	before = laneCount(LaneStaticToken)
	admitted(t, cfg, mintToken("gateway", "s3cret", time.Now().Unix(), false), ctrl)
	if got := laneCount(LaneStaticToken) - before; got != 0 {
		t.Fatalf("an HMAC admission moved the static-token count by %d", got)
	}
}

func whois(t *testing.T, cfg *config.Config, peer *x509.Certificate) {
	t.Helper()
	h := Middleware(cfg)(CountNonControllerWhois(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })))
	r := httptest.NewRequest("GET", "/tailnet/whois?ip=100.64.0.1", nil)
	r.Header.Set("Authorization", "Bearer test-token")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("whois must still be served (observe only), got %d", rec.Code)
	}
}

// /tailnet/whois served to a PEER node's leaf is counted; to the
// controller it is not. Neither is refused.
func TestLegacyLane_WhoisToAPeerIsCounted(t *testing.T) {
	cfg := &config.Config{NodeAgentToken: "test-token", TLSCA: "ca.pem"}

	before := laneCount(LaneWhoisNonController)
	whois(t, cfg, leaf(t, "host9", "Mesh Cluster Node"))
	if got := laneCount(LaneWhoisNonController) - before; got != 1 {
		t.Fatalf("whois to a peer counted %d times, want 1", got)
	}

	before = laneCount(LaneWhoisNonController)
	whois(t, cfg, leaf(t, "gateway", "Mesh Cluster Gateway"))
	if got := laneCount(LaneWhoisNonController) - before; got != 0 {
		t.Fatalf("whois to the controller moved the count by %d", got)
	}
}

// The heartbeat shape: every lane present (zeros included) plus the window.
func TestLegacyLaneSnapshot_HasEveryLaneAndItsWindow(t *testing.T) {
	s := LegacyLaneSnapshot()
	for _, k := range []string{"since_unix", LaneStaticToken, LaneWhoisNonController} {
		if _, ok := s[k]; !ok {
			t.Fatalf("legacy_lanes lacks %q: %v", k, s)
		}
	}
	if since, _ := s["since_unix"].(int64); since <= 0 || since > time.Now().Unix() {
		t.Fatalf("since_unix = %v", s["since_unix"])
	}
}

func TestLaneLogDue_OncePerKeyPerWindow(t *testing.T) {
	if !laneLogDue("test|x") {
		t.Fatal("first use of a key must log")
	}
	if laneLogDue("test|x") {
		t.Fatal("a second use inside the window must not log")
	}
	if !laneLogDue("test|y") {
		t.Fatal("another key logs on its own")
	}
}
