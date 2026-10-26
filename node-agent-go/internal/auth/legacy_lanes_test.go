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
	nonce := make([]byte, 16)
	tok, err := SignV2("GET", "/gpu", nil, "gateway", "s3cret", time.Now(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	admitted(t, cfg, tok, ctrl)
	if got := laneCount(LaneStaticToken) - before; got != 0 {
		t.Fatalf("an HMAC admission moved the static-token count by %d", got)
	}
}

// The heartbeat shape: every lane present (zeros included) plus the window.
func TestLegacyLaneSnapshot_HasEveryLaneAndItsWindow(t *testing.T) {
	s := LegacyLaneSnapshot()
	for _, k := range []string{"since_unix", LaneStaticToken, LaneHMACv1Refused} {
		if _, ok := s[k]; !ok {
			t.Fatalf("legacy_lanes lacks %q: %v", k, s)
		}
	}
	for _, gone := range []string{"whois_non_controller", "cluster_hmac_v1"} {
		if _, ok := s[gone]; ok {
			t.Fatalf("legacy_lanes still reports the deleted lane %q: %v", gone, s)
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
