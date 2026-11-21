// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// runTarget sends one call through TargetNode: `target` in X-Noo-Node ("" =
// no header), `peer` as the verified client leaf (nil = none).
func runTarget(t *testing.T, cfg *config.Config, method, path, target string, peer *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	h := TargetNode(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	r := httptest.NewRequest(method, path, nil)
	if target != "" {
		r.Header.Set(TargetNodeHeader, target)
	}
	r.TLS = &tls.ConnectionState{}
	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func strictFor(t *testing.T, v bool) {
	t.Helper()
	prev := RequiresTargetNode()
	SetRequireTargetNode(v)
	t.Cleanup(func() { SetRequireTargetNode(prev) })
}

func TestACallAddressedToAnotherNodeIsRefusedWith421(t *testing.T) {
	strictFor(t, false)
	cfg := &config.Config{NodeID: "node_a"}
	ctrl := leaf(t, "gateway", "Mesh Cluster Gateway")
	rec := runTarget(t, cfg, "POST", "/start", "node_b", ctrl)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("a call for node_b on node_a: got %d, want 421", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["code"] != "wrong_node" {
		t.Fatalf("refusal body: %q (%v)", rec.Body.String(), err)
	}
	// The same call addressed to this node passes; the name is case-blind.
	if c := runTarget(t, cfg, "POST", "/start", "NODE_A", ctrl).Code; c != http.StatusOK {
		t.Fatalf("a call for this node: got %d, want 200", c)
	}
}

func TestAHeaderlessControllerCallFollowsTheDesiredConfigFlag(t *testing.T) {
	cfg := &config.Config{NodeID: "node_a"}
	ctrl := leaf(t, "gateway", "Mesh Cluster Gateway")
	strictFor(t, false)
	if c := runTarget(t, cfg, "POST", "/start", "", ctrl).Code; c != http.StatusOK {
		t.Fatalf("tolerant (no flag, an older controller): got %d, want 200", c)
	}
	SetRequireTargetNode(true)
	if c := runTarget(t, cfg, "POST", "/start", "", ctrl).Code; c != http.StatusMisdirectedRequest {
		t.Fatalf("strict: a header-less controller call got %d, want 421", c)
	}
	// Strict refuses only the controller's header-less calls: read-only
	// health and metrics stay open, and a call that names this node passes.
	if c := runTarget(t, cfg, "GET", "/health", "", ctrl).Code; c != http.StatusOK {
		t.Fatalf("strict: GET /health got %d, want 200", c)
	}
	if c := runTarget(t, cfg, "POST", "/start", "node_a", ctrl).Code; c != http.StatusOK {
		t.Fatalf("strict: a call naming this node got %d, want 200", c)
	}
	// A header-less call from a non-controller leaf is not this check's to
	// judge (the auth middleware does).
	own := leaf(t, "node_a", "Mesh Cluster Node")
	if c := runTarget(t, cfg, "POST", "/v1/chat/completions", "", own).Code; c != http.StatusOK {
		t.Fatalf("strict: this node's own leaf got %d, want 200", c)
	}
}

func TestDesiredConfigFlagIsAppliedAsSent(t *testing.T) {
	strictFor(t, false)
	SetRequireTargetNode(true)
	if !RequiresTargetNode() {
		t.Fatal("the flag did not apply")
	}
	SetRequireTargetNode(false)
	if RequiresTargetNode() {
		t.Fatal("an absent flag (an older controller) must make the agent tolerant again")
	}
}

// i1174 (the early window): before the first desired-config read the agent
// is tolerant of a header-less controller call and still refuses a call
// naming another node, from the first second.
func TestTheInitialStateIsTolerantAndRefusesAMismatch(t *testing.T) {
	if startsStrict {
		t.Fatal("the agent must start tolerant: an older controller's calls arrive before the first desired-config read")
	}
	strictFor(t, startsStrict)
	cfg := &config.Config{NodeID: "node_a"}
	ctrl := leaf(t, "gateway", "Mesh Cluster Gateway")
	if c := runTarget(t, cfg, "POST", "/start", "", ctrl).Code; c != http.StatusOK {
		t.Fatalf("initial state: a header-less controller call got %d, want 200", c)
	}
	if c := runTarget(t, cfg, "POST", "/start", "node_b", ctrl).Code; c != http.StatusMisdirectedRequest {
		t.Fatalf("initial state: a call for node_b got %d, want 421", c)
	}
}

// i1174: a refusal is kept for the heartbeat (verify's `target-node check`
// row), naming the node the call was for and the path.
func TestARefusalIsKeptForTheHeartbeat(t *testing.T) {
	strictFor(t, false)
	prev := lastWrongNode.Load()
	t.Cleanup(func() { lastWrongNode.Store(prev) })
	lastWrongNode.Store(nil)
	if LastWrongNode() != nil {
		t.Fatal("nothing refused, nothing reported")
	}
	cfg := &config.Config{NodeID: "node_a"}
	ctrl := leaf(t, "gateway", "Mesh Cluster Gateway")
	if c := runTarget(t, cfg, "POST", "/start", "node_a", ctrl).Code; c != http.StatusOK || LastWrongNode() != nil {
		t.Fatalf("a call for this node is no refusal: %d %v", c, LastWrongNode())
	}
	runTarget(t, cfg, "POST", "/start", "node_b", ctrl)
	w := LastWrongNode()
	if w == nil || w["target"] != "node_b" || w["path"] != "/start" {
		t.Fatalf("the refusal was not kept: %#v", w)
	}
	if at, _ := w["at"].(int64); at <= 0 {
		t.Fatalf("at: %#v", w["at"])
	}
	// An old refusal is not reported.
	lastWrongNode.Store(&wrongNodeRefusal{target: "node_b", at: time.Now().Add(-wrongNodeReportFor - time.Minute)})
	if LastWrongNode() != nil {
		t.Fatal("a refusal older than the report window is still reported")
	}
}
