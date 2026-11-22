// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
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

// misaddressedFixture resets the peer-call tracking, pins its clock to the
// returned pointer and counts its log lines per caller.
func misaddressedFixture(t *testing.T) (*time.Time, map[string]int) {
	t.Helper()
	prevNow, prevLog := misaddressedNow, misaddressedLog
	prevWrong := lastWrongNode.Load()
	misaddressedMu.Lock()
	prevMap := misaddressed
	misaddressed = map[string]*misaddressedCaller{}
	misaddressedMu.Unlock()
	t.Cleanup(func() {
		misaddressedNow, misaddressedLog = prevNow, prevLog
		lastWrongNode.Store(prevWrong)
		misaddressedMu.Lock()
		misaddressed = prevMap
		misaddressedMu.Unlock()
	})
	lastWrongNode.Store(nil)
	now := time.Unix(1_800_000_000, 0)
	lines := map[string]int{}
	misaddressedNow = func() time.Time { return now }
	misaddressedLog = func(caller, _, _ string, _ int) { lines[caller]++ }
	return &now, lines
}

// i1174: a peer's (a node leaf's) call naming another node is refused with
// the same 421, is NOT recorded for this node's verify row, and is logged.
func TestAPeerCallForAnotherNodeIsRefusedLoggedAndNotRecorded(t *testing.T) {
	strictFor(t, false)
	_, lines := misaddressedFixture(t)
	cfg := &config.Config{NodeID: "node_a"}
	rec := runTarget(t, cfg, "POST", "/start", "node_b", leaf(t, "node_c", "Mesh Cluster Node"))
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("a peer's call for node_b on node_a: got %d, want 421", rec.Code)
	}
	if w := LastWrongNode(); w != nil {
		t.Fatalf("a peer's misaddressed call was recorded as wrong_node_refused: %#v", w)
	}
	if lines["node_c"] != 1 {
		t.Fatalf("log lines for node_c = %d, want 1", lines["node_c"])
	}
	got := MisaddressedFrom()
	if len(got) != 1 || got[0]["caller"] != "node_c" || got[0]["count"] != 1 {
		t.Fatalf("misaddressed_from = %#v, want node_c once", got)
	}
}

// i1174: a controller call naming another node is refused AND recorded (the
// verify row's FAIL is the controller's routing problem), never counted as
// a peer's.
func TestAControllerCallForAnotherNodeIsRefusedAndRecorded(t *testing.T) {
	strictFor(t, false)
	_, lines := misaddressedFixture(t)
	cfg := &config.Config{NodeID: "node_a"}
	rec := runTarget(t, cfg, "POST", "/start", "node_b", leaf(t, "gateway", "Mesh Cluster Gateway"))
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("got %d, want 421", rec.Code)
	}
	if w := LastWrongNode(); w == nil || w["target"] != "node_b" {
		t.Fatalf("a controller's misaddressed call was not recorded: %#v", w)
	}
	if len(lines) != 0 || MisaddressedFrom() != nil {
		t.Fatalf("a controller call is not a peer's: lines %v, list %#v", lines, MisaddressedFrom())
	}
}

// i1174: one log line per caller per misaddressedWindow, whatever the call
// rate; a second caller has its own line; after the window it logs again.
func TestMisaddressedLoggingIsRateLimitedPerCaller(t *testing.T) {
	strictFor(t, false)
	now, lines := misaddressedFixture(t)
	cfg := &config.Config{NodeID: "node_a"}
	c, d := leaf(t, "node_c", "Mesh Cluster Node"), leaf(t, "node_d", "Mesh Cluster Node")
	for i := 0; i < 20; i++ {
		runTarget(t, cfg, "POST", "/start", "node_b", c)
		*now = now.Add(10 * time.Second)
	}
	if lines["node_c"] != 1 {
		t.Fatalf("20 calls within the window: %d log lines, want 1", lines["node_c"])
	}
	runTarget(t, cfg, "POST", "/start", "node_b", d)
	if lines["node_d"] != 1 || lines["node_c"] != 1 {
		t.Fatalf("a second caller: lines %v, want one each", lines)
	}
	*now = now.Add(misaddressedWindow)
	runTarget(t, cfg, "POST", "/start", "node_b", c)
	if lines["node_c"] != 2 {
		t.Fatalf("after the window: %d log lines for node_c, want 2", lines["node_c"])
	}
	// A caller quiet for longer than the window leaves the report.
	*now = now.Add(misaddressedWindow + time.Second)
	if got := MisaddressedFrom(); got != nil {
		t.Fatalf("quiet callers are still reported: %#v", got)
	}
}

// i1174: the callers tracked are bounded; the one seen longest ago goes.
func TestMisaddressedCallersAreBounded(t *testing.T) {
	strictFor(t, false)
	now, _ := misaddressedFixture(t)
	cfg := &config.Config{NodeID: "node_a"}
	for i := 0; i < misaddressedCallersMax+10; i++ {
		runTarget(t, cfg, "POST", "/start", "node_b", leaf(t, fmt.Sprintf("node_%03d", i), "Mesh Cluster Node"))
		*now = now.Add(time.Second)
	}
	misaddressedMu.Lock()
	n := len(misaddressed)
	_, first := misaddressed["node_000"]
	_, latest := misaddressed[fmt.Sprintf("node_%03d", misaddressedCallersMax+9)]
	misaddressedMu.Unlock()
	if n != misaddressedCallersMax || first || !latest {
		t.Fatalf("tracked %d (want %d), oldest kept %v, latest kept %v", n, misaddressedCallersMax, first, latest)
	}
}
