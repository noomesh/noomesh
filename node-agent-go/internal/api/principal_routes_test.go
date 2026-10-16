// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

// Which routes the controller keeps to itself, exercised through the real
// route table. The unit tests in internal/auth prove the decision; this
// proves the wiring — that a route someone adds with the plain auth
// middleware does not quietly join the privileged set.

func testLeaf(t *testing.T, cn, org string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// mux with a cluster CA configured, so the agent is in the state where it
// asks callers for a certificate and enforces what it finds.
func identifyingMux(t *testing.T) http.Handler {
	t.Helper()
	cfg := &config.Config{
		NodeID:         "test-node",
		NodeAgentToken: "test-token",
		TLSCA:          "ca.pem",
	}
	gpu := hardware.NewGPUDetector(nil, "http")
	return NewServer(cfg, nil, gpu, metrics.NewCollector(gpu)).mux
}

// callAs returns the status the gate produced. This harness has no Docker
// client, so a handler that is actually reached may panic on nil — which
// is itself the answer we want ("the gate let it through"), and is
// reported as reached rather than as a failure.
const reached = 599

func callAs(t *testing.T, h http.Handler, method, path string, peer *x509.Certificate) (code int) {
	t.Helper()
	defer func() {
		if recover() != nil {
			code = reached
		}
	}()
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer test-token")
	r.TLS = &tls.ConnectionState{}
	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

func TestFleetCommandRoutesRefuseANode(t *testing.T) {
	h := identifyingMux(t)
	node := testLeaf(t, "host3", "Mesh Cluster Node")

	// A peer node holds the same fleet token this request carries. Every
	// one of these would let it drive another box.
	for _, c := range []struct{ method, path string }{
		{"POST", "/start"},
		{"POST", "/stop"},
		{"POST", "/restart"},
		{"POST", "/pull"},
		{"POST", "/clean"},
		{"POST", "/cleanup/images"},
		{"POST", "/cleanup/logs"},
		{"POST", "/api/containers/start"},
		{"POST", "/api/containers/stop"},
		{"POST", "/api/skills/run"},
		{"POST", "/tailnet/dialback"},
		// whois names tailnet identities for any IP asked about; a peer
		// holding the fleet secret has no business enumerating them.
		{"GET", "/tailnet/whois"},
		{"GET", "/logs/containers"},
		{"GET", "/logs/noo-gateway"},
		{"POST", "/api/device/screenshot"},
		{"POST", "/api/device/location"},
		{"POST", "/api/device/clipboard"},
		{"POST", "/api/device/camera_capture"},
		{"POST", "/api/device/ambient_audio"},
		{"POST", "/api/device/battery_status"},
	} {
		if got := callAs(t, h, c.method, c.path, node); got != http.StatusForbidden {
			t.Errorf("%s %s: a node leaf must be refused, got %d", c.method, c.path, got)
		}
	}
}

// workRoutes are the proxy/telemetry routes. They used to be open to any
// holder of the fleet HMAC, which is every node.
//
// Every assertion below holds for `/metrics` too, but for a slightly wider
// reason: it is the one route that also admits a cluster SIDECAR leaf
// (Prometheus scrapes with `O="Mesh Cluster Service"` so the
// monitoring container need not hold gateway.key). A node leaf is still
// refused, the controller still reaches it, and an agent that cannot
// identify its callers still 503s, so it belongs in this list. What the
// list does NOT say is "controller-only" — see auth.MetricsReader and the
// service-leaf tests at the bottom of this file.
var workRoutes = []struct{ method, path string }{
	{"GET", "/gpu"},
	{"GET", "/metrics"},
	{"GET", "/stats/containers"},
	{"POST", "/v1/chat/completions"},
	{"POST", "/v1/completions"},
	{"POST", "/v1/embeddings"},
	{"GET", "/v1/models"},
	{"POST", "/embed"},
	{"POST", "/rerank"},
	{"POST", "/v1/rerank"},
	{"GET", "/api/mcp/servers"},
}

// The work routes are the controller's too.
//
// The old assertion here was the opposite — "must not be gated on the
// controller identity" — on the reasoning that running a prompt is not a
// fleet command. But the fleet secret proves only "a node", so that left
// any compromised node able to run prompts on any other node's GPU, read
// its container stats, scrape its metrics and enumerate its MCP servers.
//
// Nothing legitimate needed it: every shipped caller of these paths is the
// gateway process, and Prometheus scrapes /metrics with the gateway's own
// certificate. There is no node→node HTTP call in the tree.
func TestWorkRoutesRefuseANode(t *testing.T) {
	h := identifyingMux(t)
	node := testLeaf(t, "host3", "Mesh Cluster Node")
	for _, c := range workRoutes {
		if got := callAs(t, h, c.method, c.path, node); got != http.StatusForbidden {
			t.Errorf("%s %s: a node leaf must be refused, got %d", c.method, c.path, got)
		}
	}
}

func TestWorkRoutesReachableByTheController(t *testing.T) {
	h := identifyingMux(t)
	ctrl := testLeaf(t, "host8", "Mesh Cluster Gateway")
	for _, c := range workRoutes {
		if got := callAs(t, h, c.method, c.path, ctrl); got == http.StatusForbidden {
			t.Errorf("%s %s: the controller must reach it", c.method, c.path)
		}
	}
}

// An agent with no cluster CA cannot tell the controller from a peer, so it
// refuses the controller's routes outright — 503, naming the missing
// config. It used to SERVE them after a rate-limited warning, which made
// the gate decorative on exactly the nodes that needed it.
func TestUnidentifiedAgentRefusesControllerRoutes(t *testing.T) {
	cfg := &config.Config{NodeID: "test-node", NodeAgentToken: "test-token"} // no TLSCA
	gpu := hardware.NewGPUDetector(nil, "http")
	h := NewServer(cfg, nil, gpu, metrics.NewCollector(gpu)).mux

	for _, c := range append([]struct{ method, path string }{
		{"POST", "/start"},
		{"POST", "/stop"},
		{"POST", "/clean"},
		{"POST", "/api/skills/run"},
		{"POST", "/api/containers/start"},
		{"GET", "/logs/containers"},
	}, workRoutes...) {
		if got := callAs(t, h, c.method, c.path, nil); got != http.StatusServiceUnavailable {
			t.Errorf("%s %s: want 503 from an agent that cannot identify callers, got %d",
				c.method, c.path, got)
		}
	}

	// /health stays reachable — liveness must not need an identity.
	if got := callAs(t, h, "GET", "/health", nil); got != http.StatusOK {
		t.Errorf("/health must stay open on an unidentified agent, got %d", got)
	}
}

func TestControllerReachesFleetCommandRoutes(t *testing.T) {
	h := identifyingMux(t)
	ctrl := testLeaf(t, "host8", "Mesh Cluster Gateway")
	// Docker is nil in this harness, so the handler fails on its own terms
	// — 403 is the answer under test, and it must not appear.
	if got := callAs(t, h, "GET", "/logs/containers", ctrl); got == http.StatusForbidden {
		t.Fatal("the controller must reach its own routes")
	}
}

func TestHealthNeedsNothing(t *testing.T) {
	r := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	identifyingMux(t).ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("health must stay open for probes, got %d", rec.Code)
	}
}

// the design: Prometheus scraped node agents holding gateway.crt AND
// gateway.key, because /metrics accepted only the controller. These four
// tests are the contract that took that key out of the monitoring
// container: a service leaf reads metrics, and a service leaf reads
// NOTHING else.

func TestServiceLeafReachesMetrics(t *testing.T) {
	h := identifyingMux(t)
	svc := testLeaf(t, "prometheus", "Mesh Cluster Service")
	got := callAs(t, h, "GET", "/metrics", svc)
	if got != http.StatusOK {
		t.Fatalf("the scraper's own leaf must reach /metrics, got %d", got)
	}
}

func TestServiceLeafReachesNothingButMetrics(t *testing.T) {
	h := identifyingMux(t)
	svc := testLeaf(t, "prometheus", "Mesh Cluster Service")

	// Every route a compromised Prometheus would have reached while it
	// held gateway.key. If one of these ever answers anything but 403,
	// the service leaf has become a second controller credential.
	for _, c := range []struct{ method, path string }{
		{"POST", "/start"},
		{"POST", "/stop"},
		{"POST", "/restart"},
		{"POST", "/pull"},
		{"POST", "/clean"},
		{"POST", "/cleanup/images"},
		{"POST", "/cleanup/logs"},
		{"POST", "/api/containers/start"},
		{"POST", "/api/containers/stop"},
		{"POST", "/api/skills/run"},
		{"POST", "/tailnet/dialback"},
		{"GET", "/logs/containers"},
		{"GET", "/logs/noo-gateway"},
		{"POST", "/api/device/camera_capture"},
		{"POST", "/api/device/location"},
		{"POST", "/api/device/clipboard"},
	} {
		if got := callAs(t, h, c.method, c.path, svc); got != http.StatusForbidden {
			t.Errorf("%s %s: a service leaf must be refused, got %d", c.method, c.path, got)
		}
	}
}

// The controller keeps its own read: the live fleet scrapes with
// gateway.crt today, and the cutover to a service leaf must not be a flag
// day where metrics go dark until every prometheus.yml is updated.
func TestControllerStillReachesMetrics(t *testing.T) {
	h := identifyingMux(t)
	ctrl := testLeaf(t, "host8", "Mesh Cluster Gateway")
	if got := callAs(t, h, "GET", "/metrics", ctrl); got != http.StatusOK {
		t.Fatalf("the controller must keep reading /metrics, got %d", got)
	}
}

// The fleet secret alone is not a scrape credential. A peer node presents a
// valid bearer and a valid node leaf; before 96a that read every other
// node's metrics.
func TestNodeLeafIsRefusedMetrics(t *testing.T) {
	h := identifyingMux(t)
	node := testLeaf(t, "host3", "Mesh Cluster Node")
	if got := callAs(t, h, "GET", "/metrics", node); got != http.StatusForbidden {
		t.Fatalf("a peer node must not scrape this node, got %d", got)
	}
}
