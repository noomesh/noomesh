// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

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
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// leaf builds a certificate with the given Organization, standing in for
// what the cluster CA stamps on each kind of principal.
func leaf(t *testing.T, cn, org string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// identifying returns a config in the state where the check is live: TLS
// on, cluster CA configured, so the handshake asks callers for a cert.
func identifying(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{TLSCA: "ca.pem"}
}

func request(peer *x509.Certificate) *http.Request {
	r := httptest.NewRequest("POST", "/start", nil)
	if peer != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	} else {
		r.TLS = &tls.ConnectionState{}
	}
	return r
}

func serve(t *testing.T, cfg *config.Config, r *http.Request, actor string) *httptest.ResponseRecorder {
	t.Helper()
	reached := false
	h := ControllerOnly(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	serveAs(h, rec, r, cfg, actor)
	if reached != (rec.Code == http.StatusOK) {
		t.Fatalf("handler reached=%v but status=%d", reached, rec.Code)
	}
	return rec
}

func TestControllerCertPasses(t *testing.T) {
	rec := serve(t, identifying(t), request(leaf(t, "host8", "Mesh Cluster Gateway")), "gateway")
	if rec.Code != http.StatusOK {
		t.Fatalf("the controller must reach its own routes, got %d: %s", rec.Code, rec.Body)
	}
}

// The whole point: a node holds the fleet secret and can mint a token
// naming anyone, but it cannot obtain a gateway leaf — issuing one needs
// the CA key, which lives on the controller.
func TestNodeCertCannotCommandAPeer(t *testing.T) {
	r := request(leaf(t, "host3", "Mesh Cluster Node"))
	rec := serve(t, identifying(t), r, "gateway") // claims to be the gateway
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a node presenting a node leaf must be refused, got %d", rec.Code)
	}
}

func TestNoCertIsNotTheController(t *testing.T) {
	rec := serve(t, identifying(t), request(nil), "gateway")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a caller with a valid token but no cert must be refused, got %d", rec.Code)
	}
}

// A plaintext agent cannot tell callers apart, so it refuses the
// controller's routes outright.
//
// The old assertion was the opposite — "a plaintext agent must keep
// serving", warning instead of refusing, on the reasoning that refusing
// would lock out the controller too. But the consequence was that the gate
// did nothing on exactly the nodes that needed it: any holder of the fleet
// secret (every other node) could start, stop, pull, clean, run a skill or
// read container logs on such a box, and the only trace was a rate-limited
// line in that node's own journal.
//
// 503, not 403: the caller is not forbidden, the NODE is not configured to
// make the guarantee this route needs, and the message says which files to
// install.
func TestPlaintextAgentRefusesControllerRoutes(t *testing.T) {
	cfg := &config.Config{}
	r := httptest.NewRequest("POST", "/start", nil) // r.TLS == nil
	rec := serve(t, cfg, r, "gateway")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a plaintext agent must refuse controller routes, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "NOO_TLS_CA") {
		t.Errorf("the refusal must name the missing config, got %q", rec.Body.String())
	}
}

// TLS without a cluster CA verifies nothing, so it is the same case.
func TestTLSWithoutClusterCAIsNotIdentifying(t *testing.T) {
	cfg := &config.Config{TLSCert: "c.pem", TLSKey: "k.pem"}
	if canIdentifyPeers(cfg, request(nil)) {
		t.Fatal("no CA means no client verification, so peers are indistinguishable")
	}
}

// A privileged route reached without the token middleware having run is a
// wiring bug; guessing is how a gate becomes decorative.
func TestMissingPrincipalFailsClosed(t *testing.T) {
	h := ControllerOnly(identifying(t))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler must not be reached without a principal")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/start", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

// The org overrides are retired: a set one is a refusal naming it, and it
// never changes what counts as the controller.
func TestRetiredOrgOverridesAreARefusalNotAKnob(t *testing.T) {
	for _, name := range RetiredOrgOverrides {
		t.Setenv(name, "Acme Control Plane")
	}
	env := map[string]string{"NOO_CONTROLLER_CERT_ORG": "Acme Control Plane"}
	msg := RetiredOrgOverrideRefusal(func(k string) string { return env[k] })
	if !strings.Contains(msg, "NOO_CONTROLLER_CERT_ORG") {
		t.Fatalf("the refusal must name the variable, got %q", msg)
	}
	for _, name := range []string{"NOO_SERVICE_CERT_ORG", "NOO_NODE_CERT_ORG"} {
		one := map[string]string{name: "x"}
		if m := RetiredOrgOverrideRefusal(func(k string) string { return one[k] }); !strings.Contains(m, name) {
			t.Fatalf("%s set must refuse, got %q", name, m)
		}
	}
	if m := RetiredOrgOverrideRefusal(func(string) string { return "  " }); m != "" {
		t.Fatalf("blank is unset, got %q", m)
	}
	// Even with the variables set in THIS process, the check reads the
	// fixed organizations: the override is gone, not merely unused.
	if isController([]*x509.Certificate{leaf(t, "c", "Acme Control Plane")}) {
		t.Fatal("an overridden org must not pass as the controller")
	}
	if !isController([]*x509.Certificate{leaf(t, "c", "Mesh Cluster Gateway")}) {
		t.Fatal("the fixed controller org must still pass")
	}
}

func TestServiceLeafIsNotTheController(t *testing.T) {
	// Sidecars get O="Mesh Cluster Service". They serve metrics; they do
	// not command boxes.
	if isController([]*x509.Certificate{leaf(t, "nvidia-exporter", "Mesh Cluster Service")}) {
		t.Fatal("a service leaf must not pass as the controller")
	}
}

func TestPeerIdentityEnforcedNeedsAllThree(t *testing.T) {
	// The agent reports this to the controller, so a false positive is
	// worse than a false negative: it would report "enforcing" on a node
	// that serves fleet-command routes to any peer.
	full := &config.Config{TLSCert: "/c", TLSKey: "/k", TLSCA: "/ca"}
	if !PeerIdentityEnforced(full) {
		t.Fatal("cert+key+ca should count as enforced")
	}
	for name, cfg := range map[string]*config.Config{
		"no ca":   {TLSCert: "/c", TLSKey: "/k"},
		"no cert": {TLSKey: "/k", TLSCA: "/ca"},
		"no key":  {TLSCert: "/c", TLSCA: "/ca"},
		"empty":   {},
	} {
		if PeerIdentityEnforced(cfg) {
			t.Fatalf("%s: must not report enforced", name)
		}
	}
}

func TestMetricsReaderAcceptsTheScraperAndTheController(t *testing.T) {
	for _, org := range []string{"Mesh Cluster Service", "Mesh Cluster Gateway"} {
		served := false
		h := Middleware(tokenCfg(t))(MetricsReader(identifyingToken(t))(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, metricsRequest(leaf(t, "prometheus", org)))
		if !served {
			t.Errorf("%s: must reach /metrics, got %d", org, rec.Code)
		}
	}
}

// Every node now holds backend-door leaves with O=Mesh Cluster Service. A
// service leaf that is not the scraper's must not read another node's
// metrics.
func TestMetricsReaderRefusesANonScraperServiceLeaf(t *testing.T) {
	for _, cn := range []string{"vllm", "llamacpp", "ollama", "tei", "reranker", "grafana"} {
		h := Middleware(tokenCfg(t))(MetricsReader(identifyingToken(t))(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatalf("service leaf %q must not scrape a node", cn)
			})))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, metricsRequest(leaf(t, cn, "Mesh Cluster Service")))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: want 403, got %d", cn, rec.Code)
		}
	}
}

func TestMetricsReaderRefusesAPeerNode(t *testing.T) {
	h := Middleware(tokenCfg(t))(MetricsReader(identifyingToken(t))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("a node leaf must not scrape another node")
		})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, metricsRequest(leaf(t, "host3", "Mesh Cluster Node")))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

// The service org is NOT a second controller credential. If this ever
// passes, the 96a fix has been undone: the scrape leaf would command boxes.
func TestServiceOrgIsNotTheControllerOrg(t *testing.T) {
	if isController([]*x509.Certificate{leaf(t, "prometheus", "Mesh Cluster Service")}) {
		t.Fatal("a service leaf must never satisfy the controller check")
	}
	if isService([]*x509.Certificate{leaf(t, "host8", "Mesh Cluster Gateway")}) {
		t.Fatal("a gateway leaf must not be classified as a service")
	}
}

// MetricsReader without the token middleware in front is the same wiring
// bug ControllerOnly guards against.
func TestMetricsReaderFailsClosedWithoutAPrincipal(t *testing.T) {
	h := MetricsReader(identifyingToken(t))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not be reached without a principal")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func tokenCfg(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{NodeAgentToken: "test-token", TLSCA: "ca.pem"}
}

func identifyingToken(t *testing.T) *config.Config { return tokenCfg(t) }

func metricsRequest(peer *x509.Certificate) *http.Request {
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer test-token")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	return r
}

// ── the design: this node's own harness over loopback ───────────

func serveModel(t *testing.T, cfg *config.Config, r *http.Request, actor string) *httptest.ResponseRecorder {
	t.Helper()
	reached := false
	h := ControllerOrOwnHarness(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	serveAs(h, rec, r, cfg, actor)
	if reached != (rec.Code == http.StatusOK) {
		t.Fatalf("handler reached=%v but status=%d", reached, rec.Code)
	}
	return rec
}

func ownNodeCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg := identifying(t)
	cfg.NodeID = "host3"
	return cfg
}

// The harness beside this agent: this node's leaf, from loopback → served.
func TestOwnHarnessOverLoopbackGetsAModel(t *testing.T) {
	r := request(leaf(t, "host3", "Mesh Cluster Node"))
	r.RemoteAddr = "127.0.0.1:41234"
	if rec := serveModel(t, ownNodeCfg(t), r, "harness"); rec.Code != http.StatusOK {
		t.Fatalf("this node's own harness over loopback must be served, got %d: %s", rec.Code, rec.Body)
	}
	// IPv6 loopback is loopback too.
	r.RemoteAddr = "[::1]:41234"
	if rec := serveModel(t, ownNodeCfg(t), r, "harness"); rec.Code != http.StatusOK {
		t.Fatalf("::1 is loopback, got %d", rec.Code)
	}
}

// Same certificate, not loopback: this node's leaf used from another box
// (a copied key) is not the harness beside this agent.
func TestOwnLeafFromAnotherHostIsRefused(t *testing.T) {
	r := request(leaf(t, "host3", "Mesh Cluster Node"))
	r.RemoteAddr = "100.64.0.11:41234"
	if rec := serveModel(t, ownNodeCfg(t), r, "harness"); rec.Code != http.StatusForbidden {
		t.Fatalf("own leaf off loopback must be refused, got %d", rec.Code)
	}
}

// Loopback, but a PEER node's certificate: same node only is enforced by
// identity — a genuine node leaf naming a different id is a peer.
func TestPeerLeafOverLoopbackIsRefused(t *testing.T) {
	r := request(leaf(t, "host2", "Mesh Cluster Node"))
	r.RemoteAddr = "127.0.0.1:41234"
	if rec := serveModel(t, ownNodeCfg(t), r, "harness"); rec.Code != http.StatusForbidden {
		t.Fatalf("a peer's leaf over loopback must be refused, got %d", rec.Code)
	}
}

// The grant is inference-only: ControllerOnly is untouched by it, so the
// same caller that gets a model still cannot start, stop or pull.
func TestOwnHarnessCannotCommandThisNode(t *testing.T) {
	r := request(leaf(t, "host3", "Mesh Cluster Node"))
	r.RemoteAddr = "127.0.0.1:41234"
	if rec := serve(t, ownNodeCfg(t), r, "harness"); rec.Code != http.StatusForbidden {
		t.Fatalf("the own harness must not reach a fleet-command route, got %d", rec.Code)
	}
}

// The controller keeps everything it had on the model routes.
func TestControllerStillGetsModels(t *testing.T) {
	if rec := serveModel(t, ownNodeCfg(t), request(leaf(t, "host8", "Mesh Cluster Gateway")), "gateway"); rec.Code != http.StatusOK {
		t.Fatalf("controller on a model route: %d", rec.Code)
	}
}

// An agent that cannot identify callers serves the own harness no more
// than it serves the controller: the 503 names the missing config.
func TestOwnHarnessNeedsAnIdentifyingAgent(t *testing.T) {
	cfg := &config.Config{NodeID: "host3"} // no TLSCA: cannot tell callers apart
	r := request(leaf(t, "host3", "Mesh Cluster Node"))
	r.RemoteAddr = "127.0.0.1:41234"
	if rec := serveModel(t, cfg, r, "harness"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unidentifying agent must refuse with 503, got %d", rec.Code)
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:1": true, "[::1]:1": true, "127.0.0.9:80": true,
		"100.64.0.11:1": false, "10.0.0.1:1": false, "": false, "garbage": false, "localhost:1": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

// The scraper presents its leaf and no bearer; a node
// leaf, or no certificate, still needs the token; and an agent that cannot
// identify peers believes no certificate.
func TestTheScraperLeafNeedsNoBearerAndNothingElseSkipsIt(t *testing.T) {
	run := func(cfg *config.Config, peer *x509.Certificate, bearer string) int {
		h := ServiceLeafOrToken(cfg)(MetricsReader(cfg)(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
		r := httptest.NewRequest("GET", "/metrics", nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if peer != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
		} else {
			r.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	cfg := tokenCfg(t)
	prom := leaf(t, "prometheus", "Mesh Cluster Service")
	if c := run(cfg, prom, ""); c != http.StatusOK {
		t.Fatalf("scraper leaf, no bearer: got %d, want 200", c)
	}
	if c := run(cfg, leaf(t, "host3", "Mesh Cluster Node"), ""); c != http.StatusUnauthorized {
		t.Fatalf("node leaf, no bearer: got %d, want 401", c)
	}
	if c := run(cfg, nil, ""); c != http.StatusUnauthorized {
		t.Fatalf("no cert, no bearer: got %d, want 401", c)
	}
	if c := run(cfg, prom, "${NOO_NODE_AGENT_TOKEN}"); c != http.StatusForbidden {
		t.Fatalf("the old literal bearer is still refused: got %d, want 403", c)
	}
	blind := &config.Config{NodeAgentToken: "test-token"} // no cluster CA
	if c := run(blind, prom, ""); c != http.StatusUnauthorized {
		t.Fatalf("an agent without the cluster CA must not believe a leaf: got %d, want 401", c)
	}
}
