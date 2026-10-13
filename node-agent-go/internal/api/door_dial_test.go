// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// The host3 outage, 2026-09-29 (noo-cli-v0.5.63/64): the node agent is a
// HOST process and dials its backend doors by container name
// (https://noo-vllm:8000, https://noo-stunnel-<x>:<port>) so hostname
// verification lands on the door leaf's SAN. Container names do not resolve
// on the host; every door dial must go through the host-mode dialer
// (BackendDialContext = containerdial), which swaps the name for an address
// the host can reach while SNI + verification stay on the door name. And
// the door must verify against the CA the agent's CONFIG names — the proxy
// used to read only the container path /app/pki/ca.crt, which does not
// exist on a host install.
//
// The door here is a real mTLS listener whose leaf carries ONLY the DNS SAN
// `noo-vllm` (no IP SAN), requires a client certificate from the test CA,
// and is reachable only through the recording dialer. A transport that
// dials the container name with the ordinary dialer (system DNS) fails; a
// transport that verifies against anything but NOO_TLS_CA fails; a
// transport that verifies the dialled IP instead of the door name fails.

type testPKI struct {
	caPEM, srvCert, srvKey, cliCert, cliKey []byte
	caPool                                  *x509.CertPool
}

func mkLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, dns []string, usage x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "doordial test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	p := &testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	p.caPool = x509.NewCertPool()
	p.caPool.AddCert(ca)
	// The door leaf: DNS SAN noo-vllm ONLY — no localhost, no IP SAN — so a
	// pass proves verification ran against the door NAME, not the address
	// the dialer actually connected to.
	p.srvCert, p.srvKey = mkLeaf(t, ca, caKey, "noo-vllm", []string{"noo-vllm"}, x509.ExtKeyUsageServerAuth)
	p.cliCert, p.cliKey = mkLeaf(t, ca, caKey, "host3", []string{"host3"}, x509.ExtKeyUsageClientAuth)
	return p
}

// startDoor runs an mTLS door (client cert REQUIRED, as vLLM's
// --ssl-cert-reqs 2 and stunnel's verify = 2 are) and returns its address.
func startDoor(t *testing.T, p *testPKI) string {
	t.Helper()
	pair, err := tls.X509KeyPair(p.srvCert, p.srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.caPool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func writePKI(t *testing.T, p *testPKI) *config.Config {
	t.Helper()
	dir := t.TempDir()
	w := func(name string, b []byte) string {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	return &config.Config{
		TLSCA:   w("ca.crt", p.caPEM),
		TLSCert: w("node.crt", p.cliCert),
		TLSKey:  w("node.key", p.cliKey),
	}
}

// hostDialer stands in for containerdial: it knows the door containers and
// sends each to the one listener; anything else is a failure the test sees.
type hostDialer struct {
	mu     sync.Mutex
	doors  map[string]string // container host:port -> reachable addr
	dialed []string
}

func (h *hostDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	h.mu.Lock()
	h.dialed = append(h.dialed, addr)
	to, ok := h.doors[addr]
	h.mu.Unlock()
	if !ok {
		return nil, errors.New("hostDialer: " + addr + " is not a door")
	}
	return (&net.Dialer{}).DialContext(ctx, network, to)
}

func withHostDialer(t *testing.T, h *hostDialer) {
	t.Helper()
	prev := BackendDialContext
	BackendDialContext = h.dial
	t.Cleanup(func() { BackendDialContext = prev })
}

// Every transport the agent dials a door with — the inference reverse proxy
// (httpsTransport) and the rerank/embed proxies (backendClient) — reaches the
// door THROUGH the host dialer, by the door's name, verifies the door leaf
// against NOO_TLS_CA with the door name as ServerName, and presents the node
// leaf.
func TestEveryDoorDialGoesThroughTheHostDialer(t *testing.T) {
	p := newTestPKI(t)
	door := startDoor(t, p)
	cfg := writePKI(t, p)
	h := &hostDialer{doors: map[string]string{"noo-vllm:8000": door}}
	withHostDialer(t, h)

	s := &Server{cfg: cfg}
	clients := map[string]*http.Client{
		"inference proxy (httpsTransport)": {Timeout: 5 * time.Second, Transport: httpsTransport(cfg)},
		"rerank/embed (backendClient)":     s.backendClient("https://noo-vllm:8000", 5*time.Second),
	}
	for name, c := range clients {
		h.dialed = nil
		resp, err := c.Get("https://noo-vllm:8000/v1/models")
		if err != nil {
			t.Fatalf("%s: door dial failed: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: door answered %d (client leaf not presented?)", name, resp.StatusCode)
		}
		if len(h.dialed) == 0 || h.dialed[0] != "noo-vllm:8000" {
			t.Fatalf("%s: host dialer saw %v — the container name went to the ordinary (DNS) dialer", name, h.dialed)
		}
	}
}

// Verification is against the DOOR NAME the URL carries, not the address
// dialled: the same listener reached as noo-stunnel-x (a name its leaf does
// not carry) must fail the handshake.
func TestDoorVerificationIsOnTheDoorName(t *testing.T) {
	p := newTestPKI(t)
	door := startDoor(t, p)
	cfg := writePKI(t, p)
	h := &hostDialer{doors: map[string]string{"noo-stunnel-x:443": door}}
	withHostDialer(t, h)

	c := &http.Client{Timeout: 5 * time.Second, Transport: httpsTransport(cfg)}
	_, err := c.Get("https://noo-stunnel-x:443/health")
	if err == nil || !strings.Contains(err.Error(), "noo-stunnel-x") {
		t.Fatalf("a door whose leaf does not name the dialled door must fail verification, got %v", err)
	}
}

// Without the host dialer, a container name is not dialable from the host —
// the shape of the outage. Pins that the passing test above passes BECAUSE
// of the dialer, not because the name happens to resolve here.
func TestContainerNameIsNotDialableWithoutTheHostDialer(t *testing.T) {
	p := newTestPKI(t)
	_ = startDoor(t, p)
	cfg := writePKI(t, p)
	prev := BackendDialContext
	BackendDialContext = nil
	t.Cleanup(func() { BackendDialContext = prev })

	c := &http.Client{Timeout: 3 * time.Second, Transport: httpsTransport(cfg)}
	if _, err := c.Get("https://noo-vllm:8000/v1/models"); err == nil {
		t.Fatal("noo-vllm resolved on this host without the host dialer — the test above proves nothing here")
	}
}

// The CA the proxy verifies doors with is the one the agent config names.
func TestProxyCAIsTheConfiguredOne(t *testing.T) {
	if got := clusterCAPath(&config.Config{TLSCA: "/etc/noo/pki/ca.crt"}); got != "/etc/noo/pki/ca.crt" {
		t.Fatalf("clusterCAPath = %q, want NOO_TLS_CA", got)
	}
	if got := clusterCAPath(&config.Config{}); got != containerCAPath {
		t.Fatalf("clusterCAPath with no NOO_TLS_CA = %q, want the container mount", got)
	}
}
