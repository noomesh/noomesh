// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package preseed

// -i: the model-cache client authenticates with the node's
// own leaf, and there is exactly one way to learn where the store is.
//
// Three guards, each planted against the failure it exists for:
//
//   - a store that REQUIRES a client certificate accepts New() and refuses
//     the old bare client at the handshake — so the test is proven to be
//     looking at client-cert enforcement, not merely at "TLS works";
//   - a configured-but-unreadable certificate makes every method return
//     the error, never a bare client (the silent downgrade);
//   - CacheURL() rewrites the legacy plaintext value only when the node can
//     actually present a certificate, and never rewrites https.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// testPKI is a throwaway cluster CA with one server leaf (valid for
// 127.0.0.1) and one client leaf (O="Mesh Cluster Node"), written as PEM
// files the way the node's env names them.
type testPKI struct {
	dir                    string
	caPEM, certPEM, keyPEM string
	serverCert             tls.Certificate
	pool                   *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mesh Cluster CA", Organization: []string{"Mesh Cluster"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leaf := func(cn, org string, usage x509.ExtKeyUsage, ips []net.IP) (tls.Certificate, string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
		tc, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			t.Fatal(err)
		}
		return tc, certPEM, keyPEM
	}
	server, _, _ := leaf("model-cache", "Mesh Cluster Service", x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1)})
	_, clientCert, clientKey := leaf("host3", "Mesh Cluster Node", x509.ExtKeyUsageClientAuth, nil)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	p := &testPKI{
		dir:        dir,
		caPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		certPEM:    clientCert,
		keyPEM:     clientKey,
		serverCert: server,
		pool:       pool,
	}
	for name, body := range map[string]string{"ca.crt": p.caPEM, "node.crt": p.certPEM, "node.key": p.keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// setNodeEnv points the node's PKI env at the test files.
func (p *testPKI) setNodeEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NOO_TLS_CA", filepath.Join(p.dir, "ca.crt"))
	t.Setenv("NOO_TLS_CERT", filepath.Join(p.dir, "node.crt"))
	t.Setenv("NOO_TLS_KEY", filepath.Join(p.dir, "node.key"))
}

// storeRequiringClientCert is the 8443 listener's contract in miniature:
// TLS, and a cluster-CA client certificate or no connection.
func (p *testPKI) storeRequiringClientCert(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("weights"))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{p.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestNewPresentsTheNodeLeafAndTheBareClientIsRefused(t *testing.T) {
	p := newTestPKI(t)
	p.setNodeEnv(t)
	var hits atomic.Int32
	srv := p.storeRequiringClientCert(t, &hits)
	dest := filepath.Join(t.TempDir(), "w.gguf")

	// The client this package builds: CA pinned, node leaf presented.
	c := New()
	if err := c.Err(); err != nil {
		t.Fatalf("New() failed to build from a readable PKI: %v", err)
	}
	wrote, err := c.FetchOne(context.Background(), srv.URL+"/gguf/w.gguf", dest)
	if err != nil {
		t.Fatalf("mTLS fetch: %v", err)
	}
	if !wrote {
		t.Fatal("expected the file to be written")
	}
	if b, _ := os.ReadFile(dest); string(b) != "weights" {
		t.Fatalf("body = %q", b)
	}
	if hits.Load() != 1 {
		t.Fatalf("server hits = %d, want 1", hits.Load())
	}

	// PLANT: the client this package USED to build (`&http.Client{}`, the
	// default transport) against the same store. It must fail at the
	// handshake — proving the store above really requires a certificate,
	// so the success above is a success of the leaf, not of TLS being on.
	bare := &Client{HTTP: &http.Client{Timeout: 5 * time.Second}}
	if _, err := bare.FetchOne(context.Background(), srv.URL+"/gguf/w.gguf", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("the bare client fetched from a store that requires a client certificate — the test server is not enforcing it")
	}
	// And a client that trusts the CA but presents nothing: the exact shape
	// of a node whose env lost NOO_TLS_CERT. Handshake, not 401.
	noLeaf := &Client{HTTP: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS12},
	}}}
	if _, err := noLeaf.FetchOne(context.Background(), srv.URL+"/gguf/w.gguf", filepath.Join(t.TempDir(), "y")); err == nil {
		t.Fatal("a client with no leaf fetched from a store that requires one")
	}
	if hits.Load() != 1 {
		t.Fatalf("server hits = %d after the planted clients, want still 1 (they must fail before a request is served)", hits.Load())
	}
}

func TestAConfiguredButMissingCertIsAnErrorNotABareClient(t *testing.T) {
	p := newTestPKI(t)
	p.setNodeEnv(t)
	t.Setenv("NOO_TLS_CERT", filepath.Join(p.dir, "does-not-exist.crt"))
	var hits atomic.Int32
	srv := p.storeRequiringClientCert(t, &hits)

	c := New()
	if c.Err() == nil {
		t.Fatal("New() built a client from an unreadable NOO_TLS_CERT")
	}
	ctx := context.Background()
	dst := t.TempDir()
	if _, err := c.FetchOne(ctx, srv.URL+"/a", filepath.Join(dst, "a")); err == nil || !strings.Contains(err.Error(), "NOO_TLS_CERT") {
		t.Fatalf("FetchOne: want the construction error naming NOO_TLS_CERT, got %v", err)
	}
	if _, err := c.FetchOneVerified(ctx, srv.URL+"/b", filepath.Join(dst, "b"), strings.Repeat("0", 64)); err == nil {
		t.Fatal("FetchOneVerified on a failed client returned nil")
	}
	if _, err := c.Mirror(ctx, srv.URL+"/c/", filepath.Join(dst, "c")); err == nil {
		t.Fatal("Mirror on a failed client returned nil")
	}
	if _, err := c.MirrorHFRepo(ctx, srv.URL+"/d/", filepath.Join(dst, "d")); err == nil {
		t.Fatal("MirrorHFRepo on a failed client returned nil")
	}
	if hits.Load() != 0 {
		t.Fatalf("a client that failed to build reached the store %d time(s)", hits.Load())
	}
}

func TestResolveCacheURLRefusesPlaintextAndACertlessNode(t *testing.T) {
	// Phase 2 C-i: https + a client certificate, or nothing.
	ok := []struct{ raw, want string }{
		{"https://noo-controller:8443", "https://noo-controller:8443"},
		{"https://noo-controller:8443/", "https://noo-controller:8443"},
		{"https://100.64.0.7:8443", "https://100.64.0.7:8443"},
		{"https://[fd7a::1]:8443", "https://[fd7a::1]:8443"},
		{"https://noo-controller:9443", "https://noo-controller:9443"}, // a non-default TLS port is the operator's
		{"", ""},
		{"  ", ""},
	}
	for _, c := range ok {
		got, err := resolveCacheURL(c.raw, true)
		if err != nil || got != c.want {
			t.Errorf("resolveCacheURL(%q, cert) = %q, %v; want %q, nil", c.raw, got, err, c.want)
		}
	}
	// Every plaintext value provision ever rendered, and the shapes phase 1
	// used to rewrite: all refused, each naming the variable and the https
	// form of the same host.
	plain := []struct{ raw, wantForm string }{
		{"http://noo-controller:8083", "https://noo-controller:8443"},
		{"http://noo-controller:8083/", "https://noo-controller:8443"},
		{"http://100.64.0.7:8083", "https://100.64.0.7:8443"},
		{"http://host8.tail1234.ts.net", "https://host8.tail1234.ts.net:8443"},
		{"http://[fd7a::1]:8083", "https://[fd7a::1]:8443"},
		{"http://noo-controller:9999", "https://noo-controller:8443"},
	}
	for _, c := range plain {
		for _, cert := range []bool{true, false} {
			got, err := resolveCacheURL(c.raw, cert)
			if err == nil || got != "" {
				t.Fatalf("resolveCacheURL(%q, cert=%v) = %q, %v — a plaintext store must be refused, never used or rewritten", c.raw, cert, got, err)
			}
			for _, needle := range []string{"NOO_MODEL_CACHE_URL", c.wantForm, "noo cluster provision"} {
				if !strings.Contains(err.Error(), needle) {
					t.Errorf("resolveCacheURL(%q, cert=%v): refusal %q does not name %q", c.raw, cert, err, needle)
				}
			}
		}
	}
	// No certificate: an https URL is still unusable, and the refusal says
	// how a node gets its leaf.
	got, err := resolveCacheURL("https://noo-controller:8443", false)
	if err == nil || got != "" {
		t.Fatalf("resolveCacheURL(https, no cert) = %q, %v — want a refusal", got, err)
	}
	if !strings.Contains(err.Error(), "noo cluster provision") || !strings.Contains(err.Error(), "NOO_TLS_CERT") {
		t.Errorf("certless refusal %q names neither the remedy nor the missing setting", err)
	}
	// Off is off, with or without a certificate: no refusal for an unset feature.
	if got, err := resolveCacheURL("", false); err != nil || got != "" {
		t.Errorf("resolveCacheURL(\"\", no cert) = %q, %v; want \"\", nil", got, err)
	}
	// Not a URL at all.
	if got, err := resolveCacheURL("noo-controller:8443", true); err == nil || got != "" {
		t.Errorf("resolveCacheURL(bare host) = %q, %v; want a refusal", got, err)
	}
}

func TestCacheURLReportsARefusalToTheControllerAndClearsIt(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	t.Setenv("NOO_TLS_CERT", "/etc/noo/pki/node.crt")
	t.Setenv("NOO_TLS_KEY", "/etc/noo/pki/node.key")

	// The value provision rendered before 1234 C-i, still in an old env file.
	t.Setenv("NOO_MODEL_CACHE_URL", "http://noo-controller:8083")
	if got := CacheURL(); got != "" {
		t.Fatalf("CacheURL() with a plaintext value = %q, want \"\" (refused)", got)
	}
	rs := refusals.List()
	if len(rs) != 1 || rs[0].Scope != RefusalScope || rs[0].Target != "http://noo-controller:8083" {
		t.Fatalf("refusals after a plaintext value = %+v; want one %s refusal naming the value", rs, RefusalScope)
	}
	if !strings.Contains(rs[0].Reason, "https://noo-controller:8443") {
		t.Fatalf("the refusal reason does not carry the https form: %q", rs[0].Reason)
	}
	// Re-reading does not multiply the refusal.
	_ = CacheURL()
	if n := len(refusals.List()); n != 1 {
		t.Fatalf("refusals after a second read = %d, want 1", n)
	}

	// Without a leaf the https value is refused too, under the same scope.
	t.Setenv("NOO_MODEL_CACHE_URL", "https://noo-controller:8443")
	t.Setenv("NOO_TLS_CERT", "")
	t.Setenv("NOO_TLS_KEY", "")
	if got := CacheURL(); got != "" {
		t.Fatalf("CacheURL() without a leaf = %q, want \"\" (refused)", got)
	}
	rs = refusals.List()
	if len(rs) != 1 || rs[0].Target != "https://noo-controller:8443" {
		t.Fatalf("refusals after the certless read = %+v; want exactly the new one (the old cleared)", rs)
	}

	// Fixed: the refusal is cleared and the URL is used.
	t.Setenv("NOO_TLS_CERT", "/etc/noo/pki/node.crt")
	t.Setenv("NOO_TLS_KEY", "/etc/noo/pki/node.key")
	if got := CacheURL(); got != "https://noo-controller:8443" {
		t.Fatalf("CacheURL() with a leaf and an https value = %q", got)
	}
	if rs := refusals.List(); len(rs) != 0 {
		t.Fatalf("a fixed value still reports a refusal: %+v", rs)
	}
	t.Setenv("NOO_MODEL_CACHE_URL", "")
	if got := CacheURL(); got != "" {
		t.Fatalf("CacheURL() unset = %q, want \"\"", got)
	}
	if rs := refusals.List(); len(rs) != 0 {
		t.Fatalf("an unset feature reports a refusal: %+v", rs)
	}
}

// Every reader of NOO_MODEL_CACHE_URL goes through CacheURL(), so the
// normalisation above cannot be bypassed by a seventh copy of the old
// `strings.TrimRight(os.Getenv(...), "/")` line. Source-grep, over the
// whole module, non-test files.
func TestOnlyCacheURLReadsTheEnvironmentVariable(t *testing.T) {
	root := moduleRoot(t)
	needle := regexp.MustCompile(`os\.Getenv\(\s*"NOO_MODEL_CACHE_URL"\s*\)`)
	var readers []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || (strings.HasPrefix(d.Name(), ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for range needle.FindAll(b, -1) {
			rel, _ := filepath.Rel(root, path)
			readers = append(readers, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("internal", "preseed", "preseed.go")
	if len(readers) != 1 || readers[0] != want {
		t.Fatalf("NOO_MODEL_CACHE_URL is read at %v; the ONE reader must be %s (CacheURL) — route the new site through it", readers, want)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}
