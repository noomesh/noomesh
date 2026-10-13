// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package preseedtest is test support for callers of the preseed client:
// a throwaway cluster CA, a node leaf the way the agent's env names it,
// and a model-cache store that answers only a node leaf — the 8443
// contract in miniature. Since phase 2 C-i the store is
// mTLS-only and `preseed.CacheURL()` refuses a plaintext URL, so a test
// that used to point NOO_MODEL_CACHE_URL at a plain httptest server has
// to stand up this instead. Not a _test file so other packages' tests can
// import it; it must never be imported by non-test code.
package preseedtest

import (
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
	"testing"
	"time"
)

// PKI is a throwaway cluster CA with one server leaf (valid for 127.0.0.1)
// and one client leaf (O="Mesh Cluster Node"), written as PEM files.
type PKI struct {
	Dir        string
	serverCert tls.Certificate
	pool       *x509.CertPool
}

// New generates the CA and both leaves under a temp dir.
func New(t *testing.T) *PKI {
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
	p := &PKI{Dir: dir, serverCert: server, pool: pool}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	for name, body := range map[string]string{"ca.crt": caPEM, "node.crt": clientCert, "node.key": clientKey} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// SetNodeEnv points the node's PKI env (NOO_TLS_CA/CERT/KEY) at the files,
// for the duration of the test.
func (p *PKI) SetNodeEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NOO_TLS_CA", filepath.Join(p.Dir, "ca.crt"))
	t.Setenv("NOO_TLS_CERT", filepath.Join(p.Dir, "node.crt"))
	t.Setenv("NOO_TLS_KEY", filepath.Join(p.Dir, "node.key"))
}

// Store serves handler over TLS with the server leaf and REQUIRES a
// cluster-CA client certificate — no leaf, no connection. Its URL is
// https://127.0.0.1:<port>, which `preseed.CacheURL()` accepts as given.
func (p *PKI) Store(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
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
