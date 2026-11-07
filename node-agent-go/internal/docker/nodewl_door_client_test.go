// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testPKI struct {
	dir   string
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	pool  *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{dir: t.TempDir(), ca: ca, caKey: key, pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	if err := os.WriteFile(filepath.Join(p.dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// leaf signs a certificate and returns it, writing <name>.crt/.key when asked.
func (p *testPKI) leaf(t *testing.T, cn string, dns []string, usage x509.ExtKeyUsage, write bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kpem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if write {
		if err := os.WriteFile(filepath.Join(p.dir, cn+".crt"), crt, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p.dir, cn+".key"), kpem, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := tls.X509KeyPair(crt, kpem)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The door client presents the agent's own leaf, trusts only the cluster CA,
// checks the door's name (not its address), and follows no redirect.
func TestDoorRequestUsesTheAgentLeafAndTheDoorName(t *testing.T) {
	pki := newTestPKI(t)
	server := pki.leaf(t, "door", []string{"noo-stunnel-rhaddon-worker"}, x509.ExtKeyUsageServerAuth, false)
	pki.leaf(t, "node-a", nil, x509.ExtKeyUsageClientAuth, true)

	var gotCN, gotMethod, gotPath string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCN, gotMethod, gotPath = r.TLS.PeerCertificates[0].Subject.CommonName, r.Method, r.URL.Path
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.pool}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	ca, crt, key := filepath.Join(pki.dir, "ca.crt"), filepath.Join(pki.dir, "node-a.crt"), filepath.Join(pki.dir, "node-a.key")

	code, err := doorRequest(context.Background(), ca, crt, key, addr, "noo-stunnel-rhaddon-worker", http.MethodPost, "/v1/lifecycle/drain")
	if err != nil || code != http.StatusAccepted {
		t.Fatalf("code, err = %d, %v", code, err)
	}
	if gotCN != "node-a" || gotMethod != http.MethodPost || gotPath != "/v1/lifecycle/drain" {
		t.Errorf("door saw cn=%q method=%q path=%q", gotCN, gotMethod, gotPath)
	}
	if code, err := doorRequest(context.Background(), ca, crt, key, addr, "noo-stunnel-rhaddon-worker", http.MethodGet, "/redirect"); err != nil || code != http.StatusFound {
		t.Errorf("a redirect was followed or failed: %d, %v", code, err)
	}
	// The door's name is checked: another name is a handshake failure.
	if _, err := doorRequest(context.Background(), ca, crt, key, addr, "noo-stunnel-other-worker", http.MethodGet, "/"); err == nil {
		t.Error("a door that does not carry the expected name was accepted")
	}
	// No client certificate, no answer.
	if _, err := doorRequest(context.Background(), ca, filepath.Join(pki.dir, "missing.crt"), key, addr, "noo-stunnel-rhaddon-worker", http.MethodGet, "/"); err == nil {
		t.Error("a call without the agent leaf succeeded")
	}
	if _, err := doorRequest(context.Background(), ca, crt, key, addr, "noo-stunnel-rhaddon-worker", http.MethodGet, "no-slash"); err == nil {
		t.Error("a relative path was accepted")
	}
}
