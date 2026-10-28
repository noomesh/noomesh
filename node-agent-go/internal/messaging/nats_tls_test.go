// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package messaging

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePKI writes a self-signed cert as ca.crt/node.crt and its key as node.key.
func writePKI(t *testing.T) (ca, cert, key string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca, cert, key = filepath.Join(dir, "ca.crt"), filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key")
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for p, b := range map[string][]byte{
		ca: crt, cert: crt,
		key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}),
	} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return
}

func setTLSEnv(t *testing.T, ca, cert, key string) {
	t.Helper()
	t.Setenv("NOO_TLS_CA", ca)
	t.Setenv("NOO_TLS_CERT", cert)
	t.Setenv("NOO_TLS_KEY", key)
}

func TestBuildNATSTLSFullSetCarriesClientCert(t *testing.T) {
	ca, cert, key := writePKI(t)
	setTLSEnv(t, ca, cert, key)
	cfg, err := buildNATSTLS()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("want RootCAs and one client cert, got RootCAs=%v certs=%d", cfg.RootCAs != nil, len(cfg.Certificates))
	}
}

func TestBuildNATSTLSCAOnlyIsRefused(t *testing.T) {
	ca, cert, key := writePKI(t)
	for _, tc := range []struct{ name, cert, key, want string }{
		{"no cert", "", key, "NOO_TLS_CERT"},
		{"no key", cert, "", "NOO_TLS_KEY"},
		{"neither", "", "", "NOO_TLS_CERT, NOO_TLS_KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setTLSEnv(t, ca, tc.cert, tc.key)
			cfg, err := buildNATSTLS()
			if err == nil || cfg != nil {
				t.Fatalf("CA without a full client cert must be refused, got cfg=%v err=%v", cfg, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

func TestBuildNATSTLSNothingSetKeepsSystemRoots(t *testing.T) {
	setTLSEnv(t, "", "", "")
	cfg, err := buildNATSTLS()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs != nil || len(cfg.Certificates) != 0 {
		t.Fatalf("nothing set must stay bare TLS, got %+v", cfg)
	}
}

func TestBuildNATSTLSLoneCertWithoutCAIsRefused(t *testing.T) {
	_, cert, _ := writePKI(t)
	setTLSEnv(t, "", cert, "")
	if _, err := buildNATSTLS(); err == nil || !strings.Contains(err.Error(), "NOO_TLS_KEY") {
		t.Fatalf("want an error naming NOO_TLS_KEY, got %v", err)
	}
}
