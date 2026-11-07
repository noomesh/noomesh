// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// The refusals of doorRequest that the happy-path test cannot see: its server
// demands a client certificate and a name, so a request that should never have
// been sent fails there too. This server asks for nothing, counts what
// arrives, and so shows whether the client refused first.
func TestDoorRequestRefusesBeforeAnythingIsSent(t *testing.T) {
	pki := newTestPKI(t)
	server := pki.leaf(t, "door", []string{"noo-stunnel-rhaddon-worker"}, x509.ExtKeyUsageServerAuth, false)
	pki.leaf(t, "node-a", nil, x509.ExtKeyUsageClientAuth, true)

	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{server}} // no client certificate asked for
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	ca, crt, key := filepath.Join(pki.dir, "ca.crt"), filepath.Join(pki.dir, "node-a.crt"), filepath.Join(pki.dir, "node-a.key")
	name := "noo-stunnel-rhaddon-worker"
	do := func(ca, crt, key, path string) (int, error) {
		return doorRequest(context.Background(), ca, crt, key, addr, name, http.MethodGet, path)
	}

	// Control: the same call, with everything right, is answered.
	if code, err := do(ca, crt, key, "/"); err != nil || code != http.StatusOK {
		t.Fatalf("control: %d, %v", code, err)
	}
	hits.Store(0)

	// A path must start with "/": "?x" would still make a valid URL for this
	// host, and "@elsewhere/" would change the host.
	for _, p := range []string{"?x=1", "#frag", "@127.0.0.1:1/", "v1/lifecycle/drain"} {
		if _, err := do(ca, crt, key, p); err == nil {
			t.Errorf("path %q was accepted", p)
		}
	}
	// The cluster CA must be there, and must hold a certificate.
	if _, err := do(filepath.Join(pki.dir, "no-such-ca.crt"), crt, key, "/"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing CA file: %v, want the read error", err)
	}
	notACert := filepath.Join(pki.dir, "empty-ca.crt")
	if err := os.WriteFile(notACert, []byte("no certificate in here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := do(notACert, crt, key, "/"); err == nil {
		t.Error("a CA file with no certificate was accepted")
	}
	// The agent's own leaf must load: a missing file, a key that is not the
	// certificate's.
	if _, err := do(ca, filepath.Join(pki.dir, "missing.crt"), key, "/"); err == nil {
		t.Error("a missing leaf certificate was accepted")
	}
	if _, err := do(ca, crt, filepath.Join(pki.dir, "missing.key"), "/"); err == nil {
		t.Error("a missing leaf key was accepted")
	}
	pki.leaf(t, "node-b", nil, x509.ExtKeyUsageClientAuth, true)
	if _, err := do(ca, crt, filepath.Join(pki.dir, "node-b.key"), "/"); err == nil {
		t.Error("a key that is not the leaf's was accepted")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d requests reached the door although the client should have refused first", n)
	}
}

// The floor is TLS 1.2: a door that only speaks 1.1 is not reached.
func TestDoorRequestRefusesAnOldTLSVersion(t *testing.T) {
	pki := newTestPKI(t)
	server := pki.leaf(t, "door", []string{"noo-stunnel-rhaddon-worker"}, x509.ExtKeyUsageServerAuth, false)
	pki.leaf(t, "node-a", nil, x509.ExtKeyUsageClientAuth, true)
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{server}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	// Control: this server does speak 1.1 to a client that allows it.
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pki.pool, ServerName: "noo-stunnel-rhaddon-worker", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if err != nil {
		t.Skipf("this Go cannot speak TLS 1.1 here, so the floor cannot be shown: %v", err)
	}
	conn.Close()

	_, err = doorRequest(context.Background(), filepath.Join(pki.dir, "ca.crt"), filepath.Join(pki.dir, "node-a.crt"), filepath.Join(pki.dir, "node-a.key"),
		addr, "noo-stunnel-rhaddon-worker", http.MethodGet, "/")
	if err == nil || hits.Load() != 0 {
		t.Fatalf("a TLS 1.1 door was reached: err=%v hits=%d", err, hits.Load())
	}
}
