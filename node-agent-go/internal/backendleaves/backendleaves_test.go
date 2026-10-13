// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendleaves

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// testCA is a throwaway CA that signs leaves the way the controller does:
// DNS SANs + NotAfter, nothing the reader needs beyond that.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test cluster CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key}
}

// leaf writes services/<svc>/service.crt (and a key beside it, which the
// reader must never need) under dir, signed by the CA.
func (ca *testCA) leaf(t *testing.T, dir, svc string, dns []string, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: svc},
		DNSNames:     dns,
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(dir, "services", svc)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(d, "service.crt"), crt, 0o644); err != nil {
		t.Fatal(err)
	}
	// The key beside it is unreadable to anyone (mode 0): the reader
	// never opens it, so a test run as a normal user still passes.
	keyPath := filepath.Join(d, "service.key")
	_ = os.Remove(keyPath)
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o000); err != nil {
		t.Fatal(err)
	}
}

// A planted leaf, an expired leaf, a misnamed leaf, a garbage leaf and no
// leaf: present ones are reported exactly as they are (the verdict is the
// CLI's), unparseable and missing ones are ABSENT, never nulls.
func TestReport_PresentAbsentExpiredMisnamed(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t)
	good := time.Now().Add(80 * 24 * time.Hour).Truncate(time.Second)
	expired := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	ca.leaf(t, dir, "vllm", []string{"vllm", "localhost", "noo-vllm", "noo-vllm-secondary"}, good)
	ca.leaf(t, dir, "tei", []string{"tei", "localhost", "noo-stunnel-tei"}, expired)
	ca.leaf(t, dir, "llamacpp", []string{"llamacpp", "noo-llamacpp"}, good) // not the door it is dialled by
	if err := os.MkdirAll(filepath.Join(dir, "services", "reranker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "services", "reranker", "service.crt"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	// ollama: no leaf at all. And a non-door service the agent must ignore.
	ca.leaf(t, dir, "postgres", []string{"postgres"}, good)

	got := NewReader().Report(dir)
	want := map[string]Leaf{
		"vllm":     {DNS: []string{"vllm", "localhost", "noo-vllm", "noo-vllm-secondary"}, NotAfter: good.Unix()},
		"tei":      {DNS: []string{"tei", "localhost", "noo-stunnel-tei"}, NotAfter: expired.Unix()},
		"llamacpp": {DNS: []string{"llamacpp", "noo-llamacpp"}, NotAfter: good.Unix()},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("report = %#v\nwant %#v", got, want)
	}

	// The wire shape the CLI reads: {"<svc>": {"dns": [...], "not_after": <int>}}.
	b, _ := json.Marshal(got)
	var wire map[string]map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["vllm"]["dns"].([]any); !ok {
		t.Errorf("vllm.dns is not a list on the wire: %s", b)
	}
	if na, ok := wire["tei"]["not_after"].(float64); !ok || int64(na) != expired.Unix() {
		t.Errorf("tei.not_after on the wire = %v: %s", wire["tei"]["not_after"], b)
	}
	for _, absent := range []string{"ollama", "reranker", "postgres"} {
		if _, ok := wire[absent]; ok {
			t.Errorf("%s must be absent from the report: %s", absent, b)
		}
	}
}

// "Holds none" is a report: the map is empty, not nil, so it marshals as
// {} and the heartbeat carries the key.
func TestReport_EmptyIsAMapNotNil(t *testing.T) {
	for _, dir := range []string{"", t.TempDir(), "/nonexistent/pki"} {
		got := NewReader().Report(dir)
		if got == nil {
			t.Fatalf("Report(%q) = nil", dir)
		}
		if b, _ := json.Marshal(got); string(b) != "{}" {
			t.Fatalf("Report(%q) marshals as %s, want {}", dir, b)
		}
	}
}

// A beat stats; it re-parses only a leaf whose (size, mtime) moved, and a
// renewed leaf is picked up on the next beat.
func TestReport_CachesByStatAndSeesARenewal(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t)
	first := time.Now().Add(10 * 24 * time.Hour).Truncate(time.Second)
	ca.leaf(t, dir, "vllm", []string{"noo-vllm"}, first)

	reads := 0
	orig := parseFile
	parseFile = func(p string) (*Leaf, string) { reads++; return orig(p) }
	defer func() { parseFile = orig }()

	r := NewReader()
	for i := 0; i < 5; i++ {
		if got := r.Report(dir)["vllm"].NotAfter; got != first.Unix() {
			t.Fatalf("beat %d: not_after %d, want %d", i, got, first.Unix())
		}
	}
	if reads != 1 {
		t.Fatalf("parsed the leaf %d times over 5 beats, want 1", reads)
	}

	renewed := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	ca.leaf(t, dir, "vllm", []string{"noo-vllm"}, renewed)
	crt := filepath.Join(dir, "services", "vllm", "service.crt")
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(crt, later, later); err != nil {
		t.Fatal(err)
	}
	if got := r.Report(dir)["vllm"].NotAfter; got != renewed.Unix() {
		t.Fatalf("after renewal: not_after %d, want %d", got, renewed.Unix())
	}
	if reads != 2 {
		t.Fatalf("parsed %d times, want 2 (one per file version)", reads)
	}

	if err := os.Remove(crt); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Report(dir)["vllm"]; ok {
		t.Fatal("a removed leaf is still reported from the cache")
	}
}

// Report() reads $NOO_PKI_DIR.
func TestReport_ReadsNOOPKIDIR(t *testing.T) {
	dir := t.TempDir()
	newCA(t).leaf(t, dir, "ollama", []string{"noo-stunnel-ollama"}, time.Now().Add(40*24*time.Hour))
	t.Setenv("NOO_PKI_DIR", dir)
	if _, ok := Report()["ollama"]; !ok {
		t.Fatal("Report() did not read the ollama leaf under $NOO_PKI_DIR")
	}
}
