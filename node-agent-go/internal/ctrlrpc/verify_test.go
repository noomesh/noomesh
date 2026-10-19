// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package ctrlrpc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// pki is a throwaway cluster: a CA and the leaves it issues.
type pki struct {
	t      *testing.T
	caKey  *ecdsa.PrivateKey
	ca     *x509.Certificate
	caPEM  []byte
	serial int64
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &pki{t: t, caKey: key, ca: ca, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial: 1}
}

type leaf struct {
	key *ecdsa.PrivateKey
	der []byte
}

func (p *pki) leaf(org string, notAfter time.Time) leaf {
	p.t.Helper()
	p.serial++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: "x", Organization: []string{org}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		p.t.Fatal(err)
	}
	return leaf{key: key, der: der}
}

// sign builds a valid envelope for body, the way the gateway does.
func sign(t *testing.T, l leaf, op, node string, ts time.Time, nonce string, body []byte) Envelope {
	t.Helper()
	e := Envelope{V: EnvelopeVersion, Op: op, Node: node, TS: ts.Unix(), Nonce: nonce, BodySHA256: BodyHash(body),
		Alg: "ES256", Cert: base64.StdEncoding.EncodeToString(l.der)}
	canon, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	sig, err := l.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = base64.StdEncoding.EncodeToString(sig)
	return e
}

func nonce(n string) string { return n + strings.Repeat("0", 16) }

func expectRefused(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal containing %q, got nil", want)
	}
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal %q does not contain %q", err, want)
	}
}

func fixture(t *testing.T) (*pki, leaf, *Verifier) {
	p := newPKI(t)
	ctrl := p.leaf("Mesh Cluster Gateway", time.Now().Add(time.Hour))
	v, err := NewVerifier("host9", p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	return p, ctrl, v
}

func TestAControllerEnvelopeVerifiesOnce(t *testing.T) {
	_, ctrl, v := fixture(t)
	body := []byte(`{"backend":"vllm"}`)
	e := sign(t, ctrl, "stop", "host9", time.Now(), nonce("a"), body)
	if err := v.Verify("stop", e, body); err != nil {
		t.Fatalf("a good envelope was refused: %v", err)
	}
}

func TestAReplayedNonceIsRefused(t *testing.T) {
	_, ctrl, v := fixture(t)
	e := sign(t, ctrl, "stop", "host9", time.Now(), nonce("r"), nil)
	if err := v.Verify("stop", e, nil); err != nil {
		t.Fatal(err)
	}
	expectRefused(t, v.Verify("stop", e, nil), "replay")
}

func TestAStaleOrFutureTimestampIsRefused(t *testing.T) {
	_, ctrl, v := fixture(t)
	for i, d := range []time.Duration{-301 * time.Second, 301 * time.Second, -time.Hour} {
		e := sign(t, ctrl, "health", "host9", time.Now().Add(d), nonce(string(rune('a'+i))), nil)
		expectRefused(t, v.Verify("health", e, nil), "window")
	}
	// Inside the window on both sides is accepted.
	for i, d := range []time.Duration{-290 * time.Second, 290 * time.Second} {
		e := sign(t, ctrl, "health", "host9", time.Now().Add(d), nonce(string(rune('m'+i))), nil)
		if err := v.Verify("health", e, nil); err != nil {
			t.Fatalf("%v inside the window was refused: %v", d, err)
		}
	}
}

func TestABadSignatureIsRefused(t *testing.T) {
	_, ctrl, v := fixture(t)
	e := sign(t, ctrl, "stop", "host9", time.Now(), nonce("s"), nil)
	raw, _ := base64.StdEncoding.DecodeString(e.Sig)
	raw[len(raw)-1] ^= 0xff
	e.Sig = base64.StdEncoding.EncodeToString(raw)
	expectRefused(t, v.Verify("stop", e, nil), "signature")
	// A field changed after signing is the same refusal.
	e2 := sign(t, ctrl, "stop", "host9", time.Now(), nonce("t"), nil)
	e2.Arg = "other"
	expectRefused(t, v.Verify("stop", e2, nil), "signature")
}

func TestABodySwapIsRefused(t *testing.T) {
	_, ctrl, v := fixture(t)
	e := sign(t, ctrl, "stop", "host9", time.Now(), nonce("b"), []byte(`{"backend":"vllm"}`))
	expectRefused(t, v.Verify("stop", e, []byte(`{"backend":"ollama"}`)), "body")
}

func TestAnEnvelopeForAnotherNodeOrOpIsRefused(t *testing.T) {
	_, ctrl, v := fixture(t)
	e := sign(t, ctrl, "stop", "host8", time.Now(), nonce("n"), nil)
	expectRefused(t, v.Verify("stop", e, nil), "node")
	e = sign(t, ctrl, "stop", "host9", time.Now(), nonce("o"), nil)
	expectRefused(t, v.Verify("clean", e, nil), "op")
}

func TestOnlyAControllerLeafOfThisClusterSigns(t *testing.T) {
	p, _, v := fixture(t)
	node := p.leaf("Mesh Cluster Node", time.Now().Add(time.Hour))
	expectRefused(t, v.Verify("stop", sign(t, node, "stop", "host9", time.Now(), nonce("p"), nil), nil), "not a controller")

	other := newPKI(t)
	foreign := other.leaf("Mesh Cluster Gateway", time.Now().Add(time.Hour))
	expectRefused(t, v.Verify("stop", sign(t, foreign, "stop", "host9", time.Now(), nonce("q"), nil), nil), "cluster CA")

	expired := p.leaf("Mesh Cluster Gateway", time.Now().Add(-time.Minute))
	expectRefused(t, v.Verify("stop", sign(t, expired, "stop", "host9", time.Now(), nonce("x"), nil), nil), "cluster CA")
}

func TestAnUnsignedEnvelopeIsRefused(t *testing.T) {
	_, _, v := fixture(t)
	e := Envelope{V: EnvelopeVersion, Op: "stop", Node: "host9", TS: time.Now().Unix(), Nonce: nonce("u"), BodySHA256: BodyHash(nil)}
	expectRefused(t, v.Verify("stop", e, nil), "certificate")
}

func TestTheNonceSetIsBoundedAndFailsClosed(t *testing.T) {
	_, ctrl, v := fixture(t)
	for i := 0; i < maxNonces; i++ {
		v.seen[fmt.Sprintf("filler-%08d", i)] = time.Now().Add(time.Hour)
	}
	e := sign(t, ctrl, "health", "host9", time.Now(), nonce("full"), nil)
	expectRefused(t, v.Verify("health", e, nil), "refusing rather than forget")
	// Expired entries make room again.
	for k := range v.seen {
		v.seen[k] = time.Now().Add(-time.Second)
	}
	if err := v.Verify("health", e, nil); err != nil {
		t.Fatalf("expired nonces must free the set: %v", err)
	}
}

func TestACanonicalFieldWithALineBreakCannotBeSigned(t *testing.T) {
	e := Envelope{V: 1, Op: "stop\nhealth"}
	if _, err := e.Canonical(); err == nil {
		t.Fatal("a line break would let one envelope read as two")
	}
}

func TestNoCAMeansNoVerifier(t *testing.T) {
	if _, err := NewVerifier("host9", []byte("not a pem")); err == nil {
		t.Fatal("a verifier with no CA must not exist (the node must not advertise nats_rpc)")
	}
}

// signCanonical re-signs e (fields already set) with l.
func signCanonical(t *testing.T, l leaf, e Envelope) Envelope {
	t.Helper()
	canon, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(canon)
	sig, err := l.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = base64.StdEncoding.EncodeToString(sig)
	return e
}
