// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package ctrlrpc

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
)

// maxNonces bounds the replay set. Entries expire with the window; if the set
// is full of UNEXPIRED nonces the verifier refuses new messages rather than
// forget one (a forgotten nonce is a replay window).
const maxNonces = 16384

// Verifier checks envelopes for ONE node.
type Verifier struct {
	nodeID string
	roots  *x509.CertPool
	now    func() time.Time

	mu    sync.Mutex
	seen  map[string]time.Time // nonce -> expiry
	certs map[[32]byte]time.Time
}

// NewVerifier builds a verifier from the cluster CA (PEM). An empty or
// unparsable CA is an error: with nothing to verify against, the node must
// not advertise control over the bus.
func NewVerifier(nodeID string, caPEM []byte) (*Verifier, error) {
	if nodeID == "" {
		return nil, errors.New("no node id")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the cluster CA (NOO_TLS_CA) holds no certificate")
	}
	return &Verifier{
		nodeID: nodeID, roots: pool, now: time.Now,
		seen: map[string]time.Time{}, certs: map[[32]byte]time.Time{},
	}, nil
}

// ErrRefused wraps every verification failure.
var ErrRefused = errors.New("control envelope refused")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

// Verify judges one message: subjectOp is the op named by the subject it
// arrived on. The nonce is consumed only after everything else holds, so
// junk cannot fill the set.
func (v *Verifier) Verify(subjectOp string, e Envelope, body []byte) error {
	if e.V != EnvelopeVersion {
		return refuse("envelope version %d is not %d", e.V, EnvelopeVersion)
	}
	if e.Op == "" || e.Op != subjectOp {
		return refuse("envelope op %q does not match the subject op %q", e.Op, subjectOp)
	}
	if e.Node != v.nodeID {
		return refuse("envelope is for node %q, this node is %q", e.Node, v.nodeID)
	}
	if len(e.Nonce) < 16 || len(e.Nonce) > 64 {
		return refuse("nonce length %d outside 16..64", len(e.Nonce))
	}
	now := v.now()
	skew := now.Sub(time.Unix(e.TS, 0))
	if skew > Window || skew < -Window {
		return refuse("timestamp is %s from this node's clock (window %s); check NTP on both ends", skew.Round(time.Second), Window)
	}
	if e.OpID != "" && !ValidOpID(e.OpID) {
		return refuse("op_id %q is not a valid event token", e.OpID)
	}
	if e.BodySHA256 != BodyHash(body) {
		return refuse("body does not match the signed hash")
	}
	canon, err := e.Canonical()
	if err != nil {
		return refuse("%v", err)
	}
	cert, err := v.controllerCert(e.Cert, now)
	if err != nil {
		return err
	}
	var algo x509.SignatureAlgorithm
	switch e.Alg {
	case "ES256":
		algo = x509.ECDSAWithSHA256
	case "ES384":
		algo = x509.ECDSAWithSHA384
	default:
		return refuse("unsupported signature algorithm %q", e.Alg)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		return refuse("signature is not base64")
	}
	if err := cert.CheckSignature(algo, canon, sig); err != nil {
		return refuse("signature does not verify against the controller certificate")
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	for n, exp := range v.seen {
		if now.After(exp) {
			delete(v.seen, n)
		}
	}
	if _, dup := v.seen[e.Nonce]; dup {
		return refuse("nonce already seen (replay)")
	}
	if len(v.seen) >= maxNonces {
		return refuse("more than %d control messages inside the %s window; refusing rather than forget a nonce", maxNonces, Window)
	}
	// Remembered until the message could no longer pass the window check
	// (ts+Window); ts is within Window of now, so this is always ahead of now.
	v.seen[e.Nonce] = time.Unix(e.TS, 0).Add(Window + 5*time.Second)
	return nil
}

// controllerCert parses and chain-verifies the envelope's certificate,
// remembering good ones briefly so a poll loop does not re-verify per call.
func (v *Verifier) controllerCert(b64 string, now time.Time) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(der) == 0 || len(der) > 16<<10 {
		return nil, refuse("certificate is missing or malformed")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, refuse("certificate does not parse")
	}
	key := sha256.Sum256(der)
	v.mu.Lock()
	until, ok := v.certs[key]
	v.mu.Unlock()
	if ok && now.Before(until) {
		return cert, nil
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: v.roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, refuse("certificate does not chain to the cluster CA: %v", err)
	}
	if !auth.IsControllerCert(cert) {
		return nil, refuse("certificate is not a controller certificate (organization %v)", cert.Subject.Organization)
	}
	v.mu.Lock()
	if len(v.certs) > 64 {
		v.certs = map[[32]byte]time.Time{}
	}
	v.certs[key] = now.Add(5 * time.Minute)
	v.mu.Unlock()
	return cert, nil
}

// VerifyDetached checks a signature made by the controller's leaf over msg:
// the certificate (base64 DER) must chain to the cluster CA and carry the
// controller organization, and sig (base64 ASN.1 DER ECDSA) must verify
// against it under alg ("ES256" or "ES384"). It has no replay set: the caller
// binds msg to a fresh nonce of its own. The tunnel handshake uses it to
// prove that the gateway at the other end of a connection is the controller.
func (v *Verifier) VerifyDetached(msg []byte, alg, sigB64, certB64 string) error {
	now := v.now()
	cert, err := v.controllerCert(certB64, now)
	if err != nil {
		return err
	}
	var algo x509.SignatureAlgorithm
	switch alg {
	case "ES256":
		algo = x509.ECDSAWithSHA256
	case "ES384":
		algo = x509.ECDSAWithSHA384
	default:
		return refuse("unsupported signature algorithm %q", alg)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return refuse("signature is not base64")
	}
	if err := cert.CheckSignature(algo, msg, sig); err != nil {
		return refuse("signature does not verify against the controller certificate")
	}
	return nil
}
