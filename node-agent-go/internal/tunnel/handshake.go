// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package tunnel

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
)

// The handshake is three text messages after the WebSocket upgrade.
//
//	gateway -> node  challenge  {node, nonce, ts} signed by the controller leaf
//	node -> gateway  hello      {node, nonce, ts} signed by the node leaf
//	gateway -> node  ready      {window, max_streams}   (or refused {reason})
//
// The node checks that the challenge names it, is fresh and verifies against
// a certificate that chains to the cluster CA and carries the controller
// organization. The gateway checks the hello against the certificate the TLS
// handshake already verified. Both signatures cover a nonce the gateway chose
// for this connection, so neither can be replayed on another.

// ChallengeCanonical is the byte string the gateway signs. It must equal
// gateway-rust/src/tunnel.rs `challenge_canonical`; both sides pin the same
// literal in their tests.
func ChallengeCanonical(node, nonce string, ts int64) string {
	return fmt.Sprintf("noo-tunnel-v%d\nchallenge\n%s\n%s\n%d", ProtocolVersion, node, nonce, ts)
}

// HelloCanonical is the byte string the node signs. It must equal
// gateway-rust/src/tunnel.rs `hello_canonical`.
func HelloCanonical(node, nonce string, ts int64) string {
	return fmt.Sprintf("noo-tunnel-v%d\nhello\n%s\n%s\n%d", ProtocolVersion, node, nonce, ts)
}

type challengeMsg struct {
	T     string `json:"t"`
	V     int    `json:"v"`
	Node  string `json:"node"`
	Nonce string `json:"nonce"`
	TS    int64  `json:"ts"`
	Alg   string `json:"alg"`
	Sig   string `json:"sig"`
	Cert  string `json:"cert"`
}

type helloMsg struct {
	T     string `json:"t"`
	V     int    `json:"v"`
	Node  string `json:"node"`
	Nonce string `json:"nonce"`
	TS    int64  `json:"ts"`
	Alg   string `json:"alg"`
	Sig   string `json:"sig"`
	Cert  string `json:"cert"`
}

type readyMsg struct {
	T          string `json:"t"`
	V          int    `json:"v"`
	Window     int    `json:"window"`
	MaxStreams int    `json:"max_streams"`
	Reason     string `json:"reason"`
}

// leafSigner signs with the node's leaf key.
type leafSigner struct {
	key  crypto.Signer
	hash crypto.Hash
	alg  string
	cert string // base64 DER
}

var errNotECDSA = errors.New("the node leaf key is not ECDSA P-256 or P-384, so it cannot sign the tunnel hello")

func newLeafSigner(c tls.Certificate) (*leafSigner, error) {
	signer, ok := c.PrivateKey.(crypto.Signer)
	if !ok || len(c.Certificate) == 0 {
		return nil, errors.New("the node leaf has no usable private key")
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errNotECDSA
	}
	ls := &leafSigner{key: signer, cert: base64.StdEncoding.EncodeToString(c.Certificate[0])}
	switch pub.Curve {
	case elliptic.P256():
		ls.hash, ls.alg = crypto.SHA256, "ES256"
	case elliptic.P384():
		ls.hash, ls.alg = crypto.SHA384, "ES384"
	default:
		return nil, errNotECDSA
	}
	return ls, nil
}

func (l *leafSigner) sign(msg []byte) (string, error) {
	var digest []byte
	switch l.hash {
	case crypto.SHA384:
		d := sha512.Sum384(msg)
		digest = d[:]
	default:
		d := sha256.Sum256(msg)
		digest = d[:]
	}
	sig, err := l.key.Sign(rand.Reader, digest, l.hash)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
