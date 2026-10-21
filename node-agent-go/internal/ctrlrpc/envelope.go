// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package ctrlrpc is the node side of control over the bus (followup i131,
// phase 1): the controller sends small control calls as NATS request/reply on
// node.<id>.rpc.<op>, over a connection the NODE already holds outbound, and
// this package answers them by running the SAME handlers the HTTPS control
// API runs.
//
// Two gates, in this order:
//
//  1. The bus. nats-server permissions let a node SUBSCRIBE only its own
//     node.<id>.rpc.> and let no principal but the gateway PUBLISH
//     node.*.rpc.> (noo-cli nats_users.rs). That gate is silent when it
//     refuses, so it is never the only one.
//  2. The envelope. Every message carries {op, node, ts, nonce, ...} signed
//     with the controller's leaf private key, plus that leaf (DER). The node
//     verifies the chain to the cluster CA, the controller organization (the
//     exact test ControllerOnly applies to a TLS peer), the signature over
//     the whole message including a hash of the body, a 300 s window, and a
//     bounded nonce set. A message that fails any of it is refused and
//     never reaches a handler.
package ctrlrpc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Header names on the request and reply messages.
const (
	// HeaderEnvelope carries the JSON-encoded Envelope on a request.
	HeaderEnvelope = "Noo-Envelope"
	// HeaderStatus is the HTTP status the handler produced, on replies and
	// on the terminal event of an async op.
	HeaderStatus = "Noo-Status"
	// HeaderContentType is the handler's Content-Type.
	HeaderContentType = "Noo-Content-Type"
	// HeaderAsync marks the immediate ack of an async op: the final result
	// follows on node.<id>.evt.<op_id>.
	HeaderAsync = "Noo-Async"
	// HeaderOverflow marks a reply whose body did not fit the bus limit; the
	// caller reads the same thing over HTTPS.
	HeaderOverflow = "Noo-Overflow"
	// HeaderEvent is "progress" or "done" on an event message.
	HeaderEvent = "Noo-Event"
)

// Window is how far a message's timestamp may be from this node's clock.
const Window = 300 * time.Second

// EnvelopeVersion is the only envelope version this node accepts.
const EnvelopeVersion = 1

// Envelope is the signed header of one control message.
type Envelope struct {
	V     int    `json:"v"`
	Op    string `json:"op"`
	Node  string `json:"node"`
	TS    int64  `json:"ts"`
	Nonce string `json:"nonce"`
	// Arg is the one path value the op takes (a container name, an MCP
	// server, a cleanup kind). Query is the URL query string, no "?".
	Arg   string `json:"arg,omitempty"`
	Query string `json:"query,omitempty"`
	// OpID names an async op's event stream; chosen by the controller so it
	// can subscribe before it sends. TimeoutS bounds the handler.
	OpID     string `json:"op_id,omitempty"`
	TimeoutS int    `json:"timeout_s,omitempty"`
	// BodySHA256 binds the payload: a valid envelope cannot be replayed onto
	// a different body.
	BodySHA256 string `json:"body_sha256"`
	// Alg is "ES256" or "ES384" (the controller leaf's key); Sig is the
	// ASN.1 DER signature, base64; Cert is the controller leaf, DER, base64.
	Alg  string `json:"alg"`
	Sig  string `json:"sig"`
	Cert string `json:"cert"`
}

// Canonical is the exact byte string that is signed. It is deliberately a
// plain, line-oriented text so the Rust signer and this verifier cannot
// disagree about framing; no field may contain a newline.
func (e Envelope) Canonical() ([]byte, error) {
	fields := []string{
		"noo-rpc-v" + strconv.Itoa(e.V),
		e.Op, e.Node, strconv.FormatInt(e.TS, 10), e.Nonce, e.Arg, e.Query,
		e.OpID, strconv.Itoa(e.TimeoutS), e.BodySHA256,
	}
	for _, f := range fields {
		if strings.ContainsAny(f, "\n\r") {
			return nil, fmt.Errorf("envelope field contains a line break")
		}
	}
	return []byte(strings.Join(fields, "\n")), nil
}

// BodyHash is the hex sha256 BodySHA256 must equal.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// ValidOpID reports whether s is acceptable as an event-stream token.
func ValidOpID(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
