// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package heartbeat

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
)

// Gzip heartbeats (i675 F11).
//
// A beat is 5.7 KB (CPU node) to 9.7 KB (GPU node) of JSON; gzip cuts it by
// 60-68% (payload_size_test.go). The agent compresses ONLY after the
// gateway's last 200 reply advertised `"accept_encoding": ["gzip"]`: a
// gateway that never says so (every gateway before this change) receives
// plain JSON exactly as before.
//
// The v2 cluster token is signed over the bytes AS SENT
// (auth.SetClusterAuth hashes the request body), so a gzip beat is signed
// over the compressed bytes, and the gateway verifies it before it decodes.
//
// A gzip beat answered 400, 413 or 415 is taken as the encoding refused:
// the same beat is re-sent plain at once, and this process sends plain for
// the rest of its life, whatever later replies advertise. A gateway that
// advertises gzip and then refuses it would otherwise cost two POSTs a beat.

// beatReply is what the agent reads from a 200 heartbeat reply.
type beatReply struct {
	AcceptEncoding []string `json:"accept_encoding"`
}

// acceptsGzip: the reply advertises gzip request bodies.
func (b beatReply) acceptsGzip() bool {
	for _, e := range b.AcceptEncoding {
		if e == "gzip" {
			return true
		}
	}
	return false
}

// readBeatReply decodes a 200 reply. An unreadable or non-JSON body is a
// reply that advertises nothing: the safe reading, plain beats.
func readBeatReply(body io.Reader) beatReply {
	var rep beatReply
	_ = json.NewDecoder(io.LimitReader(body, 64<<10)).Decode(&rep)
	return rep
}

// encodingRefused: the status a gateway answers a body encoding it will not
// read (malformed, too large once decoded, or unsupported).
func encodingRefused(status int) bool {
	return status == 400 || status == 413 || status == 415
}

// beatEncoding is the Run loop's gzip state. Touched only from that
// goroutine, like the delivery bookkeeping.
type beatEncoding struct {
	// advertised: the last 200 reply said `accept_encoding: ["gzip"]`.
	advertised bool
	// refused: a gzip beat was refused; plain for the process lifetime.
	refused bool
}

func (e *beatEncoding) useGzip() bool { return e.advertised && !e.refused }

// gzipBytes compresses one beat.
func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
