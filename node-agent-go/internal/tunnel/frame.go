// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package tunnel is the node's side of the node-held control tunnel
// (followup i131, phase 2).
//
// The node dials the gateway OUTBOUND over its mTLS leaf, upgrades the
// connection to a WebSocket and keeps it. The gateway then sends the calls
// that must not wait on an inbound connection to :8081 down it: inference
// SSE, the container proxy, logs, device blobs. Each call is a stream on the
// one connection; the node serves it IN-PROCESS through the agent's existing
// http.Handler, so a handler does not know which way a request came.
//
// # Wire format (noo-tunnel/1)
//
// One WebSocket binary message is one frame:
//
//	type   u8
//	stream u32, big endian
//	payload
//
// Types: OPEN (gateway to node, JSON: method, path, headers, principal),
// HEAD (node to gateway, JSON: status, headers), DATA, END (the sender has
// finished its body), CREDIT (u32: the receiver may send that much more
// DATA), RESET (UTF-8 reason: abort the stream). Only the gateway opens
// streams. Before any frame the two sides exchange three text messages
// (challenge, hello, ready); see handshake.go.
//
// # Flow control
//
// Each direction of each stream has a window of Window bytes. A DATA frame
// of n bytes costs max(n, MinCost) of it, so a flood of tiny frames cannot
// outrun the window, and a receiver grants that cost back with CREDIT once
// the bytes have been handed to the consumer (the handler reading the request
// body, the gateway's caller reading the response). A sender with no credit
// waits; that is the backpressure. A receiver that is sent more than the
// window resets the stream.
//
// # Trust
//
// The node dials; the controller never dials in. The node refuses to speak
// to a server whose certificate is not the controller's (organization "Mesh
// Cluster Gateway", chaining to the cluster CA) and then requires the
// gateway to sign a fresh challenge naming this node. Streams on the session
// are served as the controller (auth.WithTunnelController), which is a value
// in the request context and never a header: see internal/auth/tunnel.go.
package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Frame types.
const (
	FrameOpen   byte = 1
	FrameHead   byte = 2
	FrameData   byte = 3
	FrameEnd    byte = 4
	FrameCredit byte = 5
	FrameReset  byte = 6
)

// Protocol constants. The gateway states Window and MaxStreams in its
// "ready" message; the node uses what it is told, bounded by these ceilings.
const (
	ProtocolVersion = 1
	// MaxData is the largest DATA payload a sender writes.
	MaxData = 32 * 1024
	// MinCost is the least a DATA frame costs against a window.
	MinCost = 1024
	// DefaultWindow is the per-stream, per-direction window.
	DefaultWindow = 256 * 1024
	// MaxWindow bounds what a gateway may ask this node to buffer per stream.
	MaxWindow = 4 * 1024 * 1024
	// DefaultMaxStreams is the gateway's per-node concurrent-stream cap.
	DefaultMaxStreams = 64
	// NodeStreamCeiling is the most streams this node serves at once,
	// whatever the gateway says.
	NodeStreamCeiling = 128
	// MaxMessage bounds one WebSocket message.
	MaxMessage = MaxData + 64*1024
)

// PingEvery is the keepalive interval; DeadAfter is how long the peer may be
// silent (no frame, no pong) before the connection is dropped. Variables so a
// test can shorten them; nothing else assigns them.
var (
	PingEvery = 15 * time.Second
	DeadAfter = 45 * time.Second
)

// Cost is what a DATA frame of n payload bytes spends from a window.
func Cost(n int) int {
	if n < MinCost {
		return MinCost
	}
	return n
}

func encode(kind byte, stream uint32, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:5], stream)
	copy(b[5:], payload)
	return b
}

func decode(b []byte) (kind byte, stream uint32, payload []byte, err error) {
	if len(b) < 5 {
		return 0, 0, nil, fmt.Errorf("frame of %d bytes is shorter than its 5-byte header", len(b))
	}
	return b[0], binary.BigEndian.Uint32(b[1:5]), b[5:], nil
}

func creditPayload(n int) []byte {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], uint32(n))
	return p[:]
}

var errWindowClosed = errors.New("stream closed")

// window is a byte-credit counter a sender waits on.
type window struct {
	mu     sync.Mutex
	avail  int
	wake   chan struct{}
	closed bool
}

func newWindow(n int) *window { return &window{avail: n, wake: make(chan struct{})} }

// take waits until n bytes of credit are available and spends them.
func (w *window) take(ctx context.Context, n int) error {
	for {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return errWindowClosed
		}
		if w.avail >= n {
			w.avail -= n
			w.mu.Unlock()
			return nil
		}
		ch := w.wake
		w.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

func (w *window) add(n int) {
	w.mu.Lock()
	w.avail += n
	close(w.wake)
	w.wake = make(chan struct{})
	w.mu.Unlock()
}

func (w *window) close() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.wake)
	}
	w.mu.Unlock()
}
