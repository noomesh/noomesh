// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlrpc"
)

// Path is where the gateway serves the tunnel.
const Path = "/api/node/tunnel"

// Options configure a Client.
type Options struct {
	NodeID string
	// ControllerURL is the gateway's base URL (CONTROLLER_URL); it must be
	// https.
	ControllerURL string
	// TLS carries the cluster CA (RootCAs) and the node's leaf
	// (Certificates). It is cloned, never modified.
	TLS *tls.Config
	// Sign puts the cluster credential on the upgrade request.
	Sign func(*http.Request)
	// Handler serves each stream in-process: the agent's mux.
	Handler http.Handler
	// Verifier checks the controller's signature on the challenge.
	Verifier *ctrlrpc.Verifier

	// RetryMin/RetryMax bound the reconnect backoff after a failure (default
	// 1 s / 60 s, jittered). NotOfferedRetry is the long interval used when
	// the gateway answers that it has no tunnel (default 10 min).
	RetryMin, RetryMax, NotOfferedRetry time.Duration
}

// Client holds the node's tunnel to the controller.
type Client struct {
	opt       Options
	leaf      *leafSigner
	wsURL     string
	connected atomic.Bool

	mu       sync.Mutex
	lastLog  string
	lastWarn time.Time

	// Counters for logs and tests.
	Connects atomic.Uint64
	Streams  atomic.Uint64
}

// New validates the options. An error means the tunnel cannot run on this
// node (no https controller, no ECDSA leaf, no CA to verify the controller
// with); the caller logs it and stays on HTTPS.
func New(opt Options) (*Client, error) {
	if opt.NodeID == "" || opt.Handler == nil || opt.Verifier == nil || opt.TLS == nil {
		return nil, errors.New("tunnel: node id, handler, verifier and TLS config are required")
	}
	u, err := url.Parse(opt.ControllerURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("tunnel: CONTROLLER_URL %q is not a URL", opt.ControllerURL)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("tunnel: CONTROLLER_URL %q is not https; the tunnel carries controller commands and is only opened over TLS", opt.ControllerURL)
	}
	if len(opt.TLS.Certificates) == 0 {
		return nil, errors.New("tunnel: the node has no client certificate (NOO_TLS_CERT / NOO_TLS_KEY), so the gateway cannot identify it")
	}
	leaf, err := newLeafSigner(opt.TLS.Certificates[0])
	if err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	if opt.RetryMin <= 0 {
		opt.RetryMin = time.Second
	}
	if opt.RetryMax < opt.RetryMin {
		opt.RetryMax = 60 * time.Second
	}
	if opt.NotOfferedRetry <= 0 {
		opt.NotOfferedRetry = 10 * time.Minute
	}
	if opt.Sign == nil {
		opt.Sign = func(*http.Request) {}
	}
	return &Client{opt: opt, leaf: leaf, wsURL: "wss://" + u.Host + strings.TrimRight(u.Path, "/") + Path}, nil
}

// Connected is true while a session is up (handshake complete). The
// heartbeat advertises control_transports.tunnel from it.
func (c *Client) Connected() bool { return c.connected.Load() }

// notOfferedError: the gateway answered the upgrade with a status that means
// "no tunnel here" (an older gateway, the tunnel switched off) or a refusal.
type notOfferedError struct {
	status int
	body   string
}

func (e *notOfferedError) Error() string {
	b := strings.TrimSpace(e.body)
	if b == "" {
		return fmt.Sprintf("the gateway answered %d to the tunnel upgrade", e.status)
	}
	return fmt.Sprintf("the gateway answered %d to the tunnel upgrade: %s", e.status, b)
}

// notOffered: statuses an OLDER gateway gives a route it does not have
// (404; 403 from the node-route allow-list, which runs before routing; 405)
// and the ones a current gateway gives a refusal. Either way an immediate
// retry cannot change the answer, so the node waits a long interval and stays
// on HTTPS.
func notOffered(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return true
	}
	return false
}

// Run keeps the tunnel up until ctx ends: dial, serve, and on any failure
// back off with jitter and dial again.
func (c *Client) Run(ctx context.Context) {
	bo := backoff{min: c.opt.RetryMin, max: c.opt.RetryMax}
	for ctx.Err() == nil {
		started := time.Now()
		connected, err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		var delay time.Duration
		var ne *notOfferedError
		switch {
		case errors.As(err, &ne):
			delay = jitter(c.opt.NotOfferedRetry)
			c.logFailure(err, true)
		default:
			if connected && time.Since(started) > 30*time.Second {
				bo.reset()
			}
			delay = bo.next()
			c.logFailure(err, false)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// logFailure keeps a node that cannot get a tunnel from filling its journal:
// one warning when the failure starts or its text changes, then one every
// half hour. Everything in between is debug.
func (c *Client) logFailure(err error, refused bool) {
	if err == nil {
		return
	}
	msg := err.Error()
	c.mu.Lock()
	same := msg == c.lastLog
	stale := time.Since(c.lastWarn) > 30*time.Minute
	if !same || stale {
		c.lastLog, c.lastWarn = msg, time.Now()
	}
	c.mu.Unlock()
	if same && !stale {
		slog.Debug("node tunnel: still not connected", "error", msg)
		return
	}
	if refused {
		slog.Warn("node tunnel: not available from this controller; control stays on HTTPS (an older gateway, the tunnel switched off, or this node was refused)",
			"error", msg, "retry", c.opt.NotOfferedRetry.String())
		return
	}
	slog.Warn("node tunnel: not connected; control stays on HTTPS until it is", "error", msg)
}

func (c *Client) tlsConfig() *tls.Config {
	cfg := c.opt.TLS.Clone()
	cfg.MinVersion = tls.VersionTLS12
	cfg.NextProtos = []string{"http/1.1"} // WebSocket upgrade is HTTP/1.1
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || !auth.IsControllerCert(cs.PeerCertificates[0]) {
			subj := ""
			if len(cs.PeerCertificates) > 0 {
				subj = fmt.Sprintf("CN=%q O=%q", cs.PeerCertificates[0].Subject.CommonName, cs.PeerCertificates[0].Subject.Organization)
			}
			return fmt.Errorf("the server presented a certificate that is not the controller's (%s): the tunnel carries controller commands and is only opened to a server whose certificate carries the controller organization", subj)
		}
		return nil
	}
	return cfg
}

func (c *Client) dial(ctx context.Context) (*websocket.Conn, *http.Response, error) {
	probe, err := http.NewRequest(http.MethodGet, "https://"+strings.TrimPrefix(c.wsURL, "wss://"), nil)
	if err != nil {
		return nil, nil, err
	}
	c.opt.Sign(probe)
	hdr := http.Header{}
	for k, vs := range probe.Header {
		for _, v := range vs {
			hdr.Add(k, v)
		}
	}
	d := websocket.Dialer{
		TLSClientConfig:  c.tlsConfig(),
		HandshakeTimeout: 20 * time.Second,
		Proxy:            nil,
		ReadBufferSize:   64 << 10,
		WriteBufferSize:  64 << 10,
	}
	return d.DialContext(ctx, c.wsURL, hdr)
}

// session dials, handshakes and serves one connection. connected reports
// whether it got as far as ready.
func (c *Client) session(ctx context.Context) (connected bool, err error) {
	conn, resp, err := c.dial(ctx)
	if err != nil {
		if resp != nil && notOffered(resp.StatusCode) {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			return false, &notOfferedError{status: resp.StatusCode, body: string(snippet)}
		}
		return false, fmt.Errorf("dial %s: %w", c.wsURL, err)
	}
	defer conn.Close()
	ready, err := c.handshake(conn)
	if err != nil {
		return false, err
	}
	s := newSession(c, conn, ready)
	c.connected.Store(true)
	c.Connects.Add(1)
	defer c.connected.Store(false)
	slog.Info("node tunnel up", "gateway", c.wsURL, "window", ready.Window, "max_streams", ready.MaxStreams)
	err = s.serve(ctx)
	if err != nil && ctx.Err() == nil {
		slog.Warn("node tunnel dropped; control returns to HTTPS until it reconnects", "error", err)
	}
	return true, err
}

func (c *Client) handshake(conn *websocket.Conn) (readyMsg, error) {
	var ready readyMsg
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	typ, data, err := conn.ReadMessage()
	if err != nil {
		return ready, fmt.Errorf("tunnel handshake: no challenge from the gateway: %w", err)
	}
	if typ != websocket.TextMessage {
		return ready, errors.New("tunnel handshake: the gateway's first message was not a challenge")
	}
	var probe struct {
		T      string `json:"t"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(data, &probe)
	if probe.T == "refused" {
		return ready, fmt.Errorf("tunnel handshake: the gateway refused this node: %s", probe.Reason)
	}
	var ch challengeMsg
	if err := json.Unmarshal(data, &ch); err != nil || ch.T != "challenge" || ch.V != ProtocolVersion {
		return ready, errors.New("tunnel handshake: the gateway's first message was not a v1 challenge (an incompatible gateway)")
	}
	if ch.Node != c.opt.NodeID {
		return ready, fmt.Errorf("tunnel handshake: the challenge names node %q, this node is %q", ch.Node, c.opt.NodeID)
	}
	if len(ch.Nonce) < 16 || len(ch.Nonce) > 128 {
		return ready, errors.New("tunnel handshake: the challenge nonce has a bad length")
	}
	skew := time.Since(time.Unix(ch.TS, 0))
	if skew > ctrlrpc.Window || skew < -ctrlrpc.Window {
		return ready, fmt.Errorf("tunnel handshake: the challenge is %s from this node's clock (check NTP on both ends)", skew.Round(time.Second))
	}
	if err := c.opt.Verifier.VerifyDetached([]byte(ChallengeCanonical(ch.Node, ch.Nonce, ch.TS)), ch.Alg, ch.Sig, ch.Cert); err != nil {
		return ready, fmt.Errorf("tunnel handshake: the challenge is not signed by the controller: %w", err)
	}
	now := time.Now().Unix()
	sig, err := c.leaf.sign([]byte(HelloCanonical(c.opt.NodeID, ch.Nonce, now)))
	if err != nil {
		return ready, fmt.Errorf("tunnel handshake: signing the hello: %w", err)
	}
	hello, _ := json.Marshal(helloMsg{T: "hello", V: ProtocolVersion, Node: c.opt.NodeID, Nonce: ch.Nonce, TS: now,
		Alg: c.leaf.alg, Sig: sig, Cert: c.leaf.cert})
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, hello); err != nil {
		return ready, fmt.Errorf("tunnel handshake: sending the hello: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	typ, data, err = conn.ReadMessage()
	if err != nil {
		return ready, fmt.Errorf("tunnel handshake: no answer to the hello: %w", err)
	}
	if typ != websocket.TextMessage || json.Unmarshal(data, &ready) != nil {
		return ready, errors.New("tunnel handshake: the gateway's answer to the hello was not understood")
	}
	if ready.T == "refused" {
		return ready, fmt.Errorf("tunnel handshake: the gateway refused this node: %s", ready.Reason)
	}
	if ready.T != "ready" || ready.V != ProtocolVersion {
		return ready, errors.New("tunnel handshake: the gateway did not say ready")
	}
	if ready.Window < 8*MinCost || ready.Window > MaxWindow {
		ready.Window = DefaultWindow
	}
	if ready.MaxStreams <= 0 || ready.MaxStreams > NodeStreamCeiling {
		ready.MaxStreams = NodeStreamCeiling
	}
	return ready, nil
}

// backoff is exponential with jitter: each delay is uniform in [d/2, d].
type backoff struct {
	min, max, cur time.Duration
}

func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.min
	} else {
		b.cur *= 2
		if b.cur > b.max {
			b.cur = b.max
		}
	}
	return jitter(b.cur)
}

func (b *backoff) reset() { b.cur = 0 }

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}
