// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// outcome is the status contract, decided in one place.
type outcome int

const (
	outcomeAccepted outcome = iota // 2xx: the batch is in
	outcomeDropped                 // 400/413 (or retry:false): never acceptable; drop it, say so once
	outcomeRetry                   // 401/403/429/5xx/404/transport (or retry:true): keep it, back off
)

type pushResult struct {
	outcome    outcome
	status     int
	reason     string
	retryAfter time.Duration
	err        error
}

// refusal is the gateway's error body.
type refusal struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
	Retry  *bool  `json:"retry"`
}

// errRouteAbsent is the roll-safety signal: the controller answered 404 to
// the ingest route, i.e. this agent was upgraded before the gateway.
var errRouteAbsent = errors.New("the controller has no log ingest route yet (HTTP 404) — gateway older than this agent")

// pusher POSTs one gzip body. It holds the same transport the heartbeat
// uses (node leaf for mTLS) and sets the same bearer.
type pusher struct {
	client *http.Client
	url    string
	auth   func(*http.Request)
}

// newPusher builds the push URL from the controller URL and REFUSES a
// plaintext scheme. The transport carries the node's client certificate;
// over http:// it would carry nothing and the cluster token would cross
// the wire in the clear.
func newPusher(controllerURL, nodeID string, client *http.Client, auth func(*http.Request)) (*pusher, error) {
	u := strings.TrimRight(strings.TrimSpace(controllerURL), "/")
	if !strings.HasPrefix(strings.ToLower(u), "https://") {
		return nil, fmt.Errorf("log shipping refuses a plaintext controller URL %q — logs and the cluster token travel over TLS only", controllerURL)
	}
	if nodeID == "" {
		return nil, errors.New("log shipping needs a node id")
	}
	if client == nil {
		return nil, errors.New("log shipping needs the agent's HTTP client")
	}
	return &pusher{
		client: client,
		url:    u + "/api/cluster/nodes/" + nodeID + "/logs",
		auth:   auth,
	}, nil
}

// send POSTs an already-gzipped body and classifies the answer.
func (p *pusher) send(ctx context.Context, gz []byte) pushResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(gz))
	if err != nil {
		return pushResult{outcome: outcomeRetry, err: err, reason: "build request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if p.auth != nil {
		p.auth(req)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return pushResult{outcome: outcomeRetry, err: err, reason: "transport: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return classify(resp.StatusCode, resp.Header.Get("Retry-After"), body)
}

// classify is the whole status contract.
func classify(status int, retryAfterHdr string, body []byte) pushResult {
	res := pushResult{status: status, retryAfter: parseRetryAfter(retryAfterHdr)}
	var ref refusal
	_ = json.Unmarshal(body, &ref)
	text := strings.TrimSpace(string(body))
	if ref.Error != "" {
		text = ref.Error
	}
	if len(text) > 200 {
		text = text[:200]
	}
	res.reason = fmt.Sprintf("http %d", status)
	if ref.Reason != "" {
		res.reason += " " + ref.Reason
	}
	if text != "" {
		res.reason += ": " + text
	}

	switch {
	case status >= 200 && status < 300:
		res.outcome = outcomeAccepted
	case status == http.StatusNotFound:
		// Older gateway: keep the batch and let the shipper re-probe.
		res.outcome = outcomeRetry
		res.err = errRouteAbsent
	case ref.Retry != nil:
		// The gateway said whether this is worth retrying; believe it.
		if *ref.Retry {
			res.outcome = outcomeRetry
		} else {
			res.outcome = outcomeDropped
		}
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		// A credential problem is fixed on the controller or by a
		// re-provision; the lines are still good. Keep them.
		res.outcome = outcomeRetry
	case status == http.StatusTooManyRequests:
		res.outcome = outcomeRetry
	case status >= 400 && status < 500:
		// 400 malformed, 413 too large, and anything else in the class:
		// resending the same bytes cannot succeed.
		res.outcome = outcomeDropped
	default:
		res.outcome = outcomeRetry
	}
	return res
}

// probe asks whether the route exists at all, with an empty push. The
// gateway answers 400 to an empty push; any answer but 404 (400, 401,
// 403, 2xx…) proves the route is mounted. A transport error proves
// nothing.
func (p *pusher) probe(ctx context.Context) (present bool, err error) {
	gz, err := gzipBytes([]byte(`{"streams":[]}`))
	if err != nil {
		return false, err
	}
	res := p.send(ctx, gz)
	if res.status == 0 {
		return false, res.err
	}
	if res.status == http.StatusNotFound {
		return false, errRouteAbsent
	}
	return true, nil
}

// parseRetryAfter reads seconds or an HTTP date; 0 when absent or junk.
func parseRetryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if n, err := strconv.Atoi(h); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// backoff is 1 s → 60 s, doubling, with ±25 % jitter so a fleet that lost
// its controller at the same instant does not knock on the door in step.
type backoff struct {
	cur, min, max time.Duration
	rnd           *rand.Rand
}

func newBackoff(min, max time.Duration) *backoff {
	return &backoff{cur: 0, min: min, max: max, rnd: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

// next returns the wait before the next attempt; hint (Retry-After) wins
// when the server gave one, capped at max.
func (b *backoff) next(hint time.Duration) time.Duration {
	if b.cur == 0 {
		b.cur = b.min
	} else {
		b.cur *= 2
		if b.cur > b.max {
			b.cur = b.max
		}
	}
	d := b.cur
	if hint > 0 {
		d = hint
		if d > b.max {
			d = b.max
		}
		return d
	}
	jitter := time.Duration(float64(d) * 0.25 * (b.rnd.Float64()*2 - 1))
	return d + jitter
}

func (b *backoff) reset() { b.cur = 0 }
