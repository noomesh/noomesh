// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cluster token v2: an HMAC that authenticates the REQUEST, not just the
// holder.
//
// v1 signs "<actor>:<ts>" only, so one captured Authorization header is a
// bearer for any method, path and body for five minutes. v2 signs
//
//	v2 \n METHOD \n path?query \n hex(sha256(body)) \n actor \n ts \n nonce
//
// and travels as "v2:<actor>:<ts>:<nonce>:<hex hmac>". The nonce is 128
// random bits; a verifier remembers every nonce it accepted for the replay
// window and refuses a second use. Mirrors gateway-rust/src/cluster_token_v2.rs
// — the two are pinned together by the shared test vector in both suites.
const (
	tokenV2Prefix = "v2:"
	// ClusterTokenWindow is the freshness window, both directions of skew.
	ClusterTokenWindow = 5 * time.Minute
	// maxSignedBody bounds what a verifier buffers to hash. A larger body
	// is refused (413) rather than admitted unbound.
	maxSignedBody = 32 << 20
	// nonceCap bounds the replay set. Only a request that already verified
	// under the fleet secret reaches it, so filling it takes the secret; at
	// the cap new tokens are refused (closed), never admitted unchecked.
	nonceCap = 200_000
)

// BodySHAHeader carries the hex sha256 of the body the token was signed over.
const BodySHAHeader = "X-Noo-Content-Sha256"

var errBodyTooLarge = errors.New("body too large to verify")

// clock is replaced in tests.
var clock = time.Now

// V1Allowed reports whether the legacy v1 token is still accepted.
// NOO_CLUSTER_TOKEN_V1=0 closes it (the posture gate, set once every caller
// signs v2). Unset or anything else keeps the rollout default: accepted and
// counted.
func V1Allowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NOO_CLUSTER_TOKEN_V1"))) {
	case "0", "false", "no", "off", "closed":
		return false
	}
	return true
}

// SignV1Only pins signers to the v1 wire form (NOO_CLUSTER_TOKEN_SIGN=v1).
// Only for a node rolled BEFORE its controller: an old gateway cannot read v2.
func SignV1Only() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("NOO_CLUSTER_TOKEN_SIGN")), "v1")
}

func v2Message(method, requestURI, bodySHA, actor, ts, nonce string) string {
	return strings.Join([]string{"v2", strings.ToUpper(method), requestURI, bodySHA, actor, ts, nonce}, "\n")
}

func v2Sig(secret, msg string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignV2 builds a v2 token for one request. nonce is 16 random bytes.
func SignV2(method, requestURI string, body []byte, actor, secret string, at time.Time, nonce []byte) (string, error) {
	if actor == "" || strings.ContainsAny(actor, ":\n") {
		return "", fmt.Errorf("actor %q cannot be signed", actor)
	}
	if secret == "" {
		return "", errors.New("no secret")
	}
	sum := sha256.Sum256(body)
	ts := strconv.FormatInt(at.Unix(), 10)
	n := hex.EncodeToString(nonce)
	sig := v2Sig(secret, v2Message(method, requestURI, hex.EncodeToString(sum[:]), actor, ts, n))
	return fmt.Sprintf("v2:%s:%s:%s:%s", actor, ts, n, sig), nil
}

// SetClusterAuth sets the Authorization header on an outbound request to the
// controller: a v2 token bound to this request's method, target and body, or
// the v1 token when the body cannot be re-read or v1 is pinned. Call it AFTER
// the body is attached (http.NewRequest sets GetBody for bytes/strings
// readers).
func SetClusterAuth(req *http.Request, nodeID, secret string) {
	if secret == "" {
		return
	}
	if !SignV1Only() {
		var body []byte
		ok := true
		if req.Body != nil && req.Body != http.NoBody {
			if req.GetBody == nil {
				ok = false
			} else if rc, err := req.GetBody(); err != nil {
				ok = false
			} else {
				body, err = io.ReadAll(rc)
				_ = rc.Close()
				ok = err == nil
			}
		}
		if ok {
			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err == nil {
				if tok, err := SignV2(req.Method, req.URL.RequestURI(), body, nodeID, secret, clock(), nonce); err == nil {
					req.Header.Set("Authorization", "Bearer "+tok)
					// The gateway's rate limiter runs before it reads the body, so
					// it checks the signature against this hash; its auth layer
					// hashes the real body and never trusts the header.
					sum := sha256.Sum256(body)
					req.Header.Set(BodySHAHeader, hex.EncodeToString(sum[:]))
					return
				}
			}
		}
		slog.Warn("cluster token: request not signable as v2, sending v1", "method", req.Method, "path", req.URL.Path)
	}
	req.Header.Set("Authorization", "Bearer "+CreateClusterToken(nodeID, secret))
}

// IsV2Token reports whether a bearer is in the v2 wire form.
func IsV2Token(token string) bool { return strings.HasPrefix(token, tokenV2Prefix) }

// bufferBody reads the request body (bounded) and restores it for the handler.
func bufferBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxSignedBody+1))
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(b) > maxSignedBody {
		return nil, errBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

// verifyClusterTokenV2 checks signature, window, request binding and replay.
// body is the request's full body (nil when none). Returns the actor.
func verifyClusterTokenV2(token, secret string, r *http.Request, body []byte) (bool, string) {
	parts := strings.Split(token, ":")
	if len(parts) != 5 || parts[0] != "v2" {
		return false, ""
	}
	actor, tsStr, nonce, sig := parts[1], parts[2], parts[3], parts[4]
	if actor == "" || len(nonce) != 32 || len(sig) != 64 {
		return false, ""
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return false, ""
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, ""
	}
	now := clock()
	if now.Sub(time.Unix(ts, 0)).Abs() > ClusterTokenWindow {
		return false, ""
	}
	sum := sha256.Sum256(body)
	want := v2Sig(secret, v2Message(r.Method, r.URL.RequestURI(), hex.EncodeToString(sum[:]), actor, tsStr, nonce))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return false, ""
	}
	// Only a token that VERIFIED is remembered, so a stranger cannot fill the
	// set; and the claim is last so a failed signature never burns a nonce.
	if !nonces.claim(actor+"|"+nonce, now) {
		return false, ""
	}
	return true, actor
}

// nonceSet is the replay memory: nonce -> expiry, bounded by the window.
type nonceSet struct {
	mu        sync.Mutex
	seen      map[string]int64
	nextSweep int64
}

var nonces = &nonceSet{seen: map[string]int64{}}

// claim records the nonce; false when it was already used inside the window
// or the set is full (fail closed).
func (n *nonceSet) claim(key string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	t := now.Unix()
	if t >= n.nextSweep || len(n.seen) >= nonceCap {
		for k, exp := range n.seen {
			if exp <= t {
				delete(n.seen, k)
			}
		}
		n.nextSweep = t + 30
	}
	if exp, ok := n.seen[key]; ok && exp > t {
		return false
	}
	if len(n.seen) >= nonceCap {
		return false
	}
	// Kept for window+skew on both sides: a token stamped 5 min in the
	// future stays valid 10 min from now.
	n.seen[key] = t + int64(2*ClusterTokenWindow/time.Second) + 1
	return true
}

// resetNoncesForTest empties the replay memory.
func resetNoncesForTest() {
	nonces.mu.Lock()
	nonces.seen = map[string]int64{}
	nonces.nextSweep = 0
	nonces.mu.Unlock()
}
