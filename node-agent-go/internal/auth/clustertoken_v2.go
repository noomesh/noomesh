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
	"net/http"
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

// ErrNotSignable is wrapped by SetClusterAuth when a request cannot carry a
// v2 cluster token. There is no v1 fallback: the controller refuses the old
// form, so a request sent anyway would only be a guaranteed 401.
var ErrNotSignable = errors.New("cluster token: request not signable as v2")

// SetClusterAuth sets the Authorization header on an outbound request to the
// controller: a v2 token bound to this request's method, target and body. It
// returns an error (wrapping ErrNotSignable) when the request cannot be
// signed — the body fails to read or exceeds what a verifier accepts, or no
// randomness is available — and leaves the request unauthenticated; the
// caller must not send it. A body with no GetBody (a stream) is read here,
// bounded, and put back as bytes so it can be hashed. Call it AFTER the body
// is attached.
func SetClusterAuth(req *http.Request, nodeID, secret string) error {
	if secret == "" {
		return nil
	}
	body, ok := signableBody(req)
	if !ok {
		return fmt.Errorf("%w: body unreadable or larger than %d bytes (%s %s)", ErrNotSignable, maxSignedBody, req.Method, req.URL.Path)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("%w: %v", ErrNotSignable, err)
	}
	tok, err := SignV2(req.Method, req.URL.RequestURI(), body, nodeID, secret, clock(), nonce)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotSignable, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	// The gateway's rate limiter runs before it reads the body, so it checks
	// the signature against this hash; its auth layer hashes the real body
	// and never trusts the header.
	sum := sha256.Sum256(body)
	req.Header.Set(BodySHAHeader, hex.EncodeToString(sum[:]))
	return nil
}

// signableBody returns the bytes a v2 token is signed over. A body that can
// be re-read (GetBody) is read from a copy; one that cannot is read once,
// up to maxSignedBody, and replaced by those bytes (with a GetBody), so the
// request still sends exactly what was signed. false: the body failed to
// read, or is larger than a verifier accepts — the caller then has nothing
// a v2 token can describe.
func signableBody(req *http.Request) ([]byte, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, true
	}
	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err != nil {
			return nil, false
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		return b, err == nil
	}
	orig := req.Body
	b, err := io.ReadAll(io.LimitReader(orig, maxSignedBody+1))
	if err != nil || len(b) > maxSignedBody {
		// Too large (or broken) to sign: send it unchanged, what was read
		// first and the rest after.
		req.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(b), orig), orig}
		return nil, false
	}
	_ = orig.Close()
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	req.ContentLength = int64(len(b))
	return b, true
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
