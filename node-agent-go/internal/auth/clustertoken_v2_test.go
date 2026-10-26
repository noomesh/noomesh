// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

const v2Secret = "s3cret"

func v2Handler(t *testing.T, served *int) http.Handler {
	t.Helper()
	cfg := &config.Config{ClusterSecret: v2Secret}
	return Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*served++
		b, _ := io.ReadAll(r.Body)
		w.Write(b) // the handler must still see the body after hashing
	}))
}

func signedReq(t *testing.T, method, uri, body string) *http.Request {
	t.Helper()
	// http.NewRequest (not httptest) sets GetBody, as every production caller's does.
	req, err := http.NewRequest(method, "http://controller"+uri, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := SetClusterAuth(req, "host2", v2Secret); err != nil {
		t.Fatal(err)
	}
	if !IsV2Token(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")) {
		t.Fatalf("signer did not produce v2: %q", req.Header.Get("Authorization"))
	}
	return req
}

func TestV2_SharedVectorMatchesShellAndRust(t *testing.T) {
	nonce, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	tok, err := SignV2("POST", "/bootstrap/bundle/host1/applied", []byte(`{"a":1}`), "host1", v2Secret, time.Unix(1700000000, 0), nonce)
	if err != nil {
		t.Fatal(err)
	}
	want := "v2:host1:1700000000:00112233445566778899aabbccddeeff:3aee59b3fc968f448b71de5aeb463044b25a26a3ef8ccdff6fc3d53cbbe59540"
	if tok != want {
		t.Fatalf("vector drifted (noo-fetch.sh and the gateway pin the same value)\n got %s\nwant %s", tok, want)
	}
}

func TestV2_ValidRequestServedWithBodyIntact(t *testing.T) {
	resetNoncesForTest()
	n := 0
	rec := httptest.NewRecorder()
	v2Handler(t, &n).ServeHTTP(rec, signedReq(t, "POST", "/start?x=1", `{"a":1}`))
	if rec.Code != 200 || n != 1 || rec.Body.String() != `{"a":1}` {
		t.Fatalf("code=%d served=%d body=%q", rec.Code, n, rec.Body.String())
	}
}

func TestV2_ReplayIsRefused(t *testing.T) {
	resetNoncesForTest()
	n := 0
	h := v2Handler(t, &n)
	req := signedReq(t, "POST", "/start", `{}`)
	h.ServeHTTP(httptest.NewRecorder(), req)
	replay := httptest.NewRequest("POST", "/start", strings.NewReader(`{}`))
	replay.Header.Set("Authorization", req.Header.Get("Authorization"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, replay)
	if rec.Code != http.StatusForbidden || n != 1 {
		t.Fatalf("replay: code=%d served=%d (want 403 and exactly one execution)", rec.Code, n)
	}
}

func TestV2_BodyPathMethodTamperRefused(t *testing.T) {
	cases := map[string]func(*http.Request) *http.Request{
		"body": func(r *http.Request) *http.Request {
			x := httptest.NewRequest(r.Method, r.URL.RequestURI(), strings.NewReader(`{"evil":1}`))
			x.Header = r.Header.Clone()
			return x
		},
		"path": func(r *http.Request) *http.Request {
			x := httptest.NewRequest(r.Method, "/stop", strings.NewReader(`{}`))
			x.Header = r.Header.Clone()
			return x
		},
		"query": func(r *http.Request) *http.Request {
			x := httptest.NewRequest(r.Method, "/start?admin=1", strings.NewReader(`{}`))
			x.Header = r.Header.Clone()
			return x
		},
		"method": func(r *http.Request) *http.Request {
			x := httptest.NewRequest("DELETE", r.URL.RequestURI(), strings.NewReader(`{}`))
			x.Header = r.Header.Clone()
			return x
		},
	}
	for name, mutate := range cases {
		resetNoncesForTest()
		n := 0
		bad := mutate(signedReq(t, "POST", "/start", `{}`))
		rec := httptest.NewRecorder()
		v2Handler(t, &n).ServeHTTP(rec, bad)
		if rec.Code != http.StatusForbidden || n != 0 {
			t.Errorf("%s tamper: code=%d served=%d (want 403, handler never run)", name, rec.Code, n)
		}
	}
}

func TestV2_StaleAndWrongSecretRefused(t *testing.T) {
	resetNoncesForTest()
	nonce := make([]byte, 16)
	nonce[0] = 7
	n := 0
	h := v2Handler(t, &n)
	for name, tok := range map[string]func() string{
		"stale": func() string {
			s, _ := SignV2("GET", "/x", nil, "host2", v2Secret, time.Now().Add(-6*time.Minute), nonce)
			return s
		},
		"wrong secret": func() string {
			s, _ := SignV2("GET", "/x", nil, "host2", "other", time.Now(), nonce)
			return s
		},
	} {
		req := httptest.NewRequest("GET", "/x", nil)
		req.Header.Set("Authorization", "Bearer "+tok())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 || n != 0 {
			t.Errorf("%s: code=%d served=%d", name, rec.Code, n)
		}
	}
}

// v1 is always refused: there is no gate to reopen it, whatever the env says,
// and every refusal is counted as a refusal (never an admission).
func TestV1_AlwaysRefusedAndCounted(t *testing.T) {
	resetNoncesForTest()
	n := 0
	h := v2Handler(t, &n)
	for _, env := range []string{"", "0", "1"} {
		t.Setenv("NOO_CLUSTER_TOKEN_V1", env) // retired: must change nothing
		refusedBefore := laneHMACv1Refused.Load()
		req := httptest.NewRequest("GET", "/x", nil)
		req.Header.Set("Authorization", "Bearer "+mintToken("host2", v2Secret, time.Now().Unix(), false))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 || n != 0 || !strings.Contains(rec.Body.String(), "signs v2") {
			t.Fatalf("v1 (env=%q): code=%d served=%d body=%s", env, rec.Code, n, rec.Body.String())
		}
		if got := laneHMACv1Refused.Load() - refusedBefore; got != 1 {
			t.Fatalf("env=%q: refused v1 counted %d times, want 1", env, got)
		}
	}
	// A v1 token that does not verify is an ordinary bad token: not counted.
	before := laneHMACv1Refused.Load()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+mintToken("host2", "wrong-secret", time.Now().Unix(), false))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 || laneHMACv1Refused.Load() != before {
		t.Fatalf("forged v1: code=%d counted=%d", rec.Code, laneHMACv1Refused.Load()-before)
	}
	// ...and v2 is untouched.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, signedReq(t, "GET", "/x", ""))
	if rec.Code != 200 {
		t.Fatalf("v2: %d", rec.Code)
	}
}

func TestV2_NonceSetIsBoundedAndFailsClosed(t *testing.T) {
	s := &nonceSet{seen: map[string]int64{}}
	now := time.Unix(1_000_000, 0)
	for i := 0; i < nonceCap; i++ {
		s.seen[fmt.Sprintf("k%d|x", i)] = now.Unix() + 600
	}
	if s.claim("new|n", now) {
		t.Fatal("a full replay set must refuse, not admit unchecked")
	}
	if !s.claim("new|n", now.Add(20*time.Minute)) {
		t.Fatal("expired entries must be swept so the set recovers")
	}
}

// There is no v1 signer: NOO_CLUSTER_TOKEN_SIGN=v1 (the old pin) changes
// nothing, and a request that cannot be signed is an ERROR, not a v1 token.
func TestSetClusterAuth_NoV1Fallback(t *testing.T) {
	t.Setenv("NOO_CLUSTER_TOKEN_SIGN", "v1") // retired pin: ignored
	req := httptest.NewRequest("GET", "/x", nil)
	if err := SetClusterAuth(req, "host2", v2Secret); err != nil {
		t.Fatal(err)
	}
	if !IsV2Token(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")) {
		t.Fatal("the retired pin must not make the signer send anything but v2")
	}

	// A body that fails to read cannot be signed: error, and no Authorization.
	bad := httptest.NewRequest("POST", "/x", io.NopCloser(errReader{}))
	bad.GetBody = nil
	err := SetClusterAuth(bad, "host2", v2Secret)
	if !errors.Is(err, ErrNotSignable) {
		t.Fatalf("unreadable body: err = %v, want ErrNotSignable", err)
	}
	if bad.Header.Get("Authorization") != "" {
		t.Fatalf("an unsignable request must not carry a token: %q", bad.Header.Get("Authorization"))
	}

	// An actor that cannot be signed is an error too (was: silently v1).
	if err := SetClusterAuth(httptest.NewRequest("GET", "/x", nil), "bad:actor", v2Secret); !errors.Is(err, ErrNotSignable) {
		t.Fatalf("bad actor: err = %v", err)
	}
	// No secret configured: nothing to sign, nothing wrong.
	if err := SetClusterAuth(httptest.NewRequest("GET", "/x", nil), "host2", ""); err != nil {
		t.Fatalf("no secret: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// A body with no GetBody (a pipe, a gzip writer, a caller's own reader) used
// to go out on the v1 token. It is read, signed v2, and sent as the bytes
// that were signed: the verifier admits it and the handler sees the body.
func TestSetClusterAuth_StreamBodyIsBufferedAndSignedV2(t *testing.T) {
	resetNoncesForTest()
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write([]byte(`{"streamed":true}`)); _ = pw.Close() }()
	req, err := http.NewRequest("POST", "http://controller/api/cluster/nodes/host2/logs", pr)
	if err != nil {
		t.Fatal(err)
	}
	if req.GetBody != nil {
		t.Fatal("precondition: a pipe body has no GetBody")
	}
	if err := SetClusterAuth(req, "host2", v2Secret); err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !IsV2Token(tok) {
		t.Fatalf("a stream body was not signed v2: %q", tok)
	}
	if req.ContentLength != int64(len(`{"streamed":true}`)) || req.GetBody == nil {
		t.Fatalf("the buffered body must be re-readable with its length: len=%d", req.ContentLength)
	}
	n := 0
	rec := httptest.NewRecorder()
	in := httptest.NewRequest("POST", "/api/cluster/nodes/host2/logs", req.Body)
	in.Header = req.Header.Clone()
	v2Handler(t, &n).ServeHTTP(rec, in)
	if rec.Code != 200 || n != 1 || rec.Body.String() != `{"streamed":true}` {
		t.Fatalf("verifier must admit the buffered body: code=%d served=%d body=%q", rec.Code, n, rec.Body.String())
	}
}

// Every outbound call shape the agent makes (no body, bytes, strings, a
// stream) signs v2, so a 0.6.8 agent adds nothing to
// the controller's cluster_hmac_v1_refused lane.
func TestSetClusterAuth_EveryBodyShapeSignsV2(t *testing.T) {
	bodies := map[string]func() io.Reader{
		"nil":     func() io.Reader { return nil },
		"bytes":   func() io.Reader { return strings.NewReader("x") }, // NewRequest: GetBody
		"strings": func() io.Reader { return strings.NewReader(`{"a":1}`) },
		"stream": func() io.Reader {
			pr, pw := io.Pipe()
			go func() { _, _ = pw.Write([]byte("chunk")); _ = pw.Close() }()
			return pr
		},
	}
	for name, mk := range bodies {
		req, err := http.NewRequest("POST", "http://controller/api/cluster/nodes/host2/heartbeat", mk())
		if err != nil {
			t.Fatal(err)
		}
		if err := SetClusterAuth(req, "host2", v2Secret); err != nil {
			t.Fatal(err)
		}
		if tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "); !IsV2Token(tok) {
			t.Errorf("%s body: signed %q, want v2", name, tok)
		}
		if req.Header.Get(BodySHAHeader) == "" {
			t.Errorf("%s body: no %s header", name, BodySHAHeader)
		}
	}
}
