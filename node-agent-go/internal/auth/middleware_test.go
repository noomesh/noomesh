// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

func TestMiddleware_NoAuthConfigured(t *testing.T) {
	cfg := &config.Config{} // no token, no secret
	mw := Middleware(cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestMiddleware_MissingBearerToken(t *testing.T) {
	cfg := &config.Config{NodeAgentToken: "secret123"}
	mw := Middleware(cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/start", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	cfg := &config.Config{NodeAgentToken: "correct-token"}
	mw := Middleware(cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/start", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestMiddleware_ValidStaticToken(t *testing.T) {
	cfg := &config.Config{NodeAgentToken: "correct-token"}
	mw := Middleware(cfg)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/start", nil)
	req.Header.Set("Authorization", "Bearer correct-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestMiddleware_ValidHMACToken(t *testing.T) {
	secret := "cluster-secret-abc"
	cfg := &config.Config{ClusterSecret: secret}
	mw := Middleware(cfg)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))

	token := CreateClusterToken("node-1", secret)

	req := httptest.NewRequest("GET", "/start", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestMiddleware_ExpiredHMACToken(t *testing.T) {
	secret := "cluster-secret-abc"
	cfg := &config.Config{ClusterSecret: secret}
	mw := Middleware(cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	// Create a token with a timestamp 10 minutes ago
	oldTS := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	message := fmt.Sprintf("node-1:%s", oldTS)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))
	expiredToken := fmt.Sprintf("node-1:%s:%s", oldTS, sig)

	req := httptest.NewRequest("GET", "/start", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for expired token, got %d", rec.Code)
	}
}

func TestMiddleware_StaticTokenFallsThruToHMAC(t *testing.T) {
	secret := "cluster-secret"
	cfg := &config.Config{
		NodeAgentToken: "static-token",
		ClusterSecret:  secret,
	}
	mw := Middleware(cfg)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))

	// Use HMAC token (not the static one) — should still work via fallthrough
	token := CreateClusterToken("node-2", secret)
	req := httptest.NewRequest("GET", "/start", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200 via HMAC fallthrough, got %d", rec.Code)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestCreateClusterToken_Roundtrip(t *testing.T) {
	secret := "test-secret-key"
	nodeID := "gpu-worker-1"

	token := CreateClusterToken(nodeID, secret)
	valid, parsedNode := verifyClusterToken(token, secret)

	if !valid {
		t.Error("token should be valid")
	}
	if parsedNode != nodeID {
		t.Errorf("expected node_id %q, got %q", nodeID, parsedNode)
	}
}

func TestVerifyClusterToken_WrongSecret(t *testing.T) {
	token := CreateClusterToken("node-1", "correct-secret")
	valid, _ := verifyClusterToken(token, "wrong-secret")

	if valid {
		t.Error("token should be invalid with wrong secret")
	}
}

func TestVerifyClusterToken_MalformedToken(t *testing.T) {
	cases := []string{
		"",
		"no-colons",
		"one:colon",
		"too:many:colons:here",
	}

	for _, tc := range cases {
		valid, _ := verifyClusterToken(tc, "secret")
		if valid {
			t.Errorf("malformed token %q should be invalid", tc)
		}
	}
}

// mintToken builds "<actor>:<ts>:<sig>" the way the Rust gateway
// (routes/cluster.rs mint_cluster_token) and noo-cli (auth.rs cluster_token)
// do: full 64-hex HMAC-SHA256 over "actor:ts".
func mintToken(actor, secret string, ts int64, truncate bool) string {
	tsStr := fmt.Sprintf("%d", ts)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(actor + ":" + tsStr))
	sig := hex.EncodeToString(mac.Sum(nil))
	if truncate {
		sig = sig[:32]
	}
	return actor + ":" + tsStr + ":" + sig
}

// TestVerifyClusterToken_Full64HexFromRustMinters guards the cross-language
// HMAC width contract: the Rust gateway and noo-cli mint full 64-hex
// signatures for node-agent-bound tokens, and this verifier must accept them.
func TestVerifyClusterToken_Full64HexFromRustMinters(t *testing.T) {
	secret := "shared-cluster-secret"
	token := mintToken("gateway", secret, time.Now().Unix(), false)
	valid, actor := verifyClusterToken(token, secret)
	if !valid {
		t.Fatal("full 64-hex token from Rust-style minter should verify")
	}
	if actor != "gateway" {
		t.Errorf("expected actor gateway, got %q", actor)
	}
}

// TestVerifyClusterToken_Rejects32HexTruncated documents the strictness
// decision: the Go verifier only accepts the full 64-hex width. Legacy
// Python create_cluster_token still emits 32-hex, but Python never
// authenticates to Go node-agents via HMAC (it uses NOO_NODE_AGENT_TOKEN),
// so no working pair depends on 32-hex here.
func TestVerifyClusterToken_Rejects32HexTruncated(t *testing.T) {
	secret := "shared-cluster-secret"
	token := mintToken("cli", secret, time.Now().Unix(), true)
	if valid, _ := verifyClusterToken(token, secret); valid {
		t.Error("truncated 32-hex signature must be rejected")
	}
}

// TestMiddleware_RefusesCLIActors: a fleet-secret token signed as the noo
// CLI (`cli`, `cli-*`) is refused on node routes even with a valid
// signature. No CLI sends one any more; other actors are unaffected.
func TestMiddleware_RefusesCLIActors(t *testing.T) {
	secret := "cluster-secret-abc"
	cfg := &config.Config{ClusterSecret: secret}
	called := false
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	for _, actor := range []string{"cli", "cli-break-glass", "cli-onboard", "cli-posture"} {
		called = false
		req := httptest.NewRequest("GET", "/gpu", nil)
		req.Header.Set("Authorization", "Bearer "+CreateClusterToken(actor, secret))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || called {
			t.Errorf("actor %q: expected 403 and no handler call, got %d (called=%v)", actor, rec.Code, called)
		}
	}
	for _, actor := range []string{"gateway", "node-1", "client", "clinic"} {
		called = false
		req := httptest.NewRequest("GET", "/gpu", nil)
		req.Header.Set("Authorization", "Bearer "+CreateClusterToken(actor, secret))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 || !called {
			t.Errorf("actor %q must still be admitted, got %d", actor, rec.Code)
		}
	}
}
