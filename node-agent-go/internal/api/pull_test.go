// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// `/pull kind=binary` — the agent half of the gateway-signed
// agent swap — is retired. It must answer 410 with the reason and the rail
// command, not stage anything; the pre-retirement handler went on to fetch a
// manifest and queue a root swap. Docker is nil here on purpose: the refusal
// does not depend on any backend being up.
func TestPullKindBinaryIsRefused(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/pull",
		strings.NewReader(`{"kind":"binary","binary":"noo-node-agent"}`))
	rec := httptest.NewRecorder()
	s.handlePull(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("kind=binary: status %d, want 410 Gone; body %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["detail"], "retired") || !strings.Contains(body["detail"], "noo cluster provision") {
		t.Fatalf("refusal must say retired and name the rail: %q", body["detail"])
	}
}

// The other kinds are untouched: with no Docker they still answer 503, which
// shows the binary refusal is a branch of its own and not a blanket change.
func TestPullOtherKindsStillReachDockerCheck(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/pull", strings.NewReader(`{"kind":"image","image":"x"}`))
	rec := httptest.NewRecorder()
	s.handlePull(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("kind=image without docker: %d, want 503", rec.Code)
	}
}
