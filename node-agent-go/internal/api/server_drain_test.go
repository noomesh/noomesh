// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/stopdrain"
)

// Before the agent installs the drain, a call is served as before and the
// controller's marker still never reaches the backend.
func TestTheDrainGuardStripsTheMarkerAndServesWithoutAGate(t *testing.T) {
	s := &Server{}
	got := "unset"
	h := s.drainGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(stopdrain.ResendHeader)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(stopdrain.ResendHeader, stopdrain.ResendWhole)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || got != "" {
		t.Fatalf("code %d, marker at the backend %q", rec.Code, got)
	}
}

// A plain request is not the controller: only a verified controller leaf or
// the node's own tunnel is.
func TestAPlainRequestIsNotTheController(t *testing.T) {
	if IsController(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)) {
		t.Fatal("a request with no verified principal is not the controller")
	}
}
