// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// POST /reconcile hands the controller's request to the reconciler's Nudge
// and answers 202; before the reconciler is wired it answers 503 and nudges
// nothing. The route-parity table (rpc_test.go) covers the bus twin.
func TestReconcileNudgesTheReconcilerOnce(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.handleReconcile(w, httptest.NewRequest("POST", "/reconcile", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired: got %d want 503", w.Code)
	}
	n := 0
	s.SetReconcileNudge(func() { n++ })
	w = httptest.NewRecorder()
	s.handleReconcile(w, httptest.NewRequest("POST", "/reconcile", nil))
	if w.Code != http.StatusAccepted || n != 1 {
		t.Fatalf("wired: got %d, nudges %d; want 202 and 1", w.Code, n)
	}
}
