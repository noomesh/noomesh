// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// i1174: the agent applies desired-config's require_target_node on every
// read, and a read that omits it (a controller one step back) makes the
// agent tolerant again. A failed read changes nothing.
func TestDesiredConfigAppliesAndClearsRequireTargetNode(t *testing.T) {
	prev := auth.RequiresTargetNode()
	t.Cleanup(func() { auth.SetRequireTargetNode(prev) })
	var body atomic.Pointer[string]
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(*body.Load()))
	}))
	defer srv.Close()
	r := &Reconciler{cfg: &config.Config{ControllerURL: srv.URL, NodeID: "node-a"}, client: srv.Client()}
	read := func(b string, code int) error {
		body.Store(&b)
		status.Store(int32(code))
		_, err := r.fetch(context.Background())
		return err
	}

	auth.SetRequireTargetNode(false)
	if err := read(`{"require_target_node":true}`, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	if !auth.RequiresTargetNode() {
		t.Fatal("require_target_node: true was not applied")
	}
	if err := read(`{"error":"busy"}`, http.StatusServiceUnavailable); err == nil {
		t.Fatal("a 503 read must fail")
	}
	if !auth.RequiresTargetNode() {
		t.Fatal("a failed read must keep the applied flag")
	}
	if err := read(`{}`, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	if auth.RequiresTargetNode() {
		t.Fatal("a desired-config without require_target_node (an older controller) must make the agent tolerant again")
	}
}
