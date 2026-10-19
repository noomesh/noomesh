// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"encoding/json"
	"net/http"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
)

// HarnessPlacement is what GET /harness/placement answers: the harness
// placement this node is asked to run, so the harness process can learn its
// kind at startup without a unit change or an env restage (the kind is the
// placement's, and the unit's EnvironmentFile cannot carry it).
type HarnessPlacement struct {
	Kind         string            `json:"kind"`
	Env          map[string]string `json:"env"`
	DesiredState string            `json:"desired_state"`
	Placed       bool              `json:"placed"`
	// Profile is the node's resolved harness profile exactly as the
	// controller sent it in desired-config (stream_idle_secs, thinking,
	// claude_prompt, ...: the harness applies those), omitted when the node
	// has none. It holds no secret: the controller's resolution is numbers,
	// enums and kind names.
	Profile json.RawMessage `json:"profile,omitempty"`
}

// SetHarnessPlacement installs the provider of the node's desired harness
// placement. nil (or a provider that reports placed=false) answers 404.
func (s *Server) SetHarnessPlacement(f func() HarnessPlacement) { s.harnessPlacement = f }

// handleHarnessPlacement is read-only and answers only this node's own
// harness (see registerRoutes). 404 {"placed": false} when no harness
// placement is desired.
func (s *Server) handleHarnessPlacement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.harnessPlacement != nil {
		if hp := s.harnessPlacement(); hp.Placed {
			if hp.Env == nil {
				hp.Env = map[string]string{}
			}
			_ = json.NewEncoder(w).Encode(hp)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"placed": false}`))
}

// ownHarnessOnly admits only this node's own harness: its verified leaf over
// loopback (auth.Principal.OwnHarness). The controller, a peer and a bearer
// alone are all refused: this route is the harness's, not the fleet's.
func ownHarnessOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := auth.FromContext(r.Context()); ok && p.Identified && p.OwnHarness {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, `{"detail":"this route answers the node's own harness over loopback only"}`, http.StatusForbidden)
	})
}
