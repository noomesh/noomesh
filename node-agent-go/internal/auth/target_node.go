// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// An agent refuses calls addressed to another node (i1174).
//
// The gateway names the node every call is meant for in TargetNodeHeader.
// This agent answers only calls that name ITSELF: a call naming another node
// is refused with 421 Misdirected Request and {"code":"wrong_node"}, whoever
// sent it.
//
// A call that names no node is accepted while the controller has not said
// otherwise. The controller turns strictness on PER NODE through the
// authenticated desired-config it already serves (`require_target_node`),
// and only once this agent reported it checks the header
// (ChecksTargetNodeField on every heartbeat). From then on a controller call
// (the gateway's leaf) with no header is refused too. An older controller
// sends no field, which reads as false: the agent goes tolerant again, so a
// one-step-back controller keeps working, and a controller-first roll never
// strands a node that has not upgraded yet.
//
// Only the HTTPS listener is wrapped. The node-held tunnel and the bus
// reach this agent by its own node id (the controller picks the tunnel or
// the subject by node), so nothing on them is addressed to another node.
// GET /health and GET /metrics stay open to a header-less caller: they
// change nothing, and the controller's startup probe and the scraper read
// them.

// TargetNodeHeader names the node a call is meant for.
const TargetNodeHeader = "X-Noo-Node"

// ChecksTargetNodeField is the heartbeat field saying this agent checks
// TargetNodeHeader.
const ChecksTargetNodeField = "checks_target_node"

// RequiresTargetNodeField is the heartbeat field saying whether this agent
// refuses a header-less controller call right now (the desired-config flag
// it last applied).
const RequiresTargetNodeField = "requires_target_node"

// WrongNodeCode is the refusal's machine-readable code.
const WrongNodeCode = "wrong_node"

var requireTargetNode atomic.Bool

// SetRequireTargetNode applies desired-config's `require_target_node`
// (absent = false).
func SetRequireTargetNode(v bool) {
	if requireTargetNode.Swap(v) != v {
		slog.Info("target_node_strictness", "require_target_node", v)
	}
}

// RequiresTargetNode reports whether a header-less controller call is
// refused now.
func RequiresTargetNode() bool { return requireTargetNode.Load() }

// TargetNode wraps the agent's HTTPS listener with the target check.
func TargetNode(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if why := TargetNodeRefusal(cfg, r); why != "" {
				slog.Warn("wrong_node", "path", r.URL.Path, "target", r.Header.Get(TargetNodeHeader), "detail", why)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusMisdirectedRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": WrongNodeCode, "detail": why})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TargetNodeRefusal is why the call is refused, or "" when it is not.
func TargetNodeRefusal(cfg *config.Config, r *http.Request) string {
	self := ""
	if cfg != nil {
		self = strings.TrimSpace(cfg.NodeID)
	}
	if want := strings.TrimSpace(r.Header.Get(TargetNodeHeader)); want != "" {
		if self != "" && !strings.EqualFold(want, self) {
			return "this call is addressed to node " + want + "; this agent is " + self
		}
		return ""
	}
	if !RequiresTargetNode() || targetNodeExempt(r) {
		return ""
	}
	if r.TLS != nil && isController(r.TLS.PeerCertificates) {
		return "a controller call must name the node it is meant for (" + TargetNodeHeader + ")"
	}
	return ""
}

func targetNodeExempt(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.URL.Path == "/health" || r.URL.Path == "/metrics")
}
