// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// handleMCPCall — POST /api/mcp/{server}/call {"tool": "...", "arguments": {...}}
//
// The node-side half of the bridge. The gateway
// decided WHO may call (audience) and WHICH node hosts the server; this
// handler only runs the call on the live server and returns the MCP
// result verbatim. Controller-only by the certificate principal, like
// every other command route on this agent.
func (s *Server) handleMCPCall(w http.ResponseWriter, r *http.Request) {
	if s.mcp == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no MCP supervisor on this agent"})
		return
	}
	server := r.PathValue("server")
	var req struct {
		Tool      string          `json:"tool"`
		Arguments json.RawMessage `json:"arguments"`
		TimeoutS  int             `json:"timeout_secs"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil || req.Tool == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "body must be {\"tool\": name, \"arguments\": {...}}"})
		return
	}
	timeout := 120 * time.Second
	if req.TimeoutS > 0 && req.TimeoutS <= 600 {
		timeout = time.Duration(req.TimeoutS) * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	res, err := s.mcp.Call(ctx, server, req.Tool, req.Arguments)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "server": server, "tool": req.Tool})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res)
}

// handleMCPServers — GET /api/mcp/servers: what is live here, for the
// operator and for the controller's health views.
func (s *Server) handleMCPServers(w http.ResponseWriter, _ *http.Request) {
	if s.mcp == nil {
		writeJSON(w, http.StatusOK, map[string]any{"servers": []any{}, "supervisor": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": s.mcp.Statuses(), "supervisor": true})
}
