// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlrpc"
)

// rpcOp maps a control-bus op onto the HTTP handler that already implements
// it. There is no second implementation: RPCDo builds the request the HTTPS
// route would have received and calls the very same handler function, so the
// status, headers and body are the ones the HTTPS API sends.
//
// The authentication middleware (ctrlMW) is NOT in this path: the bus gate
// is the signed envelope internal/ctrlrpc verified, which is the same fact
// ControllerOnly establishes for a TLS peer (a leaf the cluster CA signed,
// carrying the controller organization). TestRPCOpsMatchTheControllerRoutes
// pins that every op names a route this server registers behind ctrlMW.
type rpcOp struct {
	method  string
	path    string // the registered pattern, for the route-parity test
	handler func(*Server) http.HandlerFunc
	// pathValue names the {wildcard} the envelope's Arg fills ("" = none).
	pathValue string
	// async ops are acked at once and answer on the event stream.
	async bool
}

// rpcOps is the control set. Not here on purpose: streaming and bulk routes
// (inference SSE, the container proxy, device blobs, /metrics), which stay on
// HTTPS until the tunnel (followup i131 phase 2). The inventory also lists
// /tools; this agent has no such route, so there is no op for it.
var rpcOps = map[string]rpcOp{
	"health":      {method: "GET", path: "/health", handler: func(s *Server) http.HandlerFunc { return s.handleHealth }},
	"gpu":         {method: "GET", path: "/gpu", handler: func(s *Server) http.HandlerFunc { return s.handleGPUMetrics }},
	"stats":       {method: "GET", path: "/stats/containers", handler: func(s *Server) http.HandlerFunc { return s.handleContainerStats }},
	"models":      {method: "GET", path: "/v1/models", handler: func(s *Server) http.HandlerFunc { return s.handleListModels }},
	"start":       {method: "POST", path: "/start", handler: func(s *Server) http.HandlerFunc { return s.handleStartBackend }},
	"stop":        {method: "POST", path: "/stop", handler: func(s *Server) http.HandlerFunc { return s.handleStopBackend }},
	"restart":     {method: "POST", path: "/restart", handler: func(s *Server) http.HandlerFunc { return s.handleRestart }},
	"clean":       {method: "POST", path: "/clean", handler: func(s *Server) http.HandlerFunc { return s.handleClean }},
	"pull":        {method: "POST", path: "/pull", handler: func(s *Server) http.HandlerFunc { return s.handlePull }, async: true},
	"skills.run":  {method: "POST", path: "/api/skills/run", handler: func(s *Server) http.HandlerFunc { return s.handleSkillRun }, async: true},
	"mcp.call":    {method: "POST", path: "/api/mcp/{server}/call", handler: func(s *Server) http.HandlerFunc { return s.handleMCPCall }, pathValue: "server"},
	"mcp.servers": {method: "GET", path: "/api/mcp/servers", handler: func(s *Server) http.HandlerFunc { return s.handleMCPServers }},
}

// rpcCleanup is the `cleanup` op: the envelope's Arg picks the route, as the
// URL path does over HTTPS (/cleanup/images, /cleanup/logs).
var rpcCleanup = map[string]struct {
	path    string
	handler func(*Server) http.HandlerFunc
}{
	"images": {"/cleanup/images", func(s *Server) http.HandlerFunc { return s.handleCleanupImages }},
	"logs":   {"/cleanup/logs", func(s *Server) http.HandlerFunc { return s.handleCleanupLogs }},
}

// RPCOp implements ctrlrpc.Dispatcher.
func (s *Server) RPCOp(op string) (known, async bool) {
	switch op {
	case "cleanup", "logs":
		return true, false
	}
	o, ok := rpcOps[op]
	return ok, o.async
}

// resolveRPC picks method, handler and the path value for a call.
func (s *Server) resolveRPC(c ctrlrpc.Call) (method string, h http.HandlerFunc, pv, pvName string, ok bool) {
	switch c.Op {
	case "cleanup":
		r, found := rpcCleanup[c.Arg]
		if !found {
			return "", nil, "", "", false
		}
		return "POST", r.handler(s), "", "", true
	case "logs":
		// GET /logs/{container}; no container = GET /logs/containers.
		if c.Arg == "" {
			return "GET", s.handleListLogContainers, "", "", true
		}
		return "GET", s.handleContainerLogs, c.Arg, "container", true
	}
	o, found := rpcOps[c.Op]
	if !found {
		return "", nil, "", "", false
	}
	return o.method, o.handler(s), c.Arg, o.pathValue, true
}

// RPCDo implements ctrlrpc.Dispatcher: it runs the HTTP handler for the op
// against an in-memory request and returns what the handler wrote.
func (s *Server) RPCDo(ctx context.Context, c ctrlrpc.Call) (res ctrlrpc.Result) {
	method, h, pv, pvName, ok := s.resolveRPC(c)
	if !ok {
		return ctrlrpc.Result{Status: http.StatusBadRequest, ContentType: "application/json",
			Body: []byte(`{"detail":"unsupported argument for control op ` + c.Op + `"}`)}
	}
	target := "http://control.bus/"
	if c.Query != "" {
		target += "?" + c.Query
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(c.Body))
	if err != nil {
		return ctrlrpc.Result{Status: http.StatusBadRequest, ContentType: "application/json", Body: []byte(`{"detail":"bad control request"}`)}
	}
	if pvName != "" {
		req.SetPathValue(pvName, pv)
	}
	req.RemoteAddr = "bus"
	if len(c.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := &rpcRecorder{header: http.Header{}, status: http.StatusOK}
	// net/http recovers a handler panic into a dropped connection; here the
	// handler runs on the agent's own goroutine, so a panic must become a 500
	// and not the end of the process.
	defer func() {
		if p := recover(); p != nil {
			slog.Error("control op panicked", "op", c.Op, "panic", p)
			res = ctrlrpc.Result{Status: http.StatusInternalServerError, ContentType: "application/json",
				Body: []byte(`{"detail":"control op failed on the node"}`)}
		}
	}()
	h(rec, req)
	ct := rec.header.Get("Content-Type")
	if ct == "" && rec.body.Len() > 0 {
		ct = strings.TrimSpace(http.DetectContentType(rec.body.Bytes()))
	}
	return ctrlrpc.Result{Status: rec.status, ContentType: ct, Body: rec.body.Bytes()}
}

// rpcRecorder is the minimal http.ResponseWriter RPCDo hands a handler.
type rpcRecorder struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
}

func (r *rpcRecorder) Header() http.Header { return r.header }
func (r *rpcRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
}
func (r *rpcRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}
