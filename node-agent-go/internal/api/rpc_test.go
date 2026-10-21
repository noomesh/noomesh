// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlrpc"
	"github.com/noomesh/noomesh/node-agent-go/internal/hardware"
	"github.com/noomesh/noomesh/node-agent-go/internal/metrics"
)

func rpcServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{NodeID: "test-node", NodeAgentToken: "test-token", TLSCA: "ca.pem"}
	gpu := hardware.NewGPUDetector(nil, "http")
	return NewServer(cfg, nil, gpu, metrics.NewCollector(gpu))
}

// rpcCase is one op with the HTTP request that is its twin.
type rpcCase struct {
	op, arg, query, body string
	method, path         string
}

var rpcCases = []rpcCase{
	{op: "health", method: "GET", path: "/health"},
	{op: "gpu", method: "GET", path: "/gpu"},
	{op: "stats", method: "GET", path: "/stats/containers"},
	{op: "start", method: "POST", path: "/start", body: `{"backend":"vllm","model":"m"}`},
	{op: "start", method: "POST", path: "/start", body: `not json`},
	{op: "stop", method: "POST", path: "/stop", body: `{"backend":"vllm"}`},
	{op: "clean", method: "POST", path: "/clean", body: `{"deep":true}`},
	{op: "pull", method: "POST", path: "/pull", body: `{"kind":"image","image":"x"}`},
	{op: "pull", method: "POST", path: "/pull", body: `{"kind":"binary"}`},
	{op: "pull", method: "POST", path: "/pull", body: `{"kind":"nope"}`},
	{op: "cleanup", arg: "images", method: "POST", path: "/cleanup/images"},
	{op: "cleanup", arg: "logs", method: "POST", path: "/cleanup/logs"},
	{op: "logs", method: "GET", path: "/logs/containers"},
	{op: "logs", arg: "noo-gateway", query: "tail=5", method: "GET", path: "/logs/noo-gateway?tail=5"},
	{op: "skills.run", method: "POST", path: "/api/skills/run", body: `{}`},
	{op: "mcp.servers", method: "GET", path: "/api/mcp/servers"},
	{op: "mcp.call", arg: "srv", method: "POST", path: "/api/mcp/srv/call", body: `{"tool":"t"}`},
}

// viaHTTP sends the twin request through the REAL route table (middleware
// included) as the controller: its leaf, no bearer.
func viaHTTP(t *testing.T, s *Server, c rpcCase) (code int, ctype string, body []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			code = -1
		}
	}()
	r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{testLeaf(t, "host8", "Mesh Cluster Gateway")}}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, r)
	return rec.Code, rec.Header().Get("Content-Type"), rec.Body.Bytes()
}

func viaBus(s *Server, c rpcCase) (code int, ctype string, body []byte) {
	defer func() {
		if r := recover(); r != nil {
			code = -1
		}
	}()
	res := s.RPCDo(auth.WithBusController(context.Background()), ctrlrpc.Call{Op: c.op, Arg: c.arg, Query: c.query, Body: []byte(c.body)})
	return res.Status, res.ContentType, res.Body
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

// Every op answers exactly what the HTTPS route answers: same status, same
// content type, same body. The twin goes through the real mux with the
// controller's leaf, so this also proves the bus path skips nothing that
// changes the result.
func TestEveryOpAnswersWhatItsHTTPSRouteAnswers(t *testing.T) {
	s := rpcServer(t)
	for _, c := range rpcCases {
		hc, hct, hb := viaHTTP(t, s, c)
		bc, bct, bb := viaBus(s, c)
		if hc == -1 || bc == -1 {
			t.Errorf("%s %s: a handler panicked (http=%d bus=%d)", c.op, c.arg, hc, bc)
			continue
		}
		if hc != bc {
			t.Errorf("%s %q: HTTPS status %d, bus status %d", c.op, c.arg, hc, bc)
		}
		if hct != bct {
			t.Errorf("%s %q: HTTPS content type %q, bus %q", c.op, c.arg, hct, bct)
		}
		if c.op == "health" || c.op == "gpu" {
			// The detail fields (disk usage) can move between two reads; the
			// shape must not: the bus call is the controller, so it gets the
			// controller's detail, exactly like the leaf over HTTPS.
			var hm, bm map[string]any
			_ = json.Unmarshal(hb, &hm)
			_ = json.Unmarshal(bb, &bm)
			for k := range hm {
				if _, ok := bm[k]; !ok {
					t.Errorf("health: bus reply lacks %q that HTTPS has", k)
				}
			}
			if c.op == "gpu" {
				continue
			}
			if bm["node_id"] != "test-node" {
				t.Errorf("health over the bus must carry the controller's detail, got %v", bm)
			}
			continue
		}
		if !sameJSON(hb, bb) {
			t.Errorf("%s %q: HTTPS body %s, bus body %s", c.op, c.arg, hb, bb)
		}
	}
}

// Each op names a route this server registers, with the method it states,
// behind the controller gate (everything but the public /health).
func TestRPCOpsMatchTheControllerRoutes(t *testing.T) {
	s := rpcServer(t)
	for op, o := range rpcOps {
		path := strings.NewReplacer("{server}", "x", "{container}", "x").Replace(o.path)
		req := httptest.NewRequest(o.method, path, nil)
		if _, pattern := s.mux.Handler(req); pattern != o.method+" "+o.path {
			t.Errorf("op %s: no route %s %s (mux matched %q)", op, o.method, o.path, pattern)
		}
		if op == "health" {
			continue
		}
		// No credentials at all: the HTTPS route refuses it, which is what
		// makes it a control route whose twin needs the envelope gate.
		rec := httptest.NewRecorder()
		func() {
			defer func() { _ = recover() }()
			s.mux.ServeHTTP(rec, httptest.NewRequest(o.method, path, nil))
		}()
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Errorf("op %s: %s %s answered %d with no credentials; it is not behind the controller gate", op, o.method, path, rec.Code)
		}
	}
	for arg, r := range rpcCleanup {
		req := httptest.NewRequest("POST", r.path, nil)
		if _, pattern := s.mux.Handler(req); pattern != "POST "+r.path {
			t.Errorf("cleanup %s: no route %s", arg, r.path)
		}
	}
}

// A handler that panics must not take the agent down: over HTTPS net/http
// recovers it; on the bus RPCDo does.
func TestAPanickingHandlerBecomesA500(t *testing.T) {
	s := rpcServer(t)
	// models panics without a Docker client in this harness (the HTTPS route
	// panics the same way); the bus must answer 500, not die.
	res := s.RPCDo(auth.WithBusController(context.Background()), ctrlrpc.Call{Op: "models"})
	if res.Status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", res.Status)
	}
}

func TestEveryDispatcherOpIsKnownAndAsyncOnlyWhereDeclared(t *testing.T) {
	s := rpcServer(t)
	for _, op := range []string{"health", "gpu", "stats", "models", "start", "stop", "restart", "clean", "cleanup", "logs", "mcp.call", "mcp.servers"} {
		if known, async := s.RPCOp(op); !known || async {
			t.Errorf("%s: known=%v async=%v, want known sync", op, known, async)
		}
	}
	for _, op := range []string{"pull", "skills.run"} {
		if known, async := s.RPCOp(op); !known || !async {
			t.Errorf("%s: known=%v async=%v, want known async (acked at once, result on the event stream)", op, known, async)
		}
	}
	if known, _ := s.RPCOp("device.camera"); known {
		t.Error("device blobs are bulk and stay on HTTPS in phase 1")
	}
	if known, _ := s.RPCOp("tools"); known {
		t.Error("this agent has no /tools route, so there is no op for it")
	}
}

func TestAnUnknownCleanupKindIsRefusedNotGuessed(t *testing.T) {
	s := rpcServer(t)
	res := s.RPCDo(auth.WithBusController(context.Background()), ctrlrpc.Call{Op: "cleanup", Arg: "../../etc"})
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status %d", res.Status)
	}
}

func TestHealthOverTheBusWithoutTheMarkIsTheAnonymousShape(t *testing.T) {
	// The bus path is trusted only through ctrlrpc's verified mark. A context
	// without it (a future caller that forgets) gets the public answer.
	s := rpcServer(t)
	res := s.RPCDo(context.Background(), ctrlrpc.Call{Op: "health"})
	var m map[string]any
	_ = json.Unmarshal(res.Body, &m)
	if _, leaked := m["node_id"]; leaked {
		t.Fatalf("unmarked bus call got controller detail: %v", m)
	}
}
