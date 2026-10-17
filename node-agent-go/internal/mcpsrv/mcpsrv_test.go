// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"time"
)

// fakeServer answers the legacy handshake and a two-tool catalog over a
// newline-delimited stream — what a stdio server looks like from the
// agent's side, without a process.
func fakeServer(t *testing.T, r io.Reader, w io.Writer) {
	t.Helper()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		if req.ID == nil {
			continue // notification
		}
		var result string
		switch req.Method {
		case "initialize":
			result = `{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"0"}}`
		case "tools/list":
			result = `{"tools":[{"name":"echo","description":"Echo","inputSchema":{"type":"object","properties":{"s":{"type":"string"}}}},{"name":"noschema","description":""}]}`
		case "tools/call":
			quoted, _ := json.Marshal(string(req.Params))
			result = `{"content":[{"type":"text","text":` + string(quoted) + `}],"isError":false}`
		default:
			w.Write([]byte(`{"jsonrpc":"2.0","id":` + itoa(*req.ID) + `,"error":{"code":-32601,"message":"nope"}}` + "\n"))
			continue
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":` + itoa(*req.ID) + `,"result":` + result + `}` + "\n"))
	}
}

func itoa(i int64) string   { return json.Number(strings.TrimSpace(string(mustJSON(i)))).String() }
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestPipeClient_HandshakeListAndCall(t *testing.T) {
	c2s := newPipe()
	s2c := newPipe()
	go fakeServer(t, c2s.r, s2c.w)
	c := newPipeClient(s2c.r, c2s.w)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tools, err := c.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 2 || tools[0].Name != "echo" {
		t.Fatalf("tools = %+v", tools)
	}
	// A tool with no inputSchema gets the minimal object schema, never nil.
	if string(tools[1].InputSchema) != `{"type":"object"}` {
		t.Fatalf("default schema = %s", tools[1].InputSchema)
	}
	res, err := c.CallTool(ctx, "echo", json.RawMessage(`{"s":"hi"}`))
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !strings.Contains(string(res), `"isError":false`) {
		t.Fatalf("result = %s", res)
	}
	// An unknown method surfaces the server's error, not a hang.
	if _, err := c.call(ctx, "nope/x", nil); err == nil || !strings.Contains(err.Error(), "-32601") {
		t.Fatalf("expected -32601, got %v", err)
	}
}

// Noise on stdout (a server that logs to stdout) must not break framing.
func TestPipeClient_IgnoresNonJSONLines(t *testing.T) {
	c2s := newPipe()
	s2c := newPipe()
	go func() {
		s2c.w.Write([]byte("starting up...\n[warn] something\n"))
		fakeServer(t, c2s.r, s2c.w)
	}()
	c := newPipeClient(s2c.r, c2s.w)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Initialize(ctx); err != nil {
		t.Fatalf("initialize through noise: %v", err)
	}
}

func TestPipeClient_ServerCloseFailsWaiters(t *testing.T) {
	c2s := newPipe()
	s2c := newPipe()
	c := newPipeClient(s2c.r, c2s.w)
	go func() {
		// Read one request, then hang up without answering.
		bufio.NewScanner(c2s.r).Scan()
		s2c.w.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Initialize(ctx); err == nil {
		t.Fatal("expected an error when the server closes the stream")
	}
}

func TestHTTPClient_JSONAndSSEResponses(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req rpcRequest
		json.NewDecoder(r.Body).Decode(&req)
		if r.Header.Get("X-Test") != "resolved" {
			http.Error(w, "missing header", 401)
			return
		}
		if req.ID == nil {
			w.WriteHeader(202)
			return
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "s1")
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"jsonrpc":"2.0","id":` + itoa(*req.ID) + `,"result":{"protocolVersion":"2024-11-05"}}`))
		case "tools/list":
			if r.Header.Get("Mcp-Session-Id") != "s1" {
				http.Error(w, "no session", 400)
				return
			}
			// SSE-framed, with a progress frame before the answer.
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"))
			w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":" + itoa(*req.ID) + ",\"result\":{\"tools\":[{\"name\":\"t\",\"description\":\"d\",\"inputSchema\":{\"type\":\"object\"}}]}}\n\n"))
		}
	}))
	defer srv.Close()
	c := newHTTPClient(srv.URL, map[string]string{"X-Test": "resolved"}, srv.Client())
	ctx := context.Background()
	tools, err := c.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "t" {
		t.Fatalf("tools = %+v", tools)
	}
	if calls < 3 {
		t.Fatalf("expected initialize + initialized + list, got %d calls", calls)
	}
}

func TestResolveRefs(t *testing.T) {
	env := map[string]string{"GITHUB_TOKEN": "$GITHUB_TOKEN", "HOME": "/srv", "LITERAL_DOLLAR": "$5 fee"}
	got, err := ResolveRefs(env, func(k string) (string, bool) {
		if k == "GITHUB_TOKEN" {
			return "ghp_real", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["GITHUB_TOKEN"] != "ghp_real" || got["HOME"] != "/srv" || got["LITERAL_DOLLAR"] != "$5 fee" {
		t.Fatalf("got %v", got)
	}
	// A reference the node cannot resolve is an error naming it — never an empty value.
	_, err = ResolveRefs(map[string]string{"API_KEY": "$MISSING_KEY"}, func(string) (string, bool) { return "", false })
	if err == nil || !strings.Contains(err.Error(), "MISSING_KEY") {
		t.Fatalf("expected an error naming MISSING_KEY, got %v", err)
	}
}

func TestSpecHash_StableAndOrderIndependent(t *testing.T) {
	a := Placement{ID: "git", Transport: "stdio", Spec: json.RawMessage(`{"command":"uvx","args":["x"],"env":{"A":"1","B":"2"}}`)}
	b := Placement{ID: "git", Transport: "stdio", Spec: json.RawMessage(`{"env":{"B":"2","A":"1"},"args":["x"],"command":"uvx"}`)}
	if SpecHash(a) != SpecHash(b) {
		t.Fatal("key order must not change the hash")
	}
	c := a
	c.Spec = json.RawMessage(`{"command":"uvx","args":["y"]}`)
	if SpecHash(a) == SpecHash(c) {
		t.Fatal("a changed spec must change the hash")
	}
}

// Apply with a real child process. The server comes from the NODE's own
// file — the controller cannot supply one any more — and the point is
// lifecycle: an unresolvable secret refuses to start (and says which), and
// a server the node stops declaring is stopped.
func TestSupervisor_ApplyLifecycle(t *testing.T) {
	// A root-owned binary that reads stdin forever, which is all this test
	// needs: it never gets as far as starting, because its secret is
	// unresolvable.
	bin := rootOwnedBinary(t)
	localFile(t, `[{"id":"needs-secret","image":"`+testImage+`","command":"`+bin+`","env":{"TOKEN":"$NOPE"}}]`)

	s := New(nil, nil, nil)
	s.lookup = func(string) (string, bool) { return "", false }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.Apply(ctx, nil)
	st := s.Statuses()
	if len(st) != 1 || !strings.Contains(st[0].Error, "NOPE") {
		t.Fatalf("statuses = %+v", st)
	}

	// The node stops declaring it.
	localFile(t, `[]`)
	s.Apply(ctx, nil)
	if len(s.Statuses()) != 0 {
		t.Fatalf("an undeclared server must be dropped: %+v", s.Statuses())
	}
	if _, err := s.Call(ctx, "needs-secret", "x", nil); err == nil {
		t.Fatal("call on a dropped server must fail")
	}
}

// ── helpers ──

type pipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newPipe() pipe { r, w := io.Pipe(); return pipe{r: r, w: w} }

// A supervisor without the agent's mTLS client must not report: the report
// carries the fleet bearer, and the default client has no node leaf.
func TestReportRefusesWithoutTheAgentsClient(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	s := &Supervisor{cfg: &config.Config{ControllerURL: srv.URL, NodeID: "n1", ClusterSecret: "s"}}
	err := s.report(context.Background(), "srv", nil)
	if err == nil || !strings.Contains(err.Error(), "no controller client") {
		t.Fatalf("want a no-controller-client error, got %v", err)
	}
	if hit {
		t.Fatal("a request left without the node's client")
	}
}
