// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package mcpsrv supervises the EXTERNAL MCP servers placed on this node
// and speaks MCP to them on the gateway's behalf.
//
// Two transports, one client shape:
//
//   - stdio: the server is a child process of the agent (uvx, npx, a
//     binary). JSON-RPC rides newline-delimited stdin/stdout. The command
//     comes from the registry the controller holds; the agent runs it as
//     itself, never as root, with `$NAME` env references resolved from the
//     credential file the node was delivered.
//   - streamable_http: the server is somewhere the node can dial; each
//     request is one POST. The response may be a JSON object or a single
//     SSE frame; both are read.
//
// The client speaks the LEGACY handshake (initialize → tools/list) on
// purpose: every server in the wild answers it, and a 2026-07-28 server
// that is dual-era (ours is) answers it too. Nothing here is a general MCP
// SDK — it is the four calls the node needs: initialize, tools/list,
// tools/call, and the notification that closes the handshake.
package mcpsrv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Tool is one entry of a server's catalog, in the shape the gateway records.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Client is what the supervisor needs from a transport.
type Client interface {
	// Initialize performs the legacy handshake. Idempotent.
	Initialize(ctx context.Context) error
	ListTools(ctx context.Context) ([]Tool, error)
	CallTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error)
	Close() error
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type rpcResponse struct {
	ID     *int64          `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc %d: %s", e.Code, e.Message) }

// parseTools reads a tools/list result into the recorded shape. The MCP
// field is `inputSchema`; the registry column is `input_schema`.
func parseTools(result json.RawMessage) ([]Tool, error) {
	var body struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(result, &body); err != nil {
		return nil, fmt.Errorf("tools/list result: %w", err)
	}
	out := make([]Tool, 0, len(body.Tools))
	for _, t := range body.Tools {
		if strings.TrimSpace(t.Name) == "" {
			continue
		}
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		out = append(out, Tool{Name: t.Name, Description: t.Description, InputSchema: schema})
	}
	return out, nil
}

// ───────────────────────── stdio transport ─────────────────────────

// pipeClient is the JSON-RPC core over a byte stream pair. The stdio
// client wraps a child process around it; the tests wrap io.Pipes.
type pipeClient struct {
	w      io.Writer
	wmu    sync.Mutex
	nextID atomic.Int64
	// pending maps a request id to the channel its response lands on.
	pmu     sync.Mutex
	pending map[int64]chan rpcResponse
	done    chan struct{}
	readErr error
	initOK  atomic.Bool
}

func newPipeClient(r io.Reader, w io.Writer) *pipeClient {
	c := &pipeClient{w: w, pending: map[int64]chan rpcResponse{}, done: make(chan struct{})}
	go c.readLoop(r)
	return c
}

// readLoop demultiplexes responses by id. A line that is not a response
// (a server notification, a log line the child wrote to stdout) is
// ignored rather than fatal — stdout noise is common in stdio servers.
func (c *pipeClient) readLoop(r io.Reader) {
	defer close(c.done)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var resp rpcResponse
		if err := json.Unmarshal(line, &resp); err != nil || resp.ID == nil {
			continue
		}
		c.pmu.Lock()
		ch, ok := c.pending[*resp.ID]
		if ok {
			delete(c.pending, *resp.ID)
		}
		c.pmu.Unlock()
		if ok {
			ch <- resp
		}
	}
	c.readErr = sc.Err()
	// Fail every waiter: the stream is gone.
	c.pmu.Lock()
	for id, ch := range c.pending {
		delete(c.pending, id)
		close(ch)
	}
	c.pmu.Unlock()
}

func (c *pipeClient) write(msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.w.Write(append(b, '\n'))
	return err
}

func (c *pipeClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	ch := make(chan rpcResponse, 1)
	c.pmu.Lock()
	c.pending[id] = ch
	c.pmu.Unlock()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	if err := c.write(rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: raw}); err != nil {
		c.pmu.Lock()
		delete(c.pending, id)
		c.pmu.Unlock()
		return nil, err
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errors.New("server closed the stream before answering")
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	case <-ctx.Done():
		c.pmu.Lock()
		delete(c.pending, id)
		c.pmu.Unlock()
		return nil, ctx.Err()
	case <-c.done:
		return nil, errors.New("server stream closed")
	}
}

func (c *pipeClient) notify(method string) error {
	return c.write(rpcRequest{JSONRPC: "2.0", Method: method})
}

func (c *pipeClient) Initialize(ctx context.Context) error {
	if c.initOK.Load() {
		return nil
	}
	_, err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "noo-node-agent", "version": "1"},
	})
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	if err := c.notify("notifications/initialized"); err != nil {
		return err
	}
	c.initOK.Store(true)
	return nil
}

func (c *pipeClient) ListTools(ctx context.Context) ([]Tool, error) {
	if err := c.Initialize(ctx); err != nil {
		return nil, err
	}
	res, err := c.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	return parseTools(res)
}

func (c *pipeClient) CallTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	if err := c.Initialize(ctx); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	return c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
}

// ───────────────────────── http transport ─────────────────────────

// httpClient: one POST per message. No sessions are tracked — a modern
// server has none, and a legacy one that mints an Mcp-Session-Id is
// echoed it back, which is all the legacy transport requires.
type httpClient struct {
	url     string
	headers map[string]string
	http    *http.Client
	nextID  atomic.Int64
	session atomic.Value // string
	initOK  atomic.Bool
}

func newHTTPClient(url string, headers map[string]string, hc *http.Client) *httpClient {
	if hc == nil {
		hc = &http.Client{Timeout: 120 * time.Second}
	}
	c := &httpClient{url: url, headers: headers, http: hc}
	c.session.Store("")
	return c
}

func (c *httpClient) post(ctx context.Context, msg rpcRequest) (*rpcResponse, error) {
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if sid, _ := c.session.Load().(string); sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.session.Store(sid)
	}
	if resp.StatusCode == http.StatusAccepted {
		return nil, nil // a notification
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	payload := body
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		payload = lastSSEData(body)
	}
	var out rpcResponse
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, fmt.Errorf("response is not JSON-RPC: %s", truncate(string(payload), 120))
	}
	return &out, nil
}

// lastSSEData returns the payload of the last `data:` line — the response
// on a stream that carried progress frames before it.
func lastSSEData(body []byte) []byte {
	var last []byte
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if rest, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			rest = bytes.TrimSpace(rest)
			if len(rest) > 0 && rest[0] == '{' {
				last = rest
			}
		}
	}
	return last
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (c *httpClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	resp, err := c.post(ctx, rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: raw})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("server answered a request with 202 (no body)")
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Result, nil
}

func (c *httpClient) Initialize(ctx context.Context) error {
	if c.initOK.Load() {
		return nil
	}
	_, err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "noo-node-agent", "version": "1"},
	})
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	_, _ = c.post(ctx, rpcRequest{JSONRPC: "2.0", Method: "notifications/initialized"})
	c.initOK.Store(true)
	return nil
}

func (c *httpClient) ListTools(ctx context.Context) ([]Tool, error) {
	if err := c.Initialize(ctx); err != nil {
		return nil, err
	}
	res, err := c.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	return parseTools(res)
}

func (c *httpClient) CallTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	if err := c.Initialize(ctx); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	return c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
}

func (c *httpClient) Close() error { return nil }
