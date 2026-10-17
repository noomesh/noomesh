// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// Placement is one external MCP server the controller placed on this node,
// as `desired-config` carries it.
type Placement struct {
	ID           string          `json:"id"`
	Transport    string          `json:"transport"`
	Spec         json.RawMessage `json:"spec"`
	Kind         string          `json:"kind"`
	DesiredState string          `json:"desired_state"`
}

// transportContainer is the node-local transport: a contained server whose
// JSON-RPC rides an attached stdio stream. It replaced "stdio" entirely —
// see container.go and the block where startStdio used to be.
const transportContainer = "container"

type httpSpec struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

// SpecHash fingerprints a placement so a changed spec recreates the
// server and an unchanged one is left alone — the same idea as the
// backend spec-hash label, and for the same reason: churn is an outage.
func SpecHash(p Placement) string {
	h := sha256.New()
	h.Write([]byte(p.ID))
	h.Write([]byte{0})
	h.Write([]byte(p.Transport))
	h.Write([]byte{0})
	h.Write(canonicalJSON(p.Spec))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func canonicalJSON(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v) // encoding/json sorts map keys
	if err != nil {
		return raw
	}
	return b
}

// ResolveRefs turns `$NAME` values into secrets the NODE holds. The registry
// never holds a secret (the gateway refuses literals under a secret-looking
// key); the node resolves the name from an operator-written, node-local file
// — see SecretLookup in admission.go.
//
// It used to resolve from os.Environ(). That made every credential the AGENT
// holds nameable from a controller row: a streamable_http placement with
// `headers: {"X-Api-Key": "$NOO_CLUSTER_SECRET"}` posted the fleet secret to
// whatever URL the placement gave. The registry was designed to hold
// references rather than secrets precisely so that the node would decide
// what a reference means; resolving against the agent's own environment gave
// that decision back to the controller.
//
// A reference with no value is an ERROR, not an empty string — a server
// started with an empty token fails somewhere later and less legibly.
func ResolveRefs(m map[string]string, lookup func(string) (string, bool)) (map[string]string, error) {
	out := make(map[string]string, len(m))
	var missing []string
	for k, v := range m {
		if name, ok := strings.CutPrefix(v, "$"); ok && isIdent(name) {
			val, found := lookup(name)
			if !found || val == "" {
				missing = append(missing, name)
				continue
			}
			out[k] = val
			continue
		}
		out[k] = v
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf(
			"unresolved secret reference(s) %v — write them as KEY=VALUE in this node's MCP "+
				"secrets file (%s by default, or %s) and restart the agent. They are "+
				"deliberately NOT read from the agent's own environment: that would let a "+
				"placement name the fleet secret",
			missing, mcpSecretsDefaultPath, SecretsFileEnv)
	}
	return out, nil
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		alpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
		digit := r >= '0' && r <= '9'
		if !(alpha || (digit && i > 0)) {
			return false
		}
	}
	return true
}

// ───────────────────────── live server ─────────────────────────

type server struct {
	placement Placement
	hash      string
	client    Client
	tools     []Tool
	lastErr   string
	startedAt time.Time
}

// bufio_tail keeps the last few KB of stderr for the log line that says
// WHY a server died — without it a crashed stdio server is a silent hole.
type bufio_tail struct {
	mu  sync.Mutex
	buf []byte
}

func (t *bufio_tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > 4096 {
		t.buf = t.buf[len(t.buf)-4096:]
	}
	return len(p), nil
}

func (t *bufio_tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// The plain-exec lane that used to live here — `startStdio`, `exec.Command`,
// Setpgid/Pdeathsig — is GONE, and there is no fallback to it.
//
// It ran the server as `noo-agent`, and `noo-agent` is in the `docker` group,
// so an MCP binary that was compromised upstream could open
// /var/run/docker.sock and be root on the host. That could not be fixed in
// place: dropping the `docker` supplementary group needs CAP_SETGID (the agent
// is deliberately not root) and Go offers no hook between fork and exec in
// which to call prctl(PR_SET_NO_NEW_PRIVS). A container gets both for free, so
// the transport moved rather than the flags — see container.go, and
// docker.SkillFloorHostConfig for the floor it shares with `/api/skills/run`.

func dialHTTP(p Placement, lookup func(string) (string, bool), hc *http.Client) (Client, error) {
	var spec httpSpec
	if err := json.Unmarshal(p.Spec, &spec); err != nil {
		return nil, fmt.Errorf("spec: %w", err)
	}
	if !strings.HasPrefix(spec.URL, "http://") && !strings.HasPrefix(spec.URL, "https://") {
		return nil, errors.New("spec.url is not http(s)")
	}
	headers, err := ResolveRefs(spec.Headers, lookup)
	if err != nil {
		return nil, err
	}
	return newHTTPClient(spec.URL, headers, hc), nil
}

// ───────────────────────── supervisor ─────────────────────────

// Supervisor owns the live servers on this node and reports their
// catalogs to the controller. `Apply` is called from the reconcile tick
// with the placements the controller asked for; anything running that is
// no longer asked for, or whose spec changed, is stopped (and restarted
// when the spec changed). Discovery runs after every start and on every
// tick, so a server that came up late is caught on the next pass.
type Supervisor struct {
	cfg  *config.Config
	http *http.Client
	// runtime is how a node-local server is contained. nil means this agent
	// has no Docker, and then a node-local server does not start at all —
	// startContainer says so by name. There is no un-contained fallback.
	runtime ContainerRuntime
	lookup  func(string) (string, bool)
	mu      sync.Mutex
	live    map[string]*server
}

func New(cfg *config.Config, hc *http.Client, rt ContainerRuntime) *Supervisor {
	// A nil *docker.Client arrives here as a non-nil interface holding a nil
	// pointer, which would defeat startContainer's nil check and panic on the
	// first placement instead of refusing it.
	if c, ok := rt.(*docker.Client); ok && c == nil {
		rt = nil
	}
	return &Supervisor{cfg: cfg, http: hc, runtime: rt, lookup: SecretLookup, live: map[string]*server{}}
}

// Status is what /health and the logs show per server.
type Status struct {
	ID        string `json:"id"`
	Transport string `json:"transport"`
	Tools     int    `json:"tools"`
	Error     string `json:"error,omitempty"`
	Since     string `json:"since,omitempty"`
}

func (s *Supervisor) Statuses() []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Status, 0, len(s.live))
	for _, srv := range s.live {
		st := Status{ID: srv.placement.ID, Transport: srv.placement.Transport, Tools: len(srv.tools), Error: srv.lastErr}
		if !srv.startedAt.IsZero() {
			st.Since = srv.startedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Apply converges the live set toward `want` and (re)discovers catalogs.
//
// `want` is the CONTROLLER's desired state. Its stdio entries are refused
// (see resolveWanted); its streamable_http entries are honoured, because
// those are a URL this node dials out to, not a process it executes. The
// stdio servers that DO run here come from the node's own file.
func (s *Supervisor) Apply(ctx context.Context, want []Placement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := s.resolveWanted(want)
	// Stop what is no longer wanted, or whose spec changed.
	for id, srv := range s.live {
		p, ok := wanted[id]
		if !ok || SpecHash(p) != srv.hash {
			slog.Info("mcpsrv.stopping", "server", id, "reason", map[bool]string{true: "spec changed", false: "unplaced or stopped"}[ok])
			if srv.client != nil {
				_ = srv.client.Close()
			}
			delete(s.live, id)
		}
	}
	// Start what is wanted and not live; discover everything live.
	for id, p := range wanted {
		srv, ok := s.live[id]
		if !ok {
			srv = &server{placement: p, hash: SpecHash(p)}
			s.live[id] = srv
			if err := s.start(ctx, srv); err != nil {
				srv.lastErr = err.Error()
				slog.Warn("mcpsrv.start_failed", "server", id, "transport", p.Transport, "error", err)
				continue
			}
			srv.startedAt = time.Now()
			slog.Info("mcpsrv.started", "server", id, "transport", p.Transport)
		}
		if srv.client == nil {
			// A previous start failed; try again this tick.
			if err := s.start(ctx, srv); err != nil {
				srv.lastErr = err.Error()
				continue
			}
			srv.startedAt = time.Now()
		}
		s.discover(ctx, srv)
	}
}

// resolveWanted merges what the controller asked for with what this node
// declares, and REFUSES rather than silently skips.
//
// The refusal is the point. `noo_mcp_placements` records intent and
// nothing else, so before the refusals channel existed a node that
// declined a placement looked from the controller exactly like a node that
// had never been asked — an operator would have chased "my MCP server is
// not starting" through the gateway logs and found nothing. Every branch
// here that drops a placement says so, on the heartbeat, with the fix.
func (s *Supervisor) resolveWanted(want []Placement) map[string]Placement {
	wanted := map[string]Placement{}

	// 1. This node's OWN stdio servers, from a root-owned file the
	// controller cannot write. These win every collision below.
	local, localRefusals, err := LoadLocalStdio()
	if err != nil {
		slog.Error("mcpsrv.local_file_unusable", "path", LocalStdioPath(), "error", err)
		refusals.Record("mcp_local_file", LocalStdioPath(), err.Error())
	} else {
		refusals.Clear("mcp_local_file", LocalStdioPath())
	}
	for id, why := range localRefusals {
		slog.Error("mcpsrv.local_entry_refused", "server", id, "error", why)
		refusals.Record("mcp_local_server", id, why)
	}
	declared := map[string]bool{}
	for _, e := range local {
		declared[e.ID] = true
		wanted[e.ID] = e.Placement()
		refusals.Clear("mcp_local_server", e.ID)
	}

	// 2. The controller's placements.
	for _, p := range want {
		if strings.EqualFold(p.Transport, "stdio") {
			// THE wall. A stdio placement names a command, its arguments,
			// its working directory and its environment — all from a
			// controller database row — and the agent used to exec it as a
			// user in the docker group. That made "place an MCP server" a
			// remote-code-execution verb against every node in the fleet.
			//
			// There is no validation that fixes this, because the problem
			// is not the shape of the row: it is that the row is written by
			// the side whose compromise this wall exists to contain.
			slog.Error("mcpsrv.controller_stdio_refused", "server", p.ID)
			refusals.Record("mcp_server", p.ID, fmt.Sprintf(
				"the controller may not place a stdio MCP server: its spec is a command this "+
					"node would execute. Declare it in %s on this node instead (root-owned; "+
					"see docs/security/node-agent.md), or register the server as "+
					"streamable_http and give this node a URL to dial",
				LocalStdioPath()))
			continue
		}
		if declared[p.ID] {
			// A controller row and a node-local server with the same id.
			// The node's own file wins — it is the more trusted source —
			// but the operator hears about the clash rather than wondering
			// why their registry row has no effect.
			slog.Warn("mcpsrv.controller_placement_shadowed", "server", p.ID)
			refusals.Record("mcp_server", p.ID, fmt.Sprintf(
				"this node declares its own MCP server with this id in %s, which wins; "+
					"rename one of them", LocalStdioPath()))
			continue
		}
		refusals.Clear("mcp_server", p.ID)
		if p.DesiredState == "" || p.DesiredState == "running" {
			wanted[p.ID] = p
		}
	}
	return wanted
}

func (s *Supervisor) start(ctx context.Context, srv *server) error {
	switch srv.placement.Transport {
	case transportContainer:
		c, err := startContainer(ctx, s.runtime, srv.placement, s.lookup)
		if err != nil {
			return err
		}
		srv.client = c
	case "stdio":
		// Unreachable: the controller's stdio placements are refused in
		// resolveWanted, and the node's own file renders `container`. Kept as
		// a NAMED refusal rather than falling into the default, because the
		// word "stdio" in a spec now means "an uncontained process", and the
		// operator reading the message needs to know that is the thing that
		// is refused.
		return fmt.Errorf(
			"transport %q no longer runs a process on this node: a node-local MCP server "+
				"runs in a container under the skills sandbox floor. Add an `image` to its "+
				"entry in %s", srv.placement.Transport, LocalStdioPath())
	case "streamable_http":
		c, err := dialHTTP(srv.placement, s.lookup, s.http)
		if err != nil {
			return err
		}
		srv.client = c
	default:
		return fmt.Errorf("transport %q is not container or streamable_http", srv.placement.Transport)
	}
	return nil
}

func (s *Supervisor) discover(ctx context.Context, srv *server) {
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tools, err := srv.client.ListTools(dctx)
	if err != nil {
		srv.lastErr = err.Error()
		detail := ""
		if sc, ok := srv.client.(*containerClient); ok {
			detail = truncate(strings.TrimSpace(sc.stderr.String()), 300)
		}
		slog.Warn("mcpsrv.discover_failed", "server", srv.placement.ID, "error", err, "stderr", detail)
		// A stdio server that died takes its client with it: drop it so
		// the next tick restarts rather than talking to a corpse.
		if sc, ok := srv.client.(*containerClient); ok {
			select {
			case <-sc.done:
				_ = sc.Close()
				srv.client = nil
			default:
			}
		}
		return
	}
	srv.lastErr = ""
	changed := !sameTools(srv.tools, tools)
	srv.tools = tools
	if changed {
		if err := s.report(ctx, srv.placement.ID, tools); err != nil {
			slog.Warn("mcpsrv.report_failed", "server", srv.placement.ID, "error", err)
		} else {
			slog.Info("mcpsrv.catalog_reported", "server", srv.placement.ID, "tools", len(tools))
		}
	}
}

func sameTools(a, b []Tool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Description != b[i].Description || string(a[i].InputSchema) != string(b[i].InputSchema) {
			return false
		}
	}
	return true
}

// report writes the catalog to the controller: POST
// /api/cluster/nodes/{self}/mcp/{server}/tools — a node-rail route, so the
// token names this node and the gateway checks the placement is ours.
func (s *Supervisor) report(ctx context.Context, id string, tools []Tool) error {
	if s.cfg == nil || s.cfg.ControllerURL == "" {
		return errors.New("no controller URL")
	}
	// The report carries the fleet bearer, which the gateway accepts only
	// with this node's leaf. A nil client would be http.DefaultClient (no
	// leaf), so refuse instead of sending a token that cannot identify us.
	if s.http == nil {
		return errors.New("no controller client: the supervisor was built without the agent's mTLS client")
	}
	body, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/cluster/nodes/%s/mcp/%s/tools", strings.TrimRight(s.cfg.ControllerURL, "/"), s.cfg.NodeID, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.ClusterSecret != "" {
		auth.SetClusterAuth(req, s.cfg.NodeID, s.cfg.ClusterSecret)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// Call runs one tool on a live server — the node-side half of the bridge
// (phase C calls this through POST /api/mcp/{server}/call).
func (s *Supervisor) Call(ctx context.Context, id, tool string, args json.RawMessage) (json.RawMessage, error) {
	s.mu.Lock()
	srv, ok := s.live[id]
	var client Client
	if ok {
		client = srv.client
	}
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no MCP server %q is placed on this node", id)
	}
	if client == nil {
		return nil, fmt.Errorf("MCP server %q is not running: %s", id, srv.lastErr)
	}
	return client.CallTool(ctx, tool, args)
}

// Close stops every live server (agent shutdown).
func (s *Supervisor) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, srv := range s.live {
		if srv.client != nil {
			_ = srv.client.Close()
		}
		delete(s.live, id)
	}
}
