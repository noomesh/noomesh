// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package messaging provides NATS JetStream integration for event publishing,
// job dispatch subscription, mesh discovery, and gossip.
package messaging

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/logship"
)

// Connection state names reported by Status. They are a closed set — the
// gateway and the /health consumers switch on these strings.
const (
	// StateConnecting — the client has never completed a connection yet.
	StateConnecting = "connecting"
	// StateConnected — the bus is live and subscriptions are bound.
	StateConnected = "connected"
	// StateReconnecting — the link dropped; nats.go is retrying.
	StateReconnecting = "reconnecting"
	// StateClosed — nats.go gave up permanently (e.g. a repeated
	// authorization violation aborts reconnect regardless of
	// MaxReconnects). The watchdog rebuilds the connection from this state.
	StateClosed = "closed"
	// StateUnavailable — no client exists at all. Reported by Status() on a
	// nil *Client so a caller can never mistake "no messaging" for
	// "connected" (honest-status convention).
	StateUnavailable = "unavailable"
)

// watchdogInterval is how often the supervisor re-checks connection health.
const watchdogInterval = 15 * time.Second

// Status is the observable NATS connection state, surfaced on the node
// agent's /health and on every heartbeat POST so the gateway can tell a
// bus-deaf node from a healthy one. A node that keeps heartbeating over
// HTTPS while its NATS client is dead looks perfectly healthy otherwise —
// that is exactly how host9 and host9-sensors stayed "online" for two days
// while every job dispatched to them rotted.
type Status struct {
	State     string `json:"state"`
	Connected bool   `json:"connected"`
	// RFC3339 timestamps; nil (JSON null) means "never happened" — not zero,
	// not now. An unknown must read as unknown.
	LastConnectedAt    *string `json:"last_connected_at"`
	LastDisconnectedAt *string `json:"last_disconnected_at"`
	// Seconds since the link dropped. nil while connected.
	DisconnectedForSec *int64 `json:"disconnected_for_sec"`
	// Successful (re)connections since process start. 1 = connected once and
	// never dropped.
	Connects uint64 `json:"connects"`
	URL      string `json:"url"`
	// The principal this agent AUTHENTICATES AS — the username only, never
	// the password. `role` names which pair it came from:
	// "node" = its own per-principal credential (NATS_NODE_USER),
	// "anonymous" = no credential at all (NOO_NATS_ALLOW_ANONYMOUS).
	// ("shared", the fleet-wide NATS_USER pair, was retired;
	// an older agent may still report it.)
	//
	// Without this the controller cannot tell a node that is DELIBERATELY on
	// the shared pair from one whose per-principal credential never arrived:
	// both report `connected: true` and look identical. On 2026-09-05 that
	// distinction was the whole diagnosis of a fleet-wide gossip outage, and
	// it had to be reconstructed by reading source and correlating which
	// nodes broke.
	//
	// Omitted by agents that predate this, so absence means "not reported" —
	// never "anonymous".
	User string `json:"user,omitempty"`
	Role string `json:"role,omitempty"`
}

// Client wraps a NATS connection with JetStream for the node agent.
//
// The connection is supervised: nats.go reconnects on its own for the
// ordinary cases, and a watchdog goroutine rebuilds the connection outright
// for the one state nats.go can never leave by itself (CLOSED). Every
// successful (re)connection fires the registered reconnect hooks, which is
// how JetStream durables and the mesh responder get re-bound.
type Client struct {
	mu     sync.RWMutex
	nc     *nats.Conn
	js     nats.JetStreamContext
	nodeID string
	url    string
	opts   []nats.Option

	stateMu        sync.Mutex
	state          string
	lastConnected  *time.Time
	lastDisconnect *time.Time
	connects       uint64
	closing        bool
	// The principal presented at connect: username and which pair it came
	// from. Never the password. Guarded by stateMu like the rest of the
	// reported state, because Status() reads it from another goroutine.
	credUser string
	credRole string

	hookMu         sync.Mutex
	reconnectHooks []func()

	stopOnce sync.Once
	stop     chan struct{}
}

// OnReconnect registers a callback fired (in its own goroutine) after the
// NATS connection is (re-)established. JetStream push consumers do NOT
// always survive a server-side stream recreation even though nats.go
// replays plain subscriptions — observed 2026-07-03: host9's agent
// reconnected fine but node_host9_dispatch stayed push_bound=None and jobs
// stranded. Subscribers use this hook to explicitly re-bind their durables.
//
// Hooks must be idempotent: they also fire after a watchdog-driven
// connection rebuild, and on the deferred first connect when the server was
// down at agent startup.
func (c *Client) OnReconnect(f func()) {
	c.hookMu.Lock()
	c.reconnectHooks = append(c.reconnectHooks, f)
	c.hookMu.Unlock()
}

func (c *Client) fireHooks() {
	c.hookMu.Lock()
	hooks := append([]func(){}, c.reconnectHooks...)
	c.hookMu.Unlock()
	for _, h := range hooks {
		go h()
	}
}

// Connect establishes a NATS connection and initializes JetStream.
// TLS is configured automatically when the URL starts with "tls://",
// using NOO_TLS_CA, NOO_TLS_CERT, and NOO_TLS_KEY environment variables.
//
// Connect never fails because the server is down: with RetryOnFailedConnect
// the client is returned in the reconnecting state and keeps trying
// forever. Before that option existed, a node agent that started while the
// controller's NATS was down logged one warning and then ran deaf for the
// rest of its lifetime, heartbeating happily over HTTPS the whole time.
func Connect(url, nodeID string) (*Client, error) {
	c := &Client{
		nodeID: nodeID,
		url:    url,
		state:  StateConnecting,
		stop:   make(chan struct{}),
	}
	opts, err := c.buildOptions()
	if err != nil {
		return nil, err
	}
	c.opts = opts

	nc, err := nats.Connect(url, c.opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	c.mu.Lock()
	c.nc = nc
	c.js = js
	c.mu.Unlock()

	// A synchronous success does NOT fire ReconnectHandler, so record it here.
	// A deferred success (server was down) does fire it.
	if nc.IsConnected() {
		c.markConnected()
	} else {
		slog.Warn("nats not yet connected — retrying in the background", "url", logship.ScrubURLUserinfo(url))
	}

	go c.watchdog()
	return c, nil
}

// buildOptions returns the connection options. Kept separate so a rebuild
// uses exactly the same configuration, and so tests can assert the
// resilience settings without a server.
func (c *Client) buildOptions() ([]nats.Option, error) {
	opts := []nats.Option{
		nats.Name("noo-node-agent-" + c.nodeID),

		// Per-client inbox prefix. The default
		// "_INBOX." is used by every principal on the bus, so no permission
		// rule can grant a node its own replies and nobody else's. The node
		// id is sanitised because a "." in it would turn one token into a
		// subject hierarchy and silently widen whatever rule is written
		// against it.
		nats.CustomInboxPrefix(NodeInboxPrefix(c.nodeID)),

		// Reconnect forever, with jitter so a fleet restarting together does
		// not synchronise its retries onto the controller.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.ReconnectJitter(500*time.Millisecond, 2*time.Second),

		// Keep retrying the FIRST connect too, in the background.
		nats.RetryOnFailedConnect(true),
		nats.Timeout(10 * time.Second),

		// Detect a black-holed link (common over the tailnet, where a dead
		// peer produces no RST) in ~60s instead of nats.go's ~4min default.
		nats.PingInterval(20 * time.Second),
		nats.MaxPingsOutstanding(3),

		// nats.go aborts reconnecting — permanently, ignoring MaxReconnects —
		// when the same server answers with an authorization error twice.
		// The controller's NATS is recreated by `noo stack start`, and a
		// client that reconnects into a half-initialised server would be
		// killed for good with no log line at all. Keep retrying instead;
		// the error is logged by ErrorHandler either way.
		nats.IgnoreAuthErrorAbort(),

		// Publishes issued while disconnected are buffered and flushed on
		// reconnect rather than dropped.
		nats.ReconnectBufSize(8 * 1024 * 1024),

		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			// err is nil on a clean server-side close (a container recreate
			// is exactly that). The old handler only logged when err != nil,
			// which is why the incident produced no disconnect line at all.
			c.markDisconnected()
			slog.Warn("nats disconnected — reconnecting", "node_id", c.nodeID, "error", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			c.markConnected()
			slog.Info("nats reconnected", "node_id", c.nodeID, "url", logship.ScrubURLUserinfo(nc.ConnectedUrl()))
			c.fireHooks()
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			if c.isClosing() {
				slog.Info("nats connection closed on shutdown", "node_id", c.nodeID)
				return
			}
			c.setState(StateClosed)
			// Loud: this is terminal for nats.go. The watchdog rebuilds.
			slog.Error("nats connection CLOSED — node is bus-deaf until rebuilt",
				"node_id", c.nodeID)
		}),
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			subject := ""
			if sub != nil {
				subject = sub.Subject
			}
			slog.Error("nats async error", "node_id", c.nodeID, "subject", subject, "error", err)
		}),
	}

	// Configure TLS if using tls:// scheme.
	//
	// A FAILURE HERE IS FATAL. It used to WARN and connect
	// anyway: against the TLS profile the server refuses the plaintext
	// handshake, so the agent looped on "nats not yet connected" with the
	// cause one WARN above the noise — and against the plain profile it
	// SUCCEEDED, putting every job dispatch and every prompt on the wire in
	// clear while the URL said `tls://`. An operator who wrote `tls://`
	// asked for TLS; silently downgrading is the one answer that must not
	// be available.
	if strings.HasPrefix(c.url, "tls://") {
		tlsCfg, err := buildNATSTLS()
		if err != nil {
			return nil, fmt.Errorf(
				"NATS_URL is %s but the TLS configuration could not be built: %w — refusing to "+
					"connect in the clear. Check NOO_TLS_CA/NOO_TLS_CERT/NOO_TLS_KEY on this node "+
					"(`noo enroll` and `noo cluster provision` deliver them)", logship.ScrubURLUserinfo(c.url), err)
		}
		if tlsCfg != nil {
			opts = append(opts, nats.Secure(tlsCfg))
		}
	}

	// NATS auth (user/password from env).
	//
	// Absent credentials are announced ONCE, loudly, at option-build time.
	// They are not made fatal: a cluster may legitimately run NATS without
	// auth, and refusing to start would break those. But silence is the wrong
	// default in the other direction, and it cost twelve minutes of a live
	// cutover on 2026-08-14 — host9's generated env file carried NATS_URL and
	// no NATS_USER/NATS_PASSWORD at all, so the agent connected anonymously,
	// was rejected, and reported only
	//
	//   nats not yet connected — retrying in the background
	//
	// on a loop. DNS resolved, TCP 4222 was open, the CA verified: every
	// signal available to the operator pointed away from credentials. The
	// controller could see the consequence ("jobs dispatched to this node will
	// strand") while the node never said why.
	//
	// One WARN naming the two variables turns that into a five-second
	// diagnosis.
	// Since the design the node reads its OWN pair
	// (NATS_NODE_USER/NATS_NODE_PASSWORD) and,, ONLY that
	// pair: the shared fleet pair and its bridge are retired, and the server
	// no longer defines that user. And the both-absent case above is no
	// longer a warning but a refusal: an empty user is not "no auth configured" to the
	// server — its authorization block with an empty value ACCEPTS the
	// anonymous connection, so a blank in the environment file used to
	// remove bus authentication in total silence. NOO_NATS_ALLOW_ANONYMOUS=1
	// is the deliberate opt-in for a dev server with no password.
	// Through the secret reader: the password may be a
	// NATS_NODE_PASSWORD_FILE pointer, and an unreadable one is an error.
	get, err := nodeconfig.SecretLookup(os.Getenv)
	if err != nil {
		return nil, err
	}
	cred, err := resolveNATSCredential(get, c.nodeID, c.url)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		// Recorded so the heartbeat can say so out loud: an anonymous bus
		// connection is a posture the controller must be able to SEE.
		c.stateMu.Lock()
		c.credUser, c.credRole = "", "anonymous"
		c.stateMu.Unlock()
		slog.Warn("connecting ANONYMOUSLY — "+natsAllowAnonymousVar+" is set",
			"node_id", c.nodeID, "url", logship.ScrubURLUserinfo(c.url))
	} else {
		slog.Info("nats credential resolved",
			"node_id", c.nodeID, "role", cred.Source, "user", cred.User)
		c.stateMu.Lock()
		c.credUser, c.credRole = cred.User, cred.Source
		c.stateMu.Unlock()
		opts = append(opts, nats.UserInfo(cred.User, cred.Password))
	}

	return opts, nil
}

// NATS credential variables. The node's own pair is the ONLY credential this
// agent presents.
const (
	natsNodeUserVar       = "NATS_NODE_USER"
	natsNodePasswordVar   = "NATS_NODE_PASSWORD"
	natsAllowAnonymousVar = "NOO_NATS_ALLOW_ANONYMOUS"
	// natsRetiredSharedUserVar is the shared fleet user retired by followup
	// 536. It is read ONLY so the refusal can say, specifically, why a stale
	// NATS_USER line in /etc/noo-node-agent.env is ignored — it is never
	// presented, and there is no bridge back to it. The stale line (and its
	// NATS_PASSWORD) stays until the node is re-provisioned; harmless.
	natsRetiredSharedUserVar = "NATS_USER"
)

// natsCredential is the pair this agent presents, plus which variables it
// came from (for the log line — never the password).
type natsCredential struct {
	User     string
	Password string
	Source   string
}

// NodeInboxPrefix returns this node's inbox prefix with the node id reduced
// to [A-Za-z0-9_-]. Any other byte becomes "_": a "." would create a subject
// hierarchy, which is precisely what the permission rule counts on not
// happening.
func NodeInboxPrefix(nodeID string) string {
	return "_INBOX_node_" + SubjectToken(nodeID)
}

// SubjectToken sanitises a value used as ONE NATS subject token.
func SubjectToken(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

// resolveNATSCredential picks the pair to present, warning about a half-set
// pair and refusing when nothing is set.
//
// The half-set warnings are kept verbatim from the 2026-08-14 cutover: they
// are the difference between a five-second diagnosis and twelve minutes of
// "nats not yet connected — retrying in the background" while DNS, TCP and
// the CA all look fine.
func resolveNATSCredential(get func(string) string, nodeID, url string) (*natsCredential, error) {
	read := func(k string) string { return strings.TrimSpace(get(k)) }

	truthy := func(v string) bool {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		}
		return false
	}

	user, pass := read(natsNodeUserVar), read(natsNodePasswordVar)
	if user != "" {
		if pass == "" {
			slog.Warn(natsNodeUserVar+" is set but "+natsNodePasswordVar+" is empty — the server will "+
				"reject this connection and the agent will retry forever without "+
				"saying why", "node_id", nodeID, "url", logship.ScrubURLUserinfo(url))
		}
		return &natsCredential{User: user, Password: pass, Source: "node"}, nil
	}
	if pass != "" {
		slog.Warn(natsNodePasswordVar+" is set but "+natsNodeUserVar+" is empty — that pair is "+
			"ignored", "node_id", nodeID, "url", logship.ScrubURLUserinfo(url))
	}

	if truthy(read(natsAllowAnonymousVar)) {
		return nil, nil
	}

	if read(natsRetiredSharedUserVar) != "" {
		return nil, fmt.Errorf(
			"%s/%s are not set. %s is set, but the shared bus user was RETIRED "+
				": the server no longer defines it and this agent never "+
				"presents it. Run `noo cluster nats-creds rotate %s` on the controller — it "+
				"mints, DELIVERS and re-renders — or `noo cluster provision %s` if this node "+
				"was never provisioned",
			natsNodeUserVar, natsNodePasswordVar, natsRetiredSharedUserVar, nodeID, nodeID)
	}

	return nil, fmt.Errorf(
		"no NATS credential: set %s/%s in the agent environment file. An empty user "+
			"connects ANONYMOUSLY and the server accepts it, which silently removes bus "+
			"authentication — so this is refused. `noo cluster nats-creds rotate %s` "+
			"delivers this node's pair (`noo cluster provision %s` for a node never "+
			"provisioned). Set %s=1 to connect anonymously on purpose",
		natsNodeUserVar, natsNodePasswordVar, nodeID, nodeID, natsAllowAnonymousVar)
}

// watchdog supervises the connection. nats.go recovers from a dropped link
// on its own, but not from CLOSED — and it has no opinion about a link that
// has been down for hours. This loop rebuilds a closed connection and keeps
// a long outage visible in the logs instead of silent.
func (c *Client) watchdog() {
	ticker := time.NewTicker(watchdogInterval)
	defer ticker.Stop()

	deafFor := time.Duration(0)
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
		}

		nc := c.conn()
		if nc == nil {
			continue
		}

		if nc.IsClosed() {
			deafFor = 0
			if err := c.rebuild(); err != nil {
				slog.Error("nats rebuild failed — retrying", "error", err)
			}
			continue
		}

		if nc.IsConnected() {
			deafFor = 0
			continue
		}

		deafFor += watchdogInterval
		slog.Error("nats still disconnected — jobs dispatched to this node will strand",
			"node_id", c.nodeID, "disconnected_for", deafFor.String(), "url", logship.ScrubURLUserinfo(c.url))
	}
}

// rebuild discards a permanently closed connection and dials a fresh one,
// then fires the reconnect hooks so durables and the mesh responder re-bind
// against the new connection. This is the in-process equivalent of
// `noo cluster restart-agent`, minus the lost running jobs.
func (c *Client) rebuild() error {
	slog.Warn("rebuilding closed nats connection", "node_id", c.nodeID, "url", logship.ScrubURLUserinfo(c.url))

	opts, err := c.buildOptions()
	if err != nil {
		return err
	}
	nc, err := nats.Connect(c.url, opts...)
	if err != nil {
		return err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return err
	}

	c.mu.Lock()
	old := c.nc
	c.nc = nc
	c.js = js
	c.mu.Unlock()
	if old != nil {
		old.Close()
	}

	if nc.IsConnected() {
		c.markConnected()
		slog.Info("nats connection rebuilt", "node_id", c.nodeID)
		c.fireHooks()
	} else {
		c.setState(StateReconnecting)
	}
	return nil
}

// Close drains and closes the NATS connection.
func (c *Client) Close() {
	c.stateMu.Lock()
	c.closing = true
	c.stateMu.Unlock()

	c.stopOnce.Do(func() { close(c.stop) })
	if nc := c.conn(); nc != nil {
		nc.Drain()
	}
}

// isClosing reports whether Close was called, so a deliberate shutdown does
// not raise the bus-deaf alarm.
func (c *Client) isClosing() bool {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.closing
}

func (c *Client) conn() *nats.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nc
}

// IsConnected returns true if the NATS connection is active.
func (c *Client) IsConnected() bool {
	nc := c.conn()
	return nc != nil && nc.IsConnected()
}

func (c *Client) setState(s string) {
	c.stateMu.Lock()
	c.state = s
	c.stateMu.Unlock()
}

func (c *Client) markConnected() {
	now := time.Now()
	c.stateMu.Lock()
	c.state = StateConnected
	c.lastConnected = &now
	c.connects++
	c.stateMu.Unlock()
}

func (c *Client) markDisconnected() {
	now := time.Now()
	c.stateMu.Lock()
	c.state = StateReconnecting
	c.lastDisconnect = &now
	c.stateMu.Unlock()
}

// Status reports the connection state. Safe on a nil *Client: a node agent
// that never built a messaging client reports "unavailable", never a
// benign-looking default.
func (c *Client) Status() Status {
	if c == nil {
		return Status{State: StateUnavailable, Connected: false}
	}

	c.stateMu.Lock()
	st := Status{
		State:    c.state,
		Connects: c.connects,
		URL:      logship.ScrubURLUserinfo(c.url),
		User:     c.credUser,
		Role:     c.credRole,
	}
	lastConn, lastDisc := c.lastConnected, c.lastDisconnect
	c.stateMu.Unlock()

	// The live socket is the authority for `connected`; the state string is
	// bookkeeping that could lag a callback.
	st.Connected = c.IsConnected()
	if st.Connected && st.State != StateConnected {
		st.State = StateConnected
	}
	// The socket dropping and the callback running are not simultaneous —
	// nats.go flips its status first and invokes DisconnectErrHandler on
	// another goroutine. Never report "connected" over a dead socket in that
	// window.
	if !st.Connected && st.State == StateConnected {
		st.State = StateReconnecting
	}

	if lastConn != nil {
		s := lastConn.UTC().Format(time.RFC3339)
		st.LastConnectedAt = &s
	}
	if lastDisc != nil {
		s := lastDisc.UTC().Format(time.RFC3339)
		st.LastDisconnectedAt = &s
		if !st.Connected {
			secs := int64(time.Since(*lastDisc).Seconds())
			st.DisconnectedForSec = &secs
		}
	}
	return st
}

// ErrNotConnected is returned by PublishEvent when there is no usable
// connection, so callers report a real failure instead of assuming the
// message went out.
var ErrNotConnected = errors.New("nats not connected")

// PublishEvent publishes a JSON event to the NATS subject "events.<eventType>".
func (c *Client) PublishEvent(eventType string, data map[string]any) error {
	nc := c.conn()
	if nc == nil || nc.IsClosed() {
		return ErrNotConnected
	}

	// Always include node_id
	data["node_id"] = c.nodeID

	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	subject := "events." + eventType
	if err := nc.Publish(subject, payload); err != nil {
		return fmt.Errorf("publish %s: %w", subject, err)
	}
	return nil
}

// PublishNodeEvent publishes an event on the NODE-SCOPED subject
// "events.<eventType>.<node_id>".
//
// Use this, not PublishEvent, for anything a node emits about itself. The
// per-principal bus credential grants a node only the scoped
// forms -- `events.node.registered.{id}`, `events.ingest.doc.parsed.{id}` --
// so a bare subject is REFUSED by the server. NATS reports permission
// violations asynchronously, so Publish returns nil, nothing is logged, and
// the event simply never arrives. That is the failure that silently stopped
// gossip; these two were the same bug in the same rail, found by looking
// for siblings rather than by anything breaking.
//
// Nothing subscribes to either subject today, so no control path depended
// on them -- but both land in the EVENTS JetStream stream (`events.>`, 24h),
// and losing that history during a fresh onboard is losing it exactly when
// a node-registration breadcrumb is the thing you want.
func (c *Client) PublishNodeEvent(eventType string, data map[string]any) error {
	return c.PublishEvent(eventType+"."+SubjectToken(c.nodeID), data)
}

// PublishJobEvent publishes a job lifecycle event on the NODE-SCOPED subject
// "events.job.<kind>.<node_id>".
//
// The unsuffixed "events.job.<kind>" that this replaces carried no publisher
// identity, so any holder of the bus credential could complete or fail ANY
// job id — terminalising someone else's job, or poisoning its retry. With
// the node in the subject the gateway can compare it against the node the
// job was actually dispatched to, and a permission rule can later restrict
// each node to its own suffix.
//
// The gateway accepts both shapes during the rollout; the fleet upgrades
// node by node.
//
// DIVERGENCE, not yet resolved: this side sanitises the id through
// SubjectToken (which maps `.` to `_`), and the credential that authorises
// it does not -- `nats_users.rs` renders the grant from the raw id. For
// every id in the fleet today (host3, host9, host8, host6) the two are
// byte-identical, so nothing is live. A node id containing a DOT would
// diverge: this publishes `events.job.ack.host8` while the grant
// authorises `events.job.ack.pop.os`, and the publish is refused the same
// silent way. Sanitising is the correct side -- the gateway parses the
// suffix as ONE token and rejects `a.b` (scheduler_completions parse_subject)
// -- so the fix is for the grant to apply the same rule, not for this to
// stop applying it. Do not conclude from "it works today" that the two
// agree; they agree only because no id has a dot in it.
func (c *Client) PublishJobEvent(kind string, data map[string]any) error {
	return c.PublishEvent("job."+kind+"."+SubjectToken(c.nodeID), data)
}

// JS returns the JetStream context for direct access when needed.
// Always re-read it — a rebuild replaces it.
func (c *Client) JS() nats.JetStreamContext {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.js
}

// NC returns the underlying NATS connection.
// Always re-read it — a rebuild replaces it.
func (c *Client) NC() *nats.Conn {
	return c.conn()
}

// WaitForConnection blocks until the client is connected or ctx is done.
// Used at startup so the first subscription attempt does not race the
// initial connect.
func (c *Client) WaitForConnection(ctx context.Context, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if c.IsConnected() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// buildNATSTLS creates a TLS config for NATS from PAI environment variables.
func buildNATSTLS() (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	// Load CA cert
	caPath := os.Getenv("NOO_TLS_CA")
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("reading NATS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse NATS CA cert")
		}
		tlsCfg.RootCAs = pool
	}

	// Load client cert for mTLS
	certPath := os.Getenv("NOO_TLS_CERT")
	keyPath := os.Getenv("NOO_TLS_KEY")
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("loading NATS client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
