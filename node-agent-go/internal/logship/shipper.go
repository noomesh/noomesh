// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package logship

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Source produces entries. Run blocks until ctx ends; emit is safe to call
// from any goroutine and never blocks on the network (it queues or spills).
type Source interface {
	Name() string
	Run(ctx context.Context, emit func(Entry))
}

// Config is what the agent hands the shipper.
type Config struct {
	NodeID        string
	ControllerURL string
	// Client carries the node's TLS transport (config.HTTPTransport). Its
	// timeout is replaced: a 3 MB gzip push over a slow link needs more
	// than the heartbeat's 10 s.
	Client *http.Client
	// Auth sets the bearer exactly as the heartbeat does.
	Auth func(*http.Request) error
	// StateDir is the agent's writable state dir; the spill ring lives
	// under <StateDir>/logship.
	StateDir string

	// Tunables; zero = default.
	MemMaxLines   int
	MemMaxBytes   int
	FlushEvery    time.Duration
	FlushLines    int
	SpillMaxBytes int64
	RouteRetry    time.Duration // wait after a 404 probe (older gateway)
	PushTimeout   time.Duration
}

func (c *Config) defaults() {
	if c.MemMaxLines == 0 {
		c.MemMaxLines = 10_000
	}
	if c.MemMaxBytes == 0 {
		c.MemMaxBytes = 8 << 20
	}
	if c.FlushEvery == 0 {
		c.FlushEvery = 2 * time.Second
	}
	if c.FlushLines == 0 {
		c.FlushLines = 1000
	}
	if c.SpillMaxBytes == 0 {
		c.SpillMaxBytes = 64 << 20
	}
	if c.RouteRetry == 0 {
		c.RouteRetry = 10 * time.Minute
	}
	if c.PushTimeout == 0 {
		c.PushTimeout = 30 * time.Second
	}
}

// Shipper is the bounded queue, the flush loop and the push contract.
type Shipper struct {
	cfg      Config
	push     *pusher
	spill    *spill
	sources  []Source
	selfPath string

	mu       sync.Mutex
	mem      []Entry
	memBytes int
	wake     chan struct{}

	// Telemetry for the heartbeat (`log_ship`).
	shippedTotal     int64
	droppedTotal     int64
	redactedTotal    int64 // credential shapes scrubbed at intake (redact.go)
	lastAcceptedUnix int64
	lastError        string
	routeReady       bool
	started          bool

	onceMu sync.Mutex
	once   map[string]time.Time

	// pemFlows holds the flows (source, name, stream) whose last entry was
	// a PEM body line, so the next entry is scrubbed as its successor
	// (RedactAfter, pem-tail). Present only while true: a handful of keys
	// at most, and empty in the common case.
	pemMu    sync.Mutex
	pemFlows map[string]bool
}

// New validates the config (refusing plaintext) and prepares the spill.
func New(cfg Config) (*Shipper, error) {
	cfg.defaults()
	client := &http.Client{Timeout: cfg.PushTimeout}
	if cfg.Client != nil {
		client.Transport = cfg.Client.Transport
	}
	p, err := newPusher(cfg.ControllerURL, cfg.NodeID, client, cfg.Auth)
	if err != nil {
		return nil, err
	}
	s := &Shipper{
		cfg:      cfg,
		push:     p,
		wake:     make(chan struct{}, 1),
		once:     map[string]time.Time{},
		pemFlows: map[string]bool{},
		selfPath: "/api/cluster/nodes/" + cfg.NodeID + "/logs",
	}
	sp, err := newSpill(filepath.Join(cfg.StateDir, "logship"), cfg.SpillMaxBytes, s.noteDropped)
	if err != nil {
		return nil, err
	}
	s.spill = sp
	return s, nil
}

// AddSource registers a source to start once the route is known to exist.
func (s *Shipper) AddSource(src Source) { s.sources = append(s.sources, src) }

// Offer queues one entry. Never blocks on the network: past the memory
// caps it spills to disk, and past the disk cap the oldest spilled lines
// are dropped (counted).
func (s *Shipper) Offer(e Entry) {
	if e.Line == "" {
		return
	}
	// Self-loop guard: the controller's own agent ships the gateway's
	// stdout, and the gateway logs requests. The ingest route is excluded
	// from the gateway's request logger; this is the belt to that brace.
	if strings.Contains(e.Line, s.selfPath) {
		return
	}
	if e.TS == 0 {
		e.TS = time.Now().UnixNano()
	}
	// Scrub HERE, ahead of both the memory queue and the spill: the spill
	// is a 0640 file that outlives the process, and this is the one
	// place every line passes through before either.
	// One source runs one goroutine, so a flow's entries arrive in order.
	flow := e.Labels.flowKey()
	s.pemMu.Lock()
	prev := ""
	if s.pemFlows[flow] {
		prev = pemBodyPlaceholder
	}
	s.pemMu.Unlock()
	if line, n := RedactAfter(prev, e.Line); n > 0 {
		e.Line, e.Redacted = line, n
		s.noteRedacted(int64(n))
	}
	s.pemMu.Lock()
	if e.Line[strings.LastIndexByte(e.Line, '\n')+1:] == pemBodyPlaceholder {
		s.pemFlows[flow] = true
	} else {
		delete(s.pemFlows, flow)
	}
	s.pemMu.Unlock()
	s.mu.Lock()
	if len(s.mem) < s.cfg.MemMaxLines && s.memBytes+e.size() <= s.cfg.MemMaxBytes {
		s.mem = append(s.mem, e)
		s.memBytes += e.size()
		n := len(s.mem)
		s.mu.Unlock()
		if n >= s.cfg.FlushLines {
			s.kick()
		}
		return
	}
	s.mu.Unlock()
	if err := s.spill.write([]Entry{e}); err != nil {
		s.noteDropped(1)
		s.logOnce("spill", "log shipper cannot spill to disk; dropping", "error", err)
	}
}

func (s *Shipper) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run blocks until ctx ends. Roll safety first: sources start only once
// the controller answers the route, so an agent upgraded before its
// gateway idles (probing every RouteRetry) instead of spilling for nothing.
func (s *Shipper) Run(ctx context.Context) {
	if !s.waitForRoute(ctx) {
		return
	}
	s.mu.Lock()
	s.routeReady, s.started = true, true
	s.mu.Unlock()
	for _, src := range s.sources {
		go src.Run(ctx, s.Offer)
	}
	slog.Info("log shipper started", "url", ScrubURLUserinfo(s.push.url), "sources", s.sourceNames())
	s.flushLoop(ctx)
}

func (s *Shipper) sourceNames() []string {
	out := make([]string, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src.Name())
	}
	return out
}

func (s *Shipper) waitForRoute(ctx context.Context) bool {
	bo := newBackoff(5*time.Second, time.Minute)
	for {
		present, err := s.push.probe(ctx)
		if present {
			return true
		}
		wait := bo.next(0)
		if err == errRouteAbsent {
			s.logOnce("route-404", "log shipping idle: the controller has no ingest route yet (older gateway); retrying",
				"retry_in", s.cfg.RouteRetry, "fix", "upgrade the gateway first, then the agents")
			wait = s.cfg.RouteRetry
		} else {
			s.logOnce("route-probe", "log shipping cannot reach the controller yet", "error", err, "retry_in", wait)
		}
		s.setError(errString(err))
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// flushLoop ships every FlushEvery or FlushLines, memory first, then the
// disk backlog once memory is quiet.
func (s *Shipper) flushLoop(ctx context.Context) {
	tk := time.NewTicker(s.cfg.FlushEvery)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			// Nothing in memory may be lost to a restart.
			batch := s.take(s.cfg.MemMaxLines)
			if len(batch) > 0 {
				_ = s.spill.write(batch)
			}
			return
		case <-tk.C:
		case <-s.wake:
		}
		for {
			batch := s.take(s.cfg.FlushLines)
			if len(batch) == 0 {
				break
			}
			if !s.shipBatch(ctx, batch) {
				return
			}
		}
		// Backlog: at most a few batches per tick so live lines stay
		// interleaved with the replay.
		for i := 0; i < 4 && s.spill.pending(); i++ {
			batch, err := s.spill.drain(s.cfg.FlushLines)
			if err != nil {
				s.logOnce("spill-read", "log shipper cannot read its spill file", "error", err)
				break
			}
			if len(batch) == 0 {
				break
			}
			if !s.shipBatch(ctx, batch) {
				return
			}
		}
	}
}

func (s *Shipper) take(max int) []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.mem) == 0 {
		return nil
	}
	n := len(s.mem)
	if n > max {
		n = max
	}
	out := make([]Entry, n)
	copy(out, s.mem[:n])
	rest := make([]Entry, len(s.mem)-n)
	copy(rest, s.mem[n:])
	s.mem = rest
	s.memBytes = 0
	for _, e := range s.mem {
		s.memBytes += e.size()
	}
	return out
}

// shipBatch pushes a batch to completion under the status contract.
// Returns false only when ctx ended (the unsent remainder is spilled).
func (s *Shipper) shipBatch(ctx context.Context, batch []Entry) bool {
	pieces := splitEntries(s.cfg.NodeID, batch, SplitBelowBytes)
	for i, piece := range pieces {
		if !s.shipPiece(ctx, piece) {
			var rest []Entry
			for _, p := range pieces[i:] {
				rest = append(rest, p...)
			}
			_ = s.spill.write(rest)
			return false
		}
	}
	return true
}

// shipPiece sends one under-cap piece: accepted or dropped ends it;
// retryable answers loop with backoff. False when ctx ended first.
func (s *Shipper) shipPiece(ctx context.Context, piece []Entry) bool {
	n := int64(len(piece))
	gz, err := gzipBytes(encode(s.cfg.NodeID, piece))
	if err != nil {
		s.noteDropped(n)
		return true
	}
	redacted := 0
	for _, e := range piece {
		redacted += e.Redacted
	}
	bo := newBackoff(time.Second, 60*time.Second)
	for {
		res := s.push.send(ctx, gz)
		switch res.outcome {
		case outcomeAccepted:
			s.noteAccepted(n)
			if redacted > 0 {
				slog.Debug("log batch shipped with credentials scrubbed", "lines", n, "redacted", redacted)
			}
			return true
		case outcomeDropped:
			s.noteDropped(n)
			s.setError(res.reason)
			s.logOnce("4xx:"+res.reason, "log batch refused by the controller; dropped", "reason", res.reason, "lines", n)
			return true
		}
		s.setError(res.reason)
		wait := bo.next(res.retryAfter)
		if errors.Is(res.err, errRouteAbsent) {
			// The gateway lost the route (a rollback): same treatment as
			// before start — keep the batch, re-probe on the long cadence.
			wait = s.cfg.RouteRetry
			s.logOnce("route-404", "log shipping paused: the controller has no ingest route (older gateway); retrying",
				"retry_in", wait, "fix", "upgrade the gateway first, then the agents")
		} else {
			s.logOnce("retry:"+reasonClass(res), "log push failed; retrying with backoff", "reason", res.reason, "wait", wait)
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
	}
}

func reasonClass(r pushResult) string {
	if r.status != 0 {
		return "http-" + itoa(r.status)
	}
	return "transport"
}

func itoa(n int) string { return nsString(int64(n)) }

func (s *Shipper) noteAccepted(n int64) {
	s.mu.Lock()
	s.shippedTotal += n
	s.lastAcceptedUnix = time.Now().Unix()
	s.lastError = ""
	s.mu.Unlock()
}

func (s *Shipper) noteDropped(n int64) {
	s.mu.Lock()
	s.droppedTotal += n
	s.mu.Unlock()
}

func (s *Shipper) noteRedacted(n int64) {
	s.mu.Lock()
	s.redactedTotal += n
	s.mu.Unlock()
}

func (s *Shipper) setError(msg string) {
	s.mu.Lock()
	s.lastError = msg
	s.mu.Unlock()
}

// logOnce emits a WARN once per reason per 5 minutes: a controller that
// is down for an hour costs a dozen lines, not one per batch.
func (s *Shipper) logOnce(reason, msg string, kv ...any) {
	s.onceMu.Lock()
	last, seen := s.once[reason]
	if seen && time.Since(last) < 5*time.Minute {
		s.onceMu.Unlock()
		return
	}
	s.once[reason] = time.Now()
	// Bound the map: reasons carry response text.
	if len(s.once) > 256 {
		for k, t := range s.once {
			if time.Since(t) > 5*time.Minute {
				delete(s.once, k)
			}
		}
	}
	s.onceMu.Unlock()
	slog.Warn(msg, kv...)
}

// State is the heartbeat's `log_ship` object.
func (s *Shipper) State() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	queued := len(s.mem)
	return map[string]any{
		"enabled":            true,
		"queued":             queued,
		"shipped_total":      s.shippedTotal,
		"dropped_total":      s.droppedTotal,
		"redacted_total":     s.redactedTotal,
		"last_accepted_unix": s.lastAcceptedUnix,
		"last_error":         s.lastError,
		"route_ready":        s.routeReady,
		"spill_pending":      s.spill.pending(),
	}
}

// DisabledState is what the heartbeat carries when shipping is off, so
// `cluster verify` can tell "off by choice" from "an agent too old".
func DisabledState(reason string) map[string]any {
	return map[string]any{
		"enabled":            false,
		"queued":             0,
		"shipped_total":      0,
		"last_accepted_unix": 0,
		"last_error":         reason,
	}
}
