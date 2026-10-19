// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package ctrlrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/noomesh/noomesh/node-agent-go/internal/auth"
	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
)

// Limits.
const (
	// maxReply is the largest body sent in one bus message. The server's
	// max_payload is 1 MB; headers and framing take the rest. A larger result
	// is refused with HeaderOverflow and read over HTTPS.
	maxReply = 900 << 10
	// maxInflight bounds concurrent handlers; the rest get 429.
	maxInflight = 32
	// defaultSyncTimeout bounds a sync handler whose envelope names none.
	defaultSyncTimeout = 120 * time.Second
	// defaultAsyncTimeout bounds an async op (pull, skills.run).
	defaultAsyncTimeout = 30 * time.Minute
	maxTimeout          = time.Hour
	// progressEvery is the keepalive cadence on an async op's event stream.
	progressEvery = 10 * time.Second
	// ensureEvery is how often an unready service retries its binding.
	ensureEvery = 60 * time.Second
)

// settleWait is how long bind waits for an asynchronous permission refusal.
var settleWait = 300 * time.Millisecond

// Bus is the part of messaging.Client the service uses.
type Bus interface {
	NC() *nats.Conn
	IsConnected() bool
	OnReconnect(func())
	ViolationsSince(since time.Time, substr string) []string
}

var _ Bus = (*messaging.Client)(nil)

// Call is one control request, as the HTTP handler would see it.
type Call struct {
	Op    string
	Arg   string
	Query string
	Body  []byte
	OpID  string
}

// Result is the handler's HTTP answer: what the HTTPS API would have sent.
type Result struct {
	Status      int
	ContentType string
	Body        []byte
}

// Dispatcher runs ops. The node agent's api.Server implements it by calling
// the same handlers its HTTPS routes call.
type Dispatcher interface {
	// RPCOp says whether op exists and whether it is long-running (acked at
	// once, result on the event stream).
	RPCOp(op string) (known, async bool)
	// RPCDo runs the op. ctx carries the verified-controller mark.
	RPCDo(ctx context.Context, c Call) Result
}

// Reporter lets a handler that keeps working after it answered (start)
// report its outcome on the op's event stream. nil-safe through ReporterFrom.
type Reporter interface {
	Done(status int, v any)
}

type reporterKey struct{}

// ReporterFrom returns the op's reporter, or a no-op one (the HTTPS path).
func ReporterFrom(ctx context.Context) Reporter {
	if r, ok := ctx.Value(reporterKey{}).(Reporter); ok {
		return r
	}
	return noReporter{}
}

type noReporter struct{}

func (noReporter) Done(int, any) {}

// Service subscribes to node.<id>.rpc.> and answers.
type Service struct {
	bus      Bus
	nodeID   string
	verifier *Verifier
	disp     Dispatcher
	sem      chan struct{}

	mu      sync.Mutex
	sub     *nats.Subscription
	boundAt time.Time
	hooked  bool
}

// NewService builds the service. It does not touch the bus until Start.
func NewService(bus Bus, nodeID string, v *Verifier, d Dispatcher) *Service {
	return &Service{bus: bus, nodeID: nodeID, verifier: v, disp: d, sem: make(chan struct{}, maxInflight)}
}

func (s *Service) rpcPrefix() string { return "node." + s.nodeID + ".rpc." }
func (s *Service) evtPrefix() string { return "node." + s.nodeID + ".evt." }

// Start binds the subscription (and rebinds on reconnect and on a timer
// while it is not Ready). It never fails the agent: an unbound service is
// simply not advertised, and the controller keeps using HTTPS.
func (s *Service) Start(ctx context.Context) {
	if messaging.SubjectToken(s.nodeID) != s.nodeID {
		slog.Warn("control over the bus disabled: the node id is not a single NATS token "+
			"(letters, digits, '_' and '-' only), so no subject permission can name it",
			"node_id", s.nodeID)
		return
	}
	s.mu.Lock()
	hook := !s.hooked
	s.hooked = true
	s.mu.Unlock()
	if hook {
		s.bus.OnReconnect(func() { s.bind() })
	}
	s.bind()
	go func() {
		t := time.NewTicker(ensureEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !s.Ready() {
					s.bind()
				}
			}
		}
	}()
}

// bind (re)creates the subscription and PROVES it was accepted: nats.go
// returns a live-looking subscription for a subject the server refused, and
// reports the refusal later, asynchronously, to the error handler. A round
// trip (flush) after the SUB makes the server's -ERR arrive before we look.
func (s *Service) bind() {
	nc := s.bus.NC()
	if nc == nil || !nc.IsConnected() {
		return
	}
	subject := s.rpcPrefix() + ">"
	started := time.Now()
	sub, err := nc.Subscribe(subject, s.handle)
	if err != nil {
		slog.Error("control over the bus: subscribe failed", "subject", subject, "error", err)
		return
	}
	if err := nc.FlushTimeout(3 * time.Second); err != nil {
		slog.Warn("control over the bus: could not confirm the subscription", "subject", subject, "error", err)
		_ = sub.Unsubscribe()
		return
	}
	// The flush guarantees the server has PROCESSED the SUB (and sent any
	// -ERR) but nats.go hands the error to the async handler on its own
	// goroutine, so give that a moment to land. Ready() re-checks, so a
	// refusal that is slower than this still takes the advertisement back.
	time.Sleep(settleWait)
	if v := s.bus.ViolationsSince(started, subject); len(v) > 0 {
		_ = sub.Unsubscribe()
		slog.Error("control over the bus NOT enabled: the NATS server refused this node's subscription. "+
			"The controller's NATS users file predates control over the bus; run "+
			"`noo cluster nats-users render` on the controller (this node keeps taking control calls over HTTPS meanwhile)",
			"subject", subject, "server_said", v[0])
		return
	}
	s.mu.Lock()
	old := s.sub
	s.sub, s.boundAt = sub, started
	s.mu.Unlock()
	if old != nil {
		_ = old.Unsubscribe()
	}
	slog.Info("control over the bus enabled", "subject", subject)
}

// Ready is true when this node can answer control calls over the bus right
// now. The heartbeat advertises exactly this as control_transports.nats_rpc.
func (s *Service) Ready() bool {
	s.mu.Lock()
	sub, since := s.sub, s.boundAt
	s.mu.Unlock()
	if s.verifier == nil || sub == nil || !sub.IsValid() || !s.bus.IsConnected() {
		return false
	}
	// A later refusal (a re-rendered file that dropped a grant, a reply or
	// event publish the server denied) takes it back.
	node := "node." + s.nodeID + "."
	if len(s.bus.ViolationsSince(since, node)) > 0 ||
		len(s.bus.ViolationsSince(since, messaging.NodeReplyRoot+"."+messaging.SubjectToken(s.nodeID)+".")) > 0 {
		return false
	}
	return true
}

func (s *Service) reply(m *nats.Msg, status int, ctype string, body []byte, extra map[string]string) {
	if m.Reply == "" {
		return
	}
	h := nats.Header{}
	if len(body) > maxReply {
		status, ctype = 413, "application/json"
		body = []byte(`{"detail":"reply exceeds the bus message limit; read it over HTTPS"}`)
		h.Set(HeaderOverflow, "1")
	}
	h.Set(HeaderStatus, fmt.Sprint(status))
	if ctype != "" {
		h.Set(HeaderContentType, ctype)
	}
	for k, v := range extra {
		h.Set(k, v)
	}
	if err := m.RespondMsg(&nats.Msg{Header: h, Data: body}); err != nil {
		slog.Warn("control over the bus: reply failed", "subject", m.Subject, "error", err)
	}
}

func (s *Service) refuse(m *nats.Msg, status int, detail string) {
	b, _ := json.Marshal(map[string]string{"detail": detail})
	s.reply(m, status, "application/json", b, nil)
}

func (s *Service) handle(m *nats.Msg) {
	op := strings.TrimPrefix(m.Subject, s.rpcPrefix())
	var env Envelope
	if err := json.Unmarshal([]byte(m.Header.Get(HeaderEnvelope)), &env); err != nil {
		slog.Warn("control over the bus: message without a readable envelope refused", "subject", m.Subject)
		s.refuse(m, 403, "control envelope missing or unreadable")
		return
	}
	if err := s.verifier.Verify(op, env, m.Data); err != nil {
		slog.Warn("control over the bus: message refused", "op", op, "error", err)
		s.refuse(m, 403, err.Error())
		return
	}
	known, async := s.disp.RPCOp(op)
	if !known {
		s.refuse(m, 404, "unknown control op "+op)
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.refuse(m, 429, "too many control calls in flight on this node")
		return
	}
	call := Call{Op: op, Arg: env.Arg, Query: env.Query, Body: m.Data, OpID: env.OpID}
	timeout := defaultSyncTimeout
	if async {
		timeout = defaultAsyncTimeout
	}
	if env.TimeoutS > 0 {
		timeout = time.Duration(env.TimeoutS) * time.Second
		if timeout > maxTimeout {
			timeout = maxTimeout
		}
	}
	if async {
		if env.OpID == "" {
			<-s.sem
			s.refuse(m, 400, "op "+op+" is long-running and needs an op_id in the envelope")
			return
		}
		ack, _ := json.Marshal(map[string]string{"op_id": env.OpID, "status": "accepted"})
		s.reply(m, 202, "application/json", ack, map[string]string{HeaderAsync: "1"})
		go func() {
			defer func() { <-s.sem }()
			s.runAsync(call, timeout)
		}()
		return
	}
	go func() {
		defer func() { <-s.sem }()
		ctx, cancel := context.WithTimeout(auth.WithBusController(context.Background()), timeout)
		// Cancelled only after the reply left: restart's handler exits the
		// process when its request context ends, and the controller must have
		// the answer first.
		defer cancel()
		if env.OpID != "" {
			ctx = context.WithValue(ctx, reporterKey{}, &eventReporter{s: s, opID: env.OpID})
		}
		res := s.disp.RPCDo(ctx, call)
		s.reply(m, res.Status, res.ContentType, res.Body, nil)
		if nc := s.bus.NC(); nc != nil {
			_ = nc.FlushTimeout(2 * time.Second)
		}
	}()
}

func (s *Service) runAsync(call Call, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(auth.WithBusController(context.Background()), timeout)
	defer cancel()
	ctx = context.WithValue(ctx, reporterKey{}, &eventReporter{s: s, opID: call.OpID})
	started := time.Now()
	s.event(call.OpID, "progress", 0, "application/json", []byte(`{"phase":"started"}`))
	done := make(chan Result, 1)
	go func() { done <- s.disp.RPCDo(ctx, call) }()
	t := time.NewTicker(progressEvery)
	defer t.Stop()
	for {
		select {
		case res := <-done:
			s.event(call.OpID, "done", res.Status, res.ContentType, res.Body)
			return
		case <-t.C:
			b, _ := json.Marshal(map[string]any{"phase": "running", "elapsed_s": int(time.Since(started).Seconds())})
			s.event(call.OpID, "progress", 0, "application/json", b)
		}
	}
}

// event publishes on node.<id>.evt.<op_id>.
func (s *Service) event(opID, kind string, status int, ctype string, body []byte) {
	nc := s.bus.NC()
	if nc == nil {
		return
	}
	h := nats.Header{}
	h.Set(HeaderEvent, kind)
	if kind == "done" {
		if len(body) > maxReply {
			status, ctype = 413, "application/json"
			body = []byte(`{"detail":"result exceeds the bus message limit"}`)
			h.Set(HeaderOverflow, "1")
		}
		h.Set(HeaderStatus, fmt.Sprint(status))
		if ctype != "" {
			h.Set(HeaderContentType, ctype)
		}
	}
	if err := nc.PublishMsg(&nats.Msg{Subject: s.evtPrefix() + opID, Header: h, Data: body}); err != nil {
		slog.Warn("control over the bus: event publish failed", "op_id", opID, "error", err)
	}
}

type eventReporter struct {
	s    *Service
	opID string
}

func (r *eventReporter) Done(status int, v any) {
	b, _ := json.Marshal(v)
	r.s.event(r.opID, "done", status, "application/json", b)
}
