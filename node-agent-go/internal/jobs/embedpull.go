// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
	"github.com/noomesh/noomesh/node-agent-go/internal/modelpresence"
	"github.com/noomesh/noomesh/node-agent-go/internal/occupancy"
)

// The pulled-embedding worker (proposal i179, PR C). The gateway publishes
// bulk embed batches to the WORK_EMBED work-queue stream, one subject and one
// durable pull consumer per embed model, and this worker claims them when it
// has a free embed slot. The wire contract (subjects, message and completion
// shapes, ack/nak/term rules) is stated in the proposal and in
// embedpull_subjects.go; this file only implements the node side.
//
// Hard rules that shape the code:
//   - The node only BINDS. The gateway creates the consumers; a bind failure
//     is logged once per model, retried on a timer and reported as
//     bound=false. It must never touch tasks.dispatch handling, so this
//     worker shares nothing with Executor but the NATS client.
//   - Bound() asks the SERVER (ConsumerInfo), never the client's own
//     subscription flag; see Executor.Bound for the outage that taught that.
//   - Lifecycle events go through PublishJobEvent, so they land on the
//     node-scoped subjects the credential already grants. No new subject.

const (
	// embedPullBatchMax is the most messages one fetch asks for.
	embedPullBatchMax = 4
	// embedReserveSlots is held back for query-time /embed.
	embedReserveSlots = 1
	// embedFallbackSlots stands in for a backend that declares no slot count
	// (TEI, for one): one bulk job at a time beside the reserved slot.
	embedFallbackSlots = 2
)

// EmbedFunc runs one OpenAI-shaped embeddings request against the local
// embedder in process and returns the HTTP status and body /embed would have
// answered. The agent passes api.Server.EmbedLocal, which IS handleEmbedProxy.
type EmbedFunc func(ctx context.Context, body []byte) (status int, resp []byte, err error)

// embedServed is one embed model this node serves, with the backend that
// serves it (the occupancy key).
type embedServed struct {
	Model   string
	Backend string
}

// EmbedSlug is the gateway's model slug (embed_jobs::slug): ASCII A-Z
// lowercased, then every char outside [a-z0-9_-] becomes '_'. No trimming or
// collapsing. ASCII only because Go's and Rust's Unicode lowercasing differ
// (U+0130), and one stray '_' would route a model's jobs to a subject nobody
// pulls. Both sides test the same vectors.
func EmbedSlug(model string) string {
	var b strings.Builder
	for _, r := range model {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A' // ASCII only: Unicode lowercasing differs from Rust's
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// EmbedSubject is the work subject for a model.
func EmbedSubject(model string) string { return "work.embed." + EmbedSlug(model) }

// EmbedConsumer is the durable consumer name for a model.
func EmbedConsumer(model string) string { return EmbedConsumerPrefix + EmbedSlug(model) }

// ServedEmbedModels is every embed model this node serves right now, read
// from the same table the heartbeat's model_presence comes from (role=embed,
// present). The key is "<backend>#embed[@model]" or the bare backend name.
func ServedEmbedModels() []embedServed {
	var out []embedServed
	seen := map[string]bool{}
	for key, e := range modelpresence.Report() {
		if e.Role != "embed" || !e.Present || strings.TrimSpace(e.Model) == "" {
			continue
		}
		backend, _, _ := strings.Cut(key, "#")
		if seen[e.Model] {
			continue
		}
		seen[e.Model] = true
		out = append(out, embedServed{Model: e.Model, Backend: backend})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Model < out[j].Model })
	return out
}

// embedJob is the gateway's job message.
type embedJob struct {
	V     int      `json:"v"`
	JobID string   `json:"job_id"`
	Model string   `json:"model"`
	Space string   `json:"space"`
	Dims  *int     `json:"dims"`
	Input []string `json:"input"`
}

// embedBind is one live pull subscription.
type embedBind struct {
	served embedServed
	sub    *nats.Subscription
	cancel context.CancelFunc
}

// EmbedPuller claims bulk embedding work from WORK_EMBED.
type EmbedPuller struct {
	nats   *messaging.Client
	nodeID string
	embed  EmbedFunc
	models func() []embedServed

	// Tunables (fields so tests can run in milliseconds).
	fetchWait       time.Duration
	idleSleep       time.Duration
	errBackoff      time.Duration
	syncEvery       time.Duration
	bindRetry       time.Duration
	inProgressEvery time.Duration
	mismatchDelay   time.Duration

	slotMu  sync.Mutex     // guards claimed
	claimed map[string]int // backend -> fetched, not yet admitted

	mu         sync.Mutex
	binds      map[string]*embedBind // slug -> bind
	nextTry    map[string]time.Time  // slug -> earliest next bind attempt
	failLogged map[string]bool       // slug -> bind failure already logged
	desired    []embedServed
	hook       bool
	root       context.Context
	wg         sync.WaitGroup
}

// NewEmbedPuller builds the worker. embed must not be nil.
func NewEmbedPuller(c *messaging.Client, nodeID string, embed EmbedFunc) *EmbedPuller {
	return &EmbedPuller{
		nats:            c,
		nodeID:          nodeID,
		embed:           embed,
		models:          ServedEmbedModels,
		fetchWait:       5 * time.Second,
		idleSleep:       time.Second,
		errBackoff:      2 * time.Second,
		syncEvery:       15 * time.Second,
		bindRetry:       60 * time.Second,
		inProgressEvery: 15 * time.Second,
		mismatchDelay:   30 * time.Second,
		claimed:         map[string]int{},
		binds:           map[string]*embedBind{},
		nextTry:         map[string]time.Time{},
		failLogged:      map[string]bool{},
	}
}

// Run keeps the bindings matched to the served models until ctx ends. Block
// on it from a goroutine. A reconnect re-syncs at once (the same hook the
// dispatch executor registers).
func (p *EmbedPuller) Run(ctx context.Context) {
	p.mu.Lock()
	p.root = ctx
	register := !p.hook
	p.hook = true
	p.mu.Unlock()
	if register {
		p.nats.OnReconnect(func() { p.Sync() })
	}

	p.Sync()
	t := time.NewTicker(p.syncEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.unbindAll()
			p.wg.Wait()
			return
		case <-t.C:
			p.Sync()
		}
	}
}

// Sync reconciles the bindings with the served models once: unbinds models
// no longer served (their in-flight jobs finish), drops bindings the server
// no longer knows, and binds the rest, subject to the per-model retry timer.
func (p *EmbedPuller) Sync() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.root == nil || p.root.Err() != nil {
		return
	}
	want := map[string]embedServed{}
	var desired []embedServed
	for _, m := range p.models() {
		slug := EmbedSlug(m.Model)
		if _, dup := want[slug]; dup {
			continue
		}
		want[slug] = m
		desired = append(desired, m)
	}
	p.desired = desired

	for slug, b := range p.binds {
		if _, ok := want[slug]; !ok {
			slog.Info("embed pull: model no longer served, unbinding", "model", b.served.Model)
			p.dropLocked(slug)
			delete(p.nextTry, slug)
			delete(p.failLogged, slug)
			continue
		}
		// Server truth, not client state.
		if _, err := b.sub.ConsumerInfo(); err != nil {
			slog.Warn("embed pull: consumer gone server-side, rebinding",
				"model", b.served.Model, "error", err)
			p.dropLocked(slug)
			delete(p.nextTry, slug)
		}
	}
	for slug := range p.nextTry {
		if _, ok := want[slug]; !ok {
			delete(p.nextTry, slug)
			delete(p.failLogged, slug)
		}
	}
	if !p.nats.IsConnected() {
		return
	}
	now := time.Now()
	for slug, m := range want {
		if _, bound := p.binds[slug]; bound {
			continue
		}
		if t, ok := p.nextTry[slug]; ok && now.Before(t) {
			continue
		}
		if err := p.bindLocked(slug, m); err != nil {
			p.nextTry[slug] = now.Add(p.bindRetry)
			if !p.failLogged[slug] {
				p.failLogged[slug] = true
				slog.Warn("embed pull: cannot bind consumer; retrying every minute (old gateway, no stream or consumer, or a denied grant)",
					"model", m.Model, "consumer", EmbedConsumer(m.Model), "error", err)
			}
			continue
		}
		delete(p.nextTry, slug)
		delete(p.failLogged, slug)
		slog.Info("embed pull: bound", "model", m.Model, "consumer", EmbedConsumer(m.Model))
	}
}

func (p *EmbedPuller) bindLocked(slug string, m embedServed) error {
	js := p.nats.JS()
	if js == nil {
		return messaging.ErrNotConnected
	}
	durable := EmbedConsumerPrefix + slug
	sub, err := js.PullSubscribe("work.embed."+slug, durable, nats.Bind(EmbedStream, durable))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(p.root)
	b := &embedBind{served: m, sub: sub, cancel: cancel}
	p.binds[slug] = b
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.pullLoop(ctx, b)
	}()
	return nil
}

func (p *EmbedPuller) dropLocked(slug string) {
	if b, ok := p.binds[slug]; ok {
		b.cancel()
		_ = b.sub.Unsubscribe()
		delete(p.binds, slug)
	}
}

func (p *EmbedPuller) unbindAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for slug := range p.binds {
		p.dropLocked(slug)
	}
}

// Status is the heartbeat's pull_embed value. models are the served embed
// model names; bound is true only when there is at least one and the SERVER
// confirms every consumer.
func (p *EmbedPuller) Status() map[string]any {
	p.mu.Lock()
	names := make([]string, 0, len(p.desired))
	for _, m := range p.desired {
		names = append(names, m.Model)
	}
	subs := make([]*nats.Subscription, 0, len(p.binds))
	for _, b := range p.binds {
		subs = append(subs, b.sub)
	}
	nWant := len(p.desired)
	p.mu.Unlock()
	return map[string]any{"models": names, "bound": nWant > 0 && len(subs) == nWant && p.verify(subs)}
}

// Bound reports whether every served embed model's consumer is confirmed by
// the server right now.
func (p *EmbedPuller) Bound() bool {
	b, _ := p.Status()["bound"].(bool)
	return b
}

func (p *EmbedPuller) verify(subs []*nats.Subscription) bool {
	if !p.nats.IsConnected() {
		return false
	}
	for _, s := range subs {
		if _, err := s.ConsumerInfo(); err != nil {
			return false
		}
	}
	return true
}

// claim decides how many messages to fetch for the backend and counts them
// as claimed. free = slots - in_flight - claimed - reserve, where slots and
// in_flight come from the occupancy package (what the heartbeat reports; the
// fallback stands in for an undeclared slot count) and claimed is what this
// worker has fetched but not yet admitted. Nothing is held in occupancy while
// a fetch waits, so an idle worker never takes a slot from chat.
func (p *EmbedPuller) claim(backend string) int {
	p.slotMu.Lock()
	defer p.slotMu.Unlock()
	if occupancy.Draining(backend) {
		return 0
	}
	slots := occupancy.Slots(backend)
	if slots <= 0 {
		slots = embedFallbackSlots
	}
	free := slots - occupancy.InFlight(backend) - p.claimed[backend] - embedReserveSlots
	if free > embedPullBatchMax {
		free = embedPullBatchMax
	}
	if free <= 0 {
		return 0
	}
	p.claimed[backend] += free
	return free
}

func (p *EmbedPuller) unclaim(backend string, n int) {
	if n <= 0 {
		return
	}
	p.slotMu.Lock()
	p.claimed[backend] -= n
	if p.claimed[backend] < 0 {
		p.claimed[backend] = 0
	}
	p.slotMu.Unlock()
}

func (p *EmbedPuller) pullLoop(ctx context.Context, b *embedBind) {
	sleep := func(d time.Duration) bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
			return true
		}
	}
	for ctx.Err() == nil {
		n := p.claim(b.served.Backend)
		if n == 0 {
			if !sleep(p.idleSleep) {
				return
			}
			continue
		}
		msgs, err := b.sub.Fetch(n, nats.MaxWait(p.fetchWait))
		p.unclaim(b.served.Backend, n-len(msgs))
		for _, m := range msgs {
			p.wg.Add(1)
			go func(m *nats.Msg) {
				defer p.wg.Done()
				p.handle(p.root, m, b.served)
			}(m)
		}
		if err != nil && !errors.Is(err, nats.ErrTimeout) {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("embed pull: fetch failed", "model", b.served.Model, "error", err)
			if !sleep(p.errBackoff) {
				return
			}
		}
	}
}

// embedResponse is the part of an OpenAI embeddings reply the worker reads.
type embedResponse struct {
	Model string `json:"model"`
	Data  []struct {
		Index     int       `json:"index"`
		Embedding []float64 `json:"embedding"`
	} `json:"data"`
}

// sameEmbedModel mirrors the gateway's embedding_spaces::same_model.
func sameEmbedModel(a, b string) bool {
	n := func(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ":latest") }
	return n(a) == n(b)
}

// servedModelRefusal mirrors the gateway's served_model_refusal: a reply that
// names no model passes, one that names another model is refused.
func servedModelRefusal(served, model string) string {
	served = strings.TrimSpace(served)
	if served == "" || sameEmbedModel(served, model) {
		return ""
	}
	return fmt.Sprintf("served model '%s', not the job's '%s'", served, model)
}

// handle settles one delivered message. ctx is the worker's root context: a
// shutdown abandons the message (no ack, nak or term) so JetStream redelivers
// it after ack_wait to another puller.
func (p *EmbedPuller) handle(ctx context.Context, msg *nats.Msg, served embedServed) {
	// The message was claimed against the backend's free slots when fetched;
	// it is admitted (counted in_flight) or abandoned before this returns.
	var once sync.Once
	unclaim := func() { once.Do(func() { p.unclaim(served.Backend, 1) }) }
	defer unclaim()

	var job embedJob
	if err := json.Unmarshal(msg.Data, &job); err != nil || job.JobID == "" || job.V != 1 ||
		len(job.Input) == 0 || strings.TrimSpace(job.Model) == "" {
		slog.Error("embed pull: unreadable job message, terminating it", "model", served.Model, "error", err)
		if job.JobID != "" {
			p.fail(job.JobID, "unreadable embed job message", false)
		}
		_ = msg.Term()
		return
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(p.inProgressEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-wctx.Done():
				return
			case <-t.C:
				_ = msg.InProgress()
			}
		}
	}()

	// Count the job in flight on the backend for its whole run, so the
	// heartbeat's numbers and the next claim see it. May wait if chat took
	// the slot first; InProgress keeps the message ours meanwhile.
	release, err := occupancy.Admit(wctx, served.Backend)
	unclaim()
	if err != nil {
		return // shutting down: leave it to redelivery
	}
	defer release()

	_ = p.nats.PublishJobEvent("ack", map[string]any{"job_id": job.JobID})
	body, _ := json.Marshal(map[string]any{"model": job.Model, "input": job.Input})
	status, resp, err := p.embed(wctx, body)

	if ctx.Err() != nil {
		slog.Warn("embed pull: shutting down mid-job, leaving it to redelivery", "job_id", job.JobID)
		return
	}
	if err != nil || status < 200 || status >= 300 {
		reason := fmt.Sprintf("embedder answered %d: %s", status, truncate(string(resp), 300))
		if err != nil {
			reason = "embedder call failed: " + err.Error()
		}
		// 5xx, 429, 408 and 404 (another node may carry the model) are worth
		// another delivery; a 400-class refusal of the request itself is not.
		retryable := err != nil || status >= 500 || status == 429 || status == 408 || status == 404
		p.settleFailure(msg, job.JobID, reason, retryable)
		return
	}
	var er embedResponse
	if err := json.Unmarshal(resp, &er); err != nil || len(er.Data) != len(job.Input) {
		p.settleFailure(msg, job.JobID,
			fmt.Sprintf("embedder reply unusable (%d vectors for %d inputs, parse error %v)", len(er.Data), len(job.Input), err), true)
		return
	}
	if why := servedModelRefusal(er.Model, job.Model); why != "" {
		slog.Warn("embed pull: wrong model answered, not storing vectors",
			"job_id", job.JobID, "reason", why)
		_ = msg.NakWithDelay(p.mismatchDelay)
		return
	}
	sort.SliceStable(er.Data, func(i, j int) bool { return er.Data[i].Index < er.Data[j].Index })
	dims := len(er.Data[0].Embedding)
	if dims == 0 {
		p.settleFailure(msg, job.JobID, "embedder returned an empty vector", true)
		return
	}
	if job.Dims != nil && *job.Dims != dims {
		slog.Warn("embed pull: embedder dims differ from the job's", "job_id", job.JobID, "job_dims", *job.Dims, "got", dims)
	}
	raw := make([]byte, 0, len(er.Data)*dims*4)
	for _, d := range er.Data {
		if len(d.Embedding) != dims {
			p.settleFailure(msg, job.JobID, "embedder returned vectors of differing widths", false)
			return
		}
		for _, f := range d.Embedding {
			raw = binary.LittleEndian.AppendUint32(raw, math.Float32bits(float32(f)))
		}
	}
	servedModel := strings.TrimSpace(er.Model)
	if servedModel == "" {
		servedModel = job.Model
	}
	result, _ := json.Marshal(map[string]any{"embed": map[string]any{
		"v": 1, "model": servedModel, "dims": dims, "n": len(er.Data),
		"vectors_b64": base64.StdEncoding.EncodeToString(raw),
	}})
	if err := p.nats.PublishJobEvent("complete", map[string]any{
		"job_id": job.JobID, "result": string(result),
	}); err != nil {
		// Nothing told the gateway: do not ack, let it come back.
		slog.Error("embed pull: could not publish complete; nak", "job_id", job.JobID, "error", err)
		_ = msg.Nak()
		return
	}
	if err := msg.Ack(); err != nil {
		slog.Warn("embed pull: ack failed", "job_id", job.JobID, "error", err)
	}
}

func (p *EmbedPuller) fail(jobID, reason string, retryable bool) {
	_ = p.nats.PublishJobEvent("failed", map[string]any{
		"job_id": jobID, "error": reason, "retryable": retryable,
	})
}

func (p *EmbedPuller) settleFailure(msg *nats.Msg, jobID, reason string, retryable bool) {
	slog.Error("embed pull: job failed", "job_id", jobID, "retryable", retryable, "reason", reason)
	p.fail(jobID, reason, retryable)
	if retryable {
		_ = msg.Nak()
	} else {
		_ = msg.Term()
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
