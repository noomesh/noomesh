// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package jobs handles NATS-dispatched job execution on the node agent.
package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
)

// Executor dispatches and runs jobs received via NATS JetStream.
type Executor struct {
	nats   *messaging.Client
	docker *dockerpkg.Client
	http   *http.Client
	scheme string

	controllerURL string
	nodeID        string

	mu        sync.Mutex
	active    map[string]context.CancelFunc // job_id -> cancel
	cancelled map[string]struct{}

	subMu          sync.Mutex
	dispatchSub    *nats.Subscription
	cancelSub      *nats.Subscription
	hookRegistered bool
}

// NewExecutor creates a job executor.
func NewExecutor(
	nats *messaging.Client,
	docker *dockerpkg.Client,
	httpClient *http.Client,
	scheme string,
	controllerURL string,
	nodeID string,
) *Executor {
	return &Executor{
		nats:          nats,
		docker:        docker,
		http:          httpClient,
		scheme:        scheme,
		controllerURL: controllerURL,
		nodeID:        nodeID,
		active:        make(map[string]context.CancelFunc),
		cancelled:     make(map[string]struct{}),
	}
}

// ActiveCount returns the number of currently running jobs.
func (e *Executor) ActiveCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.active)
}

// Subscribe sets up JetStream subscriptions for job dispatch and cancellation.
//
// Also registers a reconnect hook that re-binds both durables: nats.go's
// automatic resubscription does not reliably restore JetStream push
// consumers after a server-side stream recreation — the agent looks
// connected (heartbeats flow) while its dispatch consumer sits
// push_bound=None and jobs strand (observed on host9, 2026-07-03).
//
// The hook is registered BEFORE the first bind attempt, and a failed first
// bind is not fatal: the agent may start while the controller's NATS is
// down, in which case the connection completes later and the hook binds
// then. Returning an error here used to leave the node permanently without
// a dispatch subscription.
func (e *Executor) Subscribe() error {
	e.subMu.Lock()
	register := !e.hookRegistered
	e.hookRegistered = true
	e.subMu.Unlock()
	if register {
		e.nats.OnReconnect(func() {
			if err := e.bindSubscriptions(); err != nil {
				slog.Error("job dispatch resubscribe failed", "error", err, "node_id", e.nodeID)
			} else {
				slog.Info("job dispatch resubscribed after reconnect", "node_id", e.nodeID)
			}
		})
	}

	if err := e.bindSubscriptions(); err != nil {
		if !e.nats.IsConnected() {
			// Expected while the bus is down — the reconnect hook binds later.
			slog.Warn("job dispatch subscribe deferred until nats connects",
				"node_id", e.nodeID, "error", err)
			return nil
		}
		return err
	}
	return nil
}

// Bound reports whether the dispatch durable is currently bound. Used by
// /health so a node that is connected-but-unsubscribed cannot read as
// healthy.
// Bound reports whether dispatch can actually be RECEIVED, which is not the
// same question as whether a subscription object exists.
//
// It used to answer `dispatchSub != nil && dispatchSub.IsValid()`. IsValid is
// a CLIENT-side check: the subscription struct is live locally. A subscription
// the server refused on permissions is still valid by that measure, so the
// node reported `job_dispatch_bound: true` while receiving nothing — for
// hours, across four nodes, with every status surface agreeing. A status that cannot be wrong is not a status.
//
// The deliver subject is the discriminator, and it is knowable locally: if the
// consumer this agent bound delivers somewhere this node's grant will not let
// it subscribe, it is not bound, whatever the client thinks. The watchdog's
// server round trip catches the other case — the consumer vanishing entirely.
func (e *Executor) Bound() bool {
	e.subMu.Lock()
	defer e.subMu.Unlock()
	if e.dispatchSub == nil || !e.dispatchSub.IsValid() {
		return false
	}
	return deliverableHere(e.nodeID, e.dispatchSub)
}

// deliverableHere reports whether a subscription's deliver subject is one this
// node is entitled to receive on — i.e. under its own inbox prefix.
//
// A pull consumer has no deliver subject and needs no grant, so it counts as
// deliverable. Anything under the shared default `_INBOX.` does not: that
// prefix belongs to the gateway, and a node's grant denies it precisely so one
// node cannot read another's replies.
func deliverableHere(nodeID string, sub *nats.Subscription) bool {
	ci, err := sub.ConsumerInfo()
	if err != nil {
		// The server could not be asked. Do not manufacture confidence from
		// a failed question — the watchdog will re-bind and ask again.
		return false
	}
	ds := ci.Config.DeliverSubject
	if ds == "" {
		return true // pull consumer
	}
	return strings.HasPrefix(ds, messaging.NodeInboxPrefix(nodeID)+".")
}

// rebindInterval is how often EnsureBound re-checks the durable.
// Variable so the reconnect integration test can drive it quickly.
var rebindInterval = 30 * time.Second

// EnsureBound polls the dispatch binding and repairs it. Blocks until ctx
// is done; run it as a goroutine.
//
// The reconnect hook alone is not sufficient. `js.Subscribe` fails outright
// when the TASKS stream does not exist yet — which is exactly the state
// right after the controller's NATS container is recreated, since the
// gateway creates the stream on ITS OWN startup, possibly after the node
// has already reconnected. A node that reconnected into that window would
// log one "resubscribe failed" and stay unbound forever, which is
// indistinguishable from the incident this file already documents.
//
// Same shape as the Python scheduler's `_check_completion_listener`
// (cluster/scheduler.py): a sticky health flag, a periodic checker, and one
// idempotent re-bind function.
func (e *Executor) EnsureBound(ctx context.Context) {
	ticker := time.NewTicker(rebindInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if !e.nats.IsConnected() {
			continue
		}
		if e.Bound() {
			// Client-side validity is not the truth. A durable can vanish
			// SERVER-side with the TCP connection never dropping — a stream
			// deleted and recreated by an operator or a limits change —
			// and Subscription.IsValid() stays true while zero messages
			// will ever arrive again (the same silent-deaf presentation as
			// the 2026-07-03 incident, minus the reconnect that would have
			// fired the repair hook). Ask the SERVER whether this sub's
			// consumer still exists; one round trip per tick.
			e.subMu.Lock()
			sub := e.dispatchSub
			e.subMu.Unlock()
			if sub != nil {
				if _, err := sub.ConsumerInfo(); err == nil {
					continue // truly bound, server agrees
				}
				slog.Warn("job dispatch consumer missing SERVER-side — re-binding",
					"node_id", e.nodeID)
			}
		}
		if err := e.bindSubscriptions(); err != nil {
			slog.Warn("job dispatch still unbound — retrying", "node_id", e.nodeID, "error", err)
		} else {
			slog.Info("job dispatch re-bound by watchdog", "node_id", e.nodeID)
		}
	}
}

// bindSubscriptions (re)creates the dispatch + cancel subscriptions,
// dropping any previous client-side bindings first so the durable can be
// re-bound cleanly.
func (e *Executor) bindSubscriptions() error {
	e.subMu.Lock()
	defer e.subMu.Unlock()

	js := e.nats.JS()

	if e.dispatchSub != nil {
		e.dispatchSub.Unsubscribe()
		e.dispatchSub = nil
	}
	if e.cancelSub != nil {
		e.cancelSub.Unsubscribe()
		e.cancelSub = nil
	}

	// Subscribe to dispatch for this node
	subject := fmt.Sprintf("tasks.dispatch.%s", e.nodeID)
	durable := fmt.Sprintf("node_%s_dispatch", e.nodeID)

	sub, err := js.Subscribe(subject, func(msg *natsMsg) {
		msg.Ack()
		e.handleDispatch(msg.Data)
	}, natsSubOpts(durable, deliverSubject(e.nodeID, "dispatch"))...)
	if err != nil {
		return fmt.Errorf("subscribe dispatch (if the durable %s exists with a "+
			"different deliver subject, the GATEWAY must delete it — this node's "+
			"grant denies CONSUMER.DELETE): %w", durable, err)
	}
	e.dispatchSub = sub
	slog.Info("job dispatch subscribed", "node_id", e.nodeID)

	// Subscribe to cancel events
	cancelSubject := "events.job.cancel"
	cancelDurable := fmt.Sprintf("node_%s_cancel", e.nodeID)
	csub, err := js.Subscribe(cancelSubject, func(msg *natsMsg) {
		msg.Ack()
		e.handleCancel(msg.Data)
	}, natsSubOpts(cancelDurable, deliverSubject(e.nodeID, "cancel"))...)
	if err != nil {
		slog.Warn("cancel subscription failed", "error", err)
		// Non-fatal — jobs will just run to completion
	} else {
		e.cancelSub = csub
	}

	return nil
}

func (e *Executor) handleDispatch(data []byte) {
	var job jobPayload
	if err := json.Unmarshal(data, &job); err != nil {
		slog.Error("invalid job payload", "error", err)
		return
	}
	if job.JobID == "" {
		return
	}

	slog.Info("job received", "job_id", job.JobID, "type", job.Type)

	// Defence in depth: the gateway rejects unrunnable types at submit, but
	// a job dispatched here that this agent has no executor for must still
	// terminate honestly and immediately. `retryable: false` tells the
	// scheduler not to bounce it to the next node — every node runs this
	// same executor, so the retry budget would only delay the same answer
	// (that is exactly how `test_run` used to sit dispatched for minutes
	// before dying). No job.ack: we never started it.
	if !CanExecute(job.Type) {
		slog.Error("job rejected: no executor for type", "job_id", job.JobID, "type", job.Type)
		e.nats.PublishJobEvent("failed", map[string]any{
			"job_id":    job.JobID,
			"error":     fmt.Sprintf("node %s cannot execute job type %q", e.nodeID, job.Type),
			"retryable": false,
		})
		return
	}

	// ACK receipt
	// Node-scoped lifecycle subjects: the gateway
	// checks the node in the subject against the node it dispatched the job
	// to, so a stolen credential can no longer terminalise another node's
	// job.
	//
	// ORDER MATTERS. The gateway must be upgraded FIRST. Its old consumer
	// filtered "events.job.*", a SINGLE-token wildcard that does not match
	// the suffixed subject at all — a node running this code against an
	// un-upgraded gateway would have every completion silently ignored and
	// every job reaped as a timeout. The new consumer filters
	// "events.job.>" and accepts both shapes, so gateway-then-nodes is
	// safe in any order and node-then-gateway is not. Publishing both
	// subjects instead is NOT an option: the new gateway would see each
	// failure twice and burn two retries for one failure.
	e.nats.PublishJobEvent("ack", map[string]any{
		"job_id": job.JobID,
	})

	// Execute in background
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.active[job.JobID] = cancel
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			delete(e.active, job.JobID)
			delete(e.cancelled, job.JobID)
			e.mu.Unlock()
			cancel()
		}()

		result, err := e.runJob(ctx, &job)

		// Check if cancelled
		e.mu.Lock()
		_, wasCancelled := e.cancelled[job.JobID]
		e.mu.Unlock()
		if wasCancelled {
			slog.Info("job cancelled", "job_id", job.JobID)
			return
		}

		if err != nil {
			slog.Error("job failed", "job_id", job.JobID, "error", err)
			e.nats.PublishJobEvent("failed", map[string]any{
				"job_id": job.JobID,
				"error":  err.Error(),
			})
			return
		}

		slog.Info("job completed", "job_id", job.JobID, "type", job.Type)
		e.nats.PublishJobEvent("complete", map[string]any{
			"job_id": job.JobID,
			"result": result,
		})
	}()
}

func (e *Executor) handleCancel(data []byte) {
	var event struct {
		JobID  string `json:"job_id"`
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return
	}
	if event.NodeID != e.nodeID {
		return
	}

	e.mu.Lock()
	if cancel, ok := e.active[event.JobID]; ok {
		e.cancelled[event.JobID] = struct{}{}
		cancel()
		slog.Info("job cancel requested", "job_id", event.JobID)
	}
	e.mu.Unlock()
}

func (e *Executor) runJob(ctx context.Context, job *jobPayload) (any, error) {
	var payload map[string]any
	switch p := job.Payload.(type) {
	case string:
		json.Unmarshal([]byte(p), &payload)
	case map[string]any:
		payload = p
	}
	if payload == nil {
		payload = map[string]any{}
	}

	switch job.Type {
	case "inference":
		return e.executeInference(ctx, payload, job.Backend, job.TimeoutSec)
	case "tool_exec":
		return e.executeTool(payload)
	case "model_download":
		return e.executeModelDownload(ctx, payload)
	case "background_graph":
		return e.executeBackgroundGraph(ctx, payload)
	case "background_cache":
		return e.executeBackgroundCache(ctx, payload)
	case "fetch_bundle":
		return e.executeFetchBundle()
	case "model_file":
		return e.executeModelFile(ctx, payload)
	default:
		// Unreachable via handleDispatch (which pre-checks CanExecute), but
		// kept so a case added to Executable without one here still fails
		// loudly rather than returning a nil result as "completed".
		return nil, fmt.Errorf("unknown job type: %s", job.Type)
	}
}

// --- Job type implementations ---

func (e *Executor) executeInference(ctx context.Context, payload map[string]any, backend string, timeoutSec int) (any, error) {
	prompt, _ := payload["prompt"].(string)
	model, _ := payload["model"].(string)

	backends := e.docker.RunningBackends()
	if backend == "" {
		for _, b := range []string{"vllm", "llamacpp", "ollama"} {
			if _, ok := backends[b]; ok {
				backend = b
				break
			}
		}
		if backend == "" {
			return nil, fmt.Errorf("no inference backend running")
		}
	}

	// vLLM (and ollama) reject unknown model ids — "default" only works on
	// llama.cpp's single-model server. Resolve to the loaded model when the
	// payload doesn't pin one.
	if model == "" {
		model = backends[backend]
	}

	// Use Docker network URL (stunnel-aware) when inside Docker,
	// falls back to localhost for bare-metal edge deployment. The running
	// containers' declaration (TLS + client cert, llama.cpp's sidecar) wins
	// over the env flag; e.http presents the node leaf.
	baseURL := e.docker.BackendDialURL(backend)

	var reqBody []byte
	var url string
	if backend == "ollama" {
		url = baseURL + "/api/generate"
		reqBody, _ = json.Marshal(map[string]any{
			"model":  firstOr(model, "default"),
			"prompt": prompt,
			"stream": false,
		})
	} else {
		url = baseURL + "/v1/chat/completions"
		reqBody, _ = json.Marshal(map[string]any{
			"model":    firstOr(model, "default"),
			"messages": []map[string]string{{"role": "user", "content": prompt}},
		})
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Honor the scheduler's job timeout — the previous hardcoded 120s
	// undercut the default job timeout_sec=300 and killed slow-but-fine
	// CPU inference (host9 E2B first request exceeded 120s, 2026-07-03).
	if timeoutSec <= 0 {
		timeoutSec = 300
	}
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second, Transport: e.http.Transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		// Propagate upstream errors as job failures so the scheduler's
		// retry machinery engages — otherwise an error JSON body gets
		// recorded as a successful result and the job reads "completed".
		msg := string(body)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("backend %s HTTP %d: %s", backend, resp.StatusCode, msg)
	}
	var result any
	json.Unmarshal(body, &result)
	return result, nil
}

// executeTool is a REFUSAL, not an implementation.
//
// This used to echo the request back as {"status":"executed"} without
// running anything — the silent-success shape: the scheduler marked the
// job complete, the dashboard showed a green run, and no tool had been
// called. A verdict assembled from your own echo is worse than an error,
// because nothing downstream can tell it from work.
//
// Tools run in the gateway's tool gate (approval mode, sandbox, audit),
// not on a node. Nothing in this repo dispatches a `tool_exec` job to a
// node today; if that changes, the executor gets a real implementation
// and this function goes away. Until then it fails loudly.
func (e *Executor) executeTool(payload map[string]any) (any, error) {
	toolName, _ := payload["tool"].(string)
	return nil, fmt.Errorf(
		"tool_exec is not implemented on the node (requested tool %q): tools run in the "+
			"gateway's tool gate, which owns approval, sandboxing and audit. This job type "+
			"previously reported success without executing anything",
		toolName)
}

func (e *Executor) executeModelDownload(ctx context.Context, payload map[string]any) (any, error) {
	profile, _ := payload["profile"].(string)
	if profile == "" {
		return nil, fmt.Errorf("no profile specified")
	}
	if err := e.docker.PullProfile(profile); err != nil {
		return nil, err
	}
	return map[string]string{"status": "downloaded", "profile": profile}, nil
}

func (e *Executor) executeBackgroundGraph(ctx context.Context, payload map[string]any) (any, error) {
	scope, _ := payload["scope"].(string)
	if scope == "" {
		scope = "extract"
	}
	batchSize := intOr(payload["batch_size"], 20)

	slog.Info("background graph start", "scope", scope, "batch_size", batchSize)

	var endpoints []string
	if scope == "extract" {
		endpoints = []string{
			e.controllerURL + "/api/v1/rag/extract",
			e.controllerURL + "/api/v1/graph/extract",
		}
	} else if scope == "build_edges" {
		endpoints = []string{
			e.controllerURL + "/api/v1/rag/build-edges",
			e.controllerURL + "/api/v1/graph/build-edges",
		}
	} else {
		return nil, fmt.Errorf("unknown scope: %s", scope)
	}

	body, _ := json.Marshal(map[string]int{"batch_size": batchSize})
	for _, endpoint := range endpoints {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := e.http.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			return map[string]string{"status": "completed", "scope": scope}, nil
		}
	}

	// Fallback: no gateway endpoint accepted the request. Publish an
	// observability breadcrumb and report SKIPPED — events.ingest.doc.parsed
	// has no in-tree subscriber (it lands in the JetStream EVENTS stream for
	// external observation only), so nothing will run the extraction. The
	// previous "completed via nats_event" status misrepresented that.
	if e.nats.IsConnected() {
		e.nats.PublishNodeEvent("ingest.doc.parsed", map[string]any{
			"trigger":    "background_graph",
			"batch_size": batchSize,
		})
		return map[string]any{"status": "skipped", "scope": scope, "reason": "no endpoint; event published (no in-tree consumer)"}, nil
	}

	return map[string]string{"status": "skipped", "scope": scope, "reason": "no endpoint"}, nil
}

func (e *Executor) executeBackgroundCache(ctx context.Context, payload map[string]any) (any, error) {
	action, _ := payload["action"].(string)
	if action == "" {
		action = "warm_embeddings"
	}

	slog.Info("background cache start", "action", action)

	var url string
	switch action {
	case "warm_embeddings":
		url = fmt.Sprintf("%s/api/v1/rag/status", e.controllerURL)
	case "warm_entities":
		url = fmt.Sprintf("%s/api/v1/graph/entities?q=*&limit=50", e.controllerURL)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := e.http.Do(req)
	if err != nil {
		return map[string]any{"status": "partial", "action": action, "reason": err.Error()}, nil
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return map[string]any{"status": "skipped", "action": action, "reason": "endpoint not available"}, nil
	}

	return map[string]string{"status": "completed", "action": action}, nil
}

// --- Types ---

type jobPayload struct {
	JobID      string `json:"job_id"`
	Type       string `json:"type"`
	Backend    string `json:"backend"`
	Payload    any    `json:"payload"`
	TimeoutSec int    `json:"timeout_sec"`
}

// Alias for the nats.Msg used in subscribe callbacks
type natsMsg = nats.Msg

// natsSubOpts returns standard subscription options with a durable name and
// an EXPLICIT deliver subject under this node's own inbox prefix.
//
// Without the explicit subject, nats.go mints one with nc.NewInbox() on the
// CREATE path only; binding an EXISTING durable reuses whatever subject that
// consumer already recorded (js.go, `case info != nil` -> processConsInfo).
// Consumers created while the agent held the SHARED credential recorded the
// default `_INBOX.` prefix, and a per-principal grant denies it — so the node
// bound the durable it was entitled to and then subscribed to an inbox it was
// not. Silently: a denied SUBSCRIBE is refused after nc.Subscribe has already
// returned. Confirmed live on 2026-09-06, the design: four nodes, eight
// consumers, every one on `_INBOX.`, every one reporting bound.
//
// The suffix is STABLE, not a nuid. A random one would differ on every rebind
// and mismatch the consumer this agent itself created a moment earlier — the
// same bug, self-inflicted, once per reconnect.
//
// When an existing consumer disagrees, nats.go now returns an error instead of
// silently adopting the wrong subject. The node reports UNBOUND, which is the
// honest answer; repairing it needs the gateway, because a node's own grant
// denies $JS.API.CONSUMER.DELETE by design.
func natsSubOpts(durable, deliver string) []nats.SubOpt {
	return []nats.SubOpt{
		nats.Durable(durable),
		nats.ManualAck(),
		nats.DeliverSubject(deliver),
	}
}

// deliverSubject is where this node's consumer delivers, derived only from the
// node id — so it is the same string on every bind, on every connection, for
// the life of the node.
func deliverSubject(nodeID, kind string) string {
	return messaging.NodeInboxPrefix(nodeID) + "." + kind
}

func firstOr(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

func intOr(v any, fallback int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return fallback
}
