// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
	"github.com/noomesh/noomesh/node-agent-go/internal/occupancy"
)

func TestEmbedSlugVectors(t *testing.T) {
	for in, want := range map[string]string{
		"nomic-embed-text:v1.5": "nomic-embed-text_v1_5",
		"Harrier/1024":          "harrier_1024",
		"bge-m3":                "bge-m3",
		"a.b*c>d e":             "a_b_c_d_e",
	} {
		if got := EmbedSlug(in); got != want {
			t.Errorf("EmbedSlug(%q) = %q, want %q", in, got, want)
		}
	}
	if EmbedSubject("bge-m3") != "work.embed.bge-m3" || EmbedConsumer("bge-m3") != "embed_bge-m3" {
		t.Error("subject/consumer must be built from the slug and the PR A constants")
	}
}

func TestServedModelRefusalMirrorsGateway(t *testing.T) {
	if servedModelRefusal("", "m") != "" || servedModelRefusal("M:latest", "m") != "" {
		t.Error("blank or same-modulo-latest/case must pass")
	}
	if servedModelRefusal("other", "m") == "" {
		t.Error("a different model must be refused")
	}
}

// --- harness ------------------------------------------------------------

type pullEnv struct {
	t      *testing.T
	url    string
	client *messaging.Client
	events chan pullEvent
}

type pullEvent struct {
	kind string
	data map[string]any
}

func newPullEnv(t *testing.T) *pullEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test: runs an in-process NATS server")
	}
	t.Setenv("NOO_NATS_ALLOW_ANONYMOUS", "1")
	port := freePort(t)
	srv := startNATS(t, port)
	t.Cleanup(srv.Shutdown)
	occupancy.Reset()
	t.Cleanup(occupancy.Reset)
	e := &pullEnv{t: t, url: fmt.Sprintf("nats://127.0.0.1:%d", port), events: make(chan pullEvent, 64)}
	e.client = e.connect("it-node")
	// Observe the job lifecycle events, as the gateway would.
	nc, err := nats.Connect(e.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	if _, err := nc.Subscribe("events.job.>", func(m *nats.Msg) {
		var d map[string]any
		_ = json.Unmarshal(m.Data, &d)
		var kind string
		_, _ = fmt.Sscanf(m.Subject, "events.job.%s", &kind)
		e.events <- pullEvent{kind: kind, data: d}
	}); err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	return e
}

func (e *pullEnv) connect(node string) *messaging.Client {
	c, err := messaging.Connect(e.url, node)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(c.Close)
	if !c.WaitForConnection(context.Background(), 10*time.Second) {
		e.t.Fatal("never connected")
	}
	return c
}

// createWork mimics the gateway: the stream and one durable per model.
func (e *pullEnv) createWork(model string, ackWait time.Duration) {
	e.t.Helper()
	js := e.client.JS()
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: EmbedStream, Subjects: []string{"work.embed.>"},
		Retention: nats.WorkQueuePolicy, Storage: nats.MemoryStorage,
	}); err != nil && err != nats.ErrStreamNameAlreadyInUse {
		e.t.Fatal(err)
	}
	if _, err := js.AddConsumer(EmbedStream, &nats.ConsumerConfig{
		Durable: EmbedConsumer(model), FilterSubject: EmbedSubject(model),
		AckPolicy: nats.AckExplicitPolicy, AckWait: ackWait, MaxDeliver: 3, MaxAckPending: 256,
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *pullEnv) publishJob(model, id string, input []string) {
	e.t.Helper()
	dims := 3
	b, _ := json.Marshal(map[string]any{"v": 1, "job_id": id, "model": model, "space": "knowledge", "dims": dims, "input": input})
	if _, err := e.client.JS().PublishMsg(&nats.Msg{
		Subject: EmbedSubject(model), Data: b, Header: nats.Header{"Nats-Msg-Id": []string{id}},
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *pullEnv) info(model string) *nats.ConsumerInfo {
	e.t.Helper()
	ci, err := e.client.JS().ConsumerInfo(EmbedStream, EmbedConsumer(model))
	if err != nil {
		e.t.Fatal(err)
	}
	return ci
}

// next returns the next event of a kind within d, or ok=false.
func (e *pullEnv) next(kind string, d time.Duration) (map[string]any, bool) {
	deadline := time.After(d)
	for {
		select {
		case ev := <-e.events:
			if ev.kind == kind || ev.kind[:len(kind)] == kind {
				return ev.data, true
			}
		case <-deadline:
			return nil, false
		}
	}
}

// fastPuller returns a worker with millisecond timers serving one model.
func fastPuller(c *messaging.Client, node, backend, model string, embed EmbedFunc) *EmbedPuller {
	p := NewEmbedPuller(c, node, embed)
	p.models = func() []embedServed { return []embedServed{{Model: model, Backend: backend}} }
	p.fetchWait = 200 * time.Millisecond
	p.idleSleep = 20 * time.Millisecond
	p.errBackoff = 50 * time.Millisecond
	p.syncEvery = 100 * time.Millisecond
	p.bindRetry = 100 * time.Millisecond
	p.inProgressEvery = 100 * time.Millisecond
	return p
}

// fakeEmbedder answers like the node's /embed: OpenAI shape, 3 dims, vector i
// = [i, i+0.5, -i].
func fakeEmbedder(model string, calls *atomic.Int32) EmbedFunc {
	return func(ctx context.Context, body []byte) (int, []byte, error) {
		calls.Add(1)
		var in struct {
			Input []string `json:"input"`
			Model string   `json:"model"`
		}
		_ = json.Unmarshal(body, &in)
		data := []map[string]any{}
		for i := range in.Input {
			f := float64(i)
			data = append(data, map[string]any{"index": i, "embedding": []float64{f, f + 0.5, -f}})
		}
		b, _ := json.Marshal(map[string]any{"object": "list", "data": data, "model": model})
		return 200, b, nil
	}
}

func startPuller(t *testing.T, p *EmbedPuller) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return cancel
}

func waitCond(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- tests --------------------------------------------------------------

func TestPullWorkerCompletesAndAcks(t *testing.T) {
	e := newPullEnv(t)
	const model = "Harrier/1024"
	e.createWork(model, 5*time.Second)
	occupancy.SetSlots(map[string]int{"ollama": 4})
	var calls atomic.Int32
	p := fastPuller(e.client, "it-node", "ollama", model, fakeEmbedder(model, &calls))
	startPuller(t, p)

	e.publishJob(model, "job-1", []string{"a", "b"})

	ack, ok := e.next("ack", 5*time.Second)
	if !ok || ack["job_id"] != "job-1" {
		t.Fatalf("no ack event: %v", ack)
	}
	done, ok := e.next("complete", 5*time.Second)
	if !ok {
		t.Fatal("no complete event")
	}
	if done["job_id"] != "job-1" || done["node_id"] != "it-node" {
		t.Errorf("envelope = %v", done)
	}
	res, _ := done["result"].(string)
	var out struct {
		Embed struct {
			V          int    `json:"v"`
			Model      string `json:"model"`
			Dims       int    `json:"dims"`
			N          int    `json:"n"`
			VectorsB64 string `json:"vectors_b64"`
		} `json:"embed"`
	}
	if err := json.Unmarshal([]byte(res), &out); err != nil {
		t.Fatalf("result is not the contract JSON: %v (%s)", err, res)
	}
	if out.Embed.V != 1 || out.Embed.Model != model || out.Embed.Dims != 3 || out.Embed.N != 2 {
		t.Errorf("embed = %+v", out.Embed)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Embed.VectorsB64)
	if err != nil || len(raw) != 2*3*4 {
		t.Fatalf("vectors_b64 decode: len=%d err=%v", len(raw), err)
	}
	want := []float32{0, 0.5, 0, 1, 1.5, -1}
	for i, w := range want {
		if g := math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4:])); g != w {
			t.Errorf("float %d = %v, want %v", i, g, w)
		}
	}
	waitCond(t, 3*time.Second, "message acked", func() bool {
		ci := e.info(model)
		return ci.NumPending == 0 && ci.NumAckPending == 0
	})
	if calls.Load() != 1 {
		t.Errorf("embedder calls = %d", calls.Load())
	}
	waitCond(t, 3*time.Second, "slot released", func() bool { return occupancy.InFlight("ollama") == 0 })
	st := p.Status()
	if st["bound"] != true || fmt.Sprint(st["models"]) != "["+model+"]" {
		t.Errorf("status = %v", st)
	}
}

func TestPullWorkerWithNoFreeSlotFetchesNothing(t *testing.T) {
	e := newPullEnv(t)
	const model = "bge-m3"
	e.createWork(model, 5*time.Second)
	// 2 slots, 1 reserved, 1 busy: free = 0.
	occupancy.SetSlots(map[string]int{"ollama": 2})
	rel, err := occupancy.Admit(context.Background(), "ollama")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	startPuller(t, fastPuller(e.client, "it-node", "ollama", model, fakeEmbedder(model, &calls)))
	e.publishJob(model, "job-busy", []string{"x"})

	time.Sleep(600 * time.Millisecond) // several fetch cycles
	ci := e.info(model)
	if ci.NumPending != 1 || ci.NumAckPending != 0 || ci.Delivered.Consumer != 0 || calls.Load() != 0 {
		t.Fatalf("worker took work with no free slot: %+v calls=%d", ci, calls.Load())
	}
	// Free the slot: now it takes the job.
	rel()
	if _, ok := e.next("complete", 5*time.Second); !ok {
		t.Fatal("job not taken once a slot freed")
	}
}

func TestPullWorkerModelMismatchNaksWithoutCompletion(t *testing.T) {
	e := newPullEnv(t)
	const model = "harrier"
	e.createWork(model, 5*time.Second)
	occupancy.SetSlots(map[string]int{"ollama": 4})
	var calls atomic.Int32
	p := fastPuller(e.client, "it-node", "ollama", model, fakeEmbedder("some-other-model", &calls))
	p.mismatchDelay = 30 * time.Second
	startPuller(t, p)
	e.publishJob(model, "job-wrong", []string{"x"})

	waitCond(t, 5*time.Second, "embedder to be called", func() bool { return calls.Load() == 1 })
	if d, ok := e.next("complete", 400*time.Millisecond); ok {
		t.Fatalf("completion published for the wrong model: %v", d)
	}
	if d, ok := e.next("failed", 100*time.Millisecond); ok {
		t.Fatalf("a mismatch is a nak, not a failure event: %v", d)
	}
	ci := e.info(model)
	if ci.NumAckPending != 1 || ci.NumPending != 0 {
		t.Errorf("message should sit in its 30s nak delay: %+v", ci)
	}
}

func TestPullWorkerEmbedderErrorFailsThenRedelivers(t *testing.T) {
	e := newPullEnv(t)
	const model = "harrier"
	e.createWork(model, 5*time.Second)
	occupancy.SetSlots(map[string]int{"ollama": 4})
	var n atomic.Int32
	good := fakeEmbedder(model, new(atomic.Int32))
	p := fastPuller(e.client, "it-node", "ollama", model, func(ctx context.Context, b []byte) (int, []byte, error) {
		if n.Add(1) == 1 {
			return 503, []byte(`{"error":"busy"}`), nil
		}
		return good(ctx, b)
	})
	startPuller(t, p)
	e.publishJob(model, "job-flaky", []string{"x"})

	f, ok := e.next("failed", 5*time.Second)
	if !ok || f["job_id"] != "job-flaky" || f["retryable"] != true || f["error"] == "" {
		t.Fatalf("failed event = %v", f)
	}
	if _, ok := e.next("complete", 5*time.Second); !ok {
		t.Fatal("retryable failure was not redelivered and completed")
	}
}

func TestPullWorkerNonRetryableErrorIsTerminated(t *testing.T) {
	e := newPullEnv(t)
	const model = "harrier"
	e.createWork(model, 5*time.Second)
	occupancy.SetSlots(map[string]int{"ollama": 4})
	var n atomic.Int32
	p := fastPuller(e.client, "it-node", "ollama", model, func(ctx context.Context, b []byte) (int, []byte, error) {
		n.Add(1)
		return 400, []byte(`{"error":"bad"}`), nil
	})
	startPuller(t, p)
	e.publishJob(model, "job-bad", []string{"x"})

	f, ok := e.next("failed", 5*time.Second)
	if !ok || f["retryable"] != false {
		t.Fatalf("failed event = %v", f)
	}
	waitCond(t, 3*time.Second, "message terminated", func() bool {
		ci := e.info(model)
		return ci.NumPending == 0 && ci.NumAckPending == 0
	})
	time.Sleep(300 * time.Millisecond)
	if n.Load() != 1 {
		t.Errorf("a terminated message was delivered %d times", n.Load())
	}
}

func TestKilledWorkerMidJobIsRedeliveredAfterAckWait(t *testing.T) {
	e := newPullEnv(t)
	const model = "harrier"
	e.createWork(model, 500*time.Millisecond)
	occupancy.SetSlots(map[string]int{"ollama": 4})

	started := make(chan struct{}, 1)
	p1 := fastPuller(e.client, "it-node", "ollama", model, func(ctx context.Context, b []byte) (int, []byte, error) {
		started <- struct{}{}
		<-ctx.Done() // the job never finishes: the worker is killed
		return 0, nil, ctx.Err()
	})
	kill := startPuller(t, p1)
	e.publishJob(model, "job-orphan", []string{"x"})
	<-started
	// While alive, InProgress keeps the message past ack_wait.
	time.Sleep(900 * time.Millisecond)
	if ci := e.info(model); ci.NumRedelivered != 0 {
		t.Fatalf("InProgress did not extend ack_wait: %+v", ci)
	}
	kill()

	var calls atomic.Int32
	c2 := e.connect("it-node-2")
	startPuller(t, fastPuller(c2, "it-node-2", "ollama", model, fakeEmbedder(model, &calls)))
	done, ok := e.next("complete", 5*time.Second)
	if !ok || done["job_id"] != "job-orphan" || done["node_id"] != "it-node-2" {
		t.Fatalf("job not redelivered to the surviving worker: %v", done)
	}
	if _, bad := e.next("failed", 100*time.Millisecond); bad {
		t.Error("a killed worker must not report failure")
	}
}

func TestMissingConsumerReportsUnboundThenBinds(t *testing.T) {
	e := newPullEnv(t)
	const model = "harrier"
	// No stream, no consumer: an old gateway.
	var calls atomic.Int32
	p := fastPuller(e.client, "it-node", "ollama", model, fakeEmbedder(model, &calls))
	startPuller(t, p)

	time.Sleep(350 * time.Millisecond) // a few sync + retry cycles
	st := p.Status()
	if st["bound"] != false || fmt.Sprint(st["models"]) != "["+model+"]" {
		t.Fatalf("status = %v", st)
	}
	if p.Bound() {
		t.Fatal("Bound() true with no consumer")
	}

	// The gateway catches up: the worker binds on its retry timer.
	e.createWork(model, 5*time.Second)
	waitCond(t, 5*time.Second, "bind after the consumer appears", p.Bound)
	occupancy.SetSlots(map[string]int{"ollama": 4})
	e.publishJob(model, "job-late", []string{"x"})
	if _, ok := e.next("complete", 5*time.Second); !ok {
		t.Fatal("no work after late bind")
	}
}

func TestDroppedModelUnbindsAndInFlightFinishes(t *testing.T) {
	e := newPullEnv(t)
	const model = "harrier"
	e.createWork(model, 5*time.Second)
	occupancy.SetSlots(map[string]int{"ollama": 4})
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	good := fakeEmbedder(model, new(atomic.Int32))
	var mu sync.Mutex
	served := []embedServed{{Model: model, Backend: "ollama"}}
	p := fastPuller(e.client, "it-node", "ollama", model, func(ctx context.Context, b []byte) (int, []byte, error) {
		started <- struct{}{}
		<-release
		return good(ctx, b)
	})
	p.models = func() []embedServed { mu.Lock(); defer mu.Unlock(); return served }
	startPuller(t, p)
	e.publishJob(model, "job-inflight", []string{"x"})
	<-started

	mu.Lock()
	served = nil
	mu.Unlock()
	waitCond(t, 3*time.Second, "unbind", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.binds) == 0
	})
	close(release)
	if _, ok := e.next("complete", 5*time.Second); !ok {
		t.Fatal("in-flight work for a dropped model must still finish")
	}
}
