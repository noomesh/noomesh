// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
)

// bindDurable's checks, each proven by its own mutant against the 0.6.24-rc.7
// code (noomesh-internal security-mutant pass, 2026-11-13). Before these tests,
// four of them could be removed with every test still green:
//
//   - a durable that already exists and delivers to ANOTHER subject is refused,
//     never adopted (the security check: adopting it would hand this node's
//     dispatches to whoever listens there, or this node someone else's);
//   - a durable it creates filters on its own subject and acks explicitly
//     (without explicit ack, a dispatch whose node crashes is never redelivered);
//   - a lookup error other than "not found" is returned, not treated as a
//     missing durable and subscribed past.
//
// Not pinned: nats.ManualAck() on the bound subscribe. Both handlers call
// msg.Ack() first, so without it nats.go's auto-ack only adds a second ack
// (a near-equivalent mutant).

// bindTestBus starts an in-process NATS server with the TASKS and EVENTS
// streams, connected as nodeID.
func bindTestBus(t *testing.T, nodeID string) *messaging.Client {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test: runs an in-process NATS server")
	}
	port := freePort(t)
	srv := startNATS(t, port)
	t.Cleanup(srv.Shutdown)
	t.Setenv("NOO_NATS_ALLOW_ANONYMOUS", "1")
	c, err := messaging.Connect(fmt.Sprintf("nats://127.0.0.1:%d", port), nodeID)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(c.Close)
	if !c.WaitForConnection(context.Background(), 10*time.Second) {
		t.Fatal("initial connect never completed")
	}
	createTasksStream(t, c)
	if _, err := c.JS().AddStream(&nats.StreamConfig{Name: "EVENTS", Subjects: []string{"events.>"}, Storage: nats.MemoryStorage}); err != nil {
		t.Fatalf("create EVENTS stream: %v", err)
	}
	return c
}

func TestBindRefusesADurableThatDeliversElsewhere(t *testing.T) {
	nodeID := "foreign-node"
	c := bindTestBus(t, nodeID)
	durable := "node_" + nodeID + "_dispatch"
	foreign := "_INBOX.someone-else.dispatch"
	if _, err := c.JS().AddConsumer("TASKS", &nats.ConsumerConfig{
		Durable:        durable,
		DeliverSubject: foreign,
		FilterSubject:  "tasks.dispatch." + nodeID,
		AckPolicy:      nats.AckExplicitPolicy,
	}); err != nil {
		t.Fatalf("pre-create the foreign durable: %v", err)
	}
	before, err := c.JS().ConsumerInfo("TASKS", durable)
	if err != nil {
		t.Fatalf("info: %v", err)
	}

	exec := NewExecutor(c, nil, http.DefaultClient, "https", "https://127.0.0.1:1", nodeID)
	err = exec.bindSubscriptions()
	if err == nil {
		t.Fatalf("bound to %s although it delivers to %q, not this node's %q", durable, foreign, deliverSubject(nodeID, "dispatch"))
	}
	if !strings.Contains(err.Error(), durable) || !strings.Contains(err.Error(), foreign) {
		t.Fatalf("the refusal does not name the durable and where it delivers: %v", err)
	}
	if exec.dispatchSub != nil {
		t.Fatal("a dispatch subscription was kept although the bind was refused")
	}

	// Refused, and left exactly as it was: the node never deletes or rewrites it.
	after, err := c.JS().ConsumerInfo("TASKS", durable)
	if err != nil {
		t.Fatalf("the refused durable is gone: %v", err)
	}
	if after.Config.DeliverSubject != foreign || !after.Created.Equal(before.Created) {
		t.Fatalf("the refused durable was changed: deliver %q (was %q), created %v (was %v)",
			after.Config.DeliverSubject, foreign, after.Created, before.Created)
	}
}

func TestACreatedDurableFiltersOnItsSubjectAndAcksExplicitly(t *testing.T) {
	nodeID := "fresh-node"
	c := bindTestBus(t, nodeID)
	exec := NewExecutor(c, nil, http.DefaultClient, "https", "https://127.0.0.1:1", nodeID)
	if err := exec.bindSubscriptions(); err != nil {
		t.Fatalf("bind: %v", err)
	}
	for _, d := range []struct{ stream, durable, filter, kind string }{
		{"TASKS", "node_" + nodeID + "_dispatch", "tasks.dispatch." + nodeID, "dispatch"},
		{"EVENTS", "node_" + nodeID + "_cancel", "events.job.cancel", "cancel"},
	} {
		info, err := c.JS().ConsumerInfo(d.stream, d.durable)
		if err != nil {
			t.Fatalf("%s was not created: %v", d.durable, err)
		}
		if info.Config.FilterSubject != d.filter {
			t.Errorf("%s filters on %q, want %q", d.durable, info.Config.FilterSubject, d.filter)
		}
		if info.Config.AckPolicy != nats.AckExplicitPolicy {
			t.Errorf("%s acks %v, want explicit: a dispatch whose node dies is never redelivered otherwise", d.durable, info.Config.AckPolicy)
		}
		if info.Config.DeliverSubject != deliverSubject(nodeID, d.kind) {
			t.Errorf("%s delivers to %q", d.durable, info.Config.DeliverSubject)
		}
	}
}

// lookupFails is a JetStream context whose ConsumerInfo fails with an error
// that is not "not found"; it records whether a subscribe was attempted.
type lookupFails struct {
	nats.JetStreamContext
	err        error
	subscribed bool
}

func (l *lookupFails) ConsumerInfo(string, string, ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	return nil, l.err
}

func (l *lookupFails) Subscribe(subj string, cb nats.MsgHandler, opts ...nats.SubOpt) (*nats.Subscription, error) {
	l.subscribed = true
	return l.JetStreamContext.Subscribe(subj, cb, opts...)
}

func TestALookupErrorIsReturnedNotSubscribedPast(t *testing.T) {
	nodeID := "lookup-node"
	c := bindTestBus(t, nodeID)
	durable := "node_" + nodeID + "_dispatch"
	// The durable exists and is this node's: only the lookup fails.
	if _, err := c.JS().AddConsumer("TASKS", &nats.ConsumerConfig{
		Durable:        durable,
		DeliverSubject: deliverSubject(nodeID, "dispatch"),
		FilterSubject:  "tasks.dispatch." + nodeID,
		AckPolicy:      nats.AckExplicitPolicy,
	}); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	boom := errors.New("context deadline exceeded (JetStream API)")
	js := &lookupFails{JetStreamContext: c.JS(), err: boom}

	sub, err := bindDurable(js, "TASKS", "tasks.dispatch."+nodeID, durable, deliverSubject(nodeID, "dispatch"), func(*nats.Msg) {})
	if sub != nil {
		_ = sub.Unsubscribe()
	}
	if !errors.Is(err, boom) {
		t.Fatalf("a failed lookup was not returned: err=%v", err)
	}
	if js.subscribed {
		t.Fatal("subscribed although the durable could not be looked up: an unverified consumer was bound")
	}
}
