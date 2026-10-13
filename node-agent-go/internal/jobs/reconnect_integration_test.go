// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
)

// End-to-end proof for the 2026-08-02 incident: a node whose NATS server is
// killed and later restarted must rediscover the bus and RE-BIND its
// JetStream dispatch durable, not just reconnect the socket.
//
// The restart deliberately uses a FRESH JetStream store, so the TASKS stream
// and the node_<id>_dispatch consumer are both gone — the same state a
// recreated `noo-nats` container leaves behind. That is the case nats.go's
// automatic resubscription cannot cover, and the case where the agent
// previously went silently deaf while still heartbeating over HTTPS.
//
// Runs an in-process nats-server; it touches nothing outside the test.
func TestReconnectRebindsDispatchDurableAfterServerWipe(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: runs an in-process NATS server")
	}

	// Drive the repair loop fast.
	old := rebindInterval
	rebindInterval = 250 * time.Millisecond
	defer func() { rebindInterval = old }()

	port := freePort(t)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	nodeID := "it-node"

	srv := startNATS(t, port)

	// The in-process server has no authorization block; credentials are
	// fail-closed stage 1, so opt in explicitly.
	t.Setenv("NOO_NATS_ALLOW_ANONYMOUS", "1")

	c, err := messaging.Connect(url, nodeID)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if !c.WaitForConnection(context.Background(), 10*time.Second) {
		t.Fatal("initial connect never completed")
	}
	createTasksStream(t, c)

	exec := NewExecutor(c, nil, http.DefaultClient, "https", "https://127.0.0.1:1", nodeID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := exec.Subscribe(); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	go exec.EnsureBound(ctx)

	if !exec.Bound() {
		t.Fatal("dispatch durable not bound after the initial subscribe")
	}

	// Baseline: a dispatched job produces a job.failed event (the executor
	// rejects an unrunnable type immediately), proving delivery end to end.
	assertDispatchDelivered(t, c, nodeID, "job-before")

	// --- kill NATS ---
	srv.Shutdown()
	srv.WaitForShutdown()

	// The outage must become observable — this is the whole point of the
	// visibility change. Waiting on Status (not IsConnected) also covers the
	// window between nats.go flipping its status and running the callback.
	waitFor(t, 15*time.Second, "the outage to show up in Status", func() bool {
		st := c.Status()
		return !st.Connected &&
			st.State == messaging.StateReconnecting &&
			st.DisconnectedForSec != nil
	})

	// --- restart NATS on the same port with an empty JetStream store ---
	srv2 := startNATS(t, port)
	defer srv2.Shutdown()

	waitFor(t, 30*time.Second, "client to reconnect", func() bool {
		return c.IsConnected()
	})

	// The gateway recreates the stream on its own startup — which may land
	// AFTER the node has reconnected. Until it does, the executor cannot
	// bind, and the reconnect hook alone would have given up. EnsureBound
	// keeps trying.
	createTasksStream(t, c)

	waitFor(t, 30*time.Second, "dispatch durable to be re-bound", func() bool {
		return exec.Bound()
	})

	// --- the real assertion: dispatch works again ---
	assertDispatchDelivered(t, c, nodeID, "job-after")

	final := c.Status()
	if final.Connects < 2 {
		t.Errorf("Connects = %d, want >= 2 (initial + reconnect)", final.Connects)
	}
	if final.LastDisconnectedAt == nil {
		t.Error("the outage must remain visible in the status after recovery")
	}
	if final.DisconnectedForSec != nil {
		t.Error("DisconnectedForSec must clear once reconnected")
	}
}

// assertDispatchDelivered publishes a dispatch for an unrunnable job type and
// waits for the executor's job.failed event. It is the cheapest full
// round-trip: JetStream in, core event out, no docker or HTTP involved.
func assertDispatchDelivered(t *testing.T, c *messaging.Client, nodeID, jobID string) {
	t.Helper()

	got := make(chan string, 4)
	// Node-scoped subject: the agent names itself in
	// the subject so the gateway can refuse an event about a job dispatched
	// somewhere else.
	subject := "events.job.failed." + messaging.SubjectToken(nodeID)
	sub, err := c.NC().Subscribe(subject, func(m *nats.Msg) {
		var ev struct {
			JobID string `json:"job_id"`
		}
		_ = json.Unmarshal(m.Data, &ev)
		got <- ev.JobID
	})
	if err != nil {
		t.Fatalf("subscribe to %s: %v", subject, err)
	}
	defer sub.Unsubscribe()

	payload, _ := json.Marshal(map[string]any{
		"job_id": jobID,
		"type":   "definitely_not_a_job_type",
	})
	if _, err := c.JS().Publish(fmt.Sprintf("tasks.dispatch.%s", nodeID), payload); err != nil {
		t.Fatalf("publish dispatch %s: %v", jobID, err)
	}

	deadline := time.After(20 * time.Second)
	for {
		select {
		case id := <-got:
			if id == jobID {
				return
			}
		case <-deadline:
			t.Fatalf("dispatch %s was never delivered — the node is bus-deaf", jobID)
		}
	}
}

// createTasksStream mimics what the gateway does at startup.
func createTasksStream(t *testing.T, c *messaging.Client) {
	t.Helper()
	_, err := c.JS().AddStream(&nats.StreamConfig{
		Name:     "TASKS",
		Subjects: []string{"tasks.>"},
		Storage:  nats.MemoryStorage,
	})
	if err != nil && err != nats.ErrStreamNameAlreadyInUse {
		t.Fatalf("create TASKS stream: %v", err)
	}
}

func startNATS(t *testing.T, port int) *natsserver.Server {
	t.Helper()
	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      port,
		JetStream: true,
		StoreDir:  t.TempDir(), // fresh on every start — the wipe case
		NoLog:     true,
		NoSigs:    true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("start nats-server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(15 * time.Second) {
		t.Fatal("nats-server never became ready")
	}
	return srv
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", timeout, what)
}

// TestWatchdogRebindsAfterServerSideConsumerDeletion covers the residual
// silent-deaf class the reconnect hook can NEVER see: the durable consumer
// is deleted SERVER-side (an operator recreating the stream, a limits
// change) while the TCP connection stays up. Client-side
// Subscription.IsValid() keeps returning true, so before the ConsumerInfo
// verification the watchdog concluded "bound" forever and zero messages
// arrived again.
func TestWatchdogRebindsAfterServerSideConsumerDeletion(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: runs an in-process NATS server")
	}

	old := rebindInterval
	rebindInterval = 250 * time.Millisecond
	defer func() { rebindInterval = old }()

	port := freePort(t)
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	nodeID := "it-node2"

	srv := startNATS(t, port)
	defer srv.Shutdown()

	t.Setenv("NOO_NATS_ALLOW_ANONYMOUS", "1")

	c, err := messaging.Connect(url, nodeID)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if !c.WaitForConnection(context.Background(), 10*time.Second) {
		t.Fatal("initial connect never completed")
	}
	createTasksStream(t, c)

	exec := NewExecutor(c, nil, http.DefaultClient, "https", "https://127.0.0.1:1", nodeID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := exec.Subscribe(); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	go exec.EnsureBound(ctx)

	assertDispatchDelivered(t, c, nodeID, "job-before-delete")

	// Delete the durable SERVER-side. No disconnect happens, so the
	// reconnect hook never fires — only the watchdog's server-side
	// verification can notice.
	durable := fmt.Sprintf("node_%s_dispatch", nodeID)
	if err := c.JS().DeleteConsumer("TASKS", durable); err != nil {
		t.Fatalf("delete consumer: %v", err)
	}

	// The client-side subscription still LOOKS valid — that is the bug
	// class. (Do not assert Bound()==true here: nats.go may invalidate the
	// sub asynchronously on some server versions; the property under test
	// is recovery, not the exact lie.)

	// The watchdog must notice within a few ticks and re-bind.
	waitFor(t, 30*time.Second, "dispatch durable to be re-bound after server-side delete", func() bool {
		info, err := c.JS().ConsumerInfo("TASKS", durable)
		return err == nil && info != nil
	})

	assertDispatchDelivered(t, c, nodeID, "job-after-delete")
}
