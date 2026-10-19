// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package ctrlrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/noomesh/noomesh/node-agent-go/internal/messaging"
)

// The grants below are the ones noo-cli nats_users.rs renders for the
// gateway and for a node (TestNodeRpcGrantsMatchTheGoServiceTest pins the
// strings there); the embedded server enforces them for real, so a missing
// grant fails here the way it fails on a fleet: silently, until checked.
func nodeUser(id string, withRPC bool) *natsserver.User {
	sub := []string{"_INBOX_node_" + id + ".>", "mesh.inference.discover", "harness.run." + id}
	pub := []string{"events.job.ack." + id, "_INBOX_gw.node." + id + ".>"}
	if withRPC {
		sub = append(sub, "node."+id+".rpc.>")
		pub = append(pub, "node."+id+".evt.>")
	}
	return &natsserver.User{
		Username: "node-" + id, Password: "pw-" + id,
		Permissions: &natsserver.Permissions{
			Publish:   &natsserver.SubjectPermission{Allow: pub, Deny: []string{"node.*.rpc.>"}},
			Subscribe: &natsserver.SubjectPermission{Allow: sub},
			Response:  &natsserver.ResponsePermission{MaxMsgs: 1, Expires: 20 * time.Minute},
		},
	}
}

func startBus(t *testing.T, users ...*natsserver.User) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	gw := &natsserver.User{Username: "gateway", Password: "pw-gw", Permissions: &natsserver.Permissions{
		Publish: &natsserver.SubjectPermission{Allow: []string{">"}}, Subscribe: &natsserver.SubjectPermission{Allow: []string{">"}},
	}}
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: port, NoLog: true, NoSigs: true, Users: append(users, gw)})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats-server did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	return fmt.Sprintf("nats://127.0.0.1:%d", port)
}

func connectNode(t *testing.T, url, id string) *messaging.Client {
	t.Helper()
	t.Setenv("NATS_NODE_USER", "node-"+id)
	t.Setenv("NATS_NODE_PASSWORD", "pw-"+id)
	c, err := messaging.Connect(url, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if !c.WaitForConnection(context.Background(), 10*time.Second) {
		t.Fatal("node never connected")
	}
	return c
}

func connectGateway(t *testing.T, url string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(url, nats.UserInfo("gateway", "pw-gw"), nats.CustomInboxPrefix("_INBOX_gw"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

type fakeDisp struct {
	mu    sync.Mutex
	calls []Call
	async map[string]bool
	n     atomic.Int32
}

func (f *fakeDisp) RPCOp(op string) (bool, bool) {
	a, ok := f.async[op]
	return ok, a
}
func (f *fakeDisp) RPCDo(ctx context.Context, c Call) Result {
	f.n.Add(1)
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	return Result{Status: 200, ContentType: "application/json", Body: []byte(`{"op":"` + c.Op + `","arg":"` + c.Arg + `"}`)}
}

// request sends one signed control message the way the gateway does: reply
// inbox under the node's own prefix.
func request(t *testing.T, nc *nats.Conn, l leaf, node, op string, mutate func(*Envelope), body []byte) (*nats.Msg, error) {
	t.Helper()
	e := sign(t, l, op, node, time.Now(), fmt.Sprintf("n%015d", time.Now().UnixNano()), body)
	if mutate != nil {
		mutate(&e)
		// re-sign nothing: mutate is for fields that must be covered by the signature or not.
	}
	raw, _ := json.Marshal(e)
	h := nats.Header{}
	h.Set(HeaderEnvelope, string(raw))
	return nc.RequestMsg(&nats.Msg{Subject: "node." + node + ".rpc." + op, Header: h, Data: body}, 5*time.Second)
}

func startService(t *testing.T, url string, p *pki, id string, d Dispatcher) *Service {
	t.Helper()
	c := connectNode(t, url, id)
	v, err := NewVerifier(id, p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	s := NewService(c, id, v, d)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.Start(ctx)
	return s
}

func TestARoundTripRunsTheOpAndRepliesWithTheHandlersStatus(t *testing.T) {
	p, ctrl, _ := fixture(t)
	url := startBus(t, nodeUser("host9", true))
	d := &fakeDisp{async: map[string]bool{"health": false, "logs": false}}
	s := startService(t, url, p, "host9", d)
	if !s.Ready() {
		t.Fatal("a node with the grants must be ready (it advertises nats_rpc)")
	}
	gw := connectGateway(t, url)
	msg, err := request(t, gw, ctrl, "host9", "health", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get(HeaderStatus) != "200" || string(msg.Data) != `{"op":"health","arg":""}` {
		t.Fatalf("reply %q status %q", msg.Data, msg.Header.Get(HeaderStatus))
	}
	// The path argument and query ride the signed envelope.
	e := sign(t, ctrl, "logs", "host9", time.Now(), "q00000000000000001", nil)
	e.Arg, e.Query = "noo-gateway", "tail=5"
	// Not re-signed: must be refused (arg/query are covered by the signature).
	raw, _ := json.Marshal(e)
	h := nats.Header{}
	h.Set(HeaderEnvelope, string(raw))
	bad, err := gw.RequestMsg(&nats.Msg{Subject: "node.host9.rpc.logs", Header: h}, 5*time.Second)
	if err != nil || bad.Header.Get(HeaderStatus) != "403" {
		t.Fatalf("an arg changed after signing must be refused, got %v %v", bad, err)
	}
	if d.n.Load() != 1 {
		t.Fatalf("the refused message reached the handler (%d calls)", d.n.Load())
	}
}

func TestARefusedEnvelopeNeverReachesTheHandler(t *testing.T) {
	p, ctrl, _ := fixture(t)
	url := startBus(t, nodeUser("host9", true))
	d := &fakeDisp{async: map[string]bool{"stop": false}}
	startService(t, url, p, "host9", d)
	gw := connectGateway(t, url)

	// Unsigned.
	h := nats.Header{}
	h.Set(HeaderEnvelope, `{"v":1,"op":"stop","node":"host9"}`)
	m, err := gw.RequestMsg(&nats.Msg{Subject: "node.host9.rpc.stop", Header: h}, 5*time.Second)
	if err != nil || m.Header.Get(HeaderStatus) != "403" {
		t.Fatalf("unsigned: %v %v", m, err)
	}
	// No envelope header at all.
	m, err = gw.RequestMsg(&nats.Msg{Subject: "node.host9.rpc.stop"}, 5*time.Second)
	if err != nil || m.Header.Get(HeaderStatus) != "403" {
		t.Fatalf("headerless: %v %v", m, err)
	}
	// A node-organization key cannot command another node.
	nodeLeaf := p.leaf("Mesh Cluster Node", time.Now().Add(time.Hour))
	m, err = request(t, gw, nodeLeaf, "host9", "stop", nil, nil)
	if err != nil || m.Header.Get(HeaderStatus) != "403" {
		t.Fatalf("node-org leaf: %v %v", m, err)
	}
	// Replay of a captured good message.
	e := sign(t, ctrl, "stop", "host9", time.Now(), "replay0000000000001", nil)
	raw, _ := json.Marshal(e)
	h2 := nats.Header{}
	h2.Set(HeaderEnvelope, string(raw))
	for i, want := range []string{"200", "403"} {
		m, err = gw.RequestMsg(&nats.Msg{Subject: "node.host9.rpc.stop", Header: h2}, 5*time.Second)
		if err != nil || m.Header.Get(HeaderStatus) != want {
			t.Fatalf("send %d: want %s got %v %v", i, want, m, err)
		}
	}
	if d.n.Load() != 1 {
		t.Fatalf("handler ran %d times, want exactly 1 (the first, valid, send)", d.n.Load())
	}
}

func TestAnAsyncOpAcksAtOnceAndAnswersOnTheEventStream(t *testing.T) {
	p, ctrl, _ := fixture(t)
	url := startBus(t, nodeUser("host9", true))
	d := &fakeDisp{async: map[string]bool{"pull": true}}
	startService(t, url, p, "host9", d)
	gw := connectGateway(t, url)

	opID := "op-0123456789"
	events := make(chan *nats.Msg, 8)
	sub, err := gw.ChanSubscribe("node.host9.evt."+opID, events)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	gw.Flush()

	m, err := request(t, gw, ctrl, "host9", "pull", func(e *Envelope) {}, []byte(`{"kind":"image"}`))
	// The default request has no op_id: refused, and says why.
	if err != nil || m.Header.Get(HeaderStatus) != "400" {
		t.Fatalf("an async op without an op_id must be refused: %v %v", m, err)
	}

	e := sign(t, ctrl, "pull", "host9", time.Now(), "async000000000001", []byte(`{"kind":"image"}`))
	e.OpID, e.TimeoutS = opID, 60
	// op_id/timeout are part of the signature, so sign again with them set.
	e = resign(t, ctrl, e)
	raw, _ := json.Marshal(e)
	h := nats.Header{}
	h.Set(HeaderEnvelope, string(raw))
	ack, err := gw.RequestMsg(&nats.Msg{Subject: "node.host9.rpc.pull", Header: h, Data: []byte(`{"kind":"image"}`)}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Header.Get(HeaderStatus) != "202" || ack.Header.Get(HeaderAsync) != "1" {
		t.Fatalf("ack headers %v", ack.Header)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Header.Get(HeaderEvent) == "done" {
				if ev.Header.Get(HeaderStatus) != "200" || string(ev.Data) != `{"op":"pull","arg":""}` {
					t.Fatalf("done event %q status %q", ev.Data, ev.Header.Get(HeaderStatus))
				}
				return
			}
		case <-deadline:
			t.Fatal("no terminal event on node.host9.evt.<op_id>")
		}
	}
}

// resign recomputes the signature after fields were set.
func resign(t *testing.T, l leaf, e Envelope) Envelope {
	t.Helper()
	body := []byte(nil)
	_ = body
	n := sign(t, l, e.Op, e.Node, time.Unix(e.TS, 0), e.Nonce, nil)
	n.BodySHA256 = e.BodySHA256
	n.Arg, n.Query, n.OpID, n.TimeoutS = e.Arg, e.Query, e.OpID, e.TimeoutS
	return signCanonical(t, l, n)
}

func TestAPeerNodeCannotPublishToAnotherNodesRpcSubject(t *testing.T) {
	p, ctrl, _ := fixture(t)
	url := startBus(t, nodeUser("host9", true), nodeUser("host8", true))
	d := &fakeDisp{async: map[string]bool{"stop": false}}
	startService(t, url, p, "host9", d)

	// host8 holds a perfectly valid controller envelope (stolen) and tries to
	// publish it to host9. The server must refuse the publish itself.
	h8 := connectNode(t, url, "host8")
	e := sign(t, ctrl, "stop", "host9", time.Now(), "steal00000000000001", nil)
	raw, _ := json.Marshal(e)
	hdr := nats.Header{}
	hdr.Set(HeaderEnvelope, string(raw))
	before := time.Now()
	if err := h8.NC().PublishMsg(&nats.Msg{Subject: "node.host9.rpc.stop", Header: hdr}); err != nil {
		t.Fatal(err) // Publish returns nil on a denied publish; that is the trap.
	}
	_ = h8.NC().FlushTimeout(2 * time.Second)
	time.Sleep(300 * time.Millisecond)
	if d.n.Load() != 0 {
		t.Fatal("a peer node's publish reached host9's handler")
	}
	if len(h8.ViolationsSince(before, "node.host9.rpc.stop")) == 0 {
		t.Fatal("the server did not report the refused publish (the evidence that the gate held)")
	}
}

func TestADeniedSubscriptionMeansNotReady(t *testing.T) {
	p, _, _ := fixture(t)
	// An older controller NATS file: the node's user has no node.<id>.rpc.> grant.
	url := startBus(t, nodeUser("host9", false))
	d := &fakeDisp{async: map[string]bool{"health": false}}
	s := startService(t, url, p, "host9", d)
	if s.Ready() {
		t.Fatal("a node whose subscription the server refused must NOT advertise nats_rpc")
	}
}

func TestNoResponderIsImmediate(t *testing.T) {
	_, ctrl, _ := fixture(t)
	url := startBus(t, nodeUser("host9", true))
	gw := connectGateway(t, url)
	start := time.Now()
	_, err := request(t, gw, ctrl, "host9", "health", nil, nil)
	if err != nats.ErrNoResponders {
		t.Fatalf("want ErrNoResponders (a node that is not listening is DOWN, now), got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("no-responders must not wait for the timeout")
	}
}

func TestAnOversizedReplyIsMarkedForHTTPS(t *testing.T) {
	p, ctrl, _ := fixture(t)
	url := startBus(t, nodeUser("host9", true))
	big := &bigDisp{}
	startService(t, url, p, "host9", big)
	gw := connectGateway(t, url)
	m, err := request(t, gw, ctrl, "host9", "logs", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get(HeaderOverflow) != "1" || m.Header.Get(HeaderStatus) != "413" {
		t.Fatalf("overflow not marked: %v", m.Header)
	}
}

type bigDisp struct{}

func (bigDisp) RPCOp(op string) (bool, bool) { return op == "logs", false }
func (bigDisp) RPCDo(context.Context, Call) Result {
	return Result{Status: 200, ContentType: "application/json", Body: make([]byte, maxReply+1)}
}

// A refusal that arrives AFTER the bind (a re-rendered users file that
// dropped a grant, a reply or event publish the server denied) takes the
// advertisement back, so the controller stops sending control there.
func TestALaterRefusalTakesTheAdvertisementBack(t *testing.T) {
	p, _, _ := fixture(t)
	url := startBus(t, nodeUser("host9", true))
	c := connectNode(t, url, "host9")
	v, _ := NewVerifier("host9", p.caPEM)
	s := NewService(c, "host9", v, &fakeDisp{})
	s.Start(context.Background())
	if !s.Ready() {
		t.Fatal("not ready after a clean bind")
	}
	c.NoteViolationForTest(fmt.Errorf("nats: permissions violation: Permissions Violation for Publish to %q", "node.host9.evt.op-0123456789"))
	if s.Ready() {
		t.Fatal("still ready after the server refused one of this node's publishes")
	}
}

func TestANodeIdThatIsNotOneTokenNeverEnables(t *testing.T) {
	p, _, _ := fixture(t)
	url := startBus(t, nodeUser("host9", true))
	c := connectNode(t, url, "host9")
	v, _ := NewVerifier("a.b", p.caPEM)
	s := NewService(c, "a.b", v, &fakeDisp{})
	s.Start(context.Background())
	if s.Ready() {
		t.Fatal("an id with a dot cannot be named by a subject permission; the service must stay off")
	}
}
