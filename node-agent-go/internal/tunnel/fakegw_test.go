// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlrpc"
)

// ── a throwaway cluster PKI ─────────────────────────────────────────────

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  []byte
	next int64
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test cluster CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: c, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), next: 10}
}

func (ca *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// leaf issues a leaf with the given CN and organization.
func (ca *testCA) leaf(t *testing.T, cn, org string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca.next++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.next),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ── a fake gateway ──────────────────────────────────────────────────────

type frame struct {
	kind    byte
	id      uint32
	payload []byte
}

type fakeGW struct {
	t       *testing.T
	ca      *testCA
	srv     *httptest.Server
	gwLeaf  tls.Certificate // what the server presents and signs the challenge with
	signer  tls.Certificate // what signs the challenge (default: gwLeaf)
	nodeID  string
	window  int
	maxStrm int

	// upgradeStatus, when set, answers the upgrade with that status.
	upgradeStatus atomic.Int32
	// challengeFor overrides the node the challenge names ("" = the caller's).
	challengeFor string

	dials atomic.Int32
	conns chan *gwConn
	pings atomic.Int32
	// silent makes the server stop reading after the handshake, so pings go
	// unanswered.
	silent atomic.Bool
}

type gwConn struct {
	g      *fakeGW
	c      *websocket.Conn
	wmu    sync.Mutex
	frames chan frame
	hello  helloMsg
	done   chan struct{}
}

func newFakeGW(t *testing.T, ca *testCA, nodeID string, gwLeaf tls.Certificate) *fakeGW {
	g := &fakeGW{t: t, ca: ca, gwLeaf: gwLeaf, signer: gwLeaf, nodeID: nodeID,
		window: DefaultWindow, maxStrm: DefaultMaxStreams, conns: make(chan *gwConn, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc(Path, g.handle)
	g.srv = httptest.NewUnstartedServer(mux)
	g.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{gwLeaf},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool(),
		NextProtos:   []string{"http/1.1"},
	}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGW) handle(w http.ResponseWriter, r *http.Request) {
	g.dials.Add(1)
	if s := int(g.upgradeStatus.Load()); s != 0 {
		http.Error(w, `{"detail":"nope"}`, s)
		return
	}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	c, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	gc := &gwConn{g: g, c: c, frames: make(chan frame, 1024), done: make(chan struct{})}
	c.SetPingHandler(func(m string) error {
		g.pings.Add(1)
		return c.WriteControl(websocket.PongMessage, []byte(m), time.Now().Add(time.Second))
	})
	nonce := base64.RawURLEncoding.EncodeToString(sha256Sum([]byte(time.Now().String())))
	ts := time.Now().Unix()
	node := g.nodeID
	if g.challengeFor != "" {
		node = g.challengeFor
	}
	sig, alg, cert := signLeaf(g.signer, []byte(ChallengeCanonical(node, nonce, ts)))
	ch, _ := json.Marshal(challengeMsg{T: "challenge", V: 1, Node: node, Nonce: nonce, TS: ts, Alg: alg, Sig: sig, Cert: cert})
	_ = c.WriteMessage(websocket.TextMessage, ch)
	_, data, err := c.ReadMessage()
	if err != nil {
		c.Close()
		return
	}
	if json.Unmarshal(data, &gc.hello) != nil || gc.hello.Nonce != nonce {
		c.Close()
		return
	}
	ready, _ := json.Marshal(readyMsg{T: "ready", V: 1, Window: g.window, MaxStreams: g.maxStrm})
	_ = c.WriteMessage(websocket.TextMessage, ready)
	g.conns <- gc
	if g.silent.Load() {
		<-gc.done // never read again: the node's pings go unanswered
		return
	}
	for {
		typ, data, err := c.ReadMessage()
		if err != nil {
			close(gc.frames)
			return
		}
		if typ != websocket.BinaryMessage {
			continue
		}
		k, id, p, err := decode(data)
		if err != nil {
			continue
		}
		gc.frames <- frame{k, id, append([]byte(nil), p...)}
	}
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func signLeaf(c tls.Certificate, msg []byte) (sig, alg, cert string) {
	ls, err := newLeafSigner(c)
	if err != nil {
		panic(err)
	}
	s, err := ls.sign(msg)
	if err != nil {
		panic(err)
	}
	return s, ls.alg, ls.cert
}

func (gc *gwConn) write(kind byte, id uint32, payload []byte) {
	gc.wmu.Lock()
	defer gc.wmu.Unlock()
	_ = gc.c.WriteMessage(websocket.BinaryMessage, encode(kind, id, payload))
}

func (gc *gwConn) open(id uint32, method, path string, headers [][2]string) {
	b, _ := json.Marshal(openMsg{Method: method, Path: path, Headers: headers, Principal: "controller"})
	gc.write(FrameOpen, id, b)
}

func (gc *gwConn) next(t *testing.T) frame {
	t.Helper()
	select {
	case f, ok := <-gc.frames:
		if !ok {
			t.Fatal("the node closed the tunnel")
		}
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a frame from the node")
	}
	return frame{}
}

// collect reads frames for stream id until END or RESET, returning the head
// status, the body and how the stream ended. CREDIT frames for other
// purposes are skipped.
func (gc *gwConn) collect(t *testing.T, id uint32) (status int, body []byte, ended string) {
	t.Helper()
	for {
		f := gc.next(t)
		if f.id != id {
			continue
		}
		switch f.kind {
		case FrameHead:
			var hm headMsg
			_ = json.Unmarshal(f.payload, &hm)
			status = hm.Status
		case FrameData:
			body = append(body, f.payload...)
			gc.write(FrameCredit, id, creditPayload(Cost(len(f.payload))))
		case FrameEnd:
			return status, body, "end"
		case FrameReset:
			return status, body, "reset: " + string(f.payload)
		}
	}
}

// ── a client against the fake ───────────────────────────────────────────

type rig struct {
	t      *testing.T
	ca     *testCA
	gw     *fakeGW
	client *Client
	node   tls.Certificate
}

// newRig builds a CA, a controller-org gateway and a client for node "host9".
func newRig(t *testing.T, h http.Handler, tweak func(*Options)) *rig {
	t.Helper()
	ca := newTestCA(t)
	gwLeaf := ca.leaf(t, "gateway", "Mesh Cluster Gateway")
	return newRigWith(t, ca, gwLeaf, h, tweak)
}

func newRigWith(t *testing.T, ca *testCA, gwLeaf tls.Certificate, h http.Handler, tweak func(*Options)) *rig {
	t.Helper()
	node := ca.leaf(t, "host9", "Mesh Cluster Node")
	g := newFakeGW(t, ca, "host9", gwLeaf)
	v, err := ctrlrpc.NewVerifier("host9", ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{
		NodeID: "host9", ControllerURL: g.srv.URL,
		TLS:      &tls.Config{RootCAs: ca.pool(), Certificates: []tls.Certificate{node}},
		Handler:  h,
		Verifier: v,
		RetryMin: 20 * time.Millisecond, RetryMax: 80 * time.Millisecond, NotOfferedRetry: time.Hour,
	}
	if tweak != nil {
		tweak(&opt)
	}
	c, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, ca: ca, gw: g, client: c, node: node}
}

// run starts the client and returns the first session's connection.
func (r *rig) run(t *testing.T) (*gwConn, func()) {
	t.Helper()
	ctx, cancel := contextWithCancel()
	done := make(chan struct{})
	go func() { r.client.Run(ctx); close(done) }()
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	select {
	case gc := <-r.gw.conns:
		waitFor(t, "the client to report connected", r.client.Connected)
		return gc, stop
	case <-time.After(5 * time.Second):
		t.Fatal("the client never connected")
	}
	return nil, stop
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
