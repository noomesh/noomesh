// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

const (
	testAddon    = "ao"
	testWorkload = "wk"
	testWorker   = "noo-wl-ao-wk"
	testDoorName = "noo-stunnel-ao-wk"
	testResv     = "0b9c5e1a-3c7d-4e0f-9a51-2f6d8c1b7a44"
)

// wlPKI is a test CA, a node leaf (the agent's client cert) and a way to
// issue door leaves.
type wlPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	pool   *x509.CertPool
	cfg    *config.Config
	nodeCN string
}

func newWLPKI(t *testing.T) *wlPKI {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wl test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &wlPKI{ca: ca, caKey: k, nodeCN: "node-agent-7", pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	p.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	crt, key := mkLeaf(t, ca, k, p.nodeCN, []string{p.nodeCN}, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	w := func(n string, b []byte) string {
		f := filepath.Join(dir, n)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	p.cfg = &config.Config{TLSCA: w("ca.crt", p.caPEM), TLSCert: w("node.crt", crt), TLSKey: w("node.key", key)}
	return p
}

// seen is what the door observed of one call.
type seen struct {
	header   http.Header
	path     string
	query    string
	body     string
	sni      string
	peerCN   string
	upgraded bool
}

type fakeDoor struct {
	addr string
	mu   sync.Mutex
	last seen
	n    int
}

func (d *fakeDoor) get() seen { d.mu.Lock(); defer d.mu.Unlock(); return d.last }

// startWLDoor runs an mTLS door whose leaf names `name`. It answers HTTP with
// a JSON body, and upgrades a WebSocket into an echo.
func startWLDoor(t *testing.T, p *wlPKI, name string) *fakeDoor {
	t.Helper()
	crt, key := mkLeaf(t, p.ca, p.caKey, name, []string{name}, x509.ExtKeyUsageServerAuth)
	pair, err := tls.X509KeyPair(crt, key)
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDoor{}
	up := websocket.Upgrader{} // default CheckOrigin: an Origin that reached us would be refused
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := seen{header: r.Header.Clone(), path: r.URL.Path, query: r.URL.RawQuery, body: string(b), sni: r.TLS.ServerName}
		if len(r.TLS.PeerCertificates) > 0 {
			s.peerCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		if websocket.IsWebSocketUpgrade(r) {
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			s.upgraded = true
			d.mu.Lock()
			d.last, d.n = s, d.n+1
			d.mu.Unlock()
			for {
				mt, m, err := c.ReadMessage()
				if err != nil {
					return
				}
				_ = c.WriteMessage(mt, m)
			}
		}
		d.mu.Lock()
		d.last, d.n = s, d.n+1
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"door":"ok"}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	d.addr = srv.Listener.Addr().String()
	return d
}

type fakeDoors struct {
	mu      sync.Mutex
	managed bool
	addrs   []string // answered in order, the last one repeating
	asked   int
	addrErr error
}

func (f *fakeDoors) NodeWorkloadOf(_ context.Context, name string) (string, string, bool, error) {
	if f.managed && name == testWorker {
		return testAddon, testWorkload, true, nil
	}
	return "", "", false, nil
}

func (f *fakeDoors) NodeWorkloadDoorAddr(context.Context, string, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addrErr != nil {
		return "", f.addrErr
	}
	i := f.asked
	if i >= len(f.addrs) {
		i = len(f.addrs) - 1
	}
	f.asked++
	return f.addrs[i], nil
}

func wlMux(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/containers/{name}/proxy/{path...}", s.handleContainerProxy)
	return mux
}

// gatewayHeaders are the three the gateway sets.
func gatewayHeaders(h http.Header) {
	h.Set("X-Noo-Reservation", testResv)
	h.Set("X-Noo-Requester-Sub", "addon:ao")
	h.Set("X-Noo-Requester-Role", "operator")
}

func TestNodeWorkloadHTTPGoesToTheDoorWithTheLeafAndTheDoorName(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	plain := 0
	container := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { plain++ }))
	defer container.Close()
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}},
		proxyTarget: func(string) (string, error) { return strings.TrimPrefix(container.URL, "http://"), nil }}

	req := httptest.NewRequest("POST", "/api/containers/"+testWorker+"/proxy/v1/run?x=1", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	gatewayHeaders(req.Header)
	rec := httptest.NewRecorder()
	wlMux(s).ServeHTTP(rec, req)

	if rec.Code != 200 || rec.Body.String() != `{"door":"ok"}` {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	g := door.get()
	if g.peerCN != p.nodeCN {
		t.Errorf("door saw client cert CN %q, want the node leaf %q", g.peerCN, p.nodeCN)
	}
	if g.sni != testDoorName {
		t.Errorf("SNI = %q, want %q", g.sni, testDoorName)
	}
	if g.path != "/v1/run" || g.query != "x=1" || g.body != `{"a":1}` {
		t.Errorf("path=%q query=%q body=%q", g.path, g.query, g.body)
	}
	if plain != 0 {
		t.Errorf("the container-IP path was used %d times", plain)
	}
}

func TestNodeWorkloadDoorAddressIsReResolvedEveryCall(t *testing.T) {
	p := newWLPKI(t)
	a, b := startWLDoor(t, p, testDoorName), startWLDoor(t, p, testDoorName)
	f := &fakeDoors{managed: true, addrs: []string{a.addr, b.addr}}
	s := &Server{cfg: p.cfg, workloadDoors: f}
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
		gatewayHeaders(req.Header)
		rec := httptest.NewRecorder()
		wlMux(s).ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("call %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if a.n != 1 || b.n != 1 {
		t.Errorf("door a saw %d, door b saw %d; each call must follow the address the daemon gave NOW", a.n, b.n)
	}
}

// A door whose leaf names another door is refused, even though the CA signed
// it and the address is the one the daemon reported.
func TestNodeWorkloadDoorWithAnotherNameIsRefused(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, "noo-stunnel-other-door")
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}}}
	req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
	gatewayHeaders(req.Header)
	rec := httptest.NewRecorder()
	wlMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", rec.Code)
	}
	if door.n != 0 {
		t.Errorf("the request reached a door that does not carry the workload's name")
	}
}

// A door signed by some other CA is refused too.
func TestNodeWorkloadDoorFromAnotherCAIsRefused(t *testing.T) {
	p, other := newWLPKI(t), newWLPKI(t)
	door := startWLDoor(t, other, testDoorName)
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}}}
	req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
	gatewayHeaders(req.Header)
	rec := httptest.NewRecorder()
	wlMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || door.n != 0 {
		t.Fatalf("got %d (door saw %d calls), want 502 and none", rec.Code, door.n)
	}
}

// An unreachable door is a 502 with a reason, and the request is NOT
// retried on a plain or container-IP connection.
func TestNodeWorkloadUnreachableDoorIs502WithNoFallback(t *testing.T) {
	p := newWLPKI(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	hits := 0
	container := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer container.Close()
	targetAsked := 0
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{dead}},
		proxyTarget: func(string) (string, error) {
			targetAsked++
			return strings.TrimPrefix(container.URL, "http://"), nil
		}}
	for name, f := range map[string]*fakeDoors{
		"closed port":    {managed: true, addrs: []string{dead}},
		"no door at all": {managed: true, addrErr: errors.New("no door container for ao/wk")},
	} {
		s.workloadDoors = f
		req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
		gatewayHeaders(req.Header)
		rec := httptest.NewRecorder()
		wlMux(s).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "door") {
			t.Errorf("%s: got %d %q, want 502 naming the door", name, rec.Code, rec.Body.String())
		}
	}
	if hits != 0 || targetAsked != 0 {
		t.Errorf("fell back to the container path: %d requests, %d target lookups", hits, targetAsked)
	}
}

func TestNodeWorkloadWithoutALeafOrCAIsRefusedNotDialledBare(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	for name, cfg := range map[string]*config.Config{
		"no leaf": {TLSCA: p.cfg.TLSCA},
		"no CA":   {TLSCert: p.cfg.TLSCert, TLSKey: p.cfg.TLSKey, TLSCA: filepath.Join(t.TempDir(), "absent.crt")},
	} {
		s := &Server{cfg: cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}}}
		req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
		gatewayHeaders(req.Header)
		rec := httptest.NewRecorder()
		wlMux(s).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Errorf("%s: got %d, want 502", name, rec.Code)
		}
	}
	if door.n != 0 {
		t.Errorf("the door was called %d times without a verified TLS session", door.n)
	}
}

// What the client could inject never reaches the worker; the gateway's three
// do, and where the two collide the gateway's value is the only one.
func TestNodeWorkloadHeadersAreAnAllowlist(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}}}

	req := httptest.NewRequest("POST", "/api/containers/"+testWorker+"/proxy/x", strings.NewReader("{}"))
	gatewayHeaders(req.Header)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// The client's own, never the gateway's.
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Authorization", "Bearer AGENT")
	req.Header.Set("Cookie", "session=1")
	req.Header.Set(UpstreamAuthHeader, "Bearer BROWSER")
	req.Header.Set("X-Noo-Admin", "true")
	req.Header.Set("X-Noo-Requester-Token", "secret")
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	req.Header.Set("X-Custom", "1")
	rec := httptest.NewRecorder()
	wlMux(s).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	got := door.get().header
	for _, k := range []string{"Origin", "Authorization", "Cookie", UpstreamAuthHeader, "X-Noo-Admin", "X-Noo-Requester-Token", "X-Forwarded-For", "X-Custom"} {
		if v := got.Values(k); len(v) != 0 {
			t.Errorf("worker saw %s = %v", k, v)
		}
	}
	for k, want := range map[string]string{
		"X-Noo-Reservation": testResv, "X-Noo-Requester-Sub": "addon:ao", "X-Noo-Requester-Role": "operator",
		"Content-Type": "application/json", "Accept": "application/json",
	} {
		if v := got.Values(k); len(v) != 1 || v[0] != want {
			t.Errorf("worker saw %s = %v, want exactly [%s]", k, v, want)
		}
	}
	for k := range got {
		if strings.HasPrefix(strings.ToLower(k), "x-noo-") {
			switch k {
			case "X-Noo-Reservation", "X-Noo-Requester-Sub", "X-Noo-Requester-Role":
			default:
				t.Errorf("an x-noo header outside the three reached the worker: %s", k)
			}
		}
	}
}

// The reservation is the gateway's UUID or the call is refused before the
// door is dialled. A header repeated cannot be told gateway from client.
func TestNodeWorkloadPeerHeadersAreValidated(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}}}
	cases := map[string]func(h http.Header){
		"missing":       func(h http.Header) { h.Del("X-Noo-Reservation") },
		"not a uuid":    func(h http.Header) { h.Set("X-Noo-Reservation", "abc") },
		"upper case":    func(h http.Header) { h.Set("X-Noo-Reservation", strings.ToUpper(testResv)) },
		"trailing junk": func(h http.Header) { h.Set("X-Noo-Reservation", testResv+"x") },
		"twice":         func(h http.Header) { h.Add("X-Noo-Reservation", "11111111-1111-4111-8111-111111111111") },
		"no sub":        func(h http.Header) { h.Del("X-Noo-Requester-Sub") },
		"role twice":    func(h http.Header) { h.Add("X-Noo-Requester-Role", "admin") },
	}
	for name, mut := range cases {
		req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
		gatewayHeaders(req.Header)
		mut(req.Header)
		rec := httptest.NewRecorder()
		wlMux(s).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
	}
	if door.n != 0 {
		t.Errorf("a refused call reached the door %d times", door.n)
	}
}

func TestNodeWorkloadWebSocketGoesToTheDoorWithTheLeafAndAllowlistedHeaders(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}}}
	agent := httptest.NewServer(wlMux(s))
	defer agent.Close()

	h := http.Header{}
	gatewayHeaders(h)
	h.Set("Origin", "https://evil.example")
	h.Set("Authorization", "Bearer AGENT")
	h.Set("Cookie", "session=1")
	h.Set("X-Noo-Admin", "true")
	h.Set("Sec-WebSocket-Protocol", "noo.v1")
	c, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(agent.URL, "http")+"/api/containers/"+testWorker+"/proxy/ws/chat?k=v", h)
	if err != nil {
		t.Fatalf("dial through the agent: %v (%v)", err, resp)
	}
	defer c.Close()
	if err := c.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, m, err := c.ReadMessage()
	if err != nil || string(m) != "hello" {
		t.Fatalf("echo = %q, %v", m, err)
	}
	g := door.get()
	if !g.upgraded || g.path != "/ws/chat" || g.query != "k=v" {
		t.Errorf("door saw upgraded=%v path=%q query=%q", g.upgraded, g.path, g.query)
	}
	if g.peerCN != p.nodeCN || g.sni != testDoorName {
		t.Errorf("door saw client CN %q, SNI %q", g.peerCN, g.sni)
	}
	for _, k := range []string{"Origin", "Authorization", "Cookie", "X-Noo-Admin"} {
		if v := g.header.Values(k); len(v) != 0 {
			t.Errorf("worker saw %s = %v on the upgrade", k, v)
		}
	}
	if g.header.Get("X-Noo-Reservation") != testResv || g.header.Get("X-Noo-Requester-Sub") != "addon:ao" || g.header.Get("X-Noo-Requester-Role") != "operator" {
		t.Errorf("worker saw peer headers %v", g.header)
	}
	if g.header.Get("Sec-WebSocket-Protocol") != "noo.v1" {
		t.Errorf("subprotocol not passed: %v", g.header)
	}
}

func TestNodeWorkloadWebSocketRefusals(t *testing.T) {
	p := newWLPKI(t)
	wrong := startWLDoor(t, p, "noo-stunnel-other-door")
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{wrong.addr}}}
	agent := httptest.NewServer(wlMux(s))
	defer agent.Close()
	base := "ws" + strings.TrimPrefix(agent.URL, "http") + "/api/containers/" + testWorker + "/proxy/ws"

	h := http.Header{}
	gatewayHeaders(h)
	_, resp, err := websocket.DefaultDialer.Dial(base, h)
	if err == nil || resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Errorf("a door with another name: err=%v resp=%v, want a 502 handshake refusal", err, resp)
	}
	h = http.Header{}
	_, resp, err = websocket.DefaultDialer.Dial(base, h)
	if err == nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no reservation: err=%v resp=%v, want 400", err, resp)
	}
	if wrong.n != 0 {
		t.Errorf("a refused upgrade reached the door")
	}
}

// Every container that is not an agent-managed workload keeps today's path:
// the loopback port, the upstream bearer, headers passed as they were.
func TestNonManagedContainerProxyIsUnchanged(t *testing.T) {
	var got http.Header
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotPath = r.Header.Clone(), r.URL.Path
		w.WriteHeader(201)
	}))
	defer backend.Close()
	p := newWLPKI(t)
	f := &fakeDoors{managed: false, addrs: []string{"127.0.0.1:1"}}
	s := &Server{cfg: p.cfg, workloadDoors: f,
		proxyTarget: func(string) (string, error) { return strings.TrimPrefix(backend.URL, "http://"), nil }}
	for _, name := range []string{testWorker, "noo-browser-ab12"} { // the first: an i163 / unlabelled one
		got = nil
		req := httptest.NewRequest("POST", "/api/containers/"+name+"/proxy/navigate", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer AGENT")
		req.Header.Set(UpstreamAuthHeader, "Bearer BROWSER")
		req.Header.Set("Cookie", "c=1")
		req.Header.Set("X-Custom", "kept")
		rec := httptest.NewRecorder()
		wlMux(s).ServeHTTP(rec, req)
		if rec.Code != 201 || gotPath != "/navigate" {
			t.Fatalf("%s: got %d path %q", name, rec.Code, gotPath)
		}
		if got.Get("Authorization") != "Bearer BROWSER" || got.Get(UpstreamAuthHeader) != "" ||
			got.Get("Cookie") != "c=1" || got.Get("X-Custom") != "kept" {
			t.Errorf("%s: headers changed on the existing path: %v", name, got)
		}
	}
	if f.asked != 0 {
		t.Errorf("a door address was looked up for a container that is not a node workload")
	}
}
