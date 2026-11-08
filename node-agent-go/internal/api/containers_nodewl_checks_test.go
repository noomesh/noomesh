// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
)

// i300 F5c: the checks the first test pass left masked by another layer or
// not reached by any test. Each test here is red when its one check alone is
// disabled.

// recDoors claims every name it is asked about is the workload's worker, and
// records what it was asked. addr/addrErr are answered TOGETHER, so a caller
// that ignores addrErr dials a real door and would succeed.
type recDoors struct {
	mu      sync.Mutex
	of      []string
	ofErr   error
	addr    string
	addrErr error
}

func (f *recDoors) NodeWorkloadOf(_ context.Context, name string) (string, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.of = append(f.of, name)
	if f.ofErr != nil {
		return "", "", false, f.ofErr
	}
	return testAddon, testWorkload, true, nil
}

func (f *recDoors) NodeWorkloadDoorAddr(context.Context, string, string) (string, error) {
	return f.addr, f.addrErr
}

func (f *recDoors) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.of...)
}

// A name that fails ValidateManagedContainerName never reaches the workload
// lookup: it gets the plain path's 400, not the lookup's answer.
func TestContainerProxyNameGateRunsBeforeTheWorkloadLookup(t *testing.T) {
	p := newWLPKI(t)
	for _, name := range []string{"other-box", "noo-node-agent", "noo-has$dollar"} {
		f := &recDoors{}
		resolved := 0
		s := &Server{cfg: p.cfg, workloadDoors: f,
			proxyTarget: func(string) (string, error) { resolved++; return "127.0.0.1:1", nil }}
		req := httptest.NewRequest("GET", "/api/containers/"+name+"/proxy/x", nil)
		gatewayHeaders(req.Header)
		rec := httptest.NewRecorder()
		wlMux(s).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d %q, want the plain path's 400", name, rec.Code, rec.Body.String())
		}
		if got := f.asked(); len(got) != 0 {
			t.Errorf("%s: the workload lookup ran for an invalid name: %v", name, got)
		}
		if resolved != 0 {
			t.Errorf("%s: the container target was resolved for an invalid name", name)
		}
	}
}

// When the daemon cannot say whether the container is a node workload, the
// answer is 502; the request is never treated as a plain container.
func TestContainerProxyLookupErrorIs502WithNoFallback(t *testing.T) {
	p := newWLPKI(t)
	hits := 0
	container := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer container.Close()
	resolved := 0
	f := &recDoors{ofErr: errors.New("docker daemon unreachable")}
	s := &Server{cfg: p.cfg, workloadDoors: f,
		proxyTarget: func(string) (string, error) {
			resolved++
			return strings.TrimPrefix(container.URL, "http://"), nil
		}}
	req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
	gatewayHeaders(req.Header)
	rec := httptest.NewRecorder()
	wlMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "cannot tell whether the container is a node workload") {
		t.Errorf("got %d %q, want 502 saying it cannot tell", rec.Code, rec.Body.String())
	}
	if hits != 0 || resolved != 0 {
		t.Errorf("fell back to the plain container proxy: %d requests, %d target lookups", hits, resolved)
	}
}

// Blank and oversize peer values are refused; 512 bytes is the last one
// accepted. The door is never reached by a refused call.
func TestNodeWorkloadPeerHeaderBlankAndLengthLimits(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}}}
	long := func(n int) string { return strings.Repeat("a", n) }
	type tc struct {
		name string
		mut  func(h http.Header)
		want int
	}
	cases := []tc{
		{"sub blank", func(h http.Header) { h.Set("X-Noo-Requester-Sub", "") }, 400},
		{"sub spaces", func(h http.Header) { h.Set("X-Noo-Requester-Sub", "   ") }, 400},
		{"role blank", func(h http.Header) { h.Set("X-Noo-Requester-Role", "") }, 400},
		{"reservation blank", func(h http.Header) { h.Set("X-Noo-Reservation", "") }, 400},
		{"sub 513 bytes", func(h http.Header) { h.Set("X-Noo-Requester-Sub", long(513)) }, 400},
		{"role 513 bytes", func(h http.Header) { h.Set("X-Noo-Requester-Role", long(513)) }, 400},
		{"sub 512 bytes", func(h http.Header) { h.Set("X-Noo-Requester-Sub", long(512)) }, 200},
	}
	for _, c := range cases {
		before := door.n
		req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
		gatewayHeaders(req.Header)
		c.mut(req.Header)
		rec := httptest.NewRecorder()
		wlMux(s).ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: got %d %q, want %d", c.name, rec.Code, rec.Body.String(), c.want)
		}
		if c.want != 200 && door.n != before {
			t.Errorf("%s: a refused call reached the door", c.name)
		}
	}
}

// Only a websocket upgrade is relayed; any other Upgrade is a 400 and never
// reaches the door.
func TestNodeWorkloadNonWebSocketUpgradeIsRefused(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	s := &Server{cfg: p.cfg, workloadDoors: &fakeDoors{managed: true, addrs: []string{door.addr}}}
	cases := map[string]func(h http.Header){
		"h2c with Connection": func(h http.Header) { h.Set("Connection", "Upgrade"); h.Set("Upgrade", "h2c") },
		"h2c alone":           func(h http.Header) { h.Set("Upgrade", "h2c") },
		"Connection alone":    func(h http.Header) { h.Set("Connection", "keep-alive, Upgrade") },
	}
	for name, mut := range cases {
		req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
		gatewayHeaders(req.Header)
		mut(req.Header)
		rec := httptest.NewRecorder()
		wlMux(s).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "websocket") {
			t.Errorf("%s: got %d %q, want 400 naming websocket", name, rec.Code, rec.Body.String())
		}
	}
	if door.n != 0 {
		t.Errorf("a refused upgrade reached the door %d times", door.n)
	}
}

// A failed door-address lookup is its own 502. The fake answers the lookup
// with BOTH an error and a live door's address, so a caller that ignored the
// error would dial the door and get a 200 rather than fail on an empty address.
func TestNodeWorkloadDoorAddrErrorIs502EvenWithAnAddress(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	s := &Server{cfg: p.cfg, workloadDoors: &recDoors{addr: door.addr, addrErr: errors.New("no door container for ao/wk")}}
	req := httptest.NewRequest("GET", "/api/containers/"+testWorker+"/proxy/x", nil)
	gatewayHeaders(req.Header)
	rec := httptest.NewRecorder()
	wlMux(s).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "is not reachable") {
		t.Errorf("got %d %q, want 502 'is not reachable'", rec.Code, rec.Body.String())
	}
	if door.n != 0 {
		t.Errorf("the door was dialled after its address lookup failed")
	}
}

// doorTransport, called directly: each refusal stands on its own, told apart
// by what the error says, so none can hide behind another layer (a nil CA pool
// would fall back to system roots; an empty leaf path would fail in the key
// load).
func TestDoorTransportRefusals(t *testing.T) {
	p := newWLPKI(t)
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"CA not loadable", &config.Config{TLSCA: filepath.Join(dir, "absent.crt"), TLSCert: p.cfg.TLSCert, TLSKey: p.cfg.TLSKey}, "cluster CA"},
		{"CA not PEM", &config.Config{TLSCA: garbage, TLSCert: p.cfg.TLSCert, TLSKey: p.cfg.TLSKey}, "cluster CA"},
		{"no leaf cert path", &config.Config{TLSCA: p.cfg.TLSCA, TLSKey: p.cfg.TLSKey}, "no leaf certificate"},
		{"no leaf key path", &config.Config{TLSCA: p.cfg.TLSCA, TLSCert: p.cfg.TLSCert}, "no leaf certificate"},
		{"leaf not loadable", &config.Config{TLSCA: p.cfg.TLSCA, TLSCert: garbage, TLSKey: garbage}, "leaf is not loadable"},
	}
	for _, c := range cases {
		s := &Server{cfg: c.cfg}
		tr, err := s.doorTransport(testDoorName, "127.0.0.1:1")
		if err == nil {
			t.Errorf("%s: got a transport (RootCAs set: %v), want an error", c.name, tr.TLSClientConfig.RootCAs != nil)
			continue
		}
		if tr != nil {
			t.Errorf("%s: a transport came back with the error", c.name)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not say %q", c.name, err, c.want)
		}
	}
}

// The door's name is pinned in the TLS config itself, not only carried by the
// URL host: a door whose leaf is valid for a different name is refused even
// when the request's URL names exactly what the leaf carries. The mirror case
// shows the pin is what is checked: the URL names something else entirely and
// the right door still verifies.
func TestDoorTransportPinsTheServerName(t *testing.T) {
	p := newWLPKI(t)
	door := startWLDoor(t, p, testDoorName)
	s := &Server{cfg: p.cfg}

	// Pinned to another door's name, URL host = the name the leaf DOES carry.
	tr, err := s.doorTransport("noo-stunnel-other-door", door.addr)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Transport: tr}
	if resp, err := cl.Get("https://" + testDoorName + "/x"); err == nil {
		resp.Body.Close()
		t.Errorf("a door valid for %q was accepted by a transport pinned to another name", testDoorName)
	}
	if door.n != 0 {
		t.Errorf("the request reached a door that failed the pinned name")
	}
	tr.CloseIdleConnections()

	// Pinned to the right name, URL host a name the leaf does not carry.
	tr, err = s.doorTransport(testDoorName, door.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get("https://not-the-door.example/x")
	if err != nil {
		t.Fatalf("pinned to %q, the right door was refused: %v", testDoorName, err)
	}
	resp.Body.Close()
	if door.get().sni != testDoorName {
		t.Errorf("SNI = %q, want the pinned %q", door.get().sni, testDoorName)
	}
	if tr.TLSClientConfig.ServerName != testDoorName || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("TLS config = ServerName %q MinVersion %x", tr.TLSClientConfig.ServerName, tr.TLSClientConfig.MinVersion)
	}
}
