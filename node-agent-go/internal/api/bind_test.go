// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestPlanBind_DefaultIsTheRegisteredAddressPlusLoopback(t *testing.T) {
	p, err := PlanBind("", "100.64.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if p.Derived != "100.64.0.9" || p.Hosts[0] != "100.64.0.9" {
		t.Fatalf("plan = %+v", p)
	}
	for _, h := range p.Hosts {
		if h == "" || h == "0.0.0.0" {
			t.Fatalf("a derived plan must never include every interface: %+v", p)
		}
	}
	if !strings.Contains(strings.Join(p.Hosts, ","), "127.0.0.1") {
		t.Fatalf("loopback is how this host's own harness and healthcheck reach the agent: %+v", p)
	}
}

// i515a, secure by default: with no controller-reachable address known the
// agent listens on loopback ONLY and waits for one. It used to fall back to
// every interface. Every interface is only ever NODE_AGENT_BIND=all.
func TestPlanBind_NoKnownAddressListensOnLoopbackOnlyAndWaits(t *testing.T) {
	for _, detected := range []string{"", "127.0.0.1", "0.0.0.0", "not-an-ip"} {
		p, err := PlanBind("", detected)
		if err != nil || !p.Awaiting || p.Derived != "" {
			t.Fatalf("detected=%q: %+v err=%v", detected, p, err)
		}
		for _, h := range p.Hosts {
			ip := net.ParseIP(h)
			if ip == nil || !ip.IsLoopback() {
				t.Fatalf("detected=%q: host %q is not loopback, the agent would be reachable off-box: %+v", detected, h, p)
			}
		}
		if !strings.Contains(p.Why, "LOOPBACK ONLY") || !strings.Contains(p.Why, "NODE_AGENT_BIND") {
			t.Fatalf("detected=%q: the reason does not say what it did and how to change it: %q", detected, p.Why)
		}
	}
	// A known address is not awaited.
	if p, _ := PlanBind("", "100.64.0.9"); p.Awaiting {
		t.Fatalf("a known address is marked awaiting: %+v", p)
	}
}

func TestPlanBind_ExplicitValues(t *testing.T) {
	if p, _ := PlanBind("all", "100.64.0.9"); p.Hosts[0] != "" || p.Derived != "" {
		t.Fatalf("all: %+v", p)
	}
	p, err := PlanBind("100.64.0.9, 127.0.0.1", "10.0.0.5")
	if err != nil || len(p.Hosts) != 2 || p.Derived != "" {
		t.Fatalf("list: %+v %v", p, err)
	}
	if _, err := PlanBind("host3.local", ""); err == nil || !strings.Contains(err.Error(), "NODE_AGENT_BIND") {
		t.Fatalf("a hostname must be refused with a message naming the setting, got %v", err)
	}
}

// The property that matters: a confined listener is NOT reachable on the
// wildcard address. Binds loopback only, then proves 0.0.0.0:<port> is free.
func TestListenAll_ConfinedListenerDoesNotHoldTheWildcard(t *testing.T) {
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	lns, err := listenAll([]string{"127.0.0.1"}, port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, l := range lns {
			_ = l.Close()
		}
	}()
	if lns[0].Addr().String() != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
		t.Fatalf("bound %s", lns[0].Addr())
	}
	// A different loopback address on the same port is still free: the
	// listener is not on the wildcard.
	other, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("no 127.0.0.2 on this host: %v", err)
	}
	_ = other.Close()
}

// The listener follows an awaited address: without that, a worker whose
// tailnet comes up after the agent would stay on loopback, unreachable, until
// someone restarts it.
func TestPlanBind_AnAwaitedAddressIsFollowed(t *testing.T) {
	p, _ := PlanBind("", "")
	if !p.followed() {
		t.Fatalf("a loopback-only plan is not re-detected: the node stays unreachable: %+v", p)
	}
	if p, _ := PlanBind("", "100.64.0.9"); !p.followed() {
		t.Fatalf("a derived address is not followed: %+v", p)
	}
	for _, setting := range []string{"all", "100.64.0.9"} {
		if p, _ := PlanBind(setting, ""); p.followed() {
			t.Fatalf("NODE_AGENT_BIND=%s is followed: an explicit binding must stay put: %+v", setting, p)
		}
	}
}
