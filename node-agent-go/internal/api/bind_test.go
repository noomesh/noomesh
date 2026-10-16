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

func TestPlanBind_NoKnownAddressFallsBackToAllInterfacesAndSaysSo(t *testing.T) {
	for _, detected := range []string{"", "127.0.0.1", "0.0.0.0", "not-an-ip"} {
		p, err := PlanBind("", detected)
		if err != nil || len(p.Hosts) != 1 || p.Hosts[0] != "" || !strings.Contains(p.Why, "ALL interfaces") {
			t.Fatalf("detected=%q: %+v err=%v", detected, p, err)
		}
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
