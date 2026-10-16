// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package api

import (
	"fmt"
	"net"
	"strings"
)

// BindPlan is where the control API listens, decided from NODE_AGENT_BIND and
// the address the controller reaches this node on.
//
// The agent used to listen on every interface (":8081"). The only callers it
// has are the controller (over the tailnet or the registered LAN address),
// peer nodes at that same address, and this host's own processes on loopback;
// a docker bridge, a second NIC or a public address has none of them. So by
// default it binds the registered address plus loopback, and falls back to
// all interfaces only when no such address is known (logged, never silent).
type BindPlan struct {
	// Hosts to bind; "" means every interface.
	Hosts []string
	// Derived is the auto-detected address (so the listener can follow it if
	// it moves); "" when the operator chose the binding or nothing was known.
	Derived string
	// Why is the one log line explaining the choice.
	Why string
}

// PlanBind turns the setting and the detected address into a plan. detected
// is DetectHostIP's answer (already vetted as dialable by the caller, or "").
func PlanBind(setting, detected string) (BindPlan, error) {
	s := strings.TrimSpace(setting)
	switch strings.ToLower(s) {
	case "":
		ip := net.ParseIP(strings.TrimSpace(detected))
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return BindPlan{Hosts: []string{""}, Why: "no controller-reachable address known (NODE_IP unset and the route to the controller gave none): listening on ALL interfaces; set NODE_AGENT_BIND to an address to confine it"}, nil
		}
		return BindPlan{
			Hosts:   []string{ip.String(), "127.0.0.1", "::1"},
			Derived: ip.String(),
			Why:     "listening on the address the controller reaches this node on (" + ip.String() + ") and loopback; NODE_AGENT_BIND=all restores every interface",
		}, nil
	case "all", "0.0.0.0", "::", "*":
		return BindPlan{Hosts: []string{""}, Why: "NODE_AGENT_BIND=" + s + ": listening on ALL interfaces (explicit)"}, nil
	}
	var hosts []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		ip := net.ParseIP(h)
		if ip == nil {
			return BindPlan{}, fmt.Errorf("NODE_AGENT_BIND=%q: %q is not an IP address — use an address, a comma list, or `all`", setting, h)
		}
		hosts = append(hosts, ip.String())
	}
	return BindPlan{Hosts: hosts, Why: "NODE_AGENT_BIND: listening on " + strings.Join(hosts, ", ")}, nil
}

// listenAll opens one listener per host. The first host is required; the
// rest (loopback, ::1) are best effort, because a box with no IPv6 has no
// ::1 and that must not stop the agent.
func listenAll(hosts []string, port int) ([]net.Listener, error) {
	var out []net.Listener
	for i, h := range hosts {
		ln, err := net.Listen("tcp", net.JoinHostPort(h, fmt.Sprint(port)))
		if err != nil {
			if i == 0 || len(hosts) == 1 {
				for _, l := range out {
					_ = l.Close()
				}
				return nil, fmt.Errorf("control API cannot listen on %s: %w", net.JoinHostPort(h, fmt.Sprint(port)), err)
			}
			continue
		}
		out = append(out, ln)
	}
	return out, nil
}
