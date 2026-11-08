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
// default it binds the registered address plus loopback. When no such address
// is known it listens on LOOPBACK ONLY and waits for one (i515a, secure by
// default): it used to fall back to every interface. The node is then
// unreachable from the controller, loudly, until the address is known, and the
// listener rebinds within bindRecheck once it is. Every interface is only ever
// the written-down NODE_AGENT_BIND=all.
type BindPlan struct {
	// Hosts to bind; "" means every interface.
	Hosts []string
	// Derived is the auto-detected address (so the listener can follow it if
	// it moves); "" when the operator chose the binding or nothing was known.
	Derived string
	// Awaiting: no controller-reachable address was known, so this plan is
	// loopback only and the listener re-detects until one appears.
	Awaiting bool
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
			return BindPlan{
				Hosts:    []string{"127.0.0.1", "::1"},
				Awaiting: true,
				Why:      "no controller-reachable address known (NODE_IP unset and the route to the controller gave none): listening on LOOPBACK ONLY, so the controller cannot reach this node until the address is known (re-detected every minute); set NODE_IP, or NODE_AGENT_BIND to an address",
			}, nil
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

// followed: the listener re-detects the address and rebinds when it moves (a
// derived address) or appears (an awaited one). An explicit binding is not
// followed.
func (p BindPlan) followed() bool { return p.Derived != "" || p.Awaiting }

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
