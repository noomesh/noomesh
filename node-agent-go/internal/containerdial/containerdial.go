// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package containerdial lets a HOST-PROCESS node-agent dial backends that
// are addressed by docker-DNS container names ("noo-reranker") on networks
// that publish no host ports — fu 52's re-cut gate for the agent-host
// cutover.
//
// The design point is WHERE the fix lives: at DialContext, not in the URLs.
// The agent builds backend URLs in several places (the inference reverse
// proxies, two plain http.Clients, the heartbeat's Ollama probe, the embed
// target) and rewriting them all would chase strings forever. A dialer swap
// fixes every site at once, and because the URL — and therefore the Host
// header, TLS SNI and certificate verification — is untouched, an https
// backend still verifies against its "noo-*" SAN while the socket goes to
// the bridge IP.
//
// Activation is HOST-MODE ONLY (`Install` is a no-op inside a container):
// in-container the compose network's DNS already answers, and keeping that
// path byte-identical is what makes this safe to ship ahead of the re-cut.
//
// Resolution order per dial: docker-inspect the host as a container name
// (the loopback-published door if the container has one, else its bridge
// IP); a name docker does not know falls back to the ordinary dialer. The fallback is what
// keeps /etc/hosts names working — "noo-controller" is a single-label name
// that is NOT a container on a worker, so its inspect fails and the normal
// path (hosts-file entry) proceeds untouched.
//
// Host mode itself is decided by hostMode, not by the /.dockerenv probe
// alone (newcomer rehearsal, 2026-09-28): a host-installed agent
// (noo-node-agent.service, /usr/local/bin/noo-node-agent) run on a box
// that is ITSELF a container — nested Docker, LXC, some VPS images — saw
// /.dockerenv and concluded it was the in-compose agent, so Install
// stayed a no-op and every backend proxy failed with
// "lookup noo-ollama on 127.0.0.11:53: no such host". hostMode instead
// asks how the process was STARTED: systemd sets INVOCATION_ID for every
// unit it launches (see deploy/noo-node-agent.service, Type=simple), and
// compose never starts a container that way, so its presence means "the
// systemd host service" regardless of what the enclosing box's own
// /.dockerenv says. An explicit NOO_AGENT_HOST_MODE=1|0 overrides both,
// for the environments neither heuristic reaches.
package containerdial

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// IPResolver is the one docker fact this package needs: the host:port the
// HOST can dial to reach a container's port. Satisfied by
// internal/docker.Client (ContainerDialAddr): a loopback-published door
// when the container has one (Docker Desktop on macOS, where bridge IPs
// are not routable from the host), the bridge IP otherwise (Linux). An
// interface so tests need no docker daemon.
type IPResolver interface {
	ContainerDialAddr(ctx context.Context, name, port string) (string, error)
}

// InContainer reports whether this process runs inside a container —
// the same /.dockerenv probe the rest of the tree uses. Kept as a
// standalone probe (other packages, e.g. internal/docker, use their own
// copy for a different purpose); Install no longer uses this alone — see
// hostMode.
func InContainer() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// hostMode is the pure decision behind Install's activation check, taking
// its inputs as parameters so it needs neither the filesystem nor the
// process environment to test. Rules, in order:
//
//  1. NOO_AGENT_HOST_MODE=1 or =0 — an explicit operator override; wins
//     over every heuristic below, for the one environment (some other
//     nested-container shape) neither heuristic reaches.
//  2. env("INVOCATION_ID") != "" — systemd sets this for every unit it
//     starts, including Type=simple services (noo-node-agent.service).
//     Compose never starts a container this way, so its presence is proof
//     the process is the systemd-launched host service, independent of
//     what /.dockerenv reports about the box it's running on.
//  3. Otherwise, the original /.dockerenv probe: present means
//     containerised (host mode false), absent means host mode true.
//
// Returns the decision and a short reason string for the startup log line.
func hostMode(env func(string) string, dockerenvExists bool) (bool, string) {
	switch env("NOO_AGENT_HOST_MODE") {
	case "1":
		return true, "NOO_AGENT_HOST_MODE=1 override"
	case "0":
		return false, "NOO_AGENT_HOST_MODE=0 override"
	}
	if env("INVOCATION_ID") != "" {
		return true, "systemd INVOCATION_ID set (noo-node-agent.service)"
	}
	if dockerenvExists {
		return false, "/.dockerenv present, no systemd invocation"
	}
	return true, "/.dockerenv absent, no systemd invocation"
}

type cacheEntry struct {
	addr    string // host:port to dial; empty = negative entry (name is not a container)
	err     error  // why the name did not resolve (kept for the error a container dial returns)
	expires time.Time
}

// Resolver caches name→IP so a chatty proxy does not inspect per dial.
// Positive entries live for ttl (container IPs change only on recreate);
// negative entries for a quarter of it, so a backend that starts a moment
// later is found promptly.
type Resolver struct {
	inner IPResolver
	ttl   time.Duration
	now   func() time.Time // injectable for tests

	mu    sync.Mutex
	cache map[string]cacheEntry
}

func New(inner IPResolver) *Resolver {
	return &Resolver{
		inner: inner,
		ttl:   10 * time.Second,
		now:   time.Now,
		cache: map[string]cacheEntry{},
	}
}

// candidateName reports whether host is worth asking docker about: a bare
// single-label name that is not an address. Dotted names (DNS), IPs and
// localhost never reach the docker daemon.
func candidateName(host string) bool {
	if host == "" || host == "localhost" {
		return false
	}
	if strings.Contains(host, ".") || strings.Contains(host, ":") {
		return false // dotted hostname, IPv4 with dots, or bracketless IPv6
	}
	return net.ParseIP(host) == nil
}

// resolve returns the host:port to dial for host:port, or "" when host is
// not a (running, addressable) container. key is name:port — a container's
// loopback-published door and its bridge IP answer per port.
func (r *Resolver) resolve(ctx context.Context, host, port string) string {
	key := net.JoinHostPort(host, port)
	now := r.now()
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && now.Before(e.expires) {
		r.mu.Unlock()
		return e.addr
	}
	r.mu.Unlock()

	addr, err := r.inner.ContainerDialAddr(ctx, host, port)
	entry := cacheEntry{addr: addr, expires: now.Add(r.ttl)}
	if err != nil || addr == "" {
		entry = cacheEntry{addr: "", err: err, expires: now.Add(r.ttl / 4)}
	}
	r.mu.Lock()
	r.cache[key] = entry
	r.mu.Unlock()
	return entry.addr
}

func (r *Resolver) evict(host, port string) {
	r.mu.Lock()
	delete(r.cache, net.JoinHostPort(host, port))
	r.mu.Unlock()
}

type dialFn = func(ctx context.Context, network, addr string) (net.Conn, error)

// WrapDialContext returns a dialer that rewrites container names to the
// address the host can reach them on (ContainerDialAddr).
//
// A name that IS a container never falls through to the ordinary dialer.
// It used to: a failed dial to the bridge IP (a vLLM still loading its
// model, so the port refuses) fell back to `net.Dial("noo-vllm:8000")`,
// which asked the system resolver and surfaced as
//
//	dial tcp: lookup noo-vllm on 100.100.100.100:53: no such host
//
// on every request of a cold load
// — a DNS error standing in for "connection refused", which sent the
// incident after name resolution instead of the backend. A failed dial is
// now retried ONCE against a fresh inspect (a recreated container has a
// new IP; the stale cache entry must not strand the caller until the TTL)
// and otherwise returned as what it is, naming the container and the
// address dialled. Only a name docker does not know (noo-controller on a
// worker, an /etc/hosts entry) takes the ordinary path.
func (r *Resolver) WrapDialContext(base dialFn) dialFn {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || !candidateName(host) {
			return base(ctx, network, addr)
		}
		target := r.resolve(ctx, host, port)
		if target == "" {
			return base(ctx, network, addr)
		}
		conn, derr := base(ctx, network, target)
		if derr == nil {
			return conn, nil
		}
		// Stale address after a recreate? Re-inspect once.
		r.evict(host, port)
		if fresh := r.resolve(ctx, host, port); fresh != "" {
			if fresh != target {
				conn, err2 := base(ctx, network, fresh)
				if err2 == nil {
					return conn, nil
				}
				derr, target = err2, fresh
			}
			return nil, fmt.Errorf("container %s (host-mode dial %s): %w", host, target, derr)
		}
		// Gone between the two inspects: say that, not a DNS miss.
		return nil, fmt.Errorf("container %s (host-mode dial %s, container no longer resolvable): %w", host, target, derr)
	}
}

// Install activates host-mode dialing process-wide. It wraps
// http.DefaultTransport (which every bare &http.Client{} in the tree uses)
// and returns the wrapped dial function so explicitly-constructed
// transports (the inference proxies, config.HTTPTransport) can adopt the
// same one. Inside a container it does nothing and returns nil — callers
// treat nil as "keep your default dialer". The mode and the reason for it
// are always logged, so a nested-container box's choice is visible in the
// journal without reproducing hostMode's inputs by hand.
func Install(inner IPResolver) dialFn {
	host, reason := hostMode(os.Getenv, InContainer())
	if !host {
		slog.Info("containerdial.mode", "mode", "container", "reason", reason)
		return nil
	}
	slog.Info("containerdial.mode", "mode", "host", "reason", reason)
	r := New(inner)
	base := (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	wrapped := r.WrapDialContext(base)
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t.DialContext = wrapped
	}
	return wrapped
}
