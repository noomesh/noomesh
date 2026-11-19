// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/client"
)

// The heartbeat's `docker_engine` fact (i1058): which Docker Engine this node
// runs, so the controller can tell which nodes sit below the oldest engine the
// project tests. Three states, each explicit, so a reader never has to guess
// from an absent key (absent means an agent that predates the fact):
//
//	{"state":"ok","version":"27.3.1","kind":"dockerd"|"docker-desktop"|"podman"}
//	{"state":"none"}                       no Docker on this node
//	{"state":"unreadable","error":"..."}   Docker is there, its version is not
const (
	EngineStateOK         = "ok"
	EngineStateNone       = "none"
	EngineStateUnreadable = "unreadable"

	EngineKindDockerd = "dockerd"
	EngineKindDesktop = "docker-desktop"
	EngineKindPodman  = "podman"
)

// The engine version changes only when the daemon is upgraded, so a good
// answer is kept for an hour; "none" and "unreadable" are asked again sooner,
// since a daemon that was starting may answer now.
const (
	engineOKTTL    = time.Hour
	engineRetryTTL = 5 * time.Minute
	// maxEngineErrLen keeps the error inside the gateway's per-value cap.
	maxEngineErrLen = 200
)

// engineProbe caches the `/version` answer. version is the daemon call;
// noDocker says whether its error means no daemon exists here at all.
type engineProbe struct {
	version  func(ctx context.Context) (client.ServerVersionResult, error)
	noDocker func(err error) bool
	now      func() time.Time

	mu      sync.Mutex
	report  map[string]any
	expires time.Time
}

// Report is the cached `docker_engine` value, probing when it has expired.
func (p *engineProbe) Report(ctx context.Context) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.report != nil && now.Before(p.expires) {
		return copyReport(p.report)
	}
	res, err := p.version(ctx)
	p.report = engineReport(res, err, p.noDocker)
	ttl := engineRetryTTL
	if p.report["state"] == EngineStateOK {
		ttl = engineOKTTL
	}
	p.expires = now.Add(ttl)
	return copyReport(p.report)
}

func copyReport(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// engineReport turns one `/version` answer into the fact.
func engineReport(res client.ServerVersionResult, err error, noDocker func(error) bool) map[string]any {
	if err != nil {
		if noDocker != nil && noDocker(err) {
			return map[string]any{"state": EngineStateNone}
		}
		msg := err.Error()
		if len(msg) > maxEngineErrLen {
			msg = msg[:maxEngineErrLen]
		}
		return map[string]any{"state": EngineStateNone}
	}
	v := strings.TrimSpace(res.Version)
	if v == "" {
		return map[string]any{"state": EngineStateUnreadable, "error": "the daemon's /version answer carries no Version"}
	}
	if len(v) > 64 {
		v = v[:64]
	}
	return map[string]any{"state": EngineStateOK, "version": v, "kind": engineKind(res)}
}

// engineKind: Podman's compat API names a "Podman Engine" component; Docker
// Desktop names itself in Platform.Name ("Docker Desktop 4.49.0 (208003)");
// anything else is a plain dockerd ("Docker Engine - Community", or empty).
func engineKind(res client.ServerVersionResult) string {
	for _, c := range res.Components {
		if strings.Contains(strings.ToLower(c.Name), "podman") {
			return EngineKindPodman
		}
	}
	name := strings.ToLower(res.Platform.Name)
	switch {
	case strings.Contains(name, "podman"):
		return EngineKindPodman
	case strings.Contains(name, "docker desktop"):
		return EngineKindDesktop
	}
	return EngineKindDockerd
}

// socketAbsent is the "no Docker here" test: the call could not connect and
// the daemon's unix socket does not exist. A socket that exists but refuses,
// a TCP host, or any other error is "unreadable", never "none".
func socketAbsent(daemonHost string) func(error) bool {
	return func(err error) bool {
		if !client.IsErrConnectionFailed(err) {
			return false
		}
		u, perr := url.Parse(daemonHost)
		if perr != nil || u.Scheme != "unix" {
			return false
		}
		path := u.Path
		if path == "" {
			path = u.Opaque
		}
		_, serr := os.Stat(path)
		return errors.Is(serr, os.ErrNotExist)
	}
}

// EngineReport is the heartbeat's `docker_engine` fact for this client's
// daemon (cached; see engineProbe).
func (c *Client) EngineReport(ctx context.Context) map[string]any {
	c.engineOnce.Do(func() {
		c.engine = &engineProbe{
			version: func(ctx context.Context) (client.ServerVersionResult, error) {
				return c.docker.ServerVersion(ctx, client.ServerVersionOptions{})
			},
			noDocker: socketAbsent(c.docker.DaemonHost()),
			now:      time.Now,
		}
	})
	return c.engine.Report(ctx)
}
