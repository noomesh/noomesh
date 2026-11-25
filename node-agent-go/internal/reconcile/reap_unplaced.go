// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/backendreap"
	"github.com/noomesh/noomesh/node-agent-go/internal/ctrlreach"
	dockerpkg "github.com/noomesh/noomesh/node-agent-go/internal/docker"
)

// The node agent removes a backend container ONLY after an explicit unplace.
//
// Absence never reaps. A controller whose database came up empty, was
// restored from an older backup or is mid-restore answers desired-config
// with a good, fresh, stable "nothing placed", pass after pass; no freshness
// or agreement check defends against a controller that is confidently
// wrong. So a container no placement wants is REPORTED (orphan_backends) and
// left running. It is removed only when the controller ships an explicit
// tombstone for it (`unplaced`, written by the unplace in the same
// transaction as the placement DELETE), and only when every one of these
// holds:
//
//  1. a good read: desired-config answered 200 and decoded, `node` is not
//     null, and the controller is not away (ctrlreach);
//  2. `unplaced` names the backend and nothing in `placements` wants it (a
//     re-place wins);
//  3. the same tombstone (backend, role, unplaced_at) was in two
//     consecutive good reads, and this is not the first good pass since the
//     agent started;
//  4. the replay guard: Docker created the container BEFORE unplaced_at, so
//     a stale or restored tombstone never removes a container placed again
//     after it;
//  5. the controller lists `reap_unplaced_backends` in gateway_features;
//  6. exact ownership: `noo.managed-by=node-agent-go` and
//     `noo.backend=<b>` on a container named exactly the backend's container
//     name or its door's; never a native backend, the harness, a compose
//     service, a node workload or an add-on container.
//
// Then the backend goes through the existing stop path (StopBackend: stop
// with its timeout so a serving request drains, remove the container and its
// door). Model files, volumes, the PKI dir and images are never touched.

// reapFeature is the gateway_features entry that lets the agent act.
const reapFeature = "reap_unplaced_backends"

// unplacedTombstone is one entry of desired-config's `unplaced`.
type unplacedTombstone struct {
	Backend    string `json:"backend"`
	Role       string `json:"role"`
	UnplacedAt string `json:"unplaced_at"`
}

// forgetUnplaced drops what the last good read named: a failed read breaks
// "two consecutive good reads".
func (r *Reconciler) forgetUnplaced() {
	r.unplacedPrev = nil
}

// observeUnplaced records this read's tombstones and returns the ones that
// may be acted on: in this good read AND the previous one, never on the
// first good pass since the agent started. A read that is not good (no
// node, the controller away) forgets everything.
func (r *Reconciler) observeUnplaced(d *desiredConfig) []unplacedTombstone {
	away, _ := ctrlreach.Down()
	if d == nil || d.Node == nil || away {
		r.forgetUnplaced()
		return nil
	}
	r.goodReads++
	cur := map[unplacedTombstone]bool{}
	var confirmed []unplacedTombstone
	for _, u := range d.Unplaced {
		if u.Backend == "" || u.UnplacedAt == "" {
			continue
		}
		cur[u] = true
		if r.unplacedPrev[u] {
			confirmed = append(confirmed, u)
		}
	}
	r.unplacedPrev = cur
	if r.goodReads < 2 {
		return nil
	}
	return confirmed
}

// reapInput is everything planReap judges, gathered by the phase.
type reapInput struct {
	desired *desiredConfig
	// confirmed: the tombstones observeUnplaced passed (rules 1 and 3).
	confirmed      []unplacedTombstone
	controllerAway bool
	containers     []dockerpkg.ManagedContainer
	native         map[string]string
	nativeOnly     func(string) bool
}

// reapAction is one backend to stop.
type reapAction struct {
	backend    string
	container  string
	unplacedAt string
}

// wantedBackend: some placement, in any role or state, names the backend.
func wantedBackend(placements []placement, backend string) bool {
	for _, p := range placements {
		if p.Backend == backend {
			return true
		}
	}
	return false
}

// ownedBackendContainer is rule 6: this agent created c as backend b's
// container or door, by exact name, and b is a container backend it manages.
func ownedBackendContainer(c dockerpkg.ManagedContainer, b string, native map[string]string, nativeOnly func(string) bool) bool {
	if b == "" || b == "harness" {
		return false
	}
	if c.Labels[dockerpkg.ManagedByLabel] != dockerpkg.ManagedByNodeAgent || c.Labels[dockerpkg.BackendLabel] != b {
		return false
	}
	if c.Labels[dockerpkg.ComposeServiceLabel] != "" {
		return false
	}
	if _, ok := native[b]; ok {
		return false
	}
	if nativeOnly != nil && nativeOnly(b) {
		return false
	}
	name := dockerpkg.ContainerNameFor(b)
	door := dockerpkg.SidecarContainerFor(b)
	return (name != "" && c.Name == name) || (door != "" && c.Name == door)
}

// createdBefore is the replay guard: Docker's creation time (whole seconds,
// so the container was created somewhere in [created, created+1)) is before
// unplacedAt. An unreadable time is never before.
func createdBefore(created int64, unplacedAt string) bool {
	at, err := time.Parse(time.RFC3339Nano, unplacedAt)
	if err != nil || created <= 0 {
		return false
	}
	return !time.Unix(created+1, 0).After(at)
}

// planReap decides, purely, which backends to stop and which containers to
// report. The orphan report needs only a good read; a stop needs every rule.
func planReap(in reapInput) ([]reapAction, []backendreap.Orphan) {
	d := in.desired
	if d == nil || d.Node == nil {
		return nil, nil
	}
	named := map[string]bool{}
	for _, u := range d.Unplaced {
		named[u.Backend] = true
	}
	var orphans []backendreap.Orphan
	for _, c := range in.containers {
		b := c.Labels[dockerpkg.BackendLabel]
		if !ownedBackendContainer(c, b, in.native, in.nativeOnly) || wantedBackend(d.Placements, b) || named[b] {
			continue
		}
		orphans = append(orphans, backendreap.Orphan{Backend: b, Container: c.Name, Since: time.Unix(c.Created, 0).UTC().Format(time.RFC3339)})
	}
	if in.controllerAway || !slices.Contains(d.GatewayFeatures, reapFeature) {
		return nil, orphans
	}
	var acts []reapAction
	done := map[string]bool{}
	for _, u := range in.confirmed {
		if done[u.Backend] || wantedBackend(d.Placements, u.Backend) {
			continue
		}
		for _, c := range in.containers {
			if c.Name != dockerpkg.ContainerNameFor(u.Backend) || !ownedBackendContainer(c, u.Backend, in.native, in.nativeOnly) {
				continue
			}
			if !createdBefore(c.Created, u.UnplacedAt) {
				slog.Warn("reconcile.unplaced_backend_newer_than_unplace", "backend", u.Backend, "container", c.Name,
					"unplaced_at", u.UnplacedAt, "created", time.Unix(c.Created, 0).UTC().Format(time.RFC3339),
					"effect", "left running: the container was created after the unplace")
				continue
			}
			acts = append(acts, reapAction{backend: u.Backend, container: c.Name, unplacedAt: u.UnplacedAt})
			done[u.Backend] = true
			break
		}
	}
	return acts, orphans
}

// reapUnplacedBackends is the reconcile phase: report the orphans, and stop
// each backend planReap allows through the existing stop path.
func (r *Reconciler) reapUnplacedBackends(ctx context.Context, t *tick) bool {
	list := r.listManagedFn
	stop := r.stopBackendFn
	if r.docker != nil {
		if list == nil {
			list = r.docker.ManagedContainers
		}
		if stop == nil {
			stop = r.docker.StopBackend
		}
	}
	if list == nil || stop == nil {
		return true
	}
	containers, err := list(ctx)
	if err != nil {
		// Could not ask docker is not "nothing runs": no report, no stop.
		slog.Warn("reconcile.docker_list_failed", "error", err, "effect", "no unplace reaping or orphan report this pass")
		return true
	}
	away, _ := ctrlreach.Down()
	acts, orphans := planReap(reapInput{
		desired:        t.desired,
		confirmed:      t.reapConfirmed,
		controllerAway: away,
		containers:     containers,
		native:         t.native,
		nativeOnly:     r.reapNativeOnly(),
	})
	backendreap.SetOrphans(orphans)
	for _, a := range acts {
		slog.Info("reconcile.stopping_unplaced_backend", "backend", a.backend, "node", r.cfg.NodeID,
			"unplaced_at", a.unplacedAt, "container", a.container)
		if err := stop(ctx, a.backend); err != nil {
			slog.Warn("reconcile.stop_unplaced_backend_failed", "backend", a.backend, "error", err)
			continue
		}
		backendreap.RecordReaped(a.backend, a.unplacedAt, r.reapClock())
	}
	return true
}

func (r *Reconciler) reapNativeOnly() func(string) bool {
	if r.native == nil {
		return nil
	}
	return r.nativeOnly
}

func (r *Reconciler) reapClock() time.Time {
	if r.reapNow != nil {
		return r.reapNow()
	}
	return time.Now()
}
