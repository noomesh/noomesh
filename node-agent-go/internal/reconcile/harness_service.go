// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostsvc"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// harnessRefusalTarget is the refusal row's target for the harness under
// the `backend_start` scope (#233) — the same row a container start
// failure lands in, so `noo cluster status` reads it in one place.
const harnessRefusalTarget = "harness"

// convergeHarness makes the host service match the placement: placed = running. It never starts a unit that is not installed —
// that is a refusal naming the fix — and a start the grant refuses is a
// refusal naming the grant. Read-only on every tick otherwise.
func (r *Reconciler) convergeHarness(ctx context.Context, p placement, all []placement) {
	if r.harness == nil {
		// Tests that build a Reconciler without one; nothing to converge.
		return
	}
	state := r.harness.State(ctx)
	switch p.DesiredState {
	case "running":
		// The kind is checked BEFORE anything
		// starts: a foreign runner is not shipped, and a kind the node's
		// chat backend cannot serve would take turns it cannot answer.
		// Both are refusals at placement time, not failures at turn time.
		if why := harnessKindRefusal(p, all, r.runnerInstalled, r.cliInstalled); why != "" {
			slog.Error("reconcile.harness_kind_refused", "detail", why)
			refusals.Record("backend_start", harnessRefusalTarget, why)
			return
		}
		// A start that SUCCEEDS and then dies is not a start.
		//
		// `systemctl start` on a Type=simple unit returns 0 the moment
		// systemd forks, so a harness whose binary cannot run or whose env
		// is incomplete gives rc=0 and a dead unit — and with
		// Restart=always and the start limit disabled, systemd restarts it
		// every 30 s forever. On host3 (2026-09-19, the first live roll of
		// the hostd lifecycle) that produced a harness which was never
		// running, never refused, and started again every tick: followup
		// 219's gap one layer along.
		//
		// The restart COUNTER is what catches it, and it is checked before
		// the state switch because a crash-looping unit reads `active` part
		// of the time — so the Running arm below would otherwise clear the
		// refusal on the strength of a lucky glance.
		if why := r.crashLooping(ctx); why != "" {
			slog.Error("reconcile.harness_restart_loop", "detail", why)
			refusals.Record("backend_start", harnessRefusalTarget, why)
			return
		}
		desiredKind := desiredHarnessKind(p)
		switch state {
		case hostsvc.Running:
			if r.harnessStartedKind == "" {
				// Running before this agent knew its kind (agent restart):
				// adopt the desired kind rather than bounce a live harness.
				r.harnessStartedKind = desiredKind
			}
			if harnessKindDecision(r.harnessStartedKind, desiredKind) == "restart" {
				slog.Info("reconcile.restarting_backend", "backend", "harness",
					"detail", "the placement's kind changed; restarting so the harness re-reads it",
					"from", r.harnessStartedKind, "to", desiredKind)
				if err := r.harness.Restart(ctx); err != nil {
					slog.Error("reconcile.restart_failed", "backend", "harness", "error", err)
					refusals.Record("backend_start", harnessRefusalTarget, err.Error())
					return
				}
				r.harnessStartedKind = desiredKind
			}
			refusals.Clear("backend_start", harnessRefusalTarget)
		case hostsvc.Absent:
			slog.Error("reconcile.harness_absent",
				"detail", hostsvc.ErrAbsent.Error())
			refusals.Record("backend_start", harnessRefusalTarget, hostsvc.ErrAbsent.Error())
		default:
			slog.Info("reconcile.starting_backend", "backend", "harness", "runtime", r.harness.Runtime())
			if err := r.harness.Start(ctx); err != nil {
				slog.Error("reconcile.start_failed", "backend", "harness", "error", err)
				refusals.Record("backend_start", harnessRefusalTarget, err.Error())
				return
			}
			r.harnessStartedKind = desiredKind
			// Deliberately NOT followed by a "did it come up?" check: the
			// unit is Type=simple with Restart=always and no start limit,
			// so `is-active` cycles and a point-in-time look would pass
			// falsely before the process dies and refuse falsely during a
			// slow start. The crash loop is caught by the restart counter
			// on the NEXT tick instead (see crashLooping), which needs no
			// window at all.
			refusals.Clear("backend_start", harnessRefusalTarget)
		}
	case "stopped":
		if r.stopHarness(ctx, state) {
			r.harnessStartedKind = ""
		}
	}
}

// desiredHarnessKind is the kind a harness placement names; `noo` when it
// names none.
func desiredHarnessKind(p placement) string {
	if k := strings.TrimSpace(p.Env["NOO_HARNESS_KIND"]); k != "" {
		return k
	}
	return "noo"
}

// harnessKindDecision is the pure restart decision: a harness started with
// one kind must be restarted when the placement now names another, so it
// re-reads its kind at startup. An unknown started kind ("") is kept.
func harnessKindDecision(startedKind, desiredKind string) string {
	if startedKind != "" && startedKind != desiredKind {
		return "restart"
	}
	return "keep"
}

// secretLookingEnvKey says whether a placement env key reads as a credential.
// GET /harness/placement leaves these out; the placement env is a tuning
// vocabulary (the node agent already refuses credentials in it) but the
// route fails closed.
func secretLookingEnvKey(k string) bool {
	u := strings.ToUpper(k)
	for _, s := range []string{"SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE", "AUTH", "KEY", "SIGNATURE"} {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}

// recordHarnessPlacement remembers the harness placement the controller
// currently desires (nil when none), for HarnessPlacementView.
func (r *Reconciler) recordHarnessPlacement(all []placement) {
	var found *placement
	for i := range all {
		if all[i].Backend == "harness" {
			cp := all[i]
			found = &cp
			break
		}
	}
	r.harnessMu.Lock()
	r.harnessDesired = found
	r.harnessMu.Unlock()
}

// HarnessPlacementView is the desired harness placement for the loopback
// route: kind, env without anything secret-looking, desired state. placed is
// false when no harness placement is desired (or it is stopped: a stopped
// harness has nothing to learn).
func (r *Reconciler) HarnessPlacementView() (kind string, env map[string]string, desiredState string, placed bool) {
	r.harnessMu.RLock()
	p := r.harnessDesired
	r.harnessMu.RUnlock()
	if p == nil {
		return "", nil, "", false
	}
	env = map[string]string{}
	for k, v := range p.Env {
		if !secretLookingEnvKey(k) {
			env[k] = v
		}
	}
	return desiredHarnessKind(*p), env, p.DesiredState, p.DesiredState != "stopped"
}

// reapUnplacedHarness stops a harness the controller no longer places.
//
// `noo cluster unplace <node> harness` DELETES the row, it does not set
// it to stopped, and the converge loop above only walks placements that
// are PRESENT — so an unplaced harness was never visited and the service
// ran on. For a container that is a documented shrug ("the container is
// left as-is"): it stays visible in `docker ps` and the operator can see
// what they left behind. For the harness it is not the same thing. The
// unit runs as a dedicated user holding node credentials and a bus
// subscription, and the gateway has already forgotten it exists — so
// nothing reports it, nothing converges it, and `noo cluster status`
// shows a node with no harness while one is running on it. Removing the
// placement has to mean the thing stops.
//
// Safe against a bad read: `Once` returns early on a fetch error and on
// an empty desired state, so reaching here means the controller answered
// and this node genuinely has no harness placement.
func (r *Reconciler) reapUnplacedHarness(ctx context.Context, all []placement) {
	if r.harness == nil {
		return
	}
	for _, p := range all {
		if p.Backend == "harness" {
			return // placed — convergeHarness owns it
		}
	}
	state := r.harness.State(ctx)
	if state != hostsvc.Running {
		return
	}
	slog.Info("reconcile.stopping_unplaced_harness", "backend", "harness",
		"detail", "no harness placement in desired state; stopping the host service")
	// Clear only on a CLEAN stop. Clearing unconditionally would erase
	// the refusal stopHarness had just recorded for a stop this node
	// could not perform — reporting "gone" for a harness still running.
	if r.stopHarness(ctx, state) {
		refusals.Clear("backend_start", harnessRefusalTarget)
	}
}

// stopHarness stops the service if it is running, and refuses loudly if
// this node cannot. Any of the three "this node cannot do it" shapes is
// worth a refusal on a STOP too: a harness left running because the
// privileged helper is down is exactly the state an operator must be told
// about, and silence here reads as a clean stop.
// It reports whether the service is now stopped.
func (r *Reconciler) stopHarness(ctx context.Context, state hostsvc.State) bool {
	if state != hostsvc.Running {
		return true
	}
	slog.Info("reconcile.stopping_backend", "backend", "harness")
	if err := r.harness.Stop(ctx); err != nil {
		slog.Warn("reconcile.stop_failed", "backend", "harness", "error", err)
		if errors.Is(err, hostsvc.ErrNoGrant) ||
			errors.Is(err, hostsvc.ErrNoHostd) ||
			errors.Is(err, hostsvc.ErrOpUnsupported) {
			refusals.Record("backend_start", harnessRefusalTarget, err.Error())
		}
		return false
	}
	return true
}

// HarnessState is what the heartbeat reports.
func (r *Reconciler) HarnessState(ctx context.Context) hostsvc.State {
	if r.harness == nil {
		return hostsvc.Absent
	}
	return r.harness.State(ctx)
}

// crashLooping reports why the harness is restarting, or "" when it is not.
//
// Detection is the restart counter CLIMBING between ticks — timing-free,
// where any "is it up right now" check flaps on a unit systemd is
// restarting every 30 s. The reason comes from the service manager's own
// words, which is what the operator actually needs: "result=exit-code
// exit_status=127" names a missing library; "status=..." names what the
// process said on its way out.
//
// The first observation only remembers: with nothing to compare against, a
// node whose harness has been looping since before the agent started would
// otherwise look healthy for one tick, and one tick is the right price for
// never reporting a loop that is not there.
func (r *Reconciler) crashLooping(ctx context.Context) string {
	n, ok := r.harness.Restarts(ctx)
	if !ok {
		return "" // darwin, or the counter could not be read
	}
	prev, seen := r.harnessRestarts, r.harnessRestartsSeen
	r.harnessRestarts, r.harnessRestartsSeen = n, true
	if !seen || n <= prev {
		return ""
	}
	why := strings.TrimSpace(r.harness.WhyNotRunning(ctx))
	detail := fmt.Sprintf("the harness keeps exiting and systemd keeps restarting it (%d restarts, %d since the last check)", n, n-prev)
	if why != "" {
		detail += ": " + why
	}
	return detail
}

// harnessKindRefusal is why a placement's kind cannot run here, or "".
// A kind is refused for what is ABSENT: a wire no running chat backend
// serves, a kind the table does not declare, a runner the table says does
// not ship, or a runner that ships but is not installed on this node.
// installed is the runner check and cliInstalled the vendor-CLI check (nil
// skips either).
func harnessKindRefusal(p placement, all []placement, installed func(runner string) bool, cliInstalled func(cli string) bool) string {
	kind := strings.TrimSpace(p.Env["NOO_HARNESS_KIND"])
	if kind == "" {
		kind = "noo"
	}
	for _, c := range all {
		if c.Backend == "harness" || c.DesiredState == "stopped" || (c.Role != "" && c.Role != "chat") {
			continue
		}
		if err := harnessKindCompatible(kind, c.Backend); err != nil {
			return err.Error()
		}
		break
	}
	k, known := harnessKindByName(kind)
	if !known {
		return fmt.Sprintf("unknown harness kind %q (known: %s)", kind, knownHarnessKinds())
	}
	if k.Runner == nil {
		return fmt.Sprintf("harness kind %q: its runner is not shipped yet", kind)
	}
	if installed != nil && !installed(*k.Runner) {
		return fmt.Sprintf("harness kind %q: its runner %q is not installed on this node", kind, *k.Runner)
	}
	if k.CLI != nil && cliInstalled != nil && !cliInstalled(*k.CLI) {
		return fmt.Sprintf("harness kind %q: its runner is present but the %q command is not installed on this node", kind, *k.CLI)
	}
	return ""
}
