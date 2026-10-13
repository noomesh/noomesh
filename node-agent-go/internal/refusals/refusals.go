// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package refusals records the desired-state instructions this node
// DECLINED, so the controller learns about them.
//
// Before this there was no channel at all. `noo_backend_placements` has a
// `desired_state` column and nothing else — no observed state, no error —
// and the reconciler logged every failure to the node's own journal and
// stopped there (reconcile.Once: "Errors are logged, never fatal"). From
// the controller, a node that refused a placement looked exactly like a
// node that had never been asked.
//
// That was survivable while every refusal was an accident. It is not
// survivable now that the node refuses instructions ON PURPOSE — a mount
// outside its declared roots, an MCP command it does not allow-list, a
// placement env key that is not tuning. A wall the operator cannot see is
// a wall they will debug as a bug.
//
// So: the reconciler records refusals here, the heartbeat carries them to
// the gateway, and the gateway raises one operator alert per node. The
// registry is a package-level singleton for the same reason embedtarget is
// — the producer (reconcile) and the consumer (heartbeat) are wired at
// different points in agent startup, and a nil-channel between them is a
// silent hole of exactly the kind this package exists to close.
package refusals

import (
	"sort"
	"sync"
	"time"
)

// Refusal is one instruction this node declined, in the terms an operator
// needs to fix it: what was asked, what was refused, and why.
type Refusal struct {
	// Scope names the kind of instruction: "models_dir", "placement",
	// "placement_env", "mcp_server".
	Scope string `json:"scope"`
	// Target is the specific thing — the path, the backend, the server id.
	Target string `json:"target"`
	// Reason is the agent's own error text. It names the fix.
	Reason string `json:"reason"`
	// Since is when this refusal was FIRST recorded, RFC3339 UTC. A
	// refusal that keeps being re-recorded every tick keeps its original
	// timestamp, so an operator can tell a new problem from a standing one.
	Since string `json:"since"`
}

var (
	mu   sync.Mutex
	live = map[string]Refusal{}
)

func key(scope, target string) string { return scope + "\x00" + target }

// Record notes a refusal. Re-recording an identical (scope, target) keeps
// the original `Since` — this is called on every reconcile tick and a
// standing refusal must not look brand new each time.
func Record(scope, target, reason string) {
	mu.Lock()
	defer mu.Unlock()
	k := key(scope, target)
	if prev, ok := live[k]; ok {
		prev.Reason = reason
		live[k] = prev
		return
	}
	live[k] = Refusal{
		Scope:  scope,
		Target: target,
		Reason: reason,
		Since:  time.Now().UTC().Format(time.RFC3339),
	}
}

// Clear removes a refusal that no longer applies — the operator widened the
// roots, or the controller changed the instruction. Called on the success
// path so a fixed problem stops being reported; a refusal that could only
// ever be added would train operators to ignore the field.
func Clear(scope, target string) {
	mu.Lock()
	defer mu.Unlock()
	delete(live, key(scope, target))
}

// List returns the standing refusals, sorted for a stable heartbeat body
// (an unstable order would make every heartbeat look like a change).
// Empty slice, never nil: the heartbeat omits the key when there are none.
func List() []Refusal {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Refusal, 0, len(live))
	for _, r := range live {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// Reset drops every recorded refusal. Tests only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	live = map[string]Refusal{}
}
