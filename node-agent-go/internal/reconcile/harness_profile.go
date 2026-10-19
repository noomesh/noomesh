// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"

	"github.com/noomesh/noomesh/node-agent-go/internal/harnessprofile"
)

// ollamaContextKey is the placement env key the profile's ollama_context
// defaults (placementEnvExact and backendrt.OllamaTuningKeys allow it).
const ollamaContextKey = "OLLAMA_CONTEXT_LENGTH"

// applyHarnessProfile installs desired-config's `harness_profile` as the
// node's current profile. Called only on a SUCCESSFUL fetch, so a failed one
// keeps the last good profile. Absent clears it (today's behaviour). A
// malformed one is logged and the last good profile kept: a controller bug
// must not take a node's bounds back to defaults mid-flight.
func applyHarnessProfile(raw json.RawMessage) {
	p, err := harnessprofile.Parse(raw)
	if err != nil {
		slog.Warn("reconcile.harness_profile_unreadable",
			"error", err, "effect", "keeping the last good profile")
		return
	}
	harnessprofile.Set(p)
}

// profileOllamaContext is the value to default OLLAMA_CONTEXT_LENGTH to for
// an ollama whose env is env, or "" when nothing is injected: no profile, no
// ollama_context in it, or the placement already sets the key (the
// placement's own value is never touched).
func profileOllamaContext(env map[string]string, prof *harnessprofile.Profile) string {
	if prof == nil || prof.OllamaContext <= 0 {
		return ""
	}
	if v, ok := env[ollamaContextKey]; ok && strings.TrimSpace(v) != "" {
		return ""
	}
	return strconv.Itoa(prof.OllamaContext)
}

// withProfileOllamaContext returns the effective placements with the
// profile's ollama context default added to each RUNNING ollama placement
// whose env does not set it. The env map is copied, never mutated: the
// placement rows are the controller's. Applied before specHash, so the
// default is part of the container's spec and a change recreates it.
func withProfileOllamaContext(ps []placement, prof *harnessprofile.Profile) []placement {
	out := make([]placement, len(ps))
	copy(out, ps)
	for i, p := range out {
		if p.Backend != "ollama" || p.DesiredState != "running" {
			continue
		}
		v := profileOllamaContext(p.Env, prof)
		if v == "" {
			continue
		}
		env := make(map[string]string, len(p.Env)+1)
		for k, val := range p.Env {
			env[k] = val
		}
		env[ollamaContextKey] = v
		out[i].Env = env
	}
	return out
}

// nativeOllamaTuning is what the macOS guard writes into a brew-managed
// ollama's plist (backendrt.SetOllamaTuning). Several roles in one daemon:
// the merged env, as before, plus the profile's context default when no role
// sets it. A lone placement's env is left as it always was, EXCEPT that the
// profile's context default reaches the plist when the placement does not
// set the key. No rows, no tuning.
func nativeOllamaTuning(rows []placement, prof *harnessprofile.Profile) map[string]string {
	switch {
	case len(rows) > 1:
		env, _ := mergeOllamaEnv(rows)
		if v := profileOllamaContext(env, prof); v != "" {
			env[ollamaContextKey] = v
		}
		return buildPlacementEnv(placement{Backend: "ollama", Env: env})
	case len(rows) == 1:
		if v := profileOllamaContext(rows[0].Env, prof); v != "" {
			return map[string]string{ollamaContextKey: v}
		}
	}
	return nil
}

// chatPlacementOf is the placement this node serves chat from: the first
// RUNNING placement whose role is chat (or unset) on a chat engine (a
// backend `noo` speaks, harness_kinds.json), in desired order. ok=false
// when there is none.
func chatPlacementOf(all []placement) (placement, bool) {
	for _, p := range all {
		if p.Backend == "harness" || p.DesiredState != "running" || (p.Role != "" && p.Role != "chat") {
			continue
		}
		for _, b := range harnessKinds["noo"] {
			if b == p.Backend {
				return p, true
			}
		}
	}
	return placement{}, false
}

// recordChatPlacement remembers the desired chat placement for ChatPlacement.
func (r *Reconciler) recordChatPlacement(all []placement) {
	p, ok := chatPlacementOf(all)
	r.harnessMu.Lock()
	defer r.harnessMu.Unlock()
	if !ok {
		r.chatDesired = nil
		return
	}
	r.chatDesired = &p
}

// ChatPlacement is the desired chat placement's backend and model, for
// POST /bench. ok=false when the controller places no running chat model.
func (r *Reconciler) ChatPlacement() (backend, model string, ok bool) {
	r.harnessMu.RLock()
	defer r.harnessMu.RUnlock()
	if r.chatDesired == nil {
		return "", "", false
	}
	return r.chatDesired.Backend, r.chatDesired.Model, true
}
