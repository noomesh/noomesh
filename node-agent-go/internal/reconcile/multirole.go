// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Multi-role placements: the gateway keys placements (node, backend, role),
// so ONE ollama daemon can be asked to serve chat AND embed (and rerank) at
// once - one container (or one launchd job), several models. Everything here
// is the pure half of making that true on the node.

// roleOf is a placement's role; pre-role gateways omit it, which means chat.
func roleOf(p placement) string {
	if r := strings.TrimSpace(p.Role); r != "" {
		return r
	}
	return "chat"
}

func rolePriority(role string) int {
	switch role {
	case "chat":
		return 0
	case "embed":
		return 1
	case "rerank":
		return 2
	}
	return 3
}

// orderPlacements returns a copy ordered chat, embed, rerank, then any other
// role alphabetically (ties by model), so every decision below is
// independent of the order the gateway happened to list the rows in.
func orderPlacements(ps []placement) []placement {
	out := append([]placement(nil), ps...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := roleOf(out[i]), roleOf(out[j])
		if pi, pj := rolePriority(ri), rolePriority(rj); pi != pj {
			return pi < pj
		}
		if ri != rj {
			return ri < rj
		}
		return out[i].Model < out[j].Model
	})
	return out
}

// primaryPlacement is the placement that names the daemon: the chat one,
// else the first by role order. Zero value for an empty list.
func primaryPlacement(ps []placement) placement {
	if len(ps) == 0 {
		return placement{}
	}
	return orderPlacements(ps)[0]
}

// presenceKey is the modelpresence key for p among its backend's running
// placements: the primary keeps the bare backend name (the single-placement
// wire shape), every other role is "<backend>#<role>".
func presenceKey(backend string, p, primary placement) string {
	if roleOf(p) == roleOf(primary) && p.Model == primary.Model {
		return backend
	}
	return backend + "#" + roleOf(p)
}

// ollamaMaxKeys merge by integer MAX; see mergeOllamaEnv.
var ollamaMaxKeys = map[string]bool{
	"OLLAMA_NUM_PARALLEL":      true,
	"OLLAMA_MAX_LOADED_MODELS": true,
}

// mergeOllamaEnv merges the env of the RUNNING ollama placements that share
// one daemon into the daemon's env.
//
// MERGE RULE (the daemon env is process-wide, so there is no per-role env):
//   - OLLAMA_NUM_PARALLEL and OLLAMA_MAX_LOADED_MODELS merge by integer MAX.
//     If any value for the key is not an integer, the key falls back to the
//     priority rule below.
//   - Every other key: the highest-priority role wins (chat > embed > rerank
//     > other, alphabetical); keys are unioned across placements.
//   - A key present in 2+ placements with differing values yields a warning,
//     e.g. "OLLAMA_NUM_PARALLEL: chat=1 embed=4 -> 4 (max)".
//   - With n > 1 placements: OLLAMA_MAX_LOADED_MODELS = max(merged or 0, n)
//     so every placed model fits loaded, and OLLAMA_KEEP_ALIVE defaults to
//     "-1" when no placement set it (placed models stay resident - warm; the
//     gateway's memory-fit check guarantees they fit). Neither injection
//     warns.
//
// Keys are merged raw; the allow-list (buildPlacementEnv) is applied later.
func mergeOllamaEnv(ps []placement) (map[string]string, []string) {
	ordered := orderPlacements(ps)
	keys := map[string]bool{}
	for _, p := range ordered {
		for k := range p.Env {
			keys[k] = true
		}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	env := map[string]string{}
	var warnings []string
	for _, k := range sorted {
		type hold struct{ role, val string }
		var held []hold
		for _, p := range ordered {
			if v, ok := p.Env[k]; ok {
				held = append(held, hold{roleOf(p), v})
			}
		}
		winner, how := held[0].val, held[0].role // priority rule
		if ollamaMaxKeys[k] {
			best, allInt := int64(0), true
			for i, h := range held {
				n, err := strconv.ParseInt(strings.TrimSpace(h.val), 10, 64)
				if err != nil {
					allInt = false
					break
				}
				if i == 0 || n > best {
					best = n
				}
			}
			if allInt {
				winner, how = strconv.FormatInt(best, 10), "max"
			}
		}
		env[k] = winner
		differ := false
		for _, h := range held[1:] {
			if h.val != held[0].val {
				differ = true
			}
		}
		if len(held) > 1 && differ {
			var parts []string
			for _, h := range held {
				parts = append(parts, h.role+"="+h.val)
			}
			warnings = append(warnings, fmt.Sprintf("%s: %s -> %s (%s)", k, strings.Join(parts, " "), winner, how))
		}
	}
	if n := len(ps); n > 1 {
		cur, _ := strconv.Atoi(strings.TrimSpace(env["OLLAMA_MAX_LOADED_MODELS"]))
		if n > cur {
			cur = n
		}
		env["OLLAMA_MAX_LOADED_MODELS"] = strconv.Itoa(cur)
		if _, ok := env["OLLAMA_KEEP_ALIVE"]; !ok {
			env["OLLAMA_KEEP_ALIVE"] = "-1"
		}
	}
	return env, warnings
}

// mergeOllamaTarget is the hardware target of ONE ollama daemon serving
// several roles. The device is container-wide, so the daemon runs on CPU only
// when EVERY role asked for cpu; any role that wants the GPU (or did not say)
// keeps the GPU for all of them, because taking it away would move a GPU
// model onto the CPU without anyone asking. A mix is reported.
func mergeOllamaTarget(ps []placement) (string, string) {
	cpu, other := 0, 0
	var parts []string
	for _, p := range orderPlacements(ps) {
		t := strings.TrimSpace(p.Target)
		if t == "cpu" {
			cpu++
		} else {
			other++
		}
		if t == "" {
			t = "unset"
		}
		parts = append(parts, roleOf(p)+"="+t)
	}
	switch {
	case cpu > 0 && other == 0:
		return "cpu", ""
	case cpu > 0:
		return "gpu", fmt.Sprintf("target: %s -> gpu (one ollama daemon has one device; it runs on cpu only when every role asks for cpu)", strings.Join(parts, " "))
	}
	// No role said cpu: keep what the primary declared ("" or "gpu").
	return strings.TrimSpace(primaryPlacement(ps).Target), ""
}

// effectivePlacements collapses the gateway's per-role rows to ONE placement
// per backend for the container lifecycle, preserving first-appearance order
// (harness rows pass through untouched). A backend with a single running
// placement yields that placement UNCHANGED (spec hash identical). Stopped
// rows are ignored when a sibling is running; all-stopped yields the first
// row (stop as before). Several running ollama rows become one merged
// placement: model/image/port/tls from the primary, env from mergeOllamaEnv.
// The warnings are the env conflicts to surface.
func effectivePlacements(all []placement) ([]placement, []string) {
	var out []placement
	var warnings []string
	done := map[string]bool{}
	for _, p := range all {
		if p.Backend == "harness" {
			out = append(out, p)
			continue
		}
		if done[p.Backend] {
			continue
		}
		done[p.Backend] = true
		var running []placement
		for _, q := range all {
			if q.Backend == p.Backend && q.DesiredState == "running" {
				running = append(running, q)
			}
		}
		switch {
		case len(running) == 0:
			out = append(out, p)
		case len(running) == 1:
			out = append(out, running[0])
		case p.Backend == "ollama":
			merged := primaryPlacement(running)
			env, w := mergeOllamaEnv(running)
			merged.Env = env
			target, tw := mergeOllamaTarget(running)
			merged.Target = target
			out = append(out, merged)
			warnings = append(warnings, w...)
			if tw != "" {
				warnings = append(warnings, tw)
			}
		default:
			// Only ollama hosts several models in one daemon; for anything
			// else the primary names the container and the rest are not
			// something this node can honour.
			out = append(out, primaryPlacement(running))
		}
	}
	return out, warnings
}

// runningOllama is the running ollama rows, primary first.
func runningOllama(all []placement) []placement {
	var ps []placement
	for _, p := range all {
		if p.Backend == "ollama" && p.DesiredState == "running" {
			ps = append(ps, p)
		}
	}
	return orderPlacements(ps)
}

// ensureOllamaModels runs ensureOllamaModel for every given running ollama
// placement (all roles) under its presence key, and returns the set of keys
// that are wanted (for modelpresence.Retain).
func (r *Reconciler) ensureOllamaModels(
	node string,
	ps []placement,
	has func(context.Context, string) (bool, error),
	pull func(context.Context, string) (string, error),
) map[string]bool {
	keep := map[string]bool{}
	ordered := orderPlacements(ps)
	if len(ordered) == 0 {
		return keep
	}
	primary := ordered[0]
	for _, p := range ordered {
		key := presenceKey(p.Backend, p, primary)
		keep[key] = true
		r.ensureOllamaModel(node, key, p, has, pull)
	}
	return keep
}
