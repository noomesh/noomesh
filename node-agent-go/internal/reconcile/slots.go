// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"strconv"
	"strings"
)

// slotKeys names, per backend, the placement env key that declares how
// many requests the engine serves at once. Undeclared = 0 = unknown: the
// proxy then counts requests but never queues them itself
// (internal/occupancy).
var slotKeys = map[string][]string{
	"ollama":   {"OLLAMA_NUM_PARALLEL"},
	"llamacpp": {"N_PARALLEL", "LLAMA_ARG_N_PARALLEL"},
	"vllm":     {"VLLM_MAX_NUM_SEQS"},
}

// backendSlots is each running placement's declared concurrency, read from
// the env the backend is started with (allow-listed; the merged env for a
// multi-role ollama, which effectivePlacements already produced).
//
// Only an engine with a slot key is read. The allow-list filter LOGS and
// RECORDS every key it drops, and the harness placement carries
// NOO_HARNESS_KIND by design (convergeHarness reads it; the harness is a
// host service, never a container), so running the filter over it raised
// "node refused 1 desired-state instruction" on every kind change while the
// change itself went through (awolf, 2026-10-24, the harness compare).
func backendSlots(effective []placement) map[string]int {
	out := map[string]int{}
	for _, p := range effective {
		keys, engine := slotKeys[p.Backend]
		if !engine || p.DesiredState != "running" {
			continue
		}
		env := buildPlacementEnv(p)
		for _, k := range keys {
			n, err := strconv.Atoi(strings.TrimSpace(env[k]))
			if err == nil && n > 0 {
				out[p.Backend] = n
				break
			}
		}
	}
	return out
}
