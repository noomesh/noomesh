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
func backendSlots(effective []placement) map[string]int {
	out := map[string]int{}
	for _, p := range effective {
		if p.DesiredState != "running" {
			continue
		}
		env := buildPlacementEnv(p)
		for _, k := range slotKeys[p.Backend] {
			n, err := strconv.Atoi(strings.TrimSpace(env[k]))
			if err == nil && n > 0 {
				out[p.Backend] = n
				break
			}
		}
	}
	return out
}
