// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

// Vendor telemetry switches (docs/security/telemetry.md).
//
// noomesh makes a "no telemetry" claim, and some of the third-party
// software it launches phones home unless told not to. vLLM is the live
// example: by default it posts a usage report (GPU, CPU, model
// architecture, a stable uuid) to stats.vllm.ai when the engine starts and
// every 10 minutes after. host3's noo-vllm had been doing exactly that.
//
// Each backend spec carries its switches LITERALLY in its Env map (so a
// reader of backendSpecs sees them, and tests/test_no_vendor_telemetry.py
// can check the Go source against the compose services). This table is
// what those specs must carry and what a running container is judged
// against: buildEnvList re-asserts a spec's switches after every override,
// and BackendContainers reports the ones a running container lacks so
// `noo cluster verify` can FAIL on them.
//
// Keep in step with TELEMETRY_SWITCHES in tests/test_no_vendor_telemetry.py
// and the table in docs/security/telemetry.md.

import (
	"sort"
	"strings"
)

var (
	// vLLM reads VLLM_NO_USAGE_STATS, VLLM_DO_NOT_TRACK and DO_NOT_TRACK
	// (vllm/usage/usage_lib.py is_usage_stats_enabled); huggingface_hub,
	// which it downloads models with, reads the last two.
	telemetryOffVLLM = map[string]string{
		"VLLM_NO_USAGE_STATS":      "1",
		"VLLM_DO_NOT_TRACK":        "1",
		"DO_NOT_TRACK":             "1",
		"HF_HUB_DISABLE_TELEMETRY": "1",
	}
	// huggingface_hub / transformers (airllm, and TEI's hf-hub fetch).
	telemetryOffHF = map[string]string{
		"HF_HUB_DISABLE_TELEMETRY": "1",
		"DO_NOT_TRACK":             "1",
	}
	// Ollama sends no usage telemetry; OLLAMA_NO_CLOUD stops it handing a
	// prompt to ollama.com (cloud models, web search).
	telemetryOffOllama = map[string]string{
		"OLLAMA_NO_CLOUD": "1",
	}
)

// BackendEnvGeneration is folded into the reconciler's spec hash
// (reconcile.specHash) beside BackendDoorGeneration, so a backend created
// by an agent whose spec env was OLDER is recreated ONCE on the first
// reconcile tick after the agent binary rolls, with no placement edit. A
// bump recreates every placed backend on every node (a cold model load
// each).
//
//	1  2026-10-03: vendor telemetry switches (VLLM_NO_USAGE_STATS & co.)
const BackendEnvGeneration = 1

// TelemetrySwitchesFor is the set of KEY=value switches a backend's
// container must carry. isTEI selects the reranker's engine (the reranker
// key covers both a TEI cross-encoder and llama.cpp --reranking); it is
// ignored for every other backend. nil = the software has no phone-home
// to switch off (llama.cpp).
func TelemetrySwitchesFor(backend string, isTEI bool) map[string]string {
	switch backend {
	case "vllm", "vllm-secondary":
		return telemetryOffVLLM
	case "embedding":
		return telemetryOffHF
	case "reranker":
		if isTEI {
			return telemetryOffHF
		}
		return nil
	case "airllm":
		return telemetryOffHF
	case "ollama":
		return telemetryOffOllama
	}
	return nil
}

// IsTelemetrySwitch reports whether key is one of the switches above.
func IsTelemetrySwitch(key string) bool {
	for _, m := range []map[string]string{telemetryOffVLLM, telemetryOffHF, telemetryOffOllama} {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

// TelemetryMissing returns the switch NAMES a container's env (KEY=value
// pairs, as `docker inspect` gives Config.Env) lacks or carries with a
// different value, sorted. Empty = every switch its backend needs is set.
func TelemetryMissing(backend string, env []string) []string {
	have := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		have[k] = v
	}
	// A reranker is TEI when it carries TEI's MODEL_ID (the llama.cpp
	// engine reads MODEL_PATH), the same test StartBackendSDK uses.
	_, isTEI := have["MODEL_ID"]
	want := TelemetrySwitchesFor(backend, isTEI)
	missing := []string{}
	for k, v := range want {
		if have[k] != v {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	return missing
}
