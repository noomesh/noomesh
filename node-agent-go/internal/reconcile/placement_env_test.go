// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// Placement `env` is a raw jsonb blob the gateway ships verbatim, and it
// used to be merged into a root backend container with no filter at all —
// a general-purpose injection point for LD_PRELOAD, PATH, PYTHONSTARTUP and
// a backend's own credential variables.
func TestPlacementEnvAllowList(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)

	allowed := []string{
		"MODEL_PATH", "MODEL_ID", "PORT", "HOST",
		"N_GPU_LAYERS", "N_CTX", "N_THREADS",
		"GPU_MEMORY_UTILIZATION", "TENSOR_PARALLEL_SIZE",
		"OLLAMA_MODEL", "OLLAMA_KEEP_ALIVE",
		"VLLM_TOOL_PARSER", "VLLM_MAX_MODEL_LEN", "VLLM_USE_V2_MODEL_RUNNER",
		"LLAMA_ARG_JINJA", "TEI_MODEL", "RERANK_N_CTX", "LOG_LEVEL",
	}
	refused := []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "HOME",
		"PYTHONPATH", "PYTHONSTARTUP",
		"NVIDIA_VISIBLE_DEVICES",
		"HF_TOKEN", "HUGGING_FACE_HUB_TOKEN",
		"NOO_CLUSTER_SECRET", "NOO_NODE_AGENT_TOKEN", "NOO_TLS_KEY",
		"NATS_PASSWORD", "DOCKER_HOST",
		"MODELS_DIR", "NOO_DATA_ROOT",
	}

	for _, k := range allowed {
		if !placementEnvAllowed(k) {
			t.Errorf("%q is a tuning key and must be allowed", k)
		}
	}
	for _, k := range refused {
		if placementEnvAllowed(k) {
			t.Errorf("%q must NOT be settable from a placement", k)
		}
	}

	// And the filter has to be the one buildPlacementEnv applies, not a
	// predicate nobody calls.
	p := placement{
		Backend: "llamacpp",
		Env: map[string]string{
			"N_CTX":              "8192",
			"LD_PRELOAD":         "/tmp/evil.so",
			"NOO_CLUSTER_SECRET": "stolen",
		},
	}
	env := buildPlacementEnv(p)
	if env["N_CTX"] != "8192" {
		t.Errorf("tuning key dropped: %v", env)
	}
	for _, k := range []string{"LD_PRELOAD", "NOO_CLUSTER_SECRET"} {
		if _, present := env[k]; present {
			t.Errorf("%q reached the container env: %v", k, env)
		}
	}

	// A dropped key is REPORTED, not silent: a placement whose env did not
	// take effect is otherwise indistinguishable from one that did.
	got := refusals.List()
	if len(got) != 2 {
		t.Fatalf("expected both refused keys reported, got %+v", got)
	}
	for _, r := range got {
		if r.Scope != "placement_env" {
			t.Errorf("unexpected refusal scope %q", r.Scope)
		}
	}
}
