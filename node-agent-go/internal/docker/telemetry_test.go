// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"strings"
	"testing"
)

// Every backend spec carries its vendor telemetry switches literally
// (docs/security/telemetry.md). Dropping VLLM_NO_USAGE_STATS from the vllm
// spec fails here and in tests/test_no_vendor_telemetry.py.
func TestBackendSpecsCarryTheirTelemetrySwitches(t *testing.T) {
	specs := map[string]BackendSpec{}
	for k, v := range backendSpecs {
		specs[k] = v
	}
	specs["reranker(tei)"] = rerankerSpecTEI()
	specs["reranker(llamacpp)"] = rerankerSpecLlamacpp()
	checked := 0
	for name, spec := range specs {
		key := strings.SplitN(name, "(", 2)[0]
		_, isTEI := spec.Env["MODEL_ID"]
		for k, want := range TelemetrySwitchesFor(key, isTEI) {
			checked++
			if got, ok := spec.Env[k]; !ok || got != want {
				t.Errorf("backend %s: Env[%s] = %q (present=%v), want %q — vendor telemetry must stay off", name, k, got, ok, want)
			}
		}
	}
	// The vllm spec alone carries four; a table that found nothing to
	// check would pass without checking.
	if checked < 4 {
		t.Fatalf("checked only %d switches — the table or the specs went empty", checked)
	}
}

// The backends whose software phones home must each have a non-empty set.
func TestTelemetryTableCoversThePhoneHomeBackends(t *testing.T) {
	for _, b := range []string{"vllm", "vllm-secondary", "embedding", "airllm", "ollama"} {
		if len(TelemetrySwitchesFor(b, false)) == 0 {
			t.Errorf("%s has no telemetry switches", b)
		}
	}
	if len(TelemetrySwitchesFor("reranker", true)) == 0 {
		t.Error("a TEI reranker has no telemetry switches")
	}
	if TelemetrySwitchesFor("reranker", false) != nil || TelemetrySwitchesFor("llamacpp", false) != nil {
		t.Error("llama.cpp has no phone-home; it must not be asked for switches it cannot read")
	}
	if _, ok := TelemetrySwitchesFor("vllm", false)["VLLM_NO_USAGE_STATS"]; !ok {
		t.Error("vllm must carry VLLM_NO_USAGE_STATS")
	}
}

// A placement or node-local override cannot turn a switch back on.
func TestBuildEnvListReassertsTelemetrySwitches(t *testing.T) {
	env := buildEnvList(backendSpecs["vllm"].Env, map[string]string{
		"VLLM_NO_USAGE_STATS": "0",
		"DO_NOT_TRACK":        "",
		"VLLM_MODEL":          "m",
	})
	if miss := TelemetryMissing("vllm", env); len(miss) != 0 {
		t.Fatalf("overrides turned telemetry back on: missing %v", miss)
	}
	found := false
	for _, kv := range env {
		if kv == "VLLM_MODEL=m" {
			found = true
		}
	}
	if !found {
		t.Error("an ordinary override must still win")
	}
}

func TestTelemetryMissingNamesWhatIsAbsent(t *testing.T) {
	got := TelemetryMissing("vllm", []string{"VLLM_MODEL=x", "DO_NOT_TRACK=1", "VLLM_NO_USAGE_STATS=0"})
	want := []string{"HF_HUB_DISABLE_TELEMETRY", "VLLM_DO_NOT_TRACK", "VLLM_NO_USAGE_STATS"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("missing = %v, want %v", got, want)
	}
	if m := TelemetryMissing("llamacpp", nil); len(m) != 0 {
		t.Errorf("llamacpp needs no switch, got %v", m)
	}
	// A reranker is judged by its engine.
	if m := TelemetryMissing("reranker", []string{"MODEL_ID=x"}); len(m) != 2 {
		t.Errorf("a TEI reranker without switches must miss two, got %v", m)
	}
	if m := TelemetryMissing("reranker", []string{"MODEL_PATH=/models/x.gguf"}); len(m) != 0 {
		t.Errorf("a llama.cpp reranker needs none, got %v", m)
	}
	// Never nil: `[]` on the heartbeat is the proof.
	if m := TelemetryMissing("llamacpp", nil); m == nil {
		t.Error("TelemetryMissing must return an empty slice, not nil")
	}
}

func TestIsTelemetrySwitch(t *testing.T) {
	for _, k := range []string{"VLLM_NO_USAGE_STATS", "DO_NOT_TRACK", "HF_HUB_DISABLE_TELEMETRY", "OLLAMA_NO_CLOUD"} {
		if !IsTelemetrySwitch(k) {
			t.Errorf("%s must be a telemetry switch", k)
		}
	}
	if IsTelemetrySwitch("VLLM_MODEL") {
		t.Error("VLLM_MODEL is not a telemetry switch")
	}
}
