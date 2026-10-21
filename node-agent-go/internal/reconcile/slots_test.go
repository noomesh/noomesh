// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import "testing"

func TestBackendSlotsReadEachEngineDeclaredConcurrency(t *testing.T) {
	got := backendSlots([]placement{
		{Backend: "ollama", DesiredState: "running", Env: map[string]string{"OLLAMA_NUM_PARALLEL": " 2 "}},
		{Backend: "llamacpp", DesiredState: "running", Env: map[string]string{"N_PARALLEL": "4"}},
		{Backend: "vllm", DesiredState: "running", Env: map[string]string{"VLLM_MAX_NUM_SEQS": "64"}},
		{Backend: "vllm-secondary", DesiredState: "running", Env: map[string]string{"VLLM_MAX_NUM_SEQS": "8"}},
		{Backend: "harness", DesiredState: "running"},
	})
	want := map[string]int{"ollama": 2, "llamacpp": 4, "vllm": 64}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for b, n := range want {
		if got[b] != n {
			t.Errorf("%s: got %d want %d", b, got[b], n)
		}
	}
}

func TestBackendSlotsAreUnknownUnlessDeclared(t *testing.T) {
	got := backendSlots([]placement{
		{Backend: "ollama", DesiredState: "running"},
		{Backend: "llamacpp", DesiredState: "running", Env: map[string]string{"N_PARALLEL": "lots"}},
		{Backend: "vllm", DesiredState: "stopped", Env: map[string]string{"VLLM_MAX_NUM_SEQS": "64"}},
	})
	if len(got) != 0 {
		t.Fatalf("undeclared, unparsable or stopped: nothing published, got %v", got)
	}
}
