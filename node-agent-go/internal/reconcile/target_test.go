// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"strings"
	"testing"
)

// A declared target is part of the spec (it decides the GPU device), so a
// change recreates the container; an undeclared one leaves every existing
// placement's hash exactly as it was.
func TestSpecHashFoldsInADeclaredTargetOnly(t *testing.T) {
	base := placement{Backend: "llamacpp", Model: "m.gguf", Env: map[string]string{"N_CTX": "4096"}}
	cpu := base
	cpu.Target = "cpu"
	gpu := base
	gpu.Target = "gpu"
	if specHash(base) == specHash(cpu) || specHash(cpu) == specHash(gpu) {
		t.Fatal("a declared target must change the spec hash")
	}
	again := base
	again.Target = ""
	if specHash(base) != specHash(again) {
		t.Fatal("an undeclared target must not change the hash")
	}
}

func TestOllamaDaemonRunsOnCPUOnlyWhenEveryRoleAsks(t *testing.T) {
	chat := placement{Backend: "ollama", Model: "gemma", Role: "chat", DesiredState: "running", Target: "cpu"}
	embed := placement{Backend: "ollama", Model: "harrier", Role: "embed", DesiredState: "running", Target: "cpu"}
	if got, w := mergeOllamaTarget([]placement{chat, embed}); got != "cpu" || w != "" {
		t.Fatalf("all cpu: got %q warning %q", got, w)
	}
	embed.Target = "gpu"
	got, w := mergeOllamaTarget([]placement{chat, embed})
	if got != "gpu" || !strings.Contains(w, "chat=cpu embed=gpu") {
		t.Fatalf("mixed: got %q warning %q", got, w)
	}
	embed.Target = ""
	if got, _ := mergeOllamaTarget([]placement{chat, embed}); got != "gpu" {
		t.Fatalf("an unset role keeps the GPU, got %q", got)
	}
	chat.Target = ""
	if got, w := mergeOllamaTarget([]placement{chat, embed}); got != "" || w != "" {
		t.Fatalf("nobody declared: got %q warning %q", got, w)
	}
	// Through effectivePlacements: the merged daemon carries the target.
	chat.Target, embed.Target = "cpu", "cpu"
	eff, _ := effectivePlacements([]placement{chat, embed})
	if len(eff) != 1 || eff[0].Target != "cpu" {
		t.Fatalf("effective: %+v", eff)
	}
}

func TestSpecHashFoldsInADerivedMemoryLimitOnlyWhenSet(t *testing.T) {
	base := placement{Backend: "llamacpp", Model: "m.gguf"}
	limited := base
	limited.MemoryLimitBytes = 17_500_000_000
	if specHash(base) == specHash(limited) {
		t.Fatal("a memory limit change must recreate the container")
	}
	zero := base
	zero.MemoryLimitBytes = 0
	if specHash(base) != specHash(zero) {
		t.Fatal("no limit must leave the hash as it was")
	}
}
