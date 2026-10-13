// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import "testing"

// The host8 reranker restart loop: a gguf-only engine was given a
// HuggingFace repo id, and the reconciler's guard keyed on the model ENDING
// in .gguf — so the one case that can NEVER work was the one that slipped
// through to an infinite restart loop.
func TestExpectsGGUFModel(t *testing.T) {
	t.Run("llamacpp always wants a file", func(t *testing.T) {
		if !ExpectsGGUFModel("llamacpp") {
			t.Error("llamacpp should expect a gguf file")
		}
	})

	t.Run("reranker wants a file by default", func(t *testing.T) {
		t.Setenv("RERANK_ENGINE", "")
		if !ExpectsGGUFModel("reranker") {
			t.Error("default reranker engine is llamacpp, which needs a gguf")
		}
	})

	t.Run("reranker on TEI legitimately takes a repo id", func(t *testing.T) {
		t.Setenv("RERANK_ENGINE", "tei")
		if ExpectsGGUFModel("reranker") {
			t.Error("TEI reranker resolves a HuggingFace repo id itself")
		}
	})

	t.Run("engine match is case- and space-insensitive", func(t *testing.T) {
		t.Setenv("RERANK_ENGINE", "  TEI  ")
		if ExpectsGGUFModel("reranker") {
			t.Error("RERANK_ENGINE should be trimmed and compared case-insensitively")
		}
	})

	t.Run("repo-id backends are unaffected", func(t *testing.T) {
		for _, b := range []string{"embedding", "vllm", "ollama", "airllm"} {
			if ExpectsGGUFModel(b) {
				t.Errorf("%s does not load a gguf file from the models dir", b)
			}
		}
	})
}
