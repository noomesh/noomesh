// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"reflect"
	"testing"
)

func fakeImages(t *testing.T) {
	t.Helper()
	prev := placementImageFn
	placementImageFn = func(backend, override string) string {
		if override != "" {
			return override
		}
		return "img/" + backend + ":1"
	}
	t.Cleanup(func() { placementImageFn = prev })
}

func TestPrefetchSelectsOnlyPlacementsTheStartLoopWillStart(t *testing.T) {
	fakeImages(t)
	run := func(backend string) placement {
		return placement{Backend: backend, Model: "m.gguf", DesiredState: "running"}
	}
	converged := run("embedding")
	effective := []placement{
		run("llamacpp"),
		converged,
		{Backend: "reranker", Model: "BAAI/bge-reranker-base", DesiredState: "running"}, // gguf-only engine, non-gguf model: never starts
		{Backend: "vllm", Model: "x", DesiredState: "stopped"},
		{Backend: "harness", DesiredState: "running"},
		{Backend: "ollama", Model: "q", DesiredState: "running"}, // native
	}
	running := map[string]string{"embedding": "m.gguf"}
	labels := map[string]string{"embedding": specHash(converged)}
	native := map[string]string{"ollama": "q"}

	refs, n := imagesToPrefetch(effective, running, labels, nil, native, map[string]string{})
	if want := []string{"img/llamacpp:1"}; !reflect.DeepEqual(refs, want) || n != 1 {
		t.Fatalf("refs=%v n=%d, want %v 1", refs, n, want)
	}

	// Same placement, drifted label: a recreate, so its image is wanted.
	labels["embedding"] = "stale"
	refs, n = imagesToPrefetch(effective, running, labels, nil, native, map[string]string{})
	if want := []string{"img/llamacpp:1", "img/embedding:1"}; !reflect.DeepEqual(refs, want) || n != 2 {
		t.Fatalf("drifted: refs=%v n=%d, want %v 2", refs, n, want)
	}

	// Already recreated once for this hash (drift-stuck): not started.
	refs, _ = imagesToPrefetch(effective, running, labels, nil, native, map[string]string{"embedding": specHash(converged)})
	if want := []string{"img/llamacpp:1"}; !reflect.DeepEqual(refs, want) {
		t.Fatalf("stuck: refs=%v, want %v", refs, want)
	}

	// Converged label, but the container runs on a floating ref an older
	// agent picked (aserve's noo-ollama on ollama/ollama:latest): a recreate.
	labels["embedding"] = specHash(converged)
	floating := map[string]string{"embedding": "ollama/ollama:latest"}
	refs, n = imagesToPrefetch(effective, running, labels, floating, native, map[string]string{})
	if want := []string{"img/llamacpp:1", "img/embedding:1"}; !reflect.DeepEqual(refs, want) || n != 2 {
		t.Fatalf("floating: refs=%v n=%d, want %v 2", refs, n, want)
	}
}

func TestPrefetchSkipsPlacementsWhoseImageCannotBeNamed(t *testing.T) {
	prev := placementImageFn
	placementImageFn = func(string, string) string { return "" }
	t.Cleanup(func() { placementImageFn = prev })
	refs, n := imagesToPrefetch([]placement{{Backend: "vllm", Model: "m", DesiredState: "running"}},
		map[string]string{}, map[string]string{}, nil, map[string]string{}, map[string]string{})
	if len(refs) != 0 || n != 0 {
		t.Fatalf("refs=%v n=%d, want none", refs, n)
	}
}
