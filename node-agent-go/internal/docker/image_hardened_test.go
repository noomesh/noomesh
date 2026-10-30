// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// i323 (operator decision 3): the default llama.cpp and Ollama images are OUR
// hardened builds from the node's release, on every architecture; the
// upstream image is used only when ours is not local and not staged.

func pinRelease(t *testing.T) {
	t.Helper()
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	t.Setenv("NOO_IMAGE_TAG", "v0.6.15")
	for _, v := range []string{"LLAMACPP_IMAGE", "OLLAMA_IMAGE", "RERANK_IMAGE", "RERANK_ENGINE"} {
		t.Setenv(v, "")
	}
}

func TestHardenedDefaultsAreOursOnEveryArchWithUpstreamFallback(t *testing.T) {
	pinRelease(t)
	for backend, want := range map[string][2]string{
		"llamacpp": {"ghcr.io/noomesh/llamacpp:v0.6.15", upstreamLlamacppImage},
		"reranker": {"ghcr.io/noomesh/llamacpp:v0.6.15", upstreamLlamacppImage},
		"ollama":   {"ghcr.io/noomesh/ollama:v0.6.15", upstreamOllamaImage},
	} {
		ours, up := hardenedDefault(backend)
		if ours != want[0] || up != want[1] {
			t.Errorf("%s: hardenedDefault = (%q, %q), want %v", backend, ours, up, want)
		}
		spec := backendSpecs[backend]
		choice, err := chooseBackendImage(backend, spec, "")
		if err != nil {
			t.Fatalf("%s: %v", backend, err)
		}
		if choice.Ref != want[0] || choice.Fallback != want[1] {
			t.Errorf("%s: choice = %+v, want ref %q fallback %q", backend, choice, want[0], want[1])
		}
	}
	// llamacppDefaultImage no longer branches on GOARCH: the same ref anywhere.
	if got := llamacppDefaultImage(); got != "ghcr.io/noomesh/llamacpp:v0.6.15" {
		t.Errorf("llamacppDefaultImage = %q", got)
	}
	if got := ollamaDefaultImage(); got != "ghcr.io/noomesh/ollama:v0.6.15" {
		t.Errorf("ollamaDefaultImage = %q", got)
	}
}

func TestExplicitImagesWinAndNeverFallBack(t *testing.T) {
	pinRelease(t)
	pin := "@sha256:" + strings.Repeat("a", 64)
	t.Run("placement override", func(t *testing.T) {
		c, err := chooseBackendImage("ollama", backendSpecs["ollama"], "ollama/ollama:0.40.5"+pin)
		if err != nil || c.Fallback != "" || !strings.HasPrefix(c.Ref, "ollama/ollama:0.40.5") {
			t.Fatalf("choice %+v err %v", c, err)
		}
	})
	t.Run("LLAMACPP_IMAGE", func(t *testing.T) {
		t.Setenv("LLAMACPP_IMAGE", "registry.example/mine/llama:1")
		if ours, up := hardenedDefault("llamacpp"); ours != "" || up != "" {
			t.Fatalf("an explicit LLAMACPP_IMAGE must disable the hardened default, got (%q, %q)", ours, up)
		}
	})
	t.Run("OLLAMA_IMAGE", func(t *testing.T) {
		t.Setenv("OLLAMA_IMAGE", "ollama/ollama:0.40.5"+pin)
		c, err := chooseBackendImage("ollama", backendSpecs["ollama"], "")
		if err != nil || c.Fallback != "" || !strings.HasPrefix(c.Ref, "ollama/ollama:0.40.5") {
			t.Fatalf("choice %+v err %v", c, err)
		}
	})
	t.Run("RERANK_ENGINE=tei", func(t *testing.T) {
		t.Setenv("RERANK_ENGINE", "tei")
		if ours, _ := hardenedDefault("reranker"); ours != "" {
			t.Fatalf("the TEI reranker has no hardened llama default, got %q", ours)
		}
	})
}

func TestNoReleasePinKeepsTheUpstreamDefault(t *testing.T) {
	t.Setenv("NOO_IMAGE_PREFIX", "")
	t.Setenv("NOO_IMAGE_TAG", "")
	t.Setenv("OLLAMA_IMAGE", "")
	if ours, _ := hardenedDefault("ollama"); ours != "" {
		t.Fatalf("no pin: hardenedDefault must be empty, got %q", ours)
	}
	if got := ollamaDefaultImage(); got != upstreamOllamaImage {
		t.Errorf("ollamaDefaultImage with no pin = %q", got)
	}
	c, err := chooseBackendImage("ollama", backendSpecs["ollama"], "")
	if err != nil || c.Ref != upstreamOllamaImage || c.Fallback != "" {
		t.Fatalf("choice %+v err %v", c, err)
	}
}

// The fallback is exactly: ours first through EnsureImage; ImageNotStagedError
// only then upstream through EnsureImage.
func TestEnsureImageWithFallback(t *testing.T) {
	const ours, up = "ghcr.io/noomesh/ollama:v0.6.15", "ollama/ollama:0.40.5"
	notStaged := &ImageNotStagedError{Ref: ours, Arch: "arm64"}
	run := func(t *testing.T, errs map[string]error, fallback string) (string, error, []string) {
		t.Helper()
		var asked []string
		prev := ensureImageFn
		ensureImageFn = func(_ context.Context, _ *Client, ref string) error {
			asked = append(asked, ref)
			return errs[ref]
		}
		t.Cleanup(func() { ensureImageFn = prev })
		img, err := ensureImageWithFallback(context.Background(), &Client{}, "ollama", ours, fallback, true)
		return img, err, asked
	}

	t.Run("ours available: upstream is never asked", func(t *testing.T) {
		img, err, asked := run(t, nil, up)
		if err != nil || img != ours || len(asked) != 1 {
			t.Fatalf("img %q err %v asked %v", img, err, asked)
		}
	})
	t.Run("ours not staged: upstream, via EnsureImage", func(t *testing.T) {
		img, err, asked := run(t, map[string]error{ours: fmt.Errorf("wrapped: %w", notStaged)}, up)
		if err != nil || img != up || len(asked) != 2 || asked[0] != ours || asked[1] != up {
			t.Fatalf("img %q err %v asked %v", img, err, asked)
		}
	})
	t.Run("not staged and upstream refused too: one error naming both", func(t *testing.T) {
		img, err, _ := run(t, map[string]error{ours: notStaged, up: errors.New("registry fallback is off")}, up)
		var ns *ImageNotStagedError
		if err == nil || !errors.As(err, &ns) || img != ours || !strings.Contains(err.Error(), up) {
			t.Fatalf("img %q err %v", img, err)
		}
	})
	t.Run("any other failure never falls back", func(t *testing.T) {
		for _, bad := range []error{errors.New("pull ... verification failed: sha256 mismatch"), errors.New("transport")} {
			img, err, asked := run(t, map[string]error{ours: bad}, up)
			if !errors.Is(err, bad) || img != ours || len(asked) != 1 {
				t.Fatalf("%v: img %q err %v asked %v", bad, img, err, asked)
			}
		}
	})
	t.Run("no fallback declared (explicit image): the refusal stands", func(t *testing.T) {
		img, err, asked := run(t, map[string]error{ours: notStaged}, "")
		if !errors.Is(err, notStaged) || img != ours || len(asked) != 1 {
			t.Fatalf("img %q err %v asked %v", img, err, asked)
		}
	})
}

// The upstream fallback is not rail-only: the first ask carries the choice's
// rail-only mark, the fallback ask is the plain context so the registry
// policy (NOO_IMAGE_REGISTRY_FALLBACK) can allow it.
func TestFallbackAskIsNotRailOnly(t *testing.T) {
	const ours, up = "ghcr.io/noomesh/llamacpp:v1", "ghcr.io/ggml-org/llama.cpp:server"
	var railOnly []bool
	prev := ensureImageFn
	ensureImageFn = func(ctx context.Context, _ *Client, ref string) error {
		railOnly = append(railOnly, isRailOnly(ctx))
		if ref == ours {
			return &ImageNotStagedError{Ref: ref, Arch: "arm64"}
		}
		return nil
	}
	t.Cleanup(func() { ensureImageFn = prev })
	if img, err := ensureImageWithFallback(context.Background(), &Client{}, "llamacpp", ours, up, true); err != nil || img != up {
		t.Fatalf("img %q err %v", img, err)
	}
	if len(railOnly) != 2 || !railOnly[0] || railOnly[1] {
		t.Fatalf("rail-only marks %v, want [true false]", railOnly)
	}
}

// The reconciler folds ReleaseBackendImage into the spec hash only when the
// placement names no image; Ollama joins llamacpp so a roll recreates it once
// onto the new release image, and a stable release is a stable value (no loop).
func TestReleaseBackendImageCoversOllama(t *testing.T) {
	pinRelease(t)
	a := ReleaseBackendImage("ollama")
	if a != "ghcr.io/noomesh/ollama:v0.6.15" || a != ReleaseBackendImage("ollama") {
		t.Fatalf("ReleaseBackendImage(ollama) = %q", a)
	}
	t.Setenv("OLLAMA_IMAGE", "ollama/ollama:0.40.5")
	if got := ReleaseBackendImage("ollama"); got != "" {
		t.Errorf("an upstream override is not this release's image, got %q", got)
	}
}

// (d) the retired local-name lookup is gone for good.
func TestRetiredPaiAssistantLlamacppLookupIsGone(t *testing.T) {
	raw, err := os.ReadFile("backends.go")
	if err != nil {
		t.Fatal(err)
	}
	b := string(raw)
	for _, dead := range []string{"pai-assistant/llamacpp:%s", `"pai-assistant/llamacpp:latest",`, "using hardened llamacpp build"} {
		if strings.Contains(b, dead) {
			t.Errorf("backends.go still carries the retired lookup: %q", dead)
		}
	}
}
