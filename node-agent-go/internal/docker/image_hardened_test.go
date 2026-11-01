// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
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

func TestHardenedDefaultsAreOursOnEveryArch(t *testing.T) {
	pinRelease(t)
	for backend, want := range map[string]string{
		"llamacpp": "ghcr.io/noomesh/llamacpp:v0.6.15",
		"reranker": "ghcr.io/noomesh/llamacpp:v0.6.15",
		"ollama":   "ghcr.io/noomesh/ollama:v0.6.15",
	} {
		if ours := hardenedDefault(backend); ours != want {
			t.Errorf("%s: hardenedDefault = %q, want %q", backend, ours, want)
		}
		choice, err := chooseBackendImage(backend, backendSpecs[backend], "")
		if err != nil {
			t.Fatalf("%s: %v", backend, err)
		}
		if choice.Ref != want || !choice.RailOnly {
			t.Errorf("%s: choice = %+v, want rail-only %q", backend, choice, want)
		}
	}
	if got := llamacppDefaultImage(); got != "ghcr.io/noomesh/llamacpp:v0.6.15" {
		t.Errorf("llamacppDefaultImage = %q", got)
	}
	if got := ollamaDefaultImage(); got != "ghcr.io/noomesh/ollama:v0.6.15" {
		t.Errorf("ollamaDefaultImage = %q", got)
	}
}

func TestExplicitImagesWin(t *testing.T) {
	pinRelease(t)
	pin := "@sha256:" + strings.Repeat("a", 64)
	t.Run("placement override", func(t *testing.T) {
		c, err := chooseBackendImage("ollama", backendSpecs["ollama"], "ollama/ollama:0.40.5"+pin)
		if err != nil || !strings.HasPrefix(c.Ref, "ollama/ollama:0.40.5") {
			t.Fatalf("choice %+v err %v", c, err)
		}
	})
	t.Run("LLAMACPP_IMAGE", func(t *testing.T) {
		t.Setenv("LLAMACPP_IMAGE", "registry.example/mine/llama:1")
		if ours := hardenedDefault("llamacpp"); ours != "" {
			t.Fatalf("an explicit LLAMACPP_IMAGE must disable the hardened default, got %q", ours)
		}
	})
	t.Run("OLLAMA_IMAGE", func(t *testing.T) {
		t.Setenv("OLLAMA_IMAGE", "ollama/ollama:0.40.5"+pin)
		c, err := chooseBackendImage("ollama", backendSpecs["ollama"], "")
		if err != nil || !strings.HasPrefix(c.Ref, "ollama/ollama:0.40.5") {
			t.Fatalf("choice %+v err %v", c, err)
		}
	})
	t.Run("RERANK_ENGINE=tei", func(t *testing.T) {
		t.Setenv("RERANK_ENGINE", "tei")
		if ours := hardenedDefault("reranker"); ours != "" {
			t.Fatalf("the TEI reranker has no hardened llama default, got %q", ours)
		}
	})
}

func TestNoReleasePinKeepsTheUpstreamDefault(t *testing.T) {
	t.Setenv("NOO_IMAGE_PREFIX", "")
	t.Setenv("NOO_IMAGE_TAG", "")
	t.Setenv("OLLAMA_IMAGE", "")
	if ours := hardenedDefault("ollama"); ours != "" {
		t.Fatalf("no pin: hardenedDefault must be empty, got %q", ours)
	}
	if got := ollamaDefaultImage(); got != upstreamOllamaImage {
		t.Errorf("ollamaDefaultImage with no pin = %q", got)
	}
	c, err := chooseBackendImage("ollama", backendSpecs["ollama"], "")
	if err != nil || c.Ref != upstreamOllamaImage {
		t.Fatalf("choice %+v err %v", c, err)
	}
}

// Not staged for this arch is a LOUD refusal for our images: no upstream
// container is ever started in its place.
func TestOurImageNotStagedIsRefusedLoudlyWithoutFallback(t *testing.T) {
	pinRelease(t)
	for _, backend := range []string{"ollama", "llamacpp", "reranker"} {
		var asked []string
		prev := ensureImageFn
		ensureImageFn = func(_ context.Context, _ *Client, ref string) error {
			asked = append(asked, ref)
			return &ImageNotStagedError{Ref: ref, Arch: "arm64", Tar: ImageTarGzName(ref, "arm64"), AltTar: ImageTarName(ref, "arm64")}
		}
		err := (&Client{}).StartBackendSDK(context.Background(), backend, "", 0, StartOverrides{})
		ensureImageFn = prev
		if err == nil || !IsImageNotStaged(err) {
			t.Fatalf("%s: want the not-staged refusal, got %v", backend, err)
		}
		if len(asked) != 1 || strings.Contains(asked[0], "ollama/ollama") || strings.Contains(asked[0], "ggml-org") {
			t.Fatalf("%s: asked %v, an upstream image must never be asked for", backend, asked)
		}
		for _, want := range []string{asked[0], "arm64", "noo cluster sync-images", "-i " + asked[0], "NOT fall back", "noo upgrade --stack"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: refusal lacks %q: %v", backend, want, err)
			}
		}
	}
}

func TestNoUpstreamFallbackCodeRemains(t *testing.T) {
	raw, err := os.ReadFile("backends.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, dead := range []string{"ensureImageWithFallback", "Fallback:"} {
		if strings.Contains(string(raw), dead) {
			t.Errorf("backends.go still has %q", dead)
		}
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
