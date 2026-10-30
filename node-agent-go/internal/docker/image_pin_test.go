// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

const pinDigest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func clearImageEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"NOO_IMAGE_SOURCE", "NOO_IMAGE_PREFIX", "NOO_IMAGE_TAG", "VLLM_IMAGE", "OLLAMA_IMAGE", "NOO_MODEL_CACHE_URL", preseed.OllamaRegistryPullEnv} {
		t.Setenv(k, "")
	}
	// Rail is the default; these cases model a registry node, which is an
	// explicit opt-out. Rail cases set NOO_IMAGE_SOURCE=rail themselves.
	t.Setenv("NOO_IMAGE_SOURCE", "legacy")
}

// The floating defaults are gone: nothing in the specs resolves to :latest
// or an untagged third-party ref.
func TestBackendSpecDefaultsAreVersioned(t *testing.T) {
	clearImageEnv(t)
	for _, name := range []string{"vllm", "ollama", "embedding"} {
		ref := pickBackendImage(backendSpecs[name], "")
		if isFloatingRef(ref) {
			t.Errorf("%s default image %q floats", name, ref)
		}
	}
}

func TestChooseBackendImagePolicy(t *testing.T) {
	spec := backendSpecs["vllm"]
	pinned := "vllm/vllm-openai:v0.25.0" + pinDigest

	t.Run("floating override refused everywhere", func(t *testing.T) {
		clearImageEnv(t)
		for _, ref := range []string{"vllm/vllm-openai:latest", "vllm/vllm-openai", "docker.io/vllm/vllm-openai"} {
			if _, err := chooseBackendImage("vllm", spec, ref); err == nil || !strings.Contains(err.Error(), "floating") {
				t.Errorf("%q: want a floating-image refusal, got %v", ref, err)
			}
		}
	})
	t.Run("digest ref accepted and kept on a registry node", func(t *testing.T) {
		clearImageEnv(t)
		t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
		ch, err := chooseBackendImage("vllm", spec, pinned)
		if err != nil || ch.Ref != pinned || ch.RailOnly {
			t.Fatalf("got %+v, %v", ch, err)
		}
	})
	t.Run("rail node strips the digest and forbids the registry", func(t *testing.T) {
		clearImageEnv(t)
		t.Setenv("NOO_IMAGE_SOURCE", "rail")
		ch, err := chooseBackendImage("vllm", spec, pinned)
		if err != nil || ch.Ref != "vllm/vllm-openai:v0.25.0" || !ch.RailOnly {
			t.Fatalf("got %+v, %v", ch, err)
		}
	})
	t.Run("old controller: a digest-less default is refused on a dist registry node", func(t *testing.T) {
		clearImageEnv(t)
		t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
		_, err := chooseBackendImage("vllm", spec, "")
		if err == nil || !strings.Contains(err.Error(), "digest") || !strings.Contains(err.Error(), "noo upgrade --stack") {
			t.Fatalf("want an explained digest refusal, got %v", err)
		}
	})
	t.Run("old controller: a rail node may run its default only from the rail", func(t *testing.T) {
		clearImageEnv(t)
		t.Setenv("NOO_IMAGE_SOURCE", "rail")
		ch, err := chooseBackendImage("vllm", spec, "")
		if err != nil || !ch.RailOnly || ch.Ref != "vllm/vllm-openai:v0.25.0" {
			t.Fatalf("got %+v, %v", ch, err)
		}
	})
	t.Run("a placed digest-less ref is refused even off the rail", func(t *testing.T) {
		clearImageEnv(t)
		if _, err := chooseBackendImage("vllm", spec, "vllm/vllm-openai:v0.25.0"); err == nil {
			t.Fatal("want a refusal")
		}
	})
	t.Run("a hand-run dev node keeps its versioned default", func(t *testing.T) {
		clearImageEnv(t)
		if ch, err := chooseBackendImage("vllm", spec, ""); err != nil || ch.RailOnly {
			t.Fatalf("got %+v, %v", ch, err)
		}
	})
	t.Run("our own local build names are exempt", func(t *testing.T) {
		clearImageEnv(t)
		t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
		if _, err := chooseBackendImage("airllm", backendSpecs["airllm"], ""); err != nil {
			t.Fatalf("airllm local build: %v", err)
		}
	})
}

// ONE function: the prefetch ref IS the ref the start path asks for.
func TestPrefetchRefIsTheStartRef(t *testing.T) {
	clearImageEnv(t)
	t.Setenv("NOO_IMAGE_SOURCE", "rail")
	override := "vllm/vllm-openai:v0.25.0" + pinDigest
	pre := BackendImageRef("vllm", override)

	asked := recordEnsure(t)
	c := &Client{}
	err := c.StartBackendSDK(context.Background(), "vllm", "org/model", 1, StartOverrides{Image: override})
	if !errors.Is(err, errSentinelEnsure) || len(*asked) != 1 {
		t.Fatalf("err %v asked %v", err, *asked)
	}
	if pre == "" || pre != (*asked)[0] {
		t.Fatalf("prefetch %q != start %q", pre, (*asked)[0])
	}
	// a ref the policy refuses is not prefetched, and the start refuses it
	if got := BackendImageRef("vllm", "vllm/vllm-openai:latest"); got != "" {
		t.Fatalf("prefetch of a refused ref = %q", got)
	}
}

func TestRailOnlyContextBlocksTheRegistryFallback(t *testing.T) {
	clearImageEnv(t)
	t.Setenv("NOO_IMAGE_SOURCE", "rail")
	prevL, prevR := imageLocalID, imageRegistryPull
	imageLocalID = func(context.Context, *Client, string) (string, bool) { return "", false }
	pulled := false
	imageRegistryPull = func(context.Context, *Client, string) error { pulled = true; return nil }
	t.Cleanup(func() { imageLocalID, imageRegistryPull = prevL, prevR })
	c := &Client{}
	_, _, err := c.resolveImage(withRailOnly(context.Background(), true), "vllm/vllm-openai:v0.25.0")
	if err == nil || pulled {
		t.Fatalf("a rail-only fetch reached the registry (pulled=%v err=%v)", pulled, err)
	}
}

// A placed node never downloads weights: a store miss is an explained refusal,
// not a start that downloads from huggingface.co with the node's token.
func TestPlacedNodeRefusesAnHFCacheMiss(t *testing.T) {
	clearImageEnv(t)
	t.Setenv("NOO_MODEL_CACHE_URL", "http://127.0.0.1:1") // refused value: still a placed node
	hf := t.TempDir()
	t.Setenv("HF_CACHE_DIR", hf)
	prev := ensureImageFn
	ensureImageFn = func(context.Context, *Client, string) error { return nil }
	t.Cleanup(func() { ensureImageFn = prev })
	c := &Client{}
	err := c.StartBackendSDK(context.Background(), "vllm", "org/not-staged", 1, StartOverrides{Image: "vllm/vllm-openai:v0.25.0" + pinDigest})
	var miss *ModelNotStagedError
	if !errors.As(err, &miss) {
		t.Fatalf("want ModelNotStagedError, got %v", err)
	}
	for _, want := range []string{"model_cache_miss", "org/not-staged", "controller", "noo cluster verify"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
	if hfRepoCachedLocally("org/not-staged") {
		t.Fatal("empty cache reads as cached")
	}
	snap := filepath.Join(hf, "hub", "models--org--staged", "snapshots", "abc")
	if err := os.MkdirAll(snap, 0o755); err != nil {
		t.Fatal(err)
	}
	if !hfRepoCachedLocally("org/staged") {
		t.Fatal("a preseeded snapshot must count (controller briefly unreachable)")
	}
}

func TestOllamaRegistryPullRefusedOnAPlacedNode(t *testing.T) {
	clearImageEnv(t)
	c := &Client{}
	// not placed: passes the policy and fails later (no Docker)
	if _, err := c.OllamaPull(context.Background(), "gemma4:12b"); err == nil || strings.Contains(err.Error(), "ollama_registry_pull_refused") {
		t.Fatalf("an unplaced node must not hit the placed-node refusal: %v", err)
	}
	t.Setenv("NOO_MODEL_CACHE_URL", "https://controller:8443")
	_, err := c.OllamaPull(context.Background(), "gemma4:12b")
	if err == nil || !strings.Contains(err.Error(), "noo models fetch") || !strings.Contains(err.Error(), preseed.OllamaRegistryPullEnv) {
		t.Fatalf("want an explained refusal, got %v", err)
	}
	t.Setenv(preseed.OllamaRegistryPullEnv, "1")
	if _, err := c.OllamaPull(context.Background(), "gemma4:12b"); err == nil || strings.Contains(err.Error(), "ollama_registry_pull_refused") {
		t.Fatalf("the explicit opt-in must pass the policy: %v", err)
	}
}
