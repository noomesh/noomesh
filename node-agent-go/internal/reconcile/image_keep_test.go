// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"strings"
	"testing"
	"time"
)

const dgA = "ghcr.io/noomesh/llamacpp@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const dgB = "registry.example.net/acme/tool@sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func fakeRef(backend, override string) string {
	if override != "" {
		return override
	}
	return "ghcr.io/noomesh/" + backend + ":v1"
}

func fakeID(ref string) string { return "sha256:id-of-" + ref }

func keepHas(k *keepFileOut, ref, id string) bool {
	for _, e := range k.Keep {
		if e.Ref == ref && e.ID == id {
			return true
		}
	}
	return false
}

func TestNodeKeepKeepsPausedAndStoppedPlacements(t *testing.T) {
	d := &desiredConfig{Placements: []placement{
		{Backend: "vllm", DesiredState: "paused"},
		{Backend: "ollama", DesiredState: "stopped"},
		{Backend: "llamacpp", Image: dgA, DesiredState: "running"},
	}}
	k := buildNodeKeep(d, nil, fakeRef, fakeID, []string{"ghcr.io/noomesh/"}, nil, time.Unix(0, 0))
	if !keepHas(k, "", fakeID("ghcr.io/noomesh/vllm:v1")) {
		t.Fatalf("a paused placement's image must be kept by id: %+v", k.Keep)
	}
	if !keepHas(k, "", fakeID("ghcr.io/noomesh/ollama:v1")) {
		t.Fatalf("a stopped placement's image must be kept: %+v", k.Keep)
	}
	if !keepHas(k, dgA, fakeID(dgA)) {
		t.Fatalf("a digest-pinned placement must be kept by ref and id: %+v", k.Keep)
	}
	if k.Version != 1 || k.MaxAgeSeconds != 3600 {
		t.Fatalf("version/max age: %+v", k)
	}
}

func TestNodeKeepScansDesiredConfigDigestsAndTheirNamespaces(t *testing.T) {
	raw := []byte(`{"addon_workloads":[{"image":"` + dgB + `"}],"node_workloads":[{"image":"plain:latest"}]}`)
	k := buildNodeKeep(&desiredConfig{}, raw, fakeRef, fakeID, []string{"ghcr.io/noomesh/"}, nil, time.Unix(0, 0))
	if !keepHas(k, dgB, fakeID(dgB)) {
		t.Fatalf("a digest named in desired-config must be kept: %+v", k.Keep)
	}
	if strings.Join(k.Namespaces, ",") != "ghcr.io/noomesh/,registry.example.net/acme/tool/" {
		t.Fatalf("namespaces = %v", k.Namespaces)
	}
	for _, e := range k.Keep {
		if strings.Contains(e.Ref, "plain") {
			t.Fatalf("a tag-only ref is not a digest and must not be kept by ref: %+v", e)
		}
	}
}

func TestNodeKeepUnresolvedImageIsNotAnEntry(t *testing.T) {
	d := &desiredConfig{Placements: []placement{{Backend: "vllm", DesiredState: "running"}}}
	k := buildNodeKeep(d, nil, fakeRef, func(string) string { return "" }, nil, nil, time.Unix(0, 0))
	if len(k.Keep) != 0 {
		t.Fatalf("an image the daemon does not have has nothing to keep: %+v", k.Keep)
	}
}

func TestNodeKeepCarriesPreviousGenerationOnceThenHoldsIt(t *testing.T) {
	gen1 := &desiredConfig{Placements: []placement{{Backend: "llamacpp", Image: "ghcr.io/noomesh/llamacpp:v1", DesiredState: "running"}}}
	gen2 := &desiredConfig{Placements: []placement{{Backend: "llamacpp", Image: "ghcr.io/noomesh/llamacpp:v2", DesiredState: "running"}}}
	gen3 := &desiredConfig{Placements: []placement{{Backend: "llamacpp", Image: "ghcr.io/noomesh/llamacpp:v3", DesiredState: "running"}}}
	now := time.Unix(0, 0)
	k1 := buildNodeKeep(gen1, nil, fakeRef, fakeID, nil, nil, now)
	k2 := buildNodeKeep(gen2, nil, fakeRef, fakeID, nil, k1, now)
	v1 := fakeID("ghcr.io/noomesh/llamacpp:v1")
	if !keepHas(k2, "", v1) {
		t.Fatalf("the change must carry the previous image: %+v", k2.Keep)
	}
	k2b := buildNodeKeep(gen2, nil, fakeRef, fakeID, nil, k2, now)
	if !keepHas(k2b, "", v1) {
		t.Fatalf("an unchanged pass must keep carrying the previous image: %+v", k2b.Keep)
	}
	k3 := buildNodeKeep(gen3, nil, fakeRef, fakeID, nil, k2b, now)
	if keepHas(k3, "", v1) {
		t.Fatalf("two generations back must not be kept: %+v", k3.Keep)
	}
	if !keepHas(k3, "", fakeID("ghcr.io/noomesh/llamacpp:v2")) {
		t.Fatalf("the generation just replaced must be kept: %+v", k3.Keep)
	}
}

func TestOwnRootsNeverIncludeLocalBuilds(t *testing.T) {
	// The reconcile side passes docker.OwnRegistryRoots; namespaces come only
	// from it and from digest refs with a registry host.
	if keepNamespace("noomesh/gateway@sha256:"+strings.Repeat("c", 64)) != "" {
		t.Fatal("a ref with no registry host must not add a namespace")
	}
	if keepNamespace("docker.io/library/redis@sha256:"+strings.Repeat("d", 64)) != "docker.io/library/redis/" {
		t.Fatal("a digest ref must claim its own repository, never its whole registry path")
	}
	k := buildNodeKeep(&desiredConfig{}, []byte(dgA), fakeRef, fakeID, []string{"noomesh/", "ghcr.io/noomesh/"}, nil, time.Unix(0, 0))
	if strings.Join(k.Namespaces, ",") != "ghcr.io/noomesh/,ghcr.io/noomesh/llamacpp/" {
		t.Fatalf("a root hostd would refuse must be dropped, not written: %v", k.Namespaces)
	}
	if keepNamespace(dgA) != "ghcr.io/noomesh/llamacpp/" {
		t.Fatalf("got %q", keepNamespace(dgA))
	}
}
