// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"strings"
	"testing"

	"github.com/moby/moby/api/types/mount"
)

// The agent's vLLM keeps its compile caches on a named volume, so a recreate
// does not recompile (followup i305): the mount reaches Docker as a volume at
// vLLM's cache root, and every cache env var lands under it.
func TestVLLMCompileCacheIsAVolumeTheEngineWrites(t *testing.T) {
	spec := backendSpecs["vllm"]
	mounts, skipped := buildMounts(spec.Volumes)
	var got *mount.Mount
	for i := range mounts {
		if mounts[i].Target == VLLMCompileCacheTarget {
			got = &mounts[i]
		}
	}
	if got == nil {
		t.Fatalf("no mount at %s in the vllm spec: mounts %+v, skipped %+v", VLLMCompileCacheTarget, mounts, skipped)
	}
	if got.Type != mount.TypeVolume || got.Source != VLLMCompileCacheVolume || got.ReadOnly {
		t.Fatalf("compile cache mount = %+v, want a writable volume %q", *got, VLLMCompileCacheVolume)
	}
	// A named volume is no host path: the missing-bind-source refusal must
	// pass it by, or every vLLM start on a node would be refused.
	if err := requireMountSources("vllm", []mount.Mount{*got}); err != nil {
		t.Fatalf("requireMountSources refused the compile cache volume: %v", err)
	}
	// The engine writes the volume as root on a writable root: no user and
	// no read-only root on this spec (the default vllm-openai image keeps
	// USER root).
	if spec.ReadOnlyRoot {
		t.Fatal("vllm spec went read-only; check the engine can still write its caches")
	}

	env := map[string]string{}
	for _, kv := range buildEnvList(spec.Env, nil) {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	for _, k := range []string{"VLLM_CACHE_ROOT", "TRITON_CACHE_DIR", "TORCHINDUCTOR_CACHE_DIR", "FLASHINFER_WORKSPACE_BASE"} {
		v := env[k]
		if v != VLLMCompileCacheTarget && !strings.HasPrefix(v, VLLMCompileCacheTarget+"/") {
			t.Errorf("%s = %q, want a path under the compile cache mount %s", k, v, VLLMCompileCacheTarget)
		}
	}
	if env["VLLM_CACHE_ROOT"] != VLLMCompileCacheTarget {
		t.Errorf("VLLM_CACHE_ROOT = %q, want the mount itself", env["VLLM_CACHE_ROOT"])
	}
	// Not XDG_CACHE_HOME: it would also move HF_HOME off the HF cache mount.
	if _, ok := env["XDG_CACHE_HOME"]; ok {
		t.Error("XDG_CACHE_HOME set: it moves the HF cache off " + HFCacheTarget)
	}
}

// A data mount report counts host roots only; the volume is none.
func TestCompileCacheVolumeIsNoBindSource(t *testing.T) {
	mounts, _ := buildMounts([]VolumeMount{{Source: VLLMCompileCacheVolume, Target: VLLMCompileCacheTarget, Volume: true}})
	if len(mounts) != 1 || mounts[0].Type != mount.TypeVolume || mounts[0].Source != VLLMCompileCacheVolume {
		t.Fatalf("got %+v", mounts)
	}
}
