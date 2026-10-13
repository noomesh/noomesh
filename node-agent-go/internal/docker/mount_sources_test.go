// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/mount"
	"github.com/noomesh/noomesh/node-agent-go/internal/dataroots"
)

// The 2026-09-29 host3 outage: a bind source that no longer existed was only
// discovered by Docker's create, after the running container was gone.
func TestRequireMountSourcesRefusesMissingBindSource(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "hf-cache")
	err := requireMountSources("vllm", []mount.Mount{
		{Type: mount.TypeBind, Source: missing, Target: "/root/.cache/huggingface"},
	})
	if err == nil {
		t.Fatal("expected a refusal for a missing bind source")
	}
	if !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "not replacing the running container") {
		t.Fatalf("error should name the path and say the old container stays: %v", err)
	}
}

func TestRequireMountSourcesAcceptsExistingAndNonBind(t *testing.T) {
	dir := t.TempDir()
	err := requireMountSources("vllm", []mount.Mount{
		{Type: mount.TypeBind, Source: dir, Target: "/root/.cache/huggingface"},
		{Type: mount.TypeVolume, Source: "named-volume-not-a-path", Target: "/data"},
	})
	if err != nil {
		t.Fatalf("existing bind + volume mount should pass: %v", err)
	}
}

// no backend spec carries one machine's path as its fallback;
// every derived source falls back to dataroots.DefaultDataRoot.
func TestBackendSpecsDeriveFromTheOneDefault(t *testing.T) {
	t.Setenv("NOO_DATA_ROOT", "")
	t.Setenv("HF_CACHE_DIR", "")
	t.Setenv("MODELS_DIR", "")
	t.Setenv("OLLAMA_DATA_DIR", "")
	seen := 0
	for name, spec := range backendSpecs {
		for _, v := range spec.Volumes {
			if strings.Contains(v.Source, "/mnt/") {
				t.Errorf("%s mounts %q: a machine-specific fallback", name, v.Source)
			}
			if strings.Contains(v.Source, "NOO_DATA_ROOT") || strings.Contains(v.Source, "MODELS_DIR") {
				seen++
				if got := resolveEnv(v.Source); !strings.HasPrefix(got, dataroots.DefaultDataRoot+"/") {
					t.Errorf("%s: %q resolves to %q, not under %s", name, v.Source, got, dataroots.DefaultDataRoot)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no data-root-derived mounts found; the check proved nothing")
	}
	t.Setenv("NOO_DATA_ROOT", "/srv/chosen")
	if got := resolveEnv(modelsSource); got != "/srv/chosen/models" {
		t.Fatalf("a chosen root must win: %q", got)
	}
}

// A missing source that came from the DEFAULT root says so and names the fix;
// one under a chosen root keeps the plain message.
func TestMissingDefaultRootSourceNamesTheFix(t *testing.T) {
	t.Setenv("NOO_DATA_ROOT", "")
	src := dataroots.DefaultDataRoot + "/no-such-dir-for-test/models"
	err := requireMountSources("vllm", []mount.Mount{{Type: mount.TypeBind, Source: src, Target: "/models"}})
	if err == nil || !strings.Contains(err.Error(), "NOO_DATA_ROOT is unset") ||
		!strings.Contains(err.Error(), "noo cluster set-config <node> --data-root <path>") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv("NOO_DATA_ROOT", "/srv/chosen")
	err = requireMountSources("vllm", []mount.Mount{{Type: mount.TypeBind, Source: "/srv/chosen/nope/models", Target: "/models"}})
	if err == nil || strings.Contains(err.Error(), "is unset") {
		t.Fatalf("a chosen root must not be called unset: %v", err)
	}
}
