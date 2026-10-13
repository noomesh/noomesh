// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestResolveFromRoot(t *testing.T) {
	r := Resolve(env(map[string]string{"NOO_DATA_ROOT": "/data/noo"}))
	want := Roots{"/data/noo", "env", "/data/noo/hf-cache", "/data/noo/models", "/data/noo/ollama"}
	if r != want {
		t.Fatalf("got %+v want %+v", r, want)
	}
}

func TestResolveExplicitDirsWinAndFallbackIsNamed(t *testing.T) {
	r := Resolve(env(map[string]string{"HF_CACHE_DIR": " /x/hf ", "MODELS_DIR": "/y/m"}))
	if r.NooDataRoot != DefaultDataRoot || r.NooDataRootSource != "default" {
		t.Fatalf("fallback must be reported as default: %+v", r)
	}
	if r.HFCacheDir != "/x/hf" || r.ModelsDir != "/y/m" || r.OllamaDataDir != DefaultDataRoot+"/ollama" {
		t.Fatalf("got %+v", r)
	}
}

func TestReportMountsShapes(t *testing.T) {
	r := Resolve(env(map[string]string{"NOO_DATA_ROOT": "/data/noo"}))
	rep := Report(r, func() (map[string][]string, error) { return nil, nil })
	if m, ok := rep["running_mounts"].(map[string][]string); !ok || m == nil || len(m) != 0 {
		t.Fatalf("no containers must be an empty map, got %#v", rep["running_mounts"])
	}
	rep = Report(r, func() (map[string][]string, error) { return nil, errors.New("docker down") })
	if _, has := rep["running_mounts"]; has || rep["running_mounts_error"] != "docker down" {
		t.Fatalf("docker error must omit mounts and say why: %#v", rep)
	}
	rep = Report(r, nil)
	if _, has := rep["running_mounts"]; has || rep["running_mounts_error"] == nil {
		t.Fatalf("nil source: %#v", rep)
	}
	rep = Report(r, func() (map[string][]string, error) {
		return map[string][]string{"vllm": {"/data/noo/hf-cache"}}, nil
	})
	if !reflect.DeepEqual(rep["running_mounts"], map[string][]string{"vllm": {"/data/noo/hf-cache"}}) {
		t.Fatalf("%#v", rep)
	}
}

// A real symlink on disk (the host3 shape: /opt/noo/hf-cache -> /data/noo/hf-cache),
// a real file, and a broken link.
func TestReportResolvesSymlinkedMountsAndRoot(t *testing.T) {
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(tmp, "data", "noo")
	if err := os.MkdirAll(filepath.Join(real, "hf-cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "opt-hf-cache")
	if err := os.Symlink(filepath.Join(real, "hf-cache"), link); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(tmp, "broken")
	if err := os.Symlink(filepath.Join(tmp, "nowhere"), broken); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(tmp, "rootlink")
	if err := os.Symlink(real, rootLink); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(real, "hf-cache")
	missing := filepath.Join(tmp, "missing")

	r := Roots{NooDataRoot: rootLink, NooDataRootSource: "env"}
	rep := Report(r, func() (map[string][]string, error) {
		return map[string][]string{"vllm": {link, plain}, "ollama": {broken, missing}}, nil
	})
	got, _ := rep["running_mounts_resolved"].(map[string]string)
	want := map[string]string{link: plain}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("running_mounts_resolved = %v, want %v (plain, broken and missing sources must be omitted)", got, want)
	}
	if rep["noo_data_root_resolved"] != real {
		t.Fatalf("noo_data_root_resolved = %v, want %v", rep["noo_data_root_resolved"], real)
	}
	// running_mounts stays literal.
	m := rep["running_mounts"].(map[string][]string)
	if m["vllm"][0] != link {
		t.Fatalf("running_mounts was rewritten: %v", m)
	}
}

func TestReportOmitsResolutionWhenNothingDiffers(t *testing.T) {
	rep := Report(Roots{NooDataRoot: "/nonexistent/noo", NooDataRootSource: "env"},
		func() (map[string][]string, error) {
			return map[string][]string{"vllm": {"/nonexistent/noo/hf-cache"}}, nil
		})
	if _, ok := rep["running_mounts_resolved"]; ok {
		t.Fatalf("unresolvable path produced running_mounts_resolved: %v", rep)
	}
	if _, ok := rep["noo_data_root_resolved"]; ok {
		t.Fatalf("unresolvable root produced noo_data_root_resolved: %v", rep)
	}
}
