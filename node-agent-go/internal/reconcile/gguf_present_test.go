// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

const ggufModel = "m.gguf"

// ggufFixture: a Reconciler whose file check answers from present (and
// records the dir it was asked about).
func ggufFixture(t *testing.T, present *bool, askedDir *string) *Reconciler {
	t.Helper()
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	return &Reconciler{
		cfg: &config.Config{NodeID: "node-a"},
		ggufExists: func(_ context.Context, dir, file string) (bool, error) {
			if file != ggufModel {
				t.Fatalf("checked file %q, want %q", file, ggufModel)
			}
			if askedDir != nil {
				*askedDir = dir
			}
			return *present, nil
		},
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ggufStartRefusals() map[string]string {
	out := map[string]string{}
	for _, rf := range refusals.List() {
		if rf.Scope == "backend_start" {
			out[rf.Target] = rf.Reason
		}
	}
	return out
}

var ggufPlacement = placement{Backend: "llamacpp", Model: ggufModel, DesiredState: "running"}

func TestQuarantinedGGUFOnDefaultModelsDirIsNotStartedAndRefused(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MODELS_DIR", dir)
	touch(t, filepath.Join(dir, ggufModel+".quarantined-20261118T134753Z"))
	present, asked := false, ""
	r := ggufFixture(t, &present, &asked)
	// No controller-declared models_dir: the node's own default is mounted.
	tk := &tick{desired: &desiredConfig{}}
	if r.ggufPresent(context.Background(), tk, ggufPlacement) {
		t.Fatal("a quarantined gguf on the default models dir was let through to start")
	}
	if asked != dir {
		t.Fatalf("checked dir %q, want the effective default %q", asked, dir)
	}
	want := "gguf_quarantined: m.gguf was proven not to match the controller's record and moved aside to " +
		filepath.Join(dir, ggufModel+".quarantined-20261118T134753Z") +
		"; ship the verified file: noo cluster sync-model-files node-a -m m.gguf"
	if got := ggufStartRefusals()["llamacpp"]; got != want {
		t.Fatalf("refusal = %q, want %q", got, want)
	}
}

func TestGGUFQuarantinedSiblingRefusalNamesItAndTheSyncRemedy(t *testing.T) {
	dir := t.TempDir()
	touch(t, filepath.Join(dir, ggufModel+".quarantined-20261101T000000Z"))
	touch(t, filepath.Join(dir, ggufModel+".quarantined-20261117T120000Z"))
	present := false
	r := ggufFixture(t, &present, nil)
	tk := &tick{desired: &desiredConfig{}, modelsDir: dir}
	if r.ggufPresent(context.Background(), tk, ggufPlacement) {
		t.Fatal("a quarantined gguf was let through to start")
	}
	want := "gguf_quarantined: m.gguf was proven not to match the controller's record and moved aside to " +
		filepath.Join(dir, ggufModel+".quarantined-20261117T120000Z") +
		"; ship the verified file: noo cluster sync-model-files node-a -m m.gguf"
	if got := ggufStartRefusals()["llamacpp"]; got != want {
		t.Fatalf("refusal = %q, want %q", got, want)
	}
}

func TestMissingGGUFWithoutQuarantinedSiblingIsModelMissing(t *testing.T) {
	dir := t.TempDir()
	// Another model's quarantined file is not this model's sibling.
	touch(t, filepath.Join(dir, "other.gguf.quarantined-20261117T120000Z"))
	present := false
	r := ggufFixture(t, &present, nil)
	tk := &tick{desired: &desiredConfig{}, modelsDir: dir}
	if r.ggufPresent(context.Background(), tk, ggufPlacement) {
		t.Fatal("a missing gguf was let through to start")
	}
	want := "model_missing: m.gguf is not in " + dir + "; ship it: noo cluster sync-model-files node-a -m m.gguf"
	if got := ggufStartRefusals()["llamacpp"]; got != want {
		t.Fatalf("refusal = %q, want %q", got, want)
	}
}

func TestMissingGGUFRefusalIsNotClearedWhileTheFileStaysMissing(t *testing.T) {
	dir := t.TempDir()
	present := false
	r := ggufFixture(t, &present, nil)
	tk := &tick{desired: &desiredConfig{}, modelsDir: dir}
	want := "model_missing: m.gguf is not in " + dir + "; ship it: noo cluster sync-model-files node-a -m m.gguf"
	for pass := 1; pass <= 2; pass++ {
		if r.ggufPresent(context.Background(), tk, ggufPlacement) {
			t.Fatalf("pass %d: a missing gguf was let through to start", pass)
		}
		// The success path of a container left running (or of another
		// start) must not wipe the refusal while the file is missing.
		r.clearBackendStart("llamacpp")
		if got := ggufStartRefusals()["llamacpp"]; got != want {
			t.Fatalf("pass %d: refusal = %q, want %q", pass, got, want)
		}
	}
}

func TestGGUFPresentAgainStartsAndClearsTheRefusal(t *testing.T) {
	dir := t.TempDir()
	present := false
	r := ggufFixture(t, &present, nil)
	tk := &tick{desired: &desiredConfig{}, modelsDir: dir}
	if r.ggufPresent(context.Background(), tk, ggufPlacement) {
		t.Fatal("a missing gguf was let through to start")
	}
	present = true // the verified file was shipped
	if !r.ggufPresent(context.Background(), tk, ggufPlacement) {
		t.Fatal("a present gguf was not started")
	}
	r.clearBackendStart("llamacpp") // the start succeeded
	if got, ok := ggufStartRefusals()["llamacpp"]; ok {
		t.Fatalf("refusal still standing after the file returned and the start succeeded: %q", got)
	}
}

// A plain missing gguf on the node's own default dir (a first placement,
// nothing quarantined) goes on to the start, whose preseed fetches a verified
// copy from the controller's store: no refusal, as before #1303's guard.
func TestMissingGGUFOnDefaultModelsDirWithoutQuarantineGoesOnToPreseed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MODELS_DIR", dir)
	present := false
	r := ggufFixture(t, &present, nil)
	tk := &tick{desired: &desiredConfig{}}
	if !r.ggufPresent(context.Background(), tk, ggufPlacement) {
		t.Fatal("a first placement on the default dir was refused before the preseed could fetch it")
	}
	if got := ggufStartRefusals()["llamacpp"]; got != "" {
		t.Fatalf("refusal recorded for a fetchable first placement: %q", got)
	}
}
