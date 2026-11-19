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
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// The container-level proof of the stack lane (.github/workflows/
// ollama-pull-record.yml). Skipped unless that job set the environment: it
// started our ollama image with its store bound at
// $NOO_PULLRECORD_DATA_ROOT/ollama (owner 65532, the image's umask), pulled
// the model through it, and had the CLI write the controller's record of that
// pull into $NOO_PULLRECORD_STORE (noo-cli ollama_stage.rs,
// the_record_of_a_real_pull_is_written_into_the_controller_store). This test
// runs as the runner's uid, not 65532: exactly noo-agent's position, reading
// the store through its "other" permission bits.
//
// NOO_PULLRECORD_WANT is the state the job expects: "verified" as the image
// left the store, "cannot-read" after it made one blob 0600.
func TestPullRecordContainerStackLaneVerifiesARealPull(t *testing.T) {
	root := os.Getenv("NOO_PULLRECORD_DATA_ROOT")
	store := os.Getenv("NOO_PULLRECORD_STORE")
	want := os.Getenv("NOO_PULLRECORD_WANT")
	if root == "" || store == "" || want == "" {
		t.Skip("the container job's proof: NOO_PULLRECORD_DATA_ROOT, NOO_PULLRECORD_STORE and NOO_PULLRECORD_WANT are not set")
	}
	model := os.Getenv("NOO_PULLRECORD_MODEL")
	if model == "" {
		model = "qwen2.5:0.5b"
	}
	if os.Geteuid() == 65532 {
		t.Fatal("run this as the runner's uid: as the store's owner it proves nothing about noo-agent's read")
	}
	// The stack lane derives its store from NOO_DATA_ROOT the way compose
	// does; OLLAMA_DATA_DIR pointing elsewhere must not matter.
	t.Setenv("NOO_DATA_ROOT", root)
	t.Setenv("OLLAMA_DATA_DIR", filepath.Join(t.TempDir(), "not-the-stack"))
	ns, name, tag, err := parseOllamaRef(model)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := mirrorRefOf(model)
	if !ok {
		t.Fatalf("%s is not a registry tag", model)
	}
	recordName := r.stem + mirrorManifestSuffix
	record, err := os.ReadFile(filepath.Join(store, recordName))
	if err != nil {
		t.Fatalf("the controller's record of the pull: %v", err)
	}
	v := &OllamaVerifier{
		ModelsDir: ollamaModelsDir(OllamaLaneStack),
		Lane:      OllamaLaneStack,
		Record:    preseed.OpenVerifiedRecord(filepath.Join(t.TempDir(), "ollama-blobs.json")),
		// The controller's store, read from disk: the record is what the
		// gateway would serve as the ollamamanifest artifact.
		lookup: func(_ context.Context, kind, art string) (string, error) {
			if kind == "ollamamanifest" && art == recordName {
				return hexOf(record), nil
			}
			return "", ErrArtifactAbsent
		},
		fetch: func(_ context.Context, art, sha string) ([]byte, error) {
			if art != recordName || sha != hexOf(record) {
				return nil, errors.New("not in the controller's store")
			}
			return record, nil
		},
		hash: preseed.HashFile,
		repair: func(context.Context, string, string, []string) error {
			t.Fatal("the stack lane repaired")
			return nil
		},
		now: time.Now,
	}
	if want, got := filepath.Join(root, "ollama", "models"), v.ModelsDir; got != want {
		t.Fatalf("stack lane store %q, want %q", got, want)
	}
	if _, err := os.Stat(v.manifestPath(ns, name, tag)); err != nil {
		t.Fatalf("the pulled manifest is not where the stack lane looks: %v", err)
	}
	res := v.Verify(context.Background(), model)
	t.Logf("%s: state=%s anchor=%s layer=%s reason=%s remedy=%s", model, res.State, res.Anchor, res.ModelLayer, res.Reason, res.Remedy)
	if res.State != want {
		t.Fatalf("state %q, want %q", res.State, want)
	}
	if want == OllamaCannotRead && !strings.Contains(res.Reason, "permission denied") {
		t.Fatalf("cannot-read without the permission named: %q", res.Reason)
	}
	if want == OllamaVerified && res.Anchor != OllamaAnchorMirror {
		t.Fatalf("verified against %q, want the record of the pull", res.Anchor)
	}
}
