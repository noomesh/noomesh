// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelsets

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A manifest that is on disk and parses is still not read once the set stops
// being verified here (the marker is gone, or the manifest no longer matches
// it): VerifiedManifest judges the set first, not only the file.
func TestVerifiedManifestIsRefusedOnceTheSetIsNoLongerVerified(t *testing.T) {
	for name, undo := range map[string]func(t *testing.T, dir string){
		"the marker is gone": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, MarkerName)); err != nil {
				t.Fatal(err)
			}
		},
		"the manifest no longer matches the marker": func(t *testing.T, dir string) {
			p := filepath.Join(dir, ManifestName)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.stage(refA, filesA, r.key)
			if err := r.store.Fetch(context.Background(), refA); err != nil {
				t.Fatal(err)
			}
			if _, err := r.store.VerifiedManifest(refA); err != nil {
				t.Fatalf("verified set: %v", err)
			}
			dir := r.store.dir(refA)
			if err := os.Chmod(dir, 0o755); err != nil { // sealed sets are 0555
				t.Fatal(err)
			}
			undo(t, dir)
			if set, err := r.store.VerifiedManifest(refA); err == nil {
				t.Fatalf("a set that is no longer verified returned its manifest: %+v", set)
			}
		})
	}
}
