// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package modelsets

import (
	"context"
	"testing"
)

// The gate reads a profile's min_compute from a manifest only once the set is
// verified here; a set that is not is an error, never a guess.
func TestVerifiedManifestIsOnlyReadFromAVerifiedSet(t *testing.T) {
	r := newRig(t)
	r.stage(refA, filesA, r.key)
	if _, err := r.store.VerifiedManifest(refA); err == nil {
		t.Fatal("a set not yet fetched returned a manifest")
	}
	if err := r.store.Fetch(context.Background(), refA); err != nil {
		t.Fatal(err)
	}
	set, err := r.store.VerifiedManifest(refA)
	if err != nil || set.ID != refA.ID || set.Revision != refA.Revision {
		t.Fatalf("manifest = %+v, %v", set, err)
	}
}
