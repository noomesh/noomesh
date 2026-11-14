// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

// idStore answers inspect by exact ref or ID; tag records what it named.
type idStore struct {
	names  map[string]string // ref or ID → ID
	arch   string
	tagged []string
	tagErr error
}

func (s *idStore) inspect(_ context.Context, ref string) (string, string, error) {
	id, ok := s.names[ref]
	if !ok {
		return "", "", errors.New("No such image: " + ref)
	}
	return id, s.arch, nil
}

func (s *idStore) tag(_ context.Context, source, target string) error {
	if s.tagErr != nil {
		return s.tagErr
	}
	s.tagged = append(s.tagged, source+"→"+target)
	s.names[target] = source
	return nil
}

const (
	retagOld = "ghcr.io/noomesh/ollama:v0.6.23"
	retagNew = "ghcr.io/noomesh/ollama:v0.6.24"
)

var retagID = "sha256:" + strings.Repeat("7", 64)

// i675 F4: a roll that re-tagged the same digest. The node holds the ID
// under the old tag; the manifest vouches for that ID; the new ref is
// tagged, nothing is fetched.
func TestRetagVouchedTagsAnIDAlreadyHereUnderAnotherTag(t *testing.T) {
	st := &idStore{names: map[string]string{retagOld: retagID, retagID: retagID}, arch: runtime.GOARCH}
	id, ok := retagVouched(context.Background(), st, retagNew, &artifactManifest{ImageID: retagID, SHA256: strings.Repeat("a", 64)})
	if !ok || id != retagID {
		t.Fatalf("not re-tagged: id %q ok %v", id, ok)
	}
	if len(st.tagged) != 1 || st.tagged[0] != retagID+"→"+retagNew {
		t.Fatalf("tagged %v", st.tagged)
	}
}

// Nothing vouched is present (or the manifest names no ID): no tag, the
// caller fetches the tar.
func TestRetagVouchedFetchesWhenTheVouchedIDIsAbsent(t *testing.T) {
	other := "sha256:" + strings.Repeat("8", 64)
	st := &idStore{names: map[string]string{retagOld: other, other: other}, arch: runtime.GOARCH}
	if _, ok := retagVouched(context.Background(), st, retagNew, &artifactManifest{ImageID: retagID}); ok || len(st.tagged) != 0 {
		t.Fatalf("an image the manifest does not vouch for was tagged: %v", st.tagged)
	}
	if _, ok := retagVouched(context.Background(), st, retagNew, &artifactManifest{}); ok || len(st.tagged) != 0 {
		t.Fatalf("a manifest with no ID re-tagged something: %v", st.tagged)
	}
	if _, ok := retagVouched(context.Background(), st, retagNew, nil); ok {
		t.Fatal("a nil manifest re-tagged")
	}
}

// An ID lookup the daemon answers with a DIFFERENT image (a short or
// ambiguous ID resolving elsewhere) is not the vouched image: fetch.
func TestRetagVouchedRefusesAnIDLookupThatResolvesElsewhere(t *testing.T) {
	other := "sha256:" + strings.Repeat("9", 64)
	st := &idStore{names: map[string]string{retagID: other}, arch: runtime.GOARCH}
	if _, ok := retagVouched(context.Background(), st, retagNew, &artifactManifest{ImageID: retagID}); ok || len(st.tagged) != 0 {
		t.Fatalf("an image other than the vouched one was tagged: %v", st.tagged)
	}
}

// The vouched ID at a FOREIGN arch (a foreign-arch stage left on this node)
// is not this node's image: fetch.
func TestRetagVouchedRefusesAForeignArch(t *testing.T) {
	foreign := "arm64"
	if runtime.GOARCH == "arm64" {
		foreign = "amd64"
	}
	st := &idStore{names: map[string]string{retagID: retagID}, arch: foreign}
	if _, ok := retagVouched(context.Background(), st, retagNew, &artifactManifest{ImageID: retagID}); ok || len(st.tagged) != 0 {
		t.Fatalf("a foreign-arch image was tagged: %v", st.tagged)
	}
}

// A tag that fails, or a ref that afterwards names something else, is not
// a skip.
func TestRetagVouchedFetchesWhenTheTagDoesNotTake(t *testing.T) {
	st := &idStore{names: map[string]string{retagID: retagID}, arch: runtime.GOARCH, tagErr: errors.New("daemon said no")}
	if _, ok := retagVouched(context.Background(), st, retagNew, &artifactManifest{ImageID: retagID}); ok {
		t.Fatal("a failed tag counted as a skip")
	}
	race := &racingStore{idStore{names: map[string]string{retagID: retagID}, arch: runtime.GOARCH}}
	if _, ok := retagVouched(context.Background(), race, retagNew, &artifactManifest{ImageID: retagID}); ok {
		t.Fatal("a ref that does not name the tagged image afterwards counted as a skip")
	}
}

// racingStore: the tag "succeeds" but the ref then names another image
// (re-tagged under us by a concurrent load).
type racingStore struct{ idStore }

func (r *racingStore) tag(_ context.Context, source, target string) error {
	r.names[target] = "sha256:" + strings.Repeat("5", 64)
	return nil
}

// PullImageArtifact asks retagVouched AFTER the manifest is fetched (the
// vouching) and BEFORE anything is downloaded, and only when a caller's
// controllerImageID agrees with the manifest.
func TestPullImageArtifactRetagsBeforeFetching(t *testing.T) {
	src, err := os.ReadFile("artifacts.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "func (c *Client) PullImageArtifact(")
	if start < 0 {
		t.Fatal("PullImageArtifact moved: this guard is stale")
	}
	body := s[start:]
	man := strings.Index(body, "fetchImageManifest(ctx, ref, arch)")
	re := strings.Index(body, "retagVouched(ctx, dockerImageStore{c}, ref, m)")
	fetch := strings.Index(body, "FetchOneVerified(")
	if man < 0 || re < 0 || fetch < 0 {
		t.Fatalf("manifest %d, retag %d, fetch %d: a step is missing", man, re, fetch)
	}
	if !(man < re && re < fetch) {
		t.Fatalf("order manifest %d < retag %d < fetch %d broken", man, re, fetch)
	}
	if !strings.Contains(body[:re], `(controllerImageID == "" || sameImageID(controllerImageID, m.ImageID))`) {
		t.Fatal("the re-tag ignores the caller's controllerImageID")
	}
}
