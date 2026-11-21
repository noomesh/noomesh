// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// A manifest still being hashed is a staged image: the pull and the start say
// so and neither says "not staged" nor "run sync-images" (i1159b row 14: the
// sibling of the GGUF wording).
func TestPullImageArtifactStillHashingIsNotImageNotStaged(t *testing.T) {
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	srv := pki.Store(t, http.NotFoundHandler())
	t.Setenv("NOO_MODEL_CACHE_URL", srv.URL)
	prev := imageManifestFetch
	imageManifestFetch = func(context.Context, string) (*artifactManifest, error) {
		return nil, &hashingError{retryAfter: 5 * time.Second}
	}
	t.Cleanup(func() { imageManifestFetch = prev })

	_, err := (&Client{}).PullImageArtifact(context.Background(), ownRef, "", "")
	if err == nil {
		t.Fatal("want an error")
	}
	if IsImageNotStaged(err) {
		t.Fatalf("a hashing controller has the image staged: %v", err)
	}
	for _, want := range []string{"the controller is still hashing", "retry shortly", "it keeps hashing between requests"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q is missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "auth failed") || strings.Contains(err.Error(), "sync-images") {
		t.Errorf("the hashing wait must not blame the route or tell the operator to stage: %v", err)
	}
}

func TestEnsureImageStillHashingIsRetriedNotNotStaged(t *testing.T) {
	for _, policy := range []string{"", "public", "off"} {
		for name, merr := range map[string]error{
			"hashing": &hashingError{retryAfter: time.Second},
			"budget":  fmt.Errorf("%w: the controller was still hashing the file after 10m", ErrArtifactManifestTimeout),
		} {
			t.Run(name+"/policy="+policy, func(t *testing.T) {
				t.Setenv(RegistryFallbackEnv, policy)
				f := &fakeImageRail{local: map[string]string{}, manifestErr: merr}
				f.install(t)
				err := (&Client{}).EnsureImage(context.Background(), ownRef)
				if err == nil || IsImageNotStaged(err) {
					t.Fatalf("want the hashing error, got %v", err)
				}
				for _, want := range []string{ownRef + ": the controller is still hashing its image tar", "the start is retried on the next reconcile pass"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q is missing %q", err, want)
					}
				}
				if strings.Contains(err.Error(), "not staged") || strings.Contains(err.Error(), "sync-images") {
					t.Errorf("says not staged: %v", err)
				}
				if len(f.registryPull) != 0 || len(f.railPulls) != 0 {
					t.Errorf("nothing may be pulled: rail %v registry %v", f.railPulls, f.registryPull)
				}
			})
		}
	}
}
