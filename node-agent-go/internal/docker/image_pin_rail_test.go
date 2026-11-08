// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
)

// The 0.6.18 roll: aserve and robopi refused the staged hardened ollama
// because the agent asked the rail for a tar named after the lock's digest.

const (
	pinnedOllama = "ghcr.io/noomesh/ollama:v0.6.18"
	thePin       = "sha256:2c99870b2514d9e143c3f33f3d5a9b4cbe89516e32343e5ac9c1379a9123844b"
	otherPin     = "sha256:5d3a2f25f9825628daba94dc0b1d421c7d57d6c03ae5faa9ba050e058bab8241"
)

// THE staged-name rule, held to the same table noo-cli and the gateway read:
// an own ref with a digest names its rail tar after the tag ref, and the
// digest survives as the pin.
func TestOwnImageRefsNameTheStagedTarLikeTheCLIAndTheGateway(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "own_image_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Rows []struct {
			Ref       string `json:"ref"`
			Arch      string `json:"arch"`
			StagedRef string `json:"staged_ref"`
			TarGz     string `json:"tar_gz"`
		} `json:"staged_names"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Rows) < 4 {
		t.Fatalf("fixture parse found %d staged_names rows", len(fx.Rows))
	}
	for _, r := range fx.Rows {
		clearImageEnv(t)
		// The row's registry is this node's own prefix, so the ref is ours.
		repo := r.StagedRef[:strings.LastIndex(r.StagedRef, ":")]
		t.Setenv("NOO_IMAGE_PREFIX", repo[:strings.LastIndex(repo, "/")])
		ch, err := chooseBackendImage("ollama", backendSpecs["ollama"], r.Ref)
		if err != nil {
			t.Fatalf("%s: %v", r.Ref, err)
		}
		if ch.Ref != r.StagedRef || !ch.RailOnly {
			t.Errorf("%s: choice %+v, want ref %s, rail-only", r.Ref, ch, r.StagedRef)
		}
		if got := ImageTarGzName(ch.Ref, r.Arch); got != r.TarGz {
			t.Errorf("%s: asks the rail for %s, the controller stages %s", r.Ref, got, r.TarGz)
		}
		_, wantPin := splitDigest(r.Ref)
		if ch.Pin != wantPin {
			t.Errorf("%s: pin %q, want %q", r.Ref, ch.Pin, wantPin)
		}
	}
}

// The start path hands the choice's pin to the image fetch.
func TestThePinTravelsFromTheChoiceToTheImageFetch(t *testing.T) {
	clearImageEnv(t)
	var gotRef, gotPin string
	prev := ensureImageFn
	ensureImageFn = func(ctx context.Context, _ *Client, ref string) error {
		gotRef, gotPin = ref, imagePin(ctx)
		return errSentinelEnsure
	}
	t.Cleanup(func() { ensureImageFn = prev })
	err := (&Client{}).StartBackendSDK(context.Background(), "ollama", "m", 0, StartOverrides{Image: pinnedOllama + "@" + thePin})
	if !errors.Is(err, errSentinelEnsure) {
		t.Fatalf("start: %v", err)
	}
	if gotRef != pinnedOllama || gotPin != thePin {
		t.Fatalf("fetch asked for %q pinned %q, want %q pinned %q", gotRef, gotPin, pinnedOllama, thePin)
	}
}

func pinnedStage(lockDigest string) map[string]*artifactManifest {
	return map[string]*artifactManifest{
		ImageTarName(pinnedOllama, runtime.GOARCH): {SHA256: strings.Repeat("b", 64), ImageID: "sha256:staged", LockDigest: lockDigest},
	}
}

func pinnedCtx() context.Context {
	return withImagePin(context.Background(), thePin)
}

func TestAPinnedImageStagedByItsDigestIsLoadedFromTheRail(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{}, staged: pinnedStage(thePin)}
	f.install(t)
	if err := (&Client{}).EnsureImage(pinnedCtx(), pinnedOllama); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	if len(f.railPulls) != 1 || len(f.registryPull) != 0 {
		t.Fatalf("rail pulls %v, registry pulls %v", f.railPulls, f.registryPull)
	}
	if got := sourceOf(t, pinnedOllama); got != imagesource.Rail {
		t.Errorf("source = %q, want rail", got)
	}
}

func TestAPinnedImagePresentAtTheStagedIDRunsWithoutAPull(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{pinnedOllama: "sha256:staged"}, staged: pinnedStage(thePin)}
	f.install(t)
	if err := (&Client{}).EnsureImage(pinnedCtx(), pinnedOllama); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	if len(f.railPulls) != 0 {
		t.Fatalf("rail pulls %v, want none", f.railPulls)
	}
}

// Check 1: the tar the rail holds was not staged by the pinned digest.
func TestAPinnedImageStagedByAnotherDigestIsRefused(t *testing.T) {
	for _, staged := range []string{otherPin, ""} {
		t.Run("staged="+staged, func(t *testing.T) {
			// Present locally at the staged ID too: the pin still decides.
			f := &fakeImageRail{local: map[string]string{pinnedOllama: "sha256:staged"}, staged: pinnedStage(staged)}
			f.install(t)
			err := (&Client{}).EnsureImage(pinnedCtx(), pinnedOllama)
			if !IsImagePin(err) {
				t.Fatalf("want ImagePinError, got %v", err)
			}
			want := []string{pinnedOllama, thePin, "noo upgrade --stack"}
			if staged == "" {
				want = append(want, "staged by name")
			} else {
				want = append(want, otherPin)
			}
			for _, w := range want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal lacks %q: %v", w, err)
				}
			}
			if len(f.railPulls) != 0 || len(f.registryPull) != 0 {
				t.Errorf("nothing is pulled for a refused pin: rail %v registry %v", f.railPulls, f.registryPull)
			}
		})
	}
}

// Check 3: the image the load produced is not the one staged from that tar.
func TestAPinnedImageWhoseLoadIsNotTheStagedOneIsRefused(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{}, staged: pinnedStage(thePin)}
	f.install(t)
	imageRailPull = func(_ context.Context, _ *Client, ref string) error {
		f.railPulls = append(f.railPulls, ref)
		f.local[ref] = "sha256:not-the-staged-one"
		return nil
	}
	err := (&Client{}).EnsureImage(pinnedCtx(), pinnedOllama)
	if !IsImagePin(err) {
		t.Fatalf("want ImagePinError, got %v", err)
	}
	for _, w := range []string{pinnedOllama, thePin, "sha256:not-the-staged-one"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal lacks %q: %v", w, err)
		}
	}
	if got := sourceOf(t, pinnedOllama); got != "" {
		t.Errorf("a refused image is recorded as %q", got)
	}
}

// A present local copy is not run when the controller cannot vouch for it.
func TestAPinnedImageIsNotRunUnverifiedWhenTheManifestRouteFails(t *testing.T) {
	f := &fakeImageRail{
		local:       map[string]string{pinnedOllama: "sha256:staged"},
		manifestErr: errors.New("connection refused"),
	}
	f.install(t)
	err := (&Client{}).EnsureImage(pinnedCtx(), pinnedOllama)
	if err == nil || !strings.Contains(err.Error(), "refusing to start an unverified image") || !strings.Contains(err.Error(), thePin) {
		t.Fatalf("want a fail-closed refusal naming the pin, got %v", err)
	}
	if len(f.railPulls) != 0 || len(f.registryPull) != 0 {
		t.Errorf("rail %v registry %v", f.railPulls, f.registryPull)
	}
}
