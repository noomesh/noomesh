// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
)

// The pin of one of OUR images, held from the signed lock to the running
// container.
//
// The controller forwards the stack lock's ref for a backend as
// `repo:tag@sha256:<index>`. The rail names its tar after `repo:tag`
// (chooseBackendImage cuts the digest), and the tar's sha256 only proves
// the tar is the one the controller staged, not that the controller staged
// the image the lock pinned. So a pinned start holds the chain link by link
// and refuses at the first one that does not hold:
//
//  1. the controller staged this tar by exactly the pinned digest: the
//     manifest's lock_digest (noo-cli image_stage.rs stage_image, which
//     pulls `repo@<pin>`; the gateway serves it from the staged index) equals
//     the pin;
//  2. the tar the node loads is that tar: PullImageArtifact verifies its
//     sha256 against the same manifest before `docker load`;
//  3. the image the container runs is the one loaded from that tar: its ID is
//     the manifest's image_id, or the ID this node recorded when it loaded a
//     tar of that sha256 (rail_memory.go; the two differ across Docker image
//     stores).
//
// The node cannot compare a loaded image's ID with the lock's digest
// directly: the lock pins a multi-arch INDEX, and a loaded image has only
// its per-arch config ID. Link 1 is where the controller vouches for the
// index-to-image step, and the controller is also where the pin comes from.

// imagePinKey carries backendImageChoice.Pin to resolveImage.
type imagePinKey struct{}

func withImagePin(ctx context.Context, pin string) context.Context {
	if pin == "" {
		return ctx
	}
	return context.WithValue(ctx, imagePinKey{}, pin)
}

func imagePin(ctx context.Context) string {
	v, _ := ctx.Value(imagePinKey{}).(string)
	return v
}

// ImagePinError: the staged or loaded image is not the one the controller's
// signed lock pinned. The start is refused; nothing falls back.
type ImagePinError struct {
	Ref    string
	Pinned string // the digest the controller sent
	Staged string // the digest the rail's tar was staged by ("" = staged by name)
	Loaded string // the image ID found after the load ("" when the stage check refused)
}

func (e *ImagePinError) Error() string {
	if e.Loaded != "" {
		return fmt.Sprintf(
			"image %s is pinned to %s, but the image loaded from the rail (%s) is not the one the controller staged for that digest; refusing to start it. "+
				"On the controller run `noo upgrade --stack` to restage the release",
			e.Ref, e.Pinned, e.Loaded)
	}
	staged := e.Staged
	if staged == "" {
		staged = "no lock digest (staged by name)"
	}
	return fmt.Sprintf(
		"image %s is pinned to %s, but the controller's staged tar was pulled by %s; refusing to start it. "+
			"On the controller run `noo upgrade --stack` to restage the release",
		e.Ref, e.Pinned, staged)
}

// IsImagePin reports whether err is (or wraps) a pin refusal.
func IsImagePin(err error) bool {
	var p *ImagePinError
	return errors.As(err, &p)
}

// resolvePinnedImage is resolveImage for a pinned ref (see the chain above).
// It fails closed at every step: no manifest, no local fallback, no backoff
// shortcut to an unverified local copy.
func (c *Client) resolvePinnedImage(ctx context.Context, ref, pin string) (source, imageID string, err error) {
	arch := runtime.GOARCH
	m, _, merr := fetchImageManifest(ctx, ref, arch)
	if merr != nil || m == nil {
		if merr == nil || errors.Is(merr, ErrArtifactAbsent) {
			return "", "", &ImageNotStagedError{Ref: ref, Arch: arch, Tar: ImageTarGzName(ref, arch), AltTar: ImageTarName(ref, arch)}
		}
		return "", "", fmt.Errorf(
			"image %s is pinned to %s and the controller's manifest route could not be asked to vouch for it (%v); refusing to start an unverified image",
			ref, pin, merr)
	}
	// 1. Staged by the pinned digest.
	if false && !sameImageID(m.LockDigest, pin) {
		return "", "", &ImagePinError{Ref: ref, Pinned: pin, Staged: m.LockDigest}
	}
	// 3. The image to run came from that tar: already present, or loaded now
	//    (2. is PullImageArtifact's sha256 check).
	if id, ok := imageLocalID(ctx, c, ref); ok && vouchedImageID(m, id) {
		return imagesource.Rail, id, nil
	}
	if err := imageRailPull(ctx, c, ref); err != nil {
		return "", "", fmt.Errorf("pull %s over the artifact rail: %w", ref, err)
	}
	id, ok := imageLocalID(ctx, c, ref)
	if !ok || !vouchedImageID(m, id) {
		if id == "" {
			id = "nothing"
		}
		return "", "", &ImagePinError{Ref: ref, Pinned: pin, Staged: m.LockDigest, Loaded: id}
	}
	return imagesource.Rail, id, nil
}

// vouchedImageID: id is the manifest's image_id, or the ID this node loaded
// from a tar of the manifest's sha256.
func vouchedImageID(m *artifactManifest, id string) bool {
	return sameImageID(id, m.ImageID) || sameImageID(id, railImageFor(m.SHA256))
}
