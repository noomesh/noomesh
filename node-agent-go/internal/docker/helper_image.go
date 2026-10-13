// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Making sure the helper image is THERE before something needs it.
//
// # The live failure (host3, v0.2.39, tracker row R50)
//
// Every host operation the agent performs — create the models dir, chown
// it, test whether a weight file exists, copy weights out of the
// controller's store — runs in a disposable container from helperImage(),
// which on a released node resolves to
// `ghcr.io/noomesh/node-agent:<tag>` via the
// NOO_IMAGE_PREFIX/NOO_IMAGE_TAG pair the provisioner writes.
//
// A HOST-PROCESS node never has that image. The agent binary was installed
// as a binary — scp'd or delivered over the bundle rail — and nothing ever
// asked Docker to pull the image whose name the binary derives. GHCR is
// private, so the daemon cannot fetch it either: `docker pull` fails
// authentication, and the node holds no registry credential by design.
//
// So `ContainerCreate` answered "No such image", `runHelper` returned that
// as a plain error, and `preseedModel` — which treats ANY error as "the
// controller store does not have this model" — returned false and let the
// backend download from HuggingFace instead. That download then died
// mid-stream over the WAN. Three things went wrong and only the third was
// visible:
//
//  1. the helper image was missing and nothing tried to get it;
//  2. "my helper image is missing" was reported as "the store does not
//     have this model", which is a different fact with a different fix;
//  3. the fallback silently moved multi-GB of traffic from the LAN cache to
//     the public internet, which is the thing the model store exists to
//     avoid.
//
// # The fix
//
// The node fetches the helper over the SAME rail its backend images arrive
// on: the controller's image store, digest-verified, pulled by the node as
// its own identity (PullImageArtifact). No registry, no credential, no
// controller-side push.
//
// And when the rail cannot supply it, that is a REFUSAL — recorded on the
// refusals channel with the exact command that fixes it — never a fallback.
// A node that quietly downloads from HuggingFace because its helper is
// missing looks like a slow node, not a broken one.

// HelperImageUnavailableError says the helper image is not on this node and
// could not be fetched. It is a distinct type because the CALLER's decision
// turns on it: a genuine store miss may fall back to HuggingFace, and this
// must not.
type HelperImageUnavailableError struct {
	Ref string
	Err error
}

func (e *HelperImageUnavailableError) Error() string {
	return fmt.Sprintf("helper image %s is not on this node and could not be fetched over the artifact rail: %v", e.Ref, e.Err)
}

func (e *HelperImageUnavailableError) Unwrap() error { return e.Err }

// Fix is the command an operator runs on the CONTROLLER to unblock this
// node. It names the exact ref, because the default `sync-images` set does
// not cover it (see helperImageSyncHint).
func (e *HelperImageUnavailableError) Fix(nodeID string) string {
	if nodeID == "" {
		nodeID = "<node>"
	}
	return fmt.Sprintf("noo cluster sync-images %s -i %s --no-restart", nodeID, e.Ref)
}

// IsHelperImageUnavailable reports whether err is (or wraps) the refusal.
func IsHelperImageUnavailable(err error) bool {
	var target *HelperImageUnavailableError
	return errors.As(err, &target)
}

// helperPullBackoff is how long a failed fetch is remembered.
//
// Without it, a reconcile tick with several placements would attempt the
// same multi-hundred-MB fetch once per placement, and a node whose
// controller has not exported the tar would retry every five minutes
// forever. One attempt per window, then the recorded refusal stands until
// something changes.
const helperPullBackoff = 30 * time.Minute

var (
	helperMu       sync.Mutex
	helperLastFail time.Time
	helperLastRef  string
)

// EnsureHelperImage guarantees helperImage() is in the local image store,
// fetching it over the artifact rail if it is not.
//
// Called from runHelperScript, so EVERY helper operation is covered by one
// check rather than each caller remembering. The local inspect is a cheap
// call to a daemon on the same machine, and doing it every time makes this
// self-healing: an operator who `docker rmi`s the image gets it back on the
// next tick instead of a puzzle.
// The two daemon-facing steps are package-level vars so a test can
// exercise this decision without a Docker daemon — the same seam
// `pingDocker` uses a few files over, and for the same reason: the
// interesting logic here is "present? fetch? refuse?", not the API calls.
var (
	helperImagePresent = func(ctx context.Context, c *Client, ref string) bool {
		_, err := c.docker.ImageInspect(ctx, ref)
		return err == nil
	}
	helperImagePull = func(ctx context.Context, c *Client, ref string) (*PullImageArtifactResult, error) {
		// The SAME rail backend images arrive on: the controller's export,
		// digest-verified, fetched by the node as its own identity. Never a
		// registry pull — GHCR is private and the node holds no credential,
		// which is the whole reason the rail exists.
		return c.PullImageArtifact(ctx, ref, "", "")
	}
)

func (c *Client) EnsureHelperImage(ctx context.Context) error {
	ref := helperImage()
	if helperImagePresent(ctx, c, ref) {
		return nil
	}

	helperMu.Lock()
	recentlyFailed := ref == helperLastRef && time.Since(helperLastFail) < helperPullBackoff
	helperMu.Unlock()
	if recentlyFailed {
		return &HelperImageUnavailableError{
			Ref: ref,
			Err: fmt.Errorf("a fetch failed less than %s ago; not retrying yet", helperPullBackoff),
		}
	}

	slog.Warn("helper image is not on this node; fetching it over the artifact rail",
		"image", ref,
		"detail", "every host operation (models dir, weight preseed) runs in a container from this image; "+
			"a host-process node never pulled it and cannot reach the private registry")

	res, err := helperImagePull(ctx, c, ref)
	if err != nil {
		helperMu.Lock()
		helperLastFail, helperLastRef = time.Now(), ref
		helperMu.Unlock()
		return &HelperImageUnavailableError{Ref: ref, Err: err}
	}

	helperMu.Lock()
	helperLastFail, helperLastRef = time.Time{}, ""
	helperMu.Unlock()
	slog.Info("helper image fetched over the artifact rail", "image", ref, "status", res.Status, "tar", res.Tar)
	return nil
}

// resetHelperImageBackoff clears the remembered failure. Tests only.
func resetHelperImageBackoff() {
	helperMu.Lock()
	helperLastFail, helperLastRef = time.Time{}, ""
	helperMu.Unlock()
}

// HelperImageRef is the helper image this node would use. Exported so the
// reconciler can name it on a refusal without duplicating the derivation.
func HelperImageRef() string { return helperImage() }

// HelperImageFix is the operator-facing refusal reason, including the exact
// command. Exported for the same reason.
func HelperImageFix(nodeID string) string {
	if nodeID == "" || nodeID == "auto" {
		nodeID = nodeIDForHints()
	}
	return helperImageSyncHint(nodeID, helperImage())
}

// helperImageSyncHint is the operator-facing explanation carried on the
// refusal, and it names the ref explicitly ON PURPOSE.
//
// `noo cluster sync-images` with no `-i` syncs `noomesh/node-agent:latest`
// and `pai-assistant/node-agent:latest` — the unprefixed LOCAL build names.
// A released node's helperImage() is the GHCR ref with a version tag, so
// the default set does not contain it and the bare command appears to
// succeed while changing nothing on this node. That skew is exactly how the
// host3 incident needed a hand-written `-i`.
func helperImageSyncHint(nodeID, ref string) string {
	if nodeID == "" {
		nodeID = "<node>"
	}
	return fmt.Sprintf(
		"this node cannot run host operations (models dir, weight preseed) without the helper image %s, "+
			"and it is neither present locally nor in the controller's image store. On the controller: "+
			"`noo cluster sync-images %s -i %s --no-restart`. The bare `sync-images` will NOT do it — its "+
			"default set names the unprefixed local builds, not this node's release ref.",
		ref, nodeID, ref)
}

// nodeIDForHints is the node's own id, for putting a copy-pasteable command
// in a message. Best-effort: a missing NODE_ID costs a placeholder, not the
// message.
func nodeIDForHints() string {
	if v := os.Getenv("NODE_ID"); v != "" && v != "auto" {
		return v
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}
