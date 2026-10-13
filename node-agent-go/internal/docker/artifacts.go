// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Artifact pulls — the design (the /pull verb, image kind).
//
// The controller exports `docker save` tars into its image store
// (${IMAGES_DIR}, served by the model-cache nginx as /images/ and described
// by the gateway's artifact manifest). This file is the node side: given an
// image REF, derive the tar name for THIS node's architecture, fetch it
// digest-verified, and `docker load` it. The direction inversion is the
// point — the controller never SSHes bytes at the node; the node pulls as
// its own service identity over the same mTLS transport everything else
// uses. And because the tar name embeds runtime.GOARCH, the historical
// upgrade-agents bug (x86 image shipped to an ARM node, reported as
// success) becomes structurally impossible: a node can only ever ask for
// its own architecture, and a store miss is an honest 404.
package docker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/moby/moby/client"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// ImageTarName maps an image ref + architecture to the flat filename the
// controller's export uses: '/' and ':' become '_', then "_<arch>.tar".
// MUST stay in lockstep with `image_tar_name` in noo-cli's sync-images —
// the convention IS the protocol (there is no lookup table to drift from).
func ImageTarName(ref, arch string) string {
	sanitized := strings.NewReplacer("/", "_", ":", "_").Replace(ref)
	return sanitized + "_" + arch + ".tar"
}

// PullImageArtifactResult is the honest outcome of one pull.
type PullImageArtifactResult struct {
	Status  string `json:"status"` // "loaded" | "up_to_date"
	Image   string `json:"image"`
	Tar     string `json:"tar"`
	Arch    string `json:"arch"`
	Removed string `json:"removed_container,omitempty"`
}

// stagingDir is where fetched tars land before `docker load` reads them.
// The agent is a host process; /var/lib keeps multi-GB tars off
// tmpfs-backed /tmp on hosts that mount it that way.
func stagingDir() string {
	if d := os.Getenv("NOO_AGENT_STAGING_DIR"); d != "" {
		return d
	}
	return "/var/lib/noo-node-agent/staging"
}

// PullImageArtifact fetches the controller's exported tar for ref (at this
// node's arch), verifies it against the artifact manifest, and loads it.
//
// controllerImageID, when non-empty, short-circuits: if the local image
// already has that ID the transfer is skipped ("up_to_date") — the same
// check the SSH-era sync did with a remote `docker image inspect`, now run
// where the answer lives. removeContainer, when non-empty, force-removes
// that container AFTER a successful load so the next backend start
// recreates it on the new image (BackendManager/desired-state owns the
// bring-back; this deliberately does not restart anything itself).
//
// Unlike GGUF preseeds, the digest is REQUIRED: an image is executable
// code, and "no manifest" also means the store has no tar for this arch —
// there is nothing honest to pull unverified.
func (c *Client) PullImageArtifact(ctx context.Context, ref, controllerImageID, removeContainer string) (*PullImageArtifactResult, error) {
	if ref == "" || strings.ContainsAny(ref, " \t\n") {
		return nil, fmt.Errorf("invalid image ref %q", ref)
	}
	cacheURL := preseed.CacheURL()
	if cacheURL == "" {
		return nil, fmt.Errorf("NOO_MODEL_CACHE_URL is not set — no data plane to pull from")
	}
	arch := runtime.GOARCH
	tarName := ImageTarName(ref, arch)

	if controllerImageID != "" {
		if inspect, err := c.docker.ImageInspect(ctx, ref); err == nil && inspect.ID == controllerImageID {
			return &PullImageArtifactResult{Status: "up_to_date", Image: ref, Tar: tarName, Arch: arch}, nil
		}
	}

	m, merr := imageManifestFetch(ctx, tarName)
	if merr != nil {
		if errors.Is(merr, ErrArtifactAbsent) {
			return nil, &ImageNotStagedError{Ref: ref, Arch: arch, Tar: tarName}
		}
		return nil, fmt.Errorf(
			"no artifact manifest for %s (the manifest route or its auth failed: %v) — an image is executable code, so nothing is pulled unverified",
			tarName, merr)
	}
	sha := m.SHA256

	if err := os.MkdirAll(stagingDir(), 0o755); err != nil {
		return nil, fmt.Errorf("staging dir: %w", err)
	}
	staged := filepath.Join(stagingDir(), tarName)
	src := cacheURL + "/images/" + url.PathEscape(tarName)
	slog.Info("pulling image artifact", "image", ref, "tar", tarName, "sha256", sha[:12]+"…")
	fetchCtx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	defer cancel()
	if _, err := preseed.New().FetchOneVerified(fetchCtx, src, staged, sha); err != nil {
		if errors.Is(err, preseed.ErrDigestMismatch) {
			return nil, &ImageVerificationError{Ref: ref, Err: fmt.Errorf("fetch %s: %w", tarName, err)}
		}
		return nil, fmt.Errorf("fetch %s: %w", tarName, err)
	}
	// The tar is single-use: remove it whether or not the load succeeds. A
	// re-run re-fetches (LAN-cheap), and a failed load never leaves a
	// multi-GB corpse accumulating in /var/lib.
	defer os.Remove(staged)

	// Before the daemon sees a byte: the archive must describe exactly ONE
	// image, tagged as nothing or as the ref asked for. A verified tar from
	// a controller that names another image (say `alpine:latest`) would
	// otherwise re-point that tag on this node as a side effect of loading.
	if err := checkTarManifest(staged, ref); err != nil {
		return nil, &ImageVerificationError{Ref: ref, Err: err}
	}

	f, err := os.Open(staged)
	if err != nil {
		return nil, fmt.Errorf("open staged tar: %w", err)
	}
	defer f.Close()
	res, err := c.docker.ImageLoad(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("docker load: %w", err)
	}
	// Drain the progress stream — the daemon only commits the load as the
	// body is consumed, and Close alone can truncate it.
	loadOut := drainToString(res)
	res.Close()
	if strings.Contains(loadOut, "\"error\"") {
		return nil, fmt.Errorf("docker load reported: %s", strings.TrimSpace(loadOut))
	}
	slog.Info("image artifact loaded", "image", ref, "detail", strings.TrimSpace(lastLine(loadOut)))

	id, err := finishLoad(ctx, dockerImageStore{c}, ref, loadOut, arch)
	if err != nil {
		return nil, err
	}
	rememberRailImage(sha, id)

	out := &PullImageArtifactResult{Status: "loaded", Image: ref, Tar: tarName, Arch: arch}
	if removeContainer != "" {
		if _, err := c.docker.ContainerRemove(ctx, removeContainer, client.ContainerRemoveOptions{Force: true}); err != nil {
			slog.Warn("post-load container remove failed (continuing — image is loaded)",
				"container", removeContainer, "err", err)
		} else {
			out.Removed = removeContainer
		}
	}
	return out, nil
}

// imageManifestFetch is the control-plane half of an image pull — a seam so
// the decision logic (not staged? mismatch?) is testable without a gateway.
// lookupArtifactManifest (manifest_probe.go) keeps the reason, so "not staged"
// (ErrArtifactAbsent) and "the controller did not answer" stay distinct.
var imageManifestFetch = func(ctx context.Context, tarName string) (*artifactManifest, error) {
	return lookupArtifactManifest(ctx, "image", tarName)
}

// ImageNotStagedError: the controller's store has no tar of this image for
// this node's architecture. Its text carries the exact fix, because the node
// cannot do anything about it and the operator can.
type ImageNotStagedError struct {
	Ref  string
	Arch string
	Tar  string
}

func (e *ImageNotStagedError) Error() string {
	return fmt.Sprintf(
		"image %s not staged on the controller (no %s tar %s in its artifact store) — run `noo cluster sync-images %s -i %s` or `noo upgrade` on the controller",
		e.Ref, e.Arch, e.Tar, nodeIDOrPlaceholder(), e.Ref)
}

// IsImageNotStaged reports whether err is (or wraps) the not-staged refusal.
func IsImageNotStaged(err error) bool {
	var t *ImageNotStagedError
	return errors.As(err, &t)
}

func nodeIDOrPlaceholder() string {
	if id := nodeIDForHints(); id != "" {
		return id
	}
	return "<node>"
}

// ImageVerificationError: the rail delivered something that does not check
// out — tar sha256, archive contents, loaded image ID or architecture. Never
// run, never fallen back from: the caller refuses the start. Every OTHER
// rail failure (no cache URL, unreachable, timeout, disk full) is transport.
type ImageVerificationError struct {
	Ref string
	Err error
}

func (e *ImageVerificationError) Error() string {
	return fmt.Sprintf("image %s failed verification: %v", e.Ref, e.Err)
}

func (e *ImageVerificationError) Unwrap() error { return e.Err }

// IsImageVerification reports whether err is (or wraps) a verification failure.
func IsImageVerification(err error) bool {
	var t *ImageVerificationError
	return errors.As(err, &t)
}

// imageStore is the slice of the daemon finishLoad needs — a seam so the
// re-tag and verify logic is testable without one.
type imageStore interface {
	inspect(ctx context.Context, ref string) (id, arch string, err error)
	tag(ctx context.Context, source, target string) error
}

type dockerImageStore struct{ c *Client }

func (d dockerImageStore) inspect(ctx context.Context, ref string) (string, string, error) {
	r, err := d.c.docker.ImageInspect(ctx, ref)
	if err != nil {
		return "", "", err
	}
	return r.ID, r.Architecture, nil
}

func (d dockerImageStore) tag(ctx context.Context, source, target string) error {
	_, err := d.c.docker.ImageTag(ctx, client.ImageTagOptions{Source: source, Target: target})
	return err
}

// finishLoad makes ref name what `docker load` just loaded and checks it.
//
// The re-tag is UNCONDITIONAL whenever the load reports an ID: a tar saved by
// ID (foreign-arch stage) loads untagged, and if ref already exists at an
// older ID, tagging only an ABSENT ref would leave ref on the old image and
// every start would loop on "digest mismatch" re-fetching the same tar.
func finishLoad(ctx context.Context, st imageStore, ref, loadOut, arch string) (string, error) {
	loadedID, loadedRefs := parseLoadOutput(loadOut)
	if loadedID != "" {
		if err := st.tag(ctx, loadedID, ref); err != nil {
			return "", fmt.Errorf("tag loaded image %s as %s: %w", shortImageID(loadedID), ref, err)
		}
	} else if len(loadedRefs) > 0 && !containsRef(loadedRefs, ref) {
		return "", &ImageVerificationError{Ref: ref, Err: fmt.Errorf("the archive loaded as %v, not %s", loadedRefs, ref)}
	}
	gotID, gotArch, err := st.inspect(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("loaded %s but it does not resolve: %w", ref, err)
	}
	if err := verifyLoadedImage(ref, loadedID, gotID, arch, gotArch); err != nil {
		return "", &ImageVerificationError{Ref: ref, Err: err}
	}
	return gotID, nil
}

// verifyLoadedImage is the post-load check, pure so the refusal is testable:
// the ref must resolve to the image the load produced (when known) and be
// built for this node's architecture.
func verifyLoadedImage(ref, wantID, gotID, arch, gotArch string) error {
	if wantID != "" && !sameImageID(gotID, wantID) {
		return fmt.Errorf(
			"image digest mismatch for %s: the verified tar loaded as %s but %s resolves to %s — refusing to run it (re-stage it on the controller: `noo cluster sync-images %s -i %s`)",
			ref, shortImageID(wantID), ref, shortImageID(gotID), nodeIDOrPlaceholder(), ref)
	}
	if gotArch != "" && gotArch != arch {
		return fmt.Errorf(
			"loaded %s but its architecture is %s, not this node's %s — the controller exported a mislabeled tar (it IS now in the local image store; remove it with `docker rmi %s`)",
			ref, gotArch, arch, ref)
	}
	return nil
}

// parseLoadOutput reads `docker load`'s progress stream for what it loaded:
// "Loaded image: <ref>" lines (a tar saved by tag) and "Loaded image ID:
// sha256:…" (a tar saved by ID). The stream is JSON lines whose "stream"
// field carries that text; matching the text is enough and survives both.
func parseLoadOutput(out string) (id string, refs []string) {
	for _, chunk := range strings.Split(out, "\\n") {
		for _, line := range strings.Split(chunk, "\n") {
			if i := strings.Index(line, "Loaded image ID: "); i >= 0 {
				id = strings.TrimSpace(strings.Trim(line[i+len("Loaded image ID: "):], "\"}"))
				continue
			}
			if i := strings.Index(line, "Loaded image: "); i >= 0 {
				refs = append(refs, strings.TrimSpace(strings.Trim(line[i+len("Loaded image: "):], "\"}")))
			}
		}
	}
	return id, refs
}

// containsRef reports whether xs names ref, comparing normalised names
// ("ollama/ollama:latest" == "docker.io/ollama/ollama:latest").
func containsRef(xs []string, ref string) bool {
	want := normalizeRef(ref)
	for _, v := range xs {
		if normalizeRef(v) == want {
			return true
		}
	}
	return false
}

// sameImageID compares two image IDs with or without the "sha256:" prefix.
func sameImageID(a, b string) bool {
	norm := func(s string) string { return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "sha256:") }
	return a != "" && b != "" && norm(a) == norm(b)
}

func shortImageID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func drainToString(r interface{ Read([]byte) (int, error) }) string {
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			b.Write(buf[:n])
		}
		if err != nil {
			return b.String()
		}
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
