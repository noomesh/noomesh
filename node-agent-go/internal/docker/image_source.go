// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/client"

	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
)

// Where a node's container images come from — ONE function, every start path.
//
// # The decision (operator, 2026-10-10)
//
// "the controller should pull everything and stage on rail then node pulls
// it over; node shouldn't need everything."
//
// The controller pulls every image with its own registry login and exports
// it into its artifact store (`noo upgrade`, `noo cluster stage-images`,
// `noo cluster sync-images`). A node takes images from there — over the
// mTLS model-cache, digest-verified against the gateway's manifest — and
// never holds a registry credential.
//
// # The live failure it fixes (host8-ma)
//
// A fresh node could not start llama.cpp:
//
//	reconcile.start_failed backend=llamacpp error="pull image
//	ghcr.io/noomesh/llamacpp:v0.2.103: ... unauthorized"
//
// because the backend path asked the Docker daemon to pull from GHCR, which
// is private, with no credential — and five other start paths (the client
// profile pull, the containers API, MCP stdio servers, skills, the stunnel
// sidecar) did the same. Only the helper image went over the rail.
//
// # The order, for every ref
//
//  1. Present locally at the image ID the controller's manifest names, or
//     at the ID this node loaded from that exact tar before
//     (rail_memory.go) → use it (source "rail": the controller vouches).
//  2. Staged on the controller → pull the tar over the rail, verify its
//     sha256 against the manifest before `docker load`, and that the ref
//     resolves to what was loaded after it (PullImageArtifact). A mismatch
//     is a refusal, never a start.
//  3. Present locally but nothing to compare it against (not staged, an
//     older gateway, the controller unreachable) → use it, reported as
//     source "local" so `noo cluster verify` names it.
//  4. Not present and not staged:
//     - our own images (managedRegistryRoots, NOO_IMAGE_PREFIX, the local
//     build names) → refusal naming the exact controller command. Never a
//     registry pull: there is no credential and there must not be one.
//     - a public third-party image (upstream llama.cpp for ARM, ollama,
//     the alpine sidecar fallback…) → a registry pull ONLY when
//     NOO_IMAGE_REGISTRY_FALLBACK allows it (default "public"; "off"
//     makes the node rail-only), logged at WARN and reported as source
//     "registry". Staging those on the controller too is preferred:
//     `noo cluster sync-images <node> -i ollama/ollama:latest`.
//
// # Verification vs transport failures
//
// A rail pull that fails VERIFICATION (tar sha256, archive contents, loaded
// image ID, architecture) is a refusal: nothing is run. A pull that fails in
// TRANSPORT or on DISK (no NOO_MODEL_CACHE_URL, cache unreachable, timeout,
// staging dir full) while the image is present locally runs the local copy
// as source "local" with a WARN — the controller being briefly unreachable
// must not take down a backend the node already holds — and the ref is not
// retried for railRetryBackoff, so a flaky link does not re-download a
// multi-GB tar on every reconcile tick.
//
// # The rollout switch
//
// NOO_IMAGE_SOURCE=rail|legacy (node env). `legacy` — the DEFAULT for the
// first release that ships this — is the pre-rail behaviour: a local image
// is used, an absent one is pulled from its registry. Provenance is still
// reported, so `noo cluster verify` shows what the rail WOULD change. The
// operator turns `rail` on one node at a time for the live dry-run.
//
// The ONLY registry pull in the agent is registryPull below; a guard test
// (TestNoRegistryPullOutsideTheFallback) fails on any other.

// RegistryFallbackEnv selects the third-party registry fallback policy.
const RegistryFallbackEnv = "NOO_IMAGE_REGISTRY_FALLBACK"

// The two policies. Anything else is treated as "off" (fail closed).
const (
	RegistryFallbackPublic = "public"
	RegistryFallbackOff    = "off"
)

// registryFallbackPolicy reads RegistryFallbackEnv. Unset → public (third-
// party images may come from their public registry when the controller has
// not staged them); our own images are rail-only under every policy.
func registryFallbackPolicy() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(RegistryFallbackEnv)))
	switch v {
	case "", RegistryFallbackPublic:
		return RegistryFallbackPublic
	case RegistryFallbackOff, "none", "rail-only", "rail":
		return RegistryFallbackOff
	default:
		policyWarnOnce.Do(func() {
			slog.Warn("unknown "+RegistryFallbackEnv+" value; treating it as \"off\" (rail-only)",
				"value", v, "accepted", "public | off")
		})
		return RegistryFallbackOff
	}
}

var policyWarnOnce sync.Once

// isOwnImage reports whether ref is one of OUR images — rail-only, because
// a registry pull of one would need a credential the node must never hold.
// The rule is isOwnImageWith (image_ref.go), shared with the Rust side; the
// roots here are the managed registry roots plus this node's NOO_IMAGE_PREFIX.
func isOwnImage(ref string) bool {
	roots := append([]string{}, managedRegistryRoots...)
	if p := strings.TrimSpace(os.Getenv("NOO_IMAGE_PREFIX")); p != "" {
		roots = append(roots, p)
	}
	return isOwnImageWith(ref, roots)
}

// imageSourceMode is the rollout switch (imagesource.Mode, NOO_IMAGE_SOURCE).
func imageSourceMode() string { return imagesource.Mode() }

// railRetryBackoff is how long a ref whose rail pull failed in transport is
// left alone before the rail is tried again.
const railRetryBackoff = 30 * time.Minute

var (
	railFailMu sync.Mutex
	railFail   = map[string]railFailure{}
	nowFn      = time.Now
)

type railFailure struct {
	at  time.Time
	err error
}

func railBackedOff(ref string) (error, bool) {
	railFailMu.Lock()
	defer railFailMu.Unlock()
	f, ok := railFail[ref]
	if !ok || nowFn().Sub(f.at) >= railRetryBackoff {
		return nil, false
	}
	return f.err, true
}

func noteRailFailure(ref string, err error) {
	railFailMu.Lock()
	railFail[ref] = railFailure{at: nowFn(), err: err}
	railFailMu.Unlock()
}

func clearRailFailure(ref string) {
	railFailMu.Lock()
	delete(railFail, ref)
	railFailMu.Unlock()
}

// resetRailBackoff forgets every remembered failure. Tests only.
func resetRailBackoff() {
	railFailMu.Lock()
	railFail = map[string]railFailure{}
	railFailMu.Unlock()
}

// The daemon-facing steps, as package vars so the decision is testable
// without a Docker daemon (the same seam helper_image.go uses).
var (
	imageLocalID = func(ctx context.Context, c *Client, ref string) (string, bool) {
		if c == nil || c.docker == nil {
			return "", false
		}
		inspect, err := c.docker.ImageInspect(ctx, ref)
		if err != nil {
			return "", false
		}
		return inspect.ID, true
	}
	imageRailPull = func(ctx context.Context, c *Client, ref string) error {
		_, err := c.PullImageArtifact(ctx, ref, "", "")
		return err
	}
	imageRegistryPull = func(ctx context.Context, c *Client, ref string) error {
		return c.registryPull(ctx, ref)
	}
)

// EnsureImage makes ref available locally by the order above and records
// where it came from. Every container start path calls this before it
// creates a container; none of them talks to a registry itself.
func (c *Client) EnsureImage(ctx context.Context, ref string) error {
	source, id, err := c.resolveImage(ctx, ref)
	if err != nil {
		return err
	}
	imagesource.Record(ref, source, id)
	return nil
}

// ensureImageFn is what the start paths call — a seam so a test can prove
// each one goes through EnsureImage without a daemon.
var ensureImageFn = func(ctx context.Context, c *Client, ref string) error {
	return c.EnsureImage(ctx, ref)
}

func (c *Client) resolveImage(ctx context.Context, ref string) (source, imageID string, err error) {
	if ref == "" || strings.ContainsAny(ref, " \t\n") {
		return "", "", fmt.Errorf("invalid image ref %q", ref)
	}
	if imageSourceMode() != imagesource.ModeRail {
		return c.resolveLegacy(ctx, ref)
	}
	arch := runtime.GOARCH
	localID, present := imageLocalID(ctx, c, ref)

	// A ref whose rail pull failed in transport recently is not retried
	// yet: run the local copy, or repeat the failure for an absent one.
	if berr, off := railBackedOff(ref); off {
		if present {
			return imagesource.Local, localID, nil
		}
		return "", "", fmt.Errorf("%s: the last rail pull failed less than %s ago (%v); not retrying yet", ref, railRetryBackoff, berr)
	}

	m, _, merr := fetchImageManifest(ctx, ref, arch)
	staged := merr == nil && m != nil

	// 1. Present at an ID the controller vouches for: the manifest's
	//    image_id, or the ID this node loaded from that exact tar before
	//    (rail_memory.go — the two differ across Docker image-store types).
	var known []string
	if staged {
		for _, id := range []string{m.ImageID, railImageFor(m.SHA256)} {
			if id != "" {
				known = append(known, id)
			}
		}
	}
	if present {
		for _, id := range known {
			if sameImageID(localID, id) {
				return imagesource.Rail, localID, nil
			}
		}
	}
	// 2. Staged and (absent, or present at a DIFFERENT ID): the staged one
	//    is the truth.
	if staged && (!present || len(known) > 0) {
		if present {
			slog.Info("local image differs from the one staged on the controller; pulling the staged one over the rail",
				"image", ref, "local", shortImageID(localID), "staged", shortImageID(known[0]))
		}
		if err := imageRailPull(ctx, c, ref); err != nil {
			if IsImageVerification(err) {
				return "", "", fmt.Errorf("pull %s over the artifact rail: %w", ref, err)
			}
			noteRailFailure(ref, err)
			if present {
				slog.Warn("image.rail_transport_failed: running the local copy; the rail is retried after the backoff",
					"image", ref, "local", shortImageID(localID), "err", err, "retry_after", railRetryBackoff.String())
				return imagesource.Local, localID, nil
			}
			return "", "", fmt.Errorf("pull %s over the artifact rail: %w", ref, err)
		}
		clearRailFailure(ref)
		id, _ := imageLocalID(ctx, c, ref)
		return imagesource.Rail, id, nil
	}
	// 3. Present, nothing to compare against.
	if present {
		if merr != nil && !errors.Is(merr, ErrArtifactAbsent) {
			slog.Debug("image present locally; controller manifest unavailable, using the local copy",
				"image", ref, "err", merr)
		}
		return imagesource.Local, localID, nil
	}
	// 4. Absent and not staged.
	notStaged := &ImageNotStagedError{Ref: ref, Arch: arch, Tar: ImageTarGzName(ref, arch), AltTar: ImageTarName(ref, arch)}
	if isOwnImage(ref) || registryFallbackPolicy() != RegistryFallbackPublic {
		if merr != nil && !errors.Is(merr, ErrArtifactAbsent) {
			return "", "", fmt.Errorf("%w (the controller's manifest route could not be asked: %v)", notStaged, merr)
		}
		return "", "", notStaged
	}
	slog.Warn("image.registry_fallback: pulling a public third-party image from its registry because the controller has not staged it",
		"image", ref, "arch", arch, "policy", RegistryFallbackEnv+"="+RegistryFallbackPublic,
		"fix", fmt.Sprintf("stage it on the controller so this node needs no internet registry: `noo cluster sync-images %s -i %s`; set %s=off to forbid this", nodeIDOrPlaceholder(), ref, RegistryFallbackEnv))
	if err := imageRegistryPull(ctx, c, ref); err != nil {
		return "", "", fmt.Errorf("%w; the public-registry fallback failed too: %v", notStaged, err)
	}
	id, _ := imageLocalID(ctx, c, ref)
	return imagesource.Registry, id, nil
}

// resolveLegacy is the pre-rail behaviour (NOO_IMAGE_SOURCE=legacy): use a
// local image, pull an absent one from its registry. Provenance is still
// recorded so verify shows what `rail` would change.
func (c *Client) resolveLegacy(ctx context.Context, ref string) (string, string, error) {
	if id, ok := imageLocalID(ctx, c, ref); ok {
		return imagesource.Local, id, nil
	}
	slog.Info("pulling image (legacy image source)", "image", ref, "switch", imagesource.ModeEnv+"=rail takes it from the controller's artifact rail")
	if err := imageRegistryPull(ctx, c, ref); err != nil {
		return "", "", fmt.Errorf("pull image %s: %w", ref, err)
	}
	id, _ := imageLocalID(ctx, c, ref)
	return imagesource.Registry, id, nil
}

// registryPull is the agent's ONLY registry pull. Reached solely from
// resolveImage's third-party fallback; never for our own images.
func (c *Client) registryPull(ctx context.Context, ref string) error {
	reader, err := c.docker.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()
	// Drain: the daemon commits the pull as the stream is consumed. An
	// error mid-stream arrives as a JSON line, not as err.
	out := drainToString(reader)
	if strings.Contains(out, "\"error\"") {
		return fmt.Errorf("registry pull reported: %s", strings.TrimSpace(lastLine(out)))
	}
	return nil
}

// ImagePullParallelismEnv overrides imagePullParallelism. "1" disables the
// concurrency (pulls run one after another, as before the prefetch existed).
const ImagePullParallelismEnv = "NOO_IMAGE_PULL_PARALLELISM"

// imagePullParallelism is how many image tars one prefetch pulls at once.
// It is also the disk bound: each worker stages at most one tar at a time
// (PullImageArtifact removes it after the load), so a node never holds more
// than this many multi-GB tars in its staging dir.
const imagePullParallelism = 2

// imagePullParallelismNow reads ImagePullParallelismEnv. Unset, empty,
// non-numeric or < 1 → the default (a typo must not turn the prefetch into
// something other than the documented bound); logged once per bad value.
func imagePullParallelismNow() int {
	v := strings.TrimSpace(os.Getenv(ImagePullParallelismEnv))
	if v == "" {
		return imagePullParallelism
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		slog.Warn("ignoring "+ImagePullParallelismEnv+"; using the default",
			"value", v, "default", imagePullParallelism)
		return imagePullParallelism
	}
	return n
}

// PrefetchResult is what one PrefetchImages call did, for the caller's log.
type PrefetchResult struct {
	Wanted  int // distinct refs asked for
	Pulled  int // refs EnsureImage resolved
	Failed  int // refs EnsureImage refused (each is logged; the start path reports it again)
	Skipped int // refs already local
}

// PrefetchImages makes every ref in refs available locally, concurrently
// (bounded by imagePullParallelismNow), BEFORE the caller's ordered start
// loop. It exists because the start loop calls EnsureImage per placement,
// so a node placed with several backends after a release pulled their
// multi-GB tars one after another.
//
// What it does NOT do: decide anything. A ref already local is left to its
// start path (which still runs the full resolveImage comparison against the
// controller's manifest); a pull that fails is logged and counted, never
// returned as an error, because the placement's own start path reports the
// same failure through its own error text and refusal record. When the
// controller or the rail is ABSENT, OLD or failing, the pull errors exactly
// as EnsureImage would and the start path repeats it.
//
// Two placements on one image produce one pull (refs are deduplicated here;
// PullImageArtifact additionally serialises on a per-ref lock so a start
// path overlapping this prefetch cannot write the same staged .partial).
func (c *Client) PrefetchImages(ctx context.Context, refs []string, placements int) PrefetchResult {
	seen := map[string]bool{}
	var res PrefetchResult
	var missing []string
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		res.Wanted++
		if _, ok := imageLocalID(ctx, c, ref); ok {
			res.Skipped++
			continue
		}
		missing = append(missing, ref)
	}
	if len(missing) == 0 {
		return res
	}
	par := imagePullParallelismNow()
	if par > len(missing) {
		par = len(missing)
	}
	slog.Info(fmt.Sprintf("prefetching %d image(s) for %d placement(s) (parallelism %d)",
		len(missing), placements, par), "images", missing)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		jobs = make(chan string)
	)
	for i := 0; i < par; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ref := range jobs {
				err := ensureImageFn(ctx, c, ref)
				mu.Lock()
				if err != nil {
					res.Failed++
				} else {
					res.Pulled++
				}
				mu.Unlock()
				if err != nil {
					slog.Warn("image.prefetch_failed: the placement's start will report it",
						"image", ref, "err", err)
				}
			}
		}()
	}
	for _, ref := range missing {
		jobs <- ref
	}
	close(jobs)
	wg.Wait()
	return res
}

// BackendImageRef is the image StartBackend will use for backend, so the
// reconciler can prefetch it. It mirrors the image choices at the top of
// StartBackendSDK (CPU image on a node without NVIDIA, the controller's
// override, ${VAR} substitution). It returns "" when it cannot tell (unknown
// backend) or when StartBackendSDK would swap in a locally-built hardened
// llama.cpp (present locally, so nothing to fetch). A wrong answer here only
// costs a missed or wasted prefetch: the start path decides by itself.
func BackendImageRef(backend, override string) string {
	spec, ok := backendSpecs[backend]
	if !ok {
		return ""
	}
	if spec.CPUImage != "" && !hasNvidiaGPU() {
		spec.Image = spec.CPUImage
	}
	if override != "" {
		spec.Image = override
	} else {
		spec.Image = resolveEnv(spec.Image)
	}
	if backend == "llamacpp" && spec.Image == "ghcr.io/ggml-org/llama.cpp:server" {
		// StartBackendSDK prefers a locally-present hardened build; if one
		// is here the upstream image is not needed, and if none is, the
		// start path pulls the upstream one itself.
		return ""
	}
	return spec.Image
}
