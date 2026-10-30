// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/imagesource"
	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// fakeImageRail stands in for the daemon and the controller: what is
// present locally (ref → image ID), what the controller has staged (tar →
// manifest), and a record of every pull asked of the rail and the registry.
type fakeImageRail struct {
	local        map[string]string
	staged       map[string]*artifactManifest
	manifestErr  error // returned instead of a manifest when set
	railErr      error
	registryErr  error
	railPulls    []string
	registryPull []string
}

func (f *fakeImageRail) install(t *testing.T) {
	t.Helper()
	pl, pm, pr, pg := imageLocalID, imageManifestFetch, imageRailPull, imageRegistryPull
	imageLocalID = func(_ context.Context, _ *Client, ref string) (string, bool) {
		id, ok := f.local[ref]
		return id, ok
	}
	imageManifestFetch = func(_ context.Context, tar string) (*artifactManifest, error) {
		if f.manifestErr != nil {
			return nil, f.manifestErr
		}
		if m, ok := f.staged[tar]; ok {
			return m, nil
		}
		return nil, ErrArtifactAbsent
	}
	imageRailPull = func(_ context.Context, _ *Client, ref string) error {
		f.railPulls = append(f.railPulls, ref)
		if f.railErr != nil {
			return f.railErr
		}
		if m, ok := f.staged[ImageTarName(ref, runtime.GOARCH)]; ok {
			f.local[ref] = m.ImageID
		}
		return nil
	}
	imageRegistryPull = func(_ context.Context, _ *Client, ref string) error {
		f.registryPull = append(f.registryPull, ref)
		if f.registryErr != nil {
			return f.registryErr
		}
		f.local[ref] = "sha256:registry"
		return nil
	}
	resetRailBackoff()
	imagesource.Reset()
	prevMem := railMemoryPath
	memFile := filepath.Join(t.TempDir(), "rail", "images.json")
	railMemoryPath = func() string { return memFile }
	resetRailMemory()
	t.Cleanup(func() {
		imageLocalID, imageManifestFetch, imageRailPull, imageRegistryPull = pl, pm, pr, pg
		railMemoryPath = prevMem
		resetRailMemory()
		resetRailBackoff()
		imagesource.Reset()
	})
}

const ownRef = "ghcr.io/noomesh/llamacpp:v0.2.103"

func stagedAt(ref, id string) map[string]*artifactManifest {
	return map[string]*artifactManifest{
		ImageTarName(ref, runtime.GOARCH): {SHA256: strings.Repeat("a", 64), ImageID: id},
	}
}

func sourceOf(t *testing.T, ref string) string {
	t.Helper()
	for _, e := range imagesource.Report() {
		if e.Image == ref {
			return e.Source
		}
	}
	return ""
}

// THE finding (host8-ma): our own image, absent, staged on the controller
// → it arrives over the rail and the registry is never asked.
func TestOwnImageAbsentIsPulledOverTheRail(t *testing.T) {
	t.Setenv("NODE_ID", "host8-ma")
	f := &fakeImageRail{local: map[string]string{}, staged: stagedAt(ownRef, "sha256:abc")}
	f.install(t)
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	if len(f.railPulls) != 1 || len(f.registryPull) != 0 {
		t.Fatalf("rail pulls %v, registry pulls %v — want one rail pull and no registry", f.railPulls, f.registryPull)
	}
	if got := sourceOf(t, ownRef); got != imagesource.Rail {
		t.Errorf("source = %q, want rail", got)
	}
}

// Not staged: the refusal names the image, says "not staged on the
// controller" and carries both fixes. The registry is NOT the fallback for
// our own images, under any policy.
func TestOwnImageNotStagedIsARefusalWithTheFix(t *testing.T) {
	for _, policy := range []string{"", "public", "off"} {
		t.Run("policy="+policy, func(t *testing.T) {
			t.Setenv("NODE_ID", "host8-ma")
			t.Setenv(RegistryFallbackEnv, policy)
			f := &fakeImageRail{local: map[string]string{}}
			f.install(t)
			err := (&Client{}).EnsureImage(context.Background(), ownRef)
			if !IsImageNotStaged(err) {
				t.Fatalf("want ImageNotStagedError, got %v", err)
			}
			for _, want := range []string{
				"image " + ownRef + " not staged on the controller",
				"noo cluster sync-images host8-ma -i " + ownRef,
				"noo upgrade",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q is missing %q", err, want)
				}
			}
			if len(f.registryPull) != 0 || len(f.railPulls) != 0 {
				t.Errorf("nothing may be pulled: rail %v registry %v", f.railPulls, f.registryPull)
			}
		})
	}
}

// Present at exactly the staged image ID → used as-is, reported as rail.
func TestLocalImageMatchingTheManifestIsUsed(t *testing.T) {
	f := &fakeImageRail{
		local:  map[string]string{ownRef: "sha256:abc"},
		staged: stagedAt(ownRef, "abc"), // prefix-less form compares equal
	}
	f.install(t)
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
		t.Fatal(err)
	}
	if len(f.railPulls) != 0 {
		t.Errorf("a verified local image must not be re-fetched: %v", f.railPulls)
	}
	if got := sourceOf(t, ownRef); got != imagesource.Rail {
		t.Errorf("source = %q, want rail", got)
	}
}

// Present at a DIFFERENT ID than the staged one → the staged one is pulled;
// a stale local copy is not run instead. And if that pull fails, the start
// fails: no silent fallback to the copy the controller does not vouch for.
func TestLocalImageDifferingFromTheManifestIsReplaced(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{ownRef: "sha256:old"}, staged: stagedAt(ownRef, "sha256:new")}
	f.install(t)
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
		t.Fatal(err)
	}
	if len(f.railPulls) != 1 {
		t.Fatalf("want one rail pull, got %v", f.railPulls)
	}

	// A VERIFICATION failure refuses the start even though a local copy
	// exists: the controller's bytes did not check out.
	g := &fakeImageRail{
		local: map[string]string{ownRef: "sha256:old"}, staged: stagedAt(ownRef, "sha256:new"),
		railErr: &ImageVerificationError{Ref: ownRef, Err: errors.New("image digest mismatch for x")},
	}
	g.install(t)
	err := (&Client{}).EnsureImage(context.Background(), ownRef)
	if !IsImageVerification(err) || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("a verification failure must fail the start, got %v", err)
	}
}

// A TRANSPORT failure with the image present runs the local copy (source
// local) and is not retried inside the backoff — no multi-GB re-download
// every tick. After the backoff the rail is tried again.
func TestTransportFailureRunsTheLocalCopyAndBacksOff(t *testing.T) {
	f := &fakeImageRail{
		local: map[string]string{ownRef: "sha256:old"}, staged: stagedAt(ownRef, "sha256:new"),
		railErr: errors.New("fetch x: dial tcp 10.0.0.1:8443: i/o timeout"),
	}
	f.install(t)
	base := time.Now()
	nowFn = func() time.Time { return base }
	t.Cleanup(func() { nowFn = time.Now })

	for i := 0; i < 3; i++ {
		if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
			t.Fatalf("call %d: a transport failure with a local copy must start it, got %v", i, err)
		}
		if got := sourceOf(t, ownRef); got != imagesource.Local {
			t.Fatalf("call %d: source = %q, want local", i, got)
		}
	}
	if len(f.railPulls) != 1 {
		t.Fatalf("want ONE rail attempt inside the backoff, got %d", len(f.railPulls))
	}
	nowFn = func() time.Time { return base.Add(railRetryBackoff + time.Second) }
	f.railErr = nil
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
		t.Fatal(err)
	}
	if len(f.railPulls) != 2 || sourceOf(t, ownRef) != imagesource.Rail {
		t.Fatalf("after the backoff the rail is retried: pulls %v source %q", f.railPulls, sourceOf(t, ownRef))
	}

	// Absent + transport failure: an error (nothing to run), also backed off.
	g := &fakeImageRail{local: map[string]string{}, staged: stagedAt(ownRef, "sha256:new"), railErr: errors.New("no space left on device")}
	g.install(t)
	for i := 0; i < 2; i++ {
		if err := (&Client{}).EnsureImage(context.Background(), ownRef); err == nil {
			t.Fatal("absent and the rail failed: want an error")
		}
	}
	if len(g.railPulls) != 1 {
		t.Errorf("absent image: want one attempt inside the backoff, got %d", len(g.railPulls))
	}
}

// NOO_IMAGE_SOURCE is retired: whatever it holds (legacy included), an
// absent staged image is taken over the rail and never from the registry.
func TestRetiredImageSourceVariableIsIgnored(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{}, staged: stagedAt(ownRef, "sha256:new")}
	f.install(t)
	t.Setenv(imagesource.RetiredEnv, "legacy")
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
		t.Fatal(err)
	}
	if len(f.railPulls) != 1 || len(f.registryPull) != 0 {
		t.Errorf("legacy value must be ignored: rail %v registry %v", f.railPulls, f.registryPull)
	}
	if sourceOf(t, ownRef) != imagesource.Rail {
		t.Errorf("provenance: %+v", imagesource.Report())
	}
}

// Present but nothing vouches for it (not staged, or the controller is
// unreachable) → used, and reported as "local" so verify names it.
func TestUnvouchedLocalImageIsUsedAndReportedLocal(t *testing.T) {
	for name, merr := range map[string]error{"not staged": nil, "unreachable": errors.New("dial tcp: refused")} {
		t.Run(name, func(t *testing.T) {
			f := &fakeImageRail{local: map[string]string{ownRef: "sha256:abc"}, manifestErr: merr}
			f.install(t)
			if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
				t.Fatal(err)
			}
			if got := sourceOf(t, ownRef); got != imagesource.Local {
				t.Errorf("source = %q, want local", got)
			}
			if len(f.railPulls)+len(f.registryPull) != 0 {
				t.Errorf("no pulls expected")
			}
		})
	}
}

// A public third-party image the controller has not staged: the registry
// fallback runs under the default policy (logged, reported "registry"), and
// NOT under "off".
func TestThirdPartyRegistryFallbackFollowsThePolicy(t *testing.T) {
	const ref = "ollama/ollama:latest"

	t.Setenv(RegistryFallbackEnv, "")
	f := &fakeImageRail{local: map[string]string{}}
	f.install(t)
	if err := (&Client{}).EnsureImage(context.Background(), ref); err != nil {
		t.Fatalf("default policy allows the third-party fallback: %v", err)
	}
	if len(f.registryPull) != 1 || sourceOf(t, ref) != imagesource.Registry {
		t.Errorf("want one registry pull reported as registry; pulls %v source %q", f.registryPull, sourceOf(t, ref))
	}

	t.Setenv(RegistryFallbackEnv, "off")
	g := &fakeImageRail{local: map[string]string{}}
	g.install(t)
	err := (&Client{}).EnsureImage(context.Background(), ref)
	if !IsImageNotStaged(err) || len(g.registryPull) != 0 {
		t.Fatalf("policy off must refuse without a registry pull; err %v pulls %v", err, g.registryPull)
	}

	// An unknown value fails closed.
	t.Setenv(RegistryFallbackEnv, "sometimes")
	if registryFallbackPolicy() != RegistryFallbackOff {
		t.Error("an unknown policy must mean off")
	}
}

// A staged third-party image comes from the rail even though the registry
// would be allowed: staging is preferred.
func TestStagedThirdPartyImageComesFromTheRail(t *testing.T) {
	const ref = "ghcr.io/ggml-org/llama.cpp:server"
	f := &fakeImageRail{local: map[string]string{}, staged: stagedAt(ref, "sha256:up")}
	f.install(t)
	if err := (&Client{}).EnsureImage(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if len(f.railPulls) != 1 || len(f.registryPull) != 0 {
		t.Errorf("rail %v registry %v", f.railPulls, f.registryPull)
	}
}

func TestOwnImageClassification(t *testing.T) {
	t.Setenv("NOO_IMAGE_PREFIX", "registry.example/acme")
	for _, own := range []string{
		"ghcr.io/noomesh/stunnel:v1",
		"ghcr.io/noomesh/node-agent:v1",
		"registry.example/acme/llamacpp:v1",
		"noomesh/stunnel:latest",
		"pai-assistant/llamacpp:amd64",
		"noo-sandbox-base:latest",
		"noo-browser:latest",
	} {
		if !isOwnImage(own) {
			t.Errorf("%s must be classified as ours (rail-only)", own)
		}
	}
	for _, third := range []string{"ollama/ollama:latest", "alpine:3.20", "ghcr.io/ggml-org/llama.cpp:server", "vllm/vllm-openai:latest"} {
		if isOwnImage(third) {
			t.Errorf("%s is a public third-party image", third)
		}
	}
}

// --- every start path goes through the rail helper -------------------------

var errSentinelEnsure = errors.New("ensure-image sentinel")

// recordEnsure swaps ensureImageFn for a recorder that refuses, so each start
// path returns right after asking — before any container is created.
func recordEnsure(t *testing.T) *[]string {
	t.Helper()
	var asked []string
	prev := ensureImageFn
	ensureImageFn = func(_ context.Context, _ *Client, ref string) error {
		asked = append(asked, ref)
		return errSentinelEnsure
	}
	t.Cleanup(func() { ensureImageFn = prev })
	return &asked
}

func TestStartPathsGoThroughEnsureImage(t *testing.T) {
	c := &Client{}

	t.Run("containers API", func(t *testing.T) {
		asked := recordEnsure(t)
		_, err := c.StartManagedContainer(context.Background(), ContainerStartRequest{Image: "noo-browser:latest", ContainerName: "noo-browser-abc", NetworkMode: "bridge"})
		if !errors.Is(err, errSentinelEnsure) || len(*asked) != 1 || (*asked)[0] != "noo-browser:latest" {
			t.Fatalf("err %v asked %v", err, *asked)
		}
	})
	t.Run("skills", func(t *testing.T) {
		asked := recordEnsure(t)
		_, err := c.RunSkillContainer(context.Background(), SkillRunRequest{Image: "busybox", ContainerName: "noo-skill-1", NetworkMode: "none"})
		if !errors.Is(err, errSentinelEnsure) || len(*asked) != 1 {
			t.Fatalf("err %v asked %v", err, *asked)
		}
	})
	t.Run("profile pull (client.go)", func(t *testing.T) {
		asked := recordEnsure(t)
		t.Setenv("VLLM_IMAGE", "")
		err := c.PullProfile(context.Background(), "ollama")
		if !errors.Is(err, errSentinelEnsure) || len(*asked) != 1 || (*asked)[0] != "ollama/ollama:0.40.5" {
			t.Fatalf("err %v asked %v", err, *asked)
		}
	})
	t.Run("stunnel sidecar", func(t *testing.T) {
		asked := recordEnsure(t)
		t.Setenv(StunnelImageEnv, "")
		t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
		t.Setenv("NOO_IMAGE_TAG", "v0.2.103")
		_, err := c.ensureSidecarImage(context.Background(), "llamacpp")
		if err == nil {
			t.Fatal("every candidate refused: want an error")
		}
		// Every candidate was asked of the rail helper, in order, and the
		// error carries each refusal.
		want := stunnelImageCandidates("llamacpp")
		if strings.Join(*asked, ",") != strings.Join(want, ",") {
			t.Fatalf("asked %v, want %v", *asked, want)
		}
	})
	t.Run("backends", func(t *testing.T) {
		asked := recordEnsure(t)
		t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
		t.Setenv("NOO_IMAGE_TAG", "v0.2.103")
		err := c.StartBackendSDK(context.Background(), "ollama", "", 0, StartOverrides{Image: "ollama/ollama:0.40.5@sha256:" + strings.Repeat("a", 64)})
		if !errors.Is(err, errSentinelEnsure) || len(*asked) != 1 {
			t.Fatalf("err %v asked %v", err, *asked)
		}
	})
}

// MCP stdio needs a root-owned binary to build its spec, so its wiring is
// pinned by source: each start-path file calls ensureImageFn.
func TestEveryStartPathFileCallsEnsureImage(t *testing.T) {
	for _, f := range []string{"backends.go", "client.go", "containers.go", "mcp_stdio.go", "sidecar.go", "skills.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// ensureImageWithFallback (backends.go) is ensureImageFn plus the i323
		// hardened-default fallback; it is not another route to a registry.
		if !strings.Contains(string(b), "ensureImageFn(ctx, c, ") && !strings.Contains(string(b), "ensureImageWithFallback(ctx, c, ") {
			t.Errorf("%s no longer resolves its image through ensureImageFn", f)
		}
	}
}

// THE guard: no registry pull anywhere in the agent except the one
// third-party fallback in image_source.go. A new `ImagePull(` call is a
// node asking a registry for an image — for our own images that needs a
// credential nodes must never hold.
// `.ImagePull` as a call or a method value (but not ImagePullOptions), and
// any ImageCreate.
var registryPullPattern = regexp.MustCompile(`\.ImagePull\b|\bImageCreate\b`)

func TestRegistryPullPatternCatchesValuesAndCreate(t *testing.T) {
	for _, src := range []string{"c.docker.ImagePull(ctx, r, o)", "pull := c.docker.ImagePull", "c.docker.ImageCreate(ctx, r, o)"} {
		if !registryPullPattern.MatchString(src) {
			t.Errorf("guard misses %q", src)
		}
	}
	if registryPullPattern.MatchString("client.ImagePullOptions{}") {
		t.Error("the options type is not a pull")
	}
}

func TestNoRegistryPullOutsideTheFallback(t *testing.T) {
	root := filepath.Join("..", "..") // node-agent-go/
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Calls AND method values (`f := c.docker.ImagePull`), and
		// ImageCreate (the raw API a pull is built on).
		n := len(registryPullPattern.FindAllIndex(b, -1))
		if n == 0 {
			return nil
		}
		if filepath.Base(path) == "image_source.go" && filepath.Base(filepath.Dir(path)) == "docker" && n == 1 {
			return nil
		}
		offenders = append(offenders, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("registry pulls outside internal/docker/image_source.go's fallback: %v — resolve images with EnsureImage", offenders)
	}
}

// --- PullImageArtifact refusals --------------------------------------------

func TestPullImageArtifactNotStagedIsTyped(t *testing.T) {
	preseedtest.New(t).SetNodeEnv(t)
	t.Setenv("NOO_MODEL_CACHE_URL", "https://127.0.0.1:9")
	t.Setenv("NODE_ID", "host8-ma")
	prev := imageManifestFetch
	imageManifestFetch = func(context.Context, string) (*artifactManifest, error) { return nil, ErrArtifactAbsent }
	t.Cleanup(func() { imageManifestFetch = prev })

	_, err := (&Client{}).PullImageArtifact(context.Background(), ownRef, "", "")
	if !IsImageNotStaged(err) {
		t.Fatalf("want ImageNotStagedError, got %v", err)
	}
	if !strings.Contains(err.Error(), "noo cluster sync-images host8-ma -i "+ownRef) {
		t.Errorf("missing the fix: %v", err)
	}
}

// The loaded image must be the one the manifest named: a mismatch is a
// refusal with the re-stage command, not a start.
func TestLoadedImageIDMismatchIsRefused(t *testing.T) {
	err := verifyLoadedImage(ownRef, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "amd64", "amd64")
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("want a digest-mismatch refusal, got %v", err)
	}
	if err := verifyLoadedImage(ownRef, strings.Repeat("a", 64), "sha256:"+strings.Repeat("a", 64), "amd64", "amd64"); err != nil {
		t.Errorf("same ID with/without prefix must match: %v", err)
	}
	if err := verifyLoadedImage(ownRef, "", "sha256:x", "arm64", "amd64"); err == nil || !strings.Contains(err.Error(), "architecture") {
		t.Errorf("wrong arch must be refused, got %v", err)
	}
	if err := verifyLoadedImage(ownRef, "", "sha256:x", "amd64", "amd64"); err != nil {
		t.Errorf("an older gateway (no image_id) still loads: %v", err)
	}
}

// Tar bytes that do not hash to the manifest's sha256 are refused BEFORE
// `docker load` — the client here has no daemon at all, so reaching the load
// would panic rather than pass.
func TestTarDigestMismatchIsRefusedBeforeLoad(t *testing.T) {
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	srv := pki.Store(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not the bytes the manifest describes"))
	}))
	t.Setenv("NOO_MODEL_CACHE_URL", srv.URL)
	t.Setenv("NOO_AGENT_STAGING_DIR", t.TempDir())
	prev := imageManifestFetch
	imageManifestFetch = func(context.Context, string) (*artifactManifest, error) {
		return &artifactManifest{SHA256: strings.Repeat("0", 64), ImageID: "sha256:abc"}, nil
	}
	t.Cleanup(func() { imageManifestFetch = prev })

	_, err := (&Client{}).PullImageArtifact(context.Background(), ownRef, "", "")
	if err == nil {
		t.Fatal("a tar whose sha256 does not match the manifest must be refused")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "sha256") && !strings.Contains(strings.ToLower(err.Error()), "mismatch") {
		t.Errorf("the refusal should name the digest check: %v", err)
	}
}

// Across Docker image-store types the controller's image_id never equals the
// node's local ID. After one verified load the node remembers "this tar
// loaded as this ID", so the next start uses the local copy instead of
// re-fetching a multi-GB tar every time.
func TestRailMemoryMatchesAcrossImageStoreTypes(t *testing.T) {
	sha := strings.Repeat("c", 64)
	f := &fakeImageRail{
		local:  map[string]string{ownRef: "sha256:containerd-manifest-digest"},
		staged: map[string]*artifactManifest{ImageTarName(ownRef, runtime.GOARCH): {SHA256: sha, ImageID: "sha256:classic-config-digest"}},
	}
	f.install(t)
	rememberRailImage(sha, "sha256:containerd-manifest-digest")
	resetRailMemory() // and it survives an agent restart (read back from disk)
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
		t.Fatal(err)
	}
	if len(f.railPulls) != 0 {
		t.Errorf("a local image this node loaded from the same tar must not be re-fetched: %v", f.railPulls)
	}
	if sourceOf(t, ownRef) != imagesource.Rail {
		t.Errorf("source = %q, want rail", sourceOf(t, ownRef))
	}
}

func TestParseLoadOutput(t *testing.T) {
	byTag := `{"stream":"Loaded image: ghcr.io/x/llamacpp:v1\n"}`
	id, refs := parseLoadOutput(byTag)
	if id != "" || len(refs) != 1 || refs[0] != "ghcr.io/x/llamacpp:v1" {
		t.Errorf("by tag: id %q refs %v", id, refs)
	}
	byID := `{"stream":"Loaded image ID: sha256:` + strings.Repeat("d", 64) + `\n"}`
	id, refs = parseLoadOutput(byID)
	if id != "sha256:"+strings.Repeat("d", 64) || len(refs) != 0 {
		t.Errorf("by id: id %q refs %v", id, refs)
	}
}

// --- finishLoad: the re-tag is unconditional ---------------------------------

type fakeStore struct {
	tags map[string]string // ref → id
	arch string
	tagN int
}

func (f *fakeStore) inspect(_ context.Context, ref string) (string, string, error) {
	id, ok := f.tags[normalizeRef(ref)]
	if !ok {
		return "", "", errors.New("No such image: " + ref)
	}
	return id, f.arch, nil
}

func (f *fakeStore) tag(_ context.Context, source, target string) error {
	f.tagN++
	f.tags[normalizeRef(target)] = source
	return nil
}

// THE review finding: the ref already exists at an OLD id and the tar was
// saved by ID. Tagging only an absent ref left ref on the old image and the
// next start looped on "digest mismatch".
func TestFinishLoadRetagsARefAlreadyPresentAtAnOldID(t *testing.T) {
	newID := "sha256:" + strings.Repeat("e", 64)
	st := &fakeStore{tags: map[string]string{normalizeRef(ownRef): "sha256:" + strings.Repeat("1", 64)}, arch: runtime.GOARCH}
	id, err := finishLoad(context.Background(), st, ownRef, `{"stream":"Loaded image ID: `+newID+`\n"}`, runtime.GOARCH)
	if err != nil {
		t.Fatalf("finishLoad: %v", err)
	}
	if id != newID || st.tagN != 1 {
		t.Fatalf("ref must now name the loaded image: id %s, tags %d", id, st.tagN)
	}
}

func TestFinishLoadRefusesAWrongTagOrArch(t *testing.T) {
	st := &fakeStore{tags: map[string]string{normalizeRef("alpine:latest"): "sha256:a"}, arch: runtime.GOARCH}
	_, err := finishLoad(context.Background(), st, ownRef, `{"stream":"Loaded image: alpine:latest\n"}`, runtime.GOARCH)
	if !IsImageVerification(err) {
		t.Fatalf("an archive that loaded as another name must be refused, got %v", err)
	}
	st2 := &fakeStore{tags: map[string]string{}, arch: "s390x"}
	_, err = finishLoad(context.Background(), st2, ownRef, `{"stream":"Loaded image ID: sha256:`+strings.Repeat("f", 64)+`\n"}`, runtime.GOARCH)
	if !IsImageVerification(err) || !strings.Contains(err.Error(), "architecture") {
		t.Fatalf("wrong arch must be a verification refusal, got %v", err)
	}
}

// --- the archive's own manifest, before load ---------------------------------

func tarWith(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestTarManifestCheck(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		ok    bool
	}{
		{"tagged as the ref", map[string]string{"manifest.json": `[{"Config":"c.json","RepoTags":["` + ownRef + `"]}]`}, true},
		{"saved by ID (no tags)", map[string]string{"manifest.json": `[{"Config":"c.json","RepoTags":null}]`}, true},
		{"familiar vs full name", map[string]string{"manifest.json": `[{"RepoTags":["docker.io/library/alpine:3.20"]}]`}, false},
		{"another tag", map[string]string{"manifest.json": `[{"RepoTags":["alpine:latest"]}]`}, false},
		{"a second tag beside the ref", map[string]string{"manifest.json": `[{"RepoTags":["` + ownRef + `","alpine:latest"]}]`}, false},
		{"two images", map[string]string{"manifest.json": `[{"RepoTags":[]},{"RepoTags":[]}]`}, false},
		{"oci index, one image named right", map[string]string{"index.json": `{"manifests":[{"annotations":{"io.containerd.image.name":"` + ownRef + `"}}]}`}, true},
		{"oci index, two images", map[string]string{"index.json": `{"manifests":[{},{}]}`}, false},
		{"oci index names another", map[string]string{"index.json": `{"manifests":[{"annotations":{"io.containerd.image.name":"docker.io/library/alpine:latest"}}]}`}, false},
		{"not an image archive", map[string]string{"hello.txt": "x"}, false},
	}
	for _, c := range cases {
		err := checkTarManifestReader(tarWith(t, c.files), ownRef)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
	// Familiar and full spellings of the SAME ref agree.
	if err := checkTarManifestReader(tarWith(t, map[string]string{"manifest.json": `[{"RepoTags":["docker.io/library/alpine:3.20"]}]`}), "alpine:3.20"); err != nil {
		t.Errorf("docker.io/library/alpine:3.20 is alpine:3.20: %v", err)
	}
}

// --- the shared ownership rule ------------------------------------------------

func TestOwnImageRuleMatchesTheSharedFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "own_image_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Roots []string `json:"roots"`
		Cases []struct {
			Ref string `json:"ref"`
			Own bool   `json:"own"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Cases) < 10 {
		t.Fatalf("fixture parse found %d cases", len(fx.Cases))
	}
	for _, c := range fx.Cases {
		if got := isOwnImageWith(c.Ref, fx.Roots); got != c.Own {
			t.Errorf("%s: own = %v, want %v", c.Ref, got, c.Own)
		}
	}
}

// --- rail memory is believed only from a file only this agent wrote -----------

func TestRailMemoryRefusesAWritableFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rail", "images.json")
	prev := railMemoryPath
	railMemoryPath = func() string { return p }
	t.Cleanup(func() { railMemoryPath = prev; resetRailMemory() })
	resetRailMemory()

	sha := strings.Repeat("9", 64)
	rememberRailImage(sha, "sha256:x")
	fi, err := os.Stat(filepath.Dir(p))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("rail memory dir must be 0700: %v %v", fi.Mode().Perm(), err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %o, want 600", fi.Mode().Perm())
	}
	resetRailMemory()
	if railImageFor(sha) != "sha256:x" {
		t.Fatal("a file this agent wrote is read back")
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	resetRailMemory()
	if railImageFor(sha) != "" {
		t.Error("a world-writable record must not be believed")
	}
}
