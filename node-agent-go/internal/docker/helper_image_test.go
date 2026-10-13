// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// fakeHelperRail swaps the two daemon-facing steps of EnsureHelperImage and
// reports what was asked of them.
type fakeHelperRail struct {
	present   bool
	pullErr   error
	pullCalls []string
}

func (f *fakeHelperRail) install(t *testing.T) {
	t.Helper()
	prevPresent, prevPull := helperImagePresent, helperImagePull
	helperImagePresent = func(context.Context, *Client, string) bool { return f.present }
	helperImagePull = func(_ context.Context, _ *Client, ref string) (*PullImageArtifactResult, error) {
		f.pullCalls = append(f.pullCalls, ref)
		if f.pullErr != nil {
			return nil, f.pullErr
		}
		f.present = true // a real load puts it in the store
		return &PullImageArtifactResult{Status: "loaded", Image: ref, Tar: ImageTarName(ref, "amd64")}, nil
	}
	t.Cleanup(func() {
		helperImagePresent, helperImagePull = prevPresent, prevPull
		resetHelperImageBackoff()
	})
	resetHelperImageBackoff()
}

// releasedNode is the env a provisioned node carries: a release image pair,
// so helperImage() resolves to the private GHCR ref that a host-process
// node has never pulled and cannot pull.
func releasedNode(t *testing.T) string {
	t.Helper()
	t.Setenv("NOO_HELPER_IMAGE", "")
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	t.Setenv("NOO_IMAGE_TAG", "v0.2.39")
	t.Setenv("NODE_ID", "host3")
	return "ghcr.io/noomesh/node-agent:v0.2.39"
}

// THE finding (host3, v0.2.39, R50): the helper image is not on a
// host-process node, nothing ever tried to get it, and ContainerCreate
// answered "No such image".
//
// Now it is fetched over the artifact rail — the same rail backend images
// arrive on — and the fetch asks for exactly the ref helperImage() derives.
func TestHelperImageAbsentIsFetchedOverTheRail(t *testing.T) {
	ref := releasedNode(t)
	rail := &fakeHelperRail{present: false}
	rail.install(t)

	c := &Client{}
	if err := c.EnsureHelperImage(context.Background()); err != nil {
		t.Fatalf("an absent helper must be fetched, not refused: %v", err)
	}
	if len(rail.pullCalls) != 1 || rail.pullCalls[0] != ref {
		t.Fatalf("expected one rail fetch for %q, got %v", ref, rail.pullCalls)
	}

	// Second call is a no-op: it is in the store now.
	if err := c.EnsureHelperImage(context.Background()); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(rail.pullCalls) != 1 {
		t.Errorf("a present helper must not be re-fetched: %v", rail.pullCalls)
	}
}

// A present helper costs nothing: no fetch, no refusal. (This is every
// container-hosted node, and every host node after the first tick.)
func TestHelperImagePresentIsLeftAlone(t *testing.T) {
	releasedNode(t)
	rail := &fakeHelperRail{present: true}
	rail.install(t)

	if err := (&Client{}).EnsureHelperImage(context.Background()); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(rail.pullCalls) != 0 {
		t.Errorf("no fetch should have been attempted: %v", rail.pullCalls)
	}
}

// Rail unavailable → a typed refusal naming the ref, never a fallback.
func TestRailUnavailableIsATypedRefusal(t *testing.T) {
	ref := releasedNode(t)
	rail := &fakeHelperRail{present: false, pullErr: errors.New("no artifact manifest for node-agent tar")}
	rail.install(t)

	err := (&Client{}).EnsureHelperImage(context.Background())
	if err == nil {
		t.Fatal("an unfetchable helper must be a refusal")
	}
	if !IsHelperImageUnavailable(err) {
		t.Fatalf("the refusal must be TYPED so callers can tell it from a store miss: %T %v", err, err)
	}
	if !strings.Contains(err.Error(), ref) {
		t.Errorf("the refusal must name the image: %v", err)
	}

	var typed *HelperImageUnavailableError
	if !errors.As(err, &typed) {
		t.Fatal("errors.As")
	}
	// The operator copies this line. It must name the node AND the ref,
	// because the bare `sync-images` default set does not cover the
	// release ref (that skew is what made host3 need a hand-written -i).
	fix := typed.Fix("host3")
	for _, want := range []string{"noo cluster sync-images", "host3", "-i " + ref, "--no-restart"} {
		if !strings.Contains(fix, want) {
			t.Errorf("fix %q is missing %q", fix, want)
		}
	}
}

// One failed fetch is remembered, so a tick with several placements does not
// re-attempt a multi-hundred-megabyte transfer once per placement.
func TestFailedFetchIsNotRetriedEveryCall(t *testing.T) {
	releasedNode(t)
	rail := &fakeHelperRail{present: false, pullErr: errors.New("cache unreachable")}
	rail.install(t)

	c := &Client{}
	for i := 0; i < 5; i++ {
		if err := c.EnsureHelperImage(context.Background()); !IsHelperImageUnavailable(err) {
			t.Fatalf("call %d: want a refusal, got %v", i, err)
		}
	}
	if len(rail.pullCalls) != 1 {
		t.Errorf("expected one attempt inside the backoff window, got %d", len(rail.pullCalls))
	}
}

// A rail that starts working is picked up — the backoff must expire, or an
// operator who fixes the export waits 30 minutes wondering why.
func TestBackoffExpires(t *testing.T) {
	releasedNode(t)
	rail := &fakeHelperRail{present: false, pullErr: errors.New("cache unreachable")}
	rail.install(t)
	c := &Client{}

	if err := c.EnsureHelperImage(context.Background()); !IsHelperImageUnavailable(err) {
		t.Fatalf("want refusal, got %v", err)
	}
	// Wind the clock back past the window, then let the rail succeed.
	helperMu.Lock()
	helperLastFail = time.Now().Add(-helperPullBackoff - time.Minute)
	helperMu.Unlock()
	rail.pullErr = nil

	if err := c.EnsureHelperImage(context.Background()); err != nil {
		t.Fatalf("after the window the fetch must be retried: %v", err)
	}
	if len(rail.pullCalls) != 2 {
		t.Errorf("expected a second attempt, got %d", len(rail.pullCalls))
	}
}

// ── the fallback that must not happen ───────────────────────────────────

// preseedModel used to treat EVERY error from the helper as "the controller
// store does not have this model" and fall back to a HuggingFace download.
// The preseed runs in this process against the host path since 2026-09-12:
// no helper container, so a node without the agent image loses nothing. A
// served repo lands in HF_CACHE_DIR/hub/<repo>; a store miss (404) returns
// false and touches nothing, which is the best-effort fallback to HF.
func TestPreseedMirrorsInProcessWithoutAHelper(t *testing.T) {
	// The store is mTLS-only: a plaintext
	// httptest URL would be REFUSED by preseed.CacheURL, so the node's PKI
	// and a store that requires its leaf are stood up for real.
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	srv := pki.Store(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hf/models--Qwen--Qwen3-8B/refs/main":
			_, _ = w.Write([]byte("abc123\n"))
		case "/hf/models--Qwen--Qwen3-8B/snapshots/abc123/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"config.json","type":"file","size":2}]`))
		case "/hf/models--Qwen--Qwen3-8B/snapshots/abc123/config.json":
			_, _ = w.Write([]byte("{}"))
		default:
			w.WriteHeader(404)
		}
	}))
	hf := t.TempDir()
	t.Setenv("NOO_MODEL_CACHE_URL", srv.URL)
	t.Setenv("HF_CACHE_DIR", hf)
	if !(&Client{}).preseedModel(context.Background(), "vllm", "Qwen/Qwen3-8B") {
		t.Fatal("a served repo must preseed in-process")
	}
	if _, err := os.Stat(filepath.Join(hf, "hub", "models--Qwen--Qwen3-8B", "snapshots", "abc123", "config.json")); err != nil {
		t.Fatalf("snapshot file not mirrored into HF_CACHE_DIR/hub: %v", err)
	}
	// A store miss is a miss: false, nothing written, HF fallback follows.
	if (&Client{}).preseedModel(context.Background(), "vllm", "Qwen/Qwen3-0.6B") {
		t.Fatal("a store miss must not report success")
	}
	if _, err := os.Stat(filepath.Join(hf, "hub", "models--Qwen--Qwen3-0.6B")); err == nil {
		t.Fatal("a store miss must not create the repo dir")
	}
}

// Nothing in the preseed path reaches the Docker daemon any more: a nil
// handle is fine, and no helper_image refusal is ever recorded.
func TestPreseedNeverNeedsTheHelperImage(t *testing.T) {
	releasedNode(t)
	rail := &fakeHelperRail{present: false, pullErr: errors.New("no artifact manifest")}
	rail.install(t)
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	preseedtest.New(t).SetNodeEnv(t)
	t.Setenv("NOO_MODEL_CACHE_URL", "https://127.0.0.1:9") // nothing listens: a miss
	t.Setenv("HF_CACHE_DIR", t.TempDir())
	if (&Client{}).preseedModel(context.Background(), "vllm", "Qwen/Qwen3-8B") {
		t.Fatal("an unreachable store must not report success")
	}
	for _, r := range refusals.List() {
		if r.Scope == "helper_image" {
			t.Fatalf("the preseed must not depend on the helper image any more: %+v", r)
		}
	}
	if len(rail.pullCalls) != 0 {
		t.Fatalf("the preseed must not pull the helper image: %v", rail.pullCalls)
	}
}

// The refusal text is what an operator acts on, so it is pinned.
func TestSyncHintNamesTheRefAndTheSkew(t *testing.T) {
	ref := releasedNode(t)
	hint := HelperImageFix("host3")
	for _, want := range []string{
		ref,
		"noo cluster sync-images host3 -i " + ref + " --no-restart",
		"will NOT do it",
	} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint is missing %q:\n%s", want, hint)
		}
	}
	// With no node id it still produces something runnable.
	if h := helperImageSyncHint("", ref); !strings.Contains(h, "<node>") {
		t.Errorf("want a placeholder node: %s", h)
	}
	_ = fmt.Sprint(ref)
}
