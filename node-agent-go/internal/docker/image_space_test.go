// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

const gib = uint64(1) << 30

// stubDisks makes diskStatFn answer from a table (path → stat) and pins
// Docker's data root to root, as if read on a Linux host.
func stubDisks(t *testing.T, root string, disks map[string]diskStat) *int {
	t.Helper()
	pd, pr, ph := diskStatFn, dockerRootDirFn, dockerRootOnHost
	calls := 0
	diskStatFn = func(p string) (diskStat, error) {
		calls++
		st, ok := disks[p]
		if !ok {
			return diskStat{}, fmt.Errorf("no such path %s", p)
		}
		return st, nil
	}
	dockerRootDirFn = func(context.Context, *Client) string { return root }
	dockerRootOnHost = true
	t.Cleanup(func() { diskStatFn, dockerRootDirFn, dockerRootOnHost = pd, pr, ph })
	return &calls
}

// spaceRailNode stands up a store that counts every request, and a manifest
// stub answering m for any tar.
func spaceRailNode(t *testing.T, m *artifactManifest) (staging string, requests *int64) {
	t.Helper()
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	var n int64
	srv := pki.Store(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&n, 1)
		_, _ = w.Write([]byte("tar bytes"))
	}))
	t.Setenv("NOO_MODEL_CACHE_URL", srv.URL)
	staging = t.TempDir()
	t.Setenv("NOO_AGENT_STAGING_DIR", staging)
	prev := imageManifestFetch
	imageManifestFetch = func(context.Context, string) (*artifactManifest, error) { return m, nil }
	t.Cleanup(func() { imageManifestFetch = prev })
	return staging, &n
}

// The manifest's size_bytes (the tar's size) is decoded: it is what the
// space check estimates from.
func TestManifestSizeBytesIsDecoded(t *testing.T) {
	m, err := decodeArtifactManifest([]byte(`{"sha256":"` + strings.Repeat("a", 64) + `","size_bytes":5368709120}`))
	if err != nil {
		t.Fatal(err)
	}
	if m.SizeBytes != 5*gib {
		t.Fatalf("SizeBytes = %d, want %d", m.SizeBytes, 5*gib)
	}
}

// A shortfall refuses with the typed error BEFORE any byte is fetched.
func TestNoSpaceRefusesBeforeAnyFetch(t *testing.T) {
	staging, requests := spaceRailNode(t, &artifactManifest{SHA256: strings.Repeat("0", 64), SizeBytes: 4 * gib})
	stubDisks(t, "/docker-root", map[string]diskStat{
		staging:        {dev: 1, free: 100 << 20},
		"/docker-root": {dev: 2, free: 100 * gib},
	})
	_, err := (&Client{}).PullImageArtifact(context.Background(), ownRef, "", "")
	if !IsNoSpace(err) {
		t.Fatalf("want a NoSpaceError, got %v", err)
	}
	if got := atomic.LoadInt64(requests); got != 0 {
		t.Fatalf("the store was asked %d time(s): a shortfall must refuse before the fetch", got)
	}
	for _, want := range []string{noSpacePrefix, staging, "100 MiB free", "noo autonomy decisions -l disk_watermark", "noo autonomy live disk_watermark", "--on cpu"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "docker image prune") {
		t.Errorf("the remedy must be noo's reclaim, not a raw docker command: %v", err)
	}
}

// The staging dir and Docker's data root on ONE filesystem must hold the
// tar and the load at once; on two, each holds its own share.
func TestSameFilesystemNeedsTheSum(t *testing.T) {
	tar := 4 * gib // fetch 4.5 GiB, load 8.5 GiB, both 12.5 GiB (with margins)
	stubDisks(t, "/root", map[string]diskStat{"/staging": {dev: 7, free: 10 * gib}, "/root": {dev: 7, free: 10 * gib}})
	err := checkImagePullSpace(ownRef, "/staging", "/root", tar)
	if !IsNoSpace(err) || !strings.Contains(err.Error(), "one filesystem") {
		t.Fatalf("one filesystem with 10 GiB for a 4 GiB tar: want a refusal, got %v", err)
	}
	stubDisks(t, "/root", map[string]diskStat{"/staging": {dev: 7, free: 10 * gib}, "/root": {dev: 8, free: 10 * gib}})
	if err := checkImagePullSpace(ownRef, "/staging", "/root", tar); err != nil {
		t.Fatalf("two filesystems with 10 GiB each: want no refusal, got %v", err)
	}
}

// A manifest without size_bytes (an older gateway) is no space check: the
// pull proceeds as before, never refused on an unknown size.
func TestManifestWithoutSizeBytesPullsWithoutASpaceCheck(t *testing.T) {
	staging, requests := spaceRailNode(t, &artifactManifest{SHA256: strings.Repeat("0", 64)})
	stubDisks(t, "/docker-root", map[string]diskStat{
		staging:        {dev: 1, free: 0},
		"/docker-root": {dev: 1, free: 0},
	})
	_, err := (&Client{}).PullImageArtifact(context.Background(), ownRef, "", "")
	if IsNoSpace(err) {
		t.Fatalf("an unknown size must not be refused: %v", err)
	}
	if got := atomic.LoadInt64(requests); got == 0 {
		t.Fatalf("no fetch happened: an unknown size must pull as before (err %v)", err)
	}
}

// A no-space refusal is not a transport failure: the next resolve retries
// right away (the space check is cheap), it is never backed off.
func TestNoSpaceIsNotBackedOff(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{}, staged: stagedAt(ownRef, "sha256:new"),
		railErr: &NoSpaceError{Ref: ownRef, What: "the agent's staging dir", Path: "/staging", Free: 1, Need: 2}}
	f.install(t)
	for i := 0; i < 2; i++ {
		err := (&Client{}).EnsureImage(context.Background(), ownRef)
		if !IsNoSpace(err) {
			t.Fatalf("call %d: want the no-space refusal, got %v", i, err)
		}
	}
	if len(f.railPulls) != 2 {
		t.Fatalf("want a rail attempt on every pass (no backoff), got %d", len(f.railPulls))
	}
}

// A real ENOSPC that slips past the estimate — in docker load's answer, or
// from the fetch's write — is the same typed error, not transport.
func TestRawENOSPCFromLoadIsNoSpace(t *testing.T) {
	out := `{"errorDetail":{"message":"write /var/lib/docker/tmp/x: no space left on device"},"error":"write /var/lib/docker/tmp/x: no space left on device"}`
	err := loadReportError(ownRef, "/var/lib/docker", out)
	if !IsNoSpace(err) || !strings.HasPrefix(err.Error(), noSpacePrefix) || !strings.Contains(err.Error(), "/var/lib/docker") {
		t.Fatalf("docker load's no-space answer: want a NoSpaceError naming the data root, got %v", err)
	}
	if err := loadReportError(ownRef, "/var/lib/docker", `{"error":"invalid tar header"}`); err == nil || IsNoSpace(err) {
		t.Errorf("another load error must stay as it is, got %v", err)
	}
	if err := loadReportError(ownRef, "/var/lib/docker", `{"stream":"Loaded image: x\n"}`); err != nil {
		t.Errorf("a clean load: %v", err)
	}
	werr := classifyNoSpace(ownRef, "the agent's staging dir", "/staging", fmt.Errorf("fetch x: %w", syscall.ENOSPC))
	if !IsNoSpace(werr) || !errors.Is(werr, syscall.ENOSPC) {
		t.Errorf("a fetch write's ENOSPC: want a NoSpaceError wrapping it, got %v", werr)
	}
}

// noSpaceRecorded reports whether ref has a real-ENOSPC record. Tests only.
func noSpaceRecorded(ref string) bool {
	railFailMu.Lock()
	defer railFailMu.Unlock()
	_, ok := noSpaceSeen[ref]
	return ok
}

// realENOSPC is what PullImageArtifact returns when the fetch's write ran
// out of space for real (classifyNoSpace).
func realENOSPC(path string) error {
	return &NoSpaceError{Ref: ownRef, What: "the agent's staging dir", Path: path, Err: fmt.Errorf("fetch x: %w", syscall.ENOSPC)}
}

// A real ENOSPC (the estimate passed, the disk did not) is not re-fetched
// on the next pass while free space is unchanged; once the path gains
// noSpaceRetryStep the pull is tried again. No timer involved.
func TestARealENOSPCDoesNotRefetchUntilSpaceGrows(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{}, staged: stagedAt(ownRef, "sha256:new"), railErr: realENOSPC("/staging")}
	f.install(t)
	disks := map[string]diskStat{"/staging": {dev: 1, free: 1 * gib}}
	stubDisks(t, "/root", disks)

	for i := 0; i < 2; i++ {
		if err := (&Client{}).EnsureImage(context.Background(), ownRef); !IsNoSpace(err) {
			t.Fatalf("pass %d: want the no-space refusal, got %v", i, err)
		}
	}
	if len(f.railPulls) != 1 {
		t.Fatalf("free space unchanged: want ONE fetch over two passes, got %d", len(f.railPulls))
	}
	err := (&Client{}).EnsureImage(context.Background(), ownRef)
	if err == nil || !strings.Contains(err.Error(), "waiting for space: /staging had 1024 MiB free") {
		t.Fatalf("the waiting refusal must name the path and the free space seen: %v", err)
	}

	disks["/staging"] = diskStat{dev: 1, free: 1*gib + noSpaceRetryStep}
	f.railErr = nil
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
		t.Fatalf("free space grew past the step: the pull must run, got %v", err)
	}
	if len(f.railPulls) != 2 {
		t.Fatalf("after the space grew: want a second fetch, got %d", len(f.railPulls))
	}
}

// A successful pull clears the record, also when it ran without the gate
// (free space unknown at the time: retried, the record kept until then).
func TestASuccessfulPullClearsTheNoSpaceRecord(t *testing.T) {
	f := &fakeImageRail{local: map[string]string{}, staged: stagedAt(ownRef, "sha256:new"), railErr: realENOSPC("/staging")}
	f.install(t)
	disks := map[string]diskStat{"/staging": {dev: 1, free: 1 * gib}}
	stubDisks(t, "/root", disks)
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); !IsNoSpace(err) {
		t.Fatalf("want the no-space refusal, got %v", err)
	}
	if !noSpaceRecorded(ownRef) {
		t.Fatal("a real ENOSPC with a readable path must be recorded")
	}
	delete(disks, "/staging") // free space unknown: retried, no loop guard
	f.railErr = nil
	if err := (&Client{}).EnsureImage(context.Background(), ownRef); err != nil {
		t.Fatalf("unknown free space must retry, got %v", err)
	}
	if len(f.railPulls) != 2 {
		t.Fatalf("want the retry to fetch, got %d pulls", len(f.railPulls))
	}
	if noSpaceRecorded(ownRef) {
		t.Fatal("a successful pull must clear the no-space record")
	}
}
