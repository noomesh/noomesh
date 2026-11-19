// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/nodewl"
)

// i1036 step 3: an add-on node workload's image tar gets the same disk-space
// rule as a backend image (image_space.go, PullImageArtifact).

const wlArtifact = "noo-addon-wl_a_b_ffff_amd64.tar"

// A shortfall refuses with the typed error BEFORE any byte is fetched.
func TestNodeWorkloadTarShortOnDiskRefusesBeforeAnyFetch(t *testing.T) {
	staging, requests := spaceRailNode(t, &artifactManifest{SHA256: strings.Repeat("0", 64), SizeBytes: 4 * gib})
	stubDisks(t, "/docker-root", map[string]diskStat{
		staging:        {dev: 1, free: 100 << 20},
		"/docker-root": {dev: 2, free: 100 * gib},
	})
	path, _, err := fetchRailTar(context.Background(), wlArtifact, "/docker-root")
	if !IsNoSpace(err) {
		t.Fatalf("want a NoSpaceError, got %v", err)
	}
	if got := atomic.LoadInt64(requests); got != 0 {
		t.Fatalf("the store was asked %d time(s): a shortfall must refuse before the fetch", got)
	}
	if path != "" {
		t.Errorf("a path %q came back with the refusal", path)
	}
	for _, want := range []string{noSpacePrefix, wlArtifact, staging, "100 MiB free"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// A manifest without size_bytes is no space check: the fetch proceeds, never
// refused on an unknown size, even with every disk reading 0 bytes free.
func TestNodeWorkloadTarWithoutSizeBytesFetchesWithoutASpaceCheck(t *testing.T) {
	staging, requests := spaceRailNode(t, &artifactManifest{SHA256: sumHex([]byte("tar bytes"))})
	stubDisks(t, "/docker-root", map[string]diskStat{
		staging:        {dev: 1, free: 0},
		"/docker-root": {dev: 1, free: 0},
	})
	path, cleanup, err := fetchRailTar(context.Background(), wlArtifact, "/docker-root")
	if err != nil {
		t.Fatalf("an unknown size must not refuse: %v", err)
	}
	defer cleanup()
	if got := atomic.LoadInt64(requests); got != 1 {
		t.Fatalf("the store was asked %d time(s), want 1", got)
	}
	if path == "" {
		t.Error("no staged path came back")
	}
}

// A real ENOSPC from docker load is reason disk naming the shortfall, not an
// uncoded docker failure.
func TestNodeWorkloadLoadENOSPCIsNoSpace(t *testing.T) {
	t.Cleanup(resetRailBackoff)
	h := newHarness(t)
	h.api.loadErr = fmt.Errorf("write /var/lib/docker/tmp/x: %w", syscall.ENOSPC)
	err := h.provision()
	if nodewl.CodeOf(err) != nodewl.ReasonDisk {
		t.Fatalf("err %v, want reason %q", err, nodewl.ReasonDisk)
	}
	for _, want := range []string{noSpacePrefix, "Docker's data root", "no space left on device"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// A NoSpaceError from the fetch is reason disk and never on the transport
// fetch backoff: the next pass tries again (a statfs) at once.
func TestNodeWorkloadNoSpaceIsNotBackedOff(t *testing.T) {
	t.Cleanup(resetRailBackoff)
	h := newHarness(t)
	calls := 0
	h.p.fetchTar = func(context.Context, string, string) (string, func(), error) {
		calls++
		return "", nil, &NoSpaceError{Ref: wlArtifact, What: "the agent's staging dir", Path: "/staging", Free: 1 << 20, Need: 5 * gib}
	}
	for pass := 1; pass <= 2; pass++ {
		err := h.provision()
		if nodewl.CodeOf(err) != nodewl.ReasonDisk || !strings.Contains(err.Error(), noSpacePrefix) {
			t.Fatalf("pass %d: err %v, want reason %q naming the shortfall", pass, err, nodewl.ReasonDisk)
		}
	}
	if calls != 2 {
		t.Fatalf("fetched %d time(s) in two passes: a NoSpaceError must not be backed off", calls)
	}
	if why, wait := h.p.fetchBackoff.blocked(h.entry.Image.Artifact, time.Now()); wait != 0 {
		t.Fatalf("the fetch backoff holds %q for %s", why, wait)
	}
}
