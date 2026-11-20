// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

// Disk space for an image pull over the artifact rail.
//
// A pull lands the controller's tar in stagingDir(), then `docker load`
// unpacks it into Docker's data root while the tar is still on disk. The
// peak need is the tar plus the unpacked layers. Before this check a full
// disk surfaced as a raw "no space left on device" from the fetch or the
// load, which resolveImage took for a transport failure and backed off for
// railRetryBackoff (30 min) — so after an operator freed space the start
// still waited up to half an hour. A shortfall is now a NoSpaceError,
// refused BEFORE any byte is fetched, and never backed off: each reconcile
// pass re-checks (a statfs, cheap) and the start goes ahead as soon as
// there is room.

// imageSpaceMargin is the headroom kept on each filesystem on top of the
// estimated need — the same 512 MiB requireFree (ollama_mirror_import.go)
// keeps for an ollama import.
const imageSpaceMargin uint64 = 512 << 20

// imageLoadExtraFloor is the floor of imageLoadNeed's tar + N GiB arm.
const imageLoadExtraFloor uint64 = 2 << 30

// imageLoadNeed is the space `docker load` of a tar of tarBytes is assumed
// to need in Docker's data root: the larger of 2 × the tar or the tar +
// 2 GiB. A STATED, CONSERVATIVE ESTIMATE: the unpacked size of an image is
// not known on the node (the manifest carries only the tar's size_bytes,
// and a .tar.gz unpacks to more than its own size). The controller now
// records the real unpacked size with the staged tar (i1036), and its
// place-time check (gateway-rust routes/cluster.rs image_space_need) needs
// the tar + the LARGER of that size and this estimate + imageSpaceMargin, so
// it refuses nothing this check would pass: change the two together
// (TestImageLoadNeedFixedExample pins the shared number).
func imageLoadNeed(tarBytes uint64) uint64 {
	if twice := 2 * tarBytes; twice > tarBytes+imageLoadExtraFloor {
		return twice
	}
	return tarBytes + imageLoadExtraFloor
}

// diskStat is what the check reads of one path's filesystem.
type diskStat struct {
	dev  uint64 // the filesystem's device: equal devs share free space
	free uint64 // bytes available to an unprivileged writer
}

// diskStatFn reads path's filesystem; a seam so the check is testable
// without filling a disk.
var diskStatFn = func(path string) (diskStat, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return diskStat{}, err
	}
	free, err := freeBytes(path)
	if err != nil {
		return diskStat{}, err
	}
	return diskStat{dev: uint64(st.Dev), free: free}, nil //nolint:unconvert // Dev's type differs by platform
}

// defaultDockerRootDir is where Docker keeps images when `docker info`
// cannot say.
const defaultDockerRootDir = "/var/lib/docker"

// dockerRootDirFn is Docker's data root as the daemon reports it
// (`docker info` DockerRootDir), or defaultDockerRootDir. A seam for tests.
var dockerRootDirFn = func(ctx context.Context, c *Client) string {
	if c != nil && c.docker != nil {
		if res, err := c.docker.Info(ctx, client.InfoOptions{}); err == nil && res.Info.DockerRootDir != "" {
			return res.Info.DockerRootDir
		}
	}
	return defaultDockerRootDir
}

// dockerRootOnHost: the daemon's data root is a path on this host. Not on
// a Mac, where Docker Desktop keeps it inside its Linux VM. A var so a test
// can pin it.
var dockerRootOnHost = runtime.GOOS == "linux"

// containerdRootDir is containerd's root. On a node whose Docker keeps
// images in the containerd image store, the unpacked layers land here and
// not under DockerRootDir; `GET /health`'s disk list (api/handlers.go) and
// the reclaim (diskreclaim.Paths) read the same path.
const containerdRootDir = "/var/lib/containerd"

// imageStoreFreeBytes is the heartbeat's `image_store_free_bytes` (i1036):
// the LEAST free space, in bytes, over the filesystems an image pull writes
// to — Docker's data root, containerd's root and the agent's staging dir —
// so the controller can tell before it places a GPU llama.cpp whether the
// CUDA image (~2.6 GB tar, ~4 GB unpacked) can land here.
//
// A path that does not exist is skipped, never counted as 0 (most nodes
// have no containerd root). The staging dir is created on the first pull,
// so until then its nearest existing parent is read: the filesystem the
// fetch will write to. Any other read error, a host whose Docker data root
// is not on this host (a Mac's VM) or no readable path at all is UNKNOWN:
// ok=false, and the key is omitted (an i300 key: never 0 for unknown).
func imageStoreFreeBytes(dockerRoot, staging string) (int64, bool) {
	if !dockerRootOnHost {
		return 0, false
	}
	var least uint64
	seen := false
	for _, p := range []struct {
		path   string
		walkUp bool
	}{{dockerRoot, false}, {containerdRootDir, false}, {staging, true}} {
		if p.path == "" {
			continue
		}
		path := filepath.Clean(p.path)
		st, err := diskStatFn(path)
		for p.walkUp && errors.Is(err, fs.ErrNotExist) && filepath.Dir(path) != path {
			path = filepath.Dir(path)
			st, err = diskStatFn(path)
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			slog.Debug("heartbeat omits image_store_free_bytes", "path", path, "err", err)
			return 0, false
		}
		if !seen || st.free < least {
			least, seen = st.free, true
		}
	}
	if !seen {
		return 0, false
	}
	if least > math.MaxInt64 {
		least = math.MaxInt64
	}
	return int64(least), true
}

// dockerRootTTL is how long the heartbeat reuses Docker's data root: it
// changes only when the daemon restarts with another data-root, and asking
// `docker info` every 30 s beat would cost a daemon round trip for nothing.
const dockerRootTTL = 10 * time.Minute

var dockerRootCache struct {
	mu   sync.Mutex
	root string
	at   time.Time
}

// ImageStoreFreeBytes is the provider of the heartbeat's
// `image_store_free_bytes` (imageStoreFreeBytes over this node's paths).
// ctx bounds the `docker info` that reads Docker's data root.
func (c *Client) ImageStoreFreeBytes(ctx context.Context) (int64, bool) {
	dockerRootCache.mu.Lock()
	if dockerRootCache.root == "" || time.Since(dockerRootCache.at) > dockerRootTTL {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		dockerRootCache.root = dockerRootDirFn(ctx, c)
		cancel()
		dockerRootCache.at = time.Now()
	}
	root := dockerRootCache.root
	dockerRootCache.mu.Unlock()
	return imageStoreFreeBytes(root, stagingDir())
}

// checkImagePullSpace refuses a pull of a tar of tarBytes when the staging
// dir lacks room for the tar, or Docker's data root lacks room for the
// load (imageLoadNeed); when both are one filesystem it must hold the sum.
// Each filesystem keeps imageSpaceMargin on top.
//
// tarBytes 0 (an older gateway that sends no size_bytes) is no check: there
// is nothing to estimate from, and the raw ENOSPC classification below still
// keeps a full disk out of the transport backoff. A path whose filesystem
// cannot be read is skipped with a log, never a refusal on an unknown.
func checkImagePullSpace(ref, staging, dockerRoot string, tarBytes uint64) error {
	if tarBytes == 0 {
		return nil
	}
	sst, err := diskStatFn(staging)
	if err != nil {
		slog.Warn("image.space_unknown: cannot read the staging dir's free space; pulling without the check",
			"image", ref, "path", staging, "err", err)
		return nil
	}
	fetchNeed := tarBytes + imageSpaceMargin
	loadNeed := imageLoadNeed(tarBytes) + imageSpaceMargin
	if dockerRootOnHost && dockerRoot != "" {
		if rst, rerr := diskStatFn(dockerRoot); rerr != nil {
			slog.Debug("image.space_unknown: cannot read Docker's data root; checking the staging dir only",
				"image", ref, "path", dockerRoot, "err", rerr)
		} else if rst.dev == sst.dev {
			// One filesystem holds the tar AND the unpacked layers at once.
			need := tarBytes + imageLoadNeed(tarBytes) + imageSpaceMargin
			if sst.free < need {
				return &NoSpaceError{Ref: ref, What: "the staging dir and Docker's data root (one filesystem)",
					Path: staging + " + " + dockerRoot, Free: sst.free, Need: need}
			}
			return nil
		} else if rst.free < loadNeed {
			return &NoSpaceError{Ref: ref, What: "Docker's data root", Path: dockerRoot, Free: rst.free, Need: loadNeed}
		}
	}
	if sst.free < fetchNeed {
		return &NoSpaceError{Ref: ref, What: "the agent's staging dir", Path: staging, Free: sst.free, Need: fetchNeed}
	}
	return nil
}

// noSpacePrefix starts every NoSpaceError's text. `noo cluster verify`'s
// `backend starts` row matches it (with the raw "no space left on device")
// to give a disk remedy: keep the two in lockstep.
const noSpacePrefix = "not enough disk space for image"

// NoSpaceError: this node has no room to pull ref — refused before the
// fetch (Free/Need set), or a real ENOSPC from the fetch or the load (Err
// set). Not a transport failure: resolveImage never backs it off.
type NoSpaceError struct {
	Ref  string
	What string // which store: the staging dir, Docker's data root, or both
	Path string // the node path that is short
	Free uint64
	Need uint64
	Err  error // the raw ENOSPC, when that is what was seen
	// Waiting: no pull was tried — the last one ran out of space at Path
	// with Free bytes free, and Path has not gained noSpaceRetryStep since
	// (noSpaceGate, image_source.go).
	Waiting bool
}

func (e *NoSpaceError) Error() string {
	// noo's own way first (the disk_watermark reclaim), never a raw docker
	// command on a remote shell.
	node := nodeIDOrPlaceholder()
	remedy := "free space on " + node + ": `noo autonomy decisions -l disk_watermark` shows what noo's reclaim would free there; " +
		"`noo autonomy live disk_watermark` lets it act (an operator decision; see docs/operating/disk-and-images.md)"
	if strings.Contains(e.Ref, "llamacpp") {
		remedy += ", or place it on cpu: `noo cluster place " + node + " llamacpp <model> --on cpu`"
	}
	remedy += "; `noo cluster show " + node + "`; the next reconcile pass retries as soon as there is room"
	if e.Waiting {
		return fmt.Sprintf("%s %s: waiting for space: %s had %d MiB free when the last pull ran out; retrying once it has more — %s",
			noSpacePrefix, e.Ref, e.Path, e.Free>>20, remedy)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s %s: %s (%s) ran out of space (%v) — %s", noSpacePrefix, e.Ref, e.What, e.Path, e.Err, remedy)
	}
	return fmt.Sprintf("%s %s: %s (%s) has %d MiB free; this pull needs %d MiB there — %s",
		noSpacePrefix, e.Ref, e.What, e.Path, e.Free>>20, e.Need>>20, remedy)
}

func (e *NoSpaceError) Unwrap() error { return e.Err }

// IsNoSpace reports whether err is (or wraps) a NoSpaceError.
func IsNoSpace(err error) bool {
	var t *NoSpaceError
	return errors.As(err, &t)
}

// classifyNoSpace turns a real "no space left on device" (ENOSPC, or the
// text of one in a daemon's answer) into a NoSpaceError naming what and
// path; any other error comes back unchanged.
func classifyNoSpace(ref, what, path string, err error) error {
	if err == nil || IsNoSpace(err) {
		return err
	}
	if errors.Is(err, syscall.ENOSPC) || strings.Contains(strings.ToLower(err.Error()), "no space left on device") {
		return &NoSpaceError{Ref: ref, What: what, Path: path, Err: err}
	}
	return err
}

// loadReportError reads `docker load`'s drained progress stream: nil when it
// reports no error, a NoSpaceError when the daemon ran out of space, else
// the reported error.
func loadReportError(ref, dockerRoot, loadOut string) error {
	if !strings.Contains(loadOut, "\"error\"") {
		return nil
	}
	return classifyNoSpace(ref, "Docker's data root", dockerRoot,
		fmt.Errorf("docker load reported: %s", strings.TrimSpace(loadOut)))
}
