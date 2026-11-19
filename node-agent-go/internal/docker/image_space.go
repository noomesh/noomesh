// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"syscall"

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
// and a .tar.gz unpacks to more than its own size). It is temporary — it is
// replaced by the real unpacked size once the controller records it with
// the staged tar (step 2), and this function is the one place to change.
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
}

func (e *NoSpaceError) Error() string {
	remedy := "free space there (`docker image prune -f` on this node; `noo cluster show " + nodeIDOrPlaceholder() + "`)"
	if strings.Contains(e.Ref, "llamacpp") {
		remedy += ", or place llamacpp on cpu (`noo cluster place " + nodeIDOrPlaceholder() + " llamacpp <model> --on cpu`)"
	}
	remedy += "; the next reconcile pass retries as soon as there is room"
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
