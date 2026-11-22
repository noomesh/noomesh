// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

// A REAL-daemon proof of rung 5's removal (i1206): the fakes in
// image_retention_test.go model the two image stores, and the bug lived in
// the difference between a model and a daemon. Runs only when
// NOO_REAL_DAEMON_RETENTION_TEST=1 (the image-retention-daemon workflow, one
// leg per store, each asserting the store it was given); everywhere else it
// skips. It talks to whatever DOCKER_HOST the environment names.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// probeImage is a small public image pulled by tag, so the daemon records
// both a tag and a repo digest for it (the shape of a pulled release image).
const probeImage = "busybox:1.37.0"

func realDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func realDaemonOrSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("NOO_REAL_DAEMON_RETENTION_TEST") != "1" {
		t.Skip("real-daemon proof: runs only in the image-retention-daemon workflow (NOO_REAL_DAEMON_RETENTION_TEST=1)")
	}
	t.Logf("daemon: %s", realDocker(t, "info", "--format", "Docker {{.ServerVersion}}, driver {{.Driver}} {{json .DriverStatus}}"))
}

// pulled: the probe pulled, its repo digest, and two refs shaped like ours,
// all on one image. Returns the image ID and its refs (ours first, then the
// upstream tag and digest).
func pulled(t *testing.T, suffix string) (string, []string) {
	t.Helper()
	realDocker(t, "pull", "-q", probeImage)
	id := realDocker(t, "image", "inspect", "--format", "{{.Id}}", probeImage)
	dig := realDocker(t, "image", "inspect", "--format", "{{index .RepoDigests 0}}", probeImage)
	ours := []string{
		"ghcr.io/noomesh/retention-probe-" + suffix + ":v0.6.24",
		"ghcr.io/noomesh/retention-probe-" + suffix + ":v0.6.25",
	}
	for _, r := range ours {
		realDocker(t, "tag", probeImage, r)
	}
	return id, append(ours, probeImage, dig)
}

// Every ref of a several-ref image goes, the image is gone, and NOTHING is
// reported refused, on either store (on the containerd store one ref's
// removal can delete the image; the later refs then answer "No such image").
func TestRealDaemonRemovesEveryRefOfAnImageWithNoRefusal(t *testing.T) {
	realDaemonOrSkip(t)
	id, refs := pulled(t, "rm")
	e := &Engine{Runner: ExecRunner{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	msg, ok := e.removeImage(ctx, &imageVerdict{ID: id, Refs: refs, Remove: true})
	if !ok {
		t.Fatalf("a removable image was reported refused: %q (refs %v)", msg, refs)
	}
	if out, err := exec.Command("docker", "image", "inspect", id).CombinedOutput(); err == nil {
		t.Fatalf("reported removed but the image is still there: %s", out)
	}
}

// An image a stopped container still uses is refused, and the reason is
// Docker's own words (never the empty "refused: " the operator saw).
func TestRealDaemonRefusesAnImageAStoppedContainerUsesWithDockersWords(t *testing.T) {
	realDaemonOrSkip(t)
	id, refs := pulled(t, "keep")
	name := fmt.Sprintf("noo-retention-probe-%d", time.Now().UnixNano())
	realDocker(t, "create", "--name", name, refs[0], "true")
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", name).Run()
		for _, r := range refs {
			_ = exec.Command("docker", "image", "rm", r).Run()
		}
		_ = exec.Command("docker", "image", "rm", id).Run()
	})
	e := &Engine{Runner: ExecRunner{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	msg, ok := e.removeImage(ctx, &imageVerdict{ID: id, Refs: refs, Remove: true})
	if ok {
		t.Fatalf("an image a container uses was reported removed (refs %v)", refs)
	}
	if strings.TrimSpace(msg) == "" || !strings.Contains(strings.ToLower(msg), "container") {
		t.Fatalf("the refusal must carry Docker's reason naming the container, got %q", msg)
	}
	t.Logf("refusal, in Docker's words: %s", msg)
}
