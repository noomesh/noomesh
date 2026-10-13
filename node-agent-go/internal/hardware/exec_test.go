// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hardware

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type fakeFileInfo struct{ mode os.FileMode }

func (f fakeFileInfo) Name() string       { return "nvidia-smi" }
func (f fakeFileInfo) Size() int64        { return 1 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func TestResolveNvidiaSmi(t *testing.T) {
	notFound := func(string) (string, error) { return "", errors.New("not in PATH") }
	statNone := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	// PATH hit wins outright — no fallback probing.
	got := resolveNvidiaSmi(
		func(string) (string, error) { return "/usr/bin/nvidia-smi", nil },
		func(string) (os.FileInfo, error) { t.Fatal("stat must not be called on a PATH hit"); return nil, nil },
	)
	if got != "/usr/bin/nvidia-smi" {
		t.Fatalf("PATH hit: got %q", got)
	}

	// The WSL2 location: present on disk but never on the systemd PATH —
	// the exact shape that reported gpu_count=0 on a working RTX 3080.
	got = resolveNvidiaSmi(notFound, func(p string) (os.FileInfo, error) {
		if p == "/usr/lib/wsl/lib/nvidia-smi" {
			return fakeFileInfo{mode: 0o755}, nil
		}
		return nil, os.ErrNotExist
	})
	if got != "/usr/lib/wsl/lib/nvidia-smi" {
		t.Fatalf("WSL fallback: got %q", got)
	}

	// A directory at a candidate path must not be treated as the binary.
	got = resolveNvidiaSmi(notFound, func(p string) (os.FileInfo, error) {
		if p == "/usr/lib/wsl/lib/nvidia-smi" {
			return fakeFileInfo{mode: os.ModeDir | 0o755}, nil
		}
		return nil, os.ErrNotExist
	})
	if got != "nvidia-smi" {
		t.Fatalf("directory candidate: got %q", got)
	}

	// Nothing anywhere: bare name, so exec fails the way it always did.
	if got = resolveNvidiaSmi(notFound, statNone); got != "nvidia-smi" {
		t.Fatalf("no binary: got %q", got)
	}
}

// A deadline miss must be errors.Is-distinguishable from an affirmative
// failure: busyness (nvidia-smi too slow on a saturated GPU) must never be
// classified as "no GPU" — that classification caches sticky and pages the
// operator via gpu_health until the agent restarts.
func TestExecWithinClassifiesDeadlineVsFailure(t *testing.T) {
	_, err := execWithin(100*time.Millisecond, "sleep", "1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow command: want DeadlineExceeded, got %v", err)
	}

	_, err = execWithin(time.Second, "definitely-not-a-binary-noo-test")
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing binary: want a non-deadline error, got %v", err)
	}
}

// The deadline must hold even when the child cannot be reaped on time.
// `sh -c "sleep 3 & sleep 3"`: SIGKILL takes the shell, but the sleep it
// backgrounded inherited stdout, so cmd.Output would sit on that pipe for
// the full three seconds — thirty times the budget. That is the shape that
// silenced host3 (a stuck nvidia-smi on a saturated WSL2 GPU) for minutes
// at a time while every caller believed it had a five-second probe.
func TestExecWithinReturnsAtTheDeadlineWhenTheChildCannotBeReaped(t *testing.T) {
	start := time.Now()
	_, err := execWithin(100*time.Millisecond, "sh", "-c", "sleep 3 & sleep 3")
	took := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if took > time.Second {
		t.Fatalf("returned after %v; the 100ms deadline was not honoured", took)
	}

	// While that child is still outstanding, a second call for the same
	// command does not spawn another copy to get stuck behind it: it
	// answers at once, and the answer still reads as a deadline miss.
	start = time.Now()
	_, err = execWithin(time.Second, "sh", "-c", "true")
	if !errors.Is(err, ErrProbeStuck) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second call while stuck: want ErrProbeStuck wrapping DeadlineExceeded, got %v", err)
	}
	if since := time.Since(start); since > 100*time.Millisecond {
		t.Fatalf("second call while stuck took %v; it must not wait", since)
	}

	// A different command is not held hostage by it.
	if out, err := execWithin(time.Second, "echo", "ok"); err != nil || out != "ok\n" {
		t.Fatalf("unrelated command while sh is stuck: out=%q err=%v", out, err)
	}

	// Once the kernel lets go, the gate clears and the command runs again.
	deadline := time.Now().Add(8 * time.Second)
	for stuckCount("sh") > 0 {
		if time.Now().After(deadline) {
			t.Fatal("stuck count for sh never cleared after the child exited")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if out, err := execWithin(time.Second, "sh", "-c", "echo back"); err != nil || out != "back\n" {
		t.Fatalf("after the stuck child exited: out=%q err=%v", out, err)
	}
}
