// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build unix

package hostd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A real bash runs the real boot-restore script against a FAKE docker that
// answers from files; PATH is the fake plus symlinks to the few tools the
// script needs, so the machine's own docker is unreachable from the run.
type bootFixture struct {
	e      *Engine
	dir    string // fake docker dir
	rundir string
	mu     sync.Mutex
	logs   []string
}

func (f *bootFixture) logText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.logs, "\n")
}

func (f *bootFixture) argv(t *testing.T) []string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(f.dir, "argv.log"))
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// behave: a docker subcommand+container pair that sleeps instead of answering.
func (f *bootFixture) hang(t *testing.T, key string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "hang."+key), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

const fakeDocker = `#!/bin/bash
d="$(dirname "$0")"
printf 'docker' >> "$d/argv.log"; printf ' %s' "$@" >> "$d/argv.log"; printf '\n' >> "$d/argv.log"
sub="$1"; id=""
for a in "$@"; do id="$a"; done
[ "$sub" = ps ] && id=ps
kind="$sub"
case "$*" in *Mounts*) kind=mounts ;; *State.Running*) kind=running ;; esac
[ -e "$d/hang.$kind.$id" ] && exec sleep 60
case "$sub" in
  ps) printf 'aaa\nbbb\nccc\n' ;;
  start) ;;
  inspect)
    case "$*" in
      *Mounts*) echo "$(cat "$d/rundir")/x" ;;
      *State.Running*) echo true ;;
    esac ;;
esac
exit 0
`

func newBootFixture(t *testing.T) *bootFixture {
	t.Helper()
	root := t.TempDir()
	fake := t.TempDir()
	tools := t.TempDir()
	rundir := filepath.Join(t.TempDir(), "secrets")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "scripts"), 0o755))
	must(os.WriteFile(filepath.Join(root, "scripts", "lib-secrets.sh"),
		[]byte("secret_rundir() { echo '"+rundir+"'; }\nload_secrets() { mkdir -p '"+rundir+"' && touch '"+rundir+"/f'; }\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "docker-compose.cluster.yml"), []byte("services: {}\n"), 0o644))
	must(os.WriteFile(filepath.Join(fake, "docker"), []byte(fakeDocker), 0o755))
	must(os.WriteFile(filepath.Join(fake, "rundir"), []byte(rundir), 0o644))
	for _, tool := range []string{"bash", "timeout", "sleep", "grep", "cut", "sed", "awk", "sort", "tr", "head", "ls", "dirname", "cat", "mkdir", "touch", "printf", "echo"} {
		if p, err := exec.LookPath(tool); err == nil {
			must(os.Symlink(p, filepath.Join(tools, tool)))
		}
	}
	t.Setenv("PATH", fake+":"+tools)
	t.Setenv("COMPOSE_LOCK_FILE", filepath.Join(t.TempDir(), "compose.lock"))
	t.Setenv("COMPOSE_PROJECT_NAME", "")
	// The real docker must be unreachable from this PATH: the only `docker`
	// it resolves is the fake.
	if p, err := exec.LookPath("docker"); err != nil || p != filepath.Join(fake, "docker") {
		t.Fatalf("docker resolves to %q (%v), want the fake", p, err)
	}
	f := &bootFixture{dir: fake, rundir: rundir}
	f.e = &Engine{Root: root, Runner: ExecRunner{}, Logf: func(format string, a ...any) {
		f.mu.Lock()
		f.logs = append(f.logs, strings.TrimSpace(fmt.Sprintf(format, a...)))
		f.mu.Unlock()
	}}
	// short bounds for the test; restored after
	ol, oi, os_, on, oo := bootListBound, bootInspectBound, bootStartBound, bootNetnsBound, bootOverall
	t.Cleanup(func() {
		bootListBound, bootInspectBound, bootStartBound, bootNetnsBound, bootOverall = ol, oi, os_, on, oo
	})
	bootListBound, bootInspectBound, bootStartBound, bootNetnsBound, bootOverall = 2*time.Second, 1*time.Second, 5*time.Second, 1*time.Second, 20*time.Second
	return f
}

func assertLockFree(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		unlock, err := acquireComposeLock(context.Background())
		if err == nil {
			unlock()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the compose lock is still held after boot-restore returned")
	}
}

// Docker answers normally: the same calls in the same order as before the
// bounds, with the same argv (timeout execs docker unchanged).
func TestBootRestoreBoundedNormalPathRecordsTheSameDockerCalls(t *testing.T) {
	f := newBootFixture(t)
	f.e.BootRestore(context.Background())
	mounts := "docker inspect -f {{range .Mounts}}{{println .Source}}{{end}} "
	var want = []string{"docker ps -aq --filter status=created --filter status=exited"}
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		want = append(want, "docker "+strings.TrimPrefix(mounts, "docker ")+id, "docker start "+id, "docker inspect -f {{.State.Running}} "+id)
	}
	got := f.argv(t)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("docker calls changed:\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(f.logText(), "boot-restore: done") || strings.Contains(f.logText(), "did not answer") {
		t.Fatalf("log: %s", f.logText())
	}
	assertLockFree(t)
}

// One container Docker never answers for (the mounts inspect, the start, or
// the running check) is skipped and named; the rest are still handled;
// boot-restore returns within the bounds.
func TestBootRestoreBoundedSkipsAContainerDockerDoesNotAnswerFor(t *testing.T) {
	for _, tc := range []struct{ key, call string }{
		{"mounts.bbb", "docker inspect"},
		{"start.bbb", "docker start"},
		{"running.bbb", "docker inspect"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			f := newBootFixture(t)
			f.hang(t, tc.key)
			t0 := time.Now()
			f.e.BootRestore(context.Background())
			if el := time.Since(t0); el > 8*time.Second {
				t.Fatalf("boot-restore took %s with one wedged container", el)
			}
			argv := strings.Join(f.argv(t), "\n")
			for _, id := range []string{"aaa", "ccc"} {
				if !strings.Contains(argv, "docker start "+id) || !strings.Contains(argv, "docker inspect -f {{.State.Running}} "+id) {
					t.Errorf("container %s was not fully handled:\n%s", id, argv)
				}
			}
			logs := f.logText()
			if !strings.Contains(logs, "Docker did not answer for container bbb within") || !strings.Contains(logs, "("+tc.call+"); it was left alone") {
				t.Errorf("the skipped container is not named:\n%s", logs)
			}
			if !strings.Contains(logs, "started 2; Docker did not answer for: bbb (left alone)") && !strings.Contains(logs, "started 3; Docker did not answer for: bbb (left alone)") || strings.Contains(logs, "boot-restore: done") {
				t.Errorf("a skipped container must not be reported as a plain success:\n%s", logs)
			}
			assertLockFree(t)
		})
	}
}

// A hung `docker ps` fails the attempt within the list bound, says so, and
// releases the lock; nothing is started.
func TestBootRestoreBoundedHungListFailsTheAttemptAndReleasesTheLock(t *testing.T) {
	f := newBootFixture(t)
	f.hang(t, "ps.ps")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inner := f.e.Logf
	f.e.Logf = func(format string, a ...any) {
		inner(format, a...)
		if strings.Contains(fmt.Sprintf(format, a...), "attempt 1 failed") {
			cancel() // stop the retry loop's sleep
		}
	}
	t0 := time.Now()
	f.e.BootRestore(ctx)
	if el := time.Since(t0); el > 8*time.Second {
		t.Fatalf("took %s with a hung docker ps (list bound 2s)", el)
	}
	logs := f.logText()
	if !strings.Contains(logs, "attempt 1 failed (exit 1)") || !strings.Contains(logs, "did not answer the container list within 2s") {
		t.Errorf("the failure is not stated:\n%s", logs)
	}
	if strings.Contains(strings.Join(f.argv(t), "\n"), "docker start") {
		t.Errorf("something was started")
	}
	assertLockFree(t)
}

// The overall deadline stops a run that the per-call bounds did not (here the
// list bound is longer than the overall one): the shell is killed,
// the lock released, and the log says so (no retry, no silent success).
func TestBootRestoreBoundedOverallDeadlineKillsTheRunAndReleasesTheLock(t *testing.T) {
	f := newBootFixture(t)
	f.hang(t, "ps.ps")
	bootListBound = 30 * time.Second
	bootOverall = 2 * time.Second
	t0 := time.Now()
	f.e.BootRestore(context.Background())
	if el := time.Since(t0); el > 8*time.Second {
		t.Fatalf("took %s with an overall deadline of 2s", el)
	}
	logs := f.logText()
	if !strings.Contains(logs, "BOOT-RESTORE WARN: the run did not finish within 2s and was stopped") || strings.Contains(logs, "boot-restore: done") {
		t.Errorf("log: %s", logs)
	}
	assertLockFree(t)
}

// The namespace-restore script runs under the same lock; a hang there is cut
// at its bound and the pass still reports.
func TestBootRestoreBoundedHungNamespaceRestoreIsCutOff(t *testing.T) {
	f := newBootFixture(t)
	if err := os.WriteFile(filepath.Join(f.e.Root, "scripts", "noo-netns-restore.sh"), []byte("exec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	f.e.BootRestore(context.Background())
	if el := time.Since(t0); el > 8*time.Second {
		t.Fatalf("took %s with a hung namespace restore (bound 1s)", el)
	}
	if !strings.Contains(f.logText(), "the namespace restore reported a problem") {
		t.Errorf("log: %s", f.logText())
	}
	assertLockFree(t)
}
