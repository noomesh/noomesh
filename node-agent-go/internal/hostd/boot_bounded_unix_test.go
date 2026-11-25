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
// Time limits are generous (the fake sleeps 120 s when it hangs, the tests
// allow 45 s) so a loaded host does not flip them and an unbounded call does.
const testTimeLimit = 45 * time.Second

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

// callsEnding counts recorded docker calls whose last argument is id.
func (f *bootFixture) callsEnding(t *testing.T, id string) int {
	n := 0
	for _, l := range f.argv(t) {
		if strings.HasSuffix(l, " "+id) {
			n++
		}
	}
	return n
}

func (f *bootFixture) startsOf(t *testing.T, id string) int {
	n := 0
	for _, l := range f.argv(t) {
		if l == "docker start "+id {
			n++
		}
	}
	return n
}

// hang makes a fake call sleep: key "<kind>.<id>" (kinds ps, mounts, running,
// start); count 0 = every call, n = only the first n calls.
func (f *bootFixture) hang(t *testing.T, key string, count int) {
	t.Helper()
	body := ""
	if count > 0 {
		body = fmt.Sprint(count)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "hang."+key), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fail makes a fake call exit 1 at once: key "<kind>.<id>", count 0 = every
// call, n = only the first n calls.
func (f *bootFixture) fail(t *testing.T, key string, count int) {
	t.Helper()
	body := ""
	if count > 0 {
		body = fmt.Sprint(count)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "failn."+key), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// unbound makes the container's mounts not include the secret directory, so
// the script has to read its labels (the meta inspect).
func (f *bootFixture) unbound(t *testing.T, id string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "unbound."+id), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// down makes the Running check say false until a start of id is answered.
func (f *bootFixture) down(t *testing.T, id string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "down."+id), nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeTimeout installs a `timeout` ahead of the real one on PATH.
func (f *bootFixture) fakeTimeout(t *testing.T, body string) {
	t.Helper()
	real, err := exec.LookPath("timeout")
	if err != nil {
		t.Skip("no timeout(1) on this host")
	}
	script := "#!/bin/bash\nREAL=" + real + "\n" + body
	if err := os.WriteFile(filepath.Join(f.dir, "timeout"), []byte(script), 0o755); err != nil {
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
if [ -e "$d/failn.$kind.$id" ]; then
  n="$(cat "$d/failn.$kind.$id")"
  c=$(( $(cat "$d/fcnt.$kind.$id" 2>/dev/null || echo 0) + 1 )); echo $c > "$d/fcnt.$kind.$id"
  if [ -z "$n" ] || [ "$c" -le "$n" ]; then echo "Cannot connect to the Docker daemon" >&2; exit 1; fi
fi
if [ -e "$d/hang.$kind.$id" ]; then
  n="$(cat "$d/hang.$kind.$id")"
  if [ -z "$n" ]; then exec sleep 120; fi
  c=$(( $(cat "$d/cnt.$kind.$id" 2>/dev/null || echo 0) + 1 )); echo $c > "$d/cnt.$kind.$id"
  [ "$c" -le "$n" ] && exec sleep 120
fi
case "$sub" in
  ps) printf 'aaa\nbbb\nccc\n' ;;
  start) rm -f "$d/down.$id" ;;
  inspect)
    case "$*" in
      *Mounts*) if [ -e "$d/unbound.$id" ]; then echo /other/x; else echo "$(cat "$d/rundir")/x"; fi ;;
      *State.Running*) if [ -e "$d/down.$id" ]; then echo false; else echo true; fi ;;
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
	for _, tool := range []string{"bash", "timeout", "sleep", "grep", "cut", "sed", "awk", "sort", "tr", "head", "ls", "dirname", "cat", "mkdir", "touch", "printf", "echo", "true", "rm"} {
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
	ol, ot, ow, oi, os_, on, oo := bootListBound, bootListWindow, bootListWait, bootInspectBound, bootStartBound, bootNetnsBound, bootOverall
	t.Cleanup(func() {
		bootListBound, bootListWindow, bootListWait, bootInspectBound, bootStartBound, bootNetnsBound, bootOverall = ol, ot, ow, oi, os_, on, oo
	})
	bootListBound, bootListWindow, bootListWait = 2*time.Second, 20*time.Second, 1*time.Second
	bootInspectBound, bootStartBound, bootNetnsBound, bootOverall = 2*time.Second, 3*time.Second, 2*time.Second, 60*time.Second
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
	case <-time.After(5 * time.Second):
		t.Fatal("the compose lock is still held after boot-restore returned")
	}
}

func (f *bootFixture) run(t *testing.T) time.Duration {
	t.Helper()
	t0 := time.Now()
	f.e.BootRestore(context.Background())
	el := time.Since(t0)
	if el > testTimeLimit {
		t.Fatalf("boot-restore took %s (limit %s)", el, testTimeLimit)
	}
	return el
}

func normalArgv() []string {
	want := []string{"docker ps -aq --filter status=created --filter status=exited"}
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		want = append(want,
			"docker inspect -f {{range .Mounts}}{{println .Source}}{{end}} "+id,
			"docker start "+id,
			"docker inspect -f {{.State.Running}} "+id)
	}
	return want
}

// Docker answers normally: the same calls in the same order as before the
// bounds, with the same argv (timeout execs docker unchanged).
func TestBootRestoreBoundedNormalPathRecordsTheSameDockerCalls(t *testing.T) {
	f := newBootFixture(t)
	f.run(t)
	if got, want := strings.Join(f.argv(t), "\n"), strings.Join(normalArgv(), "\n"); got != want {
		t.Fatalf("docker calls changed:\n got %q\nwant %q", got, want)
	}
	if !strings.Contains(f.logText(), "boot-restore: done") || strings.Contains(f.logText(), "did not answer") {
		t.Fatalf("log: %s", f.logText())
	}
	assertLockFree(t)
}

// One container Docker never answers for is skipped and named, the rest are
// handled, and NOTHING more is done to the skipped one (the exact number of
// docker calls naming it is pinned, so a removed `continue` shows).
func TestBootRestoreBoundedSkipsAContainerDockerDoesNotAnswerFor(t *testing.T) {
	for _, tc := range []struct {
		name, key, call string
		down            bool
		calls, starts   int
		started         string
	}{
		{"mounts inspect", "mounts.bbb", "docker inspect", false, 1, 0, "started 2"},
		{"start (and not running)", "start.bbb", "docker start", true, 5, 2, "started 2"},
		{"running check", "running.bbb", "docker inspect", false, 3, 1, "started 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBootFixture(t)
			f.hang(t, tc.key, 0)
			if tc.down {
				f.down(t, "bbb")
			}
			f.run(t)
			for _, id := range []string{"aaa", "ccc"} {
				if f.startsOf(t, id) != 1 || f.callsEnding(t, id) != 3 {
					t.Errorf("container %s was not handled exactly once:\n%s", id, strings.Join(f.argv(t), "\n"))
				}
			}
			if got := f.startsOf(t, "bbb"); got != tc.starts {
				t.Errorf("docker start bbb ran %d times, want %d", got, tc.starts)
			}
			if got := f.callsEnding(t, "bbb"); got != tc.calls {
				t.Errorf("docker calls naming bbb: %d, want %d:\n%s", got, tc.calls, strings.Join(f.argv(t), "\n"))
			}
			logs := f.logText()
			if !strings.Contains(logs, "Docker did not answer for container bbb within") || !strings.Contains(logs, "("+tc.call+"); it was left alone") {
				t.Errorf("the skipped container is not named:\n%s", logs)
			}
			if !strings.Contains(logs, tc.started+"; not handled (left alone): bbb") || strings.Contains(logs, "boot-restore: done") {
				t.Errorf("a skipped container must not be reported as a plain success:\n%s", logs)
			}
			assertLockFree(t)
		})
	}
}

// A start that only TIMES OUT but leaves the container running is a slow
// start: counted as started, noted, never called "left alone".
func TestBootRestoreBoundedSlowStartThatIsRunningCountsAsStarted(t *testing.T) {
	f := newBootFixture(t)
	f.hang(t, "start.bbb", 0) // bbb is not marked down: its Running check says true
	f.run(t)
	logs := f.logText()
	if !strings.Contains(logs, "container bbb was slow to start") || strings.Contains(logs, "left alone") || !strings.Contains(logs, "boot-restore: done") {
		t.Fatalf("log: %s", logs)
	}
	if !strings.Contains(logs, "started 3 container(s)") {
		t.Fatalf("the slow container is not counted: %s", logs)
	}
	if f.startsOf(t, "bbb") != 1 {
		t.Errorf("a running container was started again")
	}
	assertLockFree(t)
}

// A start that times out on a container that is NOT running gets one more
// bounded start; if that answers, it is started.
func TestBootRestoreBoundedSlowStartThatIsNotRunningIsStartedOnceMore(t *testing.T) {
	f := newBootFixture(t)
	f.hang(t, "start.bbb", 1) // the first start hangs, the second answers
	f.down(t, "bbb")
	f.run(t)
	logs := f.logText()
	if f.startsOf(t, "bbb") != 2 || strings.Contains(logs, "left alone") || !strings.Contains(logs, "started 3 container(s)") || !strings.Contains(logs, "boot-restore: done") {
		t.Fatalf("starts of bbb: %d; log: %s", f.startsOf(t, "bbb"), logs)
	}
	assertLockFree(t)
}

// A list Docker does not answer is retried; one that answers on the third try
// starts the containers and reports done.
func TestBootRestoreBoundedListThatAnswersOnTheThirdTryStartsTheContainers(t *testing.T) {
	f := newBootFixture(t)
	f.hang(t, "ps.ps", 2)
	f.run(t)
	ps := 0
	for _, l := range f.argv(t) {
		if strings.HasPrefix(l, "docker ps ") {
			ps++
		}
	}
	if ps != 3 {
		t.Fatalf("docker ps ran %d times, want 3", ps)
	}
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		if f.startsOf(t, id) != 1 {
			t.Errorf("container %s was not started", id)
		}
	}
	if !strings.Contains(f.logText(), "boot-restore: done") || !strings.Contains(f.logText(), "try 2, ") {
		t.Fatalf("log: %s", f.logText())
	}
	assertLockFree(t)
}

// A list that never answers is a WARN, never "done": the secret files are
// already written, so a second pass would only say "nothing to do". Nothing is
// started, the caller does not retry, the lock is free.
func TestBootRestoreBoundedListThatNeverAnswersIsAWarnNotDone(t *testing.T) {
	f := newBootFixture(t)
	f.hang(t, "ps.ps", 0)
	bootListWindow = 5 * time.Second
	f.run(t)
	logs := f.logText()
	if !strings.Contains(logs, "BOOT-RESTORE WARN") || !strings.Contains(logs, "did not answer the container list") || !strings.Contains(logs, "NO container was started") {
		t.Errorf("the failure is not stated:\n%s", logs)
	}
	if strings.Contains(logs, "boot-restore: done") || strings.Contains(logs, "attempt 2") {
		t.Errorf("a list that never answered was reported as done or retried:\n%s", logs)
	}
	ps := 0
	for _, l := range f.argv(t) {
		if strings.Contains(l, " start ") {
			t.Errorf("something was started: %s", l)
		}
		if strings.HasPrefix(l, "docker ps ") {
			ps++
		}
	}
	if ps < 2 || ps > 4 {
		t.Errorf("docker ps ran %d times, want a few tries within the window", ps)
	}
	assertLockFree(t)
}

// The overall deadline stops a run that the per-call bounds did not (no usable
// timeout(1) here, so the calls are unbounded): the shell is killed, the lock
// released, and the log says so (no retry, no silent success).
func TestBootRestoreBoundedOverallDeadlineKillsTheRunAndReleasesTheLock(t *testing.T) {
	f := newBootFixture(t)
	f.fakeTimeout(t, "exit 125\n") // no per-call bound: only the backstop can end the run
	f.hang(t, "ps.ps", 0)
	bootOverall = 4 * time.Second
	f.run(t)
	logs := f.logText()
	if !strings.Contains(logs, "BOOT-RESTORE WARN: the run did not finish within 4s and was stopped") || strings.Contains(logs, "boot-restore: done") {
		t.Errorf("log: %s", logs)
	}
	assertLockFree(t)
}

// The namespace-restore pass runs under the same lock; a hang there is cut at
// its own bound and the pass still reports.
func TestBootRestoreBoundedHungNamespaceRestoreIsCutOff(t *testing.T) {
	f := newBootFixture(t)
	if err := os.WriteFile(filepath.Join(f.e.Root, "scripts", "noo-netns-restore.sh"), []byte("exec sleep 120\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.run(t)
	if !strings.Contains(f.logText(), "the namespace restore reported a problem") {
		t.Errorf("log: %s", f.logText())
	}
	assertLockFree(t)
}

// The pass's bound is capped by what is left of the script budget, so it ends
// before the overall deadline and no orphan can outlive the lock: here the
// pass's own bound is 100 s but the overall deadline is 24 s.
func TestBootRestoreBoundedNamespaceRestoreEndsBeforeTheOverallDeadline(t *testing.T) {
	f := newBootFixture(t)
	if err := os.WriteFile(filepath.Join(f.e.Root, "scripts", "noo-netns-restore.sh"), []byte("exec sleep 120\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bootNetnsBound = 100 * time.Second
	bootOverall = 24 * time.Second
	f.run(t)
	logs := f.logText()
	if strings.Contains(logs, "did not finish within") || !strings.Contains(logs, "the namespace restore reported a problem") {
		t.Errorf("the pass outlived the script budget:\n%s", logs)
	}
	assertLockFree(t)
}

// A timeout(1) without --foreground and -k (BusyBox) still bounds each call.
func TestBootRestoreBoundedBusyBoxTimeoutStillBoundsTheCalls(t *testing.T) {
	f := newBootFixture(t)
	f.fakeTimeout(t, `case "$1" in --foreground|-k|-*) exit 125 ;; esac
exec "$REAL" "$@"
`)
	f.hang(t, "mounts.bbb", 0)
	f.run(t)
	logs := f.logText()
	if !strings.Contains(logs, "Docker did not answer for container bbb") || strings.Contains(logs, "not usable") || f.startsOf(t, "bbb") != 0 || f.startsOf(t, "ccc") != 1 {
		t.Fatalf("log: %s", logs)
	}
	assertLockFree(t)
}

// A timeout(1) that works in no form: the calls run unbounded, said once, and
// the run is NOT "started 0" success: it behaves exactly as before.
func TestBootRestoreBoundedUnusableTimeoutFallsBackToUnboundedAndSaysSo(t *testing.T) {
	f := newBootFixture(t)
	f.fakeTimeout(t, "exit 125\n")
	f.run(t)
	if got, want := strings.Join(f.argv(t), "\n"), strings.Join(normalArgv(), "\n"); got != want {
		t.Fatalf("docker calls changed:\n got %q\nwant %q", got, want)
	}
	logs := f.logText()
	if strings.Count(logs, "timeout(1) is not usable here") != 1 || !strings.Contains(logs, "started 3 container(s)") || !strings.Contains(logs, "boot-restore: done") {
		t.Fatalf("log: %s", logs)
	}
	assertLockFree(t)
}

// A list that FAILS at once (dockerd not listening yet) is "Docker did not
// answer yet", not an empty list: it is retried, and once it answers the
// containers are started.
func TestBootRestoreBoundedListThatFailsFastIsRetriedThenStarts(t *testing.T) {
	f := newBootFixture(t)
	f.fail(t, "ps.ps", 2)
	f.run(t)
	logs := f.logText()
	if !strings.Contains(logs, "(exit 1, try 2") || !strings.Contains(logs, "started 3 container(s)") || !strings.Contains(logs, "boot-restore: done") {
		t.Fatalf("log: %s", logs)
	}
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		if f.startsOf(t, id) != 1 {
			t.Errorf("container %s was not started", id)
		}
	}
	assertLockFree(t)
}

// A list that always fails fast is a WARN naming it, never "started 0" done.
func TestBootRestoreBoundedListThatAlwaysFailsFastIsAWarnNotDone(t *testing.T) {
	f := newBootFixture(t)
	f.fail(t, "ps.ps", 0)
	bootListWindow = 4 * time.Second
	f.run(t)
	logs := f.logText()
	if !strings.Contains(logs, "BOOT-RESTORE WARN") || !strings.Contains(logs, "did not answer the container list (exit 1") || !strings.Contains(logs, "NO container was started") {
		t.Errorf("log: %s", logs)
	}
	if strings.Contains(logs, "boot-restore: done") || strings.Contains(logs, "started 0") {
		t.Errorf("a failing list was reported as done:\n%s", logs)
	}
	assertLockFree(t)
}

// The budget bounds every call, not only the entry to each container: a start
// reached near the budget is clamped, and the script ends ITSELF with its
// summary naming what was not handled (exit 4), not by the Go deadline.
func TestBootRestoreBoundedBudgetClampsALateStartAndTheScriptSummarisesItself(t *testing.T) {
	f := newBootFixture(t)
	f.hang(t, "start.aaa", 0)
	f.down(t, "aaa")
	bootStartBound = 100 * time.Second // far past the budget of 12 s
	bootOverall = 24 * time.Second     // script budget: 12 s
	f.run(t)
	logs := f.logText()
	if strings.Contains(logs, "did not finish within") {
		t.Fatalf("the Go deadline fired instead of the script's own summary:\n%s", logs)
	}
	if !strings.Contains(logs, "BOOT-RESTORE WARN") || !strings.Contains(logs, "not handled (left alone): aaa, bbb and the rest (out of time)") {
		t.Fatalf("the summary does not name what was left:\n%s", logs)
	}
	if f.startsOf(t, "bbb") != 0 || f.startsOf(t, "ccc") != 0 {
		t.Errorf("containers past the budget were started")
	}
	assertLockFree(t)
}

// A docker start that FAILS at once is a failed start (as before): not
// counted, not "did not answer"; the container is reported as still down.
func TestBootRestoreBoundedQuickFailingStartIsAFailedStartNotNoAnswer(t *testing.T) {
	f := newBootFixture(t)
	f.fail(t, "start.bbb", 0)
	f.down(t, "bbb")
	f.run(t)
	logs := f.logText()
	if strings.Contains(logs, "did not answer for container bbb") || !strings.Contains(logs, "started 2; still down: bbb") {
		t.Fatalf("log: %s", logs)
	}
	if f.startsOf(t, "bbb") != 1 {
		t.Errorf("a failed start was retried")
	}
	assertLockFree(t)
}

// The labels inspect (reached for a container whose mounts do not bind the
// secret directory) is bounded too: skipped, named, nothing else done to it.
func TestBootRestoreBoundedHungLabelsInspectSkipsTheContainer(t *testing.T) {
	f := newBootFixture(t)
	f.unbound(t, "bbb")
	f.hang(t, "inspect.bbb", 0)
	f.run(t)
	logs := f.logText()
	if !strings.Contains(logs, "Docker did not answer for container bbb within") || !strings.Contains(logs, "(docker inspect); it was left alone") {
		t.Fatalf("log: %s", logs)
	}
	if f.callsEnding(t, "bbb") != 2 || f.startsOf(t, "bbb") != 0 || f.startsOf(t, "ccc") != 1 {
		t.Errorf("calls naming bbb: %d, starts of bbb: %d:\n%s", f.callsEnding(t, "bbb"), f.startsOf(t, "bbb"), strings.Join(f.argv(t), "\n"))
	}
	assertLockFree(t)
}

// The production numbers are pinned: changing one is a decision, not a drift.
func TestBootRestoreBoundedProductionBoundsArePinned(t *testing.T) {
	if bootListBound != 20*time.Second || bootListWindow != 10*time.Minute || bootListWait != 15*time.Second ||
		bootInspectBound != 15*time.Second || bootStartBound != 180*time.Second || bootNetnsBound != 150*time.Second ||
		bootOverall != 25*time.Minute {
		t.Fatalf("bounds changed: list %s window %s wait %s inspect %s start %s netns %s overall %s",
			bootListBound, bootListWindow, bootListWait, bootInspectBound, bootStartBound, bootNetnsBound, bootOverall)
	}
	if got := scriptBudget(bootOverall); got != 1440 {
		t.Fatalf("script budget = %ds, want 1440", got)
	}
	// After the longest list wait the container pass still has its full time.
	if pass := scriptBudget(bootOverall) - secs(bootListWindow); pass < 840 {
		t.Fatalf("the container pass has only %ds after the list window", pass)
	}
}
