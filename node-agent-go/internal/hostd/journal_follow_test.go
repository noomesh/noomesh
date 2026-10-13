// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeJournal substitutes journalctl: it emits canned NDJSON lines and then
// blocks until the context ends (a real follower never returns). argv is
// recorded so a test can assert the cursor/unit arguments.
type fakeJournal struct {
	lines []string
	argv  [][]string
}

func (f *fakeJournal) start(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
	f.argv = append(f.argv, args)
	pr, pw := io.Pipe()
	go func() {
		for _, l := range f.lines {
			_, _ = io.WriteString(pw, l+"\n")
		}
		<-ctx.Done()
		_ = pw.Close()
	}()
	return pr, func() error { return nil }, nil
}

func journalEngine(t *testing.T, fj *fakeJournal) *Engine {
	t.Helper()
	orig := startJournalctl
	startJournalctl = fj.start
	t.Cleanup(func() { startJournalctl = orig })
	return &Engine{Mode: ModeWorker, Spool: t.TempDir(), Runner: &fakeRunner{rc: map[string]int{}}, Logf: t.Logf}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The allowlist is the whole contract: an op that followed any unit the
// caller named would be "read any journal on the box".
func TestJournalFollowRefusesANonAllowlistedUnit(t *testing.T) {
	fj := &fakeJournal{}
	e := journalEngine(t, fj)
	r := queue(t, e, "jf1", Command{Op: "journal-follow", Service: "noo-node-agent",
		Args: []string{"units=noo-hostd,sshd"}})
	if r.OK || r.RC == 0 {
		t.Fatalf("a non-allowlisted unit was accepted: %+v", r)
	}
	if !strings.Contains(r.Stderr, `"sshd"`) {
		t.Fatalf("refusal must name the unit: %q", r.Stderr)
	}
	if len(fj.argv) != 0 {
		t.Fatalf("journalctl must not be started on a refused request: %v", fj.argv)
	}
	if e.journalState() != nil {
		t.Fatal("a refused request must leave no follower behind")
	}
}

func TestJournalFollowDefaultsToTheWholeAllowlist(t *testing.T) {
	units, err := parseFollowUnits(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "noo-fetch", "noo-harness", "noo-hostd", "noo-node-agent", "tailscaled"}
	if strings.Join(units, ",") != strings.Join(want, ",") {
		t.Fatalf("default units = %v, want %v", units, want)
	}
	// Shipped, not readable over the rail: the host daemons stay out of unit-logs.
	for _, u := range []string{"docker", "tailscaled"} {
		if unitLogUnits[u] {
			t.Errorf("%q is followed for shipping but must not be readable through unit-logs", u)
		}
	}
	// unit-logs and journal-follow must agree: every unit-logs unit is followable.
	for u := range unitLogUnits {
		if !journalFollowUnits[u] {
			t.Errorf("unit-logs allows %q but journal-follow does not", u)
		}
	}
}

// Lines land in the spool file, the cursor is persisted, the heartbeat
// carries the live state, and a restart resumes AFTER the persisted cursor.
func TestJournalFollowWritesTheSpoolFileAndPersistsTheCursor(t *testing.T) {
	fj := &fakeJournal{lines: []string{
		`{"__CURSOR":"s=aa;i=1","MESSAGE":"one","_SYSTEMD_UNIT":"noo-hostd.service","__REALTIME_TIMESTAMP":"1700000000000000"}`,
		`{"__CURSOR":"s=aa;i=2","MESSAGE":"two","_SYSTEMD_UNIT":"docker.service","__REALTIME_TIMESTAMP":"1700000001000000"}`,
	}}
	e := journalEngine(t, fj)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Command{Op: "journal-follow", Service: "noo-node-agent", Args: []string{"units=noo-hostd,docker"}}
	rc, stderr := opJournalFollow(ctx, e, "jf2", c)
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, stderr)
	}
	r := readResult(t, e.Spool, "jf2")
	if r.Status != "running" || !r.OK {
		t.Fatalf("detached op must report running: %+v", r)
	}

	follow := filepath.Join(e.Spool, JournalFollowFile)
	waitFor(t, "both lines in the follow file", func() bool {
		b, _ := os.ReadFile(follow)
		return strings.Count(string(b), "\n") == 2
	})
	b, _ := os.ReadFile(follow)
	if !strings.Contains(string(b), `"MESSAGE":"two"`) {
		t.Fatalf("follow file lacks the journal lines: %q", b)
	}
	st := e.journalState()
	if st == nil || !st.Running || strings.Join(st.Units, ",") != "docker,noo-hostd" {
		t.Fatalf("heartbeat state = %+v", st)
	}
	if len(fj.argv) != 1 || !strings.Contains(strings.Join(fj.argv[0], " "), "--lines=0") {
		t.Fatalf("first start must begin at now (--lines=0), got %v", fj.argv)
	}
	for _, u := range []string{"--unit=docker", "--unit=noo-hostd"} {
		if !strings.Contains(strings.Join(fj.argv[0], " "), u) {
			t.Fatalf("argv lacks %s: %v", u, fj.argv[0])
		}
	}

	// A second request while running is idempotent: done, not a second child.
	r2 := queue(t, e, "jf3", Command{Op: "journal-follow", Service: "noo-node-agent"})
	if !r2.OK || r2.Status != "done" || !strings.Contains(r2.Stderr, "already running") {
		t.Fatalf("second request = %+v", r2)
	}
	if len(fj.argv) != 1 {
		t.Fatalf("a second journalctl was started: %v", fj.argv)
	}

	// Stop the child: the cursor is flushed on exit and the state says so.
	cancel()
	waitFor(t, "cursor file", func() bool {
		c, err := os.ReadFile(filepath.Join(e.Spool, JournalCursorFile))
		return err == nil && strings.TrimSpace(string(c)) == "s=aa;i=2"
	})
	waitFor(t, "follower to stop", func() bool { st := e.journalState(); return st != nil && !st.Running })

	// A fresh daemon (new Engine, same spool) resumes after the cursor.
	fj2 := &fakeJournal{}
	e2 := journalEngine(t, fj2)
	e2.Spool = e.Spool
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if rc, stderr := opJournalFollow(ctx2, e2, "jf4", c); rc != 0 {
		t.Fatalf("restart rc=%d %s", rc, stderr)
	}
	waitFor(t, "second start", func() bool { return len(fj2.argv) == 1 })
	joined := strings.Join(fj2.argv[0], " ")
	if !strings.Contains(joined, "--after-cursor=s=aa;i=2") || strings.Contains(joined, "--lines=0") {
		t.Fatalf("restart must resume after the persisted cursor: %v", fj2.argv[0])
	}
}

// An ancient cursor must not replay days of journal into the log store.
func TestJournalFollowIgnoresAStaleCursor(t *testing.T) {
	e := journalEngine(t, &fakeJournal{})
	p := filepath.Join(e.Spool, JournalCursorFile)
	if err := os.WriteFile(p, []byte("s=old;i=9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * journalCursorMaxAge)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if c := e.readCursor(); c != "" {
		t.Fatalf("stale cursor %q was accepted", c)
	}
}

// The spool file is bounded: past the cap it rotates to .1 and the previous
// .1 is gone — two files, never more.
func TestRotatingWriterKeepsTwoFilesAtMost(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "journal.follow")
	w, err := newRotatingWriter(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 50; i++ {
		if err := w.WriteLine([]byte(fmt.Sprintf("line-%02d-%s", i, strings.Repeat("x", 20)))); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected exactly journal.follow and journal.follow.1, got %v", names)
	}
	for _, f := range []string{p, p + ".1"} {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > 100 {
			t.Fatalf("%s is %d bytes, over the 100-byte cap", f, st.Size())
		}
	}
	// The newest line is in the live file, in order.
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "line-49-") {
		t.Fatalf("live file lacks the newest line: %q", b)
	}
}
