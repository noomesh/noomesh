// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build unix

package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Followup i515: noo-hostd runs as root in a spool directory the (Mac) user
// owns. Every name hostd writes must be safe against a symlink planted there,
// and every user-written file hostd reads must never be followed.

const canaryBody = "CANARY-do-not-touch\n"

// plantCanary makes a canary file in a directory OUTSIDE the spool.
func plantCanary(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertCanary(t *testing.T, p, want string) {
	t.Helper()
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canary was written through a symlink: %q (want %q)", got, want)
	}
}

// The implementation guarantee, asserted exactly: a symlink at a name hostd
// writes (temp OR final) is never written through; the write SUCCEEDS and the
// name afterwards is a regular file holding hostd's content (the symlink
// itself was replaced). The canary is untouched.
func TestWritesNeverFollowPlantedSymlinks(t *testing.T) {
	writers := map[string]struct {
		final string
		write func(e *Engine) error
	}{
		"heartbeat": {HeartbeatFile, func(e *Engine) error {
			return writeJSONAtomic(filepath.Join(e.Spool, HeartbeatFile), Heartbeat{PID: 1})
		}},
		"result": {"job1" + resultSuffix, func(e *Engine) error {
			return WriteResult(e.Spool, "job1", Result{Op: "restart", RC: 0})
		}},
		"command": {"job2" + cmdSuffix, func(e *Engine) error {
			return WriteCommand(e.Spool, "job2", Command{Op: "restart", Service: "gateway"})
		}},
		"alert": {"UNHEALTHY-job3.alert", func(e *Engine) error {
			return spoolWriteFile(e.Spool, "UNHEALTHY-job3.alert", []byte("x"), 0o644)
		}},
		"logout": {"job4" + LogOutSuffix, func(e *Engine) error {
			return spoolWriteFile(e.Spool, "job4"+LogOutSuffix, []byte("x"), 0o644)
		}},
		"cursor": {JournalCursorFile, func(e *Engine) error {
			e.writeCursor("s=abc")
			return nil
		}},
	}
	for name, w := range writers {
		for _, where := range []string{"tmp", "final"} {
			t.Run(name+"/"+where, func(t *testing.T) {
				e, _ := testEngine(t)
				canary := plantCanary(t, canaryBody)
				planted := w.final
				if where == "tmp" {
					planted = "." + w.final + ".tmp"
				}
				if err := os.Symlink(canary, filepath.Join(e.Spool, planted)); err != nil {
					t.Fatal(err)
				}
				if err := w.write(e); err != nil {
					t.Fatalf("write should replace the symlink and succeed: %v", err)
				}
				assertCanary(t, canary, canaryBody)
				st, err := os.Lstat(filepath.Join(e.Spool, w.final))
				if err != nil {
					t.Fatal(err)
				}
				if !st.Mode().IsRegular() {
					t.Fatalf("%s is %v after the write, want a regular file (symlink replaced)", w.final, st.Mode())
				}
				if where == "tmp" {
					if _, err := os.Lstat(filepath.Join(e.Spool, planted)); !os.IsNotExist(err) {
						t.Fatalf("the temp name must be gone after the rename: %v", err)
					}
				}
			})
		}
	}
}

// The heartbeat goes through the real publisher, not just the helper.
func TestHeartbeatPublisherDoesNotFollowSymlinks(t *testing.T) {
	e, _ := testEngine(t)
	canary := plantCanary(t, canaryBody)
	for _, n := range []string{"." + HeartbeatFile + ".tmp", HeartbeatFile} {
		if err := os.Symlink(canary, filepath.Join(e.Spool, n)); err != nil {
			t.Fatal(err)
		}
	}
	e.writeHeartbeat(stamp(), time.Second)
	assertCanary(t, canary, canaryBody)
	hb, err := ReadHeartbeat(e.Spool)
	if err != nil || hb.PID != os.Getpid() {
		t.Fatalf("agent side must still read the heartbeat: %v %+v", err, hb)
	}
}

// Append-mode opens (the stack-rebuild log, the journal-follow file) refuse a
// symlink rather than writing through it.
func TestAppendOpensRefuseSymlinks(t *testing.T) {
	e, _ := testEngine(t)
	canary := plantCanary(t, canaryBody)
	if err := os.Symlink(canary, filepath.Join(e.Spool, "x.rebuild.log")); err != nil {
		t.Fatal(err)
	}
	if f, err := spoolOpenAppend(e.Spool, "x.rebuild.log"); err == nil {
		f.Close()
		t.Fatal("append open followed a symlink")
	}
	if err := os.Symlink(canary, filepath.Join(e.Spool, JournalFollowFile)); err != nil {
		t.Fatal(err)
	}
	if w, err := newRotatingWriter(filepath.Join(e.Spool, JournalFollowFile), 100); err == nil {
		w.Close()
		t.Fatal("rotating writer followed a symlink")
	}
	assertCanary(t, canary, canaryBody)
}

// A planted symlink at the journal cursor is not read either.
func TestCursorReadDoesNotFollowSymlink(t *testing.T) {
	e, _ := testEngine(t)
	canary := plantCanary(t, "s=leaked\n")
	if err := os.Symlink(canary, filepath.Join(e.Spool, JournalCursorFile)); err != nil {
		t.Fatal(err)
	}
	if c := e.readCursor(); c != "" {
		t.Fatalf("cursor read followed a symlink: %q", c)
	}
}

// ── reads of user-written command files ────────────────────────────────────

func validCommandJSON(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(Command{Op: "restart", Service: "gateway"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Each hostile command entry is skipped: nothing runs, the target is not read,
// and the scan does not block. A control (a plain regular command) proves the
// harness would have run it.
func TestHostileCommandEntriesAreSkipped(t *testing.T) {
	cmdFile := func(e *Engine) string { return filepath.Join(e.Spool, "evil.cmd.json") }
	cases := map[string]func(t *testing.T, e *Engine) (canary string){
		"symlink to a valid command": func(t *testing.T, e *Engine) string {
			c := plantCanary(t, string(validCommandJSON(t)))
			if err := os.Symlink(c, cmdFile(e)); err != nil {
				t.Fatal(err)
			}
			return c
		},
		"fifo": func(t *testing.T, e *Engine) string {
			if err := syscall.Mkfifo(cmdFile(e), 0o644); err != nil {
				t.Fatal(err)
			}
			return ""
		},
		"oversize regular file": func(t *testing.T, e *Engine) string {
			// A valid command followed by padding past the cap.
			pad := bytes.Repeat([]byte(" "), maxSpoolCommandBytes+1)
			if err := os.WriteFile(cmdFile(e), append(validCommandJSON(t), pad...), 0o644); err != nil {
				t.Fatal(err)
			}
			return ""
		},
		"directory": func(t *testing.T, e *Engine) string {
			if err := os.Mkdir(cmdFile(e), 0o755); err != nil {
				t.Fatal(err)
			}
			return ""
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			e, fr := testEngine(t)
			var logs []string
			e.Logf = func(f string, a ...any) { logs = append(logs, f) }
			canary := plant(t, e)

			done := make(chan struct{})
			go func() { e.ScanOnce(context.Background()); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("ScanOnce blocked on a hostile entry")
			}

			if len(fr.calls) != 0 {
				t.Fatalf("a hostile command entry was executed: %v", fr.joined())
			}
			if r := readResult(t, e.Spool, "evil"); r.OK || r.Stderr != "unreadable" {
				t.Fatalf("hostile entry must be rejected as unreadable, got %+v", r)
			}
			if !strings.Contains(strings.Join(logs, "\n"), "REJECT") {
				t.Fatalf("the skip must be logged: %v", logs)
			}
			if canary != "" {
				// Not read, not modified; its (valid) command never ran.
				if got, _ := os.ReadFile(canary); string(got) != string(validCommandJSON(t)) {
					t.Fatalf("canary changed: %q", got)
				}
			}
		})
	}

	t.Run("control: a regular command does run", func(t *testing.T) {
		e, fr := testEngine(t)
		queue(t, e, "evil", Command{Op: "restart", Service: "gateway"})
		if len(fr.calls) == 0 {
			t.Fatal("control command did not run; the skip assertions above prove nothing")
		}
	})
}

// A name that does not match the producers' pattern is ignored outright.
func TestScanIgnoresOddlyNamedEntries(t *testing.T) {
	e, fr := testEngine(t)
	for _, n := range []string{"-rf.cmd.json", ".hidden.cmd.json", "a b.cmd.json", "a$(x).cmd.json"} {
		if err := os.WriteFile(filepath.Join(e.Spool, n), validCommandJSON(t), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.ScanOnce(context.Background())
	if len(fr.calls) != 0 {
		t.Fatalf("oddly named entries ran: %v", fr.joined())
	}
}

// ── the spool directory itself ─────────────────────────────────────────────

func TestSpoolDirSymlinkIsRefused(t *testing.T) {
	e, fr := testEngine(t)
	// The real directory holds a valid command; the "spool" is a symlink to it.
	real := e.Spool
	if err := os.WriteFile(filepath.Join(real, "a.cmd.json"), validCommandJSON(t), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "spool-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	e.Spool = link

	if _, err := openSpoolDir(link); err == nil {
		t.Fatal("openSpoolDir followed a symlinked spool")
	}
	if err := WriteResult(link, "r", Result{}); err == nil {
		t.Fatal("WriteResult wrote through a symlinked spool")
	}
	if err := WriteCommand(link, "c", Command{Op: "restart", Service: "gateway"}); err == nil {
		t.Fatal("WriteCommand wrote through a symlinked spool")
	}
	e.writeHeartbeat(stamp(), time.Second)
	e.ScanOnce(context.Background())
	if len(fr.calls) != 0 {
		t.Fatalf("a symlinked spool was scanned: %v", fr.joined())
	}
	entries, _ := os.ReadDir(real)
	for _, en := range entries {
		if en.Name() != "a.cmd.json" {
			t.Fatalf("hostd wrote %q into the symlink's target", en.Name())
		}
	}
}

func TestSpoolPathThatIsAFileIsRefused(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openSpoolDir(f); err == nil {
		t.Fatal("a regular file was accepted as the spool")
	}
}
