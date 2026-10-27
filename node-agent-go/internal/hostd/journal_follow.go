// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// journal-follow: the one privileged piece of fleet log shipping.
//
// The node agent ships logs to the controller (internal/logship) but cannot
// read the journal: it runs unprivileged, and the
// `systemd-journal` group would open EVERY journal on the box, not the five
// units we manage (the same objection api/hostlogs.go records for the
// one-shot `unit-logs` op). This daemon is already root with a closed op
// table and no network, so it runs `journalctl --follow --output=json` for
// the allowlisted units and writes the NDJSON to a file in the spool the
// agent already tails. hostd never dials anything; the agent never reads a
// journal. Each half keeps exactly the privilege it had.
//
// Long-lived, bounded, restart-safe:
//   - the child is restarted by this daemon if it exits; the op result stays
//     "running" and the heartbeat carries the live state, so the agent can
//     tell "follower dead" from "follower quiet" and re-issue the op after a
//     hostd restart;
//   - the output file rotates at journalFollowRotateBytes (one predecessor
//     kept), so a chatty unit cannot fill the spool;
//   - the last __CURSOR is persisted every few seconds and the restart
//     resumes after it (bounded by cursorMaxAge — an ancient cursor would
//     replay days of journal into Loki, so past that it starts at now).
package hostd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// JournalFollowFile is the NDJSON the follower writes under the spool;
	// JournalFollowFile+".1" is the one rotated predecessor.
	JournalFollowFile = "journal.follow"
	// JournalCursorFile persists the last __CURSOR seen.
	JournalCursorFile = "journal.cursor"
	// OpJournalFollow is the op name, shared with the agent (the consumer
	// matches it against the heartbeat's op list).
	OpJournalFollow = "journal-follow"

	journalFollowRotateBytes = 16 << 20 // 16 MiB per file, two files
	journalCursorFlush       = 5 * time.Second
	journalCursorMaxAge      = 24 * time.Hour
	journalMaxLine           = 1 << 20 // a journal MESSAGE can be large; cap the scanner
)

// journalFollowUnits is the CLOSED set of units the follower may attach to:
// the one-shot unit-logs allowlist plus two host daemons we do not manage but
// depend on — docker, whose journal is where "GPU fell off the bus" showed up
// first, and tailscaled, the node's only path to the controller. Without
// tailscaled's journal a boot that left it in "NoState"
// could only be diagnosed by someone at the node. Neither is added to
// unitLogUnits: shipping a daemon's log is not the same as letting the rail
// read any unit. Built from unitLogUnits so the two lists cannot drift apart.
var journalFollowUnits = func() map[string]bool {
	m := map[string]bool{"docker": true, "tailscaled": true}
	for u := range unitLogUnits {
		m[u] = true
	}
	return m
}()

// JournalFollowDefaultUnits is the sorted allowlist — what the follower
// attaches to when the caller names nothing.
func JournalFollowDefaultUnits() []string {
	out := make([]string, 0, len(journalFollowUnits))
	for u := range journalFollowUnits {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// JournalFollowState is published in the heartbeat while the follower is
// wanted. Running=false with a LastError is "the child keeps dying"; a nil
// state means no journal-follow op has been requested since this daemon
// started — the agent's cue to request one.
type JournalFollowState struct {
	Running   bool     `json:"running"`
	Units     []string `json:"units"`
	File      string   `json:"file"`
	Since     string   `json:"since"`
	Restarts  int      `json:"restarts"`
	LastError string   `json:"last_error,omitempty"`
}

// journalFollower is the live follower an Engine owns (at most one).
type journalFollower struct {
	mu    sync.Mutex
	state JournalFollowState
}

func (e *Engine) journalState() *JournalFollowState {
	e.journalMu.Lock()
	f := e.journal
	e.journalMu.Unlock()
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.state
	st.Units = append([]string(nil), f.state.Units...)
	return &st
}

// startJournalctl is the exec seam for the follower. It returns the
// child's stdout and a wait function; tests substitute a fake that emits
// canned NDJSON. A package var like nowUTC rather than a Runner method
// because the Runner interface is "run to completion and return the
// outcome" and this child never completes on purpose. The real exec lives
// in exec.go with the rest of the seam.
var startJournalctl = func(ctx context.Context, args []string) (io.ReadCloser, func() error, error) {
	return startStreaming(ctx, "journalctl", args...)
}

// parseFollowUnits reads `units=a,b,c` from the args, defaulting to the
// whole allowlist, and refuses anything outside it. Refusal, not
// filtering: silently dropping a unit means following a DIFFERENT set than
// the caller asked for and reporting success.
func parseFollowUnits(args []string) ([]string, error) {
	var units []string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "units="); ok {
			for _, u := range strings.Split(v, ",") {
				u = strings.TrimSpace(u)
				if u == "" {
					continue
				}
				if !journalFollowUnits[u] {
					return nil, fmt.Errorf("unit %q is not one this op may follow (allowed: %s)",
						u, strings.Join(JournalFollowDefaultUnits(), " "))
				}
				units = append(units, u)
			}
		}
	}
	if len(units) == 0 {
		units = JournalFollowDefaultUnits()
	}
	sort.Strings(units)
	return units, nil
}

// ParseFollowUnitsForTest exposes parseFollowUnits to the agent-side tests
// that assert both ends agree on what "no units" means.
func ParseFollowUnitsForTest(args []string) ([]string, error) { return parseFollowUnits(args) }

// opJournalFollow starts the follower (detached) or reports the one already
// running. Idempotent by design: the agent re-issues it whenever the
// heartbeat says nothing is following, and two followers writing one file
// would interleave lines.
func opJournalFollow(ctx context.Context, e *Engine, name string, c *Command) (int, string) {
	units, err := parseFollowUnits(c.Args)
	if err != nil {
		return 1, err.Error()
	}
	e.journalMu.Lock()
	if e.journal != nil {
		e.journalMu.Unlock()
		// Detached ops own their result; say "already running" as a
		// finished result so the caller's poll completes.
		e.writeResult(name, Result{
			OK: true, Op: c.Op, Service: c.Service, RC: 0,
			Stderr: "journal follower already running", Status: "done",
		})
		return 0, ""
	}
	f := &journalFollower{state: JournalFollowState{
		Units: units,
		File:  filepath.Join(e.Spool, JournalFollowFile),
		Since: stamp(),
	}}
	e.journal = f
	e.journalMu.Unlock()

	e.writeResult(name, Result{
		OK: true, Op: c.Op, Service: c.Service, RC: 0,
		Stderr: "detached; file=" + f.state.File, Status: "running",
	})
	e.logf("EXEC %s op=journal-follow units=%s detached file=%s", name, strings.Join(units, ","), f.state.File)
	go e.runJournalFollower(ctx, f)
	return 0, ""
}

// runJournalFollower keeps one journalctl child alive until ctx ends.
func (e *Engine) runJournalFollower(ctx context.Context, f *journalFollower) {
	backoff := 2 * time.Second
	for {
		err := e.followOnce(ctx, f)
		f.mu.Lock()
		f.state.Running = false
		if err != nil {
			f.state.LastError = err.Error()
		}
		f.state.Restarts++
		f.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		e.logf("WARN journal-follow child exited (%v); restarting in %s", err, backoff)
		if !sleepCtx(ctx, backoff) {
			return
		}
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

var cursorRe = regexp.MustCompile(`"__CURSOR"\s*:\s*"([^"]+)"`)

// followOnce runs one child to completion, streaming its NDJSON into the
// rotating spool file and persisting the cursor.
func (e *Engine) followOnce(ctx context.Context, f *journalFollower) error {
	args := []string{"--follow", "--output=json", "--no-pager"}
	if c := e.readCursor(); c != "" {
		args = append(args, "--after-cursor="+c)
	} else {
		args = append(args, "--lines=0")
	}
	f.mu.Lock()
	for _, u := range f.state.Units {
		args = append(args, "--unit="+u)
	}
	f.mu.Unlock()

	out, wait, err := startJournalctl(ctx, args)
	if err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}
	defer out.Close()

	w, err := newRotatingWriter(filepath.Join(e.Spool, JournalFollowFile), journalFollowRotateBytes)
	if err != nil {
		_ = wait()
		return fmt.Errorf("open follow file: %w", err)
	}
	defer w.Close()

	f.mu.Lock()
	f.state.Running = true
	f.state.LastError = ""
	f.mu.Unlock()

	var (
		lastCursor string
		lastFlush  = time.Now()
	)
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), journalMaxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if err := w.WriteLine(line); err != nil {
			e.logf("WARN journal-follow write: %v", err)
		}
		if m := cursorRe.FindSubmatch(line); m != nil {
			lastCursor = string(m[1])
		}
		if lastCursor != "" && time.Since(lastFlush) >= journalCursorFlush {
			e.writeCursor(lastCursor)
			lastFlush = time.Now()
		}
	}
	if lastCursor != "" {
		e.writeCursor(lastCursor)
	}
	werr := wait()
	if serr := sc.Err(); serr != nil && ctx.Err() == nil {
		return fmt.Errorf("read journalctl: %w", serr)
	}
	if werr != nil && ctx.Err() == nil {
		return fmt.Errorf("journalctl: %w", werr)
	}
	return werr
}

func (e *Engine) cursorPath() string { return filepath.Join(e.Spool, JournalCursorFile) }

// readCursor returns the persisted cursor, or "" when there is none or it
// is too old to resume from safely.
func (e *Engine) readCursor() string {
	st, err := os.Stat(e.cursorPath())
	if err != nil || time.Since(st.ModTime()) > journalCursorMaxAge {
		return ""
	}
	b, err := os.ReadFile(e.cursorPath())
	if err != nil {
		return ""
	}
	c := strings.TrimSpace(string(b))
	if strings.ContainsAny(c, " \n\t") {
		return ""
	}
	return c
}

func (e *Engine) writeCursor(c string) {
	tmp := e.cursorPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(c+"\n"), 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, e.cursorPath())
}

// rotatingWriter appends lines to path and, past cap bytes, renames it to
// path+".1" (replacing the previous one) and starts a fresh file. Two files
// at most — the bound is the point.
type rotatingWriter struct {
	path string
	cap  int64
	f    *os.File
	size int64
}

func newRotatingWriter(path string, capBytes int64) (*rotatingWriter, error) {
	w := &rotatingWriter{path: path, cap: capBytes}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

func (w *rotatingWriter) WriteLine(line []byte) error {
	if w.size > 0 && w.size+int64(len(line))+1 > w.cap {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	n, err := w.f.Write(append(append([]byte(nil), line...), '\n'))
	w.size += int64(n)
	return err
}

func (w *rotatingWriter) rotate() error {
	_ = w.f.Close()
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return w.open()
}

func (w *rotatingWriter) Close() error {
	if w.f == nil {
		return nil
	}
	return w.f.Close()
}
