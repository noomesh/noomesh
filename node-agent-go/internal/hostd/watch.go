// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/version"
)

// DefaultPollInterval is the spool scan cadence.
//
// A plain poll, with no inotify. The bash watcher used inotifywait "for
// responsiveness" with a poll fallback, which meant two code paths and an
// extra package to install for a saving measured against a 2-second ceiling —
// on operations that take between 5 seconds and 20 minutes. The poll is the
// whole mechanism here, and there is no inotifywait to be missing.
const DefaultPollInterval = 2 * time.Second

// Run is the daemon: publish a heartbeat, drain the spool, repeat.
//
// Returns when ctx is cancelled. Ops execute inline (one at a time) except
// detached ones, deliberately: two concurrent recreates of the same service is
// the interleave the compose lock exists to prevent, and serialising here
// means the lock is a backstop rather than the primary defence.
func (e *Engine) Run(ctx context.Context, poll, heartbeat time.Duration) error {
	if poll <= 0 {
		poll = DefaultPollInterval
	}
	if heartbeat <= 0 {
		heartbeat = DefaultHeartbeatInterval
	}

	// Any *.rebuild.running marker present at startup is stale: a detached
	// rebuild dies with the daemon (same process tree), so nothing it marked
	// is still running. Left behind, they reject every future rebuild as
	// "already running" — a permanent wedge from a single unclean restart.
	if markers, _ := filepath.Glob(filepath.Join(e.Spool, "*.rebuild.running")); len(markers) > 0 {
		for _, m := range markers {
			_ = os.Remove(m)
		}
		e.logf("cleared %d stale rebuild marker(s) from a previous run", len(markers))
	}

	started := stamp()
	e.logf("noo-hostd %s started; project_root=%s spool=%s port=%s ops=%v",
		version.String(), e.Root, e.Spool, e.GatewayPort, SupportedOpsFor(e.Mode))

	e.writeHeartbeat(started, heartbeat)
	// Reboot path for the RAM-backed secret files (boot.go).
	if e.RestoreOnBoot {
		go e.BootRestore(ctx)
	}
	hbTicker := time.NewTicker(heartbeat)
	defer hbTicker.Stop()
	pollTicker := time.NewTicker(poll)
	defer pollTicker.Stop()

	for {
		e.ScanOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-hbTicker.C:
			e.writeHeartbeat(started, heartbeat)
		case <-pollTicker.C:
		}
	}
}

// writeHeartbeat publishes liveness and, crucially, the op list THIS BINARY
// implements — see the Heartbeat doc comment for why the running binary's list
// rather than the source tree's is the load-bearing part.
func (e *Engine) writeHeartbeat(started string, interval time.Duration) {
	hb := Heartbeat{
		PID:       os.Getpid(),
		Version:   version.String(),
		StartedAt: started,
		TS:        stamp(),
		Interval:  int(interval.Seconds()),
		Ops:       SupportedOpsFor(e.Mode),
		Spool:     e.Spool,
		Root:      e.Root,
		Features:  FeaturesFor(e.Mode),
		Host:      e.currentHostFacts(context.Background()),
		// Live, per beat: a follower that died with its child must read
		// as not running on the very next heartbeat.
		JournalFollow: e.journalState(),
	}
	if err := writeJSONAtomic(filepath.Join(e.Spool, HeartbeatFile), hb); err != nil {
		// Log, do not exit. A spool that briefly cannot be written (the bind
		// mount remounting during a compose operation) should not take the
		// daemon down — the staleness check on the reader side already
		// reports this correctly as "not alive".
		e.logf("WARN cannot write heartbeat: %v", err)
	}
}

// ScanOnce claims and processes every pending command. Exported for tests and
// for a `noo-hostd drain` one-shot.
func (e *Engine) ScanOnce(ctx context.Context) {
	matches, err := filepath.Glob(filepath.Join(e.Spool, "*"+cmdSuffix))
	if err != nil {
		return
	}
	// Sorted so the time-ordered filenames the producers mint (<nanos>-<hex>)
	// execute in the order they were requested. Glob's order is unspecified;
	// a restart-then-recreate pair running backwards leaves the container down.
	sort.Strings(matches)
	for _, f := range matches {
		select {
		case <-ctx.Done():
			return
		default:
		}
		claimed, err := claim(f)
		if err != nil {
			continue // another iteration got it, or it vanished
		}
		e.processCommand(ctx, claimed)
	}
}

// processCommand executes one claimed command file and writes its result.
func (e *Engine) processCommand(ctx context.Context, path string) {
	name := commandName(path)
	defer os.Remove(path)

	raw, err := os.ReadFile(path)
	if err != nil {
		e.logf("REJECT %s: cannot read claimed command: %v", name, err)
		_ = WriteResult(e.Spool, name, Result{Op: "unknown", RC: 1, Stderr: "unreadable"})
		return
	}

	cmd, err := ParseCommand(raw)
	if err != nil {
		// Historically this also fired when the gateway (uid 65532) wrote a
		// file the watcher (uid 1000) could not read — "not valid JSON" was
		// the symptom of a PERMISSION problem, which sent more than one
		// investigation the wrong way. Reading and parsing are separate steps
		// above so the two now report differently.
		e.logf("REJECT %s: not valid JSON", name)
		_ = WriteResult(e.Spool, name, Result{Op: "unknown", RC: 1, Stderr: "invalid json"})
		return
	}

	op, known := LookupOpFor(e.Mode, cmd.Op)
	if !known {
		e.logf("REJECT %s: invalid op %q", name, cmd.Op)
		_ = WriteResult(e.Spool, name, Result{Op: cmd.Op, Service: cmd.Service, RC: 1, Stderr: "invalid op"})
		return
	}
	if err := ValidateService(cmd.Service); err != nil {
		e.logf("REJECT %s: invalid service %q", name, cmd.Service)
		_ = WriteResult(e.Spool, name, Result{Op: cmd.Op, Service: cmd.Service, RC: 1, Stderr: "invalid service"})
		return
	}
	if cmd.Rollback != nil && cmd.Rollback.SHA != "" {
		if err := ValidateSHA(cmd.Rollback.SHA); err != nil {
			e.logf("REJECT %s: invalid rollback sha %q", name, cmd.Rollback.SHA)
			_ = WriteResult(e.Spool, name, Result{Op: cmd.Op, Service: cmd.Service, RC: 1, Stderr: "invalid rollback sha"})
			return
		}
	}

	e.logf("EXEC %s op=%s service=%s health_check=%t", name, cmd.Op, cmd.Service, cmd.HealthCheck)
	began := time.Now()
	rc, stderr := op.Run(ctx, e, name, cmd)
	took := time.Since(began).Milliseconds()

	if op.Detached && rc == 0 {
		// The detached job owns this op's result lifecycle from here.
		return
	}
	if rc == 0 {
		e.logf("OK   %s op=%s service=%s rc=0", name, cmd.Op, cmd.Service)
	} else {
		e.logf("FAIL %s op=%s service=%s rc=%d stderr=%s", name, cmd.Op, cmd.Service, rc, truncateLog(stderr))
	}
	res := Result{
		OK: rc == 0, Op: cmd.Op, Service: cmd.Service, RC: rc, Stderr: stderr,
		DurationMS: took,
	}
	if cmd.Op == "backup" {
		res = annotateBackup(res)
	}
	_ = WriteResult(e.Spool, name, res)
}

func truncateLog(s string) string {
	if len(s) <= 300 {
		return s
	}
	return s[:300]
}

// runStreaming runs a command with stdout+stderr teed to w, returning its exit
// code. Used for the detached rebuild, whose log IS the operator's view.
func runStreaming(ctx context.Context, dir string, w io.Writer, name string, args ...string) int {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdout = w
	cmd.Stderr = w
	return exitCode(cmd.Run())
}
