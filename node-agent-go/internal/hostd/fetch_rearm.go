// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// The Mac's bundle fetch job is the system LaunchDaemon net.noomesh.fetch
// (installed by `noo enroll`). When the CLI binary it runs is replaced by an
// update, launchd can refuse to spawn it (exit 78, "needs LWCR update") until
// the job is bootstrapped again, and nothing did that: the operator ran
// `noo enroll --resume`. The node agent runs as the node user and cannot touch
// the system domain; this daemon is root and can. The cause is inferred from
// one incident and has not been run on a real Mac.
//
// What this does, and nothing else: look at `launchctl print
// system/net.noomesh.fetch` (at most every fetchCheckEvery, and after each
// fetch kick), and
//   - not loaded, plist present  → bootstrap the existing plist, kickstart;
//   - loaded, not running, spawn refused, and still so on two more prints a few
//     seconds apart → bootout, wait out teardown, bootstrap the existing
//     plist, kickstart;
//   - anything else → nothing. A running job is never touched (that would abort
//     an apply). No plist or binary is ever written; no other job is touched.
// After a fetch kick the check runs only when the kick itself failed: a
// kick that worked leaves launchd mid-spawn, with the previous run's exit
// status still on display. Re-arms are rate limited and give up loudly (until this daemon restarts)
// after fetchGiveUpAfter consecutive failures. Linux has a systemd timer that
// re-fires by itself, so nothing here runs there.

const (
	fetchCheckEvery   = 10 * time.Minute
	fetchRearmEvery   = 30 * time.Minute
	fetchGiveUpAfter  = 3
	fetchSpawnRefused = 78 // EX_CONFIG, what launchd reports for a refused spawn
)

// Package vars so tests pin the OS, the plist and the bound without a Mac.
var (
	fetchRearmGOOS      = runtime.GOOS
	fetchLaunchctlLimit = 20 * time.Second
	// The gap between the confirming prints before a bootout; a package var so
	// tests need not sleep.
	fetchConfirmGap   = 5 * time.Second
	fetchConfirmSleep = func() { time.Sleep(fetchConfirmGap) }
	fetchKickGOOS     = runtime.GOOS
	fetchPlistExists  = func(p string) bool { _, err := os.Stat(p); return err == nil }
)

// FetchJob states in the fact.
const (
	FetchJobOK           = "ok"
	FetchJobRearmed      = "rearmed"
	FetchJobPlistMissing = "plist_missing"
	FetchJobRearmFailed  = "rearm_failed"
)

// FetchJobFact is the `fetch_job` fact in the heartbeat file.
type FetchJobFact struct {
	State  string `json:"state"`
	TS     string `json:"ts"`
	Detail string `json:"detail,omitempty"`
}

// fetchJobStatus is what `launchctl print` says about the job.
type fetchJobStatus int

const (
	fetchJobUnknown      fetchJobStatus = iota // garbage / unrecognised: do nothing
	fetchJobNotLoaded                          // launchd has no such job
	fetchJobRunning                            // an instance is running: never touch
	fetchJobIdle                               // loaded, not running, last exit fine
	fetchJobSpawnRefused                       // loaded, not running, spawn refused
)

var (
	fetchStateRe  = regexp.MustCompile(`(?m)^\s*state = (.+?)\s*$`)
	fetchPIDRe    = regexp.MustCompile(`(?m)^\s*pid = \d+`)
	fetchStatusRe = regexp.MustCompile(`(?m)^\s*(last exit (?:code|status)|reason) = (.*?)\s*$`)
	fetchExit78Re = regexp.MustCompile(`^78\b`)
)

// parseFetchJob classifies `launchctl print system/<label>` (exit status and
// stdout). Pure and strict: only the specific "not found" signal (exit 113 or
// launchd's own words) is NotLoaded; only `state = running` is Running; only
// the exact idle states ("not running", "waiting") with no `pid = ` line are
// Idle or SpawnRefused; everything else (another state such as "spawn
// scheduled", a pid with an idle state, a failing print, no state line,
// garbage) is Unknown, and Unknown means leave the job alone. Refused is read
// only from the job's own `last exit code|status =` and `reason =` lines:
// exit 78, or "LWCR" / "spawn failed".
func parseFetchJob(rc int, out string) fetchJobStatus {
	if rc != 0 {
		if rc == 113 || strings.Contains(strings.ToLower(out), "could not find service") {
			return fetchJobNotLoaded
		}
		return fetchJobUnknown
	}
	m := fetchStateRe.FindStringSubmatch(out)
	if m == nil {
		return fetchJobUnknown
	}
	if m[1] == "running" {
		return fetchJobRunning
	}
	if (m[1] != "not running" && m[1] != "waiting") || fetchPIDRe.MatchString(out) {
		return fetchJobUnknown
	}
	for _, l := range fetchStatusRe.FindAllStringSubmatch(out, -1) {
		v := strings.ToLower(l[2])
		if fetchExit78Re.MatchString(v) || strings.Contains(v, "lwcr") || strings.Contains(v, "spawn failed") {
			return fetchJobSpawnRefused
		}
	}
	return fetchJobIdle
}

// fetchRearm is the state across checks. Guarded by mu; held for a whole
// check, which is bounded (every launchctl call has a deadline).
type fetchRearm struct {
	mu            sync.Mutex
	lastCheck     time.Time
	lastRearm     time.Time
	failures      int  // consecutive failed re-arms
	pendingVerify bool // the last re-arm ran clean; the next sighting of the problem means it did not work
	gaveUp        bool
	fact          *FetchJobFact
}

func (e *Engine) fetchJobFact() *FetchJobFact {
	e.fetch.mu.Lock()
	defer e.fetch.mu.Unlock()
	if e.fetch.fact == nil {
		return nil
	}
	f := *e.fetch.fact
	return &f
}

// boundedRunner gives every launchctl call its own deadline and remembers
// whether one ran out, so a hung launchctl is never read as an answer.
type boundedRunner struct {
	inner    Runner
	limit    time.Duration
	timedOut bool
}

func (b *boundedRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (int, string) {
	c, cancel := context.WithTimeout(ctx, b.limit)
	defer cancel()
	rc, out := b.inner.Run(c, dir, env, name, args...)
	if c.Err() != nil {
		b.timedOut = true
	}
	return rc, out
}

func (b *boundedRunner) Capture(ctx context.Context, dir string, name string, args ...string) (int, string) {
	c, cancel := context.WithTimeout(ctx, b.limit)
	defer cancel()
	rc, out := b.inner.Capture(c, dir, name, args...)
	if c.Err() != nil {
		b.timedOut = true
	}
	return rc, out
}

// fetchJobCheck is the periodic and after-kick entry. force skips the
// 10-minute spacing (the re-arm rate limit still applies).
func (e *Engine) fetchJobCheck(ctx context.Context, force bool) {
	if fetchRearmGOOS != "darwin" || e.Mode != ModeWorker {
		return
	}
	f := &e.fetch
	f.mu.Lock()
	defer f.mu.Unlock()
	now := nowUTC()
	if !force && !f.lastCheck.IsZero() && now.Sub(f.lastCheck) < fetchCheckEvery {
		return
	}
	f.lastCheck = now
	r := &boundedRunner{inner: e.Runner, limit: fetchLaunchctlLimit}
	target := "system/" + FetchLaunchdLabel
	rc, out := r.Capture(ctx, "/", "launchctl", "print", target)
	if r.timedOut {
		e.logf("WARN fetch job: launchctl print %s timed out after %s; leaving the job alone", target, fetchLaunchctlLimit)
		return
	}
	plist := fetchLaunchdPlist()
	switch parseFetchJob(rc, out) {
	case fetchJobRunning, fetchJobIdle:
		f.failures, f.pendingVerify = 0, false
		f.setFact(now, FetchJobOK, "")
	case fetchJobNotLoaded:
		if !fetchPlistExists(plist) {
			if f.fact == nil || f.fact.State != FetchJobPlistMissing {
				e.logf("WARN fetch job: %s is not loaded and its plist %s does not exist; not writing one (run `noo enroll --resume` on this Mac)", target, plist)
			}
			f.setFact(now, FetchJobPlistMissing, plist+" is missing")
			return
		}
		e.fetchRearmJob(ctx, r, f, now, plist, target, "not loaded", false)
	case fetchJobSpawnRefused:
		if !fetchPlistExists(plist) {
			e.logf("WARN fetch job: %s refuses to spawn and its plist %s does not exist; not touching it", target, plist)
			f.setFact(now, FetchJobPlistMissing, plist+" is missing")
			return
		}
		// Never bootout on one sighting: a job mid-spawn can show the previous
		// run's exit status. It must stay idle-and-refused on two more prints.
		for i := 0; i < 2; i++ {
			fetchConfirmSleep()
			rc2, out2 := r.Capture(ctx, "/", "launchctl", "print", target)
			if r.timedOut || parseFetchJob(rc2, out2) != fetchJobSpawnRefused {
				e.logf("fetch job: %s looked spawn-refused but the job changed on print %d; leaving it alone this round", target, i+2)
				return
			}
		}
		e.fetchRearmJob(ctx, r, f, now, plist, target, "loaded, not running, spawn refused", true)
	default:
		e.logf("WARN fetch job: could not read `launchctl print %s` (rc=%d); leaving the job alone", target, rc)
	}
}

func (f *fetchRearm) setFact(now time.Time, state, detail string) {
	f.fact = &FetchJobFact{State: state, TS: now.Format("2006-01-02T15:04:05Z"), Detail: detail}
}

// fetchRearmJob runs one re-arm: [bootout,] bootstrap the existing plist,
// kickstart. f.mu is held.
func (e *Engine) fetchRearmJob(ctx context.Context, r *boundedRunner, f *fetchRearm, now time.Time, plist, target, why string, bootout bool) {
	if f.gaveUp {
		return
	}
	if !f.lastRearm.IsZero() && now.Sub(f.lastRearm) < fetchRearmEvery {
		return
	}
	if f.pendingVerify {
		// The last re-arm ran clean and the job is still in trouble.
		f.pendingVerify = false
		f.failures++
		e.logf("WARN fetch job: %s is still %s after the last re-arm (%d consecutive failure(s))", target, why, f.failures)
	}
	if f.failures >= fetchGiveUpAfter {
		f.gaveUp = true
		e.logf("ERROR fetch job: giving up re-arming %s after %d consecutive failures; run `noo enroll --resume` on this Mac (no further attempts until noo-hostd restarts)", target, f.failures)
		f.setFact(now, FetchJobRearmFailed, "gave up after repeated failures")
		return
	}
	f.lastRearm = now
	e.logf("fetch job: %s is %s; re-arming from %s", target, why, plist)
	fail := func(step string, rc int, msg string) {
		f.failures++
		detail := fmt.Sprintf("%s failed (rc=%d): %s", step, rc, truncate(msg))
		e.logf("WARN fetch job: re-arm of %s: %s (%d consecutive failure(s))", target, detail, f.failures)
		f.setFact(now, FetchJobRearmFailed, detail)
		if f.failures >= fetchGiveUpAfter {
			f.gaveUp = true
			e.logf("ERROR fetch job: giving up re-arming %s after %d consecutive failures; run `noo enroll --resume` on this Mac (no further attempts until noo-hostd restarts)", target, f.failures)
		}
	}
	if bootout {
		// A failed bootout is tolerated: the bootstrap below says whether it worked.
		r.Run(ctx, "/", nil, "launchctl", "bootout", target)
	}
	if rc, msg := bootstrapPlistOutwaitingTeardown(ctx, r, plist); rc != 0 {
		fail("launchctl bootstrap", rc, msg)
		return
	}
	if rc, msg := r.Run(ctx, "/", nil, "launchctl", "kickstart", target); rc != 0 {
		fail("launchctl kickstart", rc, msg)
		return
	}
	f.pendingVerify = true
	e.logf("fetch job: re-armed %s", target)
	f.setFact(now, FetchJobRearmed, why)
}
