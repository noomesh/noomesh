// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package hostd implements noo-hostd: the host-side executor for the command
// spool the gateway container writes into.
//
// # Why this exists
//
// The gateway container is given ZERO Docker access — no /var/run/docker.sock,
// no docker CLI. Anything it
// needs done on the host, it asks for by dropping an atomic JSON command file
// into a bind-mounted spool directory. Something on the host has to read that
// spool and act.
//
// That something was scripts/noo-host-watcher.sh, ~600 lines of bash. This
// package replaces its CONTROL PATH — parse, validate, dispatch, report,
// heartbeat — with a typed, tested, single static binary. Three concrete
// defects motivated the port, all of them observed rather than imagined:
//
//  1. The spool schema existed twice (a Rust/Python writer and a bash reader)
//     with nothing tying them together, and it drifted: `rotate` was a live,
//     executable handler that the validation list did not include, so every
//     rotate request was rejected before reaching it. Here the schema is one
//     Go type and the op list is one table, checked by test against the
//     writers.
//
//  2. The watcher is a long-lived process holding a snapshot of a bash file.
//     Editing the script changes nothing until someone restarts the service —
//     which is exactly what happened once: db-resync was added on the
//     4th, the service had been running since the 1st, and the gateway spent
//     two days queueing an op its watcher had never heard of. The heartbeat
//     below closes that: the daemon publishes the op list it ACTUALLY has, so
//     a caller can refuse to promise a repair nothing will run.
//
//  3. bash + jq + inotifywait + coreutils is a dependency chain to install on
//     every machine that runs the controller. A static binary is not.
//
// # What it deliberately does NOT change
//
// Ops still shell out to `docker`/`docker compose` and to the existing
// scripts. That is the point: noo-hostd is a host process, and a host process
// using the docker CLI is not the risk we are removing — an untrusted
// CONTAINER holding the socket is. Reimplementing `docker compose up
// --force-recreate` against the Engine API would be a large pile of new
// behaviour to get subtly wrong, for no security gain.
//
// Secret loading likewise still delegates to scripts/lib-secrets.sh (see
// ops.go). SOPS+age keyring handling reimplemented in Go would be a second
// implementation of the thing whose whole value is being the single one.
package hostd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Command is the spool command schema. It is written by three producers —
// gateway-rust (routes/settings.rs, dependency_watchdog.rs, heartbeat_actions.rs,
// autonomy_evaluators.rs), src/noomesh/gateway/host_spool.py, and the bash
// watcher's own docs — and consumed here.
//
// Field names and JSON types are load-bearing across repos: `health_check` is
// a real bool (not the string "true"), `args` is a list of strings, and
// `rollback` is null or an object. Changing any of them silently breaks a
// producer that this module cannot see, so treat this struct as a published
// interface, not an internal detail.
type Command struct {
	Op          string    `json:"op"`
	Service     string    `json:"service"`
	HealthCheck bool      `json:"health_check"`
	Rollback    *Rollback `json:"rollback"`
	Args        []string  `json:"args"`
	RequestedBy string    `json:"requested_by"`
	TS          string    `json:"ts"`
	// (A `manifest` field rode here for swap-agent until the design
	// retired it. A producer older than that may still send one; unknown
	// fields are ignored, see ParseCommand, and the op is refused anyway.)
}

// Rollback rides along on a recreate for AUDIT AND ALERTING ONLY. Nothing in
// this daemon ever applies it: the host working tree can hold an operator's
// uncommitted work, so an unattended `git checkout` is a data-loss bug wearing
// a recovery costume. On an unhealthy recreate we print the suggested command
// and stop.
type Rollback struct {
	SHA   string   `json:"sha"`
	Files []string `json:"files"`
}

// Result is written back beside the command as <name>.result.json.
//
// Status is "done" for ordinary ops. Detached ops (stack-rebuild) write
// "running" immediately and overwrite with "done"/"failed" when the detached
// job finishes, so a caller polling the file can tell "still going" from
// "finished successfully".
type Result struct {
	OK      bool   `json:"ok"`
	Op      string `json:"op"`
	Service string `json:"service"`
	RC      int    `json:"rc"`
	Stderr  string `json:"stderr"`
	Status  string `json:"status"`
	TS      string `json:"ts"`

	// DurationMS is how long the op ran (set for every op the scan loop runs
	// to completion). Artifact and Bytes name what an op PRODUCED, so the
	// requester can verify the artifact rather than the clock; today only
	// `backup` fills them (see annotateBackup). All three are omitted when
	// empty, so the file is unchanged for every other op.
	DurationMS int64  `json:"duration_ms,omitempty"`
	Artifact   string `json:"artifact,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	// Offsite is the backup's off-site outcome as the script reported it
	// ("copied 3 artifact(s) to dir:/mnt/x", "FAILED: ...", "declined ...",
	// "not configured ..."), so the run's text can state it. Only `backup`.
	Offsite string `json:"offsite,omitempty"`
}

// Heartbeat is published to <spool>/hostd.heartbeat.json on a fixed interval.
//
// This is the piece the bash watcher had no equivalent of, and its absence was
// a real defect: the gateway would queue a repair and tell the operator "a
// repair has been queued" with no evidence that anything was listening. A
// stale heartbeat (or one whose Ops list lacks the op) means the honest
// message is "I cannot fix this myself" — which is actionable — instead of a
// promise that quietly expires.
//
// Ops is the op list this RUNNING BINARY supports, not the one in the source
// tree. That distinction is the entire point: it is what makes the
// stale-deployment failure visible.
type Heartbeat struct {
	PID       int      `json:"pid"`
	Version   string   `json:"version"`
	StartedAt string   `json:"started_at"`
	TS        string   `json:"ts"`
	Interval  int      `json:"interval_secs"`
	Ops       []string `json:"ops"`
	Spool     string   `json:"spool"`
	Root      string   `json:"project_root"`
	// Features are contract capabilities orthogonal to the op table —
	// e.g. `stage-dir` (worker mode,: swap-agent adopted a spool-staged
	// binary, so an unprivileged agent can stage). Absent on older
	// daemons, which is exactly the signal: a caller needing a feature
	// an old daemon lacks gets a refusal it can explain, not a swap that
	// silently looks in the wrong place.
	Features []string `json:"features,omitempty"`
	// Host is what this node's next boot will do:
	// running/default/fallback kernel, NVIDIA module per kernel, platform
	// package versions and holds, Tailscale control state. Linux only;
	// absent on older daemons and on macOS.
	Host *HostFacts `json:"host,omitempty"`
	// JournalFollow is the live state of the journal-follow op (fleet log
	// shipping). nil = nothing requested since this daemon started, which
	// is the agent's cue to request one; Running=false with LastError =
	// the child keeps dying. Worker mode only; absent on older daemons.
	JournalFollow *JournalFollowState `json:"journal_follow,omitempty"`
	// Backup is the newest Postgres dump in the backup directory, read from
	// the files each beat. Controller mode only; absent on workers and on older
	// daemons. It is the backup-age signal that does not depend on the
	// database or the heartbeat scheduler (see BackupFacts).
	Backup *BackupFacts `json:"backup,omitempty"`
}

// HeartbeatFile is the fixed name callers look for. It is not a <name>.cmd
// pattern, so the scan loop never mistakes it for work.
const HeartbeatFile = "hostd.heartbeat.json"

const (
	cmdSuffix        = ".cmd.json"
	processingSuffix = ".processing"
	resultSuffix     = ".result.json"
	// LogOutSuffix carries an op's stdout when it is the ANSWER rather than
	// a side effect. Result.Stderr is truncated to stderrCap, which is right
	// for an error and useless for a log tail, so the payload rides beside
	// the result instead of inside it.
	LogOutSuffix = ".logout"
)

// nowUTC is a package var so tests can pin time without a clock interface
// threaded through every call site.
var nowUTC = func() time.Time { return time.Now().UTC() }

func stamp() string { return nowUTC().Format("2006-01-02T15:04:05Z") }

// stderrCap matches the bash watcher's 2000-char truncation. Result files are
// read into alert payloads and log lines; an unbounded docker error (a compose
// failure can emit tens of kilobytes) turns one bad op into an unreadable
// alert.
const stderrCap = 2000

func truncate(s string) string {
	if len(s) <= stderrCap {
		return s
	}
	return s[:stderrCap]
}

// serviceRe mirrors the bash watcher's valid_service. The leading-dash check
// is separate and deliberate: a service named "--volumes" would otherwise be
// spliced into a docker command line as an OPTION rather than an operand.
var serviceRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// shaRe accepts a git short-or-full SHA. Only used to reject junk before it
// reaches an operator-facing "suggested rollback" line — a malformed value
// there is a copy-paste hazard, not an injection one (we never run it).
var shaRe = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// ValidateService reports whether a service/container name is safe to pass as
// a docker operand.
func ValidateService(s string) error {
	switch {
	case s == "":
		return fmt.Errorf("invalid service")
	case len(s) >= 64:
		return fmt.Errorf("invalid service")
	case strings.HasPrefix(s, "-"):
		// Option injection: docker would read this as a flag, not a name.
		return fmt.Errorf("invalid service")
	case !serviceRe.MatchString(s):
		return fmt.Errorf("invalid service")
	}
	return nil
}

// ValidateSHA reports whether a rollback SHA is well-formed.
func ValidateSHA(s string) error {
	if !shaRe.MatchString(s) {
		return fmt.Errorf("invalid rollback sha")
	}
	return nil
}

// ParseCommand decodes a spool command file.
//
// DisallowUnknownFields is deliberately NOT set. A newer producer adding a
// field must not brick an older daemon: an unknown field means "something I
// don't handle", which for every op here degrades to the documented default,
// whereas rejecting the whole command turns a forward-compatible addition into
// a fleet-wide outage.
func ParseCommand(b []byte) (*Command, error) {
	var c Command
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}
	return &c, nil
}

// commandName strips the spool suffixes to recover the caller's command name,
// which keys the result file back to the request.
func commandName(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, processingSuffix)
	return strings.TrimSuffix(base, cmdSuffix)
}

// claim atomically takes ownership of a pending command by renaming it to
// <name>.cmd.json.processing.
//
// Rename is the claim primitive rather than a lock file because it is atomic
// within a directory on every filesystem we run on, and because it survives
// the daemon being killed mid-op: the .processing file is left behind as
// evidence rather than an unreleased lock that blocks the next start.
func claim(path string) (string, error) {
	target := path + processingSuffix
	if err := os.Rename(path, target); err != nil {
		return "", err
	}
	return target, nil
}

// writeJSONAtomic writes via tmp+rename so a reader never sees a half-written
// file. The same discipline the producers use on the way in — a result file
// read mid-write parses as invalid JSON, which upstream reports as a FAILED
// op, inverting the meaning of a successful run.
func writeJSONAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteCommand queues a command for the daemon serving spool. This is the
// PRODUCER half of the worker-mode contract: the agent
// stages a verified artifact, then asks for the privileged half by writing
// here. tmp+rename so the scan loop never claims a half-written command.
func WriteCommand(spool, name string, c Command) error {
	if c.TS == "" {
		c.TS = stamp()
	}
	return writeJSONAtomic(filepath.Join(spool, name+cmdSuffix), c)
}

// ReadResult loads the result the daemon wrote for a command name, if it has
// finished. os.IsNotExist(err) means "still pending".
func ReadResult(spool, name string) (*Result, error) {
	b, err := os.ReadFile(filepath.Join(spool, name+resultSuffix))
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("result unreadable: %w", err)
	}
	return &r, nil
}

// WriteResult records the outcome of a command for the caller to poll.
func WriteResult(spool, name string, r Result) error {
	if r.Status == "" {
		r.Status = "done"
	}
	r.Stderr = truncate(r.Stderr)
	r.TS = stamp()
	return writeJSONAtomic(filepath.Join(spool, name+resultSuffix), r)
}

// ReadHeartbeat loads and freshness-checks the daemon heartbeat.
//
// Exposed so the gateway side (and `noo-hostd status`) share ONE definition of
// "is the host daemon alive", rather than each growing its own staleness
// constant that drifts from the publish interval.
func ReadHeartbeat(spool string) (*Heartbeat, error) {
	b, err := os.ReadFile(filepath.Join(spool, HeartbeatFile))
	if err != nil {
		return nil, err
	}
	var hb Heartbeat
	if err := json.Unmarshal(b, &hb); err != nil {
		return nil, fmt.Errorf("heartbeat unreadable: %w", err)
	}
	return &hb, nil
}

// Stale reports whether a heartbeat is too old to be believed.
//
// The allowance is 3 intervals. One would flag every ordinary scheduling
// hiccup as a dead daemon (and a false "host daemon down" alert during a
// working repair is worse than a few seconds of latency); much more than
// three and a genuinely dead daemon stays believed for minutes, which is the
// failure this exists to catch.
func (h *Heartbeat) Stale(now time.Time) bool {
	ts, err := time.Parse("2006-01-02T15:04:05Z", h.TS)
	if err != nil {
		return true
	}
	interval := time.Duration(h.Interval) * time.Second
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	return now.Sub(ts) > 3*interval
}

// Supports reports whether the running daemon has a handler for op. A caller
// that queues an op absent from this list gets no result file, ever — the
// silent-expiry failure mode.
func (h *Heartbeat) Supports(op string) bool {
	for _, o := range h.Ops {
		if o == op {
			return true
		}
	}
	return false
}

// HasFeature reports whether the running daemon advertises a contract
// feature (see Heartbeat.Features). Old daemons omit the field entirely.
func (h *Heartbeat) HasFeature(f string) bool {
	for _, v := range h.Features {
		if v == f {
			return true
		}
	}
	return false
}

// FeaturesFor lists the contract features THIS BINARY's mode provides —
// same running-binary discipline as SupportedOpsFor.
func FeaturesFor(mode string) []string {
	// Worker mode advertised `stage-dir` (spool staging for swap-agent)
	// retired the swap; no feature remains.
	_ = mode
	return nil
}

// DefaultHeartbeatInterval is the publish cadence. Short enough that a caller
// deciding whether to promise a repair is never working from minutes-old
// evidence; long enough that the write is free.
const DefaultHeartbeatInterval = 15 * time.Second
