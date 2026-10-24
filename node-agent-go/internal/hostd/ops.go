// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Op is one host operation the gateway may request.
//
// The table below is the SINGLE definition of what this daemon accepts. In the
// bash watcher the same fact lived in two places — a `case` in the validator
// and a `case` in the executor — and they drifted: `rotate` had a working
// handler that the validator did not list, so every rotate request was
// rejected with "invalid op" before reaching code that would have worked. One
// table cannot disagree with itself.
type Op struct {
	Name string

	// Detached ops own their own result lifecycle: they write status=running
	// immediately and overwrite it when the background job finishes. The scan
	// loop must not write a completion result on their behalf.
	Detached bool

	// Run performs the operation and returns (exit code, stderr text).
	Run func(ctx context.Context, e *Engine, name string, c *Command) (int, string)
}

// Engine holds the daemon's resolved configuration and executes ops.
type Engine struct {
	// Mode selects the op table: ModeController (compose ops against
	// the project root) or ModeWorker.
	// Empty means controller — every pre-step-4 install ran without it.
	Mode        string
	Root        string // project root (where docker-compose.cluster.yml lives)
	Spool       string // host side of the ./.noo-host-spool bind mount
	GatewayPort string
	Runner      Runner

	// RestoreOnBoot runs BootRestore when Run starts (boot.go): set by the
	// daemon's main, off in unit tests.
	RestoreOnBoot bool

	// Health-check tuning for `recreate`.
	HealthWake     time.Duration
	HealthTimeout  time.Duration
	HealthInterval time.Duration

	// Cap for each buildx builder's cache, in bytes. 0 (the default) disables
	// rung 2b of the reclaim ladder. Needed because rung 2's age filter is on
	// LAST USED, so cache that every build reuses is never idle and an age
	// policy alone cannot bound it — see reclaim.go.
	CacheCapBytes int64

	// Logf receives operator-facing lines. Injected so tests observe the log
	// without a file, and so main can tee to journald and the spool log.
	Logf func(format string, args ...any)

	// journal is the live journal-follow follower (worker mode, at most
	// one); its state rides the heartbeat. See journal_follow.go.
	journalMu sync.Mutex
	journal   *journalFollower
}

func (e *Engine) logf(format string, args ...any) {
	if e.Logf != nil {
		e.Logf(format, args...)
	}
}

// composeArgs builds the compose invocation, mirroring the launcher scripts.
// The override file is included only when present — compose errors out on a
// missing -f, which would turn "no override configured" (the normal case on a
// fresh install) into every recreate failing.
func (e *Engine) composeArgs() []string {
	args := []string{"compose", "-f", filepath.Join(e.Root, "docker-compose.cluster.yml")}
	override := filepath.Join(e.Root, "docker-compose.override.yml")
	if _, err := os.Stat(override); err == nil {
		args = append(args, "-f", override)
	}
	return append(args, "--profile", "controller")
}

// ops is the registry. Keep it alphabetical by name; the parity test against
// the producers reads this table, not the docs.
var ops = map[string]Op{
	"recreate":      {Name: "recreate", Run: opRecreate},
	"restart":       {Name: "restart", Run: opRestart},
	"rebuild":       {Name: "rebuild", Run: opRebuild},
	"backup":        {Name: "backup", Run: opBackup},
	"rotate":        {Name: "rotate", Run: opRotate},
	"db-resync":     {Name: "db-resync", Run: opDBResync},
	"disk-reclaim":  {Name: "disk-reclaim", Run: opDiskReclaim},
	"stack-rebuild": {Name: "stack-rebuild", Detached: true, Run: opStackRebuild},
}

// opsFor selects the registry for a mode. Empty/unknown falls back to the
// controller table — every pre-step-4 install runs modeless, and "unknown
// mode silently means no ops at all" would be the stale-deployment failure
// this daemon's heartbeat exists to prevent.
func opsFor(mode string) map[string]Op {
	if mode == ModeWorker {
		return workerOps
	}
	return ops
}

// SupportedOpsFor returns the op names a given mode implements, sorted.
// Published in the heartbeat so a caller can tell "the daemon does not know
// this op" from "the daemon is dead" — two failures that look identical when
// the only symptom is a result file that never appears.
func SupportedOpsFor(mode string) []string {
	table := opsFor(mode)
	names := make([]string, 0, len(table))
	for n := range table {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SupportedOps is the controller-mode list (compat shim: `noo-hostd status`
// and the parity tests predate modes).
func SupportedOps() []string { return SupportedOpsFor(ModeController) }

// LookupOpFor returns the handler for op in the given mode's table.
func LookupOpFor(mode, op string) (Op, bool) {
	o, ok := opsFor(mode)[op]
	return o, ok
}

// LookupOp is the controller-mode lookup (compat shim, as above).
func LookupOp(op string) (Op, bool) { return LookupOpFor(ModeController, op) }

// ── recreate ───────────────────────────────────────────────────────────────

func opRecreate(ctx context.Context, e *Engine, name string, c *Command) (int, string) {
	// Single-flight across every compose-mutating entry point.
	// A spooled recreate firing mid-`noo stack start` is the two-owners
	// interleave that took a fleet down: the stack was left in
	// `Created` with rename orphans blocking recreation. Held per-operation,
	// not for the daemon's life — this process is long-lived and holding it
	// throughout would deadlock every launcher script on the box.
	unlock, err := acquireComposeLock(ctx)
	if err != nil {
		return 1, "compose lock timeout"
	}
	defer unlock()

	// Under withSecrets, like every other op that needs the store: since
	// the file-backed-secrets flip compose sources each `secrets:` entry
	// from an environment variable, and with it unset `up --force-recreate`
	// REMOVES the running container and then refuses to create the new one
	// ("required by secret … is not set") — a `Created` stub where a
	// working service was. load_secrets also derives the pgpass bodies.
	args := append(e.composeArgs(), "up", "-d", "--force-recreate", "--", c.Service)
	bin, wrapped := withSecrets(e.Root, "docker", args...)
	rc, stderr := e.Runner.Run(ctx, e.Root, nil, bin, wrapped...)
	if rc != 0 || !c.HealthCheck {
		return rc, stderr
	}

	e.logf("HEALTH %s: waiting %s then polling /health (timeout %s)", name, e.HealthWake, e.HealthTimeout)
	sleepCtx(ctx, e.HealthWake)
	if e.pollHealthy(ctx) {
		e.logf("HEALTH %s: gateway healthy", name)
		return 0, stderr
	}

	// LOUD, and deliberately NOT self-correcting. The suggested rollback is
	// printed rather than run because the host working tree may hold the
	// operator's uncommitted work — an unattended `git checkout` here destroys
	// it to recover from a problem it has not diagnosed.
	sha := "none"
	files := "none"
	if c.Rollback != nil {
		if c.Rollback.SHA != "" {
			sha = c.Rollback.SHA
		}
		if len(c.Rollback.Files) > 0 {
			files = strings.Join(c.Rollback.Files, " ")
		}
	}
	e.logf("ALERT %s: GATEWAY UNHEALTHY after %s — OPERATOR INTERVENTION REQUIRED", name, e.HealthTimeout)
	e.logf("ALERT %s:   suggested manual rollback (review first!): git -C %q checkout %s -- %s", name, e.Root, sha, files)
	body := fmt.Sprintf(
		"UNHEALTHY %s at %s\n  op=%s service=%s\n  rollback.sha=%s\n  rollback.files=%s\n"+
			"  NOTE: auto-rollback intentionally NOT performed (host tree may hold uncommitted work).\n",
		name, stamp(), c.Op, c.Service, sha, files)
	_ = os.WriteFile(filepath.Join(e.Spool, "UNHEALTHY-"+name+".alert"), []byte(body), 0o644)

	if rc == 0 {
		rc = 1
	}
	return rc, stderr
}

// clusterCAPath is the first readable cluster CA: the agent env's
// NOO_TLS_CA, the node layout, then the project's own PKI dir. Empty when
// there is none, which callers treat as "cannot verify".
func (e *Engine) clusterCAPath() string {
	candidates := []string{
		os.Getenv("NOO_TLS_CA"),
		"/etc/noo/pki/ca.crt",
		filepath.Join(e.Root, "pki", "ca.crt"),
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			if f, err := os.Open(c); err == nil {
				_ = f.Close()
				return c
			}
		}
	}
	return ""
}

func (e *Engine) pollHealthy(ctx context.Context) bool {
	deadline := nowUTC().Add(e.HealthTimeout)
	// The separate change the old comment deferred. The gateway serves
	// TLS signed by the CLUSTER CA — which this box holds — and its cert
	// carries 127.0.0.1 among its IP SANs, so the loopback probe verifies
	// like any other request. `curl -sk` was never needed; it was inherited
	// from the bash watcher. No CA, no verdict: an unverified 200 does not
	// establish that the gateway answered.
	ca := e.clusterCAPath()
	if ca == "" {
		e.logf("recreate: no readable cluster CA (NOO_TLS_CA, /etc/noo/pki/ca.crt, %s/pki/ca.crt) — cannot verify the gateway's health endpoint", e.Root)
		return false
	}
	for nowUTC().Before(deadline) {
		rc, out := e.Runner.Capture(ctx, e.Root, "curl", "-s", "--cacert", ca, "-o", "/dev/null",
			"-w", "%{http_code}", "--max-time", "5",
			fmt.Sprintf("https://127.0.0.1:%s/health", e.GatewayPort))
		if rc == 0 && out == "200" {
			return true
		}
		if !sleepCtx(ctx, e.HealthInterval) {
			return false
		}
	}
	return false
}

// sleepCtx sleeps unless the context is cancelled. Returns false if cancelled,
// so a shutting-down daemon stops polling instead of holding the process open
// for the remainder of a 180s health timeout.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ── restart / rebuild ──────────────────────────────────────────────────────

func opRestart(ctx context.Context, e *Engine, _ string, c *Command) (int, string) {
	return e.Runner.Run(ctx, e.Root, nil, "docker", "restart", "--", c.Service)
}

// opRebuild is stop-then-start, not `docker restart`. The distinction is real:
// a container recreated by compose with a new image needs a full stop/start to
// pick it up, and `restart` on some Docker versions short-circuits.
func opRebuild(ctx context.Context, e *Engine, _ string, c *Command) (int, string) {
	rc, stderr := e.Runner.Run(ctx, e.Root, nil, "docker", "stop", "--", c.Service)
	if rc != 0 {
		return rc, stderr
	}
	return e.Runner.Run(ctx, e.Root, nil, "docker", "start", "--", c.Service)
}

// ── backup ─────────────────────────────────────────────────────────────────

// opBackup dumps Postgres to $NOO_BACKUP_DIR under the database_backup
// heartbeat action. Runs under withSecrets because the backup passphrases live
// in the authoritative store: without them the dump silently writes
// UNENCRYPTED, which is worse than failing — you end up trusting encryption
// you do not have.
func opBackup(ctx context.Context, e *Engine, _ string, _ *Command) (int, string) {
	name, args := withSecrets(e.Root, filepath.Join(e.Root, "scripts", "backup-controller.sh"))
	return e.Runner.Run(ctx, e.Root, backupExtraEnv(e.Root), name, args...)
}

// backupExtraEnv carries NOO_BACKUP_OFFSITE into the backup run. withSecrets
// loads the secret store and noomesh.yaml but NOT the checkout's plain .env,
// which is where `noo backups setup` records the destination — so a spooled
// backup saw it unset, said "not configured", and exited 0 (2026-10-24). The
// script now resolves it itself as well; passing it here keeps the two from
// ever disagreeing. An exported value in hostd's own environment wins, as it
// does in the script.
func backupExtraEnv(root string) []string {
	if strings.TrimSpace(os.Getenv("NOO_BACKUP_OFFSITE")) != "" {
		return nil
	}
	if v := envFileValue(filepath.Join(root, ".env"), "NOO_BACKUP_OFFSITE"); v != "" {
		return []string{"NOO_BACKUP_OFFSITE=" + v}
	}
	return nil
}

// envFileValue is the last uncommented `KEY=value` (optionally `export `ed,
// optionally quoted) in an env file, or "" when absent or unreadable.
func envFileValue(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	val := ""
	for _, line := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(line)
		l = strings.TrimSpace(strings.TrimPrefix(l, "export "))
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.HasPrefix(l, "#") || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		val = v
	}
	return val
}

// backupArtifactMarker prefixes the stderr line backup-controller.sh prints
// naming the dump it wrote. Stdout is discarded by the Runner, so the path
// rides the one stream that is captured.
const backupArtifactMarker = "NOO_BACKUP_ARTIFACT="

// backupOffsiteMarker prefixes the stderr line naming the off-site outcome.
// Without it a success result could not say whether anything left the machine
// (2026-10-24: a configured destination read as unset, the run reported OK).
const backupOffsiteMarker = "NOO_BACKUP_OFFSITE_RESULT="

// annotateBackup turns a finished backup's stderr into Result fields: it
// strips the marker line, then names the dump and its size so the gateway can
// verify the ARTIFACT (exists, non-empty) instead of trusting an exit code.
// A marker whose file is missing or empty turns an rc=0 run into a failure.
// A zero exit that names no dump is a failure too: the script reported success
// but produced nothing (it skipped the dump), and the requester must not be
// told a backup happened.
func annotateBackup(r Result) Result {
	var kept []string
	path := ""
	for _, line := range strings.Split(r.Stderr, "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), backupArtifactMarker); ok {
			path = strings.TrimSpace(p)
			continue
		}
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), backupOffsiteMarker); ok {
			r.Offsite = strings.TrimSpace(p)
			continue
		}
		kept = append(kept, line)
	}
	r.Stderr = strings.TrimSpace(strings.Join(kept, "\n"))
	if !r.OK {
		return r
	}
	if path == "" {
		r.OK, r.RC = false, 1
		r.Stderr = strings.TrimSpace("the script reported success but named no dump (no " + backupArtifactMarker + " line)\n" + r.Stderr)
		return r
	}
	st, err := os.Stat(path)
	switch {
	case err != nil:
		r.OK, r.RC = false, 1
		r.Stderr = strings.TrimSpace("backup reported " + path + " but it cannot be read: " + err.Error() + "\n" + r.Stderr)
	case st.Size() == 0:
		r.OK, r.RC = false, 1
		r.Stderr = strings.TrimSpace("backup wrote an EMPTY dump: " + path + "\n" + r.Stderr)
	default:
		r.Artifact, r.Bytes = path, st.Size()
	}
	return r
}

// ── rotate ─────────────────────────────────────────────────────────────────

// opRotate runs the PKI rotation. Host-side by necessity: the CA key is
// 0600 operator-only and containers cannot read it by design. Only the CLI's
// rotate-all carries the full closed loop — back up old certs, rotate, restart
// consumers, health-probe, auto-revert on failure.
//
// The native `noo` binary runs it (`noo security pki rotate-all`), found the
// same way db-resync finds it. It used to look ONLY under <root>/venv/bin
// for the retired Python CLI — and a standalone controller (~/.noo) has no
// venv, so every cert_auto_rotate and admin pki-rotate spool command there
// exited 127 while the certificates kept ageing. The venv stays as a last
// resort for a checkout that still has one.
func opRotate(ctx context.Context, e *Engine, _ string, _ *Command) (int, string) {
	bin, err := e.resolveCLI()
	if err != nil {
		legacy := filepath.Join(e.Root, "venv", "bin", "noo-py")
		if !isExecutable(legacy) {
			return 127, err.Error() + "; and no legacy " + legacy
		}
		bin = legacy
	}
	return e.Runner.Run(ctx, e.Root, nil, bin, "security", "pki", "rotate-all", "--force")
}

// ── db-resync ──────────────────────────────────────────────────────────────

// opDBResync converges the Postgres ROLE onto the password in the
// authoritative store. Queued by the gateway's dependency watchdog when
// Postgres is UP and REJECTING it (SQLSTATE 28P01) — store and role hold
// different passwords.
//
// Why this is safe to run unprompted: it mints nothing, rewrites no store, and
// recreates no container. Every consumer already holds the stored value, which
// is why they recover the instant the role catches up. The CLI re-probes each
// role and only ALTERs one whose stored password is REJECTED while a negative
// control is ALSO rejected — so an unreachable Postgres and a `trust` pg_hba
// both resolve to "learned nothing" and are declined. It cannot fire during an
// ordinary outage, and running it when nothing has drifted is a verified no-op.
func opDBResync(ctx context.Context, e *Engine, _ string, _ *Command) (int, string) {
	cli, err := e.resolveCLI()
	if err != nil {
		return 127, err.Error()
	}
	name, args := withSecrets(e.Root, cli, "security", "secrets", "resync", "--all")
	return e.Runner.Run(ctx, e.Root, nil, name, args...)
}

// resolveCLI finds the Rust `noo` binary explicitly.
//
// Not a bare "noo" on PATH: systemd hands this unit
// PATH=/usr/local/bin:/usr/bin:/bin, which does NOT include ~/.local/bin where
// the CLI installs. Relying on PATH here fails with exit 127 and no
// explanation — the failure mode is a repair that never happens and an
// operator with nothing to read.
func (e *Engine) resolveCLI() (string, error) {
	if p := os.Getenv("NOO_CLI_BIN"); p != "" {
		if isExecutable(p) {
			return p, nil
		}
		return "", fmt.Errorf("NOO_CLI_BIN=%s is not executable", p)
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".local", "bin", "noo"),
		// A root-owned install (NOO_INSTALL_DIR=/usr/local/bin). This named
		// the pre-rename binary, /usr/local/bin/pai, which no install has.
		"/usr/local/bin/noo",
		filepath.Join(e.Root, "noo-cli", "target", "release", "noo"),
	}
	for _, c := range candidates {
		if isExecutable(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("no noo CLI found (tried $NOO_CLI_BIN, %s)", strings.Join(candidates, ", "))
}

func isExecutable(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode()&0o111 != 0
}

// ── stack-rebuild ──────────────────────────────────────────────────────────

// rebuildArgRe is the allowlist for stack-rebuild arguments. Anything outside
// it aborts the op rather than being dropped: silently ignoring an argument
// means running a DIFFERENT rebuild than the caller asked for, and reporting
// success for it.
var rebuildArgRe = regexp.MustCompile(`^(--quick|--no-cache|[a-z0-9._-]+)$`)

// opStackRebuild runs the full-stack rebuild detached.
//
// It takes minutes and recreates containers including the gateway, so it must
// not block the spool loop — a blocked loop means every other queued op waits
// behind it, including the ones that would report the rebuild going wrong.
func opStackRebuild(ctx context.Context, e *Engine, name string, c *Command) (int, string) {
	var args []string
	for _, a := range c.Args {
		if a == "" {
			continue
		}
		if !rebuildArgRe.MatchString(a) {
			return 1, fmt.Sprintf("invalid rebuild arg %q", a)
		}
		args = append(args, a)
	}

	marker := filepath.Join(e.Spool, name+".rebuild.running")
	if existing, _ := filepath.Glob(filepath.Join(e.Spool, "*.rebuild.running")); len(existing) > 0 {
		return 1, "another stack rebuild is already running"
	}
	logPath := filepath.Join(e.Spool, name+".rebuild.log")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		return 1, fmt.Sprintf("cannot claim rebuild marker: %v", err)
	}

	_ = WriteResult(e.Spool, name, Result{
		OK: true, Op: c.Op, Service: c.Service, RC: 0,
		Stderr: "detached; log=" + logPath, Status: "running",
	})
	e.logf("EXEC %s op=stack-rebuild args=%q detached log=%s", name, strings.Join(args, " "), logPath)

	go func() {
		defer os.Remove(marker)
		rc := e.runRebuildScript(context.WithoutCancel(ctx), logPath, args)
		if rc == 0 {
			_ = WriteResult(e.Spool, name, Result{
				OK: true, Op: c.Op, Service: c.Service, Stderr: "log=" + logPath, Status: "done",
			})
			e.logf("OK   %s op=stack-rebuild rc=0 (detached job finished)", name)
			return
		}
		_ = WriteResult(e.Spool, name, Result{
			OK: false, Op: c.Op, Service: c.Service, RC: rc,
			Stderr: "rebuild failed; see " + logPath, Status: "failed",
		})
		e.logf("FAIL %s op=stack-rebuild rc=%d (detached job finished)", name, rc)
	}()

	return 0, ""
}

// runRebuildScript streams the rebuild to its own log file. Separate from
// Runner because this output is the operator's only window into a multi-minute
// job — it must land on disk as it happens, not be buffered into a result
// field that appears when it is already too late to watch.
func (e *Engine) runRebuildScript(ctx context.Context, logPath string, args []string) int {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 1
	}
	defer f.Close()
	return runStreaming(ctx, e.Root, f, filepath.Join(e.Root, "scripts", "noomesh-rebuild.sh"), args...)
}

// ── disk-reclaim ───────────────────────────────────────────────────────────

// opDiskReclaim runs the bounded reclaim ladder.
//
// Args are a strict allowlist and an unrecognised one keeps the SAFE default
// rather than erroring. The asymmetry is deliberate and the opposite of
// stack-rebuild's: here the safe default is dry_run=true, so a malformed
// argument degrades to previewing instead of deleting. Erroring out on a
// mangled watermark, by contrast, would leave a filling disk unattended.
func opDiskReclaim(ctx context.Context, e *Engine, _ string, c *Command) (int, string) {
	dryRun := true
	watermark := 85
	var capBytes int64
	for _, a := range c.Args {
		switch {
		case a == "dry_run=true":
			dryRun = true
		case a == "dry_run=false":
			dryRun = false
		case strings.HasPrefix(a, "watermark="):
			if v, err := strconv.Atoi(strings.TrimPrefix(a, "watermark=")); err == nil && v >= 1 && v <= 100 {
				watermark = v
			}
		case strings.HasPrefix(a, "cache_cap_bytes="):
			// The caller's cap for this run (rung 2b). Junk or <= 0 leaves
			// the engine's own setting in force.
			if v, err := strconv.ParseInt(strings.TrimPrefix(a, "cache_cap_bytes="), 10, 64); err == nil && v > 0 {
				capBytes = v
			}
		}
	}
	return e.diskReclaim(ctx, dryRun, watermark, capBytes)
}
