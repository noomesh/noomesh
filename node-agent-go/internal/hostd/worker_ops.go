// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Worker-mode ops — the design: the self-update problem).
//
// A worker gets the same no-listener daemon shape the controller invented in
// with a deliberately tiny op set: the agent (unprivileged, network-
// facing) STAGES work by writing spool files; this daemon (root, no network
// surface) performs the two operations that genuinely need root on a worker.
// Remote compromise of the agent therefore lets an attacker request
// `restart-agent` and the other fixed ops below — not run arbitrary root
// commands. `swap-agent` is still NAMED here only to be refused
// agent binaries reach a node only in a signed bundle over the pull rail.
// That is the blast-radius contract, and this file is its whole surface.
package hostd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Engine modes. ModeController is the original (compose/backup/rotate
// ops against the project root); ModeWorker is this file. The mode is picked
// once at startup — a single binary, two op tables, and the heartbeat
// publishes whichever table is actually live so a caller can tell them apart.
const (
	ModeController = "controller"
	ModeWorker     = "worker"
)

// WorkerSpoolDir is the fixed spool location on a worker — the one path the
// agent (producer, unprivileged) and this daemon (consumer, root) both know
// without a project checkout to anchor to. The agent needs write access;
// the installer creates it 0775 root:noo-agent once a service user exists
// (step 3's user), and 0755 root-owned works while the agent still runs as
// root.
//
// Spool command convention in worker mode: `service` carries the agent unit
// name ("noo-node-agent") — the dispatch loop validates service names
// unconditionally, and the unit name is both valid and honest in logs.
const WorkerSpoolDir = "/var/lib/noo-node-agent/spool"

// workerOps is the worker-mode registry. Alphabetical, same as ops.
var workerOps = map[string]Op{
	// disk-reclaim: the same bounded ladder the controller runs (reclaim.go),
	// queued by this node's agent when its own disk crosses the watermark.
	// Before this a worker had no reclaim at all — the controller's ladder
	// cannot reach a worker's disk, so a full node only raised an alert.
	"disk-reclaim":  {Name: "disk-reclaim", Run: opDiskReclaim},
	"fetch-bundle":  {Name: "fetch-bundle", Run: opFetchBundle},
	"harness-start": {Name: "harness-start", Run: opHarnessStart},
	"harness-stop":  {Name: "harness-stop", Run: opHarnessStop},
	// journal-follow (read-only, long-lived, detached): the privileged half
	// of fleet log shipping — see journal_follow.go.
	"journal-follow": {Name: OpJournalFollow, Detached: true, Run: opJournalFollow},
	"restart-agent":  {Name: "restart-agent", Run: opRestartAgent},
	"unit-logs":      {Name: "unit-logs", Run: opUnitLogs},
	"swap-agent":     {Name: "swap-agent", Run: opSwapAgentRetired},
}

// harnessUnit is the unit these two ops may touch. A CONSTANT, deliberately:
// the op takes no unit name from the caller, so "the agent may ask for the
// harness to start" can never widen into "the agent may start any unit".
// That is the whole difference between this and the sudoers grant it
// replaces.
func harnessUnit() string { return "noo-harness" }

// opHarnessStart / opHarnessStop are the harness lifecycle,
// moved here from a sudo call in the agent.
//
// WHY the agent cannot do it itself: `noo-node-agent.service` runs as
// `noo-agent` with `NoNewPrivileges=true` (which took
// the agent off root — a real hardening win). That flag makes setuid
// binaries inert, so sudo can never elevate, whatever /etc/sudoers.d says.
// A first harness start failed with sudo's own words:
// "the 'no new privileges' flag is set, which prevents sudo from running as
// root". The grant was installed and valid and could not be used.
//
// WHY here: this daemon is already the node's confined root division of
// labour — "Root remains only inside noo-hostd"), already runs `systemctl`
// on named units for restart-agent, and the agent already writes this
// spool. So the harness lifecycle costs NO new privilege, and the sudoers
// drop-in it replaces can be removed — fewer grants after the fix than
// before.
// HarnessLaunchdLabel / HarnessLaunchdPlist are the Darwin harness as the
// provision bundle installs it: a system LaunchDaemon. The label is a
// constant here for the same reason harnessUnit() is — the op names its
// target itself, so "start the harness" can never become "bootstrap any
// plist the caller points at".
const (
	HarnessLaunchdLabel = "net.noomesh.harness"
	HarnessLaunchdPlist = "/Library/LaunchDaemons/" + HarnessLaunchdLabel + ".plist"
)

// One design, two runtimes. On Linux the harness is a systemd unit and the
// verbs are systemctl start/stop. On Darwin it is a system LaunchDaemon:
// `launchctl bootstrap system <plist>` loads and starts it; `launchctl
// bootout system/<label>` stops and unloads it. Both need root, which is
// the one thing this daemon has and the node agent does not — on a Mac the
// agent runs as the user and cannot reach the system domain at all, so
// without this op the harness there is unmanageable.
func opHarnessStart(ctx context.Context, e *Engine, _ string, _ *Command) (int, string) {
	if runtime.GOOS == "darwin" {
		return darwinHarnessStart(ctx, e.Runner, func() bool {
			_, err := os.Stat(HarnessLaunchdPlist)
			return err == nil
		})
	}
	return e.Runner.Run(ctx, "/", nil, "systemctl", "start", harnessUnit())
}

// darwinHarnessStart brings the harness LaunchDaemon to RUNNING from
// whatever state launchd has it in. Loading and starting are two different
// things on launchd, and the plist says so on purpose: RunAtLoad is false
// (placement decides whether the harness runs, not the last reboot), so
// `bootstrap` alone loads a job that then sits there, "loaded, not
// running". The first version of this op did exactly that, then on the
// next tick bootstrapped the loaded job again and got launchd's answer for
// that — "Bootstrap failed: 5: Input/output error", which names neither
// cause — while /tmp/noomesh-harness.log never came into existence because
// nothing had ever launched.
//
// So: ask launchd what it has (`print`), bootstrap only when the job is
// not loaded, and then `kickstart` it unless it is already running. The
// plain-Runner argument is the test seam; the GOOS gate stays in the
// caller so this can be exercised on the linux CI that builds it.
func darwinHarnessStart(ctx context.Context, r Runner, plistInstalled func() bool) (int, string) {
	if !plistInstalled() {
		return 1, "the harness LaunchDaemon is not installed at " + HarnessLaunchdPlist
	}
	target := "system/" + HarnessLaunchdLabel
	rc, state := r.Capture(ctx, "/", "launchctl", "print", target)
	if rc != 0 {
		if rc, stderr := bootstrapOutwaitingTeardown(ctx, r); rc != 0 {
			return rc, "launchctl bootstrap: " + stderr
		}
		rc, state = r.Capture(ctx, "/", "launchctl", "print", target)
		if rc != 0 {
			return rc, "bootstrapped, but launchctl print " + target + " still fails: the job did not load"
		}
	}
	if strings.Contains(state, "state = running") {
		return 0, ""
	}
	if rc, stderr := r.Run(ctx, "/", nil, "launchctl", "kickstart", target); rc != 0 {
		return rc, "launchctl kickstart: " + stderr
	}
	return 0, ""
}

// bootstrapRetries / bootstrapRetrySleep bound how long a bootstrap will
// wait for launchd to finish tearing down the previous instance.
// `launchctl bootout` returns before the job is gone, and a bootstrap
// issued in that window fails with "Bootstrap failed: 5: Input/output
// error" — the same words launchd uses for a plist it refuses, so the
// applier learned to wait for `print` to fail before bootstrapping the
// agent (node_fetch.rs, host6 2026-09-03). `print` failing is not proof
// the label is gone, though: a harness-stop followed within seconds by a
// harness-start (a reconcile flap) still lands in the window. So EIO is
// retried, briefly and boundedly, before it is believed.
var (
	bootstrapRetries    = 5
	bootstrapRetrySleep = func() { time.Sleep(time.Second) }
)

func bootstrapOutwaitingTeardown(ctx context.Context, r Runner) (int, string) {
	var rc int
	var stderr string
	for attempt := 0; attempt <= bootstrapRetries; attempt++ {
		rc, stderr = r.Run(ctx, "/", nil, "launchctl", "bootstrap", "system", HarnessLaunchdPlist)
		if rc == 0 || !strings.Contains(stderr, "Input/output error") {
			return rc, stderr
		}
		if attempt < bootstrapRetries {
			bootstrapRetrySleep()
		}
	}
	return rc, stderr + " (still failing after " + strconv.Itoa(bootstrapRetries) + " retries — not a teardown race)"
}

func opHarnessStop(ctx context.Context, e *Engine, _ string, _ *Command) (int, string) {
	if runtime.GOOS == "darwin" {
		rc, stderr := e.Runner.Run(ctx, "/", nil, "launchctl", "bootout", "system/"+HarnessLaunchdLabel)
		// Not loaded is the state we wanted.
		if rc != 0 && (strings.Contains(stderr, "No such process") || strings.Contains(stderr, "not find")) {
			return 0, ""
		}
		return rc, stderr
	}
	return e.Runner.Run(ctx, "/", nil, "systemctl", "stop", harnessUnit())
}

// agentUnit is the systemd unit the swap restarts. Env override so a test
// never restarts the developer's real agent.
func agentUnit() string {
	if u := os.Getenv("NOO_AGENT_UNIT"); u != "" {
		return u
	}
	return "noo-node-agent"
}

// ── fetch-bundle ───────────────────────────────────────────────────────────

// fetchUnit is the oneshot prep-host installs alongside its 60s timer.
func fetchUnit() string {
	if u := os.Getenv("NOO_FETCH_UNIT"); u != "" {
		return u
	}
	return "noo-fetch.service"
}

// confDir is /etc/noo, the node's config directory noo-fetch.sh reads.
// Overridable so tests never touch the real filesystem — same pattern as
// fetchUnit's NOO_FETCH_UNIT.
func confDir() string {
	if d := os.Getenv("NOO_CONF_DIR"); d != "" {
		return d
	}
	return "/etc/noo"
}

// expectBundleFastTicks mirrors noo-fetch.sh's own cadence comment: "every
// apply attempt — success or failure — re-arms 10 fast ticks". Keep the two
// numbers in sync if either changes.
const expectBundleFastTicks = "10\n"

// armExpectBundle re-arms the adaptive-cadence marker BEFORE the poked
// fetch runs, in the exact format prep-host seeds at enrollment (a bare
// countdown of fast ticks). Without this, a poked run is still subject to
// noo-fetch.sh's steady-state throttle (fetch only on every 3rd tick) and
// can exit 0 without fetching — observed once: the poke was a no-op,
// and the bundle only landed 63s later on the next unrelated timer tick.
// noo-hostd runs as root, so it can write /etc/noo directly.
func armExpectBundle(e *Engine) {
	dir, err := expectBundleDir(runtime.GOOS)
	if err != nil {
		e.logf("fetch-bundle: could not locate the fetcher's cadence marker (poke may be throttled by the adaptive cadence): %v", err)
		return
	}
	path := filepath.Join(dir, "expect-bundle")
	if err := os.WriteFile(path, []byte(expectBundleFastTicks), 0o644); err != nil {
		e.logf("fetch-bundle: could not arm %s (poke may be throttled by the adaptive cadence): %v", path, err)
	}
}

// fetchLaunchdPlist is the Mac fetch job's definition; its ProgramArguments
// carry `--user <u>`, which is how `noo node fetch` picks its base.
func fetchLaunchdPlist() string {
	if p := os.Getenv("NOO_FETCH_PLIST"); p != "" {
		return p
	}
	return "/Library/LaunchDaemons/" + FetchLaunchdLabel + ".plist"
}

// expectBundleDir is the directory whose expect-bundle the fetcher reads:
// /etc/noo for noo-fetch.sh on Linux; on macOS the fetcher (noo-cli
// node_fetch.rs) uses base = /Users/<user>/noomesh, where <user> is the
// `--user` argument in its own LaunchDaemon plist. Read from that same plist
// rather than guessing, so a node enrolled under any account resolves.
func expectBundleDir(goos string) (string, error) {
	if goos != "darwin" {
		return confDir(), nil
	}
	b, err := os.ReadFile(fetchLaunchdPlist())
	if err != nil {
		return "", err
	}
	user := fetchPlistUser(string(b))
	if user == "" {
		return "", fmt.Errorf("no --user in %s", fetchLaunchdPlist())
	}
	return "/Users/" + user + "/noomesh", nil
}

// fetchPlistUser returns the string following `--user` in a plist's
// ProgramArguments, or "" (also for values that could escape the base).
func fetchPlistUser(plist string) string {
	m := regexp.MustCompile(`<string>\s*--user\s*</string>\s*<string>([^<]*)</string>`).FindStringSubmatch(plist)
	if m == nil {
		return ""
	}
	u := strings.TrimSpace(m[1])
	if u == "" || strings.ContainsAny(u, "/\\ \t\n") || u == "." || u == ".." {
		return ""
	}
	return u
}

// opFetchBundle runs the bundle collection NOW instead of at the next timer
// tick.
//
// This is the root half of "stage and poke", the shape that replaces
// controller SSH. The controller stages a CA-signed bundle at the gateway
// and then asks the node to collect it; the node still pulls, still verifies
// the signature, and still applies through noo-apply. Only the TIMING comes
// from the controller — never the content, and never a write.
//
// That is the whole reason this is a poke and not a push. A push would need
// the network-facing agent to hold write access to root-owned files
// (/etc/noo-node-agent.env is root:root 0600), which is exactly the
// privilege the design took away from it. Here the agent's power is
// "ask for a fetch that was going to happen anyway, sooner" — worth nothing
// to an attacker who compromises it, because the bundle it collects is only
// applied if the cluster CA signed it.
//
// Takes no arguments, deliberately: a URL or a node id from the caller would
// be content, and content does not come from this direction.
//
// It first re-arms the expect-bundle marker (see armExpectBundle) so the
// poke itself always lands on the fast cadence rather than being silently
// absorbed by the steady-state throttle.
func opFetchBundle(ctx context.Context, e *Engine, _ string, _ *Command) (int, string) {
	armExpectBundle(e)
	argv := fetchKickArgv(runtime.GOOS)
	return e.Runner.Run(ctx, "/", nil, argv[0], argv[1:]...)
}

// FetchLaunchdLabel is the Mac fetch job: a system LaunchDaemon with a 60s
// StartInterval (noo-cli's FETCH_LABEL; the CLI installs it at enroll).
const FetchLaunchdLabel = "net.noomesh.fetch"

// fetchKickArgv is the command that runs the fetcher NOW. A Mac has no
// systemctl (a poke there failed with `exec: "systemctl": executable file
// not found in $PATH`, 2026-10-06): the fetcher is a system-domain
// LaunchDaemon and this daemon is root, so `launchctl kickstart` on
// system/<label> is the equivalent. No -k: a fetch already running is
// mid-apply, and killing it would abort the apply it is doing; kickstart
// without -k leaves a running job alone and starts an idle one.
func fetchKickArgv(goos string) []string {
	if goos == "darwin" {
		return []string{"launchctl", "kickstart", "system/" + FetchLaunchdLabel}
	}
	return []string{"systemctl", "start", fetchUnit()}
}

// ── restart-agent ──────────────────────────────────────────────────────────

// opRestartAgent restarts the agent service. The agent cannot do this to
// itself over its own API in any trustworthy way — the process handling the
// request is the process being killed — which is exactly the problem this
// daemon exists to hold.
func opRestartAgent(ctx context.Context, e *Engine, _ string, _ *Command) (int, string) {
	return e.Runner.Run(ctx, "/", nil, "systemctl", "restart", agentUnit())
}

// ── swap-agent (RETIRED — the design) ──────────────────────────────────

// SwapAgentRetired is the refusal every swap-agent request gets. The op name
// stays in the table so that an agent or gateway older than the retirement
// gets THIS answer — loud, in the journal and in the op result — rather than
// an "unknown op" that reads like a stale daemon. It must stay ADVERTISED
// for a second reason: noo-apply proves a freshly installed hostd is running
// by a new heartbeat naming `swap-agent` — every applier on the fleet today
// does — so dropping the name would make it revert this very binary.
//
// Why it went: the swap installed, as root, an agent binary whose only
// provenance was a manifest signed with the GATEWAY's TLS key — the
// web-facing process. A compromised gateway could therefore run code as root
// on every Linux node. The pull rail already delivers
// `agent-binary` in a bundle signed by the fleet signing key, with the
// applier's health-checked restart, so one code lane is kept, not two. The
// NOO_HOSTD_ALLOW_UNSIGNED escape went with it: there is nothing left for it
// to loosen, and setting it changes nothing.
const SwapAgentRetired = "swap-agent is retired: this daemon no longer installs " +
	"agent binaries. Agent binaries arrive only in a signed bundle over the pull rail — " +
	"run `noo cluster provision <node> --wait` on the controller"

func opSwapAgentRetired(_ context.Context, e *Engine, name string, c *Command) (int, string) {
	e.logf("REFUSED %s: swap-agent requested by %q — %s", name, c.RequestedBy, SwapAgentRetired)
	return 1, SwapAgentRetired
}

// ── unit-logs (read-only) ────────────────────────────────────────────────

// unitLogUnits is the CLOSED set of units whose logs may be read. A caller
// names one of these and nothing else: an op that took a free-form unit
// name would be "read any journal on the box", which is a different and
// much larger thing than "read the logs of the services we manage".
//
// It exists because the harness is not a container. `noo cluster logs`
// reaches a container through the agent, and the agent serves its OWN logs
// from an in-memory ring under its unit name — but the harness is a third
// case: a separate host process whose output only systemd holds. Reading
// the journal needs privilege the agent deliberately does not have, so it
// asks here instead. Nothing about journald is reimplemented: it already
// captures at the fd level (which is why it sees a binary that dies in the
// dynamic linker, before any of our code runs), rotates, and caps.
var unitLogUnits = map[string]bool{
	"noo-harness":    true,
	"noo-node-agent": true,
	"noo-fetch":      true,
	"noo-hostd":      true,
}

const (
	unitLogDefaultLines = 200
	unitLogMaxLines     = 2000
)

// opUnitLogs returns recent journal lines for one allowlisted unit.
//
// READ-ONLY: it changes nothing, which is worth saying because every other
// op in this table mutates the host. The payload goes to <name>.logout
// beside the result, since Result.Stderr is truncated.
func opUnitLogs(ctx context.Context, e *Engine, name string, c *Command) (int, string) {
	unit := strings.TrimSpace(c.Service)
	if !unitLogUnits[unit] {
		return 1, fmt.Sprintf("unit %q is not one this op may read", unit)
	}
	lines := unitLogDefaultLines
	for _, a := range c.Args {
		if v, ok := strings.CutPrefix(a, "lines="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				lines = n
			}
		}
	}
	// Bounded: an unbounded tail is a memory and disk amplifier reachable
	// by anyone who can queue a command.
	if lines > unitLogMaxLines {
		lines = unitLogMaxLines
	}
	rc, out := e.Runner.Capture(ctx, "/", "journalctl",
		"--unit", unit, "--lines", strconv.Itoa(lines), "--no-pager", "--output", "short-iso")
	if rc != 0 {
		return rc, fmt.Sprintf("journalctl for %s exited %d", unit, rc)
	}
	if err := os.WriteFile(filepath.Join(e.Spool, name+LogOutSuffix), []byte(out), 0o644); err != nil {
		return 1, "could not write the log payload: " + err.Error()
	}
	return 0, ""
}

// ReadLogOut loads the payload an op wrote beside its result, and removes
// it — a tail is read once and must not accumulate in the spool.
func ReadLogOut(spool, name string) (string, error) {
	p := filepath.Join(spool, name+LogOutSuffix)
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	_ = os.Remove(p)
	return string(b), nil
}
