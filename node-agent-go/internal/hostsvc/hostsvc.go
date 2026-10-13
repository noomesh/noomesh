// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package hostsvc is the agent's control over the ONE host service it
// regulates: the harness.
//
// The harness is not a container and not a child of the agent. It is a
// systemd unit (a LaunchDaemon on darwin) installed by the applier as its
// own user, and the agent starts and stops it per placement — placed =
// running — through the narrowest root it could be given: a sudoers
// drop-in for start|stop|restart of this unit and nothing else, written by
// noo-apply beside the unit (the design is why the agent is not its
// parent: the agent is in the docker group, and a child inherits that).
//
// Reading state needs no root at all: `systemctl is-active` answers any
// caller. So the heartbeat can say running|stopped|absent honestly on
// every tick, whatever the grant looks like.
package hostsvc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// State is what the heartbeat carries for the service.
type State string

const (
	// Absent: the unit is not installed on this node — a pre-52 node, or
	// one whose bundle carried no harness. Starting it is not possible;
	// the fix is `noo upgrade --nodes` on a release that has the asset.
	Absent State = "absent"
	// Stopped: installed, not running.
	Stopped State = "stopped"
	// Running: installed and active.
	Running State = "running"
)

// Service is the lifecycle the reconciler drives. One implementation per
// init system, plus a fake for tests.
type Service interface {
	// State never needs privilege and never returns an error for "not
	// running": absence and inactivity are states, not failures.
	State(ctx context.Context) State
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
	// Runtime names the supervisor for the heartbeat's backend_runtimes.
	Runtime() string

	// Restarts is how many times the service manager has restarted this
	// unit, and whether it could be read at all. A CLIMBING value between
	// ticks is timing-free proof of a crash loop — which `State` cannot
	// give, because the unit is Type=simple with Restart=always and no
	// start limit, so `is-active` cycles through active / activating /
	// failed / inactive depending on the instant you look.
	Restarts(ctx context.Context) (uint64, bool)

	// WhyNotRunning explains, in the service manager's own words, why the
	// unit is not staying up. Empty when it has nothing to add.
	WhyNotRunning(ctx context.Context) string
}

// UnitName is the systemd unit and the sudoers grant's subject.
const UnitName = "noo-harness"

// LaunchdLabel is the darwin LaunchDaemon label (provision's plist).
const LaunchdLabel = "net.noomesh.harness"

// ErrNoGrant is the start/stop failure that means the sudoers drop-in is
// missing or wrong — the applier installs it beside the unit, so on a node
// that has the unit this is a real misconfiguration, named as such.
// Kept because a STOP that hostd rejects still needs a name reconcile can
// match on, and because an older agent's recorded refusal may quote it.
// The sudoers drop-in it originally described is gone: it could not work
// under NoNewPrivileges and noo-apply now deletes it.
var ErrNoGrant = errors.New("the node refused this lifecycle request (the harness is driven through noo-hostd's harness-start/harness-stop ops, not sudo)")

// OpHarnessStart / OpHarnessStop are the hostd op names this package asks
// for. Named constants because the heartbeat's advertised op list is
// matched against them — a typo would read as "the daemon is too old".
const (
	OpHarnessStart = "harness-start"
	OpHarnessStop  = "harness-stop"
)

// ErrNoHostd is the node's confined-root daemon being absent or stale. The
// harness cannot be started without it, and that is a node-level fault
// rather than anything about the harness.
var ErrNoHostd = errors.New("the node's privileged helper (noo-hostd) is not running, so the harness cannot be started or stopped")

// ErrOpUnsupported is a hostd too old to know the harness ops — "upgrade
// this node", which is a different instruction from ErrNoHostd's.
var ErrOpUnsupported = errors.New("this node's noo-hostd predates the harness lifecycle ops (run `noo upgrade --nodes`)")

// ErrAbsent is a start of a unit that is not installed.
// The text names WHERE this agent looked, and does not tell the operator
// to re-run the upgrade: on host6 the unit WAS installed —
// in the system launchd domain — while the agent looked in the user's
// LaunchAgents, and "run noo upgrade --nodes" was a ready-made wrong
// explanation that would have sent an operator round the same loop.
var ErrAbsent = errors.New("the harness service is not installed where this agent looks for it")

// New picks the implementation for this host.
func New() Service {
	if runtime.GOOS == "darwin" {
		return &launchd{}
	}
	return &systemd{}
}

// ───────────────────────── systemd ─────────────────────────

type systemd struct{}

func (s *systemd) Runtime() string { return "systemd" }

func (s *systemd) State(ctx context.Context) State {
	if _, err := os.Stat("/etc/systemd/system/" + UnitName + ".service"); err != nil {
		return Absent
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// is-active exits 0 for active, non-zero otherwise; the word on stdout
	// is the state. Unprivileged.
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", UnitName).Output()
	if strings.TrimSpace(string(out)) == "active" {
		return Running
	}
	return Stopped
}

// Restarts reads systemd's own restart counter.
//
// This is the DETECTION, and `State` cannot be: the harness unit is
// Type=simple with `Restart=always`, `RestartSec=30` and the start limit
// deliberately disabled, so systemd restarts a dying harness forever and
// `is-active` reports whatever phase the cycle happens to be in. A check
// right after a start would pass falsely when it lands before the process
// dies, and refuse falsely when it lands during a slow start — and a
// flapping refusal trains an operator to ignore the field.
//
// `NRestarts` needs no window. With `Restart=always`, a value that climbed
// since the last tick means it died and was restarted. Unprivileged.
func (s *systemd) Restarts(ctx context.Context) (uint64, bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show", UnitName, "-p", "NRestarts").Output()
	if err != nil {
		return 0, false
	}
	_, v, ok := strings.Cut(strings.TrimSpace(string(out)), "=")
	if !ok || v == "" {
		return 0, false
	}
	n, perr := strconv.ParseUint(v, 10, 64)
	if perr != nil {
		return 0, false
	}
	return n, true
}

// WhyNotRunning asks systemd what became of the unit.
//
// `systemctl start` on a Type=simple unit returns 0 the moment systemd
// forks the process — so a harness whose binary cannot run, or whose env is
// incomplete, produces a SUCCESSFUL start and a dead unit. Before
// 2026-09-19 that combination was invisible: the agent cleared the refusal,
// the next tick found it stopped and started it again, and the controller
// saw a harness that was never running and never refused. This is what it
// reports instead. All four properties are readable unprivileged.
func (s *systemd) WhyNotRunning(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show", UnitName,
		"-p", "Result", "-p", "ExecMainStatus", "-p", "ExecMainCode", "-p", "StatusText",
	).Output()
	if err != nil {
		return ""
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && v != "" {
			fields[k] = v
		}
	}
	// `Result=success` with the unit not running means it exited cleanly —
	// worth saying differently from a crash, because the remedy differs.
	var parts []string
	if r := fields["Result"]; r != "" {
		parts = append(parts, "result="+r)
	}
	if st := fields["ExecMainStatus"]; st != "" && st != "0" {
		parts = append(parts, "exit_status="+st)
	}
	if txt := fields["StatusText"]; txt != "" {
		parts = append(parts, "status="+txt)
	}
	return strings.Join(parts, " ")
}

func (s *systemd) Start(ctx context.Context) error { return s.lifecycle(ctx, OpHarnessStart) }
func (s *systemd) Stop(ctx context.Context) error  { return s.lifecycle(ctx, OpHarnessStop) }

// Restart is stop-then-start: hostd has no harness-restart op, and adding
// one would be a third name for something the two existing ops compose.
// A stop that fails because it is already stopped must not block the start.
func (s *systemd) Restart(ctx context.Context) error {
	if s.State(ctx) == Running {
		if err := s.lifecycle(ctx, OpHarnessStop); err != nil {
			return err
		}
	}
	return s.lifecycle(ctx, OpHarnessStart)
}

// sudo runs exactly the verb the drop-in grants. -n: never prompt — a
// missing grant fails now, with sudo's own words, rather than hanging the
// reconcile tick on a password nobody will type.
// lifecycle asks the node's confined-root daemon to start or stop the
// harness. It replaces a `sudo -n systemctl` call that COULD NOT WORK.
//
// `noo-node-agent.service` runs as `noo-agent` with `NoNewPrivileges=true`
// (which took the agent off root). That flag makes
// setuid binaries inert, so sudo can never elevate no matter what
// /etc/sudoers.d grants. On 2026-09-19 host3's first harness start failed
// with sudo's own words — "the 'no new privileges' flag is set, which
// prevents sudo from running as root" — with the drop-in installed and
// valid. Two correct hardening decisions that cannot compose.
//
// hostd is the answer that costs nothing: it is already root on this node,
// already runs `systemctl` on named units, already reads a spool the agent
// already writes, and its op table is fixed — `harness-start` takes no
// unit name from us, so this can never widen into "the agent may start any
// unit". The sudoers drop-in is removed rather than replaced.
func (s *systemd) lifecycle(ctx context.Context, op string) error {
	if s.State(ctx) == Absent {
		return fmt.Errorf("%w (%s)", ErrAbsent, "/etc/systemd/system/"+UnitName+".service")
	}
	return lifecycleViaHostd(ctx, op)
}

// lifecycleViaHostd asks the node's confined-root daemon for a harness op
// and waits for the answer. Shared by systemd and launchd: the runtime
// differs, the delegation does not, and neither agent has the privilege to
// do this itself — NoNewPrivileges on Linux, the user-vs-system launchd
// domain on Darwin.
func lifecycleViaHostd(ctx context.Context, op string) error {
	hb, err := hostd.ReadHeartbeat(hostd.WorkerSpoolDir)
	if err != nil {
		return fmt.Errorf("%w: no heartbeat at %s (%v)", ErrNoHostd, hostd.WorkerSpoolDir, err)
	}
	if hb.Stale(time.Now().UTC()) {
		return fmt.Errorf("%w: heartbeat is stale (published %s)", ErrNoHostd, hb.TS)
	}
	// A daemon too old to know the op is a DIFFERENT failure from a dead
	// one, and the operator needs to be told which: one is "upgrade the
	// node", the other is "the node's privileged helper is down".
	if !hb.Supports(op) {
		return fmt.Errorf("%w: hostd %s serves [%s]", ErrOpUnsupported, hb.Version, strings.Join(hb.Ops, " "))
	}
	// Stamped so serial requests never collide on result files — the
	// daemon claims by rename and a duplicate name would shadow an earlier
	// result (same reason fetch-bundle and swap-agent stamp theirs).
	name := fmt.Sprintf("%s-%d", op, time.Now().UTC().UnixNano())
	if err := hostd.WriteCommand(hostd.WorkerSpoolDir, name, hostd.Command{
		Op:          op,
		Service:     UnitName,
		RequestedBy: "node-agent:reconcile/harness",
	}); err != nil {
		return fmt.Errorf("could not queue %s: %w", op, err)
	}
	// Wait for the result: convergeHarness needs to know whether the start
	// took, so it can record a refusal naming the reason rather than leave
	// the controller to infer one from silence.
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for {
		res, rerr := hostd.ReadResult(hostd.WorkerSpoolDir, name)
		if rerr == nil {
			if res.RC == 0 {
				return nil
			}
			return fmt.Errorf("%s: rc=%d: %s", op, res.RC, strings.TrimSpace(res.Stderr))
		}
		if !os.IsNotExist(rerr) {
			return fmt.Errorf("%s: result unreadable: %w", op, rerr)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: hostd did not answer within 60s (command %s still queued)", op, name)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// ───────────────────────── launchd ─────────────────────────

// launchd drives the LaunchAgent the darwin applier installs for the
// enrolling user (the agent on a Mac runs as that user, so no sudo).
type launchd struct{}

func (l *launchd) Runtime() string { return "launchd" }

func (l *launchd) plist() string {
	// The provision bundle installs the harness as a SYSTEM LaunchDaemon
	// (node_fetch.rs, root applier). This used to look in the user's
	// LaunchAgents, so a correctly installed harness read as Absent forever
	// (host6, 2026-09-22).
	return hostd.HarnessLaunchdPlist
}

func (l *launchd) target() string { return "system/" + hostd.HarnessLaunchdLabel }

// Restarts: launchd exposes no restart counter through `launchctl print`,
// so darwin relies on state plus the last exit status. Reported as
// unavailable rather than zero, so the caller can tell "no counter here"
// from "never restarted".
func (l *launchd) Restarts(context.Context) (uint64, bool) { return 0, false }

// WhyNotRunning: launchd's own record of the last exit, from
// `launchctl print system/<label>`, which is readable without privilege.
func (l *launchd) WhyNotRunning(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "launchctl", "print", l.target()).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "last exit code") || strings.HasPrefix(t, "last exit reason") {
			if _, v, ok := strings.Cut(t, "="); ok {
				return "last_exit=" + strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func (l *launchd) State(ctx context.Context) State {
	if _, err := os.Stat(l.plist()); err != nil {
		return Absent
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// `launchctl print system/<label>` exits 0 only when the job is
	// bootstrapped into the system domain; with KeepAlive that means
	// running or about to be. Reading state needs no privilege.
	out, err := exec.CommandContext(ctx, "launchctl", "print", l.target()).Output()
	if err != nil {
		return Stopped
	}
	if strings.Contains(string(out), "state = running") {
		return Running
	}
	return Stopped
}

// Start and Stop go through noo-hostd, exactly as on Linux. The agent runs
// as the user and cannot bootstrap a system LaunchDaemon; the daemon can.
func (l *launchd) Start(ctx context.Context) error {
	if l.State(ctx) == Absent {
		return fmt.Errorf("%w (%s)", ErrAbsent, l.plist())
	}
	return lifecycleViaHostd(ctx, OpHarnessStart)
}

func (l *launchd) Stop(ctx context.Context) error {
	if l.State(ctx) == Absent {
		return fmt.Errorf("%w (%s)", ErrAbsent, l.plist())
	}
	return lifecycleViaHostd(ctx, OpHarnessStop)
}

func (l *launchd) Restart(ctx context.Context) error {
	if err := l.Stop(ctx); err != nil {
		return err
	}
	return l.Start(ctx)
}

// ───────────────────────── fake (tests) ─────────────────────────

// Fake records what the reconciler asked for.
type Fake struct {
	Cur   State
	Calls []string
	// Fail makes the named verb return this error.
	Fail map[string]error
	// Why is what WhyNotRunning reports; startDies makes a SUCCESSFUL
	// start leave the service stopped, which is what a Type=simple unit
	// whose process exits immediately does.
	Why       string
	startDies bool
	// NRestarts is what Restarts reports; NoCounter makes it unavailable.
	NRestarts uint64
	NoCounter bool
}

func (f *Fake) Runtime() string { return "fake" }

func (f *Fake) State(context.Context) State { return f.Cur }

// StartDies models the case the live fleet hit: the start SUCCEEDS and the
// process is gone by the time anyone looks. `Why` is what the service
// manager would say about it.
func (f *Fake) SetStartDies(why string) { f.startDies, f.Why = true, why }

// Restarts models systemd's counter; NoCounter models darwin, where there
// is none to read.
func (f *Fake) Restarts(context.Context) (uint64, bool) {
	return f.NRestarts, !f.NoCounter
}

func (f *Fake) WhyNotRunning(context.Context) string { return f.Why }

func (f *Fake) do(verb string, next State) error {
	f.Calls = append(f.Calls, verb)
	if err, ok := f.Fail[verb]; ok && err != nil {
		return err
	}
	if f.Cur == Absent {
		return ErrAbsent
	}
	if f.startDies && next == Running {
		// rc=0, and the unit is not up.
		return nil
	}
	f.Cur = next
	return nil
}

func (f *Fake) Start(context.Context) error   { return f.do("start", Running) }
func (f *Fake) Stop(context.Context) error    { return f.do("stop", Stopped) }
func (f *Fake) Restart(context.Context) error { return f.do("restart", Running) }
