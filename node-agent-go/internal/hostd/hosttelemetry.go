// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

// Host-software telemetry facts (docs/security/telemetry.md, "Host
// software"). noomesh's stance is zero vendor phone-home. The containers and
// node-agent backends carry their switches; this reports the two things on
// the HOST that noomesh installs or lives beside:
//
//   - tailscaled, which noomesh installs on every node. Tailscale's client
//     uploads operational logs to log.tailscale.io unless it is started with
//     --no-logs-no-support (or TS_NO_LOGS_NO_SUPPORT=true in its
//     environment). The same switch also opts out of Tailscale technical
//     support. noomesh's enroll sets it on a new node; for an existing node
//     hostd only REPORTS (verify prints the remedy): turning it on means
//     restarting tailscaled, which drops the tailnet link and, on the
//     controller, every node's path to it. A helper that restarts the node's
//     only route to the controller on its own is the wrong shape.
//   - the Ubuntu reporters that belong to the OS (motd-news, popularity-
//     contest, whoopsie crash upload). These are the operator's to decide, so
//     they are reported, never changed.
//
// Everything is read from the filesystem under root so tests can use a fake
// tree; the process is judged from /proc, not from the config file, because a
// file edited without a restart changes nothing.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Values of HostTelemetry.TailscaleLogs.
const (
	// TailscaleLogsOff: the running tailscaled carries the switch.
	TailscaleLogsOff = "off"
	// TailscaleLogsOn: it is running without the switch, so its log upload is live.
	TailscaleLogsOn = "on"
	// TailscaleLogsNotRunning: no tailscaled process.
	TailscaleLogsNotRunning = "not_running"
	// TailscaleLogsUnknown: running but its command line or environment could not be read.
	TailscaleLogsUnknown = "unknown"
	// TailscaleLogsUnmanaged: macOS, no brew tailscale plist: the Standalone
	// or App Store app, which Tailscale does not let anyone switch (its docs:
	// the flag works only with the open-source tailscaled).
	TailscaleLogsUnmanaged = "unmanaged"
)

// tailscaleBrewPlist is the brew formula's root LaunchDaemon under older
// Homebrew; tailscaleBrewPlistCurrent is its name under current Homebrew
// (labels moved from homebrew.mxcl.* to sh.brew.*). The newest present wins.
const (
	tailscaleBrewPlist        = "Library/LaunchDaemons/homebrew.mxcl.tailscale.plist"
	tailscaleBrewPlistCurrent = "Library/LaunchDaemons/sh.brew.tailscale.plist"
)

// tailscalePlist is the brew tailscale plist present under root, "" if none.
func tailscalePlist(root string) string {
	for _, p := range []string{tailscaleBrewPlistCurrent, tailscaleBrewPlist} {
		if exists(root, p) {
			return p
		}
	}
	return ""
}

// collectDarwinTelemetry judges the brew tailscaled on a Mac. hostd runs
// there as a root LaunchDaemon, so it can read the plist and the process's
// environment. Report only; `noo enroll` sets the key.
func collectDarwinTelemetry(ctx context.Context, root string, r Runner) *HostTelemetry {
	t := &HostTelemetry{OSReporters: []string{}, TailscaleLogs: TailscaleLogsUnmanaged}
	t.TailscaleLogsOperatorChoice = exists(root, TailscaleUploadMarker)
	rel := tailscalePlist(root)
	if rel == "" || r == nil {
		return t
	}
	plist := filepath.Join(root, rel)
	_, v := r.Capture(ctx, "", "/usr/libexec/PlistBuddy", "-c", "Print :EnvironmentVariables:"+tailscaleNoLogsEnv, plist)
	t.TailscaleLogsConfigured = truthy(v)
	rc, pids := r.Capture(ctx, "", "pgrep", "-x", "tailscaled")
	fields := strings.Fields(pids)
	if rc != 0 || len(fields) == 0 {
		t.TailscaleLogs = TailscaleLogsNotRunning
		return t
	}
	_, env := r.Capture(ctx, "", "ps", "eww", "-p", fields[0])
	switch {
	case strings.Contains(env, tailscaleNoLogsEnv+"=true") || strings.Contains(env, tailscaleNoLogsEnv+"=1"):
		t.TailscaleLogs = TailscaleLogsOff
	case strings.Contains(env, "PATH=") || strings.Contains(env, "HOME="):
		t.TailscaleLogs = TailscaleLogsOn
	default:
		t.TailscaleLogs = TailscaleLogsUnknown
	}
	return t
}

// HostTelemetry is the `telemetry` object inside HostFacts.
type HostTelemetry struct {
	// TailscaleLogs is judged from the running tailscaled process.
	TailscaleLogs string `json:"tailscale_logs"`
	// TailscaleLogsConfigured: /etc/default/tailscaled carries the switch
	// (FLAGS or TS_NO_LOGS_NO_SUPPORT), i.e. the next restart will have it.
	TailscaleLogsConfigured bool `json:"tailscale_logs_configured"`
	// TailscaleLogsOperatorChoice: the operator opted in to the upload (to
	// get Tailscale support) by creating TailscaleUploadMarker. verify then
	// shows WARN "by operator choice" instead of FAIL, and enroll leaves the
	// switch off. Removing the file puts the node back under the default.
	TailscaleLogsOperatorChoice bool `json:"tailscale_logs_operator_choice"`
	// OSReporters names the Ubuntu reporters that are enabled on this host.
	OSReporters []string `json:"os_reporters"`
}

// TailscaleUploadMarker is the per-node opt-in. Keep it identical to
// noo-cli/src/vendor.rs TAILSCALE_UPLOAD_MARKER (tests/test_no_vendor_telemetry.py
// compares them).
const TailscaleUploadMarker = "/etc/noo/allow-tailscale-log-upload"

const tailscaleNoLogsFlag = "no-logs-no-support"
const tailscaleNoLogsEnv = "TS_NO_LOGS_NO_SUPPORT"

// collectHostTelemetry reads the facts; never nil.
func collectHostTelemetry(ctx context.Context, root string, r Runner) *HostTelemetry {
	t := &HostTelemetry{OSReporters: []string{}}
	t.TailscaleLogs = tailscaleLogsState(root)
	t.TailscaleLogsConfigured = tailscaleDefaultsHaveSwitch(readFile(root, "etc/default/tailscaled"))
	t.TailscaleLogsOperatorChoice = exists(root, TailscaleUploadMarker)
	t.OSReporters = append(t.OSReporters, osReporters(ctx, root, r)...)
	return t
}

// truthy follows strconv.ParseBool, which is what Go's flag package and
// Tailscale's envknob both use for a boolean.
func truthy(v string) bool {
	b, err := strconv.ParseBool(strings.Trim(strings.TrimSpace(v), `"'`))
	return err == nil && b
}

// argHasNoLogs: one argv element is --no-logs-no-support, -no-logs-no-support,
// or either with =<bool>.
func argHasNoLogs(arg string) bool {
	a := strings.TrimLeft(arg, "-")
	if len(arg)-len(a) < 1 || len(arg)-len(a) > 2 {
		return false
	}
	if a == tailscaleNoLogsFlag {
		return true
	}
	if v, ok := strings.CutPrefix(a, tailscaleNoLogsFlag+"="); ok {
		return truthy(v)
	}
	return false
}

// tailscaleDefaultsHaveSwitch reads the contents of /etc/default/tailscaled.
// The systemd unit loads it as an EnvironmentFile and appends $FLAGS to the
// tailscaled command line.
func tailscaleDefaultsHaveSwitch(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "FLAGS":
			for _, f := range strings.Fields(strings.Trim(strings.TrimSpace(v), `"'`)) {
				if argHasNoLogs(f) {
					return true
				}
			}
		case tailscaleNoLogsEnv:
			if truthy(v) {
				return true
			}
		}
	}
	return false
}

// tailscaleLogsState judges the running tailscaled from /proc.
func tailscaleLogsState(root string) string {
	comms, _ := filepath.Glob(filepath.Join(root, "proc/[0-9]*/comm"))
	state := TailscaleLogsNotRunning
	for _, c := range comms {
		b, err := os.ReadFile(c)
		if err != nil || strings.TrimSpace(string(b)) != "tailscaled" {
			continue
		}
		dir := filepath.Dir(c)
		cmd, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			state = TailscaleLogsUnknown
			continue
		}
		for _, a := range strings.Split(string(cmd), "\x00") {
			if argHasNoLogs(a) {
				return TailscaleLogsOff
			}
		}
		env, err := os.ReadFile(filepath.Join(dir, "environ"))
		if err != nil {
			state = TailscaleLogsUnknown
			continue
		}
		for _, kv := range strings.Split(string(env), "\x00") {
			if v, ok := strings.CutPrefix(kv, tailscaleNoLogsEnv+"="); ok && truthy(v) {
				return TailscaleLogsOff
			}
		}
		if state != TailscaleLogsUnknown {
			state = TailscaleLogsOn
		}
	}
	return state
}

// shellValue reads KEY=value (optionally quoted) from a shell-style defaults
// file; "" when absent. Later lines win, as they do when the file is sourced.
func shellValue(content, key string) string {
	val := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			val = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return val
}

// osReporters lists the enabled Ubuntu reporters.
func osReporters(ctx context.Context, root string, r Runner) []string {
	var out []string
	// motd-news: fetches a message of the day from motd.ubuntu.com on login
	// and from a timer. /etc/default/motd-news ENABLED=1 turns it on.
	if shellValue(readFile(root, "etc/default/motd-news"), "ENABLED") == "1" {
		out = append(out, "motd-news")
	}
	// popularity-contest: weekly package-usage report to popcon.ubuntu.com.
	if strings.EqualFold(shellValue(readFile(root, "etc/popularity-contest.conf"), "PARTICIPATE"), "yes") {
		out = append(out, "popularity-contest")
	}
	// whoopsie: uploads apport crash reports to daisy.ubuntu.com.
	if r != nil {
		if _, s := r.Capture(ctx, "", "systemctl", "is-active", "whoopsie"); strings.TrimSpace(s) == "active" {
			out = append(out, "whoopsie")
		}
	}
	return out
}
