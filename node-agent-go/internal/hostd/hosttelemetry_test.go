// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostd

import (
	"context"
	"reflect"
	"testing"
)

func fakeTailscaled(t *testing.T, root, pid, cmdline, environ string) {
	write(t, root, "proc/"+pid+"/comm", "tailscaled\n")
	write(t, root, "proc/"+pid+"/cmdline", cmdline)
	write(t, root, "proc/"+pid+"/environ", environ)
}

// The live host3 shape: no FLAGS, so the log upload is on.
func TestTailscaledWithoutTheSwitchIsReportedOn(t *testing.T) {
	root := t.TempDir()
	fakeTailscaled(t, root, "812",
		"/usr/sbin/tailscaled\x00--state=/var/lib/tailscale/tailscaled.state\x00--socket=/run/tailscale/tailscaled.sock\x00--port=41641\x00",
		"PATH=/usr/bin\x00")
	write(t, root, "etc/default/tailscaled", "# Set the port to listen on for incoming VPN packets.\nPORT=\"41641\"\nFLAGS=\"\"\n")
	f := CollectHostFacts(context.Background(), root, &fakeRunner{})
	if f.Telemetry == nil || f.Telemetry.TailscaleLogs != TailscaleLogsOn {
		t.Fatalf("telemetry = %+v, want tailscale_logs on", f.Telemetry)
	}
	if f.Telemetry.TailscaleLogsConfigured {
		t.Fatal("FLAGS=\"\" must not read as configured")
	}
}

func TestTailscaledSwitchIsFoundOnTheCommandLineOrInTheEnvironment(t *testing.T) {
	for name, tc := range map[string]struct{ cmd, env string }{
		"flag":      {"/usr/sbin/tailscaled\x00--no-logs-no-support\x00", ""},
		"flag=true": {"/usr/sbin/tailscaled\x00--no-logs-no-support=true\x00", ""},
		"env":       {"/usr/sbin/tailscaled\x00--port=41641\x00", "TS_NO_LOGS_NO_SUPPORT=true\x00"},
	} {
		root := t.TempDir()
		fakeTailscaled(t, root, "9", tc.cmd, tc.env)
		if got := tailscaleLogsState(root); got != TailscaleLogsOff {
			t.Errorf("%s: state = %q, want off", name, got)
		}
	}
	root := t.TempDir()
	fakeTailscaled(t, root, "9", "/usr/sbin/tailscaled\x00--no-logs-no-support=false\x00", "TS_NO_LOGS_NO_SUPPORT=0\x00")
	if got := tailscaleLogsState(root); got != TailscaleLogsOn {
		t.Errorf("explicit false: state = %q, want on", got)
	}
}

func TestTailscaledNotRunningOrUnreadable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "proc/1/comm", "systemd\n")
	if got := tailscaleLogsState(root); got != TailscaleLogsNotRunning {
		t.Fatalf("got %q", got)
	}
	write(t, root, "proc/5/comm", "tailscaled\n") // no cmdline file
	if got := tailscaleLogsState(root); got != TailscaleLogsUnknown {
		t.Fatalf("got %q", got)
	}
}

func TestConfiguredDefaultsFile(t *testing.T) {
	yes := []string{
		"FLAGS=\"--no-logs-no-support\"\n",
		"PORT=41641\nFLAGS='--tun=userspace-networking --no-logs-no-support'\n",
		"TS_NO_LOGS_NO_SUPPORT=true\n",
	}
	no := []string{"", "FLAGS=\"\"\n", "# FLAGS=\"--no-logs-no-support\"\n", "TS_NO_LOGS_NO_SUPPORT=false\n", "FLAGS=\"--no-logs-no-supportX\"\n"}
	for _, c := range yes {
		if !tailscaleDefaultsHaveSwitch(c) {
			t.Errorf("not found in %q", c)
		}
	}
	for _, c := range no {
		if tailscaleDefaultsHaveSwitch(c) {
			t.Errorf("false positive in %q", c)
		}
	}
}

func TestOSReportersAreReportedNotChanged(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/default/motd-news", "# comment\nENABLED=1\nURLS=\"https://motd.ubuntu.com\"\n")
	write(t, root, "etc/popularity-contest.conf", "PARTICIPATE=\"yes\"\n")
	r := &fakeRunner{stdout: map[string]string{"systemctl is-active whoopsie": "active"}}
	got := osReporters(context.Background(), root, r)
	want := []string{"motd-news", "popularity-contest", "whoopsie"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Everything off.
	root = t.TempDir()
	write(t, root, "etc/default/motd-news", "ENABLED=0\n")
	write(t, root, "etc/popularity-contest.conf", "PARTICIPATE=\"no\"\n")
	if got := osReporters(context.Background(), root, &fakeRunner{}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	// Reporting only: no write op ran.
	for _, c := range r.joined() {
		if c != "systemctl is-active whoopsie" {
			t.Errorf("unexpected command %q", c)
		}
	}
}

func TestDarwinBrewTailscaledJudgedFromPlistAndProcess(t *testing.T) {
	root := t.TempDir()
	// An App Store / Standalone Tailscale: no brew plist.
	if got := collectDarwinTelemetry(context.Background(), root, &fakeRunner{}); got.TailscaleLogs != TailscaleLogsUnmanaged {
		t.Fatalf("got %+v", got)
	}
	write(t, root, tailscaleBrewPlist, "<plist/>")
	// Plist lacks the key, process running without it.
	r := &fakeRunner{stdout: map[string]string{"pgrep": "412", "ps eww": "412 tailscaled PATH=/usr/bin HOME=/var/root"}}
	got := collectDarwinTelemetry(context.Background(), root, r)
	if got.TailscaleLogs != TailscaleLogsOn || got.TailscaleLogsConfigured {
		t.Fatalf("got %+v", got)
	}
	// Key in the plist and in the process.
	r = &fakeRunner{stdout: map[string]string{
		"PlistBuddy": "true", "pgrep": "412", "ps eww": "412 tailscaled PATH=/usr/bin TS_NO_LOGS_NO_SUPPORT=true"}}
	got = collectDarwinTelemetry(context.Background(), root, r)
	if got.TailscaleLogs != TailscaleLogsOff || !got.TailscaleLogsConfigured {
		t.Fatalf("got %+v", got)
	}
	// Key in the plist, process predates it (needs the restart).
	r = &fakeRunner{stdout: map[string]string{"PlistBuddy": "true", "pgrep": "412", "ps eww": "412 tailscaled PATH=/usr/bin"}}
	got = collectDarwinTelemetry(context.Background(), root, r)
	if got.TailscaleLogs != TailscaleLogsOn || !got.TailscaleLogsConfigured {
		t.Fatalf("got %+v", got)
	}
}

func TestOperatorOptInMarkerIsReportedAndRemovingItReverts(t *testing.T) {
	root := t.TempDir()
	fakeTailscaled(t, root, "9", "/usr/sbin/tailscaled\x00", "PATH=/usr/bin\x00")
	if f := collectHostTelemetry(context.Background(), root, &fakeRunner{}); f.TailscaleLogsOperatorChoice || f.TailscaleLogs != TailscaleLogsOn {
		t.Fatalf("no marker: %+v", f)
	}
	write(t, root, TailscaleUploadMarker, "")
	f := collectHostTelemetry(context.Background(), root, &fakeRunner{})
	if !f.TailscaleLogsOperatorChoice || f.TailscaleLogs != TailscaleLogsOn {
		t.Fatalf("marker: %+v", f)
	}
	// Mac reads the same marker.
	write(t, root, tailscaleBrewPlist, "<plist/>")
	if m := collectDarwinTelemetry(context.Background(), root, &fakeRunner{}); !m.TailscaleLogsOperatorChoice {
		t.Fatalf("darwin: %+v", m)
	}
}

// Current Homebrew names the daemon sh.brew.tailscale; it must be judged too.
func TestDarwinCurrentBrewLabelIsJudged(t *testing.T) {
	root := t.TempDir()
	write(t, root, tailscaleBrewPlistCurrent, "<plist/>")
	r := &fakeRunner{stdout: map[string]string{
		"PlistBuddy": "true", "pgrep": "412", "ps eww": "412 tailscaled PATH=/usr/bin TS_NO_LOGS_NO_SUPPORT=true"}}
	got := collectDarwinTelemetry(context.Background(), root, r)
	if got.TailscaleLogs != TailscaleLogsOff || !got.TailscaleLogsConfigured {
		t.Fatalf("sh.brew.tailscale not judged: %+v", got)
	}
}
