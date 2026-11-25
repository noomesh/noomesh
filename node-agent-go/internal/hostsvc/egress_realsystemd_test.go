// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostsvc

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

// TestRealSystemdEgress runs the production egress reader with its real
// defaults (real systemctl, real self-test file, real harness-net hosts file,
// the real resolver) against a noo-harness unit a CI script has started. It
// is skipped unless NOO_REAL_SYSTEMD=1, so a developer machine never runs it.
// On failure it prints the whole Egress and the raw `systemctl show` output,
// so a property-format difference between systemd versions is visible.
// After the host rewrote a plain-file /etc/resolv.conf
// (tests/ci/harness-egress-systemd.sh, step f3): the live unit reads as
// enforced, with its private resolver file reported replaced.
func TestRealSystemdEgressResolvReplaced(t *testing.T) {
	if os.Getenv("NOO_REAL_SYSTEMD_RESOLV_REPLACED") != "1" {
		t.Skip("set NOO_REAL_SYSTEMD_RESOLV_REPLACED=1 to run against a real noo-harness unit after a host resolver rewrite")
	}
	got := DefaultEgressReader().Read(context.Background())
	if got.State != EgressEnforced || !got.PIDMatch {
		t.Fatalf("state = %q (%s), pid_match = %v; want enforced", got.State, got.Reason, got.PIDMatch)
	}
	if got.ResolvHeld == nil || *got.ResolvHeld {
		t.Fatalf("resolv_held = %v, want false (the private resolver file replaced)", got.ResolvHeld)
	}
}

func TestRealSystemdEgress(t *testing.T) {
	if os.Getenv("NOO_REAL_SYSTEMD") != "1" {
		t.Skip("set NOO_REAL_SYSTEMD=1 to run against a real noo-harness unit")
	}
	got := DefaultEgressReader().Read(context.Background())
	raw, err := exec.Command("systemctl", "show", UnitName, "-p", "MainPID", "-p", "IPAddressDeny",
		"-p", "IPAddressAllow", "-p", "BindReadOnlyPaths", "-p", "InaccessiblePaths").CombinedOutput()
	dump := func() {
		t.Helper()
		t.Logf("egress: %+v", got)
		t.Logf("systemctl show (err=%v):\n%s", err, raw)
	}
	if got.State != EgressEnforced {
		dump()
		t.Errorf("state = %q (%s), want enforced", got.State, got.Reason)
	}
	if got.Resolver != "unit" {
		dump()
		t.Errorf("resolver = %q, want unit", got.Resolver)
	}
	if !got.PIDMatch {
		dump()
		t.Errorf("pid_match = false")
	}
	if !denyCoversAny(got.IPDeny) {
		dump()
		t.Errorf("ip_deny %q does not cover any", got.IPDeny)
	}
	if len(got.StaleHosts) != 0 {
		dump()
		t.Errorf("stale_hosts = %v, want none", got.StaleHosts)
	}
}
