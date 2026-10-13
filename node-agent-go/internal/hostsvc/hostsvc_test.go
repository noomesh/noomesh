// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package hostsvc

import (
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/hostd"
)

// The refusal for a unit that is not where the agent looks must not carry
// a ready-made wrong explanation. On host6 the harness WAS
// installed — as a system LaunchDaemon — while the agent looked in the
// user's LaunchAgents, and the old text told the operator to re-run the
// upgrade, which would have changed nothing and sent them round again.
func TestAbsentRefusalNamesWhereItLookedAndNotAnUpgrade(t *testing.T) {
	msg := ErrAbsent.Error()
	if strings.Contains(msg, "upgrade") {
		t.Fatalf("ErrAbsent tells the operator to upgrade, which does not fix a path mismatch: %q", msg)
	}
	if !strings.Contains(msg, "where this agent looks") {
		t.Fatalf("ErrAbsent must say the unit is absent WHERE THIS AGENT LOOKS, got %q", msg)
	}
}

// One design, two runtimes: on Darwin the harness is a SYSTEM LaunchDaemon
// (the root applier installs it there), so the agent must look in the
// system domain, not the user's LaunchAgents — which is what read a
// correctly installed harness as Absent forever.
func TestDarwinHarnessLivesInTheSystemDomain(t *testing.T) {
	l := &launchd{}
	if got := l.plist(); got != "/Library/LaunchDaemons/net.noomesh.harness.plist" {
		t.Fatalf("launchd looks for the harness at %q; the applier installs it under /Library/LaunchDaemons", got)
	}
	if got := l.target(); got != "system/net.noomesh.harness" {
		t.Fatalf("launchd targets %q; the harness is bootstrapped into the system domain", got)
	}
	// And the path the agent checks is the path hostd acts on — the two
	// halves of the lifecycle must agree on one file.
	if l.plist() != hostd.HarnessLaunchdPlist {
		t.Fatalf("agent checks %q but hostd manages %q", l.plist(), hostd.HarnessLaunchdPlist)
	}
}

// The op names the agent asks for are the ones hostd advertises; a rename
// on either side reads as "this daemon is too old", which is silent.
func TestLifecycleOpNamesMatchHostd(t *testing.T) {
	for _, op := range []string{OpHarnessStart, OpHarnessStop} {
		if _, ok := hostd.LookupOpFor(hostd.ModeWorker, op); !ok {
			t.Fatalf("the agent asks hostd for %q and hostd's worker table does not serve it", op)
		}
	}
}
