// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package backendrt

import (
	"strings"
	"testing"

	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// Followup i1156: the native lane is a Mac's only Ollama lane.

func TestOnlyTheNativeLaneIsExclusive(t *testing.T) {
	var none *Native
	if none.Exclusive() || none.NativeOnly("ollama") {
		t.Fatal("no lane (Linux) is never exclusive")
	}
	if NewStackAt("http://127.0.0.1:1").NativeOnly("ollama") {
		t.Fatal("the self-node's stack lane is not exclusive")
	}
	mac := NewNativeAt("http://127.0.0.1:1")
	if !mac.NativeOnly("ollama") {
		t.Fatal("a Mac's native lane is ollama's only lane")
	}
	if mac.NativeOnly("llamacpp") {
		t.Fatal("the native lane serves only ollama")
	}
}

// The remedy text: start it when the binary is there, install it first when
// it is not. Both name the boot service run as the node's user and `noo enroll`.
func TestNativeDownRemedyText(t *testing.T) {
	present := (&NativeDownError{Backend: "ollama", BinaryPresent: true, User: "nodeuser"}).Error()
	if want := "the native Ollama isn't running on this Mac: start it with " +
		"`sudo HOMEBREW_NO_ANALYTICS=1 brew services start --sudo-service-user nodeuser ollama` (a boot service), or run `noo enroll --resume`"; present != want {
		t.Fatalf("binary present:\n got %s\nwant %s", present, want)
	}
	absent := (&NativeDownError{Backend: "ollama", User: "nodeuser"}).Error()
	if want := "the native Ollama isn't installed on this Mac: install it: `HOMEBREW_NO_ANALYTICS=1 brew install ollama`, then start it with " +
		"`sudo HOMEBREW_NO_ANALYTICS=1 brew services start --sudo-service-user nodeuser ollama` (a boot service), or run `noo enroll --resume`"; absent != want {
		t.Fatalf("binary absent:\n got %s\nwant %s", absent, want)
	}
	if got := OllamaBootServiceCmd(""); !strings.Contains(got, `--sudo-service-user "$USER" ollama`) {
		t.Fatalf("unknown user: %s", got)
	}
}

// guardSystem: the boot-service plist exists (enroll's), no user LaunchAgent.
func guardSystem(f *fakeMac, label string) *OllamaGuard {
	p := OllamaSystemPlistPath(label)
	return &OllamaGuard{Home: "/Users/m", UID: 501, Run: f.run, Exists: func(q string) bool { return q == p }}
}

// The agent cannot write root's plist: it never tries, never restarts, and
// records one refusal with the sudo commands instead.
func TestABootServicePlistIsReportedNeverWritten(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	f := &fakeMac{}
	g := guardSystem(f, newBrew)
	managed, restarted, err := g.Converge()
	if err != nil || !managed || restarted {
		t.Fatalf("managed=%v restarted=%v err=%v", managed, restarted, err)
	}
	if f.had("-replace") || f.had("bootout") || f.had("bootstrap") || f.had("-insert") {
		t.Fatalf("the agent wrote or restarted a root-owned plist: %v", f.cmds)
	}
	var why string
	for _, r := range refusals.List() {
		if r.Scope == "ollama_env" {
			why = r.Reason
		}
	}
	plist := "/Library/LaunchDaemons/sh.brew.ollama.plist"
	if !strings.Contains(why, "sudo "+plutilBin+" -replace EnvironmentVariables.OLLAMA_NO_CLOUD -string '1' "+plist) ||
		!strings.Contains(why, "sudo launchctl bootstrap system "+plist) {
		t.Fatalf("refusal = %q", why)
	}
	e := g.Report(true)
	if e["managed"] != true || e["plist_domain"] != "system" || e["plist_label"] != newBrew {
		t.Fatalf("report: %v", e)
	}

	// Once the plist carries the switch, the refusal clears.
	f.env = map[string]string{ollamaNoCloud: "1"}
	if _, _, err := g.Converge(); err != nil {
		t.Fatal(err)
	}
	for _, r := range refusals.List() {
		if r.Scope == "ollama_env" {
			t.Fatalf("refusal kept after the switch was set: %v", r)
		}
	}
}

// A stopped native Ollama's report says whether the binary is installed.
func TestReportOfAStoppedOllamaNamesTheBinary(t *testing.T) {
	prev := OllamaBinaryPresent
	OllamaBinaryPresent = func() bool { return false }
	t.Cleanup(func() { OllamaBinaryPresent = prev })
	e := guardSystem(&fakeMac{}, newBrew).Report(false)
	if e["running"] != false || e["binary_present"] != false {
		t.Fatalf("report: %v", e)
	}
	if _, ok := guardSystem(&fakeMac{}, newBrew).Report(true)["binary_present"]; ok {
		t.Fatal("a running ollama's report needs no binary probe")
	}
}
