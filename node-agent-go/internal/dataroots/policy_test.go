// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The shape rule is mirrored in the noo CLI; both read the same cases.
func TestShapeMatchesTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "data-root-shape-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			OS, Home, Path, Code string
			OK                   bool
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 20 {
		t.Fatalf("only %d cases; the vectors file is not being read", len(doc.Cases))
	}
	for _, c := range doc.Cases {
		probs := CheckShape(c.Path, c.OS, c.Home)
		if c.OK && len(probs) != 0 {
			t.Errorf("%s %q: want ok, got %v", c.OS, c.Path, probs)
		}
		if !c.OK && (len(probs) == 0 || probs[0].Code != c.Code) {
			t.Errorf("%s %q: want %s, got %v", c.OS, c.Path, c.Code, probs)
		}
	}
}

func TestOwnershipNeedsTheAgentsAccountAndNoGroupWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "noo")
	if p := CheckOwnership(dir, os.Geteuid()); len(p) != 1 || p[0].Code != "missing" {
		t.Fatalf("missing dir: %v", p)
	}
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if p := CheckOwnership(dir, os.Geteuid()); len(p) != 0 {
		t.Fatalf("own 0750 dir should pass: %v", p)
	}
	if p := CheckOwnership(dir, os.Geteuid()+1); os.Geteuid() != 0 && (len(p) != 1 || p[0].Code != "wrong_owner") {
		t.Fatalf("another uid: %v", p)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if p := CheckOwnership(dir, os.Geteuid()); len(p) != 1 || p[0].Code != "writable_by_others" {
		t.Fatalf("group-writable: %v", p)
	}
}

func TestExplicitChildrenMustStayInsideTheRoot(t *testing.T) {
	r := Roots{NooDataRoot: "/var/lib/noo", HFCacheDir: "/var/lib/noo/hf-cache",
		ModelsDir: "/home/x/models", OllamaDataDir: "/var/lib/noo/ollama"}
	p := checkContainment(r)
	if len(p) != 1 || p[0].Code != "outside_root" || !strings.Contains(p[0].Detail, "MODELS_DIR") {
		t.Fatalf("got %v", p)
	}
}

func TestWarnReportsAndEnforceRefuses(t *testing.T) {
	probs := []Problem{{Code: "home_dir", Detail: "x"}}
	t.Setenv(PolicyEnv, "")
	if rep := PolicyReport(probs); rep["mode"] != "warn" || rep["ok"] != false {
		t.Fatalf("warn report: %v", rep)
	}
	if err := Refusal(probs); err != nil {
		t.Fatalf("warn mode must not refuse: %v", err)
	}
	t.Setenv(PolicyEnv, "enforce")
	if err := Refusal(probs); err == nil || !strings.Contains(err.Error(), "home_dir") {
		t.Fatalf("enforce must refuse naming the problem: %v", err)
	}
	if err := Refusal(nil); err != nil {
		t.Fatalf("a passing root is never refused: %v", err)
	}
	if rep := PolicyReport(nil); rep["ok"] != true || rep["mode"] != "enforce" {
		t.Fatalf("passing report: %v", rep)
	}
}

func TestDefaultsAreTheStandardLocations(t *testing.T) {
	if DefaultFor("linux", "/home/x") != "/var/lib/noo" {
		t.Fatal(DefaultFor("linux", "/home/x"))
	}
	if got := DefaultFor("darwin", "/Users/alice"); got != "/Users/alice/noomesh" {
		t.Fatal(got)
	}
	// The Mac agent's env file is sourced by a shell: a default with
	// whitespace is split on it and the node comes up with no data roots.
	for _, home := range []string{"/Users/alice", "/Users/alice/"} {
		if got := DefaultFor("darwin", home); strings.ContainsAny(got, " \t\n") {
			t.Fatalf("the darwin default has whitespace: %q", got)
		}
	}
	for _, c := range [][2]string{{"linux", ""}, {"darwin", "/Users/alice"}} {
		if p := CheckShape(DefaultFor(c[0], c[1]), c[0], c[1]); len(p) != 0 {
			t.Fatalf("the %s default fails its own shape rule: %v", c[0], p)
		}
	}
}

// The controller's self-agent shares the operator's root: the node may
// declare that owner in its own env, and nothing else widens the rule.
func TestADeclaredOwnerIsAcceptedOnlyWhenDeclared(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns everything it creates; the case needs a non-root uid")
	}
	dir := filepath.Join(t.TempDir(), "noo")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	other := os.Geteuid() + 1
	t.Setenv(OwnerEnv, "")
	if p := CheckOwnership(dir, other); len(p) != 1 || p[0].Code != "wrong_owner" {
		t.Fatalf("undeclared owner must fail: %v", p)
	}
	t.Setenv(OwnerEnv, strconv.Itoa(os.Geteuid()))
	if p := CheckOwnership(dir, other); len(p) != 0 {
		t.Fatalf("declared owner must pass: %v", p)
	}
	t.Setenv(OwnerEnv, "not-a-uid")
	if p := CheckOwnership(dir, other); len(p) != 1 {
		t.Fatalf("a junk declaration must not widen the rule: %v", p)
	}
}

// Release-session rehearsal ask: an undeclared node whose data sits on an
// earlier default must NOT move to /var/lib/noo on upgrade.
func TestAnUndeclaredNodeKeepsItsLegacyRoot(t *testing.T) {
	defer func() { adoptedLegacy = "" }()
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	set := func(k, v string) error { env[k] = v; return nil }
	exists := map[string]bool{"/data/noo": true}
	isDir := func(d string) bool { return exists[d] }

	// implicit /data/noo (with its running mounts) -> stays /data/noo
	if got := AdoptLegacyRoot(get, set, isDir); got != "/data/noo" {
		t.Fatalf("adopted %q, want /data/noo", got)
	}
	r := Resolve(get)
	if r.NooDataRoot != "/data/noo" || r.NooDataRootSource != "legacy_default" {
		t.Fatalf("resolved %+v", r)
	}
	if r.ModelsDir != "/data/noo/models" {
		t.Fatalf("children must follow the kept root: %+v", r)
	}
	probs := Check(r, "linux", "", 0)
	if len(probs) == 0 || probs[0].Code != "undeclared_root" {
		t.Fatalf("a kept legacy root must ask to be declared: %v", probs)
	}

	// /mnt/d/noo was the default before #754; it wins when present.
	adoptedLegacy, env = "", map[string]string{}
	exists["/mnt/d/noo"] = true
	if got := AdoptLegacyRoot(get, set, isDir); got != "/mnt/d/noo" {
		t.Fatalf("adopted %q, want /mnt/d/noo", got)
	}

	// A declared root is never overridden.
	adoptedLegacy, env = "", map[string]string{"NOO_DATA_ROOT": "/srv/storage/noo"}
	if got := AdoptLegacyRoot(get, set, isDir); got != "" || env["NOO_DATA_ROOT"] != "/srv/storage/noo" {
		t.Fatalf("declared root touched: adopted %q, env %q", got, env["NOO_DATA_ROOT"])
	}

	// Fresh node, no legacy dir: today's default, nothing adopted.
	adoptedLegacy, env, exists = "", map[string]string{}, map[string]bool{}
	if got := AdoptLegacyRoot(get, set, isDir); got != "" {
		t.Fatalf("adopted %q on a fresh node", got)
	}
	if r := Resolve(get); r.NooDataRoot != DefaultDataRoot || r.NooDataRootSource != "default" {
		t.Fatalf("fresh node: %+v", r)
	}
}

// A root the agent cannot stat (a 0700 home dir) says so plainly, not as a
// raw stat error spliced after the shape verdict (v0.2.92-rc.1 rehearsal).
func TestAnUninspectableRootSaysSoPlainly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can stat anything")
	}
	parent := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(filepath.Join(parent, "noo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0o755)
	p := CheckOwnership(filepath.Join(parent, "noo"), os.Geteuid())
	if len(p) != 1 || p[0].Code != "unreadable" {
		t.Fatalf("got %v", p)
	}
	d := p[0].Detail
	if !strings.Contains(d, "could not inspect ownership") || !strings.Contains(d, "permission denied for the agent's account") ||
		strings.Contains(d, "stat ") {
		t.Fatalf("detail = %q", d)
	}
}

// A Mac that already used the Application Support default (#754) keeps its
// data there; a fresh Mac gets the space-free default.
func TestADarwinNodeKeepsTheApplicationSupportLegacyRoot(t *testing.T) {
	defer func() { adoptedLegacy = "" }()
	legacy := "/Users/alice/Library/Application Support/noo"
	env := map[string]string{"HOME": "/Users/alice"}
	get := func(k string) string { return env[k] }
	set := func(k, v string) error { env[k] = v; return nil }
	isDir := func(d string) bool { return d == legacy }

	if got := adoptLegacyRoot("darwin", get, set, isDir); got != legacy {
		t.Fatalf("adopted %q, want %q", got, legacy)
	}
	if env["NOO_DATA_ROOT"] != legacy {
		t.Fatalf("env %q", env["NOO_DATA_ROOT"])
	}
	// The legacy root is still a legal shape on macOS.
	if p := CheckShape(legacy, "darwin", "/Users/alice"); len(p) != 0 {
		t.Fatalf("legacy root refused: %v", p)
	}
	// Linux never looks for it.
	adoptedLegacy, env = "", map[string]string{"HOME": "/Users/alice"}
	if got := adoptLegacyRoot("linux", get, set, isDir); got != "" {
		t.Fatalf("linux adopted %q", got)
	}
	// Nothing on disk: nothing adopted, the default stands.
	adoptedLegacy, env = "", map[string]string{"HOME": "/Users/alice"}
	if got := adoptLegacyRoot("darwin", get, set, func(string) bool { return false }); got != "" {
		t.Fatalf("adopted %q on a fresh Mac", got)
	}
}
