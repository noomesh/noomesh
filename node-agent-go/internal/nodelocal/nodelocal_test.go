// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package nodelocal

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type fakeEnv map[string]string

func (e fakeEnv) get(k string) string   { return e[k] }
func (e fakeEnv) set(k, v string) error { e[k] = v; return nil }
func (e fakeEnv) unset(k string) error  { delete(e, k); return nil }

// write puts body in a 0600 file owned by the test user and returns its path.
func write(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.local.env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func me() uint32 { return uint32(os.Getuid()) }

func run(t *testing.T, body string, env fakeEnv) *Report {
	t.Helper()
	return apply(write(t, body, 0o600), me(), me(), env.get, env.set, env.unset)
}

func declared(r *Report) string {
	var out []string
	for _, d := range r.Declared {
		out = append(out, d.Key+"@"+d.Source)
	}
	return strings.Join(out, ",")
}

func refusedKeys(r *Report) []string {
	var out []string
	for _, x := range r.Refused {
		out = append(out, x.Key)
	}
	return out
}

// ── the file ────────────────────────────────────────────────────────────────

func TestAnAbsentFileDeclaresNothing(t *testing.T) {
	env := fakeEnv{}
	r := apply(filepath.Join(t.TempDir(), "none"), me(), me(), env.get, env.set, env.unset)
	if r.State != "absent" || len(r.Declared) != 0 || len(env) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}

func TestAGroupWritableFileIsRefusedWhole(t *testing.T) {
	env := fakeEnv{}
	r := apply(write(t, "NOO_ALLOW_OLLAMA_REGISTRY_PULL=1\n", 0o620), me(), me(), env.get, env.set, env.unset)
	if r.State != "refused" || !strings.Contains(r.Why, "group- or world-writable") || len(env) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}

func TestAWorldWritableFileIsRefusedWhole(t *testing.T) {
	env := fakeEnv{}
	r := apply(write(t, "NOO_ALLOW_OLLAMA_REGISTRY_PULL=1\n", 0o602), me(), me(), env.get, env.set, env.unset)
	if r.State != "refused" || len(env) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}

func TestAFileOwnedBySomeoneElseIsRefusedWhole(t *testing.T) {
	env := fakeEnv{}
	r := apply(write(t, "NOO_ALLOW_OLLAMA_REGISTRY_PULL=1\n", 0o600), me()+1, me(), env.get, env.set, env.unset)
	if r.State != "refused" || !strings.Contains(r.Why, "owned by uid") || len(env) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}

func TestASymlinkIsRefusedWhole(t *testing.T) {
	real := write(t, "NOO_ALLOW_OLLAMA_REGISTRY_PULL=1\n", 0o600)
	link := filepath.Join(t.TempDir(), "agent.local.env")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	env := fakeEnv{}
	r := apply(link, me(), me(), env.get, env.set, env.unset)
	if r.State != "refused" || !strings.Contains(r.Why, "not a regular file") || len(env) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}

// ── names ───────────────────────────────────────────────────────────────────

// The file sets only node-local keys: a controller-owned name is ignored and
// named, never applied.
func TestOnlyNodeLocalKeysAreTaken(t *testing.T) {
	env := fakeEnv{"NOO_CLUSTER_SECRET": "controller-value"}
	r := run(t, "NOO_CLUSTER_SECRET=mine\nNODE_AGENT_BIND=0.0.0.0\nNOO_ALLOW_OLLAMA_REGISTRY_PULL=1\n", env)
	if env["NOO_CLUSTER_SECRET"] != "controller-value" || env["NODE_AGENT_BIND"] != "" {
		t.Fatalf("a controller-owned key was applied: %v", env)
	}
	if strings.Join(r.Ignored, ",") != "NODE_AGENT_BIND,NOO_CLUSTER_SECRET" || declared(r) != "NOO_ALLOW_OLLAMA_REGISTRY_PULL@local file" {
		t.Fatalf("%+v", r)
	}
}

func TestAKeyDeclaredTwiceIsRefused(t *testing.T) {
	env := fakeEnv{}
	r := run(t, "NOO_ALLOW_OLLAMA_REGISTRY_PULL=1\nNOO_ALLOW_OLLAMA_REGISTRY_PULL=1\n", env)
	if strings.Join(refusedKeys(r), ",") != "NOO_ALLOW_OLLAMA_REGISTRY_PULL" || env["NOO_ALLOW_OLLAMA_REGISTRY_PULL"] != "" {
		t.Fatalf("%+v %v", r, env)
	}
}

// A value is data, never code: shell syntax is refused by the charset.
func TestAValueWithShellSyntaxIsRefused(t *testing.T) {
	for _, v := range []string{"$(touch x)", "`id`", "a b", `"1"`, "1;id", "a%b"} {
		env := fakeEnv{}
		r := run(t, "NOO_LOG_SHIP_UNITS="+v+"\n", env)
		if len(r.Refused) != 1 || env["NOO_LOG_SHIP_UNITS"] != "" {
			t.Fatalf("%q: %+v %v", v, r, env)
		}
	}
}

// ── failing closed ──────────────────────────────────────────────────────────

// A refused trust declaration is not applied and is removed from the
// environment: a widening never falls back to allow.
func TestARefusedTrustDeclarationIsRemoved(t *testing.T) {
	env := fakeEnv{"NOO_ALLOW_OLLAMA_REGISTRY_PULL": "1"}
	r := run(t, "NOO_ALLOW_OLLAMA_REGISTRY_PULL=yes\n", env)
	if _, set := env["NOO_ALLOW_OLLAMA_REGISTRY_PULL"]; set || len(r.Refused) != 1 {
		t.Fatalf("%+v %v", r, env)
	}
}

// A refused narrowing falls to its narrowest value.
func TestARefusedRegistryFallbackIsOff(t *testing.T) {
	env := fakeEnv{}
	run(t, "NOO_IMAGE_REGISTRY_FALLBACK=everywhere\n", env)
	if env["NOO_IMAGE_REGISTRY_FALLBACK"] != "off" {
		t.Fatalf("%v", env)
	}
}

// A refused tuning key is not applied: the agent's default stands (the local
// file wins, and so does its refusal).
func TestARefusedTuningKeyFallsToTheDefault(t *testing.T) {
	env := fakeEnv{"NOO_GPU_YIELD_AFTER_S": "60"}
	r := run(t, "NOO_GPU_YIELD_AFTER_S=soon\n", env)
	if _, set := env["NOO_GPU_YIELD_AFTER_S"]; set || len(r.Refused) != 1 {
		t.Fatalf("%+v %v", r, env)
	}
}

// ── the environment (a systemd drop-in) ─────────────────────────────────────

// A node-local key that arrives through the agent's environment keeps
// working, named with its source; the local file wins when both set it.
func TestAnEnvironmentDeclarationKeepsWorkingAndTheFileWins(t *testing.T) {
	env := fakeEnv{"NOO_GPU_YIELD": "off", "NOO_ALLOW_OLLAMA_REGISTRY_PULL": "0"}
	r := run(t, "NOO_ALLOW_OLLAMA_REGISTRY_PULL=1\n", env)
	if env["NOO_GPU_YIELD"] != "off" || env["NOO_ALLOW_OLLAMA_REGISTRY_PULL"] != "1" {
		t.Fatalf("%v", env)
	}
	if declared(r) != "NOO_ALLOW_OLLAMA_REGISTRY_PULL@local file,NOO_GPU_YIELD@environment" {
		t.Fatalf("%s", declared(r))
	}
}

// A trust key from the environment is held to the same rule and fails closed:
// it is no longer taken blindly.
func TestAnEnvironmentTrustDeclarationIsValidatedAndFailsClosed(t *testing.T) {
	env := fakeEnv{"NOO_CONTAINER_RUN_USER": "0:0", "NOO_IMAGE_REGISTRY_FALLBACK": "anywhere"}
	r := apply(filepath.Join(t.TempDir(), "none"), me(), me(), env.get, env.set, env.unset)
	if _, set := env["NOO_CONTAINER_RUN_USER"]; set || env["NOO_IMAGE_REGISTRY_FALLBACK"] != "off" {
		t.Fatalf("%v", env)
	}
	for _, x := range r.Refused {
		if x.Source != "environment" || !x.Trust {
			t.Fatalf("%+v", x)
		}
	}
	if len(r.Refused) != 2 {
		t.Fatalf("%+v", r)
	}
}

// ── one test per key rule ───────────────────────────────────────────────────

func expect(t *testing.T, key string, good, bad []string) {
	t.Helper()
	for _, v := range good {
		if err := Keys[key].check(v); err != nil {
			t.Errorf("%s=%s refused: %v", key, v, err)
		}
	}
	for _, v := range bad {
		if err := Keys[key].check(v); err == nil {
			t.Errorf("%s=%s accepted", key, v)
		}
	}
}

func TestBackendCapAddMustBeGrantable(t *testing.T) {
	expect(t, "NOO_BACKEND_CAP_ADD", []string{"none", "CHOWN", "chown,CAP_SYS_NICE"}, []string{"SYS_ADMIN", "CHOWN,NET_ADMIN", "ALL"})
}

func TestImageAllowMustBeARepositoryOrANamespacePrefix(t *testing.T) {
	expect(t, "NOO_CONTAINER_IMAGE_ALLOW", []string{"ollama/ollama", "ghcr.io/org/", "registry.local:5000/team/app"}, []string{"docker.io/", "ghcr.io/", "Bad/Repo", "a//b"})
}

func TestRunUserMustBeANonRootUid(t *testing.T) {
	expect(t, "NOO_CONTAINER_RUN_USER", []string{"1000", "1000:1000"}, []string{"0", "0:0", "root", "1000:"})
	expect(t, "NOO_SKILL_RUN_USER", []string{"65534:65534"}, []string{"0:1000", "nobody"})
}

func TestRegistryPullIsZeroOrOne(t *testing.T) {
	expect(t, "NOO_ALLOW_OLLAMA_REGISTRY_PULL", []string{"0", "1"}, []string{"yes", "true", "2"})
}

func TestSkillBindRootsStayOutOfSystemTrees(t *testing.T) {
	expect(t, "NOO_SKILL_BIND_ROOTS", []string{"/srv/skills", "/data/a:/data/b"}, []string{"/", "/etc/x", "/var", "/var/lib/docker", "relative", "/data/../etc", "/home"})
}

func TestMcpSecretsFileIsAnAbsolutePath(t *testing.T) {
	expect(t, "NOO_MCP_SECRETS_FILE", []string{"/etc/noo/mcp-secrets.env"}, []string{"mcp.env", "/proc/self/environ", "/etc/../x"})
}

func TestRegistryFallbackIsPublicOrOff(t *testing.T) {
	expect(t, "NOO_IMAGE_REGISTRY_FALLBACK", []string{"public", "off"}, []string{"on", "any"})
}

func TestTuningKeysHoldTheirShapes(t *testing.T) {
	expect(t, "NOO_GPU_YIELD", []string{"on", "off"}, []string{"maybe"})
	expect(t, "NOO_GPU_YIELD_FOREIGN_MB", []string{"2048"}, []string{"-1", "1e9", "lots"})
	expect(t, "NOO_LOG_SHIP_UNITS", []string{"noo-hostd,docker"}, []string{"noo hostd"})
	expect(t, "NOO_AGENT_TUNNEL", []string{"off", "1"}, []string{"later"})
}

// A good declaration is applied as written.
func TestAGoodDeclarationIsApplied(t *testing.T) {
	env := fakeEnv{}
	r := run(t, "# the Mac pulls Ollama tags itself\nNOO_ALLOW_OLLAMA_REGISTRY_PULL=1\nNOO_BACKEND_CAP_ADD=CHOWN,SYS_NICE\n", env)
	if env["NOO_ALLOW_OLLAMA_REGISTRY_PULL"] != "1" || env["NOO_BACKEND_CAP_ADD"] != "CHOWN,SYS_NICE" || len(r.Refused) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}

// The charset rule on its own: every key's rule also refuses these
// characters, which would mask a broken charset check, so it is tested
// directly. It is the defence that holds even if a key's rule is widened.
func TestTheValueCharsetRefusesShellSyntaxOnItsOwn(t *testing.T) {
	for _, v := range []string{"$(id)", "`id`", "a b", `"x"`, "'x'", `a\b`, "50%", "a\tb"} {
		if valueRefusal(v) == "" {
			t.Errorf("%q passed the charset", v)
		}
	}
	if valueRefusal("CHOWN,SYS_NICE") != "" || valueRefusal("/data/a:/data/b") != "" {
		t.Error("a plain value was refused")
	}
}

// ── the directory ───────────────────────────────────────────────────────────

func TestAGroupWritableDirectoryIsRefused(t *testing.T) {
	p := write(t, "NOO_GPU_YIELD=off\n", 0o644)
	if err := os.Chmod(filepath.Dir(p), 0o770); err != nil {
		t.Fatal(err)
	}
	env := fakeEnv{}
	r := apply(p, me(), me(), env.get, env.set, env.unset)
	if r.State != "refused" || !strings.Contains(r.Why, "directory") || len(env) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}

// The macOS layout: /etc is a symlink to /private/etc. The directory check
// follows the parent's link to its real, owner-held directory (never refusing
// every Mac), while the file itself may still not be a symlink.
func TestASymlinkedParentIsCheckedAtItsRealPath(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "private-etc")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "etc")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "agent.local.env"), []byte("NOO_GPU_YIELD=off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := fakeEnv{}
	r := apply(filepath.Join(link, "agent.local.env"), me(), me(), env.get, env.set, env.unset)
	if r.State != "read" || env["NOO_GPU_YIELD"] != "off" {
		t.Fatalf("%+v %v", r, env)
	}
}

// ── read as the agent's own (non-owner) uid: needs root ─────────────────────
//
// The agent runs as its own unprivileged user and the file is root's, so the
// reader must work as a uid that does NOT own it. Run as root (CI does, with
// sudo), this re-runs the test binary as uid 65534: a root-owned 644 file is
// read and applied; a root-owned 600 one is a NAMED refusal ("unreadable by
// the agent"), never "no declarations".

const childEnv = "NODELOCAL_TEST_CHILD_PATH"

func TestNodeLocalChildRead(t *testing.T) {
	p := os.Getenv(childEnv)
	if p == "" {
		t.Skip("helper for TestTheAgentsUidReadsARootOwnedFile")
	}
	env := fakeEnv{}
	r := apply(p, 0, 0, env.get, env.set, env.unset)
	os.Stdout.WriteString("\nSTATE=" + r.State + "\nDECLARED=" + declared(r) + "\nWHY=" + r.Why + "\n")
}

func TestTheAgentsUidReadsARootOwnedFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: CI runs it with sudo (the reader as a non-owner uid)")
	}
	dir, err := os.MkdirTemp("/tmp", "nodelocal-uid-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	child := func(p string) string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestNodeLocalChildRead$", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"="+p)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	ok := filepath.Join(dir, "ok.env")
	if err := os.WriteFile(ok, []byte("NOO_GPU_YIELD=off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := child(ok); !strings.Contains(out, "STATE=read") || !strings.Contains(out, "DECLARED=NOO_GPU_YIELD@local file") {
		t.Fatalf("a root-owned 644 file must be read by the agent's uid:\n%s", out)
	}
	closed := filepath.Join(dir, "closed.env")
	if err := os.WriteFile(closed, []byte("NOO_GPU_YIELD=off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := child(closed); !strings.Contains(out, "STATE=refused") || !strings.Contains(out, "unreadable by the agent") {
		t.Fatalf("a root-owned 600 file must be a named refusal, not 'no declarations':\n%s", out)
	}
}

// The directory must be root's too: a directory another user owns could have
// the file swapped. (The file's own owner check passes here; only the
// directory's fails.)
func TestADirectoryOwnedBySomeoneElseIsRefused(t *testing.T) {
	p := write(t, "NOO_GPU_YIELD=off\n", 0o644)
	env := fakeEnv{}
	r := apply(p, me(), me()+1, env.get, env.set, env.unset)
	if r.State != "refused" || !strings.Contains(r.Why, "its directory") || len(env) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}

// A file the agent cannot read is a NAMED refusal in the node-local row,
// never silently "no declarations". (Mode 000: unreadable even by its owner,
// so this holds without root; CI's sudo step proves the real non-owner case.)
func TestAnUnreadableFileIsANamedRefusal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	p := write(t, "NOO_GPU_YIELD=off\n", 0o000)
	env := fakeEnv{}
	r := apply(p, me(), me(), env.get, env.set, env.unset)
	if r.State != "refused" || !strings.Contains(r.Why, "unreadable by the agent") || len(env) != 0 {
		t.Fatalf("%+v %v", r, env)
	}
}
