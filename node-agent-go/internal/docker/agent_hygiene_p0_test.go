// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Proposal 61 phase 0: four checks that narrow what the agent's own code
// asks the root Docker daemon for. One test per check.

// (1) The ollama store re-own runs a root helper with a read-write bind: a
// store that does not resolve under a declared data root is refused, and
// the helper never runs.
func TestTheOllamaReownRefusesAStoreOutsideTheDataRoots(t *testing.T) {
	ran := false
	origRun, origOwner, origList, origRoots := ollamaReownRun, ollamaOwnerUID, ollamaListDir, ollamaStoreUnderRoots
	t.Cleanup(func() {
		ollamaReownRun, ollamaOwnerUID, ollamaListDir, ollamaStoreUnderRoots = origRun, origOwner, origList, origRoots
	})
	ollamaOwnerUID = func(string) (int, bool) { return 0, true } // root-owned: needs a re-own
	ollamaListDir = func(string) []string { return nil }
	ollamaReownRun = func(context.Context, *Client, string) (int, string, error) { ran = true; return 0, "", nil }

	ollamaStoreUnderRoots = func(p string) (string, error) {
		return "", errors.New("outside this node's declared data roots")
	}
	err := (&Client{}).ensureOllamaStoreOwned(context.Background(), "/etc")
	if err == nil || !strings.Contains(err.Error(), "refusing to re-own the ollama store") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if ran {
		t.Fatal("the root helper ran on a store outside the data roots")
	}

	// Under a root: the helper runs on the CANONICAL path the check returned.
	var got string
	ollamaStoreUnderRoots = func(p string) (string, error) { return "/var/lib/noo/ollama", nil }
	ollamaReownRun = func(_ context.Context, _ *Client, dir string) (int, string, error) { got = dir; return 0, "", nil }
	if err := (&Client{}).ensureOllamaStoreOwned(context.Background(), "/var/lib/noo/./ollama-link"); err != nil {
		t.Fatal(err)
	}
	if got != "/var/lib/noo/ollama" {
		t.Fatalf("helper bound %q, want the canonical path", got)
	}
}

// (2) /pull's remove_container force-removes only a backend container this
// agent manages (or the legacy containerised agent); any other name is
// refused and the image stays loaded.
func TestPullRemovesOnlyABackendContainerTheAgentManages(t *testing.T) {
	var removed []string
	orig := removeContainerFn
	t.Cleanup(func() { removeContainerFn = orig })
	removeContainerFn = func(_ context.Context, _ *Client, name string) error { removed = append(removed, name); return nil }

	ollama := ContainerNameFor("ollama")
	if ollama == "" {
		t.Fatal("no ollama backend spec")
	}
	for _, name := range []string{"noo-gateway", "noo-postgres", "some-user-container", "noo-ollama-x", ""} {
		out := &PullImageArtifactResult{}
		(&Client{}).removeAfterLoad(context.Background(), name, out)
		if out.Removed != "" {
			t.Errorf("%q was removed", name)
		}
	}
	if len(removed) != 0 {
		t.Fatalf("removed %v; want nothing outside the backends", removed)
	}
	for _, name := range []string{ollama, "noo-node-agent"} {
		out := &PullImageArtifactResult{}
		(&Client{}).removeAfterLoad(context.Background(), name, out)
		if out.Removed != name {
			t.Errorf("%q was not removed", name)
		}
	}
}

// (3) NOO_BACKEND_CAP_ADD grants only capabilities from the allow-list; a
// capability that reaches the host is refused by name.
func TestTheBackendCapabilityEnvGrantsOnlyTheAllowList(t *testing.T) {
	t.Setenv(BackendCapsEnv, "SYS_NICE, cap_ipc_lock, SYS_ADMIN, SYS_PTRACE, DAC_READ_SEARCH, ALL, NET_ADMIN")
	got := backendCaps()
	if !slices.Equal(got, []string{"SYS_NICE", "IPC_LOCK"}) {
		t.Fatalf("caps = %v, want only SYS_NICE and IPC_LOCK", got)
	}
	for _, bad := range []string{"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH", "NET_ADMIN", "MKNOD", "BPF", "ALL"} {
		if backendCapAllowed[bad] {
			t.Errorf("%s is on the allow-list", bad)
		}
	}
	for _, c := range backendCapsDefault {
		if !backendCapAllowed[c] {
			t.Errorf("default cap %s is not on the allow-list", c)
		}
	}
}

// (4) A helper container drops every capability but the three its two jobs
// need, sets no-new-privileges, and has no network.
func TestAHelperContainerKeepsOnlyWhatItsJobsNeed(t *testing.T) {
	h := helperHostConfig([]string{"/var/lib/noo/ollama:/own"})
	if !slices.Equal(h.CapDrop, []string{"ALL"}) {
		t.Errorf("CapDrop = %v", h.CapDrop)
	}
	if !slices.Equal(h.CapAdd, []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"}) {
		t.Errorf("CapAdd = %v", h.CapAdd)
	}
	if !slices.Contains(h.SecurityOpt, "no-new-privileges") {
		t.Errorf("SecurityOpt = %v", h.SecurityOpt)
	}
	if string(h.NetworkMode) != "none" {
		t.Errorf("NetworkMode = %q", h.NetworkMode)
	}
	if h.Privileged {
		t.Error("privileged")
	}
}
