// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fakeOwner(t *testing.T, uids map[string]int) *int {
	t.Helper()
	runs := 0
	prevStat, prevRun := ollamaOwnerUID, ollamaReownRun
	ollamaOwnerUID = func(p string) (int, bool) { u, ok := uids[p]; return u, ok }
	ollamaReownRun = func(_ context.Context, _ *Client, dir string) (int, string, error) {
		runs++
		for p := range uids { // the chown -R lands
			if p == dir || strings.HasPrefix(p, dir+"/") {
				uids[p] = ollamaStoreUID
			}
		}
		return 0, "", nil
	}
	t.Cleanup(func() { ollamaOwnerUID, ollamaReownRun = prevStat, prevRun })
	return &runs
}

func TestOllamaStoreReownIsOnceAndIdempotent(t *testing.T) {
	const dir = "/data/ollama"
	runs := fakeOwner(t, map[string]int{dir: 0, dir + "/models": 0})
	c := &Client{}
	if err := c.ensureOllamaStoreOwned(context.Background(), dir); err != nil || *runs != 1 {
		t.Fatalf("first: err %v runs %d", err, *runs)
	}
	if err := c.ensureOllamaStoreOwned(context.Background(), dir); err != nil || *runs != 1 {
		t.Fatalf("second run must do nothing: err %v runs %d", err, *runs)
	}
}

func TestOllamaStoreReownLeavesFreshAndOwnedStoresAlone(t *testing.T) {
	for name, uids := range map[string]map[string]int{
		"fresh (absent)":       {},
		"already owned":        {"/d": ollamaStoreUID, "/d/models": ollamaStoreUID},
		"owned, no models yet": {"/d": ollamaStoreUID},
	} {
		runs := fakeOwner(t, uids)
		if err := (&Client{}).ensureOllamaStoreOwned(context.Background(), "/d"); err != nil || *runs != 0 {
			t.Errorf("%s: err %v runs %d", name, err, *runs)
		}
	}
	// A models dir left root-owned under an owned top dir (a fallback run as root) is re-owned.
	runs := fakeOwner(t, map[string]int{"/d": ollamaStoreUID, "/d/models": 0})
	if err := (&Client{}).ensureOllamaStoreOwned(context.Background(), "/d"); err != nil || *runs != 1 {
		t.Errorf("root models dir: err %v runs %d", err, *runs)
	}
}

func TestOllamaStoreReownOnlyChownsAndFailsLoudly(t *testing.T) {
	var script string
	prevStat, prevRun := ollamaOwnerUID, ollamaReownRun
	t.Cleanup(func() { ollamaOwnerUID, ollamaReownRun = prevStat, prevRun })
	ollamaOwnerUID = func(string) (int, bool) { return 0, true }
	ollamaReownRun = func(ctx context.Context, c *Client, dir string) (int, string, error) { return 1, "denied", nil }
	err := (&Client{}).ensureOllamaStoreOwned(context.Background(), "/d")
	if err == nil || !strings.Contains(err.Error(), "sudo chown -R 65532:65532 /d") {
		t.Fatalf("a failed re-own must refuse with the manual command, got %v", err)
	}
	ollamaReownRun = func(context.Context, *Client, string) (int, string, error) {
		return -1, "", errors.New("no helper image")
	}
	if err := (&Client{}).ensureOllamaStoreOwned(context.Background(), "/d"); err == nil {
		t.Fatal("helper failure must refuse the start")
	}
	// The real script is chown -R and nothing destructive.
	src := readFile(t, "ollama_store.go")
	i := strings.Index(src, "script := fmt.Sprintf(`")
	script = src[i : i+80]
	for _, bad := range []string{"rm ", "mv ", "find ", "-delete"} {
		if strings.Contains(script, bad) {
			t.Errorf("re-own script must only chown, found %q", bad)
		}
	}
	if !strings.Contains(script, "chown -R") {
		t.Errorf("re-own script %q", script)
	}
}

func TestOllamaStoreMountFollowsTheImage(t *testing.T) {
	t.Setenv("NOO_IMAGE_PREFIX", "ghcr.io/noomesh")
	spec := backendSpecs["ollama"]
	got, ours := ollamaStoreFor(spec, "ghcr.io/noomesh/ollama:v0.6.16")
	if !ours || got.Volumes[0].Target != ollamaOursStore || got.Volumes[0].Source != spec.Volumes[0].Source {
		t.Fatalf("ours: %+v ours=%v", got.Volumes, ours)
	}
	if spec.Volumes[0].Target != ollamaUpstreamStore {
		t.Fatal("the shared spec must not be mutated")
	}
	got, ours = ollamaStoreFor(spec, "ollama/ollama:0.40.5")
	if ours || got.Volumes[0].Target != ollamaUpstreamStore {
		t.Fatalf("upstream keeps /root/.ollama as root: %+v", got.Volumes)
	}
}

// Nothing in the ollama spec, the agent's container floor or the image may put
// the hardened image back on root.
func TestOllamaIsNonRootEverywhere(t *testing.T) {
	df := readFile(t, "../../../docker/Dockerfile.ollama")
	final := df[strings.LastIndex(df, "\nFROM "):]
	if !strings.Contains(final, "\nUSER 65532:65532") {
		t.Error("the final stage of Dockerfile.ollama must set USER 65532:65532")
	}
	if !strings.Contains(final, "HOME=/home/nonroot") {
		t.Error("HOME must be the non-root user's")
	}
	b := readFile(t, "backends.go")
	for _, bad := range []string{`User: "0"`, `User:       "0"`, "Privileged: true", "Privileged:true"} {
		if strings.Contains(b, bad) {
			t.Errorf("backends.go runs a container as root/privileged: %q", bad)
		}
	}
}
