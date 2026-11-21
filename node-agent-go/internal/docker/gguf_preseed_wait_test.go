// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed/preseedtest"
)

// ggufStore serves the controller's manifest route through `manifest` and
// the file at /gguf/<name>, over mTLS, and points the node at it with a
// fresh models dir. It returns the dir.
func ggufStore(t *testing.T, name string, body []byte, manifest http.HandlerFunc) string {
	t.Helper()
	pki := preseedtest.New(t)
	pki.SetNodeEnv(t)
	srv := pki.Store(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/artifacts/manifest/"):
			manifest(w, r)
		case r.URL.Path == "/gguf/"+name:
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	dir := t.TempDir()
	t.Setenv("MODELS_DIR", dir)
	t.Setenv("CONTROLLER_URL", srv.URL)
	t.Setenv("NOO_MODEL_CACHE_URL", srv.URL)
	t.Setenv("NOO_AGENT_STAGING_DIR", t.TempDir())
	return dir
}

func shortBudget(t *testing.T, d time.Duration) {
	t.Helper()
	old := manifestAwaitBudget
	manifestAwaitBudget = d
	t.Cleanup(func() { manifestAwaitBudget = old })
}

func ggufManifestJSON(b []byte) string { return `{"sha256":"` + sha(b) + `","size_bytes":3}` }

// The controller answers 202 + Retry-After while it hashes: the start waits
// for the 200 and the file lands (it used to read the 202 as "no manifest").
func TestPreseedGGUFWaitsOutA202AndWritesTheFile(t *testing.T) {
	w := ggufBytes()
	var asks atomic.Int32
	dir := ggufStore(t, "m.gguf", w, func(rw http.ResponseWriter, r *http.Request) {
		if asks.Add(1) == 1 {
			rw.Header().Set("Retry-After", "1")
			rw.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = rw.Write([]byte(ggufManifestJSON(w)))
	})
	shortBudget(t, 30*time.Second)
	wrote, err := (&Client{}).preseedGGUF(t.Context(), "llamacpp", "m.gguf")
	if err != nil || !wrote {
		t.Fatalf("wrote=%v err=%v, want the file written after the 202", wrote, err)
	}
	if got, rerr := os.ReadFile(filepath.Join(dir, "m.gguf")); rerr != nil || string(got) != string(w) {
		t.Fatalf("file not written: %v", rerr)
	}
	if asks.Load() != 2 {
		t.Fatalf("manifest asked %d times, want 2 (202 then 200)", asks.Load())
	}
}

// A 202 that never ends is a typed error naming the model and the hashing,
// and the start gate returns it: no container is created without the file.
func TestAPermanent202IsATypedErrorAndTheStartGateStopsBeforeAContainer(t *testing.T) {
	dir := ggufStore(t, "m.gguf", ggufBytes(), func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Retry-After", "1")
		rw.WriteHeader(http.StatusAccepted)
	})
	shortBudget(t, 1500*time.Millisecond)
	err := (&Client{}).ggufStartGate(t.Context(), "llamacpp", "m.gguf", "")
	var un *GGUFUnavailableError
	if !errors.As(err, &un) {
		t.Fatalf("err = %v, want *GGUFUnavailableError", err)
	}
	for _, want := range []string{"m.gguf", "still hashing", "retrying", "no container was started"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if !errors.Is(err, ErrArtifactManifestTimeout) {
		t.Errorf("the cause should be the manifest timeout: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "m.gguf")); serr == nil {
		t.Fatal("a file appeared without a manifest")
	}
}

// 404, 5xx and a timeout are errors too, never (false, nil).
func TestAnUnavailableManifestIsAnErrorNotARefusalThatReturnsNil(t *testing.T) {
	cases := map[string]struct {
		h      http.HandlerFunc
		ctxFor time.Duration
		reason string
	}{
		"404": {func(rw http.ResponseWriter, r *http.Request) { http.NotFound(rw, r) }, 0, "no artifact manifest"},
		"500": {func(rw http.ResponseWriter, r *http.Request) { http.Error(rw, "boom", 500) }, 0, "HTTP 500"},
		"slow": {func(rw http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		}, 300 * time.Millisecond, "did not answer in time"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := ggufStore(t, "m.gguf", ggufBytes(), tc.h)
			ctx := t.Context()
			if tc.ctxFor > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.ctxFor)
				defer cancel()
			}
			wrote, err := (&Client{}).preseedGGUF(ctx, "llamacpp", "m.gguf")
			var un *GGUFUnavailableError
			if wrote || !errors.As(err, &un) || !strings.Contains(un.Reason, tc.reason) {
				t.Fatalf("wrote=%v err=%v, want a GGUFUnavailableError with %q", wrote, err, tc.reason)
			}
			if gerr := (&Client{}).ggufStartGate(ctx, "llamacpp", "m.gguf", ""); gerr == nil {
				t.Fatal("the start gate let a start through with no file and no manifest")
			}
			_ = dir
		})
	}
}

// A file already on the node still starts when the controller cannot vouch
// (availability, as before): only a MISSING file stops the start.
func TestTheStartGateLetsALocalFileStartWhenTheManifestIsUnavailable(t *testing.T) {
	dir := ggufStore(t, "m.gguf", ggufBytes(), func(rw http.ResponseWriter, r *http.Request) { http.NotFound(rw, r) })
	if err := os.WriteFile(filepath.Join(dir, "m.gguf"), ggufBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Client{}).ggufStartGate(t.Context(), "llamacpp", "m.gguf", ""); err != nil {
		t.Fatalf("a present file must start: %v", err)
	}
	// The effective dir is the placement's models_dir when one is declared.
	other := t.TempDir()
	if err := (&Client{}).ggufStartGate(t.Context(), "llamacpp", "m.gguf", other); err == nil {
		t.Fatal("the file is in the default dir, not the declared one: the start must be refused")
	}
}

// The gate runs before anything creates a container.
func TestTheGGUFGateRunsBeforeTheContainerIsCreated(t *testing.T) {
	raw, err := os.ReadFile("backends.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	gate := strings.Index(s, "c.ggufStartGate(")
	remove := strings.Index(s, "c.docker.ContainerRemove(ctx, spec.ContainerName, client.ContainerRemoveOptions{Force: true})")
	create := strings.Index(s, "c.docker.ContainerCreate(")
	if gate < 0 || remove < 0 || create < 0 || gate > remove || gate > create {
		t.Fatalf("ggufStartGate must precede the container remove/create (gate=%d remove=%d create=%d)", gate, remove, create)
	}
}
