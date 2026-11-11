// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A REAL ollama, native, serving a temp store: the mirror install against the
// daemon it is written for. Set NOO_TEST_OLLAMA_BIN to an ollama binary to
// run it (no model is loaded; ollama lists a model without loading it, and
// listing is the proof). Skipped otherwise, so CI without the binary is
// unaffected.
func realOllama(t *testing.T) (base, models string) {
	t.Helper()
	bin := os.Getenv("NOO_TEST_OLLAMA_BIN")
	if bin == "" {
		t.Skip("NOO_TEST_OLLAMA_BIN is not set: no real ollama to install into")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	home := t.TempDir()
	models = filepath.Join(home, "models")
	if err := os.Mkdir(models, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "serve")
	cmd.Env = []string{"HOME=" + home, "OLLAMA_HOST=" + addr, "OLLAMA_MODELS=" + models, "OLLAMA_NO_CLOUD=1", "PATH=/usr/bin:/bin"}
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	base = "http://" + addr
	for i := 0; i < 100; i++ {
		if resp, err := http.Get(base + "/api/tags"); err == nil {
			resp.Body.Close()
			return base, models
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("ollama did not answer: %s", log.String())
	return "", ""
}

func realDeps(base, models string, blobs map[string][]byte, fetched *int, t *testing.T) mirrorDeps {
	dir := t.TempDir()
	return mirrorDeps{
		api: &ollamaHTTP{base: base, transport: &http.Transport{}},
		fetchBlob: func(_ context.Context, b mirrorBlob) (string, error) {
			*fetched++
			p := filepath.Join(dir, b.blobName())
			return p, os.WriteFile(p, blobs[b.Hex], 0o600)
		},
		writeManifest: func(_ context.Context, ns, name, tag string, body []byte) (*manifestWrite, error) {
			return writeManifestNative(models, ns, name, tag, body)
		},
		checkSpace: func(missing []mirrorBlob) error { return requireFree(models, missing, "the test store") },
	}
}

func TestARealOllamaInstallsAMirrorAndAdoptsBlobsItAlreadyHas(t *testing.T) {
	base, models := realOllama(t)
	body, blobs := visionFixture()
	m, err := parseMirrorManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	api := &ollamaHTTP{base: base, transport: &http.Transport{}}

	fetched := 0
	if err := installMirror(t.Context(), "library", "rhmirror", "v1", m, realDeps(base, models, blobs, &fetched, t)); err != nil {
		t.Fatalf("install into a real ollama: %v", err)
	}
	if fetched != len(m.Blobs) {
		t.Fatalf("fetched %d blobs, want %d", fetched, len(m.Blobs))
	}
	d, listed, err := api.TagDigest(t.Context(), "rhmirror:v1")
	if err != nil || !listed || d != m.SHA256 {
		t.Fatalf("ollama lists rhmirror:v1 as %q listed=%v err=%v, want digest %s", d, listed, err, m.SHA256)
	}

	// The operator pulled the tag by hand (or a re-run): every blob is
	// already there. Nothing is fetched again, the manifest is (re)written
	// with the staged bytes, and the daemon's digest still matches.
	fetched = 0
	if err := installMirror(t.Context(), "library", "rhmirror", "v1", m, realDeps(base, models, blobs, &fetched, t)); err != nil {
		t.Fatalf("re-install over present blobs: %v", err)
	}
	if fetched != 0 {
		t.Fatalf("blobs ollama already held were fetched again: %d", fetched)
	}
	got, _ := os.ReadFile(filepath.Join(models, "manifests/registry.ollama.ai/library/rhmirror/v1"))
	if !bytes.Equal(got, body) {
		t.Fatal("the manifest in ollama's store is not the staged bytes")
	}
}

func TestARealOllamaNeverReceivesTheWrongBytes(t *testing.T) {
	base, models := realOllama(t)
	good := bytes.Repeat([]byte("GGUF-weights-"), 50_000)
	bad := bytes.Clone(good)
	bad[len(bad)-1] ^= 1
	body, blobs := mirrorFixture(
		blobFix{"application/vnd.docker.container.image.v1+json", []byte(`{"model_format":"gguf"}`)},
		blobFix{ollamaModelMedia, good},
	)
	m, _ := parseMirrorManifest(body)
	blobs[sha(good)] = bad // the store hands over other bytes of the same size
	fetched := 0
	err := installMirror(t.Context(), "library", "rhbad", "v1", m, realDeps(base, models, blobs, &fetched, t))
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("want the agent's own refusal, got %v", err)
	}
	api := &ollamaHTTP{base: base, transport: &http.Transport{}}
	if ok, _ := api.HasBlob(t.Context(), sha(good)); ok {
		t.Fatal("ollama holds a blob under the digest of bytes it never received")
	}
	if _, listed, _ := api.TagDigest(t.Context(), "rhbad:v1"); listed {
		t.Fatal("ollama lists a model whose blob was refused")
	}
}

func TestAManifestWrittenWhereARealOllamaDoesNotLookIsTakenBackOut(t *testing.T) {
	base, _ := realOllama(t)
	wrong := filepath.Join(t.TempDir(), "models")
	_ = os.Mkdir(wrong, 0o755)
	body, blobs := visionFixture()
	m, _ := parseMirrorManifest(body)
	fetched := 0
	err := installMirror(t.Context(), "library", "rhelse", "v1", m, realDeps(base, wrong, blobs, &fetched, t))
	if err == nil || !strings.Contains(err.Error(), "taken back out") {
		t.Fatalf("want the write undone, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(wrong, "manifests/registry.ollama.ai/library/rhelse/v1")); err == nil {
		t.Fatal(fmt.Sprintf("the manifest is still in %s", wrong))
	}
}
