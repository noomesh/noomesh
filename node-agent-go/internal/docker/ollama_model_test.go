// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The FROM line is how the node learns which weight to fetch, so it is also
// the one place a Modelfile gets to influence what this verb does. Every
// refusal here is a path the daemon must never be handed.
func TestModelfileWeight(t *testing.T) {
	good := []struct{ body, want string }{
		{"FROM ./qwen3-tuned-Q4_K_M.gguf\nPARAMETER num_ctx 4096\n", "qwen3-tuned-Q4_K_M.gguf"},
		// The convert script writes `./`, but a hand-written one may not.
		{"FROM qwen3-tuned-Q4_K_M.gguf\n", "qwen3-tuned-Q4_K_M.gguf"},
		{"  from   ./a.GGUF  \n", "a.GGUF"},
		{`FROM "./quoted.gguf"`, "quoted.gguf"},
		// TEMPLATE lines can contain the word FROM; only the directive counts.
		{"TEMPLATE \"\"\"answer FROM context\"\"\"\nFROM ./real.gguf\n", "real.gguf"},
	}
	for _, tc := range good {
		got, err := modelfileWeight(tc.body)
		if err != nil {
			t.Errorf("modelfileWeight(%q): %v", tc.body, err)
			continue
		}
		if got != tc.want {
			t.Errorf("modelfileWeight(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}

	bad := []struct{ name, body string }{
		{"traversal", "FROM ../../etc/shadow.gguf\n"},
		{"absolute path", "FROM /etc/passwd.gguf\n"},
		{"a directory component", "FROM ./sub/dir.gguf\n"},
		{"a registry pull, which is a different operation", "FROM llama3\n"},
		{"an existing local model", "FROM qwen3:8b\n"},
		{"no FROM at all", "PARAMETER num_ctx 4096\n"},
		{"FROM with no argument", "FROM\n"},
		{"empty", ""},
	}
	for _, tc := range bad {
		if got, err := modelfileWeight(tc.body); err == nil {
			t.Errorf("%s: modelfileWeight(%q) returned %q, want an error", tc.name, tc.body, got)
		}
	}
}

func TestSafeArtifactName(t *testing.T) {
	for _, good := range []string{"qwen3-tuned.Modelfile", "a-b_c.1.gguf", "x"} {
		if !safeArtifactName(good) {
			t.Errorf("%q must be accepted", good)
		}
	}
	for _, bad := range []string{"", "a/b", `a\b`, "..", "../x", "a/../b", ".hidden", strings.Repeat("x", 300)} {
		if safeArtifactName(bad) {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// Both files must extract into ONE directory: `FROM ./<file>` is resolved
// relative to the Modelfile, so a tar that scattered them would produce an
// `ollama create` failing on a path nobody sent.
func TestDirTarPutsBothFilesInOneDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.Modelfile"), []byte("FROM ./w.gguf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "w.gguf"), []byte("weights"), 0o644); err != nil {
		t.Fatal(err)
	}
	buf, err := dirTar(dir, []string{"m.Modelfile", "w.gguf"})
	if err != nil {
		t.Fatalf("dirTar: %v", err)
	}
	tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	seen := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		body, _ := io.ReadAll(tr)
		seen[h.Name] = int64(len(body))
		if h.Size != int64(len(body)) {
			t.Errorf("%s: header says %d, body is %d", h.Name, h.Size, len(body))
		}
	}
	// convertDir without its leading slash, which is what CopyToContainer
	// wants for a destination of "/".
	for _, want := range []string{"convert/", "convert/m.Modelfile", "convert/w.gguf"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("tar lacks %q; has %v", want, seen)
		}
	}
	if seen["convert/w.gguf"] != int64(len("weights")) {
		t.Errorf("weight round-tripped as %d bytes", seen["convert/w.gguf"])
	}
}

func TestDirTarFailsOnAMissingFile(t *testing.T) {
	if _, err := dirTar(t.TempDir(), []string{"absent.gguf"}); err == nil {
		t.Fatal("a missing file must be an error, not an empty entry")
	}
}

func TestPullOllamaModelRefusesBadInput(t *testing.T) {
	var nilClient *Client
	if _, err := nilClient.PullOllamaModel(t.Context(), "x"); err == nil {
		t.Error("a nil client must refuse")
	}
}

// A launchd-started agent on a Mac has no Homebrew prefix on PATH; the import
// must still find the ollama that is serving (live: host6, 2026-10-09).
func TestOllamaBinary_FallsBackToKnownInstallPaths(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "ollama")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notExec := filepath.Join(dir, "ollama-noexec")
	if err := os.WriteFile(notExec, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir()) // PATH has no ollama

	old := ollamaHostPaths
	t.Cleanup(func() { ollamaHostPaths = old })

	ollamaHostPaths = []string{filepath.Join(dir, "missing"), notExec, fake}
	if got, ok := ollamaBinary(); !ok || got != fake {
		t.Fatalf("ollamaBinary() = %q, %v; want %q, true", got, ok, fake)
	}

	ollamaHostPaths = []string{filepath.Join(dir, "missing"), notExec}
	if got, ok := ollamaBinary(); ok {
		t.Fatalf("ollamaBinary() = %q, true; want not found (missing and non-executable only)", got)
	}
}

// A pull body naming `ollama:<tag>` resolves to the staged pair, with the
// created model named by the tag (not "ollama:gemma4:12b").
func TestPullOllamaModelStripsOllamaPrefix(t *testing.T) {
	t.Setenv("NOO_MODEL_CACHE_URL", "")
	c := &Client{}
	_, err := c.PullOllamaModel(context.Background(), "ollama:gemma4:12b")
	if err == nil || !strings.Contains(err.Error(), "NOO_MODEL_CACHE_URL") {
		t.Fatalf("err = %v, want it to get past name resolution to the data-plane check", err)
	}
	_, err = c.PullOllamaModel(context.Background(), "ollama:hf.co/org/repo")
	if err == nil || !strings.Contains(err.Error(), "neither a store artifact name nor a registry.ollama.ai reference") {
		t.Fatalf("err = %v, want a bad-reference refusal", err)
	}
}
