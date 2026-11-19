// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
	for _, want := range []string{"home/nonroot/.ollama/convert/", "home/nonroot/.ollama/convert/m.Modelfile", "home/nonroot/.ollama/convert/w.gguf"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("tar lacks %q; has %v", want, seen)
		}
	}
	if seen["home/nonroot/.ollama/convert/w.gguf"] != int64(len("weights")) {
		t.Errorf("weight round-tripped as %d bytes", seen["home/nonroot/.ollama/convert/w.gguf"])
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

// rc.2 (0.6.16): the hardened image is uid 65532 with a root-owned `/`, so the
// staging dir must be under the user's store, and the archive entries must be
// owned by that user (the daemon otherwise extracts them as root).
func TestConvertDirIsNotRootLevelAndEntriesAreOwnedByTheImageUser(t *testing.T) {
	if !strings.HasPrefix(convertDir, ollamaOursStore+"/") {
		t.Fatalf("convertDir %q is not under the non-root store %q", convertDir, ollamaOursStore)
	}
	if strings.Count(strings.TrimPrefix(convertDir, "/"), "/") < 2 {
		t.Fatalf("convertDir %q is a root-level path", convertDir)
	}
	dir := t.TempDir()
	for _, n := range []string{"m.Modelfile", "w.gguf"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	buf, err := dirTar(dir, []string{"m.Modelfile", "w.gguf"})
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(buf)
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
		if !strings.HasPrefix(h.Name, strings.TrimPrefix(convertDir, "/")) {
			t.Errorf("entry %q is outside convertDir", h.Name)
		}
		if h.Uid != 65532 || h.Gid != 65532 {
			t.Errorf("entry %q owned %d:%d, want 65532:65532", h.Name, h.Uid, h.Gid)
		}
		if h.Mode&0o044 != 0o044 {
			t.Errorf("entry %q mode %o is not world-readable", h.Name, h.Mode)
		}
	}
	if n != 3 {
		t.Errorf("want dir + 2 files, got %d entries", n)
	}
	if got := convertCleanupCmd(); got[len(got)-1] != convertDir {
		t.Errorf("cleanup targets %v, want %s", got, convertDir)
	}
}

// ── copies into noo-ollama carry their owner in the tar, not CopyUIDGID ──
//
// rc.4: with CopyUIDGID the daemon resolves the container's Config.User
// through a passwd lookup; the image's `USER 65532:65532` is taken whole as a
// name and the copy fails ("getent unable to find entry \"65532:65532\" in
// passwd database"). Without it the daemon's untar chowns each entry to its
// tar header's uid/gid, so every header must name the owner.

// archiveCopy is one PUT /containers/<name>/archive the fake daemon saw.
type archiveCopy struct {
	query map[string][]string
	body  []byte
}

// newCopyCaptureDaemon fakes the Docker API for noo-ollama: running, its
// store mounted at ollamaOursStore, every exec exiting 0, and every archive
// copy recorded.
func newCopyCaptureDaemon(t *testing.T) (*Client, func() []archiveCopy) {
	t.Helper()
	var mu sync.Mutex
	var copies []archiveCopy
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/_ping"):
			w.Header().Set("API-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id":"c1","Name":"/` + OllamaContainer + `","State":{"Status":"running","Running":true},"Mounts":[{"Type":"volume","Destination":"` + ollamaOursStore + `"}]}`))
		case r.Method == http.MethodPut && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/archive"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			copies = append(copies, archiveCopy{query: r.URL.Query(), body: body})
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/containers/"+OllamaContainer+"/exec"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"e1"}`))
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/exec/e1/start"):
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusOK)
				return
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_ = buf.Flush()
			_ = conn.Close()
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/exec/e1/json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ID":"e1","Running":false,"ExitCode":0}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"not faked: ` + r.Method + " " + p + `"}`))
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
	c, err := NewClient(http.DefaultClient, "http", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	return c, func() []archiveCopy {
		mu.Lock()
		defer mu.Unlock()
		return append([]archiveCopy(nil), copies...)
	}
}

// checkCopyOwnedBy asserts the copy did not ask for CopyUIDGID and that every
// entry in its archive is owned by uid:uid.
func checkCopyOwnedBy(t *testing.T, cp archiveCopy, uid int, wantEntries int) {
	t.Helper()
	if v, ok := cp.query["copyUIDGID"]; ok {
		t.Errorf("the copy asked for copyUIDGID=%v; the daemon would look up the image's USER as a passwd name and fail", v)
	}
	tr := tar.NewReader(bytes.NewReader(cp.body))
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read the copied tar: %v", err)
		}
		n++
		if h.Uid != uid || h.Gid != uid {
			t.Errorf("entry %q owned %d:%d, want %d:%d (the daemon chowns to the header)", h.Name, h.Uid, h.Gid, uid, uid)
		}
	}
	if n != wantEntries {
		t.Errorf("the copied tar has %d entries, want %d", n, wantEntries)
	}
}

func TestWriteManifestCopyCarriesTheOwnerWithoutCopyUIDGID(t *testing.T) {
	c, copies := newCopyCaptureDaemon(t)
	mw, err := c.writeManifestContainer(t.Context(), "library", "qwen2.5", "0.5b", []byte(`{"schemaVersion":2}`))
	if err != nil {
		t.Fatalf("writeManifestContainer: %v", err)
	}
	if mw != nil && mw.commit != nil {
		mw.commit()
	}
	got := copies()
	if len(got) != 1 {
		t.Fatalf("want one archive copy, got %d", len(got))
	}
	checkCopyOwnedBy(t, got[0], ollamaStoreUID, 1)
}

func TestOllamaCreateCopyCarriesTheOwnerWithoutCopyUIDGID(t *testing.T) {
	c, copies := newCopyCaptureDaemon(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.Modelfile"), []byte("FROM ./w.gguf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "w.gguf"), []byte("weights"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ollamaCreateInContainer(t.Context(), dir, "m", "m.Modelfile", "w.gguf"); err != nil {
		t.Fatalf("ollamaCreateInContainer: %v", err)
	}
	got := copies()
	if len(got) != 1 {
		t.Fatalf("want one archive copy, got %d", len(got))
	}
	checkCopyOwnedBy(t, got[0], convertOwner, 3)
}

// Source guard: no CopyUIDGID: true in the agent's non-test code. The daemon
// resolves the container's USER through passwd for it, and our hardened
// images run as a numeric `USER 65532:65532` that has no passwd entry, so the
// copy fails on a real daemon. Put the owner in the tar headers instead.
func TestNoCopyUIDGIDInAgentCode(t *testing.T) {
	re := regexp.MustCompile(`CopyUIDGID\s*:\s*true`)
	root := ".." // node-agent-go/internal
	walked := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		walked++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if re.MatchString(line) {
				t.Errorf("%s:%d sets CopyUIDGID: true — the daemon looks the image's numeric USER up as a passwd name and the copy fails; set Uid/Gid in the tar headers instead", p, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if walked < 10 {
		t.Fatalf("the guard walked %d files under %s; it is not reading the agent's code", walked, root)
	}
}
