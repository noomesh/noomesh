// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// ── fixtures ────────────────────────────────────────────────────────────

type blobFix struct {
	media string
	body  []byte
}

// mirrorFixture is a registry manifest for blobs (the first is the config)
// in the registry's own byte layout, and the blobs by hex digest.
func mirrorFixture(blobs ...blobFix) ([]byte, map[string][]byte) {
	desc := func(b blobFix) string {
		return fmt.Sprintf(`{"mediaType":%q,"digest":"sha256:%s","size":%d}`, b.media, sha(b.body), len(b.body))
	}
	var layers []string
	for _, b := range blobs[1:] {
		layers = append(layers, desc(b))
	}
	body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":` +
		desc(blobs[0]) + `,"layers":[` + strings.Join(layers, ",") + `]}`)
	byHex := map[string][]byte{}
	for _, b := range blobs {
		byHex[sha(b.body)] = b.body
	}
	return body, byHex
}

// visionFixture is a model with a projector and a layer type nobody knows
// yet: exactly what the old GGUF + Modelfile rebuild refused.
func visionFixture() ([]byte, map[string][]byte) {
	return mirrorFixture(
		blobFix{"application/vnd.docker.container.image.v1+json", []byte(`{"model_format":"gguf","renderer":"gemma4","parser":"gemma4"}`)},
		blobFix{ollamaModelMedia, []byte("GGUF-the-weights")},
		blobFix{"application/vnd.ollama.image.projector", []byte("GGUF-the-projector")},
		blobFix{"application/vnd.ollama.image.template", []byte("{{ .Prompt }}")},
		blobFix{"application/vnd.ollama.image.future-thing", []byte("tomorrow's layer")},
	)
}

// ── parseMirrorManifest ────────────────────────────────────────────────

func TestAMirrorManifestWithAProjectorAndAnUnknownLayerParses(t *testing.T) {
	body, blobs := visionFixture()
	m, err := parseMirrorManifest(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.SHA256 != sha(body) {
		t.Fatalf("manifest digest %s, want the sha256 of its exact bytes %s", m.SHA256, sha(body))
	}
	if len(m.Blobs) != len(blobs) {
		t.Fatalf("%d blobs, want %d", len(m.Blobs), len(blobs))
	}
	if !strings.Contains(m.Blobs[0].Media, "container.image") {
		t.Fatalf("the config blob must come first, got %+v", m.Blobs[0])
	}
	for _, b := range m.Blobs {
		if int64(len(blobs[b.Hex])) != b.Size {
			t.Fatalf("blob %s size %d, want %d", b.short(), b.Size, len(blobs[b.Hex]))
		}
	}
}

func TestADuplicatedLayerIsOneBlob(t *testing.T) {
	w := blobFix{ollamaModelMedia, []byte("GGUF-w")}
	body, _ := mirrorFixture(blobFix{"application/vnd.docker.container.image.v1+json", []byte("{}")}, w, w)
	m, err := parseMirrorManifest(body)
	if err != nil || len(m.Blobs) != 2 {
		t.Fatalf("want 2 unique blobs, got %v %v", m, err)
	}
}

func TestAMirrorManifestThatCouldMisleadIsRefused(t *testing.T) {
	cfg := `{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `","size":2}`
	layer := func(media, digest string, size int64) string {
		return fmt.Sprintf(`{"mediaType":%q,"digest":%q,"size":%d}`, media, digest, size)
	}
	good := "sha256:" + strings.Repeat("b", 64)
	model := layer(ollamaModelMedia, good, 10)
	wrap := func(schema int, config string, layers ...string) []byte {
		c := ""
		if config != "" {
			c = `"config":` + config + `,`
		}
		return []byte(fmt.Sprintf(`{"schemaVersion":%d,%s"layers":[%s]}`, schema, c, strings.Join(layers, ",")))
	}
	many := make([]string, mirrorMaxLayers+1)
	for i := range many {
		many[i] = layer(ollamaModelMedia, fmt.Sprintf("sha256:%064x", i+1), 1)
	}
	cases := map[string][]byte{
		"schemaVersion 1":       wrap(1, cfg, model),
		"no config":             wrap(2, "", model),
		"no layers":             wrap(2, cfg),
		"too many layers":       wrap(2, cfg, many...),
		"uppercase digest":      wrap(2, cfg, layer(ollamaModelMedia, "sha256:"+strings.Repeat("B", 64), 10)),
		"short digest":          wrap(2, cfg, layer(ollamaModelMedia, "sha256:"+strings.Repeat("b", 63), 10)),
		"sha512 digest":         wrap(2, cfg, layer(ollamaModelMedia, "sha512:"+strings.Repeat("b", 64), 10)),
		"a path as a digest":    wrap(2, cfg, layer(ollamaModelMedia, "sha256:../../../../etc/passwd", 10)),
		"size 0":                wrap(2, cfg, layer(ollamaModelMedia, good, 0)),
		"negative size":         wrap(2, cfg, layer(ollamaModelMedia, good, -1)),
		"size over the bound":   wrap(2, cfg, layer(ollamaModelMedia, good, mirrorMaxBlobBytes+1)),
		"sizes over the bound":  wrap(2, cfg, layer(ollamaModelMedia, good, mirrorMaxBlobBytes), layer("x/y", "sha256:"+strings.Repeat("c", 64), 1)),
		"one blob, two sizes":   wrap(2, cfg, model, layer(ollamaModelMedia, good, 11)),
		"a media type with a /..": wrap(2, cfg, model, layer("a b", "sha256:"+strings.Repeat("c", 64), 1)),
		"no model layer":        wrap(2, cfg, layer("application/vnd.ollama.image.template", good, 10)),
		"missing size":          wrap(2, cfg, `{"mediaType":"x","digest":"`+good+`"}`),
		"not JSON":              []byte("<html>"),
		"over 1 MiB":            append(wrap(2, cfg, model), bytes.Repeat([]byte(" "), mirrorMaxManifestBytes)...),
	}
	for name, body := range cases {
		if _, err := parseMirrorManifest(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseMirrorManifest(wrap(2, cfg, model)); err != nil {
		t.Fatalf("the control case must parse: %v", err)
	}
}

// ── installMirror (fakes, each check alone) ─────────────────────────────

// fakeAPI is ollama's three routes in memory, with an event log.
type fakeAPI struct {
	mu      sync.Mutex
	have    map[string]bool
	events  []string
	pushed  []string
	tags    map[string]string // model → digest, set by the fake writer
	tagsErr error
	// dropOnce: these blobs vanish right after their first push (ollama's
	// startup prune); dropAlways: after every push.
	dropOnce, dropAlways map[string]bool
}

func newFakeAPI(have ...string) *fakeAPI {
	f := &fakeAPI{have: map[string]bool{}, tags: map[string]string{}, dropOnce: map[string]bool{}, dropAlways: map[string]bool{}}
	for _, h := range have {
		f.have[h] = true
	}
	return f
}

func (f *fakeAPI) HasBlob(_ context.Context, h string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, fmt.Sprintf("head %s %v", h[:6], f.have[h]))
	return f.have[h], nil
}

func (f *fakeAPI) PushBlob(_ context.Context, h string, _ int64, body io.Reader) error {
	b, err := io.ReadAll(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.events = append(f.events, "aborted "+h[:6])
		return err
	}
	if sha(b) != h {
		return errors.New("digest mismatch")
	}
	f.events = append(f.events, "push "+h[:6])
	f.pushed = append(f.pushed, h)
	f.have[h] = !f.dropAlways[h] && !f.dropOnce[h]
	delete(f.dropOnce, h)
	return nil
}

func (f *fakeAPI) TagDigest(_ context.Context, model string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "tags")
	d, ok := f.tags[model]
	return d, ok, f.tagsErr
}

type mirrorRun struct {
	api               *fakeAPI
	fetched           []string
	written, undone   int
	committed         int
	writeLists        string // the digest the fake daemon then lists
	writeErr          error
}

func (r *mirrorRun) deps(t *testing.T, blobs map[string][]byte) mirrorDeps {
	dir := t.TempDir()
	return mirrorDeps{
		api: r.api,
		fetchBlob: func(_ context.Context, b mirrorBlob) (string, error) {
			r.fetched = append(r.fetched, b.Hex)
			p := filepath.Join(dir, b.blobName())
			return p, os.WriteFile(p, blobs[b.Hex], 0o600)
		},
		writeManifest: func(_ context.Context, ns, name, tag string, body []byte) (*manifestWrite, error) {
			r.api.mu.Lock()
			r.api.events = append(r.api.events, "write")
			if r.writeLists != "" {
				r.api.tags[ollamaModelName(ns, name, tag)] = r.writeLists
			}
			r.api.mu.Unlock()
			r.written++
			if r.writeErr != nil {
				return nil, r.writeErr
			}
			return &manifestWrite{undo: func() error { r.undone++; return nil }, commit: func() { r.committed++ }}, nil
		},
	}
}

func TestMirrorPushesExactlyTheMissingBlobsThenWritesTheManifestLast(t *testing.T) {
	body, blobs := visionFixture()
	m, _ := parseMirrorManifest(body)
	present := m.Blobs[0].Hex // the config is already in ollama
	r := &mirrorRun{api: newFakeAPI(present), writeLists: m.SHA256}
	if err := installMirror(t.Context(), "library", "gemma4", "e2b", m, r.deps(t, blobs)); err != nil {
		t.Fatalf("install: %v", err)
	}
	var want []string
	for _, b := range m.Blobs[1:] {
		want = append(want, b.Hex)
	}
	if !slices.Equal(r.api.pushed, want) {
		t.Fatalf("pushed %v, want exactly the blobs ollama lacked %v", r.api.pushed, want)
	}
	if slices.Contains(r.fetched, present) {
		t.Fatal("a blob ollama already held was fetched from the store")
	}
	// The manifest is written once, after a HEAD pass that found EVERY blob
	// present, and then the daemon is asked to list it.
	w := slices.Index(r.api.events, "write")
	if w < len(m.Blobs) || r.written != 1 || r.committed != 1 || r.undone != 0 {
		t.Fatalf("events %v written=%d committed=%d undone=%d", r.api.events, r.written, r.committed, r.undone)
	}
	for i, b := range m.Blobs {
		if ev := r.api.events[w-len(m.Blobs)+i]; ev != "head "+b.Hex[:6]+" true" {
			t.Fatalf("the HEAD pass before the write must confirm every blob in order; event %q (all: %v)", ev, r.api.events)
		}
	}
	if r.api.events[len(r.api.events)-1] != "tags" {
		t.Fatalf("the daemon was not asked to list the tag after the write: %v", r.api.events)
	}
}

func TestABlobPrunedAfterItsPushIsPushedAgainBeforeTheManifest(t *testing.T) {
	body, blobs := visionFixture()
	m, _ := parseMirrorManifest(body)
	r := &mirrorRun{api: newFakeAPI(), writeLists: m.SHA256}
	r.api.dropOnce[m.Blobs[2].Hex] = true
	if err := installMirror(t.Context(), "library", "gemma4", "e2b", m, r.deps(t, blobs)); err != nil {
		t.Fatalf("install: %v", err)
	}
	n := 0
	for _, h := range r.api.pushed {
		if h == m.Blobs[2].Hex {
			n++
		}
	}
	if n != 2 || r.written != 1 {
		t.Fatalf("the pruned blob was pushed %d times (want 2) and the manifest written %d times", n, r.written)
	}
}

func TestABlobThatKeepsVanishingFailsWithoutAManifest(t *testing.T) {
	body, blobs := visionFixture()
	m, _ := parseMirrorManifest(body)
	r := &mirrorRun{api: newFakeAPI(), writeLists: m.SHA256}
	r.api.dropAlways[m.Blobs[1].Hex] = true
	err := installMirror(t.Context(), "library", "gemma4", "e2b", m, r.deps(t, blobs))
	if err == nil || !strings.Contains(err.Error(), "re-run") {
		t.Fatalf("want a bounded failure naming the re-run, got %v", err)
	}
	if r.written != 0 {
		t.Fatal("a manifest was written while ollama lacked one of its blobs")
	}
	n := 0
	for _, h := range r.api.pushed {
		if h == m.Blobs[1].Hex {
			n++
		}
	}
	if n != mirrorMaxRounds {
		t.Fatalf("pushed %d times, want the bound %d", n, mirrorMaxRounds)
	}
}

func TestNoSpaceMeansNothingIsPushed(t *testing.T) {
	body, blobs := visionFixture()
	m, _ := parseMirrorManifest(body)
	r := &mirrorRun{api: newFakeAPI(), writeLists: m.SHA256}
	d := r.deps(t, blobs)
	d.checkSpace = func([]mirrorBlob) error { return errors.New("no room") }
	if err := installMirror(t.Context(), "library", "gemma4", "e2b", m, d); err == nil || len(r.api.pushed) != 0 || r.written != 0 {
		t.Fatalf("err=%v pushed=%v written=%d", err, r.api.pushed, r.written)
	}
}

func TestAManifestTheDaemonDoesNotReadIsTakenBackOut(t *testing.T) {
	body, blobs := visionFixture()
	m, _ := parseMirrorManifest(body)
	for name, setup := range map[string]func(r *mirrorRun){
		"not listed":     func(r *mirrorRun) { r.writeLists = "" },
		"another digest": func(r *mirrorRun) { r.writeLists = strings.Repeat("f", 64) },
		"tags failed":    func(r *mirrorRun) { r.writeLists = m.SHA256; r.api.tagsErr = errors.New("boom") },
	} {
		r := &mirrorRun{api: newFakeAPI()}
		setup(r)
		err := installMirror(t.Context(), "library", "gemma4", "e2b", m, r.deps(t, blobs))
		if err == nil || r.undone != 1 || r.committed != 0 || !strings.Contains(err.Error(), "taken back out") {
			t.Errorf("%s: err=%v undone=%d committed=%d", name, err, r.undone, r.committed)
		}
	}
}

// ── the push itself: hashing, withholding, bounds ───────────────────────

// recordingDaemon is ollama's upload route over real HTTP: it stores a blob
// only when the body is complete and hashes to its URL digest, and records
// every body it saw (complete or not).
type recordingDaemon struct {
	mu       sync.Mutex
	stored   map[string][]byte
	received []int
	srv      *httptest.Server
}

func newRecordingDaemon(t *testing.T) *recordingDaemon {
	d := &recordingDaemon{stored: map[string][]byte{}}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimPrefix(r.URL.Path, "/api/blobs/sha256:")
		switch r.Method {
		case http.MethodHead:
			d.mu.Lock()
			_, ok := d.stored[h]
			d.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodPost:
			b, err := io.ReadAll(r.Body)
			d.mu.Lock()
			d.received = append(d.received, len(b))
			d.mu.Unlock()
			if err != nil || int64(len(b)) != r.ContentLength {
				return
			}
			if sha(b) != h {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			d.mu.Lock()
			d.stored[h] = b
			d.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		}
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func pushDeps(t *testing.T, d *recordingDaemon, file []byte) mirrorDeps {
	p := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(p, file, 0o600); err != nil {
		t.Fatal(err)
	}
	return mirrorDeps{
		api:       &ollamaHTTP{base: d.srv.URL, transport: &http.Transport{}},
		fetchBlob: func(context.Context, mirrorBlob) (string, error) { return p, nil },
	}
}

func TestAPushStreamsTheVerifiedBytes(t *testing.T) {
	d := newRecordingDaemon(t)
	good := bytes.Repeat([]byte("weights!"), 100_000)
	b := mirrorBlob{Hex: sha(good), Size: int64(len(good))}
	if err := pushOne(t.Context(), pushDeps(t, d, good), b); err != nil {
		t.Fatalf("push: %v", err)
	}
	if !bytes.Equal(d.stored[b.Hex], good) {
		t.Fatal("the daemon did not store the blob")
	}
}

func TestBytesThatDoNotHashToTheDigestNeverReachTheDaemonWhole(t *testing.T) {
	d := newRecordingDaemon(t)
	good := bytes.Repeat([]byte("weights!"), 100_000)
	bad := bytes.Clone(good)
	bad[len(bad)-1] ^= 1 // same size, last byte flipped
	b := mirrorBlob{Hex: sha(good), Size: int64(len(good))}
	err := pushOne(t.Context(), pushDeps(t, d, bad), b)
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("want the agent's own hash refusal, got %v", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.stored) != 0 {
		t.Fatal("the daemon stored a blob")
	}
	for _, n := range d.received {
		if n >= len(good) {
			t.Fatalf("the daemon received a complete body (%d bytes) of the wrong bytes: the agent must withhold the end", n)
		}
	}
}

func TestAFetchedBlobOfTheWrongSizeIsNotPushed(t *testing.T) {
	d := newRecordingDaemon(t)
	good := []byte("GGUF-weights")
	b := mirrorBlob{Hex: sha(good), Size: int64(len(good)) + 1}
	if err := pushOne(t.Context(), pushDeps(t, d, good), b); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("want a size refusal, got %v", err)
	}
	if len(d.received) != 0 {
		t.Fatal("a push was attempted")
	}
}

func TestTheHashingReaderRefusesAShortSource(t *testing.T) {
	hr := &hashingReader{r: strings.NewReader("abc"), h: sha256.New(), want: strings.Repeat("0", 64), limit: 4}
	_, err := io.ReadAll(hr)
	if err == nil || hr.done {
		t.Fatalf("a short source must fail, got %v done=%v", err, hr.done)
	}
}

func TestPushBudgetGrowsWithSize(t *testing.T) {
	if pushBudget(0) <= 0 || pushBudget(100<<30) <= pushBudget(1<<20) {
		t.Fatal("the push budget must be positive and grow with the blob")
	}
}

func TestOllamaHTTPReadsTheThreeRoutes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "aa"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "bb"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusInternalServerError)
		case r.URL.Path == "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"gemma4:e2b","model":"gemma4:e2b","digest":"ABC"}]}`))
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"digest mismatch"}`))
		}
	}))
	defer srv.Close()
	o := &ollamaHTTP{base: srv.URL, transport: &http.Transport{}}
	if ok, err := o.HasBlob(t.Context(), "aa"); !ok || err != nil {
		t.Errorf("200 → present: %v %v", ok, err)
	}
	if ok, err := o.HasBlob(t.Context(), "bb"); ok || err != nil {
		t.Errorf("404 → absent: %v %v", ok, err)
	}
	if _, err := o.HasBlob(t.Context(), "cc"); err == nil {
		t.Error("500 must be an error, not an answer")
	}
	if d, ok, err := o.TagDigest(t.Context(), "gemma4:e2b"); d != "abc" || !ok || err != nil {
		t.Errorf("tags: %q %v %v", d, ok, err)
	}
	if _, ok, _ := o.TagDigest(t.Context(), "other:x"); ok {
		t.Error("a model not listed was found")
	}
	if err := o.PushBlob(t.Context(), "aa", 1, strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("a 400 push must fail with ollama's reason, got %v", err)
	}
}

// ── writeManifestNative: the one file written directly ──────────────────

func manifestPath(models string) string {
	return filepath.Join(models, "manifests", "registry.ollama.ai", "library", "gemma4", "e2b")
}

func TestTheNativeManifestLandsInOllamasLayoutAndUndoes(t *testing.T) {
	models := filepath.Join(t.TempDir(), "models")
	if err := os.Mkdir(models, 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := writeManifestNative(models, "library", "gemma4", "e2b", []byte("v1"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := os.Lstat(manifestPath(models))
	if err != nil || st.Mode().Perm() != 0o644 || !st.Mode().IsRegular() {
		t.Fatalf("manifest %v %v", st, err)
	}
	if err := w.undo(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(manifestPath(models)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("undo of a first write must remove it")
	}
	// Over an existing manifest, undo restores the old bytes.
	if _, err := writeManifestNative(models, "library", "gemma4", "e2b", []byte("old")); err != nil {
		t.Fatal(err)
	}
	w, err = writeManifestNative(models, "library", "gemma4", "e2b", []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(manifestPath(models)); string(b) != "new" {
		t.Fatalf("got %q", b)
	}
	if err := w.undo(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(manifestPath(models)); string(b) != "old" {
		t.Fatalf("undo restored %q, want the old bytes", b)
	}
	// No temp file is left behind.
	ents, _ := os.ReadDir(filepath.Dir(manifestPath(models)))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".noo-") {
			t.Fatalf("left behind %s", e.Name())
		}
	}
}

func TestASymlinkedModelStoreIsRefused(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	_ = os.Mkdir(real, 0o755)
	link := filepath.Join(root, "models")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := writeManifestNative(link, "library", "gemma4", "e2b", []byte("x")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("want a symlink refusal, got %v", err)
	}
	assertEmptyTree(t, real)
}

func TestASymlinkBelowTheStoreIsNotWrittenThrough(t *testing.T) {
	for _, at := range []string{"manifests", "manifests/registry.ollama.ai", "manifests/registry.ollama.ai/library", "manifests/registry.ollama.ai/library/gemma4"} {
		t.Run(strings.ReplaceAll(at, "/", "_"), func(t *testing.T) {
			root := t.TempDir()
			models := filepath.Join(root, "models")
			elsewhere := filepath.Join(root, "elsewhere")
			_ = os.MkdirAll(filepath.Dir(filepath.Join(models, at)), 0o755)
			_ = os.Mkdir(elsewhere, 0o755)
			if err := os.Symlink(elsewhere, filepath.Join(models, at)); err != nil {
				t.Fatal(err)
			}
			_, err := writeManifestNative(models, "library", "gemma4", "e2b", []byte("x"))
			if err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("want a symlink refusal, got %v", err)
			}
			assertEmptyTree(t, elsewhere)
		})
	}
}

func TestAnExistingManifestThatIsASymlinkIsRefused(t *testing.T) {
	models := filepath.Join(t.TempDir(), "models")
	dir := filepath.Dir(manifestPath(models))
	_ = os.MkdirAll(dir, 0o755)
	target := filepath.Join(t.TempDir(), "target")
	_ = os.WriteFile(target, []byte("untouched"), 0o644)
	if err := os.Symlink(target, manifestPath(models)); err != nil {
		t.Fatal(err)
	}
	if _, err := writeManifestNative(models, "library", "gemma4", "e2b", []byte("x")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "untouched" {
		t.Fatal("the symlink's target was written")
	}
	if st, _ := os.Lstat(manifestPath(models)); st.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced")
	}
}

func TestAWritableByOthersDirectoryBelowTheStoreIsRefused(t *testing.T) {
	models := filepath.Join(t.TempDir(), "models")
	open := filepath.Join(models, "manifests")
	_ = os.MkdirAll(open, 0o755)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := writeManifestNative(models, "library", "gemma4", "e2b", []byte("x")); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

func TestASymlinkAboveTheStoreOwnedByAUserIsRefused(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	_ = os.MkdirAll(filepath.Join(real, "models"), 0o755)
	link := filepath.Join(root, "via")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// Under root (noo-batch) the link is root's: hand it to nobody, the
		// case being tested.
		if err := os.Lchown(link, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	_, err := writeManifestNative(filepath.Join(link, "models"), "library", "gemma4", "e2b", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("want a refusal of a user-owned link above the store, got %v", err)
	}
	assertEmptyTree(t, filepath.Join(real, "models"))
}

func TestAnAncestorOwnedByAnotherUserIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give a directory to another user (noo-batch runs tests as root)")
	}
	root := t.TempDir()
	other := filepath.Join(root, "other")
	models := filepath.Join(other, "models")
	_ = os.MkdirAll(models, 0o755)
	if err := os.Chown(other, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := writeManifestNative(models, "library", "gemma4", "e2b", []byte("x")); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("want an ownership refusal, got %v", err)
	}
}

func assertEmptyTree(t *testing.T, dir string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && p != dir {
			t.Errorf("written through a link: %s", p)
		}
		return nil
	})
}

// ── the whole import, through the store and a daemon that reads its store ─

// storeDaemon is a native ollama: upload routes that write into modelsDir
// (as ollama would) and /api/tags read from modelsDir's manifests.
func storeDaemon(t *testing.T, models string) (*httptest.Server, *[]string) {
	var pushed []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blobPath := func(h string) string { return filepath.Join(models, "blobs", "sha256-"+h) }
		h := strings.TrimPrefix(r.URL.Path, "/api/blobs/sha256:")
		switch {
		case r.Method == http.MethodHead:
			if _, err := os.Stat(blobPath(h)); err != nil {
				w.WriteHeader(http.StatusNotFound)
			}
		case r.Method == http.MethodPost:
			b, err := io.ReadAll(r.Body)
			if err != nil || sha(b) != h {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = os.MkdirAll(filepath.Join(models, "blobs"), 0o755)
			_ = os.WriteFile(blobPath(h), b, 0o644)
			mu.Lock()
			pushed = append(pushed, h)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case r.URL.Path == "/api/tags":
			var out []string
			base := filepath.Join(models, "manifests", "registry.ollama.ai")
			_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
					return nil
				}
				rel, _ := filepath.Rel(base, p)
				parts := strings.Split(rel, string(filepath.Separator))
				b, _ := os.ReadFile(p)
				name := parts[0] + "/" + parts[1] + ":" + parts[2]
				name = strings.TrimPrefix(name, "library/")
				out = append(out, fmt.Sprintf(`{"name":%q,"digest":%q}`, name, sha(b)))
				return nil
			})
			_, _ = w.Write([]byte(`{"models":[` + strings.Join(out, ",") + `]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &pushed
}

func TestAMirrorStagedVisionTagImportsEndToEnd(t *testing.T) {
	body, blobs := visionFixture()
	stem := "ollama+library+gemma4+e2b-it-qat"
	files := map[string][]byte{stem + mirrorManifestSuffix: body}
	for h, b := range blobs {
		files["sha256-"+h+mirrorBlobSuffix] = b
	}
	fc := stageController(t, files)
	models := filepath.Join(t.TempDir(), "models")
	_ = os.Mkdir(models, 0o755)
	t.Setenv("OLLAMA_MODELS", models)
	daemon, pushed := storeDaemon(t, models)
	t.Setenv("OLLAMA_URL", daemon.URL)

	res, err := (&Client{}).PullOllamaModel(t.Context(), "gemma4:e2b-it-qat")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.ManifestSHA256 != sha(body) || res.Blobs != len(blobs) || res.Via != "host" {
		t.Fatalf("result %+v", res)
	}
	if got, _ := os.ReadFile(filepath.Join(models, "manifests/registry.ollama.ai/library/gemma4/e2b-it-qat")); !bytes.Equal(got, body) {
		t.Fatal("the manifest in ollama's store is not the staged bytes")
	}
	if len(*pushed) != len(blobs) {
		t.Fatalf("pushed %d blobs, want %d", len(*pushed), len(blobs))
	}
	if _, ran := fc.created(); ran {
		t.Fatal("`ollama create` ran: a mirror is installed, not rebuilt")
	}
	for _, h := range fc.hits {
		if strings.Contains(h, ".Modelfile") {
			t.Fatalf("a mirror import asked for a Modelfile: %s", h)
		}
	}
}

func TestAStoreBlobWhoseDigestIsNotItsNameIsRefused(t *testing.T) {
	body, blobs := visionFixture()
	stem := "ollama+library+gemma4+e2b-it-qat"
	files := map[string][]byte{stem + mirrorManifestSuffix: body}
	var swapped string
	for h, b := range blobs {
		files["sha256-"+h+mirrorBlobSuffix] = b
		if bytes.HasPrefix(b, []byte("GGUF-the-projector")) {
			swapped = h
		}
	}
	files["sha256-"+swapped+mirrorBlobSuffix] = []byte("GGUF-something-else")
	stageController(t, files)
	models := filepath.Join(t.TempDir(), "models")
	_ = os.Mkdir(models, 0o755)
	t.Setenv("OLLAMA_MODELS", models)
	daemon, pushed := storeDaemon(t, models)
	t.Setenv("OLLAMA_URL", daemon.URL)
	_, err := (&Client{}).PullOllamaModel(t.Context(), "gemma4:e2b-it-qat")
	if err == nil || !strings.Contains(err.Error(), "not the blob its name says") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if slices.Contains(*pushed, swapped) {
		t.Fatal("the mislabelled blob was pushed")
	}
	if _, err := os.Stat(filepath.Join(models, "manifests")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a manifest was written for an incomplete model")
	}
}

func TestAGatewayThatPredatesTheKindIsNamed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if strings.Contains(r.URL.Path, "ollamamanifest") {
			_, _ = w.Write([]byte(`{"error":"unknown artifact kind 'ollamamanifest' (kinds: gguf, image, modelfile, modelset)"}`))
		}
	}))
	defer srv.Close()
	ask := func(kind string) error {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/artifacts/manifest/"+kind+"/x", nil)
		_, err := doArtifactManifest(srv.Client(), req)
		return err
	}
	err := ask("ollamamanifest")
	if !errors.Is(err, ErrArtifactKindUnknown) || !errors.Is(err, ErrArtifactAbsent) {
		t.Fatalf("an unknown-kind 400 must be both kind-unknown and absent, got %v", err)
	}
	if err := ask("gguf"); errors.Is(err, ErrArtifactKindUnknown) || !errors.Is(err, ErrArtifactAbsent) {
		t.Fatalf("a plain 400 is absent, not kind-unknown: %v", err)
	}
}

func TestTheModelNameOllamaListsDropsLibrary(t *testing.T) {
	if got := ollamaModelName("library", "gemma4", "e2b"); got != "gemma4:e2b" {
		t.Fatal(got)
	}
	if got := ollamaModelName("someone", "m", "q4"); got != "someone/m:q4" {
		t.Fatal(got)
	}
	_ = hex.EncodeToString
}
