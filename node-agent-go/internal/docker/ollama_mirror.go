// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Importing an ollama registry tag the controller staged as a MIRROR.
//
// `noo models fetch ollama:<tag>` (noo-cli/src/commands/ollama_stage.rs)
// copies the registry's manifest and every blob it names into the
// controller's store, byte for byte:
//
//	sha256-<hex>.ollama-blob                   one per blob (config included)
//	ollama+<ns>+<name>+<tag>.ollama-manifest   the registry's manifest, verbatim
//
// A mirror carries what a GGUF plus a Modelfile cannot: a vision projector,
// and any layer type ollama adds later. The node installs it without
// rebuilding anything:
//
//  1. The manifest is fetched from the store, digest-verified, and parsed
//     (parseMirrorManifest). It is only READ for the blob list; every path
//     the node writes is built from the validated tag, never from it.
//  2. Each blob ollama does not already hold (HEAD /api/blobs/<digest>) is
//     fetched from the store (verified against the gateway's digest, which
//     must equal the blob's name) and pushed to ollama through its own
//     upload route, POST /api/blobs/sha256:<hex>. The agent hashes the bytes
//     again as it streams them and fails the request on a mismatch; ollama's
//     own digest check (400) is the second check, not the only one. Ollama
//     writes the file into its store as its own user, so the agent never
//     writes a blob into someone else's directory.
//  3. Only when a full HEAD pass finds every blob present is the manifest
//     written, last. Until then ollama sees no model, never half of one. A
//     blob that goes missing between the push and that pass (ollama prunes
//     unreferenced blobs when it starts) is pushed again, a bounded number
//     of times.
//  4. The same daemon must then list the tag with the staged manifest's
//     digest (`/api/tags` reports the sha256 of the manifest file). If it
//     does not, the manifest went to a store that daemon does not read, and
//     it is taken back out.
//
// Only the manifest is written directly. On a native ollama that is
// writeManifestNative (ollama_mirror_unix.go: a symlink-refusing, owner-
// checked walk and an O_EXCL temp file renamed into place); in the
// noo-ollama container it is a one-file copy plus `mv` inside the container.
package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// The limits a staged manifest is held to. The CLI applies the same ones
// before it downloads anything (ollama_stage.rs MIRROR_*;
// tests/test_ollama_stage_parity.py pins that they match).
const (
	mirrorMaxLayers        = 64
	mirrorMaxManifestBytes = 1 << 20
	mirrorMaxBlobBytes     = 1 << 40
	mirrorBlobSuffix       = ".ollama-blob"
	mirrorManifestSuffix   = ".ollama-manifest"
	// mirrorMaxRounds bounds how many times missing blobs are pushed before
	// the import gives up.
	mirrorMaxRounds = 3
	// ollamaModelMedia is the layer every model has; a manifest without one
	// is not a model.
	ollamaModelMedia = "application/vnd.ollama.image.model"
)

var (
	mirrorDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mirrorMediaRe  = regexp.MustCompile(`^[A-Za-z0-9.+/_-]{1,128}$`)
)

// mirrorBlob is one blob the staged manifest names.
type mirrorBlob struct {
	Hex   string // 64 lowercase hex, no prefix
	Size  int64
	Media string
}

// mirrorManifest is a parsed staged manifest: its exact bytes, their digest,
// and the UNIQUE blobs it names (config first, then layers in order).
type mirrorManifest struct {
	Body   []byte
	SHA256 string
	Blobs  []mirrorBlob
}

// blobName is the store artifact a blob is staged under.
func (b mirrorBlob) blobName() string { return "sha256-" + b.Hex + mirrorBlobSuffix }

func (b mirrorBlob) short() string { return b.Hex[:12] }

// parseMirrorManifest validates a staged manifest. Nothing is filtered by
// media type: an unknown layer is what a mirror is for. What is refused is
// anything a path, a size bound or a request could be built from wrongly.
func parseMirrorManifest(body []byte) (*mirrorManifest, error) {
	if len(body) > mirrorMaxManifestBytes {
		return nil, fmt.Errorf("the staged manifest is %d bytes, over the %d limit", len(body), mirrorMaxManifestBytes)
	}
	type desc struct {
		MediaType *string `json:"mediaType"`
		Digest    *string `json:"digest"`
		Size      *int64  `json:"size"`
	}
	var m struct {
		SchemaVersion int     `json:"schemaVersion"`
		Config        *desc   `json:"config"`
		Layers        []*desc `json:"layers"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("the staged manifest is not JSON: %w", err)
	}
	if m.SchemaVersion != 2 {
		return nil, fmt.Errorf("the staged manifest has schemaVersion %d, want 2", m.SchemaVersion)
	}
	if m.Config == nil {
		return nil, errors.New("the staged manifest has no config")
	}
	if len(m.Layers) == 0 {
		return nil, errors.New("the staged manifest has no layers")
	}
	if len(m.Layers) > mirrorMaxLayers {
		return nil, fmt.Errorf("the staged manifest has %d layers, over the %d limit", len(m.Layers), mirrorMaxLayers)
	}
	sum := sha256.Sum256(body)
	out := &mirrorManifest{Body: body, SHA256: hex.EncodeToString(sum[:])}
	seen := map[string]bool{}
	var total int64
	hasModel := false
	all := append([]*desc{m.Config}, m.Layers...)
	for i, d := range all {
		what := "the config"
		if i > 0 {
			what = fmt.Sprintf("layer %d", i-1)
		}
		if d == nil || d.MediaType == nil || d.Digest == nil || d.Size == nil {
			return nil, fmt.Errorf("%s lacks a mediaType, digest or size", what)
		}
		if !mirrorMediaRe.MatchString(*d.MediaType) {
			return nil, fmt.Errorf("%s has an unusable mediaType %q", what, *d.MediaType)
		}
		if !mirrorDigestRe.MatchString(*d.Digest) {
			return nil, fmt.Errorf("%s digest %q is not sha256:<64 lowercase hex>", what, *d.Digest)
		}
		if *d.Size < 1 || *d.Size > mirrorMaxBlobBytes {
			return nil, fmt.Errorf("%s size %d is outside 1..%d", what, *d.Size, int64(mirrorMaxBlobBytes))
		}
		if i > 0 && *d.MediaType == ollamaModelMedia {
			hasModel = true
		}
		h := strings.TrimPrefix(*d.Digest, "sha256:")
		if seen[h] {
			// One blob listed twice (ollama dedupes too): it must say the
			// same size both times, or one of them is wrong.
			for _, b := range out.Blobs {
				if b.Hex == h && b.Size != *d.Size {
					return nil, fmt.Errorf("blob %s is listed with two sizes (%d and %d)", h[:12], b.Size, *d.Size)
				}
			}
			continue
		}
		seen[h] = true
		total += *d.Size
		if total > mirrorMaxBlobBytes {
			return nil, fmt.Errorf("the staged manifest's blobs add up to over %d bytes", int64(mirrorMaxBlobBytes))
		}
		out.Blobs = append(out.Blobs, mirrorBlob{Hex: h, Size: *d.Size, Media: *d.MediaType})
	}
	if !hasModel {
		return nil, fmt.Errorf("the staged manifest has no %s layer — not a model", ollamaModelMedia)
	}
	return out, nil
}

// ollamaBlobAPI is the daemon side of an install: the three ollama routes
// it uses. ollamaHTTP is the real one; tests count calls on a fake server.
type ollamaBlobAPI interface {
	HasBlob(ctx context.Context, hexDigest string) (bool, error)
	PushBlob(ctx context.Context, hexDigest string, size int64, body io.Reader) error
	// TagDigest is the digest `/api/tags` reports for model (the sha256 of
	// its manifest file), and whether the daemon lists it at all.
	TagDigest(ctx context.Context, model string) (string, bool, error)
}

// mirrorDeps is everything installMirror touches, so each check is tested
// on its own.
type mirrorDeps struct {
	api ollamaBlobAPI
	// fetchBlob returns a local file holding the blob, verified against the
	// store's digest for its name. The caller removes it after the push.
	fetchBlob func(ctx context.Context, b mirrorBlob) (string, error)
	// writeManifest puts body where the daemon reads ns/name:tag from.
	writeManifest func(ctx context.Context, ns, name, tag string, body []byte) (*manifestWrite, error)
	// checkSpace refuses before any push when the blobs cannot fit; nil =
	// not checked (the container's store is not visible to the agent).
	checkSpace func(missing []mirrorBlob) error
}

// manifestWrite is a written manifest that is not yet known to be read:
// undo puts back what the path held before (or removes it), commit drops
// whatever undo kept. Exactly one of them is called.
type manifestWrite struct {
	undo   func() error
	commit func()
}

// installMirror pushes every blob the daemon lacks, confirms them all, then
// writes the manifest and proves the daemon reads it.
func installMirror(ctx context.Context, ns, name, tag string, m *mirrorManifest, d mirrorDeps) error {
	for round := 1; ; round++ {
		var missing []mirrorBlob
		for _, b := range m.Blobs {
			ok, err := d.api.HasBlob(ctx, b.Hex)
			if err != nil {
				return fmt.Errorf("asking ollama for blob %s: %w", b.short(), err)
			}
			if !ok {
				missing = append(missing, b)
			}
		}
		if len(missing) == 0 {
			break
		}
		if round > mirrorMaxRounds {
			return fmt.Errorf("ollama still lacks %d blob(s) (first: %s) after %d rounds of pushing them — it removed them while the import ran "+
				"(ollama deletes unreferenced blobs when it restarts); re-run the import once ollama is steady", len(missing), missing[0].short(), mirrorMaxRounds)
		}
		if round == 1 && d.checkSpace != nil {
			if err := d.checkSpace(missing); err != nil {
				return err
			}
		}
		for _, b := range missing {
			if err := pushOne(ctx, d, b); err != nil {
				return err
			}
		}
	}
	w, err := d.writeManifest(ctx, ns, name, tag, m.Body)
	if err != nil {
		return fmt.Errorf("writing the manifest for %s: %w", ollamaModelName(ns, name, tag), err)
	}
	model := ollamaModelName(ns, name, tag)
	got, listed, err := d.api.TagDigest(ctx, model)
	if err == nil && listed && got == m.SHA256 {
		w.commit()
		return nil
	}
	why := fmt.Sprintf("it lists %s with digest %s, not the staged %s", model, short(got), m.SHA256[:12])
	switch {
	case err != nil:
		why = "asking it failed: " + err.Error()
	case !listed:
		why = "it does not list " + model
	}
	if uerr := w.undo(); uerr != nil {
		return fmt.Errorf("the manifest was written but the ollama the blobs went to does not read it (%s); taking it back out ALSO failed: %v", why, uerr)
	}
	return fmt.Errorf("the manifest was written but the ollama the blobs went to does not read it (%s) — the agent's ollama URL and its model store are different ollamas; the manifest was taken back out", why)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "(none)"
	}
	return s
}

// pushOne fetches one blob from the store and streams it to the daemon.
func pushOne(ctx context.Context, d mirrorDeps, b mirrorBlob) error {
	path, err := d.fetchBlob(ctx, b)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(path) }()
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening the fetched blob %s: %w", b.short(), err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("reading the fetched blob %s: %w", b.short(), err)
	}
	if st.Size() != b.Size {
		return fmt.Errorf("the store's blob %s is %d bytes, the staged manifest says %d — restage the tag", b.short(), st.Size(), b.Size)
	}
	pctx, cancel := context.WithTimeout(ctx, pushBudget(b.Size))
	defer cancel()
	body := &hashingReader{r: f, h: sha256.New(), want: b.Hex, limit: b.Size}
	if err := d.api.PushBlob(pctx, b.Hex, b.Size, body); err != nil {
		if body.err != nil {
			return body.err
		}
		return fmt.Errorf("pushing blob %s to ollama: %w", b.short(), err)
	}
	if body.err != nil {
		return body.err
	}
	if !body.done {
		return fmt.Errorf("ollama accepted blob %s before reading all of it", b.short())
	}
	return nil
}

// pushBudget bounds one push: a floor for small blobs, then 10 MiB/s, which
// a loopback (or a door on the same host) beats by a wide margin. A push
// slower than that is stalled, and fails like a stalled fetch.
func pushBudget(size int64) time.Duration {
	return 2*time.Minute + time.Duration(size/(10<<20))*time.Second
}

// hashingReader streams a blob while hashing it, and WITHHOLDS the final
// chunk until the digest is checked: the read that would complete the body
// is the one that compares, and on a mismatch it returns an error instead of
// those bytes. The daemon therefore never receives a complete upload of the
// wrong bytes; the HTTP client aborts a body that is short of its declared
// length. A source shorter than the manifest's size fails the same way.
type hashingReader struct {
	r     io.Reader
	h     hash.Hash
	want  string
	limit int64
	n     int64
	done  bool
	err   error
}

func (hr *hashingReader) Read(p []byte) (int, error) {
	if hr.err != nil {
		return 0, hr.err
	}
	if hr.n == hr.limit {
		// Everything was handed over, checked. The source must be at its end.
		var one [1]byte
		if k, _ := hr.r.Read(one[:]); k > 0 {
			hr.err = fmt.Errorf("blob %s is longer than the staged manifest's %d bytes", hr.want[:12], hr.limit)
			return 0, hr.err
		}
		return 0, io.EOF
	}
	if rem := hr.limit - hr.n; int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := hr.r.Read(p)
	hr.h.Write(p[:n])
	hr.n += int64(n)
	if hr.n == hr.limit {
		if got := hex.EncodeToString(hr.h.Sum(nil)); got != hr.want {
			hr.err = fmt.Errorf("blob %s hashed to %s while it was pushed — the upload was aborted before its last bytes; restage the tag", hr.want[:12], got[:12])
			return 0, hr.err
		}
		hr.done = true
		return n, nil
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			hr.err = fmt.Errorf("blob %s ended after %d of %d bytes — the upload was aborted", hr.want[:12], hr.n, hr.limit)
		} else {
			hr.err = fmt.Errorf("reading blob %s: %w", hr.want[:12], err)
		}
		return 0, hr.err
	}
	return n, nil
}

// ollamaHTTP is ollamaBlobAPI over the URL the agent already dials ollama
// at (loopback, or the noo-ollama door with the node leaf). Never an address
// taken from a manifest or a model name.
type ollamaHTTP struct {
	base      string
	transport http.RoundTripper
}

func (o *ollamaHTTP) do(ctx context.Context, method, path string, body io.Reader, size int64, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(o.base, "/")+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	cl := &http.Client{Transport: o.transport, Timeout: timeout}
	return cl.Do(req)
}

func (o *ollamaHTTP) HasBlob(ctx context.Context, h string) (bool, error) {
	resp, err := o.do(ctx, http.MethodHead, "/api/blobs/sha256:"+h, nil, 0, 30*time.Second)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("HEAD /api/blobs answered HTTP %d", resp.StatusCode)
}

func (o *ollamaHTTP) PushBlob(ctx context.Context, h string, size int64, body io.Reader) error {
	// The context carries the budget (pushBudget); no client timeout on top.
	resp, err := o.do(ctx, http.MethodPost, "/api/blobs/sha256:"+h, body, size, 0)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("ollama answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

func (o *ollamaHTTP) TagDigest(ctx context.Context, model string) (string, bool, error) {
	resp, err := o.do(ctx, http.MethodGet, "/api/tags", nil, 0, 30*time.Second)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("/api/tags answered HTTP %d", resp.StatusCode)
	}
	var tags struct {
		Models []struct {
			Name   string `json:"name"`
			Model  string `json:"model"`
			Digest string `json:"digest"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&tags); err != nil {
		return "", false, fmt.Errorf("/api/tags is not JSON: %w", err)
	}
	for _, m := range tags.Models {
		if strings.EqualFold(m.Name, model) || strings.EqualFold(m.Model, model) {
			return strings.ToLower(m.Digest), true, nil
		}
	}
	return "", false, nil
}
