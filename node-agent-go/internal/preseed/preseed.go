// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package preseed mirrors a model's files from the controller's model-weight
// store into a local directory, using nginx's JSON directory listing
// (autoindex_format json). Pure Go — no wget/curl/rsync — so it runs inside
// the node-agent's own image via the runHelper pattern, with the node's HF
// cache bind-mounted as the destination.
//
// Design: storage, not proxy. The controller serves weights it already
// downloaded (no HuggingFace proxying, no CDN). A placed node copies the
// model here, then runs the backend with HF_HUB_OFFLINE=1.
package preseed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/logship"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// entry is one item in nginx's JSON autoindex listing.
type entry struct {
	Name string `json:"name"`
	Type string `json:"type"` // "file" | "directory"
}

// Client mirrors a remote tree over HTTP(S).
type Client struct {
	HTTP *http.Client
	// err is a construction failure. Every method returns it, so a node
	// whose PKI is configured but unreadable never dials the store with a
	// bare client — the failure mode this field exists to rule out.
	err error
}

// New builds the model-cache client from the node's own PKI
// C-i: the cluster CA pinned as the only root, and the node leaf presented
// as the client certificate — exactly the transport the artifact-manifest
// call already uses. Built per call, so a rotated leaf is picked up by the
// next fetch without a restart.
//
// A configured-but-unreadable NOO_TLS_CA/CERT/KEY is an ERROR carried in
// the client, not a fallback to the default transport: the old bare
// `&http.Client{}` is what kept the store on plaintext for a year, and a
// silent return to it would put a node on plaintext while looking healthy.
// There is no plaintext fallback anywhere in this package; a TLS failure is
// a preseed miss whose error names the cause.
func New() *Client {
	tr, err := nodeconfig.Load().HTTPTransport()
	if err != nil {
		return &Client{err: fmt.Errorf("model-cache client: %w", err)}
	}
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Minute, Transport: tr}}
}

// Err reports the construction failure, if any. Callers that want to refuse
// before building a request (rather than on the first Do) read it here.
func (c *Client) Err() error {
	if c == nil {
		return errors.New("model-cache client is nil")
	}
	return c.err
}

// do is the one place a request leaves this package. It is where the
// construction error surfaces, so no method can accidentally reach the
// network on a client that failed to build.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	if err := c.Err(); err != nil {
		return nil, err
	}
	if c.HTTP == nil {
		return nil, errors.New("model-cache client has no HTTP client")
	}
	return c.HTTP.Do(req)
}

// tlsPort is where the mTLS listener answers — a literal of the nginx conf
// (docker/model-cache.nginx.conf), and the only port there since phase 2 of
// -i deleted the plaintext 8083 listener.
const tlsPort = "8443"

// RefusalScope is the refusals-channel scope under which a rejected
// NOO_MODEL_CACHE_URL is reported to the controller (heartbeat →
// `reconcile_refusals` → the `noo cluster verify` "model cache" row names
// this node). The refusal's target is the value that was refused.
const RefusalScope = "model_cache_url"

var (
	refuseMu     sync.Mutex
	refusedValue string // the target currently recorded under RefusalScope, "" for none
)

// CacheURL is the ONE reader of NOO_MODEL_CACHE_URL (a source-grep test
// pins that). It returns the store's base URL without a trailing slash, or
// "" when the feature is off — OR when the configured value is refused.
//
// Phase 2 C-i: the store answers mTLS on 8443 and nothing
// else, so there are exactly two ways to use it — an https:// URL and a
// client certificate — and a node missing either cannot preseed. Phase 1
// rewrote a legacy `http://H:8083` to the TLS listener and only warned;
// that rewrite is gone, because a value that is silently corrected is a
// value nobody re-provisions, and the next config that carries it (a
// restored backup, a hand-copied env) would carry it forever. Now an
// http:// value is a REFUSAL: logged at error level, recorded on the
// refusals channel so the controller sees it, and treated as "no store"
// by every caller. There is no plaintext fallback in either direction.
//
// A refusal is returned as "" rather than an error because every caller
// already reads "" as "no data plane to pull from" and refuses its own
// work; the loud half is the log line and the refusals record.
func CacheURL() string {
	raw := os.Getenv("NOO_MODEL_CACHE_URL")
	cfg := nodeconfig.Load()
	u, err := resolveCacheURL(raw, cfg.TLSCert != "" && cfg.TLSKey != "")
	refuseMu.Lock()
	defer refuseMu.Unlock()
	if err != nil {
		target := strings.TrimSpace(raw)
		if refusedValue != "" && refusedValue != target {
			refusals.Clear(RefusalScope, refusedValue)
		}
		if refusedValue != target {
			slog.Error("model cache refused: NOO_MODEL_CACHE_URL is unusable", "url", logship.ScrubURLUserinfo(target), "reason", err.Error())
		}
		refusals.Record(RefusalScope, target, err.Error())
		refusedValue = target
		return ""
	}
	if refusedValue != "" {
		refusals.Clear(RefusalScope, refusedValue)
		refusedValue = ""
	}
	return u
}

// resolveCacheURL is CacheURL without the environment or the refusals
// channel, for the table test. It returns the normalised https URL, or ""
// when the feature is off, or an error naming the variable and the fix.
func resolveCacheURL(raw string, hasClientCert bool) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("NOO_MODEL_CACHE_URL=%q is not a URL — set it to https://<controller>:%s (re-run `noo cluster provision <this-node>`)", raw, tlsPort)
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if host == "" {
			host = "<controller>"
		}
		return "", fmt.Errorf("NOO_MODEL_CACHE_URL=%q is plaintext; the model cache answers mTLS only (the 8083 listener was removed in phase 2 C-i) — set NOO_MODEL_CACHE_URL=%s in /etc/noo-node-agent.env (re-run `noo cluster provision <this-node>`, which renders it) and restart the agent",
			raw, "https://"+net.JoinHostPort(host, tlsPort))
	}
	if !hasClientCert {
		return "", fmt.Errorf("this node has no client certificate (NOO_TLS_CERT/NOO_TLS_KEY unset) and the model cache at %s admits only a node leaf — run `noo cluster provision <this-node>` to issue one", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// Mirror recursively copies the directory at srcURL into destDir. srcURL must
// point at a directory served with nginx `autoindex_format json`. Returns the
// number of files written. Existing same-size files are skipped (resumable).
func (c *Client) Mirror(ctx context.Context, srcURL, destDir string) (int, error) {
	if !strings.HasSuffix(srcURL, "/") {
		srcURL += "/"
	}
	entries, err := c.list(ctx, srcURL)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, e := range entries {
		if e.Name == "" || strings.Contains(e.Name, "/") || e.Name == ".." {
			continue // guard against listing oddities / traversal
		}
		childURL := srcURL + url.PathEscape(e.Name)
		childDest := filepath.Join(destDir, e.Name)
		switch e.Type {
		case "directory":
			n, err := c.Mirror(ctx, childURL+"/", childDest)
			if err != nil {
				return written, err
			}
			written += n
		default: // file
			ok, err := c.fetchFile(ctx, childURL, childDest)
			if err != nil {
				return written, err
			}
			if ok {
				written++
			}
		}
	}
	return written, nil
}

func (c *Client) list(ctx context.Context, dirURL string) ([]entry, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, dirURL, nil)
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list %s: HTTP %d", dirURL, resp.StatusCode)
	}
	var entries []entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("list %s: decode: %w", dirURL, err)
	}
	return entries, nil
}

// fetchFile downloads fileURL to dest. Skips (returns false) when dest already
// exists with the same size, so a re-run resumes rather than re-downloads.
func (c *Client) fetchFile(ctx context.Context, fileURL, dest string) (bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	resp, err := c.do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("fetch %s: HTTP %d", fileURL, resp.StatusCode)
	}
	if st, err := os.Stat(dest); err == nil && resp.ContentLength >= 0 && st.Size() == resp.ContentLength {
		return false, nil // already have it
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return false, err
	}
	tmp := dest + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return false, err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return false, err
	}
	f.Close()
	if err := os.Rename(tmp, dest); err != nil {
		return false, err
	}
	return true, nil
}

// MirrorHFRepo mirrors a HuggingFace-cache repo directory (models--org--name/)
// the way huggingface_hub actually loads it offline: it copies only refs/main
// and the single snapshots/<revision>/ that main points at — skipping blobs/
// (the served snapshot files already carry the real bytes), .no_exist/ (empty
// negative-cache markers), and any other revisions.
//
// This matters: over HTTP the controller's nginx serves each snapshot symlink
// as the resolved blob content, so a blind recursive Mirror would download the
// same weights once per revision AND again as blobs/ — measured at ~4x on a
// real 3-snapshot model. HF_HUB_OFFLINE=1 loads fine from real files in
// snapshots/<rev>/ with no blobs/ dir, so copying just that one tree is both
// correct and minimal.
//
// baseURL must point at the repo dir (…/hf/models--org--name/). Falls back to a
// full recursive Mirror if refs/main can't be read (unexpected layout), so an
// odd store still preseeds rather than failing shut.
func (c *Client) MirrorHFRepo(ctx context.Context, baseURL, destDir string) (int, error) {
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	rev, err := c.fetchText(ctx, baseURL+"refs/main")
	if err != nil {
		// Unknown layout — fall back to a full mirror rather than fail shut.
		return c.Mirror(ctx, baseURL, destDir)
	}
	rev = strings.TrimSpace(rev)
	if rev == "" || strings.ContainsAny(rev, "/\\") {
		return c.Mirror(ctx, baseURL, destDir)
	}
	// Persist refs/main — HF resolves the snapshot revision through it offline.
	if err := os.MkdirAll(filepath.Join(destDir, "refs"), 0o755); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(destDir, "refs", "main"), []byte(rev), 0o644); err != nil {
		return 0, err
	}
	snapURL := baseURL + "snapshots/" + url.PathEscape(rev) + "/"
	snapDest := filepath.Join(destDir, "snapshots", rev)
	return c.Mirror(ctx, snapURL, snapDest)
}

// fetchText GETs a small text resource (e.g. refs/main) and returns its body.
func (c *Client) fetchText(ctx context.Context, u string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get %s: HTTP %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// FetchOne copies a single file at fileURL to dest (creating parent dirs),
// skipping when dest already has the same size (resumable). Used for GGUF
// weights, which are one flat file served from the controller's /gguf/.
// Returns true if it wrote the file, false if it was already present.
func (c *Client) FetchOne(ctx context.Context, fileURL, dest string) (bool, error) {
	return c.fetchFile(ctx, fileURL, dest)
}

// FetchOneVerified is FetchOne with an integrity contract
// step 1: expectedSHA256 is the lowercase-hex digest the controller's
// artifact manifest stated, and the file only lands if the bytes hash to it.
//
// Three properties worth their code:
//
//   - The hash is computed WHILE streaming (TeeReader), not in a second pass
//     over a multi-GB file.
//   - A transport failure KEEPS the .partial; the next call hashes it and
//     resumes with a Range request. A mismatch removes the .partial and errors — the destination is never
//     replaced by unverified bytes, and a corrupt/tampered transfer cannot
//     be told apart from a miss by the caller (both fail the preseed).
//   - An ALREADY-PRESENT destination is re-hashed rather than size-trusted.
//     fetchFile's size shortcut is fine for opportunistic caching; once a
//     digest exists, "same length, different bytes" is exactly the case the
//     digest is for. A matching existing file is a no-op; a mismatching one
//     is re-downloaded.
func (c *Client) FetchOneVerified(ctx context.Context, fileURL, dest, expectedSHA256 string) (bool, error) {
	want := strings.ToLower(strings.TrimSpace(expectedSHA256))
	if len(want) != 64 {
		return false, fmt.Errorf("expected sha256 must be 64 hex chars, got %q", expectedSHA256)
	}
	if _, err := os.Stat(dest); err == nil {
		got, err := sha256File(dest)
		if err == nil && got == want {
			return false, nil // verified present — nothing to do
		}
		// Hash error or mismatch: fall through and re-download over it.
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return false, err
	}
	tmp := dest + ".partial"

	// Resume. A transport failure keeps dest.partial (nobody but this
	// function reads it), so the next call hashes the kept prefix and asks
	// for the rest with a Range header. The server being OLD or ignoring
	// ranges is fine: it answers 200 and we start over. The final digest
	// covers the WHOLE file, so a corrupt or stale prefix can never land.
	hasher := sha256.New()
	var have int64
	if fi, err := os.Stat(tmp); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		n, herr := hashInto(hasher, tmp)
		if herr != nil {
			os.Remove(tmp)
			hasher.Reset()
		} else {
			have = n
		}
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	resp, err := c.do(req)
	if err != nil {
		return false, err // partial kept
	}
	defer resp.Body.Close()

	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	switch {
	case resp.StatusCode == http.StatusPartialContent && have > 0:
		start, ok := contentRangeStart(resp.Header.Get("Content-Range"))
		if !ok || start != have {
			os.Remove(tmp)
			return false, fmt.Errorf("fetch %s: 206 with Content-Range %q does not continue at byte %d; partial discarded", fileURL, resp.Header.Get("Content-Range"), have)
		}
		slog.Info("resuming verified fetch", "file", filepath.Base(dest), "from_mb", have>>20)
		flags = os.O_WRONLY | os.O_APPEND
	case resp.StatusCode == http.StatusOK:
		if have > 0 {
			slog.Info("server ignored the Range request; restarting the download", "file", filepath.Base(dest))
		}
		hasher.Reset()
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && have > 0:
		// The partial is at least as long as the file: it cannot be a prefix of it.
		os.Remove(tmp)
		slog.Info("partial is longer than the file; restarting the download", "file", filepath.Base(dest))
		return c.FetchOneVerified(ctx, fileURL, dest, want)
	default:
		return false, fmt.Errorf("fetch %s: HTTP %d", fileURL, resp.StatusCode) // partial kept
	}

	f, err := os.OpenFile(tmp, flags, 0o644)
	if err != nil {
		return false, err
	}
	if _, err := io.Copy(f, io.TeeReader(resp.Body, hasher)); err != nil {
		f.Close()
		return false, err // transport failure: keep the partial for the next try
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	got := hex.EncodeToString(hasher.Sum(nil))
	if got != want {
		os.Remove(tmp) // a corrupt partial must never be resumed
		return false, fmt.Errorf("%w for %s: manifest says %s, bytes are %s", ErrDigestMismatch, fileURL, want, got)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return false, err
	}
	return true, nil
}

// hashInto streams path through h and returns its length.
func hashInto(h io.Writer, path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(h, f)
}

// contentRangeStart parses the first byte of "bytes <start>-<end>/<total>".
func contentRangeStart(v string) (int64, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(v), "bytes ")
	if !ok {
		return 0, false
	}
	first, _, ok := strings.Cut(rest, "-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	return n, err == nil && n >= 0
}

// ErrDigestMismatch: the bytes arrived but do not hash to the manifest's
// sha256. A VERIFICATION failure — callers must refuse, never fall back.
var ErrDigestMismatch = errors.New("digest mismatch")

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RepoCacheDir maps a HuggingFace repo id ("org/name") to its cache directory
// name ("models--org--name"), matching huggingface_hub's on-disk layout.
func RepoCacheDir(repo string) string {
	return "models--" + strings.ReplaceAll(strings.Trim(repo, "/"), "/", "--")
}
