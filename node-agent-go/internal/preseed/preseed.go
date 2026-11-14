// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// Package preseed copies model files from the controller's model-weight
// store into a local directory, every file verified against a sha256 the
// controller's authenticated artifact manifest states. Pure Go — no
// wget/curl/rsync — and in-process: the agent writes the node's HF cache and
// models dir on the host path.
//
// Design: storage, not proxy. The controller serves weights it already
// downloaded (no HuggingFace proxying, no CDN). A placed node copies the
// model here, then runs the backend with HF_HUB_OFFLINE=1.
//
// There is no unverified path. A file is kept or landed only when its bytes
// hash to the digest the manifest states (or this node's verified-digest
// record says it already did, for exactly this inode, size, mtime and ctime;
// see verified_record.go). Size alone never accepts a file: the old
// size-shortcut fetchFile kept any local file whose length matched, which a
// model container with the HF cache mounted read-write could satisfy with
// different bytes (i675 F13).
package preseed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"sync/atomic"
	"time"

	nodeconfig "github.com/noomesh/noomesh/node-agent-go/internal/config"
	"github.com/noomesh/noomesh/node-agent-go/internal/logship"
	"github.com/noomesh/noomesh/node-agent-go/internal/refusals"
)

// Client mirrors a remote tree over HTTP(S).
type Client struct {
	HTTP *http.Client
	// Record, when set, is this node's verified-digest record: a file it
	// names with the same identity is not re-hashed (see verified_record.go).
	// nil = hash every present file (always correct, slower).
	Record *VerifiedRecord
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

// Placed: this node takes weights and images from the controller's store.
// Read from the raw variable, not CacheURL(): a REFUSED (plaintext or
// certificate-less) value is a mis-provisioned placed node, which must refuse
// rather than fall back to the WAN.
func Placed() bool { return strings.TrimSpace(rawCacheURL()) != "" }

// rawCacheURL is the ONE read of NOO_MODEL_CACHE_URL.
func rawCacheURL() string { return os.Getenv("NOO_MODEL_CACHE_URL") }

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
	raw := rawCacheURL()
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

// FetchOneVerified copies one file at fileURL to dest (creating parent dirs)
// under an integrity contract: expectedSHA256 is the lowercase-hex digest the controller's
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
//   - An ALREADY-PRESENT destination is re-hashed rather than size-trusted:
//     "same length, different bytes" is exactly the case the digest is for.
//     A matching existing file is a no-op; a mismatching one is
//     re-downloaded. With c.Record set, a file the record names with an
//     identical (dev, inode, size, mtime, ctime) skips the re-hash.
func (c *Client) FetchOneVerified(ctx context.Context, fileURL, dest, expectedSHA256 string) (bool, error) {
	return c.FetchOneVerifiedProgress(ctx, fileURL, dest, expectedSHA256, nil)
}

// ProgressStep is how many bytes pass between two progress calls: the
// callback is a status read, not a per-write hook.
const ProgressStep = 1 << 20

// FetchOneVerifiedProgress is FetchOneVerified that also reports how many
// bytes of THIS file are on disk so far (a resumed prefix included), through
// progress (nil = none). It is called at most once per ProgressStep bytes,
// plus once when the last byte is written, always from the fetching
// goroutine. A file that is already present and verified writes nothing and
// reports nothing.
func (c *Client) FetchOneVerifiedProgress(ctx context.Context, fileURL, dest, expectedSHA256 string, progress func(written int64)) (bool, error) {
	return c.fetchVerified(ctx, fileURL, dest, expectedSHA256, progress, nil)
}

// validSHA256 is a 64-char lowercase-hex digest, normalised. An empty or
// malformed digest is an error, never "no check".
func validSHA256(s string) (string, error) {
	want := strings.ToLower(strings.TrimSpace(s))
	if len(want) != 64 {
		return "", fmt.Errorf("expected sha256 must be 64 hex chars, got %q", s)
	}
	if _, err := hex.DecodeString(want); err != nil {
		return "", fmt.Errorf("expected sha256 must be 64 hex chars, got %q", s)
	}
	return want, nil
}

// fetchVerified is FetchOneVerifiedProgress with a second callback, onHash,
// that reports bytes of an ALREADY-PRESENT dest as they are re-hashed (the
// HF preseed's "verifying … n/total GB" line). progress keeps its meaning:
// bytes of the file written so far.
func (c *Client) fetchVerified(ctx context.Context, fileURL, dest, expectedSHA256 string, progress, onHash func(int64)) (bool, error) {
	want, err := validSHA256(expectedSHA256)
	if err != nil {
		return false, err
	}
	if ok, _ := c.verifyPresent(dest, want, onHash); ok {
		return false, nil // verified present — nothing to do
	}
	// Absent, unreadable or mismatching: fetch and land over it.

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
	// Lstat, not Stat: in a cache a model container can write, a .partial
	// that is a link would aim this process's writes at its target.
	if fi, err := os.Lstat(tmp); err == nil && !fi.Mode().IsRegular() {
		if err := os.Remove(tmp); err != nil {
			return false, fmt.Errorf("remove non-file %s: %w", tmp, err)
		}
	}
	if fi, err := os.Lstat(tmp); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
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
	var start int64 // bytes of the file already on disk when the body starts
	switch {
	case resp.StatusCode == http.StatusPartialContent && have > 0:
		start, ok := contentRangeStart(resp.Header.Get("Content-Range"))
		if !ok || start != have {
			os.Remove(tmp)
			return false, fmt.Errorf("fetch %s: 206 with Content-Range %q does not continue at byte %d; partial discarded", fileURL, resp.Header.Get("Content-Range"), have)
		}
		slog.Info("resuming verified fetch", "file", filepath.Base(dest), "from_mb", have>>20)
		flags = os.O_WRONLY | os.O_APPEND
		start = have
	case resp.StatusCode == http.StatusOK:
		if have > 0 {
			slog.Info("server ignored the Range request; restarting the download", "file", filepath.Base(dest))
		}
		hasher.Reset()
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && have > 0:
		// The partial is at least as long as the file: it cannot be a prefix of it.
		os.Remove(tmp)
		slog.Info("partial is longer than the file; restarting the download", "file", filepath.Base(dest))
		return c.FetchOneVerifiedProgress(ctx, fileURL, dest, want, progress)
	default:
		return false, fmt.Errorf("fetch %s: HTTP %d", fileURL, resp.StatusCode) // partial kept
	}

	f, err := os.OpenFile(tmp, flags, 0o644)
	if err != nil {
		return false, err
	}
	var sink io.Writer = f
	var pw *progressWriter
	if progress != nil {
		pw = &progressWriter{w: f, n: start, last: start, fn: progress}
		sink = pw
	}
	if _, err := io.Copy(sink, io.TeeReader(resp.Body, hasher)); err != nil {
		f.Close()
		return false, err // transport failure: keep the partial for the next try
	}
	if pw != nil && pw.n != pw.last {
		progress(pw.n) // the tail below one step
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
	// Recorded AFTER the rename: the identity is the landed file's, and the
	// rename itself moves its ctime on most filesystems.
	c.Record.Remember(dest, want)
	return true, nil
}

// verifyPresent: dest exists as a regular file and its bytes are want —
// by the record (same identity as when this node last hashed it) or by
// hashing it now. A mismatch forgets the record entry and returns false; the
// caller decides whether that means "re-fetch" or "refuse".
func (c *Client) verifyPresent(dest, want string, onHash func(int64)) (bool, error) {
	fi, err := os.Stat(dest)
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", dest)
	}
	if c.Record.Verified(dest, want) {
		return true, nil
	}
	got, err := hashFile(dest, onHash)
	if err != nil {
		c.Record.Forget(dest)
		return false, err
	}
	if got != want {
		c.Record.Forget(dest)
		return false, fmt.Errorf("%w: %s holds %s, the manifest says %s", ErrDigestMismatch, dest, got, want)
	}
	c.Record.Remember(dest, want)
	return true, nil
}

// progressWriter counts what reaches the file and calls fn at most once per
// ProgressStep bytes; the caller adds the final call at the end of the body.
type progressWriter struct {
	w       io.Writer
	n, last int64
	fn      func(int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.n += int64(n)
	if p.n-p.last >= ProgressStep {
		p.last = p.n
		p.fn(p.n)
	}
	return n, err
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

// hashCalls counts hashFile calls: the tests' view of "re-hashed or not".
var hashCalls atomic.Int64

// hashFile is the sha256 of a file already on disk, computed at LOWERED
// priority (hashNiced: nice_linux.go) so a first-after-upgrade verification
// of a multi-GB snapshot does not compete with the backends this node
// serves. onHash (nil = none) is told the bytes hashed so far, at most once
// per ProgressStep plus once at the end.
func hashFile(path string, onHash func(int64)) (string, error) {
	hashCalls.Add(1)
	return hashNiced(func() (string, error) {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		h := sha256.New()
		var sink io.Writer = h
		var pw *progressWriter
		if onHash != nil {
			pw = &progressWriter{w: h, fn: onHash}
			sink = pw
		}
		if _, err := io.Copy(sink, f); err != nil {
			return "", err
		}
		if pw != nil && pw.n != pw.last {
			onHash(pw.n)
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	})
}

// RepoCacheDir maps a HuggingFace repo id ("org/name") to its cache directory
// name ("models--org--name"), matching huggingface_hub's on-disk layout.
func RepoCacheDir(repo string) string {
	return "models--" + strings.ReplaceAll(strings.Trim(repo, "/"), "/", "--")
}
