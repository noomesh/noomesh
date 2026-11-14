// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package preseed

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// HF snapshots, verified file by file (i675 F13).
//
// The HF preseed used to walk the controller's nginx JSON listing and keep
// any local file whose length matched the served one (fetchFile's size
// shortcut), copying a miss with no hash at all. The node's HF cache is
// mounted READ-WRITE into vllm, TEI and the reranker, so a model container
// could rewrite a weight at the same size and every later start would load
// it. Now the controller's gateway states each file of the snapshot with the
// sha256 of its resolved blob (GET /api/artifacts/manifest/hf/<models--org--
// name>, cross-checked there against the blob's HF oid), and nothing lands
// or is kept unless its bytes hash to that.

// HFFile is one file of an HF snapshot as the controller's `hf` manifest
// states it: the path inside snapshots/<rev>/, its size, and the sha256 of
// its bytes.
type HFFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// HFManifest is the gateway's `hf` manifest: the commit refs/main names and
// every file of that one snapshot.
type HFManifest struct {
	Rev   string   `json:"rev"`
	Files []HFFile `json:"files"`
}

// ErrNoManifest: no verified list of the snapshot's files. NO MANIFEST, NO
// PRESEED — the same rule preseedGGUF follows.
var ErrNoManifest = errors.New("no verified manifest for this HF snapshot")

// Validate checks the manifest's shape and normalises each digest. A file
// without a well-formed sha256 makes the WHOLE manifest invalid: a snapshot
// that is verified except for one file is not verified.
func (m *HFManifest) Validate() error {
	if m == nil {
		return ErrNoManifest
	}
	if !isLowerHex(m.Rev, 40) {
		return fmt.Errorf("hf manifest: rev %q is not a 40-hex commit id", m.Rev)
	}
	if len(m.Files) == 0 {
		return fmt.Errorf("hf manifest: rev %s lists no files", m.Rev)
	}
	seen := make(map[string]bool, len(m.Files))
	for i := range m.Files {
		f := &m.Files[i]
		if err := safeRelPath(f.Path); err != nil {
			return fmt.Errorf("hf manifest: %w", err)
		}
		if seen[f.Path] {
			return fmt.Errorf("hf manifest: %s is listed twice", f.Path)
		}
		seen[f.Path] = true
		sha, err := validSHA256(f.SHA256)
		if err != nil {
			return fmt.Errorf("hf manifest: %s has no usable digest: %w", f.Path, err)
		}
		f.SHA256 = sha
		if f.Bytes < 0 {
			return fmt.Errorf("hf manifest: %s has a negative size", f.Path)
		}
	}
	return nil
}

// TotalBytes is the snapshot's size, for the progress line.
func (m *HFManifest) TotalBytes() int64 {
	var n int64
	for _, f := range m.Files {
		n += f.Bytes
	}
	return n
}

// safeRelPath: a relative slash path with no empty, "." or ".." segment —
// it becomes a path under the node's HF cache.
func safeRelPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return fmt.Errorf("file path %q is not a relative path", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("file path %q has a %q segment", p, seg)
		}
	}
	return nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// HFProgress is told the verified bytes so far across the whole snapshot
// (hashed or downloaded) and the snapshot's total.
type HFProgress func(done, total int64)

// MirrorHFRepo makes destDir (the node's hub/models--org--name) hold the
// snapshot m names, every file verified: an existing file is kept only when
// it hashes to its manifest digest (or the verified-digest record vouches
// for exactly that inode), anything else is fetched from
// baseURL/snapshots/<rev>/<path> and lands only if the bytes match. Files in
// the snapshot directory that m does not list are removed, and refs/main is
// written LAST, so a half-mirrored snapshot is never the one HF resolves.
//
// baseURL is the repo's directory in the model cache (…/hf/models--org--
// name/). Returns the number of files downloaded. A nil or invalid manifest
// is ErrNoManifest-class and touches nothing; a digest mismatch is
// ErrDigestMismatch and leaves that file's destination as it was.
func (c *Client) MirrorHFRepo(ctx context.Context, baseURL, destDir string, m *HFManifest, progress HFProgress) (int, error) {
	if err := c.Err(); err != nil {
		return 0, err
	}
	if err := m.Validate(); err != nil {
		return 0, err
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	snapDest := filepath.Join(destDir, "snapshots", m.Rev)
	total := m.TotalBytes()
	var base int64
	written := 0
	for _, f := range m.Files {
		dest := filepath.Join(snapDest, filepath.FromSlash(f.Path))
		if err := realDirsUnder(destDir, filepath.Dir(dest)); err != nil {
			return written, err
		}
		src := baseURL + "snapshots/" + url.PathEscape(m.Rev) + "/" + escapeSlashPath(f.Path)
		done := base
		report := func(n int64) {
			if progress != nil {
				progress(done+min(n, f.Bytes), total)
			}
		}
		wrote, err := c.fetchVerified(ctx, src, dest, f.SHA256, report, report)
		if err != nil {
			return written, fmt.Errorf("%s: %w", f.Path, err)
		}
		if wrote {
			written++
		}
		base += f.Bytes
		if progress != nil {
			progress(base, total)
		}
	}
	if err := removeStrays(snapDest, m); err != nil {
		return written, err
	}
	if err := writeRefsMain(destDir, m.Rev); err != nil {
		return written, err
	}
	return written, nil
}

// VerifyHFRepoLocal checks, with no network, that destDir holds the snapshot
// m names: refs/main points at m.Rev and every listed file hashes to its
// digest (or the record vouches for that exact inode). A file that changed
// since the record was written is re-hashed, and a mismatch is an error
// wrapping ErrDigestMismatch — the caller refuses to start on it. Unlisted
// files in the snapshot directory are removed.
func (c *Client) VerifyHFRepoLocal(destDir string, m *HFManifest, progress HFProgress) error {
	if err := m.Validate(); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(destDir, "refs", "main"))
	if err != nil {
		return fmt.Errorf("no local refs/main: %w", err)
	}
	if got := strings.TrimSpace(string(b)); got != m.Rev {
		return fmt.Errorf("local refs/main points at %q, the verified snapshot is %s", got, m.Rev)
	}
	snapDest := filepath.Join(destDir, "snapshots", m.Rev)
	total := m.TotalBytes()
	var base int64
	for _, f := range m.Files {
		done := base
		report := func(n int64) {
			if progress != nil {
				progress(done+min(n, f.Bytes), total)
			}
		}
		ok, err := c.verifyPresent(filepath.Join(snapDest, filepath.FromSlash(f.Path)), f.SHA256, report)
		if !ok {
			if err == nil {
				err = errors.New("not verified")
			}
			return fmt.Errorf("%s: %w", f.Path, err)
		}
		base += f.Bytes
		if progress != nil {
			progress(base, total)
		}
	}
	return removeStrays(snapDest, m)
}

// realDirsUnder makes every directory from root down to dir a real
// directory: a symlink (or a file) in the way is removed and replaced. The
// HF cache is writable by the model containers that mount it, and a planted
// link would otherwise point this process's writes somewhere else.
func realDirsUnder(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is not under %s", dir, root)
	}
	cur := root
	segs := []string{}
	if rel != "." {
		segs = strings.Split(rel, string(filepath.Separator))
	}
	for i := -1; i < len(segs); i++ {
		if i >= 0 {
			cur = filepath.Join(cur, segs[i])
		}
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			mk := os.Mkdir
			if i < 0 {
				mk = os.MkdirAll // the repo dir; hub/ may not exist yet
			}
			if err := mk(cur, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			continue
		case err != nil:
			return err
		case fi.IsDir():
			continue
		}
		if i < 0 {
			// The repo dir itself is a link or a file: not ours to fix silently.
			return fmt.Errorf("%s is not a directory (%s)", cur, fi.Mode().Type())
		}
		if err := os.Remove(cur); err != nil {
			return fmt.Errorf("replace %s (%s) with a directory: %w", cur, fi.Mode().Type(), err)
		}
		if err := os.Mkdir(cur, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// removeStrays deletes every non-directory under snapDest that m does not
// list (a leftover .partial included). A file planted next to the verified
// ones is not part of the verified snapshot, and HF would load it.
func removeStrays(snapDest string, m *HFManifest) error {
	want := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		want[filepath.Join(snapDest, filepath.FromSlash(f.Path))] = true
	}
	return filepath.WalkDir(snapDest, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || want[p] {
			return nil
		}
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("remove unlisted %s: %w", p, err)
		}
		return nil
	})
}

// writeRefsMain points refs/main at rev (tmp + rename).
func writeRefsMain(destDir, rev string) error {
	if err := realDirsUnder(destDir, filepath.Join(destDir, "refs")); err != nil {
		return err
	}
	p := filepath.Join(destDir, "refs", "main")
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, []byte(rev), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// escapeSlashPath escapes each segment of a slash path for a URL.
func escapeSlashPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
