// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package preseed

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The verified-digest record: "this node hashed the file at <path> and it was
// sha256 X, when the file was (dev, inode, size, mtime, ctime)". It exists so
// an agent restart does not re-hash ~6.5 GB of weights per backend start; it
// must never be the weak link of the verification it shortcuts.
//
// WHO CAN WRITE WHAT:
//
//   - The HF cache (HF_CACHE_DIR) is writable by the agent's user AND by
//     every model container that mounts it read-write (vllm, TEI, the
//     reranker). So anything that can rewrite a weight is assumed hostile.
//   - The record lives in the agent's own state dir (NOO_AGENT_STATE,
//     default /var/lib/noo-node-agent → verified/hf-weights.json), which is
//     mounted into no container. OpenVerifiedRecord REFUSES a path under any
//     directory the caller names as mounted into model containers (the HF
//     cache, the models dir, the Ollama store); a refused record is simply
//     never used (every file is hashed). The directory is created 0700 and
//     the file written 0600, and either is READ only when owned by this
//     process's uid and not group/other-writable. So only the agent's uid
//     (and root) can write the record.
//
// A HIT needs the digest the manifest asks for AND an identical (dev, inode,
// size, mtime, ctime). A writer can set mtime back (utimes) but not ctime,
// which the kernel moves on every write, chmod, rename or utimes; and an
// in-place rewrite or a replacement file changes ctime or the inode. Any
// difference is a MISS: the file is re-hashed, and a mismatch is refused or
// re-fetched by the caller and forgotten here.

// fileID is what a hit must match. Filled by statID (fileid_*.go).
type fileID struct {
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtime_ns"`
	CtimeNs int64  `json:"ctime_ns"`
}

type recordEntry struct {
	SHA256 string `json:"sha256"`
	fileID
}

type recordFile struct {
	Version int                    `json:"version"`
	Files   map[string]recordEntry `json:"files"`
	// Repos is the last `hf` manifest this node verified a snapshot against,
	// per repo dir: what a restart checks the local copy against while the
	// controller cannot be reached.
	Repos map[string]HFManifest `json:"repos,omitempty"`
}

// VerifiedRecord is one record file. Methods are nil-safe: a nil record
// verifies nothing and remembers nothing.
type VerifiedRecord struct {
	path     string
	disabled string // non-empty: why this record is never read or written

	mu     sync.Mutex
	loaded bool
	data   recordFile
}

var (
	recordsMu sync.Mutex
	records   = map[string]*VerifiedRecord{}
)

// OpenVerifiedRecord returns the record at path (one instance per path in
// this process). mounted are the host directories bind-mounted into model
// containers; a record under any of them is disabled, loudly.
func OpenVerifiedRecord(path string, mounted ...string) *VerifiedRecord {
	clean := filepath.Clean(path)
	recordsMu.Lock()
	defer recordsMu.Unlock()
	if r, ok := records[clean]; ok {
		return r
	}
	r := &VerifiedRecord{path: clean}
	if !filepath.IsAbs(clean) {
		r.disabled = "the record path is not absolute"
	}
	for _, m := range mounted {
		if strings.TrimSpace(m) != "" && pathWithin(clean, m) {
			r.disabled = fmt.Sprintf("it is under %s, which is mounted into model containers that could rewrite it", m)
		}
	}
	if r.disabled != "" {
		slog.Error("verified-digest record not used: every weight is re-hashed at each start",
			"path", clean, "reason", r.disabled,
			"fix", "set NOO_AGENT_STATE to a directory only the agent can write, outside HF_CACHE_DIR, MODELS_DIR and OLLAMA_DATA_DIR")
	}
	records[clean] = r
	return r
}

// Path is where the record lives.
func (r *VerifiedRecord) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Disabled is why the record is not used ("" = it is).
func (r *VerifiedRecord) Disabled() string {
	if r == nil {
		return "no record"
	}
	return r.disabled
}

// pathWithin: p is root or under it, comparing symlink-resolved forms where
// the paths exist (a state dir reached through a link into the cache counts).
func pathWithin(p, root string) bool {
	rp, rr := resolveExisting(p), resolveExisting(root)
	rel, err := filepath.Rel(rr, rp)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolveExisting resolves the longest existing prefix of p through symlinks.
func resolveExisting(p string) string {
	p = filepath.Clean(p)
	var tail []string
	for cur := p; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(append([]string{r}, tail...)...)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
}

// Verified: the record says this node hashed dest to want, and dest is still
// the very same file (dev, inode, size, mtime, ctime all equal).
func (r *VerifiedRecord) Verified(dest, want string) bool {
	if r == nil || r.disabled != "" {
		return false
	}
	id, ok := statID(dest)
	if !ok {
		return false
	}
	key := recordKey(dest)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	e, ok := r.data.Files[key]
	return ok && e.SHA256 == want && e.fileID == id
}

// Remember records that dest, as it is NOW, hashed to sha. Called only right
// after this process hashed (or landed) those bytes.
func (r *VerifiedRecord) Remember(dest, sha string) {
	if r == nil || r.disabled != "" {
		return
	}
	id, ok := statID(dest)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	r.data.Files[recordKey(dest)] = recordEntry{SHA256: sha, fileID: id}
	r.saveLocked()
}

// Forget drops dest's entry (it failed verification or could not be read).
func (r *VerifiedRecord) Forget(dest string) {
	if r == nil || r.disabled != "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	key := recordKey(dest)
	if _, ok := r.data.Files[key]; ok {
		delete(r.data.Files, key)
		r.saveLocked()
	}
}

// RepoManifest is the last manifest a snapshot of repo was verified against.
func (r *VerifiedRecord) RepoManifest(repo string) (*HFManifest, bool) {
	if r == nil || r.disabled != "" {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	m, ok := r.data.Repos[repo]
	if !ok {
		return nil, false
	}
	cp := HFManifest{Rev: m.Rev, Files: append([]HFFile(nil), m.Files...)}
	return &cp, true
}

// SetRepoManifest remembers the manifest repo was just verified against.
func (r *VerifiedRecord) SetRepoManifest(repo string, m *HFManifest) {
	if r == nil || r.disabled != "" || m == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	r.data.Repos[repo] = HFManifest{Rev: m.Rev, Files: append([]HFFile(nil), m.Files...)}
	r.saveLocked()
}

func recordKey(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return filepath.Clean(p)
}

// loadLocked reads the file once, and only a file this agent alone can have
// written; anything else starts empty (and is replaced on the next save,
// since the rename lands in a directory that passed the same check).
func (r *VerifiedRecord) loadLocked() {
	if r.loaded {
		return
	}
	r.loaded = true
	r.data = recordFile{Version: 1, Files: map[string]recordEntry{}, Repos: map[string]HFManifest{}}
	if err := ownedNotShared(filepath.Dir(r.path), true); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("verified-digest record ignored: its directory is not one only this agent can write",
				"path", r.path, "reason", err.Error(), "effect", "weights are re-hashed")
		}
		return
	}
	if err := ownedNotShared(r.path, false); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("verified-digest record ignored: the file is not one only this agent can have written",
				"path", r.path, "reason", err.Error(), "effect", "weights are re-hashed")
		}
		return
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	var f recordFile
	if json.Unmarshal(b, &f) != nil || f.Version != 1 {
		return
	}
	if f.Files != nil {
		r.data.Files = f.Files
	}
	if f.Repos != nil {
		r.data.Repos = f.Repos
	}
}

// saveLocked writes the record (tmp 0600 + rename) into a 0700 directory
// that passes the ownership check. Entries for files that no longer exist
// are dropped. A failed save costs a re-hash after a restart, never a wrong
// answer, so it is logged and not returned.
func (r *VerifiedRecord) saveLocked() {
	for k := range r.data.Files {
		if _, err := os.Lstat(k); err != nil {
			delete(r.data.Files, k)
		}
	}
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Warn("verified-digest record not saved", "path", r.path, "error", err)
		return
	}
	if err := ownedNotShared(dir, true); err != nil {
		slog.Warn("verified-digest record not saved: its directory is not one only this agent can write",
			"path", r.path, "reason", err.Error())
		return
	}
	b, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".hf-weights-*.tmp") // 0600
	if err != nil {
		slog.Warn("verified-digest record not saved", "path", r.path, "error", err)
		return
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		slog.Warn("verified-digest record not saved", "path", r.path, "error", errors.Join(werr, cerr))
		return
	}
	if err := os.Rename(tmp.Name(), r.path); err != nil {
		_ = os.Remove(tmp.Name())
		slog.Warn("verified-digest record not saved", "path", r.path, "error", err)
	}
}

// ownedNotShared: p (a directory when dir, else a regular file — never a
// link) is owned by this process's uid and writable by nobody else.
func ownedNotShared(p string, dir bool) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	switch {
	case dir && !fi.IsDir():
		return fmt.Errorf("not a directory (%s)", fi.Mode().Type())
	case !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("not a regular file (%s)", fi.Mode().Type())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("group- or world-writable (%o)", fi.Mode().Perm())
	}
	if uid, ok := ownerUID(fi); ok && uid != os.Getuid() {
		return fmt.Errorf("owned by uid %d, not this agent's %d", uid, os.Getuid())
	}
	return nil
}
