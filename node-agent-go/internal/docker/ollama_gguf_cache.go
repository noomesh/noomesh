// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/noomesh/noomesh/node-agent-go/internal/preseed"
)

// A verified copy of an import's GGUF weight, kept across retries (i675 F9).
//
// Reconcile retries an import about every ten minutes while `ollama list`
// lacks the model. Each attempt stages into a fresh work dir that is removed
// afterwards, so an `ollama create` that kept failing re-downloaded the whole
// multi-GB weight every time. The weight now lands first in a cache keyed by
// the sha256 the controller's artifact manifest names (never by file name),
// and the work dir gets a hard link to it.
//
// The cache is an integrity boundary: what is in it is handed to ollama as
// the weight the controller published. An entry is reused only when the
// directory and the file are this agent's alone and the bytes, hashed again
// now, are the manifest's digest. Anything else is removed and fetched fresh.
//
// It cleans up after itself: a successful create removes the entry, and a
// failing one is bounded by age (ggufCacheTTL) and count (ggufCacheMaxEntries).

// ggufCacheTTL and ggufCacheMaxEntries bound what failed imports leave
// behind. Variables so tests can set them.
var (
	ggufCacheTTL        = 24 * time.Hour
	ggufCacheMaxEntries = 2
)

// ggufCacheMu serialises use of the cache: two imports of one weight must
// not write the same .partial, and a prune must not remove what another
// import is fetching.
var ggufCacheMu sync.Mutex

const (
	ggufCacheSuffix  = ".gguf"
	ggufPartialAffix = ".partial" // preseed's FetchOneVerified writes <dest>.partial
)

func ggufCacheDir() string { return filepath.Join(stagingDir(), "ollama-gguf-cache") }

// ownedByUsAndNotShared is railMemoryFileTrusted's ownership rule: owned by
// this process's uid and writable by nobody else.
func ownedByUsAndNotShared(fi os.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("group- or world-writable (%o)", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("owned by uid %d, not this agent's %d", st.Uid, os.Getuid())
	}
	return nil
}

// ggufCacheDirTrusted: a real directory (not a symlink), ours alone.
func ggufCacheDirTrusted(fi os.FileInfo) error {
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("not a directory (%s)", fi.Mode().Type())
	}
	return ownedByUsAndNotShared(fi)
}

// ggufCacheFileTrusted: a regular file (Lstat, so a symlink is not one),
// ours alone.
func ggufCacheFileTrusted(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file (%s)", fi.Mode().Type())
	}
	return ownedByUsAndNotShared(fi)
}

// prepareGGUFCache returns the cache directory, created 0700 when absent and
// started over when it is not one only this agent can write. ok=false means
// the cache cannot be used this attempt (the caller fetches straight into
// the work dir, as before the cache existed).
func prepareGGUFCache() (string, bool) {
	dir := ggufCacheDir()
	fi, err := os.Lstat(dir)
	switch {
	case err == nil:
		if terr := ggufCacheDirTrusted(fi); terr != nil {
			slog.Warn("ollama weight cache not trusted; starting it over",
				"dir", dir, "check", "dir", "reason", terr.Error())
			if rerr := os.RemoveAll(dir); rerr != nil {
				slog.Warn("ollama weight cache could not be removed; fetching without it",
					"dir", dir, "error", rerr.Error())
				return "", false
			}
		} else {
			return dir, true
		}
	case !errors.Is(err, os.ErrNotExist):
		slog.Warn("ollama weight cache unreadable; fetching without it", "dir", dir, "error", err.Error())
		return "", false
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		slog.Warn("ollama weight cache could not be created; fetching without it", "dir", dir, "error", err.Error())
		return "", false
	}
	// Re-check what is there now rather than trusting the Mkdir.
	if fi, err = os.Lstat(dir); err != nil || ggufCacheDirTrusted(fi) != nil {
		slog.Warn("ollama weight cache not trusted after creating it; fetching without it", "dir", dir)
		return "", false
	}
	return dir, true
}

// ggufCacheName reports whether name is a cache entry or its partial, and
// for which sha256.
func ggufCacheName(name string) (string, bool) {
	base := strings.TrimSuffix(name, ggufPartialAffix)
	sha, ok := strings.CutSuffix(base, ggufCacheSuffix)
	return sha, ok && validSHA256Hex(sha)
}

func validSHA256Hex(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// pruneGGUFCache bounds what failed imports leave behind: anything that is
// not an entry (or an entry's partial) is removed, as is anything older than
// ggufCacheTTL; of the rest only the newest ggufCacheMaxEntries are kept.
func pruneGGUFCache(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type kept struct {
		path  string
		mtime time.Time
	}
	var live []kept
	now := time.Now()
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		fi, lerr := os.Lstat(p)
		if lerr != nil {
			continue
		}
		_, named := ggufCacheName(e.Name())
		reason := ""
		switch {
		case !named:
			reason = "not a cache entry"
		case !fi.Mode().IsRegular():
			reason = "not a regular file"
		case now.Sub(fi.ModTime()) > ggufCacheTTL:
			reason = "older than the cache TTL"
		}
		if reason != "" {
			slog.Info("ollama weight cache: removing", "path", p, "reason", reason)
			_ = os.RemoveAll(p)
			continue
		}
		live = append(live, kept{p, fi.ModTime()})
	}
	sort.Slice(live, func(i, j int) bool { return live[i].mtime.After(live[j].mtime) })
	for _, k := range live[min(max(ggufCacheMaxEntries, 0), len(live)):] {
		slog.Info("ollama weight cache: removing", "path", k.path, "reason", "over the cache entry limit")
		_ = os.Remove(k.path)
	}
}

func sha256OfFile(p string) (string, error) {
	f, err := os.Open(p)
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

// stageGGUFViaCache puts the weight whose sha256 is want at dest, from the
// cache when a trusted, re-verified copy is there and fetched into the cache
// otherwise. It returns the cache entry (for dropCachedGGUF after a
// successful create), or "" when the cache could not be used and the weight
// was fetched straight to dest.
func stageGGUFViaCache(ctx context.Context, src, dest, want string) (string, error) {
	want = strings.ToLower(strings.TrimSpace(want))
	if !validSHA256Hex(want) {
		// Never build a file name from it: fetch as before the cache, and
		// let FetchOneVerified give its own refusal.
		_, err := preseed.New().FetchOneVerified(ctx, src, dest, want)
		return "", err
	}

	ggufCacheMu.Lock()
	defer ggufCacheMu.Unlock()

	dir, ok := prepareGGUFCache()
	if !ok {
		_, err := preseed.New().FetchOneVerified(ctx, src, dest, want)
		return "", err
	}
	pruneGGUFCache(dir)

	entry := filepath.Join(dir, want+ggufCacheSuffix)
	hit := false
	if fi, err := os.Lstat(entry); err == nil {
		check, reason := "", error(nil)
		if terr := ggufCacheFileTrusted(fi); terr != nil {
			check, reason = "file", terr
		} else if got, herr := sha256OfFile(entry); herr != nil {
			check, reason = "sha256", herr
		} else if got != want {
			check, reason = "sha256", fmt.Errorf("bytes hash to %s", got)
		}
		if reason == nil {
			hit = true
			slog.Info("ollama weight cache: reusing a verified copy", "sha256", want, "path", entry)
		} else {
			slog.Warn("ollama weight cache entry not used; fetching it again",
				"path", entry, "check", check, "reason", reason.Error())
			_ = os.Remove(entry)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(entry)
	}

	if !hit {
		dropUntrustedPartial(entry + ggufPartialAffix)
		// On a digest mismatch FetchOneVerified removes the partial and
		// never renames it to entry: the entry name only ever holds
		// verified bytes.
		if _, err := preseed.New().FetchOneVerified(ctx, src, entry, want); err != nil {
			return "", err
		}
		if err := os.Chmod(entry, 0o600); err != nil {
			_ = os.Remove(entry)
			return "", err
		}
	}

	if err := linkOrCopy(entry, dest); err != nil {
		return "", fmt.Errorf("stage the cached weight: %w", err)
	}
	return entry, nil
}

// dropUntrustedPartial removes a partial that is not this agent's own regular
// file: FetchOneVerified resumes from <entry>.partial and would follow a
// symlink there. (The prune removes one too; this does not rely on it.)
func dropUntrustedPartial(partial string) {
	if fi, err := os.Lstat(partial); err == nil && ggufCacheFileTrusted(fi) != nil {
		slog.Warn("ollama weight cache: removing a partial download it cannot trust",
			"path", partial, "check", "partial")
		_ = os.Remove(partial)
	}
}

// linkOrCopy hard-links src to dest, copying when a link cannot be made
// (another filesystem, a filesystem without links).
func linkOrCopy(src, dest string) error {
	if err := os.Link(src, dest); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dest)
		return err
	}
	return out.Close()
}

// dropCachedGGUF removes a cache entry once ollama holds the model.
func dropCachedGGUF(entry string) {
	if entry == "" {
		return
	}
	ggufCacheMu.Lock()
	defer ggufCacheMu.Unlock()
	if err := os.Remove(entry); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("ollama weight cache: could not remove the entry after a successful create", "path", entry, "error", err.Error())
	}
}
