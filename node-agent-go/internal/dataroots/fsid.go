// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

package dataroots

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The data roots' FILESYSTEM: is each root on the disk it was on at a
// known-good start (i1160, "Data roots at boot")?
//
// A data disk that did not mount (late at boot, unplugged, a power cut) leaves
// its mount point as an empty directory on the ROOT filesystem. Every other
// rule passes on it (the directory exists, has the right owner), and before
// this check the agent fetched multi-GB models into it and started backends
// that bound it: data on the wrong disk, shadowed once the mount came back.
//
// The identity is the controller's (scripts/lib-data-root-mount.sh, findmnt
// -T): the mount that CONTAINS the path, read from /proc/self/mountinfo (a
// procfs read, so it never touches a hung mount), as its target, source and
// filesystem type, plus the filesystem UUID when /dev/disk/by-uuid names the
// source device (udev; readable without root). The comparison is the
// controller's too: the UUIDs when both sides have one, else source + target
// + type.
//
// The record lives in the agent's own state directory, beside its other
// node-local facts: <NOO_AGENT_STATE>/data-root-fs.json (default
// /var/lib/noo-node-agent, which is on the root filesystem by design, so it
// is there when the data disk is not). One entry per root path.
//
// First run (no entry for a path): the current filesystem is recorded only
// when it is NOT the root filesystem's device, or when the node declares its
// data root a plain directory (NOO_DATA_ROOT_FS=directory). A path that sits
// on the root filesystem with nothing recorded may be an empty mount point
// whose disk is late, and recording that would refuse the real disk later.
//
// What the node is MEANT to have, without a record:
//   - NOO_DATA_ROOT_FS=mount (node-local declaration): the data root must be
//     on its own filesystem; on the root filesystem's device it is refused.
//   - an /etc/fstab entry whose mount point contains the path: the path must
//     be on that mount; a containing mount ABOVE it (the fstab mount is not
//     there) is refused.
//   - NOO_DATA_ROOT_FS=directory: a plain directory; recorded where it is.
//
// A path whose filesystem differs from the record, or a declared mount that
// is not there, is a SAFETY problem: refused in warn mode too (Refusal), for
// backend starts and for the fetch paths' directory creation (MkdirAll). It
// is re-checked on every use, so the refusal clears itself when the mount
// returns. Linux only: macOS has another mount model (the controller's check
// skips it the same way). A deliberate move (a new disk) is re-recorded by
// removing the record file: the agent records again at its next check.

// FSEnv is the node-local declaration of what the data root is.
const FSEnv = "NOO_DATA_ROOT_FS"

// RecordFileName is the record's name inside the agent's state directory.
const RecordFileName = "data-root-fs.json"

// FSID is one filesystem's identity, as findmnt -T would name it.
type FSID struct {
	Target string `json:"target"`
	Source string `json:"source"`
	FSType string `json:"fstype"`
	UUID   string `json:"uuid,omitempty"`
	Dev    string `json:"dev"` // major:minor, from mountinfo
}

func (f FSID) String() string {
	s := fmt.Sprintf("%s at %s (%s)", f.Source, f.Target, f.FSType)
	if f.UUID != "" {
		s = "UUID " + f.UUID + ", " + s
	}
	return s
}

// fsRecord is one root's entry in the record file.
type fsRecord struct {
	FSID
	OnRootFS   bool   `json:"on_root_fs"`
	RecordedAt string `json:"recorded_at"`
}

type fsRecordFile struct {
	Roots map[string]fsRecord `json:"roots"`
}

// Seams for tests: the mount table, fstab, the by-uuid directory, the
// record's location and path resolution.
var (
	mountinfoPath = "/proc/self/mountinfo"
	fstabPath     = "/etc/fstab"
	byUUIDDir     = "/dev/disk/by-uuid"
	fsCheckOS     = runtime.GOOS
	fsEvalPath    = filepath.EvalSymlinks
	fsStatDir     = func(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
	recordPath    = func() string {
		dir := os.Getenv("NOO_AGENT_STATE")
		if dir == "" {
			dir = "/var/lib/noo-node-agent"
		}
		return filepath.Join(dir, RecordFileName)
	}
	// fsIdentity is the filesystem containing p and the root filesystem's
	// device; the empty-mount-point tests replace it.
	fsIdentity = readFSIdentity
)

type mountEntry struct {
	dev, target, fstype, source string
}

// unescapeMount undoes mountinfo/fstab octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseMountinfo reads /proc/self/mountinfo lines: "id parent major:minor
// root mountpoint opts [optional...] - fstype source superopts".
func parseMountinfo(text string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(f) {
			continue
		}
		out = append(out, mountEntry{dev: f[2], target: unescapeMount(f[4]), fstype: f[sep+1], source: unescapeMount(f[sep+2])})
	}
	return out
}

func under(p, mp string) bool {
	return mp == "/" || p == mp || strings.HasPrefix(p, mp+"/")
}

// containing is the mount holding p: the longest mount point above it, the
// LAST one listed on a tie (a later mount is on top).
func containing(mounts []mountEntry, p string) (mountEntry, bool) {
	var best mountEntry
	found := false
	for _, m := range mounts {
		// An automount trap (autofs) is not the filesystem: the real mount
		// stacks on it once the path is touched (path resolution does).
		if m.fstype == "autofs" || !under(p, m.target) {
			continue
		}
		if !found || len(m.target) >= len(best.target) {
			best, found = m, true
		}
	}
	return best, found
}

// uuidOf is the UUID /dev/disk/by-uuid gives source's device, or "".
func uuidOf(source string) string {
	if !strings.HasPrefix(source, "/dev/") {
		return ""
	}
	want, err := filepath.EvalSymlinks(source)
	if err != nil {
		want = source
	}
	entries, err := os.ReadDir(byUUIDDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		got, err := filepath.EvalSymlinks(filepath.Join(byUUIDDir, e.Name()))
		if err == nil && got == want {
			return e.Name()
		}
	}
	return ""
}

// readFSIdentity: the filesystem containing p, and the root filesystem's
// major:minor. Never touches p's own mount beyond the path resolution the
// caller did.
func readFSIdentity(p string) (FSID, string, error) {
	b, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return FSID{}, "", err
	}
	mounts := parseMountinfo(string(b))
	rootDev := ""
	if m, ok := containing(mounts, "/"); ok && m.target == "/" {
		rootDev = m.dev
	}
	m, ok := containing(mounts, p)
	if !ok {
		return FSID{}, rootDev, fmt.Errorf("no mount in %s holds %s", mountinfoPath, p)
	}
	return FSID{Target: m.target, Source: m.source, FSType: m.fstype, Dev: m.dev, UUID: uuidOf(m.source)}, rootDev, nil
}

// fstabMountFor is the longest /etc/fstab mount point (never "/", never
// swap) that contains p, or "".
func fstabMountFor(p string) string {
	b, err := os.ReadFile(fstabPath)
	if err != nil {
		return ""
	}
	best := ""
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || f[2] == "swap" {
			continue
		}
		mp := filepath.Clean(unescapeMount(f[1]))
		if mp == "/" || !strings.HasPrefix(mp, "/") || !under(p, mp) {
			continue
		}
		if len(mp) > len(best) {
			best = mp
		}
	}
	return best
}

// sameFS is the controller's comparison: UUIDs when both sides have one,
// else the mount (source, target, type).
func sameFS(rec, now FSID) bool {
	if rec.UUID != "" && now.UUID != "" {
		return rec.UUID == now.UUID
	}
	return rec.Source == now.Source && rec.Target == now.Target && rec.FSType == now.FSType
}

var (
	recordMu    sync.Mutex
	recordCache fsRecordFile
	recordStamp string // path|mtime|size of what recordCache holds
	recordWarn  string // last write failure logged
)

// loadRecordLocked refreshes the cache when the file changed (an operator
// removing it to re-record is seen at the next check).
func loadRecordLocked() fsRecordFile {
	p := recordPath()
	fi, err := os.Stat(p)
	stamp := p + "|absent"
	if err == nil {
		stamp = fmt.Sprintf("%s|%d|%d", p, fi.ModTime().UnixNano(), fi.Size())
	}
	if stamp == recordStamp && recordCache.Roots != nil {
		return recordCache
	}
	rf := fsRecordFile{Roots: map[string]fsRecord{}}
	if err == nil {
		if b, rerr := os.ReadFile(p); rerr == nil {
			var got fsRecordFile
			if json.Unmarshal(b, &got) == nil && got.Roots != nil {
				rf = got
			} else {
				slog.Warn("data root filesystem record unreadable; treated as nothing recorded", "file", p)
			}
		}
	}
	recordCache, recordStamp = rf, stamp
	return rf
}

func writeRecordLocked(rf fsRecordFile) {
	p := recordPath()
	b, _ := json.MarshalIndent(rf, "", "  ")
	tmp := p + ".tmp"
	err := os.MkdirAll(filepath.Dir(p), 0o700)
	if err == nil {
		err = os.WriteFile(tmp, append(b, '\n'), 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		if recordWarn != err.Error() {
			recordWarn = err.Error()
			slog.Warn("data root filesystem not recorded; the check stays on fstab and NOO_DATA_ROOT_FS only", "file", p, "error", err)
		}
		recordCache = rf // keep it for this process
		return
	}
	recordStamp = ""
	_ = loadRecordLocked()
}

// recorded reports whether p has an entry in the record.
func recorded(p string) bool {
	recordMu.Lock()
	defer recordMu.Unlock()
	_, ok := loadRecordLocked().Roots[filepath.Clean(p)]
	return ok
}

// fsFinding is a safety problem on one root path.
type fsFinding struct {
	path string
	Problem
}

// safetyCodes are refused in warn mode too: using the root would write to,
// or mount, the wrong disk.
var safetyCodes = map[string]bool{"not_on_recorded_fs": true, "mount_missing": true, "not_answering": true}

// IsSafety reports whether a problem code is refused whatever the mode.
func IsSafety(code string) bool { return safetyCodes[code] }

// fsPaths are the distinct root paths to check: the data root first.
func fsPaths(r Roots) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range []string{r.NooDataRoot, r.HFCacheDir, r.ModelsDir, r.OllamaDataDir} {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// declaredFS is NOO_DATA_ROOT_FS: "mount", "directory" or "" (not declared).
func declaredFS() string {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(FSEnv))); v {
	case "mount", "directory":
		return v
	}
	return ""
}

// checkFilesystems compares each root's filesystem with its record (or what
// it is declared to be), recording on a first known-good look.
func checkFilesystems(r Roots) []fsFinding {
	if fsCheckOS != "linux" {
		return nil
	}
	decl := declaredFS()
	var out []fsFinding
	for i, p := range fsPaths(r) {
		isDataRoot := i == 0
		resolved := p
		if rp, err := fsEvalPath(p); err == nil && rp != "" {
			resolved = rp
		}
		now, rootDev, err := fsIdentity(resolved)
		recordMu.Lock()
		rec, has := loadRecordLocked().Roots[p]
		recordMu.Unlock()
		if err != nil {
			if has {
				out = append(out, fsFinding{p, Problem{Code: "not_on_recorded_fs", Detail: fmt.Sprintf(
					"which filesystem holds %s cannot be read (%v); recorded %s; refusing until it can", p, err, rec.FSID)}})
			}
			continue
		}
		onRootFS := rootDev != "" && now.Dev == rootDev
		if has {
			if !sameFS(rec.FSID, now) {
				what := ""
				if onRootFS {
					what = ": the ROOT filesystem, so its mount is not there"
				}
				out = append(out, fsFinding{p, Problem{Code: "not_on_recorded_fs", Detail: fmt.Sprintf(
					"%s is on %s%s, not its recorded %s; refusing backend starts and fetches into it until the mount is back (nothing is created)",
					p, now, what, rec.FSID)}})
			}
			continue
		}
		// Nothing recorded: what is it MEANT to be?
		if mp := fstabMountFor(resolved); mp != "" && len(now.Target) < len(mp) {
			out = append(out, fsFinding{p, Problem{Code: "mount_missing", Detail: fmt.Sprintf(
				"/etc/fstab mounts %s, which holds %s, but it is not mounted (%s holds it); refusing until it is (nothing is created)",
				mp, p, now)}})
			continue
		}
		if isDataRoot && decl == "mount" && onRootFS {
			out = append(out, fsFinding{p, Problem{Code: "mount_missing", Detail: fmt.Sprintf(
				"%s=mount, but %s is on the root filesystem (%s): its mount is not there; refusing until it is (nothing is created)",
				FSEnv, p, now)}})
			continue
		}
		// First run: record a known-good look only.
		if (onRootFS && !(isDataRoot && decl == "directory")) || rootDev == "" || !fsStatDir(p) {
			continue
		}
		recordMu.Lock()
		rf := loadRecordLocked()
		if _, raced := rf.Roots[p]; !raced {
			next := fsRecordFile{Roots: map[string]fsRecord{}}
			for k, v := range rf.Roots {
				next.Roots[k] = v
			}
			next.Roots[p] = fsRecord{FSID: now, OnRootFS: onRootFS, RecordedAt: time.Now().UTC().Format(time.RFC3339)}
			writeRecordLocked(next)
			slog.Info("data_root.filesystem_recorded", "path", p, "filesystem", now.String(), "file", recordPath())
		}
		recordMu.Unlock()
	}
	return out
}

// FilesystemReport is the heartbeat's data_roots.policy.filesystem: what the
// data root is MEANT to be ("mount", "directory" or "unknown"), which the
// verify remedy reads (create the directory only for a plain directory).
func FilesystemReport(r Roots) map[string]any {
	p := filepath.Clean(strings.TrimSpace(r.NooDataRoot))
	meant := "unknown"
	switch decl := declaredFS(); {
	case decl != "":
		meant = decl
	default:
		recordMu.Lock()
		rec, has := loadRecordLocked().Roots[p]
		recordMu.Unlock()
		switch {
		case has && rec.OnRootFS:
			meant = "directory"
		case has:
			meant = "mount"
		case fsCheckOS == "linux" && fstabMountFor(p) != "":
			meant = "mount"
		}
	}
	return map[string]any{"meant": meant, "declared": declaredFS(), "recorded": recorded(p)}
}

// SetFSIdentityForTest replaces how a path's filesystem is read and turns the
// check on whatever the OS, so tests in other packages can simulate an empty
// mount point or a hung disk. It returns the restore func. Never called by
// the agent.
func SetFSIdentityForTest(f func(string) (FSID, string, error)) func() {
	prevID, prevOS := fsIdentity, fsCheckOS
	fsIdentity, fsCheckOS = f, "linux"
	return func() { fsIdentity, fsCheckOS = prevID, prevOS }
}
