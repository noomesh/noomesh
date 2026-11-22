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
// What a root is MEANT to be comes from what the machine already declares,
// never from a switch set by hand: a root is a MOUNT when a boot-time mount
// covers it (the longest mount point above it) — an /etc/fstab entry without
// `noauto` (or with `x-systemd.automount`), or a systemd mount unit
// (/etc/systemd/system/*.mount, /run/systemd/generator*/*.mount, read by its
// Where=; a unit whose Options= has `noauto` does not count unless an
// .automount unit names the same Where=). Otherwise it is a plain directory.
// A unit file in /etc/systemd/system counts whether or not it is enabled.
//
// First run (no entry for a path): a root covered by a boot-time mount that
// is not mounted is refused (mount_missing), and nothing is recorded; any
// other root is recorded where it is (a plain directory on the root
// filesystem included: a hand-made, non-boot mount does not come back after a
// reboot either, so there is nothing to protect).
//
// An automount (`x-systemd.automount`, a .automount unit, or an autofs trap in
// mountinfo) is not mounted until first access: before it is called missing,
// the check touches the path ONCE through Bounded (ProbeTimeout) and reads
// the mount table again. A touch that hangs is `not_answering`; it never
// blocks the agent.
//
// A late network mount (_netdev, nfs, cifs) is refused the same way and
// clears by itself: every use re-checks, and the first check that finds it
// mounted logs "data root <p> is mounted now; the refusal is cleared" once.
//
// Which way the filesystem changed matters. A root recorded on the ROOT
// filesystem (a plain directory, or an empty mount point at the first look)
// that is now on a different, non-root filesystem is the disk arriving: it
// is accepted and re-recorded, with one log line. When the root held
// entries at that first look, they are now hidden under the mount, and the
// line and the heartbeat (data_roots.policy.filesystem.hidden_entries) say
// so. A root recorded on its own disk that is now on the root filesystem
// (the empty mount point), or on another non-root filesystem (a different
// disk), is refused.

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
	// Entries is the root's top-level entry count when it was recorded on
	// the root filesystem (at most entryCap; Capped when there were more).
	Entries int  `json:"entries,omitempty"`
	Capped  bool `json:"entries_capped,omitempty"`
	// Hidden is Entries carried over when a disk arrived over the root:
	// what the node wrote there before is now under the mount.
	Hidden       int  `json:"hidden_entries,omitempty"`
	HiddenCapped bool `json:"hidden_capped,omitempty"`
}

// entryCap bounds the one readdir at the first look.
const entryCap = 10000

type fsRecordFile struct {
	Roots map[string]fsRecord `json:"roots"`
}

// Seams for tests: the mount table, fstab, the by-uuid directory, the
// record's location and path resolution.
var (
	mountinfoPath = "/proc/self/mountinfo"
	fstabPath     = "/etc/fstab"
	// mountUnitGlobs are where systemd mount and automount units live
	// (generator* holds the fstab-generated ones too).
	mountUnitGlobs = []string{
		"/etc/systemd/system/*.mount", "/etc/systemd/system/*.automount",
		"/run/systemd/generator*/*.mount", "/run/systemd/generator*/*.automount",
	}
	// automountTrigger touches p once so an automount mounts (an open
	// follows the path; a stat would not trigger it).
	automountTrigger = func(p string) {
		if f, err := os.Open(p); err == nil {
			f.Close()
		}
	}
	byUUIDDir  = "/dev/disk/by-uuid"
	fsCheckOS  = runtime.GOOS
	fsEvalPath = filepath.EvalSymlinks
	fsStatDir  = func(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
	recordPath = func() string {
		dir := os.Getenv("NOO_AGENT_STATE")
		if dir == "" {
			dir = "/var/lib/noo-node-agent"
		}
		return filepath.Join(dir, RecordFileName)
	}
	// countEntries is p's top-level entry count, capped at entryCap (one
	// readdir, at the first look only; the callers run it bounded).
	countEntries = func(p string) (int, bool) {
		f, err := os.Open(p)
		if err != nil {
			return 0, false
		}
		defer f.Close()
		names, _ := f.Readdirnames(entryCap + 1)
		if len(names) > entryCap {
			return entryCap, true
		}
		return len(names), false
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

// bootMount is a boot-time mount the machine declares.
type bootMount struct {
	where     string
	by        string // "fstab" or "systemd unit"
	automount bool   // mounted on first access
	network   bool   // _netdev or a network filesystem: may be late at boot
}

func hasOpt(opts []string, o string) bool {
	for _, x := range opts {
		if x == o {
			return true
		}
	}
	return false
}

func isNetworkFS(fstype string) bool {
	switch fstype {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "glusterfs", "ceph":
		return true
	}
	return false
}

// fstabMounts are the /etc/fstab boot-time mounts (never "/", never swap,
// never `noauto` unless it is also an automount).
func fstabMounts() []bootMount {
	b, err := os.ReadFile(fstabPath)
	if err != nil {
		return nil
	}
	var out []bootMount
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
		if mp == "/" || !strings.HasPrefix(mp, "/") {
			continue
		}
		var opts []string
		if len(f) > 3 {
			opts = strings.Split(f[3], ",")
		}
		auto := hasOpt(opts, "x-systemd.automount")
		if hasOpt(opts, "noauto") && !auto {
			continue
		}
		out = append(out, bootMount{where: mp, by: "fstab", automount: auto,
			network: hasOpt(opts, "_netdev") || isNetworkFS(f[2])})
	}
	return out
}

// unescapeUnitPath decodes a mount unit's name into its path, as
// `systemd-escape --path --unescape` does: "-" is "/", "\xNN" a byte.
func unescapeUnitPath(name string) string {
	var b strings.Builder
	b.WriteByte('/')
	for i := 0; i < len(name); i++ {
		switch {
		case name[i] == '-':
			b.WriteByte('/')
		case name[i] == '\\' && i+3 < len(name) && name[i+1] == 'x':
			if n, err := strconv.ParseUint(name[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
			b.WriteByte(name[i])
		default:
			b.WriteByte(name[i])
		}
	}
	return filepath.Clean(b.String())
}

// unitMounts are the systemd mount units' boot-time mounts. A .mount whose
// Options= has noauto does not count; an .automount names an automount.
func unitMounts() []bootMount {
	var out []bootMount
	for _, g := range mountUnitGlobs {
		files, _ := filepath.Glob(g)
		for _, file := range files {
			b, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			base := filepath.Base(file)
			ext := filepath.Ext(base)
			where, fstype, opts := "", "", ""
			for _, line := range strings.Split(string(b), "\n") {
				k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
				if !ok {
					continue
				}
				switch strings.TrimSpace(k) {
				case "Where":
					where = strings.TrimSpace(v)
				case "Type":
					fstype = strings.TrimSpace(v)
				case "Options":
					opts = strings.TrimSpace(v)
				}
			}
			if where == "" {
				where = unescapeUnitPath(strings.TrimSuffix(base, ext))
			}
			where = filepath.Clean(where)
			if where == "/" || !strings.HasPrefix(where, "/") {
				continue
			}
			o := strings.Split(opts, ",")
			if ext == ".automount" {
				out = append(out, bootMount{where: where, by: "systemd unit", automount: true})
				continue
			}
			if hasOpt(o, "noauto") {
				continue
			}
			out = append(out, bootMount{where: where, by: "systemd unit",
				network: hasOpt(o, "_netdev") || isNetworkFS(fstype)})
		}
	}
	return out
}

// bootMountFor is the longest boot-time mount covering p (zero when none).
// fstab names it when both declare the same mount point (systemd generates
// units from fstab); the flags are merged.
func bootMountFor(p string) bootMount {
	var best bootMount
	for _, m := range append(fstabMounts(), unitMounts()...) {
		if !under(p, m.where) {
			continue
		}
		switch {
		case len(m.where) > len(best.where):
			best = m
		case m.where == best.where:
			best.automount = best.automount || m.automount
			best.network = best.network || m.network
		}
	}
	return best
}

// autofsCovering is the longest autofs trap in mountinfo above p, or "".
func autofsCovering(p string) string {
	b, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return ""
	}
	best := ""
	for _, m := range parseMountinfo(string(b)) {
		if m.fstype == "autofs" && m.target != "/" && under(p, m.target) && len(m.target) > len(best) {
			best = m.target
		}
	}
	return best
}

// automountFor is the automount point above p that a touch would mount: the
// boot mount's when it is an automount, or an autofs trap; the longer wins.
func automountFor(p string, bm bootMount) string {
	want := ""
	if bm.automount {
		want = bm.where
	}
	if t := autofsCovering(p); len(t) > len(want) {
		want = t
	}
	return want
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
			slog.Warn("data root filesystem not recorded; the check stays on fstab and the mount units only", "file", p, "error", err)
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

var (
	refusedMu sync.Mutex
	refused   = map[string]bool{} // root paths refused at the last check
)

// clearedLine is logged once when a refused root passes again.
func clearedLine(p string) string {
	return fmt.Sprintf("data root %s is mounted now; the refusal is cleared", p)
}

// noteRefusals remembers which paths were refused and logs, once, each
// path that was refused before and is not now.
func noteRefusals(paths []string, finds []fsFinding) {
	now := map[string]bool{}
	for _, f := range finds {
		now[f.path] = true
	}
	refusedMu.Lock()
	defer refusedMu.Unlock()
	for _, p := range paths {
		if refused[p] && !now[p] {
			slog.Info(clearedLine(p), "event", "data_root.refusal_cleared", "path", p)
		}
		refused[p] = now[p]
	}
}

// checkFilesystems compares each root's filesystem with its record (or what
// the machine declares it to be), recording on a first known-good look.
func checkFilesystems(r Roots) []fsFinding {
	if fsCheckOS != "linux" {
		// darwin (and anything else): not checked; see the header.
		return nil
	}
	paths := fsPaths(r)
	var out []fsFinding
	for _, p := range paths {
		resolved := p
		if rp, err := fsEvalPath(p); err == nil && rp != "" {
			resolved = rp
		}
		bm := bootMountFor(resolved)
		now, rootDev, err := fsIdentity(resolved)
		if err == nil {
			// An automount is not mounted until touched: touch it once,
			// bounded, then read the table again.
			if want := automountFor(resolved, bm); want != "" && len(now.Target) < len(want) {
				if _, terr := Bounded(want, func() struct{} { automountTrigger(resolved); return struct{}{} }); terr != nil {
					out = append(out, fsFinding{p, Problem{Code: "not_answering", Detail: fmt.Sprintf(
						"%v (touching the automount at %s, which holds %s)", terr, want, p)}})
					continue
				}
				now, rootDev, err = fsIdentity(resolved)
			}
		}
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
				// The safe direction: recorded on the root filesystem and now
				// on its own disk. The disk arrived: accept and record it.
				if rec.OnRootFS && !onRootFS && rootDev != "" && fsStatDir(p) {
					next := fsRecord{FSID: now, Hidden: rec.Entries, HiddenCapped: rec.Capped}
					if putRecord(p, next, false) {
						logArrived(p, now, next)
					}
					continue
				}
				var detail string
				if onRootFS {
					detail = fmt.Sprintf("%s is on %s: the ROOT filesystem, so its mount is not there, not its recorded %s; "+
						"refusing backend starts and fetches into it until the mount is back (nothing is created)", p, now, rec.FSID)
				} else {
					detail = fmt.Sprintf("%s is on a different filesystem, %s, not its recorded %s: another disk is mounted there; "+
						"refusing backend starts and fetches into it until the recorded one is back (nothing is created)", p, now, rec.FSID)
				}
				out = append(out, fsFinding{p, Problem{Code: "not_on_recorded_fs", Detail: detail}})
			}
			continue
		}
		// Nothing recorded: a boot-time mount above it that is not there.
		if bm.where != "" && len(now.Target) < len(bm.where) {
			late := ""
			if bm.network {
				late = "; a network mount can be late at boot: the agent re-checks on every use and clears this by itself"
			}
			out = append(out, fsFinding{p, Problem{Code: "mount_missing", Detail: fmt.Sprintf(
				"%s declares the mount %s, which holds %s, but it is not mounted (%s holds it); refusing until it is (nothing is created)%s",
				bootMountSource(bm), bm.where, p, now, late)}})
			continue
		}
		// First run: record a known-good look.
		if rootDev == "" || !fsStatDir(p) {
			continue
		}
		first := fsRecord{FSID: now, OnRootFS: onRootFS}
		if onRootFS {
			first.Entries, first.Capped = countEntries(p)
		}
		if putRecord(p, first, true) {
			slog.Info("data_root.filesystem_recorded", "path", p, "filesystem", now.String(), "entries", first.Entries, "file", recordPath())
		}
	}
	noteRefusals(paths, out)
	return out
}

// putRecord writes p's entry (stamped now); onlyIfAbsent keeps an entry
// another check wrote first. Reports whether it wrote.
func putRecord(p string, rec fsRecord, onlyIfAbsent bool) bool {
	recordMu.Lock()
	defer recordMu.Unlock()
	rf := loadRecordLocked()
	if cur, has := rf.Roots[p]; has && (onlyIfAbsent || sameFS(cur.FSID, rec.FSID)) {
		return false
	}
	next := fsRecordFile{Roots: map[string]fsRecord{}}
	for k, v := range rf.Roots {
		next.Roots[k] = v
	}
	rec.RecordedAt = time.Now().UTC().Format(time.RFC3339)
	next.Roots[p] = rec
	writeRecordLocked(next)
	return true
}

// HiddenNote is what a person is told when a disk arrived over a root that
// held n entries (capped: at least n): they are under the mount now.
func HiddenNote(p string, n int, capped bool) string {
	count := strconv.Itoa(n)
	if capped {
		count = "at least " + count
	}
	return fmt.Sprintf("the disk is now mounted at %s; %s files written before it was mounted are hidden under the mount point "+
		"on the root filesystem: unmount to recover or remove them", p, count)
}

// arrivedLine is the one line logged when a root recorded on the root
// filesystem is found on its own disk and re-recorded.
func arrivedLine(p string, now FSID, rec fsRecord) string {
	if rec.Hidden > 0 {
		return fmt.Sprintf("data root %s is now on its own filesystem (%s, was on the root filesystem); recorded; %s",
			p, now.Source, HiddenNote(p, rec.Hidden, rec.HiddenCapped))
	}
	return fmt.Sprintf("data root %s is now on its own filesystem (%s, was on the root filesystem); recorded", p, now.Source)
}

func logArrived(p string, now FSID, rec fsRecord) {
	if rec.Hidden > 0 {
		slog.Warn(arrivedLine(p, now, rec), "event", "data_root.filesystem_arrived", "path", p, "hidden_entries", rec.Hidden, "file", recordPath())
		return
	}
	slog.Info(arrivedLine(p, now, rec), "event", "data_root.filesystem_arrived", "path", p, "file", recordPath())
}

// bootMountSource names where a boot mount is declared, for a detail.
func bootMountSource(bm bootMount) string {
	if bm.by == "fstab" {
		return fstabPath
	}
	return "a systemd mount unit"
}

// FilesystemReport is the heartbeat's data_roots.policy.filesystem: what the
// data root is MEANT to be ("mount", "directory" or "unknown") and, for a
// mount, what says so ("fstab", "systemd unit", or "recorded": on its own
// disk at a known-good start, with no boot-time mount declared). The verify
// remedy reads it (create the directory only for a plain directory) and the
// `data root policy` row shows it.
func FilesystemReport(r Roots) map[string]any {
	p := filepath.Clean(strings.TrimSpace(r.NooDataRoot))
	meant, by := "unknown", ""
	hidden, hiddenCapped := 0, false
	if fsCheckOS == "linux" {
		resolved := p
		if rp, err := fsEvalPath(p); err == nil && rp != "" {
			resolved = rp
		}
		recordMu.Lock()
		rec, has := loadRecordLocked().Roots[p]
		recordMu.Unlock()
		hidden, hiddenCapped = rec.Hidden, rec.HiddenCapped
		switch bm := bootMountFor(resolved); {
		case bm.where != "":
			meant, by = "mount", bm.by
		case has && !rec.OnRootFS:
			meant, by = "mount", "recorded"
		default:
			meant = "directory"
		}
	}
	out := map[string]any{"meant": meant, "by": by, "recorded": recorded(p)}
	if hidden > 0 {
		out["hidden_entries"] = hidden
		out["hidden_capped"] = hiddenCapped
	}
	return out
}

// SetFSIdentityForTest replaces how a path's filesystem is read and turns the
// check on whatever the OS, so tests in other packages can simulate an empty
// mount point or a hung disk. It returns the restore func. Never called by
// the agent.
// The host's own fstab, mount units and mount table are hidden meanwhile.
func SetFSIdentityForTest(f func(string) (FSID, string, error)) func() {
	prevID, prevOS, prevFstab, prevUnits, prevMI := fsIdentity, fsCheckOS, fstabPath, mountUnitGlobs, mountinfoPath
	fsIdentity, fsCheckOS = f, "linux"
	fstabPath, mountUnitGlobs, mountinfoPath = "/nonexistent/fstab", nil, "/nonexistent/mountinfo"
	return func() {
		fsIdentity, fsCheckOS, fstabPath, mountUnitGlobs, mountinfoPath = prevID, prevOS, prevFstab, prevUnits, prevMI
	}
}
