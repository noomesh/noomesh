// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

// `noo-hostd at-rest copy` and `noo-hostd at-rest wipe` — the root half of
// i10a PR-D (`noo security at-rest migrate`, `... wipe-plaintext`). Like
// create-volume they run as root only because a person typed `sudo
// noo-hostd at-rest …` (the CLI runs that line); no sudoers entry, no spool op.
//
// copy: one state directory into the encrypted volume, by rsync as root
// (the sources are owned by postgres, redis, … and the PKI keys are 0600).
//
//	--src  <abs dir>        the plaintext source (kept, never modified)
//	--name <state dir>      postgres redis nats prometheus grafana loki
//	                        noo-data claude-config alertmanager-data pki
//	--mode pre|final|verify
//
//	pre     rsync -aHAXS --numeric-ids src/ dst/            (online pre-copy)
//	final   … --delete                                       (stack stopped)
//	verify  … --checksum --dry-run --delete --itemize-changes
//	        must list ZERO differences or the verb fails
//
// The destination is always <manifest volume mountpoint>/<name>: the caller
// cannot aim root's rsync anywhere else, and nothing is copied unless the
// manifest records a volume and it is mounted from /dev/mapper/noo-state.
//
// wipe: removes the old plaintext copies, ONLY after the encrypted copy
// exists. Every --entry <abs path>=<name> must be an allowed name, a real
// directory (not a symlink), not inside the volume, and have its counterpart
// <mountpoint>/<name> present. Then fstrim on the parent filesystem
// (best-effort; the SSD caveat is the CLI's to print).
//
// measure: how many bytes the state really is, read as root (postgres is 0700
// and owned by another user, so the operator's own `du` under-counts).
//
//	--entry <abs dir>=<state name>   (repeatable)
//
// Read-only. It needs no volume (the size decides the volume), but the names
// are the same allowed set and each path a real directory. ANY unreadable
// entry fails the verb: a partial measurement is refused, never reported, so
// the caller cannot size a volume from a number that is too small.
//
// Protocol: progress to stderr; stdout carries exactly ONE JSON line.
// Test seam: NOO_RSYNC, NOO_FSTRIM (and PR-C's NOO_ETC_NOO, NOO_MAPPER_DIR),
// printed when active.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// MigrateStateNames is what `copy --name` and `wipe --entry` accept: the
// state set (compose volumes under NOO_STATE_ROOT) plus the PKI.
var MigrateStateNames = []string{
	"postgres", "redis", "nats", "prometheus", "grafana", "loki", "noo-data",
	"claude-config", "alertmanager-data", "pki",
}

// MigrateConfig is every host fact and binary the two verbs touch.
type MigrateConfig struct {
	Volume VolumeConfig // EtcNoo (the manifest), MapperDir, Geteuid
	Rsync  string
	Fstrim string
	// Mounted reports whether mountpoint is mounted from the noo-state
	// mapping (a test replaces it; production reads /proc/mounts).
	Mounted   func(mountpoint string) bool
	Overrides []string
}

// MigrateConfigFromEnv is the production configuration.
func MigrateConfigFromEnv() MigrateConfig {
	c := MigrateConfig{Volume: VolumeConfigFromEnv(), Rsync: "rsync", Fstrim: "fstrim"}
	c.Overrides = append(c.Overrides, c.Volume.Overrides...)
	for _, o := range []struct {
		env string
		dst *string
	}{{"NOO_RSYNC", &c.Rsync}, {"NOO_FSTRIM", &c.Fstrim}} {
		if v := strings.TrimSpace(os.Getenv(o.env)); v != "" {
			*o.dst = v
			c.Overrides = append(c.Overrides, o.env+"="+v)
		}
	}
	cfg := c
	c.Mounted = func(mp string) bool { return migrateMountedFromMapper(cfg.Volume, "/proc/mounts", mp) }
	return c
}

// IsAtRestMigrateVerb reports whether `noo-hostd at-rest <verb>` is one of
// this file's.
func IsAtRestMigrateVerb(args []string) bool {
	return len(args) > 0 && (args[0] == "copy" || args[0] == "wipe" || args[0] == "measure")
}

// RunAtRestMigrate dispatches `noo-hostd at-rest copy|wipe …`.
func RunAtRestMigrate(args []string, stdout, stderr io.Writer) error {
	return runAtRestMigrate(MigrateConfigFromEnv(), args, stdout, stderr)
}

func runAtRestMigrate(cfg MigrateConfig, args []string, stdout, stderr io.Writer) error {
	if !IsAtRestMigrateVerb(args) {
		return errors.New("at-rest: not a copy/wipe verb")
	}
	for _, o := range cfg.Overrides {
		fmt.Fprintf(stderr, "noo-hostd at-rest: override in effect: %s\n", o)
	}
	switch args[0] {
	case "copy":
		return migrateCopyCmd(cfg, args[1:], stdout, stderr)
	case "measure":
		return migrateMeasureCmd(cfg, args[1:], stdout, stderr)
	default:
		return migrateWipeCmd(cfg, args[1:], stdout, stderr)
	}
}

func migrateNameOK(name string) bool {
	for _, n := range MigrateStateNames {
		if n == name {
			return true
		}
	}
	return false
}

// migrateMountedFromMapper: the last /proc/mounts entry for mountpoint is
// the noo-state mapping (by name, or by the dm-N node whose dm name it is).
func migrateMountedFromMapper(vc VolumeConfig, procMounts, mountpoint string) bool {
	f, err := os.Open(procMounts)
	if err != nil {
		return false
	}
	defer f.Close()
	want := strings.TrimRight(mountpoint, "/")
	last := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 2 {
			continue
		}
		if strings.TrimRight(strings.ReplaceAll(fl[1], `\040`, " "), "/") == want {
			last = fl[0]
		}
	}
	if last == "" {
		return false
	}
	if last == vc.MapperPath() || last == "/dev/mapper/"+VolumeMapperName {
		return true
	}
	if dev := strings.TrimPrefix(last, "/dev/"); strings.HasPrefix(dev, "dm-") && !strings.Contains(dev, "/") {
		if b, err := os.ReadFile("/sys/block/" + dev + "/dm/name"); err == nil {
			return strings.TrimSpace(string(b)) == VolumeMapperName
		}
	}
	return false
}

// migrateVolumeMount returns the manifest's mountpoint, refusing unless the
// caller is root and the volume is open and mounted.
func migrateVolumeMount(cfg MigrateConfig) (string, error) {
	if cfg.Volume.Geteuid() != 0 {
		return "", errors.New("must run as root (sudo noo-hostd at-rest …)")
	}
	m, err := volReadManifest(cfg.Volume)
	if err != nil {
		return "", err
	}
	mp, _ := m["volume_mountpoint"].(string)
	mp = strings.TrimRight(mp, "/")
	if mp == "" || !filepath.IsAbs(mp) || filepath.Clean(mp) != mp {
		return "", fmt.Errorf("%s records no encrypted state volume: run `noo security at-rest create-volume` first", cfg.Volume.ManifestPath())
	}
	if !cfg.Mounted(mp) {
		return "", fmt.Errorf("the encrypted state volume is not open: %s is not mounted from %s — nothing was touched", mp, cfg.Volume.MapperPath())
	}
	return mp, nil
}

// migrateInside: is p equal to or under dir?
func migrateInside(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// migrateCheckDir: absolute, clean, a real directory (not a symlink), at least
// two path elements deep.
func migrateCheckDir(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%q: an absolute, clean path is required", p)
	}
	if strings.Count(p, "/") < 2 {
		return fmt.Errorf("%q: too shallow", p)
	}
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("%q: must be a real directory, not a symlink or file", p)
	}
	return nil
}

func migrateCopyCmd(cfg MigrateConfig, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("copy", flag.ContinueOnError)
	fset.SetOutput(stderr)
	src := fset.String("src", "", "the plaintext source directory (kept)")
	name := fset.String("name", "", "the state directory name under the volume")
	mode := fset.String("mode", "", "pre | final | verify")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 0 {
		return fmt.Errorf("copy: unexpected argument %q", fset.Arg(0))
	}
	if !migrateNameOK(*name) {
		return fmt.Errorf("copy: --name %q is not one of %s", *name, strings.Join(MigrateStateNames, ", "))
	}
	if *mode != "pre" && *mode != "final" && *mode != "verify" {
		return fmt.Errorf("copy: --mode must be pre, final or verify, not %q", *mode)
	}
	mp, err := migrateVolumeMount(cfg)
	if err != nil {
		return err
	}
	if err := migrateCheckDir(*src); err != nil {
		return fmt.Errorf("copy: --src %w", err)
	}
	if migrateInside(*src, mp) || migrateInside(mp, *src) {
		return fmt.Errorf("copy: --src %s overlaps the volume %s", *src, mp)
	}
	dst := filepath.Join(mp, *name)
	if *mode == "verify" {
		if _, err := os.Stat(dst); err != nil {
			return fmt.Errorf("copy: nothing to verify, %s does not exist", dst)
		}
	} else if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	rsyncArgs := []string{"-aHAXS", "--numeric-ids"}
	switch *mode {
	case "final":
		rsyncArgs = append(rsyncArgs, "--delete")
	case "verify":
		rsyncArgs = append(rsyncArgs, "--checksum", "--dry-run", "--delete", "--itemize-changes")
	}
	rsyncArgs = append(rsyncArgs, *src+"/", dst+"/")
	fmt.Fprintf(stderr, "noo-hostd at-rest copy: %s %s\n", filepath.Base(cfg.Rsync), strings.Join(rsyncArgs, " "))
	var out bytes.Buffer
	cmd := exec.Command(cfg.Rsync, rsyncArgs...)
	cmd.Stdout = &out
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("copy %s (%s): rsync failed: %v — the source was not modified", *name, *mode, err)
	}
	diffs := 0
	if *mode == "verify" {
		var shown []string
		for _, l := range strings.Split(out.String(), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			diffs++
			if len(shown) < 20 {
				shown = append(shown, l)
			}
		}
		if diffs > 0 {
			return fmt.Errorf("copy %s (verify): %d difference(s) between %s and %s, first:\n%s", *name, diffs, *src, dst, strings.Join(shown, "\n"))
		}
	}
	return migrateJSON(stdout, map[string]any{"ok": true, "verb": "copy", "mode": *mode, "name": *name, "src": *src, "dst": dst, "differences": diffs})
}

func migrateJSON(w io.Writer, v map[string]any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

type migrateEntries []string

func (e *migrateEntries) String() string     { return strings.Join(*e, ",") }
func (e *migrateEntries) Set(v string) error { *e = append(*e, v); return nil }

func migrateWipeCmd(cfg MigrateConfig, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("wipe", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var entries migrateEntries
	fset.Var(&entries, "entry", "<abs plaintext dir>=<state name> (repeatable)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 0 || len(entries) == 0 {
		return errors.New("wipe: one or more --entry <abs path>=<name> are required")
	}
	mp, err := migrateVolumeMount(cfg)
	if err != nil {
		return err
	}
	type target struct{ path, name string }
	var ts []target
	// Validate EVERYTHING before removing anything.
	for _, e := range entries {
		i := strings.LastIndex(e, "=")
		if i <= 0 {
			return fmt.Errorf("wipe: --entry %q is not <path>=<name>", e)
		}
		p, n := e[:i], e[i+1:]
		if !migrateNameOK(n) {
			return fmt.Errorf("wipe: %q: %q is not a state name", p, n)
		}
		if err := migrateCheckDir(p); err != nil {
			return fmt.Errorf("wipe: %w", err)
		}
		if migrateInside(p, mp) || migrateInside(mp, p) {
			return fmt.Errorf("wipe: %s overlaps the encrypted volume %s: refusing", p, mp)
		}
		if st, err := os.Stat(filepath.Join(mp, n)); err != nil || !st.IsDir() {
			return fmt.Errorf("wipe: %s has no encrypted counterpart %s: refusing to remove the only copy", p, filepath.Join(mp, n))
		}
		ts = append(ts, target{p, n})
	}
	removed := []string{}
	trim := "skipped"
	for _, t := range ts {
		fmt.Fprintf(stderr, "noo-hostd at-rest wipe: removing %s (encrypted copy: %s)\n", t.path, filepath.Join(mp, t.name))
		if err := os.RemoveAll(t.path); err != nil {
			return fmt.Errorf("wipe: removing %s: %w (removed so far: %v)", t.path, err, removed)
		}
		removed = append(removed, t.path)
		cmd := exec.Command(cfg.Fstrim, "-v", filepath.Dir(t.path))
		cmd.Stdout, cmd.Stderr = stderr, stderr
		if err := cmd.Run(); err != nil {
			trim = "failed"
			fmt.Fprintf(stderr, "noo-hostd at-rest wipe: fstrim %s: %v (not fatal; the blocks may linger until the SSD reuses them)\n", filepath.Dir(t.path), err)
		} else if trim != "failed" {
			trim = "ok"
		}
	}
	return migrateJSON(stdout, map[string]any{"ok": true, "verb": "wipe", "removed": removed, "fstrim": trim})
}

// migrateMeasure sums the on-disk size of a tree: the larger of apparent size
// and allocated blocks per file, hard links once, and any error is fatal.
func migrateMeasure(root string) (uint64, error) {
	var total uint64
	seen := map[[2]uint64]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		size := uint64(info.Size())
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			if alloc := uint64(st.Blocks) * 512; alloc > size {
				size = alloc
			}
			if !info.IsDir() && st.Nlink > 1 {
				k := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
				if seen[k] {
					return nil
				}
				seen[k] = true
			}
		}
		total += size
		return nil
	})
	return total, err
}

func migrateMeasureCmd(cfg MigrateConfig, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("measure", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var entries migrateEntries
	fset.Var(&entries, "entry", "<abs dir>=<state name> (repeatable)")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 0 || len(entries) == 0 {
		return errors.New("measure: one or more --entry <abs path>=<name> are required")
	}
	if cfg.Volume.Geteuid() != 0 {
		return errors.New("measure: must run as root (sudo noo-hostd at-rest measure): as the operator it would under-count what it cannot read")
	}
	bytesBy := map[string]uint64{}
	var total uint64
	for _, e := range entries {
		i := strings.LastIndex(e, "=")
		if i <= 0 {
			return fmt.Errorf("measure: --entry %q is not <path>=<name>", e)
		}
		p, n := e[:i], e[i+1:]
		if !migrateNameOK(n) {
			return fmt.Errorf("measure: %q: %q is not a state name", p, n)
		}
		if err := migrateCheckDir(p); err != nil {
			return fmt.Errorf("measure: %w", err)
		}
		b, err := migrateMeasure(p)
		if err != nil {
			return fmt.Errorf("measure: %s is only partly readable (%v): refusing to report a partial size", p, err)
		}
		bytesBy[n] = b
		total += b
	}
	return migrateJSON(stdout, map[string]any{"ok": true, "verb": "measure", "bytes": bytesBy, "total": total})
}
