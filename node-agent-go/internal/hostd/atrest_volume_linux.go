// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

// `noo-hostd at-rest create-volume` — the root half of i10a PR-C: the
// sensitive state set (postgres, redis, nats, prometheus, grafana, loki,
// noo-data, the PKI and an escrow copy of the age key) on a file-backed LUKS2
// volume that this machine's TPM unlocks at boot.
//
// On a controller noo-hostd is a USER unit; this verb runs as root only
// because a person typed `sudo /usr/local/bin/noo-hostd at-rest
// create-volume …` (the CLI runs that line, or prints it). There is no
// sudoers entry and no spool op.
//
// What it does, in order — nothing is claimed until the end, and a failure
// undoes what this run made (the backing file, the mapping, the mountpoint,
// the crypttab/fstab lines, the drop-in):
//
//  1. refuses unless root, not WSL2, a TPM resource manager is present, the
//     data root is a plain absolute path, no volume exists yet, and the data
//     root has the space plus a margin;
//  2. fallocates `<data_root>/state.luks2` (fully allocated, 0600 root);
//  3. `cryptsetup luksFormat --type luks2` with a temporary random key in a
//     0700 directory under /run (tmpfs), keyslot 0;
//  4. `systemd-cryptenroll --recovery-key`: the key is read from its stdout
//     into memory, proven to open the volume (`--test-passphrase`, key on
//     stdin), and handed back on THIS process's stdout only — never written
//     to a file, never logged (skipped with --defer-recovery-key);
//  5. `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=<7|"">`: PCR 7
//     when Secure Boot is on, TPM-only (an explicit empty list) when off;
//     never the firmware PCRs 0/2 (operator decision 2026-10-23);
//  6. proves the TPM token opens it, then `--wipe-slot=0` (the temporary key);
//  7. opens it by the TPM token as `noo-state`, `mkfs.ext4 -L noo-state`;
//  8. `chattr +i` on the EMPTY mountpoint `<data_root>/state` BEFORE the
//     first mount, so with the volume closed nothing can be written there;
//  9. mounts it, makes the state subdirectories with their owners, escrows
//     the age key at `<state>/keys/age.txt`, and (fresh onboard) moves the
//     just-made PKI to `<state>/pki`;
// 10. crypttab `noo-state <file> none luks,tpm2-device=auto,headless=true,nofail`,
//     fstab `/dev/mapper/noo-state <mnt> ext4 defaults,nofail,x-systemd.requires=…`,
//     docker drop-in with After=/Wants= on the mount unit ONLY (never
//     Requires=: a closed volume must not stop docker, the launch check
//     refuses the stack instead), daemon-reload;
// 11. merges the manifest `/etc/noo/at-rest.json` (no secrets).
//
// Protocol: progress goes to stderr; stdout carries exactly ONE JSON line at
// the end, `{"ok":true,"recovery_key":"…",…}`, read by the CLI over a pipe.
//
// Test seam: every binary and path is a VolumeConfig field, overridable from
// the environment (NOO_CRYPTSETUP, NOO_CRYPTENROLL, NOO_MKFS, NOO_CHATTR,
// NOO_MOUNT, NOO_UMOUNT, NOO_FALLOCATE, NOO_SYSTEMCTL, NOO_CRYPTTAB,
// NOO_FSTAB, NOO_UNIT_DIR, NOO_ETC_NOO, NOO_RUN_DIR, NOO_MAPPER_DIR,
// NOO_EFIVARS_DIR, NOO_TPM_DEVICE) in the style of PR-B's seal verbs.
// sudo's env_reset strips them from an operator's shell; an active override
// is printed.
//
// The names here are prefixed (Volume…, vol…) so this file and PR-B's
// atrest_linux.go compile side by side in one package.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// VolumeMapperName is the dm-crypt mapping (`/dev/mapper/noo-state`) and
	// the crypttab name; its unit is systemd-cryptsetup@noo\x2dstate.service.
	VolumeMapperName = "noo-state"
	// VolumeCryptsetupUnit is the unit systemd generates for the crypttab line.
	VolumeCryptsetupUnit = `systemd-cryptsetup@noo\x2dstate.service`
	// VolumeFileName is the backing file under the data root.
	VolumeFileName = "state.luks2"
	// VolumeMountDir is the mountpoint under the data root (NOO_STATE_ROOT).
	VolumeMountDir = "state"
	// VolumeFSLabel is the ext4 label.
	VolumeFSLabel = "noo-state"
	// VolumeDockerDropIn is the docker.service drop-in that orders docker
	// after the mount (After=/Wants= only).
	VolumeDockerDropIn = "docker.service.d/10-noo-state.conf"
	// VolumeManifestName is shared with PR-B (fields are merged, never replaced).
	VolumeManifestName = "at-rest.json"
	// VolumeMarginBytes is the free space kept beyond the volume on the data root.
	VolumeMarginBytes = uint64(5) << 30

	volTempKeySlot   = "0"
	volTmpfsMagic    = 0x01021994
	volSecureBootVar = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	volMaxAgeKey     = 64 << 10
)

// VolumeConfig is every host fact and binary create-volume touches.
type VolumeConfig struct {
	Cryptsetup  string // cryptsetup
	Cryptenroll string // systemd-cryptenroll
	Mkfs        string // mkfs.ext4
	Chattr      string // chattr
	Mount       string // mount
	Umount      string // umount
	Fallocate   string // fallocate
	Systemctl   string // systemctl
	Crypttab    string // /etc/crypttab
	Fstab       string // /etc/fstab
	UnitDir     string // /etc/systemd/system
	EtcNoo      string // /etc/noo
	RunDir      string // /run (tmpfs; the temporary key lives here)
	MapperDir   string // /dev/mapper
	EFIVarsDir  string // /sys/firmware/efi/efivars
	TPMDevice   string // /dev/tpmrm0
	ProcVersion string // /proc/version (the WSL2 check)

	// RootUID/RootGID own the backing file and the mountpoint. 0 in
	// production; the test's own ids in tests.
	RootUID, RootGID int

	Geteuid    func() int
	Now        func() time.Time
	LookupUser func(name string) (uid, gid int, err error)
	// FreeBytes is the space available to root on the filesystem holding path.
	FreeBytes func(path string) (uint64, error)
	// IsTmpfs reports whether path is on tmpfs (the temporary key must never
	// touch a disk).
	IsTmpfs func(path string) bool

	// Overrides lists the env overrides in effect, printed by the verb.
	Overrides []string
}

// VolumeConfigFromEnv is the production configuration.
func VolumeConfigFromEnv() VolumeConfig {
	c := VolumeConfig{
		Cryptsetup:  "cryptsetup",
		Cryptenroll: "systemd-cryptenroll",
		Mkfs:        "mkfs.ext4",
		Chattr:      "chattr",
		Mount:       "mount",
		Umount:      "umount",
		Fallocate:   "fallocate",
		Systemctl:   "systemctl",
		Crypttab:    "/etc/crypttab",
		Fstab:       "/etc/fstab",
		UnitDir:     "/etc/systemd/system",
		EtcNoo:      "/etc/noo",
		RunDir:      "/run",
		MapperDir:   "/dev/mapper",
		EFIVarsDir:  "/sys/firmware/efi/efivars",
		TPMDevice:   "/dev/tpmrm0",
		ProcVersion: "/proc/version",
		Geteuid:     os.Geteuid,
		Now:         time.Now,
		LookupUser:  volLookupUser,
		FreeBytes:   volFreeBytes,
		IsTmpfs:     volIsTmpfs,
	}
	for _, o := range []struct {
		env string
		dst *string
	}{
		{"NOO_CRYPTSETUP", &c.Cryptsetup},
		{"NOO_CRYPTENROLL", &c.Cryptenroll},
		{"NOO_MKFS", &c.Mkfs},
		{"NOO_CHATTR", &c.Chattr},
		{"NOO_MOUNT", &c.Mount},
		{"NOO_UMOUNT", &c.Umount},
		{"NOO_FALLOCATE", &c.Fallocate},
		{"NOO_SYSTEMCTL", &c.Systemctl},
		{"NOO_CRYPTTAB", &c.Crypttab},
		{"NOO_FSTAB", &c.Fstab},
		{"NOO_UNIT_DIR", &c.UnitDir},
		{"NOO_ETC_NOO", &c.EtcNoo},
		{"NOO_RUN_DIR", &c.RunDir},
		{"NOO_MAPPER_DIR", &c.MapperDir},
		{"NOO_EFIVARS_DIR", &c.EFIVarsDir},
		{"NOO_TPM_DEVICE", &c.TPMDevice},
	} {
		if v := strings.TrimSpace(os.Getenv(o.env)); v != "" {
			*o.dst = v
			c.Overrides = append(c.Overrides, o.env+"="+v)
		}
	}
	return c
}

func volLookupUser(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("no such user %q: %w", name, err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("user %q has a non-numeric uid/gid (%s/%s)", name, u.Uid, u.Gid)
	}
	return uid, gid, nil
}

func volFreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func volIsTmpfs(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	return int64(st.Type) == volTmpfsMagic
}

// ManifestPath is /etc/noo/at-rest.json (shared with PR-B's seal verbs).
func (c VolumeConfig) ManifestPath() string { return filepath.Join(c.EtcNoo, VolumeManifestName) }

// MapperPath is /dev/mapper/noo-state.
func (c VolumeConfig) MapperPath() string { return filepath.Join(c.MapperDir, VolumeMapperName) }

// DropInPath is the docker.service drop-in.
func (c VolumeConfig) DropInPath() string { return filepath.Join(c.UnitDir, VolumeDockerDropIn) }

// IsAtRestVolumeVerb reports whether `noo-hostd at-rest <verb>` is one this
// file serves. With PR-B's RunAtRest in the same binary, main dispatches on it.
func IsAtRestVolumeVerb(args []string) bool {
	return len(args) > 0 && args[0] == "create-volume"
}

// RunAtRestVolume dispatches `noo-hostd at-rest create-volume …`.
func RunAtRestVolume(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		volUsage(stderr)
		if len(args) == 0 {
			return errors.New("at-rest: a verb is required")
		}
		return nil
	}
	if !IsAtRestVolumeVerb(args) {
		volUsage(stderr)
		return fmt.Errorf("at-rest: unknown verb %q", args[0])
	}
	cfg := VolumeConfigFromEnv()
	for _, o := range cfg.Overrides {
		fmt.Fprintf(stderr, "noo-hostd at-rest: override in effect: %s\n", o)
	}
	opts, err := parseCreateVolumeArgs(args[1:], stderr)
	if err != nil {
		return err
	}
	return CreateVolume(cfg, opts, stdout, stderr)
}

type subdirList []string

func (s *subdirList) String() string     { return strings.Join(*s, ",") }
func (s *subdirList) Set(v string) error { *s = append(*s, v); return nil }

func parseCreateVolumeArgs(args []string, stderr io.Writer) (VolumeOptions, error) {
	fset := flag.NewFlagSet("create-volume", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dataRoot := fset.String("data-root", "", "the data root; the volume is <data-root>/state.luks2, mounted at <data-root>/state")
	size := fset.Int("size", 0, "the volume size in GiB (fully allocated)")
	u := fset.String("user", "", "the operator account that owns the mounted state")
	pcrs := fset.String("pcrs", "auto", "PCR policy: 7, none, or auto (7 iff Secure Boot is on)")
	ageKey := fset.String("age-key", "", "escrow this age key file at <state>/keys/age.txt (copied; the source is kept)")
	pkiFrom := fset.String("pki-from", "", "MOVE this freshly made PKI directory to <state>/pki (fresh onboard only)")
	deferKey := fset.Bool("defer-recovery-key", false, "enroll no recovery key now (TPM-only until `noo security at-rest recovery-key`)")
	var subdirs subdirList
	fset.Var(&subdirs, "subdir", "a state subdirectory to create: name or name=uid:gid (repeatable)")
	if err := fset.Parse(args); err != nil {
		return VolumeOptions{}, err
	}
	if fset.NArg() != 0 {
		return VolumeOptions{}, fmt.Errorf("create-volume: unexpected argument %q", fset.Arg(0))
	}
	return VolumeOptions{
		DataRoot: *dataRoot, SizeGiB: *size, User: *u, PCRs: *pcrs,
		AgeKey: *ageKey, PKIFrom: *pkiFrom, DeferRecoveryKey: *deferKey, Subdirs: subdirs,
	}, nil
}

func volUsage(w io.Writer) {
	fmt.Fprint(w, `noo-hostd at-rest create-volume — the encrypted state volume (i10a; root)

  sudo noo-hostd at-rest create-volume --data-root <dir> --size <GiB> --user <operator>
        [--subdir <name>[=<uid>:<gid>]]... [--age-key <file>] [--pki-from <dir>]
        [--pcrs 7|none|auto] [--defer-recovery-key]
        Create <dir>/state.luks2 (LUKS2, unlocked at boot by this machine's
        TPM), mount it at <dir>/state, write crypttab/fstab and a docker
        drop-in, and print ONE JSON line on stdout carrying the recovery key.
        Run by 'noo security at-rest create-volume' and by 'noo onboard'.
`)
}

// VolumeOptions are the create-volume arguments.
type VolumeOptions struct {
	DataRoot         string
	SizeGiB          int
	User             string
	PCRs             string // "auto" (or ""), "7", "none"
	AgeKey           string
	PKIFrom          string
	DeferRecoveryKey bool
	Subdirs          []string
}

// VolumeResult is the one JSON line create-volume prints on stdout.
type VolumeResult struct {
	OK          bool   `json:"ok"`
	RecoveryKey string `json:"recovery_key,omitempty"`
	Deferred    bool   `json:"recovery_key_deferred"`
	File        string `json:"volume_file"`
	Mountpoint  string `json:"volume_mountpoint"`
	Mapper      string `json:"volume_mapper"`
	SizeGiB     int    `json:"volume_size_gib"`
	PCRs        string `json:"volume_pcrs"`
	PCRNote     string `json:"pcr_note"`
	PKIDir      string `json:"pki_dir,omitempty"`
	AgeEscrow   string `json:"age_key_escrow,omitempty"`
}

var volSafePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// volValidPath: absolute, clean, no `..`, and only characters fstab,
// crypttab and unit names take without escaping.
func volValidPath(p string) error {
	if p == "" || !volSafePath.MatchString(p) || filepath.Clean(p) != p || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") || p == "/" {
		return fmt.Errorf("%q must be an absolute, clean path of letters, digits, '.', '_', '-' and '/' (fstab and crypttab take nothing else)", p)
	}
	return nil
}

var volSubdirName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type volSubdir struct {
	name     string
	uid, gid int
	owned    bool // an explicit owner was given; otherwise the operator
}

func volParseSubdirs(specs []string) ([]volSubdir, error) {
	var out []volSubdir
	seen := map[string]bool{}
	for _, s := range specs {
		name, owner, has := strings.Cut(s, "=")
		if !volSubdirName.MatchString(name) || name == "keys" || name == "pki" || name == "lost+found" {
			return nil, fmt.Errorf("--subdir %q: a plain lowercase name, not keys/pki (made by this verb)", s)
		}
		if seen[name] {
			return nil, fmt.Errorf("--subdir %q given twice", name)
		}
		seen[name] = true
		d := volSubdir{name: name}
		if has {
			u, g, ok := strings.Cut(owner, ":")
			uid, err1 := strconv.Atoi(u)
			gid, err2 := strconv.Atoi(g)
			if !ok || err1 != nil || err2 != nil || uid < 0 || gid < 0 {
				return nil, fmt.Errorf("--subdir %q: the owner must be <uid>:<gid>", s)
			}
			d.uid, d.gid, d.owned = uid, gid, true
		}
		out = append(out, d)
	}
	return out, nil
}

func volIsWSL(procVersion string) bool {
	b, err := os.ReadFile(procVersion)
	return err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft")
}

// VolumeSecureBoot reads the SecureBoot EFI variable (4 attribute bytes, then
// the value). known=false when it cannot be read: treated as off, never on.
func VolumeSecureBoot(efivarsDir string) (on, known bool) {
	b, err := os.ReadFile(filepath.Join(efivarsDir, volSecureBootVar))
	if err != nil || len(b) < 5 {
		return false, false
	}
	return b[4] == 1, true
}

// VolumePCRs maps the requested policy and Secure Boot to "7" or "none".
// The firmware PCRs (0/2) are never bound: a BIOS update would lock the box
// out (operator decision 2026-10-23).
func VolumePCRs(requested string, sbOn, sbKnown bool) (string, string, error) {
	switch strings.TrimSpace(requested) {
	case "", "auto":
		if sbKnown && sbOn {
			return "7", "Secure Boot is on: bound to PCR 7 (a changed boot chain will not unlock the volume).", nil
		}
		return "none", "Secure Boot is off (or unreadable): TPM-only. The drive alone does not decrypt elsewhere, " +
			"but a live-USB boot of THIS machine is not blocked from unlocking it.", nil
	case "7":
		if !(sbKnown && sbOn) {
			return "7", "PCR 7 bound with Secure Boot OFF: turning Secure Boot on later stops the unlock until re-enrolled.", nil
		}
		return "7", "Secure Boot is on: bound to PCR 7.", nil
	case "none":
		return "none", "TPM-only: a live-USB boot of this machine is not blocked from unlocking it.", nil
	default:
		return "", "", fmt.Errorf("--pcrs %q refused: only 7 or none (auto picks 7 iff Secure Boot is on); "+
			"the firmware PCRs 0/2 are never bound, so a BIOS update cannot lock this machine out", requested)
	}
}

// volPCRsFlag: "none" is an EXPLICIT empty list — systemd-cryptenroll binds
// PCR 7 when --tpm2-pcrs is absent, which would silently bind a TPM-only box.
func volPCRsFlag(pcrs string) string {
	if pcrs == "7" {
		return "--tpm2-pcrs=7"
	}
	return "--tpm2-pcrs="
}

// VolumeMountUnit is systemd-escape --path --suffix=mount for p.
func VolumeMountUnit(p string) string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return "-.mount"
	}
	var b strings.Builder
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		switch {
		case c == '/':
			b.WriteByte('-')
		case c == '.' && (i == 0 || trimmed[i-1] == '/'):
			fmt.Fprintf(&b, `\x%02x`, c)
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ':' || c == '_' || c == '.':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String() + ".mount"
}

// VolumeCrypttabLine is the crypttab entry for the backing file.
func VolumeCrypttabLine(file string) string {
	return fmt.Sprintf("%s %s none luks,tpm2-device=auto,headless=true,nofail", VolumeMapperName, file)
}

// VolumeFstabLine is the fstab entry for the mountpoint.
func VolumeFstabLine(mnt string) string {
	return fmt.Sprintf("/dev/mapper/%s %s ext4 defaults,nofail,x-systemd.requires=%s 0 2", VolumeMapperName, mnt, VolumeCryptsetupUnit)
}

// VolumeDockerDropInBody orders docker after the mount. After= + Wants= ONLY:
// a Requires= would stop docker with the volume, and a closed volume is the
// launch check's to refuse, not a reason to take the whole engine down.
func VolumeDockerDropInBody(mnt string) string {
	unit := VolumeMountUnit(mnt)
	return "# Written by 'noo-hostd at-rest create-volume' (i10a). Do not edit.\n" +
		"# Docker starts after the encrypted state volume is mounted, when it is.\n" +
		"[Unit]\n" +
		"After=" + unit + "\n" +
		"Wants=" + unit + "\n"
}

// volRecoveryKeyRe is systemd's recovery key: 64 modhex characters in eight
// dash-separated groups.
var volRecoveryKeyRe = regexp.MustCompile(`^[cbdefghijklnrtuv]{8}(-[cbdefghijklnrtuv]{8}){7}$`)

// volParseRecoveryKey finds exactly one recovery key in cryptenroll's stdout.
func volParseRecoveryKey(out []byte) (string, error) {
	var found []string
	for _, f := range strings.Fields(string(out)) {
		if volRecoveryKeyRe.MatchString(f) {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("systemd-cryptenroll --recovery-key printed %d recovery keys, expected exactly one", len(found))
	}
	return found[0], nil
}

func volResolveBin(name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found: %w", name, err)
	}
	return filepath.Abs(p)
}

// volRun runs a binary with stdout discarded and stderr captured; the error
// carries stderr with any `redact` strings removed.
func volRun(stdin []byte, redact []string, name string, args ...string) error {
	var errBuf bytes.Buffer
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		for _, r := range redact {
			if r != "" {
				msg = strings.ReplaceAll(msg, r, "<redacted>")
			}
		}
		return fmt.Errorf("%s %s: %v: %s", filepath.Base(name), strings.Join(args, " "), err, msg)
	}
	return nil
}

func volWriteAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".noo-new"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// volTableHas reports whether a crypttab/fstab body has a live (uncommented)
// line whose field `idx` equals want.
func volTableHas(body, want string, idx int) bool {
	for _, l := range strings.Split(body, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		if len(f) > idx && f[idx] == want {
			return true
		}
	}
	return false
}

func volAppendLine(body, line string) string {
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return body + "# noomesh encrypted state volume (i10a)\n" + line + "\n"
}

func volReadOptional(p string) (string, bool, error) {
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

func volReadManifest(cfg VolumeConfig) (map[string]any, error) {
	m := map[string]any{}
	b, err := os.ReadFile(cfg.ManifestPath())
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s does not parse (%v) — it is not overwritten; move it aside first", cfg.ManifestPath(), err)
	}
	return m, nil
}

// volMergeManifest read-modify-writes the manifest, keeping the fields other
// verbs own (PR-B's sealed age key).
func volMergeManifest(cfg VolumeConfig, set map[string]any) error {
	if err := os.MkdirAll(cfg.EtcNoo, 0o755); err != nil {
		return err
	}
	m, err := volReadManifest(cfg)
	if err != nil {
		return err
	}
	for k, v := range set {
		m[k] = v
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return volWriteAtomic(cfg.ManifestPath(), append(b, '\n'), 0o644)
}

// volReadAgeKey reads the key to escrow with the guards a root process owes
// a path someone typed: a regular file (not a symlink), small, owned by the
// operator or root, holding an age secret key.
func volReadAgeKey(path string, operatorUID, rootUID int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("--age-key %q must be an absolute path", path)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the age key: %w", err)
	}
	if st.Mode()&fs.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (a symlink?) — pass the real key file", path)
	}
	if st.Size() == 0 || st.Size() > volMaxAgeKey {
		return nil, fmt.Errorf("%s is %d bytes — not an age key file", path, st.Size())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != operatorUID && int(sys.Uid) != rootUID {
		return nil, fmt.Errorf("%s is owned by uid %d, neither the operator (%d) nor root", path, sys.Uid, operatorUID)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(b, []byte("AGE-SECRET-KEY-1")) { // leak-ok: the age key marker checked for, not a key
		return nil, fmt.Errorf("%s holds no age secret key", path)
	}
	return b, nil
}

// volCheckPKISource: the directory a fresh onboard just made its PKI in. It
// is MOVED (copied, verified, then removed), so it must look like one.
func volCheckPKISource(src string, operatorUID, rootUID int, mnt string) error {
	if !filepath.IsAbs(src) || filepath.Clean(src) != src || src == "/" {
		return fmt.Errorf("--pki-from %q must be an absolute, clean path", src)
	}
	if src == mnt || strings.HasPrefix(src, mnt+"/") {
		return fmt.Errorf("--pki-from %q is inside the volume's mountpoint", src)
	}
	st, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("--pki-from: %w", err)
	}
	if st.Mode()&fs.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("--pki-from %s is not a directory (a symlink?)", src)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != operatorUID && int(sys.Uid) != rootUID {
		return fmt.Errorf("--pki-from %s is owned by uid %d, neither the operator nor root", src, sys.Uid)
	}
	if _, err := os.Lstat(filepath.Join(src, "ca.crt")); err != nil {
		return fmt.Errorf("--pki-from %s holds no ca.crt — not a PKI directory, not moved", src)
	}
	return nil
}

// volCopyTree copies src into dst preserving modes and owners (root does the
// copy, so container-owned keys keep their uid), then proves every file
// arrived byte-identical. Symlinks are copied as links.
func volCopyTree(src, dst string) error {
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		sys, _ := info.Sys().(*syscall.Stat_t)
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			if err := os.Symlink(link, target); err != nil {
				return err
			}
		case info.IsDir():
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			if err := os.Chmod(target, info.Mode().Perm()); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(target, b, 0o600); err != nil {
				return err
			}
			if err := os.Chmod(target, info.Mode().Perm()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s is neither a file, a directory nor a symlink — not copied", p)
		}
		if sys != nil {
			if err := os.Lchown(target, int(sys.Uid), int(sys.Gid)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Prove it.
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		a, err1 := os.ReadFile(p)
		b, err2 := os.ReadFile(filepath.Join(dst, rel))
		if err1 != nil || err2 != nil || sha256.Sum256(a) != sha256.Sum256(b) {
			return fmt.Errorf("the copy of %s does not match the original — the original is kept", rel)
		}
		return nil
	})
}

// volStep prints one progress line on stderr (never a secret).
func volStep(w io.Writer, format string, a ...any) {
	fmt.Fprintf(w, "noo-hostd at-rest: "+format+"\n", a...)
}

// CreateVolume is `create-volume`.
func CreateVolume(cfg VolumeConfig, o VolumeOptions, stdout, stderr io.Writer) (retErr error) {
	// ── 1. preflight: refuse before touching anything ──────────────────
	if cfg.Geteuid() != 0 {
		return errors.New("create-volume needs root: sudo /usr/local/bin/noo-hostd at-rest create-volume --data-root <dir> --size <GiB> --user <you>")
	}
	if volIsWSL(cfg.ProcVersion) {
		return errors.New("not supported here: WSL2 has no TPM to unlock a volume with (i10a covers Linux controllers only)")
	}
	if _, err := os.Stat(cfg.TPMDevice); err != nil {
		return fmt.Errorf("no TPM resource manager at %s — enable the firmware TPM (Intel PTT / AMD fTPM) or a vTPM, then retry", cfg.TPMDevice)
	}
	if o.User == "" {
		return errors.New("--user is required: the operator account that owns the mounted state")
	}
	uid, gid, err := cfg.LookupUser(o.User)
	if err != nil {
		return err
	}
	if err := volValidPath(o.DataRoot); err != nil {
		return fmt.Errorf("--data-root: %w", err)
	}
	if st, err := os.Stat(o.DataRoot); err != nil || !st.IsDir() {
		return fmt.Errorf("--data-root %s is not an existing directory", o.DataRoot)
	}
	if o.SizeGiB < 1 {
		return errors.New("--size must be a whole number of GiB, at least 1")
	}
	subdirs, err := volParseSubdirs(o.Subdirs)
	if err != nil {
		return err
	}
	file := filepath.Join(o.DataRoot, VolumeFileName)
	mnt := filepath.Join(o.DataRoot, VolumeMountDir)
	if _, err := os.Lstat(file); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite a volume", file)
	}
	if _, err := os.Lstat(cfg.MapperPath()); err == nil {
		return fmt.Errorf("%s already exists — a noo-state mapping is open", cfg.MapperPath())
	}
	mntExisted := false
	if st, err := os.Lstat(mnt); err == nil {
		if st.Mode()&fs.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", mnt)
		}
		ents, err := os.ReadDir(mnt)
		if err != nil {
			return err
		}
		if len(ents) > 0 {
			return fmt.Errorf("%s is not empty — the state there would be hidden under the volume; move it first", mnt)
		}
		mntExisted = true
	}
	manifest, err := volReadManifest(cfg)
	if err != nil {
		return err
	}
	if v, _ := manifest["volume_file"].(string); v != "" {
		return fmt.Errorf("the manifest %s already records a volume (%s)", cfg.ManifestPath(), v)
	}
	crypttab, crypttabExisted, err := volReadOptional(cfg.Crypttab)
	if err != nil {
		return err
	}
	if volTableHas(crypttab, VolumeMapperName, 0) {
		return fmt.Errorf("%s already has a %s line", cfg.Crypttab, VolumeMapperName)
	}
	fstab, fstabExisted, err := volReadOptional(cfg.Fstab)
	if err != nil {
		return err
	}
	if volTableHas(fstab, mnt, 1) {
		return fmt.Errorf("%s already mounts something at %s", cfg.Fstab, mnt)
	}
	if _, err := os.Lstat(cfg.DropInPath()); err == nil {
		return fmt.Errorf("%s already exists", cfg.DropInPath())
	}
	size := uint64(o.SizeGiB) << 30
	free, err := cfg.FreeBytes(o.DataRoot)
	if err != nil {
		return fmt.Errorf("cannot read the free space under %s: %w", o.DataRoot, err)
	}
	if free < size+VolumeMarginBytes {
		return fmt.Errorf("not enough space under %s: %d GiB free, the volume needs %d GiB plus a %d GiB margin",
			o.DataRoot, free>>30, o.SizeGiB, VolumeMarginBytes>>30)
	}
	if !cfg.IsTmpfs(cfg.RunDir) {
		return fmt.Errorf("%s is not tmpfs — the temporary key must never touch a disk", cfg.RunDir)
	}
	var ageKey []byte
	if o.AgeKey != "" {
		if ageKey, err = volReadAgeKey(o.AgeKey, uid, cfg.RootUID); err != nil {
			return err
		}
	}
	if o.PKIFrom != "" {
		if err := volCheckPKISource(o.PKIFrom, uid, cfg.RootUID, mnt); err != nil {
			return err
		}
	}
	sbOn, sbKnown := VolumeSecureBoot(cfg.EFIVarsDir)
	pcrs, note, err := VolumePCRs(o.PCRs, sbOn, sbKnown)
	if err != nil {
		return err
	}
	for _, p := range []*string{&cfg.Cryptsetup, &cfg.Cryptenroll, &cfg.Mkfs, &cfg.Chattr, &cfg.Mount, &cfg.Umount, &cfg.Fallocate, &cfg.Systemctl} {
		abs, err := volResolveBin(*p)
		if err != nil {
			return err
		}
		*p = abs
	}

	// ── rollback: undo what THIS run made, newest first ────────────────
	var undo []func()
	committed := false // the manifest records the volume: nothing is undone after that
	defer func() {
		if retErr == nil || committed {
			return
		}
		volStep(stderr, "failed — undoing what this run made")
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}()

	// ── 2. the temporary key, on tmpfs ─────────────────────────────────
	keyDir, err := os.MkdirTemp(cfg.RunDir, "noo-at-rest-")
	if err != nil {
		return fmt.Errorf("cannot make a temporary key directory under %s: %w", cfg.RunDir, err)
	}
	if err := os.Chmod(keyDir, 0o700); err != nil {
		_ = os.RemoveAll(keyDir)
		return err
	}
	tmpKey := filepath.Join(keyDir, "key")
	defer func() {
		// Overwrite, then remove, whatever happened.
		_ = os.WriteFile(tmpKey, make([]byte, 64), 0o600)
		_ = os.RemoveAll(keyDir)
	}()
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	if err := os.WriteFile(tmpKey, secret, 0o600); err != nil {
		return err
	}
	for i := range secret {
		secret[i] = 0
	}

	// ── 3. the backing file ────────────────────────────────────────────
	volStep(stderr, "allocating %s (%d GiB, fully allocated)", file, o.SizeGiB)
	if err := volRun(nil, nil, cfg.Fallocate, "-l", strconv.FormatUint(size, 10), file); err != nil {
		_ = os.Remove(file)
		return err
	}
	undo = append(undo, func() { _ = os.Remove(file) })
	if err := os.Lchown(file, cfg.RootUID, cfg.RootGID); err != nil {
		return err
	}
	if err := os.Chmod(file, 0o600); err != nil {
		return err
	}

	// ── 4. LUKS2 with the temporary key in slot 0 ──────────────────────
	volStep(stderr, "formatting LUKS2")
	if err := volRun(nil, nil, cfg.Cryptsetup, "luksFormat", "--type", "luks2", "--batch-mode",
		"--key-slot", volTempKeySlot, "--key-file", tmpKey, "--label", VolumeFSLabel, file); err != nil {
		return err
	}

	// ── 5. the recovery key: in memory, proven, handed back on stdout ──
	recovery := ""
	if !o.DeferRecoveryKey {
		volStep(stderr, "enrolling a recovery key (shown once by the CLI, never written to disk)")
		var out, errBuf bytes.Buffer
		cmd := exec.Command(cfg.Cryptenroll, "--recovery-key", "--unlock-key-file="+tmpKey, file)
		cmd.Stdout = &out
		cmd.Stderr = &errBuf
		runErr := cmd.Run()
		key, perr := volParseRecoveryKey(out.Bytes())
		msg := strings.TrimSpace(errBuf.String())
		if key != "" {
			msg = strings.ReplaceAll(msg, key, "<redacted>")
		}
		out.Reset()
		if runErr != nil {
			return fmt.Errorf("systemd-cryptenroll --recovery-key: %v: %s", runErr, msg)
		}
		if perr != nil {
			return perr
		}
		recovery = key
		if err := volRun([]byte(recovery), []string{recovery}, cfg.Cryptsetup, "open", "--test-passphrase", "--key-file=-", file); err != nil {
			return fmt.Errorf("the recovery key did not open the volume in a test — nothing kept: %w", err)
		}
	} else {
		volStep(stderr, "recovery key DEFERRED: the volume unlocks by the TPM only until `noo security at-rest recovery-key`")
	}

	// ── 6. the TPM, proven, then the temporary key wiped ───────────────
	volStep(stderr, "enrolling the TPM (%s)", volPCRsFlag(pcrs))
	if err := volRun(nil, []string{recovery}, cfg.Cryptenroll, "--tpm2-device=auto", volPCRsFlag(pcrs), "--unlock-key-file="+tmpKey, file); err != nil {
		return err
	}
	if err := volRun(nil, []string{recovery}, cfg.Cryptsetup, "open", "--test-passphrase", "--token-only", "--token-type", "systemd-tpm2", file); err != nil {
		return fmt.Errorf("the TPM enrollment did not open the volume in a test — nothing kept: %w", err)
	}
	if err := volRun(nil, []string{recovery}, cfg.Cryptenroll, "--wipe-slot="+volTempKeySlot, file); err != nil {
		return err
	}

	// ── 7. open by the TPM, ext4 ───────────────────────────────────────
	volStep(stderr, "opening %s by the TPM", VolumeMapperName)
	if err := volRun(nil, []string{recovery}, cfg.Cryptsetup, "open", "--token-only", "--token-type", "systemd-tpm2", file, VolumeMapperName); err != nil {
		return err
	}
	undo = append(undo, func() { _ = volRun(nil, nil, cfg.Cryptsetup, "close", VolumeMapperName) })
	mapper := "/dev/mapper/" + VolumeMapperName
	if err := volRun(nil, nil, cfg.Mkfs, "-F", "-q", "-L", VolumeFSLabel, mapper); err != nil {
		return err
	}

	// ── 8. the EMPTY mountpoint, immutable before the first mount ──────
	if !mntExisted {
		if err := os.Mkdir(mnt, 0o755); err != nil {
			return err
		}
		undo = append(undo, func() { _ = os.Remove(mnt) })
	}
	if err := os.Lchown(mnt, cfg.RootUID, cfg.RootGID); err != nil {
		return err
	}
	if err := os.Chmod(mnt, 0o755); err != nil {
		return err
	}
	if err := volRun(nil, nil, cfg.Chattr, "+i", mnt); err != nil {
		return err
	}
	undo = append(undo, func() { _ = volRun(nil, nil, cfg.Chattr, "-i", mnt) })

	// ── 9. mount, then the state layout ────────────────────────────────
	volStep(stderr, "mounting at %s", mnt)
	if err := volRun(nil, nil, cfg.Mount, "-t", "ext4", mapper, mnt); err != nil {
		return err
	}
	undo = append(undo, func() { _ = volRun(nil, nil, cfg.Umount, mnt) })
	if err := os.Lchown(mnt, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(mnt, 0o755); err != nil {
		return err
	}
	for _, d := range subdirs {
		p := filepath.Join(mnt, d.name)
		if err := os.Mkdir(p, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		ou, og := uid, gid
		if d.owned {
			ou, og = d.uid, d.gid
		}
		if err := os.Lchown(p, ou, og); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o755); err != nil {
			return err
		}
	}
	escrow := ""
	if ageKey != nil {
		keys := filepath.Join(mnt, "keys")
		if err := os.Mkdir(keys, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := os.Lchown(keys, uid, gid); err != nil {
			return err
		}
		escrow = filepath.Join(keys, "age.txt")
		if err := os.WriteFile(escrow, ageKey, 0o600); err != nil {
			return err
		}
		if err := os.Lchown(escrow, uid, gid); err != nil {
			return err
		}
		if b, err := os.ReadFile(escrow); err != nil || sha256.Sum256(b) != sha256.Sum256(ageKey) {
			return errors.New("the escrowed age key does not read back identical")
		}
		volStep(stderr, "age key escrowed at %s (the source is kept)", escrow)
	}
	pkiDir := filepath.Join(mnt, "pki")
	if o.PKIFrom != "" {
		if err := volCopyTree(o.PKIFrom, pkiDir); err != nil {
			return fmt.Errorf("moving the PKI: %w", err)
		}
	} else {
		if err := os.Mkdir(pkiDir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := os.Lchown(pkiDir, uid, gid); err != nil {
			return err
		}
	}

	// ── 10. boot: crypttab, fstab, docker drop-in ──────────────────────
	volStep(stderr, "writing %s, %s and %s", cfg.Crypttab, cfg.Fstab, cfg.DropInPath())
	if err := volWriteAtomic(cfg.Crypttab, []byte(volAppendLine(crypttab, VolumeCrypttabLine(file))), 0o644); err != nil {
		return err
	}
	undo = append(undo, func() {
		if crypttabExisted {
			_ = volWriteAtomic(cfg.Crypttab, []byte(crypttab), 0o644)
		} else {
			_ = os.Remove(cfg.Crypttab)
		}
	})
	if err := volWriteAtomic(cfg.Fstab, []byte(volAppendLine(fstab, VolumeFstabLine(mnt))), 0o644); err != nil {
		return err
	}
	undo = append(undo, func() {
		if fstabExisted {
			_ = volWriteAtomic(cfg.Fstab, []byte(fstab), 0o644)
		} else {
			_ = os.Remove(cfg.Fstab)
		}
	})
	if err := os.MkdirAll(filepath.Dir(cfg.DropInPath()), 0o755); err != nil {
		return err
	}
	if err := volWriteAtomic(cfg.DropInPath(), []byte(VolumeDockerDropInBody(mnt)), 0o644); err != nil {
		return err
	}
	undo = append(undo, func() { _ = os.Remove(cfg.DropInPath()) })
	if err := volRun(nil, nil, cfg.Systemctl, "daemon-reload"); err != nil {
		return err
	}

	// ── 11. the manifest, last: claimed only once all of the above held ─
	now := cfg.Now().UTC()
	recState := "enrolled"
	if o.DeferRecoveryKey {
		recState = "deferred"
	}
	if err := volMergeManifest(cfg, map[string]any{
		"version":                      1,
		"volume_file":                  file,
		"volume_size_gib":              o.SizeGiB,
		"volume_mapper":                VolumeMapperName,
		"volume_mountpoint":            mnt,
		"volume_mount_unit":            VolumeMountUnit(mnt),
		"volume_pcrs":                  pcrs,
		"volume_secure_boot_at_create": sbKnown && sbOn,
		"volume_created_at":            now.Format(time.RFC3339),
		"volume_created_unix":          now.Unix(),
		"volume_recovery_key":          recState,
		"volume_age_key_escrow":        escrow,
		"volume_pki_dir":               pkiDir,
		"volume_operator":              o.User,
	}); err != nil {
		return err
	}
	committed = true

	// Only now is the source PKI removed: the copy is verified and the
	// volume is recorded. A failure here leaves both copies (said loudly).
	if o.PKIFrom != "" {
		if err := os.RemoveAll(o.PKIFrom); err != nil {
			fmt.Fprintf(stderr, "noo-hostd at-rest: WARNING: the PKI is on the volume but the old copy at %s could not be removed: %v — remove it by hand\n", o.PKIFrom, err)
		} else {
			volStep(stderr, "PKI moved to %s", pkiDir)
		}
	}
	volStep(stderr, "done: %s mounted at %s (PCR policy: %s). %s", mapper, mnt, pcrs, note)

	res := VolumeResult{
		OK: true, RecoveryKey: recovery, Deferred: o.DeferRecoveryKey,
		File: file, Mountpoint: mnt, Mapper: mapper, SizeGiB: o.SizeGiB,
		PCRs: pcrs, PCRNote: note, AgeEscrow: escrow, PKIDir: pkiDir,
	}
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(b))
	return err
}
