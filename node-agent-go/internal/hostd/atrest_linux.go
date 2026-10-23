// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

// `noo-hostd at-rest …` — the root half of i10a (sensitive controller state
// sealed to the TPM). On a controller noo-hostd is a USER unit; these verbs
// are the one place it runs as root, and only because a person typed
// `sudo /usr/local/bin/noo-hostd at-rest …` (the CLI prints that line when
// it cannot run sudo itself). There is no sudoers entry and no spool op:
// nothing reaches these verbs except an interactive root shell.
//
// PR-B ships `seal-age-key` and `unseal-status`. The dispatcher is shaped so
// later work adds `create-volume` (PR-C) and `recovery-key` / `reenroll`
// (PR-E) as further verbs without touching these.
//
// What seal-age-key does, in order — nothing is claimed until the end:
//  1. refuses unless root, not WSL2, a TPM resource manager is present, and
//     the key file is a regular file holding an age secret key;
//  2. picks the PCR policy (operator decision 2026-10-23): PCR 7 iff Secure
//     Boot is on, TPM-only otherwise; never the firmware PCRs 0/2, so a BIOS
//     update cannot lock the box out;
//  3. `systemd-creds encrypt --with-key=tpm2` the key (read from stdin, so
//     what is sealed is exactly the bytes checked here) to a temp file next
//     to the final credential, in a 0700 root dir, mode 0600;
//  4. test-decrypts it IN MEMORY (stdout of `systemd-creds decrypt`, never a
//     file) and compares sha256 with the source — a mismatch installs nothing;
//  5. renames it into place, writes noo-unseal.service (LoadCredentialEncrypted
//     → /run/noo/keys/age.txt 0400, owned by the operator), daemon-reload +
//     enable;
//  6. writes /etc/noo/at-rest.json (no secrets: paths, the PCR policy, the
//     Secure Boot state at sealing, when, for whom, the PUBLIC key).
// The plaintext key is NOT deleted: that is `noo security at-rest finalize`,
// after a real reboot proved the unit unseals unattended.
//
// Test seam: every binary and directory is overridable through the
// environment (NOO_SYSTEMD_CREDS, NOO_SYSTEMCTL, NOO_INSTALL_BIN,
// NOO_UNIT_DIR, NOO_SEALED_DIR, NOO_ETC_NOO, NOO_RUN_KEYS_DIR,
// NOO_EFIVARS_DIR, NOO_TPM_DEVICE), in the style of NOO_SECRET_CHOWN_CMD.
// sudo's env_reset strips them from an operator's shell, so in production
// they are only ever root's own choice; an active override is printed.

import (
	"bytes"
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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"
)

const (
	// AtRestCredName is the credential's name: what LoadCredentialEncrypted
	// exposes under $CREDENTIALS_DIRECTORY and what --name binds into the
	// sealed blob (a credential renamed on disk will not decrypt as another).
	AtRestCredName = "noo-age-key"
	// AtRestUnitName is the root system unit that unseals at boot.
	AtRestUnitName = "noo-unseal.service"
	// AtRestManifestName is the file under /etc/noo that records what was
	// sealed. It holds no secret.
	AtRestManifestName = "at-rest.json"
	// AtRestCredFile is the sealed key's file name inside the sealed dir.
	AtRestCredFile = "age-key.cred"
	// AtRestRuntimeFile is the unsealed key's name inside the run-keys dir.
	AtRestRuntimeFile = "age.txt"

	secureBootVar  = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	maxAgeKeyBytes = 64 << 10
)

// AtRestConfig is every host fact and binary the at-rest verbs touch.
type AtRestConfig struct {
	SystemdCreds string // systemd-creds
	Systemctl    string // systemctl
	InstallBin   string // install(1), written into the unit's ExecStart
	UnitDir      string // /etc/systemd/system
	SealedDir    string // /var/lib/noo/sealed
	EtcNoo       string // /etc/noo
	RunKeysDir   string // /run/noo/keys (its parent is made 0755 root)
	EFIVarsDir   string // /sys/firmware/efi/efivars
	TPMDevice    string // /dev/tpmrm0
	ProcVersion  string // /proc/version (the WSL2 check)

	// RootUID/RootGID own the sealed dir, the credential and /run/noo.
	// 0 in production; the test's own ids in tests.
	RootUID, RootGID int

	Geteuid    func() int
	Now        func() time.Time
	LookupUser func(name string) (uid, gid int, err error)

	// Overrides lists the env overrides in effect, printed by the verbs.
	Overrides []string
}

// AtRestConfigFromEnv is the production configuration.
func AtRestConfigFromEnv() AtRestConfig {
	c := AtRestConfig{
		SystemdCreds: "systemd-creds",
		Systemctl:    "systemctl",
		InstallBin:   "",
		UnitDir:      "/etc/systemd/system",
		SealedDir:    "/var/lib/noo/sealed",
		EtcNoo:       "/etc/noo",
		RunKeysDir:   "/run/noo/keys",
		EFIVarsDir:   "/sys/firmware/efi/efivars",
		TPMDevice:    "/dev/tpmrm0",
		ProcVersion:  "/proc/version",
		Geteuid:      os.Geteuid,
		Now:          time.Now,
		LookupUser:   lookupUser,
	}
	for _, o := range []struct {
		env string
		dst *string
	}{
		{"NOO_SYSTEMD_CREDS", &c.SystemdCreds},
		{"NOO_SYSTEMCTL", &c.Systemctl},
		{"NOO_INSTALL_BIN", &c.InstallBin},
		{"NOO_UNIT_DIR", &c.UnitDir},
		{"NOO_SEALED_DIR", &c.SealedDir},
		{"NOO_ETC_NOO", &c.EtcNoo},
		{"NOO_RUN_KEYS_DIR", &c.RunKeysDir},
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

func lookupUser(name string) (int, int, error) {
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

// CredPath, RuntimePath and ManifestPath are the three locations the rest of
// the system (CLI, lib-secrets.sh, verify) reads.
func (c AtRestConfig) CredPath() string     { return filepath.Join(c.SealedDir, AtRestCredFile) }
func (c AtRestConfig) RuntimePath() string  { return filepath.Join(c.RunKeysDir, AtRestRuntimeFile) }
func (c AtRestConfig) ManifestPath() string { return filepath.Join(c.EtcNoo, AtRestManifestName) }
func (c AtRestConfig) UnitPath() string     { return filepath.Join(c.UnitDir, AtRestUnitName) }

// RunAtRest dispatches `noo-hostd at-rest <verb> …`.
func RunAtRest(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		atRestUsage(stderr)
		return errors.New("at-rest: a verb is required")
	}
	cfg := AtRestConfigFromEnv()
	for _, o := range cfg.Overrides {
		fmt.Fprintf(stderr, "noo-hostd at-rest: override in effect: %s\n", o)
	}
	switch args[0] {
	case "seal-age-key":
		fset := flag.NewFlagSet("seal-age-key", flag.ContinueOnError)
		fset.SetOutput(stderr)
		u := fset.String("user", "", "the operator account that will own the unsealed key")
		key := fset.String("key", "", "the plaintext age key file to seal (kept; finalize removes it)")
		pcrs := fset.String("pcrs", "auto", "PCR policy: 7, none, or auto (7 iff Secure Boot is on)")
		if err := fset.Parse(args[1:]); err != nil {
			return err
		}
		if fset.NArg() != 0 {
			return fmt.Errorf("seal-age-key: unexpected argument %q", fset.Arg(0))
		}
		return SealAgeKey(cfg, SealOptions{User: *u, KeyPath: *key, PCRs: *pcrs}, stdout)
	case "unseal-status":
		fset := flag.NewFlagSet("unseal-status", flag.ContinueOnError)
		fset.SetOutput(stderr)
		asJSON := fset.Bool("json", false, "print the status as JSON")
		if err := fset.Parse(args[1:]); err != nil {
			return err
		}
		return UnsealStatus(cfg, *asJSON, stdout)
	case "help", "--help", "-h":
		atRestUsage(stdout)
		return nil
	default:
		atRestUsage(stderr)
		return fmt.Errorf("at-rest: unknown verb %q", args[0])
	}
}

func atRestUsage(w io.Writer) {
	fmt.Fprint(w, `noo-hostd at-rest — seal controller secrets to this machine's TPM (i10a; root)

  sudo noo-hostd at-rest seal-age-key --user <operator> --key <path> [--pcrs 7|none|auto]
        Seal the SOPS age key with systemd-creds (tpm2) and install
        noo-unseal.service, which unseals it into RAM (/run/noo/keys/age.txt)
        at every boot. The plaintext key is kept: 'noo security at-rest
        finalize' removes it after a reboot proved the unseal.

  noo-hostd at-rest unseal-status [--json]
        Report what is sealed, the PCR policy, Secure Boot now vs at sealing,
        and whether the key is unsealed on this boot.
`)
}

// SealOptions are the seal-age-key arguments.
type SealOptions struct {
	User    string
	KeyPath string
	PCRs    string // "auto" (or ""), "7", "none"
}

// isWSL reports whether /proc/version names a Microsoft kernel.
func isWSL(procVersion string) bool {
	b, err := os.ReadFile(procVersion)
	return err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft")
}

// SecureBootState reads the SecureBoot EFI variable: 4 attribute bytes, then
// one data byte (1 = on). known=false when it cannot be read (legacy BIOS
// boot, no efivarfs) — treated as off by the PCR policy, never as on.
func SecureBootState(efivarsDir string) (on, known bool) {
	b, err := os.ReadFile(filepath.Join(efivarsDir, secureBootVar))
	if err != nil || len(b) < 5 {
		return false, false
	}
	return b[4] == 1, true
}

// DecidePCRs maps the requested policy and the Secure Boot state to the
// --tpm2-pcrs value. "7" binds PCR 7; "none" binds no PCR. Anything else is
// refused: the firmware PCRs (0/2) change on a BIOS update and would lock
// the box out, and a policy nobody decided is not one to guess.
func DecidePCRs(requested string, sbOn, sbKnown bool) (pcrs string, note string, err error) {
	switch strings.TrimSpace(requested) {
	case "", "auto":
		if sbKnown && sbOn {
			return "7", "Secure Boot is on: bound to PCR 7 (a changed boot chain will not unseal).", nil
		}
		return "none", "Secure Boot is off (or unreadable): TPM-only. The drive alone does not decrypt elsewhere, " +
			"but a live-USB boot of THIS machine is not blocked from unsealing.", nil
	case "7":
		if !(sbKnown && sbOn) {
			return "7", "PCR 7 bound with Secure Boot OFF: turning Secure Boot on later will stop the unseal until resealed.", nil
		}
		return "7", "Secure Boot is on: bound to PCR 7.", nil
	case "none":
		if sbKnown && sbOn {
			return "none", "Secure Boot is on but --pcrs none was asked: TPM-only, a changed boot chain is NOT detected.", nil
		}
		return "none", "TPM-only: a live-USB boot of this machine is not blocked from unsealing.", nil
	default:
		return "", "", fmt.Errorf("--pcrs %q refused: only 7 or none (auto picks 7 iff Secure Boot is on); "+
			"the firmware PCRs 0/2 are never bound, so a BIOS update cannot lock this machine out", requested)
	}
}

// pcrsFlag is the systemd-creds argument for a policy. "none" is passed as an
// EXPLICIT empty list: systemd-creds binds PCR 7 when --tpm2-pcrs is absent,
// which would silently bind a box whose policy is TPM-only.
func pcrsFlag(pcrs string) string {
	if pcrs == "7" {
		return "--tpm2-pcrs=7"
	}
	return "--tpm2-pcrs="
}

// agePublicKey returns the "# public key: age1…" comment age-keygen writes,
// or "" — public, so it may go in the manifest; finalize compares it.
func agePublicKey(key []byte) string {
	for _, l := range strings.Split(string(key), "\n") {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "# public key:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// readAgeKey reads the plaintext key with the guards the root process owes
// a path an operator typed: a regular file (not a symlink — after finalize
// keys.txt IS one, and resealing through it is a different operation), small,
// holding an age secret key, owned by the operator or root.
func readAgeKey(path string, operatorUID, rootUID int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("--key is required (the plaintext age key, e.g. ~/.config/sops/age/keys.txt)")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("--key %q must be an absolute path", path)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the key: %w", err)
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink (already finalized?) — seal from a regular key file", path)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() == 0 || st.Size() > maxAgeKeyBytes {
		return nil, fmt.Errorf("%s is %d bytes — not an age key file", path, st.Size())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if int(sys.Uid) != operatorUID && int(sys.Uid) != rootUID {
			return nil, fmt.Errorf("%s is owned by uid %d, neither the operator (%d) nor root", path, sys.Uid, operatorUID)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the key: %w", err)
	}
	if !bytes.Contains(b, []byte("AGE-SECRET-KEY-1")) {
		return nil, fmt.Errorf("%s holds no age secret key", path)
	}
	return b, nil
}

// resolveBin makes a configured binary name absolute (systemd wants absolute
// ExecStart paths, and a root process should not chase a relative PATH hit).
func resolveBin(name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found: %w", name, err)
	}
	return filepath.Abs(p)
}

// ensureRootDir makes dir exist as a real directory (not a symlink), owned by
// root, with exactly mode.
func ensureRootDir(dir string, mode os.FileMode, rootUID, rootGID int) error {
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if st.Mode()&fs.ModeSymlink != 0 || !st.IsDir() {
		return fmt.Errorf("%s is not a directory (a symlink?) — refusing to seal into it", dir)
	}
	if err := os.Lchown(dir, rootUID, rootGID); err != nil {
		return fmt.Errorf("cannot chown %s: %w", dir, err)
	}
	return os.Chmod(dir, mode)
}

// writeFileAtomic writes via a temp file in the same dir and renames.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".new"
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

func runQuiet(name string, args ...string) error {
	var errBuf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(errBuf.String()))
	}
	return nil
}

// UnitVars are the values the unseal unit is rendered from.
type UnitVars struct {
	InstallBin       string
	CredPath         string
	RunDir           string // parent of RunKeysDir, made 0755 root
	RunKeysDir       string
	RuntimePath      string
	CredName         string
	UID, GID         int
	RootUID, RootGID int
}

const unsealUnitTmpl = `# Written by 'noo-hostd at-rest seal-age-key' (i10a). Do not edit: reseal to change it.
[Unit]
Description=noomesh: unseal the SOPS age key from the TPM into RAM
Documentation=https://github.com/noomesh/noomesh/blob/dev/docs/security/secrets.md
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
LoadCredentialEncrypted={{.CredName}}:{{.CredPath}}
UMask=0077
NoNewPrivileges=yes
PrivateNetwork=yes
ExecStart={{.InstallBin}} -d -m 0755 -o {{.RootUID}} -g {{.RootGID}} {{.RunDir}}
ExecStart={{.InstallBin}} -d -m 0700 -o {{.UID}} -g {{.GID}} {{.RunKeysDir}}
ExecStart={{.InstallBin}} -m 0400 -o {{.UID}} -g {{.GID}} ${CREDENTIALS_DIRECTORY}/{{.CredName}} {{.RuntimePath}}

[Install]
WantedBy=multi-user.target
`

// RenderUnsealUnit renders noo-unseal.service. Plain install(1) does the
// copy: no product binary runs as root at boot.
func RenderUnsealUnit(v UnitVars) (string, error) {
	for _, p := range []string{v.InstallBin, v.CredPath, v.RunDir, v.RunKeysDir, v.RuntimePath} {
		if p == "" || !filepath.IsAbs(p) || strings.ContainsAny(p, " \t\n\"'\\$%;") {
			return "", fmt.Errorf("unit path %q must be absolute with no spaces, quotes or specifiers", p)
		}
	}
	t, err := template.New("unit").Parse(unsealUnitTmpl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Execute(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// SealAgeKey is `seal-age-key`.
func SealAgeKey(cfg AtRestConfig, o SealOptions, out io.Writer) error {
	if cfg.Geteuid() != 0 {
		return errors.New("seal-age-key needs root: sudo /usr/local/bin/noo-hostd at-rest seal-age-key --user <you> --key <path>")
	}
	if isWSL(cfg.ProcVersion) {
		return errors.New("not supported here: WSL2 has no TPM this host can seal to (i10a covers Linux controllers only)")
	}
	if _, err := os.Stat(cfg.TPMDevice); err != nil {
		return fmt.Errorf("no TPM resource manager at %s — enable the firmware TPM (Intel PTT / AMD fTPM) or a vTPM, then retry", cfg.TPMDevice)
	}
	if o.User == "" {
		return errors.New("--user is required: the operator account that will own the unsealed key")
	}
	uid, gid, err := cfg.LookupUser(o.User)
	if err != nil {
		return err
	}
	key, err := readAgeKey(o.KeyPath, uid, cfg.RootUID)
	if err != nil {
		return err
	}
	sbOn, sbKnown := SecureBootState(cfg.EFIVarsDir)
	pcrs, note, err := DecidePCRs(o.PCRs, sbOn, sbKnown)
	if err != nil {
		return err
	}
	creds, err := resolveBin(cfg.SystemdCreds)
	if err != nil {
		return err
	}
	systemctl, err := resolveBin(cfg.Systemctl)
	if err != nil {
		return err
	}
	installBin := cfg.InstallBin
	if installBin == "" {
		installBin = "install"
	}
	if installBin, err = resolveBin(installBin); err != nil {
		return err
	}

	// 1. Seal to a temp credential next to the final one.
	if err := ensureRootDir(cfg.SealedDir, 0o700, cfg.RootUID, cfg.RootGID); err != nil {
		return err
	}
	final := cfg.CredPath()
	tmp := final + ".new"
	_ = os.Remove(tmp)
	enc := exec.Command(creds, "encrypt", "--with-key=tpm2", pcrsFlag(pcrs), "--name="+AtRestCredName, "-", tmp)
	enc.Stdin = bytes.NewReader(key)
	var encErr bytes.Buffer
	enc.Stdout = io.Discard
	enc.Stderr = &encErr
	if err := enc.Run(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("systemd-creds encrypt failed: %v: %s", err, strings.TrimSpace(encErr.String()))
	}
	if err := os.Lchown(tmp, cfg.RootUID, cfg.RootGID); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	// 2. Test-decrypt in memory and compare with the source.
	dec := exec.Command(creds, "decrypt", "--name="+AtRestCredName, tmp, "-")
	var plain, decErr bytes.Buffer
	dec.Stdout = &plain
	dec.Stderr = &decErr
	if err := dec.Run(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("test-decrypt failed, nothing installed: %v: %s", err, strings.TrimSpace(decErr.String()))
	}
	want, got := sha256.Sum256(key), sha256.Sum256(plain.Bytes())
	plain.Reset()
	if want != got {
		_ = os.Remove(tmp)
		return errors.New("test-decrypt did not return the key (sha256 differs) — nothing installed")
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	// 3. The boot unit.
	unit, err := RenderUnsealUnit(UnitVars{
		InstallBin: installBin, CredPath: final, CredName: AtRestCredName,
		RunDir: filepath.Dir(cfg.RunKeysDir), RunKeysDir: cfg.RunKeysDir, RuntimePath: cfg.RuntimePath(),
		UID: uid, GID: gid, RootUID: cfg.RootUID, RootGID: cfg.RootGID,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.UnitDir, 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.UnitPath(), []byte(unit), 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", cfg.UnitPath(), err)
	}
	if err := runQuiet(systemctl, "daemon-reload"); err != nil {
		return err
	}
	if err := runQuiet(systemctl, "enable", AtRestUnitName); err != nil {
		return err
	}

	// 4. The manifest, last: "sealed" is claimed only once all of the above held.
	now := cfg.Now().UTC()
	if err := mergeManifest(cfg, map[string]any{
		"version":             1,
		"age_key_sealed":      true,
		"age_key_cred":        final,
		"age_key_runtime":     cfg.RuntimePath(),
		"age_key_public":      agePublicKey(key),
		"age_key_source":      o.KeyPath,
		"age_key_pcrs":        pcrs,
		"secure_boot_at_seal": sbKnown && sbOn,
		"secure_boot_known":   sbKnown,
		"age_key_sealed_at":   now.Format(time.RFC3339),
		"age_key_sealed_unix": now.Unix(),
		"operator":            o.User,
		"operator_uid":        uid,
		"unseal_unit":         AtRestUnitName,
	}); err != nil {
		return err
	}

	fmt.Fprintf(out, "sealed: %s (PCR policy: %s)\n", final, pcrs)
	fmt.Fprintf(out, "  %s\n", note)
	fmt.Fprintf(out, "unit: %s enabled — unseals into %s (0400, %s) at every boot, before docker\n", cfg.UnitPath(), cfg.RuntimePath(), o.User)
	fmt.Fprintf(out, "manifest: %s\n", cfg.ManifestPath())
	fmt.Fprintf(out, "the plaintext key is KEPT at %s until finalize.\n", o.KeyPath)
	fmt.Fprintln(out, "next: reboot, then run: noo security at-rest finalize")
	return nil
}

// mergeManifest read-modify-writes /etc/noo/at-rest.json, keeping fields
// other verbs own (PR-C's volume). A manifest that does not parse is not
// overwritten: it may be the only record of a volume.
func mergeManifest(cfg AtRestConfig, set map[string]any) error {
	if err := os.MkdirAll(cfg.EtcNoo, 0o755); err != nil {
		return err
	}
	m := map[string]any{}
	if b, err := os.ReadFile(cfg.ManifestPath()); err == nil {
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("%s does not parse (%v) — move it aside and reseal; it is not overwritten", cfg.ManifestPath(), err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for k, v := range set {
		m[k] = v
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(cfg.ManifestPath(), append(b, '\n'), 0o644)
}

// UnsealStatus is `unseal-status`: read-only, works without root (the
// sealed dir is 0700 root, so the credential reads as "unknown" there).
func UnsealStatus(cfg AtRestConfig, asJSON bool, out io.Writer) error {
	st := map[string]any{"manifest": cfg.ManifestPath()}
	m := map[string]any{}
	if b, err := os.ReadFile(cfg.ManifestPath()); err == nil {
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("%s does not parse: %w", cfg.ManifestPath(), err)
		}
	}
	sealed, _ := m["age_key_sealed"].(bool)
	st["sealed"] = sealed
	for _, k := range []string{"age_key_pcrs", "secure_boot_at_seal", "age_key_sealed_at", "operator"} {
		if v, ok := m[k]; ok {
			st[k] = v
		}
	}
	switch _, err := os.Stat(cfg.CredPath()); {
	case err == nil:
		st["cred"] = "present"
	case errors.Is(err, fs.ErrNotExist):
		st["cred"] = "missing"
	default:
		st["cred"] = "unknown (root only)"
	}
	if fi, err := os.Stat(cfg.RuntimePath()); err == nil {
		st["runtime_key"] = fmt.Sprintf("present, mode %04o", fi.Mode().Perm())
	} else {
		st["runtime_key"] = "absent"
	}
	sbOn, sbKnown := SecureBootState(cfg.EFIVarsDir)
	if sbKnown {
		st["secure_boot_now"] = sbOn
	} else {
		st["secure_boot_now"] = "unknown"
	}
	if sys, err := resolveBin(cfg.Systemctl); err == nil {
		for _, q := range []string{"is-enabled", "is-active"} {
			o, _ := exec.Command(sys, q, AtRestUnitName).Output()
			st["unit_"+strings.ReplaceAll(q, "-", "_")] = strings.TrimSpace(string(o))
		}
	}
	if asJSON {
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Fprintln(out, string(b))
		return nil
	}
	keys := make([]string, 0, len(st))
	for k := range st {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(out, "%-20s %v\n", k, st[k])
	}
	return nil
}
