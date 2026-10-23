// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Assembled, not literal: a fixture shaped like a real secret is what
// scripts/leak-check.sh exists to find. (Names are vol-prefixed so this file
// compiles beside PR-B's atrest_linux_test.go.)
var volTestAgeKey = []byte("# public key: age1" + strings.Repeat("vol", 19) + "x\n" +
	strings.Join([]string{"AGE", "SECRET", "KEY"}, "-") + "-1" + strings.Repeat("VOLT", 14) + "VOLTVO\n")

// A recovery key in systemd's shape: 8 groups of 8 modhex characters.
var volTestRecovery = strings.Join([]string{"cbdefghi", "jklnrtuv", "cbdefghi", "jklnrtuv", "vutrnlkj", "ihgfedcb", "ccccdddd", "eeeeffff"}, "-")

// One shell stand-in per binary. Each appends "<name> <argv>" to $FAKE_LOG
// (argv only: the recovery key reaches cryptsetup on stdin and must never be
// an argument) and fails when $FAKE_FAIL names its step.
const volFakeHeader = `#!/bin/sh
name="$(basename "$0")"
echo "$name $*" >> "$FAKE_LOG"
`

var volFakes = map[string]string{
	"fallocate": volFakeHeader + `[ "$FAKE_FAIL" = fallocate ] && exit 1
: > "$3"
`,
	"cryptsetup": volFakeHeader + `case "$*" in
*luksFormat*) [ "$FAKE_FAIL" = luksFormat ] && exit 1 ;;
*"--test-passphrase --key-file=-"*)
    k="$(cat)"
    [ "$k" = "$FAKE_RECOVERY" ] || { echo "wrong passphrase" >&2; exit 2; } ;;
*"--test-passphrase --token-only"*) [ "$FAKE_FAIL" = tpmtest ] && exit 1 ;;
esac
exit 0
`,
	"systemd-cryptenroll": volFakeHeader + `case "$*" in
*--recovery-key*)
    echo "A secret recovery key has been generated for this volume:" >&2
    printf '%s\n' "$FAKE_RECOVERY"
    echo "Please save this secret recovery key at a secure location." >&2 ;;
esac
exit 0
`,
	"mkfs.ext4": volFakeHeader + `[ "$FAKE_FAIL" = mkfs ] && { echo "mkfs exploded" >&2; exit 1; }
exit 0
`,
	// Records whether the mountpoint was EMPTY when +i was set.
	"chattr": volFakeHeader + `if [ "$1" = "+i" ]; then
    if [ -z "$(ls -A "$2")" ]; then echo "chattr-empty yes" >> "$FAKE_LOG"; else echo "chattr-empty no" >> "$FAKE_LOG"; fi
fi
exit 0
`,
	"mount":     volFakeHeader + "exit 0\n",
	"umount":    volFakeHeader + "exit 0\n",
	"systemctl": volFakeHeader + "exit 0\n",
}

type volRig struct {
	cfg      VolumeConfig
	root     string // the fake filesystem root (scanned for leaks)
	dataRoot string
	log      string
	pkiSrc   string
	ageKey   string
	free     uint64
}

func newVolRig(t *testing.T, secureBoot *bool) *volRig {
	t.Helper()
	root := t.TempDir()
	bins := t.TempDir() // OUTSIDE the scanned root: the fakes carry the test key
	for name, body := range volFakes {
		if err := os.WriteFile(filepath.Join(bins, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(rel string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write := func(rel, body string, mode os.FileMode) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	dataRoot := mk("var/lib/noo")
	mk("run")
	mk("dev/mapper")
	mk("efivars")
	write("dev/tpmrm0", "", 0o600)
	write("proc/version", "Linux version 6.8.0-45-generic (buildd@ubuntu)", 0o644)
	write("etc/crypttab", "# <target name> <source device> <key file> <options>\ncryptswap /dev/sda3 /dev/urandom swap,cipher=aes-xts-plain64\n", 0o644)
	write("etc/fstab", "UUID=1234-abcd / ext4 errors=remount-ro 0 1\n", 0o644)
	// PR-B's fields, which create-volume must keep.
	write("etc/noo/at-rest.json", `{"version":1,"age_key_sealed":true,"age_key_pcrs":"7"}`+"\n", 0o644)
	if secureBoot != nil {
		v := byte(0)
		if *secureBoot {
			v = 1
		}
		write("efivars/"+volSecureBootVar, string([]byte{6, 0, 0, 0, v}), 0o644)
	}
	ageKey := write("home/user/.config/sops/age/keys.txt", string(volTestAgeKey), 0o600)
	pkiSrc := mk("home/user/noomesh/pki")
	write("home/user/noomesh/pki/ca.crt", "CA CERT\n", 0o644)
	write("home/user/noomesh/pki/ca.key", "CA KEY\n", 0o600)
	write("home/user/noomesh/pki/services/redis/service.key", "REDIS KEY\n", 0o640)

	log := filepath.Join(t.TempDir(), "calls.log")
	t.Setenv("FAKE_LOG", log)
	t.Setenv("FAKE_RECOVERY", volTestRecovery)
	t.Setenv("FAKE_FAIL", "")
	uid, gid := os.Getuid(), os.Getgid()
	r := &volRig{root: root, dataRoot: dataRoot, log: log, pkiSrc: pkiSrc, ageKey: ageKey, free: 500 << 30}
	r.cfg = VolumeConfig{
		Cryptsetup:  filepath.Join(bins, "cryptsetup"),
		Cryptenroll: filepath.Join(bins, "systemd-cryptenroll"),
		Mkfs:        filepath.Join(bins, "mkfs.ext4"),
		Chattr:      filepath.Join(bins, "chattr"),
		Mount:       filepath.Join(bins, "mount"),
		Umount:      filepath.Join(bins, "umount"),
		Fallocate:   filepath.Join(bins, "fallocate"),
		Systemctl:   filepath.Join(bins, "systemctl"),
		Crypttab:    filepath.Join(root, "etc/crypttab"),
		Fstab:       filepath.Join(root, "etc/fstab"),
		UnitDir:     filepath.Join(root, "etc/systemd/system"),
		EtcNoo:      filepath.Join(root, "etc/noo"),
		RunDir:      filepath.Join(root, "run"),
		MapperDir:   filepath.Join(root, "dev/mapper"),
		EFIVarsDir:  filepath.Join(root, "efivars"),
		TPMDevice:   filepath.Join(root, "dev/tpmrm0"),
		ProcVersion: filepath.Join(root, "proc/version"),
		RootUID:     uid, RootGID: gid,
		Geteuid:    func() int { return 0 },
		Now:        func() time.Time { return time.Unix(1_800_000_000, 0) },
		LookupUser: func(string) (int, int, error) { return uid, gid, nil },
		FreeBytes:  func(string) (uint64, error) { return r.free, nil },
		IsTmpfs:    func(string) bool { return true },
	}
	return r
}

func (r *volRig) opts() VolumeOptions {
	uid, gid := os.Getuid(), os.Getgid()
	own := func(n string) string { return n + "=" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid) }
	return VolumeOptions{
		DataRoot: r.dataRoot, SizeGiB: 50, User: "op",
		AgeKey: r.ageKey, PKIFrom: r.pkiSrc,
		Subdirs: []string{"noo-data", own("redis"), own("postgres"), "nats", own("prometheus"), own("grafana"), own("loki")},
	}
}

func (r *volRig) calls() []string {
	b, _ := os.ReadFile(r.log)
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (r *volRig) run(t *testing.T, o VolumeOptions) (VolumeResult, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := CreateVolume(r.cfg, o, &stdout, &stderr)
	var res VolumeResult
	if err == nil {
		if n := strings.Count(stdout.String(), "\n"); n != 1 {
			t.Fatalf("stdout must be exactly one JSON line, got %d:\n%s", n, stdout.String())
		}
		if jerr := json.Unmarshal(stdout.Bytes(), &res); jerr != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", jerr, stdout.String())
		}
	}
	return res, stderr.String(), err
}

func (r *volRig) manifest(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(r.cfg.ManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func volBoolp(b bool) *bool { return &b }

// index of the first call containing every needle, or -1.
func callIndex(calls []string, needles ...string) int {
	for i, c := range calls {
		ok := true
		for _, n := range needles {
			if !strings.Contains(c, n) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func TestCreateVolumeRunsTheStepsInOrder(t *testing.T) {
	r := newVolRig(t, volBoolp(true))
	res, stderr, err := r.run(t, r.opts())
	if err != nil {
		t.Fatalf("create-volume: %v\n%s", err, stderr)
	}
	calls := r.calls()
	file := filepath.Join(r.dataRoot, "state.luks2")
	mnt := filepath.Join(r.dataRoot, "state")
	steps := [][]string{
		{"fallocate -l 53687091200 " + file},
		{"cryptsetup luksFormat --type luks2 --batch-mode --key-slot 0 --key-file ", " --label noo-state " + file},
		{"systemd-cryptenroll --recovery-key --unlock-key-file="},
		{"cryptsetup open --test-passphrase --key-file=- " + file},
		{"systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 --unlock-key-file="},
		{"cryptsetup open --test-passphrase --token-only --token-type systemd-tpm2 " + file},
		{"systemd-cryptenroll --wipe-slot=0 " + file},
		{"cryptsetup open --token-only --token-type systemd-tpm2 " + file + " noo-state"},
		{"mkfs.ext4 -F -q -L noo-state /dev/mapper/noo-state"},
		{"chattr +i " + mnt},
		{"mount -t ext4 /dev/mapper/noo-state " + mnt},
		{"systemctl daemon-reload"},
	}
	last := -1
	for _, s := range steps {
		i := callIndex(calls, s...)
		if i < 0 {
			t.Fatalf("missing step %q in:\n%s", s, strings.Join(calls, "\n"))
		}
		if i <= last {
			t.Fatalf("step %q out of order (at %d, previous at %d):\n%s", s, i, last, strings.Join(calls, "\n"))
		}
		last = i
	}
	// +i was set on an EMPTY mountpoint, before the mount.
	if callIndex(calls, "chattr-empty yes") < 0 || callIndex(calls, "chattr-empty no") >= 0 {
		t.Fatalf("chattr +i must see an empty mountpoint:\n%s", strings.Join(calls, "\n"))
	}
	// The temporary key file was in the run dir and is gone.
	luks := calls[callIndex(calls, "luksFormat")]
	tmp := strings.Fields(luks[strings.Index(luks, "--key-file ")+len("--key-file "):])[0]
	if !strings.HasPrefix(tmp, r.cfg.RunDir+"/") {
		t.Errorf("the temporary key %s is not under the run dir %s", tmp, r.cfg.RunDir)
	}
	if ents, _ := os.ReadDir(r.cfg.RunDir); len(ents) != 0 {
		t.Errorf("the temporary key directory was left behind: %v", ents)
	}

	// Golden boot files.
	ct, _ := os.ReadFile(r.cfg.Crypttab)
	wantCT := "# <target name> <source device> <key file> <options>\ncryptswap /dev/sda3 /dev/urandom swap,cipher=aes-xts-plain64\n" +
		"# noomesh encrypted state volume (i10a)\nnoo-state " + file + " none luks,tpm2-device=auto,headless=true,nofail\n"
	if string(ct) != wantCT {
		t.Errorf("crypttab:\n%s\nwant:\n%s", ct, wantCT)
	}
	fst, _ := os.ReadFile(r.cfg.Fstab)
	wantFS := "UUID=1234-abcd / ext4 errors=remount-ro 0 1\n" +
		"# noomesh encrypted state volume (i10a)\n/dev/mapper/noo-state " + mnt + ` ext4 defaults,nofail,x-systemd.requires=systemd-cryptsetup@noo\x2dstate.service 0 2` + "\n"
	if string(fst) != wantFS {
		t.Errorf("fstab:\n%s\nwant:\n%s", fst, wantFS)
	}
	unit := VolumeMountUnit(mnt)
	di, _ := os.ReadFile(filepath.Join(r.cfg.UnitDir, "docker.service.d/10-noo-state.conf"))
	wantDI := "# Written by 'noo-hostd at-rest create-volume' (i10a). Do not edit.\n" +
		"# Docker starts after the encrypted state volume is mounted, when it is.\n" +
		"[Unit]\nAfter=" + unit + "\nWants=" + unit + "\n"
	if string(di) != wantDI {
		t.Errorf("docker drop-in:\n%s\nwant:\n%s", di, wantDI)
	}

	// The state layout on the (fake) mounted volume.
	for _, d := range []string{"noo-data", "redis", "postgres", "nats", "prometheus", "grafana", "loki", "pki", "keys"} {
		if st, err := os.Stat(filepath.Join(mnt, d)); err != nil || !st.IsDir() {
			t.Errorf("%s/%s was not made", mnt, d)
		}
	}
	esc, err := os.ReadFile(filepath.Join(mnt, "keys/age.txt"))
	if err != nil || !bytes.Equal(esc, volTestAgeKey) {
		t.Errorf("the age key escrow differs from the source")
	}
	if st, _ := os.Stat(filepath.Join(mnt, "keys/age.txt")); st == nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the escrow must be 0600")
	}
	if _, err := os.Stat(r.ageKey); err != nil {
		t.Errorf("the source age key must be kept (PR-B seals it): %v", err)
	}
	// The PKI was moved: identical on the volume, gone from the old place.
	for rel, want := range map[string]string{"ca.crt": "CA CERT\n", "ca.key": "CA KEY\n", "services/redis/service.key": "REDIS KEY\n"} {
		b, err := os.ReadFile(filepath.Join(mnt, "pki", rel))
		if err != nil || string(b) != want {
			t.Errorf("pki/%s not moved intact", rel)
		}
	}
	if st, _ := os.Stat(filepath.Join(mnt, "pki/services/redis/service.key")); st == nil || st.Mode().Perm() != 0o640 {
		t.Errorf("the moved key lost its mode")
	}
	if _, err := os.Stat(r.pkiSrc); !os.IsNotExist(err) {
		t.Errorf("the plaintext PKI was left at %s", r.pkiSrc)
	}

	// The manifest: merged (PR-B's fields kept), no secrets.
	m := r.manifest(t)
	if m["age_key_sealed"] != true || m["age_key_pcrs"] != "7" {
		t.Errorf("PR-B's manifest fields were dropped: %v", m)
	}
	for k, want := range map[string]any{
		"volume_file": file, "volume_mountpoint": mnt, "volume_mapper": "noo-state",
		"volume_pcrs": "7", "volume_recovery_key": "enrolled", "volume_size_gib": float64(50),
		"volume_secure_boot_at_create": true, "volume_mount_unit": unit,
		"volume_created_at": "2027-01-15T08:00:00Z", "volume_pki_dir": filepath.Join(mnt, "pki"),
	} {
		if m[k] != want {
			t.Errorf("manifest %s = %v, want %v", k, m[k], want)
		}
	}

	// The result line carries the key; stderr never does.
	if res.RecoveryKey != volTestRecovery || res.Deferred || res.PCRs != "7" || res.Mountpoint != mnt {
		t.Errorf("result: %+v", res)
	}
	if strings.Contains(stderr, volTestRecovery) {
		t.Errorf("the recovery key reached stderr:\n%s", stderr)
	}
}

func TestCreateVolumeIsTPMOnlyWhenSecureBootIsOffOrUnknown(t *testing.T) {
	for name, sb := range map[string]*bool{"off": volBoolp(false), "unknown": nil} {
		t.Run(name, func(t *testing.T) {
			r := newVolRig(t, sb)
			res, stderr, err := r.run(t, r.opts())
			if err != nil {
				t.Fatalf("create-volume: %v\n%s", err, stderr)
			}
			calls := r.calls()
			i := callIndex(calls, "systemd-cryptenroll --tpm2-device=auto")
			if i < 0 {
				t.Fatalf("no TPM enrollment:\n%s", strings.Join(calls, "\n"))
			}
			// An EXPLICIT empty list: absent, systemd binds PCR 7.
			if !strings.Contains(calls[i], " --tpm2-pcrs= --unlock-key-file=") || strings.Contains(calls[i], "--tpm2-pcrs=7") {
				t.Errorf("Secure Boot %s must enroll TPM-only (--tpm2-pcrs=): %q", name, calls[i])
			}
			for _, c := range calls {
				for _, bad := range []string{"--tpm2-pcrs=0", "--tpm2-pcrs=2", "+0", "0+"} {
					if strings.Contains(c, "cryptenroll") && strings.Contains(c, bad) {
						t.Errorf("a firmware PCR was bound: %q", c)
					}
				}
			}
			if r.manifest(t)["volume_pcrs"] != "none" || res.PCRs != "none" {
				t.Errorf("policy not recorded as none")
			}
			if !strings.Contains(res.PCRNote, "live-USB") {
				t.Errorf("the TPM-only note must say a live-USB boot is not blocked: %q", res.PCRNote)
			}
		})
	}
}

// The recovery key exists in memory and on the result line only: after a run
// no file anywhere under the fake root holds it, and no argv carried it.
func TestTheRecoveryKeyIsNeverWrittenToAFile(t *testing.T) {
	r := newVolRig(t, volBoolp(true))
	res, stderr, err := r.run(t, r.opts())
	if err != nil {
		t.Fatalf("create-volume: %v\n%s", err, stderr)
	}
	if res.RecoveryKey != volTestRecovery {
		t.Fatalf("the run did not produce the key: %+v", res)
	}
	scanned := 0
	err = filepath.WalkDir(r.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		scanned++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(volTestRecovery)) || bytes.Contains(b, []byte("cbdefghi-jklnrtuv")) {
			t.Errorf("the recovery key was written to %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 8 {
		t.Fatalf("scanned only %d files — the walk found too little to mean anything", scanned)
	}
	for _, c := range r.calls() {
		if strings.Contains(c, volTestRecovery) {
			t.Errorf("the recovery key was an argument: %q", c)
		}
	}
	// And the fake really checked it on stdin (a wrong key fails the run).
	r2 := newVolRig(t, volBoolp(true))
	t.Setenv("FAKE_RECOVERY", volTestRecovery) // printed by cryptenroll…
	r2.cfg.Cryptsetup = writeWrongKeyCryptsetup(t)
	if _, _, err := r2.run(t, r2.opts()); err == nil || !strings.Contains(err.Error(), "recovery key did not open") {
		t.Fatalf("a recovery key that does not open the volume must fail the run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r2.dataRoot, "state.luks2")); !os.IsNotExist(err) {
		t.Errorf("the failed run left its backing file")
	}
}

// A cryptsetup whose --test-passphrase rejects every key.
func writeWrongKeyCryptsetup(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "cryptsetup")
	body := volFakeHeader + `case "$*" in *"--test-passphrase --key-file=-"*) cat >/dev/null; exit 2 ;; esac
exit 0
`
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCreateVolumeRefusesBeforeTouchingAnything(t *testing.T) {
	cases := map[string]struct {
		mutate func(r *volRig, o *VolumeOptions)
		want   string
	}{
		"non-root": {func(r *volRig, o *VolumeOptions) { r.cfg.Geteuid = func() int { return 1000 } }, "needs root"},
		"wsl": {func(r *volRig, o *VolumeOptions) {
			_ = os.WriteFile(r.cfg.ProcVersion, []byte("Linux version 6.6.87.2-microsoft-standard-WSL2"), 0o644)
		}, "WSL2"},
		"no tpm":               {func(r *volRig, o *VolumeOptions) { _ = os.Remove(r.cfg.TPMDevice) }, "no TPM resource manager"},
		"insufficient space":   {func(r *volRig, o *VolumeOptions) { r.free = 54 << 30 }, "not enough space"},
		"space without margin": {func(r *volRig, o *VolumeOptions) { r.free = (50 << 30) + (4 << 30) }, "margin"},
		"run dir not tmpfs":    {func(r *volRig, o *VolumeOptions) { r.cfg.IsTmpfs = func(string) bool { return false } }, "not tmpfs"},
		"path with a space":    {func(r *volRig, o *VolumeOptions) { o.DataRoot = "/srv/my data" }, "fstab and crypttab"},
		"relative path":        {func(r *volRig, o *VolumeOptions) { o.DataRoot = "var/lib/noo" }, "absolute"},
		"backing file exists": {func(r *volRig, o *VolumeOptions) {
			_ = os.WriteFile(filepath.Join(o.DataRoot, "state.luks2"), nil, 0o600)
		}, "already exists"},
		"mapping open": {func(r *volRig, o *VolumeOptions) {
			_ = os.WriteFile(filepath.Join(r.cfg.MapperDir, "noo-state"), nil, 0o600)
		}, "mapping is open"},
		"mountpoint holds data": {func(r *volRig, o *VolumeOptions) {
			_ = os.MkdirAll(filepath.Join(o.DataRoot, "state", "postgres"), 0o755)
		}, "not empty"},
		"crypttab has it": {func(r *volRig, o *VolumeOptions) {
			_ = os.WriteFile(r.cfg.Crypttab, []byte("noo-state /x none luks\n"), 0o644)
		}, "already has a noo-state line"},
		"manifest has a volume": {func(r *volRig, o *VolumeOptions) {
			_ = os.WriteFile(r.cfg.ManifestPath(), []byte(`{"volume_file":"/old/state.luks2"}`), 0o644)
		}, "already records a volume"},
		"firmware pcrs":     {func(r *volRig, o *VolumeOptions) { o.PCRs = "0+2+7" }, "never bound"},
		"not a pki dir":     {func(r *volRig, o *VolumeOptions) { _ = os.Remove(filepath.Join(r.pkiSrc, "ca.crt")) }, "not a PKI directory"},
		"age key is a link": {func(r *volRig, o *VolumeOptions) { l := r.ageKey + ".lnk"; _ = os.Symlink(r.ageKey, l); o.AgeKey = l }, "not a regular file"},
		"bad subdir":        {func(r *volRig, o *VolumeOptions) { o.Subdirs = []string{"../etc"} }, "plain lowercase name"},
		"no user":           {func(r *volRig, o *VolumeOptions) { o.User = "" }, "--user is required"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := newVolRig(t, volBoolp(true))
			o := r.opts()
			c.mutate(r, &o)
			before, _ := os.ReadFile(r.cfg.Crypttab)
			_, _, err := r.run(t, o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a refusal containing %q, got %v", c.want, err)
			}
			if calls := r.calls(); len(calls) != 0 {
				t.Errorf("a refusal ran binaries:\n%s", strings.Join(calls, "\n"))
			}
			if name != "backing file exists" {
				if _, err := os.Stat(filepath.Join(r.dataRoot, "state.luks2")); !os.IsNotExist(err) {
					t.Errorf("a refusal made the backing file")
				}
			}
			after, _ := os.ReadFile(r.cfg.Crypttab)
			if !bytes.Equal(before, after) {
				t.Errorf("a refusal changed crypttab")
			}
		})
	}
}

// A step that fails part-way undoes what this run made and claims nothing.
func TestCreateVolumeUndoesAFailedRun(t *testing.T) {
	r := newVolRig(t, volBoolp(true))
	t.Setenv("FAKE_FAIL", "mkfs")
	ctBefore, _ := os.ReadFile(r.cfg.Crypttab)
	fsBefore, _ := os.ReadFile(r.cfg.Fstab)
	_, stderr, err := r.run(t, r.opts())
	if err == nil || !strings.Contains(err.Error(), "mkfs") {
		t.Fatalf("want the mkfs failure, got %v", err)
	}
	if strings.Contains(err.Error(), volTestRecovery) || strings.Contains(stderr, volTestRecovery) {
		t.Errorf("the failure leaked the recovery key")
	}
	calls := r.calls()
	if callIndex(calls, "cryptsetup close noo-state") < 0 {
		t.Errorf("the opened mapping was not closed:\n%s", strings.Join(calls, "\n"))
	}
	if callIndex(calls, "mount -t ext4") >= 0 {
		t.Errorf("mounted after a failed mkfs")
	}
	if _, err := os.Stat(filepath.Join(r.dataRoot, "state.luks2")); !os.IsNotExist(err) {
		t.Errorf("the backing file was left")
	}
	ct, _ := os.ReadFile(r.cfg.Crypttab)
	fst, _ := os.ReadFile(r.cfg.Fstab)
	if !bytes.Equal(ct, ctBefore) || !bytes.Equal(fst, fsBefore) {
		t.Errorf("crypttab/fstab changed by a failed run")
	}
	m := r.manifest(t)
	if _, ok := m["volume_file"]; ok {
		t.Errorf("a failed run recorded a volume: %v", m)
	}
	if m["age_key_sealed"] != true {
		t.Errorf("PR-B's fields were lost")
	}
	if _, err := os.Stat(r.pkiSrc); err != nil {
		t.Errorf("a failed run removed the PKI: %v", err)
	}
	if ents, _ := os.ReadDir(r.cfg.RunDir); len(ents) != 0 {
		t.Errorf("the temporary key directory was left: %v", ents)
	}
	// A failure AFTER the mount also unmounts and lifts +i.
	r2 := newVolRig(t, volBoolp(true))
	t.Setenv("FAKE_FAIL", "")
	r2.cfg.Systemctl = filepath.Join(t.TempDir(), "systemctl")
	_ = os.WriteFile(r2.cfg.Systemctl, []byte(volFakeHeader+"exit 1\n"), 0o755)
	if _, _, err := r2.run(t, r2.opts()); err == nil {
		t.Fatal("a failed daemon-reload must fail the run")
	}
	c2 := r2.calls()
	if !(callIndex(c2, "umount") > callIndex(c2, "systemctl daemon-reload") && callIndex(c2, "chattr -i") > callIndex(c2, "umount") && callIndex(c2, "cryptsetup close") > callIndex(c2, "chattr -i")) {
		t.Errorf("undo order must be umount, chattr -i, close:\n%s", strings.Join(c2, "\n"))
	}
	ct2, _ := os.ReadFile(r2.cfg.Crypttab)
	if strings.Contains(string(ct2), "noo-state") {
		t.Errorf("crypttab kept the line after a failed run")
	}
	if _, err := os.Stat(r2.cfg.DropInPath()); !os.IsNotExist(err) {
		t.Errorf("the docker drop-in was left")
	}
}

func TestDeferredRecoveryKeyEnrollsTheTPMOnly(t *testing.T) {
	r := newVolRig(t, volBoolp(true))
	o := r.opts()
	o.DeferRecoveryKey = true
	res, stderr, err := r.run(t, o)
	if err != nil {
		t.Fatalf("create-volume: %v\n%s", err, stderr)
	}
	calls := r.calls()
	if callIndex(calls, "--recovery-key") >= 0 || callIndex(calls, "--key-file=-") >= 0 {
		t.Errorf("deferred must enroll no recovery key:\n%s", strings.Join(calls, "\n"))
	}
	if callIndex(calls, "--tpm2-device=auto") < 0 || callIndex(calls, "--wipe-slot=0") < 0 {
		t.Errorf("the TPM must still be enrolled and the temp slot wiped")
	}
	if res.RecoveryKey != "" || !res.Deferred {
		t.Errorf("result: %+v", res)
	}
	if r.manifest(t)["volume_recovery_key"] != "deferred" {
		t.Errorf("the manifest must say deferred")
	}
}

func TestVolumeMountUnitIsSystemdEscaped(t *testing.T) {
	for in, want := range map[string]string{
		"/var/lib/noo/state":          "var-lib-noo-state.mount",
		"/srv/my-data/state":          `srv-my\x2ddata-state.mount`,
		"/media/alice/data/noo/state": "media-alice-data-noo-state.mount",
		"/srv/.hidden/state":          `srv-\x2ehidden-state.mount`,
	} {
		if got := VolumeMountUnit(in); got != want {
			t.Errorf("VolumeMountUnit(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTheDockerDropInNeverRequiresTheVolume(t *testing.T) {
	body := VolumeDockerDropInBody("/var/lib/noo/state")
	if strings.Contains(body, "Requires") || strings.Contains(body, "BindsTo") {
		t.Fatalf("a closed volume must not take docker down:\n%s", body)
	}
	if !strings.Contains(body, "After=var-lib-noo-state.mount") || !strings.Contains(body, "Wants=var-lib-noo-state.mount") {
		t.Fatalf("drop-in: %s", body)
	}
}

func TestRecoveryKeyParseWantsExactlyOne(t *testing.T) {
	if k, err := volParseRecoveryKey([]byte(volTestRecovery + "\n")); err != nil || k != volTestRecovery {
		t.Fatalf("parse: %q %v", k, err)
	}
	for _, bad := range []string{"", "no key here\n", volTestRecovery + " " + volTestRecovery, "abcdefgh-" + volTestRecovery[9:]} {
		if _, err := volParseRecoveryKey([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCreateVolumeFlagsParse(t *testing.T) {
	var errBuf bytes.Buffer
	o, err := parseCreateVolumeArgs([]string{"--data-root", "/var/lib/noo", "--size", "64", "--user", "op",
		"--subdir", "redis=65532:65532", "--subdir", "noo-data", "--age-key", "/home/user/k", "--defer-recovery-key"}, &errBuf)
	if err != nil {
		t.Fatal(err)
	}
	if o.DataRoot != "/var/lib/noo" || o.SizeGiB != 64 || o.User != "op" || !o.DeferRecoveryKey || o.PCRs != "auto" ||
		len(o.Subdirs) != 2 || o.Subdirs[0] != "redis=65532:65532" || o.AgeKey != "/home/user/k" {
		t.Fatalf("parsed: %+v", o)
	}
	if _, err := parseCreateVolumeArgs([]string{"--size", "64", "stray"}, &errBuf); err == nil {
		t.Fatal("a stray argument must be refused")
	}
	if !IsAtRestVolumeVerb([]string{"create-volume"}) || IsAtRestVolumeVerb([]string{"seal-age-key"}) || IsAtRestVolumeVerb(nil) {
		t.Fatal("IsAtRestVolumeVerb")
	}
}
