// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Assembled, not literal: a fixture shaped like a real age key is what
// scripts/leak-check.sh exists to find.
var testAgeKey = []byte("# created: 2026-01-01T00:00:00Z\n# public key: age1" + strings.Repeat("test", 14) + "te\n" +
	strings.Join([]string{"AGE", "SECRET", "KEY"}, "-") + "-1" + strings.Repeat("TEST", 16) + "TE\n")

// fakeCreds is a systemd-creds stand-in: it records argv (one line per call)
// and "encrypts" by prefixing a marker, "decrypts" by stripping it (to stdout
// when the output is "-"). FAKE_CREDS_CORRUPT=1 makes decrypt return other
// bytes, which seal-age-key must refuse.
const fakeCreds = `#!/bin/sh
echo "$*" >> "$FAKE_LOG"
verb="$1"; shift
args=""
for a in "$@"; do case "$a" in --*) ;; *) args="$args $a" ;; esac; done
set -- $args
case "$verb" in
encrypt)
    if [ "$1" = "-" ]; then { echo FAKECRED; cat; } > "$2"; else { echo FAKECRED; cat "$1"; } > "$2"; fi ;;
decrypt)
    if [ -n "$FAKE_CREDS_CORRUPT" ]; then body="not the key"; else body="$(tail -n +2 "$1")"; fi
    if [ "$2" = "-" ] || [ -z "$2" ]; then printf '%s\n' "$body"; else printf '%s\n' "$body" > "$2"; fi ;;
*) exit 2 ;;
esac
`

const fakeSystemctl = `#!/bin/sh
echo "systemctl $*" >> "$FAKE_LOG"
`

type sealRig struct {
	cfg     AtRestConfig
	keyPath string
	log     string
	root    string
}

func newSealRig(t *testing.T, secureBoot *bool) *sealRig {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	for _, d := range []string{bin, filepath.Join(root, "efivars"), filepath.Join(root, "home")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, body string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bin, "systemd-creds"), fakeCreds, 0o755)
	write(filepath.Join(bin, "systemctl"), fakeSystemctl, 0o755)
	write(filepath.Join(root, "tpmrm0"), "", 0o600)
	write(filepath.Join(root, "version"), "Linux version 6.8.0-generic (buildd@ubuntu)", 0o644)
	if secureBoot != nil {
		v := byte(0)
		if *secureBoot {
			v = 1
		}
		write(filepath.Join(root, "efivars", secureBootVar), string([]byte{6, 0, 0, 0, v}), 0o644)
	}
	keyPath := filepath.Join(root, "home", "keys.txt")
	if err := os.WriteFile(keyPath, testAgeKey, 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "calls.log")
	t.Setenv("FAKE_LOG", log)
	uid, gid := os.Getuid(), os.Getgid()
	return &sealRig{
		root: root, keyPath: keyPath, log: log,
		cfg: AtRestConfig{
			SystemdCreds: filepath.Join(bin, "systemd-creds"),
			Systemctl:    filepath.Join(bin, "systemctl"),
			InstallBin:   "install",
			UnitDir:      filepath.Join(root, "etc/systemd/system"),
			SealedDir:    filepath.Join(root, "var/lib/noo/sealed"),
			EtcNoo:       filepath.Join(root, "etc/noo"),
			RunKeysDir:   filepath.Join(root, "run/noo/keys"),
			EFIVarsDir:   filepath.Join(root, "efivars"),
			TPMDevice:    filepath.Join(root, "tpmrm0"),
			ProcVersion:  filepath.Join(root, "version"),
			RootUID:      uid, RootGID: gid,
			Geteuid:    func() int { return 0 },
			Now:        func() time.Time { return time.Unix(1_800_000_000, 0) },
			LookupUser: func(string) (int, int, error) { return uid, gid, nil },
		},
	}
}

func (r *sealRig) calls(t *testing.T) string {
	b, _ := os.ReadFile(r.log)
	return string(b)
}

func boolp(b bool) *bool { return &b }

func encryptLine(t *testing.T, calls string) string {
	for _, l := range strings.Split(calls, "\n") {
		if strings.HasPrefix(l, "encrypt ") {
			return l
		}
	}
	t.Fatalf("no encrypt call recorded:\n%s", calls)
	return ""
}

func TestSealBindsPCR7WhenSecureBootIsOn(t *testing.T) {
	r := newSealRig(t, boolp(true))
	var out bytes.Buffer
	if err := SealAgeKey(r.cfg, SealOptions{User: "op", KeyPath: r.keyPath}, &out); err != nil {
		t.Fatalf("seal: %v", err)
	}
	calls := r.calls(t)
	enc := encryptLine(t, calls)
	for _, want := range []string{"--with-key=tpm2", "--tpm2-pcrs=7", "--name=noo-age-key"} {
		if !strings.Contains(enc, want) {
			t.Errorf("encrypt argv lacks %s: %q", want, enc)
		}
	}
	if !strings.Contains(calls, "systemctl daemon-reload") || !strings.Contains(calls, "systemctl enable noo-unseal.service") {
		t.Errorf("unit not reloaded+enabled:\n%s", calls)
	}
	// The credential: 0600 in a 0700 dir; it is not the plaintext.
	st, err := os.Stat(r.cfg.CredPath())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cred mode: %v %v", st, err)
	}
	if d, _ := os.Stat(r.cfg.SealedDir); d.Mode().Perm() != 0o700 {
		t.Errorf("sealed dir mode %o", d.Mode().Perm())
	}
	if _, err := os.Stat(r.cfg.CredPath() + ".new"); err == nil {
		t.Error("temp credential left behind")
	}
	// The plaintext is kept (finalize removes it, not seal).
	if b, _ := os.ReadFile(r.keyPath); !bytes.Equal(b, testAgeKey) {
		t.Error("seal touched the plaintext key")
	}
	// The manifest: sealed, PCR 7, Secure Boot on, and no secret in it.
	b, err := os.ReadFile(r.cfg.ManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("SECRET-KEY")) {
		t.Fatal("the manifest holds the secret key")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["age_key_sealed"] != true || m["age_key_pcrs"] != "7" || m["secure_boot_at_seal"] != true {
		t.Errorf("manifest: %v", m)
	}
	if m["age_key_sealed_unix"].(float64) != 1_800_000_000 || m["operator"] != "op" {
		t.Errorf("manifest: %v", m)
	}
	if !strings.HasPrefix(m["age_key_public"].(string), "age1") {
		t.Errorf("public key not recorded: %v", m["age_key_public"])
	}
}

func TestSealIsTPMOnlyWhenSecureBootIsOff(t *testing.T) {
	for name, sb := range map[string]*bool{"off": boolp(false), "unreadable": nil} {
		t.Run(name, func(t *testing.T) {
			r := newSealRig(t, sb)
			if err := SealAgeKey(r.cfg, SealOptions{User: "op", KeyPath: r.keyPath}, &bytes.Buffer{}); err != nil {
				t.Fatalf("seal: %v", err)
			}
			enc := encryptLine(t, r.calls(t))
			// Explicitly EMPTY: systemd-creds binds PCR 7 when the flag is absent.
			if !strings.Contains(enc, "--tpm2-pcrs= ") || strings.Contains(enc, "--tpm2-pcrs=7") {
				t.Errorf("want an explicit empty PCR list, got %q", enc)
			}
			b, _ := os.ReadFile(r.cfg.ManifestPath())
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			if m["age_key_pcrs"] != "none" || m["secure_boot_at_seal"] != false {
				t.Errorf("manifest: %v", m)
			}
		})
	}
}

func TestSealRefusesWhenTheTestDecryptDiffers(t *testing.T) {
	r := newSealRig(t, boolp(true))
	t.Setenv("FAKE_CREDS_CORRUPT", "1")
	err := SealAgeKey(r.cfg, SealOptions{User: "op", KeyPath: r.keyPath}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "sha256 differs") {
		t.Fatalf("want a sha256 refusal, got %v", err)
	}
	for _, p := range []string{r.cfg.CredPath(), r.cfg.CredPath() + ".new", r.cfg.UnitPath(), r.cfg.ManifestPath()} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s exists after a refused seal", p)
		}
	}
	if strings.Contains(r.calls(t), "systemctl") {
		t.Error("systemctl ran after a refused seal")
	}
}

func TestSealRefusals(t *testing.T) {
	cases := map[string]func(r *sealRig) (SealOptions, string){
		"not root": func(r *sealRig) (SealOptions, string) {
			r.cfg.Geteuid = func() int { return 1000 }
			return SealOptions{User: "op", KeyPath: r.keyPath}, "needs root"
		},
		"wsl": func(r *sealRig) (SealOptions, string) {
			_ = os.WriteFile(r.cfg.ProcVersion, []byte("Linux version 6.6.87.2-microsoft-standard-WSL2"), 0o644)
			return SealOptions{User: "op", KeyPath: r.keyPath}, "not supported here"
		},
		"no tpm": func(r *sealRig) (SealOptions, string) {
			r.cfg.TPMDevice = filepath.Join(r.root, "absent")
			return SealOptions{User: "op", KeyPath: r.keyPath}, "no TPM"
		},
		"firmware pcr": func(r *sealRig) (SealOptions, string) {
			return SealOptions{User: "op", KeyPath: r.keyPath, PCRs: "0+7"}, "never bound"
		},
		"symlinked key": func(r *sealRig) (SealOptions, string) {
			l := filepath.Join(r.root, "home", "link.txt")
			_ = os.Symlink(r.keyPath, l)
			return SealOptions{User: "op", KeyPath: l}, "symlink"
		},
		"not a key": func(r *sealRig) (SealOptions, string) {
			_ = os.WriteFile(r.keyPath, []byte("hello\n"), 0o600)
			return SealOptions{User: "op", KeyPath: r.keyPath}, "no age secret key"
		},
		"relative key": func(r *sealRig) (SealOptions, string) {
			return SealOptions{User: "op", KeyPath: "keys.txt"}, "absolute"
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := newSealRig(t, boolp(true))
			o, want := setup(r)
			err := SealAgeKey(r.cfg, o, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("want %q, got %v", want, err)
			}
			if _, err := os.Stat(r.cfg.ManifestPath()); err == nil {
				t.Error("a refused seal wrote the manifest")
			}
		})
	}
}

func TestDecidePCRsNeverBindsFirmwarePCRs(t *testing.T) {
	for _, req := range []string{"0", "2", "0,7", "7+2", "all"} {
		if _, _, err := DecidePCRs(req, true, true); err == nil {
			t.Errorf("%q accepted", req)
		}
	}
	if p, _, _ := DecidePCRs("auto", true, true); p != "7" {
		t.Errorf("auto+SB on = %s", p)
	}
	if p, _, _ := DecidePCRs("auto", true, false); p != "none" {
		t.Errorf("auto with an unreadable SB var = %s (unknown is never 'on')", p)
	}
}

// The rendered unit's ExecStart lines, run with a fake CREDENTIALS_DIRECTORY,
// leave the key at the runtime path, 0400, owned by the operator, in a 0700
// dir under a 0755 parent the operator can traverse.
func TestUnsealUnitExecStartPutsTheKeyInPlace(t *testing.T) {
	r := newSealRig(t, boolp(true))
	if err := SealAgeKey(r.cfg, SealOptions{User: "op", KeyPath: r.keyPath}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(r.cfg.UnitPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Type=oneshot", "RemainAfterExit=yes", "Before=docker.service", "WantedBy=multi-user.target",
		"LoadCredentialEncrypted=noo-age-key:" + r.cfg.CredPath(),
	} {
		if !strings.Contains(string(unit), want+"\n") {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	credDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(credDir, AtRestCredName), testAgeKey, 0o400); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(unit), "\n") {
		cmdline, ok := strings.CutPrefix(line, "ExecStart=")
		if !ok {
			continue
		}
		n++
		cmdline = strings.ReplaceAll(cmdline, "${CREDENTIALS_DIRECTORY}", credDir)
		argv := strings.Fields(cmdline)
		if !filepath.IsAbs(argv[0]) {
			t.Fatalf("ExecStart binary not absolute: %q", argv[0])
		}
		if out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", cmdline, err, out)
		}
	}
	if n != 3 {
		t.Fatalf("want 3 ExecStart lines, got %d", n)
	}
	st, err := os.Stat(r.cfg.RuntimePath())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o400 {
		t.Errorf("runtime key mode %o, want 0400", st.Mode().Perm())
	}
	if int(st.Sys().(*syscall.Stat_t).Uid) != os.Getuid() {
		t.Errorf("runtime key not owned by the operator uid")
	}
	if b, _ := os.ReadFile(r.cfg.RuntimePath()); !bytes.Equal(b, testAgeKey) {
		t.Error("runtime key content differs")
	}
	if d, _ := os.Stat(r.cfg.RunKeysDir); d.Mode().Perm() != 0o700 {
		t.Errorf("keys dir mode %o, want 0700", d.Mode().Perm())
	}
	if d, _ := os.Stat(filepath.Dir(r.cfg.RunKeysDir)); d.Mode().Perm() != 0o755 {
		t.Errorf("run dir mode %o, want 0755", d.Mode().Perm())
	}
}

func TestRenderUnitRefusesUnsafePaths(t *testing.T) {
	v := UnitVars{InstallBin: "/usr/bin/install", CredPath: "/var/lib/noo/sealed/age-key.cred", RunDir: "/run/noo",
		RunKeysDir: "/run/noo/keys", RuntimePath: "/run/noo/keys/age.txt", CredName: AtRestCredName}
	if _, err := RenderUnsealUnit(v); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"relative/x", "/a b", "/a%n", "/a$X", "/a;b"} {
		w := v
		w.RuntimePath = bad
		if _, err := RenderUnsealUnit(w); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// A manifest written by another verb (PR-C's volume) survives a reseal; one
// that does not parse is never overwritten.
func TestManifestMergeKeepsOtherFieldsAndRefusesGarbage(t *testing.T) {
	r := newSealRig(t, boolp(true))
	_ = os.MkdirAll(r.cfg.EtcNoo, 0o755)
	_ = os.WriteFile(r.cfg.ManifestPath(), []byte(`{"volume_encrypted": true}`), 0o644)
	if err := SealAgeKey(r.cfg, SealOptions{User: "op", KeyPath: r.keyPath}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(r.cfg.ManifestPath())
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["volume_encrypted"] != true || m["age_key_sealed"] != true {
		t.Errorf("merge lost a field: %v", m)
	}
	_ = os.WriteFile(r.cfg.ManifestPath(), []byte("{not json"), 0o644)
	if err := SealAgeKey(r.cfg, SealOptions{User: "op", KeyPath: r.keyPath}, &bytes.Buffer{}); err == nil {
		t.Fatal("a garbage manifest was overwritten")
	}
	if b, _ := os.ReadFile(r.cfg.ManifestPath()); string(b) != "{not json" {
		t.Error("garbage manifest changed")
	}
}
