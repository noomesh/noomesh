// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A second recovery key in systemd's shape (the rotation's NEW key).
var volTestRecovery2 = strings.Join([]string{"dddddddd", "eeeeeeee", "ffffffff", "gggggggg", "hhhhhhhh", "iiiiiiii", "jjjjjjjj", "kkkkkkkk"}, "-")

// Slot-aware stand-ins: $FAKE_STATE/slots holds "N type" lines. They log
// argv only; the new key is only ever in $FAKE_RECOVERY_NEW (the
// environment) and arrives at cryptsetup on stdin.
var recFakes = map[string]string{
	"systemd-cryptenroll": volFakeHeader + `slots="$FAKE_STATE/slots"
next() { awk 'BEGIN{m=-1} {if ($1>m) m=$1} END{print m+1}' "$slots"; }
case "$*" in
*--recovery-key*)
    if [ -e "$FAKE_STATE/tpm_broken" ]; then echo "TPM2 unseal failed" >&2; exit 1; fi
    n="$(next)"; echo "$n recovery" >> "$slots"
    printf '%s\n' "$FAKE_RECOVERY_NEW" ;;
*--wipe-slot=tpm2*)
    if [ -n "$FAKE_FAIL" ] && [ "$FAKE_FAIL" = reenroll ]; then echo "no" >&2; exit 1; fi
    grep -v ' tpm2$' "$slots" > "$slots.n"; mv "$slots.n" "$slots"
    n="$(next)"; echo "$n tpm2" >> "$slots" ;;
*--wipe-slot=*)
    for a in "$@"; do case "$a" in --wipe-slot=*) w="${a#--wipe-slot=}";; esac; done
    grep -v "^$w " "$slots" > "$slots.n"; mv "$slots.n" "$slots" ;;
*)
    echo "SLOT TYPE"; awk '{printf "%4d %s\n", $1, $2}' "$slots" ;;
esac
exit 0
`,
	"cryptsetup": volFakeHeader + `case "$*" in
status*) printf '/dev/mapper/noo-state is active and is in use.\n  type:    LUKS2\n  device:  /dev/loop7\n  loop:    /x/state.luks2\n' ;;
*"--test-passphrase --key-file=-"*)
    k="$(cat)"
    [ "$k" = "$FAKE_RECOVERY_NEW" ] || { echo "wrong passphrase" >&2; exit 2; } ;;
esac
exit 0
`,
}

type recRig struct {
	*volRig
	state string
	file  string
}

func newRecRig(t *testing.T, secureBoot *bool, slots string) *recRig {
	t.Helper()
	r := &recRig{volRig: newVolRig(t, secureBoot)}
	bins := t.TempDir()
	for name, body := range recFakes {
		if err := os.WriteFile(filepath.Join(bins, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r.cfg.Cryptenroll = filepath.Join(bins, "systemd-cryptenroll")
	r.cfg.Cryptsetup = filepath.Join(bins, "cryptsetup")
	r.state = t.TempDir() // outside the scanned root, like the fakes
	if err := os.WriteFile(filepath.Join(r.state, "slots"), []byte(slots), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_STATE", r.state)
	t.Setenv("FAKE_RECOVERY_NEW", volTestRecovery2)
	r.file = filepath.Join(r.dataRoot, VolumeFileName)
	if err := os.WriteFile(r.file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r.setManifest(t, map[string]any{
		"version": 1, "volume_file": r.file, "volume_mountpoint": filepath.Join(r.dataRoot, "state"),
		"volume_pcrs": "7", "volume_recovery_key": "enrolled", "volume_operator": "op", "age_key_sealed": true,
		"volume_age_key_escrow": "/var/lib/noo/state/keys/age.txt",
	})
	return r
}

func (r *recRig) setManifest(t *testing.T, m map[string]any) {
	t.Helper()
	b, _ := json.Marshal(m)
	if err := os.WriteFile(r.cfg.ManifestPath(), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (r *recRig) manifest(t *testing.T) map[string]any {
	t.Helper()
	m, err := volReadManifest(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (r *recRig) slots(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(r.state, "slots"))
	return strings.Join(strings.Fields(string(b)), " ")
}

func (r *recRig) open(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.cfg.MapperDir, VolumeMapperName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func indexOfCall(calls []string, sub string) int {
	for i, c := range calls {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

func TestRecoveryKeyIsEnrolledAndConfirmedBeforeTheOldSlotIsWiped(t *testing.T) {
	r := newRecRig(t, nil, "1 recovery\n2 tpm2\n")
	var out, errb bytes.Buffer
	if err := EnrollRecoveryKey(r.cfg, &out, &errb); err != nil {
		t.Fatalf("enroll: %v\n%s", err, errb.String())
	}
	var got RecoveryEnrolled
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.RecoveryKey != volTestRecovery2 {
		t.Fatalf("enroll output: %v %q", err, out.String())
	}
	if got.NewSlot != 3 || len(got.OldSlots) != 1 || got.OldSlots[0] != 1 {
		t.Fatalf("slots: new=%d old=%v", got.NewSlot, got.OldSlots)
	}
	// Phase one wipes NOTHING: the old key still works until the person confirms.
	calls := r.calls()
	if indexOfCall(calls, "--wipe-slot") >= 0 {
		t.Fatalf("phase one wiped a slot:\n%s", strings.Join(calls, "\n"))
	}
	enroll := indexOfCall(calls, "--recovery-key --unlock-tpm2-device=auto")
	proof := indexOfCall(calls, "--test-passphrase --key-file=-")
	if enroll < 0 || proof < enroll {
		t.Fatalf("the new key must be enrolled, then proven to open the volume:\n%s", strings.Join(calls, "\n"))
	}
	if r.slots(t) != "1 recovery 2 tpm2 3 recovery" {
		t.Fatalf("slots after enroll: %s", r.slots(t))
	}
	// Phase two (after the person retyped the key): the old slot goes.
	if err := FinishRecoveryKey(r.cfg, got.NewSlot, got.OldSlots, &out, &errb); err != nil {
		t.Fatalf("finish: %v", err)
	}
	calls = r.calls()
	if w := indexOfCall(calls, "--wipe-slot=1"); w < proof {
		t.Fatalf("the old slot was wiped before the new key was confirmed:\n%s", strings.Join(calls, "\n"))
	}
	if r.slots(t) != "2 tpm2 3 recovery" {
		t.Fatalf("slots after finish: %s", r.slots(t))
	}
	if m := r.manifest(t); m["volume_recovery_key"] != "enrolled" || m["volume_recovery_rotated_at"] == nil || m["age_key_sealed"] != true {
		t.Fatalf("manifest: %v", m)
	}
}

func TestRecoveryKeyOnADeferredVolumeHasNothingToWipe(t *testing.T) {
	r := newRecRig(t, nil, "0 tpm2\n")
	r.setManifest(t, map[string]any{"version": 1, "volume_file": r.file, "volume_recovery_key": "deferred"})
	var out, errb bytes.Buffer
	if err := EnrollRecoveryKey(r.cfg, &out, &errb); err != nil {
		t.Fatal(err)
	}
	var got RecoveryEnrolled
	_ = json.Unmarshal(out.Bytes(), &got)
	if len(got.OldSlots) != 0 || got.NewSlot != 1 {
		t.Fatalf("%+v", got)
	}
	if r.manifest(t)["volume_recovery_key"] != "enrolled" {
		t.Fatal("the manifest must now say enrolled")
	}
}

func TestRecoveryKeyNeverWipesTheLastUnlockMethodOrANonRecoverySlot(t *testing.T) {
	r := newRecRig(t, nil, "0 password\n1 recovery\n2 tpm2\n3 recovery\n")
	var out, errb bytes.Buffer
	for name, c := range map[string]struct {
		newSlot int
		old     []int
	}{
		"the TPM slot":          {3, []int{2}},
		"the password slot":     {3, []int{0}},
		"the new slot itself":   {3, []int{3}},
		"a new slot that isn't": {2, []int{1}}, // slot 2 is the TPM, not a recovery key
		"a slot that is absent": {3, []int{9}},
	} {
		if err := FinishRecoveryKey(r.cfg, c.newSlot, c.old, &out, &errb); err == nil {
			t.Errorf("%s: wipe was not refused", name)
		}
	}
	if indexOfCall(r.calls(), "--wipe-slot") >= 0 {
		t.Fatalf("a refused finish still wiped:\n%s", strings.Join(r.calls(), "\n"))
	}
	if r.slots(t) != "0 password 1 recovery 2 tpm2 3 recovery" {
		t.Fatalf("slots changed: %s", r.slots(t))
	}
}

func TestRecoveryKeyWhenTheTPMDoesNotUnlockExplainsAndChangesNothing(t *testing.T) {
	r := newRecRig(t, nil, "1 recovery\n2 tpm2\n")
	if err := os.WriteFile(filepath.Join(r.state, "tpm_broken"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	err := EnrollRecoveryKey(r.cfg, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "reenroll") || !strings.Contains(err.Error(), "at-rest-recovery.md") {
		t.Fatalf("want an explanation naming reenroll and the runbook, got %v", err)
	}
	if out.Len() != 0 || r.slots(t) != "1 recovery 2 tpm2" {
		t.Fatal("a failed enroll printed or changed something")
	}
}

func TestTheNewRecoveryKeyIsNeverWrittenToAFileArgOrLog(t *testing.T) {
	r := newRecRig(t, nil, "1 recovery\n2 tpm2\n")
	var out, errb bytes.Buffer
	if err := EnrollRecoveryKey(r.cfg, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if err := FinishRecoveryKey(r.cfg, 3, []int{1}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errb.String(), volTestRecovery2) || strings.Contains(strings.Join(r.calls(), "\n"), volTestRecovery2) {
		t.Fatal("the key is in stderr or the call log (argv)")
	}
	if strings.Count(out.String(), volTestRecovery2) != 1 {
		t.Fatal("the key must appear exactly once, in the one stdout line")
	}
	scan := func(dir string) {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(volTestRecovery2)) {
				t.Errorf("the recovery key leaked into %s", p)
			}
			return nil
		})
	}
	scan(r.root)
	scan(r.state)
	scan(filepath.Dir(r.log))
}

func TestReenrollBindsPCR7OnlyWithSecureBootOn(t *testing.T) {
	on, off := true, false
	for _, c := range []struct {
		name string
		sb   *bool
		want string
		pcrs string
	}{
		{"secure boot on", &on, "--wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7 /dev/loop7", "7"},
		{"secure boot off", &off, "--wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs= /dev/loop7", "none"},
		{"secure boot unreadable", nil, "--wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs= /dev/loop7", "none"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRecRig(t, c.sb, "1 recovery\n5 tpm2\n")
			r.setManifest(t, map[string]any{"version": 1, "volume_file": r.file, "volume_pcrs": "7"})
			r.open(t)
			var out, errb bytes.Buffer
			if err := Reenroll(r.cfg, ReenrollOptions{PCRs: "auto"}, &out, &errb); err != nil {
				t.Fatalf("%v\n%s", err, errb.String())
			}
			calls := r.calls()
			if i := indexOfCall(calls, c.want); i < 0 {
				t.Fatalf("want a cryptenroll call ending %q:\n%s", c.want, strings.Join(calls, "\n"))
			}
			if indexOfCall(calls, "--tpm2-pcrs=0") >= 0 || indexOfCall(calls, "--tpm2-pcrs=2") >= 0 {
				t.Fatal("a firmware PCR was bound")
			}
			if indexOfCall(calls, "--test-passphrase --token-only --token-type systemd-tpm2 /dev/loop7") < 0 {
				t.Fatal("the new TPM enrollment was not proven to unlock the volume")
			}
			if m := r.manifest(t); m["volume_pcrs"] != c.pcrs || m["volume_secure_boot_at_create"] != (c.sb != nil && *c.sb) {
				t.Fatalf("manifest: %v", m)
			}
			if r.slots(t) != "1 recovery 2 tpm2" { // stale slot 5 gone, a new TPM slot in
				t.Fatalf("the recovery key must survive a TPM re-enrollment: %s", r.slots(t))
			}
		})
	}
}

func TestReenrollRefusesFirmwarePCRs(t *testing.T) {
	on := true
	r := newRecRig(t, &on, "1 recovery\n2 tpm2\n")
	r.open(t)
	for _, p := range []string{"0", "2", "0,2", "7,0", "firmware"} {
		var out, errb bytes.Buffer
		err := Reenroll(r.cfg, ReenrollOptions{PCRs: p}, &out, &errb)
		if err == nil || !strings.Contains(err.Error(), "never bound") {
			t.Errorf("--pcrs %q: want a refusal naming the firmware PCRs, got %v", p, err)
		}
	}
	if indexOfCall(r.calls(), "--wipe-slot") >= 0 {
		t.Fatal("a refused PCR policy still touched the keyslots")
	}
}

func TestReenrollWhenTheVolumeIsNotOpenExplainsHowToOpenIt(t *testing.T) {
	on := true
	r := newRecRig(t, &on, "1 recovery\n2 tpm2\n")
	var out, errb bytes.Buffer
	err := Reenroll(r.cfg, ReenrollOptions{PCRs: "auto"}, &out, &errb)
	if err == nil {
		t.Fatal("reenroll ran on a closed volume")
	}
	for _, want := range []string{"not open", "cryptsetup open " + r.file + " noo-state", "RECOVERY key", "at-rest-recovery.md"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the explanation lacks %q: %v", want, err)
		}
	}
	if indexOfCall(r.calls(), "systemd-cryptenroll") >= 0 {
		t.Fatal("systemd-cryptenroll ran against a closed volume")
	}
	if r.slots(t) != "1 recovery 2 tpm2" {
		t.Fatal("slots changed")
	}
}

func TestReenrollResealsTheAgeKeyWhenSealedAndPrintsTheCommandWhenItCannot(t *testing.T) {
	on := true
	run := func(t *testing.T, reseal func(user, key, pcrs string, _ interface{}) error, sealed bool) (ReenrollResult, map[string]any) {
		r := newRecRig(t, &on, "1 recovery\n2 tpm2\n")
		r.setManifest(t, map[string]any{
			"version": 1, "volume_file": r.file, "volume_pcrs": "none", "volume_operator": "op",
			"volume_age_key_escrow": "/var/lib/noo/state/keys/age.txt",
			"age_key_sealed":        sealed, "age_key_pcrs": "none",
		})
		r.open(t)
		old := volReseal
		defer func() { volReseal = old }()
		volReseal = func(user, key, pcrs string, _ io.Writer) error { return reseal(user, key, pcrs, nil) }
		var out, errb bytes.Buffer
		if err := Reenroll(r.cfg, ReenrollOptions{PCRs: "auto"}, &out, &errb); err != nil {
			t.Fatal(err)
		}
		var res ReenrollResult
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return res, r.manifest(t)
	}
	var gotUser, gotKey, gotPCRs string
	res, m := run(t, func(u, k, p string, _ interface{}) error { gotUser, gotKey, gotPCRs = u, k, p; return nil }, true)
	if gotUser != "op" || gotKey != "/var/lib/noo/state/keys/age.txt" || gotPCRs != "7" || !res.AgeKeyResealed {
		t.Fatalf("reseal: %s %s %s %+v", gotUser, gotKey, gotPCRs, res)
	}
	if m["age_key_pcrs"] != "7" || m["secure_boot_at_seal"] != true {
		t.Fatalf("the manifest's age key fields were not updated: %v", m)
	}
	res, m = run(t, func(string, string, string, interface{}) error { return errResealAbsent }, true)
	if res.AgeKeyResealed || !strings.Contains(res.ResealCommand, "sudo /usr/local/bin/noo-hostd at-rest seal-age-key --user op --key /var/lib/noo/state/keys/age.txt --pcrs 7") {
		t.Fatalf("want the exact reseal command, got %+v", res)
	}
	if m["age_key_pcrs"] != "none" {
		t.Fatal("the age key fields must not claim a reseal that did not happen")
	}
	called := false
	res, _ = run(t, func(string, string, string, interface{}) error { called = true; return nil }, false)
	if called || res.AgeKeySealed || res.AgeKeyResealed {
		t.Fatalf("an unsealed age key must not be resealed: %+v", res)
	}
}

func TestRecoveryVerbsAreDispatchedAndFlagsParse(t *testing.T) {
	if !IsAtRestRecoveryVerb([]string{"reenroll"}) || !IsAtRestRecoveryVerb([]string{"recovery-key", "--finish"}) || IsAtRestRecoveryVerb([]string{"create-volume"}) {
		t.Fatal("dispatch")
	}
	if got := volParseSlots("SLOT TYPE\n   1 recovery\n   2 tpm2\n"); len(got) != 2 || got[1].Type != "tpm2" {
		t.Fatalf("%v", got)
	}
}
