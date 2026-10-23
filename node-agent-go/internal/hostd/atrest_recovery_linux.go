// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//go:build linux

package hostd

// `noo-hostd at-rest recovery-key` and `reenroll` — the root half of i10a
// PR-E, for the TPM-unlocked LUKS2 state volume PR-C made.
//
// recovery-key (two phases, so the OLD key is only wiped once the person has
// the NEW one):
//
//	sudo noo-hostd at-rest recovery-key
//	    unlocks with the TPM, enrolls a NEW recovery key, proves it opens the
//	    volume (key on stdin, never an argument), records the slot numbers,
//	    and prints ONE JSON line carrying the key. The old recovery slots are
//	    still there. This is also how a --defer-recovery-key volume gets its
//	    first recovery key (there is no old slot to wipe).
//	sudo noo-hostd at-rest recovery-key --finish --new-slot N [--old-slots a,b]
//	    run by the CLI only after the person retyped the new key: wipes the
//	    old recovery slots by NUMBER (never `--wipe-slot=recovery`, which
//	    would take the new one too), refusing to wipe anything that is not a
//	    recovery slot, the new slot itself, or the last unlock method.
//
// reenroll: after a firmware or Secure Boot change, drop the stale TPM slot
// and enroll the TPM again against the CURRENT boot chain
// (`--wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=<7|"">`: PCR 7 with
// Secure Boot on, an explicit empty list with it off, never the firmware
// PCRs 0/2 — operator decision 2026-10-23), on the device `cryptsetup status
// noo-state` names. The volume must already be open (with the recovery key,
// if the TPM no longer unseals it); systemd-cryptenroll asks the person for
// that key itself, on their terminal. Then it reseals the age key when the
// manifest says it is sealed, and updates the manifest's PCR fields.
//
// The recovery key is never written to a file, never an argument, never in a
// log: it lives in memory between systemd-cryptenroll's stdout and this
// process's stdout.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IsAtRestRecoveryVerb reports whether `noo-hostd at-rest <verb>` is one of
// this file's.
func IsAtRestRecoveryVerb(args []string) bool {
	return len(args) > 0 && (args[0] == "recovery-key" || args[0] == "reenroll")
}

// RunAtRestRecovery dispatches `recovery-key` and `reenroll`.
func RunAtRestRecovery(args []string, stdout, stderr io.Writer) error {
	cfg := VolumeConfigFromEnv()
	for _, o := range cfg.Overrides {
		fmt.Fprintf(stderr, "noo-hostd at-rest: override in effect: %s\n", o)
	}
	switch args[0] {
	case "recovery-key":
		fset := flag.NewFlagSet("recovery-key", flag.ContinueOnError)
		fset.SetOutput(stderr)
		finish := fset.Bool("finish", false, "wipe the old recovery slots once the new key is confirmed")
		newSlot := fset.Int("new-slot", -1, "with --finish: the slot of the new recovery key")
		oldSlots := fset.String("old-slots", "", "with --finish: comma-separated old recovery slots to wipe")
		if err := fset.Parse(args[1:]); err != nil {
			return err
		}
		if fset.NArg() != 0 {
			return fmt.Errorf("recovery-key: unexpected argument %q", fset.Arg(0))
		}
		if !*finish {
			return EnrollRecoveryKey(cfg, stdout, stderr)
		}
		var old []int
		for _, f := range strings.Split(*oldSlots, ",") {
			if f = strings.TrimSpace(f); f == "" {
				continue
			}
			n, err := strconv.Atoi(f)
			if err != nil || n < 0 {
				return fmt.Errorf("--old-slots: %q is not a slot number", f)
			}
			old = append(old, n)
		}
		return FinishRecoveryKey(cfg, *newSlot, old, stdout, stderr)
	default: // reenroll
		fset := flag.NewFlagSet("reenroll", flag.ContinueOnError)
		fset.SetOutput(stderr)
		pcrs := fset.String("pcrs", "auto", "PCR policy: 7, none, or auto (7 iff Secure Boot is on)")
		if err := fset.Parse(args[1:]); err != nil {
			return err
		}
		if fset.NArg() != 0 {
			return fmt.Errorf("reenroll: unexpected argument %q", fset.Arg(0))
		}
		return Reenroll(cfg, ReenrollOptions{PCRs: *pcrs}, stdout, stderr)
	}
}

// ── keyslots ────────────────────────────────────────────────────────────

// VolumeSlot is one row of `systemd-cryptenroll <device>`.
type VolumeSlot struct {
	N    int
	Type string // password, recovery, tpm2, fido2, pkcs11
}

var volSlotLine = regexp.MustCompile(`^\s*(\d+)\s+([a-z0-9-]+)\s*$`)

// volParseSlots reads the SLOT/TYPE table; anything else is ignored.
func volParseSlots(out string) []VolumeSlot {
	var s []VolumeSlot
	for _, l := range strings.Split(out, "\n") {
		if m := volSlotLine.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			s = append(s, VolumeSlot{N: n, Type: m[2]})
		}
	}
	return s
}

func volListSlots(cfg VolumeConfig, file string) ([]VolumeSlot, error) {
	var out, errBuf bytes.Buffer
	cmd := exec.Command(cfg.Cryptenroll, file)
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemd-cryptenroll (listing the keyslots): %v: %s", err, strings.TrimSpace(errBuf.String()))
	}
	return volParseSlots(out.String()), nil
}

func volSlotsOfType(s []VolumeSlot, typ string) []int {
	var n []int
	for _, x := range s {
		if x.Type == typ {
			n = append(n, x.N)
		}
	}
	sort.Ints(n)
	return n
}

func volHasSlot(s []VolumeSlot, n int, typ string) bool {
	for _, x := range s {
		if x.N == n && x.Type == typ {
			return true
		}
	}
	return false
}

// volCheckWipe is the guard around wiping the old recovery slots: each must
// be a recovery slot, none may be the new one, and the new one must exist,
// so an unlock method always remains.
func volCheckWipe(slots []VolumeSlot, newSlot int, old []int) error {
	if !volHasSlot(slots, newSlot, "recovery") {
		return fmt.Errorf("slot %d is not a recovery key on this volume — refusing to wipe anything", newSlot)
	}
	for _, o := range old {
		if o == newSlot {
			return errors.New("refusing to wipe the new recovery key's own slot")
		}
		if !volHasSlot(slots, o, "recovery") {
			return fmt.Errorf("slot %d is not a recovery key (wipes by number, recovery slots only) — refusing", o)
		}
	}
	return nil
}

func volManifestVolume(cfg VolumeConfig) (file string, m map[string]any, err error) {
	if cfg.Geteuid() != 0 {
		return "", nil, errors.New("this needs root: run it through 'noo security at-rest …', or with sudo /usr/local/bin/noo-hostd at-rest …")
	}
	if volIsWSL(cfg.ProcVersion) {
		return "", nil, errors.New("not supported here: WSL2 has no TPM (i10a covers Linux controllers only)")
	}
	m, err = volReadManifest(cfg)
	if err != nil {
		return "", nil, err
	}
	file, _ = m["volume_file"].(string)
	if file == "" {
		return "", nil, fmt.Errorf("%s records no encrypted state volume — create it first: noo security at-rest create-volume", cfg.ManifestPath())
	}
	if st, serr := os.Stat(file); serr != nil || !st.Mode().IsRegular() {
		return "", nil, fmt.Errorf("the volume file %s recorded in the manifest is missing — if the disk moved, see docs/operating/runbooks/at-rest-recovery.md", file)
	}
	return file, m, nil
}

func volResolveAll(cfg *VolumeConfig) error {
	for _, p := range []*string{&cfg.Cryptsetup, &cfg.Cryptenroll} {
		abs, err := volResolveBin(*p)
		if err != nil {
			return err
		}
		*p = abs
	}
	return nil
}

// RecoveryEnrolled is the one JSON line `recovery-key` prints. NOT logged.
type RecoveryEnrolled struct {
	OK          bool   `json:"ok"`
	RecoveryKey string `json:"recovery_key"`
	NewSlot     int    `json:"new_slot"`
	OldSlots    []int  `json:"old_slots"`
	File        string `json:"volume_file"`
}

// EnrollRecoveryKey is `recovery-key` (phase one): enroll and prove a NEW
// recovery key. It wipes nothing.
func EnrollRecoveryKey(cfg VolumeConfig, stdout, stderr io.Writer) error {
	file, _, err := volManifestVolume(cfg)
	if err != nil {
		return err
	}
	if err := volResolveAll(&cfg); err != nil {
		return err
	}
	before, err := volListSlots(cfg, file)
	if err != nil {
		return err
	}
	if len(volSlotsOfType(before, "tpm2")) == 0 {
		return errors.New("the volume has no TPM keyslot to unlock it with here — open it with the existing recovery key and run 'noo security at-rest reenroll' first (docs/operating/runbooks/at-rest-recovery.md)")
	}
	volStep(stderr, "enrolling a NEW recovery key (unlocked by the TPM; the old one is kept until you confirm the new one)")
	var out, errBuf bytes.Buffer
	cmd := exec.Command(cfg.Cryptenroll, "--recovery-key", "--unlock-tpm2-device=auto", file)
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	runErr := cmd.Run()
	key, perr := volParseRecoveryKey(out.Bytes())
	msg := strings.TrimSpace(errBuf.String())
	if key != "" {
		msg = strings.ReplaceAll(msg, key, "<redacted>")
	}
	out.Reset()
	if runErr != nil {
		return fmt.Errorf("the TPM did not unlock the volume to enroll a recovery key (%v: %s) — if the firmware or Secure Boot changed, open the volume with the old recovery key and run 'noo security at-rest reenroll' (docs/operating/runbooks/at-rest-recovery.md)", runErr, msg)
	}
	if perr != nil {
		return perr
	}
	if err := volRun([]byte(key), []string{key}, cfg.Cryptsetup, "open", "--test-passphrase", "--key-file=-", file); err != nil {
		return fmt.Errorf("the new recovery key did not open the volume in a test — the old one is untouched: %w", err)
	}
	after, err := volListSlots(cfg, file)
	if err != nil {
		return err
	}
	var newSlot = -1
	old := volSlotsOfType(before, "recovery")
	for _, n := range volSlotsOfType(after, "recovery") {
		isOld := false
		for _, o := range old {
			if o == n {
				isOld = true
			}
		}
		if !isOld {
			newSlot = n
		}
	}
	if newSlot < 0 {
		return errors.New("could not find the new recovery key's keyslot — nothing was wiped")
	}
	if err := volMergeManifest(cfg, map[string]any{"volume_recovery_key": "enrolled"}); err != nil {
		return err
	}
	b, err := json.Marshal(RecoveryEnrolled{OK: true, RecoveryKey: key, NewSlot: newSlot, OldSlots: old, File: file})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(b))
	return err
}

// FinishRecoveryKey is `recovery-key --finish`: wipe the old recovery slots.
func FinishRecoveryKey(cfg VolumeConfig, newSlot int, old []int, stdout, stderr io.Writer) error {
	file, _, err := volManifestVolume(cfg)
	if err != nil {
		return err
	}
	if newSlot < 0 {
		return errors.New("--finish needs --new-slot")
	}
	if err := volResolveAll(&cfg); err != nil {
		return err
	}
	slots, err := volListSlots(cfg, file)
	if err != nil {
		return err
	}
	if err := volCheckWipe(slots, newSlot, old); err != nil {
		return err
	}
	for _, o := range old {
		volStep(stderr, "wiping the OLD recovery key (slot %d)", o)
		if err := volRun(nil, nil, cfg.Cryptenroll, "--wipe-slot="+strconv.Itoa(o), file); err != nil {
			return err
		}
	}
	if err := volMergeManifest(cfg, map[string]any{
		"volume_recovery_key":        "enrolled",
		"volume_recovery_rotated_at": cfg.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "{\"ok\":true,\"wiped\":%d}\n", len(old))
	return err
}

// ── reenroll ────────────────────────────────────────────────────────────

// ReenrollOptions are reenroll's arguments.
type ReenrollOptions struct {
	PCRs string // "auto" (or ""), "7", "none"
}

// ReenrollResult is the one JSON line `reenroll` prints.
type ReenrollResult struct {
	OK              bool   `json:"ok"`
	PCRs            string `json:"volume_pcrs"`
	PCRNote         string `json:"pcr_note"`
	SecureBoot      bool   `json:"secure_boot"`
	AgeKeyResealed  bool   `json:"age_key_resealed"`
	AgeKeySealed    bool   `json:"age_key_sealed"`
	ResealCommand   string `json:"reseal_command,omitempty"`
	ResealNote      string `json:"reseal_note,omitempty"`
	CryptsetupStats string `json:"device,omitempty"`
}

var volStatusDevice = regexp.MustCompile(`(?m)^\s*device:\s+(\S+)\s*$`)

// volResealArgs is the seal-age-key line for a re-seal.
func volResealArgs(user, key, pcrs string) []string {
	return []string{"at-rest", "seal-age-key", "--user", user, "--key", key, "--pcrs", pcrs}
}

// volResealRunner re-seals through PR-B's verb in this same binary, when it
// has one (feature-detected from `at-rest help`); errResealAbsent otherwise.
var errResealAbsent = errors.New("this noo-hostd has no seal-age-key verb")

// volReseal is the seam tests replace (the default re-executes this binary).
var volReseal = volDefaultReseal

func volDefaultReseal(user, key, pcrs string, stderr io.Writer) error {
	self, err := os.Executable()
	if err != nil {
		return errResealAbsent
	}
	help, _ := exec.Command(self, "at-rest", "help").CombinedOutput()
	if !bytes.Contains(help, []byte("seal-age-key")) {
		return errResealAbsent
	}
	cmd := exec.Command(self, volResealArgs(user, key, pcrs)...)
	cmd.Stdout, cmd.Stderr = stderr, stderr
	return cmd.Run()
}

// Reenroll is `reenroll`.
func Reenroll(cfg VolumeConfig, o ReenrollOptions, stdout, stderr io.Writer) error {
	file, m, err := volManifestVolume(cfg)
	if err != nil {
		return err
	}
	sbOn, sbKnown := VolumeSecureBoot(cfg.EFIVarsDir)
	pcrs, note, err := VolumePCRs(o.PCRs, sbOn, sbKnown)
	if err != nil {
		return err
	}
	if err := volResolveAll(&cfg); err != nil {
		return err
	}
	// The volume must already be open: the device comes from its mapping.
	var st, stErr bytes.Buffer
	cmd := exec.Command(cfg.Cryptsetup, "status", VolumeMapperName)
	cmd.Stdout, cmd.Stderr = &st, &stErr
	_, mapErr := os.Lstat(cfg.MapperPath())
	var dm []string
	if mapErr == nil && cmd.Run() == nil {
		dm = volStatusDevice.FindStringSubmatch(st.String())
	}
	if dm == nil {
		return fmt.Errorf("the encrypted state volume is not open (%s is absent), so there is nothing to re-enroll against. "+
			"If the TPM no longer unseals it (a firmware or Secure Boot change, a cleared TPM), open it with the RECOVERY key first: "+
			"sudo cryptsetup open %s %s   (type the recovery key), sudo mount %s, then run this again "+
			"(docs/operating/runbooks/at-rest-recovery.md)", cfg.MapperPath(), file, VolumeMapperName, mountpointOf(m))
	}
	device := dm[1]

	volStep(stderr, "re-enrolling the TPM on %s (%s; Secure Boot %s). systemd-cryptenroll will ask for the recovery key if the TPM cannot unlock the volume", device, volPCRsFlag(pcrs), onOff(sbKnown && sbOn))
	enr := exec.Command(cfg.Cryptenroll, "--wipe-slot=tpm2", "--tpm2-device=auto", volPCRsFlag(pcrs), device)
	enr.Stdin, enr.Stdout, enr.Stderr = os.Stdin, stderr, stderr
	if err := enr.Run(); err != nil {
		return fmt.Errorf("systemd-cryptenroll could not re-enroll the TPM (%v) — the existing keyslots are as they were unless it said otherwise above", err)
	}
	if err := volRun(nil, nil, cfg.Cryptsetup, "open", "--test-passphrase", "--token-only", "--token-type", "systemd-tpm2", device); err != nil {
		return fmt.Errorf("the new TPM enrollment did not open the volume in a test: %w", err)
	}
	set := map[string]any{
		"volume_pcrs":                  pcrs,
		"volume_secure_boot_at_create": sbKnown && sbOn,
		"volume_secure_boot_known":     sbKnown,
		"volume_reenrolled_at":         cfg.Now().UTC().Format(time.RFC3339),
	}
	res := ReenrollResult{OK: true, PCRs: pcrs, PCRNote: note, SecureBoot: sbKnown && sbOn, CryptsetupStats: device}

	// The age key, when sealed: resealed against the same boot chain, from
	// the escrow copy on the (open) volume.
	res.AgeKeySealed, _ = m["age_key_sealed"].(bool)
	if res.AgeKeySealed {
		user, _ := m["volume_operator"].(string)
		if user == "" {
			user, _ = m["operator"].(string)
		}
		key, _ := m["volume_age_key_escrow"].(string)
		keyArg := key
		if keyArg == "" {
			keyArg = "<the age key file>"
		}
		res.ResealCommand = "sudo " + strings.Join(append([]string{"/usr/local/bin/noo-hostd"}, volResealArgs(user, keyArg, pcrs)...), " ")
		if key == "" || user == "" {
			res.ResealNote = "the manifest records no escrowed age key copy, so it was not resealed automatically"
		} else if rerr := volReseal(user, key, pcrs, stderr); rerr == nil {
			res.AgeKeyResealed = true
			res.ResealCommand = ""
			set["age_key_pcrs"] = pcrs
			set["secure_boot_at_seal"] = sbKnown && sbOn
			set["secure_boot_known"] = sbKnown
		} else if errors.Is(rerr, errResealAbsent) {
			res.ResealNote = "this noo-hostd has no seal-age-key verb yet; run the command below once it does"
		} else {
			res.ResealNote = "resealing the age key failed (" + rerr.Error() + "); run the command below"
		}
	}
	if err := volMergeManifest(cfg, set); err != nil {
		return err
	}
	volStep(stderr, "done: TPM re-enrolled (PCR policy: %s). %s", pcrs, note)
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(b))
	return err
}

func mountpointOf(m map[string]any) string {
	if s, _ := m["volume_mountpoint"].(string); s != "" {
		return s
	}
	return filepath.Join("<data root>", VolumeMountDir)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
