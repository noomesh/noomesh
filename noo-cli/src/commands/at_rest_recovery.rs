// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! At-rest encryption, part E (i10a): the way back in, and the way through a
//! firmware update.
//!
//! - `noo security at-rest recovery-key` enrolls a NEW recovery key through
//!   `sudo noo-hostd at-rest recovery-key`, shows it once (terminal only; the
//!   person retypes its first and last groups, the same flow as
//!   `create-volume`), and only THEN has hostd wipe the old recovery slot
//!   (`recovery-key --finish`). If the person does not confirm, the old key
//!   is untouched and verify warns. A volume made with
//!   `--defer-recovery-key` gets its first key here. Records the
//!   person-only acknowledgement setting.
//! - `noo security at-rest reenroll` runs `sudo noo-hostd at-rest reenroll`
//!   after a firmware or Secure Boot change: the stale TPM slot is replaced,
//!   PCR 7 with Secure Boot on and TPM-only with it off (never the firmware
//!   PCRs), and the sealed age key is resealed. The volume must be open: if
//!   the TPM no longer unseals it, open it with the recovery key first (the
//!   runbook says how).
//! - `noo security at-rest preflight-firmware` checks, before a BIOS or
//!   fwupd update, that the way back exists, and prints what to do after.
//!
//! The recovery key is never written to a file, never logged, never put in
//! JSON output: it lives in memory between the pipe and the terminal and is
//! overwritten on drop.

use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::commands::at_rest::{AcceptedState, Cpu, TpmFacts};
use crate::commands::at_rest_volume::{
    flag_from, hostd_bin_path, operator_user, read_volume, reveal_on_terminal, Volume, MAPPER_PATH, RECOVERY_SETTING, RUNBOOK,
};
use crate::commands::cluster_verify::{Check, Verdict};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// A backup newer than this is "fresh" for the preflight.
pub(crate) const FRESH_BACKUP_SECS: u64 = 24 * 3600;

pub(crate) const PREFLIGHT_VOLUME: &str = "volume";
pub(crate) const PREFLIGHT_RECOVERY: &str = "recovery key";
pub(crate) const PREFLIGHT_BACKUP: &str = "fresh backup";
pub(crate) const PREFLIGHT_BINDING: &str = "TPM binding";
pub(crate) const PREFLIGHT_FTPM: &str = "firmware TPM reset";
pub(crate) const PREFLIGHT_DBX: &str = "Secure Boot database update";

// ── recovery-key: the hostd conversation ────────────────────────────────

/// What `recovery-key` (phase one) reported. Deliberately NOT `Debug`: it
/// holds the new recovery key, overwritten on drop.
pub(crate) struct Rotated {
    pub key: String,
    pub new_slot: u64,
    pub old_slots: Vec<u64>,
}

impl Drop for Rotated {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8.
        unsafe { self.key.as_bytes_mut() }.fill(0);
    }
}

/// Parse phase one's stdout: the last non-empty line is one JSON object with
/// `"ok": true`. Errors never echo stdout (it holds the key).
pub(crate) fn parse_rotated(stdout: &[u8]) -> Result<Rotated, String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().rev().find(|l| !l.trim().is_empty()).ok_or("recovery-key printed no result")?;
    let v: Value = serde_json::from_str(line.trim()).map_err(|_| "recovery-key's result line is not JSON".to_string())?;
    if v["ok"] != true {
        return Err("recovery-key did not report success".into());
    }
    let key = v["recovery_key"].as_str().unwrap_or_default().to_string();
    if key.is_empty() {
        return Err("recovery-key reported no key".into());
    }
    let new_slot = v["new_slot"].as_u64().ok_or("recovery-key reported no slot for the new key")?;
    let old_slots = v["old_slots"].as_array().map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
    Ok(Rotated { key, new_slot, old_slots })
}

pub(crate) fn enroll_argv(hostd: &str) -> Vec<String> {
    vec![hostd.into(), "at-rest".into(), "recovery-key".into()]
}

/// Phase two: wipe the OLD recovery slots, by number, once the new key is
/// confirmed.
pub(crate) fn finish_argv(hostd: &str, new_slot: u64, old: &[u64]) -> Vec<String> {
    let mut a = vec![hostd.into(), "at-rest".into(), "recovery-key".into(), "--finish".into(), "--new-slot".into(), new_slot.to_string()];
    if !old.is_empty() {
        a.push("--old-slots".into());
        a.push(old.iter().map(u64::to_string).collect::<Vec<_>>().join(","));
    }
    a
}

pub(crate) fn reenroll_argv(hostd: &str, pcrs: &str) -> Vec<String> {
    let mut a = vec![hostd.into(), "at-rest".into(), "reenroll".into()];
    if pcrs != "auto" {
        a.push("--pcrs".into());
        a.push(pcrs.into());
    }
    a
}

/// Run `sudo <argv>` with stdout piped (the result line, never shown) and
/// stdin/stderr on the terminal (sudo's password prompt, and
/// systemd-cryptenroll's own recovery-key prompt).
fn run_sudo(argv: &[String]) -> Result<Vec<u8>, String> {
    let out = Command::new("sudo")
        .args(argv)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| format!("could not run sudo: {e}"))?;
    if !out.status.success() {
        let code = out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "a signal".into());
        return Err(format!("{} failed (exit {code}); its reason is above", argv.get(2).map(String::as_str).unwrap_or("noo-hostd")));
    }
    Ok(out.stdout)
}

fn controller_gate(g: &Globals) -> Volume {
    if !cfg!(target_os = "linux") || std::fs::read_to_string("/proc/version").map(|v| v.to_ascii_lowercase().contains("microsoft")).unwrap_or(false) {
        fail(g.json, ExitCode::Generic, "not_supported_here", "not supported here: the encrypted state volume is for Linux controllers (not macOS, WSL2 or worker nodes)", None);
    }
    let Some(v) = read_volume() else {
        fail(
            g.json,
            ExitCode::Generic,
            "no_volume",
            "this machine has no encrypted state volume (/etc/noo/at-rest.json records none)",
            Some("noo security at-rest create-volume"),
        );
    };
    if operator_user().is_none() {
        fail(g.json, ExitCode::Generic, "no_operator", "run this as the operator account (not root); it asks sudo for the root half", None);
    }
    v
}

fn require_hostd(g: &Globals, hostd: &str) {
    if !Path::new(hostd).is_file() {
        fail(g.json, ExitCode::Generic, "no_hostd", &format!("{hostd} is not installed — it does the root half"), Some("noo onboard --only services"));
    }
}

/// `noo security at-rest recovery-key [--dry-run]`
pub fn security_at_rest_recovery_key(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut dry = false;
    for a in args {
        match a.as_str() {
            "--dry-run" => dry = true,
            _ => return Err(Unhandled),
        }
    }
    let v = controller_gate(g);
    let terminal = crate::onboard::prompt::stdin_is_tty() && crate::onboard::prompt::stdout_is_tty() && !g.json;
    if !terminal {
        fail(
            g.json,
            ExitCode::Generic,
            "needs_terminal",
            "the recovery key is shown once, on a terminal only — run this at a terminal on the controller",
            None,
        );
    }
    let hostd = hostd_bin_path();
    let argv = enroll_argv(&hostd);
    if dry {
        ui::step(&format!("would run: sudo {}  (then, once you confirm the new key, sudo {} --finish …)", argv.join(" "), argv.join(" ")));
        return Ok(0);
    }
    require_hostd(g, &hostd);
    if !Path::new(MAPPER_PATH).exists() {
        println!("{}", ui::note(&format!("{MAPPER_PATH} is not open; hostd unlocks {} with the TPM itself", v.file)));
    }
    ui::step("enrolling a NEW recovery key (the TPM unlocks the volume; the old key keeps working until you confirm the new one)");
    let stdout = match run_sudo(&argv) {
        Ok(o) => o,
        Err(e) => fail(
            g.json,
            ExitCode::Generic,
            "recovery_key_failed",
            &format!("{e}. If the TPM no longer unlocks the volume, open it with the old recovery key and run `noo security at-rest reenroll` first"),
            Some(RUNBOOK),
        ),
    };
    let mut stdout = stdout;
    let parsed = parse_rotated(&stdout);
    stdout.fill(0);
    let rotated = match parsed {
        Ok(r) => r,
        Err(e) => fail(g.json, ExitCode::Generic, "recovery_key_failed", &e, None),
    };
    let confirmed = reveal_on_terminal(&rotated.key);
    if !confirmed {
        // Both keys work. Say so; the acknowledgement no longer describes a key the person holds.
        let _ = crate::http::post_json_try(g, "/api/settings/flags/set", &json!({"key": RECOVERY_SETTING, "value": false}), true, 10);
        ui::warned("you did not confirm the new recovery key, so the OLD one was NOT removed and both open the volume. Run this again when you can store a key off this machine");
        return Ok(1);
    }
    if let Err(e) = run_sudo(&finish_argv(&hostd, rotated.new_slot, &rotated.old_slots)) {
        ui::warned(&format!(
            "the new key is enrolled and works, but removing the old recovery key failed ({e}). Both still open the volume; run this again to retry"
        ));
        return Ok(1);
    }
    match crate::http::post_json_try(g, "/api/settings/flags/set", &json!({"key": RECOVERY_SETTING, "value": true}), true, 10) {
        Ok(_) => ui::done("recorded: you stored the new recovery key off this machine"),
        Err(e) => ui::warned(&format!("the key is rotated, but your acknowledgement was NOT recorded ({e}); verify will warn until it is")),
    }
    if g.json {
        println!("{}", json!({"recovery_key_rotated": true, "old_slots_wiped": rotated.old_slots.len(), "recovery_key_acknowledged": true}));
    } else {
        ui::done(if rotated.old_slots.is_empty() { "recovery key enrolled" } else { "new recovery key enrolled; the old one no longer opens the volume" });
        ui::guide(&[("noo cluster verify --controller", "the at-rest recovery key row")]);
    }
    Ok(0)
}

// ── reenroll ────────────────────────────────────────────────────────────

/// Why re-enrolling cannot start now, or `None`.
pub(crate) fn reenroll_refusal(v: &Volume, open: bool) -> Option<String> {
    if open {
        return None;
    }
    Some(format!(
        "the encrypted state volume is not open ({MAPPER_PATH} is absent), so there is nothing to re-enroll against. If the TPM no longer unseals it (a firmware or Secure Boot change, a cleared TPM), open it with the RECOVERY key first:\n  sudo cryptsetup open {} noo-state     (type the recovery key)\n  sudo mount {}\nthen run `noo security at-rest reenroll` again ({RUNBOOK})",
        v.file, v.mountpoint
    ))
}

/// `noo security at-rest reenroll [--pcrs 7|none|auto] [--dry-run]`
pub fn security_at_rest_reenroll(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut pcrs = "auto".to_string();
    let mut dry = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pcrs" => pcrs = it.next().ok_or(Unhandled)?.clone(),
            "--dry-run" => dry = true,
            _ => return Err(Unhandled),
        }
    }
    if !matches!(pcrs.as_str(), "7" | "none" | "auto") {
        fail(g.json, ExitCode::Usage, "bad_pcrs", &format!("--pcrs {pcrs}: only 7, none or auto (the firmware PCRs 0/2 are never bound, so a BIOS update cannot lock this machine out)"), None);
    }
    let v = controller_gate(g);
    let hostd = hostd_bin_path();
    let argv = reenroll_argv(&hostd, &pcrs);
    if dry {
        ui::step(&format!("would run: sudo {}", argv.join(" ")));
        return Ok(0);
    }
    if let Some(why) = reenroll_refusal(&v, Path::new(MAPPER_PATH).exists()) {
        fail(g.json, ExitCode::Generic, "volume_not_open", &why, Some(RUNBOOK));
    }
    require_hostd(g, &hostd);
    ui::step("re-enrolling the TPM on the encrypted state volume (systemd-cryptenroll asks for the recovery key if the TPM cannot unlock it)");
    let mut out = match run_sudo(&argv) {
        Ok(o) => o,
        Err(e) => fail(g.json, ExitCode::Generic, "reenroll_failed", &e, Some(RUNBOOK)),
    };
    let text = String::from_utf8_lossy(&out).into_owned();
    out.fill(0);
    let line = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default();
    let r: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
    if r["ok"] != true {
        fail(g.json, ExitCode::Generic, "reenroll_failed", "reenroll did not report success", Some(RUNBOOK));
    }
    let resealed = r["age_key_resealed"].as_bool().unwrap_or(false);
    let sealed = r["age_key_sealed"].as_bool().unwrap_or(false);
    if g.json {
        println!("{}", json!({"volume_pcrs": r["volume_pcrs"], "secure_boot": r["secure_boot"], "age_key_sealed": sealed, "age_key_resealed": resealed, "reseal_command": r["reseal_command"]}));
    } else {
        ui::done(&format!("TPM re-enrolled (PCR policy: {})", r["volume_pcrs"].as_str().unwrap_or("?")));
        if let Some(n) = r["pcr_note"].as_str().filter(|n| !n.is_empty()) {
            println!("{}", ui::note(n));
        }
        if sealed && resealed {
            ui::done("the sealed age key was resealed against the same boot chain");
        } else if sealed {
            ui::warned(r["reseal_note"].as_str().unwrap_or("the sealed age key was NOT resealed"));
            if let Some(c) = r["reseal_command"].as_str().filter(|c| !c.is_empty()) {
                println!("  {c}");
            }
        }
        ui::guide(&[
            ("reboot once", "prove the unattended unlock"),
            ("noo stack start", "if the stack was stopped for the recovery"),
            ("noo cluster verify --controller", "the at-rest rows, incl. the PCR bindings"),
        ]);
    }
    Ok(if sealed && !resealed { 1 } else { 0 })
}

// ── verify: the volume's TPM binding against Secure Boot now ────────────

pub(crate) const BINDING_ROW: &str = "at-rest volume binding";

/// The `at-rest volume binding` row: the volume's TPM token against live
/// Secure Boot. (PR-B's `at-rest pcr binding` judges the sealed age key; the
/// volume has its own token, so its own row.) No row without a volume.
pub(crate) fn volume_binding_check(v: Option<&Volume>, secure_boot: Option<bool>) -> Option<Check> {
    let v = v?;
    let c = |verdict, detail: String, remedy: Option<&str>| Check { name: BINDING_ROW, verdict, detail, remedy: remedy.map(str::to_string) };
    Some(match (v.pcrs.as_str(), secure_boot) {
        ("7", Some(true)) => c(Verdict::Ok, "the volume's TPM token is bound to PCR 7 and Secure Boot is on".into(), None),
        ("7", _) => c(
            Verdict::Fail,
            "the volume's TPM token is bound to PCR 7 but Secure Boot is not on now: the TPM will not unlock it at the next boot".into(),
            Some("noo security at-rest reenroll"),
        ),
        (_, Some(true)) => c(
            Verdict::Warn,
            "the volume is TPM-only while Secure Boot is on: a live-USB boot of this machine is not blocked from unlocking it".into(),
            Some("noo security at-rest reenroll --pcrs 7"),
        ),
        _ => c(Verdict::Ok, "the volume is TPM-only and Secure Boot is off: nothing binds it to the boot chain".into(), None),
    })
}

// ── preflight-firmware ──────────────────────────────────────────────────

/// Everything the preflight judges, gathered by the caller so the matrix is
/// testable without a machine.
pub(crate) struct Preflight<'a> {
    pub volume: Option<&'a Volume>,
    /// The acknowledgement setting; `None` = could not be read.
    pub ack: Option<&'a AcceptedState>,
    /// Seconds since the newest backup artifact; `None` = no backup found.
    pub backup_age_secs: Option<u64>,
    /// Live Secure Boot: `Some(true)` on, `Some(false)` off, `None` unreadable.
    pub secure_boot: Option<bool>,
    pub cpu: Cpu,
}

fn pc(name: &'static str, verdict: Verdict, detail: impl Into<String>, remedy: Option<&str>) -> Check {
    Check { name, verdict, detail: detail.into(), remedy: remedy.map(str::to_string) }
}

/// The checks. A volume that does not exist means there is nothing for a
/// firmware update to lock out: one OK row and nothing else.
pub(crate) fn preflight_checks(p: &Preflight) -> Vec<Check> {
    let Some(v) = p.volume else {
        return vec![pc(
            PREFLIGHT_VOLUME,
            Verdict::Ok,
            "no encrypted state volume on this machine: a firmware update cannot lock any data out",
            None,
        )];
    };
    let mut c = vec![pc(PREFLIGHT_VOLUME, Verdict::Ok, format!("{} (TPM policy: {})", v.file, if v.pcrs == "7" { "PCR 7" } else { "TPM-only" }), None)];

    // The way back: a recovery key that exists AND that someone stored.
    c.push(if v.recovery == "deferred" {
        pc(
            PREFLIGHT_RECOVERY,
            Verdict::Fail,
            "no recovery key: if the update stops the TPM unlocking the volume, the data cannot be opened",
            Some("noo security at-rest recovery-key"),
        )
    } else {
        match p.ack {
            Some(a) if a.accepted => pc(PREFLIGHT_RECOVERY, Verdict::Ok, "enrolled and acknowledged as stored off this machine", None),
            Some(_) => pc(
                PREFLIGHT_RECOVERY,
                Verdict::Fail,
                "a recovery key exists but nobody confirmed storing it off this machine",
                Some("noo security at-rest recovery-key"),
            ),
            None => pc(
                PREFLIGHT_RECOVERY,
                Verdict::Warn,
                "could not read whether the recovery key was acknowledged (the gateway did not answer)",
                Some("noo security at-rest recovery-key"),
            ),
        }
    });

    c.push(match p.backup_age_secs {
        None => pc(
            PREFLIGHT_BACKUP,
            Verdict::Fail,
            "no backup found: a failed unlock with no recovery key and no backup loses the data",
            Some("noo backups status"),
        ),
        Some(s) if s > FRESH_BACKUP_SECS => pc(
            PREFLIGHT_BACKUP,
            Verdict::Warn,
            format!("the newest backup is {} h old (fresh means under {} h)", s / 3600, FRESH_BACKUP_SECS / 3600),
            Some("scripts/backup-controller.sh"),
        ),
        Some(s) => pc(PREFLIGHT_BACKUP, Verdict::Ok, format!("the newest backup is {} h old", s / 3600), None),
    });

    // The volume's binding against Secure Boot as it is NOW.
    c.push(match (v.pcrs.as_str(), p.secure_boot) {
        ("7", Some(true)) => pc(PREFLIGHT_BINDING, Verdict::Ok, "bound to PCR 7 and Secure Boot is on", None),
        ("7", _) => pc(
            PREFLIGHT_BINDING,
            Verdict::Warn,
            "bound to PCR 7 but Secure Boot is not on now: the TPM will not unlock this volume at the next boot",
            Some("noo security at-rest reenroll"),
        ),
        (_, Some(true)) => pc(
            PREFLIGHT_BINDING,
            Verdict::Ok,
            "TPM-only and Secure Boot is on: the update cannot change the unlock; `reenroll` afterwards would bind PCR 7",
            None,
        ),
        _ => pc(PREFLIGHT_BINDING, Verdict::Ok, "TPM-only: boot-chain changes do not affect the unlock", None),
    });

    // What a firmware update can do that no check can see.
    c.push(if p.cpu == Cpu::Amd {
        pc(
            PREFLIGHT_FTPM,
            Verdict::Warn,
            "AMD fTPM: a BIOS update can reset the firmware TPM, which voids the TPM slot — only the recovery key then opens the volume",
            Some("keep the recovery key at hand; after the update: noo security at-rest reenroll"),
        )
    } else {
        pc(
            PREFLIGHT_FTPM,
            Verdict::Ok,
            "a BIOS update can still reset a firmware TPM (Intel PTT) on some boards; the recovery key is the way back",
            None,
        )
    });
    c.push(if v.pcrs == "7" {
        pc(
            PREFLIGHT_DBX,
            Verdict::Warn,
            "bound to PCR 7: a fwupd dbx (Secure Boot database) update changes PCR 7 and stops the TPM unlocking until re-enrolled",
            Some("after the update: noo security at-rest reenroll"),
        )
    } else {
        pc(PREFLIGHT_DBX, Verdict::Ok, "TPM-only: a Secure Boot database update does not affect the unlock", None)
    });
    c
}

/// Newest modification time (seconds ago) among the backup artifacts.
fn newest_backup_age_secs() -> Option<u64> {
    let mut all = crate::commands::secrets::backup_artifacts("pg_*.sql.gz.enc");
    all.extend(crate::commands::secrets::backup_artifacts("age-key_*"));
    all.iter()
        .filter_map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .filter_map(|t| t.elapsed().ok())
        .map(|d| d.as_secs())
        .min()
}

/// What to do after the update, as lines.
pub(crate) fn after_update_steps(v: Option<&Volume>) -> Vec<String> {
    let Some(v) = v else { return vec!["nothing: there is no encrypted state volume".into()] };
    vec![
        "1. Reboot (or let the update reboot). If the machine comes back and `noo cluster verify --controller` is green, you are done.".into(),
        format!("2. If `noo stack start` refuses (\"the encrypted state volume is not open\"), the TPM no longer unseals it. Over ssh: sudo cryptsetup open {} noo-state  (type the RECOVERY key), then sudo mount {}", v.file, v.mountpoint),
        "3. noo security at-rest reenroll   (re-binds the TPM to the new firmware state and reseals the age key)".into(),
        "4. noo stack start, then reboot once to prove the unattended unlock.".into(),
        format!("Full steps: {RUNBOOK}"),
    ]
}

/// `noo security at-rest preflight-firmware [--json]`
pub fn security_at_rest_preflight_firmware(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    if !cfg!(target_os = "linux") {
        fail(g.json, ExitCode::Generic, "not_supported_here", "not supported here: the encrypted state volume is for Linux controllers", None);
    }
    let v = read_volume();
    let facts = TpmFacts::probe(Path::new("/"));
    let flags = crate::http::get_json_opt(g, "/api/settings/flags", true, 10);
    let ack = flags.as_ref().and_then(|b| flag_from(b, RECOVERY_SETTING));
    let checks = preflight_checks(&Preflight {
        volume: v.as_ref(),
        ack: ack.as_ref(),
        backup_age_secs: newest_backup_age_secs(),
        secure_boot: facts.secure_boot,
        cpu: facts.cpu,
    });
    let failed = checks.iter().any(|c| c.verdict == Verdict::Fail);
    let steps = after_update_steps(v.as_ref());
    if g.json {
        let rows: Vec<Value> = checks
            .iter()
            .map(|c| json!({"check": c.name, "verdict": format!("{:?}", c.verdict).to_lowercase(), "detail": c.detail, "remedy": c.remedy}))
            .collect();
        println!("{}", json!({"ready": !failed, "checks": rows, "after_the_update": steps}));
        return Ok(i32::from(failed));
    }
    println!("{}", ui::header("Before a firmware update", None));
    for c in &checks {
        let line = format!("{}: {}", c.name, c.detail);
        match c.verdict {
            Verdict::Ok => ui::done(&line),
            _ => ui::warned(&line),
        }
        if let (Some(r), true) = (c.remedy.as_deref(), c.verdict != Verdict::Ok) {
            println!("    {r}");
        }
    }
    println!();
    println!("{}", ui::emph("After the update"));
    for s in &steps {
        println!("  {s}");
    }
    if failed {
        ui::warned("not ready: fix the failed checks above before updating the firmware");
    } else {
        ui::done("ready for the firmware update");
    }
    Ok(i32::from(failed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vol(pcrs: &str, recovery: &str) -> Volume {
        Volume {
            file: "/var/lib/noo/state.luks2".into(),
            mountpoint: "/var/lib/noo/state".into(),
            size_gib: 64,
            pcrs: pcrs.into(),
            recovery: recovery.into(),
            created_at: "t".into(),
        }
    }

    fn ack(accepted: bool) -> AcceptedState {
        AcceptedState { accepted, source: "db".into(), updated_by: Some("alice".into()), updated_at: Some("t".into()) }
    }

    fn verdict(c: &[Check], name: &str) -> Verdict {
        c.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no row {name}")).verdict
    }

    fn run(v: &Volume, a: Option<&AcceptedState>, backup: Option<u64>, sb: Option<bool>, cpu: Cpu) -> Vec<Check> {
        preflight_checks(&Preflight { volume: Some(v), ack: a, backup_age_secs: backup, secure_boot: sb, cpu })
    }

    #[test]
    fn a_machine_with_no_volume_has_nothing_to_lose() {
        let c = preflight_checks(&Preflight { volume: None, ack: None, backup_age_secs: None, secure_boot: None, cpu: Cpu::Amd });
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].verdict, Verdict::Ok);
        assert!(after_update_steps(None)[0].contains("nothing"));
    }

    #[test]
    fn the_preflight_matrix() {
        let a = ack(true);
        let ready = run(&vol("7", "enrolled"), Some(&a), Some(3600), Some(true), Cpu::Intel);
        assert!(ready.iter().all(|c| c.verdict != Verdict::Fail), "{ready:?}");
        assert_eq!(verdict(&ready, PREFLIGHT_RECOVERY), Verdict::Ok);
        assert_eq!(verdict(&ready, PREFLIGHT_BACKUP), Verdict::Ok);
        assert_eq!(verdict(&ready, PREFLIGHT_BINDING), Verdict::Ok);

        // recovery key: deferred and unacknowledged FAIL; unreadable only warns
        assert_eq!(verdict(&run(&vol("7", "deferred"), None, Some(1), Some(true), Cpu::Intel), PREFLIGHT_RECOVERY), Verdict::Fail);
        let no = ack(false);
        assert_eq!(verdict(&run(&vol("7", "enrolled"), Some(&no), Some(1), Some(true), Cpu::Intel), PREFLIGHT_RECOVERY), Verdict::Fail);
        assert_eq!(verdict(&run(&vol("7", "enrolled"), None, Some(1), Some(true), Cpu::Intel), PREFLIGHT_RECOVERY), Verdict::Warn);

        // backup: none FAIL, stale WARN, fresh OK
        assert_eq!(verdict(&run(&vol("7", "enrolled"), Some(&a), None, Some(true), Cpu::Intel), PREFLIGHT_BACKUP), Verdict::Fail);
        assert_eq!(verdict(&run(&vol("7", "enrolled"), Some(&a), Some(FRESH_BACKUP_SECS + 1), Some(true), Cpu::Intel), PREFLIGHT_BACKUP), Verdict::Warn);
        assert_eq!(verdict(&run(&vol("7", "enrolled"), Some(&a), Some(FRESH_BACKUP_SECS), Some(true), Cpu::Intel), PREFLIGHT_BACKUP), Verdict::Ok);

        // binding vs live Secure Boot
        assert_eq!(verdict(&run(&vol("7", "enrolled"), Some(&a), Some(1), Some(false), Cpu::Intel), PREFLIGHT_BINDING), Verdict::Warn);
        assert_eq!(verdict(&run(&vol("7", "enrolled"), Some(&a), Some(1), None, Cpu::Intel), PREFLIGHT_BINDING), Verdict::Warn);
        assert_eq!(verdict(&run(&vol("none", "enrolled"), Some(&a), Some(1), Some(true), Cpu::Intel), PREFLIGHT_BINDING), Verdict::Ok);

        // AMD fTPM warns; PCR-7 volumes warn about the dbx update; TPM-only does not
        assert_eq!(verdict(&run(&vol("7", "enrolled"), Some(&a), Some(1), Some(true), Cpu::Amd), PREFLIGHT_FTPM), Verdict::Warn);
        assert_eq!(verdict(&ready, PREFLIGHT_FTPM), Verdict::Ok);
        assert_eq!(verdict(&ready, PREFLIGHT_DBX), Verdict::Warn);
        assert_eq!(verdict(&run(&vol("none", "enrolled"), Some(&a), Some(1), Some(false), Cpu::Intel), PREFLIGHT_DBX), Verdict::Ok);
    }

    #[test]
    fn the_volume_binding_row_follows_live_secure_boot() {
        assert!(volume_binding_check(None, Some(true)).is_none());
        let row = |pcrs: &str, sb| volume_binding_check(Some(&vol(pcrs, "enrolled")), sb).expect("a row").verdict;
        assert_eq!(row("7", Some(true)), Verdict::Ok);
        assert_eq!(row("7", Some(false)), Verdict::Fail, "PCR 7 with Secure Boot gone will not unlock");
        assert_eq!(row("7", None), Verdict::Fail);
        assert_eq!(row("none", Some(true)), Verdict::Warn);
        assert_eq!(row("none", Some(false)), Verdict::Ok);
    }

    #[test]
    fn the_after_update_steps_name_the_recovery_path_and_reenroll() {
        let s = after_update_steps(Some(&vol("7", "enrolled"))).join("\n");
        assert!(s.contains("sudo cryptsetup open /var/lib/noo/state.luks2 noo-state"), "{s}");
        assert!(s.contains("sudo mount /var/lib/noo/state") && s.contains("noo security at-rest reenroll") && s.contains("noo stack start"), "{s}");
        assert!(s.contains(RUNBOOK));
        assert!(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(RUNBOOK).is_file(), "the runbook named must exist");
    }

    #[test]
    fn reenroll_refuses_a_closed_volume_and_says_how_to_open_it() {
        let v = vol("7", "enrolled");
        assert_eq!(reenroll_refusal(&v, true), None);
        let why = reenroll_refusal(&v, false).expect("must refuse");
        assert!(why.contains("sudo cryptsetup open /var/lib/noo/state.luks2 noo-state") && why.contains("RECOVERY key") && why.contains(RUNBOOK), "{why}");
    }

    #[test]
    fn the_hostd_argv() {
        let h = "/usr/local/bin/noo-hostd";
        assert_eq!(enroll_argv(h), [h, "at-rest", "recovery-key"]);
        assert_eq!(finish_argv(h, 3, &[1, 2]), [h, "at-rest", "recovery-key", "--finish", "--new-slot", "3", "--old-slots", "1,2"]);
        assert_eq!(finish_argv(h, 1, &[]), [h, "at-rest", "recovery-key", "--finish", "--new-slot", "1"], "a deferred volume has no old slot to wipe");
        assert_eq!(reenroll_argv(h, "auto"), [h, "at-rest", "reenroll"]);
        assert_eq!(reenroll_argv(h, "none"), [h, "at-rest", "reenroll", "--pcrs", "none"]);
        // the key is never an argument
        assert!(!finish_argv(h, 3, &[1]).iter().any(|a| a.contains('-') && a.len() > 60));
    }

    #[test]
    fn the_rotation_result_parses_and_never_echoes_the_key() {
        let key = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-vutrnlkj-ihgfedcb-ccccdddd-eeeeffff";
        let line = format!("{}\n", json!({"ok": true, "recovery_key": key, "new_slot": 3, "old_slots": [1], "volume_file": "/f"}));
        let r = parse_rotated(line.as_bytes()).expect("parses");
        assert_eq!((r.key.as_str(), r.new_slot, r.old_slots.clone()), (key, 3, vec![1]));
        for bad in [format!("{{\"ok\":false,\"recovery_key\":\"{key}\"}}"), format!("{{\"ok\":true,\"recovery_key\":\"{key}\"}}"), format!("not json {key}"), String::new()] {
            let e = parse_rotated(bad.as_bytes()).err().expect("must refuse");
            assert!(!e.contains(key), "{e}");
        }
    }
}
