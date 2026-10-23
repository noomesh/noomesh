// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security at-rest seal|finalize` and the two verify rows that judge
//! the result (i10a PR-B: the SOPS age key sealed to the TPM).
//!
//! # Two phases, and why
//!
//! `seal` runs `sudo /usr/local/bin/noo-hostd at-rest seal-age-key`, which
//! seals the key with `systemd-creds encrypt --with-key=tpm2`, test-decrypts
//! it, installs the root unit `noo-unseal.service` (it unseals into RAM at
//! `/run/noo/keys/age.txt` at every boot, before docker) and writes the
//! manifest `/etc/noo/at-rest.json`. It does NOT delete the plaintext key.
//!
//! `finalize` deletes it — and only once each of these holds, because after
//! it the TPM is the only on-box way back to every secret:
//!   * the manifest says sealed;
//!   * the key is in RAM now, the machine BOOTED after the seal, and
//!     noo-unseal.service reached active during that boot (before the boot
//!     finished) — a real, unattended unseal, not a `systemctl start` by hand;
//!   * the RAM copy is the key that was sealed (public key) and the plaintext
//!     it replaces (sha256);
//!   * an `age-key_*.txt.enc` backup newer than the seal and under 24 h old
//!     decrypts, with NOO_AGE_BACKUP_PASSPHRASE, to that same key.
//! Then: `.env` gets `SOPS_AGE_KEY_FILE=/run/noo/keys/age.txt`, the plaintext
//! is `shred -u`'d, and `~/.config/sops/age/keys.txt` becomes a symlink to
//! the RAM copy. Shredding on an SSD does not guarantee the old blocks are
//! gone, which is why the age key is rotated next (i10a).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::age_key::{self, Manifest, UNSEAL_UNIT};
use crate::commands::cluster_verify::{Check, Verdict};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// Where the CLI expects the root helper (the CLI prints the line when it
/// cannot run sudo itself). `NOO_HOSTD_BIN` overrides it.
pub const HOSTD_BIN: &str = "/usr/local/bin/noo-hostd";
/// A finalize-grade backup is newer than the seal and at most this old.
pub const BACKUP_MAX_AGE_SECS: i64 = 24 * 3600;
pub const PCR_ROW: &str = "at-rest pcr binding";
pub const AGE_ROW: &str = "age key at rest";

fn hostd_bin() -> String {
    std::env::var("NOO_HOSTD_BIN").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| HOSTD_BIN.to_string())
}

fn systemctl_bin() -> String {
    std::env::var("NOO_SYSTEMCTL").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "systemctl".to_string())
}

fn on_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Exits (never returns) on a host the at-rest verbs do not cover.
fn refuse_unsupported_host(g: &Globals) {
    if !cfg!(target_os = "linux") || on_wsl() {
        fail(
            g.json,
            ExitCode::Generic,
            "not_supported_here",
            "not supported here: sealing to the TPM is for Linux controllers (not macOS, WSL2 or worker nodes)",
            None,
        );
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(bin)).find(|p| p.is_file())
}

fn shell_line(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.chars().all(|c| c.is_ascii_alphanumeric() || "/._-=+:@".contains(c)) {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

// ─────────────────────────────────────────────────────────────────────────
// seal
// ─────────────────────────────────────────────────────────────────────────

/// `noo security at-rest seal [--pcrs 7|none|auto] [--dry-run]`.
pub fn at_rest_seal(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
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
        fail(
            g.json,
            ExitCode::Usage,
            "bad_pcrs",
            &format!("--pcrs {pcrs}: only 7, none or auto (the firmware PCRs 0/2 are never bound)"),
            None,
        );
    }
    refuse_unsupported_host(g);
    let key = age_key::path();
    if !key.is_file() {
        fail(
            g.json,
            ExitCode::Generic,
            "no_age_key",
            &format!("no age key at {} — nothing to seal", key.display()),
            Some("restore it from its backup first (docs/security/secrets.md)"),
        );
    }
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|u| !u.trim().is_empty() && u != "root");
    let Some(user) = user else {
        fail(
            g.json,
            ExitCode::Generic,
            "no_operator",
            "run this as the operator account (not root): the unsealed key is handed to you",
            None,
        );
    };
    let hostd = hostd_bin();
    let argv: Vec<String> = vec![
        hostd.clone(),
        "at-rest".into(),
        "seal-age-key".into(),
        "--user".into(),
        user,
        "--key".into(),
        key.display().to_string(),
        "--pcrs".into(),
        pcrs,
    ];
    let line = format!("sudo {}", shell_line(&argv));
    if dry {
        if g.json {
            println!("{}", serde_json::json!({"dry_run": true, "command": line}));
        } else {
            ui::step(&format!("would run: {line}"));
        }
        return Ok(0);
    }
    if !Path::new(&hostd).is_file() {
        fail(
            g.json,
            ExitCode::Generic,
            "no_hostd",
            &format!("{hostd} is not installed — it does the root half of sealing"),
            Some("noo onboard --only services"),
        );
    }
    if g.json || !stdin_is_tty() || which("sudo").is_none() {
        ui::warned("sealing needs root and an interactive sudo — run this yourself, then reboot and finalize:");
        println!("    {line}");
        return Ok(1);
    }
    ui::step(&format!("running: {line}"));
    let ok = Command::new("sudo").args(&argv).status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        ui::failed("seal-age-key did not complete — nothing was claimed sealed unless it said so above", None);
        return Ok(1);
    }
    // Prove the unit on this boot (the reboot proves it unattended). Same
    // sudo session; failure here is reported, not fatal: the reboot is the test.
    let started = Command::new("sudo")
        .args([systemctl_bin().as_str(), "start", UNSEAL_UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let runtime = age_key::sealed_manifest().map(|m| m.runtime).unwrap_or_else(|| age_key::SEALED_RUNTIME_PATH.into());
    let same = match (std::fs::read(&runtime), std::fs::read(&key)) {
        (Ok(a), Ok(b)) => age_key::sha256_hex(&a) == age_key::sha256_hex(&b),
        _ => false,
    };
    if started && same {
        ui::done(&format!("{UNSEAL_UNIT} unsealed the key into {runtime} on this boot"));
    } else {
        ui::warned(&format!(
            "{UNSEAL_UNIT} did not put the key at {runtime} just now — check: systemctl status {UNSEAL_UNIT} (finalize will refuse until a boot unseals it)"
        ));
    }
    ui::close_done(&format!(
        "Sealed. The plaintext key stays at {} until finalize. Next: reboot, then: noo security at-rest finalize",
        key.display()
    ));
    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────
// finalize: facts → refusals (pure) → action
// ─────────────────────────────────────────────────────────────────────────

/// The plaintext key at the default path.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Plain {
    Regular { sha: String },
    /// Already a symlink to the runtime path: finalized before.
    LinkedToRuntime,
    Absent,
    Other(String),
}

/// noo-unseal.service on this boot, from `systemctl show`.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct UnitBoot {
    pub active: bool,
    /// ActiveEnterTimestampMonotonic (µs since boot; 0 = never this boot).
    pub enter_mono_us: u64,
    /// The manager's FinishTimestampMonotonic (µs; 0 = boot not finished).
    pub boot_finish_mono_us: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BackupFact {
    pub path: String,
    pub mtime_unix: i64,
    /// sha256 of what it decrypts to, or why it did not.
    pub decrypted_sha: Result<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FinalizeFacts {
    pub manifest: Option<Manifest>,
    /// `SOPS_AGE_KEY_FILE` as the process sees it (after `.env`).
    pub sops_age_key_file: Option<String>,
    pub default_path: String,
    pub runtime_sha: Option<String>,
    pub runtime_public: Option<String>,
    pub plaintext: Plain,
    pub boot_unix: Option<i64>,
    pub unit: UnitBoot,
    pub backup_dir: String,
    pub backup: Option<BackupFact>,
    pub now_unix: i64,
}

/// Every reason finalize must not run; empty = go. Pure.
pub(crate) fn finalize_refusals(f: &FinalizeFacts) -> Vec<String> {
    let mut r: Vec<String> = Vec::new();
    let Some(m) = f.manifest.as_ref().filter(|m| m.sealed) else {
        r.push(format!(
            "the age key is not sealed here (no sealed manifest at {}): run `noo security at-rest seal` first",
            age_key::manifest_path().display()
        ));
        return r;
    };
    let Some(sealed_unix) = m.sealed_unix else {
        r.push("the manifest records no sealing time — reseal: `noo security at-rest seal`".to_string());
        return r;
    };
    if let Some(k) = f.sops_age_key_file.as_deref() {
        if k != m.runtime && k != f.default_path {
            r.push(format!(
                "SOPS_AGE_KEY_FILE names {k}; finalize replaces only {} — unset it or point it at {}",
                f.default_path, m.runtime
            ));
        }
    }
    if f.runtime_sha.is_none() {
        r.push(format!(
            "the key is not unsealed on this boot ({} is absent): systemctl status {}",
            m.runtime, UNSEAL_UNIT
        ));
    }
    match f.boot_unix {
        Some(b) if b > sealed_unix => {}
        Some(_) => r.push(
            "no reboot since sealing: reboot so the boot itself proves the unseal, then run finalize again".to_string(),
        ),
        None => r.push("could not read this boot's start time (/proc/stat btime)".to_string()),
    }
    if !f.unit.active || f.unit.enter_mono_us == 0 {
        r.push(format!("{UNSEAL_UNIT} has not run on this boot: systemctl status {UNSEAL_UNIT}"));
    } else if f.unit.boot_finish_mono_us == 0 || f.unit.enter_mono_us > f.unit.boot_finish_mono_us {
        r.push(format!(
            "{UNSEAL_UNIT} was started after boot, not by the boot itself: reboot and run finalize again"
        ));
    }
    if !m.public_key.is_empty() && f.runtime_sha.is_some() && f.runtime_public.as_deref() != Some(m.public_key.as_str()) {
        r.push(format!("the unsealed key is not the one sealed (public key differs from {})", m.public_key));
    }
    match (&f.plaintext, &f.runtime_sha) {
        (Plain::Regular { sha }, Some(rt)) if sha != rt => r.push(format!(
            "{} differs from the unsealed key — the key changed after sealing; reseal: `noo security at-rest seal`",
            f.default_path
        )),
        (Plain::Other(why), _) => r.push(format!("{}: {why}", f.default_path)),
        _ => {}
    }
    match &f.backup {
        None => r.push(format!(
            "no age-key backup (age-key_*.txt.enc) in {}: run scripts/backup-controller.sh, then finalize",
            f.backup_dir
        )),
        Some(b) if b.mtime_unix <= sealed_unix => r.push(format!(
            "the newest age-key backup ({}) predates the seal: run scripts/backup-controller.sh, then finalize",
            b.path
        )),
        Some(b) if f.now_unix - b.mtime_unix > BACKUP_MAX_AGE_SECS => r.push(format!(
            "the newest age-key backup ({}) is over 24 h old: run scripts/backup-controller.sh, then finalize",
            b.path
        )),
        Some(b) => match (&b.decrypted_sha, &f.runtime_sha) {
            (Err(e), _) => r.push(format!("the newest age-key backup ({}) does not decrypt: {e}", b.path)),
            (Ok(s), Some(rt)) if s != rt => r.push(format!(
                "the newest age-key backup ({}) holds a different key than the unsealed one",
                b.path
            )),
            _ => {}
        },
    }
    r
}

/// `systemctl show` output → key/value pairs.
pub(crate) fn parse_show(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

pub(crate) fn unit_boot_from(unit_show: &str, manager_show: &str) -> UnitBoot {
    let u = parse_show(unit_show);
    let m = parse_show(manager_show);
    let num = |map: &std::collections::HashMap<String, String>, k: &str| {
        map.get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
    };
    UnitBoot {
        active: u.get("ActiveState").map(|s| s == "active").unwrap_or(false),
        enter_mono_us: num(&u, "ActiveEnterTimestampMonotonic"),
        boot_finish_mono_us: num(&m, "FinishTimestampMonotonic"),
    }
}

/// `btime` from /proc/stat: when this boot started (unix seconds).
pub(crate) fn boot_unix_from(proc_stat: &str) -> Option<i64> {
    proc_stat.lines().find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse().ok()))
}

fn backup_dir() -> String {
    std::env::var("NOO_BACKUP_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("{}/noo-backups", std::env::var("HOME").unwrap_or_default()))
}

fn mtime_unix(p: &Path) -> Option<i64> {
    let t = std::fs::metadata(p).ok()?.modified().ok()?;
    t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs() as i64)
}

/// The newest `age-key_*.txt.enc` and what it decrypts to (hashed in memory).
fn newest_age_backup(dir: &str) -> Option<BackupFact> {
    let mut best: Option<(i64, PathBuf)> = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("age-key_") && name.ends_with(".txt.enc")) {
            continue;
        }
        let p = e.path();
        if let Some(t) = mtime_unix(&p) {
            if best.as_ref().map(|(bt, _)| t > *bt).unwrap_or(true) {
                best = Some((t, p));
            }
        }
    }
    let (mtime, path) = best?;
    Some(BackupFact { path: path.display().to_string(), mtime_unix: mtime, decrypted_sha: decrypt_backup_sha(&path) })
}

/// Decrypt the backup the way scripts/backup-controller.sh wrote it and
/// scripts/restore-drill.sh reads it — to a pipe, never a file.
fn decrypt_backup_sha(path: &Path) -> Result<String, String> {
    let pass = std::env::var("NOO_AGE_BACKUP_PASSPHRASE")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("NOO_AGE_BACKUP_PASSPHRASE_FILE")
                .ok()
                .and_then(|f| std::fs::read_to_string(f).ok())
                .map(|s| s.trim_end_matches(['\n', '\r']).to_string())
                .filter(|v| !v.is_empty())
        })
        .ok_or_else(|| "no NOO_AGE_BACKUP_PASSPHRASE (in the store, the env or _FILE)".to_string())?;
    let out = Command::new("openssl")
        .args(["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", "env:NOO_FINALIZE_BACKUP_PASS", "-in"])
        .arg(path)
        .env("NOO_FINALIZE_BACKUP_PASS", pass)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("could not run openssl: {e}"))?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err("openssl could not decrypt it with NOO_AGE_BACKUP_PASSPHRASE".to_string());
    }
    Ok(age_key::sha256_hex(&out.stdout))
}

fn plain_state(default: &Path, runtime: &str) -> Plain {
    match std::fs::symlink_metadata(default) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Plain::Absent,
        Err(e) => Plain::Other(format!("cannot read it ({e})")),
        Ok(md) if md.file_type().is_symlink() => match std::fs::read_link(default) {
            Ok(t) if t == Path::new(runtime) => Plain::LinkedToRuntime,
            Ok(t) => Plain::Other(format!("is a symlink to {}, not to {runtime}", t.display())),
            Err(e) => Plain::Other(format!("cannot read the link ({e})")),
        },
        Ok(md) if md.is_file() => match std::fs::read(default) {
            Ok(b) => Plain::Regular { sha: age_key::sha256_hex(&b) },
            Err(e) => Plain::Other(format!("cannot read it ({e})")),
        },
        Ok(_) => Plain::Other("is not a regular file".to_string()),
    }
}

fn systemctl_show(systemctl: &str, args: &[&str]) -> String {
    Command::new(systemctl)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn gather_finalize_facts() -> FinalizeFacts {
    let manifest = age_key::read_manifest();
    let runtime = manifest.as_ref().map(|m| m.runtime.clone()).unwrap_or_else(|| age_key::SEALED_RUNTIME_PATH.into());
    let default = age_key::default_path();
    let rt = std::fs::read(&runtime).ok();
    let runtime_sha = rt.as_deref().map(age_key::sha256_hex);
    let runtime_public = rt.as_deref().and_then(age_key::public_key_of);
    drop(rt);
    let sc = systemctl_bin();
    let unit = unit_boot_from(
        &systemctl_show(&sc, &["show", UNSEAL_UNIT, "--property=ActiveState,ActiveEnterTimestampMonotonic"]),
        &systemctl_show(&sc, &["show", "--property=FinishTimestampMonotonic"]),
    );
    let bdir = backup_dir();
    FinalizeFacts {
        sops_age_key_file: std::env::var("SOPS_AGE_KEY_FILE").ok().filter(|v| !v.trim().is_empty()),
        default_path: default.display().to_string(),
        plaintext: plain_state(&default, &runtime),
        runtime_sha,
        runtime_public,
        boot_unix: std::fs::read_to_string("/proc/stat").ok().as_deref().and_then(boot_unix_from),
        unit,
        backup: newest_age_backup(&bdir),
        backup_dir: bdir,
        now_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        manifest,
    }
}

/// `noo security at-rest finalize [--dry-run] [-y|--yes]`.
pub fn at_rest_finalize(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut yes = false;
    let mut dry = false;
    for a in args {
        match a.as_str() {
            "-y" | "--yes" => yes = true,
            "--dry-run" => dry = true,
            _ => return Err(Unhandled),
        }
    }
    refuse_unsupported_host(g);
    let f = gather_finalize_facts();
    let refusals = finalize_refusals(&f);
    if !refusals.is_empty() {
        if g.json {
            println!("{}", serde_json::json!({"finalized": false, "refusals": refusals}));
        } else {
            for r in &refusals {
                ui::failed(r, None);
            }
            ui::close_failed(
                "finalize refused: the plaintext age key was left exactly as it was",
                Some("noo security at-rest finalize --dry-run"),
            );
        }
        return Ok(1);
    }
    let m = f.manifest.clone().unwrap_or_default();
    let others = plaintext_copies(
        Path::new(&f.default_path).parent().unwrap_or(Path::new("/")),
        Path::new(&f.backup_dir),
    )
    .into_iter()
    .filter(|p| *p != f.default_path)
    .collect::<Vec<_>>();
    if dry {
        if g.json {
            println!("{}", serde_json::json!({"finalized": false, "dry_run": true, "refusals": [], "other_plaintext": others}));
        } else {
            ui::done(&format!(
                "every finalize check passes: sealed {} for {}, a boot unsealed it and a fresh backup decrypts to it",
                m.sealed_at, m.operator
            ));
        }
        return Ok(0);
    }
    if f.plaintext == Plain::LinkedToRuntime {
        if let Err(e) = crate::envfile::set_env_value("SOPS_AGE_KEY_FILE", Some(m.runtime.as_str())) {
            fail(g.json, ExitCode::Generic, "env_write", &e, None);
        }
        ui::done(&format!("already finalized: {} links to {}", f.default_path, m.runtime));
        return Ok(0);
    }
    crate::commands::confirm_prompt(
        g,
        yes,
        &format!("Shred the plaintext age key {} and link it to the sealed copy in RAM ({})?", f.default_path, m.runtime),
    );
    // 1. .env first: if anything below fails, every reader already looks in RAM.
    if let Err(e) = crate::envfile::set_env_value("SOPS_AGE_KEY_FILE", Some(m.runtime.as_str())) {
        fail(g.json, ExitCode::Generic, "env_write", &format!("{e} — nothing removed"), None);
    }
    // 2. The plaintext, if there is one.
    if let Plain::Regular { .. } = f.plaintext {
        let shredded = Command::new("shred").args(["-u", "--"]).arg(&f.default_path).status().map(|s| s.success()).unwrap_or(false);
        if !shredded {
            fail(
                g.json,
                ExitCode::Generic,
                "shred_failed",
                &format!("shred -u {} failed — the plaintext key is still there; .env already names {}", f.default_path, m.runtime),
                None,
            );
        }
    }
    // 3. The default path now leads to RAM, for every tool that reads it.
    if let Err(e) = std::os::unix::fs::symlink(&m.runtime, &f.default_path) {
        fail(
            g.json,
            ExitCode::Generic,
            "symlink_failed",
            &format!("the plaintext key is gone, but {} could not link to {} ({e}); SOPS_AGE_KEY_FILE in .env still points readers there", f.default_path, m.runtime),
            None,
        );
    }
    if g.json {
        println!(
            "{}",
            serde_json::json!({"finalized": true, "key_file": m.runtime, "linked": f.default_path, "other_plaintext": others})
        );
        return Ok(0);
    }
    ui::done(&format!("{} is now a symlink to {} (RAM); .env names it in SOPS_AGE_KEY_FILE", f.default_path, m.runtime));
    if !others.is_empty() {
        ui::warned(&format!(
            "other plaintext copies remain: {} — shred -u them once you no longer need them",
            others.join(", ")
        ));
    }
    ui::warned(
        "an SSD can keep the old blocks after shred: treat the old key as exposed and rotate the age key next (i10a)",
    );
    ui::close_done("Finalized: the age key is on disk only sealed to this machine's TPM");
    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────
// verify rows
// ─────────────────────────────────────────────────────────────────────────

/// Plaintext age-key copies on disk: the default key file (when it is a
/// regular file, not the finalize symlink), `keys.txt.*`, `keys.new`, and
/// non-`.enc` `age-key_*.txt` in the backup dir.
pub(crate) fn plaintext_copies(age_dir: &Path, backup_dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let regular = |p: &Path| std::fs::symlink_metadata(p).map(|m| m.is_file()).unwrap_or(false);
    if let Ok(rd) = std::fs::read_dir(age_dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if (n == "keys.txt" || n.starts_with("keys.txt.") || n == "keys.new") && regular(&e.path()) {
                out.push(e.path().display().to_string());
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(backup_dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("age-key_") && n.ends_with(".txt") && regular(&e.path()) {
                out.push(e.path().display().to_string());
            }
        }
    }
    out.sort();
    out
}

/// The filesystem type of the mount holding `path` (longest mount prefix).
pub(crate) fn fs_type_of(proc_mounts: &str, path: &str) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for line in proc_mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let mp = f[1].replace("\\040", " ");
        let covers = mp == "/" || path == mp || path.starts_with(&format!("{}/", mp.trim_end_matches('/')));
        if covers && best.as_ref().map(|(l, _)| mp.len() >= *l).unwrap_or(true) {
            best = Some((mp.len(), f[2].to_string()));
        }
    }
    best.map(|(_, t)| t)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum CredState {
    Present,
    Missing,
    /// The sealed dir is root 0700: an operator cannot see inside it.
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AgeKeyFacts {
    pub manifest: Manifest,
    pub cred: CredState,
    pub runtime_present: bool,
    pub runtime_fstype: Option<String>,
    pub plaintext: Vec<String>,
    pub default_path: String,
}

fn check(name: &'static str, verdict: Verdict, detail: String, remedy: Option<String>) -> Check {
    Check { name, verdict, detail, remedy }
}

/// The `age key at rest` row on a box whose manifest says sealed. Pure.
pub(crate) fn age_key_row(f: &AgeKeyFacts) -> Check {
    let m = &f.manifest;
    if f.cred == CredState::Missing {
        return check(
            AGE_ROW,
            Verdict::Warn,
            format!("the manifest says sealed but {} is missing — the next boot cannot unseal", m.cred),
            Some("reseal while the key is still readable: noo security at-rest seal".into()),
        );
    }
    if !f.runtime_present {
        return check(
            AGE_ROW,
            Verdict::Warn,
            format!("sealed to this machine's TPM, but not unsealed on this boot ({} is absent)", m.runtime),
            Some(format!("systemctl status {UNSEAL_UNIT}")),
        );
    }
    match f.runtime_fstype.as_deref() {
        Some("tmpfs") | Some("ramfs") => {}
        Some(other) => {
            return check(
                AGE_ROW,
                Verdict::Warn,
                format!("the unsealed key {} is on a {other} filesystem, not in RAM", m.runtime),
                Some(format!("systemctl cat {UNSEAL_UNIT} — /run must be a tmpfs")),
            )
        }
        None => {
            return check(
                AGE_ROW,
                Verdict::Warn,
                format!("could not tell which filesystem holds the unsealed key {}", m.runtime),
                None,
            )
        }
    }
    if !f.plaintext.is_empty() {
        let unfinalized = f.plaintext.iter().any(|p| *p == f.default_path);
        return check(
            AGE_ROW,
            Verdict::Warn,
            format!(
                "sealed to the TPM and unsealed into RAM, but plaintext copies remain on disk: {}",
                f.plaintext.join(", ")
            ),
            Some(if unfinalized {
                "after a reboot proved the unseal and a fresh backup: noo security at-rest finalize".into()
            } else {
                "shred -u those files, then rotate the age key (i10a)".into()
            }),
        );
    }
    let cred = match f.cred {
        CredState::Present => format!("{} present", m.cred),
        _ => format!("{} (root-only; not checked)", m.cred),
    };
    check(
        AGE_ROW,
        Verdict::Ok,
        format!(
            "sealed to this machine's TPM ({cred}, PCR policy {}); the live key is in RAM at {}; no plaintext copy on disk",
            if m.pcrs.is_empty() { "?" } else { m.pcrs.as_str() },
            m.runtime
        ),
        None,
    )
}

/// The live `age key at rest` row when the manifest says sealed; `None`
/// otherwise (the directory-based row then stands).
pub(crate) fn sealed_age_key_row(proc_mounts: &str) -> Option<Check> {
    let manifest = age_key::sealed_manifest()?;
    let cred = match std::fs::metadata(&manifest.cred) {
        Ok(_) => CredState::Present,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CredState::Missing,
        Err(_) => CredState::Unknown,
    };
    let runtime_present = Path::new(&manifest.runtime).is_file();
    let default = age_key::default_path();
    let facts = AgeKeyFacts {
        cred,
        runtime_present,
        runtime_fstype: if runtime_present { fs_type_of(proc_mounts, &manifest.runtime) } else { None },
        plaintext: plaintext_copies(default.parent().unwrap_or(Path::new("/")), Path::new(&backup_dir())),
        default_path: default.display().to_string(),
        manifest,
    };
    Some(age_key_row(&facts))
}

/// The `at-rest pcr binding` row: the policy sealed vs the Secure Boot state
/// now. Pure.
pub(crate) fn pcr_binding_row(m: &Manifest, sb_now: Option<bool>) -> Check {
    let Some(now) = sb_now else {
        return check(
            PCR_ROW,
            Verdict::Warn,
            format!("could not read Secure Boot's state now (sealed with PCR policy {})", m.pcrs),
            None,
        );
    };
    let onoff = |b: bool| if b { "on" } else { "off" };
    let changed = m.secure_boot_known && now != m.secure_boot_at_seal;
    if m.pcrs == "7" && changed {
        return check(
            PCR_ROW,
            Verdict::Warn,
            format!(
                "bound to PCR 7 with Secure Boot {} at sealing, {} now — the next boot will not unseal; reseal or use the recovery path",
                onoff(m.secure_boot_at_seal),
                onoff(now)
            ),
            Some("while the key is still unsealed: noo security at-rest seal".into()),
        );
    }
    if m.pcrs == "7" {
        return check(PCR_ROW, Verdict::Ok, format!("bound to PCR 7; Secure Boot {} now, as at sealing", onoff(now)), None);
    }
    if now {
        return check(
            PCR_ROW,
            Verdict::Warn,
            "TPM-only (no PCR) though Secure Boot is on now — a changed boot chain is not detected; reseal to bind PCR 7".to_string(),
            Some("noo security at-rest seal".into()),
        );
    }
    check(
        PCR_ROW,
        Verdict::Warn,
        "TPM-only (Secure Boot off): the drive alone does not decrypt elsewhere, but a live-USB boot of this machine is not blocked from unsealing".to_string(),
        Some("turn Secure Boot on in the firmware, then: noo security at-rest seal".into()),
    )
}

/// The live `at-rest pcr binding` row; `None` when nothing is sealed.
pub(crate) fn pcr_binding_row_live() -> Option<Check> {
    let m = age_key::sealed_manifest()?;
    Some(pcr_binding_row(&m, age_key::secure_boot_now()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RT: &str = "/run/noo/keys/age.txt";
    const DEF: &str = "/home/op/.config/sops/age/keys.txt";
    const SEALED_AT: i64 = 1_800_000_000;

    fn manifest() -> Manifest {
        Manifest {
            sealed: true,
            cred: age_key::SEALED_CRED_PATH.into(),
            runtime: RT.into(),
            public_key: "age1pub".into(),
            pcrs: "7".into(),
            secure_boot_at_seal: true,
            secure_boot_known: true,
            sealed_at: "2027-01-15T08:00:00Z".into(),
            sealed_unix: Some(SEALED_AT),
            operator: "op".into(),
        }
    }

    /// Everything a finalize needs, true: rebooted an hour after sealing, the
    /// unit active during boot, a backup from ten minutes ago that decrypts to
    /// the unsealed key.
    fn good() -> FinalizeFacts {
        FinalizeFacts {
            manifest: Some(manifest()),
            sops_age_key_file: None,
            default_path: DEF.into(),
            runtime_sha: Some("aaaa".into()),
            runtime_public: Some("age1pub".into()),
            plaintext: Plain::Regular { sha: "aaaa".into() },
            boot_unix: Some(SEALED_AT + 3600),
            unit: UnitBoot { active: true, enter_mono_us: 4_000_000, boot_finish_mono_us: 30_000_000 },
            backup_dir: "/home/op/noo-backups".into(),
            backup: Some(BackupFact {
                path: "/home/op/noo-backups/age-key_x.txt.enc".into(),
                mtime_unix: SEALED_AT + 7200,
                decrypted_sha: Ok("aaaa".into()),
            }),
            now_unix: SEALED_AT + 7800,
        }
    }

    fn refused(f: &FinalizeFacts, needle: &str) {
        let r = finalize_refusals(f);
        assert!(r.iter().any(|x| x.contains(needle)), "want a refusal containing {needle:?}, got {r:?}");
    }

    #[test]
    fn finalize_goes_only_when_everything_holds() {
        assert!(finalize_refusals(&good()).is_empty(), "{:?}", finalize_refusals(&good()));
    }

    #[test]
    fn finalize_refuses_without_a_reboot_since_the_seal() {
        let mut f = good();
        f.boot_unix = Some(SEALED_AT - 60);
        refused(&f, "no reboot since sealing");
        f.boot_unix = None;
        refused(&f, "btime");
    }

    #[test]
    fn finalize_refuses_a_unit_started_by_hand_or_not_at_all() {
        let mut f = good();
        f.unit.enter_mono_us = 40_000_000; // after the boot finished
        refused(&f, "started after boot");
        f.unit = UnitBoot { active: false, enter_mono_us: 0, boot_finish_mono_us: 30_000_000 };
        refused(&f, "has not run on this boot");
        f.unit = UnitBoot { active: true, enter_mono_us: 4_000_000, boot_finish_mono_us: 0 };
        refused(&f, "started after boot");
    }

    #[test]
    fn finalize_refuses_when_the_key_is_not_in_ram() {
        let mut f = good();
        f.runtime_sha = None;
        f.runtime_public = None;
        refused(&f, "not unsealed on this boot");
    }

    #[test]
    fn finalize_refuses_without_a_fresh_verified_backup() {
        let mut f = good();
        f.backup = None;
        refused(&f, "no age-key backup");
        let mut f = good();
        f.backup.as_mut().unwrap().mtime_unix = SEALED_AT - 1;
        refused(&f, "predates the seal");
        let mut f = good();
        f.now_unix = f.backup.as_ref().unwrap().mtime_unix + BACKUP_MAX_AGE_SECS + 1;
        refused(&f, "over 24 h old");
        let mut f = good();
        f.backup.as_mut().unwrap().decrypted_sha = Err("no NOO_AGE_BACKUP_PASSPHRASE".into());
        refused(&f, "does not decrypt");
        let mut f = good();
        f.backup.as_mut().unwrap().decrypted_sha = Ok("bbbb".into());
        refused(&f, "different key");
    }

    #[test]
    fn finalize_refuses_a_changed_or_foreign_key() {
        let mut f = good();
        f.plaintext = Plain::Regular { sha: "cccc".into() };
        refused(&f, "differs from the unsealed key");
        let mut f = good();
        f.runtime_public = Some("age1other".into());
        refused(&f, "not the one sealed");
        let mut f = good();
        f.sops_age_key_file = Some("/srv/elsewhere/keys.txt".into());
        refused(&f, "SOPS_AGE_KEY_FILE names");
        // The runtime path itself (a re-run after finalize) is fine.
        let mut f = good();
        f.sops_age_key_file = Some(RT.into());
        f.plaintext = Plain::LinkedToRuntime;
        assert!(finalize_refusals(&f).is_empty(), "{:?}", finalize_refusals(&f));
    }

    #[test]
    fn finalize_refuses_when_nothing_is_sealed() {
        let mut f = good();
        f.manifest = None;
        refused(&f, "not sealed here");
        let mut f = good();
        f.manifest.as_mut().unwrap().sealed = false;
        refused(&f, "not sealed here");
    }

    #[test]
    fn systemctl_show_and_btime_parse() {
        let u = unit_boot_from(
            "ActiveState=active\nActiveEnterTimestampMonotonic=4123456\n",
            "FinishTimestampMonotonic=31000000\n",
        );
        assert_eq!(u, UnitBoot { active: true, enter_mono_us: 4_123_456, boot_finish_mono_us: 31_000_000 });
        assert_eq!(unit_boot_from("", ""), UnitBoot::default());
        assert_eq!(boot_unix_from("cpu  1 2 3\nbtime 1800003600\nprocesses 9\n"), Some(1_800_003_600));
        assert_eq!(boot_unix_from("cpu 1\n"), None);
    }

    fn row_facts() -> AgeKeyFacts {
        AgeKeyFacts {
            manifest: manifest(),
            cred: CredState::Unknown,
            runtime_present: true,
            runtime_fstype: Some("tmpfs".into()),
            plaintext: vec![],
            default_path: DEF.into(),
        }
    }

    #[test]
    fn age_key_row_ok_only_when_sealed_in_ram_and_no_plaintext() {
        let c = age_key_row(&row_facts());
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(c.name, "age key at rest");

        let mut f = row_facts();
        f.plaintext = vec![DEF.into()];
        let c = age_key_row(&f);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.remedy.unwrap().contains("noo security at-rest finalize"));

        let mut f = row_facts();
        f.plaintext = vec!["/home/op/noo-backups/age-key_1.txt".into(), "/home/op/.config/sops/age/keys.txt.bak".into()];
        let c = age_key_row(&f);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("age-key_1.txt") && c.remedy.unwrap().contains("shred -u"));

        let mut f = row_facts();
        f.runtime_present = false;
        assert!(age_key_row(&f).remedy.unwrap().contains("noo-unseal.service"));

        let mut f = row_facts();
        f.runtime_fstype = Some("ext4".into());
        assert_eq!(age_key_row(&f).verdict, Verdict::Warn);

        let mut f = row_facts();
        f.cred = CredState::Missing;
        assert_eq!(age_key_row(&f).verdict, Verdict::Warn);
    }

    #[test]
    fn pcr_row_warns_when_secure_boot_changed_since_sealing() {
        let m = manifest();
        assert_eq!(pcr_binding_row(&m, Some(true)).verdict, Verdict::Ok);
        let c = pcr_binding_row(&m, Some(false));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("the next boot will not unseal; reseal or use the recovery path"), "{}", c.detail);
        assert_eq!(c.name, "at-rest pcr binding");
        assert_eq!(pcr_binding_row(&m, None).verdict, Verdict::Warn);

        let mut tpm_only = manifest();
        tpm_only.pcrs = "none".into();
        tpm_only.secure_boot_at_seal = false;
        let c = pcr_binding_row(&tpm_only, Some(false));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("live-USB boot"), "{}", c.detail);
        assert!(pcr_binding_row(&tpm_only, Some(true)).detail.contains("reseal to bind PCR 7"));
    }

    #[test]
    fn fs_type_picks_the_longest_mount() {
        let mounts = "/dev/sda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/sdb1 /run/media ext4 rw 0 0\n";
        assert_eq!(fs_type_of(mounts, "/run/noo/keys/age.txt").as_deref(), Some("tmpfs"));
        assert_eq!(fs_type_of(mounts, "/run/media/x").as_deref(), Some("ext4"));
        assert_eq!(fs_type_of(mounts, "/home/op/x").as_deref(), Some("ext4"));
        assert_eq!(fs_type_of("", "/x"), None);
    }

    #[test]
    fn plaintext_copies_finds_the_named_shapes_only() {
        let t = std::env::temp_dir().join(format!("noo-atrest-{}", std::process::id()));
        let age = t.join("age");
        let bk = t.join("bk");
        std::fs::create_dir_all(&age).unwrap();
        std::fs::create_dir_all(&bk).unwrap();
        for n in ["keys.txt", "keys.txt.bak", "keys.new", "other.txt"] {
            std::fs::write(age.join(n), "x").unwrap();
        }
        for n in ["age-key_1.txt", "age-key_2.txt.enc", "pg_1.sql.gz.enc"] {
            std::fs::write(bk.join(n), "x").unwrap();
        }
        let got = plaintext_copies(&age, &bk);
        let names: Vec<String> = got.iter().map(|p| Path::new(p).file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["age-key_1.txt", "keys.new", "keys.txt", "keys.txt.bak"], "{got:?}");
        // The finalize symlink is not a plaintext copy.
        std::fs::remove_file(age.join("keys.txt")).unwrap();
        std::os::unix::fs::symlink(RT, age.join("keys.txt")).unwrap();
        assert!(!plaintext_copies(&age, &bk).iter().any(|p| p.ends_with("/keys.txt")));
        let _ = std::fs::remove_dir_all(&t);
    }
}
