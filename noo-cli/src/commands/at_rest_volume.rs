// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! At-rest encryption, part C (i10a): the sensitive state set on a
//! file-backed LUKS2 volume that this machine's TPM unlocks at boot.
//!
//! - `noo security at-rest create-volume` runs the root half,
//!   `sudo /usr/local/bin/noo-hostd at-rest create-volume …`
//!   (node-agent-go/internal/hostd/atrest_volume_linux.go), reads its one
//!   JSON line over a pipe, and shows the recovery key ONCE, on a terminal
//!   only: the person retypes its first and last groups, then the person-only
//!   setting [`RECOVERY_SETTING`] records who acknowledged it and when. With
//!   no terminal it refuses unless `--defer-recovery-key` (TPM-only until a
//!   later 0.6.11 step makes one).
//! - [`setup_fresh`] is what a fresh `noo onboard` runs when the person says
//!   yes: the volume BEFORE any service starts, then `NOO_STATE_ROOT` and
//!   `NOO_PKI_DIR` point at it. Its steps are a trait so the order is pinned
//!   by tests without a TPM.
//! - `noo config launch-check state-root` ([`launch_check`]) refuses to start
//!   the stack when this install's state root is the volume and the volume is
//!   not open and mounted (scripts/lib-state-volume.sh, every launcher and
//!   hostd's boot restore).
//! - The verify rows `at-rest volume` and `at-rest recovery key`.
//!
//! The recovery key is never written to a file, never logged, never put in
//! JSON output, and never sent anywhere: it lives in this process's memory
//! between the pipe and the terminal, and is overwritten on drop.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::commands::at_rest::{AcceptedState, TpmFacts};
use crate::commands::cluster_verify::{Check, Verdict};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// The person-only, db_only setting that records that the recovery key was
/// shown and the person confirmed storing it. Registered in
/// `gateway-rust/src/routes/settings.rs` (`AT_REST_RECOVERY_KEY_ACKNOWLEDGED`).
pub(crate) const RECOVERY_SETTING: &str = "at_rest.recovery_key_acknowledged";
/// The dm-crypt mapping and its device.
pub(crate) const MAPPER: &str = "noo-state";
pub(crate) const MAPPER_PATH: &str = "/dev/mapper/noo-state";
/// The unit systemd generates for the crypttab line.
pub(crate) const CRYPTSETUP_UNIT: &str = r"systemd-cryptsetup@noo\x2dstate.service";
/// The recovery runbook (written with the recovery-key verbs, i10a PR-E).
pub(crate) const RUNBOOK: &str = "docs/operating/runbooks/at-rest-recovery.md";
/// Where the root helper lives; `NOO_HOSTD_BIN` overrides it.
pub(crate) const HOSTD_BIN: &str = "/usr/local/bin/noo-hostd";
/// Operator decision 2026-10-23: about 2x the current state, at least 50 GiB.
pub(crate) const MIN_SIZE_GIB: u64 = 50;
/// Kept free beside the volume (hostd refuses below it too).
pub(crate) const MARGIN_GIB: u64 = 5;
pub(crate) const VOLUME_ROW: &str = "at-rest volume";
pub(crate) const RECOVERY_ROW: &str = "at-rest recovery key";
/// Exit code of `noo config launch-check state-root` when it refuses — the
/// code the other launch checks use, so the shell can tell a refusal from an
/// older `noo` that lacks the verb.
pub(crate) const LAUNCH_REFUSED: i32 = 3;

const GIB: u64 = 1 << 30;

fn etc_noo() -> PathBuf {
    std::env::var("NOO_ETC_NOO")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/noo"))
}

pub(crate) fn hostd_bin_path() -> String {
    hostd_bin()
}

fn hostd_bin() -> String {
    std::env::var("NOO_HOSTD_BIN").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| HOSTD_BIN.to_string())
}

// ── the manifest (/etc/noo/at-rest.json, shared with PR-B) ──────────────

/// The volume as `noo-hostd at-rest create-volume` recorded it. No secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Volume {
    pub file: String,
    pub mountpoint: String,
    pub size_gib: u64,
    /// "7" or "none".
    pub pcrs: String,
    /// "enrolled" or "deferred".
    pub recovery: String,
    pub created_at: String,
}

/// The volume fields of a parsed manifest; `None` when it records none.
pub(crate) fn volume_from_manifest(v: &Value) -> Option<Volume> {
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    let file = s("volume_file");
    let mountpoint = s("volume_mountpoint");
    if file.is_empty() || mountpoint.is_empty() {
        return None;
    }
    Some(Volume {
        file,
        mountpoint: mountpoint.trim_end_matches('/').to_string(),
        size_gib: v["volume_size_gib"].as_u64().unwrap_or(0),
        pcrs: s("volume_pcrs"),
        recovery: s("volume_recovery_key"),
        created_at: s("volume_created_at"),
    })
}

/// This machine's volume, from the manifest. `None` when there is no
/// manifest, it records no volume, or it does not parse.
pub(crate) fn read_volume() -> Option<Volume> {
    let text = std::fs::read_to_string(etc_noo().join("at-rest.json")).ok()?;
    volume_from_manifest(&serde_json::from_str::<Value>(&text).ok()?)
}

/// The volume size for a state set of `state_bytes`: about twice it, in
/// whole GiB, and never under [`MIN_SIZE_GIB`].
pub(crate) fn size_for(state_bytes: u64) -> u64 {
    let twice = state_bytes.saturating_mul(2);
    twice.div_ceil(GIB).max(MIN_SIZE_GIB)
}

// ── is it open? ─────────────────────────────────────────────────────────

/// Is `mountpoint` mounted (the visible, last mount there) from the noo-state
/// mapping? `/proc/mounts` names it `/dev/mapper/noo-state`, or `/dev/dm-N`
/// whose dm name `dm_name("dm-N")` is `noo-state`.
pub(crate) fn mounted_from_mapper(proc_mounts: &str, mountpoint: &str, dm_name: &dyn Fn(&str) -> Option<String>) -> bool {
    let want = mountpoint.trim_end_matches('/');
    let mut last: Option<String> = None;
    for line in proc_mounts.lines() {
        let mut it = line.split_whitespace();
        let (Some(dev), Some(mp)) = (it.next(), it.next()) else { continue };
        if mp.replace("\\040", " ").trim_end_matches('/') == want {
            last = Some(dev.to_string());
        }
    }
    match last {
        Some(dev) if dev == MAPPER_PATH => true,
        Some(dev) => dev.strip_prefix("/dev/").and_then(dm_name).is_some_and(|n| n.trim() == MAPPER),
        None => false,
    }
}

/// `/sys/block/<dm-N>/dm/name`.
pub(crate) fn dm_name_live(dev: &str) -> Option<String> {
    if !dev.starts_with("dm-") || dev.contains('/') {
        return None;
    }
    std::fs::read_to_string(format!("/sys/block/{dev}/dm/name")).ok()
}

/// Whether the install's state root is the volume (or under it).
pub(crate) fn state_on_volume(state_root: &str, v: &Volume) -> bool {
    let s = state_root.trim_end_matches('/');
    let m = v.mountpoint.trim_end_matches('/');
    s == m || s.starts_with(&format!("{m}/"))
}

/// What the launchers print when they refuse, or `None` when the stack may
/// start: no volume recorded, the state root is not on it (the install was
/// not switched to it yet), or it is mounted from the mapping.
pub(crate) fn launch_refusal(
    v: Option<&Volume>,
    state_root: &str,
    proc_mounts: &str,
    dm_name: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let v = v?;
    if !state_on_volume(state_root, v) || mounted_from_mapper(proc_mounts, &v.mountpoint, dm_name) {
        return None;
    }
    Some(format!(
        "REFUSED: not starting — the encrypted state volume is not open: {mp} is not mounted from {MAPPER_PATH}.\n  \
         This install's state (NOO_STATE_ROOT={state_root}) lives on it; started now, the services would find an empty directory. \
         Nothing was changed and no container was touched.\n  \
         check: systemctl status '{CRYPTSETUP_UNIT}'\n  \
         recovery: {RUNBOOK} — by hand, with the recovery key: sudo cryptsetup open {file} {MAPPER} && sudo mount {mp}",
        mp = v.mountpoint,
        file = v.file,
    ))
}

/// The state root the launcher will hand compose: the environment first
/// (the launcher exports `noomesh.yaml`'s compose_env), then `<root>/.env`,
/// exactly `${NOO_STATE_ROOT:-${NOO_DATA_ROOT}}` (scripts/lib-instance.sh).
pub(crate) fn resolve_state_root(env: &dyn Fn(&str) -> Option<String>) -> String {
    let data = env("NOO_DATA_ROOT")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.to_string());
    crate::commands::data_root::state_root_of(env("NOO_STATE_ROOT").as_deref(), data.trim().trim_end_matches('/'))
}

/// `noo config launch-check state-root [<install-root>]` — hidden, called by
/// `scripts/lib-state-volume.sh` `check_state_volume_open` in every launcher
/// and by hostd's boot restore. Exit 0 = may start; [`LAUNCH_REFUSED`] =
/// refused, the reason on stderr.
pub fn launch_check(args: &[String]) -> i32 {
    let root = args.first().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let env_file = root.join(".env");
    let env = |k: &str| -> Option<String> {
        std::env::var(k)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| Some(crate::onboard::env::read_env_key(&env_file, k)).filter(|v| !v.trim().is_empty()))
    };
    let state_root = resolve_state_root(&env);
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    match launch_refusal(read_volume().as_ref(), &state_root, &mounts, &dm_name_live) {
        None => 0,
        Some(msg) => {
            eprintln!("{msg}");
            LAUNCH_REFUSED
        }
    }
}

// ── verify rows ─────────────────────────────────────────────────────────

/// A flag row from `GET /api/settings/flags`, any key.
pub(crate) fn flag_from(body: &Value, key: &str) -> Option<AcceptedState> {
    let row = body["flags"].as_array()?.iter().find(|f| f["key"] == key)?;
    Some(AcceptedState {
        accepted: row["value"].as_bool()?,
        source: row["source"].as_str().unwrap_or("unknown").to_string(),
        updated_by: row["updated_by"].as_str().map(str::to_string),
        updated_at: row["updated_at"].as_str().map(str::to_string),
    })
}

fn check(name: &'static str, verdict: Verdict, detail: String, remedy: Option<String>) -> Check {
    Check { name, verdict, detail, remedy }
}

/// What the live mapping looks like, for [`volume_check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Live {
    /// `/dev/mapper/noo-state` exists.
    pub open: bool,
    /// The mountpoint is mounted from it.
    pub mounted: bool,
    /// Free bytes on the mounted volume, when it is.
    pub free: Option<u64>,
}

/// The `at-rest volume` row.
///
/// - no volume recorded: ACCEPTED when the person opted out, WARN with the
///   reason when there is no usable TPM, else WARN naming create-volume;
/// - recorded but not open or not mounted: FAIL (the launchers refuse too);
/// - open and mounted but the state root is elsewhere: WARN (not moved yet);
/// - open, mounted, and the state root on it: OK with size and free space.
pub(crate) fn volume_check(
    v: Option<&Volume>,
    live: Live,
    state_root: &str,
    decision: Option<&AcceptedState>,
    tpm: &TpmFacts,
) -> Check {
    let Some(v) = v else {
        if let Some(d) = decision.filter(|d| d.accepted) {
            return check(
                VOLUME_ROW,
                Verdict::Accepted,
                crate::commands::cluster_verify::accepted_detail(d, &format!("the state set at {state_root}")),
                None,
            );
        }
        if !tpm.tpm2_usable() {
            return check(
                VOLUME_ROW,
                Verdict::Warn,
                format!("no encrypted state volume: it cannot be made here ({}); the state set at {state_root} is in the clear", tpm.unavailable_reason()),
                Some(crate::commands::at_rest::enable_hint(tpm)),
            );
        }
        return check(
            VOLUME_ROW,
            Verdict::Warn,
            format!("no encrypted state volume on this controller; the state set at {state_root} is in the clear"),
            Some("noo security at-rest create-volume".into()),
        );
    };
    if !live.open || !live.mounted {
        let what = if !live.open { format!("not open ({MAPPER_PATH} is absent)") } else { format!("open but not mounted at {}", v.mountpoint) };
        return check(
            VOLUME_ROW,
            Verdict::Fail,
            format!("the manifest records the encrypted volume {} and it is {what}", v.file),
            Some(format!("systemctl status '{CRYPTSETUP_UNIT}'; recovery: {RUNBOOK}")),
        );
    }
    let free = live.free.map(|b| format!(", {} GiB free", b / GIB)).unwrap_or_default();
    let policy = if v.pcrs == "7" { "bound to PCR 7 (Secure Boot)".to_string() } else { "TPM-only (a live-USB boot of this machine is not blocked)".to_string() };
    if !state_on_volume(state_root, v) {
        return check(
            VOLUME_ROW,
            Verdict::Warn,
            format!(
                "{MAPPER_PATH} is open and mounted at {} ({} GiB{free}), but this install's state root is {state_root}: the state is not on it yet",
                v.mountpoint, v.size_gib
            ),
            Some("noo security at-rest migrate --dry-run".into()),
        );
    }
    check(
        VOLUME_ROW,
        Verdict::Ok,
        format!("{MAPPER_PATH} open, mounted at {} ({} GiB{free}); unlocked by this machine's TPM, {policy}", v.mountpoint, v.size_gib),
        None,
    )
}

/// The `at-rest recovery key` row.
pub(crate) fn recovery_check(v: Option<&Volume>, ack: Option<&AcceptedState>) -> Check {
    let Some(v) = v else {
        return check(RECOVERY_ROW, Verdict::Ok, "no encrypted state volume here, so no recovery key".into(), None);
    };
    let later = "noo security at-rest recovery-key   (makes a new one; store it off this machine)";
    if v.recovery == "deferred" {
        return check(
            RECOVERY_ROW,
            Verdict::Warn,
            format!(
                "deferred: {} unlocks by this machine's TPM only — if the TPM, the firmware or (with PCR 7) the boot chain changes, the data cannot be opened",
                v.file
            ),
            Some(later.into()),
        );
    }
    match ack {
        Some(a) if a.accepted => check(
            RECOVERY_ROW,
            Verdict::Ok,
            format!(
                "shown once at creation and acknowledged by {} at {}",
                a.updated_by.as_deref().unwrap_or("an unknown person"),
                a.updated_at.as_deref().unwrap_or("an unknown time")
            ),
            None,
        ),
        Some(_) => check(
            RECOVERY_ROW,
            Verdict::Warn,
            format!("a recovery key was enrolled at {} but nobody acknowledged storing it off this machine", v.created_at),
            Some(later.into()),
        ),
        None => check(
            RECOVERY_ROW,
            Verdict::Warn,
            "could not read whether the recovery key was acknowledged (the gateway did not answer, or predates the setting)".into(),
            None,
        ),
    }
}

/// Free bytes on the filesystem holding `path` (statvfs). The field types
/// differ by platform, hence the casts.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn free_bytes(path: &str) -> Option<u64> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Both rows, read live (cluster verify --controller).
pub(crate) fn rows_live(proc_mounts: &str, flags: Option<&Value>, decision: Option<&AcceptedState>, tpm: &TpmFacts) -> Vec<Check> {
    let v = read_volume();
    let state_root = resolve_state_root(&|k| std::env::var(k).ok());
    let live = match &v {
        Some(v) => {
            let mounted = mounted_from_mapper(proc_mounts, &v.mountpoint, &dm_name_live);
            Live { open: Path::new(MAPPER_PATH).exists(), mounted, free: if mounted { free_bytes(&v.mountpoint) } else { None } }
        }
        None => Live { open: false, mounted: false, free: None },
    };
    let ack = flags.and_then(|b| flag_from(b, RECOVERY_SETTING));
    let mut rows = vec![volume_check(v.as_ref(), live, &state_root, decision, tpm), recovery_check(v.as_ref(), ack.as_ref())];
    rows.extend(crate::commands::at_rest_recovery::volume_binding_check(v.as_ref(), tpm.secure_boot));
    rows
}

// ── the root half: plan, argv, result ───────────────────────────────────

/// What `noo-hostd at-rest create-volume` is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatePlan {
    pub data_root: String,
    pub size_gib: u64,
    pub user: String,
    pub pcrs: String,
    /// `name` or `name=uid:gid`.
    pub subdirs: Vec<String>,
    pub age_key: Option<String>,
    pub pki_from: Option<String>,
    pub defer: bool,
}

/// The state subdirectories, with the owners onboard gives them
/// (`onboard::steps::subdir_owner`), as `--subdir` values.
pub(crate) fn state_subdir_specs() -> Vec<String> {
    crate::onboard::STATE_SUBDIRS
        .iter()
        .map(|n| match crate::onboard::steps::subdir_owner(n) {
            Some(owner) => format!("{n}={owner}"),
            None => n.to_string(),
        })
        .collect()
}

/// `noo-hostd at-rest create-volume …` (run under sudo).
pub(crate) fn hostd_argv(hostd: &str, p: &CreatePlan) -> Vec<String> {
    let mut a: Vec<String> = vec![
        hostd.into(),
        "at-rest".into(),
        "create-volume".into(),
        "--data-root".into(),
        p.data_root.trim_end_matches('/').to_string(),
        "--size".into(),
        p.size_gib.to_string(),
        "--user".into(),
        p.user.clone(),
        "--pcrs".into(),
        p.pcrs.clone(),
    ];
    for s in &p.subdirs {
        a.push("--subdir".into());
        a.push(s.clone());
    }
    if let Some(k) = &p.age_key {
        a.push("--age-key".into());
        a.push(k.clone());
    }
    if let Some(d) = &p.pki_from {
        a.push("--pki-from".into());
        a.push(d.clone());
    }
    if p.defer {
        a.push("--defer-recovery-key".into());
    }
    a
}

/// What create-volume reported. Deliberately NOT `Debug`: it holds the
/// recovery key, which is overwritten when this is dropped.
pub(crate) struct Created {
    pub recovery_key: Option<String>,
    pub deferred: bool,
    pub file: String,
    pub mountpoint: String,
    pub pcrs: String,
    pub pcr_note: String,
    pub pki_dir: String,
    pub age_escrow: String,
}

impl Drop for Created {
    fn drop(&mut self) {
        if let Some(k) = self.recovery_key.as_mut() {
            // SAFETY: zero bytes are valid UTF-8.
            unsafe { k.as_bytes_mut() }.fill(0);
        }
    }
}

/// Parse create-volume's stdout: its last non-empty line is one JSON object
/// with `"ok": true`. The error never echoes stdout (it may hold the key).
pub(crate) fn parse_created(stdout: &[u8]) -> Result<Created, String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().rev().find(|l| !l.trim().is_empty()).ok_or("create-volume printed no result")?;
    let v: Value = serde_json::from_str(line.trim()).map_err(|_| "create-volume's result line is not JSON".to_string())?;
    if v["ok"] != true {
        return Err("create-volume did not report success".into());
    }
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    let deferred = v["recovery_key_deferred"].as_bool().unwrap_or(false);
    let key = Some(s("recovery_key")).filter(|k| !k.is_empty());
    if !deferred && key.is_none() {
        return Err("create-volume reported no recovery key and did not say it was deferred".into());
    }
    let mountpoint = s("volume_mountpoint");
    if mountpoint.is_empty() {
        return Err("create-volume reported no mountpoint".into());
    }
    Ok(Created {
        recovery_key: key,
        deferred,
        file: s("volume_file"),
        mountpoint,
        pcrs: s("volume_pcrs"),
        pcr_note: s("pcr_note"),
        pki_dir: s("pki_dir"),
        age_escrow: s("age_key_escrow"),
    })
}

/// Run `sudo <argv>`: stdout piped (the result line, never shown), stdin
/// inherited (sudo's password prompt uses the terminal) unless `sudo_n`.
/// Returns the result and whatever stderr was captured (empty when
/// `inherit_stderr`).
pub(crate) fn run_hostd(argv: &[String], sudo_n: bool, inherit_stderr: bool) -> (Result<Created, String>, String) {
    let mut cmd = Command::new("sudo");
    if sudo_n {
        cmd.arg("-n").stdin(Stdio::null());
    } else {
        cmd.stdin(Stdio::inherit());
    }
    cmd.args(argv).stdout(Stdio::piped());
    cmd.stderr(if inherit_stderr { Stdio::inherit() } else { Stdio::piped() });
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => return (Err(format!("could not run sudo: {e}")), String::new()),
    };
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        let code = out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "a signal".into());
        return (Err(format!("noo-hostd at-rest create-volume failed (exit {code}); its reason is above, and it undid what it had made")), stderr);
    }
    let mut stdout = out.stdout;
    let r = parse_created(&stdout);
    stdout.fill(0);
    (r, stderr)
}

/// The first and last groups of a recovery key, the two the person retypes.
pub(crate) fn key_groups(key: &str) -> Option<(&str, &str)> {
    let mut g = key.split('-');
    let first = g.next()?;
    let last = key.rsplit('-').next()?;
    if first.is_empty() || last.is_empty() || first.len() == key.len() {
        return None;
    }
    Some((first, last))
}

/// Did the person retype the first and last groups correctly?
pub(crate) fn retyped_ok(key: &str, first: &str, last: &str) -> bool {
    match key_groups(key) {
        Some((f, l)) => first.trim().eq_ignore_ascii_case(f) && last.trim().eq_ignore_ascii_case(l),
        None => false,
    }
}

/// What the person is told above the key.
pub(crate) const RECOVERY_KEY_WARNING: &str = "This recovery key opens the encrypted state volume when the TPM cannot (a firmware or boot-chain change, a new motherboard, a moved disk). It is shown ONCE and is not stored anywhere on this machine. Write it down or put it in a password manager OFF this machine now.";

// ── fresh onboard ───────────────────────────────────────────────────────

/// The onboard side of a fresh setup, as a trait so the order is testable.
pub(crate) trait FreshSteps {
    /// The volume this machine already has, if any (the manifest).
    fn existing_volume(&self) -> Option<Volume>;
    /// A state directory that already holds data (not a fresh install).
    fn state_in_use(&self) -> Option<String>;
    fn free_bytes(&self, path: &str) -> Option<u64>;
    /// A private terminal the key can be shown on (the plain console).
    fn can_show_secret(&self) -> bool;
    fn create_volume(&mut self, plan: &CreatePlan) -> Result<Created, String>;
    /// Show the key once and have the person retype it; true = acknowledged.
    fn show_recovery_key(&mut self, key: &str) -> bool;
    fn read_env(&self, key: &str) -> String;
    fn set_env(&mut self, key: &str, value: &str);
}

/// What [`setup_fresh`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FreshOutcome {
    /// The volume was made and `.env` points the state root and PKI at it.
    Created { state_root: String, acknowledged: bool, deferred: bool },
    /// This data root already has its volume; `.env` points at it.
    AlreadyThere { state_root: String },
    /// Nothing was done, and why (said to the person; not a failure).
    Skipped(String),
}

/// The fresh-onboard "yes": the volume BEFORE any service starts, so nothing
/// is ever written in the clear; then `NOO_STATE_ROOT` and `NOO_PKI_DIR` (and
/// the TLS paths under the old PKI dir) point at it. An `Err` stops onboard:
/// it never carries on unencrypted after the person said yes.
pub(crate) fn setup_fresh(s: &mut dyn FreshSteps, mut plan: CreatePlan) -> Result<FreshOutcome, String> {
    let want = format!("{}/state", plan.data_root.trim_end_matches('/'));
    if let Some(v) = s.existing_volume() {
        if v.mountpoint == want {
            if s.read_env("NOO_STATE_ROOT").trim_end_matches('/') != want {
                s.set_env("NOO_STATE_ROOT", &want);
            }
            return Ok(FreshOutcome::AlreadyThere { state_root: want });
        }
        return Ok(FreshOutcome::Skipped(format!(
            "this machine's encrypted state volume already belongs to {} (one per machine); this install's state stays in the clear",
            v.mountpoint
        )));
    }
    if let Some(p) = s.state_in_use() {
        return Ok(FreshOutcome::Skipped(format!(
            "{p} already holds data, so this is not a fresh install: move it onto an encrypted volume with `noo security at-rest migrate`. Nothing was changed"
        )));
    }
    let need = (plan.size_gib + MARGIN_GIB) * GIB;
    if let Some(free) = s.free_bytes(&plan.data_root).filter(|f| *f < need) {
        return Err(format!(
            "not enough free space under {} for the {} GiB encrypted volume: {} GiB free, {} GiB needed with the margin. Free some space, or answer no (your data then stays unencrypted on disk)",
            plan.data_root,
            plan.size_gib,
            free / GIB,
            need / GIB
        ));
    }
    plan.defer = !s.can_show_secret();
    let created = s.create_volume(&plan)?;
    s.set_env("NOO_STATE_ROOT", &created.mountpoint);
    if !created.pki_dir.is_empty() {
        if let Some(from) = plan.pki_from.as_deref() {
            let prefix = format!("{}/", from.trim_end_matches('/'));
            for k in ["NOO_TLS_CA", "NOO_TLS_CERT", "NOO_TLS_KEY"] {
                let v = s.read_env(k);
                if let Some(rest) = v.strip_prefix(&prefix) {
                    s.set_env(k, &format!("{}/{rest}", created.pki_dir));
                }
            }
        }
        s.set_env("NOO_PKI_DIR", &created.pki_dir);
    }
    let acknowledged = match created.recovery_key.as_deref() {
        Some(k) => s.show_recovery_key(k),
        None => false,
    };
    Ok(FreshOutcome::Created { state_root: created.mountpoint.clone(), acknowledged, deferred: created.deferred })
}

/// The operator account (never root): the mounted state is handed to it.
pub(crate) fn operator_user() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|u| !u.trim().is_empty() && u != "root")
}

/// The age key to escrow: `SOPS_AGE_KEY_FILE`, else the default, resolved to
/// the real file (hostd refuses a symlink).
pub(crate) fn age_key_to_escrow(sops_age_key_file: &str) -> Option<String> {
    let p = if sops_age_key_file.trim().is_empty() {
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config/sops/age/keys.txt")
    } else {
        PathBuf::from(sops_age_key_file.trim())
    };
    let real = std::fs::canonicalize(&p).ok()?;
    real.is_file().then(|| real.to_string_lossy().into_owned())
}

// ── the command ─────────────────────────────────────────────────────────

fn on_wsl() -> bool {
    std::fs::read_to_string("/proc/version").map(|v| v.to_ascii_lowercase().contains("microsoft")).unwrap_or(false)
}

/// Bytes under the existing state directories (an estimate: what this user
/// cannot read is not counted, which is why `--size` exists).
fn state_bytes(state_root: &str) -> u64 {
    let dirs: Vec<String> = crate::onboard::STATE_SUBDIRS
        .iter()
        .map(|n| format!("{}/{n}", state_root.trim_end_matches('/')))
        .filter(|p| Path::new(p).is_dir())
        .collect();
    if dirs.is_empty() {
        return 0;
    }
    let out = Command::new("du").arg("-sbc").args(&dirs).stderr(Stdio::null()).output();
    let Ok(out) = out else { return 0 };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .and_then(|l| l.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn read_answer(label: &str) -> Option<String> {
    crate::onboard::prompt::read_line_edited(&format!("  {label}: "))
}

/// Show the key on this terminal and have the person retype its first and
/// last groups. True = acknowledged. An empty answer gives up (the row then
/// warns until a new key is made).
pub(crate) fn reveal_on_terminal(key: &str) -> bool {
    println!();
    ui::warned(RECOVERY_KEY_WARNING);
    println!();
    println!("  {}", ui::emph("Recovery key for the encrypted state volume"));
    ui::value(key);
    println!();
    loop {
        let first = read_answer("Type the FIRST group of the key (empty to skip)").unwrap_or_default();
        if first.trim().is_empty() {
            return false;
        }
        let last = read_answer("Type the LAST group of the key").unwrap_or_default();
        if retyped_ok(key, &first, &last) {
            // Off the screen and, where the terminal allows, its scrollback.
            ui::clear_revealed_secret();
            return true;
        }
        ui::warned("those groups do not match the key above — read it again and retype them");
    }
}

/// `noo security at-rest create-volume [--size <GiB>] [--pcrs 7|none|auto] [--defer-recovery-key] [--dry-run]`
pub fn security_at_rest_create_volume(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut size: Option<u64> = None;
    let mut pcrs = "auto".to_string();
    let mut defer = false;
    let mut dry = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--size" => size = Some(it.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?),
            "--pcrs" => pcrs = it.next().ok_or(Unhandled)?.clone(),
            "--defer-recovery-key" => defer = true,
            "--dry-run" => dry = true,
            _ => return Err(Unhandled),
        }
    }
    if !matches!(pcrs.as_str(), "7" | "none" | "auto") {
        fail(g.json, ExitCode::Usage, "bad_pcrs", &format!("--pcrs {pcrs}: only 7, none or auto (the firmware PCRs 0/2 are never bound)"), None);
    }
    if size.is_some_and(|s| s < MIN_SIZE_GIB) {
        fail(g.json, ExitCode::Usage, "too_small", &format!("--size: at least {MIN_SIZE_GIB} GiB"), None);
    }
    if !cfg!(target_os = "linux") || on_wsl() {
        fail(g.json, ExitCode::Generic, "not_supported_here", "not supported here: the encrypted state volume is for Linux controllers (not macOS, WSL2 or worker nodes)", None);
    }
    let facts = TpmFacts::probe(Path::new("/"));
    if !facts.tpm2_usable() {
        fail(
            g.json,
            ExitCode::Generic,
            "no_tpm",
            &format!("no usable TPM 2.0 here ({}) — the volume would not unlock at boot", facts.unavailable_reason()),
            Some(&crate::commands::at_rest::enable_hint(&facts)),
        );
    }
    if !facts.missing_tools().is_empty() {
        fail(
            g.json,
            ExitCode::Generic,
            "missing_tools",
            &format!("missing: {}", facts.missing_tools().join(", ")),
            Some("install cryptsetup and a systemd that ships systemd-cryptenroll (v250 or newer)"),
        );
    }
    if let Some(v) = read_volume() {
        fail(
            g.json,
            ExitCode::Generic,
            "volume_exists",
            &format!("this machine already has its encrypted state volume: {} at {}", v.file, v.mountpoint),
            Some("noo cluster verify --controller"),
        );
    }
    let Some(user) = operator_user() else {
        fail(g.json, ExitCode::Generic, "no_operator", "run this as the operator account (not root): the mounted state is handed to you", None);
    };
    let terminal = crate::onboard::prompt::stdin_is_tty() && crate::onboard::prompt::stdout_is_tty() && !g.json;
    if !defer && !terminal {
        fail(
            g.json,
            ExitCode::Generic,
            "needs_terminal",
            "the recovery key is shown once, on a terminal only — run this at a terminal, or pass --defer-recovery-key (TPM-only until a recovery key is made)",
            None,
        );
    }
    let env = |k: &str| std::env::var(k).ok();
    let data_root = env("NOO_DATA_ROOT")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.to_string())
        .trim_end_matches('/')
        .to_string();
    let state_root = resolve_state_root(&env);
    let size_gib = size.unwrap_or_else(|| size_for(state_bytes(&state_root)));
    let plan = CreatePlan {
        data_root: data_root.clone(),
        size_gib,
        user,
        pcrs,
        subdirs: state_subdir_specs(),
        age_key: age_key_to_escrow(&env("SOPS_AGE_KEY_FILE").unwrap_or_default()),
        pki_from: None,
        defer,
    };
    let hostd = hostd_bin();
    let argv = hostd_argv(&hostd, &plan);
    let line = format!("sudo {}", argv.join(" "));
    if dry {
        if g.json {
            println!("{}", json!({"dry_run": true, "command": line, "size_gib": size_gib}));
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
            &format!("{hostd} is not installed — it does the root half of the volume"),
            Some("noo onboard --only services"),
        );
    }
    if !g.json {
        ui::step(&format!("creating a {size_gib} GiB encrypted state volume at {data_root}/state.luks2 (mounted at {data_root}/state); running: {line}"));
    }
    let (res, _) = run_hostd(&argv, false, true);
    let created = match res {
        Ok(c) => c,
        Err(e) => fail(g.json, ExitCode::Generic, "create_failed", &e, None),
    };
    let mut acknowledged = false;
    if let Some(k) = created.recovery_key.as_deref() {
        acknowledged = reveal_on_terminal(k);
    }
    if acknowledged {
        match crate::http::post_json_try(g, "/api/settings/flags/set", &json!({"key": RECOVERY_SETTING, "value": true}), true, 10) {
            Ok(_) => ui::done("recorded: you stored the recovery key off this machine"),
            Err(e) => ui::warned(&format!(
                "the volume is made, but your acknowledgement was NOT recorded ({e}); verify will warn about the recovery key until it is"
            )),
        }
    } else if created.deferred {
        ui::warned("no recovery key yet: the volume unlocks by this machine's TPM only until one is made: noo security at-rest recovery-key");
    } else {
        ui::warned("the recovery key was not acknowledged: verify will warn until a new one is made and stored: noo security at-rest recovery-key");
    }
    if g.json {
        println!(
            "{}",
            json!({
                "volume_file": created.file,
                "volume_mountpoint": created.mountpoint,
                "volume_pcrs": created.pcrs,
                "recovery_key_deferred": created.deferred,
                "recovery_key_acknowledged": acknowledged,
            })
        );
        return Ok(0);
    }
    ui::done(&format!("encrypted state volume {} open and mounted at {}", created.file, created.mountpoint));
    if !created.pcr_note.is_empty() {
        println!("{}", ui::note(&created.pcr_note));
    }
    if !created.age_escrow.is_empty() {
        println!("{}", ui::note(&format!("a copy of the age key is escrowed inside the volume at {}", created.age_escrow)));
    }
    if !state_on_volume(&state_root, &Volume {
        file: created.file.clone(),
        mountpoint: created.mountpoint.clone(),
        size_gib,
        pcrs: created.pcrs.clone(),
        recovery: String::new(),
        created_at: String::new(),
    }) {
        println!(
            "{}",
            ui::note(&format!(
                "it is empty: this install's state is still at {state_root}, in the clear. Move it with `noo security at-rest migrate`."
            ))
        );
    }
    ui::guide(&[("noo cluster verify --controller", "the at-rest volume and recovery key rows")]);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vol() -> Volume {
        Volume {
            file: "/var/lib/noo/state.luks2".into(),
            mountpoint: "/var/lib/noo/state".into(),
            size_gib: 64,
            pcrs: "7".into(),
            recovery: "enrolled".into(),
            created_at: "2026-10-23T12:00:00Z".into(),
        }
    }

    fn no_dm(_: &str) -> Option<String> {
        None
    }

    const MOUNTED: &str = "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n\
                           /dev/mapper/noo-state /var/lib/noo/state ext4 rw,relatime 0 0\n";
    const NOT_MOUNTED: &str = "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n";

    #[test]
    fn the_manifest_volume_fields_are_read_and_pr_b_fields_ignored() {
        let m = json!({
            "version": 1, "age_key_sealed": true,
            "volume_file": "/var/lib/noo/state.luks2", "volume_mountpoint": "/var/lib/noo/state/",
            "volume_size_gib": 64, "volume_pcrs": "7", "volume_recovery_key": "enrolled",
            "volume_created_at": "2026-10-23T12:00:00Z", "volume_operator": "alice",
        });
        assert_eq!(volume_from_manifest(&m), Some(vol()));
        assert_eq!(volume_from_manifest(&json!({"version": 1, "age_key_sealed": true})), None, "PR-B alone records no volume");
        assert_eq!(volume_from_manifest(&json!({})), None);
    }

    #[test]
    fn the_size_is_twice_the_state_and_at_least_50_gib() {
        assert_eq!(size_for(0), 50);
        assert_eq!(size_for(10 * GIB), 50);
        assert_eq!(size_for(25 * GIB), 50);
        assert_eq!(size_for(25 * GIB + 1), 51, "rounded up to whole GiB");
        assert_eq!(size_for(40 * GIB), 80);
    }

    /// The launch check, on a fake mount table: refuses only when the state
    /// root IS the volume and the volume is not mounted from the mapping.
    #[test]
    fn the_launch_check_refuses_a_closed_volume_the_state_lives_on() {
        let v = vol();
        let refusal = launch_refusal(Some(&v), "/var/lib/noo/state", NOT_MOUNTED, &no_dm).expect("must refuse");
        assert!(refusal.contains("the encrypted state volume is not open"), "{refusal}");
        assert!(refusal.contains(r"systemctl status 'systemd-cryptsetup@noo\x2dstate.service'"), "quoted for the shell: {refusal}");
        assert!(refusal.contains("recovery: docs/operating/runbooks/at-rest-recovery.md"), "{refusal}");
        assert!(refusal.contains("sudo cryptsetup open /var/lib/noo/state.luks2 noo-state && sudo mount /var/lib/noo/state"), "{refusal}");
        // a subdirectory of the volume as the state root counts too
        assert!(launch_refusal(Some(&v), "/var/lib/noo/state/instances/a", NOT_MOUNTED, &no_dm).is_some());
        // open and mounted: may start
        assert_eq!(launch_refusal(Some(&v), "/var/lib/noo/state", MOUNTED, &no_dm), None);
        // mounted under its dm-N name
        let dm = "/dev/dm-3 /var/lib/noo/state ext4 rw 0 0\n";
        assert_eq!(launch_refusal(Some(&v), "/var/lib/noo/state", dm, &|d| (d == "dm-3").then(|| "noo-state\n".to_string())), None);
        assert!(launch_refusal(Some(&v), "/var/lib/noo/state", dm, &|_| Some("other".into())).is_some(), "another mapping is not the volume");
        // something ELSE mounted there (a plain disk) is not the volume
        let other = "/dev/sdb1 /var/lib/noo/state ext4 rw 0 0\n";
        assert!(launch_refusal(Some(&v), "/var/lib/noo/state", other, &no_dm).is_some());
        // the visible mount is the LAST one at that path
        let stacked = format!("{MOUNTED}/dev/sdb1 /var/lib/noo/state ext4 rw 0 0\n");
        assert!(launch_refusal(Some(&v), "/var/lib/noo/state", &stacked, &no_dm).is_some());
        // not switched yet (state root elsewhere): the volume is not in use
        assert_eq!(launch_refusal(Some(&v), "/var/lib/noo", NOT_MOUNTED, &no_dm), None);
        assert_eq!(launch_refusal(Some(&v), "/var/lib/noo/state-old", NOT_MOUNTED, &no_dm), None, "a sibling prefix is not under it");
        // no volume recorded: nothing to judge
        assert_eq!(launch_refusal(None, "/var/lib/noo/state", NOT_MOUNTED, &no_dm), None);
    }

    #[test]
    fn the_state_root_resolves_like_compose() {
        let env = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(a, _)| *a == k).map(|(_, b)| b.to_string());
        assert_eq!(resolve_state_root(&env(&[("NOO_DATA_ROOT", "/srv/noo")])), "/srv/noo");
        assert_eq!(resolve_state_root(&env(&[("NOO_DATA_ROOT", "/srv/noo"), ("NOO_STATE_ROOT", "/srv/noo/state/")])), "/srv/noo/state");
        assert_eq!(resolve_state_root(&env(&[("NOO_DATA_ROOT", "/srv/noo"), ("NOO_STATE_ROOT", "")])), "/srv/noo");
        assert_eq!(resolve_state_root(&env(&[])), crate::commands::data_root::DEFAULT_DATA_ROOT);
    }

    fn tpm(usable: bool) -> TpmFacts {
        // Tests run in parallel threads of one process: a counter keeps each root apart.
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("noo-at-rest-vol-{usable}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        if usable {
            std::fs::create_dir_all(root.join("sys/class/tpm/tpm0")).unwrap();
            std::fs::write(root.join("sys/class/tpm/tpm0/tpm_version_major"), "2\n").unwrap();
            std::fs::create_dir_all(root.join("dev")).unwrap();
            std::fs::write(root.join("dev/tpmrm0"), "").unwrap();
        } else {
            std::fs::create_dir_all(&root).unwrap();
        }
        let f = TpmFacts::probe(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(f.tpm2_usable(), usable);
        f
    }

    fn decision(accepted: bool) -> AcceptedState {
        AcceptedState {
            accepted,
            source: "db".into(),
            updated_by: Some("alice".into()),
            updated_at: Some("2026-10-23T12:00:00Z".into()),
        }
    }

    #[test]
    fn the_volume_row() {
        let v = vol();
        let up = Live { open: true, mounted: true, free: Some(60 * GIB) };
        let c = volume_check(Some(&v), up, "/var/lib/noo/state", None, &tpm(true));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("64 GiB, 60 GiB free") && c.detail.contains("PCR 7"), "{}", c.detail);
        // recorded but closed: FAIL, naming the unit and the runbook
        let c = volume_check(Some(&v), Live { open: false, mounted: false, free: None }, "/var/lib/noo/state", None, &tpm(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("not open"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().contains(CRYPTSETUP_UNIT) && c.remedy.as_deref().unwrap().contains(RUNBOOK));
        // open but not mounted: FAIL too
        let c = volume_check(Some(&v), Live { open: true, mounted: false, free: None }, "/var/lib/noo/state", None, &tpm(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("not mounted"), "{}", c.detail);
        // a closed volume FAILS even before the install was switched to it
        assert_eq!(volume_check(Some(&v), Live { open: false, mounted: false, free: None }, "/var/lib/noo", None, &tpm(true)).verdict, Verdict::Fail);
        // open, but the state still lives elsewhere: WARN
        let c = volume_check(Some(&v), up, "/var/lib/noo", None, &tpm(true));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("not on it yet"), "{}", c.detail);
        // TPM-only policy is said plainly
        let mut v2 = v.clone();
        v2.pcrs = "none".into();
        assert!(volume_check(Some(&v2), up, "/var/lib/noo/state", None, &tpm(true)).detail.contains("live-USB"));
        // no volume: WARN naming create-volume / the TPM reason / ACCEPTED when opted out
        let c = volume_check(None, Live { open: false, mounted: false, free: None }, "/var/lib/noo", None, &tpm(true));
        assert_eq!(c.verdict, Verdict::Warn);
        assert_eq!(c.remedy.as_deref(), Some("noo security at-rest create-volume"));
        let c = volume_check(None, Live { open: false, mounted: false, free: None }, "/var/lib/noo", None, &tpm(false));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("cannot be made here"), "{}", c.detail);
        let c = volume_check(None, Live { open: false, mounted: false, free: None }, "/var/lib/noo", Some(&decision(true)), &tpm(true));
        assert_eq!(c.verdict, Verdict::Accepted);
        assert!(c.detail.contains(crate::commands::at_rest::DISCLOSURE_OFF), "{}", c.detail);
        assert_eq!(c.name, VOLUME_ROW);
    }

    #[test]
    fn the_recovery_key_row() {
        let v = vol();
        let c = recovery_check(Some(&v), Some(&decision(true)));
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("acknowledged by alice at 2026-10-23T12:00:00Z"), "{}", c.detail);
        assert_eq!(recovery_check(Some(&v), Some(&decision(false))).verdict, Verdict::Warn);
        assert_eq!(recovery_check(Some(&v), None).verdict, Verdict::Warn);
        let mut d = v.clone();
        d.recovery = "deferred".into();
        let c = recovery_check(Some(&d), Some(&decision(true)));
        assert_eq!(c.verdict, Verdict::Warn, "deferred warns whatever the flag says");
        assert!(c.detail.starts_with("deferred"), "{}", c.detail);
        assert_eq!(recovery_check(None, None).verdict, Verdict::Ok);
        assert_eq!(c.name, RECOVERY_ROW);
        let flags = json!({"flags": [{"key": RECOVERY_SETTING, "value": true, "source": "db", "updated_by": "bob", "updated_at": "t"}]});
        assert_eq!(flag_from(&flags, RECOVERY_SETTING).unwrap().updated_by.as_deref(), Some("bob"));
        assert_eq!(flag_from(&flags, "at_rest.unencrypted_accepted"), None);
    }

    #[test]
    fn the_hostd_argv_carries_the_plan_and_never_a_key() {
        let p = CreatePlan {
            data_root: "/var/lib/noo/".into(),
            size_gib: 64,
            user: "alice".into(),
            pcrs: "auto".into(),
            subdirs: state_subdir_specs(),
            age_key: Some("/home/user/.config/sops/age/keys.txt".into()),
            pki_from: Some("/home/user/noomesh/pki".into()),
            defer: true,
        };
        let a = hostd_argv("/usr/local/bin/noo-hostd", &p);
        let s = a.join(" ");
        assert!(s.starts_with("/usr/local/bin/noo-hostd at-rest create-volume --data-root /var/lib/noo --size 64 --user alice --pcrs auto"), "{s}");
        for want in ["--subdir redis=65532:65532", "--subdir postgres=70:70", "--subdir noo-data", "--subdir loki=65532:65532",
                     "--age-key /home/user/.config/sops/age/keys.txt", "--pki-from /home/user/noomesh/pki", "--defer-recovery-key"] {
            assert!(s.contains(want), "missing {want}: {s}");
        }
        assert_eq!(state_subdir_specs().len(), crate::onboard::STATE_SUBDIRS.len());
    }

    #[test]
    fn the_result_line_is_parsed_and_its_errors_never_echo_it() {
        let key = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-vutrnlkj-ihgfedcb-ccccdddd-eeeeffff";
        let line = format!(r#"{{"ok":true,"recovery_key":"{key}","recovery_key_deferred":false,"volume_file":"/v/state.luks2","volume_mountpoint":"/v/state","volume_pcrs":"7","pcr_note":"n","pki_dir":"/v/state/pki"}}"#);
        let c = parse_created(format!("{line}\n").as_bytes()).unwrap();
        assert_eq!(c.recovery_key.as_deref(), Some(key));
        assert_eq!(c.mountpoint, "/v/state");
        assert_eq!(c.pki_dir, "/v/state/pki");
        let no_key = r#"{"ok":true,"recovery_key_deferred":false,"volume_mountpoint":"/v/state"}"#;
        assert!(parse_created(no_key.as_bytes()).is_err(), "no key and not deferred is not success");
        let deferred = r#"{"ok":true,"recovery_key_deferred":true,"volume_mountpoint":"/v/state"}"#;
        assert!(parse_created(deferred.as_bytes()).unwrap().recovery_key.is_none());
        let garbage = format!("{key} not json");
        let e = parse_created(garbage.as_bytes()).err().unwrap();
        assert!(!e.contains(key), "an error echoed the key: {e}");
    }

    #[test]
    fn the_person_retypes_the_first_and_last_groups() {
        let key = "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-vutrnlkj-ihgfedcb-ccccdddd-eeeeffff";
        assert_eq!(key_groups(key), Some(("cbdefghi", "eeeeffff")));
        assert!(retyped_ok(key, "cbdefghi", "eeeeffff"));
        assert!(retyped_ok(key, " CBDEFGHI ", "eeeeffff\n"), "case and whitespace are forgiven");
        assert!(!retyped_ok(key, "cbdefghi", "ccccdddd"));
        assert!(!retyped_ok(key, "", ""));
        assert!(!retyped_ok("nodashes", "nodashes", "nodashes"));
        assert!(!RECOVERY_KEY_WARNING.to_lowercase().contains("secure"), "no 'your data is secure' claim");
    }

    // ── setup_fresh, with every step injected ───────────────────────────

    struct Fake {
        events: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
        existing: Option<Volume>,
        in_use: Option<String>,
        free: Option<u64>,
        terminal: bool,
        fail_create: bool,
        acknowledge: bool,
        seen_plan: Option<CreatePlan>,
    }

    impl Fake {
        fn new() -> Fake {
            let mut env = std::collections::BTreeMap::new();
            env.insert("NOO_PKI_DIR".into(), "/home/user/noomesh/pki".into());
            env.insert("NOO_TLS_CA".into(), "/home/user/noomesh/pki/ca.crt".into());
            env.insert("NOO_TLS_CERT".into(), "/home/user/noomesh/pki/gateway/gateway.crt".into());
            env.insert("NOO_TLS_KEY".into(), "/home/user/noomesh/pki/gateway/gateway.key".into());
            Fake { events: vec![], env, existing: None, in_use: None, free: Some(500 * GIB), terminal: true, fail_create: false, acknowledge: true, seen_plan: None }
        }
    }

    impl FreshSteps for Fake {
        fn existing_volume(&self) -> Option<Volume> {
            self.existing.clone()
        }
        fn state_in_use(&self) -> Option<String> {
            self.in_use.clone()
        }
        fn free_bytes(&self, _: &str) -> Option<u64> {
            self.free
        }
        fn can_show_secret(&self) -> bool {
            self.terminal
        }
        fn create_volume(&mut self, plan: &CreatePlan) -> Result<Created, String> {
            self.events.push("create-volume".into());
            self.seen_plan = Some(plan.clone());
            if self.fail_create {
                return Err("cryptsetup said no".into());
            }
            Ok(Created {
                recovery_key: (!plan.defer).then(|| "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-vutrnlkj-ihgfedcb-ccccdddd-eeeeffff".to_string()),
                deferred: plan.defer,
                file: "/var/lib/noo/state.luks2".into(),
                mountpoint: "/var/lib/noo/state".into(),
                pcrs: "7".into(),
                pcr_note: String::new(),
                pki_dir: "/var/lib/noo/state/pki".into(),
                age_escrow: "/var/lib/noo/state/keys/age.txt".into(),
            })
        }
        fn show_recovery_key(&mut self, _key: &str) -> bool {
            self.events.push("show-key".into());
            self.acknowledge
        }
        fn read_env(&self, key: &str) -> String {
            self.env.get(key).cloned().unwrap_or_default()
        }
        fn set_env(&mut self, key: &str, value: &str) {
            self.events.push(format!("env {key}={value}"));
            self.env.insert(key.into(), value.into());
        }
    }

    fn plan() -> CreatePlan {
        CreatePlan {
            data_root: "/var/lib/noo".into(),
            size_gib: 50,
            user: "alice".into(),
            pcrs: "auto".into(),
            subdirs: state_subdir_specs(),
            age_key: None,
            pki_from: Some("/home/user/noomesh/pki".into()),
            defer: false,
        }
    }

    /// The order onboard depends on: the volume first, then the env that
    /// sends every later write (and the services) onto it, then the key.
    #[test]
    fn a_fresh_yes_creates_the_volume_before_pointing_anything_at_it() {
        let mut f = Fake::new();
        let out = setup_fresh(&mut f, plan()).unwrap();
        assert_eq!(out, FreshOutcome::Created { state_root: "/var/lib/noo/state".into(), acknowledged: true, deferred: false });
        assert_eq!(f.events[0], "create-volume", "{:?}", f.events);
        let pos = |e: &str| f.events.iter().position(|x| x == e).unwrap_or_else(|| panic!("no {e}: {:?}", f.events));
        assert!(pos("env NOO_STATE_ROOT=/var/lib/noo/state") > 0);
        assert!(pos("env NOO_PKI_DIR=/var/lib/noo/state/pki") > 0);
        assert!(pos("show-key") > pos("env NOO_STATE_ROOT=/var/lib/noo/state"));
        assert_eq!(f.env["NOO_TLS_CA"], "/var/lib/noo/state/pki/ca.crt");
        assert_eq!(f.env["NOO_TLS_CERT"], "/var/lib/noo/state/pki/gateway/gateway.crt");
        assert_eq!(f.env["NOO_TLS_KEY"], "/var/lib/noo/state/pki/gateway/gateway.key");
        assert!(!f.seen_plan.unwrap().defer, "a terminal shows the key now");
    }

    #[test]
    fn a_failed_create_changes_no_env_and_is_an_error() {
        let mut f = Fake::new();
        f.fail_create = true;
        let e = setup_fresh(&mut f, plan()).unwrap_err();
        assert!(e.contains("cryptsetup said no"), "{e}");
        assert_eq!(f.events, vec!["create-volume"], "nothing may point at a volume that does not exist");
        assert_eq!(f.env["NOO_PKI_DIR"], "/home/user/noomesh/pki");
    }

    #[test]
    fn no_terminal_defers_the_key_and_never_shows_it() {
        let mut f = Fake::new();
        f.terminal = false;
        let out = setup_fresh(&mut f, plan()).unwrap();
        assert_eq!(out, FreshOutcome::Created { state_root: "/var/lib/noo/state".into(), acknowledged: false, deferred: true });
        assert!(f.seen_plan.unwrap().defer);
        assert!(!f.events.iter().any(|e| e == "show-key"));
    }

    #[test]
    fn not_fresh_another_volume_or_no_space_create_nothing() {
        let mut f = Fake::new();
        f.in_use = Some("/var/lib/noo/postgres".into());
        assert!(matches!(setup_fresh(&mut f, plan()).unwrap(), FreshOutcome::Skipped(w) if w.contains("not a fresh install")));
        assert!(f.events.is_empty());

        let mut f = Fake::new();
        let mut other = vol();
        other.mountpoint = "/srv/other/state".into();
        f.existing = Some(other);
        assert!(matches!(setup_fresh(&mut f, plan()).unwrap(), FreshOutcome::Skipped(w) if w.contains("/srv/other/state")));
        assert!(f.events.is_empty());

        let mut f = Fake::new();
        f.existing = Some(vol());
        assert_eq!(setup_fresh(&mut f, plan()).unwrap(), FreshOutcome::AlreadyThere { state_root: "/var/lib/noo/state".into() });
        assert_eq!(f.events, vec!["env NOO_STATE_ROOT=/var/lib/noo/state"], "a re-run only re-points the env");

        let mut f = Fake::new();
        f.free = Some(54 * GIB);
        let e = setup_fresh(&mut f, plan()).unwrap_err();
        assert!(e.contains("not enough free space") && e.contains("answer no"), "{e}");
        assert!(f.events.is_empty());
    }

    /// The recovery key is never in the JSON output or the plan.
    #[test]
    fn the_command_never_puts_the_key_in_json() {
        let src = include_str!("at_rest_volume.rs");
        let cmd = &src[src.find("pub fn security_at_rest_create_volume(").unwrap()..src.find("#[cfg(test)]").unwrap()];
        let json_out = &cmd[cmd.find("if g.json {\n        println!(").expect("the JSON result block")..];
        let json_out = &json_out[..json_out.find("return Ok(0);").unwrap()];
        assert!(json_out.contains("recovery_key_acknowledged"), "found the wrong block: {json_out}");
        assert!(!json_out.contains("created.recovery_key"), "the key reached the JSON output");
        assert!(!json_out.contains("\"recovery_key\""), "the key reached the JSON output");
        // the one place the key is printed: ui::value, on a terminal
        let reveal = &src[src.find("fn reveal_on_terminal(").unwrap()..];
        assert!(reveal[..reveal.find("\n}\n").unwrap()].contains("ui::value(key)"));
    }

    /// The loop→crypt chain lsblk reports for a file-backed volume is what
    /// makes the nine data rows read "a dm-crypt device".
    #[test]
    fn a_file_backed_volume_reads_as_dm_crypt() {
        assert_eq!(crate::commands::cluster_verify::lsblk_types_say_crypt("crypt\nloop\n"), Some(true));
        assert_eq!(crate::commands::cluster_verify::lsblk_types_say_crypt("part\ndisk\n"), Some(false));
        assert_eq!(crate::commands::cluster_verify::lsblk_types_say_crypt(""), None);
        let env = |k: &str| match k {
            "NOO_DATA_ROOT" => Some("/var/lib/noo".to_string()),
            "NOO_STATE_ROOT" => Some("/var/lib/noo/state".to_string()),
            "HOME" => Some("/home/alice".to_string()),
            _ => None,
        };
        for row in crate::commands::cluster_verify::at_rest_dirs(&env) {
            if row.name == "pki at rest" || row.name == "age key at rest" {
                continue;
            }
            let (dev, mp) = crate::commands::cluster_verify::mount_of(MOUNTED, &row.path).unwrap();
            assert_eq!((dev.as_str(), mp.as_str()), (MAPPER_PATH, "/var/lib/noo/state"), "{}", row.name);
            let c = crate::commands::cluster_verify::at_rest_check_with(
                row.name, row.what, &row.path, true, Some((dev.as_str(), mp.as_str())),
                crate::commands::cluster_verify::lsblk_types_say_crypt("crypt\nloop\n"), None, None,
            );
            assert_eq!(c.verdict, Verdict::Ok, "{}: {}", row.name, c.detail);
        }
    }
}
