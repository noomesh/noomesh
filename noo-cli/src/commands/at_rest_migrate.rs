// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! At-rest encryption, part D (i10a): move an EXISTING install's sensitive
//! state onto the TPM-unlocked LUKS2 state volume (part C), backup-first,
//! resumable and reversible.
//!
//! - `noo security at-rest migrate [--dry-run] [--yes] [--confirm-offbox <phrase>]`
//!   walks [`STEPS`], journaling each in `<repo>/.noo-at-rest-migrate.json`.
//!   A crash or Ctrl-C anywhere resumes at the first step not journaled; every
//!   step is safe to run twice.
//! - `noo security at-rest migrate --rollback` stops the stack, puts the
//!   ORIGINAL `.env` back byte for byte (a copy is taken at preflight) and
//!   starts it again. The plaintext directories are only ever READ by the
//!   copy (rsync as root through `noo-hostd at-rest copy`), so the old
//!   install is exactly as it was; the volume stays.
//! - `noo security at-rest wipe-plaintext` is a separate verb and the only
//!   one that deletes anything: refused unless the migration completed, a
//!   fresh backup was taken FROM the encrypted state, the new state has run
//!   healthy for N hours (default 24), and the person types a phrase.
//!
//! Safety gates before anything is stopped or copied:
//! 1. a FRESH backup (`scripts/backup-controller.sh`), decrypted and restored
//!    into a throwaway Postgres by `scripts/restore-drill.sh`, its artifacts'
//!    sha256 recorded in the journal;
//! 2. proof that a copy left this machine (the backup script's own
//!    `offsite: copied` line), or the typed phrase [`OFFBOX_PHRASE`];
//! 3. the final rsync is followed by a `--checksum` dry-run that must list
//!    ZERO differences before `.env` is touched.
//!
//! Test seam: `NOO_AT_REST_VOLUME=dir` + `NOO_AT_REST_VOLUME_DIR=<dir>` make a
//! plain directory stand in for the mounted volume (no TPM, no hostd, no
//! sudo: rsync runs directly, `NOO_AT_REST_RSYNC`). Other binaries are
//! overridable (`NOO_HOSTD_BIN`, `NOO_AT_REST_SUDO`, `NOO_AT_REST_NOO_BIN`,
//! `NOO_AT_REST_DOCKER`, `NOO_AT_REST_BACKUP_CMD`, `NOO_AT_REST_DRILL_CMD`,
//! `NOO_AT_REST_PSQL_CMD`); the engine ([`run_migrate`], [`run_rollback`],
//! [`run_wipe`]) takes a [`Ctx`] so the tests drive it without any of them.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use sha2::Digest as _;

use crate::commands::at_rest::TpmFacts;
use crate::commands::at_rest_volume::{self, read_volume, resolve_state_root, state_on_volume, Volume, MARGIN_GIB};
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// The journal, in the install root.
pub(crate) const JOURNAL: &str = ".noo-at-rest-migrate.json";
/// A byte-for-byte copy of `.env` as it was before the first change.
pub(crate) const ENV_ORIG: &str = ".noo-at-rest-migrate.env.orig";
/// Typed (or passed to `--confirm-offbox`) when no copy of the backup left
/// this machine: the person says they understand it dies with the disk.
pub(crate) const OFFBOX_PHRASE: &str = "backup is only on this machine";
/// Typed (or passed to `--confirm`) to delete the old plaintext state.
pub(crate) const WIPE_PHRASE: &str = "delete the plaintext state";
/// Healthy hours on the encrypted state before the plaintext may go.
pub(crate) const DEFAULT_HEALTHY_HOURS: u64 = 24;
const GIB: u64 = 1 << 30;

/// The steps, in order. Each is journaled when it finishes.
pub(crate) const STEPS: [&str; 12] = [
    "preflight",  // facts, plan, baseline verify, original .env saved
    "backup",     // fresh backup + restore drill, sha256s journaled
    "offbox",     // an off-machine copy, or the typed phrase
    "volume",     // create the volume if absent (part C)
    "precopy",    // online rsync of the state set + PKI
    "rowcounts",  // row counts and sizes while still running
    "stop",       // noo stack stop
    "finalsync",  // rsync --delete, then a --checksum dry-run with zero differences
    "switch",     // .env now points at the volume
    "start",      // noo stack start
    "verify",     // health, cluster verify rows, row counts compared
    "postbackup", // a backup taken FROM the encrypted state (wipe needs it)
];

/// Compose volumes of the state set that live under NOO_STATE_ROOT.
const STATE_COPIES: [&str; 7] = ["postgres", "redis", "nats", "prometheus", "grafana", "loki", "noo-data"];
/// Plain docker volumes that join the state set at migration (suffix match),
/// with the compose switch variable and the bind volume it selects.
const DOCKER_COPIES: [(&str, &str, &str); 2] = [
    ("claude-config", "NOO_CLAUDE_CONFIG_VOLUME", "claude-config-state"),
    ("alertmanager-data", "NOO_ALERTMANAGER_VOLUME", "alertmanager-data-state"),
];
/// Keys the preflight records the old value of.
const ENV_KEYS: [&str; 8] = [
    "NOO_STATE_ROOT",
    "NOO_PKI_DIR",
    "NOO_PG_DATA",
    "NOO_TLS_CA",
    "NOO_TLS_CERT",
    "NOO_TLS_KEY",
    "NOO_CLAUDE_CONFIG_VOLUME",
    "NOO_ALERTMANAGER_VOLUME",
];

// ── configuration ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Backend {
    /// The real thing: part C's volume, rsync as root through noo-hostd.
    Hostd,
    /// Test seam: this directory stands in for the mounted volume.
    Dir(PathBuf),
}

/// Everything the engine touches, so tests drive it without the host.
pub(crate) struct Ctx<'a> {
    pub g: Option<&'a Globals>,
    /// The install root: `.env`, the journal, `scripts/`.
    pub root: PathBuf,
    pub backend: Backend,
    /// "sudo" (or "env" in tests).
    pub sudo: String,
    pub hostd: String,
    pub rsync: String,
    /// The `noo` that runs `stack stop|start` and `cluster verify`.
    pub noo: String,
    pub docker: String,
    /// bash snippets, run in `root`.
    pub backup_cmd: String,
    pub drill_cmd: String,
    /// Run with `NOO_SQL` in the environment; prints rows.
    pub psql_cmd: String,
    pub backup_dir: PathBuf,
    /// Process environment values that matter (NOO_DATA_ROOT, NOO_STATE_ROOT,
    /// NOO_PKI_DIR, NOO_PG_DATA, HOME): injected so tests need no env mutation.
    pub env: BTreeMap<String, String>,
    /// Unix seconds, fixed per run.
    pub now: u64,
    pub dry_run: bool,
    pub yes: bool,
    pub tty: bool,
    /// `--confirm-offbox` / `--confirm`.
    pub offbox_phrase: Option<String>,
    pub confirm: Option<String>,
    pub healthy_hours: u64,
    /// How long `verify` polls for a healthy stack.
    pub verify_wait_secs: u64,
    /// Tests: return "simulated crash" after this step ran, before it is journaled.
    pub crash_before_journal: Option<&'static str>,
    /// Tests: return after this step is journaled.
    pub stop_after: Option<&'static str>,
}

fn env_nonempty(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

impl<'a> Ctx<'a> {
    /// From the real process environment.
    pub(crate) fn live(g: &'a Globals) -> Ctx<'a> {
        let root = crate::envfile::repo_root();
        let mut env = BTreeMap::new();
        for k in ["NOO_DATA_ROOT", "NOO_STATE_ROOT", "NOO_PKI_DIR", "NOO_PG_DATA", "HOME", "SOPS_AGE_KEY_FILE"] {
            if let Some(v) = env_nonempty(k) {
                env.insert(k.to_string(), v);
            }
        }
        let backend = if env_nonempty("NOO_AT_REST_VOLUME").as_deref() == Some("dir") {
            Backend::Dir(PathBuf::from(env_nonempty("NOO_AT_REST_VOLUME_DIR").unwrap_or_default()))
        } else {
            Backend::Hostd
        };
        let docker = env_nonempty("NOO_AT_REST_DOCKER").unwrap_or_else(|| "docker".into());
        let secrets = "set -e; . scripts/lib-secrets.sh; load_secrets";
        Ctx {
            g: Some(g),
            backend,
            sudo: env_nonempty("NOO_AT_REST_SUDO").unwrap_or_else(|| "sudo".into()),
            hostd: env_nonempty("NOO_HOSTD_BIN").unwrap_or_else(|| at_rest_volume::HOSTD_BIN.into()),
            rsync: env_nonempty("NOO_AT_REST_RSYNC").unwrap_or_else(|| "rsync".into()),
            noo: env_nonempty("NOO_AT_REST_NOO_BIN")
                .or_else(|| std::env::current_exe().ok().map(|p| p.display().to_string()))
                .unwrap_or_else(|| "noo".into()),
            backup_cmd: env_nonempty("NOO_AT_REST_BACKUP_CMD").unwrap_or_else(|| format!("{secrets}; bash scripts/backup-controller.sh")),
            drill_cmd: env_nonempty("NOO_AT_REST_DRILL_CMD")
                .unwrap_or_else(|| format!("{secrets}; bash scripts/restore-drill.sh \"$NOO_DRILL_BACKUP\"")),
            psql_cmd: env_nonempty("NOO_AT_REST_PSQL_CMD")
                .unwrap_or_else(|| format!("{docker} exec noo-postgres psql -X -tA -F '|' -U noo -d noomesh -c \"$NOO_SQL\"")),
            docker,
            backup_dir: crate::commands::secrets::backup_dir(),
            root,
            env,
            now: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            dry_run: false,
            yes: false,
            tty: crate::onboard::prompt::stdin_is_tty() && crate::onboard::prompt::stdout_is_tty() && !g.json,
            offbox_phrase: None,
            confirm: None,
            healthy_hours: DEFAULT_HEALTHY_HOURS,
            verify_wait_secs: 180,
            crash_before_journal: None,
            stop_after: None,
        }
    }

    fn env_path(&self) -> PathBuf {
        self.root.join(".env")
    }

    /// The effective value of a key: the process environment, else `.env`
    /// (quotes stripped). Empty = unset.
    fn eff(&self, k: &str) -> String {
        if let Some(v) = self.env.get(k).filter(|v| !v.trim().is_empty()) {
            return v.trim().to_string();
        }
        env_file_value(&self.env_path(), k)
    }

    fn home(&self) -> String {
        self.env.get("HOME").cloned().unwrap_or_default()
    }
}

fn env_file_value(path: &Path, k: &str) -> String {
    crate::onboard::env::read_env_key(path, k).trim().trim_matches('"').trim_matches('\'').to_string()
}

fn say(msg: &str) {
    ui::step(msg);
}

// ── the journal ─────────────────────────────────────────────────────────

pub(crate) struct Journal {
    pub path: PathBuf,
    pub v: Value,
}

impl Journal {
    fn fresh(path: PathBuf, now: u64, backend: &Backend) -> Journal {
        let b = match backend {
            Backend::Hostd => "hostd",
            Backend::Dir(_) => "dir",
        };
        Journal { path, v: json!({"version": 1, "state": "in_progress", "started_at": now, "backend": b, "steps": {}}) }
    }

    pub(crate) fn load(path: &Path) -> Result<Option<Journal>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} does not parse ({e}); it is the record of a migration in progress — move it aside only if you are sure", path.display()))?;
        if !v["steps"].is_object() {
            return Err(format!("{} has no steps object; not a migration journal", path.display()));
        }
        Ok(Some(Journal { path: path.to_path_buf(), v }))
    }

    /// Atomic: write a sibling, then rename. 0600.
    pub(crate) fn save(&self) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = self.path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(&self.v).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, format!("{text}\n")).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("{}: {e}", self.path.display()))
    }

    pub(crate) fn is_done(&self, step: &str) -> bool {
        self.v["steps"][step].is_u64()
    }

    fn mark(&mut self, step: &str, now: u64) {
        self.v["steps"][step] = json!(now);
    }

    pub(crate) fn state(&self) -> String {
        self.v["state"].as_str().unwrap_or("").to_string()
    }

    fn s(&self, path: &[&str]) -> String {
        let mut cur = &self.v;
        for p in path {
            cur = &cur[*p];
        }
        cur.as_str().unwrap_or_default().to_string()
    }

    fn u(&self, path: &[&str]) -> u64 {
        let mut cur = &self.v;
        for p in path {
            cur = &cur[*p];
        }
        cur.as_u64().unwrap_or(0)
    }
}

// ── small helpers ───────────────────────────────────────────────────────

struct Out {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn tail(&self) -> String {
        let all = format!("{}\n{}", self.stdout.trim_end(), self.stderr.trim_end());
        let lines: Vec<&str> = all.lines().filter(|l| !l.trim().is_empty()).collect();
        let from = lines.len().saturating_sub(12);
        lines[from..].join("\n")
    }
}

fn finish(r: std::io::Result<std::process::Output>, what: &str) -> Result<Out, String> {
    let o = r.map_err(|e| format!("could not run {what}: {e}"))?;
    Ok(Out {
        ok: o.status.success(),
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    })
}

/// `bash -c <script>` in `cwd`, output captured.
fn sh(cwd: &Path, script: &str, envs: &[(&str, &str)]) -> Result<Out, String> {
    let mut c = Command::new("bash");
    c.arg("-c").arg(script).current_dir(cwd).stdin(Stdio::null());
    for (k, v) in envs {
        c.env(k, v);
    }
    finish(c.output(), "bash")
}

fn run(program: &str, args: &[String], cwd: &Path) -> Result<Out, String> {
    let mut c = Command::new(program);
    c.args(args).current_dir(cwd).stdin(Stdio::null());
    finish(c.output(), program)
}

fn sha256_file(p: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("{}: {e}", p.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_bytes(b: &[u8]) -> String {
    hex(&sha2::Sha256::digest(b))
}

fn on_wsl() -> bool {
    std::fs::read_to_string("/proc/version").map(|v| v.to_ascii_lowercase().contains("microsoft")).unwrap_or(false)
}

/// The typed confirmation: the flag value, else (on a terminal) a prompt.
/// `Err` says what to do instead.
fn confirm_phrase(given: &Option<String>, tty: bool, phrase: &str, prompt: &str, flag: &str) -> Result<(), String> {
    if let Some(g) = given {
        return if g.trim() == phrase {
            Ok(())
        } else {
            Err(format!("{flag}: that is not the phrase. It is exactly: {phrase}"))
        };
    }
    if !tty {
        return Err(format!("{prompt}\n  No terminal to ask on: pass {flag} \"{phrase}\" once you mean it."));
    }
    println!("{prompt}");
    println!("  To proceed, type \"{phrase}\"");
    let line = crate::onboard::prompt::read_line_edited("  > ").unwrap_or_default();
    if line.trim() == phrase {
        Ok(())
    } else {
        Err("that was not the phrase; nothing was changed".into())
    }
}

// ── the plan (preflight) ────────────────────────────────────────────────

/// `rsync` arguments for one directory; the same flags `noo-hostd at-rest
/// copy` uses (node-agent-go/internal/hostd/atrest_migrate_linux.go).
pub(crate) fn rsync_args(mode: &str, src: &str, dst: &str) -> Vec<String> {
    let mut a: Vec<String> = vec!["-aHAXS".into(), "--numeric-ids".into()];
    match mode {
        "final" => a.push("--delete".into()),
        "verify" => {
            for x in ["--checksum", "--dry-run", "--delete", "--itemize-changes"] {
                a.push(x.into());
            }
        }
        _ => {}
    }
    a.push(format!("{}/", src.trim_end_matches('/')));
    a.push(format!("{}/", dst.trim_end_matches('/')));
    a
}

/// `noo-hostd at-rest copy …` behind sudo, as an argv.
pub(crate) fn hostd_copy_argv(ctx: &Ctx, src: &str, name: &str, mode: &str) -> Vec<String> {
    vec![
        ctx.hostd.clone(),
        "at-rest".into(),
        "copy".into(),
        "--src".into(),
        src.into(),
        "--name".into(),
        name.into(),
        "--mode".into(),
        mode.into(),
    ]
}

fn quote_id(s: &str) -> Result<String, String> {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(format!("\"{s}\""))
    } else {
        Err(format!("unexpected characters in the table name {s:?}"))
    }
}

/// The docker volume whose name is `suffix` or ends `_suffix`: its
/// Mountpoint. `Ok(None)` = no such volume; `Err` = ambiguous.
fn docker_volume(ctx: &Ctx, suffix: &str) -> Result<Option<(String, String)>, String> {
    let ls = match run(&ctx.docker, &["volume".into(), "ls".into(), "--format".into(), "{{.Name}}".into()], &ctx.root) {
        Ok(o) if o.ok => o,
        _ => return Ok(None), // no docker, or no daemon: nothing to copy from it
    };
    let tail = format!("_{suffix}");
    let names: Vec<&str> = ls.stdout.lines().map(str::trim).filter(|n| *n == suffix || n.ends_with(&tail)).collect();
    match names.as_slice() {
        [] => Ok(None),
        [one] => {
            let ins = run(&ctx.docker, &["volume".into(), "inspect".into(), "--format".into(), "{{.Mountpoint}}".into(), (*one).into()], &ctx.root)?;
            let mp = ins.stdout.trim().to_string();
            if !ins.ok || !mp.starts_with('/') {
                return Err(format!("docker volume inspect {one} gave no mountpoint"));
            }
            Ok(Some(((*one).to_string(), mp)))
        }
        many => Err(format!("more than one docker volume ends in {suffix} ({}): refusing to guess which is this install's", many.join(", "))),
    }
}

/// `noo-hostd at-rest measure --entry <path>=<name> ...` behind sudo, as an argv.
pub(crate) fn hostd_measure_argv(ctx: &Ctx, entries: &[(String, String)]) -> Vec<String> {
    let mut a = vec![ctx.sudo.clone(), ctx.hostd.clone(), "at-rest".into(), "measure".into()];
    for (name, src) in entries {
        a.push("--entry".into());
        a.push(format!("{src}={name}"));
    }
    a
}

/// Parse measure's one JSON line. EVERY requested name must be present: a
/// partial answer is refused, never summed (a too-small total would size a
/// volume that fails mid-copy).
pub(crate) fn parse_measure(stdout: &str, names: &[String]) -> Result<u64, String> {
    let line = stdout.lines().rev().find(|l| l.trim_start().starts_with('{')).unwrap_or("");
    let v: Value = serde_json::from_str(line).map_err(|_| "the size measurement printed nothing readable".to_string())?;
    if v["ok"] != true {
        return Err("the size measurement did not report success".into());
    }
    let mut total = 0u64;
    for n in names {
        total = total.saturating_add(v["bytes"][n].as_u64().ok_or_else(|| format!("the size measurement has no figure for {n}"))?);
    }
    Ok(total)
}

/// Measure the state as ROOT (the operator cannot read postgres's directory,
/// so `du` here would under-count and the volume would be sized too small).
/// Failure or a partial answer REFUSES; it never falls back to a minimum.
fn measure_state(ctx: &Ctx, entries: &[(String, String)]) -> Result<u64, String> {
    let argv = hostd_measure_argv(ctx, entries);
    let o = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(&ctx.root)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| format!("could not run {}: {e}", argv[0]))?;
    let refuse = |why: String| {
        format!("could not measure the state as root, so the volume cannot be sized safely: {why}. Nothing was changed. Fix it (is noo-hostd installed and sudo allowed?) and run again")
    };
    if !o.status.success() {
        return Err(refuse(format!("`sudo noo-hostd at-rest measure` exited {} (its reason is above)", o.status.code().unwrap_or(-1))));
    }
    let names: Vec<String> = entries.iter().map(|(n, _)| n.clone()).collect();
    parse_measure(&String::from_utf8_lossy(&o.stdout), &names).map_err(refuse)
}

/// Read-only: the plan for this machine, or the reason it cannot proceed.
/// Touches nothing (so `--dry-run` can print it).
pub(crate) fn compute_plan(ctx: &Ctx) -> Result<Value, String> {
    if ctx.backend == Backend::Hostd && (!cfg!(target_os = "linux") || on_wsl()) {
        return Err("not supported here: the encrypted state volume is for Linux controllers (not macOS, WSL2 or worker nodes)".into());
    }
    let env_file = ctx.env_path();
    if !env_file.is_file() {
        return Err(format!("{} is missing: this is not an installed controller root (set NOO_REPO_ROOT?)", env_file.display()));
    }
    // A value set in the process environment or noomesh.yaml, not in .env,
    // would shadow the switch: refuse rather than switch nothing.
    for k in ["NOO_STATE_ROOT", "NOO_PKI_DIR", "NOO_PG_DATA"] {
        let from_env = ctx.env.get(k).cloned().unwrap_or_default();
        if !from_env.is_empty() && env_file_value(&env_file, k) != from_env {
            return Err(format!("{k} is set in the environment ({from_env}) and differs from .env: the switch would not take effect. Unset it (or put it in .env) and run again"));
        }
    }
    if let Ok(y) = std::fs::read_to_string(ctx.root.join("noomesh.yaml")) {
        for k in ["NOO_STATE_ROOT", "NOO_PKI_DIR", "NOO_PG_DATA"] {
            if y.lines().any(|l| !l.trim_start().starts_with('#') && l.contains(k)) {
                return Err(format!("noomesh.yaml sets {k} (compose_env): that wins over .env, so the switch would not take effect. Remove it there first"));
            }
        }
    }
    let data_root = {
        let d = ctx.eff("NOO_DATA_ROOT");
        if d.is_empty() { crate::commands::data_root::DEFAULT_DATA_ROOT.to_string() } else { d.trim_end_matches('/').to_string() }
    };
    let old_state = resolve_state_root(&|k| {
        let v = ctx.eff(k);
        if v.is_empty() { None } else { Some(v) }
    });
    // Where the volume is (or will be).
    let (mount, volume_exists, vol_free): (String, bool, Option<u64>) = match &ctx.backend {
        Backend::Dir(d) => {
            let m = d.display().to_string();
            if m.is_empty() || !d.is_dir() {
                return Err("NOO_AT_REST_VOLUME=dir needs NOO_AT_REST_VOLUME_DIR=<an existing directory>".into());
            }
            let free = at_rest_volume::free_bytes(&m);
            (m, true, free)
        }
        Backend::Hostd => match read_volume() {
            Some(v) => {
                let free = at_rest_volume::free_bytes(&v.mountpoint);
                (v.mountpoint.clone(), true, free)
            }
            None => (format!("{data_root}/state"), false, None),
        },
    };
    let m = mount.trim_end_matches('/').to_string();
    let as_volume = Volume {
        file: String::new(),
        mountpoint: m.clone(),
        size_gib: 0,
        pcrs: String::new(),
        recovery: String::new(),
        created_at: String::new(),
    };
    if state_on_volume(&old_state, &as_volume) {
        return Err(format!("this install's state root {old_state} is already on the encrypted volume {m}: nothing to migrate"));
    }

    // What to copy.
    let mut copies: Vec<Value> = Vec::new();
    let pg_override = ctx.eff("NOO_PG_DATA");
    for name in STATE_COPIES {
        let src = if name == "postgres" && !pg_override.is_empty() {
            pg_override.trim_end_matches('/').to_string()
        } else {
            format!("{}/{name}", old_state.trim_end_matches('/'))
        };
        if Path::new(&src).is_dir() {
            copies.push(json!({"name": name, "src": src}));
        } else if name == "postgres" {
            return Err(format!("the database directory {src} does not exist: this does not look like an install with data to migrate (NOO_PG_DATA / NOO_STATE_ROOT / NOO_DATA_ROOT?)"));
        }
    }
    for (suffix, _var, _to) in DOCKER_COPIES {
        if let Some((vol, mp)) = docker_volume(ctx, suffix)? {
            copies.push(json!({"name": suffix, "src": mp, "volume": vol}));
        }
    }
    let pki_src = {
        let p = ctx.eff("NOO_PKI_DIR");
        if p.is_empty() { format!("{}/.config/mesh/pki", ctx.home()) } else { p.trim_end_matches('/').to_string() }
    };
    if !Path::new(&pki_src).is_dir() {
        return Err(format!("the PKI directory {pki_src} does not exist (NOO_PKI_DIR?): refusing to migrate without it"));
    }
    let mut measured: Vec<(String, String)> = copies
        .iter()
        .filter_map(|c| Some((c["name"].as_str()?.to_string(), c["src"].as_str()?.to_string())))
        .collect();
    measured.push(("pki".to_string(), pki_src.clone()));
    let du = measure_state(ctx, &measured)?;

    // Space, and the TPM when the volume has to be made.
    let size_gib = at_rest_volume::size_for(du);
    if volume_exists {
        let need = du.saturating_add(du / 5).saturating_add(GIB);
        if let Some(free) = vol_free.filter(|f| *f < need) {
            return Err(format!(
                "not enough free space on the encrypted volume {m}: {} GiB free, about {} GiB needed (state {} GiB plus margin). Grow the volume or free space",
                free / GIB,
                need / GIB,
                du / GIB
            ));
        }
    } else {
        let need = (size_gib + MARGIN_GIB) * GIB;
        if let Some(free) = at_rest_volume::free_bytes(&data_root).filter(|f| *f < need) {
            return Err(format!(
                "not enough free space under {data_root} for the {size_gib} GiB encrypted volume (twice the measured {} GiB of state, at least {} GiB) plus the {MARGIN_GIB} GiB margin: {} GiB free, {} GiB needed. Free space on that disk, or move NOO_DATA_ROOT, and run again",
                du / GIB,
                at_rest_volume::MIN_SIZE_GIB,
                free / GIB,
                need / GIB
            ));
        }
        let tpm = TpmFacts::probe(Path::new("/"));
        if !tpm.tpm2_usable() {
            return Err(format!(
                "no usable TPM 2.0 here ({}); the volume would not unlock at boot. {}",
                tpm.unavailable_reason(),
                crate::commands::at_rest::enable_hint(&tpm)
            ));
        }
        if !tpm.missing_tools().is_empty() {
            return Err(format!("missing: {} (install cryptsetup and systemd 250 or newer)", tpm.missing_tools().join(", ")));
        }
    }
    Ok(json!({
        "old_state": old_state,
        "new_state": m,
        "data_root": data_root,
        "volume_exists": volume_exists,
        "size_gib": size_gib,
        "du_bytes": du,
        "copies": copies,
        "pki_src": pki_src,
        "pki_dst": format!("{m}/pki"),
        "pg_data_was_set": !pg_override.is_empty(),
    }))
}

fn plan_copies(j: &Journal) -> Vec<(String, String, Option<String>)> {
    j.v["plan"]["copies"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|c| (c["name"].as_str().unwrap_or("").to_string(), c["src"].as_str().unwrap_or("").to_string(), c["volume"].as_str().map(str::to_string)))
                .collect()
        })
        .unwrap_or_default()
}

/// Every directory that is copied: the state set, then the PKI.
fn all_dirs(j: &Journal) -> Vec<(String, String, Option<String>)> {
    let mut v = plan_copies(j);
    v.push(("pki".to_string(), j.s(&["plan", "pki_src"]), None));
    v
}

// ── cluster verify ──────────────────────────────────────────────────────

/// `(failing check names, at-rest rows as (name, verdict, detail))`.
type VerifyRows = (BTreeSet<String>, Vec<(String, String, String)>);

/// `(failing check names, the at-rest rows as "name: verdict — detail")`.
/// Err when the output cannot be read: a verdict from nothing is no verdict.
fn verify_rows(ctx: &Ctx) -> Result<VerifyRows, String> {
    let o = run(&ctx.noo, &["cluster".into(), "verify".into(), "--controller".into(), "--json".into()], &ctx.root)?;
    let line = o.stdout.lines().rev().find(|l| l.trim_start().starts_with('{')).unwrap_or("");
    let v: Value = serde_json::from_str(line).map_err(|_| format!("the JSON of `noo cluster verify --controller` was not readable (exit {}): {}", o.code, o.tail()))?;
    let checks = v["controller"]["checks"].as_array().ok_or("cluster verify --json has no controller checks")?;
    let mut failing = BTreeSet::new();
    let mut rows = Vec::new();
    for c in checks {
        let name = c["name"].as_str().unwrap_or("").to_string();
        let verdict = c["verdict"].as_str().unwrap_or("").to_string();
        if verdict == "fail" {
            failing.insert(name.clone());
        }
        if name.starts_with("at-rest") {
            rows.push((name, verdict, c["detail"].as_str().unwrap_or("").to_string()));
        }
    }
    Ok((failing, rows))
}

/// Failing checks now that were not failing in the baseline, plus the
/// at-rest volume row (which must be ok on a real volume).
fn health_problems(ctx: &Ctx, baseline: &BTreeSet<String>) -> Result<Vec<String>, String> {
    let (failing, rows) = verify_rows(ctx)?;
    let mut problems: Vec<String> = failing.difference(baseline).map(|n| format!("{n}: FAIL (was not failing before the migration)")).collect();
    if ctx.backend == Backend::Hostd {
        match rows.iter().find(|r| r.0 == "at-rest volume") {
            Some(r) if r.1 == "ok" => {}
            Some(r) => problems.push(format!("at-rest volume: {} — {}", r.1, r.2)),
            None => problems.push("at-rest volume: no such row (is this noo older than part C?)".into()),
        }
    }
    for (n, v, d) in &rows {
        ui::step(&format!("{n}: {v} — {d}"));
    }
    Ok(problems)
}

/// Poll [`health_problems`] until none, or the deadline.
fn wait_healthy(ctx: &Ctx, baseline: &BTreeSet<String>) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(ctx.verify_wait_secs);
    loop {
        let problems = health_problems(ctx, baseline)?;
        if problems.is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("the stack is not healthy:\n  {}", problems.join("\n  ")));
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

// ── row counts ──────────────────────────────────────────────────────────

fn psql(ctx: &Ctx, sql: &str) -> Result<String, String> {
    let o = sh(&ctx.root, &ctx.psql_cmd, &[("NOO_SQL", sql)])?;
    if !o.ok {
        return Err(format!("the database query failed (exit {}; is the stack running?): {}", o.code, o.tail()));
    }
    Ok(o.stdout)
}

/// `(tables counted, exact row count per table, database size in bytes)`.
type Counts = (Vec<String>, BTreeMap<String, u64>, u64);

/// Exact counts of the ten busiest tables (from pg_stat_user_tables) and the
/// database size. `tables` fixes which tables are counted: the "after"
/// capture counts the same ones.
fn capture_counts(ctx: &Ctx, tables: Option<Vec<String>>) -> Result<Counts, String> {
    let tables = match tables {
        Some(t) => t,
        None => psql(
            ctx,
            "select schemaname || '.' || relname from pg_stat_user_tables order by n_live_tup desc, 1 limit 10",
        )?
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect(),
    };
    let mut counts = BTreeMap::new();
    for t in &tables {
        let (schema, table) = t.split_once('.').ok_or_else(|| format!("unexpected table name {t:?}"))?;
        let sql = format!("select count(*) from {}.{}", quote_id(schema)?, quote_id(table)?);
        let n: u64 = psql(ctx, &sql)?.trim().parse().map_err(|_| format!("count of {t} was not a number"))?;
        counts.insert(t.clone(), n);
    }
    let size: u64 = psql(ctx, "select pg_database_size(current_database())")?.trim().parse().unwrap_or(0);
    Ok((tables, counts, size))
}

// ── backups ─────────────────────────────────────────────────────────────

fn list_files(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter(|e| e.path().is_file()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default()
}

/// Run the backup, then restore-drill the new dump. Returns the journal
/// record `{taken_at, artifacts:[{path,sha256}], offsite_ok, drill:"ok"}`.
/// "Fresh" = files that did not exist before this run.
fn take_backup(ctx: &Ctx) -> Result<Value, String> {
    let before = list_files(&ctx.backup_dir);
    let bdir = ctx.backup_dir.display().to_string();
    say("taking a fresh backup (scripts/backup-controller.sh)");
    let out = sh(&ctx.root, &ctx.backup_cmd, &[("NOO_BACKUP_DIR", bdir.as_str())])?;
    let text = format!("{}\n{}", out.stdout, out.stderr);
    let offsite_failed_only = !out.ok && text.contains("the offsite copy FAILED");
    if !out.ok && !offsite_failed_only {
        return Err(format!("the backup failed (exit {}), so nothing was changed:\n{}", out.code, out.tail()));
    }
    let offsite_ok = text.lines().any(|l| l.trim_start().starts_with("offsite: copied"));
    let after = list_files(&ctx.backup_dir);
    let fresh: Vec<String> = after.difference(&before).cloned().collect();
    let pg = fresh.iter().find(|n| n.starts_with("pg_") && n.ends_with(".sql.gz.enc")).cloned();
    let Some(pg) = pg else {
        return Err(format!(
            "the backup script exited 0 but wrote no new pg_*.sql.gz.enc in {}: that is not a fresh backup. Nothing was changed",
            ctx.backup_dir.display()
        ));
    };
    let pg_path = ctx.backup_dir.join(&pg);
    if std::fs::metadata(&pg_path).map(|m| m.len()).unwrap_or(0) == 0 {
        return Err(format!("{} is empty: not a usable backup", pg_path.display()));
    }
    say(&format!("proving {pg} decrypts and restores (scripts/restore-drill.sh)"));
    let pg_str = pg_path.display().to_string();
    let drill = sh(&ctx.root, &ctx.drill_cmd, &[("NOO_DRILL_BACKUP", pg_str.as_str()), ("NOO_BACKUP_DIR", bdir.as_str())])?;
    if !drill.ok {
        return Err(format!("the restore drill FAILED on the new backup (exit {}), so it is not trusted and nothing was changed:\n{}", drill.code, drill.tail()));
    }
    let mut artifacts = Vec::new();
    for n in &fresh {
        let p = ctx.backup_dir.join(n);
        artifacts.push(json!({"path": p.display().to_string(), "sha256": sha256_file(&p)?}));
    }
    Ok(json!({"taken_at": ctx.now, "artifacts": artifacts, "offsite_ok": offsite_ok, "offsite_failed": offsite_failed_only, "drill": "ok"}))
}

/// Do the journaled artifacts still exist with the same sha256?
fn artifacts_intact(b: &Value) -> Result<(), String> {
    let arts = b["artifacts"].as_array().ok_or("the journal records no backup artifacts")?;
    if arts.is_empty() {
        return Err("the journal records no backup artifacts".into());
    }
    for a in arts {
        let p = a["path"].as_str().unwrap_or("");
        let want = a["sha256"].as_str().unwrap_or("");
        let got = sha256_file(Path::new(p))?;
        if got != want {
            return Err(format!("{p} changed since it was journaled (sha256 {got}, expected {want})"));
        }
    }
    Ok(())
}

// ── the steps ───────────────────────────────────────────────────────────

fn step_preflight(ctx: &Ctx, j: &mut Journal) -> Result<(), String> {
    let plan = compute_plan(ctx)?;
    let env_path = ctx.env_path();
    let orig = ctx.root.join(ENV_ORIG);
    if !orig.exists() {
        // fs::copy keeps the mode, so a restore is the same bytes AND mode.
        std::fs::copy(&env_path, &orig).map_err(|e| format!("saving {}: {e}", orig.display()))?;
    }
    j.v["env_sha256"] = json!(sha256_bytes(&std::fs::read(&orig).map_err(|e| format!("{}: {e}", orig.display()))?));
    let mut old = serde_json::Map::new();
    for k in ENV_KEYS {
        let v = env_file_value(&env_path, k);
        old.insert(k.to_string(), if v.is_empty() { Value::Null } else { json!(v) });
    }
    j.v["old_env"] = Value::Object(old);
    j.v["plan"] = plan;
    say("recording a baseline of `noo cluster verify` (what already fails is not blamed on the migration)");
    let (failing, _) = verify_rows(ctx)?;
    j.v["baseline_failing"] = json!(failing.iter().cloned().collect::<Vec<_>>());
    let p = &j.v["plan"];
    ui::done(&format!(
        "plan: {} dirs ({} GiB) from {} + PKI {} -> {} ({})",
        p["copies"].as_array().map(|a| a.len()).unwrap_or(0),
        p["du_bytes"].as_u64().unwrap_or(0) / GIB,
        p["old_state"].as_str().unwrap_or(""),
        p["pki_src"].as_str().unwrap_or(""),
        p["new_state"].as_str().unwrap_or(""),
        if p["volume_exists"].as_bool().unwrap_or(false) { "volume exists" } else { "volume will be created" }
    ));
    Ok(())
}

fn step_backup(ctx: &Ctx, j: &mut Journal) -> Result<(), String> {
    j.v["backup"] = take_backup(ctx)?;
    // Journal now: a crash between here and the step mark must not lose the
    // artifact list that the offbox step reads.
    j.save()
}

fn step_offbox(ctx: &Ctx, j: &mut Journal) -> Result<(), String> {
    artifacts_intact(&j.v["backup"])?;
    if j.v["backup"]["offsite_ok"].as_bool().unwrap_or(false) {
        j.v["offbox"] = json!({"proof": "offsite", "at": ctx.now});
        ui::done("the backup script reported an offsite copy");
        return Ok(());
    }
    let why = if j.v["backup"]["offsite_failed"].as_bool().unwrap_or(false) {
        "the offsite copy FAILED"
    } else {
        "no offsite copy was made (NOO_BACKUP_OFFSITE unset, none or portable)"
    };
    let prompt = format!(
        "{why}. The backup just taken is only on this machine. If the disk is lost mid-migration, so is it.\n  \
         Copy it somewhere else now (scripts/noo-backup-export.sh, or `noo backups setup`) — or accept the risk."
    );
    confirm_phrase(&ctx.offbox_phrase, ctx.tty, OFFBOX_PHRASE, &prompt, "--confirm-offbox")?;
    j.v["offbox"] = json!({"proof": "phrase", "at": ctx.now});
    Ok(())
}

fn step_volume(ctx: &Ctx, j: &mut Journal) -> Result<(), String> {
    match &ctx.backend {
        Backend::Dir(d) => {
            if !d.is_dir() {
                return Err(format!("{} is not a directory", d.display()));
            }
            Ok(())
        }
        Backend::Hostd => {
            if let Some(v) = read_volume() {
                ui::done(&format!("the encrypted volume {} already exists", v.file));
                j.v["plan"]["new_state"] = json!(v.mountpoint.clone());
                j.v["plan"]["pki_dst"] = json!(format!("{}/pki", v.mountpoint));
                return Ok(());
            }
            let Some(g) = ctx.g else { return Err("cannot create the volume without a command context".into()) };
            let size = j.u(&["plan", "size_gib"]).to_string();
            say("creating the encrypted state volume (noo security at-rest create-volume): it shows its recovery key ONCE; store it off this machine");
            let rc = at_rest_volume::security_at_rest_create_volume(g, &["--size".to_string(), size]).map_err(|_| "create-volume: bad arguments".to_string())?;
            if rc != 0 {
                return Err(format!("create-volume exited {rc}"));
            }
            let v = read_volume().ok_or("create-volume succeeded but /etc/noo/at-rest.json records no volume")?;
            j.v["plan"]["new_state"] = json!(v.mountpoint.clone());
            j.v["plan"]["pki_dst"] = json!(format!("{}/pki", v.mountpoint));
            Ok(())
        }
    }
}

/// One directory, through the root helper (or rsync directly on the dir backend).
fn copy_one(ctx: &Ctx, src: &str, name: &str, mode: &str) -> Result<(), String> {
    match &ctx.backend {
        Backend::Dir(d) => {
            let dst = d.join(name);
            if mode != "verify" {
                std::fs::create_dir_all(&dst).map_err(|e| format!("{}: {e}", dst.display()))?;
            }
            let o = run(&ctx.rsync, &rsync_args(mode, src, &dst.display().to_string()), &ctx.root)?;
            if !o.ok {
                return Err(format!("rsync {name} ({mode}) failed (exit {}): {}", o.code, o.tail()));
            }
            if mode == "verify" {
                let diffs: Vec<&str> = o.stdout.lines().filter(|l| !l.trim().is_empty()).collect();
                if !diffs.is_empty() {
                    return Err(format!("{name}: {} difference(s) between {src} and {}; first: {}", diffs.len(), dst.display(), diffs[0]));
                }
            }
            Ok(())
        }
        Backend::Hostd => {
            let mut argv = vec![ctx.sudo.clone()];
            argv.extend(hostd_copy_argv(ctx, src, name, mode));
            say(&format!("{name}: {mode} copy -> the encrypted volume (sudo noo-hostd at-rest copy)"));
            let o = Command::new(&argv[0])
                .args(&argv[1..])
                .current_dir(&ctx.root)
                .stdin(Stdio::inherit())
                .stderr(Stdio::inherit())
                .stdout(Stdio::piped())
                .output()
                .map_err(|e| format!("could not run {}: {e}", argv[0]))?;
            if !o.status.success() {
                return Err(format!("{name}: {mode} copy failed (exit {}); its reason is above", o.status.code().unwrap_or(-1)));
            }
            Ok(())
        }
    }
}

fn step_copy(ctx: &Ctx, j: &Journal, mode: &str) -> Result<(), String> {
    for (name, src, _) in all_dirs(j) {
        copy_one(ctx, &src, &name, mode)?;
    }
    Ok(())
}

fn step_rowcounts(ctx: &Ctx, j: &mut Journal) -> Result<(), String> {
    let (tables, counts, size) = capture_counts(ctx, None)?;
    j.v["rowcounts"] = json!({"tables": tables, "counts": counts, "db_bytes": size, "at": ctx.now});
    ui::done(&format!("recorded row counts for {} tables, database {} MiB", tables.len(), size >> 20));
    Ok(())
}

fn stack(ctx: &Ctx, verb: &str) -> Result<(), String> {
    say(&format!("running: stack {verb}"));
    let st = Command::new(&ctx.noo)
        .args(["stack", verb])
        .current_dir(&ctx.root)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("could not run {}: {e}", ctx.noo))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("the stack {verb} command exited {}", st.code().unwrap_or(-1)))
    }
}

fn step_switch(ctx: &Ctx, j: &mut Journal) -> Result<(), String> {
    let env_path = ctx.env_path();
    let new_state = j.s(&["plan", "new_state"]);
    let pki_dst = j.s(&["plan", "pki_dst"]);
    let old_pki = j.s(&["plan", "pki_src"]);
    let set = |k: &str, v: &str| crate::onboard::env::update_env_key(&env_path, k, v).map_err(|e| format!("{}: {e}", env_path.display()));
    set("NOO_STATE_ROOT", &new_state)?;
    set("NOO_PKI_DIR", &pki_dst)?;
    if j.v["plan"]["pg_data_was_set"].as_bool().unwrap_or(false) {
        set("NOO_PG_DATA", &format!("{new_state}/postgres"))?;
    }
    let prefix = format!("{}/", old_pki.trim_end_matches('/'));
    for k in ["NOO_TLS_CA", "NOO_TLS_CERT", "NOO_TLS_KEY"] {
        let v = env_file_value(&env_path, k);
        if let Some(rest) = v.strip_prefix(&prefix) {
            set(k, &format!("{pki_dst}/{rest}"))?;
        }
    }
    for (suffix, var, to) in DOCKER_COPIES {
        if plan_copies(j).iter().any(|(n, _, _)| n == suffix) {
            set(var, to)?;
        }
    }
    j.v["switched_at"] = json!(ctx.now);
    ui::done(&format!("{} now points the state at {new_state} (the original is saved as {ENV_ORIG})", env_path.display()));
    Ok(())
}

fn step_verify(ctx: &Ctx, j: &mut Journal) -> Result<(), String> {
    let baseline: BTreeSet<String> = j.v["baseline_failing"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    wait_healthy(ctx, &baseline).map_err(|e| format!("{e}\n  the stack started from the new state but is not healthy. To go back: noo security at-rest migrate --rollback"))?;
    let tables: Vec<String> = j.v["rowcounts"]["tables"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let (_, after, size) = capture_counts(ctx, Some(tables))?;
    let mut bad = Vec::new();
    for (t, n) in after.iter() {
        let before = j.v["rowcounts"]["counts"][t].as_u64().unwrap_or(0);
        if *n < before {
            bad.push(format!("{t}: {before} rows before, {n} now"));
        }
    }
    j.v["rowcounts_after"] = json!({"counts": after, "db_bytes": size, "at": ctx.now});
    if !bad.is_empty() {
        return Err(format!(
            "row counts DROPPED after the move:\n  {}\n  Do not wipe anything. To go back: noo security at-rest migrate --rollback",
            bad.join("\n  ")
        ));
    }
    j.v["healthy_since"] = json!(ctx.now);
    ui::done("healthy on the encrypted state; no table lost rows");
    Ok(())
}

fn step_postbackup(ctx: &Ctx, j: &mut Journal) -> Result<(), String> {
    let mut b = take_backup(ctx)?;
    b["from_state"] = json!(j.s(&["plan", "new_state"]));
    j.v["post_backup"] = b;
    Ok(())
}

fn run_step(ctx: &Ctx, j: &mut Journal, step: &str) -> Result<(), String> {
    match step {
        "preflight" => step_preflight(ctx, j),
        "backup" => step_backup(ctx, j),
        "offbox" => step_offbox(ctx, j),
        "volume" => step_volume(ctx, j),
        "precopy" => step_copy(ctx, j, "pre"),
        "rowcounts" => step_rowcounts(ctx, j),
        "stop" => stack(ctx, "stop"),
        "finalsync" => {
            step_copy(ctx, j, "final")?;
            say("verifying: a --checksum dry-run must list ZERO differences");
            step_copy(ctx, j, "verify")
        }
        "switch" => step_switch(ctx, j),
        "start" => stack(ctx, "start"),
        "verify" => step_verify(ctx, j),
        "postbackup" => step_postbackup(ctx, j),
        other => Err(format!("unknown step {other}")),
    }
}

// ── the engine ──────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    DryRun,
    Stopped(String),
    Complete,
}

fn dry_run_plan(ctx: &Ctx, j: Option<&Journal>) -> Result<(), String> {
    println!("dry run: nothing is changed, no file is written. The steps, in order:");
    let plan = match j.filter(|j| j.v["plan"].is_object()) {
        Some(j) => j.v["plan"].clone(),
        None => compute_plan(ctx)?,
    };
    let dirs: Vec<String> = plan["copies"].as_array().map(|a| a.iter().filter_map(|c| c["name"].as_str().map(str::to_string)).collect()).unwrap_or_default();
    let new_state = plan["new_state"].as_str().unwrap_or("");
    let detail = |s: &str| -> String {
        match s {
            "preflight" => format!("save .env as {ENV_ORIG}; record {} -> {new_state}; baseline `noo cluster verify`", plan["old_state"].as_str().unwrap_or("")),
            "backup" => "scripts/backup-controller.sh, then scripts/restore-drill.sh on the new dump; sha256s journaled".into(),
            "offbox" => format!("an offsite copy, or the phrase \"{OFFBOX_PHRASE}\""),
            "volume" => if plan["volume_exists"].as_bool().unwrap_or(false) { "the volume exists".into() } else { format!("create a {} GiB volume (noo security at-rest create-volume; recovery key shown once)", plan["size_gib"].as_u64().unwrap_or(0)) },
            "precopy" => format!("online rsync -aHAXS --numeric-ids of {} and the PKI {} into {new_state}", dirs.join(", "), plan["pki_src"].as_str().unwrap_or("")),
            "rowcounts" => "exact counts of the ten busiest tables, database size".into(),
            "stop" => "noo stack stop (the maintenance window starts)".into(),
            "finalsync" => "rsync --delete, then a --checksum dry-run that must show zero differences".into(),
            "switch" => "NOO_STATE_ROOT, NOO_PKI_DIR (NOO_PG_DATA, TLS paths) in .env; claude-config and alertmanager-data to bind volumes".into(),
            "start" => "noo stack start".into(),
            "verify" => "health, cluster verify rows, row counts compared (none may drop)".into(),
            "postbackup" => "a backup taken FROM the encrypted state (wipe-plaintext needs it)".into(),
            _ => String::new(),
        }
    };
    for (i, s) in STEPS.iter().copied().enumerate() {
        let state = match j {
            Some(j) if j.is_done(s) => "done",
            _ => "todo",
        };
        println!("  {:>2}. [{state}] {s}: {}", i + 1, detail(s));
    }
    println!("The old plaintext directories are never touched by migrate; `--rollback` returns to them. Deleting them is `noo security at-rest wipe-plaintext`.");
    Ok(())
}

/// Start or resume the migration.
pub(crate) fn run_migrate(ctx: &Ctx) -> Result<Outcome, String> {
    let jpath = ctx.root.join(JOURNAL);
    let existing = Journal::load(&jpath)?;
    if ctx.dry_run {
        dry_run_plan(ctx, existing.as_ref().filter(|j| j.state() == "in_progress"))?;
        return Ok(Outcome::DryRun);
    }
    let mut j = match existing {
        Some(j) if j.state() == "complete" => {
            return Err("this install is already migrated (the journal says complete). Next: `noo security at-rest wipe-plaintext` after a day of healthy running; to undo, `--rollback`".into());
        }
        Some(j) if j.state() == "rolled_back" => {
            let old = ctx.root.join(format!("{JOURNAL}.rolled-back-{}", ctx.now));
            std::fs::rename(&jpath, &old).map_err(|e| format!("{}: {e}", old.display()))?;
            // The saved .env belongs to the old attempt.
            let _ = std::fs::rename(ctx.root.join(ENV_ORIG), ctx.root.join(format!("{ENV_ORIG}.rolled-back-{}", ctx.now)));
            Journal::fresh(jpath.clone(), ctx.now, &ctx.backend)
        }
        Some(j) => {
            ui::step(&format!("resuming the migration started at {}", j.u(&["started_at"])));
            j
        }
        None => Journal::fresh(jpath.clone(), ctx.now, &ctx.backend),
    };
    let nothing_done = STEPS.iter().all(|s| !j.is_done(s));
    if nothing_done && !ctx.yes {
        if !ctx.tty {
            return Err("no terminal to confirm on: pass --yes (see --dry-run for the steps)".into());
        }
        let plan = compute_plan(ctx)?;
        let prompt = format!(
            "This moves the state of this controller onto the encrypted volume {}.\n  \
             The stack will be STOPPED for the final copy (about the time it takes to copy {} GiB again).\n  \
             A fresh backup comes first; the old data is not deleted; `--rollback` undoes it.",
            plan["new_state"].as_str().unwrap_or(""),
            plan["du_bytes"].as_u64().unwrap_or(0) / GIB
        );
        println!("{prompt}");
        let a = crate::onboard::prompt::read_line_edited("  Type yes to begin: ").unwrap_or_default();
        if a.trim() != "yes" {
            return Err("not confirmed; nothing was changed".into());
        }
    }
    for step in STEPS {
        if j.is_done(step) {
            continue;
        }
        ui::step(&format!("[{}/{}] {step}", STEPS.iter().position(|s| *s == step).unwrap_or(0) + 1, STEPS.len()));
        run_step(ctx, &mut j, step).map_err(|e| {
            // Nothing journaled yet (a refused preflight) leaves no file behind.
            if STEPS.iter().any(|s| j.is_done(s)) {
                j.v["last_error"] = json!({"step": step, "error": e.clone(), "at": ctx.now});
                let _ = j.save();
            }
            format!("step {step} failed: {e}\n  Nothing past this step ran. Fix the cause and run the same command again to resume; or `noo security at-rest migrate --rollback`.")
        })?;
        if ctx.crash_before_journal == Some(step) {
            return Err(format!("simulated crash after {step}, before it was journaled"));
        }
        j.mark(step, ctx.now);
        j.v["last_error"] = Value::Null;
        j.save()?;
        if ctx.stop_after == Some(step) {
            return Ok(Outcome::Stopped(step.to_string()));
        }
    }
    j.v["state"] = json!("complete");
    j.v["completed_at"] = json!(ctx.now);
    j.save()?;
    Ok(Outcome::Complete)
}

/// `--rollback`: stop, restore `.env` byte for byte, start. The plaintext
/// was never touched; the volume stays.
pub(crate) fn run_rollback(ctx: &Ctx) -> Result<(), String> {
    let jpath = ctx.root.join(JOURNAL);
    let Some(mut j) = Journal::load(&jpath)? else {
        return Err(format!("no migration journal at {}: nothing to roll back", jpath.display()));
    };
    if j.state() == "rolled_back" {
        return Err("already rolled back".into());
    }
    if j.v["wipe"].is_object() {
        return Err("the plaintext state was wiped: there is nothing to roll back to. Restore from the backup instead (docs/operating/runbooks/backup-restore-secrets.md)".into());
    }
    let orig = ctx.root.join(ENV_ORIG);
    let bounced = j.is_done("stop");
    if bounced && !orig.is_file() {
        return Err(format!("{} is missing: cannot restore the original .env", orig.display()));
    }
    if ctx.dry_run {
        println!("dry run: nothing is changed.");
        if bounced {
            println!("  1. noo stack stop\n  2. put {} back as .env (the current one is kept as .env.pre-rollback-<time>)\n  3. noo stack start", orig.display());
        } else {
            println!("  the stack was never stopped and .env never switched: only the journal is closed");
        }
        println!("  the old plaintext directories were never modified; the encrypted volume stays.");
        return Ok(());
    }
    if bounced {
        stack(ctx, "stop")?;
        let env_path = ctx.env_path();
        if env_path.is_file() {
            let keep = ctx.root.join(format!(".env.pre-rollback-{}", ctx.now));
            std::fs::copy(&env_path, &keep).map_err(|e| format!("{}: {e}", keep.display()))?;
        }
        std::fs::copy(&orig, &env_path).map_err(|e| format!("restoring .env: {e}"))?;
        if let Some(want) = j.v["env_sha256"].as_str() {
            let got = sha256_bytes(&std::fs::read(&env_path).map_err(|e| e.to_string())?);
            if got != want {
                return Err(format!(".env restored but its sha256 {got} is not the journaled {want}"));
            }
        }
    }
    j.v["state"] = json!("rolled_back");
    j.v["rolled_back_at"] = json!(ctx.now);
    j.save()?;
    ui::done(if bounced { ".env restored exactly as it was" } else { "the journal is closed; nothing had changed" });
    if bounced {
        stack(ctx, "start")?;
    }
    ui::done("rolled back; the old plaintext state is in use again, the encrypted volume stays for another try");
    Ok(())
}

/// What `wipe-plaintext` removes: dir entries and docker volumes.
pub(crate) fn run_wipe(ctx: &Ctx) -> Result<(), String> {
    let jpath = ctx.root.join(JOURNAL);
    let Some(mut j) = Journal::load(&jpath)? else {
        return Err("no migration journal here: there is no plaintext state this tool knows to remove".into());
    };
    match j.state().as_str() {
        "complete" => {}
        "rolled_back" => return Err("the migration was rolled back: the plaintext state is the live state. Nothing to wipe".into()),
        _ => return Err("refused: the migration has not completed (the journal is still in progress). Finish it with `noo security at-rest migrate`".into()),
    }
    if j.v["wipe"].is_object() {
        return Err("already wiped".into());
    }
    for s in STEPS {
        if !j.is_done(s) {
            return Err(format!("refused: the journal says complete but step {s} was never recorded"));
        }
    }
    // A fresh backup taken FROM the encrypted state, intact.
    let pb = &j.v["post_backup"];
    if !pb.is_object() || pb["from_state"].as_str().unwrap_or("") != j.s(&["plan", "new_state"]) {
        return Err("refused: no backup was taken from the encrypted state".into());
    }
    if pb["taken_at"].as_u64().unwrap_or(0) < j.u(&["switched_at"]) {
        return Err("refused: the recorded backup is older than the switch to the encrypted state".into());
    }
    artifacts_intact(pb).map_err(|e| format!("refused: the post-migration backup is not intact: {e}"))?;
    // Time on the encrypted state.
    let since = j.u(&["healthy_since"]);
    let need = ctx.healthy_hours.saturating_mul(3600);
    let have = ctx.now.saturating_sub(since);
    if since == 0 || have < need {
        return Err(format!(
            "refused: too soon. The encrypted state has been healthy for {}h {}m of the {}h required (--hours changes the requirement; a day gives time to notice a bad write)",
            have / 3600,
            (have % 3600) / 60,
            ctx.healthy_hours
        ));
    }
    // Still on the volume, still healthy.
    let new_state = j.s(&["plan", "new_state"]);
    let now_state = ctx.eff("NOO_STATE_ROOT");
    if now_state.trim_end_matches('/') != new_state.trim_end_matches('/') {
        return Err(format!("refused: .env NOO_STATE_ROOT is {now_state:?}, not the encrypted volume {new_state}: the stack is not running from it"));
    }
    let baseline: BTreeSet<String> = j.v["baseline_failing"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let problems = health_problems(ctx, &baseline)?;
    if !problems.is_empty() {
        return Err(format!("refused: the stack is not healthy right now:\n  {}", problems.join("\n  ")));
    }
    let dirs = all_dirs(&j);
    let listing: Vec<String> = dirs.iter().map(|(n, s, v)| match v { Some(v) => format!("docker volume {v}"), None => format!("{n}: {s}") }).collect();
    if ctx.dry_run {
        println!("dry run: nothing is deleted. Would remove:\n  {}", listing.join("\n  "));
        return Ok(());
    }
    let prompt = format!(
        "This DELETES the old plaintext copies of the state. It cannot be undone, and --rollback stops working:\n  {}",
        listing.join("\n  ")
    );
    confirm_phrase(&ctx.confirm, ctx.tty, WIPE_PHRASE, &prompt, "--confirm")?;
    let mut entries: Vec<String> = Vec::new();
    for (name, src, vol) in &dirs {
        match vol {
            Some(v) => {
                let o = run(&ctx.docker, &["volume".into(), "rm".into(), v.clone()], &ctx.root)?;
                if !o.ok {
                    return Err(format!("docker volume rm {v} failed: {}", o.tail()));
                }
            }
            None => entries.push(format!("{src}={name}")),
        }
    }
    match &ctx.backend {
        Backend::Dir(_) => {
            for e in &entries {
                if let Some((p, _)) = e.rsplit_once('=') {
                    std::fs::remove_dir_all(p).map_err(|e2| format!("{p}: {e2}"))?;
                }
            }
        }
        Backend::Hostd => {
            let mut argv = vec![ctx.sudo.clone(), ctx.hostd.clone(), "at-rest".into(), "wipe".into()];
            for e in &entries {
                argv.push("--entry".into());
                argv.push(e.clone());
            }
            let st = Command::new(&argv[0])
                .args(&argv[1..])
                .current_dir(&ctx.root)
                .stdin(Stdio::inherit())
                .stderr(Stdio::inherit())
                .stdout(Stdio::piped())
                .output()
                .map_err(|e| format!("could not run {}: {e}", argv[0]))?;
            if !st.status.success() {
                return Err("the wipe failed; its reason is above. Some directories may already be gone; the encrypted copy is untouched".into());
            }
        }
    }
    j.v["wipe"] = json!({"at": ctx.now, "removed": listing});
    j.save()?;
    ui::done("the old plaintext state is removed");
    println!("{}", ui::note(SSD_CAVEAT));
    ui::guide(&[("rotate keys next", "i10a decision: the age key, the CA and leaf keys, and the DB and app secrets")]);
    Ok(())
}

pub(crate) const SSD_CAVEAT: &str =
    "On an SSD, deleting files does not erase their blocks: fstrim tells the drive they are free, but old copies of the data (the age key and PKI keys among it) may stay readable on the flash until it reuses them. Until the keys are rotated, assume the old plaintext could still be recovered from a stolen drive. Rotate keys next (i10a decision).";

// ── the hint on `noo upgrade --stack` ───────────────────────────────────

/// The line `noo upgrade --stack` prints on a controller whose state is not on
/// an encrypted volume. A hint only: upgrade never migrates.
pub(crate) fn hint_for(linux_controller: bool, tpm_usable: bool, volume: Option<&Volume>, state_root: &str) -> Option<String> {
    if !linux_controller {
        return None;
    }
    if let Some(v) = volume {
        if state_on_volume(state_root, v) {
            return None;
        }
    }
    let how = if tpm_usable {
        "`noo security at-rest migrate --dry-run` shows the steps (a fresh backup first, reversible), then `noo security at-rest migrate`; or accept the risk with `noo security at-rest opt-out`"
    } else {
        "this machine has no usable TPM 2.0 (`noo security at-rest status` says why and how to enable one); or record the decision with `noo security at-rest opt-out`"
    };
    Some(format!("your state ({state_root}) is not on an encrypted volume. {how}. This upgrade changed nothing about it."))
}

/// For `noo upgrade --stack`: the hint for THIS machine, or `None`.
pub(crate) fn upgrade_hint() -> Option<String> {
    let linux = cfg!(target_os = "linux") && !on_wsl();
    let tpm = linux && TpmFacts::probe(Path::new("/")).tpm2_usable();
    let state_root = resolve_state_root(&|k| std::env::var(k).ok());
    hint_for(linux, tpm, read_volume().as_ref(), &state_root)
}

// ── the commands ────────────────────────────────────────────────────────

fn finish_cmd(g: &Globals, r: Result<(), String>, kind: &str) -> Result<i32, Unhandled> {
    match r {
        Ok(()) => Ok(0),
        Err(e) => fail(g.json, ExitCode::Generic, kind, &e, None),
    }
}

/// `noo security at-rest migrate [--dry-run] [--rollback] [--yes] [--confirm-offbox <phrase>]`
pub fn security_at_rest_migrate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut ctx = Ctx::live(g);
    let mut rollback = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dry-run" => ctx.dry_run = true,
            "--rollback" => rollback = true,
            "--yes" | "-y" => ctx.yes = true,
            "--confirm-offbox" => ctx.offbox_phrase = Some(it.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    if rollback {
        return finish_cmd(g, run_rollback(&ctx), "rollback_failed");
    }
    match run_migrate(&ctx) {
        Ok(Outcome::Complete) => {
            ui::done("migrated: this controller's state is on the encrypted volume");
            ui::guide(&[
                ("noo cluster verify --controller", "the at-rest rows"),
                ("noo security at-rest migrate --rollback", "go back to the plaintext state, exactly as it was"),
                ("noo security at-rest wipe-plaintext", "after a day of healthy running: delete the old plaintext copies"),
            ]);
            Ok(0)
        }
        Ok(_) => Ok(0),
        Err(e) => fail(g.json, ExitCode::Generic, "migrate_failed", &e, Some("noo security at-rest migrate --dry-run")),
    }
}

/// `noo security at-rest wipe-plaintext [--dry-run] [--hours <N>] [--confirm <phrase>]`
pub fn security_at_rest_wipe_plaintext(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut ctx = Ctx::live(g);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dry-run" => ctx.dry_run = true,
            "--hours" => ctx.healthy_hours = it.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            "--confirm" => ctx.confirm = Some(it.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    finish_cmd(g, run_wipe(&ctx), "wipe_refused")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    /// A whole fake install: root with .env, plaintext state, a dir standing
    /// in for the volume, and shell stand-ins for every external command.
    /// Everything logs to `calls`.
    struct Rig {
        top: PathBuf,
        root: PathBuf,
        vol: PathBuf,
        bak: PathBuf,
        old_state: PathBuf,
        pki: PathBuf,
        bin: PathBuf,
        ctl: PathBuf, // FAKE_* switches, one file per switch
    }

    const ENV_BEFORE: &str = "# controller\nNOO_DATA_ROOT=@DATA@\nNOO_PKI_DIR=@PKI@\nNOO_TLS_CA=@PKI@/ca.crt\nOTHER=1\n";

    impl Rig {
        fn new() -> Rig {
            let top = std::env::temp_dir().join(format!("noo-migrate-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
            let _ = std::fs::remove_dir_all(&top);
            let root = top.join("root");
            let vol = top.join("vol");
            let bak = top.join("backups");
            let old_state = top.join("data");
            let pki = top.join("pki");
            let bin = top.join("bin");
            let ctl = top.join("ctl");
            for d in [&root, &vol, &bak, &bin, &ctl, &pki] {
                std::fs::create_dir_all(d).unwrap();
            }
            for name in STATE_COPIES {
                let d = old_state.join(name);
                std::fs::create_dir_all(&d).unwrap();
                std::fs::write(d.join("data.bin"), format!("plain {name}\n")).unwrap();
            }
            std::fs::write(pki.join("ca.crt"), "CA\n").unwrap();
            let env = ENV_BEFORE.replace("@DATA@", &old_state.display().to_string()).replace("@PKI@", &pki.display().to_string());
            std::fs::write(root.join(".env"), env).unwrap();
            let r = Rig { top, root, vol, bak, old_state, pki, bin, ctl };
            r.script("noo", NOO);
            r.script("rsync", RSYNC);
            r.script("docker", DOCKER);
            r.script("backup", BACKUP);
            r.script("drill", DRILL);
            r.script("psql", PSQL);
            r.script("noo-hostd", HOSTD);
            std::fs::write(r.ctl.join("tables"), "public.users\npublic.memories\n").unwrap();
            std::fs::write(r.ctl.join("counts"), "public.users 10\npublic.memories 20\n").unwrap();
            r
        }

        fn script(&self, name: &str, body: &str) {
            let p = self.bin.join(name);
            let b = body.replace("@CTL@", &self.ctl.display().to_string()).replace("@BAK@", &self.bak.display().to_string());
            crate::test_exec::write_exec(&p, format!("#!/bin/sh\n{b}"), 0o755);
        }

        fn ctx(&self) -> Ctx<'static> {
            let mut env = BTreeMap::new();
            env.insert("HOME".to_string(), self.top.display().to_string());
            Ctx {
                g: None,
                root: self.root.clone(),
                backend: Backend::Dir(self.vol.clone()),
                sudo: "env".into(),
                hostd: self.bin.join("noo-hostd").display().to_string(),
                rsync: self.bin.join("rsync").display().to_string(),
                noo: self.bin.join("noo").display().to_string(),
                docker: self.bin.join("docker").display().to_string(),
                backup_cmd: self.bin.join("backup").display().to_string(),
                drill_cmd: self.bin.join("drill").display().to_string(),
                psql_cmd: self.bin.join("psql").display().to_string(),
                backup_dir: self.bak.clone(),
                env,
                now: 1_000_000,
                dry_run: false,
                yes: true,
                tty: false,
                offbox_phrase: None,
                confirm: None,
                healthy_hours: 24,
                verify_wait_secs: 0,
                crash_before_journal: None,
                stop_after: None,
            }
        }

        fn flag(&self, name: &str) {
            std::fs::write(self.ctl.join(name), "1").unwrap();
        }
        fn unflag(&self, name: &str) {
            let _ = std::fs::remove_file(self.ctl.join(name));
        }
        fn calls(&self) -> String {
            std::fs::read_to_string(self.ctl.join("calls")).unwrap_or_default()
        }
        fn env_text(&self) -> String {
            std::fs::read_to_string(self.root.join(".env")).unwrap()
        }
        fn journal(&self) -> Journal {
            Journal::load(&self.root.join(JOURNAL)).unwrap().expect("journal")
        }
        /// A snapshot of every file under the rig (path, size, mtime-free
        /// content hash) to prove a run changed nothing.
        fn snapshot(&self) -> BTreeMap<String, String> {
            fn walk(p: &Path, out: &mut BTreeMap<String, String>) {
                if let Ok(rd) = std::fs::read_dir(p) {
                    for e in rd.flatten() {
                        let path = e.path();
                        if path.file_name().map(|n| n == "calls").unwrap_or(false) {
                            continue; // the call log is the probe, not state
                        }
                        if path.is_dir() {
                            out.insert(path.display().to_string(), "dir".into());
                            walk(&path, out);
                        } else {
                            out.insert(path.display().to_string(), sha256_bytes(&std::fs::read(&path).unwrap_or_default()));
                        }
                    }
                }
            }
            let mut m = BTreeMap::new();
            walk(&self.top, &mut m);
            m
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.top);
        }
    }

    // `noo stack stop|start`, `noo cluster verify --controller --json`.
    const NOO: &str = r#"echo "noo $*" >> @CTL@/calls
case "$*" in
"stack stop") [ -f @CTL@/fail_stop ] && exit 1; exit 0 ;;
"stack start") [ -f @CTL@/fail_start ] && exit 1; exit 0 ;;
"cluster verify --controller --json")
  vol=ok; [ -f @CTL@/volume_bad ] && vol=fail
  other=ok; [ -f @CTL@/other_fail ] && other=fail
  [ -f @CTL@/baseline_fail ] && other=fail
  printf '{"controller":{"ok":true,"checks":[{"name":"at-rest volume","verdict":"%s","detail":"x"},{"name":"gateway","verdict":"%s","detail":"y"}]}}\n' "$vol" "$other"
  exit 0 ;;
esac
exit 2
"#;

    // A rsync stand-in with the real argv contract: copies unless --dry-run;
    // under --dry-run prints @CTL@/diffs when present. Logs argv.
    const RSYNC: &str = r#"echo "rsync $*" >> @CTL@/calls
[ -f @CTL@/fail_rsync ] && exit 23
for a in "$@"; do prev="$last"; last="$a"; done
src="$prev"; dst="$last"
case "$*" in
*--dry-run*) [ -f @CTL@/diffs ] && cat @CTL@/diffs; exit 0 ;;
esac
case "$*" in *--delete*) rm -rf "$dst"* ;; esac
mkdir -p "$dst"
cp -a "$src". "$dst"
exit 0
"#;

    // `noo-hostd at-rest measure --entry p=name ...`: reports $ctl/measure_each
    // bytes per name (default 1000), unless told to fail or to leave one out.
    const HOSTD: &str = r#"echo "hostd $*" >> @CTL@/calls
[ -f @CTL@/fail_measure ] && { echo "permission denied" >&2; exit 1; }
each=$(cat @CTL@/measure_each 2>/dev/null || echo 1000)
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = --entry ]; then n="${2##*=}"; [ "$n" = "$(cat @CTL@/measure_skip 2>/dev/null)" ] || out="$out\"$n\":$each,"; shift; fi
  shift
done
printf '{"ok":true,"bytes":{%s"zz":0},"total":0}\n' "$out"
exit 0
"#;

    const DOCKER: &str = r#"echo "docker $*" >> @CTL@/calls
case "$*" in
"volume ls"*) cat @CTL@/docker_volumes 2>/dev/null; exit 0 ;;
"volume inspect"*) cat @CTL@/docker_mountpoint 2>/dev/null; exit 0 ;;
"volume rm"*) exit 0 ;;
esac
exit 0
"#;

    // Writes pg_/age-key_ artifacts unless told not to; prints an offsite
    // line when asked.
    const BACKUP: &str = r#"echo "backup" >> @CTL@/calls
n=$(cat @CTL@/seq 2>/dev/null || echo 0); n=$((n+1)); echo $n > @CTL@/seq
[ -f @CTL@/fail_backup ] && { echo "Backup FAILED" >&2; exit 1; }
if [ ! -f @CTL@/no_artifacts ]; then
  printf 'dump %s\n' "$n" > @BAK@/pg_$n.sql.gz.enc
  printf 'key %s\n' "$n" > @BAK@/age-key_$n.txt.enc
fi
[ -f @CTL@/offsite_ok ] && echo "  offsite: copied 2 artifact(s) to dir:/mnt/x"
[ -f @CTL@/offsite_fail ] && { echo "[now] Backup written, but the offsite copy FAILED — see above." >&2; exit 1; }
exit 0
"#;

    const DRILL: &str = r#"echo "drill $NOO_DRILL_BACKUP" >> @CTL@/calls
[ -f @CTL@/fail_drill ] && { echo "RESTORE FAILED" >&2; exit 1; }
exit 0
"#;

    const PSQL: &str = r#"echo "psql $NOO_SQL" >> @CTL@/calls
[ -f @CTL@/fail_psql ] && exit 1
case "$NOO_SQL" in
*pg_stat_user_tables*) cat @CTL@/tables ;;
*"count(*)"*) t="${NOO_SQL##*from }"; t=$(echo "$t" | tr -d '"'); grep "^$t " @CTL@/counts | cut -d' ' -f2 ;;
*pg_database_size*) echo 123456 ;;
esac
exit 0
"#;

    fn ok(r: Result<Outcome, String>) -> Outcome {
        r.unwrap_or_else(|e| panic!("expected success, got: {e}"))
    }

    fn err(r: Result<Outcome, String>) -> String {
        match r {
            Ok(o) => panic!("expected a refusal, got {o:?}"),
            Err(e) => e,
        }
    }

    // ── the happy path ──────────────────────────────────────────────────

    #[test]
    fn the_whole_migration_moves_the_state_and_switches_env() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        assert_eq!(ok(run_migrate(&rig.ctx())), Outcome::Complete);
        for name in STATE_COPIES {
            let got = std::fs::read_to_string(rig.vol.join(name).join("data.bin")).unwrap();
            assert_eq!(got, format!("plain {name}\n"), "{name} was not copied");
            assert!(rig.old_state.join(name).join("data.bin").is_file(), "{name}: the plaintext was touched");
        }
        assert_eq!(std::fs::read_to_string(rig.vol.join("pki/ca.crt")).unwrap(), "CA\n");
        let env = rig.env_text();
        let vol = rig.vol.display().to_string();
        assert!(env.contains(&format!("NOO_STATE_ROOT={vol}\n")), "{env}");
        assert!(env.contains(&format!("NOO_PKI_DIR={vol}/pki\n")), "{env}");
        assert!(env.contains(&format!("NOO_TLS_CA={vol}/pki/ca.crt\n")), "{env}");
        assert!(env.contains("OTHER=1"), "{env}");
        assert!(!env.contains("NOO_PG_DATA"), "NOO_PG_DATA was not set before, so it must not appear: {env}");
        let j = rig.journal();
        assert_eq!(j.state(), "complete");
        for s in STEPS {
            assert!(j.is_done(s), "{s} not journaled");
        }
        assert_eq!(j.v["old_env"]["NOO_PKI_DIR"], json!(rig.pki.display().to_string()));
        assert!(j.v["old_env"]["NOO_STATE_ROOT"].is_null());
        assert_eq!(j.v["rowcounts"]["counts"]["public.users"], json!(10));
        assert_eq!(j.v["backup"]["offsite_ok"], json!(true));
        let sha = j.v["backup"]["artifacts"][0]["sha256"].as_str().unwrap().to_string();
        assert_eq!(sha.len(), 64);
        assert_eq!(j.v["post_backup"]["from_state"], json!(vol));
        // The order that matters, in the call log: stop before the final sync
        // and the switch, start after, the checksum dry-run before the switch.
        let calls = rig.calls();
        let at = |needle: &str| calls.find(needle).unwrap_or_else(|| panic!("{needle} missing in:\n{calls}"));
        assert!(at("backup") < at("drill"));
        assert!(at("drill") < at("rsync -aHAXS --numeric-ids "));
        assert!(at("psql") < at("noo stack stop"));
        assert!(at("noo stack stop") < at("--delete "));
        assert!(at("--delete ") < at("--checksum --dry-run"));
        assert!(at("--checksum --dry-run") < at("noo stack start"));
        assert!(at("noo stack stop") < at("noo stack start"));
    }

    #[test]
    fn claude_config_and_alertmanager_join_the_state_set_and_compose_is_switched() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        let cc = rig.top.join("dockervol-cc");
        let am = rig.top.join("dockervol-am");
        for d in [&cc, &am] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("f"), "x").unwrap();
        }
        // One fake docker answering both volumes: the mountpoint depends on
        // which volume is inspected.
        rig.script(
            "docker",
            &format!(
                r#"echo "docker $*" >> @CTL@/calls
case "$*" in
"volume ls"*) printf 'stack_claude-config\nstack_alertmanager-data\nstack_other\n'; exit 0 ;;
"volume inspect"*stack_claude-config) echo {cc}; exit 0 ;;
"volume inspect"*stack_alertmanager-data) echo {am}; exit 0 ;;
esac
exit 0
"#,
                cc = cc.display(),
                am = am.display()
            ),
        );
        assert_eq!(ok(run_migrate(&rig.ctx())), Outcome::Complete);
        assert!(rig.vol.join("claude-config/f").is_file());
        assert!(rig.vol.join("alertmanager-data/f").is_file());
        let env = rig.env_text();
        assert!(env.contains("NOO_CLAUDE_CONFIG_VOLUME=claude-config-state\n"), "{env}");
        assert!(env.contains("NOO_ALERTMANAGER_VOLUME=alertmanager-data-state\n"), "{env}");
        assert!(cc.join("f").is_file() && am.join("f").is_file(), "the docker volumes were touched");
    }

    #[test]
    fn nonstandard_pg_data_is_copied_and_repointed() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        let pg = rig.top.join("elsewhere-pg");
        std::fs::create_dir_all(&pg).unwrap();
        std::fs::write(pg.join("PG_VERSION"), "16").unwrap();
        let mut env = rig.env_text();
        env.push_str(&format!("NOO_PG_DATA={}\n", pg.display()));
        std::fs::write(rig.root.join(".env"), env).unwrap();
        assert_eq!(ok(run_migrate(&rig.ctx())), Outcome::Complete);
        assert!(rig.vol.join("postgres/PG_VERSION").is_file(), "the NOO_PG_DATA dir is the one copied");
        assert!(rig.env_text().contains(&format!("NOO_PG_DATA={}/postgres\n", rig.vol.display())));
        assert_eq!(rig.journal().v["old_env"]["NOO_PG_DATA"], json!(pg.display().to_string()));
    }

    // ── the size is measured as root ────────────────────────────────────

    const GIB_: u64 = 1 << 30;

    #[test]
    fn preflight_sizes_the_volume_from_the_root_measurement() {
        let rig = Rig::new();
        // 8 entries (7 state dirs + pki) at 20 GiB each, as root reports them,
        // although the files on disk are a few bytes (what `du` would say).
        std::fs::write(rig.ctl.join("measure_each"), (20 * GIB_).to_string()).unwrap();
        let plan = compute_plan(&rig.ctx());
        // The dir backend checks free space on a real tmp disk; whether that
        // refuses is the disk's business. What must hold either way: the
        // figure used is the measured one.
        match plan {
            Ok(p) => {
                assert_eq!(p["du_bytes"].as_u64().unwrap(), 8 * 20 * GIB_);
                assert_eq!(p["size_gib"].as_u64().unwrap(), at_rest_volume::size_for(8 * 20 * GIB_));
                assert_eq!(p["size_gib"].as_u64().unwrap(), 320);
            }
            Err(e) => assert!(e.contains("not enough free space") && e.contains("160 GiB"), "{e}"),
        }
        let c = rig.calls();
        assert!(c.contains("hostd at-rest measure --entry"), "{c}");
        assert!(c.contains(&format!("{}/postgres=postgres", rig.old_state.display())), "{c}");
        assert!(c.contains(&format!("{}=pki", rig.pki.display())), "{c}");
    }

    #[test]
    fn a_small_state_still_gets_the_fifty_gib_minimum_and_twice_otherwise() {
        assert_eq!(at_rest_volume::size_for(3 * GIB_), 50);
        assert_eq!(at_rest_volume::size_for(100 * GIB_), 200);
    }

    #[test]
    fn a_failed_or_partial_measurement_refuses_instead_of_falling_back() {
        let rig = Rig::new();
        rig.flag("fail_measure");
        let e = compute_plan(&rig.ctx()).unwrap_err();
        assert!(e.contains("cannot be sized safely") && e.contains("Nothing was changed"), "{e}");
        rig.unflag("fail_measure");
        std::fs::write(rig.ctl.join("measure_skip"), "loki").unwrap();
        let e = compute_plan(&rig.ctx()).unwrap_err();
        assert!(e.contains("no figure for loki"), "{e}");
        // Through the engine: refused at preflight, nothing journaled or run.
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("no figure for loki"), "{e}");
        assert!(!rig.root.join(JOURNAL).exists());
        assert!(!rig.calls().contains("rsync") && !rig.calls().contains("noo stack"));
    }

    #[test]
    fn parse_measure_needs_every_name_and_success() {
        let names = vec!["postgres".to_string(), "pki".to_string()];
        assert_eq!(parse_measure("{\"ok\":true,\"bytes\":{\"postgres\":5,\"pki\":7}}", &names), Ok(12));
        assert!(parse_measure("{\"ok\":true,\"bytes\":{\"postgres\":5}}", &names).is_err());
        assert!(parse_measure("{\"ok\":false}", &names).is_err());
        assert!(parse_measure("garbage", &names).is_err());
    }

    // ── the gates ───────────────────────────────────────────────────────

    #[test]
    fn refuses_without_a_fresh_backup_and_changes_nothing() {
        let rig = Rig::new();
        // A stale dump from last week must not count as fresh.
        std::fs::write(rig.bak.join("pg_old.sql.gz.enc"), "old").unwrap();
        rig.flag("no_artifacts");
        let before = rig.env_text();
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("not a fresh backup"), "{e}");
        assert!(!rig.calls().contains("noo stack stop") && !rig.calls().contains("rsync"), "{}", rig.calls());
        assert_eq!(rig.env_text(), before);
        assert!(!rig.journal().is_done("backup"));
        // A backup that fails outright is refused too.
        rig.unflag("no_artifacts");
        rig.flag("fail_backup");
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("the backup failed"), "{e}");
        assert!(!rig.calls().contains("rsync"));
    }

    #[test]
    fn refuses_when_the_restore_drill_fails() {
        let rig = Rig::new();
        rig.flag("fail_drill");
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("restore drill FAILED"), "{e}");
        assert!(!rig.journal().is_done("backup"));
        assert!(!rig.calls().contains("rsync") && !rig.calls().contains("noo stack stop"));
    }

    #[test]
    fn refuses_without_off_box_proof_or_the_phrase() {
        let rig = Rig::new();
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("backup is only on this machine"), "{e}");
        assert!(!rig.calls().contains("rsync") && !rig.calls().contains("noo stack stop"), "{}", rig.calls());
        // A wrong phrase is refused as well.
        let mut ctx = rig.ctx();
        ctx.offbox_phrase = Some("yes".into());
        let e = err(run_migrate(&ctx));
        assert!(e.contains("not the phrase"), "{e}");
        // A FAILED offsite copy is not proof (a fresh install, so a fresh backup).
        let failed = Rig::new();
        failed.flag("offsite_fail");
        let e = err(run_migrate(&failed.ctx()));
        assert!(e.contains("offsite copy FAILED"), "{e}");
        assert!(!failed.calls().contains("rsync") && !failed.calls().contains("noo stack stop"));
        // The phrase is accepted instead of proof.
        let mut ctx = rig.ctx();
        ctx.offbox_phrase = Some(OFFBOX_PHRASE.into());
        assert_eq!(ok(run_migrate(&ctx)), Outcome::Complete);
        assert_eq!(rig.journal().v["offbox"]["proof"], json!("phrase"));
    }

    #[test]
    fn a_noninteractive_run_without_yes_is_refused_before_any_step() {
        let rig = Rig::new();
        let mut ctx = rig.ctx();
        ctx.yes = false;
        let e = err(run_migrate(&ctx));
        assert!(e.contains("--yes"), "{e}");
        assert!(rig.calls().is_empty(), "{}", rig.calls());
        assert!(!rig.root.join(JOURNAL).exists());
    }

    #[test]
    fn a_failed_final_checksum_stops_before_the_env_switch() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        rig.flag("diffs");
        std::fs::write(rig.ctl.join("diffs"), ">fc.t...... base/1/1259\n").unwrap();
        let before = rig.env_text();
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("difference"), "{e}");
        assert_eq!(rig.env_text(), before, ".env was switched with differences left");
        assert!(!rig.calls().contains("noo stack start"));
        let j = rig.journal();
        assert!(j.is_done("stop") && !j.is_done("finalsync") && !j.is_done("switch"));
    }

    #[test]
    fn row_counts_that_drop_fail_the_verify_step_and_point_at_rollback() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        let mut ctx = rig.ctx();
        ctx.stop_after = Some("start");
        assert_eq!(ok(run_migrate(&ctx)), Outcome::Stopped("start".into()));
        std::fs::write(rig.ctl.join("counts"), "public.users 10\npublic.memories 19\n").unwrap();
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("public.memories: 20 rows before, 19 now") && e.contains("--rollback"), "{e}");
        assert!(!rig.journal().is_done("verify"));
        assert!(rig.journal().v["healthy_since"].is_null());
    }

    #[test]
    fn a_new_failing_check_after_the_move_fails_the_verify_step_but_an_old_one_does_not() {
        // gateway already failing before the migration: not blamed on it.
        let rig = Rig::new();
        rig.flag("offsite_ok");
        rig.flag("baseline_fail");
        assert_eq!(ok(run_migrate(&rig.ctx())), Outcome::Complete);
        // gateway healthy before, failing after: blamed.
        let rig = Rig::new();
        rig.flag("offsite_ok");
        let mut ctx = rig.ctx();
        ctx.stop_after = Some("start");
        ok(run_migrate(&ctx));
        rig.flag("other_fail");
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("gateway: FAIL") && e.contains("--rollback"), "{e}");
    }

    #[test]
    fn refuses_up_front_for_a_state_root_already_on_the_volume_and_for_shadowing_env() {
        let rig = Rig::new();
        let mut env = rig.env_text();
        env.push_str(&format!("NOO_STATE_ROOT={}\n", rig.vol.display()));
        std::fs::write(rig.root.join(".env"), env).unwrap();
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("already on the encrypted volume"), "{e}");

        let rig = Rig::new();
        let mut ctx = rig.ctx();
        ctx.env.insert("NOO_PKI_DIR".into(), "/somewhere/else".into());
        let e = err(run_migrate(&ctx));
        assert!(e.contains("set in the environment"), "{e}");

        let rig = Rig::new();
        std::fs::write(rig.root.join("noomesh.yaml"), "compose_env:\n  NOO_STATE_ROOT: /x\n").unwrap();
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("noomesh.yaml sets NOO_STATE_ROOT"), "{e}");
    }

    #[test]
    fn a_missing_database_directory_is_refused() {
        let rig = Rig::new();
        std::fs::remove_dir_all(rig.old_state.join("postgres")).unwrap();
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("database directory"), "{e}");
    }

    // ── resume after a crash at each step ───────────────────────────────

    #[test]
    fn resumes_correctly_after_a_crash_at_every_step() {
        for crash in STEPS {
            let rig = Rig::new();
            rig.flag("offsite_ok");
            let mut ctx = rig.ctx();
            ctx.crash_before_journal = Some(crash);
            let e = err(run_migrate(&ctx));
            assert!(e.contains("simulated crash"), "{crash}: {e}");
            let idx = STEPS.iter().position(|s| *s == crash).unwrap();
            match Journal::load(&rig.root.join(JOURNAL)).unwrap() {
                // Nothing is journaled before the first step finishes.
                None => assert_eq!(idx, 0, "{crash}: the journal vanished"),
                Some(j) => {
                    assert!(!j.is_done(crash), "{crash}: a crashed step must not be journaled");
                    // Everything before it is.
                    for s in &STEPS[..idx] {
                        assert!(j.is_done(s), "{crash}: {s} lost");
                    }
                }
            }
            // Resume with a clean context: it finishes, the result is the same.
            assert_eq!(ok(run_migrate(&rig.ctx())), Outcome::Complete, "resume after {crash}");
            let env = rig.env_text();
            assert!(env.contains(&format!("NOO_STATE_ROOT={}\n", rig.vol.display())), "{crash}: {env}");
            assert_eq!(env.matches("NOO_STATE_ROOT=").count(), 1, "{crash}: duplicated: {env}");
            for name in STATE_COPIES {
                assert_eq!(std::fs::read_to_string(rig.vol.join(name).join("data.bin")).unwrap(), format!("plain {name}\n"), "{crash}: {name}");
            }
            // The original .env was saved once, before any change, and the
            // journal still names the ORIGINAL values after the resume.
            let orig = std::fs::read_to_string(rig.root.join(ENV_ORIG)).unwrap();
            assert!(!orig.contains("NOO_STATE_ROOT"), "{crash}: {orig}");
            assert!(rig.journal().v["old_env"]["NOO_STATE_ROOT"].is_null(), "{crash}");
            // Steps ran at most once more than needed; the stack was stopped
            // before the switch and started after it, in every variant.
            let calls = rig.calls();
            assert!(calls.rfind("noo stack stop").unwrap() < calls.rfind("noo stack start").unwrap(), "{crash}");
        }
    }

    #[test]
    fn a_resume_never_repeats_a_journaled_step() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        let mut ctx = rig.ctx();
        ctx.stop_after = Some("rowcounts");
        ok(run_migrate(&ctx));
        assert_eq!(rig.calls().lines().filter(|l| *l == "backup").count(), 1);
        ok(run_migrate(&rig.ctx()));
        // Exactly one more backup (postbackup); the first was not redone.
        let n = rig.calls().lines().filter(|l| *l == "backup").count();
        assert_eq!(n, 2, "{}", rig.calls());
        assert_eq!(rig.calls().lines().filter(|l| *l == "noo stack stop").count(), 1);
    }

    #[test]
    fn a_completed_migration_is_not_started_again() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        ok(run_migrate(&rig.ctx()));
        let e = err(run_migrate(&rig.ctx()));
        assert!(e.contains("already migrated"), "{e}");
    }

    // ── dry run ─────────────────────────────────────────────────────────

    #[test]
    fn dry_run_touches_nothing() {
        let rig = Rig::new();
        let before = rig.snapshot();
        let mut ctx = rig.ctx();
        ctx.dry_run = true;
        ctx.yes = false;
        assert_eq!(ok(run_migrate(&ctx)), Outcome::DryRun);
        assert_eq!(rig.snapshot(), before, "a dry run changed files");
        assert!(!rig.root.join(JOURNAL).exists() && !rig.root.join(ENV_ORIG).exists());
        let c = rig.calls();
        assert!(!c.contains("noo stack") && !c.contains("rsync") && !c.contains("backup") && !c.contains("psql"), "{c}");
    }

    #[test]
    fn dry_run_mid_migration_changes_nothing_either() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        let mut ctx = rig.ctx();
        ctx.stop_after = Some("precopy");
        ok(run_migrate(&ctx));
        let before = rig.snapshot();
        let mut ctx = rig.ctx();
        ctx.dry_run = true;
        assert_eq!(ok(run_migrate(&ctx)), Outcome::DryRun);
        assert_eq!(rig.snapshot(), before);
    }

    // ── rollback ────────────────────────────────────────────────────────

    #[test]
    fn rollback_restores_the_exact_env_and_leaves_plaintext_and_volume() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        let original = rig.env_text();
        let mut ctx = rig.ctx();
        ctx.stop_after = Some("verify");
        ok(run_migrate(&ctx));
        assert_ne!(rig.env_text(), original);
        let calls_before = rig.calls().lines().filter(|l| *l == "noo stack start").count();
        run_rollback(&rig.ctx()).unwrap();
        assert_eq!(rig.env_text(), original, ".env is not byte-for-byte what it was");
        assert_eq!(rig.journal().state(), "rolled_back");
        for name in STATE_COPIES {
            assert_eq!(std::fs::read_to_string(rig.old_state.join(name).join("data.bin")).unwrap(), format!("plain {name}\n"));
            assert!(rig.vol.join(name).is_dir(), "the volume must stay");
        }
        let calls = rig.calls();
        assert_eq!(calls.lines().filter(|l| *l == "noo stack start").count(), calls_before + 1);
        assert!(calls.rfind("noo stack stop").unwrap() < calls.rfind("noo stack start").unwrap());
        assert!(std::fs::read_dir(&rig.root).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with(".env.pre-rollback-")), "the switched .env is kept");
        // A second rollback is refused; a new migrate archives the old journal.
        assert!(run_rollback(&rig.ctx()).unwrap_err().contains("already rolled back"));
        assert_eq!(ok(run_migrate(&rig.ctx())), Outcome::Complete);
    }

    #[test]
    fn rollback_before_the_stack_was_stopped_does_not_bounce_it() {
        let rig = Rig::new();
        rig.flag("offsite_ok");
        let original = rig.env_text();
        let mut ctx = rig.ctx();
        ctx.stop_after = Some("precopy");
        ok(run_migrate(&ctx));
        run_rollback(&rig.ctx()).unwrap();
        assert_eq!(rig.env_text(), original);
        assert!(!rig.calls().contains("noo stack"), "{}", rig.calls());
        assert_eq!(rig.journal().state(), "rolled_back");
    }

    #[test]
    fn rollback_dry_run_and_missing_journal() {
        let rig = Rig::new();
        assert!(run_rollback(&rig.ctx()).unwrap_err().contains("no migration journal"));
        rig.flag("offsite_ok");
        let mut ctx = rig.ctx();
        ctx.stop_after = Some("switch");
        ok(run_migrate(&ctx));
        let before = rig.snapshot();
        let mut ctx = rig.ctx();
        ctx.dry_run = true;
        run_rollback(&ctx).unwrap();
        assert_eq!(rig.snapshot(), before);
    }

    // ── wipe-plaintext ──────────────────────────────────────────────────

    fn migrated(rig: &Rig) {
        rig.flag("offsite_ok");
        assert_eq!(ok(run_migrate(&rig.ctx())), Outcome::Complete);
    }

    /// The wipe context: `hours` after the verify step.
    fn wipe_ctx(rig: &Rig, hours: u64) -> Ctx<'static> {
        let mut ctx = rig.ctx();
        ctx.now += hours * 3600;
        ctx.confirm = Some(WIPE_PHRASE.into());
        ctx
    }

    #[test]
    fn wipe_removes_the_plaintext_after_the_gates_and_the_phrase() {
        let rig = Rig::new();
        migrated(&rig);
        run_wipe(&wipe_ctx(&rig, 25)).unwrap();
        for name in STATE_COPIES {
            assert!(!rig.old_state.join(name).exists(), "{name} survived");
            assert!(rig.vol.join(name).join("data.bin").is_file(), "{name}: the encrypted copy was damaged");
        }
        assert!(!rig.pki.exists(), "the plaintext PKI survived");
        assert!(rig.vol.join("pki/ca.crt").is_file());
        assert!(rig.journal().v["wipe"].is_object());
        assert!(run_wipe(&wipe_ctx(&rig, 26)).unwrap_err().contains("already wiped"));
        // Past the wipe there is nothing to go back to, and rollback says so.
        assert!(run_rollback(&rig.ctx()).unwrap_err().contains("wiped"));
        assert!(SSD_CAVEAT.contains("Rotate keys next"));
    }

    #[test]
    fn wipe_is_refused_before_the_migration_completed() {
        let rig = Rig::new();
        assert!(run_wipe(&wipe_ctx(&rig, 48)).unwrap_err().contains("no migration journal"));
        rig.flag("offsite_ok");
        let mut ctx = rig.ctx();
        ctx.stop_after = Some("start");
        ok(run_migrate(&ctx));
        let e = run_wipe(&wipe_ctx(&rig, 48)).unwrap_err();
        assert!(e.contains("has not completed"), "{e}");
        for name in STATE_COPIES {
            assert!(rig.old_state.join(name).is_dir());
        }
        // A rolled-back install is running on the plaintext: never wipe it.
        run_rollback(&rig.ctx()).unwrap();
        assert!(run_wipe(&wipe_ctx(&rig, 48)).unwrap_err().contains("rolled back"));
    }

    #[test]
    fn wipe_is_refused_without_the_phrase() {
        let rig = Rig::new();
        migrated(&rig);
        let mut ctx = wipe_ctx(&rig, 25);
        ctx.confirm = None;
        let e = run_wipe(&ctx).unwrap_err();
        assert!(e.contains("--confirm"), "{e}");
        ctx.confirm = Some("yes".into());
        assert!(run_wipe(&ctx).unwrap_err().contains("not the phrase"));
        assert!(rig.old_state.join("postgres").is_dir(), "wiped without the phrase");
    }

    #[test]
    fn wipe_is_refused_too_soon_but_the_hours_are_configurable() {
        let rig = Rig::new();
        migrated(&rig);
        let e = run_wipe(&wipe_ctx(&rig, 3)).unwrap_err();
        assert!(e.contains("too soon") && e.contains("3h 0m of the 24h"), "{e}");
        assert!(rig.old_state.join("postgres").is_dir());
        let mut ctx = wipe_ctx(&rig, 3);
        ctx.healthy_hours = 2;
        run_wipe(&ctx).unwrap();
        assert!(!rig.old_state.join("postgres").exists());
    }

    #[test]
    fn wipe_is_refused_when_the_post_migration_backup_is_gone_or_changed() {
        let rig = Rig::new();
        migrated(&rig);
        let pb = rig.journal().v["post_backup"]["artifacts"][0]["path"].as_str().unwrap().to_string();
        std::fs::write(&pb, "tampered").unwrap();
        let e = run_wipe(&wipe_ctx(&rig, 25)).unwrap_err();
        assert!(e.contains("not intact") && e.contains("changed since"), "{e}");
        std::fs::remove_file(&pb).unwrap();
        assert!(run_wipe(&wipe_ctx(&rig, 25)).unwrap_err().contains("not intact"));
        assert!(rig.old_state.join("postgres").is_dir());
    }

    #[test]
    fn wipe_is_refused_when_unhealthy_or_off_the_volume_and_dry_run_deletes_nothing() {
        let rig = Rig::new();
        migrated(&rig);
        rig.flag("other_fail");
        let e = run_wipe(&wipe_ctx(&rig, 25)).unwrap_err();
        assert!(e.contains("not healthy"), "{e}");
        rig.unflag("other_fail");
        // Pointed back at the plaintext by hand.
        let ok_env = rig.env_text();
        let moved = ok_env.replace(&format!("NOO_STATE_ROOT={}", rig.vol.display()), &format!("NOO_STATE_ROOT={}", rig.old_state.display()));
        std::fs::write(rig.root.join(".env"), moved).unwrap();
        let e = run_wipe(&wipe_ctx(&rig, 25)).unwrap_err();
        assert!(e.contains("not running from it"), "{e}");
        std::fs::write(rig.root.join(".env"), ok_env).unwrap();
        let before = rig.snapshot();
        let mut ctx = wipe_ctx(&rig, 25);
        ctx.dry_run = true;
        run_wipe(&ctx).unwrap();
        assert_eq!(rig.snapshot(), before, "a dry-run wipe deleted something");
    }

    // ── pure pieces ─────────────────────────────────────────────────────

    #[test]
    fn rsync_argv_is_what_the_hostd_verb_runs() {
        assert_eq!(rsync_args("pre", "/a/b/", "/v/b"), vec!["-aHAXS", "--numeric-ids", "/a/b/", "/v/b/"]);
        assert_eq!(rsync_args("final", "/a", "/v/a"), vec!["-aHAXS", "--numeric-ids", "--delete", "/a/", "/v/a/"]);
        assert_eq!(
            rsync_args("verify", "/a", "/v/a"),
            vec!["-aHAXS", "--numeric-ids", "--checksum", "--dry-run", "--delete", "--itemize-changes", "/a/", "/v/a/"]
        );
        // The Go side builds the same flags.
        let go = std::fs::read_to_string(crate::test_support::repo_file("node-agent-go/internal/hostd/atrest_migrate_linux.go")).expect("hostd copy verb source");
        assert!(go.contains(r#"[]string{"-aHAXS", "--numeric-ids"}"#), "hostd copy changed its rsync flags");
        assert!(go.contains(r#""--checksum", "--dry-run", "--delete", "--itemize-changes""#));
        for name in STATE_COPIES.iter().chain(["claude-config", "alertmanager-data", "pki"].iter()) {
            assert!(go.contains(&format!("\"{name}\"")), "hostd does not accept {name}");
        }
    }

    #[test]
    fn hostd_copy_goes_through_sudo_with_the_exact_verb() {
        let rig = Rig::new();
        let mut ctx = rig.ctx();
        ctx.hostd = "/usr/local/bin/noo-hostd".into();
        assert_eq!(
            hostd_copy_argv(&ctx, "/var/lib/noo/postgres", "postgres", "final"),
            vec!["/usr/local/bin/noo-hostd", "at-rest", "copy", "--src", "/var/lib/noo/postgres", "--name", "postgres", "--mode", "final"]
        );
    }

    #[test]
    fn table_names_are_quoted_and_validated() {
        assert_eq!(quote_id("users").unwrap(), "\"users\"");
        assert!(quote_id("a\"; drop table x; --").is_err());
        assert!(quote_id("").is_err());
    }

    #[test]
    fn the_upgrade_hint_only_hints_and_is_quiet_once_migrated() {
        let v = Volume {
            file: "/var/lib/noo/state.luks2".into(),
            mountpoint: "/var/lib/noo/state".into(),
            size_gib: 64,
            pcrs: "7".into(),
            recovery: "enrolled".into(),
            created_at: String::new(),
        };
        let h = hint_for(true, true, None, "/var/lib/noo").unwrap();
        assert!(h.contains("at-rest migrate --dry-run") && h.contains("opt-out") && h.contains("changed nothing"), "{h}");
        assert!(!h.contains("--yes"), "the hint must not suggest a bare migration");
        assert!(hint_for(true, false, None, "/var/lib/noo").unwrap().contains("no usable TPM"));
        assert!(hint_for(true, true, Some(&v), "/var/lib/noo").is_some(), "a volume exists but the state is not on it");
        assert!(hint_for(true, true, Some(&v), "/var/lib/noo/state").is_none());
        assert!(hint_for(false, true, None, "/var/lib/noo").is_none(), "not a Linux controller");
    }

    #[test]
    fn upgrade_only_hints_it_never_migrates() {
        let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/upgrade.rs")).unwrap();
        assert!(src.contains("at_rest_migrate::upgrade_hint()"), "upgrade --stack lost its at-rest hint");
        assert!(!src.contains("run_migrate") && !src.contains("security_at_rest_migrate"), "upgrade must never run the migration");
    }

    #[test]
    fn the_confirmation_gate_needs_the_exact_phrase_or_a_terminal() {
        assert!(confirm_phrase(&Some(OFFBOX_PHRASE.into()), false, OFFBOX_PHRASE, "p", "--f").is_ok());
        assert!(confirm_phrase(&Some("nope".into()), true, OFFBOX_PHRASE, "p", "--f").is_err());
        assert!(confirm_phrase(&None, false, OFFBOX_PHRASE, "p", "--f").unwrap_err().contains("--f"));
    }

    #[test]
    fn the_journal_is_atomic_private_and_rejects_garbage() {
        let rig = Rig::new();
        let p = rig.root.join(JOURNAL);
        assert!(Journal::load(&p).unwrap().is_none());
        let mut j = Journal::fresh(p.clone(), 5, &Backend::Hostd);
        j.mark("preflight", 6);
        j.save().unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!p.with_extension("json.tmp").exists());
        assert!(Journal::load(&p).unwrap().unwrap().is_done("preflight"));
        std::fs::write(&p, "{not json").unwrap();
        assert!(Journal::load(&p).is_err(), "a corrupt journal must be an error, never 'no journal'");
        std::fs::write(&p, "{\"version\":1}").unwrap();
        assert!(Journal::load(&p).is_err());
    }

    #[test]
    fn the_steps_are_the_documented_order() {
        assert_eq!(STEPS[0], "preflight");
        let pos = |s: &str| STEPS.iter().position(|x| *x == s).unwrap();
        assert!(pos("backup") < pos("offbox") && pos("offbox") < pos("volume") && pos("volume") < pos("precopy"));
        assert!(pos("rowcounts") < pos("stop") && pos("stop") < pos("finalsync") && pos("finalsync") < pos("switch"));
        assert!(pos("switch") < pos("start") && pos("start") < pos("verify") && pos("verify") < pos("postbackup"));
    }
}
