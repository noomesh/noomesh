// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons after-boot` (hidden): once per boot, retry each enabled
//! add-on whose containers are down, ONCE, through the normal launcher start
//! (`noo stack restart <addon>`), and report every attempt to the gateway
//! (`POST /api/addons/<addon>/boot-start`). Run by the systemd oneshot
//! `noo-addons-after-boot.service` that `noo onboard` installs on the
//! controller; nobody types it.
//!
//! The unit runs as the install owner, never root, so the first thing this
//! does is refuse to run unless the unit and the owner record are the ones
//! onboard wrote (root-owned, not writable by anyone else, naming the same
//! user). Every journal line goes to stderr and names the add-on, the code
//! and, where it helps, the remedy `noo stack restart <addon>`.
//!
//! Everything that touches the machine sits behind [`Os`] (uid, file owner
//! and mode) and [`Run`] (boot id, stamp, gateway, containers, launcher), so
//! the tests run no script, no docker and no network, and need no root.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::{Globals, Unhandled};

pub const UNIT_NAME: &str = "noo-addons-after-boot.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/noo-addons-after-boot.service";
pub const OWNER_PATH: &str = "/etc/noo/addons-after-boot.owner";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const STAMP_FILE: &str = "addons-after-boot";

/// The gateway refuses a `detail` longer than this many BYTES.
pub const DETAIL_MAX_BYTES: usize = 4096;
const GATEWAY_WAIT_SECS: u64 = 300;
const GATEWAY_POLL_SECS: u64 = 5;

const USAGE: &str = "noo addons after-boot";

/// Why an attempt failed: the code the gateway records. The wire names are
/// pinned to `testdata/addon_boot_start_codes.json` by a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    LauncherFailed,
    RefusedByGuard,
    StillDownAfterStart,
    GatewayWaitTimeout,
}

impl Code {
    #[cfg(test)]
    pub const ALL: [Code; 4] = [Code::LauncherFailed, Code::RefusedByGuard, Code::StillDownAfterStart, Code::GatewayWaitTimeout];

    pub fn as_str(self) -> &'static str {
        match self {
            Code::LauncherFailed => "launcher_failed",
            Code::RefusedByGuard => "refused_by_guard",
            Code::StillDownAfterStart => "still_down_after_start",
            Code::GatewayWaitTimeout => "gateway_wait_timeout",
        }
    }
}

/// What one attempt came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Started,
    Failed(Code, String),
}

/// Cut `s` to at most `max` bytes, on a UTF-8 character boundary.
pub fn truncate_detail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s[..cut].to_string()
}

/// The JSON body of one report.
pub fn report_body(boot_id: &str, outcome: &Outcome) -> Value {
    match outcome {
        Outcome::Started => json!({"boot_id": boot_id, "outcome": "started"}),
        Outcome::Failed(code, detail) => {
            let mut b = json!({"boot_id": boot_id, "outcome": "failed", "code": code.as_str()});
            if !detail.is_empty() {
                b["detail"] = Value::String(truncate_detail(detail, DETAIL_MAX_BYTES));
            }
            b
        }
    }
}

/// A report the gateway did not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// A non-2xx answer, with its raw body.
    Status(u16, String),
    /// Nothing answered.
    Transport(String),
}

/// One journal phrase for a rejected report: the status and the body's
/// `error` string (the raw body when it is not that shape).
pub fn describe_rejection(e: &ReportError) -> String {
    match e {
        ReportError::Transport(why) => format!("the gateway could not be reached ({why})"),
        ReportError::Status(status, body) => {
            let said = serde_json::from_str::<Value>(body)
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_string))
                .unwrap_or_else(|| body.trim().to_string());
            if said.is_empty() { format!("HTTP {status}") } else { format!("HTTP {status}: {said}") }
        }
    }
}

// ── The unit and the owner record ─────────────────────────────────

fn safe_user(u: &str) -> bool {
    !u.is_empty() && u.len() <= 64 && u.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// A path systemd reads as written: absolute, no whitespace, quotes,
/// backslash, `%` (a specifier) or `$` (a variable), no control bytes.
fn plain_path(p: &str) -> bool {
    p.starts_with('/') && p.bytes().all(|b| b > b' ' && b != 0x7f && !matches!(b, b'"' | b'\'' | b'\\' | b'%' | b'$'))
}

/// The unit file text. `root` is the install onboard configured: the unit
/// runs in it and declares it (`NOO_REPO_ROOT`), because a systemd service
/// starts in `/`, where the CLI would otherwise fall back to `~/.noo`, which is
/// not the install for a checkout. `Err` when the user name or either path
/// could change what systemd reads.
pub fn render_unit(user: &str, exe: &str, root: &str) -> Result<String, String> {
    if !safe_user(user) {
        return Err(format!("the install owner's name {user:?} is not a plain account name"));
    }
    if !plain_path(exe) {
        return Err(format!("the noo binary path {exe:?} must be absolute and free of whitespace, quotes, % and $"));
    }
    if !plain_path(root) {
        return Err(format!("the install root {root:?} must be absolute and free of whitespace, quotes, % and $"));
    }
    // Boot ordering (i1160). A target is ordered After= every unit it Wants=
    // unless that unit says DefaultDependencies=no, so this oneshot held
    // multi-user.target (and graphical.target) for its whole run: up to the
    // 300 s gateway wait on every boot, and for ever on a hung launcher run.
    // DefaultDependencies=no drops that edge; the lines after it restore the
    // rest of a service's defaults (sysinit, basic, shutdown) by hand.
    // TimeoutStartSec bounds the run itself: the gateway wait (300 s) plus,
    // per add-on, the launcher's compose-lock wait (600 s) and a recreate;
    // 3600 s covers three add-ons. Nothing waits on it, so a generous
    // ceiling costs no boot time.
    Ok(format!(
        "[Unit]\nDescription=noomesh: start enabled add-ons that are down after a boot (once)\nDefaultDependencies=no\nRequires=sysinit.target\nAfter=sysinit.target basic.target\nAfter=docker.service network-online.target\nWants=network-online.target\nConflicts=shutdown.target\nBefore=shutdown.target\n\n[Service]\nType=oneshot\nTimeoutStartSec=3600\nUser={user}\nWorkingDirectory={root}\nEnvironment=NOO_REPO_ROOT={root}\nExecStart={exe} addons after-boot\n\n[Install]\nWantedBy=multi-user.target\n"
    ))
}

/// The root-owned record of who the install owner is: `<uid> <name>\n`.
pub fn render_owner(uid: u32, user: &str) -> Result<String, String> {
    if uid == 0 {
        return Err("the install owner must not be root".into());
    }
    if !safe_user(user) {
        return Err(format!("the install owner's name {user:?} is not a plain account name"));
    }
    Ok(format!("{uid} {user}\n"))
}

/// Parse [`render_owner`]'s output: exactly one line, `<uid> <name>`.
pub fn parse_owner(text: &str) -> Result<(u32, String), String> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') {
        return Err("it has more than one line".into());
    }
    let mut it = line.split(' ');
    match (it.next(), it.next(), it.next()) {
        (Some(uid), Some(name), None) if safe_user(name) => {
            let uid: u32 = uid.parse().map_err(|_| format!("{uid:?} is not a uid"))?;
            Ok((uid, name.to_string()))
        }
        _ => Err("it is not `<uid> <username>`".into()),
    }
}

// ── Which of an add-on's containers are down, and which are held ──

/// An add-on's containers as they are now: `down` are expected to run and do
/// not; `unhealthy` run but report an unhealthy healthcheck (`starting` is
/// not unhealthy); `held` the launcher never starts (a GPU, the Docker
/// socket or privileged mode, `resources::holds`), with why. A held
/// container is neither expected to run nor started. "Expected" is every
/// name in `x-noo-addon: containers` plus every compose service of the
/// overlay that has no `profiles:` key (a profiled service is optional).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Containers {
    pub down: Vec<String>,
    pub held: Vec<(String, String)>,
    /// The add-on's overlay has no `x-noo-addon` block, so it names no
    /// containers to check: verify WARNs, after-boot skips it with one log
    /// line. Never a FAIL: the operator cannot fix a third-party overlay.
    pub undeclared: bool,
    /// Running with `State.Health.Status == unhealthy`. Reported by verify;
    /// never a reason for after-boot to start the add-on.
    pub unhealthy: Vec<String>,
    /// The part of `down` that exited 0 (maybe a one-shot nobody declared):
    /// verify names the fix.
    pub exited_clean: Vec<String>,
    /// Only the names in `x-noo-addon: containers` that are not running: what
    /// after-boot acts on, exactly as before the widened check. Never grows
    /// with compose services, so the boot-time restart cannot loop on a
    /// service that exits on purpose.
    pub boot_down: Vec<String>,
    /// docker did not answer in time (what was being read); a row that never
    /// hangs and never passes on this.
    pub docker_timeout: Option<String>,
}

/// One container (any state) as `docker inspect` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub name: String,
    /// Its `com.docker.compose.project` label.
    pub project: String,
    /// Its `com.docker.compose.service` label; empty when it has none.
    pub service: String,
    /// `.State.Status`: running, exited, restarting, created, dead, ...
    pub state: String,
    pub exit_code: i32,
    /// `.State.Health.Status`; empty when the container has no healthcheck.
    pub health: String,
}

/// The format [`parse_states`] reads. Separate from the pin logic's
/// `INSPECT_FORMAT`, which must not change.
pub const STATE_FORMAT: &str = "{{.Name}}\t{{index .Config.Labels \"com.docker.compose.project\"}}\t{{index .Config.Labels \"com.docker.compose.service\"}}\t{{.State.Status}}\t{{.State.ExitCode}}\t{{if .State.Health}}{{.State.Health.Status}}{{end}}";

/// Parse [`STATE_FORMAT`] output. Any other line is an error, never skipped.
pub fn parse_states(out: &str) -> Result<Vec<Seen>, String> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let [n, project, svc, state, code, health] = f.as_slice() else {
                return Err(format!("unexpected docker inspect line {l:?}"));
            };
            let exit_code = code.trim().parse::<i32>().map_err(|_| format!("unexpected docker inspect line {l:?}"))?;
            if n.is_empty() || state.is_empty() {
                return Err(format!("unexpected docker inspect line {l:?}"));
            }
            Ok(Seen {
                name: n.trim_start_matches('/').to_string(),
                project: project.trim().to_string(),
                service: svc.trim().to_string(),
                state: state.trim().to_string(),
                exit_code,
                health: health.trim().to_string(),
            })
        })
        .collect()
}

/// One container the add-on is expected to run.
struct Want {
    /// What the row names: the container name when the overlay sets one.
    label: String,
    /// Match a container by this name when set, else by `service`.
    cname: Option<String>,
    service: Option<String>,
    /// Meant to run once and exit 0 (see [`judge_containers`]).
    oneshot: bool,
    /// Named in `x-noo-addon: containers` (what after-boot acts on).
    declared: bool,
}

fn replicas_zero(def: &serde_yaml::Value) -> bool {
    def.get("deploy").and_then(|d| d.get("replicas")).and_then(serde_yaml::Value::as_u64) == Some(0)
        || def.get("scale").and_then(serde_yaml::Value::as_u64) == Some(0)
}

fn yaml_restart_is_no(def: &serde_yaml::Value) -> bool {
    match def.get("restart") {
        Some(serde_yaml::Value::String(s)) => s == "no",
        Some(serde_yaml::Value::Bool(b)) => !b,
        _ => false,
    }
}

/// Judge an add-on's containers against what docker `seen` (every state).
/// Pure; [`down_containers_at`] reads the inputs from the machine. Only
/// containers of compose project `project` count: another project's service
/// of the same name neither makes this one look up nor makes it fail.
///
/// Expected = `decl` (the overlay's `x-noo-addon: containers`) UNION every
/// compose service without a `profiles:` key. A service resolves to its
/// container by `container_name` when the overlay sets one, else by the
/// `com.docker.compose.service` label. A one-shot (a service on the declared
/// list `oneshots`, or one whose overlay says `restart: "no"`) is excused
/// when no container of it exists or every one exited 0; anything else not
/// running is `down`. A running container whose health is `unhealthy` is
/// listed in `unhealthy`. `held` names are neither. A service with
/// `deploy.replicas: 0` or `scale: 0` has no container by design and is not
/// expected, unless the add-on declares it in `x-noo-addon: containers` (a
/// declared name is always expected). Profiles the operator enables through `COMPOSE_PROFILES` are
/// not read here: a profiled service is expected only when it is named in
/// `x-noo-addon: containers`.
pub fn judge_containers(
    decl: &[String],
    overlay: &str,
    project: &str,
    seen: &[Seen],
    held: &[(String, String)],
    oneshots: &[String],
) -> Result<Containers, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(overlay).map_err(|e| format!("the overlay is not valid YAML ({e})"))?;
    let mut wants: Vec<Want> = Vec::new();
    if let Some(services) = doc.get("services").and_then(|s| s.as_mapping()) {
        for (k, def) in services {
            let Some(svc) = k.as_str() else { continue };
            let cname = def.get("container_name").and_then(|c| c.as_str()).map(str::to_string);
            let label = cname.clone().unwrap_or_else(|| svc.to_string());
            let listed = decl.iter().any(|d| d == &label || d == svc);
            if replicas_zero(def) {
                continue;
            }
            if def.get("profiles").is_some() && !listed {
                continue;
            }
            let oneshot = yaml_restart_is_no(def) || crate::oneshots::is_oneshot_in(svc, oneshots) || crate::oneshots::is_oneshot_in(&label, oneshots);
            wants.push(Want { label, cname, service: Some(svc.to_string()), oneshot, declared: listed });
        }
    }
    for d in decl {
        if !wants.iter().any(|w| &w.label == d || w.service.as_deref() == Some(d.as_str())) {
            wants.push(Want { label: d.clone(), cname: Some(d.clone()), service: None, oneshot: crate::oneshots::is_oneshot_in(d, oneshots), declared: true });
        }
    }
    let mut c = Containers::default();
    for w in &wants {
        if let Some((_, why)) = held.iter().find(|(h, _)| h == &w.label) {
            c.held.push((w.label.clone(), why.clone()));
            continue;
        }
        let mine: Vec<&Seen> = seen
            .iter()
            .filter(|s| s.project == project)
            .filter(|s| match (&w.cname, &w.service) {
                (Some(n), _) => &s.name == n,
                (None, Some(svc)) => &s.service == svc,
                (None, None) => false,
            })
            .collect();
        let running: Vec<&&Seen> = mine.iter().filter(|s| s.state == "running").collect();
        if running.is_empty() && w.declared {
            c.boot_down.push(w.label.clone());
        }
        if !running.is_empty() {
            if running.iter().any(|s| s.health == "unhealthy") {
                c.unhealthy.push(w.label.clone());
            }
            continue;
        }
        let finished = mine.iter().all(|s| s.state == "exited" && s.exit_code == 0);
        if w.oneshot && finished {
            continue;
        }
        if !mine.is_empty() && mine.iter().all(|s| s.state == "exited" && s.exit_code == 0) {
            c.exited_clean.push(w.label.clone());
        }
        c.down.push(w.label.clone());
    }
    Ok(c)
}

/// The containers the launcher holds for this overlay, by container name:
/// `resources::holds` (the launcher's own rule, third-party add-ons only, as
/// `launch-resources` applies it), each held service mapped to its
/// `container_name` (else the service name).
pub fn held_containers(overlay: &str, third_party: bool) -> Result<Vec<(String, String)>, String> {
    if !third_party {
        return Ok(Vec::new());
    }
    let doc: Value = serde_yaml::from_str::<serde_yaml::Value>(overlay)
        .map_err(|e| format!("the overlay is not valid YAML ({e})"))
        .and_then(|y| serde_json::to_value(y).map_err(|e| e.to_string()))?;
    Ok(crate::addons::resources::holds(overlay)?
        .into_iter()
        .map(|(svc, why)| {
            let cn = doc["services"][svc.as_str()]["container_name"].as_str().map(str::to_string).unwrap_or(svc);
            (cn, why)
        })
        .collect())
}

// ── The seams ─────────────────────────────────────────────────────

/// Owner and mode of a file (a symlink is not followed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// The operating-system facts the refusal checks read.
pub trait Os {
    fn euid(&self) -> u32;
    fn facts(&self, path: &Path) -> Result<FileFacts, String>;
    /// A directory's facts (the install root); `Err` when it cannot be
    /// reached from this account (a closed directory above it) or is not one.
    fn dir_facts(&self, path: &Path) -> Result<FileFacts, String>;
    fn read(&self, path: &Path) -> Result<String, String>;
}

/// Where the files are. `Default` is production.
#[derive(Debug, Clone)]
pub struct Paths {
    pub unit: PathBuf,
    pub owner_file: PathBuf,
    pub boot_id: PathBuf,
    /// `$XDG_STATE_HOME/noo`; the stamp is `addons-after-boot` inside it.
    pub state_dir: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            unit: PathBuf::from(UNIT_PATH),
            owner_file: PathBuf::from(OWNER_PATH),
            boot_id: PathBuf::from(BOOT_ID_PATH),
            state_dir: state_dir_from(std::env::var("XDG_STATE_HOME").ok(), std::env::var("HOME").ok()),
        }
    }
}

impl Paths {
    pub fn stamp(&self) -> PathBuf {
        self.state_dir.join(STAMP_FILE)
    }
}

/// `$XDG_STATE_HOME/noo`, else `~/.local/state/noo`.
pub fn state_dir_from(xdg: Option<String>, home: Option<String>) -> PathBuf {
    match xdg.filter(|x| x.starts_with('/')) {
        Some(x) => PathBuf::from(x).join("noo"),
        None => PathBuf::from(home.unwrap_or_default()).join(".local/state/noo"),
    }
}

/// How long to wait for the gateway, and how often to ask.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub wait: Duration,
    pub poll: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { wait: Duration::from_secs(GATEWAY_WAIT_SECS), poll: Duration::from_secs(GATEWAY_POLL_SECS) }
    }
}

/// Everything else the run does to the machine.
pub trait Run {
    fn boot_id(&mut self) -> Result<String, String>;
    /// The boot id the stamp file holds, if any.
    fn stamp(&mut self) -> Option<String>;
    fn write_stamp(&mut self, boot_id: &str) -> Result<(), String>;
    fn gateway_healthy(&mut self) -> bool;
    fn sleep(&mut self, d: Duration);
    /// Why the stored credential cannot be used, `None` when it can.
    fn credential_problem(&mut self) -> Option<String>;
    fn enabled_addons(&mut self) -> Result<Vec<String>, String>;
    /// The add-on's declared containers: which are down, which are held.
    fn containers(&mut self, addon: &str) -> Result<Containers, String>;
    /// The guard's sentence when the add-on guards refuse its bundle.
    fn guard_refusal(&mut self, addon: &str) -> Option<String>;
    /// The normal launcher start. `Err` carries what to report.
    fn start(&mut self, addon: &str) -> Result<(), String>;
    fn report(&mut self, addon: &str, body: &Value) -> Result<(), ReportError>;
}

// ── The refusal checks ────────────────────────────────────────────

fn writable_by_others(mode: u32) -> bool {
    mode & 0o022 != 0
}

fn root_owned_tight(os: &dyn Os, path: &Path, check: &str, what: &str) -> Result<(), String> {
    let f = os.facts(path).map_err(|e| format!("refusing to run: check {check} failed: {what} {} cannot be read ({e})", path.display()))?;
    if f.uid != 0 || f.gid != 0 {
        return Err(format!(
            "refusing to run: check {check} failed: {what} {} is owned by {}:{}, not root:root",
            path.display(), f.uid, f.gid
        ));
    }
    if writable_by_others(f.mode) {
        return Err(format!(
            "refusing to run: check {check} failed: {what} {} is group- or other-writable (mode {:04o})",
            path.display(), f.mode & 0o7777
        ));
    }
    Ok(())
}

/// Check (e), and onboard's test before it records an owner: the install the
/// unit starts belongs to the account that runs it. An install root another
/// account owns (rc.6: root's /root/.noo run by another account through ACLs)
/// does not fail once; every later step meets one more file it cannot
/// change, one refusal per release. So it is refused here, once, with the
/// whole picture and the one remedy. `None` when the owner owns the root.
/// The remedy moves only `owner:owner`-style files (root's own, or the other
/// account's), never root's files in a service's group (the libpq key rule).
pub fn install_owner_problem(os: &dyn Os, root: &Path, uid: u32, name: &str) -> Option<String> {
    let r = root.display();
    let f = match os.dir_facts(root) {
        Ok(f) => f,
        Err(e) => {
            return Some(format!(
                "the install {r} cannot be reached as {name} ({e}): it sits where {name} cannot go, e.g. inside \
                 another account's home. An install belongs to the account that runs it: onboard as {name} \
                 in a directory {name} owns"
            ))
        }
    };
    if f.uid == uid {
        return None;
    }
    let who = if f.uid == 0 { "root".to_string() } else { format!("uid {}", f.uid) };
    let fix = if f.uid == 0 {
        format!("sudo find {r} -xdev -user root -group root -exec chown {name}:{name} {{}} +")
    } else {
        format!("sudo find {r} -xdev -user {} -exec chown {name} {{}} +", f.uid)
    };
    Some(format!(
        "the install {r} belongs to {who}, not to {name} (uid {uid}), the account recorded to run it. An install \
         belongs to the account that runs it; run as {name}, every later step would refuse on another file it \
         cannot change. Onboard as {name} in a directory {name} owns, or give {name} the install: {fix}"
    ))
}

/// The unit's `WorkingDirectory=`: the install root it starts.
fn unit_root(unit: &str) -> Option<PathBuf> {
    unit.lines().find_map(|l| l.trim().strip_prefix("WorkingDirectory=")).map(|v| PathBuf::from(v.trim())).filter(|p| p.is_absolute())
}

/// The refusals, in order: (d) not root, the owner record is sound,
/// (a) this is the recorded owner, (b) the unit is root's and tight, (c) the
/// unit runs as that owner, (e) that owner owns the install the unit starts. `Ok` is the recorded `(uid, name)`.
pub fn refusals(os: &dyn Os, paths: &Paths) -> Result<(u32, String), String> {
    if os.euid() == 0 {
        return Err("refusing to run: check (d) failed: running as root (euid 0); this runs as the install owner, never root".into());
    }
    root_owned_tight(os, &paths.owner_file, "(a)", "the owner record")?;
    let text = os.read(&paths.owner_file).map_err(|e| format!("refusing to run: check (a) failed: the owner record {} cannot be read ({e})", paths.owner_file.display()))?;
    let (uid, name) = parse_owner(&text).map_err(|e| format!("refusing to run: check (a) failed: the owner record {} is malformed: {e}", paths.owner_file.display()))?;
    if os.euid() != uid {
        return Err(format!(
            "refusing to run: check (a) failed: running as uid {}, but the install owner recorded at onboard is {name} (uid {uid})",
            os.euid()
        ));
    }
    root_owned_tight(os, &paths.unit, "(b)", "the unit file")?;
    let unit = os.read(&paths.unit).map_err(|e| format!("refusing to run: check (c) failed: the unit file {} cannot be read ({e})", paths.unit.display()))?;
    let users: Vec<&str> = unit.lines().filter_map(|l| l.trim().strip_prefix("User=")).map(str::trim).collect();
    if users.is_empty() || users.iter().any(|u| *u != name) {
        return Err(format!(
            "refusing to run: check (c) failed: the unit file {} does not run as {name} (its User= is {})",
            paths.unit.display(),
            if users.is_empty() { "missing".to_string() } else { users.join(", ") }
        ));
    }
    if let Some(root) = unit_root(&unit) {
        if let Some(p) = install_owner_problem(os, &root, uid, &name) {
            return Err(format!("refusing to run: check (e) failed: {p}"));
        }
    }
    Ok((uid, name))
}

// ── The run ───────────────────────────────────────────────────────

/// Run the whole thing; returns the exit code. `journal` takes one line at a
/// time (stderr in production).
pub fn run(os: &dyn Os, paths: &Paths, limits: &Limits, r: &mut dyn Run, journal: &mut dyn FnMut(&str)) -> i32 {
    if let Err(line) = refusals(os, paths) {
        journal(&line);
        return 1;
    }
    let boot_id = match r.boot_id() {
        Ok(b) => b,
        Err(e) => {
            journal(&format!("noo addons after-boot: cannot read the boot id ({e}); nothing was started"));
            return 1;
        }
    };
    if r.stamp().as_deref() == Some(boot_id.as_str()) {
        journal(&format!("noo addons after-boot: already ran for this boot ({boot_id}); nothing to do"));
        return 0;
    }
    let enabled = match r.enabled_addons() {
        Ok(e) => e,
        Err(e) => {
            journal(&format!("noo addons after-boot: cannot tell which add-ons are enabled ({e}); nothing was started"));
            return 1;
        }
    };
    if enabled.is_empty() {
        journal("noo addons after-boot: no add-on is enabled; nothing to do");
        return match r.write_stamp(&boot_id) {
            Ok(()) => 0,
            Err(e) => {
                journal(&format!("noo addons after-boot: could not record this boot ({e})"));
                1
            }
        };
    }

    // Wait for the gateway: the reports need it, and so do the add-ons.
    let mut waited = Duration::ZERO;
    while !r.gateway_healthy() {
        if waited >= limits.wait {
            for a in &enabled {
                journal(&format!(
                    "{a}: {} — the gateway was not healthy after {}s, so nothing was started; run: noo stack restart {a}",
                    Code::GatewayWaitTimeout.as_str(),
                    waited.as_secs()
                ));
            }
            return 1;
        }
        r.sleep(limits.poll);
        waited += limits.poll;
    }
    if let Some(why) = r.credential_problem() {
        journal(&format!("noo addons after-boot: cannot report to the gateway: {why}; run: noo auth login (nothing was started)"));
        return 1;
    }

    let mut all_ok = true;
    for a in &enabled {
        let down = match r.containers(a) {
            Ok(c) if c.undeclared => {
                journal(&format!("{a}: declares no x-noo-addon containers, so they are not checked or started after boot"));
                continue;
            }
            Ok(c) => {
                for (h, why) in &c.held {
                    journal(&format!("{a}: {h} is held ({why}); not started"));
                }
                c.down
            }
            Err(e) => {
                journal(&format!("{a}: cannot tell whether its containers are running ({e}); run: noo stack restart {a}"));
                all_ok = false;
                continue;
            }
        };
        if down.is_empty() {
            journal(&format!("{a}: already running; left alone"));
            continue;
        }
        let outcome = attempt(r, a, &down);
        match &outcome {
            Outcome::Started => journal(&format!("{a}: started after boot")),
            Outcome::Failed(code, detail) => {
                all_ok = false;
                let first = detail.lines().next().unwrap_or("");
                journal(&format!("{a}: {} — {first}; run: noo stack restart {a}", code.as_str()));
            }
        }
        if let Err(e) = r.report(a, &report_body(&boot_id, &outcome)) {
            all_ok = false;
            journal(&format!("{a}: the gateway did not accept the boot-start report: {}", describe_rejection(&e)));
        }
    }
    if let Err(e) = r.write_stamp(&boot_id) {
        all_ok = false;
        journal(&format!("noo addons after-boot: could not record this boot ({e}); the next run will try again"));
    }
    if all_ok { 0 } else { 1 }
}

/// One start of one down add-on.
fn attempt(r: &mut dyn Run, addon: &str, down: &[String]) -> Outcome {
    if let Some(sentence) = r.guard_refusal(addon) {
        return Outcome::Failed(Code::RefusedByGuard, sentence);
    }
    if let Err(tail) = r.start(addon) {
        return Outcome::Failed(Code::LauncherFailed, tail);
    }
    match r.containers(addon).map(|c| c.down) {
        Ok(still) if still.is_empty() => Outcome::Started,
        Ok(still) => Outcome::Failed(Code::StillDownAfterStart, format!("the launcher finished but these containers are still not running: {}", still.join(", "))),
        Err(e) => Outcome::Failed(Code::StillDownAfterStart, format!("the launcher finished but its containers could not be read ({e}); they were down before: {}", down.join(", "))),
    }
}

// ── Production wiring ─────────────────────────────────────────────

pub(crate) struct LiveOs;

impl Os for LiveOs {
    fn euid(&self) -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn facts(&self, path: &Path) -> Result<FileFacts, String> {
        use std::os::unix::fs::MetadataExt as _;
        let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !m.file_type().is_file() {
            return Err("not a regular file".into());
        }
        Ok(FileFacts { uid: m.uid(), gid: m.gid(), mode: m.mode() & 0o7777 })
    }

    fn dir_facts(&self, path: &Path) -> Result<FileFacts, String> {
        use std::os::unix::fs::MetadataExt as _;
        let m = std::fs::metadata(path).map_err(|e| e.to_string())?;
        if !m.is_dir() {
            return Err("not a directory".into());
        }
        Ok(FileFacts { uid: m.uid(), gid: m.gid(), mode: m.mode() & 0o7777 })
    }

    fn read(&self, path: &Path) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    }
}

struct Live<'a> {
    g: &'a Globals,
    paths: Paths,
    root: PathBuf,
}

impl Run for Live<'_> {
    fn boot_id(&mut self) -> Result<String, String> {
        let t = std::fs::read_to_string(&self.paths.boot_id).map_err(|e| format!("{}: {e}", self.paths.boot_id.display()))?;
        let t = t.trim();
        let ok = t.len() == 36 && t.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
        if ok { Ok(t.to_string()) } else { Err(format!("{} does not hold a UUID", self.paths.boot_id.display())) }
    }

    fn stamp(&mut self) -> Option<String> {
        std::fs::read_to_string(self.paths.stamp()).ok().map(|t| t.trim().to_string())
    }

    fn write_stamp(&mut self, boot_id: &str) -> Result<(), String> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::create_dir_all(&self.paths.state_dir).map_err(|e| format!("{}: {e}", self.paths.state_dir.display()))?;
        let tmp = self.paths.state_dir.join(format!("{STAMP_FILE}.tmp.{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(format!("{boot_id}\n").as_bytes()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.sync_all().map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, self.paths.stamp()).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", self.paths.stamp().display())
        })
    }

    fn gateway_healthy(&mut self) -> bool {
        matches!(crate::http::get_raw_opt(self.g, "/health", false, 3), Some((s, _)) if (200..300).contains(&s))
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn credential_problem(&mut self) -> Option<String> {
        let r = crate::auth::resolve(self.g);
        if r.header.is_some() {
            return None;
        }
        Some(match crate::auth::refresh_failure() {
            Some(why) => format!("the stored CLI credential is expired and could not be refreshed ({why})"),
            None => "there is no stored CLI credential for this user".to_string(),
        })
    }

    fn enabled_addons(&mut self) -> Result<Vec<String>, String> {
        crate::addons::licensed_on(&self.root).map(|v| v.into_iter().map(str::to_string).collect())
    }

    fn containers(&mut self, addon: &str) -> Result<Containers, String> {
        down_containers_at(&self.root, addon).and_then(boot_view)
    }

    fn guard_refusal(&mut self, addon: &str) -> Option<String> {
        let names: Vec<String> = crate::addons::decls::CHECKED_FILES.iter().map(|s| s.to_string()).collect();
        let files = crate::addons::pins::materialised_files(&self.root, addon, names.iter());
        crate::addons::guards::guard_install(&self.root, addon, &files).err()
    }

    fn start(&mut self, addon: &str) -> Result<(), String> {
        let script = self.root.join("scripts").join("noomesh-restart.sh");
        if !script.is_file() {
            return Err(format!("the launcher {} was not found", script.display()));
        }
        // Not `mesh_restart`: that posts its own `started` (fresh UUID), and
        // this run reports the start once, under the boot id.
        match super::mesh::restart_reporting(self.g, &[addon.to_string()], false) {
            Ok(0) => Ok(()),
            Ok(n) => Err(format!("`noo stack restart {addon}` exited {n}; its output is above in this journal")),
            Err(Unhandled) => Err(format!("`noo stack restart {addon}` was not accepted")),
        }
    }

    fn report(&mut self, addon: &str, body: &Value) -> Result<(), ReportError> {
        let path = format!("/api/addons/{addon}/boot-start");
        match crate::http::request_try(self.g, "POST", &path, Some(body), true, 15) {
            Ok((s, _)) if (200..300).contains(&s) => Ok(()),
            Ok((s, text)) => Err(ReportError::Status(s, text)),
            Err(e) => Err(ReportError::Transport(e)),
        }
    }
}

/// The add-on's containers on the install at `root` (the names in
/// `x-noo-addon: containers` and every non-profiled compose service of the
/// install's compose project): which are down, which are unhealthy, and which
/// the launcher holds. `boot_down` is the declared-names-only part after-boot
/// acts on.
pub(crate) fn down_containers_at(root: &Path, addon: &str) -> Result<Containers, String> {
    let overlay = crate::addons::pins::addon_dir(root, addon).join("docker-compose.yml");
    let text = std::fs::read_to_string(&overlay).map_err(|e| format!("{}: {e}", overlay.display()))?;
    let Some(decl) = crate::addon_decl_parse::parse_decl(&format!("{addon}'s overlay"), &text, Some(addon))? else {
        return Ok(Containers { undeclared: true, ..Default::default() });
    };
    // The stack runs every add-on overlay in the install's own compose project.
    let project = crate::envfile::compose_project();
    let held = held_containers(&text, crate::addons::resolve::third_party(addon))?;
    // One deadline for all of this add-on's reads, not one per call.
    let deadline = std::time::Instant::now() + DOCKER_LIMIT;
    let mut run = |args: &[&str], limit: Duration| crate::bounded::docker(args, limit);
    let mut c = match read_states_via(&project, deadline, &mut run)
        .and_then(|seen| judge_containers(&decl.containers, &text, &project, &seen, &held, crate::oneshots::declared()).map_err(StatesError::Failed))
    {
        Ok(c) => c,
        Err(StatesError::TimedOut(what)) => return Ok(Containers { docker_timeout: Some(what), ..Default::default() }),
        Err(StatesError::Failed(e)) => return Err(format!("could not list containers: {e}")),
    };
    match drop_running_elsewhere(&mut c, deadline, &mut run) {
        Ok(()) => Ok(c),
        Err(StatesError::TimedOut(what)) => Ok(Containers { docker_timeout: Some(what), ..Default::default() }),
        Err(StatesError::Failed(e)) => Err(format!("could not list containers: {e}")),
    }
}

/// What a bounded docker call may still take: the time left to `deadline`.
/// `None` once it has passed.
fn remaining(deadline: std::time::Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    (!left.is_zero()).then_some(left)
}

/// A declared container is matched by its name wherever it runs, as
/// after-boot always did: a declared name running under another compose
/// project is not down for `boot_down` (verify's own view stays per project).
/// One bounded `docker ps` of the running names, only when a declared name
/// is missing from this project.
fn drop_running_elsewhere(
    c: &mut Containers,
    deadline: std::time::Instant,
    docker: &mut dyn FnMut(&[&str], Duration) -> crate::bounded::Bounded,
) -> Result<(), StatesError> {
    use crate::bounded::Bounded;
    if c.boot_down.is_empty() {
        return Ok(());
    }
    let Some(left) = remaining(deadline) else { return Err(StatesError::TimedOut("docker ps after 20s".into())) };
    let out = match docker(&["ps", "--format", "{{.Names}}"], left) {
        Bounded::Answered(o) => o,
        Bounded::TimedOut { secs } => return Err(StatesError::TimedOut(format!("docker ps after {secs}s"))),
        Bounded::SpawnFailed(e) => return Err(StatesError::Failed(format!("docker ps: {e}"))),
    };
    if !out.status.success() {
        return Err(StatesError::Failed(format!("docker ps: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    let names: Vec<String> = String::from_utf8_lossy(&out.stdout).split_whitespace().map(|n| n.trim_start_matches('/').to_string()).collect();
    c.boot_down.retain(|d| !names.contains(d));
    Ok(())
}

/// What after-boot sees: only the names `x-noo-addon: containers` declares,
/// as before the row looked at compose services. A docker that did not
/// answer is an error here (never "already running").
pub(crate) fn boot_view(c: Containers) -> Result<Containers, String> {
    if let Some(what) = &c.docker_timeout {
        return Err(format!("docker did not answer for {what}"));
    }
    Ok(Containers { down: c.boot_down.clone(), unhealthy: Vec::new(), exited_clean: Vec::new(), ..c })
}

/// The bound on each docker call the container check makes.
const DOCKER_LIMIT: Duration = Duration::from_secs(20);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StatesError {
    /// The docker call that did not answer in time.
    TimedOut(String),
    Failed(String),
}

/// This project's containers in any state: `docker ps -aq` filtered on the
/// compose project label, then one inspect of [`STATE_FORMAT`] of just those.
/// A container removed between the two fails the inspect; read once more
/// before calling it an error. `docker` runs one bounded call within the
/// time left to `deadline`, shared by every call of one add-on's read (the
/// real one is `bounded::docker`; a test injects its own).
pub(crate) fn read_states_via(
    project: &str,
    deadline: std::time::Instant,
    docker: &mut dyn FnMut(&[&str], Duration) -> crate::bounded::Bounded,
) -> Result<Vec<Seen>, StatesError> {
    use crate::bounded::Bounded;
    let mut last = String::new();
    for _ in 0..2 {
        let filter = format!("label=com.docker.compose.project={project}");
        let Some(left) = remaining(deadline) else { return Err(StatesError::TimedOut("docker ps after 20s".into())) };
        let ps = match docker(&["ps", "-aq", "--no-trunc", "--filter", &filter], left) {
            Bounded::Answered(o) => o,
            Bounded::TimedOut { secs } => return Err(StatesError::TimedOut(format!("docker ps after {secs}s"))),
            Bounded::SpawnFailed(e) => return Err(StatesError::Failed(format!("docker ps: {e}"))),
        };
        if !ps.status.success() {
            return Err(StatesError::Failed(format!("docker ps: {}", String::from_utf8_lossy(&ps.stderr).trim())));
        }
        let ids: Vec<String> = String::from_utf8_lossy(&ps.stdout).split_whitespace().map(String::from).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut args: Vec<&str> = vec!["inspect", "--type", "container", "--format", STATE_FORMAT];
        args.extend(ids.iter().map(String::as_str));
        let Some(left) = remaining(deadline) else { return Err(StatesError::TimedOut("docker inspect after 20s".into())) };
        let out = match docker(&args, left) {
            Bounded::Answered(o) => o,
            Bounded::TimedOut { secs } => return Err(StatesError::TimedOut(format!("docker inspect after {secs}s"))),
            Bounded::SpawnFailed(e) => return Err(StatesError::Failed(format!("docker inspect: {e}"))),
        };
        if out.status.success() {
            let found = parse_states(&String::from_utf8_lossy(&out.stdout)).map_err(|e| StatesError::Failed(format!("docker inspect: {e}")))?;
            if found.len() != ids.len() {
                return Err(StatesError::Failed(format!("docker inspect: {} of {} containers read", found.len(), ids.len())));
            }
            return Ok(found);
        }
        last = String::from_utf8_lossy(&out.stderr).trim().to_string();
    }
    Err(StatesError::Failed(format!("docker inspect: {last}")))
}

/// A random (version 4) UUID from 16 bytes of the kernel's randomness.
pub fn uuid_v4_from(mut b: [u8; 16]) -> String {
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn fresh_uuid() -> Result<String, String> {
    use std::io::Read as _;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).map_err(|e| format!("/dev/urandom: {e}"))?;
    Ok(uuid_v4_from(b))
}

/// Which add-ons a successful `noo stack restart` should report as started
/// (i509: that clears an open `addon.boot_start_failed` alert): the enabled
/// add-ons it named, or every enabled add-on when it named none (the whole
/// stack). A name that is not an enabled add-on (a core service) is skipped.
pub fn restarted_addons(named: &[String], enabled: &[String]) -> Vec<String> {
    if named.is_empty() {
        return enabled.to_vec();
    }
    enabled.iter().filter(|a| named.iter().any(|n| n == *a)).cloned().collect()
}

/// After a successful `noo stack restart`: post `started` for each restarted
/// add-on whose containers are all running, each under a fresh UUID (a
/// repeat of one boot_id is deduplicated by the gateway). It never fails the
/// restart. A post that could not be made is said, because an open alert
/// then stays open.
pub fn report_restarted(g: &Globals, named: &[String]) {
    let root = crate::envfile::repo_root();
    let Ok(enabled) = crate::addons::licensed_on(&root) else { return };
    let enabled: Vec<String> = enabled.into_iter().map(str::to_string).collect();
    for a in restarted_addons(named, &enabled) {
        if !matches!(down_containers_at(&root, &a).and_then(boot_view), Ok(c) if c.down.is_empty() && !c.undeclared) {
            continue;
        }
        let sent = fresh_uuid().and_then(|id| {
            let path = format!("/api/addons/{a}/boot-start");
            match crate::http::request_try(g, "POST", &path, Some(&report_body(&id, &Outcome::Started)), true, 15) {
                Ok((s, _)) if (200..300).contains(&s) => Ok(()),
                Ok((s, text)) => Err(describe_rejection(&ReportError::Status(s, text))),
                Err(e) => Err(describe_rejection(&ReportError::Transport(e))),
            }
        });
        if let Err(why) = sent {
            crate::ui::say(&crate::ui::note(&format!("{a} is running, but the gateway was not told ({why}); an open boot-start alert for it stays open until it is")));
        }
    }
}

/// `noo addons after-boot` (hidden).
pub fn addons_after_boot(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        eprintln!("usage: {USAGE}");
        return Err(Unhandled);
    }
    let mut live = Live { g, paths: Paths::default(), root: crate::envfile::repo_root() };
    let paths = live.paths.clone();
    Ok(run(&LiveOs, &paths, &Limits::default(), &mut live, &mut |l: &str| eprintln!("{l}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const BOOT: &str = "0b9f3c1e-7a52-4d0b-9a34-5c6e2f1d8a77";
    const OWNER_UID: u32 = 1000;

    struct FakeOs {
        euid: u32,
        files: BTreeMap<PathBuf, (FileFacts, String)>,
        dirs: BTreeMap<PathBuf, FileFacts>,
    }

    fn tight(uid: u32) -> FileFacts {
        FileFacts { uid, gid: if uid == 0 { 0 } else { uid }, mode: 0o644 }
    }

    impl Os for FakeOs {
        fn euid(&self) -> u32 {
            self.euid
        }
        fn facts(&self, p: &Path) -> Result<FileFacts, String> {
            self.files.get(p).map(|f| f.0).ok_or_else(|| "no such file".to_string())
        }
        fn dir_facts(&self, p: &Path) -> Result<FileFacts, String> {
            self.dirs.get(p).copied().ok_or_else(|| "Permission denied (os error 13)".to_string())
        }
        fn read(&self, p: &Path) -> Result<String, String> {
            self.files.get(p).map(|f| f.1.clone()).ok_or_else(|| "no such file".to_string())
        }
    }

    fn paths() -> Paths {
        Paths {
            unit: PathBuf::from("/fake/noo-addons-after-boot.service"),
            owner_file: PathBuf::from("/fake/addons-after-boot.owner"),
            boot_id: PathBuf::from("/fake/boot_id"),
            state_dir: PathBuf::from("/fake/state/noo"),
        }
    }

    fn good_os() -> FakeOs {
        let p = paths();
        let mut files = BTreeMap::new();
        files.insert(p.owner_file, (tight(0), format!("{OWNER_UID} rhowner\n")));
        files.insert(p.unit, (tight(0), render_unit("rhowner", "/usr/local/bin/noo", "/srv/noomesh").unwrap()));
        let mut dirs = BTreeMap::new();
        dirs.insert(PathBuf::from("/srv/noomesh"), FileFacts { uid: OWNER_UID, gid: OWNER_UID, mode: 0o755 });
        FakeOs { euid: OWNER_UID, files, dirs }
    }

    #[derive(Default)]
    struct Fake {
        stamp: Option<String>,
        stamped: Vec<String>,
        healthy_after: Option<u32>,
        probes: u32,
        sleeps: u32,
        credential: Option<String>,
        enabled: Vec<String>,
        /// addon -> containers down now
        down: BTreeMap<String, Vec<String>>,
        /// addon -> containers still down after a start
        down_after: BTreeMap<String, Vec<String>>,
        started_flag: BTreeMap<String, bool>,
        guard: BTreeMap<String, String>,
        launcher_error: BTreeMap<String, String>,
        /// addon -> held containers and why
        held: BTreeMap<String, Vec<(String, String)>>,
        /// add-ons whose overlay declares no containers
        undeclared: Vec<String>,
        starts: Vec<String>,
        reports: Vec<(String, Value)>,
        reject: BTreeMap<String, ReportError>,
    }

    impl Run for Fake {
        fn boot_id(&mut self) -> Result<String, String> {
            Ok(BOOT.to_string())
        }
        fn stamp(&mut self) -> Option<String> {
            self.stamp.clone()
        }
        fn write_stamp(&mut self, boot_id: &str) -> Result<(), String> {
            self.stamped.push(boot_id.to_string());
            self.stamp = Some(boot_id.to_string());
            Ok(())
        }
        fn gateway_healthy(&mut self) -> bool {
            self.probes += 1;
            matches!(self.healthy_after, Some(n) if self.probes > n)
        }
        fn sleep(&mut self, _d: Duration) {
            self.sleeps += 1;
        }
        fn credential_problem(&mut self) -> Option<String> {
            self.credential.clone()
        }
        fn enabled_addons(&mut self) -> Result<Vec<String>, String> {
            Ok(self.enabled.clone())
        }
        fn containers(&mut self, addon: &str) -> Result<Containers, String> {
            let held = self.held.get(addon).cloned().unwrap_or_default();
            let down = if self.started_flag.get(addon).copied().unwrap_or(false) {
                self.down_after.get(addon).cloned().unwrap_or_default()
            } else {
                self.down.get(addon).cloned().unwrap_or_default()
            };
            Ok(Containers { down, held, undeclared: self.undeclared.iter().any(|u| u == addon), ..Default::default() })
        }
        fn guard_refusal(&mut self, addon: &str) -> Option<String> {
            self.guard.get(addon).cloned()
        }
        fn start(&mut self, addon: &str) -> Result<(), String> {
            self.starts.push(addon.to_string());
            self.started_flag.insert(addon.to_string(), true);
            match self.launcher_error.get(addon) {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }
        fn report(&mut self, addon: &str, body: &Value) -> Result<(), ReportError> {
            self.reports.push((addon.to_string(), body.clone()));
            match self.reject.get(addon) {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }
    }

    fn healthy_fake(enabled: &[&str], down: &[(&str, &[&str])]) -> Fake {
        Fake {
            healthy_after: Some(0),
            enabled: enabled.iter().map(|s| s.to_string()).collect(),
            down: down.iter().map(|(a, c)| (a.to_string(), c.iter().map(|s| s.to_string()).collect())).collect(),
            ..Default::default()
        }
    }

    fn go(os: &FakeOs, fake: &mut Fake) -> (i32, Vec<String>) {
        let mut lines = Vec::new();
        let code = run(os, &paths(), &Limits { wait: Duration::from_secs(20), poll: Duration::from_secs(5) }, fake, &mut |l: &str| lines.push(l.to_string()));
        (code, lines)
    }

    fn assert_refused_and_idle(os: &FakeOs, needle: &str) {
        let mut fake = healthy_fake(&["rhaddon"], &[("rhaddon", &["noo-rhaddon"])]);
        let (code, lines) = go(os, &mut fake);
        assert_ne!(code, 0, "{lines:?}");
        assert_eq!(lines.len(), 1, "one journal line: {lines:?}");
        assert!(lines[0].contains(needle), "{lines:?} should contain {needle:?}");
        assert!(fake.starts.is_empty() && fake.reports.is_empty() && fake.stamped.is_empty() && fake.probes == 0, "nothing may happen after a refusal");
    }

    /// An enabled add-on with no `x-noo-addon` block (a third-party overlay
    /// the operator cannot fix) is skipped with one journal line: nothing
    /// started, nothing reported, and the run still succeeds.
    #[test]
    fn an_add_on_that_declares_no_containers_is_skipped_with_one_line() {
        let mut fake = healthy_fake(&["rhaddon"], &[]);
        fake.undeclared.push("rhaddon".to_string());
        let (code, lines) = go(&good_os(), &mut fake);
        assert_eq!(code, 0, "{lines:?}");
        let about: Vec<&String> = lines.iter().filter(|l| l.starts_with("rhaddon:")).collect();
        assert_eq!(about.len(), 1, "{lines:?}");
        assert!(about[0].contains("declares no x-noo-addon containers"), "{lines:?}");
        assert!(fake.starts.is_empty() && fake.reports.is_empty(), "nothing started or reported: {:?} {:?}", fake.starts, fake.reports);
    }

    /// The overlay itself: no block reads as undeclared, before any docker
    /// call, never as an error.
    #[test]
    fn an_overlay_without_the_block_reads_as_undeclared() {
        let root = std::env::temp_dir().join(format!("noo-undeclared-{}", std::process::id()));
        let dir = crate::addons::pins::addon_dir(&root, "rhaddon");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("docker-compose.yml"), "services:\n  noo-rhaddon:\n    image: x\n").unwrap();
        let c = down_containers_at(&root, "rhaddon").expect("no block is not an error");
        assert!(c.undeclared && c.down.is_empty() && c.held.is_empty(), "{c:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// One after-boot start makes one gateway record: the restart it runs
    /// must not post its own `started` (0.6.24-rc.7 rehearsal: two records).
    #[test]
    fn the_after_boot_start_does_not_let_the_restart_post_too() {
        let own = crate::test_src::own_code(include_str!("addon_after_boot.rs"));
        let start = crate::test_src::fn_body(&own, "    fn start(&mut self, addon: &str) -> Result<(), String> \u{7b}\n        let script");
        assert!(start.contains("restart_reporting(self.g, &[addon.to_string()], false)"), "{start}");
        assert!(!start.contains("mesh_restart("), "mesh_restart posts its own started record");
        let mesh = crate::test_src::own_code(include_str!("mesh.rs"));
        let body = crate::test_src::fn_body(&mesh, "pub(crate) fn restart_reporting(");
        let gate = body.find("if report_started \u{7b}").expect("the post is gated");
        let post = body.find("report_restarted(g, &services)").expect("the post");
        assert!(gate < post, "the post must sit inside the gate");
        let cli = crate::test_src::fn_body(&mesh, "pub fn mesh_restart(");
        assert!(cli.contains("restart_reporting(g, args, true)"), "`noo stack restart` itself always reports");
    }

    #[test]
    fn the_good_install_passes_every_refusal_check() {
        assert_eq!(refusals(&good_os(), &paths()), Ok((OWNER_UID, "rhowner".to_string())));
    }

    /// rc.6 A-afterboot: an install root another account owns is refused
    /// once, up front, with the whole picture, never step by step.
    #[test]
    fn an_install_the_owner_does_not_own_is_refused_by_check_e_once_with_the_remedy() {
        let mut os = good_os();
        os.dirs.insert(PathBuf::from("/srv/noomesh"), FileFacts { uid: 0, gid: 0, mode: 0o755 });
        let e = refusals(&os, &paths()).unwrap_err();
        assert!(e.starts_with("refusing to run: check (e) failed: the install /srv/noomesh belongs to root, not to rhowner"), "{e}");
        assert!(e.contains("sudo find /srv/noomesh -xdev -user root -group root -exec chown rhowner:rhowner {} +"), "{e}");
        assert_refused_and_idle(&os, "check (e)");
    }

    #[test]
    fn an_install_root_the_owner_cannot_reach_is_refused_by_check_e() {
        let mut os = good_os();
        os.dirs.clear();
        let e = refusals(&os, &paths()).unwrap_err();
        assert!(e.contains("check (e) failed: the install /srv/noomesh cannot be reached as rhowner"), "{e}");
        assert!(e.contains("inside another account's home"), "{e}");
    }

    #[test]
    fn an_install_another_user_owns_names_that_uid_in_the_remedy() {
        let mut os = good_os();
        os.dirs.insert(PathBuf::from("/srv/noomesh"), FileFacts { uid: 1001, gid: 1001, mode: 0o755 });
        let e = refusals(&os, &paths()).unwrap_err();
        assert!(e.contains("belongs to uid 1001") && e.contains("sudo find /srv/noomesh -xdev -user 1001 -exec chown rhowner {} +"), "{e}");
    }

    #[test]
    fn running_as_root_is_refused_by_check_d_and_nothing_is_started() {
        let mut os = good_os();
        os.euid = 0;
        assert_refused_and_idle(&os, "check (d)");
    }

    #[test]
    fn running_as_someone_other_than_the_recorded_owner_is_refused_by_check_a() {
        let mut os = good_os();
        os.euid = OWNER_UID + 1;
        assert_refused_and_idle(&os, "check (a)");
    }

    #[test]
    fn a_unit_file_not_owned_by_root_is_refused_by_check_b() {
        let mut os = good_os();
        os.files.get_mut(&paths().unit).unwrap().0 = FileFacts { uid: OWNER_UID, gid: OWNER_UID, mode: 0o644 };
        assert_refused_and_idle(&os, "check (b)");
    }

    #[test]
    fn a_group_or_other_writable_unit_file_is_refused_by_check_b() {
        for mode in [0o664, 0o646, 0o666, 0o620] {
            let mut os = good_os();
            os.files.get_mut(&paths().unit).unwrap().0 = FileFacts { uid: 0, gid: 0, mode };
            assert_refused_and_idle(&os, "check (b)");
        }
    }

    #[test]
    fn a_unit_whose_user_is_not_the_recorded_owner_is_refused_by_check_c() {
        let mut os = good_os();
        os.files.get_mut(&paths().unit).unwrap().1 = render_unit("someoneelse", "/usr/local/bin/noo", "/srv/noomesh").unwrap();
        assert_refused_and_idle(&os, "check (c)");
        let mut os = good_os();
        os.files.get_mut(&paths().unit).unwrap().1 = "[Service]\nType=oneshot\n".to_string();
        assert_refused_and_idle(&os, "check (c)");
    }

    #[test]
    fn an_owner_record_that_is_not_root_owned_or_is_writable_or_malformed_is_refused() {
        let mut os = good_os();
        os.files.get_mut(&paths().owner_file).unwrap().0 = FileFacts { uid: OWNER_UID, gid: OWNER_UID, mode: 0o644 };
        assert_refused_and_idle(&os, "owner record");
        let mut os = good_os();
        os.files.get_mut(&paths().owner_file).unwrap().0 = FileFacts { uid: 0, gid: 0, mode: 0o666 };
        assert_refused_and_idle(&os, "group- or other-writable");
        for bad in ["", "1000\n", "rhowner 1000\n", "1000 rhowner extra\n", "1000 rhowner\n1001 other\n", "1000  rhowner\n"] {
            let mut os = good_os();
            os.files.get_mut(&paths().owner_file).unwrap().1 = bad.to_string();
            assert_refused_and_idle(&os, "malformed");
        }
        let mut os = good_os();
        os.files.remove(&paths().owner_file);
        assert_refused_and_idle(&os, "owner record");
    }

    #[test]
    fn two_enabled_add_ons_one_down_starts_only_the_down_one_reports_started_and_stamps_the_boot() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon", "otheraddon"], &[("rhaddon", &["noo-rhaddon"])]);
        let (code, lines) = go(&os, &mut fake);
        assert_eq!(code, 0, "{lines:?}");
        assert_eq!(fake.starts, vec!["rhaddon".to_string()]);
        assert_eq!(fake.reports.len(), 1);
        assert_eq!(fake.reports[0].0, "rhaddon");
        assert_eq!(fake.reports[0].1, json!({"boot_id": BOOT, "outcome": "started"}));
        assert_eq!(fake.stamped, vec![BOOT.to_string()]);
        assert!(lines.iter().any(|l| l.starts_with("rhaddon: started")), "{lines:?}");
    }

    #[test]
    fn a_launcher_that_exits_non_zero_is_reported_as_launcher_failed_with_its_output() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon"], &[("rhaddon", &["noo-rhaddon"])]);
        fake.launcher_error.insert("rhaddon".into(), "compose up exited 3".into());
        let (code, lines) = go(&os, &mut fake);
        assert_ne!(code, 0);
        assert_eq!(fake.reports[0].1, json!({"boot_id": BOOT, "outcome": "failed", "code": "launcher_failed", "detail": "compose up exited 3"}));
        assert!(lines.iter().any(|l| l.contains("rhaddon") && l.contains("launcher_failed") && l.contains("noo stack restart rhaddon")), "{lines:?}");
        assert_eq!(fake.stamped.len(), 1, "a failed attempt still stamps: once per boot");
    }

    #[test]
    fn an_add_on_the_guards_refuse_is_not_started_and_reports_the_guards_sentence() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon"], &[("rhaddon", &["noo-rhaddon"])]);
        fake.guard.insert("rhaddon".into(), "add-on rhaddon: interpolates NOO_JWT_SECRET".into());
        let (code, _) = go(&os, &mut fake);
        assert_ne!(code, 0);
        assert!(fake.starts.is_empty(), "a refused add-on is never started");
        assert_eq!(fake.reports[0].1["code"], "refused_by_guard");
        assert_eq!(fake.reports[0].1["detail"], "add-on rhaddon: interpolates NOO_JWT_SECRET");
    }

    #[test]
    fn a_start_that_leaves_containers_down_is_reported_as_still_down_after_start() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon"], &[("rhaddon", &["noo-rhaddon"])]);
        fake.down_after.insert("rhaddon".into(), vec!["noo-rhaddon".into()]);
        let (code, _) = go(&os, &mut fake);
        assert_ne!(code, 0);
        assert_eq!(fake.starts.len(), 1);
        assert_eq!(fake.reports[0].1["code"], "still_down_after_start");
        assert!(fake.reports[0].1["detail"].as_str().unwrap().contains("noo-rhaddon"));
    }

    #[test]
    fn a_second_run_in_the_same_boot_does_nothing() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon"], &[("rhaddon", &["noo-rhaddon"])]);
        assert_eq!(go(&os, &mut fake).0, 0);
        let (starts, reports) = (fake.starts.len(), fake.reports.len());
        fake.started_flag.clear();
        let (code, lines) = go(&os, &mut fake);
        assert_eq!(code, 0);
        assert_eq!((fake.starts.len(), fake.reports.len()), (starts, reports), "nothing new was started or reported");
        assert!(lines.iter().any(|l| l.contains("already ran for this boot")), "{lines:?}");
        // A different boot id is a new boot.
        fake.stamp = Some("11111111-1111-1111-1111-111111111111".into());
        fake.started_flag.clear();
        assert_eq!(go(&os, &mut fake).0, 0);
        assert_eq!(fake.starts.len(), starts + 1);
    }

    #[test]
    fn a_gateway_that_never_becomes_healthy_starts_nothing_stamps_nothing_and_fails() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon", "otheraddon"], &[("rhaddon", &["noo-rhaddon"])]);
        fake.healthy_after = None;
        let (code, lines) = go(&os, &mut fake);
        assert_ne!(code, 0);
        assert!(fake.starts.is_empty() && fake.reports.is_empty() && fake.stamped.is_empty());
        assert_eq!(fake.sleeps, 4, "20s of waiting in 5s polls");
        for a in ["rhaddon", "otheraddon"] {
            assert!(lines.iter().any(|l| l.starts_with(&format!("{a}: gateway_wait_timeout")) && l.contains(&format!("noo stack restart {a}"))), "{lines:?}");
        }
    }

    #[test]
    fn a_gateway_that_comes_up_late_is_waited_for() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon"], &[("rhaddon", &["noo-rhaddon"])]);
        fake.healthy_after = Some(2);
        assert_eq!(go(&os, &mut fake).0, 0);
        assert_eq!(fake.sleeps, 2);
        assert_eq!(fake.starts.len(), 1);
    }

    #[test]
    fn a_missing_credential_names_noo_auth_login_and_starts_nothing() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon"], &[("rhaddon", &["noo-rhaddon"])]);
        fake.credential = Some("there is no stored CLI credential for this user".into());
        let (code, lines) = go(&os, &mut fake);
        assert_ne!(code, 0);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("noo auth login") && lines[0].contains("no stored CLI credential"), "{lines:?}");
        assert!(fake.starts.is_empty() && fake.stamped.is_empty());
    }

    #[test]
    fn a_rejected_report_prints_the_gateways_error_continues_to_the_next_add_on_and_fails() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon", "otheraddon"], &[("rhaddon", &["noo-rhaddon"]), ("otheraddon", &["noo-otheraddon"])]);
        fake.reject.insert("rhaddon".into(), ReportError::Status(400, "\u{7b}\"error\":\"boot_id is not a uuid\"\u{7d}".into()));
        let (code, lines) = go(&os, &mut fake);
        assert_ne!(code, 0);
        assert_eq!(fake.starts, vec!["rhaddon".to_string(), "otheraddon".to_string()], "the run went on");
        assert_eq!(fake.reports.len(), 2);
        assert!(lines.iter().any(|l| l.contains("rhaddon") && l.contains("HTTP 400: boot_id is not a uuid")), "{lines:?}");
        assert_eq!(fake.stamped.len(), 1);
    }

    #[test]
    fn a_rejection_that_is_not_json_prints_the_raw_body() {
        assert_eq!(describe_rejection(&ReportError::Status(502, "bad gateway\n".into())), "HTTP 502: bad gateway");
        assert_eq!(describe_rejection(&ReportError::Status(500, String::new())), "HTTP 500");
        assert!(describe_rejection(&ReportError::Transport("refused".into())).contains("refused"));
    }

    #[test]
    fn detail_is_cut_to_4096_bytes_on_a_character_boundary() {
        // 4095 ASCII bytes then a 3-byte character straddling byte 4096.
        let s = format!("{}\u{20ac}tail", "a".repeat(4095));
        let cut = truncate_detail(&s, DETAIL_MAX_BYTES);
        assert_eq!(cut.len(), 4095, "the euro sign does not fit and is dropped whole");
        assert!(cut.chars().all(|c| c == 'a'));
        let short = truncate_detail("short", DETAIL_MAX_BYTES);
        assert_eq!(short, "short");
        let exact = "b".repeat(4096);
        assert_eq!(truncate_detail(&exact, DETAIL_MAX_BYTES).len(), 4096);
        let body = report_body(BOOT, &Outcome::Failed(Code::LauncherFailed, s));
        assert!(body["detail"].as_str().unwrap().len() <= DETAIL_MAX_BYTES);
    }

    #[test]
    fn the_report_body_has_exactly_the_documented_shape() {
        assert_eq!(report_body(BOOT, &Outcome::Started), json!({"boot_id": BOOT, "outcome": "started"}));
        assert_eq!(
            report_body(BOOT, &Outcome::Failed(Code::StillDownAfterStart, String::new())),
            json!({"boot_id": BOOT, "outcome": "failed", "code": "still_down_after_start"})
        );
    }

    fn seen(name: &str, service: &str, state: &str, exit_code: i32, health: &str) -> Seen {
        Seen { name: name.into(), project: "p".into(), service: service.into(), state: state.into(), exit_code, health: health.into() }
    }

    const TWO_SERVICES: &str = "services:\n  web:\n    container_name: noo-rhaddon\n    image: x\n  worker:\n    container_name: noo-rhaddon-worker\n    image: x\n  gpu:\n    container_name: noo-rhaddon-gpu\n    image: x\n";

    /// A held container (the launcher's hold) is neither expected to run nor
    /// started; another expected container that is down still is. Not
    /// subtracting holds turns a held GPU worker into a FAIL every boot.
    #[test]
    fn a_held_container_is_not_down_and_another_down_one_still_is() {
        let declared = vec!["noo-rhaddon".to_string(), "noo-rhaddon-gpu".to_string()];
        let overlay = "services:\n  web:\n    container_name: noo-rhaddon\n  gpu:\n    container_name: noo-rhaddon-gpu\n";
        let held = vec![("noo-rhaddon-gpu".to_string(), "asks for a GPU".to_string())];
        let up = [seen("noo-rhaddon", "web", "running", 0, "")];
        let c = judge_containers(&declared, overlay, "p", &up, &held, &[]).unwrap();
        assert_eq!(c, Containers { held: held.clone(), ..Default::default() }, "held only: nothing is down");
        let c = judge_containers(&declared, overlay, "p", &[], &held, &[]).unwrap();
        assert_eq!(c.down, vec!["noo-rhaddon".to_string()], "only the container that should run is down");
        assert_eq!(c.held, held);
        assert_eq!(judge_containers(&declared, overlay, "p", &[], &[], &[]).unwrap().down, declared, "without a hold both are down");
    }

    /// A compose service that `x-noo-addon: containers` does not list is
    /// still expected: Exited (127) next to a running sibling is down, and
    /// an unhealthy running container is named, not passed.
    #[test]
    fn a_service_outside_the_declared_list_is_expected_and_health_is_read() {
        let decl = vec!["noo-rhaddon".to_string()];
        let s = [seen("noo-rhaddon", "web", "running", 0, "unhealthy"), seen("noo-rhaddon-worker", "worker", "exited", 127, "")];
        let c = judge_containers(&decl, TWO_SERVICES, "p", &s, &[], &[]).unwrap();
        assert_eq!(c.down, vec!["noo-rhaddon-worker".to_string(), "noo-rhaddon-gpu".to_string()], "{c:?}");
        assert_eq!(c.unhealthy, vec!["noo-rhaddon".to_string()], "{c:?}");
        // `starting` is not unhealthy; with every service up nothing is named.
        let s = [
            seen("noo-rhaddon", "web", "running", 0, "starting"),
            seen("noo-rhaddon-worker", "worker", "running", 0, "healthy"),
            seen("noo-rhaddon-gpu", "gpu", "running", 0, ""),
        ];
        let c = judge_containers(&decl, TWO_SERVICES, "p", &s, &[], &[]).unwrap();
        assert_eq!(c, Containers::default(), "{c:?}");
    }

    /// A service without `container_name` resolves by its compose label; a
    /// profiled service is optional; a one-shot that finished (exit 0) or
    /// never ran is not down, one that failed is.
    #[test]
    fn services_resolve_by_label_profiles_are_optional_and_one_shots_may_exit() {
        let decl = vec!["noo-rhaddon".to_string()];
        let overlay = "services:\n  web:\n    container_name: noo-rhaddon\n  api:\n    image: x\n  extra:\n    image: x\n    profiles: [debug]\n  routes:\n    image: x\n    restart: \"no\"\n  prep:\n    image: x\n";
        let base = [seen("noo-rhaddon", "web", "running", 0, ""), seen("acme-api-1", "api", "running", 0, "")];
        let c = judge_containers(&decl, overlay, "p", &base, &[], &["prep".to_string()]).unwrap();
        assert_eq!(c, Containers::default(), "profiled absent, one-shots never created: ok: {c:?}");
        let mut done = base.to_vec();
        done.push(seen("acme-routes-1", "routes", "exited", 0, ""));
        done.push(seen("acme-prep-1", "prep", "exited", 0, ""));
        assert_eq!(judge_containers(&decl, overlay, "p", &done, &[], &["prep".to_string()]).unwrap(), Containers::default());
        let mut bad = base.to_vec();
        bad.push(seen("acme-routes-1", "routes", "exited", 1, ""));
        assert_eq!(judge_containers(&decl, overlay, "p", &bad, &[], &[]).unwrap().down, vec!["routes".to_string(), "prep".to_string()]);
        // Without the declared list, `prep` (no `restart: "no"`) is expected.
        assert_eq!(judge_containers(&decl, overlay, "p", &done, &[], &[]).unwrap().down, vec!["prep".to_string()]);
    }

    /// Another compose project's service of the same name is invisible, both
    /// ways: its running `db` does not make this project's dead `db` look up,
    /// and its failed one-shot does not fail this project.
    #[test]
    fn another_projects_service_of_the_same_name_does_not_count() {
        let decl = vec!["noo-rhaddon".to_string()];
        let overlay = "services:\n  web:\n    container_name: noo-rhaddon\n  db:\n    image: x\n  job:\n    image: x\n    restart: \"no\"\n";
        let other = |svc: &str, state: &str, code: i32| Seen { name: format!("other-{svc}-1"), project: "other".into(), service: svc.into(), state: state.into(), exit_code: code, health: String::new() };
        let web = seen("noo-rhaddon", "web", "running", 0, "");
        // Ours is dead, theirs runs: still down.
        let mut s = vec![web.clone(), seen("p-db-1", "db", "exited", 1, ""), other("db", "running", 0)];
        assert_eq!(judge_containers(&decl, overlay, "p", &s, &[], &[]).unwrap().down, vec!["db".to_string()]);
        // Ours runs, theirs failed (and their one-shot failed): nothing is down.
        s = vec![web, seen("p-db-1", "db", "running", 0, ""), other("db", "exited", 1), other("job", "exited", 1)];
        assert_eq!(judge_containers(&decl, overlay, "p", &s, &[], &[]).unwrap(), Containers::default());
    }

    /// `deploy.replicas: 0` / `scale: 0` are not expected; a service that
    /// exited 0 without being a declared one-shot is down for verify (named
    /// in `exited_clean`) but never in `boot_down`, so after-boot cannot loop.
    #[test]
    fn replicas_zero_is_not_expected_and_after_boot_acts_only_on_the_declared_names() {
        let decl = vec!["noo-rhaddon".to_string()];
        let overlay = "services:\n  web:\n    container_name: noo-rhaddon\n  off:\n    image: x\n    deploy:\n      replicas: 0\n  off2:\n    image: x\n    scale: 0\n  quiet:\n    image: x\n";
        let s = [seen("noo-rhaddon", "web", "running", 0, ""), seen("p-quiet-1", "quiet", "exited", 0, "")];
        let c = judge_containers(&decl, overlay, "p", &s, &[], &[]).unwrap();
        assert_eq!(c.down, vec!["quiet".to_string()], "{c:?}");
        assert_eq!(c.exited_clean, vec!["quiet".to_string()], "{c:?}");
        assert!(c.boot_down.is_empty(), "after-boot must not act on it: {c:?}");
        let v = boot_view(c).unwrap();
        assert!(v.down.is_empty() && v.unhealthy.is_empty(), "{v:?}");
        // A declared container that is down is what after-boot starts.
        let c = judge_containers(&decl, overlay, "p", &[], &[], &[]).unwrap();
        assert_eq!(boot_view(c).unwrap().down, vec!["noo-rhaddon".to_string()]);
    }

    fn answered(stdout: &str) -> crate::bounded::Bounded {
        use std::os::unix::process::ExitStatusExt as _;
        crate::bounded::Bounded::Answered(std::process::Output { status: std::process::ExitStatus::from_raw(0), stdout: stdout.as_bytes().to_vec(), stderr: Vec::new() })
    }

    /// A declared name running under another project is not down for
    /// after-boot (matched by container name wherever it runs, as before);
    /// one running nowhere still is. Verify's per-project view is unchanged.
    #[test]
    fn a_declared_name_running_under_another_project_is_not_down_for_after_boot() {
        let decl = vec!["noo-rhaddon".to_string()];
        let overlay = "services:\n  web:\n    container_name: noo-rhaddon\n";
        let mut c = judge_containers(&decl, overlay, "p", &[], &[], &[]).unwrap();
        assert_eq!(c.boot_down, vec!["noo-rhaddon".to_string()]);
        let far = std::time::Instant::now() + Duration::from_secs(60);
        drop_running_elsewhere(&mut c, far, &mut |_, _| answered("noo-rhaddon\nother\n")).unwrap();
        assert!(c.boot_down.is_empty(), "{c:?}");
        assert_eq!(c.down, vec!["noo-rhaddon".to_string()], "verify still reads it per project");
        let mut c = judge_containers(&decl, overlay, "p", &[], &[], &[]).unwrap();
        drop_running_elsewhere(&mut c, far, &mut |_, _| answered("other\n")).unwrap();
        assert_eq!(c.boot_down, vec!["noo-rhaddon".to_string()]);
        let past = std::time::Instant::now();
        assert!(matches!(drop_running_elsewhere(&mut c, past, &mut |_, _| answered("")), Err(StatesError::TimedOut(_))), "an expired deadline makes no call");
    }

    /// One add-on's reads share one deadline: a call is given only the time
    /// that is left, never a fresh 20 s.
    #[test]
    fn the_reads_of_one_add_on_share_one_deadline() {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut limits: Vec<Duration> = Vec::new();
        let _ = read_states_via("proj", deadline, &mut |args, limit| {
            limits.push(limit);
            std::thread::sleep(Duration::from_millis(30));
            if args[0] == "ps" { answered("abc\n") } else { answered("/noo-a\tproj\tweb\trunning\t0\t\n") }
        });
        assert_eq!(limits.len(), 2);
        assert!(limits[0] <= Duration::from_secs(20) && limits[1] < limits[0], "{limits:?}");
    }

    /// The listing is filtered on this project and only its ids are
    /// inspected; a docker that hangs is a timeout, never an empty answer.
    #[test]
    fn docker_is_asked_about_this_project_only_and_a_hang_is_not_a_pass() {
        let mut calls: Vec<Vec<String>> = Vec::new();
        let far = std::time::Instant::now() + Duration::from_secs(60);
        let r = read_states_via("proj", far, &mut |args, _| {
            calls.push(args.iter().map(|a| a.to_string()).collect());
            if args[0] == "ps" { answered("abc\n") } else { answered("/noo-a\tproj\tweb\trunning\t0\t\n") }
        });
        assert_eq!(r.unwrap().len(), 1);
        assert!(calls[0].contains(&"label=com.docker.compose.project=proj".to_string()), "{calls:?}");
        assert_eq!(calls[1].last().map(String::as_str), Some("abc"), "{calls:?}");
        for hang_on in ["ps", "inspect"] {
            let r = read_states_via("proj", far, &mut |args, _| {
                if args[0] == hang_on { crate::bounded::Bounded::TimedOut { secs: 20 } } else { answered("abc\n") }
            });
            assert!(matches!(r, Err(StatesError::TimedOut(ref w)) if w.contains(hang_on)), "{r:?}");
        }
        let hung = Containers { docker_timeout: Some("docker ps after 20s".into()), ..Default::default() };
        assert!(boot_view(hung).is_err(), "after-boot never reads a hang as already running");
    }

    #[test]
    fn state_lines_parse_with_and_without_a_healthcheck() {
        let out = "/noo-a\tp\tweb\trunning\t0\thealthy\n/noo-b\tp\t\texited\t127\t\n";
        let v = parse_states(out).unwrap();
        assert_eq!(v[0], seen("noo-a", "web", "running", 0, "healthy"));
        assert_eq!(v[1], seen("noo-b", "", "exited", 127, ""));
        assert!(parse_states("garbage").is_err());
    }

    /// The hold is the launcher's (`resources::holds`), for a third-party
    /// add-on only, by container name.
    #[test]
    fn holds_are_read_from_the_launchers_rule_by_container_name() {
        let overlay = include_str!("../../../tests/fixtures/addons/rhaddon/docker-compose.yml");
        let held = held_containers(overlay, true).unwrap();
        assert_eq!(held.len(), 1, "{held:?}");
        assert_eq!(held[0].0, "noo-rhaddon-gpu");
        assert!(held[0].1.contains("GPU"), "{held:?}");
        assert!(held_containers(overlay, false).unwrap().is_empty(), "the launcher holds nothing of a first-party add-on");
    }

    #[test]
    fn an_add_on_whose_only_missing_container_is_held_is_not_started_or_reported() {
        let os = good_os();
        let mut fake = healthy_fake(&["rhaddon"], &[]);
        fake.held.insert("rhaddon".into(), vec![("noo-rhaddon-gpu".into(), "asks for a GPU".into())]);
        let (code, lines) = go(&os, &mut fake);
        assert_eq!(code, 0, "{lines:?}");
        assert!(fake.starts.is_empty() && fake.reports.is_empty(), "a held container is never started or reported");
        assert_eq!(lines.iter().filter(|l| l.contains("held")).count(), 1, "one log line: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("noo-rhaddon-gpu is held (asks for a GPU)")), "{lines:?}");
    }

    #[test]
    fn a_restart_reports_the_enabled_add_ons_it_named_or_all_of_them() {
        let enabled = vec!["rhaddon".to_string(), "otheraddon".to_string()];
        assert_eq!(restarted_addons(&[], &enabled), enabled, "a whole-stack restart restarts every enabled add-on");
        assert_eq!(restarted_addons(&["rhaddon".into(), "gateway".into()], &enabled), vec!["rhaddon".to_string()], "a core service is not an add-on");
        assert!(restarted_addons(&["gateway".into()], &enabled).is_empty());
    }

    #[test]
    fn a_fresh_uuid_is_a_version_4_uuid() {
        let u = uuid_v4_from([0xff; 16]);
        assert_eq!(u, "ffffffff-ffff-4fff-bfff-ffffffffffff");
        let u = uuid_v4_from([0; 16]);
        assert_eq!(u, "00000000-0000-4000-8000-000000000000");
        assert_eq!(u.len(), 36);
    }

    #[test]
    fn every_code_the_cli_can_send_is_in_the_shared_code_list() {
        let list: Value = serde_json::from_str(include_str!("../testdata/addon_boot_start_codes.json")).unwrap();
        let codes = list["codes"].as_object().expect("codes is an object");
        for c in Code::ALL {
            assert!(codes.contains_key(c.as_str()), "{} is not in addon_boot_start_codes.json", c.as_str());
        }
        let outcomes: Vec<&str> = list["outcomes"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(outcomes, vec!["started", "failed"]);
    }

    #[test]
    fn the_unit_runs_a_oneshot_as_the_owner_after_docker_and_the_network() {
        let u = render_unit("rhowner", "/usr/local/bin/noo", "/srv/noomesh").unwrap();
        assert!(u.contains("\nType=oneshot\n"), "{u}");
        assert!(u.contains("\nUser=rhowner\n"), "{u}");
        assert!(u.contains("\nExecStart=/usr/local/bin/noo addons after-boot\n"), "{u}");
        assert!(u.contains("\nAfter=docker.service network-online.target\n"), "{u}");
        assert!(u.contains("\nWants=network-online.target\n"), "{u}");
        assert!(u.contains("\nWantedBy=multi-user.target\n"), "{u}");
        // Bounded, and multi-user.target is not ordered after it (i1160).
        assert!(u.contains("\nTimeoutStartSec=3600\n"), "{u}");
        assert!(u.contains("\nDefaultDependencies=no\n") && u.contains("\nConflicts=shutdown.target\n"), "{u}");
        // It runs in, and declares, the install onboard configured (a
        // service starts in /, where the CLI would fall back to ~/.noo).
        assert!(u.contains("\nWorkingDirectory=/srv/noomesh\n") && u.contains("\nEnvironment=NOO_REPO_ROOT=/srv/noomesh\n"), "{u}");
    }

    #[test]
    fn a_unit_is_not_rendered_for_a_name_or_path_that_could_change_what_systemd_reads() {
        assert!(render_unit("a b", "/usr/local/bin/noo", "/srv/noomesh").is_err());
        assert!(render_unit("a\nUser=root", "/usr/local/bin/noo", "/srv/noomesh").is_err());
        assert!(render_unit("", "/usr/local/bin/noo", "/srv/noomesh").is_err());
        assert!(render_unit("rhowner", "noo", "/srv/noomesh").is_err());
        assert!(render_unit("rhowner", "/opt/my noo/noo", "/srv/noomesh").is_err());
        assert!(render_unit("rhowner", "/opt/noo%h", "/srv/noomesh").is_err());
        assert!(render_unit("rhowner", "/usr/local/bin/noo", "srv/noomesh").is_err(), "a relative root");
        assert!(render_unit("rhowner", "/usr/local/bin/noo", "/srv/$HOME").is_err(), "a root systemd would expand");
        assert!(render_owner(0, "root").is_err());
    }

    #[test]
    fn the_owner_record_round_trips() {
        let t = render_owner(1000, "rhowner").unwrap();
        assert_eq!(t, "1000 rhowner\n");
        assert_eq!(parse_owner(&t), Ok((1000, "rhowner".to_string())));
    }

    #[test]
    fn the_stamp_lives_under_xdg_state_home_or_the_default_state_dir() {
        assert_eq!(state_dir_from(Some("/x/state".into()), Some("/home/u".into())), PathBuf::from("/x/state/noo"));
        assert_eq!(state_dir_from(None, Some("/home/u".into())), PathBuf::from("/home/u/.local/state/noo"));
        assert_eq!(state_dir_from(Some("relative".into()), Some("/home/u".into())), PathBuf::from("/home/u/.local/state/noo"));
        assert_eq!(paths().stamp(), PathBuf::from("/fake/state/noo/addons-after-boot"));
    }
}
