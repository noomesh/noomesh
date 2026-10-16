// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Warm-up rows. `noo upgrade --stack` and `noo stack
//! restart --force` end by pointing at `noo cluster verify`; run straight
//! away, the `loki` row printed "/ready did not answer — the container is
//! down, or its leaf/CA does not match" for a Loki that had started five
//! seconds earlier and was still joining its ring. Two minutes later the
//! same row was ✓. The advice sent the operator after a certificate problem
//! that did not exist.
//!
//! The rule, and the whole of it:
//!
//! * Only a row named in [`WARMUP_ROWS`] may be judged here, and only for
//!   its readiness miss (the caller says which failure that is). A missing
//!   leaf, an unset URL, any TLS/secrets/auth row: never. Those are wrong
//!   whenever they are seen.
//! * The miss reads as [`Verdict::Starting`] — "starting (up 40s)", neither
//!   OK nor FAIL — only when `docker inspect` says the row's container is
//!   running, started less than [`WARMUP_WINDOW_SECS`] ago, and its health
//!   is `starting` (or it declares no healthcheck, as Loki does). Unhealthy,
//!   healthy-but-not-ready, not running, or not inspectable: the FAIL
//!   stands.
//! * Past the window the FAIL stands and names the container and how long
//!   it has been up, so a row stuck in "starting" is a failure you can act on.
//! * For `loki`, a readiness miss is ANY not-ready answer the gateway
//!   reports — no answer, a timeout, a 503, any 5xx — judged from
//!   `loki_ready != true` alone, never from the text of
//!   `loki_ready_detail`. Loki's own 503 bodies ("Ingester not ready:
//!   waiting for 15s after being ready", the v0.2.87 rehearsal at ~4 min)
//!   are its ring still joining; matching them would break on the next
//!   wording. The detail is carried, never parsed.
//! * `Starting` is not a pass: the verb still exits 1 and says why, so a
//!   real fault inside the window is never reported as holding.
//!   `--wait` polls the warm-up rows until none is starting, capped at
//!   [`WAIT_CAP_SECS`], and then judges everything once.
//!
//! Node rows. The controller never runs `docker inspect`
//! on a node, so a node row is judged from what the agent
//! reports on its heartbeat: `backend_containers`, per running backend
//! container `{running, started_at, health?}`. The same rule applies to
//! the `backend doors` row ([`judge_node_doors`]): only its "no leaf yet"
//! problems may be warm-up, only when every backend they name is reported
//! running, started inside the window, health `starting` (or none). An
//! agent that does not report `backend_containers`, or does not report the
//! backend in question, leaves the row exactly as it was.

use super::{Check, Verdict};
use crate::Globals;
use serde_json::Value;
use std::process::Command;

/// Loki answers `/ready` 1-2 min after start (2026-09-30 rehearsals);
/// three minutes is the most a readiness miss may be called warm-up.
pub(crate) const WARMUP_WINDOW_SECS: i64 = 180;
/// `--wait` never polls longer than the window plus one poll: past that no
/// row can still be `Starting` anyway.
pub(crate) const WAIT_CAP_SECS: i64 = LOKI_WARMUP_WINDOW_SECS + WAIT_POLL_SECS as i64;

/// Loki's own window. After a stack roll its ring takes longer than
/// [`WARMUP_WINDOW_SECS`] to join: the v0.2.84 rehearsal (2026-10-02)
/// started Loki at 15:07:38 and saw `/ready` answer at 15:11:42 — 244s —
/// with nothing but the startup `ratestore … empty ring` in its log. A
/// miss inside this window reads `starting (ring joining, …)`; past it,
/// the row FAILs with the gateway's `loki_ready_detail`.
pub(crate) const LOKI_WARMUP_WINDOW_SECS: i64 = 300;

/// The warm-up window for a row: Loki's own, else the shared one.
fn window_for(row: &str) -> i64 {
    if row == "loki" { LOKI_WARMUP_WINDOW_SECS } else { WARMUP_WINDOW_SECS }
}
const WAIT_POLL_SECS: u64 = 10;

/// The only rows whose failure may be explained by warm-up: `loki` (its
/// `/ready` miss, against `docker inspect <prefix>-loki`) and the node's
/// `backend doors` (its "no leaf yet" problems only, against the node's
/// `backend_containers` report). No other row, and no security fault on
/// these two, is ever softened (pinned by tests).
pub(crate) const WARMUP_ROWS: &[&str] = &["loki", "backend doors"];

/// The one `backend_tls` refusal warm-up may explain: the node's PKI dir
/// has no leaf for the door YET (node-agent-go `backendDoorCheck`, pinned
/// against its source by a test). A leaf that is there and does not name
/// its door, an unreadable one, a missing CA: never.
pub(crate) const NO_LEAF_YET_REFUSAL: &str = "PKI dir has no services/";

/// What `docker inspect` says about a container's life.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContainerState {
    pub running: bool,
    pub started_unix: i64,
    /// `.State.Health.Status`; `None` when the container declares no
    /// healthcheck (or disables it).
    pub health: Option<String>,
    /// `.RestartCount`: restarts docker's policy has made. 0 for a node
    /// report, which does not carry it.
    pub restart_count: i64,
    /// `.State.Restarting`: docker is between restarts right now.
    pub restarting: bool,
    /// `.State.ExitCode` of the last run.
    pub exit_code: i64,
}

const INSPECT_TEMPLATE: &str = "{{.State.Running}}|{{.State.StartedAt}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.RestartCount}}|{{.State.Restarting}}|{{.State.ExitCode}}";

/// Parse one line of [`INSPECT_TEMPLATE`] output.
pub(crate) fn parse_inspect(line: &str) -> Option<ContainerState> {
    let mut parts = line.trim().splitn(6, '|');
    let running = parts.next()? == "true";
    let started_unix = super::parse_rfc3339_unix(parts.next()?)?;
    let health = parts.next().map(str::trim).filter(|h| !h.is_empty()).map(str::to_string);
    // The trailing fields are absent in a short (older-shape) line: 0/false.
    let restart_count = parts.next().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    let restarting = parts.next().map(|v| v.trim() == "true").unwrap_or(false);
    let exit_code = parts.next().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    Some(ContainerState { running, started_unix, health, restart_count, restarting, exit_code })
}

/// What `docker inspect` gave back: a state, or why there is none. A
/// failure or an unparsable line is named, never swallowed — the `loki`
/// row prints it (v0.2.87 sandbox: a ✗ at ~255s that no branch could be
/// read off, because a `None` here said nothing about why).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Inspected {
    Ok(ContainerState),
    /// docker could not be run, or exited non-zero: its first stderr line.
    Failed(String),
    /// docker answered, but not in [`INSPECT_TEMPLATE`]'s shape: the raw line.
    Unparsed(String),
}

impl Inspected {
    pub(crate) fn state(&self) -> Option<&ContainerState> {
        match self {
            Inspected::Ok(st) => Some(st),
            _ => None,
        }
    }
    fn label(&self) -> String {
        match self {
            Inspected::Ok(_) => "ok".into(),
            Inspected::Failed(e) => format!("failed: {e}"),
            Inspected::Unparsed(raw) => format!("unparsed: {raw}"),
        }
    }
}

/// One line, bounded: what an inspect failure or raw answer prints as.
fn one_line(s: &str) -> String {
    let line = s.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string();
    if line.chars().count() > 160 { format!("{}…", line.chars().take(160).collect::<String>()) } else { line }
}

/// Classify one `docker inspect` run. Pure over its result, so every arm
/// is testable without docker.
pub(crate) fn read_inspect(ran: Result<(bool, String, String), String>) -> Inspected {
    match ran {
        Err(e) => Inspected::Failed(format!("could not run docker: {}", one_line(&e))),
        Ok((false, _, stderr)) => {
            let e = one_line(&stderr);
            Inspected::Failed(if e.is_empty() { "docker inspect exited non-zero, no stderr".into() } else { e })
        }
        Ok((true, stdout, _)) => match parse_inspect(&stdout) {
            Some(st) => Inspected::Ok(st),
            None => Inspected::Unparsed(format!("{:?}", one_line(&stdout))),
        },
    }
}

fn inspect(container: &str) -> Inspected {
    read_inspect(
        Command::new("docker")
            .args(["inspect", "-f", INSPECT_TEMPLATE, container])
            .output()
            .map(|o| (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned()))
            .map_err(|e| e.to_string()),
    )
}

/// What the `loki` row was judged on — printed on a FAIL or Starting row
/// as `[judged …]` and emitted as `warmup` on the row in `--json`, so the
/// branch that fired can be read off any report.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WarmupSeen {
    pub container: String,
    pub inspect: String,
    pub started_unix: Option<i64>,
    pub health: Option<String>,
    pub window_secs: i64,
    pub now_unix: i64,
}

impl WarmupSeen {
    fn new(container: &str, inspected: &Inspected, window_secs: i64, now_unix: i64) -> Self {
        let st = inspected.state();
        WarmupSeen {
            container: container.to_string(),
            inspect: inspected.label(),
            started_unix: st.map(|s| s.started_unix),
            health: st.and_then(|s| s.health.clone()),
            window_secs,
            now_unix,
        }
    }
    pub(crate) fn up_secs(&self) -> Option<i64> {
        self.started_unix.map(|t| (self.now_unix - t).max(0))
    }
    pub(crate) fn bracket(&self) -> String {
        let or_q = |v: Option<i64>| v.map(|n| n.to_string()).unwrap_or_else(|| "?".into());
        let health = match (&self.started_unix, &self.health) {
            (None, _) => "?",
            (Some(_), None) => "none",
            (Some(_), Some(h)) => h.as_str(),
        };
        format!("[judged {}: inspect {}, up {}s, health {health}, window {}s, now {}, started {}]",
            self.container, self.inspect, or_q(self.up_secs()), self.window_secs, self.now_unix, or_q(self.started_unix))
    }
    pub(crate) fn json(&self) -> Value {
        serde_json::json!({
            "container": self.container,
            "inspect": self.inspect,
            "up_secs": self.up_secs(),
            "health": self.health,
            "window_secs": self.window_secs,
            "now_unix": self.now_unix,
            "started_unix": self.started_unix,
        })
    }
}

/// [`judge`] for the `loki` row, then — on a FAIL or Starting verdict —
/// append what it was judged on. `inspected` is `None` only when the row
/// did not FAIL before judging (nothing to explain, nothing appended).
pub(crate) fn judge_loki(check: Check, readiness_miss: bool, container: &str, inspected: Option<&Inspected>, now_unix: i64) -> (Check, Option<WarmupSeen>) {
    let state = if readiness_miss { inspected.and_then(Inspected::state) } else { None };
    let judged = judge(check, readiness_miss, container, state, now_unix);
    if !matches!(judged.verdict, Verdict::Fail | Verdict::Starting) {
        return (judged, None);
    }
    let Some(inspected) = inspected else {
        return (judged, None);
    };
    let seen = WarmupSeen::new(container, inspected, window_for(judged.name), now_unix);
    let detail = format!("{} {}", judged.detail, seen.bracket());
    (Check { detail, ..judged }, Some(seen))
}

/// Judge a row that may be warming up. `readiness_miss` is the caller's
/// word that `check` failed ONLY because its subject did not answer yet;
/// any other failure, any row not in [`WARMUP_ROWS`], and any verdict but
/// FAIL passes through untouched.
pub(crate) fn judge(check: Check, readiness_miss: bool, container: &str, state: Option<&ContainerState>, now_unix: i64) -> Check {
    if check.verdict != Verdict::Fail || !readiness_miss || !WARMUP_ROWS.contains(&check.name) {
        return check;
    }
    let Some(st) = state else {
        // Not inspectable: nothing explains the miss. Say so, so a FAIL
        // inside the window is not mistaken for a judged one.
        return Check { detail: format!("{} — `docker inspect {container}` gave no state, so warm-up cannot explain it", check.detail), ..check };
    };
    let up = (now_unix - st.started_unix).max(0);
    let health = st.health.as_deref();
    let window = window_for(check.name);
    // A container docker keeps restarting never leaves warm-up by the clock
    // (every restart resets `started_unix`), so the clock cannot judge it:
    // Restarting now, or restarted at all inside the window, is a failure
    // that names the container (i58). Warm-up is for a first start only.
    if st.restarting || (st.restart_count > 0 && up < window) {
        return Check {
            verdict: Verdict::Fail,
            detail: format!("{} — {container} crash-looping ({} restarts; last exit {}) — noo stack logs {}",
                check.detail, st.restart_count, st.exit_code, check.name),
            remedy: None,
            ..check
        };
    }
    let warming = st.running && matches!(health, None | Some("starting"));
    if warming && up < window {
        let hs = health.map(|h| format!(", health={h}")).unwrap_or_default();
        let phase = if check.name == "loki" { "ring joining, " } else { "" };
        return Check {
            verdict: Verdict::Starting,
            detail: format!("starting ({phase}{up}s since start{hs}; {container} gets {window}s) — re-run in a minute, or `noo cluster verify --wait`"),
            remedy: None,
            ..check
        };
    }
    let why = if !st.running {
        format!("{container} is not running")
    } else if warming {
        format!("{container} has been up {}s, past the {window}s warm-up, and is still not ready{}",
            up, health.map(|h| format!(" (health={h})")).unwrap_or_default())
    } else {
        format!("{container} up {up}s, health={}", health.unwrap_or("?"))
    };
    Check { detail: format!("{} — {why}", check.detail), ..check }
}

/// One backend container's life as the node reports it on its heartbeat
/// (`backend_containers.<backend>`). `None` when the agent does not
/// report it, or reports it without a start time: nothing explains a miss.
pub(crate) fn node_container_state(n: &Value, backend: &str) -> Option<ContainerState> {
    let e = n.get("backend_containers")?.get(backend)?;
    Some(ContainerState {
        running: e["running"].as_bool()?,
        started_unix: e["started_at"].as_i64()?,
        health: e["health"].as_str().map(str::trim).filter(|h| !h.is_empty()).map(str::to_string),
        restart_count: 0,
        restarting: false,
        exit_code: 0,
    })
}

/// Judge the node's `backend doors` FAIL for warm-up. `warm` names the
/// backends behind its problems, and the caller has already ruled that
/// every problem is a "no leaf yet" one (any security fault returns the
/// FAIL before this). Softens to [`Verdict::Starting`] only when EVERY
/// such backend is reported running, started less than
/// [`WARMUP_WINDOW_SECS`] ago, health `starting` or none. Otherwise the
/// FAIL stands; past the window it also names the backend and its uptime.
pub(crate) fn judge_node_doors(check: Check, warm: &[String], n: &Value, now_unix: i64) -> Check {
    if check.verdict != Verdict::Fail || warm.is_empty() || !WARMUP_ROWS.contains(&check.name) {
        return check;
    }
    let mut backends: Vec<&str> = warm.iter().map(String::as_str).collect();
    backends.sort_unstable();
    backends.dedup();
    let mut starting = Vec::new();
    let mut why = Vec::new();
    for b in &backends {
        let Some(st) = node_container_state(n, b) else {
            return check; // not reported: nothing explains the miss
        };
        let up = (now_unix - st.started_unix).max(0);
        let health = st.health.as_deref();
        let hs = health.map(|h| format!(", health={h}")).unwrap_or_default();
        let warming = st.running && matches!(health, None | Some("starting"));
        if warming && up < WARMUP_WINDOW_SECS {
            starting.push(format!("{b} {up}s since start{hs}"));
        } else if !st.running {
            why.push(format!("the {b} container is not running"));
        } else if warming {
            why.push(format!("the {b} container has been up {up}s, past the {WARMUP_WINDOW_SECS}s warm-up{hs}"));
        } else {
            why.push(format!("the {b} container is up {up}s{hs}"));
        }
    }
    if why.is_empty() {
        let id = n["id"].as_str().unwrap_or("<node>");
        return Check {
            verdict: Verdict::Starting,
            detail: format!("starting ({}; a backend gets {WARMUP_WINDOW_SECS}s; not yet judged: {}) — re-run in a minute, or `noo cluster verify {id} --wait`",
                starting.join(", "), check.detail),
            remedy: None,
            ..check
        };
    }
    Check { detail: format!("{} — {}", check.detail, why.join("; ")), ..check }
}

/// `cluster verify <node>... --wait`: poll the node records until no
/// selected node's `backend doors` row is starting, or the cap. Prints one
/// line when the cap is hit (never in `--json`).
pub(crate) fn wait_for_node_warmup(g: &Globals, ids: &[String]) {
    let mut starting = || {
        let Some(body) = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10) else {
            return false; // unreachable: the caller reports it
        };
        let now = super::now_unix();
        body["nodes"].as_array().is_some_and(|ns| ns.iter()
            .filter(|n| ids.is_empty() || ids.iter().any(|w| n["id"].as_str() == Some(w.as_str())))
            .any(|n| super::backend_doors_row(n, now).verdict == Verdict::Starting))
    };
    let settled = wait_until_settled(&mut starting, WAIT_CAP_SECS, &super::now_unix, &mut |s| {
        std::thread::sleep(std::time::Duration::from_secs(s))
    });
    if !g.json && !settled {
        println!("{}", crate::ui::status_line(crate::ui::Glyph::Warn, &format!(
            "a node backend is still starting after {WAIT_CAP_SECS}s — judging now; a door stuck past its warm-up fails and names its backend")));
    }
}

/// The `loki` row's readiness miss: leaf present, the gateway configured
/// with a URL, and `/ready` not ready — whatever the gateway's
/// `loki_ready_detail` says (no answer, a timeout, 503, any 5xx). Exactly
/// the shape of the one `loki_check` failure that warm-up can explain
/// (pinned by a test). Never reads the detail text.
pub(crate) fn loki_readiness_miss(status: Option<&Value>, leaf_present: bool) -> bool {
    leaf_present
        && status.is_some_and(|s| s["loki_configured"].as_bool() == Some(true) && s["loki_ready"].as_bool() != Some(true))
}

fn loki_leaf_present() -> bool {
    crate::pki::pki_dir().join("services").join("loki").join("service.crt").is_file()
}

/// The `loki` row as `cluster verify` prints it: `loki_check`, judged for
/// warm-up against `docker inspect <prefix>-loki`.
pub(crate) fn loki_row(g: &Globals, now_unix: i64) -> Check {
    loki_row_seen(g, now_unix).0
}

/// [`loki_row`] plus what it was judged on (for `--json`'s `warmup`).
pub(crate) fn loki_row_seen(g: &Globals, now_unix: i64) -> (Check, Option<WarmupSeen>) {
    let leaf = loki_leaf_present();
    let status = crate::http::get_json_opt(g, "/api/logs/status", true, 10);
    let check = super::loki_check(status.as_ref(), leaf);
    let miss = loki_readiness_miss(status.as_ref(), leaf);
    let container = crate::envfile::container("loki");
    let inspected = if check.verdict == Verdict::Fail { Some(inspect(&container)) } else { None };
    judge_loki(check, miss, &container, inspected.as_ref(), now_unix)
}

/// Poll until `starting()` is false or `cap_secs` have passed on `clock`.
/// Returns whether it settled. Pure over the probe, the clock and the
/// sleeper, so the cap is testable without waiting.
pub(crate) fn wait_until_settled(
    starting: &mut dyn FnMut() -> bool,
    cap_secs: i64,
    clock: &dyn Fn() -> i64,
    sleep: &mut dyn FnMut(u64),
) -> bool {
    let t0 = clock();
    loop {
        if !starting() {
            return true;
        }
        if clock() - t0 >= cap_secs {
            return false;
        }
        sleep(WAIT_POLL_SECS);
    }
}

/// `cluster verify --wait`: hold the verdict until no warm-up row is
/// starting, or the cap. Prints one line either way (never in `--json`).
pub(crate) fn wait_for_warmup(g: &Globals) {
    let mut starting = || loki_row(g, super::now_unix()).verdict == Verdict::Starting;
    let settled = wait_until_settled(&mut starting, WAIT_CAP_SECS, &super::now_unix, &mut |s| {
        std::thread::sleep(std::time::Duration::from_secs(s))
    });
    if !g.json && !settled {
        println!("{}", crate::ui::status_line(crate::ui::Glyph::Warn, &format!(
            "still starting after {WAIT_CAP_SECS}s — judging now; a row stuck past its warm-up fails and names its container")));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_crash_looping_container_fails_where_a_first_start_only_warms_up() {
        // Real shape of `docker inspect -f INSPECT_TEMPLATE` for each case.
        let at = "2026-10-14T12:00:00Z";
        let t = super::super::parse_rfc3339_unix(at).unwrap();
        let judged = |line: &str, up: i64| {
            let st = parse_inspect(line).unwrap();
            judge(loki_fail(), true, "noo-loki", Some(&st), t + up)
        };
        // Restarting, RestartCount=10, 39s since the latest start: red.
        let c = judged(&format!("false|{at}||10|true|1"), 39);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("noo-loki crash-looping (10 restarts; last exit 1) — noo stack logs loki"), "{}", c.detail);
        // Between restarts it can read running=true with RestartCount>0: still red.
        let c = judged(&format!("true|{at}||3|false|137"), 39);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("(3 restarts; last exit 137)"), "{}", c.detail);
        // First start, never restarted: warm-up grace kept.
        let c = judged(&format!("true|{at}||0|false|0"), 39);
        assert_eq!(c.verdict, Verdict::Starting, "{}", c.detail);
        assert!(!c.detail.contains("crash-looping"), "{}", c.detail);
        // Healthy and ready: not touched at all.
        let ok = Check { verdict: Verdict::Ok, ..loki_fail() };
        let c = judge(ok, false, "noo-loki", Some(&parse_inspect(&format!("true|{at}|healthy|2|false|0")).unwrap()), t + 39);
        assert_eq!(c.verdict, Verdict::Ok);
    }

    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_790_000_000;

    fn loki_fail() -> Check {
        super::super::loki_check(Some(&json!({ "loki_configured": true, "loki_url": "https://noo-loki:3100", "loki_ready": false })), true)
    }
    fn state(up: i64, health: Option<&str>) -> ContainerState {
        ContainerState { running: true, started_unix: NOW - up, health: health.map(str::to_string), restart_count: 0, restarting: false, exit_code: 0 }
    }

    #[test]
    fn a_container_started_five_seconds_ago_reads_as_starting_not_fail() {
        let c = judge(loki_fail(), true, "noo-loki", Some(&state(5, Some("starting"))), NOW);
        assert_eq!(c.verdict, Verdict::Starting, "{}", c.detail);
        assert!(c.detail.contains("starting (ring joining, 5s since start"), "{}", c.detail);
        assert!(c.remedy.is_none(), "a warm-up carries no remedy: {:?}", c.remedy);
        // Loki declares no healthcheck: uptime alone explains it.
        let none = judge(loki_fail(), true, "noo-loki", Some(&state(40, None)), NOW);
        assert_eq!(none.verdict, Verdict::Starting, "{}", none.detail);
    }

    #[test]
    fn the_same_container_past_the_window_fails_and_names_itself() {
        let c = judge(loki_fail(), true, "noo-loki", Some(&state(LOKI_WARMUP_WINDOW_SECS, Some("starting"))), NOW);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("noo-loki has been up 300s, past the 300s warm-up"), "{}", c.detail);
        assert!(c.remedy.is_some());
        let late = judge(loki_fail(), true, "noo-loki", Some(&state(LOKI_WARMUP_WINDOW_SECS + 400, None)), NOW);
        assert_eq!(late.verdict, Verdict::Fail);
    }

    /// The v0.2.84 rehearsal: Loki's ring joined 244s after start, past the
    /// shared 180s. At 240s it is `starting (ring joining, …)` — still not
    /// OK, so the run still exits 1. At 320s it FAILs, carrying the
    /// gateway's own reason (`loki_ready_detail`).
    #[test]
    fn loki_gets_its_own_ring_join_window_then_fails_with_the_gateway_reason() {
        const { assert!(LOKI_WARMUP_WINDOW_SECS > WARMUP_WINDOW_SECS) };
        let c = judge(loki_fail(), true, "noo-loki", Some(&state(240, None)), NOW);
        assert_eq!(c.verdict, Verdict::Starting, "{}", c.detail);
        assert!(c.detail.starts_with("starting (ring joining, 240s since start"), "{}", c.detail);
        assert_ne!(c.verdict, Verdict::Ok);
        let named = super::super::loki_check(Some(&json!({ "loki_configured": true, "loki_url": "https://noo-loki:3100",
            "loki_ready": false, "loki_ready_detail": "answered 503: Ingester not ready: waiting for 15s after being ready" })), true);
        let f = judge(named, true, "noo-loki", Some(&state(320, None)), NOW);
        assert_eq!(f.verdict, Verdict::Fail, "{}", f.detail);
        assert!(f.detail.contains("/ready answered 503: Ingester not ready") && f.detail.contains("up 320s"), "{}", f.detail);
        // The other warm-up row keeps the shared window.
        assert_eq!(window_for("backend doors"), WARMUP_WINDOW_SECS);
    }

    #[test]
    fn inside_the_window_a_miss_with_no_warmup_explanation_still_fails() {
        for st in [
            state(5, Some("unhealthy")),
            state(5, Some("healthy")),
            ContainerState { running: false, started_unix: NOW - 5, health: None, restart_count: 0, restarting: false, exit_code: 0 },
        ] {
            let c = judge(loki_fail(), true, "noo-loki", Some(&st), NOW);
            assert_eq!(c.verdict, Verdict::Fail, "{st:?}: {}", c.detail);
            assert!(c.detail.contains("noo-loki"), "{}", c.detail);
        }
        // Not inspectable: nothing explains it.
        assert_eq!(judge(loki_fail(), true, "noo-loki", None, NOW).verdict, Verdict::Fail);
    }

    /// Operator rule: a TLS, secrets or auth row never softens, however
    /// fresh the container. Only the named warm-up rows, and only their
    /// readiness miss, may.
    #[test]
    fn a_security_row_is_never_softened() {
        let fresh = state(5, Some("starting"));
        // `backend doors` is a warm-up row for its "no leaf yet" problems
        // only; its security faults are pinned in cluster_verify.rs
        // (`backend_doors_security_faults_never_soften`).
        for name in ["postgres client cert", "loki listener", "sandbox listener", "backend listener", "nats tls", "secrets not in env", "shared secrets",
            "logs access", "pki key modes", "service keys", "posture"] {
            let row = Check { name, verdict: Verdict::Fail, detail: "wrong".into(), remedy: Some("fix".into()) };
            let c = judge(row.clone(), true, "noo-x", Some(&fresh), NOW);
            assert_eq!(c, row, "{name} was softened");
            assert!(!WARMUP_ROWS.contains(&name), "{name} must not be a warm-up row");
        }
        // The loki row's own configuration failures are not warm-up either.
        let no_leaf = super::super::loki_check(None, false);
        assert!(!loki_readiness_miss(None, false));
        assert_eq!(judge(no_leaf.clone(), false, "noo-loki", Some(&fresh), NOW), no_leaf);
        let unset = json!({ "loki_configured": false });
        let c = super::super::loki_check(Some(&unset), true);
        assert!(!loki_readiness_miss(Some(&unset), true));
        assert_eq!(judge(c.clone(), false, "noo-loki", Some(&fresh), NOW), c);
    }

    #[test]
    fn the_readiness_miss_is_exactly_the_ready_did_not_answer_failure() {
        let s = json!({ "loki_configured": true, "loki_url": "u", "loki_ready": false });
        assert!(loki_readiness_miss(Some(&s), true));
        assert!(loki_check_says_ready_missed(&super::super::loki_check(Some(&s), true)));
        let ready = json!({ "loki_configured": true, "loki_url": "u", "loki_ready": true });
        assert!(!loki_readiness_miss(Some(&ready), true));
        assert!(!loki_readiness_miss(None, true), "an unanswered status is a WARN, not a miss");
    }
    fn loki_check_says_ready_missed(c: &Check) -> bool {
        c.verdict == Verdict::Fail && c.detail.contains("/ready did not answer")
    }

    /// The `loki` row end to end, as `loki_row` builds it: gateway status →
    /// `loki_check` → `loki_readiness_miss` → `judge`.
    fn loki_judged(detail: Option<&str>, st: Option<&ContainerState>) -> Check {
        let mut s = json!({ "loki_configured": true, "loki_url": "https://noo-loki:3100", "loki_ready": false });
        if let Some(d) = detail {
            s["loki_ready_detail"] = json!(d);
        }
        let check = super::super::loki_check(Some(&s), true);
        judge(check, loki_readiness_miss(Some(&s), true), "noo-loki", st, NOW)
    }
    const INGESTER_503: &str = "answered 503: Ingester not ready: waiting for 15s after being ready";

    /// v0.2.87 rehearsal (and host8 after v0.2.86): ~4 min after start
    /// /ready answered 503 "Ingester not ready: waiting for 15s after being
    /// ready", and was ready at 5 min. Inside the window that is warm-up.
    #[test]
    fn a_503_inside_the_loki_window_reads_as_starting() {
        let c = loki_judged(Some(INGESTER_503), Some(&state(240, None)));
        assert_eq!(c.verdict, Verdict::Starting, "{}", c.detail);
        assert!(c.detail.starts_with("starting (ring joining, 240s since start"), "{}", c.detail);
        assert!(c.remedy.is_none());
    }

    /// Any not-ready answer, not one Loki wording: the judgement never
    /// matches the detail text.
    #[test]
    fn any_not_ready_answer_inside_the_window_reads_as_starting() {
        for d in [
            Some("answered 500"),
            Some("answered 502: bad gateway"),
            Some("answered 503"),
            Some("answered 504: upstream timed out"),
            Some("answered 599: something new Loki says one day"),
            Some("no answer: error sending request: operation timed out"),
            Some("no answer: tls handshake eof"),
            None,
        ] {
            let c = loki_judged(d, Some(&state(240, None)));
            assert_eq!(c.verdict, Verdict::Starting, "{d:?}: {}", c.detail);
        }
    }

    #[test]
    fn the_same_503_past_the_loki_window_fails_with_the_detail() {
        let c = loki_judged(Some(INGESTER_503), Some(&state(320, None)));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("/ready answered 503: Ingester not ready: waiting for 15s after being ready"), "{}", c.detail);
        assert!(c.detail.contains("noo-loki has been up 320s, past the 300s warm-up"), "{}", c.detail);
        assert!(c.remedy.is_some());
    }

    #[test]
    fn a_503_from_a_loki_not_running_or_not_inspectable_still_fails() {
        let stopped = ContainerState { running: false, started_unix: NOW - 240, health: None, restart_count: 0, restarting: false, exit_code: 0 };
        let c = loki_judged(Some(INGESTER_503), Some(&stopped));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("noo-loki is not running") && c.detail.contains("answered 503"), "{}", c.detail);
        let c = loki_judged(Some(INGESTER_503), None);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("docker inspect noo-loki") && c.detail.contains("answered 503"), "{}", c.detail);
    }

    /// v0.2.87 sandbox: a ✗ at ~255s whose branch could not be read off
    /// the row. A failed inspect now names the container and docker's error.
    #[test]
    fn a_failed_inspect_names_the_container_and_the_docker_error() {
        let s = json!({ "loki_configured": true, "loki_url": "u", "loki_ready": false, "loki_ready_detail": INGESTER_503 });
        let failed = read_inspect(Ok((false, String::new(), "Error: No such object: noo-galaxy-loki\nmore\n".into())));
        assert_eq!(failed, Inspected::Failed("Error: No such object: noo-galaxy-loki".into()));
        let (c, seen) = judge_loki(super::super::loki_check(Some(&s), true), loki_readiness_miss(Some(&s), true),
            "noo-galaxy-loki", Some(&failed), NOW);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("[judged noo-galaxy-loki: inspect failed: Error: No such object: noo-galaxy-loki, up ?s, health ?, window 300s"),
            "{}", c.detail);
        assert!(c.detail.contains("answered 503"), "{}", c.detail);
        let j = seen.unwrap().json();
        assert_eq!(j["container"], "noo-galaxy-loki");
        assert!(j["inspect"].as_str().unwrap().starts_with("failed: Error: No such object"));
        assert!(j["up_secs"].is_null() && j["started_unix"].is_null());
        // docker not runnable, and an answer in the wrong shape: named too.
        assert!(matches!(read_inspect(Err("No such file or directory (os error 2)".into())),
            Inspected::Failed(e) if e.contains("could not run docker: No such file")));
        assert!(matches!(read_inspect(Ok((true, "<no value>|bogus\n".into(), String::new()))),
            Inspected::Unparsed(r) if r.contains("<no value>|bogus")));
    }

    /// Starting and FAIL both carry what was judged; OK carries nothing.
    #[test]
    fn a_judged_loki_row_says_what_it_was_judged_on() {
        let s = json!({ "loki_configured": true, "loki_url": "u", "loki_ready": false, "loki_ready_detail": INGESTER_503 });
        let ok = read_inspect(Ok((true, "true|2026-09-30T12:00:05Z|\n".into(), String::new())));
        let started = ok.state().unwrap().started_unix;
        let (c, seen) = judge_loki(super::super::loki_check(Some(&s), true), true, "noo-loki", Some(&ok), started + 255);
        assert_eq!(c.verdict, Verdict::Starting, "{}", c.detail);
        assert!(c.detail.ends_with(&format!("[judged noo-loki: inspect ok, up 255s, health none, window 300s, now {}, started {started}]", started + 255)),
            "{}", c.detail);
        let j = seen.unwrap().json();
        assert_eq!(j["up_secs"], 255);
        assert!(j["health"].is_null());
        let (f, _) = judge_loki(super::super::loki_check(Some(&s), true), true, "noo-loki", Some(&ok), started + 320);
        assert_eq!(f.verdict, Verdict::Fail);
        assert!(f.detail.contains("[judged noo-loki: inspect ok, up 320s, health none, window 300s"), "{}", f.detail);
        let up = json!({ "loki_configured": true, "loki_url": "u", "loki_ready": true });
        let (o, none) = judge_loki(super::super::loki_check(Some(&up), true), false, "noo-loki", None, started);
        assert_eq!(o.verdict, Verdict::Ok);
        assert!(none.is_none() && !o.detail.contains("[judged"));
        // In --json the fields ride on the loki row as `warmup`.
        let seen = judge_loki(super::super::loki_check(Some(&s), true), true, "noo-loki", Some(&ok), started + 255).1;
        let mut cj = super::super::checks_json(&[c]);
        super::super::with_warmup_json(&mut cj, "loki", seen.as_ref());
        assert_eq!(cj[0]["warmup"]["window_secs"], 300);
        assert_eq!(cj[0]["warmup"]["inspect"], "ok");
    }

    #[test]
    fn wait_stops_at_the_cap() {
        let t = std::cell::Cell::new(NOW);
        let mut polls = 0;
        let mut starting = || { polls += 1; true };
        let settled = wait_until_settled(&mut starting, WAIT_CAP_SECS, &|| t.get(), &mut |s| t.set(t.get() + s as i64));
        assert!(!settled);
        assert!(t.get() - NOW >= WAIT_CAP_SECS && t.get() - NOW < WAIT_CAP_SECS + WAIT_POLL_SECS as i64, "waited {}s", t.get() - NOW);
        assert_eq!(polls as i64, WAIT_CAP_SECS / WAIT_POLL_SECS as i64 + 1);
    }

    #[test]
    fn wait_returns_as_soon_as_nothing_is_starting() {
        let t = std::cell::Cell::new(NOW);
        let mut left = 3;
        let mut starting = || { left -= 1; left > 0 };
        assert!(wait_until_settled(&mut starting, WAIT_CAP_SECS, &|| t.get(), &mut |s| t.set(t.get() + s as i64)));
        assert_eq!(t.get() - NOW, 2 * WAIT_POLL_SECS as i64);
    }

    #[test]
    fn a_starting_row_is_its_own_state_in_json() {
        let c = judge(loki_fail(), true, "noo-loki", Some(&state(5, None)), NOW);
        assert_eq!(super::super::checks_json(&[c])[0]["verdict"], "starting");
    }

    #[test]
    fn docker_inspect_lines_parse() {
        let s = parse_inspect("true|2026-09-30T12:00:05.123456789Z|starting\n").unwrap();
        assert!(s.running);
        assert_eq!(s.health.as_deref(), Some("starting"));
        let n = parse_inspect("true|2026-09-30T12:00:05.1Z|").unwrap();
        assert_eq!(n.health, None);
        assert_eq!(s.started_unix, n.started_unix);
        assert!(parse_inspect("garbage").is_none());
    }
}
