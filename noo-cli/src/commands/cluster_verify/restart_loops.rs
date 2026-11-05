// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The "restart loops" controller row, and the same judgement for
//! `noo upgrade --stack`'s post-roll gate.
//!
//! 2026-10-16, controller, 0.6.3 -> 0.6.4: `noo-redis` crash-looped once a
//! minute for three hours on a root-owned `appendonly.aof.manifest`. Every
//! point-in-time look (`noo upgrade`'s gate, `noo cluster verify
//! --controller`) caught it between restarts, read "Up", and passed; the
//! gateway booted with no Redis. A container docker keeps restarting is
//! judged by its `RestartCount` and how recently it started, never by its
//! state at one instant.
//!
//! The rule: a stack container (`<prefix>-*`) is restart-looping when it is
//! LIVE (running, or restarting now), has restarted more than
//! [`MAX_RESTARTS`] times, AND it is restarting now, or started within the
//! last [`RECENT_SECS`], or (the upgrade gate) started after the stack roll.
//! The upgrade gate counts only the restarts made DURING the roll: a
//! [`Baseline`] taken when the roll starts holds each container's Id and
//! RestartCount, so a lifetime count is never judged (pop-os 2026-11-05: two
//! containers the operator had `docker stop`ped, 117 lifetime restarts,
//! refused a clean roll). A container that is not live is judged by how it
//! ended ([`Ended`]): crashed during the roll refuses, stopped before it is
//! one line, exit 0 (a one-shot) is nothing.
//! The row names the container, its restart count and its last error line
//! (`docker logs --tail 50`, the last line matching fatal / permission
//! denied / error).
//!
//! Inspect shape and parsing are the warm-up module's
//! ([`warmup::INSPECT_TEMPLATE`], [`warmup::read_inspect`]) — one reader of
//! `docker inspect` for every crash-loop judgement (i58's loki rule, `noo
//! stack status`'s Restarting line, and this).

use super::warmup::{self, ContainerState, Inspected};
use super::{fail, ok, warn, Check};

pub(crate) const NAME: &str = "restart loops";
/// A container that started this recently with more than
/// [`MAX_RESTARTS`] restarts is looping now, not recovered long ago.
pub(crate) const RECENT_SECS: i64 = 600;
/// More than this many restarts is a loop (one or two can be a dependency
/// that was not up yet).
pub(crate) const MAX_RESTARTS: i64 = 2;
/// The upgrade gate re-looks while a container has restarted at all since
/// the roll but not yet past [`MAX_RESTARTS`], for at most this long.
pub(crate) const GATE_SETTLE_SECS: i64 = 60;
const GATE_POLL_SECS: u64 = 10;

/// `docker <args>` → `(success, stdout, stderr)`, or why it could not run.
/// Injected so every judgement is testable without docker.
pub(crate) type DockerRun<'a> = &'a dyn Fn(&[&str]) -> Result<(bool, String, String), String>;

pub(crate) fn real_docker(args: &[&str]) -> Result<(bool, String, String), String> {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .map(|o| (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned()))
        .map_err(|e| e.to_string())
}

/// One restart-looping container.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Looping {
    pub container: String,
    pub restarts: i64,
    /// The last log line that names a failure; `None` when none matched.
    pub last_error: Option<String>,
    /// `Some(code)`: not a loop but a crash, it exited `code` during the
    /// roll and stayed down (the upgrade gate only).
    pub crashed: Option<i64>,
}

impl Looping {
    /// `noo-redis is restart-looping (37 restarts): <last error>`, or
    /// `noo-x exited 1 during the roll: <last error>`.
    pub(crate) fn line(&self) -> String {
        let err = self.last_error.as_deref().unwrap_or("no fatal/error line in its last 50 log lines");
        match self.crashed {
            Some(code) => format!("{} exited {code} during the roll: {err}", self.container),
            None => format!("{} is restart-looping ({} restarts): {err}", self.container, self.restarts),
        }
    }
}

/// `docker inspect` fields only the upgrade gate reads (warm-up's shared
/// INSPECT_TEMPLATE is parsed by three other readers and stays as it is).
pub(crate) const GATE_TEMPLATE: &str = "{{.Id}}|{{.RestartCount}}|{{.State.FinishedAt}}|{{.State.OOMKilled}}";

/// One container as [`GATE_TEMPLATE`] reads it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GateFacts {
    pub id: String,
    pub restart_count: i64,
    /// `.State.FinishedAt`; docker's zero time (never finished) reads as far past.
    pub finished_unix: i64,
    pub oom_killed: bool,
}

pub(crate) fn parse_gate_facts(line: &str) -> Option<GateFacts> {
    let mut p = line.trim().splitn(4, '|');
    let id = p.next()?.trim().to_string();
    if id.is_empty() {
        return None;
    }
    let restart_count = p.next()?.trim().parse().ok()?;
    let finished_unix = p.next().and_then(|t| super::parse_rfc3339_unix(t.trim())).unwrap_or(i64::MIN);
    let oom_killed = p.next().map(|v| v.trim() == "true").unwrap_or(false);
    Some(GateFacts { id, restart_count, finished_unix, oom_killed })
}

fn gate_facts(docker: DockerRun, c: &str) -> Option<GateFacts> {
    match docker(&["inspect", "-f", GATE_TEMPLATE, c]) {
        Ok((true, out, _)) => parse_gate_facts(&out),
        _ => None,
    }
}

/// What the gate knew of each stack container when the roll started:
/// name -> (Id, RestartCount). Best-effort: a container it could not read is
/// absent, and is then judged by its count since it was created. The second
/// field is the launcher's own record of the containers it stopped on
/// purpose during the roll ([`IntendedStops`]), read once the launcher exits.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Baseline(pub(crate) std::collections::HashMap<String, (String, i64)>, pub(crate) IntendedStops);

/// The containers the launcher stopped ON PURPOSE during this roll: a
/// refused add-on's leftover (`addons_stop_refused`), trellion or the voice
/// services switched off. A crash-looping one is stopped with its last exit
/// code (1), so by its state alone it reads "exited 1 during the roll" and
/// refused a roll the launcher did right (harness 0.6.17 review, a1).
/// The CLI creates a fresh 0600 file per roll and hands its path to the
/// launcher as `NOO_LAUNCHER_STOPS`; the launcher appends `<id> <reason>`
/// before each such stop (lib-addons.sh `addons_note_intended_stop`).
/// Matched by container Id, never by name: a container recreated under the
/// same name is a different container. A file that cannot be read is an
/// empty set (the caller warns): every stop is then judged by its state,
/// never excused.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct IntendedStops(pub(crate) Vec<(String, String)>);

/// A recorded Id this short is never matched as a prefix (`docker ps -q`
/// prints 12 characters; anything shorter could match an unrelated Id).
const MIN_ID_PREFIX: usize = 12;

impl IntendedStops {
    /// One `<id> <reason>` per line; a blank line or one with no reason is
    /// skipped.
    pub(crate) fn parse(text: &str) -> Self {
        IntendedStops(text.lines().filter_map(|l| {
            let (id, why) = l.trim().split_once(' ')?;
            let why = why.trim();
            (!id.is_empty() && !why.is_empty()).then(|| (id.to_string(), why.to_string()))
        }).collect())
    }

    /// Why the launcher stopped the container with the full Id `id`, when it
    /// did: the recorded Id equals it, or is a prefix of it at least
    /// [`MIN_ID_PREFIX`] long.
    pub(crate) fn reason(&self, id: &str) -> Option<&str> {
        self.0.iter()
            .find(|(rec, _)| rec == id || (rec.len() >= MIN_ID_PREFIX && id.starts_with(rec.as_str())))
            .map(|(_, why)| why.as_str())
    }
}

/// The launcher's record at `path`, or why it could not be read.
pub(crate) fn read_intended(path: &std::path::Path) -> Result<IntendedStops, String> {
    std::fs::read_to_string(path)
        .map(|t| IntendedStops::parse(&t))
        .map_err(|e| format!("{}: {e}", path.display()))
}

impl Baseline {
    /// Restarts made since the baseline: the delta for the same container,
    /// the whole count for one the roll created (a new Id; compose's
    /// recreate starts the count at 0).
    pub(crate) fn since(&self, name: &str, now: &GateFacts) -> i64 {
        match self.0.get(name) {
            Some((id, before)) if *id == now.id => (now.restart_count - before).max(0),
            _ => now.restart_count,
        }
    }
}

/// The [`Baseline`] for this stack, taken when the roll starts.
pub(crate) fn snapshot(docker: DockerRun, prefix: &str) -> Baseline {
    let mut m = std::collections::HashMap::new();
    for c in stack_containers(docker, prefix).unwrap_or_default() {
        if let Some(f) = gate_facts(docker, &c) {
            m.insert(c, (f.id, f.restart_count));
        }
    }
    Baseline(m, IntendedStops::default())
}

/// How a container that is not live ended, judged against the roll's start.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Ended {
    /// Exit 0 (a one-shot that did its job): nothing to say.
    Clean,
    /// Stopped by someone (SIGTERM 143, or a stop's SIGKILL 137 that was not
    /// an OOM kill), or it ended before the roll: said, never a refusal.
    Stopped,
    /// Exited non-zero DURING the roll and stayed down: a broken stack.
    Crashed(i64),
}

pub(crate) fn ended(st: &ContainerState, facts: Option<&GateFacts>, since: i64) -> Ended {
    if st.exit_code == 0 {
        return Ended::Clean;
    }
    let during = facts.is_some_and(|f| f.finished_unix >= since);
    let stop_signal = st.exit_code == 143 || (st.exit_code == 137 && !facts.is_some_and(|f| f.oom_killed));
    if during && !stop_signal { Ended::Crashed(st.exit_code) } else { Ended::Stopped }
}

/// The loop rule, pure. `since` is the stack roll's start (the upgrade
/// gate); `None` for `cluster verify`.
pub(crate) fn is_looping(st: &ContainerState, now_unix: i64, since: Option<i64>) -> bool {
    (st.running || st.restarting)
        && st.restart_count > MAX_RESTARTS
        && (st.restarting
            || now_unix - st.started_unix < RECENT_SECS
            || since.is_some_and(|t| st.started_unix >= t))
}

/// Restarted at all since the roll, but not (yet) a loop: the gate looks
/// again rather than pass a container on its way to its third restart.
fn is_suspect(st: &ContainerState, since: i64) -> bool {
    st.restart_count > 0 && (st.restarting || st.started_unix >= since)
}

/// The last line of `logs` naming a failure (fatal, permission denied,
/// error — case-insensitive), trimmed and bounded.
pub(crate) fn last_error_line(logs: &str) -> Option<String> {
    let line = logs.lines().rev().map(str::trim).find(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("fatal") || l.contains("permission denied") || l.contains("error")
    })?;
    Some(if line.chars().count() > 200 { format!("{}…", line.chars().take(200).collect::<String>()) } else { line.to_string() })
}

/// Every container of this stack (`<prefix>-*`), running or not.
pub(crate) fn stack_containers(docker: DockerRun, prefix: &str) -> Result<Vec<String>, String> {
    let filter = format!("name={prefix}-"); // substring; the prefix is re-checked below
    match docker(&["ps", "-a", "--filter", filter.as_str(), "--format", "{{.Names}}"]) {
        Err(e) => Err(format!("could not run docker: {e}")),
        Ok((false, _, err)) => Err(err.lines().next().unwrap_or("docker ps exited non-zero").trim().to_string()),
        Ok((true, out, _)) => {
            let want = format!("{prefix}-");
            let mut v: Vec<String> = out.lines().map(str::trim).filter(|n| n.starts_with(&want)).map(str::to_string).collect();
            v.sort();
            Ok(v)
        }
    }
}

/// The compose service behind a container: `noo-redis` → `redis`.
pub(crate) fn service_of<'a>(container: &'a str, prefix: &str) -> &'a str {
    container.strip_prefix(prefix).and_then(|s| s.strip_prefix('-')).unwrap_or(container)
}

/// The last failure line of `c`'s log.
fn last_error_of(docker: DockerRun, c: &str) -> Option<String> {
    match docker(&["logs", "--tail", "50", c]) {
        Ok((_, out, err)) => last_error_line(&format!("{out}\n{err}")),
        Err(_) => None,
    }
}

/// One look: the looping (or, for the gate, crashed) containers, how many
/// more have restarted since `since` without (yet) being a loop, and one
/// line per container that is stopped and would once have been called a
/// loop. `gate` is the roll's start and [`Baseline`] (the upgrade gate);
/// `None` for `cluster verify`.
pub(crate) fn scan(docker: DockerRun, prefix: &str, now_unix: i64, gate: Option<(i64, &Baseline)>) -> Result<(Vec<Looping>, usize, Vec<String>), String> {
    let mut looping = Vec::new();
    let mut suspects = 0;
    let mut notes = Vec::new();
    let since = gate.map(|(t, _)| t);
    for c in stack_containers(docker, prefix)? {
        let inspected = warmup::read_inspect(docker(&["inspect", "-f", warmup::INSPECT_TEMPLATE, c.as_str()]));
        let Inspected::Ok(mut st) = inspected else { continue };
        let facts = gate.and_then(|_| gate_facts(docker, &c));
        if let (Some((_, base)), Some(f)) = (gate, facts.as_ref()) {
            // Only the restarts made during the roll count.
            st.restart_count = base.since(&c, f);
        }
        let live = st.running || st.restarting;
        if is_looping(&st, now_unix, since) {
            let last_error = last_error_of(docker, &c);
            looping.push(Looping { container: c, restarts: st.restart_count, last_error, crashed: None });
        } else if live {
            if since.is_some_and(|t| is_suspect(&st, t)) {
                suspects += 1;
            }
        } else if let Some(t) = since {
            match ended(&st, facts.as_ref(), t) {
                Ended::Clean => {}
                Ended::Crashed(code) => {
                    // The launcher stopped it on purpose: its last exit code
                    // is the loop's, not a crash of the roll.
                    let intended = gate.zip(facts.as_ref()).and_then(|((_, base), f)| base.1.reason(&f.id));
                    if let Some(why) = intended {
                        notes.push(format!("{c} was stopped by the launcher ({why}); its last exit was {code}, not a crash of the roll"));
                    } else {
                        let last_error = last_error_of(docker, &c);
                        looping.push(Looping { container: c, restarts: st.restart_count, last_error, crashed: Some(code) });
                    }
                }
                Ended::Stopped => notes.push(format!(
                    "{c} is stopped (exit {}), not looping; if nothing declares it, remove it: docker rm -f {c}",
                    st.exit_code)),
            }
        }
    }
    Ok((looping, suspects, notes))
}

/// The `restart loops` row from one [`scan`].
pub(crate) fn row(found: Result<Vec<Looping>, String>, prefix: &str) -> Check {
    match found {
        Err(e) => warn(NAME, format!("not judged — {e}"), None),
        Ok(v) if v.is_empty() => ok(NAME, format!("no {prefix}-* container has restarted more than {MAX_RESTARTS} times in the last {}m", RECENT_SECS / 60)),
        Ok(v) => {
            let detail = v.iter().map(Looping::line).collect::<Vec<_>>().join("; ");
            let remedy = format!("noo stack logs {}", service_of(&v[0].container, prefix));
            fail(NAME, detail, remedy)
        }
    }
}

/// `noo cluster verify --controller`'s row.
pub(crate) fn restart_loops_row() -> Check {
    let prefix = crate::envfile::container_prefix();
    row(scan(&real_docker, &prefix, super::now_unix(), None).map(|(v, _, _)| v), &prefix)
}

/// `noo upgrade --stack`'s post-roll gate: the looping containers, judged
/// against the roll's start. Looks again every [`GATE_POLL_SECS`] while a
/// container has restarted since the roll but not past [`MAX_RESTARTS`],
/// for at most [`GATE_SETTLE_SECS`]. `Err` only when docker could not list
/// the stack (the caller warns; it does not block on that).
pub(crate) fn gate_loops(
    docker: DockerRun,
    prefix: &str,
    since: i64,
    baseline: &Baseline,
    clock: &dyn Fn() -> i64,
    sleep: &mut dyn FnMut(u64),
) -> Result<(Vec<Looping>, Vec<String>), String> {
    let start = clock();
    loop {
        let (looping, suspects, notes) = scan(docker, prefix, clock(), Some((since, baseline)))?;
        if !looping.is_empty() || suspects == 0 || clock() - start >= GATE_SETTLE_SECS {
            return Ok((looping, notes));
        }
        sleep(GATE_POLL_SECS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;
    use std::cell::Cell;
    use std::collections::HashMap;

    const NOW: i64 = 1_792_000_000;

    /// `docker` as a table: `ps` → names; `inspect … <c>` → that line;
    /// `logs … <c>` → that stderr.
    fn fake<'a>(inspect: &'a HashMap<&'a str, String>, logs: &'a HashMap<&'a str, &'a str>) -> impl Fn(&[&str]) -> Result<(bool, String, String), String> + 'a {
        move |args: &[&str]| {
            let c = *args.last().unwrap();
            match args[0] {
                "ps" => {
                    assert_eq!(args[..4], ["ps", "-a", "--filter", "name=noo-"]);
                    let mut names: Vec<&str> = inspect.keys().copied().collect();
                    names.push("other-redis"); // another stack's container: never judged
                    Ok((true, names.join("\n"), String::new()))
                }
                "inspect" if args[2] == GATE_TEMPLATE => {
                    // Id `id-<c>`, its restart count, never finished, no OOM.
                    let l = inspect.get(c).ok_or_else(|| format!("no such container {c}"))?;
                    let restarts = l.split('|').nth(3).unwrap_or("0");
                    Ok((true, format!("id-{c}|{restarts}|0001-01-01T00:00:00Z|false"), String::new()))
                }
                "inspect" => {
                    assert_eq!(args[2], warmup::INSPECT_TEMPLATE);
                    inspect.get(c).map(|l| (true, l.clone(), String::new())).ok_or_else(|| format!("no such container {c}"))
                }
                "logs" => {
                    assert_eq!(args[..3], ["logs", "--tail", "50"]);
                    Ok((true, String::new(), logs.get(c).copied().unwrap_or("").to_string()))
                }
                other => panic!("unexpected docker {other}"),
            }
        }
    }

    /// running|startedAt|health|restarts|restarting|exit
    fn state(running: bool, started: i64, restarts: i64, restarting: bool) -> String {
        state_exit(running, started, restarts, restarting, 1)
    }

    fn rfc3339(t: i64) -> String {
        let secs = t - 1_791_936_000; // 2026-10-14T00:00:00Z
        let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
        format!("2026-10-14T{h:02}:{m:02}:{s:02}.123456789Z")
    }

    fn state_exit(running: bool, started: i64, restarts: i64, restarting: bool, exit: i64) -> String {
        format!("{running}|{}||{restarts}|{restarting}|{exit}", rfc3339(started))
    }

    const AOF: &str = "1:C 16 Oct 2026 03:01:02.000 # Fatal error: can't open the AOF manifest file appendonlydir/appendonly.aof.manifest for reading: Permission denied";

    #[test]
    fn the_state_helper_round_trips_through_the_shared_parser() {
        let st = warmup::parse_inspect(&state(true, NOW - 30, 5, false)).unwrap();
        assert_eq!((st.started_unix, st.restart_count, st.running), (NOW - 30, 5, true));
    }

    #[test]
    fn a_redis_caught_between_restarts_is_a_loop_naming_its_last_error() {
        // "Up 20 seconds" at the instant of the look — the 2026-10-16 miss.
        let inspect = HashMap::from([
            ("noo-redis", state(true, NOW - 20, 187, false)),
            ("noo-gateway", state(true, NOW - 3000, 0, false)),
        ]);
        // An earlier error line, then the fatal one, then a non-matching tail.
        let full = format!("1:C boot\nsome error earlier\n{AOF}\n1:C bye");
        let logs = HashMap::from([("noo-redis", full.as_str())]);
        let (v, _, _) = scan(&fake(&inspect, &logs), "noo", NOW, None).unwrap();
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].container, "noo-redis");
        assert_eq!(v[0].restarts, 187);
        assert_eq!(v[0].last_error.as_deref(), Some(AOF));
        let c = row(Ok(v), "noo");
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("noo-redis is restart-looping (187 restarts): ") && c.detail.contains("Permission denied"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo stack logs redis"));
    }

    #[test]
    fn restarting_now_counts_however_long_ago_it_started() {
        let inspect = HashMap::from([("noo-loki", state(false, NOW - 5000, 9, true))]);
        let logs = HashMap::new();
        let (v, _, _) = scan(&fake(&inspect, &logs), "noo", NOW, None).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].last_error, None);
        assert!(v[0].line().contains("no fatal/error line"));
    }

    #[test]
    fn old_restarts_and_few_restarts_are_not_loops() {
        let inspect = HashMap::from([
            // recovered long ago: many restarts, stable for over 10 min
            ("noo-prometheus", state(true, NOW - RECENT_SECS - 1, 12, false)),
            // two restarts (a dependency not up yet), just now
            ("noo-gateway", state(true, NOW - 10, MAX_RESTARTS, false)),
        ]);
        let logs = HashMap::new();
        let (v, _, _) = scan(&fake(&inspect, &logs), "noo", NOW, None).unwrap();
        assert!(v.is_empty(), "{v:?}");
        let c = row(Ok(v), "noo");
        assert_eq!(c.verdict, Verdict::Ok);
    }

    #[test]
    fn a_start_after_the_roll_is_a_loop_even_past_ten_minutes() {
        let st = warmup::parse_inspect(&state(true, NOW - 2000, 3, false)).unwrap();
        assert!(!is_looping(&st, NOW, None));
        assert!(is_looping(&st, NOW, Some(NOW - 2500)));
        assert!(!is_looping(&st, NOW, Some(NOW - 1000)));
    }

    #[test]
    fn docker_unlistable_is_a_warning_not_a_pass() {
        let docker = |_: &[&str]| -> Result<(bool, String, String), String> { Err("No such file or directory".into()) };
        let c = row(scan(&docker, "noo", NOW, None).map(|(v, _, _)| v), "noo");
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("could not run docker"), "{}", c.detail);
    }

    #[test]
    fn last_error_line_takes_the_last_match_case_insensitive() {
        assert_eq!(last_error_line("ok\nERROR one\nfine\nFATAL two\nbye"), Some("FATAL two".into()));
        assert_eq!(last_error_line("ok\nfine"), None);
    }

    #[test]
    fn the_gate_waits_out_a_container_on_its_way_to_a_loop() {
        // First look: redis restarted once since the roll (suspect, not a
        // loop yet). Second look, 10s later: 4 restarts — a loop.
        let since = NOW - 30;
        let looks = Cell::new(0);
        let logs: HashMap<&str, &str> = HashMap::from([("noo-redis", AOF)]);
        let one = HashMap::from([("noo-redis", String::new())]);
        let rest = fake(&one, &logs); // ps + logs; inspect is answered here
        let docker = |args: &[&str]| -> Result<(bool, String, String), String> {
            if args[0] == "inspect" {
                looks.set(looks.get() + 1);
                let n = if looks.get() == 1 { 1 } else { 4 };
                return Ok((true, state(true, NOW - 2, n, false), String::new()));
            }
            rest(args)
        };
        let clock = Cell::new(NOW);
        let mut slept = Vec::new();
        let (v, _) = gate_loops(&docker, "noo", since, &Baseline::default(), &|| clock.get(), &mut |s| {
            slept.push(s);
            clock.set(clock.get() + s as i64);
        })
        .unwrap();
        assert_eq!(slept, vec![GATE_POLL_SECS]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line(), format!("noo-redis is restart-looping (4 restarts): {AOF}"));
    }

    #[test]
    fn the_gate_passes_a_clean_roll_without_waiting_and_caps_a_slow_one() {
        let inspect = HashMap::from([("noo-redis", state(true, NOW - 20, 0, false))]);
        let logs = HashMap::new();
        let mut slept = 0;
        let (v, _) = gate_loops(&fake(&inspect, &logs), "noo", NOW - 40, &Baseline::default(), &|| NOW, &mut |_| slept += 1).unwrap();
        assert!(v.is_empty());
        assert_eq!(slept, 0);
        // A container that restarted once and stays there: looked at until
        // the cap, then passed.
        let inspect = HashMap::from([("noo-redis", state(true, NOW - 20, 1, false))]);
        let clock = Cell::new(NOW);
        let (v, _) = gate_loops(&fake(&inspect, &logs), "noo", NOW - 40, &Baseline::default(), &|| clock.get(), &mut |s| clock.set(clock.get() + s as i64)).unwrap();
        assert!(v.is_empty());
        assert!(clock.get() - NOW >= GATE_SETTLE_SECS && clock.get() - NOW < GATE_SETTLE_SECS + GATE_POLL_SECS as i64 + 1);
    }

    #[test]
    fn service_of_strips_the_prefix() {
        assert_eq!(service_of("noo-redis", "noo"), "redis");
        assert_eq!(service_of("lab-grafana", "lab"), "grafana");
        assert_eq!(service_of("weird", "noo"), "weird");
    }

    /// A fake whose GATE_TEMPLATE answers come from `facts` (Id, count,
    /// FinishedAt, OOMKilled) for the containers it names.
    fn fake_facts<'a>(inspect: &'a HashMap<&'a str, String>, facts: &'a HashMap<&'a str, String>, logs: &'a HashMap<&'a str, &'a str>)
        -> impl Fn(&[&str]) -> Result<(bool, String, String), String> + 'a {
        let base = fake(inspect, logs);
        move |args: &[&str]| {
            if args[0] == "inspect" && args[2] == GATE_TEMPLATE {
                if let Some(f) = facts.get(*args.last().unwrap()) {
                    return Ok((true, f.clone(), String::new()));
                }
            }
            base(args)
        }
    }

    fn baseline(rows: &[(&str, &str, i64)]) -> Baseline {
        Baseline(rows.iter().map(|(n, id, c)| (n.to_string(), (id.to_string(), *c))).collect(), IntendedStops::default())
    }

    fn no_sleep() -> impl FnMut(u64) {
        |_| {}
    }

    /// pop-os 2026-11-05: the operator `docker stop`ped two looping
    /// containers BEFORE the roll; Exited, 117 lifetime restarts, last start
    /// minutes old. The gate passed nothing and refused the roll. Now: not a
    /// loop, one line, no refusal.
    #[test]
    fn a_container_stopped_before_the_roll_is_a_line_not_a_refusal() {
        let since = NOW - 300;
        let inspect = HashMap::from([("noo-voice", state_exit(false, NOW - 400, 117, false, 143))]);
        let facts = HashMap::from([("noo-voice", format!("id-v|117|{}|false", rfc3339(NOW - 350)))]);
        let logs = HashMap::new();
        let (v, notes) = gate_loops(&fake_facts(&inspect, &facts, &logs), "noo", since,
            &baseline(&[("noo-voice", "id-v", 117)]), &|| NOW, &mut no_sleep()).unwrap();
        assert!(v.is_empty(), "{v:?}");
        assert_eq!(notes, vec!["noo-voice is stopped (exit 143), not looping; if nothing declares it, remove it: docker rm -f noo-voice".to_string()]);
        // cluster verify agrees: a stopped container is not looping now.
        let (v, _, _) = scan(&fake_facts(&inspect, &facts, &logs), "noo", NOW, None).unwrap();
        assert!(v.is_empty(), "{v:?}");
    }

    /// A running container with a high LIFETIME count that has not restarted
    /// during the roll is not looping: only the delta from the baseline counts.
    #[test]
    fn only_restarts_during_the_roll_count() {
        let since = NOW - 300;
        let inspect = HashMap::from([("noo-ollama", state(true, NOW - 200, 117, false))]);
        let facts = HashMap::from([("noo-ollama", format!("id-o|117|{}|false", rfc3339(NOW - 201)))]);
        let logs = HashMap::new();
        let (v, _) = gate_loops(&fake_facts(&inspect, &facts, &logs), "noo", since,
            &baseline(&[("noo-ollama", "id-o", 117)]), &|| NOW, &mut no_sleep()).unwrap();
        assert!(v.is_empty(), "{v:?}");
        // The same container, restarted 3 times during the roll: a loop.
        let inspect = HashMap::from([("noo-ollama", state(true, NOW - 20, 120, false))]);
        let facts = HashMap::from([("noo-ollama", format!("id-o|120|{}|false", rfc3339(NOW - 21)))]);
        let (v, _) = gate_loops(&fake_facts(&inspect, &facts, &logs), "noo", since,
            &baseline(&[("noo-ollama", "id-o", 117)]), &|| NOW, &mut no_sleep()).unwrap();
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].restarts, 3, "the delta, not the lifetime count");
        // Recreated by the roll (a new Id): its whole count is since the roll.
        let facts = HashMap::from([("noo-ollama", format!("id-new|4|{}|false", rfc3339(NOW - 21)))]);
        let inspect = HashMap::from([("noo-ollama", state(true, NOW - 20, 4, false))]);
        let (v, _) = gate_loops(&fake_facts(&inspect, &facts, &logs), "noo", since,
            &baseline(&[("noo-ollama", "id-o", 117)]), &|| NOW, &mut no_sleep()).unwrap();
        assert_eq!(v.first().map(|l| l.restarts), Some(4), "{v:?}");
    }

    /// A container that crashed DURING the roll and stayed down (restart
    /// policy no, or on-failure past its retries) is a broken stack: refused,
    /// with its exit code and last log line. Exit 0 (a one-shot) is nothing.
    #[test]
    fn a_crash_during_the_roll_refuses_and_a_one_shot_does_not() {
        let since = NOW - 300;
        let inspect = HashMap::from([
            ("noo-worker", state_exit(false, NOW - 120, 0, false, 1)),
            ("noo-evolve-routes", state_exit(false, NOW - 150, 0, false, 0)),
        ]);
        let facts = HashMap::from([
            ("noo-worker", format!("id-w|0|{}|false", rfc3339(NOW - 100))),
            ("noo-evolve-routes", format!("id-r|0|{}|false", rfc3339(NOW - 140))),
        ]);
        let logs = HashMap::from([("noo-worker", "boot\nFATAL: cannot connect to the bus")]);
        let (v, notes) = gate_loops(&fake_facts(&inspect, &facts, &logs), "noo", since,
            &Baseline::default(), &|| NOW, &mut no_sleep()).unwrap();
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].line(), "noo-worker exited 1 during the roll: FATAL: cannot connect to the bus");
        assert!(notes.is_empty(), "the one-shot's exit 0 says nothing: {notes:?}");
        // An OOM kill during the roll is a crash; a stop's SIGKILL is not.
        let inspect = HashMap::from([("noo-worker", state_exit(false, NOW - 120, 0, false, 137))]);
        let oom = HashMap::from([("noo-worker", format!("id-w|0|{}|true", rfc3339(NOW - 100)))]);
        let (v, _) = gate_loops(&fake_facts(&inspect, &oom, &logs), "noo", since, &Baseline::default(), &|| NOW, &mut no_sleep()).unwrap();
        assert_eq!(v.first().and_then(|l| l.crashed), Some(137), "{v:?}");
        let stop = HashMap::from([("noo-worker", format!("id-w|0|{}|false", rfc3339(NOW - 100)))]);
        let (v, notes) = gate_loops(&fake_facts(&inspect, &stop, &logs), "noo", since, &Baseline::default(), &|| NOW, &mut no_sleep()).unwrap();
        assert!(v.is_empty() && notes.len() == 1, "{v:?} {notes:?}");
    }

    /// The 2026-10-16 redis, live and looping during the roll, is still caught.
    #[test]
    fn the_redis_loop_during_the_roll_is_still_caught() {
        let since = NOW - 300;
        let inspect = HashMap::from([("noo-redis", state(false, NOW - 5, 4, true))]);
        let facts = HashMap::from([("noo-redis", format!("id-r|4|{}|false", rfc3339(NOW - 6)))]);
        let logs = HashMap::from([("noo-redis", AOF)]);
        let (v, _) = gate_loops(&fake_facts(&inspect, &facts, &logs), "noo", since,
            &baseline(&[("noo-redis", "id-r", 0)]), &|| NOW, &mut no_sleep()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line(), format!("noo-redis is restart-looping (4 restarts): {AOF}"));
    }

    /// harness 0.6.17 review a1: a crash-looping add-on container the
    /// launcher stops on purpose (refused this start) keeps its last exit
    /// code, 1, and finished during the roll. Recorded by the launcher, it is
    /// a line; the same container NOT recorded is still a crash. Matched by
    /// Id: a recorded short Id matches its full Id, another Id does not.
    #[test]
    fn a_container_the_launcher_stopped_on_purpose_is_a_line_not_a_crash() {
        let since = NOW - 300;
        let full = "a1b2c3d4e5f6a7b8c9d0";
        let inspect = HashMap::from([("noo-rhold", state_exit(false, NOW - 120, 0, false, 1))]);
        let facts = HashMap::from([("noo-rhold", format!("{full}|0|{}|false", rfc3339(NOW - 100)))]);
        let logs = HashMap::from([("noo-rhold", "FATAL: no key")]);
        let mut base = baseline(&[("noo-rhold", full, 0)]);
        base.1 = IntendedStops::parse("a1b2c3d4e5f6 add-on rhold was refused this start\n");
        let (v, notes) = gate_loops(&fake_facts(&inspect, &facts, &logs), "noo", since, &base, &|| NOW, &mut no_sleep()).unwrap();
        assert!(v.is_empty(), "{v:?}");
        assert_eq!(notes, vec!["noo-rhold was stopped by the launcher (add-on rhold was refused this start); \
            its last exit was 1, not a crash of the roll".to_string()]);
        // Not recorded, or recorded under another Id: the crash refuses, as before.
        for rec in ["", "ffffffffffff add-on rhold was refused this start", "a1b2 add-on rhold was refused this start"] {
            base.1 = IntendedStops::parse(rec);
            let (v, _) = gate_loops(&fake_facts(&inspect, &facts, &logs), "noo", since, &base, &|| NOW, &mut no_sleep()).unwrap();
            assert_eq!(v.first().and_then(|l| l.crashed), Some(1), "{rec:?}: {v:?}");
        }
    }

    #[test]
    fn the_launchers_record_is_read_by_line_and_a_missing_one_is_an_error() {
        let s = IntendedStops::parse("abc123def456 trellion is off\n\nbad\nfeed00000000   voice is off  \n");
        assert_eq!(s.0, vec![("abc123def456".to_string(), "trellion is off".to_string()),
                             ("feed00000000".to_string(), "voice is off".to_string())]);
        assert_eq!(s.reason("abc123def456ffff"), Some("trellion is off"));
        assert_eq!(s.reason("abc123"), None, "a shorter Id never matches a longer record");
        let dir = std::env::temp_dir().join(format!("noo-intended-stops-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_intended(&dir.join("missing")).is_err());
        std::fs::write(dir.join("stops"), "abc123def456 trellion is off\n").unwrap();
        let read = read_intended(&dir.join("stops"));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read.unwrap().0, s.0[..1].to_vec());
    }
}
