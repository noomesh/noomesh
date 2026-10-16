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
//! The rule: a stack container (`<prefix>-*`) is restart-looping when
//! `RestartCount > 2` AND it is restarting now, or started within the last
//! [`RECENT_SECS`], or (the upgrade gate) started after the stack roll.
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
}

impl Looping {
    /// `noo-redis is restart-looping (37 restarts): <last error>`
    pub(crate) fn line(&self) -> String {
        let err = self.last_error.as_deref().unwrap_or("no fatal/error line in its last 50 log lines");
        format!("{} is restart-looping ({} restarts): {err}", self.container, self.restarts)
    }
}

/// The loop rule, pure. `since` is the stack roll's start (the upgrade
/// gate); `None` for `cluster verify`.
pub(crate) fn is_looping(st: &ContainerState, now_unix: i64, since: Option<i64>) -> bool {
    st.restart_count > MAX_RESTARTS
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

/// One look: the looping containers, and how many more have restarted
/// since `since` without (yet) being a loop.
pub(crate) fn scan(docker: DockerRun, prefix: &str, now_unix: i64, since: Option<i64>) -> Result<(Vec<Looping>, usize), String> {
    let mut looping = Vec::new();
    let mut suspects = 0;
    for c in stack_containers(docker, prefix)? {
        let inspected = warmup::read_inspect(docker(&["inspect", "-f", warmup::INSPECT_TEMPLATE, c.as_str()]));
        let Inspected::Ok(st) = inspected else { continue };
        if is_looping(&st, now_unix, since) {
            let last_error = match docker(&["logs", "--tail", "50", c.as_str()]) {
                Ok((_, out, err)) => last_error_line(&format!("{out}\n{err}")),
                Err(_) => None,
            };
            looping.push(Looping { container: c, restarts: st.restart_count, last_error });
        } else if since.is_some_and(|t| is_suspect(&st, t)) {
            suspects += 1;
        }
    }
    Ok((looping, suspects))
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
    row(scan(&real_docker, &prefix, super::now_unix(), None).map(|(v, _)| v), &prefix)
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
    clock: &dyn Fn() -> i64,
    sleep: &mut dyn FnMut(u64),
) -> Result<Vec<Looping>, String> {
    let start = clock();
    loop {
        let (looping, suspects) = scan(docker, prefix, clock(), Some(since))?;
        if !looping.is_empty() || suspects == 0 || clock() - start >= GATE_SETTLE_SECS {
            return Ok(looping);
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
        let secs = started - 1_791_936_000; // 2026-10-14T00:00:00Z
        let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
        format!("{running}|2026-10-14T{h:02}:{m:02}:{s:02}.123456789Z||{restarts}|{restarting}|1")
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
        let (v, _) = scan(&fake(&inspect, &logs), "noo", NOW, None).unwrap();
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
        let (v, _) = scan(&fake(&inspect, &logs), "noo", NOW, None).unwrap();
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
        let (v, _) = scan(&fake(&inspect, &logs), "noo", NOW, None).unwrap();
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
        let c = row(scan(&docker, "noo", NOW, None).map(|(v, _)| v), "noo");
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
        let docker = |args: &[&str]| -> Result<(bool, String, String), String> {
            if args[0] == "inspect" {
                looks.set(looks.get() + 1);
                let n = if looks.get() == 1 { 1 } else { 4 };
                return Ok((true, state(true, NOW - 2, n, false), String::new()));
            }
            let one = HashMap::from([("noo-redis", String::new())]);
            fake(&one, &logs)(args)
        };
        let clock = Cell::new(NOW);
        let mut slept = Vec::new();
        let v = gate_loops(&docker, "noo", since, &|| clock.get(), &mut |s| {
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
        let v = gate_loops(&fake(&inspect, &logs), "noo", NOW - 40, &|| NOW, &mut |_| slept += 1).unwrap();
        assert!(v.is_empty());
        assert_eq!(slept, 0);
        // A container that restarted once and stays there: looked at until
        // the cap, then passed.
        let inspect = HashMap::from([("noo-redis", state(true, NOW - 20, 1, false))]);
        let clock = Cell::new(NOW);
        let v = gate_loops(&fake(&inspect, &logs), "noo", NOW - 40, &|| clock.get(), &mut |s| clock.set(clock.get() + s as i64)).unwrap();
        assert!(v.is_empty());
        assert!(clock.get() - NOW >= GATE_SETTLE_SECS && clock.get() - NOW < GATE_SETTLE_SECS + GATE_POLL_SECS as i64 + 1);
    }

    #[test]
    fn service_of_strips_the_prefix() {
        assert_eq!(service_of("noo-redis", "noo"), "redis");
        assert_eq!(service_of("lab-grafana", "lab"), "grafana");
        assert_eq!(service_of("weird", "noo"), "weird");
    }
}
