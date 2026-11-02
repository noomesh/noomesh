// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The gateway's open file descriptors, against its `RLIMIT_NOFILE`.
//!
//! On 2026-11-02 the pop-os gateway (0.6.15, up ~45 h) reached its soft
//! limit of 1024 and logged 51,760 `Too many open files (os error 24)`
//! lines in five hours. It could not read `/run/secrets/*` or reach
//! Postgres, `/health` went red, and external chat answered 401 until an
//! operator restarted the container. Nothing had said the count was
//! climbing. The image has no shell, `/proc/<pid>/fd` is root's, and
//! `/metrics` exported no fd gauge, so the first sign was the outage.
//!
//! This module is the early warning, not the fix for whatever leaks.
//! - `/metrics` carries `process_open_fds` and `process_max_fds` (the
//!   standard names), so Prometheus keeps the history and a slope is
//!   visible days before the limit.
//! - `/health` (authenticated body) carries `dependencies.fds`, which
//!   `noo cluster verify` reads as the `gateway fds` row.
//! - A loop reads the count every [`INTERVAL_SECS`]. At [`WARN_PCT`] of the
//!   soft limit it logs WARN and alerts the operator; at [`CRIT_PCT`], or
//!   when the count cannot be read at all, it logs ERROR and alerts again.
//!   Both fire while the gateway can still reach the alert channel. At the
//!   limit itself it could not.
//!
//! Old code: no fd count anywhere; EMFILE was the first symptom.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::state::AppState;

/// Share of the soft limit that logs WARN and alerts once.
pub const WARN_PCT: u64 = 70;
/// Share of the soft limit that logs ERROR, alerts and marks `/health`
/// degraded (the status word only; the code stays with db and nats).
pub const CRIT_PCT: u64 = 90;
/// How often the loop reads the count. At the 2026-11-02 leak rate
/// (~22 fds an hour) 70% → 100% of 1024 is ~14 h, so 30 s loses nothing.
pub const INTERVAL_SECS: u64 = 30;
/// While critical, the ERROR line repeats this often, so a log reader
/// who arrives late still finds it.
const CRIT_REPEAT_SECS: u64 = 600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdUse {
    pub open: u64,
    pub soft: u64,
    pub hard: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Critical,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Critical => "critical",
        }
    }
}

impl FdUse {
    /// Percent of the soft limit in use, `None` when there is no finite
    /// soft limit to measure against.
    pub fn pct(&self) -> Option<u64> {
        if self.soft == 0 || self.soft == u64::MAX {
            return None;
        }
        Some(self.open.saturating_mul(100) / self.soft)
    }

    pub fn level(&self) -> Level {
        match self.pct() {
            Some(p) if p >= CRIT_PCT => Level::Critical,
            Some(p) if p >= WARN_PCT => Level::Warn,
            _ => Level::Ok,
        }
    }
}

/// The level a read gives: a failed read is critical, because the usual
/// reason it fails is EMFILE itself.
pub fn level_of(read: &Result<FdUse, String>) -> Level {
    match read {
        Ok(u) => u.level(),
        Err(_) => Level::Critical,
    }
}

/// Count this process's open fds and read its `RLIMIT_NOFILE`.
// `rlim_t` is u64 on linux and macOS; the cast is for the platforms where it is not.
#[allow(clippy::unnecessary_cast)]
pub fn read() -> Result<FdUse, String> {
    let entries = std::fs::read_dir("/proc/self/fd").map_err(|e| format!("cannot list /proc/self/fd: {e}"))?;
    // The listing holds one fd of its own while it is read.
    let open = (entries.count() as u64).saturating_sub(1);
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit writes into the struct we pass and nothing else.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } != 0 {
        return Err(format!("getrlimit(RLIMIT_NOFILE): {}", std::io::Error::last_os_error()));
    }
    let lim = |v: libc::rlim_t| if v == libc::RLIM_INFINITY { u64::MAX } else { v as u64 };
    Ok(FdUse { open, soft: lim(rl.rlim_cur), hard: lim(rl.rlim_max) })
}

/// The `/metrics` lines. Nothing when the count cannot be read: an absent
/// series is what Prometheus alerting expects, and a made-up zero would
/// read as healthy.
pub fn metrics_text(read: &Result<FdUse, String>) -> String {
    let Ok(u) = read else { return String::new() };
    let mut out = format!("# TYPE process_open_fds gauge\nprocess_open_fds {}\n", u.open);
    if u.soft != u64::MAX {
        out.push_str(&format!("# TYPE process_max_fds gauge\nprocess_max_fds {}\n", u.soft));
    }
    out
}

/// `dependencies.fds` in the authenticated `/health` body.
pub fn health_dep(read: &Result<FdUse, String>) -> Value {
    let level = level_of(read);
    match read {
        Ok(u) => json!({
            "healthy": level != Level::Critical,
            "level": level.as_str(),
            "open": u.open,
            "soft_limit": (u.soft != u64::MAX).then_some(u.soft),
            "hard_limit": (u.hard != u64::MAX).then_some(u.hard),
            "warn_pct": WARN_PCT,
            "critical_pct": CRIT_PCT,
        }),
        Err(e) => json!({
            "healthy": false,
            "level": level.as_str(),
            "error": e,
            "warn_pct": WARN_PCT,
            "critical_pct": CRIT_PCT,
        }),
    }
}

fn describe(read: &Result<FdUse, String>) -> String {
    match read {
        Ok(u) => match u.pct() {
            Some(p) => format!("{} of {} open ({p}% of the soft limit; hard limit {})", u.open, u.soft, u.hard),
            None => format!("{} open (no finite soft limit)", u.open),
        },
        Err(e) => format!("the count cannot be read ({e})"),
    }
}

/// What the loop does on a reading, given the level it last saw and when it
/// last logged a critical line. Pure, so the transitions are tested.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Quiet,
    Warn,
    Critical,
    RepeatCritical,
    Recovered,
}

pub fn step(prev: Level, now: Level, secs_since_crit_log: u64) -> Step {
    match (prev, now) {
        (_, Level::Critical) if prev != Level::Critical => Step::Critical,
        (Level::Critical, Level::Critical) if secs_since_crit_log >= CRIT_REPEAT_SECS => Step::RepeatCritical,
        (Level::Ok, Level::Warn) => Step::Warn,
        (Level::Warn | Level::Critical, Level::Ok) => Step::Recovered,
        _ => Step::Quiet,
    }
}

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut prev = Level::Ok;
        let mut last_crit = std::time::Instant::now();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(INTERVAL_SECS));
        loop {
            tick.tick().await;
            let r = read();
            let now = level_of(&r);
            let what = describe(&r);
            match step(prev, now, last_crit.elapsed().as_secs()) {
                Step::Quiet => {}
                Step::Warn => {
                    tracing::warn!(event = "gateway_fds_high", detail = %what, "gateway_fds_high: {what}");
                    alert(&state, "warn", format!(
                        "⚠️ The gateway has {what}. At the limit it cannot open sockets, secret files or \
                         database connections (2026-11-02: five hours of 401s). Something is holding descriptors."
                    )).await;
                }
                Step::Critical | Step::RepeatCritical => {
                    last_crit = std::time::Instant::now();
                    tracing::error!(event = "gateway_fds_critical", detail = %what, "gateway_fds_critical: {what}");
                    if prev != Level::Critical {
                        alert(&state, "critical", format!(
                            "🛑 The gateway has {what}. It will refuse connections and secret reads when it \
                             reaches the limit. Restart it now (`noo stack restart gateway`) and keep the \
                             `process_open_fds` graph for the leak."
                        )).await;
                    }
                }
                Step::Recovered => tracing::info!(event = "gateway_fds_recovered", detail = %what, "gateway_fds_recovered: {what}"),
            }
            prev = now;
        }
    });
}

async fn alert(state: &AppState, level: &str, message: String) {
    crate::operator_alert::send_operator_alert_with(
        state,
        crate::operator_alert::OperatorAlert::new("gateway.fds", level, message).investigate("noo cluster verify"),
        3600,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(open: u64, soft: u64) -> FdUse {
        FdUse { open, soft, hard: 524_288 }
    }

    #[test]
    fn the_levels_split_at_seventy_and_ninety_percent_of_the_soft_limit() {
        assert_eq!(u(716, 1024).level(), Level::Ok);
        assert_eq!(u(717, 1024).level(), Level::Warn);
        assert_eq!(u(921, 1024).level(), Level::Warn);
        assert_eq!(u(922, 1024).level(), Level::Critical);
        assert_eq!(u(1024, 1024).level(), Level::Critical);
        assert_eq!(u(10, u64::MAX).level(), Level::Ok, "no finite limit, nothing to measure against");
    }

    #[test]
    fn an_unreadable_count_is_critical_because_emfile_is_why_it_fails() {
        let r: Result<FdUse, String> = Err("cannot list /proc/self/fd: Too many open files (os error 24)".into());
        assert_eq!(level_of(&r), Level::Critical);
        let dep = health_dep(&r);
        assert_eq!(dep["healthy"], false);
        assert_eq!(dep["level"], "critical");
        assert!(dep["error"].as_str().unwrap().contains("os error 24"));
        assert_eq!(metrics_text(&r), "", "no made-up zero in /metrics");
    }

    #[test]
    fn health_and_metrics_carry_the_count_and_the_soft_limit() {
        let r = Ok(u(800, 1024));
        let dep = health_dep(&r);
        assert_eq!((dep["open"].as_u64(), dep["soft_limit"].as_u64(), dep["hard_limit"].as_u64()), (Some(800), Some(1024), Some(524_288)));
        assert_eq!((dep["level"].as_str(), dep["healthy"].as_bool()), (Some("warn"), Some(true)));
        let m = metrics_text(&r);
        assert!(m.contains("\nprocess_open_fds 800\n") && m.contains("\nprocess_max_fds 1024\n"), "{m}");
    }

    #[test]
    fn the_loop_alerts_on_the_way_up_repeats_only_critical_and_says_when_it_recovers() {
        assert_eq!(step(Level::Ok, Level::Ok, 0), Step::Quiet);
        assert_eq!(step(Level::Ok, Level::Warn, 0), Step::Warn);
        assert_eq!(step(Level::Warn, Level::Warn, 9_999), Step::Quiet);
        assert_eq!(step(Level::Warn, Level::Critical, 0), Step::Critical);
        assert_eq!(step(Level::Ok, Level::Critical, 0), Step::Critical, "a jump straight past warn still pages");
        assert_eq!(step(Level::Critical, Level::Critical, 599), Step::Quiet);
        assert_eq!(step(Level::Critical, Level::Critical, 600), Step::RepeatCritical);
        assert_eq!(step(Level::Critical, Level::Warn, 0), Step::Quiet);
        assert_eq!(step(Level::Critical, Level::Ok, 0), Step::Recovered);
        assert_eq!(step(Level::Warn, Level::Ok, 0), Step::Recovered);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_can_count_its_own_fds() {
        let r = read().expect("readable on linux");
        assert!(r.open >= 3, "stdin, stdout and stderr at least: {r:?}");
        assert!(r.soft >= r.open && r.hard >= r.soft, "{r:?}");
    }
}
