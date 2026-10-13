// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Loop-liveness registry — the fix for "a background loop died and
//! nobody noticed" (see memory: the Python autonomy loop was silently
//! dead in prod for weeks).
//!
//! Every always-on `tokio::spawn` loop calls [`record_tick`] at the top
//! of each cycle with its own expected interval. A monitor task
//! ([`spawn_monitor`]) checks the registry every minute and sends an
//! operator alert (cooldown-deduplicated) when a registered loop hasn't
//! ticked within 3× its interval. `/api/agent/loops` exposes the
//! registry for dashboards and `noo` CLI.
//!
//! Loops that never start (e.g. ingest_loop with watched_folders
//! disabled) never register and are not flagged — absent ≠ stale.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::state::AppState;

/// Minimum staleness threshold — protects very short intervals (5-30s
/// loops) from flapping alerts on transient scheduler pressure.
const MIN_STALE_SECS: u64 = 180;

/// Multiple of a loop's own interval after which it counts as stale.
const STALE_FACTOR: u64 = 3;

#[derive(Clone, Copy)]
struct TickRecord {
    last_tick_unix: u64,
    interval_secs: u64,
}

fn registry() -> &'static Mutex<HashMap<&'static str, TickRecord>> {
    static REG: OnceLock<Mutex<HashMap<&'static str, TickRecord>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Record that `name` completed (or started) a cycle. Call at the top of
/// every loop iteration; `interval_secs` is the loop's expected cadence
/// so the monitor can derive a staleness threshold without a parallel
/// config table.
pub fn record_tick(name: &'static str, interval_secs: u64) {
    let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    reg.insert(
        name,
        TickRecord {
            last_tick_unix: now_unix(),
            interval_secs,
        },
    );
}

/// One loop's liveness as exposed via `/api/agent/loops`.
#[derive(Serialize)]
pub struct LoopStatus {
    pub name: &'static str,
    pub interval_secs: u64,
    pub last_tick_unix: u64,
    pub age_secs: u64,
    pub stale_after_secs: u64,
    pub stale: bool,
}

fn stale_after(interval_secs: u64) -> u64 {
    (interval_secs.saturating_mul(STALE_FACTOR)).max(MIN_STALE_SECS)
}

/// Snapshot of every registered loop, sorted by name for stable output.
pub fn snapshot() -> Vec<LoopStatus> {
    let now = now_unix();
    let reg = registry().lock().unwrap_or_else(|p| p.into_inner());
    let mut out: Vec<LoopStatus> = reg
        .iter()
        .map(|(name, rec)| {
            let age = now.saturating_sub(rec.last_tick_unix);
            let threshold = stale_after(rec.interval_secs);
            LoopStatus {
                name,
                interval_secs: rec.interval_secs,
                last_tick_unix: rec.last_tick_unix,
                age_secs: age,
                stale_after_secs: threshold,
                stale: age > threshold,
            }
        })
        .collect();
    out.sort_by_key(|s| s.name);
    out
}

/// Turn a loop's tick record into the pair every status endpoint needs:
/// a **nullable** "is it running?" and a sentence explaining the answer.
///
/// Status handlers used to answer this question with a constant (`running:
/// true`), with the wrong fact (an enabled flag, or "some task has a future
/// next_run"), or with a fail-closed `false`. All three are claims the gateway
/// had not checked. There are genuinely three answers — yes, no, and *we have
/// no tick record so we do not know* — and `None` is the honest third one.
pub fn describe(name: &str, status: Option<&LoopStatus>) -> (Option<bool>, String) {
    match status {
        Some(l) if l.stale => (
            Some(false),
            format!(
                "{name} last ticked {}s ago (stale after {}s)",
                l.age_secs, l.stale_after_secs
            ),
        ),
        Some(l) => (Some(true), format!("{name} ticked {}s ago", l.age_secs)),
        None => (
            None,
            format!("unknown — the {name} loop has never reported a tick to this gateway"),
        ),
    }
}

/// `describe` against the live registry.
pub fn liveness(name: &str) -> (Option<bool>, String) {
    let snap = snapshot();
    describe(name, snap.iter().find(|l| l.name == name))
}

/// Spawn the liveness monitor. Checks all registered loops every 60s and
/// alerts the operator (1h cooldown per loop) when one goes stale. Also
/// logs a recovery line when a previously-stale loop ticks again.
pub fn spawn_monitor(state: Arc<AppState>) {
    tracing::info!(
        stale_factor = STALE_FACTOR,
        min_stale_secs = MIN_STALE_SECS,
        "loop_health_monitor_spawned"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await; // discard immediate first tick
        let mut previously_stale: Vec<&'static str> = Vec::new();
        loop {
            tick.tick().await;
            record_tick("loop_health_monitor", 60);

            let snap = snapshot();
            let mut now_stale: Vec<&'static str> = Vec::new();
            for loop_status in &snap {
                if !loop_status.stale {
                    continue;
                }
                now_stale.push(loop_status.name);
                tracing::warn!(
                    name = loop_status.name,
                    age_secs = loop_status.age_secs,
                    threshold_secs = loop_status.stale_after_secs,
                    "loop_health_stale"
                );
                crate::operator_alert::send_operator_alert_with(
                    &state,
                    crate::operator_alert::OperatorAlert::new(
                        "loop_health.stale",
                        loop_status.name,
                        format!(
                            "🛑 Gateway background loop `{}` has stopped; the \
                             scheduled work it owns is not running.",
                            loop_status.name,
                        ),
                    )
                    .detail(format!(
                        "no tick for {}s (expected every {}s); a gateway restart restores it",
                        loop_status.age_secs, loop_status.interval_secs
                    ))
                    .investigate("noo stack logs gateway --tail 200"),
                    3600,
                )
                .await;
            }
            for name in &previously_stale {
                if !now_stale.contains(name) {
                    tracing::info!(name = *name, "loop_health_recovered");
                }
            }
            previously_stale = now_stale;
        }
    });
}

#[cfg(test)]
mod liveness_tests {
    use super::*;

    fn rec(age_secs: u64, stale: bool) -> LoopStatus {
        LoopStatus {
            name: "demo_loop",
            interval_secs: 30,
            last_tick_unix: 0,
            age_secs,
            stale_after_secs: 90,
            stale,
        }
    }

    #[test]
    fn no_tick_record_is_unknown_not_stopped() {
        let (running, detail) = describe("demo_loop", None);
        assert_eq!(running, None, "absence of evidence must not render as `false`");
        assert!(detail.contains("unknown"), "detail must say why: {detail}");
        assert!(detail.contains("demo_loop"));
    }

    #[test]
    fn fresh_tick_is_running_with_its_age() {
        let (running, detail) = describe("demo_loop", Some(&rec(4, false)));
        assert_eq!(running, Some(true));
        assert!(detail.contains("4s ago"), "{detail}");
    }

    #[test]
    fn stale_tick_is_not_running_and_says_how_stale() {
        let (running, detail) = describe("demo_loop", Some(&rec(600, true)));
        assert_eq!(running, Some(false));
        assert!(detail.contains("600s ago"), "{detail}");
        assert!(detail.contains("stale after 90s"), "{detail}");
    }
}
