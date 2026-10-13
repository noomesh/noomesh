// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Outcome reconciliation for Python-delegated heartbeat tasks.
//!
//! ## Why this exists
//!
//! `delegate_to_python` used a synchronous NATS **request**, so Rust sat
//! blocked for the entire task and `NOO_WORKER_TIMEOUT_SECS` (120s) acted as a
//! task deadline it was never meant to be. Real work exceeds it routinely —
//! observed 2026-08-01: `graph_signals` **392s** and `structured_research`
//! **135s**, both of which SUCCEEDED and both of which were reported as
//! failures. Operators were being paged for healthy tasks, which is how alert
//! fatigue starts and how the next real failure gets ignored.
//!
//! Dispatch is now fire-and-forget. But that alone would silently undo PR #271:
//! the ONLY failure alerting for delegated tasks was Rust inspecting the NATS
//! reply. Python raises no operator alerts at all — verified, there are zero
//! `operator_alert` call sites in `heartbeat.py`. Removing the wait without
//! replacing the detector would restore the exact bug #271 fixed, where
//! `database_backup` failed silently for weeks.
//!
//! So the wait is replaced by reconciliation against the DB, which is the real
//! source of truth: Python writes the outcome via `store.save_run`.
//!
//! ## The dead-worker case
//!
//! `save_run` is called **once, at completion**. There is no `running` row —
//! `noo_heartbeat_runs.status` only ever holds `success` or `error`. So a
//! worker that dies mid-task writes NOTHING, and "no row" is indistinguishable
//! from "no dispatch" if you only look at the table.
//!
//! That is what the Redis ledger is for. Rust records every dispatch; the
//! reconciler resolves each entry against the run table:
//!
//! | Ledger entry | Run row | Verdict |
//! | --- | --- | --- |
//! | present | `success` | done, drop |
//! | present | `error` | **alert**, drop |
//! | present | none, age < deadline | still running, leave |
//! | present | none, age > deadline | **alert** (worker died), drop |
//!
//! Both failure modes that mattered stay covered, and a slow-but-healthy task
//! is no longer one of them.

use std::sync::Arc;

use serde_json::Value;
use tokio::time::{interval, Duration};

use crate::state::AppState;

/// Redis zset of in-flight dispatches. Score is the dispatch time as a Unix
/// timestamp, so `zrangebyscore` selects by age directly.
pub const INFLIGHT_KEY: &str = "noo:heartbeat:inflight";

/// How often to reconcile. Matches the scheduler poll cadence.
const RECONCILE_INTERVAL_SECS: u64 = 60;

/// Don't inspect an entry until it has had a chance to finish. Purely an
/// efficiency guard — a task completing inside this window is resolved on the
/// next pass, not lost.
const SETTLE_SECS: i64 = 90;

/// Age past which a dispatch with no run row is presumed dead.
///
/// Must sit comfortably above the slowest real task or this reintroduces the
/// false alerts under a new name. The observed worst case is `graph_signals`
/// at 392s, so the 30-minute default has ~4.5x headroom. Override with
/// `NOO_HEARTBEAT_DISPATCH_DEADLINE_SECS`.
const DEFAULT_DEADLINE_SECS: i64 = 1800;

pub fn deadline_secs() -> i64 {
    std::env::var("NOO_HEARTBEAT_DISPATCH_DEADLINE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &i64| *v > 0)
        .unwrap_or(DEFAULT_DEADLINE_SECS)
}

/// One in-flight dispatch. Serialised as the zset member.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Dispatch {
    pub task_id: String,
    pub task_name: String,
    pub action: String,
    /// Unix seconds. Also the zset score; kept in the member so a resolved
    /// entry can be matched against `started_at` without a second lookup.
    pub dispatched_at: i64,
}

impl Dispatch {
    pub fn encode(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
    pub fn decode(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
}

/// Record a dispatch in the ledger. Best-effort: if Redis is down we lose
/// outcome alerting for this run, but the task itself still executes — a
/// bookkeeping failure must not stop work from being dispatched.
pub async fn record_dispatch(state: &AppState, d: &Dispatch) {
    let Some(redis) = state.redis.as_ref() else {
        tracing::warn!(
            task_id = %d.task_id,
            "heartbeat_dispatch_unledgered: no redis, outcome will not be reconciled"
        );
        return;
    };
    redis.zadd(INFLIGHT_KEY, &d.encode(), d.dispatched_at as f64).await;
}

/// What the reconciler decided about one in-flight dispatch. Split out so the
/// decision is unit-testable without Redis, NATS, or Postgres.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Completed successfully — drop it, say nothing.
    Done,
    /// Completed with an error — alert, then drop.
    Failed(String),
    /// No run row yet and still inside the deadline — leave it alone.
    StillRunning,
    /// No run row and past the deadline — the worker never reported back.
    Abandoned,
}

/// Decide the fate of one dispatch.
///
/// `run` is the run row found for this task at or after `dispatched_at`, as
/// `(status, error)`. `age_secs` is how long ago it was dispatched.
pub fn classify(run: Option<(&str, Option<&str>)>, age_secs: i64, deadline: i64) -> Verdict {
    match run {
        Some(("success", _)) => Verdict::Done,
        // The gateway inserts the row at dispatch with status "running"
        // (run-lifecycle change) — that row is the run being ALIVE, not an
        // outcome. Past the deadline it is the same abandonment the no-row
        // case detects (a worker that died mid-task never updates it).
        Some(("running", _)) if age_secs > deadline => Verdict::Abandoned,
        Some(("running", _)) => Verdict::StillRunning,
        Some((_, err)) => Verdict::Failed(
            err.filter(|e| !e.is_empty())
                .unwrap_or("no error detail recorded")
                .chars()
                .take(300)
                .collect(),
        ),
        None if age_secs > deadline => Verdict::Abandoned,
        None => Verdict::StillRunning,
    }
}

/// Spawn the reconciliation loop. Call alongside `heartbeat_loop::spawn`.
pub fn spawn(state: Arc<AppState>) {
    tracing::info!(
        interval_s = RECONCILE_INTERVAL_SECS,
        deadline_s = deadline_secs(),
        "heartbeat_reconcile_spawned"
    );
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(RECONCILE_INTERVAL_SECS));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            crate::loop_health::record_tick("heartbeat_reconcile", RECONCILE_INTERVAL_SECS);
            if let Err(e) = reconcile_once(&state).await {
                tracing::warn!(error = %e, "heartbeat_reconcile_error");
            }
        }
    });
}

/// One reconciliation pass. Public for tests and for a future admin endpoint.
pub async fn reconcile_once(state: &Arc<AppState>) -> Result<(), sqlx::Error> {
    let Some(redis) = state.redis.as_ref() else { return Ok(()) };

    let now = chrono::Utc::now().timestamp();
    let deadline = deadline_secs();

    // Only entries old enough to have plausibly finished.
    let members = redis
        .zrangebyscore(INFLIGHT_KEY, 0.0, (now - SETTLE_SECS) as f64)
        .await;
    if members.is_empty() {
        return Ok(());
    }

    for member in members {
        let Some(d) = Dispatch::decode(&member) else {
            // Unparseable entry — drop it rather than retry forever.
            tracing::warn!(member = %member, "heartbeat_reconcile_bad_entry");
            redis.zrem(INFLIGHT_KEY, &member).await;
            continue;
        };

        let started_at = match chrono::DateTime::from_timestamp(d.dispatched_at, 0) {
            Some(t) => t,
            None => {
                redis.zrem(INFLIGHT_KEY, &member).await;
                continue;
            }
        };

        // The run row Python wrote for THIS dispatch. Keyed on
        // started_at >= dispatched_at so an older run of the same task can
        // never be mistaken for this one's outcome.
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT status, error FROM noo_heartbeat_runs \
             WHERE task_id = $1 AND started_at >= $2 \
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(&d.task_id)
        .bind(started_at)
        .fetch_optional(&state.db)
        .await?;

        let verdict = classify(
            row.as_ref().map(|(s, e)| (s.as_str(), e.as_deref())),
            now - d.dispatched_at,
            deadline,
        );

        // Any terminal verdict releases the delegate's in-flight claim
        // (taken at dispatch so a cron tick cannot double-run a task a
        // manual trigger is already executing remotely).
        if !matches!(verdict, Verdict::StillRunning) {
            crate::heartbeat_actions::end_run(&d.task_id);
        }
        match verdict {
            Verdict::StillRunning => continue,
            Verdict::Done => {
                tracing::info!(
                    task_id = %d.task_id,
                    duration_s = now - d.dispatched_at,
                    "heartbeat_delegate_reconciled_ok"
                );
            }
            Verdict::Failed(detail) => {
                tracing::error!(
                    task_id = %d.task_id, action = %d.action, error = %detail,
                    "heartbeat_python_delegate_task_failed"
                );
                crate::operator_alert::send_operator_alert_with(
                    state,
                    crate::operator_alert::OperatorAlert::new(
                        "heartbeat.task_failed",
                        &d.task_id,
                        format!("❌ Heartbeat task '{}' ({}) FAILED.", d.task_name, d.action),
                    )
                    .detail(detail.clone())
                    .investigate(format!(
                        "noo heartbeat history --task-id {} --limit 5",
                        d.task_id
                    )),
                    3600,
                )
                .await;
            }
            Verdict::Abandoned => {
                tracing::error!(
                    task_id = %d.task_id, action = %d.action,
                    age_s = now - d.dispatched_at,
                    "heartbeat_delegate_abandoned"
                );
                crate::operator_alert::send_operator_alert_with(
                    state,
                    crate::operator_alert::OperatorAlert::new(
                        "heartbeat.task_failed",
                        &d.task_id,
                        format!(
                            "❌ Heartbeat task '{}' was handed to the Python worker and \
                             never reported back; no run record was written.",
                            d.task_name,
                        ),
                    )
                    .detail(format!(
                        "action {}, dispatched {}s ago, no outcome; the worker may have died mid-task",
                        d.action,
                        now - d.dispatched_at
                    ))
                    .investigate(format!(
                        "noo heartbeat history --task-id {} --limit 5",
                        d.task_id
                    )),
                    3600,
                )
                .await;
            }
        }
        redis.zrem(INFLIGHT_KEY, &member).await;
    }
    Ok(())
}

/// Payload for the fire-and-forget dispatch. `run_id` rides along so the
/// Python worker records its outcome onto the SAME run row the gateway
/// inserts at dispatch (status "running") — one id to poll across all
/// three action paths. An older worker ignores the extra field and
/// generates its own id (its upsert then inserts a second, final row;
/// the running row is reconciled by the abandonment sweep — transition
/// window only, both images ship in one release).
pub fn dispatch_payload(task_id: &str, run_id: &str) -> Value {
    serde_json::json!({ "task_id": task_id, "run_id": run_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE: i64 = 1800;

    #[test]
    fn success_row_is_silent() {
        assert_eq!(classify(Some(("success", None)), 500, DEADLINE), Verdict::Done);
    }

    #[test]
    fn running_row_is_still_running_not_failed() {
        assert_eq!(
            classify(Some(("running", None)), 500, DEADLINE),
            Verdict::StillRunning
        );
    }

    #[test]
    fn running_row_past_deadline_is_abandoned() {
        assert_eq!(
            classify(Some(("running", None)), DEADLINE + 1, DEADLINE),
            Verdict::Abandoned
        );
    }

    #[test]
    fn error_row_alerts_with_detail() {
        let v = classify(Some(("error", Some("disk full"))), 10, DEADLINE);
        assert_eq!(v, Verdict::Failed("disk full".into()));
    }

    #[test]
    fn error_row_without_detail_still_alerts() {
        // An empty error string must not produce a blank alert body.
        assert_eq!(
            classify(Some(("error", Some(""))), 10, DEADLINE),
            Verdict::Failed("no error detail recorded".into())
        );
        assert_eq!(
            classify(Some(("error", None)), 10, DEADLINE),
            Verdict::Failed("no error detail recorded".into())
        );
    }

    // The regression this whole change exists to prevent: a task that runs
    // longer than the old 120s RPC timeout is NOT a failure.
    #[test]
    fn slow_task_is_not_a_failure() {
        // graph_signals, observed at 392s.
        assert_eq!(classify(None, 392, DEADLINE), Verdict::StillRunning);
        // structured_research, observed at 135s.
        assert_eq!(classify(None, 135, DEADLINE), Verdict::StillRunning);
        // And once it finishes, it reconciles clean.
        assert_eq!(classify(Some(("success", None)), 392, DEADLINE), Verdict::Done);
    }

    // The regression that fire-and-forget would otherwise reintroduce (#271):
    // a worker that dies writes no row at all, and must still page someone.
    #[test]
    fn dead_worker_is_detected() {
        assert_eq!(classify(None, DEADLINE + 1, DEADLINE), Verdict::Abandoned);
    }

    #[test]
    fn deadline_boundary_is_not_abandoned() {
        assert_eq!(classify(None, DEADLINE, DEADLINE), Verdict::StillRunning);
    }

    #[test]
    fn long_errors_are_truncated_for_the_alert() {
        let long = "x".repeat(1000);
        let Verdict::Failed(detail) = classify(Some(("error", Some(&long))), 10, DEADLINE) else {
            panic!("expected Failed");
        };
        assert_eq!(detail.chars().count(), 300);
    }

    #[test]
    fn dispatch_round_trips() {
        let d = Dispatch {
            task_id: "daily_log".into(),
            task_name: "Daily Log".into(),
            action: "write_log".into(),
            dispatched_at: 1_754_000_000,
        };
        assert_eq!(Dispatch::decode(&d.encode()), Some(d));
    }

    #[test]
    fn bad_ledger_entry_decodes_to_none() {
        assert_eq!(Dispatch::decode("not json"), None);
    }

    #[test]
    fn deadline_default_exceeds_slowest_observed_task() {
        // Guard the headroom: 392s is the worst case seen in production.
        let deadline = DEFAULT_DEADLINE_SECS;
        assert!(
            deadline > 392 * 2,
            "deadline must keep clear headroom over the slowest real task"
        );
    }
}
