// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A critical heartbeat task that never ran, or never completed, alerts.
//!
//! Until now the only backup alert was for a backup that RAN and FAILED
//! (`backup_completion`, `heartbeat.task_failed`). 2026-10-24, the pop-os
//! controller: the data NVMe failed at 21:07Z on 10-23 and Postgres was down
//! until ~14:15Z on 10-24. The `database_backup` task (`30 3 * * *`) did not
//! run at 03:30 — the gateway and database that schedule it were down — so
//! "ran and failed" never fired, and 18 hours of data were unprotected with
//! nobody told. The scheduler cannot report its own outage while it is down;
//! what it CAN do is notice, the moment it is back, that the last success is
//! older than its schedule allows, and say so BEFORE it runs the catch-up.
//!
//! This is that check. It runs once before the scheduler's first poll after a
//! start (so the alert precedes the catch-up run) and on every poll tick
//! after (so a scheduler that is up but not completing the task is caught
//! too). A task is overdue when its newest SUCCESS is older than one schedule
//! interval plus [`GRACE_SECS`] (26 h for a daily task).
//!
//! The alert is a PERSISTING condition (`operator_alert`): one message at
//! onset, silence while it holds, reminders at 4 h / 12 h / 24 h then daily,
//! and one "recovered" message when a success lands — which is the follow-up
//! when the catch-up succeeds. A catch-up that fails raises the existing
//! `database_backup.failed` alert.
//!
//! "Critical": [`CRITICAL_ACTIONS`] (the backup) or a task whose config sets
//! `"critical": true`.
//!
//! For `database_backup` the newest dump hostd saw in the backup directory
//! (its heartbeat, `host_daemon::newest_backup`) is a second witness: a fresh
//! dump file means the data IS protected even when a run record was lost, so
//! it counts as a success for this purpose.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde_json::Value;

use crate::egress::{self, OperatorAlert};
use crate::state::AppState;

/// Slack on top of the schedule interval. A dump takes minutes; two hours never
/// hides a missed day. Mirrors `BACKUP_GRACE_SECS` in the CLI.
pub const GRACE_SECS: i64 = 2 * 3600;

/// Operator-alert kind; the target is the task id.
pub const ALERT_KIND: &str = "heartbeat.overdue";

/// Actions that are critical without any per-task flag.
pub const CRITICAL_ACTIONS: &[&str] = &["database_backup"];

/// Whether a task must have a recent success.
pub fn is_critical(action: &str, config: &Value) -> bool {
    CRITICAL_ACTIONS.contains(&action)
        || config.get("critical").and_then(Value::as_bool).unwrap_or(false)
}

/// Seconds between two consecutive firings of `schedule` after `from`.
pub fn interval_secs(schedule: &str, from: DateTime<Utc>, tz: Tz) -> Option<i64> {
    let first = crate::heartbeat_actions::compute_next_run(schedule, from, tz)?;
    let second = crate::heartbeat_actions::compute_next_run(schedule, first, tz)?;
    Some((second - first).num_seconds())
}

/// A critical task whose newest success is too old.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overdue {
    /// The newest success, if there has ever been one.
    pub last_ok: Option<DateTime<Utc>>,
    /// What the age was measured from: the last success, else task creation.
    pub reference: DateTime<Utc>,
    pub age_secs: i64,
    /// The first scheduled firing after `reference` — the run that should have
    /// produced a success.
    pub missed_at: Option<DateTime<Utc>>,
    pub interval_secs: i64,
}

/// Pure: is this task overdue at `now`? `created_at` is the floor for a task
/// that has never succeeded (a new install is not overdue on its first day).
pub fn assess(
    last_ok: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    schedule: &str,
    now: DateTime<Utc>,
    tz: Tz,
) -> Option<Overdue> {
    let interval = interval_secs(schedule, now, tz)?;
    let reference = last_ok.unwrap_or(created_at);
    let age = (now - reference).num_seconds();
    if age <= interval + GRACE_SECS {
        return None;
    }
    Some(Overdue {
        last_ok,
        reference,
        age_secs: age,
        missed_at: crate::heartbeat_actions::compute_next_run(schedule, reference, tz),
        interval_secs: interval,
    })
}

fn local(ts: DateTime<Utc>, tz: Tz) -> String {
    ts.with_timezone(&tz).format("%Y-%m-%d %H:%M %Z").to_string()
}

/// The alert for an overdue task. A persisting condition, scoped to the task.
pub fn overdue_alert(task_id: &str, task_name: &str, o: &Overdue, tz: Tz) -> OperatorAlert {
    let age = egress::human_duration(o.age_secs);
    let missed = o
        .missed_at
        .map(|m| format!("the scheduled run at {} has not completed successfully", local(m, tz)))
        .unwrap_or_else(|| "no scheduled run has completed successfully since".to_string());
    let summary = match o.last_ok {
        Some(ok) => format!(
            "⏰ '{task_name}' is overdue: last successful run {} ({age} ago); {missed}.",
            local(ok, tz)
        ),
        None => format!(
            "⏰ '{task_name}' is overdue: it has never completed successfully (created {}, {age} ago); {missed}.",
            local(o.reference, tz)
        ),
    };
    OperatorAlert::new(ALERT_KIND, task_id, summary)
        .detail(format!(
            "interval {}s + grace {}s exceeded by age {}s",
            o.interval_secs, GRACE_SECS, o.age_secs
        ))
        .investigate(format!("noo heartbeat history --task-id {task_id} --limit 5"))
        .persisting()
}

/// The "recovered" message that closes [`overdue_alert`].
pub fn recovered_alert(task_id: &str, task_name: &str) -> OperatorAlert {
    OperatorAlert::new(
        ALERT_KIND,
        task_id,
        format!("✅ '{task_name}' has completed successfully again."),
    )
    .investigate(format!("noo heartbeat history --task-id {task_id} --limit 5"))
}

/// One critical task's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub task_id: String,
    pub task_name: String,
    pub overdue: Option<Overdue>,
}

/// Read every enabled critical task and judge it. `hostd_backup` is the newest
/// dump hostd saw (second witness for `database_backup` only).
pub async fn findings(
    db: &sqlx::PgPool,
    now: DateTime<Utc>,
    tz: Tz,
    hostd_backup: Option<DateTime<Utc>>,
) -> Result<Vec<Finding>, sqlx::Error> {
    let tasks: Vec<(String, String, String, String, Value, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, name, schedule, action, COALESCE(config, '{}'::jsonb), created_at \
         FROM noo_heartbeat_tasks WHERE enabled = true",
    )
    .fetch_all(db)
    .await?;
    let mut out = Vec::new();
    for (id, name, schedule, action, config, created_at) in tasks {
        if !is_critical(&action, &config) {
            continue;
        }
        let mut last_ok: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT MAX(completed_at) FROM noo_heartbeat_runs WHERE task_id = $1 AND status = 'success'",
        )
        .bind(&id)
        .fetch_one(db)
        .await?;
        if action == "database_backup" {
            last_ok = match (last_ok, hostd_backup) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
        out.push(Finding { overdue: assess(last_ok, created_at, &schedule, now, tz), task_id: id, task_name: name });
    }
    Ok(out)
}

/// One pass: alert for each overdue critical task, close the alert for each
/// that is fine. Errors are logged, never propagated — the scheduler must go
/// on to dispatch, and a database that is down is the very case this exists for.
pub async fn check(state: &Arc<AppState>) {
    let tz = crate::heartbeat_actions::resolve_tz();
    let hostd = crate::host_daemon::newest_backup().await;
    let found = match findings(&state.db, Utc::now(), tz, hostd).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "backup_overdue_check_failed");
            return;
        }
    };
    for f in found {
        match &f.overdue {
            Some(o) => {
                tracing::warn!(task_id = %f.task_id, age_secs = o.age_secs, "heartbeat_task_overdue");
                crate::operator_alert::send_operator_alert_with(
                    state,
                    overdue_alert(&f.task_id, &f.task_name, o, tz),
                    0, // persisting: its own schedule replaces the cooldown
                )
                .await;
            }
            None => {
                crate::operator_alert::clear_operator_alert(state, recovered_alert(&f.task_id, &f.task_name)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_alert::{clear_step, persisting_step, ClearStep, Step};
    use chrono::{Duration, TimeZone};
    use serde_json::json;

    const DAILY: &str = "30 3 * * *";

    fn at(d: u32, h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, d, h, m, 0).unwrap()
    }

    fn made() -> DateTime<Utc> {
        at(1, 0, 0)
    }

    #[test]
    fn a_daily_schedule_has_a_24h_interval_and_the_backup_is_critical() {
        assert_eq!(interval_secs(DAILY, at(24, 0, 0), chrono_tz::UTC), Some(86_400));
        assert!(is_critical("database_backup", &json!({})));
        assert!(is_critical("custom_prompt", &json!({"critical": true})), "generalises by flag");
        assert!(!is_critical("custom_prompt", &json!({})));
    }

    /// 2026-10-24: last good backup 10-23 03:31, scheduler back at 14:15.
    #[test]
    fn the_incident_is_overdue_and_names_the_missed_run() {
        let o = assess(Some(at(23, 3, 31)), made(), DAILY, at(24, 14, 15), chrono_tz::UTC)
            .expect("34h without a success must be overdue");
        assert_eq!(o.missed_at, Some(at(24, 3, 30)));
        assert!(o.age_secs > 34 * 3600);
        let a = overdue_alert("database_backup", "Database backup", &o, chrono_tz::UTC);
        assert!(a.summary.contains("overdue") && a.summary.contains("2026-10-23 03:31"), "{}", a.summary);
        assert!(a.summary.contains("2026-10-24 03:30") && a.summary.contains("1d 10h"), "{}", a.summary);
        assert!(a.persisting && a.target == "database_backup" && a.kind == ALERT_KIND);
    }

    #[test]
    fn thirty_hours_old_is_overdue_and_a_fresh_success_is_not() {
        let now = at(24, 14, 15);
        assert!(assess(Some(now - Duration::hours(30)), made(), DAILY, now, chrono_tz::UTC).is_some());
        assert!(assess(Some(at(24, 3, 32)), made(), DAILY, now, chrono_tz::UTC).is_none());
        // inside interval + grace (25h) is still fine; the dump takes minutes
        assert!(assess(Some(now - Duration::hours(25)), made(), DAILY, now, chrono_tz::UTC).is_none());
        // a new install is not overdue before its first scheduled run is a day late
        assert!(assess(None, now - Duration::hours(5), DAILY, now, chrono_tz::UTC).is_none());
        let never = assess(None, now - Duration::hours(40), DAILY, now, chrono_tz::UTC).unwrap();
        assert!(overdue_alert("t", "Backup", &never, chrono_tz::UTC).summary.contains("never completed"));
    }

    /// The real funnel schedule, not a copy of it: once at onset, quiet while
    /// it holds, a reminder at 4h, and a recovered message when a success lands.
    #[test]
    fn the_alert_is_raised_once_then_reminds_then_recovers() {
        let o = assess(Some(at(23, 3, 31)), made(), DAILY, at(24, 14, 15), chrono_tz::UTC).unwrap();
        let alert = overdue_alert("database_backup", "Database backup", &o, chrono_tz::UTC);
        let t0 = 1_792_000_000;
        let (s1, st) = persisting_step(None, &alert, t0, false);
        assert_eq!(s1, Step::Deliver(None), "raised at onset, before the catch-up runs");
        let (s2, st) = persisting_step(Some(st), &alert, t0 + 60, false);
        assert_eq!(s2, Step::Quiet, "the next tick must not repeat it");
        let (s3, st) = persisting_step(Some(st), &alert, t0 + 4 * 3600, false);
        assert!(matches!(s3, Step::Deliver(Some(_))), "{s3:?}");
        assert_eq!(clear_step(Some(&st), t0 + 5 * 3600, false), ClearStep::Deliver(5 * 3600));
        assert_eq!(clear_step(None, t0, false), ClearStep::Nothing, "a task never announced has nothing to recover");
    }

    #[test]
    fn the_check_runs_before_the_first_poll_and_on_every_tick() {
        let hl = include_str!("heartbeat_loop.rs");
        assert!(hl.contains("crate::backup_overdue::check(&state).await"), "the loop must call the overdue check");
        let first = hl.find("crate::backup_overdue::check(&state).await").unwrap();
        let poll = hl.find("tokio::select!").unwrap();
        assert!(first < poll, "the first check must precede the first poll (the catch-up)");
        assert!(hl[poll..].contains("backup_overdue::check"), "and it must run on every tick too");
        assert!(include_str!("main.rs").contains("mod backup_overdue;"));
    }

    // ── DB-backed (skipped without NOO_BROKER_TEST_DSN) ──

    async fn seed(db: &sqlx::PgPool, success_at: Option<DateTime<Utc>>, task_age: Duration) {
        sqlx::query("INSERT INTO noo_heartbeat_tasks (id, name, schedule, action, config, enabled, created_at) VALUES ('database_backup', 'Database backup', $1, 'database_backup', '{}', true, $2) ON CONFLICT DO NOTHING")
            .bind(DAILY)
            .bind(Utc::now() - task_age)
            .execute(db).await.unwrap();
        if let Some(t) = success_at {
            sqlx::query("INSERT INTO noo_heartbeat_runs (run_id, task_id, task_name, action, started_at, completed_at, status) VALUES ('ok1', 'database_backup', 'b', 'database_backup', $1, $1, 'success')")
                .bind(t).execute(db).await.unwrap();
        }
        // a recent FAILURE must not count as a success
        sqlx::query("INSERT INTO noo_heartbeat_runs (run_id, task_id, task_name, action, started_at, completed_at, status) VALUES ('bad1', 'database_backup', 'b', 'database_backup', $1, $1, 'error')")
            .bind(Utc::now() - Duration::hours(1)).execute(db).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_30h_old_success_is_overdue_and_a_failure_since_does_not_count() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("bo_old").await else { return };
        let now = Utc::now();
        seed(&db, Some(now - Duration::hours(30)), Duration::days(30)).await;
        let f = findings(&db, now, chrono_tz::UTC, None).await.unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].overdue.is_some(), "30h without a success, and the later failure is not one");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fresh_success_or_a_fresh_dump_file_is_not_overdue() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("bo_fresh").await else { return };
        let now = Utc::now();
        seed(&db, Some(now - Duration::hours(3)), Duration::days(30)).await;
        assert!(findings(&db, now, chrono_tz::UTC, None).await.unwrap()[0].overdue.is_none());
        // hostd's file witness alone also clears an old history (a lost run record)
        sqlx::query("DELETE FROM noo_heartbeat_runs WHERE run_id = 'ok1'").execute(&db).await.unwrap();
        assert!(findings(&db, now, chrono_tz::UTC, None).await.unwrap()[0].overdue.is_some());
        let dump = Some(now - Duration::hours(2));
        assert!(findings(&db, now, chrono_tz::UTC, dump).await.unwrap()[0].overdue.is_none());
    }
}
