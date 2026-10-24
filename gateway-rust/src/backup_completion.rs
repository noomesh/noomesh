// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Completion hook for the `database_backup` heartbeat action.
//!
//! The action used to queue the host-spool `backup` command and then POLL for
//! hostd's result file for `wait_secs` (120), holding the heartbeat run open.
//! The dump grows with the database: runs took 70, 90, 95, 95, 100, 110 s, then
//! passed 120 s, and every later run was recorded FAILED ("queued but produced
//! no result") and alerted, though hostd was still dumping. A clock was being
//! used to judge an artifact.
//!
//! Now the action queues and returns at once. Its run stays `running` with a
//! result text that names the result file ([`pending_text`]) — queued is not a
//! success, and the run model already has a `running` state, so no migration.
//! This module's loop ([`spawn`]) finishes that SAME run when the file lands:
//!
//!   * `ok: true`  -> success, with the dump path, size and duration. The size
//!     is checked against the file when the gateway can see it, else hostd's
//!     reported size is used; an empty dump is a failure either way.
//!   * `ok: false` -> failure with hostd's stderr, plus an operator alert.
//!   * nothing within [`RESULT_DEADLINE_SECS`] -> failure plus an alert.
//!
//! A slow but successful dump alerts nobody. The alert goes through the
//! operator_alert funnel with a cooldown; its repeat policy is not touched here.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use crate::egress::OperatorAlert;
use crate::state::AppState;

/// How long hostd gets to produce a result before the run is failed and an
/// operator is told. Generous on purpose: the dump has been seen taking 2+
/// minutes and grows, and a slow success must never page anyone.
pub const RESULT_DEADLINE_SECS: i64 = 2 * 60 * 60;

/// How often pending backups are checked. The cost of a tick with nothing
/// pending is one indexed query.
pub const POLL_INTERVAL_SECS: u64 = 30;

/// `loop_health` name, so a dead completion loop shows up as stale.
pub const LOOP_NAME: &str = "database_backup_completion";

/// Operator-alert kind, and its cooldown (one alert per task per window).
pub const ALERT_KIND: &str = "database_backup.failed";
pub const ALERT_COOLDOWN_SECS: i64 = 6 * 60 * 60;

/// The action name the hook serves.
pub const ACTION: &str = "database_backup";

/// Start of a pending run's `result_text`. The text is the durable record of
/// "queued, waiting on THIS file": it survives a gateway restart, and the
/// startup orphan sweep leaves rows that carry it alone.
pub const PENDING_MARKER: &str = "Database backup queued; awaiting host result file: ";

/// The `result_text` of a queued backup run.
pub fn pending_text(result_path: &str) -> String {
    format!("{PENDING_MARKER}{result_path}")
}

/// The result file a pending run is waiting on, or `None` if `text` is not a
/// pending-backup marker.
pub fn pending_result_path(text: &str) -> Option<&str> {
    text.strip_prefix(PENDING_MARKER).map(str::trim).filter(|p| !p.is_empty())
}

/// What a pending backup's evidence says right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No usable result yet and the deadline has not passed.
    Pending,
    Succeeded { text: String },
    Failed { error: String },
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

/// Decide a pending backup from hostd's result (if any) and the clock.
///
/// `elapsed` is time since the command was queued. `visible_size` reports the
/// size of a dump path IF this process can see it (the backup dir is only
/// mounted into the gateway on some installs); `None` means "cannot see it",
/// not "empty".
pub fn judge(
    result: Option<&Value>,
    elapsed: Duration,
    visible_size: &dyn Fn(&str) -> Option<u64>,
) -> Verdict {
    let verdict = judge_dump(result, elapsed, visible_size);
    // The off-site outcome is part of the run's text, success OR failure: a
    // success line that cannot say whether anything left the machine hid, on
    // 2026-10-24, a configured destination that was never copied to.
    let Some(note) = offsite_note(result) else { return verdict };
    match verdict {
        Verdict::Succeeded { text } => Verdict::Succeeded { text: format!("{text}; off-site: {note}") },
        Verdict::Failed { error } => Verdict::Failed { error: format!("{error} (off-site: {note})") },
        v => v,
    }
}

/// hostd's off-site outcome line (`offsite` in the result), if it sent one.
pub fn offsite_note(result: Option<&Value>) -> Option<String> {
    result?
        .get("offsite")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}

/// The note the script prints while off-site has never been decided.
pub const OFFSITE_UNDECIDED_PREFIX: &str = "not decided";
pub const OFFSITE_ALERT_KIND: &str = "database_backup.offsite_undecided";
/// At most one reminder a week.
pub const OFFSITE_ALERT_COOLDOWN_SECS: i64 = 7 * 24 * 60 * 60;

/// The weekly nudge while off-site is undecided. `none` set on purpose says
/// "declined" and never reaches this.
pub fn offsite_undecided_alert(result: Option<&Value>, task_id: &str) -> Option<OperatorAlert> {
    let res = result.filter(|r| r.get("status").and_then(Value::as_str) != Some("running"))?;
    let note = offsite_note(Some(res))?;
    if !note.starts_with(OFFSITE_UNDECIDED_PREFIX) {
        return None;
    }
    Some(
        OperatorAlert::new(
            OFFSITE_ALERT_KIND,
            task_id,
            "⚠️ Every database backup is on this machine only — off-site storage has never been decided. \
             The data and its backups share one machine.",
        )
        .detail(note)
        .investigate("noo backups setup"),
    )
}

fn judge_dump(
    result: Option<&Value>,
    elapsed: Duration,
    visible_size: &dyn Fn(&str) -> Option<u64>,
) -> Verdict {
    // A missing, half-written or still-`running` result is "not yet".
    let finished = result.filter(|r| r.get("status").and_then(Value::as_str) != Some("running"));
    let Some(res) = finished else {
        return if elapsed > Duration::seconds(RESULT_DEADLINE_SECS) {
            Verdict::Failed {
                error: format!(
                    "Database backup queued but noo-hostd produced no result within {}h — \
                     is noo-hostd running? `systemctl --user status noo-hostd`, then \
                     `journalctl --user -u noo-hostd`",
                    RESULT_DEADLINE_SECS / 3600
                ),
            }
        } else {
            Verdict::Pending
        };
    };

    if !res.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        let stderr: String = res.get("stderr").and_then(Value::as_str).unwrap_or("").chars().take(300).collect();
        return Verdict::Failed { error: format!("Database backup FAILED — {stderr}") };
    }

    let took = res
        .get("duration_ms")
        .and_then(Value::as_u64)
        .map(|ms| format!("{}s", ms / 1000))
        .unwrap_or_else(|| format!("{}s since queued", elapsed.num_seconds().max(0)));
    let reported = res.get("bytes").and_then(Value::as_u64);

    // `artifact` ABSENT means an older noo-hostd that never reports one. A new
    // hostd always names the dump on success, so a key that is present but
    // empty (or not a string) is a backup that produced nothing: a failure.
    let Some(artifact) = res.get("artifact") else {
        // Say so rather than claim a verification that did not happen.
        return Verdict::Succeeded {
            text: format!(
                "Database backup: OK in {took} — pg dump written to the host backup dir \
                 (NOO_BACKUP_DIR, 7-day retention). Dump path and size NOT verified: this \
                 noo-hostd does not report them; upgrade it."
            ),
        };
    };
    let Some(path) = artifact.as_str().filter(|p| !p.is_empty()) else {
        return Verdict::Failed {
            error: "Database backup FAILED — noo-hostd reported success but named no dump file".to_string(),
        };
    };

    let size = match (visible_size(path), reported) {
        (Some(n), _) => n,
        (None, Some(n)) => n,
        (None, None) => {
            return Verdict::Succeeded {
                text: format!("Database backup: OK in {took} — {path} (size not reported, file not visible to the gateway)"),
            };
        }
    };
    if size == 0 {
        return Verdict::Failed { error: format!("Database backup FAILED — the dump is empty: {path}") };
    }
    Verdict::Succeeded { text: format!("Database backup: OK in {took} — {path} ({})", human_size(size)) }
}

/// A queued backup run, as read back from `noo_heartbeat_runs`.
#[derive(Debug, Clone)]
pub struct PendingRun {
    pub run_id: String,
    pub task_id: String,
    pub started_at: DateTime<Utc>,
    pub result_path: String,
}

/// The alert a verdict calls for: a real failure (the dump failed, or no result
/// by the deadline) and nothing else. A pending or successful backup, however
/// slow, alerts nobody.
pub fn alert_for(verdict: &Verdict, run: &PendingRun) -> Option<OperatorAlert> {
    match verdict {
        Verdict::Failed { error } => Some(failure_alert(run, error)),
        Verdict::Pending | Verdict::Succeeded { .. } => None,
    }
}

/// The alert a failed backup raises. One place, so the cooldown scope and the
/// investigation command cannot drift between the two failure kinds.
pub fn failure_alert(run: &PendingRun, error: &str) -> OperatorAlert {
    OperatorAlert::new(
        ALERT_KIND,
        &run.task_id,
        format!("❌ Database backup FAILED (run `{}`). No usable dump was confirmed.", run.run_id),
    )
    .detail(error.to_string())
    .investigate(format!("noo heartbeat history --task-id {} --limit 5", run.task_id))
}

/// Park a run that was just queued: it stays `running`, and its text names the
/// result file. Returns whether the row was updated (it must exist and still
/// be `running`).
pub async fn park_run(db: &sqlx::PgPool, run_id: &str, queued_text: &str) -> Result<bool, sqlx::Error> {
    let n = sqlx::query("UPDATE noo_heartbeat_runs SET result_text = $2 WHERE run_id = $1 AND status = 'running'")
        .bind(run_id)
        .bind(queued_text)
        .execute(db)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// Finish the pending run `run_id` with its verdict. Returns whether THIS call
/// finished it: the `WHERE` demands the run is still pending, so a second
/// settle (a racing tick, a replica) changes nothing and alerts nothing.
async fn finish(
    db: &sqlx::PgPool,
    run: &PendingRun,
    now: DateTime<Utc>,
    status: &str,
    text: &str,
    error: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let ms = (now - run.started_at).num_milliseconds().clamp(0, i32::MAX as i64) as i32;
    let n = sqlx::query(
        "UPDATE noo_heartbeat_runs SET status = $2, completed_at = $3, result_text = $4, error = $5, \
                duration_ms = $6 \
         WHERE run_id = $1 AND status = 'running' AND result_text LIKE $7",
    )
    .bind(&run.run_id)
    .bind(status)
    .bind(now)
    .bind(text)
    .bind(error)
    .bind(ms)
    .bind(format!("{PENDING_MARKER}%"))
    .execute(db)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Judge one pending run and record the outcome on THAT run. Returns the alert
/// to send, if this call recorded a failure.
pub async fn settle(
    db: &sqlx::PgPool,
    run: &PendingRun,
    now: DateTime<Utc>,
    result: Option<&Value>,
    visible_size: &(dyn Fn(&str) -> Option<u64> + Sync),
) -> Result<Option<OperatorAlert>, sqlx::Error> {
    let verdict = judge(result, now - run.started_at, visible_size);
    let recorded = match &verdict {
        Verdict::Pending => return Ok(None),
        Verdict::Succeeded { text } => finish(db, run, now, "success", text, None).await?,
        Verdict::Failed { error } => finish(db, run, now, "error", "", Some(error)).await?,
    };
    // Only the call that recorded the outcome alerts, so a second pass is quiet.
    Ok(if recorded { alert_for(&verdict, run) } else { None })
}

fn on_disk_size(path: &str) -> Option<u64> {
    std::fs::metadata(path).ok().filter(|m| m.is_file()).map(|m| m.len())
}

/// One pass over every pending backup run.
pub async fn tick(state: &Arc<AppState>) -> anyhow::Result<()> {
    let rows: Vec<(String, String, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT run_id, task_id, started_at, result_text FROM noo_heartbeat_runs \
         WHERE action = $1 AND status = 'running' AND result_text LIKE $2",
    )
    .bind(ACTION)
    .bind(format!("{PENDING_MARKER}%"))
    .fetch_all(&state.db)
    .await?;
    for (run_id, task_id, started_at, text) in rows {
        let Some(path) = pending_result_path(&text) else { continue };
        let run = PendingRun { run_id, task_id, started_at, result_path: path.to_string() };
        // A missing or half-written file is "not yet"; the next tick re-reads.
        let result: Option<Value> = tokio::fs::read_to_string(&run.result_path)
            .await
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok());
        if let Some(alert) = offsite_undecided_alert(result.as_ref(), &run.task_id) {
            crate::operator_alert::send_operator_alert_with(state, alert, OFFSITE_ALERT_COOLDOWN_SECS).await;
        }
        match settle(&state.db, &run, Utc::now(), result.as_ref(), &on_disk_size).await {
            Ok(Some(alert)) => {
                tracing::warn!(run_id = %run.run_id, task_id = %run.task_id, "database_backup_failed");
                crate::operator_alert::send_operator_alert_with(state, alert, ALERT_COOLDOWN_SECS).await;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(run_id = %run.run_id, error = %e, "database_backup_settle_failed"),
        }
    }
    Ok(())
}

/// Start the completion loop. `ManagedLoop` stamps `loop_health::record_tick`
/// each cycle, so a dead hook is visible on `/api/agent/loops`.
pub fn spawn(state: Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new(LOOP_NAME, POLL_INTERVAL_SECS)
        .immediate_first_tick()
        .spawn(state, |state| async move { tick(&state).await });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cant_see(_: &str) -> Option<u64> {
        None
    }
    fn mins(n: i64) -> Duration {
        Duration::minutes(n)
    }

    #[test]
    fn the_pending_marker_round_trips_and_nothing_else_parses() {
        let t = pending_text("/spool/1-ab.result.json");
        assert_eq!(pending_result_path(&t), Some("/spool/1-ab.result.json"));
        assert_eq!(pending_result_path("Database backup: OK"), None);
        assert_eq!(pending_result_path(PENDING_MARKER), None, "a marker with no path is not pending");
    }

    #[test]
    fn no_result_yet_is_pending_not_failed() {
        assert_eq!(judge(None, mins(5), &cant_see), Verdict::Pending);
        // hostd's own "still going" status is not a result either
        let running = json!({"ok": true, "status": "running"});
        assert_eq!(judge(Some(&running), mins(5), &cant_see), Verdict::Pending);
    }

    #[test]
    fn ok_true_succeeds_with_path_size_and_duration() {
        let r = json!({"ok": true, "status": "done", "artifact": "/b/pg.sql.gz.enc", "bytes": 3_145_728u64, "duration_ms": 130_000u64});
        match judge(Some(&r), mins(3), &cant_see) {
            Verdict::Succeeded { text } => {
                assert!(text.contains("/b/pg.sql.gz.enc"), "{text}");
                assert!(text.contains("3.0 MiB"), "{text}");
                assert!(text.contains("130s"), "{text}");
            }
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn a_dump_the_gateway_can_see_is_measured_not_trusted() {
        // hostd claims a size, the file on disk says empty: the file wins.
        let r = json!({"ok": true, "artifact": "/b/pg.enc", "bytes": 999u64});
        let v = judge(Some(&r), mins(1), &|_| Some(0));
        assert!(matches!(v, Verdict::Failed { ref error } if error.contains("empty")), "{v:?}");
        // and the on-disk size is the one reported
        match judge(Some(&r), mins(1), &|_| Some(2048)) {
            Verdict::Succeeded { text } => assert!(text.contains("2.0 KiB"), "{text}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_empty_dump_hostd_reports_is_a_failure_even_when_unseen() {
        let r = json!({"ok": true, "artifact": "/b/pg.enc", "bytes": 0u64});
        assert!(matches!(judge(Some(&r), mins(1), &cant_see), Verdict::Failed { .. }));
    }

    #[test]
    fn an_old_hostd_with_no_artifact_succeeds_but_says_it_did_not_verify() {
        let r = json!({"ok": true, "status": "done"});
        match judge(Some(&r), mins(2), &cant_see) {
            Verdict::Succeeded { text } => assert!(text.contains("NOT verified"), "{text}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_new_hostd_ok_with_an_empty_or_null_artifact_is_a_failure_not_unverified() {
        for bad in [json!(""), json!(null), json!(42)] {
            let r = json!({"ok": true, "status": "done", "artifact": bad});
            let v = judge(Some(&r), mins(2), &cant_see);
            assert!(matches!(&v, Verdict::Failed { error } if error.contains("named no dump")), "{v:?}");
            assert!(alert_for(&v, &a_run()).is_some(), "a backup that produced nothing must alert");
        }
    }

    #[test]
    fn ok_false_fails_with_hostds_stderr() {
        let r = json!({"ok": false, "rc": 1, "stderr": "ERROR: no NOO_BACKUP_PASSPHRASE"});
        match judge(Some(&r), mins(1), &cant_see) {
            Verdict::Failed { error } => assert!(error.contains("no NOO_BACKUP_PASSPHRASE"), "{error}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn no_result_past_the_deadline_fails_and_before_it_does_not() {
        let before = Duration::seconds(RESULT_DEADLINE_SECS - 60);
        let after = Duration::seconds(RESULT_DEADLINE_SECS + 60);
        assert_eq!(judge(None, before, &cant_see), Verdict::Pending);
        match judge(None, after, &cant_see) {
            Verdict::Failed { error } => assert!(error.contains("no result within 2h"), "{error}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_slow_but_in_deadline_success_is_a_success_with_no_alert() {
        // 100 minutes after queueing: far past the old 120 s wait, inside the deadline.
        let r = json!({"ok": true, "artifact": "/b/pg.enc", "bytes": 5_000_000u64, "duration_ms": 6_000_000u64});
        let v = judge(Some(&r), mins(100), &cant_see);
        assert!(matches!(v, Verdict::Succeeded { .. }), "{v:?}");
    }

    #[test]
    fn the_runs_text_states_the_offsite_outcome_on_success_and_failure() {
        let ok = json!({"ok": true, "artifact": "/b/pg.enc", "bytes": 5_000_000u64, "duration_ms": 1000u64,
                        "offsite": "copied 1 artifact(s) to dir:/mnt/x"});
        match judge(Some(&ok), mins(2), &cant_see) {
            Verdict::Succeeded { text } => assert!(text.ends_with("; off-site: copied 1 artifact(s) to dir:/mnt/x"), "{text}"),
            v => panic!("{v:?}"),
        }
        let undecided = json!({"ok": true, "artifact": "/b/pg.enc", "bytes": 9u64, "duration_ms": 1u64,
                               "offsite": "not decided (noo backups setup)"});
        match judge(Some(&undecided), mins(2), &cant_see) {
            Verdict::Succeeded { text } => assert!(text.contains("off-site: not decided"), "{text}"),
            v => panic!("{v:?}"),
        }
        let bad = json!({"ok": false, "stderr": "offsite: FAILED", "offsite": "FAILED: /mnt/x missing"});
        match judge(Some(&bad), mins(2), &cant_see) {
            Verdict::Failed { error } => assert!(error.contains("off-site: FAILED: /mnt/x missing"), "{error}"),
            v => panic!("{v:?}"),
        }
        // An older hostd sends no outcome: the text is unchanged.
        let old = json!({"ok": true, "artifact": "/b/pg.enc", "bytes": 9u64, "duration_ms": 1u64});
        match judge(Some(&old), mins(2), &cant_see) {
            Verdict::Succeeded { text } => assert!(!text.contains("off-site")),
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn only_an_undecided_offsite_nudges_and_none_set_on_purpose_stays_quiet() {
        let undecided = json!({"ok": true, "offsite": "not decided (noo backups setup)"});
        let a = offsite_undecided_alert(Some(&undecided), "database_backup").expect("undecided must nudge");
        assert_eq!(a.kind, OFFSITE_ALERT_KIND);
        assert_eq!(a.target, "database_backup", "cooldown is scoped per task");
        assert_eq!(a.investigate.as_deref(), Some("noo backups setup"));
        assert_eq!(OFFSITE_ALERT_COOLDOWN_SECS, 7 * 86_400);
        for quiet in ["declined (recorded as accepted)", "copied 1 artifact(s) to dir:/x", "portable — nothing copied"] {
            let r = json!({"ok": true, "offsite": quiet});
            assert!(offsite_undecided_alert(Some(&r), "database_backup").is_none(), "{quiet}");
        }
        let running = json!({"status": "running", "offsite": "not decided"});
        assert!(offsite_undecided_alert(Some(&running), "database_backup").is_none());
        assert!(offsite_undecided_alert(None, "database_backup").is_none());
    }

    fn a_run() -> PendingRun {
        PendingRun { run_id: "r1".into(), task_id: "database_backup".into(), started_at: Utc::now(), result_path: "p".into() }
    }

    #[test]
    fn a_failed_dump_alerts() {
        let r = json!({"ok": false, "stderr": "pg_dump: connection refused"});
        let v = judge(Some(&r), mins(2), &cant_see);
        let a = alert_for(&v, &a_run()).expect("ok=false must raise the alert");
        assert!(a.detail.contains("connection refused"));
    }

    #[test]
    fn silence_past_the_deadline_alerts() {
        let v = judge(None, Duration::seconds(RESULT_DEADLINE_SECS + 1), &cant_see);
        assert!(alert_for(&v, &a_run()).is_some());
    }

    #[test]
    fn pending_and_slow_successful_backups_never_alert() {
        let slow_ok = json!({"ok": true, "artifact": "/b/pg.enc", "bytes": 9u64, "duration_ms": 6_000_000u64});
        let at_100_minutes = mins(100);
        assert!(alert_for(&judge(Some(&slow_ok), at_100_minutes, &cant_see), &a_run()).is_none());
        assert!(alert_for(&judge(None, at_100_minutes, &cant_see), &a_run()).is_none(), "still inside the deadline");
        let running = json!({"ok": true, "status": "running"});
        assert!(alert_for(&judge(Some(&running), at_100_minutes, &cant_see), &a_run()).is_none());
    }

    #[test]
    fn the_failure_alert_is_the_funnels_kind_scoped_to_the_task() {
        let a = failure_alert(&a_run(), "boom");
        assert_eq!(a.kind, ALERT_KIND);
        assert_eq!(a.target, "database_backup", "cooldown is scoped per task");
        assert_eq!(a.detail, "boom", "evidence is carried to the log, not the summary");
        assert!(!a.summary.contains("boom"));
        assert!(a.investigate.as_deref().unwrap_or("").starts_with("noo heartbeat history"));
    }

    /// The wiring, pinned the way this tree pins it: the completion loop is
    /// started from main, the orphan sweep spares pending rows, and BOTH run
    /// paths (cron tick, run-now) park a pending outcome rather than record it.
    #[test]
    fn the_hook_is_wired_into_startup_the_sweep_and_both_run_paths() {
        let main = include_str!("main.rs");
        assert!(main.contains("backup_completion::spawn(state.clone())"), "main must start the completion loop");
        assert!(main.contains("mod backup_completion;"));
        let hl = include_str!("heartbeat_loop.rs");
        assert!(hl.contains("backup_completion::PENDING_MARKER"), "the orphan sweep must spare pending backups");
        assert!(hl.contains("backup_completion::park_run"), "the cron path must park, not complete, a queued backup");
        let intel = include_str!("routes/intelligence.rs");
        assert!(intel.contains("backup_completion::park_run"), "run-now must park, not complete, a queued backup");
    }

    // ── DB-backed: the SAME run is finished (skipped without NOO_BROKER_TEST_DSN) ──

    async fn seed_pending(db: &sqlx::PgPool, run_id: &str, started_at: DateTime<Utc>) -> PendingRun {
        sqlx::query("INSERT INTO noo_heartbeat_tasks (id, name, schedule, action, config, enabled) VALUES ('database_backup', 'b', '30 3 * * *', 'database_backup', '{}', true) ON CONFLICT DO NOTHING")
            .execute(db).await.unwrap();
        crate::repo::heartbeat::record_run_start(db, run_id, "database_backup", "b", "database_backup", started_at).await.unwrap();
        let path = "/spool/x.result.json";
        assert!(park_run(db, run_id, &pending_text(path)).await.unwrap());
        PendingRun { run_id: run_id.into(), task_id: "database_backup".into(), started_at, result_path: path.into() }
    }

    async fn row(db: &sqlx::PgPool, run_id: &str) -> (String, String, Option<String>) {
        sqlx::query_as("SELECT status, COALESCE(result_text, ''), error FROM noo_heartbeat_runs WHERE run_id = $1")
            .bind(run_id).fetch_one(db).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_queued_run_stays_running_until_the_result_lands_then_that_run_succeeds() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("bk_ok").await else { return };
        let now = Utc::now();
        let run = seed_pending(&db, "run-ok", now - mins(4)).await;
        assert_eq!(row(&db, "run-ok").await.0, "running", "queued is not a success");
        // no result yet: nothing changes, nothing alerts
        assert!(settle(&db, &run, now, None, &cant_see).await.unwrap().is_none());
        assert_eq!(row(&db, "run-ok").await.0, "running");
        // the result lands
        let res = json!({"ok": true, "artifact": "/b/pg.enc", "bytes": 4096u64, "duration_ms": 200_000u64});
        assert!(settle(&db, &run, now, Some(&res), &cant_see).await.unwrap().is_none(), "success must not alert");
        let (status, text, err) = row(&db, "run-ok").await;
        assert_eq!(status, "success");
        assert!(text.contains("/b/pg.enc") && text.contains("4.0 KiB") && text.contains("200s"), "{text}");
        assert!(err.is_none());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM noo_heartbeat_runs WHERE action = 'database_backup'").fetch_one(&db).await.unwrap();
        assert_eq!(n, 1, "the same run was finished, no second row");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_result_fails_that_run_and_raises_the_alert_once() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("bk_fail").await else { return };
        let now = Utc::now();
        let run = seed_pending(&db, "run-bad", now - mins(2)).await;
        let res = json!({"ok": false, "stderr": "pg_dump: connection refused"});
        let alert = settle(&db, &run, now, Some(&res), &cant_see).await.unwrap();
        assert_eq!(alert.expect("a failed dump must alert").kind, ALERT_KIND);
        let (status, _, err) = row(&db, "run-bad").await;
        assert_eq!(status, "error");
        assert!(err.unwrap().contains("connection refused"));
        // settled once: a second pass over the same evidence changes and alerts nothing
        assert!(settle(&db, &run, now, Some(&res), &cant_see).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_result_past_the_deadline_fails_the_run_with_an_alert() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("bk_late").await else { return };
        let now = Utc::now();
        let run = seed_pending(&db, "run-late", now - Duration::seconds(RESULT_DEADLINE_SECS + 120)).await;
        let alert = settle(&db, &run, now, None, &cant_see).await.unwrap();
        assert!(alert.is_some(), "silence past the deadline must alert");
        assert_eq!(row(&db, "run-late").await.0, "error");
    }
}
