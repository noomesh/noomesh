// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Heartbeat tasks and run history — `noo_heartbeat_tasks`, `noo_heartbeat_runs`.
//!
//! Neither table carries `user_id`/`org_id`, so unlike the other modules here
//! this one buys no tenant scoping. It is a maintenance consolidation, and the
//! reason is that heartbeat has **two independent write paths for the same
//! event**:
//!
//! - `heartbeat_loop.rs` — the scheduler firing a task on its cron
//! - `routes/intelligence.rs` — an operator triggering the same task manually
//!
//! Both ended with a byte-identical 12-column `INSERT INTO noo_heartbeat_runs`
//! followed by a byte-identical `last_run` update. Twelve *positional* binds
//! duplicated across two files is the `app_version` failure waiting to happen:
//! add a column to one and the other keeps inserting, silently short a field.
//! Positional binds fail quietly in a way named ones do not.
//!
//! Retention had the same split, but worse. The 90-day cutoff was written three
//! times across two files, and `routes/admin.rs` held **both** the dry-run
//! `COUNT(*)` and the real `DELETE`. Drift between those two is not a stale
//! number — it is a dry run that reports one thing and a delete that removes
//! another, which is precisely the check an operator relies on before letting
//! a destructive cleanup proceed. It is now one constant, used by both.
//!
//! ## Call sites decide what a write failure means
//!
//! Errors propagate as `sqlx::Error`; this module never swallows one. The two
//! execution paths then differ deliberately:
//!
//! - the manual route propagates, so the caller sees its own failure;
//! - the scheduler cannot fail the run — the task already executed and its side
//!   effects (a backup taken, a report sent) are done — so it logs and raises an
//!   operator alert instead.
//!
//! Those scheduler writes were `let _ = ...` until the follow-up to this module.
//! That left no trace when a run record failed to write, which makes a task that
//! ran indistinguishable from one that never fired — the #247 shape, where a
//! failure reports as nothing at all.

use serde_json::Value as JsonValue;

/// How long heartbeat run history is kept.
///
/// Previously the literal `INTERVAL '90 days'` in three places. The dry-run
/// count and the delete MUST share this or the preview lies about the deletion.
pub const RUN_RETENTION_DAYS: i32 = 90;

/// How long a staged (pruned) run record stays restorable before the staging
/// row itself is dropped.
///
/// Matches the 30-day window `graph_prune` uses, for the same reason: the point
/// of staging is that somebody can notice a bad prune and undo it, and 30 days
/// is long enough for a monthly review to be that somebody. Making it unbounded
/// would just move the unbounded-growth problem from one table to another.
pub const RUN_PRUNE_RESTORE_DAYS: i32 = 30;

/// A completed heartbeat execution, scheduled or manual.
///
/// Borrowed rather than owned so call sites pass what they already have without
/// cloning result text that can run to thousands of characters.
pub struct RunRecord<'a> {
    pub run_id: &'a str,
    pub task_id: &'a str,
    pub task_name: &'a str,
    pub action: &'a str,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
    pub status: &'a str,
    pub result_text: &'a str,
    /// `None` when the run carried no error. Call sites map an empty string to
    /// `None` so "" and NULL do not both come to mean "no error".
    pub error: Option<&'a str>,
    pub duration_ms: i32,
    pub notified_channels: &'a JsonValue,
    pub artifacts: &'a JsonValue,
}

/// Insert a run record. The single writer for both execution paths.
pub async fn record_run(
    exec: impl sqlx::PgExecutor<'_>,
    r: &RunRecord<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO noo_heartbeat_runs \
            (run_id, task_id, task_name, action, started_at, completed_at, \
             status, result_text, error, duration_ms, notified_channels, artifacts) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        r.run_id,
        r.task_id,
        r.task_name,
        r.action,
        r.started_at,
        r.completed_at,
        r.status,
        r.result_text,
        r.error,
        r.duration_ms,
        r.notified_channels,
        r.artifacts,
    )
    .execute(exec)
    .await?;
    Ok(())
}

/// Insert the run row AT START (status "running", completed_at NULL) so
/// in-flight runs are visible in history instead of only in logs (the
/// 2026-08-28 incident diagnosis needed log-grepping to see whether a run
/// was alive). Runtime-checked query on purpose: the .sqlx offline data
/// does not need regenerating for it.
pub async fn record_run_start(
    exec: impl sqlx::PgExecutor<'_>,
    run_id: &str,
    task_id: &str,
    task_name: &str,
    action: &str,
    started_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO noo_heartbeat_runs             (run_id, task_id, task_name, action, started_at, completed_at,              status, result_text, error, duration_ms, notified_channels, artifacts)          VALUES ($1, $2, $3, $4, $5, NULL, 'running', '', NULL, 0, '[]'::jsonb, '[]'::jsonb)          ON CONFLICT (run_id) DO NOTHING",
    )
    .bind(run_id)
    .bind(task_id)
    .bind(task_name)
    .bind(action)
    .bind(started_at)
    .execute(exec)
    .await?;
    Ok(())
}

/// Complete a run: UPDATE the start row when one exists, else INSERT the
/// full record (covers writers that never made a start row, and the
/// transition window). This replaces direct record_run() at completion
/// sites so a start row can never be left dangling as "running".
pub async fn complete_run(
    exec: impl sqlx::PgExecutor<'_> + Copy,
    r: &RunRecord<'_>,
) -> Result<(), sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE noo_heartbeat_runs SET             completed_at = $2, status = $3, result_text = $4, error = $5,             duration_ms = $6, notified_channels = $7, artifacts = $8          WHERE run_id = $1",
    )
    .bind(r.run_id)
    .bind(r.completed_at)
    .bind(r.status)
    .bind(r.result_text)
    .bind(r.error)
    .bind(r.duration_ms)
    .bind(r.notified_channels)
    .bind(r.artifacts)
    .execute(exec)
    .await?
    .rows_affected();
    if updated == 0 {
        record_run(exec, r).await?;
    }
    Ok(())
}

/// Stamp when a task last started. Called by both execution paths.
pub async fn set_last_run(
    exec: impl sqlx::PgExecutor<'_>,
    task_id: &str,
    started_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE noo_heartbeat_tasks SET last_run = $1, updated_at = NOW() WHERE id = $2",
        started_at,
        task_id,
    )
    .execute(exec)
    .await?;
    Ok(())
}

/// Stamp the next scheduled fire time.
pub async fn set_next_run(
    exec: impl sqlx::PgExecutor<'_>,
    task_id: &str,
    next_run: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE noo_heartbeat_tasks SET next_run = $1, updated_at = NOW() WHERE id = $2",
        next_run,
        task_id,
    )
    .execute(exec)
    .await?;
    Ok(())
}

/// Enable or disable a task.
///
/// Replaces both the parameterised form in `routes/intelligence.rs` and the two
/// hardcoded `SET enabled = false` sites (the scheduler disabling a task whose
/// cron will not parse, and `agent_meta_loop` retiring one).
///
/// Returns rows affected: the toggle route distinguishes "updated" from "no such
/// task" by that count, and returning it here keeps that site from needing raw
/// SQL just to see it.
pub async fn set_enabled(
    exec: impl sqlx::PgExecutor<'_>,
    task_id: &str,
    enabled: bool,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE noo_heartbeat_tasks SET enabled = $1, updated_at = NOW() WHERE id = $2",
        enabled,
        task_id,
    )
    .execute(exec)
    .await?;
    Ok(res.rows_affected())
}

/// Create or update a task definition.
///
/// Both the REST save handler and the `noo_heartbeat_create_task` tool wrote
/// this same nine-column upsert verbatim, including the `next_run` reset — so
/// the rule "editing a schedule must clear `next_run`" lived in two places. It
/// is not an obvious rule: without it a schedule edit does not take effect until
/// after the task fires once more on the OLD schedule, because the tick loop
/// only recomputes `next_run` after a firing.
///
/// The two call sites differ only in their pre-checks (the tool guards against
/// clobbering a different task with the same id); those stay at the call sites.
///
/// NB: no SQL `--` comments in this literal. Rust's `\` line-continuation
/// collapses it to one line and `--` would then comment out everything after it.
pub async fn upsert_task(
    exec: impl sqlx::PgExecutor<'_>,
    t: &TaskDef<'_>,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!(
        "INSERT INTO noo_heartbeat_tasks \
            (id, name, schedule, action, config, channels, recipients, enabled, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT(id) DO UPDATE SET \
            name = EXCLUDED.name, schedule = EXCLUDED.schedule, action = EXCLUDED.action, \
            config = EXCLUDED.config, channels = EXCLUDED.channels, recipients = EXCLUDED.recipients, \
            enabled = EXCLUDED.enabled, updated_at = NOW(), \
            next_run = CASE \
                WHEN noo_heartbeat_tasks.schedule IS DISTINCT FROM EXCLUDED.schedule THEN NULL \
                ELSE noo_heartbeat_tasks.next_run \
            END",
        t.id,
        t.name,
        t.schedule,
        t.action,
        t.config,
        t.channels,
        t.recipients,
        t.enabled,
        t.created_by,
    )
    .execute(exec)
    .await?;
    Ok(res.rows_affected())
}

/// Change ONLY a task's schedule. Returns `None` for an unknown task, else the
/// task's `next_run` after the write.
///
/// `next_run` is cleared when the schedule actually changes (the same rule as
/// [`upsert_task`]: the tick loop reseats it from the new cron) and left alone
/// when the value is the one already stored. Name, action, config, channels,
/// recipients and enabled are not touched, which is the point: re-adding a task
/// to move its schedule upserts the whole row and blanks what the caller did
/// not repeat.
///
/// Runtime query, not `query!`: it takes no offline-cache entry.
pub async fn set_schedule(
    exec: impl sqlx::PgExecutor<'_>,
    task_id: &str,
    schedule: &str,
) -> Result<Option<Option<chrono::DateTime<chrono::Utc>>>, sqlx::Error> {
    let row: Option<(Option<chrono::DateTime<chrono::Utc>>,)> = sqlx::query_as(
        "UPDATE noo_heartbeat_tasks SET schedule = $1, updated_at = NOW(), \
            next_run = CASE WHEN schedule IS DISTINCT FROM $1 THEN NULL ELSE next_run END \
         WHERE id = $2 RETURNING next_run",
    )
    .bind(schedule)
    .bind(task_id)
    .fetch_optional(exec)
    .await?;
    Ok(row.map(|(n,)| n))
}

/// A heartbeat task definition as supplied by an operator or a tool call.
pub struct TaskDef<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub schedule: &'a str,
    pub action: &'a str,
    pub config: &'a JsonValue,
    pub channels: &'a JsonValue,
    pub recipients: &'a JsonValue,
    pub enabled: bool,
    pub created_by: &'a str,
}

/// Delete a task. `noo_heartbeat_runs` rows cascade.
pub async fn delete_task(
    exec: impl sqlx::PgExecutor<'_>,
    task_id: &str,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!("DELETE FROM noo_heartbeat_tasks WHERE id = $1", task_id)
        .execute(exec)
        .await?;
    Ok(res.rows_affected())
}

/// How many run records are past retention — the dry-run preview.
pub async fn count_expired_runs(exec: impl sqlx::PgExecutor<'_>) -> Result<i64, sqlx::Error> {
    let n = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM noo_heartbeat_runs \
         WHERE started_at < NOW() - make_interval(days => $1)",
        RUN_RETENTION_DAYS,
    )
    .fetch_one(exec)
    .await?;
    // COUNT(*) is never NULL; sqlx types the aggregate as Option regardless.
    Ok(n.unwrap_or(0))
}

/// Prune run records past retention: stage the whole row, then delete it.
///
/// Shares [`RUN_RETENTION_DAYS`] with [`count_expired_runs`] so the preview and
/// the prune cannot disagree.
///
/// This replaced a bare `DELETE`. The delete was correct and had never run —
/// nothing scheduled it — so the first thing a schedule would have done is
/// irreversibly remove 1,399 rows nobody had reviewed. `noo_heartbeat_runs` is
/// the only durable evidence that a scheduled task executed, and staging is
/// what makes "we pruned the wrong window" recoverable rather than terminal.
/// Same shape as `graph_prune` (migration 014) and the temporal-edge prune
/// (045); staging table is migration 046.
///
/// Both statements run in ONE transaction, taken here rather than accepted as a
/// parameter: staging and deleting must not be separable. A caller that got
/// them as two executor calls could commit the delete without the snapshot,
/// which is the unstaged hard delete this function exists to eliminate.
///
/// `to_jsonb(hr)` snapshots the whole row, so a column added to
/// `noo_heartbeat_runs` later is carried without touching this code — the
/// alternative, a named-column list, silently stops copying new fields.
///
/// Returns the number of rows pruned.
pub async fn prune_expired_runs(
    db: &sqlx::PgPool,
    prune_run_id: &str,
) -> Result<u64, sqlx::Error> {
    let mut tx = db.begin().await?;

    // A single statement does both halves: the CTE deletes and RETURNING feeds
    // the staging INSERT. Written as one statement rather than SELECT-then-
    // DELETE because the two-statement form can stage a row that a concurrent
    // write has since changed — the snapshot would not match what was removed.
    let res = sqlx::query!(
        "WITH pruned AS ( \
             DELETE FROM noo_heartbeat_runs hr \
              WHERE hr.started_at < NOW() - make_interval(days => $1) \
          RETURNING hr.run_id, hr.task_id, to_jsonb(hr) AS payload \
         ) \
         INSERT INTO noo_heartbeat_run_prune_staging \
             (run_id, task_id, payload, reason, prune_run_id) \
         SELECT p.run_id, p.task_id, p.payload, $2, $3 FROM pruned p",
        RUN_RETENTION_DAYS,
        format!("age > {RUN_RETENTION_DAYS}d"),
        prune_run_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(res.rows_affected())
}

/// Drop staging rows whose restore window has closed.
///
/// Without this the staging table becomes the new unbounded table and the prune
/// has moved the problem rather than solved it. Rows already restored are
/// dropped too — a restored row's snapshot is redundant with the live row.
pub async fn expire_prune_staging(exec: impl sqlx::PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    let res = sqlx::query!(
        "DELETE FROM noo_heartbeat_run_prune_staging \
         WHERE staged_at < NOW() - make_interval(days => $1)",
        RUN_PRUNE_RESTORE_DAYS,
    )
    .execute(exec)
    .await?;
    Ok(res.rows_affected())
}

/// Put staged runs back. `prune_run_id` scopes the restore to one prune tick,
/// which is the only unit an operator can reason about after the fact.
///
/// `ON CONFLICT DO NOTHING` because a run may have been restored already or
/// re-recorded since; a restore must be safe to run twice.
pub async fn restore_pruned_runs(
    db: &sqlx::PgPool,
    prune_run_id: &str,
) -> Result<u64, sqlx::Error> {
    let mut tx = db.begin().await?;

    // jsonb_populate_record rebuilds the row from the snapshot, so this stays
    // correct as noo_heartbeat_runs gains columns — the same reason the prune
    // stores to_jsonb(hr) instead of a column list.
    //
    // The EXISTS guard is load-bearing: noo_heartbeat_runs.task_id references
    // noo_heartbeat_tasks ON DELETE CASCADE, so a task deleted after the prune
    // leaves staged rows with no parent. Without the guard one such orphan
    // raises a foreign-key violation that aborts the whole restore, losing the
    // rows that COULD have come back. Skipping orphans is the recoverable
    // failure; they stay staged and visible.
    let res = sqlx::query!(
        "INSERT INTO noo_heartbeat_runs \
         SELECT (jsonb_populate_record(NULL::noo_heartbeat_runs, s.payload)).* \
           FROM noo_heartbeat_run_prune_staging s \
          WHERE s.prune_run_id = $1 AND s.restored_at IS NULL \
            AND EXISTS (SELECT 1 FROM noo_heartbeat_tasks t WHERE t.id = s.task_id) \
         ON CONFLICT (run_id) DO NOTHING",
        prune_run_id,
    )
    .execute(&mut *tx)
    .await?;

    // Only rows that actually came back are marked restored. Stamping the
    // orphans the EXISTS guard skipped would claim a restore that did not
    // happen and hide them from the next attempt.
    sqlx::query!(
        "UPDATE noo_heartbeat_run_prune_staging s \
            SET restored_at = NOW() \
          WHERE s.prune_run_id = $1 AND s.restored_at IS NULL \
            AND EXISTS (SELECT 1 FROM noo_heartbeat_tasks t WHERE t.id = s.task_id)",
        prune_run_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(res.rows_affected())
}
