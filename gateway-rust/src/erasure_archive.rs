// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The right-to-be-forgotten archive and how long it lives.
//!
//! An erase (`routes/users.rs::erase_account`, `routes/erase_kb.rs`) copies
//! every row it deletes into `noo_user_erasure_staging` first, so a mistaken
//! erase can be undone. That copy is the erased person's data, so it is not
//! kept for ever: **30 days after the erase it is purged, automatically, by
//! this module's daily loop.** Past the window an erase is a delete.
//!
//! The window is a constant, not a setting. It is a promise made to the person
//! erased (the CLI states it, the compliance doc states it), a value that must
//! not be loosened by whoever can edit `noomesh.yaml` or flip a flag, and one
//! that must not be able to read "never". A deployment that wants a SHORTER
//! window gets it by changing the constant in a release, where the change is
//! reviewed; there is deliberately no knob to lengthen it.
//!
//! The loop reports to `loop_health` through `ManagedLoop` like every gateway
//! loop. A purge that errors alerts the operator (`erasure.purge_failed`,
//! cooldown-deduplicated) and the controller's `noo cluster verify
//! --controller` row ("erasure archive") fails when the oldest archived
//! erasure is older than the window plus one day, which is what a purge that
//! is not running looks like from the outside.
//!
//! This module also answers "does this staged row belong to an erased user?"
//! for the graph-prune restore routes ([`user_is_erased`]).

use std::sync::Arc;

use serde_json::{json, Value};
use sqlx::PgPool;

use crate::state::AppState;

/// How long an erased user's archived copy is kept. Never "forever".
pub const RETENTION_DAYS: i64 = 30;

/// The purge runs once a day.
pub const INTERVAL_SECS: u64 = 86_400;

/// The loop's `loop_health` name.
pub const LOOP_NAME: &str = "erasure_purge";

/// Let the gateway finish booting (and the migrations settle) before the
/// first purge; the first run is then immediate, so a gateway restarted more
/// often than daily still purges.
const STARTUP_GRACE_SECS: u64 = 180;

/// A failed purge alerts once a day, not once a tick.
const ALERT_COOLDOWN_SECS: i64 = 86_400;

/// Delete every archived row staged more than `days` days ago. Returns how
/// many went. A restored row goes with the rest: restoring does not extend
/// the window, and the restored data is back in its own store.
pub async fn purge_expired(db: &PgPool, days: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM noo_user_erasure_staging WHERE staged_at < now() - ($1::bigint * interval '1 day')",
    )
    .bind(days)
    .execute(db)
    .await?
    .rows_affected())
}

/// What the archive holds, for `GET /api/security/erasure-archive` and the
/// controller verify row.
pub async fn status(db: &PgPool) -> Result<Value, sqlx::Error> {
    let (rows, runs, oldest_age): (i64, i64, Option<f64>) = sqlx::query_as(
        "SELECT count(*), count(DISTINCT run_id), \
                EXTRACT(EPOCH FROM (now() - min(staged_at)))::float8 \
         FROM noo_user_erasure_staging",
    )
    .fetch_one(db)
    .await?;
    let oldest_staged_at: Option<String> =
        sqlx::query_scalar("SELECT min(staged_at)::text FROM noo_user_erasure_staging").fetch_one(db).await?;
    let (running, detail) = crate::loop_health::liveness(LOOP_NAME);
    Ok(json!({
        "retention_days": RETENTION_DAYS,
        "fail_after_days": RETENTION_DAYS + 1,
        "rows": rows,
        "runs": runs,
        "oldest_staged_at": oldest_staged_at,
        "oldest_age_secs": oldest_age.map(|s| s.max(0.0) as i64),
        "purge_loop": { "running": running, "detail": detail },
    }))
}

/// Does a row staged at `staged_at` for `user_id` belong to an erased user?
///
/// True when the account no longer exists, or when an erase of it ran at or
/// after the row was staged (a kept account that was wiped: what the prune
/// set aside before the wipe is not the user's to have back, but what it sets
/// aside AFTER the wipe is the account's new life). `None` (an unattributed
/// row) is nobody's, so never erased.
pub async fn user_is_erased(
    db: &PgPool,
    user_id: Option<&str>,
    staged_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, sqlx::Error> {
    let Some(user_id) = user_id.filter(|u| !u.is_empty()) else { return Ok(false) };
    sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM noo_users WHERE username = $1) \
             OR EXISTS (SELECT 1 FROM noo_user_erasure_staging WHERE username = $1 AND staged_at >= $2)",
    )
    .bind(user_id)
    .bind(staged_at)
    .fetch_one(db)
    .await
}

async fn tick(state: Arc<AppState>) -> anyhow::Result<()> {
    match purge_expired(&state.db, RETENTION_DAYS).await {
        Ok(0) => Ok(()),
        Ok(n) => {
            tracing::info!(purged = n, retention_days = RETENTION_DAYS, "erasure_archive_purged");
            // The count only: what was purged is somebody's erased data.
            crate::routes::core::audit_event(
                &state.db,
                "erasure_archive_purge",
                "info",
                "system:erasure_purge",
                "noo_user_erasure_staging",
                "ok",
                json!({ "rows_purged": n, "retention_days": RETENTION_DAYS }),
            )
            .await;
            Ok(())
        }
        Err(e) => {
            crate::operator_alert::send_operator_alert_with(
                &state,
                crate::operator_alert::OperatorAlert::new(
                    "erasure.purge_failed",
                    "erasure_archive",
                    format!(
                        "The daily purge of the erasure archive failed; erased users' copies older than {RETENTION_DAYS} days are being kept past their window."
                    ),
                )
                .detail(e.to_string())
                .investigate("noo cluster verify --controller"),
                ALERT_COOLDOWN_SECS,
            )
            .await;
            Err(anyhow::anyhow!("erasure archive purge failed: {e}"))
        }
    }
}

/// Boot wiring: the daily purge on the managed-loop primitive, which stamps
/// `loop_health` on every cycle.
pub fn spawn(state: Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new(LOOP_NAME, INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .immediate_first_tick()
        .spawn(state, tick);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A user's archived rows: one run, staged `age_days` ago.
    async fn stage(db: &PgPool, user: &str, store: &str, age_days: i64) {
        sqlx::query(
            "INSERT INTO noo_user_erasure_staging (run_id, username, store, payload, staged_at) \
             VALUES (gen_random_uuid(), $1, $2, '{}'::jsonb, now() - ($3::bigint * interval '1 day'))",
        )
        .bind(user)
        .bind(store)
        .bind(age_days)
        .execute(db)
        .await
        .unwrap();
    }

    async fn stores(db: &PgPool) -> Vec<String> {
        sqlx::query_scalar("SELECT store FROM noo_user_erasure_staging ORDER BY store").fetch_all(db).await.unwrap()
    }

    /// The operator's decision: the archive keeps an erased
    /// user's copy for 30 days, then it is purged for good.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_purge_deletes_archived_rows_older_than_thirty_days_and_keeps_newer_ones() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("erasure_purge").await else { return };
        assert_eq!(RETENTION_DAYS, 30, "the window the CLI and the compliance doc state");
        stage(&db, "old", "entries", 31).await;
        stage(&db, "old", "kb_docs", 90).await;
        stage(&db, "inside", "entries", 29).await;
        stage(&db, "fresh", "entries", 0).await;
        assert_eq!(purge_expired(&db, RETENTION_DAYS).await.unwrap(), 2, "the two past the window go");
        assert_eq!(stores(&db).await, ["entries", "entries"], "29 days and today stay");
        let left: Vec<String> =
            sqlx::query_scalar("SELECT username FROM noo_user_erasure_staging ORDER BY 1").fetch_all(&db).await.unwrap();
        assert_eq!(left, ["fresh", "inside"]);
        // Idempotent: a second run has nothing to do.
        assert_eq!(purge_expired(&db, RETENTION_DAYS).await.unwrap(), 0);
    }

    /// The verify row reads this: the oldest copy's age, and the window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn status_reports_the_oldest_archived_erasure_and_the_window() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("erasure_status").await else { return };
        let empty = status(&db).await.unwrap();
        assert_eq!(empty["rows"], 0);
        assert!(empty["oldest_age_secs"].is_null(), "nothing archived: no age: {empty}");
        assert_eq!((empty["retention_days"].as_i64(), empty["fail_after_days"].as_i64()), (Some(30), Some(31)));
        stage(&db, "a", "entries", 3).await;
        stage(&db, "b", "entries", 40).await;
        let s = status(&db).await.unwrap();
        assert_eq!(s["rows"], 2);
        let age = s["oldest_age_secs"].as_i64().unwrap();
        assert!((40 * 86_400..40 * 86_400 + 600).contains(&age), "the oldest is 40 days old: {age}");
    }

    /// Every gateway loop reports to loop_health: this one through
    /// `ManagedLoop` (which stamps `record_tick` before each run), spawned at
    /// boot, and never as a bare `tokio::spawn`.
    #[test]
    fn the_purge_loop_is_wired_through_the_loop_health_primitive_and_started_at_boot() {
        let me = include_str!("erasure_archive.rs");
        assert!(me.contains("ManagedLoop::new(LOOP_NAME, INTERVAL_SECS)"), "loop_health coverage comes from ManagedLoop");
        assert_eq!(LOOP_NAME, "erasure_purge");
        assert_eq!(INTERVAL_SECS, 86_400, "daily");
        let main = include_str!("main.rs");
        assert!(main.contains("erasure_archive::spawn(state.clone())"), "main must start the purge");
        assert!(main.contains("\nmod erasure_archive;"));
        // The managed loop is what stamps the registry.
        let ml = include_str!("managed_loop.rs");
        assert!(ml.contains("crate::loop_health::record_tick(name, interval_secs)"));
    }

    /// A failing purge must not read as success: the tick returns the error
    /// (ManagedLoop logs it) after alerting the operator.
    #[test]
    fn a_failed_purge_alerts_and_returns_the_error() {
        let me = include_str!("erasure_archive.rs");
        let tick_src = &me[me.find("async fn tick(").unwrap()..me.find("pub fn spawn(").unwrap()];
        assert!(tick_src.contains("send_operator_alert_with"));
        assert!(tick_src.contains("Err(anyhow::anyhow!"), "an error is returned, not swallowed into Ok");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_staged_row_belongs_to_an_erased_user_when_the_account_is_gone_or_was_wiped_since() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("erasure_is_erased").await else { return };
        use crate::auth::Role;
        let _ = crate::ops::tests::account(&db, "alive", Role::User).await;
        let _ = crate::ops::tests::account(&db, "wiped", Role::User).await;
        let long_ago = chrono::Utc::now() - chrono::TimeDelta::days(10);
        let later = chrono::Utc::now() - chrono::TimeDelta::days(1);
        stage(&db, "wiped", "entries", 5).await; // an erase of `wiped` five days ago, account kept
        assert!(!user_is_erased(&db, Some("alive"), long_ago).await.unwrap(), "a live account, never erased");
        assert!(user_is_erased(&db, Some("gone"), long_ago).await.unwrap(), "no such account any more");
        assert!(user_is_erased(&db, Some("wiped"), long_ago).await.unwrap(), "staged before the wipe");
        assert!(!user_is_erased(&db, Some("wiped"), later).await.unwrap(), "staged after the wipe: the account's new life");
        assert!(!user_is_erased(&db, None, long_ago).await.unwrap(), "an unattributed row is nobody's");
    }
}
