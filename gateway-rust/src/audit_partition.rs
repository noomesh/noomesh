// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Audit partition lifecycle — startup hook.
//!
//! `noo_security_audit` is a Postgres-level partitioned table (RANGE on
//! `timestamp`, monthly). At startup we ensure the current month and
//! next month partitions exist so inserts never fail with "no partition
//! for this range".
//!
//! Mirrors `gateway/audit_archive.py::ensure_current_and_next` — that
//! Python version was called from the Python lifespan, which doesn't run
//! in production (Rust gateway owns the port). This Rust version
//! restores the behavior.
//!
//! Future work (Tier 3 followup): port `export_partition` and
//! `drop_partition` to a heartbeat task once the heartbeat loop is
//! soaked. Today the Python `audit_archive.py` exporter remains as the
//! reference implementation (Tier 4 — live library marker).

use chrono::Datelike;

use crate::state::AppState;

/// Ensure partitions exist for current month + next month. Returns the
/// number of partitions created (0, 1, or 2).
///
/// Errors are logged, not fatal: a partition failure must not stop the
/// gateway booting. But the old comment here promised that "the next audit
/// insert will fail loudly if a partition is genuinely missing", and that
/// was never true — `audit_event` discarded its result, so the insert
/// failed in total silence. The loudness now lives where it belongs, in
/// `routes::core::audit_insert`, which logs a lost audit row at `error!`
/// and heals the partition itself. This hook is the fast path, not the
/// guarantee.
pub async fn ensure_current_and_next(state: &AppState) -> usize {
    let now = chrono::Utc::now();
    let cur_year = now.year();
    let cur_month = now.month();
    let (next_year, next_month) = if cur_month == 12 {
        (cur_year + 1, 1u32)
    } else {
        (cur_year, cur_month + 1)
    };

    let mut created = 0usize;
    for (y, m) in [(cur_year, cur_month), (next_year, next_month)] {
        match ensure_partition(state, y, m as i32).await {
            Ok(true) => created += 1,
            Ok(false) => {} // already existed
            Err(e) => {
                tracing::warn!(year = y, month = m, error = %e, "audit_partition_ensure_failed");
            }
        }
    }
    if created > 0 {
        tracing::info!(created, "audit_partitions_ensured");
    }
    created
}

/// Ensure the monthly partition exists, via a SECURITY DEFINER function.
///
/// This used to run `CREATE TABLE ... PARTITION OF` directly, which only worked
/// because the gateway connected as a superuser — exactly what migration 033
/// exists to end. `noo_app` has no CREATE on the schema, and granting it would
/// let the role create any table at all.
///
/// `noo_ensure_audit_partition` (migration 036) runs as its owner and builds
/// the partition name internally from the year/month integers, so the caller
/// cannot name an arbitrary table or re-parent the partition. The existence
/// check lives inside the function too, so this is one round trip and there is
/// no check-then-create race between two gateway instances.
async fn ensure_partition(state: &AppState, year: i32, month: i32) -> Result<bool, sqlx::Error> {
    ensure_partition_on(&state.db, year, month).await
}

/// UNQUALIFIED, deliberately. This call used to name `public.` explicitly,
/// which was the whole bug: a fresh install puts the mesh schema — tables
/// AND functions — in `mesh`, so `public.noo_ensure_audit_partition` did
/// not exist, every startup logged one `audit_partition_ensure_failed`
/// warning, no partition was ever created, and the audit log was dead for
/// the life of the install.
///
/// Every other runtime query in the gateway is unqualified and resolves
/// through the `search_path` the pool pins in `state.rs`
/// (`mesh,public,trellion,evolve`), which is what makes one binary serve
/// both the fresh and the legacy layout. This was the only runtime query
/// that opted out of that, and it opted out of the only thing that made it
/// portable. `usage::record` calls its twin unqualified and was unaffected.
pub(crate) async fn ensure_partition_on(
    db: &sqlx::PgPool,
    year: i32,
    month: i32,
) -> Result<bool, sqlx::Error> {
    let created: bool = sqlx::query_scalar("SELECT noo_ensure_audit_partition($1, $2)")
        .bind(year)
        .bind(month)
        .fetch_one(db)
        .await?;
    if created {
        tracing::info!(year, month, "audit_partition_created");
    }
    Ok(created)
}

/// Heal path for a write that just hit a missing partition: ensure this
/// month and next, best-effort, so the caller can retry.
///
/// Separate from [`ensure_current_and_next`] only because that one takes an
/// `AppState` and the audit writer has a bare pool — the audit path is
/// reached from places with no `AppState` in hand.
pub(crate) async fn ensure_for_heal(db: &sqlx::PgPool) {
    let now = chrono::Utc::now();
    let (y, m) = (now.year(), now.month() as i32);
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    for (year, month) in [(y, m), (ny, nm)] {
        if let Err(e) = ensure_partition_on(db, year, month).await {
            tracing::error!(year, month, error = %e, "audit_partition_heal_failed");
        }
    }
}

#[cfg(test)]
mod tests {
    /// The startup hook must work on a FRESH install, where the mesh schema
    /// — tables and functions alike — lives in `mesh` rather than `public`.
    ///
    /// This is the regression that killed the audit log: the call named
    /// `public.noo_ensure_audit_partition` explicitly, so on a fresh install
    /// it resolved to nothing, the failure was logged once as a warning at
    /// startup, and every later audit insert was discarded because no
    /// partition existed. Re-adding the qualifier fails this test with
    /// "function public.noo_ensure_audit_partition(integer, integer) does
    /// not exist".
    ///
    /// Gated on NOO_BROKER_TEST_DSN like the other real-catalogue suites; a
    /// mock cannot answer a question about schema resolution.
    #[tokio::test]
    async fn the_startup_hook_resolves_the_function_on_a_fresh_mesh_layout() {
        let Some(dsn) = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty())
        else {
            return;
        };
        const DB: &str = "audit_partition_layout_test";
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&dsn)
            .await
            .expect("connect to NOO_BROKER_TEST_DSN");
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {DB} (FORCE)")))
            .execute(&admin)
            .await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {DB}")))
            .execute(&admin)
            .await
            .expect("create scratch db");
        let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
        let scratch_dsn = format!("{head}/{DB}");

        let build = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&scratch_dsn)
            .await
            .expect("connect scratch");
        unsafe { std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret") };
        for ext in ["vector", "pg_trgm"] {
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}")))
                .execute(&build)
                .await
                .expect("extension");
        }
        crate::mesh_migrate::apply(&build).await.expect("apply migrations");
        build.close().await;

        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&scratch_dsn)
            .expect("scratch dsn")
            // The search_path `state.rs` pins. The point of the test is that
            // the call relies on THIS and nothing else.
            .options([("search_path", "mesh,public,trellion,evolve")]);
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(opts)
            .await
            .expect("connect scratch");

        // The precondition that made the bug possible, asserted so the test
        // cannot quietly become vacuous if the layout ever changes.
        let schema: String = sqlx::query_scalar(
            "SELECT n.nspname FROM pg_proc p \
             JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE p.proname = 'noo_ensure_audit_partition'",
        )
        .fetch_one(&db)
        .await
        .expect("the function must exist somewhere");
        assert_eq!(
            schema, "mesh",
            "a fresh install puts the function in `mesh`; that is why a \
             `public.`-qualified call cannot find it"
        );

        // First call creates, second is idempotent.
        let created = super::ensure_partition_on(&db, 2026, 9)
            .await
            .expect("a fresh mesh-layout install must resolve the function");
        assert!(created, "the first call creates this month's partition");
        let again = super::ensure_partition_on(&db, 2026, 9)
            .await
            .expect("second call must succeed");
        assert!(!again, "the second call is a no-op, not a duplicate");

        db.close().await;
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {DB} (FORCE)")))
            .execute(&admin)
            .await;
    }
}
