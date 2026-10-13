// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Persisted accountability for the autonomy engine.
//!
//! Until now the engine had readers and no writer. `/api/autonomy/audit`
//! queried `noo_autonomy_audit`, `security.rs` granted on it and two tool
//! definitions described it — and nothing in the tree ever created the table
//! or inserted a row. Every fired action left a tracing line and nothing
//! else, so "what has autonomy actually done" was unanswerable once the log
//! rotated. That mattered more item 15 made four locations
//! able to change the fleet.
//!
//! ## What gets a row
//!
//! Decisions, not heartbeats. A row is written when a location FIRES, when it
//! WOULD have acted but is disarmed, and when it ERRORS. A location that
//! evaluates and finds nothing writes nothing.
//!
//! That is a deliberate bound, not laziness: 19 enabled locations at their
//! configured intervals produce roughly 27,000 evaluations a day, almost all
//! of them "no action needed". Persisting those would bury the handful of
//! rows an operator actually needs and make the table a write-amplifier on
//! every install. `last_check` therefore comes from the loop's in-memory map
//! (see [`crate::autonomy_loop`]), not from here — it is a liveness fact, and
//! it is legitimately lost on restart.
//!
//! ## Why `would` rows are the point
//!
//! A disarmed action logs what it WOULD have done, naming the node, backend
//! or replica count. That is exactly the evidence an operator needs to decide
//! whether to arm it — and it was reachable only by grepping the gateway log.
//! Persisting it turns "should I arm this?" into a question the data answers.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::state::AppState;

/// What happened at a location. Stored as text so a new outcome does not need
/// a migration; read back as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The action ran and changed something.
    Fired,
    /// The condition held and the action is disarmed — this is what it would
    /// have done.
    Would,
    /// The evaluation itself failed. NOT the same as "no action needed": an
    /// unevaluable location is a location that is not watching anything.
    Error,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Fired => "fired",
            Outcome::Would => "would",
            Outcome::Error => "error",
        }
    }
}

/// One decision, ready to persist. `target` is the thing acted on (a node id,
/// a backend, a cert name); `detail` is the human sentence.
pub struct Decision<'a> {
    pub location: &'a str,
    pub action: &'a str,
    pub outcome: Outcome,
    pub target: Option<&'a str>,
    pub detail: &'a str,
    /// Whether the action gate was on. `None` for locations that HAVE no gate
    /// (alert-only ones) — absence must not be rendered as "off", which would
    /// assert a gate that does not exist.
    pub armed: Option<bool>,
    pub dry_run: Option<bool>,
    pub metrics: Option<Value>,
}

/// Persist one decision. Never fails the caller: an autonomy action must not
/// be abandoned because its audit row could not be written, and a gateway on
/// a pre-migration schema must keep running. A failure warns, loudly enough
/// to find, and the action proceeds.
pub async fn record(state: &AppState, d: Decision<'_>) {
    let res = sqlx::query(
        "INSERT INTO noo_autonomy_audit \
             (location, action, outcome, target, detail, armed, dry_run, metrics) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(d.location)
    .bind(d.action)
    .bind(d.outcome.as_str())
    .bind(d.target)
    .bind(d.detail)
    .bind(d.armed)
    .bind(d.dry_run)
    .bind(&d.metrics)
    .execute(&state.db)
    .await;

    if let Err(e) = res {
        tracing::warn!(
            location = %d.location,
            action = %d.action,
            outcome = %d.outcome.as_str(),
            error = %e,
            "autonomy.audit.write_failed — the action still happened; only its record did not"
        );
    }
}

/// Convenience for the common disarmed case.
pub async fn record_would(
    state: &AppState,
    location: &str,
    action: &str,
    target: Option<&str>,
    detail: &str,
) {
    record(
        state,
        Decision {
            location,
            action,
            outcome: Outcome::Would,
            target,
            detail,
            armed: Some(false),
            dry_run: None,
            metrics: None,
        },
    )
    .await;
}

/// Convenience for a fired action.
pub async fn record_fired(
    state: &AppState,
    location: &str,
    action: &str,
    target: Option<&str>,
    detail: &str,
) {
    record(
        state,
        Decision {
            location,
            action,
            outcome: Outcome::Fired,
            target,
            detail,
            armed: Some(true),
            dry_run: Some(false),
            metrics: None,
        },
    )
    .await;
}

/// One row as the API serves it.
#[derive(Debug, sqlx::FromRow)]
pub struct AuditRow {
    pub at: DateTime<Utc>,
    pub location: String,
    pub action: Option<String>,
    pub outcome: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub armed: Option<bool>,
    pub dry_run: Option<bool>,
    pub metrics: Option<Value>,
}

/// Recent decisions, newest first. `location` filters to one location.
/// Returns the sqlx error so the caller can say the store is unreadable
/// rather than serving an empty list — an empty list reads as "autonomy has
/// never acted", which is the lie this whole module exists to remove.
pub async fn recent(
    state: &AppState,
    limit: i64,
    location: Option<&str>,
    outcome: Option<&str>,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    let limit = limit.clamp(1, 500);
    // Both filters belong in SQL, not in the caller. Filtering after the
    // LIMIT would silently under-return — ask for 20 'would' rows, get the
    // handful that happen to be in the newest 20 of everything — and the
    // caller has no way to tell a short page from a quiet week.
    let mut sql = String::from(
        "SELECT at, location, action, outcome, target, detail, armed, dry_run, metrics \
         FROM noo_autonomy_audit",
    );
    let mut clauses: Vec<String> = Vec::new();
    if location.is_some() {
        clauses.push(format!("location = ${}", clauses.len() + 1));
    }
    if outcome.is_some() {
        clauses.push(format!("outcome = ${}", clauses.len() + 1));
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(&format!(" ORDER BY at DESC LIMIT ${}", clauses.len() + 1));

    let mut q = sqlx::query_as::<_, AuditRow>(&sql);
    if let Some(loc) = location {
        q = q.bind(loc);
    }
    if let Some(out) = outcome {
        q = q.bind(out);
    }
    q.bind(limit).fetch_all(&state.db).await
}

/// `{location: last time it FIRED}`. Survives a restart, which is why this
/// comes from the table while `last_check` comes from the loop's memory.
pub async fn last_fired(state: &AppState) -> Result<Vec<(String, DateTime<Utc>)>, sqlx::Error> {
    sqlx::query_as::<_, (String, DateTime<Utc>)>(
        "SELECT location, max(at) FROM noo_autonomy_audit \
         WHERE outcome = 'fired' GROUP BY location",
    )
    .fetch_all(&state.db)
    .await
}

/// How long a decision row is kept. Declared once, here: the CLI and the
/// runbook quote this number, and it is deliberately a constant rather than a
/// setting (same stance as `erasure_archive::RETENTION_DAYS`), so the table
/// cannot be left unbounded by config.
pub const RETENTION_DAYS: i64 = 90;

/// The prune runs once a day.
pub const PRUNE_INTERVAL_SECS: u64 = 86_400;

/// The prune loop's `loop_health` name.
pub const PRUNE_LOOP_NAME: &str = "autonomy_audit_prune";

/// Let the gateway finish booting (and the migrations settle) first.
const STARTUP_GRACE_SECS: u64 = 240;

/// Bound the table: delete every row older than `keep_days`. Run by the
/// daily [`spawn`] loop, not from a migration: retention is an operational
/// policy, and a DELETE inside a migration would run once and never again.
pub async fn prune(db: &sqlx::PgPool, keep_days: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM noo_autonomy_audit WHERE at < now() - ($1::bigint * interval '1 day')",
    )
    .bind(keep_days)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

/// One scheduled prune at the declared retention.
async fn prune_once(db: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
    prune(db, RETENTION_DAYS).await
}

async fn prune_tick(state: std::sync::Arc<AppState>) -> anyhow::Result<()> {
    match prune_once(&state.db).await {
        Ok(0) => Ok(()),
        Ok(n) => {
            tracing::info!(pruned = n, retention_days = RETENTION_DAYS, "autonomy.audit.pruned");
            Ok(())
        }
        // A failing prune is logged by the managed loop (`<name>_error`);
        // the table growing is slow, so no operator alert of its own.
        Err(e) => Err(anyhow::anyhow!("autonomy audit prune failed: {e}")),
    }
}

/// Boot wiring: the daily prune on the managed-loop primitive, which stamps
/// `loop_health` on every cycle.
pub fn spawn(state: std::sync::Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new(PRUNE_LOOP_NAME, PRUNE_INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .immediate_first_tick()
        .spawn(state, prune_tick);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_strings_are_the_stored_values() {
        // The CLI filters and the docs quote these. Changing one is a data
        // migration, not a rename.
        assert_eq!(Outcome::Fired.as_str(), "fired");
        assert_eq!(Outcome::Would.as_str(), "would");
        assert_eq!(Outcome::Error.as_str(), "error");
    }

    #[test]
    fn armed_is_optional_so_absence_is_not_a_negative() {
        // An alert-only location has no gate. Storing `false` would assert
        // one, which reads as "this could act but is off" — a subtler lie
        // than the empty audit list.
        let d = Decision {
            location: "node_health",
            action: "alert",
            outcome: Outcome::Fired,
            target: None,
            detail: "2 nodes offline",
            armed: None,
            dry_run: None,
            metrics: None,
        };
        assert!(d.armed.is_none());
    }

    /// Rows past the retention are removed by the scheduled prune; newer stay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_scheduled_prune_removes_rows_past_retention_and_keeps_newer() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("autonomy_audit_prune").await else { return };
        for (loc, age) in [("old", RETENTION_DAYS + 1), ("older", 400), ("inside", RETENTION_DAYS - 1), ("fresh", 0)] {
            sqlx::query(
                "INSERT INTO noo_autonomy_audit (at, location, outcome) \
                 VALUES (now() - ($1::bigint * interval '1 day'), $2, 'fired')",
            )
            .bind(age)
            .bind(loc)
            .execute(&db)
            .await
            .unwrap();
        }
        assert_eq!(prune_once(&db).await.unwrap(), 2);
        let left: Vec<String> =
            sqlx::query_scalar("SELECT location FROM noo_autonomy_audit ORDER BY 1").fetch_all(&db).await.unwrap();
        assert_eq!(left, ["fresh", "inside"]);
    }
}
