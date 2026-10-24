// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The security audit log — `noo_security_audit`.
//!
//! This module is the only place outside `mesh_migrate.rs` (DDL) and
//! `audit_partition.rs` (partition management over `pg_catalog`, `tableoid`
//! and dynamic partition names) that spells the table's columns for the
//! ordinary reads and the row INSERT. The WRITER's policy (signing, chaining,
//! the spool, the missing-partition heal) stays in `audit.rs` and
//! `audit_chain.rs`; what moved here is the SQL.
//!
//! Everything is runtime-checked (`query_as` / `query_scalar` with typed
//! rows), not `query!`: the statements moved verbatim, and a new `query!`
//! would need the `.sqlx` offline cache regenerated. `"timestamp"` is quoted
//! in the statements that name it as a column because it is a type keyword.

use chrono::{DateTime, Utc};

// ── Reads ───────────────────────────────────────────────────────────────

/// One listed row: `(id, timestamp, event_type, severity, actor, resource,
/// outcome, request_id, details_text, chain_seq, entry_hash)`.
pub type ListRow = (
    String,
    DateTime<Utc>,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
);

/// Newest-first page of rows, every filter optional. `cursor` is the previous
/// page's last `(timestamp, id)`; ask for `limit` rows (the caller asks for
/// one extra to learn whether another page exists).
pub async fn list<'e, E>(
    db: E,
    since: Option<DateTime<Utc>>,
    event_type: Option<&str>,
    actor: Option<&str>,
    cursor: Option<(DateTime<Utc>, &str)>,
    limit: i64,
) -> Result<Vec<ListRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT id::text, \"timestamp\", event_type, severity, actor, resource, outcome, \
                request_id, details::text, chain_seq, entry_hash \
           FROM noo_security_audit \
          WHERE ($1::timestamptz IS NULL OR \"timestamp\" >= $1) \
            AND ($2::text IS NULL OR event_type = $2) \
            AND ($3::text IS NULL OR actor = $3) \
            AND ($4::timestamptz IS NULL OR (\"timestamp\", id) < ($4::timestamptz, $5::uuid)) \
          ORDER BY \"timestamp\" DESC, id DESC \
          LIMIT $6",
    )
    .bind(since)
    .bind(event_type)
    .bind(actor)
    .bind(cursor.map(|c| c.0))
    .bind(cursor.map(|c| c.1))
    .bind(limit)
    .fetch_all(db)
    .await
}

/// Event counts by `event_type` over the trailing `interval` (a Postgres
/// interval literal such as `"5 minutes"`), unordered.
pub async fn counts_by_type_within<'e, E>(
    db: E,
    interval: &str,
) -> Result<Vec<(String, i64)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, (String, i64)>(
        "SELECT event_type, COUNT(*) AS cnt \
         FROM noo_security_audit \
         WHERE timestamp > NOW() - $1::interval \
         GROUP BY event_type",
    )
    .bind(interval)
    .fetch_all(db)
    .await
}

/// Event counts by `event_type` over the trailing `hours`, biggest first.
pub async fn counts_by_type_hours<'e, E>(
    db: E,
    hours: i32,
) -> Result<Vec<(String, i64)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT event_type, COUNT(*)::bigint \
         FROM noo_security_audit \
         WHERE timestamp > NOW() - ($1::int * INTERVAL '1 hour') \
         GROUP BY event_type \
         ORDER BY 2 DESC",
    )
    .bind(hours)
    .fetch_all(db)
    .await
}

/// Event types that fired MORE than `threshold` times in the last hour,
/// biggest first.
pub async fn spikes_last_hour<'e, E>(
    db: E,
    threshold: i64,
) -> Result<Vec<(String, i64)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT event_type, COUNT(*)::bigint \
         FROM noo_security_audit \
         WHERE timestamp > NOW() - INTERVAL '1 hour' \
         GROUP BY event_type \
         HAVING COUNT(*) > $1::bigint \
         ORDER BY 2 DESC",
    )
    .bind(threshold)
    .fetch_all(db)
    .await
}

/// Rows of one `event_type` in the last five minutes.
pub async fn count_last_5m<'e, E>(db: E, event_type: &str) -> Result<i64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM noo_security_audit \
         WHERE event_type = $1 AND timestamp > NOW() - INTERVAL '5 minutes'",
    )
    .bind(event_type)
    .fetch_one(db)
    .await
}

/// The newest chained row's `(chain_seq, chain_hash)`, if any.
pub async fn chain_head<'e, E>(db: E) -> Result<Option<(i64, String)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, (i64, String)>(
        "SELECT chain_seq, chain_hash FROM noo_security_audit \
         WHERE chain_seq IS NOT NULL AND chain_hash IS NOT NULL ORDER BY chain_seq DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await
}

/// `(chain_seq, chain_hash, timestamp)` of the newest chained row.
pub type ChainTail = (i64, String, DateTime<Utc>);

/// The chain's tail. Callers hold the chain advisory lock when it matters.
pub async fn chain_tail<'e, E>(db: E) -> Result<Option<ChainTail>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, ChainTail>(
        "SELECT chain_seq, chain_hash, \"timestamp\" FROM noo_security_audit \
         WHERE chain_seq IS NOT NULL ORDER BY chain_seq DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await
}

/// `(min, max)` chained `chain_seq` with a timestamp in `[start, end)`.
pub async fn chain_span<'e, E>(
    db: E,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<(Option<i64>, Option<i64>), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT min(chain_seq), max(chain_seq) FROM noo_security_audit \
         WHERE \"timestamp\" >= $1 AND \"timestamp\" < $2 AND chain_seq IS NOT NULL",
    )
    .bind(start)
    .bind(end)
    .fetch_one(db)
    .await
}

/// The `chain_hash` of the row at `seq` within `[start, end)`. The outer
/// `Option` is "no such row"; the inner is a row whose hash is NULL.
pub async fn chain_hash_at<'e, E>(
    db: E,
    seq: i64,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Option<Option<String>>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT chain_hash FROM noo_security_audit WHERE chain_seq = $1 \
         AND \"timestamp\" >= $2 AND \"timestamp\" < $3",
    )
    .bind(seq)
    .bind(start)
    .bind(end)
    .fetch_optional(db)
    .await
}

/// Is there a row with this `event_type` and exact `resource`?
pub async fn has_event_resource<'e, E>(
    db: E,
    event_type: &str,
    resource: &str,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let have: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM noo_security_audit WHERE event_type = $1 AND resource = $2 LIMIT 1",
    )
    .bind(event_type)
    .bind(resource)
    .fetch_optional(db)
    .await?;
    Ok(have.is_some())
}

/// Rows not yet in the chain: `(id, timestamp, entry_hash)`.
pub async fn unchained<'e, E>(
    db: E,
) -> Result<Vec<(String, DateTime<Utc>, Option<String>)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT id::text, \"timestamp\", entry_hash FROM noo_security_audit WHERE chain_seq IS NULL",
    )
    .fetch_all(db)
    .await
}

/// The thirteen columns `verify` judges, as one tuple.
pub type VerifyRow = (
    String,
    DateTime<Utc>,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
);

/// `details::text` is Postgres's jsonb rendering — the text the v2 writer
/// hashed, because it asked Postgres for exactly that before signing.
pub const SELECT_ROWS: &str = "SELECT id::text, \"timestamp\", event_type, severity, actor, resource, \
     outcome, request_id, entry_hash, details::text, prev_hash, chain_seq, chain_hash \
     FROM noo_security_audit";

/// Every row, oldest first, for `verify`.
pub async fn all_for_verify<'e, E>(db: E) -> Result<Vec<VerifyRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT_ROWS} ORDER BY \"timestamp\" ASC, id ASC"
    )))
    .fetch_all(db)
    .await
}

/// Rows with an `event_type`, for the key-roll checkpoint probe.
pub async fn count_event_resource_like<'e, E>(
    db: E,
    event_type: &str,
    resource_like: &str,
) -> Result<i64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM noo_security_audit WHERE event_type = $1 AND resource LIKE $2",
    )
    .bind(event_type)
    .bind(resource_like)
    .fetch_one(db)
    .await
}

// ── The INSERT ──────────────────────────────────────────────────────────

/// One fully-formed row to insert. `details` is Postgres's jsonb text;
/// `request_id`, `prev_hash` and the chain pair are NULL when `None`.
pub struct InsertRow<'a> {
    pub id: &'a str,
    pub ts: DateTime<Utc>,
    pub event_type: &'a str,
    pub severity: &'a str,
    pub actor: &'a str,
    pub resource: &'a str,
    pub outcome: &'a str,
    pub details: &'a str,
    pub request_id: Option<&'a str>,
    pub entry_hash: &'a str,
    pub prev_hash: Option<&'a str>,
    pub chain_seq: Option<i64>,
    pub chain_hash: Option<&'a str>,
}

/// The ONE statement that inserts into `noo_security_audit`. An `Err` from a
/// missing monthly partition is for the caller to heal and retry.
pub async fn insert<'e, E>(db: E, r: &InsertRow<'_>) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO noo_security_audit \
           (id, \"timestamp\", event_type, severity, actor, resource, outcome, details, \
            request_id, entry_hash, prev_hash, chain_seq, chain_hash) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12, $13)",
    )
    .bind(r.id)
    .bind(r.ts)
    .bind(r.event_type)
    .bind(r.severity)
    .bind(r.actor)
    .bind(r.resource)
    .bind(r.outcome)
    .bind(r.details)
    .bind(r.request_id)
    .bind(r.entry_hash)
    .bind(r.prev_hash)
    .bind(r.chain_seq)
    .bind(r.chain_hash)
    .execute(db)
    .await?;
    Ok(())
}
