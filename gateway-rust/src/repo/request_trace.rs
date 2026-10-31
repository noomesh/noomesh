// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Request traces — `noo_request_trace` (i359). One row per request the
//! gateway served: metadata and sizes, never text. Written by
//! `crate::request_trace` when a request ends, pruned by its daily loop.
//!
//! Runtime queries, not `query!`: the table postdates the offline cache, as
//! `noo_token_usage`'s writer does.

use crate::request_trace::SummaryRow;

/// Insert one row. The account is resolved by name IN the insert, as the
/// usage writer does, and a name with no account (a service key, an internal
/// caller) stores NULL rather than a made-up identity.
pub async fn insert(db: &sqlx::PgPool, row: &SummaryRow) -> Result<(), sqlx::Error> {
    let s = &row.summary;
    let username = if s.actor_kind.as_deref() == Some("user") { s.actor.as_deref() } else { None };
    sqlx::query(
        "INSERT INTO noo_request_trace
             (trace_id, method, route, status, duration_ms, user_uuid, actor, actor_kind,
              model, backend, node_id, prompt_tokens, completion_tokens, span_count,
              request_bytes, response_bytes)
         VALUES ($1, $2, $3, $4, $5,
                 (SELECT u.user_uuid FROM noo_users u WHERE u.username = $6),
                 $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(&row.trace_id)
    .bind(&row.method)
    .bind(&row.route)
    .bind(row.status)
    .bind(row.duration_ms)
    .bind(username)
    .bind(s.actor.as_deref())
    .bind(s.actor_kind.as_deref())
    .bind(s.model.as_deref())
    .bind(s.backend.as_deref())
    .bind(s.node.as_deref())
    .bind(s.prompt_tokens)
    .bind(s.completion_tokens)
    .bind(row.span_count)
    .bind(row.request_bytes)
    .bind(row.response_bytes)
    .execute(db)
    .await
    .map(|_| ())
}

/// Delete every row older than `keep_days`; the number deleted.
pub async fn prune(db: &sqlx::PgPool, keep_days: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("DELETE FROM noo_request_trace WHERE at < now() - ($1::bigint * interval '1 day')")
        .bind(keep_days)
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}
