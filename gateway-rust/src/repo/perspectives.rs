// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! "View as" perspectives (i538 P1): `noo_perspectives`, and the
//! `perspective_id` stamp on `noo_refresh_tokens`.
//!
//! The policy (who may start one, narrowing, the liveness cache, the audit
//! rows) stays in `perspective.rs`; this module is only the statements.
//! Every function is generic over the executor, so `begin`, `switch`, `end`
//! and the refresh keep their transactions at the call site.

use chrono::{DateTime, Utc};
use serde_json::Value;

/// `(account, ended, cap_at, started_at)` of one perspective.
pub async fn liveness<'e, E>(db: E, id: &str) -> Result<Option<(String, bool, DateTime<Utc>, DateTime<Utc>)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT account, ended_at IS NOT NULL, cap_at, started_at FROM noo_perspectives WHERE id = $1::uuid",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

/// End one live perspective. `Some(account)` only when THIS call ended it.
pub async fn mark_ended<'e, E>(db: E, id: &str, reason: &str) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE noo_perspectives SET ended_at = now(), end_reason = $2 \
          WHERE id = $1::uuid AND ended_at IS NULL RETURNING account",
    )
    .bind(id)
    .bind(reason)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(account,)| account))
}

/// Clear the stamp on every refresh row carrying this perspective.
pub async fn unstamp<'e, E>(db: E, id: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_refresh_tokens SET perspective_id = NULL WHERE perspective_id = $1::uuid")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// End every live perspective of an account. Returns the ids this call ended.
pub async fn mark_all_ended<'e, E>(db: E, account: &str, reason: &str) -> Result<Vec<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<(String,)> = sqlx::query_as(
        "UPDATE noo_perspectives SET ended_at = now(), end_reason = $2 \
          WHERE account = $1 AND ended_at IS NULL RETURNING id::text",
    )
    .bind(account)
    .bind(reason)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Clear the stamp on every refresh row of an account.
pub async fn unstamp_account<'e, E>(db: E, account: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_refresh_tokens SET perspective_id = NULL WHERE user_id = $1 AND perspective_id IS NOT NULL")
        .bind(account)
        .execute(db)
        .await?;
    Ok(())
}

/// `(id, perspective_id)` of the live (unrevoked, unexpired) refresh row with
/// this token hash, when it is `account`'s.
pub async fn session_row<'e, E>(db: E, token_hash: &str, account: &str) -> Result<Option<(String, Option<String>)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT id::text, perspective_id::text FROM noo_refresh_tokens \
          WHERE token_hash = $1 AND (user_id = $2 OR $2 IS NOT NULL) AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(token_hash)
    .bind(account)
    .fetch_optional(db)
    .await
}

/// A new perspective row, to be inserted.
pub struct NewPerspective<'a> {
    pub id: &'a str,
    pub account: &'a str,
    pub refresh_family: &'a str,
    pub dims: &'a Value,
    pub cap_hours: i32,
    pub switched_from: Option<&'a str>,
}

/// Insert a perspective. Returns its `started_at`.
pub async fn insert<'e, E>(db: E, p: &NewPerspective<'_>) -> Result<DateTime<Utc>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let (started_at,): (DateTime<Utc>,) = sqlx::query_as(
        "INSERT INTO noo_perspectives (id, account, refresh_family, dims, cap_at, switched_from) \
         VALUES ($1::uuid, $2, $3::uuid, $4, now() + make_interval(hours => $5), $6::uuid) \
         RETURNING started_at",
    )
    .bind(p.id)
    .bind(p.account)
    .bind(p.refresh_family)
    .bind(p.dims)
    .bind(p.cap_hours)
    .bind(p.switched_from)
    .fetch_one(db)
    .await?;
    Ok(started_at)
}

/// Stamp `new_id` on a refresh row, only while it is live and still carries
/// `expect`. Returns the rows changed (1, or 0 when the row moved).
pub async fn stamp<'e, E>(db: E, refresh_id: &str, new_id: &str, expect: Option<&str>) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(
        "UPDATE noo_refresh_tokens SET perspective_id = $1::uuid \
          WHERE id = $2::uuid AND revoked_at IS NULL AND perspective_id IS NOT DISTINCT FROM $3::uuid",
    )
    .bind(new_id)
    .bind(refresh_id)
    .bind(expect)
    .execute(db)
    .await?
    .rows_affected())
}

/// End `id` for a switch, only while it is live and `account`'s. Returns the
/// rows changed (1, or 0 when it had already ended or is not the caller's).
pub async fn end_for_switch<'e, E>(db: E, id: &str, reason: &str, account: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(
        "UPDATE noo_perspectives SET ended_at = now(), end_reason = $2 \
          WHERE id = $1::uuid AND account = $3 AND ended_at IS NULL",
    )
    .bind(id)
    .bind(reason)
    .bind(account)
    .execute(db)
    .await?
    .rows_affected())
}

/// `(account, ended, past_cap, dims)` of the perspective a refresh carries.
pub async fn carried<'e, E>(db: E, id: &str) -> Result<Option<(String, bool, bool, Value)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT account, ended_at IS NOT NULL, cap_at <= now(), dims FROM noo_perspectives WHERE id = $1::uuid",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

/// Test fixtures: rows written or read directly, to set up a state the API
/// cannot reach (a crash between two writes, an aged cap, a newer gateway's
/// dimension) or to read what it left behind.
#[cfg(test)]
pub mod fixtures {
    use sqlx::PgPool;

    pub async fn add_user(db: &PgPool, name: &str, role: &str) {
        sqlx::query(
            "INSERT INTO noo_users (username, hashed_password, role, scopes, disabled) \
             VALUES ($1, 'x', $2, '[\"read\"]'::jsonb, false)",
        )
        .bind(name)
        .bind(role)
        .execute(db)
        .await
        .expect("insert user");
    }

    pub async fn set_role(db: &PgPool, name: &str, role: &str) {
        sqlx::query("UPDATE noo_users SET role = $2 WHERE username = $1")
            .bind(name)
            .bind(role)
            .execute(db)
            .await
            .expect("set role");
    }

    pub async fn is_live(db: &PgPool, id: &str) -> bool {
        sqlx::query_scalar("SELECT ended_at IS NULL FROM noo_perspectives WHERE id = $1::uuid")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("read the perspective")
    }

    pub async fn end_reason(db: &PgPool, id: &str) -> Option<String> {
        sqlx::query_scalar("SELECT end_reason FROM noo_perspectives WHERE id = $1::uuid")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("read the perspective")
    }

    /// End the row but leave every session's stamp.
    pub async fn end_row_only(db: &PgPool, id: &str) {
        sqlx::query("UPDATE noo_perspectives SET ended_at = now(), end_reason = 'back_to_me' WHERE id = $1::uuid")
            .bind(id)
            .execute(db)
            .await
            .expect("end the row");
    }

    pub async fn count_for(db: &PgPool, account: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM noo_perspectives WHERE account = $1")
            .bind(account)
            .fetch_one(db)
            .await
            .expect("count")
    }

    pub async fn age_cap(db: &PgPool, id: &str) {
        sqlx::query("UPDATE noo_perspectives SET cap_at = now() - interval '1 second' WHERE id = $1::uuid")
            .bind(id)
            .execute(db)
            .await
            .expect("age the cap");
    }

    pub async fn set_dims(db: &PgPool, id: &str, dims: serde_json::Value) {
        sqlx::query("UPDATE noo_perspectives SET dims = $2 WHERE id = $1::uuid")
            .bind(id)
            .bind(dims)
            .execute(db)
            .await
            .expect("set dims");
    }

    /// One column of the audit rows of `event_type` by `actor`.
    pub async fn audit_column(db: &PgPool, column: &str, event_type: &str, actor: &str) -> Vec<String> {
        let sql = match column {
            "details" => "SELECT details::text FROM noo_security_audit WHERE event_type = $1 AND actor = $2",
            "outcome" => "SELECT outcome FROM noo_security_audit WHERE event_type = $1 AND actor = $2",
            other => panic!("no audit column fixture for {other}"),
        };
        sqlx::query_scalar(sql)
            .bind(event_type)
            .bind(actor)
            .fetch_all(db)
            .await
            .expect("read audit rows")
    }
}
