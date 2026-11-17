// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo_service_keys.context_overflow` (migration 125, i802): what the raw
//! proxy does with a consumer's prompt that is longer than the model's
//! context, `flag` or `refuse`. The rule and its cache live in
//! `service_keys`; the SQL lives here.

use sqlx::PgPool;

/// Set the mode on every ACTIVE key of `consumer` and drop the cached
/// modes; the number of keys set.
pub async fn set(db: &PgPool, consumer: &str, mode: &str) -> Result<u64, sqlx::Error> {
    let r = sqlx::query("UPDATE noo_service_keys SET context_overflow = $2 WHERE consumer = $1 AND active = true")
        .bind(consumer)
        .bind(mode)
        .execute(db)
        .await?;
    // The mode is read through a short cache: the new one applies now.
    crate::service_keys::invalidate_cache();
    Ok(r.rows_affected())
}

/// Whether any active key of `consumer` is set to refuse; `None` when the
/// consumer has no active key.
pub async fn refuses(db: &PgPool, consumer: &str) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query_scalar("SELECT bool_or(context_overflow = 'refuse') FROM noo_service_keys WHERE consumer = $1 AND active = true")
        .bind(consumer)
        .fetch_one(db)
        .await
}
