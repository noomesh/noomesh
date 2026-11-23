// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Admin overrides — `noo_settings`.
//!
//! Resolution order (`settings.rs`): this table → env var → registered
//! default. The flag setter wrote the same upsert twice (string registry and
//! boolean registry) with the same column list; it is one statement here.
//!
//! Runtime-checked (`query` / `query_as`): the statements moved verbatim and
//! a new `query!` would need the `.sqlx` offline cache regenerated.

/// Every override as `(key, value)`, for the 15-second cache refresh.
pub async fn all<'e, E>(db: E) -> Result<Vec<(String, String)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, (String, String)>("SELECT key, value FROM noo_settings")
        .fetch_all(db)
        .await
}

/// `(key, value, updated_by, updated_at)` with `updated_at` rendered as a UTC
/// ISO-8601 string, for the admin flag listing ("who turned this on").
pub async fn all_with_meta<'e, E>(
    db: E,
) -> Result<Vec<(String, String, Option<String>, Option<String>)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "SELECT key, value, updated_by, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM noo_settings",
    )
    .fetch_all(db)
    .await
}

/// Set (or replace) one override, stamping who and when.
///
/// Refuses a key in the unplace-tombstone namespace (`backend_unplaced:`):
/// only `placement_delete` writes those ([`super::backend_unplaced::write`]),
/// so the authority to change a setting never becomes the authority to make
/// a node remove a container. The routes refuse it first with a 400; this is
/// the floor under any other caller.
pub async fn upsert<'e, E>(
    db: E,
    key: &str,
    value: &str,
    category: &str,
    updated_by: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    if super::backend_unplaced::is_reserved(key) {
        return Err(sqlx::Error::Protocol(format!("{key}: the backend_unplaced: namespace is written only by an unplace")));
    }
    sqlx::query(
        "INSERT INTO noo_settings (key, value, category, updated_by, updated_at) \
         VALUES ($1, $2, $3, $4, NOW()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, \
           updated_by = EXCLUDED.updated_by, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .bind(category)
    .bind(updated_by)
    .execute(db)
    .await?;
    Ok(())
}

/// Record what the memory store is embedded with: the two `memory` rows
/// `embedding_model` and `embedding_dims`, written by preflight.
pub async fn record_embedding<'e, E>(db: E, model: &str, dims: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO noo_settings (key, value, category, updated_by) \
         VALUES ('embedding_model', $1, 'memory', 'preflight'), \
                ('embedding_dims', $2, 'memory', 'preflight') \
         ON CONFLICT (key) DO UPDATE \
         SET value = EXCLUDED.value, updated_by = 'preflight', updated_at = NOW()",
    )
    .bind(model)
    .bind(dims)
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// The floor under every caller: an upsert of an unplace-tombstone key
    /// is refused before the database is touched (the pool here cannot
    /// connect; reaching it would be a different error).
    #[tokio::test]
    async fn upsert_refuses_the_unplace_tombstone_namespace() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://nobody@127.0.0.1:1/nothing")
            .expect("lazy pool");
        let err = super::upsert(&pool, "backend_unplaced:node-a:ollama:chat", "{}", "unplace", "op").await.unwrap_err();
        assert!(matches!(err, sqlx::Error::Protocol(ref m) if m.contains("written only by an unplace")), "{err}");
        let other = super::upsert(&pool, "CLOUD_PROVIDERS_ENABLED", "1", "general", "op").await.unwrap_err();
        assert!(!matches!(other, sqlx::Error::Protocol(_)), "any other key reaches the database: {other}");
    }
}
