// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Autonomy rule overrides — `noo_autonomy_overrides` (the runtime tier
//! that wins over the YAML for a built-in rule).

use serde_json::Value;

/// Upsert a built-in rule's override. `patch` keys are MERGED into the
/// stored config (jsonb `||`), never substituted for it: the console's arm
/// toggle sends only `enabled_action`, and replacing used to drop a stored
/// `dry_run: false` and any tunable. `enabled: None` keeps the stored flag.
/// Returns the stored config after the write.
pub async fn upsert_override<'e, E>(db: E, name: &str, enabled: Option<bool>, patch: Option<&Value>, updated_by: &str) -> Result<Option<Value>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, Option<Value>>(
        "INSERT INTO noo_autonomy_overrides (name, enabled, config, updated_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (name) DO UPDATE SET \
           enabled = COALESCE($2, noo_autonomy_overrides.enabled), \
           config = CASE WHEN $3::jsonb IS NULL THEN noo_autonomy_overrides.config \
                         ELSE COALESCE(noo_autonomy_overrides.config, '{}'::jsonb) || $3::jsonb END, \
           updated_at = now(), updated_by = $4 \
         RETURNING config",
    )
    .bind(name)
    .bind(enabled)
    .bind(patch)
    .bind(updated_by)
    .fetch_one(db)
    .await
}

/// A rule's stored `enabled` flag (`None`: no override, or no flag set).
pub async fn override_enabled<'e, E>(db: E, name: &str) -> Result<Option<bool>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query_scalar::<_, Option<bool>>("SELECT enabled FROM noo_autonomy_overrides WHERE name = $1")
        .bind(name)
        .fetch_optional(db)
        .await?
        .flatten())
}

/// Remove a rule's override (back to the YAML / built-in default).
pub async fn delete_override<'e, E>(db: E, name: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query("DELETE FROM noo_autonomy_overrides WHERE name = $1").bind(name).execute(db).await?.rows_affected())
}
