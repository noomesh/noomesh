// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! KB role grants and teams — `noo_kb_role_grants`, `noo_kb_teams`.
//!
//! Pilot domain for the repository layer. Chosen because
//! it had the clearest duplication in `routes/users.rs` and a small blast
//! radius, while still touching the RTBF/erasure and org-boundary paths that
//! matter most to get right.
//!
//! Also the pilot for **compile-checked SQL** (Phase 4): every statement below
//! uses `sqlx::query!`, so the column names, types and nullability are verified
//! against the live schema at build time via the committed `.sqlx/` cache.
//! Converting these eight functions immediately falsified two type signatures —
//! `roles` and `updated_at`/`created_at` are `NOT NULL` in the schema but were
//! declared `Option`, so call sites carried `unwrap_or_else(|| json!([]))`
//! branches for a case the database cannot produce. Runtime `query_as` accepts
//! that silently because `Option<T>` decodes a non-null value happily; the
//! macro does not.
//!
//! `noo_kb_teams` carries `org_id`, so it is one of the 13 tenant-scoped
//! tables. The functions here take `org_id` explicitly where the original
//! queries did; none of them invents a filter that the original lacked —
//! adding scoping is a behaviour change and belongs in the PR5b-4 work, not in
//! a refactor whose whole value is that it changes nothing.

use serde_json::Value;

/// All grants, as `(username, roles)`.
///
/// Replaces three identical copies of this query in `routes/users.rs`.
/// `roles` is `NOT NULL` (default `'[]'::jsonb`), so it is not optional.
pub async fn list_grants<'e, E>(db: E) -> Result<Vec<(String, Value)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!("SELECT username, roles FROM noo_kb_role_grants")
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().map(|r| (r.username, r.roles)).collect())
}

/// The `roles` JSON for one user, or `None` if they have no grant row.
///
/// The `Option` here is row presence, not column nullability.
pub async fn get_roles<'e, E>(db: E, username: &str) -> Result<Option<Value>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query!(
        "SELECT roles FROM noo_kb_role_grants WHERE username = $1",
        username
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| r.roles))
}

/// Upsert a user's roles.
///
/// Replaces three copies that differed only in whitespace. One of them ran
/// inside a transaction, which is why this is generic over the executor rather
/// than taking a pool.
pub async fn upsert_roles<'e, E>(
    db: E,
    username: &str,
    roles: &Value,
    updated_by: &str,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        "INSERT INTO noo_kb_role_grants (username, roles, updated_by) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (username) DO UPDATE SET \
         roles = $2, updated_at = now(), updated_by = $3",
        username,
        roles,
        updated_by,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Replace a user's roles. Distinct from [`upsert_roles`]: this only touches an
/// existing row and reports whether one was affected, which the callers that
/// pair it with [`delete_grant`] rely on.
pub async fn update_roles<'e, E>(
    db: E,
    username: &str,
    roles: &Value,
    updated_by: &str,
) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        "UPDATE noo_kb_role_grants SET roles = $2, updated_at = now(), \
         updated_by = $3 WHERE username = $1",
        username,
        roles,
        updated_by,
    )
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// Delete a user's grant row, returning the number of rows removed.
///
/// Replaces four copies. Note this is also reachable via the erasure path's
/// hardcoded `erase_targets()` table list, which deliberately builds its own
/// SQL so that erasure stays one auditable transaction — that call site is
/// intentionally NOT routed through here.
pub async fn delete_grant<'e, E>(db: E, username: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        "DELETE FROM noo_kb_role_grants WHERE username = $1",
        username
    )
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// Which of `names` exist in `noo_kb_teams`.
///
/// Replaces three identical copies. Callers use this to detect `team:*` roles
/// that reference a team which was never registered.
pub async fn existing_team_names<'e, E>(
    db: E,
    names: &[String],
) -> Result<Vec<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!("SELECT name FROM noo_kb_teams WHERE name = ANY($1)", names)
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().map(|r| r.name).collect())
}

/// Whether a single team is registered.
pub async fn team_exists<'e, E>(db: E, name: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query!("SELECT name FROM noo_kb_teams WHERE name = $1", name)
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

/// Grant row type for the admin listing: `(username, roles, updated_at,
/// updated_by)`. `updated_at` is `NOT NULL DEFAULT now()`.
pub type GrantDetail = (
    String,
    Value,
    chrono::DateTime<chrono::Utc>,
    Option<String>,
);

/// All grants with audit columns, for the admin listing.
pub async fn list_grants_detailed<'e, E>(db: E) -> Result<Vec<GrantDetail>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        "SELECT username, roles, updated_at, updated_by \
         FROM noo_kb_role_grants ORDER BY username"
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.username, r.roles, r.updated_at, r.updated_by))
        .collect())
}

/// Team row type: `(name, description, created_at, created_by)`.
/// `created_at` is `NOT NULL DEFAULT now()`.
pub type TeamDetail = (
    String,
    Option<String>,
    chrono::DateTime<chrono::Utc>,
    Option<String>,
);

/// All teams, ordered by name.
///
/// NOTE: `noo_kb_teams` carries `org_id`, and this query is deliberately
/// unscoped — it matches the original. Org-scoping the admin listing is a
/// behaviour change belonging to PR5b, not to this refactor.
pub async fn list_teams<'e, E>(db: E) -> Result<Vec<TeamDetail>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        "SELECT name, description, created_at, created_by \
         FROM noo_kb_teams ORDER BY name"
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.name, r.description, r.created_at, r.created_by))
        .collect())
}

/// Create a team. Returns rows inserted — `0` means the name already existed
/// (`ON CONFLICT DO NOTHING`), which callers surface as a conflict.
/// `description` stays `Option` rather than `&str`: the column is nullable and
/// the original call site bound an `Option<String>`. Coercing would silently
/// turn NULL into an empty string.
pub async fn create_team<'e, E>(
    db: E,
    name: &str,
    description: Option<&str>,
    created_by: &str,
    org_id: &str,
) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        "INSERT INTO noo_kb_teams (name, description, created_by, org_id) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO NOTHING",
        name,
        description,
        created_by,
        org_id,
    )
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// Delete a team, returning rows removed.
pub async fn delete_team<'e, E>(db: E, name: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!("DELETE FROM noo_kb_teams WHERE name = $1", name)
        .execute(db)
        .await?;
    Ok(r.rows_affected())
}
