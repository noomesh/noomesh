// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Add-on feature settings and the super-admin flag (noomesh-internal f99):
//! `noo_addon_access`, `noo_users.super_admin`.
//!
//! `noo_addon_access` holds one row per `(addon, feature, subject)` that is
//! set on or off; "inherit" is the absence of a row. The decision itself is
//! `crate::addon_access::decide`; nothing here interprets a row.
//!
//! Runtime-checked SQL (`sqlx::query_as`), like `agent_messages`: these
//! statements are new, and the offline cache is regenerated against a live
//! schema, which the PR that adds them cannot do.

use crate::addon_access::Setting;

/// One stored row with who set it, for the admin listing.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct Row {
    pub addon: String,
    pub feature: String,
    pub subject: String,
    pub allowed: bool,
    pub set_by: String,
    pub set_at: String,
    pub source: String,
    pub reason: Option<String>,
}

impl Row {
    pub fn setting(&self) -> Setting {
        Setting {
            addon: self.addon.clone(),
            feature: self.feature.clone(),
            subject: self.subject.clone(),
            allowed: self.allowed,
        }
    }
}


/// Every setting, ordered for a stable listing.
pub async fn list<'e, E>(db: E) -> Result<Vec<Row>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, Row>(
        "SELECT addon, feature, subject, allowed, set_by, \
                to_char(set_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS set_at, source, reason \
         FROM noo_addon_access ORDER BY addon, feature, subject",
    )
    .fetch_all(db)
    .await
}

/// Set a feature on or off for a subject (insert or replace).
pub async fn set<'e, E>(
    db: E,
    addon: &str,
    feature: &str,
    subject: &str,
    allowed: bool,
    set_by: &str,
    source: &str,
    reason: Option<&str>,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "INSERT INTO noo_addon_access (addon, feature, subject, allowed, set_by, source, reason) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (addon, feature, subject) DO UPDATE SET \
         allowed = EXCLUDED.allowed, set_by = EXCLUDED.set_by, set_at = now(), \
         source = EXCLUDED.source, reason = EXCLUDED.reason",
    )
    .bind(addon)
    .bind(feature)
    .bind(subject)
    .bind(allowed)
    .bind(set_by)
    .bind(source)
    .bind(reason)
    .execute(db)
    .await
    .map(|_| ())
}

/// Back to inherit: remove the row. Returns how many rows went (0 or 1).
pub async fn clear<'e, E>(db: E, addon: &str, feature: &str, subject: &str) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("DELETE FROM noo_addon_access WHERE addon = $1 AND feature = $2 AND subject = $3")
        .bind(addon)
        .bind(feature)
        .bind(subject)
        .execute(db)
        .await
        .map(|r| r.rows_affected())
}

/// The enabled accounts that are super admins, sorted. While NO enabled
/// account carries the flag, every enabled admin is one: migration 104 flags
/// the admins an upgraded install already has, but a fresh install creates
/// its admin after the migration ran, and the two must not differ.
pub async fn super_admins<'e, E>(db: E) -> Result<Vec<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, String>(
        "SELECT username FROM noo_users \
         WHERE NOT COALESCE(disabled, false) \
           AND (super_admin OR (role = 'admin' AND NOT EXISTS \
                (SELECT 1 FROM noo_users f WHERE f.super_admin AND NOT COALESCE(f.disabled, false)))) \
         ORDER BY username",
    )
    .fetch_all(db)
    .await
}

/// Write the implicit set down before the first explicit change: while no
/// enabled account is flagged, flag every enabled admin (what
/// [`super_admins`] already reports). Without it, naming one super admin on
/// a fresh install would silently demote every other admin, the caller
/// included. A no-op once any account is flagged.
pub async fn flag_implicit_super_admins<'e, E>(db: E) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE noo_users SET super_admin = true \
         WHERE role = 'admin' AND NOT COALESCE(disabled, false) \
           AND NOT EXISTS (SELECT 1 FROM noo_users f WHERE f.super_admin AND NOT COALESCE(f.disabled, false))",
    )
    .execute(db)
    .await
    .map(|r| r.rows_affected())
}

/// Set or clear one account's super-admin flag. Returns rows changed (0 when
/// the account does not exist).
pub async fn set_super_admin<'e, E>(db: E, username: &str, on: bool) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_users SET super_admin = $2 WHERE username = $1")
        .bind(username)
        .bind(on)
        .execute(db)
        .await
        .map(|r| r.rows_affected())
}
