// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! User accounts — `noo_users`.
//!
//! The account table is written from eight places in `routes/users.rs` alone
//! (create ×3, scopes ×2, disabled ×3), and the duplicates are not identical:
//! the same UPDATE exists in two spellings with the placeholders reversed.
//!
//! ```text
//! UPDATE noo_users SET scopes = $2 WHERE username = $1   // bind(username), bind(scopes)
//! UPDATE noo_users SET scopes = $1 WHERE username = $2   // bind(scopes), bind(username)
//! ```
//!
//! Both are correct today — each site's bind order matches its own
//! placeholders. But they are two spellings of one operation, and the failure
//! mode if an edit crosses them is writing a username into the `scopes`
//! column: a JSONB cast error at best, a silently wrong authorization record
//! at worst. Collapsing them to one function removes the opportunity rather
//! than relying on the next editor noticing.
//!
//! Statements are `sqlx::query!`, checked against the schema at build time.
//! Regenerate `.sqlx/` with `scripts/sqlx-prepare.sh`.
//!
//! **`erase_targets()` in `routes/users.rs` deliberately does NOT route through
//! here.** It deletes 15 targets in a single transaction spanning both mesh-
//! and trellion-owned tables, and that atomicity is the RTBF compliance
//! guarantee. Splitting it across repository calls would make partial erasure
//! representable. It builds its own SQL on purpose; leave it alone.

use serde_json::Value;

/// `(username, disabled, scopes, created_at, last_login_at,
/// failed_login_count)`.
///
/// `created_at` is `NOT NULL DEFAULT now()`. Both original call sites typed it
/// `Option<DateTime<Utc>>`, which claimed a state the column forbids.
pub type UserSummary = (
    String,
    bool,
    Value,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    i32,
);

/// [`UserSummary`] plus `locked_until` and `role`, for the admin listing that
/// surfaces lockout state and the account's permission tier.
pub type UserSummaryLocked = (
    String,
    bool,
    Value,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    i32,
    Option<chrono::DateTime<chrono::Utc>>,
    String,
);

/// All accounts, oldest first.
pub async fn list<'e, E>(db: E) -> Result<Vec<UserSummary>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        "SELECT username, disabled, scopes, created_at, last_login_at, \
         failed_login_count FROM noo_users ORDER BY created_at"
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.username,
                r.disabled,
                r.scopes,
                r.created_at,
                r.last_login_at,
                r.failed_login_count,
            )
        })
        .collect())
}

/// All accounts including lockout state and role, oldest first.
///
/// Runtime-checked (`query_as`, not `query!`): the `role` column lands via
/// this crate's own migration 050 at startup, so the offline `.sqlx` cache —
/// generated against a pre-050 live schema — cannot type-check it yet.
pub async fn list_with_lock<'e, E>(db: E) -> Result<Vec<UserSummaryLocked>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, UserSummaryLocked>(
        "SELECT username, disabled, scopes, created_at, last_login_at, \
         failed_login_count, locked_until, role FROM noo_users ORDER BY created_at",
    )
    .fetch_all(db)
    .await
}

/// Org every account lands in when the caller does not name one. Matches the
/// org seeded by migration `027_org_boundary` and the existing runtime
/// fallback in `routes/users.rs`.
pub const DEFAULT_ORG_ID: &str = "default";

/// Create an account, enabled with a zeroed failure counter.
///
/// Returns rows inserted — `0` means the username already existed
/// (`ON CONFLICT DO NOTHING`), which callers surface as a conflict rather than
/// silently adopting the existing row. Replaces three identical copies, one of
/// which runs inside a transaction; hence the generic executor.
///
/// `org_id` is `None` for "use the default org". It must never end up NULL in
/// the row: this INSERT previously omitted the column entirely, so every
/// account created after `027_org_boundary` (which backfilled once and left
/// nothing behind it) landed org-less. Org-scoped reads filter on `org_id`, so
/// such an account authenticates fine and silently sees nothing — a quiet
/// access-control failure. Observed 2026-08-02 on the `alice` account.
/// `041_users_org_required` backfills and makes the column NOT NULL, which is
/// only safe because this insert now supplies a value.
pub async fn create<'e, E>(
    db: E,
    username: &str,
    hashed_password: &str,
    scopes: &Value,
    org_id: Option<&str>,
) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    // `role` is derived from the scopes IN the statement — same containment
    // rule as migration 050's backfill and `auth::Role::from_scopes` — so a
    // created account can never carry a role its scopes contradict.
    // Runtime-checked (`query`, not `query!`): see `list_with_lock`.
    let r = sqlx::query(
        "INSERT INTO noo_users (username, hashed_password, scopes, disabled, \
         failed_login_count, org_id, role) \
         VALUES ($1, $2, $3, false, 0, COALESCE($4, $5), CASE \
           WHEN $3::jsonb @> '[\"admin\"]'::jsonb THEN 'admin' \
           WHEN $3::jsonb @> '[\"write\"]'::jsonb THEN 'operator' \
           ELSE 'user' END) \
         ON CONFLICT (username) DO NOTHING",
    )
    .bind(username)
    .bind(hashed_password)
    .bind(scopes)
    .bind(org_id)
    .bind(DEFAULT_ORG_ID)
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// Replace an account's scopes. Returns rows affected — `0` means no such user.
///
/// One of the two reversed spellings described in the module docs.
///
/// **Also re-derives `role` from the new scopes, atomically.** The scopes
/// surface is deprecated but still writable for the dual-accept window, and
/// leaving `role` stale would be an escalation: revoke `admin` via scopes and
/// a role column still saying `admin` keeps issuing admin tokens. One
/// statement, so no window where the two columns disagree.
pub async fn set_scopes<'e, E>(
    db: E,
    username: &str,
    scopes: &Value,
) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query(
        "UPDATE noo_users SET scopes = $2, role = CASE \
           WHEN $2::jsonb @> '[\"admin\"]'::jsonb THEN 'admin' \
           WHEN $2::jsonb @> '[\"write\"]'::jsonb THEN 'operator' \
           ELSE 'user' END \
         WHERE username = $1",
    )
    .bind(username)
    .bind(scopes)
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// Assign an account's role. Returns rows affected — `0` means
/// no such user.
///
/// **Also re-derives the legacy `scopes` from the role, atomically**: the
/// derived tier scopes replace `read`/`write`/`admin`, while non-tier scopes
/// (`ingest`, `peer`) are preserved — they are additive capabilities, not
/// tiers, and a role change must neither grant nor revoke them. Without this
/// sync a demotion admin→user would leave `scopes=["read","write","admin"]`
/// live on every dual-accept validator (and on the Python KB resolver, which
/// treats admin/write as unrestricted readers).
///
/// `role` must be a canonical `auth::Role::as_str()` value — callers parse
/// first; the DB CHECK rejects anything else.
pub async fn set_role<'e, E>(
    db: E,
    username: &str,
    role: crate::auth::Role,
) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let tier_scopes = serde_json::json!(role.legacy_scopes());
    let r = sqlx::query(
        "UPDATE noo_users SET role = $2, \
         scopes = COALESCE( \
           (SELECT jsonb_agg(e) FROM jsonb_array_elements_text(scopes) AS t(e) \
             WHERE e NOT IN ('read', 'write', 'admin')), '[]'::jsonb) || $3::jsonb \
         WHERE username = $1",
    )
    .bind(username)
    .bind(role.as_str())
    .bind(tier_scopes)
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// Enable or disable an account. Returns rows affected — `0` means no such user.
///
/// Also replaces the `SET disabled = true` literal variant: passing `true`
/// is the same statement, and having one spelling means the disable path and
/// the toggle path cannot drift apart.
pub async fn set_disabled<'e, E>(
    db: E,
    username: &str,
    disabled: bool,
) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        "UPDATE noo_users SET disabled = $2 WHERE username = $1",
        username,
        disabled,
    )
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// Move an account to an org. Returns rows affected — `0` means no such user.
///
/// Takes `&str`, not `Option<&str>`: `041_users_org_required` makes `org_id`
/// NOT NULL, so clearing an assignment is no longer a representable state.
/// The previous signature let a caller write NULL and produce an account that
/// authenticates but is invisible to every org-scoped read. No caller passed
/// `None`, so this narrows the type to match the constraint rather than
/// changing behaviour.
pub async fn set_org<'e, E>(
    db: E,
    username: &str,
    org_id: &str,
) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query!(
        "UPDATE noo_users SET org_id = $2 WHERE username = $1",
        username,
        org_id,
    )
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

// ── Lookups by username ─────────────────────────────────────────────────
//
// Every read below is runtime-checked (`query_as` / `query_scalar`): these
// statements moved here verbatim from their call sites, and a new `query!`
// would need the `.sqlx` offline cache regenerated. Each returns the raw
// `sqlx::Error` so the caller keeps its own fail-open / fail-closed choice
// (several of them are security gates that must NOT default on error).

/// The `login` row: `(username, hashed_password, disabled, scopes,
/// failed_login_count, locked_until, role)`.
pub type LoginRow = (
    String,
    String,
    bool,
    Value,
    Option<i32>,
    Option<chrono::DateTime<chrono::Utc>>,
    String,
);

/// The row the login path needs, `None` when there is no such account.
/// `scopes` falls back to `["read"]` and `failed_login_count` to 0 in SQL.
pub async fn login_row<'e, E>(db: E, username: &str) -> Result<Option<LoginRow>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as::<_, LoginRow>(
        "SELECT username, hashed_password, disabled, \
                COALESCE(scopes, '[\"read\"]'::jsonb), \
                COALESCE(failed_login_count, 0), locked_until, role \
         FROM noo_users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(db)
    .await
}

/// The account's `user_uuid` — the one spelling of "who owns this" that the
/// rest of the schema keys on. `None` when there is no such account.
pub async fn uuid_by_username<'e, E>(
    db: E,
    username: &str,
) -> Result<Option<uuid::Uuid>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT user_uuid FROM noo_users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await
}

/// Does the account exist (enabled or not)?
pub async fn exists<'e, E>(db: E, username: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(String,)> =
        sqlx::query_as("SELECT username FROM noo_users WHERE username = $1")
            .bind(username)
            .fetch_optional(db)
            .await?;
    Ok(row.is_some())
}

/// Is the account an ENABLED row? (`false` for disabled and for no such row.)
pub async fn is_enabled<'e, E>(db: E, username: &str) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM noo_users WHERE username = $1 AND NOT disabled)",
    )
    .bind(username)
    .fetch_one(db)
    .await
}

/// The raw `role` column, whether or not the account is disabled.
pub async fn role_of<'e, E>(db: E, username: &str) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT role FROM noo_users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await
}

/// The raw `role` column of an ENABLED account; `None` for a disabled or
/// missing one.
pub async fn enabled_role<'e, E>(db: E, username: &str) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT role FROM noo_users WHERE username = $1 AND NOT disabled")
        .bind(username)
        .fetch_optional(db)
        .await
}

/// The `disabled` flag; `None` when there is no such account.
pub async fn disabled_flag<'e, E>(db: E, username: &str) -> Result<Option<bool>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT disabled FROM noo_users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await
}

/// `(disabled, role)`, `None` when there is no such account.
pub async fn role_and_disabled<'e, E>(
    db: E,
    username: &str,
) -> Result<Option<(bool, String)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as("SELECT COALESCE(disabled, false), role FROM noo_users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await
}

/// `(role, scopes, disabled)`, `None` when there is no such account. The
/// live-row read behind every token mint that must re-check the account.
pub async fn role_scopes_disabled<'e, E>(
    db: E,
    username: &str,
) -> Result<Option<(String, Value, bool)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT role, scopes, COALESCE(disabled, false) FROM noo_users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(db)
    .await
}

/// `(role, scopes)`, `None` when there is no such account.
pub async fn role_and_scopes<'e, E>(
    db: E,
    username: &str,
) -> Result<Option<(String, Value)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as("SELECT role, scopes FROM noo_users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await
}

/// The account's `org_id`; `None` when there is no such account or the
/// column is NULL (the two were never distinguished by a caller).
pub async fn org_of<'e, E>(db: E, username: &str) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT org_id FROM noo_users WHERE username = $1")
            .bind(username)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(o,)| o))
}

/// Accounts per org, one grouped scan. The org is `None` for a NULL column.
pub async fn member_counts_by_org<'e, E>(
    db: E,
) -> Result<Vec<(Option<String>, i64)>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as("SELECT org_id, COUNT(*) FROM noo_users GROUP BY org_id")
        .fetch_all(db)
        .await
}

/// Enabled accounts that are admin by EITHER the `role` column or the legacy
/// `admin` scope — counted on both so a desynced row can never make the fleet
/// look like it has fewer admins than it does.
pub async fn enabled_admin_count<'e, E>(db: E) -> Result<i64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM noo_users WHERE disabled = false \
         AND (role = 'admin' OR scopes @> '[\"admin\"]'::jsonb)",
    )
    .fetch_one(db)
    .await?;
    Ok(n)
}

/// Is there at least one enabled admin (by role OR legacy scope)? The
/// bootstrap-admin gate: an `Err` must be treated as "yes, keep the door shut".
pub async fn any_enabled_admin<'e, E>(db: E) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM noo_users \
         WHERE disabled = false \
           AND (role = 'admin' OR scopes @> '[\"admin\"]'::jsonb))",
    )
    .fetch_one(db)
    .await
}

// ── Writes beyond create / scopes / role / disabled / org ───────────────

/// Set a new password hash, stamp `password_changed_at`, and clear the
/// lockout (so this is also the lockout bypass — callers gate it). Returns
/// rows affected; `0` means no such user.
pub async fn set_password<'e, E>(
    db: E,
    username: &str,
    hashed_password: &str,
) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let r = sqlx::query(
        "UPDATE noo_users SET hashed_password = $1, password_changed_at = NOW(), \
         failed_login_count = 0, locked_until = NULL WHERE username = $2",
    )
    .bind(hashed_password)
    .bind(username)
    .execute(db)
    .await?;
    Ok(r.rows_affected())
}

/// Count a failed login and lock the account once `strikes` is reached, for
/// `lockout_minutes`. The threshold and window are bound, not interpolated:
/// sqlx refuses a dynamic SQL string.
pub async fn record_failed_login<'e, E>(
    db: E,
    username: &str,
    strikes: i32,
    lockout_minutes: i32,
) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE noo_users SET failed_login_count = COALESCE(failed_login_count, 0) + 1, \
         locked_until = CASE \
           WHEN COALESCE(failed_login_count, 0) + 1 >= $2 THEN NOW() + make_interval(mins => $3) \
           ELSE locked_until \
         END \
         WHERE username = $1",
    )
    .bind(username)
    .bind(strikes)
    .bind(lockout_minutes)
    .execute(db)
    .await
    .map(|_| ())
}

/// Reset the failure counter and lockout, stamp `last_login_at`.
pub async fn record_successful_login<'e, E>(db: E, username: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE noo_users SET failed_login_count = 0, locked_until = NULL, \
         last_login_at = NOW() WHERE username = $1",
    )
    .bind(username)
    .execute(db)
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    /// The Rust fallback and the org seeded by migration
    /// `041_users_org_required` must name the same org.
    ///
    /// If they drift, `create()` writes an org id that does not exist in
    /// `noo_orgs` — and since there is deliberately no FK, the database
    /// accepts it silently and the account becomes invisible to org-scoped
    /// reads. That is the exact failure this change removes, so the value is
    /// pinned rather than left as a bare literal in two files.
    ///
    /// Deliberately does NOT `include_str!` the migration: that would make the
    /// Rust crate build-depend on the Python tree, which the release image
    /// does not carry.
    #[test]
    fn default_org_is_the_seeded_org() {
        assert_eq!(
            super::DEFAULT_ORG_ID, "default",
            "must match _DEFAULT_ORG in 041_users_org_required.py and the org \
             seeded by 027_org_boundary"
        );
    }
}
