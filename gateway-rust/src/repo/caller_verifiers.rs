// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The caller-verifier group role: who may read `noo_addon_caller_keys`.
//!
//! The SQL only. The policy (which runtime roles belong, and when one is
//! revoked) is the systems broker's: `system_provision::sync_caller_verifier`
//! and the sweep at the end of `system_provision::reconcile`. An add-on
//! declares `verify_callers` in its signed `system.json`; the broker makes its
//! runtime role a member of [`GROUP`], which alone holds USAGE on the view's
//! schema and SELECT on the view.
//!
//! Runtime queries, not `sqlx::query!`: role DDL cannot take bind parameters
//! and the catalogue reads need no offline cache entry.

/// The NOLOGIN group role whose members may read [`VIEW`].
pub const GROUP: &str = "noo_caller_verifiers";

/// The view the group may read (mesh revision 077).
pub const VIEW: &str = "noo_addon_caller_keys";

/// `name` as a quoted SQL identifier, for names read back from the catalogue.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The schema holding [`VIEW`]: `mesh` on a cluster install, `public` on a
/// legacy one, `None` when 077 found no `noo_service_keys` to view. Looked up
/// in the catalogue, not through `to_regclass`: the broker's pool does not
/// carry the migration's search_path.
pub async fn view_schema<'e, E>(db: E) -> Result<Option<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, String>(
        "SELECT n.nspname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relname = $1 AND c.relkind = 'v' AND n.nspname IN ('mesh', 'public') \
         ORDER BY n.nspname = 'mesh' DESC LIMIT 1",
    )
    .bind(VIEW)
    .fetch_optional(db)
    .await
}

/// The roles that are members of [`GROUP`] now. Empty when the group does not
/// exist (nothing ever declared `verify_callers` on this cluster).
pub async fn members<'e, E>(db: E) -> Result<Vec<String>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT m.rolname::text FROM pg_auth_members am \
         JOIN pg_roles g ON g.oid = am.roleid JOIN pg_roles m ON m.oid = am.member \
         WHERE g.rolname = $1 ORDER BY 1",
    )
    .bind(GROUP)
    .fetch_all(db)
    .await
}

/// Create [`GROUP`] if absent: no login, no escalation attribute. Returns
/// whether this call created it.
pub async fn ensure_group(db: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
        .bind(GROUP)
        .fetch_one(db)
        .await?;
    if exists {
        return Ok(false);
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {GROUP} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"
    )))
    .execute(db)
    .await?;
    Ok(true)
}

/// Grant [`GROUP`] USAGE on `schema` and SELECT on the view in it.
/// Idempotent.
pub async fn grant_view(db: &sqlx::PgPool, schema: &str) -> Result<(), sqlx::Error> {
    let schema = quote_ident(schema);
    for stmt in [
        format!("GRANT USAGE ON SCHEMA {schema} TO {GROUP}"),
        format!("GRANT SELECT ON {schema}.{VIEW} TO {GROUP}"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(stmt)).execute(db).await?;
    }
    Ok(())
}

/// Make `role` a member of [`GROUP`].
pub async fn add_member(db: &sqlx::PgPool, role: &str) -> Result<(), sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(format!("GRANT {GROUP} TO {}", quote_ident(role))))
        .execute(db)
        .await
        .map(|_| ())
}

/// Take `role` out of [`GROUP`].
pub async fn remove_member(db: &sqlx::PgPool, role: &str) -> Result<(), sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(format!("REVOKE {GROUP} FROM {}", quote_ident(role))))
        .execute(db)
        .await
        .map(|_| ())
}

/// The `search_path` value a member gets: the defaults first, the view's
/// schema LAST, so nothing in `mesh` can shadow an add-on's own or `public`
/// names. On the legacy layout the view is in `public` and the value is the
/// server default (`"$user", public`).
pub fn search_path_value(schema: &str) -> String {
    if schema == "public" {
        "\"$user\", public".to_string()
    } else {
        format!("\"$user\", public, {}", quote_ident(schema))
    }
}

/// Put the view's `schema` on `role`'s search_path in THIS database
/// (`ALTER ROLE .. IN DATABASE .. SET`), so the documented unqualified
/// `SELECT .. FROM noo_addon_caller_keys` resolves on the add-on's own
/// connections. Per member, never on [`GROUP`]: a role setting applies to the
/// role that LOGS IN and is not inherited through membership. Takes effect on
/// the role's next login; open sessions keep their path. Idempotent.
pub async fn set_search_path(db: &sqlx::PgPool, role: &str, schema: &str) -> Result<(), sqlx::Error> {
    let database: String = sqlx::query_scalar("SELECT current_database()::text").fetch_one(db).await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER ROLE {} IN DATABASE {} SET search_path = {}",
        quote_ident(role),
        quote_ident(&database),
        search_path_value(schema)
    )))
    .execute(db)
    .await
    .map(|_| ())
}

/// Undo [`set_search_path`]: drop `role`'s search_path setting in THIS
/// database. A role-wide setting (no `IN DATABASE`) is not the broker's and is
/// left alone. Idempotent.
pub async fn reset_search_path(db: &sqlx::PgPool, role: &str) -> Result<(), sqlx::Error> {
    let database: String = sqlx::query_scalar("SELECT current_database()::text").fetch_one(db).await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER ROLE {} IN DATABASE {} RESET search_path",
        quote_ident(role),
        quote_ident(&database)
    )))
    .execute(db)
    .await
    .map(|_| ())
}

/// Test probe, on a connection that LOGGED IN as an add-on role: the
/// documented, unqualified caller read (`noo_addon_caller_keys` resolved
/// through that login's search_path).
#[cfg(test)]
pub async fn probe_read_view_unqualified(conn: &mut sqlx::PgConnection, key_hash: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>("SELECT consumer FROM noo_addon_caller_keys WHERE key_hash = $1")
        .bind(key_hash)
        .fetch_all(&mut *conn)
        .await
}

/// Test probe: the schemas this login's search_path resolves to.
#[cfg(test)]
pub async fn probe_current_schemas(conn: &mut sqlx::PgConnection) -> Vec<String> {
    sqlx::query_scalar("SELECT current_schemas(false)::text[]").fetch_one(&mut *conn).await.expect("current_schemas")
}

/// Test probe: read `noo_service_keys` in `schema` directly (must be refused
/// for an add-on role: it may read the view only).
#[cfg(test)]
pub async fn probe_read_service_keys(conn: &mut sqlx::PgConnection, schema: &str) -> Result<(), sqlx::Error> {
    sqlx::query(sqlx::AssertSqlSafe(format!("SELECT 1 FROM {}.noo_service_keys", quote_ident(schema))))
        .fetch_all(&mut *conn)
        .await
        .map(|_| ())
}

/// Test probe: `role`'s settings in THIS database, as stored
/// (`pg_db_role_setting.setconfig`, e.g. `search_path="$user", public, mesh`).
#[cfg(test)]
pub async fn db_role_settings(db: &sqlx::PgPool, role: &str) -> Vec<String> {
    sqlx::query_scalar::<_, Vec<String>>(
        "SELECT s.setconfig::text[] FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole \
         JOIN pg_database d ON d.oid = s.setdatabase WHERE r.rolname = $1 AND d.datname = current_database()",
    )
    .bind(role)
    .fetch_optional(db)
    .await
    .expect("pg_db_role_setting")
    .unwrap_or_default()
}

/// Test probe: can `role` read the view in `schema`? The catalogue's answer,
/// and the rows (or the error) of an actual SELECT made AS that role on one
/// connection (SET ROLE is connection state).
#[cfg(test)]
pub async fn probe_read(db: &sqlx::PgPool, schema: &str, role: &str) -> (bool, Result<Vec<String>, sqlx::Error>) {
    let qualified = format!("{}.{VIEW}", quote_ident(schema));
    let by_catalogue: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, 'SELECT')")
        .bind(role)
        .bind(&qualified)
        .fetch_one(db)
        .await
        .expect("has_table_privilege");
    let mut conn = db.acquire().await.expect("acquire");
    sqlx::query(sqlx::AssertSqlSafe(format!("SET ROLE {}", quote_ident(role)))).execute(&mut *conn).await.expect("set role");
    let got = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!("SELECT consumer FROM {qualified}")))
        .fetch_all(&mut *conn)
        .await;
    sqlx::query("RESET ROLE").execute(&mut *conn).await.expect("reset role");
    (by_catalogue, got)
}

/// Test cleanup: drop a cluster-global role, ignoring "does not exist".
#[cfg(test)]
pub async fn drop_role(db: &sqlx::PgPool, role: &str) {
    let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS {}", quote_ident(role)))).execute(db).await;
}
