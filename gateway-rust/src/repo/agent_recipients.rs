// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The names agent mail can be delivered to, for the recipient check in
//! `agent_recipient.rs` (i277g): an account (`noo_users`, through
//! [`super::users::exists`]), a node (`noo_node_config`), an MCP session
//! (`noo_mcp_sessions`, any age: a name is a mailbox, `mcp_session::rename`)
//! and an active service key's connection (`noo_service_keys`; its label is
//! derived in Rust, `auth::connection_label`, so this returns the consumer).
//!
//! Read-only. The tables' writers stay where they are (`mcp_session.rs`,
//! `service_keys.rs`, the cluster routes).

/// Is `id` a node this controller knows?
pub async fn node_exists<'e, E: sqlx::PgExecutor<'e>>(db: E, id: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM noo_node_config WHERE node_id = $1)").bind(id).fetch_one(db).await
}

/// Has any MCP session of `account` ever held `label`?
pub async fn session_exists<'e, E: sqlx::PgExecutor<'e>>(db: E, account: &str, label: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM noo_mcp_sessions WHERE account = $1 AND label = $2)")
        .bind(account)
        .bind(label)
        .fetch_one(db)
        .await
}

/// `<account>/<label>` of every MCP session name, most recently seen first,
/// for one account or (`None`) all of them.
pub async fn session_names<'e, E: sqlx::PgExecutor<'e>>(db: E, account: Option<&str>, limit: i64) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT account || '/' || label FROM noo_mcp_sessions \
         WHERE ($1::text IS NULL OR account = $1) \
         GROUP BY account, label ORDER BY max(last_seen) DESC LIMIT $2",
    )
    .bind(account)
    .bind(limit)
    .fetch_all(db)
    .await
}

/// `(account, consumer)` of every active service key bound to an account,
/// for one account or (`None`) all of them.
pub async fn key_consumers<'e, E: sqlx::PgExecutor<'e>>(db: E, account: Option<&str>) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT user_id, consumer FROM noo_service_keys \
         WHERE active AND user_id IS NOT NULL AND ($1::text IS NULL OR user_id = $1) \
         ORDER BY created_at DESC",
    )
    .bind(account)
    .fetch_all(db)
    .await
}
