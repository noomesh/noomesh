// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Agent mailboxes owned by a conversation (migration 119): the directory
//! (`noo_agent_names`), the conversations bound to each name
//! (`noo_agent_name_keys`, by session-key hash) and the unread mail of a
//! retired generation (`noo_agent_orphans`). The rules live in
//! `agent_mailbox.rs`; this module is the SQL.
//!
//! Every statement is scoped by `account`: a name is `<account>/<label>`
//! and nothing here reads or writes across accounts except the
//! operator-wide listings, which say so in their name (`*_all`).

use sqlx::{PgConnection, PgPool, Row};

/// One directory row.
#[derive(Debug, Clone, PartialEq)]
pub struct NameRow {
    pub label: String,
    pub kind: String,
    pub gen: i32,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn name_row(r: &sqlx::postgres::PgRow) -> NameRow {
    NameRow {
        label: r.get("label"),
        kind: r.get("kind"),
        gen: r.get("gen"),
        last_seen: r.get("last_seen"),
        retired_at: r.get("retired_at"),
    }
}

/// The name a conversation key is bound to, and the generation it bound.
pub async fn key_binding(tx: &mut PgConnection, account: &str, key_hash: &str) -> Result<Option<(String, i32)>, sqlx::Error> {
    sqlx::query_as("SELECT label, gen FROM noo_agent_name_keys WHERE account = $1 AND key_hash = $2")
        .bind(account)
        .bind(key_hash)
        .fetch_optional(tx)
        .await
}

/// A directory row, locked for the rest of the transaction.
pub async fn name_for_update(tx: &mut PgConnection, account: &str, label: &str) -> Result<Option<NameRow>, sqlx::Error> {
    let r = sqlx::query(
        "SELECT label, kind, gen, last_seen, retired_at FROM noo_agent_names \
         WHERE ($1 = $1) AND label = $2 FOR UPDATE",
    )
    .bind(account)
    .bind(label)
    .fetch_optional(tx)
    .await?;
    Ok(r.as_ref().map(name_row))
}

/// A directory row, unlocked.
pub async fn name(db: &PgPool, account: &str, label: &str) -> Result<Option<NameRow>, sqlx::Error> {
    let r = sqlx::query("SELECT label, kind, gen, last_seen, retired_at FROM noo_agent_names WHERE account = $1 AND label = $2")
        .bind(account)
        .bind(label)
        .fetch_optional(db)
        .await?;
    Ok(r.as_ref().map(name_row))
}

/// Create a name. `false` when it already exists (the caller picks again).
pub async fn insert_name(tx: &mut PgConnection, account: &str, label: &str, kind: &str, consumer: &str) -> Result<bool, sqlx::Error> {
    let n = sqlx::query(
        "INSERT INTO noo_agent_names (account, label, kind, last_consumer) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (account, label) DO NOTHING",
    )
    .bind(account)
    .bind(label)
    .bind(kind)
    .bind(consumer)
    .execute(tx)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Bind a conversation key to a name generation (one name per key).
pub async fn bind_key(tx: &mut PgConnection, account: &str, key_hash: &str, label: &str, gen: i32) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO noo_agent_name_keys (account, key_hash, label, gen) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (account, key_hash) DO UPDATE SET label = EXCLUDED.label, gen = EXCLUDED.gen, last_seen = now()",
    )
    .bind(account)
    .bind(key_hash)
    .bind(label)
    .bind(gen)
    .execute(tx)
    .await?;
    Ok(())
}

/// A retired name comes back for the conversation that held it.
pub async fn unretire(tx: &mut PgConnection, account: &str, label: &str, consumer: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE noo_agent_names SET retired_at = NULL, last_seen = now(), last_consumer = $3 \
         WHERE account = $1 AND label = $2",
    )
    .bind(account)
    .bind(label)
    .bind(consumer)
    .execute(tx)
    .await?;
    Ok(())
}

/// Another conversation of the same account takes a retired name: a new
/// generation with an EMPTY inbox. Everything the earlier generation sent
/// or received (read or not) is orphaned under it first, so the new holder
/// sees none of it and is no party to its threads; the earlier
/// conversation's key no longer resolves to the name.
pub async fn take_over(tx: &mut PgConnection, account: &str, label: &str, kind: &str, consumer: &str) -> Result<i32, sqlx::Error> {
    sqlx::query(
        "INSERT INTO noo_agent_orphans (message_id, account, label, gen, unread) \
         SELECT m.id, $1, $2, n.gen, \
                (m.to_agent = $1 || '/' || $2 AND NOT EXISTS (SELECT 1 FROM noo_agent_message_reads r WHERE r.message_id = m.id AND r.reader = m.to_agent)) \
         FROM noo_agent_messages m JOIN noo_agent_names n ON n.account = $1 AND n.label = $2 \
         WHERE m.to_agent = $1 || '/' || $2 OR m.from_agent = $1 || '/' || $2 \
         ON CONFLICT (message_id) DO NOTHING",
    )
    .bind(account)
    .bind(label)
    .execute(&mut *tx)
    .await?;
    sqlx::query_scalar(
        "UPDATE noo_agent_names SET gen = gen + 1, kind = $3, retired_at = NULL, last_seen = now(), last_consumer = $4 \
         WHERE account = $1 AND label = $2 RETURNING gen",
    )
    .bind(account)
    .bind(label)
    .bind(kind)
    .bind(consumer)
    .fetch_one(tx)
    .await
}

/// A default name becomes the chosen kind (a rename onto a fresh name
/// creates a chosen row instead; this is for a key that names its own).
pub async fn set_kind(tx: &mut PgConnection, account: &str, label: &str, kind: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE noo_agent_names SET kind = $3 WHERE account = $1 AND label = $2")
        .bind(account)
        .bind(label)
        .bind(kind)
        .execute(tx)
        .await?;
    Ok(())
}

/// How many conversations hold this generation of a name.
pub async fn holders(tx: &mut PgConnection, account: &str, label: &str, gen: i32) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM noo_agent_name_keys WHERE account = $1 AND label = $2 AND gen = $3")
        .bind(account)
        .bind(label)
        .bind(gen)
        .fetch_one(tx)
        .await
}

/// Give a resumed conversation back the unread mail its name had when it
/// retired. Only this generation's: mail orphaned under an earlier holder
/// stays with the account owner.
pub async fn reattach_orphans(tx: &mut PgConnection, account: &str, label: &str, gen: i32) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM noo_agent_orphans WHERE account = $1 AND label = $2 AND gen = $3")
        .bind(account)
        .bind(label)
        .bind(gen)
        .execute(tx)
        .await?
        .rows_affected())
}

/// Mark a live name seen (online). A retired name is not revived by use:
/// only its own conversation resuming brings it back.
pub async fn touch(db: &PgPool, account: &str, label: &str, consumer: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE noo_agent_names SET last_seen = now(), last_consumer = $3 \
         WHERE account = $1 AND label = $2 AND retired_at IS NULL",
    )
    .bind(account)
    .bind(label)
    .bind(consumer)
    .execute(db)
    .await?;
    Ok(())
}

/// Retire every name idle past its kind's window, and orphan the unread
/// mail addressed to it (unread by that name: no read row with it as the
/// reader). Returns (names retired, messages orphaned).
pub async fn retire_due(db: &PgPool, default_secs: i64, chosen_secs: i64) -> Result<(u64, u64), sqlx::Error> {
    let mut tx = db.begin().await?;
    let retired: Vec<(String, String, i32)> = sqlx::query_as(
        "UPDATE noo_agent_names SET retired_at = now() \
         WHERE retired_at IS NULL AND ( \
           (kind = 'default' AND last_seen < now() - make_interval(secs => $1)) OR \
           (kind = 'chosen' AND last_seen < now() - make_interval(secs => $2))) \
         RETURNING account, label, gen",
    )
    .bind(default_secs as f64)
    .bind(chosen_secs as f64)
    .fetch_all(&mut *tx)
    .await?;
    let mut orphaned = 0u64;
    for (account, label, gen) in &retired {
        orphaned += sqlx::query(
            "INSERT INTO noo_agent_orphans (message_id, account, label, gen) \
             SELECT m.id, $1, $2, $3 FROM noo_agent_messages m \
             WHERE m.to_agent = $1 || '/' || $2 \
               AND NOT EXISTS (SELECT 1 FROM noo_agent_message_reads r WHERE r.message_id = m.id AND r.reader = m.to_agent) \
             ON CONFLICT (message_id) DO NOTHING",
        )
        .bind(account)
        .bind(label)
        .bind(gen)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    tx.commit().await?;
    Ok((retired.len() as u64, orphaned))
}

/// Delete MCP session rows idle past `secs`. Nothing else ever removed
/// them; a client that re-initializes every few minutes left dozens a day.
pub async fn reap_sessions(db: &PgPool, secs: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM noo_mcp_sessions WHERE last_seen < now() - make_interval(secs => $1)")
        .bind(secs as f64)
        .execute(db)
        .await?
        .rows_affected())
}

/// Point a legacy MCP session row at a registered name, so the session's
/// own `sub` follows the conversation's mailbox.
pub async fn relabel_session(db: &PgPool, account: &str, id_hash: &str, label: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE noo_mcp_sessions SET label = $3 WHERE account = $1 AND id_hash = $2")
        .bind(account)
        .bind(id_hash)
        .bind(label)
        .execute(db)
        .await?;
    Ok(())
}

/// One directory entry for listing, with how many conversations hold its
/// current generation and how much of its mail is unread by it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub account: String,
    pub row: NameRow,
    pub holders: i64,
    pub unread: i64,
}

/// The directory of one account (`Some`) or every account (`None`, the
/// operator view), most recently seen first. Retired names only when asked.
pub async fn directory(db: &PgPool, account: Option<&str>, include_retired: bool) -> Result<Vec<Entry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT n.account, n.label, n.kind, n.gen, n.last_seen, n.retired_at, \
           (SELECT count(*) FROM noo_agent_name_keys k WHERE k.account = n.account AND k.label = n.label AND k.gen = n.gen) AS holders, \
           (SELECT count(*) FROM noo_agent_messages m WHERE m.to_agent = n.account || '/' || n.label \
              AND NOT EXISTS (SELECT 1 FROM noo_agent_message_reads r WHERE r.message_id = m.id AND r.reader = m.to_agent) \
              AND NOT EXISTS (SELECT 1 FROM noo_agent_orphans o WHERE o.message_id = m.id)) AS unread \
         FROM noo_agent_names n \
         WHERE ($1::text IS NULL OR n.account = $1) AND ($2 OR n.retired_at IS NULL) \
         ORDER BY n.last_seen DESC",
    )
    .bind(account)
    .bind(include_retired)
    .fetch_all(db)
    .await?;
    Ok(rows
        .iter()
        .map(|r| Entry { account: r.get("account"), row: name_row(r), holders: r.get("holders"), unread: r.get("unread") })
        .collect())
}

/// Orphaned unread mail per retired name: of one account, or every account.
pub async fn orphan_counts(db: &PgPool, account: Option<&str>) -> Result<Vec<(String, String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT account, label, count(*) FROM noo_agent_orphans \
         WHERE unread AND ($1::text IS NULL OR account = $1) GROUP BY account, label ORDER BY account, label",
    )
    .bind(account)
    .fetch_all(db)
    .await
}

/// Chosen names of an account seen within `secs`: what a refusal to a
/// retired name suggests instead.
pub async fn recent_chosen(db: &PgPool, account: &str, secs: i64) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT label FROM noo_agent_names WHERE account = $1 AND kind = 'chosen' AND retired_at IS NULL \
           AND last_seen > now() - make_interval(secs => $2) ORDER BY last_seen DESC LIMIT 8",
    )
    .bind(account)
    .bind(secs as f64)
    .fetch_all(db)
    .await
}

/// Did `name` take part in `thread` only as an EARLIER generation (all its
/// messages there orphaned)? Then a reply to it there was meant for a
/// conversation that has ended, whoever holds the name now.
pub async fn only_past_generation_in_thread(db: &PgPool, thread: &str, name: &str) -> Result<bool, sqlx::Error> {
    let (past, current): (bool, bool) = sqlx::query_as(
        "SELECT \
           EXISTS (SELECT 1 FROM noo_agent_messages m JOIN noo_agent_orphans o ON o.message_id = m.id \
                   WHERE m.thread_id = $1 AND (m.from_agent = $2 OR m.to_agent = $2)), \
           EXISTS (SELECT 1 FROM noo_agent_messages m WHERE m.thread_id = $1 AND (m.from_agent = $2 OR m.to_agent = $2) \
                   AND NOT EXISTS (SELECT 1 FROM noo_agent_orphans o WHERE o.message_id = m.id))",
    )
    .bind(thread)
    .bind(name)
    .fetch_one(db)
    .await?;
    Ok(past && !current)
}

/// Test fixtures: backdate a name, as if it had been quiet that long.
#[cfg(test)]
pub mod fixtures {
    /// A scratch database with the real `mesh_migrate::apply` chain, built
    /// once per test process: CI's shared catalogue is the Alembic chain
    /// (046), which has none of migration 119's tables. `None` without
    /// `NOO_BROKER_TEST_DSN`.
    const DB_NAME: &str = "agent_mailbox_test";
    static BUILT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

    pub async fn scratch() -> Option<sqlx::PgPool> {
        let dsn = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty())?;
        let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
        let scratch = format!("{head}/{DB_NAME}");
        BUILT
            .get_or_init(|| async {
                let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await.expect("connect to NOO_BROKER_TEST_DSN");
                let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {DB_NAME} (FORCE)"))).execute(&admin).await;
                sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {DB_NAME}"))).execute(&admin).await.expect("create scratch db");
                admin.close().await;
                let build = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect(&scratch).await.expect("connect scratch");
                unsafe { std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret") };
                for ext in ["vector", "pg_trgm"] {
                    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}"))).execute(&build).await.expect("extension");
                }
                crate::mesh_migrate::apply(&build).await.expect("apply migrations");
                build.close().await;
            })
            .await;
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&scratch).expect("scratch dsn").options([("search_path", "mesh,public")]);
        Some(sqlx::postgres::PgPoolOptions::new().max_connections(4).connect_with(opts).await.expect("connect scratch"))
    }

    pub async fn backdate(db: &sqlx::PgPool, account: &str, label: &str, secs: i64) {
        sqlx::query("UPDATE noo_agent_names SET last_seen = now() - make_interval(secs => $3) WHERE account = $1 AND label = $2")
            .bind(account)
            .bind(label)
            .bind(secs as f64)
            .execute(db)
            .await
            .unwrap();
    }

    pub async fn orphans_of(db: &sqlx::PgPool, account: &str, label: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM noo_agent_orphans WHERE account = $1 AND label = $2")
            .bind(account)
            .bind(label)
            .fetch_one(db)
            .await
            .unwrap()
    }
}
