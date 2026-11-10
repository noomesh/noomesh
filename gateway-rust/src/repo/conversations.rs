// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The transcript writer's statements (`noo_conversations`, `noo_entries`) and
//! the add-on source ledger (`noo_conversation_sources`, i608).
//!
//! The policy stays in `session.rs` (attribution, immutability, the
//! transaction) and `routes/conversation_import.rs` (who may publish, the
//! tombstone rules). Every function is generic over the executor, so the
//! callers keep one transaction across the writer and the ledger.

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

/// Create the conversation, or fill an anonymous row and repair its default
/// org; an existing attribution is never overwritten. With `require_owner`, an
/// existing row owned by someone else is left untouched and `None` comes back.
pub async fn ensure<'e, E>(
    db: E,
    id: Uuid,
    user_id: Option<&str>,
    metadata: &Value,
    started_at: Option<DateTime<Utc>>,
    require_owner: bool,
) -> Result<Option<Uuid>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    // org_id: a NULL org is invisible to every org-scoped read, so it rides on
    // the same statement, resolved by subselect ('default' with no user). The
    // conflict branch upgrades 'default' as well as NULL, mirroring the
    // trellion trigger `noo_conv_set_org`.
    sqlx::query_scalar(
        "INSERT INTO noo_conversations (id, total_messages, metadata, user_id, org_id, started_at) \
         VALUES ($1, 0, $3, $2, \
                 COALESCE((SELECT org_id FROM noo_users WHERE username = $2), 'default'), \
                 COALESCE($4, now())) \
         ON CONFLICT (id) DO UPDATE \
            SET user_id = COALESCE(noo_conversations.user_id, EXCLUDED.user_id), \
                org_id = CASE \
                    WHEN EXCLUDED.user_id IS NOT NULL \
                     AND (noo_conversations.org_id IS NULL \
                          OR noo_conversations.org_id = 'default') \
                    THEN EXCLUDED.org_id \
                    ELSE COALESCE(noo_conversations.org_id, EXCLUDED.org_id) \
                END, \
                started_at = LEAST(noo_conversations.started_at, COALESCE($4, noo_conversations.started_at)) \
         WHERE NOT $5 OR noo_conversations.user_id = EXCLUDED.user_id \
         RETURNING id",
    )
    .bind(id)
    .bind(user_id)
    .bind(metadata)
    .bind(started_at)
    .bind(require_owner)
    .fetch_optional(db)
    .await
}

/// A message to insert.
pub struct NewEntry<'a> {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub role: &'a str,
    pub content: &'a str,
    pub metadata: &'a Value,
    pub created_at: Option<DateTime<Utc>>,
}

/// Insert an entry; an existing id is left alone. Returns the rows inserted.
pub async fn insert_entry<'e, E>(db: E, e: &NewEntry<'_>) -> Result<u64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(
        "INSERT INTO noo_entries (id, conversation_id, type, content, metadata, created_at) \
         VALUES ($1, $2, $3, $4, $5, COALESCE($6, now())) ON CONFLICT (id) DO NOTHING",
    )
    .bind(e.id)
    .bind(e.conversation_id)
    .bind(e.role)
    .bind(e.content)
    .bind(e.metadata)
    .bind(e.created_at)
    .execute(db)
    .await?
    .rows_affected())
}

/// Whether the stored entry with this id is exactly `e` (same conversation,
/// role, content and metadata; same time when `e` names one), compared in
/// Postgres's own precision.
pub async fn entry_unchanged<'e, E>(db: E, e: &NewEntry<'_>) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM noo_entries WHERE id=$1 AND conversation_id=$2 \
         AND type=$3 AND content=$4 AND metadata=$5 \
         AND ($6::timestamptz IS NULL OR created_at=$6))",
    )
    .bind(e.id)
    .bind(e.conversation_id)
    .bind(e.role)
    .bind(e.content)
    .bind(e.metadata)
    .bind(e.created_at)
    .fetch_one(db)
    .await
}

pub async fn count_message<'e, E>(db: E, conversation_id: Uuid) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_conversations SET total_messages = COALESCE(total_messages, 0) + 1 WHERE id = $1")
        .bind(conversation_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Record a session ending. Out-of-order delivery cannot move it backwards.
pub async fn finish<'e, E>(db: E, conversation_id: Uuid, ended_at: DateTime<Utc>, metadata: &Value) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE noo_conversations SET ended_at=GREATEST(ended_at,$2), \
         metadata=COALESCE(metadata,'{}'::jsonb) || $3 WHERE id=$1",
    )
    .bind(conversation_id)
    .bind(ended_at)
    .bind(metadata)
    .execute(db)
    .await?;
    Ok(())
}

/// The owner of a conversation, row-locked. `None`: no such conversation;
/// `Some(None)`: anonymous.
pub async fn owner_for_update<'e, E>(db: E, conversation_id: Uuid) -> Result<Option<Option<String>>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT user_id FROM noo_conversations WHERE id=$1 FOR UPDATE")
        .bind(conversation_id)
        .fetch_optional(db)
        .await
}

/// The rows a transcript delete removes, children first.
pub const DELETE_STATEMENTS: [&str; 5] = [
    "DELETE FROM noo_tool_executions WHERE conversation_id=$1",
    "DELETE FROM noo_context_retrievals WHERE conversation_id=$1",
    "DELETE FROM noo_feedback WHERE conversation_id=$1",
    "DELETE FROM noo_entries WHERE conversation_id=$1",
    "DELETE FROM noo_conversations WHERE id=$1",
];

/// Run one of [`DELETE_STATEMENTS`].
pub async fn delete_step<'e, E>(db: E, statement: &'static str, conversation_id: Uuid) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    debug_assert!(DELETE_STATEMENTS.contains(&statement));
    sqlx::query(sqlx::AssertSqlSafe(statement)).bind(conversation_id).execute(db).await?;
    Ok(())
}

pub async fn exists<'e, E>(db: E, conversation_id: Uuid) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM noo_conversations WHERE id=$1)")
        .bind(conversation_id)
        .fetch_one(db)
        .await
}

// ── the add-on source ledger (noo_conversation_sources) ──

/// Record a source the first time it is seen. Returns whether this call
/// created the row.
pub async fn claim_source<'e, E>(db: E, account: &str, publisher: Uuid, source: Uuid, conversation_id: Uuid) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    Ok(sqlx::query(
        "INSERT INTO noo_conversation_sources (user_id, publisher_id, source_id, conversation_id) \
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(account)
    .bind(publisher)
    .bind(source)
    .bind(conversation_id)
    .execute(db)
    .await?
    .rows_affected()
        == 1)
}

/// Whether a source is tombstoned, row-locked.
pub async fn source_deleted_for_update<'e, E>(db: E, account: &str, publisher: Uuid, source: Uuid) -> Result<bool, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT deleted FROM noo_conversation_sources \
         WHERE user_id=$1 AND publisher_id=$2 AND source_id=$3 FOR UPDATE",
    )
    .bind(account)
    .bind(publisher)
    .bind(source)
    .fetch_one(db)
    .await
}

/// Tombstone the source that maps to this conversation.
pub async fn tombstone_source<'e, E>(db: E, conversation_id: Uuid) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("UPDATE noo_conversation_sources SET deleted=true WHERE conversation_id=$1")
        .bind(conversation_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Test fixtures: rows written or read directly, to set up accounts and to
/// read what the writer left behind.
#[cfg(test)]
pub mod fixtures {
    use chrono::{DateTime, Utc};
    use serde_json::Value;
    use sqlx::PgPool;
    use uuid::Uuid;

    /// One conversation row, as the tests read it.
    #[derive(Debug, Clone, PartialEq)]
    pub struct ConvRow {
        pub user_id: Option<String>,
        pub org_id: String,
        pub total_messages: i32,
        pub started_at: DateTime<Utc>,
        pub ended_at: Option<DateTime<Utc>>,
        pub metadata: Value,
    }

    pub async fn add_user(db: &PgPool, name: &str, org: &str) {
        sqlx::query("INSERT INTO noo_users (username, hashed_password, org_id) VALUES ($1, 'unused-test-hash', $2)")
            .bind(name)
            .bind(org)
            .execute(db)
            .await
            .unwrap();
    }

    pub async fn disable_user(db: &PgPool, name: &str) {
        sqlx::query("UPDATE noo_users SET disabled = true WHERE username = $1").bind(name).execute(db).await.unwrap();
    }

    /// Remove a test account and everything it wrote.
    pub async fn remove_user(db: &PgPool, name: &str) {
        for statement in [
            "DELETE FROM noo_entries WHERE conversation_id IN (SELECT id FROM noo_conversations WHERE user_id = $1)",
            "DELETE FROM noo_conversations WHERE user_id = $1",
            "DELETE FROM noo_conversation_sources WHERE user_id = $1",
            "DELETE FROM noo_users WHERE username = $1",
        ] {
            sqlx::query(sqlx::AssertSqlSafe(statement)).bind(name).execute(db).await.unwrap();
        }
    }

    /// Delete a conversation and its entries behind the writer's back (an
    /// erasure the source ledger did not see).
    pub async fn erase_conversation(db: &PgPool, id: Uuid) {
        for statement in ["DELETE FROM noo_entries WHERE conversation_id = $1", "DELETE FROM noo_conversations WHERE id = $1"] {
            sqlx::query(sqlx::AssertSqlSafe(statement)).bind(id).execute(db).await.unwrap();
        }
    }

    pub async fn conversation(db: &PgPool, id: Uuid) -> ConvRow {
        let (user_id, org_id, total_messages, started_at, ended_at, metadata): (
            Option<String>,
            String,
            i32,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Value,
        ) = sqlx::query_as(
            "SELECT user_id, org_id, total_messages, started_at, ended_at, metadata FROM noo_conversations WHERE id = $1",
        )
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap();
        ConvRow { user_id, org_id, total_messages, started_at, ended_at, metadata }
    }

    /// `(type, content, metadata)` of a conversation's entries, oldest first.
    pub async fn entries(db: &PgPool, conversation_id: Uuid) -> Vec<(String, String, Value)> {
        sqlx::query_as("SELECT type, content, metadata FROM noo_entries WHERE conversation_id = $1 ORDER BY created_at, id")
            .bind(conversation_id)
            .fetch_all(db)
            .await
            .unwrap()
    }

    pub async fn source_rows(db: &PgPool, conversation_id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM noo_conversation_sources WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(db)
            .await
            .unwrap()
    }
}
