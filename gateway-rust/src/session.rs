// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Session management — Postgres-backed conversation state.
//!
//! Same schema as Python's ConversationStore. Sessions load from
//! and persist to the same tables, so switching engines is seamless.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// A conversation session with message history.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub conversation_id: String,
    pub messages: Vec<Value>,
    pub channel: String,
    pub turn_count: u32,
}

impl Session {
    pub fn new(conversation_id: String, channel: String) -> Self {
        Self {
            conversation_id,
            messages: Vec::new(),
            channel,
            turn_count: 0,
        }
    }

    /// Add system prompt as first message.
    pub fn set_system_prompt(&mut self, prompt: &str) {
        // Replace or insert system message at position 0
        if let Some(first) = self.messages.first() {
            if first.get("role").and_then(|r| r.as_str()) == Some("system") {
                self.messages[0] = json!({"role": "system", "content": prompt});
                return;
            }
        }
        self.messages.insert(0, json!({"role": "system", "content": prompt}));
    }

    /// Add a user message.
    pub fn add_user_message(&mut self, content: &str) {
        self.messages.push(json!({"role": "user", "content": content}));
        self.turn_count += 1;
    }

    /// Add an assistant message.
    pub fn add_assistant_message(&mut self, content: &str, tool_calls: Option<&[Value]>) {
        let mut msg = json!({"role": "assistant", "content": content});
        if let Some(tcs) = tool_calls {
            if !tcs.is_empty() {
                msg["tool_calls"] = Value::Array(tcs.to_vec());
            }
        }
        self.messages.push(msg);
    }

    /// Add a tool result message.
    pub fn add_tool_result(&mut self, name: &str, content: &str, tool_call_id: &str) {
        let mut msg = json!({
            "role": "tool",
            "name": name,
            "content": content,
        });
        if !tool_call_id.is_empty() {
            msg["tool_call_id"] = json!(tool_call_id);
        }
        self.messages.push(msg);
    }

    /// Trim to keep only system prompt + last N messages.
    pub fn trim(&mut self, max_messages: usize) {
        if self.messages.len() <= max_messages + 1 {
            return;
        }
        // Keep system messages at start
        let system: Vec<Value> = self.messages.iter()
            .take(2)
            .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
            .cloned()
            .collect();
        let non_system: Vec<Value> = self.messages.iter()
            .filter(|m| m.get("role").and_then(|r| r.as_str()) != Some("system"))
            .cloned()
            .collect();
        let keep = non_system.len().saturating_sub(max_messages);
        self.messages = system;
        self.messages.extend(non_system.into_iter().skip(keep));
    }
}

/// Load recent messages for a conversation from Postgres.
pub async fn load_session(
    db: &PgPool,
    conversation_id: &str,
    max_messages: u32,
) -> Result<Vec<Value>> {
    let conv_uuid = coerce_conversation_id(conversation_id);
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT type, content FROM noo_entries \
         WHERE conversation_id = $1::uuid \
         ORDER BY id DESC \
         LIMIT $2"
    )
    .bind(&conv_uuid)
    .bind(max_messages as i64)
    .fetch_all(db)
    .await?;

    // Reverse to chronological order.
    // Skip system messages from history — vLLM/Qwen requires all system
    // messages at the beginning, and we inject fresh context each turn.
    let messages: Vec<Value> = rows.into_iter()
        .rev()
        .filter_map(|(role, content)| {
            let mapped_role = match role.as_str() {
                "assistant" => "assistant",
                "system" => return None,  // Skip — injected fresh each turn
                _ => "user",
            };
            Some(json!({"role": mapped_role, "content": content}))
        })
        .collect();

    Ok(messages)
}

/// Coerce a conversation_id string into a valid UUID.
///
/// Accepts: proper UUIDs (pass-through), or arbitrary strings like
/// "heartbeat-research_report_gchat-xyz" which get converted to a
/// deterministic UUIDv5 (same input → same UUID).
///
/// This lets heartbeat tasks, agent workflows, and other non-chat sources
/// persist to `noo_entries` without needing to generate their own UUIDs.
pub fn coerce_conversation_id(raw: &str) -> String {
    if uuid::Uuid::parse_str(raw).is_ok() {
        return raw.to_string();
    }
    // UUIDv5 namespace: DNS (stable, well-known). The input string becomes
    // deterministic under this namespace — same string → same UUID.
    let ns = uuid::Uuid::NAMESPACE_DNS;
    uuid::Uuid::new_v5(&ns, raw.as_bytes()).to_string()
}

/// Persist a message to the conversation store.
///
/// `user_id` attributes the conversation to a person. Pass `None` only when the
/// caller genuinely has no identity (system-originated work); do NOT pass a
/// placeholder, because NULL is what marks a row as shared/non-personal and a
/// fake value would make system data look like someone's personal data.
///
/// Why this parameter exists: `noo_conversations.user_id` was never written by
/// the Rust path, so every conversation since 2026-04-06 is NULL. That silently
/// disables right-to-be-forgotten — `erase_targets()` filters
/// `user_id = $1` and therefore matches nothing — and it breaks the
/// `edge -> conversation -> user` chain the temporal graph depends on for the
/// same purpose. See the design.
pub async fn save_message(
    db: &PgPool,
    conversation_id: &str,
    role: &str,
    content: &str,
    metadata: Option<&Value>,
    user_id: Option<&str>,
) -> Result<()> {
    let conversation = ConversationWrite {
        id: Uuid::parse_str(&coerce_conversation_id(conversation_id))?,
        user_id,
        metadata: None,
        started_at: None,
        require_owner: false,
    };
    let message = MessageWrite {
        id: Uuid::new_v4(),
        role,
        content,
        metadata,
        created_at: None,
    };
    let mut tx = db.begin().await?;
    save_message_in(&mut tx, &conversation, &message).await?;
    tx.commit().await?;
    Ok(())
}

/// Transcript storage options shared by native chat and source adapters.
/// Ownership and organization always use Noomesh's account identity. Adapters
/// require an exact owner match; native system writes may fill anonymous rows.
pub(crate) struct ConversationWrite<'a> {
    pub id: Uuid,
    pub user_id: Option<&'a str>,
    /// Initial metadata; existing Noomesh labels are retained on conflict.
    pub metadata: Option<&'a Value>,
    pub started_at: Option<DateTime<Utc>>,
    pub require_owner: bool,
}

/// Native messages get fresh IDs/timestamps; import adapters can supply stable
/// IDs and original timestamps for immutable, idempotent delivery.
pub(crate) struct MessageWrite<'a> {
    pub id: Uuid,
    pub role: &'a str,
    pub content: &'a str,
    pub metadata: Option<&'a Value>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConversationWriteError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("Conversation source conflict")]
    OwnershipConflict,
    #[error("Published entry is immutable")]
    ImmutableEntry,
}

/// Ensure a conversation using the native writer's attribution rules. The
/// caller owns the transaction, so an entry conflict rolls back these changes
/// along with any source-ledger updates.
async fn ensure_conversation_in(
    db: &mut PgConnection,
    conversation: &ConversationWrite<'_>,
) -> Result<(), ConversationWriteError> {
    // First identified writer fills an anonymous row and repairs its default
    // org; an existing attribution is never overwritten. Org resolution stays
    // here, shared by native callers and external transcript adapters.
    let metadata = conversation.metadata.cloned().unwrap_or_else(|| json!({}));
    let saved: Option<Uuid> = sqlx::query_scalar(
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
         RETURNING id"
    )
    .bind(conversation.id)
    .bind(conversation.user_id)
    .bind(metadata)
    .bind(conversation.started_at)
    .bind(conversation.require_owner)
    .fetch_optional(db)
    .await?;
    if saved.is_none() {
        return Err(ConversationWriteError::OwnershipConflict);
    }
    Ok(())
}

/// Canonical entry writer. Use inside a caller-owned transaction: conversation,
/// entry, counter and optional adapter bookkeeping commit or roll back together.
pub(crate) async fn save_message_in(
    db: &mut PgConnection,
    conversation: &ConversationWrite<'_>,
    message: &MessageWrite<'_>,
) -> Result<(), ConversationWriteError> {
    ensure_conversation_in(db, conversation).await?;
    let metadata = message.metadata.cloned().unwrap_or_else(|| json!({}));
    let inserted = sqlx::query(
        "INSERT INTO noo_entries (id, conversation_id, type, content, metadata, created_at) \
         VALUES ($1, $2, $3, $4, $5, COALESCE($6, now())) ON CONFLICT (id) DO NOTHING",
    )
    .bind(message.id)
    .bind(conversation.id)
    .bind(message.role)
    .bind(message.content)
    .bind(&metadata)
    .bind(message.created_at)
    .execute(&mut *db)
    .await?
    .rows_affected();

    if inserted == 0 {
        // Include conversation identity in the comparison. Timestamps compare
        // in Postgres's own precision, including on the first source retry.
        let unchanged: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM noo_entries WHERE id=$1 AND conversation_id=$2 \
             AND type=$3 AND content=$4 AND metadata=$5 \
             AND ($6::timestamptz IS NULL OR created_at=$6))",
        )
        .bind(message.id)
        .bind(conversation.id)
        .bind(message.role)
        .bind(message.content)
        .bind(metadata)
        .bind(message.created_at)
        .fetch_one(&mut *db)
        .await?;
        if !unchanged {
            return Err(ConversationWriteError::ImmutableEntry);
        }
    } else {
        sqlx::query(
            "UPDATE noo_conversations SET total_messages = COALESCE(total_messages, 0) + 1 \
             WHERE id = $1",
        )
        .bind(conversation.id)
        .execute(&mut *db)
        .await?;
    }
    Ok(())
}

/// Record a source session ending through the same conversation lifecycle.
/// Out-of-order delivery cannot move the ending backwards.
pub(crate) async fn finish_conversation_in(
    db: &mut PgConnection,
    conversation: &ConversationWrite<'_>,
    ended_at: DateTime<Utc>,
    metadata: &Value,
) -> Result<(), ConversationWriteError> {
    ensure_conversation_in(db, conversation).await?;
    sqlx::query(
        "UPDATE noo_conversations SET ended_at=GREATEST(ended_at,$2), \
         metadata=COALESCE(metadata,'{}'::jsonb) || $3 WHERE id=$1",
    )
    .bind(conversation.id)
    .bind(ended_at)
    .bind(metadata)
    .execute(db)
    .await?;
    Ok(())
}

/// Delete a caller-owned transcript, retaining any adapter tombstone outside
/// the conversation tables. Missing conversations are already deleted.
pub(crate) async fn delete_conversation_in(
    db: &mut PgConnection,
    conversation_id: Uuid,
    user_id: &str,
) -> Result<(), ConversationWriteError> {
    let owner: Option<Option<String>> =
        sqlx::query_scalar("SELECT user_id FROM noo_conversations WHERE id=$1 FOR UPDATE")
            .bind(conversation_id)
            .fetch_optional(&mut *db)
            .await?;
    if owner.is_some_and(|owner| owner.as_deref() != Some(user_id)) {
        return Err(ConversationWriteError::OwnershipConflict);
    }
    for statement in [
        "DELETE FROM noo_tool_executions WHERE conversation_id=$1",
        "DELETE FROM noo_context_retrievals WHERE conversation_id=$1",
        "DELETE FROM noo_feedback WHERE conversation_id=$1",
        "DELETE FROM noo_entries WHERE conversation_id=$1",
        "DELETE FROM noo_conversations WHERE id=$1",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(conversation_id)
            .execute(&mut *db)
            .await?;
    }
    Ok(())
}

/// Update conversation-level metadata (tokens, latency, engine info).
/// Merges with existing metadata rather than replacing it.
pub async fn update_conversation_metadata(
    db: &PgPool,
    conversation_id: &str,
    metadata: &Value,
) -> Result<()> {
    let meta_str = metadata.to_string();
    let conv_uuid = coerce_conversation_id(conversation_id);

    sqlx::query(
        "UPDATE noo_conversations \
         SET metadata = COALESCE(metadata, '{}'::jsonb) || $2::jsonb \
         WHERE id = $1::uuid"
    )
    .bind(&conv_uuid)
    .bind(&meta_str)
    .execute(db)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the exact UUIDv5 output of `coerce_conversation_id`.
    ///
    /// `backfill-conversation-user.sh` (a retired
    /// one-shot) recomputes these UUIDs in Python
    /// to tell system-generated conversations from a person's, so that erasing a
    /// human does not also delete operational history. That script and this
    /// function must agree on namespace and input format; if they drift, the
    /// script silently stops matching and mislabels internal rows as user data.
    /// Hardcoded values, not a re-derivation, so a namespace change fails here.
    #[test]
    fn coerce_conversation_id_is_stable_uuid_v5() {
        assert_eq!(
            coerce_conversation_id("heartbeat-daily_briefing"),
            "b7599e62-db9d-5dd7-93a3-acc0ca07325a"
        );
        assert_eq!(
            coerce_conversation_id("heartbeat-research_report-run123"),
            "d7e36f08-8eea-50d8-b97d-59b4ff936dc9"
        );
    }

    /// A real UUID must pass through untouched — otherwise a user's chat session
    /// would be rewritten into a v5 id and become indistinguishable from
    /// system-generated traffic.
    #[test]
    fn coerce_conversation_id_passes_through_real_uuids() {
        let real = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
        assert_eq!(coerce_conversation_id(real), real);
    }
}
