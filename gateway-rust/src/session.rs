// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Session management — Postgres-backed conversation state.
//!
//! Same schema as Python's ConversationStore. Sessions load from
//! and persist to the same tables, so switching engines is seamless.

use anyhow::Result;
use serde_json::{json, Value};
use sqlx::PgPool;

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
    let meta = metadata.map(|m| m.to_string()).unwrap_or_else(|| "{}".into());
    // Accept non-UUID strings (heartbeat tasks, workflows) by coercing
    // to deterministic UUIDv5.
    let conv_uuid = coerce_conversation_id(conversation_id);

    // Ensure conversation exists (id column is uuid type — cast text to uuid).
    //
    // COALESCE on conflict rather than DO NOTHING: a conversation row is created
    // by whichever write lands first, and that is often a tool-record insert that
    // has no identity in scope. DO NOTHING would let that anonymous row win
    // permanently, so the conversation would stay unattributed even though a
    // later message knows exactly who it belongs to.
    //
    // COALESCE also makes this self-healing and non-destructive: an existing
    // attribution is never overwritten (first writer wins), and a NULL is filled
    // in the first time an identified message arrives.
    //
    // org_id rides along on the same statement. A conversation with a NULL
    // org is invisible to every org-scoped read, not merely narrowed by one:
    // `conversation_store.py` applies a HARD boundary (`c.org_id = :org`),
    // and `NULL = 'default'` is false, so the filter returned nothing rather
    // than fewer rows. Every account has an org — `noo_users.org_id` is
    // `text DEFAULT 'default' NOT NULL` — so a single-user install is simply
    // one user in one org running this exact code path, not a special case.
    //
    // Resolved by subselect rather than a second round trip: this runs once
    // per saved message, and a `SELECT org_id FROM noo_users` per message is
    // a hot-path query for a value the INSERT can fetch itself. 'default'
    // when there is no user at all (heartbeat, autonomy, system tools) —
    // those rows are not outside every org, they are in the default one.
    //
    // The conflict branch upgrades 'default' as well as NULL, mirroring the
    // trigger `noo_conv_set_org`: a row created anonymously (a tool record
    // lands before the first message) starts at 'default', and the first
    // message that knows the user must be able to move it to that user's
    // real org. Once a genuine org is recorded, first writer still wins.
    sqlx::query(
        "INSERT INTO noo_conversations (id, total_messages, metadata, user_id, org_id) \
         VALUES ($1::uuid, 0, '{}', $2, \
                 COALESCE((SELECT org_id FROM noo_users WHERE username = $2), 'default')) \
         ON CONFLICT (id) DO UPDATE \
            SET user_id = COALESCE(noo_conversations.user_id, EXCLUDED.user_id), \
                org_id = CASE \
                    WHEN EXCLUDED.user_id IS NOT NULL \
                     AND (noo_conversations.org_id IS NULL \
                          OR noo_conversations.org_id = 'default') \
                    THEN EXCLUDED.org_id \
                    ELSE COALESCE(noo_conversations.org_id, EXCLUDED.org_id) \
                END"
    )
    .bind(&conv_uuid)
    .bind(user_id)
    .execute(db)
    .await?;

    // Insert message (both id and conversation_id are uuid columns)
    sqlx::query(
        "INSERT INTO noo_entries \
         (id, conversation_id, type, content, metadata) \
         VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb)"
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&conv_uuid)
    .bind(role)
    .bind(content)
    .bind(&meta)
    .execute(db)
    .await?;

    // Increment message count
    sqlx::query(
        "UPDATE noo_conversations \
         SET total_messages = COALESCE(total_messages, 0) + 1 \
         WHERE id = $1::uuid"
    )
    .bind(&conv_uuid)
    .execute(db)
    .await?;

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
