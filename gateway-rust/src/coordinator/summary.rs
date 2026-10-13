// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Running conversation summary generation, shard tagging, and
//! post-response temporal extraction.

use anyhow::Result;
use serde_json::{json, Value};

use crate::session;
use crate::state::AppState;

#[allow(unused_imports)]
use super::*;

const SUMMARY_TURN_INTERVAL: u32 = 10;

const SUMMARY_MIN_MESSAGES: usize = 8;

/// Fetch the stored running summary for this conversation (if any).
/// Stored in noo_conversations.metadata.running_summary.
pub(super) async fn fetch_running_summary(db: &sqlx::PgPool, conversation_id: &str) -> Option<String> {
    let row: Result<Option<(Value,)>, _> = sqlx::query_as(
        "SELECT metadata FROM noo_conversations WHERE id = $1::uuid"
    )
    .bind(conversation_id)
    .fetch_optional(db)
    .await;

    let (metadata,) = row.ok()??;
    let summary = metadata.get("running_summary").and_then(|s| s.as_str())?;
    if summary.is_empty() { None } else { Some(summary.to_string()) }
}

/// Get the last turn number the summary was generated at.
async fn fetch_last_summary_turn(db: &sqlx::PgPool, conversation_id: &str) -> u32 {
    let row: Result<Option<(Value,)>, _> = sqlx::query_as(
        "SELECT metadata FROM noo_conversations WHERE id = $1::uuid"
    )
    .bind(conversation_id)
    .fetch_optional(db)
    .await;

    row.ok()
        .flatten()
        .and_then(|(m,)| m.get("last_summary_turn").and_then(|v| v.as_u64()).map(|v| v as u32))
        .unwrap_or(0)
}

/// Decide whether the running summary should be regenerated for this conversation.
/// Triggered every SUMMARY_TURN_INTERVAL turns once the conversation has enough messages.
pub(super) async fn should_regenerate_summary(db: &sqlx::PgPool, conversation_id: &str, current_turn: u32) -> bool {
    if current_turn < SUMMARY_MIN_MESSAGES as u32 {
        return false;
    }
    let last = fetch_last_summary_turn(db, conversation_id).await;
    (current_turn - last) >= SUMMARY_TURN_INTERVAL
}

/// Generate and persist a rolling summary of the conversation.
/// Fire-and-forget — runs in background, doesn't block the current turn.
/// Called after each turn when should_regenerate_summary returns true.
///
/// Uses a direct HTTP call to the configured local vLLM (no backend resolution)
/// so the spawned task only needs a cloneable PgPool — not AppState.
pub(super) async fn generate_running_summary(
    db: sqlx::PgPool,
    vllm_url: String,
    vllm_model: String,
    conversation_id: String,
    current_turn: u32,
) {
    let history = match session::load_session(&db, &conversation_id, 40).await {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(error = %e, "summary_history_load_failed");
            return;
        }
    };
    if history.is_empty() {
        return;
    }

    let prior_summary = fetch_running_summary(&db, &conversation_id).await
        .unwrap_or_else(|| "(none)".to_string());

    let mut transcript = String::new();
    for msg in &history {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("?");
        let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
        let preview: String = content.chars().take(400).collect();
        transcript.push_str(&format!("\n{role}: {preview}\n"));
    }

    let system_prompt = format!(
        "You are a conversation summarizer. Produce a concise 2-3 paragraph summary \
         preserving: key topics, user goals, decisions made, and pivots. \
         Focus on what a future turn would need to pick up the thread.\n\n\
         Prior summary:\n{prior_summary}\n\n\
         New conversation transcript:\n{transcript}"
    );

    let body = json!({
        "model": vllm_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "Produce the summary now."}
        ],
        "max_tokens": 1024,
        "stream": false,
    });

    let client = crate::tls::cluster_client();

    let url = format!("{vllm_url}/v1/chat/completions");
    let resp = match client.post(&url).json(&body).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::debug!(status = %r.status(), "summary_llm_non_2xx");
            return;
        }
        Err(e) => {
            tracing::debug!(error = %e, "summary_llm_request_failed");
            return;
        }
    };

    let resp_json: Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return,
    };

    let summary_text = resp_json.get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let summary_text = strip_think_blocks(&summary_text);

    if summary_text.is_empty() {
        return;
    }

    let meta = json!({
        "running_summary": summary_text,
        "last_summary_turn": current_turn,
    });
    if let Err(e) = session::update_conversation_metadata(&db, &conversation_id, &meta).await {
        tracing::debug!(error = %e, "summary_persist_failed");
    } else {
        tracing::info!(
            conversation_id = conversation_id,
            turn = current_turn,
            summary_len = summary_text.len(),
            "running_summary_updated"
        );
    }
}

// ═══════════════════════════════════════════════════════════════
// Shard key tracking (for future distributed Postgres routing)
// ═══════════════════════════════════════════════════════════════

/// Get the shard key for this node. Each node owns conversations
/// tagged with its shard_key, enabling future distributed routing.
/// Priority: config.cluster.shard_key > NOO_SHARD_KEY env > NODE_ID env > "default"
fn get_shard_key(state: &AppState) -> String {
    state.config.cluster.shard_key.clone()
        .or_else(|| std::env::var("NOO_SHARD_KEY").ok())
        .or_else(|| std::env::var("NODE_ID").ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string())
}

/// Tag this conversation with the current node's shard_key.
/// Idempotent — only writes if no shard_key is set yet.
pub(super) async fn tag_conversation_shard(state: &AppState, conversation_id: &str) {
    let shard_key = get_shard_key(state);
    // Only set if not already set (first-write-wins so conversations
    // don't get reassigned between nodes)
    let _ = sqlx::query(
        "UPDATE noo_conversations \
         SET metadata = metadata || jsonb_build_object('shard_key', $2::text) \
         WHERE id = $1::uuid \
           AND (metadata->>'shard_key') IS NULL"
    )
    .bind(conversation_id)
    .bind(&shard_key)
    .execute(&state.db)
    .await;
}

/// Fire-and-forget: publish to NATS for the temporal extractor to process
/// the user prompt + assistant response. Background extraction populates
/// the temporal graph for Layer D recall on future turns.
///
/// Two NATS publishes (one per role) so the LLM extracts triples per
/// message author cleanly.
pub(super) async fn fire_temporal_extraction(
    state: &AppState,
    conversation_id: &str,
    user_message: &str,
    assistant_response: &str,
    user_id: Option<&str>,
) {
    // User message
    if !user_message.trim().is_empty() {
        let payload = json!({
            "conversation_id": conversation_id,
            "author": "user",
            "message_text": user_message,
            "user_id": user_id,
        });
        crate::worker_client::publish_fire_and_forget_metered(
            state.nats.clone(),
            state.db.clone(),
            "worker.temporal.extract",
            payload,
            state.metrics.clone(),
        );
    }

    // Assistant response (cleaned of think blocks already by caller)
    if !assistant_response.trim().is_empty() {
        let payload = json!({
            "conversation_id": conversation_id,
            "author": "assistant",
            "message_text": assistant_response,
            "user_id": user_id,
        });
        crate::worker_client::publish_fire_and_forget_metered(
            state.nats.clone(),
            state.db.clone(),
            "worker.temporal.extract",
            payload,
            state.metrics.clone(),
        );
    }
}
