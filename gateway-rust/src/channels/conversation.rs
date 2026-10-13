// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Conversation identity — the one place Rust asks the memory plane for a
//! stable `conversation_id`.
//!
//! Every inbound pipeline needs this and none of them may invent it:
//! `native_inference` mints a random UUID when `conversation_id` is absent,
//! so a pipeline that skips resolution answers perfectly while forgetting
//! the previous turn — a failure that passes any single-message smoke test.
//!
//! Resolution deliberately does NOT read Trellion's tables from Rust.
//! Conversation identity is memory, memory is Trellion, and duplicating its
//! schema knowledge across two languages is the exact failure mode the
//! channel port exists to remove — it is what produced the OAuth
//! token-cache outage, where one job implemented twice drifted apart and
//! killed all inbound Chat.
//!
//! What stays per-channel is the *metadata* a new conversation is created
//! with, and the chat-context key: a Google Chat space keys by space, a
//! Telegram group keys by chat, a WhatsApp DM keys by sender. Those are
//! channel semantics and belong with each adapter. The request/response
//! handling below is not, and used to be copy-pasted per pipeline.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::state::AppState;

/// Subject that owns conversation identity. See `workers/memory.py`.
const RESOLVE_CONVERSATION: &str = "worker.memory.resolve_conversation";

/// Ask the memory plane for this chat context's stable conversation id.
///
/// `metadata` is used only if a conversation must be created. It must carry
/// the `noo_routing` block — the explicit contract with Trellion, which
/// exists so the memory system stores a routing record instead of guessing
/// a reply address from channel-specific keys.
///
/// Errors are returned, never defaulted: a resolution failure must stop the
/// pipeline rather than fall through to inference with no id.
pub async fn resolve(
    state: &Arc<AppState>,
    channel: &str,
    context_id: &str,
    metadata: Value,
) -> Result<String> {
    // Channel ingress runs before any user is known — resolving the
    // conversation is how the account gets attached. So this one is
    // genuinely internal, and it reads/writes only conversation rows.
    let resp = crate::bus_principal::with_internal(
        "channel-ingress",
        &["read", "write"],
        crate::worker_client::request(
            &state.nats,
            RESOLVE_CONVERSATION,
            &json!({
                "channel": channel,
                "chat_context_id": context_id,
                "metadata": metadata,
            }),
        ),
    )
    .await
    .map_err(|e| anyhow!("resolve_conversation request failed: {e}"))?;

    let data = unwrap_envelopes(&resp)
        .map_err(|err| anyhow!("resolve_conversation failed: {err}"))?;
    let id = data
        .get("conversation_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("resolve_conversation returned no conversation_id"))?;

    // `created` on every message means the context key is unstable — the bot
    // would appear to forget the previous turn each time. Surface it.
    if data.get("created").and_then(|v| v.as_bool()) == Some(true) {
        tracing::info!(
            channel,
            context_id = %context_id,
            conversation_id = %id,
            "channel_conversation_created"
        );
    }
    Ok(id.to_string())
}

/// Unwrap nested `{success, data}` envelopes down to the payload.
///
/// The reply is DOUBLE-wrapped: the worker pool puts every handler result
/// in its own `{success, data}` envelope, and the resolve handler returns a
/// `{success, data}` envelope of its own (deliberately — its failure branch
/// is load-bearing). Reading only one layer down made a SUCCESSFUL resolve
/// parse as "no conversation_id", which failed the pipeline on every
/// inbound gchat message (live, 2026-08-08: trellion logged
/// `conversation_created` while the gateway reported no id). A
/// `success: false` at ANY depth is an error — the pool wraps a handler's
/// own failure envelope in a success:true outer layer, so the old top-level
/// check could never see it.
pub(crate) fn unwrap_envelopes(resp: &serde_json::Value) -> Result<&serde_json::Value, String> {
    let mut data = resp;
    loop {
        if data.get("success").and_then(|v| v.as_bool()) == Some(false) {
            let err = data
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(err.to_string());
        }
        match data.get("data") {
            Some(inner) if data.get("success").is_some() => data = inner,
            _ => break,
        }
    }
    Ok(data)
}

#[cfg(test)]
mod envelope_tests {
    use super::unwrap_envelopes;
    use serde_json::json;

    /// The exact live wire shape from 2026-08-08: pool envelope around the
    /// handler's own envelope around the payload.
    #[test]
    fn double_wrapped_success_reaches_the_payload() {
        let resp = json!({
            "success": true,
            "data": {
                "success": true,
                "data": {"conversation_id": "81ff2eac", "created": true}
            }
        });
        let data = unwrap_envelopes(&resp).unwrap();
        assert_eq!(
            data.get("conversation_id").and_then(|v| v.as_str()),
            Some("81ff2eac")
        );
    }

    #[test]
    fn single_wrapped_success_still_works() {
        let resp = json!({"success": true, "data": {"conversation_id": "abc"}});
        let data = unwrap_envelopes(&resp).unwrap();
        assert_eq!(
            data.get("conversation_id").and_then(|v| v.as_str()),
            Some("abc")
        );
    }

    /// The handler's own validation failure arrives wrapped in a
    /// success:true pool envelope — it must surface as an error, not as
    /// "no conversation_id".
    #[test]
    fn nested_failure_is_an_error() {
        let resp = json!({
            "success": true,
            "data": {"success": false, "error": "channel and chat_context_id are required"}
        });
        let err = unwrap_envelopes(&resp).unwrap_err();
        assert!(err.contains("chat_context_id"));
    }

    #[test]
    fn top_level_failure_is_an_error() {
        let resp = json!({"success": false, "error": "boom"});
        assert_eq!(unwrap_envelopes(&resp).unwrap_err(), "boom");
    }

    /// A bare payload (no envelope at all) passes through untouched.
    #[test]
    fn bare_payload_passes_through() {
        let resp = json!({"conversation_id": "xyz"});
        let data = unwrap_envelopes(&resp).unwrap();
        assert_eq!(
            data.get("conversation_id").and_then(|v| v.as_str()),
            Some("xyz")
        );
    }

    /// The no-store branch: success at every layer, null id — not an
    /// error here; the caller turns the missing id into its own error.
    #[test]
    fn null_id_unwraps_cleanly() {
        let resp = json!({
            "success": true,
            "data": {"success": true, "data": {"conversation_id": null, "created": false}}
        });
        let data = unwrap_envelopes(&resp).unwrap();
        assert!(data.get("conversation_id").unwrap().is_null());
    }
}
