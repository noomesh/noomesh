// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Telegram inbound — long-poll transport + pipeline, in Rust.
//!
//! Same shape as the Google Chat pipeline: pull,
//! parse, resolve identity on the memory plane, run inference in process,
//! send. It replaces `channels/telegram.py`'s `_poll_loop` and
//! `_handle_poll_update`, and with them the HTTP loopback back into Rust
//! that `generate_reply` performed for every message.
//!
//! Long-polling specifics that are easy to get wrong and expensive to get
//! wrong, all preserved from the Python implementation:
//!
//!  - **offset must advance to `update_id + 1`.** Telegram redelivers any
//!    update that has not been confirmed by a later offset, so an offset
//!    that fails to advance reprocesses the same message forever — the bot
//!    answers the same prompt in a loop.
//!  - **HTTP 409 means someone else is polling** (another instance, or a
//!    registered webhook). Backing off is right; retrying hard is not, and
//!    treating it as a generic error would hide a genuine misconfiguration.
//!  - **client timeout must exceed the long-poll timeout**, else every poll
//!    is cancelled client-side just as the server is holding it open.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::state::AppState;

/// Server-side long-poll hold. Telegram returns early when an update
/// arrives, so this is an idle ceiling rather than added latency.
const POLL_TIMEOUT_SECS: u64 = 30;
/// Must be > POLL_TIMEOUT_SECS — see module docs.
const CLIENT_TIMEOUT_SECS: u64 = 45;
const MAX_BACKOFF_SECS: f64 = 60.0;
/// A 409 is a configuration conflict, not a transient error: a fixed,
/// longer pause avoids hammering the API while it is resolved.
const CONFLICT_PAUSE_SECS: u64 = 10;

/// One inbound Telegram update, reduced to what the pipeline needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUpdate {
    /// Telegram chat id — the conversation context for BOTH DMs and groups
    /// (for a DM, chat.id equals the user's id).
    pub chat_id: String,
    /// The human who sent it. Distinct from chat_id in groups, and the id
    /// the allow-list is checked against.
    pub user_id: String,
    pub sender_name: String,
    pub text: String,
    /// "private" | "group" | "supergroup" | "channel"
    pub chat_type: String,
    pub chat_title: String,
    /// `Some(data)` when this update was an inline-keyboard press rather
    /// than typed text.
    ///
    /// Without this the two are indistinguishable downstream — `text` is set
    /// from `callback_query.data` either way — and an approval button press
    /// was sent to inference as if the user had typed
    /// `noo-cluster-approve:<uuid>`. See `channels::approvals`.
    pub callback_data: Option<String>,
}

/// Parse an update envelope. Returns None for updates with nothing to
/// answer (no text, unsupported type), which the caller skips.
///
/// Handles `callback_query` (inline keyboard press) as well as `message`,
/// because both arrive on the same subscription and a button press is a
/// user turn like any other.
pub fn parse_update(update: &Value) -> Option<ParsedUpdate> {
    if let Some(cb) = update.get("callback_query") {
        let user = cb.get("from")?;
        let chat = cb.get("message")?.get("chat")?;
        let data = cb.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string();
        return Some(ParsedUpdate {
            chat_id: chat.get("id")?.to_string().trim_matches('"').to_string(),
            user_id: user.get("id")?.to_string().trim_matches('"').to_string(),
            sender_name: display_name(user),
            text: data.clone(),
            chat_type: chat
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("private")
                .to_string(),
            chat_title: chat
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            callback_data: Some(data),
        });
    }

    let message = update.get("message")?;
    let user = message.get("from")?;
    let chat = message.get("chat")?;

    // A caption on a photo/document is the user's text. Without this,
    // sending an image with a question attached looks like an empty
    // message and is silently dropped.
    let text = message
        .get("text")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| message.get("caption").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    if text.trim().is_empty() {
        return None;
    }

    Some(ParsedUpdate {
        chat_id: chat.get("id")?.to_string().trim_matches('"').to_string(),
        user_id: user.get("id")?.to_string().trim_matches('"').to_string(),
        sender_name: display_name(user),
        text,
        chat_type: chat
            .get("type")
            .and_then(|v| v.as_str())
            // A missing type is NOT assumed to be a DM: `unknown` is
            // treated as a shared room (see `channels::is_shared_room`).
            .unwrap_or("unknown")
            .to_string(),
        chat_title: chat
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        callback_data: None,
    })
}

fn display_name(user: &Value) -> String {
    let first = user.get("first_name").and_then(|v| v.as_str()).unwrap_or("");
    let last = user.get("last_name").and_then(|v| v.as_str()).unwrap_or("");
    let name = format!("{first} {last}").trim().to_string();
    if !name.is_empty() {
        return name;
    }
    user.get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn chat_context_id(chat_id: &str, user_id: &str, chat_type: &str) -> String {
    // A DM is keyed by the chat (which is the user's id anyway). A group,
    // supergroup or channel is keyed by (chat, SENDER): each member has their
    // own thread, so one member's history is never loaded as another's
    // context. The room is shared for delivery and for knowledge (see
    // `channels::is_shared_room`), not for conversation.
    if super::is_shared_room(chat_type) {
        format!("telegram:{chat_id}:{user_id}")
    } else {
        format!("telegram:{chat_id}")
    }
}

/// Start the long-poll loop. Returns immediately; the loop runs until the
/// process exits.
///
/// Runs UNCONDITIONALLY when `TELEGRAM_BOT_TOKEN` is set. The
/// `NOO_TELEGRAM_ENGINE=python` hatch that used to stand this loop down is
/// obsolete: the Python poll loop can no longer start
/// retired the engine hatches, so honouring the selector would leave the
/// bot token with ZERO pollers and the channel silently dead. The selector
/// is warned about and ignored — never honoured, never silent.
pub fn start(state: Arc<AppState>) {
    // Through `secret_env` (a `/run/secrets` file). An
    // EMPTY value used to count as set here and start a poller with no
    // token; unset and empty now both mean disabled.
    if crate::config::secret_env::secret_opt("TELEGRAM_BOT_TOKEN").is_none() {
        tracing::info!("telegram_disabled: TELEGRAM_BOT_TOKEN unset");
        return;
    }
    super::warn_if_obsolete_python_selector("NOO_TELEGRAM_ENGINE");
    // One line if the retired allow-list still reaches this process.
    super::ingress::warn_retired_allowlist();
    tokio::spawn(async move { run(state).await });
}

async fn run(state: Arc<AppState>) {
    let mut offset: i64 = 0;
    let mut backoff = 1.0_f64;
    let client = reqwest::Client::new();

    tracing::info!("telegram_poll_loop_started");
    loop {
        match poll_once(&state, &client, offset).await {
            Ok(next_offset) => {
                offset = next_offset;
                backoff = 1.0;
            }
            Err(PollError::Conflict) => {
                tracing::warn!(
                    "telegram_poll_conflict: another bot instance or a registered \
                     webhook is consuming updates. Delete the webhook or stop the \
                     other instance."
                );
                tokio::time::sleep(Duration::from_secs(CONFLICT_PAUSE_SECS)).await;
            }
            Err(PollError::Other(e)) => {
                tracing::error!(error = %e, backoff, "telegram_poll_error");
                tokio::time::sleep(Duration::from_secs_f64(backoff)).await;
                backoff = (backoff * 2.0).min(MAX_BACKOFF_SECS);
            }
        }
    }
}

enum PollError {
    Conflict,
    Other(String),
}

/// One getUpdates cycle. Returns the offset to use next.
async fn poll_once(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    offset: i64,
) -> Result<i64, PollError> {
    let token = crate::config::secret_env::secret_required("TELEGRAM_BOT_TOKEN").map_err(PollError::Other)?;
    let url = format!("https://api.telegram.org/bot{token}/getUpdates");

    let resp = client
        .post(&url)
        .json(&json!({
            "offset": offset,
            "timeout": POLL_TIMEOUT_SECS,
            "allowed_updates": ["message", "callback_query"],
        }))
        .timeout(Duration::from_secs(CLIENT_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| PollError::Other(crate::redact::scrub(&e.to_string())))?;

    if resp.status().as_u16() == 409 {
        return Err(PollError::Conflict);
    }
    if !resp.status().is_success() {
        return Err(PollError::Other(format!("getUpdates HTTP {}", resp.status())));
    }

    let body: Value = resp
        .json()
        .await
        .map_err(|e| PollError::Other(crate::redact::scrub(&e.to_string())))?;
    let updates = body
        .get("result")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut next = offset;
    for update in &updates {
        // Advance the offset BEFORE handling. Telegram redelivers anything
        // not confirmed by a later offset, so if handling panics or the
        // process dies mid-reply, an un-advanced offset replays the same
        // message on the next poll — forever.
        if let Some(id) = update.get("update_id").and_then(|v| v.as_i64()) {
            next = id + 1;
        }
        let st = state.clone();
        let upd = update.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_update(st, &upd).await {
                // WARN: a dropped inbound message is invisible to the user
                // except as silence.
                // Scrubbed because this error can have come from a SEND,
                // whose URL carries the token as surely as the poll's does.
                tracing::warn!(error = %crate::redact::scrub(&e.to_string()), "telegram_pipeline_failed");
            }
        });
    }
    if !updates.is_empty() {
        tracing::info!(count = updates.len(), "telegram_updates_dispatched");
    }
    Ok(next)
}

/// Parse → identity → inference → send, for one update.
pub async fn handle_update(state: Arc<AppState>, update: &Value) -> Result<()> {
    let Some(parsed) = parse_update(update) else {
        return Ok(());
    };

    // DEFAULT DENY. A link in `noo_user_channel_links` is
    // the only thing that admits a sender. The old rule admitted anyone
    // when TELEGRAM_ALLOWED_USERS was unset and ran the turn under the raw
    // numeric id — a tool-bearing session scoped to an identity the system
    // invented on the spot.
    let canonical_user = match super::ingress::admit(&state.db, "telegram", &parsed.user_id).await {
        super::ingress::Admission::Admitted(u) => u,
        super::ingress::Admission::Refused { reply } => {
            if let Some(text) = reply {
                // Best-effort: a send failure must not turn a refusal into a
                // pipeline error that looks like a bug in the poll loop.
                if let Err(e) =
                    crate::routes::communication::send_telegram_reply(&parsed.chat_id, &text).await
                {
                    tracing::warn!(error = %e, "telegram_refusal_send_failed");
                }
            }
            return Ok(());
        }
    };

    // Resolved BEFORE the approval branches: the conversation is what a
    // bare `y` is now scoped to, so it has to exist before a shorthand can
    // be interpreted. It is the same conversation the turn would use, so
    // this costs one lookup, not a second identity.
    let context_id = chat_context_id(&parsed.chat_id, &parsed.user_id, &parsed.chat_type);
    let conversation_id = super::conversation::resolve(
        &state,
        "telegram",
        &context_id,
        conversation_metadata(&parsed),
    )
    .await?;

    // Approval buttons are decided, not answered. This check must come
    // BEFORE inference: without it a button press reached the model as the
    // literal text `noo-cluster-approve:<uuid>`, the proposal stayed
    // pending, and nothing anywhere reported a failure.
    //
    // Only recognized prefixes are intercepted; any other callback_data
    // falls through and is treated as a user turn, matching the Python
    // adapter's behaviour.
    if let Some(data) = parsed.callback_data.as_deref() {
        if let Some((verdict, proposal_id)) = super::approvals::parse_decision(data) {
            // Operator identity, not just "the adapter let this sender in".
            let ack = match super::approvals::chat_decider(&state.db, "telegram", &parsed.user_id).await {
                Ok(decider) => {
                    super::approvals::decide_cluster_proposal(
                        &state,
                        &proposal_id,
                        verdict,
                        &decider,
                        "telegram",
                    )
                    .await
                }
                Err(refusal) => refusal,
            };
            crate::routes::communication::send_telegram_reply(&parsed.chat_id, &ack)
                .await
                .map_err(|e| anyhow!("approval ack send failed: {e}"))?;
            tracing::info!(
                proposal_id = %proposal_id,
                verdict,
                chat_id = %parsed.chat_id,
                "telegram_approval_handled"
            );
            return Ok(());
        }
        if data.is_empty() {
            // Empty callback data: nothing to decide and nothing to answer.
            return Ok(());
        }
    }

    // Text-reply exec-approval decisions, same contract as the gchat
    // pipeline: `approve` / `deny` [id] as the whole message is decided,
    // not answered.
    if let Some(decision) = super::approvals::parse_text_decision(&parsed.text) {
        use super::approvals::PendingResolution;
        let ack = match super::approvals::resolve_pending_request(
            &state.db,
            decision.id.as_deref(),
            &conversation_id,
        )
        .await
        {
            Ok(PendingResolution::One(request_id)) => Some(
                match super::approvals::chat_decider(&state.db, "telegram", &parsed.user_id).await {
                    Ok(decider) => {
                        super::approvals::decide_exec_approval(
                            &state.db,
                            &request_id,
                            decision.verdict,
                            &decider,
                        )
                        .await
                    }
                    Err(refusal) => refusal,
                },
            ),
            // Shorthand (y/n/...) with nothing pending is just conversation
            // — fall through to the coordinator below.
            Ok(PendingResolution::None) if decision.soft => None,
            Ok(PendingResolution::None) => {
                Some("No pending approval requests.".to_string())
            }
            Ok(PendingResolution::Ambiguous) => {
                Some(super::approvals::AMBIGUOUS_PENDING_REPLY.to_string())
            }
            Err(msg) => Some(msg),
        };
        if let Some(ack) = ack {
            crate::routes::communication::send_telegram_reply(&parsed.chat_id, &ack)
                .await
                .map_err(|e| anyhow!("text approval ack send failed: {e}"))?;
            tracing::info!(verdict = decision.verdict, "telegram_text_approval_handled");
            return Ok(());
        }
    }

    // Scope the approval target: a HIGH-risk tool call made while
    // answering sends its approval notice back into THIS chat (operator
    // default 2026-08-08) instead of a separately configured one.
    let approval_target = crate::routes::communication::ApprovalTarget {
        channel: "telegram",
        recipient: parsed.chat_id.clone(),
        thread_id: None,
        // The real type: the approval card goes back into THIS chat, and
        // the target must say whether that is a room.
        chat_type: parsed.chat_type.clone(),
    };
    // The linked account's REAL role and scopes, not a blanket tier.
    let Some(principal) = crate::bus_principal::account_principal(&state.db, &canonical_user).await else {
        if let Err(e) = crate::routes::communication::send_telegram_reply(
            &parsed.chat_id,
            super::ACCOUNT_UNAVAILABLE_REPLY,
        )
        .await
        {
            tracing::warn!(error = %crate::redact::scrub(&e), "telegram_refusal_send_failed");
        }
        tracing::warn!(user = %canonical_user, "telegram_turn_refused: account disabled or unresolvable");
        return Ok(());
    };
    let (result, banner) = super::scoped_turn(principal, &parsed.chat_type, crate::routes::communication::CHANNEL_APPROVAL_TARGET
        .scope(Some(approval_target), async {
            crate::routes::communication::GATED_TOOL_FAILURES
                .scope(Default::default(), async {
                    crate::routes::communication::COMPLETED_GATED_CALLS
                        .scope(Default::default(), async {
                            let r = crate::coordinator::run(
                                &state,
                                &parsed.text,
                                &conversation_id,
                                "telegram",
                                state.config.coordinator.max_iterations,
                                None,
                                // Canonical username, NOT the raw Telegram id: per-user
                                // memory scoping, model preferences and org/team
                                // filtering all key on this, so passing the channel id
                                // makes one human look like a different person on
                                // every channel.
                                Some(&canonical_user),
                            )
                            .await;
                            let banner =
                                crate::routes::communication::gated_failure_banner();
                            (r, banner)
                        })
                        .await
                })
                .await
        }))
        .await;
    // A failed turn used to answer with silence. Tier 2 of the egress
    // boundary: the chat gets a general sentence and a reference id, the
    // error is logged under that reference (crate::egress::error_reply).
    let result = match result {
        Ok(r) => r,
        Err(e) => {
            let notice = crate::egress::error_reply("answer that \u{2014} try again in a minute", &e);
            if let Err(se) = crate::routes::communication::send_telegram_reply(&parsed.chat_id, &notice).await {
                tracing::warn!(error = %crate::redact::scrub(&se), "telegram_failure_notice_failed");
            }
            return Err(anyhow!("inference failed: {e}"));
        }
    };

    // Token-usage accounting — fire-and-forget.
    crate::usage::record(
        state.db.clone(),
        result.node.clone(),
        result.backend.clone(),
        result.model.clone(),
        "channel",
        crate::usage::UsageActor::user(canonical_user.clone(), "telegram"),
        result.usage.prompt_tokens,
        result.usage.completion_tokens,
    );

    // send_telegram already handles the 4096-char limit by splitting.
    let reply = match &banner {
        Some(b) => format!("{b}{}", result.response),
        None => result.response.clone(),
    };
    crate::routes::communication::send_telegram_reply(&parsed.chat_id, &reply)
        .await
        .map_err(|e| anyhow!("send failed: {e}"))?;

    tracing::info!(
        conversation_id = %conversation_id,
        chat_type = %parsed.chat_type,
        model = %result.model,
        iterations = result.iterations,
        "telegram_reply_sent"
    );
    Ok(())
}

/// Metadata a newly created Telegram conversation is stored with. See
/// `channels::conversation` for why `noo_routing` is explicit.
fn conversation_metadata(p: &ParsedUpdate) -> Value {
    json!({
        "source_channel": "telegram",
        "chat_id": p.chat_id,
        "chat_type": p.chat_type,
        "chat_title": p.chat_title,
        "user_id": p.user_id,
        "noo_routing": {
            "version": 1,
            "channel": "telegram",
            "recipient": p.chat_id,
            "chat_type": p.chat_type,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(chat_id: i64, chat_type: &str, text: &str) -> Value {
        json!({
            "update_id": 1,
            "message": {
                "chat": {"id": chat_id, "type": chat_type, "title": "Room"},
                "from": {"id": 42, "first_name": "Ada", "last_name": "L"},
                "text": text,
                "date": 0
            }
        })
    }

    #[test]
    fn parses_a_plain_message() {
        let p = parse_update(&msg(1234, "private", "hello")).unwrap();
        assert_eq!(p.chat_id, "1234");
        assert_eq!(p.user_id, "42");
        assert_eq!(p.sender_name, "Ada L");
        assert_eq!(p.text, "hello");
        assert_eq!(p.chat_type, "private");
    }

    #[test]
    fn group_keys_by_chat_and_sender() {
        // Each member of a group has their OWN thread: one member's history
        // must never load as another's context.
        let pa = parse_update(&msg(-100, "group", "a")).unwrap();
        let a = chat_context_id(&pa.chat_id, &pa.user_id, &pa.chat_type);
        let mut other = msg(-100, "group", "b");
        other["message"]["from"]["id"] = json!(99);
        let pb = parse_update(&other).unwrap();
        let b = chat_context_id(&pb.chat_id, &pb.user_id, &pb.chat_type);
        assert_ne!(a, b);
        assert_eq!(a, "telegram:-100:42");
        assert_eq!(b, "telegram:-100:99");
        // The same member in the same group keeps the same thread.
        assert_eq!(a, chat_context_id("-100", "42", "supergroup"));
    }

    #[test]
    fn a_dm_is_keyed_by_the_chat_alone() {
        let p = parse_update(&msg(1234, "private", "hi")).unwrap();
        assert_eq!(chat_context_id(&p.chat_id, &p.user_id, &p.chat_type), "telegram:1234");
    }

    #[test]
    fn a_missing_chat_type_is_a_room_not_a_dm() {
        let mut m = msg(7, "private", "hi");
        m["message"]["chat"].as_object_mut().unwrap().remove("type");
        let p = parse_update(&m).unwrap();
        assert_eq!(p.chat_type, "unknown");
        assert!(super::super::is_shared_room(&p.chat_type));
        assert_eq!(chat_context_id(&p.chat_id, &p.user_id, &p.chat_type), "telegram:7:42");
    }

    /// The approval target carries the chat's real type (it was hard-coded
    /// `private`), and the turn is scoped as the linked account.
    #[test]
    fn the_approval_target_uses_the_real_chat_type() {
        let src = include_str!("telegram.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(!code.contains("chat_type: \"private\".to_string()"));
        assert!(code.contains("chat_type: parsed.chat_type.clone()"));
    }

    #[test]
    fn caption_is_used_when_there_is_no_text() {
        // An image with a question attached must not read as empty.
        let mut m = msg(1, "private", "");
        m["message"]["text"] = json!("");
        m["message"]["caption"] = json!("what is this?");
        let p = parse_update(&m).unwrap();
        assert_eq!(p.text, "what is this?");
    }

    #[test]
    fn empty_message_is_skipped() {
        let mut m = msg(1, "private", "");
        m["message"]["text"] = json!("   ");
        assert!(parse_update(&m).is_none());
    }

    #[test]
    fn callback_query_is_distinguishable_from_typed_text() {
        // The bug this guards: both shapes set `text`, so without
        // callback_data an approval button press was indistinguishable from
        // someone typing the button id, and went to inference.
        let cb = json!({
            "callback_query": {
                "from": {"id": 42, "first_name": "Ada"},
                "message": {"chat": {"id": 99, "type": "private"}},
                "data": "noo-cluster-approve:abc-123"
            }
        });
        let parsed = parse_update(&cb).expect("callback should parse");
        assert_eq!(
            parsed.callback_data.as_deref(),
            Some("noo-cluster-approve:abc-123")
        );
        assert!(
            super::super::approvals::parse_decision(parsed.callback_data.as_deref().unwrap())
                .is_some(),
            "an approval press must be recognized as a decision, not a chat turn"
        );

        // A typed message must NOT look like a callback.
        let typed = parse_update(&msg(99, "private", "hello")).expect("message should parse");
        assert_eq!(typed.callback_data, None);
    }

    #[test]
    fn parses_a_callback_query() {
        let cb = json!({
            "update_id": 2,
            "callback_query": {
                "from": {"id": 7, "username": "bob"},
                "data": "approve",
                "message": {"chat": {"id": 55, "type": "private"}, "date": 0}
            }
        });
        let p = parse_update(&cb).unwrap();
        assert_eq!(p.text, "approve");
        assert_eq!(p.chat_id, "55");
        assert_eq!(p.user_id, "7");
        assert_eq!(p.sender_name, "bob");
    }

    #[test]
    fn display_name_falls_back_to_username() {
        let u = json!({"id": 1, "username": "solo"});
        assert_eq!(display_name(&u), "solo");
    }
}
