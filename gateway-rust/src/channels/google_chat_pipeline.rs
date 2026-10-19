// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Google Chat inbound pipeline — Rust end to end.
//!
//! Replaces the round trip that every inbound message used to make:
//!
//! ```text
//!   Rust pull → NATS → Python parse → HTTP loopback (cluster-HMAC)
//!       → Rust /api/inference → back to Python → Rust send
//! ```
//!
//! `ChannelManager.generate_reply` in Rust-primary mode was an HTTP call
//! back into Rust. This module removes that hop and the auth round trip
//! with it: parse, identity, inference, formatting and send all happen in
//! one process.
//!
//! What is deliberately NOT here: conversation identity. That is memory,
//! and memory is Trellion, so it is resolved over
//! `worker.memory.resolve_conversation`. Reading Trellion's tables from
//! Rust would duplicate schema knowledge across two languages — the exact
//! failure mode this port exists to eliminate (it is what produced the
//! OAuth token-cache outage, where the same job implemented twice drifted
//! apart and killed all inbound Chat).

use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_json::json;

use super::google_chat_format::{parse_event, resolve_reply_target, ParsedEvent};
use crate::state::AppState;

/// Chat context key for this channel.
///
/// A named space is keyed by (SPACE, SENDER): the room is shared for
/// delivery and for knowledge, but each member has their own thread, so one
/// member's history is never loaded as another's context. A DM is keyed by
/// the sender. This is the adapter-specific rule that used to live in
/// `ChannelManager._chat_context_id`, and it travels with the harness rather
/// than moving into the memory plane.
fn chat_context_id(chat_type: &str, space_name: &str, sender_id: &str) -> String {
    if chat_type == "space" && !space_name.is_empty() {
        format!("google_chat:{space_name}:{sender_id}")
    } else {
        format!("google_chat:{sender_id}")
    }
}

/// Handle one inbound Chat event, from raw Pub/Sub body to sent reply.
/// Immediate acknowledgement for pull-mode messages. Parity with the
/// Python adapter's _PUBSUB_ACK_NOTICE; see the comment at the send site.
const ACK_NOTICE: &str = "\u{1F4AD} Thinking\u{2026}";
/// What the chat is told when reply generation fails after the ack —
/// without it the chat shows "Thinking…" forever. Tier 2 of the egress
/// boundary: a general sentence and a reference id; the error itself is
/// logged under that reference (`crate::egress::error_reply`).
const FAILURE_WHAT: &str = "answer that \u{2014} try again in a minute";

pub async fn handle_event(state: Arc<AppState>, body: &[u8]) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| anyhow!("event body is not JSON: {e}"))?;

    let ev = parse_event(&value);

    // Is this an event we would ACT on at all? ADDED_TO_SPACE and friends
    // arrive on the same subscription; refusing those would answer Google's
    // lifecycle events with a "link your account" notice.
    let card_action = super::approvals::extract_card_action_id(&value);
    let actionable =
        card_action.is_some() || (ev.event_type == "MESSAGE" && !ev.text.trim().is_empty());
    if !actionable {
        tracing::debug!(event_type = %ev.event_type, "gchat_event_skipped");
        return Ok(());
    }

    // DEFAULT DENY. Google Chat had NO allow-list at all:
    // `resolve_user(...).unwrap_or_else(|| sender_id)` handed the raw
    // `users/1152…` string to the coordinator as the user, so anyone who
    // could DM the bot — or be added to a space with it — got a
    // tool-bearing session under an identity the system invented. A link in
    // `noo_user_channel_links` is now the only thing that admits a sender,
    // the same rule Telegram applies.
    let canonical_user = match super::ingress::admit(&state.db, "google_chat", &ev.sender_id).await {
        super::ingress::Admission::Admitted(u) => u,
        super::ingress::Admission::Refused { reply } => {
            if let Some(text) = reply {
                let target = resolve_reply_target(&ev);
                if !target.recipient.is_empty() {
                    if let Err(e) = crate::routes::communication::send_google_chat_reply(
                        &target.recipient,
                        &text,
                        target.thread_id.as_deref(),
                        Some(&target.chat_type),
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "gchat_refusal_send_failed");
                    }
                }
            }
            return Ok(());
        }
    };

    // Card clicks are decided, not answered — and they must be handled BEFORE
    // the MESSAGE gate below, which is what used to drop them. A CARD_CLICKED
    // event arriving over Pub/Sub hit the `event_type != "MESSAGE"` early
    // return and vanished at debug level, so approval buttons in Chat did
    // nothing and said nothing.
    //
    // Unrecognized action ids fall through to the normal message flow, which
    // matches the Python adapter: only the cluster-proposal prefixes are
    // intercepted.
    if let Some(action_id) = card_action {
        // Exec-approval cards first (approve-then-execute gate): the click
        // flips the noo_approval_requests row the blocked tool call is
        // polling, then acks into the same space.
        if let Some((verdict, request_id)) = super::approvals::parse_exec_decision(&action_id) {
            let ev = parse_event(&value);
            let ack = match super::approvals::chat_decider(&state.db, "google_chat", &ev.sender_id).await {
                Ok(decider) => {
                    super::approvals::decide_exec_approval(&state.db, &request_id, verdict, &decider).await
                }
                Err(refusal) => refusal,
            };
            let target = resolve_reply_target(&ev);
            if target.recipient.is_empty() {
                tracing::warn!(
                    request_id = %request_id,
                    "gchat_exec_approval_ack_undeliverable_no_recipient"
                );
                return Ok(());
            }
            crate::routes::communication::send_google_chat_reply(
                &target.recipient,
                &ack,
                target.thread_id.as_deref(),
                Some(&target.chat_type),
            )
            .await
            .map_err(|e| anyhow!("exec approval ack send failed: {e}"))?;
            tracing::info!(
                request_id = %request_id,
                verdict,
                "gchat_exec_approval_handled"
            );
            return Ok(());
        }
        if let Some((verdict, proposal_id)) = super::approvals::parse_decision(&action_id) {
            let ack = match super::approvals::chat_decider(&state.db, "google_chat", &ev.sender_id).await {
                Ok(decider) => {
                    super::approvals::decide_cluster_proposal(
                        &state,
                        &proposal_id,
                        verdict,
                        &decider,
                        "google_chat",
                    )
                    .await
                }
                Err(refusal) => refusal,
            };
            let target = resolve_reply_target(&ev);
            if target.recipient.is_empty() {
                // Nothing to reply into. Say so rather than dropping the ack
                // silently — the decision IS already recorded at this point.
                tracing::warn!(
                    proposal_id = %proposal_id,
                    "gchat_approval_ack_undeliverable_no_recipient"
                );
                return Ok(());
            }
            crate::routes::communication::send_google_chat_reply(
                &target.recipient,
                &ack,
                target.thread_id.as_deref(),
                Some(&target.chat_type),
            )
            .await
            .map_err(|e| anyhow!("approval ack send failed: {e}"))?;
            tracing::info!(
                proposal_id = %proposal_id,
                verdict,
                space = %target.recipient,
                "gchat_approval_handled"
            );
            return Ok(());
        }
    }

    // An UNRECOGNISED card action falls through to here (the branch above
    // only intercepts the four known prefixes). It is not a message, so it
    // has nothing to answer.
    if ev.event_type != "MESSAGE" || ev.text.trim().is_empty() {
        tracing::debug!(event_type = %ev.event_type, "gchat_event_skipped");
        return Ok(());
    }

    // Resolved BEFORE the text-decision branch: a bare `y` is scoped to the
    // conversation it was typed in, so the conversation has to exist before
    // the shorthand can mean anything. Same conversation the turn uses.
    let context_id = chat_context_id(&ev.chat_type, &ev.space_name, &ev.sender_id);
    let conversation_id = super::conversation::resolve(
        &state,
        "google_chat",
        &context_id,
        conversation_metadata(&ev),
    )
    .await?;

    // Text-reply decisions: `approve` / `deny` [id] as the WHOLE message
    // flips the exec-approval row directly — the transport that provably
    // works, since Pub/Sub apps never receive card button clicks (first
    // live card test, 2026-08-09). Decided, not answered: no thinking ack,
    // no coordinator turn.
    if let Some(decision) = super::approvals::parse_text_decision(&ev.text) {
        use super::approvals::PendingResolution;
        let ack = match super::approvals::resolve_pending_request(
            &state.db,
            decision.id.as_deref(),
            &conversation_id,
        )
        .await
        {
            Ok(PendingResolution::One(request_id)) => Some(
                // Being admitted is not being an operator: `chat_decider`
                // is the second gate, and it is the only thing between a
                // linked colleague in a shared space and a blocked exec
                //
                match super::approvals::chat_decider(&state.db, "google_chat", &ev.sender_id).await {
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
            let target = resolve_reply_target(&ev);
            if !target.recipient.is_empty() {
                crate::routes::communication::send_google_chat_reply(
                    &target.recipient,
                    &ack,
                    target.thread_id.as_deref(),
                    Some(&target.chat_type),
                )
                .await
                .map_err(|e| anyhow!("text approval ack send failed: {e}"))?;
            }
            tracing::info!(verdict = decision.verdict, "gchat_text_approval_handled");
            return Ok(());
        }
    }

    // Immediate acknowledgement — Pub/Sub pull has no synchronous response
    // and inference runs 30-80s, so without this the space/DM shows nothing
    // until the answer lands. Parity with the Python adapter's
    // _PUBSUB_ACK_NOTICE ("the ack" operators expect — its absence was
    // reported as a missing feature the day the Rust reply path first
    // worked, 2026-08-08). Best-effort: an ack failure must not eat the
    // real reply.
    let ack_target = resolve_reply_target(&ev);
    if !ack_target.recipient.is_empty() {
        if let Err(e) = crate::routes::communication::send_google_chat_reply(
            &ack_target.recipient,
            ACK_NOTICE,
            ack_target.thread_id.as_deref(),
            Some(&ack_target.chat_type),
        )
        .await
        {
            tracing::warn!(error = %e, "gchat_ack_send_failed");
        }
    }

    // Failure after the ack must not strand a bare "Thinking…" in the
    // chat — send the failure notice (best-effort) and still surface the
    // error to the dispatcher's gchat_pipeline_failed log.
    let outcome = process_message(state, &ev, &conversation_id, &canonical_user).await;
    if let Err(e) = &outcome {
        if !ack_target.recipient.is_empty() {
            let _ = crate::routes::communication::send_google_chat_reply(
                &ack_target.recipient,
                &crate::egress::error_reply(FAILURE_WHAT, e),
                ack_target.thread_id.as_deref(),
                Some(&ack_target.chat_type),
            )
            .await;
        }
        tracing::warn!(error = %e, "gchat_failure_notice_sent");
    }
    outcome
}

/// Resolution → inference → reply for one MESSAGE event. Split from
/// handle_event so the caller can pair any failure with a failure notice.
async fn process_message(
    state: Arc<AppState>,
    ev: &ParsedEvent,
    conversation_id: &str,
    canonical_user: &str,
) -> Result<()> {
    // Both already resolved by the caller: the conversation because the
    // approval shorthand is scoped to it, and the canonical user because
    // admission IS identity resolution here — there is no longer an
    // "unlinked sender" case to fall back for.
    let canonical_user = canonical_user.to_string();

    // Scope the approval target to this turn: a HIGH-risk tool call made
    // while answering posts its Approve/Deny card back into THIS
    // conversation (operator default 2026-08-08) instead of a separately
    // configured space.
    let approval_target = {
        let t = resolve_reply_target(ev);
        crate::routes::communication::ApprovalTarget {
            channel: "google_chat",
            recipient: t.recipient,
            thread_id: t.thread_id,
            chat_type: t.chat_type,
        }
    };
    // The linked account's REAL role and scopes, not a blanket tier.
    let Some(principal) = crate::bus_principal::account_principal(&state.db, &canonical_user).await else {
        let target = resolve_reply_target(ev);
        if let Err(e) = crate::routes::communication::send_google_chat_reply(
            &target.recipient,
            super::ACCOUNT_UNAVAILABLE_REPLY,
            target.thread_id.as_deref(),
            Some(&target.chat_type),
        )
        .await
        {
            tracing::warn!(error = %crate::redact::scrub(&e), "gchat_refusal_send_failed");
        }
        tracing::warn!(user = %canonical_user, "gchat_turn_refused: account disabled or unresolvable");
        return Ok(());
    };
    let (result, banner) = super::scoped_turn(principal, &ev.chat_type, crate::routes::communication::CHANNEL_APPROVAL_TARGET
        .scope(Some(approval_target), async {
            crate::routes::communication::GATED_TOOL_FAILURES
                .scope(Default::default(), async {
                    crate::routes::communication::COMPLETED_GATED_CALLS
                        .scope(Default::default(), async {
                            let r = crate::coordinator::run(
                                &state,
                                &ev.text,
                                conversation_id,
                                "google_chat",
                                state.config.coordinator.max_iterations,
                                None,
                                Some(&canonical_user),
                            )
                            .await;
                            // Read inside the scope: the task-local dies with it.
                            let banner =
                                crate::routes::communication::gated_failure_banner();
                            (r, banner)
                        })
                        .await
                })
                .await
        }))
        .await;
    let result = result.map_err(|e| anyhow!("inference failed: {e}"))?;

    // Token-usage accounting — fire-and-forget.
    crate::usage::record(
        state.db.clone(),
        result.node.clone(),
        result.backend.clone(),
        result.model.clone(),
        "channel",
        crate::usage::UsageActor::user(canonical_user.clone(), "google_chat"),
        result.usage.prompt_tokens,
        result.usage.completion_tokens,
    );

    let target = resolve_reply_target(ev);
    let threaded = target.thread_id.is_some();

    // Send the RAW model output. `send_google_chat` already applies both
    // Chat formatting (`markdown_to_gchat`) and the named-space
    // `messageReplyOption` rule, so pre-converting here would double-encode
    // every message — the two converters are different implementations
    // (regex vs hand-rolled with code-span protection), so the second pass
    // would mangle code spans rather than being a harmless no-op.
    //
    // That duplication is real and should be collapsed onto the tested
    // `google_chat_format` versions, but doing it here would change the
    // formatting of ALL outbound Chat traffic inside a change whose point
    // is moving the inbound path. Left as a follow-up so a formatting
    // regression stays attributable.
    // Gateway gets the last word: a denied/expired gated call prepends a
    // correction banner so the model cannot claim the action happened.
    let reply = match &banner {
        Some(b) => format!("{b}{}", result.response),
        None => result.response.clone(),
    };
    crate::routes::communication::send_google_chat_reply(
        &target.recipient,
        &reply,
        target.thread_id.as_deref(),
        Some(&target.chat_type),
    )
    .await
    .map_err(|e| anyhow!("send failed: {e}"))?;

    tracing::info!(
        conversation_id = %conversation_id,
        chat_type = %ev.chat_type,
        threaded,
        model = %result.model,
        iterations = result.iterations,
        "gchat_reply_sent"
    );
    Ok(())
}

/// Metadata a newly created Google Chat conversation is stored with.
///
/// `noo_routing` is the explicit contract with Trellion — it exists so the
/// memory system stores a routing record instead of reconstructing a reply
/// address from channel-specific keys it should not have to understand.
fn conversation_metadata(ev: &super::google_chat_format::ParsedEvent) -> serde_json::Value {
    json!({
        "source_channel": "google_chat",
        "chat_id": ev.sender_id,
        "chat_type": ev.chat_type,
        "space_name": ev.space_name,
        "noo_routing": {
            "version": 1,
            "channel": "google_chat",
            "recipient": if ev.chat_type == "space" { &ev.space_name } else { &ev.sender_id },
            "chat_type": ev.chat_type,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_keys_by_space_and_sender() {
        // Each member of a room has their own thread: one member's history
        // is never loaded as another's context.
        let a = chat_context_id("space", "spaces/AAA", "users/1");
        let b = chat_context_id("space", "spaces/AAA", "users/2");
        assert_ne!(a, b);
        assert_eq!(a, "google_chat:spaces/AAA:users/1");
        // And the same member in a different space has a different thread.
        assert_ne!(a, chat_context_id("space", "spaces/BBB", "users/1"));
        // The same member in the same space keeps the same thread.
        assert_eq!(a, chat_context_id("space", "spaces/AAA", "users/1"));
    }

    #[test]
    fn dm_keys_by_sender() {
        let a = chat_context_id("private", "", "users/1");
        let b = chat_context_id("private", "", "users/2");
        assert_ne!(a, b);
        assert_eq!(a, "google_chat:users/1");
    }

    #[test]
    fn card_click_is_recognized_before_the_message_gate() {
        // The bug this guards: CARD_CLICKED has event_type != "MESSAGE" and
        // empty text, so it hit the early return and was dropped. Assert the
        // action id is extractable and parses as a decision, so the handler
        // reaches the approval branch first.
        let ev = json!({
            "type": "CARD_CLICKED",
            "user": {"name": "users/1", "displayName": "Ada"},
            "space": {"name": "spaces/AAA", "type": "ROOM"},
            "action": {"actionMethodName": "noo-cluster-approve:abc-123"}
        });
        let parsed = parse_event(&ev);
        assert_ne!(parsed.event_type, "MESSAGE");
        assert!(parsed.text.trim().is_empty());

        let action = super::super::approvals::extract_card_action_id(&ev)
            .expect("card action id must be extractable");
        assert_eq!(
            super::super::approvals::parse_decision(&action),
            Some(("approve", "abc-123".to_string()))
        );
        // And the ack must have somewhere to go.
        assert_eq!(resolve_reply_target(&parsed).recipient, "spaces/AAA");
    }

    #[test]
    fn v2_card_click_resolves_its_space() {
        // v2 nests space under chat.messagePayload; without the fallback the
        // recipient was empty and the ack had nowhere to be delivered.
        let ev = json!({
            "chat": {
                "user": {"name": "users/9", "displayName": "Grace"},
                "messagePayload": {"space": {"name": "spaces/BBB", "type": "ROOM"}},
                "buttonClickedPayload": {"clientActions": [
                    {"actionMethodName": "noo-cluster-reject:xyz"}
                ]}
            }
        });
        let parsed = parse_event(&ev);
        assert_eq!(parsed.space_name, "spaces/BBB");
        assert_eq!(parsed.sender_name, "Grace");
        assert_eq!(resolve_reply_target(&parsed).recipient, "spaces/BBB");
    }

    #[test]
    fn space_without_a_name_falls_back_to_sender() {
        // Never key on an empty string — every such space would collapse
        // into one shared conversation.
        let id = chat_context_id("space", "", "users/7");
        assert_eq!(id, "google_chat:users/7");
    }
}
