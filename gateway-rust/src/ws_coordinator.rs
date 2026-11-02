// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! WebSocket handler for /ws/coordinator — chat streaming.
//!
//! Delegates to the coordinator module for the full agentic loop:
//! backend resolution → context injection → LLM call → tool dispatch → persist.
//!
//! Writes go through a [`crate::websocket::WsWriter`] (channel + forwarder
//! task) rather than the socket directly: the agent loop holds the
//! writer for a whole turn, and an exec-approval request raised mid-turn
//! must still reach THIS client as an `approval_request` frame — with a
//! `&mut WebSocket` that was impossible, which is why #606's broadcast only
//! ever reached other, idle tabs.

use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::coordinator;
use crate::state::AppState;
use crate::websocket::{verify_ws_auth, WsParams, WsWriter};

#[derive(Debug, Deserialize)]
struct ChatMessage {
    prompt: String,
    #[serde(default, deserialize_with = "nullable_string")]
    conversation_id: String,
    #[serde(default, deserialize_with = "nullable_string")]
    user_id: String,
    #[serde(default)]
    enable_thinking: bool,
    #[serde(default)]
    model: Option<String>,
}

/// Deserialize a string that might be null (JS sends null for unset fields).
fn nullable_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Option::<String>::deserialize(d).map(|o| o.unwrap_or_default())
}

/// WebSocket upgrade handler for /ws/coordinator.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let jwt_sec = crate::auth::jwt_secret();

    match verify_ws_auth(&params, &jwt_sec) {
        Ok(claims) => {
            ws.on_upgrade(move |socket| handle_chat(socket, state, claims))
        }
        Err(e) => {
            tracing::warn!(error = %e, "ws_coordinator auth failed");
            ws.on_upgrade(move |mut socket| async move {
                let _ = crate::websocket::send_event(
                    &mut socket,
                    "error",
                    json!("Authentication failed"),
                )
                .await;
                // Close with 4401 so the client knows not to reconnect
                let close_frame = axum::extract::ws::CloseFrame {
                    code: 4401,
                    reason: "Authentication failed".into(),
                };
                let _ = socket.send(Message::Close(Some(close_frame))).await;
            })
        }
    }
}

async fn handle_chat(
    socket: axum::extract::ws::WebSocket,
    state: Arc<AppState>,
    claims: crate::auth::Claims,
) {
    let user_id = claims.sub.clone();
    let role = claims.resolved_role();
    // The identity every tool call this session makes will be signed with.
    //
    // Built ONCE from the verified JWT, not per turn from the message: the
    // payload's `user_id` is advisory and `effective_user_id` already
    // discards it when it disagrees, so there is exactly one subject here
    // and no impersonation path to preserve.
    let principal =
        crate::bus_principal::Principal::user(user_id.clone(), role, claims.scopes.clone());
    tracing::info!(user_id = %user_id, "ws_coordinator connected");

    let (writer, mut stream, forwarder) = WsWriter::spawn(socket);

    // Register with alert hub; a dedicated forwarder keeps broadcast
    // alerts flowing even while a turn is in progress (previously the
    // select loop was blocked inside run_streaming for the whole turn,
    // so alerts queued until the turn ended).
    state.alert_hub.register_client();
    let alert_writer = writer.clone();
    let mut alert_rx = state.alert_hub.subscribe();
    let alert_sub = user_id.clone();
    let alert_task = tokio::spawn(async move {
        loop {
            match alert_rx.recv().await {
                Ok(payload) => {
                    if !crate::state::audience_allows(&payload, &alert_sub, role) {
                        continue;
                    }
                    if !alert_writer.send_json(&payload).await {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!(missed = n, "ws_coordinator alert_rx lagged");
                }
                Err(_) => break, // channel closed
            }
        }
    });

    // The session ends when the token's `exp` passes or the account logs
    // out: close 4401, reason in the close frame. No `error` frame — the
    // console wrote it into the last reply on screen, one "Token expired"
    // per 15 minutes in an idle tab. Expiry first lets a streaming turn
    // finish (`TurnGate`); a logout closes at once. The read loop ends on
    // the peer's close reply (or on the next failed keepalive).
    let gate = Arc::new(crate::websocket::TurnGate::default());
    let guard_writer = writer.clone();
    let guard_sub = user_id.clone();
    let guard_gate = gate.clone();
    let ends = state.alert_hub.subscribe_session_end();
    let exp = claims.exp;
    let guard_task = tokio::spawn(async move {
        let reason = crate::websocket::session_ended(exp, &guard_sub, ends).await;
        if reason == "Logged out" {
            guard_gate.end_now();
        } else {
            guard_gate.finish_then_end(crate::websocket::TURN_GRACE).await;
        }
        tracing::info!(user_id = %guard_sub, reason, "ws_coordinator session ended");
        let _ = guard_writer.send_close(reason).await;
    });

    loop {
        // Client message or timeout (keepalive)
        let msg = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next()).await;
        match msg {
            Ok(Some(Ok(Message::Text(text)))) => {
                let chat_msg: ChatMessage = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = writer
                            .send_event("error", json!(format!("Invalid message: {e}")))
                            .await;
                        continue;
                    }
                };

                // The session is closing (token expired, logout): start
                // nothing; the console reconnects with a fresh token.
                let Some(_turn) = gate.begin() else {
                    let _ = writer
                        .send_event("error", json!("Your session was renewing. Send that again."))
                        .await;
                    continue;
                };

                let conv_id = if chat_msg.conversation_id.is_empty() {
                    uuid::Uuid::new_v4().to_string()
                } else {
                    chat_msg.conversation_id.clone()
                };

                let max_iter = state.config.coordinator.max_iterations;

                // Run the full agentic loop.
                // The authenticated subject (verified JWT `sub`, passed in
                // as `user_id`) is authoritative — a client-supplied
                // user_id in the message body is never trusted, otherwise
                // any authenticated user could set it to another user and
                // read/write that user's memory (H-D1 impersonation).
                let uid = crate::auth::effective_user_id(Some(&user_id), Some(&chat_msg.user_id));

                // Check LLM cache first — keyed by WHO asked as well as what
                // the answer is built from the caller's own
                // memory and audience-filtered KB evidence.
                let messages_for_cache = vec![json!({"role": "user", "content": chat_msg.prompt})];
                let cache_key = crate::cache::RedisCache::llm_cache_key(
                    "auto", &messages_for_cache, uid.as_deref());
                if let Some(redis) = state.redis.as_ref() {
                    if let Some(cached) = redis.get_llm_cache(&cache_key).await {
                        tracing::debug!("llm_cache_hit");
                        if let Some(content) = cached.get("content").and_then(|c| c.as_str()) {
                            let _ = writer.send_event("content", json!(content)).await;
                        }
                        let _ = writer
                            .send_event("done", json!({
                                "iterations": 0, "cached": true, "engine": "rust",
                            }))
                            .await;
                        continue;
                    }
                }

                // Run the full agentic loop (identity resolved above).

                // Scope the dashboard approval writer around the turn
                //: a High-risk tool call inside run_streaming
                // raises an inline approval_request frame on THIS socket.
                // Sign the turn as the person who asked for it.
                //
                // Task-locals do not cross `tokio::spawn`, and the upgrade
                // that produced this task is a spawn — so the principal the
                // HTTP middleware puts in scope never reached here. Every
                // `worker.*` message a chat turn sent went out as
                // `internal:unattributed`, a real principal with NO scopes.
                //
                // That is not a silent-but-harmless gap. Knowledge reads
                // resolve the caller's audience from this subject, so an
                // unattributed turn got `{company, system, user:internal:
                // unattributed}` and matched nothing a real person owns —
                // returning zero results as a SUCCESS, which reads as "there
                // is nothing there" rather than "I do not know who you are".
                // It also made every chat turn anonymous in the worker audit
                // trail.
                let run = crate::bus_principal::with_principal(
                    principal.clone(),
                    crate::routes::communication::DASHBOARD_APPROVAL_TX.scope(
                    Some(writer.clone()),
                    coordinator::run_streaming(
                        &writer,
                        &state,
                        &chat_msg.prompt,
                        &conv_id,
                        max_iter,
                        chat_msg.model.as_deref(),
                        uid.as_deref(),
                        chat_msg.enable_thinking,
                    ),
                    ),
                );
                // A logout or an admin ending the account's sessions drops the
                // turn here, tools and all; the guard sends the 4401 close and
                // the loop ends on the peer's close reply. Expiry never
                // revokes: it lets the turn finish (`TurnGate`). While the
                // turn runs, a keepalive every TURN_KEEPALIVE tells the console
                // it is alive: its frames can be minutes apart, and the console
                // gives up on a silent turn (0.6.15: Send stayed disabled).
                let ka_writer = writer.clone();
                let outcome = match crate::websocket::run_turn_with_keepalive(
                    run,
                    gate.revoked(),
                    crate::websocket::TURN_KEEPALIVE,
                    || {
                        let w = ka_writer.clone();
                        async move {
                            let _ = w.send_keepalive().await;
                        }
                    },
                )
                .await
                {
                    Some(r) => r,
                    None => {
                        tracing::info!(user_id = %user_id, conv_id = %conv_id, "ws_coordinator turn dropped: session revoked");
                        // The turn in flight owns the console's last reply: end
                        // it there, so the composer unlocks even when the 4401
                        // close is slow to arrive. (Between turns, a session end
                        // sends no error frame; see the guard above.)
                        let _ = writer
                            .send_event("error", json!("Your session ended (signed out), so this reply stopped. Sign in and send it again."))
                            .await;
                        let _ = writer.send_event("done", json!({"iterations": 0, "error": "session revoked"})).await;
                        continue;
                    }
                };
                match outcome {
                    Ok(result) => {
                        // Cache the response
                        if !result.response.is_empty() {
                            if let Some(redis) = state.redis.as_ref() {
                                redis
                                    .set_llm_cache(
                                        &cache_key,
                                        &json!({"content": result.response}),
                                        None,
                                    )
                                    .await;
                            }
                        }
                        // Token-usage accounting —
                        // fire-and-forget.
                        crate::usage::record(
                            state.db.clone(),
                            result.node.clone(),
                            result.backend.clone(),
                            result.model.clone(),
                            "chat",
                            crate::usage::UsageActor::user(user_id.clone(), "dashboard"),
                            result.usage.prompt_tokens,
                            result.usage.completion_tokens,
                        );
                    }
                    Err(e) => {
                        let err_msg = format!("{e:#}");
                        tracing::error!(error = %err_msg, prompt = %chat_msg.prompt, conv_id = %conv_id, "coordinator_streaming_error");
                        let _ = writer.send_event("error", json!(err_msg)).await;
                        let _ = writer
                            .send_event("done", json!({"iterations": 0, "error": err_msg}))
                            .await;
                    }
                }
            }
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
            Ok(Some(Err(e))) => {
                tracing::debug!(error = %e, "ws_coordinator error");
                break;
            }
            Err(_)
                if !writer.send_keepalive().await => {
                    break;
                }
            _ => {}
        }
    }

    alert_task.abort();
    guard_task.abort();
    drop(writer); // last clone gone → forwarder drains and exits
    let _ = forwarder.await;
    state.alert_hub.deregister_client();
    tracing::info!(user_id = %user_id, "ws_coordinator disconnected");
}

#[cfg(test)]
mod tests {
    use crate::auth::Role;
    use crate::bus_principal::{Kind, Principal, UNATTRIBUTED};

    /// The source of this module, comments stripped.
    ///
    /// A guard that reads its own file is the only kind available here: the
    /// thing being asserted is that a future is WRAPPED, and a wrapper that
    /// is removed changes no signature and breaks no test that merely calls
    /// the handler.
    fn code() -> String {
        let whole = include_str!("ws_coordinator.rs");
        // Everything ABOVE this test module. Without the cut the guard reads
        // its own assertion literals and matches them — which is exactly how
        // the first version of it failed, and the third time this session
        // that a source-reading guard has been fooled by the prose beside
        // the code it guards.
        let src = &whole[..whole.find("#[cfg(test)]").unwrap_or(whole.len())];
        src.lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_turn_runs_inside_a_principal_scope() {
        let src = code();
        let at = src
            .find("with_principal(")
            .expect("the chat turn no longer enters a bus principal — every tool call it makes \
                    will publish as internal:unattributed, and knowledge reads will resolve an \
                    audience that matches nothing a real person owns");
        let after = &src[at..];
        let run = after
            .find("run_streaming(")
            .expect("with_principal is present but does not wrap run_streaming");
        // Nothing but the approval scope may sit between them.
        assert!(
            run < 400,
            "run_streaming is no longer inside the principal scope"
        );
    }

    #[test]
    fn the_principal_is_built_from_the_verified_claims() {
        // Not from the message body. `effective_user_id` already discards a
        // client-supplied user_id that disagrees with the token, so a
        // principal taken from the payload would be the one place the
        // client could name its own subject on the bus.
        let src = code();
        assert!(
            src.contains("Principal::user(user_id.clone(), role, claims.scopes.clone())"),
            "the session principal is no longer built from the verified JWT"
        );
        assert!(
            !src.contains("Principal::user(chat_msg"),
            "the principal must never be built from the message body"
        );
    }

    #[test]
    fn a_user_principal_carries_the_subject_role_and_scopes() {
        let p = Principal::user("alice", Role::Operator, vec!["read".into(), "write".into()]);
        assert_eq!(p.sub, "alice");
        assert_eq!(p.kind, Kind::User);
        assert_eq!(p.role, "operator");
        assert_eq!(p.scopes, vec!["read".to_string(), "write".to_string()]);
    }

    #[test]
    fn a_chat_principal_is_never_the_unattributed_one() {
        // The failure this replaced: UNATTRIBUTED is a real, verifiable
        // principal with no scopes, so a knowledge read under it succeeded
        // and returned nothing rather than refusing.
        let p = Principal::user("alice", Role::User, vec!["read".into()]);
        assert_ne!(p.sub, UNATTRIBUTED);
    }
}
