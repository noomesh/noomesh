// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! WebSocket handler for /ws/agent — Agent-to-Agent (A2A) peer protocol.
//!
//! Unlike /ws/collab (which is a read-only broadcast dashboard for internal
//! multi-agent sessions), /ws/agent is a fully bidirectional channel designed
//! for external harnesses (e.g. hermes, noo-trading) to join as peer agents.
//!
//! ## Credential
//!
//! A **peer token only** — `sub = "peer:<agent_id>"`, `scopes = ["peer"]`,
//! minted for exactly one agent id by `POST /api/agents/peer/register`. A
//! user JWT is refused at the handshake even at Operator/Admin tier: a
//! person authenticates as a person, an agent authenticates as that agent,
//! and an operator who must act as an agent mints that agent's token first
//! (audited). See [`handshake_allowed`].
//!
//! ## Protocol
//!
//! Agent messaging: after the handshake the peer
//! receives `{"type":"message","message":<envelope>}` for anything
//! addressed to its agent id (and broadcasts, flagged `"broadcast":true`),
//! and may send `{"type":"send","to":…,"text"|"body":…,"kind":…,
//! "thread_id":…,"refs":[…]}` → `{"type":"sent","message":<envelope>}`.
//! The envelope's identity is the peer's own (user = the JWT subject,
//! node = this controller, agent = agent_id, harness = `ws:<agent_id>`;
//! the hello name is kept separately as `harness_claimed`).
//!
//! **Handshake (client initiates):**
//! ```json
//! → {"type":"agent_hello","agent_id":"hermes-1","name":"Hermes","version":"1.0.0",
//!    "capabilities":["market_analysis","trade_execution"],
//!    "endpoint":"https://hermes.local","ttl_seconds":3600}
//! ← {"type":"agent_welcome","gateway_id":"mesh","agent_id":"hermes-1",
//!    "subscribed_capabilities":["market_analysis","trade_execution"],"ts":...}
//! ```
//!
//! ## Capability-based work delegation (primary model)
//!
//! External harnesses are **work extensions**, not role fillers. MESH delegates
//! to a peer whenever it has work matching the peer's advertised capabilities:
//!
//! ```text
//! MESH publishes to → agent.capability.request.market_analysis
//!           (any peer that subscribed to that subject handles it)
//! Peer receives     ← {"type":"capability_request","capability":"market_analysis",
//!                       "args":{...},"reply_subject":"_INBOX.abc"}
//! Peer responds     → {"type":"capability_response","reply_subject":"_INBOX.abc",
//!                       "success":true,"data":{...}}
//! MESH receives on ← _INBOX.abc (NATS request/reply — transparent to MESH caller)
//! ```
//!
//! On connect, `ws_agent` automatically subscribes the peer to
//! `agent.capability.request.{cap}` for each capability in `agent_hello.capabilities`.
//! No separate subscription step needed from the harness author.
//!
//!
//! **Task delegation (gateway → peer):**
//! ```json
//! ← {"type":"task_request","task_id":"t-123","role":"trader","task":"Analyze AAPL...","context":{}}
//! → {"type":"task_token","task_id":"t-123","content":"Based on the 20-day..."}
//! → {"type":"task_done","task_id":"t-123","result":"Full analysis..."}
//! ```
//!
//! **Capability request (either direction):**
//! ```json
//! ← {"type":"capability_request","request_id":"req-1","capability":"web_search","args":{}}
//! → {"type":"capability_response","request_id":"req-1","success":true,"data":{}}
//! ```
//!
//! **Peer context relay (collab events forwarded to connected peers):**
//! ```json
//! ← {"type":"peer_context","event":{...collab event...}}
//! ```
//!
//! **Keepalive:** ping/pong + server keepalive every 30s.
//!
//! ## NATS subjects produced
//! - `agent.peer.{agent_id}.task.{task_id}` — task token/done/error from peer
//! - `agent.capability.response.{request_id}` — capability response from peer
//! - `agent.peer.{agent_id}.connected` — fires on connect
//! - `agent.peer.{agent_id}.disconnected` — fires on disconnect

use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use futures::SinkExt;

use crate::state::AppState;
use crate::websocket::{WsParams, send_json, verify_ws_auth};

// ── Handshake types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AgentHello {
    agent_id: String,
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    endpoint: Option<String>,
    /// How long the registration entry should live in NATS KV (seconds).
    /// Defaults to 3600 (1 hour). The peer must reconnect before expiry
    /// or re-register via POST /api/agents/peer/register to extend.
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

// ── WebSocket upgrade handler ─────────────────────────────────────

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let jwt_sec = crate::auth::jwt_secret();

    match verify_ws_auth(&params, &jwt_sec) {
        Ok(claims) => ws.on_upgrade(move |socket| handle_peer(socket, state, claims)),
        Err(e) => {
            tracing::warn!(error = %e, "ws_agent auth failed");
            ws.on_upgrade(move |mut socket| async move {
                let _ = send_json(
                    &mut socket,
                    &json!({"type": "error", "data": "Authentication failed"}),
                )
                .await;
                let _ = socket.close().await;
            })
        }
    }
}

/// Who may speak as `agent_id` on this socket.
///
/// `/ws/agent` is an **agent** door: the only credential it takes is a peer
/// token — `sub = "peer:<agent_id>"`, `scopes = ["peer"]`, minted for exactly
/// one agent id by `POST /api/agents/peer/register` (operator, one of the
/// stack's own services, or the peer renewing itself).
///
/// A **user** JWT is refused outright, an operator's and an admin's included.
/// It used to be exempt "because operators legitimately act on behalf of any
/// agent" — but no caller in this repo ever did (the UI, the CLI, the Python
/// clients and the tests all speak HTTP or the bus, never this socket), while
/// `scope_allows` passes every GET for a User-tier token and the upgrade is a
/// GET. So the exemption was not a feature with a caller, it was a hole: any
/// logged-in person could connect as any agent id, take over that agent's
/// `peer_agents` record and push channel, subscribe to its capability
/// requests, receive its inbox opened by the gateway, and send messages as it.
///
/// An operator who genuinely needs to act as an agent takes the explicit,
/// audited path: mint a peer token for that id (`peer_token_minted` in
/// `noo_security_audit`), then connect with it. Keeping an Operator branch
/// here would have put the person and the agent back in one credential, and
/// left no record of which one acted.
pub(crate) fn handshake_allowed(
    claims: &crate::auth::Claims,
    agent_id: &str,
) -> Result<(), &'static str> {
    if !claims.scopes.iter().any(|s| s == "peer") {
        return Err(
            "/ws/agent takes a peer token, not a user token: mint one with \
             POST /api/agents/peer/register and connect with ?token=<peer_token>",
        );
    }
    if claims.sub != format!("peer:{agent_id}") {
        return Err("agent_id does not match token subject");
    }
    Ok(())
}

// ── Connection handler ────────────────────────────────────────────

async fn handle_peer(
    mut socket: WebSocket,
    state: Arc<AppState>,
    claims: crate::auth::Claims,
) {
    tracing::info!(sub = %claims.sub, "ws_agent connected");

    // Wait for agent_hello (30s timeout — peer must identify itself promptly)
    let hello = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        recv_hello(&mut socket),
    )
    .await;

    let hello = match hello {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::warn!("ws_agent: connection closed before agent_hello");
            return;
        }
        Err(_) => {
            let _ = send_json(
                &mut socket,
                &json!({"type": "error", "data": "Handshake timeout: expected agent_hello within 30s"}),
            )
            .await;
            return;
        }
    };

    let agent_id = hello.agent_id.clone();

    // Ids and capabilities become NATS subject tokens and registry keys:
    // reject anything that is not a plain id BEFORE it touches a subject
    // ( — `>`/`*` here would subscribe to everything).
    if let Err(e) = crate::agent_messages::check_id("agent_id", &agent_id) {
        let _ = send_json(&mut socket, &json!({"type": "error", "data": e})).await;
        return;
    }
    if let Some(bad) = hello.capabilities.iter().find(|c| !is_subject_token(c)) {
        let _ = send_json(
            &mut socket,
            &json!({"type": "error", "data": format!("capability '{bad}' is not a plain token (letters, digits, '-', '_')")}),
        )
        .await;
        return;
    }

    // A PERSON is not an AGENT. This door takes an
    // agent credential only — see [`handshake_allowed`].
    if let Err(why) = handshake_allowed(&claims, &agent_id) {
        tracing::warn!(
            sub = %claims.sub, agent_id = %agent_id, why,
            "ws_agent: refusing the handshake — credential is not this agent"
        );
        let _ = send_json(&mut socket, &json!({"type": "error", "data": why})).await;
        return;
    }
    tracing::info!(agent_id = %agent_id, name = %hello.name, roles = ?hello.roles, "ws_agent handshake");

    // Register in NATS KV peer_agents (cluster-wide visibility + TTL)
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let reg_value = json!({
        "agent_id": &agent_id,
        "name": &hello.name,
        "version": &hello.version,
        "capabilities": &hello.capabilities,
        "roles": &hello.roles,
        "endpoint": &hello.endpoint,
        "connected_at": now_secs,
        "status": "connected",
    });

    if let Ok(kv) = state.js.get_key_value("peer_agents").await {
        if let Err(e) = kv.put(
            &agent_id,
            serde_json::to_vec(&reg_value).unwrap_or_default().into(),
        ).await {
            tracing::warn!(error = %e, agent_id = %agent_id, "ws_agent: failed to write peer_agents KV");
        }
    }

    // Announce connection on NATS (other subsystems can react)
    let _ = state
        .nats
        .publish(
            format!("agent.peer.{agent_id}.connected"),
            serde_json::to_vec(&reg_value).unwrap_or_default().into(),
        )
        .await;

    // Register active connection — gives other handlers a channel to push to this peer.
    // We keep a clone of `tx` for capability subscriptions (see below) so we
    // can forward inbound NATS capability requests to the WebSocket without
    // needing any additional shared state.
    let (tx, mut rx) = mpsc::channel::<Value>(64);
    {
        let mut conns = state.peer_connections.write().await;
        conns.insert(agent_id.clone(), tx.clone());
    }

    // For each capability the peer advertises, subscribe to the NATS
    // request/reply subject so any part of MESH (coordinator, collab loop,
    // tool dispatcher) can delegate work to this peer by publishing to
    // `agent.capability.request.{capability}` — no role assignment needed.
    for cap in &hello.capabilities {
        let cap_subject = format!("agent.capability.request.{cap}");
        match state.nats.subscribe(cap_subject.clone()).await {
            Ok(mut cap_sub) => {
                let tx_cap = tx.clone();
                let cap_name = cap.clone();
                tokio::spawn(async move {
                    while let Some(msg) = cap_sub.next().await {
                        let reply_subject = msg.reply
                            .as_deref()
                            .unwrap_or("")
                            .to_string();
                        let args = serde_json::from_slice::<Value>(&msg.payload)
                            .unwrap_or(Value::Null);
                        let request_id = args
                            .get("request_id")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .unwrap_or_else(|| reply_subject.clone());
                        let payload = json!({
                            "type": "capability_request",
                            "request_id": request_id,
                            "capability": cap_name,
                            "args": args,
                            // Include the NATS reply-to so the peer can route
                            // its response back without server-side tracking.
                            "reply_subject": reply_subject,
                        });
                        if tx_cap.send(payload).await.is_err() {
                            break; // peer disconnected — subscription task exits
                        }
                    }
                });
                tracing::info!(
                    agent_id = %agent_id,
                    capability = %cap,
                    subject = %cap_subject,
                    "ws_agent capability_subscription"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    agent_id = %agent_id,
                    capability = %cap,
                    "ws_agent: failed to subscribe to capability subject"
                );
            }
        }
    }

    // Build and send agent_welcome
    let gateway_id = std::env::var("NODE_ID").unwrap_or_else(|_| "mesh".into());
    let welcome = json!({
        "type": "agent_welcome",
        "gateway_id": &gateway_id,
        "agent_id": &agent_id,
        // Capabilities this gateway will route work to this peer for.
        // Each entry maps to a NATS subscription: agent.capability.request.{cap}
        "subscribed_capabilities": &hello.capabilities,
        "endpoints": {
            "inference": "/api/inference",
            "inference_stream": "/api/inference/stream",
            "rag": "/api/v1/rag/query",
            "collaborate": "/api/agents/collaborate",
            // The user door on this same listener; the separate plain-HTTP
            // port this used to advertise was removed in stack-v0.2.40.
            "mcp": "/mcp/user",
            "peer_dispatch": format!("/api/agents/peer/{}/task", &agent_id),
        },
        "capability_subject_prefix": "agent.capability.request",
        "collab_subject_prefix": "agent.collab",
        "ts": now_secs,
    });

    if !send_json(&mut socket, &welcome).await {
        cleanup(&state, &agent_id).await;
        return;
    }

    // Subscribe to collab events so we can relay relevant ones to this peer
    let mut collab_sub = match state.nats.subscribe("agent.collab.>").await {
        Ok(sub) => sub,
        Err(e) => {
            tracing::warn!(error = %e, agent_id = %agent_id, "ws_agent: failed to subscribe to collab events");
            cleanup(&state, &agent_id).await;
            return;
        }
    };

    // Agent messaging: this peer's inbox on the bus
    // — direct messages addressed to its agent id, plus broadcasts — are
    // delivered as `{"type":"message","message":<envelope>}`.
    let inbox_subject = format!(
        "{}.direct.{}",
        crate::agent_messages::SUBJECT_ROOT,
        crate::agent_messages::subject_token(&agent_id)
    );
    let mut inbox_sub = match state.nats.subscribe(inbox_subject.clone()).await {
        Ok(sub) => sub,
        Err(e) => {
            tracing::warn!(error = %e, agent_id = %agent_id, "ws_agent: failed to subscribe to the agent inbox");
            cleanup(&state, &agent_id).await;
            return;
        }
    };
    let mut broadcast_sub = match state
        .nats
        .subscribe(format!("{}.broadcast", crate::agent_messages::SUBJECT_ROOT))
        .await
    {
        Ok(sub) => sub,
        Err(e) => {
            tracing::warn!(error = %e, agent_id = %agent_id, "ws_agent: failed to subscribe to broadcasts");
            cleanup(&state, &agent_id).await;
            return;
        }
    };
    // The harness is `ws:<agent_id>`, not the name the peer sent in its
    // hello: `agent_id` is bound to the token subject a
    // few lines above, so it is the one thing about this connection the
    // gateway has verified. `hello.name` is free text and rides along as a
    // clearly-marked claim.
    let peer_identity = crate::agent_messages::Identity::new(
        Some(&claims.sub),
        Some(&crate::agent_messages::controller_node()),
        Some(&agent_id),
        Some(&format!("ws:{agent_id}")),
    )
    .with_claimed_harness(Some(&hello.name));

    // Per-connection budgets. The HTTP rate limiter
    // skips `/ws*` — and must, since it sees one request per connection —
    // so an authenticated peer could otherwise drive JetStream (30-day
    // retention) and `noo_agent_messages` (90-day) as fast as it can write
    // to a socket. Two buckets, because the two costs are different:
    //
    //  - `frames`: everything the peer sends. 50/s sustained, 200 burst.
    //    Sized for `task_token` streaming, which is one frame per model
    //    token — a fast local model emits 30-60 tok/s, so this clears real
    //    streaming with headroom and still bounds the socket.
    //  - `writes`: the verbs that leave something behind — `send`
    //    (JetStream + Postgres) and `register_key` (a KV write). 5/s
    //    sustained, 30 burst. A peer holding a conversation sends a message
    //    every few seconds; 5/s is two orders of magnitude above that and
    //    still caps a hostile peer at ~432k rows/day rather than unbounded.
    //
    // Over budget is an error frame, not a disconnect: a peer that bursts
    // is usually badly written, not hostile, and dropping the socket loses
    // the delivery path with it. The notice itself is throttled so a flood
    // cannot amplify into a reply flood.
    let mut frame_budget = TokenBucket::new(200.0, 50.0);
    let mut write_budget = TokenBucket::new(30.0, 5.0);
    let mut last_notice: Option<std::time::Instant> = None;

    // Collaborations this peer is a party to — filled from the `collab_start`
    // events that name it, emptied on `collab_done`. Per connection, so it
    // dies with the socket.
    let mut my_collabs: std::collections::HashSet<String> = std::collections::HashSet::new();

    // ── Main event loop ───────────────────────────────────────────
    loop {
        tokio::select! {
            // Agent messages addressed to this peer (and broadcasts).
            m = inbox_sub.next() => {
                if let Some(msg) = m {
                    if let Ok(env) = serde_json::from_slice::<Value>(&msg.payload) {
                        // Gateway-trusted delivery (phase 2b): the peer holds
                        // no key yet, so the body is opened for it here.
                        if !send_json(&mut socket, &json!({"type": "message", "message": open_for_peer(env)})).await {
                            break;
                        }
                    }
                }
            }
            m = broadcast_sub.next() => {
                if let Some(msg) = m {
                    if let Ok(env) = serde_json::from_slice::<Value>(&msg.payload) {
                        if !send_json(&mut socket, &json!({"type": "message", "message": open_for_peer(env), "broadcast": true})).await {
                            break;
                        }
                    }
                }
            }

            // Gateway → Peer: task requests, capability requests, etc.
            msg = rx.recv() => {
                match msg {
                    Some(payload) => {
                        if !send_json(&mut socket, &payload).await {
                            break;
                        }
                    }
                    None => break,
                }
            }

            // Collab events: forward peer_inject/collab_start/collab_done for
            // the collaborations THIS peer takes part in.
            // The subscription is still the wildcard — one NATS subscription
            // per connection — but the relay is filtered by membership, so a
            // peer no longer reads every other collaboration's task text and
            // results. See [`collab_relay`].
            collab_msg = collab_sub.next() => {
                if let Some(msg) = collab_msg {
                    if let Ok(data) = serde_json::from_slice::<Value>(&msg.payload) {
                        let decision = collab_relay(
                            msg.subject.as_str(), &data, &agent_id, &mut my_collabs,
                        );
                        if decision {
                            let relay = json!({
                                "type": "peer_context",
                                "event": data,
                            });
                            if !send_json(&mut socket, &relay).await {
                                break;
                            }
                        }
                    }
                }
            }

            // Peer → Gateway: inbound messages
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(data) = serde_json::from_str::<Value>(&text) {
                            let msg_type = data.get("type")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            let costs_a_write = matches!(msg_type.as_str(), "send" | "register_key");
                            let over = if !frame_budget.take() {
                                Some("frames")
                            } else if costs_a_write && !write_budget.take() {
                                Some("writes")
                            } else {
                                None
                            };
                            if let Some(scope) = over {
                                if should_notice(&mut last_notice) {
                                    tracing::warn!(agent_id = %agent_id, scope, "ws_agent: peer over its per-connection rate budget");
                                    if !send_json(&mut socket, &json!({
                                        "type": "error",
                                        "code": "rate_limited",
                                        "data": format!("over the per-connection {scope} budget — slow down; this frame was not processed"),
                                    })).await {
                                        break;
                                    }
                                }
                                continue;
                            }
                            if msg_type == "ping" {
                                if !send_json(&mut socket, &json!({"type": "pong"})).await {
                                    break;
                                }
                            } else if msg_type == "register_key" {
                                // Phase 4: the peer's own public keys — from now
                                // on messages to it are wrapped to this key too.
                                let record = data.get("keys").cloned().unwrap_or(Value::Null);
                                let by = format!("ws:{}", claims.sub);
                                let reply = match crate::agent_crypto::register_keys(&state.js, &agent_id, &record, &by, false).await {
                                    Ok(()) => json!({"type": "key_registered", "agent_id": agent_id}),
                                    Err(e) => json!({"type": "error", "data": format!("register_key: {e}")}),
                                };
                                if !send_json(&mut socket, &reply).await {
                                    break;
                                }
                            } else if msg_type == "send" {
                                // Peer → another agent: publish with THIS peer's
                                // identity — a peer cannot send as anyone else.
                                let to = data.get("to").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                // A peer is never privileged, so it never
                                // broadcasts: `*` reaches
                                // every connected peer and costs the gateway
                                // one body-open per recipient.
                                if matches!(to.as_str(), "*" | "broadcast") {
                                    if !send_json(&mut socket, &json!({
                                        "type": "error",
                                        "data": "broadcast is operator-only — address an agent or a thread by name",
                                    })).await {
                                        break;
                                    }
                                    continue;
                                }
                                let kind = data.get("kind").and_then(|v| v.as_str()).unwrap_or("message").to_string();
                                let body = data.get("body").cloned()
                                    .or_else(|| data.get("text").and_then(|t| t.as_str()).map(|t| json!({"text": t})))
                                    .unwrap_or(Value::Null);
                                let thread_id = data.get("thread_id").and_then(|v| v.as_str()).map(str::to_string);
                                let refs: Vec<String> = data.get("refs").and_then(|v| v.as_array())
                                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                                    .unwrap_or_default();
                                let env = crate::agent_messages::Envelope::new(&agent_id, &to, &kind, body, thread_id.as_deref(), refs)
                                    .with_from(peer_identity.clone());
                                // A peer is never privileged: it may only post into
                                // threads it already takes part in.
                                let outsider = match thread_id.as_deref() {
                                    Some(t) => matches!(crate::repo::agent_messages::is_party(&state.db, t, &agent_id).await, Ok(Some(false))),
                                    None => false,
                                };
                                let reply = if outsider {
                                    json!({"type": "error", "data": "not a party to that thread"})
                                } else {
                                    match crate::agent_messages::publish(&state.js, &env).await {
                                        Ok(sent) => json!({"type": "sent", "message": env, "enc": sent.enc}),
                                        Err(e) => json!({"type": "error", "data": format!("send failed: {e}")}),
                                    }
                                };
                                if !send_json(&mut socket, &reply).await {
                                    break;
                                }
                            } else {
                                handle_peer_message(&state, &agent_id, data).await;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, agent_id = %agent_id, "ws_agent recv error");
                        break;
                    }
                    _ => {}
                }
            }

            // Server-initiated keepalive
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                if !send_json(&mut socket, &json!({"type": "keepalive"})).await {
                    break;
                }
            }
        }
    }

    cleanup(&state, &agent_id).await;
    tracing::info!(agent_id = %agent_id, "ws_agent disconnected");
}

/// Wait for the first `agent_hello` message, skipping other message types.
async fn recv_hello(socket: &mut WebSocket) -> Option<AgentHello> {
    loop {
        match socket.recv().await? {
            Ok(Message::Text(text)) => {
                if let Ok(data) = serde_json::from_str::<Value>(&text) {
                    if data.get("type").and_then(|t| t.as_str()) == Some("agent_hello") {
                        return serde_json::from_value::<AgentHello>(data).ok();
                    }
                }
            }
            Ok(Message::Close(_)) => return None,
            _ => continue,
        }
    }
}

/// Route inbound peer messages to the appropriate NATS subjects so PAI's
/// internal subsystems can react without coupling to the WebSocket directly.
async fn handle_peer_message(state: &AppState, agent_id: &str, data: Value) {
    let msg_type = data.get("type").and_then(|t| t.as_str()).unwrap_or("");

    match msg_type {
        // Task streaming: peer is sending tokens or completion for a delegated task
        "task_token" | "task_done" | "task_error" => {
            let task_id = data
                .get("task_id")
                .and_then(|t| t.as_str())
                .filter(|t| is_subject_token(t))
                .unwrap_or("unknown");
            let subject = format!("agent.peer.{agent_id}.task.{task_id}");
            let _ = state
                .nats
                .publish(subject, serde_json::to_vec(&data).unwrap_or_default().into())
                .await;
        }

        // Capability response: peer answering a capability_request from the gateway.
        // If the peer echoed back the `reply_subject` from the original request,
        // publish directly there (NATS request/reply). Otherwise fall back to the
        // named subject so non-reply callers can still subscribe.
        "capability_response" => {
            // The peer echoes the reply-to the gateway handed it, which is
            // always a NATS inbox. Anything else — `agent.msg.direct.x`,
            // a wildcard — is a client-chosen publish and is refused
            // forged envelopes must not reach the stream
            // through this socket.
            let reply_subject = data
                .get("reply_subject")
                .and_then(|v| v.as_str())
                .filter(|s| is_inbox_subject(s))
                .map(String::from);
            let fallback_subject = {
                let request_id = data
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .filter(|r| is_subject_token(r))
                    .unwrap_or("unknown");
                format!("agent.capability.response.{request_id}")
            };
            let subject = reply_subject.unwrap_or(fallback_subject);
            let _ = state
                .nats
                .publish(subject, serde_json::to_vec(&data).unwrap_or_default().into())
                .await;
        }

        // Peer initiating a capability request to PAI — route via standard subject
        "capability_request" => {
            let capability = data
                .get("capability")
                .and_then(|t| t.as_str())
                .filter(|c| is_subject_token(c))
                .unwrap_or("unknown");
            let subject = format!("agent.capability.request.{capability}");
            let _ = state
                .nats
                .publish(subject, serde_json::to_vec(&data).unwrap_or_default().into())
                .await;
        }

        // External health probe / error report — publish to autonomy issue subscriber.
        // The autonomy_loop::spawn_issue_subscriber picks this up, runs healing,
        // and pushes a heal_result back to this peer via state.peer_connections.
        "issue_report" => {
            let subject = format!("agent.issue.report.{agent_id}");
            let _ = state
                .nats
                .publish(subject, serde_json::to_vec(&data).unwrap_or_default().into())
                .await;
            tracing::info!(
                agent_id,
                category = data.get("category").and_then(|v| v.as_str()).unwrap_or("unknown"),
                severity = data.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "external_issue_report_received"
            );
        }

        other => {
            tracing::debug!(agent_id, msg_type = other, "ws_agent: unhandled message type");
        }
    }
}

/// A refill-over-time budget for one WebSocket connection
/// M21a. Not the Redis limiter in `middleware.rs`: that one is per IP and
/// per HTTP request, and a WebSocket is a single request that then carries
/// unbounded traffic, so the only place a message count can be enforced is
/// here, in the receive loop.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    per_sec: f64,
    last: std::time::Instant,
}

impl TokenBucket {
    fn new(capacity: f64, per_sec: f64) -> Self {
        TokenBucket { tokens: capacity, capacity, per_sec, last: std::time::Instant::now() }
    }

    /// Spend one token; false when the bucket is empty.
    fn take(&mut self) -> bool {
        let now = std::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.per_sec)
            .min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// At most one "you are over budget" frame per second, so a peer flooding
/// the socket cannot turn the refusal into an outbound flood of its own.
fn should_notice(last: &mut Option<std::time::Instant>) -> bool {
    let now = std::time::Instant::now();
    match last {
        Some(t) if now.duration_since(*t) < std::time::Duration::from_secs(1) => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

/// The collab id in `agent.collab.{collab_id}.{role|ctrl}`.
fn collab_id_from_subject(subject: &str) -> Option<&str> {
    let rest = subject.strip_prefix("agent.collab.")?;
    let id = rest.split('.').next()?;
    (!id.is_empty()).then_some(id)
}

/// Does a `collab_start` event name `agent_id` as one of its participants?
/// The publisher marks peer slots `backend_type: "peer"` with the agent id in
/// `node_id` (`parallel_collab.py`).
fn collab_start_names(event: &Value, agent_id: &str) -> bool {
    event
        .get("backends")
        .and_then(|v| v.as_array())
        .map(|slots| {
            slots.iter().any(|b| {
                b.get("backend_type").and_then(Value::as_str) == Some("peer")
                    && b.get("node_id").and_then(Value::as_str) == Some(agent_id)
            })
        })
        .unwrap_or(false)
}

/// Should this collab event reach this peer? Membership is learned from the
/// `collab_start` that names the peer and forgotten on `collab_done`; nothing
/// else opens the door, so a peer that was never assigned a slot sees nothing.
fn collab_relay(
    subject: &str,
    event: &Value,
    agent_id: &str,
    my_collabs: &mut std::collections::HashSet<String>,
) -> bool {
    let Some(collab_id) = collab_id_from_subject(subject) else {
        return false;
    };
    match event.get("type").and_then(Value::as_str).unwrap_or("") {
        "collab_start" => {
            if collab_start_names(event, agent_id) {
                my_collabs.insert(collab_id.to_string());
                true
            } else {
                false
            }
        }
        "peer_inject" => my_collabs.contains(collab_id),
        "collab_done" => my_collabs.remove(collab_id),
        _ => false,
    }
}

/// One NATS subject token from a client: letters, digits, `-`, `_` only —
/// never `.`, `*`, `>` or whitespace.
fn is_subject_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A reply-to the gateway itself handed out: a NATS inbox, no wildcards.
fn is_inbox_subject(s: &str) -> bool {
    s.starts_with("_INBOX.")
        && s.len() <= 256
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Remove this peer's active connection from the registry and announce disconnect.
async fn cleanup(state: &AppState, agent_id: &str) {
    {
        let mut conns = state.peer_connections.write().await;
        conns.remove(agent_id);
    }

    let _ = state
        .nats
        .publish(
            format!("agent.peer.{agent_id}.disconnected"),
            json!({"agent_id": agent_id}).to_string().into(),
        )
        .await;
}


/// Open a sealed envelope for WebSocket delivery to a peer that holds no
/// key of its own. Leaves `enc` as it travelled so
/// the peer knows; a body the review key cannot open is passed as is.
fn open_for_peer(mut env: Value) -> Value {
    let enc = env["enc"].as_str().unwrap_or("none").to_string();
    if enc == "none" {
        return env;
    }
    let body = env["body"].clone();
    let meta = env.get("enc_meta").cloned();
    let f = |k: &str| env[k].as_str().unwrap_or_default().to_string();
    let aad = crate::agent_messages::envelope_aad(&f("id"), &f("thread_id"), &f("from"), &f("to"), &f("kind"));
    if let Ok(opened) = crate::agent_messages::open_body(&enc, &body, meta.as_ref(), &aad) {
        env["body"] = opened;
        env["opened_by"] = Value::String("gateway".into());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(sub: &str, role: &str, scopes: &[&str]) -> crate::auth::Claims {
        crate::auth::Claims {
            sub: sub.into(),
            exp: 4_102_444_800,
            role: role.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            harness: None,
            conv: None,
            act: None,
            cnf: None,
        }
    }

    /// PINNED: ONLY the peer token minted for an id may
    /// take that id on the socket. Every user token is refused, an
    /// operator's and an admin's included — a person is not an agent, and
    /// an operator who must act as one mints that agent's token first.
    #[test]
    fn the_socket_binds_every_caller_to_an_agent_id() {
        assert!(handshake_allowed(&claims("peer:hermes-1", "", &["peer"]), "hermes-1").is_ok());
        assert!(handshake_allowed(&claims("peer:hermes-1", "", &["peer"]), "hermes-2").is_err());
        assert!(handshake_allowed(&claims("alice", "operator", &["read", "write"]), "hermes-1").is_err(), "an operator is a person, not an agent");
        assert!(handshake_allowed(&claims("root", "admin", &["read", "write", "admin"]), "anything").is_err(), "an admin is a person, not an agent");
        assert!(handshake_allowed(&claims("alice", "user", &["read"]), "hermes-1").is_err(), "a user token is not a peer");
        // A user claiming `peer:` in sub without the scope is still a user.
        assert!(handshake_allowed(&claims("peer:hermes-1", "user", &["read"]), "hermes-1").is_err());
    }

    /// The budget must let a burst through and then stop it — an
    /// authenticated peer with an unbounded socket is the whole of M21a.
    #[test]
    fn token_bucket_allows_a_burst_then_refuses() {
        let mut b = TokenBucket::new(5.0, 1.0);
        for i in 0..5 {
            assert!(b.take(), "burst token {i} must pass");
        }
        assert!(!b.take(), "the sixth call in the same instant must be refused");
    }

    /// It is a rate limit, not a quota: the bucket refills with time, so a
    /// peer that slows down is never permanently cut off.
    #[test]
    fn token_bucket_refills_over_time() {
        let mut b = TokenBucket::new(2.0, 1000.0);
        assert!(b.take());
        assert!(b.take());
        assert!(!b.take());
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(b.take(), "20ms at 1000/s must have refilled at least one token");
    }

    /// The write budget has to be the tighter of the two: `send` costs a
    /// JetStream record (30 days) and a Postgres row (90 days), while a
    /// `task_token` frame costs a NATS publish nobody retains.
    #[test]
    fn write_budget_is_tighter_than_the_frame_budget() {
        let frames = TokenBucket::new(200.0, 50.0);
        let writes = TokenBucket::new(30.0, 5.0);
        assert!(writes.per_sec < frames.per_sec);
        assert!(writes.capacity < frames.capacity);
    }

    /// The refusal notice is throttled so a flood cannot be turned into an
    /// outbound flood by way of the error frames.
    #[test]
    fn refusal_notice_is_throttled() {
        let mut last = None;
        assert!(should_notice(&mut last), "first refusal is always reported");
        assert!(!should_notice(&mut last), "an immediate second refusal is silent");
    }

    /// the hole. A logged-in person could connect as any agent id
    /// because `scope_allows` passes every GET and the upgrade is a GET.
    /// On the old code this assertion failed — the user JWT was exempt.
    #[test]
    fn a_user_jwt_is_not_an_agent() {
        for role in ["user", "operator", "admin"] {
            let c = claims("alice", role, &["read", "write", "admin"]);
            let err = handshake_allowed(&c, "hermes-1")
                .expect_err("a user JWT must never speak as an agent");
            assert!(err.contains("peer token"), "unexpected refusal: {err}");
        }
    }

    /// A peer token is bound to ONE agent id.
    #[test]
    fn a_peer_token_may_only_be_its_own_agent() {
        let c = claims("peer:hermes-1", "user", &["peer"]);
        assert!(handshake_allowed(&c, "hermes-1").is_ok());
        let err = handshake_allowed(&c, "hermes-2").expect_err("cross-agent hello must fail");
        assert!(err.contains("does not match"), "unexpected refusal: {err}");
    }

    /// A near-miss subject must not pass by prefix.
    #[test]
    fn peer_subject_is_matched_whole() {
        let c = claims("peer:hermes-1-evil", "user", &["peer"]);
        assert!(handshake_allowed(&c, "hermes-1").is_err());
    }

    #[test]
    fn collab_id_comes_from_the_subject() {
        assert_eq!(collab_id_from_subject("agent.collab.c-1.ctrl"), Some("c-1"));
        assert_eq!(collab_id_from_subject("agent.collab.c-1.analyst"), Some("c-1"));
        assert_eq!(collab_id_from_subject("agent.collab."), None);
        assert_eq!(collab_id_from_subject("agent.msg.direct.x"), None);
    }

    /// A peer sees the collaborations it was assigned to and nothing else —
    /// the wildcard relay used to hand every peer every collab's task text
    /// and per-role results.
    #[test]
    fn collab_relay_is_scoped_to_membership() {
        let mut mine = std::collections::HashSet::new();
        let start_for_me = json!({
            "type": "collab_start", "collab_id": "c-1", "task": "secret",
            "backends": [{"backend_type": "peer", "node_id": "hermes-1", "role": "analyst"}],
        });
        let start_for_other = json!({
            "type": "collab_start", "collab_id": "c-2", "task": "other secret",
            "backends": [{"backend_type": "peer", "node_id": "hermes-9", "role": "analyst"}],
        });
        let inject = json!({"type": "peer_inject", "role": "analyst"});
        let done = json!({"type": "collab_done", "results": {"analyst": "…"}});

        // Someone else's collaboration: never relayed, at any stage.
        assert!(!collab_relay("agent.collab.c-2.ctrl", &start_for_other, "hermes-1", &mut mine));
        assert!(!collab_relay("agent.collab.c-2.analyst", &inject, "hermes-1", &mut mine));
        assert!(!collab_relay("agent.collab.c-2.ctrl", &done, "hermes-1", &mut mine));

        // Mine: start admits me, the stream follows, done closes the door.
        assert!(collab_relay("agent.collab.c-1.ctrl", &start_for_me, "hermes-1", &mut mine));
        assert!(collab_relay("agent.collab.c-1.analyst", &inject, "hermes-1", &mut mine));
        assert!(collab_relay("agent.collab.c-1.ctrl", &done, "hermes-1", &mut mine));
        assert!(
            !collab_relay("agent.collab.c-1.analyst", &inject, "hermes-1", &mut mine),
            "membership must not outlive collab_done"
        );
    }

    /// An internal-only collaboration names no peer, so no peer observes it.
    #[test]
    fn collab_with_no_peer_slot_reaches_no_peer() {
        let mut mine = std::collections::HashSet::new();
        let start = json!({
            "type": "collab_start", "collab_id": "c-3",
            "backends": [{"backend_type": "vllm", "node_id": "hermes-1", "role": "coder"}],
        });
        assert!(
            !collab_relay("agent.collab.c-3.ctrl", &start, "hermes-1", &mut mine),
            "a node id that happens to equal an agent id is not a peer slot"
        );
    }

    /// Identity on this surface is server-derived; the peer's own name for
    /// itself is kept apart so nothing renders it as fact (M14).
    #[test]
    fn peer_identity_derives_harness_and_keeps_the_claim_separate() {
        let id = crate::agent_messages::Identity::new(
            Some("peer:hermes-1"),
            Some("host8"),
            Some("hermes-1"),
            Some("ws:hermes-1"),
        )
        .with_claimed_harness(Some("Hermes"));
        assert_eq!(id.harness.as_deref(), Some("ws:hermes-1"));
        assert_eq!(id.harness_claimed.as_deref(), Some("Hermes"));
        assert!(id.label().contains("claims: Hermes"));
    }
}
