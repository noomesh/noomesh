// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! WebSocket handler for /ws/collab — collaboration event relay.
//!
//! Subscribes to `agent.collab.>` on NATS and relays all events
//! to connected browser clients. Same protocol as Python's collab_ws.py.

use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;


use crate::state::AppState;
use crate::websocket::{WsParams, send_json, verify_ws_auth};

const MAX_CACHED_EVENTS: usize = 50;

/// Shared event cache for late-connecting clients.
pub struct CollabCache {
    events: Mutex<Vec<Value>>,
}

impl CollabCache {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub async fn push(&self, event: Value) {
        let mut cache = self.events.lock().await;
        let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();

        if event_type == "collab_start" {
            cache.clear();
        }

        cache.push(event);

        if cache.len() > MAX_CACHED_EVENTS {
            // Keep start event + last N
            let start: Vec<Value> = cache.iter()
                .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("collab_start"))
                .cloned()
                .collect();
            let tail_start = cache.len().saturating_sub(MAX_CACHED_EVENTS - start.len());
            let tail: Vec<Value> = cache[tail_start..].to_vec();
            *cache = start;
            cache.extend(tail);
        }

        if event_type == "collab_done" {
            cache.clear();
        }
    }

    pub async fn replay(&self) -> Vec<Value> {
        self.events.lock().await.clone()
    }
}

/// WebSocket upgrade handler for /ws/collab.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsParams>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let jwt_sec = crate::auth::jwt_secret();

    match verify_ws_auth(&params, &jwt_sec) {
        Ok(claims) => {
            ws.on_upgrade(move |socket| handle_collab(socket, state, claims))
        }
        Err(e) => {
            tracing::warn!(error = %e, "ws_collab auth failed");
            ws.on_upgrade(move |mut socket| async move {
                let _ = send_json(&mut socket, &json!({"type": "error", "data": "Authentication failed"})).await;
                // Close with 4401 (same as /ws/coordinator) so clients stop
                // reconnecting instead of looping on auth failures.
                let close_frame = axum::extract::ws::CloseFrame {
                    code: 4401,
                    reason: "Authentication failed".into(),
                };
                let _ = socket.send(Message::Close(Some(close_frame))).await;
            })
        }
    }
}

async fn handle_collab(mut socket: WebSocket, state: Arc<AppState>, claims: crate::auth::Claims) {
    let sub = claims.sub.clone();
    let role = claims.resolved_role();
    tracing::info!(user_id = %sub, "ws_collab connected");

    // Token `exp` or a logout ends the session with close 4401 (websocket.rs).
    let session = crate::websocket::session_ended(
        claims.exp,
        &sub,
        state.alert_hub.subscribe_session_end(),
    );
    tokio::pin!(session);

    // Register with alert hub so broadcast alerts reach this client
    state.alert_hub.register_client();
    let mut alert_rx = state.alert_hub.subscribe();

    // Subscribe to NATS collab events
    let mut nats_sub = match state.nats.subscribe("agent.collab.>").await {
        Ok(sub) => sub,
        Err(e) => {
            let _ = send_json(&mut socket, &json!({
                "type": "error",
                "data": format!("NATS subscription failed: {e}"),
            })).await;
            state.alert_hub.deregister_client();
            return;
        }
    };

    // Replay cached events for late-connecting clients
    let cached = state.collab_cache.replay().await;
    for event in &cached {
        if !send_json(&mut socket, event).await {
            state.alert_hub.deregister_client();
            return;
        }
    }

    loop {
        tokio::select! {
            // Alert broadcast from AlertHub
            reason = &mut session => {
                tracing::info!(user_id = %sub, reason, "ws_collab session ended");
                let _ = send_json(&mut socket, &json!({"type": "error", "data": reason})).await;
                let _ = socket.send(crate::websocket::session_close_frame(reason)).await;
                break;
            }

            alert = alert_rx.recv() => {
                match alert {
                    Ok(payload) => {
                        if !crate::state::audience_allows(&payload, &sub, role) {
                            continue;
                        }
                        if !send_json(&mut socket, &payload).await {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!(missed = n, "ws_collab alert_rx lagged");
                    }
                    Err(_) => break,
                }
            }

            // NATS event → cache + forward to WebSocket
            msg = nats_sub.next() => {
                match msg {
                    Some(nats_msg) => {
                        if let Ok(data) = serde_json::from_slice::<Value>(&nats_msg.payload) {
                            // Cache the event
                            state.collab_cache.push(data.clone()).await;

                            if !send_json(&mut socket, &data).await {
                                break;
                            }
                        }
                    }
                    None => break,
                }
            }

            // WebSocket message from client
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(data) = serde_json::from_str::<Value>(&text) {
                            if data.get("type").and_then(|t| t.as_str()) == Some("ping") {
                                let _ = send_json(&mut socket, &json!({"type": "pong"})).await;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "ws_collab error");
                        break;
                    }
                    _ => {}
                }
            }

            // Keepalive
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                if !send_json(&mut socket, &json!({"type": "keepalive"})).await {
                    break;
                }
            }
        }
    }

    state.alert_hub.deregister_client();
    tracing::info!("ws_collab disconnected");
}
