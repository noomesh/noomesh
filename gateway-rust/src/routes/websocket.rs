// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! WebSocket route registration.
//!
//! Native handlers live in ws_coordinator.rs, ws_collab.rs and ws_agent.rs.
//! Some legacy WS paths (see the note below) are simply not registered and
//! 404 — there is no catchall/fallback for them (Axum WS can't delegate via
//! NATS anyway).

use std::sync::Arc;
use axum::{
    Router,
    routing::get,
};

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Native WebSocket handlers ──
        .route("/ws/coordinator", get(crate::ws_coordinator::ws_handler))
        .route("/ws/collab", get(crate::ws_collab::ws_handler))
        // A2A peer protocol — bidirectional, for external harnesses (hermes, noo-trading, etc.)
        .route("/ws/agent", get(crate::ws_agent::ws_handler))
        // Note: /ws/companion/{node_id}, /ws/terminal/{session_id}, /ws
        // do not exist. They were retired along with the (now-deleted)
        // Python gateway and now simply 404 — there is no fallback handler
        // for them. Bringing them back needs dedicated Rust WS
        // implementations (can't proxy WebSocket via NATS request/reply).
}
