// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Peer agent routes — A2A registration, discovery, AgentCard.
//!
//! ## Endpoints
//!
//! | Method | Path | Auth | Purpose |
//! |--------|------|------|---------|
//! | GET  | `/.well-known/agent.json` | none | AgentCard (A2A discovery) |
//! | POST | `/api/agents/peer/register` | owner¹ | Register an external peer agent, and mint its peer token |
//! | GET  | `/api/agents/peer/`         | JWT  | List all registered peer agents |
//! | DELETE | `/api/agents/peer/{id}`   | owner¹ | Deregister a peer agent |
//! | POST | `/api/agents/peer/{id}/task` | owner¹ | Dispatch a task to a connected peer |
//!
//! ¹ **owner** = [`authorize_peer_action`]: Operator or above, one of the
//! stack's own services, or that agent's own peer token. An agent id is an
//! identity — one peer must not mint, delete or drive another.
//!
//! ## AgentCard
//! Follows the Google A2A specification format (Feb 2026). Published at
//! `/.well-known/agent.json` with no auth so peer agents can discover
//! PAI's capabilities before authenticating.
//!
//! ## Peer registry
//! Registrations are stored in NATS KV bucket `peer_agents` with the TTL
//! provided at registration time (default 3600s). Active WebSocket connections
//! are tracked in `state.peer_connections` (in-memory, lost on restart).

use crate::audit::{AuditEvent, AuditKind};
use std::sync::Arc;
use axum::{
    Router,
    routing::{delete, get, post},
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;
use super::{AppError, AppJson, AppResult};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Public discovery — no auth (/.well-known/ is in PUBLIC_PATH_PREFIXES)
        .route("/.well-known/agent.json", get(agent_card))

        // Peer management — JWT auth required (middleware handles it)
        .route("/api/agents/peer/", get(peer_list))
        .route("/api/agents/peer/register", post(peer_register))
        .route("/api/agents/peer/{agent_id}", delete(peer_deregister))
        .route("/api/agents/peer/{agent_id}/task", post(peer_dispatch_task))
        // Capability-based discovery — find the first connected peer for a capability
        .route("/api/agents/peer/for-capability/{capability}", get(peer_for_capability))
}

// ═══════════════════════════════════════════════════════════════
// AgentCard — public discovery endpoint (no auth)
// ═══════════════════════════════════════════════════════════════

/// GET /.well-known/agent.json — PAI's AgentCard for A2A discovery.
///
/// External harnesses fetch this to learn PAI's capabilities, available
/// roles, and how to authenticate before connecting via /ws/agent.
/// Format follows the Google A2A specification (Feb 2026).
async fn agent_card() -> AppJson {
    let gateway_host = crate::config::env_or_yaml(
        "NOO_GATEWAY_URL",
        |c| c.services.gateway_url.clone(),
        "https://localhost:8080",
    );
    let gateway_id = std::env::var("NODE_ID").unwrap_or_else(|_| "mesh".into());

    Json(json!({
        // A2A standard fields
        "name": "MESH",
        "description": "Distributed AI agent cluster runtime — inference, RAG, knowledge graph, multi-agent orchestration",
        "version": env!("CARGO_PKG_VERSION"),
        "url": gateway_host,
        "id": gateway_id,

        // What PAI can do (capabilities a peer can request)
        "capabilities": {
            "inference": {
                "description": "Run prompts on GPU cluster (vLLM/Ollama/llama.cpp)",
                "endpoint": "/api/inference",
                "streaming": true,
            },
            "rag": {
                "description": "Query PageIndex knowledge base",
                "endpoint": "/api/v1/rag/query",
            },
            "temporal_graph": {
                "description": "Query bi-temporal knowledge graph",
                "endpoint": "/api/v1/graph/entities",
            },
            "multi_agent": {
                "description": "Trigger parallel multi-role agent collaborations",
                "endpoint": "/api/agents/collaborate",
            },
            "tool_execution": {
                "description": "Execute tools via MCP hub",
                "endpoint": "/mcp/user",
            },
            "cluster_management": {
                "description": "Query and manage GPU cluster nodes",
                "endpoint": "/api/cluster/nodes",
            },
        },

        // Roles PAI can fill in a collaboration (peer can request these)
        "roles": ["researcher", "coder", "analyst", "planner", "reviewer"],

        // How to authenticate
        "authentication": {
            "schemes": ["Bearer"],
            "token_endpoint": "/auth/token",
            "peer_registration": "/api/agents/peer/register",
        },

        // Key endpoints for peer integration
        "endpoints": {
            "peer_websocket": "/ws/agent",
            "peer_list": "/api/agents/peer/",
            "collaborate": "/api/agents/collaborate",
            "inference": "/api/inference",
            "inference_stream": "/api/inference/stream",
            "rag_query": "/api/v1/rag/query",
            "graph": "/api/v1/graph/entities",
            "mcp": "/mcp/user",
            "agent_card": "/.well-known/agent.json",
        },

        // NATS subject layout (for peers with direct NATS access)
        "nats_subjects": {
            "peer_connected": "agent.peer.{agent_id}.connected",
            "peer_disconnected": "agent.peer.{agent_id}.disconnected",
            "task_stream": "agent.peer.{agent_id}.task.{task_id}",
            "capability_request": "agent.capability.request.{capability}",
            "capability_advertise": "agent.capability.advertise.{node_id}",
            "collab_events": "agent.collab.>",
        },
    }))
}

// ═══════════════════════════════════════════════════════════════
// Peer registration
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct PeerRegisterRequest {
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
    /// Registration TTL in seconds. Defaults to 3600 (1 hour).
    /// The peer must re-register before expiry to maintain visibility.
    #[serde(default)]
    ttl_seconds: Option<u64>,
    /// What a human should call this session.
    ///
    /// **Display only, and that is enforced by never comparing it.** The
    /// identity is `agent_id`; this is what a listing shows a person.
    /// Renaming the display costs nothing, renaming the identity mints a
    /// new one.
    ///
    /// Nothing may route, filter or authorize on this field. Two
    /// different sessions may legitimately both call themselves
    /// "laptop", so any code that treated it as a key would be wrong on
    /// the first honest collision — never mind a dishonest one. If you
    /// are about to compare this string, you want `agent_id`.
    #[serde(default)]
    display_name: Option<String>,
    /// What this agent is interested in receiving — message kinds.
    ///
    /// **An ADVERTISEMENT, never an authorization.** A sender may read it
    /// to route sensibly; a receiving loop must not filter on it. The
    /// moment a receiver trusts this, whoever can write a registration
    /// decides what an agent acts on, and a discovery record has become
    /// an access-control record. Whose messages an agent will ACT on is
    /// the trust list (`noo_agent_trust`), applied by the receiver,
    /// locally, and never taken from here.
    ///
    /// Carried on every refresh rather than only the first registration:
    /// what an agent listens for changes mid-session, and a stale value
    /// under a fresh TTL is the worst of both.
    #[serde(default)]
    listens_for: Vec<String>,
}

/// Who the caller is, for the peer surface's mutations.
///
/// An agent id is an identity, so everything that mints, deletes or drives
/// one is gated the same way: a **person** must be
/// Operator or above, one of the **stack's own services** passes, and a
/// **peer** passes only for its own id — and for `tasking`, not even then
/// (see [`peer_action_allowed`]). The returned label names the actor for the
/// audit row; it is never taken from the body.
///
/// Before this, `peer_deregister` and `peer_dispatch_task` took no caller
/// context at all: any peer token could delete any other peer's registration
/// or push a `task_request` into another peer's socket.
fn authorize_peer_action(
    verb: &str,
    agent_id: &str,
    requester: Option<&crate::auth::RequesterCtx>,
    cluster: Option<&crate::auth::ClusterNode>,
    peer: Option<&crate::auth::PeerSub>,
) -> Result<String, AppError> {
    let operator = requester.map(|r| r.role >= crate::auth::Role::Operator).unwrap_or(false);
    let internal = cluster.map(|c| c.is_internal()).unwrap_or(false);
    let this_peer = peer.map(|p| p.0 == format!("peer:{agent_id}")).unwrap_or(false);

    if !peer_action_allowed(operator, internal, this_peer, verb) {
        return Err(AppError::Forbidden(format!(
            "{verb} '{agent_id}' needs an operator token{}",
            if verb == "tasking" { "" } else { ", or the peer token already issued for that id" }
        )));
    }

    // The label, in the same order the rule consulted them.
    Ok(match (operator, internal) {
        (true, _) => format!("user:{}", requester.map(|r| r.sub.as_str()).unwrap_or("?")),
        (_, true) => format!("cluster:{}", cluster.map(|c| c.0.as_str()).unwrap_or("?")),
        _ => peer.map(|p| p.0.clone()).unwrap_or_default(),
    })
}

/// The peer-management rule, pure so a test can pin it:
/// operators and stack services may act on any peer; a peer may act only on
/// itself — and tasking oneself is the one thing that makes no sense, so
/// `tasking` refuses peers altogether. A peer that wants another peer to do
/// something sends it an agent message, which is recorded.
pub(crate) fn peer_action_allowed(operator: bool, internal: bool, this_peer: bool, verb: &str) -> bool {
    operator || internal || (this_peer && verb != "tasking")
}

/// POST /api/agents/peer/register — register an external peer agent.
///
/// Writes the peer's registration record to NATS KV `peer_agents` with
/// the requested TTL. Returns a peer-scoped JWT the agent can use for
/// subsequent calls including the /ws/agent WebSocket connection.
///
/// ## Two rules for whoever builds presence here
///
/// **1. `kv.put(&agent_id, …)` is one record per NAME, and that is the
/// defect phase C exists to fix.** The registry cannot represent "two of
/// me are alive": two sessions registering under one identity overwrite
/// each other silently, and a sender finds whichever refreshed last.
/// It is not fixable before connections are distinct identities, because
/// there is no per-session key to record under; that key is the design's.
///
/// **2. A registration is an ADVERTISEMENT, never an AUTHORIZATION.** An
/// agent may declare what it listens for — which names, which kinds — and
/// a sender may read that to route sensibly. A receiving loop must NOT
/// filter on it, because the moment it does, whoever can write a
/// registration decides what an agent acts on, and a discovery record has
/// quietly become an access-control record.
///
/// The declaration says *what I am interested in*; the trust list says
/// *whose messages I will act on*; the receiver applies the second one
/// locally and never takes it from the registry. This is the same
/// collapse as "prefix ownership is not `may_manage`" and "the account
/// keys history, the connection keys routing" — the third and fourth
/// times it has been caught in this design, which makes it the shape to
/// look for rather than a coincidence.
///
/// Two consequences worth writing down before they are rediscovered: the
/// declaration has to ride the REFRESH, not just the registration (what
/// an agent listens for changes mid-session, and a stale value under a
/// fresh TTL is the worst combination), and addressing a kind the
/// receiver does not listen for should be refused at send rather than
/// delivered to sit unread forever — same argument, and same enforcement
/// point, as resolving an unknown recipient.
async fn peer_register(
    State(state): State<Arc<AppState>>,
    requester: Option<axum::Extension<crate::auth::RequesterCtx>>,
    cluster: Option<axum::Extension<crate::auth::ClusterNode>>,
    peer: Option<axum::Extension<crate::auth::PeerSub>>,
    Json(body): Json<PeerRegisterRequest>,
) -> AppResult {
    let agent_id = body.agent_id.trim().to_string();
    if agent_id.is_empty() {
        return Err(AppError::BadRequest("agent_id is required".into()));
    }
    // Ids become NATS subject tokens and registry keys — one rule everywhere.
    crate::agent_messages::check_id("agent_id", &agent_id).map_err(AppError::BadRequest)?;
    if let Some(bad) = body.capabilities.iter().find(|c| c.is_empty() || !c.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')) {
        return Err(AppError::BadRequest(format!("capability '{bad}' is not a plain token")));
    }
    // Who may mint a token for this agent id: an operator,
    // one of the stack's own services, or the peer that already holds
    // `peer:<agent_id>` renewing itself. A peer token for agent A must not
    // become a token for agent B.
    let minter = authorize_peer_action(
        "registering",
        &agent_id,
        requester.as_ref().map(|axum::Extension(r)| r),
        cluster.as_ref().map(|axum::Extension(c)| c),
        peer.as_ref().map(|axum::Extension(p)| p),
    )?;

    let ttl = body.ttl_seconds.unwrap_or(3600).min(86400); // cap at 24h
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at = now_secs + ttl;

    // Same token rule as capabilities: these end up in a listing beside
    // an id the system derived, and a well-guarded neighbour is evidence
    // about the neighbour, never about the field next to it.
    if let Some(bad) = body.listens_for.iter().find(|k| !crate::auth::valid_name_segment(k)) {
        return Err(AppError::BadRequest(format!(
            "listens_for '{bad}' is not a plain token"
        )));
    }
    if let Some(d) = body.display_name.as_deref() {
        // Bounded and printable, but NOT the id class: a display name is
        // allowed spaces and punctuation precisely because nothing
        // compares it. The limit is so a listing stays readable.
        if d.chars().count() > 64 || d.chars().any(|c| c.is_control()) {
            return Err(AppError::BadRequest(
                "display_name must be at most 64 characters and contain no control characters".into(),
            ));
        }
    }

    let record = json!({
        "agent_id": &agent_id,
        "display_name": &body.display_name,
        "listens_for": &body.listens_for,
        "owner": crate::auth::account_of(&agent_id),
        "name": &body.name,
        "version": &body.version,
        "capabilities": &body.capabilities,
        "roles": &body.roles,
        "endpoint": &body.endpoint,
        "registered_at": now_secs,
        "expires_at": expires_at,
        "status": "registered",
    });

    // Write to NATS KV (cluster-wide visibility)
    if let Ok(kv) = state.js.get_key_value("peer_agents").await {
        kv.put(&agent_id, serde_json::to_vec(&record).unwrap_or_default().into())
            .await
            .map_err(|e| AppError::Internal(format!("NATS KV write failed: {e}")))?;
    }

    // Issue a peer-scoped JWT the agent can use for /ws/agent and API calls
    let peer_token = issue_peer_token(&agent_id, ttl)?;

    tracing::info!(
        agent_id = %agent_id,
        name = %body.name,
        ttl = ttl,
        minter = %minter,
        "peer_registered"
    );

    // Minting an agent identity is an identity event: who minted it, for
    // which agent, for how long. The token itself is never logged.
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::PeerTokenMinted, &minter, &format!("agent:{agent_id}"))
            .outcome(crate::audit::Outcome::custom("success"))
            .details(json!({ "agent_id": &agent_id, "ttl_seconds": ttl, "expires_at": expires_at })),
    )
    .await;

    Ok(Json(json!({
        "status": "registered",
        "agent_id": agent_id,
        "expires_at": expires_at,
        "peer_token": peer_token,
        "websocket_url": "/ws/agent",
        "instructions": "Connect to websocket_url with ?token=<peer_token>, then send agent_hello",
    })))
}

/// Issue a JWT scoped to a specific peer agent.
/// Subject is `peer:{agent_id}`, scopes include `["peer"]`.
fn issue_peer_token(agent_id: &str, ttl_secs: u64) -> Result<String, AppError> {
    use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};

    let now = chrono::Utc::now();
    let exp = now + chrono::TimeDelta::seconds(ttl_secs as i64);

    let claims = json!({
        "sub": format!("peer:{agent_id}"),
        "scopes": ["peer"],
        "agent_id": agent_id,
        "exp": exp.timestamp(),
        "iat": now.timestamp(),
        "iss": crate::auth::JWT_ISSUER,
        "aud": crate::auth::JWT_AUDIENCE,
    });

    let secret = crate::auth::jwt_secret();
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());

    encode(&header, &claims, &key)
        .map_err(|e| AppError::Internal(format!("JWT issuance failed: {e}")))
}

// ═══════════════════════════════════════════════════════════════
// Peer listing
// ═══════════════════════════════════════════════════════════════

/// GET /api/agents/peer/ — list all registered peer agents.
///
/// Reads from NATS KV `peer_agents`. Also annotates each entry with
/// `is_connected: bool` from the in-memory connection map so callers
/// can distinguish registered-but-offline from actively connected peers.
async fn peer_list(State(state): State<Arc<AppState>>) -> AppResult {
    let connected_ids: std::collections::HashSet<String> = {
        let conns = state.peer_connections.read().await;
        conns.keys().cloned().collect()
    };

    let mut peers: Vec<Value> = Vec::new();

    if let Ok(kv) = state.js.get_key_value("peer_agents").await {
        use tokio_stream::StreamExt;
        if let Ok(keys) = kv.keys().await {
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
            for key in keys {
                if let Ok(Some(entry)) = kv.get(&key).await {
                    if let Ok(mut record) = serde_json::from_slice::<Value>(&entry) {
                        let is_connected = connected_ids.contains(&key);
                        if let Some(obj) = record.as_object_mut() {
                            obj.insert("is_connected".into(), json!(is_connected));
                        }
                        peers.push(record);
                    }
                }
            }
        }
    }

    Ok(Json(json!({
        "peers": peers,
        "total": peers.len(),
        "connected": connected_ids.len(),
    })))
}

// ═══════════════════════════════════════════════════════════════
// Peer deregistration
// ═══════════════════════════════════════════════════════════════


/// DELETE /api/agents/peer/{agent_id} — deregister a peer agent.
///
/// Removes the peer from NATS KV. If the peer has an active WebSocket
/// connection it will remain until the connection closes naturally, but
/// no new tasks will be dispatched to it.
async fn peer_deregister(
    State(state): State<Arc<AppState>>,
    requester: Option<axum::Extension<crate::auth::RequesterCtx>>,
    cluster: Option<axum::Extension<crate::auth::ClusterNode>>,
    peer: Option<axum::Extension<crate::auth::PeerSub>>,
    Path(agent_id): Path<String>,
) -> AppResult {
    // Who may remove this peer: an operator, a stack
    // service, or the peer itself. Any other peer could delete any other
    // peer before this.
    let actor = authorize_peer_action(
        "deregistering",
        &agent_id,
        requester.as_ref().map(|axum::Extension(r)| r),
        cluster.as_ref().map(|axum::Extension(c)| c),
        peer.as_ref().map(|axum::Extension(p)| p),
    )?;

    let removed_kv = if let Ok(kv) = state.js.get_key_value("peer_agents").await {
        kv.delete(&agent_id).await.is_ok()
    } else {
        false
    };

    let was_connected = {
        let conns = state.peer_connections.read().await;
        conns.contains_key(&agent_id)
    };

    tracing::info!(
        agent_id = %agent_id,
        removed_kv,
        was_connected,
        actor = %actor,
        "peer_deregistered"
    );

    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::PeerDeregistered, &actor, &format!("agent:{agent_id}"))
            .outcome(crate::audit::Outcome::custom("success"))
            .details(json!({ "agent_id": &agent_id, "removed_kv": removed_kv, "was_connected": was_connected })),
    )
    .await;

    Ok(Json(json!({
        "status": "deregistered",
        "agent_id": agent_id,
        "was_connected": was_connected,
    })))
}

// ═══════════════════════════════════════════════════════════════
// Task dispatch to a connected peer
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct PeerTaskRequest {
    task_id: Option<String>,
    role: String,
    task: String,
    #[serde(default)]
    context: Value,
}

/// POST /api/agents/peer/{agent_id}/task — dispatch a task to a connected peer.
///
/// Sends a `task_request` message to the peer's active WebSocket connection.
/// The peer is expected to stream `task_token` messages back and a final
/// `task_done` or `task_error`, all routed via NATS subject
/// `agent.peer.{agent_id}.task.{task_id}`.
async fn peer_dispatch_task(
    State(state): State<Arc<AppState>>,
    requester: Option<axum::Extension<crate::auth::RequesterCtx>>,
    cluster: Option<axum::Extension<crate::auth::ClusterNode>>,
    peer: Option<axum::Extension<crate::auth::PeerSub>>,
    Path(agent_id): Path<String>,
    Json(body): Json<PeerTaskRequest>,
) -> AppResult {
    // Who may task this peer: an operator or a stack
    // service. A peer may not drive another peer — `task_request` lands
    // directly in the target's socket, so an unchecked dispatch is one peer
    // speaking with the gateway's voice into another peer's session. That is
    // what agent messages are for, with a record.
    let actor = authorize_peer_action(
        "tasking",
        &agent_id,
        requester.as_ref().map(|axum::Extension(r)| r),
        cluster.as_ref().map(|axum::Extension(c)| c),
        peer.as_ref().map(|axum::Extension(p)| p),
    )?;

    let tx = {
        let conns = state.peer_connections.read().await;
        conns.get(&agent_id).cloned()
    };

    let tx = match tx {
        Some(t) => t,
        None => {
            return Err(AppError::NotFound(format!(
                "Peer agent '{agent_id}' is not connected via /ws/agent"
            )));
        }
    };

    let task_id = body
        .task_id
        .unwrap_or_else(|| format!("t-{}", uuid_short()));

    let payload = json!({
        "type": "task_request",
        "task_id": &task_id,
        "role": &body.role,
        "task": &body.task,
        "context": &body.context,
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });

    tx.send(payload)
        .await
        .map_err(|_| AppError::Internal("Peer connection channel closed".into()))?;

    tracing::info!(
        agent_id = %agent_id,
        task_id = %task_id,
        role = %body.role,
        actor = %actor,
        "peer_task_dispatched"
    );

    Ok(Json(json!({
        "status": "dispatched",
        "task_id": task_id,
        "agent_id": agent_id,
        "result_subject": format!("agent.peer.{agent_id}.task.{task_id}"),
    })))
}

// ═══════════════════════════════════════════════════════════════
// Capability-based peer discovery
// ═══════════════════════════════════════════════════════════════

/// GET /api/agents/peer/for-capability/{capability} — find a connected peer.
///
/// Returns the first connected peer that advertises the requested capability.
/// MESH coordinator and tool dispatch layer use this to decide whether to
/// delegate work to an external harness rather than running it internally.
///
/// Response includes the peer's agent_id and a `dispatch_url` ready to POST to.
async fn peer_for_capability(
    State(state): State<Arc<AppState>>,
    Path(capability): Path<String>,
) -> AppResult {
    let connected_ids: std::collections::HashSet<String> = {
        let conns = state.peer_connections.read().await;
        conns.keys().cloned().collect()
    };

    if connected_ids.is_empty() {
        return Err(AppError::NotFound(format!(
            "No peer agents connected — cannot handle capability '{capability}'"
        )));
    }

    if let Ok(kv) = state.js.get_key_value("peer_agents").await {
        use tokio_stream::StreamExt;
        if let Ok(keys) = kv.keys().await {
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
            for key in keys {
                if !connected_ids.contains(&key) {
                    continue;
                }
                if let Ok(Some(entry)) = kv.get(&key).await {
                    if let Ok(record) = serde_json::from_slice::<Value>(&entry) {
                        let caps = record
                            .get("capabilities")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        let has_cap = caps.iter().any(|c| {
                            c.as_str().map(|s| s == capability).unwrap_or(false)
                        });
                        if has_cap {
                            return Ok(Json(json!({
                                "found": true,
                                "agent_id": &key,
                                "name": record.get("name"),
                                "capability": &capability,
                                "dispatch_url": format!("/api/agents/peer/{key}/task"),
                                "nats_subject": format!("agent.capability.request.{capability}"),
                            })));
                        }
                    }
                }
            }
        }
    }

    Err(AppError::NotFound(format!(
        "No connected peer offers capability '{capability}'"
    )))
}

fn uuid_short() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", ts & 0xFFFF_FFFF)
}

#[cfg(test)]
mod peer_rule_tests {
    use super::peer_action_allowed;

    /// PINNED: peers act only on themselves, and never
    /// task through the gateway; operators and services act on any peer.
    #[test]
    fn peers_manage_only_themselves_and_never_task() {
        assert!(peer_action_allowed(true, false, false, "tasking"));
        assert!(peer_action_allowed(false, true, false, "tasking"));
        assert!(!peer_action_allowed(false, false, true, "tasking"));
        assert!(peer_action_allowed(false, false, true, "deregistering"));
        assert!(!peer_action_allowed(false, false, false, "deregistering"), "a user token manages no peer");
        assert!(!peer_action_allowed(false, false, false, "tasking"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{ClusterKind, ClusterNode, PeerSub, RequesterCtx, Role};

    fn person(sub: &str, role: Role) -> RequesterCtx {
        RequesterCtx { sub: sub.into(), scopes: vec![], role, harness: None, act: None }
    }

    /// `peer_deregister` and `peer_dispatch_task` took no caller context,
    /// so any peer token could delete or drive any other peer. On the old
    /// code there was nothing to call here at all.
    #[test]
    fn a_peer_may_not_act_on_another_peer() {
        let hermes = PeerSub("peer:hermes-1".into());
        let err = authorize_peer_action("deregistering", "hermes-2", None, None, Some(&hermes))
            .expect_err("cross-peer deregistration must be refused");
        assert!(matches!(err, AppError::Forbidden(_)), "must be a 403, got {err:?}");
        assert!(authorize_peer_action("deregistering", "hermes-1", None, None, Some(&hermes)).is_ok());
    }

    /// Tasking is stricter than deregistering: a peer may not dispatch a task
    /// even to ITSELF through the gateway — that is what agent messages are
    /// for, and they leave a record.
    #[test]
    fn a_peer_never_tasks_through_the_gateway() {
        let hermes = PeerSub("peer:hermes-1".into());
        assert!(authorize_peer_action("tasking", "hermes-1", None, None, Some(&hermes)).is_err());
        assert!(authorize_peer_action("tasking", "hermes-2", None, None, Some(&hermes)).is_err());
        // A peer renewing its own registration is still fine.
        assert_eq!(
            authorize_peer_action("registering", "hermes-1", None, None, Some(&hermes)).unwrap(),
            "peer:hermes-1"
        );
    }

    /// A person needs Operator or above; a User-tier token is not an
    /// agent-identity authority even though it is a valid credential.
    #[test]
    fn a_user_tier_person_may_not_act_on_an_agent() {
        let user = person("alice", Role::User);
        assert!(authorize_peer_action("deregistering", "hermes-1", Some(&user), None, None).is_err());
        for role in [Role::Operator, Role::Admin] {
            let p = person("alice", role);
            let actor = authorize_peer_action("deregistering", "hermes-1", Some(&p), None, None)
                .expect("an operator may deregister any peer");
            assert_eq!(actor, "user:alice", "the audit actor is the token subject");
        }
    }

    /// The stack's own services pass; a NODE-tier cluster token does not —
    /// a compute node has no business minting or deleting agent identities.
    #[test]
    fn internal_services_pass_and_nodes_do_not() {
        let internal = ClusterNode("gateway".into(), ClusterKind::Internal);
        assert_eq!(
            authorize_peer_action("registering", "hermes-1", None, Some(&internal), None).unwrap(),
            "cluster:gateway"
        );
        let node = ClusterNode("host3".into(), ClusterKind::Node);
        assert!(authorize_peer_action("registering", "hermes-1", None, Some(&node), None).is_err());
    }

    /// No credential context at all → refused, not defaulted.
    #[test]
    fn no_caller_context_is_refused() {
        assert!(authorize_peer_action("registering", "hermes-1", None, None, None).is_err());
    }
}
