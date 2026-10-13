// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Other/uncategorized routes — device, terminal, MCP, cloud, capability-router.
//!
//! Native Rust handlers (ported from NATS delegation 2026-03-31):
//! - MCP status: HTTP health check to MCP hub port
//! - Cloud providers status: env var checks for API keys
//! - Capability router status: read from cached YAML config
//! - Device action: HTTP proxy to companion device
//! - Ollama create-variant: HTTP proxy to Ollama /api/create
//!
//! Terminal ollama/pull and ollama/delete were already native Rust.

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post, delete},
    extract::{State, Path},
    Json,
    body::Body,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde_json::{json, Value};

use crate::state::AppState;
use super::{AppJson, AppError, AppResult};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── MCP: Native Rust (HTTP health check to MCP hub) ──
        .route("/api/mcp/status", get(mcp_status))

        // ── Cloud providers: Native Rust (env var checks) ──
        .route("/api/cloud-providers/status", get(cloud_providers_status))

        // ── Coordinator: Native Rust (state from Rust coordinator, ported 2026-03-31) ──
        .route("/api/coordinator/context", get(coordinator_context))

        // ── Capability router: Native Rust (YAML config) ──
        .route("/api/capability-router/status", get(capability_router_status))

        // ── Device: Native Rust (HTTP proxy to companion device) ──
        .route("/api/v1/device/{action}", post(device_action))

        // ── Terminal: Native Rust (HTTP proxies) ──
        .route("/api/terminal/ollama/pull", post(terminal_ollama_pull))
        .route("/api/terminal/ollama/{model_name}", delete(terminal_ollama_delete))

        // ── Terminal: Native Rust (Ollama HTTP proxy, ported from NATS 2026-03-31) ──
        .route("/api/terminal/ollama/create-claude-variant", post(ollama_create_variant))
}

// ── Coordinator context (native Rust, ported from NATS 2026-03-31) ──
//
// The Python version called coordinator.get_context() which returned
// session state from the Python coordinator object. The Rust version
// returns the Rust coordinator's state: resolved backend, active
// session info, config, and gossip mesh peer count.

/// GET /api/coordinator/context — return the Rust coordinator's current state.
///
/// Reports backend resolution status, active configuration, gossip mesh
/// peer count, and session store info. This replaces the Python coordinator's
/// get_context() which returned similar data from its in-process state.
async fn coordinator_context(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    // Attempt backend resolution (non-blocking, reports current state)
    let backend_info = match crate::coordinator::resolve_backend(&state).await {
        Ok(b) => json!({
            "url": b.url,
            "model": b.model,
            "backend_type": b.backend_type,
            "api_format": b.api_format,
            "status": "resolved",
        }),
        Err(e) => json!({
            "status": "unavailable",
            "error": format!("{e}"),
        }),
    };

    // Gossip mesh peer count
    let peers = state.gossip.find_peers(None, None, 100);
    let peer_count = peers.len();
    let peer_summaries: Vec<Value> = peers.iter().take(10).map(|p| {
        json!({
            "node_id": p.node_id,
            "backends": p.backends.keys().collect::<Vec<_>>(),
        })
    }).collect();

    // Config summary
    let config = &state.config;
    let coordinator_config = json!({
        "max_iterations": config.coordinator.max_iterations,
        "max_session_messages": config.coordinator.max_session_messages,
        "max_context_tokens": config.coordinator.max_context_tokens,
        "enabled": config.coordinator.enabled,
        "default_backend": config.cluster.default_backend,
    });

    // Active sessions: count from Postgres
    let session_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM noo_conversations \
         WHERE started_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    // Redis cache status
    let redis_status = if state.redis.is_some() { "connected" } else { "unavailable" };

    // Tool schemas count
    let tool_count = state.tool_schemas.read().await.len();

    Ok(Json(json!({
        "status": "running",
        "backend": backend_info,
        "coordinator_config": coordinator_config,
        "gossip_peers": peer_count,
        "peer_details": peer_summaries,
        "active_sessions_24h": session_count,
        "redis": redis_status,
        "tool_schemas_loaded": tool_count,
        "runbooks_loaded": state.runbooks.len(),
        "engine": "rust",
    })))
}

// ── MCP status (native Rust) ──────────────────────────────────────

/// The MCP doors this gateway serves.
///
/// GET /api/mcp/status
///
/// Until stack-v0.2.40 this dialled a separate plain-HTTP listener on
/// `NOO_MCP_HOST:NOO_MCP_PORT` and reported whether it answered. That
/// listener is gone: both doors are routes on this very process, so if
/// this handler runs, they are up. The status is a description, not a
/// probe.
async fn mcp_status() -> AppJson {
    Json(json!({
        "status": "running",
        "doors": {
            "operator": "/mcp/operator",
            "user": "/mcp/user",
        },
        "user_door_open": crate::mcp_external::enabled(),
        "engine": "rust",
    }))
}

// ── Cloud providers status (native Rust) ──────────────────────────

/// Check which cloud API keys are configured.
///
/// GET /api/cloud-providers/status
///
/// Inspects environment variables for each provider's API key.
async fn cloud_providers_status() -> AppJson {
    let providers = [
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("openai", "OPENAI_API_KEY"),
        ("google", "GOOGLE_API_KEY"),
    ];

    let mut providers_status = serde_json::Map::new();
    let mut available = Vec::new();

    for (name, env_key) in &providers {
        let api_key_set = crate::config::secret_env::secret_opt(env_key).is_some();

        providers_status.insert(name.to_string(), json!({
            "available": api_key_set,
            "api_key_set": api_key_set,
        }));

        if api_key_set {
            available.push(*name);
        }
    }

    Json(json!({
        "enabled": !available.is_empty(),
        "providers": providers_status,
        "available_providers": available,
        "engine": "rust",
    }))
}

// ── Capability router status (native Rust) ────────────────────────

/// Return capability routing configuration from YAML config.
///
/// GET /api/capability-router/status
///
/// Reads the `capability_router` section from the cached noomesh.yaml.
async fn capability_router_status(
    State(state): State<Arc<AppState>>,
) -> AppJson {
    let config = state.config_yaml.read().await;

    // Look for capability_router section in the YAML config
    if let Some(cr) = config.get("capability_router") {
        Json(json!({
            "status": "configured",
            "config": cr,
            "engine": "rust",
        }))
    } else {
        Json(json!({
            "status": "not_configured",
            "message": "No capability_router section in noomesh.yaml",
            "engine": "rust",
        }))
    }
}

// ── Device action (native Rust, HTTP proxy) ───────────────────────

/// Build the node-agent URL for a companion device action.
///
/// The Go node-agent serves device sensors under `/api/device/{action}`
/// (node-agent-go/internal/api/server.go), matching the legacy Python
/// node_agent.py routes. This proxy used to call `/device/{action}`,
/// which 404s on every agent — keep the prefix in sync with the agent.
fn device_action_url(device_url: &str, action: &str) -> String {
    format!("{}/api/device/{}", device_url.trim_end_matches('/'), action)
}

/// Proxy an action to a companion device.
///
/// POST /api/v1/device/{action}
///
/// Looks up the target device's IP from NATS KV (mesh_nodes) and proxies
/// the request to the device's HTTP endpoint.
async fn device_action(
    State(state): State<Arc<AppState>>,
    Path(action): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    // Determine target device from body or default to first companion
    let device_id = body.get("device_id")
        .or(body.get("node_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Look up device in NATS KV
    let device_url = if !device_id.is_empty() {
        super::cluster::get_node_agent_url(&state, device_id).await?
    } else {
        // Find first companion device (tier >= 5) from NATS KV
        let mut found_url = None;
        if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
            use tokio_stream::StreamExt;
            if let Ok(keys) = kv.keys().await {
                let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
                for key in keys {
                    if let Ok(Some(entry)) = kv.get(&key).await {
                        if let Ok(data) = serde_json::from_slice::<Value>(&entry) {
                            let tier = data.get("tier").and_then(|t| t.as_u64()).unwrap_or(0);
                            if tier >= 5 {
                                if let Ok(url) = super::cluster::get_node_agent_url(&state, &key).await {
                                    found_url = Some(url);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        found_url.ok_or_else(|| AppError::NotFound("No companion device found".into()))?
    };

    // Proxy the action to the device
    let url = device_action_url(&device_url, &action);
    let client = super::cluster::build_node_agent_client();
    let mut req = client.post(&url).json(&body);
    if let Some((k, v)) = crate::node_agent_auth::header_for(&url) {
        req = req.header(&k, &v);
    }

    match req.timeout(std::time::Duration::from_secs(30)).send().await {
        Ok(resp) if resp.status().is_success() => {
            let data = resp.json::<Value>().await.unwrap_or(json!({}));
            Ok(Json(data))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Err(AppError::Internal(format!("Device returned {status}: {text}")))
        }
        Err(e) => {
            Err(AppError::Internal(format!("Device unreachable: {e}")))
        }
    }
}

// ── Ollama create-variant (native Rust, HTTP proxy) ───────────────

/// Create an Ollama model variant (Modelfile-based).
///
/// POST /api/terminal/ollama/create-claude-variant
///
/// Proxies to Ollama's /api/create endpoint.  Body should contain
/// `model` (name for the new variant) and `modelfile` (Modelfile content).
async fn ollama_create_variant(
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let model = body.get("model").and_then(|v| v.as_str()).unwrap_or("");
    if model.is_empty() {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"error": "'model' is required"}))).into_response();
    }

    let modelfile = body.get("modelfile").and_then(|v| v.as_str()).unwrap_or("");
    if modelfile.is_empty() {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"error": "'modelfile' is required"}))).into_response();
    }

    let base_url = ollama_base_url();
    let url = format!("{}/api/create", base_url.trim_end_matches('/'));

    let client = crate::tls::cluster_client();

    match client
        .post(&url)
        .json(&json!({"name": model, "modelfile": modelfile}))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let data = resp.json::<Value>().await.unwrap_or(json!({"status": "success"}));
            Json(json!({
                "status": "created",
                "model": model,
                "response": data,
            })).into_response()
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            (StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                Json(json!({"error": format!("Ollama returned {status}: {text}")}))).into_response()
        }
        Err(e) => {
            (StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("Ollama unreachable: {e}")}))).into_response()
        }
    }
}

// ── Ollama URL helper ───────────────────────────────────────────────

fn ollama_base_url() -> String {
    std::env::var("OLLAMA_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| crate::config::global().services.ollama_url.clone().filter(|v| !v.is_empty()))
        // Ollama has no TLS listener of its own; its door on the compose
        // network is the stunnel sidecar (mTLS). Always — the gateway refuses
        // to start without the cluster CA, so the old `NOO_TLS_CA`-gated
        // plain `noo-ollama` form described no reachable configuration.
        .unwrap_or_else(|| "https://stunnel-ollama:11434".into())
}

// ── Terminal: Ollama pull (SSE streaming) ───────────────────────────

/// Pull an Ollama model — streams progress as SSE.
///
/// POST /api/terminal/ollama/pull
/// Body: {"model": "qwen2.5-coder:14b"}
async fn terminal_ollama_pull(
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let model_name = body.get("model").and_then(|m| m.as_str()).unwrap_or("").trim().to_string();
    if model_name.is_empty() {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"error": "model is required"}))).into_response();
    }

    let base_url = ollama_base_url();
    let url = format!("{}/api/pull", base_url.trim_end_matches('/'));

    let client = crate::tls::cluster_client();

    // Stream the response from Ollama as SSE
    match client
        .post(&url)
        .json(&json!({"name": model_name, "stream": true}))
        .timeout(std::time::Duration::from_secs(600))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let stream = resp.bytes_stream();
            let body = Body::from_stream(stream);

            Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .body(body)
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Stream error").into_response()
                })
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            (StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                Json(json!({"error": format!("Ollama returned {status}: {text}")}))).into_response()
        }
        Err(e) => {
            (StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("Ollama unreachable: {e}")}))).into_response()
        }
    }
}

// ── Terminal: Ollama delete ─────────────────────────────────────────

/// Delete an Ollama model.
///
/// DELETE /api/terminal/ollama/{model_name}
async fn terminal_ollama_delete(
    Path(model_name): Path<String>,
) -> impl IntoResponse {
    let base_url = ollama_base_url();
    let url = format!("{}/api/delete", base_url.trim_end_matches('/'));

    let client = super::cluster::build_node_agent_client();

    match client
        .delete(&url)
        .json(&json!({"name": model_name}))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            Json(json!({"status": "deleted", "model": model_name})).into_response()
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            (StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(json!({"error": format!("Failed to delete: Ollama returned {status}: {text}")}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to delete: {e}")}))).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::device_action_url;

    /// Contract with the node-agent: device sensor routes live under
    /// /api/device/* (Go server.go, legacy Python node_agent.py). The
    /// old `/device/{action}` form 404'd on every agent.
    #[test]
    fn device_action_url_uses_api_prefix() {
        assert_eq!(
            device_action_url("https://phone-1:8081", "camera_capture"),
            "https://phone-1:8081/api/device/camera_capture"
        );
        // Trailing slash on the agent URL must not double up.
        assert_eq!(
            device_action_url("https://phone-1:8081/", "location"),
            "https://phone-1:8081/api/device/location"
        );
    }
}
