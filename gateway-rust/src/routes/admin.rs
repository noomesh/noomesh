// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Admin routes — scheduler, logs, security, testing, cleanup.
//!
//! Native Rust: log proxying to Loki, security audit-history (SQL),
//!              cache stats (Redis INFO), heartbeat-run prune restore (SQL),
//!              job queries (Redis: list, history, get-by-id),
//!              job cancel + reprioritize (Redis mutations),
//!              scheduler submit/status/pause/resume/drain/undrain (Redis),
//!              test runner (background pytest),
//!              security violations (Redis counters), PKI status (filesystem),
//!              exec-approval status (env/config), approval CRUD (SQL)
//! NATS delegation: PKI rotate-expiring (needs Python PKI manager)

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
    extract::{State, Path, Query},
    Extension,
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use crate::auth::{account_of, scoped_account, scoped_user, AuthActor, ClusterNode, RequesterCtx};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;
use super::{logs_search, AppJson, AppError, AppResult};

// Python subjects this module has replaced. See `crate::ported`.
crate::ported! {
    POST "/api/logs/errors"    => "worker.api.logs.errors",
    POST "/api/logs/tail"      => "worker.api.logs.tail",
    POST "/api/mesh/rebuild"  => "worker.api.mesh.rebuild",
    POST "/api/mesh/restart"  => "worker.api.mesh.restart",
    GET  "/api/mesh/status"   => "worker.api.mesh.status",
    GET  "/api/metrics/query"  => "worker.api.metrics.query",
}


pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Logs: Native Rust (HTTP proxy to Loki / node-agents) ──
        .route("/api/logs/status", get(logs_status))
        .route("/api/logs/query", get(logs_query))
        .route("/api/logs/containers", get(logs_containers))
        .route("/api/logs/docker-stats", get(logs_docker_stats))
        .route("/api/logs/node/{node_id}/{container}", get(logs_node_container))

        // ── Cache stats: Native Rust (Redis INFO) ──
        .route("/api/cache/stats", get(cache_stats))

        // ── Schema migrations: the runner's own view. The
        // CLI's `noo db current/history/upgrade` used to docker-exec Python
        // into this container, which has carried no Python since the mesh
        // chain went native — every one of them failed. Read = any auth;
        // apply = admin (cluster-HMAC callers are privileged, as elsewhere).
        .route("/api/db/migrations", get(db_migrations))
        .route("/api/db/migrations/apply", post(db_migrations_apply))

        // ── Security audit-history: Native Rust (SQL) ──
        .route("/api/security/audit-history", get(security_audit_history))
        // ── Security audit stats: counters by event_type in last N minutes
        // (the design port; replaces a NATS-routed Python handler that
        // had the wrong column name `created_at` and silently 0'd out).
        .route("/api/security/audit/stats", get(security_audit_stats))
        // ── Audit integrity: verify every row's entry_hash across the audit
        // key checkpoint (audit_integrity.rs). Here, because only the gateway
        // holds BOTH keys the log was ever signed with.
        .route("/api/security/audit/verify", get(security_audit_verify))

        // ── Cleanup: the prune itself is the `heartbeat_retention` heartbeat
        // task (run on demand via POST /api/heartbeat/tasks/{task_id}/run).
        // Undo one heartbeat-retention prune. A staging table nobody can read
        // back from is not a restore window, it is a slower delete — so the
        // prune's counterpart gets a route, not just a repo function.
        .route(
            "/api/cleanup/heartbeat-runs/restore",
            post(cleanup_restore_heartbeat_runs),
        )

        // ── Scheduler: Native Rust (Redis reads + mutations) ──
        .route("/api/jobs", get(list_jobs))
        .route("/api/jobs/history", get(job_history))
        .route("/api/jobs/{job_id}", get(get_job).delete(cancel_job))
        .route("/api/jobs/{job_id}/reprioritize", post(reprioritize_job))

        // ── Scheduler: Native Rust (Redis submit/status/controls) ──
        .route("/api/tasks/submit", post(scheduler_submit_task))
        // /api/tasks/inference is in inference.rs (avoids overlap)
        .route("/api/jobs/submit", post(scheduler_submit_job))
        .route("/api/scheduler/status", get(scheduler_status))
        .route("/api/scheduler/pause", post(scheduler_pause))
        .route("/api/scheduler/resume", post(scheduler_resume))
        .route("/api/scheduler/drain/{node_id}", post(scheduler_drain))
        .route("/api/scheduler/undrain/{node_id}", post(scheduler_undrain))

        // ── Security: Native Rust (Redis counters + filesystem PKI check) ──
        .route("/api/security/violations", get(security_violations))
        .route("/api/security/pki/status", get(security_pki_status))
        // PKI rotate: native spool write — rotation always ran HOST-side
        // via the watcher (the "needs Python cryptography" note was wrong;
        // the Python handler's body was this same spool write + poll)
        .route("/api/security/pki/rotate-expiring", post(security_pki_rotate_expiring))

        // ── Approval: Native Rust (SQL on noo_approval_requests + env config) ──
        .route("/api/exec-approval/status", get(approval_status))
        .route("/api/approval/stats", get(approval_stats))
        .route("/api/approval/pending", get(approval_pending))
        .route("/api/approval/{request_id}/approve", post(approval_approve))
        .route("/api/approval/{request_id}/deny", post(approval_deny))
        .route("/api/approval/{request_id}/decide", post(approval_decide))

        // POST /api/v1/debug/query (admin raw-SQL passthrough) was removed
        // 2026-09-27: no caller, and its error fallback re-ran the query
        // outside the READ ONLY transaction.

        // ── Tests: Native Rust (filesystem + background subprocess) ──
        .route("/api/tests/status", get(tests_status))
        .route("/api/tests/run", post(tests_run))

        // ── Mesh host operations: Native Rust (host-watcher spool files) ──
        .route("/api/mesh/operations", get(mesh_operations))
        .route("/api/mesh/stack-rebuild", post(mesh_stack_rebuild))

        // ── Self-administration: Native Rust ports of the worker.api.logs.* /
        //    worker.api.mesh.* / worker.api.metrics.query NATS handlers.
        //    Explicit routes here shadow the /api/{*path} Python catch-all;
        //    the Python handlers in workers/admin.py stay as NATS fallback. ──
        .route("/api/logs/tail", post(logs_tail))
        .route("/api/logs/errors", post(logs_errors))
        .route("/api/logs/search", post(logs_search))
        .route("/api/mesh/status", get(mesh_status))
        .route("/api/mesh/restart", post(mesh_restart))
        .route("/api/mesh/rebuild", post(mesh_rebuild))
        .route("/api/metrics/query", get(metrics_query))
        .route("/api/metrics/range", get(metrics_range))
        .route("/api/metrics/discover", get(metrics_discover))
        .route("/api/alerts/list", get(alerts_list))
        .route("/api/metrics/increment", post(metrics_increment))
        .route("/api/metrics/gauge", post(metrics_gauge))
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Logs (Loki proxy)
// ═══════════════════════════════════════════════════════════════

/// Log system status — check Loki connectivity.
async fn logs_status(State(state): State<Arc<AppState>>) -> AppJson {
    let loki_url = crate::config::env_or_yaml("NOO_LOKI_URL", |c| c.services.loki_url.clone(), "");
    let configured = !loki_url.is_empty();

    let mut healthy = false;
    // WHY /ready did not answer 2xx — Loki's own body ("Ingester not ready:
    // …"), a status, or the transport error. Until 2026-10-02 this was
    // folded into `false`: host8's verify FAILed the row once, the probe and
    // the push share this client and URL, logs were being accepted, and the
    // reason the probe missed was unrecoverable. Now it is in the response
    // (the `loki` row prints it) and in the gateway log.
    let mut detail: Option<String> = None;
    if configured {
        let client = crate::tls::cluster_client();
        let probe = client
            .get(format!("{loki_url}/ready"))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
        match probe {
            Ok(r) if r.status().is_success() => healthy = true,
            Ok(r) => {
                let status = r.status().as_u16();
                let body: String = r.text().await.unwrap_or_default().trim().chars().take(200).collect();
                detail = Some(loki_ready_detail(Some(status), &body));
            }
            Err(e) => {
                // The chain, not the top line: reqwest's own Display is
                // "error sending request" for a TLS refusal and a timeout alike.
                let mut chain = e.to_string();
                let mut src = std::error::Error::source(&e);
                while let Some(x) = src {
                    chain.push_str(": ");
                    chain.push_str(&x.to_string());
                    src = x.source();
                }
                detail = Some(loki_ready_detail(None, &chain));
            }
        }
        if let Some(d) = &detail {
            tracing::warn!(url = %loki_url, "loki /ready did not answer 2xx: {d}");
        }
    }

    // Was a literal `true` — `noo logs status` therefore printed
    // "node registry: available" even with NATS down. The registry lives in
    // the `mesh_nodes` KV bucket, so ask for the bucket instead of asserting.
    let node_registry_available = state.js.get_key_value("mesh_nodes").await.is_ok();

    Json(json!({
        "loki_url": loki_url,
        "loki_configured": configured,
        "loki_healthy": healthy,
        "loki_ready": healthy,
        "loki_ready_detail": detail,
        "node_registry_available": node_registry_available,
    }))
}

/// One line for a `/ready` miss: `status` + Loki's body, or the transport
/// error when nothing answered. Bounded; never a credential (Loki's ready
/// body is a fixed sentence, and the transport error names a host).
fn loki_ready_detail(status: Option<u16>, text: &str) -> String {
    let text: String = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(200).collect();
    match (status, text.is_empty()) {
        (Some(s), true) => format!("answered {s}"),
        (Some(s), false) => format!("answered {s}: {text}"),
        (None, _) => format!("no answer: {text}"),
    }
}

#[derive(Deserialize)]
struct LogQueryParams {
    query: String,
    limit: Option<u32>,
    start: Option<String>,
    end: Option<String>,
    direction: Option<String>,
}

/// Proxy log queries to Loki.
async fn logs_query(Query(params): Query<LogQueryParams>) -> impl IntoResponse {
    let loki_url = crate::config::env_or_yaml("NOO_LOKI_URL", |c| c.services.loki_url.clone(), "");
    if loki_url.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Loki not configured"}))).into_response();
    }

    let client = crate::tls::cluster_client();

    let limit = params.limit.unwrap_or(200).min(5000);
    let direction = params.direction.as_deref().unwrap_or("backward");

    let mut url = format!("{loki_url}/loki/api/v1/query_range?query={}&limit={limit}&direction={direction}",
        urlencoding::encode(&params.query));
    if let Some(start) = &params.start { url.push_str(&format!("&start={start}")); }
    if let Some(end) = &params.end { url.push_str(&format!("&end={end}")); }

    match client.get(&url).timeout(std::time::Duration::from_secs(30)).send().await {
        Ok(resp) => {
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let body = resp.text().await.unwrap_or_default();
            (status, body).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("Loki unreachable: {e}")}))).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Container/Docker logs (node-agent proxy)
// ═══════════════════════════════════════════════════════════════

/// Default local node-agent URL for single-machine / Docker Compose setups.
///
/// Dialled only when the KV lists no node at all, so there is no record to
/// key its credential on except the controller's own (`self_node`): its
/// callers use `node_agent_auth::header_for_self`, which sends no bearer once
/// the self node reported `controller_leaf_only` and the legacy bearer
/// otherwise.
fn local_agent_url() -> String {
    if let Ok(url) = std::env::var("NOO_LOCAL_AGENT_URL") {
        return url;
    }
    // Node agents serve mTLS only (no plaintext listener exists).
    let proto = "https";
    format!("{proto}://node-agent:8081")
}

/// Collect all node entries from NATS KV mesh_nodes (excluding gateway).
///
/// Returns Vec of (node_id, agent_url, hostname).
pub(crate) async fn all_node_agents(state: &AppState) -> Vec<(String, String, String)> {
    let mut nodes = Vec::new();
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        use tokio_stream::StreamExt;
        if let Ok(keys) = kv.keys().await {
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
            for key in keys {
                if key == "gateway" { continue; }
                if let Ok(Some(entry)) = kv.get(&key).await {
                    if let Ok(data) = serde_json::from_slice::<Value>(&entry) {
                        // Skip tier 0 (gateway entries)
                        if data.get("tier").and_then(|t| t.as_u64()) == Some(0) { continue; }
                        let hostname = data.get("hostname").and_then(|h| h.as_str())
                            .unwrap_or(&key).to_string();
                        // Resolve agent URL
                        let agent_url = if let Some(url) = data.get("agent_url").and_then(|v| v.as_str()) {
                            if !url.is_empty() { url.to_string() } else { continue; }
                        } else if let Some(ip) = data.get("ip_address").and_then(|v| v.as_str()) {
                            if !ip.is_empty() {
                                let proto = "https"; // node agents are mTLS-only
                                format!("{proto}://{ip}:8081")
                            } else { continue; }
                        } else {
                            continue;
                        };
                        nodes.push((key, agent_url, hostname));
                    }
                }
            }
        }
    }
    nodes
}

#[derive(Deserialize)]
struct ContainerQueryParams {
    node_id: Option<String>,
}

/// List containers across all nodes via node-agent `/logs/containers`.
///
/// GET /api/logs/containers?node_id=optional
async fn logs_containers(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ContainerQueryParams>,
) -> AppJson {
    let client = super::cluster::build_node_agent_client();
    let mut results: Vec<Value> = Vec::new();

    let nodes = all_node_agents(&state).await;

    if !nodes.is_empty() {
        for (nid, agent_url, hostname) in &nodes {
            if let Some(ref filter) = params.node_id {
                if nid != filter { continue; }
            }
            let mut req = client.get(format!("{agent_url}/logs/containers"));
            if let Some((ref k, ref v)) = crate::node_agent_auth::header_for(agent_url) {
                req = req.header(k.as_str(), v.as_str());
            }
            match req.timeout(std::time::Duration::from_secs(10)).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(containers) = resp.json::<Vec<Value>>().await {
                        for mut c in containers {
                            c["node_id"] = json!(nid);
                            c["node_hostname"] = json!(hostname);
                            results.push(c);
                        }
                    }
                }
                Ok(_) | Err(_) => {
                    tracing::debug!(node_id = %nid, "container list failed");
                }
            }
        }
    } else if params.node_id.is_none() {
        // Fallback: try local node-agent directly
        let local = local_agent_url();
        let mut req = client.get(format!("{local}/logs/containers"));
        if let Some((ref k, ref v)) = crate::node_agent_auth::header_for_self(&local) {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Ok(resp) = req.timeout(std::time::Duration::from_secs(10)).send().await {
            if resp.status().is_success() {
                if let Ok(containers) = resp.json::<Vec<Value>>().await {
                    for mut c in containers {
                        c["node_id"] = json!("local");
                        c["node_hostname"] = json!("local");
                        results.push(c);
                    }
                }
            }
        }
    }

    Json(json!({"containers": results}))
}

/// Get live container resource stats (CPU, memory, net/block I/O) across nodes.
///
/// GET /api/logs/docker-stats?node_id=optional
async fn logs_docker_stats(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ContainerQueryParams>,
) -> AppJson {
    let client = super::cluster::build_node_agent_client();
    let mut results: Vec<Value> = Vec::new();

    let nodes = all_node_agents(&state).await;

    if !nodes.is_empty() {
        for (nid, agent_url, hostname) in &nodes {
            if let Some(ref filter) = params.node_id {
                if nid != filter { continue; }
            }
            let mut req = client.get(format!("{agent_url}/stats/containers"));
            if let Some((ref k, ref v)) = crate::node_agent_auth::header_for(agent_url) {
                req = req.header(k.as_str(), v.as_str());
            }
            match req.timeout(std::time::Duration::from_secs(10)).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(containers) = resp.json::<Vec<Value>>().await {
                        for mut c in containers {
                            c["node_id"] = json!(nid);
                            c["node_hostname"] = json!(hostname);
                            results.push(c);
                        }
                    }
                }
                Ok(_) | Err(_) => {
                    tracing::debug!(node_id = %nid, "container stats failed");
                }
            }
        }
    } else if params.node_id.is_none() {
        // Fallback: try local node-agent directly
        let local = local_agent_url();
        let mut req = client.get(format!("{local}/stats/containers"));
        if let Some((ref k, ref v)) = crate::node_agent_auth::header_for_self(&local) {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Ok(resp) = req.timeout(std::time::Duration::from_secs(10)).send().await {
            if resp.status().is_success() {
                if let Ok(containers) = resp.json::<Vec<Value>>().await {
                    for mut c in containers {
                        c["node_id"] = json!("local");
                        c["node_hostname"] = json!("local");
                        results.push(c);
                    }
                }
            }
        }
    }

    let timestamp = chrono::Utc::now().to_rfc3339();
    Json(json!({"containers": results, "timestamp": timestamp}))
}

#[derive(Deserialize)]
struct NodeContainerLogParams {
    #[serde(default = "default_tail")]
    tail: u32,
    since: Option<String>,
}
fn default_tail() -> u32 { 200 }

/// Fetch logs from a specific container on a specific node.
///
/// GET /api/logs/node/{node_id}/{container}?tail=200&since=...
async fn logs_node_container(
    State(state): State<Arc<AppState>>,
    Path((node_id, container)): Path<(String, String)>,
    Query(params): Query<NodeContainerLogParams>,
) -> impl IntoResponse {
    let agent_url = match super::cluster::get_node_agent_url(&state, &node_id).await {
        Ok(url) => url,
        Err(_) => {
            return (StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Node not found: {node_id}")}))).into_response();
        }
    };

    let client = super::cluster::build_node_agent_client();
    let auth = crate::node_agent_auth::header_for(&agent_url);

    let tail = params.tail.min(2000);
    let mut url = format!("{agent_url}/logs/{container}?tail={tail}");
    if let Some(ref since) = params.since {
        url.push_str(&format!("&since={}", urlencoding::encode(since)));
    }

    let mut req = client.get(&url);
    if let Some((ref k, ref v)) = auth {
        req = req.header(k.as_str(), v.as_str());
    }

    match req.timeout(std::time::Duration::from_secs(30)).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Value>().await {
                Ok(body) => Json(body).into_response(),
                Err(e) => (StatusCode::BAD_GATEWAY,
                    Json(json!({"error": format!("Invalid response from node agent: {e}")}))).into_response(),
            }
        }
        Ok(resp) => {
            let status_code = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let body = resp.text().await.unwrap_or_default();
            (status_code, Json(json!({"error": format!("Log fetch failed: {body}")}))).into_response()
        }
        Err(e) => {
            (StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("Cannot connect to node-agent on {node_id}: {e}")}))).into_response()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Cache stats (Redis)
// ═══════════════════════════════════════════════════════════════

/// Redis cache statistics — key counts, memory usage, uptime.
///
/// Fetches Redis INFO and parses key metrics (memory, hit/miss ratio,
/// connections). Falls back to a basic healthy/unhealthy response if
/// INFO parsing fails.
pub(crate) async fn cache_stats(State(state): State<Arc<AppState>>) -> AppJson {
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Json(json!({"enabled": false, "reason": "Redis not connected"})),
    };

    let healthy = redis.is_healthy().await;

    // Try to get detailed INFO stats
    if let Some(info_str) = redis.info_raw().await {
        let mut stats = serde_json::Map::new();
        for line in info_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, val)) = line.split_once(':') {
                match key {
                    "used_memory_human" => { stats.insert("used_memory_human".into(), json!(val)); }
                    "used_memory" => { stats.insert("used_memory_bytes".into(), json!(val.parse::<i64>().unwrap_or(0))); }
                    "keyspace_hits" => { stats.insert("keyspace_hits".into(), json!(val.parse::<i64>().unwrap_or(0))); }
                    "keyspace_misses" => { stats.insert("keyspace_misses".into(), json!(val.parse::<i64>().unwrap_or(0))); }
                    "connected_clients" => { stats.insert("connected_clients".into(), json!(val.parse::<i64>().unwrap_or(0))); }
                    "total_connections_received" => { stats.insert("total_connections_received".into(), json!(val.parse::<i64>().unwrap_or(0))); }
                    "uptime_in_seconds" => { stats.insert("uptime_seconds".into(), json!(val.parse::<i64>().unwrap_or(0))); }
                    "maxmemory_human" => { stats.insert("maxmemory_human".into(), json!(val)); }
                    _ => {}
                }
            }
        }

        // Compute hit rate if both hits and misses are available
        if let (Some(hits), Some(misses)) = (
            stats.get("keyspace_hits").and_then(|v| v.as_i64()),
            stats.get("keyspace_misses").and_then(|v| v.as_i64()),
        ) {
            let total = hits + misses;
            let hit_rate = if total > 0 { hits as f64 / total as f64 } else { 0.0 };
            stats.insert("hit_rate".into(), json!(format!("{:.2}%", hit_rate * 100.0)));
        }

        Json(json!({
            "enabled": true,
            "healthy": healthy,
            "engine": "rust",
            "stats": stats,
        }))
    } else {
        Json(json!({
            "enabled": true,
            "healthy": healthy,
            "engine": "rust",
        }))
    }
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Security audit-history (SQL)
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct AuditHistoryParams {
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct AuditStatsParams {
    minutes: Option<i64>,
}

/// Return recent heartbeat runs for security_audit and disk_cleanup actions.
///
/// SQL query on noo_heartbeat_runs WHERE action IN ('security_audit', 'disk_cleanup').
/// Mirrors the Python `security_audit_history()` endpoint.
async fn security_audit_history(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Query(params): Query<AuditHistoryParams>,
) -> AppResult {
    super::operator_read_guard(&ctx)?;
    let limit = params.limit.unwrap_or(20).min(200);

    let rows = sqlx::query_as::<_, (
        String,                                    // run_id
        String,                                    // task_id
        String,                                    // task_name
        String,                                    // action
        chrono::DateTime<chrono::Utc>,             // started_at
        Option<chrono::DateTime<chrono::Utc>>,     // completed_at
        String,                                    // status
        Option<String>,                            // result_text
        Option<String>,                            // error
        i32,                                       // duration_ms
        Value,                                     // notified_channels
    )>(
        "SELECT run_id, task_id, task_name, action, started_at, completed_at, \
                status, result_text, error, COALESCE(duration_ms, 0), \
                COALESCE(notified_channels, '[]'::jsonb) \
         FROM noo_heartbeat_runs \
         WHERE action IN ('security_audit', 'disk_cleanup') \
         ORDER BY started_at DESC \
         LIMIT $1"
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    let runs: Vec<Value> = rows.iter().map(|(
        run_id, task_id, task_name, action,
        started_at, completed_at, status,
        result_text, error, duration_ms, channels,
    )| {
        json!({
            "run_id": run_id,
            "task_id": task_id,
            "task_name": task_name,
            "action": action,
            "started_at": started_at,
            "completed_at": completed_at,
            "status": status,
            "result_text": result_text,
            "error": error,
            "duration_ms": duration_ms,
            "notified_channels": channels,
        })
    }).collect();

    Ok(Json(json!({"runs": runs})))
}

/// GET /api/security/audit/stats?minutes=5
///
/// Counters of security audit events by `event_type` over the trailing
/// window. The Python predecessor referenced a `created_at` column that
/// doesn't exist (the table column is `timestamp`), so the rolled-up
/// counts have been silently zero for as long as anyone's looked. Native
/// version uses the right column.
async fn security_audit_stats(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Query(params): Query<AuditStatsParams>,
) -> AppResult {
    super::operator_read_guard(&ctx)?;
    let minutes = params.minutes.unwrap_or(5).clamp(1, 1440);
    let interval = format!("{minutes} minutes");

    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT event_type, COUNT(*) AS cnt \
         FROM noo_security_audit \
         WHERE timestamp > NOW() - $1::interval \
         GROUP BY event_type",
    )
    .bind(&interval)
    .fetch_all(&state.db)
    .await?;

    let mut events_5m = serde_json::Map::new();
    let mut auth_failures = 0i64;
    let mut rate_limit = 0i64;
    for (event_type, cnt) in &rows {
        events_5m.insert(event_type.clone(), json!(cnt));
        if event_type == "auth_failure" {
            auth_failures = *cnt;
        } else if event_type == "rate_limit" {
            rate_limit = *cnt;
        }
    }

    // The `_5m` suffixes are a lie whenever the caller passes `?minutes=` —
    // `?minutes=1440` returned a full day's count in a field named `_5m`, and
    // `metrics.rs` exports a genuinely-5-minute `noo_auth_failures_5m` from a
    // separate fixed-window query, so the two could disagree by 288x. Emit
    // window-neutral names as the truth; the `_5m` keys stay as deprecated
    // aliases for existing consumers and are only correct when minutes == 5.
    Ok(Json(json!({
        "auth_failures": auth_failures,
        "rate_limit": rate_limit,
        "events": events_5m,
        "window_minutes": minutes,
        "auth_failures_5m": auth_failures,
        "rate_limit_5m": rate_limit,
        "events_5m": events_5m,
    })))
}

/// GET /api/security/audit/verify
///
/// Recompute every `noo_security_audit` row's `entry_hash` under the key its
/// epoch was signed with — the retired `NOO_JWT_SECRET` derivation before the
/// audit-key checkpoint, `NOO_AUDIT_HMAC_KEY` after it — and name each row
/// that does not verify. Operator-only (or the stack's own services): the
/// answer lists row ids and says which keys this gateway holds.
async fn security_audit_verify(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> AppResult {
    if let Some(axum::Extension(r)) = &ctx {
        if r.role < crate::auth::Role::Operator {
            return Err(AppError::Forbidden(
                "audit verification is operator-only (Operator role or above)".into(),
            ));
        }
    }
    let report = crate::audit_integrity::verify_db(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("cannot read noo_security_audit: {e}")))?;
    Ok(Json(serde_json::to_value(report).map_err(|e| AppError::Internal(e.to_string()))?))
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Cleanup (undo a heartbeat-retention prune)
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct RestoreRunsRequest {
    /// Which prune tick to undo. Required and not defaulted: "restore
    /// everything staged" is not a thing an operator should be able to ask for
    /// by omission, and a prune tick is the only unit that can be reasoned
    /// about after the fact.
    prune_run_id: String,
}

/// Put back the run records staged by one `heartbeat_retention` prune.
///
/// Safe to call twice — the underlying INSERT is `ON CONFLICT DO NOTHING` and
/// only rows that actually came back are stamped `restored_at`.
///
/// Rows whose task has since been deleted are skipped rather than aborting the
/// batch (`noo_heartbeat_runs.task_id` cascades from `noo_heartbeat_tasks`), so
/// `restored` can legitimately be lower than what the prune reported. The
/// response says as much rather than leaving the caller to infer data loss.
async fn cleanup_restore_heartbeat_runs(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RestoreRunsRequest>,
) -> impl IntoResponse {
    if body.prune_run_id.trim().is_empty() {
        return Json(json!({ "error": "prune_run_id is required" })).into_response();
    }
    match crate::repo::heartbeat::restore_pruned_runs(&state.db, &body.prune_run_id).await {
        Ok(restored) => Json(json!({
            "prune_run_id": body.prune_run_id,
            "restored": restored,
            "note": "Rows whose heartbeat task has since been deleted are skipped \
                     and stay staged; restored may be lower than the number pruned.",
        })).into_response(),
        Err(e) => Json(json!({ "error": e.to_string() })).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Job Scheduler (Redis)
// ═══════════════════════════════════════════════════════════════

// Redis key constants — must match Python scheduler.py
const JOB_QUEUE_KEY: &str = "noo:jobs:queue";
pub(crate) const JOB_KEY_PREFIX: &str = "noo:jobs:";
pub(crate) const JOB_ACTIVE_SET: &str = "noo:jobs:active";
const JOB_HISTORY_KEY: &str = "noo:jobs:history";
const NODE_JOBS_PREFIX: &str = "noo:jobs:node:";

/// Terminal job states — jobs in these states cannot be cancelled.
const TERMINAL_STATES: &[&str] = &["completed", "cancelled", "dead"];

/// TTL applied to a job hash once it reaches a terminal state — must match
/// Python scheduler.py `JOB_TTL_AFTER_TERMINAL` (24h).
pub(crate) const JOB_TTL_AFTER_TERMINAL: i64 = 86400;

/// Canonical `noo:jobs:<id>` hash shape — must match Python
/// `scheduler.py::submit_job()` field for field. Python's reaper keys on
/// `status` + `dispatched_at` + `timeout_sec` + `retries`/`max_retries`,
/// its janitor on `status` + `node_id`, and `_record_history` reads `id`
/// (NOT `job_id` — that rename shipped history rows with `"id": null`).
/// Every Rust writer of this hash goes through `job_hash_pairs()` so the
/// shape lives in exactly one place; the shape-parity test at the bottom
/// of this file pins it against a fixture copied from the Python writer.
pub(crate) struct JobHashSpec<'a> {
    pub job_id: &'a str,
    pub job_type: &'a str,
    /// JSON-serialized payload (Python stores `json.dumps(payload)`).
    pub payload: &'a str,
    pub priority: i64,
    pub status: &'a str,
    /// Timestamp used for both `created_at` and `updated_at`.
    pub now: &'a str,
    /// "" for queued jobs (the dispatcher fills it at dispatch time);
    /// set to `now` for gateway-local jobs that start running immediately,
    /// otherwise Python's reaper skips them and a job whose completion
    /// task died hangs in `noo:jobs:active` forever.
    pub dispatched_at: &'a str,
    /// "" for queued jobs; "gateway" for gateway-local jobs. "gateway" is
    /// never in the node registry, so the janitor's dead-node requeue
    /// leaves these alone while node-set cleanup still works.
    pub node_id: &'a str,
    pub max_retries: i64,
    pub timeout_sec: i64,
    pub force_node: &'a str,
    pub min_vram_gb: f64,
    pub backend: &'a str,
}

/// Build the canonical job-hash field list from a spec.
pub(crate) fn job_hash_pairs(spec: &JobHashSpec<'_>) -> Vec<(&'static str, String)> {
    vec![
        ("id", spec.job_id.to_string()),
        ("type", spec.job_type.to_string()),
        ("payload", spec.payload.to_string()),
        ("priority", spec.priority.to_string()),
        ("status", spec.status.to_string()),
        ("created_at", spec.now.to_string()),
        ("updated_at", spec.now.to_string()),
        ("dispatched_at", spec.dispatched_at.to_string()),
        ("completed_at", String::new()),
        ("node_id", spec.node_id.to_string()),
        ("result", String::new()),
        ("error", String::new()),
        ("retries", "0".to_string()),
        ("max_retries", spec.max_retries.to_string()),
        ("timeout_sec", spec.timeout_sec.to_string()),
        ("force_node", spec.force_node.to_string()),
        ("min_vram_gb", spec.min_vram_gb.to_string()),
        ("backend", spec.backend.to_string()),
    ]
}

/// HSET the canonical pairs (plus optional Rust-only extras like `owner`).
pub(crate) async fn hset_job_hash(
    redis: &crate::cache::RedisCache,
    key: &str,
    pairs: &[(&'static str, String)],
    extras: &[(&str, &str)],
) -> bool {
    let mut refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    refs.extend_from_slice(extras);
    redis.hset(key, &refs).await
}

#[derive(Deserialize)]
pub(super) struct ListJobsParams {
    // pub(super) so routes/kiosk.rs can build one; the route still fills it
    // from the query string.
    pub(super) status: Option<String>,
    pub(super) node_id: Option<String>,
    pub(super) limit: Option<usize>,
    /// Whose jobs. NOT a query parameter — `serde(skip)`
    /// so a caller cannot name somebody else by typing `?scope=`; the route
    /// fills it from [`scoped_user`]. `None` = every job (Operator+ and
    /// internal cluster services), `Some(u)` = that account's own jobs plus
    /// the unowned ones.
    #[serde(skip)]
    pub(super) scope: Option<String>,
    /// A kiosk display token: also lists the unowned (fleet) jobs. `serde(skip)`
    /// like `scope`, set only by the route from the verified credential.
    #[serde(skip)]
    pub(super) fleet: bool,
}

/// Whether a job hash is visible to `scope`.
///
/// An EMPTY owner means unowned — every job queued before the `owner` field
/// shipped, plus the autonomy/heartbeat work no person submitted. That is
/// FLEET work: Operator+ (`scope == None`) sees and clears it, a User does not
/// see it at all (a 404 by id, absent from lists), so its payload never
/// reaches a User and an id never confirms that a fleet job exists.
///
/// `scope` is an ACCOUNT (`auth::scoped_account`) and the owner is compared by
/// account too, so a job submitted from one MCP session label
/// (`alice/codex-x`, also what rows written before the owner became the
/// account hold) is visible to every session of `alice`.
pub(crate) fn job_visible(owner: &str, scope: Option<&str>) -> bool {
    match scope {
        None => true,
        // A User sees ONLY its own account's jobs. Unowned work (autonomy,
        // heartbeat, cluster-HMAC, rows from before `owner` existed) is fleet
        // work: invisible, payload and all (by design: "Users
        // see and cancel only their own jobs").
        Some(me) => !owner.is_empty() && account_of(owner) == me,
    }
}

/// [`job_visible`] for the LIST route, plus the one deliberate exception: a
/// kiosk display token (a User-tier subject that is not a person) lists the
/// queue of the whole mesh, as the kiosk projection (`routes/kiosk.rs`)
/// already does unscoped. `fleet` is true only for such a token; it widens
/// nothing for a person.
pub(crate) fn job_listed(owner: &str, scope: Option<&str>, fleet: bool) -> bool {
    job_visible(owner, scope) || (fleet && owner.is_empty())
}

/// Whether the caller may CHANGE (cancel, reprioritize) the job. Stricter than
/// [`job_visible`] for exactly one case: an UNOWNED job (autonomy, heartbeat,
/// cluster-HMAC and pre-owner work, i.e. fleet jobs) is readable by anyone but
/// changeable only by Operator+ (`scope == None`). A User changes only a job
/// owned by its own account.
pub(crate) fn job_mutable_by(owner: &str, scope: Option<&str>) -> bool {
    match scope {
        None => true,
        Some(me) => !owner.is_empty() && account_of(owner) == me,
    }
}

/// List jobs with optional filters.
///
/// GET /api/jobs?status=queued&node_id=worker-1&limit=50
///
/// Reads the active set + queue sorted set from Redis, fetches each job
/// hash, applies filters, and returns sorted by created_at descending.
/// Mirrors Python `JobScheduler.list_jobs()`.
async fn list_jobs(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(mut params): Query<ListJobsParams>,
) -> AppResult {
    params.scope = scoped_account(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
    )
    .map_err(AppError::Forbidden)?;
    params.fleet = requester
        .as_ref()
        .is_some_and(|Extension(r)| r.scopes.iter().any(|s| s == crate::auth::KIOSK_SCOPE));
    Ok(Json(list_jobs_for(state, params).await))
}

/// The body of [`list_jobs`], callable without an extractor, so
/// `routes/kiosk.rs` can project this route's own answer instead of reading
/// Redis a second time.
pub(super) async fn list_jobs_for(state: Arc<AppState>, params: ListJobsParams) -> Value {
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return json!({"jobs": [], "count": 0, "error": "Redis not connected"}),
    };

    let limit = params.limit.unwrap_or(50).min(500);

    // Get active + queued job IDs (mirrors Python: active_ids | set(queued_ids))
    let active_ids = redis.smembers(JOB_ACTIVE_SET).await;
    let queued_ids = redis.zrange(JOB_QUEUE_KEY, 0, -1).await;

    let mut all_ids: std::collections::HashSet<String> = active_ids.into_iter().collect();
    for qid in queued_ids {
        all_ids.insert(qid);
    }

    let mut jobs: Vec<Value> = Vec::new();
    for jid in &all_ids {
        let key = format!("{JOB_KEY_PREFIX}{jid}");
        if let Some(map) = redis.hgetall(&key).await {
            // Apply filters
            if let Some(ref filter_status) = params.status {
                if map.get("status").map(|s| s.as_str()) != Some(filter_status.as_str()) {
                    continue;
                }
            }
            if let Some(ref filter_node) = params.node_id {
                if map.get("node_id").map(|s| s.as_str()) != Some(filter_node.as_str()) {
                    continue;
                }
            }
            // Ownership, applied where the other filters are so it cannot be
            // skipped by an early `continue` above it.
            if !job_listed(
                map.get("owner").map(|s| s.as_str()).unwrap_or(""),
                params.scope.as_deref(),
                params.fleet,
            ) {
                continue;
            }

            // A kiosk display (`fleet`) is a shared screen: it gets the job
            // without its payload.
            jobs.push(job_to_json(&map, params.fleet));
        }
    }

    // Sort by created_at descending (matches Python)
    jobs.sort_by(|a, b| {
        let a_ts = a.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        let b_ts = b.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        b_ts.cmp(a_ts)
    });

    let jobs: Vec<Value> = jobs.into_iter().take(limit).collect();
    let count = jobs.len();

    json!({"jobs": jobs, "count": count})
}

/// A job hash as JSON, deserializing the payload field (JSON if it parses,
/// else the raw string). `strip_payload` drops it altogether: a shared display
/// must not show what was asked of the fleet.
pub(crate) fn job_to_json(map: &std::collections::HashMap<String, String>, strip_payload: bool) -> Value {
    let mut job = serde_json::Map::new();
    for (k, v) in map {
        if k == "payload" {
            if strip_payload {
                continue;
            }
            match serde_json::from_str::<Value>(v) {
                Ok(parsed) => { job.insert(k.clone(), parsed); }
                Err(_) => { job.insert(k.clone(), json!(v)); }
            }
        } else {
            job.insert(k.clone(), json!(v));
        }
    }
    Value::Object(job)
}

#[derive(Deserialize)]
struct JobHistoryParams {
    limit: Option<i64>,
}

/// Get job history (completed/cancelled/failed jobs that survived TTL expiry).
///
/// GET /api/jobs/history?limit=50
///
/// Reads from Redis LIST `noo:jobs:history`. Each entry is a JSON string.
/// Mirrors Python `JobScheduler.get_job_history()`.
async fn job_history(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(params): Query<JobHistoryParams>,
) -> AppResult {
    let scope = scoped_account(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
    )
    .map_err(AppError::Forbidden)?;
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => {
            return Ok(Json(
                json!({"history": [], "count": 0, "error": "Redis not connected"}),
            ))
        }
    };

    let limit = params.limit.unwrap_or(50).min(500);

    // Read the window, THEN narrow: a User-tier caller sees at most `limit`
    // of their own entries, never somebody else's padding the page out.
    let raw = redis.lrange(JOB_HISTORY_KEY, 0, limit - 1).await;
    let history: Vec<Value> = raw
        .iter()
        .filter_map(|s| serde_json::from_str::<Value>(s).ok())
        .filter(|e| {
            job_visible(
                e.get("owner").and_then(|v| v.as_str()).unwrap_or(""),
                scope.as_deref(),
            )
        })
        .collect();
    let count = history.len();

    Ok(Json(json!({"history": history, "count": count})))
}

/// Get a single job by ID.
///
/// GET /api/jobs/{job_id}
///
/// Reads the job hash from Redis. Returns 404 if not found.
/// Mirrors Python `JobScheduler.get_job()`.
async fn get_job(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(job_id): Path<String>,
) -> AppResult {
    let scope = scoped_account(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
    )
    .map_err(AppError::Forbidden)?;
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Err(AppError::Internal("Redis not connected".into())),
    };

    let key = format!("{JOB_KEY_PREFIX}{job_id}");
    match redis.hgetall(&key).await {
        Some(map) => {
            // 404, not 403: the id is addressable, so a 403 would confirm
            // that somebody else's job exists. Same convention as the rest
            // of the id-addressed surface (`job_visible` decides it).
            if !job_visible(
                map.get("owner").map(|s| s.as_str()).unwrap_or(""),
                scope.as_deref(),
            ) {
                return Err(AppError::NotFound("Job not found".into()));
            }
            let mut job = serde_json::Map::new();
            for (k, v) in &map {
                if k == "payload" {
                    match serde_json::from_str::<Value>(v) {
                        Ok(parsed) => { job.insert(k.clone(), parsed); }
                        Err(_) => { job.insert(k.clone(), json!(v)); }
                    }
                } else {
                    job.insert(k.clone(), json!(v));
                }
            }
            Ok(Json(Value::Object(job)))
        }
        None => Err(AppError::NotFound("Job not found".into())),
    }
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Job Scheduler mutations (Redis)
// ═══════════════════════════════════════════════════════════════

/// Cancel a job.
///
/// DELETE /api/jobs/{job_id}
///
/// Sets job status to `cancelled`, removes from queue and active sets.
/// If the job was dispatched to a node, also removes from the node's job set
/// and publishes a cancellation event via NATS.
/// Mirrors Python `JobScheduler.cancel_job()`.
async fn cancel_job(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<AuthActor>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(job_id): Path<String>,
) -> AppResult {
    let scope = scoped_account(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
    )
    .map_err(AppError::Forbidden)?;
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Err(AppError::Internal("Redis not connected".into())),
    };

    let key = format!("{JOB_KEY_PREFIX}{job_id}");

    // Fetch current job state
    let map = match redis.hgetall(&key).await {
        Some(m) => m,
        None => return Err(AppError::NotFound("Job not found".into())),
    };

    // Ownership. Any write-scoped caller could previously cancel ANY job,
    // which matters now that multi-user is live. Rules, in order:
    //   - Operator and above (and internal cluster callers) → allow,
    //     operators must be able to clear the queue, unowned jobs included;
    //   - otherwise the caller's ACCOUNT must be the job's owner account. An
    //     unowned job (every job queued before the owner field shipped,
    //     autonomy and heartbeat work, cluster-submitted fleet jobs) is NOT
    //     cancellable by a User: the User tier can now reach this route.
    // Cluster-HMAC callers carry no AuthActor (auth.rs inserts one only on
    // the JWT path); they are internal and treated as privileged, same as
    // they already are for every other admin route.
    //
    // The privileged tier is `scoped_user`'s, i.e. Operator+, not Admin as
    // it was when this check was written on its own. The read side of the
    // same resource (`GET /api/jobs`, `GET /api/jobs/{id}`) hands the whole
    // queue to Operator+, so keeping cancel at Admin meant an Operator could
    // see a job it could not clear, and the two answers to "whose is this"
    // drifted apart. One helper now answers it for list, detail, history,
    // cancel and reprioritize.
    let owner = map.get("owner").map(|s| s.as_str()).unwrap_or("");
    let caller = actor.as_ref().map(|Extension(a)| a.0.as_str()).unwrap_or("cluster-internal");
    // A User may cancel only a job its own account owns: an UNOWNED job is
    // fleet work (fetch_bundle, model_download, autonomy), which `job_visible`
    // leaves readable but a User must not be able to kill.
    if !job_mutable_by(owner, scope.as_deref()) {
        tracing::warn!(%job_id, %caller, %owner, "job_cancel_denied_not_owner");
        crate::routes::core::audit_event(
            &state.db,
            "job_cancel_denied",
            "warning",
            caller,
            &job_id,
            "denied_not_owner",
            json!({"account": account_of(caller), "owner": owner}),
        )
        .await;
        // 404, matching `get_job`: a caller who cannot see the job must not
        // learn from the cancel route that it exists.
        return Err(AppError::NotFound("Job not found".into()));
    }

    // Check if already terminal
    let current_status = map.get("status").map(|s| s.as_str()).unwrap_or("");
    if TERMINAL_STATES.contains(&current_status) {
        return Err(AppError::BadRequest(
            format!("Job already in terminal state: {current_status}"),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();

    // Update job hash: status → cancelled
    redis.hset(&key, &[
        ("status", "cancelled"),
        ("updated_at", &now),
        ("completed_at", &now),
    ]).await;

    // Remove from queue (if still queued)
    redis.zrem(JOB_QUEUE_KEY, &job_id).await;

    // Remove from active set
    redis.srem(JOB_ACTIVE_SET, &job_id).await;

    // Remove from node's job set if dispatched
    let node_id = map.get("node_id").map(|s| s.as_str()).unwrap_or("");
    if !node_id.is_empty() {
        let node_key = format!("{NODE_JOBS_PREFIX}{node_id}");
        redis.srem(&node_key, &job_id).await;

        // Notify node via NATS (best-effort, non-blocking)
        // Python uses `publish_event("job.cancel", ...)` which maps to subject `events.job.cancel`
        let nats = state.nats.clone();
        let jid = job_id.clone();
        let nid = node_id.to_string();
        tokio::spawn(async move {
            let payload = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "type": "job.cancel",
                "data": {
                    "job_id": jid,
                    "node_id": nid,
                },
            });
            if let Ok(bytes) = serde_json::to_vec(&payload) {
                let _ = nats.publish("events.job.cancel", bytes.into()).await;
            }
        });
    }

    tracing::info!(job_id = %job_id, "job_cancelled");
    // Same rule as submit: the row attributes a person's cancel, not a cluster poke.
    if actor.is_some() {
    crate::routes::core::audit_event(
        &state.db,
        "job_cancel",
        "info",
        caller,
        &job_id,
        "cancelled",
        json!({
            "account": account_of(caller),
            "owner": owner,
            "prior_status": current_status,
            "node_id": node_id,
        }),
    )
    .await;
    }

    Ok(Json(json!({
        "job_id": job_id,
        "status": "cancelled",
    })))
}

#[derive(Deserialize)]
struct ReprioritizeRequest {
    priority: i64,
}

/// Change priority of a queued job.
///
/// POST /api/jobs/{job_id}/reprioritize
///
/// Updates the priority field in the job hash and the queue score.
/// Only works for jobs with status `queued`.
/// Mirrors Python `JobScheduler.reprioritize_job()`.
async fn reprioritize_job(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(job_id): Path<String>,
    Json(body): Json<ReprioritizeRequest>,
) -> AppResult {
    let scope = scoped_account(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
    )
    .map_err(AppError::Forbidden)?;
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Err(AppError::Internal("Redis not connected".into())),
    };

    let key = format!("{JOB_KEY_PREFIX}{job_id}");

    // Fetch current job state
    let map = match redis.hgetall(&key).await {
        Some(m) => m,
        None => return Err(AppError::NotFound("Job not found".into())),
    };

    // Ownership, same rule as cancel. This route had NO owner check at all:
    // a User-tier account could push any other tenant's job to the front of
    // the queue (or to the back of it), which is a denial-of-service on
    // somebody else's work even though it reads nothing.
    if !job_mutable_by(
        map.get("owner").map(|s| s.as_str()).unwrap_or(""),
        scope.as_deref(),
    ) {
        return Err(AppError::NotFound("Job not found".into()));
    }

    // Only queued jobs can be reprioritized
    let current_status = map.get("status").map(|s| s.as_str()).unwrap_or("");
    if current_status != "queued" {
        return Err(AppError::BadRequest(
            format!("Job not queued (status: {current_status})"),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let priority_str = body.priority.to_string();

    // Update job hash
    redis.hset(&key, &[
        ("priority", &priority_str),
        ("updated_at", &now),
    ]).await;

    // Update queue score (negative priority so higher priority pops first)
    redis.zadd(JOB_QUEUE_KEY, &job_id, -(body.priority as f64)).await;

    tracing::info!(job_id = %job_id, priority = body.priority, "job_reprioritized");

    Ok(Json(json!({
        "job_id": job_id,
        "priority": body.priority,
    })))
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Scheduler submit / status / controls (Redis)
// ═══════════════════════════════════════════════════════════════

// Redis keys for scheduler control flags — shared with Python scheduler.py
const SCHED_DRAINED_KEY: &str = "noo:jobs:drained_nodes";
const SCHED_PAUSED_KEY: &str = "noo:scheduler:paused";

#[derive(Deserialize)]
struct SubmitTaskRequest {
    #[serde(alias = "job_type")]
    r#type: Option<String>,
    payload: Option<Value>,
    priority: Option<i64>,
}

/// Submit a task to the scheduler queue.
///
/// POST /api/tasks/submit
///
/// Creates a job hash in Redis, adds to the priority queue (ZADD) and
/// active set (SADD). Mirrors Python `JobScheduler.submit_job()`.
async fn scheduler_submit_task(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<AuthActor>>,
    Json(body): Json<SubmitTaskRequest>,
) -> AppResult {
    let job_type = body.r#type.as_deref().unwrap_or("inference");
    let payload = body.payload.clone().unwrap_or(json!({}));
    let priority = body.priority.unwrap_or(5);

    if let Some(resp) = route_by_executor(&state, job_type, &payload).await? {
        return Ok(resp);
    }

    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Err(AppError::Internal("Redis not connected".into())),
    };
    // The owner is the ACCOUNT (`account_of`), not the session label.
    let owner = actor.as_ref().map(|Extension(a)| account_of(a.0.as_str())).unwrap_or("");

    let opts = JobOptions { owner, ..Default::default() };
    match submit_job_to_redis(redis, job_type, &payload, priority, opts).await {
        Some(job_id) => Ok(Json(json!({"job_id": job_id, "status": "queued"}))),
        None => Err(AppError::Internal("Failed to submit task to Redis".into())),
    }
}

/// Gate every user-facing submit on the authoritative job-type table.
///
/// Returns `Err` for a type nobody can execute (400, naming the valid
/// types), `Ok(Some(response))` when the type is gateway-local and has been
/// started in-process, and `Ok(None)` when the caller should carry on and
/// queue it for a node.
///
/// Before this gate, an unexecutable type was accepted, queued, dispatched
/// and left to rot until the reaper; and `test_run` — which only the
/// gateway can run — was dispatched to a node-agent that has no case for
/// it. Both failure modes are silent from the submitter's side, which is
/// why this is a rejection at submit rather than a log line later.
async fn route_by_executor(
    state: &Arc<AppState>,
    job_type: &str,
    payload: &Value,
) -> Result<Option<Json<Value>>, AppError> {
    match crate::job_types::executor_for(job_type) {
        None => Err(AppError::BadRequest(
            crate::job_types::unknown_type_error(job_type),
        )),
        Some(crate::job_types::Executor::Gateway) => {
            let job_id = run_gateway_local(state, job_type, payload).await;
            tracing::info!(job_id = %job_id, job_type, "job_submitted_gateway_local");
            Ok(Some(Json(json!({
                "job_id": job_id,
                "status": "running",
                "executor": "gateway",
            }))))
        }
        Some(crate::job_types::Executor::Node) => Ok(None),
    }
}

#[derive(Deserialize)]
struct SubmitJobRequest {
    #[serde(alias = "job_type")]
    r#type: Option<String>,
    payload: Option<Value>,
    priority: Option<i64>,
    backend: Option<String>,
    force_node: Option<String>,
    /// Per-job execution knobs. Python's `JobScheduler.submit_job()` has
    /// always accepted these; the Rust route used to hardcode them and
    /// silently ignore whatever the body sent, so a caller asking for a
    /// 30-minute job still got killed at the 300s default.
    timeout_sec: Option<i64>,
    max_retries: Option<i64>,
    min_vram_gb: Option<f64>,
    /// Queue a job whose `backend` no node is serving yet (it will wait for
    /// one to come up). Off by default: such a job used to be queued and die.
    #[serde(default)]
    allow_queue_without_backend: bool,
    /// Give up on the job if it is still QUEUED this many seconds after
    /// submit: the janitor flips it `dead` with an "expired" reason. For
    /// work that is worthless late — `noo provision`'s fetch poke is only
    /// useful inside the CLI's own wait window. Unset = the scheduler-wide
    /// bound (`scheduler_engine::QUEUED_MAX_AGE_SECS`).
    expire_after_sec: Option<i64>,
}

/// Optional job knobs, mirroring the defaults in Python
/// `JobScheduler.submit_job()` (`src/noomesh/cluster/scheduler.py:131-168`).
///
/// Grouped into a struct rather than added as positional parameters: the
/// shared writer already took 6 arguments and every extra `None, None` at a
/// call site is a chance to silently transpose two of them.
pub(crate) struct JobOptions<'a> {
    pub backend: Option<&'a str>,
    pub force_node: Option<&'a str>,
    pub timeout_sec: i64,
    pub max_retries: i64,
    pub min_vram_gb: f64,
    /// Identity that submitted the job, used by `cancel_job` for ownership.
    /// Empty string = unattributable (internal submitter with no actor).
    pub owner: &'a str,
    /// Seconds after submit at which a still-queued job expires (written as
    /// `expires_at`). None = only the scheduler-wide queued-age bound.
    pub expire_after_sec: Option<i64>,
}

impl Default for JobOptions<'_> {
    fn default() -> Self {
        Self {
            backend: None,
            force_node: None,
            timeout_sec: 300,
            max_retries: 2,
            min_vram_gb: 0.0,
            owner: "",
            expire_after_sec: None,
        }
    }
}

/// How long a caller of `/api/jobs/submit` is told to wait when the gateway
/// has no Redis client.
pub(crate) const REDIS_RETRY_AFTER_SECS: u64 = 5;

/// The refusal `/api/jobs/submit` answers while the gateway holds no Redis
/// client: 503 + `Retry-After` + `{"error":"redis_reconnecting"}`, never a
/// bare 500. The queue IS Redis, so nothing can be queued; the caller (the
/// CLI's node poke during `noo upgrade --all`) retries on the code.
///
/// NOTE: today the client is made once, at boot (`state.rs`): a gateway that
/// came up before Redis accepted connections keeps answering this until it
/// is restarted. The code says "reconnecting" because that is what a caller
/// should do about it (wait and retry), and because a reconnecting client is
/// the fix this body is shaped for.
pub(crate) fn redis_not_connected() -> AppError {
    AppError::UnavailableRetry {
        code: "redis_reconnecting",
        detail: "Redis not connected: the job queue is unavailable until the gateway's Redis client connects".into(),
        retry_after_secs: REDIS_RETRY_AFTER_SECS,
    }
}

/// Submit a job to the scheduler queue (full form with backend/force_node).
///
/// POST /api/jobs/submit
///
/// Creates a job hash in Redis, adds to the priority queue (ZADD) and
/// active set (SADD). Mirrors Python `JobScheduler.submit_job()`.
async fn scheduler_submit_job(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<AuthActor>>,
    requester: Option<Extension<RequesterCtx>>,
    Json(body): Json<SubmitJobRequest>,
) -> AppResult {
    let job_type = body.r#type.as_deref().unwrap_or("inference");
    let payload = body.payload.clone().unwrap_or(json!({}));
    let mut priority = body.priority.unwrap_or(5);
    let actor_sub = actor.as_ref().map(|Extension(a)| a.0.as_str()).unwrap_or("cluster-internal");
    // The owner is the ACCOUNT, so every session of the same person sees and
    // can cancel the job. Empty = unattributable internal submitter.
    let owner = actor.as_ref().map(|Extension(a)| account_of(a.0.as_str())).unwrap_or("");
    // No requester = cluster-HMAC caller: internal, privileged, as before.
    let restricted = requester.as_ref().is_some_and(|Extension(r)| r.role < crate::auth::Role::Operator);
    let audit = |outcome: &'static str, severity: &'static str, extra: Value| {
        let db = state.db.clone();
        let sub = actor_sub.to_string();
        let account = account_of(actor_sub).to_string();
        let jt = job_type.to_string();
        // Cluster-HMAC callers (provisioning, autonomy) carry no identity to
        // attribute and are high-volume: the audit row records PEOPLE's submits.
        let attributable = actor.is_some();
        async move {
            if !attributable {
                return;
            }
            let mut d = json!({"account": account, "type": jt});
            if let (Some(o), Some(e)) = (d.as_object_mut(), extra.as_object()) {
                for (k, v) in e { o.insert(k.clone(), v.clone()); }
            }
            let resource = d.get("job_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            crate::routes::core::audit_event(&db, "job_submit", severity, &sub, &resource, outcome, d).await;
        }
    };

    let mut knobs = (body.timeout_sec, body.max_retries, body.expire_after_sec);
    if restricted {
        if let Err(e) = user_submit_refusal(
            job_type,
            &payload,
            body.backend.as_deref(),
            body.force_node.as_deref(),
            body.min_vram_gb,
            body.allow_queue_without_backend,
        ) {
            audit("rejected", "warning", json!({"reason": e.to_string(), "priority": priority})).await;
            return Err(e);
        }
        let (p, k) = clamp_user_job_knobs(priority, knobs.0, knobs.1, knobs.2);
        priority = p;
        knobs = k;
        // AFTER validation: a refused request is not charged to the quota.
        let Some(redis) = state.redis.as_ref() else {
            return Err(redis_not_connected());
        };
        match redis
            .check_named_limit("job-submit", account_of(actor_sub), USER_JOB_SUBMITS_PER_WINDOW, USER_JOB_SUBMIT_WINDOW_SECS)
            .await
        {
            Ok(crate::cache::RateResult::Allowed { .. }) => {}
            Ok(crate::cache::RateResult::Limited { retry_after }) => {
                audit("rate_limited", "warning", json!({"retry_after_secs": retry_after, "priority": priority})).await;
                return Err(AppError::TooManyRequests {
                    msg: format!(
                        "job submit limit reached: {USER_JOB_SUBMITS_PER_WINDOW} jobs per hour per account"
                    ),
                    retry_after_secs: retry_after.max(1) as u64,
                });
            }
            // Fail closed: the quota is the control that makes this door safe.
            Err(e) => {
                tracing::error!(error = %e, "job_submit_rate_limit_unavailable");
                return Err(AppError::Unavailable("job submit limiter unavailable; try again".into()));
            }
        }
    }

    if let Some(resp) = route_by_executor(&state, job_type, &payload).await? {
        audit("gateway_local", "info", json!({"priority": priority})).await;
        return Ok(resp);
    }

    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Err(redis_not_connected()),
    };
    // refuse a job that names a backend nobody is serving
    // instead of queuing it to die. A pinned job is the operator's call.
    if let Some(b) = body.backend.as_deref().filter(|b| !b.is_empty()) {
        if body.force_node.is_none() && !body.allow_queue_without_backend {
            let nodes = crate::scheduler_engine::load_nodes(&state).await;
            if let Some(reason) = crate::scheduler_candidates::backend_unserved_reason(&nodes, b) {
                return Err(AppError::BadRequest(format!(
                    "{reason}. Or set allow_queue_without_backend=true to wait for one"
                )));
            }
        }
    }
    let defaults = JobOptions::default();

    let opts = JobOptions {
        backend: body.backend.as_deref(),
        force_node: body.force_node.as_deref(),
        // Clamp rather than trust: a zero/negative timeout would make the
        // reaper treat the job as instantly expired.
        timeout_sec: knobs.0.filter(|v| *v > 0).unwrap_or(defaults.timeout_sec),
        max_retries: knobs.1.filter(|v| *v >= 0).unwrap_or(defaults.max_retries),
        min_vram_gb: body.min_vram_gb.filter(|v| *v >= 0.0).unwrap_or(defaults.min_vram_gb),
        owner,
        expire_after_sec: knobs.2.filter(|v| *v > 0),
    };

    match submit_job_to_redis(redis, job_type, &payload, priority, opts).await {
        Some(job_id) => {
            audit("queued", "info", json!({"job_id": job_id, "priority": priority, "backend": body.backend, "force_node": body.force_node})).await;
            Ok(Json(json!({"job_id": job_id, "status": "queued"})))
        }
        None => Err(AppError::Internal("Failed to submit job to Redis".into())),
    }
}

/// Job types a User-tier account may submit: non-destructive, no side effects
/// on a node beyond running inference. `tool_exec` (arbitrary tool run),
/// `model_download`/`model_file`/`fetch_bundle` (fleet mutation, disk, network),
/// `background_*` (maintenance) and gateway-local `test_run` are operator work.
pub(crate) const USER_JOB_TYPES: &[&str] = &["inference"];
/// Backends a User may prefer. A `force_node` pin is not allowed at all.
const USER_JOB_BACKENDS: &[&str] = &["vllm", "ollama", "llamacpp"];
/// Serialized payload cap for a User submit.
pub(crate) const USER_JOB_PAYLOAD_MAX_BYTES: usize = 64 * 1024;
const USER_JOB_PRIORITY_MAX: i64 = 5;
const USER_JOB_TIMEOUT_MAX_SECS: i64 = 600;
const USER_JOB_RETRIES_MAX: i64 = 2;
const USER_JOB_EXPIRE_MAX_SECS: i64 = 3600;
/// Per-account submit quota (Redis fixed window, ns `job-submit`).
pub(crate) const USER_JOB_SUBMITS_PER_WINDOW: i64 = 30;
pub(crate) const USER_JOB_SUBMIT_WINDOW_SECS: i64 = 3600;

/// Why a User-tier submit is refused, or `Ok(())`. Runs BEFORE
/// `route_by_executor`, so a gateway-local type (`test_run`) never starts.
pub(crate) fn user_submit_refusal(
    job_type: &str,
    payload: &Value,
    backend: Option<&str>,
    force_node: Option<&str>,
    min_vram_gb: Option<f64>,
    allow_queue_without_backend: bool,
) -> Result<(), AppError> {
    if !USER_JOB_TYPES.contains(&job_type) {
        return Err(AppError::Forbidden(format!(
            "job type '{job_type}' is operator-only; a user account may submit: {}",
            USER_JOB_TYPES.join(", ")
        )));
    }
    if !payload.is_object() {
        return Err(AppError::BadRequest("payload must be a JSON object".into()));
    }
    let size = serde_json::to_string(payload).map(|s| s.len()).unwrap_or(usize::MAX);
    if size > USER_JOB_PAYLOAD_MAX_BYTES {
        return Err(AppError::BadRequest(format!(
            "payload is {size} bytes; the limit is {USER_JOB_PAYLOAD_MAX_BYTES}"
        )));
    }
    if let Some(b) = backend.filter(|b| !b.is_empty()) {
        if !USER_JOB_BACKENDS.contains(&b) {
            return Err(AppError::BadRequest(format!(
                "backend '{b}' is not allowed; use one of: {}",
                USER_JOB_BACKENDS.join(", ")
            )));
        }
    }
    if force_node.is_some_and(|n| !n.is_empty()) {
        return Err(AppError::Forbidden("force_node is operator-only".into()));
    }
    if min_vram_gb.is_some_and(|v| v > 0.0) {
        return Err(AppError::Forbidden("min_vram_gb is operator-only".into()));
    }
    if allow_queue_without_backend {
        return Err(AppError::Forbidden("allow_queue_without_backend is operator-only".into()));
    }
    Ok(())
}

/// Clamp a User's execution knobs: `(priority, (timeout, retries, expire))`.
pub(crate) fn clamp_user_job_knobs(
    priority: i64,
    timeout_sec: Option<i64>,
    max_retries: Option<i64>,
    expire_after_sec: Option<i64>,
) -> (i64, (Option<i64>, Option<i64>, Option<i64>)) {
    (
        priority.clamp(0, USER_JOB_PRIORITY_MAX),
        (
            timeout_sec.map(|v| v.min(USER_JOB_TIMEOUT_MAX_SECS)),
            max_retries.map(|v| v.min(USER_JOB_RETRIES_MAX)),
            expire_after_sec.map(|v| v.min(USER_JOB_EXPIRE_MAX_SECS)),
        ),
    )
}

/// Shared implementation for submit_task and submit_job.
///
/// Creates the full job hash (matching Python scheduler.py field layout),
/// adds to priority queue and active set.
pub(crate) async fn submit_job_to_redis(
    redis: &crate::cache::RedisCache,
    job_type: &str,
    payload: &Value,
    priority: i64,
    opts: JobOptions<'_>,
) -> Option<String> {
    // This is the only writer of the node dispatch queue, so it is also the
    // right place to fail closed: a type no node-agent can execute must not
    // enter the queue at all, whoever the submitter is (routes, autonomy
    // evaluators, future internal callers). The routes reject earlier with a
    // 400 that names the valid types; this catches everyone else.
    if crate::job_types::executor_for(job_type) != Some(crate::job_types::Executor::Node) {
        tracing::error!(job_type, "scheduler_submit_rejected_not_node_executable");
        return None;
    }

    let job_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let payload_str = serde_json::to_string(payload).unwrap_or_default();

    let key = format!("{JOB_KEY_PREFIX}{job_id}");

    // Store the full job record as a hash (canonical shape — see JobHashSpec)
    let pairs = job_hash_pairs(&JobHashSpec {
        job_id: &job_id,
        job_type,
        payload: &payload_str,
        priority,
        status: "queued",
        now: &now,
        dispatched_at: "",
        node_id: "",
        max_retries: opts.max_retries,
        timeout_sec: opts.timeout_sec,
        force_node: opts.force_node.unwrap_or(""),
        min_vram_gb: opts.min_vram_gb,
        backend: opts.backend.unwrap_or(""),
    });
    // `owner`: who submitted this (Rust-only extra field). Empty for internal
    // submitters with no actor (autonomy evaluators, cluster-HMAC callers) —
    // `cancel_job` treats an empty owner as unowned so pre-existing jobs stay
    // cancellable.
    // `expires_at` (Rust-only extra, like `owner`): when the janitor gives
    // up on this job if it is still queued. Absent = the scheduler-wide
    // queued-age bound only.
    let expires_at = opts
        .expire_after_sec
        .map(|secs| (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339())
        .unwrap_or_default();
    let mut extras: Vec<(&str, &str)> = vec![("owner", opts.owner)];
    if !expires_at.is_empty() {
        extras.push(("expires_at", expires_at.as_str()));
    }
    let ok = hset_job_hash(redis, &key, &pairs, &extras).await;

    if !ok {
        tracing::error!(job_id = %job_id, "scheduler_submit_hset_failed");
        return None;
    }

    // Add to priority queue (score = -priority so higher priority pops first)
    redis.zadd(JOB_QUEUE_KEY, &job_id, -(priority as f64)).await;

    // Track in active set
    redis.sadd(JOB_ACTIVE_SET, &job_id).await;

    tracing::info!(job_id = %job_id, job_type = %job_type, priority = priority, "job_submitted");

    Some(job_id)
}

/// Whether the dispatch loop is actually running, and how we know.
///
/// This used to be a literal `true`, which claimed a fact the gateway had not
/// checked. Dispatch is unconditionally this
/// process's `scheduler_engine` loop, so the answer comes from `loop_health`
/// — which reports `null` until the loop has actually ticked rather than
/// asserting liveness it has not observed.
///
/// Returns `(engine, running, detail)`.
fn scheduler_running() -> (&'static str, Option<bool>, String) {
    let (running, detail) = crate::loop_health::liveness("scheduler_dispatch");
    ("rust", running, detail)
}

/// Get scheduler status.
///
/// GET /api/scheduler/status
///
/// Reads queue depth, active job count, drained nodes, background queue
/// depth, and history size from Redis. Paused flag is read from a Redis
/// key (noo:scheduler:paused). Mirrors Python `JobScheduler.get_status()`.
pub(crate) async fn scheduler_status(
    State(state): State<Arc<AppState>>,
) -> AppJson {
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Json(json!({"error": "Redis not connected"})),
    };

    let queue_depth = redis.zcard(JOB_QUEUE_KEY).await;
    let active_jobs = redis.scard(JOB_ACTIVE_SET).await;
    let drained_nodes = redis.smembers(SCHED_DRAINED_KEY).await;
    let history_size = redis.llen(JOB_HISTORY_KEY).await;

    // Background jobs in queue (score = 0, meaning priority = 0 → -0 = 0)
    let bg_queued = redis.zrangebyscore(JOB_QUEUE_KEY, 0.0, 0.0).await;
    let bg_queue_depth = bg_queued.len();

    // Paused flag from Redis (set by scheduler_pause/resume)
    let paused = redis.get_string(SCHED_PAUSED_KEY).await
        .map(|v| v == "1")
        .unwrap_or(false);

    let (engine, running, running_detail) = scheduler_running();

    Json(json!({
        "engine": engine,
        "running": running,
        "running_detail": running_detail,
        "paused": paused,
        "queue_depth": queue_depth,
        "active_jobs": active_jobs,
        "drained_nodes": drained_nodes,
        "background_queue_depth": bg_queue_depth,
        "history_size": history_size,
    }))
}

/// Pause the scheduler — no new jobs will be dispatched.
///
/// POST /api/scheduler/pause
///
/// Sets Redis flag `noo:scheduler:paused` = "1". The Python dispatch loop
/// checks this key and skips dispatching when set.
async fn scheduler_pause(
    State(state): State<Arc<AppState>>,
) -> AppJson {
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Json(json!({"error": "Redis not connected"})),
    };

    redis.set_string(SCHED_PAUSED_KEY, "1").await;
    tracing::info!("scheduler_paused");

    Json(json!({"status": "paused"}))
}

/// Resume the scheduler — allow dispatching again.
///
/// POST /api/scheduler/resume
///
/// Deletes the Redis flag `noo:scheduler:paused`.
async fn scheduler_resume(
    State(state): State<Arc<AppState>>,
) -> AppJson {
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Json(json!({"error": "Redis not connected"})),
    };

    redis.del_key(SCHED_PAUSED_KEY).await;
    tracing::info!("scheduler_resumed");

    Json(json!({"status": "resumed"}))
}

/// Drain a node — prevent new jobs from being dispatched to it.
///
/// POST /api/scheduler/drain/{node_id}
///
/// Adds node_id to the Redis SET `noo:jobs:drained_nodes`.
/// Mirrors Python `JobScheduler.drain_node()`.
async fn scheduler_drain(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> AppJson {
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Json(json!({"error": "Redis not connected"})),
    };

    if node_id.is_empty() {
        return Json(json!({"error": "Missing node_id"}));
    }

    redis.sadd(SCHED_DRAINED_KEY, &node_id).await;
    tracing::info!(node_id = %node_id, "node_drained");

    Json(json!({"status": "drained", "node_id": node_id}))
}

/// Undrain a node — allow new jobs to be dispatched to it again.
///
/// POST /api/scheduler/undrain/{node_id}
///
/// Removes node_id from the Redis SET `noo:jobs:drained_nodes`.
/// Mirrors Python `JobScheduler.undrain_node()`.
async fn scheduler_undrain(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> AppJson {
    let redis = match state.redis.as_ref() {
        Some(r) => r,
        None => return Json(json!({"error": "Redis not connected"})),
    };

    if node_id.is_empty() {
        return Json(json!({"error": "Missing node_id"}));
    }

    redis.srem(SCHED_DRAINED_KEY, &node_id).await;
    tracing::info!(node_id = %node_id, "node_undrained");

    Json(json!({"status": "undrained", "node_id": node_id}))
}


// ═══════════════════════════════════════════════════════════════
// Native handlers — Test runner (filesystem + subprocess)
// ═══════════════════════════════════════════════════════════════

/// Return the most recent test results.
///
/// GET /api/tests/status
///
/// Reads the latest pytest results from `.test-results.json` (written
/// by `noo test run`) or from the database test_results table.
async fn tests_status(
    State(state): State<Arc<AppState>>,
) -> AppJson {
    // Try filesystem first — pytest writes results here
    let results_paths = [
        ".test-results.json",
        "test-results.json",
        "/data/test-results.json",
    ];

    for path in &results_paths {
        if let Ok(contents) = tokio::fs::read_to_string(path).await {
            if let Ok(data) = serde_json::from_str::<Value>(&contents) {
                return Json(json!({
                    "status": "available",
                    "source": "filesystem",
                    "path": path,
                    "results": data,
                    "engine": "rust",
                }));
            }
        }
    }

    // Fallback: check database for test results
    match sqlx::query_as::<_, (Value,)>(
        "SELECT row_to_json(t)::jsonb FROM (
            SELECT * FROM test_results ORDER BY created_at DESC LIMIT 10
        ) t"
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) if !rows.is_empty() => {
            let results: Vec<Value> = rows.into_iter().map(|r| r.0).collect();
            Json(json!({
                "status": "available",
                "source": "database",
                "results": results,
                "engine": "rust",
            }))
        }
        _ => {
            Json(json!({
                "status": "no_results",
                "message": "No test results found. Run tests with POST /api/tests/run",
                "engine": "rust",
            }))
        }
    }
}

/// Run the test suite as a background process.
///
/// POST /api/tests/run
///
/// Body: `{"suite": "unit"}` (optional — empty runs all tests)
///
/// Spawns pytest in the background and returns a job ID immediately.
/// Results are written to `.test-results.json` and stored in Redis.
async fn tests_run(
    State(state): State<Arc<AppState>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let body = body.map(|b| b.0).unwrap_or(json!({}));
    let suite = suite_from_payload(&body);
    let job_id = spawn_test_run(&state, suite).await;

    Ok(Json(json!({
        "status": "accepted",
        "job_id": job_id,
        "message": format!("Test run started in background{}",
            if suite.is_empty() { String::new() } else { format!(" (suite: {suite})") }),
        "engine": "rust",
    })))
}

/// Extract the pytest `-k` selector from either shape callers use:
/// `{"suite": …}` (the route body) or `{"params": {"suite": …}}`.
fn suite_from_payload(body: &Value) -> &str {
    body.get("suite")
        .or_else(|| body.get("params").and_then(|p| p.get("suite")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// Execute a gateway-local job type in this process.
///
/// The counterpart of dispatching to a node: `job_types::Executor::Gateway`
/// types never go on `tasks.dispatch.*`, because no node-agent has a case
/// for them. Returns the job id.
///
/// Adding a `Gateway` row to `job_types::JOB_TYPES` requires an arm here —
/// the `unreachable` arm is the reminder.
pub(crate) async fn run_gateway_local(
    state: &Arc<AppState>,
    job_type: &str,
    payload: &Value,
) -> String {
    match job_type {
        "test_run" => spawn_test_run(state, suite_from_payload(payload)).await,
        other => unreachable!("no gateway-local executor for job type '{other}'"),
    }
}

/// Record and start a `test_run` job. Returns the job id immediately; the
/// pytest process runs in a detached tokio task that writes the terminal
/// status back to the job hash.
async fn spawn_test_run(state: &Arc<AppState>, suite: &str) -> String {
    let job_id = uuid::Uuid::new_v4().to_string();
    let job_id_clone = job_id.clone();

    // Record job. Gateway-local: it runs here as a tokio task, not on a node,
    // so max_retries=0 — a Python requeue would hand this job to a node-agent
    // that cannot run it; instead the reaper marks a hung run dead once
    // timeout_sec elapses (dispatched_at/node_id make it reaper-visible).
    let now = chrono::Utc::now().to_rfc3339();
    const TESTS_TIMEOUT_SEC: i64 = 3600;
    if let Some(redis) = state.redis.as_ref() {
        let key = format!("{JOB_KEY_PREFIX}{job_id}");
        let payload = json!({"suite": suite}).to_string();
        let pairs = job_hash_pairs(&JobHashSpec {
            job_id: &job_id,
            job_type: "test_run",
            payload: &payload,
            priority: 5,
            status: "running",
            now: &now,
            dispatched_at: &now,
            node_id: "gateway",
            max_retries: 0,
            timeout_sec: TESTS_TIMEOUT_SEC,
            force_node: "",
            min_vram_gb: 0.0,
            backend: "",
        });
        let _ = hset_job_hash(redis, &key, &pairs, &[]).await;
        // Defensive TTL: if this process dies before the completion write
        // below, nothing else ever touches this hash (Python only EXPIREs
        // terminal jobs it observes). Terminal write refreshes it to the
        // standard 24h.
        let _ = redis.expire(&key, TESTS_TIMEOUT_SEC + JOB_TTL_AFTER_TERMINAL).await;
        let _ = redis.sadd(JOB_ACTIVE_SET, &job_id).await;
    }

    // Build pytest command
    let mut cmd_args = vec!["-m", "pytest", "--tb=short", "-q"];
    if !suite.is_empty() {
        cmd_args.push("-k");
        cmd_args.push(suite);
    }
    // Write JSON results
    cmd_args.push("--json-report");
    cmd_args.push("--json-report-file=.test-results.json");

    let cmd_args_owned: Vec<String> = cmd_args.iter().map(|s| s.to_string()).collect();

    let state_bg = state.clone();
    tokio::spawn(async move {
        let python = std::env::var("PYTHON_BIN").unwrap_or_else(|_| "python3".into());
        tracing::info!(job_id = %job_id_clone, "tests: spawning pytest");

        let result = tokio::process::Command::new(&python)
            .args(&cmd_args_owned)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await;

        let (status, summary) = match result {
            Ok(output) => {
                let status = if output.status.success() { "completed" } else { "failed" };
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Extract summary line (last non-empty line of pytest output)
                let summary = stdout.lines().rev().find(|l| !l.trim().is_empty())
                    .unwrap_or("no output").to_string();
                (status, summary)
            }
            Err(e) => ("failed", format!("Failed to spawn pytest: {e}")),
        };

        tracing::info!(job_id = %job_id_clone, status, "tests: finished");

        if let Some(redis) = state_bg.redis.as_ref() {
            let done_at = chrono::Utc::now().to_rfc3339();
            let key = format!("{JOB_KEY_PREFIX}{job_id_clone}");
            let error = if status == "failed" { summary.as_str() } else { "" };
            let _ = redis.hset(&key, &[
                ("status", status),
                ("completed_at", &done_at),
                ("updated_at", &done_at),
                ("result", &summary),
                ("error", error),
            ]).await;
            // Mirror Python's terminal EXPIRE semantics (JOB_TTL_AFTER_TERMINAL).
            let _ = redis.expire(&key, JOB_TTL_AFTER_TERMINAL).await;
            let _ = redis.srem(JOB_ACTIVE_SET, &job_id_clone).await;
        }
    });

    job_id
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Security violations (Redis counters)
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct ViolationParams {
    period_hours: Option<i64>,
}

/// GET /api/security/violations — return violation stats.
///
/// Reads from Redis counter keys matching the Python SecurityManager format.
/// If Redis is unavailable or no counters exist, returns sensible defaults.
/// Matches Python response: {violations: {...}, risk_level, period_hours}.
async fn security_violations(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Query(params): Query<ViolationParams>,
) -> AppResult {
    super::operator_read_guard(&ctx)?;
    let period_hours = params.period_hours.unwrap_or(24);

    // Try to read violation counters from Redis (matching Python SecurityManager keys)
    let mut stats = serde_json::Map::new();
    let mut total: i64 = 0;

    if let Some(redis) = state.redis.as_ref() {
        // Counters written by the Rust request path (see
        // cache.rs::record_security_violation): the rate-limit middleware
        // bumps `rate_limit` on 429s and `before_tool_call` bumps the
        // sanitiser types on blocked tool input. Keys carry a 24h TTL, so
        // these are "last 24h" counts regardless of the period_hours param.
        // `blocked_file` is kept for Python response-shape parity but has no
        // Rust writer yet (file-extension blocking lives in Python security.py,
        // which tracks its events in process memory, not Redis).
        let violation_types = [
            "rate_limit", "path_traversal", "shell_meta", "sql_injection",
            "xss", "blocked_file", "dangerous_code", "input_limit",
        ];
        for vtype in &violation_types {
            let key = format!("noo:security:violations:{vtype}");
            let count: i64 = redis.get_string(&key).await
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            // Map "rate_limit" to "violations" for compatibility with Python response format
            let stat_key = if *vtype == "rate_limit" { "violations" } else { vtype };
            stats.insert(stat_key.to_string(), json!(count));
            total += count;
        }
    } else {
        stats.insert("violations".to_string(), json!(0));
        stats.insert("path_traversal".to_string(), json!(0));
        stats.insert("shell_meta".to_string(), json!(0));
        stats.insert("sql_injection".to_string(), json!(0));
        stats.insert("xss".to_string(), json!(0));
        stats.insert("blocked_file".to_string(), json!(0));
        stats.insert("dangerous_code".to_string(), json!(0));
        stats.insert("input_limit".to_string(), json!(0));
    }

    stats.insert("total".to_string(), json!(total));

    let risk_level = if total < 5 { "LOW" } else if total < 15 { "MEDIUM" } else { "HIGH" };

    Ok(Json(json!({
        "violations": stats,
        "risk_level": risk_level,
        "period_hours": period_hours,
    })))
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — PKI status (filesystem)
// ═══════════════════════════════════════════════════════════════

/// POST /api/security/pki/rotate-expiring — queue a host-side leaf-cert
/// rotation on the watcher spool. Port of the Python
/// `worker.security.pki_rotate` handler (response shape preserved):
/// rotation MUST happen host-side — the CA key is 0600 operator-only and
/// only the watcher's rotate carries the closed loop (backup→rotate→
/// reload→probe→auto-revert). Returns quickly with `queued: true`; a fast
/// outcome ("nothing expiring") is merged in if the result file lands
/// within the 40s poll, otherwise the rotation reports via the result
/// file after this returns.
async fn security_pki_rotate_expiring() -> AppJson {
    if std::env::var("NOO_PKI_DIR").unwrap_or_default().is_empty() {
        return Json(json!({"error": "NOO_PKI_DIR not configured"}));
    }

    let path = match host_spool_write_command("rotate", "pki", &[], "security_pki_rotate").await {
        Some(p) => p,
        None => {
            return Json(json!({
                "error": "could not queue rotation (host spool unavailable — \
                          is noo-hostd running? systemctl --user status noo-hostd)"
            }))
        }
    };

    let cmd_path = std::path::PathBuf::from(&path);
    let result_path = cmd_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".cmd.json"))
        .map(|stem| {
            cmd_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(format!("{stem}.result.json"))
        });

    if let Some(result_path) = result_path {
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if result_path.exists() {
                if let Ok(body) = tokio::fs::read_to_string(&result_path).await {
                    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&body) {
                        let mut out = serde_json::Map::new();
                        out.insert("queued".into(), json!(true));
                        out.insert("completed".into(), json!(true));
                        out.extend(map);
                        return Json(Value::Object(out));
                    }
                }
                break;
            }
        }
        return Json(json!({
            "queued": true,
            "completed": false,
            "note": format!(
                "rotation running host-side (backup→rotate→reload→probe→\
                 auto-revert); result will land at {}",
                result_path.display()
            ),
        }));
    }
    Json(json!({"queued": true, "completed": false}))
}

/// GET /api/security/pki/status — read PKI certificate files and check expiry.
///
/// Reads the cluster CA and gateway cert from NOO_PKI_DIR (default
/// ~/.config/mesh/pki). Reports existence, subject, issuer, and
/// not_after for each cert found. Matches the Python pki.manager
/// get_status() response shape.
async fn security_pki_status(ctx: Option<Extension<RequesterCtx>>) -> AppResult {
    super::operator_read_guard(&ctx)?;
    let pki_dir = std::env::var("NOO_PKI_DIR")
        .ok()
        .filter(|p| std::path::Path::new(p).join("ca.crt").exists())
        .or_else(|| {
            // Check common Docker container paths (entrypoint.py copies to /tmp/pki)
            ["/tmp/pki", "/app/pki"].iter()
                .find(|p| std::path::Path::new(p).join("ca.crt").exists())
                .map(|p| p.to_string())
        })
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            format!("{home}/.config/mesh/pki")
        });

    let pki_path = std::path::Path::new(&pki_dir);
    if !pki_path.exists() || !pki_path.join("ca.crt").exists() {
        return Ok(Json(json!({"status": "not_initialized"})));
    }

    let ca_cert_path = pki_path.join("ca.crt");
    let gw_cert_path = pki_path.join("gateway").join("gateway.crt");

    let mut certs = serde_json::Map::new();

    // Check CA cert
    if ca_cert_path.exists() {
        certs.insert("ca".into(), cert_file_info(&ca_cert_path).await);
    }

    // Check gateway cert
    if gw_cert_path.exists() {
        certs.insert("gateway".into(), cert_file_info(&gw_cert_path).await);
    }

    // Scan node certs
    let nodes_dir = pki_path.join("nodes");
    if nodes_dir.exists() {
        if let Ok(mut rd) = tokio::fs::read_dir(&nodes_dir).await {
            let mut node_certs = Vec::new();
            while let Ok(Some(entry)) = rd.next_entry().await {
                let node_cert = entry.path().join("node.crt");
                if node_cert.exists() {
                    let node_id = entry.file_name().to_string_lossy().to_string();
                    let info = cert_file_info(&node_cert).await;
                    node_certs.push(json!({
                        "node_id": node_id,
                        "cert": info,
                    }));
                }
            }
            if !node_certs.is_empty() {
                certs.insert("nodes".into(), json!(node_certs));
            }
        }
    }

    let status = if certs.contains_key("ca") && certs.contains_key("gateway") {
        "initialized"
    } else if certs.contains_key("ca") {
        "partial"
    } else {
        "not_initialized"
    };

    Ok(Json(json!({
        "status": status,
        "pki_dir": pki_dir,
        "certs": certs,
    })))
}

/// Read a PEM certificate file and extract basic info.
///
/// Parses the PEM to extract not_before/not_after dates using x509-parser
/// style text parsing. Since we don't want to pull in the full x509 crate,
/// we read the file metadata + use openssl CLI if available, otherwise
/// just report file existence and modification time.
async fn cert_file_info(path: &std::path::Path) -> Value {
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(e) => return json!({"error": format!("Cannot read: {e}")}),
    };

    let modified = meta.modified().ok().map(|t| {
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        dt.to_rfc3339()
    });

    // Try to parse PEM and extract dates using openssl x509 CLI (lightweight)
    let pem_info = match tokio::process::Command::new("openssl")
        .args(["x509", "-noout", "-subject", "-issuer", "-dates", "-in"])
        .arg(path)
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut info = serde_json::Map::new();
            for line in stdout.lines() {
                let line = line.trim();
                if let Some(val) = line.strip_prefix("subject=") {
                    info.insert("subject".into(), json!(val.trim()));
                } else if let Some(val) = line.strip_prefix("issuer=") {
                    info.insert("issuer".into(), json!(val.trim()));
                } else if let Some(val) = line.strip_prefix("notBefore=") {
                    info.insert("not_before".into(), json!(val.trim()));
                } else if let Some(val) = line.strip_prefix("notAfter=") {
                    info.insert("not_after".into(), json!(val.trim()));
                }
            }
            Some(Value::Object(info))
        }
        _ => None,
    };

    let mut result = serde_json::Map::new();
    result.insert("exists".into(), json!(true));
    result.insert("path".into(), json!(path.to_string_lossy()));
    result.insert("size_bytes".into(), json!(meta.len()));
    if let Some(m) = modified {
        result.insert("modified".into(), json!(m));
    }
    if let Some(Value::Object(map)) = pem_info {
        for (k, v) in map {
            result.insert(k, v);
        }
    }

    Value::Object(result)
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Exec-approval status + Approval CRUD (SQL)
// ═══════════════════════════════════════════════════════════════

/// GET /api/exec-approval/status — return whether approval is enabled.
///
/// Resolution: delegated to `middleware::exec_approval_mode` — the same
/// function the GATE calls, not a re-implementation of it. This endpoint
/// previously had its own copy of the precedence chain, including a YAML tier
/// (`security.exec_approval_mode`) that the gate has now dropped; two copies of
/// a precedence rule is how a status endpoint ends up reporting a mode nobody
/// is enforcing. Same for the window: the gate honours
/// `NOO_EXEC_APPROVAL_TIMEOUT_SECS` and ignored the YAML `exec_approval_timeout`
/// this endpoint used to report, so a dashboard showed a window length that was
/// never applied.
async fn approval_status(
    State(_state): State<Arc<AppState>>,
) -> AppJson {
    let mode = crate::middleware::exec_approval_mode();
    let timeout = crate::middleware::exec_approval_timeout_secs() as i64;

    let enabled = mode != "disabled";

    Json(json!({
        "enabled": enabled,
        "mode": mode,
        "timeout": timeout,
    }))
}

/// GET /api/approval/stats — SQL COUNT on noo_approval_requests grouped by status.
///
/// Returns counts of pending/approved/denied/timed_out requests.
/// If the table doesn't exist, returns zeros gracefully.
async fn approval_stats(
    State(state): State<Arc<AppState>>,
) -> AppJson {
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT status, COUNT(*) FROM noo_approval_requests GROUP BY status"
    )
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(rows) => {
            let mut pending: i64 = 0;
            let mut approved: i64 = 0;
            let mut denied: i64 = 0;
            let mut timed_out: i64 = 0;
            let mut expired: i64 = 0;
            let mut total: i64 = 0;

            for (status, count) in &rows {
                total += count;
                match status.as_str() {
                    "pending" => pending = *count,
                    "approved" => approved = *count,
                    "denied" => denied = *count,
                    "timed_out" => timed_out = *count,
                    "expired" => expired = *count,
                    _ => {}
                }
            }

            Json(json!({
                "enabled": true,
                "pending": pending,
                "approved": approved,
                "denied": denied,
                "timed_out": timed_out,
                "expired": expired,
                "total": total,
            }))
        }
        Err(e) => {
            // This used to answer "enabled: false, pending: 0" on the grounds
            // that the table might not exist. Migration 023 creates
            // `noo_approval_requests`, so on any real install an error here is
            // a database fault — and it was being rendered as "the exec
            // approval gate is off and nothing is waiting", which is the exact
            // answer that makes an operator stop looking at a security queue.
            tracing::warn!(error = %e, "approval_stats query failed");
            Json(json!({
                "enabled": Value::Null,
                "pending": Value::Null,
                "approved": Value::Null,
                "denied": Value::Null,
                "timed_out": Value::Null,
                "total": Value::Null,
                "error": format!("cannot read the approval queue: {e}"),
            }))
        }
    }
}

/// The pending-queue read, with the scope as a NULLABLE bind: `$1` is the
/// caller's username, or NULL for Operator+ and internal cluster services.
///
/// `requester = $1` and not `requester IS NOT DISTINCT FROM $1`, so an
/// UNBOUND row (NULL requester — an unattended heartbeat/autonomy turn, and
/// every row written before migration 070) belongs to nobody and stays
/// operator-only rather than showing up in everybody's queue.
pub(crate) const APPROVAL_PENDING_SQL: &str = "SELECT request_id, tool_name, risk_level, reason, created_at, \
        requester, conversation_id, channel, chat_id \
 FROM noo_approval_requests \
 WHERE status = 'pending' \
   AND ($1::text IS NULL OR requester = $1) \
 ORDER BY created_at DESC \
 LIMIT 100";

/// GET /api/approval/pending — list pending approval requests.
///
/// SQL SELECT from noo_approval_requests WHERE status='pending'.
/// If the table doesn't exist, returns empty list gracefully.
async fn approval_pending(
    State(state): State<Arc<AppState>>,
    requester_ctx: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
) -> AppResult {
    // requester/conversation/channel come from migration 070: an operator
    // deciding a request has to be able to see WHOSE call it is and where
    // it was raised. Before that the answer was "a tool wants to run"
    //
    //
    // 070 is also what makes this list scopeable. The tier
    // gate admits every GET regardless of role, so before this a User-tier
    // account could read the whole security queue — every other tenant's
    // tool names, argument previews and conversation ids — even though it
    // could not decide a single row (approve/deny/decide are Operator+).
    // A User now sees the requests IT raised. Unbound rows (unattended
    // heartbeat/autonomy turns, and every row written before 070) have no
    // requester, so they belong to nobody and stay operator-only.
    let scope = scoped_user(
        requester_ctx.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;
    let rows = sqlx::query_as::<_, (
        String,                                    // request_id
        String,                                    // tool_name
        String,                                    // risk_level
        Option<String>,                            // reason
        chrono::DateTime<chrono::Utc>,             // created_at
        Option<String>,                            // requester
        Option<String>,                            // conversation_id
        Option<String>,                            // channel
        Option<String>,                            // chat_id
    )>(APPROVAL_PENDING_SQL)
    .bind(scope.as_deref())
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(rows) => {
            let pending: Vec<Value> = rows.iter().map(
                |(rid, tool, risk, reason, created, requester, conv, channel, chat)| {
                json!({
                    "request_id": rid,
                    "tool_name": tool,
                    "risk_level": risk,
                    "reason": reason,
                    "created_at": created,
                    "status": "pending",
                    // Null means an UNATTENDED turn (heartbeat, autonomy) —
                    // genuinely nobody's conversation, not a missing value.
                    "requester": requester,
                    "conversation_id": conv,
                    "channel": channel,
                    "chat_id": chat,
                })
            }).collect();

            Ok(Json(json!({"pending": pending, "scope": scope})))
        }
        Err(e) => {
            tracing::debug!(error = %e, "approval_pending query failed (table may not exist)");
            Ok(Json(json!({"pending": [], "scope": scope})))
        }
    }
}

/// Approvals are operator-only: RequesterCtx is attached exclusively on
/// JWT auth, so cluster-HMAC callers cannot use these dashboard routes.
/// The CLI decides via POST /api/approval/{id}/decide, which since phase 3
/// applies the same rule — a named operator, not the shared cluster HMAC.
/// See `decide_actor`.
fn require_operator(
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> Result<String, AppError> {
    match ctx {
        Some(axum::Extension(r)) if r.role >= crate::auth::Role::Operator => {
            Ok(r.sub.clone())
        }
        _ => Err(AppError::Forbidden(
            "approval decisions require a logged-in operator (Operator role or above)".into(),
        )),
    }
}

/// An approval decision is a human's. The gate exists so a person decides every
/// high-risk action; a model that could decide its own pending request would make
/// the gate decoration. So the decision routes accept only a PERSON's credential
/// (`task_guard::resolve_origin`): a worker-delegated token (the one a tool call
/// carries back to this gateway), a harness token, an MCP-door key, a service
/// identity or an account that is not an enabled user is refused with 403.
/// Fails closed: if the account lookup fails the caller is not a person.
/// Dashboard and `noo approval` use an ordinary login token, so they pass.
async fn require_human_decider(
    db: &sqlx::PgPool,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> Result<(), AppError> {
    decider_refusal(&crate::task_guard::resolve_origin(db, ctx).await)
}

/// The rule of [`require_human_decider`], pure so it can be pinned.
fn decider_refusal(origin: &crate::task_guard::Origin) -> Result<(), AppError> {
    match origin {
        crate::task_guard::Origin::Person { .. } => Ok(()),
        crate::task_guard::Origin::Agent { via, .. } => {
            tracing::warn!(via = %via, "approval decision refused: not a person's credential");
            Err(AppError::Forbidden(format!(
                "approval decisions are made by a person, not by an agent: this credential is {via}. \
                 Decide in the dashboard, with `noo approval approve <id>` (or `noo approval deny <id>`) after `noo auth login`, \
                 or from a linked chat channel"
            )))
        }
    }
}

/// POST /api/approval/{request_id}/approve — approve a pending request.
///
/// SQL UPDATE noo_approval_requests SET status='approved' WHERE request_id=$1.
async fn approval_approve(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let requester = require_operator(&ctx)?;
    require_human_decider(&state.db, &ctx).await?;
    let approved_by = body
        .as_ref()
        .and_then(|b| b.get("approved_by"))
        .and_then(|v| v.as_str())
        .unwrap_or(&requester);

    let now = chrono::Utc::now();

    let result = sqlx::query(
        "UPDATE noo_approval_requests \
         SET status = 'approved', resolved_by = $2, resolved_at = $3 \
         WHERE request_id = $1 AND status = 'pending'"
    )
    .bind(&request_id)
    .bind(approved_by)
    .bind(now)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) => {
            let updated = r.rows_affected() > 0;
            Ok(Json(json!({
                "approved": updated,
                "request_id": request_id,
            })))
        }
        Err(e) => {
            tracing::debug!(error = %e, "approval_approve failed (table may not exist)");
            Ok(Json(json!({
                "approved": false,
                "request_id": request_id,
                "error": format!("{e}"),
            })))
        }
    }
}

/// POST /api/approval/{request_id}/deny — deny a pending request.
///
/// SQL UPDATE noo_approval_requests SET status='denied' WHERE request_id=$1.
async fn approval_deny(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let requester = require_operator(&ctx)?;
    require_human_decider(&state.db, &ctx).await?;
    let reason = body
        .as_ref()
        .and_then(|b| b.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let denied_by = body
        .as_ref()
        .and_then(|b| b.get("denied_by"))
        .and_then(|v| v.as_str())
        .unwrap_or(&requester);

    let now = chrono::Utc::now();

    let result = sqlx::query(
        "UPDATE noo_approval_requests \
         SET status = 'denied', reason = $2, resolved_by = $3, resolved_at = $4 \
         WHERE request_id = $1 AND status = 'pending'"
    )
    .bind(&request_id)
    .bind(reason)
    .bind(denied_by)
    .bind(now)
    .execute(&state.db)
    .await;

    match result {
        Ok(r) => {
            let updated = r.rows_affected() > 0;
            Ok(Json(json!({
                "denied": updated,
                "request_id": request_id,
            })))
        }
        Err(e) => {
            tracing::debug!(error = %e, "approval_deny failed (table may not exist)");
            Ok(Json(json!({
                "denied": false,
                "request_id": request_id,
                "error": format!("{e}"),
            })))
        }
    }
}

/// Map a `decide` body to the target status + optional reason.
///
/// `decision` must be exactly `"approve"` or `"deny"` (→ the stored statuses
/// `approved` / `denied`); anything else is a 400. `reason` is optional for
/// both decisions — when absent the row's existing reason (the tool-call args
/// summary written at enqueue time) is preserved, matching the Python CLI's
/// `COALESCE(:r, reason)` semantics.
fn parse_decision(body: &Value) -> Result<(&'static str, Option<String>), AppError> {
    let decision = body
        .get("decision")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("body must include decision: approve|deny".into()))?;
    let status = match decision {
        "approve" => "approved",
        "deny" => "denied",
        other => {
            return Err(AppError::BadRequest(format!(
                "invalid decision '{other}' (expected approve|deny)"
            )))
        }
    };
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    Ok((status, reason))
}

/// Resolve WHO is deciding on the `decide` route.
///
/// **Phase 3 of the CLI auth plan.** This used to map "cluster-HMAC caller,
/// therefore no `RequesterCtx`" to `cli-operator` with full approve/deny
/// rights. A shared secret is held by more than one process, so that made
/// anyone who could read it cluster-root on the exec gate, with no
/// attribution and no way to revoke one person without rotating the secret
/// everywhere. An approval decision is precisely the action that most needs
/// a named human, so it **requires one**.
///
/// - JWT with an operator scope (`admin`/`write`) → that subject. (A
///   read-scope JWT is refused here even though `require_any_auth`'s RBAC
///   already blocks non-operator POSTs — defense in depth, mirrors
///   `require_operator` on the sibling /approve|/deny routes.)
/// - No `RequesterCtx` (shared-secret HMAC, service key) → **403**, always.
///   The `NOO_APPROVAL_BREAK_GLASS` posture gate that once let such a caller
///   decide as `cli-operator:break-glass` is RETIRED
///   (`posture::RETIRED_BRIDGES`): an install still holding it open does not
///   start. A locked-out operator recovers a login on the controller with
///   `noo security admin-password reset`, never with a shared secret.
fn decide_actor(
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> Result<String, AppError> {
    match ctx {
        Some(axum::Extension(r)) => {
            if r.role >= crate::auth::Role::Operator {
                Ok(r.sub.clone())
            } else {
                Err(AppError::Forbidden(
                    "approval decisions require an operator (Operator role or \
                     above); your credential has neither the role nor a scope \
                     that maps to it"
                        .into(),
                ))
            }
        }
        // A shared-secret HMAC proves "something holds the secret", never
        // "this person decided". Name yourself or don't decide.
        None => Err(AppError::Forbidden(
            "approval decisions require a named operator — run `noo auth login` \
             (a shared secret cannot be attributed to a person). Locked out: \
             `noo security admin-password reset` on the controller"
                .into(),
        )),
    }
}

/// The pending-only state machine for a decision, as the DB implies it:
/// a missing row is a 404; any row that already left `pending` (approved,
/// denied, timed_out) is a 409 — deciding twice must fail loudly rather than
/// silently rewrite history. `Ok(())` means the transition may proceed.
fn check_transition(row_status: Option<&str>, request_id: &str) -> Result<(), AppError> {
    match row_status {
        None => Err(AppError::NotFound(format!(
            "approval request '{request_id}' not found"
        ))),
        Some("pending") => Ok(()),
        Some(other) => Err(AppError::Conflict(format!(
            "approval request '{request_id}' already {other}"
        ))),
    }
}

/// POST /api/approval/{request_id}/decide — the operator write path.
///
/// Body: `{"decision": "approve"|"deny", "reason": "..."?}`.
/// Responses: 200 `{status, request_id, resolved_by}` on pending→decided;
/// 400 bad decision; 404 unknown id; 409 already decided; 401/403 from the
/// auth layer. Row lock (`FOR UPDATE`) makes a concurrent double-decide
/// serialize into one 200 and one 409.
///
/// This endpoint exists so BOTH CLIs (Rust `noo approval approve/deny` and
/// the Python fallback) stop doing direct SQL UPDATEs from the host — every
/// decision now lands in the tamper-evident audit log like the sibling
/// mutating routes (user_create / security_posture_set).
async fn approval_decide(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let resolved_by = decide_actor(&ctx)?;
    require_human_decider(&state.db, &ctx).await?;
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let (new_status, reason) = parse_decision(&body)?;

    let mut tx = state.db.begin().await?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT status, tool_name FROM noo_approval_requests \
         WHERE request_id = $1 FOR UPDATE",
    )
    .bind(&request_id)
    .fetch_optional(&mut *tx)
    .await?;

    check_transition(row.as_ref().map(|(s, _)| s.as_str()), &request_id)?;
    let tool_name = row.map(|(_, t)| t).unwrap_or_default();

    sqlx::query(
        "UPDATE noo_approval_requests \
         SET status = $2, reason = COALESCE($3, reason), \
             resolved_by = $4, resolved_at = now() \
         WHERE request_id = $1",
    )
    .bind(&request_id)
    .bind(new_status)
    .bind(&reason)
    .bind(&resolved_by)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // Tamper-evident audit sink, same pattern as the sibling mutating routes.
    crate::routes::core::audit_event(
        &state.db,
        "approval_decision",
        "info",
        &resolved_by,
        &request_id,
        new_status,
        json!({
            "tool_name": tool_name,
            "reason": reason,
        }),
    )
    .await;
    tracing::info!(
        request_id = %request_id,
        status = %new_status,
        by = %resolved_by,
        "approval_decision"
    );

    Ok(Json(json!({
        "status": new_status,
        "request_id": request_id,
        "resolved_by": resolved_by,
    })))
}

// ═══════════════════════════════════════════════════════════════
// Mesh host operations — host-watcher spool
// [ported from workers/admin.py + gateway/host_spool.py 2026-07-18]
// ═══════════════════════════════════════════════════════════════
//
// The gateway container has ZERO Docker access (no /var/run/docker.sock, no
// docker CLI). Container-lifecycle operations are written as atomic JSON
// command files into the spool dir (`NOO_HOST_SPOOL_DIR`, default
// `/var/run/noo-spool` — a bind mount of the host's `./.noo-host-spool`,
// see docker-compose.cluster.yml). The host-side daemon
// `scripts/noo-host-watcher.sh` watches that dir, performs the docker/compose
// operation, and writes `<name>.result.json` (plus `.rebuild.log` /
// `.rebuild.running` for stack rebuilds) back into the same dir.

/// Spool dir, env-overridable — mirrors `host_spool._spool_dir()`.
fn host_spool_dir() -> String {
    std::env::var("NOO_HOST_SPOOL_DIR").unwrap_or_else(|_| "/var/run/noo-spool".into())
}

/// Write a spool command file atomically, mirroring
/// `host_spool.write_command`: payload schema
/// `{op, service, health_check, rollback, args, requested_by, ts}`, filename
/// `<time_ns>-<8 hex>.cmd.json` (nanos prefix keeps lexical sort
/// chronological — the operations listing depends on it), temp-file +
/// same-dir rename so the watcher never observes a half-written file.
/// Returns the final path on success, None on any failure (never errors —
/// a failed spool write must not crash the caller).
pub(crate) async fn host_spool_write_command(
    op: &str,
    service: &str,
    args: &[String],
    requested_by: &str,
) -> Option<String> {
    let spool_dir = host_spool_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let suffix: String = {
        use rand::Rng;
        let mut bytes = [0u8; 4];
        rand::rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let name = format!("{nanos}-{suffix}");
    let payload = json!({
        "op": op,
        "service": service,
        "health_check": false,
        "rollback": null,
        "args": args,
        "requested_by": requested_by,
        "ts": chrono::Utc::now().to_rfc3339(),
    });

    let dir = std::path::Path::new(&spool_dir);
    let tmp_path = dir.join(format!(".{name}.tmp"));
    let final_path = dir.join(format!("{name}.cmd.json"));

    let write = async {
        tokio::fs::create_dir_all(&spool_dir).await?;
        tokio::fs::write(&tmp_path, payload.to_string().as_bytes()).await?;
        tokio::fs::rename(&tmp_path, &final_path).await?;
        Ok::<(), std::io::Error>(())
    };
    match write.await {
        Ok(()) => {
            tracing::info!(
                op = %op, service = %service, requested_by = %requested_by,
                path = %final_path.display(), "host_spool_command_written"
            );
            Some(final_path.to_string_lossy().into_owned())
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            tracing::warn!(
                op = %op, service = %service, spool_dir = %spool_dir,
                error = %e, "host_spool_command_write_failed"
            );
            None
        }
    }
}

/// Service-name validation matching Python's `re.fullmatch(r"[a-z0-9._-]{1,63}", s)`.
fn valid_service_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

/// POST /api/mesh/stack-rebuild — queue a full-stack rebuild.
/// [ported from workers/admin.py::_mesh_stack_rebuild 2026-07-18]
///
/// Runs scripts/noomesh-rebuild.sh DETACHED under the host watcher, so it
/// survives this gateway being recreated mid-rebuild. Single-flight is
/// enforced host-side (a concurrent request gets a failed result file).
/// Operator-scope only via the mutation middleware (`scope_allows` requires
/// write/admin for POST); this is the dashboard "Rebuild" path, so the agent
/// self-modify gate does not apply — but every request is audit-logged.
async fn mesh_stack_rebuild(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let quick = body.get("quick").and_then(|v| v.as_bool()).unwrap_or(false);
    let no_cache = body.get("no_cache").and_then(|v| v.as_bool()).unwrap_or(false);

    let services: Vec<String> = match body.get("services") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for s in items {
                match s.as_str() {
                    Some(name) if valid_service_name(name) => out.push(name.to_string()),
                    _ => {
                        return Err(AppError::BadRequest(format!(
                            "invalid service name: {s:?}"
                        )));
                    }
                }
            }
            out
        }
        Some(_) => {
            return Err(AppError::BadRequest(
                "services must be a list of service names".into(),
            ));
        }
    };

    let mut args: Vec<String> = Vec::new();
    if quick {
        args.push("--quick".into());
    }
    if no_cache {
        args.push("--no-cache".into());
    }
    args.extend(services);

    let spool_path =
        host_spool_write_command("stack-rebuild", "stack", &args, "api:stack_rebuild").await;

    let actor = ctx
        .as_ref()
        .map(|e| e.0.sub.clone())
        .unwrap_or_else(|| "cluster-cli".to_string());
    crate::routes::core::audit_event(
        &state.db,
        "stack_rebuild",
        "warning",
        &actor,
        "mesh:stack",
        if spool_path.is_some() { "queued_spool" } else { "spool_write_failed" },
        json!({ "args": &args, "spool_command": &spool_path }),
    )
    .await;

    let Some(spool_path) = spool_path else {
        return Err(AppError::Internal(
            "could not queue stack rebuild (host spool write failed)".into(),
        ));
    };
    Ok(Json(json!({
        "queued": true,
        "args": args,
        "spool_command": spool_path,
        "via": "host_watcher_spool",
        "hint": "poll GET /api/mesh/operations for progress",
    })))
}

/// GET /api/mesh/operations — recent host-watcher spool operations.
/// [ported from workers/admin.py::_mesh_operations 2026-07-18]
///
/// Reads the result files the watcher writes back into the spool dir
/// (restarts, backups, cert rotations, stack rebuilds). For the newest stack
/// rebuild that actually ran, a log tail is attached so the dashboard can
/// show live progress. Feeds the dashboard Host Operations panel.
async fn mesh_operations() -> AppJson {
    let spool_dir = host_spool_dir();

    // Single directory scan replaces Python's three globs.
    let mut result_names: Vec<String> = Vec::new();
    let mut pending: u64 = 0;
    let mut running: u64 = 0;
    if let Ok(mut rd) = tokio::fs::read_dir(&spool_dir).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let fname = entry.file_name().to_string_lossy().into_owned();
            if fname.ends_with(".result.json") {
                result_names.push(fname);
            } else if fname.ends_with(".cmd.json") {
                pending += 1;
            } else if fname.ends_with(".rebuild.running") {
                running += 1;
            }
        }
    }

    // Filenames start with <time_ns>, so lexical sort is chronological.
    result_names.sort_by(|a, b| b.cmp(a));
    let mut ops: Vec<Value> = Vec::new();
    for fname in result_names.into_iter().take(50) {
        let name = fname.strip_suffix(".result.json").unwrap_or(&fname).to_string();
        let path = std::path::Path::new(&spool_dir).join(&fname);
        let Ok(raw) = tokio::fs::read_to_string(&path).await else { continue };
        let Ok(mut data) = serde_json::from_str::<Value>(&raw) else { continue };
        if let Some(obj) = data.as_object_mut() {
            obj.insert("name".into(), json!(name));
        } else {
            continue;
        }
        ops.push(data);
    }

    // Live log tail for the newest stack rebuild that actually ran (a
    // rejected request — bad arg, already-running — leaves no log).
    let mut rebuild_log_tail: Option<Vec<String>> = None;
    for op in &ops {
        if op.get("op").and_then(|v| v.as_str()) == Some("stack-rebuild") {
            let name = op.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let log_path = std::path::Path::new(&spool_dir).join(format!("{name}.rebuild.log"));
            match tokio::fs::read(&log_path).await {
                Ok(bytes) => {
                    // errors="replace" equivalent: lossy UTF-8 decode. Tail is
                    // the last 4000 chars, then the last 30 lines of that.
                    let text = String::from_utf8_lossy(&bytes);
                    let chars: Vec<char> = text.chars().collect();
                    let start = chars.len().saturating_sub(4000);
                    let tail: String = chars[start..].iter().collect();
                    let lines: Vec<String> = tail.lines().map(String::from).collect();
                    let keep = lines.len().saturating_sub(30);
                    rebuild_log_tail = Some(lines[keep..].to_vec());
                    break;
                }
                Err(_) => continue,
            }
        }
    }

    Json(json!({
        "operations": ops,
        "pending_commands": pending,
        "rebuild_running": running > 0,
        "rebuild_log_tail": rebuild_log_tail,
    }))
}

// ═══════════════════════════════════════════════════════════════
// Self-administration — logs tail/errors, stack status/restart/rebuild,
// metrics query
// [ported from workers/admin.py 2026-07-18]
// ═══════════════════════════════════════════════════════════════
//
// Two tiers, mirroring the Python module:
//  - LOW risk: logs_tail, logs_errors, mesh_status, metrics_query.
//    Always available.
//  - HIGH risk: mesh_restart, mesh_rebuild. These are OPERATOR endpoints,
//    not agent tools — they are no longer exposed over MCP, and they now
//    require a logged-in caller holding the **Admin** role (a cluster-HMAC
//    caller is refused: the fleet secret names nobody, and restarting the
//    fleet must be attributable to a person). On top of the role gate they
//    keep the per-LLM-provider rate limits, a JSONL audit row
//    (NOO_SELF_MODIFY_AUDIT_PATH) AND a noo_security_audit event on every
//    call.
//
// Error mapping follows the earlier ports in this file / users.rs: behind
// the Python catch-all every handler-level {"error": ...} body came back
// as HTTP 400, so validation/gate/rate-limit rejections are 400 with the
// exact Python body (including extra fields like "hint"); infra failures
// (spool write) are 500 like `mesh_stack_rebuild` above.

/// Container-name prefixes considered part of the PAI stack
/// (`_NOO_CONTAINER_PREFIXES` in workers/admin.py).
const NOO_CONTAINER_PREFIXES: &[&str] = &["noo-", "mesh-"];

fn is_noo_container(name: &str) -> bool {
    NOO_CONTAINER_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Python `str(body.get(k) or "").strip()`.
fn body_str_trim(body: &Value, key: &str) -> String {
    match body.get(key) {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Bool(false)) => String::new(),
        Some(v) => v.to_string().trim().to_string(),
    }
}

/// Python `int(body.get(key, default))` then `max(lo, min(x, hi))`. Accepts
/// JSON numbers and numeric strings; anything else falls back to the default
/// (the Python original would raise → opaque 500; a clamp-to-default is the
/// forgiving equivalent and keeps the route total).
fn body_int_clamped(body: &Value, key: &str, default: i64, lo: i64, hi: i64) -> i64 {
    let raw = match body.get(key) {
        None | Some(Value::Null) => default,
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().map(|f| f as i64))
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
            .unwrap_or(default),
    };
    raw.clamp(lo, hi)
}

/// All containers across the cluster — same data the Python handlers got by
/// self-HTTP-calling GET /api/logs/containers (a native route in this file);
/// here we invoke the handler directly instead of looping back over HTTP.
async fn all_containers(state: Arc<AppState>) -> Vec<Value> {
    let Json(v) = logs_containers(State(state), Query(ContainerQueryParams { node_id: None })).await;
    match v.get("containers") {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    }
}

/// Resolve `(node_id, full_container_name)` for a container name or
/// substring, mirroring the Python lookup (first match wins).
fn find_container(containers: &[Value], wanted: &str) -> Option<(String, String)> {
    for row in containers {
        let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name == wanted || name.contains(wanted) {
            let node = row.get("node_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            return Some((node, name.to_string()));
        }
    }
    None
}

/// Fetch log lines for one container from its node-agent. The Python
/// handlers went through GET /api/logs/node/{node}/{container}, which clamps
/// `tail` to 2000 — the same clamp is applied here so behaviour matches the
/// pre-port chain. Error strings mirror the Python handler's.
async fn node_log_lines(
    state: &AppState,
    node_id: &str,
    container: &str,
    tail: i64,
) -> Result<Vec<String>, String> {
    let agent_url = super::cluster::get_node_agent_url(state, node_id)
        .await
        .map_err(|_| "node-agent logs failed: HTTP 404".to_string())?;
    let client = super::cluster::build_node_agent_client();
    let auth = crate::node_agent_auth::header_for(&agent_url);
    let tail = tail.clamp(1, 2000);
    let mut req = client.get(format!("{agent_url}/logs/{container}?tail={tail}"));
    if let Some((ref k, ref v)) = auth {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("node-agent logs error: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("node-agent logs failed: HTTP {}", resp.status().as_u16()));
    }
    let data: Value = resp
        .json()
        .await
        .map_err(|e| format!("node-agent logs error: {e}"))?;
    // An absent or non-array `logs` is a protocol error, not "no logs" — a
    // container with nothing to say still answers `"logs": []`. Collapsing
    // the two made a broken fetch indistinguishable from a quiet container,
    // which is precisely how a truncated read read as "no matches" while
    // chasing a proxy timeout.
    match data.get("logs") {
        Some(Value::Array(a)) => Ok(a
            .iter()
            .map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))
            .collect()),
        Some(other) => Err(format!(
            "node-agent logs returned `logs` as {}, expected an array",
            match other {
                Value::Null => "null",
                Value::Bool(_) => "a boolean",
                Value::Number(_) => "a number",
                Value::String(_) => "a string",
                Value::Object(_) => "an object",
                Value::Array(_) => unreachable!(),
            }
        )),
        None => Err("node-agent logs response had no `logs` field".to_string()),
    }
}

/// Optional non-empty string field.
fn body_opt_str(body: &Value, key: &str) -> Option<String> {
    let s = body_str_trim(body, key);
    if s.is_empty() { None } else { Some(s) }
}

/// The `container` a caller names is `noo-gateway`; the `name` label the
/// shipper attaches is `gateway` (the prefix stripped, `logs_ingest`). A
/// unit name (`noo-hostd`) is shipped as-is, so the prefix-less form is
/// matched as a substring and finds both.
fn container_to_name_contains(container: &str) -> String {
    for p in NOO_CONTAINER_PREFIXES {
        if let Some(rest) = container.strip_prefix(p) {
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    container.to_string()
}

/// POST /api/logs/tail — body {container, lines?=200, grep?, node?, name?,
/// source?, since?, until?}.
/// [ported from workers/admin.py::_logs_tail (worker.api.logs.tail) 2026-07-18;
/// Loki-backed 2026-09-28 (fleet logging phase 5)]
///
/// The last N lines of one container (or unit), oldest first. With Loki
/// configured and answering, the lines come from Loki — every node, any
/// history the retention holds, `name` matching the shipped label — and
/// the answer says `"backend": "loki"`. Otherwise the pre-Loki path: the
/// container is located on a node-agent (exact name first-match or
/// substring across the cluster list when `node` is not given) and its
/// `docker logs` tail is read, and the answer says `"backend":
/// "agent-scan"` with `loki_error` explaining why. The optional
/// case-insensitive `grep` regex is applied after the fetch on both paths.
async fn logs_tail(
    State(state): State<Arc<AppState>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let mut container = body_str_trim(&body, "container");
    let lines = body_int_clamped(&body, "lines", 200, 1, 5000);
    let grep = match body.get("grep") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    let mut node = body_opt_str(&body, "node");
    let name = body_opt_str(&body, "name");

    if container.is_empty() && name.is_none() {
        return Err(AppError::BadRequest("container required".into()));
    }

    // Compile the grep pattern before any network work (Python compiled it
    // after the fetch; failing fast is strictly better and same contract).
    let grep_rx = match &grep {
        Some(pat) => match regex::RegexBuilder::new(pat).case_insensitive(true).build() {
            Ok(rx) => Some(rx),
            Err(e) => {
                return Err(AppError::BadRequest(format!("invalid grep pattern: {e}")));
            }
        },
        None => None,
    };

    // ── Loki first ──
    let spec = logs_search::SearchSpec {
        node: node.clone(),
        name: name.clone(),
        name_contains: if container.is_empty() { None } else { Some(container_to_name_contains(&container)) },
        source: body_opt_str(&body, "source"),
        since: Some(body_opt_str(&body, "since").unwrap_or_else(|| "24h".to_string())),
        until: body_opt_str(&body, "until"),
        limit: Some(lines.min(logs_search::MAX_LIMIT as i64)),
        direction: Some("backward".into()),
        ..Default::default()
    };
    let built = logs_search::build(&spec, chrono::Utc::now()).map_err(AppError::BadRequest)?;
    let outcome = logs_search::query_configured_loki(&built).await;
    let fallback = match outcome {
        logs_search::LokiOutcome::Lines(mut got) => {
            got.reverse(); // fetched newest-first; a tail reads oldest-first
            if let Some(rx) = &grep_rx {
                got.retain(|l| rx.is_match(&l.line));
            }
            let names: Vec<String> = {
                let mut v: Vec<String> = got.iter().map(|l| l.name.clone()).collect();
                v.sort();
                v.dedup();
                v
            };
            let answer = json!({
                "container": if container.is_empty() { name.clone().unwrap_or_default() } else { container },
                "node": node.unwrap_or_default(),
                "names": names,
                "matched_lines": got.len(),
                "lines": got.iter().map(|l| l.line.clone()).collect::<Vec<_>>(),
                "entries": got.iter().map(logs_search::Line::to_json).collect::<Vec<_>>(),
            });
            return Ok(Json(logs_search::merge(answer, logs_search::loki_envelope(&built, &got))));
        }
        logs_search::LokiOutcome::Refused(reason) => return Err(AppError::BadRequest(reason)),
        ref down => logs_search::fallback_reason(down).unwrap_or_else(|| "Loki did not answer".into()),
    };

    // ── the node-agent scan ──
    if container.is_empty() {
        // `name` alone is a Loki-vocabulary ask; the scan knows containers.
        container = name.unwrap_or_default();
    }
    if node.is_none() {
        let containers = all_containers(state.clone()).await;
        if let Some((nid, full_name)) = find_container(&containers, &container) {
            node = Some(nid);
            container = full_name;
        }
    }
    let Some(node) = node else {
        return Err(AppError::BadRequest(format!(
            "could not locate container '{container}' on any node (and Loki did not answer: {fallback})"
        )));
    };

    let mut out_lines = node_log_lines(&state, &node, &container, lines)
        .await
        .map_err(AppError::BadRequest)?;
    if let Some(rx) = grep_rx {
        out_lines.retain(|ln| rx.is_match(ln));
    }

    Ok(Json(logs_search::fallback_envelope(
        json!({
            "container": container,
            "node": node,
            "matched_lines": out_lines.len(),
            "lines": out_lines,
        }),
        &fallback,
    )))
}

/// POST /api/logs/errors — body {container?, minutes?=15, limit?=200, node?,
/// name?, source?, since?, until?}.
/// [ported from workers/admin.py::_logs_errors (worker.api.logs.errors) 2026-07-18;
/// Loki-backed 2026-09-28 (fleet logging phase 5)]
///
/// Warning and error lines across the fleet in a recent window, oldest
/// first. With Loki configured and answering: `{level=~"error|warn"}` over
/// the shipped labels (`node`, `name`, `source`), the window `since`
/// (default `minutes`), and the answer says `"backend": "loki"`. Otherwise
/// the pre-Loki scan: one (name or substring) or all PAI containers'
/// `docker logs` tails read through the node-agents and grepped for the
/// error words — tail depth 50 lines/minute, floor 500, cap 5000 (then the
/// node-agent fetch clamp of 2000) — and the answer says `"backend":
/// "agent-scan"` with `loki_error`, because a scan of what the node-agents
/// could reach is not the fleet view.
async fn logs_errors(
    State(state): State<Arc<AppState>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let target = body_opt_str(&body, "container");
    let minutes = body_int_clamped(&body, "minutes", 15, 1, 240);
    let limit = body_int_clamped(&body, "limit", 200, 1, 2000) as usize;
    let node = body_opt_str(&body, "node");

    // ── Loki first ──
    let spec = logs_search::SearchSpec {
        node: node.clone(),
        name: body_opt_str(&body, "name"),
        name_contains: target.as_deref().map(container_to_name_contains),
        source: body_opt_str(&body, "source"),
        level: Some("error,warn".into()),
        since: Some(body_opt_str(&body, "since").unwrap_or_else(|| format!("{minutes}m"))),
        until: body_opt_str(&body, "until"),
        limit: Some(limit as i64),
        direction: Some("backward".into()),
        ..Default::default()
    };
    let built = logs_search::build(&spec, chrono::Utc::now()).map_err(AppError::BadRequest)?;
    let outcome = logs_search::query_configured_loki(&built).await;
    let fallback = match outcome {
        logs_search::LokiOutcome::Lines(mut got) => {
            got.reverse();
            let window_minutes = (built.end - built.start).num_minutes().max(1);
            let matches: Vec<Value> = got
                .iter()
                .map(|l| {
                    json!({
                        "container": l.name,
                        "node": l.node,
                        "line": l.line,
                        "ts": l.ts_rfc3339(),
                        "level": l.level,
                        "source": l.source,
                    })
                })
                .collect();
            let answer = json!({
                "window_minutes": window_minutes,
                "matches": matches,
            });
            return Ok(Json(logs_search::merge(answer, logs_search::loki_envelope(&built, &got))));
        }
        logs_search::LokiOutcome::Refused(reason) => return Err(AppError::BadRequest(reason)),
        ref down => logs_search::fallback_reason(down).unwrap_or_else(|| "Loki did not answer".into()),
    };

    // ── the node-agent scan ──
    // `\b(error|warn|...)\b` case-insensitive, same class list as Python.
    static ERR_RX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let rx = ERR_RX.get_or_init(|| {
        regex::RegexBuilder::new(r"\b(error|warn|warning|panic|exception|traceback|failed|fatal)\b")
            .case_insensitive(true)
            .build()
            .expect("static regex")
    });

    let containers = all_containers(state.clone()).await;
    let mut targets: Vec<(String, String)> = Vec::new();
    for row in &containers {
        let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(ref t) = target {
            if !(name == t || name.contains(t.as_str())) {
                continue;
            }
        } else if !is_noo_container(name) {
            continue;
        }
        let node_id = row.get("node_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if let Some(ref want) = node {
            if &node_id != want {
                continue;
            }
        }
        targets.push((node_id, name.to_string()));
    }

    if targets.is_empty() {
        return Ok(Json(logs_search::fallback_envelope(
            json!({"matches": [], "note": "no matching containers"}),
            &fallback,
        )));
    }

    let tail_lines = (minutes * 50).clamp(500, 5000);
    let mut out: Vec<Value> = Vec::new();
    'outer: for (node_id, name) in &targets {
        let Ok(lines) = node_log_lines(&state, node_id, name, tail_lines).await else {
            continue; // same as Python: skip containers whose fetch fails
        };
        for ln in lines {
            if rx.is_match(&ln) {
                out.push(json!({"container": name, "node": node_id, "line": ln}));
                if out.len() >= limit {
                    break 'outer;
                }
            }
        }
    }

    Ok(Json(logs_search::fallback_envelope(
        json!({
            "window_minutes": minutes,
            "matches": out,
            "scanned": targets.len(),
        }),
        &fallback,
    )))
}

/// POST /api/logs/search — body {query?, text?, node?, name?, source?,
/// level?, since?, until?, limit?≤2000, direction?}. Operator or Admin
/// (`auth::LOGS_READ_PREFIX`).
///
/// The fleet search: "what happened on host3 at 14:02", "every error in
/// the last hour". The gateway BUILDS the LogQL from the typed fields
/// (`logs_search::build`); free text (`text`, or a `query` that does not
/// start with `{`) becomes a `|=` line filter with quotes and backslashes
/// escaped. A `query` starting with `{` is an operator's own LogQL and
/// goes through unchanged — under the same limit cap (2000) and range cap
/// (7 days). Loki down or unconfigured is 503 with the reason: there is no
/// scan fallback here, because a scan cannot answer a fleet query honestly.
async fn logs_search(body: Option<Json<Value>>) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let spec = search_spec_from_body(&body);
    let built = logs_search::build(&spec, chrono::Utc::now()).map_err(AppError::BadRequest)?;
    match logs_search::query_configured_loki(&built).await {
        logs_search::LokiOutcome::Lines(got) => {
            let answer = json!({
                "lines": got.iter().map(logs_search::Line::to_json).collect::<Vec<_>>(),
            });
            Ok(Json(logs_search::merge(answer, logs_search::loki_envelope(&built, &got))))
        }
        logs_search::LokiOutcome::Refused(reason) => Err(AppError::BadRequest(reason)),
        logs_search::LokiOutcome::Down(reason) => Err(AppError::Unavailable(format!(
            "log search needs Loki and it did not answer: {reason}"
        ))),
    }
}

/// The search body → spec. `query` is LogQL when it starts with `{`,
/// free text otherwise; `text` is always free text.
fn search_spec_from_body(body: &Value) -> logs_search::SearchSpec {
    let (query, text_from_query) = match body_opt_str(body, "query") {
        Some(q) if q.starts_with('{') => (Some(q), None),
        Some(q) => (None, Some(q)),
        None => (None, None),
    };
    let text = body_opt_str(body, "text").or(text_from_query);
    logs_search::SearchSpec {
        query,
        text,
        node: body_opt_str(body, "node"),
        name: body_opt_str(body, "name"),
        name_contains: body_opt_str(body, "container").map(|c| container_to_name_contains(&c)),
        source: body_opt_str(body, "source"),
        level: body_opt_str(body, "level"),
        since: body_opt_str(body, "since"),
        until: body_opt_str(body, "until"),
        limit: body.get("limit").and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_f64().map(|f| f as i64))
                .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
        }),
        direction: body_opt_str(body, "direction"),
    }
}

/// GET /api/mesh/status — PAI containers across all cluster nodes.
/// [ported from workers/admin.py::_mesh_status (worker.api.mesh.status) 2026-07-18]
async fn mesh_status(State(state): State<Arc<AppState>>) -> AppJson {
    let containers = all_containers(state).await;
    let mut rows: Vec<Value> = Vec::new();
    for row in &containers {
        let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if !is_noo_container(name) {
            continue;
        }
        let node = row
            .get("node_hostname")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| row.get("node_id").and_then(|v| v.as_str()))
            .unwrap_or("");
        rows.push(json!({
            "name": name,
            "node": node,
            "image": row.get("image").and_then(|v| v.as_str()).unwrap_or(""),
            "status": row.get("status").and_then(|v| v.as_str()).unwrap_or("?"),
        }));
    }
    rows.sort_by(|a, b| {
        let ka = (a["node"].as_str().unwrap_or(""), a["name"].as_str().unwrap_or(""));
        let kb = (b["node"].as_str().unwrap_or(""), b["name"].as_str().unwrap_or(""));
        ka.cmp(&kb)
    });
    Json(json!({"count": rows.len(), "containers": rows}))
}

#[derive(Deserialize)]
struct MetricsIncrementBody {
    name: String,
    #[serde(default = "one")]
    value: f64,
    #[serde(default)]
    labels: std::collections::HashMap<String, String>,
}

fn one() -> f64 {
    1.0
}

/// POST /api/metrics/increment — an add-on increments one of its counters.
///
/// Body `{"name": "<x>_total", "value": 1, "labels": {…}}`; rendered at
/// `/metrics` as `noo_addon_<name>{addon="<source>",…}`, the source taken
/// from the credential. The one door add-on metrics enter by:
/// evolve had posted here since its extraction and no gateway served it, and
/// trellion published on a NATS subject nothing subscribed to, so neither
/// add-on's counters ever reached a scrape. Scope `metrics` on an add-on key.
async fn metrics_increment(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<AuthActor>>,
    cluster: Option<Extension<ClusterNode>>,
    Json(body): Json<MetricsIncrementBody>,
) -> axum::response::Response {
    let who = actor
        .map(|a| a.0 .0.clone())
        .or_else(|| cluster.map(|c| c.0 .0.clone()))
        .unwrap_or_default();
    let source = crate::metrics::addon_source(&who);
    if source.is_empty() {
        return AppError::BadRequest("no caller to attribute the counter to".into()).into_response();
    }
    if let Some(why) = crate::metrics::addon_counter_refusal(&body.name, &body.labels, body.value) {
        return AppError::BadRequest(why).into_response();
    }
    match state
        .metrics
        .inc_addon_counter(&source, &body.name, &body.labels, body.value as u64)
        .await
    {
        Ok(()) => Json(json!({"ok": true, "series": format!("{}{}", crate::metrics::ADDON_COUNTER_PREFIX, body.name), "addon": source})).into_response(),
        Err(why) => {
            tracing::warn!(source = %source, name = %body.name, "addon_counter_refused: {why}");
            (axum::http::StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": why}))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct MetricsGaugeBody {
    name: String,
    value: f64,
    #[serde(default)]
    labels: std::collections::HashMap<String, String>,
}

/// POST /api/metrics/gauge — an add-on sets one of its gauges.
///
/// Body `{"name": "<x>", "value": 12.5, "labels": {…}}`; rendered at
/// `/metrics` as `noo_addon_<name>{addon="<source>",…}` under `# TYPE …
/// gauge`, the source taken from the credential. The gauge twin of
/// `/api/metrics/increment` under the same `metrics` scope
/// phase C: trellion's `set_gauge` published to a NATS subject nothing
/// read. Same validation as a counter except the value, which is any finite
/// number, and the name, which must not end in `_total`. Last write wins.
/// New series count against the source's 256-series cap together with its
/// counters; past it the route answers 429.
async fn metrics_gauge(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<AuthActor>>,
    cluster: Option<Extension<ClusterNode>>,
    Json(body): Json<MetricsGaugeBody>,
) -> axum::response::Response {
    let who = actor
        .map(|a| a.0 .0.clone())
        .or_else(|| cluster.map(|c| c.0 .0.clone()))
        .unwrap_or_default();
    let source = crate::metrics::addon_source(&who);
    if source.is_empty() {
        return AppError::BadRequest("no caller to attribute the gauge to".into()).into_response();
    }
    if let Some(why) = crate::metrics::addon_gauge_refusal(&body.name, &body.labels, body.value) {
        return AppError::BadRequest(why).into_response();
    }
    match state.metrics.set_addon_gauge(&source, &body.name, &body.labels, body.value).await {
        Ok(()) => Json(json!({"ok": true, "series": format!("{}{}", crate::metrics::ADDON_COUNTER_PREFIX, body.name), "addon": source})).into_response(),
        Err(why) => {
            tracing::warn!(source = %source, name = %body.name, "addon_gauge_refused: {why}");
            (axum::http::StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": why}))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct MetricsQueryParams {
    query: Option<String>,
    time: Option<String>,
}

/// GET /api/metrics/query?query=<PromQL>[&time=...] — Prometheus proxy.
/// [ported from workers/admin.py::_metrics_query (worker.api.metrics.query) 2026-07-18]
///
/// Gives callers the same eyes as Grafana (GPU temps, request rates, node
/// load history). NB: the old Python path was unreachable for GET params —
/// the catch-all forwarded an empty body — so this native route is the
/// first time the documented GET contract actually works.
async fn metrics_query(
    Query(params): Query<MetricsQueryParams>,
) -> axum::response::Response {
    let query = params.query.as_deref().unwrap_or("").trim().to_string();
    if query.is_empty() {
        return AppError::BadRequest("query (PromQL) required".into()).into_response();
    }
    let prom_url = crate::config::env_or_yaml(
        "NOO_PROMETHEUS_URL",
        |c| c.services.prometheus_url.clone(),
        "https://prometheus:9090",
    );

    // Python: verify against NOO_TLS_CA when present, else no verification.
    // The shared cluster client is already built on the cluster CA (and
    // falls back to a default client when TLS material is absent).
    let client = crate::tls::cluster_client();
    let mut req = client
        .get(format!("{prom_url}/api/v1/query"))
        .query(&[("query", query.as_str())])
        .timeout(std::time::Duration::from_secs(15));
    if let Some(ref t) = params.time {
        req = req.query(&[("time", t.as_str())]);
    }

    let data: Value = match req.send().await {
        Ok(resp) => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                return AppError::BadRequest(format!(
                    "prometheus unreachable at {prom_url}: {e}"
                ))
                .into_response();
            }
        },
        Err(e) => {
            return AppError::BadRequest(format!("prometheus unreachable at {prom_url}: {e}"))
                .into_response();
        }
    };

    if data.get("status").and_then(|v| v.as_str()) != Some("success") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": data.get("error").cloned().unwrap_or_else(|| json!("query failed")),
                "errorType": data.get("errorType").cloned().unwrap_or_else(|| json!("")),
            })),
        )
            .into_response();
    }
    let result = data.get("data").cloned().unwrap_or_else(|| json!({}));
    let mut items = match result.get("result") {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    items.truncate(100);
    Json(json!({
        "resultType": result.get("resultType").and_then(|v| v.as_str()).unwrap_or(""),
        "result": items,
    }))
    .into_response()
}

// ═══════════════════════════════════════════════════════════════
// Operator observability — range queries, series discovery, alerts
// ═══════════════════════════════════════════════════════════════
//
// Read-only siblings of `metrics_query`: what Grafana shows (a range of
// points, the names to ask for) plus what is alerting. All GET, all behind
// `auth::METRICS_READ_PATHS` (Operator/Admin), all over the shared cluster
// client with the caller's leaf — no new credential, no new network path.
// The pure parts (argument validation, point cap, compaction, truncation) are
// free functions below so they are tested against Prometheus-shaped fixtures.

/// Prometheus refuses a range query past this many points per series
/// ("exceeded maximum resolution of 11,000 points"). Refused here first, with
/// the number the caller needs to fix it.
const MAX_RANGE_POINTS: u64 = 11_000;
/// Series kept from one query (same cap as `metrics_query`).
const MAX_SERIES: usize = 100;
/// Names/values kept from one discovery call.
const MAX_DISCOVER: usize = 500;
/// Rules kept from one alerts call.
const MAX_ALERT_ROWS: usize = 200;
/// Alertmanager alerts kept from one alerts call.
const MAX_AM_ALERTS: usize = 100;
/// Firing instances shown per rule.
const MAX_INSTANCES_PER_RULE: usize = 5;
const OBS_TIMEOUT_SECS: u64 = 15;

/// A Prometheus timestamp: unix seconds (fractions allowed) or RFC3339.
fn parse_prom_time(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Ok(v) = s.parse::<f64>() {
        return v.is_finite().then_some(v);
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp_millis() as f64 / 1000.0)
}

/// A step: seconds (`"15"`, `"0.5"`) or a Prometheus duration (`"30s"`,
/// `"5m"`, `"1h"`, `"2d"`, `"1w"`). Must be positive.
fn parse_prom_step(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Ok(v) = s.parse::<f64>() {
        return (v.is_finite() && v > 0.0).then_some(v);
    }
    let split = s.find(|c: char| c.is_ascii_alphabetic())?;
    let (num, unit) = s.split_at(split);
    let n: f64 = num.parse().ok()?;
    let mult = match unit {
        "ms" => 0.001,
        "s" => 1.0,
        "m" => 60.0,
        "h" => 3600.0,
        "d" => 86_400.0,
        "w" => 604_800.0,
        _ => return None,
    };
    let v = n * mult;
    (v.is_finite() && v > 0.0).then_some(v)
}

/// Validate a range request. Returns the number of points per series.
fn validate_range(start: &str, end: &str, step: &str) -> Result<u64, String> {
    let s = parse_prom_time(start).ok_or("start must be a unix timestamp or RFC3339 time")?;
    let e = parse_prom_time(end).ok_or("end must be a unix timestamp or RFC3339 time")?;
    let st = parse_prom_step(step)
        .ok_or("step must be positive seconds or a duration such as 30s, 5m, 1h")?;
    if e < s {
        return Err("end is before start".into());
    }
    let points = ((e - s) / st).floor() as u64 + 1;
    if points > MAX_RANGE_POINTS {
        return Err(format!(
            "{points} points per series exceeds the {MAX_RANGE_POINTS} cap; \
             raise step or shorten the window"
        ));
    }
    Ok(points)
}

/// Keep at most `max` entries; returns (kept, total, truncated).
fn cap_list(mut items: Vec<Value>, max: usize) -> (Vec<Value>, usize, bool) {
    let total = items.len();
    items.truncate(max);
    (items, total, total > max)
}

/// Unwrap a Prometheus `{status, data}` envelope. `Err` carries the
/// upstream's own error text so the operator sees the PromQL complaint.
fn prom_data(body: &Value) -> Result<Value, String> {
    if body.get("status").and_then(|v| v.as_str()) == Some("success") {
        return Ok(body.get("data").cloned().unwrap_or(Value::Null));
    }
    let err = body.get("error").and_then(|v| v.as_str()).unwrap_or("query failed");
    let kind = body.get("errorType").and_then(|v| v.as_str()).unwrap_or("");
    Err(if kind.is_empty() { err.to_string() } else { format!("{kind}: {err}") })
}

/// GET `{base}{path}` with query params; returns the decoded JSON body
/// whatever the HTTP status (Prometheus puts its error text in a 4xx body).
/// Unreachable or non-JSON is a 503 naming the upstream, never a bare
/// transport error.
async fn obs_get_json(
    base: &str,
    path: &str,
    params: &[(&str, String)],
    what: &str,
) -> Result<Value, AppError> {
    if base.is_empty() {
        return Err(AppError::Unavailable(format!("{what} is not configured on this gateway")));
    }
    let resp = crate::tls::cluster_client()
        .get(format!("{base}{path}"))
        .query(params)
        .timeout(std::time::Duration::from_secs(OBS_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| AppError::Unavailable(format!("{what} unreachable at {base}: {e}")))?;
    let status = resp.status();
    resp.json::<Value>().await.map_err(|e| {
        AppError::Unavailable(format!("{what} at {base} answered {status} with a non-JSON body: {e}"))
    })
}

fn prometheus_base() -> String {
    crate::config::env_or_yaml(
        "NOO_PROMETHEUS_URL",
        |c| c.services.prometheus_url.clone(),
        "https://prometheus:9090",
    )
}

fn alertmanager_base() -> String {
    crate::config::env_or_yaml(
        "NOO_ALERTMANAGER_URL",
        |c| c.services.alertmanager_url.clone(),
        "https://alertmanager:9093",
    )
}

/// Run a Prometheus GET and unwrap its envelope; PromQL errors are 400.
async fn prom_get_data(path: &str, params: &[(&str, String)]) -> Result<Value, AppError> {
    let body = obs_get_json(&prometheus_base(), path, params, "prometheus").await?;
    prom_data(&body).map_err(AppError::BadRequest)
}

#[derive(Deserialize)]
struct MetricsRangeParams {
    query: Option<String>,
    start: Option<String>,
    end: Option<String>,
    step: Option<String>,
}

/// GET /api/metrics/range?query=<PromQL>&start=&end=&step= — Prometheus
/// `query_range` proxy (operator-only, read-only).
///
/// `start`/`end` are unix seconds or RFC3339; `step` is seconds or a
/// duration (`30s`, `5m`). Refused above 11,000 points per series (the limit
/// Prometheus enforces anyway) and truncated to 100 series.
async fn metrics_range(Query(p): Query<MetricsRangeParams>) -> axum::response::Response {
    let get = |v: &Option<String>| v.as_deref().unwrap_or("").trim().to_string();
    let (query, start, end, step) = (get(&p.query), get(&p.start), get(&p.end), get(&p.step));
    if query.is_empty() {
        return AppError::BadRequest("query (PromQL) required".into()).into_response();
    }
    if start.is_empty() || end.is_empty() || step.is_empty() {
        return AppError::BadRequest("start, end and step are required".into()).into_response();
    }
    if let Err(why) = validate_range(&start, &end, &step) {
        return AppError::BadRequest(why).into_response();
    }
    let data = match prom_get_data(
        "/api/v1/query_range",
        &[("query", query), ("start", start), ("end", end), ("step", step)],
    )
    .await
    {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };
    Json(compact_range(&data)).into_response()
}

/// Truncate a `query_range` result to [`MAX_SERIES`] series.
fn compact_range(data: &Value) -> Value {
    let items = match data.get("result") {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    let (kept, total, truncated) = cap_list(items, MAX_SERIES);
    json!({
        "resultType": data.get("resultType").and_then(|v| v.as_str()).unwrap_or(""),
        "result": kept,
        "series_total": total,
        "truncated": truncated,
    })
}

#[derive(Deserialize)]
struct MetricsDiscoverParams {
    label: Option<String>,
    selector: Option<String>,
    prefix: Option<String>,
    limit: Option<usize>,
}

/// A Prometheus label name: `[a-zA-Z_][a-zA-Z0-9_]*`.
fn valid_label_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Filter by prefix, sort, cap. `limit` is clamped to 1..=[`MAX_DISCOVER`].
fn compact_discover(values: &Value, prefix: &str, limit: Option<usize>) -> Value {
    let cap = limit.unwrap_or(MAX_DISCOVER).clamp(1, MAX_DISCOVER);
    let mut names: Vec<String> = values
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if !prefix.is_empty() {
        names.retain(|n| n.starts_with(prefix));
    }
    names.sort();
    names.dedup();
    let total = names.len();
    names.truncate(cap);
    json!({"values": names, "total": total, "truncated": total > cap})
}

/// GET /api/metrics/discover[?label=&selector=&prefix=&limit=] — what can I
/// ask Prometheus for? With no `label`, the metric names (`__name__`); with
/// one, that label's values (for example `job` or `instance`). `selector` is
/// a series selector narrowing the lookup (`{job="node"}`), `prefix` filters
/// by leading characters, results are sorted and capped at 500.
async fn metrics_discover(Query(p): Query<MetricsDiscoverParams>) -> axum::response::Response {
    let label = p.label.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or("__name__");
    if !valid_label_name(label) {
        return AppError::BadRequest(
            "label must be a Prometheus label name ([a-zA-Z_][a-zA-Z0-9_]*)".into(),
        )
        .into_response();
    }
    let mut params: Vec<(&str, String)> = Vec::new();
    if let Some(sel) = p.selector.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        params.push(("match[]", sel.to_string()));
    }
    let data = match prom_get_data(&format!("/api/v1/label/{label}/values"), &params).await {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };
    let prefix = p.prefix.as_deref().unwrap_or("").trim();
    let mut out = compact_discover(&data, prefix, p.limit);
    out["label"] = json!(label);
    Json(out).into_response()
}

#[derive(Deserialize)]
struct AlertsListParams {
    state: Option<String>,
    alertmanager: Option<bool>,
}

fn state_rank(s: &str) -> u8 {
    match s {
        "firing" => 0,
        "pending" => 1,
        _ => 2,
    }
}

/// Parse a Prometheus `for` (already seconds in the rules API) to seconds.
fn rule_for_secs(rule: &Value) -> Value {
    rule.get("duration").cloned().unwrap_or_else(|| json!(0))
}

/// Merge `/api/v1/rules?type=alert` (what can alert, and in what state) with
/// `/api/v1/alerts` (the live instances) into one compact row per alerting
/// rule, firing first. `state_filter` is `firing|pending|inactive` or empty.
fn compact_alert_rules(rules: &Value, alerts: &Value, state_filter: &str) -> Value {
    let mut instances: std::collections::HashMap<String, Vec<Value>> = Default::default();
    for a in alerts.get("alerts").and_then(|v| v.as_array()).into_iter().flatten() {
        let name = a.pointer("/labels/alertname").and_then(|v| v.as_str()).unwrap_or("").to_string();
        instances.entry(name).or_default().push(json!({
            "state": a.get("state").cloned().unwrap_or(Value::Null),
            "activeAt": a.get("activeAt").cloned().unwrap_or(Value::Null),
            "value": a.get("value").cloned().unwrap_or(Value::Null),
            "labels": a.get("labels").cloned().unwrap_or(Value::Null),
        }));
    }
    let mut rows: Vec<Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = Default::default();
    for g in rules.get("groups").and_then(|v| v.as_array()).into_iter().flatten() {
        for r in g.get("rules").and_then(|v| v.as_array()).into_iter().flatten() {
            if r.get("type").and_then(|v| v.as_str()) != Some("alerting") {
                continue;
            }
            let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let state = r.get("state").and_then(|v| v.as_str()).unwrap_or("inactive").to_string();
            seen.insert(name.clone());
            let inst = instances.get(&name).cloned().unwrap_or_default();
            // Earliest activeAt among the instances (RFC3339 sorts as text).
            let active_at = inst
                .iter()
                .filter_map(|i| i.get("activeAt").and_then(|v| v.as_str()))
                .min()
                .map(|s| json!(s))
                .unwrap_or(Value::Null);
            let (shown, count, _) = cap_list(inst, MAX_INSTANCES_PER_RULE);
            rows.push(json!({
                "name": name,
                "state": state,
                "severity": r.pointer("/labels/severity").cloned().unwrap_or(Value::Null),
                "summary": r.pointer("/annotations/summary").cloned().unwrap_or(Value::Null),
                "activeAt": active_at,
                "for_seconds": rule_for_secs(r),
                "group": g.get("name").cloned().unwrap_or(Value::Null),
                "instance_count": count,
                "instances": shown,
            }));
        }
    }
    // Live alerts whose rule the rules API did not list (another ruler).
    for (name, inst) in &instances {
        if seen.contains(name) {
            continue;
        }
        let state = inst.first().and_then(|i| i.get("state")).and_then(|v| v.as_str()).unwrap_or("firing");
        let count = inst.len();
        rows.push(json!({
            "name": name,
            "state": state,
            "severity": inst[0].pointer("/labels/severity").cloned().unwrap_or(Value::Null),
            "summary": Value::Null,
            "activeAt": inst.iter().filter_map(|i| i.get("activeAt").and_then(|v| v.as_str())).min().map(|s| json!(s)).unwrap_or(Value::Null),
            "for_seconds": Value::Null,
            "group": Value::Null,
            "instance_count": count,
            "instances": inst.iter().take(MAX_INSTANCES_PER_RULE).cloned().collect::<Vec<_>>(),
        }));
    }
    if !state_filter.is_empty() {
        rows.retain(|r| r.get("state").and_then(|v| v.as_str()) == Some(state_filter));
    }
    rows.sort_by(|a, b| {
        let key = |v: &Value| (
            state_rank(v.get("state").and_then(|s| s.as_str()).unwrap_or("")),
            v.get("name").and_then(|s| s.as_str()).unwrap_or("").to_string(),
        );
        key(a).cmp(&key(b))
    });
    let firing = rows.iter().filter(|r| r["state"] == "firing").count();
    let pending = rows.iter().filter(|r| r["state"] == "pending").count();
    let (kept, total, truncated) = cap_list(rows, MAX_ALERT_ROWS);
    json!({"rules": kept, "rules_total": total, "firing": firing, "pending": pending, "truncated": truncated})
}

/// Compact one Alertmanager `/api/v2/alerts` array: state (active,
/// suppressed), silenced/inhibited-by ids, receivers.
fn compact_alertmanager(alerts: &Value) -> Value {
    let arr = alerts.as_array().cloned().unwrap_or_default();
    let rows: Vec<Value> = arr
        .iter()
        .map(|a| {
            let ids = |p: &str| a.pointer(p).cloned().unwrap_or_else(|| json!([]));
            json!({
                "alertname": a.pointer("/labels/alertname").cloned().unwrap_or(Value::Null),
                "severity": a.pointer("/labels/severity").cloned().unwrap_or(Value::Null),
                "summary": a.pointer("/annotations/summary").cloned().unwrap_or(Value::Null),
                "state": a.pointer("/status/state").cloned().unwrap_or(Value::Null),
                "silencedBy": ids("/status/silencedBy"),
                "inhibitedBy": ids("/status/inhibitedBy"),
                "startsAt": a.get("startsAt").cloned().unwrap_or(Value::Null),
                "receivers": a.get("receivers").and_then(|r| r.as_array()).map(|r| {
                    r.iter().filter_map(|x| x.get("name").cloned()).collect::<Vec<_>>()
                }).unwrap_or_default(),
                "labels": a.get("labels").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let (kept, total, truncated) = cap_list(rows, MAX_AM_ALERTS);
    let count = |s: &str| kept.iter().filter(|r| r["state"] == s).count();
    json!({"alerts": kept, "alerts_total": total, "truncated": truncated,
           "suppressed": count("suppressed")})
}

/// GET /api/alerts/list[?state=firing|pending|inactive&alertmanager=true] —
/// every alerting rule with its state, severity, summary, `activeAt` and
/// `for`, firing first, merged from Prometheus `/api/v1/rules` and
/// `/api/v1/alerts`. Alertmanager's own view (active, silenced, inhibited) is
/// added under `alertmanager` unless `alertmanager=false`; if Alertmanager
/// cannot be reached that section reports the error and the Prometheus half
/// still answers. Read-only: nothing here silences or acknowledges.
async fn alerts_list(Query(p): Query<AlertsListParams>) -> axum::response::Response {
    let state = p.state.as_deref().map(str::trim).unwrap_or("");
    if !matches!(state, "" | "firing" | "pending" | "inactive") {
        return AppError::BadRequest("state must be firing, pending or inactive".into()).into_response();
    }
    let rules = match prom_get_data("/api/v1/rules", &[("type", "alert".to_string())]).await {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };
    let alerts = match prom_get_data("/api/v1/alerts", &[]).await {
        Ok(d) => d,
        Err(e) => return e.into_response(),
    };
    let mut out = compact_alert_rules(&rules, &alerts, state);
    if p.alertmanager.unwrap_or(true) {
        let am = obs_get_json(
            &alertmanager_base(),
            "/api/v2/alerts",
            &[
                ("active", "true".to_string()),
                ("silenced", "true".to_string()),
                ("inhibited", "true".to_string()),
            ],
            "alertmanager",
        )
        .await;
        out["alertmanager"] = match am {
            Ok(v) if v.is_array() => compact_alertmanager(&v),
            Ok(v) => json!({"error": format!(
                "alertmanager answered something other than an alert list: {}",
                v.to_string().chars().take(200).collect::<String>())}),
            Err(e) => json!({"error": e.to_string()}),
        };
    }
    Json(out).into_response()
}

// ── Self-modify gate + rate limits + JSONL audit ────────────────

/// Gate for the state-changing stack-lifecycle handlers
/// (`/api/mesh/restart`, `/api/mesh/rebuild`).
///
/// These used to be gated on the `NOO_SELF_MODIFY_ENABLED` flag, whose real
/// purpose was to keep the MODEL from restarting its own stack — the two MCP
/// tools that drove them (`noomesh_restart`, `noomesh_rebuild`) are gone, so
/// the flag went with them. Deleting a default-off flag without replacing it
/// would have OPENED these endpoints, so the gate is replaced, not removed.
///
/// Deliberately `Role::Admin`, not `is_operator`, and deliberately not the
/// cluster HMAC — the same reasoning as `users::scope_mutation_guard`: writing
/// a command into the host spool restarts the fleet, and the fleet-shared
/// secret is not attributable to a person. A restart must name who ordered it,
/// because the `noo_security_audit` row is only worth keeping if the actor in
/// it is a human.
fn mesh_lifecycle_admin_guard(
    ctx: &Option<Extension<RequesterCtx>>,
) -> Result<&RequesterCtx, AppError> {
    match ctx {
        None => Err(AppError::Forbidden(
            "stack restart/rebuild requires a logged-in admin — the cluster HMAC \
             is shared and not attributable; run `noo auth login` first"
                .into(),
        )),
        Some(Extension(r)) if r.role >= crate::auth::Role::Admin => Ok(r),
        Some(_) => Err(AppError::Forbidden(
            "admin role required to restart or rebuild the stack".into(),
        )),
    }
}

/// Append a row to the self-modify JSONL audit trail
/// (NOO_SELF_MODIFY_AUDIT_PATH, default /data/noo_self_modify_audit.jsonl) —
/// the same file the Python fallback handlers write, so the operator keeps a
/// single chronological trail. Best-effort; never errors into the caller.
pub(crate) async fn self_modify_audit(entry: Value) {
    let write = async {
        let mut entry = entry;
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("ts".into(), json!(chrono::Utc::now().to_rfc3339()));
        }
        let path = std::env::var("NOO_SELF_MODIFY_AUDIT_PATH")
            .unwrap_or_else(|_| "/data/noo_self_modify_audit.jsonl".into());
        if let Some(parent) = std::path::Path::new(&path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        use tokio::io::AsyncWriteExt;
        let mut fh = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        fh.write_all(format!("{entry}\n").as_bytes()).await?;
        Ok::<(), std::io::Error>(())
    };
    if let Err(e) = write.await {
        tracing::warn!(error = %e, "self_modify_audit_write_failed");
    }
}

/// cloud vs local from a model name (`_classify_provider`). Cloud rates
/// apply to claude/gpt/gemini; unknown/missing defaults to the looser
/// local budget.
fn classify_provider(model_hint: Option<&str>) -> &'static str {
    let Some(hint) = model_hint.filter(|h| !h.is_empty()) else {
        return "local";
    };
    let m = hint.to_lowercase();
    if ["claude-", "gpt-", "gemini-", "anthropic/", "openai/"]
        .iter()
        .any(|p| m.starts_with(p))
    {
        "cloud"
    } else {
        "local"
    }
}

/// Rolling window for both budgets (`_RATE_WINDOW_SECONDS`).
const SELF_MODIFY_RATE_WINDOW_SECS: f64 = 3600.0;

/// Per-(provider, action) budget, env-overridable — same names and
/// defaults as Python `_rate_limits()`.
fn self_modify_rate_limit(provider: &str, action: &str) -> i64 {
    let default = match (provider, action) {
        ("cloud", "restart") => 3,
        ("cloud", "rebuild") => 1,
        ("local", "restart") => 10,
        ("local", "rebuild") => 5,
        _ => 0,
    };
    let key = format!(
        "NOO_SELF_MODIFY_RATE_{}_{}",
        provider.to_ascii_uppercase(),
        action.to_ascii_uppercase()
    );
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

/// In-process fallback bucket when Redis is unavailable — the direct
/// equivalent of Python's `_RATE_BUCKET` (cleared on restart).
fn self_modify_local_bucket()
-> &'static std::sync::Mutex<std::collections::HashMap<(String, String), Vec<f64>>> {
    static BUCKET: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<(String, String), Vec<f64>>>,
    > = std::sync::OnceLock::new();
    BUCKET.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Returns (allowed, used_in_window, limit); records the attempt if
/// allowed — same semantics as Python `_check_rate_limit` (the returned
/// `used` includes the current attempt when allowed).
///
/// Storage: Redis sliding-window ZSET `noo:self_modify:rate:{provider}:{action}`
/// (member = attempt nanos, score = unix seconds, TTL 2h) so the budget
/// survives gateway restarts; falls back to Python's in-memory-bucket
/// behaviour when Redis is down. NB: the Python fallback handler keeps its
/// own in-process bucket — the budgets are per-engine, not shared (Python
/// had no Redis state to share; with this route shadowing the catch-all,
/// HTTP traffic only ever hits this one).
async fn self_modify_check_rate_limit(
    state: &AppState,
    provider: &str,
    action: &str,
) -> (bool, i64, i64) {
    let limit = self_modify_rate_limit(provider, action);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let cutoff = now - SELF_MODIFY_RATE_WINDOW_SECS;

    if let Some(redis) = state.redis.as_ref() {
        let key = format!("noo:self_modify:rate:{provider}:{action}");
        // Prune entries older than the window (few members; limits are ≤10).
        for stale in redis.zrangebyscore(&key, 0.0, cutoff).await {
            redis.zrem(&key, &stale).await;
        }
        let used = redis.zrangebyscore(&key, cutoff, f64::MAX).await.len() as i64;
        if used >= limit {
            return (false, used, limit);
        }
        let member = format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        redis.zadd(&key, &member, now).await;
        redis.expire(&key, (SELF_MODIFY_RATE_WINDOW_SECS as i64) * 2).await;
        return (true, used + 1, limit);
    }

    let mut map = self_modify_local_bucket()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let bucket = map
        .entry((provider.to_string(), action.to_string()))
        .or_default();
    bucket.retain(|t| *t > cutoff);
    if bucket.len() as i64 >= limit {
        return (false, bucket.len() as i64, limit);
    }
    bucket.push(now);
    (true, bucket.len() as i64, limit)
}

/// Model hint: `body.get("_llm_provider") or body.get("model") or None`.
fn model_hint_of(body: &Value) -> Option<String> {
    for key in ["_llm_provider", "model"] {
        if let Some(s) = body.get(key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// POST /api/mesh/restart — body {service, reason, _llm_provider?|model?}.
/// [ported from workers/admin.py::_mesh_restart (worker.api.mesh.restart) 2026-07-18]
///
/// Restart one PAI container via the host-watcher spool (the gateway has
/// ZERO Docker access). Operator-only: requires a logged-in **Admin**
/// (`mesh_lifecycle_admin_guard`) plus the
/// per-LLM-provider rate limit; every attempt (including rejections) is
/// written to the self-modify JSONL trail, and queued/failed outcomes are
/// additionally recorded in noo_security_audit. Fire-and-forget — the host
/// daemon owns timing (a noo-gateway self-restart lands after the response
/// has flushed).
async fn mesh_restart(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    body: Option<Json<Value>>,
) -> axum::response::Response {
    let admin = match mesh_lifecycle_admin_guard(&ctx) {
        Ok(r) => r.sub.clone(),
        Err(e) => {
            self_modify_audit(json!({
                "action": "restart", "result": "rejected_not_admin",
            }))
            .await;
            return e.into_response();
        }
    };
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let service = body_str_trim(&body, "service");
    let reason = body_str_trim(&body, "reason");
    let model_hint = model_hint_of(&body);

    if service.is_empty() {
        return AppError::BadRequest("service required".into()).into_response();
    }
    if reason.is_empty() {
        return AppError::BadRequest("reason required (audit log)".into()).into_response();
    }
    if !is_noo_container(&service) {
        return AppError::BadRequest(format!(
            "refusing to restart non-PAI container '{service}'"
        ))
        .into_response();
    }

    let provider = classify_provider(model_hint.as_deref());
    let (allowed, used, limit) = self_modify_check_rate_limit(&state, provider, "restart").await;
    if !allowed {
        self_modify_audit(json!({
            "action": "restart", "service": service, "reason": reason,
            "provider": provider, "result": "rejected_rate_limit",
            "used": used, "limit": limit,
        }))
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("rate limit exceeded for provider={provider}"),
                "used_in_window": used, "limit_per_hour": limit,
            })),
        )
            .into_response();
    }

    let is_self = service == "noo-gateway";
    let spool_path = host_spool_write_command("restart", &service, &[], "mesh_restart").await;
    let result = if spool_path.is_some() { "queued_spool" } else { "spool_write_failed" };
    self_modify_audit(json!({
        "action": "restart", "service": service, "reason": reason,
        "provider": provider, "result": result, "spool_command": spool_path,
    }))
    .await;
    let actor = if admin.is_empty() { "admin".to_string() } else { admin };
    crate::routes::core::audit_event(
        &state.db,
        "mesh_restart",
        "warning",
        &actor,
        &service,
        result,
        json!({ "reason": reason, "provider": provider, "spool_command": &spool_path }),
    )
    .await;

    let Some(spool_path) = spool_path else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "could not queue restart command (host spool write failed)",
                "service": service,
            })),
        )
            .into_response();
    };
    Json(json!({
        "queued": true, "service": service,
        "self_restart": is_self,
        "spool_command": spool_path,
        "via": "host_watcher_spool",
        "rate_limit": {"provider": provider, "used": used, "limit_per_hour": limit},
    }))
    .into_response()
}

/// POST /api/mesh/rebuild — body {service, reason, _llm_provider?|model?}.
/// [ported from workers/admin.py::_mesh_rebuild (worker.api.mesh.rebuild) 2026-07-18]
///
/// Quick per-service rebuild (stop + re-create with current code mounts, no
/// image build) via the host-watcher spool. Same Admin-role gate + audit
/// treatment as restart but a separate, stricter rate budget. noo-gateway is refused —
/// its compiled Rust binary needs a full host-side rebuild.
async fn mesh_rebuild(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    body: Option<Json<Value>>,
) -> axum::response::Response {
    let admin = match mesh_lifecycle_admin_guard(&ctx) {
        Ok(r) => r.sub.clone(),
        Err(e) => {
            self_modify_audit(json!({
                "action": "rebuild", "result": "rejected_not_admin",
            }))
            .await;
            return e.into_response();
        }
    };
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let service = body_str_trim(&body, "service");
    let reason = body_str_trim(&body, "reason");
    let model_hint = model_hint_of(&body);

    if service.is_empty() {
        return AppError::BadRequest("service required".into()).into_response();
    }
    if reason.is_empty() {
        return AppError::BadRequest("reason required (audit log)".into()).into_response();
    }
    if !is_noo_container(&service) {
        return AppError::BadRequest(format!(
            "refusing to rebuild non-PAI container '{service}'"
        ))
        .into_response();
    }

    let provider = classify_provider(model_hint.as_deref());
    let (allowed, used, limit) = self_modify_check_rate_limit(&state, provider, "rebuild").await;
    if !allowed {
        self_modify_audit(json!({
            "action": "rebuild", "service": service, "reason": reason,
            "provider": provider, "result": "rejected_rate_limit",
            "used": used, "limit": limit,
        }))
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("rate limit exceeded for provider={provider}"),
                "used_in_window": used, "limit_per_hour": limit,
            })),
        )
            .into_response();
    }

    // Quick rebuild won't pick up compiled Rust changes — reject noo-gateway
    // with the same guidance string as the Python handler.
    if service == "noo-gateway" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "'{service}' uses a compiled Rust binary; quick rebuild \
                     won't pick up Rust source changes. Run \
                     `noo stack rebuild gateway` from the host instead."
                ),
                "hint": "For picking up Python edits, restart the service \
                         instead: POST /api/mesh/restart, or \
                         `noo stack restart <service>` from the host.",
            })),
        )
            .into_response();
    }

    let spool_path = host_spool_write_command("rebuild", &service, &[], "mesh_rebuild").await;
    let result = if spool_path.is_some() { "queued_spool" } else { "spool_write_failed" };
    self_modify_audit(json!({
        "action": "rebuild", "service": service, "reason": reason,
        "provider": provider, "result": result, "spool_command": spool_path,
    }))
    .await;
    let actor = if admin.is_empty() { "admin".to_string() } else { admin };
    crate::routes::core::audit_event(
        &state.db,
        "mesh_rebuild",
        "warning",
        &actor,
        &service,
        result,
        json!({ "reason": reason, "provider": provider, "spool_command": &spool_path }),
    )
    .await;

    let Some(spool_path) = spool_path else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "could not queue rebuild command (host spool write failed)",
                "service": service,
            })),
        )
            .into_response();
    };
    Json(json!({
        "queued": true, "service": service, "self_rebuild": false,
        "spool_command": spool_path,
        "via": "host_watcher_spool",
        "rate_limit": {"provider": provider, "used": used, "limit_per_hour": limit},
    }))
    .into_response()
}

// ═══════════════════════════════════════════════════════════════
// Tests — approval decide semantics (WP-4a)
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod job_type_routing_tests {
    use super::*;
    use crate::job_types::{self, Executor};

    #[test]
    fn every_gateway_local_type_has_an_executor_arm() {
        // Mirrors the match in `run_gateway_local`. A new `Gateway` row in
        // the table without an arm there would panic at runtime on the
        // first submit; this fails at test time instead.
        for (name, ex) in job_types::JOB_TYPES {
            if *ex == Executor::Gateway {
                assert!(
                    matches!(*name, "test_run"),
                    "gateway-local job type '{name}' has no arm in run_gateway_local"
                );
            }
        }
    }

    /// A submit while the gateway has no Redis client is a retryable 503
    /// with a machine-readable code and `Retry-After` (2026-10-15: every node
    /// poke of a `noo upgrade --all` got a bare 500 "Redis not connected").
    #[tokio::test]
    async fn no_redis_client_is_a_retryable_503_with_a_code() {
        let r = redis_not_connected().into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            r.headers().get(axum::http::header::RETRY_AFTER).and_then(|v| v.to_str().ok()),
            Some(REDIS_RETRY_AFTER_SECS.to_string().as_str()),
        );
        let body = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "redis_reconnecting");
        assert_eq!(v["retry_after_secs"], REDIS_RETRY_AFTER_SECS);
        assert!(v["detail"].as_str().is_some_and(|d| d.contains("Redis not connected")));
    }

    #[test]
    fn suite_is_read_from_both_body_shapes() {
        assert_eq!(suite_from_payload(&json!({"suite": "smoke"})), "smoke");
        assert_eq!(
            suite_from_payload(&json!({"params": {"suite": "smoke"}})),
            "smoke"
        );
        assert_eq!(suite_from_payload(&json!({})), "");
    }

    #[test]
    fn node_queue_accepts_only_node_executable_types() {
        // The guard at the top of `submit_job_to_redis`. `test_run` is
        // gateway-local and must never reach `tasks.dispatch.*`, which is
        // exactly the bug this change fixes.
        assert_eq!(job_types::executor_for("inference"), Some(Executor::Node));
        assert_ne!(job_types::executor_for("test_run"), Some(Executor::Node));
        assert_eq!(job_types::executor_for("nonesuch"), None);
    }
}

#[cfg(test)]
mod job_ownership_tests {
    use super::{clamp_user_job_knobs, job_listed, job_mutable_by, job_to_json, job_visible, user_submit_refusal, USER_JOB_PAYLOAD_MAX_BYTES};
    use crate::auth::{account_of, scoped_account, RequesterCtx, Role};
    use crate::routes::AppError;
    use serde_json::json;

    /// `job_visible` is the ONE answer to "whose job is
    /// this", shared by list, detail, history, cancel and reprioritize —
    /// so these five routes cannot drift apart the way cancel (Admin+) and
    /// list (nobody) had.
    #[test]
    fn an_unscoped_caller_sees_every_job() {
        // Operator+, and internal cluster services.
        assert!(job_visible("ada", None));
        assert!(job_visible("", None));
    }

    #[test]
    fn a_user_sees_its_own() {
        assert!(job_visible("ada", Some("ada")));
    }

    #[test]
    fn a_user_does_not_see_another_tenants() {
        assert!(!job_visible("bob", Some("ada")));
    }

    /// An empty owner is UNOWNED fleet work (autonomy, heartbeat, cluster-HMAC,
    /// rows from before the field shipped). Operator+ sees it; a User does
    /// not, so a fleet job's payload never reaches a person and an id never
    /// confirms that one exists (the handlers answer 404, not 403).
    #[test]
    fn an_unowned_job_is_invisible_to_a_user_and_visible_to_operator() {
        assert!(!job_visible("", Some("ada")));
        assert!(!job_visible("", Some("bob")));
        assert!(job_visible("", None));
    }

    /// A User sees its own account's jobs and nobody else's, whichever MCP
    /// session label submitted them.
    #[test]
    fn a_user_sees_only_its_own_jobs_not_another_users_or_the_fleets() {
        assert!(job_visible("alice", Some("alice")));
        assert!(job_visible("alice/codex-x", Some("alice")));
        assert!(!job_visible("bob", Some("alice")));
        assert!(!job_visible("bob/codex-x", Some("alice")));
        assert!(!job_visible("", Some("alice")));
    }

    /// The kiosk token's list never carries a payload (a shared screen), while
    /// every other caller's list still does.
    #[test]
    fn the_kiosk_list_never_carries_a_payload() {
        let mut m = std::collections::HashMap::new();
        m.insert("job_id".to_string(), "j1".to_string());
        m.insert("status".to_string(), "queued".to_string());
        m.insert("payload".to_string(), r#"{"prompt":"secret"}"#.to_string());
        let kiosk = job_to_json(&m, true);
        assert!(kiosk.get("payload").is_none(), "{kiosk}");
        assert_eq!(kiosk["job_id"], "j1");
        assert!(!kiosk.to_string().contains("secret"));
        assert_eq!(job_to_json(&m, false)["payload"]["prompt"], "secret");
    }

    /// The kiosk display lists the whole queue, so its token (and only a
    /// token with the kiosk scope: `fleet`) also lists unowned jobs. It
    /// never sees another person's job, and a person never gets `fleet`.
    #[test]
    fn only_a_kiosk_token_lists_the_unowned_fleet_jobs() {
        assert!(job_listed("", Some("kiosk:hall"), true));
        assert!(!job_listed("bob", Some("kiosk:hall"), true));
        assert!(!job_listed("", Some("alice"), false));
        assert!(job_listed("alice", Some("alice"), false));
        assert!(job_listed("bob", None, false));
    }

    /// Not a prefix match, not a case fold — the owner is the account name
    /// the JWT carried.
    #[test]
    fn the_match_is_exact() {
        assert!(!job_visible("ada2", Some("ada")));
        assert!(!job_visible("Ada", Some("ada")));
    }

    fn requester(sub: &str, role: Role) -> RequesterCtx {
        RequesterCtx { sub: sub.into(), scopes: vec!["read".into()], role, harness: None, act: None }
    }

    /// The owner of a door-submitted job is the ACCOUNT, whatever the MCP
    /// session label, so the CLI and other sessions of the same person see it.
    #[test]
    fn owner_is_the_account_not_the_session_label() {
        assert_eq!(account_of("alice/codex-x"), "alice");
        assert_eq!(account_of("alice/other"), "alice");
        assert_eq!(account_of("alice"), "alice");
        assert_ne!(account_of("bob/codex-x"), account_of("alice/codex-x"));
        let a = scoped_account(Some(&requester("alice/codex-x", Role::User)), None).unwrap();
        assert_eq!(a.as_deref(), Some("alice"));
        // Operator+ stays unscoped.
        assert_eq!(scoped_account(Some(&requester("root/x", Role::Operator)), None).unwrap(), None);
    }

    #[test]
    fn visibility_compares_accounts_so_legacy_session_owners_still_match() {
        // A row written with the raw sub before this change.
        assert!(job_visible("alice/codex-x", Some("alice")));
        assert!(job_visible("alice", Some("alice")));
        assert!(!job_visible("bob/codex-x", Some("alice")));
        assert!(!job_visible("alice2/x", Some("alice")));
    }

    #[test]
    fn a_user_changes_only_its_own_accounts_jobs() {
        // own account, from any session label
        assert!(job_mutable_by("alice", Some("alice")));
        assert!(job_mutable_by("alice/codex-x", Some("alice")));
        // someone else's, and unowned (fleet) jobs: refused (the handler says 404)
        assert!(!job_mutable_by("bob", Some("alice")));
        assert!(!job_mutable_by("", Some("alice")));
        // Operator+ / internal: anything, unowned included
        assert!(job_mutable_by("", None));
        assert!(job_mutable_by("bob", None));
        // and a User cannot even SEE an unowned job
        assert!(!job_visible("", Some("alice")));
    }

    #[test]
    fn a_user_may_submit_inference_and_nothing_else() {
        let p = json!({"prompt": "hi"});
        assert!(user_submit_refusal("inference", &p, None, None, None, false).is_ok());
        assert!(user_submit_refusal("inference", &p, Some("vllm"), None, Some(0.0), false).is_ok());
        let refused = [
            "fetch_bundle", "model_file", "model_download", "tool_exec", "test_run",
            "background_graph", "background_cache", "embedding", "", "Inference",
        ];
        assert!(refused.len() >= 8, "vacuous");
        for t in refused {
            let e = user_submit_refusal(t, &p, None, None, None, false).unwrap_err();
            assert!(matches!(e, AppError::Forbidden(_)), "{t}: {e}");
            assert!(e.to_string().contains("inference"), "the refusal names the allowed set: {e}");
        }
    }

    #[test]
    fn a_user_submit_is_bounded() {
        let ok = json!({"prompt": "hi"});
        for bad in [json!("a string"), json!([1, 2]), json!(null), json!(7)] {
            assert!(matches!(user_submit_refusal("inference", &bad, None, None, None, false), Err(AppError::BadRequest(_))), "{bad}");
        }
        let big = json!({"prompt": "x".repeat(USER_JOB_PAYLOAD_MAX_BYTES + 1)});
        assert!(matches!(user_submit_refusal("inference", &big, None, None, None, false), Err(AppError::BadRequest(_))));
        let under = json!({"prompt": "x".repeat(USER_JOB_PAYLOAD_MAX_BYTES - 100)});
        assert!(user_submit_refusal("inference", &under, None, None, None, false).is_ok());
        assert!(matches!(user_submit_refusal("inference", &ok, Some("tensorrt"), None, None, false), Err(AppError::BadRequest(_))));
        assert!(matches!(user_submit_refusal("inference", &ok, None, Some("node-1"), None, false), Err(AppError::Forbidden(_))));
        assert!(matches!(user_submit_refusal("inference", &ok, None, None, Some(80.0), false), Err(AppError::Forbidden(_))));
        assert!(matches!(user_submit_refusal("inference", &ok, None, None, None, true), Err(AppError::Forbidden(_))));
        // empty strings are "unset", not a pin
        assert!(user_submit_refusal("inference", &ok, Some(""), Some(""), None, false).is_ok());
    }

    #[test]
    fn user_knobs_are_clamped() {
        assert_eq!(clamp_user_job_knobs(99, Some(99_999), Some(50), Some(10_000_000)), (5, (Some(600), Some(2), Some(3600))));
        assert_eq!(clamp_user_job_knobs(-3, None, None, None), (0, (None, None, None)));
        assert_eq!(clamp_user_job_knobs(3, Some(30), Some(0), Some(60)), (3, (Some(30), Some(0), Some(60))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Operator observability (range / discover / alerts) ──────────
    // Pure parts only, fed the shapes Prometheus and Alertmanager return.
    // Fixtures use documentation addresses (192.0.2.0/24).

    #[test]
    fn range_arguments_are_validated_and_the_point_cap_is_prometheus_s() {
        // 1h at 60s = 61 points.
        assert_eq!(validate_range("1700000000", "1700003600", "60").unwrap(), 61);
        assert_eq!(validate_range("2026-01-01T00:00:00Z", "2026-01-01T06:00:00Z", "5m").unwrap(), 73);
        // Exactly 11000 points passes, 11001 is refused with the number named.
        assert_eq!(validate_range("0", "10999", "1").unwrap(), 11_000);
        let why = validate_range("0", "11000", "1").unwrap_err();
        assert!(why.contains("11001") && why.contains("11000"), "{why}");
        assert!(validate_range("100", "50", "15").unwrap_err().contains("before start"));
        for bad in ["0", "-5", "abc", "5x", "", "NaN"] {
            assert!(validate_range("0", "100", bad).is_err(), "step {bad:?} accepted");
        }
        assert!(validate_range("yesterday", "100", "15").is_err());
        assert!(validate_range("0", "tomorrow", "15").is_err());
    }

    #[test]
    fn steps_parse_like_prometheus_durations() {
        assert_eq!(parse_prom_step("15"), Some(15.0));
        assert_eq!(parse_prom_step("0.5"), Some(0.5));
        assert_eq!(parse_prom_step("30s"), Some(30.0));
        assert_eq!(parse_prom_step("5m"), Some(300.0));
        assert_eq!(parse_prom_step("1h"), Some(3600.0));
        assert_eq!(parse_prom_step("2d"), Some(172_800.0));
        assert_eq!(parse_prom_step("500ms"), Some(0.5));
        assert_eq!(parse_prom_step("0s"), None);
        assert_eq!(parse_prom_step("1y"), None);
    }

    #[test]
    fn range_results_are_truncated_to_100_series_and_say_so() {
        let series: Vec<Value> = (0..130)
            .map(|i| json!({"metric": {"instance": format!("192.0.2.{}:9100", i % 250)}, "values": [[1700000000, "1"]]}))
            .collect();
        let out = compact_range(&json!({"resultType": "matrix", "result": series}));
        assert_eq!(out["result"].as_array().unwrap().len(), 100);
        assert_eq!(out["series_total"], 130);
        assert_eq!(out["truncated"], true);
        assert_eq!(out["resultType"], "matrix");
        let small = compact_range(&json!({"resultType": "matrix", "result": [{"metric": {}, "values": []}]}));
        assert_eq!(small["truncated"], false);
        assert_eq!(small["series_total"], 1);
        // Garbage in, empty out, never a panic.
        assert_eq!(compact_range(&Value::Null)["result"], json!([]));
    }

    #[test]
    fn prometheus_error_envelopes_surface_the_promql_complaint() {
        let ok = json!({"status": "success", "data": {"resultType": "matrix", "result": []}});
        assert_eq!(prom_data(&ok).unwrap()["resultType"], "matrix");
        let bad = json!({"status": "error", "errorType": "bad_data", "error": "parse error: unexpected end of input"});
        assert_eq!(prom_data(&bad).unwrap_err(), "bad_data: parse error: unexpected end of input");
        assert_eq!(prom_data(&json!({})).unwrap_err(), "query failed");
    }

    #[test]
    fn discover_filters_sorts_dedups_and_caps() {
        let names = json!(["up", "noo_node_load", "node_load1", "noo_gpu_utilization_percent", "up", 7]);
        let all = compact_discover(&names, "", None);
        assert_eq!(all["values"], json!(["node_load1", "noo_gpu_utilization_percent", "noo_node_load", "up"]));
        assert_eq!(all["total"], 4);
        let noo = compact_discover(&names, "noo_", None);
        assert_eq!(noo["values"], json!(["noo_gpu_utilization_percent", "noo_node_load"]));
        let one = compact_discover(&names, "", Some(1));
        assert_eq!(one["values"].as_array().unwrap().len(), 1);
        assert_eq!(one["truncated"], true);
        // Capped even when the caller asks for more than the ceiling.
        let many: Vec<Value> = (0..900).map(|i| json!(format!("m_{i:04}"))).collect();
        let capped = compact_discover(&Value::Array(many), "", Some(10_000));
        assert_eq!(capped["values"].as_array().unwrap().len(), 500);
        assert_eq!(capped["total"], 900);
        assert_eq!(capped["truncated"], true);
        // limit 0 is clamped up, not an empty answer.
        assert_eq!(compact_discover(&names, "", Some(0))["values"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn label_names_are_checked_before_they_reach_the_url() {
        assert!(valid_label_name("__name__") && valid_label_name("node_id") && valid_label_name("job"));
        for bad in ["", "9x", "a/b", "a b", "../x", "a?b=c", "job%2F"] {
            assert!(!valid_label_name(bad), "{bad:?} accepted");
        }
    }

    fn rules_fixture() -> Value {
        json!({"groups": [{"name": "node", "rules": [
            {"type": "alerting", "name": "HighLoad", "state": "firing", "duration": 300,
             "labels": {"severity": "warning"}, "annotations": {"summary": "load above 8 on 192.0.2.10"},
             "alerts": []},
            {"type": "alerting", "name": "DiskFilling", "state": "pending", "duration": 600,
             "labels": {"severity": "critical"}, "annotations": {"summary": "disk 90%"}},
            {"type": "alerting", "name": "NodeDown", "state": "inactive", "duration": 0,
             "labels": {}, "annotations": {}},
            {"type": "recording", "name": "job:up:sum", "query": "sum(up)"}
        ]}]})
    }

    fn alerts_fixture() -> Value {
        json!({"alerts": [
            {"labels": {"alertname": "HighLoad", "instance": "192.0.2.10:9100", "severity": "warning"},
             "state": "firing", "activeAt": "2026-10-10T08:00:00Z", "value": "9.1"},
            {"labels": {"alertname": "HighLoad", "instance": "192.0.2.11:9100", "severity": "warning"},
             "state": "firing", "activeAt": "2026-10-10T07:30:00Z", "value": "8.4"},
            {"labels": {"alertname": "DiskFilling", "instance": "192.0.2.12:9100"},
             "state": "pending", "activeAt": "2026-10-10T08:05:00Z", "value": "0.91"},
            {"labels": {"alertname": "ExternalRule", "severity": "info"},
             "state": "firing", "activeAt": "2026-10-10T06:00:00Z", "value": "1"}
        ]})
    }

    #[test]
    fn alert_rules_merge_with_live_instances_firing_first() {
        let out = compact_alert_rules(&rules_fixture(), &alerts_fixture(), "");
        let rows = out["rules"].as_array().unwrap();
        let names: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
        // firing (HighLoad, ExternalRule), pending, inactive; recording rule dropped.
        assert_eq!(names, ["ExternalRule", "HighLoad", "DiskFilling", "NodeDown"]);
        assert_eq!(out["firing"], 2);
        assert_eq!(out["pending"], 1);
        let hl = &rows[1];
        assert_eq!(hl["severity"], "warning");
        assert_eq!(hl["summary"], "load above 8 on 192.0.2.10");
        assert_eq!(hl["for_seconds"], 300);
        assert_eq!(hl["instance_count"], 2);
        assert_eq!(hl["activeAt"], "2026-10-10T07:30:00Z", "earliest instance");
        let nd = &rows[3];
        assert_eq!(nd["activeAt"], Value::Null);
        assert_eq!(nd["severity"], Value::Null);
        // The rule the rules API did not list still shows, marked as ruleless.
        assert_eq!(rows[0]["group"], Value::Null);
    }

    #[test]
    fn alert_state_filter_and_row_cap() {
        let pending = compact_alert_rules(&rules_fixture(), &alerts_fixture(), "pending");
        assert_eq!(pending["rules"].as_array().unwrap().len(), 1);
        assert_eq!(pending["rules"][0]["name"], "DiskFilling");
        // Many instances of one rule are shown 5 at a time but counted fully.
        let many: Vec<Value> = (0..12)
            .map(|i| json!({"labels": {"alertname": "HighLoad", "instance": format!("192.0.2.{i}:9100")},
                            "state": "firing", "activeAt": "2026-10-10T08:00:00Z", "value": "9"}))
            .collect();
        let out = compact_alert_rules(&rules_fixture(), &json!({"alerts": many}), "firing");
        let hl = &out["rules"][0];
        assert_eq!(hl["instance_count"], 12);
        assert_eq!(hl["instances"].as_array().unwrap().len(), 5);
        // 250 rules cap at 200 and say so.
        let rules: Vec<Value> = (0..250)
            .map(|i| json!({"type": "alerting", "name": format!("R{i:03}"), "state": "inactive", "duration": 0}))
            .collect();
        let big = compact_alert_rules(&json!({"groups": [{"name": "g", "rules": rules}]}), &json!({"alerts": []}), "");
        assert_eq!(big["rules"].as_array().unwrap().len(), 200);
        assert_eq!(big["rules_total"], 250);
        assert_eq!(big["truncated"], true);
        // Empty / malformed upstream bodies are an empty list, not a panic.
        let none = compact_alert_rules(&Value::Null, &Value::Null, "");
        assert_eq!(none["rules"], json!([]));
    }

    #[test]
    fn alertmanager_alerts_are_compacted_with_silence_and_inhibit_ids() {
        let am = json!([
            {"labels": {"alertname": "HighLoad", "severity": "warning", "instance": "192.0.2.10:9100"},
             "annotations": {"summary": "load"}, "startsAt": "2026-10-10T08:00:00Z",
             "receivers": [{"name": "null"}],
             "status": {"state": "active", "silencedBy": [], "inhibitedBy": []}},
            {"labels": {"alertname": "NodeDown", "severity": "critical"},
             "annotations": {}, "startsAt": "2026-10-10T07:00:00Z", "receivers": [{"name": "null"}],
             "status": {"state": "suppressed", "silencedBy": ["s-1"], "inhibitedBy": []}}
        ]);
        let out = compact_alertmanager(&am);
        assert_eq!(out["alerts_total"], 2);
        assert_eq!(out["suppressed"], 1);
        assert_eq!(out["alerts"][0]["state"], "active");
        assert_eq!(out["alerts"][0]["receivers"], json!(["null"]));
        assert_eq!(out["alerts"][1]["silencedBy"], json!(["s-1"]));
        let many: Vec<Value> = (0..130).map(|i| json!({"labels": {"alertname": format!("A{i}")}, "status": {"state": "active"}})).collect();
        let capped = compact_alertmanager(&Value::Array(many));
        assert_eq!(capped["alerts"].as_array().unwrap().len(), 100);
        assert_eq!(capped["truncated"], true);
    }

    /// The transport is real, the upstream is a closed local port: the
    /// refusal must name the upstream and be a 503, not a bare reqwest error
    /// and not a hang. (Documentation address; nothing listens on 127.0.0.1:9.)
    #[tokio::test]
    async fn an_unreachable_upstream_is_a_named_503() {
        let err = obs_get_json("http://127.0.0.1:9", "/api/v1/alerts", &[], "prometheus")
            .await
            .unwrap_err();
        match err {
            AppError::Unavailable(m) => assert!(m.contains("prometheus unreachable at http://127.0.0.1:9"), "{m}"),
            other => panic!("expected Unavailable, got {other}"),
        }
        let none = obs_get_json("", "/x", &[], "alertmanager").await.unwrap_err();
        assert!(matches!(none, AppError::Unavailable(m) if m.contains("not configured")));
    }

    /// The `/ready` miss is named, not folded into `false`: a status with
    /// Loki's body, a bare status, or the transport error. The handler
    /// returns it as `loki_ready_detail` and logs it.
    #[test]
    fn a_loki_ready_miss_says_why() {
        assert_eq!(loki_ready_detail(Some(503), "Ingester not ready:\n waiting for 15s after being ready"),
            "answered 503: Ingester not ready: waiting for 15s after being ready");
        assert_eq!(loki_ready_detail(Some(500), "  "), "answered 500");
        assert!(loki_ready_detail(None, "error sending request: tls handshake eof").starts_with("no answer: "));
        assert!(loki_ready_detail(Some(503), &"x".repeat(1000)).len() < 260, "bounded");
        let src = include_str!("admin.rs");
        let body = &src[src.find("async fn logs_status(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains("\"loki_ready_detail\": detail"), "the reason is not returned");
        assert!(!body.contains("unwrap_or(false)"), "the probe folds its reason into false again");
    }

    // The decide route's semantics live in three pure helpers so they are
    // testable without a database (repo convention — no DB-backed route
    // harness exists): body parsing, actor/trust resolution, and the
    // pending-only state machine. The handler is a thin composition.

    fn ctx(scopes: &[&str]) -> Option<axum::Extension<crate::auth::RequesterCtx>> {
        // Role derived from scopes, matching how `require_any_auth` resolves
        // a legacy scope-only token (dual-accept).
        Some(axum::Extension(crate::auth::RequesterCtx {
            sub: "alice".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            role: crate::auth::Role::from_scopes(scopes),
            harness: None,
            act: None,
        }))
    }

    #[test]
    fn parse_decision_approve_and_deny() {
        assert!(matches!(
            parse_decision(&json!({"decision": "approve"})),
            Ok(("approved", None))
        ));
        let (status, reason) =
            parse_decision(&json!({"decision": "deny", "reason": "too risky"})).unwrap();
        assert_eq!(status, "denied");
        assert_eq!(reason.as_deref(), Some("too risky"));
    }

    #[test]
    fn parse_decision_blank_reason_is_none() {
        // Preserves the row's enqueue-time reason via COALESCE.
        let (_, reason) = parse_decision(&json!({"decision": "deny", "reason": "  "})).unwrap();
        assert!(reason.is_none());
        let (_, reason) = parse_decision(&json!({"decision": "approve"})).unwrap();
        assert!(reason.is_none());
    }

    #[test]
    fn parse_decision_rejects_missing_or_unknown() {
        assert!(matches!(
            parse_decision(&json!({})),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            parse_decision(&json!({"decision": "maybe"})),
            Err(AppError::BadRequest(_))
        ));
        // Stored statuses are NOT accepted as decisions (approve != approved).
        assert!(matches!(
            parse_decision(&json!({"decision": "approved"})),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn decide_actor_unbound_hmac_caller_is_refused() {
        // THE phase-3 change: a shared-secret HMAC
        // caller carries no RequesterCtx; it proves nothing about WHO is
        // deciding. That is a 403, always — the break-glass gate that once
        // opened this is retired (posture::RETIRED_BRIDGES).
        let err = decide_actor(&None).unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
        // The message has to tell the locked-out operator what to do — and
        // must not send them to a retired gate.
        let msg = format!("{err:?}");
        assert!(msg.contains("noo auth login"), "{msg}");
        assert!(msg.contains("noo security admin-password reset"), "{msg}");
        assert!(!msg.contains("NOO_APPROVAL_BREAK_GLASS"), "{msg}");
    }

    /// The retired arm stays gone: nothing in the route reads the gate, and
    /// no decision is attributed to the old break-glass actor.
    #[test]
    fn the_break_glass_arm_is_gone() {
        let src = include_str!("admin.rs");
        let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        let gate = ["approval_break_glass", "_enabled"].concat();
        let actor = ["cli-operator:", "break-glass"].concat();
        assert!(!code.contains(&gate), "the approval route reads the retired gate again");
        assert!(!code.contains(&actor), "a decision can be attributed to the retired break-glass actor again");
    }

    #[test]
    fn decide_actor_jwt_requires_operator_scope() {
        assert_eq!(decide_actor(&ctx(&["admin"])).unwrap(), "alice");
        assert_eq!(decide_actor(&ctx(&["read", "write"])).unwrap(), "alice");
        assert!(matches!(decide_actor(&ctx(&["read"])), Err(AppError::Forbidden(_))));
        assert!(matches!(decide_actor(&ctx(&[])), Err(AppError::Forbidden(_))));
    }

    // ── Job-hash shape parity ───────────────────────────────────────
    //
    // Fixture copied from Python `scheduler.py::submit_job()`'s `job` dict
    // (the same trick noo-cli uses for tools.json). If either side renames,
    // adds, or drops a field, this fails instead of shipping a silent
    // contract drift — the last one produced history rows with "id": null
    // because Rust wrote `job_id` where Python reads `id`.
    const PYTHON_SUBMIT_JOB_FIELDS: &[&str] = &[
        "id",
        "type",
        "payload",
        "priority",
        "status",
        "created_at",
        "updated_at",
        "dispatched_at",
        "completed_at",
        "node_id",
        "result",
        "error",
        "retries",
        "max_retries",
        "timeout_sec",
        "force_node",
        "min_vram_gb",
        "backend",
    ];

    fn spec<'a>() -> JobHashSpec<'a> {
        JobHashSpec {
            job_id: "j-1",
            job_type: "inference",
            payload: "{}",
            priority: 5,
            status: "queued",
            now: "2026-08-01T00:00:00+00:00",
            dispatched_at: "",
            node_id: "",
            max_retries: 2,
            timeout_sec: 300,
            force_node: "",
            min_vram_gb: 0.0,
            backend: "",
        }
    }

    #[test]
    fn job_hash_matches_python_writer_field_for_field() {
        let pairs = job_hash_pairs(&spec());
        let rust_fields: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        // Exact set AND order — Python builds the dict in this order, and
        // an ordered comparison makes a diff readable when it fires.
        assert_eq!(rust_fields, PYTHON_SUBMIT_JOB_FIELDS);
    }

    #[test]
    fn job_hash_values_match_python_defaults() {
        let by_key: std::collections::HashMap<&str, String> =
            job_hash_pairs(&spec()).into_iter().collect();
        // Python: str(priority), "0" retries, JobStatus.QUEUED.value, and
        // empty strings (never nulls) for not-yet-set fields.
        assert_eq!(by_key["id"], "j-1");
        assert_eq!(by_key["status"], "queued");
        assert_eq!(by_key["priority"], "5");
        assert_eq!(by_key["retries"], "0");
        assert_eq!(by_key["max_retries"], "2");
        assert_eq!(by_key["timeout_sec"], "300");
        assert_eq!(by_key["dispatched_at"], "");
        assert_eq!(by_key["completed_at"], "");
        assert_eq!(by_key["node_id"], "");
        assert_eq!(by_key["result"], "");
        assert_eq!(by_key["error"], "");
        assert_eq!(by_key["force_node"], "");
        assert_eq!(by_key["backend"], "");
    }

    #[test]
    fn terminal_ttl_matches_python_constant() {
        // scheduler.py: JOB_TTL_AFTER_TERMINAL = 86400
        assert_eq!(JOB_TTL_AFTER_TERMINAL, 86400);
    }

    #[test]
    fn check_transition_pending_only() {
        // Only pending → decided is legal.
        assert!(check_transition(Some("pending"), "r1").is_ok());
        // Missing id → 404.
        assert!(matches!(
            check_transition(None, "r1"),
            Err(AppError::NotFound(_))
        ));
        // Already-decided (any non-pending status) → 409, never rewritten.
        for s in ["approved", "denied", "timed_out"] {
            assert!(matches!(
                check_transition(Some(s), "r1"),
                Err(AppError::Conflict(_))
            ));
        }
    }
}


// ── Schema migrations ────────────────────────────────────────────────────

/// The stamp a version table holds, per-system schema first (fresh layout)
/// then `public` (legacy) — the same resolution order the runners use.
async fn stamp_of(db: &sqlx::PgPool, schema: &str, table: &str) -> Option<String> {
    for rel in [format!("{schema}.{table}"), format!("public.{table}")] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(&rel)
            .fetch_one(db)
            .await
            .ok()?;
        if exists {
            let v: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT version_num FROM {rel} LIMIT 1")))
                .fetch_optional(db)
                .await
                .ok()
                .flatten();
            if v.is_some() {
                return v;
            }
        }
    }
    None
}

/// GET /api/db/migrations — mesh (native runner: current, head, ported
/// chain with pending markers), memory (trellion's alembic stamp) and
/// evolve (pro) in one document.
async fn db_migrations(State(state): State<Arc<AppState>>) -> AppResult {
    use crate::mesh_migrate::{self, MIGRATIONS};
    let current = mesh_migrate::current_revision(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("mesh version read failed: {e}")))?;
    let (pending, plan_error): (Vec<&str>, Option<String>) =
        match mesh_migrate::plan(current.as_deref(), MIGRATIONS) {
            Ok(p) => (p.iter().map(|m| m.revision).collect(), None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
    let chain: Vec<Value> = MIGRATIONS
        .iter()
        .map(|m| {
            json!({
                "revision": m.revision,
                "down_revision": m.down_revision,
                "pending": pending.contains(&m.revision),
            })
        })
        .collect();
    Ok(Json(json!({
        "mesh": {
            "owner": "gateway (native sqlx runner)",
            "engine": format!("{:?}", mesh_migrate::Engine::from_env()).to_lowercase(),
            "current": current,
            "head": MIGRATIONS.last().map(|m| m.revision),
            "ported": MIGRATIONS.len(),
            "pending": pending,
            "plan_error": plan_error,
            "chain": chain,
        },
        "memory": {
            "owner": "trellion (alembic, applied at its container start)",
            "current": stamp_of(&state.db, "trellion", "alembic_version_memory").await,
        },
        "evolve": {
            "owner": "evolve (alembic, evolve overlay)",
            "current": stamp_of(&state.db, "evolve", "alembic_version_evolve").await,
        },
    })))
}

/// POST /api/db/migrations/apply — run the mesh runner now (what the
/// gateway does at boot). Admin only. Memory/evolve are not touched: they
/// belong to their containers' entrypoints.
async fn db_migrations_apply(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
) -> AppResult {
    use crate::mesh_migrate;
    if let Some(Extension(r)) = &requester {
        if r.role < crate::auth::Role::Admin {
            return Err(AppError::Forbidden("applying migrations needs the admin role".into()));
        }
    }
    let before = mesh_migrate::current_revision(&state.db).await.ok().flatten();
    // The runner's future is not `Send` (it is written for the boot path,
    // which awaits it on the main task); an axum handler's future must be.
    // Drive it to completion on a blocking thread with the runtime handle —
    // it is a one-off admin action, not a hot path.
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || handle.block_on(mesh_migrate::run()))
        .await
        .map_err(|e| AppError::Internal(format!("mesh migration task failed: {e}")))?
        .map_err(|e| AppError::Internal(format!("mesh migration apply failed: {e}")))?;
    let after = mesh_migrate::current_revision(&state.db).await.ok().flatten();
    Ok(Json(json!({
        "applied": true,
        "mesh": { "before": before, "after": after },
        "note": "memory (trellion) and evolve migrate at their own container start — restart those services to apply theirs",
    })))
}

#[cfg(test)]
mod mesh_lifecycle_gate_tests {
    use super::*;
    use crate::auth::{RequesterCtx, Role};

    fn ctx_role(role: Role, scopes: &[&str]) -> Option<Extension<RequesterCtx>> {
        Some(Extension(RequesterCtx {
            sub: "alice".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            role,
            harness: None,
            act: None,
        }))
    }

    /// `None` is how a cluster-HMAC / internal caller arrives — no
    /// `RequesterCtx` extension is inserted for it. Restarting the fleet
    /// must name a person, so the shared fleet secret is refused.
    #[test]
    fn cluster_token_is_refused() {
        let err = mesh_lifecycle_admin_guard(&None).unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
        let msg = format!("{err:?}");
        assert!(msg.contains("cluster HMAC"), "message should say why: {msg}");
    }

    #[test]
    fn plain_user_is_refused() {
        let err = mesh_lifecycle_admin_guard(&ctx_role(Role::User, &["read"])).unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    /// Operator is deliberately NOT enough — same reasoning as
    /// `users::scope_mutation_guard`. Restart/rebuild is an Admin action.
    #[test]
    fn operator_is_refused() {
        let err = mesh_lifecycle_admin_guard(&ctx_role(Role::Operator, &["write"])).unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {err:?}");
    }

    #[test]
    fn admin_is_allowed_and_is_named() {
        let ctx = ctx_role(Role::Admin, &["admin"]);
        let r = mesh_lifecycle_admin_guard(&ctx).expect("admin must pass");
        assert_eq!(r.sub, "alice", "the audit row needs the admin's name");
    }
}

#[cfg(test)]
mod approval_decider_tests {
    use super::*;
    use crate::auth::{Actor, RequesterCtx, Role};

    fn ctx(sub: &str, harness: Option<&str>, act: bool) -> Option<axum::Extension<RequesterCtx>> {
        Some(axum::Extension(RequesterCtx {
            sub: sub.into(),
            scopes: vec!["read".into(), "write".into(), "admin".into()],
            role: Role::Admin,
            harness: harness.map(String::from),
            act: act.then(|| Actor { sub: "svc:worker".into(), iss_user: None, task: Some("t1".into()) }),
        }))
    }

    /// A pool that never connects: the agent paths must refuse before any query,
    /// and the person path must fail closed when the account lookup cannot run.
    fn dead_pool() -> sqlx::PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://nobody@127.0.0.1:1/nothing")
            .expect("lazy pool")
    }

    #[tokio::test]
    async fn the_model_cannot_decide_its_own_approval() {
        let db = dead_pool();
        // worker-delegated token (what a tool call carries back), harness token,
        // MCP-door key, service identity.
        for c in [
            ctx("alice", None, true),
            ctx("alice", Some("worker:t1"), false),
            ctx("alice", Some("node:host3"), false),
            ctx("alice", Some("mcp-external:codex"), false),
            ctx("svc:evolve", None, false),
            None,
        ] {
            let r = require_human_decider(&db, &c).await;
            match r {
                Err(AppError::Forbidden(m)) => assert!(m.contains("by a person"), "{m}"),
                other => panic!("expected 403 for {c:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_person_login_passes_and_an_unverifiable_one_fails_closed() {
        // Pure rule: a person is accepted.
        let person = crate::task_guard::Origin::Person { account: "olive".into(), role: Role::Operator };
        assert!(decider_refusal(&person).is_ok(), "dashboard / CLI login must keep working");
        // Account lookup impossible (DB down): not a person.
        let r = require_human_decider(&dead_pool(), &ctx("olive", None, false)).await;
        assert!(matches!(r, Err(AppError::Forbidden(_))), "fail closed");
    }

    #[test]
    fn all_three_decision_routes_check_it() {
        let src = include_str!("admin.rs");
        for f in ["async fn approval_approve(", "async fn approval_deny(", "async fn approval_decide("] {
            let start = src.find(f).expect(f);
            let body = &src[start..start + 700];
            assert!(body.contains("require_human_decider("), "{f} must refuse non-person credentials");
        }
    }
}
