// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Reservations: a feature that must continuously consume a piece of the
//! mesh (voice while voice is on; an image or video worker with its model
//! loaded) reserves a GPU, and that capacity is not routable to the pool
//! until released (noomesh-internal i163 §6b). Not voice-specific: core
//! never names a workload; the add-on's verified bundle declares it
//! (`crate::addon_workloads`).
//!
//! A reservation IS the node's GPU lease (`routes/cluster.rs gpu_hold`): its
//! id is the lease's `operation_id`, its holder the lease's owner, its
//! workload the lease's `workload`. Nothing is stored twice: the list is
//! read from the nodes' heartbeats.
//!
//! Taking one: pick a node (any live node with enough free GPU memory, or
//! the `node` the caller pins), take an owned hold in mode drain (the pool's
//! in-flight work there finishes, nothing is cut), start the declared
//! workload through the node agent's actuator, wait for it to run. Releasing
//! one: the add-on's declared drain route runs first, the workload is
//! stopped, the hold is released by compare-and-set with `resume: now`, and
//! the GPU rejoins routing. A hand-over (`hand_over: <id>`) moves one GPU
//! from one workload to the next with a force hold, so the pool never gets
//! the GPU in between. A timeout anywhere leaves the current holder in
//! place and reports `needs_attention`; a running request is never cut.
//!
//! The workload proxy (`/api/addon-workloads/{addon}/{workload}/proxy/…`)
//! lets an add-on's own token reach ITS reserved worker through the node
//! agent's container proxy: the reservation names the node, the declaration
//! names the container, nothing else is reachable.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{any, get, post},
    Json, Router,
};
use serde_json::{json, Value};

use super::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/cluster/reservations", get(reservations_list).post(reservation_take))
        .route("/api/cluster/reservations/{id}", get(reservation_get).delete(reservation_release))
        .route("/api/cluster/reservations/{id}/release", post(reservation_release))
        .route("/api/cluster/workloads", get(workloads_list))
        .route("/api/addon-workloads/{addon}/{workload}/proxy/{*path}", any(workload_proxy))
}

/// How long a reservation waits for the started workload to run (and pass
/// its healthcheck when it has one) before it reports `needs_attention`.
pub(crate) const READY_TIMEOUT_SECS: u64 = 180;
/// A node whose last heartbeat is older than this is not a candidate.
const FRESH_SECS: f64 = 120.0;

// ── what the heartbeats say ──────────────────────────────────────────────

/// One reservation as the node's lease reports it (plain operator holds are
/// listed too, with no workload).
fn reservation_of(node_id: &str, record: &Value) -> Option<Value> {
    let gc = record.get("gpu_contention")?;
    let lease = gc.get("lease")?;
    let id = lease.get("operation_id").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    Some(json!({
        "id": id,
        "workload": lease.get("workload").and_then(Value::as_str).unwrap_or(""),
        "holder": lease.get("owner").and_then(Value::as_str).unwrap_or(""),
        "node": node_id,
        "state": gc.get("state").and_then(Value::as_str).unwrap_or(""),
        "generation": lease.get("generation").and_then(Value::as_u64).unwrap_or(0),
        "since": lease.get("since").and_then(Value::as_str).unwrap_or(""),
        "mode": lease.get("mode").and_then(Value::as_str).unwrap_or(""),
        "reason": lease.get("reason").and_then(Value::as_str).unwrap_or(""),
        "paused_backends": gc.get("paused_backends").cloned().unwrap_or(json!([])),
        "gpu_total_mb": gc.get("total_mb").and_then(Value::as_u64).unwrap_or(0),
    }))
}

/// Every node's KV record, `(node_id, record)`.
async fn node_records(state: &AppState) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else { return out };
    let Ok(keys) = kv.keys().await else { return out };
    use tokio_stream::StreamExt;
    let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect::<Vec<String>>().await;
    for key in keys {
        if key == "gateway" {
            continue;
        }
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(data) = serde_json::from_slice::<Value>(&entry) else { continue };
        let id = data.get("id").and_then(Value::as_str).unwrap_or(&key).to_string();
        out.push((id, data));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

async fn all_reservations(state: &AppState) -> Vec<Value> {
    node_records(state).await.iter().filter_map(|(id, r)| reservation_of(id, r)).collect()
}

async fn find_reservation(state: &AppState, id: &str) -> Option<Value> {
    all_reservations(state).await.into_iter().find(|r| r["id"] == id)
}

/// Why a node cannot take the workload, or `Ok(free_mb)` when it can.
/// Pure, so the placement rule is tested without a KV.
pub(crate) fn eligibility(record: &Value, decl: &crate::addon_workloads::WorkloadDecl, now_unix: f64, hand_over_id: Option<&str>) -> Result<u64, String> {
    let status = record.get("status").and_then(Value::as_str).unwrap_or("");
    if matches!(status, "offline" | "quarantined") {
        return Err(format!("status {status}"));
    }
    let last = record.get("last_heartbeat").or_else(|| record.get("ts")).and_then(Value::as_f64);
    match last {
        Some(t) if now_unix - t <= FRESH_SECS => {}
        Some(t) => return Err(format!("last heartbeat {:.0} s ago", now_unix - t)),
        None => return Err("no heartbeat".into()),
    }
    let gc = record.get("gpu_contention").cloned().unwrap_or(json!({}));
    let total_mb = gc
        .get("total_mb")
        .and_then(Value::as_u64)
        .filter(|t| *t > 0)
        .or_else(|| record.get("vram_gb").and_then(Value::as_f64).filter(|v| *v > 0.0).map(|v| (v * 1024.0) as u64));
    if decl.gpu {
        let Some(total) = total_mb else { return Err("no GPU reported".into()) };
        let state = gc.get("state").and_then(Value::as_str).unwrap_or("free");
        let lease_id = gc.pointer("/lease/operation_id").and_then(Value::as_str).unwrap_or("");
        match state {
            "free" | "shared" | "yielded" => {}
            "held" | "draining" if hand_over_id.is_some_and(|h| h == lease_id) => {}
            "held" | "draining" => {
                return Err(format!(
                    "GPU held by {} (reservation {lease_id})",
                    gc.pointer("/lease/owner").and_then(Value::as_str).unwrap_or("operator")
                ))
            }
            other => return Err(format!("gpu state {other}")),
        }
        // The pool's backends are paused by the hold, so what is left for
        // the workload is the GPU minus foreign use.
        let foreign = gc.get("foreign_mb").and_then(Value::as_u64).unwrap_or(0);
        let free = total.saturating_sub(foreign);
        if decl.need_mb > 0 && free < decl.need_mb {
            return Err(format!("{free} MB free of {total} MB, the workload needs {} MB", decl.need_mb));
        }
        return Ok(free);
    }
    Ok(total_mb.unwrap_or(0))
}

fn now_unix() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

// ── routes ───────────────────────────────────────────────────────────────

/// GET /api/cluster/reservations — every lease the nodes report. Operator read.
async fn reservations_list(State(state): State<Arc<AppState>>, ctx: Option<axum::Extension<crate::auth::RequesterCtx>>) -> AppResult {
    super::operator_read_guard(&ctx)?;
    Ok(Json(json!({"reservations": all_reservations(&state).await})))
}

/// GET /api/cluster/reservations/{id}
async fn reservation_get(State(state): State<Arc<AppState>>, ctx: Option<axum::Extension<crate::auth::RequesterCtx>>, Path(id): Path<String>) -> AppResult {
    super::operator_read_guard(&ctx)?;
    match find_reservation(&state, &id).await {
        Some(r) => Ok(Json(r)),
        None => Err(AppError::NotFound(format!("no reservation {id}"))),
    }
}

/// GET /api/cluster/workloads — what the verified add-on bundles declare.
async fn workloads_list(ctx: Option<axum::Extension<crate::auth::RequesterCtx>>) -> AppResult {
    super::operator_read_guard(&ctx)?;
    let v: Vec<Value> = crate::addon_workloads::declared()
        .iter()
        .map(|d| json!({"workload": d.key(), "addon": d.addon, "name": d.name, "container": d.container, "gpu": d.gpu, "need_mb": d.need_mb,
            "drain": d.drain.as_ref().map(|x| json!({"route": x.route, "timeout_secs": x.timeout_secs}))}))
        .collect();
    Ok(Json(json!({"workloads": v})))
}

/// The agent's actuator path for a workload.
fn actuator_path(decl: &crate::addon_workloads::WorkloadDecl, op: &str) -> String {
    format!("/api/addon-workloads/{}/{}{}", decl.addon, decl.name, op)
}

/// One actuator call; the agent's JSON on 2xx, else the sentence to show.
async fn actuator(link: &crate::node_link::NodeLink, decl: &crate::addon_workloads::WorkloadDecl, op: &str, body: Value, wait_secs: u64) -> Result<Value, String> {
    let method = if op.is_empty() { reqwest::Method::GET } else { reqwest::Method::POST };
    let req = link.request(method, &actuator_path(decl, op)).json(&body).timeout(std::time::Duration::from_secs(wait_secs));
    match req.send().await {
        Ok(resp) if resp.status().is_success() => Ok(resp.json::<Value>().await.unwrap_or(json!({}))),
        Ok(resp) => {
            let status = resp.status().as_u16();
            let v = resp.json::<Value>().await.unwrap_or(json!({}));
            let code = v.get("error").and_then(Value::as_str).unwrap_or("error");
            let detail = v.get("detail").and_then(Value::as_str).unwrap_or("");
            Err(format!("{code} ({status}): {detail}"))
        }
        Err(e) => Err(format!("node agent unreachable: {e}")),
    }
}

/// Wait until the workload's container runs (and is not `starting` or
/// `unhealthy` when it has a healthcheck). `Ok(state)` or the reason.
async fn wait_ready(link: &crate::node_link::NodeLink, decl: &crate::addon_workloads::WorkloadDecl, timeout: std::time::Duration) -> Result<Value, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut last = json!({});
    loop {
        match actuator(link, decl, "", json!({}), 15).await {
            Ok(st) => {
                let running = st.get("running").and_then(Value::as_bool).unwrap_or(false);
                let health = st.get("health").and_then(Value::as_str).unwrap_or("");
                if running && health == "unhealthy" {
                    return Err("the workload's container reports unhealthy".into());
                }
                if running && health != "starting" {
                    return Ok(st);
                }
                last = st;
            }
            Err(e) => last = json!({"error": e}),
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("not ready after {} s (last: {last})", timeout.as_secs()));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Drain and stop a workload on a node: the add-on's declared drain route,
/// then the actuator's stop. `force` carries on past a failed drain.
async fn drain_and_stop(link: &crate::node_link::NodeLink, decl: &crate::addon_workloads::WorkloadDecl, reservation: &str, force: bool) -> Result<Value, String> {
    let mut drained = json!(null);
    if let Some(drain) = &decl.drain {
        let body = json!({"reservation": reservation, "workload": decl.key(), "timeout_secs": drain.timeout_secs});
        match tokio::time::timeout(
            std::time::Duration::from_secs(drain.timeout_secs + 30),
            crate::addon_proxy::call(&decl.addon, &drain.route, Some(body)),
        )
        .await
        {
            Ok(crate::addon_proxy::CallOutcome::Ok(v)) => drained = v,
            Ok(crate::addon_proxy::CallOutcome::Unavailable(reason)) if !force => return Err(format!("drain route {} refused: {reason}", drain.route)),
            Ok(crate::addon_proxy::CallOutcome::Unavailable(reason)) => tracing::warn!(addon = %decl.addon, route = %drain.route, reason = %reason, "reservation_drain_skipped_by_force"),
            Err(_) if !force => return Err(format!("drain route {} did not answer within {} s", drain.route, drain.timeout_secs + 30)),
            Err(_) => tracing::warn!(addon = %decl.addon, route = %drain.route, "reservation_drain_timeout_forced"),
        }
    }
    let grace = decl.drain.as_ref().map(|d| d.timeout_secs.min(600)).unwrap_or(30);
    let stopped = actuator(link, decl, "/stop", json!({"timeout_secs": grace}), grace + 60).await?;
    Ok(json!({"drained": drained, "stopped": stopped}))
}

/// POST /api/cluster/reservations — body `{workload: "<addon>/<name>",
/// node?, hand_over?: <reservation id>, timeout_secs?}`. Operator only;
/// audited (`reservation_take`).
async fn reservation_take(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let actor = super::cluster::gpu_hold_actor(&ctx)?;
    let b = body.map(|Json(b)| b).unwrap_or_else(|| json!({}));
    let key = b.get("workload").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let Some((addon, name)) = crate::addon_workloads::split_key(&key) else {
        return Err(AppError::BadRequest("workload must be <addon>/<workload> (lowercase names)".into()));
    };
    let Some(decl) = crate::addon_workloads::lookup(&addon, &name) else {
        return Err(AppError::NotFound(format!("no verified add-on bundle declares workload {key}")));
    };
    let pinned = b.get("node").and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let hand_over = b.get("hand_over").and_then(Value::as_str).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let timeout_secs = b
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .unwrap_or(super::cluster::GPU_DRAIN_TIMEOUT_DEFAULT_SECS)
        .clamp(1, super::cluster::GPU_DRAIN_TIMEOUT_MAX_SECS);

    // The outgoing reservation, when this is a hand-over.
    let old = match &hand_over {
        Some(id) => Some(find_reservation(&state, id).await.ok_or_else(|| AppError::NotFound(format!("no reservation {id} to hand over from")))?),
        None => None,
    };
    let pinned = match (&old, pinned) {
        (Some(o), Some(n)) if o["node"] != n => {
            return Err(AppError::Conflict(format!("reservation {} is on {}, not {n}: a hand-over stays on its node", o["id"], o["node"])))
        }
        (Some(o), _) => Some(o["node"].as_str().unwrap_or("").to_string()),
        (None, p) => p,
    };

    // Placement: every live node with room, best first; a pin narrows it.
    let now = now_unix();
    let mut ok: Vec<(u64, String)> = Vec::new();
    let mut why: Vec<String> = Vec::new();
    for (id, record) in node_records(&state).await {
        if pinned.as_deref().is_some_and(|p| p != id) {
            continue;
        }
        match eligibility(&record, &decl, now, hand_over.as_deref()) {
            Ok(free) => ok.push((free, id)),
            Err(e) => why.push(format!("{id}: {e}")),
        }
    }
    ok.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let Some((_, node)) = ok.first().cloned() else {
        let scope = pinned.as_deref().map(|p| format!("node {p}")).unwrap_or_else(|| "no node".to_string());
        return Err(AppError::Conflict(format!("{scope} can take {key}: {}", if why.is_empty() { "no node reported".to_string() } else { why.join("; ") })));
    };
    let link = crate::node_link::NodeLink::for_node(&state, &node).await?;
    let id = uuid::Uuid::new_v4().to_string();
    let mut steps = json!({});

    // A hand-over: the outgoing workload drains and stops first; its lease
    // is then taken over by force, so the pool never gets the GPU.
    if let Some(o) = &old {
        if let Some((oa, on)) = crate::addon_workloads::split_key(o["workload"].as_str().unwrap_or("")) {
            if let Some(odecl) = crate::addon_workloads::lookup(&oa, &on) {
                let out = drain_and_stop(&link, &odecl, o["id"].as_str().unwrap_or(""), false)
                    .await
                    .map_err(|e| AppError::Conflict(format!("hand-over: the outgoing workload {} did not stop: {e}; its reservation stays", odecl.key())))?;
                steps["handed_over"] = out;
            }
        }
    }

    // The lease: an owned hold that drains the pool's work first.
    let hold = super::cluster::gpu_hold_op(
        &state,
        actor.clone(),
        &node,
        "hold",
        json!({"reason": format!("reservation {key}"), "operation_id": id, "owner": actor, "workload": key,
               "mode": "drain", "timeout_secs": timeout_secs, "force": old.is_some(), "legacy": false}),
        std::time::Duration::from_secs(timeout_secs + 60),
    )
    .await?;
    let Json(hold) = hold;
    let lease = hold.pointer("/gpu_contention/lease").cloned().unwrap_or(Value::Null);
    let generation = lease.get("generation").and_then(Value::as_u64).unwrap_or(0);

    // Start the workload; a start that fails gives the GPU back at once.
    let started = match actuator(&link, &decl, "/start", json!({}), 120).await {
        Ok(v) => v,
        Err(e) => {
            let _ = super::cluster::gpu_hold_op(&state, actor.clone(), &node, "release",
                json!({"operation_id": id, "generation": generation, "force": false, "legacy": false, "resume": "now"}),
                std::time::Duration::from_secs(90)).await;
            audit(&state, "reservation_take", &actor, &node, "error", json!({"id": id, "workload": key, "step": "start", "detail": e})).await;
            return Err(AppError::Internal(format!("{key} did not start on {node}: {e}; the GPU was released back to the pool")));
        }
    };
    steps["started"] = started;

    // Ready: the container runs (and passes its healthcheck when it has
    // one). A timeout keeps the reservation and says so.
    let (status, worker, detail) = match wait_ready(&link, &decl, std::time::Duration::from_secs(READY_TIMEOUT_SECS)).await {
        Ok(st) => ("reserved", st, String::new()),
        Err(e) => ("needs_attention", json!({}), e),
    };
    audit(&state, "reservation_take", &actor, &node, if status == "reserved" { "ok" } else { "needs_attention" },
        json!({"id": id, "workload": key, "hand_over": hand_over, "lease": lease, "detail": detail})).await;
    tracing::info!(id = %id, workload = %key, node = %node, actor = %actor, status, "reservation_take");
    Ok(Json(json!({"id": id, "workload": key, "node": node, "holder": actor, "status": status, "detail": detail,
        "lease": lease, "worker": worker, "steps": steps, "paused_backends": hold.pointer("/gpu_contention/paused_backends").cloned().unwrap_or(json!([]))})))
}

/// POST /api/cluster/reservations/{id}/release (or DELETE …/{id}) — body
/// `{force?}`. The holder, or an operator with `force` (audited). The
/// workload drains (its declared route), stops, and the lease is released
/// by compare-and-set with `resume: now`.
async fn reservation_release(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult {
    let actor = super::cluster::gpu_hold_actor(&ctx)?;
    let force = body.as_ref().and_then(|Json(b)| b.get("force")).and_then(Value::as_bool).unwrap_or(false);
    let Some(r) = find_reservation(&state, &id).await else {
        return Err(AppError::NotFound(format!("no reservation {id}")));
    };
    let node = r["node"].as_str().unwrap_or("").to_string();
    let holder = r["holder"].as_str().unwrap_or("").to_string();
    if holder != actor && !force {
        return Err(AppError::Conflict(format!("not_owner: reservation {id} is held by {holder}; release it with force")));
    }
    let key = r["workload"].as_str().unwrap_or("").to_string();
    let link = crate::node_link::NodeLink::for_node(&state, &node).await?;
    let mut steps = json!({});
    if let Some((a, n)) = crate::addon_workloads::split_key(&key) {
        if let Some(decl) = crate::addon_workloads::lookup(&a, &n) {
            match drain_and_stop(&link, &decl, &id, force).await {
                Ok(v) => steps["stopped"] = v,
                Err(e) => {
                    audit(&state, "reservation_release", &actor, &node, "error", json!({"id": id, "workload": key, "detail": e, "force": force})).await;
                    return Err(AppError::Conflict(format!("{key} did not stop on {node}: {e}; the reservation stays (force to release anyway)")));
                }
            }
        }
    }
    let generation = r["generation"].as_u64().unwrap_or(0);
    let released = super::cluster::gpu_hold_op(&state, actor.clone(), &node, "release",
        json!({"operation_id": id, "generation": generation, "force": force, "legacy": false, "resume": "now"}),
        std::time::Duration::from_secs(90)).await?;
    let Json(released) = released;
    audit(&state, "reservation_release", &actor, &node, "ok", json!({"id": id, "workload": key, "holder": holder, "force": force})).await;
    tracing::info!(id = %id, workload = %key, node = %node, actor = %actor, force, "reservation_release");
    Ok(Json(json!({"id": id, "workload": key, "node": node, "status": "released", "steps": steps,
        "gpu_contention": released.get("gpu_contention").cloned().unwrap_or(json!({}))})))
}

async fn audit(state: &AppState, event: &str, actor: &str, node: &str, outcome: &str, details: Value) {
    super::core::audit_event(&state.db, event, "info", actor, &format!("node:{node}"), outcome, details).await;
}

// ── the workload proxy ───────────────────────────────────────────────────

/// `/api/addon-workloads/{addon}/{workload}/proxy/{path}` (any method,
/// WebSocket upgrades included): the add-on's own token (`addon:<addon>`)
/// or an operator reaches the RESERVED workload's container through the
/// node agent's container proxy. 404 when no such workload is declared, 409
/// when it is not reserved right now. A request is forwarded with its
/// method, query, body and content type; a WebSocket is relayed frame by
/// frame for as long as the reservation stands (the stream closes with
/// code 4001 when it ends), so a coordinator opens ONE connection to its
/// worker and every exchange rides it: no ingress to the worker, no
/// credential on it.
async fn workload_proxy(
    State(state): State<Arc<AppState>>,
    Path((addon, workload, path)): Path<(String, String, String)>,
    req: axum::extract::Request,
) -> Result<Response, AppError> {
    let (mut parts, body) = req.into_parts();
    let Some(r) = parts.extensions.get::<crate::auth::RequesterCtx>().cloned() else {
        return Err(AppError::Forbidden("a credential is required".into()));
    };
    let own = r.sub == format!("{}{addon}", crate::auth::ADDON_SUBJECT_PREFIX);
    if !own && r.role < crate::auth::Role::Operator {
        return Err(AppError::Forbidden(format!("only the add-on {addon} itself or an operator may reach its workloads")));
    }
    let Some(decl) = crate::addon_workloads::lookup(&addon, &workload) else {
        return Err(AppError::NotFound(format!("no verified add-on bundle declares workload {addon}/{workload}")));
    };
    let key = decl.key();
    let Some(res) = all_reservations(&state).await.into_iter().find(|r| r["workload"] == key && r["state"] == "held") else {
        return Err(AppError::Conflict(format!("not_reserved: {key} holds no GPU right now (noo cluster reserve {key})")));
    };
    let reservation = res["id"].as_str().unwrap_or("").to_string();
    let node = res["node"].as_str().unwrap_or("").to_string();
    let link = crate::node_link::NodeLink::for_node(&state, &node).await?;
    let query = parts.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let upstream = format!("/api/containers/{}/proxy/{}{query}", decl.container, path.trim_start_matches('/'));

    if is_websocket_upgrade(&parts.headers) {
        use axum::extract::FromRequestParts;
        let protocol = parts.headers.get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(str::to_string);
        let ws = axum::extract::ws::WebSocketUpgrade::from_request_parts(&mut parts, &()).await.map_err(|e| AppError::BadRequest(format!("websocket upgrade: {e}")))?;
        let url = link.url(&upstream).replacen("https://", "wss://", 1).replacen("http://", "ws://", 1);
        let mut auth = link.auth_headers();
        auth.extend(peer_headers(&reservation, &r));
        let state2 = state.clone();
        let mut resp = ws.on_upgrade(move |client| relay_websocket(client, url, auth, protocol, state2, node, reservation));
        resp.headers_mut().insert("x-noo-reservation", axum::http::HeaderValue::from_str(res["id"].as_str().unwrap_or("")).unwrap_or(axum::http::HeaderValue::from_static("")));
        return Ok(resp);
    }

    let body = axum::body::to_bytes(body, PROXY_BODY_LIMIT).await.map_err(|e| AppError::BadRequest(format!("body: {e}")))?;
    let m = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut up = link.stream(m, &upstream).body(body);
    for name in [axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT] {
        if let Some(v) = parts.headers.get(&name) {
            up = up.header(name.as_str(), v.as_bytes());
        }
    }
    for (k, v) in peer_headers(&reservation, &r) {
        up = up.header(k, v);
    }
    let resp = up.send().await.map_err(|e| AppError::Internal(format!("node agent unreachable: {e}")))?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let ct = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream").to_string();
    let mut out = Response::new(Body::from_stream(resp.bytes_stream()));
    *out.status_mut() = status;
    if let Ok(v) = axum::http::HeaderValue::from_str(&ct) {
        out.headers_mut().insert(axum::http::header::CONTENT_TYPE, v);
    }
    out.headers_mut().insert("x-noo-reservation", axum::http::HeaderValue::from_str(&reservation).unwrap_or(axum::http::HeaderValue::from_static("")));
    Ok(out)
}

/// What the worker sees about its peer, set by the gateway on every
/// forwarded request and relayed WebSocket (the node agent passes them
/// through; the client's own copies never reach the worker). Not signed:
/// the worker's port is bound to the node's loopback and the only path to
/// it is the agent's controller-only proxy, so a request that carries them
/// came through here.
pub const PEER_RESERVATION_HEADER: &str = "x-noo-reservation";
pub const PEER_SUB_HEADER: &str = "x-noo-requester-sub";
pub const PEER_ROLE_HEADER: &str = "x-noo-requester-role";

fn peer_headers(reservation: &str, r: &crate::auth::RequesterCtx) -> Vec<(String, String)> {
    vec![
        (PEER_RESERVATION_HEADER.into(), reservation.to_string()),
        (PEER_SUB_HEADER.into(), r.sub.clone()),
        (PEER_ROLE_HEADER.into(), r.role.as_str().to_string()),
    ]
}

/// The largest request body the proxy forwards in one piece.
const PROXY_BODY_LIMIT: usize = 32 * 1024 * 1024;
/// How often the relay checks that the reservation still stands.
const RESERVATION_WATCH_SECS: u64 = 5;
/// The close code a relayed stream ends with when the reservation ended.
pub const CLOSE_RESERVATION_ENDED: u16 = 4001;

fn is_websocket_upgrade(h: &HeaderMap) -> bool {
    h.get(axum::http::header::UPGRADE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

fn to_upstream(m: axum::extract::ws::Message) -> Option<tokio_tungstenite::tungstenite::Message> {
    use axum::extract::ws::Message as A;
    use tokio_tungstenite::tungstenite::Message as T;
    Some(match m {
        A::Text(t) => T::Text(t.as_str().into()),
        A::Binary(b) => T::Binary(b),
        A::Ping(b) => T::Ping(b),
        A::Pong(b) => T::Pong(b),
        A::Close(Some(f)) => T::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame { code: f.code.into(), reason: f.reason.as_str().into() })),
        A::Close(None) => T::Close(None),
    })
}

fn to_client(m: tokio_tungstenite::tungstenite::Message) -> Option<axum::extract::ws::Message> {
    use axum::extract::ws::{CloseFrame, Message as A};
    use tokio_tungstenite::tungstenite::Message as T;
    Some(match m {
        T::Text(t) => A::Text(t.as_str().into()),
        T::Binary(b) => A::Binary(b),
        T::Ping(b) => A::Ping(b),
        T::Pong(b) => A::Pong(b),
        T::Close(Some(f)) => A::Close(Some(CloseFrame { code: f.code.into(), reason: f.reason.as_str().into() })),
        T::Close(None) => A::Close(None),
        T::Frame(_) => return None,
    })
}

/// Relay one client WebSocket to the worker's, through the node agent, for
/// as long as the reservation stands.
async fn relay_websocket(
    client: axum::extract::ws::WebSocket,
    url: String,
    auth: Vec<(String, String)>,
    protocol: Option<String>,
    state: Arc<AppState>,
    node: String,
    reservation: String,
) {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut client = client;
    let request = match url.as_str().into_client_request() {
        Ok(mut r) => {
            for (k, v) in &auth {
                if let (Ok(name), Ok(value)) = (axum::http::HeaderName::from_bytes(k.as_bytes()), axum::http::HeaderValue::from_str(v)) {
                    r.headers_mut().insert(name, value);
                }
            }
            if let Some(p) = protocol.as_deref().and_then(|p| axum::http::HeaderValue::from_str(p).ok()) {
                r.headers_mut().insert("sec-websocket-protocol", p);
            }
            r
        }
        Err(e) => {
            tracing::warn!(error = %e, url = %url, "workload_ws_bad_url");
            let _ = client.send(axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame { code: 1011, reason: "bad upstream".into() }))).await;
            return;
        }
    };
    let connector = match crate::tls::cluster_rustls_config() {
        Ok(Some(cfg)) => Some(tokio_tungstenite::Connector::Rustls(cfg)),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "workload_ws_tls_config");
            None
        }
    };
    let (upstream, _) = match tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector).await {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!(error = %e, node = %node, reservation = %reservation, "workload_ws_upstream_failed");
            let _ = client.send(axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame { code: 1014, reason: "worker unreachable".into() }))).await;
            return;
        }
    };
    tracing::info!(node = %node, reservation = %reservation, "workload_ws_open");
    let (mut up_tx, mut up_rx) = upstream.split();
    let (mut cl_tx, mut cl_rx) = client.split();
    let mut watch = tokio::time::interval(std::time::Duration::from_secs(RESERVATION_WATCH_SECS));
    watch.tick().await;
    let why = loop {
        tokio::select! {
            m = cl_rx.next() => match m {
                Some(Ok(m)) => {
                    let close = matches!(m, axum::extract::ws::Message::Close(_));
                    if let Some(t) = to_upstream(m) {
                        if up_tx.send(t).await.is_err() { break "worker closed"; }
                    }
                    if close { break "client closed"; }
                }
                _ => break "client closed",
            },
            m = up_rx.next() => match m {
                Some(Ok(m)) => {
                    let close = matches!(m, tokio_tungstenite::tungstenite::Message::Close(_));
                    if let Some(a) = to_client(m) {
                        if cl_tx.send(a).await.is_err() { break "client closed"; }
                    }
                    if close { break "worker closed"; }
                }
                _ => break "worker closed",
            },
            _ = watch.tick() => {
                let still = super::cluster::node_record(&state, &node).await
                    .and_then(|r| reservation_of(&node, &r))
                    .is_some_and(|r| r["id"] == reservation.as_str() && r["state"] == "held");
                if !still {
                    let _ = cl_tx.send(axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame { code: CLOSE_RESERVATION_ENDED, reason: "reservation ended".into() }))).await;
                    let _ = up_tx.send(tokio_tungstenite::tungstenite::Message::Close(None)).await;
                    break "reservation ended";
                }
            }
        }
    };
    tracing::info!(node = %node, reservation = %reservation, why, "workload_ws_closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addon_workloads::WorkloadDecl;

    fn decl(gpu: bool, need_mb: u64) -> WorkloadDecl {
        WorkloadDecl { addon: "pai-voice".into(), name: "voice-worker".into(), container: "noo-pai-voice-worker".into(), gpu, need_mb, drain: None }
    }

    fn node(gc: Value) -> Value {
        json!({"id": "awolf", "status": "online", "last_heartbeat": 1000.0, "vram_gb": 16, "gpu_contention": gc})
    }

    #[test]
    fn placement_takes_a_live_node_with_room_and_names_why_not_otherwise() {
        let d = decl(true, 11264);
        let free = node(json!({"state": "free", "total_mb": 16376, "foreign_mb": 0}));
        assert_eq!(eligibility(&free, &d, 1010.0, None), Ok(16376));
        let shared = node(json!({"state": "shared", "total_mb": 16376, "foreign_mb": 4000}));
        assert_eq!(eligibility(&shared, &d, 1010.0, None), Ok(12376));
        let tight = node(json!({"state": "shared", "total_mb": 16376, "foreign_mb": 8000}));
        assert!(eligibility(&tight, &d, 1010.0, None).unwrap_err().contains("needs 11264 MB"));
        let held = node(json!({"state": "held", "total_mb": 16376, "lease": {"operation_id": "res-1", "owner": "a"}}));
        assert!(eligibility(&held, &d, 1010.0, None).unwrap_err().contains("held by a"));
        assert!(eligibility(&held, &d, 1010.0, Some("res-1")).is_ok(), "a hand-over from that reservation may take it");
        assert!(eligibility(&held, &d, 1010.0, Some("res-2")).is_err(), "not from another");
        let stale = json!({"id": "x", "status": "online", "last_heartbeat": 100.0, "gpu_contention": {"state": "free", "total_mb": 16376}});
        assert!(eligibility(&stale, &d, 1010.0, None).unwrap_err().contains("heartbeat"));
        let off = json!({"id": "x", "status": "offline", "last_heartbeat": 1000.0, "gpu_contention": {"state": "free", "total_mb": 16376}});
        assert!(eligibility(&off, &d, 1010.0, None).unwrap_err().contains("offline"));
        let no_gpu = json!({"id": "x", "status": "online", "last_heartbeat": 1000.0});
        assert!(eligibility(&no_gpu, &d, 1010.0, None).unwrap_err().contains("no GPU"));
        // vram_gb stands in when the node reports no gpu_contention total.
        let by_vram = json!({"id": "x", "status": "online", "last_heartbeat": 1000.0, "vram_gb": 24.0});
        assert_eq!(eligibility(&by_vram, &d, 1010.0, None), Ok(24576));
        // A CPU workload needs no GPU at all.
        assert!(eligibility(&no_gpu, &decl(false, 0), 1010.0, None).is_ok());
    }

    #[test]
    fn a_reservation_is_read_from_the_nodes_lease() {
        let rec = json!({"gpu_contention": {"state": "held", "total_mb": 16376, "paused_backends": ["vllm"],
            "lease": {"operation_id": "res-1", "owner": "rbwolf", "workload": "pai-voice/voice-worker", "generation": 3, "since": "t", "mode": "drain", "reason": "reservation pai-voice/voice-worker"}}});
        let r = reservation_of("awolf", &rec).unwrap();
        assert_eq!(r["id"], "res-1");
        assert_eq!(r["workload"], "pai-voice/voice-worker");
        assert_eq!(r["holder"], "rbwolf");
        assert_eq!(r["node"], "awolf");
        assert_eq!(r["generation"], 3);
        assert_eq!(r["paused_backends"], json!(["vllm"]));
        assert!(reservation_of("x", &json!({"gpu_contention": {"state": "free"}})).is_none());
        // A plain operator hold lists too, with no workload.
        let plain = json!({"gpu_contention": {"state": "held", "lease": {"operation_id": "op-9", "owner": "op"}}});
        assert_eq!(reservation_of("x", &plain).unwrap()["workload"], "");
    }

    #[test]
    fn the_actuator_paths_are_the_agents() {
        let d = decl(true, 0);
        assert_eq!(actuator_path(&d, "/start"), "/api/addon-workloads/pai-voice/voice-worker/start");
        assert_eq!(actuator_path(&d, ""), "/api/addon-workloads/pai-voice/voice-worker");
    }

    /// Source test: the reservation routes are operator-gated and audited;
    /// a failed start releases the GPU; a ready timeout keeps the holder.
    #[test]
    fn take_and_release_are_gated_audited_and_never_strand_a_gpu() {
        let src = include_str!("reservations.rs").split("fn take_and_release_are_gated_audited_and_never_strand_a_gpu").next().unwrap();
        let take = src.split("async fn reservation_take(").nth(1).unwrap().split("\nasync fn ").next().unwrap();
        assert!(take.find("gpu_hold_actor(&ctx)?").unwrap() < take.find("body.map(").unwrap(), "operator gate before the body");
        let start = take.find("\"/start\"").expect("start");
        let rollback = take[start..].find("\"release\"").expect("a failed start releases");
        assert!(take[start + rollback..].contains("\"resume\": \"now\""), "the pool gets the GPU back at once");
        assert!(take.contains("\"needs_attention\""), "a ready timeout keeps the reservation and says so");
        assert!(take.matches("audit(&state, \"reservation_take\"").count() >= 2);
        let rel = src.split("async fn reservation_release(").nth(1).unwrap().split("\nasync fn ").next().unwrap();
        assert!(rel.contains("holder != actor && !force"), "only the holder, or a force");
        assert!(rel.find("drain_and_stop(").unwrap() < rel.find("\"release\"").unwrap(), "the workload stops before the lease is released");
        let proxy = src.split("async fn workload_proxy(").nth(1).unwrap().split("\n}\n").next().unwrap();
        assert!(proxy.contains("r[\"state\"] == \"held\""), "only a reserved workload is reachable");
        assert!(proxy.contains("decl.container"), "the container comes from the declaration, never the caller");
        assert!(proxy.find("r.role < crate::auth::Role::Operator").unwrap() < proxy.find("lookup(&addon").unwrap(), "identity before anything is looked up");
        let relay = src.split("async fn relay_websocket(").nth(1).unwrap().split("\n}\n").next().unwrap();
        assert!(relay.contains("CLOSE_RESERVATION_ENDED"), "a relayed stream closes with the reservation");
        assert_eq!(CLOSE_RESERVATION_ENDED, 4001);
    }
}
