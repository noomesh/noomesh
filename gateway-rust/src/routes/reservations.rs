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

use crate::audit::{AuditEvent, AuditKind};
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
        .route("/api/addon-workloads/{addon}/{workload}/status", get(workload_status))
        .route("/api/addon-workloads/{addon}/{workload}/reserve", post(addon_reserve))
        .route("/api/addon-workloads/{addon}/{workload}/release", post(addon_release))
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
        // i344b: `user` for the operator's own use; empty from an older agent.
        "purpose": lease.get("purpose").and_then(Value::as_str).unwrap_or(""),
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
async fn reservations_list(State(state): State<Arc<AppState>>, _op: crate::authz::OperatorOrInternal) -> AppResult {
    Ok(Json(json!({"reservations": all_reservations(&state).await})))
}

/// GET /api/cluster/reservations/{id}
async fn reservation_get(State(state): State<Arc<AppState>>, _op: crate::authz::OperatorOrInternal, Path(id): Path<String>) -> AppResult {
    match find_reservation(&state, &id).await {
        Some(r) => Ok(Json(r)),
        None => Err(AppError::NotFound(format!("no reservation {id}"))),
    }
}

/// GET /api/cluster/workloads — what the verified add-on bundles declare.
async fn workloads_list(_op: crate::authz::OperatorOrInternal) -> AppResult {
    let v: Vec<Value> = crate::addon_workloads::declared()
        .iter()
        .map(|d| json!({"workload": d.key(), "addon": d.addon, "name": d.name, "container": d.container, "gpu": d.gpu, "need_mb": d.need_mb,
            "drain": {"route": d.drain.route, "timeout_secs": d.drain.timeout_secs}}))
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
        Ok(resp) if resp.status().is_success() => crate::upstream_body::json_2xx(resp, &format!("the {} workload actuator", decl.name)).await,
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

/// The error for a failed actuator start. The agent loads its workload
/// declarations a moment after it registers; a start in that window meets its
/// 404 `not_declared`, a transient state (this gateway's own bundle declares
/// the workload), so the caller is told to retry, not shown a 500. Any other
/// failure stays an internal error.
fn start_failure(key: &str, node: &str, e: &str) -> AppError {
    if e.starts_with("not_declared (404)") {
        return AppError::UnavailableRetry {
            code: "node_workloads_not_loaded",
            detail: format!("{key} cannot start on {node}: the node has not loaded its workload declarations yet; retry"),
            retry_after_secs: 10,
        };
    }
    AppError::Internal(format!("{key} did not start on {node}: {e}; the GPU was released back to the pool"))
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

// ── i300 node workloads (H4) ─────────────────────────────────────────────
//
// A reservation of a node workload the operator placed (`node-workloads.json`,
// `noo_node_workload_placements`) runs through the same take and release as
// an i163 container: [`managed_decl`] gives it the i163 shape (the agent's
// worker container `noo-wl-<addon>-<name>`, `service_drain` as the drain
// route, GPU need from the profile), and the agent's actuator serves both
// kinds on the same routes (managed workloads start and stop through the
// node workload lifecycle, which drains through the door). What differs:
//   - the node is the placement's, never chosen (strict, phase 2);
//   - the row goes `running` under the reservation BEFORE the start (the
//     agent's start reads desired-config afresh) and back to `provisioned`
//     after the add-on's service drain and BEFORE the stop (the release order,
//     docs/reference/node-workloads.md), so the agent never restarts it;
//   - the ready wait is the declaration's `start_secs`, at most 600 s.

/// A reservation's node workload: its placement's node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Managed {
    pub node: String,
}

/// The longest a node workload's start is waited for.
pub(crate) const MANAGED_READY_MAX_SECS: u64 = 600;

/// The ready wait for a node workload: `start_secs`, at most
/// [`MANAGED_READY_MAX_SECS`].
pub(crate) fn managed_ready_secs(start_secs: i64) -> u64 {
    u64::try_from(start_secs.max(1)).unwrap_or(1).min(MANAGED_READY_MAX_SECS)
}

/// GPU memory a node workload needs: the profile's `vram_mb` plus
/// `per_slot_vram_mb` for every slot past the first (A11). Unknown (no
/// profile figures): 0, which the GPU check reads as "no size to check".
pub(crate) fn managed_need_mb(profile: Option<&crate::node_workloads::SetProfile>, slots: u64) -> u64 {
    let Some(p) = profile else { return 0 };
    let base = u64::try_from(p.vram_mb.unwrap_or(0)).unwrap_or(0);
    let per = u64::try_from(p.per_slot_vram_mb.unwrap_or(0)).unwrap_or(0);
    base.saturating_add(per.saturating_mul(slots.saturating_sub(1)))
}

/// The i163 shape of a placed node workload `d` of `addon`.
pub(crate) fn managed_decl(addon: &str, d: &crate::node_workloads::Decl, need_mb: u64) -> crate::addon_workloads::WorkloadDecl {
    let sd = d.service_drain.clone().unwrap_or_default();
    crate::addon_workloads::WorkloadDecl {
        addon: addon.to_string(),
        name: d.name.clone(),
        container: format!("noo-wl-{addon}-{}", d.name),
        gpu: d.accel.gpu > 0,
        need_mb,
        drain: crate::addon_workloads::DrainSpec { route: sd.route, timeout_secs: u64::try_from(sd.timeout_secs.max(1)).unwrap_or(1) },
    }
}

/// The slot count a placement's env asks for (`accel.slots_env`), else one.
fn placement_slots(d: &crate::node_workloads::Decl, env: &Value) -> u64 {
    d.accel
        .slots_env
        .as_deref()
        .and_then(|k| env.get(k))
        .and_then(Value::as_str)
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}

/// What a reservation of `addon`/`name` acts on: its declaration in the
/// i163 shape, the placement when it is a node workload, and its ready wait.
async fn resolve_workload(
    state: &AppState,
    addon: &str,
    name: &str,
) -> Result<(crate::addon_workloads::WorkloadDecl, Option<Managed>, u64), AppError> {
    if let Some(d) = crate::addon_workloads::lookup(addon, name) {
        return Ok((d, None, READY_TIMEOUT_SECS));
    }
    let nw = match crate::node_workload_sources::declared(addon) {
        Ok(Some(nw)) => nw,
        Ok(None) => return Err(AppError::NotFound(format!("no verified add-on bundle declares workload {addon}/{name}"))),
        Err(r) => return Err(AppError::Conflict(format!("{addon}'s node-workloads.json is refused: {r}"))),
    };
    let Some(d) = nw.workloads.iter().find(|w| w.name == name) else {
        return Err(AppError::NotFound(format!("no verified add-on bundle declares workload {addon}/{name}")));
    };
    let Some(row) = crate::repo::node_workload_placements::get(&state.db, addon, name)
        .await
        .map_err(|e| AppError::Internal(format!("reading the placement of {addon}/{name}: {e}")))?
    else {
        return Err(AppError::Conflict(format!(
            "{addon}/{name} is not placed on a node: place it first (PUT /api/cluster/nodes/<node>/node-workloads/{addon}/{name})"
        )));
    };
    let main = d.models.first().map(|s| s.slot.clone()).unwrap_or_default();
    let profile = row.sets.pointer(&format!("/{main}/0")).and_then(|r| {
        let (id, rev) = (r.get("id")?.as_str()?, r.get("revision")?.as_str()?);
        let sets = crate::routes::artifacts::gguf_dir().join("sets");
        let (set, _) = crate::node_workload_sources::staged_set(&sets, id, rev).ok()?;
        set.needs.profiles.into_iter().find(|p| Some(p.name.as_str()) == row.profile.as_deref())
    });
    let need = managed_need_mb(profile.as_ref(), placement_slots(d, &row.env));
    Ok((managed_decl(addon, d, need), Some(Managed { node: row.node_id }), managed_ready_secs(d.health.start_secs)))
}

// ── add-on-scoped reserve and release (i300 H5, A5) ──────────────────────
//
// An add-on reserves and releases ITS OWN placed node workload FOR A PERSON
// (operator decision 2026-11-07, "check the person"): D2 runs a worker on
// demand, and who it runs for is a person f99 decides on. The add-on
// presents the i143 delegated token the gateway minted for that person's
// proxied request (`sub` = the person, `act.sub = addon:<addon>`, `act.feature`
// = the add-on feature it was minted under); its service key alone is
// refused. Fail closed: no delegation, no person, another add-on, no feature
// named, or a feature f99 turns off for the person, is a 403. The reservation
// records both (holder `addon:<addon>/<person>`), so audit names the person
// and only the same person, through the same add-on, releases it.
// Unchanged: the node is the operator's placement (strict), and the add-on
// cannot hand over, force, or reach an i163 workload or another add-on's.
// An operator keeps /api/cluster/reservations.

/// The holder a delegated reserve records, `addon:<addon>/<person>`, or why
/// the caller is refused: it must be `addon`'s delegated token, for a person.
pub(crate) fn delegated_holder(sub: &str, act_sub: Option<&str>, addon: &str) -> Result<String, String> {
    if !crate::addon_registry::name_ok(addon) {
        return Err(format!("{addon:?} is not an add-on name"));
    }
    if act_sub != Some(format!("{}{addon}", crate::auth::ADDON_SUBJECT_PREFIX).as_str()) {
        return Err(format!("{addon} reserves for a person: present the delegated token of the person it acts for"));
    }
    let person = crate::auth::account_of(sub);
    if person.is_empty() || person.starts_with(crate::auth::ADDON_SUBJECT_PREFIX) || person.starts_with("key:") {
        return Err("the delegated token names no person".into());
    }
    Ok(format!("{}{addon}/{person}", crate::auth::ADDON_SUBJECT_PREFIX))
}

/// f99 against the person: the delegated token must name the add-on feature
/// it was minted under, and the person must hold it (`holds`). No feature
/// named is refused: there is then nothing f99 could decide.
pub(crate) fn person_admitted(feature: Option<&str>, holds: impl Fn(&str) -> bool) -> Result<(), String> {
    let Some(f) = feature.filter(|f| !f.is_empty()) else {
        return Err("the delegated token names no add-on feature, so f99 cannot admit the person".into());
    };
    if holds(f) {
        Ok(())
    } else {
        Err(format!("the add-on feature {f:?} is off for this person"))
    }
}

/// The requester of an add-on-scoped call, held to [`delegated_holder`] and
/// [`person_admitted`]; the holder it reserves as.
fn addon_caller(ctx: Option<&axum::Extension<crate::auth::RequesterCtx>>, addon: &str) -> Result<String, AppError> {
    let Some(axum::Extension(r)) = ctx else {
        return Err(AppError::Forbidden("a credential is required".into()));
    };
    let holder = delegated_holder(&r.sub, r.act.as_ref().map(|a| a.sub.as_str()), addon).map_err(AppError::Forbidden)?;
    let person = crate::auth::account_of(&r.sub);
    let feature = r.act.as_ref().and_then(|a| a.feature.as_deref());
    person_admitted(feature, |f| crate::addon_access::feature_allows(addon, f, person, r.role).allowed).map_err(AppError::Forbidden)?;
    Ok(holder)
}

/// POST /api/addon-workloads/{addon}/{workload}/reserve — body `{timeout_secs?}`.
async fn addon_reserve(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path((addon, workload)): Path<(String, String)>,
    body: Option<Json<Value>>,
) -> AppResult {
    let actor = addon_caller(ctx.as_ref(), &addon)?;
    let (_, managed, _) = resolve_workload(&state, &addon, &workload).await?;
    let Some(m) = managed else {
        return Err(AppError::Conflict(format!("{addon}/{workload} is not a placed node workload: only those are reserved by the add-on itself")));
    };
    let mut b = json!({"workload": format!("{addon}/{workload}"), "node": m.node});
    if let Some(t) = body.as_ref().and_then(|Json(v)| v.get("timeout_secs")).and_then(Value::as_u64) {
        b["timeout_secs"] = json!(t);
    }
    take(state, actor, b).await
}

/// POST /api/addon-workloads/{addon}/{workload}/release — the add-on's own
/// reservation of it, never another holder's, never forced.
async fn addon_release(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path((addon, workload)): Path<(String, String)>,
) -> AppResult {
    let actor = addon_caller(ctx.as_ref(), &addon)?;
    let key = format!("{addon}/{workload}");
    let Some(r) = all_reservations(&state).await.into_iter().find(|r| r["workload"] == key && r["holder"] == actor) else {
        return Err(AppError::NotFound(format!("{actor} holds no reservation of {key}")));
    };
    let id = r["id"].as_str().unwrap_or("").to_string();
    release(state, actor, id, false).await
}

/// The node's heartbeat row for `addon`/`name` (`node_workloads`), if any.
pub(crate) fn node_workload_row<'a>(record: &'a Value, addon: &str, name: &str) -> Option<&'a Value> {
    record.get("node_workloads")?.as_array()?.iter().find(|r| {
        r.get("addon").and_then(Value::as_str) == Some(addon) && r.get("name").and_then(Value::as_str) == Some(name)
    })
}

/// A new session is refused while the node reports the workload `draining`
/// (docs/reference/node-workloads.md, reported states). Any other state, or
/// no row (an unknown is not a drain), lets it through.
pub(crate) fn refuses_new_session(row: Option<&Value>) -> bool {
    row.and_then(|r| r.get("state")).and_then(Value::as_str) == Some("draining")
}

/// Drain and stop a workload on a node: the add-on's declared drain route,
/// then the actuator's stop. `force` carries on past a failed drain. A node
/// workload's row (`managed`: the state and its node) goes back to
/// `provisioned` between the two, so the agent's stop is the release.
async fn drain_and_stop(
    link: &crate::node_link::NodeLink,
    decl: &crate::addon_workloads::WorkloadDecl,
    reservation: &str,
    force: bool,
    managed: Option<(&AppState, &str)>,
) -> Result<Value, String> {
    let drained;
    let drain = &decl.drain;
    {
        let body = json!({"reservation": reservation, "workload": decl.key(), "timeout_secs": drain.timeout_secs});
        match tokio::time::timeout(
            std::time::Duration::from_secs(drain.timeout_secs + 30),
            crate::addon_proxy::call(&decl.addon, &drain.route, Some(body)),
        )
        .await
        {
            Ok(crate::addon_proxy::CallOutcome::Ok(v)) => drained = v,
            Ok(crate::addon_proxy::CallOutcome::Unavailable(reason)) if !force => return Err(format!("drain route {} refused: {reason}", drain.route)),
            Ok(crate::addon_proxy::CallOutcome::Unavailable(reason)) => {
                tracing::warn!(addon = %decl.addon, route = %drain.route, reason = %reason, "reservation_drain_skipped_by_force");
                drained = json!({"skipped": reason});
            }
            Err(_) if !force => return Err(format!("drain route {} did not answer within {} s", drain.route, drain.timeout_secs + 30)),
            Err(_) => {
                tracing::warn!(addon = %decl.addon, route = %drain.route, "reservation_drain_timeout_forced");
                drained = json!({"skipped": "timeout"});
            }
        }
    }
    if let Some((state, node)) = managed {
        match crate::repo::node_workload_placements::set_provisioned(&state.db, node, &decl.addon, &decl.name, reservation).await {
            Ok(true) => {}
            Ok(false) => tracing::warn!(addon = %decl.addon, workload = %decl.name, %reservation, "reservation_release: the placement was not held by this reservation"),
            Err(e) => return Err(format!("could not set {} back to provisioned: {e}", decl.key())),
        }
    }
    let grace = drain.timeout_secs.min(600);
    let stopped = actuator(link, decl, "/stop", json!({"timeout_secs": grace}), grace + 60).await?;
    Ok(json!({"drained": drained, "stopped": stopped}))
}

/// POST /api/cluster/reservations — body `{workload: "<addon>/<name>",
/// node?, hand_over?: <reservation id>, timeout_secs?}`. Operator only;
/// audited (`reservation_take`).
async fn reservation_take(
    State(state): State<Arc<AppState>>,
    operator: crate::authz::Operator,
    body: Option<Json<Value>>,
) -> AppResult {
    let actor = operator.sub().to_string();
    let b = body.map(|Json(b)| b).unwrap_or_else(|| json!({}));
    take(state, actor, b).await
}

/// A reservation take for `actor` (an operator, or an add-on for its own
/// placed node workload, [`addon_reserve`]). Body as `reservation_take`.
async fn take(state: Arc<AppState>, actor: String, b: Value) -> AppResult {
    let key = b.get("workload").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let Some((addon, name)) = crate::addon_workloads::split_key(&key) else {
        return Err(AppError::BadRequest("workload must be <addon>/<workload> (lowercase names)".into()));
    };
    let (decl, managed, ready_secs) = resolve_workload(&state, &addon, &name).await?;
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
    // A node workload runs where the operator placed it, nowhere else.
    let pinned = match (&managed, pinned) {
        (Some(m), Some(p)) if p != m.node => {
            return Err(AppError::Conflict(format!("{key} is placed on {}, not {p}", m.node)));
        }
        (Some(m), _) => Some(m.node.clone()),
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
            if let Ok((odecl, omanaged, _)) = resolve_workload(&state, &oa, &on).await {
                let onode = o["node"].as_str().unwrap_or("").to_string();
                let out = drain_and_stop(&link, &odecl, o["id"].as_str().unwrap_or(""), false, omanaged.as_ref().map(|_| (state.as_ref(), onode.as_str())))
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

    let release_hold = |why: &'static str| {
        let (state, actor, node, id) = (state.clone(), actor.clone(), node.clone(), id.clone());
        async move {
            let _ = super::cluster::gpu_hold_op(&state, actor, &node, "release",
                json!({"operation_id": id, "generation": generation, "force": false, "legacy": false, "resume": "now"}),
                std::time::Duration::from_secs(90)).await;
            tracing::warn!(%node, reason = why, "reservation_take_gave_the_gpu_back");
        }
    };

    // A node workload: the row runs under this reservation BEFORE the start
    // (the agent's start reads it afresh). Only from provisioned, so a second
    // reservation can never take a workload another one holds.
    if managed.is_some() {
        match crate::repo::node_workload_placements::set_running(&state.db, &node, &addon, &name, &id).await {
            Ok(true) => {}
            Ok(false) => {
                release_hold("already_reserved").await;
                return Err(AppError::Conflict(format!("{key} is already reserved (its placement is not provisioned); release that reservation first")));
            }
            Err(e) => {
                release_hold("placement_unwritable").await;
                return Err(AppError::Internal(format!("could not mark {key} running: {e}; the GPU was released back to the pool")));
            }
        }
    }

    // Start the workload; a start that fails gives the GPU back at once.
    let started = match actuator(&link, &decl, "/start", json!({}), if managed.is_some() { 660 } else { 120 }).await {
        Ok(v) => v,
        Err(e) => {
            if managed.is_some() {
                let _ = crate::repo::node_workload_placements::set_provisioned(&state.db, &node, &addon, &name, &id).await;
            }
            let _ = super::cluster::gpu_hold_op(&state, actor.clone(), &node, "release",
                json!({"operation_id": id, "generation": generation, "force": false, "legacy": false, "resume": "now"}),
                std::time::Duration::from_secs(90)).await;
            audit(&state, AuditKind::ReservationTake, &actor, &node, "error", json!({"id": id, "workload": key, "step": "start", "detail": e})).await;
            return Err(start_failure(&key, &node, &e));
        }
    };
    steps["started"] = started;

    // Ready: the container runs (and passes its healthcheck when it has
    // one). A timeout keeps the reservation and says so.
    let (status, worker, detail) = match wait_ready(&link, &decl, std::time::Duration::from_secs(ready_secs)).await {
        Ok(st) => ("reserved", st, String::new()),
        Err(e) => ("needs_attention", json!({}), e),
    };
    audit(&state, AuditKind::ReservationTake, &actor, &node, if status == "reserved" { "ok" } else { "needs_attention" },
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
    operator: crate::authz::Operator,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult {
    let actor = operator.sub().to_string();
    let force = body.as_ref().and_then(|Json(b)| b.get("force")).and_then(Value::as_bool).unwrap_or(false);
    release(state, actor, id, force).await
}

/// A reservation release by `actor`: the holder, or (`force`) an operator.
async fn release(state: Arc<AppState>, actor: String, id: String, force: bool) -> AppResult {
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
        if let Ok((decl, managed, _)) = resolve_workload(&state, &a, &n).await {
            match drain_and_stop(&link, &decl, &id, force, managed.as_ref().map(|_| (state.as_ref(), node.as_str()))).await {
                Ok(v) => steps["stopped"] = v,
                Err(e) => {
                    audit(&state, AuditKind::ReservationRelease, &actor, &node, "error", json!({"id": id, "workload": key, "detail": e, "force": force})).await;
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
    audit(&state, AuditKind::ReservationRelease, &actor, &node, "ok", json!({"id": id, "workload": key, "holder": holder, "force": force})).await;
    tracing::info!(id = %id, workload = %key, node = %node, actor = %actor, force, "reservation_release");
    Ok(Json(json!({"id": id, "workload": key, "node": node, "status": "released", "steps": steps,
        "gpu_contention": released.get("gpu_contention").cloned().unwrap_or(json!({}))})))
}

async fn audit(
    state: &AppState,
    kind: AuditKind,
    actor: &str,
    node: &str,
    outcome: impl Into<crate::audit::Outcome>,
    details: Value,
) {
    crate::audit::record(
        &state.db,
        AuditEvent::new(kind, actor, &format!("node:{node}")).outcome(outcome).details(details),
    )
    .await;
}

/// `GET /api/addon-workloads/{addon}/{workload}/status`: how an add-on
/// observes its own reservation without touching the worker. The add-on's
/// own token or an operator; 404 when the workload is not declared.
/// `{workload, reserved, reservation: {id, node, holder, state, since,
/// generation} | null}`.
async fn workload_status(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path((addon, workload)): Path<(String, String)>,
) -> AppResult {
    let Some(axum::Extension(r)) = ctx.as_ref() else {
        return Err(AppError::Forbidden("a credential is required".into()));
    };
    let own = crate::addon_workloads::subject_owns(&r.sub, &addon);
    if !own && r.role < crate::auth::Role::Operator {
        return Err(AppError::Forbidden(format!("only the add-on {addon} itself or an operator may read its workloads")));
    }
    let (decl, managed, _) = resolve_workload(&state, &addon, &workload).await?;
    let key = decl.key();
    let res = all_reservations(&state).await.into_iter().find(|r| r["workload"] == key);
    let reserved = res.as_ref().is_some_and(|r| r["state"] == "held");
    let mut out = json!({"workload": key, "container": decl.container, "reserved": reserved,
        "reservation": res.map(|r| json!({"id": r["id"], "node": r["node"], "holder": r["holder"], "state": r["state"], "since": r["since"], "generation": r["generation"]}))});
    // A node workload: what its node reports (heartbeat `node_workloads`).
    if let Some(m) = &managed {
        let record = node_records(&state).await.into_iter().find(|(id, _)| id == &m.node).map(|(_, r)| r).unwrap_or(json!({}));
        out["node"] = json!(m.node);
        out["node_workload"] = node_workload_row(&record, &addon, &workload).cloned().unwrap_or(Value::Null);
    }
    Ok(Json(out))
}

// ── the workload proxy ───────────────────────────────────────────────────

/// `/api/addon-workloads/{addon}/{workload}/proxy/{path}` (any method,
/// WebSocket upgrades included): the add-on's own token (`addon:svc:<addon>`)
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
    let own = crate::addon_workloads::subject_owns(&r.sub, &addon);
    if !own && r.role < crate::auth::Role::Operator {
        return Err(AppError::Forbidden(format!("only the add-on {addon} itself or an operator may reach its workloads")));
    }
    let (decl, managed, _) = resolve_workload(&state, &addon, &workload).await?;
    let key = decl.key();
    let Some(res) = all_reservations(&state).await.into_iter().find(|r| r["workload"] == key && r["state"] == "held") else {
        return Err(AppError::Conflict(format!("not_reserved: {key} holds no GPU right now (noo cluster reserve {key})")));
    };
    let reservation = res["id"].as_str().unwrap_or("").to_string();
    let node = res["node"].as_str().unwrap_or("").to_string();
    // A node workload that is draining takes no NEW session (a WebSocket is
    // a session); requests on the sessions it still serves pass.
    if managed.is_some() && is_websocket_upgrade(&parts.headers) {
        let record = node_records(&state).await.into_iter().find(|(id, _)| id == &node).map(|(_, r)| r).unwrap_or(json!({}));
        if refuses_new_session(node_workload_row(&record, &addon, &workload)) {
            return Err(AppError::Conflict(format!("draining: {key} is draining on {node} and takes no new session")));
        }
    }
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
    let resp = up.send().await.map_err(|e| AppError::Upstream(format!("node agent unreachable: {e}")))?;
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

/// The upstream WebSocket stream: TCP, then the cluster's TLS (tokio-rustls
/// over `tls::cluster_rustls_config`, the same CA and mTLS identity every
/// node call presents) for `wss://`, then the WebSocket handshake.
type UpstreamWs = tokio_tungstenite::WebSocketStream<UpstreamIo>;

/// Plain or TLS, as the agent's URL says.
enum UpstreamIo {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncRead for UpstreamIo {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            UpstreamIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamIo {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpstreamIo::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            UpstreamIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            UpstreamIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            UpstreamIo::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

async fn connect_upstream(request: tokio_tungstenite::tungstenite::handshake::client::Request, url: &str) -> Result<UpstreamWs, String> {
    let uri = request.uri().clone();
    let host = uri.host().ok_or_else(|| format!("no host in {url}"))?.to_string();
    let tls = matches!(uri.scheme_str(), Some("wss") | Some("https"));
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let tcp = tokio::time::timeout(std::time::Duration::from_secs(10), tokio::net::TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| format!("connect to {host}:{port} timed out"))?
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;
    let io = if tls {
        let cfg = match crate::tls::cluster_rustls_config() {
            Ok(Some(cfg)) => cfg,
            Ok(None) => return Err("no cluster TLS config for a wss:// node call".into()),
            Err(e) => return Err(format!("cluster TLS config: {e}")),
        };
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| format!("server name {host}: {e}"))?;
        let s = tokio_rustls::TlsConnector::from(cfg).connect(name, tcp).await.map_err(|e| format!("TLS to {host}:{port}: {e}"))?;
        UpstreamIo::Tls(Box::new(s))
    } else {
        UpstreamIo::Plain(tcp)
    };
    let (ws, _) = tokio_tungstenite::client_async_with_config(request, io, None).await.map_err(|e| format!("websocket handshake with the node agent: {e}"))?;
    Ok(ws)
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
    let upstream = match connect_upstream(request, &url).await {
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
        WorkloadDecl { addon: "pai-voice".into(), name: "voice-worker".into(), container: "noo-pai-voice-worker".into(), gpu, need_mb,
            drain: crate::addon_workloads::DrainSpec { route: "drain".into(), timeout_secs: 120 } }
    }

    #[test]
    fn workload_peer_keeps_the_exchanged_service_identity() {
        let requester = crate::auth::RequesterCtx {
            sub: "addon:svc:pai-voice".into(), scopes: vec!["metrics".into()],
            role: crate::auth::Role::User, harness: None, act: None,
        };
        let headers = peer_headers("reservation-id", &requester);
        assert!(headers.contains(&(PEER_SUB_HEADER.into(), "addon:svc:pai-voice".into())));
        assert!(headers.contains(&(PEER_ROLE_HEADER.into(), "user".into())));
        assert!(!headers.iter().any(|(name, _)| name == "authorization"));
    }

    fn node(gc: Value) -> Value {
        json!({"id": "awolf", "status": "online", "last_heartbeat": 1000.0, "vram_gb": 16, "gpu_contention": gc})
    }

    // ── i300 node workloads (H4) ──────────────────────────────────────────

    fn nw_decl() -> crate::node_workloads::Decl {
        let raw: Value = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/testdata/i300/desired-node-workloads.json")).unwrap(),
        )
        .unwrap();
        let w = raw["node_workloads"][0]["decl"].clone();
        let lock: std::collections::BTreeSet<String> = [w["image"].as_str().unwrap().to_string()].into();
        let file = json!({"format": "noo-addon-node-workloads/1", "workloads": [w]});
        crate::node_workloads::validate_decl(file.to_string().as_bytes(), "rhaddon", &lock, None).unwrap().workloads.remove(0)
    }

    #[test]
    fn a_draining_node_workload_refuses_a_new_session_and_nothing_else_does() {
        let rec = json!({"node_workloads": [
            {"addon": "rhaddon", "name": "worker", "state": "draining", "ready": true, "door_port": 8443},
            {"addon": "rhaddon", "name": "other", "state": "running", "ready": true, "door_port": 8443}]});
        assert!(refuses_new_session(node_workload_row(&rec, "rhaddon", "worker")));
        assert!(!refuses_new_session(node_workload_row(&rec, "rhaddon", "other")), "running takes sessions");
        assert!(!refuses_new_session(node_workload_row(&rec, "rhaddon", "missing")), "no row is not a drain");
        assert!(!refuses_new_session(node_workload_row(&json!({}), "rhaddon", "worker")));
        for st in ["provisioned", "needs_attention", "absent"] {
            let r = json!({"addon": "a", "name": "w", "state": st});
            assert!(!refuses_new_session(Some(&r)), "{st}");
        }
    }

    /// The proxy checks the drain for a node workload's NEW session (a
    /// WebSocket upgrade) before it relays anything.
    #[test]
    fn the_proxy_refuses_a_new_session_while_draining_before_relaying() {
        let own = crate::test_src::own_code(include_str!("reservations.rs"));
        let body = crate::test_src::fn_body(&own, "async fn workload_proxy(");
        let check = body.find("refuses_new_session(").expect("the drain check");
        let relay = body.find("ws.on_upgrade(").expect("the relay");
        assert!(check < relay, "the check comes first");
        assert!(body.contains("resolve_workload(&state, &addon, &workload)"), "node workloads are resolved, not only i163 ones");
    }

    #[test]
    fn a_reserve_is_for_a_person_through_the_addons_own_delegation() {
        let act = Some("addon:rhaddon");
        assert_eq!(delegated_holder("alice", act, "rhaddon").as_deref(), Ok("addon:rhaddon/alice"), "the person is recorded");
        assert!(delegated_holder("addon:rhaddon", None, "rhaddon").is_err(), "the service key alone: no person");
        assert!(delegated_holder("alice", None, "rhaddon").is_err(), "a person's own token is not the add-on acting");
        assert!(delegated_holder("alice", Some("addon:otheraddon"), "rhaddon").is_err(), "another add-on's delegation");
        assert!(delegated_holder("", act, "rhaddon").is_err(), "no person");
        assert!(delegated_holder("addon:rhaddon", act, "rhaddon").is_err(), "an add-on is not a person");
        assert!(delegated_holder("key:svc", act, "rhaddon").is_err(), "a service key is not a person");
        assert!(delegated_holder("alice", Some("addon:../rhaddon"), "../rhaddon").is_err(), "not a name");
        assert_ne!(delegated_holder("alice", act, "rhaddon"), delegated_holder("bob", act, "rhaddon"), "two people hold two different reservations");
    }

    #[test]
    fn f99_decides_on_the_person_and_fails_closed() {
        assert_eq!(person_admitted(Some("converse"), |f| f == "converse"), Ok(()));
        assert!(person_admitted(Some("converse"), |_| false).is_err(), "the feature is off for the person");
        assert!(person_admitted(None, |_| true).is_err(), "no feature named: nothing to decide, refused");
        assert!(person_admitted(Some(""), |_| true).is_err());
    }

    /// The handler holds every add-on call to the person's delegation and f99.
    #[test]
    fn the_addon_routes_decide_the_person_before_anything_else() {
        let own = crate::test_src::own_code(include_str!("reservations.rs"));
        let caller = crate::test_src::fn_body(&own, "fn addon_caller(");
        assert!(caller.contains("delegated_holder(") && caller.contains("person_admitted("), "{caller}");
        assert!(caller.contains("crate::addon_access::feature_allows(addon, f, person, r.role).allowed"), "f99 itself decides");
        for f in ["async fn addon_reserve(", "async fn addon_release("] {
            let body = crate::test_src::fn_body(&own, f);
            assert!(body.trim_start().contains("let actor = addon_caller(ctx.as_ref(), &addon)?;"), "{f}");
        }
    }

    /// The add-on cannot choose the node, hand over or force: its take names
    /// only the workload and the placement's node, and its release is never
    /// forced and only of a reservation it holds.
    #[test]
    fn an_addon_reserves_on_its_placement_and_releases_only_its_own() {
        let own = crate::test_src::own_code(include_str!("reservations.rs"));
        let take = crate::test_src::fn_body(&own, "async fn addon_reserve(");
        assert!(take.contains(r#"json!({"workload": format!("{addon}/{workload}"), "node": m.node})"#), "{take}");
        assert!(!take.contains("hand_over") && !take.contains("force"), "no hand-over, no force");
        assert!(take.contains("let Some(m) = managed else"), "a placed node workload only");
        let rel = crate::test_src::fn_body(&own, "async fn addon_release(");
        assert!(rel.contains(r#"r["holder"] == actor"#) && rel.contains("release(state, actor, id, false)"), "{rel}");
    }

    #[test]
    fn the_ready_wait_is_start_secs_at_most_600() {
        assert_eq!(managed_ready_secs(300), 300);
        assert_eq!(managed_ready_secs(900), 600, "a long cold start is capped");
        assert_eq!(managed_ready_secs(0), 1);
        assert_eq!(managed_ready_secs(-5), 1);
    }

    #[test]
    fn a_node_workloads_gpu_need_is_its_profile_plus_each_extra_slot() {
        let p = crate::node_workloads::SetProfile { name: "int8".into(), vram_mb: Some(14336), per_slot_vram_mb: Some(1024), ..Default::default() };
        assert_eq!(managed_need_mb(Some(&p), 1), 14336);
        assert_eq!(managed_need_mb(Some(&p), 3), 14336 + 2 * 1024);
        assert_eq!(managed_need_mb(None, 4), 0, "no figures: nothing to size");
        let bare = crate::node_workloads::SetProfile { name: "int8".into(), ..Default::default() };
        assert_eq!(managed_need_mb(Some(&bare), 2), 0);
    }

    #[test]
    fn a_placed_node_workload_takes_the_i163_shape_with_its_service_drain() {
        let d = nw_decl();
        let w = managed_decl("rhaddon", &d, 15360);
        assert_eq!(w.key(), format!("rhaddon/{}", d.name));
        assert_eq!(w.container, format!("noo-wl-rhaddon-{}", d.name), "the agent's worker container name");
        assert!(w.gpu);
        assert_eq!(w.need_mb, 15360);
        let sd = d.service_drain.clone().unwrap();
        assert_eq!((w.drain.route.as_str(), w.drain.timeout_secs), (sd.route.as_str(), sd.timeout_secs as u64), "release runs the add-on's service drain");
    }

    #[test]
    fn the_slot_count_is_the_placements_slots_env_else_one() {
        let d = nw_decl();
        let key = d.accel.slots_env.clone().expect("the fixture declares slots_env");
        assert_eq!(placement_slots(&d, &json!({key.clone(): "3"})), 3);
        assert_eq!(placement_slots(&d, &json!({})), 1);
        assert_eq!(placement_slots(&d, &json!({key: "0"})), 1, "zero is not a count");
    }

    /// The release order (docs/reference/node-workloads.md): the add-on's
    /// service drain, then the row back to provisioned, then the agent's stop.
    #[test]
    fn a_node_workloads_row_goes_back_to_provisioned_between_the_drain_and_the_stop() {
        let own = crate::test_src::own_code(include_str!("reservations.rs"));
        let body = crate::test_src::fn_body(&own, "async fn drain_and_stop(");
        let drain = body.find("crate::addon_proxy::call(").expect("the service drain");
        let back = body.find("set_provisioned(").expect("the row goes back");
        let stop = body.find("actuator(link, decl, \"/stop\"").expect("the stop");
        assert!(drain < back && back < stop, "drain, then provisioned, then stop");
    }

    /// The take order: the row runs under the reservation BEFORE the start
    /// (the agent's start reads it afresh), and a start that fails gives it back.
    #[test]
    fn a_node_workloads_row_runs_before_the_start_and_is_given_back_on_failure() {
        let own = crate::test_src::own_code(include_str!("reservations.rs"));
        let body = crate::test_src::fn_body(&own, "async fn take(");
        let run = body.find("set_running(").expect("the row runs");
        let start = body.find("actuator(&link, &decl, \"/start\"").expect("the start");
        assert!(run < start, "running before the start");
        let after = &body[start..];
        assert!(after.find("set_provisioned(").is_some_and(|i| i < after.find("start_failure(").unwrap_or(usize::MAX)), "a failed start gives the row back");
        assert!(body.contains("std::time::Duration::from_secs(ready_secs)"), "the declared ready wait");
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
        assert_eq!(reservation_of("x", &plain).unwrap()["purpose"], "");
        let user = json!({"gpu_contention": {"state": "held", "lease": {"operation_id": "op-u", "owner": "op", "purpose": "user"}}});
        assert_eq!(reservation_of("x", &user).unwrap()["purpose"], "user");
    }

    #[test]
    fn a_not_declared_start_is_a_retryable_503_and_other_failures_stay_internal() {
        match start_failure("rhaddon/rhworker", "awolf", "not_declared (404): no such workload") {
            AppError::UnavailableRetry { code, detail, retry_after_secs } => {
                assert_eq!(code, "node_workloads_not_loaded");
                assert!(detail.contains("has not loaded its workload declarations yet; retry"), "{detail}");
                assert!(retry_after_secs > 0);
            }
            other => panic!("not_declared must be retryable, got {other:?}"),
        }
        assert!(matches!(start_failure("k", "n", "docker_error (500): boom"), AppError::Internal(_)));
        assert!(matches!(start_failure("k", "n", "node agent unreachable: x"), AppError::Internal(_)));
    }

    #[test]
    fn the_actuator_paths_are_the_agents() {
        let d = decl(true, 0);
        assert_eq!(actuator_path(&d, "/start"), "/api/addon-workloads/pai-voice/voice-worker/start");
        assert_eq!(actuator_path(&d, ""), "/api/addon-workloads/pai-voice/voice-worker");
    }

    /// The record the hold write-back produces yields the new lease at once.
    #[test]
    fn a_merged_record_lists_the_new_lease_and_a_release_clears_it() {
        let rec = json!({"id": "awolf", "status": "online", "gpu_contention": {"state": "free", "total_mb": 16376}});
        let held = super::super::cluster::with_contention(rec, json!({"state": "held", "total_mb": 16376, "paused_backends": ["vllm"],
            "lease": {"operation_id": "op-7", "owner": "op", "workload": "pai-voice/voice-worker", "generation": 3}}));
        let r = reservation_of("awolf", &held).expect("the new lease is a reservation");
        assert_eq!(r["id"], "op-7");
        assert_eq!(r["generation"], 3);
        assert_eq!(r["state"], "held");
        let freed = super::super::cluster::with_contention(held, json!({"state": "free", "total_mb": 16376}));
        assert!(reservation_of("awolf", &freed).is_none());
    }

    /// Source test: the reservation routes are operator-gated and audited;
    /// a failed start releases the GPU; a ready timeout keeps the holder.
    #[test]
    fn take_and_release_are_gated_audited_and_never_strand_a_gpu() {
        let own = crate::test_src::own_code(include_str!("reservations.rs"));
        // The operator route gates, then hands the body to the shared take()
        // (H5: the add-on route shares it), where the order lives.
        let entry = crate::test_src::fn_body(&own, "async fn reservation_take(");
        assert!(entry.contains("operator: crate::authz::Operator"), "operator gate (an extractor, so it runs before the body)");
        assert!(entry.contains("take(state, actor, b).await"), "the operator route runs the shared take");
        let take = crate::test_src::fn_body(&own, "async fn take(");
        let start = take.find("\"/start\"").expect("start");
        let rollback = take[start..].find("\"release\"").expect("a failed start releases");
        assert!(take[start + rollback..].contains("\"resume\": \"now\""), "the pool gets the GPU back at once");
        assert!(take.contains("\"needs_attention\""), "a ready timeout keeps the reservation and says so");
        assert!(take.matches("audit(&state, AuditKind::ReservationTake").count() >= 2);
        let rel_entry = crate::test_src::fn_body(&own, "async fn reservation_release(");
        assert!(rel_entry.contains("operator: crate::authz::Operator") && rel_entry.contains("release(state, actor, id, force).await"));
        let rel = crate::test_src::fn_body(&own, "async fn release(");
        assert!(rel.contains("holder != actor && !force"), "only the holder, or a force");
        assert!(rel.find("drain_and_stop(").unwrap() < rel.find("\"release\"").unwrap(), "the workload stops before the lease is released");
        let proxy = crate::test_src::fn_body(&own, "async fn workload_proxy(");
        assert!(proxy.contains("r[\"state\"] == \"held\""), "only a reserved workload is reachable");
        assert!(proxy.contains("decl.container"), "the container comes from the declaration, never the caller");
        assert!(proxy.find("r.role < crate::auth::Role::Operator").unwrap() < proxy.find("resolve_workload(&state, &addon").unwrap(), "identity before anything is looked up");
        let relay = crate::test_src::fn_body(&own, "async fn relay_websocket(");
        assert!(relay.contains("CLOSE_RESERVATION_ENDED"), "a relayed stream closes with the reservation");
        assert_eq!(CLOSE_RESERVATION_ENDED, 4001);
    }

    /// i460: an actuator 200 cut off mid-body is an error naming the
    /// workload, never `{}` handed to the caller as the agent's answer.
    #[tokio::test]
    async fn a_cut_off_actuator_answer_is_an_error_not_an_empty_object() {
        let link = crate::node_link::NodeLink::for_base(&crate::upstream_body::stub_cut_short().await);
        let e = actuator(&link, &decl(true, 1), "/start", json!({}), 5).await.unwrap_err();
        assert!(e.starts_with("the voice-worker workload actuator answered HTTP 200 but its body could not be read"), "{e}");
    }
}
