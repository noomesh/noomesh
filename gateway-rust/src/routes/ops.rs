// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Asynchronous operations: the HTTP surface and the registry of types.
//!
//! The engine, the store and the guarantees are in `crate::ops`; read that
//! module's header first. This file is two things:
//!
//! 1. The generic API.
//!
//! | route | does |
//! |---|---|
//! | `POST /api/v1/ops {type, params}` | start an op; `202 {op_id, status, poll, poll_interval_ms}` |
//! | `GET /api/v1/ops/{id}?wait=<s>` | status, progress, result or error; `wait` long-polls (bounded) |
//! | `DELETE /api/v1/ops/{id}` | cancel: stop the gateway-side wait, say what the worker does |
//! | `GET /api/v1/ops?mine=1&status=` | the caller's ops (an admin: everyone's) |
//! | `GET /api/v1/ops/types` | the registered types |
//!
//! 2. The registry. Each [`OpType`] names the SAME shared function its
//!    synchronous route used to run (`knowledge::recluster_core`, ...). The
//!    long routes themselves are no longer a place work happens: each one is
//!    [`route_start`], which starts the op and waits up to the type's
//!    `default_wait` (or `?wait=`): finished in time = `200` with the result in
//!    today's shape, otherwise `202` with the handle. A type that slows down
//!    later therefore starts answering with handles by itself, and no request
//!    is ever held for a whole run.
//!
//! AUTHORISATION. Starting an op asks `auth::requester_allows(POST, route)`
//! about the operation's OWN route, so the check is the one that route is
//! subject to at the front door, not a copy of it. Anything the route's
//! handler enforces itself (the Intelligent-tier gate, the audience filter) is
//! inside the shared function, which the op runs with the OWNER's identity
//! captured at start.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{Method, StatusCode},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use super::delegation::StatusJson;
use super::{knowledge, snapshots};
use crate::auth::RequesterCtx;
use crate::ops::{self, CancelOutcome, OpCtx, OpRow, OpSpec, Outcome, RunFuture, StartError, Started, MAX_WAIT_SECS};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/ops", get(ops_list).post(ops_start))
        // Registered before `{id}`, which would otherwise read "types" as an id.
        .route("/api/v1/ops/types", get(ops_types))
        .route("/api/v1/ops/{id}", get(ops_get).delete(ops_cancel))
}

/// `?wait=<seconds>` on a long route: how long to hold the request for the op
/// before answering with its handle. Absent = the type's `default_wait`.
#[derive(Deserialize, Default)]
pub(super) struct WaitQuery {
    pub wait: Option<u64>,
}

// ───────────────────────────── the registry ─────────────────────────────

/// One registered operation type: its declaration, the function that runs it,
/// and the refusal (if any) that must come BEFORE an op exists.
pub struct OpType {
    pub spec: OpSpec,
    pub run: fn(Arc<AppState>, OpCtx, Value) -> RunFuture,
    /// A licensing/availability refusal the synchronous route gave before
    /// dispatch (a Basic install asking for an Intelligent-tier op). Answered
    /// at start, not recorded as a doomed op.
    pub precheck: fn() -> Option<StatusJson>,
}

fn no_precheck() -> Option<StatusJson> {
    None
}

fn worker_budget() -> Duration {
    crate::worker_client::worker_timeout() + Duration::from_secs(30)
}

fn recluster_budget() -> Duration {
    crate::memory::provider::RECLUSTER_TIMEOUT + Duration::from_secs(30)
}

/// The cleanup scans every entity with three correlated counts, then stages and
/// deletes in batches of 200 (at most 5,000 per run): minutes on a real graph.
fn entity_cleanup_budget() -> Duration {
    crate::memory::provider::ENTITY_CLEANUP_TIMEOUT + Duration::from_secs(30)
}

/// A consolidation is "30 s to 5 min" by the worker's own account.
fn consolidate_budget() -> Duration {
    Duration::from_secs(600)
}

/// Every registered type. The names are the public contract (`type` in
/// `POST /api/v1/ops`); the `route` of each is the synchronous route that is
/// now a thin start-and-wait over the same op.
pub static TYPES: &[OpType] = &[
    OpType {
        spec: OpSpec {
            name: "graph.recluster",
            summary: "Rebuild the entity communities (groups related entities into labelled clusters). Minutes.",
            route: "/api/v1/graph/recluster",
            timeout: recluster_budget,
            default_wait_secs: 0,
            poll_interval_ms: 5000,
            cancel_note: "the worker's clustering run is NOT stopped; it finishes on its own, and a new recluster is \
                          refused as already_running until it does",
            exclusive: true,
            retry_safe: true,
            writes_user_data: false,
            admin_only: false,
            human_only_apply: false,
            redact: ops::redact_default,
        },
        run: run_recluster,
        precheck: pre_recluster,
    },
    OpType {
        spec: OpSpec {
            name: "graph.extract_relations",
            summary: "Typed relation extraction for one page (an LLM pass).",
            route: "/api/v1/graph/extract-relations",
            timeout: worker_budget,
            default_wait_secs: 3,
            poll_interval_ms: 2000,
            cancel_note: "the worker's extraction is NOT stopped; edges it has already written stay",
            exclusive: false,
            retry_safe: false,
            writes_user_data: true,
            admin_only: false,
            human_only_apply: false,
            redact: ops::redact_default,
        },
        run: run_extract_relations,
        precheck: pre_extract_relations,
    },
    OpType {
        spec: OpSpec {
            name: "snapshots.consolidate",
            summary: "Slice the live graph into a snapshot (the worker builds it in the background; this follows it to complete).",
            route: "/api/snapshots/consolidate",
            timeout: consolidate_budget,
            default_wait_secs: 3,
            poll_interval_ms: 3000,
            cancel_note: "the snapshot keeps building in the worker; this stops following it (GET /api/snapshots/{id} \
                          still reports it)",
            exclusive: false,
            retry_safe: false,
            writes_user_data: true,
            admin_only: false,
            human_only_apply: false,
            redact: ops::redact_default,
        },
        run: run_consolidate,
        precheck: no_precheck,
    },
    OpType {
        spec: OpSpec {
            name: "graph.navigate",
            summary: "Graph-guided navigation: seeds, expansion, pages, hypotheses. Audience-filtered.",
            route: "/api/v1/graph/navigate",
            timeout: worker_budget,
            default_wait_secs: 12,
            poll_interval_ms: 1000,
            cancel_note: "the worker finishes the walk and its result is discarded",
            exclusive: false,
            retry_safe: true,
            writes_user_data: true,
            admin_only: false,
            human_only_apply: false,
            redact: ops::redact_default,
        },
        run: run_navigate,
        precheck: pre_navigate,
    },
    OpType {
        spec: OpSpec {
            name: "graph.traverse",
            summary: "Intent-weighted priority traversal from an entity. Audience-filtered.",
            route: "/api/v1/graph/traverse",
            timeout: worker_budget,
            default_wait_secs: 12,
            poll_interval_ms: 1000,
            cancel_note: "the worker finishes the traversal and its result is discarded",
            exclusive: false,
            retry_safe: true,
            writes_user_data: true,
            admin_only: false,
            human_only_apply: false,
            redact: ops::redact_default,
        },
        run: run_traverse,
        precheck: pre_traverse,
    },
    OpType {
        spec: OpSpec {
            name: "rag.ingest",
            summary: "Ingest a document into the knowledge base (the operator route).",
            route: "/api/v1/rag/ingest",
            timeout: worker_budget,
            default_wait_secs: 3,
            poll_interval_ms: 2000,
            cancel_note: "the worker may still finish ingesting the document",
            exclusive: false,
            retry_safe: false,
            writes_user_data: true,
            admin_only: false,
            human_only_apply: false,
            redact: redact_ingest,
        },
        run: run_rag_ingest,
        precheck: no_precheck,
    },
    OpType {
        spec: OpSpec {
            name: "docs.ingest",
            summary: "Ingest a document into the knowledge base (the upload route; the `ingest` scope suffices).",
            route: "/api/v1/docs/ingest",
            timeout: worker_budget,
            default_wait_secs: 3,
            poll_interval_ms: 2000,
            cancel_note: "the worker may still finish ingesting the document",
            exclusive: false,
            retry_safe: false,
            writes_user_data: true,
            admin_only: false,
            human_only_apply: false,
            redact: redact_ingest,
        },
        run: run_docs_ingest,
        precheck: no_precheck,
    },
    OpType {
        spec: OpSpec {
            name: "graph.entity_cleanup",
            summary: "Stage and remove the junk entities already in the graph (dry run unless `apply`). Admin only; restorable for 30 days.",
            route: "/api/v1/graph/entity-cleanup",
            timeout: entity_cleanup_budget,
            default_wait_secs: 3,
            poll_interval_ms: 3000,
            cancel_note: "the worker's cleanup is NOT stopped; batches it has already committed stay staged and are \
                          restorable (POST /api/v1/graph/prune/restore), and a new apply is refused as busy until it ends",
            exclusive: false,
            retry_safe: true,
            writes_user_data: true,
            admin_only: true,
            human_only_apply: true,
            redact: ops::redact_default,
        },
        run: run_entity_cleanup,
        precheck: no_precheck,
    },
];

/// The type named `name`.
pub fn find(name: &str) -> Option<&'static OpType> {
    TYPES.iter().find(|t| t.spec.name == name)
}

fn type_for_row(row: &OpRow) -> Option<&'static OpType> {
    find(&row.op_type)
}

/// The only ingest params the row records. An ALLOW-list, not a deny-list: the
/// worker reads `request.params` as well as the top level, so a deny-list of
/// text-like names stored `{"params": {"text": ...}}` for a day. Everything else
/// (the document, `metadata`, whatever a future field is) is recorded as its
/// size alone. Nested `params` objects get the same treatment.
const INGEST_STORED: &[&str] = &["title", "source", "source_uri", "roles", "force", "persona_id"];

fn redact_ingest(params: &Value) -> Value {
    fn walk(v: &Value, depth: u8) -> Value {
        let Some(obj) = v.as_object() else { return json!({"_omitted_bytes": v.to_string().len()}) };
        let mut out = serde_json::Map::new();
        for (k, val) in obj {
            if k == "_requester" {
                continue;
            }
            let keep = INGEST_STORED.contains(&k.as_str());
            if keep && !val.is_object() && val.to_string().len() <= 512 {
                out.insert(k.clone(), val.clone());
            } else if k == "params" && depth < 4 && val.is_object() {
                out.insert(k.clone(), walk(val, depth + 1));
            } else {
                out.insert(k.clone(), json!({"_omitted_bytes": val.as_str().map(str::len).unwrap_or_else(|| val.to_string().len())}));
            }
        }
        Value::Object(out)
    }
    ops::cap_params(walk(params, 0))
}

// ── adapters: each calls the SAME function the synchronous route did ──────────

fn pre_recluster() -> Option<StatusJson> {
    knowledge::intel_refusal(knowledge::RECLUSTER_WHAT)
}
fn pre_extract_relations() -> Option<StatusJson> {
    knowledge::intel_refusal(knowledge::EXTRACT_RELATIONS_WHAT)
}
fn pre_navigate() -> Option<StatusJson> {
    knowledge::intel_refusal(knowledge::NAVIGATE_WHAT)
}
fn pre_traverse() -> Option<StatusJson> {
    knowledge::intel_refusal(knowledge::TRAVERSE_WHAT)
}

fn outcome_of((status, Json(body)): StatusJson) -> Outcome {
    Outcome::from_http(status.as_u16(), body)
}

fn run_recluster(state: Arc<AppState>, c: OpCtx, params: Value) -> RunFuture {
    Box::pin(async move {
        let mut out = outcome_of(knowledge::recluster_core(&state, &c.ctx(), params).await);
        // The worker answers 200 `already_running` and starts nothing. An op
        // that started nothing did not succeed, whatever the status line says.
        if out.failure.is_none() && out.body.get("status").and_then(Value::as_str) == Some("already_running") {
            out.failure = Some(
                "already_running: a clustering run is already in flight in the worker (started elsewhere, \
                 e.g. the heartbeat); this request started nothing"
                    .to_string(),
            );
        }
        out
    })
}

fn run_entity_cleanup(state: Arc<AppState>, c: OpCtx, params: Value) -> RunFuture {
    Box::pin(async move {
        // Destructive: an op whose row was erased or cancelled before it got
        // here deletes nothing.
        if !c.still_live().await {
            return no_longer_wanted();
        }
        knowledge::entity_cleanup_core(&state, &c.ctx(), params).await
    })
}

fn run_extract_relations(state: Arc<AppState>, c: OpCtx, params: Value) -> RunFuture {
    Box::pin(async move {
        if !c.still_live().await {
            return no_longer_wanted();
        }
        outcome_of(knowledge::extract_relations_core(&state, c.ctx(), params).await)
    })
}

fn run_navigate(state: Arc<AppState>, c: OpCtx, params: Value) -> RunFuture {
    Box::pin(async move {
        if !c.still_live().await {
            return no_longer_wanted();
        }
        outcome_of(knowledge::navigate_core(&state, c.ctx(), params).await)
    })
}

fn run_traverse(state: Arc<AppState>, c: OpCtx, params: Value) -> RunFuture {
    Box::pin(async move {
        if !c.still_live().await {
            return no_longer_wanted();
        }
        outcome_of(knowledge::traverse_core(&state, c.ctx(), params).await)
    })
}

/// Said when the op's row is gone (its owner was erased) or it was cancelled
/// between start and dispatch.
fn no_longer_wanted() -> Outcome {
    Outcome::failed(410, json!({"error": "this operation was erased or cancelled before it ran"}), "operation no longer live; nothing was written")
}

fn run_rag_ingest(state: Arc<AppState>, c: OpCtx, params: Value) -> RunFuture {
    Box::pin(async move {
        if !c.still_live().await {
            return no_longer_wanted();
        }
        outcome_of(knowledge::rag_ingest_core(&state, &c.ctx(), params).await)
    })
}

fn run_docs_ingest(state: Arc<AppState>, c: OpCtx, params: Value) -> RunFuture {
    Box::pin(async move {
        if !c.still_live().await {
            return no_longer_wanted();
        }
        outcome_of(knowledge::docs_ingest_core(&state, &c.ctx(), params).await)
    })
}

/// Consolidate: ONE call to the shared function (which makes the worker
/// create the snapshot row and answer `building`), then follow that snapshot
/// to `complete` or `failed`. It never calls consolidate twice.
fn run_consolidate(state: Arc<AppState>, c: OpCtx, params: Value) -> RunFuture {
    Box::pin(async move {
        if !c.still_live().await {
            return no_longer_wanted();
        }
        let out = outcome_of(snapshots::consolidate_core(&state, &c.ctx(), params).await);
        if out.failure.is_some() {
            return out;
        }
        let building = out.body.get("status").and_then(Value::as_str) == Some("building");
        let Some(id) = out.body.get("snapshot_id").and_then(Value::as_str).map(str::to_string) else {
            return out;
        };
        if !building {
            return out;
        }
        c.progress(json!({"snapshot_id": id, "snapshot_status": "building"})).await;
        let mut errors = 0u32;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            match state.memory().snapshots_get(&id).await {
                Ok(Some(snap)) => {
                    errors = 0;
                    let status = snap.get("status").and_then(Value::as_str).unwrap_or("").to_string();
                    if status != "building" && !status.is_empty() {
                        let mut body = out.body.clone();
                        body["status"] = json!(status);
                        body["note"] = json!(format!("consolidation finished — GET /api/snapshots/{id} for the snapshot"));
                        return if status == "failed" {
                            Outcome::failed(200, body, format!("snapshot {id} failed; GET /api/snapshots/{id} says why"))
                        } else {
                            Outcome::done(200, body)
                        };
                    }
                }
                Ok(None) => {
                    return Outcome::failed(
                        500,
                        json!({"snapshot_id": id}),
                        format!("snapshot {id} vanished while it was being built"),
                    );
                }
                Err(e) => {
                    errors += 1;
                    tracing::warn!(snapshot = %id, error = %e, "consolidate_op_poll_failed");
                    if errors >= 5 {
                        return Outcome::failed(
                            503,
                            json!({"snapshot_id": id}),
                            format!("lost sight of snapshot {id}: {e}; GET /api/snapshots/{id} when the database is back"),
                        );
                    }
                }
            }
        }
    })
}

// ───────────────────────────── erasure ─────────────────────────────

/// How long an erase-pending mark lasts: twice the longest run limit, so an
/// abandoned erase cannot lock the account forever.
pub(crate) fn erase_pending_ttl_secs() -> u64 {
    TYPES.iter().map(|t| (t.spec.timeout)().as_secs()).max().unwrap_or(930) * 2
}

/// If `owner` has a write-side operation live, or cancelled but whose worker
/// run may still be going, the seconds until the last of them can have ended
/// (the Retry-After of the refused erase); `None` if the erase may proceed.
/// An op of a type the registry does not know is treated as write-side.
pub(crate) async fn erase_block(tx: &mut sqlx::PgConnection, owner: Uuid) -> Result<Option<u64>, sqlx::Error> {
    use sqlx::Row as _;
    let rows = sqlx::query(
        "SELECT op_type, status, COALESCE(started_at, created_at) AS since, \
                worker_may_run_until AS may_run_until \
           FROM noo_ops WHERE owner_uuid = $1 AND ( status IN ('queued','running') \
                OR worker_may_run_until > now() )",
    )
    .bind(owner)
    .fetch_all(tx)
    .await?;
    let now = chrono::Utc::now();
    let mut longest: Option<u64> = None;
    for r in rows {
        let op_type: String = r.try_get("op_type")?;
        let status: String = r.try_get("status")?;
        let (writes, limit) = match find(&op_type) {
            Some(t) => (t.spec.writes_user_data, (t.spec.timeout)()),
            None => (true, Duration::from_secs(930)),
        };
        if !writes {
            continue;
        }
        // ANY status with a worker window still open blocks (cancelled, and
        // failed by a restart, a lost runner or a supervisor timeout).
        let window: Option<chrono::DateTime<chrono::Utc>> = r.try_get("may_run_until")?;
        let end = if window.is_some_and(|w| w > now) {
            window
        } else if status == "queued" || status == "running" {
            let since: chrono::DateTime<chrono::Utc> = r.try_get("since")?;
            Some(since + chrono::Duration::from_std(limit).unwrap_or_default())
        } else {
            None
        };
        if let Some(end) = end {
            let secs = (end - now).num_seconds().max(1) as u64;
            longest = Some(longest.map_or(secs, |l| l.max(secs)));
        }
    }
    Ok(longest)
}

// ───────────────────────────── starting ─────────────────────────────

fn refuse(status: StatusCode, msg: impl Into<String>) -> StatusJson {
    (status, Json(json!({"error": msg.into()})))
}

/// The handle a start answers with.
fn handle(row: &OpRow, spec: &OpSpec, joined: bool) -> Value {
    let mut v = json!({
        "op_id": row.op_id,
        "type": row.op_type,
        "status": row.status,
        "poll": format!("/api/v1/ops/{}", row.op_id),
        "poll_interval_ms": spec.poll_interval_ms,
        "hint": "poll GET <poll> (add ?wait=<s> to long-poll); from an MCP client call noo_op_status with this op_id",
    });
    if joined {
        v["joined"] = json!(true);
        v["note"] = json!("this type runs one at a time and your own run is already in flight; this request joined it and started nothing new");
    }
    v
}

/// What a finished op answers a waiting route with: the status line and body
/// the synchronous route would have given for the same run.
fn compat_reply(row: &OpRow) -> StatusJson {
    let status = |default: u16| {
        StatusCode::from_u16(row.result_status.unwrap_or(default as i32) as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    };
    match row.status.as_str() {
        ops::SUCCEEDED => (status(200), Json(row.result.clone().unwrap_or(Value::Null))),
        ops::FAILED => match &row.result {
            Some(body) => (status(500), Json(body.clone())),
            None => (status(500), Json(json!({"error": row.error, "op_id": row.op_id}))),
        },
        ops::CANCELLED => (
            StatusCode::CONFLICT,
            Json(json!({"error": "the operation was cancelled while this request waited for it", "op_id": row.op_id})),
        ),
        _ => (
            StatusCode::GONE,
            Json(json!({"error": "the operation's result has expired", "op_id": row.op_id})),
        ),
    }
}

fn busy_body(spec: &OpSpec) -> Value {
    json!({
        "status": "already_running",
        "message": format!(
            "a {} run started by another account is in flight; this request started nothing",
            spec.name
        ),
    })
}

fn start_error(e: StartError) -> StatusJson {
    match e {
        StartError::NoAccount => refuse(
            StatusCode::FORBIDDEN,
            "an operation belongs to an account, and this credential's account has no record",
        ),
        StartError::TooMany(cap) => refuse(
            StatusCode::TOO_MANY_REQUESTS,
            format!("this account already has {cap} operations in flight; wait for one to finish or cancel one"),
        ),
        StartError::Contended => refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "another operation start for this account is in progress; retry in a moment",
        ),
        StartError::ErasePending => refuse(
            StatusCode::LOCKED,
            "erasure is pending for this account: new operations are refused until it completes (or the mark expires)",
        ),
        StartError::Db(e) => {
            tracing::error!(error = %e, "ops_store_unavailable");
            refuse(StatusCode::SERVICE_UNAVAILABLE, "the operations store is unavailable")
        }
    }
}

/// Why a harness credential's apply is refused. Names the command a person runs.
pub(crate) fn human_only_apply_message(name: &str) -> String {
    format!(
        "{name} only previews over MCP or any agent harness; the delete needs a person at a terminal: \
         run `noo graph entity-cleanup --apply`"
    )
}

/// Start `spec` for `ctx`: validate, authorise against the operation's own
/// route, run the pre-dispatch refusal, then create the op. `Err` is the
/// response to send.
pub(crate) async fn begin(
    db: &PgPool,
    ctx: &Option<axum::Extension<RequesterCtx>>,
    spec: &'static OpSpec,
    precheck: fn() -> Option<StatusJson>,
    params: Value,
    runner: Box<dyn FnOnce(OpCtx, Value) -> RunFuture + Send + 'static>,
) -> Result<Started, StatusJson> {
    let params = if params.is_null() { json!({}) } else { params };
    if !params.is_object() {
        return Err(refuse(StatusCode::BAD_REQUEST, "params must be a JSON object"));
    }
    let requester = ctx.as_ref().map(|axum::Extension(r)| r);
    let principal = crate::bus_principal::current();
    // The route's own front-door rule, asked again about the route this op is
    // the body of. A caller with NO RequesterCtx is admitted only if it is the
    // controller's own internal service (a controller-secret caller, which the
    // front door admits with full access): anything else, including a
    // credential class added later, has no account to own the op and is refused
    // rather than run unrestricted.
    if requester.is_none() && !crate::bus_principal::is_internal_cluster(&principal) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "an operation belongs to an account; this credential has none and is not a controller service",
        ));
    }
    // An admin-only type needs an accountable Admin: an operator, a user and a
    // credential with no account (a controller service) are all refused, and
    // before anything is created. The front door cannot say this (it admits an
    // Operator everywhere), so the type declares it.
    if spec.admin_only && !requester.is_some_and(|r| r.role >= crate::auth::Role::Admin) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            format!("{} needs the Admin role; an operator or service credential cannot start it", spec.name),
        ));
    }
    // A destructive admin run is never started by ANY delegated or exchanged
    // credential: a worker-delegated agent token (`act.sub` = the worker), an
    // identity-exchange token (`act.sub` = `key:<consumer>`, role = min(subject,
    // issuer), so a key bound to an admin mints an Admin token) or any actor
    // added later. Each is prompt-injectable or a loop away from deleting 5,000
    // entities per call, and none is a person at a terminal. So: refuse on
    // `act` being PRESENT, not on its value, and even though the operator door's
    // tool for it makes the route a "tool route".
    if spec.admin_only && requester.is_some_and(|r| r.act.is_some()) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            format!(
                "{} is a destructive admin operation: a delegated or exchanged credential (an agent or key token) cannot start it",
                spec.name
            ),
        ));
    }
    if spec.human_only_apply
        && requester.is_some_and(|r| r.harness.is_some())
        && params.get("apply").and_then(Value::as_bool) == Some(true)
    {
        return Err(refuse(StatusCode::FORBIDDEN, human_only_apply_message(spec.name)));
    }
    if let Some(r) = requester {
        // A worker-delegated token (an agentic run, prompt-injectable) is
        // confined to the tool routes: it gets 403 on `POST /api/v1/rag/ingest`
        // directly, so it must not reach the same work through
        // `POST /api/v1/ops {type: rag.ingest}`. The same confinement, asked
        // about the operation's own route.
        if r.act.as_ref().is_some_and(|a| a.sub == crate::worker_delegation::WORKER_ACTOR)
            && !crate::worker_delegation::route_allowed("POST", spec.route)
        {
            return Err(refuse(
                StatusCode::FORBIDDEN,
                format!("{} is not a tool route: a delegated agent token cannot start it", spec.name),
            ));
        }
        if !crate::auth::requester_allows(r, &Method::POST, spec.route) {
            return Err(refuse(
                StatusCode::FORBIDDEN,
                format!(
                    "starting {} needs what POST {} needs, and this credential does not have it",
                    spec.name, spec.route
                ),
            ));
        }
    }
    if let Some(refusal) = precheck() {
        return Err(refusal);
    }
    ops::start(db, spec, requester, principal, params, runner).await.map_err(start_error)
}

/// The thing every long route is: start the op, wait up to `wait` (or the
/// type's default) for it, answer with the result in today's shape if it
/// finished and with the handle if it did not.
pub(crate) async fn serve(
    db: &PgPool,
    ctx: &Option<axum::Extension<RequesterCtx>>,
    spec: &'static OpSpec,
    precheck: fn() -> Option<StatusJson>,
    params: Value,
    wait: Option<u64>,
    busy_status: StatusCode,
    runner: Box<dyn FnOnce(OpCtx, Value) -> RunFuture + Send + 'static>,
) -> StatusJson {
    let (mut row, joined) = match begin(db, ctx, spec, precheck, params, runner).await {
        Ok(Started::New(r)) => (r, false),
        Ok(Started::Joined(r)) => (r, true),
        Ok(Started::Busy) => return (busy_status, Json(busy_body(spec))),
        Err(refusal) => return refusal,
    };
    let secs = wait.unwrap_or_else(|| spec.default_wait()).min(MAX_WAIT_SECS);
    if secs > 0 {
        match ops::wait_terminal(db, row.op_id, Duration::from_secs(secs)).await {
            Ok(Some(r)) if r.is_terminal() => return compat_reply(&r),
            Ok(Some(r)) => row = r,
            _ => {}
        }
    }
    (StatusCode::ACCEPTED, Json(handle(&row, spec, joined)))
}

/// A long route's body. `type_name` is one of [`TYPES`].
pub(super) async fn route_start(
    state: &Arc<AppState>,
    ctx: &Option<axum::Extension<RequesterCtx>>,
    type_name: &str,
    params: Value,
    wait: Option<u64>,
) -> StatusJson {
    let Some(ty) = find(type_name) else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("no operation type named {type_name}"));
    };
    let st = state.clone();
    let run = ty.run;
    // A long route that finds another account's run in flight answers as the
    // worker always did: 200 `already_running`, nothing started.
    serve(&state.db, ctx, &ty.spec, ty.precheck, params, wait, StatusCode::OK, Box::new(move |c, p| run(st, c, p))).await
}

// ───────────────────────────── the generic API ─────────────────────────────

#[derive(Deserialize)]
struct StartBody {
    #[serde(rename = "type")]
    op_type: String,
    #[serde(default)]
    params: Value,
}

/// POST /api/v1/ops — start an operation by type; answers `202` with the
/// handle at once and never waits (poll `GET /api/v1/ops/{id}?wait=`).
/// Authorised exactly as the type's own route is (`GET /api/v1/ops/types`
/// names it); a caller without that route's role is refused with 403.
async fn ops_start(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
    Json(body): Json<StartBody>,
) -> StatusJson {
    let Some(ty) = find(&body.op_type) else {
        let known: Vec<&str> = TYPES.iter().map(|t| t.spec.name).collect();
        return refuse(
            StatusCode::BAD_REQUEST,
            format!("unknown operation type `{}`; known types: {}", body.op_type, known.join(", ")),
        );
    };
    let st = state.clone();
    let run = ty.run;
    serve(
        &state.db,
        &ctx,
        &ty.spec,
        ty.precheck,
        body.params,
        Some(0),
        StatusCode::CONFLICT,
        Box::new(move |c, p| run(st, c, p)),
    )
    .await
}

fn view_of(row: &OpRow, include_result: bool) -> Value {
    let ty = type_for_row(row);
    row.view(
        include_result,
        ty.map(|t| t.spec.poll_interval_ms).unwrap_or(2000),
        ty.map(|t| t.spec.retry_safe),
    )
}

fn parse_id(id: &str) -> Option<Uuid> {
    Uuid::parse_str(id).ok()
}

fn not_found() -> StatusJson {
    // The one body for "no such op" AND "not yours".
    refuse(StatusCode::NOT_FOUND, "no such operation")
}

#[derive(Deserialize, Default)]
struct GetQuery {
    wait: Option<u64>,
}

/// The status read, over the pool alone (so it can be tested without a
/// gateway): visibility, then an optional bounded long-poll.
pub(crate) async fn read_op(
    db: &PgPool,
    requester: Option<&RequesterCtx>,
    id: &str,
    wait: Option<u64>,
) -> StatusJson {
    let Some(op_id) = parse_id(id) else { return not_found() };
    let row = match ops::get_visible(db, requester, op_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => return start_error(StartError::Db(e)),
    };
    let secs = wait.unwrap_or(0).min(MAX_WAIT_SECS);
    let row = if secs > 0 && !row.is_terminal() {
        // Visibility was decided above; waiting re-reads by id only.
        match ops::wait_terminal(db, op_id, Duration::from_secs(secs)).await {
            Ok(Some(r)) => r,
            _ => row,
        }
    } else {
        row
    };
    (StatusCode::OK, Json(view_of(&row, true)))
}

/// GET /api/v1/ops/{id}?wait=<s> — an operation's status, progress and, once
/// finished, its result or error. `wait` (seconds, at most 25) holds the
/// request until the op finishes or the time is up, so a client can wait
/// without hammering. An id that is not the caller's is answered exactly as an
/// id that never existed (404), so ids cannot be probed.
async fn ops_get(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
    Path(id): Path<String>,
    Query(q): Query<GetQuery>,
) -> StatusJson {
    read_op(&state.db, ctx.as_ref().map(|axum::Extension(r)| r), &id, q.wait).await
}

/// The cancel, over the pool alone.
pub(crate) async fn cancel_op(db: &PgPool, requester: Option<&RequesterCtx>, id: &str) -> StatusJson {
    let Some(op_id) = parse_id(id) else { return not_found() };
    let row = match ops::get_visible(db, requester, op_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found(),
        Err(e) => return start_error(StartError::Db(e)),
    };
    let note = type_for_row(&row).map(|t| t.spec.cancel_note).unwrap_or("the worker is not stopped");
    // The worker may run to the type's limit; an unregistered type is held for the longest known.
    let hold = type_for_row(&row).map(|t| (t.spec.timeout)()).unwrap_or_else(recluster_budget);
    match ops::cancel(db, row, note, hold).await {
        Ok(CancelOutcome::Cancelled(r)) => (StatusCode::OK, Json(view_of(&r, true))),
        Ok(CancelOutcome::AlreadyFinished(r)) if r.status == ops::CANCELLED => (StatusCode::OK, Json(view_of(&r, true))),
        Ok(CancelOutcome::AlreadyFinished(r)) => (
            StatusCode::CONFLICT,
            Json(json!({"error": format!("the operation already {}; nothing to cancel", r.status), "operation": view_of(&r, true)})),
        ),
        Ok(CancelOutcome::OtherInstance(r)) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "this operation is running on another gateway instance; a cancel can only stop a run on the \
                          instance that holds it",
                "operation": view_of(&r, false),
            })),
        ),
        Err(e) => start_error(StartError::Db(e)),
    }
}

/// DELETE /api/v1/ops/{id} — cancel a queued or running operation.
///
/// Stops the gateway-side wait and records `cancelled`. It cannot stop a
/// worker run already underway, and the response says so in `cancel`
/// (`gateway_aborted`, `worker_stopped: false`, and what the worker will do).
/// An already-cancelled op answers 200 unchanged; one that already finished
/// answers 409.
async fn ops_cancel(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
    Path(id): Path<String>,
) -> StatusJson {
    cancel_op(&state.db, ctx.as_ref().map(|axum::Extension(r)| r), &id).await
}

#[derive(Deserialize, Default)]
struct ListQuery {
    /// Only the caller's own (an admin otherwise sees everyone's).
    mine: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
}

/// The listing, over the pool alone.
pub(crate) async fn list_ops(
    db: &PgPool,
    requester: Option<&RequesterCtx>,
    mine: bool,
    status: Option<&str>,
    limit: i64,
) -> StatusJson {
    if let Some(s) = status {
        if !["queued", "running", "succeeded", "failed", "cancelled", "expired"].contains(&s) {
            return refuse(
                StatusCode::BAD_REQUEST,
                "status must be one of queued, running, succeeded, failed, cancelled, expired",
            );
        }
    }
    match ops::list(db, requester, mine, status, limit).await {
        Ok(rows) => {
            let items: Vec<Value> = rows.iter().map(|r| view_of(r, false)).collect();
            (StatusCode::OK, Json(json!({"operations": items, "count": items.len()})))
        }
        Err(e) => start_error(StartError::Db(e)),
    }
}

/// GET /api/v1/ops?mine=1&status=&limit= — the caller's operations, newest
/// first, without their results (fetch one for that). An admin sees every
/// account's unless `mine` is set.
async fn ops_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
    Query(q): Query<ListQuery>,
) -> StatusJson {
    let mine = matches!(q.mine.as_deref(), Some("1" | "true" | "yes"));
    list_ops(
        &state.db,
        ctx.as_ref().map(|axum::Extension(r)| r),
        mine,
        q.status.as_deref().filter(|s| !s.is_empty()),
        q.limit.unwrap_or(50),
    )
    .await
}

/// GET /api/v1/ops/types — the registered operation types: the route each is
/// the body of (which also decides who may start it), how long a run may
/// take, how long its route waits before answering with a handle
/// (`default_wait_secs`, overridable per type with the setting named in
/// `wait_setting`), and what a cancel can and cannot stop.
async fn ops_types() -> StatusJson {
    let types: Vec<Value> = TYPES
        .iter()
        .map(|t| {
            json!({
                "type": t.spec.name,
                "summary": t.spec.summary,
                "route": t.spec.route,
                "timeout_secs": (t.spec.timeout)().as_secs(),
                "default_wait_secs": t.spec.default_wait(),
                "wait_setting": t.spec.wait_key(),
                "poll_interval_ms": t.spec.poll_interval_ms,
                "exclusive": t.spec.exclusive,
                "admin_only": t.spec.admin_only,
                "human_only_apply": t.spec.human_only_apply,
                "retry_safe": t.spec.retry_safe,
                "cancellable": true,
                "worker_stoppable": false,
                "cancel": t.spec.cancel_note,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({"types": types, "max_wait_secs": MAX_WAIT_SECS})))
}

