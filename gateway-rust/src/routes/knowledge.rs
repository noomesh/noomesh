// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Knowledge routes — RAG, documents, graph.
//!
//! Every handler here that touches provider-derived data (KB query and
//! ingest, entity search/detail/neighbors/resolve, overview, clusters,
//! export, prune staging + restore, docs list) goes through the
//! memory-provider facade (`state.memory()` — ); the
//! NatsTrellion impl keeps the same NATS subjects and SQL those handlers
//! issued directly before, so behavior is unchanged and phase 3 can swap
//! the transport without touching this file.
//!
//! Deliberately NOT behind the facade: `graph_stats` and `rag_status` —
//! OBSERVABILITY-bucket count endpoints (phase-0 classification) that
//! must keep answering to REPORT a provider outage.

use crate::audit::{AuditEvent, AuditKind, Outcome as AuditOutcome, Severity};
use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
    extract::{State, Path, Query},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::measured::{put_into, Measured};
use crate::memory::scope::{self, Audience};
use crate::state::AppState;
use super::{AppResult, AppError};
use crate::authz::OperatorOrInternal;
use super::delegation;
use super::ops::WaitQuery;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // RAG query/ingest — kb group of the memory provider (still NATS →
        // Python PageIndex runtime inside trellion, via the facade)
        // Standalone queries may include owner-only Google evidence.
        .route("/api/v1/rag/query", post(rag_query).layer(axum::middleware::from_fn(
            super::connections::private_response_headers,
        )))
        .route("/api/v1/rag/retag", post(rag_retag))
        .route("/api/v1/rag/ingest", post(rag_ingest))
        // Document upload — the multipart endpoint died with the archived
        // Python gateway, silently breaking the dashboard file-drop and the
        // heartbeat KB-ingest action (which posts JSON here). Restored as a
        // native handler accepting BOTH content types, delegating to the
        // same worker.rag.ingest the CLI uses. 32MB cap for text docs.
        .route(
            "/api/v1/docs/ingest",
            post(docs_ingest).layer(axum::extract::DefaultBodyLimit::max(32 * 1024 * 1024)),
        )
        // Page-level dedupe — also lost in the archive; PageIndexStore
        // .deduplicate_pages still exists, re-exposed via a worker handler.
        .route("/api/v1/rag/deduplicate", post(rag_deduplicate))
        // RAG status + docs list — native SQL (ported 2026-03-31)
        .route("/api/v1/rag/status", get(rag_status))
        .route("/api/v1/docs", get(docs_list))
        // Document hold: operator-only (the global write rule for the POSTs,
        // the `OperatorOrInternal` extractor for the GET). Deliberately NOT in any add-on
        // control scope.
        .route("/api/v1/docs/hold", post(docs_hold))
        .route("/api/v1/docs/unhold", post(docs_unhold))
        .route("/api/v1/docs/purge", post(docs_purge))
        .route("/api/v1/docs/held", get(docs_held))
        .route("/api/v1/docs/{doc_id}", get(doc_detail))
        // Manual trigger for the watched_folders + watched_drives ingest loops.
        // ?source=folders|drives|all (default all). Synchronous — returns the
        // ScanResult so the caller can immediately see what was ingested.
        .route("/api/v1/ingest/scan", post(trigger_ingest_scan))
        // Graph — all native Rust SQL (ported 2026-03-31)
        .route("/api/v1/graph/stats", get(graph_stats))
        .route("/api/v1/graph/entities", get(graph_entities))
        .route("/api/v1/graph/entities/resolve", post(graph_entities_resolve))
        .route("/api/v1/graph/entities/{entity_id}", get(graph_entity_detail))
        .route("/api/v1/graph/entities/{entity_id}/neighbors", get(graph_entity_neighbors))
        // Whole-graph overview: top N entities by degree + their interconnecting edges
        .route("/api/v1/graph/overview", get(graph_overview))
        // Cluster overview — one super-node per cluster, edges weighted by member-set crossings
        .route("/api/v1/graph/clusters/overview", get(graph_clusters_overview))
        // Operator audit of how clusters mix audiences.
        .route("/api/v1/graph/clusters/audit", get(graph_clusters_audit))
        // The only writer of entity_clusters. Delegated, because community
        // detection is trellion's.
        .route("/api/v1/graph/recluster", post(graph_recluster))
        // The Intelligent tier's graph surface. Every one of these had an MCP
        // tool naming it and no route behind it, so the licensed capability
        // was reachable only from inside the retrieval path.
        .route("/api/v1/graph/navigate", post(graph_navigate))
        .route("/api/v1/graph/traverse", post(graph_traverse))
        .route("/api/v1/graph/explain-path", post(graph_explain_path))
        .route("/api/v1/graph/semantic-search", post(graph_semantic_search))
        .route("/api/v1/graph/search-clusters", post(graph_search_clusters))
        .route("/api/v1/graph/classify-intent", post(graph_classify_intent))
        .route("/api/v1/graph/extract-relations", post(graph_extract_relations))
        .route("/api/v1/graph/recall-traversals", post(graph_recall_traversals))
        // Prune staging area — list soft-deleted entities + selective restore.
        // Writer is the Python graph_prune heartbeat action; restore is pure
        // SQL so it lives here (RUST_PYTHON_SPLIT decision rule).
        .route("/api/v1/graph/prune/staged", get(graph_prune_staged))
        .route("/api/v1/graph/prune/restore", post(graph_prune_restore))
        // The junk-entity cleanup (stages into the same area, so the restore
        // above brings an entity back). ADMIN ONLY; see `graph_entity_cleanup`.
        .route("/api/v1/graph/entity-cleanup", post(graph_entity_cleanup))
        // Every route in this module reads TRELLION-OWNED tables (`pages`,
        // `entities`, `edges` — none created by the mesh baseline) directly
        // over SQL, so the NATS-boundary trellion gate never saw them.
        // Without the add-on they answered a raw `relation does not exist`
        // 500 where the contract promises an explained 503.
        .route_layer(axum::middleware::from_fn(super::require_trellion))
}

// ═══════════════════════════════════════════════════════════════
// Ingest trigger — manually fire one cycle of the watched_* loops
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct ScanQuery {
    /// "folders", "drives", or "all" (default).
    #[serde(default)]
    source: Option<String>,
}

/// POST /api/v1/ingest/scan?source=folders|drives|all
///
/// Fires one immediate scan of the requested ingest source(s) and
/// returns each `ScanResult` synchronously. Useful for testing the
/// loop end-to-end without waiting for the next periodic tick.
///
/// Safe to call while a periodic scan is in flight — both rely on
/// `docs.source_uri` dedup + PageIndex content-hash backstop.
async fn trigger_ingest_scan(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ScanQuery>,
) -> AppResult {
    let which = q.source.as_deref().unwrap_or("all").to_lowercase();
    let mut results = Vec::new();

    if which == "folders" || which == "all" {
        results.push(crate::ingest_loop::scan_folders_once(&state).await);
    }
    if which == "drives" || which == "all" {
        results.push(crate::ingest_loop::scan_drives_once(&state).await);
    }
    if results.is_empty() {
        return Err(AppError::BadRequest(format!(
            "unknown source '{which}' — use folders, drives, or all"
        )));
    }

    Ok(Json(json!({ "results": results })))
}

// ═══════════════════════════════════════════════════════════════
// RAG query / ingest / dedupe — memory-provider facade (kb group)
// ═══════════════════════════════════════════════════════════════
//
// These three reproduce `delegate_post` exactly — attach requester, call,
// map status via the shared delegation helpers — with the facade issuing
// the NATS request so the call is counted and the provider swappable.

/// POST /api/v1/rag/query — `noo_rag_query` surface (`kb/query`).
async fn rag_query(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(mut body): Json<Value>,
) -> delegation::StatusJson {
    delegation::attach_requester(&mut body, &ctx);
    match state.memory().kb_query(&body).await {
        Ok(response) => delegation::worker_ok(response),
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

/// POST /api/v1/rag/retag — change which audience documents belong to.
///
/// Operator-gated by the global tier check like every other mutating route;
/// the WORKER then clamps the target roles to what this requester could
/// write to itself, so an operator cannot publish someone's private
/// documents into a team they do not belong to. Dry-run unless the body
/// says `apply`.
async fn rag_retag(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(mut body): Json<Value>,
) -> delegation::StatusJson {
    delegation::attach_requester(&mut body, &ctx);
    let applying = body.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    match state.memory().kb_retag(&body).await {
        Ok(response) => {
            if applying {
                audit_retag(&state, &ctx, &body, &response).await;
            }
            delegation::worker_ok(response)
        }
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

/// The security-audit row for an APPLIED retag: an audience change is an
/// access-control change, and `noo_security_audit` is where those are read
/// (`/api/security/audit`). One row per call; per-document `{from, to}` is
/// on each document (`metadata.audience_history`), so the row names the
/// selector, the target roles and the ids rather than repeating every pair.
/// A refused apply (not yours to tag into, empty audience) is recorded too,
/// with the reason: asking for an audience you do not hold is worth seeing.
async fn audit_retag(
    state: &AppState,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: &Value,
    response: &Value,
) {
    let actor = ctx
        .as_ref()
        .map(|c| crate::auth::account_of(&c.sub).to_string())
        .unwrap_or_else(|| "cluster".to_string());
    let (severity, outcome, details) = retag_audit_row(body, response);
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::KbRetag, &actor, "kb:docs")
            .outcome(outcome)
            .severity(severity)
            .details(details),
    )
    .await;
}

/// `(severity, outcome, details)` of the audit row for an applied retag.
/// Pure so a test can pin what is recorded.
fn retag_audit_row(body: &Value, response: &Value) -> (Severity, AuditOutcome, Value) {
    let payload = response.get("data").unwrap_or(response);
    let error = payload.get("error").and_then(|e| e.as_str());
    let ids: Vec<Value> = payload
        .get("documents")
        .and_then(|d| d.as_array())
        .map(|d| d.iter().filter_map(|x| x.get("doc_id").cloned()).take(50).collect())
        .unwrap_or_default();
    (
        if error.is_some() { Severity::Warning } else { Severity::Info },
        if error.is_some() { AuditOutcome::custom("refused") } else { AuditOutcome::Ok },
        json!({
            "roles": body.get("roles"),
            "match": body.get("match"),
            "doc_ids_requested": body.get("doc_ids"),
            "relabel": body.get("only_untagged").and_then(|v| v.as_bool()).map(|v| !v),
            "matched": payload.get("matched"),
            "applied": payload.get("applied"),
            "doc_ids": ids,
            "error": error,
            "warning": payload.get("warning"),
        }),
    )
}

/// While `docs.held_at` is absent (trellion not yet migrated to 105) every
/// hold call is refused with the one "roll trellion first" sentence, before
/// anything is sent to a worker.
async fn hold_column_gate(state: &AppState) -> Option<delegation::StatusJson> {
    if crate::held_column::present(&state.db).await {
        None
    } else {
        Some(delegation::worker_ok(json!({ "error": crate::held_column::ROLL_TRELLION_FIRST })))
    }
}

/// POST /api/v1/docs/hold — keep documents, out of embedding and search.
/// Body `{title_prefix | doc_ids, reason, apply}`. A DRY RUN unless `apply`
/// is `true`: the answer says what WOULD be held. Nothing is deleted.
async fn docs_hold(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(mut body): Json<Value>,
) -> delegation::StatusJson {
    if let Some(refusal) = hold_column_gate(&state).await {
        return refusal;
    }
    delegation::attach_requester(&mut body, &ctx);
    let applying = body.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    match state.memory().kb_hold(&body).await {
        Ok(response) => {
            if applying {
                audit_hold(&state, &ctx, AuditKind::KbHold, &body, &response).await;
            }
            delegation::worker_ok(response)
        }
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

/// POST /api/v1/docs/unhold — release held documents (same body as hold,
/// no reason needed). A dry run unless `apply` is `true`.
async fn docs_unhold(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(mut body): Json<Value>,
) -> delegation::StatusJson {
    if let Some(refusal) = hold_column_gate(&state).await {
        return refusal;
    }
    delegation::attach_requester(&mut body, &ctx);
    let applying = body.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    match state.memory().kb_unhold(&body).await {
        Ok(response) => {
            if applying {
                audit_hold(&state, &ctx, AuditKind::KbUnhold, &body, &response).await;
            }
            delegation::worker_ok(response)
        }
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

/// POST /api/v1/docs/purge — DELETE the documents held under exactly
/// `reason`. IRREVERSIBLE. Body `{reason, apply}`; a dry run unless `apply`
/// is `true`. Documents that are not held, or held under another reason, are
/// never touched.
async fn docs_purge(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(mut body): Json<Value>,
) -> delegation::StatusJson {
    if let Some(refusal) = hold_column_gate(&state).await {
        return refusal;
    }
    delegation::attach_requester(&mut body, &ctx);
    let applying = body.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    match state.memory().kb_purge(&body).await {
        Ok(response) => {
            if applying {
                audit_hold(&state, &ctx, AuditKind::KbPurge, &body, &response).await;
            }
            delegation::worker_ok(response)
        }
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

/// GET /api/v1/docs/held?reason=&limit=&offset= — held documents (id, title,
/// reason, held_at), paged, with the `total`. Operator only.
async fn docs_held(
    State(state): State<Arc<AppState>>,
    // The listing names every held document: Operator or above, or a caller
    // with no account (a controller service).
    _op: OperatorOrInternal,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(q): Query<HeldQuery>,
) -> Result<delegation::StatusJson, AppError> {
    if let Some(refusal) = hold_column_gate(&state).await {
        return Ok(refusal);
    }
    let mut body = json!({ "reason": q.reason, "limit": q.limit, "offset": q.offset });
    delegation::attach_requester(&mut body, &ctx);
    Ok(match state.memory().kb_held(&body).await {
        Ok(response) => delegation::worker_ok(response),
        Err(e) => delegation::worker_unavailable(e, None),
    })
}

#[derive(Debug, Deserialize)]
struct HeldQuery {
    reason: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

/// The security-audit row for an APPLIED hold, unhold or purge. Hiding or
/// deleting documents is an operator act worth reading back later.
async fn audit_hold(
    state: &AppState,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
    event: AuditKind,
    body: &Value,
    response: &Value,
) {
    let actor = ctx
        .as_ref()
        .map(|c| crate::auth::account_of(&c.sub).to_string())
        .unwrap_or_else(|| "cluster".to_string());
    let (severity, outcome, details) = hold_audit_row(&event, body, response);
    crate::audit::record(
        &state.db,
        AuditEvent::new(event, &actor, "kb:docs")
            .outcome(outcome)
            .severity(severity)
            .details(details),
    )
    .await;
}

/// `(severity, outcome, details)` of the audit row. Pure so a test can pin it.
fn hold_audit_row(event: &AuditKind, body: &Value, response: &Value) -> (Severity, AuditOutcome, Value) {
    let payload = response.get("data").unwrap_or(response);
    let error = payload.get("error").and_then(|e| e.as_str());
    (
        if error.is_some() || *event == AuditKind::KbPurge { Severity::Warning } else { Severity::Info },
        if error.is_some() { AuditOutcome::custom("refused") } else { AuditOutcome::Ok },
        json!({
            "reason": body.get("reason"),
            "title_prefix": body.get("title_prefix"),
            "doc_ids_requested": body.get("doc_ids"),
            "count": payload.get("count"),
            "applied": payload.get("applied"),
            "deleted": payload.get("deleted"),
            "doc_ids": payload.get("doc_ids"),
            "error": error,
        }),
    )
}

/// POST /api/v1/rag/ingest — `kb/ingest`.
///
/// An ASYNCHRONOUS-OPERATION route (`ops.rs`): it starts the `rag.ingest` op
/// and waits up to that type's `default_wait` (or `?wait=`). A document that
/// ingests in time is answered 200 with the worker's reply, as ever; a slow
/// one is answered 202 with an op handle to poll at `GET /api/v1/ops/{id}`.
/// The work is [`rag_ingest_core`], the one body both paths run.
async fn rag_ingest(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(w): Query<WaitQuery>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    super::ops::route_start(&state, &ctx, "rag.ingest", body, w.wait).await
}

/// What `POST /api/v1/rag/ingest` does: attach the requester, ask the memory
/// provider, map the answer to the worker status contract. Shared by the
/// route's op and by `POST /api/v1/ops {type: "rag.ingest"}`.
pub(super) async fn rag_ingest_core(
    state: &Arc<AppState>,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
    mut body: Value,
) -> delegation::StatusJson {
    delegation::attach_requester(&mut body, ctx);
    match state.memory().kb_ingest(&body).await {
        Ok(response) => delegation::worker_ok(response),
        Err(e) => delegation::worker_failed(&e, None),
    }
}

/// POST /api/v1/rag/deduplicate — kb maintenance.
async fn rag_deduplicate(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(mut body): Json<Value>,
) -> delegation::StatusJson {
    delegation::attach_requester(&mut body, &ctx);
    match state.memory().kb_deduplicate(&body).await {
        Ok(response) => delegation::worker_ok(response),
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

// ═══════════════════════════════════════════════════════════════
// Graph handlers — memory-provider facade (SQL-internal today)
// ═══════════════════════════════════════════════════════════════

/// Is this sqlx error "the table does not exist" (Postgres 42P01)?
///
/// That distinction is the whole point: on a fresh install the KB tables are
/// genuinely absent and a count of 0 is the truth. Every *other* failure — the
/// database being down, a permission error, a pool timeout — is not "the
/// knowledge base is empty", and zero-filling it tells an operator the corpus
/// vanished. Only 42P01 may be answered with a number.
fn missing_table(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01"))
}

/// Entities the caller may see. Same missing-table rule as [`count_or_err`]:
/// a fresh install has none (0), any other failure is not a count.
async fn entity_count_for(state: &AppState, aud: &Audience) -> Result<i64, AppError> {
    match state.memory().graph_entity_count(aud).await {
        Ok(n) => Ok(n),
        Err(e) if missing_table(&e) => Ok(0),
        Err(e) => Err(AppError::Internal(format!("cannot count entities: {e}"))),
    }
}

/// `SELECT COUNT(*)`-shaped scalar where a missing table means 0 and any other
/// error is propagated to the caller as a 500 instead of being flattened.
async fn count_or_err(
    db: &sqlx::PgPool,
    sql: &str,
    what: &str,
) -> Result<i64, AppError> {
    // Every caller passes a literal or an `autonomy_evaluators::sql_unembedded_*`
    // string, built from constants: nothing caller-supplied reaches the string.
    match sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql)).fetch_one(db).await {
        Ok(n) => Ok(n),
        Err(e) if missing_table(&e) => Ok(0),
        Err(e) => Err(AppError::Internal(format!("cannot count {what}: {e}"))),
    }
}

/// GET /api/v1/graph/stats — entity type counts + total edges.
async fn graph_stats(State(state): State<Arc<AppState>>) -> AppResult {
    // Entity types grouped with counts. Previously `.unwrap_or_default()` /
    // `.unwrap_or(0)`: a database outage rendered as an empty graph.
    let type_rows = match sqlx::query_as::<_, (String, i64)>(
        "SELECT type, COUNT(*) FROM entities GROUP BY type ORDER BY COUNT(*) DESC"
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) if missing_table(&e) => Vec::new(),
        Err(e) => return Err(AppError::Internal(format!("cannot read entities: {e}"))),
    };

    let entity_types: serde_json::Map<String, Value> = type_rows
        .into_iter()
        .map(|(t, c)| (t, json!(c)))
        .collect();

    // Total edges
    let total_edges = count_or_err(&state.db, "SELECT COUNT(*) FROM edges", "edges").await?;

    Ok(Json(json!({
        "entity_types": entity_types,
        "total_edges": total_edges,
    })))
}

#[derive(Deserialize)]
struct GraphEntitySearch {
    q: Option<String>,
    #[allow(dead_code)]
    semantic: Option<bool>,  // reserved for future semantic entity search
}

/// GET /api/v1/graph/entities?q=... — search entities by name (ILIKE).
async fn graph_entities(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(params): Query<GraphEntitySearch>,
) -> AppResult {
    let q = params.q.unwrap_or_default();
    if q.is_empty() {
        return Ok(Json(json!([])));
    }

    let aud = scope::resolve(&state, &ctx).await?;
    let rows = state.memory().graph_search_entities(&aud, &q).await?;

    let entities: Vec<Value> = rows.iter().map(|(id, name, etype, aliases, created)| {
        json!({
            "entity_id": id,
            "canonical_name": name,
            "type": etype,
            "aliases": aliases,
            "created_at": created,
        })
    }).collect();

    Ok(Json(json!(entities)))
}

/// GET /api/v1/graph/entities/{entity_id} — entity detail with connections + pages.
///
/// ONE facade call: detail assembly (entity + 1-hop connections + pages)
/// is a single tool invocation, so it lives provider-side.
async fn graph_entity_detail(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(entity_id): Path<String>,
) -> AppResult {
    let aud = scope::resolve(&state, &ctx).await?;
    match state.memory().graph_entity_detail(&aud, &entity_id).await? {
        Some(detail) => Ok(Json(detail)),
        None => Err(AppError::NotFound(format!("Entity {entity_id} not found"))),
    }
}

#[derive(Deserialize)]
struct NeighborParams {
    hops: Option<i32>,
    rel_types: Option<String>,
}

/// GET /api/v1/graph/entities/{entity_id}/neighbors — multi-hop graph traversal.
///
/// Uses a recursive CTE matching the Python PageIndexStore.get_entity_neighbors()
/// implementation.  Supports optional rel_types filter (comma-separated) and
/// configurable hop depth (default 1, max 5).
async fn graph_entity_neighbors(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(entity_id): Path<String>,
    Query(params): Query<NeighborParams>,
) -> AppResult {
    let hops = params.hops.unwrap_or(1).clamp(1, 5);
    let rel_types: Option<Vec<String>> = params.rel_types.as_ref().map(|s| {
        s.split(',').map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).collect()
    }).filter(|v: &Vec<String>| !v.is_empty());

    let rows = {
        // Parse at the edge: the previous query bound this String straight into
        // `$1::uuid` and let Postgres coerce, so a malformed id surfaced as a
        // 500 from the database rather than a 400 from the router.
        let eid = uuid::Uuid::parse_str(&entity_id).map_err(|_| {
            AppError::BadRequest(format!("entity_id is not a valid UUID: {entity_id}"))
        })?;
        let aud = scope::resolve(&state, &ctx).await?;
        state.memory().graph_neighbors(&aud, eid, hops, rel_types.as_deref()).await?
    };

    let edges: Vec<Value> = rows.iter().map(|(eid, src, rel, dst, evidence, depth)| {
        json!({
            "edge_id": eid,
            "src_entity_id": src,
            "rel_type": rel,
            "dst_entity_id": dst,
            "evidence": evidence,
            "depth": depth,
        })
    }).collect();

    Ok(Json(json!(edges)))
}

/// POST /api/v1/graph/entities/resolve — batch-resolve entity IDs to names.
async fn graph_entities_resolve(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> AppResult {
    let ids: Vec<String> = body.get("ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if ids.is_empty() {
        return Ok(Json(json!({})));
    }

    // Cap at 200 IDs (matching Python)
    let ids: Vec<String> = ids.into_iter().take(200).collect();

    let aud = scope::resolve(&state, &ctx).await?;
    let rows = state.memory().graph_entities_resolve(&aud, &ids).await?;

    let mut result = serde_json::Map::new();
    for (eid, name, etype) in rows {
        result.insert(eid, json!({"name": name, "type": etype}));
    }

    Ok(Json(Value::Object(result)))
}

// ═══════════════════════════════════════════════════════════════
// RAG status + docs list — native SQL (ported from NATS delegation)
// ═══════════════════════════════════════════════════════════════

/// GET /api/v1/rag/status — return table counts for docs, pages, entities,
/// edges, page_embeddings, page_chunks, chunk_embeddings.
///
/// Matches the Python PageIndexRAG.status() response format exactly.
/// If any table doesn't exist, that count is returned as 0.
pub(crate) async fn rag_status(State(state): State<Arc<AppState>>) -> AppResult {
    // Query each table count individually — graceful if table doesn't exist
    let tables = [
        ("docs", "doc_count"),
        ("pages", "page_count"),
        ("entities", "entity_count"),
        ("edges", "edge_count"),
        ("page_embeddings", "embedded_pages"),
        ("page_chunks", "chunk_count"),
        ("chunk_embeddings", "embedded_chunks"),
    ];

    let mut counts = serde_json::Map::new();
    let mut all_ok = true;

    for (table, key) in &tables {
        let query = format!("SELECT COUNT(*) FROM {table}");
        match sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(&*query))
            .fetch_one(&state.db)
            .await
        {
            Ok(count) => { counts.insert(key.to_string(), json!(count)); }
            // A table that does not exist yet is a real, reportable 0.
            Err(e) if missing_table(&e) => {
                counts.insert(key.to_string(), json!(0));
                if *table == "docs" {
                    // If even the docs table doesn't exist, RAG isn't started
                    all_ok = false;
                }
            }
            // Anything else (DB down, permissions, pool timeout) is NOT "the
            // knowledge base is empty" — it was reported as 0 across every
            // count, which is the single most misleading RAG dashboard state.
            Err(e) => {
                return Err(AppError::Internal(format!("cannot count {table}: {e}")));
            }
        }
    }

    if !all_ok {
        return Ok(Json(json!({"started": false})));
    }

    // Compute derived counts (matching Python)

    // The backlog is what the embedder can still be offered: a held document
    // (`docs.held_at`) is kept out of embedding on purpose. Counted by the
    // one definition the autonomy evaluator and /metrics use, not
    // `total - embedded` (which would count every held page as pending).
    // Before trellion's migration 105 there is no `held_at`: the plain form
    // is used, and the status still answers.
    let held_col = crate::held_column::present(&state.db).await;
    let unembedded_pages = count_or_err(
        &state.db,
        &crate::autonomy_evaluators::sql_unembedded_pages(held_col),
        "unembedded pages",
    ).await?;
    let unembedded_chunks = count_or_err(
        &state.db,
        &crate::autonomy_evaluators::sql_unembedded_chunks(held_col),
        "unembedded chunks",
    ).await?;
    counts.insert("unembedded_pages".to_string(), json!(unembedded_pages));
    counts.insert("unembedded_chunks".to_string(), json!(unembedded_chunks));
    let held_documents = if held_col {
        count_or_err(
            &state.db,
            "SELECT COUNT(*) FROM docs WHERE held_at IS NOT NULL",
            "held documents",
        ).await?
    } else {
        0
    };
    counts.insert("held_documents".to_string(), json!(held_documents));

    // Duplicate page count
    let dup_count = count_or_err(
        &state.db,
        "SELECT COUNT(*) FROM ( \
            SELECT 1 FROM pages \
            GROUP BY doc_id, page_no \
            HAVING COUNT(*) > 1 \
         ) sub",
        "duplicate pages",
    ).await?;
    counts.insert("duplicate_pages".to_string(), json!(dup_count));

    // Edge classification progress. These two used to `.unwrap_or(0)`
    // independently, so one failing query swung `classification_pct` to a
    // confident 0% or 100% — a number an operator schedules work off.
    let classified = count_or_err(
        &state.db,
        "SELECT COUNT(*) FROM edges WHERE classified_at IS NOT NULL",
        "classified edges",
    ).await?;

    let unclassified = count_or_err(
        &state.db,
        "SELECT COUNT(*) FROM edges WHERE classified_at IS NULL",
        "unclassified edges",
    ).await?;

    let edge_types_rows = match sqlx::query_as::<_, (String, i64)>(
        "SELECT rel_type, COUNT(*) as cnt FROM edges \
         GROUP BY rel_type ORDER BY cnt DESC LIMIT 10"
    ).fetch_all(&state.db).await {
        Ok(rows) => rows,
        Err(e) if missing_table(&e) => Vec::new(),
        Err(e) => return Err(AppError::Internal(format!("cannot read edge types: {e}"))),
    };

    let edge_types: serde_json::Map<String, Value> = edge_types_rows.into_iter()
        .map(|(t, c)| (t, json!(c)))
        .collect();

    let total_edges = classified + unclassified;
    // With no edges at all there is no percentage to report. `0.0` read as
    // "classification has not started", which is a different claim.
    let classification_pct = if total_edges > 0 {
        json!((classified as f64 / total_edges as f64 * 100.0).round())
    } else {
        Value::Null
    };

    counts.insert("graph_enrichment".to_string(), json!({
        "total_edges": total_edges,
        "classified": classified,
        "unclassified": unclassified,
        "classification_pct": classification_pct,
        "edge_types": edge_types,
    }));

    counts.insert("started".to_string(), json!(true));

    Ok(Json(Value::Object(counts)))
}

#[derive(Deserialize)]
struct DocsListParams {
    /// Page size (default 200, capped at 2000).
    limit: Option<u32>,
    /// Rows to skip, newest-first (default 0).
    offset: Option<u32>,
    /// `1`/`true`: wrap the answer as `{docs, summary}` with the audience
    /// summary over ALL documents the caller may read (not just this page).
    summary: Option<String>,
    /// `1`/`true`: only documents with no audience tag (operator/admin).
    untagged: Option<String>,
    /// Only documents whose audience contains this tag; a trailing `*` is a
    /// prefix (`user:*` = every personal tier).
    audience: Option<String>,
    /// Only documents whose `source_uri` matches this glob (the one
    /// `noo rag retag --match` takes).
    #[serde(rename = "match")]
    source_match: Option<String>,
    /// Only documents whose title contains this text, case-insensitively.
    q: Option<String>,
}

impl DocsListParams {
    fn filter(&self) -> scope::DocFilter {
        let text = |v: &Option<String>| v.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
        scope::DocFilter {
            untagged: truthy(self.untagged.as_deref()),
            audience: text(&self.audience),
            source_glob: text(&self.source_match),
            title: text(&self.q),
        }
    }
}

fn truthy(v: Option<&str>) -> bool {
    v.is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

const DOCS_LIST_DEFAULT_LIMIT: u32 = 200;
const DOCS_LIST_MAX_LIMIT: u32 = 2000;

fn docs_page_bounds(limit: Option<u32>, offset: Option<u32>) -> (i64, i64) {
    (
        limit.unwrap_or(DOCS_LIST_DEFAULT_LIMIT).clamp(1, DOCS_LIST_MAX_LIMIT) as i64,
        offset.unwrap_or(0) as i64,
    )
}

/// `metadata.roles` as a list of tags; None when absent, not an array, or empty.
fn roles_of(roles: &Option<Value>) -> Option<Vec<String>> {
    let arr = roles.as_ref()?.as_array()?;
    let tags: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    if tags.is_empty() { None } else { Some(tags) }
}

/// Audience summary over every document: how many carry no tag at all
/// (invisible to everyone but an admin), and how many carry each tag. A
/// document with several tags counts under each, so the by_audience values
/// can sum to more than `total`. `user:<name>` tags are folded to `user:*`
/// so the summary does not enumerate accounts.
fn audience_summary(all_roles: &[Option<Value>]) -> Value {
    let mut untagged = 0u64;
    let mut by: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for r in all_roles {
        match roles_of(r) {
            None => untagged += 1,
            Some(tags) => {
                let mut seen = std::collections::BTreeSet::new();
                for t in tags {
                    let k = if t.starts_with("user:") { "user:*".to_string() } else { t };
                    if seen.insert(k.clone()) {
                        *by.entry(k).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    json!({ "total": all_roles.len(), "untagged": untagged, "by_audience": by })
}

fn docs_json(rows: &[crate::memory::provider::DocRow], privileged: bool) -> Vec<Value> {
    rows.iter().map(|(id, uri, title, hash, created, roles, ingest, history_len)| {
        let mut d = json!({
            "doc_id": id,
            "source_uri": uri,
            "title": title,
            "hash": hash,
            "created_at": created.map(|t| t.to_rfc3339()),
        });
        if privileged {
            d["roles"] = roles_of(roles).map(|r| json!(r)).unwrap_or(Value::Null);
            // Where the document came from (null: ingested before provenance
            // was recorded) and how many times its audience was changed.
            d["provenance"] = ingest.clone().filter(|v| v.is_object()).unwrap_or(Value::Null);
            d["audience_history_len"] = json!(history_len);
        }
        d
    }).collect()
}

/// GET /api/v1/docs — list documents from the docs table.
///
/// Returns an array of {doc_id, source_uri, title, hash, created_at}, newest
/// first. `?limit=` (default 200, max 2000) and `?offset=` page it.
///
/// A caller who is not unrestricted (admin / `kb:unrestricted`; see
/// `workers/kb.py::_resolve_kb_roles`, asked via `worker.rag.audience`) sees
/// only documents whose `metadata.roles` overlaps their role set: their own
/// `user:<account>`, `company`, `system` and granted `team:*`. Untagged
/// (legacy) documents are unreadable to them, exactly as in retrieval.
///
/// For an operator or admin tier each item also carries `roles` (the
/// audience tags, null when the document has none). `?summary=1` (any
/// caller) wraps the answer as `{docs, summary: {total, untagged,
/// by_audience}}` with the counts taken over every document THIS CALLER MAY
/// READ, not the page; for a restricted caller `untagged` is always 0.
///
/// the design, the operator's review view. Operator/admin items also carry
/// `provenance` (`{by, via, at}` of the first ingest, null when it predates
/// provenance) and `audience_history_len`. Four filters narrow the listing
/// AND the summary: `?untagged=1`, `?audience=<tag>` (`user:*` = any personal
/// tier), `?match=<source_uri glob>`, `?q=<title text>`. Each is ANDed with
/// the caller's audience, so they only ever remove rows; for a restricted
/// caller `?untagged=1` therefore matches nothing, and `?audience=admin`
/// cannot reveal what they could not already read.
async fn docs_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(p): Query<DocsListParams>,
) -> AppResult {
    let privileged = is_privileged(&ctx);
    let want_summary = truthy(p.summary.as_deref());
    let filter = p.filter();
    let (limit, offset) = docs_page_bounds(p.limit, p.offset);
    // the listing obeys the audience retrieval obeys. Resolved
    // BEFORE the query and applied in SQL, so paging and the summary count
    // only what this caller may read.
    let aud = scope::resolve(&state, &ctx).await?;

    match state.memory().kb_docs_list(&aud, &filter, limit, offset).await {
        Ok(rows) => {
            let docs = docs_json(&rows, privileged);
            if !want_summary {
                return Ok(Json(json!(docs)));
            }
            match state.memory().kb_docs_roles_all(&aud, &filter).await {
                Ok(all) => Ok(Json(json!({ "docs": docs, "summary": audience_summary(&all) }))),
                Err(e) => Err(AppError::Internal(format!("audience summary failed: {e}"))),
            }
        }
        Err(e) => {
            // Table likely doesn't exist — return empty list
            tracing::debug!(error = %e, "docs_list query failed (table may not exist)");
            Ok(Json(json!([])))
        }
    }
}

/// Operator/admin tier, or a machine caller (cluster HMAC carries no
/// requester and is unrestricted everywhere on these routes).
fn is_privileged(ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>) -> bool {
    ctx.as_ref().is_none_or(|c| c.role >= crate::auth::Role::Operator)
}

/// How many characters of text the detail view previews.
const DOC_PREVIEW_CHARS: usize = 1000;

/// The detail JSON from a row. `privileged` adds the whole `metadata`
/// block (roles, ingest provenance, audience history); a restricted caller
/// gets the document and its preview, never the trail.
fn doc_detail_json(row: &scope::DocDetailRow, privileged: bool) -> Value {
    let (id, uri, title, hash, created, metadata, pages, preview) = row;
    let preview: Option<String> = preview.as_ref().map(|t| t.chars().take(DOC_PREVIEW_CHARS).collect());
    let mut d = json!({
        "doc_id": id,
        "source_uri": uri,
        "title": title,
        "hash": hash,
        "created_at": created.map(|t| t.to_rfc3339()),
        "page_count": pages,
        "text_preview": preview,
    });
    if privileged {
        let meta = metadata.clone().unwrap_or_else(|| json!({}));
        d["roles"] = roles_of(&meta.get("roles").cloned()).map(|r| json!(r)).unwrap_or(Value::Null);
        d["provenance"] = meta.get("ingest").filter(|v| v.is_object()).cloned().unwrap_or(Value::Null);
        d["audience_history"] = meta.get("audience_history").filter(|v| v.is_array()).cloned().unwrap_or_else(|| json!([]));
        d["metadata"] = meta;
    }
    d
}

/// GET /api/v1/docs/{doc_id} — one document, for judging what it is.
///
/// Operator/admin: row, page count, the first ~1000 characters of text and
/// the whole `metadata` (`roles`, `provenance`, `audience_history`). Anyone
/// else: 404 unless the document is readable to them (the same audience as
/// the listing), and then without metadata, provenance or history. An
/// unreadable document and a missing one answer identically.
async fn doc_detail(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(doc_id): Path<String>,
) -> AppResult {
    let id = uuid::Uuid::parse_str(doc_id.trim())
        .map_err(|_| AppError::BadRequest(format!("'{doc_id}' is not a document id")))?
        .to_string();
    let aud = scope::resolve(&state, &ctx).await?;
    match state.memory().kb_doc_detail(&aud, &id).await {
        Ok(Some(row)) => Ok(Json(doc_detail_json(&row, is_privileged(&ctx)))),
        Ok(None) => Err(AppError::NotFound(format!("no document {id}"))),
        Err(e) if missing_table(&e) => Err(AppError::NotFound(format!("no document {id}"))),
        Err(e) => Err(AppError::Internal(format!("cannot read document: {e}"))),
    }
}

#[derive(Deserialize)]
struct OverviewParams {
    /// Max number of nodes to return (default 200, capped at 500).
    /// Selected by degree centrality — most-connected entities first.
    limit: Option<u32>,
    /// Optional entity type filter (e.g. "concept", "person").
    entity_type: Option<String>,
    /// Min number of connections an entity must have to be included (default 2).
    min_degree: Option<u32>,
}

/// GET /api/v1/graph/overview — top-N entities by degree centrality + their
/// interconnecting edges. The "skeleton" view of the whole graph.
///
/// At ~8K entities and ~54K edges, you can't render everything in 3D, so
/// this returns the most-connected nodes and their internal links — typically
/// 200 nodes + ~1000 edges, which renders smoothly.
async fn graph_overview(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(p): Query<OverviewParams>,
) -> AppResult {
    let aud = scope::resolve(&state, &ctx).await?;
    graph_overview_for(
        state,
        &aud,
        p.min_degree.unwrap_or(2) as i32,
        p.entity_type.as_deref(),
        p.limit.unwrap_or(200).min(500) as i32,
    )
    .await
    .map(Json)
}

/// The body of [`graph_overview`], callable without an extractor.
///
/// Split out for the same reason [`graph_clusters_overview_for`] was: so
/// `routes/kiosk.rs` projects this route's own answer instead of issuing a
/// second query against the same tables. One assembly, one set of reasons
/// for an empty result, no drift.
pub(super) async fn graph_overview_for(
    state: Arc<AppState>,
    aud: &Audience,
    min_degree: i32,
    entity_type: Option<&str>,
    limit: i32,
) -> Result<Value, AppError> {
    // 1. Top N entities by degree (count of edges where they're src or dst)
    let nodes = state
        .memory()
        .graph_top_entities(aud, min_degree, entity_type, limit)
        .await
        .map_err(|e| AppError::Internal(format!("nodes query: {e}")))?;
    if nodes.is_empty() {
        // Two empty arrays used to be the whole answer, and they conflate
        // three different situations — the same failure the cluster route
        // was fixed for. Say which one this is.
        //
        // Note what is NOT among them: `requires_intelligent_tier`. This
        // view is built from `entities` and `edges`, which every tier
        // writes. That is the reason the display is being pointed here.
        let entities = entity_count_for(&state, aud).await;
        let (reason, hint) = match &entities {
            // A count that FAILED is not a count of zero. Reporting
            // "nothing ingested" during a Postgres incident is the exact
            // failure this branch exists to prevent.
            Err(_) => (
                "counts_unavailable",
                Some("the entity list is empty and the database would not say whether \
                      that means an empty graph or a filter that matched nothing — \
                      treat this as unknown, not as empty"),
            ),
            Ok(0) => ("empty_graph", None),
            // Entities exist; `min_degree` (and any type filter) excluded
            // every one of them. On a freshly ingested graph the default
            // `min_degree=2` does this, and "nothing ingested" would send
            // the operator to ingest what they have already ingested.
            Ok(_) => (
                "below_min_degree",
                Some("the graph has entities, but none meets this request's \
                      `min_degree` (or `entity_type`) — lower it to see them"),
            ),
        };
        // `stats` counts the arrays returned (both empty); the unknown is
        // `entity_count`, null with a detail when the database would not answer.
        let mut body = json!({
            "nodes": [], "edges": [],
            "stats": {"node_count": 0, "edge_count": 0, "min_degree": min_degree},
            "reason": reason,
            "hint": hint,
        });
        put_into(&mut body, "entity_count", Measured::from_result_in(entities.as_ref().map(|n| *n), "cannot count entities"));
        return Ok(body);
    }

    let node_ids: Vec<String> = nodes.iter().map(|(id, _, _, _)| id.clone()).collect();

    // 2. Edges between those entities (intra-set only, not external connections)
    let edges = state
        .memory()
        .graph_overview_edges(aud, &node_ids)
        .await
        .map_err(|e| AppError::Internal(format!("edges query: {e}")))?;

    let (created_min, created_max) = edges.iter()
        .filter_map(|(_, _, _, _, ts)| *ts)
        .fold((None::<chrono::DateTime<chrono::Utc>>, None::<chrono::DateTime<chrono::Utc>>), |(mn, mx), t| {
            (Some(mn.map_or(t, |m| m.min(t))), Some(mx.map_or(t, |m| m.max(t))))
        });

    // The graph's TOTAL entity count, not this page of it. The display
    // renders "N of M", and computing M from `nodes.len()` would make the
    // two always agree and never be right.
    let entity_count = entity_count_for(&state, aud).await;

    Ok(json!({
        "nodes": nodes.iter().map(|(id, name, etype, deg)| json!({
            "id": id,
            "name": name,
            "type": etype,
            "degree": deg,
        })).collect::<Vec<_>>(),
        "edges": edges.iter().map(|(src, dst, rel, conf, ts)| json!({
            "src": src,
            "dst": dst,
            "rel_type": rel,
            "confidence": conf,
            "created_at": ts.map(|t| t.to_rfc3339()),
        })).collect::<Vec<_>>(),
        "stats": {
            "node_count": nodes.len(),
            "edge_count": edges.len(),
            "max_degree": nodes.first().map(|(_, _, _, d)| d).unwrap_or(&0),
            "min_degree": nodes.last().map(|(_, _, _, d)| d).unwrap_or(&0),
            "created_min": created_min.map(|t| t.to_rfc3339()),
            "created_max": created_max.map(|t| t.to_rfc3339()),
        },
        "entity_count": entity_count.as_ref().ok(),
    }))
}

#[derive(Deserialize)]
struct ClusterOverviewParams {
    /// Cluster hierarchy level (0 = top-level). Default 0.
    level: Option<i32>,
    /// Max number of clusters to return. Default 100.
    limit: Option<u32>,
    /// Min member count for a cluster to be included. Default 2.
    min_members: Option<u32>,
}

/// GET /api/v1/graph/clusters/overview — returns clusters as super-nodes,
/// with edges weighted by number of cross-cluster entity edges. Lets the
/// user see the "shape" of the knowledge graph at a higher level than
/// individual entities.
async fn graph_clusters_overview(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(p): Query<ClusterOverviewParams>,
) -> AppResult {
    let aud = scope::resolve(&state, &ctx).await?;
    graph_clusters_overview_for(
        state,
        &aud,
        p.level.unwrap_or(0),
        p.min_members.unwrap_or(2) as i32,
        p.limit.unwrap_or(100).min(500) as i32,
    )
    .await
    .map(Json)
}

/// The body of [`graph_clusters_overview`], callable without an extractor.
///
/// Split out so `routes/kiosk.rs` can project this route's own answer rather
/// than issue a second query against the same tables — one assembly, one set
/// of reasons for an empty result, no drift.
pub(super) async fn graph_clusters_overview_for(
    state: Arc<AppState>,
    aud: &Audience,
    level: i32,
    min_members: i32,
    limit: i32,
) -> Result<Value, AppError> {

    let clusters = state
        .memory()
        .graph_clusters(aud, level, min_members, limit)
        .await
        .map_err(|e| AppError::Internal(format!("clusters query: {e}")))?;

    if clusters.is_empty() {
        // An empty answer that reads as a small one is this repo's most
        // repeated failure, and this endpoint was its purest form: served,
        // green, and empty on every install created after the Rust port,
        // because `entity_clusters` had no writer at all until
        // `/api/v1/graph/recluster` existed.
        //
        // So say WHY it is empty. A graph with entities in it and no
        // clusters has never been clustered; a graph with no entities is
        // genuinely empty and clustering it would change nothing. Those are
        // different problems with different fixes and the caller cannot tell
        // them apart from two empty arrays.
        let entities = entity_count_for(&state, aud).await;
        // Unfiltered, because the query above is filtered by `level`,
        // `min_members` and `limit`. A graph WITH clusters, asked for
        // `?level=1` when only level 0 exists, was being told it had "never
        // been clustered" and pointed at a fifteen-minute job that would
        // change nothing.
        let all_clusters =
            count_or_err(&state.db, "SELECT COUNT(*) FROM entity_clusters", "entity_clusters").await;

        let (reason, hint) = match (&entities, &all_clusters) {
            // A count that FAILED is not a count of zero. `count_or_err`
            // already maps a missing table to Ok(0) and reserves Err for a
            // real failure — connection loss, permission denied — so
            // swallowing it to 0 would report "nothing ingested, go ingest
            // something" in the middle of a Postgres incident. That is the
            // exact failure the rest of this branch exists to prevent.
            (Err(_), _) | (_, Err(_)) => (
                "counts_unavailable",
                Some("the cluster list is empty and the database would not say \
                      whether that means an empty graph, an unclustered one, or \
                      a filter that matched nothing — treat this as unknown, \
                      not as empty"),
            ),
            (Ok(0), _) => ("empty_graph", None),
            // Clusters exist; this request's filters excluded all of them.
            (Ok(_), Ok(n)) if *n > 0 => (
                "no_clusters_at_this_level",
                Some("the graph is clustered, but no cluster matches this \
                      request's `level` and `min_members` — widen them before \
                      reclustering, which would change nothing"),
            ),
            // The common case, and the one two empty arrays hid completely:
            // the graph is fine, clustering is simply not part of this tier.
            (Ok(_), Ok(_)) if !crate::addons::trellion_intel_enabled() => (
                "requires_intelligent_tier",
                Some("the graph has entities; community detection is an \
                      Intelligent-tier capability (trellion_intel) and is not \
                      enabled here. /api/v1/graph/overview is the entity-level \
                      view, built on every tier and needing no clustering"),
            ),
            (Ok(_), Ok(_)) => (
                "no_clusters",
                Some("the graph has entities but has never been clustered — \
                      POST /api/v1/graph/recluster (or `noo graph recluster`) \
                      builds them; /api/v1/graph/overview is the entity-level \
                      view and needs no clustering"),
            ),
        };
        let mut body = json!({
            "nodes": [], "edges": [],
            "stats": {"node_count": 0, "edge_count": 0, "level": level},
            "reason": reason,
            "hint": hint,
        });
        put_into(&mut body, "entity_count", Measured::from_result_in(entities.as_ref().map(|n| *n), "cannot count entities"));
        put_into(&mut body, "cluster_count", Measured::from_result_in(all_clusters.as_ref().map(|n| *n), "cannot count clusters"));
        return Ok(body);
    }

    let cluster_ids: Vec<String> = clusters.iter().map(|(id, _, _, _)| id.clone()).collect();

    // Inter-cluster edges: for each pair of clusters, count entity edges
    // whose endpoints belong to different clusters at this level.
    let inter = state
        .memory()
        .graph_cluster_edges(aud, level, &cluster_ids)
        .await
        .map_err(|e| AppError::Internal(format!("inter-cluster edges query: {e}")))?;

    Ok(json!({
        "nodes": clusters.iter().map(|(id, name, lvl, mc)| json!({
            "id": id,
            "name": name,
            "type": "cluster",
            "level": lvl,
            "degree": mc,           // reuse degree slot for sizing — bigger cluster = bigger node
            "member_count": mc,
        })).collect::<Vec<_>>(),
        "edges": inter.iter().map(|(src, dst, w)| json!({
            "src": src,
            "dst": dst,
            "rel_type": "INTER_CLUSTER",
            "confidence": *w as f64,    // weight as confidence so edge rendering can scale
            "weight": w,
        })).collect::<Vec<_>>(),
        "stats": {
            "node_count": clusters.len(),
            "edge_count": inter.len(),
            "level": level,
        }
    }))
}

#[derive(Deserialize)]
struct ClusterAuditParams {
    /// Max clusters listed, largest first. Default 1000, capped at 5000. The
    /// summary always covers every cluster.
    limit: Option<u32>,
}

/// The refusal a restricted caller gets from the audit. Fixed text: it names
/// no cluster, entity, document or tier, so the 403 carries nothing.
const CLUSTER_AUDIT_FORBIDDEN: &str =
    "the cluster audience audit is limited to administrators";

/// Admin / unrestricted only. The audit counts every tier's documents, so a
/// restricted audience cannot be given a filtered version of it: the counts
/// are the finding.
fn cluster_audit_gate(aud: &Audience) -> Result<(), AppError> {
    match aud {
        Audience::Unrestricted => Ok(()),
        Audience::Roles(_) => Err(AppError::Forbidden(CLUSTER_AUDIT_FORBIDDEN.to_string())),
    }
}

/// GET /api/v1/graph/clusters/audit — how each cluster mixes audience tiers,
/// what a `{company, system}` reader would see of them, and whether the tags
/// are complete enough for the numbers to mean anything. Read-only; admin or
/// `kb:unrestricted` only (a restricted caller gets 403 and nothing else).
///
/// This is the "measure first" step of the design's per-audience
/// clustering design: a member's tiers are the `metadata.roles` of every
/// document it is mentioned in (`mentions -> pages -> docs`); a cluster is
/// `pure:<tier>` or `mixed`. Two aggregate statements and one scalar, no
/// per-cluster round trips (`memory/cluster_audit.rs`).
async fn graph_clusters_audit(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(p): Query<ClusterAuditParams>,
) -> AppResult {
    let aud = scope::resolve(&state, &ctx).await?;
    cluster_audit_gate(&aud)?;
    let raw = crate::memory::cluster_audit::fetch(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("cluster audit query: {e}")))?;
    let limit = p.limit.unwrap_or(1000).clamp(1, 5000) as usize;
    Ok(Json(crate::memory::cluster_audit::build(raw, limit)))
}

/// POST /api/v1/graph/recluster — run community detection over the graph.
///
/// Delegated to `worker.graph.recluster` on a 900s timeout: it clusters the
/// whole graph and labels each cluster. Minutes on a real corpus.
///
/// Intelligent tier: the clusterer role comes from the add-on, so the base
/// tier cannot run it — the refusal below is the honest answer, not a
/// stopgap. The base tier still gets a document graph; it is the structure
/// OVER the graph that is licensed.
///
/// Before this route the only path to `run_clustering` was the
/// `graph_clustering` heartbeat action, which an operator has to schedule;
/// the two entry points the clusterer's own docstring named, the
/// `gnn_reclustering` autonomy location and the CLI recluster verb, were both
/// lost in the Rust port.
///
/// An ASYNCHRONOUS-OPERATION route (`ops.rs`): this starts the
/// `graph.recluster` op and, by default, answers `202` with the op handle at
/// once (`default_wait` is 0 for this type: a run is minutes). `?wait=<s>`
/// waits up to that long and returns the worker's own reply, `200`, if the
/// run finished. The work is [`recluster_core`].
async fn graph_recluster(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(w): Query<WaitQuery>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    super::ops::route_start(&state, &ctx, "graph.recluster", body, w.wait).await
}

/// The capability a recluster is refused for on a Basic install.
pub(super) const RECLUSTER_WHAT: &str = "community detection is an Intelligent-tier capability";

/// What `POST /api/v1/graph/recluster` does: the Intelligent-tier gate, the
/// requester, the 900 s worker call. One body for the route's op and for
/// `POST /api/v1/ops {type: "graph.recluster"}`.
pub(super) async fn recluster_core(
    state: &Arc<AppState>,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
    mut body: Value,
) -> delegation::StatusJson {
    if let Some(refusal) = intel_refusal(RECLUSTER_WHAT) {
        return refusal;
    }
    delegation::attach_requester(&mut body, ctx);
    match state.memory().graph_recluster(&body).await {
        Ok(response) => delegation::worker_ok(response),
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

/// Refuse an Intelligent-tier route before dispatch, or `None` to proceed.
///
/// These subjects are registered on the ml-intel surface only, so without
/// the add-on there is no subscriber at all: the caller would wait out the
/// worker timeout to be told "worker timeout", which is a transport word for
/// a licensing fact. `what` names the capability so the message is about the
/// thing asked for, not about add-ons in general.
///
/// The entity-level graph — overview, stats, search, detail, neighbors — is
/// built on every tier by the open `graph_builder`, so the hint always has
/// somewhere real to point.
pub(super) fn intel_refusal(what: &str) -> Option<delegation::StatusJson> {
    if crate::addons::trellion_intel_enabled() {
        return None;
    }
    Some((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": crate::addons::intel_refusal_msg(),
            "addon": "trellion_intel",
            "state": crate::addons::health_word("trellion_intel"),
            "capability": what,
            "hint": "the entity-level graph (/api/v1/graph/overview, stats, \
                     search, detail, neighbors) is built on every tier and \
                     needs none of this",
        })),
    ))
}

/// Every Intelligent-tier graph route: gate, attach the requester, delegate.
///
/// One helper rather than eight near-identical bodies, because the thing
/// that must not vary between them is the gate — a route that forgot it
/// would look like a 900-second hang, and only on unlicensed installs.
pub(super) async fn intel_graph(
    state: &Arc<AppState>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    op: &str,
    what: &str,
    body: Value,
) -> delegation::StatusJson {
    if let Some(refusal) = intel_refusal(what) {
        return refusal;
    }
    // These handlers walk the whole graph (navigator,
    // embedding and traversal tables) and used to be refused to any caller
    // whose knowledge-base audience is restricted. They now FILTER: the
    // caller's audience is resolved once (`worker.rag.audience`, the same
    // resolver retrieval uses) and handed down as `roles`; trellion_intel
    // applies it in SQL while it walks (absent = unrestricted, unchanged).
    //
    // The trellion-intel image is NOT pinned by this stack's tags, so an
    // older worker or intel may ignore `roles` and answer for the corpus.
    // A restricted caller is therefore only ever given a reply that says it
    // was filtered (`scope::confirm_audience`); anything else is dropped and
    // answered 503. An unrestricted caller never depends on it.
    // `classify_intent` reads only the query string and carries no audience.
    //
    // A client-supplied `roles` is never honoured: it is removed here and
    // replaced by the gateway's own answer, or left absent.
    let audience = if op_needs_audience(op) {
        match scope::resolve(state, &ctx).await {
            Ok(a) => a,
            Err(e) => {
                return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": e.to_string()})));
            }
        }
    } else {
        Audience::Unrestricted
    };
    let mut body = graph_request_body(body, &audience);
    delegation::attach_requester(&mut body, &ctx);
    match state.memory().graph_intel(op, &body).await {
        Ok(response) => graph_reply(&audience, op, what, response),
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

/// Every graph op reads corpus data except the classifier, which reads only
/// the query string.
fn op_needs_audience(op: &str) -> bool {
    op != "classify_intent"
}

/// The body handed to the worker: whatever `roles` the client sent is dropped
/// (and the confirmation marker, which only a worker may set), then the
/// gateway's own audience is attached for a restricted caller.
fn graph_request_body(mut body: Value, audience: &Audience) -> Value {
    if let Some(obj) = body.as_object_mut() {
        obj.remove("roles");
        obj.remove(scope::AUDIENCE_KEY);
    }
    if let Audience::Roles(roles) = audience {
        if !body.is_object() {
            body = json!({});
        }
        body["roles"] = json!(roles);
    }
    body
}

/// The worker's reply as HTTP: a restricted caller gets it only if the worker
/// confirmed it filtered by their audience (`scope::confirm_audience`),
/// otherwise 503. This is what replaced the blanket 403.
fn graph_reply(audience: &Audience, op: &str, what: &str, response: Value) -> delegation::StatusJson {
    match scope::confirm_audience(audience, response) {
        Some(confirmed) => delegation::worker_ok(confirmed),
        None => {
            tracing::warn!(op, "graph reply carried no audience confirmation; refused for a restricted caller");
            scope::unconfirmed_response(what)
        }
    }
}

/// POST /api/v1/graph/navigate — seeds → expand → pages → paths.
///
/// An ASYNCHRONOUS-OPERATION route (`ops.rs`): a navigation that finishes
/// within `default_wait` (or `?wait=`) is answered 200 as ever; one that has
/// grown slower is answered 202 with an op handle. The work is
/// [`navigate_core`], which is `intel_graph`: the audience is resolved from the
/// OWNER's identity captured when the op started.
async fn graph_navigate(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(w): Query<WaitQuery>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    super::ops::route_start(&state, &ctx, "graph.navigate", body, w.wait).await
}

pub(super) const NAVIGATE_WHAT: &str = "graph-guided navigation";
pub(super) const TRAVERSE_WHAT: &str = "intent-weighted traversal";
pub(super) const EXTRACT_RELATIONS_WHAT: &str = "typed relation extraction";

/// What `POST /api/v1/graph/navigate` does. Audience-filtered: it goes
/// through `intel_graph` (`scope::resolve` + `confirm_audience`).
pub(super) async fn navigate_core(
    state: &Arc<AppState>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Value,
) -> delegation::StatusJson {
    intel_graph(state, ctx, "navigate", NAVIGATE_WHAT, body).await
}

/// POST /api/v1/graph/traverse — intent-weighted priority traversal.
/// An ASYNCHRONOUS-OPERATION route, like navigate (see [`graph_navigate`]).
async fn graph_traverse(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(w): Query<WaitQuery>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    super::ops::route_start(&state, &ctx, "graph.traverse", body, w.wait).await
}

/// What `POST /api/v1/graph/traverse` does (audience-filtered, as navigate).
pub(super) async fn traverse_core(
    state: &Arc<AppState>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Value,
) -> delegation::StatusJson {
    intel_graph(state, ctx, "traverse", TRAVERSE_WHAT, body).await
}

/// POST /api/v1/graph/explain-path — shortest reasoning path between two
/// entities. An empty path is an answer ("no route within 5 hops"), not an
/// absence, and the worker reports it as `found: false`.
async fn graph_explain_path(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    intel_graph(&state, ctx, "explain_path", "path explanation", body).await
}

/// POST /api/v1/graph/semantic-search — entities by embedding similarity.
/// Needs `entity_embeddings`, which the Intelligent tier's embedder writes.
async fn graph_semantic_search(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    intel_graph(&state, ctx, "semantic_search", "entity semantic search", body).await
}

/// POST /api/v1/graph/search-clusters — clusters by centroid similarity.
/// Centroids come from a clustering pass, so this is empty with a stated
/// reason until `/api/v1/graph/recluster` has run.
async fn graph_search_clusters(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    intel_graph(&state, ctx, "search_clusters", "cluster semantic search", body).await
}

/// POST /api/v1/graph/classify-intent — the router's query classification.
async fn graph_classify_intent(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    intel_graph(&state, ctx, "classify_intent", "query intent classification", body).await
}

/// POST /api/v1/graph/extract-relations — typed relations for one page.
/// An ASYNCHRONOUS-OPERATION route (see [`graph_navigate`]): an LLM pass over
/// one page, up to the worker timeout.
async fn graph_extract_relations(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(w): Query<WaitQuery>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    super::ops::route_start(&state, &ctx, "graph.extract_relations", body, w.wait).await
}

/// What `POST /api/v1/graph/extract-relations` does (audience-filtered).
pub(super) async fn extract_relations_core(
    state: &Arc<AppState>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Value,
) -> delegation::StatusJson {
    intel_graph(state, ctx, "extract_relations", EXTRACT_RELATIONS_WHAT, body).await
}

/// POST /api/v1/graph/recall-traversals — past traversals by similarity.
async fn graph_recall_traversals(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    intel_graph(&state, ctx, "recall_traversals", "traversal recall", body).await
}

// ═══════════════════════════════════════════════════════════════
// Graph prune staging — list + selective restore (soft delete)
//
// The Python `graph_prune` heartbeat action snapshots every entity it
// removes (entity row + edges + mentions as JSONB) into
// `graph_prune_staging` and purges rows past the retention window.
// These endpoints let the operator inspect the staging area and
// selectively restore entities within that window.
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct StagedQuery {
    limit: Option<i64>,
    reason: Option<String>,
    #[serde(default)]
    include_restored: bool,
}

/// GET /api/v1/graph/prune/staged — list soft-deleted entities, newest
/// first. Returns an empty list when the staging table doesn't exist yet
/// (graph_prune has never run).
async fn graph_prune_staged(
    State(state): State<Arc<AppState>>,
    // The listing carries canonical entity NAMES (up to 5,000 per cleanup run), so
    // it is held to the tier `prune/restore` is: Operator and above, or a caller
    // with no account (a controller service, which the front door admits to
    // `prune/restore` too). A bare GET is otherwise open to a User at the front door.
    _op: OperatorOrInternal,
    Query(params): Query<StagedQuery>,
) -> AppResult {
    let limit = params.limit.unwrap_or(200).clamp(1, 1000);
    let body = state
        .memory()
        .graph_prune_staged(limit, params.reason.as_deref(), params.include_restored)
        .await;
    Ok(Json(body))
}

/// Entities one `{run_id}` restore call brings back.
const RESTORE_RUN_BATCH: i64 = 500;

/// POST /api/v1/graph/prune/restore — body `{"staging_ids": ["...", ...]}`
/// or `{"run_id": "entq-…"}` (everything one cleanup run staged).
///
/// Re-inserts the entity (or grafts onto an existing entity with the same
/// name+type if one was re-extracted since the deletion), re-creates or
/// re-points its edges and mentions from the snapshot, then marks the
/// staging row restored. Edges/mentions whose other endpoint has since
/// vanished are skipped and counted, not fatal. Embeddings and graph
/// signals are not restored — rag_reindex / graph_signals regenerate them.
async fn graph_prune_restore(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppResult {
    // `{run_id}`: restore what one cleanup run staged (it stages up to 5,000;
    // staging_ids takes 100 per call). At most RESTORE_RUN_BATCH per call:
    // `remaining` > 0 means call again.
    if let Some(run) = body.get("run_id") {
        let run = run.as_str().filter(|r| (1..=64).contains(&r.len())
            && r.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        let Some(run) = run else {
            return Err(AppError::BadRequest("run_id must be 1-64 letters, digits, '-' or '_'".into()));
        };
        return Ok(Json(state.memory().graph_prune_restore_run(run, RESTORE_RUN_BATCH).await));
    }
    // Staged EDGES restore separately via edge_staging_ids
    let edge_ids: Vec<String> = body.get("edge_staging_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let ids: Vec<String> = body.get("staging_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if !edge_ids.is_empty() {
        let edge_ids: Vec<String> = edge_ids.into_iter().take(500).collect();
        let mut results: Vec<Value> = Vec::with_capacity(edge_ids.len());
        for sid in &edge_ids {
            results.push(state.memory().graph_prune_restore_edge(sid).await);
        }
        if ids.is_empty() {
            return Ok(Json(json!({"results": results})));
        }
        // Both kinds requested — fall through and merge
        let mut all = results;
        let ids: Vec<String> = ids.into_iter().take(100).collect();
        for sid in &ids {
            all.push(state.memory().graph_prune_restore_entity(sid).await);
        }
        return Ok(Json(json!({"results": all})));
    }

    if ids.is_empty() {
        return Err(AppError::BadRequest("staging_ids or edge_staging_ids required".into()));
    }
    let ids: Vec<String> = ids.into_iter().take(100).collect();

    let mut results: Vec<Value> = Vec::with_capacity(ids.len());
    for sid in &ids {
        results.push(state.memory().graph_prune_restore_entity(sid).await);
    }
    Ok(Json(json!({"results": results})))
}

// ═══════════════════════════════════════════════════════════════
// Junk-entity cleanup — `noo graph entity-cleanup`
// ═══════════════════════════════════════════════════════════════

/// POST /api/v1/graph/entity-cleanup — body `{apply?, examples?, max_delete?}`.
///
/// Finds the entities trellion's validator rejects (`a`, `x_t`, `theta`,
/// `0.003`) and, with `apply`, stages each one into `graph_prune_staging`
/// (reason `junk_entity`) and deletes it, at most `max_delete` (default and
/// ceiling 5,000) per run. A DRY RUN unless `apply` is the JSON boolean
/// `true`: the default pass only SELECTs.
///
/// ADMIN ONLY, which is stricter than `graph/prune/restore` (any Operator).
/// This one deletes graph rows. The rule is the type's `admin_only`, checked
/// when the op starts, so it is the same here and at `POST /api/v1/ops`.
///
/// An ASYNCHRONOUS-OPERATION route (`ops.rs`): starts the `graph.entity_cleanup`
/// op and waits its default wait (3 s): a dry run on a modest graph answers
/// `200` with the report, anything slower `202` with a handle. The work is
/// [`entity_cleanup_core`].
async fn graph_entity_cleanup(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(w): Query<WaitQuery>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    super::ops::route_start(&state, &ctx, "graph.entity_cleanup", body, w.wait).await
}

/// The most entities one applied run removes, and the default.
pub(crate) const ENTITY_CLEANUP_MAX_DELETE: i64 = 5000;
/// Examples returned in the report (the CLI shows a table of them).
const ENTITY_CLEANUP_MAX_EXAMPLES: i64 = 200;

/// The request the worker is sent, from the caller's params, or the refusal.
/// ONLY these three fields cross: no engine, DSN, restriction list or
/// `_requester` of the caller's making can ride along. `apply` must be the
/// boolean `true` to apply (the string "false" is not a request to delete).
pub(crate) fn entity_cleanup_request(params: &Value) -> Result<(bool, Value), String> {
    let int = |k: &str, default: i64, lo: i64, hi: i64| -> Result<i64, String> {
        match params.get(k) {
            None | Some(Value::Null) => Ok(default),
            Some(v) => v
                .as_i64()
                .filter(|n| (lo..=hi).contains(n))
                .ok_or_else(|| format!("{k} must be an integer from {lo} to {hi}")),
        }
    };
    let apply = match params.get("apply") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("apply must be true or false".into()),
    };
    let examples = int("examples", 20, 0, ENTITY_CLEANUP_MAX_EXAMPLES)?;
    let max_delete = int("max_delete", ENTITY_CLEANUP_MAX_DELETE, 1, ENTITY_CLEANUP_MAX_DELETE)?;
    Ok((apply, json!({"apply": apply, "examples": examples, "max_delete": max_delete})))
}

/// The security-audit details of an applied cleanup: counts and the run id,
/// NEVER an entity name (the report's `examples` carry those, and the audit
/// log is read by more people than the op row is). Built from an allow-list
/// of numeric/identifier fields, so a name cannot arrive by a worker adding a
/// field. Pure so a test can pin what is recorded.
fn audit_key_ok(k: &str) -> bool {
    (1..=32).contains(&k.len()) && k.chars().all(|c| c.is_ascii_alphabetic() || c == '_')
}

pub(crate) fn entity_cleanup_audit_details(request: &Value, report: Option<&Value>, op: &str) -> Value {
    let pick = |k: &str| report.and_then(|r| r.get(k)).filter(|v| v.is_number()).cloned();
    // The KEYS of `by_reason` / `by_type` are free-form (an entity type is whatever
    // the LLM extractor said), so only `^[A-Za-z_]{1,32}$` keys are kept; every
    // other key's count is folded into `other`. A key is never a way to put text
    // an extractor produced into the audit log.
    let by = |k: &str| {
        report.and_then(|r| r.get(k)).and_then(Value::as_object).map(|m| {
            let mut out = serde_json::Map::new();
            let mut other: i64 = 0;
            for (key, v) in m {
                let Some(n) = v.as_i64() else { continue };
                if audit_key_ok(key) {
                    let cur = out.get(key).and_then(Value::as_i64).unwrap_or(0);
                    out.insert(key.clone(), json!(cur + n));
                } else {
                    other += n;
                }
            }
            if other > 0 {
                let cur = out.get("other").and_then(Value::as_i64).unwrap_or(0);
                out.insert("other".into(), json!(cur + other));
            }
            Value::Object(out)
        })
    };
    json!({
        "op": op,
        "max_delete": request.get("max_delete"),
        "run_id": report.and_then(|r| r.get("run_id")).and_then(Value::as_str).filter(|s| s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')),
        "scanned": pick("scanned"),
        "junk": pick("junk"),
        "staged": pick("staged"),
        "skipped_over_cap": pick("skipped_over_cap"),
        "by_reason": by("by_reason"),
        "by_type": by("by_type"),
    })
}

/// What `POST /api/v1/graph/entity-cleanup` does. One body for the route's op
/// and for `POST /api/v1/ops {type: "graph.entity_cleanup"}`.
///
/// AUDIT. An APPLIED run writes two `noo_security_audit` rows. The first,
/// `outcome: started`, is written BEFORE the worker is asked and through
/// `audit::record_required`: a destructive run must not happen unaudited, so if
/// the row cannot be written (no `NOO_AUDIT_HMAC_KEY`, the partition heal
/// failed) nothing is deleted and the answer is 503. The second, written after
/// (`ok` / `busy` / `failed`), carries the counts and the run id and is
/// best-effort like every other audit write. A dry run is a read and writes
/// none. Neither row names an entity.
///
/// BUSY. The worker takes graph prune's advisory lock and answers
/// `{status: "busy"}` when prune (or another cleanup) holds it; a recluster
/// rewrites the cluster tables this run's deletes cascade into, so a live
/// `graph.recluster` op is refused the same way. Both are 409 failures that
/// say "busy", never a silent queue.
pub(super) async fn entity_cleanup_core(
    state: &Arc<AppState>,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
    params: Value,
) -> crate::ops::Outcome {
    entity_cleanup_with(&state.db, ctx, params, |body| async move {
        state.memory().junk_entity_cleanup(&body).await
    })
    .await
}

/// [`entity_cleanup_core`] with the worker call as a parameter, so a test can
/// stand a worker in without a bus. Everything else (the Admin check, the busy
/// check, the audit rows, the status mapping) is this function's, and is what
/// runs in production.
pub(crate) async fn entity_cleanup_with<F, Fut>(
    db: &sqlx::PgPool,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
    params: Value,
    ask_worker: F,
) -> crate::ops::Outcome
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Value>>,
{
    use crate::ops::Outcome;
    let refuse = |status: u16, msg: &str| Outcome::failed(status, json!({"error": msg}), msg.to_string());
    let (apply, request) = match entity_cleanup_request(&params) {
        Ok(r) => r,
        Err(m) => return refuse(400, &m),
    };
    // An applied run is attributed to an Admin account or it does not happen.
    let actor = match ctx {
        // A person's own Admin credential only: never a delegated or exchanged one (`act`).
        Some(c) if c.role >= crate::auth::Role::Admin && c.act.is_none() => crate::auth::account_of(&c.sub).to_string(),
        _ => return refuse(403, "graph.entity_cleanup needs an Admin account"),
    };
    // The same rule as the type's `human_only_apply` flag, asked again here because this is
    // the one body every entry shares: a harness credential may preview, never delete.
    if apply && ctx.as_ref().is_some_and(|c| c.harness.is_some()) {
        return refuse(403, &super::ops::human_only_apply_message("graph.entity_cleanup"));
    }
    let caller = CleanupCaller { actor, requester: ctx.clone(), extra: Value::Null };
    entity_cleanup_run(db, &caller, apply, request, ask_worker).await
}

/// Who a cleanup run is recorded against and who the worker is told asked for it.
///
/// The route's caller is an Admin's own credential (`actor` = the account, `requester` = that
/// credential, `extra` empty). A SCHEDULED run has no credential: `actor` is the heartbeat task,
/// `requester` is the task's synthetic Admin identity, and `extra` carries the task id and the
/// person who authorised its apply, so the audit row names both.
pub(crate) struct CleanupCaller {
    pub actor: String,
    pub requester: Option<axum::Extension<crate::auth::RequesterCtx>>,
    pub extra: Value,
}

/// Merge `extra`'s fields (task id, authoriser) into an audit details object.
fn with_extra(mut details: Value, extra: &Value) -> Value {
    if let (Some(d), Some(e)) = (details.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            d.insert(k.clone(), v.clone());
        }
    }
    details
}

/// The part of the cleanup that every entry shares once the caller has been admitted: the
/// recluster check, the audit-before-delete row, the worker call, the busy mapping and the result
/// row. The route/op body ([`entity_cleanup_with`]) and the scheduled heartbeat action
/// (`entity_cleanup_task`) both end here, so the cap, the 409 handling and the audit cannot drift
/// between them. `request` is [`entity_cleanup_request`]'s output.
pub(crate) async fn entity_cleanup_run<F, Fut>(
    db: &sqlx::PgPool,
    caller: &CleanupCaller,
    apply: bool,
    request: Value,
    ask_worker: F,
) -> crate::ops::Outcome
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Value>>,
{
    use crate::ops::Outcome;
    let refuse = |status: u16, msg: &str| Outcome::failed(status, json!({"error": msg}), msg.to_string());
    let actor = caller.actor.as_str();
    let ctx = &caller.requester;
    if apply {
        let recluster_live: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM noo_ops WHERE op_type = 'graph.recluster' AND status IN ('queued','running'))",
        )
        .fetch_one(db)
        .await
        // Cannot tell: do not delete under a recluster that may be running.
        .unwrap_or(true);
        if recluster_live {
            return Outcome::failed(
                409,
                json!({"status": "busy", "error": "busy: a graph recluster is running (or could not be ruled out); \
                       try again when it has finished"}),
                "busy: a graph recluster is running; try again when it has finished",
            );
        }
        if !crate::audit::record_required(
            db,
            AuditEvent::new(AuditKind::GraphEntityCleanup, actor, "graph:entities")
                .outcome(AuditOutcome::custom("started"))
                .severity(Severity::Warning)
                .details(with_extra(entity_cleanup_audit_details(&request, None, "apply"), &caller.extra)),
        )
        .await
        {
            return refuse(
                503,
                "the security audit log could not record this run, so nothing was deleted; \
                 check the gateway log for audit_write_* and retry",
            );
        }
    }
    let mut body = request.clone();
    delegation::attach_requester(&mut body, ctx);
    let (status, payload) = match ask_worker(body).await {
        Ok(response) => {
            let (st, axum::Json(p)) = delegation::worker_ok(response);
            (st.as_u16(), p)
        }
        Err(e) => {
            let (st, axum::Json(p)) = delegation::worker_unavailable(e, None);
            (st.as_u16(), p)
        }
    };
    let busy = payload.get("status").and_then(Value::as_str) == Some("busy");
    let outcome = if busy {
        let why = payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("busy: graph prune holds the lock right now; nothing was changed")
            .to_string();
        Outcome::failed(409, payload.clone(), why)
    } else {
        Outcome::from_http(status, payload.clone())
    };
    if apply {
        let result = if busy { "busy" } else if outcome.failure.is_some() { "failed" } else { "ok" };
        crate::audit::record(
            db,
            AuditEvent::new(AuditKind::GraphEntityCleanup, actor, "graph:entities")
                .outcome(result)
                .severity(if result == "ok" { Severity::Warning } else { Severity::Error })
                .details(with_extra(
                    entity_cleanup_audit_details(&request, if outcome.failure.is_none() { Some(&payload) } else { None }, "apply"),
                    &caller.extra,
                )),
        )
        .await;
    }
    outcome
}

// ═══════════════════════════════════════════════════════════════
// Document upload (multipart or JSON) → memory provider kb/ingest
// ═══════════════════════════════════════════════════════════════

/// POST /api/v1/docs/ingest — dual content-type document ingest.
///
/// multipart/form-data: `file` part (+ optional `title`) — the dashboard
/// file-drop shape. UTF-8 text only; binary (PDF etc.) gets an honest 415
/// (the PDF parse path was Python-gateway-only; watched folders remain the
/// ingest path for binaries).
/// application/json: `{text, title?, source?, source_uri?}` — the
/// heartbeat KB-ingest shape; passed through to the worker unchanged.
async fn docs_ingest(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    // Who is ingesting. This route is hand-written rather than built by
    // `delegate_post`, so it never picked up `delegation.rs::attach_requester`
    // and shipped `_requester`-less bodies to the worker.
    //
    // That mattered more than it looked: `workers/rag.py::_rag_ingest` clamps
    // the audience tags a non-admin/write caller may set, and its guard is
    // `if requester and …` — with no requester the clamp never ran. It was
    // dead code, masked only because `scope_allows` let nobody but
    // write/admin reach this path, and for them the clamp is a deliberate
    // no-op. Adding the `ingest` scope makes it load-bearing.
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(w): Query<WaitQuery>,
    request: axum::extract::Request,
) -> Result<delegation::StatusJson, AppError> {
    use axum::extract::FromRequest;

    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body: serde_json::Value = if content_type.starts_with("multipart/form-data") {
        let mut multipart = axum::extract::Multipart::from_request(request, &state)
            .await
            .map_err(|e| AppError::BadRequest(format!("invalid multipart body: {e}")))?;
        let mut text: Option<String> = None;
        let mut filename = String::new();
        let mut title: Option<String> = None;
        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|e| AppError::BadRequest(format!("multipart read error: {e}")))?
        {
            match field.name().unwrap_or("") {
                "file" | "document" | "upload" => {
                    filename = field.file_name().unwrap_or("upload").to_string();
                    let bytes = field
                        .bytes()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("file read error: {e}")))?;
                    match String::from_utf8(bytes.to_vec()) {
                        Ok(t) => text = Some(t),
                        Err(_) => {
                            return Err(AppError::BadRequest(format!(
                                "'{filename}' is not UTF-8 text — binary/PDF upload has no \
                                 parse path on this gateway; drop it into a watched folder \
                                 instead (noo rag scan)"
                            )))
                        }
                    }
                }
                "title" => {
                    title = field.text().await.ok();
                }
                _ => {}
            }
        }
        let Some(text) = text else {
            return Err(AppError::BadRequest("multipart body missing 'file' part".into()));
        };
        serde_json::json!({
            "text": text,
            "title": title.filter(|t| !t.is_empty()).unwrap_or_else(|| filename.clone()),
            "source": "upload",
            "source_uri": format!("upload://{filename}"),
        })
    } else {
        // JSON (heartbeat KB-ingest and any API caller): pass through.
        let bytes = axum::body::to_bytes(request.into_body(), 32 * 1024 * 1024)
            .await
            .map_err(|e| AppError::BadRequest(format!("body read error: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AppError::BadRequest(format!("invalid JSON body: {e}")))?
    };

    // The request body is read HERE, before any op exists: it is a stream
    // that dies with this request. What is handed on is the parsed document.
    // An ASYNCHRONOUS-OPERATION route (`ops.rs`, type `docs.ingest`): answered
    // 200 with the worker's reply when the ingest finishes within
    // `default_wait` (or `?wait=`), 202 with an op handle otherwise.
    Ok(super::ops::route_start(&state, &ctx, "docs.ingest", body, w.wait).await)
}

/// What `POST /api/v1/docs/ingest` does once the body is parsed.
///
/// Overwrite, never merge: `_requester` is an authenticated fact, and the
/// body is caller-controlled. A client that sends its own `_requester`
/// would otherwise pick its own audience tags — the impersonation this
/// whole path exists to prevent. Absent context (cluster-HMAC, service
/// key) leaves the key unset, which the worker reads as "internal caller,
/// unrestricted" exactly as before.
///
/// Attached through `delegation::attach_requester`, not hand-built: this
/// route used to stamp `sub: r.sub` raw, and an MCP-door credential's
/// subject is a CONNECTION (`user/label`), which names no account — so
/// the worker's audience default would have been `user:user/label`, a
/// tier nobody can read. `attach_requester` sends the ACCOUNT as `sub`.
pub(super) async fn docs_ingest_core(
    state: &Arc<AppState>,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
    mut body: Value,
) -> delegation::StatusJson {
    if ctx.is_some() {
        delegation::attach_requester(&mut body, ctx);
    } else if let Some(obj) = body.as_object_mut() {
        obj.remove("_requester");
    }

    match state.memory().kb_ingest(&body).await {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Worker unavailable: {e}")})),
        ),
    }
}

#[cfg(test)]
mod honesty_tests {
    use super::*;

    /// A missing table is the ONLY sqlx failure that may be answered with a
    /// count. Everything else — the database being down, a pool timeout, a
    /// permission error — used to render as `0` across every RAG count, which
    /// tells an operator the corpus is gone rather than that the DB is down.
    #[test]
    fn only_undefined_table_may_be_zero_filled() {
        // sqlx::Error variants that are NOT a database error can never be 42P01.
        assert!(!missing_table(&sqlx::Error::PoolTimedOut));
        assert!(!missing_table(&sqlx::Error::RowNotFound));
        assert!(!missing_table(&sqlx::Error::WorkerCrashed));
        assert!(!missing_table(&sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))));
    }
}

#[cfg(test)]
mod docs_audience_tests {
    use super::*;

    type Row = crate::memory::provider::DocRow;
    fn row(id: &str, roles: Option<Value>) -> Row {
        (id.into(), None, Some("t".into()), None, None, roles, None, 0)
    }

    #[test]
    fn roles_present_and_null_when_untagged() {
        let rows = vec![
            row("a", Some(json!(["user:alice", "company"]))),
            row("b", None),
            row("c", Some(json!([]))),
        ];
        let out = docs_json(&rows, true);
        assert_eq!(out[0]["roles"], json!(["user:alice", "company"]));
        assert!(out[1]["roles"].is_null());
        assert!(out[1].as_object().unwrap().contains_key("roles"));
        assert!(out[2]["roles"].is_null(), "an empty array is untagged too");
    }

    #[test]
    fn non_admin_shape_has_no_roles_key() {
        let out = docs_json(&[row("a", Some(json!(["company"])))], false);
        assert!(!out[0].as_object().unwrap().contains_key("roles"));
        // ...nor the trail: provenance and history are the operator's.
        let mut r = row("a", Some(json!(["company"])));
        r.6 = Some(json!({"by": "alice", "via": "cli"}));
        r.7 = 3;
        let out = docs_json(&[r], false);
        let o = out[0].as_object().unwrap();
        assert!(!o.contains_key("provenance") && !o.contains_key("audience_history_len"));
    }

    #[test]
    fn privileged_rows_carry_provenance_and_history_length() {
        let mut r = row("a", Some(json!(["user:alice"])));
        r.6 = Some(json!({"by": "alice", "via": "cli", "at": "2026-10-01T00:00:00+00:00"}));
        r.7 = 2;
        let out = docs_json(&[r, row("b", None)], true);
        assert_eq!(out[0]["provenance"]["via"], "cli");
        assert_eq!(out[0]["audience_history_len"], 2);
        assert!(out[1]["provenance"].is_null(), "no provenance recorded: null, shown as unknown");
        assert_eq!(out[1]["audience_history_len"], 0);
    }

    #[test]
    fn filters_parse_trim_and_drop_blanks() {
        let p = DocsListParams {
            limit: None, offset: None, summary: None,
            untagged: Some("true".into()),
            audience: Some(" user:* ".into()),
            source_match: Some("".into()),
            q: Some("  plan ".into()),
        };
        assert_eq!(
            p.filter(),
            scope::DocFilter {
                untagged: true,
                audience: Some("user:*".into()),
                source_glob: None,
                title: Some("plan".into()),
            }
        );
        let none = DocsListParams {
            limit: None, offset: None, summary: None, untagged: Some("0".into()),
            audience: None, source_match: None, q: None,
        };
        assert_eq!(none.filter(), scope::DocFilter::default());
    }

    fn detail_row() -> scope::DocDetailRow {
        (
            "d1".into(), Some("gdrive://x".into()), Some("T".into()), Some("h".into()), None,
            Some(json!({
                "roles": ["user:alice"],
                "ingest": {"by": "alice", "via": "cli", "at": "t"},
                "audience_history": [{"at": "t", "by": "root", "from": ["admin"], "to": ["user:alice"]}],
                "folder_path": ["secret", "dir"],
            })),
            4,
            Some("é".repeat(3000)),
        )
    }

    #[test]
    fn detail_for_an_operator_has_the_whole_trail() {
        let d = doc_detail_json(&detail_row(), true);
        assert_eq!(d["roles"], json!(["user:alice"]));
        assert_eq!(d["provenance"]["via"], "cli");
        assert_eq!(d["audience_history"].as_array().unwrap().len(), 1);
        assert_eq!(d["page_count"], 4);
        assert_eq!(d["metadata"]["folder_path"], json!(["secret", "dir"]));
        assert_eq!(d["text_preview"].as_str().unwrap().chars().count(), DOC_PREVIEW_CHARS, "char-safe cut");
    }

    #[test]
    fn detail_for_a_restricted_caller_has_no_metadata_provenance_or_history() {
        let d = doc_detail_json(&detail_row(), false);
        let o = d.as_object().unwrap();
        for k in ["roles", "provenance", "audience_history", "metadata"] {
            assert!(!o.contains_key(k), "{k} leaked to a restricted caller");
        }
        assert!(!d.to_string().contains("secret"), "metadata contents leaked");
        assert_eq!(d["title"], "T");
        assert!(!d["text_preview"].as_str().unwrap().is_empty());
    }

    #[test]
    fn a_detail_with_no_recorded_trail_says_unknown_not_missing() {
        let mut r = detail_row();
        r.5 = Some(json!({"roles": ["admin"]}));
        let d = doc_detail_json(&r, true);
        assert!(d["provenance"].is_null());
        assert_eq!(d["audience_history"], json!([]));
    }

    #[test]
    fn an_applied_retag_is_audited_with_target_selector_and_outcome() {
        let body = json!({"roles": ["user:alice"], "match": "gdrive://*", "only_untagged": false, "apply": true});
        let resp = json!({"data": {"status": "ok", "matched": 2, "applied": 2, "roles": ["user:alice"],
            "documents": [{"doc_id": "d1", "from": ["admin"], "to": ["user:alice"]}, {"doc_id": "d2"}]}});
        let (sev, outcome, d) = retag_audit_row(&body, &resp);
        assert_eq!((sev, outcome), (Severity::Info, AuditOutcome::Ok));
        assert_eq!(d["roles"], json!(["user:alice"]));
        assert_eq!(d["match"], "gdrive://*");
        assert_eq!(d["relabel"], true);
        assert_eq!((d["matched"].as_u64(), d["applied"].as_u64()), (Some(2), Some(2)));
        assert_eq!(d["doc_ids"], json!(["d1", "d2"]));
        // A refused apply is recorded too, as a warning with the reason.
        let refused = json!({"error": "not yours to tag into: ['admin']"});
        let (sev, outcome, d) = retag_audit_row(&body, &refused);
        assert_eq!((sev, outcome), (Severity::Warning, AuditOutcome::custom("refused")));
        assert!(d["error"].as_str().unwrap().contains("not yours"));
    }

    #[test]
    fn retag_route_audits_applied_calls_only() {
        let src = include_str!("knowledge.rs");
        let route = &src[src.find("async fn rag_retag(").unwrap()..src.find("async fn audit_retag(").unwrap()];
        assert!(route.contains("if applying {") && route.contains("audit_retag("));
    }

    #[test]
    fn held_listing_is_operator_only() {
        // The refusal itself is the extractor (`authz::tests` drives it through
        // a router); what is pinned here is that the route takes it.
        let src = include_str!("knowledge.rs");
        let at = src.find("async fn docs_held(").unwrap();
        assert!(src[at..at + 400].contains("_op: OperatorOrInternal"));
    }

    #[test]
    fn hold_unhold_and_purge_audit_applied_calls_only() {
        let src = include_str!("knowledge.rs");
        for (route, event) in [
            ("async fn docs_hold(", "kb_hold"),
            ("async fn docs_unhold(", "kb_unhold"),
            ("async fn docs_purge(", "kb_purge"),
        ] {
            let start = src.find(route).unwrap();
            let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
            assert!(body.contains("let applying = body.get(\"apply\")"), "{route}");
            assert!(body.contains(".unwrap_or(false)"), "{route}: apply must default to false");
            assert!(body.contains("if applying {") && body.contains(event), "{route}");
        }
    }

    #[test]
    fn hold_audit_row_records_what_was_asked_and_done() {
        let body = json!({"title_prefix": "p", "reason": "r", "apply": true});
        let ok = json!({"count": 3, "applied": 3, "doc_ids": ["a", "b", "c"]});
        let (sev, outcome, d) = hold_audit_row(&AuditKind::KbHold, &body, &ok);
        assert_eq!((sev, outcome), (Severity::Info, AuditOutcome::Ok));
        assert_eq!(d["count"], 3);
        assert_eq!(d["reason"], "r");
        // a purge is always at least a warning, and a refusal is recorded
        let (sev, _, _) = hold_audit_row(&AuditKind::KbPurge, &body, &json!({"count": 1, "deleted": 1}));
        assert_eq!(sev, Severity::Warning);
        let (sev, outcome, d) = hold_audit_row(&AuditKind::KbHold, &body, &json!({"error": "a hold needs a reason"}));
        assert_eq!((sev, outcome), (Severity::Warning, AuditOutcome::custom("refused")));
        assert_eq!(d["error"], "a hold needs a reason");
    }

    #[test]
    fn backlog_counts_never_include_held_documents() {
        use crate::autonomy_evaluators::{sql_unembedded_chunks, sql_unembedded_pages};
        for sql in [sql_unembedded_pages(true), sql_unembedded_chunks(true)] {
            assert!(sql.contains("d.held_at IS NULL"), "{sql}");
            assert!(sql.contains("JOIN docs d"), "{sql}");
        }
    }

    /// Trellion may not have run migration 105 yet (a stack tag does not pin
    /// trellion; the gateway can start first). Then NO count or listing may
    /// name the column, or it errors.
    #[test]
    fn without_the_held_column_no_backlog_query_names_it() {
        use crate::autonomy_evaluators::{sql_unembedded_chunks, sql_unembedded_pages};
        for sql in [sql_unembedded_pages(false), sql_unembedded_chunks(false)] {
            assert!(!sql.contains("held_at"), "{sql}");
            assert!(sql.contains("embedding IS NULL"), "{sql}");
        }
        assert!(!scope::docs_where_for_test(false).contains("held_at"));
        assert!(scope::docs_where_for_test(true).contains("d.held_at IS NULL"));
        assert!(!scope::scope_ctes_for_test(false).contains("held_at"));
        assert!(scope::scope_ctes_for_test(true).contains("d.held_at IS NULL"));
        assert!(!scope::entity_pages_sql(false).contains("held_at"));
        assert!(scope::entity_pages_sql(true).contains("d.held_at IS NULL"));
    }

    /// The four hold routes answer "roll trellion first" without a NATS round
    /// trip while the column is absent.
    #[test]
    fn hold_routes_refuse_while_the_column_is_absent() {
        let src = include_str!("knowledge.rs");
        for route in ["async fn docs_hold(", "async fn docs_unhold(", "async fn docs_purge(", "async fn docs_held("] {
            let start = src.find(route).unwrap();
            let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
            assert!(body.contains("hold_column_gate(&state)"), "{route}");
        }
    }

    #[test]
    fn a_machine_caller_counts_as_privileged_and_a_user_does_not() {
        assert!(is_privileged(&None));
        let ctx = |role| Some(axum::Extension(crate::auth::RequesterCtx {
            sub: "x".into(), scopes: vec![], role, harness: None, act: None,
        }));
        assert!(is_privileged(&ctx(crate::auth::Role::Operator)));
        assert!(!is_privileged(&ctx(crate::auth::Role::User)));
    }

    #[test]
    fn summary_counts_untagged_and_audiences() {
        let all = vec![
            Some(json!(["user:alice"])),
            Some(json!(["user:amy", "company"])),
            Some(json!(["team:x", "company"])),
            None,
            Some(Value::Null),
            Some(json!([])),
        ];
        let s = audience_summary(&all);
        assert_eq!(s["total"], 6);
        assert_eq!(s["untagged"], 3);
        assert_eq!(s["by_audience"]["user:*"], 2);
        assert_eq!(s["by_audience"]["company"], 2);
        assert_eq!(s["by_audience"]["team:x"], 1);
    }

    #[test]
    fn limit_is_defaulted_and_capped() {
        assert_eq!(docs_page_bounds(None, None), (200, 0));
        assert_eq!(docs_page_bounds(Some(99_999), Some(40)), (2000, 40));
        assert_eq!(docs_page_bounds(Some(0), None), (1, 0));
        assert_eq!(docs_page_bounds(Some(50), None), (50, 0));
    }
}

/// the design guard: a route that reads documents or anything derived from
/// them must resolve the caller's audience. A new handler that forgets is the
/// bug this followup was filed for, and `scope_allows` lets every GET through,
/// so nothing else would stop it.
#[cfg(test)]
mod audience_guard {
    const SRC: &str = include_str!("knowledge.rs");

    /// Body of `async fn <name>(` up to the next top-level item.
    fn body(name: &str) -> &'static str {
        let code = &SRC[..SRC.find("#[cfg(test)]").unwrap()];
        let start = code
            .find(&format!("async fn {name}("))
            .unwrap_or_else(|| panic!("handler {name} not found"));
        let rest = &code[start..];
        let end = rest[1..]
            .find("\nasync fn ")
            .or_else(|| rest[1..].find("\npub(super) async fn "))
            .or_else(|| rest[1..].find("\nfn "))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        &rest[..end]
    }

    #[test]
    fn every_knowledge_read_route_resolves_the_callers_audience() {
        for name in [
            "docs_list",
            "graph_entities",
            "graph_entity_detail",
            "graph_entity_neighbors",
            "graph_entities_resolve",
            "graph_overview",
            "graph_clusters_overview",
            "graph_clusters_audit",
            "intel_graph",
        ] {
            assert!(
                body(name).contains("scope::resolve("),
                "{name} reads the knowledge base without resolving the caller's audience"
            );
        }
    }

    /// The audit counts every tier's documents, so a restricted caller must be
    /// refused BEFORE any SQL runs, and the refusal must be the one gate.
    #[test]
    fn the_cluster_audit_refuses_a_restricted_caller_before_it_reads_anything() {
        let b = body("graph_clusters_audit");
        let gate = b.find("cluster_audit_gate(").expect("handler must call the gate");
        let fetch = b.find("cluster_audit::fetch").expect("handler must fetch");
        assert!(b.find("scope::resolve(").unwrap() < gate && gate < fetch, "resolve, then gate, then read");
    }

    #[test]
    fn the_kiosk_is_the_only_unrestricted_graph_caller() {
        let kiosk = include_str!("kiosk.rs");
        assert_eq!(
            kiosk.matches("Audience::Unrestricted").count(),
            1,
            "kiosk graph is the one deliberate unrestricted read"
        );
        let code = &SRC[..SRC.find("#[cfg(test)]").unwrap()];
        assert!(!code.contains("&Audience::Unrestricted"), "route code must not pass a hardcoded unrestricted audience");
    }
}

/// the design, measure-first audit: admin only, and a refusal that carries nothing.
#[cfg(test)]
mod cluster_audit_gate_tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn a_restricted_caller_gets_403_and_the_body_names_nothing() {
        for roles in [
            vec!["company".to_string(), "system".to_string(), "user:alice".to_string()],
            vec!["company".to_string(), "team:ops".to_string()],
            vec![], // an empty set is restricted, not unrestricted
        ] {
            let err = cluster_audit_gate(&Audience::Roles(roles.clone())).expect_err("restricted must be refused");
            let resp = err.into_response();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{roles:?}");
        }
        assert!(!CLUSTER_AUDIT_FORBIDDEN.contains("user:") && !CLUSTER_AUDIT_FORBIDDEN.contains("team:"));
    }

    #[test]
    fn an_unrestricted_caller_is_admitted() {
        assert!(cluster_audit_gate(&Audience::Unrestricted).is_ok());
    }
}

/// the Intelligent-tier graph routes serve a restricted caller
/// FILTERED results (they used to 403), and only on the worker's confirmation.
#[cfg(test)]
mod graph_audience_tests {
    use super::*;

    fn restricted() -> Audience {
        Audience::Roles(vec!["company".into(), "system".into(), "user:a".into()])
    }

    #[test]
    fn a_restricted_caller_is_served_a_confirmed_reply_not_a_403() {
        let (status, body) = graph_reply(
            &restricted(),
            "navigate",
            "graph-guided navigation",
            json!({"seed_entities": [{"canonical_name": "E_co"}], AUDIENCE_KEY_FOR_TEST: true}),
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.0["seed_entities"][0]["canonical_name"], "E_co");
        // the internal marker is not part of the public shape
        assert!(body.0.get(AUDIENCE_KEY_FOR_TEST).is_none());
    }

    #[test]
    fn a_reply_without_the_confirmation_is_never_forwarded_to_a_restricted_caller() {
        // The skew case: an older worker / trellion-intel ignored `roles` and
        // answered for the whole corpus. Its answer must not reach the caller.
        for stale in [
            json!({"seed_entities": [{"canonical_name": "E_b_priv"}], "candidate_page_ids": ["p-b"]}),
            json!({"data": {"entities": [{"canonical_name": "E_adm"}], "count": 1}}),
            json!({"entities": [], AUDIENCE_KEY_FOR_TEST: false}),
            json!({"error": "trellion-intel does not filter `navigate` by audience"}),
        ] {
            let (status, body) = graph_reply(&restricted(), "navigate", "graph-guided navigation", stale);
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            let text = body.0.to_string();
            assert!(!text.contains("E_b_priv") && !text.contains("E_adm") && !text.contains("p-b"), "{text}");
        }
    }

    /// a user's saved walks are the most private thing the
    /// graph routes can return (their own questions), so the guard applies to
    /// `recall_walks` exactly as it does to a navigate: an older worker, or one
    /// over a trellion-intel with no `walks` module, cannot produce the stamp.
    #[test]
    fn a_saved_walk_reply_without_the_stamp_is_never_forwarded_to_a_restricted_caller() {
        let walk = json!({"walks": [{"id": "w1", "query": "A-PRIVATE-QUESTION", "kind": "thread"}], "count": 1});
        let (status, body) = graph_reply(&restricted(), "recall_walks", "saved-walk recall", walk.clone());
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!body.0.to_string().contains("A-PRIVATE-QUESTION"), "{}", body.0);
        let mut stamped = walk;
        stamped[AUDIENCE_KEY_FOR_TEST] = json!(true);
        let (status, body) = graph_reply(&restricted(), "recall_walks", "saved-walk recall", stamped);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.0["walks"][0]["query"], "A-PRIVATE-QUESTION");
        // and the route a client reaches it by is the one that carries the guard
        assert!(op_needs_audience("recall_walks"));
        let src = include_str!("walks.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        assert_eq!(code.matches("knowledge::intel_graph(").count(), 2, "recall and show both go through the guarded helper");
        assert!(!code.contains("graph_intel("), "walks.rs must not call the worker around the audience guard");
    }

    #[test]
    fn an_unrestricted_caller_never_depends_on_the_confirmation() {
        let (status, body) = graph_reply(
            &Audience::Unrestricted,
            "navigate",
            "graph-guided navigation",
            json!({"seed_entities": [{"canonical_name": "E_b_priv"}]}),
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.0["seed_entities"][0]["canonical_name"], "E_b_priv");
    }

    #[test]
    fn classify_intent_stays_open_and_every_other_op_carries_an_audience() {
        assert!(!op_needs_audience("classify_intent"));
        for op in [
            "navigate", "traverse", "explain_path", "semantic_search",
            "search_clusters", "recall_traversals", "recall_walks", "extract_relations",
        ] {
            assert!(op_needs_audience(op), "{op}");
        }
        // ...and the helper is what intel_graph consults, with no 403 left in it.
        let src = include_str!("knowledge.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        let helper = &code[code.find("async fn intel_graph(").unwrap()..];
        let helper = &helper[..helper.find("\n/// POST /api/v1/graph/navigate").unwrap()];
        assert!(helper.contains("op_needs_audience(op)"));
        assert!(!helper.contains("FORBIDDEN"), "the blanket 403 for restricted callers is gone");
    }

    #[test]
    fn the_clients_own_roles_are_never_forwarded_and_the_gateways_are_attached() {
        let evil = json!({"query": "q", "roles": ["admin", "user:b"], AUDIENCE_KEY_FOR_TEST: true});
        // restricted: the gateway's roles replace the client's
        let b = graph_request_body(evil.clone(), &restricted());
        assert_eq!(b["roles"], json!(["company", "system", "user:a"]));
        assert!(b.get(AUDIENCE_KEY_FOR_TEST).is_none());
        // unrestricted: none at all (absent = unrestricted), whatever the client sent
        let b = graph_request_body(evil, &Audience::Unrestricted);
        assert!(b.get("roles").is_none());
        assert_eq!(b["query"], "q");
        // an empty role list is a restricted audience and is forwarded as such
        let b = graph_request_body(json!({"query": "q"}), &Audience::Roles(vec![]));
        assert_eq!(b["roles"], json!([]));
    }

    const AUDIENCE_KEY_FOR_TEST: &str = "audience_filtered";

    #[test]
    fn the_marker_spelling_is_pinned() {
        // the worker's spelling is pinned by tests/test_graph_audience_worker.py
        assert_eq!(scope::AUDIENCE_KEY, AUDIENCE_KEY_FOR_TEST);
    }
}
