// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! External inference boundary — `/api/external/*`.
//!
//! Gateway-owned surface for external service consumers (noo-trading,
//! noo-trellion, …). They submit typed inference requests; mesh owns engine
//! routing (vLLM / embedder / reranker / chat-as-classifier), mesh-routed
//! via the node-agent (`embedding_client::resolve()` + `embed_with_mesh()`).
//! Consumers never call the engines directly. Every call is scope-checked
//! against the caller's named service key ([`Consumer`], set by
//! `auth::require_any_auth`) and audited to `noo_external_requests`.
//!
//! Routes:
//!   - POST /api/external/embeddings        → mesh-routed embedder via
//!                                             node-agent (default: ollama/
//!                                             harrier; OpenAI-shaped
//!                                             response). TEI is an
//!                                             optional/legacy wire format,
//!                                             not the deployed default.
//!   - POST /api/external/rerank            → mesh-routed reranker via
//!                                             node-agent (hardened
//!                                             llama.cpp is the current
//!                                             default; TEI is a legacy
//!                                             wire format still accepted)
//!   - POST /api/external/classify          → chat model + structured output
//!   - POST /api/external/chat/completions  → vLLM (streaming passthrough)
//!   - POST /api/external/inference         → typed multiplexer over the above
//!   - GET  /api/external/capabilities      → availability discovery
//!   - GET  /api/external/usage             → caller's own audit/usage rows

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::coordinator;
use crate::service_keys::{record_external_request, Consumer};
use crate::state::AppState;
use crate::usage::UsageActor;

use super::raw_chat::{self, Outcome, RawChatError};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/external/embeddings", post(embeddings))
        .route("/api/external/embedding-spaces/{space}/migration", put(embedding_migration_report))
        .route("/api/external/rerank", post(rerank))
        .route("/api/external/classify", post(classify))
        .route("/api/external/chat/completions", post(chat_completions))
        .route("/api/external/inference", post(typed_inference))
        // `models` is the third sub-path an OpenAI SDK appends to its
        // base_url, alongside `chat/completions` and `embeddings`. The
        // contract has named all three as kept since 2026-06-14,
        // "OpenAI-SDK compatibility") and this one was never built, so an
        // SDK pointed at the DOCUMENTED base_url still broke on the
        // `.models.list()` that many clients issue at init — which is how a
        // consumer ended up pointing at `/v1` instead and finding no
        // `embeddings` there either (reported 2026-09-12).
        //
        // Same handler as `/v1/models`, so the two surfaces cannot drift;
        // unscoped like `capabilities` for the reason given there — it is a
        // listing, not an inference payload.
        .route("/api/external/models", get(super::inference::openai_models))
        .route("/api/external/capabilities", get(capabilities))
        .route("/api/external/usage", get(usage))
}

// ──────────────────────────── audit helpers ────────────────────────────

/// Spawn an audit-row insert. Never blocks the response.
#[allow(clippy::too_many_arguments)]
fn audit(
    state: &Arc<AppState>,
    consumer: &str,
    endpoint: &'static str,
    kind: Option<&str>,
    model: Option<&str>,
    backend: Option<&str>,
    units: Option<Value>,
    status: u16,
    started: Instant,
    error: Option<String>,
) {
    let latency = started.elapsed().as_millis() as i64;
    tokio::spawn(record_external_request(
        state.db.clone(),
        consumer.to_string(),
        endpoint,
        kind.map(String::from),
        model.map(String::from),
        backend.map(String::from),
        units,
        status,
        latency,
        None,
        error,
    ));
}

/// 403 + audit when a key lacks the required scope.
fn forbidden(
    state: &Arc<AppState>,
    consumer: &Consumer,
    endpoint: &'static str,
    scope: &str,
    started: Instant,
) -> Response {
    audit(
        state,
        &consumer.name,
        endpoint,
        None,
        None,
        None,
        None,
        403,
        started,
        Some(format!("missing scope: {scope}")),
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": {"message": format!("service key lacks '{scope}' scope"), "type": "forbidden"}})),
    )
        .into_response()
}

/// A failure on this surface. Carries the operator detail and renders the
/// consumer's general message (phase 0): see `raw_chat::RawChatError`.
pub(crate) type ExtFail = RawChatError;

/// Refuse: audit the detail under the reference (`trace_id` column), log it,
/// answer the general body. The ONE place an error leaves this module.
#[allow(clippy::too_many_arguments)]
fn refuse(
    state: &Arc<AppState>,
    consumer: &str,
    endpoint: &'static str,
    kind: Option<&str>,
    model: Option<&str>,
    backend: Option<&str>,
    started: Instant,
    e: ExtFail,
) -> Response {
    let latency = started.elapsed().as_millis() as i64;
    tokio::spawn(record_external_request(
        state.db.clone(),
        consumer.to_string(),
        endpoint,
        kind.map(String::from),
        model.map(String::from),
        backend.map(String::from),
        None,
        e.status.as_u16(),
        latency,
        Some(e.reference.clone()),
        Some(e.detail.clone()),
    ));
    e.into_response(endpoint)
}

fn bad_request(msg: &str) -> ExtFail {
    ExtFail::bad_request(msg)
}

/// A refusal about the state of a record (409); the message IS the public one.
fn conflict(msg: impl Into<String>) -> ExtFail {
    ExtFail::conflict(msg)
}

fn upstream(status: StatusCode, detail: impl Into<String>) -> ExtFail {
    ExtFail::new(status, if status.is_server_error() { "backend_unavailable" } else { "backend_error" }, detail)
}

// ──────────────────────────── embeddings ────────────────────────────

async fn embeddings(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    Json(body): Json<Value>,
) -> Response {
    let started = Instant::now();
    const EP: &str = "/api/external/embeddings";
    if !consumer.has_scope("embeddings") {
        return forbidden(&state, &consumer, EP, "embeddings", started);
    }
    let input = body.get("input").cloned().unwrap_or(Value::Null);
    let api_format = crate::embedding_client::resolve().api_format;
    let space = body.get("model").and_then(Value::as_str);
    match do_embeddings(&state, &input, space).await {
        Ok((resp, n, model)) => {
            audit(
                &state, &consumer.name, EP, Some("embedding"), Some(&model),
                Some(&api_format), Some(json!({"inputs": n})), 200, started, None,
            );
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => refuse(&state, &consumer.name, EP, Some("embedding"), None, Some(&api_format), started, e),
    }
}

/// Map an embed failure onto the external refusal. The detail (which may
/// name the embedder's URL) goes to the audit row and the log under the
/// reference; the consumer sees the general wording for the status. A
/// saturated fleet is shed fast: 503 + `Retry-After`.
pub(crate) fn embed_error_to_ext(e: crate::embedding_client::EmbedError) -> ExtFail {
    use crate::embedding_client::EmbedError;
    match e {
        EmbedError::Saturated { retry_after_secs } => {
            let mut f = upstream(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("embedders saturated: shed after the admission wait; retry in {retry_after_secs}s"),
            );
            f.retry_after = Some(retry_after_secs);
            f
        }
        EmbedError::Unavailable(d) => upstream(StatusCode::SERVICE_UNAVAILABLE, format!("embedding backend unavailable: {d:?}")),
        EmbedError::BadStatus(s) => upstream(StatusCode::BAD_GATEWAY, format!("embedding backend returned {s}")),
        EmbedError::Parse(e) => upstream(StatusCode::BAD_GATEWAY, format!("embedding backend parse error: {e}")),
    }
}

/// Proxy to the embedding space's pool (tei | openai | ollama wire format —
/// see `crate::embedding_client`), reshape into OpenAI embeddings shape.
/// `input` is a string or an array of strings. `space` is the body's
/// `model`: an embedding space (`knowledge`, `code`), a space's model name,
/// or `default`/absent for `knowledge` (i145). Anything else is a 400 naming
/// the spaces: an embed is never answered from another model's space.
async fn do_embeddings(
    state: &Arc<AppState>,
    input: &Value,
    space: Option<&str>,
) -> Result<(Value, usize, String), ExtFail> {
    let inputs: Vec<String> = match input {
        Value::String(s) => vec![s.clone()],
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => return Err(bad_request("missing or invalid 'input'")),
    };
    if inputs.is_empty() {
        return Err(bad_request("'input' is empty"));
    }
    // Truncate each to 1500 chars (matches the query-side embed in memory.rs).
    let truncated: Vec<String> = inputs.iter().map(|s| s.chars().take(1500).collect()).collect();

    // The detail of an embed failure (which may name the embedder's URL)
    // goes to the audit row and the log under the reference; the consumer
    // sees the general wording for the status.
    let (model, embeddings) = if let Some(name) = crate::embedding_spaces::parse_next(space) {
        // `<space>@next` (i150): the space's NEXT model during a migration,
        // over the mesh nodes declaring it. trellion's re-embed worker.
        let spaces = crate::embedding_spaces::all();
        let s = crate::embedding_spaces::resolve(&spaces, Some(name)).map_err(|e| bad_request(&e))?;
        let m = s
            .migration
            .as_ref()
            .ok_or_else(|| conflict(format!("embedding space '{}' has no migration: '{}@next' means its next model", s.space, s.space)))?;
        if let Some(why) = crate::embedding_spaces::trellion_refusal(m) {
            return Err(conflict(why));
        }
        let v = crate::embedding_client::EmbeddingEndpoint::embed_model_over_mesh(
            state,
            &m.next_model,
            m.next_dims.unwrap_or(0),
            &crate::embedding_client::NEXT_BALANCER,
            &truncated,
            std::time::Duration::from_secs(30),
        )
        .await
        .map_err(embed_error_to_ext)?;
        (m.next_model.clone(), v)
    } else {
        let endpoint = crate::embedding_client::resolve_space(space).map_err(|e| bad_request(&e))?;
        let v = endpoint
            .embed_with_mesh(state, &truncated, std::time::Duration::from_secs(30))
            .await
            .map_err(embed_error_to_ext)?;
        (endpoint.model.clone(), v)
    };

    let out: Vec<Value> = embeddings
        .iter()
        .enumerate()
        .map(|(i, emb)| json!({"object": "embedding", "index": i, "embedding": emb}))
        .collect();
    let n = out.len();

    let resp = json!({
        "object": "list",
        "data": out,
        "model": model,
        "usage": {"prompt_tokens": 0, "total_tokens": 0}
    });
    Ok((resp, n, model))
}

/// One table in trellion's re-embed report.
#[derive(Debug, Deserialize)]
struct TableProgress {
    done: u64,
    total: u64,
}

#[derive(Debug, Deserialize)]
struct MigrationReport {
    next_model: String,
    tables: std::collections::BTreeMap<String, TableProgress>,
    #[serde(default)]
    cutover_done: bool,
}

/// PUT /api/external/embedding-spaces/{space}/migration (i150) -- trellion's
/// re-embed worker reports progress with its consumer key. Stores the report
/// and its time; in `cutover`, `cutover_done: true` swaps the space to its
/// next model in one UPDATE. 409 when the space has no migration or the
/// report is about another model.
async fn embedding_migration_report(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    Path(space): Path<String>,
    Json(body): Json<MigrationReport>,
) -> Response {
    use crate::embedding_spaces as es;
    let started = Instant::now();
    const EP: &str = "/api/external/embedding-spaces/{space}/migration";
    if !consumer.has_scope("embeddings") {
        return forbidden(&state, &consumer, EP, "embeddings", started);
    }
    let res: Result<Value, ExtFail> = async {
        let err = |what: &str, e: sqlx::Error| ExtFail::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("{what}: {e}"));
        let space = space.trim().to_ascii_lowercase();
        let spaces = es::load(&state.db).await.map_err(|e| err("embedding spaces read", e))?;
        let s = spaces
            .iter()
            .find(|s| s.space == space)
            .ok_or_else(|| bad_request(&format!("no embedding space '{space}'")))?;
        let m = s.migration.as_ref().ok_or_else(|| conflict(format!("space '{space}' has no migration")))?;
        if let Some(why) = es::trellion_refusal(m) {
            return Err(conflict(why));
        }
        if !es::same_model(&m.next_model, &body.next_model) {
            return Err(conflict(format!("space '{space}' is migrating to '{}', not '{}'", m.next_model, body.next_model)));
        }
        let progress = json!({"next_model": m.next_model, "tables": body.tables.iter()
            .map(|(t, p)| (t.clone(), json!({"done": p.done, "total": p.total}))).collect::<serde_json::Map<_, _>>()});
        let ok = match es::progress_action(m, body.cutover_done) {
            es::ProgressAction::Store => es::store_progress(&state.db, &space, &m.next_model, &progress).await,
            es::ProgressAction::Flip => es::flip_to_next(&state.db, &space, &m.next_model).await,
        }
        .map_err(|e| err("embedding migration write", e))?;
        if !ok {
            return Err(conflict(format!("space '{space}' changed under this report; retry")));
        }
        if es::progress_action(m, body.cutover_done) == es::ProgressAction::Flip {
            tracing::info!(space = %space, model = %m.next_model, "embedding_migration_finished");
        }
        let all = es::load(&state.db).await.map_err(|e| err("embedding spaces read", e))?;
        let view = all.iter().find(|s| s.space == space).and_then(|s| serde_json::to_value(s).ok()).unwrap_or(Value::Null);
        es::set_cache(all);
        Ok(view)
    }
    .await;
    match res {
        Ok(view) => {
            audit(&state, &consumer.name, EP, Some("embedding_migration"), Some(&body.next_model), None, None, 200, started, None);
            (StatusCode::OK, Json(view)).into_response()
        }
        Err(e) => refuse(&state, &consumer.name, EP, Some("embedding_migration"), Some(&body.next_model), None, started, e),
    }
}

// ──────────────────────────── rerank ────────────────────────────

async fn rerank(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    Json(body): Json<Value>,
) -> Response {
    let started = Instant::now();
    const EP: &str = "/api/external/rerank";
    if !consumer.has_scope("rerank") {
        return forbidden(&state, &consumer, EP, "rerank", started);
    }
    let input = body.get("input").cloned().unwrap_or(Value::Null);
    let wanted = body.get("model").and_then(Value::as_str).or_else(|| input.get("model").and_then(Value::as_str));
    match do_rerank(&state, &input, wanted).await {
        Ok((resp, n)) => {
            let served = resp["noo"]["model"].as_str().unwrap_or("default").to_string();
            audit(
                &state, &consumer.name, EP, Some("rerank"), Some(&served),
                Some("reranker"), Some(json!({"documents": n})), 200, started, None,
            );
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => refuse(&state, &consumer.name, EP, Some("rerank"), None, Some("reranker"), started, e),
    }
}

/// Rerank `{query, documents}` → `{results: [{index, score}], noo: {...}}`.
///
/// Routing (the gateway owns this; consumers never reach a reranker directly):
///   1. Every node advertising the `rerank` capability, tried in turn
///      through its node-agent on :8081 (mTLS + HMAC). A named `model` is a
///      PREFERENCE (i145): nodes whose role=rerank placement serves it go
///      first, every other reranker after. Rerank scores are per request,
///      so another reranker is a fine stand-in, never a mixed index.
///   2. When none answers (or none advertises), the LLM reranker.
///
/// `noo` says what served: `served_by` (a node, or `llm`), `model`,
/// `fallback` (true when the preference or the reranker tier was unmet) and
/// `requested_model`. It used to take the FIRST node only, so one wedged
/// reranker failed the request with the rest of the fleet idle, and the LLM
/// tier ran only when no node advertised at all.
///
/// There is no other path. The `NOO_RERANK_URL` co-located bypass was
/// removed: it skipped mesh routing AND sent no auth headers.
async fn do_rerank(
    state: &Arc<AppState>,
    input: &Value,
    wanted: Option<&str>,
) -> Result<(Value, usize), ExtFail> {
    let query = input
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("missing input.query"))?;
    let docs: Vec<String> = input
        .get("documents")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .ok_or_else(|| bad_request("missing input.documents"))?;
    if docs.is_empty() {
        return Err(bad_request("input.documents is empty"));
    }
    let wanted = crate::coordinator::model_hint(wanted);
    let mut cands = Vec::new();
    for t in mesh_targets(state, "rerank", "rerank", 8).await {
        let declared = crate::model_presence::node_role_model(state, &t.node_id, "rerank").await;
        cands.push((t, declared));
    }
    let ordered = rerank_order(cands, wanted);
    let mut failures: Vec<String> = Vec::new();
    for (t, declared, stand_in) in &ordered {
        match tei_rerank(query, &docs, &t.url, &t.headers).await {
            Ok(results) => {
                let n = results.len();
                if !failures.is_empty() {
                    tracing::warn!(node = %t.node_id, failed = ?failures, "rerank_failover: an earlier reranker failed; this one answered");
                }
                let noo = rerank_noo(&t.node_id, declared.as_deref(), wanted, *stand_in || !failures.is_empty());
                return Ok((json!({"results": results, "noo": noo}), n));
            }
            Err(e) => {
                tracing::warn!(node = %t.node_id, error = %e.detail, "rerank_node_failed: trying the next reranker");
                failures.push(t.node_id.clone());
            }
        }
    }
    if !ordered.is_empty() {
        tracing::warn!(failed = ?failures, "rerank_all_nodes_failed: answering with the LLM reranker");
    }
    let results = llm_rerank_fallback(state, query, &docs).await?;
    let n = results.len();
    Ok((json!({"results": results, "noo": rerank_noo("llm", None, wanted, true)}), n))
}

/// The reranker order: nodes serving the requested model first (in the
/// mesh order), then every other one, each flagged as a stand-in when a
/// model was requested and it does not serve it. No request = mesh order,
/// nobody a stand-in.
pub(crate) fn rerank_order<T>(cands: Vec<(T, Option<String>)>, wanted: Option<&str>) -> Vec<(T, Option<String>, bool)> {
    let Some(w) = wanted else {
        return cands.into_iter().map(|(t, m)| (t, m, false)).collect();
    };
    let serves = |m: &Option<String>| m.as_deref().is_some_and(|m| crate::embedding_spaces::same_model(m, w));
    let (first, rest): (Vec<_>, Vec<_>) = cands.into_iter().partition(|(_, m)| serves(m));
    first.into_iter().map(|(t, m)| (t, m, false)).chain(rest.into_iter().map(|(t, m)| (t, m, true))).collect()
}

/// The `noo` block of a rerank answer.
pub(crate) fn rerank_noo(served_by: &str, model: Option<&str>, requested: Option<&str>, fallback: bool) -> Value {
    let mut v = json!({
        "served_by": served_by,
        "model": model.unwrap_or(if served_by == "llm" { "llm" } else { "default" }),
        "fallback": fallback,
    });
    if let Some(r) = requested {
        v["requested_model"] = json!(r);
    }
    v
}

/// Normalize a `[{index, score}]` array into the response shape.
fn norm_rerank_rows(arr: &[Value]) -> Vec<Value> {
    arr.iter()
        .map(|r| {
            json!({
                "index": r.get("index").cloned().unwrap_or(json!(0)),
                "score": r.get("score").cloned().unwrap_or(json!(0.0)),
            })
        })
        .collect()
}

/// TEI-family reranker over HTTP (co-located stunnel or a node-agent proxy).
async fn tei_rerank(
    query: &str,
    docs: &[String],
    url: &str,
    headers: &[(String, String)],
) -> Result<Vec<Value>, ExtFail> {
    let payload = json!({"query": query, "texts": docs, "return_text": false});
    // mTLS-aware client — verifies the cluster CA whether we're hitting the
    // local stunnel-reranker or a remote node-agent on :8081.
    let client = crate::tls::cluster_client();
    let mut req = client.post(url).json(&payload).timeout(Duration::from_secs(60));
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| upstream(StatusCode::SERVICE_UNAVAILABLE, format!("rerank backend at {url} unavailable: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        crate::coordinator::warn_if_node_agent_outdated(status, url);
        let _ = resp.text().await;
        return Err(upstream(StatusCode::BAD_GATEWAY, format!("rerank backend at {url} returned {status}")));
    }
    let data: Value = resp
        .json()
        .await
        .map_err(|e| upstream(StatusCode::BAD_GATEWAY, format!("rerank parse error from {url}: {e}")))?;
    let arr = data
        .as_array()
        .ok_or_else(|| upstream(StatusCode::BAD_GATEWAY, format!("rerank unexpected format from {url}")))?;
    Ok(norm_rerank_rows(arr))
}

/// LLM-based rerank — the no-reranker fallback, now in-process.
///
/// Was a NATS round trip to `worker.rerank.llm`, whose Python handler POSTed
/// back to this gateway's own `/v1/chat/completions` to reach the model. The
/// loopback is gone: `llm_rerank` resolves the backend and calls it directly.
///
/// Never fails: degrades to identity order, matching the contract the Python
/// implementation documented ("never returns empty").
async fn llm_rerank_fallback(
    state: &Arc<AppState>,
    query: &str,
    docs: &[String],
) -> Result<Vec<Value>, ExtFail> {
    Ok(crate::llm_rerank::rerank(state, query, docs, None).await)
}

/// Decide where a rerank call goes. Returns `(url, auth_headers)`.
/// One reachable mesh endpoint for a capability.
pub(crate) struct MeshTarget {
    pub node_id: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// Ordered mesh candidates for a capability — the shared shape for embed,
/// rerank, and anything else the fleet serves by node.
///
/// The work is POSTED TO THE MESH and whichever node can serve it does. That
/// means callers get a LIST, not a single peer: previously both embed and
/// rerank took exactly one (`find_peers_by_capability(cap, 1)`), so a single
/// busy or wedged node failed the whole request with a healthy fleet sitting
/// idle behind it.
///
/// Ordering is GPU-first, then least-loaded. A GPU node is preferred because
/// it is dramatically faster for this class of work, but it is a PREFERENCE,
/// not a requirement: a CPU-only node is a perfectly good target when no GPU
/// node is available, which is what keeps the fleet serving through a GPU
/// falling off the bus. `find_peers_by_capability` has already filtered to
/// peers that are alive and under 95% load.
///
/// Every returned URL is a node-agent proxy reached over mTLS
/// (`tls::cluster_client()`) with the node-agent bearer in `headers` — both
/// are required, the proxy 401s without the token and refuses the handshake
/// without the client cert.
pub(crate) async fn mesh_targets(
    state: &AppState,
    capability: &str,
    path: &str,
    max: usize,
) -> Vec<MeshTarget> {
    let mut peers = state.gossip.find_peers_by_capability(capability, max);
    // Stable within each group: find_peers_by_capability already sorted by
    // load ascending, so a stable partition by "has GPU" keeps that order
    // inside both halves.
    peers.sort_by_key(|p| if p.vram_gb > 0.0 { 0 } else { 1 });

    let considered = peers.len();
    let mut skipped_no_agent: Vec<String> = Vec::new();
    let mut skipped_model_missing: Vec<String> = Vec::new();
    let mut out = Vec::with_capacity(peers.len());
    for peer in peers {
        let Ok(link) = crate::node_link::NodeLink::for_node(state, &peer.node_id).await
        else {
            // A peer advertising the capability but with no reachable agent
            // is a real condition (agent restarting, URL not yet published)
            // — skip it and try the next rather than failing the request.
            // WARN, not debug: this is a routing decision, and a silently
            // dropped candidate is indistinguishable from a node that never
            // advertised at all. Diagnosing "no embed target" without this
            // line means guessing between the capability path and the
            // routing path.
            tracing::warn!(node = %peer.node_id, capability, "mesh_target_skipped_unreachable_agent");
            skipped_no_agent.push(peer.node_id.clone());
            continue;
        };
        // Routing reads the node's ROLE capabilities, derived from its
        // placements (`role_capability`), and nothing else:
        //  * a node with no running placement for this role never receives the
        //    work, whatever its gossip still says (a chat-only host6 kept
        //    drawing embeds after its embed role was replaced);
        //  * one whose agent REPORTS the placed model absent or
        //    its backend down is dropped; silence (an older agent) keeps it.
        // Only capabilities that name a role are gated; `whisper` and friends
        // are not roles.
        if let Some(role) = crate::role_capability::role_for_capability(capability) {
            if crate::role_capability::node_serves_role(state, &peer.node_id, role).await == Some(false) {
                tracing::warn!(node = %peer.node_id, capability, "mesh_target_skipped_role_not_served");
                skipped_model_missing.push(peer.node_id.clone());
                continue;
            }
        } else if crate::model_presence::node_role_model_missing(state, &peer.node_id, capability).await {
            tracing::warn!(node = %peer.node_id, capability, "mesh_target_skipped_model_missing");
            skipped_model_missing.push(peer.node_id.clone());
            continue;
        }
        // Per agent: none for an agent that admits the
        // gateway's leaf alone, the legacy bearer for one that has not said.
        let headers = link.auth_headers();
        out.push(MeshTarget {
            node_id: peer.node_id,
            url: link.url(&format!("/{}", path.trim_start_matches('/'))),
            headers,
        });
    }

    // Always state what the mesh considered and what survived. Routing
    // decisions must be observable in production: "considered 0" means no
    // node ADVERTISED the capability, while "considered 2, kept 0" means
    // they advertised but none was reachable — two completely different
    // faults that otherwise present identically as a 503.
    tracing::info!(
        capability,
        considered,
        kept = out.len(),
        kept_nodes = %out.iter().map(|t| t.node_id.as_str()).collect::<Vec<_>>().join(","),
        skipped_no_agent = %skipped_no_agent.join(","),
        skipped_model_missing = %skipped_model_missing.join(","),
        "mesh_targets_resolved"
    );
    out
}

/// Mesh URL source for embeddings — the same mesh leg [`do_rerank`] walks,
/// for the `embed` capability. Picks the least-loaded peer whose node-agent
/// fronts a local embedding container (nodes advertise `embed` only when a
/// TEI container is actually running) and returns the node-agent's `/embed`
/// proxy URL plus the HMAC auth header for the mTLS hop. The proxy speaks
/// the OpenAI `/v1/embeddings` contract (POST OpenAI body → OpenAI reply).
///
/// Deliberately does NOT consult `NOO_EMBEDDING_URL` — precedence between a
/// co-located TEI and mesh routing is owned by the embedding client; this is
/// just the "find me an embed-capable node" leg for it to use as a URL
/// source. Use `crate::tls::cluster_client()` for the request (cluster-CA
/// verified), attaching the returned headers.
#[allow(dead_code)] // wired by the embedding client (separate change)
pub(crate) async fn embed_target(
    state: &Arc<AppState>,
) -> Result<(String, Vec<(String, String)>), ExtFail> {
    let first = mesh_targets(state, "embed", "embed", 5)
        .await
        .into_iter()
        .next()
        .ok_or_else(|| upstream(
            StatusCode::SERVICE_UNAVAILABLE,
            "embed not available (no node advertises the capability)",
        ))?;
    Ok((first.url, first.headers))
}

// ──────────────────────────── classify ────────────────────────────

async fn classify(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    Json(body): Json<Value>,
) -> Response {
    let started = Instant::now();
    const EP: &str = "/api/external/classify";
    if !consumer.has_scope("classify") {
        return forbidden(&state, &consumer, EP, "classify", started);
    }
    let input = body.get("input").cloned().unwrap_or(Value::Null);
    match do_classify(&state, &input).await {
        Ok((resp, model)) => {
            audit(
                &state, &consumer.name, EP, Some("classify"), Some(&model),
                Some("chat-structured"), None, 200, started, None,
            );
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => refuse(&state, &consumer.name, EP, Some("classify"), None, Some("chat-structured"), started, e),
    }
}

/// Classify text into a caller-supplied closed label set using the chat model
/// with constrained JSON output. v1 backing; mesh can swap a dedicated
/// classifier later without changing this contract. `input` is
/// `{text, labels, multi_label}`.
async fn do_classify(
    state: &Arc<AppState>,
    input: &Value,
) -> Result<(Value, String), ExtFail> {
    let labels: Vec<String> = input
        .get("labels")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .ok_or_else(|| bad_request("missing input.labels"))?;
    if labels.is_empty() {
        return Err(bad_request("input.labels is empty"));
    }
    let multi = input.get("multi_label").and_then(|v| v.as_bool()).unwrap_or(false);
    let texts: Vec<String> = match input.get("text") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => return Err(bad_request("missing input.text")),
    };
    if texts.is_empty() {
        return Err(bad_request("input.text is empty"));
    }

    let backend = coordinator::resolve_backend(state)
        .await
        .map_err(|e| ExtFail::from_resolve(&e))?;
    let client = crate::tls::cluster_client();
    let url = format!("{}/v1/chat/completions", backend.url.trim_end_matches('/'));

    let mut results = Vec::with_capacity(texts.len());
    for (i, text) in texts.iter().enumerate() {
        let chosen = classify_one(&client, &url, &backend, text, &labels, multi).await?;
        if multi {
            results.push(json!({"index": i, "labels": chosen}));
        } else {
            let label = chosen.first().cloned().unwrap_or(json!(labels[0]));
            results.push(json!({"index": i, "label": label}));
        }
    }

    Ok((
        json!({"results": results, "model": backend.model, "method": "chat-structured"}),
        backend.model.clone(),
    ))
}

/// One chat round-trip with up to one repair retry. Returns the validated
/// label(s) (subset of `labels`).
async fn classify_one(
    client: &reqwest::Client,
    url: &str,
    backend: &coordinator::ResolvedBackend,
    text: &str,
    labels: &[String],
    multi: bool,
) -> Result<Vec<Value>, ExtFail> {
    let label_list = labels.join(", ");
    let instruction = if multi {
        format!(
            "You are a text classifier. Choose zero or more labels from this exact set: [{label_list}]. \
             Respond ONLY with compact JSON of the form {{\"labels\": [\"...\"]}} using only labels from the set."
        )
    } else {
        format!(
            "You are a text classifier. Choose exactly ONE label from this exact set: [{label_list}]. \
             Respond ONLY with compact JSON of the form {{\"label\": \"...\"}} using a label from the set."
        )
    };
    let body = json!({
        "model": backend.model,
        "messages": [
            {"role": "system", "content": instruction},
            {"role": "user", "content": text}
        ],
        "temperature": 0,
        "max_tokens": 120,
        "stream": false
    });

    for attempt in 0..2 {
        let req = crate::node_link::backend_request_on(
            client,
            reqwest::Method::POST,
            url,
            &backend.backend_type,
        )
        .json(&body)
        .timeout(Duration::from_secs(60));
        let resp = req
            .send()
            .await
            .map_err(|e| upstream(StatusCode::BAD_GATEWAY, format!("classify backend at {url} unreachable: {e}")))?;
        if !resp.status().is_success() {
            if attempt == 1 {
                let s = resp.status();
                return Err(upstream(StatusCode::BAD_GATEWAY, format!("classify backend at {url} returned {s}")));
            }
            continue;
        }
        let data: Value = resp.json().await.unwrap_or(json!({}));
        let content = data
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(chosen) = parse_labels(content, labels, multi) {
            return Ok(chosen);
        }
    }
    Err(upstream(StatusCode::BAD_GATEWAY, "classifier did not return a valid label"))
}

/// Extract `{label}` / `{labels:[...]}` from model output and validate every
/// returned label is in the allowed set.
fn parse_labels(content: &str, labels: &[String], multi: bool) -> Option<Vec<Value>> {
    let start = content.find('{')?;
    let end = content.rfind('}')?;
    if end < start {
        return None;
    }
    let parsed: Value = serde_json::from_str(&content[start..=end]).ok()?;
    if multi {
        let arr = parsed.get("labels")?.as_array()?;
        let valid: Vec<Value> = arr
            .iter()
            .filter(|v| v.as_str().map(|s| labels.iter().any(|l| l == s)).unwrap_or(false))
            .cloned()
            .collect();
        if valid.is_empty() {
            None
        } else {
            Some(valid)
        }
    } else {
        let l = parsed.get("label")?.as_str()?;
        if labels.iter().any(|x| x == l) {
            Some(vec![json!(l)])
        } else {
            None
        }
    }
}

// ──────────────────────────── chat ────────────────────────────

/// POST /api/external/chat/completions — the SAME path as
/// `/v1/chat/completions` (`routes::raw_chat::chat_completions`): the
/// body's `model` is honoured as a class / alias / concrete model hint
/// (it used to be discarded, so every consumer shared one backend),
/// candidates fail over, the answer names the class and served model, and
/// an error is general with a `ref` whose detail is on the audit row.
async fn chat_completions(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    headers: axum::http::HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    let started = Instant::now();
    const EP: &str = "/api/external/chat/completions";
    if !consumer.has_scope("chat") {
        return forbidden(&state, &consumer, EP, "chat", started);
    }
    let (_, actor) = super::inference::bind_identity(None, None, Some(&consumer), None, "external");
    match raw_chat::chat_completions(&state, &mut body, "external", actor, &raw_chat::pin_headers(&headers)).await {
        Ok(Outcome::Stream { resp, served, usage, guard }) => {
            // Usage isn't available without parsing the SSE stream — audit the
            // envelope with null units (documented behaviour).
            audit(&state, &consumer.name, EP, Some("chat"), Some(&served.model),
                  Some(&served.backend_type), None, 200, started, None);
            raw_chat::stream_response(*resp, &served, usage, guard)
        }
        Ok(Outcome::Json { data, served }) => {
            let units = data.get("usage").cloned();
            audit(&state, &consumer.name, EP, Some("chat"), Some(&served.model),
                  Some(&served.backend_type), units, 200, started, None);
            raw_chat::json_response(data, &served)
        }
        Err(e) => refuse(&state, &consumer.name, EP, Some("chat"), None, None, started, e),
    }
}

// ──────────────────────────── typed multiplexer ────────────────────────────

async fn typed_inference(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    Json(body): Json<Value>,
) -> Response {
    let started = Instant::now();
    const EP: &str = "/api/external/inference";
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let input = body.get("input").cloned().unwrap_or(Value::Null);

    match kind.as_str() {
        "embedding" => {
            if !consumer.has_scope("embeddings") {
                return forbidden(&state, &consumer, EP, "embeddings", started);
            }
            // For the typed path, `input` is `{ "input": ... }`.
            let inner = input.get("input").cloned().unwrap_or(Value::Null);
            let space = input.get("model").and_then(Value::as_str);
            match do_embeddings(&state, &inner, space).await {
                Ok((resp, n, model)) => {
                    audit(&state, &consumer.name, EP, Some("embedding"), Some(&model),
                          Some("tei"), Some(json!({"inputs": n})), 200, started, None);
                    (StatusCode::OK, Json(resp)).into_response()
                }
                Err(e) => refuse(&state, &consumer.name, EP, Some("embedding"), None, Some("tei"), started, e),
            }
        }
        "rerank" => {
            if !consumer.has_scope("rerank") {
                return forbidden(&state, &consumer, EP, "rerank", started);
            }
            let wanted = input.get("model").and_then(Value::as_str);
            match do_rerank(&state, &input, wanted).await {
                Ok((resp, n)) => {
                    let served = resp["noo"]["model"].as_str().unwrap_or("default").to_string();
                    audit(&state, &consumer.name, EP, Some("rerank"), Some(&served),
                          Some("reranker"), Some(json!({"documents": n})), 200, started, None);
                    (StatusCode::OK, Json(resp)).into_response()
                }
                Err(e) => refuse(&state, &consumer.name, EP, Some("rerank"), None, Some("reranker"), started, e),
            }
        }
        "classify" => {
            if !consumer.has_scope("classify") {
                return forbidden(&state, &consumer, EP, "classify", started);
            }
            match do_classify(&state, &input).await {
                Ok((resp, model)) => {
                    audit(&state, &consumer.name, EP, Some("classify"), Some(&model),
                          Some("chat-structured"), None, 200, started, None);
                    (StatusCode::OK, Json(resp)).into_response()
                }
                Err(e) => refuse(&state, &consumer.name, EP, Some("classify"), None, Some("chat-structured"), started, e),
            }
        }
        "chat" => {
            if !consumer.has_scope("chat") {
                return forbidden(&state, &consumer, EP, "chat", started);
            }
            let (_, actor) = super::inference::bind_identity(None, None, Some(&consumer), None, "external");
            match do_chat_nonstream(&state, &input, actor).await {
                Ok((data, units, served)) => {
                    audit(&state, &consumer.name, EP, Some("chat"), Some(&served.model),
                          Some(&served.backend_type), units, 200, started, None);
                    raw_chat::json_response(data, &served)
                }
                Err(e) => refuse(&state, &consumer.name, EP, Some("chat"), None, None, started, e),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"message": "unknown or missing 'kind' (chat|embedding|rerank|classify)", "type": "bad_request"}})),
        )
            .into_response(),
    }
}

/// Non-streaming chat for the typed multiplexer. `input` is the OpenAI chat
/// body (`{messages, model?, ...}`); `stream` is forced off. Same class
/// resolution and failover as the streaming route.
async fn do_chat_nonstream(
    state: &Arc<AppState>,
    input: &Value,
    actor: UsageActor,
) -> Result<(Value, Option<Value>, raw_chat::Served), ExtFail> {
    if !input.is_object() {
        return Err(bad_request("chat 'input' must be an object with 'messages'"));
    }
    let mut chat_body = input.clone();
    chat_body["stream"] = json!(false);
    // A `node` field in `input` pins the node, as on the streaming route.
    match raw_chat::chat_completions(state, &mut chat_body, "external", actor, &raw_chat::PinHeaders::default()).await? {
        Outcome::Json { data, served } => {
            let units = data.get("usage").cloned();
            Ok((data, units, served))
        }
        Outcome::Stream { .. } => Err(ExtFail::new(StatusCode::BAD_GATEWAY, "backend_error", "backend streamed a non-streaming request")),
    }
}

// ──────────────────────────── capabilities ────────────────────────────

async fn capabilities(State(state): State<Arc<AppState>>) -> Response {
    // Configured-availability (not a live health probe): chat depends on a
    // resolvable backend; embeddings are a core controller service; rerank is
    // on iff a mesh node advertises it; classify rides the chat backend.
    // The ids a consumer may send as `model`: every class and alias
    // (`coordinator::classes`), the same list `GET /api/external/models`
    // returns. Chat is available when some class has a routable candidate.
    let chat_ids: Vec<String> = match coordinator::classes::load_table(&state).await {
        Ok(t) if !t.classes.is_empty() => t.ids(),
        _ => Vec::new(),
    };
    let chat_ok = !chat_ids.is_empty() || coordinator::resolve_backend(&state).await.is_ok();
    let chat_models: Value = if chat_ids.is_empty() { json!(["default"]) } else { json!(chat_ids) };

    // `let emb_ok = true;` used to live here — a literal asserted into the
    // PUBLIC capabilities contract, so an external consumer was told
    // embeddings were available even with no embedder deployed at all. And
    // `emb_model` was read straight from TEI_MODEL, ignoring
    // PAGEINDEX_EMBEDDING_MODEL/URL, so it could name a model the configured
    // endpoint does not serve.
    //
    // Both now come from embedding_client::resolve() — the same resolution the
    // embedder itself uses — and availability is a reachability probe of that
    // endpoint's health URL, mirroring how voice_status probes its provider.
    let emb = crate::embedding_client::resolve();
    let emb_ok = crate::tls::cluster_client()
        .get(emb.health_url())
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    let emb_model = emb.model.clone();

    // `"dimension": 768` was a literal while the model name came from env — a
    // consumer pointed at a 1024-dim model would allocate wrong-width vectors
    // and only find out on insert. EMBEDDING_DIM (env → services.embedding_dim)
    // is the configured truth; embedding_client uses 0 as its "unknown / don't
    // check" sentinel, which becomes null here rather than a guess.
    let (emb_dimension, emb_dimension_detail) = if emb.dims > 0 {
        (json!(emb.dims), Value::Null)
    } else {
        (
            Value::Null,
            json!(
                "unknown — EMBEDDING_DIM (services.embedding_dim) is not \
                 configured, and the gateway does not probe the endpoint for \
                 its width here. Previously reported as a hardcoded 768."
            ),
        )
    };

    // rerank is available iff some alive mesh node advertises the capability.
    // (The co-located NOO_RERANK_URL path is gone — see `rerank_target`.)
    let rerank_ok = !state.gossip.find_peers_by_capability("rerank", 1).is_empty();
    let rerank_models: Value = if rerank_ok { json!(["default"]) } else { json!([]) };

    Json(json!({
        "chat": {
            "available": chat_ok,
            "openai_compatible": true,
            "models": chat_models
        },
        "embeddings": {
            "available": emb_ok,
            "available_detail": if emb_ok {
                json!(format!("{} responded to a health probe", emb.health_url()))
            } else {
                json!(format!("{} did not respond OK to a health probe", emb.health_url()))
            },
            "openai_compatible": true,
            "models": ["default", emb_model],
            "dimension": emb_dimension,
            "dimension_detail": emb_dimension_detail,
            // i145: what a consumer may send as `model` — a space name (or its
            // model's name). Vectors from different spaces never mix.
            "spaces": crate::embedding_spaces::all()
        },
        "rerank": {
            "available": rerank_ok,
            "models": rerank_models
        },
        "classify": {
            "available": chat_ok,
            "models": chat_models,
            "method": "chat-structured"
        }
    }))
    .into_response()
}

// ──────────────────────────── usage ────────────────────────────

/// One `GET /api/external/usage` row as the CONSUMER sees it. The audit
/// row's `error` column holds the operator detail (`refuse` writes the
/// node, address and upstream body there) and is deliberately NOT a field
/// here — it was, which handed every refused request's topology back to
/// the same service key. A consumer gets the status and the `ref` the
/// error body carried; the operator reads the detail by that ref.
#[allow(clippy::too_many_arguments)]
fn usage_row_json(
    ts: chrono::DateTime<chrono::Utc>,
    endpoint: &str,
    kind: Option<String>,
    model: Option<String>,
    backend: Option<String>,
    units: Option<Value>,
    status: i32,
    latency: Option<i32>,
    trace_id: Option<String>,
) -> Value {
    json!({
        "ts": ts.to_rfc3339(),
        "endpoint": endpoint,
        "kind": kind,
        "model": model,
        "backend": backend,
        "units": units,
        "status_code": status,
        "latency_ms": latency,
        "ref": trace_id,
    })
}

#[derive(Deserialize)]
struct UsageQuery {
    limit: Option<i64>,
}

/// A consumer's own recent audit/usage rows. This is the "do we see external
/// requests" view — distinct from `/api/jobs` (Redis background tasks).
async fn usage(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    Query(params): Query<UsageQuery>,
) -> Response {
    let limit = params.limit.unwrap_or(100).clamp(1, 1000);

    let rows = sqlx::query_as::<
        _,
        (
            chrono::DateTime<chrono::Utc>,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<Value>,
            i32,
            Option<i32>,
            Option<String>,
        ),
    >(
        "SELECT ts, endpoint, kind, model, backend, units, status_code, latency_ms, trace_id \
         FROM noo_external_requests WHERE consumer = $1 ORDER BY ts DESC LIMIT $2",
    )
    .bind(&consumer.name)
    .bind(limit)
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(rows) => {
            let items: Vec<Value> = rows
                .into_iter()
                .map(|(ts, endpoint, kind, model, backend, units, status, latency, trace_id)| {
                    usage_row_json(ts, &endpoint, kind, model, backend, units, status, latency, trace_id)
                })
                .collect();
            Json(json!({"consumer": consumer.name, "count": items.len(), "requests": items}))
                .into_response()
        }
        Err(e) => ExtFail::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", format!("usage query failed: {e}")).into_response("/api/external/usage"),
    }
}

#[cfg(test)]
mod response_guard_tests {
    /// Phase 0 guard: the external error constructors. Every
    /// `error` body built in this file and in the `/v1` handlers is either a
    /// fixed literal (the scope refusal, the unknown-kind 400, the catalogue
    /// 503/404) or goes through `RawChatError` — nothing interpolates an
    /// upstream error (`{e}`), an upstream body (`{text}`) or a URL into a
    /// body. The literal patterns that leaked on `origin/dev` are named so
    /// their return is a test failure, not a code-review catch.
    #[test]
    fn external_error_constructors_interpolate_nothing_from_upstream() {
        // This module's own literals are not constructors: scan up to it.
        let external = include_str!("external.rs").split("mod response_guard_tests").next().unwrap();
        // inference.rs also hosts the internal `/api/inference*` routes, whose
        // operator-facing bodies carry the detail on purpose: scan its `/v1`
        // handlers only (the catalogue through the model detail).
        let inference_all = include_str!("inference.rs");
        let v1_start = inference_all.find("async fn openai_models(").expect("openai_models");
        let v1_end = inference_all.find("// Inference streaming — native Rust SSE").expect("streaming section");
        let inference = &inference_all[v1_start..v1_end];
        for (file, src) in [("external.rs", external), ("inference.rs", inference)] {
            // The exact shapes that leaked before.
            for leaky in [
                "\"backend unreachable: {e}\"",
                "\"backend {status}: {text}\"",
                "\"no inference backend available: {e}\"",
                "\"no inference backend: {e}\"",
                "\"classify backend unreachable: {e}\"",
                "err_json(",
            ] {
                let in_code = src.lines().filter(|l| !l.trim_start().starts_with("//")).any(|l| l.contains(leaky));
                assert!(!in_code, "{file} still builds an external error with {leaky}");
            }
            // Every `error` body literal is static text, never an interpolation.
            let bodies: Vec<&str> = src.lines().filter(|l| l.contains("json!({\"error\"") && !l.trim_start().starts_with("//")).collect();
            assert!(!bodies.is_empty(), "{file}: the scan found no error bodies — the pattern it looks for has moved");
            for line in bodies {
                let interpolates = line.contains("{e}") || line.contains("{text}") || line.contains("{status}") || line.contains("{url}") || line.contains("{msg}");
                assert!(!interpolates, "{file} interpolates upstream text into an error body: {line}");
            }
        }
        // And the shared constructor is what the handlers use.
        assert!(!external.contains("\"error\": error,"), "the usage projection must not return the audit error column");
        assert!(external.contains("fn refuse("), "external.rs lost its one error exit");
        let refusals = external.matches("=> refuse(").count();
        assert!(refusals >= 7, "every handler's error arm goes through refuse(): found {refusals}");
    }
}

#[cfg(test)]
mod usage_projection_tests {
    use super::usage_row_json;

    /// After a refused request the usage view carries the status and the
    /// ref, never the operator detail the audit row holds.
    #[test]
    fn a_refused_request_shows_status_and_ref_and_no_detail() {
        // The row `refuse` would have written for a failed candidate.
        let detail = "every candidate of class 'chat-default' failed (2 tried; last: unreachable: https://100.64.0.10:8081 connection refused; host3, host6)";
        assert!(detail.contains("100.64") && detail.contains("host3"));
        let v = usage_row_json(chrono::Utc::now(), "/api/external/chat/completions", Some("chat".into()), None, None, None, 502, Some(12), Some("ref-3f9c2b1e0a".into()));
        let text = serde_json::to_string(&v).unwrap();
        for forbidden in [":8081", "100.", "172.", "https://", "host3", "host6", "connection refused"] {
            assert!(!text.contains(forbidden), "usage leaks {forbidden}: {text}");
        }
        assert_eq!(v["status_code"], 502);
        assert_eq!(v["ref"], "ref-3f9c2b1e0a");
        assert!(v.get("error").is_none(), "no error field at all: {text}");
        // The projection has no parameter through which the detail could arrive.
        let src = include_str!("external.rs");
        let sig = src.split("fn usage_row_json(").nth(1).unwrap().split(") -> Value").next().unwrap();
        assert!(!sig.contains("error"), "{sig}");
    }
}

#[cfg(test)]
mod rerank_preference_tests {
    use super::{rerank_noo, rerank_order};

    /// i145 phase C: a named rerank model is a preference. Its nodes go
    /// first, every other reranker follows as a flagged stand-in.
    #[test]
    fn a_rerank_model_is_tried_first_and_the_rest_stand_in() {
        let c = |n: &str, m: Option<&str>| (n.to_string(), m.map(str::to_string));
        let cands = vec![c("gpu-1", Some("bge-reranker-base")), c("mac", Some("qwen3-reranker")), c("old", None)];
        let o = rerank_order(cands.clone(), Some("qwen3-reranker"));
        let order: Vec<(&str, bool)> = o.iter().map(|(n, _, s)| (n.as_str(), *s)).collect();
        assert_eq!(order, [("mac", false), ("gpu-1", true), ("old", true)]);
        let o = rerank_order(cands, None);
        assert!(o.iter().all(|(_, _, s)| !s), "no request: mesh order, nobody a stand-in");
        assert_eq!(o[0].0, "gpu-1");
        let n = rerank_noo("llm", None, Some("qwen3-reranker"), true);
        assert_eq!((n["served_by"].as_str(), n["model"].as_str(), n["fallback"].as_bool()), (Some("llm"), Some("llm"), Some(true)));
        assert_eq!(n["requested_model"], "qwen3-reranker");
        assert!(rerank_noo("gpu-1", Some("bge"), None, false).get("requested_model").is_none());
    }
}
