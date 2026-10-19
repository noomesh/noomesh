// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Inference routes — native Rust coordinator + LLM health probes.
//!
//! Native Rust:
//!   - POST /api/inference — full agentic loop via coordinator::run_with_thinking(…, false)
//!   - POST /api/inference/stream — SSE streaming via coordinator (ported 2026-03-31)
//!   - GET /v1/models/{model_id} — OpenAI compat model detail (ported 2026-03-31)
//!   - Backend health probes (vLLM, Ollama, llama.cpp — HTTP proxies)
//!
//!   - POST /api/tasks/inference — queue an inference job (ported 2026-08-08;
//!     the Python handler was a one-line submit into the Python scheduler,
//!     which shares the Redis job structures Rust already writes)

use std::sync::Arc;
use axum::{
    Router, Json,
    routing::{get, post},
    extract::{State, Path, Extension},
    response::IntoResponse,
    http::StatusCode,
    body::Body,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::coordinator;
use crate::service_keys::Consumer;
use crate::state::AppState;
use crate::usage::UsageActor;

/// 403 for the `/v1/*` surface when a named service key lacks the required
/// scope. Mirrors the error shape `routes::external::forbidden` returns
/// (`{"error": {"message": "...", "type": "forbidden"}}`, HTTP 403) so both
/// inference surfaces speak the same contract. The `/v1/*` handlers omit the
/// `noo_external_requests` audit row external.rs writes — this surface has no
/// audit plumbing — but the scope enforcement is identical.
///
/// Internal callers (JWT subject / cluster HMAC / legacy env key / dev
/// bypass) resolve to `Consumer::all`, whose scope set already contains
/// "chat"/"embeddings"/"rerank"/"classify", so `has_scope` returns true for
/// them and this is never hit. Only narrowly-scoped named service keys can.
fn forbidden_v1(scope: &str) -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": {
            "message": format!("service key lacks '{scope}' scope"),
            "type": "forbidden"
        }})),
    )
        .into_response()
}

/// The 403 a closed cloud gate gets on the non-streaming route; `None` for any
/// other failure. Finds the typed refusal even under added `.context(..)`.
fn cloud_gate_response(e: &anyhow::Error) -> Option<axum::response::Response> {
    let r = coordinator::cloud_gate_refusal(e)?;
    let mut body = coordinator::cloud_gate_body(r.0);
    body["success"] = json!(false);
    Some((StatusCode::FORBIDDEN, Json(body)).into_response())
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Backend health probes (proxy to actual backends — native Rust).
        // `/v1/models` is a read/listing endpoint (OpenAI model discovery); it
        // carries no inference payload and the analogous external surface
        // (`/api/external/capabilities`) is also unscoped, so it is left
        // unguarded — any authenticated caller may list models.
        .route("/v1/models", get(openai_models))
        .route("/api/tags", get(proxy_ollama_health))
        .route("/api/version", get(proxy_ollama_version))
        // Inference: native Rust coordinator (resolves backend, injects context via NATS, calls LLM)
        .route("/api/inference", post(native_inference))
        // Streaming: Native Rust SSE (ported from NATS delegation 2026-03-31)
        .route("/api/inference/stream", post(native_inference_stream))
        .route("/api/tasks/inference", post(submit_inference_task))
        // POST /chat REMOVED. It delegated to worker.chat, whose handler
        // resolves a coordinator from services.coordinator (never assigned)
        // and falls back to gateway/coordinator.py (deleted in the Rust port).
        // Probed live before removal:
        //   POST /chat -> 400 {"error":"Coordinator not initialized"}
        // The working chat surfaces are /api/inference, /api/inference/stream
        // and the /ws/coordinator websocket.
        // Anthropic compatibility shim — chat-type generation, requires "chat".
        // Scope-guarded native wrapper around the NATS delegation (the generic
        // delegate_post closure can't carry a Consumer scope check).
        // Model detail: Native Rust (ported from NATS delegation 2026-03-31).
        // Read/listing endpoint — unscoped, same rationale as `/v1/models`.
        .route("/v1/models/{model_id}", get(compat_model_detail))
        // Native Rust proxy (was delegate_post to a Python handler that never
        // existed → import error). Pure OpenAI passthrough, no ML, so it
        // belongs in Rust per the runtime split.
        .route("/v1/chat/completions", post(openai_chat_completions))
        // Responses API: same auth lane and resolver.
        .route("/v1/responses", post(v1_responses))
}

crate::ported! {
    POST "/api/tasks/inference" => "worker.inference.task",
}

/// POST /api/tasks/inference — queue an inference job for a worker node.
///
/// Native port of `worker.inference.task` (reference implementation kept
/// unregistered in `noomesh/workers/inference.py::_inference_task`). The
/// Python handler was `scheduler.submit_job("inference", request, priority)`;
/// the Rust job queue writes the same Redis structures via
/// `submit_job_to_redis`, so this is the same submit without the NATS hop.
/// Response shape preserved: `{"job_id": ..., "status": "queued"}`.
async fn submit_inference_task(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<crate::auth::AuthActor>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let Some(redis) = state.redis.as_ref() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Redis not connected"})),
        );
    };
    // Python passed the WHOLE request dict as the job payload (priority
    // field included) — preserved so node-agent consumers see the same
    // payload shape.
    let priority = body.get("priority").and_then(|p| p.as_i64()).unwrap_or(5);
    let owner = actor.as_ref().map(|Extension(a)| crate::auth::account_of(a.0.as_str())).unwrap_or("");
    let opts = super::admin::JobOptions { owner, ..Default::default() };
    match super::admin::submit_job_to_redis(redis, "inference", &body, priority, opts).await {
        Some(job_id) => (
            StatusCode::OK,
            Json(json!({"job_id": job_id, "status": "queued"})),
        ),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to submit inference task to Redis"})),
        ),
    }
}

/// Request body for POST /api/inference.
#[derive(Debug, Deserialize)]
struct InferenceRequest {
    /// The user's prompt/message.
    prompt: String,
    /// Optional conversation ID for session continuity.
    #[serde(default)]
    conversation_id: Option<String>,
    /// Channel source (api, dashboard, telegram, etc.)
    #[serde(default = "default_channel")]
    channel: String,
    /// Maximum agentic iterations.
    #[serde(default)]
    max_iterations: Option<u32>,
    /// Optional model override (e.g. "claude-3-opus", "gpt-4").
    /// Cloud models are delegated to Python's cloud provider manager via NATS.
    #[serde(default)]
    model: Option<String>,
    /// If true, the caller should use POST /api/inference/stream instead.
    /// This field is kept for backward compatibility; the /api/inference
    /// endpoint returns a redirect hint when stream=true is set.
    #[serde(default)]
    stream: Option<bool>,
    /// Optional user ID for user-specific model preferences.
    #[serde(default)]
    user_id: Option<String>,
    /// The node to try first (a preference: the pool answers when it
    /// cannot, flagged `fallback`). `noo inference run --node <id>`.
    #[serde(default)]
    node: Option<String>,
    /// Keep the request on `node` alone (no fallback into the pool), for
    /// locality or privacy; `X-Noo-Node-Strict` does the same.
    #[serde(default)]
    node_strict: Option<bool>,
    /// `false` = raw model call: no coordinator, no context
    /// layers, no conversation row — the prompt is the only message, sent
    /// through the same resolver/proxy/accounting as `/v1/chat/completions`.
    /// Default true (the coordinator path).
    #[serde(default)]
    context: Option<bool>,
    /// Sampling controls, honoured on the raw path (`context: false`).
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    temperature: Option<f64>,
}

fn default_channel() -> String { "api".to_string() }

/// Who is asking, and who the call is charged to.
///
/// Three kinds of caller reach the chat surfaces, and each answers "which
/// user" differently:
///
/// - a **JWT** caller (dashboard, CLI login, an MCP user-door key, an MCP
///   operator key bound to an admin) IS the subject; a body `user_id` that
///   disagrees is ignored and logged, as `effective_user_id` always did.
/// - a **cluster** caller: only the controller's own services
///   (`ClusterKind::Internal`) may delegate a body `user_id`, because the
///   in-process channel adapters and workers submit on behalf of an
///   already-resolved person. A **node** token may not — a node is not a
///   person and has no business naming one (P12's "user_id in body accepted
///   as delegation" was this, from any cluster token).
/// - a **service key** on the inference surface: a BOUND key is its user; an
///   unbound machine key is its consumer and nobody else — it cannot
///   delegate either.
///
/// Returns `(effective user for scoping, actor for accounting)`.
pub(crate) fn bind_identity(
    jwt_subject: Option<&str>,
    cluster: Option<&crate::auth::ClusterNode>,
    consumer: Option<&Consumer>,
    claimed_user_id: Option<&str>,
    via: &'static str,
) -> (Option<String>, UsageActor) {
    let claims_someone = claimed_user_id.map(str::trim).is_some_and(|v| !v.is_empty());
    if let Some(sub) = jwt_subject.map(str::trim).filter(|s| !s.is_empty()) {
        let uid = crate::auth::effective_user_id(Some(sub), claimed_user_id);
        return (uid.clone(), UsageActor { username: uid, consumer: Some(via.into()) });
    }
    if let Some(crate::auth::ClusterNode(actor, kind)) = cluster {
        return match kind {
            crate::auth::ClusterKind::Internal => {
                let uid = crate::auth::effective_user_id(None, claimed_user_id);
                (uid.clone(), UsageActor { username: uid, consumer: Some(actor.clone()) })
            }
            crate::auth::ClusterKind::Node => {
                if claims_someone {
                    tracing::warn!(node = %actor, "ignoring user_id delegation from a node token");
                }
                (None, UsageActor::consumer(format!("node:{actor}")))
            }
        };
    }
    if let Some(c) = consumer {
        return match &c.user {
            Some(u) => {
                if claims_someone && claimed_user_id.map(str::trim) != Some(u.as_str()) {
                    tracing::warn!(consumer = %c.name, user = %u, "ignoring user_id that does not match the key's bound user");
                }
                (Some(u.clone()), UsageActor { username: Some(u.clone()), consumer: Some(c.name.clone()) })
            }
            None => {
                if claims_someone {
                    tracing::warn!(consumer = %c.name, "ignoring user_id delegation from an unbound service key");
                }
                (None, UsageActor::consumer(c.name.clone()))
            }
        };
    }
    // No credential of any kind reached the handler. Unreachable: there is
    // ONE listener, every inference route sits behind `require_any_auth`
    // (`inference_routes_are_behind_the_auth_gate` pins it), and the
    // "legacy unauthenticated deployment" this arm once served no longer
    // exists. So it grants nothing: a body `user_id` is never honoured
    // without a credential that may delegate.
    if claims_someone {
        tracing::error!(via, "inference reached with NO credential — refusing the body's user_id");
    }
    (None, UsageActor::consumer(format!("unauthenticated:{via}")))
}

/// POST /api/inference — native Rust coordinator.
///
/// Runs the full agentic loop:
///   1. Resolve backend (gossip → mesh → KV)
///   2. Inject RAG + memory context via NATS workers
///   3. Call LLM with tool schemas
///   4. Execute tools, loop until final answer
///   5. Persist conversation to Postgres
async fn native_inference(
    State(state): State<Arc<AppState>>,
    // Present only for JWT-authenticated (user) callers; absent for trusted
    // internal callers (cluster-HMAC / service key), who may delegate a user_id.
    actor: Option<Extension<crate::auth::AuthActor>>,
    cluster: Option<Extension<crate::auth::ClusterNode>>,
    consumer: Option<Extension<Consumer>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<InferenceRequest>,
) -> impl IntoResponse {
    let conversation_id = req.conversation_id
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let max_iterations = req.max_iterations
        .unwrap_or(state.config.coordinator.max_iterations);

    tracing::info!(
        conversation_id = %conversation_id,
        channel = %req.channel,
        prompt_len = req.prompt.len(),
        model = ?req.model,
        "native_inference_start"
    );

    // If stream=true is requested, redirect to the streaming endpoint.
    // POST /api/inference/stream handles true SSE streaming natively.
    if req.stream.unwrap_or(false) {
        tracing::info!("stream=true requested, use POST /api/inference/stream for SSE streaming");
        return (StatusCode::OK, Json(json!({
            "success": false,
            "error": "Use POST /api/inference/stream for SSE streaming",
            "redirect": "/api/inference/stream",
        }))).into_response();
    }

    // Node-pinned path: bypass coordinator + cache, proxy directly to a backend
    // on the named node. Used for `noo inference run --node <id>`.
    //
    // A node is a PREFERENCE (operator, 2026-10-19): when it cannot answer,
    // the request goes to the pool on the raw path below (context-free,
    // like the pin) and the answer carries `fallback: true` and the node
    // that was asked for. `node_strict` / `X-Noo-Node-Strict` keeps it on
    // that node — locality or privacy — with the refusals below. A name
    // that is no node of this mesh is a 404 either way.
    //
    // Leniency: small local models routinely put the node id in `model`
    // ("model": "host9") even when the tool schema says `node`. A model
    // string that exactly matches a live node id is unambiguous — real
    // model names look like "org/name" or "*.gguf" — so treat it as a pin.
    // `X-Noo-Node` is the same pin as the body's `node` (the header wins),
    // as on `/v1/chat/completions` and `/api/external/chat/completions`.
    let pin = super::raw_chat::pin_headers(&headers);
    let strict = pin.strict.or(req.node_strict).unwrap_or(false);
    let mut node_pin = pin.node.clone().or_else(|| req.node.clone());
    let mut node_from_model = false;
    if node_pin.is_none() {
        if let Some(m) = req.model.as_deref() {
            if node_chat_backend(&state, m).await.is_node() {
                tracing::info!(node = %m, "model_field_matched_node_id_treating_as_pin");
                node_pin = Some(m.to_string());
                node_from_model = true;
            }
        }
    }
    // The preferred node could not answer and the pin is not strict:
    // (node, why). The pool answers on the raw path below.
    let mut unmet: Option<(String, String)> = None;
    if let Some(node_id) = node_pin.as_deref() {
        // Resolve the node's inference backend INCLUDING the controller (self).
        // gossip.alive_peers() excludes self, so `--node HOST3` (the controller)
        // used to 404 even though it runs vllm/embedding locally.
        // node_chat_backend() reads the mesh_nodes KV (every node).
        match node_chat_backend(&state, node_id).await {
            NodeChat::Unknown => return (StatusCode::NOT_FOUND, Json(json!({
                "success": false,
                "error": format!("node '{}' not found or has no inference backend", node_id),
            }))).into_response(),
            // Refused BEFORE dispatch: the node is there, it just serves no chat.
            NodeChat::NoChat(msg) if strict => return (NO_CHAT_STATUS, Json(json!({
                "success": false,
                "error": msg,
                "code": "node_serves_no_chat",
                "node": node_id,
            }))).into_response(),
            NodeChat::NoChat(msg) => unmet = Some((node_id.to_string(), msg)),
            NodeChat::Serves(backend_type, model_name, base_url) => {
                // When the pin came from the model field, that value is a node id,
                // not a model — use the backend's actual model name.
                let model = if node_from_model { model_name } else { req.model.clone().unwrap_or(model_name) };

                let started = std::time::Instant::now();
                match chat_completion_on_node(&backend_type, &model, &base_url, &req.prompt).await {
                    Ok(text) => return (StatusCode::OK, Json(json!({
                        "success": true,
                        "data": {
                            "response": text,
                            "node": node_id,
                            "backend": backend_type,
                            "model": model,
                            "latency_ms": started.elapsed().as_millis(),
                            "engine": "rust",
                            "pinned": true,
                            "fallback": false,
                        },
                    }))).into_response(),
                    Err(e) if strict && backend_cannot_chat(&e) => return (NO_CHAT_STATUS, Json(json!({
                        "success": false,
                        "error": no_chat_refusal(node_id, &[(backend_type.clone(), model.clone())], &[]),
                        "code": "node_serves_no_chat",
                        "node": node_id,
                        "backend": backend_type,
                        "detail": e,
                    }))).into_response(),
                    Err(e) if strict => return (StatusCode::BAD_GATEWAY, Json(json!({
                        "success": false,
                        "error": e,
                        "node": node_id,
                        "backend": backend_type,
                    }))).into_response(),
                    Err(e) => {
                        if !backend_cannot_chat(&e) {
                            // Rank it last for the pool too, as a stalled
                            // raw-chat candidate is.
                            crate::coordinator::classes::note_stall(&base_url, &backend_type);
                        }
                        unmet = Some((node_id.to_string(), e));
                    }
                }
            }
        }
        if let Some((n, why)) = &unmet {
            tracing::warn!(node = %n, reason = %why, "inference_node_preference_unmet_pool_answers");
        }
    }
    if unmet.is_some() || req.context == Some(false) {
        // Raw model call as this user. Auth lane is the
        // route's own (a user-door JWT opens it); the `chat` consumer scope
        // gates the `/v1/*` surface, not this one.
        let actor_sub = actor.as_ref().map(|Extension(a)| a.0.as_str());
        let (_, usage_actor) = bind_identity(
            actor_sub,
            cluster.as_ref().map(|Extension(c)| c),
            consumer.as_ref().map(|Extension(c)| c),
            req.user_id.as_deref(),
            "api",
        );
        let mut body = json!({
            // A node id sent as `model` is not a model.
            "model": if node_from_model { String::new() } else { req.model.clone().unwrap_or_default() },
            "messages": [{"role": "user", "content": req.prompt}],
        });
        if let Some(m) = req.max_tokens { body["max_tokens"] = json!(m); }
        if let Some(t) = req.temperature { body["temperature"] = json!(t); }
        let started = std::time::Instant::now();
        // Same class resolution and failover as `/v1/chat/completions`. This
        // is an operator surface (a user-door JWT opens it), so the error
        // carries the detail, not the general wording.
        // A node pin reaches here only when the node could not answer and
        // was not strict (`unmet`): the pool answers and says so.
        match super::raw_chat::chat_completions(&state, &mut body, "api", usage_actor, &super::raw_chat::PinHeaders::default()).await {
            Ok(super::raw_chat::Outcome::Json { data, served }) => {
                let text = data.pointer("/choices/0/message/content").and_then(Value::as_str).unwrap_or("");
                let (p, c) = crate::usage::usage_from_frame(&data).unwrap_or((0, 0));
                let mut out = json!({
                    "response": text,
                    "conversation_id": null,
                    "model": served.model,
                    "backend": served.backend_type,
                    "class": served.class,
                    "fallback": served.fallback,
                    "elapsed_seconds": (started.elapsed().as_secs_f64() * 10.0).round() / 10.0,
                    "usage": {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c},
                    "context": false,
                    "engine": "rust",
                });
                if let Some((n, why)) = &unmet {
                    out["fallback"] = json!(true);
                    out["requested_node"] = json!(n);
                    out["node_unavailable"] = json!(why);
                }
                (StatusCode::OK, Json(json!({"success": true, "data": out}))).into_response()
            }
            Ok(super::raw_chat::Outcome::Stream { .. }) => (StatusCode::BAD_REQUEST, Json(json!({
                "success": false, "error": "stream is not supported on this route; use POST /api/inference/stream",
            }))).into_response(),
            Err(e) => {
                e.log("api");
                (e.status, Json(json!({"success": false, "error": e.detail, "ref": e.reference}))).into_response()
            }
        }
    } else {

    // Bind the identity: a JWT-authenticated user's subject wins over any
    // body-supplied user_id; a trusted internal caller may delegate one.
    let actor_sub = actor.as_ref().map(|Extension(a)| a.0.as_str());
    let (effective_uid, usage_actor) = bind_identity(
        actor_sub,
        cluster.as_ref().map(|Extension(c)| c),
        consumer.as_ref().map(|Extension(c)| c),
        req.user_id.as_deref(),
        "api",
    );

    // Check LLM cache first — keyed by WHO asked as well as what: the answer is built from the caller's own memory and
    // audience-filtered KB evidence, so it is not shareable across people.
    let messages_for_cache = vec![json!({"role": "user", "content": req.prompt})];
    let cache_key = crate::cache::RedisCache::llm_cache_key(
        "auto", &messages_for_cache, effective_uid.as_deref());

    if let Some(redis) = state.redis.as_ref() {
        if let Some(cached) = redis.get_llm_cache(&cache_key).await {
            tracing::debug!("inference_cache_hit");
            return (StatusCode::OK, Json(json!({
                "success": true,
                "data": {
                    "response": cached.get("content").and_then(|c| c.as_str()).unwrap_or(""),
                    "conversation_id": conversation_id,
                    "cached": true,
                    "engine": "rust",
                },
            }))).into_response();
        }
    }

    // Run the agentic loop (with optional model for cloud delegation).
    // Non-streaming: the caller gets one final string, and there is no
    // thinking panel for reasoning to go to — on gemma-4 it came back inline
    // as a bare `thought` prefix (the MCP door's agentic tool, 2026-09-27).
    match coordinator::run_with_thinking(
        &state,
        &req.prompt,
        &conversation_id,
        &req.channel,
        max_iterations,
        req.model.as_deref(),
        effective_uid.as_deref(),
        false,
    ).await {
        Ok(result) => {
            // Cache the response
            if !result.response.is_empty() {
                if let Some(redis) = state.redis.as_ref() {
                    redis.set_llm_cache(
                        &cache_key,
                        &json!({"content": result.response}),
                        None,
                    ).await;
                }
            }

            // Token-usage accounting — fire-and-forget.
            crate::usage::record(
                state.db.clone(),
                result.node.clone(),
                result.backend.clone(),
                result.model.clone(),
                "api",
                usage_actor,
                result.usage.prompt_tokens,
                result.usage.completion_tokens,
            );

            (StatusCode::OK, Json(json!({
                "success": true,
                "data": {
                    "response": result.response,
                    "conversation_id": conversation_id,
                    "model": result.model,
                    "backend": result.backend,
                    "iterations": result.iterations,
                    "tool_calls": result.tool_calls,
                    "elapsed_seconds": (result.elapsed_secs * 10.0).round() / 10.0,
                    "usage": {
                        "prompt_tokens": result.usage.prompt_tokens,
                        "completion_tokens": result.usage.completion_tokens,
                        "total_tokens": result.usage.total_tokens,
                    },
                    "engine": "rust",
                },
            }))).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "native_inference_failed");
            // Policy refusal (cloud gate closed): 403 with the typed body, not a
            // retryable 500.
            if let Some(resp) = cloud_gate_response(&e) {
                return resp;
            }
            let status = StatusCode::from_u16(coordinator::resolve_failure_status(&e, 500)).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(json!({
                "success": false,
                "error": format!("{e}"),
            }))).into_response()
        }
    }
    }  // end of `else` (non-node-pinned) branch
}

/// GET /v1/models (and `/api/external/models`) — the catalogue of ids a
/// consumer may send as `model`: every model CLASS and ALIAS
/// (`coordinator::classes`), `owned_by: "noomesh"`, with the class's
/// candidate and healthy counts under `noo`. Concrete per-node names stay on
/// `/api/cluster/backends`; nothing here names a node, an address or a URL.
///
/// Still the dashboard's chat-readiness probe (200 = serving, 503 = not
/// yet), so the status is earned the way it always was: the first routable
/// `chat-default` candidate must answer its own `GET /v1/models`. A vLLM that
/// is up but still loading weights answers that with 502/503, and the
/// dashboard shows "loading" instead of letting a send fail. With no class
/// at all (the KV is empty) the legacy resolver's static last resort is
/// probed, as before.
pub(crate) async fn openai_models(State(state): State<Arc<AppState>>) -> axum::response::Response {
    let table = match crate::coordinator::classes::load_table(&state).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "models_catalogue_unavailable");
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"object": "list", "data": [], "error": {"message": "model catalogue unavailable", "type": "server_error"}}))).into_response();
        }
    };
    let probe_url = crate::coordinator::classes::resolve_hint(&table, None)
        .and_then(|c| crate::coordinator::classes::ordered(c, &[]).first().map(|c| (c.url.clone(), c.backend.clone())));
    let (probe_url, backend_type) = match probe_url {
        Some(p) => p,
        None => match crate::coordinator::resolve_backend(&state).await {
            Ok(b) if !b.url.is_empty() => (b.url, b.backend_type),
            _ => {
                return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
                    "object": "list", "data": crate::coordinator::classes::catalogue(&table),
                    "error": {"message": "no inference backend is available right now", "type": "backend_unavailable"},
                }))).into_response();
            }
        },
    };
    let url = format!("{}/v1/models", probe_url.trim_end_matches('/'));
    let req = crate::coordinator::with_backend_hint_url(
        crate::tls::cluster_client().get(&url).timeout(std::time::Duration::from_secs(5)),
        &url, &backend_type,
    );
    let ready = match req.send().await {
        Ok(resp) => {
            crate::coordinator::warn_if_node_agent_outdated(resp.status(), &url);
            resp.status().is_success()
        }
        Err(e) => {
            tracing::warn!(backend = %backend_type, url = %url, error = %e, "models_probe_unreachable");
            false
        }
    };
    let data = crate::coordinator::classes::catalogue(&table);
    if ready {
        (StatusCode::OK, Json(json!({"object": "list", "data": data}))).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
            "object": "list", "data": data,
            "error": {"message": "the inference backend is not serving yet", "type": "backend_unavailable"},
        }))).into_response()
    }
}

/// Proxy /api/tags to Ollama backend (health check)
async fn proxy_ollama_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    proxy_backend_health(&state, "ollama", "/api/tags").await
}

/// Proxy /api/version to Ollama backend
async fn proxy_ollama_version(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    proxy_backend_health(&state, "ollama", "/api/version").await
}

/// Single-turn chat completion against a specific node's backend.
///
/// Extracted from the node-pinned branch of `native_inference` so the native
/// `noo_inference` tool executor (`tools::execute_native`) can honour the
/// tool's `node` argument through the same code path instead of a second
/// implementation. Returns the response text, or an error string that keeps
/// the route's historical wording ("backend returned N: ..." /
/// "backend unreachable: ...").
pub(crate) async fn chat_completion_on_node(
    backend_type: &str,
    model: &str,
    base_url: &str,
    prompt: &str,
) -> Result<String, String> {
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
    let body = json!({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 256,
        "temperature": 0.7,
    });

    let client = crate::tls::cluster_client();

    // Add X-Noo-Backend hint for node-agent proxy URLs.
    // 240s: edge nodes are slow — host9 (gemma-4-E2B on a Pi) needs
    // ~40s for even one-word replies, so 60s failed any real prompt
    // with a misleading "backend unreachable" (reqwest timeout).
    let req = crate::coordinator::with_backend_hint_url(
        client.post(&url).json(&body).timeout(std::time::Duration::from_secs(240)),
        &url, backend_type,
    );
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let data: Value = resp.json().await.unwrap_or(json!({}));
            Ok(data.pointer("/choices/0/message/content")
                .and_then(|v| v.as_str()).unwrap_or("").to_string())
        }
        Ok(resp) => {
            let status = resp.status();
            crate::coordinator::warn_if_node_agent_outdated(status, &url);
            let body = resp.text().await.unwrap_or_default();
            Err(format!("backend returned {}: {}", status, body))
        }
        Err(e) => Err(format!("backend unreachable: {}", e)),
    }
}

/// What a pinned chat can get from a named node.
#[derive(Debug, PartialEq)]
pub(crate) enum NodeChat {
    /// `(backend_type, model, node_agent_base_url)` — a backend that may serve chat.
    Serves(String, String, String),
    /// The node is in the mesh with running backends, but every one is
    /// placed for a non-chat role (an embedder, a reranker). Dispatching
    /// anyway was the raw 502 `"harrier" does not support chat` (i69a).
    /// Carries the refusal, already worded.
    NoChat(String),
    /// No such node, or it runs no inference backend at all.
    Unknown,
}

impl NodeChat {
    /// Whether `node_id` named a node at all — for the `model: "<node-id>"`
    /// leniency, where an embed-only node is still a pin (and is refused).
    pub(crate) fn is_node(&self) -> bool {
        !matches!(self, NodeChat::Unknown)
    }
}

/// HTTP status for a pin to a node that serves no chat. The request is
/// wrong, not the backend: 4xx, never the 502 it used to be.
pub(crate) const NO_CHAT_STATUS: StatusCode = StatusCode::UNPROCESSABLE_ENTITY;

/// The node's first chat-capable backend (vllm > ollama > llamacpp), or the
/// `(backend, model)` pairs it runs when none may serve chat. Pure: the
/// caller supplies the node's `running_backends` and the declared non-chat
/// `(node, backend)` set (`coordinator::non_chat_backends`, the one the
/// resolver already skips with `backend_skipped_non_chat_role`).
pub(crate) fn pick_chat_backend(
    node_id: &str,
    running: &serde_json::Map<String, Value>,
    non_chat: &std::collections::HashSet<(String, String)>,
) -> Result<(String, String), Vec<(String, String)>> {
    let mut skipped = Vec::new();
    for bt in ["vllm", "ollama", "llamacpp"] {
        let Some(m) = running.get(bt).and_then(|m| m.as_str()).filter(|m| !m.is_empty()) else { continue };
        if non_chat.contains(&(node_id.to_string(), bt.to_string())) || crate::coordinator::classes::is_embedding_model_name(m) {
            skipped.push((bt.to_string(), m.to_string()));
            continue;
        }
        return Ok((bt.to_string(), m.to_string()));
    }
    Err(skipped)
}

/// The refusal for a chat pinned to a node that serves no chat, naming what
/// it does serve and where to go instead.
pub(crate) fn no_chat_refusal(node_id: &str, served: &[(String, String)], roles: &[(String, String)]) -> String {
    let what: Vec<String> = served
        .iter()
        .map(|(bt, model)| {
            let r: Vec<&str> = roles
                .iter()
                .filter(|(b, role)| b == bt && role != "chat")
                .map(|(_, role)| role.as_str())
                .collect();
            let r = if r.is_empty() { "a non-chat role".to_string() } else { r.join("+") };
            format!("{bt} ({model}) for {r}")
        })
        .collect();
    format!(
        "node '{node_id}' serves no chat: it runs {} — a chat pinned there cannot be answered. \
         Pin a node that serves chat (`noo cluster status` lists what each node runs), \
         or drop the node pin and let the cluster choose",
        what.join(", ")
    )
}

/// Resolve a named node's chat backend, INCLUDING the controller (self)
/// which gossip.alive_peers() excludes. Matches the mesh_nodes KV on node id
/// or hostname.
pub(crate) async fn node_chat_backend(state: &AppState, node_id: &str) -> NodeChat {
    // Read the mesh_nodes KV for ALL nodes. We deliberately do NOT use
    // gossip.alive_peers() here: it excludes the controller (self), AND a peer's
    // BackendInfo.url is the backend's advertised address (e.g. the internal
    // `noo-llamacpp:8085`) which is unreachable from the gateway for a remote
    // node. The KV gives ip_address → the node-agent URL (`<ip>:8081`), the same
    // reachable path coordinator::resolve_backend uses, for every node.
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else { return NodeChat::Unknown };
    use tokio_stream::StreamExt;
    let Ok(keys) = kv.keys().await else { return NodeChat::Unknown };
    let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
    for key in keys {
        if key == "gateway" { continue; }
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(data) = serde_json::from_slice::<Value>(&entry) else { continue };
        let id = data.get("id").and_then(|v| v.as_str()).unwrap_or(key.as_str());
        let host = data.get("hostname").and_then(|v| v.as_str()).unwrap_or(key.as_str());
        if id != node_id && host != node_id { continue; }
        let ip = data.get("ip_address").and_then(|v| v.as_str())
            .or_else(|| data.get("ip").and_then(|v| v.as_str())).unwrap_or("");
        if ip.is_empty() { continue; }
        let Some(rb) = data.get("running_backends").and_then(|b| b.as_object()) else { continue };
        // The same declared-role set the resolver routes by. Unavailable
        // (DB down, no cache) is not a reason to refuse a pin: dispatch as
        // before and let the backend answer.
        let non_chat = match crate::coordinator::non_chat_backends(state).await {
            Ok(set) => set,
            Err(e) => {
                tracing::warn!(node = %id, error = %e, "pinned_chat_role_check_unavailable");
                Default::default()
            }
        };
        match pick_chat_backend(id, rb, &non_chat) {
            Ok((bt, m)) => return NodeChat::Serves(bt, m, format!("https://{ip}:8081")),
            Err(served) if !served.is_empty() => {
                let roles = crate::repo::cluster::node_running_roles(&state.db, id).await.unwrap_or_default();
                let msg = no_chat_refusal(id, &served, &roles);
                tracing::warn!(node = %id, served = ?served, "pinned_chat_refused_node_serves_no_chat");
                return NodeChat::NoChat(msg);
            }
            Err(_) => continue,
        }
    }
    NodeChat::Unknown
}

/// A backend's own "this model cannot chat" answer (ollama:
/// `"harrier" does not support chat`). The placement table is the first
/// line; this catches an embedder nobody declared, so the caller still gets
/// a 4xx naming the node rather than a raw 502.
pub(crate) fn backend_cannot_chat(err: &str) -> bool {
    err.contains("does not support chat")
}

/// Find the node-agent URL for any node running `backend_type`, INCLUDING the
/// controller (self). gossip.find_peers() only tracks OTHER nodes, so a backend
/// running on the controller (e.g. ollama/vllm on HOST3) is invisible to it —
/// the cause of false "No {backend} available" 503s. Check gossip first (live
/// load), then fall back to the authoritative mesh_nodes KV (every node).
///
/// SECURITY: gossip is
/// used only to PICK a node, never to supply its address. A peer's
/// `BackendInfo.url` arrives on `mesh.gossip.announce`, which carries no
/// per-message authentication — dialing it would let any bus publisher steer a
/// gateway-initiated request, and `proxy_backend_health` attaches a live
/// cluster-HMAC credential via `with_backend_hint_url`. The address therefore
/// always comes from the authenticated `mesh_nodes` KV, exactly as the sibling
/// `node_chat_backend` already does.
async fn backend_node_agent_url(state: &AppState, backend_type: &str) -> Option<String> {
    // Gossip supplies a *preference* (lowest load) — an id, not a URL.
    let preferred: Option<String> = state
        .gossip
        .find_peers(None, Some(backend_type), 1)
        .first()
        .map(|p| p.node_id.clone());

    let kv = state.js.get_key_value("mesh_nodes").await.ok()?;
    use tokio_stream::StreamExt;
    let keys: Vec<String> = kv.keys().await.ok()?.filter_map(|k| k.ok()).collect().await;

    let mut fallback: Option<String> = None;
    for key in keys {
        if key == "gateway" { continue; }
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(data) = serde_json::from_slice::<Value>(&entry) else { continue };
        let ip = data.get("ip_address").and_then(|v| v.as_str())
            .or_else(|| data.get("ip").and_then(|v| v.as_str())).unwrap_or("");
        if ip.is_empty() { continue; }
        let has = data.get("running_backends").and_then(|b| b.as_object())
            .and_then(|rb| rb.get(backend_type)).and_then(|m| m.as_str())
            .map(|m| !m.is_empty()).unwrap_or(false);
        if !has { continue; }

        let url = format!("https://{ip}:8081");
        // Prefer the gossip-chosen node when the KV confirms it exists and
        // actually runs this backend; otherwise take the first that does.
        let id = data.get("id").and_then(|v| v.as_str()).unwrap_or(key.as_str());
        let host = data.get("hostname").and_then(|v| v.as_str()).unwrap_or(key.as_str());
        if preferred.as_deref() == Some(id) || preferred.as_deref() == Some(host) {
            return Some(url);
        }
        if fallback.is_none() { fallback = Some(url); }
    }
    fallback
}

/// Proxy a health check to a backend of the given type — controller-aware via
/// backend_node_agent_url(). Sends node-agent auth (with_backend_hint_url) like
/// the real inference path.
async fn proxy_backend_health(
    state: &AppState,
    backend_type: &str,
    path: &str,
) -> axum::response::Response {
    let base = match backend_node_agent_url(state, backend_type).await {
        Some(u) => u,
        None => return (StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": format!("No {} backend available", backend_type)}).to_string()).into_response(),
    };
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let client = crate::tls::cluster_client();
    let req = crate::coordinator::with_backend_hint_url(
        client.get(&url).timeout(std::time::Duration::from_secs(5)), &url, backend_type,
    );
    match req.send().await {
        Ok(resp) => {
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            crate::coordinator::warn_if_node_agent_outdated(resp.status(), &url);
            let body = resp.text().await.unwrap_or_default();
            (status, body).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("Backend unreachable: {e}")).into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════
// OpenAI-compatible chat completions — native Rust proxy
// ═══════════════════════════════════════════════════════════════
//
// POST /v1/chat/completions. Previously delegated to a Python NATS handler
// (`worker.compat.chat_completions`) that imported `handle_chat_completions`
// from anthropic_compat.py — a function that was never defined (only the old
// FastAPI-style `_handle_chat_completions(Request, gw)` exists), so the route
// 500'd with `cannot import name 'handle_chat_completions'`. An OpenAI
// passthrough needs no in-process ML, so the correct home is Rust: resolve
// the live vLLM backend and forward the request. This lets any OpenAI client
// (e.g. noo-trading) share the one vLLM instance through the gateway instead
// of reaching for the mTLS-only, non-host-published vLLM port directly.

/// The `model` an OpenAI-style body asks for, as a resolver hint. `"default"`
/// and blank mean "whatever the cluster is configured to serve" — the
/// placeholder rules live in one place now (`coordinator::backend::model_hint`)
/// so every surface drops the same sentinels.
fn requested_model_hint(body: &Value) -> Option<&str> {
    crate::coordinator::model_hint(body.get("model").and_then(|v| v.as_str()))
}

/// POST /v1/chat/completions — OpenAI-compatible, class-routed with
/// failover (`routes::raw_chat`): the body's `model` is a class, an alias or
/// a concrete served model; the answer says which class and model served
/// (`X-Noo-Served-Class` / `X-Noo-Served-Model`, body `noo`), and an error
/// is general with a `ref` — the detail is in the log under it.
async fn openai_chat_completions(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    cluster: Option<Extension<crate::auth::ClusterNode>>,
    headers: axum::http::HeaderMap,
    Json(mut body): Json<Value>,
) -> axum::response::Response {
    // Per-consumer scope gate: a key scoped only to e.g. "embeddings" must not
    // be able to drive chat generation through the legacy `/v1/*` surface.
    if !consumer.has_scope("chat") {
        return forbidden_v1("chat");
    }
    // Accounting (P12: this surface was the one unmetered chat path). A
    // bound key is its user, a machine key its consumer, a cluster caller
    // its actor label; `user` in an OpenAI body is never an identity.
    let (_, usage_actor) = bind_identity(
        None,
        cluster.as_ref().map(|Extension(c)| c),
        Some(&consumer),
        None,
        "v1",
    );
    let requested = body.get("model").and_then(|v| v.as_str()).unwrap_or("default").to_string();
    match super::raw_chat::chat_completions(&state, &mut body, "v1", usage_actor, &super::raw_chat::pin_headers(&headers)).await {
        Ok(super::raw_chat::Outcome::Stream { resp, served, usage, guard }) => {
            tracing::info!(model_requested = %requested, class = %served.class, model_actual = %served.model, backend = %served.backend_type, stream = true, "openai_chat_completions_proxy");
            super::raw_chat::stream_response(*resp, &served, usage, guard)
        }
        Ok(super::raw_chat::Outcome::Json { data, served }) => {
            tracing::info!(model_requested = %requested, class = %served.class, model_actual = %served.model, backend = %served.backend_type, stream = false, "openai_chat_completions_proxy");
            super::raw_chat::json_response(data, &served)
        }
        Err(e) => e.into_response("v1"),
    }
}

fn sse_body(body: Body) -> axum::response::Response {
    axum::response::Response::builder()
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("x-accel-buffering", "no")
        .body(body)
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "stream build error").into_response())
}

/// POST /v1/responses — the OpenAI Responses API, for
/// harnesses that speak only it (Codex CLI since 2026-02). A vLLM backend that
/// serves `/v1/responses` is proxied straight through; every other backend
/// (and a vLLM that answers 404/405 — an old image, or a node-agent proxy
/// that only spans chat/completions/embeddings) is reached by translating to
/// chat completions (`responses_shim`). Stateless: no `previous_response_id`
/// store, so there is no `GET /v1/responses/{id}`.
async fn v1_responses(
    State(state): State<Arc<AppState>>,
    Extension(consumer): Extension<Consumer>,
    cluster: Option<Extension<crate::auth::ClusterNode>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    if !consumer.has_scope("chat") {
        return forbidden_v1("chat");
    }
    let (_, usage_actor) = bind_identity(
        None,
        cluster.as_ref().map(|Extension(c)| c),
        Some(&consumer),
        None,
        "v1",
    );
    use super::raw_chat::{self, Outcome};
    let (class, cands) = match raw_chat::resolve_candidates(&state, requested_model_hint(&body), None, false).await {
        Ok(r) => r,
        Err(e) => return e.into_response("v1"),
    };
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);

    // Native: a vLLM reached directly (not through node-agent, whose proxy has
    // no /v1/responses route) is proxied as-is, with failover across the
    // class's native-vLLM candidates; a 404/405 (old image) falls through
    // to the translation over the whole class.
    let native = native_vllm_candidates(&cands);
    if let Some(first) = native.first() {
        {
            let template = body.clone();
            match raw_chat::send_with_failover(&state, &class, &native, stream, "v1", usage_actor.clone(), |cand| {
                let mut b = template.clone();
                b["model"] = json!(cand.model);
                ("/v1/responses".to_string(), b)
            })
            .await
            {
                Ok(Outcome::Stream { resp, served, usage, guard }) => return raw_chat::stream_response(*resp, &served, usage, guard),
                Ok(Outcome::Json { data, served }) => return raw_chat::json_response(data, &served),
                Err(e) if e.status == StatusCode::NOT_FOUND || e.status == StatusCode::METHOD_NOT_ALLOWED => {
                    tracing::info!(url = %first.url, "vllm_has_no_v1_responses_translating");
                }
                Err(e) => return e.into_response("v1"),
            }
        }
    }

    use crate::routes::responses_shim as shim;
    let template = body.clone();
    let outcome = raw_chat::send_with_failover(&state, &class, &cands, stream, "v1", usage_actor, |cand| {
        let mut chat_body = shim::responses_to_chat_request(&template, &cand.model);
        if stream {
            chat_body["stream_options"] = json!({"include_usage": true});
        }
        ("/v1/chat/completions".to_string(), chat_body)
    })
    .await;
    match outcome {
        Ok(Outcome::Stream { resp, served, usage, guard }) => {
            use futures::StreamExt as _;
            // No metadata frame here: a Responses-API consumer expects every
            // event to carry a `type`; the headers say what served.
            let mut tr = shim::StreamTranslator::new(&served.model, &body);
            let tapped = crate::usage::tap_stream(resp.bytes_stream(), usage);
            let events = tapped
                .map(Some)
                .chain(futures::stream::once(async { None }))
                .flat_map(move |item| {
                    guard.mark_streamed();
                    let evs = match item {
                        Some(Ok(b)) => tr.push(&b),
                        // Upstream died or ended: close out what we have.
                        Some(Err(_)) | None => tr.finish(),
                    };
                    futures::stream::iter(evs.into_iter().map(|e| Ok::<_, std::io::Error>(axum::body::Bytes::from(e))))
                });
            let mut r = sse_body(Body::from_stream(events));
            if let Ok(v) = axum::http::HeaderValue::from_str(&served.class) { r.headers_mut().insert(raw_chat::HEADER_CLASS, v); }
            if let Ok(v) = axum::http::HeaderValue::from_str(&served.model) { r.headers_mut().insert(raw_chat::HEADER_MODEL, v); }
            r
        }
        Ok(Outcome::Json { data, served }) => raw_chat::json_response(shim::chat_to_response(&data, &served.model, &body), &served),
        Err(e) => e.into_response("v1"),
    }
}

// ═══════════════════════════════════════════════════════════════
// Anthropic compatibility shim — scope-guarded NATS delegation
// ═══════════════════════════════════════════════════════════════
//
// `/v1/complete` and `/v1/messages` are chat-type generation endpoints that
// delegate to Python workers over NATS. They previously used the generic
// `delegation::delegate_post` closure, which has no access to the resolved
// `Consumer` and so applied no scope check. These thin native wrappers inject
// the Consumer, enforce the "chat" scope, then forward to the same NATS
// subjects the closures used.

// /v1/complete and /v1/messages (Anthropic-style) were REMOVED along with
// their Python implementation, gateway/anthropic_compat.py (1,222 lines).
// Nothing used them: the `/v1/*` surface has no `noo_external_requests`
// audit plumbing, so this was confirmed with the operator rather than
// inferred from an absence of records.
//
// The OpenAI-compatible surface is unaffected — /v1/chat/completions is
// native Rust (openai_chat_completions) and /v1/models/{id} is native
// (compat_model_detail).

// ═══════════════════════════════════════════════════════════════
// Model detail — native Rust (ported from NATS delegation 2026-03-31)
// ═══════════════════════════════════════════════════════════════
//
// The Python version called _resolve_backend_url(gw) to find the local
// model name, then returned a simple model info object. The Rust version
// resolves the backend the same way via coordinator::resolve_backend().

/// GET /v1/models/{model_id} — one catalogue entry, or 404 for an id that is
/// not a class, an alias or a served model (it used to answer 200 for any
/// string, so a consumer could not tell a typo from a model).
async fn compat_model_detail(
    State(state): State<Arc<AppState>>,
    Path(model_id): Path<String>,
) -> impl IntoResponse {
    let table = match crate::coordinator::classes::load_table(&state).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "model_detail_catalogue_unavailable");
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": {"message": "model catalogue unavailable", "type": "server_error"}})));
        }
    };
    match model_detail_for(&table, &model_id) {
        Some(v) => (StatusCode::OK, Json(v)),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": {
            "message": format!("model '{model_id}' is not a class, alias or served model"),
            "type": "model_not_found",
            "code": "model_not_found",
        }}))),
    }
}

/// The candidates `/v1/responses` may proxy natively: every vLLM of the
/// class reached directly (a node-agent proxy has no `/v1/responses`), in
/// class order — so the native branch fails over too, instead of trying
/// the first candidate once.
fn native_vllm_candidates(cands: &[crate::coordinator::classes::Candidate]) -> Vec<crate::coordinator::classes::Candidate> {
    cands
        .iter()
        .filter(|c| c.backend.starts_with("vllm") && !coordinator::is_node_agent_url(&c.url))
        .cloned()
        .collect()
}

/// The catalogue entry for `id` — the class it names (directly or through
/// an alias), or `None`.
fn model_detail_for(table: &crate::coordinator::classes::ClassTable, id: &str) -> Option<Value> {
    let class = crate::coordinator::classes::resolve_hint(table, crate::coordinator::model_hint(Some(id)))?;
    let alias = !class.name.eq_ignore_ascii_case(id) && !crate::coordinator::classes::norm_model(&class.name).eq(&crate::coordinator::classes::norm_model(id));
    Some(json!({
        "id": id,
        "object": "model",
        "owned_by": "noomesh",
        "display_name": if alias { format!("{id} (→ {})", class.name) } else { id.to_string() },
        "noo": {
            "class": class.name,
            "alias": alias,
            "candidates": class.routable_count(),
            "healthy": class.healthy_count(),
            "declared": class.declared,
        },
        "engine": "rust",
    }))
}

// ═══════════════════════════════════════════════════════════════
// Inference streaming — native Rust SSE (ported from NATS 2026-03-31)
// ═══════════════════════════════════════════════════════════════
//
// The Python version called coordinator.run() non-streaming over NATS
// (streaming over NATS is limited). The Rust version resolves the backend
// directly and proxies the SSE stream from the LLM backend (vLLM/Ollama),
// giving true token-by-token streaming without NATS overhead.
//
// For cloud models, falls back to NATS delegation to Python.

/// Request body for POST /api/inference/stream.
#[derive(Debug, Deserialize)]
struct StreamInferenceRequest {
    /// The user's prompt/message.
    prompt: String,
    /// Optional conversation ID for session continuity.
    #[serde(default)]
    conversation_id: Option<String>,
    /// Channel source (api, dashboard, telegram, etc.)
    #[serde(default = "default_stream_channel")]
    channel: String,
    /// Optional model override.
    #[serde(default)]
    model: Option<String>,
}

fn default_stream_channel() -> String { "api".to_string() }

/// POST /api/inference/stream — SSE streaming inference.
///
/// Resolves the backend and proxies the SSE stream directly from the LLM.
/// This provides true token-by-token streaming without the NATS
/// request/reply bottleneck that limited the Python implementation.
///
/// Response format: Server-Sent Events (text/event-stream), each line
/// containing a JSON chunk matching OpenAI's streaming format.
async fn native_inference_stream(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<crate::auth::AuthActor>>,
    cluster: Option<Extension<crate::auth::ClusterNode>>,
    Json(req): Json<StreamInferenceRequest>,
) -> axum::response::Response {
    // Accounting only — the raw proxy below scopes nothing per user, so the
    // identity is not used for anything but the usage row.
    let (_, usage_actor) = bind_identity(
        actor.as_ref().map(|Extension(a)| a.0.as_str()),
        cluster.as_ref().map(|Extension(c)| c),
        None,
        None,
        "api",
    );
    let conversation_id = req.conversation_id
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    tracing::info!(
        conversation_id = %conversation_id,
        channel = %req.channel,
        prompt_len = req.prompt.len(),
        model = ?req.model,
        "native_inference_stream_start"
    );

    // Cloud models run through Rust's own provider clients.
    //
    // This used to delegate to `worker.chat` over NATS, commented "Python has
    // the API keys". Both halves were wrong:
    //
    //   1. Rust reads ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY
    //      itself (coordinator/cloud.rs) and already routes cloud models
    //      natively from both run() and run_streaming().
    //   2. worker.chat could not answer. Its handler resolves a coordinator
    //      from `services.coordinator`, which nothing ever assigns, and falls
    //      back to importing gateway/coordinator.py, deleted in the Rust port.
    //      Probed live: POST /chat -> 400 {"error":"Coordinator not initialized"}.
    //
    // So streaming with any claude-/gpt-/gemini- model returned an SSE event
    // containing that error instead of a completion.
    //
    // Still a single SSE event rather than token streaming: run_cloud_completion
    // is non-streaming, which matches what this branch always did. Real
    // token-level cloud streaming is a separate feature, not a bug fix.
    if let Some(ref model) = req.model {
        if model.starts_with("claude-") || model.starts_with("gpt-") || model.starts_with("gemini-") {
            // Gate first: refused before any provider lookup or HTTP.
            let payload = match crate::coordinator::cloud_gate() {
                Err(msg) => crate::coordinator::cloud_gate_body(msg),
                Ok(()) => {
                    tracing::info!(model = %model, "streaming cloud model natively");
                    match crate::coordinator::run_cloud(
                        &state, &req.prompt, &conversation_id, &req.channel, model,
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(e) => json!({"error": format!("cloud completion failed: {e}")}),
                    }
                }
            };
            let event = format!(
                "data: {}\n\ndata: [DONE]\n\n",
                serde_json::to_string(&payload).unwrap_or_default()
            );
            return axum::response::Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .body(Body::from(event))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stream error").into_response());
        }
    }

    // Resolve local backend FOR THE REQUESTED MODEL. This route is what
    // `noo chat` speaks, and it used to resolve with no model at all, so a
    // `--model qwen2.5:0.5b` (or the model a `noo models switch` had just
    // placed) was ignored and the static fallback was asked for the
    // configured vLLM default — "model 'Qwen/Qwen3-8B-AWQ' not found" on a
    // CPU standalone install whose only backend is Ollama, while
    // `noo inference run --model …` on the sibling route answered fine
    // (2026-09-28 newcomer rehearsal). `resolve_backend_for_model` is the
    // same chain the OpenAI-compatible route already uses.
    let backend = match coordinator::resolve_backend_for_model(&state, req.model.as_deref()).await {
        Ok(b) => b,
        Err(e) => {
            let err = json!({"error": format!("No backend available: {e}")});
            let event = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::to_string(&err).unwrap_or_default());
            return axum::response::Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .body(Body::from(event))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stream error").into_response());
        }
    };

    // Build the streaming request to the backend
    let url = match backend.api_format.as_str() {
        "ollama" => format!("{}/api/chat", backend.url),
        "llamacpp" => format!("{}/completion", backend.url),
        _ => format!("{}/v1/chat/completions", backend.url), // OpenAI-compat (vLLM)
    };

    let messages = vec![
        json!({"role": "user", "content": req.prompt}),
    ];

    let body = match backend.api_format.as_str() {
        "ollama" => json!({
            "model": backend.model,
            "messages": messages,
            "stream": true,
        }),
        "llamacpp" => json!({
            "prompt": req.prompt,
            "stream": true,
        }),
        _ => json!({
            "model": backend.model,
            "messages": messages,
            "stream": true,
            "stream_options": {"include_usage": true},
        }),
    };

    let client = crate::tls::cluster_client();

    // Stream the response from the backend as SSE.
    // Add X-Noo-Backend hint for node-agent proxy URLs.
    let req = crate::coordinator::with_backend_hint_url(
        client.post(&url).json(&body),
        &url, &backend.backend_type,
    );
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!(
                backend = %backend.backend_type,
                model = %backend.model,
                url = %url,
                "streaming_proxy_connected"
            );
            let usage_ctx = crate::usage::StreamUsageCtx {
                db: state.db.clone(),
                node_id: coordinator::node_from_backend_url(&backend.url),
                backend: backend.backend_type.clone(),
                model: backend.model.clone(),
                source: "api",
                actor: usage_actor,
            };
            let stream = crate::usage::tap_stream(resp.bytes_stream(), usage_ctx);
            let body = Body::from_stream(stream);

            axum::response::Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("X-Backend", backend.backend_type.as_str())
                .header("X-Model", backend.model.as_str())
                .body(body)
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Stream error").into_response()
                })
        }
        Ok(resp) => {
            let status = resp.status();
            crate::coordinator::warn_if_node_agent_outdated(status, &url);
            let status_code = status.as_u16();
            let text = resp.text().await.unwrap_or_default();
            tracing::error!(status = status_code, body = %text.chars().take(200).collect::<String>(), "streaming_backend_error");
            let err = json!({"error": format!("Backend returned {status}: {}", text.chars().take(200).collect::<String>())});
            let event = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::to_string(&err).unwrap_or_default());
            axum::response::Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .body(Body::from(event))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stream error").into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "streaming_backend_unreachable");
            let err = json!({"error": format!("Backend unreachable: {e}")});
            let event = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::to_string(&err).unwrap_or_default());
            axum::response::Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .body(Body::from(event))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Stream error").into_response())
        }
    }
}

#[cfg(test)]
mod identity_tests {
    use super::bind_identity;
    use crate::auth::{ClusterKind, ClusterNode};
    use crate::service_keys::Consumer;

    fn key(name: &str, user: Option<&str>) -> Consumer {
        Consumer {
            name: name.into(),
            scopes: vec!["chat".into()],
            rpm_limit: None,
            user: user.map(str::to_string),
            user_scopes: Vec::new(),
            user_role: None,
        }
    }

    /// A JWT subject is the identity; a disagreeing body user_id is noise.
    #[test]
    fn jwt_subject_wins_and_is_charged() {
        let (uid, actor) = bind_identity(Some("alice"), None, None, Some("mallory"), "api");
        assert_eq!(uid.as_deref(), Some("alice"));
        assert_eq!(actor.username.as_deref(), Some("alice"));
        assert_eq!(actor.consumer.as_deref(), Some("api"));
    }

    /// only the controller's own services may delegate a user.
    #[test]
    fn internal_cluster_callers_delegate_nodes_do_not() {
        let internal = ClusterNode("mcp-local".into(), ClusterKind::Internal);
        let (uid, actor) = bind_identity(None, Some(&internal), None, Some("alice"), "api");
        assert_eq!(uid.as_deref(), Some("alice"));
        assert_eq!(actor.username.as_deref(), Some("alice"));
        assert_eq!(actor.consumer.as_deref(), Some("mcp-local"));

        let node = ClusterNode("host9".into(), ClusterKind::Node);
        let (uid, actor) = bind_identity(None, Some(&node), None, Some("alice"), "api");
        assert_eq!(uid, None, "a node token cannot name a person");
        assert_eq!(actor.username, None);
        assert_eq!(actor.consumer.as_deref(), Some("node:host9"));
    }

    /// A bound service key IS its user; an unbound one is only its consumer
    /// and cannot delegate either.
    #[test]
    fn service_keys_are_their_binding() {
        let bound = key("alice-laptop", Some("alice"));
        let (uid, actor) = bind_identity(None, None, Some(&bound), Some("mallory"), "v1");
        assert_eq!(uid.as_deref(), Some("alice"));
        assert_eq!(actor.username.as_deref(), Some("alice"));
        assert_eq!(actor.consumer.as_deref(), Some("alice-laptop"));

        let machine = key("noo-trading", None);
        let (uid, actor) = bind_identity(None, None, Some(&machine), Some("alice"), "v1");
        assert_eq!(uid, None);
        assert_eq!(actor.username, None);
        assert_eq!(actor.consumer.as_deref(), Some("noo-trading"));
    }

    /// The synthetic `Consumer::all("cluster")` a cluster caller carries on
    /// the inference surface must not shadow its real cluster identity.
    #[test]
    fn cluster_identity_beats_the_synthetic_consumer() {
        let internal = ClusterNode("worker".into(), ClusterKind::Internal);
        let synthetic = Consumer::all("cluster");
        let (_, actor) = bind_identity(None, Some(&internal), Some(&synthetic), None, "v1");
        assert_eq!(actor.consumer.as_deref(), Some("worker"));
    }

    /// No credential at all delegates NOTHING. The "legacy unauthenticated
    /// deployment" arm that honoured the body's user_id is retired.
    #[test]
    fn unauthenticated_delegates_nothing() {
        let (uid, actor) = bind_identity(None, None, None, Some("alice"), "api");
        assert_eq!(uid, None, "a body user_id without a credential must not be honoured");
        assert_eq!(actor.username, None);
        assert_eq!(actor.consumer.as_deref(), Some("unauthenticated:api"));
    }

    /// Why the arm above can be retired: no inference route is reachable
    /// without a credential. Each is off every anonymous list the auth gate
    /// consults, and the router that carries them is merged BEFORE the
    /// `require_any_auth` layer (layers wrap what precedes them).
    #[test]
    fn inference_routes_are_behind_the_auth_gate() {
        use crate::auth::{
            is_credential_optional, is_handler_authenticated, PUBLIC_GET_PATH_PREFIXES,
            PUBLIC_PATHS_EXACT, PUBLIC_PATH_PREFIXES,
        };
        let src = include_str!("inference.rs");
        let router = src
            .split("pub fn router()")
            .nth(1)
            .and_then(|t| t.split("\n}\n").next())
            .expect("router fn");
        let paths: Vec<&str> = router
            .match_indices(".route(\"")
            .filter_map(|(i, m)| router[i + m.len()..].split('"').next())
            .collect();
        for want in ["/api/inference", "/api/inference/stream", "/v1/chat/completions", "/v1/responses"] {
            assert!(paths.contains(&want), "parse missed {want}: {paths:?}");
        }
        for p in paths.iter().copied().chain(["/api/external/inference", "/api/external/embeddings"]) {
            assert!(!PUBLIC_PATHS_EXACT.contains(&p), "{p} is public");
            assert!(!PUBLIC_PATH_PREFIXES.iter().any(|x| p.starts_with(x)), "{p} under a public prefix");
            assert!(!PUBLIC_GET_PATH_PREFIXES.iter().any(|x| p.starts_with(x)), "{p} under a public GET prefix");
            assert!(!is_handler_authenticated(p), "{p} skips the gate for a handler credential");
            assert!(!is_credential_optional(p), "{p} is credential-optional");
        }
        let mod_rs = include_str!("mod.rs");
        let merged = mod_rs.find(".merge(inference::router())").expect("inference router merged");
        let external = mod_rs.find(".merge(external::router())").expect("external router merged");
        let gate = mod_rs.find("crate::auth::require_any_auth)").expect("auth layer present");
        assert!(merged < gate && external < gate, "an inference router is merged outside the auth layer");
    }
}

#[cfg(test)]
mod hint_tests {
    use super::requested_model_hint;

    #[test]
    fn requested_model_hint_treats_placeholders_and_blank_as_none() {
        assert_eq!(requested_model_hint(&serde_json::json!({"model": "llama3.2:3b"})), Some("llama3.2:3b"));
        assert_eq!(requested_model_hint(&serde_json::json!({"model": " qwen2.5:3b "})), Some("qwen2.5:3b"));
        assert_eq!(requested_model_hint(&serde_json::json!({"model": "default"})), None);
        assert_eq!(requested_model_hint(&serde_json::json!({"model": "Default"})), None);
        assert_eq!(requested_model_hint(&serde_json::json!({"model": "auto"})), None);
        assert_eq!(requested_model_hint(&serde_json::json!({"model": ""})), None);
        assert_eq!(requested_model_hint(&serde_json::json!({})), None);
    }
}

#[cfg(test)]
mod responses_route_tests {
    use super::*;

    /// A consumer without `chat` (e.g. an embeddings-only key) is refused with
    /// the same 403 shape the other `/v1/*` handlers use.
    #[tokio::test]
    async fn responses_refuses_a_consumer_without_chat() {
        let c = Consumer {
            name: "embedder".into(),
            scopes: vec!["embeddings".into()],
            rpm_limit: None,
            user: None,
            user_scopes: Vec::new(),
            user_role: None,
        };
        assert!(!c.has_scope("chat"));
        let resp = forbidden_v1("chat");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["type"], "forbidden");
        assert_eq!(v["error"]["message"], "service key lacks 'chat' scope");
    }

    /// A closed cloud gate is a policy refusal: 403 with the typed body, even
    /// when a caller wrapped the error in context. Any other failure is None.
    #[tokio::test]
    async fn closed_cloud_gate_is_403_with_code() {
        let e = anyhow::Error::new(crate::coordinator::CloudGateClosed("Cloud models are off: x"))
            .context("agent loop");
        let resp = cloud_gate_response(&e).expect("typed refusal");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["code"], "cloud_providers_disabled");
        assert_eq!(v["success"], false);
        assert_eq!(v["setting"], "CLOUD_PROVIDERS_ENABLED");
        assert!(v["remedy"].is_string() && v["error"].is_string());
        assert!(cloud_gate_response(&anyhow::anyhow!("ANTHROPIC_API_KEY not configured")).is_none());
    }

    /// The handler must gate on `chat` BEFORE resolving a backend.
    #[test]
    fn v1_responses_checks_the_chat_scope_first() {
        let src = include_str!("inference.rs");
        let body = src.split("async fn v1_responses(").nth(1).expect("handler");
        let gate = body.find("has_scope(\"chat\")").expect("scope gate");
        let resolve = body.find("resolve_candidates(").expect("resolver call");
        assert!(gate < resolve);
    }

    /// `context: false` parses; absence means the coordinator path.
    #[test]
    fn inference_request_context_defaults_to_the_coordinator() {
        let r: InferenceRequest = serde_json::from_value(json!({"prompt": "p"})).unwrap();
        assert_eq!(r.context, None);
        let r: InferenceRequest = serde_json::from_value(json!({"prompt": "p", "context": false, "max_tokens": 5})).unwrap();
        assert_eq!(r.context, Some(false));
        assert_eq!(r.max_tokens, Some(5));
    }
}

#[cfg(test)]
mod catalogue_tests {
    use super::model_detail_for;
    use crate::coordinator::classes::{build_table, DeclaredCandidate, DeclaredClass, Declarations, NodeFacts, CHAT_DEFAULT};

    fn table() -> crate::coordinator::classes::ClassTable {
        let nodes = vec![NodeFacts {
            node_id: "host3".into(),
            ip: "100.64.0.10".into(),
            running: vec![("vllm".into(), "google/gemma-4-12B-it-qat-w4a16-ct".into())],
            heartbeat_age_secs: Some(1.0),
            inbound_ok: true,
            gpu: true,
            ..Default::default()
        }];
        let decl = Declarations {
            classes: vec![DeclaredClass {
                name: "fast".into(),
                pool: false,
                candidates: vec![DeclaredCandidate { node_id: "host3".into(), backend: "vllm".into(), model: None, degraded: false }],
            }],
            aliases: vec![("quick".into(), "fast".into())],
        };
        build_table(&nodes, &[], &decl)
    }

    /// `/v1/responses` proxies natively to EVERY directly-reached vLLM of the
    /// class, in order — node-agent-fronted and non-vLLM candidates go to
    /// the translation.
    #[test]
    fn responses_native_branch_iterates_the_classes_native_vllms() {
        use crate::coordinator::classes::Candidate;
        let mk = |node: &str, backend: &str, url: &str| Candidate::synthetic(node.into(), backend.into(), "m".into(), url.into());
        let cands = vec![
            mk("a", "vllm", "https://noo-vllm:8000"),
            mk("b", "vllm", "https://100.64.0.2:8081"),
            mk("c", "vllm-secondary", "https://noo-vllm-secondary:8000"),
            mk("d", "ollama", "https://noo-stunnel-ollama:11434"),
        ];
        let native = super::native_vllm_candidates(&cands);
        let ids: Vec<&str> = native.iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(ids, ["a", "c"], "every direct vLLM, in class order; the proxied one and the ollama are not native");
        assert!(super::native_vllm_candidates(&cands[1..2]).is_empty());
    }

    /// `GET /v1/models/{id}` answers for a class, an alias (naming its class)
    /// and a served model, and NOTHING for an unknown id — it used to be 200
    /// for any string.
    #[test]
    fn model_detail_is_404_for_an_unknown_id_and_names_the_class_otherwise() {
        let t = table();
        assert!(model_detail_for(&t, "llama3.2:1b").is_none(), "unknown concrete name");
        assert!(model_detail_for(&t, "nonsense-class").is_none());
        let d = model_detail_for(&t, "default").expect("built-in alias");
        assert_eq!(d["noo"]["class"], CHAT_DEFAULT);
        assert_eq!(d["noo"]["alias"], true);
        let q = model_detail_for(&t, "quick").expect("declared alias");
        assert_eq!(q["noo"]["class"], "fast");
        assert_eq!(q["display_name"], "quick (→ fast)");
        let f = model_detail_for(&t, "fast").expect("class");
        assert_eq!(f["noo"]["alias"], false);
        assert_eq!(f["noo"]["declared"], true);
        let m = model_detail_for(&t, "google/gemma-4-12B-it-qat-w4a16-ct").expect("served model");
        assert_eq!(m["owned_by"], "noomesh");
        assert_eq!(m["noo"]["candidates"], 1);
        let text = serde_json::to_string(&m).unwrap();
        assert!(!text.contains("host3") && !text.contains("100.64"), "{text}");
    }
}

/// i69a: a chat pinned to an embeddings-only node is refused before
/// dispatch, naming what the node serves, with a 4xx — not the backend's
/// raw 502 `"harrier" does not support chat`.
#[cfg(test)]
mod pinned_no_chat_tests {
    use super::{backend_cannot_chat, no_chat_refusal, pick_chat_backend, NodeChat, NO_CHAT_STATUS};
    use std::collections::HashSet;

    fn running(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    fn non_chat(pairs: &[(&str, &str)]) -> HashSet<(String, String)> {
        pairs.iter().map(|(n, b)| (n.to_string(), b.to_string())).collect()
    }

    #[test]
    fn an_embed_only_node_has_no_chat_backend() {
        // robopi / aserve on 2026-10-14: ollama serving harrier, placed for embed.
        let rb = running(serde_json::json!({"ollama": "harrier"}));
        let got = pick_chat_backend("robopi", &rb, &non_chat(&[("robopi", "ollama")]));
        assert_eq!(got, Err(vec![("ollama".to_string(), "harrier".to_string())]));
    }

    #[test]
    fn a_chat_backend_behind_an_embedder_is_still_found() {
        // vllm > ollama > llamacpp: the embedder used to win by order alone.
        let rb = running(serde_json::json!({"ollama": "harrier", "llamacpp": "gemma-4-E2B"}));
        let got = pick_chat_backend("robopi", &rb, &non_chat(&[("robopi", "ollama")]));
        assert_eq!(got, Ok(("llamacpp".to_string(), "gemma-4-E2B".to_string())));
    }

    #[test]
    fn the_role_set_is_per_node() {
        // Another node's embed placement does not make this node's ollama non-chat.
        let rb = running(serde_json::json!({"ollama": "llama3.2:3b"}));
        let got = pick_chat_backend("host9", &rb, &non_chat(&[("robopi", "ollama")]));
        assert_eq!(got, Ok(("ollama".to_string(), "llama3.2:3b".to_string())));
    }

    #[test]
    fn no_backends_is_not_a_no_chat_refusal() {
        let got = pick_chat_backend("x", &running(serde_json::json!({"ollama": ""})), &HashSet::new());
        assert_eq!(got, Err(vec![]));
    }

    #[test]
    fn the_refusal_names_the_node_its_roles_and_the_way_out() {
        let msg = no_chat_refusal(
            "robopi",
            &[("ollama".into(), "harrier".into())],
            &[("ollama".into(), "embed".into())],
        );
        assert!(msg.contains("node 'robopi' serves no chat"), "{msg}");
        assert!(msg.contains("ollama (harrier) for embed"), "{msg}");
        assert!(msg.contains("noo cluster status"), "{msg}");
        // Unknown role still reads as a sentence.
        let msg = no_chat_refusal("aserve", &[("ollama".into(), "harrier".into())], &[]);
        assert!(msg.contains("for a non-chat role"), "{msg}");
    }

    #[test]
    fn the_refusal_is_a_client_error() {
        assert!(NO_CHAT_STATUS.is_client_error(), "{NO_CHAT_STATUS}");
        assert_ne!(NO_CHAT_STATUS, axum::http::StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn an_undeclared_embedder_is_recognised_from_the_backend_answer() {
        // The exact error chat_completion_on_node returned on the live fleet.
        let live = r#"backend returned 400 Bad Request: {"error":"\"harrier\" does not support chat"}"#;
        assert!(backend_cannot_chat(live));
        assert!(!backend_cannot_chat("backend unreachable: timed out"));
    }

    #[test]
    fn an_embed_only_node_is_still_a_pin() {
        // `model: "robopi"` must route to the refusal, not fall through to the
        // coordinator as if "robopi" were a model name.
        assert!(NodeChat::NoChat("x".into()).is_node());
        assert!(NodeChat::Serves("a".into(), "b".into(), "c".into()).is_node());
        assert!(!NodeChat::Unknown.is_node());
    }
}
