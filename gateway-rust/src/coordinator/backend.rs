// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Backend resolution and routing: gossip/mesh/KV chain, model-aware
//! selection, node-agent URL hints, Python-coordinator model preference.

use anyhow::Result;
use serde_json::Value;

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::backend_port;
use crate::mesh;
use crate::state::AppState;

#[allow(unused_imports)]
use super::*;

/// Backend info resolved from the mesh.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedBackend {
    pub url: String,
    pub model: String,
    pub backend_type: String,
    /// API format: "openai" (vLLM), "ollama", "llamacpp"
    pub api_format: String,
}

// ── llama.cpp: native tool calls, with a remembered fallback ───────────
//
// llama-server speaks the OpenAI chat API — tools, tool_calls, usage,
// SSE — when it runs with `--jinja`, which every image this fleet ships
// does (docker/Dockerfile.llamacpp; LLAMA_ARG_JINJA for the upstream ARM
// image). Before this, a llama.cpp backend dialled directly got the
// `/completion` path: messages flattened into a prompt, tools described
// in prose, tool calls regex-parsed out of the text. That path is now
// the FALLBACK, taken only for a server that refuses `tools` (an
// operator-built llama-server without --jinja): the refusal is
// remembered per backend URL for the life of the process, so the cost is
// one failed request, once.

static LEGACY_COMPLETION: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn legacy_completion() -> &'static Mutex<HashSet<String>> {
    LEGACY_COMPLETION.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Remember that this llama.cpp backend refused native tool calls.
pub(crate) fn mark_legacy_completion(url: &str) {
    legacy_completion().lock().unwrap().insert(url.to_string());
}

/// True when this backend URL has refused native tool calls before.
pub(crate) fn uses_legacy_completion(url: &str) -> bool {
    legacy_completion().lock().unwrap().contains(url)
}

/// The protocol actually put on the wire for this backend. Differs from
/// `api_format` in exactly one case: a llama.cpp backend is spoken to as
/// OpenAI ("openai") unless it has refused tools, in which case the
/// prompt-flattening `/completion` shape ("llamacpp") is used. A cloud
/// Anthropic backend speaks the Messages API ("anthropic").
pub(crate) fn wire_format(backend: &ResolvedBackend) -> &'static str {
    match backend.api_format.as_str() {
        "ollama" => "ollama",
        "anthropic" => "anthropic",
        "llamacpp" if uses_legacy_completion(&backend.url) => "llamacpp",
        _ => "openai",
    }
}

/// llama-server's refusal of a `tools` parameter when it runs without
/// `--jinja` ("tools param requires --jinja flag", HTTP 400 or 500
/// depending on version). Anything else is not this.
pub(crate) fn refuses_tools(status: u16, body: &str) -> bool {
    (400..=599).contains(&status) && body.to_ascii_lowercase().contains("jinja")
}

/// Where a controller-local compose backend is dialled — always `https`.
///
/// `https://noo-<type>:<port>` for a backend that serves TLS itself (vLLM,
/// `--ssl-cert-reqs 2`), and the stunnel sidecar for one that cannot:
/// llama-server and ollama have no TLS listener, so the controller runs
/// each behind `stunnel-<type>` (mTLS, client certificate required) on the
/// same port, and that sidecar is what a caller with a leaf dials. The
/// backend's own port stays plain on the compose network until the
/// backends get a private network; until then this name
/// is the door, not the only one. The container name rather than the
/// compose alias, because the controller's own agent resolves container
/// names (containerdial) and both resolve inside the network.
///
/// The scheme used to follow `NOO_TLS_CA` (plain when unset). The gateway
/// now refuses to start without the CA (`tls::require_server_material`),
/// so there is no configuration in which the plain form could be reached,
/// and the doors themselves are mTLS-only (#538) — a plain dial would be
/// refused at the other end anyway. the design.
pub fn local_backend_url(backend_type: &str, port: u16) -> String {
    let host = match backend_type {
        "llamacpp" | "ollama" => format!("noo-stunnel-{backend_type}"),
        other => format!("noo-{other}"),
    };
    format!("https://{host}:{port}")
}

/// API format detection based on backend type + URL.
///
/// Special case for cross-host calls (proposal #10 — node-agent inference
/// proxy): when the URL points at node-agent (port 8081), node-agent
/// always exposes an OpenAI-compatible surface regardless of which
/// backend it dispatches to. So we force "openai" format for any node-
/// agent URL — the X-Noo-Backend header (set at the request site) tells
/// node-agent which local backend to forward to.
fn detect_api_format(backend_type: &str) -> String {
    detect_api_format_for_url(backend_type, None)
}

/// The wire family for a backend type at a URL — for a harness configuring
/// its pinned endpoint.
pub(crate) fn api_format_for(backend_type: &str, url: &str) -> String {
    detect_api_format_for_url(backend_type, Some(url))
}

/// URL-aware variant — pass the resolved URL when known so we can detect
/// the node-agent proxy case.
fn detect_api_format_for_url(backend_type: &str, url: Option<&str>) -> String {
    if let Some(u) = url {
        if u.contains(":8081") {
            return "openai".to_string();
        }
    }
    match backend_type {
        "ollama" => "ollama".to_string(),
        "llamacpp" | "llama.cpp" | "llama_cpp" => "llamacpp".to_string(),
        _ => "openai".to_string(), // vLLM and others use OpenAI-compatible
    }
}

/// True when the backend URL is the node-agent proxy (port 8081).
/// Used at request sites to add the `X-Noo-Backend` hint header so
/// node-agent picks the right local backend.
pub(crate) fn is_node_agent_url(url: &str) -> bool {
    url.contains(":8081")
}

/// Add the `X-Noo-Backend: <type>` header when the request is going
/// through the node-agent proxy. The header tells node-agent which
/// local backend (vllm/llamacpp/ollama) to dispatch to. Non-node-agent
/// URLs (controller-local backends) get no extra header.
pub(super) fn with_backend_hint(req: reqwest::RequestBuilder, backend: &ResolvedBackend) -> reqwest::RequestBuilder {
    with_backend_hint_url(req, &backend.url, &backend.backend_type)
}

/// URL-based variant of `with_backend_hint` for call sites that don't
/// have a `ResolvedBackend` in scope (e.g., `routes/inference.rs` builds
/// URLs directly from peer info). Pass empty backend_type for "no hint".
///
/// Also attaches the node-agent bearer token (NOO_NODE_AGENT_TOKEN or
/// HMAC fallback) when the URL points at a node-agent — the new /v1/*
/// inference proxy routes are auth-gated, so without this every LLM
/// call through node-agent returns 401.
pub(crate) fn with_backend_hint_url(req: reqwest::RequestBuilder, url: &str, backend_type: &str) -> reqwest::RequestBuilder {
    let mut req = req;
    if is_node_agent_url(url) {
        if !backend_type.is_empty() {
            req = req.header("X-Noo-Backend", backend_type);
        }
        if let Some((name, value)) = crate::node_agent_auth::header_for(url) {
            req = req.header(name, value);
        }
    }
    req
}

/// Surface a clear warning when a node-agent returned 404 — strong
/// signal that the worker is running an out-of-date image without the
/// `/v1/*` proxy routes added. Without this, callers
/// would silently fall back to a different backend (which is exactly
/// the original bug we fixed).
pub(crate) fn warn_if_node_agent_outdated(status: reqwest::StatusCode, url: &str) {
    if status == reqwest::StatusCode::NOT_FOUND && is_node_agent_url(url) {
        tracing::error!(
            url = %url,
            "node_agent_outdated: 404 from node-agent — likely missing /v1/* inference proxy. \
             Rebuild + redeploy node-agent on this node. \
             Falling back may pick the wrong model — strongly recommend immediate update."
        );
    }
}

/// Classify an LLM backend HTTP error response as "retryable on another
/// backend".
///
/// A resolved backend can be up in the mesh KV (stale heartbeat) while its
/// actual inference engine is down — the node-agent proxy then answers
/// 502 with a `backend_unreachable` / `node_agent_proxy_error` JSON body
/// (dial tcp ... connection refused). That's a *backend* failure, not a
/// *request* failure: the same request is expected to succeed on the next
/// viable backend, so the coordinator should mark this URL failed and
/// re-resolve. Non-gateway statuses (400 bad request, 422, 500 from the
/// engine itself) are NOT retryable — retrying elsewhere would just repeat
/// the same error.
pub(crate) fn is_retryable_llm_http_error(status: u16, body: &str) -> bool {
    // Context-window overflow: the prompt fits the CLUSTER but not THIS
    // backend (live twice: an 11.6k-token conversation routed to host9's
    // 4096-ctx llama.cpp → hard 400, turn lost). The resolver has no
    // per-backend context knowledge, but the fallback loop already
    // excludes the failed backend and re-resolves — so classifying these
    // as retryable turns "hard failure on the small box" into "failover
    // to a bigger one", with the existing operator alert naming the
    // undersized backend. If every backend overflows, the attempt cap
    // still surfaces the real error.
    if status == 400 && is_context_overflow_body(body) {
        return true;
    }
    if !matches!(status, 502..=504) {
        return false;
    }
    // Node-agent proxy dial failures + generic bad-gateway/timeout markers.
    body.contains("backend_unreachable")
        || body.contains("node_agent_proxy_error")
        || body.contains("connection refused")
        || body.contains("timed out")
        || body.trim().is_empty() // bare 502/503/504 from an intermediary
}

/// Does this 4xx body describe a context-window overflow?
///
/// Markers from the engines we route to:
///   - llama.cpp: `"exceed_context_size_error"` /
///     "the request exceeds the available context size"
///   - vLLM: "This model's maximum context length is N tokens. However,
///     you requested M tokens"
///   - ollama: truncates instead of erroring (never reaches here)
pub(crate) fn is_context_overflow_body(body: &str) -> bool {
    let b = body.to_lowercase();
    b.contains("exceed_context_size")
        || (b.contains("context") && (b.contains("exceed") || b.contains("too long")))
        || b.contains("maximum context length")
}

/// Normalise a caller-supplied `model` into a routing hint.
///
/// `"default"` and `"auto"` are placeholders meaning "whatever the cluster is
/// configured to serve" — the dashboard's picker, the OpenAI-compat proxy and
/// `noo tasks` all render one of them when nothing is pinned. They are NOT
/// model names, and treating them as one is not a harmless no-op: a non-empty
/// `target_model` that matches nothing loses tier-0 of the candidate sort, so
/// the winner is decided by preferred-backend-type and load alone. On a
/// one-box install that is how `model: "default"` landed on the ollama serving
/// `harrier` (the embedder) and every chat 400'd with "does not support chat"
/// (host7, 2026-09-12). It also suppresses the user's saved model
/// preference and prompt-detected model upstream, both of which key off
/// `model.is_none()`.
///
/// Blank and whitespace-only get the same treatment.
pub(crate) fn model_hint(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|m| {
        !m.is_empty() && !m.eq_ignore_ascii_case("default") && !m.eq_ignore_ascii_case("auto")
    })
}

/// Check if a model name refers to a cloud-hosted model (Claude, GPT, Gemini).
/// Such a model resolves to a cloud backend ([`cloud_backend`]).
pub(crate) fn is_cloud_model(model: &str) -> bool {
    model.starts_with("claude-")
        || model.starts_with("gpt-")
        || model.starts_with("gemini-")
}

/// The backend a cloud model runs on: the provider's public endpoint, with
/// `backend_type` `cloud-anthropic` / `cloud-openai` / `cloud-gemini` and
/// `api_format` `anthropic` or `openai`.
///
/// The gate (`CLOUD_PROVIDERS_ENABLED`) is checked first and its refusal is
/// the typed `CloudGateClosed`, unchanged, so the routes' 403 mapping
/// (`cloud_gate_refusal`) still finds it; then the provider key, whose
/// absence is the plain "ANTHROPIC_API_KEY not configured — cloud model
/// unavailable" error.
pub(crate) fn cloud_backend(model: &str) -> Result<ResolvedBackend> {
    super::cloud::cloud_backend_with(model, super::cloud::cloud_gate(), super::cloud::env_key)
}

/// Is this a cloud-provider backend (public internet, provider auth, no
/// node behind it)?
pub(crate) fn is_cloud_backend(backend: &ResolvedBackend) -> bool {
    backend.backend_type.starts_with("cloud-")
}

/// Detect a model reference from natural language in the user prompt.
///
/// Matches phrases like "use gemma 4", "with llama", "try qwen", "on ollama"
/// against the models currently running in the cluster (from NATS KV).
/// Returns the full model name (e.g. "google/gemma-4-E4B-it") if found.
pub(super) async fn detect_model_from_prompt(state: &AppState, prompt: &str) -> Option<String> {
    let lower = prompt.to_lowercase();

    // Quick check: does the prompt contain a model-routing signal?
    let signals = ["use ", "with ", "try ", "via ", "on ", "switch to ", "using "];
    if !signals.iter().any(|s| lower.contains(s)) {
        return None;
    }

    // Collect all running model names from NATS KV
    let mut running_models: Vec<(String, String)> = Vec::new(); // (model_name, backend_type)
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        if let Ok(keys) = kv.keys().await {
            use tokio_stream::StreamExt;
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect::<Vec<String>>().await;
            for key in keys {
                if let Ok(Some(value)) = kv.get(&key).await {
                    if let Ok(data) = serde_json::from_slice::<Value>(&value) {
                        if let Some(backends) = data.get("running_backends").and_then(|b| b.as_object()) {
                            for (bt, model_val) in backends {
                                if let Some(m) = model_val.as_str() {
                                    if !m.is_empty() {
                                        running_models.push((m.to_string(), bt.clone()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if running_models.is_empty() {
        return None;
    }

    // Build match keywords from model names:
    // "google/gemma-4-E4B-it" → ["gemma-4", "gemma 4", "gemma4", "e4b"]
    // "Qwen/Qwen3-8B-AWQ" → ["qwen3", "qwen 3", "qwen3-8b"]
    for (model_name, _bt) in &running_models {
        let short = model_name.split('/').next_back().unwrap_or(model_name).to_lowercase();
        // Generate match variants from the short name
        let variants: Vec<String> = vec![
            short.clone(),
            short.replace('-', " "),
            short.replace('_', " "),
            // First segment before size suffix: "gemma-4-e4b-it" → "gemma-4", "gemma 4"
            short.split('-').take(2).collect::<Vec<_>>().join("-"),
            short.split('-').take(2).collect::<Vec<_>>().join(" "),
            // No separators: "gemma4"
            short.replace(['-', '_'], ""),
        ];

        for variant in &variants {
            if variant.len() >= 3 && lower.contains(variant.as_str()) {
                tracing::info!(
                    detected_model = %model_name,
                    matched_on = %variant,
                    prompt_excerpt = %crate::text::clip(prompt, 80),
                    "model_detected_from_prompt"
                );
                return Some(model_name.clone());
            }
        }
    }

    None
}

/// Resolve a backend URL.
///
/// As of 2026-04-30 (proposal #10 — node-agent inference proxy): for
/// Docker-service-name URLs (noo-vllm/noo-ollama/noo-llamacpp), we
/// route through the node's node-agent on port 8081 instead of the
/// backend's own port. Node-agent has the existing mTLS surface and
/// transparently forwards `/v1/chat/completions` etc. to its local
/// docker-network backend. The `backend_type` becomes a hint via
/// `X-Noo-Backend` header (set by the caller after this resolution),
/// not part of the URL — node-agent picks the local backend.
///
/// Why: backend containers (`noo-vllm:8000`, `noo-llamacpp:8085`) bind
/// only to their per-host docker network. Cross-host calls to those
/// ports always failed (Connection refused), causing silent fallback
/// to the controller's own noo-vllm. Node-agent (port 8081) is the
/// only port already exposed on each host, and is already mTLS-secured.
///
/// Local URLs (no `noo-*` Docker name pattern) pass through unchanged
/// — the gateway-on-controller can still reach `noo-vllm:8000` directly
/// on its own docker network.
/// Does this offer disagree with what the node itself last reported?
///
/// Returns `Some(reason)` to refuse, `None` to allow — including whenever
/// the gateway has nothing to check against, because "I cannot verify" is
/// not "I have caught you". The check is deliberately one-sided for that
/// reason: it can only ever turn a KNOWN contradiction into a refusal.
///
/// The record is `mesh_nodes[<node_id>].running_backends`, a map of backend
/// type to the model that backend is serving, written by the authenticated
/// `POST /api/cluster/heartbeat` handler (`routes/cluster.rs`).
async fn offer_contradicts_registry(
    offer: &mesh::router::BackendOffer,
    state: &AppState,
) -> Option<String> {
    let kv = state.js.get_key_value("mesh_nodes").await.ok()?;
    let entry = kv.get(&offer.node_id).await.ok()??;
    let data: Value = serde_json::from_slice(&entry).ok()?;
    let running = data.get("running_backends")?.as_object()?;
    if running.is_empty() {
        return None;
    }
    match running.get(&offer.backend_type).and_then(|v| v.as_str()) {
        // The node reported this backend serving this model. Agreed.
        Some(m) if m == offer.model => None,
        Some(m) => Some(format!(
            "node reports {} serving '{m}', the offer claims '{}'",
            offer.backend_type, offer.model
        )),
        None => Some(format!(
            "node reports no '{}' backend running (it has: {})",
            offer.backend_type,
            running.keys().cloned().collect::<Vec<_>>().join(", ")
        )),
    }
}

/// How often one node's "offer named a different address" line may be logged.
const OFFER_MISMATCH_LOG_WINDOW: std::time::Duration = std::time::Duration::from_secs(3600);

/// Host part of an offered URL (`scheme://host:port/path` -> `host`).
fn offered_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    if let Some(v6) = auth.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("");
    }
    auth.split(':').next().unwrap_or("")
}

/// Does the offer name the node's registered address? Host equality, not a
/// substring test (`10.0.0.1` must not match `10.0.0.12`).
fn offer_names_registered_ip(offered: &str, registered_ip: &str) -> bool {
    offered_host(offered) == registered_ip
}

/// The known pre-fix agent pattern: a docker service name (no dots, not an
/// IP) such as `noo-vllm` or `stunnel-ollama`, i.e. the backend's
/// container-internal URL. Expected from old agents in a mixed fleet.
fn is_container_service_offer(offered: &str) -> bool {
    let h = offered_host(offered);
    !h.is_empty() && !h.contains('.') && !h.contains(':') && h != "localhost"
}

/// Per-node rate limiter: true when `node` may log now, recording the time.
fn offer_mismatch_due(
    seen: &mut std::collections::HashMap<String, std::time::Instant>,
    node: &str,
    now: std::time::Instant,
    window: std::time::Duration,
) -> bool {
    match seen.get(node) {
        Some(prev) if now.duration_since(*prev) < window => false,
        _ => {
            seen.insert(node.to_string(), now);
            true
        }
    }
}

/// Log a disagreement between an offer and the registered address at most
/// once per node per hour; a container-service offer (old agent) is info,
/// anything else (a different IP: drift or an impostor) stays a warning.
fn note_offer_mismatch(node_id: &str, offered: &str, registered_ip: &str, using: &str) {
    if offer_names_registered_ip(offered, registered_ip) {
        return;
    }
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>> =
        std::sync::OnceLock::new();
    let due = {
        let mut seen = SEEN.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
        offer_mismatch_due(&mut seen, node_id, std::time::Instant::now(), OFFER_MISMATCH_LOG_WINDOW)
    };
    if !due {
        return;
    }
    if is_container_service_offer(offered) {
        tracing::info!(
            node = %node_id, offered = %offered, using = %using,
            "discovery offer carried a container-internal address (older node agent) — using the registered address"
        );
    } else {
        tracing::warn!(
            node = %node_id, offered = %offered, using = %using,
            "discovery offer named a different address than the node's registered one — using the registered address"
        );
    }
}

/// Where to actually send work for a discovery offer.
///
/// The offer's URL is ADVISORY, never authoritative. Mesh discovery is a
/// NATS request/reply: any process holding the (fleet-wide) NATS
/// credential can answer `mesh.inference.discover` and name whatever URL
/// it likes. Returning that verbatim let a responder redirect another
/// node's inference to itself and read every prompt and completion —
/// the design finding N2, and the reason this function now prefers the
/// address the gateway itself recorded.
///
/// `mesh_nodes` is written by the authenticated HTTP heartbeat, so it is
/// the gateway's own record of where a node lives. When it has an address
/// for `node_id`, that address wins and the offer's URL is ignored (a
/// disagreement is logged — it is either drift or someone answering for a
/// node that is not theirs).
///
/// Only when the gateway has NO record does the offer's URL get used, and
/// then only if it names a controller-local docker service, which cannot
/// point off-box.
async fn resolve_backend_url(gossip_url: &str, node_id: &str, backend_type: &str, state: &AppState) -> String {
    // The gateway's own record of this node, written by the authenticated
    // heartbeat rather than by whoever answered discovery.
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        if let Ok(Some(entry)) = kv.get(node_id).await {
            if let Ok(data) = serde_json::from_slice::<Value>(&entry) {
                if let Some(ip) = data.get("ip_address").and_then(|v| v.as_str()) {
                    if !ip.is_empty() {
                        // Node agents serve mTLS only (no plaintext listener exists).
                        let proto = "https";
                        // Node-agent always on port 8081, regardless of
                        // which backend is being targeted. The
                        // X-Noo-Backend header tells node-agent which
                        // local backend to dispatch to.
                        let _hint = backend_type; // documents intent for the caller
                        let resolved = format!("{proto}://{ip}:8081");
                        note_offer_mismatch(node_id, gossip_url, ip, &resolved);
                        return resolved;
                    }
                }
            }
        }
    }

    // No registered address. Accept the offer's URL only if it names a
    // controller-local docker service — those resolve on the controller's
    // own network and cannot point at another host.
    let is_local_docker_service = gossip_url.contains("noo-vllm")
        || gossip_url.contains("noo-ollama")
        || gossip_url.contains("noo-llamacpp")
        || gossip_url.contains("noo-stunnel-llamacpp");
    if is_local_docker_service {
        return gossip_url.to_string();
    }
    tracing::warn!(
        node = %node_id, offered = %gossip_url,
        "discovery offer for a node with no registered address, and the URL is not a controller-local service — refusing to dial it"
    );
    String::new()
}

/// The unpinned choice from the class table, or `None` when the table has
/// nothing routable (fall through to discovery / the static last resort).
async fn unpinned_from_table(state: &AppState, exclude_urls: &[String]) -> Option<(ResolvedBackend, Option<String>)> {
    let table = match super::classes::load_table(state).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "backend_resolve_class_table_unavailable");
            return None;
        }
    };
    let sel = pick_unpinned(&table, exclude_urls)?;
    let best = sel.candidates.first()?;
    if sel.last_resort {
        tracing::warn!(class = %sel.label, node = %best.node_id, "backend_resolved_only_excluded_candidates_left");
    }
    tracing::info!(
        class = %sel.label,
        node = %best.node_id, backend = %best.backend, model = %best.model,
        url = %best.url, rank = %best.rank,
        candidates = sel.candidates.len(), skipped = ?sel.skipped,
        source = "class_table",
        "backend_resolved"
    );
    Some((
        ResolvedBackend {
            url: best.url.clone(),
            model: best.model.clone(),
            api_format: detect_api_format_for_url(&best.backend, Some(&best.url)),
            backend_type: best.backend.clone(),
        },
        Some(best.node_id.clone()),
    ))
}

/// The unpinned selection minus backends that already failed this request.
/// `exclude_urls` holds `ResolvedBackend.url` values — the candidate's own
/// `url` (node-agent address, or the controller-local docker URL) — so a
/// failed node's every backend is out, as the KV scan always did.
pub(crate) fn pick_unpinned(table: &super::classes::ClassTable, exclude_urls: &[String]) -> Option<super::classes::Selection> {
    super::classes::select(table, None, None, false, &|c| exclude_urls.iter().any(|u| u == &c.url)).ok()
}

/// Resolve a backend using the mesh discovery chain.
/// Resolve backend using config defaults (for coordinator brain).
pub(super) async fn resolve_backend_excluding(state: &AppState, requested_model: Option<&str>, exclude_urls: &[String]) -> Result<ResolvedBackend> {
    resolve_backend_and_node(state, requested_model, exclude_urls).await.map(|(b, _)| b)
}

pub async fn resolve_backend(state: &AppState) -> Result<ResolvedBackend> {
    resolve_backend_for_model(state, None).await
}

/// One backend a node reports serving, as the chat resolver sees it.
/// `excluded` = its node already failed this request (see `exclude_urls`).
struct Candidate {
    node_id: String,
    backend_type: String,
    model_name: String,
    url: String,
    load: f64,
    excluded: bool,
}

/// Has this backend already failed the current request? `exclude_urls` holds
/// `ResolvedBackend.url` values, which for a registered node are
/// `https://<ip>:8081`; `local_url` (the docker-service name) is compared too
/// for the controller-local case. Comparing only `local_url` meant a failure
/// never excluded anything, so the retry re-resolved the same dead backend.
fn is_excluded(exclude_urls: &[String], local_url: &str, node_ip: &str) -> bool {
    exclude_urls.iter().any(|u| {
        u == local_url || (!node_ip.is_empty() && u == &format!("https://{node_ip}:8081"))
    })
}

/// Does a served model name satisfy a pin? Ollama reports `name:tag` and
/// treats a missing tag as `:latest`, so `gemma4` and `gemma4:latest` are one
/// model; case is not significant in either runtime's naming.
pub(crate) fn model_matches_pin(served: &str, pin: &str) -> bool {
    fn norm(m: &str) -> String {
        let m = m.trim().to_ascii_lowercase();
        m.strip_suffix(":latest").map(str::to_string).unwrap_or(m)
    }
    norm(served) == norm(pin)
}

/// The caller named a model nothing reachable serves.
///
/// Typed so the routes can answer 404 (the OpenAI `model_not_found` status)
/// instead of a 500/503 that reads as a broken gateway. The wording family is
/// `model 'X' is not served by any node; ...` on every path that can produce
/// it: the KV-scan filter (`apply_pin`), and the static/discovery paths, where
/// the gateway does not know what the backend holds and learns it from the
/// backend's own refusal (`backend_model_not_found`).
#[derive(Debug)]
pub struct ModelNotServed(pub String);

impl std::fmt::Display for ModelNotServed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ModelNotServed {}

fn not_served_prefix(pin: &str) -> String {
    format!("model '{pin}' is not served by any node")
}

/// The HTTP status a failed backend resolution should carry: 404 for a pin
/// nothing serves, otherwise the caller's `fallback` (503 on the raw routes).
pub fn resolve_failure_status(e: &anyhow::Error, fallback: u16) -> u16 {
    if e.downcast_ref::<ModelNotServed>().is_some() { 404 } else { fallback }
}

/// Turn a backend's own "that model does not exist" answer into the refusal a
/// pinned caller should see, or `None` when the 404 is about something else.
///
/// The static `OLLAMA_URL` and discovery paths resolve without knowing what
/// the backend holds, so a pin of an unpulled model used to reach the backend
/// and come back as `Backend error: 404 ...` -> HTTP 500 (v0.2.87 rehearsal,
/// 2026-10-03). Asking the backend instead (`/api/tags`) would add a network
/// call to every request; its refusal costs nothing and is authoritative.
///
/// Shapes recognised: Ollama `{"error":"model 'x' not found"}` and vLLM
/// `{"message":"The model `x` does not exist."}`. A bare `404 page not found`
/// / `{"detail":"Not Found"}` (wrong URL, missing route) names no model and
/// is deliberately NOT mapped: calling a mis-pointed OLLAMA_URL "model not
/// served" would send the operator to pull a model instead of fixing the URL.
pub fn backend_model_not_found(status: u16, body: &str, pin: &str, backend_url: &str) -> Option<ModelNotServed> {
    if status != 404 {
        return None;
    }
    let b = body.to_lowercase();
    if !b.contains("model") || !(b.contains("not found") || b.contains("does not exist")) {
        return None;
    }
    Some(ModelNotServed(format!(
        "{}; the backend at {backend_url} does not have it. \
         Pull it (noo models pull) or pick a served model",
        not_served_prefix(pin)
    )))
}

/// Apply an explicit model pin to the candidate list: keep only the backends
/// that serve it, and refuse - naming who serves what - when none does.
///
/// The pin used to be only the first key of the sort, so with the serving
/// node out of the list (down, or failed earlier in the request) the next
/// candidate won whatever it served, and the caller got a different model
/// than the one named, or an opaque "All viable backends
/// failed" (2026-10-02, `gemma4:e2b-it-qat` served only by Ollama on host8
/// and host8-ma). Same rule as jobs (`backend_unserved_reason`): work goes to
/// a node serving what was asked for, or is refused saying who serves what.
///
/// `Ok(())` leaves `all` filtered to the serving, non-excluded candidates.
fn apply_pin(all: &mut Vec<Candidate>, pin: &str) -> Result<(), String> {
    let serves = |c: &Candidate| model_matches_pin(&c.model_name, pin);
    if !all.iter().any(serves) {
        let who = all
            .iter()
            .map(|c| format!("{}={}:{}", c.node_id, c.backend_type, c.model_name))
            .collect::<Vec<_>>()
            .join(" ");
        return Err(format!(
            "{}; nodes serve: {who}. \
             Place it (noo models switch / place) or pick a served model",
            not_served_prefix(pin)
        ));
    }
    all.retain(|c| serves(c));
    if all.iter().all(|c| c.excluded) {
        let who = all.iter().map(|c| format!("{}={}", c.node_id, c.backend_type)).collect::<Vec<_>>().join(" ");
        return Err(format!(
            "every node serving '{pin}' failed this request ({who}) and no other node can answer"
        ));
    }
    all.retain(|c| !c.excluded);
    Ok(())
}

/// The chat resolver's ranking key, lowest wins: exact model, then preferred
/// backend type, then under-the-ceiling, then raw load.
///
/// A function rather than four inline tuples so the ORDER can be tested. The
/// ordering is what failed live, and nothing asserted it.
fn sort_key(exact_model: bool, preferred_type: bool, load: f64) -> (i32, i32, i32, i64) {
    (
        if exact_model { 0 } else { 1 },
        if preferred_type { 0 } else { 1 },
        busy_rank(load),
        // Integer for Ord; x100 because the scale is 0.0–1.0.
        (load * 100.0) as i64,
    )
}

/// Tier 2 of the chat sort: is this node at or above the load ceiling?
///
/// It read `load >= 80.0` while nodes report 0.0–1.0, so it evaluated false for
/// every node that has ever reported and the tier never fired — while the doc
/// comment promised that a busy node was deprioritized. The two faults were
/// survivable only together: with no node advertising a held model (the
/// `SetHeld` instance bug), tier 0 tied for everyone, this tier could not fire,
/// and the decision fell through to preferred backend type — which picked a
/// Raspberry Pi at 98% load over an idle GPU box, where the request then died
/// with no answer and no error.
fn busy_rank(load: f64) -> i32 {
    if load >= crate::scheduler_candidates::LOAD_CEILING {
        1
    } else {
        0
    }
}

/// The reported load, with a LOUD complaint if it is not on the 0.0–1.0 scale.
///
/// A producer that switched to percent would silently re-break every threshold
/// in the gateway rather than failing a test, because 98.0 is a perfectly valid
/// f64. Clamping would hide it; refusing the node would turn a reporting change
/// into an outage. So it is reported and then clamped to the ceiling, which
/// keeps routing working while making the mismatch impossible to miss.
fn scale_checked_load(node_key: &str, load: f64) -> f64 {
    if load > 1.5 {
        tracing::warn!(
            node = %node_key,
            load,
            "node_load_out_of_scale — load is normalised 0.0–1.0 (load average / cores). \
             A value above 1.5 means a producer is reporting a PERCENTAGE, which makes every \
             load threshold in the gateway wrong. Treating it as fully loaded for now."
        );
        return crate::scheduler_candidates::LOAD_CEILING;
    }
    load.max(0.0)
}

/// Resolve a backend, optionally targeting a specific model.
///
/// Routing:
///   * no model: the class table's `chat-default` — every live chat node,
///     ranked (`classes::rank_key`), or the declared list — exactly what
///     unpinned raw chat picks;
///   * a model: only the nodes serving it (`apply_pin`), then preferred
///     backend type, then lowest load (from heartbeat data).
///
/// Load-aware: a node at or above `LOAD_CEILING` (0.9 of one core's worth of
/// load average per core) is deprioritized, not excluded.
pub async fn resolve_backend_for_model(state: &AppState, requested_model: Option<&str>) -> Result<ResolvedBackend> {
    resolve_backend_excluding(state, requested_model, &[]).await
}

/// (node_id, backend_type) pairs whose placement declares a non-chat role.
///
/// Sourced from desired state (`noo_backend_placements.role`), NOT from what
/// the node reports: the node only knows it is running "ollama", not whether
/// that ollama is serving a chat model or an embedder. Reading desired state
/// also means no node-agent change and no fleet roll to make this work.
///
/// Cached briefly — this sits on the inference hot path and roles change at
/// operator speed, not request speed. A stale entry costs at most one
/// CACHE_TTL window of the old routing behaviour.
pub(crate) async fn non_chat_backends(state: &AppState) -> Result<HashSet<(String, String)>> {
    const CACHE_TTL: Duration = Duration::from_secs(30);
    static CACHE: OnceLock<Mutex<Option<(Instant, HashSet<(String, String)>)>>> = OnceLock::new();

    let cell = CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cell.lock() {
        if let Some((at, ref set)) = *guard {
            if at.elapsed() < CACHE_TTL {
                return Ok(set.clone());
            }
        }
    }

    let fetched = crate::repo::cluster::placements_non_chat(&state.db).await;
    let cached = cell
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|(_, set)| set.clone()));

    match purpose_map_after_refresh(fetched.map(|rows| rows.into_iter().collect()), cached) {
        PurposeMap::Fresh(set) => {
            if let Ok(mut guard) = cell.lock() {
                *guard = Some((Instant::now(), set.clone()));
            }
            Ok(set)
        }
        PurposeMap::Stale(set) => {
            // Deliberately NOT re-stamping the cache: the next request
            // retries the database instead of trusting stale data for a
            // full TTL window. The extra failed query per request during a
            // DB blip is the price of converging back the moment it heals.
            tracing::warn!(
                entries = set.len(),
                "non_chat_placements_db_error_serving_stale"
            );
            Ok(set)
        }
        PurposeMap::Unavailable => Err(anyhow::anyhow!(
            "backend purpose map unavailable: placements query failed with no \
             cached copy — refusing to route rather than admit embed/rerank \
             backends into the chat pool"
        )),
    }
}

/// What purpose map to serve after a refresh attempt.
///
/// A database error must NEVER collapse to an empty set: empty reads as "no
/// non-chat placements", which silently readmits embed/rerank backends into
/// chat routing (the #247 silent-failure class — routing at an embedder is a
/// hard 400 that background tasks never surface). Stale beats
/// wrong-by-omission, and cold-start-with-no-DB refuses loudly instead.
enum PurposeMap {
    Fresh(HashSet<(String, String)>),
    Stale(HashSet<(String, String)>),
    Unavailable,
}

fn purpose_map_after_refresh(
    fetched: Result<HashSet<(String, String)>, sqlx::Error>,
    cached: Option<HashSet<(String, String)>>,
) -> PurposeMap {
    match (fetched, cached) {
        (Ok(set), _) => PurposeMap::Fresh(set),
        (Err(_), Some(set)) => PurposeMap::Stale(set),
        (Err(_), None) => PurposeMap::Unavailable,
    }
}


/// Core backend resolution with an exclusion list for retry-on-failure.
///
/// `exclude_urls` contains URLs of backends that already failed — they're
/// filtered out so the coordinator tries the next candidate.
/// The backend for a model AND the node it lives on, when the resolver knows.
///
/// `Some(node)` when the candidate came from a node's own gossip entry —
/// the resolver had the node id in hand the whole time. `None` for a
/// discovery offer or a controller-local static backend. The dispatcher
/// used to throw this away and re-derive the node from the URL's HOST,
/// which is an address: with two `noo_node_config` rows sharing the
/// controller's IP (`host8` and a stale `host8`), a lookup by address
/// picked the stale one and reported "node 'host8' has no harness"
/// (2026-09-22, the second turn ever dispatched). A name the resolver
/// already had was replaced by a guess at it.
pub(crate) async fn resolve_backend_and_node(state: &AppState, requested_model: Option<&str>, exclude_urls: &[String]) -> Result<(ResolvedBackend, Option<String>)> {
    // Last line of defence for callers that reach the resolver without going
    // through an entry point that already normalised (the rail, dispatch,
    // `/api/external/*`). See [`model_hint`].
    let requested_model = model_hint(requested_model);
    // A cloud model is served by its provider, not by a node: no placement,
    // no node, and nothing to exclude — a failed provider is reported, never
    // replaced by a node backend (see `send_llm_with_fallback`).
    if let Some(m) = requested_model.filter(|m| is_cloud_model(m)) {
        return cloud_backend(m).map(|b| (b, None));
    }
    let config = &state.config;
    let preferred = &config.cluster.default_backend;
    let default_model = config.cluster.backends
        .get(preferred.as_str())
        .map(|b| b.model.clone())
        .unwrap_or_default();

    // Unpinned (heartbeat tasks, agent turns with no model and no saved
    // preference): the SAME choice raw chat makes — the class table's
    // `chat-default` (dynamic: every live chat node, ranked by quality,
    // health, thermal, stalls, load; or the operator's declaration), so a
    // task and a chat request agree on where "default" goes. The yaml's
    // `cluster.backends.<x>.model` is not consulted: it is a placement
    // hint, and ranking it first sent every unpinned turn to the
    // controller's CPU e2b while a 12B GPU node idled (2026-10-17).
    // Discovery and the static OLLAMA_URL below stay the last resorts.
    if requested_model.is_none() {
        if let Some(found) = unpinned_from_table(state, exclude_urls).await {
            return Ok(found);
        }
    }

    // The target model: an explicit request only. The configured default
    // model is no longer a sort key (see above); it remains the model of
    // the static last resort.
    let target_model = requested_model.unwrap_or("");

    // 1. NATS KV (authoritative — populated by real node heartbeats)
    let inference_types = ["vllm", "vllm-secondary", "ollama", "llamacpp"];

    // Container type alone does NOT mean a backend can serve chat. `ollama`
    // is a general runtime: one instance may host a chat model, another an
    // embedding model. Routing chat at the latter is a hard 400, not a
    // fallback —
    //   llm_http_error 400 "harrier" does not support chat
    //   llm_all_backends_failed
    // — and on a background task nobody sees it. So consult the desired
    // state, where the operator declared what each backend is FOR, and drop
    // anything not serving `chat`. Placements default to 'chat', so this is
    // a no-op for every backend not explicitly marked otherwise.
    let non_chat = non_chat_backends(state).await?;

    let mut candidates: Vec<Candidate> = Vec::new();

    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        if let Ok(keys) = kv.keys().await {
            use tokio_stream::StreamExt;
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect::<Vec<String>>().await;
            for key in keys {
                if let Ok(entry) = kv.get(&key).await {
                    if let Some(value) = entry {
                        if let Ok(data) = serde_json::from_slice::<Value>(&value) {
                            let node_load = data.get("load")
                                .and_then(|l| l.as_f64())
                                .map(|l| scale_checked_load(&key, l))
                                .unwrap_or(0.0);

                            let backends = data.get("running_backends")
                                .or_else(|| data.get("backends"))
                                .and_then(|b| b.as_object());
                            if let Some(backends) = backends {
                                for (bt, model_val) in backends {
                                    if !inference_types.contains(&bt.as_str()) { continue; }
                                    let m = model_val.as_str().unwrap_or("");
                                    if !m.is_empty() {
                                        let node_id = data.get("id")
                                            .and_then(|i| i.as_str())
                                            .unwrap_or(&key)
                                            .to_string();
                                        // Declared for embed/rerank, not chat.
                                        if non_chat.contains(&(node_id.clone(), bt.clone())) {
                                            // WARN, not debug: this is a routing
                                            // decision. At prod log level a
                                            // debug line is invisible, so a
                                            // backend vanishing from the chat
                                            // pool looks identical to it never
                                            // having been there.
                                            tracing::warn!(
                                                node = %node_id, backend = %bt,
                                                "backend_skipped_non_chat_role"
                                            );
                                            continue;
                                        }
                                        // Up, but the node reports it does not hold the
                                        // placed model.
                                        if crate::model_presence::backend_model_missing(&data, bt) {
                                            tracing::warn!(node = %node_id, backend = %bt, "backend_skipped_model_missing");
                                            continue;
                                        }
                                        let port = match backend_port(bt.as_str()) {
                                            Some(p) => p,
                                            None => continue,
                                        };
                                        let url = local_backend_url(bt, port);
                                        // The address the dispatcher will record as
                                        // `ResolvedBackend.url` for this node. Failed
                                        // backends are remembered by it, so exclusion
                                        // has to compare against it: `url` is the same
                                        // docker name for every node's ollama, and
                                        // never equals a dialled node-agent address.
                                        let ip = data.get("ip_address").and_then(|v| v.as_str()).unwrap_or("");
                                        // Failed on a previous attempt of this request.
                                        let excluded = is_excluded(exclude_urls, &url, ip);
                                        candidates.push(Candidate {
                                            node_id,
                                            backend_type: bt.clone(),
                                            model_name: m.to_string(),
                                            url,
                                                                            load: node_load,
                                            excluded,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // A named model is a preference (operator rule 2026-10-19, see
    // `classes`' "Preferences, not selections"): its own nodes first; when
    // none of them can take this request (not served, or every one already
    // failed it), any live chat node answers, as raw chat does. Only when
    // the mesh reported backends at all - an empty list still falls through
    // to discovery and the static last resort below, as before.
    if let (Some(pin), false) = (requested_model, candidates.is_empty()) {
        if let Err(e) = apply_pin(&mut candidates, pin) {
            if let Some(found) = unpinned_from_table(state, exclude_urls).await {
                tracing::warn!(requested_model = pin, reason = %e, node = ?found.1, model = %found.0.model, "backend_preference_unmet_mesh_answers");
                return Ok(found);
            }
            return Err(if e.starts_with(&not_served_prefix(pin)) { anyhow::Error::new(ModelNotServed(e)) } else { anyhow::anyhow!(e) });
        }
    } else {
        candidates.retain(|c| !c.excluded);
    }

    if !candidates.is_empty() {
        // Sort by: exact model match → preferred backend → lower load
        candidates.sort_by(|a, b| {
            // Tier 0: exact model match (user requested specific model)
            let a_exact = if !target_model.is_empty() && a.model_name == target_model { 0 } else { 1 };
            let b_exact = if !target_model.is_empty() && b.model_name == target_model { 0 } else { 1 };
            // Tier 1: preferred backend type
            let a_backend = if a.backend_type == *preferred { 0 } else { 1 };
            let b_backend = if b.backend_type == *preferred { 0 } else { 1 };
            sort_key(a_exact == 0, a_backend == 0, a.load)
                .cmp(&sort_key(b_exact == 0, b_backend == 0, b.load))
        });
        let best = &candidates[0];
        // The candidate URL was built using the LOCAL Docker service name
        // (noo-vllm, noo-llamacpp) regardless of which node owns the
        // backend. Rewrite to the actual node IP if the chosen backend
        // lives on a remote node — otherwise the call hits the controller's
        // local service (which usually doesn't have that backend running)
        // and falls back to the default backend, masking the user's choice.
        let resolved_url = resolve_backend_url(&best.url, &best.node_id, &best.backend_type, state).await;
        tracing::info!(
            node = %best.node_id, backend = %best.backend_type,
            model = %best.model_name,
            url = %resolved_url,
            gossip_url = %best.url,
            load = best.load, candidates = candidates.len(),
            requested_model = ?requested_model,
            source = "nats_kv",
            "backend_resolved"
        );
        return Ok((ResolvedBackend {
            url: resolved_url.clone(),
            model: best.model_name.clone(),
            api_format: detect_api_format_for_url(&best.backend_type, Some(&resolved_url)),
            backend_type: best.backend_type.clone(),
        }, Some(best.node_id.clone())));
    }

    // 2. Mesh discovery via NATS request/reply (asks nodes directly)
    if let Ok(Some(offer)) = mesh::router::discover_backend(
        &state.nats,
        if target_model.is_empty() { None } else { Some(target_model) },
        Some(preferred),
    ).await {
        // Same docker-service-name → node-IP rewrite as the nats_kv path
        // above. Mesh discovery returns whatever URL the responder
        // advertised; if that's a local Docker name, it won't resolve
        // for the gateway calling it.
        let resolved_url = resolve_backend_url(&offer.url, &offer.node_id, &offer.backend_type, state).await;
        // Empty means the offer could not be resolved to an address the
        // gateway itself recorded, and its URL was not controller-local —
        // so it is either stale or someone answering for a node that is
        // not theirs. Fall through to the remaining resolution paths
        // rather than returning a backend that cannot be dialled.
        if resolved_url.is_empty() {
            tracing::warn!(node = %offer.node_id, "discarding an unresolvable discovery offer");
        } else if let Some(why) = offer_contradicts_registry(&offer, state).await {
            // `mesh.inference.discover` is a queue-subscribed
            // request/reply: whichever node answers first wins, and the
            // reply names its own node_id, backend and model. N2 stopped
            // the URL being trusted; the MODEL claim was still taken at
            // face value, so a node could win discovery for a model it does
            // not serve and be handed those prompts.
            //
            // Per-node bus credentials make the responder's IDENTITY
            // trustworthy — `node-<id>` can only publish as itself — so the
            // claim can now be checked against the gateway's own record.
            // `running_backends` in the `mesh_nodes` KV is written by the
            // authenticated HTTP heartbeat, not by whoever answered here.
            //
            // Only a CONTRADICTION is refused. A node with no KV record
            // yet, or a record with no backend inventory, falls through to
            // the paths below exactly as before: a gateway with nothing to
            // compare against must not start refusing work it used to do.
            tracing::warn!(
                node = %offer.node_id, model = %offer.model, backend = %offer.backend_type,
                reason = %why,
                "discarding a discovery offer that contradicts the node's own heartbeat"
            );
        } else {
        tracing::info!(
            node = %offer.node_id, backend = %offer.backend_type,
            model = %offer.model,
            url = %resolved_url,
            gossip_url = %offer.url,
            source = "mesh_discover",
            "backend_resolved"
        );
        // A discovery offer names a URL, not a node; the dispatcher resolves
        // the address only in this case, and refuses if it is ambiguous.
        return Ok((ResolvedBackend {
            url: resolved_url.clone(),
            model: offer.model,
            api_format: detect_api_format_for_url(&offer.backend_type, Some(&resolved_url)),
            backend_type: offer.backend_type,
        }, None));
        }
    }

    // Retired (#116): a fourth "Python auto-start via NATS" branch published
    // worker.backend.auto_start — no handler with that subject ever existed,
    // so the 30s request only delayed the honest failure below.
    // Static last resort (standalone controllers, 2026-09-02): the single
    // `ollama-embed` container serves chat AND embeddings on a one-box
    // install, but the node agent deliberately never reports a container
    // with "embed" in its name as a chat backend, so the mesh scan above
    // finds nothing and every chat channel failed with "No backend
    // available" while `noo channels status` looked healthy. Mirror the
    // embedding client's static-endpoint fallback: when the mesh has no
    // chat backend, use the configured OLLAMA_URL with the configured
    // default model. A real mesh backend always wins (it returned above).
    let static_url = std::env::var("OLLAMA_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| config.services.ollama_url.clone().filter(|v| !v.trim().is_empty()))
        .map(|u| u.trim_end_matches('/').to_string());
    if let Some(url) = static_url {
        if !exclude_urls.iter().any(|u| u == &url) {
            let model = if target_model.is_empty() { default_model.clone() } else { target_model.to_string() };
            if model.is_empty() {
                anyhow::bail!(
                    "No mesh backend and the static ollama at {url} has no model configured — \
                     set cluster.backends.ollama.model (noo onboard --only model)"
                );
            }
            tracing::info!(
                url = %url, model = %model, source = "static_ollama_url",
                "backend_resolved"
            );
            return Ok((ResolvedBackend {
                api_format: detect_api_format_for_url("ollama", Some(&url)),
                url,
                model,
                backend_type: "ollama".to_string(),
            }, None));
        }
    }

    anyhow::bail!("No backend available — check cluster status (no mesh backend, and OLLAMA_URL is unset)")
}

// ═══════════════════════════════════════════════════════════════
// Context injection (RAG + memory via NATS workers)
// ═══════════════════════════════════════════════════════════════

/// Get the NATS subject for delegating a tool call (public for tools.rs).
/// Reads from the cached tools.json data in AppState.
pub async fn get_tool_nats_subject(state: &AppState, tool_name: &str) -> String {
    let data = state.tools_json_raw.read().await;
    if let Some(tools) = data.get("core_tools").and_then(|t| t.as_array()) {
        for tool in tools {
            if tool.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()) == Some(tool_name) {
                if let Some(subject) = tool.get("nats_subject").and_then(|s| s.as_str()) {
                    return subject.to_string();
                }
            }
        }
    }
    "worker.tool.generic".to_string()
}

// ═══════════════════════════════════════════════════════════════
// Context injection helpers (Phase 6: reorder, dedup, metrics)
// ═══════════════════════════════════════════════════════════════

/// Load user-specific model preference from the cached YAML config.
/// Reads `preferences.preferred_model` from state.config_yaml.
/// Falls back to None if no preference is set.
pub(super) async fn fetch_user_model_preference(
    state: &AppState,
    user_id: &str,
) -> Option<String> {
    if user_id.is_empty() {
        return None;
    }
    let config = state.config_yaml.read().await;
    config
        .get("preferences")
        .and_then(|prefs| prefs.get("preferred_model"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Node attribution for token-usage accounting: the host part
/// of a resolved backend URL, which for remote backends is the node's
/// address. `localhost`/`127.0.0.1` mean the controller itself — mapped to
/// this container's `NODE_ID` (falling back to "controller") so local rows
/// group under a real node name instead of a loopback literal.
pub(crate) fn node_from_backend_url(url: &str) -> Option<String> {
    let rest = url.split("://").last().unwrap_or(url);
    let host = rest.split([':', '/']).next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    if host == "localhost" || host == "127.0.0.1" {
        return std::env::var("NODE_ID")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| Some("controller".to_string()));
    }
    Some(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::{is_container_service_offer, offer_mismatch_due, offer_names_registered_ip};

    #[test]
    fn offer_naming_registered_address_matches() {
        assert!(offer_names_registered_ip("https://192.0.2.1:8081", "192.0.2.1"));
        assert!(!offer_names_registered_ip("https://192.0.2.12:8081", "192.0.2.1"));
        assert!(!offer_names_registered_ip("https://noo-vllm:8000", "192.0.2.1"));
    }

    #[test]
    fn container_service_offer_is_the_old_agent_pattern() {
        assert!(is_container_service_offer("https://noo-vllm:8000"));
        assert!(is_container_service_offer("https://noo-stunnel-ollama:11434"));
        assert!(!is_container_service_offer("https://198.51.100.7:8081"));
        assert!(!is_container_service_offer("https://evil.example:8081"));
    }

    #[test]
    fn offer_mismatch_logs_once_per_node_per_window() {
        use std::time::{Duration, Instant};
        let mut seen = std::collections::HashMap::new();
        let t0 = Instant::now();
        let w = Duration::from_secs(3600);
        assert!(offer_mismatch_due(&mut seen, "host3", t0, w));
        assert!(!offer_mismatch_due(&mut seen, "host3", t0 + Duration::from_secs(60), w));
        assert!(offer_mismatch_due(&mut seen, "host8", t0 + Duration::from_secs(60), w), "per node");
        assert!(offer_mismatch_due(&mut seen, "host3", t0 + w, w), "window elapsed");
    }

    // ── an explicit model pin is a filter ─────

    fn cand(node: &str, bt: &str, model: &str, excluded: bool) -> Candidate {
        Candidate {
            node_id: node.into(),
            backend_type: bt.into(),
            model_name: model.into(),
            url: format!("https://noo-{bt}:1"),
            load: 0.0,
            excluded,
        }
    }

    const PIN: &str = "gemma4:e2b-it-qat";
    const HF: &str = "google/gemma-4-12B-it-qat-w4a16-ct";

    #[test]
    fn a_pin_keeps_only_the_nodes_serving_it() {
        let mut all = vec![cand("host3", "vllm", HF, false), cand("host8", "ollama", PIN, false), cand("host8-ma", "ollama", PIN, false)];
        apply_pin(&mut all, PIN).unwrap();
        let nodes: Vec<&str> = all.iter().map(|c| c.node_id.as_str()).collect();
        assert_eq!(nodes, ["host8", "host8-ma"], "the vLLM default must not stay in the pool");
    }

    #[test]
    fn a_failed_server_hands_over_to_the_other_server_never_to_another_model() {
        let mut all = vec![cand("host3", "vllm", HF, false), cand("host8", "ollama", PIN, true), cand("host8-ma", "ollama", PIN, false)];
        apply_pin(&mut all, PIN).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].node_id, "host8-ma");
    }

    #[test]
    fn when_every_server_failed_it_refuses_instead_of_substituting() {
        let mut all = vec![cand("host3", "vllm", HF, false), cand("host8", "ollama", PIN, true), cand("host8-ma", "ollama", PIN, true)];
        let err = apply_pin(&mut all, PIN).unwrap_err();
        assert!(err.contains("every node serving") && err.contains("host8") && err.contains("host8-ma"), "{err}");
    }

    #[test]
    fn an_unserved_pin_names_who_serves_what() {
        let mut all = vec![cand("host3", "vllm", HF, false), cand("host8", "ollama", "llama3.2:1b", false)];
        let err = apply_pin(&mut all, PIN).unwrap_err();
        assert!(err.contains(PIN) && err.contains(&format!("host3=vllm:{HF}")) && err.contains("host8=ollama:llama3.2:1b"), "{err}");
    }

    // ── the static / discovery paths learn it from the backend (168) ──────

    #[test]
    fn a_backends_model_not_found_becomes_the_refusal() {
        // Ollama, as the v0.2.87 rehearsal saw it.
        let ollama = r#"{"error":"model 'nonexistent-model:1b' not found"}"#;
        let r = backend_model_not_found(404, ollama, "nonexistent-model:1b", "http://ollama:11434").expect("ollama 404");
        assert!(r.0.starts_with("model 'nonexistent-model:1b' is not served by any node"), "{}", r.0);
        assert!(r.0.contains("http://ollama:11434") && r.0.contains("noo models pull"), "{}", r.0);
        // vLLM.
        let vllm = r#"{"object":"error","message":"The model `x` does not exist.","type":"NotFoundError","code":404}"#;
        assert!(backend_model_not_found(404, vllm, "x", "http://vllm:8000").is_some());
        // Same wording family as the KV-path filter.
        let mut all = vec![cand("host3", "vllm", HF, false)];
        let kv = apply_pin(&mut all, "x").unwrap_err();
        assert!(kv.starts_with(&not_served_prefix("x")), "{kv}");
        // A typed error: the routes answer 404 for it, the fallback otherwise.
        let e = anyhow::Error::new(r);
        assert_eq!(resolve_failure_status(&e, 503), 404);
        assert_eq!(resolve_failure_status(&anyhow::anyhow!("No backend available"), 503), 503);
    }

    #[test]
    fn a_404_that_is_not_about_a_model_is_not_mapped() {
        // Wrong URL / missing route: fix the URL, do not pull a model.
        assert!(backend_model_not_found(404, "404 page not found", "m", "http://u").is_none());
        assert!(backend_model_not_found(404, r#"{"detail":"Not Found"}"#, "m", "http://u").is_none());
        assert!(backend_model_not_found(404, "", "m", "http://u").is_none());
        // Right words, wrong status.
        assert!(backend_model_not_found(500, "model 'm' not found", "m", "http://u").is_none());
        assert!(backend_model_not_found(400, "model 'm' does not exist", "m", "http://u").is_none());
    }

    #[test]
    fn an_ollama_latest_tag_is_the_same_model() {
        assert!(model_matches_pin("gemma4:latest", "gemma4"));
        assert!(model_matches_pin("gemma4", "Gemma4:latest"));
        assert!(!model_matches_pin("gemma4:e2b-it-qat", "gemma4"));
    }

    #[test]
    fn a_failed_node_is_excluded_by_the_address_the_dispatcher_recorded() {
        // `ResolvedBackend.url` for a registered node is its node-agent
        // address; the candidate's own `url` is the docker name, so the old
        // comparison never matched and the retry re-picked the dead node.
        let failed = vec!["https://100.64.0.12:8081".to_string()];
        assert!(is_excluded(&failed, "https://noo-stunnel-ollama:11434", "100.64.0.12"));
        assert!(!is_excluded(&failed, "https://noo-stunnel-ollama:11434", "100.64.0.14"));
        assert!(!is_excluded(&failed, "https://noo-stunnel-ollama:11434", ""));
        assert!(is_excluded(&["https://noo-vllm:8000".to_string()], "https://noo-vllm:8000", ""));
    }
    use super::{apply_pin, backend_model_not_found, not_served_prefix, resolve_failure_status, busy_rank, is_excluded, model_matches_pin, scale_checked_load, sort_key, Candidate};

    // ── the chat resolver's ranking ────────────────────────
    //
    // Tier 2 read `load >= 80.0` while nodes report 0.0–1.0, so it evaluated
    // false for every node that has ever reported: the tier never fired, and
    // the doc comment promised it did. What the fleet saw was a chat request
    // routed to a Raspberry Pi pinned at 98% instead of an idle GPU box, where
    // it died with no answer and no error.

    #[test]
    fn a_busy_node_loses_to_an_idle_one_now_that_the_tier_can_fire() {
        // The tier that could never fire. Same backend type, same model
        // situation: the only difference is load, and 0.98 used to compare
        // false against 80.0 so it ranked as "not busy".
        let busy = sort_key(false, true, 0.98);
        let idle = sort_key(false, true, 0.10);
        assert!(idle < busy, "idle={idle:?} busy={busy:?}");
        assert_eq!(busy.2, 1, "0.98 must register as busy");
        assert_eq!(idle.2, 0);
    }

    #[test]
    fn preferred_backend_type_still_outranks_load_by_design() {
        // NOT a bug, and recorded here so it is not "fixed" by accident: the
        // documented order is exact model, then backend type, then load. An
        // idle llama.cpp box does not take work from a busy vLLM one when vLLM
        // is what the install is configured for — the engine decides what the
        // answer will be like, the load only decides how fast.
        //
        // It also means fixing the scale alone would not have changed a routing
        // decision where the two candidates differed in type. On the live
        // incident the decisive fault was that NOTHING advertised a model
        // (the SetHeld instance bug), so the only candidate carrying one won.
        let busy_preferred = sort_key(false, true, 0.98);
        let idle_other = sort_key(false, false, 0.10);
        assert!(busy_preferred < idle_other, "type outranks load, deliberately");
    }

    #[test]
    fn an_exact_model_match_still_outranks_everything() {
        // Tier 0 is not weakened by the fix: a node holding the requested model
        // wins even while busy, because the alternative is the wrong model.
        let exact_busy = sort_key(true, false, 0.99);
        let idle_preferred = sort_key(false, true, 0.01);
        assert!(exact_busy < idle_preferred);
    }

    #[test]
    fn among_equally_idle_nodes_the_preferred_type_still_wins() {
        assert!(sort_key(false, true, 0.10) < sort_key(false, false, 0.10));
    }

    #[test]
    fn among_equally_busy_nodes_the_lighter_one_wins() {
        assert!(sort_key(false, false, 0.91) < sort_key(false, false, 0.99));
    }

    #[test]
    fn the_ceiling_is_the_same_number_the_rest_of_the_gateway_uses() {
        // The bug was a second spelling of this threshold. 0.9 is the boundary
        // and it is inclusive, matching `has_capacity` and the status string.
        assert_eq!(busy_rank(0.89), 0);
        assert_eq!(busy_rank(0.9), 1, "the boundary is inclusive");
        assert_eq!(busy_rank(0.98), 1, "the value that never registered as busy");
    }

    #[test]
    fn a_percentage_producer_is_reported_and_treated_as_full() {
        // A producer switching to percent would silently re-break every
        // threshold, because 98.0 is a valid f64. It must not read as idle.
        let out = scale_checked_load("node-host9", 98.0);
        assert!(out >= 0.9, "a percent value must not rank as idle: {out}");
        assert_eq!(busy_rank(out), 1);
        // And the normal scale is untouched.
        assert_eq!(scale_checked_load("node-x", 0.42), 0.42);
        assert_eq!(scale_checked_load("node-x", -1.0), 0.0, "a negative load is not a discount");
    }

    use super::is_retryable_llm_http_error;
    use super::{mark_legacy_completion, refuses_tools, wire_format, ResolvedBackend};
    use super::node_from_backend_url;
    use super::is_context_overflow_body;
    use super::{purpose_map_after_refresh, PurposeMap};
    use std::collections::HashSet;

    /// The sentinels are placeholders, and only the whole string counts: a
    /// real model whose name merely STARTS with one must survive, or the
    /// hint silently stops pinning it.
    #[test]
    fn model_hint_drops_only_the_placeholders() {
        assert_eq!(super::model_hint(Some("gemma4:12b")), Some("gemma4:12b"));
        assert_eq!(super::model_hint(Some("  gemma4:12b  ")), Some("gemma4:12b"));
        assert_eq!(super::model_hint(Some("default-v2")), Some("default-v2"));
        assert_eq!(super::model_hint(Some("autocoder:7b")), Some("autocoder:7b"));

        assert_eq!(super::model_hint(Some("default")), None);
        assert_eq!(super::model_hint(Some("Default")), None);
        assert_eq!(super::model_hint(Some(" AUTO ")), None);
        assert_eq!(super::model_hint(Some("")), None);
        assert_eq!(super::model_hint(Some("   ")), None);
        assert_eq!(super::model_hint(None), None);
    }

    /// PINNED: the purpose map must never fail OPEN.
    /// A DB error with a cached copy serves the stale copy; with no cache it
    /// refuses — under no input does an error become an empty set, because
    /// an empty set silently readmits embed/rerank backends to chat routing.
    #[test]
    fn purpose_map_never_fails_open() {
        let cached: HashSet<(String, String)> =
            [("host8".to_string(), "ollama".to_string())].into_iter().collect();

        match purpose_map_after_refresh(Err(sqlx::Error::PoolTimedOut), Some(cached.clone())) {
            PurposeMap::Stale(set) => assert_eq!(set, cached),
            PurposeMap::Fresh(_) => panic!("a DB error must not present as fresh data"),
            PurposeMap::Unavailable => panic!("cached copy exists — must serve it, not refuse"),
        }

        match purpose_map_after_refresh(Err(sqlx::Error::PoolTimedOut), None) {
            PurposeMap::Unavailable => {}
            PurposeMap::Fresh(set) | PurposeMap::Stale(set) => {
                panic!("no cache + DB error must refuse, got a set of {}", set.len())
            }
        }

        // The success path is untouched: fresh rows win even over a cache.
        match purpose_map_after_refresh(Ok(HashSet::new()), Some(cached)) {
            PurposeMap::Fresh(set) => assert!(set.is_empty()),
            _ => panic!("a successful query is fresh truth"),
        }
    }

    #[test]
    fn context_overflow_bodies_are_retryable() {
        // Real llama.cpp shape (the host9 incident class)
        let llamacpp = r#"{"error":{"code":400,"message":"the request exceeds the available context size","type":"exceed_context_size_error"}}"#;
        assert!(is_context_overflow_body(llamacpp));
        assert!(is_retryable_llm_http_error(400, llamacpp));
        // Real vLLM shape
        let vllm = "This model's maximum context length is 4096 tokens. However, you requested 11621 tokens";
        assert!(is_context_overflow_body(vllm));
        assert!(is_retryable_llm_http_error(400, vllm));
        // Plain client errors must NOT trigger failover
        assert!(!is_retryable_llm_http_error(400, "invalid request: missing model"));
        assert!(!is_context_overflow_body("invalid request: missing model"));
        // Same body on a 200/500 path is not this classifier's business
        assert!(!is_retryable_llm_http_error(500, vllm));
    }

    #[test]
    fn node_from_backend_url_extracts_the_host() {
        assert_eq!(node_from_backend_url("http://host8:8081/v1"),
                   Some("host8".to_string()));
        assert_eq!(node_from_backend_url("https://10.0.0.5:8000"),
                   Some("10.0.0.5".to_string()));
        // No scheme, no port — the whole string is the host.
        assert_eq!(node_from_backend_url("host9"), Some("host9".to_string()));
        assert_eq!(node_from_backend_url(""), None);
    }

    #[test]
    fn node_from_backend_url_maps_loopback_to_a_node_name() {
        // NODE_ID is unset in the test env, so loopback falls back to the
        // "controller" label rather than a meaningless loopback literal.
        std::env::remove_var("NODE_ID");
        assert_eq!(node_from_backend_url("http://localhost:11434"),
                   Some("controller".to_string()));
        assert_eq!(node_from_backend_url("http://127.0.0.1:8000/v1"),
                   Some("controller".to_string()));
    }

    /// The exact error body observed in the live incident: controller's
    /// vLLM down, node-agent proxy answering 502 backend_unreachable.
    #[test]
    fn retries_node_agent_backend_unreachable_502() {
        let body = r#"{"error":{"code":"backend_unreachable","message":"dial tcp 172.19.0.5:8000: connect: connection refused","type":"node_agent_proxy_error"}}"#;
        assert!(is_retryable_llm_http_error(502, body));
    }

    #[test]
    fn retries_gateway_style_502_with_empty_body() {
        assert!(is_retryable_llm_http_error(502, ""));
        assert!(is_retryable_llm_http_error(503, "  \n"));
    }

    #[test]
    fn retries_timeout_marker_504() {
        assert!(is_retryable_llm_http_error(504, "upstream request timed out"));
    }

    #[test]
    fn does_not_retry_client_or_engine_errors() {
        // Bad request / validation errors would fail identically elsewhere.
        assert!(!is_retryable_llm_http_error(400, "model not found"));
        assert!(!is_retryable_llm_http_error(422, "invalid tool schema"));
        // Engine 500 with a real error body: not a routing failure.
        assert!(!is_retryable_llm_http_error(500, "CUDA out of memory"));
    }

    #[test]
    fn does_not_retry_502_with_substantive_engine_body() {
        // A 502 carrying an application-level error that isn't a dial
        // failure should not trigger fallback.
        assert!(!is_retryable_llm_http_error(
            502,
            r#"{"error":{"code":"model_loading","message":"engine warming up"}}"#
        ));
    }

    fn backend(kind: &str, url: &str) -> ResolvedBackend {
        ResolvedBackend {
            url: url.to_string(),
            model: "m".to_string(),
            backend_type: kind.to_string(),
            api_format: super::detect_api_format_for_url(kind, Some(url)),
        }
    }

    /// PINNED: llama.cpp is spoken to as OpenAI (native tool calls) by
    /// default; only a backend that has refused tools drops to the
    /// prompt-flattening `/completion` shape, and only that backend.
    #[test]
    fn llamacpp_is_native_until_it_refuses_tools() {
        let a = backend("llamacpp", "http://noo-llamacpp:8085");
        let b = backend("llamacpp", "http://other-node:8085");
        assert_eq!(a.api_format, "llamacpp");
        assert_eq!(wire_format(&a), "openai");
        assert_eq!(wire_format(&b), "openai");
        mark_legacy_completion(&a.url);
        assert_eq!(wire_format(&a), "llamacpp");
        assert_eq!(wire_format(&b), "openai", "the mark is per backend, not per type");
        // Other formats are untouched by the registry.
        assert_eq!(wire_format(&backend("ollama", "http://noo-ollama:11434")), "ollama");
        assert_eq!(wire_format(&backend("vllm", "http://noo-vllm:8000")), "openai");
        // Through the node-agent proxy the format was already openai.
        assert_eq!(wire_format(&backend("llamacpp", "http://node:8081")), "openai");
    }

    #[test]
    fn refusal_is_the_jinja_error_and_nothing_else() {
        assert!(refuses_tools(400, r#"{"error":{"message":"tools param requires --jinja flag"}}"#));
        assert!(refuses_tools(500, "Tools param requires --JINJA flag"));
        assert!(!refuses_tools(200, "jinja"));
        assert!(!refuses_tools(400, r#"{"error":{"message":"the request exceeds the available context size"}}"#));
        assert!(!refuses_tools(503, "upstream connect error"));
    }
}

#[cfg(test)]
mod node_agent_url_tests {
    use super::is_node_agent_url;

    /// Phase D's model endpoint is the node agent's own proxy over
    /// loopback. It must be recognised as a node-agent URL, or the bearer
    /// is never attached and every turn on a node dies with 401 — the
    /// first dispatched turn is the case.
    #[test]
    fn the_loopback_agent_proxy_is_a_node_agent_url() {
        assert!(is_node_agent_url("https://127.0.0.1:8081"));
        assert!(is_node_agent_url("https://127.0.0.1:8081/v1/chat/completions"));
    }

    /// A controller-local backend is not, so the node token never goes
    /// anywhere but a node agent.
    #[test]
    fn a_local_model_server_is_not_a_node_agent_url() {
        assert!(!is_node_agent_url("http://127.0.0.1:11434/v1"));
        assert!(!is_node_agent_url("http://vllm:8000/v1"));
    }
}

#[cfg(test)]
mod local_backend_url_tests {
    use super::local_backend_url;

    /// Every compose backend is dialled over https, and the two that cannot
    /// serve TLS themselves (llama.cpp, ollama) at their stunnel sidecars,
    /// on the same port. The sidecar requires a client certificate; the
    /// gateway dials it with `cluster_client()`, which presents its leaf.
    /// There is no plain form: the function takes no TLS flag any more.
    #[test]
    fn every_backend_is_dialled_over_https_and_the_sidecar_fronted_ones_at_their_sidecar() {
        assert_eq!(local_backend_url("llamacpp", 8085), "https://noo-stunnel-llamacpp:8085");
        assert_eq!(local_backend_url("ollama", 11434), "https://noo-stunnel-ollama:11434");
        assert_eq!(local_backend_url("vllm", 8000), "https://noo-vllm:8000");
        assert_eq!(local_backend_url("vllm-secondary", 8000), "https://noo-vllm-secondary:8000");
    }
}

/// Heartbeat tasks and agent turns with no model resolve where unpinned raw
/// chat does (operator rule 2026-10-17).
#[cfg(test)]
mod unpinned_tests {
    use super::super::classes::{build_table, select, Declarations, NodeFacts};
    use super::pick_unpinned;

    fn node(id: &str, ip: &str, backend: &str, model: &str, gpu: bool, load: f64) -> NodeFacts {
        NodeFacts {
            node_id: id.into(),
            ip: ip.into(),
            running: vec![(backend.into(), model.into())],
            load,
            gpu,
            heartbeat_age_secs: Some(2.0),
            inbound_ok: true,
            ..Default::default()
        }
    }

    #[test]
    fn the_heartbeat_path_picks_the_same_node_as_raw_chat_for_an_unpinned_turn() {
        // The 2026-10-17 fleet (addresses no other test notes a stall on).
        let nodes = vec![
            node("pop-os", "192.0.2.211", "ollama", "gemma4:e2b-it-qat", false, 0.05),
            node("mcmini", "192.0.2.212", "ollama", "gemma4:12b", true, 0.4),
        ];
        let t = build_table(&nodes, &[], &Declarations::default());
        let raw = select(&t, None, None, false, &|_| false).expect("raw chat selection");
        let task = pick_unpinned(&t, &[]).expect("heartbeat selection");
        assert_eq!(raw.candidates[0].node_id, "mcmini");
        assert_eq!(task.candidates[0].node_id, raw.candidates[0].node_id);
        assert_eq!(task.candidates[0].url, "https://192.0.2.212:8081");
        // After mcmini failed this turn (its ResolvedBackend.url excluded),
        // the turn fails over to the next node, never back to mcmini.
        let next = pick_unpinned(&t, &["https://192.0.2.212:8081".to_string()]).expect("failover");
        assert_eq!(next.candidates.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["pop-os"]);
        assert!(pick_unpinned(&t, &["https://192.0.2.212:8081".into(), "https://192.0.2.211:8081".into()]).is_none(),
            "nothing left: fall through to discovery / the static last resort");
    }

    /// The unpinned branch runs BEFORE the KV scan, and the configured
    /// default model is not a sort key any more.
    #[test]
    fn the_resolver_delegates_unpinned_turns_to_the_class_table() {
        let src = include_str!("backend.rs");
        let body = src.split("pub(crate) async fn resolve_backend_and_node(").nth(1).expect("resolver");
        let unpinned = body.find("unpinned_from_table(state, exclude_urls)").expect("delegation");
        let scan = body.find("get_key_value(\"mesh_nodes\")").expect("kv scan");
        assert!(unpinned < scan);
        assert!(body.contains("let target_model = requested_model.unwrap_or(\"\");"), "no configured-default tier-0 key");
    }
}
