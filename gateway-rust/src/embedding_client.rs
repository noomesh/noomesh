// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Backend-agnostic embedding client — the ONE place that knows how to
//! talk to an embedding server.
//!
//! TEI (HuggingFace Text Embeddings Inference) is no longer deployed on the
//! controller — it was the live embedder/reranker at cutover but is now
//! optional legacy at best. The default embedder is ollama/harrier, and the
//! default reranker is the hardened llama.cpp image, both reached mesh-routed
//! through the node-agent (`embed_with_mesh()`), not by dialling TEI or any
//! other backend directly.
//!
//! Every Rust embed call site (external embeddings proxy, memory search,
//! coordinator conversation-recall, preflight probe) resolves the endpoint
//! here and speaks one of three wire formats ("api formats"):
//!
//!   - `tei`    — HuggingFace Text Embeddings Inference native (legacy;
//!                still accepted if an install still runs a TEI server):
//!                POST {url}/embed          {"inputs": [..], "truncate": true} → [[f64]]
//!   - `openai` — OpenAI-compatible (TEI, llama.cpp, vLLM, Ollama all serve it):
//!                POST {url}/v1/embeddings  {"model": m, "input": [..]}
//!                → {"data": [{"index": i, "embedding": [..]}]}
//!   - `ollama` — Ollama native, the current default:
//!                POST {url}/api/embed      {"model": m, "input": [..]}
//!                → {"embeddings": [[f64]]}
//!
//! Config resolution (env → yaml → default, phase-2 pattern):
//!   PAGEINDEX_EMBEDDING_URL     / services.embedding_url     → http://noo-ollama:11434
//!   PAGEINDEX_EMBEDDING_BACKEND / services.embedding_backend → "ollama"
//!
//! The MODEL (and vector width) come from the embedding space record in the
//! DB (`embedding_spaces`, i145): a caller names a space, `knowledge` by
//! default. `PAGEINDEX_EMBEDDING_MODEL` → `EMBEDDING_MODEL` → `TEI_MODEL` →
//! `harrier` and `EMBEDDING_DIM` only seed `knowledge` on an empty table
//! ([`configured_model`]).
//!
//! TLS: on installs that still run a co-located TEI sidecar behind stunnel,
//! the endpoint may be that sidecar (https with the private cluster PKI), so
//! all requests go through `tls::cluster_client()` regardless of backend.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::{env_or_yaml, env_or_yaml_u64};
use crate::embedding_spaces::same_model;
use crate::log_gate::LogGate;

/// A node whose embedder keeps failing is logged when it starts failing,
/// then once per window with the suppressed count, then once when it
/// answers again. Per request it was 11,751 WARN lines an hour on the live
/// controller — half the gateway's output — for one fact.
static EMBED_NODE_FAIL: LazyLock<LogGate> = LazyLock::new(|| LogGate::new(EMBED_FAIL_LOG_WINDOW_SECS));
const EMBED_FAIL_LOG_WINDOW_SECS: u64 = 300;
/// The gate key for "every node failed" (a state of the fleet, not a node).
const ALL_NODES_KEY: &str = "\u{0}all-nodes";

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The context window, in tokens, every embed request asks ollama for
/// (`options.num_ctx`), declared ONCE here.
///
/// Derived from the ingest window: trellion's `CHUNK_SIZE_CHARS` is 1500
/// characters (~500 tokens), so 1024 leaves 2x headroom. Without it ollama
/// loads harrier at its 8192 default, which is 2.6 GB resident for a
/// 396 MB model and 8x the KV per parallel slot -- a 6 GB GPU then holds
/// almost nothing else. Sent per request (not as a container-wide
/// OLLAMA_CONTEXT_LENGTH) because the same ollama may also serve chat.
/// Longer inputs are truncated by ollama (its `truncate` default), as they
/// were at 8192 for anything past that.
pub const EMBED_NUM_CTX: u64 = 1024;

/// How long ollama keeps the embed model resident after a request
/// (`keep_alive`), declared ONCE here. Without it ollama unloads the model
/// after its 5-minute idle default, and the first request after the unload
/// is slow or fails -- which benches the target, which idles it further.
/// Sent per request (not as a container-wide `OLLAMA_KEEP_ALIVE=-1`)
/// because ollama applies it per model: the same ollama may also serve a
/// chat model whose expiry must stay untouched. Only ever sent to
/// ollama-dialect targets; TEI and OpenAI-dialect bodies do not carry it.
pub const EMBED_KEEP_ALIVE: &str = "30m";

/// Concurrent requests the gateway admits per target: matches the declared
/// `OLLAMA_NUM_PARALLEL` default (4) of the embedders, so admitting more
/// would only queue inside ollama.
const EMBED_SLOTS_PER_TARGET: usize = 4;
/// How long a request may wait for a free slot before it is shed. Only the
/// wait is bounded here; once admitted, a request keeps the caller's full
/// timeout.
const EMBED_ADMISSION_WAIT: Duration = Duration::from_millis(1500);

/// How long a target that just failed is placed behind the healthy ones.
const EMBED_TARGET_COOLDOWN_SECS: u64 = 30;

/// Resolved embedding endpoint: where to POST, which wire format, which model.
#[derive(Debug, Clone)]
pub struct EmbeddingEndpoint {
    pub url: String,
    pub api_format: String, // "tei" | "openai" | "ollama"
    pub model: String,
    /// Expected vector dims (0 = unknown, dims check skipped).
    pub dims: u64,
}

#[derive(Debug)]
pub enum EmbedError {
    /// Transport-level failure (connect/timeout) — backend unreachable.
    Unavailable(String),
    /// Backend answered with a non-2xx status.
    BadStatus(reqwest::StatusCode),
    /// Backend answered 2xx but the body didn't match the adapter's shape.
    Parse(String),
    /// Every embedder slot is busy and the bounded admission wait ran out:
    /// shed now rather than hold the caller for the full request timeout.
    /// `retry_after_secs` (2..=10) scales with how many requests are
    /// already waiting.
    Saturated { retry_after_secs: u64 },
}

impl std::fmt::Display for EmbedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmbedError::Unavailable(e) => write!(f, "embedding backend unavailable: {e}"),
            EmbedError::BadStatus(s) => write!(f, "embedding backend returned {s}"),
            EmbedError::Parse(e) => write!(f, "embedding backend parse error: {e}"),
            EmbedError::Saturated { retry_after_secs } => {
                write!(f, "embedders saturated (retry in {retry_after_secs}s)")
            }
        }
    }
}

/// Resolve the embedding endpoint for the default space: where the static
/// path posts and in which wire format (env → yaml → default), with the
/// space's model.
pub fn resolve() -> EmbeddingEndpoint {
    // Ollama-first defaults: TEI is no longer deployed on the controller
    // (the old noo-tei/tei defaults pointed at nothing on a normal install),
    // while ollama is the stack's always-available fallback engine and what
    // serves the default embedding model in practice. Explicit config still
    // wins, and most embed traffic goes through the mesh regardless — these
    // defaults only shape the static-endpoint path and preflight probes.
    // The stunnel-fronted (mTLS) ollama door: ollama serves no TLS itself.
    // Standalone sets PAGEINDEX_EMBEDDING_URL=http://ollama-embed:11434
    // explicitly (onboard/steps.rs) — the named plaintext exception that
    // PR #541 (stunnel-ollama-embed) moves to https; this default never
    // applies there.
    let url = env_or_yaml(
        "PAGEINDEX_EMBEDDING_URL",
        |c| c.services.embedding_url.clone(),
        "https://stunnel-ollama:11434",
    )
    .trim_end_matches('/')
    .to_string();

    let api_format = env_or_yaml(
        "PAGEINDEX_EMBEDDING_BACKEND",
        |c| c.services.embedding_backend.clone(),
        "ollama",
    )
    .to_lowercase();

    // The model and width come from the default embedding space (i145):
    // the DB record, not env. Before the first boot has seeded one (and in
    // unit tests) the configured model stands in.
    match crate::embedding_spaces::resolve(&crate::embedding_spaces::all(), None) {
        Ok(space) => EmbeddingEndpoint { url, api_format, model: space.model.clone(), dims: space.dims.unwrap_or(0) },
        Err(_) => EmbeddingEndpoint {
            url,
            api_format,
            model: configured_model(),
            dims: env_or_yaml_u64("EMBEDDING_DIM", |c| c.services.embedding_dim, 0),
        },
    }
}

/// The endpoint for the space a caller names (`None`/`default` = the default
/// space). `Err` names the spaces there are; with no space recorded yet the
/// default resolves to the configured model and anything else is refused.
pub fn resolve_space(requested: Option<&str>) -> Result<EmbeddingEndpoint, String> {
    let spaces = crate::embedding_spaces::all();
    if spaces.is_empty() {
        let named = requested.map(str::trim).filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("default") && !s.eq_ignore_ascii_case("auto"));
        let ep = resolve();
        return match named {
            None => Ok(ep),
            Some(n) if n.eq_ignore_ascii_case(crate::embedding_spaces::DEFAULT_SPACE) || same_model(n, &ep.model) => Ok(ep),
            Some(n) => Err(format!("'{n}' is not an embedding space; no space is recorded yet, only the default ({})", crate::embedding_spaces::DEFAULT_SPACE)),
        };
    }
    let space = crate::embedding_spaces::resolve(&spaces, requested)?;
    let base = resolve();
    Ok(EmbeddingEndpoint { model: space.model.clone(), dims: space.dims.unwrap_or(0), ..base })
}

/// The embed model the env/yaml names: only the SEED for the `knowledge`
/// space on an empty table, and the stand-in before one is recorded.
pub fn configured_model() -> String {
    let model = env_or_yaml("PAGEINDEX_EMBEDDING_MODEL", |c| c.services.embedding_model.clone(), "");
    if !model.is_empty() {
        return model;
    }
    // EMBEDDING_MODEL is the stack-wide model name; TEI_MODEL is the
    // legacy deploy-time name kept for older installs.
    std::env::var("EMBEDDING_MODEL")
        .or_else(|_| std::env::var("TEI_MODEL"))
        // harrier: the product's default embedder (1024-dim, matching
        // trellion's hardcoded vector(1024) DDL). Locally converted —
        // the CLI's embed-ensure step fetches it from the
        // models-harrier-v1 release when absent.
        .unwrap_or_else(|_| "harrier".into())
}

impl EmbeddingEndpoint {
    /// The full URL and JSON body for an embed request in this wire format.
    fn request_parts(&self, texts: &[String]) -> (String, Value) {
        match self.api_format.as_str() {
            "ollama" => (
                format!("{}/api/embed", self.url),
                json!({
                    "model": self.model,
                    "input": texts,
                    "options": {"num_ctx": EMBED_NUM_CTX},
                    "keep_alive": EMBED_KEEP_ALIVE,
                }),
            ),
            "openai" => (
                format!("{}/v1/embeddings", self.url),
                json!({"model": self.model, "input": texts}),
            ),
            // "tei" (legacy default) and anything unrecognized.
            _ => (
                format!("{}/embed", self.url),
                json!({"inputs": texts, "truncate": true}),
            ),
        }
    }

    /// Extract `Vec<Vec<f64>>` from a 2xx response body in this wire format.
    fn parse_response(&self, data: Value, n_inputs: usize) -> Result<Vec<Vec<f64>>, EmbedError> {
        let rows: Vec<Value> = match self.api_format.as_str() {
            "ollama" => data
                .get("embeddings")
                .and_then(Value::as_array)
                .cloned()
                .ok_or_else(|| EmbedError::Parse("missing 'embeddings' array".into()))?,
            "openai" => {
                let mut items: Vec<(usize, Value)> = data
                    .get("data")
                    .and_then(Value::as_array)
                    .ok_or_else(|| EmbedError::Parse("missing 'data' array".into()))?
                    .iter()
                    .enumerate()
                    .map(|(pos, item)| {
                        let idx = item
                            .get("index")
                            .and_then(Value::as_u64)
                            .map(|i| i as usize)
                            .unwrap_or(pos);
                        (idx, item.get("embedding").cloned().unwrap_or(Value::Null))
                    })
                    .collect();
                items.sort_by_key(|(idx, _)| *idx);
                items.into_iter().map(|(_, e)| e).collect()
            }
            _ => data
                .as_array()
                .cloned()
                .ok_or_else(|| EmbedError::Parse("expected top-level array".into()))?,
        };

        if rows.len() != n_inputs {
            return Err(EmbedError::Parse(format!(
                "expected {n_inputs} embeddings, got {}",
                rows.len()
            )));
        }

        rows.into_iter()
            .map(|row| {
                row.as_array()
                    .map(|arr| arr.iter().map(|v| v.as_f64().unwrap_or(0.0)).collect())
                    .ok_or_else(|| EmbedError::Parse("embedding row is not an array".into()))
            })
            .collect()
    }

    /// Embed a batch of texts. One HTTP round-trip.
    pub async fn embed(
        &self,
        texts: &[String],
        timeout: Duration,
    ) -> Result<Vec<Vec<f64>>, EmbedError> {
        self.embed_attempt(texts, timeout).await.map_err(|(e, _)| e)
    }

    /// One embed round-trip. The error carries whether it was a
    /// TRANSPORT-level send failure worth one retry on a fresh connection:
    /// `error sending request` / connection reset (a stale pooled or
    /// half-closed connection), but not a timeout (the backend may have
    /// the body and be working on it) and not an HTTP status or parse
    /// error (the backend answered).
    async fn embed_attempt(
        &self,
        texts: &[String],
        timeout: Duration,
    ) -> Result<Vec<Vec<f64>>, (EmbedError, bool)> {
        let (url, body) = self.request_parts(texts);
        // mTLS-aware client — the endpoint may be the stunnel sidecar
        // (e.g. https://stunnel-tei:443) presenting a cluster-CA cert.
        let client = crate::tls::cluster_client();
        let resp = client
            .post(&url)
            .json(&body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| (EmbedError::Unavailable(e.to_string()), !e.is_timeout()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let _ = resp.text().await;
            return Err((EmbedError::BadStatus(status), false));
        }
        let data: Value = resp
            .json()
            .await
            .map_err(|e| (EmbedError::Parse(e.to_string()), false))?;
        self.parse_response(data, texts.len()).map_err(|e| (e, false))
    }

    /// [`Self::embed`] with one retry when the first send fails at the
    /// transport level. The retry opens a fresh connection (the pool drops
    /// a connection that errored), and embeds are idempotent, so repeating
    /// one is safe. A second failure is returned as-is.
    async fn embed_retrying_transport(
        &self,
        texts: &[String],
        timeout: Duration,
    ) -> Result<Vec<Vec<f64>>, EmbedError> {
        match self.embed_attempt(texts, timeout).await {
            Err((e, true)) => {
                tracing::debug!(url = %self.url, error = %e, "embed_transport_retry: one stale connection is not a dead target");
                self.embed_attempt(texts, timeout).await.map_err(|(e, _)| e)
            }
            other => other.map_err(|(e, _)| e),
        }
    }

    /// Embed by posting to the MESH: any node that advertises `embed` can
    /// serve the work, GPU-preferred but not GPU-required.
    ///
    /// Candidates come back ordered (GPU first, then least-loaded) and are
    /// tried in turn, so one wedged or busy node degrades throughput instead
    /// of failing the request.
    ///
    /// (History: a directly-configured URL used to be tried FIRST, ahead of
    /// the mesh. That is still wrong -- see below -- and is NOT what
    /// happens now: statics are peers of the mesh nodes, balanced with
    /// them, and the mesh path never sends a configured model. The
    /// original rationale follows.) That fallback used to run FIRST, which quietly made config the source of
    /// truth over placement: a stale PAGEINDEX_EMBEDDING_URL pointing at a
    /// retired backend would be preferred over the node the fleet actually
    /// placed, and because the stale endpoint ANSWERS — with vectors from
    /// the wrong model — the mesh was never consulted and nothing looked
    /// broken. Wrong-space vectors are unrecoverable without a full
    /// re-embed, so failing loudly is strictly better than silently
    /// embedding against the wrong model.
    ///
    /// A single-node install is not a special case: that node runs a
    /// node-agent too, so its own embedder is reached by the same
    /// authenticated mesh path as any other.
    ///
    /// Every hop is mTLS (cluster CA + this gateway's client identity) plus
    /// the node-agent bearer token.
    pub async fn embed_with_mesh(
        &self,
        state: &crate::state::AppState,
        texts: &[String],
        timeout: Duration,
    ) -> Result<Vec<Vec<f64>>, EmbedError> {
        let mesh = crate::routes::external::mesh_targets(state, "embed", "embed", 5).await;
        let statics = self.static_endpoints();
        let mut cands: Vec<Candidate> = Vec::with_capacity(mesh.len() + statics.len());
        for t in mesh {
            let declared = crate::model_presence::node_role_model(state, &t.node_id, "embed").await;
            cands.push(Candidate::Mesh(t, declared));
        }
        cands.extend(statics.into_iter().map(Candidate::Static));
        self.embed_over(&BALANCER, cands, texts, timeout).await
    }

    /// The static endpoints this install declares: the resolved primary
    /// (`PAGEINDEX_EMBEDDING_URL`) plus every URL in
    /// `PAGEINDEX_EMBEDDING_EXTRA_URLS` / `services.embedding_extra_urls`
    /// (the optional CPU embedder, for one). Extras share the primary's
    /// model and wire format.
    pub fn static_endpoints(&self) -> Vec<EmbeddingEndpoint> {
        let extra = env_or_yaml(
            "PAGEINDEX_EMBEDDING_EXTRA_URLS",
            |c| c.services.embedding_extra_urls.clone(),
            "",
        );
        static_endpoints_from(self, &extra)
    }

    /// Try the candidates in the balancer's order until one answers.
    ///
    /// Spreading policy: LEAST-INFLIGHT across every candidate (mesh nodes
    /// and static endpoints alike), ties broken round-robin. A target that
    /// failed within [`EMBED_TARGET_COOLDOWN_SECS`] is placed after all the
    /// others -- skipped while anything else answers, still tried as a last
    /// resort so a fleet that is entirely cooling is not a guaranteed 503.
    ///
    /// The static endpoint used to be reached ONLY when the mesh resolved
    /// empty (or every node failed). Mesh resolution is intermittently empty
    /// right after boot, so load flipped wholesale between two embedders
    /// instead of sharing. Each declared endpoint is now a peer.
    pub(crate) async fn embed_over(
        &self,
        balancer: &EmbedBalancer,
        cands: Vec<Candidate>,
        texts: &[String],
        timeout: Duration,
    ) -> Result<Vec<Vec<f64>>, EmbedError> {
        if cands.is_empty() {
            return Err(EmbedError::Unavailable(
                "no embed target: no node advertises `embed` and no static endpoint is configured".into(),
            ));
        }
        // Vector-space consistency: only targets on the space's model
        // join the spread set (see `consistent_candidates`).
        let cands = consistent_candidates(cands, &self.model);
        if cands.is_empty() {
            return Err(EmbedError::Unavailable(
                "no embed target on this embedding space's model (see embed_target_model_mismatch); refusing to embed with a different model".into(),
            ));
        }
        // Admission: a bounded wait for a free slot, then shed. Interactive
        // single-text embeds (search, recall) get a reserve of one extra
        // slot per target so a batch backfill cannot starve them.
        let reserve = if texts.len() == 1 { cands.len() } else { 0 };
        let limit = cands.len() * balancer.slots + reserve;
        let _admitted = balancer.admit(limit, cands.len()).await?;
        let keys: Vec<String> = cands.iter().map(Candidate::key).collect();
        let order = balancer.plan(&keys, now_secs());
        let n = cands.len();
        let mut last: Option<String> = None;
        for idx in order {
            let c = &cands[idx];
            let key = &keys[idx];
            let _inflight = balancer.begin(key);
            let res = match c {
                Candidate::Mesh(t, _) => self.embed_via_mesh(&t.url, &t.headers, texts, timeout).await,
                Candidate::Static(ep) => ep.embed_retrying_transport(texts, timeout).await,
            };
            // Dimension guard: a vector of the wrong width is the wrong
            // vector space whatever the target says its model is. Expected
            // width: EMBEDDING_DIM (checked against the store's vector
            // column by preflight) when set, else what the first answering
            // MESH target returned.
            let res = res.and_then(|v| {
                let got = v.first().map_or(0, Vec::len) as u64;
                let expected = if self.dims > 0 { self.dims } else { balancer.learned_dim() };
                if expected > 0 && got != expected {
                    log_mismatch(key, &format!(
                        "returned {got}-dim vectors, expected {expected} ({})",
                        if self.dims > 0 { "EMBEDDING_DIM" } else { "first mesh target's dim" }
                    ));
                    return Err(EmbedError::Parse(format!("dimension {got} != expected {expected}")));
                }
                if expected == 0 && got > 0 && matches!(c, Candidate::Mesh(..)) {
                    balancer.learn_dim(got);
                }
                Ok(v)
            });
            match res {
                Ok(v) => {
                    balancer.succeeded(key);
                    if EMBED_NODE_FAIL.clear(key) {
                        tracing::info!(target_id = %key, "embed_node_recovered");
                    }
                    if EMBED_NODE_FAIL.clear(ALL_NODES_KEY) {
                        tracing::info!(target_id = %key, "embed_mesh_recovered: a target answers again");
                    }
                    // Which target served: one line per request, so the
                    // spread is observable (grep embed_target_served).
                    tracing::info!(
                        target_id = %key, kind = c.kind(), candidates = n,
                        served_total = balancer.served(key),
                        "embed_target_served"
                    );
                    return Ok(v);
                }
                Err(e) => {
                    balancer.failed(key, now_secs());
                    match EMBED_NODE_FAIL.should_log(key, now_secs()) {
                        Some(suppressed) => tracing::warn!(
                            node = %key, error = %e, suppressed,
                            "embed_node_failed: trying the next embed target (this target's repeats are logged once per {EMBED_FAIL_LOG_WINDOW_SECS}s; `suppressed` = repeats since the last line)"
                        ),
                        None => tracing::debug!(
                            node = %key, error = %e,
                            "embed_node_failed: trying the next embed target"
                        ),
                    }
                    last = Some(format!("{key}: {e}"));
                }
            }
        }
        match EMBED_NODE_FAIL.should_log(ALL_NODES_KEY, now_secs()) {
            Some(suppressed) => tracing::warn!(
                suppressed,
                "embed_all_nodes_failed (last {})",
                last.as_deref().unwrap_or("unknown")
            ),
            None => tracing::debug!(
                "embed_all_nodes_failed (last {})",
                last.as_deref().unwrap_or("unknown")
            ),
        }
        Err(EmbedError::Unavailable(format!(
            "all {n} embed targets failed (last {})",
            last.unwrap_or_else(|| "unknown".into())
        )))
    }

    /// One authenticated mesh embed call against a node-agent /embed proxy.
    async fn embed_via_mesh(
        &self,
        url: &str,
        headers: &[(String, String)],
        texts: &[String],
        timeout: Duration,
    ) -> Result<Vec<Vec<f64>>, EmbedError> {
        // The space's model, by name (i145). This used to be omitted on
        // purpose: a stale PAGEINDEX_EMBEDDING_MODEL (`bge-base-en-v1.5`
        // while the placement said `harrier`) broke the harrier cutover with
        // a bare 404. The model now comes from the embedding space record,
        // and only nodes declaring that model are candidates
        // ([`consistent_candidates`]), so naming it cannot disagree with the
        // placement; it makes a node that does NOT hold it fail fast (and
        // the next target answer) instead of embedding in another space.
        // `options.num_ctx` rides along so the node's ollama allocates a
        // small window per slot; the node-agent forwards it to ollama's
        // native API (its OpenAI route drops it) and strips it for engines
        // that have no such knob.
        // `keep_alive` pins the embed model in ollama; the node-agent
        // forwards it on the native route and strips it for engines that
        // have no such field.
        let body = serde_json::json!({
            "model": self.model,
            "input": texts,
            "options": {"num_ctx": EMBED_NUM_CTX},
            "keep_alive": EMBED_KEEP_ALIVE,
        });
        // cluster_client() carries the cluster CA *and* this gateway's mTLS
        // identity; `headers` carries the node-agent bearer. Both are
        // required — the proxy answers 401 without the token and refuses the
        // TLS handshake without the client cert.
        let client = crate::tls::cluster_client();
        let mut req = client.post(url).json(&body).timeout(timeout);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| EmbedError::Unavailable(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(EmbedError::BadStatus(resp.status()));
        }
        let data: Value = resp
            .json()
            .await
            .map_err(|e| EmbedError::Parse(e.to_string()))?;
        // The reply names the model that ACTUALLY served the request. Vectors
        // from another model are another space: refused, so the balancer
        // fails this target and tries the next (they used to be logged and
        // kept).
        if let Some(why) = served_model_refusal(data.get("model").and_then(|m| m.as_str()), &self.model) {
            return Err(EmbedError::Parse(why));
        }
        // The mesh proxy always answers in the OpenAI shape, whatever
        // dialect it spoke to the engine underneath.
        let openai = EmbeddingEndpoint { api_format: "openai".into(), ..self.clone() };
        openai.parse_response(data, texts.len())
    }

    /// Embed a single text (query-side convenience).
    pub async fn embed_one(
        &self,
        text: &str,
        timeout: Duration,
    ) -> Result<Vec<f64>, EmbedError> {
        let mut out = self.embed(&[text.to_string()], timeout).await?;
        out.pop()
            .ok_or_else(|| EmbedError::Parse("empty embedding response".into()))
    }

    /// Single-text variant of [`embed_with_mesh`].
    pub async fn embed_one_with_mesh(
        &self,
        state: &crate::state::AppState,
        text: &str,
        timeout: Duration,
    ) -> Result<Vec<f64>, EmbedError> {
        let mut out = self.embed_with_mesh(state, &[text.to_string()], timeout).await?;
        out.pop()
            .ok_or_else(|| EmbedError::Parse("empty embedding response".into()))
    }

    /// Health-probe URL appropriate for this wire format's server.
    pub fn health_url(&self) -> String {
        match self.api_format.as_str() {
            "ollama" => format!("{}/api/tags", self.url),
            "openai" => format!("{}/v1/models", self.url),
            _ => format!("{}/health", self.url),
        }
    }
}

/// Format an embedding as a pgvector literal: `[0.1,0.2,...]`.
pub fn pgvector_literal(embedding: &[f64]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(f64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// One place an embed request can go.
pub(crate) enum Candidate {
    /// A node-agent `/embed` proxy found by mesh resolution.
    /// The node's declared role=embed model (from its placement), when it
    /// reports one.
    Mesh(crate::routes::external::MeshTarget, Option<String>),
    /// A declared static endpoint (primary or extra), spoken to directly.
    Static(EmbeddingEndpoint),
}

impl Candidate {
    fn key(&self) -> String {
        match self {
            Candidate::Mesh(t, _) => t.node_id.clone(),
            Candidate::Static(e) => format!("static:{}", e.url),
        }
    }
    fn kind(&self) -> &'static str {
        match self {
            Candidate::Mesh(..) => "mesh",
            Candidate::Static(_) => "static",
        }
    }
}

static MISMATCH_LOG: LazyLock<LogGate> = LazyLock::new(|| LogGate::new(EMBED_FAIL_LOG_WINDOW_SECS));

/// Loud, but once per window per target (a per-request line was the
/// 11,751-lines-an-hour lesson): `embed_target_model_mismatch`.
fn log_mismatch(target: &str, what: &str) {
    if let Some(suppressed) = MISMATCH_LOG.should_log(&format!("{target}|{what}"), now_secs()) {
        tracing::warn!(
            target_id = %target, suppressed,
            "embed_target_model_mismatch: {what}; target excluded from the embed spread (logged once per {EMBED_FAIL_LOG_WINDOW_SECS}s)"
        );
    }
}

/// Keep only candidates in the space's vector space: the ones whose
/// declared model is the space's (`model`, from the embedding space record).
///
/// There is no vote. The fleet's model used to be the most common role=embed
/// declaration among the targets, so two of three nodes moving to another
/// model flipped it and excluded the one node still right (i145). A mesh node
/// declaring another model, or a static endpoint configured for another, is
/// dropped with a warning naming both -- never silently, since mixing models
/// in one index corrupts retrieval without any error. A mesh node that
/// declares nothing (an agent too old to report) stays: it is sent the
/// space's model by name, so an engine without it fails and the next target
/// answers, and its reply's model is checked ([`served_model_refusal`]).
pub(crate) fn consistent_candidates(cands: Vec<Candidate>, model: &str) -> Vec<Candidate> {
    cands
        .into_iter()
        .filter(|c| {
            let (key, declared) = match c {
                Candidate::Mesh(t, Some(m)) => (t.node_id.as_str(), m.as_str()),
                Candidate::Mesh(_, None) => return true,
                Candidate::Static(e) => (e.url.as_str(), e.model.as_str()),
            };
            if same_model(declared, model) {
                return true;
            }
            log_mismatch(key, &format!("serves model '{declared}' but this embedding space's model is '{model}'"));
            false
        })
        .collect()
}

/// Why a mesh reply cannot be used: it names a model other than the space's.
/// The vectors would be from another space; the target fails and the next
/// one is tried.
pub(crate) fn served_model_refusal(served: Option<&str>, model: &str) -> Option<String> {
    let served = served.map(str::trim).filter(|s| !s.is_empty())?;
    (!same_model(served, model)).then(|| format!("served model '{served}', not the space's '{model}'"))
}

/// The primary endpoint plus the comma-separated `extra` URLs, each
/// carrying the primary's model/format/dims. Blank entries and duplicates
/// of the primary are dropped. Pure, so "declared => present, undeclared
/// => absent" is a test, not a hope.
pub(crate) fn static_endpoints_from(primary: &EmbeddingEndpoint, extra: &str) -> Vec<EmbeddingEndpoint> {
    let mut out = vec![primary.clone()];
    for raw in extra.split(',') {
        let url = raw.trim().trim_end_matches('/');
        if url.is_empty() || out.iter().any(|e| e.url == url) {
            continue;
        }
        out.push(EmbeddingEndpoint { url: url.to_string(), ..primary.clone() });
    }
    out
}

/// In-process spreading state: in-flight count and failure cooldown per
/// target key, a round-robin cursor, and a served counter.
pub(crate) struct EmbedBalancer {
    inflight: Mutex<HashMap<String, usize>>,
    cooling_until: Mutex<HashMap<String, u64>>,
    served: Mutex<HashMap<String, u64>>,
    rr: AtomicUsize,
    /// Requests admitted (being served) / waiting for admission.
    admitted: AtomicUsize,
    waiting: AtomicUsize,
    /// Width of the first vector a mesh target returned (0 = not yet).
    learned_dim: std::sync::atomic::AtomicU64,
    slots: usize,
    admission_wait: Duration,
}

/// Releases the admission slot when the request ends.
pub(crate) struct AdmitGuard<'a>(&'a EmbedBalancer);

impl Drop for AdmitGuard<'_> {
    fn drop(&mut self) {
        self.0.admitted.fetch_sub(1, Ordering::AcqRel);
    }
}

static BALANCER: LazyLock<EmbedBalancer> = LazyLock::new(EmbedBalancer::new);

/// Decrements the in-flight count when the attempt ends (success, error or
/// the request future being dropped).
pub(crate) struct InflightGuard<'a> {
    b: &'a EmbedBalancer,
    key: String,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        let mut m = self.b.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.key);
            }
        }
    }
}

impl EmbedBalancer {
    pub(crate) fn new() -> Self {
        Self::with_limits(EMBED_SLOTS_PER_TARGET, EMBED_ADMISSION_WAIT)
    }

    pub(crate) fn with_limits(slots: usize, admission_wait: Duration) -> Self {
        Self {
            admitted: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
            learned_dim: std::sync::atomic::AtomicU64::new(0),
            slots,
            admission_wait,
            inflight: Mutex::new(HashMap::new()),
            cooling_until: Mutex::new(HashMap::new()),
            served: Mutex::new(HashMap::new()),
            rr: AtomicUsize::new(0),
        }
    }

    /// Take a slot if fewer than `limit` requests are being served, waiting
    /// up to the admission window for one to free; otherwise shed with a
    /// `Retry-After` of 2..=10 s scaled to the queue depth per target.
    async fn admit(&self, limit: usize, n_targets: usize) -> Result<AdmitGuard<'_>, EmbedError> {
        let deadline = tokio::time::Instant::now() + self.admission_wait;
        let mut counted_waiting = false;
        loop {
            let cur = self.admitted.load(Ordering::Acquire);
            if cur < limit
                && self
                    .admitted
                    .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                if counted_waiting {
                    self.waiting.fetch_sub(1, Ordering::AcqRel);
                }
                return Ok(AdmitGuard(self));
            }
            if cur < limit {
                continue; // lost the CAS race; retry immediately
            }
            if !counted_waiting {
                self.waiting.fetch_add(1, Ordering::AcqRel);
                counted_waiting = true;
            }
            if tokio::time::Instant::now() >= deadline {
                let waiting = self.waiting.fetch_sub(1, Ordering::AcqRel);
                let secs = (2 + (waiting / n_targets.max(1)) as u64).clamp(2, 10);
                tracing::warn!(
                    admitted = cur, limit, waiting, retry_after_secs = secs,
                    "embed_saturated: every embedder slot is busy; shedding with Retry-After"
                );
                return Err(EmbedError::Saturated { retry_after_secs: secs });
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Indices into `keys` in the order to try them: healthy targets by
    /// ascending in-flight (ties rotate round-robin), then the cooling
    /// ones in the same manner.
    pub(crate) fn plan(&self, keys: &[String], now: u64) -> Vec<usize> {
        let n = keys.len();
        if n == 0 {
            return Vec::new();
        }
        let start = self.rr.fetch_add(1, Ordering::Relaxed) % n;
        let inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        let cooling = self.cooling_until.lock().unwrap_or_else(|e| e.into_inner());
        let cool: HashSet<usize> = (0..n)
            .filter(|&i| cooling.get(&keys[i]).is_some_and(|&until| until > now))
            .collect();
        let mut idx: Vec<usize> = (0..n).map(|k| (start + k) % n).collect();
        // Stable sort: rotation order survives among equal keys.
        idx.sort_by_key(|&i| (cool.contains(&i), inflight.get(&keys[i]).copied().unwrap_or(0)));
        idx
    }

    pub(crate) fn begin(&self, key: &str) -> InflightGuard<'_> {
        let mut m = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        *m.entry(key.to_string()).or_insert(0) += 1;
        InflightGuard { b: self, key: key.to_string() }
    }

    pub(crate) fn failed(&self, key: &str, now: u64) {
        let mut m = self.cooling_until.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 1024 {
            m.clear();
        }
        m.insert(key.to_string(), now + EMBED_TARGET_COOLDOWN_SECS);
    }

    pub(crate) fn succeeded(&self, key: &str) {
        self.cooling_until.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
        *self.served.lock().unwrap_or_else(|e| e.into_inner()).entry(key.to_string()).or_insert(0) += 1;
    }

    pub(crate) fn learned_dim(&self) -> u64 {
        self.learned_dim.load(Ordering::Acquire)
    }

    pub(crate) fn learn_dim(&self, dim: u64) {
        let _ = self.learned_dim.compare_exchange(0, dim, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn served(&self, key: &str) -> u64 {
        self.served.lock().unwrap_or_else(|e| e.into_inner()).get(key).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::external::MeshTarget;
    use std::sync::Arc;

    type Seen = Arc<Mutex<Vec<Value>>>;

    /// A tiny embed server answering BOTH wire shapes (ollama native and
    /// the OpenAI shape the node-agent proxy returns) with `status`,
    /// recording every request body it receives.
    async fn server(status: u16) -> (String, Seen) {
        slow_server(status, 0).await
    }

    async fn slow_server(status: u16, delay_ms: u64) -> (String, Seen) {
        server_dim(status, delay_ms, 2).await
    }

    async fn server_dim(status: u16, delay_ms: u64, dim: usize) -> (String, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let app = axum::Router::new().fallback(axum::routing::post(
            move |axum::Json(body): axum::Json<Value>| {
                let s = s2.clone();
                async move {
                    let n = body["input"].as_array().map_or(1, Vec::len);
                    s.lock().unwrap().push(body);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    let vec: Vec<f64> = (0..dim).map(|i| 0.5 / (i + 1) as f64).collect();
                    let rows: Vec<Value> = (0..n).map(|_| json!(vec)).collect();
                    let data: Vec<Value> = (0..n).map(|i| json!({"index": i, "embedding": vec})).collect();
                    (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        axum::Json(json!({
                            "embeddings": rows,
                            "data": data,
                            "model": "harrier",
                        })),
                    )
                }
            },
        ));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    fn ollama(url: &str) -> EmbeddingEndpoint {
        EmbeddingEndpoint { url: url.into(), api_format: "ollama".into(), model: "harrier".into(), dims: 0 }
    }

    fn mesh(id: &str, base: &str) -> Candidate {
        mesh_declaring(id, base, Some("harrier"))
    }

    fn mesh_declaring(id: &str, base: &str, model: Option<&str>) -> Candidate {
        Candidate::Mesh(
            MeshTarget { node_id: id.into(), url: format!("{base}/embed"), headers: Vec::new() },
            model.map(str::to_string),
        )
    }

    const T: Duration = Duration::from_secs(5);

    fn texts() -> Vec<String> {
        vec!["hello".to_string()]
    }

    // Both ollama paths must ask for the small context window; without it
    // ollama loads harrier at 8192 (2.6 GB for a 396 MB model).
    #[tokio::test]
    async fn direct_ollama_request_carries_num_ctx() {
        let (url, seen) = server(200).await;
        ollama(&url).embed(&texts(), T).await.unwrap();
        let b = seen.lock().unwrap()[0].clone();
        assert_eq!(b["options"]["num_ctx"], json!(EMBED_NUM_CTX), "body: {b}");
        assert_eq!(EMBED_NUM_CTX, 1024);
    }

    #[tokio::test]
    async fn mesh_request_carries_num_ctx() {
        let (url, seen) = server(200).await;
        let ep = ollama("http://unused");
        ep.embed_via_mesh(&format!("{url}/embed"), &[], &texts(), T).await.unwrap();
        let b = seen.lock().unwrap()[0].clone();
        assert_eq!(b["options"]["num_ctx"], json!(EMBED_NUM_CTX), "body: {b}");
        // The space's model is sent by name (i145), so a node without it
        // fails instead of answering from another space.
        assert_eq!(b["model"], json!("harrier"), "body: {b}");
    }

    // The embed model must stay resident: every ollama-dialect body (direct
    // and over the mesh to a node-agent) pins it; TEI/OpenAI bodies, which
    // would not understand the field, do not carry it.
    #[tokio::test]
    async fn direct_ollama_request_carries_keep_alive() {
        let (url, seen) = server(200).await;
        ollama(&url).embed(&texts(), T).await.unwrap();
        let b = seen.lock().unwrap()[0].clone();
        assert_eq!(b["keep_alive"], json!(EMBED_KEEP_ALIVE), "body: {b}");
        assert_eq!(EMBED_KEEP_ALIVE, "30m");
    }

    #[tokio::test]
    async fn mesh_request_carries_keep_alive() {
        let (url, seen) = server(200).await;
        let ep = ollama("http://unused");
        ep.embed_via_mesh(&format!("{url}/embed"), &[], &texts(), T).await.unwrap();
        let b = seen.lock().unwrap()[0].clone();
        assert_eq!(b["keep_alive"], json!(EMBED_KEEP_ALIVE), "body: {b}");
    }

    #[test]
    fn tei_and_openai_bodies_do_not_carry_keep_alive() {
        for fmt in ["tei", "openai"] {
            let ep = EmbeddingEndpoint { url: "http://x".into(), api_format: fmt.into(), model: "m".into(), dims: 0 };
            let (_, body) = ep.request_parts(&texts());
            assert!(body.get("keep_alive").is_none(), "{fmt} body must not carry keep_alive: {body}");
        }
    }

    /// A front for `real` that drops the first `drop_first` TCP connections
    /// on accept (what a stale or reset connection looks like to the
    /// client: `error sending request`) and splices the rest through.
    /// Returns the front's URL and how many connections it has accepted.
    async fn flaky_front(real: &str, drop_first: usize) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let real = real.trim_start_matches("http://").to_string();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let a2 = accepted.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = l.accept().await else { return };
                let n = a2.fetch_add(1, Ordering::SeqCst);
                if n < drop_first {
                    drop(inbound);
                    continue;
                }
                let real = real.clone();
                tokio::spawn(async move {
                    if let Ok(mut out) = tokio::net::TcpStream::connect(real).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
                    }
                });
            }
        });
        (format!("http://{addr}"), accepted)
    }

    #[tokio::test]
    async fn one_stale_connection_does_not_bench_a_static_target() {
        use std::sync::atomic::Ordering;
        let (real, seen) = server(200).await;
        let (flaky, accepted) = flaky_front(&real, 1).await;
        let (other, sother) = server(200).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused");
        // The flaky target is first in the plan (nothing has failed yet).
        let cands = vec![Candidate::Static(ollama(&flaky)), Candidate::Static(ollama(&other))];
        let out = ep.embed_over(&bal, cands, &texts(), T).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "one dropped connection, one fresh retry");
        assert_eq!(seen.lock().unwrap().len(), 1, "the retry on the same target answered");
        assert_eq!(sother.lock().unwrap().len(), 0, "no failover: the target was not counted failed");
        // Not benched: it carries no cooldown entry.
        let key = Candidate::Static(ollama(&flaky)).key();
        assert!(
            !bal.cooling_until.lock().unwrap().contains_key(&key),
            "target must not be cooling after one stale connection"
        );
    }

    #[tokio::test]
    async fn a_target_failing_twice_is_benched_as_before() {
        use std::sync::atomic::Ordering;
        let (real, sreal) = server(200).await;
        let (flaky, accepted) = flaky_front(&real, 2).await;
        let (other, sother) = server(200).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused");
        let cands = || vec![Candidate::Static(ollama(&flaky)), Candidate::Static(ollama(&other))];
        ep.embed_over(&bal, cands(), &texts(), T).await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "tried, retried once, no third attempt");
        assert_eq!(sother.lock().unwrap().len(), 1, "failed over to the other target");
        // Benched: the next request does not touch it (it would now succeed).
        ep.embed_over(&bal, cands(), &texts(), T).await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "cooling target skipped");
        assert_eq!(sother.lock().unwrap().len(), 2);
        assert_eq!(sreal.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn an_http_error_status_is_not_retried() {
        let (bad, sbad) = server(500).await;
        let (good, _sgood) = server(200).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused");
        let cands = vec![Candidate::Static(ollama(&bad)), Candidate::Static(ollama(&good))];
        ep.embed_over(&bal, cands, &texts(), T).await.unwrap();
        assert_eq!(sbad.lock().unwrap().len(), 1, "an answered 500 is not a stale connection");
    }

    #[test]
    fn declared_cpu_endpoint_is_in_the_target_set_and_absent_when_not() {
        let primary = ollama("https://noo-stunnel-ollama-embed:11434");
        let none = static_endpoints_from(&primary, "");
        assert_eq!(none.len(), 1);
        assert_eq!(none[0].url, "https://noo-stunnel-ollama-embed:11434");

        let both = static_endpoints_from(
            &primary,
            " https://noo-stunnel-ollama-embed-cpu:11434/ , ,https://noo-stunnel-ollama-embed:11434",
        );
        let urls: Vec<_> = both.iter().map(|e| e.url.as_str()).collect();
        assert_eq!(
            urls,
            ["https://noo-stunnel-ollama-embed:11434", "https://noo-stunnel-ollama-embed-cpu:11434"],
            "extra is added (trimmed), blanks and a duplicate of the primary are dropped"
        );
        assert!(both.iter().all(|e| e.model == "harrier" && e.api_format == "ollama"));
    }

    #[tokio::test]
    async fn load_spreads_across_mesh_and_static_targets() {
        let (a, sa) = server(200).await;
        let (b, sb) = server(200).await;
        let (c, sc) = server(200).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused");
        for _ in 0..9 {
            let cands = vec![mesh("node-a", &a), mesh("node-b", &b), Candidate::Static(ollama(&c))];
            ep.embed_over(&bal, cands, &texts(), T).await.unwrap();
        }
        let hits = [sa.lock().unwrap().len(), sb.lock().unwrap().len(), sc.lock().unwrap().len()];
        assert_eq!(hits, [3, 3, 3], "round-robin over mesh nodes AND the static endpoint");
    }

    #[tokio::test]
    async fn a_failing_target_is_skipped_for_its_cooldown() {
        let (bad, sbad) = server(500).await;
        let (good, sgood) = server(200).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused");
        for _ in 0..6 {
            let cands = vec![mesh("bad", &bad), mesh("good", &good)];
            ep.embed_over(&bal, cands, &texts(), T).await.unwrap();
        }
        assert_eq!(sgood.lock().unwrap().len(), 6, "every request is answered");
        assert_eq!(
            sbad.lock().unwrap().len(),
            1,
            "the bad target is tried once, then skipped while cooling"
        );
    }

    #[tokio::test]
    async fn all_targets_failing_is_an_error_and_cooling_targets_are_still_last_resort() {
        let (bad, sbad) = server(500).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused");
        assert!(ep.embed_over(&bal, vec![mesh("bad", &bad)], &texts(), T).await.is_err());
        // Cooling, but the only candidate: still attempted.
        assert!(ep.embed_over(&bal, vec![mesh("bad", &bad)], &texts(), T).await.is_err());
        assert_eq!(sbad.lock().unwrap().len(), 2);
        assert!(ep.embed_over(&bal, vec![], &texts(), T).await.is_err());
    }

    #[test]
    fn least_inflight_wins_over_round_robin() {
        let bal = EmbedBalancer::new();
        let keys = vec!["a".to_string(), "b".to_string()];
        let _g1 = bal.begin("a");
        let _g2 = bal.begin("a");
        for _ in 0..4 {
            assert_eq!(bal.plan(&keys, 0)[0], 1, "b is idle, a has two in flight");
        }
    }

    fn two_texts() -> Vec<String> {
        vec!["a".into(), "b".into()]
    }

    // Saturation sheds fast with a Retry-After instead of holding the
    // caller for the full request timeout (30 s on /api/external/embeddings).
    #[tokio::test]
    async fn saturated_embedders_shed_fast_with_retry_after() {
        let (url, _) = slow_server(200, 900).await;
        let bal = Arc::new(EmbedBalancer::with_limits(1, Duration::from_millis(150)));
        let ep = ollama("http://unused");
        let (b2, e2, u2) = (bal.clone(), ep.clone(), url.clone());
        let served = tokio::spawn(async move {
            e2.embed_over(&b2, vec![mesh("n", &u2)], &two_texts(), Duration::from_secs(30)).await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t = std::time::Instant::now();
        let err = ep
            .embed_over(&bal, vec![mesh("n", &url)], &two_texts(), Duration::from_secs(30))
            .await
            .unwrap_err();
        assert!(t.elapsed() < Duration::from_millis(600), "shed in {:?}", t.elapsed());
        match err {
            EmbedError::Saturated { retry_after_secs } => {
                assert!((2..=10).contains(&retry_after_secs), "retry_after {retry_after_secs}")
            }
            other => panic!("expected Saturated, got {other:?}"),
        }
        // ...and the request already being served keeps its full timeout
        // (it outlives the 150 ms admission wait by 750 ms and still answers).
        assert!(served.await.unwrap().is_ok(), "a served request is never cut by the admission wait");
    }

    #[tokio::test]
    async fn a_waiting_request_is_admitted_when_a_slot_frees_inside_the_wait() {
        let (url, _) = slow_server(200, 200).await;
        let bal = Arc::new(EmbedBalancer::with_limits(1, Duration::from_millis(1500)));
        let ep = ollama("http://unused");
        let (b2, e2, u2) = (bal.clone(), ep.clone(), url.clone());
        let first = tokio::spawn(async move {
            e2.embed_over(&b2, vec![mesh("n", &u2)], &two_texts(), T).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(ep.embed_over(&bal, vec![mesh("n", &url)], &two_texts(), T).await.is_ok());
        assert!(first.await.unwrap().is_ok());
    }

    // Interactive single-text embeds ride a reserved slot so a batch
    // backfill that has filled the fleet cannot starve them.
    #[tokio::test]
    async fn single_text_embeds_get_a_reserved_slot_over_batches() {
        let (url, _) = slow_server(200, 700).await;
        let bal = Arc::new(EmbedBalancer::with_limits(1, Duration::from_millis(100)));
        let ep = ollama("http://unused");
        let (b2, e2, u2) = (bal.clone(), ep.clone(), url.clone());
        let batch = tokio::spawn(async move {
            e2.embed_over(&b2, vec![mesh("n", &u2)], &two_texts(), T).await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(matches!(
            ep.embed_over(&bal, vec![mesh("n", &url)], &two_texts(), T).await,
            Err(EmbedError::Saturated { .. })
        ));
        assert!(ep.embed_over(&bal, vec![mesh("n", &url)], &texts(), T).await.is_ok());
        let _ = batch.await;
    }

    #[test]
    fn saturation_maps_to_503_with_retry_after() {
        let f = crate::routes::external::embed_error_to_ext(EmbedError::Saturated { retry_after_secs: 6 });
        assert_eq!(f.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let resp = f.into_response("/api/external/embeddings");
        assert_eq!(resp.headers().get("retry-after").unwrap(), "6");
    }

    // The mesh declares harrier; a static endpoint configured for a stale
    // model must not join the spread set (mixed models in one index corrupt
    // retrieval silently).
    #[tokio::test]
    async fn a_static_endpoint_on_another_model_is_excluded_while_mesh_serves() {
        let (mesh_url, smesh) = server(200).await;
        let (stale_url, sstale) = server(200).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused"); // the space's model: harrier
        let stale = EmbeddingEndpoint { url: stale_url.clone(), model: "bge-base-en-v1.5".into(), ..ep.clone() };
        for _ in 0..6 {
            let cands = vec![mesh_declaring("node-a", &mesh_url, Some("harrier:latest")), Candidate::Static(stale.clone())];
            ep.embed_over(&bal, cands, &texts(), T).await.unwrap();
        }
        assert_eq!(smesh.lock().unwrap().len(), 6);
        assert_eq!(sstale.lock().unwrap().len(), 0, "the wrong-model endpoint must never be called");
    }

    #[tokio::test]
    async fn a_static_on_the_spaces_model_joins_and_no_consistent_target_fails_loudly() {
        let (mesh_url, _) = server(200).await;
        let (static_url, sstatic) = server(200).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused"); // the space's model: harrier
        for _ in 0..4 {
            let cands = vec![mesh("a", &mesh_url), Candidate::Static(EmbeddingEndpoint { url: static_url.clone(), ..ep.clone() })];
            ep.embed_over(&bal, cands, &texts(), T).await.unwrap();
        }
        assert_eq!(sstatic.lock().unwrap().len(), 2, "same model => in the spread");

        // Only targets on another model are left: fail, do not embed with them.
        let (only, sonly) = server(200).await;
        let (other, sother) = server(200).await;
        let stale = EmbeddingEndpoint { model: "bge".into(), ..ollama(&only) };
        let r = ep
            .embed_over(&EmbedBalancer::new(), vec![mesh_declaring("b", &other, Some("bge")), Candidate::Static(stale)], &texts(), T)
            .await;
        assert!(r.is_err());
        assert_eq!(sonly.lock().unwrap().len() + sother.lock().unwrap().len(), 0);
    }

    /// i145: there is no vote. Two of three nodes on another model do not
    /// make it the space's model; the one node still on the space's model
    /// takes every request.
    #[tokio::test]
    async fn a_majority_on_another_model_does_not_move_the_space() {
        let (a, sa) = server(200).await;
        let (b, sb) = server(200).await;
        let (c, sc) = server(200).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused"); // the space's model: harrier
        for _ in 0..5 {
            let cands = vec![
                mesh_declaring("a", &a, Some("bge-m3")),
                mesh_declaring("b", &b, Some("bge-m3")),
                mesh_declaring("c", &c, Some("harrier")),
            ];
            ep.embed_over(&bal, cands, &texts(), T).await.unwrap();
        }
        assert_eq!(sa.lock().unwrap().len() + sb.lock().unwrap().len(), 0, "the majority's model is not the space's");
        assert_eq!(sc.lock().unwrap().len(), 5);
    }

    /// A node that declares nothing is asked by name; a reply naming another
    /// model is another space's vectors: refused, and the next target answers.
    #[tokio::test]
    async fn a_reply_from_another_model_is_refused_and_the_next_target_answers() {
        let (harrier_url, sh) = server(200).await; // answers model "harrier"
        let bal = EmbedBalancer::new();
        let ep = EmbeddingEndpoint { model: "nomic-embed-code".into(), ..ollama("http://unused") };
        let r = ep.embed_over(&bal, vec![mesh_declaring("undeclared", &harrier_url, None)], &texts(), T).await;
        assert!(r.is_err(), "harrier's vectors are not the code space's");
        assert_eq!(sh.lock().unwrap().len(), 1);
        assert_eq!(served_model_refusal(Some("harrier:latest"), "harrier"), None);
        assert_eq!(served_model_refusal(None, "harrier"), None, "a reply that names no model is not refused on that ground");
        assert!(served_model_refusal(Some("bge"), "harrier").is_some());
    }

    #[tokio::test]
    async fn a_wrong_dimension_response_is_rejected_and_its_target_cooled() {
        let (bad, sbad) = server_dim(200, 0, 3).await;
        let (good, sgood) = server_dim(200, 0, 2).await;
        let bal = EmbedBalancer::new();
        let mut ep = ollama("http://unused");
        ep.dims = 2; // EMBEDDING_DIM
        for _ in 0..6 {
            let v = ep.embed_over(&bal, vec![mesh("bad", &bad), mesh("good", &good)], &texts(), T).await.unwrap();
            assert_eq!(v[0].len(), 2, "a wrong-width vector is never returned");
        }
        assert_eq!(sbad.lock().unwrap().len(), 1, "tried once, then cooled");
        assert_eq!(sgood.lock().unwrap().len(), 6);
    }

    #[tokio::test]
    async fn without_embedding_dim_the_first_mesh_targets_width_is_the_truth() {
        let (good, _) = server_dim(200, 0, 2).await;
        let (bad, sbad) = server_dim(200, 0, 3).await;
        let bal = EmbedBalancer::new();
        let ep = ollama("http://unused"); // dims = 0
        ep.embed_over(&bal, vec![mesh("good", &good)], &texts(), T).await.unwrap();
        assert_eq!(bal.learned_dim(), 2);
        let r = ep.embed_over(&bal, vec![mesh("bad", &bad)], &texts(), T).await;
        assert!(r.is_err(), "the only target is the wrong width: fail loudly");
        assert_eq!(sbad.lock().unwrap().len(), 1);
    }
}
