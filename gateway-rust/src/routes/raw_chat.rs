// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The raw chat path every external surface shares (phases 0–1):
//! `/v1/chat/completions`, `/v1/responses` and `/api/external/chat/completions`
//! (and its `kind: chat` multiplexer arm) resolve a model CLASS to an ordered
//! candidate list, send with failover across those candidates, and answer
//! with the class and the concrete model that served — never with a node
//! id, an address or a URL.
//!
//! ## Failover (what `send_llm_with_fallback` does for the agentic path)
//!
//! A candidate fails over when it cannot be connected to, does not return
//! response headers in time, or answers with a status+body that
//! `is_retryable_llm_http_error` classifies as the BACKEND being down
//! (502/503/504 dial failures, a context overflow), or when it STALLS: it
//! connected and then produced nothing (see below). When every candidate
//! stalled the answer is a 504, not a hang to the deadline. Up to
//! `MAX_LLM_BACKEND_ATTEMPTS` candidates are tried; a failed URL is never
//! retried within one request; each failover fires the same
//! `inference.backend_failover` operator alert (general summary, evidence in
//! the detail, 15 min cooldown per failed backend). A non-streaming request
//! is retried whole. A streaming request is retried only until its first
//! byte reaches the client: once the body is being relayed there is no
//! second attempt — the guard flips when the first chunk is forwarded.
//!
//! ## Stalls (non-streaming requests)
//!
//! A non-streaming completion's headers arrive only with the whole answer,
//! so a wedged engine (connection accepted, `/health` fine, nothing ever
//! generated) is indistinguishable from a slow one. So a non-streaming chat
//! request is sent to the backend AS A STREAM (`stream: true`,
//! `include_usage`), the first chunk is required within
//! [`FIRST_TOKEN_TIMEOUT`] and each later chunk within [`STREAM_IDLE_TIMEOUT`],
//! and `chat_aggregate` folds the frames back into one `chat.completion`
//! body. Those windows only decide when to MOVE ON: the last candidate a
//! request can still try is given the rest of [`OVERALL_DEADLINE`] to start
//! answering, since cutting it off would turn a slow answer into none; the caller still sees a non-streaming response and a long answer that
//! keeps producing tokens is never cut. A stall is a failover like any other
//! and its failure text says so plainly and names the restart command.
//! `n > 1` and non-chat paths (`/v1/responses` native) keep the old
//! single-shot call.
//!
//! ## Errors on the external surface (phase 0)
//!
//! Every error this module returns carries two texts: `detail`, which may
//! name the node, the address and the upstream body and goes to the log and
//! the audit row under a reference id; and the PUBLIC message, which is
//! general and carries that reference so the operator can find the detail.
//! `response_guard_tests` pins that the public body never contains a node
//! id, an address, a port or a URL.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::{Body, Bytes},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::coordinator::classes::{self, Candidate};
use crate::routes::chat_aggregate::{self, ReadFailure};
use crate::coordinator::{self, MAX_LLM_BACKEND_ATTEMPTS, BACKEND_FAILOVER_ALERT_COOLDOWN_SECS};
use crate::state::AppState;
use crate::usage::{StreamUsageCtx, UsageActor};

/// The whole request, all attempts included (as `send_raw_chat` always had).
pub const OVERALL_DEADLINE: Duration = Duration::from_secs(300);
/// A STREAMING attempt must produce response headers (the first token is
/// right behind them) within this, or the next candidate is tried. A
/// non-streaming call is not held to this — its headers would arrive with the
/// whole completion — it is sent as a stream and held to
/// [`FIRST_TOKEN_TIMEOUT`] / [`STREAM_IDLE_TIMEOUT`] instead.
pub const STREAM_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// A NON-streaming attempt is sent to the backend as a stream (and folded
/// back into one body, see `chat_aggregate`); the first chunk — connect,
/// headers and first token together — must arrive within this, or the
/// candidate is declared stalled and the next one is tried. A wedged engine
/// accepts the connection and says nothing; before this, such a call hung to
/// the caller's own timeout and no failover ever happened.
pub const FIRST_TOKEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Between chunks of that stream, after the first. A long answer that keeps
/// producing tokens is never cut by this; only silence is.
pub const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub const HEADER_CLASS: &str = "x-noo-served-class";
pub const HEADER_MODEL: &str = "x-noo-served-model";

// ── errors ───────────────────────────────────────────────────────────────

/// A failure on the raw path, in two voices.
#[derive(Debug, Clone)]
pub struct RawChatError {
    pub status: StatusCode,
    /// OpenAI-style `type`: `model_not_found`, `backend_unavailable`,
    /// `backend_error`, `server_error`, `bad_request`.
    pub kind: &'static str,
    /// For the operator: may name nodes, addresses, upstream text. Logged and
    /// written to the audit row; never returned to a consumer.
    pub detail: String,
    /// For the consumer, when the general wording for `status` is not right
    /// (a validation message about the caller's own input).
    public: Option<String>,
    /// `ref-…`, the same id on the log line, the audit row and the body.
    pub reference: String,
    /// Seconds a well-behaved client should wait before retrying; rendered
    /// as a `Retry-After` header. Set by load-shedding refusals only.
    pub retry_after: Option<u64>,
}

impl RawChatError {
    pub fn new(status: StatusCode, kind: &'static str, detail: impl Into<String>) -> Self {
        Self { status, kind, detail: detail.into(), public: None, reference: crate::egress::new_ref(), retry_after: None }
    }

    /// A refusal about the caller's own request (400): the message IS the
    /// public one — it names fields, not topology.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        Self { public: Some(msg.clone()), ..Self::new(StatusCode::BAD_REQUEST, "bad_request", msg) }
    }

    /// From a legacy resolver error: 404 for a pin nothing serves, else 503.
    pub fn from_resolve(e: &anyhow::Error) -> Self {
        let status = coordinator::resolve_failure_status(e, 503);
        let (status, kind) = if status == 404 {
            (StatusCode::NOT_FOUND, "model_not_found")
        } else {
            (StatusCode::SERVICE_UNAVAILABLE, "backend_unavailable")
        };
        Self::new(status, kind, format!("resolve failed: {e}"))
    }

    /// A backend answered non-2xx and the loop will not try elsewhere.
    pub fn upstream(status: StatusCode, body: &str, model: &str, url: &str) -> Self {
        if let Some(refusal) = coordinator::backend_model_not_found(status.as_u16(), body, model, url) {
            return Self::new(StatusCode::NOT_FOUND, "model_not_found", refusal.to_string());
        }
        Self::new(status, "backend_error", format!("backend at {url} answered {status}: {}", crate::text::clip(body, 500)))
    }

    /// What the consumer reads. General by status unless the error set its own.
    pub fn public_message(&self) -> String {
        if let Some(p) = &self.public {
            return p.clone();
        }
        public_message_for(self.status)
    }

    /// The OpenAI-shaped body: `{"error": {"message", "type", "ref"}}`.
    pub fn body(&self) -> Value {
        json!({"error": {
            "message": self.public_message(),
            "type": self.kind,
            "ref": self.reference,
        }})
    }

    /// Log the detail under the reference. Called once, by whoever renders.
    pub fn log(&self, surface: &str) {
        tracing::error!(
            reference = %self.reference,
            surface,
            status = self.status.as_u16(),
            kind = self.kind,
            detail = %self.detail,
            "raw_chat_refused"
        );
    }

    /// Log, then the external response.
    pub fn into_response(self, surface: &str) -> Response {
        self.log(surface);
        let retry_after = self.retry_after;
        let mut resp = (self.status, Json(self.body())).into_response();
        if let Some(secs) = retry_after {
            if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(axum::http::header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

/// The general wording for a status. No node, address, URL or upstream text
/// can get in here: the only input is the status code.
pub fn public_message_for(status: StatusCode) -> String {
    match status.as_u16() {
        404 => "no model, class or alias by that name is served".to_string(),
        503 => "no inference backend is available right now".to_string(),
        502 | 504 => "the inference backend did not answer".to_string(),
        s if (400..500).contains(&s) => format!("the inference backend rejected the request (HTTP {s})"),
        s => format!("the inference backend failed (HTTP {s})"),
    }
}

// ── outcome ──────────────────────────────────────────────────────────────

/// Which candidate answered — the operator half (`node_id`, `url`) goes to
/// usage and logs, the consumer half (`class`, `model`, `fallback`) to the
/// response envelope.
#[derive(Debug, Clone)]
pub struct Served {
    pub class: String,
    pub model: String,
    pub backend_type: String,
    pub node_id: String,
    pub url: String,
    /// The answering candidate was not the class's first choice.
    pub fallback: bool,
    pub attempts: usize,
}

impl Served {
    /// The `noo` object on a non-streaming body / the metadata frame.
    pub fn envelope(&self) -> Value {
        json!({"class": self.class, "served_model": self.model, "fallback": self.fallback})
    }
}

pub enum Outcome {
    Stream { resp: Box<reqwest::Response>, served: Served, usage: StreamUsageCtx, guard: RetryGuard },
    Json { data: Value, served: Served },
}

/// Bounds the retry loop and refuses a retry once the client has been sent
/// a byte: the body stream flips `streamed`, and `may_retry` reads it.
///
/// It also carries the winning candidate's in-flight ticket
/// (`classes::InFlight`): the guard lives as long as the answer — the
/// stream holds a clone until the client has read the last byte — so a
/// pool counts the request as open for exactly that long.
#[derive(Clone, Debug)]
pub struct RetryGuard {
    streamed: Arc<AtomicBool>,
    max_attempts: usize,
    ticket: Arc<std::sync::Mutex<Option<classes::InFlight>>>,
}

impl RetryGuard {
    pub fn new(max_attempts: usize) -> Self {
        Self { streamed: Arc::new(AtomicBool::new(false)), max_attempts, ticket: Arc::default() }
    }
    /// Keep `ticket` open for as long as this guard (or a clone) lives.
    pub fn hold(&self, ticket: classes::InFlight) {
        if let Ok(mut t) = self.ticket.lock() {
            *t = Some(ticket);
        }
    }
    /// `tried` attempts have been made; may a next one happen?
    pub fn may_retry(&self, tried: usize) -> bool {
        !self.streamed.load(Ordering::SeqCst) && tried < self.max_attempts
    }
    pub fn mark_streamed(&self) {
        self.streamed.store(true, Ordering::SeqCst);
    }
    pub fn has_streamed(&self) -> bool {
        self.streamed.load(Ordering::SeqCst)
    }
}

// ── resolution ───────────────────────────────────────────────────────────

/// The class a hint names and its routable candidates in order: the pinned
/// `node`'s first when the caller named one (`node` body field /
/// `X-Noo-Node`), then the mesh — or that node alone when `strict`
/// (`node_strict` / `X-Noo-Node-Strict`), see `classes::select_with`.
///
/// With no class table at all (a fleet whose nodes report nothing — the
/// one-box standalone whose only backend is the `ollama-embed` container,
/// or a gateway whose KV is empty), the legacy resolver's static
/// `OLLAMA_URL` last resort is wrapped as the single candidate of
/// `chat-default`, so a standalone install keeps answering.
pub async fn resolve_candidates(state: &AppState, hint: Option<&str>, node: Option<&str>, strict: bool) -> Result<(String, Vec<Candidate>), RawChatError> {
    let table = classes::load_table(state)
        .await
        .map_err(|e| RawChatError::new(StatusCode::SERVICE_UNAVAILABLE, "server_error", format!("class table unavailable: {e}")))?;
    let node = node.map(str::trim).filter(|n| !n.is_empty());
    if table.classes.is_empty() && node.is_none() {
        // The raw proxy forwards to cluster backends only; a cloud model
        // runs through the agent loop (`/api/inference`), which holds the
        // provider auth. Same 404 a cloud name got before cloud backends
        // existed in the resolver.
        if let Some(h) = coordinator::model_hint(hint).filter(|h| coordinator::is_cloud_model(h)) {
            return Err(RawChatError::new(
                StatusCode::NOT_FOUND,
                "model_not_found",
                format!("model '{h}' is a cloud model; this route serves cluster models only (cloud models run through /api/inference)"),
            ));
        }
        let backend = coordinator::resolve_backend_for_model(state, hint).await.map_err(|e| RawChatError::from_resolve(&e))?;
        let cand = classes::Candidate::synthetic(
            coordinator::node_from_backend_url(&backend.url).unwrap_or_else(|| "controller".into()),
            backend.backend_type,
            backend.model,
            backend.url,
        );
        return Ok((classes::CHAT_DEFAULT.to_string(), vec![cand]));
    }
    let sel = classes::select(&table, hint, node, strict, &|_| false).map_err(refusal_error)?;
    log_selection(&sel, node, strict);
    Ok((sel.class, sel.candidates))
}

/// A selection refusal on the raw surfaces. A node pin is the caller's own
/// input, so its refusal says what was wrong with it (the node name the
/// caller sent, nothing about addresses).
pub fn refusal_error(r: classes::Refusal) -> RawChatError {
    use classes::Refusal::*;
    match r {
        UnknownModel(m) => RawChatError::new(StatusCode::NOT_FOUND, "model_not_found", m),
        NoCandidates(m) => RawChatError::new(StatusCode::SERVICE_UNAVAILABLE, "backend_unavailable", m),
        UnknownNode(m) => RawChatError { public: Some(m.clone()), ..RawChatError::new(StatusCode::UNPROCESSABLE_ENTITY, "node_not_found", m) },
        NodeServesNoChat(m) => RawChatError { public: Some(m.clone()), ..RawChatError::new(StatusCode::UNPROCESSABLE_ENTITY, "node_serves_no_chat", m) },
        // The public text names only what the caller sent; what the node
        // DOES serve stays in the detail (operator-side, under the ref).
        NodeCannotServe(m) => {
            let public = m.split("; it serves").next().unwrap_or(&m).to_string();
            RawChatError { public: Some(public), ..RawChatError::new(StatusCode::CONFLICT, "node_cannot_serve", m) }
        }
    }
}

/// One line per request saying where it can go and why, and which nodes
/// were left out or demoted (offline, thermal, stalled, quarantined).
fn log_selection(sel: &classes::Selection, node: Option<&str>, strict: bool) {
    let order: Vec<String> = sel.candidates.iter().map(|c| format!("{}/{}={} [{}]", c.node_id, c.backend, c.model, c.rank)).collect();
    if sel.last_resort {
        tracing::warn!(class = %sel.label, order = ?order, "raw_chat_only_excluded_candidates_left");
    }
    tracing::info!(class = %sel.label, node_pin = ?node, node_strict = strict, order = ?order, skipped = ?sel.skipped, "raw_chat_candidates");
}

// ── the loop ─────────────────────────────────────────────────────────────

/// How long a candidate may stay silent before it counts as stalled.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// A streaming request's response headers.
    pub header: Duration,
    /// A non-streaming request, sent on the wire as a stream: connect, headers
    /// AND the first chunk, all inside this one window.
    pub first_token: Duration,
    /// Between chunks of a non-streaming request after the first.
    pub idle: Duration,
}

impl Timeouts {
    pub const PRODUCTION: Timeouts =
        Timeouts { header: STREAM_HEADER_TIMEOUT, first_token: FIRST_TOKEN_TIMEOUT, idle: STREAM_IDLE_TIMEOUT };
}

const CHAT_PATH: &str = "/v1/chat/completions";

/// A non-streaming chat request can be sent to the backend as a stream and
/// folded back (see `chat_aggregate`). Not for another path (the native
/// `/v1/responses` stream has a different frame shape) and not for `n > 1`
/// (the aggregator folds one choice).
fn can_aggregate(path: &str, body: &Value) -> bool {
    path == CHAT_PATH && body.get("n").and_then(Value::as_u64).unwrap_or(1) <= 1
}

/// Did the caller get something other than what it asked for? The first
/// candidate is a fallback too when `select` put it there as a stand-in
/// (rank `fallback,…`: a model nothing serves, a class with nothing live).
fn is_fallback(index: usize, cand: &Candidate) -> bool {
    index != 0 || cand.rank.starts_with("fallback,")
}

/// The operator-surface wording for a candidate that connected and then said
/// nothing. Names what happened and the one command that usually clears it.
fn stall_text(what: &str, secs: u64, cand: &Candidate) -> String {
    format!(
        "stalled: connected but {what} within {secs}s (engine may be wedged; restart: `noo cluster restart-backends {} noo-{}`)",
        cand.node_id, cand.backend
    )
}

/// What a successful attempt hands back.
pub(crate) enum CoreBody {
    Stream(Box<reqwest::Response>),
    Json(Value),
}

pub(crate) struct CoreSuccess {
    pub index: usize,
    pub attempts: usize,
    pub body: CoreBody,
    pub guard: RetryGuard,
}

/// The failover loop without the gateway's state: the client, the timeouts
/// and the alert are passed in, so it runs against fake backends in a test.
/// `on_failover(failed_url, detail)` is called when a candidate failed and
/// another will be tried.
pub(crate) async fn failover_core<'a, F, A>(
    client: &reqwest::Client,
    class: &str,
    candidates: &[Candidate],
    stream: bool,
    timeouts: Timeouts,
    deadline: Instant,
    mut build: F,
    mut on_failover: A,
) -> Result<CoreSuccess, RawChatError>
where
    F: FnMut(&Candidate) -> (String, Value),
    A: FnMut(String, String) -> futures::future::BoxFuture<'a, ()>,
{
    let guard = RetryGuard::new(MAX_LLM_BACKEND_ATTEMPTS);
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut last_failure = String::from("no candidate tried");
    let mut tried = 0usize;
    // Every failure so far was a stall: if so, the answer is a 504.
    let mut all_stalled = true;

    for (i, cand) in candidates.iter().enumerate() {
        if tried > 0 && !guard.may_retry(tried) {
            break;
        }
        if failed.iter().any(|(u, b)| u == &cand.url && b == &cand.backend) {
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last_failure = "overall deadline reached".into();
            all_stalled = false;
            break;
        }
        tried += 1;
        // Open while this attempt runs; handed to the guard if it answers.
        let ticket = classes::InFlight::open(&cand.url, &cand.backend);
        let (path, mut body) = build(cand);
        // A non-streaming call goes out as a stream so a stall is visible.
        let aggregate = !stream && can_aggregate(&path, &body);
        if aggregate {
            body["stream"] = json!(true);
            body["stream_options"] = json!({"include_usage": true});
        }
        let url = format!("{}{}", cand.url.trim_end_matches('/'), path);
        // `aggregate` reads the backend's SSE too: both are incremental reads.
        let req = if stream || aggregate {
            crate::node_link::backend_stream_on(client, reqwest::Method::POST, &url, &cand.backend)
        } else {
            crate::node_link::backend_request_on(client, reqwest::Method::POST, &url, &cand.backend)
        }
        .json(&body)
        .timeout(remaining);
        let window_start = Instant::now();
        // The stall windows exist to move on to a better candidate. With
        // nothing left to move on to, cutting this one off only turns a slow
        // answer into none: the last candidate gets the rest of the
        // deadline to start answering (a 12B on ollama prefilling a long
        // prompt, or queued behind another request, takes longer than 30 s).
        let last = !guard.may_retry(tried)
            || !candidates[i + 1..].iter().any(|c| {
                !(c.url == cand.url && c.backend == cand.backend) && !failed.iter().any(|(u, b)| u == &c.url && b == &c.backend)
            });
        let first_token = if last { remaining } else { timeouts.first_token };
        let header = if last { remaining } else { timeouts.header };
        let header_limit = if aggregate { first_token } else { header };
        let sent = if stream || aggregate {
            tokio::time::timeout(header_limit, req.send()).await
        } else {
            Ok(req.send().await)
        };
        let mut stalled = false;
        let failure = match sent {
            Err(_) if aggregate => {
                stalled = true;
                stall_text("no response", first_token.as_secs(), cand)
            }
            Err(_) => {
                stalled = true;
                stall_text("no response headers", header.as_secs(), cand)
            }
            // The request's own timeout (the deadline) can fire before the
            // window does when the window IS the deadline: still a stall.
            Ok(Err(e)) if e.is_timeout() => {
                stalled = true;
                stall_text("no response", header_limit.as_secs(), cand)
            }
            Ok(Err(e)) => format!("unreachable: {e}"),
            Ok(Ok(resp)) if resp.status().is_success() => {
                if stream {
                    guard.hold(ticket);
                    return Ok(CoreSuccess { index: i, attempts: tried, body: CoreBody::Stream(Box::new(resp)), guard });
                }
                if aggregate {
                    let first_wait = first_token.saturating_sub(window_start.elapsed());
                    match chat_aggregate::read_aggregated(resp, first_wait, timeouts.idle, deadline).await {
                        Ok(data) => return Ok(CoreSuccess { index: i, attempts: tried, body: CoreBody::Json(data), guard }),
                        Err(ReadFailure::NoFirstChunk) => {
                            stalled = true;
                            stall_text("no token", first_token.as_secs(), cand)
                        }
                        Err(ReadFailure::Idle) => {
                            stalled = true;
                            stall_text("the answer stopped", timeouts.idle.as_secs(), cand)
                        }
                        Err(ReadFailure::Deadline) => "overall deadline reached while the answer was streaming".into(),
                        Err(ReadFailure::Transport(e)) => format!("the stream broke: {e}"),
                        Err(ReadFailure::Truncated) => "the stream ended before the answer was complete".into(),
                        Err(ReadFailure::Backend(m)) => format!("the backend reported an error mid-answer: {}", crate::text::clip(&m, 200)),
                    }
                } else {
                    match resp.json().await {
                        Ok(data) => return Ok(CoreSuccess { index: i, attempts: tried, body: CoreBody::Json(data), guard }),
                        Err(e) => {
                            return Err(RawChatError::new(
                                StatusCode::BAD_GATEWAY,
                                "backend_error",
                                format!("backend at {} returned an unparseable body: {e}", cand.url),
                            ))
                        }
                    }
                }
            }
            Ok(Ok(resp)) => {
                let status = resp.status();
                coordinator::warn_if_node_agent_outdated(status, &url);
                let text = resp.text().await.unwrap_or_default();
                if !coordinator::is_retryable_llm_http_error(status.as_u16(), &text) {
                    let st = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
                    return Err(RawChatError::upstream(st, &text, &cand.model, &cand.url));
                }
                format!("HTTP {status}: {}", crate::text::clip(&text, 200))
            }
        };
        all_stalled &= stalled;
        if stalled {
            // Demote it for the next requests too, not only this one.
            classes::note_stall(&cand.url, &cand.backend);
        }

        tracing::error!(class, node = %cand.node_id, url = %cand.url, attempt = tried, failure = %failure, "raw_chat_candidate_failed");
        failed.push((cand.url.clone(), cand.backend.clone()));
        last_failure = failure.clone();

        let next = candidates[i + 1..].iter().find(|c| !failed.iter().any(|(u, b)| u == &c.url && b == &c.backend));
        if let Some(next) = next {
            if guard.may_retry(tried) {
                tracing::info!(class, failed_node = %cand.node_id, next_node = %next.node_id, next_model = %next.model, "raw_chat_failover");
                on_failover(
                    cand.url.clone(),
                    format!(
                        "class {class}: failed {}/{} at {}; reason: {failure}; next {}/{} ({}) at {}",
                        cand.node_id, cand.backend, cand.url, next.node_id, next.backend, next.model, next.url
                    ),
                )
                .await;
            }
        }
    }

    let detail = format!("every candidate of class '{class}' failed ({tried} tried of {}; last: {last_failure})", candidates.len());
    if tried > 0 && all_stalled {
        return Err(RawChatError::new(StatusCode::GATEWAY_TIMEOUT, "backend_timeout", detail));
    }
    Err(RawChatError::new(StatusCode::BAD_GATEWAY, "backend_unavailable", detail))
}

/// Send to the candidates in order with failover. `build` renders the
/// request for a candidate as `(path, body)` — the body names the
/// candidate's concrete model, since a backend 404s on a name it does not
/// hold. `stream` is what the caller asked for; it decides the header
/// timeout and the outcome shape.
pub async fn send_with_failover<F>(
    state: &AppState,
    class: &str,
    candidates: &[Candidate],
    stream: bool,
    source: &'static str,
    actor: UsageActor,
    build: F,
) -> Result<Outcome, RawChatError>
where
    F: FnMut(&Candidate) -> (String, Value),
{
    let deadline = Instant::now() + OVERALL_DEADLINE;
    let client = crate::tls::failover_client();
    let ok = failover_core(&client, class, candidates, stream, Timeouts::PRODUCTION, deadline, build, move |url, detail| {
        Box::pin(async move {
            crate::operator_alert::send_operator_alert_detached_with(
                state,
                coordinator::backend_failover_alert(&url, detail),
                BACKEND_FAILOVER_ALERT_COOLDOWN_SECS,
            )
            .await;
        })
    })
    .await?;

    let cand = &candidates[ok.index];
    let served = Served {
        class: class.to_string(),
        model: cand.model.clone(),
        backend_type: cand.backend.clone(),
        node_id: cand.node_id.clone(),
        url: cand.url.clone(),
        // Not the class's first choice, or a stand-in for what was named
        // (a class or model with nothing live, answered by the mesh).
        fallback: is_fallback(ok.index, cand),
        attempts: ok.attempts,
    };
    let label = if cand.class_label.is_empty() { class } else { cand.class_label.as_str() };
    tracing::info!(
        class = %label, node = %cand.node_id, backend = %cand.backend, model = %cand.model,
        rank = %cand.rank,
        attempt = ok.attempts, fallback = served.fallback, stream, source, "raw_chat_served"
    );
    // Rebuilt per attempt: usage is charged to the candidate that answered.
    let usage = StreamUsageCtx {
        db: state.db.clone(),
        node_id: Some(cand.node_id.clone()),
        backend: cand.backend.clone(),
        model: cand.model.clone(),
        source,
        actor,
    };
    match ok.body {
        CoreBody::Stream(resp) => Ok(Outcome::Stream { resp, served, usage, guard: ok.guard }),
        CoreBody::Json(data) => {
            if let Some((p, c)) = crate::usage::usage_from_frame(&data) {
                crate::usage::record(usage.db, usage.node_id, usage.backend, usage.model, usage.source, usage.actor, p, c);
            }
            Ok(Outcome::Json { data, served })
        }
    }
}

/// Resolve and send a chat-completions body: the one call the three
/// surfaces make. `body["model"]` is rewritten per attempt to the
/// candidate's concrete model; `stream_options.include_usage` is set on a
/// streaming request so vLLM emits the usage frame.
///
/// `pin` holds the `X-Noo-Node` / `X-Noo-Node-Strict` headers; `node` and
/// `node_strict` fields in the body do the same (a header wins). A node is
/// a preference: it is tried first, then the mesh, and the answer's
/// `fallback` says when another node answered. Strict keeps the request on
/// that node: 422 when it serves no chat, 409 when it serves chat but not
/// the named model, and never another node. A name that is no node of this
/// mesh is a 422 either way. Both fields are removed before the body is
/// forwarded.
pub async fn chat_completions(
    state: &AppState,
    body: &mut Value,
    source: &'static str,
    actor: UsageActor,
    pin: &PinHeaders,
) -> Result<Outcome, RawChatError> {
    if !body.is_object() {
        return Err(RawChatError::bad_request("the request body must be a JSON object with 'messages'"));
    }
    let pin = node_pin(body, pin)?;
    let hint = coordinator::model_hint(body.get("model").and_then(Value::as_str)).map(str::to_string);
    let (class, cands) = resolve_candidates(state, hint.as_deref(), pin.node.as_deref(), pin.strict).await?;
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);
    if stream {
        body["stream_options"] = json!({"include_usage": true});
    }
    let template = body.clone();
    send_with_failover(state, &class, &cands, stream, source, actor, |cand| {
        let mut b = template.clone();
        b["model"] = json!(cand.model);
        ("/v1/chat/completions".to_string(), b)
    })
    .await
}

/// The header naming the node a chat request prefers.
pub const HEADER_NODE: &str = "x-noo-node";
/// The header that makes that node the ONLY one (`1`/`true`/`yes`/`on`).
pub const HEADER_NODE_STRICT: &str = "x-noo-node-strict";

/// The two pin headers as sent.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PinHeaders {
    pub node: Option<String>,
    /// `Some` when `X-Noo-Node-Strict` was sent.
    pub strict: Option<bool>,
}

/// What a request pins once headers and body are read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NodePin {
    pub node: Option<String>,
    pub strict: bool,
}

/// The `X-Noo-Node` header's value, if sent and non-blank.
pub fn node_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers.get(HEADER_NODE).and_then(|v| v.to_str().ok()).map(str::trim).filter(|v| !v.is_empty()).map(str::to_string)
}

/// Both pin headers. An `X-Noo-Node-Strict` value that is not a yes/no
/// word reads as yes: a caller who sent the header meant something by it,
/// and the safe reading of a locality request is the strict one.
pub fn pin_headers(headers: &axum::http::HeaderMap) -> PinHeaders {
    let strict = headers.get(HEADER_NODE_STRICT).and_then(|v| v.to_str().ok()).map(|v| {
        !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off")
    });
    PinHeaders { node: node_header(headers), strict }
}

/// The node a request prefers (the header, else the body's `node`) and
/// whether it is strict (the header, else the body's `node_strict`). Both
/// fields are taken out of the body either way — a backend must not see
/// them.
pub fn node_pin(body: &mut Value, headers: &PinHeaders) -> Result<NodePin, RawChatError> {
    let obj = body.as_object_mut();
    let (field, strict_field) = match obj {
        Some(o) => (o.remove("node"), o.remove("node_strict")),
        None => (None, None),
    };
    let from_body = match field {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Some(_) => return Err(RawChatError::bad_request("'node' must be a string naming a node")),
    };
    let strict_body = match strict_field {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(b),
        Some(_) => return Err(RawChatError::bad_request("'node_strict' must be true or false")),
    };
    Ok(NodePin {
        node: headers.node.as_deref().map(str::trim).filter(|h| !h.is_empty()).map(str::to_string).or(from_body),
        strict: headers.strict.or(strict_body).unwrap_or(false),
    })
}

// ── rendering ────────────────────────────────────────────────────────────

fn with_served_headers(mut resp: Response, served: &Served) -> Response {
    if let Ok(v) = HeaderValue::from_str(&served.class) {
        resp.headers_mut().insert(HEADER_CLASS, v);
    }
    if let Ok(v) = HeaderValue::from_str(&served.model) {
        resp.headers_mut().insert(HEADER_MODEL, v);
    }
    resp
}

/// Non-streaming: the backend's body plus `noo: {class, served_model,
/// fallback}` and the two headers.
pub fn json_response(mut data: Value, served: &Served) -> Response {
    if data.is_object() {
        data["noo"] = served.envelope();
    }
    with_served_headers((StatusCode::OK, Json(data)).into_response(), served)
}

/// The first SSE frame of a streamed chat answer: an ordinary
/// `chat.completion.chunk` with no choices and the `noo` envelope — the
/// same shape as vLLM's trailing usage frame, which every OpenAI client
/// already tolerates. (A named `event:` frame was tried first; openai-python
/// 2.x constructs a chunk from ANY non-`thread.*` event and a consumer
/// reading `chunk.choices[0]` crashed on it.)
pub fn metadata_frame(served: &Served) -> Bytes {
    let created = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    Bytes::from(format!(
        "data: {}\n\n",
        json!({
            "id": "noo-metadata",
            "object": "chat.completion.chunk",
            "created": created,
            "model": served.model,
            "choices": [],
            "noo": served.envelope(),
        })
    ))
}

/// Streaming: the metadata frame, then the upstream bytes untouched, with
/// usage tapped and the retry guard flipped on the first forwarded chunk.
pub fn stream_response(resp: reqwest::Response, served: &Served, usage: StreamUsageCtx, guard: RetryGuard) -> Response {
    use futures::StreamExt as _;
    let first = metadata_frame(served);
    let tapped = crate::usage::tap_stream(resp.bytes_stream(), usage).map(move |item| {
        guard.mark_streamed();
        item
    });
    let body = futures::stream::once(async move { Ok::<Bytes, reqwest::Error>(first) }).chain(tapped);
    let r = Response::builder()
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(body))
        .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "stream build error").into_response());
    with_served_headers(r, served)
}

#[cfg(test)]
mod node_pin_tests {
    use super::*;

    #[test]
    fn the_node_pin_comes_from_the_header_or_the_body_and_never_reaches_the_backend() {
        let none = PinHeaders::default();
        let header = |n: &str| PinHeaders { node: Some(n.into()), strict: None };
        let mut body = json!({"model": "default", "node": "mcmini", "messages": []});
        assert_eq!(node_pin(&mut body, &none).unwrap(), NodePin { node: Some("mcmini".into()), strict: false }, "a preference by default");
        assert!(body.get("node").is_none(), "stripped before forwarding");
        let mut body = json!({"node": "mcmini"});
        assert_eq!(node_pin(&mut body, &header("pop-os")).unwrap().node.as_deref(), Some("pop-os"), "the header wins");
        let mut body = json!({"node": "  "});
        assert_eq!(node_pin(&mut body, &none).unwrap().node, None);
        let mut body = json!({"node": 7});
        assert_eq!(node_pin(&mut body, &none).unwrap_err().status, StatusCode::BAD_REQUEST);
        // Strict: the body field, the header (which wins), both stripped.
        let mut body = json!({"node": "mcmini", "node_strict": true});
        assert_eq!(node_pin(&mut body, &none).unwrap(), NodePin { node: Some("mcmini".into()), strict: true });
        assert!(body.get("node_strict").is_none());
        let mut body = json!({"node": "mcmini", "node_strict": true});
        assert!(!node_pin(&mut body, &PinHeaders { node: None, strict: Some(false) }).unwrap().strict);
        let mut body = json!({"node_strict": "yes"});
        assert_eq!(node_pin(&mut body, &none).unwrap_err().status, StatusCode::BAD_REQUEST);
        let mut h = axum::http::HeaderMap::new();
        h.insert(HEADER_NODE, HeaderValue::from_static(" mcmini "));
        assert_eq!(pin_headers(&h), PinHeaders { node: Some("mcmini".into()), strict: None });
        for (v, strict) in [("1", true), ("true", true), ("YES", true), ("on", true), ("anything", true), ("0", false), ("false", false), ("no", false), ("off", false)] {
            h.insert(HEADER_NODE_STRICT, HeaderValue::from_str(v).unwrap());
            assert_eq!(pin_headers(&h).strict, Some(strict), "{v}");
        }
    }

    #[test]
    fn node_refusals_are_422_and_409_and_do_not_list_what_the_node_serves() {
        use classes::Refusal;
        assert_eq!(refusal_error(Refusal::UnknownNode("node 'x' is not a node".into())).status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refusal_error(Refusal::NodeServesNoChat("node 'x' serves no chat".into())).status, StatusCode::UNPROCESSABLE_ENTITY);
        let e = refusal_error(Refusal::NodeCannotServe("node 'pop-os' does not serve 'gemma4:12b'; it serves ollama=gemma4:e2b-it-qat".into()));
        assert_eq!(e.status, StatusCode::CONFLICT);
        assert_eq!(e.public_message(), "node 'pop-os' does not serve 'gemma4:12b'");
        assert!(e.detail.contains("e2b"), "the detail keeps it for the operator");
        assert_eq!(refusal_error(Refusal::UnknownModel("m".into())).status, StatusCode::NOT_FOUND);
        assert_eq!(refusal_error(Refusal::NoCandidates("m".into())).status, StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything a public error body must not carry. The detail of each
    /// constructed error DOES carry them, which is the point of the test.
    const FORBIDDEN: [&str; 7] = [":8081", "100.", "172.", "https://", "host3", "host6", "connection refused"];

    fn assert_clean(body: &Value) {
        let text = serde_json::to_string(body).unwrap();
        for f in FORBIDDEN {
            assert!(!text.contains(f), "public body leaks {f:?}: {text}");
        }
        assert!(body["error"]["ref"].as_str().is_some_and(|r| r.starts_with("ref-")), "{text}");
        assert!(body["error"]["message"].as_str().is_some_and(|m| !m.is_empty()));
    }

    #[test]
    fn external_error_bodies_carry_no_node_address_or_url() {
        let cases = vec![
            RawChatError::new(StatusCode::BAD_GATEWAY, "backend_unavailable",
                "every candidate of class 'chat-default' failed (2 tried; last: unreachable: error sending request for url (https://100.64.0.10:8081/v1/chat/completions): connection refused)"),
            RawChatError::upstream(StatusCode::BAD_GATEWAY,
                r#"{"error":{"code":"backend_unreachable","message":"dial tcp 172.19.0.5:8000: connect: connection refused"}}"#,
                "gemma4:12b", "https://100.64.0.11:8081"),
            RawChatError::upstream(StatusCode::NOT_FOUND, r#"{"error":"model 'x' not found"}"#, "x", "https://host3:8081"),
            RawChatError::upstream(StatusCode::INTERNAL_SERVER_ERROR, "CUDA out of memory on host3", "m", "https://100.64.0.10:8081"),
            RawChatError::upstream(StatusCode::BAD_REQUEST, "messages[0].content: host3 is not valid", "m", "https://host6:8081"),
            RawChatError::from_resolve(&anyhow::Error::new(coordinator::ModelNotServed(
                "model 'x' is not served by any node; nodes serve: host3=vllm:HF host6=ollama:gemma4:26b".into()))),
            RawChatError::from_resolve(&anyhow::anyhow!("No mesh backend and the static ollama at https://172.19.0.3:11434 has no model")),
            RawChatError::new(StatusCode::SERVICE_UNAVAILABLE, "backend_unavailable",
                "class 'fast' has 1 declared candidate(s) and none is placed or available: host6/ollama=gemma4:12b (heartbeat 400s old)"),
        ];
        assert!(cases.len() >= 8);
        let mut statuses = std::collections::HashSet::new();
        for e in cases {
            // The detail is the operator's and does carry evidence.
            assert!(!e.detail.is_empty());
            statuses.insert(e.status.as_u16());
            assert_clean(&e.body());
        }
        // Each status family rendered at least once.
        for s in [404u16, 502, 503, 500, 400] {
            assert!(statuses.contains(&s), "status {s} not exercised: {statuses:?}");
        }
        // Model-not-found keeps the OpenAI type and status.
        let e = RawChatError::upstream(StatusCode::NOT_FOUND, r#"{"error":"model 'x' not found"}"#, "x", "https://host3:8081");
        assert_eq!(e.status, StatusCode::NOT_FOUND);
        assert_eq!(e.kind, "model_not_found");
        assert_eq!(e.body()["error"]["type"], "model_not_found");
    }

    #[test]
    fn a_bad_request_keeps_its_own_message() {
        let e = RawChatError::bad_request("missing input.query");
        assert_eq!(e.public_message(), "missing input.query");
        assert_eq!(e.status, StatusCode::BAD_REQUEST);
        assert_clean(&e.body());
    }

    #[test]
    fn public_wording_is_a_pure_function_of_the_status() {
        for s in [400u16, 401, 404, 409, 422, 429, 500, 502, 503, 504] {
            let m = public_message_for(StatusCode::from_u16(s).unwrap());
            assert!(!m.is_empty());
            for f in FORBIDDEN {
                assert!(!m.contains(f));
            }
        }
        assert_eq!(public_message_for(StatusCode::NOT_FOUND), "no model, class or alias by that name is served");
    }

    #[test]
    fn no_retry_once_a_byte_has_been_streamed() {
        let g = RetryGuard::new(3);
        assert!(g.may_retry(1), "a second attempt is allowed before any byte went out");
        assert!(g.may_retry(2));
        assert!(!g.may_retry(3), "the attempt cap holds");
        g.mark_streamed();
        assert!(g.has_streamed());
        assert!(!g.may_retry(1), "once streamed, no attempt is allowed at all");
        // The clone the body stream holds flips the loop's copy.
        let g = RetryGuard::new(3);
        let tap = g.clone();
        tap.mark_streamed();
        assert!(!g.may_retry(1));
    }

    #[test]
    fn a_stand_in_first_candidate_is_reported_as_a_fallback() {
        let mut c = cand("mcmini", "ollama", "gemma4:12b", "https://100.64.0.2:8081");
        assert!(!is_fallback(0, &c));
        assert!(is_fallback(1, &c));
        c.rank = "fallback,rank=gpu,params=12,load=0.20".into();
        assert!(is_fallback(0, &c), "a model nothing serves, answered by the mesh, says so");
    }

    #[tokio::test]
    async fn served_envelope_and_headers_say_class_and_model_and_fallback_only() {
        let served = Served {
            class: "chat-default".into(),
            model: "gemma4:12b".into(),
            backend_type: "ollama".into(),
            node_id: "host6".into(),
            url: "https://100.64.0.11:8081".into(),
            fallback: true,
            attempts: 2,
        };
        let r = json_response(json!({"id": "x", "choices": []}), &served);
        assert_eq!(r.headers().get(HEADER_CLASS).unwrap(), "chat-default");
        assert_eq!(r.headers().get(HEADER_MODEL).unwrap(), "gemma4:12b");
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["noo"]["class"], "chat-default");
        assert_eq!(v["noo"]["served_model"], "gemma4:12b");
        assert_eq!(v["noo"]["fallback"], true);
        assert_eq!(v["id"], "x", "the backend's body is kept");
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!text.contains("host6") && !text.contains("100.64"), "{text}");
        // The streaming metadata frame is a chunk a client already parses:
        // a `data:` line, `chat.completion.chunk`, an (empty) `choices`.
        let frame = String::from_utf8(metadata_frame(&served).to_vec()).unwrap();
        assert!(frame.starts_with("data: "), "{frame}");
        assert!(!frame.contains("event:"), "no named event — openai-python turns any into a chunk without choices: {frame}");
        assert!(frame.ends_with("\n\n"));
        let data: Value = serde_json::from_str(frame.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(data["object"], "chat.completion.chunk");
        assert!(data["choices"].is_array(), "{data}");
        assert_eq!(data["model"], "gemma4:12b");
        assert_eq!(data["noo"]["fallback"], true);
        assert!(!frame.contains("host6") && !frame.contains("8081"));
        // Every `data:` frame of a streamed answer — ours first, then what
        // vLLM sends — parses as a chunk a client can read `choices` from.
        let upstream = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\ndata: [DONE]\n\n";
        let whole = format!("{frame}{upstream}");
        let mut frames = 0;
        for line in whole.lines().filter(|l| l.starts_with("data: ")) {
            let payload = &line["data: ".len()..];
            if payload == "[DONE]" {
                continue;
            }
            let v: Value = serde_json::from_str(payload).expect(payload);
            assert_eq!(v["object"], "chat.completion.chunk", "{payload}");
            assert!(v["choices"].is_array(), "{payload}");
            frames += 1;
        }
        assert_eq!(frames, 3);
        assert!(!whole.contains("event:"));
        // First choice served: no fallback.
        let first = Served { fallback: false, ..served };
        assert_eq!(first.envelope()["fallback"], false);
    }

    // ── stalled backends (non-streaming failover) ────────────────────────

    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// What a fake backend does with the request it accepted.
    #[derive(Clone, Copy)]
    enum Fake {
        /// Accept, read the request, answer nothing at all.
        Silent,
        /// The live wedge: 200 + SSE headers at once, then no chunk, ever.
        HeadersOnly,
        /// Answer promptly with a complete streamed completion.
        Answer(&'static str),
        /// Stream `frames` content frames, `gap` apart, then finish: total time
        /// is far over the first-token window, each gap is well inside it.
        Steady { frames: usize, gap: Duration },
        /// Two content frames, then silence.
        DiesMidAnswer,
        /// Say nothing for `wait` (a long prefill, a queue), then answer.
        LateStart { wait: Duration, text: &'static str },
    }

    struct FakeBackend {
        url: String,
        /// The request bodies it received.
        seen: Arc<Mutex<Vec<Value>>>,
    }

    fn chunk(s: &str) -> Vec<u8> {
        format!("{:x}\r\n{s}\r\n", s.len()).into_bytes()
    }

    fn sse(v: Value) -> String {
        format!("data: {v}\n\n")
    }

    async fn fake_backend(mode: Fake) -> FakeBackend {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    // Read the head, then the body by Content-Length.
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let head_end = loop {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < head_end + len {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    if let Ok(v) = serde_json::from_slice::<Value>(&buf[head_end..head_end + len]) {
                        seen.lock().unwrap().push(v);
                    }
                    let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";
                    let delta = |t: &str| sse(json!({"id":"c","model":"m","choices":[{"index":0,"delta":{"content":t}}]}));
                    let fin = sse(json!({"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}));
                    let usage = sse(json!({"id":"c","choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}));
                    match mode {
                        Fake::Silent => {
                            tokio::time::sleep(Duration::from_secs(60)).await;
                        }
                        Fake::HeadersOnly => {
                            let _ = sock.write_all(head.as_bytes()).await;
                            tokio::time::sleep(Duration::from_secs(60)).await;
                        }
                        Fake::Answer(text) => {
                            let _ = sock.write_all(head.as_bytes()).await;
                            for f in [delta(text), fin, usage, "data: [DONE]\n\n".to_string()] {
                                let _ = sock.write_all(&chunk(&f)).await;
                            }
                            let _ = sock.write_all(b"0\r\n\r\n").await;
                        }
                        Fake::Steady { frames, gap } => {
                            let _ = sock.write_all(head.as_bytes()).await;
                            for i in 0..frames {
                                let _ = sock.write_all(&chunk(&delta(&format!("w{i} ")))).await;
                                tokio::time::sleep(gap).await;
                            }
                            for f in [fin, usage, "data: [DONE]\n\n".to_string()] {
                                let _ = sock.write_all(&chunk(&f)).await;
                            }
                            let _ = sock.write_all(b"0\r\n\r\n").await;
                        }
                        Fake::LateStart { wait, text } => {
                            tokio::time::sleep(wait).await;
                            let _ = sock.write_all(head.as_bytes()).await;
                            for f in [delta(text), fin, usage, "data: [DONE]\n\n".to_string()] {
                                let _ = sock.write_all(&chunk(&f)).await;
                            }
                            let _ = sock.write_all(b"0\r\n\r\n").await;
                        }
                        Fake::DiesMidAnswer => {
                            let _ = sock.write_all(head.as_bytes()).await;
                            let _ = sock.write_all(&chunk(&delta("one "))).await;
                            let _ = sock.write_all(&chunk(&delta("two "))).await;
                            tokio::time::sleep(Duration::from_secs(60)).await;
                        }
                    }
                });
            }
        });
        FakeBackend { url, seen }
    }

    fn cand(node: &str, backend: &str, model: &str, url: &str) -> Candidate {
        Candidate::synthetic(node.into(), backend.into(), model.into(), url.into())
    }

    /// Short windows so the tests run in a fraction of a second.
    const FAST: Timeouts =
        Timeouts { header: Duration::from_millis(250), first_token: Duration::from_millis(250), idle: Duration::from_millis(250) };

    type Alerts = Arc<Mutex<Vec<(String, String)>>>;

    async fn run(cands: &[Candidate], stream: bool, t: Timeouts) -> (Result<CoreSuccess, RawChatError>, Alerts) {
        run_until(cands, stream, t, Duration::from_secs(20)).await
    }

    async fn run_until(cands: &[Candidate], stream: bool, t: Timeouts, within: Duration) -> (Result<CoreSuccess, RawChatError>, Alerts) {
        let alerts: Alerts = Arc::new(Mutex::new(Vec::new()));
        let sink = alerts.clone();
        let client = reqwest::Client::new();
        let r = failover_core(
            &client,
            "chat-default",
            cands,
            stream,
            t,
            Instant::now() + within,
            |c| (CHAT_PATH.to_string(), json!({"model": c.model, "messages": [{"role":"user","content":"hi"}]})),
            move |url, detail| {
                sink.lock().unwrap().push((url, detail));
                Box::pin(async {})
            },
        )
        .await;
        (r, alerts)
    }

    fn json_of(r: Result<CoreSuccess, RawChatError>) -> (usize, Value) {
        let ok = r.unwrap_or_else(|e| panic!("expected an answer, got {} {}", e.status, e.detail));
        match ok.body {
            CoreBody::Json(v) => (ok.index, v),
            CoreBody::Stream(_) => panic!("a non-streaming call must come back as Json"),
        }
    }

    #[tokio::test]
    async fn an_engine_that_connects_and_never_sends_a_token_fails_over_and_the_alert_says_stalled() {
        for first in [Fake::HeadersOnly, Fake::Silent] {
            let wedged = fake_backend(first).await;
            let healthy = fake_backend(Fake::Answer("from the second")).await;
            let cands = [cand("node-a", "vllm", "m1", &wedged.url), cand("node-b", "ollama", "m2", &healthy.url)];
            let started = Instant::now();
            let (r, alerts) = run(&cands, false, FAST).await;
            let (index, data) = json_of(r);
            assert!(started.elapsed() < Duration::from_secs(5), "failover must happen at the window, not the deadline");
            assert_eq!(index, 1, "the second candidate answered");
            assert_eq!(data.pointer("/choices/0/message/content").and_then(Value::as_str), Some("from the second"));
            assert_eq!(crate::usage::usage_from_frame(&data), Some((4, 2)));
            let alerts = alerts.lock().unwrap();
            assert_eq!(alerts.len(), 1, "one failover, one alert");
            let (target, detail) = &alerts[0];
            assert_eq!(target, &wedged.url);
            assert!(detail.contains("stalled"), "{detail}");
            assert!(detail.contains("no token") || detail.contains("no response"), "{detail}");
            assert!(detail.contains("noo cluster restart-backends node-a noo-vllm"), "names the node and container: {detail}");
        }
    }

    /// 2026-10-19: every external chat to mcmini (the only live chat-default
    /// candidate, a 12B on ollama) was cut at 30 s and answered 504, for
    /// hours, although the node answered when given time. With nothing left
    /// to fail over to, the window is the deadline.
    #[tokio::test]
    async fn the_last_candidate_is_given_the_deadline_not_the_stall_window() {
        let slow = fake_backend(Fake::LateStart { wait: Duration::from_millis(700), text: "late but whole" }).await;
        for stream in [false, true] {
            let (r, alerts) = run(&[cand("mcmini", "ollama", "gemma4:12b", &slow.url)], stream, FAST).await;
            let ok = r.unwrap_or_else(|e| panic!("stream={stream}: {}", e.detail));
            if !stream {
                let (_, data) = json_of(Ok(ok));
                assert_eq!(data.pointer("/choices/0/message/content").and_then(Value::as_str), Some("late but whole"));
            }
            assert!(alerts.lock().unwrap().is_empty());
        }
        // Not the last: the same slow start still fails over at the window.
        let spare = fake_backend(Fake::Answer("spare")).await;
        let started = Instant::now();
        let (r, _) = run(&[cand("a", "ollama", "m", &slow.url), cand("b", "ollama", "m", &spare.url)], false, FAST).await;
        assert_eq!(json_of(r).0, 1);
        assert!(started.elapsed() < Duration::from_millis(650), "moved on at the window");
    }

    #[tokio::test]
    async fn a_non_streaming_call_goes_to_the_backend_as_a_stream_with_usage() {
        let b = fake_backend(Fake::Answer("ok")).await;
        let (r, _) = run(&[cand("n", "vllm", "m", &b.url)], false, FAST).await;
        json_of(r);
        let seen = b.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0]["stream"], true, "{}", seen[0]);
        assert_eq!(seen[0]["stream_options"]["include_usage"], true);
    }

    #[tokio::test]
    async fn a_slow_but_steady_stream_longer_than_the_first_token_window_is_not_failed_over() {
        // 12 frames 60 ms apart = ~720 ms, nearly three times the 250 ms windows;
        // no gap comes close to a window.
        let slow = fake_backend(Fake::Steady { frames: 12, gap: Duration::from_millis(60) }).await;
        let spare = fake_backend(Fake::Answer("must not be used")).await;
        let cands = [cand("a", "vllm", "m", &slow.url), cand("b", "ollama", "m", &spare.url)];
        let started = Instant::now();
        let (r, alerts) = run(&cands, false, FAST).await;
        let (index, data) = json_of(r);
        assert!(started.elapsed() > FAST.first_token, "the test must outlast the window to mean anything");
        assert_eq!(index, 0, "a long answer that keeps producing tokens is never cut");
        assert!(alerts.lock().unwrap().is_empty());
        let text = data.pointer("/choices/0/message/content").and_then(Value::as_str).unwrap();
        assert!(text.starts_with("w0 w1 ") && text.ends_with("w11 "), "{text}");
        assert!(spare.seen.lock().unwrap().is_empty(), "the spare was never asked");
    }

    #[tokio::test]
    async fn an_engine_that_stops_mid_answer_is_a_stall_and_the_request_is_retried_whole() {
        let dies = fake_backend(Fake::DiesMidAnswer).await;
        let healthy = fake_backend(Fake::Answer("whole answer")).await;
        let cands = [cand("a", "vllm", "m", &dies.url), cand("b", "ollama", "m", &healthy.url)];
        let (r, alerts) = run(&cands, false, FAST).await;
        let (index, data) = json_of(r);
        assert_eq!(index, 1);
        assert_eq!(data.pointer("/choices/0/message/content").and_then(Value::as_str), Some("whole answer"), "no half answer is stitched in");
        let alerts = alerts.lock().unwrap();
        assert!(alerts[0].1.contains("stalled") && alerts[0].1.contains("the answer stopped"), "{}", alerts[0].1);
    }

    #[tokio::test]
    async fn every_candidate_stalling_answers_504_naming_the_stall_for_the_operator_only() {
        let a = fake_backend(Fake::HeadersOnly).await;
        let b = fake_backend(Fake::Silent).await;
        let cands = [cand("node-one", "vllm", "m", &a.url), cand("node-two", "ollama", "m", &b.url)];
        let started = Instant::now();
        let (r, alerts) = run_until(&cands, false, FAST, Duration::from_secs(1)).await;
        let e = match r {
            Err(e) => e,
            Ok(_) => panic!("both candidates are wedged"),
        };
        // The last candidate is waited on to the deadline, never past it.
        assert!(started.elapsed() >= Duration::from_millis(900), "the last candidate gets the rest of the deadline");
        assert!(started.elapsed() < Duration::from_secs(5), "must not hang past the deadline");
        assert_eq!(e.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(e.kind, "backend_timeout");
        assert!(e.detail.contains("stalled"), "{}", e.detail);
        assert!(e.detail.contains("restart-backends node-two noo-ollama"), "{}", e.detail);
        assert_eq!(alerts.lock().unwrap().len(), 1, "an alert for the first failover; none when nothing is left to try");
        // The consumer's body stays general: no node, address or URL.
        assert_clean(&e.body());
        assert!(!e.body().to_string().contains("stalled"));
    }

    #[tokio::test]
    async fn a_mix_of_a_stall_and_a_dead_port_is_a_502_not_a_504() {
        let wedged = fake_backend(Fake::HeadersOnly).await;
        // A port nothing listens on.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let cands = [cand("a", "vllm", "m", &wedged.url), cand("b", "ollama", "m", &dead)];
        let (r, _) = run(&cands, false, FAST).await;
        let e = match r {
            Err(e) => e,
            Ok(_) => panic!("neither candidate can answer"),
        };
        assert_eq!(e.status, StatusCode::BAD_GATEWAY, "{}", e.detail);
    }

    #[tokio::test]
    async fn a_streaming_caller_still_gets_the_live_stream_and_its_header_timeout() {
        let b = fake_backend(Fake::Answer("hi")).await;
        let (r, _) = run(&[cand("n", "vllm", "m", &b.url)], true, FAST).await;
        let ok = r.unwrap_or_else(|e| panic!("{}", e.detail));
        assert!(matches!(ok.body, CoreBody::Stream(_)));
        assert_eq!(b.seen.lock().unwrap()[0].get("stream"), None, "the caller's body is passed through untouched");
        // A wedged engine that never sends headers still fails over a stream.
        let wedged = fake_backend(Fake::Silent).await;
        let healthy = fake_backend(Fake::Answer("hi")).await;
        let (r, alerts) = run(&[cand("a", "vllm", "m", &wedged.url), cand("b", "ollama", "m", &healthy.url)], true, FAST).await;
        assert_eq!(r.unwrap_or_else(|e| panic!("{}", e.detail)).index, 1);
        assert!(alerts.lock().unwrap()[0].1.contains("stalled"));
    }

    #[test]
    fn only_a_single_choice_chat_request_is_sent_as_a_stream() {
        assert!(can_aggregate(CHAT_PATH, &json!({"messages": []})));
        assert!(can_aggregate(CHAT_PATH, &json!({"n": 1})));
        assert!(!can_aggregate(CHAT_PATH, &json!({"n": 2})), "the aggregator folds one choice");
        assert!(!can_aggregate("/v1/responses", &json!({})), "the native Responses stream has its own frames");
    }
}
