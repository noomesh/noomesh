// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Request tracing (i359): every authenticated request the gateway serves
//! becomes a trace in Tempo and one summary row in `noo_request_trace`.
//! Anonymous, refused (401) and rate-limited (429) requests record nothing:
//! a flood the limiter answers costs no database write (see [`Recorder`]).
//!
//! The operator's decision (2026-10-31): trace everything, keep 30 days,
//! carry metadata and sizes only — routes, ids, model, node, timings,
//! status, token counts, tool names — and never prompt or answer text. The
//! point is that an agent can later learn from it ("which backend was slow
//! for this kind of request", "where did this task spend its time"), so the
//! summary sits in Postgres next to memory and the full spans go to Tempo
//! for Grafana.
//!
//! ## Shape
//!
//! [`trace_layer`] wraps the router. It holds the caller's W3C
//! `traceparent` when one is well formed and continues it only once the
//! caller authenticates (otherwise the request has its own trace), puts a [`Recorder`] in a
//! task-local for the handler, and answers with a `traceparent` header so a
//! caller can find its own trace. Code inside the request notes what it
//! learns: [`note_principal`] (the auth-scoped layer), [`note_usage`] (the
//! token-usage writer).
//!
//! The trace ends when the RESPONSE BODY ends, not when the headers go out:
//! a streamed answer (SSE) is still running when the handler returns. A
//! streamed body is wrapped so the trace closes when the stream is dropped,
//! finished or cut; any other body closes at once.
//!
//! ## No OpenTelemetry crates
//!
//! The exporter speaks OTLP/HTTP with the JSON encoding, which Tempo
//! accepts on its OTLP HTTP receiver, through the cluster client (cluster
//! CA, the gateway's own leaf). That keeps the dependency set as it was:
//! a span here is a handful of fields, and the wire format is stable.
//!
//! ## What is not traced
//!
//! `/health`, `/metrics`, static assets and the node log push: probes and
//! the log rail's own traffic, which would bury every request a person or
//! an agent made.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::state::AppState;

/// How long a summary row is kept. A constant, not a setting, like
/// `autonomy_audit::RETENTION_DAYS`: the operator chose 30 days, and a
/// setting would let the table be left unbounded.
pub const RETENTION_DAYS: i64 = 30;

/// The prune runs once a day.
pub const PRUNE_INTERVAL_SECS: u64 = 86_400;

/// The prune loop's `loop_health` name.
pub const PRUNE_LOOP_NAME: &str = "request_trace_prune";

/// Let the gateway finish booting (and the migrations settle) first.
const STARTUP_GRACE_SECS: u64 = 300;

/// Spans waiting for the exporter. Full means Tempo is not keeping up (or
/// is down): new spans are dropped and counted, never queued without bound
/// and never allowed to slow a request.
const EXPORT_QUEUE: usize = 8_192;

/// One OTLP request carries at most this many spans.
const EXPORT_BATCH: usize = 512;

/// A partial batch goes out after this long.
const EXPORT_EVERY: Duration = Duration::from_secs(5);

/// The service name every gateway span carries.
pub const SERVICE_NAME: &str = "noo-gateway";

/// The Tempo OTLP HTTP base URL (`https://tempo:4318`). Empty means no
/// Tempo on this controller: spans are not exported, summary rows still are.
pub const TEMPO_URL_ENV: &str = "NOO_TEMPO_OTLP_URL";

// ── ids ────────────────────────────────────────────────────────────────

/// A W3C trace context: 16-byte trace id, 8-byte span id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::Rng;
    let mut b = [0u8; N];
    // An all-zero id is invalid in W3C trace context; the odds are nil, but
    // a zero would make the whole trace unreadable, so it is never sent.
    while b.iter().all(|x| *x == 0) {
        rand::rng().fill_bytes(&mut b);
    }
    b
}

pub fn new_span_id() -> [u8; 8] {
    random_bytes::<8>()
}

/// Parse a `traceparent` header (`00-<32 hex>-<16 hex>-<2 hex>`). Anything
/// else, an all-zero id included, is ignored and a new trace starts.
pub fn parse_traceparent(v: &str) -> Option<TraceContext> {
    let mut parts = v.trim().split('-');
    let (ver, tid, sid, flags) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || ver != "00" || flags.len() != 2 || hex::decode(flags).is_err() {
        return None;
    }
    let trace_id: [u8; 16] = hex::decode(tid).ok()?.try_into().ok()?;
    let span_id: [u8; 8] = hex::decode(sid).ok()?.try_into().ok()?;
    if trace_id.iter().all(|b| *b == 0) || span_id.iter().all(|b| *b == 0) {
        return None;
    }
    Some(TraceContext { trace_id, span_id })
}

/// The `traceparent` value for a span (always sampled: everything is traced).
pub fn traceparent(trace_id: &[u8; 16], span_id: &[u8; 8]) -> String {
    format!("00-{}-{}-01", hex::encode(trace_id), hex::encode(span_id))
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

// ── spans ──────────────────────────────────────────────────────────────

/// OTLP span kinds used here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanKind {
    /// The request the gateway served.
    Server = 2,
    /// A call the gateway made for it (a model backend).
    Client = 3,
}

/// An attribute value. Text attributes are names and ids, never content.
#[derive(Clone, Debug, PartialEq)]
pub enum Attr {
    Str(String),
    Int(i64),
}

/// One finished span, ready for the exporter.
#[derive(Clone, Debug)]
pub struct SpanRecord {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent: Option<[u8; 8]>,
    pub name: String,
    pub kind: SpanKind,
    pub start_ns: u64,
    pub end_ns: u64,
    pub attrs: Vec<(&'static str, Attr)>,
    pub error: bool,
}

impl SpanRecord {
    /// The OTLP/JSON form of one span. Ids are hex, 64-bit numbers are
    /// strings: both as the OTLP JSON encoding requires.
    pub fn to_otlp(&self) -> Value {
        let attrs: Vec<Value> = self
            .attrs
            .iter()
            .map(|(k, v)| match v {
                Attr::Str(s) => json!({"key": k, "value": {"stringValue": s}}),
                Attr::Int(i) => json!({"key": k, "value": {"intValue": i.to_string()}}),
            })
            .collect();
        let mut span = json!({
            "traceId": hex::encode(self.trace_id),
            "spanId": hex::encode(self.span_id),
            "name": self.name,
            "kind": self.kind as u8,
            "startTimeUnixNano": self.start_ns.to_string(),
            "endTimeUnixNano": self.end_ns.to_string(),
            "attributes": attrs,
            "status": {"code": if self.error { 2 } else { 1 }},
        });
        if let Some(p) = self.parent {
            span["parentSpanId"] = json!(hex::encode(p));
        }
        span
    }
}

/// The OTLP/JSON request body for a batch of gateway spans.
pub fn otlp_body(spans: &[SpanRecord]) -> Value {
    json!({
        "resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": SERVICE_NAME}}]},
            "scopeSpans": [{
                "scope": {"name": SERVICE_NAME},
                "spans": spans.iter().map(SpanRecord::to_otlp).collect::<Vec<_>>(),
            }],
        }]
    })
}

// ── the per-request recorder ───────────────────────────────────────────

/// What a request has learned about itself by the time it ends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// The authenticated caller's subject (a username, a service-key
    /// consumer, `internal:cluster:...`).
    pub actor: Option<String>,
    /// `user` or `internal` (the bus principal's kind).
    pub actor_kind: Option<String>,
    pub model: Option<String>,
    pub backend: Option<String>,
    pub node: Option<String>,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
}

/// One request's trace while it runs.
///
/// Nothing is recorded for a request until authentication has run for it
/// ([`Recorder::authenticate`], from the auth-scoped principal layer): an
/// anonymous request, a refused one and a rate-limited one leave no row and
/// no span, so a flood the limiter answers costs no database write. The
/// caller's `traceparent` is held until then too: an unauthenticated caller
/// cannot join a trace it names.
pub struct Recorder {
    span_id: [u8; 8],
    /// This request's own trace id, used unless an authenticated caller
    /// sent a `traceparent`.
    fresh_trace: [u8; 16],
    /// The caller's `traceparent`, adopted only once it authenticated.
    incoming: Option<TraceContext>,
    authenticated: AtomicBool,
    pub method: String,
    pub route: String,
    pub start_ns: u64,
    pub request_bytes: Option<i64>,
    summary: Mutex<Summary>,
    /// Child spans closed so far (each is exported as it closes).
    children: AtomicI64,
}

impl Recorder {
    fn new(method: &Method, route: String, incoming: Option<TraceContext>, request_bytes: Option<i64>) -> Self {
        Self {
            span_id: new_span_id(),
            fresh_trace: random_bytes::<16>(),
            incoming,
            authenticated: AtomicBool::new(false),
            method: method.as_str().to_string(),
            route,
            start_ns: now_ns(),
            request_bytes,
            summary: Mutex::new(Summary::default()),
            children: AtomicI64::new(0),
        }
    }

    /// Whether authentication admitted the caller.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated.load(Ordering::Acquire)
    }

    fn adopted(&self) -> Option<TraceContext> {
        self.incoming.filter(|_| self.is_authenticated())
    }

    /// The request's trace id and its own span id: the caller's trace once
    /// an authenticated caller continued one, else this request's own.
    pub fn ctx(&self) -> TraceContext {
        let trace_id = self.adopted().map(|c| c.trace_id).unwrap_or(self.fresh_trace);
        TraceContext { trace_id, span_id: self.span_id }
    }

    /// The caller's span, when an authenticated caller sent `traceparent`.
    pub fn parent(&self) -> Option<[u8; 8]> {
        self.adopted().map(|c| c.span_id)
    }

    /// The caller authenticated as `p`: record this request, under `p`.
    fn authenticate(&self, p: &crate::bus_principal::Principal) {
        self.with_summary(|s| {
            s.actor = Some(p.sub.clone());
            s.actor_kind = Some(p.kind.as_str().to_string());
        });
        self.authenticated.store(true, Ordering::Release);
    }

    pub fn trace_id_hex(&self) -> String {
        hex::encode(self.ctx().trace_id)
    }

    fn with_summary(&self, f: impl FnOnce(&mut Summary)) {
        let mut g = match self.summary.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        f(&mut g);
    }

    pub fn summary(&self) -> Summary {
        match self.summary.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// The root span for this request, closed now.
    fn root_span(&self, status: u16, response_bytes: Option<i64>) -> SpanRecord {
        let s = self.summary();
        let mut attrs = vec![
            ("http.request.method", Attr::Str(self.method.clone())),
            ("http.route", Attr::Str(self.route.clone())),
            ("http.response.status_code", Attr::Int(status as i64)),
        ];
        let mut opt = |k: &'static str, v: &Option<String>| {
            if let Some(v) = v {
                attrs.push((k, Attr::Str(v.clone())));
            }
        };
        opt("enduser.id", &s.actor);
        opt("noo.actor_kind", &s.actor_kind);
        opt("noo.model", &s.model);
        opt("noo.backend", &s.backend);
        opt("noo.node", &s.node);
        if s.prompt_tokens > 0 || s.completion_tokens > 0 {
            attrs.push(("noo.tokens.prompt", Attr::Int(s.prompt_tokens)));
            attrs.push(("noo.tokens.completion", Attr::Int(s.completion_tokens)));
        }
        if let Some(n) = self.request_bytes {
            attrs.push(("http.request.body.size", Attr::Int(n)));
        }
        if let Some(n) = response_bytes {
            attrs.push(("http.response.body.size", Attr::Int(n)));
        }
        let ctx = self.ctx();
        SpanRecord {
            trace_id: ctx.trace_id,
            span_id: ctx.span_id,
            parent: self.parent(),
            name: format!("{} {}", self.method, self.route),
            kind: SpanKind::Server,
            start_ns: self.start_ns,
            end_ns: now_ns(),
            attrs,
            error: status >= 500,
        }
    }
}

tokio::task_local! {
    static CURRENT: Arc<Recorder>;
}

/// The request's recorder, when code runs inside a traced request.
pub fn current() -> Option<Arc<Recorder>> {
    CURRENT.try_with(|r| r.clone()).ok()
}

/// The `traceparent` naming the request in scope's own span, for a hop that
/// continues the trace without a span of its own here (a worker message).
/// Only for a recorded (authenticated) request: an unrecorded one leaves no
/// orphan worker span.
pub fn current_traceparent() -> Option<String> {
    current().filter(|r| r.is_authenticated()).map(|r| {
        let c = r.ctx();
        traceparent(&c.trace_id, &c.span_id)
    })
}

/// The trace id (hex) of the request in scope, for rows that link to it.
pub fn current_trace_id() -> Option<String> {
    current().map(|r| r.trace_id_hex())
}

/// The authenticated caller, from the bus principal the auth-scoped layer
/// builds. It is what makes the request in scope recorded at all (see
/// [`Recorder`]). Outside a traced request this does nothing.
pub fn note_principal(p: &crate::bus_principal::Principal) {
    if let Some(r) = current() {
        r.authenticate(p);
    }
}

/// A completion's model, backend, node and tokens, from the usage writer.
/// Tokens add up across completions in one request (a tool loop).
pub fn note_usage(node: Option<&str>, backend: &str, model: &str, prompt_tokens: u32, completion_tokens: u32) {
    if let Some(r) = current() {
        r.with_summary(|s| {
            s.model = Some(model.to_string());
            s.backend = Some(backend.to_string());
            if let Some(n) = node {
                s.node = Some(n.to_string());
            }
            s.prompt_tokens += prompt_tokens as i64;
            s.completion_tokens += completion_tokens as i64;
        });
    }
}

/// Run `f` with `rec` as the request in scope: for work that finishes
/// outside the request's task (a streamed answer's usage is recorded when
/// the stream ends, on whatever task drops it) but belongs to it.
pub fn with_recorder<R>(rec: Option<Arc<Recorder>>, f: impl FnOnce() -> R) -> R {
    match rec {
        Some(r) => CURRENT.sync_scope(r, f),
        None => f(),
    }
}

// ── child spans: the calls a request makes ────────────────────────────

/// One call the request made (a model backend), open until dropped. It
/// carries the `traceparent` the callee continues; when dropped it is
/// exported on its own and counted on the request.
pub struct ChildSpan {
    rec: Arc<Recorder>,
    span_id: [u8; 8],
    name: String,
    start_ns: u64,
    attrs: Vec<(&'static str, Attr)>,
    status: Option<u16>,
}

impl ChildSpan {
    /// The header value the callee continues the trace from.
    pub fn traceparent(&self) -> String {
        traceparent(&self.rec.ctx().trace_id, &self.span_id)
    }

    /// The callee's HTTP status, once it answered.
    pub fn status(&mut self, status: u16) {
        self.status = Some(status);
    }

    fn record(&self) -> SpanRecord {
        let mut attrs = self.attrs.clone();
        if let Some(s) = self.status {
            attrs.push(("http.response.status_code", Attr::Int(s as i64)));
        }
        SpanRecord {
            trace_id: self.rec.ctx().trace_id,
            span_id: self.span_id,
            parent: Some(self.rec.ctx().span_id),
            name: self.name.clone(),
            kind: SpanKind::Client,
            start_ns: self.start_ns,
            end_ns: now_ns(),
            attrs,
            error: self.status.is_some_and(|s| s >= 500),
        }
    }
}

impl Drop for ChildSpan {
    fn drop(&mut self) {
        self.rec.children.fetch_add(1, Ordering::Relaxed);
        export(vec![self.record()]);
    }
}

/// `host:port` of a URL, for `server.address`. Never the path or query.
fn server_address(url: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).ok()?;
    let host = u.host_str()?;
    Some(match u.port_or_known_default() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

/// What a backend span's end time means, so a reader never takes time to
/// first byte for the whole answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanEnd {
    /// The caller read the whole body before the span closed.
    Body,
    /// The span closed when the response headers arrived; the body was read
    /// elsewhere.
    Headers,
    /// The span closed when the streamed body did.
    Stream,
}

impl SpanEnd {
    fn as_str(self) -> &'static str {
        match self {
            SpanEnd::Body => "body",
            SpanEnd::Headers => "headers",
            SpanEnd::Stream => "stream",
        }
    }
}

/// A span for a call to a model backend, when a recorded (authenticated)
/// request is in scope: an unrecorded request leaves no orphan span.
pub fn backend_span(backend: &str, model: &str, url: &str, end: SpanEnd) -> Option<ChildSpan> {
    let rec = current().filter(|r| r.is_authenticated())?;
    let mut attrs = vec![
        ("noo.backend", Attr::Str(backend.to_string())),
        ("noo.model", Attr::Str(model.to_string())),
        ("noo.span_end", Attr::Str(end.as_str().to_string())),
    ];
    if let Some(a) = server_address(url) {
        attrs.push(("server.address", Attr::Str(a)));
    }
    Some(ChildSpan { rec, span_id: new_span_id(), name: format!("backend {backend}"), start_ns: now_ns(), attrs, status: None })
}

/// `req` with the span's `traceparent`, so the backend (or the node agent
/// fronting it) continues the trace. Unchanged without a span.
pub fn propagate(req: reqwest::RequestBuilder, span: Option<&ChildSpan>) -> reqwest::RequestBuilder {
    match span {
        Some(s) => req.header("traceparent", s.traceparent()),
        None => req,
    }
}

/// `stream`, holding `span` open until the stream is dropped: a streamed
/// backend call's span ends with its stream. The span is moved in WHOLE
/// (`let _held = &span;`), not field by field; see [`count_until_dropped`].
pub fn hold_until_dropped<S>(stream: S, span: Option<ChildSpan>) -> impl futures::Stream<Item = S::Item>
where
    S: futures::Stream,
{
    stream.map(move |item| {
        let _held = &span;
        item
    })
}

// ── the layer ──────────────────────────────────────────────────────────

/// Paths that are not traced: probes, static assets and the node log push.
pub fn untraced(method: &str, path: &str) -> bool {
    path == "/health"
        || path.starts_with("/health/")
        || path == "/metrics"
        || path.starts_with("/static/")
        || crate::middleware::access_log_suppressed(method, path)
        || is_node_span_push(method, path)
}

/// A node's span push (`POST /api/cluster/nodes/{id}/traces`): the trace
/// rail's own traffic, never itself a request worth a trace.
fn is_node_span_push(method: &str, path: &str) -> bool {
    method == "POST"
        && path
            .strip_prefix("/api/cluster/nodes/")
            .and_then(|r| r.strip_suffix("/traces"))
            .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// The route a request matched, as its template (`/api/tasks/{id}`), so a
/// summary never carries an id or a name from the URL. A path that matched
/// nothing is recorded as such, not as itself.
pub fn route_of(matched: Option<&MatchedPath>) -> String {
    matched.map(|m| m.as_str().to_string()).unwrap_or_else(|| "<unmatched>".to_string())
}

fn content_length(h: &axum::http::HeaderMap) -> Option<i64> {
    h.get(axum::http::header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

fn is_stream(h: &axum::http::HeaderMap) -> bool {
    h.get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream") || ct.starts_with("application/x-ndjson"))
}

/// The router layer. See the module docs.
pub async fn trace_layer(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    if untraced(request.method().as_str(), &path) {
        return next.run(request).await;
    }
    let incoming = request
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_traceparent);
    let rec = Arc::new(Recorder::new(
        request.method(),
        route_of(request.extensions().get::<MatchedPath>()),
        incoming,
        content_length(request.headers()),
    ));

    let mut response = CURRENT.scope(rec.clone(), next.run(request)).await;
    let status = response.status().as_u16();
    if !recorded(&rec, status) {
        // Anonymous, refused or rate-limited: nothing to record, nothing to
        // name in a header.
        return response;
    }
    let ctx = rec.ctx();
    if let Ok(v) = HeaderValue::from_str(&traceparent(&ctx.trace_id, &ctx.span_id)) {
        response.headers_mut().insert("traceparent", v);
    }

    if !is_stream(response.headers()) {
        let bytes = content_length(response.headers());
        finish(&rec, status, bytes);
        return response;
    }
    // A streamed answer: the trace ends with the stream.
    let (parts, body) = response.into_parts();
    let body = count_until_dropped(body, move |bytes| {
        finish(&rec, status, Some(bytes));
    });
    Response::from_parts(parts, body)
}

/// Whether a finished request leaves a row and spans: only an
/// authenticated one, and not when the answer is a 401 or a 429 (a refused
/// credential, the rate limiter).
pub fn recorded(rec: &Recorder, status: u16) -> bool {
    rec.is_authenticated() && !matches!(status, 401 | 429)
}

/// Runs its callback once, with the bytes counted, when dropped.
struct StreamEnd<F: FnOnce(i64)> {
    bytes: i64,
    on_end: Option<F>,
}

impl<F: FnOnce(i64)> Drop for StreamEnd<F> {
    fn drop(&mut self) {
        if let Some(f) = self.on_end.take() {
            f(self.bytes);
        }
    }
}

/// `body`, counting its bytes, calling `on_end(bytes)` once when the stream
/// is dropped: finished, cut by the client, or never read.
///
/// The guard is moved into the closure WHOLE, through `let end = &mut guard`.
/// Written as `guard.bytes += …`, edition-2021 closures capture just that
/// field: a copied i64. The guard itself then dropped when the layer
/// returned, so the trace closed at the headers with 0 bytes (caught by the
/// batch on #593).
fn count_until_dropped<F>(body: Body, on_end: F) -> Body
where
    F: FnOnce(i64) + Send + 'static,
{
    let mut guard = StreamEnd { bytes: 0, on_end: Some(on_end) };
    let stream = body.into_data_stream().map(move |chunk| {
        let end = &mut guard;
        if let Ok(c) = &chunk {
            end.bytes += c.len() as i64;
        }
        chunk
    });
    Body::from_stream(stream)
}

/// End a request's trace: its spans to the exporter, its summary row to the
/// bounded row queue. Neither may affect the response, and neither waits.
/// False (and nothing queued) for a request [`recorded`] refuses.
fn finish(rec: &Arc<Recorder>, status: u16, response_bytes: Option<i64>) -> bool {
    if !recorded(rec, status) {
        return false;
    }
    let root = rec.root_span(status, response_bytes);
    let duration_ms = (root.end_ns.saturating_sub(root.start_ns) / 1_000_000) as i64;
    // Child spans export themselves as they close; a streamed backend call
    // still running here closes with its stream and is not counted.
    let span_count = 1 + rec.children.load(Ordering::Relaxed);
    export(vec![root]);

    let row = SummaryRow {
        trace_id: rec.trace_id_hex(),
        method: rec.method.clone(),
        route: rec.route.clone(),
        status: status as i32,
        duration_ms,
        summary: rec.summary(),
        span_count,
        request_bytes: rec.request_bytes,
        response_bytes,
    };
    enqueue_row(row);
    true
}

/// Rows waiting for the writer. Full means Postgres is not keeping up: new
/// rows are dropped and counted, never queued without bound, and never one
/// task (one pool connection) per request.
const ROW_QUEUE: usize = 4_096;

/// Rows one writer pass takes from the queue before it yields.
const ROW_BATCH: usize = 64;

static ROWS: OnceLock<mpsc::Sender<SummaryRow>> = OnceLock::new();
/// Rows handed to the queue (recorded requests), for tests and the metric.
static ROWS_QUEUED: AtomicU64 = AtomicU64::new(0);
/// Rows dropped on a full queue since the writer last reported them.
static ROWS_DROPPED: AtomicU64 = AtomicU64::new(0);

fn enqueue_row(row: SummaryRow) {
    ROWS_QUEUED.fetch_add(1, Ordering::Relaxed);
    let Some(tx) = ROWS.get() else { return };
    if tx.try_send(row).is_err() {
        ROWS_DROPPED.fetch_add(1, Ordering::Relaxed);
        warn_once_a_minute("request_trace_rows_dropped", "summary rows dropped; the database is not keeping up");
    }
}

/// The one writer: rows in queue order on one connection at a time, and
/// the drops reported as `noo_request_trace_rows_dropped_total`.
async fn row_writer(state: Arc<AppState>, mut rx: mpsc::Receiver<SummaryRow>) {
    while let Some(first) = rx.recv().await {
        write_summary(&state.db, &first).await;
        for _ in 1..ROW_BATCH {
            match rx.try_recv() {
                Ok(row) => write_summary(&state.db, &row).await,
                Err(_) => break,
            }
        }
        let dropped = ROWS_DROPPED.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            state.metrics.inc_counter("noo_request_trace_rows_dropped_total", None, dropped).await;
        }
    }
}

// ── the summary row ────────────────────────────────────────────────────

/// One `noo_request_trace` row.
#[derive(Clone, Debug, PartialEq)]
pub struct SummaryRow {
    pub trace_id: String,
    pub method: String,
    pub route: String,
    pub status: i32,
    pub duration_ms: i64,
    pub summary: Summary,
    pub span_count: i64,
    pub request_bytes: Option<i64>,
    pub response_bytes: Option<i64>,
}

/// Insert one summary row (`repo::request_trace::insert`). A failure warns
/// and nothing else: tracing must never affect serving, and a gateway on a
/// pre-migration schema keeps running.
pub async fn write_summary(db: &sqlx::PgPool, row: &SummaryRow) {
    if let Err(e) = crate::repo::request_trace::insert(db, row).await {
        warn_once_a_minute("request_trace_write_failed", &e.to_string());
    }
}

async fn prune_tick(state: Arc<AppState>) -> anyhow::Result<()> {
    match crate::repo::request_trace::prune(&state.db, RETENTION_DAYS).await {
        Ok(0) => Ok(()),
        Ok(n) => {
            tracing::info!(pruned = n, retention_days = RETENTION_DAYS, "request_trace.pruned");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("request trace prune failed: {e}")),
    }
}

// ── the exporter ───────────────────────────────────────────────────────

static EXPORT: OnceLock<mpsc::Sender<SpanRecord>> = OnceLock::new();

/// Hand spans to the exporter. Never blocks: a full queue drops them.
pub fn export(spans: Vec<SpanRecord>) {
    let Some(tx) = EXPORT.get() else { return };
    for s in spans {
        if tx.try_send(s).is_err() {
            warn_once_a_minute("request_trace_export_queue_full", "spans dropped; Tempo is not keeping up or is down");
            return;
        }
    }
}

/// Rate-limited warning: one line a minute per `event`.
fn warn_once_a_minute(event: &'static str, detail: &str) {
    use std::collections::HashMap;
    static SEEN: Mutex<Option<HashMap<&'static str, u64>>> = Mutex::new(None);
    let now = now_ns() / 1_000_000_000;
    let mut g = match SEEN.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let seen = g.get_or_insert_with(HashMap::new);
    if now.saturating_sub(seen.get(event).copied().unwrap_or(0)) < 60 {
        return;
    }
    seen.insert(event, now);
    drop(g);
    tracing::warn!(detail, "{event}");
}

/// The Tempo OTLP endpoint for traces, or None when Tempo is not configured.
/// Only `https://`: spans carry account ids and routes, so a plaintext URL
/// is refused, not used.
pub fn tempo_traces_url(base: &str) -> Result<Option<String>, String> {
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        return Ok(None);
    }
    if !base.starts_with("https://") {
        return Err(format!("{TEMPO_URL_ENV}={base} is not https://; spans are exported over TLS only"));
    }
    Ok(Some(format!("{base}/v1/traces")))
}

async fn post_batch(url: &str, batch: &[SpanRecord]) {
    let res = crate::tls::cluster_client()
        .post(url)
        .timeout(Duration::from_secs(10))
        .json(&otlp_body(batch))
        .send()
        .await;
    match res {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => warn_once_a_minute("request_trace_export_refused", &format!("Tempo answered {}", r.status())),
        Err(e) => warn_once_a_minute("request_trace_export_failed", &e.to_string()),
    }
}

async fn export_loop(url: String, mut rx: mpsc::Receiver<SpanRecord>) {
    let mut batch: Vec<SpanRecord> = Vec::with_capacity(EXPORT_BATCH);
    let mut tick = tokio::time::interval(EXPORT_EVERY);
    loop {
        tokio::select! {
            got = rx.recv() => match got {
                Some(s) => {
                    batch.push(s);
                    if batch.len() >= EXPORT_BATCH {
                        post_batch(&url, &batch).await;
                        batch.clear();
                    }
                }
                None => break,
            },
            _ = tick.tick() => {
                if !batch.is_empty() {
                    post_batch(&url, &batch).await;
                    batch.clear();
                }
            }
        }
    }
}

/// Boot wiring: the row writer, the exporter (when Tempo is configured) and
/// the daily prune.
pub fn spawn(state: Arc<AppState>) {
    let (tx, rx) = mpsc::channel(ROW_QUEUE);
    if ROWS.set(tx).is_ok() {
        tokio::spawn(row_writer(state.clone(), rx));
    }
    match tempo_traces_url(&std::env::var(TEMPO_URL_ENV).unwrap_or_default()) {
        Ok(Some(url)) => {
            let (tx, rx) = mpsc::channel(EXPORT_QUEUE);
            if EXPORT.set(tx).is_ok() {
                tracing::info!(url = %url, "request_trace.exporting");
                tokio::spawn(export_loop(url, rx));
            }
        }
        Ok(None) => tracing::info!("request_trace: {TEMPO_URL_ENV} unset; summary rows only, no spans exported"),
        Err(e) => tracing::warn!("request_trace: {e}; summary rows only, no spans exported"),
    }
    crate::managed_loop::ManagedLoop::new(PRUNE_LOOP_NAME, PRUNE_INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .immediate_first_tick()
        .spawn(state, prune_tick);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wellformed_traceparent_is_continued() {
        let c = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").expect("parsed");
        assert_eq!(hex::encode(c.trace_id), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(hex::encode(c.span_id), "00f067aa0ba902b7");
    }

    #[test]
    fn a_malformed_or_zero_traceparent_starts_a_new_trace() {
        for bad in [
            "",
            "garbage",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
        ] {
            assert_eq!(parse_traceparent(bad), None, "{bad:?}");
        }
    }

    fn alice() -> crate::bus_principal::Principal {
        crate::bus_principal::Principal::user("alice", crate::auth::Role::User, vec!["read".into()])
    }

    #[test]
    fn new_ids_are_never_zero_and_round_trip_through_traceparent() {
        let rec = Recorder::new(&Method::GET, "/api/x".into(), None, None);
        let ctx = rec.ctx();
        let tp = traceparent(&ctx.trace_id, &ctx.span_id);
        assert_eq!(parse_traceparent(&tp), Some(ctx));
        assert_eq!(rec.parent(), None);
    }

    /// An unauthenticated caller's `traceparent` is ignored: it cannot join
    /// a trace it names. Once the caller authenticates, it is continued.
    #[test]
    fn a_traceparent_is_continued_only_for_an_authenticated_caller() {
        let incoming = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        let rec = Recorder::new(&Method::POST, "/v1/chat/completions".into(), incoming, Some(10));
        assert_ne!(hex::encode(rec.ctx().trace_id), "4bf92f3577b34da6a3ce929d0e0e4736", "joined before authentication");
        assert_eq!(rec.parent(), None);
        rec.authenticate(&alice());
        assert_eq!(hex::encode(rec.ctx().trace_id), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(rec.parent().map(hex::encode).as_deref(), Some("00f067aa0ba902b7"));
        assert_ne!(rec.ctx().span_id, incoming.expect("parsed").span_id, "the gateway's span is its own");
    }

    /// An anonymous flood costs no database write: a request no principal
    /// was noted for queues no row (and exports no span), whatever its
    /// status. Neither do an authenticated 401 or 429. A recorded one does.
    #[test]
    fn an_anonymous_flood_queues_no_row() {
        let before = ROWS_QUEUED.load(Ordering::Relaxed);
        for status in [200u16, 401, 403, 429, 500] {
            for _ in 0..200 {
                let rec = Arc::new(Recorder::new(&Method::POST, "/v1/chat/completions".into(), None, None));
                assert!(!finish(&rec, status, Some(1)), "an anonymous {status} was recorded");
            }
        }
        for status in [401u16, 429] {
            let rec = Arc::new(Recorder::new(&Method::POST, "/v1/chat/completions".into(), None, None));
            rec.authenticate(&alice());
            assert!(!finish(&rec, status, None), "an authenticated {status} was recorded");
        }
        assert_eq!(ROWS_QUEUED.load(Ordering::Relaxed), before, "rows were queued for requests that record nothing");
        let rec = Arc::new(Recorder::new(&Method::POST, "/v1/chat/completions".into(), None, None));
        rec.authenticate(&alice());
        assert!(finish(&rec, 200, Some(1)));
        assert_eq!(ROWS_QUEUED.load(Ordering::Relaxed), before + 1);
    }

    #[test]
    fn the_otlp_json_uses_hex_ids_and_string_numbers() {
        let rec = Recorder::new(&Method::POST, "/v1/chat/completions".into(), None, Some(42));
        rec.with_summary(|s| {
            s.actor = Some("alice".into());
            s.actor_kind = Some("user".into());
            s.model = Some("gemma".into());
            s.prompt_tokens = 7;
            s.completion_tokens = 3;
        });
        let span = rec.root_span(502, Some(9));
        let body = otlp_body(&[span]);
        let s = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(s["traceId"], json!(rec.trace_id_hex()));
        assert_eq!(s["spanId"].as_str().map(str::len), Some(16));
        assert!(s.get("parentSpanId").is_none(), "a new trace's root has no parent");
        assert_eq!(s["kind"], json!(2));
        assert_eq!(s["name"], json!("POST /v1/chat/completions"));
        assert_eq!(s["status"]["code"], json!(2), "a 5xx is an error span");
        assert!(s["startTimeUnixNano"].is_string() && s["endTimeUnixNano"].is_string());
        let attrs = s["attributes"].as_array().expect("attributes");
        let get = |k: &str| attrs.iter().find(|a| a["key"] == json!(k)).map(|a| a["value"].clone());
        assert_eq!(get("http.route"), Some(json!({"stringValue": "/v1/chat/completions"})));
        assert_eq!(get("http.response.status_code"), Some(json!({"intValue": "502"})));
        assert_eq!(get("enduser.id"), Some(json!({"stringValue": "alice"})));
        assert_eq!(get("noo.tokens.prompt"), Some(json!({"intValue": "7"})));
        assert_eq!(get("http.request.body.size"), Some(json!({"intValue": "42"})));
        assert_eq!(get("http.response.body.size"), Some(json!({"intValue": "9"})));
        assert_eq!(body["resourceSpans"][0]["resource"]["attributes"][0]["value"]["stringValue"], json!(SERVICE_NAME));
    }

    #[test]
    fn spans_go_to_tempo_over_tls_only() {
        assert_eq!(tempo_traces_url(""), Ok(None));
        assert_eq!(tempo_traces_url(" https://tempo:4318/ "), Ok(Some("https://tempo:4318/v1/traces".into())));
        for plain in ["http://tempo:4318", "HTTP://tempo:4318", "tempo:4318"] {
            let e = tempo_traces_url(plain).expect_err(plain);
            assert!(e.contains(TEMPO_URL_ENV) && e.contains("TLS only"), "{e}");
        }
    }

    #[test]
    fn probes_assets_and_the_log_push_are_not_traced() {
        for (m, p) in [
            ("GET", "/health"),
            ("GET", "/metrics"),
            ("GET", "/static/app.js"),
            ("POST", "/api/cluster/nodes/node-a/logs"),
            ("POST", "/api/cluster/nodes/node-a/traces"),
        ] {
            assert!(untraced(m, p), "{m} {p}");
        }
        for (m, p) in [("POST", "/v1/chat/completions"), ("GET", "/api/cluster/nodes/node-a/logs"), ("GET", "/healthz")] {
            assert!(!untraced(m, p), "{m} {p}");
        }
    }

    #[test]
    fn an_unmatched_path_is_not_recorded_as_itself() {
        assert_eq!(route_of(None), "<unmatched>");
    }

    #[tokio::test]
    async fn notes_land_on_the_request_in_scope_and_nowhere_else() {
        note_usage(Some("node-a"), "vllm", "m", 5, 5); // no request in scope: nothing to note on
        let rec = Arc::new(Recorder::new(&Method::POST, "/api/x".into(), None, None));
        CURRENT
            .scope(rec.clone(), async {
                note_usage(Some("node-a"), "vllm", "gemma", 10, 4);
                note_usage(None, "vllm", "gemma", 1, 1);
                note_principal(&crate::bus_principal::Principal::user(
                    "alice",
                    crate::auth::Role::User,
                    vec!["read".into()],
                ));
                assert_eq!(current_trace_id(), Some(rec.trace_id_hex()));
                let tp = parse_traceparent(&current_traceparent().expect("in scope")).expect("valid");
                assert_eq!((tp.trace_id, tp.span_id), (rec.ctx().trace_id, rec.ctx().span_id), "a worker hop parents on the request's span");
            })
            .await;
        let s = rec.summary();
        assert_eq!((s.prompt_tokens, s.completion_tokens), (11, 5), "a tool loop's completions add up");
        assert_eq!(s.node.as_deref(), Some("node-a"), "a later completion with no node keeps the first one's");
        assert_eq!(s.actor.as_deref(), Some("alice"));
        assert_eq!(s.actor_kind.as_deref(), Some("user"));
        assert_eq!(current_trace_id(), None);
    }

    /// A streamed body's trace ends when the STREAM does, with its bytes: not
    /// when the layer returns, and not with 0. Fails on the field-capture
    /// version (the callback ran before a byte was read, with 0).
    #[tokio::test]
    async fn a_streamed_body_ends_its_trace_with_its_bytes_when_it_is_done() {
        let seen: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> =
            vec![Ok("data: one\n\n".into()), Ok("data: two\n\n".into())];
        let body = count_until_dropped(Body::from_stream(futures::stream::iter(chunks)), move |b| {
            s.lock().expect("lock").push(b);
        });
        assert!(seen.lock().expect("lock").is_empty(), "the trace ended before the stream was read");
        let got = axum::body::to_bytes(body, usize::MAX).await.expect("the body reads");
        assert_eq!(got.len(), 22);
        assert_eq!(*seen.lock().expect("lock"), vec![22], "ended once, with every byte counted");
    }

    /// A client that goes away mid-stream still ends the trace, once.
    #[tokio::test]
    async fn a_dropped_stream_ends_its_trace_once() {
        let seen: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let body = count_until_dropped(Body::from("abc"), move |b| s.lock().expect("lock").push(b));
        drop(body);
        assert_eq!(*seen.lock().expect("lock"), vec![0]);
    }

    /// A streamed answer's usage is recorded when its stream ends, off the
    /// request's task. Its tokens still reach that request's trace, and
    /// before the trace closes: the tap carries the recorder, and it drops
    /// before the trace's stream guard (the inner stream before the map).
    #[tokio::test]
    async fn a_streamed_answers_tokens_reach_its_trace_before_it_closes() {
        let rec = Arc::new(Recorder::new(&Method::POST, "/api/inference/stream".into(), None, None));
        let seen: Arc<Mutex<Option<Summary>>> = Arc::new(Mutex::new(None));
        let (r, s) = (rec.clone(), seen.clone());
        let body = CURRENT
            .scope(rec.clone(), async move {
                let frames: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
                    Ok("data: {\"choices\":[]}\n\n".into()),
                    Ok("data: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\n\n".into()),
                ];
                let ctx = crate::usage::StreamUsageCtx {
                    db: sqlx::postgres::PgPoolOptions::new()
                        .acquire_timeout(Duration::from_millis(300))
                        .connect_lazy("postgres://nobody@127.0.0.1:1/nothing")
                        .expect("lazy pool"),
                    node_id: None,
                    backend: "vllm".into(),
                    model: "gemma".into(),
                    source: "api",
                    actor: crate::usage::UsageActor::unknown(),
                };
                let tapped = crate::usage::tap_stream(futures::stream::iter(frames), ctx);
                count_until_dropped(Body::from_stream(tapped), move |_| {
                    *s.lock().expect("lock") = Some(r.summary());
                })
            })
            .await;
        // Read outside the request's scope, as the server does.
        axum::body::to_bytes(body, usize::MAX).await.expect("the body reads");
        let got = seen.lock().expect("lock").clone().expect("the trace closed");
        assert_eq!((got.prompt_tokens, got.completion_tokens), (7, 3), "{got:?}");
        assert_eq!(got.model.as_deref(), Some("gemma"));
    }

    /// A backend call's span: the callee continues the request's trace from
    /// the span's own id, and closing it counts it on the request.
    #[tokio::test]
    async fn a_backend_span_continues_the_trace_and_is_counted() {
        assert!(backend_span("vllm", "m", "https://n:8081/v1/chat/completions", SpanEnd::Body).is_none(), "no request, no span");
        let rec = Arc::new(Recorder::new(&Method::POST, "/v1/chat/completions".into(), None, None));
        CURRENT
            .scope(rec.clone(), async {
                assert!(
                    backend_span("vllm", "gemma", "https://node-a:8081/v1/chat/completions", SpanEnd::Body).is_none(),
                    "an unauthenticated request makes no backend span"
                );
                rec.authenticate(&alice());
                let mut span =
                    backend_span("vllm", "gemma", "https://node-a:8081/v1/chat/completions?x=1", SpanEnd::Headers).expect("a span");
                let tp = parse_traceparent(&span.traceparent()).expect("a valid traceparent");
                assert_eq!(tp.trace_id, rec.ctx().trace_id, "the same trace");
                assert_ne!(tp.span_id, rec.ctx().span_id, "its own span");
                span.status(502);
                let r = span.record();
                assert_eq!(r.parent, Some(rec.ctx().span_id));
                assert_eq!(r.kind, SpanKind::Client);
                assert!(r.error);
                let addr = r.attrs.iter().find(|(k, _)| *k == "server.address").map(|(_, v)| v.clone());
                assert_eq!(addr, Some(Attr::Str("node-a:8081".into())), "host and port, never the path or query");
                let end = r.attrs.iter().find(|(k, _)| *k == "noo.span_end").map(|(_, v)| v.clone());
                assert_eq!(end, Some(Attr::Str("headers".into())));
            })
            .await;
        assert_eq!(rec.children.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn retention_is_the_operators_thirty_days() {
        assert_eq!(RETENTION_DAYS, 30);
    }
}
