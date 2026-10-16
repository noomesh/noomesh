// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The loopback wire translator (i83 phase E1b).
//!
//! A harness of a foreign kind (`copilot`, `claude-code`) runs the vendor's
//! CLI headless against the node's own model. The CLIs want OpenAI chat
//! (Copilot) or Anthropic Messages (Claude Code); the node's backends speak
//! OpenAI chat (vLLM, llama.cpp under `--jinja`, the node agent's proxy) or
//! Ollama's `/api/chat`. One [`Translator`] per task or turn binds an
//! ephemeral port on `127.0.0.1`, the CLI's base-URL variable is pointed at
//! [`Translator::base_url`], and every model call the CLI makes passes
//! through here on its way to the pinned endpoint:
//!
//! | route | in | to the backend |
//! |---|---|---|
//! | `POST /v1/chat/completions` | OpenAI chat | as-is (OpenAI wire), or `/api/chat` and back (Ollama) |
//! | `POST /v1/messages` | Anthropic Messages | converted to OpenAI chat, the reply converted back |
//! | `GET /v1/models` | | nothing: the pinned model, as the one entry |
//!
//! Anything else is a 404 with a JSON error body. Streaming and
//! non-streaming both work on both routes. A `model` the CLI names is
//! replaced with the pinned model (logged once): the harness is placed
//! beside ONE model, and a CLI's default model name means nothing here.
//!
//! **Metering.** Every reply's usage is added to [`UsageTotals`] — OpenAI's
//! `usage`, Ollama's `prompt_eval_count`/`eval_count`, and for a stream
//! the final usage chunk (asked for with `stream_options.include_usage`
//! from an OpenAI-wire backend, and stripped again when the CLI did not ask
//! for it) or Ollama's closing `done` object. A reply with no usage still
//! counts as a call, and is logged once. The driver reports the totals to
//! the gateway with the `usage` rail op (`RemoteRuntime::report_usage`).
//!
//! **No auth on the loopback side, deliberately.** The listener is plain
//! HTTP on `127.0.0.1`, on a port the kernel picked, for the life of one
//! task. Whatever can reach it already runs on this box as a local user —
//! the harness runs the CLI as its own uid, and that uid can read the
//! node-agent bearer the translator would be protecting. The translator
//! adds no reach: it forwards only to the one pinned endpoint, holds no
//! credential of its own, and dies with the task. The upstream side is the
//! harness's own: `tls::cluster_client()` (the cluster CA) and the node
//! agent's bearer and backend hint through
//! `coordinator::with_backend_hint_url`, exactly as the loop sends.
//!
//! Not served: the Responses API (Codex, a later phase), and llama.cpp's
//! legacy `/completion` prompt path (a llama-server without `--jinja`
//! cannot take a CLI's tool calls, so there is nothing to fall back to).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::coordinator::anthropic_wire::{self, OpenAiToAnthropicSse};
use crate::coordinator::ResolvedBackend;

/// A CLI's request can carry a whole repository's worth of context.
const MAX_BODY: usize = 64 << 20;

/// Everything counted so far, across every call the CLI made.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsageTotals {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// Upstream calls that answered, with or without usage.
    pub calls: u32,
    /// The models the replies named, distinct, in first-seen order.
    pub models: Vec<String>,
}

/// The backend's wire, as far as the translator is concerned.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Wire {
    OpenAi,
    Ollama,
}

struct Shared {
    upstream: ResolvedBackend,
    wire: Wire,
    client: reqwest::Client,
    usage: Mutex<UsageTotals>,
    logged_rewrite: AtomicBool,
    logged_no_usage: AtomicBool,
}

impl Shared {
    /// Count one answered call. `usage` is (prompt, completion, total).
    fn meter(&self, model: Option<&str>, usage: Option<(u64, u64, u64)>) {
        let model = model.filter(|m| !m.is_empty()).unwrap_or(&self.upstream.model).to_string();
        let mut u = self.usage.lock().unwrap_or_else(|p| p.into_inner());
        u.calls = u.calls.saturating_add(1);
        match usage {
            Some((p, c, t)) => {
                u.prompt_tokens += p;
                u.completion_tokens += c;
                u.total_tokens += if t == 0 { p + c } else { t };
            }
            None => {
                if !self.logged_no_usage.swap(true, Ordering::Relaxed) {
                    tracing::warn!(endpoint = %self.upstream.url, model = %model, "translator: a reply carried no usage; the call is counted, its tokens are not");
                }
            }
        }
        if !u.models.contains(&model) {
            u.models.push(model);
        }
    }

    /// The pinned model replaces whatever the CLI named.
    fn pin_model(&self, body: &mut Value) {
        let asked = body.get("model").and_then(|m| m.as_str()).unwrap_or("").to_string();
        if asked != self.upstream.model {
            if !asked.is_empty() && !self.logged_rewrite.swap(true, Ordering::Relaxed) {
                tracing::info!(asked = %asked, pinned = %self.upstream.model, "translator: the CLI named another model; using the pinned one");
            }
            body["model"] = json!(self.upstream.model);
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.upstream.url.trim_end_matches('/'))
    }
}

/// One loopback translator. Bind with [`start`](Self::start), hand
/// [`base_url`](Self::base_url) to the CLI, read [`usage`](Self::usage),
/// and [`shutdown`](Self::shutdown) when the task ends. Dropping it stops
/// the server too.
pub struct Translator {
    base_url: String,
    shared: Arc<Shared>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Translator {
    /// Bind 127.0.0.1:0 (one translator PER TASK/TURN, ephemeral port) and serve until shutdown.
    pub async fn start(upstream: ResolvedBackend) -> Result<Translator> {
        let wire = match upstream.api_format.as_str() {
            "ollama" => Wire::Ollama,
            // A node backend is never Anthropic: cloud models run on the
            // controller, not beside a harness.
            "anthropic" => bail!("translator: {} is an Anthropic endpoint; a node harness is pinned to a node backend", upstream.url),
            _ => Wire::OpenAi,
        };
        let shared = Arc::new(Shared {
            upstream,
            wire,
            client: crate::tls::cluster_client(),
            usage: Mutex::new(UsageTotals::default()),
            logged_rewrite: AtomicBool::new(false),
            logged_no_usage: AtomicBool::new(false),
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let app = router(shared.clone());
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let served = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await;
            if let Err(e) = served {
                tracing::warn!(error = %e, "translator: server ended with an error");
            }
        });
        let base_url = format!("http://{addr}");
        tracing::info!(base_url = %base_url, endpoint = %shared.upstream.url, model = %shared.upstream.model, wire = ?wire, "translator: listening");
        Ok(Translator { base_url, shared, stop: Some(stop), task: Some(task) })
    }

    /// e.g. "http://127.0.0.1:41234" — what the CLI's base-URL env gets.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Snapshot of everything counted so far.
    pub fn usage(&self) -> UsageTotals {
        self.shared.usage.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Stop accepting, let in-flight replies finish for up to five seconds,
    /// then stop.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut task) = self.task.take() {
            if tokio::time::timeout(Duration::from_secs(5), &mut task).await.is_err() {
                task.abort();
            }
        }
    }
}

impl Drop for Translator {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/messages", post(messages))
        .route("/v1/models", get(models))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared)
}

// ── replies ─────────────────────────────────────────────────────────────

/// The 404 body: Anthropic's error shape, which also carries OpenAI's
/// `error.message` and `error.type`, so either kind of client reads it.
async fn not_found(method: Method, uri: Uri) -> Response {
    error_reply(StatusCode::NOT_FOUND, "not_found_error", &format!("no route {method} {} on the noomesh wire translator", uri.path()))
}

fn error_reply(status: StatusCode, kind: &str, message: &str) -> Response {
    (status, Json(json!({"type": "error", "error": {"type": kind, "message": message}}))).into_response()
}

/// An upstream failure as the caller's wire shows it (same body either way).
fn upstream_error(status: u16, message: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let kind = if status.is_client_error() { "invalid_request_error" } else { "api_error" };
    error_reply(status, kind, message)
}

fn sse_response(body: Body) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn parse_body(bytes: &Bytes) -> Result<Value, Response> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| error_reply(StatusCode::BAD_REQUEST, "invalid_request_error", "the body is not a JSON object"))
}

async fn models(State(sh): State<Arc<Shared>>) -> Json<Value> {
    // One entry, shaped for both families: OpenAI reads `id`/`object`,
    // Anthropic reads `id`/`type`/`display_name`.
    let m = &sh.upstream.model;
    Json(json!({
        "object": "list",
        "data": [{
            "id": m,
            "object": "model",
            "type": "model",
            "display_name": m,
            "created": 0,
            "created_at": "1970-01-01T00:00:00Z",
            "owned_by": "noomesh",
        }],
        "has_more": false,
        "first_id": m,
        "last_id": m,
    }))
}

// ── the one upstream call ───────────────────────────────────────────────

/// What came back, already in OpenAI's shape whatever the backend spoke.
enum Reply {
    /// A whole chat-completion response.
    Whole(Value),
    /// Chat-completion chunks; an `Err` is the stream failing midway.
    Chunks(mpsc::Receiver<Result<Value, String>>),
}

/// Send an OpenAI chat body to the pinned endpoint on its own wire, meter
/// the reply, and hand it back in OpenAI's shape.
async fn complete(sh: &Arc<Shared>, mut body: Value) -> Result<Reply, (u16, String)> {
    sh.pin_model(&mut body);
    let stream = body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let (url, wire_body) = match sh.wire {
        Wire::OpenAi => {
            if stream {
                // Ask for the usage chunk; the chat route strips it again
                // when the CLI did not ask.
                if !body.get("stream_options").is_some_and(Value::is_object) {
                    body["stream_options"] = json!({});
                }
                body["stream_options"]["include_usage"] = json!(true);
            }
            (sh.url("/v1/chat/completions"), body)
        }
        Wire::Ollama => (sh.url("/api/chat"), ollama::request(&body)),
    };
    let req = crate::coordinator::with_backend_hint_url(sh.client.post(&url).json(&wire_body), &sh.upstream.url, &sh.upstream.backend_type);
    let resp = req.send().await.map_err(|e| (502, format!("the model endpoint did not answer: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        crate::coordinator::warn_if_node_agent_outdated(status, &url);
        let text = resp.text().await.unwrap_or_default();
        let text: String = text.chars().take(2000).collect();
        return Err((status.as_u16(), format!("the model endpoint answered {}: {text}", status.as_u16())));
    }
    if !stream {
        let v: Value = resp.json().await.map_err(|e| (502, format!("the model endpoint's reply is not JSON: {e}")))?;
        let v = match sh.wire {
            Wire::OpenAi => v,
            Wire::Ollama => ollama::response(&v, &sh.upstream.model),
        };
        let usage = v.get("usage").filter(|u| u.is_object()).map(anthropic_wire::usage_tokens);
        sh.meter(v.get("model").and_then(|m| m.as_str()), usage);
        return Ok(Reply::Whole(v));
    }
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(pump(sh.clone(), resp, tx));
    Ok(Reply::Chunks(rx))
}

/// Read a streamed reply line by line, turn each line into OpenAI chunks,
/// forward them, and meter the call when the stream ends. A CLI that hangs
/// up stops the read (and with it, the generation).
async fn pump(sh: Arc<Shared>, resp: reqwest::Response, tx: mpsc::Sender<Result<Value, String>>) {
    let mut bytes = resp.bytes_stream();
    let mut carry = String::new();
    let mut usage: Option<(u64, u64, u64)> = None;
    let mut model: Option<String> = None;
    let mut ol = ollama::Chunker::new(&sh.upstream.model);
    let mut done = false;
    // `line` -> chunks; false once the stream is over or the CLI is gone.
    let mut handle_line = |line: &str, out: &mut Vec<Value>| -> bool {
        let line = line.trim();
        match sh.wire {
            Wire::OpenAi => {
                let Some(payload) = line.strip_prefix("data:").map(str::trim) else { return true };
                if payload == "[DONE]" {
                    return false;
                }
                if let Ok(v) = serde_json::from_str::<Value>(payload) {
                    out.push(v);
                }
                true
            }
            Wire::Ollama => {
                if line.is_empty() {
                    return true;
                }
                match serde_json::from_str::<Value>(line) {
                    Ok(v) => {
                        let fin = v.get("done").and_then(|d| d.as_bool()) == Some(true);
                        out.extend(ol.chunks(&v));
                        !fin
                    }
                    Err(_) => true,
                }
            }
        }
    };
    'read: while let Some(item) = bytes.next().await {
        let chunk = match item {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.send(Err(format!("the model endpoint's stream broke: {e}"))).await;
                break;
            }
        };
        carry.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(nl) = carry.find('\n') {
            let line: String = carry.drain(..=nl).collect();
            let mut out = Vec::new();
            let more = handle_line(&line, &mut out);
            for v in out {
                if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
                    usage = Some(anthropic_wire::usage_tokens(u));
                }
                if model.is_none() {
                    model = v.get("model").and_then(|m| m.as_str()).map(str::to_string);
                }
                if tx.send(Ok(v)).await.is_err() {
                    break 'read;
                }
            }
            if !more {
                done = true;
                break 'read;
            }
        }
    }
    if !done && !carry.trim().is_empty() {
        // The last line often has no newline.
        let mut out = Vec::new();
        handle_line(&carry, &mut out);
        for v in out {
            if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
                usage = Some(anthropic_wire::usage_tokens(u));
            }
            let _ = tx.send(Ok(v)).await;
        }
    }
    sh.meter(model.as_deref(), usage);
}

// ── the routes ──────────────────────────────────────────────────────────

/// `POST /v1/chat/completions`: OpenAI chat in, OpenAI chat out.
async fn chat_completions(State(sh): State<Arc<Shared>>, bytes: Bytes) -> Response {
    let body = match parse_body(&bytes) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let wants_usage = body.pointer("/stream_options/include_usage").and_then(|v| v.as_bool()) == Some(true);
    match complete(&sh, body).await {
        Err((status, msg)) => upstream_error(status, &msg),
        Ok(Reply::Whole(v)) => Json(v).into_response(),
        Ok(Reply::Chunks(rx)) => {
            let events = futures::stream::unfold(Some(rx), move |rx| async move {
                let mut rx = rx?;
                loop {
                    match rx.recv().await {
                        Some(Ok(v)) => {
                            // The usage chunk was our request, not the CLI's.
                            let usage_only = v.get("choices").and_then(|c| c.as_array()).is_some_and(|c| c.is_empty());
                            if usage_only && !wants_usage {
                                continue;
                            }
                            return Some((Ok::<_, std::convert::Infallible>(Bytes::from(format!("data: {v}\n\n"))), Some(rx)));
                        }
                        Some(Err(e)) => {
                            let err = json!({"error": {"type": "api_error", "message": e}});
                            return Some((Ok(Bytes::from(format!("data: {err}\n\n"))), None));
                        }
                        None => return Some((Ok(Bytes::from_static(b"data: [DONE]\n\n")), None)),
                    }
                }
            });
            sse_response(Body::from_stream(events))
        }
    }
}

/// `POST /v1/messages`: Anthropic Messages in, OpenAI chat to the
/// backend, Anthropic Messages out.
async fn messages(State(sh): State<Arc<Shared>>, bytes: Bytes) -> Response {
    let body = match parse_body(&bytes) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let openai = anthropic_wire::request_body_from_anthropic(&body);
    let model = sh.upstream.model.clone();
    match complete(&sh, openai).await {
        Err((status, msg)) => upstream_error(status, &msg),
        Ok(Reply::Whole(v)) => {
            let choice = v.pointer("/choices/0").cloned().unwrap_or_else(|| json!({}));
            let msg = choice.get("message").cloned().unwrap_or_else(|| json!({"role": "assistant", "content": ""}));
            let (p, c, _) = v.get("usage").map(anthropic_wire::usage_tokens).unwrap_or((0, 0, 0));
            let fr = choice.get("finish_reason").and_then(|f| f.as_str());
            Json(anthropic_wire::response_to_anthropic(&msg, fr, (p, c), &model)).into_response()
        }
        Ok(Reply::Chunks(rx)) => {
            fn frame(events: Vec<(String, Value)>) -> Bytes {
                let mut s = String::new();
                for (name, data) in events {
                    s.push_str(&format!("event: {name}\ndata: {data}\n\n"));
                }
                Bytes::from(s)
            }
            let t = OpenAiToAnthropicSse::new(&model);
            let events = futures::stream::unfold(Some((rx, t)), |state| async move {
                let (mut rx, mut t) = state?;
                loop {
                    match rx.recv().await {
                        Some(Ok(v)) => {
                            let ev = t.on_chunk(&v);
                            if ev.is_empty() {
                                continue;
                            }
                            return Some((Ok::<_, std::convert::Infallible>(frame(ev)), Some((rx, t))));
                        }
                        Some(Err(e)) => {
                            let err = json!({"type": "error", "error": {"type": "api_error", "message": e}});
                            return Some((Ok(frame(vec![("error".into(), err)])), None));
                        }
                        None => return Some((Ok(frame(t.finish())), None)),
                    }
                }
            });
            sse_response(Body::from_stream(events))
        }
    }
}

// ── Ollama's /api/chat ──────────────────────────────────────────────────

mod ollama {
    use serde_json::{json, Value};

    fn text_of(content: Option<&Value>) -> String {
        match content {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(parts)) => parts.iter().filter_map(|p| p.get("text").and_then(|t| t.as_str())).collect::<Vec<_>>().join(""),
            _ => String::new(),
        }
    }

    /// An OpenAI chat body -> an Ollama `/api/chat` body. Ollama takes
    /// OpenAI's message and tool shapes except that a tool call's
    /// `arguments` is an object, not a string, and sampling options live
    /// under `options`.
    pub(super) fn request(body: &Value) -> Value {
        let messages: Vec<Value> = body
            .get("messages")
            .and_then(|m| m.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .map(|m| {
                let mut out = json!({
                    "role": m.get("role").cloned().unwrap_or_else(|| json!("user")),
                    "content": text_of(m.get("content")),
                });
                if let Some(calls) = m.get("tool_calls").and_then(|t| t.as_array()) {
                    out["tool_calls"] = Value::Array(
                        calls
                            .iter()
                            .map(|tc| {
                                let f = tc.get("function").unwrap_or(tc);
                                let args = match f.get("arguments") {
                                    Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok().filter(Value::is_object).unwrap_or_else(|| json!({})),
                                    Some(v @ Value::Object(_)) => v.clone(),
                                    _ => json!({}),
                                };
                                json!({"function": {"name": f.get("name").cloned().unwrap_or(Value::Null), "arguments": args}})
                            })
                            .collect(),
                    );
                }
                if let Some(id) = m.get("tool_call_id") {
                    out["tool_call_id"] = id.clone();
                }
                if let Some(name) = m.get("name") {
                    out["tool_name"] = name.clone();
                }
                out
            })
            .collect();
        let mut out = json!({
            "model": body.get("model").cloned().unwrap_or(Value::Null),
            "messages": messages,
            "stream": body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false),
        });
        if let Some(tools) = body.get("tools").and_then(|t| t.as_array()).filter(|t| !t.is_empty()) {
            out["tools"] = Value::Array(tools.clone());
        }
        let mut options = serde_json::Map::new();
        for (from, to) in [("max_tokens", "num_predict"), ("max_completion_tokens", "num_predict"), ("temperature", "temperature"), ("top_p", "top_p"), ("stop", "stop"), ("seed", "seed")] {
            if let Some(v) = body.get(from).filter(|v| !v.is_null()) {
                options.insert(to.into(), v.clone());
            }
        }
        if !options.is_empty() {
            out["options"] = Value::Object(options);
        }
        out
    }

    fn openai_tool_calls(calls: &[Value], first_index: usize) -> Vec<Value> {
        calls
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let f = tc.get("function").unwrap_or(tc);
                let args = match f.get("arguments") {
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                    None => "{}".into(),
                };
                let id = tc.get("id").and_then(|i| i.as_str()).filter(|i| !i.is_empty()).map(str::to_string).unwrap_or_else(|| format!("call_{}", first_index + i));
                json!({
                    "index": first_index + i,
                    "id": id,
                    "type": "function",
                    "function": {"name": f.get("name").and_then(|n| n.as_str()).unwrap_or(""), "arguments": args},
                })
            })
            .collect()
    }

    fn usage(v: &Value) -> Option<Value> {
        let p = v.get("prompt_eval_count").and_then(|n| n.as_u64());
        let c = v.get("eval_count").and_then(|n| n.as_u64());
        if p.is_none() && c.is_none() {
            return None;
        }
        let (p, c) = (p.unwrap_or(0), c.unwrap_or(0));
        Some(json!({"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}))
    }

    fn finish(v: &Value, had_tools: bool) -> &'static str {
        if had_tools {
            "tool_calls"
        } else if v.get("done_reason").and_then(|d| d.as_str()) == Some("length") {
            "length"
        } else {
            "stop"
        }
    }

    /// A whole `/api/chat` reply -> an OpenAI chat-completion response.
    pub(super) fn response(v: &Value, model: &str) -> Value {
        let m = v.get("message").cloned().unwrap_or_else(|| json!({}));
        let calls = m.get("tool_calls").and_then(|t| t.as_array()).cloned().unwrap_or_default();
        let mut message = json!({"role": "assistant", "content": text_of(m.get("content"))});
        if !calls.is_empty() {
            let mut tc = openai_tool_calls(&calls, 0);
            for c in tc.iter_mut() {
                if let Some(o) = c.as_object_mut() {
                    o.remove("index");
                }
            }
            message["tool_calls"] = Value::Array(tc);
        }
        let mut out = json!({
            "id": format!("chatcmpl-{}", uuid::Uuid::new_v4().simple()),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": v.get("model").and_then(|m| m.as_str()).unwrap_or(model),
            "choices": [{"index": 0, "message": message, "finish_reason": finish(v, !calls.is_empty())}],
        });
        if let Some(u) = usage(v) {
            out["usage"] = u;
        }
        out
    }

    /// Streamed `/api/chat` lines -> OpenAI chunks.
    pub(super) struct Chunker {
        id: String,
        model: String,
        created: i64,
        tools: usize,
    }

    impl Chunker {
        pub(super) fn new(model: &str) -> Self {
            Self { id: format!("chatcmpl-{}", uuid::Uuid::new_v4().simple()), model: model.to_string(), created: chrono::Utc::now().timestamp(), tools: 0 }
        }

        fn chunk(&self, choices: Value) -> Value {
            json!({"id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model, "choices": choices})
        }

        /// One NDJSON object -> zero or more chunks. The closing `done`
        /// object becomes a finish chunk and a usage chunk.
        pub(super) fn chunks(&mut self, v: &Value) -> Vec<Value> {
            let mut out = Vec::new();
            let m = v.get("message").cloned().unwrap_or_else(|| json!({}));
            let text = text_of(m.get("content"));
            if !text.is_empty() {
                out.push(self.chunk(json!([{"index": 0, "delta": {"content": text}, "finish_reason": null}])));
            }
            if let Some(calls) = m.get("tool_calls").and_then(|t| t.as_array()).filter(|c| !c.is_empty()) {
                let tc = openai_tool_calls(calls, self.tools);
                self.tools += calls.len();
                out.push(self.chunk(json!([{"index": 0, "delta": {"tool_calls": tc}, "finish_reason": null}])));
            }
            if v.get("done").and_then(|d| d.as_bool()) == Some(true) {
                out.push(self.chunk(json!([{"index": 0, "delta": {}, "finish_reason": finish(v, self.tools > 0)}])));
                if let Some(u) = usage(v) {
                    let mut c = self.chunk(json!([]));
                    c["usage"] = u;
                    out.push(c);
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny model endpoint on 127.0.0.1:0 that speaks OpenAI chat and
    /// Ollama's /api/chat, and keeps every body it received.
    struct Mock {
        url: String,
        seen: Arc<Mutex<Vec<Value>>>,
    }

    impl Mock {
        fn last(&self) -> Value {
            self.seen.lock().unwrap().last().cloned().expect("the mock saw a request")
        }
    }

    /// The mock calls a tool when it is offered tools and the last message
    /// is not already a tool result.
    fn wants_tool(body: &Value) -> bool {
        let has_tools = body.get("tools").and_then(|t| t.as_array()).is_some_and(|t| !t.is_empty());
        let last_role = body["messages"].as_array().and_then(|m| m.last()).and_then(|m| m.get("role")).and_then(|r| r.as_str()).unwrap_or("");
        has_tools && last_role != "tool"
    }

    async fn mock_openai(State(seen): State<Arc<Mutex<Vec<Value>>>>, Json(body): Json<Value>) -> Response {
        seen.lock().unwrap().push(body.clone());
        let model = body["model"].as_str().unwrap_or("").to_string();
        let tool = wants_tool(&body);
        if body["stream"].as_bool() == Some(true) {
            let mut s = String::new();
            let mut push = |v: Value| s.push_str(&format!("data: {v}\n\n"));
            push(json!({"model": model, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}], "usage": null}));
            if tool {
                push(json!({"model": model, "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_s", "type": "function", "function": {"name": "read_file", "arguments": ""}}]}}]}));
                push(json!({"model": model, "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"path\":\"a.txt\"}"}}]}}]}));
                push(json!({"model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}));
            } else {
                push(json!({"model": model, "choices": [{"index": 0, "delta": {"content": "Hel"}}]}));
                push(json!({"model": model, "choices": [{"index": 0, "delta": {"content": "lo"}}]}));
                push(json!({"model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}));
            }
            if body.pointer("/stream_options/include_usage").and_then(|v| v.as_bool()) == Some(true) {
                push(json!({"model": model, "choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}));
            }
            s.push_str("data: [DONE]\n\n");
            return ([(header::CONTENT_TYPE, "text/event-stream")], s).into_response();
        }
        let message = if tool {
            json!({"role": "assistant", "content": "", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"a.txt\"}"}}]})
        } else {
            json!({"role": "assistant", "content": "hello"})
        };
        Json(json!({
            "id": "x", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": if tool { "tool_calls" } else { "stop" }}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }))
        .into_response()
    }

    async fn mock_ollama(State(seen): State<Arc<Mutex<Vec<Value>>>>, Json(body): Json<Value>) -> Response {
        seen.lock().unwrap().push(body.clone());
        let model = body["model"].as_str().unwrap_or("").to_string();
        let tool = wants_tool(&body);
        if body["stream"].as_bool() == Some(true) {
            let mut lines = vec![
                json!({"model": model, "message": {"role": "assistant", "content": "hi "}, "done": false}),
                json!({"model": model, "message": {"role": "assistant", "content": "there"}, "done": false}),
            ];
            if tool {
                lines = vec![json!({"model": model, "message": {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "a.txt"}}}]}, "done": false})];
            }
            lines.push(json!({"model": model, "message": {"role": "assistant", "content": ""}, "done": true, "done_reason": "stop", "prompt_eval_count": 7, "eval_count": 3}));
            // No trailing newline on the last line, as some servers send it.
            let s = lines.iter().map(Value::to_string).collect::<Vec<_>>().join("\n");
            return ([(header::CONTENT_TYPE, "application/x-ndjson")], s).into_response();
        }
        let message = if tool {
            json!({"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "a.txt"}}}]})
        } else {
            json!({"role": "assistant", "content": "hi there"})
        };
        Json(json!({"model": model, "message": message, "done": true, "done_reason": "stop", "prompt_eval_count": 7, "eval_count": 3})).into_response()
    }

    async fn mock() -> Mock {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/v1/chat/completions", post(mock_openai))
            .route("/api/chat", post(mock_ollama))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Mock { url, seen }
    }

    fn backend(url: &str, api_format: &str) -> ResolvedBackend {
        ResolvedBackend { url: url.into(), model: "qwen-pinned".into(), backend_type: api_format.into(), api_format: api_format.into() }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    /// (event name, data) pairs of an Anthropic SSE body.
    fn anthropic_events(text: &str) -> Vec<(String, Value)> {
        text.split("\n\n")
            .filter(|f| !f.trim().is_empty())
            .map(|f| {
                let name = f.lines().find_map(|l| l.strip_prefix("event: ")).expect("an event line").to_string();
                let data = f.lines().find_map(|l| l.strip_prefix("data: ")).expect("a data line");
                (name, serde_json::from_str(data).unwrap())
            })
            .collect()
    }

    /// The `data:` payloads of an OpenAI SSE body, `[DONE]` included.
    fn openai_frames(text: &str) -> Vec<String> {
        text.lines().filter_map(|l| l.strip_prefix("data: ")).map(str::to_string).collect()
    }

    #[tokio::test]
    async fn chat_completions_pass_through_with_the_pinned_model_and_are_metered() {
        let m = mock().await;
        let t = Translator::start(backend(&m.url, "openai")).await.unwrap();
        assert!(t.base_url().starts_with("http://127.0.0.1:"), "{}", t.base_url());
        let c = client();
        let url = format!("{}/v1/chat/completions", t.base_url());

        let r: Value = c.post(&url).json(&json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})).send().await.unwrap().json().await.unwrap();
        assert_eq!(r["choices"][0]["message"]["content"], "hello");
        assert_eq!(m.last()["model"], "qwen-pinned", "the CLI's model name is replaced");
        assert_eq!(m.last()["messages"][0]["content"], "hi", "the body is forwarded as-is");

        // Streaming without include_usage: the translator asks for usage
        // upstream and strips the usage chunk on the way back.
        let resp = c.post(&url).json(&json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]})).send().await.unwrap();
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");
        let frames = openai_frames(&resp.text().await.unwrap());
        assert_eq!(m.last()["stream_options"]["include_usage"], true);
        assert_eq!(frames.last().map(String::as_str), Some("[DONE]"));
        let text: String = frames.iter().filter_map(|f| serde_json::from_str::<Value>(f).ok()).filter_map(|v| v.pointer("/choices/0/delta/content").and_then(|c| c.as_str()).map(str::to_string)).collect();
        assert_eq!(text, "Hello");
        assert!(!frames.iter().any(|f| f.contains("\"prompt_tokens\"")), "usage chunk not relayed to a CLI that did not ask: {frames:?}");

        // Streaming WITH include_usage: the CLI gets its usage chunk.
        let resp = c.post(&url).json(&json!({"stream": true, "stream_options": {"include_usage": true}, "messages": [{"role": "user", "content": "hi"}]})).send().await.unwrap();
        let frames = openai_frames(&resp.text().await.unwrap());
        assert!(frames.iter().any(|f| f.contains("\"prompt_tokens\":10")), "{frames:?}");

        let u = t.usage();
        assert_eq!((u.calls, u.prompt_tokens, u.completion_tokens, u.total_tokens), (3, 30, 15, 45));
        assert_eq!(u.models, vec!["qwen-pinned".to_string()]);
        t.shutdown().await;
    }

    #[tokio::test]
    async fn messages_round_trip_tool_use_through_an_openai_backend() {
        let m = mock().await;
        let t = Translator::start(backend(&m.url, "openai")).await.unwrap();
        let c = client();
        let url = format!("{}/v1/messages?beta=true", t.base_url());
        let tools = json!([{"name": "read_file", "description": "read a file", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}}]);

        let r: Value = c
            .post(&url)
            .header("x-api-key", "ignored")
            .header("anthropic-version", "2023-06-01")
            .json(&json!({"model": "claude-sonnet-4", "max_tokens": 512, "system": "Be brief.", "tools": tools, "messages": [{"role": "user", "content": "open a.txt"}]}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let up = m.last();
        assert_eq!(up["model"], "qwen-pinned");
        assert_eq!(up["messages"][0], json!({"role": "system", "content": "Be brief."}));
        assert_eq!(up["tools"][0]["function"]["name"], "read_file", "tools go upstream as functions");
        assert_eq!(r["type"], "message");
        assert_eq!(r["stop_reason"], "tool_use");
        let tu = &r["content"][0];
        assert_eq!((tu["type"].as_str(), tu["id"].as_str(), tu["name"].as_str()), (Some("tool_use"), Some("call_1"), Some("read_file")));
        assert_eq!(tu["input"], json!({"path": "a.txt"}));
        assert_eq!(r["usage"], json!({"input_tokens": 10, "output_tokens": 5}));

        // The CLI runs the tool and sends the result back.
        let r: Value = c
            .post(&url)
            .json(&json!({"model": "claude-sonnet-4", "max_tokens": 512, "tools": tools, "messages": [
                {"role": "user", "content": "open a.txt"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "call_1", "name": "read_file", "input": {"path": "a.txt"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "file body"}]},
            ]}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let up = m.last();
        let msgs = up["messages"].as_array().unwrap();
        assert_eq!(msgs[1]["tool_calls"][0]["id"], "call_1");
        assert_eq!(msgs[2], json!({"role": "tool", "tool_call_id": "call_1", "content": "file body"}));
        assert_eq!(r["content"], json!([{"type": "text", "text": "hello"}]));
        assert_eq!(r["stop_reason"], "end_turn");
        assert_eq!(t.usage().calls, 2);
        t.shutdown().await;
    }

    #[tokio::test]
    async fn streamed_messages_are_a_valid_anthropic_event_sequence() {
        let m = mock().await;
        let t = Translator::start(backend(&m.url, "openai")).await.unwrap();
        let c = client();
        let url = format!("{}/v1/messages", t.base_url());
        let resp = c.post(&url).json(&json!({"model": "claude-x", "max_tokens": 64, "stream": true, "messages": [{"role": "user", "content": "hi"}]})).send().await.unwrap();
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");
        let ev = anthropic_events(&resp.text().await.unwrap());
        let names: Vec<&str> = ev.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["message_start", "content_block_start", "content_block_delta", "content_block_delta", "content_block_stop", "message_delta", "message_stop"]);
        let text: String = ev.iter().filter_map(|(_, d)| d.pointer("/delta/text").and_then(|t| t.as_str())).collect();
        assert_eq!(text, "Hello");
        assert_eq!(ev[5].1["delta"]["stop_reason"], "end_turn");
        assert_eq!(ev[5].1["usage"], json!({"input_tokens": 10, "output_tokens": 5}));

        // A streamed tool call: one tool_use block, stop_reason tool_use.
        let tools = json!([{"name": "read_file", "input_schema": {"type": "object"}}]);
        let resp = c.post(&url).json(&json!({"max_tokens": 64, "stream": true, "tools": tools, "messages": [{"role": "user", "content": "open"}]})).send().await.unwrap();
        let ev = anthropic_events(&resp.text().await.unwrap());
        let start = ev.iter().find(|(n, _)| n == "content_block_start").expect("a block");
        assert_eq!(start.1["content_block"]["type"], "tool_use");
        let args: String = ev.iter().filter_map(|(_, d)| d.pointer("/delta/partial_json").and_then(|t| t.as_str())).collect();
        assert_eq!(serde_json::from_str::<Value>(&args).unwrap(), json!({"path": "a.txt"}));
        assert_eq!(ev.iter().find(|(n, _)| n == "message_delta").unwrap().1["delta"]["stop_reason"], "tool_use");
        let u = t.usage();
        assert_eq!((u.calls, u.prompt_tokens, u.completion_tokens), (2, 20, 10));
        t.shutdown().await;
    }

    #[tokio::test]
    async fn an_ollama_backend_is_spoken_to_on_api_chat_and_metered() {
        let m = mock().await;
        let t = Translator::start(backend(&m.url, "ollama")).await.unwrap();
        let c = client();
        let chat = format!("{}/v1/chat/completions", t.base_url());

        // Non-streaming chat, with an earlier tool call whose arguments are
        // a string on OpenAI's wire and must be an object on Ollama's.
        let r: Value = c
            .post(&chat)
            .json(&json!({"model": "gpt", "max_tokens": 99, "messages": [
                {"role": "user", "content": "x"},
                {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{\"a\":1}"}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "ok"},
            ]}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let up = m.last();
        assert_eq!(up["model"], "qwen-pinned");
        assert_eq!(up["messages"][1]["tool_calls"][0]["function"]["arguments"], json!({"a": 1}));
        assert_eq!(up["options"]["num_predict"], 99);
        assert_eq!(r["object"], "chat.completion");
        assert_eq!(r["choices"][0]["message"]["content"], "hi there");
        assert_eq!(r["usage"], json!({"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}));

        // Streaming chat: NDJSON in, SSE out, the done line metered.
        let resp = c.post(&chat).json(&json!({"stream": true, "stream_options": {"include_usage": true}, "messages": [{"role": "user", "content": "x"}]})).send().await.unwrap();
        let frames = openai_frames(&resp.text().await.unwrap());
        let text: String = frames.iter().filter_map(|f| serde_json::from_str::<Value>(f).ok()).filter_map(|v| v.pointer("/choices/0/delta/content").and_then(|c| c.as_str()).map(str::to_string)).collect();
        assert_eq!(text, "hi there");
        assert!(frames.iter().any(|f| f.contains("\"finish_reason\":\"stop\"")), "{frames:?}");
        assert_eq!(frames.last().map(String::as_str), Some("[DONE]"));

        // Anthropic over Ollama: a tool call comes back as tool_use.
        let msgs = format!("{}/v1/messages", t.base_url());
        let tools = json!([{"name": "read_file", "input_schema": {"type": "object"}}]);
        let r: Value = c.post(&msgs).json(&json!({"max_tokens": 64, "tools": tools, "messages": [{"role": "user", "content": "open"}]})).send().await.unwrap().json().await.unwrap();
        assert_eq!(r["stop_reason"], "tool_use", "{r}");
        assert_eq!(r["content"][0]["input"], json!({"path": "a.txt"}));
        // ...and streamed.
        let resp = c.post(&msgs).json(&json!({"max_tokens": 64, "stream": true, "tools": tools, "messages": [{"role": "user", "content": "open"}]})).send().await.unwrap();
        let ev = anthropic_events(&resp.text().await.unwrap());
        assert_eq!(ev.first().unwrap().0, "message_start");
        assert_eq!(ev.last().unwrap().0, "message_stop");
        let md = &ev.iter().find(|(n, _)| n == "message_delta").unwrap().1;
        assert_eq!(md["delta"]["stop_reason"], "tool_use");
        assert_eq!(md["usage"], json!({"input_tokens": 7, "output_tokens": 3}));

        let u = t.usage();
        assert_eq!((u.calls, u.prompt_tokens, u.completion_tokens, u.total_tokens), (4, 28, 12, 40));
        t.shutdown().await;
    }

    #[tokio::test]
    async fn models_lists_the_pinned_model_and_anything_else_is_a_json_404() {
        let m = mock().await;
        let t = Translator::start(backend(&m.url, "openai")).await.unwrap();
        let c = client();
        let r: Value = c.get(format!("{}/v1/models", t.base_url())).send().await.unwrap().json().await.unwrap();
        assert_eq!(r["data"].as_array().unwrap().len(), 1);
        assert_eq!(r["data"][0]["id"], "qwen-pinned");

        let resp = c.post(format!("{}/v1/responses", t.base_url())).json(&json!({})).send().await.unwrap();
        assert_eq!(resp.status(), 404);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["type"], "error");
        assert_eq!(body["error"]["type"], "not_found_error");
        assert!(body["error"]["message"].as_str().unwrap().contains("/v1/responses"));

        // Not JSON: a 400 in the same shape, and no call counted.
        let resp = c.post(format!("{}/v1/chat/completions", t.base_url())).body("nope").send().await.unwrap();
        assert_eq!(resp.status(), 400);
        assert_eq!(t.usage().calls, 0);
        assert!(m.seen.lock().unwrap().is_empty(), "nothing reached the backend");

        // After shutdown the port is closed.
        let base = t.base_url().to_string();
        t.shutdown().await;
        assert!(client().get(format!("{base}/v1/models")).send().await.is_err());
    }

    #[tokio::test]
    async fn an_upstream_error_keeps_its_status_and_a_reply_without_usage_still_counts() {
        // An endpoint that refuses everything.
        let app = Router::new()
            .route("/v1/chat/completions", post(|| async { (StatusCode::SERVICE_UNAVAILABLE, "loading model").into_response() }))
            .route("/api/chat", post(|| async { Json(json!({"message": {"role": "assistant", "content": "no counts"}, "done": true})) }));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let t = Translator::start(backend(&url, "openai")).await.unwrap();
        let resp = client().post(format!("{}/v1/messages", t.base_url())).json(&json!({"max_tokens": 8, "messages": [{"role": "user", "content": "x"}]})).send().await.unwrap();
        assert_eq!(resp.status(), 503);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"]["type"], "api_error");
        assert!(body["error"]["message"].as_str().unwrap().contains("loading model"));
        assert_eq!(t.usage().calls, 0, "a refused call is not an answered call");
        t.shutdown().await;

        let t = Translator::start(backend(&url, "ollama")).await.unwrap();
        let r: Value = client().post(format!("{}/v1/chat/completions", t.base_url())).json(&json!({"messages": [{"role": "user", "content": "x"}]})).send().await.unwrap().json().await.unwrap();
        assert_eq!(r["choices"][0]["message"]["content"], "no counts");
        let u = t.usage();
        assert_eq!((u.calls, u.total_tokens), (1, 0));
        t.shutdown().await;

        assert!(Translator::start(backend(&url, "anthropic")).await.is_err(), "a node harness never fronts an Anthropic endpoint");
    }
}
