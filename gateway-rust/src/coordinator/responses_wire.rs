// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! OpenAI's Responses API on OpenAI chat (i83 phase E2).
//!
//! Codex CLI speaks only the Responses API (`wire_api = "responses"` is the
//! only value its `model_providers` accept). Every node backend speaks
//! OpenAI chat. This module is the whole translation, pure JSON in and out,
//! the way [`super::anthropic_wire`] is for Anthropic Messages:
//!
//! - [`request_body_from_responses`]: a `POST /responses` body -> an OpenAI
//!   chat-completions body.
//! - [`response_from_chat`]: an OpenAI assistant message + finish reason +
//!   usage -> a Responses object.
//! - [`ChatToResponsesSse`]: OpenAI chat SSE chunks -> the Responses event
//!   stream (`response.created` ... `response.completed`).
//! - [`ToolNames`]: the request's tool names as the chat side sees them,
//!   so a call comes back under the name (and namespace) the client gave.
//!
//! The loopback wire translator (`harness::translator`, `/v1/responses`)
//! and the gateway's `/v1/responses` shim (`routes::responses_shim`) both
//! use it.
//!
//! **What Codex sends** (codex-rs `ResponsesApiRequest`, rust-v0.163.0,
//! `codex-rs/codex-api/src/common.rs`): `model`, `stream: true`, `input`
//! (the WHOLE conversation every time: Codex's HTTP request has no
//! `previous_response_id`; only its websocket transport, off for a custom
//! provider, chains responses), `tools`, `tool_choice: "auto"`,
//! `parallel_tool_calls`, `reasoning`, `store`, `include`,
//! `prompt_cache_key`, `text`, `client_metadata`, `service_tier`. The base
//! instructions ride in `input` as a developer message rather than in
//! `instructions` (taken too, if a client sends it). `input` items are
//! `message` (roles `developer`/`system`/`user`/`assistant`, parts
//! `input_text`/`output_text`/`input_image`), `function_call` and
//! `custom_tool_call` (each with an optional `namespace`), their `*_output`
//! items, and items with no chat equivalent (`reasoning`, `compaction`,
//! `web_search_call`, `additional_tools`, ...), which are dropped. `tools`
//! are `function`, `custom` (a freeform tool such as `apply_patch`, with a
//! grammar), `namespace` (a group of function/custom tools; MCP tools come
//! this way) and hosted tools (`web_search`, `tool_search`, ...) that a
//! node model cannot run, which are dropped.
//!
//! **Chat-side shape.** Every system/developer text is hoisted into ONE
//! leading system message (instructions first), and consecutive user
//! messages are merged: chat templates that insist on one system message
//! and alternating turns (Gemma's among them) then take any Codex history.
//! A namespaced tool `ns` + `name` is the chat function `ns__name` (`nsname`
//! when `ns` already ends in `__`); a `custom` tool is a function taking one
//! string argument `input`. [`ToolNames`] undoes both on the way back.

use serde_json::{json, Map, Value};
use std::collections::HashMap;

/// The namespace a tool with no namespace is in, as Codex spells it.
const DEFAULT_NAMESPACE: &str = "functions";

/// Request fields with a chat equivalent; anything else is dropped (and
/// [`dropped_fields`] names it, for a log line).
const HANDLED: &[&str] = &[
    "model",
    "input",
    "instructions",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "stream",
    "max_output_tokens",
    "temperature",
    "top_p",
    "text",
    "previous_response_id",
    "reasoning",
    "metadata",
];

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::new_v4().simple())
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

// ── tool names ──────────────────────────────────────────────────────────

/// One tool as the client declared it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ToolRef {
    pub namespace: Option<String>,
    pub name: String,
    /// A freeform (`custom`) tool: its call is a `custom_tool_call` whose
    /// `input` is the chat function's one `input` argument.
    pub custom: bool,
}

/// Chat function name -> the tool the client declared, for one request.
#[derive(Debug, Clone, Default)]
pub(crate) struct ToolNames(HashMap<String, ToolRef>);

/// The chat function name for `name` in `namespace`.
pub(crate) fn chat_tool_name(namespace: Option<&str>, name: &str) -> String {
    match namespace.filter(|n| !n.is_empty() && *n != DEFAULT_NAMESPACE) {
        None => name.to_string(),
        Some(ns) if ns.ends_with("__") => format!("{ns}{name}"),
        Some(ns) => format!("{ns}__{name}"),
    }
}

impl ToolNames {
    /// The names a request's `tools` declare.
    pub(crate) fn from_request(body: &Value) -> Self {
        let mut m = HashMap::new();
        for t in body.get("tools").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            match str_of(t, "type") {
                "function" | "custom" => {
                    let name = str_of(t, "name");
                    if !name.is_empty() {
                        m.insert(name.to_string(), ToolRef { namespace: None, name: name.to_string(), custom: str_of(t, "type") == "custom" });
                    }
                }
                "namespace" => {
                    let ns = str_of(t, "name");
                    for inner in t.get("tools").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
                        let name = str_of(inner, "name");
                        let kind = str_of(inner, "type");
                        if name.is_empty() || !matches!(kind, "function" | "custom") {
                            continue;
                        }
                        let namespace = Some(ns.to_string()).filter(|n| !n.is_empty() && n != DEFAULT_NAMESPACE);
                        m.insert(chat_tool_name(Some(ns), name), ToolRef { namespace, name: name.to_string(), custom: kind == "custom" });
                    }
                }
                _ => {}
            }
        }
        Self(m)
    }

    /// The declared tool behind a chat function name; an undeclared name is
    /// a plain function of that name.
    pub(crate) fn resolve(&self, chat_name: &str) -> ToolRef {
        self.0.get(chat_name).cloned().unwrap_or_else(|| ToolRef { namespace: None, name: chat_name.to_string(), custom: false })
    }
}

// ── request: Responses -> chat ──────────────────────────────────────────

/// The request fields this translation drops (non-null ones), for a log
/// line. `store`, `include`, `prompt_cache_key`, `client_metadata`,
/// `service_tier` and the like have no chat equivalent and are harmless to
/// drop (noomesh-internal i153 tracks the ones worth mapping).
pub(crate) fn dropped_fields(body: &Value) -> Vec<String> {
    body.as_object()
        .map(|o| o.iter().filter(|(k, v)| !v.is_null() && !HANDLED.contains(&k.as_str())).map(|(k, _)| k.clone()).collect())
        .unwrap_or_default()
}

/// A Responses `function` tool (or a `custom` one) -> a chat function.
fn chat_function(t: &Value, namespace: Option<&str>) -> Option<Value> {
    let name = str_of(t, "name");
    if name.is_empty() {
        return None;
    }
    let mut description = str_of(t, "description").to_string();
    let parameters = match str_of(t, "type") {
        "function" => t.get("parameters").filter(|p| p.is_object()).cloned().unwrap_or_else(|| json!({"type": "object", "properties": {}})),
        "custom" => {
            // A freeform tool takes raw text. Chat has no such tool, so the
            // text is the one string argument, and its grammar goes in the
            // description where the model can read it.
            if let Some(f) = t.get("format").filter(|f| f.is_object()) {
                let def = str_of(f, "definition");
                if !def.is_empty() {
                    description.push_str(&format!(
                        "\n\nPass the whole input as the string argument `input`. It must follow this {} grammar:\n{def}",
                        str_of(f, "syntax")
                    ));
                }
            }
            json!({"type": "object", "properties": {"input": {"type": "string", "description": "the tool's raw input"}}, "required": ["input"]})
        }
        _ => return None,
    };
    Some(json!({"type": "function", "function": {
        "name": chat_tool_name(namespace, name),
        "description": description,
        "parameters": parameters,
    }}))
}

/// The text of a message's `content` (a string, or its text parts).
fn parts_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter(|p| matches!(str_of(p, "type"), "input_text" | "output_text" | "text" | ""))
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// A user message's `content` as chat content: a string, or an array of
/// text and `image_url` parts when there are images.
fn user_content(content: Option<&Value>) -> Value {
    let Some(Value::Array(parts)) = content else {
        return json!(parts_text(content));
    };
    let mut out = Vec::new();
    for p in parts {
        match str_of(p, "type") {
            "input_text" | "output_text" | "text" | "" => {
                if let Some(t) = p.get("text").and_then(Value::as_str).filter(|t| !t.is_empty()) {
                    out.push(json!({"type": "text", "text": t}));
                }
            }
            "input_image" => {
                if let Some(u) = p.get("image_url").and_then(Value::as_str).filter(|u| !u.is_empty()) {
                    out.push(json!({"type": "image_url", "image_url": {"url": u}}));
                }
            }
            _ => {}
        }
    }
    if out.iter().all(|p| p["type"] == "text") {
        json!(out.iter().filter_map(|p| p["text"].as_str()).collect::<Vec<_>>().join("\n"))
    } else {
        Value::Array(out)
    }
}

/// A `*_output` item's `output` (a string, or content items) as text.
fn output_text(output: Option<&Value>) -> String {
    match output {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(_)) => parts_text(output),
        Some(Value::Object(o)) => o.get("content").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| Value::Object(o.clone()).to_string()),
        _ => String::new(),
    }
}

/// Append a user message, merging it into a user message right before it.
fn push_user(messages: &mut Vec<Value>, content: Value) {
    let empty = match &content {
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => true,
    };
    if empty {
        return;
    }
    if let Some(last) = messages.last_mut().filter(|m| m["role"] == "user") {
        let merged = match (last["content"].take(), content) {
            (Value::String(a), Value::String(b)) => json!(format!("{a}\n\n{b}")),
            (a, b) => {
                let as_parts = |v: Value| match v {
                    Value::Array(p) => p,
                    Value::String(s) => vec![json!({"type": "text", "text": s})],
                    _ => Vec::new(),
                };
                let mut p = as_parts(a);
                p.extend(as_parts(b));
                Value::Array(p)
            }
        };
        last["content"] = merged;
        return;
    }
    messages.push(json!({"role": "user", "content": content}));
}

/// Append a tool call to the assistant turn it belongs to: the assistant
/// message right before it, or a new one.
fn push_call(messages: &mut Vec<Value>, call: Value) {
    if let Some(last) = messages.last_mut().filter(|m| m["role"] == "assistant") {
        match last.get_mut("tool_calls").and_then(Value::as_array_mut) {
            Some(calls) => calls.push(call),
            None => last["tool_calls"] = json!([call]),
        }
        return;
    }
    messages.push(json!({"role": "assistant", "content": "", "tool_calls": [call]}));
}

/// A Responses request body -> an OpenAI chat-completions body.
///
/// - `instructions` and every `system`/`developer` message become ONE
///   leading system message; consecutive user messages are merged.
/// - `function_call` / `custom_tool_call` items become `tool_calls` on the
///   assistant turn they follow; their outputs become `role:"tool"`
///   messages.
/// - `reasoning` items and anything else without a chat equivalent are
///   dropped.
/// - `function`, `custom` and `namespace` tools become chat functions;
///   hosted tools (`web_search`, ...) are dropped.
/// - `max_output_tokens`, `temperature`, `top_p`, `tool_choice`,
///   `parallel_tool_calls`, `stream` and a JSON-schema `text.format` carry
///   over. `model` is the client's; the caller pins its own.
/// - `reasoning.effort` (i153): `none` or `minimal` becomes `reasoning:
///   {effort: "none"}`, which [`super::thinking::asks_no_reasoning`] reads
///   and the caller turns into every engine's "do not reason" field
///   (`thinking::disable_on_wire`); `low`, `medium` and `high` become chat's
///   `reasoning_effort`.
pub(crate) fn request_body_from_responses(body: &Value) -> Value {
    let mut system: Vec<String> = Vec::new();
    if let Some(i) = body.get("instructions").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
        system.push(i.to_string());
    }
    let mut messages: Vec<Value> = Vec::new();
    match body.get("input") {
        Some(Value::String(s)) => push_user(&mut messages, json!(s)),
        Some(Value::Array(items)) => {
            for item in items {
                // A bare {role, content} is a message.
                let ty = item.get("type").and_then(Value::as_str).unwrap_or(if item.get("role").is_some() { "message" } else { "" });
                match ty {
                    "message" => match str_of(item, "role") {
                        "system" | "developer" => {
                            let t = parts_text(item.get("content"));
                            if !t.trim().is_empty() {
                                system.push(t);
                            }
                        }
                        "assistant" => {
                            let t = parts_text(item.get("content"));
                            if t.is_empty() {
                                continue;
                            }
                            match messages.last_mut().filter(|m| m["role"] == "assistant" && m.get("tool_calls").is_none()) {
                                Some(last) => {
                                    let prev = last["content"].as_str().unwrap_or("").to_string();
                                    last["content"] = json!(if prev.is_empty() { t } else { format!("{prev}\n\n{t}") });
                                }
                                None => messages.push(json!({"role": "assistant", "content": t})),
                            }
                        }
                        _ => push_user(&mut messages, user_content(item.get("content"))),
                    },
                    "function_call" => {
                        let ns = item.get("namespace").and_then(Value::as_str);
                        let args = match item.get("arguments") {
                            Some(Value::String(s)) => s.clone(),
                            Some(v) if !v.is_null() => v.to_string(),
                            _ => "{}".to_string(),
                        };
                        push_call(
                            &mut messages,
                            json!({"id": str_of(item, "call_id"), "type": "function", "function": {"name": chat_tool_name(ns, str_of(item, "name")), "arguments": args}}),
                        );
                    }
                    "custom_tool_call" => {
                        let ns = item.get("namespace").and_then(Value::as_str);
                        let args = json!({"input": str_of(item, "input")}).to_string();
                        push_call(
                            &mut messages,
                            json!({"id": str_of(item, "call_id"), "type": "function", "function": {"name": chat_tool_name(ns, str_of(item, "name")), "arguments": args}}),
                        );
                    }
                    "function_call_output" | "custom_tool_call_output" => {
                        messages.push(json!({"role": "tool", "tool_call_id": str_of(item, "call_id"), "content": output_text(item.get("output"))}));
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    if !system.is_empty() {
        messages.insert(0, json!({"role": "system", "content": system.join("\n\n")}));
    }

    let mut out = Map::new();
    out.insert("model".into(), body.get("model").cloned().unwrap_or(Value::Null));
    out.insert("messages".into(), Value::Array(messages));
    out.insert("stream".into(), json!(body.get("stream").and_then(Value::as_bool).unwrap_or(false)));
    if let Some(v) = body.get("max_output_tokens").filter(|v| v.is_number()) {
        out.insert("max_tokens".into(), v.clone());
    }
    for k in ["temperature", "top_p"] {
        if let Some(v) = body.get(k).filter(|v| v.is_number()) {
            out.insert(k.into(), v.clone());
        }
    }
    let mut tools = Vec::new();
    for t in body.get("tools").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        match str_of(t, "type") {
            "function" | "custom" => tools.extend(chat_function(t, None)),
            "namespace" => {
                let ns = str_of(t, "name");
                for inner in t.get("tools").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
                    tools.extend(chat_function(inner, Some(ns)));
                }
            }
            _ => {}
        }
    }
    if !tools.is_empty() {
        out.insert("tools".into(), Value::Array(tools));
        match body.get("tool_choice") {
            Some(Value::String(s)) if matches!(s.as_str(), "auto" | "none" | "required") => {
                out.insert("tool_choice".into(), json!(s));
            }
            Some(tc @ Value::Object(_)) if str_of(tc, "type") == "function" && !str_of(tc, "name").is_empty() => {
                let name = chat_tool_name(tc.get("namespace").and_then(Value::as_str), str_of(tc, "name"));
                out.insert("tool_choice".into(), json!({"type": "function", "function": {"name": name}}));
            }
            _ => {}
        }
        if let Some(p) = body.get("parallel_tool_calls").filter(|p| p.is_boolean()) {
            out.insert("parallel_tool_calls".into(), p.clone());
        }
    }
    if let Some(f) = body.pointer("/text/format").filter(|f| str_of(f, "type") == "json_schema") {
        let mut schema = json!({"name": f.get("name").and_then(Value::as_str).unwrap_or("output"), "schema": f.get("schema").cloned().unwrap_or_else(|| json!({}))});
        if let Some(s) = f.get("strict").filter(|s| s.is_boolean()) {
            schema["strict"] = s.clone();
        }
        out.insert("response_format".into(), json!({"type": "json_schema", "json_schema": schema}));
    }
    match body.pointer("/reasoning/effort").and_then(Value::as_str).map(str::to_ascii_lowercase).as_deref() {
        Some("none" | "minimal") => {
            out.insert("reasoning".into(), json!({"effort": "none"}));
        }
        Some(e @ ("low" | "medium" | "high")) => {
            out.insert("reasoning_effort".into(), json!(e));
        }
        _ => {}
    }
    Value::Object(out)
}

/// The request's `metadata`, echoed on the Responses object (`{}` when it
/// sent none, as OpenAI answers).
pub(crate) fn metadata_of(request: &Value) -> Value {
    request.get("metadata").filter(|m| m.is_object()).cloned().unwrap_or_else(|| json!({}))
}

// ── response: chat -> Responses ─────────────────────────────────────────

/// Responses usage from (prompt, completion).
fn usage_json(usage: Option<(u64, u64)>) -> Value {
    match usage {
        Some((p, c)) => json!({
            "input_tokens": p,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": c,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": p + c,
        }),
        None => Value::Null,
    }
}

/// `length` is the one finish reason that is not a completed response.
fn status_for(finish_reason: Option<&str>) -> (&'static str, Value) {
    match finish_reason {
        Some("length") => ("incomplete", json!({"reason": "max_output_tokens"})),
        Some("content_filter") => ("incomplete", json!({"reason": "content_filter"})),
        _ => ("completed", Value::Null),
    }
}

#[allow(clippy::too_many_arguments)]
fn response_object(id: &str, model: &str, created_at: u64, status: &str, incomplete: Value, output: Vec<Value>, usage: Option<(u64, u64)>, metadata: &Value) -> Value {
    json!({
        "id": id,
        "object": "response",
        "created_at": created_at,
        "status": status,
        "error": null,
        "incomplete_details": incomplete,
        "model": model,
        "output": output,
        "parallel_tool_calls": true,
        "tool_choice": "auto",
        "tools": [],
        "usage": usage_json(usage),
        "metadata": metadata,
    })
}

fn message_item(id: &str, text: &str, status: &str) -> Value {
    let content = if status == "in_progress" { json!([]) } else { json!([{"type": "output_text", "text": text, "annotations": []}]) };
    json!({"id": id, "type": "message", "role": "assistant", "status": status, "content": content})
}

fn reasoning_item(id: &str, text: &str, done: bool) -> Value {
    let content = if done { json!([{"type": "reasoning_text", "text": text}]) } else { json!([]) };
    json!({"id": id, "type": "reasoning", "summary": [], "content": content})
}

/// A function call as the client declared its tool: `function_call` with
/// its namespace, or `custom_tool_call` with the `input` unwrapped.
fn call_item(id: &str, call_id: &str, chat_name: &str, args: &str, status: &str, names: &ToolNames) -> Value {
    let t = names.resolve(chat_name);
    let mut item = if t.custom {
        let input = serde_json::from_str::<Value>(args)
            .ok()
            .and_then(|v| v.get("input").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| args.to_string());
        json!({"id": id, "type": "custom_tool_call", "status": status, "call_id": call_id, "name": t.name, "input": input})
    } else {
        json!({"id": id, "type": "function_call", "status": status, "call_id": call_id, "name": t.name, "arguments": args})
    };
    if let Some(ns) = t.namespace {
        item["namespace"] = json!(ns);
    }
    item
}

fn arguments_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(v) if !v.is_null() => v.to_string(),
        _ => String::new(),
    }
}

/// The reasoning text of a chat message or delta (`reasoning_content`,
/// or `reasoning` on newer vLLM).
fn reasoning_of(v: &Value) -> Option<&str> {
    ["reasoning_content", "reasoning"].iter().find_map(|k| v.get(*k).and_then(Value::as_str)).filter(|s| !s.is_empty())
}

/// An OpenAI assistant message (`choices[0].message`), its finish reason
/// and the reply's usage (prompt, completion) -> a Responses object, with
/// the request's `metadata` ([`metadata_of`]).
pub(crate) fn response_from_chat(message: &Value, finish_reason: Option<&str>, usage: Option<(u64, u64)>, model: &str, names: &ToolNames, metadata: &Value) -> Value {
    let mut output = Vec::new();
    if let Some(r) = reasoning_of(message) {
        output.push(reasoning_item(&new_id("rs"), r, true));
    }
    let text = parts_text(message.get("content"));
    let calls = message.get("tool_calls").and_then(Value::as_array).cloned().unwrap_or_default();
    if !text.is_empty() || calls.is_empty() {
        output.push(message_item(&new_id("msg"), &text, "completed"));
    }
    for tc in &calls {
        let f = tc.get("function").unwrap_or(tc);
        let call_id = tc.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()).map(str::to_string).unwrap_or_else(|| new_id("call"));
        let mut args = arguments_string(f.get("arguments"));
        if args.is_empty() {
            args = "{}".into();
        }
        output.push(call_item(&new_id("fc"), &call_id, str_of(f, "name"), &args, "completed", names));
    }
    let (status, incomplete) = status_for(finish_reason);
    response_object(&new_id("resp"), model, now_secs(), status, incomplete, output, usage, metadata)
}

// ── the stream ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Item {
    Reasoning { id: String, text: String, open: bool },
    Message { id: String, text: String, open: bool },
    Call { id: String, call_id: String, chat_name: String, args: String, open: bool },
}

/// Translates OpenAI chat-completion chunks into the Responses event
/// stream — the order Codex's parser and the openai-python SDK expect:
///
/// `response.created`, `response.in_progress`, then per output item
/// `response.output_item.added` ... `response.output_item.done` (a message
/// with `response.content_part.added`, `response.output_text.delta`s,
/// `response.output_text.done`, `response.content_part.done`; a function
/// call with `response.function_call_arguments.delta`s and `.done`; a
/// reasoning item with `response.reasoning_text.delta`s), and last
/// `response.completed` (or `response.incomplete` for a `length` stop)
/// carrying every item and the usage. A stream that breaks ends with
/// `response.failed` from [`fail`](Self::fail).
///
/// A message item closes when a tool call starts; tool calls stay open to
/// the end, so interleaved argument fragments of parallel calls land in
/// the right item. Every event's data carries `type` and a running
/// `sequence_number`; the caller frames each as `event: <name>`/`data:`.
pub(crate) struct ChatToResponsesSse {
    resp_id: String,
    model: String,
    created_at: u64,
    names: ToolNames,
    seq: u64,
    started: bool,
    done: bool,
    items: Vec<Item>,
    /// Chat tool-call index -> its item's output index.
    calls: HashMap<u64, usize>,
    finish_reason: Option<String>,
    usage: Option<(u64, u64)>,
    /// The request's `metadata`, on every response snapshot.
    metadata: Value,
}

impl ChatToResponsesSse {
    pub(crate) fn new(model: &str, names: ToolNames) -> Self {
        Self {
            resp_id: new_id("resp"),
            model: model.to_string(),
            created_at: now_secs(),
            names,
            seq: 0,
            started: false,
            done: false,
            items: Vec::new(),
            calls: HashMap::new(),
            finish_reason: None,
            usage: None,
            metadata: json!({}),
        }
    }

    /// Echo the request's `metadata` ([`metadata_of`]) on every snapshot.
    pub(crate) fn with_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }

    fn ev(&mut self, out: &mut Vec<(String, Value)>, name: &str, mut data: Value) {
        data["type"] = json!(name);
        data["sequence_number"] = json!(self.seq);
        self.seq += 1;
        out.push((name.to_string(), data));
    }

    fn snapshot(&self, status: &str, incomplete: Value, output: Vec<Value>, usage: Option<(u64, u64)>) -> Value {
        response_object(&self.resp_id, &self.model, self.created_at, status, incomplete, output, usage, &self.metadata)
    }

    fn start(&mut self, out: &mut Vec<(String, Value)>) {
        if self.started {
            return;
        }
        self.started = true;
        let r = self.snapshot("in_progress", Value::Null, Vec::new(), None);
        self.ev(out, "response.created", json!({"response": r.clone()}));
        self.ev(out, "response.in_progress", json!({"response": r}));
    }

    /// The item at `i` as it stands, finished or not.
    fn item_json(&self, i: usize) -> Value {
        match &self.items[i] {
            Item::Reasoning { id, text, open } => reasoning_item(id, text, !open),
            Item::Message { id, text, open } => message_item(id, text, if *open { "in_progress" } else { "completed" }),
            Item::Call { id, call_id, chat_name, args, open } => {
                let args = if !open && args.is_empty() { "{}" } else { args.as_str() };
                call_item(id, call_id, chat_name, args, if *open { "in_progress" } else { "completed" }, &self.names)
            }
        }
    }

    /// Close item `i` if it is open, with its closing events.
    fn close(&mut self, i: usize, out: &mut Vec<(String, Value)>) {
        let was_open = match &mut self.items[i] {
            Item::Reasoning { open, .. } | Item::Message { open, .. } | Item::Call { open, .. } => std::mem::replace(open, false),
        };
        if !was_open {
            return;
        }
        match self.items[i].clone() {
            Item::Reasoning { id, text, .. } => {
                self.ev(out, "response.reasoning_text.done", json!({"item_id": id, "output_index": i, "content_index": 0, "text": text}));
            }
            Item::Message { id, text, .. } => {
                self.ev(out, "response.output_text.done", json!({"item_id": id, "output_index": i, "content_index": 0, "text": text, "logprobs": []}));
                self.ev(
                    out,
                    "response.content_part.done",
                    json!({"item_id": id, "output_index": i, "content_index": 0, "part": {"type": "output_text", "text": text, "annotations": []}}),
                );
            }
            Item::Call { id, chat_name, args, .. } => {
                let args = if args.is_empty() { "{}".to_string() } else { args };
                if self.names.resolve(&chat_name).custom {
                    let input = call_item(&id, "", &chat_name, &args, "completed", &self.names)["input"].clone();
                    self.ev(out, "response.custom_tool_call_input.done", json!({"item_id": id, "output_index": i, "input": input}));
                } else {
                    self.ev(out, "response.function_call_arguments.done", json!({"item_id": id, "output_index": i, "arguments": args}));
                }
            }
        }
        let item = self.item_json(i);
        self.ev(out, "response.output_item.done", json!({"output_index": i, "item": item}));
    }

    /// The open item of one kind (reasoning or message), if the last item
    /// of that kind is still open.
    fn open_of(&self, reasoning: bool) -> Option<usize> {
        self.items.iter().rposition(|it| match it {
            Item::Reasoning { open, .. } => reasoning && *open,
            Item::Message { open, .. } => !reasoning && *open,
            Item::Call { .. } => false,
        })
    }

    fn open_new(&mut self, item: Item, out: &mut Vec<(String, Value)>) -> usize {
        self.items.push(item);
        let i = self.items.len() - 1;
        let json = self.item_json(i);
        self.ev(out, "response.output_item.added", json!({"output_index": i, "item": json}));
        if let Item::Message { id, .. } = &self.items[i] {
            let id = id.clone();
            self.ev(
                out,
                "response.content_part.added",
                json!({"item_id": id, "output_index": i, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}}),
            );
        }
        i
    }

    /// One OpenAI chunk -> the Responses events it implies.
    pub(crate) fn on_chunk(&mut self, chunk: &Value) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        self.start(&mut out);
        if let Some(u) = chunk.get("usage").filter(|u| u.is_object()) {
            let (p, c, _) = super::anthropic_wire::usage_tokens(u);
            self.usage = Some((p, c));
        }
        let Some(choice) = chunk.get("choices").and_then(|c| c.get(0)) else {
            return out;
        };
        let delta = choice.get("delta").cloned().unwrap_or_else(|| json!({}));

        if let Some(r) = reasoning_of(&delta) {
            let i = match self.open_of(true) {
                Some(i) => i,
                None => self.open_new(Item::Reasoning { id: new_id("rs"), text: String::new(), open: true }, &mut out),
            };
            if let Item::Reasoning { text, .. } = &mut self.items[i] {
                text.push_str(r);
            }
            let id = match &self.items[i] {
                Item::Reasoning { id, .. } => id.clone(),
                _ => String::new(),
            };
            self.ev(&mut out, "response.reasoning_text.delta", json!({"item_id": id, "output_index": i, "content_index": 0, "delta": r}));
        }

        if let Some(t) = delta.get("content").and_then(Value::as_str).filter(|t| !t.is_empty()) {
            if let Some(r) = self.open_of(true) {
                self.close(r, &mut out);
            }
            let i = match self.open_of(false) {
                Some(i) => i,
                None => self.open_new(Item::Message { id: new_id("msg"), text: String::new(), open: true }, &mut out),
            };
            let id = match &mut self.items[i] {
                Item::Message { id, text, .. } => {
                    text.push_str(t);
                    id.clone()
                }
                _ => String::new(),
            };
            self.ev(&mut out, "response.output_text.delta", json!({"item_id": id, "output_index": i, "content_index": 0, "delta": t, "logprobs": []}));
        }

        for (pos, tc) in delta.get("tool_calls").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]).iter().enumerate() {
            let ti = tc.get("index").and_then(Value::as_u64).unwrap_or(pos as u64);
            let f = tc.get("function").cloned().unwrap_or_else(|| json!({}));
            let i = match self.calls.get(&ti).copied() {
                Some(i) => {
                    if let (Item::Call { chat_name, .. }, Some(n)) = (&mut self.items[i], f.get("name").and_then(Value::as_str)) {
                        // A name in fragments (rare): the done item has it whole.
                        if !chat_name.ends_with(n) {
                            chat_name.push_str(n);
                        }
                    }
                    i
                }
                None => {
                    for open in [self.open_of(true), self.open_of(false)].into_iter().flatten() {
                        self.close(open, &mut out);
                    }
                    let call_id = tc.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()).map(str::to_string).unwrap_or_else(|| new_id("call"));
                    let item = Item::Call { id: new_id("fc"), call_id, chat_name: str_of(&f, "name").to_string(), args: String::new(), open: true };
                    let i = self.open_new(item, &mut out);
                    self.calls.insert(ti, i);
                    i
                }
            };
            // Fragments of a JSON string, or (Ollama, converted upstream)
            // the whole arguments at once.
            let part = arguments_string(f.get("arguments"));
            if part.is_empty() {
                continue;
            }
            let (id, custom) = match &mut self.items[i] {
                Item::Call { id, args, chat_name, .. } => {
                    args.push_str(&part);
                    (id.clone(), self.names.resolve(chat_name).custom)
                }
                _ => continue,
            };
            // A custom tool's input is inside the JSON; it is sent whole
            // when the call closes.
            if !custom {
                self.ev(&mut out, "response.function_call_arguments.delta", json!({"item_id": id, "output_index": i, "delta": part}));
            }
        }

        if let Some(fr) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish_reason = Some(fr.to_string());
        }
        out
    }

    /// The upstream ended: close every open item and send
    /// `response.completed` (`response.incomplete` for a `length` stop)
    /// with the output and the usage. Idempotent.
    pub(crate) fn finish(&mut self) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        self.start(&mut out);
        if !self.items.iter().any(|it| matches!(it, Item::Message { .. } | Item::Call { .. })) {
            // Nothing said: still one (empty) message, so the turn has an answer.
            if let Some(r) = self.open_of(true) {
                self.close(r, &mut out);
            }
            self.open_new(Item::Message { id: new_id("msg"), text: String::new(), open: true }, &mut out);
        }
        for i in 0..self.items.len() {
            self.close(i, &mut out);
        }
        self.done = true;
        let output: Vec<Value> = (0..self.items.len()).map(|i| self.item_json(i)).collect();
        let (status, incomplete) = status_for(self.finish_reason.as_deref());
        let r = self.snapshot(status, incomplete, output, self.usage);
        let name = if status == "completed" { "response.completed" } else { "response.incomplete" };
        self.ev(&mut out, name, json!({"response": r}));
        out
    }

    /// The upstream broke midway: `response.failed` with the reason.
    pub(crate) fn fail(&mut self, message: &str) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        self.start(&mut out);
        self.done = true;
        let mut r = self.snapshot("failed", Value::Null, Vec::new(), self.usage);
        r["error"] = json!({"code": "server_error", "message": message});
        self.ev(&mut out, "response.failed", json!({"response": r}));
        out
    }
}

/// `event: <name>` / `data: <json>` frames, one blank line after each.
pub(crate) fn sse_frames(events: &[(String, Value)]) -> String {
    let mut s = String::new();
    for (name, data) in events {
        s.push_str(&format!("event: {name}\ndata: {data}\n\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Codex-shaped request: developer instructions in `input`, a
    /// namespaced MCP tool, a freeform `apply_patch`, a hosted tool, and a
    /// history with reasoning, a call and its output.
    fn codex_request() -> Value {
        json!({
            "model": "gpt-5-codex",
            "stream": true,
            "tool_choice": "auto",
            "parallel_tool_calls": false,
            "store": false,
            "include": ["reasoning.encrypted_content"],
            "prompt_cache_key": "abc",
            "reasoning": {"effort": "medium"},
            "previous_response_id": null,
            "tools": [
                {"type": "function", "name": "shell", "description": "run a command", "strict": false,
                 "parameters": {"type": "object", "properties": {"command": {"type": "array"}}}},
                {"type": "custom", "name": "apply_patch", "description": "edit files",
                 "format": {"type": "grammar", "syntax": "lark", "definition": "start: patch"}},
                {"type": "namespace", "name": "mcp__noomesh__", "description": "noomesh tools", "tools": [
                    {"type": "function", "name": "rag_query", "description": "search", "strict": false, "parameters": {"type": "object"}}]},
                {"type": "web_search"},
            ],
            "input": [
                {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "You are Codex."}]},
                {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "Sandbox: workspace-write."}]},
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "<environment_context/>"}]},
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "list the files"}]},
                {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": null},
                {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Listing."}]},
                {"type": "function_call", "call_id": "call_a", "name": "shell", "arguments": "{\"command\":[\"ls\"]}"},
                {"type": "function_call", "call_id": "call_b", "name": "rag_query", "namespace": "mcp__noomesh__", "arguments": "{}"},
                {"type": "function_call_output", "call_id": "call_a", "output": "a.txt"},
                {"type": "function_call_output", "call_id": "call_b", "output": [{"type": "input_text", "text": "no hits"}]},
                {"type": "custom_tool_call", "call_id": "call_c", "name": "apply_patch", "input": "*** Begin Patch"},
                {"type": "custom_tool_call_output", "call_id": "call_c", "output": "Done!"},
            ],
        })
    }

    #[test]
    fn a_codex_request_becomes_one_chat_body() {
        let c = request_body_from_responses(&codex_request());
        let m = c["messages"].as_array().unwrap();
        assert_eq!(m[0], json!({"role": "system", "content": "You are Codex.\n\nSandbox: workspace-write."}), "developer text hoisted into one system message");
        assert_eq!(m[1], json!({"role": "user", "content": "<environment_context/>\n\nlist the files"}), "consecutive user messages merged");
        assert_eq!(m[2]["role"], "assistant");
        assert_eq!(m[2]["content"], "Listing.");
        let calls = m[2]["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 2, "both calls ride the assistant turn they follow: {m:?}");
        assert_eq!(calls[0], json!({"id": "call_a", "type": "function", "function": {"name": "shell", "arguments": "{\"command\":[\"ls\"]}"}}));
        assert_eq!(calls[1]["function"]["name"], "mcp__noomesh__rag_query");
        assert_eq!(m[3], json!({"role": "tool", "tool_call_id": "call_a", "content": "a.txt"}));
        assert_eq!(m[4], json!({"role": "tool", "tool_call_id": "call_b", "content": "no hits"}));
        assert_eq!(m[5]["tool_calls"][0]["function"], json!({"name": "apply_patch", "arguments": "{\"input\":\"*** Begin Patch\"}"}));
        assert_eq!(m[6], json!({"role": "tool", "tool_call_id": "call_c", "content": "Done!"}));
        assert_eq!(m.len(), 7, "the reasoning item is dropped: {m:?}");

        let tools = c["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["function"]["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["shell", "apply_patch", "mcp__noomesh__rag_query"], "web_search has no chat equivalent");
        assert_eq!(tools[1]["function"]["parameters"]["required"], json!(["input"]));
        assert!(tools[1]["function"]["description"].as_str().unwrap().contains("start: patch"), "the grammar reaches the model");
        assert_eq!(c["tool_choice"], "auto");
        assert_eq!(c["parallel_tool_calls"], false);
        assert_eq!(c["stream"], true);
        for k in ["store", "include", "reasoning", "prompt_cache_key", "previous_response_id", "input", "instructions"] {
            assert!(c.get(k).is_none(), "{k} must not reach the chat body");
        }
        let mut dropped = dropped_fields(&codex_request());
        dropped.sort();
        assert_eq!(dropped, ["include", "prompt_cache_key", "store"]);
    }

    #[test]
    fn string_input_instructions_sampling_images_and_schema() {
        let c = request_body_from_responses(&json!({
            "instructions": "be brief", "input": "hi", "max_output_tokens": 50, "temperature": 0.2, "top_p": 0.9,
            "text": {"format": {"type": "json_schema", "name": "out", "schema": {"type": "object"}, "strict": true}},
        }));
        assert_eq!(c["messages"], json!([{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]));
        assert_eq!((c["max_tokens"].as_u64(), c["temperature"].as_f64(), c["top_p"].as_f64()), (Some(50), Some(0.2), Some(0.9)));
        assert_eq!(c["stream"], false);
        assert_eq!(c["response_format"], json!({"type": "json_schema", "json_schema": {"name": "out", "schema": {"type": "object"}, "strict": true}}));
        assert!(c.get("tools").is_none() && c.get("tool_choice").is_none());

        let c = request_body_from_responses(&json!({"input": [{"role": "user", "content": [
            {"type": "input_text", "text": "what is this"}, {"type": "input_image", "image_url": "data:image/png;base64,AA"}]}]}));
        assert_eq!(c["messages"][0]["content"], json!([{"type": "text", "text": "what is this"}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA"}}]));
    }

    #[test]
    fn tool_names_round_trip_namespaces_and_custom_tools() {
        let names = ToolNames::from_request(&codex_request());
        assert_eq!(names.resolve("shell"), ToolRef { namespace: None, name: "shell".into(), custom: false });
        assert_eq!(names.resolve("mcp__noomesh__rag_query"), ToolRef { namespace: Some("mcp__noomesh__".into()), name: "rag_query".into(), custom: false });
        assert!(names.resolve("apply_patch").custom);
        assert_eq!(names.resolve("made_up").name, "made_up");
        assert_eq!(chat_tool_name(Some("functions"), "x"), "x", "the default namespace is no namespace");
        assert_eq!(chat_tool_name(Some("tools"), "x"), "tools__x");
    }

    #[test]
    fn a_chat_message_becomes_a_responses_object() {
        let names = ToolNames::from_request(&codex_request());
        let msg = json!({"role": "assistant", "content": "Patching.", "reasoning_content": "think", "tool_calls": [
            {"id": "call_9", "type": "function", "function": {"name": "mcp__noomesh__rag_query", "arguments": "{\"q\":1}"}},
            {"id": "", "type": "function", "function": {"name": "apply_patch", "arguments": "{\"input\":\"*** Begin Patch\"}"}},
        ]});
        let r = response_from_chat(&msg, Some("tool_calls"), Some((10, 5)), "qwen", &names, &json!({}));
        assert_eq!((r["object"].as_str(), r["status"].as_str(), r["model"].as_str()), (Some("response"), Some("completed"), Some("qwen")));
        assert!(r["id"].as_str().unwrap().starts_with("resp_"));
        let out = r["output"].as_array().unwrap();
        let types: Vec<&str> = out.iter().map(|i| i["type"].as_str().unwrap()).collect();
        assert_eq!(types, ["reasoning", "message", "function_call", "custom_tool_call"]);
        assert_eq!(out[1]["content"], json!([{"type": "output_text", "text": "Patching.", "annotations": []}]));
        assert_eq!((out[2]["call_id"].as_str(), out[2]["name"].as_str(), out[2]["namespace"].as_str()), (Some("call_9"), Some("rag_query"), Some("mcp__noomesh__")));
        assert_eq!(out[2]["arguments"], "{\"q\":1}");
        assert_eq!(out[3]["input"], "*** Begin Patch");
        assert!(out[3]["call_id"].as_str().unwrap().starts_with("call_"), "a missing call id is minted");
        assert_eq!(r["usage"], json!({"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 5, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 15}));

        let r = response_from_chat(&json!({"role": "assistant", "content": "cut"}), Some("length"), None, "m", &ToolNames::default(), &json!({}));
        assert_eq!(r["status"], "incomplete");
        assert_eq!(r["incomplete_details"]["reason"], "max_output_tokens");
        assert!(r["usage"].is_null());
    }

    /// reasoning.effort (i153): none/minimal ask for no reasoning, low to
    /// high become chat's reasoning_effort; metadata is echoed on the whole
    /// reply and on every streamed snapshot.
    #[test]
    fn reasoning_effort_maps_and_metadata_is_echoed() {
        use crate::coordinator::thinking::asks_no_reasoning;
        let chat = |e: &str| request_body_from_responses(&json!({"input": "hi", "reasoning": {"effort": e}}));
        for e in ["none", "minimal", "MINIMAL"] {
            let c = chat(e);
            assert_eq!(c["reasoning"], json!({"effort": "none"}), "{e}: {c}");
            assert!(c.get("reasoning_effort").is_none() && asks_no_reasoning(&c), "{e}: {c}");
        }
        for e in ["low", "medium", "high"] {
            let c = chat(e);
            assert_eq!(c["reasoning_effort"], e, "{c}");
            assert!(c.get("reasoning").is_none() && !asks_no_reasoning(&c), "{e}: {c}");
        }
        let c = request_body_from_responses(&json!({"input": "hi", "reasoning": {"summary": "auto"}}));
        assert!(c.get("reasoning").is_none() && c.get("reasoning_effort").is_none(), "no effort, nothing set: {c}");

        let req = json!({"input": "hi", "metadata": {"ticket": "T-1"}});
        assert_eq!(metadata_of(&json!({"input": "hi"})), json!({}));
        let r = response_from_chat(&json!({"role": "assistant", "content": "ok"}), Some("stop"), None, "m", &ToolNames::default(), &metadata_of(&req));
        assert_eq!(r["metadata"], json!({"ticket": "T-1"}));
        let mut t = ChatToResponsesSse::new("m", ToolNames::default()).with_metadata(metadata_of(&req));
        let mut ev = t.on_chunk(&json!({"choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}]}));
        ev.extend(t.finish());
        let snapshots: Vec<_> = ev.iter().filter(|(_, d)| d.get("response").is_some()).collect();
        assert!(snapshots.iter().any(|(n, _)| n == "response.completed"), "{ev:?}");
        for (name, data) in snapshots {
            assert_eq!(data["response"]["metadata"], json!({"ticket": "T-1"}), "{name}");
        }
    }

    fn names_of(ev: &[(String, Value)]) -> Vec<&str> {
        ev.iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn chat_chunks_become_the_responses_event_sequence() {
        let names = ToolNames::from_request(&codex_request());
        let chunks = [
            json!({"choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}),
            json!({"choices": [{"index": 0, "delta": {"reasoning_content": "hmm"}}]}),
            json!({"choices": [{"index": 0, "delta": {"content": "Let me "}}]}),
            json!({"choices": [{"index": 0, "delta": {"content": "check."}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_9", "type": "function", "function": {"name": "mcp__noomesh__rag_query", "arguments": ""}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"q\":"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "\"noo\"}"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 1, "id": "call_p", "type": "function", "function": {"name": "apply_patch", "arguments": "{\"input\":\"*** Begin\"}"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
            json!({"choices": [], "usage": {"prompt_tokens": 50, "completion_tokens": 42, "total_tokens": 92}}),
        ];
        let mut t = ChatToResponsesSse::new("qwen", names);
        let mut ev: Vec<(String, Value)> = chunks.iter().flat_map(|c| t.on_chunk(c)).collect();
        ev.extend(t.finish());
        assert_eq!(
            names_of(&ev),
            [
                "response.created", "response.in_progress",
                "response.output_item.added", "response.reasoning_text.delta",
                "response.reasoning_text.done", "response.output_item.done",
                "response.output_item.added", "response.content_part.added",
                "response.output_text.delta", "response.output_text.delta",
                "response.output_text.done", "response.content_part.done", "response.output_item.done",
                "response.output_item.added", "response.function_call_arguments.delta", "response.function_call_arguments.delta",
                "response.output_item.added",
                "response.function_call_arguments.done", "response.output_item.done",
                "response.custom_tool_call_input.done", "response.output_item.done",
                "response.completed",
            ],
        );
        for (i, (name, data)) in ev.iter().enumerate() {
            assert_eq!(data["type"], name.as_str());
            assert_eq!(data["sequence_number"], i, "sequence numbers run in order");
        }
        let fc_done = &ev[18].1["item"];
        assert_eq!((fc_done["type"].as_str(), fc_done["name"].as_str(), fc_done["namespace"].as_str()), (Some("function_call"), Some("rag_query"), Some("mcp__noomesh__")));
        assert_eq!(fc_done["arguments"], "{\"q\":\"noo\"}");
        assert_eq!(fc_done["call_id"], "call_9");
        assert_eq!(ev[18].1["output_index"], 2);
        let patch = &ev[20].1["item"];
        assert_eq!((patch["type"].as_str(), patch["input"].as_str()), (Some("custom_tool_call"), Some("*** Begin")));
        let done = &ev.last().unwrap().1["response"];
        assert_eq!(done["status"], "completed");
        assert_eq!(done["output"].as_array().unwrap().len(), 4);
        assert_eq!(done["output"][1]["content"][0]["text"], "Let me check.");
        assert_eq!(done["output"][0]["content"][0]["text"], "hmm");
        assert_eq!(done["usage"]["input_tokens"], 50);
        assert_eq!(done["usage"]["output_tokens"], 42);
        assert_eq!(done["usage"]["total_tokens"], 92);
        assert_eq!(done["id"], ev[0].1["response"]["id"], "one response id throughout");
        assert!(t.finish().is_empty(), "finish is idempotent");

        // Text only: the shape a plain answer streams in.
        let mut t = ChatToResponsesSse::new("m", ToolNames::default());
        let mut ev = t.on_chunk(&json!({"choices": [{"delta": {"content": "Hi"}, "finish_reason": "stop"}]}));
        ev.extend(t.finish());
        assert_eq!(
            names_of(&ev),
            ["response.created", "response.in_progress", "response.output_item.added", "response.content_part.added", "response.output_text.delta",
             "response.output_text.done", "response.content_part.done", "response.output_item.done", "response.completed"],
        );
        assert!(ev.last().unwrap().1["response"]["usage"].is_null(), "no usage chunk, no usage");

        // An empty stream still answers with one empty message.
        let mut empty = ChatToResponsesSse::new("m", ToolNames::default());
        let ev = empty.finish();
        assert_eq!(ev.last().unwrap().1["response"]["output"][0]["type"], "message");

        // A stream cut short by length is incomplete; a broken one failed.
        let mut cut = ChatToResponsesSse::new("m", ToolNames::default());
        cut.on_chunk(&json!({"choices": [{"delta": {"content": "x"}, "finish_reason": "length"}]}));
        assert_eq!(cut.finish().last().unwrap().0, "response.incomplete");
        let mut broken = ChatToResponsesSse::new("m", ToolNames::default());
        broken.on_chunk(&json!({"choices": [{"delta": {"content": "x"}}]}));
        let ev = broken.fail("upstream died");
        assert_eq!(ev.last().unwrap().0, "response.failed");
        assert_eq!(ev.last().unwrap().1["response"]["error"]["message"], "upstream died");
        assert!(broken.finish().is_empty(), "nothing follows a failure");
        assert!(sse_frames(&ev).starts_with("event: response.failed\ndata: {"));
    }
}
