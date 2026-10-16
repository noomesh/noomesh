// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The Anthropic Messages API on the agent loop's wire (i83 phase C).
//!
//! The loop speaks one internal shape — OpenAI chat messages, OpenAI tool
//! schemas, OpenAI-style assistant messages and SSE `choices[0].delta`
//! chunks. This module is the whole translation to and from Anthropic, so
//! the loop's consumers stay as they are:
//!
//! - [`request_body`]: OpenAI messages + tools -> a `/v1/messages` body
//!   (system hoisted, `tool_calls` -> `tool_use` blocks, `role:"tool"` ->
//!   `tool_result` blocks merged into one user turn).
//! - [`parse_response`]: a non-streaming Messages response -> the
//!   normalised assistant message `parse_llm_response` returns.
//! - [`SseTranslator`]: each Anthropic SSE event -> the OpenAI chunk the
//!   loop's two SSE consumers already accumulate (content, tool-call
//!   deltas by index, finish reason, usage).

use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

/// The `/v1/messages` request body for `model`.
///
/// `max_tokens` is required by the API; the loop's other wires leave the
/// output budget to the server, which Anthropic does not allow.
pub(crate) fn request_body(
    model: &str,
    messages: &[Value],
    tools: Option<&[Value]>,
    stream: bool,
    max_tokens: u32,
) -> Value {
    let (system, msgs) = convert_messages(messages);
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": msgs,
        "stream": stream,
    });
    if !system.is_empty() {
        body["system"] = json!(system);
    }
    if let Some(tools) = tools {
        let converted: Vec<Value> = tools.iter().filter_map(convert_tool).collect();
        if !converted.is_empty() {
            body["tools"] = Value::Array(converted);
        }
    }
    body
}

/// An OpenAI function schema -> Anthropic `{name, description, input_schema}`.
fn convert_tool(tool: &Value) -> Option<Value> {
    let func = tool.get("function").unwrap_or(tool);
    let name = func.get("name").and_then(|n| n.as_str()).filter(|n| !n.is_empty())?;
    let description = func.get("description").and_then(|d| d.as_str()).unwrap_or("");
    let schema = func
        .get("parameters")
        .filter(|p| p.is_object())
        .cloned()
        .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
    Some(json!({"name": name, "description": description, "input_schema": schema}))
}

/// Text of an OpenAI message's `content` — a string, or the text parts of
/// a content-part array.
fn content_text(msg: &Value) -> String {
    match msg.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// A tool call's `arguments` (a JSON string on the loop's wire, sometimes
/// already an object) as the object Anthropic wants in `input`.
fn arguments_object(args: Option<&Value>) -> Value {
    let parsed = match args {
        Some(Value::String(s)) if !s.trim().is_empty() => serde_json::from_str::<Value>(s).ok(),
        Some(v @ Value::Object(_)) => Some(v.clone()),
        _ => None,
    };
    match parsed {
        Some(v @ Value::Object(_)) => v,
        _ => json!({}),
    }
}

/// OpenAI chat messages -> (top-level system text, Anthropic messages).
///
/// - Every `system` message is hoisted into the top-level `system` (the
///   loop builds one leading system message; any other is folded in too
///   rather than dropped).
/// - An assistant message's text and `tool_calls` become `text` and
///   `tool_use` blocks.
/// - `role:"tool"` results become `tool_result` blocks in a user turn;
///   consecutive same-role messages merge into one turn, because the API
///   requires user/assistant alternation.
/// - Pairing is enforced: a `tool_use` whose result is missing (context
///   fitting can drop it) gets a placeholder result, and a result whose
///   `tool_use` is gone becomes plain text — either orphan is a 400.
/// - Empty text blocks are dropped (the API rejects them), and a turn left
///   with no blocks is dropped.
pub(crate) fn convert_messages(messages: &[Value]) -> (String, Vec<Value>) {
    let mut system_parts: Vec<String> = Vec::new();
    // (role, blocks)
    let mut turns: Vec<(String, Vec<Value>)> = Vec::new();

    fn push(turns: &mut Vec<(String, Vec<Value>)>, role: &str, blocks: Vec<Value>) {
        if blocks.is_empty() {
            return;
        }
        match turns.last_mut() {
            Some((r, b)) if r == role => b.extend(blocks),
            _ => turns.push((role.to_string(), blocks)),
        }
    }
    fn text_block(t: &str) -> Option<Value> {
        (!t.trim().is_empty()).then(|| json!({"type": "text", "text": t}))
    }

    for msg in messages {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
        match role {
            "system" => {
                let t = content_text(msg);
                if !t.trim().is_empty() {
                    system_parts.push(t);
                }
            }
            "assistant" => {
                let mut blocks: Vec<Value> = text_block(&content_text(msg)).into_iter().collect();
                if let Some(calls) = msg.get("tool_calls").and_then(|t| t.as_array()) {
                    for (i, tc) in calls.iter().enumerate() {
                        let func = tc.get("function").unwrap_or(tc);
                        let Some(name) = func.get("name").and_then(|n| n.as_str()).filter(|n| !n.is_empty()) else {
                            continue;
                        };
                        let id = tc
                            .get("id")
                            .and_then(|i| i.as_str())
                            .filter(|i| !i.is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("call_{i}"));
                        blocks.push(json!({
                            "type": "tool_use",
                            "id": id,
                            "name": name,
                            "input": arguments_object(func.get("arguments")),
                        }));
                    }
                }
                push(&mut turns, "assistant", blocks);
            }
            "tool" => {
                let content = content_text(msg);
                let id = msg.get("tool_call_id").and_then(|i| i.as_str()).unwrap_or("");
                let block = if id.is_empty() {
                    let name = msg.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
                    text_block(&format!("Tool result ({name}): {content}"))
                } else {
                    Some(json!({
                        "type": "tool_result",
                        "tool_use_id": id,
                        "content": if content.is_empty() { "(no output)".to_string() } else { content },
                    }))
                };
                push(&mut turns, "user", block.into_iter().collect());
            }
            _ => {
                push(&mut turns, "user", text_block(&content_text(msg)).into_iter().collect());
            }
        }
    }

    pair_tool_blocks(&mut turns);

    let out = turns
        .into_iter()
        .filter(|(_, b)| !b.is_empty())
        .map(|(role, blocks)| json!({"role": role, "content": blocks}))
        .collect();
    (system_parts.join("\n\n"), out)
}

/// Make every `tool_use` answered by a `tool_result` in the very next user
/// turn, and every `tool_result` answer a `tool_use` in the turn before it.
fn pair_tool_blocks(turns: &mut Vec<(String, Vec<Value>)>) {
    fn ids_of(blocks: &[Value], kind: &str, key: &str) -> Vec<String> {
        blocks
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some(kind))
            .filter_map(|b| b.get(key).and_then(|i| i.as_str()).map(str::to_string))
            .collect()
    }

    let mut i = 0;
    while i < turns.len() {
        if turns[i].0 == "user" {
            // Results must answer a tool_use in the preceding assistant turn.
            let asked: HashSet<String> = if i > 0 && turns[i - 1].0 == "assistant" {
                ids_of(&turns[i - 1].1, "tool_use", "id").into_iter().collect()
            } else {
                HashSet::new()
            };
            for b in turns[i].1.iter_mut() {
                if b.get("type").and_then(|t| t.as_str()) != Some("tool_result") {
                    continue;
                }
                let id = b.get("tool_use_id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                if !asked.contains(&id) {
                    let content = b.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();
                    *b = json!({"type": "text", "text": format!("Tool result ({id}): {content}")});
                }
            }
            // tool_result blocks lead the turn.
            turns[i].1.sort_by_key(|b| b.get("type").and_then(|t| t.as_str()) != Some("tool_result"));
        } else if turns[i].0 == "assistant" {
            let asked = ids_of(&turns[i].1, "tool_use", "id");
            if asked.is_empty() {
                i += 1;
                continue;
            }
            if i + 1 >= turns.len() || turns[i + 1].0 != "user" {
                turns.insert(i + 1, ("user".to_string(), Vec::new()));
            }
            let answered: HashSet<String> = ids_of(&turns[i + 1].1, "tool_result", "tool_use_id").into_iter().collect();
            let missing: Vec<Value> = asked
                .iter()
                .filter(|id| !answered.contains(*id))
                .map(|id| json!({"type": "tool_result", "tool_use_id": id, "content": "(result unavailable)"}))
                .collect();
            if !missing.is_empty() {
                let mut blocks = missing;
                blocks.append(&mut turns[i + 1].1);
                turns[i + 1].1 = blocks;
            }
        }
        i += 1;
    }
}

/// Anthropic `stop_reason` -> the OpenAI `finish_reason` the loop reads.
pub(crate) fn finish_reason(stop_reason: &str) -> &'static str {
    match stop_reason {
        "tool_use" => "tool_calls",
        "max_tokens" => "length",
        "refusal" => "content_filter",
        _ => "stop",
    }
}

/// A non-streaming Messages response -> the normalised assistant message
/// (`role`, `content`, optional OpenAI-shaped `tool_calls`).
pub(crate) fn parse_response(body: &Value) -> Value {
    let blocks = body.get("content").and_then(|c| c.as_array()).cloned().unwrap_or_default();
    let mut text = String::new();
    let mut calls = Vec::new();
    for b in &blocks {
        match b.get("type").and_then(|t| t.as_str()) {
            Some("text") => text.push_str(b.get("text").and_then(|t| t.as_str()).unwrap_or("")),
            Some("tool_use") => {
                let input = b.get("input").cloned().unwrap_or_else(|| json!({}));
                calls.push(json!({
                    "id": b.get("id").and_then(|i| i.as_str()).unwrap_or(""),
                    "type": "function",
                    "function": {
                        "name": b.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                        "arguments": input.to_string(),
                    },
                }));
            }
            _ => {}
        }
    }
    let mut msg = json!({"role": "assistant", "content": text});
    if !calls.is_empty() {
        msg["tool_calls"] = Value::Array(calls);
    }
    // `stop_reason` is not carried: the message goes into the session and
    // back onto every later wire, where an unknown field can be a 400. A
    // `tool_use` stop always comes with the tool_use blocks above.
    msg
}

/// Translates Anthropic's SSE events into OpenAI-style stream chunks.
///
/// Anthropic numbers content blocks (text and tool_use alike); the loop's
/// consumers index tool calls. The translator keeps the block -> tool-call
/// index map. Usage arrives in two halves — input tokens on
/// `message_start`, output tokens on `message_delta` — and each becomes a
/// chunk whose `usage` the consumers add up.
#[derive(Default)]
pub(crate) struct SseTranslator {
    tool_index_by_block: HashMap<u64, usize>,
    next_tool: usize,
    /// `message_start` reported input tokens. When it did not (a stream
    /// that only knows its usage at the end, like the harness's wire
    /// translator), `message_delta`'s `input_tokens` is the count; when it
    /// did, `message_delta`'s is the same number again and is not added.
    saw_input: bool,
}

impl SseTranslator {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// One parsed `data:` payload -> `Ok(Some(chunk))` to accumulate,
    /// `Ok(None)` for events with nothing to add (ping, block stop, ...),
    /// `Err(reason)` for the stream's own `error` event.
    pub(crate) fn translate(&mut self, event: &Value) -> Result<Option<Value>, String> {
        let delta_chunk = |delta: Value| json!({"choices": [{"index": 0, "delta": delta}]});
        match event.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "message_start" => {
                let u = event.pointer("/message/usage").cloned().unwrap_or_else(|| json!({}));
                let input = ["input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"]
                    .iter()
                    .filter_map(|k| u.get(*k).and_then(|v| v.as_u64()))
                    .sum::<u64>();
                self.saw_input = input > 0;
                Ok(Some(json!({
                    "choices": [],
                    "usage": {"prompt_tokens": input, "completion_tokens": 0, "total_tokens": input},
                })))
            }
            "content_block_start" => {
                let block = event.get("content_block").cloned().unwrap_or_else(|| json!({}));
                let index = event.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                match block.get("type").and_then(|t| t.as_str()) {
                    Some("tool_use") => {
                        let ti = self.next_tool;
                        self.next_tool += 1;
                        self.tool_index_by_block.insert(index, ti);
                        Ok(Some(delta_chunk(json!({"tool_calls": [{
                            "index": ti,
                            "id": block.get("id").and_then(|i| i.as_str()).unwrap_or(""),
                            "type": "function",
                            "function": {
                                "name": block.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                                "arguments": "",
                            },
                        }]}))))
                    }
                    Some("text") => {
                        let t = block.get("text").and_then(|t| t.as_str()).unwrap_or("");
                        Ok((!t.is_empty()).then(|| delta_chunk(json!({"content": t}))))
                    }
                    _ => Ok(None),
                }
            }
            "content_block_delta" => {
                let d = event.get("delta").cloned().unwrap_or_else(|| json!({}));
                let index = event.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                match d.get("type").and_then(|t| t.as_str()) {
                    Some("text_delta") => {
                        let t = d.get("text").and_then(|t| t.as_str()).unwrap_or("");
                        Ok((!t.is_empty()).then(|| delta_chunk(json!({"content": t}))))
                    }
                    Some("input_json_delta") => {
                        let Some(ti) = self.tool_index_by_block.get(&index).copied() else {
                            return Ok(None);
                        };
                        let part = d.get("partial_json").and_then(|p| p.as_str()).unwrap_or("");
                        Ok((!part.is_empty()).then(|| {
                            delta_chunk(json!({"tool_calls": [{"index": ti, "function": {"arguments": part}}]}))
                        }))
                    }
                    // thinking / signature deltas: no thinking is requested
                    // in this phase; nothing to surface.
                    _ => Ok(None),
                }
            }
            "message_delta" => {
                let mut chunk = Map::new();
                let mut choice = json!({"index": 0, "delta": {}});
                if let Some(sr) = event.pointer("/delta/stop_reason").and_then(|s| s.as_str()) {
                    choice["finish_reason"] = json!(finish_reason(sr));
                }
                chunk.insert("choices".into(), json!([choice]));
                if let Some(out) = event.pointer("/usage/output_tokens").and_then(|v| v.as_u64()) {
                    let input = if self.saw_input {
                        0
                    } else {
                        event.pointer("/usage/input_tokens").and_then(|v| v.as_u64()).unwrap_or(0)
                    };
                    chunk.insert(
                        "usage".into(),
                        json!({"prompt_tokens": input, "completion_tokens": out, "total_tokens": input + out}),
                    );
                }
                Ok(Some(Value::Object(chunk)))
            }
            "error" => {
                let kind = event.pointer("/error/type").and_then(|t| t.as_str()).unwrap_or("error");
                let msg = event.pointer("/error/message").and_then(|m| m.as_str()).unwrap_or("stream error");
                Err(format!("Anthropic stream error ({kind}): {msg}"))
            }
            _ => Ok(None),
        }
    }
}

/// Usage from either wire's non-streaming body: OpenAI's
/// `prompt_tokens/completion_tokens/total_tokens` or Anthropic's
/// `input_tokens/output_tokens`. (prompt, completion, total).
pub(crate) fn usage_tokens(u: &Value) -> (u64, u64, u64) {
    let get = |k: &str| u.get(k).and_then(|v| v.as_u64());
    let prompt = get("prompt_tokens").or_else(|| get("input_tokens")).unwrap_or(0);
    let completion = get("completion_tokens").or_else(|| get("output_tokens")).unwrap_or(0);
    let total = get("total_tokens").unwrap_or(prompt + completion);
    (prompt, completion, total)
}

// ═══════════════════════════════════════════════════════════════
// The reverse direction (i83 E1b): Anthropic in, OpenAI to the backend
// ═══════════════════════════════════════════════════════════════
//
// The node harness's wire translator serves `/v1/messages` to a foreign
// CLI (Claude Code) in front of a backend that speaks OpenAI chat. The
// three items below are the inverse of the three above:
//
// - [`request_body_from_anthropic`]: a `/v1/messages` body -> an OpenAI
//   chat-completions body (system -> leading system message, `tool_use`
//   -> `tool_calls`, `tool_result` -> `role:"tool"` messages).
// - [`response_to_anthropic`]: an OpenAI assistant message + finish reason
//   + usage -> a Messages response body.
// - [`OpenAiToAnthropicSse`]: OpenAI SSE chunks -> the Anthropic event
//   sequence (`message_start`, `content_block_*`, `message_delta`,
//   `message_stop`).

/// The text of an Anthropic `content` (a string, or the `text` of its
/// text blocks) — for `system` and `tool_result` content.
fn anthropic_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()).unwrap_or("text") == "text")
            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// An Anthropic image block -> an OpenAI `image_url` content part.
fn image_part(block: &Value) -> Option<Value> {
    let src = block.get("source")?;
    let url = match src.get("type").and_then(|t| t.as_str()) {
        Some("base64") => format!(
            "data:{};base64,{}",
            src.get("media_type").and_then(|m| m.as_str()).unwrap_or("image/png"),
            src.get("data").and_then(|d| d.as_str())?
        ),
        Some("url") => src.get("url").and_then(|u| u.as_str())?.to_string(),
        _ => return None,
    };
    Some(json!({"type": "image_url", "image_url": {"url": url}}))
}

/// Anthropic `tool_choice` -> OpenAI `tool_choice`.
fn tool_choice_to_openai(tc: &Value) -> Option<Value> {
    match tc.get("type").and_then(|t| t.as_str())? {
        "auto" => Some(json!("auto")),
        "any" => Some(json!("required")),
        "none" => Some(json!("none")),
        "tool" => {
            let name = tc.get("name").and_then(|n| n.as_str())?;
            Some(json!({"type": "function", "function": {"name": name}}))
        }
        _ => None,
    }
}

/// A `/v1/messages` request body -> an OpenAI chat-completions body.
///
/// - `system` (string or text blocks) becomes the leading system message.
/// - A user turn's `tool_result` blocks become `role:"tool"` messages,
///   emitted BEFORE the turn's own text: OpenAI wants the results right
///   after the assistant message that asked for them.
/// - An assistant turn's `tool_use` blocks become `tool_calls` (input
///   serialised as the `arguments` string); `thinking` blocks are dropped
///   (they carry a signature only Anthropic can check).
/// - `tools` become function schemas; a tool with no `input_schema` (an
///   Anthropic server tool) has no OpenAI equivalent and is dropped.
/// - `max_tokens`, `temperature`, `top_p`, `stop_sequences`, `stream` and
///   `tool_choice` carry over; `metadata`, `thinking` and the rest do not.
pub(crate) fn request_body_from_anthropic(body: &Value) -> Value {
    let mut messages: Vec<Value> = Vec::new();
    let system = anthropic_text(body.get("system"));
    if !system.trim().is_empty() {
        messages.push(json!({"role": "system", "content": system}));
    }
    for m in body.get("messages").and_then(|m| m.as_array()).map(Vec::as_slice).unwrap_or(&[]) {
        let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("user");
        let blocks: Vec<Value> = match m.get("content") {
            Some(Value::String(s)) => vec![json!({"type": "text", "text": s})],
            Some(Value::Array(b)) => b.clone(),
            _ => Vec::new(),
        };
        if role == "assistant" {
            let mut text = String::new();
            let mut calls = Vec::new();
            for b in &blocks {
                match b.get("type").and_then(|t| t.as_str()) {
                    Some("text") => text.push_str(b.get("text").and_then(|t| t.as_str()).unwrap_or("")),
                    Some("tool_use") => calls.push(json!({
                        "id": b.get("id").and_then(|i| i.as_str()).unwrap_or(""),
                        "type": "function",
                        "function": {
                            "name": b.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                            "arguments": b.get("input").cloned().unwrap_or_else(|| json!({})).to_string(),
                        },
                    })),
                    _ => {}
                }
            }
            let mut msg = json!({"role": "assistant", "content": text});
            if !calls.is_empty() {
                msg["tool_calls"] = Value::Array(calls);
            }
            messages.push(msg);
            continue;
        }
        // A user turn: tool results first, then whatever the person said.
        let mut parts: Vec<Value> = Vec::new();
        for b in &blocks {
            match b.get("type").and_then(|t| t.as_str()) {
                Some("tool_result") => {
                    let mut content = anthropic_text(b.get("content"));
                    if b.get("is_error").and_then(|e| e.as_bool()) == Some(true) {
                        content = format!("Error: {content}");
                    }
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": b.get("tool_use_id").and_then(|i| i.as_str()).unwrap_or(""),
                        "content": content,
                    }));
                }
                Some("text") => {
                    let t = b.get("text").and_then(|t| t.as_str()).unwrap_or("");
                    if !t.is_empty() {
                        parts.push(json!({"type": "text", "text": t}));
                    }
                }
                Some("image") => parts.extend(image_part(b)),
                _ => {}
            }
        }
        if parts.is_empty() {
            continue;
        }
        let content = if parts.iter().all(|p| p.get("type").and_then(|t| t.as_str()) == Some("text")) {
            Value::String(
                parts.iter().filter_map(|p| p.get("text").and_then(|t| t.as_str())).collect::<Vec<_>>().join("\n"),
            )
        } else {
            Value::Array(parts)
        };
        messages.push(json!({"role": "user", "content": content}));
    }

    let mut out = json!({
        "model": body.get("model").cloned().unwrap_or(Value::Null),
        "messages": messages,
        "stream": body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false),
    });
    for (from, to) in [("max_tokens", "max_tokens"), ("temperature", "temperature"), ("top_p", "top_p"), ("stop_sequences", "stop")] {
        if let Some(v) = body.get(from).filter(|v| !v.is_null()) {
            out[to] = v.clone();
        }
    }
    let tools: Vec<Value> = body
        .get("tools")
        .and_then(|t| t.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .filter_map(|t| {
            let name = t.get("name").and_then(|n| n.as_str()).filter(|n| !n.is_empty())?;
            let schema = t.get("input_schema").filter(|s| s.is_object())?;
            Some(json!({"type": "function", "function": {
                "name": name,
                "description": t.get("description").and_then(|d| d.as_str()).unwrap_or(""),
                "parameters": schema,
            }}))
        })
        .collect();
    if !tools.is_empty() {
        out["tools"] = Value::Array(tools);
        if let Some(tc) = body.get("tool_choice").and_then(tool_choice_to_openai) {
            out["tool_choice"] = tc;
        }
    }
    out
}

/// OpenAI `finish_reason` -> Anthropic `stop_reason`. A turn that produced
/// tool calls is `tool_use` whatever the backend said (Ollama reports
/// `stop` on a tool-call turn).
pub(crate) fn stop_reason(finish_reason: Option<&str>, had_tool_calls: bool) -> &'static str {
    if had_tool_calls {
        return "tool_use";
    }
    match finish_reason {
        Some("tool_calls") | Some("function_call") => "tool_use",
        Some("length") => "max_tokens",
        Some("content_filter") => "refusal",
        _ => "end_turn",
    }
}

/// A fresh Anthropic-shaped message id.
fn message_id() -> String {
    format!("msg_{}", uuid::Uuid::new_v4().simple())
}

/// An OpenAI assistant message (`choices[0].message`), its finish reason
/// and the reply's usage (prompt, completion) -> a `/v1/messages` response.
pub(crate) fn response_to_anthropic(message: &Value, finish_reason: Option<&str>, usage: (u64, u64), model: &str) -> Value {
    let mut content: Vec<Value> = Vec::new();
    let text = content_text(message);
    if !text.is_empty() {
        content.push(json!({"type": "text", "text": text}));
    }
    let calls = message.get("tool_calls").and_then(|t| t.as_array()).cloned().unwrap_or_default();
    for (i, tc) in calls.iter().enumerate() {
        let func = tc.get("function").unwrap_or(tc);
        let id = tc
            .get("id")
            .and_then(|i| i.as_str())
            .filter(|i| !i.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("toolu_{i}"));
        content.push(json!({
            "type": "tool_use",
            "id": id,
            "name": func.get("name").and_then(|n| n.as_str()).unwrap_or(""),
            "input": arguments_object(func.get("arguments")),
        }));
    }
    json!({
        "id": message_id(),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason(finish_reason, !calls.is_empty()),
        "stop_sequence": null,
        "usage": {"input_tokens": usage.0, "output_tokens": usage.1},
    })
}

/// Which content block is open in an [`OpenAiToAnthropicSse`] stream.
#[derive(Clone, Copy, PartialEq)]
enum OpenBlock {
    Text(u64),
    Tool(u64),
}

/// Translates OpenAI chat-completion chunks into Anthropic SSE events —
/// the inverse of [`SseTranslator`].
///
/// OpenAI streams text and tool-call deltas against one message and puts
/// usage on a trailing chunk; Anthropic numbers content blocks, opens and
/// closes each one, and puts the stop reason and usage on `message_delta`.
/// Feed every chunk to [`on_chunk`](Self::on_chunk) and call
/// [`finish`](Self::finish) once at the end; each returns the events to
/// write, as `(event name, data)`.
pub(crate) struct OpenAiToAnthropicSse {
    model: String,
    started: bool,
    open: Option<OpenBlock>,
    next_block: u64,
    /// OpenAI tool-call index -> Anthropic block index.
    tool_blocks: HashMap<u64, u64>,
    finish_reason: Option<String>,
    usage: (u64, u64),
}

impl OpenAiToAnthropicSse {
    pub(crate) fn new(model: &str) -> Self {
        Self {
            model: model.to_string(),
            started: false,
            open: None,
            next_block: 0,
            tool_blocks: HashMap::new(),
            finish_reason: None,
            usage: (0, 0),
        }
    }

    fn start(&mut self, out: &mut Vec<(String, Value)>) {
        if self.started {
            return;
        }
        self.started = true;
        out.push((
            "message_start".into(),
            json!({"type": "message_start", "message": {
                "id": message_id(),
                "type": "message",
                "role": "assistant",
                "model": self.model,
                "content": [],
                "stop_reason": null,
                "stop_sequence": null,
                // OpenAI reports usage only at the end; message_delta
                // carries the real counts, input tokens included.
                "usage": {"input_tokens": 0, "output_tokens": 0},
            }}),
        ));
    }

    fn close(&mut self, out: &mut Vec<(String, Value)>) {
        if let Some(OpenBlock::Text(i) | OpenBlock::Tool(i)) = self.open.take() {
            out.push(("content_block_stop".into(), json!({"type": "content_block_stop", "index": i})));
        }
    }

    /// One OpenAI chunk -> the Anthropic events it implies.
    pub(crate) fn on_chunk(&mut self, chunk: &Value) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        self.start(&mut out);
        if let Some(u) = chunk.get("usage").filter(|u| u.is_object()) {
            let (p, c, _) = usage_tokens(u);
            self.usage = (p, c);
        }
        let Some(choice) = chunk.get("choices").and_then(|c| c.get(0)) else {
            return out;
        };
        let delta = choice.get("delta").cloned().unwrap_or_else(|| json!({}));
        if let Some(t) = delta.get("content").and_then(|c| c.as_str()).filter(|t| !t.is_empty()) {
            let index = match self.open {
                Some(OpenBlock::Text(i)) => i,
                _ => {
                    self.close(&mut out);
                    let i = self.next_block;
                    self.next_block += 1;
                    self.open = Some(OpenBlock::Text(i));
                    out.push((
                        "content_block_start".into(),
                        json!({"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}}),
                    ));
                    i
                }
            };
            out.push((
                "content_block_delta".into(),
                json!({"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": t}}),
            ));
        }
        for tc in delta.get("tool_calls").and_then(|t| t.as_array()).map(Vec::as_slice).unwrap_or(&[]) {
            let ti = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
            let func = tc.get("function").cloned().unwrap_or_else(|| json!({}));
            let block = match self.tool_blocks.get(&ti).copied() {
                Some(b) => b,
                None => {
                    self.close(&mut out);
                    let b = self.next_block;
                    self.next_block += 1;
                    self.tool_blocks.insert(ti, b);
                    self.open = Some(OpenBlock::Tool(b));
                    let id = tc
                        .get("id")
                        .and_then(|i| i.as_str())
                        .filter(|i| !i.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("toolu_{ti}"));
                    out.push((
                        "content_block_start".into(),
                        json!({"type": "content_block_start", "index": b, "content_block": {
                            "type": "tool_use",
                            "id": id,
                            "name": func.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                            "input": {},
                        }}),
                    ));
                    b
                }
            };
            // Arguments arrive as a JSON string in fragments, or (Ollama,
            // converted upstream) whole; either way they are partial JSON.
            let part = match func.get("arguments") {
                Some(Value::String(s)) => s.clone(),
                Some(v @ Value::Object(_)) => v.to_string(),
                _ => String::new(),
            };
            if !part.is_empty() {
                out.push((
                    "content_block_delta".into(),
                    json!({"type": "content_block_delta", "index": block, "delta": {"type": "input_json_delta", "partial_json": part}}),
                ));
            }
        }
        if let Some(fr) = choice.get("finish_reason").and_then(|f| f.as_str()) {
            self.finish_reason = Some(fr.to_string());
        }
        out
    }

    /// The closing events: the open block's stop, `message_delta` with the
    /// stop reason and usage, `message_stop`.
    pub(crate) fn finish(&mut self) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        self.start(&mut out);
        self.close(&mut out);
        let sr = stop_reason(self.finish_reason.as_deref(), !self.tool_blocks.is_empty());
        out.push((
            "message_delta".into(),
            json!({"type": "message_delta",
                   "delta": {"stop_reason": sr, "stop_sequence": null},
                   "usage": {"input_tokens": self.usage.0, "output_tokens": self.usage.1}}),
        ));
        out.push(("message_stop".into(), json!({"type": "message_stop"})));
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn tools() -> Vec<Value> {
        vec![json!({"type": "function", "function": {
            "name": "web_search",
            "description": "search the web",
            "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        }})]
    }

    #[test]
    fn system_is_hoisted_and_tools_become_input_schemas() {
        let messages = vec![
            json!({"role": "system", "content": "You are noo."}),
            json!({"role": "user", "content": "hi"}),
        ];
        let body = request_body("claude-x", &messages, Some(&tools()), false, 4096);
        assert_eq!(body["system"], "You are noo.");
        assert_eq!(body["max_tokens"], 4096);
        assert_eq!(body["stream"], false);
        assert_eq!(body["messages"].as_array().unwrap().len(), 1, "no system message in messages");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"][0], json!({"type": "text", "text": "hi"}));
        let t = &body["tools"][0];
        assert_eq!(t["name"], "web_search");
        assert_eq!(t["description"], "search the web");
        assert_eq!(t["input_schema"]["required"][0], "query");
        assert!(t.get("function").is_none() && t.get("type").is_none());
        // No tools, no field.
        let bare = request_body("claude-x", &messages, Some(&[]), true, 10);
        assert!(bare.get("tools").is_none());
        assert_eq!(bare["stream"], true);
    }

    #[test]
    fn tool_calls_become_tool_use_and_consecutive_results_merge_into_one_user_turn() {
        let messages = vec![
            json!({"role": "system", "content": "sys"}),
            json!({"role": "user", "content": "weather in rome and paris?"}),
            json!({"role": "assistant", "content": "Checking.", "tool_calls": [
                {"id": "toolu_1", "type": "function", "function": {"name": "web_search", "arguments": "{\"query\":\"rome\"}"}},
                {"id": "toolu_2", "type": "function", "function": {"name": "web_search", "arguments": "{\"query\":\"paris\"}"}},
            ]}),
            json!({"role": "tool", "name": "web_search", "content": "sunny", "tool_call_id": "toolu_1"}),
            json!({"role": "tool", "name": "web_search", "content": "rain", "tool_call_id": "toolu_2"}),
            json!({"role": "user", "content": "[harness] write the answer"}),
        ];
        let (system, out) = convert_messages(&messages);
        assert_eq!(system, "sys");
        assert_eq!(out.len(), 3, "user / assistant / one merged user turn: {out:#?}");
        let a = &out[1];
        assert_eq!(a["role"], "assistant");
        assert_eq!(a["content"][0], json!({"type": "text", "text": "Checking."}));
        assert_eq!(a["content"][1], json!({"type": "tool_use", "id": "toolu_1", "name": "web_search", "input": {"query": "rome"}}));
        assert_eq!(a["content"][2]["input"], json!({"query": "paris"}));
        let u = &out[2];
        assert_eq!(u["role"], "user");
        assert_eq!(u["content"][0], json!({"type": "tool_result", "tool_use_id": "toolu_1", "content": "sunny"}));
        assert_eq!(u["content"][1], json!({"type": "tool_result", "tool_use_id": "toolu_2", "content": "rain"}));
        assert_eq!(u["content"][2]["type"], "text", "the nudge rides after the results");
    }

    #[test]
    fn orphaned_tool_blocks_are_repaired_not_sent() {
        // A result whose tool_use was trimmed away, and a tool_use whose
        // result is missing: both are 400s on the real API.
        let messages = vec![
            json!({"role": "tool", "name": "x", "content": "old", "tool_call_id": "gone"}),
            json!({"role": "user", "content": "go"}),
            json!({"role": "assistant", "content": "", "tool_calls": [
                {"id": "t9", "type": "function", "function": {"name": "x", "arguments": ""}},
            ]}),
        ];
        let (_, out) = convert_messages(&messages);
        assert_eq!(out[0]["role"], "user");
        assert_eq!(out[0]["content"][0]["type"], "text", "orphan result became text: {out:#?}");
        assert_eq!(out[1]["content"][0]["input"], json!({}), "empty arguments become an empty object");
        assert_eq!(out[1]["content"].as_array().unwrap().len(), 1, "empty text dropped");
        assert_eq!(out[2]["role"], "user");
        assert_eq!(out[2]["content"][0]["tool_use_id"], "t9");
    }

    #[test]
    fn a_response_with_text_and_tool_use_normalises_to_the_openai_message() {
        let body = json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
            "content": [
                {"type": "text", "text": "Let me look."},
                {"type": "tool_use", "id": "toolu_9", "name": "web_search", "input": {"query": "noo"}},
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 120, "output_tokens": 30},
        });
        let msg = parse_response(&body);
        assert_eq!(msg["role"], "assistant");
        assert_eq!(msg["content"], "Let me look.");
        assert_eq!(finish_reason(body["stop_reason"].as_str().unwrap()), "tool_calls");
        assert!(msg.get("finish_reason").is_none(), "only session-safe fields");
        let tc = &msg["tool_calls"][0];
        assert_eq!(tc["id"], "toolu_9");
        assert_eq!(tc["type"], "function");
        assert_eq!(tc["function"]["name"], "web_search");
        let args: Value = serde_json::from_str(tc["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args, json!({"query": "noo"}));
        assert_eq!(usage_tokens(&body["usage"]), (120, 30, 150));
        assert_eq!(usage_tokens(&json!({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3})), (1, 2, 3));
        let plain = parse_response(&json!({"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"}));
        assert!(plain.get("tool_calls").is_none());
        assert_eq!(finish_reason("end_turn"), "stop");
        assert_eq!(finish_reason("max_tokens"), "length");
    }

    /// The real event order of a streamed text + tool_use turn.
    pub(crate) const CANNED_SSE: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":50,\"output_tokens\":1}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: ping\n",
        "data: {\"type\":\"ping\"}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Let me \"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"check.\"}}\n\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_7\",\"name\":\"web_search\",\"input\":{}}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"query\\\": \"}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"noo\\\"}\"}}\n\n",
        "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":42}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    #[test]
    fn sse_events_translate_to_openai_chunks() {
        let mut t = SseTranslator::new();
        let chunks: Vec<Value> = CANNED_SSE
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| t.translate(&serde_json::from_str(d).unwrap()).unwrap())
            .collect();
        // usage(in), "Let me ", "check.", tool start, 2 arg parts, message_delta
        assert_eq!(chunks.len(), 7, "{chunks:#?}");
        assert_eq!(chunks[0]["usage"]["prompt_tokens"], 50);
        assert_eq!(chunks[1]["choices"][0]["delta"]["content"], "Let me ");
        let start = &chunks[3]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(start["index"], 0, "the first tool call is index 0 though it is block 1");
        assert_eq!(start["id"], "toolu_7");
        assert_eq!(start["function"]["name"], "web_search");
        assert_eq!(chunks[4]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"], "{\"query\": ");
        assert_eq!(chunks[6]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(chunks[6]["usage"]["completion_tokens"], 42);
        // The real API repeats input_tokens on message_delta: not added twice.
        let mut t2 = SseTranslator::new();
        t2.translate(&json!({"type": "message_start", "message": {"usage": {"input_tokens": 50}}})).unwrap();
        let d = t2.translate(&json!({"type": "message_delta", "delta": {}, "usage": {"input_tokens": 50, "output_tokens": 3}})).unwrap().unwrap();
        assert_eq!(d["usage"]["prompt_tokens"], 0);
        // The stream's own error event is an error, not silence.
        let e = t.translate(&json!({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}));
        assert!(e.unwrap_err().contains("Overloaded"));
    }

    // ── the reverse direction (E1b) ──────────────────────────

    #[test]
    fn an_anthropic_request_becomes_an_openai_body_with_tool_results_first() {
        let body = json!({
            "model": "claude-sonnet-x",
            "max_tokens": 1024,
            "system": [{"type": "text", "text": "Be brief."}],
            "stop_sequences": ["END"],
            "tool_choice": {"type": "any"},
            "tools": [
                {"name": "read_file", "description": "read", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}},
                {"type": "web_search_20250305", "name": "web_search"},
            ],
            "messages": [
                {"role": "user", "content": "open a.txt"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "hm", "signature": "sig"},
                    {"type": "text", "text": "Reading."},
                    {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"path": "a.txt"}},
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "hello"}]},
                    {"type": "text", "text": "now summarise"},
                ]},
            ],
            "stream": true,
        });
        let out = request_body_from_anthropic(&body);
        assert_eq!(out["model"], "claude-sonnet-x");
        assert_eq!(out["max_tokens"], 1024);
        assert_eq!(out["stop"], json!(["END"]));
        assert_eq!(out["stream"], true);
        assert_eq!(out["tool_choice"], "required");
        assert_eq!(out["tools"].as_array().unwrap().len(), 1, "the server tool has no OpenAI form");
        assert_eq!(out["tools"][0]["function"]["parameters"]["properties"]["path"]["type"], "string");
        let m = out["messages"].as_array().unwrap();
        assert_eq!(m.len(), 5, "{m:#?}");
        assert_eq!(m[0], json!({"role": "system", "content": "Be brief."}));
        assert_eq!(m[1], json!({"role": "user", "content": "open a.txt"}));
        assert_eq!(m[2]["content"], "Reading.", "thinking dropped");
        let tc = &m[2]["tool_calls"][0];
        assert_eq!((tc["id"].as_str(), tc["function"]["name"].as_str()), (Some("toolu_1"), Some("read_file")));
        let args: Value = serde_json::from_str(tc["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args, json!({"path": "a.txt"}));
        assert_eq!(m[3], json!({"role": "tool", "tool_call_id": "toolu_1", "content": "hello"}));
        assert_eq!(m[4], json!({"role": "user", "content": "now summarise"}));
    }

    #[test]
    fn an_openai_message_becomes_an_anthropic_response() {
        let msg = json!({"role": "assistant", "content": "Let me look.", "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"b\"}"}},
        ]});
        let r = response_to_anthropic(&msg, Some("stop"), (12, 4), "qwen");
        assert_eq!(r["type"], "message");
        assert_eq!(r["role"], "assistant");
        assert_eq!(r["model"], "qwen");
        assert!(r["id"].as_str().unwrap().starts_with("msg_"));
        assert_eq!(r["content"][0], json!({"type": "text", "text": "Let me look."}));
        assert_eq!(r["content"][1], json!({"type": "tool_use", "id": "call_1", "name": "read_file", "input": {"path": "b"}}));
        assert_eq!(r["stop_reason"], "tool_use", "tool calls win over the backend's `stop`");
        assert_eq!(r["usage"], json!({"input_tokens": 12, "output_tokens": 4}));
        let plain = response_to_anthropic(&json!({"role": "assistant", "content": "done"}), Some("length"), (1, 1), "m");
        assert_eq!(plain["stop_reason"], "max_tokens");
        assert_eq!(plain["content"].as_array().unwrap().len(), 1);
    }

    /// Round trip: the Anthropic events this produces, fed back through the
    /// phase-C `SseTranslator`, give the same text, tool call and usage.
    #[test]
    fn openai_chunks_become_a_valid_anthropic_event_sequence() {
        let chunks = [
            json!({"choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}]}),
            json!({"choices": [{"index": 0, "delta": {"content": "Let me "}}]}),
            json!({"choices": [{"index": 0, "delta": {"content": "check."}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_9", "type": "function", "function": {"name": "web_search", "arguments": ""}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"query\":"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "\"noo\"}"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
            json!({"choices": [], "usage": {"prompt_tokens": 50, "completion_tokens": 42, "total_tokens": 92}}),
        ];
        let mut t = OpenAiToAnthropicSse::new("qwen");
        let mut events: Vec<(String, Value)> = chunks.iter().flat_map(|c| t.on_chunk(c)).collect();
        events.extend(t.finish());
        let names: Vec<&str> = events.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "message_start",
                "content_block_start", "content_block_delta", "content_block_delta", "content_block_stop",
                "content_block_start", "content_block_delta", "content_block_delta", "content_block_stop",
                "message_delta", "message_stop",
            ],
        );
        for (name, data) in &events {
            assert_eq!(data["type"], name.as_str(), "the event name is the data's type");
        }
        assert_eq!(events[5].1["index"], 1, "the tool block follows the text block");
        assert_eq!(events[5].1["content_block"]["id"], "call_9");
        assert_eq!(events[9].1["delta"]["stop_reason"], "tool_use");
        assert_eq!(events[9].1["usage"], json!({"input_tokens": 50, "output_tokens": 42}));

        // Back through phase C's translator: the loop would see the same turn.
        let mut back = SseTranslator::new();
        let mut text = String::new();
        let mut args = String::new();
        let mut usage = (0, 0);
        for (_, data) in &events {
            if let Some(c) = back.translate(data).unwrap() {
                if let Some(s) = c.pointer("/choices/0/delta/content").and_then(|s| s.as_str()) {
                    text.push_str(s);
                }
                if let Some(a) = c.pointer("/choices/0/delta/tool_calls/0/function/arguments").and_then(|s| s.as_str()) {
                    args.push_str(a);
                }
                if let Some(u) = c.get("usage") {
                    let (p, o, _) = usage_tokens(u);
                    usage = (usage.0 + p, usage.1 + o);
                }
            }
        }
        assert_eq!(text, "Let me check.");
        assert_eq!(serde_json::from_str::<Value>(&args).unwrap(), json!({"query": "noo"}));
        assert_eq!(usage, (50, 42));

        // An empty stream still opens and closes a message.
        let mut empty = OpenAiToAnthropicSse::new("m");
        let names: Vec<String> = empty.finish().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["message_start", "message_delta", "message_stop"]);
    }
}
