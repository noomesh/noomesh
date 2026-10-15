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
                    chunk.insert(
                        "usage".into(),
                        json!({"prompt_tokens": 0, "completion_tokens": out, "total_tokens": out}),
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
        // The stream's own error event is an error, not silence.
        let e = t.translate(&json!({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}));
        assert!(e.unwrap_err().contains("Overloaded"));
    }
}
