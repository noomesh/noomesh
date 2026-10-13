// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Reassemble an OpenAI chat-completions SSE stream into the single
//! `chat.completion` object a non-streaming caller expects.
//!
//! Why this exists: a non-streaming request cannot be told apart from a
//! wedged engine while it waits, because its response headers arrive only
//! with the whole completion. The raw chat path therefore asks the backend
//! to STREAM even when the caller did not, requires the first chunk within a
//! short window and each following chunk within an idle window, and folds
//! the frames back into one body with this module. A long answer that keeps
//! producing tokens is never cut; an engine that accepts the connection and
//! then says nothing is detected in seconds, not at the caller's timeout.
//!
//! The output carries what the existing callers read: `choices[0].message`
//! (`content`, `reasoning_content` when the engine sent reasoning,
//! `tool_calls` merged by index), `choices[0].finish_reason` and `usage`.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{json, Map, Value};

/// Folds SSE bytes into one completion. Feed it with [`push`](Self::push),
/// then take the object with [`finish`](Self::finish).
#[derive(Default)]
pub struct ChatAggregator {
    /// Bytes of the current, not yet newline-terminated line. Kept as bytes so
    /// a multi-byte character split across two network chunks survives.
    line: Vec<u8>,
    id: Option<String>,
    model: Option<String>,
    created: Option<u64>,
    content: String,
    reasoning: String,
    /// The key the engine used for reasoning (`reasoning_content` or `reasoning`).
    reasoning_key: Option<&'static str>,
    tool_calls: BTreeMap<u64, ToolAcc>,
    finish_reason: Option<String>,
    usage: Option<Value>,
    frames: usize,
    done: bool,
    error: Option<String>,
}

#[derive(Default)]
struct ToolAcc {
    id: String,
    kind: String,
    name: String,
    arguments: String,
}

impl ChatAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume the next network chunk.
    pub fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                let line = std::mem::take(&mut self.line);
                self.line_in(&line);
            } else {
                self.line.push(b);
            }
        }
    }

    fn line_in(&mut self, raw: &[u8]) {
        let text = String::from_utf8_lossy(raw);
        let line = text.trim_end_matches('\r').trim();
        let Some(data) = line.strip_prefix("data:") else { return };
        let data = data.trim();
        if data == "[DONE]" {
            self.done = true;
            return;
        }
        let Ok(frame) = serde_json::from_str::<Value>(data) else { return };
        self.frame_in(&frame);
    }

    fn frame_in(&mut self, f: &Value) {
        // A backend that fails mid-stream sends `{"error": {...}}` as a frame.
        if let Some(err) = f.get("error").filter(|e| !e.is_null()) {
            let msg = err.get("message").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| err.to_string());
            self.error = Some(msg);
            return;
        }
        self.frames += 1;
        if self.id.is_none() {
            self.id = f.get("id").and_then(Value::as_str).map(str::to_string);
        }
        if self.model.is_none() {
            self.model = f.get("model").and_then(Value::as_str).map(str::to_string);
        }
        if self.created.is_none() {
            self.created = f.get("created").and_then(Value::as_u64);
        }
        if let Some(u) = f.get("usage").filter(|u| u.is_object()) {
            self.usage = Some(u.clone());
        }
        // Only the first choice is folded; the caller never sends `n > 1`
        // through here (see `raw_chat::can_aggregate`).
        let Some(choice) = f.get("choices").and_then(|c| c.get(0)) else { return };
        if let Some(fr) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish_reason = Some(fr.to_string());
        }
        let Some(delta) = choice.get("delta") else { return };
        if let Some(t) = delta.get("content").and_then(Value::as_str) {
            self.content.push_str(t);
        }
        for key in ["reasoning_content", "reasoning"] {
            if let Some(t) = delta.get(key).and_then(Value::as_str) {
                if self.reasoning_key.is_none() && !t.is_empty() {
                    self.reasoning_key = Some(if key == "reasoning" { "reasoning" } else { "reasoning_content" });
                }
                self.reasoning.push_str(t);
            }
        }
        if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for (pos, c) in calls.iter().enumerate() {
                let idx = c.get("index").and_then(Value::as_u64).unwrap_or(pos as u64);
                let acc = self.tool_calls.entry(idx).or_default();
                if let Some(id) = c.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    acc.id = id.to_string();
                }
                if let Some(k) = c.get("type").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    acc.kind = k.to_string();
                }
                if let Some(f) = c.get("function") {
                    // The name arrives whole in the first chunk; a repeat must not double it.
                    if let Some(n) = f.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                        if acc.name.is_empty() {
                            acc.name = n.to_string();
                        }
                    }
                    if let Some(a) = f.get("arguments").and_then(Value::as_str) {
                        acc.arguments.push_str(a);
                    }
                }
            }
        }
    }

    /// Parse a final line that arrived without its newline.
    pub fn flush(&mut self) {
        if !self.line.is_empty() {
            let rest = std::mem::take(&mut self.line);
            self.line_in(&rest);
        }
    }

    /// The stream ended the way a stream ends: `[DONE]` or a finish reason.
    pub fn complete(&self) -> bool {
        self.error.is_none() && (self.done || self.finish_reason.is_some())
    }

    /// The backend's own error frame, if it sent one.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Frames parsed so far (a stream with none produced nothing).
    pub fn frames(&self) -> usize {
        self.frames
    }

    /// True once `[DONE]` was read: nothing further is worth waiting for.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// The whole completion, in the non-streaming shape.
    pub fn finish(mut self) -> Value {
        self.flush();
        let mut message = Map::new();
        message.insert("role".into(), json!("assistant"));
        let calls: Vec<Value> = self
            .tool_calls
            .into_values()
            .map(|t| {
                json!({
                    "id": t.id,
                    "type": if t.kind.is_empty() { "function".to_string() } else { t.kind },
                    "function": {"name": t.name, "arguments": t.arguments},
                })
            })
            .collect();
        if calls.is_empty() {
            message.insert("content".into(), json!(self.content));
        } else {
            message.insert("content".into(), if self.content.is_empty() { Value::Null } else { json!(self.content) });
            message.insert("tool_calls".into(), Value::Array(calls));
        }
        if !self.reasoning.is_empty() {
            message.insert(self.reasoning_key.unwrap_or("reasoning_content").into(), json!(self.reasoning));
        }
        let mut out = json!({
            "id": self.id.unwrap_or_default(),
            "object": "chat.completion",
            "created": self.created.unwrap_or(0),
            "model": self.model.unwrap_or_default(),
            "choices": [{
                "index": 0,
                "message": Value::Object(message),
                "finish_reason": self.finish_reason.unwrap_or_else(|| "stop".into()),
            }],
        });
        if let Some(u) = self.usage {
            out["usage"] = u;
        }
        out
    }
}

/// Why a streamed read did not produce a completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadFailure {
    /// No chunk arrived within the first-token window.
    NoFirstChunk,
    /// Tokens flowed, then nothing for the idle window.
    Idle,
    /// The request's overall deadline ran out first.
    Deadline,
    /// The connection broke mid-stream.
    Transport(String),
    /// The stream ended without `[DONE]` or a finish reason.
    Truncated,
    /// The backend sent an error frame.
    Backend(String),
}

/// Read a streamed chat answer to the end and fold it. `first_wait` is how
/// long the first chunk may take (the part of the first-token window the
/// request has not already used); `idle` bounds the gap between later chunks;
/// `overall` is the request's hard deadline.
pub async fn read_aggregated(
    resp: reqwest::Response,
    first_wait: Duration,
    idle: Duration,
    overall: std::time::Instant,
) -> Result<Value, ReadFailure> {
    use futures::StreamExt as _;
    let mut stream = resp.bytes_stream();
    let mut agg = ChatAggregator::new();
    let mut got_any = false;
    loop {
        let limit = if got_any { idle } else { first_wait };
        let remaining = overall.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(ReadFailure::Deadline);
        }
        match tokio::time::timeout(limit.min(remaining), stream.next()).await {
            Err(_) if remaining <= limit => return Err(ReadFailure::Deadline),
            Err(_) => return Err(if got_any { ReadFailure::Idle } else { ReadFailure::NoFirstChunk }),
            Ok(None) => break,
            Ok(Some(Err(e))) => return Err(ReadFailure::Transport(e.to_string())),
            Ok(Some(Ok(bytes))) => {
                got_any = true;
                agg.push(&bytes);
                if let Some(msg) = agg.error() {
                    return Err(ReadFailure::Backend(msg.to_string()));
                }
                if agg.is_done() {
                    break;
                }
            }
        }
    }
    agg.flush();
    if let Some(msg) = agg.error() {
        return Err(ReadFailure::Backend(msg.to_string()));
    }
    if !agg.complete() || agg.frames() == 0 {
        return Err(ReadFailure::Truncated);
    }
    Ok(agg.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(v: Value) -> Vec<u8> {
        format!("data: {v}\n\n").into_bytes()
    }

    #[test]
    fn content_split_over_chunks_and_usage_frame_reassemble_into_the_non_stream_shape() {
        let mut a = ChatAggregator::new();
        a.push(&frame(json!({"id":"c1","model":"m","created":7,"choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]})));
        a.push(&frame(json!({"id":"c1","choices":[{"index":0,"delta":{"content":"lo, "}}]})));
        a.push(&frame(json!({"id":"c1","choices":[{"index":0,"delta":{"content":"world"},"finish_reason":"stop"}]})));
        a.push(&frame(json!({"id":"c1","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}})));
        a.push(b"data: [DONE]\n\n");
        assert!(a.complete());
        let v = a.finish();
        assert_eq!(v.pointer("/choices/0/message/content").and_then(Value::as_str), Some("Hello, world"));
        assert_eq!(v.pointer("/choices/0/message/role").and_then(Value::as_str), Some("assistant"));
        assert_eq!(v.pointer("/choices/0/finish_reason").and_then(Value::as_str), Some("stop"));
        assert_eq!(v["object"], "chat.completion");
        assert_eq!(v["model"], "m");
        assert_eq!(crate::usage::usage_from_frame(&v), Some((5, 3)));
        assert_eq!(v["usage"]["total_tokens"], 8);
    }

    #[test]
    fn a_tool_call_split_over_chunks_is_merged_by_index() {
        let mut a = ChatAggregator::new();
        a.push(&frame(json!({"choices":[{"delta":{"tool_calls":[
            {"index":0,"id":"call_a","type":"function","function":{"name":"get_weather","arguments":""}}]}}]})));
        a.push(&frame(json!({"choices":[{"delta":{"tool_calls":[
            {"index":1,"id":"call_b","type":"function","function":{"name":"get_time","arguments":"{\"tz\":"}}]}}]})));
        a.push(&frame(json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]}}]})));
        a.push(&frame(json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Oslo\"}"}}]}}]})));
        a.push(&frame(json!({"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"\"UTC\"}"}}]},"finish_reason":"tool_calls"}]})));
        a.push(b"data: [DONE]\n\n");
        let v = a.finish();
        let calls = v.pointer("/choices/0/message/tool_calls").and_then(Value::as_array).expect("tool_calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], "call_a");
        assert_eq!(calls[0]["function"]["name"], "get_weather");
        assert_eq!(calls[0]["function"]["arguments"], "{\"city\":\"Oslo\"}");
        assert_eq!(calls[1]["function"]["name"], "get_time");
        assert_eq!(calls[1]["function"]["arguments"], "{\"tz\":\"UTC\"}");
        assert_eq!(v.pointer("/choices/0/finish_reason").and_then(Value::as_str), Some("tool_calls"));
        assert!(v.pointer("/choices/0/message/content").is_some_and(Value::is_null), "no text alongside tool calls is null, as the OpenAI body has it");
    }

    #[test]
    fn reasoning_is_kept_under_the_key_the_engine_used() {
        let mut a = ChatAggregator::new();
        a.push(&frame(json!({"choices":[{"delta":{"reasoning_content":"think "}}]})));
        a.push(&frame(json!({"choices":[{"delta":{"reasoning_content":"more"}}]})));
        a.push(&frame(json!({"choices":[{"delta":{"content":"answer"},"finish_reason":"stop"}]})));
        let v = a.finish();
        assert_eq!(v.pointer("/choices/0/message/reasoning_content").and_then(Value::as_str), Some("think more"));
        assert_eq!(v.pointer("/choices/0/message/content").and_then(Value::as_str), Some("answer"));
        let mut b = ChatAggregator::new();
        b.push(&frame(json!({"choices":[{"delta":{"reasoning":"hm"},"finish_reason":"stop"}]})));
        assert_eq!(b.finish().pointer("/choices/0/message/reasoning").and_then(Value::as_str), Some("hm"));
    }

    #[test]
    fn a_character_and_a_line_split_across_network_chunks_survive() {
        let whole = format!("data: {}\r\n\r\ndata: [DONE]\r\n\r\n", json!({"choices":[{"delta":{"content":"caf\u{e9} \u{2603}"},"finish_reason":"stop"}]}));
        let bytes = whole.as_bytes();
        let mut a = ChatAggregator::new();
        // One byte at a time splits every multi-byte character.
        for b in bytes {
            a.push(std::slice::from_ref(b));
        }
        assert!(a.complete());
        assert_eq!(a.finish().pointer("/choices/0/message/content").and_then(Value::as_str), Some("caf\u{e9} \u{2603}"));
    }

    #[test]
    fn an_error_frame_and_a_truncated_stream_are_not_complete() {
        let mut a = ChatAggregator::new();
        a.push(&frame(json!({"choices":[{"delta":{"content":"partial"}}]})));
        assert!(!a.complete(), "no [DONE] and no finish reason: the stream was cut");
        let mut b = ChatAggregator::new();
        b.push(&frame(json!({"error":{"message":"CUDA out of memory"}})));
        assert_eq!(b.error(), Some("CUDA out of memory"));
        assert!(!b.complete());
    }
}
