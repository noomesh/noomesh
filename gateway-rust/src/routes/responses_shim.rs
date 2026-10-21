// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! OpenAI Responses API → chat completions translation.
//!
//! `POST /v1/responses` exists so a harness that speaks ONLY the Responses
//! API (Codex CLI removed `wire_api = "chat"` in 2026-02) can use a mesh model
//! as its provider. A backend that serves `/v1/responses` natively is proxied
//! straight through (see `inference::v1_responses`); every other backend is
//! reached by translating to chat completions. The translation itself is
//! `coordinator::responses_wire`, shared with the node harness's loopback
//! wire translator; this file adapts it to the gateway route (the served
//! model, the usage request, a byte stream in and SSE frames out).
//!
//! Event names and field sets follow the openai-python SDK types
//! (`openai/types/responses/response_*_event.py`): each event carries
//! `type` and a monotonically increasing `sequence_number`.

use serde_json::{json, Value};

use crate::coordinator::responses_wire::{self as wire, ChatToResponsesSse, ToolNames};

/// Translate a Responses request body into a chat-completions body.
/// `model` is the backend's served name (the caller's value is only a hint).
pub fn responses_to_chat_request(body: &Value, model: &str) -> Value {
    let mut out = wire::request_body_from_responses(body);
    out["model"] = json!(model);
    if out["stream"] == json!(true) {
        out["stream_options"] = json!({"include_usage": true});
    } else if let Some(o) = out.as_object_mut() {
        o.remove("stream");
    }
    out
}

/// Translate a non-streaming chat completion into a Responses object.
/// `request` is the Responses body it answers: its tools say which names
/// come back as namespaced or freeform calls.
pub fn chat_to_response(chat: &Value, model: &str, request: &Value) -> Value {
    let msg = chat.pointer("/choices/0/message").cloned().unwrap_or(json!({}));
    let fr = chat.pointer("/choices/0/finish_reason").and_then(Value::as_str);
    let usage = chat.get("usage").filter(|u| u.is_object()).map(|u| {
        let (p, c, _) = crate::coordinator::anthropic_wire::usage_tokens(u);
        (p, c)
    });
    wire::response_from_chat(&msg, fr, usage, model, &ToolNames::from_request(request), &wire::metadata_of(request))
}

/// Turns a chat-completions SSE byte stream into the Responses event
/// sequence. Feed bytes with [`push`](Self::push); call
/// [`finish`](Self::finish) when the upstream ends.
pub struct StreamTranslator {
    inner: ChatToResponsesSse,
    carry: String,
}

impl StreamTranslator {
    pub fn new(model: &str, request: &Value) -> Self {
        Self { inner: ChatToResponsesSse::new(model, ToolNames::from_request(request)).with_metadata(wire::metadata_of(request)), carry: String::new() }
    }

    fn line(&mut self, line: &str, out: &mut String) {
        let Some(payload) = line.trim().strip_prefix("data:").map(str::trim) else { return };
        if payload.is_empty() || payload == "[DONE]" {
            return;
        }
        if let Ok(v) = serde_json::from_str::<Value>(payload) {
            out.push_str(&wire::sse_frames(&self.inner.on_chunk(&v)));
        }
    }

    /// Consume upstream bytes; returns the Responses SSE events they produced.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut out = String::new();
        self.carry.push_str(&String::from_utf8_lossy(chunk));
        if let Some(upto) = self.carry.rfind('\n').map(|i| i + 1) {
            let complete: String = self.carry.drain(..upto).collect();
            for l in complete.lines() {
                self.line(l, &mut out);
            }
        }
        split_frames(out)
    }

    /// Upstream ended: close the open items and emit `response.completed`.
    pub fn finish(&mut self) -> Vec<String> {
        let mut out = String::new();
        let tail = std::mem::take(&mut self.carry);
        for l in tail.lines() {
            self.line(l, &mut out);
        }
        out.push_str(&wire::sse_frames(&self.inner.finish()));
        split_frames(out)
    }
}

/// One string per `event:`/`data:` frame.
fn split_frames(s: String) -> Vec<String> {
    s.split_inclusive("\n\n").filter(|f| !f.trim().is_empty()).map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_input_and_instructions() {
        let c = responses_to_chat_request(
            &json!({"model": "x", "instructions": "be brief", "input": "hi",
                    "max_output_tokens": 50, "temperature": 0.2, "top_p": 0.9}),
            "served",
        );
        assert_eq!(c["model"], "served");
        assert_eq!(c["messages"], json!([
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": "hi"},
        ]));
        assert_eq!(c["max_tokens"], 50);
        assert_eq!(c["temperature"], 0.2);
        assert_eq!(c["top_p"], 0.9);
        assert!(c.get("stream").is_none());
    }

    #[test]
    fn array_input_with_parts_and_tool_history() {
        let c = responses_to_chat_request(&json!({"input": [
            {"role": "developer", "content": "rules"},
            {"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "a"}, {"type": "input_text", "text": "b"}]},
            {"type": "function_call", "call_id": "c1", "name": "ls", "arguments": "{\"p\":1}"},
            {"type": "function_call_output", "call_id": "c1", "output": "file.txt"},
        ]}), "m");
        let m = c["messages"].as_array().unwrap();
        assert_eq!(m[0], json!({"role": "system", "content": "rules"}));
        assert_eq!(m[1], json!({"role": "user", "content": "a\nb"}));
        assert_eq!(m[2]["tool_calls"][0]["id"], "c1");
        assert_eq!(m[2]["tool_calls"][0]["function"]["name"], "ls");
        assert_eq!(m[3], json!({"role": "tool", "tool_call_id": "c1", "content": "file.txt"}));
    }

    #[test]
    fn function_tools_map_and_others_drop_and_stream_asks_usage() {
        let c = responses_to_chat_request(&json!({"input": "x", "stream": true, "tools": [
            {"type": "function", "name": "ls", "description": "list", "parameters": {"type": "object"}},
            {"type": "web_search"},
        ]}), "m");
        let t = c["tools"].as_array().unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0]["function"]["name"], "ls");
        assert_eq!(t[0]["function"]["parameters"], json!({"type": "object"}));
        assert_eq!(c["stream"], true);
        assert_eq!(c["stream_options"]["include_usage"], true);
    }

    #[test]
    fn response_text_and_usage() {
        let r = chat_to_response(&json!({
            "choices": [{"message": {"role": "assistant", "content": "hello"}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
        }), "served", &json!({}));
        assert_eq!(r["object"], "response");
        assert_eq!(r["status"], "completed");
        assert_eq!(r["output"][0]["type"], "message");
        assert_eq!(r["output"][0]["role"], "assistant");
        assert_eq!(r["output"][0]["content"][0]["type"], "output_text");
        assert_eq!(r["output"][0]["content"][0]["text"], "hello");
        assert_eq!(r["usage"]["input_tokens"], 7);
        assert_eq!(r["usage"]["output_tokens"], 3);
        assert_eq!(r["usage"]["total_tokens"], 10);
        assert!(r["id"].as_str().unwrap().starts_with("resp_"));
    }

    #[test]
    fn response_function_call() {
        let r = chat_to_response(&json!({
            "choices": [{"message": {"role": "assistant", "content": null, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "ls", "arguments": "{\"p\":1}"}}]}}],
        }), "served", &json!({}));
        assert_eq!(r["output"].as_array().unwrap().len(), 1);
        assert_eq!(r["output"][0]["type"], "function_call");
        assert_eq!(r["output"][0]["name"], "ls");
        assert_eq!(r["output"][0]["arguments"], "{\"p\":1}");
        assert_eq!(r["output"][0]["call_id"], "call_1");
        assert!(r["usage"].is_null());
    }

    fn types(events: &[String]) -> Vec<String> {
        events
            .iter()
            .map(|e| e.lines().next().unwrap().trim_start_matches("event: ").to_string())
            .collect()
    }

    #[test]
    fn stream_two_deltas_and_usage_frame() {
        let mut t = StreamTranslator::new("served", &json!({}));
        let mut ev = Vec::new();
        // The second frame is split across two chunks on purpose.
        ev.extend(t.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"));
        ev.extend(t.push(b"data: {\"choices\":[{\"delta\":{\"con"));
        ev.extend(t.push(b"tent\":\"lo\"}}]}\n\n"));
        ev.extend(t.push(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n"));
        ev.extend(t.finish());
        assert_eq!(types(&ev), [
            "response.created", "response.in_progress",
            "response.output_item.added", "response.content_part.added",
            "response.output_text.delta", "response.output_text.delta",
            "response.output_text.done", "response.content_part.done",
            "response.output_item.done", "response.completed",
        ]);
        let data = |i: usize| -> Value {
            serde_json::from_str(ev[i].split("data: ").nth(1).unwrap().trim()).unwrap()
        };
        assert_eq!(data(4)["delta"], "Hel");
        assert_eq!(data(5)["delta"], "lo");
        assert_eq!(data(6)["text"], "Hello");
        let done = data(9);
        assert_eq!(done["response"]["output"][0]["content"][0]["text"], "Hello");
        assert_eq!(done["response"]["usage"]["input_tokens"], 5);
        assert_eq!(done["response"]["usage"]["output_tokens"], 2);
        assert_eq!(done["response"]["status"], "completed");
        for (i, e) in ev.iter().enumerate() {
            assert_eq!(serde_json::from_str::<Value>(e.split("data: ").nth(1).unwrap().trim()).unwrap()["sequence_number"], i);
        }
        assert!(t.finish().is_empty(), "finish is idempotent");
    }

    #[test]
    fn stream_tool_call_accumulates() {
        let mut t = StreamTranslator::new("m", &json!({}));
        let mut ev = t.push(b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c9\",\"function\":{\"name\":\"ls\",\"arguments\":\"{\\\"a\"}}]}}]}\n\n");
        ev.extend(t.push(b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\":1}\"}}]}}]}\n\n"));
        ev.extend(t.finish());
        let last: Value = serde_json::from_str(ev.last().unwrap().split("data: ").nth(1).unwrap().trim()).unwrap();
        let item = &last["response"]["output"][0];
        assert_eq!(item["type"], "function_call");
        assert_eq!(item["call_id"], "c9");
        assert_eq!(item["name"], "ls");
        assert_eq!(item["arguments"], "{\"a\":1}");
    }
}
