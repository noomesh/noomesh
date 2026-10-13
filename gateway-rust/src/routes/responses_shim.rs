// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! OpenAI Responses API → chat completions translation.
//!
//! `POST /v1/responses` exists so a harness that speaks ONLY the Responses
//! API (Codex CLI removed `wire_api = "chat"` in 2026-02) can use a mesh model
//! as its provider. A backend that serves `/v1/responses` natively is proxied
//! straight through (see `inference::v1_responses`); every other backend is
//! reached through the pure translators in this file, which have no I/O so
//! they can be tested on JSON alone.
//!
//! Event names and field sets follow the openai-python SDK types
//! (`openai/types/responses/response_*_event.py`): each event carries
//! `type` and a monotonically increasing `sequence_number`.

use serde_json::{json, Map, Value};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A Responses content value (string, or array of typed parts) as plain text.
fn content_text(c: &Value) -> String {
    match c {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| {
                let t = p.get("type").and_then(Value::as_str).unwrap_or("");
                if matches!(t, "input_text" | "output_text" | "text" | "") {
                    p.get("text").and_then(Value::as_str).map(str::to_string)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// Translate a Responses request body into a chat-completions body.
/// `model` is the backend's served name (the caller's value is only a hint).
pub fn responses_to_chat_request(body: &Value, model: &str) -> Value {
    let mut messages: Vec<Value> = Vec::new();

    if let Some(ins) = body.get("instructions").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
        messages.push(json!({"role": "system", "content": ins}));
    }

    match body.get("input") {
        Some(Value::String(s)) => messages.push(json!({"role": "user", "content": s})),
        Some(Value::Array(items)) => {
            for item in items {
                let ty = item.get("type").and_then(Value::as_str).unwrap_or("");
                match ty {
                    "function_call" => {
                        let call = json!({
                            "id": item.get("call_id").cloned().unwrap_or(json!("")),
                            "type": "function",
                            "function": {
                                "name": item.get("name").cloned().unwrap_or(json!("")),
                                "arguments": item.get("arguments").cloned().unwrap_or(json!("{}")),
                            },
                        });
                        // Consecutive calls are one assistant turn.
                        if let Some(last) = messages.last_mut() {
                            if last.get("role") == Some(&json!("assistant")) && last.get("tool_calls").is_some() {
                                if let Some(arr) = last["tool_calls"].as_array_mut() {
                                    arr.push(call);
                                    continue;
                                }
                            }
                        }
                        messages.push(json!({"role": "assistant", "content": null, "tool_calls": [call]}));
                    }
                    "function_call_output" => {
                        let out = match item.get("output") {
                            Some(Value::String(s)) => s.clone(),
                            Some(other) => content_text(other),
                            None => String::new(),
                        };
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": item.get("call_id").cloned().unwrap_or(json!("")),
                            "content": out,
                        }));
                    }
                    // "message", or a bare {role, content} item.
                    _ => {
                        let role = match item.get("role").and_then(Value::as_str).unwrap_or("user") {
                            "developer" => "system",
                            r => r,
                        };
                        let text = content_text(item.get("content").unwrap_or(&Value::Null));
                        messages.push(json!({"role": role, "content": text}));
                    }
                }
            }
        }
        _ => {}
    }

    let mut out = Map::new();
    out.insert("model".into(), json!(model));
    out.insert("messages".into(), Value::Array(messages));
    if let Some(v) = body.get("max_output_tokens").filter(|v| v.is_number()) {
        out.insert("max_tokens".into(), v.clone());
    }
    for k in ["temperature", "top_p"] {
        if let Some(v) = body.get(k).filter(|v| v.is_number()) {
            out.insert(k.into(), v.clone());
        }
    }
    if let Some(tools) = body.get("tools").and_then(Value::as_array) {
        let chat_tools: Vec<Value> = tools
            .iter()
            .filter(|t| t.get("type").and_then(Value::as_str) == Some("function"))
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.get("name").cloned().unwrap_or(json!("")),
                        "description": t.get("description").cloned().unwrap_or(json!("")),
                        "parameters": t.get("parameters").cloned()
                            .unwrap_or(json!({"type": "object", "properties": {}})),
                    },
                })
            })
            .collect();
        if !chat_tools.is_empty() {
            out.insert("tools".into(), Value::Array(chat_tools));
            if let Some(tc) = body.get("tool_choice").and_then(Value::as_str) {
                out.insert("tool_choice".into(), json!(tc));
            }
        }
    }
    if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
        out.insert("stream".into(), json!(true));
        out.insert("stream_options".into(), json!({"include_usage": true}));
    }
    Value::Object(out)
}

fn usage_json(p: u32, c: u32) -> Value {
    json!({
        "input_tokens": p,
        "input_tokens_details": {"cached_tokens": 0},
        "output_tokens": c,
        "output_tokens_details": {"reasoning_tokens": 0},
        "total_tokens": p + c,
    })
}

fn response_object(id: &str, model: &str, created_at: u64, status: &str, output: Vec<Value>, usage: Option<(u32, u32)>) -> Value {
    json!({
        "id": id,
        "object": "response",
        "created_at": created_at,
        "status": status,
        "model": model,
        "output": output,
        "parallel_tool_calls": true,
        "tool_choice": "auto",
        "tools": [],
        "usage": usage.map(|(p, c)| usage_json(p, c)),
    })
}

fn message_item(id: &str, text: &str, status: &str) -> Value {
    json!({
        "id": id, "type": "message", "role": "assistant", "status": status,
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    })
}

fn function_call_item(id: &str, call_id: &str, name: &str, args: &str, status: &str) -> Value {
    json!({
        "id": id, "type": "function_call", "status": status,
        "call_id": call_id, "name": name, "arguments": args,
    })
}

fn chat_usage(chat: &Value) -> Option<(u32, u32)> {
    let u = chat.get("usage")?;
    let n = |k: &str| u.get(k).and_then(Value::as_u64).map(|x| x.min(u32::MAX as u64) as u32);
    Some((n("prompt_tokens")?, n("completion_tokens")?))
}

/// Translate a non-streaming chat completion into a Responses object.
pub fn chat_to_response(chat: &Value, model: &str) -> Value {
    let msg = chat.pointer("/choices/0/message").cloned().unwrap_or(json!({}));
    let mut output = Vec::new();
    let text = msg.get("content").and_then(Value::as_str).unwrap_or("");
    let calls = msg.get("tool_calls").and_then(Value::as_array).cloned().unwrap_or_default();
    if !text.is_empty() || calls.is_empty() {
        output.push(message_item(&format!("msg_{}", uuid::Uuid::new_v4().simple()), text, "completed"));
    }
    for c in &calls {
        let args = match c.pointer("/function/arguments") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => "{}".into(),
        };
        output.push(function_call_item(
            &format!("fc_{}", uuid::Uuid::new_v4().simple()),
            c.get("id").and_then(Value::as_str).unwrap_or(""),
            c.pointer("/function/name").and_then(Value::as_str).unwrap_or(""),
            &args,
            "completed",
        ));
    }
    response_object(
        &format!("resp_{}", uuid::Uuid::new_v4().simple()),
        model, now_secs(), "completed", output, chat_usage(chat),
    )
}

/// Turns a chat-completions SSE byte stream into the Responses event
/// sequence. Feed bytes with [`push`](Self::push); call
/// [`finish`](Self::finish) when the upstream ends.
pub struct StreamTranslator {
    resp_id: String,
    msg_id: String,
    model: String,
    created_at: u64,
    seq: u64,
    carry: String,
    text: String,
    msg_open: bool,
    /// (call_id, name, arguments), in first-seen order.
    tools: Vec<(String, String, String)>,
    usage: Option<(u32, u32)>,
    started: bool,
    done: bool,
}

impl StreamTranslator {
    pub fn new(model: &str) -> Self {
        Self {
            resp_id: format!("resp_{}", uuid::Uuid::new_v4().simple()),
            msg_id: format!("msg_{}", uuid::Uuid::new_v4().simple()),
            model: model.to_string(),
            created_at: now_secs(),
            seq: 0,
            carry: String::new(),
            text: String::new(),
            msg_open: false,
            tools: Vec::new(),
            usage: None,
            started: false,
            done: false,
        }
    }

    fn ev(&mut self, ty: &str, mut data: Value) -> String {
        data["type"] = json!(ty);
        data["sequence_number"] = json!(self.seq);
        self.seq += 1;
        format!("event: {ty}\ndata: {data}\n\n")
    }

    fn start(&mut self, out: &mut Vec<String>) {
        if self.started {
            return;
        }
        self.started = true;
        let r = response_object(&self.resp_id, &self.model, self.created_at, "in_progress", vec![], None);
        out.push(self.ev("response.created", json!({"response": r.clone()})));
        out.push(self.ev("response.in_progress", json!({"response": r})));
    }

    fn open_message(&mut self, out: &mut Vec<String>) {
        if self.msg_open {
            return;
        }
        self.msg_open = true;
        let item = json!({"id": self.msg_id, "type": "message", "role": "assistant", "status": "in_progress", "content": []});
        out.push(self.ev("response.output_item.added", json!({"output_index": 0, "item": item})));
        out.push(self.ev("response.content_part.added", json!({
            "item_id": self.msg_id, "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": "", "annotations": []},
        })));
    }

    fn line(&mut self, line: &str, out: &mut Vec<String>) {
        let line = line.trim();
        let Some(payload) = line.strip_prefix("data:").map(str::trim) else { return };
        if payload.is_empty() || payload == "[DONE]" {
            return;
        }
        let Ok(v) = serde_json::from_str::<Value>(payload) else { return };
        if let Some(u) = chat_usage(&v) {
            self.usage = Some(u);
        }
        let delta = v.pointer("/choices/0/delta");
        if let Some(t) = delta.and_then(|d| d.get("content")).and_then(Value::as_str).filter(|t| !t.is_empty()) {
            self.start(out);
            self.open_message(out);
            self.text.push_str(t);
            let id = self.msg_id.clone();
            out.push(self.ev("response.output_text.delta", json!({
                "item_id": id, "output_index": 0, "content_index": 0, "delta": t, "logprobs": [],
            })));
        }
        if let Some(calls) = delta.and_then(|d| d.get("tool_calls")).and_then(Value::as_array) {
            for (pos, c) in calls.iter().enumerate() {
                let idx = c.get("index").and_then(Value::as_u64).map(|i| i as usize).unwrap_or(pos);
                while self.tools.len() <= idx {
                    self.tools.push((String::new(), String::new(), String::new()));
                }
                let slot = &mut self.tools[idx];
                if let Some(id) = c.get("id").and_then(Value::as_str) {
                    slot.0 = id.to_string();
                }
                if let Some(n) = c.pointer("/function/name").and_then(Value::as_str) {
                    slot.1.push_str(n);
                }
                if let Some(a) = c.pointer("/function/arguments").and_then(Value::as_str) {
                    slot.2.push_str(a);
                }
            }
        }
    }

    /// Consume upstream bytes; returns the Responses SSE events they produced.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        self.start(&mut out);
        self.carry.push_str(&String::from_utf8_lossy(chunk));
        if let Some(upto) = self.carry.rfind('\n').map(|i| i + 1) {
            let complete: String = self.carry.drain(..upto).collect();
            for l in complete.lines() {
                self.line(l, &mut out);
            }
        }
        out
    }

    /// Upstream ended: close the open items and emit `response.completed`.
    pub fn finish(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        self.start(&mut out);
        let tail = std::mem::take(&mut self.carry);
        for l in tail.lines() {
            self.line(l, &mut out);
        }
        self.done = true;

        let mut output: Vec<Value> = Vec::new();
        if !self.msg_open && self.tools.is_empty() {
            self.open_message(&mut out);
        }
        if self.msg_open {
            let (id, text) = (self.msg_id.clone(), self.text.clone());
            out.push(self.ev("response.output_text.done", json!({
                "item_id": id, "output_index": 0, "content_index": 0, "text": text, "logprobs": [],
            })));
            out.push(self.ev("response.content_part.done", json!({
                "item_id": id, "output_index": 0, "content_index": 0,
                "part": {"type": "output_text", "text": text, "annotations": []},
            })));
            let item = message_item(&id, &text, "completed");
            out.push(self.ev("response.output_item.done", json!({"output_index": 0, "item": item.clone()})));
            output.push(item);
        }
        let base = output.len();
        for (i, (call_id, name, args)) in self.tools.clone().into_iter().enumerate() {
            let oi = base + i;
            let fid = format!("fc_{}", uuid::Uuid::new_v4().simple());
            let args = if args.is_empty() { "{}".to_string() } else { args };
            out.push(self.ev("response.output_item.added", json!({
                "output_index": oi,
                "item": function_call_item(&fid, &call_id, &name, "", "in_progress"),
            })));
            out.push(self.ev("response.function_call_arguments.delta", json!({
                "item_id": fid, "output_index": oi, "delta": args,
            })));
            out.push(self.ev("response.function_call_arguments.done", json!({
                "item_id": fid, "output_index": oi, "arguments": args,
            })));
            let item = function_call_item(&fid, &call_id, &name, &args, "completed");
            out.push(self.ev("response.output_item.done", json!({"output_index": oi, "item": item.clone()})));
            output.push(item);
        }
        let r = response_object(&self.resp_id, &self.model, self.created_at, "completed", output, self.usage);
        out.push(self.ev("response.completed", json!({"response": r})));
        out
    }
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
        }), "served");
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
        }), "served");
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
        let mut t = StreamTranslator::new("served");
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
        let mut t = StreamTranslator::new("m");
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
