// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The scripted model behind `noo-gateway harness probe --mock-model`.
//!
//! An OpenAI-chat upstream on `127.0.0.1:0` that the probe's wire
//! translator forwards to, exactly as it would forward to a node's vLLM or
//! llama.cpp. It does not think: it plays a plausible agent conversation so
//! a vendor CLI's own loop can be exercised end to end with no model and no
//! GPU.
//!
//! - [`Script::Reply`]: every answer is `NOO_RESULT: ok`.
//! - [`Script::File`]: the first request that offers tools gets ONE tool
//!   call to whichever tool the CLI advertised for writing a file
//!   ([`choose_write_tool`]), with its required arguments filled so the
//!   call creates `probe.txt` containing `noomesh`; once a request carries
//!   a tool result, the answer is `NOO_RESULT: done`. A request with no
//!   tools (a CLI's side call: a title, a topic check) gets plain text.
//!
//! Streaming (SSE, with a final usage chunk when asked) and whole replies
//! both work. Every request is recorded ([`MockCall`]): the tools the CLI
//! advertised, and which one was chosen with which argument keys, so a
//! mismatch between the mock's guess and a vendor's tool shape is
//! diagnosable from the probe's report.
//!
//! openapi-drift: not-gateway-routes — this router is bound on a loopback
//! port inside a `harness probe` process for one test run, standing in for
//! a node's model endpoint; it is never mounted on the gateway's listener,
//! so its paths are not gateway API (`scripts/check-openapi-drift.py`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::extract::State;
use axum::http::{header, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::sync::oneshot;

/// The file the `file` test asks for, and what it must contain.
pub const PROBE_FILE: &str = "probe.txt";
pub const PROBE_WORD: &str = "noomesh";

/// What the mock plays.
#[derive(Debug, Clone)]
pub enum Script {
    Reply,
    /// `workdir` is the CLI's working directory: path arguments are given
    /// absolute inside it (Claude Code's Write wants an absolute path).
    File { workdir: PathBuf },
}

/// The tool the mock called, and why.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Choice {
    pub tool: String,
    pub class: &'static str,
    pub arg_keys: Vec<String>,
}

/// One request the mock answered.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MockCall {
    pub path: String,
    pub stream: bool,
    /// Tool names the request advertised, in order.
    pub tools: Vec<String>,
    pub had_tool_result: bool,
    /// `text: <content>`, `tool_call: <name>`, or `404`.
    pub answered: String,
    pub chosen: Option<Choice>,
}

struct Shared {
    script: Script,
    calls: Mutex<Vec<MockCall>>,
}

/// A running mock; [`url`](Self::url) is the upstream base URL.
pub struct MockModel {
    url: String,
    shared: Arc<Shared>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MockModel {
    pub async fn start(script: Script) -> Result<MockModel> {
        let shared = Arc::new(Shared { script, calls: Mutex::new(Vec::new()) });
        let app = Router::new().route("/v1/chat/completions", post(chat)).fallback(not_found).with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://{}", listener.local_addr()?);
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await;
        });
        Ok(MockModel { url, shared, stop: Some(stop), task: Some(task) })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn calls(&self) -> Vec<MockCall> {
        self.shared.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub async fn shutdown(mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), t).await;
        }
    }
}

impl Drop for MockModel {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

async fn not_found(State(sh): State<Arc<Shared>>, method: Method, uri: Uri) -> Response {
    sh.calls.lock().unwrap_or_else(|p| p.into_inner()).push(MockCall {
        path: format!("{method} {}", uri.path()),
        stream: false,
        tools: Vec::new(),
        had_tool_result: false,
        answered: "404".into(),
        chosen: None,
    });
    (StatusCode::NOT_FOUND, Json(json!({"error": {"type": "not_found_error", "message": "the probe's mock model serves POST /v1/chat/completions only"}}))).into_response()
}

fn tool_name(t: &Value) -> &str {
    t.pointer("/function/name").or_else(|| t.get("name")).and_then(|n| n.as_str()).unwrap_or("")
}

fn tool_description(t: &Value) -> &str {
    t.pointer("/function/description").or_else(|| t.get("description")).and_then(|n| n.as_str()).unwrap_or("")
}

fn tool_parameters(t: &Value) -> Value {
    t.pointer("/function/parameters").or_else(|| t.get("parameters")).or_else(|| t.get("input_schema")).cloned().unwrap_or_else(|| json!({}))
}

/// `writeFile`, `write_file`, `Write`, `str_replace_editor` -> lowercase words.
fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Words that make a "write"/"create" tool something other than a file
/// writer (Claude Code's `TodoWrite`, Codex's `create_goal` and
/// `write_stdin`, a `create_issue`, a notebook edit).
const NOT_A_FILE: &[&str] = &["goal", "stdin", "image", "todo", "plan", "notebook", "memory", "task", "issue", "pull", "pr", "branch", "dir", "directory", "agent", "mcp", "web", "comment", "gist", "repo", "repository"];

/// How a tool can make the file, best first. `None`: it cannot.
fn class_of(t: &Value) -> Option<(&'static str, u32)> {
    let w = words(tool_name(t));
    if w.is_empty() || w.iter().any(|x| NOT_A_FILE.contains(&x.as_str())) {
        return None;
    }
    let has = |k: &[&str]| w.iter().any(|x| k.contains(&x.as_str()));
    if has(&["write", "create"]) && !has(&["edit", "replace"]) {
        return Some(("write", 100));
    }
    if has(&["patch"]) {
        return Some(("patch", 80));
    }
    if has(&["edit", "replace", "editor"]) {
        return Some(("edit", 60));
    }
    if has(&["shell", "bash", "exec", "terminal", "powershell"]) || (has(&["run", "command"]) && !has(&["read", "list", "view"])) {
        return Some(("shell", 40));
    }
    let d = tool_description(t).to_ascii_lowercase();
    if (d.contains("write") || d.contains("create")) && d.contains("file") && !has(&["read", "view", "list", "glob", "grep", "search"]) {
        return Some(("write", 20));
    }
    None
}

/// The shell line that makes the file.
fn shell_line(workdir: &Path) -> String {
    let path = workdir.join(PROBE_FILE).display().to_string().replace('\'', "'\\''");
    format!("printf {PROBE_WORD} > '{path}'")
}

/// Codex's `apply_patch` grammar: an add-file patch, path relative.
pub fn add_file_patch() -> String {
    format!("*** Begin Patch\n*** Add File: {PROBE_FILE}\n+{PROBE_WORD}\n*** End Patch\n")
}

/// One argument's value for `class`, from its key and schema.
fn value_for(key: &str, schema: &Value, class: &str, workdir: &Path) -> Value {
    let k = key.to_ascii_lowercase();
    let ty = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");
    let abs = workdir.join(PROBE_FILE).display().to_string();
    if let Some(e) = schema.get("enum").and_then(|e| e.as_array()) {
        if e.iter().any(|v| v == "create") {
            return json!("create");
        }
        if let Some(first) = e.first() {
            return first.clone();
        }
    }
    let s = |v: String| -> Value {
        if ty == "array" {
            if class == "shell" {
                json!(["bash", "-lc", v])
            } else {
                json!([v])
            }
        } else {
            json!(v)
        }
    };
    match k.as_str() {
        "path" | "file_path" | "filepath" | "filename" | "file" | "target_file" | "absolute_path" | "file_name" | "target" => s(abs),
        "content" | "contents" | "file_text" | "text" | "new_str" | "new_string" | "data" | "body" | "new_content" => s(PROBE_WORD.into()),
        "old_str" | "old_string" => s(String::new()),
        "input" | "patch" if class == "patch" => s(add_file_patch()),
        "command" | "cmd" | "commands" | "script" | "input" | "code" if class == "shell" => s(shell_line(workdir)),
        "description" | "explanation" | "reason" | "justification" | "summary" | "title" => s("write probe.txt for the noomesh probe".into()),
        "workdir" | "cwd" | "directory" | "working_directory" => s(workdir.display().to_string()),
        _ => match ty {
            "boolean" => json!(false),
            "integer" | "number" => json!(0),
            "array" => json!([]),
            "object" => json!({}),
            _ => json!(""),
        },
    }
}

/// Keys the mock fills even when the schema does not require them.
const ALWAYS: &[&str] = &["path", "file_path", "filepath", "content", "contents", "file_text", "command", "cmd", "input", "new_string", "new_str", "old_string", "old_str"];

/// The tool to call to create `probe.txt`, its arguments, and the record.
pub fn choose_write_tool(tools: &[Value], workdir: &Path) -> Option<(String, Value, Choice)> {
    let (t, (class, _)) = tools.iter().filter_map(|t| class_of(t).map(|c| (t, c))).max_by_key(|(_, (_, score))| *score)?;
    let params = tool_parameters(t);
    let props = params.get("properties").and_then(|p| p.as_object()).cloned().unwrap_or_default();
    let required: Vec<String> = params.get("required").and_then(|r| r.as_array()).map(|r| r.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let mut args = serde_json::Map::new();
    for key in required.iter().cloned().chain(props.keys().filter(|k| ALWAYS.contains(&k.to_ascii_lowercase().as_str())).cloned()) {
        if args.contains_key(&key) {
            continue;
        }
        let schema = props.get(&key).cloned().unwrap_or_else(|| json!({"type": "string"}));
        args.insert(key.clone(), value_for(&key, &schema, class, workdir));
    }
    // A tool with no schema at all: give it the obvious pair.
    if args.is_empty() {
        match class {
            "shell" => {
                args.insert("command".into(), json!(shell_line(workdir)));
            }
            "patch" => {
                args.insert("input".into(), json!(add_file_patch()));
            }
            _ => {
                args.insert("path".into(), json!(workdir.join(PROBE_FILE).display().to_string()));
                args.insert("content".into(), json!(PROBE_WORD));
            }
        }
    }
    let name = tool_name(t).to_string();
    let choice = Choice { tool: name.clone(), class, arg_keys: args.keys().cloned().collect() };
    Some((name, Value::Object(args), choice))
}

/// Whether the conversation already carries a tool's result.
fn has_tool_result(body: &Value) -> bool {
    body.get("messages").and_then(|m| m.as_array()).is_some_and(|m| m.iter().any(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool")))
}

async fn chat(State(sh): State<Arc<Shared>>, Json(body): Json<Value>) -> Response {
    let tools: Vec<Value> = body.get("tools").and_then(|t| t.as_array()).cloned().unwrap_or_default();
    let names: Vec<String> = tools.iter().map(|t| tool_name(t).to_string()).collect();
    let stream = body.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let done = has_tool_result(&body);
    let (text, call) = match &sh.script {
        Script::Reply => ("NOO_RESULT: ok".to_string(), None),
        Script::File { .. } if done => ("NOO_RESULT: done".to_string(), None),
        Script::File { workdir } => match choose_write_tool(&tools, workdir) {
            Some(c) => (String::new(), Some(c)),
            None if tools.is_empty() => ("NOO_RESULT: done".to_string(), None),
            None => (format!("NOO_FAILED: the mock found no file-writing tool among: {}", names.join(", ")), None),
        },
    };
    if let Some((name, _, choice)) = &call {
        tracing::info!(tool = %name, class = choice.class, arg_keys = ?choice.arg_keys, "probe mock: calling the CLI's file tool");
    }
    sh.calls.lock().unwrap_or_else(|p| p.into_inner()).push(MockCall {
        path: "POST /v1/chat/completions".into(),
        stream,
        tools: names,
        had_tool_result: done,
        answered: match &call {
            Some((n, _, _)) => format!("tool_call: {n}"),
            None => format!("text: {text}"),
        },
        chosen: call.as_ref().map(|c| c.2.clone()),
    });
    let model = body.get("model").and_then(|m| m.as_str()).unwrap_or("noo-probe-mock").to_string();
    let usage = json!({"prompt_tokens": 42, "completion_tokens": 7, "total_tokens": 49});
    let created = chrono::Utc::now().timestamp();
    let id = format!("chatcmpl-probe-{}", uuid::Uuid::new_v4().simple());
    let call_id = format!("call_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    if !stream {
        let (message, finish) = match &call {
            Some((n, a, _)) => (json!({"role": "assistant", "content": null, "tool_calls": [{"id": call_id, "type": "function", "function": {"name": n, "arguments": a.to_string()}}]}), "tool_calls"),
            None => (json!({"role": "assistant", "content": text}), "stop"),
        };
        return Json(json!({
            "id": id, "object": "chat.completion", "created": created, "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": usage,
        }))
        .into_response();
    }
    let mut s = String::new();
    let mut push = |choices: Value, usage: Option<&Value>| {
        let mut v = json!({"id": id, "object": "chat.completion.chunk", "created": created, "model": model, "choices": choices});
        if let Some(u) = usage {
            v["usage"] = u.clone();
        }
        s.push_str(&format!("data: {v}\n\n"));
    };
    push(json!([{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": null}]), None);
    match &call {
        Some((n, a, _)) => {
            push(json!([{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": call_id, "type": "function", "function": {"name": n, "arguments": ""}}]}, "finish_reason": null}]), None);
            push(json!([{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": a.to_string()}}]}, "finish_reason": null}]), None);
            push(json!([{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]), None);
        }
        None => {
            push(json!([{"index": 0, "delta": {"content": text}, "finish_reason": null}]), None);
            push(json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]), None);
        }
    }
    if body.pointer("/stream_options/include_usage").and_then(|v| v.as_bool()) == Some(true) {
        push(json!([]), Some(&usage));
    }
    s.push_str("data: [DONE]\n\n");
    ([(header::CONTENT_TYPE, "text/event-stream"), (header::CACHE_CONTROL, "no-cache")], s).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str, description: &str, params: Value) -> Value {
        json!({"type": "function", "function": {"name": name, "description": description, "parameters": params}})
    }

    fn wd() -> PathBuf {
        PathBuf::from("/tmp/ws/work")
    }

    #[test]
    fn words_split_snake_and_camel_case() {
        assert_eq!(words("TodoWrite"), ["todo", "write"]);
        assert_eq!(words("str_replace_editor"), ["str", "replace", "editor"]);
        assert_eq!(words("writeFile"), ["write", "file"]);
        assert_eq!(words("apply_patch"), ["apply", "patch"]);
    }

    /// Claude Code's tools as the translator hands them on (Anthropic
    /// `input_schema` -> chat `parameters`).
    #[test]
    fn claude_code_gets_write_with_an_absolute_path_not_todowrite() {
        let tools = vec![
            f("Bash", "Executes a bash command", json!({"type": "object", "properties": {"command": {"type": "string"}, "timeout": {"type": "number"}}, "required": ["command"]})),
            f("TodoWrite", "Create and manage a todo list", json!({"type": "object", "properties": {"todos": {"type": "array"}}, "required": ["todos"]})),
            f("Edit", "Performs exact string replacements in files", json!({"type": "object", "properties": {"file_path": {"type": "string"}, "old_string": {"type": "string"}, "new_string": {"type": "string"}}, "required": ["file_path", "old_string", "new_string"]})),
            f("Write", "Writes a file to the local filesystem.", json!({"type": "object", "properties": {"file_path": {"type": "string"}, "content": {"type": "string"}}, "required": ["file_path", "content"]})),
            f("Read", "Reads a file", json!({"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]})),
        ];
        let (name, args, choice) = choose_write_tool(&tools, &wd()).unwrap();
        assert_eq!(name, "Write");
        assert_eq!(args, json!({"file_path": "/tmp/ws/work/probe.txt", "content": "noomesh"}));
        assert_eq!(choice.class, "write");
    }

    /// Copilot CLI's built-ins (`create` takes `path` + `file_text`).
    #[test]
    fn copilot_gets_create() {
        let tools = vec![
            f("bash", "Runs a Bash command", json!({"type": "object", "properties": {"command": {"type": "string"}, "description": {"type": "string"}}, "required": ["command", "description"]})),
            f("view", "View a file", json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]})),
            f("create", "Create a new file", json!({"type": "object", "properties": {"path": {"type": "string"}, "file_text": {"type": "string"}}, "required": ["path", "file_text"]})),
            f("edit", "Edit a file", json!({"type": "object", "properties": {"path": {"type": "string"}, "old_str": {"type": "string"}, "new_str": {"type": "string"}}, "required": ["path"]})),
        ];
        let (name, args, _) = choose_write_tool(&tools, &wd()).unwrap();
        assert_eq!(name, "create");
        assert_eq!(args, json!({"path": "/tmp/ws/work/probe.txt", "file_text": "noomesh"}));
    }

    /// Codex: `apply_patch` as a custom tool (one `input` string after the
    /// translator) beats the shell; without it, the shell writes the file.
    #[test]
    fn codex_gets_apply_patch_then_the_shell() {
        let patch = f("apply_patch", "Use apply_patch to edit files.", json!({"type": "object", "properties": {"input": {"type": "string"}}, "required": ["input"]}));
        let shell = f("shell", "Runs a shell command", json!({"type": "object", "properties": {"command": {"type": "array", "items": {"type": "string"}}, "workdir": {"type": "string"}, "timeout_ms": {"type": "number"}}, "required": ["command"]}));
        let plan = f("update_plan", "Updates the task plan", json!({"type": "object", "properties": {"plan": {"type": "array"}}, "required": ["plan"]}));
        let (name, args, choice) = choose_write_tool(&[shell.clone(), plan.clone(), patch], &wd()).unwrap();
        assert_eq!((name.as_str(), choice.class), ("apply_patch", "patch"));
        assert_eq!(args["input"], json!(add_file_patch()));
        let (name, args, _) = choose_write_tool(&[plan.clone(), shell], &wd()).unwrap();
        assert_eq!(name, "shell");
        assert_eq!(args["command"], json!(["bash", "-lc", "printf noomesh > '/tmp/ws/work/probe.txt'"]));
        let exec = f("exec_command", "Runs a command in a PTY", json!({"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}));
        let (name, args, _) = choose_write_tool(&[plan.clone(), exec], &wd()).unwrap();
        assert_eq!((name.as_str(), args["cmd"].as_str()), ("exec_command", Some("printf noomesh > '/tmp/ws/work/probe.txt'")));
        assert!(choose_write_tool(&[plan], &wd()).is_none(), "a plan tool writes no file");
    }

    /// Codex 0.163 as observed through the probe (a model it has no
    /// metadata for): no `apply_patch` at all; `exec_command` writes the
    /// file, and neither `create_goal` nor `write_stdin` is a file writer.
    #[test]
    fn codex_0_163_gets_exec_command_not_create_goal_or_write_stdin() {
        let obj = |props: Value, req: &[&str]| json!({"type": "object", "properties": props, "required": req});
        let tools = vec![
            f("exec_command", "Runs a command in a PTY", obj(json!({"cmd": {"type": "string"}, "workdir": {"type": "string"}, "yield_time_ms": {"type": "number"}}), &["cmd"])),
            f("write_stdin", "Writes characters to an existing exec session", obj(json!({"session_id": {"type": "number"}, "chars": {"type": "string"}}), &["session_id"])),
            f("request_user_input", "Ask the user", obj(json!({"questions": {"type": "array"}}), &["questions"])),
            f("view_image", "View a local image", obj(json!({"path": {"type": "string"}}), &["path"])),
            f("multi_agent_v1__spawn_agent", "Spawn a sub-agent", obj(json!({"message": {"type": "string"}}), &["message"])),
            f("get_goal", "Get the goal", obj(json!({}), &[])),
            f("create_goal", "Create a goal", obj(json!({"objective": {"type": "string"}}), &["objective"])),
            f("update_goal", "Update the goal", obj(json!({"status": {"type": "string"}}), &["status"])),
        ];
        let (name, args, choice) = choose_write_tool(&tools, &wd()).unwrap();
        assert_eq!((name.as_str(), choice.class), ("exec_command", "shell"));
        assert_eq!(args, json!({"cmd": "printf noomesh > '/tmp/ws/work/probe.txt'"}));
    }

    #[test]
    fn an_editor_with_a_command_enum_is_told_to_create() {
        let t = f("str_replace_editor", "view, create, edit files", json!({"type": "object", "properties": {"command": {"type": "string", "enum": ["view", "create", "str_replace"]}, "path": {"type": "string"}, "file_text": {"type": "string"}}, "required": ["command", "path"]}));
        let (_, args, choice) = choose_write_tool(&[t], &wd()).unwrap();
        assert_eq!(choice.class, "edit");
        assert_eq!(args, json!({"command": "create", "path": "/tmp/ws/work/probe.txt", "file_text": "noomesh"}));
    }

    async fn post(url: &str, body: Value) -> reqwest::Response {
        reqwest::Client::builder().no_proxy().build().unwrap().post(format!("{url}/v1/chat/completions")).json(&body).send().await.unwrap()
    }

    #[tokio::test]
    async fn the_file_script_calls_a_tool_then_reports_done_streamed_or_not() {
        let m = MockModel::start(Script::File { workdir: wd() }).await.unwrap();
        let tools = json!([f("Write", "Writes a file", json!({"type": "object", "properties": {"file_path": {"type": "string"}, "content": {"type": "string"}}, "required": ["file_path", "content"]}))]);
        let v: Value = post(m.url(), json!({"model": "x", "messages": [{"role": "user", "content": "go"}], "tools": tools})).await.json().await.unwrap();
        let call = &v["choices"][0]["message"]["tool_calls"][0]["function"];
        assert_eq!(call["name"], "Write");
        assert_eq!(serde_json::from_str::<Value>(call["arguments"].as_str().unwrap()).unwrap()["content"], "noomesh");
        let text = post(m.url(), json!({"model": "x", "stream": true, "stream_options": {"include_usage": true}, "tools": tools,
            "messages": [{"role": "user", "content": "go"}, {"role": "assistant", "tool_calls": []}, {"role": "tool", "tool_call_id": "c", "content": "ok"}]}))
        .await
        .text()
        .await
        .unwrap();
        assert!(text.contains("NOO_RESULT: done") && text.contains("\"total_tokens\":49") && text.trim_end().ends_with("data: [DONE]"), "{text}");
        let calls = m.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].answered, "tool_call: Write");
        assert_eq!(calls[0].chosen.as_ref().unwrap().arg_keys, ["content", "file_path"]);
        assert!(calls[1].had_tool_result && calls[1].stream);
        m.shutdown().await;
    }

    #[tokio::test]
    async fn the_reply_script_always_answers_ok() {
        let m = MockModel::start(Script::Reply).await.unwrap();
        let v: Value = post(m.url(), json!({"model": "x", "messages": [{"role": "user", "content": "hi"}]})).await.json().await.unwrap();
        assert_eq!(v["choices"][0]["message"]["content"], "NOO_RESULT: ok");
        m.shutdown().await;
    }
}
