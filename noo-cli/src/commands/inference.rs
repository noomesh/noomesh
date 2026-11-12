// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo inference …` — direct model inference through the gateway.

use crate::http::post_json;
use crate::ui;
use crate::{Globals, Unhandled};

/// Why `inference run` arguments were not turned into a request.
#[derive(Debug, PartialEq)]
enum RunArgsError {
    /// Not this command's surface — fall through to the generic usage error.
    Unhandled,
    /// A flag the gateway would silently drop; refused with a message.
    Unsupported(&'static str),
}

/// Parse `inference run` arguments into `(request body, --user)`. Pure: no
/// request is made here, so a refused flag provably sends nothing.
fn build_run_request(args: &[String]) -> Result<(serde_json::Value, Option<String>), RunArgsError> {
    use RunArgsError::Unhandled;
    let mut prompt: Option<String> = None;
    let mut user: Option<String> = None;
    let mut body = serde_json::json!({ "max_tokens": 512, "temperature": 0.7 });
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--model" | "-m" => body["model"] = iter.next().ok_or(Unhandled)?.as_str().into(),
            // The gateway's InferenceRequest has no `backend` field, so the
            // old flag was silently dropped. Refuse it until it is honoured.
            "--backend" | "-b" => {
                return Err(RunArgsError::Unsupported(
                    "`inference run` does not support -b/--backend yet: the gateway ignores it",
                ))
            }
            "--user" | "-u" => user = Some(iter.next().ok_or(Unhandled)?.to_string()),
            "--node" | "-n" => body["node"] = iter.next().ok_or(Unhandled)?.as_str().into(),
            "--strict-node" => body["node_strict"] = true.into(),
            // Skip RAG, memory, skills and tool schemas: a plain model call.
            "--raw" => body["context"] = false.into(),
            "--max-tokens" => {
                body["max_tokens"] =
                    iter.next().and_then(|v| v.parse::<u64>().ok()).ok_or(Unhandled)?.into()
            }
            "--temperature" | "-t" => {
                body["temperature"] =
                    iter.next().and_then(|v| v.parse::<f64>().ok()).ok_or(Unhandled)?.into()
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if prompt.replace(t.to_string()).is_some() {
                    return Err(Unhandled); // two positionals — not our surface
                }
            }
        }
    }
    let Some(p) = prompt else { return Err(Unhandled) };
    body["prompt"] = p.into();
    Ok((body, user))
}

const RUN_PATH: &str = "/api/inference";

/// What `inference run` got back.
#[derive(Debug, PartialEq)]
enum RunOutcome {
    /// The whole reply and its answer text (never empty).
    Answer(serde_json::Value, String),
    Failed { kind: &'static str, msg: String, hint: Option<&'static str> },
}

/// Judge the gateway's reply. An empty answer is never a success (120:
/// qwen3 on ollama printed "" and exited 0): the gateway's
/// `empty_response` refusal is one line with its reason, and a 200 whose
/// answer is empty (an older gateway) fails the same way.
fn run_outcome(sent: Result<serde_json::Value, (u16, String)>) -> RunOutcome {
    const HINT: Option<&str> = Some("a reasoning model may need a larger --max-tokens; `--json` shows the reply");
    match sent {
        Err((status, body)) => {
            let v = serde_json::from_str::<serde_json::Value>(&body).ok();
            match v.as_ref().filter(|v| v["code"] == "empty_response") {
                Some(v) => RunOutcome::Failed {
                    kind: "empty_response",
                    msg: v["error"].as_str().unwrap_or("the model returned an empty answer").to_string(),
                    hint: HINT,
                },
                None => RunOutcome::Failed {
                    kind: "remote_error",
                    msg: crate::http::remote_error_message(status, RUN_PATH, &body),
                    hint: None,
                },
            }
        }
        Ok(resp) => {
            if resp["success"] == serde_json::json!(false) {
                return RunOutcome::Failed {
                    kind: "remote_error",
                    msg: resp["error"].as_str().unwrap_or("the gateway reported a failure").to_string(),
                    hint: None,
                };
            }
            // The Rust gateway wraps the payload: {"success": true, "data": {"response": …}}.
            // Older/direct backends returned top-level "response"/"text" — accept all.
            let text = resp["data"]["response"]
                .as_str()
                .or_else(|| resp["response"].as_str())
                .or_else(|| resp["text"].as_str())
                .unwrap_or_default()
                .to_string();
            if text.trim().is_empty() {
                return RunOutcome::Failed {
                    kind: "empty_response",
                    msg: "the gateway reported success but the answer is empty".into(),
                    hint: HINT,
                };
            }
            RunOutcome::Answer(resp, text)
        }
    }
}

/// `noo inference run <prompt> [-m MODEL] [--node ID [--strict-node]]
///  [--raw] [--max-tokens N] [--temperature F]`
/// POST /api/inference. Without `--raw` the gateway runs the full pipeline
/// (RAG, memory, skills, tool schemas); `--raw` sends `context: false`.
pub fn inference_run(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut body, user) = match build_run_request(args) {
        Ok(v) => v,
        Err(RunArgsError::Unhandled) => return Err(Unhandled),
        Err(RunArgsError::Unsupported(msg)) => crate::output::fail(
            g.json,
            crate::output::ExitCode::Usage,
            "unsupported_flag",
            msg,
            Some("noo inference run <prompt> -n <node>"),
        ),
    };

    // Bind an operator identity so memory/KB context resolves a scope
    // instead of failing closed on a multi-account install.
    // The CLI authenticates via cluster-HMAC (trusted operator secret), so the
    // gateway honours this claimed user_id. Precedence: --user > NOO_OPERATOR_USER
    // > NOO_ADMIN_USER. Omitted when none set (single-user: user_id is ignored).
    let user = user
        .or_else(|| std::env::var("NOO_OPERATOR_USER").ok())
        .or_else(|| std::env::var("NOO_ADMIN_USER").ok())
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    if let Some(u) = user {
        body["user_id"] = u.into();
    }

    // Inference is slow — match the Python CLI's 120s unless --timeout given.
    let sent = crate::http::request_status(g, "POST", RUN_PATH, Some(&body), true, 120);
    let (resp, text) = match run_outcome(sent) {
        RunOutcome::Answer(resp, text) => (resp, text),
        RunOutcome::Failed { kind, msg, hint } => crate::output::fail(
            g.json,
            crate::output::ExitCode::RemoteError,
            kind,
            &msg,
            hint,
        ),
    };
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    // `-n` is a preference: say when another node answered.
    if let Some(node) = resp["data"]["requested_node"].as_str() {
        let model = resp["data"]["model"].as_str().unwrap_or("another model");
        let why = resp["data"]["node_unavailable"].as_str().unwrap_or("unavailable");
        ui::warned(&format!("answered by {model} — {node} could not: {why}"));
    }
    println!("{text}");
    Ok(0)
}

/// `noo inference agent PROMPT` — POST /api/agent/run: runs the prompt
/// through the gateway's agent role runner. The route reads only `prompt`
/// (and `role`/`conversation_id`), so the old `-m`, `--max-iters` and
/// `--no-tools` flags, which it silently ignored, are refused with a message.
/// Synchronous and slow — Python parity: 120s timeout, spinner while waiting.
pub fn inference_agent(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut prompt: Option<String> = None;
    let mut body = serde_json::json!({});
    for tok in args {
        match tok.as_str() {
            "--model" | "-m" | "--max-iters" | "--no-tools" => {
                crate::output::fail(
                    g.json,
                    crate::output::ExitCode::Usage,
                    "unsupported_flag",
                    &format!("`inference agent` no longer accepts {tok}: the gateway ignores it"),
                    Some("noo inference run <prompt> -m <model>"),
                );
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if prompt.replace(t.to_string()).is_some() {
                    return Err(Unhandled); // two positionals — not our surface
                }
            }
        }
    }
    let Some(p) = prompt else { return Err(Unhandled) };
    body["prompt"] = p.into();

    let step = super::Spinner::start(g, "running agentic loop");
    let resp = post_json(g, "/api/agent/run", &body, true, 120);
    step.done(Some("agentic loop finished"));

    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    // Python reads top-level fields; tolerate the Rust gateway's
    // {"success": true, "data": {…}} wrap like `inference run` does.
    let d = if resp["data"].is_object() { &resp["data"] } else { &resp };
    // The response text is the captured value; the tool-use summary is
    // narration (stdout, dropped by --quiet).
    ui::value(d["response"].as_str().unwrap_or_default());
    ui::guide(&[
        ("noo inference run <prompt>", "the same model without the tool loop, for comparison"),
    ]);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn raw_sends_context_false() {
        let (body, _) = build_run_request(&a(&["hi", "--raw"])).unwrap();
        assert_eq!(body["context"], serde_json::json!(false));
        assert_eq!(body["prompt"], "hi");
    }

    #[test]
    fn without_raw_the_body_has_no_context_key() {
        let (body, _) = build_run_request(&a(&["hi", "-n", "awolf"])).unwrap();
        assert!(body.get("context").is_none(), "{body}");
        assert_eq!(body["node"], "awolf");
        assert_eq!(body["max_tokens"], 512);
    }

    /// 120: the gateway's 502 `empty_response` is one line with its reason;
    /// a 200 with an empty answer (an older gateway) fails too; a real
    /// answer passes; any other error keeps the generic wording.
    #[test]
    fn an_empty_answer_never_exits_zero() {
        use serde_json::json;
        let refusal = json!({"success": false, "code": "empty_response",
            "error": "the model returned only reasoning and no answer (finish_reason: stop)",
            "finish_reason": "stop", "reasoning": "five words", "node": "pop-os"}).to_string();
        match run_outcome(Err((502, refusal))) {
            RunOutcome::Failed { kind, msg, hint } => {
                assert_eq!(kind, "empty_response");
                assert_eq!(msg, "the model returned only reasoning and no answer (finish_reason: stop)");
                assert!(hint.is_some());
            }
            other => panic!("{other:?}"),
        }
        for old in [json!({"success": true, "data": {"response": "", "node": "pop-os"}}), json!({"success": true, "data": {"response": "  \n"}})] {
            assert!(matches!(run_outcome(Ok(old.clone())), RunOutcome::Failed { kind: "empty_response", .. }), "{old}");
        }
        assert!(matches!(run_outcome(Ok(json!({"success": false, "error": "boom"}))),
            RunOutcome::Failed { kind: "remote_error", ref msg, .. } if msg == "boom"));
        match run_outcome(Err((500, "{\"detail\":\"down\"}".into()))) {
            RunOutcome::Failed { kind, msg, .. } => { assert_eq!(kind, "remote_error"); assert!(msg.contains("down") && msg.contains("500"), "{msg}"); }
            other => panic!("{other:?}"),
        }
        let ok = json!({"success": true, "data": {"response": "Hello there, how are you?"}});
        assert_eq!(run_outcome(Ok(ok.clone())), RunOutcome::Answer(ok, "Hello there, how are you?".into()));
    }

    #[test]
    fn backend_flag_is_refused_before_any_request() {
        for flag in ["-b", "--backend"] {
            let err = build_run_request(&a(&["hi", flag, "vllm"])).unwrap_err();
            match err {
                RunArgsError::Unsupported(m) => assert!(m.contains("not support"), "{m}"),
                other => panic!("expected Unsupported, got {other:?}"),
            }
        }
    }
}
