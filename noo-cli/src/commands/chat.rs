// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo chat` — interactive REPL against the cluster gateway (WP-C1).
//!
//! Probe `GET /health` (2s), then stream each turn through
//! `POST /api/inference/chat`: the COORDINATOR turn the console runs over
//! `/ws/coordinator` — the signed-in user's knowledge base, memory and tools,
//! scoped to their identity and View-as perspective — framed as SSE
//! (`gateway-rust/src/routes/inference.rs` `coordinator_chat_stream`).
//! Until 0.6.25 it spoke `/api/inference/stream`, a raw model proxy with no
//! retrieval: `noo chat` never used your documents (0 of 15 in the matrix
//! RAG probe) while console chat did. The identity is the login token's
//! subject; the body names no user.
//!
//! Stream framing tolerance: depending on the resolved backend the gateway
//! proxies different chunk shapes down the same SSE pipe —
//!   - OpenAI chunks (vLLM):        {"choices":[{"delta":{"content": …}}]}
//!   - Ollama NDJSON (/api/chat):   {"message":{"content": …},"done":bool}
//!   - llama.cpp (/completion):     {"content": …,"stop":bool}
//!   - legacy Python-gateway NDJSON: {"type":"content","text": …} /
//!     {"type":"metadata",…} / {"type":"error",…} / {"type":"done"}
//!   - error envelope:              {"error": …}
//! Lines may or may not carry a `data: ` prefix; `[DONE]` ends a turn.
//!
//! NOT ported (a usage error, exit 2 — the Python CLI is gone): the
//! in-process local-agent fallback — `--no-use-cluster`, `--config`,
//! `--base-url`, `--tool-mode`. When the gateway is unreachable this command
//! exits 3 with a pointer to `noo stack start` instead of building a local
//! agent.
//!
//! Native additions over the Python surface (agent-first contract):
//!   - `--message TEXT` — one-shot mode: send one message, stream the reply,
//!     exit. Works without a TTY and is the only mode `--json` supports
//!     (envelope: {"response","backend","conversation_id"}, plus
//!     "truncated": {"evaluated","sent_estimate"} when the backend cut the
//!     prompt, i802).
//!   - non-TTY stdin without `--message` errors (exit 2) instead of hanging.
//!   - the whole REPL session shares one `conversation_id` (the Python
//!     cluster path sent none, so every turn forgot the last).

use crate::http::{get_json_opt, post_json_stream_try};

/// The coordinator chat stream (gateway `CHAT_STREAM_PATH`).
const CHAT_PATH: &str = "/api/inference/chat";

/// How long a turn may run, end to end. An agentic turn (tools, retrieval,
/// an approval wait of up to the gateway's window) runs far past the old
/// 120 s raw-stream bound; `--timeout` still wins.
const TURN_TIMEOUT_SECS: u64 = 1800;

/// Past an approval's window, this much more before `noo chat` stops
/// waiting: the gateway decides (expires) at the window, and its verdict
/// echo needs a moment to arrive.
const APPROVAL_GRACE_SECS: u64 = 30;

/// One turn's request body. It names no user: the gateway takes the
/// identity from the login token only, and ignores any body `user_id`.
fn turn_body(prompt: &str, model: &Option<String>, conversation_id: &str) -> serde_json::Value {
    serde_json::json!({
        "prompt": prompt,
        "model": model,
        "conversation_id": conversation_id,
    })
}
use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};
use std::io::{BufRead as _, Write as _};

/// Parsed native surface of `noo chat`. Anything else → `Err(Unhandled)`.
#[derive(Debug, Default, PartialEq)]
struct ChatArgs {
    model: Option<String>,
    message: Option<String>,
}

/// Parse the token stream after `chat`. `--use-cluster` is the Python
/// default and thus a no-op; every local-fallback flag is a usage error.
fn parse_args(args: &[String]) -> Result<ChatArgs, Unhandled> {
    let mut out = ChatArgs::default();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--model" => out.model = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--message" => out.message = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--use-cluster" => {} // typer bool default — accepted, no-op
            // --no-use-cluster / --config / --base-url / --tool-mode and any
            // positional belonged to the retired Python local-agent surface (now a usage error).
            _ => return Err(Unhandled),
        }
    }
    Ok(out)
}

/// Python parity: `/exit`, `/quit`, `quit`, `exit` (case-insensitive) end the REPL.
fn is_exit_command(input: &str) -> bool {
    matches!(input.to_ascii_lowercase().as_str(), "/exit" | "/quit" | "quit" | "exit")
}

/// What one parsed stream line means for the turn.
#[derive(Debug, Default, PartialEq)]
struct StreamEvent {
    token: Option<String>,
    /// "backend on node" / metadata hint, printed after the turn.
    meta: Option<String>,
    done: bool,
    error: Option<String>,
    /// An exec-approval the turn is waiting on: (request id, tool, window s).
    approval: Option<(String, String, u64)>,
    /// A line for the person, not part of the answer (a tool starting, an
    /// approval verdict).
    note: Option<String>,
    /// The done frame's `truncation` (i802): the backend cut the prompt.
    /// (evaluated, sent_estimate): it read M of about N tokens.
    truncated: Option<(u64, u64)>,
}

/// Map one JSON chunk (any of the framings listed in the module doc) to a
/// [`StreamEvent`]. Unknown shapes are ignored (empty event).
fn extract_event(v: &serde_json::Value) -> StreamEvent {
    let mut ev = StreamEvent::default();
    // Legacy Python-gateway NDJSON has an explicit discriminator.
    if let Some(t) = v["type"].as_str() {
        match t {
            "content" => ev.token = v["text"].as_str().map(str::to_string),
            "metadata" => {
                ev.meta = Some(format!(
                    "{} on {}",
                    v["backend"].as_str().unwrap_or("?"),
                    v["node_id"].as_str().unwrap_or("?")
                ))
            }
            "error" => {
                ev.error = Some(v["message"].as_str().or(v["text"].as_str()).unwrap_or("unknown error").to_string())
            }
            "done" => {
                ev.done = true;
                if v["truncated"].as_bool() == Some(true) {
                    let t = &v["truncation"];
                    ev.truncated = t["evaluated"].as_u64().zip(t["sent_estimate"].as_u64());
                }
            }
            "approval_request" => {
                ev.approval = Some((
                    v["request_id"].as_str().unwrap_or("?").to_string(),
                    v["tool"].as_str().unwrap_or("a tool").to_string(),
                    v["window_secs"].as_u64().unwrap_or(300),
                ))
            }
            "approval_outcome" => ev.note = v["text"].as_str().map(str::to_string),
            "tool_call" => {
                ev.note = Some(format!(
                    "· {}",
                    v["name"].as_str().or(v["tool"].as_str()).unwrap_or("tool")
                ))
            }
            // thinking, tool_result, keepalive: not shown.
            _ => {}
        }
        return ev;
    }
    // Error envelope ({"error": …} from resolve/cloud/backend failures).
    if let Some(e) = v["error"].as_str() {
        ev.error = Some(e.to_string());
        return ev;
    }
    // OpenAI chunk (vLLM / OpenAI-compat proxy).
    if let Some(choice) = v["choices"].get(0) {
        ev.token = choice["delta"]["content"].as_str().map(str::to_string);
        ev.done = choice["finish_reason"].as_str().is_some();
        return ev;
    }
    // Ollama /api/chat NDJSON.
    if v["message"].is_object() {
        ev.token = v["message"]["content"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
        ev.done = v["done"].as_bool() == Some(true);
        return ev;
    }
    // llama.cpp /completion.
    if let Some(c) = v["content"].as_str() {
        ev.token = Some(c.to_string()).filter(|s| !s.is_empty());
        ev.done = v["stop"].as_bool() == Some(true);
        return ev;
    }
    ev
}

/// What one turn returned: the full response text, the optional backend
/// hint, and the backend's cut of the prompt when the gateway reported one
/// (evaluated, sent_estimate; i802).
type TurnOutput = (String, Option<String>, Option<(u64, u64)>);

/// Run one chat turn: POST the prompt, stream tokens through `on_token`, and
/// return [`TurnOutput`]. `Err` is a
/// per-turn failure — the REPL prints it and continues (Python parity),
/// one-shot mode exits on it.
fn stream_turn(
    g: &Globals,
    prompt: &str,
    model: &Option<String>,
    conversation_id: &str,
    mut on_token: impl FnMut(&str),
) -> Result<TurnOutput, String> {
    let body = turn_body(prompt, model, conversation_id);
    let mut resp = post_json_stream_try(g, CHAT_PATH, &body, true, TURN_TIMEOUT_SECS)?;

    let status = resp.status().as_u16();
    if !(200..=299).contains(&status) {
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        let detail = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v["detail"]
                    .as_str()
                    .or_else(|| v["error"].as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| format!("HTTP {status}: {text}"));
        return Err(detail);
    }

    // The Rust gateway advertises the resolved backend in headers; the legacy
    // Python gateway sent a "metadata" stream event instead. Accept both.
    let mut meta = match (
        resp.headers().get("x-backend").and_then(|h| h.to_str().ok()),
        resp.headers().get("x-model").and_then(|h| h.to_str().ok()),
    ) {
        (Some(b), Some(m)) => Some(format!("{b} · {m}")),
        (Some(b), None) => Some(b.to_string()),
        _ => None,
    };

    let mut full = String::new();
    let mut truncated: Option<(u64, u64)> = None;
    // An approval this CLI cannot answer is waited on, bounded: the gateway
    // sends a keepalive every 30 s, so the bound is checked at least that
    // often. Returning drops the connection, which ends the turn there.
    let mut waiting: Option<(String, String, u64, std::time::Instant)> = None;
    let reader = std::io::BufReader::new(resp.body_mut().as_reader());
    for line in reader.lines() {
        let line = line.map_err(|e| format!("stream interrupted: {e}"))?;
        if let Some((id, tool, window, since)) = &waiting {
            if approval_overdue(since.elapsed(), *window) {
                return Err(approval_expired_line(id, tool, *window));
            }
        }
        // Accept both framings: `data: {json}` (SSE) and bare NDJSON.
        let payload = line.strip_prefix("data: ").unwrap_or(&line).trim();
        if payload.is_empty() {
            continue;
        }
        if payload == "[DONE]" {
            break;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        let ev = extract_event(&v);
        if let Some(err) = ev.error {
            return Err(err);
        }
        if let Some(m) = ev.meta {
            meta = Some(m);
        }
        if let Some((id, tool, window)) = ev.approval {
            eprintln!("{}", ui::warn(&approval_notice(&id, &tool, window)));
            waiting = Some((id, tool, window, std::time::Instant::now()));
        }
        if let Some(n) = ev.note {
            eprintln!("{}", ui::muted(&n));
            if n.contains("approved") || n.contains("denied") || n.contains("expired") {
                waiting = None;
            }
        }
        if let Some(t) = ev.token {
            on_token(&t);
            full.push_str(&t);
        }
        if ev.truncated.is_some() {
            truncated = ev.truncated;
        }
        if ev.done {
            break;
        }
    }
    Ok((full, meta, truncated))
}

/// The one line printed after a turn whose prompt the backend cut (i802):
/// the answer above was made without most of its instructions.
fn truncated_line(evaluated: u64, sent_estimate: u64) -> String {
    format!(
        "the model read only {evaluated} of about {sent_estimate} prompt tokens: its backend cut the prompt, \
         so this answer was made without most of its instructions"
    )
}

/// What the person sees when the turn needs an approval: where to give it,
/// and how long `noo chat` will wait.
fn approval_notice(id: &str, tool: &str, window: u64) -> String {
    format!(
        "waiting for approval: {tool} (request {id}). Approve it in the console, or in another terminal with \
         `noo approval approve <id>` using that request id; waiting up to {}s.",
        window + APPROVAL_GRACE_SECS
    )
}

fn approval_overdue(waited: std::time::Duration, window: u64) -> bool {
    waited.as_secs() > window + APPROVAL_GRACE_SECS
}

fn approval_expired_line(id: &str, tool: &str, window: u64) -> String {
    format!(
        "approval {id} for {tool} was not given within {}s, so this turn was ended. Approve it with \
         `noo approval approve <id>` before the window closes, or send the message again.",
        window + APPROVAL_GRACE_SECS
    )
}

/// `noo chat [--model M] [--message TEXT]` — cluster chat REPL / one-shot.
pub fn chat(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let parsed = parse_args(args)?;

    if parsed.message.is_none() {
        // Agent-first contract: never block an agent/pipe on an interactive
        // prompt, and never stream free-text tokens in --json mode.
        if g.json {
            fail(
                true,
                ExitCode::Usage,
                "usage",
                "--json requires --message TEXT (the chat REPL is interactive)",
                Some("pass --message \"…\" for a one-shot machine-readable exchange"),
            );
        }
        if unsafe { libc::isatty(0) } != 1 {
            fail(
                g.json,
                ExitCode::Usage,
                "no_tty",
                "stdin is not a TTY and no --message was given — refusing to start an interactive REPL",
                Some("pass --message \"…\" for one-shot chat, or run from a terminal"),
            );
        }
    }

    // Health probe — Python parity: 2s timeout, ANY failure means the
    // cluster path is unavailable. The retired Python CLI built a local
    // in-process agent here; that fallback is not ported (plan §2).
    let base = crate::envfile::gateway_url(&g.gateway_override);
    if get_json_opt(g, "/health", false, 2).is_none() {
        fail(
            g.json,
            ExitCode::GatewayUnreachable,
            "gateway_unreachable",
            &format!("cluster gateway at {base} is not reachable"),
            // `--no-use-cluster` was the Python CLI's flag, never this
            // parser's; nothing reaches that CLI any more.
            Some("start the stack with `noo stack start`, then check it with `noo health`"),
        );
    }

    // One session id for the whole REPL so the gateway keeps turn context.
    let conversation_id = format!(
        "cli-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        std::process::id()
    );

    // ── one-shot mode ──
    if let Some(message) = parsed.message {
        let result = stream_turn(g, &message, &parsed.model, &conversation_id, |t| {
            if !g.json {
                print!("{t}");
                let _ = std::io::stdout().flush();
            }
        });
        match result {
            Ok((full, meta, truncated)) => {
                if g.json {
                    let mut out = serde_json::json!({
                        "response": full,
                        "backend": meta,
                        "conversation_id": conversation_id,
                    });
                    if let Some((evaluated, sent_estimate)) = truncated {
                        out["truncated"] = serde_json::json!({"evaluated": evaluated, "sent_estimate": sent_estimate});
                    }
                    println!("{out}");
                } else {
                    println!();
                    if let Some((evaluated, sent_estimate)) = truncated {
                        eprintln!("{}", ui::warn(&truncated_line(evaluated, sent_estimate)));
                    }
                    if let Some(m) = meta {
                        eprintln!("{}", ui::muted(&format!("[{m}]")));
                    }
                }
                return Ok(0);
            }
            Err(e) => fail(g.json, ExitCode::RemoteError, "chat_failed", &e, None),
        }
    }

    // ── interactive REPL (Python's prompts and slash-commands) ──
    // Interactive entry point: the wordmark (empty unless styled), then the
    // session banner. stdout — a person is here (guide §3/§5).
    print!("{}", ui::wordmark(env!("CARGO_PKG_VERSION")));
    println!("{}", ui::muted(&format!("gateway {base} · /exit or /quit ends the conversation")));
    println!();
    let stdin = std::io::stdin();
    loop {
        print!("{}", ui::emph("you> "));
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => break, // EOF / read error ends the session
            Ok(_) => {}
        }
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if is_exit_command(input) {
            break;
        }

        print!("{}", ui::cmd("noo> "));
        let _ = std::io::stdout().flush();
        match stream_turn(g, input, &parsed.model, &conversation_id, |t| {
            print!("{t}");
            let _ = std::io::stdout().flush();
        }) {
            Ok((_, meta, truncated)) => {
                println!();
                if let Some((evaluated, sent_estimate)) = truncated {
                    eprintln!("{}", ui::warn(&truncated_line(evaluated, sent_estimate)));
                }
                if let Some(m) = meta {
                    eprintln!("{}", ui::muted(&format!("[{m}]")));
                    eprintln!();
                }
            }
            // Per-turn errors keep the REPL alive (Python parity).
            Err(e) => {
                println!();
                ui::failed(&e, None);
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    // ── arg parsing ──

    #[test]
    fn parses_empty_and_flags() {
        assert_eq!(parse_args(&[]).unwrap(), ChatArgs::default());
        let a = parse_args(&argv(&["--model", "qwen3:8b", "--message", "hi"])).unwrap();
        assert_eq!(a.model.as_deref(), Some("qwen3:8b"));
        assert_eq!(a.message.as_deref(), Some("hi"));
    }

    #[test]
    fn use_cluster_default_flag_is_noop() {
        assert!(parse_args(&argv(&["--use-cluster"])).is_ok());
    }

    #[test]
    fn local_fallback_surface_falls_through() {
        // Everything owned by the retired Python in-process agent path is
        // refused as a usage error (there is no Python CLI to serve it).
        for flags in [
            &["--no-use-cluster"][..],
            &["--config", "x.yaml"],
            &["--base-url", "http://x"],
            &["--tool-mode", "off"],
            &["positional"],
            &["--bogus"],
        ] {
            assert!(parse_args(&argv(flags)).is_err(), "{flags:?} must fall through");
        }
    }

    #[test]
    fn flag_missing_value_falls_through() {
        assert!(parse_args(&argv(&["--model"])).is_err());
        assert!(parse_args(&argv(&["--message"])).is_err());
    }

    // ── slash commands ──

    #[test]
    fn exit_commands_match_python() {
        for s in ["/exit", "/quit", "quit", "exit", "/EXIT", "Quit"] {
            assert!(is_exit_command(s), "{s} should exit");
        }
        for s in ["/help", "hello", "exit now", ""] {
            assert!(!is_exit_command(s), "{s} should not exit");
        }
    }

    // ── the coordinator route ──

    #[test]
    fn a_turn_names_no_user_and_targets_the_coordinator_stream() {
        let b = turn_body("hi", &Some("m".into()), "cli-1");
        assert!(b.get("user_id").is_none(), "the identity is the login token's subject, never the body");
        assert_eq!(b["prompt"], "hi");
        assert_eq!(CHAT_PATH, "/api/inference/chat");
        assert_ne!(CHAT_PATH, "/api/inference/stream", "the raw proxy retrieves nothing");
    }

    /// i802: the done frame says the backend cut the prompt; the turn ends
    /// with one warn line naming how much of it the model read.
    #[test]
    fn a_cut_prompt_on_the_done_frame_is_read_and_said() {
        let e = ev(r#"{"type":"done","tokens_in":2051,"truncated":true,"truncation":{"sent_estimate":8800,"evaluated":2051,"context":4096}}"#);
        assert!(e.done);
        assert_eq!(e.truncated, Some((2051, 8800)));
        assert_eq!(ev(r#"{"type":"done","tokens_in":900}"#).truncated, None, "no flag, nothing said");
        assert_eq!(ev(r#"{"type":"done","truncated":false,"truncation":{"sent_estimate":1,"evaluated":1}}"#).truncated, None);
        let line = truncated_line(2051, 8800);
        assert_eq!(
            line,
            "the model read only 2051 of about 8800 prompt tokens: its backend cut the prompt, so this answer was made without most of its instructions"
        );
    }

    #[test]
    fn an_approval_is_announced_with_where_to_approve_and_the_wait_is_bounded() {
        let e = ev(r#"{"type":"approval_request","request_id":"r9","tool":"shell_exec","window_secs":120}"#);
        assert_eq!(e.approval, Some(("r9".into(), "shell_exec".into(), 120)));
        let n = approval_notice("r9", "shell_exec", 120);
        assert!(n.contains("request r9") && n.contains("noo approval approve <id>") && n.contains("console") && n.contains("150s"), "{n}");
        assert!(!approval_overdue(std::time::Duration::from_secs(150), 120));
        assert!(approval_overdue(std::time::Duration::from_secs(151), 120));
        let line = approval_expired_line("r9", "shell_exec", 120);
        assert!(line.contains("turn was ended") && line.contains("r9"), "{line}");
    }

    #[test]
    fn a_coordinator_error_event_carries_its_text() {
        assert_eq!(ev(r#"{"type":"error","text":"No backend available"}"#).error.as_deref(), Some("No backend available"));
        assert_eq!(ev(r#"{"type":"keepalive"}"#), StreamEvent::default());
    }

    // ── stream chunk shapes ──

    fn ev(json: &str) -> StreamEvent {
        extract_event(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn extracts_openai_chunk() {
        let e = ev(r#"{"choices":[{"delta":{"content":"Hel"},"finish_reason":null}]}"#);
        assert_eq!(e.token.as_deref(), Some("Hel"));
        assert!(!e.done && e.error.is_none());
        let e = ev(r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#);
        assert!(e.done && e.token.is_none());
    }

    #[test]
    fn extracts_ollama_chunk() {
        let e = ev(r#"{"message":{"role":"assistant","content":"Hi"},"done":false}"#);
        assert_eq!(e.token.as_deref(), Some("Hi"));
        assert!(!e.done);
        let e = ev(r#"{"message":{"role":"assistant","content":""},"done":true}"#);
        assert!(e.done && e.token.is_none());
    }

    #[test]
    fn extracts_llamacpp_chunk() {
        let e = ev(r#"{"content":"tok","stop":false}"#);
        assert_eq!(e.token.as_deref(), Some("tok"));
        let e = ev(r#"{"content":"","stop":true}"#);
        assert!(e.done && e.token.is_none());
    }

    #[test]
    fn extracts_legacy_python_events() {
        let e = ev(r#"{"type":"content","text":"T"}"#);
        assert_eq!(e.token.as_deref(), Some("T"));
        let e = ev(r#"{"type":"metadata","backend":"ollama","node_id":"n1"}"#);
        assert_eq!(e.meta.as_deref(), Some("ollama on n1"));
        let e = ev(r#"{"type":"error","message":"boom"}"#);
        assert_eq!(e.error.as_deref(), Some("boom"));
        assert!(ev(r#"{"type":"done"}"#).done);
    }

    #[test]
    fn extracts_error_envelope_and_ignores_unknown() {
        assert_eq!(ev(r#"{"error":"No backend available"}"#).error.as_deref(),
                   Some("No backend available"));
        assert_eq!(ev(r#"{"something":"else"}"#), StreamEvent::default());
    }
}
