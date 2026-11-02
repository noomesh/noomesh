// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo agents …` — multi-agent collaboration surfaces (Rust gateway routes
//! in `routes/agents.rs` and `routes/peers.rs`).
//!
//! Ported: list, collaborate, peer list, peer card, peer dispatch.
//! Not in the CLI:
//!   - `peer register`/`deregister` are API-only; there is no `noo` verb (an
//!     unknown verb is a usage error, exit 2).
//!
//! Note: the Python `agents *` commands DO send auth headers; the older
//! read-only ports predate that fix — either side works now.

use super::{ago, truncate};
use crate::args::{ArgError, Args};
use crate::http::{get_json, post_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo agents list` — GET /api/agents/roles. The Rust gateway wraps the
/// list ({"roles": [...]}); accept a bare array too (old Python gateway
/// shape, which is what the Python renderer still assumes).
pub fn agents_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/agents/roles", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let roles = body["roles"].as_array().or_else(|| body.as_array()).unwrap_or(&empty);
    if roles.is_empty() {
        println!("{}", ui::muted("no agent roles"));
        return Ok(0);
    }
    println!("{}", ui::header("agent roles", Some(&format!("{} roles", roles.len()))));
    println!("{}", ui::section("roles"));
    let rows: Vec<Vec<String>> = roles
        .iter()
        .map(|r| {
            let tools = r["preferred_tools"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            vec![
                truncate(r["role"].as_str().unwrap_or("?"), 16),
                r["max_tool_loops"].as_u64().unwrap_or(0).to_string(),
                truncate(&tools, 80),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(&[Col::left("role"), Col::right("max loops"), Col::left("preferred tools")], &rows)
    );
    Ok(0)
}

pub(crate) fn parse_collaborate_with(a: &mut Args) -> Result<(String, Option<Vec<String>>), ArgError> {
    let roles = a
        .value(&["--roles", "-r"])?
        .map(|csv| csv.split(',').map(|r| r.trim().to_string()).collect::<Vec<String>>());
    let task = a.one("<task>")?;
    Ok((task, roles))
}

/// `noo agents collaborate TASK [--roles/-r CSV]` — POST /api/agents/collaborate.
/// The handler reads only `task`, `roles` and `wait`; `--workflow/-w` and
/// `--mode/-m` were sent and ignored, so they are refused with a message.
/// Synchronous: the gateway returns when the collaboration finishes
/// (Python parity: 300s timeout, spinner while waiting).
pub fn agents_collaborate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    // The gateway ignored these, so they are refused with the reason.
    if let Some(tok) = args.iter().find(|t| matches!(t.as_str(), "--workflow" | "-w" | "--mode" | "-m")) {
        crate::output::fail(
            g.json,
            crate::output::ExitCode::Usage,
            "flag_removed",
            &format!("agents collaborate no longer takes {tok}: the gateway ignored it"),
            Some("choose who works with --roles/-r (default: researcher,analyst); `noo agents list` shows the roles"),
        );
    }
    let (task, roles) = parse_collaborate_with(&mut Args::new(args))?;
    let mut payload = serde_json::json!({});
    if let Some(roles) = roles {
        payload["roles"] = roles.into();
    }
    payload["task"] = task.into();

    let step = super::Spinner::start(g, "agents collaborating");
    let body = post_json(g, "/api/agents/collaborate", &payload, true, 300);
    step.done(Some("agents collaborated"));

    if g.json {
        println!("{body}");
        return Ok(0);
    }
    // Each role's output is DATA: stdout, verbatim, under a section label.
    if let Some(results) = body["results"].as_object() {
        for (role, output) in results {
            println!("{}", ui::section(role));
            match output.as_str() {
                Some(s) => println!("{s}"),
                None => println!("{output}"),
            }
        }
    }
    let mut rows: Vec<(&str, String)> = Vec::new();
    if let Some(t) = body["task_id"].as_str() {
        rows.push(("task", t.to_string()));
    }
    if let Some(t) = body["thread_id"].as_str() {
        rows.push(("thread", t.to_string()));
    }
    if body["settled"].as_bool() == Some(false) {
        rows.push(("note", "still running — `noo tasks show <task>` or `noo agents thread <thread>` for the rest".to_string()));
    }
    if !rows.is_empty() {
        println!();
        print!("{}", ui::kv(&rows));
    }
    ui::close_done("collaboration complete");
    ui::guide(&[
        ("noo agents list", "the agent roles available for the next run"),
        ("noo agents inbox", "messages the agents left for each other during the run"),
    ]);
    Ok(0)
}

/// `noo agents peer list [--connected]` — GET /api/agents/peer/.
pub fn agents_peer_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut connected_only = false;
    for tok in args {
        match tok.as_str() {
            "--connected" | "-c" => connected_only = true,
            _ => return Err(Unhandled),
        }
    }
    let body = get_json(g, "/api/agents/peer/", true, 10);
    let empty = Vec::new();
    let peers: Vec<&serde_json::Value> = body["peers"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|p| !connected_only || p["is_connected"].as_bool().unwrap_or(false))
        .collect();
    if g.json {
        // Python parity: --connected filters the JSON too ({"peers": [...]}).
        let filtered: Vec<serde_json::Value> = peers.iter().map(|p| (*p).clone()).collect();
        println!("{}", serde_json::json!({ "peers": filtered }));
        return Ok(0);
    }
    if peers.is_empty() {
        println!("{}", ui::muted("no peer agents"));
        return Ok(0);
    }
    println!(
        "{}",
        ui::header(
            "peer agents",
            Some(&format!(
                "{} registered · {} connected",
                body["total"].as_u64().unwrap_or(0),
                body["connected"].as_u64().unwrap_or(0)
            ))
        )
    );
    println!("{}", ui::section("peers"));
    let rows: Vec<Vec<String>> = peers
        .iter()
        .map(|p| {
            let join = |key: &str| -> String {
                p[key]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","))
                    .unwrap_or_default()
            };
            let connected = p["is_connected"].as_bool().unwrap_or(false);
            vec![
                ui::glyph_cell(if connected { Glyph::Ok } else { Glyph::Err }),
                ui::muted(&truncate(p["agent_id"].as_str().unwrap_or("?"), 20)),
                truncate(p["name"].as_str().unwrap_or("?"), 18),
                truncate(&join("roles"), 20),
                truncate(&join("capabilities"), 28),
                ui::state(if connected { "connected" } else { "offline" }),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("agent id"),
                Col::left("name"),
                Col::left("roles"),
                Col::left("capabilities"),
                Col::left("status"),
            ],
            &rows,
        )
    );
    Ok(0)
}

/// `noo agents peer card` — GET /.well-known/agent.json (public, no auth).
pub fn agents_peer_card(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/.well-known/agent.json", false, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    println!(
        "{}",
        ui::header(
            &format!("agent card {}", body["name"].as_str().unwrap_or("?")),
            Some(&format!("v{}", body["version"].as_str().unwrap_or("?")))
        )
    );
    let roles = body["roles"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    let mut rows: Vec<(&str, String)> = vec![
        ("description", body["description"].as_str().unwrap_or("").to_string()),
        ("roles", roles),
    ];
    if let Some(auth) = body["authentication"].as_object() {
        let schemes = auth
            .get("schemes")
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        rows.push(("auth", schemes));
    }
    print!("{}", ui::kv(&rows));
    if let Some(caps) = body["capabilities"].as_object() {
        println!("{}", ui::section("capabilities"));
        let rows: Vec<(&str, String)> = caps
            .iter()
            .map(|(cap, info)| (cap.as_str(), info["endpoint"].as_str().unwrap_or("").to_string()))
            .collect();
        for line in ui::kv(&rows).lines() {
            println!("  {line}");
        }
    }
    if let Some(eps) = body["endpoints"].as_object() {
        println!("{}", ui::section("endpoints"));
        let rows: Vec<(&str, String)> =
            eps.iter().map(|(name, url)| (name.as_str(), url.as_str().unwrap_or("?").to_string())).collect();
        for line in ui::kv(&rows).lines() {
            println!("  {line}");
        }
    }
    Ok(0)
}

pub(crate) fn parse_peer_dispatch_with(a: &mut Args) -> Result<(String, String, String), ArgError> {
    let role = a.value(&["--role", "-r"])?.unwrap_or_else(|| "agent".to_string());
    let [agent_id, task]: [String; 2] = a.positionals()?.try_into().map_err(|_| ArgError::new("expected <agent-id> <task>"))?;
    Ok((agent_id, task, role))
}

/// `noo agents peer dispatch AGENT_ID TASK [--role/-r ROLE]` —
/// POST /api/agents/peer/{agent_id}/task. Fire-and-acknowledge: the gateway
/// returns a task id immediately; the result arrives async on a NATS stream
/// (Python parity: 30s timeout, role defaults to "agent").
pub fn agents_peer_dispatch(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (agent_id, task, role) = parse_peer_dispatch_with(&mut Args::new(args))?;
    let (agent_id, task) = (&agent_id, &task);
    let payload = serde_json::json!({ "task": task, "role": role });
    let body = post_json(
        g,
        &format!("/api/agents/peer/{}/task", super::urlencode(agent_id)),
        &payload,
        true,
        30,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    ui::done(&format!("task dispatched to {agent_id} — peer is processing, token stream on /ws/collab"));
    let task_id = body["task_id"].as_str().unwrap_or("?");
    print!(
        "{}",
        ui::kv(&[("result stream", body["result_subject"].as_str().unwrap_or("?").to_string())])
    );
    // The task id is the captured value (kept by --quiet).
    ui::value(task_id);
    ui::guide(&[
        ("noo agents peer list", "check the peer's status and last heartbeat"),
        ("noo agents inbox", "results and notes the peer sends back land here"),
    ]);
    Ok(0)
}


// ── Agent messaging ────────────────────────────────

fn body_preview(m: &serde_json::Value) -> String {
    if let Some(t) = m["body"]["text"].as_str() {
        return t.replace('\n', " ");
    }
    let s = m["body"].to_string();
    if s == "null" || s == "{}" { String::new() } else { s }
}

/// `from` plus who it really was: `agent (user@node, harness)`.
///
/// Every part printed bare is server-derived: the user
/// and node come from the credential, and `harness` names the credential
/// class the message arrived on. A sender's own claim about its software
/// arrives in a different key and is printed `claims: x`, because this
/// column used to show a caller-supplied string as though the gateway had
/// checked it.
fn who(m: &serde_json::Value) -> String {
    let agent = m["from"].as_str().unwrap_or("?");
    let id = &m["from_id"];
    let mut extra: Vec<String> = Vec::new();
    match (id["user"].as_str(), id["node"].as_str()) {
        (Some(u), Some(n)) => extra.push(format!("{u}@{n}")),
        (Some(u), None) => extra.push(u.to_string()),
        (None, Some(n)) => extra.push(format!("@{n}")),
        _ => {}
    }
    if let Some(h) = id["harness"].as_str() { extra.push(h.to_string()); }
    if let Some(c) = id["harness_claimed"].as_str() { extra.push(format!("claims: {c}")); }
    if extra.is_empty() { agent.to_string() } else { format!("{agent} ({})", extra.join(", ")) }
}

fn print_message_rows(rows: &[serde_json::Value]) {
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|m| {
            vec![
                if m["read_at"].is_null() { ui::glyph_cell(Glyph::Bullet) } else { ui::glyph_cell(Glyph::Ok) },
                ui::muted(&truncate(m["id"].as_str().unwrap_or("?"), 24)),
                truncate(&who(m), 40),
                truncate(m["to"].as_str().unwrap_or("?"), 26),
                truncate(m["kind"].as_str().unwrap_or("?"), 8),
                m["ts"].as_str().unwrap_or("").chars().take(19).collect::<String>(),
                body_preview(m),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("id"),
                Col::left("from (user@node, harness)"),
                Col::left("to"),
                Col::left("kind"),
                Col::left("ts"),
                Col::left("body"),
            ],
            &table_rows,
        )
    );
    println!("  {}", ui::muted(&format!("{} = read", ui::glyph(Glyph::Ok))));
}


/// What `noo agents send` was asked for.
pub(crate) struct SendArgs {
    to: Option<String>,
    text: Vec<String>,
    from: Option<String>,
    agent: Option<String>,
    harness: Option<String>,
    thread: Option<String>,
    kind: String,
    refs: Vec<String>,
    json_body: Option<String>,
}

pub(crate) fn parse_send_with(a: &mut Args) -> Result<SendArgs, ArgError> {
    let from = a.value(&["--from"])?;
    let agent = a.value(&["--agent"])?;
    let harness = a.value(&["--harness"])?;
    let thread = a.value(&["--thread"])?;
    let kind = a.value(&["--kind"])?.unwrap_or_else(|| "message".to_string());
    let refs = a.values(&["--ref"])?;
    let json_body = a.value(&["--body"])?;
    let mut text = a.positionals()?;
    let to = if text.is_empty() { None } else { Some(text.remove(0)) };
    Ok(SendArgs { to, text, from, agent, harness, thread, kind, refs, json_body })
}

/// `noo agents send <to> <text…> [--from <agent>] [--thread <id>] [--kind <k>] [--ref <msg-id>]…`
pub fn agents_send(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let SendArgs { to, text, from, agent, harness, thread, kind, refs, json_body } = parse_send_with(&mut Args::new(args))?;
    let Some(to) = to else {
        ui::failed("usage: noo agents send <to> <text…> [--from <agent>] [--thread <id>] [--kind message|task|result|ack|note] [--ref <msg-id>]… [--body <json>]", None);
        return Ok(2);
    };
    let body = match json_body {
        Some(j) => match serde_json::from_str::<serde_json::Value>(&j) {
            Ok(v) => v,
            Err(e) => { ui::failed(&format!("--body is not JSON: {e}"), None); return Ok(2); }
        },
        None if text.is_empty() => { ui::failed("nothing to send — give text or --body <json>", None); return Ok(2); }
        None => serde_json::json!({ "text": text.join(" ") }),
    };
    let mut req = serde_json::json!({ "to": to, "kind": kind, "body": body, "refs": refs });
    if let Some(f) = from { req["from"] = serde_json::Value::String(f); }
    if let Some(a) = agent { req["agent"] = serde_json::Value::String(a); }
    // Sent as a CLAIM, not as the harness: the gateway derives that from
    // the credential and records this beside it.
    if let Some(h) = harness { req["harness_claimed"] = serde_json::Value::String(h); }
    if let Some(t) = thread { req["thread_id"] = serde_json::Value::String(t); }
    let resp = post_json(g, "/api/agents/messages", &req, true, 15);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let m = &resp["message"];
    ui::done(&format!("sent {} → {}  thread {}", m["from"].as_str().unwrap_or("?"), m["to"].as_str().unwrap_or("?"), m["thread_id"].as_str().unwrap_or("?")));
    // The message id is the captured value.
    ui::value(m["id"].as_str().unwrap_or("?"));
    let thread_cmd = format!("noo agents thread {}", m["thread_id"].as_str().unwrap_or("<id>"));
    let inbox_cmd = format!("noo agents inbox --agent {}", m["to"].as_str().unwrap_or("<agent>"));
    ui::guide(&[
        (thread_cmd.as_str(), "the whole conversation, replies included"),
        (inbox_cmd.as_str(), "what the recipient sees"),
    ]);
    Ok(0)
}

pub(crate) fn parse_inbox_with(a: &mut Args) -> Result<(Option<String>, bool, u32), ArgError> {
    let agent = a.value(&["--agent"])?;
    let unread = a.flag(&["--unread"]);
    // A limit that is not a number falls back to the default, as it always did.
    let limit = a.value(&["--limit"])?.and_then(|v| v.parse().ok()).unwrap_or(50);
    a.finish()?;
    Ok((agent, unread, limit))
}

/// `noo agents inbox [--agent <id>] [--unread] [--limit <n>]` — messages addressed to an agent.
pub fn agents_inbox(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (agent, unread, limit) = parse_inbox_with(&mut Args::new(args))?;
    let mut path = format!("/api/agents/messages?limit={limit}");
    if let Some(a) = &agent { path.push_str(&format!("&to={}", super::urlencode(a))); }
    if unread { path.push_str("&unread=true"); }
    let resp = get_json(g, &path, true, 10);
    if g.json { println!("{resp}"); return Ok(0); }
    let empty = Vec::new();
    let rows = resp["messages"].as_array().unwrap_or(&empty);
    let right = match &agent {
        Some(a) => format!("{a} · {} message(s)", rows.len()),
        None => format!("{} message(s)", rows.len()),
    };
    println!("{}", ui::header("inbox", Some(&right)));
    if rows.is_empty() { println!("{}", ui::muted("inbox empty")); return Ok(0); }
    print_message_rows(rows);
    ui::guide(&[
        ("noo agents thread <id>", "opens one conversation in full"),
        ("noo agents inbox --unread", "only what has not been read yet"),
    ]);
    Ok(0)
}

pub(crate) fn parse_presence_with(a: &mut Args) -> Result<Option<String>, ArgError> {
    let owner = a.value(&["--owner"])?;
    a.finish()?;
    Ok(owner)
}

/// `noo agents presence [--owner <account>]` — the live MCP windows under
/// an account: which of me is open, so I can address
/// one by name. Everything shown is advertisement — the window says what
/// it is, never what it may do. `--owner` is for operators; anyone else
/// gets their own account and the gateway refuses another's with 403
/// rather than an empty list, so "nobody is online" never means "you may
/// not look".
pub fn agents_presence(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let owner = parse_presence_with(&mut Args::new(args))?;
    let mut path = String::from("/api/agents/presence");
    if let Some(o) = &owner { path.push_str(&format!("?owner={}", super::urlencode(o))); }
    let resp = get_json(g, &path, true, 10);
    if g.json { println!("{resp}"); return Ok(0); }
    let owner = resp["owner"].as_str().unwrap_or("?");
    let empty = Vec::new();
    let rows = resp["sessions"].as_array().unwrap_or(&empty);
    let ttl = resp["idle_ttl_secs"].as_u64().map(|s| format!("idle after {}h", s / 3600));
    let right = match &ttl {
        Some(t) => format!("{owner} · {} window(s) · {t}", rows.len()),
        None => format!("{owner} · {} window(s)", rows.len()),
    };
    println!("{}", ui::header("presence", Some(&right)));
    if rows.is_empty() {
        println!("{}", ui::muted(&format!("no live windows under {owner}")));
        ui::guide(&[("connect an MCP client with a key bound to this account", "each window appears here under its own name")]);
        return Ok(0);
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|w| {
            vec![
                ui::glyph_cell(Glyph::Ok),
                w["connection"].as_str().unwrap_or("?").to_string(),
                truncate(w["display_name"].as_str().unwrap_or(ui::dash()), 24),
                ui::muted(&truncate(w["consumer"].as_str().unwrap_or(ui::dash()), 18)),
                ago(&w["opened_at"]),
                ago(&w["last_seen"]),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left(""), Col::left("connection"), Col::left("client"), Col::left("key"), Col::left("opened"), Col::left("seen")],
            &table,
        )
    );
    ui::guide(&[
        ("noo agents send <connection> <text>", "addresses one window; mail to the bare account reaches all of them"),
        ("noo agents inbox --agent <connection>", "what one window has been sent"),
    ]);
    Ok(0)
}

/// `noo agents thread <thread-id>` — every message in a thread, oldest first.
pub fn agents_thread(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let id = match args {
        [t] if !t.starts_with('-') => t.clone(),
        _ => { ui::failed("usage: noo agents thread <thread-id>", None); return Ok(2); }
    };
    let resp = get_json(g, &format!("/api/agents/messages?thread={}&limit=500", super::urlencode(&id)), true, 10);
    if g.json { println!("{resp}"); return Ok(0); }
    let empty = Vec::new();
    let mut rows: Vec<serde_json::Value> = resp["messages"].as_array().unwrap_or(&empty).clone();
    rows.reverse();
    if rows.is_empty() { println!("{}", ui::muted("no messages in that thread")); return Ok(1); }
    println!("{}", ui::header(&format!("thread {id}"), Some(&format!("{} messages", rows.len()))));
    for m in &rows {
        println!();
        println!("[{}] {} → {}  ({}, {})", m["ts"].as_str().unwrap_or("").chars().take(19).collect::<String>(), m["from"].as_str().unwrap_or("?"), m["to"].as_str().unwrap_or("?"), m["kind"].as_str().unwrap_or("?"), m["id"].as_str().unwrap_or("?"));
        let text = body_preview(m);
        if !text.is_empty() { println!("  {text}"); }
    }
    Ok(0)
}

/// What `noo agents messages` was asked for.
pub(crate) struct MessagesArgs {
    q: Vec<(String, String)>,
    threads: bool,
    limit: u32,
}

pub(crate) fn parse_messages_with(a: &mut Args) -> Result<MessagesArgs, ArgError> {
    let mut q: Vec<(String, String)> = Vec::new();
    for key in ["agent", "from", "to", "user", "node", "harness", "kind", "since"] {
        if let Some(v) = a.value(&[format!("--{key}").as_str()])? {
            q.push((key.to_string(), v));
        }
    }
    // A limit that is not a number falls back to the default, as it always did.
    let limit = a.value(&["--limit"])?.and_then(|v| v.parse().ok()).unwrap_or(50);
    let threads = a.flag(&["--threads"]);
    a.finish()?;
    Ok(MessagesArgs { q, threads, limit })
}

/// `noo agents messages [--agent <id>] [--from <id>] [--to <id>] [--user <u>] [--node <n>] [--harness <h>] [--kind <k>] [--since <rfc3339>] [--limit <n>] [--threads]` — operator review.
pub fn agents_messages(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let MessagesArgs { q, threads, limit } = parse_messages_with(&mut Args::new(args))?;
    let mut path = if threads { format!("/api/agents/threads?limit={limit}") } else { format!("/api/agents/messages?limit={limit}") };
    for (k, v) in &q { path.push_str(&format!("&{k}={}", super::urlencode(v))); }
    let resp = get_json(g, &path, true, 10);
    if g.json { println!("{resp}"); return Ok(0); }
    let empty = Vec::new();
    if threads {
        let rows = resp["threads"].as_array().unwrap_or(&empty);
        if rows.is_empty() { println!("{}", ui::muted("no threads")); return Ok(0); }
        let mut table_rows: Vec<Vec<String>> = Vec::new();
        for t in rows {
            let mut who: Vec<String> = Vec::new();
            for k in ["senders", "recipients"] {
                for p in t[k].as_array().unwrap_or(&empty) {
                    if let Some(s) = p.as_str() { if !who.contains(&s.to_string()) { who.push(s.to_string()); } }
                }
            }
            table_rows.push(vec![
                ui::muted(&truncate(t["thread_id"].as_str().unwrap_or("?"), 24)),
                t["messages"].as_i64().unwrap_or(0).to_string(),
                t["started"].as_str().unwrap_or("").chars().take(19).collect::<String>(),
                t["last"].as_str().unwrap_or("").chars().take(19).collect::<String>(),
                who.join(", "),
            ]);
        }
        print!(
            "{}",
            ui::table(
                &[Col::left("thread"), Col::right("msgs"), Col::left("started"), Col::left("last"), Col::left("participants")],
                &table_rows,
            )
        );
        return Ok(0);
    }
    let rows = resp["messages"].as_array().unwrap_or(&empty);
    if rows.is_empty() { println!("{}", ui::muted("no messages")); return Ok(0); }
    print_message_rows(rows);
    Ok(0)
}

// ─── agent-mail archive ──────────────────────────────────────────────────
//
// The archive lives on the controller's data volume and its bodies are
// sealed with a key only the gateway holds, so both verbs are gateway
// routes (`/api/agents/archive`, operator-only). The CLI only formats.

/// `noo agents archive list` — GET /api/agents/archive.
pub fn agents_archive_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/agents/archive", true, 60);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let files = body["files"].as_array().unwrap_or(&empty);
    if files.is_empty() {
        println!("{}", ui::muted(&format!("no archived agent mail under {}", body["dir"].as_str().unwrap_or("?"))));
        return Ok(0);
    }
    println!(
        "{}",
        ui::header("agent mail archive", Some(&format!("{} file(s), {} message(s)", files.len(), body["total_rows"].as_u64().unwrap_or(0))))
    );
    let rows: Vec<Vec<String>> = files
        .iter()
        .map(|f| {
            vec![
                f["month"].as_str().unwrap_or("?").to_string(),
                f["rows"].as_u64().unwrap_or(0).to_string(),
                f["bytes"].as_u64().unwrap_or(0).to_string(),
                f["file"].as_str().unwrap_or("?").to_string(),
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("month"), Col::right("messages"), Col::right("bytes"), Col::left("file")], &rows));
    Ok(0)
}

pub(crate) fn parse_archive_export_with(a: &mut Args) -> Result<(String, bool, Option<String>), ArgError> {
    let decrypt = a.flag(&["--decrypt"]);
    let out = a.value(&["--out", "-o"])?;
    let target = a.one("<month|file>")?;
    Ok((target, decrypt, out))
}

/// `noo agents archive export <month|file> [--decrypt] [--out <path>]` —
/// GET /api/agents/archive/{month}. JSONL, one archived row per line,
/// bodies still sealed. `--decrypt` asks the gateway to open them with the
/// cluster key (operator-only, audited by name and month); decrypted rows
/// are written ONLY to `--out` (mode 0600), never to stdout or `--json`.
pub fn agents_archive_export(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (target, decrypt, out) = parse_archive_export_with(&mut Args::new(args))?;
    let (target, out) = (target.as_str(), out.as_deref());
    if decrypt && out.is_none() {
        crate::output::fail(
            g.json,
            crate::output::ExitCode::Usage,
            "decrypt_needs_out",
            "--decrypt writes plaintext, so it needs --out <path> (it is never printed)",
            None,
        );
    }
    // A file argument names a month: the gateway rebuilds the path from it.
    let month = std::path::Path::new(target).file_name().and_then(|n| n.to_str()).unwrap_or(target);
    let path = format!("/api/agents/archive/{}{}", super::urlencode(month), if decrypt { "?decrypt=true" } else { "" });
    let body = get_json(g, &path, true, 300);
    let empty = Vec::new();
    let rows = body["rows"].as_array().unwrap_or(&empty);
    let mut text = String::new();
    for r in rows {
        text.push_str(&r.to_string());
        text.push('\n');
    }
    match out {
        Some(p) => {
            use std::io::Write as _;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let res = opts.open(p).and_then(|mut f| f.write_all(text.as_bytes()).and_then(|_| f.sync_all()));
            if let Err(e) = res {
                crate::output::fail(g.json, crate::output::ExitCode::Generic, "write_failed", &format!("cannot write {p}: {e}"), None);
            }
            if g.json {
                println!(
                    "{}",
                    serde_json::json!({"month": body["month"], "file": body["file"], "count": rows.len(), "decrypted": decrypt, "opened": body["opened"], "out": p})
                );
            } else {
                println!(
                    "{}",
                    ui::ok(&format!(
                        "wrote {} message(s) for {} to {p}{}",
                        rows.len(),
                        body["month"].as_str().unwrap_or("?"),
                        if decrypt { format!(" ({} body(ies) opened; recorded in the audit log)", body["opened"].as_u64().unwrap_or(0)) } else { " (bodies still sealed)".into() }
                    ))
                );
            }
        }
        None => print!("{text}"),
    }
    Ok(0)
}
