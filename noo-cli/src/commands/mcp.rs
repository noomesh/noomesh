// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo mcp …` — MCP surface (WP-M).
//!
//! `mcp tools` — the Python CLI spun up an IN-PROCESS `MCPClientManager` and
//! connected to every configured external MCP server from the CLI process.
//! Architecturally the gateway's operator door (`/mcp/operator`) already owns
//! those connections — `gateway/worker_pool.py` discovers the configured
//! external servers at startup and registers their tools with the hub — so
//! the native command just asks the hub. There is no plain-JSON listing
//! endpoint (`/health` reports counts only), so we speak the minimal MCP
//! streamable-http JSON-RPC exchange ourselves:
//!
//!   POST /mcp initialize            → capture `mcp-session-id` header
//!   POST /mcp notifications/initialized
//!   POST /mcp tools/list            → result.tools
//!   DELETE /mcp                     → best-effort session cleanup
//!
//! No MCP SDK needed. Responses arrive either as `application/json` or as
//! SSE frames (`text/event-stream` — the SDK server transport's default);
//! both are parsed. The door is the gateway URL; the bearer is NOO_MCP_KEY —
//! a per-admin `mcp:operator` service key — loaded from the repo `.env` like
//! every other native command. The shared NOO_MCP_TOKEN was retired on
//! 2026-09-30: the door refuses it, so it is never sent (and a stale value
//! in the environment gets one line saying what replaces it).
//!
//! `mcp external-setup` — RETIRED as a token minter (2026-08-03). It used to
//! generate NOO_MCP_EXTERNAL_TOKEN and print harness snippets for it. That
//! variable was both the external door's on-switch AND a valid bearer, so
//! opening the door necessarily created a shared, unattributed, uncapped,
//! unrevocable operator-tier credential — the bypass the native Rust door
//! (#420) removed. No door honours it now, so a token minted here would
//! authenticate nothing. The command survives only to print the real recipe
//! (posture flag + a `--user`-bound `mcp`-scoped service key) and exits 2,
//! because it did not do what was asked.

use super::truncate;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};
use serde_json::{json, Value};

/// MCP protocol revision we advertise. The hub's SDK negotiates down to the
/// client's version; tools/list is stable across every published revision.
const MCP_PROTOCOL_VERSION: &str = "2025-03-26";

// ─────────────────────────────────────────────────────────────────────────
// Hub location + transport plumbing
// ─────────────────────────────────────────────────────────────────────────

/// The operator door: `/mcp/operator` on the gateway. Until stack-v0.2.40
/// this dialled a plain-HTTP listener on `NOO_MCP_HOST:NOO_MCP_PORT`; that
/// listener is gone, so the door is reached like every other gateway
/// route — over HTTPS, verified against the cluster CA.
fn door_url(g: &Globals) -> (String, String) {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}/mcp/operator");
    (base, url)
}

/// The command that mints the only credential the operator door accepts.
/// Mirrors the gateway's `mcp_local::MINT_HINT`.
pub(crate) const MINT_HINT: &str =
    "noo security service-key issue <you>-mcp --scopes mcp:operator --user <admin>";

/// The bearer for the operator door: `NOO_MCP_KEY`, a personal
/// `mcp:operator` service key (every call is attributed to its admin).
/// Empty means the request goes out with no credential and the door
/// answers 401 naming the mint command.
///
/// `NOO_MCP_TOKEN` is NOT a fallback any more: the shared token is retired
/// and the gateway refuses it, so sending it would only turn "set a key"
/// into a confusing 401.
fn door_bearer() -> String {
    std::env::var("NOO_MCP_KEY").map(|v| v.trim().to_string()).unwrap_or_default()
}

/// One stderr line when the retired shared token is still configured, so a
/// harness that relied on it learns what replaces it instead of seeing a
/// bare 401. `None` when there is nothing to say.
pub(crate) fn retired_token_note(token: Option<&str>) -> Option<String> {
    token.filter(|v| !v.trim().is_empty()).map(|_| {
        format!(
            "NOO_MCP_TOKEN is retired and ignored — /mcp/operator takes only a per-admin key. \
             Mint one with `{MINT_HINT}`, set it as NOO_MCP_KEY, and remove the token \
             (`noo security secrets tidy`)."
        )
    })
}

fn hub_agent(g: &Globals, base: &str, default_timeout: u64) -> ureq::Agent {
    let timeout = g.timeout_secs.unwrap_or(default_timeout);
    match crate::http::agent_for(base, timeout) {
        Ok(a) => a,
        Err(e) => fail(g.json, ExitCode::GatewayUnreachable, "tls_trust", &e, None),
    }
}

/// One streamable-http POST: JSON-RPC payload in, `(status, session-id
/// header, content-type, body)` out. Transport failures return `Err(msg)`.
fn hub_post(
    agent: &ureq::Agent,
    url: &str,
    token: &str,
    session: Option<&str>,
    payload: &Value,
) -> Result<(u16, Option<String>, String, String), String> {
    let mut req = agent
        .post(url)
        .header("Accept", "application/json, text/event-stream");
    if !token.is_empty() {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }
    if let Some(sid) = session {
        req = req.header("Mcp-Session-Id", sid);
    }
    let mut resp = req.send_json(payload).map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let sid = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.body_mut().read_to_string().unwrap_or_default();
    Ok((status, sid, ctype, body))
}

/// Extract the JSON-RPC response with id `want_id` from a streamable-http
/// response body — either a plain JSON document or SSE `data:` frames.
/// Falls back to the last parseable frame when no id matches (a server that
/// batches notifications before the response).
fn parse_rpc_response(ctype: &str, body: &str, want_id: u64) -> Option<Value> {
    if !ctype.contains("text/event-stream") {
        return serde_json::from_str(body.trim()).ok();
    }
    let mut last: Option<Value> = None;
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        if let Ok(v) = serde_json::from_str::<Value>(data.trim()) {
            if v["id"].as_u64() == Some(want_id) {
                return Some(v);
            }
            last = Some(v);
        }
    }
    last
}

/// Map a non-2xx hub status to the exit-code contract and exit.
fn hub_http_fail(g: &Globals, status: u16, body: &str, base: &str) -> ! {
    let (code, kind) = match status {
        401 | 403 => (ExitCode::AuthFailed, "auth_failed"),
        _ => (ExitCode::RemoteError, "hub_error"),
    };
    let detail = body.trim();
    let msg = if detail.is_empty() {
        format!("MCP hub at {base} returned HTTP {status}")
    } else {
        format!("MCP hub at {base} returned HTTP {status}: {}", truncate(detail, 200))
    };
    fail(
        g.json,
        code,
        kind,
        &msg,
        Some(format!("set NOO_MCP_KEY to an `mcp:operator` service key bound to an admin: {MINT_HINT}").as_str()),
    );
}

// ─────────────────────────────────────────────────────────────────────────
// noo mcp tools
// ─────────────────────────────────────────────────────────────────────────

/// `noo mcp tools` — list the hub's unified tool catalog (core native +
/// external MCP servers). `--json` prints the raw `tools/list` result.
pub fn mcp_tools(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        // Python's `--config PATH` (in-process server list) or anything else
        // we don't understand → usage error (exit 2).
        return Err(Unhandled);
    }

    let (base, url) = door_url(g);
    let token = door_bearer();
    if let Some(note) = retired_token_note(std::env::var("NOO_MCP_TOKEN").ok().as_deref()) {
        eprintln!("{}", ui::warn(&note));
    }
    let agent = hub_agent(g, &base, 10);
    if g.verbose {
        eprintln!("{}", ui::muted(&format!("MCP streamable-http exchange with {url}")));
    }

    let unreachable = |e: &str| -> ! {
        fail(
            g.json,
            ExitCode::GatewayUnreachable,
            "hub_unreachable",
            &format!("cannot reach MCP hub at {base}: {e}"),
            Some("the operator door is served by the gateway itself; check the gateway URL (--gateway / NOO_GATEWAY_URL) and that it is up"),
        )
    };

    // 1. initialize — negotiates the session; the session id rides back in
    //    the Mcp-Session-Id header.
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "noo-cli", "version": env!("CARGO_PKG_VERSION")},
        },
    });
    let (status, session, ctype, body) = match hub_post(&agent, &url, &token, None, &init) {
        Ok(r) => r,
        Err(e) => unreachable(&e),
    };
    if !(200..=299).contains(&status) {
        hub_http_fail(g, status, &body, &base);
    }
    let init_resp = parse_rpc_response(&ctype, &body, 1);
    if let Some(err) = init_resp.as_ref().and_then(|v| v.get("error")) {
        fail(
            g.json,
            ExitCode::RemoteError,
            "hub_error",
            &format!("MCP initialize failed: {err}"),
            None,
        );
    }
    let session = session.as_deref();

    // 2. notifications/initialized — completes the handshake (202 expected;
    //    any 2xx accepted).
    let inited = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    match hub_post(&agent, &url, &token, session, &inited) {
        Ok((s, ..)) if (200..=299).contains(&s) => {}
        Ok((s, _, _, b)) => hub_http_fail(g, s, &b, &base),
        Err(e) => unreachable(&e),
    }

    // 3. tools/list — the payload we came for.
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}});
    let (status, _, ctype, body) = match hub_post(&agent, &url, &token, session, &list) {
        Ok(r) => r,
        Err(e) => unreachable(&e),
    };
    if !(200..=299).contains(&status) {
        hub_http_fail(g, status, &body, &base);
    }
    let resp = parse_rpc_response(&ctype, &body, 2).unwrap_or_else(|| {
        fail(
            g.json,
            ExitCode::Generic,
            "bad_response",
            &format!("MCP hub at {base} returned an unparseable tools/list response"),
            None,
        )
    });
    if let Some(err) = resp.get("error") {
        fail(
            g.json,
            ExitCode::RemoteError,
            "hub_error",
            &format!("MCP tools/list failed: {err}"),
            None,
        );
    }

    // 4. Session cleanup — best-effort; the hub reaps orphans anyway.
    if let Some(sid) = session {
        let mut req = agent.delete(&url).header("Mcp-Session-Id", sid);
        if !token.is_empty() {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        let _ = req.call();
    }

    let result = resp.get("result").cloned().unwrap_or_else(|| json!({}));
    if g.json {
        println!("{result}");
        return Ok(0);
    }

    let empty = Vec::new();
    let tools = result["tools"].as_array().unwrap_or(&empty);
    if tools.is_empty() {
        println!("{}", ui::muted("no MCP tools discovered"));
        return Ok(0);
    }
    println!("{}", ui::header("mcp tools", Some(&format!("hub {base} · {} tools", tools.len()))));
    println!();
    let rows: Vec<Vec<String>> = tools
        .iter()
        .map(|t| {
            let name = t["name"].as_str().unwrap_or("?");
            vec![
                truncate(name, 40),
                tool_source(name).to_string(),
                ui::muted(&truncate(t["description"].as_str().unwrap_or(""), 60)),
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("name"), Col::left("source"), Col::left("description")], &rows));
    Ok(0)
}

/// The hub's catalog tags each tool `source: noo|external`, but the MCP
/// `Tool` wire type drops that field. External tools are deterministic to
/// spot anyway: MCPClientManager names them `<prefix>_<server>_<tool>` with
/// the default prefix "mcp" (client.py `_format_tool_name`); PAI-native
/// names never start with `mcp_` (collisions are rejected at registration).
fn tool_source(name: &str) -> &'static str {
    if name.starts_with("mcp_") {
        "external"
    } else {
        "noo"
    }
}

// ─────────────────────────────────────────────────────────────────────────
// noo mcp external-setup
// ─────────────────────────────────────────────────────────────────────────

/// `noo mcp external-setup [--gateway URL]` — print the migration recipe for
/// external MCP access and exit 2. Mints nothing; see the module docs.
pub fn mcp_external_setup(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut gateway: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            // Accepted and ignored so an operator's muscle-memory invocation
            // reaches the explanation instead of an argument error.
            "--save" => {}
            "--gateway" | "-G" => gateway = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let gw_url = gateway
        .or_else(|| std::env::var("NOO_GATEWAY_URL").ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "https://mesh.local:8080".into());
    let door = format!("{gw_url}/mcp/user");

    if g.json {
        println!(
            "{}",
            json!({
                "retired": true,
                "reason": "NOO_MCP_EXTERNAL_TOKEN retired; no MCP door honours a shared token",
                "door": door,
                "steps": [
                    "noo security posture set NOO_MCP_EXTERNAL_ENABLED 1",
                    "noo security user create alice --scope read",
                    "# then, as alice, on her own machine:",
                    "noo auth login",
                    "noo security service-key self --note laptop",
                ],
            })
        );
        return Ok(2);
    }

    // Runbook (guide §5): stdout, in full — a section per phase, bullets
    // for steps, commands on their own lines, explanations as notes.
    let bullet = |s: &str| println!("{}", ui::status_line(Glyph::Bullet, s));
    let note = |s: &str| println!("{}", ui::note(s));
    let sh = |s: &str| println!("  {}", ui::cmd(s));
    println!("{}", ui::header("external MCP setup", Some("named keys, not a shared token")));
    println!("{}", ui::status_line(Glyph::Warn, "external MCP access is issued as a named key, not a shared token"));
    note("this command no longer mints NOO_MCP_EXTERNAL_TOKEN: that variable was both the");
    note("door's on-switch AND a credential, so every caller arrived as the same");
    note("unattributed, uncapped, unrevocable actor. No door accepts it now.");
    println!("{}", ui::section("steps"));
    bullet("open the door (DB-authoritative; restart to apply)");
    sh("noo security posture set NOO_MCP_EXTERNAL_ENABLED 1");
    bullet("give the consumer an account (operator, on the controller)");
    sh("noo security user create alice --scope read");
    bullet("alice mints her OWN key, on her own machine");
    sh("noo auth login");
    sh("noo security service-key self --note laptop");
    note("the door REFUSES (403) any key not bound to an account, so this and");
    note("`service-key issue --user <account>` are the only two verbs that");
    note("produce a door-usable key; `issue` without --user mints an unbound");
    note("machine key, good for /api/external and refused at the MCP door.");
    note("`service-key self` is scoped [mcp], bound to the caller's JWT subject,");
    note("capped at 120 rpm, and re-running it ROTATES rather than accumulates.");
    note("Her tool calls then run under alice's OWN scopes and KB roles.");
    note("The dashboard button is the same endpoint if she prefers a browser.");
    bullet("point the harness at the gateway door");
    sh(&door);
    note("headers: {\"Authorization\": \"Bearer <the issued key>\"}");
    bullet("revoke one consumer without touching any other");
    sh("noo security service-key revoke self:alice");
    note("or, as alice: noo security service-key self-revoke");
    Ok(2)
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

// ═══════════════════════════════════════════════════════════════════════
// `noo mcp server …` / `noo mcp place …` / `noo mcp import|export` — the
// registry of EXTERNAL MCP servers. Thin HTTP over
// `/api/mcp/servers*`; every rule (id shape, no literal secrets, audience
// vocabulary, node must be registered) is enforced by the gateway, so this
// side only shapes the request and prints the answer.
//
// Phase A is the RECORD. Nothing here starts a server or reaches its
// tools — the node-side supervisor (phase B) and the bridge (phase C) do
// that — and the gateway's replies say so.
// ═══════════════════════════════════════════════════════════════════════

const SERVER_ADD_USAGE: &str = "usage: noo mcp server add <id> --transport http \
    --url <url> [--header K=$NAME]... [--kind tool|device] [--audience a,b] [--note <text>] [--disabled]\n\n\
stdio servers are declared on the node that runs them, in /etc/noo/mcp-servers.json.";

/// The words the gateway uses for the same refusal, so the CLI answers
/// offline with exactly what the server would have said.
///
/// This is a REFUSAL, not a removed flag: `--transport stdio` stays
/// parseable so someone with it in a script or a runbook is told why it
/// stopped working and where the definition goes now, rather than meeting
/// a bare usage dump.
const STDIO_IS_NODE_LOCAL: &str = "stdio MCP servers are declared on the node, not from here: \
the spec is a command the node would execute, so it comes from a root-owned file on that host \
(/etc/noo/mcp-servers.json), never from the controller.";

fn parse_kv(s: &str) -> Option<(String, String)> {
    let (k, v) = s.split_once('=')?;
    let k = k.trim();
    if k.is_empty() { return None; }
    Some((k.to_string(), v.to_string()))
}

/// `noo mcp server add <id> …` — POST /api/mcp/servers.
pub fn mcp_server_add(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut id: Option<String> = None;
    let mut transport: Option<String> = None;
    let mut kind = "tool".to_string();
    let mut audience: Vec<String> = Vec::new();
    let mut note: Option<String> = None;
    let mut enabled = true;
    let mut command: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut url: Option<String> = None;
    let mut sargs: Vec<String> = Vec::new();
    let mut env = serde_json::Map::new();
    let mut headers = serde_json::Map::new();
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        macro_rules! next { () => { it.next().ok_or(Unhandled)?.clone() }; }
        match tok.as_str() {
            "--transport" => transport = Some(match next!().as_str() { "stdio" => "stdio".into(), "http" | "streamable_http" => "streamable_http".into(), _ => return Err(Unhandled) }),
            "--command" => command = Some(next!()),
            "--arg" => sargs.push(next!()),
            "--cwd" => cwd = Some(next!()),
            "--url" => url = Some(next!()),
            "--env" => { let (k, v) = parse_kv(&next!()).ok_or(Unhandled)?; env.insert(k, json!(v)); }
            "--header" => { let (k, v) = parse_kv(&next!()).ok_or(Unhandled)?; headers.insert(k, json!(v)); }
            "--kind" => kind = next!(),
            "--audience" => audience = next!().split(',').map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).collect(),
            "--note" => note = Some(next!()),
            "--disabled" => enabled = false,
            "-h" | "--help" => { println!("{SERVER_ADD_USAGE}"); return Ok(0); }
            t if t.starts_with('-') => return Err(Unhandled),
            t if id.is_none() => id = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let (Some(id), Some(transport)) = (id, transport) else {
        println!("{SERVER_ADD_USAGE}");
        return Err(Unhandled);
    };
    if transport == "stdio" {
        return Err(stdio_refusal(&id, command.as_deref(), &sargs, cwd.as_deref()));
    }
    let _ = (&command, &sargs, &cwd, &env);
    let mut spec = serde_json::Map::new();
    if let Some(u) = url { spec.insert("url".into(), json!(u)); }
    if !headers.is_empty() { spec.insert("headers".into(), Value::Object(headers)); }
    let body = json!({ "id": id, "transport": transport, "spec": spec, "kind": kind, "audience": audience, "note": note, "enabled": enabled });
    let resp = crate::http::post_json(g, "/api/mcp/servers", &body, true, 15);
    if g.json { println!("{resp}"); return Ok(0); }
    ui::done(&format!("registered '{id}' ({transport}, {kind}; audience {})", if audience.is_empty() { "operators only".to_string() } else { audience.join(",") }));
    if let Some(n) = resp["note"].as_str() { println!("{}", ui::note(n)); }
    ui::guide(&[
        (&format!("noo mcp place {id} <node>"), "declare which node dials it"),
        (&format!("noo mcp server show {id}"), "the record, its placements and discovered tools"),
    ]);
    Ok(0)
}

/// Print the refusal, and the file the operator should write instead —
/// pre-filled with what they just typed, so the next step is a copy rather
/// than a translation.
fn stdio_refusal(id: &str, command: Option<&str>, args: &[String], cwd: Option<&str>) -> Unhandled {
    ui::failed(STDIO_IS_NODE_LOCAL, None);
    println!();
    println!("{}", ui::muted("on the node that should run it, as root:"));
    // `image` is REQUIRED: a node-local MCP server runs in a
    // container under the skills sandbox floor, and an entry without it is
    // refused by the agent rather than run uncontained. It is in the paste so
    // the operator meets the requirement here, not in the agent's journal.
    let entry = json!([{
        "id": id,
        "image": "ghcr.io/example/the-server-image:tag",
        "command": command.unwrap_or("/absolute/path/to/the/server/binary"),
        "args": args,
        "cwd": cwd.unwrap_or(""),
    }]);
    println!("  {}", ui::muted("# /etc/noo/mcp-servers.json  (root:root, 0644)"));
    for line in serde_json::to_string_pretty(&entry).unwrap_or_default().lines() {
        println!("  {line}");
    }
    println!("  {}", ui::muted(
        "# `image` must be in that node's NOO_CONTAINER_IMAGE_ALLOW; `command` is"));
    println!("  {}", ui::muted(
        "# bind-mounted read-only into the container at that same path."));
    println!("  {}", ui::muted("sudo systemctl restart noo-node-agent"));
    println!();
    ui::guide(&[
        ("noo mcp server add <id> --transport http --url <url>", "register a server this node dials instead"),
        ("docs/security/node-agent.md", "why the controller cannot place a command"),
    ]);
    Unhandled
}

/// `noo mcp server list` — GET /api/mcp/servers.
pub fn mcp_server_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() { return Err(Unhandled); }
    let body = crate::http::get_json(g, "/api/mcp/servers", true, 15);
    if g.json { println!("{body}"); return Ok(0); }
    let empty = Vec::new();
    let servers = body["servers"].as_array().unwrap_or(&empty);
    println!("{}", ui::header("mcp servers", Some(&format!("{} registered", servers.len()))));
    if servers.is_empty() {
        println!("{}", ui::muted("none — `noo mcp server add <id> --transport stdio|http …`"));
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = servers.iter().map(|s| vec![
        s["id"].as_str().unwrap_or("?").to_string(),
        s["transport"].as_str().unwrap_or("?").to_string(),
        s["kind"].as_str().unwrap_or("?").to_string(),
        if s["enabled"].as_bool().unwrap_or(false) { ui::state("enabled") } else { ui::state("disabled") },
        s["placements"].as_i64().unwrap_or(0).to_string(),
        s["tools"].as_i64().unwrap_or(0).to_string(),
        s["audience"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(",")).filter(|x| !x.is_empty()).unwrap_or_else(|| "operators".into()),
    ]).collect();
    print!("{}", ui::table(&[Col::left("id"), Col::left("transport"), Col::left("kind"), Col::left("state"), Col::right("nodes"), Col::right("tools"), Col::left("audience")], &rows));
    Ok(0)
}

/// `noo mcp server show <id>` — GET /api/mcp/servers/{id}.
pub fn mcp_server_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [id] = args else { return Err(Unhandled) };
    let s = crate::http::get_json(g, &format!("/api/mcp/servers/{}", super::urlencode(id)), true, 15);
    if g.json { println!("{s}"); return Ok(0); }
    println!("{}", ui::header(id, Some("mcp server")));
    let dash = ui::dash();
    let rows: Vec<(&str, String)> = vec![
        ("transport", s["transport"].as_str().unwrap_or(dash).to_string()),
        ("kind", s["kind"].as_str().unwrap_or(dash).to_string()),
        ("enabled", s["enabled"].as_bool().map(|b| b.to_string()).unwrap_or_else(|| dash.into())),
        ("audience", s["audience"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).filter(|x| !x.is_empty()).unwrap_or_else(|| "operators only".into())),
        ("owner", s["owner"].as_str().unwrap_or(dash).to_string()),
        ("note", s["note"].as_str().unwrap_or(dash).to_string()),
        ("spec", serde_json::to_string(&s["spec"]).unwrap_or_default()),
    ];
    print!("{}", ui::kv(&rows));
    let empty = Vec::new();
    println!("{}", ui::section("placements"));
    let pl = s["placements"].as_array().unwrap_or(&empty);
    if pl.is_empty() { println!("{}", ui::muted("none — `noo mcp place <id> <node>`")); }
    for p in pl {
        println!("  {}  {}", p["node_id"].as_str().unwrap_or("?"), ui::state(p["desired_state"].as_str().unwrap_or("?")));
    }
    println!("{}", ui::section("tools"));
    let tools = s["tools"].as_array().unwrap_or(&empty);
    if tools.is_empty() { println!("{}", ui::muted("none discovered yet (node-side discovery arrives with phase B)")); }
    for t in tools {
        println!("  {}  {}", t["name"].as_str().unwrap_or("?"), ui::muted(&truncate(t["description"].as_str().unwrap_or(""), 70)));
    }
    Ok(0)
}

fn mcp_server_set_enabled(g: &Globals, args: &[String], enabled: bool) -> Result<i32, Unhandled> {
    let [id] = args else { return Err(Unhandled) };
    let resp = crate::http::put_json(g, &format!("/api/mcp/servers/{}", super::urlencode(id)), &json!({ "enabled": enabled }), true, 15);
    if g.json { println!("{resp}"); return Ok(0); }
    ui::done(&format!("'{id}' {}", if enabled { "enabled" } else { "disabled" }));
    Ok(0)
}
/// `noo mcp server enable <id>`
pub fn mcp_server_enable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> { mcp_server_set_enabled(g, args, true) }
/// `noo mcp server disable <id>`
pub fn mcp_server_disable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> { mcp_server_set_enabled(g, args, false) }

/// `noo mcp server remove <id> [-y]` — DELETE /api/mcp/servers/{id}.
pub fn mcp_server_remove(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut id: Option<String> = None;
    let mut yes = false;
    for a in args {
        match a.as_str() {
            "-y" | "--yes" | "--force" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t if id.is_none() => id = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let Some(id) = id else { return Err(Unhandled) };
    super::confirm_destructive(g, yes, "remove the MCP server record (and its placements) for", &id);
    let resp = crate::http::delete_json(g, &format!("/api/mcp/servers/{}", super::urlencode(&id)), true, 15);
    if g.json { println!("{resp}"); return Ok(0); }
    ui::done(&format!("'{id}' removed"));
    Ok(0)
}

/// `noo mcp place <id> <node> [--stopped]` — PUT …/placements/{node}.
pub fn mcp_place(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut pos: Vec<String> = Vec::new();
    let mut state = "running";
    for a in args {
        match a.as_str() {
            "--stopped" => state = "stopped",
            t if t.starts_with('-') => return Err(Unhandled),
            t => pos.push(t.to_string()),
        }
    }
    let [id, node] = pos.as_slice() else { return Err(Unhandled) };
    let resp = crate::http::put_json(g, &format!("/api/mcp/servers/{}/placements/{}", super::urlencode(id), super::urlencode(node)), &json!({ "desired_state": state }), true, 15);
    if g.json { println!("{resp}"); return Ok(0); }
    ui::done(&format!("'{id}' placed on {node} ({state})"));
    if let Some(n) = resp["note"].as_str() { println!("{}", ui::note(n)); }
    Ok(0)
}

/// `noo mcp unplace <id> <node>` — DELETE …/placements/{node}.
pub fn mcp_unplace(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [id, node] = args else { return Err(Unhandled) };
    let resp = crate::http::delete_json(g, &format!("/api/mcp/servers/{}/placements/{}", super::urlencode(id), super::urlencode(node)), true, 15);
    if g.json { println!("{resp}"); return Ok(0); }
    ui::done(&format!("'{id}' unplaced from {node}"));
    Ok(0)
}

/// The seed-file shape — YAML as DATA (the operator's rule), never as the
/// place a server is configured:
///
/// ```yaml
/// servers:
///   docs:
///     transport: http
///     kind: tool
///     audience: [company]
///     note: docs tools
///     spec: {url: https://mcp.example/mcp, headers: {Authorization: $MCP_DOCS_BEARER}}
///     placements: [host8]
/// ```
///
/// The default transport is `http`, and it used to be `stdio` — a seed file
/// that named no transport asked the fleet to execute a command. A seed
/// naming `stdio` explicitly is still passed through so the GATEWAY refuses
/// it by name; swallowing it here would hide which entry was dropped.
fn server_from_yaml(id: &str, v: &serde_json::Value) -> serde_json::Value {
    let transport = match v["transport"].as_str() { Some("http") => "streamable_http", Some(t) => t, None => "streamable_http" };
    json!({
        "id": id,
        "transport": transport,
        "spec": if v["spec"].is_null() { json!({}) } else { v["spec"].clone() },
        "kind": v["kind"].as_str().unwrap_or("tool"),
        "audience": v["audience"].as_array().cloned().unwrap_or_default(),
        "note": v["note"].as_str(),
        "enabled": v["enabled"].as_bool().unwrap_or(true),
    })
}

/// `noo mcp import [<file>] [--dry-run]` — upsert every server + placement
/// from a YAML file (default config/mcp-servers.yaml).
pub fn mcp_import(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut file = std::path::PathBuf::from("config/mcp-servers.yaml");
    let mut dry = false;
    for a in args {
        match a.as_str() {
            "--dry-run" => dry = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => file = std::path::PathBuf::from(t),
        }
    }
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => fail(g.json, ExitCode::Generic, "no_file", &format!("cannot read {}: {e}", file.display()), Some("`noo mcp export` writes one from the live registry")),
    };
    let doc: serde_json::Value = match serde_yaml::from_str::<serde_yaml::Value>(&text).ok().and_then(|y| serde_json::to_value(y).ok()) {
        Some(d) => d,
        None => fail(g.json, ExitCode::Generic, "bad_yaml", &format!("{} is not valid YAML", file.display()), None),
    };
    let empty = serde_json::Map::new();
    let servers = doc["servers"].as_object().unwrap_or(&empty);
    let (mut ok, mut failed) = (0usize, 0usize);
    for (id, v) in servers {
        let body = server_from_yaml(id, v);
        if dry {
            println!("{}", ui::status_line(Glyph::Step, &format!("would register {id}: {body}")));
        } else {
            // Create, or update the mutable half if it already exists.
            match crate::http::post_json_try(g, "/api/mcp/servers", &body, true, 15) {
                Ok(_) => { ui::done(&format!("{id}: registered")); ok += 1; }
                Err(e) if e.contains("already exists") => {
                    let upd = json!({ "spec": body["spec"], "kind": body["kind"], "audience": body["audience"], "note": body["note"], "enabled": body["enabled"] });
                    match crate::http::put_json_try(g, &format!("/api/mcp/servers/{}", super::urlencode(id)), &upd, true, 15) {
                        Ok(_) => { ui::done(&format!("{id}: updated")); ok += 1; }
                        Err(e) => { println!("{}", ui::status_line(Glyph::Err, &format!("{id}: update failed ({e})"))); failed += 1; }
                    }
                }
                Err(e) => { println!("{}", ui::status_line(Glyph::Err, &format!("{id}: register failed ({e})"))); failed += 1; continue; }
            }
        }
        for node in v["placements"].as_array().into_iter().flatten().filter_map(|n| n.as_str()) {
            if dry {
                println!("{}", ui::status_line(Glyph::Step, &format!("would place {id} on {node}")));
                continue;
            }
            match crate::http::put_json_try(g, &format!("/api/mcp/servers/{}/placements/{}", super::urlencode(id), super::urlencode(node)), &json!({}), true, 15) {
                Ok(_) => ui::done(&format!("{id}: placed on {node}")),
                Err(e) => { println!("{}", ui::status_line(Glyph::Err, &format!("{id} on {node}: {e}"))); failed += 1; }
            }
        }
    }
    if g.json {
        println!("{}", json!({ "file": file.display().to_string(), "servers": servers.len(), "applied": ok, "failed": failed, "dry_run": dry }));
    } else if !dry {
        ui::done(&format!("{ok} server(s) applied from {}{}", file.display(), if failed > 0 { format!(", {failed} failed") } else { String::new() }));
    }
    Ok(if failed > 0 { 1 } else { 0 })
}

/// `noo mcp export [--file <path>]` — snapshot the registry as the import shape.
pub fn mcp_export(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut file: Option<std::path::PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--file" | "-f" => file = Some(std::path::PathBuf::from(it.next().ok_or(Unhandled)?)),
            _ => return Err(Unhandled),
        }
    }
    let list = crate::http::get_json(g, "/api/mcp/servers", true, 15);
    let empty = Vec::new();
    let mut out = serde_yaml::Mapping::new();
    for s in list["servers"].as_array().unwrap_or(&empty) {
        let Some(id) = s["id"].as_str() else { continue };
        let full = crate::http::get_json(g, &format!("/api/mcp/servers/{}", super::urlencode(id)), true, 15);
        let mut m = serde_yaml::Mapping::new();
        for k in ["transport", "kind", "audience", "note", "enabled", "spec"] {
            if !full[k].is_null() {
                if let Ok(yv) = serde_yaml::to_value(&full[k]) { m.insert(serde_yaml::Value::String(k.into()), yv); }
            }
        }
        let nodes: Vec<serde_yaml::Value> = full["placements"].as_array().unwrap_or(&empty).iter().filter_map(|p| p["node_id"].as_str().map(|n| serde_yaml::Value::String(n.into()))).collect();
        if !nodes.is_empty() { m.insert(serde_yaml::Value::String("placements".into()), serde_yaml::Value::Sequence(nodes)); }
        out.insert(serde_yaml::Value::String(id.into()), serde_yaml::Value::Mapping(m));
    }
    let mut doc = serde_yaml::Mapping::new();
    doc.insert("servers".into(), serde_yaml::Value::Mapping(out));
    let text = serde_yaml::to_string(&serde_yaml::Value::Mapping(doc)).unwrap_or_default();
    let text = format!("# noo mcp export — the external MCP server registry as DATA.\n# Re-apply with: noo mcp import <file>. Secrets are $NAME references; none are here.\n{text}");
    match file {
        Some(p) => {
            if let Err(e) = std::fs::write(&p, &text) {
                fail(g.json, ExitCode::Generic, "write_failed", &format!("cannot write {}: {e}", p.display()), None);
            }
            if g.json { println!("{}", json!({ "file": p.display().to_string() })); } else { ui::done(&format!("wrote {}", p.display())); }
        }
        None => print!("{text}"),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_json_response() {
        let v = parse_rpc_response(
            "application/json",
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#,
            2,
        )
        .unwrap();
        assert!(v["result"]["tools"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parses_sse_frames_lf_and_crlf() {
        // LF-framed
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":true}}\n\n";
        let v = parse_rpc_response("text/event-stream", body, 2).unwrap();
        assert_eq!(v["result"]["ok"], true);
        // CRLF-framed
        let body = "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":1}}\r\n\r\n";
        let v = parse_rpc_response("text/event-stream; charset=utf-8", body, 2).unwrap();
        assert_eq!(v["result"]["ok"], 1);
    }

    #[test]
    fn sse_picks_matching_id_over_other_frames() {
        let body = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[{\"name\":\"x\"}]}}\n\n",
        );
        let v = parse_rpc_response("text/event-stream", body, 7).unwrap();
        assert_eq!(v["result"]["tools"][0]["name"], "x");
    }

    #[test]
    fn source_derivation_matches_client_prefix_convention() {
        assert_eq!(tool_source("noo_inference"), "noo");
        assert_eq!(tool_source("web_search"), "noo");
        assert_eq!(tool_source("mcp_github_create_issue"), "external");
    }

    #[test]
    fn door_bearer_is_the_personal_key_and_never_the_retired_token() {
        // Serial-safe: this test owns both vars for its duration.
        std::env::set_var("NOO_MCP_KEY", " k1 ");
        std::env::set_var("NOO_MCP_TOKEN", "shared");
        assert_eq!(door_bearer(), "k1");
        std::env::remove_var("NOO_MCP_KEY");
        assert_eq!(door_bearer(), "", "the retired shared token must never be sent");
        std::env::remove_var("NOO_MCP_TOKEN");
        assert_eq!(door_bearer(), "");
    }

    #[test]
    fn a_leftover_token_gets_one_line_naming_the_key_that_replaces_it() {
        assert!(retired_token_note(None).is_none());
        assert!(retired_token_note(Some("  ")).is_none());
        let n = retired_token_note(Some("x")).expect("a set token is noticed");
        assert!(n.contains("retired") && n.contains("NOO_MCP_KEY") && n.contains(MINT_HINT), "{n}");
        assert!(!n.contains(" x "), "the note never echoes the value");
    }

    #[test]
    fn the_door_is_the_operator_path_on_the_gateway() {
        // The 3100 listener is gone: `noo mcp tools` dials the gateway URL
        // it resolves like every other command, never a hub host/port pair.
        let g = Globals { json: false, verbose: false, gateway_override: Some("https://gw.example:8080".into()), timeout_secs: None, token: None, quiet: false };
        let (base, url) = door_url(&g);
        assert_eq!(base, "https://gw.example:8080");
        assert_eq!(url, "https://gw.example:8080/mcp/operator");
    }
}
