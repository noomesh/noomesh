// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The bridge to EXTERNAL MCP servers.
//!
//! An agent sees an external tool as `mcp_<server>_<tool>` in the same list
//! as the compiled-in tools, and calls it the same way. This module is the
//! seam: it decides WHICH external tools a caller may see (the server's
//! audience, in the knowledge-base vocabulary), turns a call on such a name
//! into a request to the node that hosts the server (`POST
//! /api/mcp/{server}/call` on the node agent, phase B), and records who
//! called what. Nothing here speaks MCP to the server itself — the hosting
//! node does; the gateway never grows an MCP client.
//!
//! Identity rides a task-local, [`CALLER`], set by the coordinator around
//! each tool execution: the tool executor has no argument for "who is
//! running", and threading one through every call site would touch code
//! that has nothing to do with this. `None` is an internal run (heartbeat,
//! research) and is treated as operator-tier, the same as everywhere else
//! a cluster caller has no person behind it.

use std::str::FromStr;

use serde_json::{json, Value};

use crate::auth::Role;
use crate::state::AppState;

tokio::task_local! {
    /// The canonical username the current tool call runs for, when a
    /// person is behind it. Set by the agent loop around `execute_tool`.
    pub static CALLER: Option<String>;
    /// The credential class the current tool call arrived on
    /// when it is not the gateway's own loop: `node:<id>` on the
    /// harness rail. Set by `routes::harness` around `execute_tool`; unset
    /// in process, where the loop is the controller's own.
    pub static HARNESS: Option<String>;
    /// The conversation the current tool call belongs to. Set by the loop
    /// around `execute_tool` and by the harness rail from the token's
    /// `conv` claim; `noo_task_done` finds its task through it.
    pub static CONVERSATION: Option<String>;
}

/// The conversation behind the current tool call, if the loop set one.
pub fn current_conversation() -> Option<String> {
    CONVERSATION.try_with(|c| c.clone()).unwrap_or(None)
}

/// The credential class behind the current tool call, if a remote one.
pub fn current_harness() -> Option<String> {
    HARNESS.try_with(|h| h.clone()).unwrap_or(None)
}

/// The username behind the current call, if the loop set one.
pub fn current_caller() -> Option<String> {
    CALLER.try_with(|c| c.clone()).unwrap_or(None)
}

pub const PREFIX: &str = "mcp_";

/// One tool the registry knows, on a server that is enabled and placed.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalTool {
    pub server: String,
    pub kind: String,
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

impl ExternalTool {
    pub fn full_name(&self) -> String {
        full_name(&self.server, &self.name)
    }
    /// The shape the coordinator hands the model (OpenAI function format,
    /// same as `config/tools.json`). The description is prefixed with the
    /// server so the model can tell two servers' `search` apart.
    pub fn llm_schema(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": self.full_name(),
                "description": format!("[{}] {}", self.server, self.description),
                "parameters": self.input_schema,
            },
            "tags": ["external", self.kind],
        })
    }
    /// The shape the MCP doors list.
    pub fn mcp_tool(&self) -> Value {
        json!({
            "name": self.full_name(),
            "description": format!("[{}] {}", self.server, self.description),
            "inputSchema": self.input_schema,
        })
    }
}

pub fn full_name(server: &str, tool: &str) -> String {
    format!("{PREFIX}{server}_{tool}")
}

/// Split `mcp_<server>_<tool>` against the registered ids. Server ids may
/// contain `_` and so may tool names, so the split is by LONGEST registered
/// id, never by the first underscore.
pub fn split_name(name: &str, ids: &[String]) -> Option<(String, String)> {
    let rest = name.strip_prefix(PREFIX)?;
    let mut best: Option<(&String, &str)> = None;
    for id in ids {
        if let Some(tool) = rest.strip_prefix(id.as_str()).and_then(|r| r.strip_prefix('_')) {
            if !tool.is_empty() && best.is_none_or(|(b, _)| id.len() > b.len()) {
                best = Some((id, tool));
            }
        }
    }
    best.map(|(id, tool)| (id.clone(), tool.to_string()))
}

/// The audience rule, pure. Empty audience = operators only. A person sees
/// a server when the audience names `company`, `system`, their own
/// `user:<name>`, or a `team:<t>` they hold. Operator and above see all;
/// so does an internal caller (no person).
pub fn audience_permits(audience: &[String], user: Option<&str>, role: Option<Role>, kb_roles: &[String]) -> bool {
    let Some(user) = user else { return true };
    if role.is_some_and(|r| r >= Role::Operator) {
        return true;
    }
    audience.iter().any(|a| {
        a == "company"
            || a == "system"
            || a.strip_prefix("user:") == Some(user)
            || (a.starts_with("team:") && kb_roles.iter().any(|r| r == a))
    })
}

fn audience_of(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// A person's role and knowledge-base roles, for the audience rule.
async fn identity(state: &AppState, user: Option<&str>) -> (Option<Role>, Vec<String>) {
    let Some(u) = user else { return (None, Vec::new()) };
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM noo_users WHERE username = $1 AND NOT disabled")
        .bind(u)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let role = role.and_then(|r| Role::from_str(&r).ok());
    let kb = crate::repo::kb_grants::get_roles(&state.db, u)
        .await
        .ok()
        .flatten()
        .map(|v| audience_of(&v))
        .unwrap_or_default();
    (role, kb)
}

/// Every external tool this caller may see: enabled servers with a
/// `running` placement and a discovered catalog, filtered by audience.
pub async fn catalog_for(state: &AppState, user: Option<&str>) -> Vec<ExternalTool> {
    let rows: Vec<(String, String, Value, String, String, Value)> = match sqlx::query_as(
        "SELECT s.id, s.kind, s.audience, t.name, t.description, t.input_schema \
         FROM noo_mcp_servers s JOIN noo_mcp_server_tools t ON t.server_id = s.id \
         WHERE s.enabled AND EXISTS ( \
             SELECT 1 FROM noo_mcp_server_placements p \
             WHERE p.server_id = s.id AND p.desired_state = 'running') \
         ORDER BY s.id, t.name",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "mcp_bridge_catalog_query_failed");
            return Vec::new();
        }
    };
    if rows.is_empty() {
        return Vec::new();
    }
    let (role, kb) = identity(state, user).await;
    rows.into_iter()
        .filter(|(_, _, aud, _, _, _)| audience_permits(&audience_of(aud), user, role, &kb))
        .map(|(server, kind, _, name, description, input_schema)| ExternalTool { server, kind, name, description, input_schema })
        .collect()
}

/// The LLM-facing schemas for a run.
pub async fn llm_schemas_for(state: &AppState, user: Option<&str>) -> Vec<Value> {
    catalog_for(state, user).await.iter().map(ExternalTool::llm_schema).collect()
}

pub async fn server_ids(state: &AppState) -> Vec<String> {
    sqlx::query_scalar("SELECT id FROM noo_mcp_servers WHERE enabled")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
}

/// Flatten an MCP `tools/call` result to the text the model reads.
/// `isError: true` is a tool execution error (the model may retry).
pub fn flatten_result(v: &Value) -> Result<String, String> {
    let texts: Vec<String> = v
        .get("content")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|c| match c.get("type").and_then(Value::as_str) {
                    Some("text") => c.get("text").and_then(Value::as_str).map(str::to_string),
                    Some(other) => Some(format!("[{other} content omitted]")),
                    None => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let mut text = texts.join("\n");
    if text.is_empty() {
        if let Some(sc) = v.get("structuredContent") {
            text = sc.to_string();
        }
    }
    if v.get("isError").and_then(Value::as_bool).unwrap_or(false) {
        return Err(if text.is_empty() { "tool reported an error".into() } else { text });
    }
    Ok(text)
}

/// Run one external tool for `user`: audience check, then the hosting node.
/// Returns the flattened text, or the reason it did not run.
pub async fn call(state: &AppState, user: Option<&str>, server: &str, tool: &str, args: &Value) -> Result<String, String> {
    let started = std::time::Instant::now();
    // The server must be enabled, the tool discovered, and the caller in
    // the audience — a model that guesses a name it was never shown gets
    // the same answer as one it was.
    let row: Option<(Value, bool)> = sqlx::query_as(
        "SELECT s.audience, EXISTS(SELECT 1 FROM noo_mcp_server_tools t WHERE t.server_id = s.id AND t.name = $2) \
         FROM noo_mcp_servers s WHERE s.id = $1 AND s.enabled",
    )
    .bind(server)
    .bind(tool)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("registry: {e}"))?;
    let Some((audience, has_tool)) = row else {
        return Err(format!("no enabled MCP server '{server}'"));
    };
    if !has_tool {
        return Err(format!("'{server}' has no discovered tool '{tool}'"));
    }
    let (role, kb) = identity(state, user).await;
    if !audience_permits(&audience_of(&audience), user, role, &kb) {
        record(state, server, tool, user, false, started).await;
        return Err(format!("'{server}' is not in your audience"));
    }
    let nodes: Vec<String> = sqlx::query_scalar(
        "SELECT node_id FROM noo_mcp_server_placements WHERE server_id = $1 AND desired_state = 'running' ORDER BY node_id",
    )
    .bind(server)
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("placements: {e}"))?;
    if nodes.is_empty() {
        return Err(format!("'{server}' is not placed on any node"));
    }
    let mut last_err = String::new();
    for node in &nodes {
        let link = match crate::node_link::NodeLink::for_node(state, node).await {
            Ok(l) => l,
            Err(e) => {
                last_err = format!("{node}: {e}");
                continue;
            }
        };
        let req = link
            .request(reqwest::Method::POST, &format!("/api/mcp/{server}/call"))
            .json(&json!({ "tool": tool, "arguments": args }))
            .timeout(std::time::Duration::from_secs(130));
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: Value = resp.json().await.unwrap_or(json!({}));
                let out = flatten_result(&body);
                record(state, server, tool, user, out.is_ok(), started).await;
                return out;
            }
            Ok(resp) => {
                let st = resp.status();
                let text = resp.text().await.unwrap_or_default();
                last_err = format!("{node}: HTTP {st} {}", text.chars().take(200).collect::<String>());
            }
            Err(e) => last_err = format!("{node}: {e}"),
        }
    }
    record(state, server, tool, user, false, started).await;
    Err(format!("no node could run '{server}': {last_err}"))
}

/// One row per call (`noo_mcp_calls`, migration 066) plus an audit event,
/// so "who used which external tool, and did it work" is answerable.
async fn record(state: &AppState, server: &str, tool: &str, user: Option<&str>, ok: bool, started: std::time::Instant) {
    let ms = started.elapsed().as_millis() as i32;
    if let Err(e) = sqlx::query(
        "INSERT INTO noo_mcp_calls (server_id, tool, user_uuid, ok, ms) \
         VALUES ($1, $2, (SELECT user_uuid FROM noo_users WHERE username = $3), $4, $5)",
    )
    .bind(server)
    .bind(tool)
    .bind(user)
    .bind(ok)
    .bind(ms)
    .execute(&state.db)
    .await
    {
        tracing::warn!(error = %e, "mcp_call_record_failed");
    }
    crate::routes::core::audit_event(
        &state.db,
        "mcp_external_call",
        "info",
        user.unwrap_or("internal"),
        &full_name(server, tool),
        if ok { "ok" } else { "error" },
        json!({ "server": server, "tool": tool, "ms": ms }),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// Ids and tool names both allow `_`; the split is by the longest
    /// registered id, so `git_hub` + `status` beats `git` + `hub_status`.
    #[test]
    fn split_prefers_the_longest_registered_id() {
        let ids = s(&["git", "git_hub", "lab-scope"]);
        assert_eq!(split_name("mcp_git_hub_status", &ids), Some(("git_hub".into(), "status".into())));
        assert_eq!(split_name("mcp_git_status", &ids), Some(("git".into(), "status".into())));
        assert_eq!(split_name("mcp_lab-scope_read_sensor", &ids), Some(("lab-scope".into(), "read_sensor".into())));
        assert_eq!(split_name("mcp_unknown_x", &ids), None);
        assert_eq!(split_name("noo_status", &ids), None, "not an external name");
        assert_eq!(split_name("mcp_git_", &ids), None, "empty tool name");
        assert_eq!(full_name("git", "status"), "mcp_git_status");
    }

    #[test]
    fn audience_rule_matrix() {
        let aud = s(&["team:lab", "user:alice"]);
        // Internal caller and operators see everything, including an empty audience.
        assert!(audience_permits(&[], None, None, &[]));
        assert!(audience_permits(&[], Some("bob"), Some(Role::Operator), &[]));
        assert!(audience_permits(&[], Some("bob"), Some(Role::Admin), &[]));
        // A user sees what names them, their team, or the company tiers.
        assert!(audience_permits(&aud, Some("alice"), Some(Role::User), &[]));
        assert!(audience_permits(&aud, Some("bob"), Some(Role::User), &s(&["team:lab"])));
        assert!(!audience_permits(&aud, Some("bob"), Some(Role::User), &s(&["team:ops"])));
        assert!(audience_permits(&s(&["company"]), Some("bob"), Some(Role::User), &[]));
        assert!(audience_permits(&s(&["system"]), Some("bob"), Some(Role::User), &[]));
        // Empty audience = operators only: a user is refused.
        assert!(!audience_permits(&[], Some("bob"), Some(Role::User), &[]));
        // An account with no role (unknown/disabled) is never an operator: it
        // still sees company-wide tools, but nothing operator-only.
        assert!(audience_permits(&s(&["company"]), Some("ghost"), None, &[]));
        assert!(!audience_permits(&[], Some("ghost"), None, &[]));
    }

    #[test]
    fn schemas_carry_the_server_and_the_prefix() {
        let t = ExternalTool {
            server: "git".into(),
            kind: "tool".into(),
            name: "status".into(),
            description: "Repo status".into(),
            input_schema: json!({"type": "object", "properties": {"repo": {"type": "string"}}}),
        };
        let llm = t.llm_schema();
        assert_eq!(llm["function"]["name"], "mcp_git_status");
        assert_eq!(llm["function"]["description"], "[git] Repo status");
        assert_eq!(llm["function"]["parameters"]["properties"]["repo"]["type"], "string");
        assert_eq!(llm["tags"], json!(["external", "tool"]));
        let mcp = t.mcp_tool();
        assert_eq!(mcp["name"], "mcp_git_status");
        assert!(mcp.get("inputSchema").is_some());
    }

    #[test]
    fn results_flatten_to_text_and_errors_stay_errors() {
        assert_eq!(
            flatten_result(&json!({"content": [{"type": "text", "text": "a"}, {"type": "image", "data": "…"}, {"type": "text", "text": "b"}], "isError": false})).unwrap(),
            "a\n[image content omitted]\nb"
        );
        assert_eq!(flatten_result(&json!({"content": [], "structuredContent": {"k": 1}})).unwrap(), r#"{"k":1}"#);
        let e = flatten_result(&json!({"content": [{"type": "text", "text": "bad date"}], "isError": true})).unwrap_err();
        assert_eq!(e, "bad date");
        assert_eq!(flatten_result(&json!({"isError": true})).unwrap_err(), "tool reported an error");
    }
}
