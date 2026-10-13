// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `/api/mcp/servers*` — the registry of EXTERNAL MCP servers
//! phase A.
//!
//! Third-party tool servers and MHS device drivers arrive through the same
//! door, so the cluster keeps ONE record of them: what a server is
//! (`noo_mcp_servers`), where it runs (`noo_mcp_server_placements`, one
//! row per node, in the same shape as backend placements), and what it
//! offers (`noo_mcp_server_tools`, filled by the node-side discovery of
//! phase B). This module is the record and its operator surface; nothing
//! here starts a server or calls a tool — that is phases B and C, and the
//! docs say so.
//!
//! Rules that hold at the write boundary rather than in prose:
//!
//! - **The id is a tool-name prefix.** Discovered tools become
//!   `mcp_<id>_<tool>`, so the id is held to the MCP tool-name charset.
//! - **No secret is ever stored here.** A `spec.env` / `spec.headers` value
//!   for a secret-looking key must be a `$NAME` reference; the hosting node
//!   resolves it from its own `/etc/noo/mcp-secrets.env` (never the
//!   controller's store, never the agent's env). A literal is refused,
//!   naming the key and that file.
//! - **Audience is the knowledge-base vocabulary.** `company`, `system`,
//!   `generated`, `team:<name>` (the team must exist), `user:<username>`.
//!   Empty means "operators only" — the safe default for a server that
//!   was just registered.
//! - **Registration is cluster-wide; placement is per node.** Any caller in
//!   the audience will reach the tools through the gateway once phase C
//!   lands; the placement only says which node hosts the process (stdio)
//!   or dials the endpoint (http).
//! - **Owner is a uuid**, resolved from the caller's name at insert;
//!   never a name column.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::{get, put},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::auth::{AuthActor, RequesterCtx, Role};
use crate::routes::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/mcp/servers", get(servers_list).post(server_create))
        .route(
            "/api/mcp/servers/{id}",
            get(server_get).put(server_update).delete(server_delete),
        )
        .route(
            "/api/mcp/servers/{id}/placements/{node}",
            put(placement_put).delete(placement_delete),
        )
        // Node rail (phase B): the hosting node reports what it discovered.
        .route("/api/cluster/nodes/{node}/mcp/{id}/tools", axum::routing::post(node_tools_report))
}

// ───────────────────────────── validation ─────────────────────────────

/// The registry still KNOWS the stdio transport — the table's check
/// constraint allows it and legacy rows may carry it — but nothing may
/// write one any more, and no node will start one. See
/// docs/security/node-agent.md.
pub const TRANSPORTS: &[&str] = &["stdio", "streamable_http"];

/// Why a stdio server cannot be registered or placed from here.
///
/// A stdio spec is a command, its arguments, its working directory and its
/// environment, which the node would EXECUTE. Shipping that from a
/// controller row made "place an MCP server" a remote-code-execution verb
/// against every node in the fleet, and no validation of the row fixes it:
/// the row is written by the side whose compromise the node's wall exists
/// to contain. So stdio servers are declared on the node, in a root-owned
/// file the controller cannot write, and the controller's half of the job
/// — which node, running or stopped — is all it keeps.
pub const STDIO_IS_NODE_LOCAL: &str = "stdio MCP servers are declared on the node, not from here: the spec is a command the node would execute, so it comes from a root-owned file on that host (/etc/noo/mcp-servers.json — see docs/security/node-agent.md), never from the controller. Register this server as `--transport http` with a URL the node dials, or add it to that file and restart its agent.";
pub const KINDS: &[&str] = &["tool", "device"];
pub const DESIRED_STATES: &[&str] = &["running", "stopped"];
const BUILTIN_AUDIENCES: &[&str] = &["company", "system", "generated"];

/// `^[a-z0-9][a-z0-9_-]{0,63}$` — lowercase so the derived tool name
/// `mcp_<id>_<tool>` stays inside the MCP tool-name charset and cannot
/// collide with a compiled-in `noo_*` tool.
pub fn valid_server_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

/// Keys whose value is a credential. A literal under one of these is
/// refused; a `$NAME` reference is what belongs here.
fn secret_looking(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    ["TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "AUTHORIZATION", "BEARER", "CREDENTIAL", "PRIVATE"]
        .iter()
        .any(|m| k.contains(m))
        || k == "KEY"
        || k.ends_with("_KEY")
}

fn is_store_ref(v: &str) -> bool {
    let Some(rest) = v.strip_prefix('$') else { return false };
    let b = rest.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn validate_kv_map(map: &Value, what: &str) -> Result<(), String> {
    let Some(obj) = map.as_object() else {
        return Err(format!("spec.{what} must be an object of string values"));
    };
    for (k, v) in obj {
        let Some(s) = v.as_str() else {
            return Err(format!("spec.{what}.{k} must be a string"));
        };
        if secret_looking(k) && !is_store_ref(s) {
            return Err(format!(
                "spec.{what}.{k} looks like a credential and is a literal — reference it as \"${k}\" and write {k}=<value> into /etc/noo/mcp-secrets.env on the node that dials this server (the controller never holds it)"
            ));
        }
        // A value that IS a credential under an innocent key.
        let low = s.to_ascii_lowercase();
        if low.starts_with("noo-sk-") || low.starts_with("bearer ") || low.starts_with("$2b$") || low.starts_with("sk-") {
            return Err(format!("spec.{what}.{k} is a literal credential — reference the secret store as \"$NAME\" instead"));
        }
    }
    Ok(())
}

/// The transport-specific shape of `spec`. Pure; the tests pin every branch.
pub fn validate_spec(transport: &str, spec: &Value) -> Result<(), String> {
    // Before the spec is even looked at: the TRANSPORT is what is refused,
    // so the answer does not depend on the shape of what came with it.
    // Checking the object shape first made a malformed stdio spec reply
    // "spec must be an object", which reads as "fix your JSON" — and an
    // operator who fixed it would meet the real refusal on the next try.
    if transport == "stdio" {
        return Err(STDIO_IS_NODE_LOCAL.into());
    }
    let Some(obj) = spec.as_object() else {
        return Err("spec must be an object".into());
    };
    match transport {
        "streamable_http" => {
            let url = obj.get("url").and_then(Value::as_str).unwrap_or("");
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err("streamable_http transport needs spec.url (http:// or https://)".into());
            }
            if let Some(h) = obj.get("headers") {
                validate_kv_map(h, "headers")?;
            }
            for k in obj.keys() {
                if !matches!(k.as_str(), "url" | "headers") {
                    return Err(format!("spec.{k} is not a streamable_http key (url, headers)"));
                }
            }
        }
        other => return Err(format!("transport '{other}' is not one of {TRANSPORTS:?}")),
    }
    Ok(())
}

/// Audience entries against the knowledge-base vocabulary. Team existence
/// is checked by the caller against the DB; this is the pure half.
pub fn validate_audience_shape(audience: &[String]) -> Result<Vec<String>, String> {
    let mut teams = Vec::new();
    for a in audience {
        if BUILTIN_AUDIENCES.contains(&a.as_str()) {
            continue;
        }
        if let Some(t) = a.strip_prefix("team:") {
            if !valid_server_id(t) {
                return Err(format!("audience '{a}': team names are [a-z0-9][a-z0-9_-]*"));
            }
            teams.push(t.to_string());
            continue;
        }
        if let Some(u) = a.strip_prefix("user:") {
            if u.is_empty() || u.len() > 128 {
                return Err(format!("audience '{a}': empty username"));
            }
            continue;
        }
        return Err(format!(
            "audience '{a}' is not company | system | generated | team:<name> | user:<username>"
        ));
    }
    Ok(teams)
}

// ───────────────────────────── auth helpers ─────────────────────────────

/// Operator-only, on reads too (a read-scope user must not enumerate the
/// servers, their env keys or their placements). Cluster-HMAC callers carry
/// no `RequesterCtx` and pass, as everywhere on `/api/security/*`.
fn operator_guard(ctx: &Option<Extension<RequesterCtx>>) -> Result<(), AppError> {
    match ctx {
        None => Ok(()),
        Some(Extension(r)) if r.role >= Role::Operator => Ok(()),
        Some(_) => Err(AppError::Forbidden("operator role required".into())),
    }
}

fn actor_label(actor: &Option<Extension<AuthActor>>) -> String {
    actor.as_ref().map(|Extension(a)| a.0.clone()).unwrap_or_else(|| "cluster".into())
}

// ───────────────────────────── handlers ─────────────────────────────

async fn servers_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    operator_guard(&ctx)?;
    let rows = sqlx::query(
        "SELECT s.id, s.transport, s.kind, s.enabled, s.audience, s.note, s.created_at, s.updated_at, \
                u.username AS owner, \
                (SELECT COUNT(*) FROM noo_mcp_server_placements p WHERE p.server_id = s.id) AS placements, \
                (SELECT COUNT(*) FROM noo_mcp_server_tools t WHERE t.server_id = s.id) AS tools \
         FROM noo_mcp_servers s LEFT JOIN noo_users u ON u.user_uuid = s.owner_uuid \
         ORDER BY s.id",
    )
    .fetch_all(&state.db)
    .await?;
    let servers: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<String, _>("id"),
                "transport": r.get::<String, _>("transport"),
                "kind": r.get::<String, _>("kind"),
                "enabled": r.get::<bool, _>("enabled"),
                "audience": r.get::<Value, _>("audience"),
                "note": r.get::<Option<String>, _>("note"),
                "owner": r.get::<Option<String>, _>("owner"),
                "placements": r.get::<i64, _>("placements"),
                "tools": r.get::<i64, _>("tools"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                "updated_at": r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
            })
        })
        .collect();
    Ok(Json(json!({ "servers": servers, "count": servers.len() })))
}

#[derive(Deserialize)]
struct CreateBody {
    id: String,
    transport: String,
    #[serde(default)]
    spec: Value,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default)]
    audience: Vec<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}
fn default_kind() -> String {
    "tool".into()
}
fn default_true() -> bool {
    true
}

async fn check_teams(db: &sqlx::PgPool, teams: &[String]) -> Result<(), AppError> {
    if teams.is_empty() {
        return Ok(());
    }
    let known = crate::repo::kb_grants::existing_team_names(db, teams).await?;
    let missing: Vec<String> = teams.iter().filter(|t| !known.contains(t)).map(|t| format!("team:{t}")).collect();
    if !missing.is_empty() {
        return Err(AppError::BadRequest(format!(
            "unregistered team(s) in audience: {missing:?} — create first with: noo security team create <name>"
        )));
    }
    Ok(())
}

async fn server_create(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    actor: Option<Extension<AuthActor>>,
    Json(body): Json<CreateBody>,
) -> AppResult {
    operator_guard(&ctx)?;
    if !valid_server_id(&body.id) {
        return Err(AppError::BadRequest(
            "id must match [a-z0-9][a-z0-9_-]{0,63} — it becomes the tool-name prefix mcp_<id>_<tool>".into(),
        ));
    }
    if !TRANSPORTS.contains(&body.transport.as_str()) {
        return Err(AppError::BadRequest(format!("transport must be one of {TRANSPORTS:?}")));
    }
    if !KINDS.contains(&body.kind.as_str()) {
        return Err(AppError::BadRequest(format!("kind must be one of {KINDS:?}")));
    }
    validate_spec(&body.transport, &body.spec).map_err(AppError::BadRequest)?;
    let teams = validate_audience_shape(&body.audience).map_err(AppError::BadRequest)?;
    check_teams(&state.db, &teams).await?;

    let owner = ctx.as_ref().map(|Extension(r)| r.sub.clone());
    let res = sqlx::query(
        "INSERT INTO noo_mcp_servers (id, transport, spec, kind, owner_uuid, audience, note, enabled) \
         VALUES ($1, $2, $3, $4, (SELECT user_uuid FROM noo_users WHERE username = $5), $6, $7, $8) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&body.id)
    .bind(&body.transport)
    .bind(&body.spec)
    .bind(&body.kind)
    .bind(owner.as_deref())
    .bind(Value::Array(body.audience.iter().map(|a| Value::String(a.clone())).collect()))
    .bind(&body.note)
    .bind(body.enabled)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::BadRequest(format!("server '{}' already exists — `noo mcp server show {}` or update it", body.id, body.id)));
    }
    crate::routes::core::audit_event(
        &state.db, "mcp_server_register", "info", &actor_label(&actor), &body.id, "ok",
        json!({ "transport": body.transport, "kind": body.kind, "audience": body.audience }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "id": body.id, "note": "registered; place it on a node with `noo mcp place <id> <node>` — tools are discovered when phase B lands" })))
}

async fn server_get(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(id): Path<String>,
) -> AppResult {
    operator_guard(&ctx)?;
    let Some(r) = sqlx::query(
        "SELECT s.id, s.transport, s.spec, s.kind, s.enabled, s.audience, s.note, s.created_at, s.updated_at, u.username AS owner \
         FROM noo_mcp_servers s LEFT JOIN noo_users u ON u.user_uuid = s.owner_uuid WHERE s.id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?
    else {
        return Err(AppError::NotFound(format!("no MCP server '{id}'")));
    };
    let placements: Vec<Value> = sqlx::query("SELECT node_id, desired_state, updated_at FROM noo_mcp_server_placements WHERE server_id = $1 ORDER BY node_id")
        .bind(&id)
        .fetch_all(&state.db)
        .await?
        .iter()
        .map(|p| json!({ "node_id": p.get::<String, _>("node_id"), "desired_state": p.get::<String, _>("desired_state"), "updated_at": p.get::<chrono::DateTime<chrono::Utc>, _>("updated_at") }))
        .collect();
    let tools: Vec<Value> = sqlx::query("SELECT name, description, discovered_at FROM noo_mcp_server_tools WHERE server_id = $1 ORDER BY name")
        .bind(&id)
        .fetch_all(&state.db)
        .await?
        .iter()
        .map(|t| json!({ "name": t.get::<String, _>("name"), "description": t.get::<String, _>("description"), "discovered_at": t.get::<chrono::DateTime<chrono::Utc>, _>("discovered_at") }))
        .collect();
    Ok(Json(json!({
        "id": r.get::<String, _>("id"),
        "transport": r.get::<String, _>("transport"),
        "spec": r.get::<Value, _>("spec"),
        "kind": r.get::<String, _>("kind"),
        "enabled": r.get::<bool, _>("enabled"),
        "audience": r.get::<Value, _>("audience"),
        "note": r.get::<Option<String>, _>("note"),
        "owner": r.get::<Option<String>, _>("owner"),
        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        "updated_at": r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
        "placements": placements,
        "tools": tools,
    })))
}

#[derive(Deserialize)]
struct UpdateBody {
    #[serde(default)]
    spec: Option<Value>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    audience: Option<Vec<String>>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn server_update(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    actor: Option<Extension<AuthActor>>,
    Path(id): Path<String>,
    Json(body): Json<UpdateBody>,
) -> AppResult {
    operator_guard(&ctx)?;
    let Some(transport): Option<String> = sqlx::query_scalar("SELECT transport FROM noo_mcp_servers WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?
    else {
        return Err(AppError::NotFound(format!("no MCP server '{id}'")));
    };
    if let Some(spec) = &body.spec {
        validate_spec(&transport, spec).map_err(AppError::BadRequest)?;
    }
    if let Some(k) = &body.kind {
        if !KINDS.contains(&k.as_str()) {
            return Err(AppError::BadRequest(format!("kind must be one of {KINDS:?}")));
        }
    }
    if let Some(a) = &body.audience {
        let teams = validate_audience_shape(a).map_err(AppError::BadRequest)?;
        check_teams(&state.db, &teams).await?;
    }
    let audience_json = body.audience.as_ref().map(|a| Value::Array(a.iter().map(|x| Value::String(x.clone())).collect()));
    sqlx::query(
        "UPDATE noo_mcp_servers SET \
            spec = COALESCE($2, spec), kind = COALESCE($3, kind), audience = COALESCE($4, audience), \
            note = COALESCE($5, note), enabled = COALESCE($6, enabled), updated_at = now() \
         WHERE id = $1",
    )
    .bind(&id)
    .bind(&body.spec)
    .bind(&body.kind)
    .bind(&audience_json)
    .bind(&body.note)
    .bind(body.enabled)
    .execute(&state.db)
    .await?;
    crate::routes::core::audit_event(
        &state.db, "mcp_server_update", "info", &actor_label(&actor), &id, "ok",
        json!({ "spec": body.spec.is_some(), "kind": body.kind, "audience": body.audience, "enabled": body.enabled }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "id": id })))
}

async fn server_delete(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    actor: Option<Extension<AuthActor>>,
    Path(id): Path<String>,
) -> AppResult {
    operator_guard(&ctx)?;
    let res = sqlx::query("DELETE FROM noo_mcp_servers WHERE id = $1").bind(&id).execute(&state.db).await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("no MCP server '{id}'")));
    }
    crate::routes::core::audit_event(&state.db, "mcp_server_remove", "info", &actor_label(&actor), &id, "ok", json!({})).await;
    Ok(Json(json!({ "status": "ok", "id": id, "removed": true })))
}

#[derive(Deserialize, Default)]
struct PlacementBody {
    #[serde(default)]
    desired_state: Option<String>,
}

async fn placement_put(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    actor: Option<Extension<AuthActor>>,
    Path((id, node)): Path<(String, String)>,
    body: Option<Json<PlacementBody>>,
) -> AppResult {
    operator_guard(&ctx)?;
    let desired = body.and_then(|Json(b)| b.desired_state).unwrap_or_else(|| "running".into());
    if !DESIRED_STATES.contains(&desired.as_str()) {
        return Err(AppError::BadRequest(format!("desired_state must be one of {DESIRED_STATES:?}")));
    }
    let existing: Option<(String, String)> =
        sqlx::query_as("SELECT id, transport FROM noo_mcp_servers WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await?;
    let Some((_, transport)) = existing else {
        return Err(AppError::NotFound(format!("no MCP server '{id}'")));
    };
    // A row that predates the wall can still be stdio. Placing it would
    // send the node a command to run, which it now refuses on arrival —
    // so refuse here, where the operator is standing, rather than letting
    // them discover it in a heartbeat refusal an hour later.
    if transport.eq_ignore_ascii_case("stdio") {
        return Err(AppError::BadRequest(format!("'{id}' is a stdio server — {STDIO_IS_NODE_LOCAL}")));
    }
    // The node must be in the gateway REGISTRY — never a name we have not
    // seen, or the placement waits forever for an agent that does not exist.
    let known = crate::repo::cluster::all_nodes(&state.db).await?;
    if !known.iter().any(|(nid, _, _)| nid.eq_ignore_ascii_case(&node)) {
        return Err(AppError::BadRequest(format!("'{node}' is not a registered node — `noo cluster status` lists the fleet")));
    }
    sqlx::query(
        "INSERT INTO noo_mcp_server_placements (server_id, node_id, desired_state) VALUES ($1, $2, $3) \
         ON CONFLICT (server_id, node_id) DO UPDATE SET desired_state = EXCLUDED.desired_state, updated_at = now()",
    )
    .bind(&id)
    .bind(&node)
    .bind(&desired)
    .execute(&state.db)
    .await?;
    crate::routes::core::audit_event(
        &state.db, "mcp_server_place", "info", &actor_label(&actor), &id, "ok",
        json!({ "node": node, "desired_state": desired }),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "id": id, "node": node, "desired_state": desired,
        "note": "recorded; the node-side supervisor that starts it arrives with phase B" })))
}

async fn placement_delete(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    actor: Option<Extension<AuthActor>>,
    Path((id, node)): Path<(String, String)>,
) -> AppResult {
    operator_guard(&ctx)?;
    let res = sqlx::query("DELETE FROM noo_mcp_server_placements WHERE server_id = $1 AND node_id = $2")
        .bind(&id)
        .bind(&node)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("'{id}' is not placed on '{node}'")));
    }
    crate::routes::core::audit_event(&state.db, "mcp_server_unplace", "info", &actor_label(&actor), &id, "ok", json!({ "node": node })).await;
    Ok(Json(json!({ "status": "ok", "id": id, "node": node, "removed": true })))
}


#[derive(Deserialize)]
struct ToolsReport {
    #[serde(default)]
    tools: Vec<ReportedTool>,
}
#[derive(Deserialize)]
struct ReportedTool {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    input_schema: Option<Value>,
}

/// POST /api/cluster/nodes/{node}/mcp/{id}/tools — a node's discovery
/// report. Node-rail route: the token must name the
/// node in the path, and the server must be PLACED on that node — a node
/// cannot describe a server it does not host. The catalog is replaced
/// whole; an empty list means the server answered with no tools, and is
/// recorded as such rather than left stale.
async fn node_tools_report(
    State(state): State<Arc<AppState>>,
    caller: Option<Extension<crate::auth::ClusterNode>>,
    Path((node, id)): Path<(String, String)>,
    Json(body): Json<ToolsReport>,
) -> AppResult {
    if let Some(Extension(crate::auth::ClusterNode(actor, _))) = &caller {
        if actor != &node {
            return Err(AppError::Forbidden(format!("node {actor} may not report for {node}")));
        }
    }
    let placed: Option<String> = sqlx::query_scalar(
        "SELECT server_id FROM noo_mcp_server_placements WHERE server_id = $1 AND node_id = $2",
    )
    .bind(&id)
    .bind(&node)
    .fetch_optional(&state.db)
    .await?;
    if placed.is_none() {
        return Err(AppError::BadRequest(format!("'{id}' is not placed on '{node}'")));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM noo_mcp_server_tools WHERE server_id = $1").bind(&id).execute(&mut *tx).await?;
    let mut n = 0usize;
    for t in &body.tools {
        if t.name.trim().is_empty() {
            continue;
        }
        sqlx::query(
            "INSERT INTO noo_mcp_server_tools (server_id, name, description, input_schema, discovered_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (server_id, name) DO UPDATE SET description = EXCLUDED.description, \
                 input_schema = EXCLUDED.input_schema, discovered_at = now()",
        )
        .bind(&id)
        .bind(&t.name)
        .bind(&t.description)
        .bind(t.input_schema.clone().unwrap_or_else(|| json!({"type": "object"})))
        .execute(&mut *tx)
        .await?;
        n += 1;
    }
    tx.commit().await?;
    tracing::info!(server = %id, node = %node, tools = n, "mcp_catalog_reported");
    Ok(Json(json!({ "status": "ok", "id": id, "node": node, "tools": n })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_tool_name_prefixes() {
        for ok in ["git", "lab-scope-2", "postgres_ro", "a"] {
            assert!(valid_server_id(ok), "{ok}");
        }
        for bad in ["", "Git", "-x", "a.b", "x y", &"z".repeat(65)] {
            assert!(!valid_server_id(bad), "{bad:?}");
        }
    }

    /// A stdio spec is a command the node would execute, so the controller
    /// does not get to write one. This used to accept
    /// `{"command": "uvx", "args": ["mcp-server-git"]}` and call it
    /// validated — which is the shape of the hole, not a fix for it: `uvx`
    /// runs whatever its arguments say.
    #[test]
    fn stdio_specs_are_refused_whatever_their_shape() {
        for spec in [
            json!({"command": "uvx", "args": ["mcp-server-git"]}),
            json!({"command": "/usr/local/bin/mcp-server-git"}),
            json!({}),
            json!([]),
        ] {
            let e = validate_spec("stdio", &spec).unwrap_err();
            assert!(e.contains("declared on the node"), "{e}");
            assert!(e.contains("/etc/noo/mcp-servers.json"), "the refusal must name the file: {e}");
        }
    }

    #[test]
    fn http_specs_are_shaped() {
        assert!(validate_spec("streamable_http", &json!({"url": "https://mcp.example/mcp"})).is_ok());
        assert!(validate_spec("streamable_http", &json!({"url": "ftp://x"})).unwrap_err().contains("url"));
        assert!(validate_spec("streamable_http", &json!({"url": "https://x", "command": "y"})).unwrap_err().contains("not a streamable_http key"));
        assert!(validate_spec("sse", &json!({})).unwrap_err().contains("transport"));
    }

    /// The rule the module exists to hold: a credential never lands in this
    /// table. A secret-looking key takes only a `$NAME` reference, and a
    /// value that IS a credential is refused under any key.
    #[test]
    fn secrets_are_references_not_literals() {
        // Exercised through the transport that still takes a spec from
        // here. (The stdio arm is refused before its env is looked at —
        // the node-local file is where a stdio server's env lives now, and
        // `noo mcp secrets`-style linting of THAT file is the operator's,
        // not the controller's.)
        assert!(validate_spec("streamable_http", &json!({"url": "https://x", "headers": {"Authorization": "$MCP_UPSTREAM_BEARER"}})).is_ok());
        let e = validate_spec("streamable_http", &json!({"url": "https://x", "headers": {"Authorization": "Bearer abc"}})).unwrap_err();
        assert!(e.contains("Authorization"), "{e}");
        let e = validate_spec("streamable_http", &json!({"url": "https://x", "headers": {"API_KEY": "literal"}})).unwrap_err();
        assert!(e.contains("API_KEY"), "{e}");
        // An innocent key hiding a key: refused by the value's shape.
        let e = validate_spec("streamable_http", &json!({"url": "https://x", "headers": {"CONFIG": "noo-sk-abcdef"}})).unwrap_err();
        assert!(e.contains("literal credential"), "{e}");
        // And the map validator itself still holds both rules directly.
        let e = validate_kv_map(&json!({"GITHUB_TOKEN": "ghp_abc"}), "env").unwrap_err();
        assert!(e.contains("GITHUB_TOKEN") && e.contains("$GITHUB_TOKEN"), "{e}");
        // The remedy names where the value really goes: the hosting node's
        // MCP secrets file, which is what the node-agent resolves against.
        assert!(e.contains("/etc/noo/mcp-secrets.env"), "{e}");
        assert!(validate_kv_map(&json!({"GITHUB_TOKEN": "$GITHUB_TOKEN", "HOME": "/srv"}), "env").is_ok());
        assert!(is_store_ref("$A_1") && !is_store_ref("$1A") && !is_store_ref("A") && !is_store_ref("$"));
    }

    #[test]
    fn audience_is_the_kb_vocabulary() {
        let aud: Vec<String> = vec!["company".into(), "team:lab".into(), "user:alice".into()];
        let teams = validate_audience_shape(&aud).unwrap();
        assert_eq!(teams, vec!["lab"]);
        assert!(validate_audience_shape(&["everyone".to_string()]).unwrap_err().contains("not company"));
        assert!(validate_audience_shape(&["team:Bad Name".to_string()]).is_err());
        assert!(validate_audience_shape(&["user:".to_string()]).is_err());
        assert!(validate_audience_shape(&[]).unwrap().is_empty(), "empty = operators only, valid");
    }
}
