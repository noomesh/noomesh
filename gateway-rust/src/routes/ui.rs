// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! UI routes — dashboard HTML pages, uploads, tools, proactive, browser.
//!
//! Native Rust: proactive status/rules/history/create/delete (YAML config + Redis),
//!              file uploads (multipart → disk), file retrieval,
//!              tools list/select (cached tool_schemas from config/tools.json),
//!              node tools (proxy to node-agent /tools endpoint),
//!              browser status (config check), browser sessions (Redis/empty),
//!              browser start/stop/action (HTTP proxy to node-agent container
//!              API + the noo-browser container, sessions in Redis). The old
//!              "browser action needs Python runtime" delegation claim was
//!              false — the Python handler only proxied HTTP; ported 2026-08-11.

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post, delete},
    extract::{Path, Query, State, Multipart},
    Extension,
    Json,
    response::IntoResponse,
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Sha256, Digest};

use crate::state::AppState;
use super::{AppError, AppJson, AppResult};
use crate::node_link::NodeLink;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Dashboard HTML pages ──
        .route("/", get(serve_index))
        .route("/dashboard", get(serve_index))  // redirect to modular shell
        // The unattended display. The gateway has no SPA
        // fallback — deliberately — so the second HTML entry the console
        // build emits needs its own route or it 404s. Public like `/`:
        // the bundle is not the secret (see auth::PUBLIC_PATHS_EXACT).
        .route("/kiosk", get(serve_kiosk))
        .route("/kiosk.html", get(serve_kiosk))
        .route("/favicon.ico", get(serve_favicon))
        .route("/ui/basic", get(serve_html("ui.html")))
        // Runbooks: loaded into state at boot since the port, but the route
        // serving them was lost with the Python gateway — every card in the
        // dashboard Docs tab dead-ended on 401 (task #14). Authenticated
        // API, rendered in-app by the UI (a target=_blank href can never
        // carry the bearer, so these are NOT public pages).
        .route("/api/docs/runbooks", get(runbooks_list))
        // The full spec, authenticated. Its public subset is a static file.
        .route("/api/docs/openapi", get(openapi_full))
        .route("/api/docs/runbooks/{name}", get(runbook_get))
        // `/bootstrap-node.sh` (the pre-token enrollment lane, #114) is
        // gone: removed 2026-09-27 with the script. Enrollment is the pull
        // rail — `noo cluster bootstrap-token create`, then `/bootstrap`.

        // ── Uploads: Native Rust (multipart → disk, ported from NATS 2026-03-31) ──
        .route("/upload", post(upload_file))
        .route("/upload/{file_id}", get(get_uploaded_file))

        // ── Tools: Native Rust (cached tool schemas from config/tools.json) ──
        .route("/tools/select", post(tools_select))
        .route("/tools/list", get(tools_list))
        // Raw registry (WP-TE, plan 4b): the COMPLETE tools.json —
        // core_tools WITH tags/speed/nats_subject + extended_tool_groups —
        // for `noo tools export`. /tools/list strips that metadata.
        .route("/api/tools/registry/raw", get(tools_registry_raw))
        // Node tools: Native Rust (proxy to node-agent /tools endpoint — ported 2026-03-31)
        .route("/api/tools/nodes/{node_id}", get(tools_node_tools))
        .route("/api/tools/browser/sessions/start", post(browser_start))
        .route("/api/tools/browser/sessions/{session_id}/stop", post(browser_stop))
        // ── Browser: Native Rust (config + Redis state, ported 2026-03-31) ──
        .route("/api/tools/browser/sessions", get(browser_sessions))
        .route("/api/tools/browser/action", post(browser_action))
        .route("/api/tools/browser/status", get(browser_status))

        // ── Proactive: Native Rust (YAML config + Redis state) ──
        .route("/api/proactive/status", get(proactive_status))
        .route("/api/proactive/rules", get(proactive_list_rules))
        .route("/api/proactive/history", get(proactive_history))
        .route("/api/proactive/rules", post(proactive_create_rule))
        .route("/api/proactive/rules/{rule_id}", delete(proactive_delete_rule))
}

/// Serve the dashboard index.
///
/// One source: the noo-mesh-ui-web artifact unpacked at UI_WWW_DIR, whose
/// asset URLs point at /assets/… (the ServeDir in routes/mod). The vendored
/// legacy console it used to fall back to no longer exists, so a missing
/// file here is a broken image rather than a reason to serve something
/// else — say so instead of degrading into a blank page.
async fn serve_index() -> impl IntoResponse {
    let path = format!("{}/index.html", crate::paths::UI_WWW_DIR);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => axum::response::Html(content).into_response(),
        Err(e) => {
            tracing::error!("dashboard index unreadable at {path}: {e}");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Dashboard assets are missing from this image (expected \
                 /var/www/index.html from noo-mesh-ui-web). Rebuild with GHCR \
                 access to that package.",
            )
                .into_response()
        }
    }
}

/// Serve the kiosk page — `dist/kiosk.html` from the same UI artifact as
/// the console. Missing = an artifact built before the kiosk entry
/// existed; say so rather than fall back to the console shell, which
/// would render an operator UI on a hallway screen.
async fn serve_kiosk() -> impl IntoResponse {
    let path = format!("{}/kiosk.html", crate::paths::UI_WWW_DIR);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => axum::response::Html(content).into_response(),
        Err(e) => {
            tracing::error!("kiosk page unreadable at {path}: {e}");
            (
                axum::http::StatusCode::NOT_FOUND,
                "The kiosk page is missing from this image (expected \
                 /var/www/kiosk.html from the mesh-ui-web artifact). The UI \
                 artifact predates the kiosk entry; rebuild against one that \
                 emits it.",
            )
                .into_response()
        }
    }
}

/// Serve inline SVG favicon (matches Python).
async fn serve_favicon() -> impl IntoResponse {
    let svg = concat!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\">",
        "<circle cx=\"16\" cy=\"16\" r=\"15\" fill=\"#0f172a\"/>",
        "<text x=\"16\" y=\"22\" text-anchor=\"middle\" font-size=\"18\" ",
        "font-family=\"sans-serif\" fill=\"#38bdf8\" font-weight=\"bold\">M</text>",
        "</svg>"
    );
    (
        StatusCode::OK,
        [
            ("content-type", "image/svg+xml"),
            ("cache-control", "public, max-age=86400"),
        ],
        svg,
    )
}

/// Serve the API documentation page (standalone, not a shell fragment).
///
/// Reads the docs.html view fragment and wraps it in a full HTML page
/// with the same theme as the dashboard.
/// GET /api/docs/runbooks — names + first-line titles of the runbooks
/// cached in state (docs/operating/runbooks/*.md, loaded at boot).
async fn runbooks_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let books: Vec<serde_json::Value> = state
        .runbooks
        .iter()
        .map(|(name, content)| {
            serde_json::json!({ "name": name, "title": runbook_title(name, content) })
        })
        .collect();
    axum::Json(serde_json::json!({ "runbooks": books }))
}

/// GET /api/docs/openapi — the FULL OpenAPI document.
///
/// Authenticated, and that is the change: it used to be
/// `/static/openapi.json` under a public `/static/` prefix, so the complete
/// route map — admin, security, posture, PKI, user management — was readable
/// with no credential by anything that could reach the gateway. Every one of
/// those routes authenticates, so this was disclosure rather than access, but
/// on a tailnet install it handed a full inventory of the surface to every
/// node and every member for nothing.
///
/// The public subset stays a static file at `/static/openapi.public.json`,
/// derived from the auth layer's own lists so the two cannot disagree.
///
/// Fetched, never linked — the same rule the runbooks above follow: a
/// `target=_blank` href cannot carry a bearer token.
async fn openapi_full() -> impl IntoResponse {
    let path = format!("{}/openapi.json", crate::paths::STATIC_DIR);
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path, "docs: cannot read the OpenAPI spec");
            (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": "the API spec is not present in this image",
                    "detail": "expected openapi.json in the gateway's static directory",
                })),
            )
                .into_response()
        }
    }
}

/// Display title for a runbook: the frontmatter `title:` field when the
/// file opens with a YAML block (every in-tree runbook does), else the
/// first non-empty line AFTER any frontmatter — the old "first non-empty
/// line" rule returned the literal `---` fence for all 11 runbooks.
fn runbook_title<'a>(name: &'a str, content: &'a str) -> &'a str {
    let mut lines = content.lines().peekable();
    if lines.peek().map(|l| l.trim()) == Some("---") {
        lines.next();
        let mut title = None;
        for line in lines.by_ref() {
            if line.trim() == "---" {
                break;
            }
            if let Some(v) = line.strip_prefix("title:") {
                title = Some(v.trim().trim_matches('"').trim());
            }
        }
        if let Some(t) = title.filter(|t| !t.is_empty()) {
            return t;
        }
    }
    lines
        .find(|l| !l.trim().is_empty())
        .unwrap_or(name)
        .trim_start_matches('#')
        .trim()
}

/// GET /api/docs/runbooks/{name} — one runbook's markdown.
async fn runbook_get(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    match state.runbooks.iter().find(|(n, _)| *n == name) {
        Some((n, content)) => axum::Json(serde_json::json!({
            "name": n,
            "markdown": content,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": format!("unknown runbook '{name}'"),
                "available": state.runbooks.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
            })),
        )
            .into_response(),
    }
}

/// Create a handler for a specific HTML file.
fn serve_html(filename: &'static str) -> impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = axum::response::Response> + Send>> + Clone {
    move || Box::pin(async move { serve_html_file(filename).await })
}

async fn serve_html_file(filename: &str) -> axum::response::Response {
    use crate::paths;
    let path = format!("{}/{filename}", paths::GATEWAY_HTML_DIR);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => axum::response::Html(content).into_response(),
        Err(_) => {
            // Fallback: try static directory
            let fallback = format!("{}/{filename}", paths::STATIC_DIR);
            match tokio::fs::read_to_string(&fallback).await {
                Ok(content) => axum::response::Html(content).into_response(),
                Err(_) => (StatusCode::NOT_FOUND, format!("Page not found: {filename}")).into_response(),
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// File uploads — native Rust (ported from Python NATS 2026-03-31)
// ═══════════════════════════════════════════════════════════════

/// Allowed file extensions for upload.
const ALLOWED_EXTENSIONS: &[&str] = &[
    ".txt", ".md", ".py", ".js", ".ts", ".java", ".cpp", ".c", ".h",
    ".json", ".yaml", ".yml", ".xml", ".html", ".css", ".sh", ".bash",
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg",
];

/// Maximum upload size: 10 MB.
const MAX_UPLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Where `POST /upload` keeps files, relative to the gateway's working directory.
pub(crate) const UPLOAD_DIR: &str = "uploads";

/// Remove the files uploaded under these content-hash ids (`{file_id}_{name}`)
/// from `dir`. Returns how many files went; one that cannot be removed is
/// logged and skipped (an erase does not fail over it). Ids are matched as a
/// literal prefix of a plain file name, never joined into a path.
pub(crate) async fn remove_upload_files(dir: &std::path::Path, file_ids: &[String]) -> u64 {
    if file_ids.is_empty() {
        return 0;
    }
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else { return 0 };
    let mut removed = 0u64;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !file_ids.iter().any(|id| name.starts_with(&format!("{id}_"))) {
            continue;
        }
        match tokio::fs::remove_file(entry.path()).await {
            Ok(()) => removed += 1,
            Err(e) => tracing::warn!(file = %name, error = %e, "erase_upload_file_remove_failed"),
        }
    }
    removed
}

/// POST /upload — Accept multipart file upload, save to disk.
///
/// Validates file type and size, generates a content-hash ID, saves to
/// the `uploads/` directory. Returns file metadata JSON.
async fn upload_file(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<crate::auth::RequesterCtx>>,
    mut multipart: Multipart,
) -> axum::response::Response {
    // Find the file field in multipart data
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name != "file" {
            continue;
        }

        let filename = field.file_name().unwrap_or("upload").to_string();
        let content_type = field.content_type().unwrap_or("application/octet-stream").to_string();

        // Validate extension
        let ext = filename.rfind('.')
            .map(|i| filename[i..].to_lowercase())
            .unwrap_or_default();
        if !ext.is_empty() && !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!(
                        "File type not allowed. Allowed: {}",
                        ALLOWED_EXTENSIONS.join(", ")
                    )
                })),
            ).into_response();
        }

        // Read file contents
        let contents = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Failed to read upload: {e}")})),
                ).into_response();
            }
        };

        // Validate size
        if contents.len() > MAX_UPLOAD_SIZE {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"error": "File too large. Maximum size: 10MB"})),
            ).into_response();
        }

        // Generate file ID from content hash (matching Python: sha256[:16])
        let mut hasher = Sha256::new();
        hasher.update(&contents);
        let hash = hasher.finalize();
        let file_id = hex::encode(&hash[..8]); // 16 hex chars = 8 bytes

        // Save to uploads directory
        let upload_dir = std::path::Path::new(UPLOAD_DIR);
        if let Err(e) = tokio::fs::create_dir_all(upload_dir).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to create upload directory: {e}")})),
            ).into_response();
        }

        // Sanitize filename: keep only the basename, replace path separators
        let safe_basename = std::path::Path::new(&filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("upload");
        let safe_filename = format!("{file_id}_{safe_basename}");
        let file_path = upload_dir.join(&safe_filename);

        if let Err(e) = tokio::fs::write(&file_path, &contents).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to save file: {e}")})),
            ).into_response();
        }

        // Record who sent it, so a right-to-be-forgotten erase can find the
        // file. A caller with no account behind it (an internal
        // service) records nothing: that file belongs to nobody to erase.
        if let Some(Extension(who)) = &ctx {
            if let Err(e) = sqlx::query(
                "INSERT INTO noo_uploads (file_id, owner, filename) VALUES ($1, $2, $3) \
                 ON CONFLICT (file_id, owner) DO NOTHING",
            )
            .bind(&file_id)
            .bind(&who.sub)
            .bind(safe_basename)
            .execute(&state.db)
            .await
            {
                tracing::warn!(file_id = %file_id, error = %e, "upload_owner_not_recorded");
            }
        }

        tracing::info!(
            file_id = %file_id,
            filename = %filename,
            size = contents.len(),
            "file_uploaded"
        );

        return (
            StatusCode::OK,
            Json(json!({
                "file_id": file_id,
                "filename": filename,
                "size": contents.len(),
                "type": content_type,
                "path": file_path.to_string_lossy(),
            })),
        ).into_response();
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "No file field in multipart upload"})),
    ).into_response()
}

/// GET /upload/{file_id} — Retrieve uploaded file metadata.
///
/// Finds the file by its content-hash ID prefix in the uploads directory.
async fn get_uploaded_file(
    Path(file_id): Path<String>,
) -> AppResult {
    let upload_dir = std::path::Path::new(UPLOAD_DIR);

    // Find file by ID prefix (format: {file_id}_{original_name})
    let mut entries = match tokio::fs::read_dir(upload_dir).await {
        Ok(entries) => entries,
        Err(_) => return Err(AppError::NotFound("Upload directory not found".into())),
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("{file_id}_")) {
            let meta = entry.metadata().await
                .map_err(|e| AppError::Internal(format!("Failed to read file metadata: {e}")))?;

            // Extract original filename (everything after {file_id}_)
            let original_name = name.split_once('_').map(|x| x.1).unwrap_or(&name);

            return Ok(Json(json!({
                "file_id": file_id,
                "filename": original_name,
                "size": meta.len(),
                "path": entry.path().to_string_lossy(),
            })));
        }
    }

    Err(AppError::NotFound("File not found".into()))
}

// ═══════════════════════════════════════════════════════════════
// Proactive agent handlers — native Rust
// ═══════════════════════════════════════════════════════════════
//
// The proactive agent's runtime state (running flag, cooldowns, in-memory
// history) lives in the Python process.  These native handlers provide a
// config-level view:
//   - Rules are read/written from the `proactive.rules` section of the
//     YAML config (noomesh.yaml), so they persist across restarts.
//   - Status reads the config + checks Redis for Python's proactive agent
//     heartbeat key (`noo:proactive:status`, SET EX 30 from
//     ProactiveAgent._schedule_loop — see gateway/proactive_agent.py).
//   - History queries the `noo_proactive_history` table. VERIFIED 2026-08-01:
//     nothing in this repo creates or writes that table — there is no Alembic
//     migration for it and no INSERT anywhere; the Python ProactiveAgent keeps
//     firings in an in-process list (`self._history`, proactive_agent.py:174)
//     that is lost on restart and invisible to this process. The old comment
//     claimed "the Python agent can write history rows there", and the handler
//     answered a clean empty list. Both were false: an empty list reads as
//     "the agent has fired nothing", when the truth is "this store does not
//     exist". These handlers now report the history as unknown (null) with an
//     explicit reason rather than a confident zero.

/// Is this sqlx error "the table does not exist" (Postgres 42P01)?
///
/// Mirrors the helper in knowledge.rs. Used here only to tell the two failure
/// modes apart in the reported detail string — for `noo_proactive_history`
/// BOTH are "unknown", because no writer exists that a missing table could
/// legitimately mean "empty" for.
fn missing_table(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01"))
}

/// Why the proactive history store could not be read, in operator language.
fn proactive_history_detail(e: &sqlx::Error) -> String {
    if missing_table(e) {
        "unknown — the noo_proactive_history table does not exist; no migration \
         creates it and nothing writes it. The Python ProactiveAgent keeps \
         firings in process memory only, so this gateway cannot see them."
            .to_string()
    } else {
        format!("unknown — cannot read noo_proactive_history: {e}")
    }
}

/// GET /api/proactive/status — proactive agent state.
///
/// Returns rule counts from config and checks Redis for the Python agent's
/// running state (key `noo:proactive:status`).
async fn proactive_status(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    let config = state.config_yaml.read().await;

    let rules = config
        .get("proactive")
        .and_then(|p| p.get("rules"))
        .and_then(|r| r.as_array());

    let rules_total = rules.map(|r| r.len()).unwrap_or(0);
    let rules_enabled = rules
        .map(|r| {
            r.iter()
                .filter(|rule| {
                    rule.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true)
                })
                .count()
        })
        .unwrap_or(0);

    // Check Redis for the Python agent's heartbeat.
    //
    // The old code collapsed "no Redis configured", "Redis unreachable" and
    // "no heartbeat key" all into `running: false` — asserting the agent is
    // stopped on missing evidence. The sibling autonomy status endpoint
    // (intelligence.rs) defaults the SAME class of fact to `true` on missing
    // evidence; the two lie in opposite directions. Both are now nullable
    // with an explicit reason, so "we don't know" is representable.
    //
    // Note `Cache::get_string` returns Option<String> and cannot distinguish
    // an absent key from a Redis error, so the detail names both.
    let (running, running_detail): (Option<bool>, String) = match state.redis.as_ref() {
        None => (
            None,
            "unknown — Redis is not configured, and the proactive agent's \
             heartbeat (noo:proactive:status) is the only evidence this \
             process has"
                .to_string(),
        ),
        Some(redis) => match redis.get_string("noo:proactive:status").await {
            Some(v) if v == "running" => (
                Some(true),
                "noo:proactive:status == \"running\" (SET EX 30 by the Python \
                 ProactiveAgent)"
                    .to_string(),
            ),
            Some(v) => (
                Some(false),
                format!("noo:proactive:status == {v:?}, which is not \"running\""),
            ),
            None => (
                None,
                "unknown — no noo:proactive:status heartbeat: the key is absent \
                 (agent stopped, or never started, or its 30s TTL lapsed) or \
                 Redis is unreachable. These are indistinguishable here."
                    .to_string(),
            ),
        },
    };

    // history_entries was a literal 0 while the sibling /api/proactive/history
    // route actually queries noo_proactive_history. Count it for real; the
    // count is null (never 0) when the store cannot be read — see
    // proactive_history_detail for why a missing table is NOT a truthful zero.
    let (history_entries, history_detail) =
        match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM noo_proactive_history")
            .fetch_one(&state.db)
            .await
        {
            Ok(n) => (Some(n), None),
            Err(e) => (None, Some(proactive_history_detail(&e))),
        };

    Ok(Json(json!({
        "running": running,
        "running_detail": running_detail,
        "rules_total": rules_total,
        "rules_enabled": rules_enabled,
        "history_entries": history_entries,
        "history_detail": history_detail,
    })))
}

/// GET /api/proactive/rules — list proactive rules from YAML config.
///
/// Each rule has id, name, trigger_type, trigger_pattern, action_type,
/// channel_targets, cooldown_seconds, enabled, use_reasoning, template.
async fn proactive_list_rules(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    let config = state.config_yaml.read().await;

    let rules = config
        .get("proactive")
        .and_then(|p| p.get("rules"))
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    // Return rules with truncated templates (matching Python behavior)
    let summaries: Vec<Value> = rules
        .iter()
        .map(|r| {
            let template = r
                .get("template")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let truncated = if template.chars().count() > 120 {
                let s: String = template.chars().take(120).collect();
                format!("{s}...")
            } else {
                template.to_string()
            };

            json!({
                "id": r.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                "name": r.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                "trigger_type": r.get("trigger_type").and_then(|v| v.as_str()).unwrap_or("event"),
                "trigger_pattern": r.get("trigger_pattern").and_then(|v| v.as_str()).unwrap_or(""),
                "action_type": r.get("action_type").and_then(|v| v.as_str()).unwrap_or("channel_message"),
                "channel_targets": r.get("channel_targets").cloned().unwrap_or(json!(["*"])),
                "cooldown_seconds": r.get("cooldown_seconds").and_then(|v| v.as_i64()).unwrap_or(300),
                "enabled": r.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
                "use_reasoning": r.get("use_reasoning").and_then(|v| v.as_bool()).unwrap_or(false),
                "template": truncated,
            })
        })
        .collect();

    Ok(Json(json!({ "rules": summaries })))
}

#[derive(Deserialize)]
struct HistoryParams {
    limit: Option<i64>,
}

/// GET /api/proactive/history — query proactive action history.
///
/// Queries the `noo_proactive_history` table. If the store cannot be read the
/// response carries `entries: null` + `count: null` + an `error`/`detail`
/// pair, NOT an empty list — see the module comment above: nothing in this
/// repo creates or writes that table, so `[]` would claim "the proactive
/// agent has fired nothing" when the real answer is "there is no store".
async fn proactive_history(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryParams>,
) -> AppResult {
    let limit = params.limit.unwrap_or(50).min(500);

    // The old comment here said "the table is created by Python on first
    // write". It is not — grep confirms no migration and no INSERT exists.
    let entries = sqlx::query_as::<_, (
        f64,                    // timestamp
        String,                 // rule_id
        String,                 // rule_name
        String,                 // trigger_event
        String,                 // message
        Value,                  // channels_sent
        bool,                   // success
    )>(
        "SELECT \
            EXTRACT(EPOCH FROM created_at)::float8, \
            rule_id, rule_name, trigger_event, \
            LEFT(message, 200), \
            COALESCE(channels_sent, '[]'::jsonb), \
            success \
         FROM noo_proactive_history \
         ORDER BY created_at DESC \
         LIMIT $1"
    )
    .bind(limit)
    .fetch_all(&state.db)
    .await;

    match entries {
        Ok(rows) => {
            let entries: Vec<Value> = rows
                .iter()
                .map(|(ts, rule_id, rule_name, trigger, msg, channels, success)| {
                    json!({
                        "timestamp": ts,
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "trigger_event": trigger,
                        "message": msg,
                        "channels_sent": channels,
                        "success": success,
                    })
                })
                .collect();
            let count = entries.len();
            Ok(Json(json!({ "entries": entries, "count": count })))
        }
        Err(e) => {
            // Old behaviour: log at debug and return Vec::new(), so callers
            // saw a clean `{"entries": []}` — indistinguishable from "the
            // agent has never fired a rule". Report the store as unknown.
            tracing::warn!(error = %e, "proactive_history store unavailable");
            Ok(Json(json!({
                "entries": Value::Null,
                "count": Value::Null,
                "error": "proactive history store unavailable",
                "detail": proactive_history_detail(&e),
            })))
        }
    }
}

/// POST /api/proactive/rules — add a new rule to the YAML config.
///
/// Accepts a rule definition in the request body, generates an ID if not
/// provided, appends to the `proactive.rules` config array, and persists.
async fn proactive_create_rule(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppResult {
    let rule_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()[..12].to_string());

    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return Err(AppError::BadRequest("Missing required field: name".into()));
    }

    // `broadcast` was the default here, which stored a rule that could never
    // deliver: no adapter resolves that word, so it reached Google Chat as a
    // URL path segment and 404'd. A rule with nowhere to send is a bad
    // request, the same as one with no name.
    let recipient = body
        .get("recipient")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .ok_or_else(|| {
            AppError::BadRequest(
                "Missing required field: recipient (a channel address, e.g. a \
                 Google Chat space resource name `spaces/<id>`)"
                    .into(),
            )
        })?;

    let new_rule = json!({
        "id": rule_id,
        "name": name,
        "trigger_type": body.get("trigger_type").and_then(|v| v.as_str()).unwrap_or("event"),
        "trigger_pattern": body.get("trigger_pattern").and_then(|v| v.as_str()).unwrap_or(""),
        "channel_targets": body.get("channel_targets").cloned().unwrap_or(json!(["*"])),
        "recipient": recipient,
        "action_type": body.get("action_type").and_then(|v| v.as_str()).unwrap_or("channel_message"),
        "template": body.get("template").and_then(|v| v.as_str()).unwrap_or(""),
        "use_reasoning": body.get("use_reasoning").and_then(|v| v.as_bool()).unwrap_or(false),
        "cooldown_seconds": body.get("cooldown_seconds").and_then(|v| v.as_i64()).unwrap_or(300),
        "enabled": body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
        "schedule_seconds": body.get("schedule_seconds").and_then(|v| v.as_i64()).unwrap_or(0),
        "condition_endpoint": body.get("condition_endpoint").and_then(|v| v.as_str()).unwrap_or(""),
        "condition_metric": body.get("condition_metric").and_then(|v| v.as_str()).unwrap_or(""),
        "condition_operator": body.get("condition_operator").and_then(|v| v.as_str()).unwrap_or("gt"),
        "condition_threshold": body.get("condition_threshold").cloned().unwrap_or(json!(0)),
    });

    // Upsert the rule into the FRESH on-disk document under the config lock
    // (mutating the startup cache silently reverted out-of-band YAML edits).
    let rid = rule_id.clone();
    super::settings::mutate_config(&state, move |doc| {
        let internal = |msg: &str| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": msg})),
            )
        };
        // Ensure proactive.rules array exists
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| internal("Config root is not an object"))?;
        let proactive = obj.entry("proactive").or_insert_with(|| json!({}));
        let proactive_obj = proactive
            .as_object_mut()
            .ok_or_else(|| internal("proactive section is not an object"))?;
        let rules = proactive_obj.entry("rules").or_insert_with(|| json!([]));
        let rules_arr = rules
            .as_array_mut()
            .ok_or_else(|| internal("proactive.rules is not an array"))?;

        // Remove existing rule with same ID (upsert behavior, matching Python)
        rules_arr.retain(|r| {
            r.get("id").and_then(|v| v.as_str()) != Some(rid.as_str())
        });
        rules_arr.push(new_rule);
        Ok(())
    })
    .await
    .map_err(|(_, body)| {
        AppError::Internal(
            body.0.get("error").and_then(|e| e.as_str()).unwrap_or("write failed").to_string()
        )
    })?;

    Ok(Json(json!({ "status": "ok", "rule_id": rule_id })))
}

/// DELETE /api/proactive/rules/{rule_id} — remove a rule from YAML config.
///
/// Removes the rule with the given ID from the `proactive.rules` array
/// and persists the change.
async fn proactive_delete_rule(
    State(state): State<Arc<AppState>>,
    Path(rule_id): Path<String>,
) -> AppResult {
    // Remove from the FRESH on-disk document under the config lock.
    let rid = rule_id.clone();
    super::settings::mutate_config(&state, move |doc| {
        let removed = doc
            .get_mut("proactive")
            .and_then(|p| p.get_mut("rules"))
            .and_then(|r| r.as_array_mut())
            .map(|rules| {
                let before = rules.len();
                rules.retain(|r| {
                    r.get("id").and_then(|v| v.as_str()) != Some(rid.as_str())
                });
                rules.len() < before
            })
            .unwrap_or(false);
        if !removed {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(json!({"error": format!("Rule '{}' not found", rid)})),
            ));
        }
        Ok(())
    })
    .await
    .map_err(|(status, body)| {
        let msg = body.0.get("error").and_then(|e| e.as_str()).unwrap_or("write failed").to_string();
        if status == axum::http::StatusCode::NOT_FOUND {
            AppError::NotFound(msg)
        } else {
            AppError::Internal(msg)
        }
    })?;

    Ok(Json(json!({ "status": "deleted", "rule_id": rule_id })))
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Tools select/list (cached tool schemas)
// ═══════════════════════════════════════════════════════════════

/// POST /tools/select — filter tool schemas by query string.
///
/// Reads from state.tool_schemas (cached from config/tools.json at startup).
/// Matches tools whose name or description contains the query string.
/// Returns {tools: [...]} matching the Python select_tools() response.
async fn tools_select(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppJson {
    let query = body.get("query")
        .or_else(|| body.get("prompt"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();

    let max_tools = body.get("max_tools")
        .and_then(|v| v.as_u64())
        .unwrap_or(8) as usize;

    let schemas = state.tool_schemas.read().await;

    if query.is_empty() {
        // No query — return up to max_tools
        let tools: Vec<Value> = schemas.iter()
            .take(max_tools)
            .cloned()
            .collect();
        return Json(json!({"tools": tools}));
    }

    // Filter by name and description matching
    let mut matched: Vec<Value> = schemas.iter()
        .filter(|tool| {
            let func = tool.get("function").unwrap_or(tool);
            let name = func.get("name").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            let desc = func.get("description").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            name.contains(&query) || desc.contains(&query)
        })
        .take(max_tools)
        .cloned()
        .collect();

    // If no matches on exact substring, try word-level matching
    if matched.is_empty() {
        let words: Vec<&str> = query.split_whitespace().collect();
        matched = schemas.iter()
            .filter(|tool| {
                let func = tool.get("function").unwrap_or(tool);
                let name = func.get("name").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                let desc = func.get("description").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
                words.iter().any(|w| name.contains(w) || desc.contains(w))
            })
            .take(max_tools)
            .cloned()
            .collect();
    }

    Json(json!({"tools": matched}))
}

/// GET /tools/list — return all available tool schemas.
///
/// Reads from state.tool_schemas (cached from config/tools.json at startup).
/// Returns {tools: [...], stats: {total}} matching the Python list_tools() response.
async fn tools_list(
    State(state): State<Arc<AppState>>,
) -> AppJson {
    let schemas = state.tool_schemas.read().await;

    let tools: Vec<Value> = schemas.iter().map(|tool| {
        let func = tool.get("function").cloned().unwrap_or(json!({}));
        // `is_base_tool` was a hardcoded `true` for every entry, and
        // `available_on_nodes` a literal `[]`. Both were assertions this
        // handler cannot make: state.tool_schemas is the flattened LLM-facing
        // schema list, which carries no core/extended distinction and no node
        // placement at all. `[]` in particular reads as "no node can run this
        // tool" — the opposite of the truth for every tool in the list.
        // Emit the flag only when the source data actually says so, and null
        // (unknown) otherwise. /api/tools/registry/raw is the route that
        // preserves the registry's own tags/routing metadata.
        let is_base_tool = tool
            .get("is_base_tool")
            .or_else(|| func.get("is_base_tool"))
            .and_then(|v| v.as_bool());
        json!({
            "name": func.get("name").cloned().unwrap_or(json!("")),
            "description": func.get("description").cloned().unwrap_or(json!("")),
            "parameters": func.get("parameters").cloned().unwrap_or(json!({})),
            "is_base_tool": is_base_tool,
            "available_on_nodes": Value::Null,
        })
    }).collect();

    let total = tools.len();

    Json(json!({
        "tools": tools,
        "stats": {
            "total": total,
        },
        "available_on_nodes_detail": "null — per-node tool placement is not \
            tracked by the gateway; this list is the loaded schema registry, \
            not a placement map. Previously emitted as [], which read as \
            'no node can run this tool'.",
        "is_base_tool_detail": "null unless the registry entry carries the \
            flag itself; previously hardcoded true for every tool.",
    }))
}

/// GET /api/tools/registry/raw — the COMPLETE tool registry as loaded from
/// config/tools.json (WP-TE, plan 4b).
///
/// Unlike /tools/list (which strips everything but the LLM-facing schema),
/// this returns the raw registry verbatim: `_version`, `_description`,
/// `core_tools` entries WITH `tags`/`speed`/`nats_subject` routing metadata,
/// and `extended_tool_groups`. `noo tools export` regenerates
/// config/tools.json from this response — serving a stripped shape here
/// would corrupt the artifact and break NATS tool routing cluster-wide
/// (the WP-A5 finding). Auth: the global require_any_auth middleware,
/// same as the sibling /tools/* read routes.
async fn tools_registry_raw(
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, AppError> {
    let raw = state.tools_json_raw.read().await;
    let body = registry_raw_body(&raw)?;
    // Source fingerprint (WP-Z staleness guard): sha256 of the served
    // document's canonical serde_json serialization. Lets callers (`noo
    // tools export`, CI) tell that a RUNNING gateway serves a registry
    // captured at ITS startup — possibly older than the repo's
    // config/tools.json — without diffing the whole body.
    let fingerprint = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(serde_json::to_vec(&body).unwrap_or_default()))
    );
    let mut resp = Json(body).into_response();
    if let Ok(v) = fingerprint.parse() {
        resp.headers_mut().insert("x-registry-fingerprint", v);
    }
    Ok(resp)
}

/// Pure body builder for /api/tools/registry/raw: pass the loaded registry
/// through VERBATIM, refusing to serve one without `core_tools` entries.
/// The startup fallback caches `{}` when config/tools.json is missing —
/// letting that through would give `noo tools export` an empty registry
/// to write over the real artifact.
fn registry_raw_body(raw: &Value) -> Result<Value, AppError> {
    let has_tools = raw
        .get("core_tools")
        .and_then(|t| t.as_array())
        .is_some_and(|a| !a.is_empty());
    if !has_tools {
        return Err(AppError::NotFound(
            "tool registry not loaded (config/tools.json was missing at startup) — \
             refusing to serve an empty registry"
                .to_string(),
        ));
    }
    Ok(raw.clone())
}

// ═══════════════════════════════════════════════════════════════
// Node tools — native Rust (proxy to node-agent /tools endpoint)
//
// Replaces the Python ClusterToolRegistry.list_tools_for_node()
// by proxying directly to the node agent's /tools endpoint.
// ═══════════════════════════════════════════════════════════════

/// GET /api/tools/nodes/{node_id} — list tools available on a specific node.
///
/// Resolves the node's agent URL from NATS KV mesh_nodes, then sends an
/// HTTP GET to the node agent's `/tools` endpoint. Falls back to returning
/// the base tool set from config/tools.json if the node agent is unreachable.
async fn tools_node_tools(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> AppResult {
    // Resolve node agent URL
    let link = match NodeLink::for_node(&state, &node_id).await {
        Ok(l) => l,
        Err(_) => return Err(AppError::NotFound(format!("Node '{}' not found", node_id))),
    };

    // Proxy to node agent /tools endpoint
    let req = link
        .request(reqwest::Method::GET, "/tools")
        .timeout(std::time::Duration::from_secs(10));

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let data = resp.json::<Value>().await.unwrap_or(json!({}));

            // The node agent typically returns {"tools": [...]} — extract and reformat
            let tools = data.get("tools")
                .and_then(|t| t.as_array())
                .cloned()
                .unwrap_or_default();

            let formatted_tools: Vec<Value> = tools.iter().map(|tool| {
                json!({
                    "name": tool.get("name").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    "description": tool.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                    "parameters": tool.get("parameters").cloned().unwrap_or(json!({})),
                })
            }).collect();

            Ok(Json(json!({
                "node_id": node_id,
                "tools": formatted_tools,
            })))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            tracing::warn!(node_id = %node_id, status, "node_agent_tools_error");
            // Return empty tools list on error (graceful degradation)
            Ok(Json(json!({
                "node_id": node_id,
                "tools": [],
                "error": format!("Node agent returned {status}"),
            })))
        }
        Err(e) => {
            tracing::warn!(node_id = %node_id, error = %e, "node_agent_tools_unreachable");
            Ok(Json(json!({
                "node_id": node_id,
                "tools": [],
                "error": format!("Node agent unreachable: {e}"),
            })))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Browser — Native Rust handlers (ported from NATS delegation 2026-03-31)
// ═══════════════════════════════════════════════════════════════
//
// browser_status: checks config for Playwright availability and reads
//   active session count from Redis (noo:browser:sessions key).
//   Python called get_browser_tool().get_status() which checked if
//   Playwright was initialized; Rust checks config + Redis instead.
//
// browser_sessions: reads active browser session list from Redis.
//   The old comment here claimed "the Python tool persists sessions to Redis
//   for cross-process visibility". VERIFIED 2026-08-01: it does not —
//   src/noomesh/tools/browser_tool.py contains no Redis reference at all
//   and keeps sessions in an in-memory dict. The ONLY writer of
//   noo:browser:session_count / noo:browser:session:* is the Rust
//   /api/tools/browser/sessions/start route below. So these counts cover
//   gateway-started sessions only; agent-started browsers are invisible here.

/// Bearer for calls INTO a `noo-browser` container.
///
/// The browser service requires an HMAC bearer under its OWN key on every
/// route and accepts nothing else — in particular NOT
/// `NOO_NODE_AGENT_TOKEN`, which is why this is separate from
/// `node_agent_auth::header_for`. Signed with `NOO_BROWSER_KEY`, never the fleet secret: the browser container used to hold every
/// node's credential, so a leak of its copy was a leak of the fleet's.
fn browser_auth_header() -> Option<(String, String)> {
    browser_auth_header_with(&crate::config::secret_env::secret_opt(BROWSER_KEY)?)
}

/// The browser door's key in the store.
pub(crate) const BROWSER_KEY: &str = "NOO_BROWSER_KEY";

/// [`browser_auth_header`] over its key, for the tests.
fn browser_auth_header_with(secret: &str) -> Option<(String, String)> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token = crate::routes::cluster::mint_cluster_token("gateway", secret, ts)?;
    Some(("Authorization".into(), format!("Bearer {token}")))
}

/// Header the node agent moves into `Authorization` on the way into the
/// container (its own `Authorization` is spent on the agent's auth).
const UPSTREAM_AUTH_HEADER: &str = "X-Noo-Upstream-Authorization";

/// Where a session container is reached: THROUGH its node agent, which
/// proxies to the container's loopback-published port
/// (`node-agent-go/internal/api/containers.go`). The container's port is
/// bound on 127.0.0.1 only, so there is no `http://<node>:<port>` to dial.
fn browser_proxy_path(container_name: &str) -> String {
    format!("/api/containers/{container_name}/proxy")
}

/// Add the second credential a proxied browser call carries: the browser
/// door's bearer (upstream header). The agent's own credential is already on
/// the request, applied by the `NodeLink` it was built from.
fn browser_proxied(mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some((_, bearer)) = browser_auth_header() {
        req = req.header(UPSTREAM_AUTH_HEADER, bearer);
    }
    req
}

/// The configured agent for a browser session with no node (`node_id`
/// empty, or `"local"` on a stored session): `NOO_DEFAULT_AGENT_URL`, or a
/// refusal that says what to do. Pure, so the refusal is testable.
///
/// There is no `https://localhost:8081` fallback any more.
/// The gateway runs in its own container, so that address was the gateway
/// itself, where no agent listens: every start without a node failed with
/// "connection refused". It was also an address with no node record, so
/// `node_agent_auth::header_for` sent it the static token.
fn default_browser_agent(configured: Option<String>) -> Result<String, AppError> {
    match configured.map(|u| u.trim().trim_end_matches('/').to_string()) {
        Some(u) if !u.is_empty() => Ok(u),
        _ => Err(AppError::BadRequest(format!(
            "a browser session needs a node: pass node_id (a node from `noo cluster status`), \
             or set NOO_DEFAULT_AGENT_URL to the agent that runs browsers. The gateway has no \
             agent of its own at localhost:{}.",
            crate::node_link::AGENT_PORT
        ))),
    }
}

/// The node agent a browser session's container runs on, and the
/// credential that agent gets.
///
/// - A named node: its record's address, and `header_for` that address,
///   which sends NO bearer once the node reported `controller_leaf_only`
///   (the connection already carries the controller's leaf). A node that is
///   not in `mesh_nodes` is a 404, never a fallback address.
/// - No node: `NOO_DEFAULT_AGENT_URL`, the operator's declared local agent.
///   It need not match any record's address, so it follows the
///   controller's own node, as `admin.rs` `local_agent_url()` does
///   (`header_for_self`).
async fn browser_agent(
    state: &AppState,
    node_id: &str,
) -> Result<NodeLink, AppError> {
    if !node_id.is_empty() && node_id != "local" {
        return NodeLink::for_node(state, node_id).await;
    }
    let url = default_browser_agent(std::env::var("NOO_DEFAULT_AGENT_URL").ok())?;
    Ok(NodeLink::self_agent_at(url))
}

/// GET /api/tools/browser/status — browser automation status.
///
/// Checks if browser automation is configured (Playwright available)
/// and reports active session count from Redis.
async fn browser_status(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    let config = state.config_yaml.read().await;

    // Check if browser tool is enabled in config
    let browser_enabled = config
        .get("tools")
        .and_then(|t| t.get("browser"))
        .and_then(|b| b.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Read active session count from Redis. Key name and value kept — but see
    // the module comment: this counter's only writer is the Rust
    // /sessions/start route, so it is a partial count, not "all live
    // browsers". Callers were free to read it as the latter.
    let (active_sessions, sessions_source) = if let Some(redis) = state.redis.as_ref() {
        match redis.get_string("noo:browser:session_count").await {
            Some(s) => match s.parse::<u32>() {
                Ok(n) => (Some(n), "redis"),
                Err(_) => (None, "unparseable"),
            },
            // Absent key and Redis error are indistinguishable through
            // get_string; absent is the overwhelmingly common case for a
            // counter only ever INCR'd by this gateway, so 0 is reported —
            // but the detail below states the scope either way.
            None => (Some(0), "redis-absent"),
        }
    } else {
        (None, "no-redis")
    };
    let active_sessions_detail = match sessions_source {
        "redis" | "redis-absent" => "counts ONLY sessions started through this \
            gateway's POST /api/tools/browser/sessions/start (the sole writer \
            of noo:browser:session_count). Browsers started by the Python \
            BrowserTool live in that process's memory and are not counted.",
        "unparseable" => "unknown — noo:browser:session_count holds a \
            non-numeric value",
        _ => "unknown — Redis is not configured, and the session counter is \
            the only record this process keeps",
    };

    // Check if Playwright binary exists (common install paths).
    //
    // This probes the GATEWAY CONTAINER's filesystem. Browsers actually run in
    // per-session containers on node-agents (see browser_start below, which
    // POSTs noo-browser:latest to a node), so a fully working deployment
    // reports playwright_installed=false and status="configured_not_installed"
    // — the field asserted a fleet-wide fact from a local-only measurement.
    // The measurement is kept (it is real for THIS process) but is now labelled
    // for what it is; no remote probe is invented.
    let playwright_in_gateway_container = [
        "/usr/bin/playwright",
        "/usr/local/bin/playwright",
        "/app/node_modules/.bin/playwright",
    ].iter().any(|p| std::path::Path::new(p).exists());

    // status likewise only ever described this container.
    let status = if browser_enabled && playwright_in_gateway_container {
        "ready"
    } else if browser_enabled {
        "configured_not_installed"
    } else {
        "not_configured"
    };

    Ok(Json(json!({
        "status": status,
        "status_detail": "scoped to this gateway container only; \
            \"configured_not_installed\" is expected and harmless in the normal \
            deployment, where browsers run in noo-browser containers on \
            node-agents rather than in the gateway.",
        "browser_enabled": browser_enabled,
        "playwright_installed": playwright_in_gateway_container,
        "playwright_detail": "true/false for the GATEWAY CONTAINER's own \
            filesystem (/usr/bin, /usr/local/bin, /app/node_modules/.bin). It \
            says nothing about the node-agent containers that actually run \
            browsers; remote availability is not probed.",
        "active_sessions": active_sessions,
        "active_sessions_detail": active_sessions_detail,
        "engine": "rust",
    })))
}

/// POST /api/tools/browser/sessions/start — start a new browser container.
///
/// Proxies to a node-agent's /api/containers/start endpoint to spin up a
/// Playwright browser container. Stores the session in Redis for cross-process
/// visibility and updates the session count.
///
/// The Python BrowserTool.start_session() does the same: POSTs to node-agent,
/// waits for health, stores session in memory. The Rust version stores in Redis
/// instead so both engines can see active sessions.
async fn browser_start(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppResult {
    // Generate session ID (matches Python: uuid4().hex[:8])
    let session_id = uuid::Uuid::new_v4().to_string().replace('-', "")[..8].to_string();
    let container_name = format!("noo-browser-{session_id}");

    // Resolve the node agent, and the credential it gets.
    let node_id = body.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
    let link = browser_agent(&state, node_id).await?;
    let agent_url = link.base().to_string();

    const BROWSER_IMAGE: &str = "noo-browser:latest";
    const BROWSER_PORT: u16 = 9222;

    // The browser container refuses every route without the cluster
    // bearer. Nothing can reach it before the secret
    // is in its environment, so fail here with the reason rather than
    // start a container that will 503 for 30s and then be called
    // "unhealthy".
    let browser_key = crate::config::secret_env::secret_or_empty(BROWSER_KEY);
    if browser_key.is_empty() {
        return Err(AppError::Internal(
            "NOO_BROWSER_KEY is not set — the browser service refuses to run \
             unauthenticated, so there is nothing to start"
                .into(),
        ));
    }

    // Build container start payload (matches Python BrowserTool.start_session)
    let mut env = json!({
        "BROWSER_PORT": BROWSER_PORT.to_string(),
        "BROWSER_IDLE_TIMEOUT": "300",
        "BROWSER_MAX_SESSION": "600",
        // The browser door's OWN key, never the fleet
        // secret. It is also set under the old name for ONE release: a node
        // still running a pre-702 `noo-browser` image reads
        // NOO_CLUSTER_SECRET, and must get the browser key there rather than
        // the fleet's. `browser_start_env_carries_no_fleet_secret` pins the
        // value; drop the old name once every node runs the new image.
        "NOO_BROWSER_KEY": browser_key.clone(),
        "NOO_CLUSTER_SECRET": browser_key,
    });
    if let Some(allowlist) = body.get("url_allowlist").and_then(|v| v.as_array()) {
        let list: Vec<&str> = allowlist.iter().filter_map(|v| v.as_str()).collect();
        env["BROWSER_URL_ALLOWLIST"] = json!(list.join(","));
    }
    if let Some(blocklist) = body.get("url_blocklist").and_then(|v| v.as_array()) {
        let list: Vec<&str> = blocklist.iter().filter_map(|v| v.as_str()).collect();
        env["BROWSER_URL_BLOCKLIST"] = json!(list.join(","));
    }

    let payload = json!({
        "image": BROWSER_IMAGE,
        "command": ["python", "/browser/server.py"],
        "container_name": container_name,
        "env": env,
        "memory_limit": "1g",
        "network_mode": "bridge",
        "gpu": false,
        "timeout": 0,
        "ports": { BROWSER_PORT.to_string(): null },
    });

    tracing::info!(
        session_id = %session_id,
        container = %container_name,
        agent_url = %agent_url,
        "browser_container_starting"
    );

    // POST to node-agent to start the container
    let req = link
        .request(reqwest::Method::POST, "/api/containers/start")
        .json(&payload)
        .timeout(std::time::Duration::from_secs(60));

    let resp = req.send().await
        .map_err(|e| AppError::Internal(format!("Failed to start browser container: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body_text = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(
            format!("Node agent returned {status}: {body_text}")
        ));
    }

    // The container is published on the node's loopback only; the gateway
    // reaches it through the node agent it already trusts.
    let proxy_path = browser_proxy_path(&container_name);
    let base_url = link.url(&proxy_path);

    // Wait for the container to become healthy (poll /status)

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut healthy = false;
    while std::time::Instant::now() < deadline {
        let probe = browser_proxied(
            link.request(reqwest::Method::GET, &format!("{proxy_path}/status"))
                .timeout(std::time::Duration::from_secs(5)),
        );
        if probe
            .send().await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            healthy = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    if !healthy {
        tracing::warn!(
            session_id = %session_id,
            "browser container did not become healthy within 30s"
        );
    }

    let now = chrono::Utc::now().timestamp() as f64;
    let session_data = json!({
        "session_id": session_id,
        "container_name": container_name,
        "node_id": if node_id.is_empty() { "local" } else { node_id },
        "base_url": base_url,
        "started_at": now,
        "last_action": now,
    });

    // Store session in Redis for cross-process visibility
    if let Some(redis) = state.redis.as_ref() {
        // Store individual session
        redis.set_string(
            &format!("noo:browser:session:{session_id}"),
            &session_data.to_string(),
        ).await;

        // Update session list (read, append, write back)
        let mut sessions: Vec<Value> = redis.get_string("noo:browser:sessions").await
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        sessions.push(session_data.clone());
        redis.set_string("noo:browser:sessions", &serde_json::to_string(&sessions).unwrap_or_default()).await;

        // Update session count
        redis.set_string("noo:browser:session_count", &sessions.len().to_string()).await;
    }

    tracing::info!(
        session_id = %session_id,
        base_url = %base_url,
        healthy,
        "browser_session_started"
    );

    Ok(Json(session_data))
}

/// POST /api/tools/browser/sessions/{session_id}/stop — stop a browser container.
///
/// Looks up the session from Redis, sends a stop request to the node-agent,
/// and removes the session from Redis. Matches the Python BrowserTool.stop_session().
async fn browser_stop(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> AppResult {
    // Look up session from Redis
    let session_data: Option<Value> = if let Some(redis) = state.redis.as_ref() {
        redis.get_string(&format!("noo:browser:session:{session_id}")).await
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    };

    let container_name = session_data.as_ref()
        .and_then(|s| s.get("container_name"))
        .and_then(|v| v.as_str())
        .unwrap_or(&format!("noo-browser-{session_id}"))
        .to_string();

    let node_id = session_data.as_ref()
        .and_then(|s| s.get("node_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Resolve the agent that runs it. A session whose agent
    // can no longer be named is refused, and its record is kept, rather
    // than "stopped" against an address where nothing listens.
    let link = browser_agent(&state, node_id).await?;

    // POST to node-agent to stop the container
    let req = link
        .request(reqwest::Method::POST, "/api/containers/stop")
        .json(&json!({"container_name": container_name}))
        .timeout(std::time::Duration::from_secs(15));

    if let Err(e) = req.send().await {
        tracing::warn!(
            session_id = %session_id,
            error = %e,
            "browser_container_stop_failed"
        );
    }

    // Remove session from Redis
    if let Some(redis) = state.redis.as_ref() {
        redis.del_key(&format!("noo:browser:session:{session_id}")).await;

        // Update session list (remove this session)
        let mut sessions: Vec<Value> = redis.get_string("noo:browser:sessions").await
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        sessions.retain(|s| {
            s.get("session_id").and_then(|v| v.as_str()) != Some(&session_id)
        });
        redis.set_string("noo:browser:sessions", &serde_json::to_string(&sessions).unwrap_or_default()).await;
        redis.set_string("noo:browser:session_count", &sessions.len().to_string()).await;
    }

    tracing::info!(session_id = %session_id, container = %container_name, "browser_session_stopped");

    Ok(Json(json!({
        "status": "stopped",
        "session_id": session_id,
        "engine": "rust",
    })))
}

/// GET /api/tools/browser/sessions — list active browser sessions.
///
/// Reads session data from Redis (noo:browser:sessions key).
/// Returns an empty list if Redis is unavailable or no sessions exist.
async fn browser_sessions(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    // Try to read sessions from Redis
    let sessions: Vec<Value> = if let Some(redis) = state.redis.as_ref() {
        match redis.get_string("noo:browser:sessions").await {
            Some(data) => {
                serde_json::from_str::<Vec<Value>>(&data).unwrap_or_default()
            }
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };

    Ok(Json(json!({
        "sessions": sessions,
        "engine": "rust",
    })))
}

/// POST /api/tools/browser/action — run a browser action natively.
///
/// Ported from `worker.browser.action` (port-lane item 6). The route
/// comment used to claim "complex Playwright interaction needs Python
/// runtime" — false: the Python handler never touched Playwright, it
/// proxied HTTP to the noo-browser container exactly like this does.
/// Session store is the same Redis keys the start/stop routes above own,
/// which also closes the old split-brain: Python kept ITS sessions in
/// process memory, so an agent action could never see a gateway-started
/// session and vice versa.
///
/// Body shapes accepted (mirrors the Python unwrap): the CLI sends
/// `{"action": ..., "params": {...}}`, and a worker-pool envelope may
/// nest that whole object under "params". Errors return `{"error": ...}`
/// with HTTP 200, matching the delegate's payload-level error contract.
async fn browser_action(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppResult {
    // Envelope unwrap: {"params": {"action": ...}} → inner object.
    let body = match body.get("params") {
        Some(p) if p.get("action").is_some() => p.clone(),
        _ => body,
    };
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if action.is_empty() {
        return Ok(Json(json!({"error": "browser action required"})));
    }
    // Params: nested {"params": {...}} or flat (everything but "action").
    let params: Value = match body.get("params") {
        Some(Value::Object(p)) => Value::Object(p.clone()),
        _ => {
            let mut m = body.as_object().cloned().unwrap_or_default();
            m.remove("action");
            Value::Object(m)
        }
    };

    // Resolve the session: explicit id → most recent Redis session →
    // auto-start one (same as Python BrowserTool.execute()).
    let mut session_id = params
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if session_id.is_empty() {
        if let Some(redis) = state.redis.as_ref() {
            let sessions: Vec<Value> = redis
                .get_string("noo:browser:sessions")
                .await
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            if let Some(sid) = sessions
                .first()
                .and_then(|s| s.get("session_id"))
                .and_then(|v| v.as_str())
            {
                session_id = sid.to_string();
            }
        }
    }
    if session_id.is_empty() {
        let start_body = json!({
            "node_id": params.get("node_id").cloned().unwrap_or(Value::Null),
            "url_allowlist": params.get("url_allowlist").cloned().unwrap_or(Value::Null),
            "url_blocklist": params.get("url_blocklist").cloned().unwrap_or(Value::Null),
        });
        let started = browser_start(State(state.clone()), Json(start_body)).await?.0;
        session_id = started
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if session_id.is_empty() {
            return Ok(Json(json!({"error": "failed to auto-start browser session"})));
        }
    }

    if action == "stop" {
        return browser_stop(State(state), Path(session_id)).await;
    }

    // Look up the session's container URL.
    let session_key = format!("noo:browser:session:{session_id}");
    let session_data: Option<Value> = match state.redis.as_ref() {
        Some(redis) => redis
            .get_string(&session_key)
            .await
            .and_then(|s| serde_json::from_str(&s).ok()),
        None => None,
    };
    let Some(mut session_data) = session_data else {
        return Ok(Json(json!({"error": format!("No browser session: {session_id}")})));
    };
    // Derive the route from the session's node and container, never from
    // the stored `base_url`: a session stored by a pre-proxy gateway holds
    // `http://<node>:<port>`, which is no longer published off-loopback.
    // (Such a session's container is orphaned by the upgrade; it dies on
    // the idle timeout, and stop still removes it by name.)
    let node_id = session_data.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
    let container_name = session_data
        .get("container_name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("noo-browser-{session_id}"));
    let link = browser_agent(&state, node_id).await?;
    let proxy_path = browser_proxy_path(&container_name);

    // Map action → container endpoint + payload (BrowserTool's action_map).
    let (path, payload, is_get) = match action.as_str() {
        "navigate" => (
            "/navigate",
            json!({
                "url": params.get("url").cloned().unwrap_or(Value::Null),
                "screenshot": params.get("screenshot").and_then(|v| v.as_bool()).unwrap_or(true),
            }),
            false,
        ),
        "click" => ("/click", json!({"selector": params.get("selector").cloned().unwrap_or(Value::Null)}), false),
        "type" => (
            "/type",
            json!({
                "selector": params.get("selector").cloned().unwrap_or(Value::Null),
                "text": params.get("text").cloned().unwrap_or(Value::Null),
            }),
            false,
        ),
        "extract" => (
            "/extract",
            json!({
                "selector": params.get("selector").cloned().unwrap_or(Value::Null),
                "attribute": params.get("attribute").cloned().unwrap_or(Value::Null),
                "all_matches": params.get("all_matches").and_then(|v| v.as_bool()).unwrap_or(false),
            }),
            false,
        ),
        "screenshot" => ("/screenshot", json!({}), false),
        "execute" => ("/execute", json!({"script": params.get("script").cloned().unwrap_or(Value::Null)}), false),
        "status" => ("/status", Value::Null, true),
        other => {
            return Ok(Json(json!({
                "error": format!(
                    "Unknown browser action: {other}. Available: navigate, click, \
                     type, extract, screenshot, execute, status, stop"
                )
            })));
        }
    };

    let result = if is_get {
        browser_proxied(
            link.request(reqwest::Method::GET, &format!("{proxy_path}{path}"))
                .timeout(std::time::Duration::from_secs(10)),
        )
        .send()
        .await
    } else {
        browser_proxied(
            link.request(reqwest::Method::POST, &format!("{proxy_path}{path}"))
                .json(&payload)
                .timeout(std::time::Duration::from_secs(30)),
        )
        .send()
        .await
    };

    let out = match result {
        Ok(resp) if resp.status().is_success() => {
            resp.json::<Value>().await.unwrap_or(json!({}))
        }
        Ok(resp) => {
            let detail = resp
                .json::<Value>()
                .await
                .ok()
                .and_then(|b| b.get("detail").cloned())
                .unwrap_or(Value::Null);
            json!({"error": detail.as_str().map(str::to_string).unwrap_or_else(|| "browser container error".into())})
        }
        Err(e) => json!({"error": format!("Browser request failed: {e}")}),
    };

    // Touch last_action so idle bookkeeping reflects reality.
    if let Some(redis) = state.redis.as_ref() {
        session_data["last_action"] = json!(chrono::Utc::now().timestamp() as f64);
        redis.set_string(&session_key, &session_data.to_string()).await;
    }

    Ok(Json(out))
}

// ═══════════════════════════════════════════════════════════════
// Tests — raw tool registry passthrough (WP-TE)
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod runbook_title_tests {
    use super::runbook_title;

    #[test]
    fn frontmatter_title_wins() {
        let md = "---\ntitle: \"Node Provisioning\"\ndomain: \"cluster\"\n---\n\n# Heading\n";
        assert_eq!(runbook_title("node-provisioning", md), "Node Provisioning");
    }

    #[test]
    fn frontmatter_without_title_falls_to_first_heading() {
        let md = "---\ndomain: \"cluster\"\n---\n\n# Real Heading\n";
        assert_eq!(runbook_title("x", md), "Real Heading");
    }

    #[test]
    fn no_frontmatter_keeps_old_rule() {
        assert_eq!(runbook_title("x", "# Plain Title\nbody"), "Plain Title");
        assert_eq!(runbook_title("fallback-name", "   \n\n"), "fallback-name");
    }
}

#[cfg(test)]
mod registry_raw_tests {
    use super::*;

    // The route's semantics live in the pure `registry_raw_body` helper so
    // they are testable without an AppState (repo convention — no DB-backed
    // route harness exists): the handler is a thin read-lock + call.

    /// A minimal registry in the exact config/tools.json shape, including
    /// the two fields /tools/list strips (the WP-A5 corruption finding):
    /// per-tool `nats_subject` and top-level `extended_tool_groups`.
    fn full_registry() -> Value {
        json!({
            "_version": 3,
            "_description": "generated",
            "core_tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "noo_rag_query",
                        "description": "Search the knowledge base.",
                        "parameters": {"type": "object", "properties": {}}
                    },
                    "tags": ["rag"],
                    "speed": "fast",
                    "nats_subject": "worker.rag.query"
                }
            ],
            "extended_tool_groups": {
                "research": {"tools": ["web_search"], "keywords": ["research"]}
            }
        })
    }

    #[test]
    fn passes_full_registry_through_verbatim() {
        let raw = full_registry();
        let body = registry_raw_body(&raw).expect("full registry is served");
        // Verbatim — nothing stripped, nothing added.
        assert_eq!(body, raw);
        // And explicitly: the routing metadata /tools/list drops is present.
        assert_eq!(
            body["core_tools"][0]["nats_subject"].as_str(),
            Some("worker.rag.query")
        );
        assert!(body["extended_tool_groups"]["research"].is_object());
        assert_eq!(body["core_tools"][0]["speed"].as_str(), Some("fast"));
        assert_eq!(body["core_tools"][0]["tags"][0].as_str(), Some("rag"));
    }

    #[test]
    fn refuses_missing_or_empty_registry() {
        // Startup fallback caches {} when config/tools.json is absent —
        // serving that would let `noo tools export` truncate the artifact.
        for raw in [json!({}), json!({"core_tools": []}), json!({"core_tools": "nope"})] {
            assert!(
                matches!(registry_raw_body(&raw), Err(AppError::NotFound(_))),
                "expected NotFound for {raw}"
            );
        }
    }
}

#[cfg(test)]
mod honesty_tests {
    use super::*;

    // "The system must not lie" audit — the pure classifier behind the
    // proactive-history reporting. The handlers themselves have no testable
    // seam without a live Postgres, so only the classifier is covered here.

    #[test]
    fn missing_table_only_matches_42p01() {
        // sqlx::Error variants that are trivially constructible; the 42P01
        // Database variant needs a driver error object, so the negative
        // cases are what is assertable in a unit test.
        assert!(!missing_table(&sqlx::Error::PoolTimedOut));
        assert!(!missing_table(&sqlx::Error::RowNotFound));
    }

    #[test]
    fn history_detail_never_claims_the_store_is_empty() {
        // Whatever the failure, the wording must describe an UNKNOWN, never
        // "no rows" — nothing writes noo_proactive_history, so a zero would
        // be a fabrication either way.
        let detail = proactive_history_detail(&sqlx::Error::PoolTimedOut);
        assert!(detail.starts_with("unknown"), "got: {detail}");
        assert!(detail.contains("noo_proactive_history"), "got: {detail}");
    }
}

#[cfg(test)]
mod browser_agent_tests {
    use super::*;

    #[test]
    fn no_node_and_no_declared_agent_is_refused_with_the_way_out() {
        for configured in [None, Some(String::new()), Some("   ".into())] {
            let Err(AppError::BadRequest(msg)) = default_browser_agent(configured.clone()) else {
                panic!("{configured:?} must be refused, not dialled");
            };
            assert!(msg.contains("node_id"), "{msg}");
            assert!(msg.contains("NOO_DEFAULT_AGENT_URL"), "{msg}");
        }
    }

    #[test]
    fn a_declared_agent_is_used_as_given() {
        assert_eq!(
            default_browser_agent(Some("https://10.0.0.5:8081/".into())).ok().as_deref(),
            Some("https://10.0.0.5:8081")
        );
    }

    /// The fallback that dialled the gateway's own container must not come
    /// back: it reached no agent, and with no record behind it the static
    /// token went with it.
    #[test]
    fn no_localhost_agent_fallback_in_the_browser_routes() {
        let needle = ["https://localhost", ":8081"].concat();
        let code = include_str!("ui.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!code.contains(&needle), "ui.rs dials {needle} again");
    }
}

#[cfg(test)]
mod browser_proxy_tests {
    #[test]
    fn session_url_is_the_agents_proxy_route() {
        assert_eq!(
            crate::node_link::NodeLink::for_base("https://10.0.0.5:8081/")
                .url(&super::browser_proxy_path("noo-browser-ab12cd34")),
            "https://10.0.0.5:8081/api/containers/noo-browser-ab12cd34/proxy"
        );
    }
}

#[cfg(test)]
mod browser_key_tests {
    /// the gateway's browser bearer is signed with the browser
    /// door's own key. It verifies there and nowhere else — not under the
    /// fleet secret (the gateway's node door) and not under another key.
    #[test]
    fn the_browser_bearer_is_the_browser_keys_and_nothing_elses() {
        let (_, bearer) = super::browser_auth_header_with("browser-key").unwrap();
        let token = bearer.strip_prefix("Bearer ").unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(crate::auth::verify_cluster_token_inner(token, "browser-key", now));
        assert!(!crate::auth::verify_cluster_token_inner(token, "fleet-secret", now), "a browser bearer is not a node token");
    }

    /// The env handed to a node-started browser container carries the browser
    /// key — under both names for one release — and never the fleet secret.
    #[test]
    fn browser_start_env_carries_no_fleet_secret() {
        let src = include_str!("ui.rs");
        let body = src.split("async fn browser_start(").nth(1).unwrap().split("\nasync fn ").next().unwrap();
        let code: String = body.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
        assert!(code.contains("secret_or_empty(BROWSER_KEY)"), "the start must read the browser key");
        assert!(!code.contains("\"NOO_CLUSTER_SECRET\")"), "browser_start reads the fleet secret again");
        assert!(code.contains("\"NOO_BROWSER_KEY\": browser_key.clone(),"));
        assert!(code.contains("\"NOO_CLUSTER_SECRET\": browser_key,"), "the one-release compat name must carry the BROWSER key");
        let header = src.split("fn browser_auth_header() -> Option<(String, String)> {").nth(1).unwrap().split("\n}").next().unwrap();
        assert!(header.contains("secret_opt(BROWSER_KEY)") && !header.contains("NOO_CLUSTER_SECRET"), "{header}");
    }
}
