// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Server-assigned MCP sessions.
//!
//! ## Why
//!
//! The doors mint the caller's JWT per tool call and, until this module,
//! had no notion of a session: every request from every window of one
//! person was the same identity. Option A (#229) made identity per KEY —
//! `<account>/<key label>` — which separates clients only if the operator
//! issues a key per client, and separates nothing when one client opens
//! several windows. The operator's requirement is that **each MCP session
//! keeps its own provenance while permissions stay scoped to the user**,
//! with no per-device configuration.
//!
//! ## How
//!
//! MCP's Streamable HTTP transport lets the server return an
//! `Mcp-Session-Id` header on the `initialize` response, and requires a
//! compliant client to echo it on every later request. So:
//!
//! - `initialize` opens a session and the response carries the id;
//! - every later request presents the id, the registry resolves it to a
//!   LABEL, and the door mints `sub = <account>/<label>`;
//! - an id the registry does not know is answered **404** — the spec's
//!   signal for "re-initialize", which a compliant client does on its own.
//!   That is also what happens after a gateway restart: sessions live in
//!   memory, so every client re-initializes once and carries on;
//! - a request with no id at all gets the per-key label (#229's
//!   behaviour), so a client that ignores the header is degraded, not
//!   broken.
//!
//! ## What the id is, and is not
//!
//! The id is 128 random bits, then `.` and the public digest of the tool
//! catalogue it was opened under (see "catalogue freshness" below). It
//! distinguishes sessions; it does **not**
//! authorise anything — the bearer key does that, on every request, as
//! before. A session is bound to the consumer that opened it and refused
//! to any other, so a leaked id is useless without the key, and with the
//! key it names a sibling session of the same person, which is inside
//! that person's own trust.
//!
//! **Provenance is the session; permission is the account.** Role, scopes,
//! KB audience and the kill switch all resolve to `account_of(sub)`. What
//! the session keys is `from`, presence and the inbox.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

/// The header, as the MCP spec names it.
pub const HEADER: &str = "mcp-session-id";

/// Idle lifetime. A window that has said nothing for a day is gone; the
/// client re-initializes on the 404 and gets a fresh session.
pub const IDLE_TTL: Duration = Duration::from_secs(24 * 3600);

/// Hard cap on live sessions. Each is a few hundred bytes; the cap is
/// there so a client looping on `initialize` cannot grow the map without
/// bound. Past it, the oldest idle session is evicted.
const MAX_SESSIONS: usize = 10_000;

#[derive(Clone, Debug)]
pub struct Session {
    pub account: String,
    pub consumer: String,
    /// The connection label this session mints under: `<type>-<session>`,
    /// a valid name segment ([`session_label`], renamed by [`rename`]).
    pub label: String,
    pub opened: Instant,
    pub last_seen: Instant,
    /// When the ROW's `last_seen` was last written. Every tool call
    /// resolves; the row is touched at most every [`TOUCH_EVERY`].
    pub last_db_touch: Instant,
}

static REGISTRY: OnceLock<RwLock<HashMap<String, Session>>> = OnceLock::new();

fn registry() -> &'static RwLock<HashMap<String, Session>> {
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A fresh, unguessable session id: 128 random bits, then `.` and the
/// tool catalogue it was opened under ([`catalogue_of`]).
fn new_id() -> String {
    use rand::Rng;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    format!("{}.{}", b64url(&b), crate::mcp_external::catalogue_digest())
}

/// The short suffix that tells two sessions of one key apart. Lowercase
/// alphanumerics so the label stays inside the name class.
fn suffix() -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut r = rand::rng();
    (0..6).map(|_| ALPHABET[r.random_range(0..ALPHABET.len())] as char).collect()
}

/// Client kinds named by their own `clientInfo.name` often enough to get a
/// short, stable type: `claude-code` → `claude`. Matched as a substring of
/// the lowercased name, first match wins.
const KNOWN_TYPES: &[&str] = &["claude", "codex", "cursor", "gemini"];

/// Longest type kept, so `<type>-<session>` stays well inside a segment.
const MAX_TYPE: usize = 32;

/// Longest session part a caller may claim with [`rename`].
pub const MAX_CLAIMED: usize = 64;

/// The TYPE half of a session's name (`<account>/<type>-<session>`): what
/// kind of client opened it. A known client's short name, else the
/// client's own name made into a segment, else the key's label — the
/// pre-type behaviour, for a client that sends no `clientInfo.name`.
///
/// The client name is self-reported and display-grade: it chooses the
/// LABEL, never a permission. Two clients that both call themselves
/// `claude` are still two sessions, told apart by the session half.
pub fn session_type(consumer: &str, client_name: Option<&str>) -> Option<String> {
    let cap = |s: String| -> String { s.chars().take(MAX_TYPE).collect::<String>().trim_end_matches('-').to_string() };
    if let Some(name) = client_name.map(str::trim).filter(|n| !n.is_empty()) {
        let lower = name.to_ascii_lowercase();
        if let Some(t) = KNOWN_TYPES.iter().find(|t| lower.contains(*t)) {
            return Some((*t).to_string());
        }
        if let Some(l) = crate::auth::connection_label(&lower).map(cap).filter(|l| !l.is_empty()) {
            return Some(l);
        }
    }
    crate::auth::connection_label(consumer).map(|l| l.chars().take(120).collect())
}

/// Build the label a session mints under: `<type>-<short suffix>`, one
/// valid segment. The suffix is what [`rename`] replaces with a name the
/// session chooses.
pub fn session_label(consumer: &str, client_name: Option<&str>) -> Option<String> {
    let base = session_type(consumer, client_name)?;
    let label = format!("{base}-{}", suffix());
    if crate::auth::valid_name_segment(&label) { Some(label) } else { None }
}

/// The label a session of type `ty` gets when it claims `wanted`:
/// `<type>-<wanted>`, or `wanted` itself when it already starts with
/// `<type>-` (claiming `claude-general` is not `claude-claude-general`).
pub fn claimed_label(ty: &str, wanted: &str) -> Result<String, String> {
    let wanted = wanted.trim();
    if wanted.is_empty() || wanted.chars().count() > MAX_CLAIMED || !crate::auth::valid_name_segment(wanted) {
        return Err(format!(
            "a session name is 1–{MAX_CLAIMED} characters of A-Z a-z 0-9 _ - (got '{wanted}')"
        ));
    }
    let label = if wanted.starts_with(&format!("{ty}-")) { wanted.to_string() } else { format!("{ty}-{wanted}") };
    if crate::auth::valid_name_segment(&label) { Ok(label) } else { Err(format!("'{label}' is not a valid name")) }
}

/// Open a session for `account` via `consumer`, typed by the client's own
/// `clientInfo.name`. `None` when neither yields a usable label — the
/// caller then falls back to the per-key path exactly as it would without
/// a session.
pub fn open_local(account: &str, consumer: &str, client_name: Option<&str>) -> Option<(String, String)> {
    let label = session_label(consumer, client_name)?;
    let id = new_id();
    let now = Instant::now();
    let mut map = registry().write().ok()?;
    if map.len() >= MAX_SESSIONS {
        // Evict the longest-idle entry rather than refusing the new one:
        // the new window is the one a person is looking at.
        if let Some(oldest) = map.iter().min_by_key(|(_, s)| s.last_seen).map(|(k, _)| k.clone()) {
            map.remove(&oldest);
        }
    }
    map.insert(
        id.clone(),
        Session { account: account.into(), consumer: consumer.into(), label: label.clone(), opened: now, last_seen: now, last_db_touch: now },
    );
    Some((id, label))
}

/// Why a presented id did not resolve. Both are answered the same on the
/// wire (404, re-initialize); they are distinct here so a test can tell a
/// stolen id from an expired one.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Unknown,
    Expired,
    /// Presented under a different key than opened it. Refused rather
    /// than re-bound: a session is provenance, and provenance that can be
    /// transferred is not.
    WrongConsumer,
}

/// Resolve a presented id for `consumer`. Touches `last_seen` on success.
pub fn resolve_local(id: &str, consumer: &str) -> Result<Session, Refusal> {
    let mut map = registry().write().map_err(|_| Refusal::Unknown)?;
    let Some(s) = map.get_mut(id) else { return Err(Refusal::Unknown) };
    if s.last_seen.elapsed() > IDLE_TTL {
        map.remove(id);
        return Err(Refusal::Expired);
    }
    if s.consumer != consumer {
        return Err(Refusal::WrongConsumer);
    }
    s.last_seen = Instant::now();
    Ok(s.clone())
}

/// The door-side half. Read the header; absent → `Ok(None)` (per-key
/// fallback); known → `Ok(Some(label))`; unknown, expired or opened under
/// another key → the spec's 404, which a compliant client answers by
/// re-initializing. One outcome per case, and no case is silent.
pub async fn from_headers(
    db: &sqlx::PgPool,
    headers: &axum::http::HeaderMap,
    consumer: &str,
) -> Result<Option<String>, axum::response::Response> {
    use axum::response::IntoResponse;
    let Some(id) = presented(headers) else {
        return Ok(None);
    };
    match resolve(db, id, consumer).await {
        Ok(s) => Ok(Some(s.label)),
        Err(why) => {
            tracing::info!(?why, consumer, "mcp session refused; client should re-initialize");
            Err((
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({"error": {"type": "session_not_found",
                    "message": "unknown or expired Mcp-Session-Id — re-initialize"}})),
            )
                .into_response())
        }
    }
}

/// The session id a request presents, if any.
fn presented(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers.get(HEADER).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty())
}

/// Stamp a freshly opened session onto the `initialize` response.
pub fn attach(mut resp: axum::response::Response, id: &str) -> axum::response::Response {
    if let Ok(v) = axum::http::HeaderValue::from_str(id) {
        resp.headers_mut().insert(axum::http::HeaderName::from_static(HEADER), v);
    }
    resp
}

// ── persistence (migration 076) ──────────────────────────────────────
//
// The map above is now a CACHE. The row is the record: a restart no
// longer forgets every window, a sender can list who is alive, and
// provenance outlives the idle TTL. The id is stored hashed — a table of
// plaintext ids would let anyone who could read it impersonate every live
// window of every person.

fn id_hash(id: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(id.as_bytes()))
}

/// How often a resolve is allowed to touch the row's `last_seen`. Every
/// tool call resolves; writing the row on each would be a write per call
/// for a value nobody reads at that resolution.
const TOUCH_EVERY: Duration = Duration::from_secs(60);

/// Open a session and record it. `display_name` is the client's own
/// `clientInfo.name` — display only. `None` when the consumer yields no
/// label (falls back to the per-key path) or the row cannot be written:
/// a session the table does not know is one a restart would forget, so
/// it is not handed out.
pub async fn open(db: &sqlx::PgPool, account: &str, consumer: &str, display_name: Option<&str>) -> Option<(String, String)> {
    let display: Option<String> = display_name
        .map(str::trim)
        .filter(|d| !d.is_empty() && d.chars().count() <= 64 && !d.chars().any(char::is_control))
        .map(str::to_string);
    let (id, label) = open_local(account, consumer, display.as_deref())?;
    let r = sqlx::query(
        "INSERT INTO noo_mcp_sessions (id_hash, account, consumer, label, display_name) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id_hash(&id))
    .bind(account)
    .bind(consumer)
    .bind(&label)
    .bind(&display)
    .execute(db)
    .await;
    if let Err(e) = r {
        tracing::error!(error = %e, account, "mcp session could not be recorded; not issuing it");
        if let Ok(mut m) = registry().write() { m.remove(&id); }
        return None;
    }
    Some((id, label))
}

/// Resolve with the cache first, the row second. A cache miss after a
/// restart repopulates from the row, so clients keep their sessions
/// across a gateway recreate instead of re-initialising.
pub async fn resolve(db: &sqlx::PgPool, id: &str, consumer: &str) -> Result<Session, Refusal> {
    match resolve_local(id, consumer) {
        Ok(s) => {
            // Touch the row at most every TOUCH_EVERY so `last_seen` and
            // presence stay honest without a write per tool call.
            if s.last_db_touch.elapsed() > TOUCH_EVERY {
                let _ = sqlx::query("UPDATE noo_mcp_sessions SET last_seen = now() WHERE id_hash = $1")
                    .bind(id_hash(id)).execute(db).await;
                if let Ok(mut m) = registry().write() {
                    if let Some(x) = m.get_mut(id) { x.last_db_touch = Instant::now(); }
                }
            }
            Ok(s)
        }
        Err(Refusal::WrongConsumer) => Err(Refusal::WrongConsumer),
        Err(_) => {
            // Not in this process's memory: ask the table.
            let row: Option<(String, String, String, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "SELECT account, consumer, label, opened_at, last_seen FROM noo_mcp_sessions WHERE id_hash = $1",
            )
            .bind(id_hash(id))
            .fetch_optional(db)
            .await
            .map_err(|_| Refusal::Unknown)?;
            let Some((account, row_consumer, label, opened_at, last_seen)) = row else { return Err(Refusal::Unknown) };
            if (chrono::Utc::now() - last_seen).to_std().map(|d| d > IDLE_TTL).unwrap_or(false) {
                return Err(Refusal::Expired);
            }
            if row_consumer != consumer {
                return Err(Refusal::WrongConsumer);
            }
            let _ = sqlx::query("UPDATE noo_mcp_sessions SET last_seen = now() WHERE id_hash = $1")
                .bind(id_hash(id)).execute(db).await;
            let now = Instant::now();
            let age = (chrono::Utc::now() - opened_at).to_std().unwrap_or_default();
            let s = Session { account, consumer: row_consumer, label, opened: now.checked_sub(age).unwrap_or(now), last_seen: now, last_db_touch: now };
            if let Ok(mut m) = registry().write() { m.insert(id.to_string(), s.clone()); }
            Ok(s)
        }
    }
}

/// Rename the live session `<account>/<old>` to `<type>-<wanted>`, so other
/// sessions can address it by a name its person chose (`owner/claude-general`)
/// instead of the random suffix it opened with. Returns the new label.
///
/// The type is recomputed from the row (consumer + client name), so a
/// session cannot rename itself into another client's type.
///
/// **A name is a mailbox.** Claiming a name another live session of the
/// same account already holds JOINS it: both mint the same `sub`, so both
/// read and send as that name. That is what lets one window's MCP
/// connections (a client often holds one per door) and its inbox hook be
/// one address. It stays inside one person's trust — sessions of an
/// account are that person's — and the reply says how many sessions were
/// already there, so a join is never silent. Renaming a shared name moves
/// every session holding it.
///
/// Mail already sent to the old name stays addressed to it; the rename is
/// for what comes next. Returns the new label and how many other live
/// sessions already held it.
pub async fn rename(db: &sqlx::PgPool, account: &str, old: &str, wanted: &str) -> Result<(String, i64), String> {
    let ttl = IDLE_TTL.as_secs().to_string();
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT consumer, display_name FROM noo_mcp_sessions \
         WHERE account = $1 AND label = $2 AND last_seen > now() - ($3 || ' seconds')::interval \
         ORDER BY last_seen DESC LIMIT 1",
    )
    .bind(account)
    .bind(old)
    .bind(&ttl)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("session lookup failed: {e}"))?;
    let Some((consumer, display)) = row else {
        return Err(format!("no live MCP session is named '{account}/{old}' — connect through an MCP door first"));
    };
    let ty = session_type(&consumer, display.as_deref()).ok_or("this session has no type to name it under")?;
    let label = claimed_label(&ty, wanted)?;
    let holders: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM noo_mcp_sessions \
         WHERE account = $1 AND label = $2 AND last_seen > now() - ($3 || ' seconds')::interval",
    )
    .bind(account)
    .bind(&label)
    .bind(&ttl)
    .fetch_one(db)
    .await
    .map_err(|e| format!("session lookup failed: {e}"))?;
    if label == old {
        // Already this name: the others are everyone holding it but us.
        return Ok((label, (holders - 1).max(0)));
    }
    let shared = holders;
    sqlx::query("UPDATE noo_mcp_sessions SET label = $3 WHERE account = $1 AND label = $2")
        .bind(account)
        .bind(old)
        .bind(&label)
        .execute(db)
        .await
        .map_err(|e| format!("rename failed: {e}"))?;
    rename_local(account, old, &label);
    Ok((label, shared))
}

/// The cache half of [`rename`]: every cached session `<account>/<old>`
/// mints under the new label from its next request.
fn rename_local(account: &str, old: &str, new: &str) {
    if let Ok(mut map) = registry().write() {
        for s in map.values_mut().filter(|s| s.account == account && s.label == old) {
            s.label = new.to_string();
        }
    }
}

/// Live sessions under `account`: last seen within the idle TTL, newest
/// first. This is presence for a person's own windows. `display_name` is
/// carried for humans and must not be used as a key by any caller.
pub async fn live_for(db: &sqlx::PgPool, account: &str) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let rows: Vec<(String, String, Option<String>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT label, consumer, display_name, opened_at, last_seen FROM noo_mcp_sessions \
         WHERE account = $1 AND last_seen > now() - ($2 || ' seconds')::interval \
         ORDER BY last_seen DESC",
    )
    .bind(account)
    .bind(IDLE_TTL.as_secs().to_string())
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(label, consumer, display_name, opened_at, last_seen)| serde_json::json!({
        "connection": format!("{account}{}{label}", crate::auth::CONNECTION_SEP),
        "label": label,
        "consumer": consumer,
        "display_name": display_name,
        "opened_at": opened_at,
        "last_seen": last_seen,
    })).collect())
}

/// Live sessions under EVERY account (operator view), newest first. Same
/// rows as [`live_for`] plus the `account` each belongs to.
pub async fn live_all(db: &sqlx::PgPool) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let rows: Vec<(String, String, String, Option<String>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT account, label, consumer, display_name, opened_at, last_seen FROM noo_mcp_sessions \
         WHERE last_seen > now() - ($1 || ' seconds')::interval \
         ORDER BY last_seen DESC",
    )
    .bind(IDLE_TTL.as_secs().to_string())
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(account, label, consumer, display_name, opened_at, last_seen)| serde_json::json!({
        "account": account,
        "connection": format!("{account}{}{label}", crate::auth::CONNECTION_SEP),
        "label": label,
        "consumer": consumer,
        "display_name": display_name,
        "opened_at": opened_at,
        "last_seen": last_seen,
    })).collect())
}

// ── catalogue freshness (i277f) ──────────────────────────────────────
//
// A client keeps the tool list it fetched when its session opened, and a
// session survives a gateway restart (the row). So a roll that changes the
// catalogue left every open window on the old list, with nothing to tell
// it: a tool added in 0.6.11 was missing in a session opened before. Nor
// does a client re-list when it re-initializes (gateway log 2026-10-30:
// 404, `initialize`, and straight back to tool calls).
//
// Each id carries the catalogue it was opened under. The first answered
// request of a session whose catalogue is not this gateway's goes back as
// an SSE stream that leads with `notifications/tools/list_changed`; a
// client answers that by fetching `tools/list` again. Legacy initialize
// advertises `listChanged: true` so it listens. The client asked for SSE
// (Streamable HTTP requires both types in `Accept`); one that did not
// gets plain JSON and is told on a later request that does. An id minted
// before this carries no catalogue and counts as stale. Told once per id
// per process, so a restart may tell a session again: one extra list.
//
// The bridged external MCP servers (`mcp_bridge`) are not in the digest:
// they change without a restart, and a session is not told.

/// The method a client re-lists on.
pub const LIST_CHANGED: &str = "notifications/tools/list_changed";

/// The catalogue digest an id was opened under (`None`: minted before ids
/// carried one).
pub fn catalogue_of(id: &str) -> Option<&str> {
    id.rsplit_once('.').map(|(_, d)| d)
}

static TOLD: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = OnceLock::new();

fn told() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    TOLD.get_or_init(Default::default)
}

/// Does the session `id` still hold a tool list from another catalogue?
pub fn owes_list_changed(id: &str) -> bool {
    if catalogue_of(id) == Some(crate::mcp_external::catalogue_digest()) {
        return false;
    }
    told().lock().map(|s| !s.contains(id)).unwrap_or(false)
}

fn mark_told(id: &str) {
    if let Ok(mut s) = told().lock() {
        if s.len() >= MAX_SESSIONS {
            s.clear(); // bounded; the cost of forgetting is one more list
        }
        s.insert(id.to_string());
    }
}

/// Both doors pass every answer through here. An answered (200, JSON)
/// request of a session that owes the notice goes back as SSE: the
/// `list_changed` notification, then the answer. Anything else is returned
/// unchanged.
pub async fn with_list_changed(headers: &axum::http::HeaderMap, resp: axum::response::Response) -> axum::response::Response {
    use axum::http::header;
    let Some(id) = presented(headers) else { return resp };
    let json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.starts_with("application/json"));
    let sse = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/event-stream"));
    if resp.status() != axum::http::StatusCode::OK || !json || !sse || !owes_list_changed(id) {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "mcp answer body unreadable; list_changed not sent");
            return axum::response::Response::from_parts(parts, axum::body::Body::empty());
        }
    };
    // One `data:` line per event: re-serialised compact, so a newline in
    // the answer cannot split it.
    let Ok(answer) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return axum::response::Response::from_parts(parts, axum::body::Body::from(bytes));
    };
    let note = serde_json::json!({"jsonrpc": "2.0", "method": LIST_CHANGED});
    let stream = format!("event: message\ndata: {note}\n\nevent: message\ndata: {answer}\n\n");
    parts.headers.insert(header::CONTENT_TYPE, axum::http::HeaderValue::from_static("text/event-stream"));
    parts.headers.insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-cache"));
    parts.headers.remove(header::CONTENT_LENGTH);
    mark_told(id);
    tracing::info!(opened_under = catalogue_of(id).unwrap_or("none"), now = crate::mcp_external::catalogue_digest(),
        "mcp tool catalogue changed since this session opened; sent tools/list_changed");
    axum::response::Response::from_parts(parts, axum::body::Body::from(stream))
}

/// Live session count, for `/health`-style reporting and tests.
pub fn live() -> usize {
    registry().read().map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered() -> axum::response::Response {
        use axum::response::IntoResponse;
        axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "a\nb"}]}})).into_response()
    }

    fn presenting(id: &str, accept: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(HEADER, id.parse().unwrap());
        h.insert(axum::http::header::ACCEPT, accept.parse().unwrap());
        h
    }

    async fn text(resp: axum::response::Response) -> (String, String) {
        let ct = resp.headers().get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (ct, String::from_utf8(b.to_vec()).unwrap())
    }

    const BOTH: &str = "application/json, text/event-stream";

    /// A session opened now holds this catalogue: never told.
    #[tokio::test]
    async fn a_session_opened_now_carries_the_catalogue_and_is_not_told() {
        let (id, _) = open_local("fresh", "self:fresh", None).unwrap();
        assert_eq!(catalogue_of(&id), Some(crate::mcp_external::catalogue_digest()));
        assert!(!owes_list_changed(&id));
        let (ct, _) = text(with_list_changed(&presenting(&id, BOTH), answered()).await).await;
        assert!(ct.starts_with("application/json"), "{ct}");
    }

    /// The 0.6.11 case: a session from before a roll that changed the
    /// catalogue. Its next answer leads with list_changed, then the answer
    /// itself, whole; the one after is plain JSON again.
    #[tokio::test]
    async fn a_session_from_another_catalogue_is_told_once_then_answered_plainly() {
        let id = "c3RhbGUtc2Vzc2lvbi1vbmU.0123456789abcdef";
        assert!(owes_list_changed(id));
        let (ct, body) = text(with_list_changed(&presenting(id, BOTH), answered()).await).await;
        assert_eq!(ct, "text/event-stream");
        let events: Vec<serde_json::Value> = body
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .map(|d| serde_json::from_str(d).expect("each data line is one JSON message"))
            .collect();
        assert_eq!(events.len(), 2, "{body}");
        assert_eq!(events[0]["method"], LIST_CHANGED);
        assert!(events[0].get("id").is_none(), "a notification carries no id");
        assert_eq!(events[1]["id"], 7);
        assert_eq!(events[1]["result"]["content"][0]["text"], "a\nb", "the answer arrives unchanged");
        assert!(!owes_list_changed(id));
        let (ct, _) = text(with_list_changed(&presenting(id, BOTH), answered()).await).await;
        assert!(ct.starts_with("application/json"), "told once: {ct}");
    }

    /// An id minted before ids carried a catalogue counts as stale. A
    /// client that does not take SSE, a refusal and a notification's 202
    /// pass unchanged, and the session still owes the notice.
    #[tokio::test]
    async fn only_an_answered_request_that_takes_sse_carries_the_notice() {
        use axum::response::IntoResponse;
        let old = "b2xkLXN0eWxlLWlkLW5vLWRvdA";
        assert_eq!(catalogue_of(old), None);
        assert!(owes_list_changed(old));
        let (ct, _) = text(with_list_changed(&presenting(old, "application/json"), answered()).await).await;
        assert!(ct.starts_with("application/json"), "{ct}");
        let r = with_list_changed(&presenting(old, BOTH), axum::http::StatusCode::ACCEPTED.into_response()).await;
        assert_eq!(r.status(), axum::http::StatusCode::ACCEPTED);
        let mut refused = answered();
        *refused.status_mut() = axum::http::StatusCode::NOT_FOUND;
        assert_eq!(with_list_changed(&presenting(old, BOTH), refused).await.status(), axum::http::StatusCode::NOT_FOUND);
        assert!(owes_list_changed(old), "nothing was sent, so the notice is still owed");
        let (ct, _) = text(with_list_changed(&axum::http::HeaderMap::new(), answered()).await).await;
        assert!(ct.starts_with("application/json"), "no session, nothing to tell: {ct}");
    }

    #[test]
    fn a_session_is_a_valid_connection_under_its_account() {
        let (id, label) = open_local("owner", "self:owner", None).expect("open");
        assert!(id.len() >= 20, "128 random bits, base64url");
        assert!(label.starts_with("self-owner-"), "{label}");
        assert!(crate::auth::valid_name_segment(&label));
        assert!(crate::agent_messages::is_valid_id(&format!("owner/{label}")));
        assert_eq!(crate::auth::account_of(&format!("owner/{label}")), "owner");
    }

    /// The requirement, stated as a test: two windows of one person on
    /// ONE key are two sessions with two labels — no per-device key.
    #[test]
    fn two_windows_on_one_key_are_two_sessions() {
        let (a, la) = open_local("owner", "self:owner", None).unwrap();
        let (b, lb) = open_local("owner", "self:owner", None).unwrap();
        assert_ne!(a, b);
        assert_ne!(la, lb);
        assert_eq!(resolve_local(&a, "self:owner").unwrap().label, la);
        assert_eq!(resolve_local(&b, "self:owner").unwrap().label, lb);
    }

    /// Provenance that can be transferred is not provenance.
    #[test]
    fn a_session_answers_only_to_the_key_that_opened_it() {
        let (id, _) = open_local("owner", "self:owner", None).unwrap();
        assert_eq!(resolve_local(&id, "other-key").unwrap_err(), Refusal::WrongConsumer);
        assert!(resolve_local(&id, "self:owner").is_ok(), "…and still works for the right one");
        assert_eq!(resolve_local("not-a-session", "self:owner").unwrap_err(), Refusal::Unknown);
    }

    #[test]
    fn a_consumer_with_no_label_opens_no_session() {
        assert!(open_local("owner", ":::", None).is_none());
    }

    /// `<account>/<type>-<session>`: the type is what the client calls
    /// itself, shortened for the clients people run, and the key's label
    /// only when the client says nothing.
    #[test]
    fn a_session_label_is_type_then_session() {
        let (_, l) = open_local("owner", "self:owner", Some("claude-code")).unwrap();
        assert!(l.starts_with("claude-") && l.len() == "claude-".len() + 6, "{l}");
        assert_eq!(session_type("k", Some("Codex MCP Client")).as_deref(), Some("codex"));
        assert_eq!(session_type("k", Some("mcp-inspector")).as_deref(), Some("mcp-inspector"));
        assert_eq!(session_type("self:owner", None).as_deref(), Some("self-owner"));
        assert_eq!(session_type("self:owner", Some("  ")).as_deref(), Some("self-owner"));
        assert_eq!(session_type("self:owner", Some("☃")).as_deref(), Some("self-owner"), "nothing usable → the key");
        let long = "x".repeat(200);
        assert!(session_type("k", Some(&long)).unwrap().len() <= MAX_TYPE);
    }

    /// A claimed name keeps the session's type and refuses anything that
    /// would not be one plain segment.
    #[test]
    fn a_claimed_name_is_prefixed_with_the_type_once() {
        assert_eq!(claimed_label("claude", "general").unwrap(), "claude-general");
        assert_eq!(claimed_label("claude", "claude-general").unwrap(), "claude-general");
        assert_eq!(claimed_label("codex", "claude-general").unwrap(), "codex-claude-general", "no switching type");
        for bad in ["", "a/b", "has space", "dot.ted", "é", &"x".repeat(MAX_CLAIMED + 1)] {
            assert!(claimed_label("claude", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_rename_reaches_every_cached_copy_of_the_session() {
        let (id, old) = open_local("renamer", "self:renamer", Some("claude-code")).unwrap();
        rename_local("renamer", &old, "claude-general");
        assert_eq!(resolve_local(&id, "self:renamer").unwrap().label, "claude-general");
        rename_local("someone-else", "claude-general", "claude-x");
        assert_eq!(resolve_local(&id, "self:renamer").unwrap().label, "claude-general", "another account's rename is not ours");
    }

    #[test]
    fn an_idle_session_expires_and_is_removed() {
        let (id, _) = open_local("owner", "self:owner", None).unwrap();
        {
            let mut map = registry().write().unwrap();
            map.get_mut(&id).unwrap().last_seen = Instant::now() - IDLE_TTL - Duration::from_secs(1);
        }
        assert_eq!(resolve_local(&id, "self:owner").unwrap_err(), Refusal::Expired);
        assert_eq!(resolve_local(&id, "self:owner").unwrap_err(), Refusal::Unknown, "removed, not merely refused");
    }
}

/// The rename against a real Postgres. Opt-in like the other storage tests:
/// `NOO_TEST_DSN` names a scratch database; without it the test says so and
/// passes.
#[cfg(test)]
mod db_tests {
    use super::*;

    #[tokio::test]
    async fn a_claimed_name_is_shared_kept_typed_and_survives_the_cache() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — session rename not exercised");
            return;
        };
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("connect scratch db");
        crate::mesh_migrate::apply_baseline(&admin).await.expect("baseline");
        crate::mesh_migrate::apply(&admin).await.expect("migrations");
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect scratch db");
        // An account no other test uses, so reruns on one database never collide.
        let acct = format!("rn{}", suffix());

        let (id1, l1) = open(&db, &acct, "k:one", Some("claude-code")).await.expect("open 1");
        let (id2, l2) = open(&db, &acct, "k:one", Some("claude-code")).await.expect("open 2");
        let (_, l3) = open(&db, &acct, "k:one", Some("codex-mcp-client")).await.expect("open 3");
        assert!(l1.starts_with("claude-") && l3.starts_with("codex-"), "{l1} {l3}");

        // First claim: the name is free.
        assert_eq!(rename(&db, &acct, &l1, "general").await.unwrap(), ("claude-general".to_string(), 0));
        // Second claim of the same name joins it, and says so.
        assert_eq!(rename(&db, &acct, &l2, "general").await.unwrap(), ("claude-general".to_string(), 1));
        // Claiming the name you already hold is a no-op that still counts the others.
        assert_eq!(rename(&db, &acct, "claude-general", "claude-general").await.unwrap().1, 1);
        // The type is the session's own: codex claiming "general" is codex-general.
        assert_eq!(rename(&db, &acct, &l3, "general").await.unwrap().0, "codex-general");

        // The row is the record: a cold cache resolves to the new label.
        registry().write().unwrap().remove(&id2);
        assert_eq!(resolve(&db, &id2, "k:one").await.unwrap().label, "claude-general");
        assert_eq!(resolve(&db, &id1, "k:one").await.unwrap().label, "claude-general");

        // Refusals: an unknown session, a bad name, and another account's session.
        assert!(rename(&db, &acct, "claude-nobody", "x").await.is_err());
        assert!(rename(&db, &acct, "codex-general", "a/b").await.is_err());
        assert!(rename(&db, "someone-else", "codex-general", "x").await.is_err());
    }
}
