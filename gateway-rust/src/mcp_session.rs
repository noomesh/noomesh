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
//! The id is 128 random bits. It distinguishes sessions; it does **not**
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
    /// The connection label this session mints under:
    /// `<label from the key>-<short suffix>`, a valid name segment.
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

/// A fresh, unguessable session id.
fn new_id() -> String {
    use rand::Rng;
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b64url(&b)
}

/// The short suffix that tells two sessions of one key apart. Lowercase
/// alphanumerics so the label stays inside the name class.
fn suffix() -> String {
    use rand::RngExt;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut r = rand::rng();
    (0..6).map(|_| ALPHABET[r.random_range(0..ALPHABET.len())] as char).collect()
}

/// Build the label a session mints under: the key's label plus a suffix,
/// capped so the whole thing remains one valid segment.
pub fn session_label(consumer: &str) -> Option<String> {
    let base = crate::auth::connection_label(consumer)?;
    let base: String = base.chars().take(120).collect();
    let label = format!("{base}-{}", suffix());
    if crate::auth::valid_name_segment(&label) { Some(label) } else { None }
}

/// Open a session for `account` via `consumer`. `None` when the consumer
/// name yields no usable label — the caller then falls back to the
/// per-key path exactly as it would without a session.
pub fn open_local(account: &str, consumer: &str) -> Option<(String, String)> {
    let label = session_label(consumer)?;
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
    let Some(id) = headers.get(HEADER).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty()) else {
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
    let (id, label) = open_local(account, consumer)?;
    let display: Option<String> = display_name
        .map(str::trim)
        .filter(|d| !d.is_empty() && d.chars().count() <= 64 && !d.chars().any(char::is_control))
        .map(str::to_string);
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

/// Live session count, for `/health`-style reporting and tests.
pub fn live() -> usize {
    registry().read().map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_is_a_valid_connection_under_its_account() {
        let (id, label) = open_local("owner", "self:owner").expect("open");
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
        let (a, la) = open_local("owner", "self:owner").unwrap();
        let (b, lb) = open_local("owner", "self:owner").unwrap();
        assert_ne!(a, b);
        assert_ne!(la, lb);
        assert_eq!(resolve_local(&a, "self:owner").unwrap().label, la);
        assert_eq!(resolve_local(&b, "self:owner").unwrap().label, lb);
    }

    /// Provenance that can be transferred is not provenance.
    #[test]
    fn a_session_answers_only_to_the_key_that_opened_it() {
        let (id, _) = open_local("owner", "self:owner").unwrap();
        assert_eq!(resolve_local(&id, "other-key").unwrap_err(), Refusal::WrongConsumer);
        assert!(resolve_local(&id, "self:owner").is_ok(), "…and still works for the right one");
        assert_eq!(resolve_local("not-a-session", "self:owner").unwrap_err(), Refusal::Unknown);
    }

    #[test]
    fn a_consumer_with_no_label_opens_no_session() {
        assert!(open_local("owner", ":::").is_none());
    }

    #[test]
    fn an_idle_session_expires_and_is_removed() {
        let (id, _) = open_local("owner", "self:owner").unwrap();
        {
            let mut map = registry().write().unwrap();
            map.get_mut(&id).unwrap().last_seen = Instant::now() - IDLE_TTL - Duration::from_secs(1);
        }
        assert_eq!(resolve_local(&id, "self:owner").unwrap_err(), Refusal::Expired);
        assert_eq!(resolve_local(&id, "self:owner").unwrap_err(), Refusal::Unknown, "removed, not merely refused");
    }
}
