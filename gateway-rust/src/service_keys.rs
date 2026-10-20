// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Named service keys + audit for the external inference boundary.
//!
//! Replaced the single anonymous `NOO_SERVICE_API_KEY` env credential with
//! per-consumer named keys stored in `noo_service_keys` (sha256-hashed,
//! migration 011). That env bearer was RETIRED on 2026-08-03 — this is now
//! the only way onto the boundary, so every external request is attributable,
//! scoped, quota-able and revocable one consumer at a time. The auth layer (`auth::require_any_auth`) resolves a
//! presented bearer to a [`Consumer`] and attaches it to the request as an
//! axum extension; `/api/external/*` handlers read it for scope checks and
//! attribution. Resolution is cached in-process (5 s TTL) to avoid a DB hit
//! per request.
//!
//! Also hosts [`record_external_request`] — the writer for the
//! `noo_external_requests` audit table (migration 012).

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

/// Resolved identity of an external caller. Attached to the request as an
/// axum extension by `auth::require_any_auth`, read by `/api/external/*`
/// handlers.
#[derive(Clone, Debug)]
pub struct Consumer {
    pub name: String,
    pub scopes: Vec<String>,
    /// Per-consumer requests-per-minute cap (`noo_service_keys.rpm_limit`).
    /// `None` = uncapped (internal callers, or a named key with no limit set).
    pub rpm_limit: Option<i64>,
    /// Mesh account this key acts for (`noo_service_keys.user_id`), when the
    /// key was issued with `--user`. `None` = a machine key with no human
    /// behind it.
    ///
    /// This is the difference between "which program is calling" and "on whose
    /// behalf". `name` has always been the former; a rate-limit bucket and an
    /// audit label, not an authorisation subject. Callers that make access
    /// decisions must read THIS field — treating a `name` as an identity is
    /// how a shared credential becomes an unattributed operator.
    pub user: Option<String>,
    /// The bound account's CURRENT scopes, joined live from `noo_users` rather
    /// than copied at issue time, so narrowing a user takes effect within the
    /// cache TTL without reissuing their key. Empty when `user` is `None`.
    pub user_scopes: Vec<String>,
    /// The bound account's CURRENT role, joined live like
    /// `user_scopes` — the key's effective tier derives from this at
    /// VALIDATION time, never from anything captured at issuance (the #408
    /// bug class). `None` when `user` is `None`.
    pub user_role: Option<crate::auth::Role>,
}

impl Consumer {
    /// A consumer granted all four operations — used for internal callers
    /// (JWT subject / cluster HMAC) and the legacy env bootstrap key. Internal
    /// callers are never rate-capped per-consumer.
    pub fn all(name: &str) -> Self {
        Self {
            name: name.to_string(),
            scopes: ["chat", "embeddings", "rerank", "classify"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            rpm_limit: None,
            // Internal callers ARE the operator; there is no separate account
            // to act for. Deliberately not "the admin username" — that would
            // make this look like a bound user to anything reading `user`.
            user: None,
            user_scopes: Vec::new(),
            user_role: None,
        }
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

struct KeyInfo {
    /// `noo_service_keys.expires_at`: set on the short-lived keys a node
    /// harness mints for a foreign CLI (`mint_door_key`); `None` = no expiry.
    /// Checked on the cached path too, so a key stops at its expiry, not up
    /// to one cache TTL later.
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    consumer: String,
    scopes: Vec<String>,
    rpm_limit: Option<i64>,
    user: Option<String>,
    user_scopes: Vec<String>,
    user_role: Option<crate::auth::Role>,
}

struct Cache {
    map: HashMap<String, KeyInfo>,
    loaded: Instant,
}

static CACHE: OnceLock<RwLock<Option<Cache>>> = OnceLock::new();
/// How long a resolved-key snapshot is trusted. Short on purpose: a key
/// revoked or an account disabled by anything other than this process's own
/// handlers (direct SQL, another gateway instance) stops working within this
/// interval; the handlers here also call [`invalidate_cache`] so their own
/// changes take effect at once.
const TTL: Duration = Duration::from_secs(5);

fn cache() -> &'static RwLock<Option<Cache>> {
    CACHE.get_or_init(|| RwLock::new(None))
}

/// sha256 hex of a raw key — matches what `noo security service-key issue`
/// stores in `noo_service_keys.key_hash`.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Service-key scopes that were RETIRED, with what replaced them. A key
/// still carrying one is refused on EVERY route — `resolve` answers `None`
/// for it, exactly as for a revoked key — and `GET /api/security/service-keys`
/// marks it so `noo security service-key list` can say "retired scope —
/// revoke with …". Keys are never revoked automatically: the operator
/// decides, and the listing tells them what to run.
///
/// `kiosk`: bought display tokens at `POST /api/kiosk/token`
/// with a credential that never expired. Displays mint at
/// `/api/kiosk/token/tailnet` by tailnet proof instead; the key lane, its
/// admission and the scope's issuance are gone.
pub const RETIRED_KEY_SCOPES: &[(&str, &str)] = &[(
    crate::auth::KIOSK_SCOPE,
    "the kiosk key lane was retired — displays mint by tailnet proof (noo kiosk invite)",
)];

/// The retired scopes among `scopes`, in declaration order.
pub fn retired_scopes_in(scopes: &[String]) -> Vec<&'static str> {
    RETIRED_KEY_SCOPES
        .iter()
        .map(|(s, _)| *s)
        .filter(|r| scopes.iter().any(|s| s == r))
        .collect()
}

/// Resolve a presented bearer token to a named [`Consumer`] via
/// `noo_service_keys`. Returns `None` when no active key matches, AND when
/// the matching key carries a [`RETIRED_KEY_SCOPES`] scope — such a key
/// authenticates nothing, anywhere. Caches the active key set for [`TTL`];
/// a revoked/new key is reflected within one TTL.
pub async fn resolve(db: &PgPool, token: &str) -> Option<Consumer> {
    refuse_retired(resolve_active(db, token).await)
}

/// The retirement gate, pure so it is testable without a database.
pub(crate) fn refuse_retired(found: Option<Consumer>) -> Option<Consumer> {
    let c = found?;
    let retired = retired_scopes_in(&c.scopes);
    if retired.is_empty() {
        return Some(c);
    }
    tracing::warn!(
        consumer = %c.name,
        scopes = %retired.join(","),
        "service key refused: it carries a retired scope — revoke it with \
         `noo security service-key revoke {}`",
        c.name
    );
    None
}

async fn resolve_active(db: &PgPool, token: &str) -> Option<Consumer> {
    let hash = sha256_hex(token);

    // Fast path — fresh cache.
    if let Ok(guard) = cache().read() {
        if let Some(c) = guard.as_ref() {
            if c.loaded.elapsed() < TTL {
                return c.map.get(&hash).filter(|k| live(k.expires_at, chrono::Utc::now())).map(|k| Consumer {
                    name: k.consumer.clone(),
                    scopes: k.scopes.clone(),
                    rpm_limit: k.rpm_limit,
                    user: k.user.clone(),
                    user_scopes: k.user_scopes.clone(),
                    user_role: k.user_role,
                });
            }
        }
    }

    // Refresh from DB (active keys only).
    // LEFT JOIN, not a second query: a key whose bound account is missing or
    // disabled must resolve with user = None, never silently keep acting as
    // that user. `u.disabled = false` lives in the JOIN condition so a
    // disabled account yields NULL rather than dropping the key entirely —
    // the key still authenticates as a machine key and is visibly unbound,
    // instead of vanishing and reading as "revoked".
    #[allow(clippy::type_complexity)]
    let rows = sqlx::query_as::<_, (String, String, Value, Option<i64>, Option<String>, Option<Value>, Option<String>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT k.key_hash, k.consumer, k.scopes, k.rpm_limit, u.username, u.scopes, u.role, k.expires_at \
         FROM noo_service_keys k \
         LEFT JOIN noo_users u ON u.username = k.user_id AND u.disabled = false \
         WHERE k.active = true AND (k.expires_at IS NULL OR k.expires_at > now())",
    )
    .fetch_all(db)
    .await
    .ok()?;

    let mut map = HashMap::new();
    for (key_hash, consumer, scopes_json, rpm_limit, user, user_scopes_json, user_role_str, expires_at) in rows {
        let scopes = scopes_json
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let user_scopes = user_scopes_json
            .as_ref()
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // Fail CLOSED to the lowest tier if the row escapes the enum (the DB
        // CHECK makes this unreachable in practice); an unbound key stays
        // role-less rather than defaulting to any tier.
        let user_role = match (&user, user_role_str.as_deref()) {
            (Some(_), r) => Some(
                r.unwrap_or("user")
                    .parse::<crate::auth::Role>()
                    .unwrap_or(crate::auth::Role::User),
            ),
            (None, _) => None,
        };
        map.insert(
            key_hash,
            KeyInfo { expires_at, consumer, scopes, rpm_limit, user, user_scopes, user_role },
        );
    }

    let found = map.get(&hash).map(|k| Consumer {
        name: k.consumer.clone(),
        scopes: k.scopes.clone(),
        rpm_limit: k.rpm_limit,
        user: k.user.clone(),
        user_scopes: k.user_scopes.clone(),
        user_role: k.user_role,
    });

    if let Ok(mut guard) = cache().write() {
        *guard = Some(Cache {
            map,
            loaded: Instant::now(),
        });
    }

    // Best-effort last_used_at bump (don't block the request).
    if found.is_some() {
        let db = db.clone();
        let h = hash.clone();
        tokio::spawn(async move {
            let _ = sqlx::query(
                "UPDATE noo_service_keys SET last_used_at = NOW() WHERE key_hash = $1",
            )
            .bind(h)
            .execute(&db)
            .await;
        });
    }

    found
}

/// Whether a key with this expiry is usable at `now`.
fn live(expires_at: Option<chrono::DateTime<chrono::Utc>>, now: chrono::DateTime<chrono::Utc>) -> bool {
    expires_at.is_none_or(|e| e > now)
}

/// Requests per minute an MCP-door consumer gets when its key carries no
/// `rpm_limit` of its own. The doors' tool calls are self-calls over
/// loopback, which the coarse per-IP limiter skips, so the per-consumer
/// quota is the only brake on tool fan-out: a key with no cap is not left
/// unmetered here. `service-key set-quota` raises or lowers a key's own
/// figure; `set-quota <c> 0` ("uncapped") still means uncapped on
/// `/api/external` but falls back to this on the MCP doors.
pub const MCP_DOOR_DEFAULT_RPM: i64 = 600;

/// The cap the MCP doors enforce for `c`: its own, else
/// [`MCP_DOOR_DEFAULT_RPM`]. Always positive.
pub fn door_rpm(c: &Consumer) -> i64 {
    c.rpm_limit.filter(|n| *n > 0).unwrap_or(MCP_DOOR_DEFAULT_RPM)
}

/// Process-local per-consumer minute counter: the MCP doors' answer when
/// Redis is absent or erroring, so "no Redis" tightens the quota to a
/// per-process one instead of removing it (the rate limiter's precedent).
/// `Some(retry_after_secs)` when `name` is over `limit` this minute.
pub fn local_quota_exceeded(name: &str, limit: i64) -> Option<i64> {
    static W: OnceLock<std::sync::Mutex<HashMap<String, (Instant, i64)>>> = OnceLock::new();
    let mut m = W.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    if m.len() > 4096 {
        m.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
    }
    let e = m.entry(name.to_string()).or_insert((now, 0));
    if now.duration_since(e.0) >= Duration::from_secs(60) {
        *e = (now, 0);
    }
    e.1 += 1;
    (e.1 > limit).then(|| 60 - now.duration_since(e.0).as_secs() as i64)
}

/// Drop the resolved-key cache, so the next `resolve` reads the table: a
/// revocation takes effect at once instead of up to one TTL later.
pub fn invalidate_cache() {
    if let Ok(mut guard) = cache().write() {
        *guard = None;
    }
}

/// The consumer-name prefix of a key minted for a node harness's foreign
/// CLI. Only such rows are revoked by [`revoke_door_key`] and swept by
/// [`mint_door_key`]; a person's own keys are never touched by either.
pub const DOOR_KEY_CONSUMER_PREFIX: &str = "harness:";

/// The consumer name of a door key: `harness:<node>:<first 8 of the
/// conversation>`. It is also where the door's connection label comes from
/// (`auth::connection_label`), so the CLI is a connection of its own,
/// distinguishable from the person's other clients.
pub fn door_key_consumer(node: &str, conversation_id: &str) -> String {
    let conv: String = conversation_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    format!("{DOOR_KEY_CONSUMER_PREFIX}{node}:{conv}")
}

/// A minted door key: the raw key (shown once), its row id, its expiry.
pub struct DoorKey {
    pub key: String,
    pub id: uuid::Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Mint the short-lived user-door key a node harness hands its foreign CLI:
/// an ordinary `noo_service_keys` row with scope `mcp`, bound to `user`,
/// expiring after `ttl_secs`. Ordinary on purpose: `/mcp/user` admits it
/// through the same `resolve` → `admit` path as any key the person minted
/// for themselves, so the tier is the account's live role and every call is
/// attributed to the person. Expired harness rows are deleted first, so the
/// table does not grow by a row per loop.
pub async fn mint_door_key(db: &PgPool, user: &str, consumer: &str, ttl_secs: u64) -> anyhow::Result<DoorKey> {
    let _ = sqlx::query("DELETE FROM noo_service_keys WHERE consumer LIKE $1 AND expires_at IS NOT NULL AND expires_at < now()")
        .bind(format!("{DOOR_KEY_CONSUMER_PREFIX}%"))
        .execute(db)
        .await;
    let key = {
        use base64::Engine;
        use rand::Rng;
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        format!("noo-sk-{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    };
    let id = uuid::Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs.min(i64::MAX as u64) as i64);
    sqlx::query(
        "INSERT INTO noo_service_keys (id, consumer, key_hash, scopes, note, user_id, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(consumer)
    .bind(sha256_hex(&key))
    .bind(serde_json::json!(["mcp"]))
    .bind("node harness: a foreign CLI's door key, expires with its turn")
    .bind(user)
    .bind(expires_at)
    .execute(db)
    .await?;
    invalidate_cache();
    Ok(DoorKey { key, id, expires_at })
}

/// Revoke a door key `mint_door_key` minted for `user`. Never touches a key
/// that is not a harness key or not that person's. `true` = a row changed.
pub async fn revoke_door_key(db: &PgPool, id: &str, user: &str) -> anyhow::Result<bool> {
    let id = uuid::Uuid::parse_str(id)?;
    let n = sqlx::query(
        "UPDATE noo_service_keys SET active = false WHERE id = $1 AND user_id = $2 AND consumer LIKE $3 AND active = true",
    )
    .bind(id)
    .bind(user)
    .bind(format!("{DOOR_KEY_CONSUMER_PREFIX}%"))
    .execute(db)
    .await?
    .rows_affected();
    invalidate_cache();
    Ok(n > 0)
}

/// One `noo_external_requests` row, as [`record_external_request`] takes it
/// and `audit_spool` holds it while the database is away.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalRequestRow {
    pub id: uuid::Uuid,
    /// When the request happened, so a row written after a database outage
    /// keeps its own time rather than the column default (now).
    pub ts: chrono::DateTime<chrono::Utc>,
    pub consumer: String,
    pub endpoint: &'static str,
    pub kind: Option<String>,
    pub model: Option<String>,
    pub backend: Option<String>,
    pub units: Option<Value>,
    pub status: u16,
    pub latency_ms: i64,
    pub trace_id: Option<String>,
    pub error: Option<String>,
}

/// Insert one audit/usage row into `noo_external_requests`. Designed to be
/// `tokio::spawn`-ed so it never blocks the response. A row the database
/// cannot take because it is away is held by `audit_spool` and written when
/// it answers; the row's `id` is fixed here, so a retry cannot duplicate it.
#[allow(clippy::too_many_arguments)]
pub async fn record_external_request(
    db: PgPool,
    consumer: String,
    endpoint: &'static str,
    kind: Option<String>,
    model: Option<String>,
    backend: Option<String>,
    units: Option<Value>,
    status: u16,
    latency_ms: i64,
    trace_id: Option<String>,
    error: Option<String>,
) {
    let row = ExternalRequestRow {
        id: uuid::Uuid::new_v4(),
        ts: chrono::Utc::now(),
        consumer, endpoint, kind, model, backend, units, status, latency_ms, trace_id, error,
    };
    if insert_external_request(&db, &row).await == crate::audit_spool::Outcome::Transient {
        if crate::audit_spool::enqueue(crate::audit_spool::Pending::External(row)) {
            tracing::warn!("external audit insert queued: the database is away; the row is held and will be written when it answers");
        } else {
            tracing::error!("external audit insert LOST: the database is away and the audit queue is full");
        }
    }
}

/// Write one [`ExternalRequestRow`]. `Lost` is logged and counted here; a
/// `Transient` outcome is the caller's to queue.
pub(crate) async fn insert_external_request(db: &PgPool, r: &ExternalRequestRow) -> crate::audit_spool::Outcome {
    let res = sqlx::query(
        "INSERT INTO noo_external_requests \
           (id, ts, consumer, endpoint, kind, model, backend, units, status_code, latency_ms, trace_id, error) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(r.id)
    .bind(r.ts)
    .bind(&r.consumer)
    .bind(r.endpoint)
    .bind(&r.kind)
    .bind(&r.model)
    .bind(&r.backend)
    .bind(&r.units)
    .bind(r.status as i32)
    .bind(r.latency_ms as i32)
    .bind(&r.trace_id)
    .bind(&r.error)
    .execute(db)
    .await;
    match res {
        Ok(_) => crate::audit_spool::Outcome::Landed,
        Err(e) if crate::audit_spool::is_transient(&e) => crate::audit_spool::Outcome::Transient,
        Err(e) => {
            tracing::warn!("external audit insert failed: {e}");
            crate::audit_spool::note_lost();
            crate::audit_spool::Outcome::Lost
        }
    }
}

#[cfg(test)]
mod door_key_tests {
    use super::*;

    #[test]
    fn an_expired_key_is_dead_and_an_unexpiring_one_lives() {
        let now = chrono::Utc::now();
        assert!(live(None, now));
        assert!(live(Some(now + chrono::Duration::seconds(5)), now));
        assert!(!live(Some(now), now));
        assert!(!live(Some(now - chrono::Duration::seconds(1)), now));
    }

    #[test]
    fn a_door_key_consumer_is_a_harness_name_and_yields_a_connection_label() {
        let c = door_key_consumer("awolf", "3f2a9c10-aaaa-bbbb");
        assert_eq!(c, "harness:awolf:3f2a9c10");
        assert!(c.starts_with(DOOR_KEY_CONSUMER_PREFIX));
        assert_eq!(crate::auth::connection_label(&c).as_deref(), Some("harness-awolf-3f2a9c10"));
    }
}

#[cfg(test)]
mod retired_scope_tests {
    use super::*;

    fn key(scopes: &[&str]) -> Consumer {
        Consumer {
            name: "kiosk-hall".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            rpm_limit: Some(60),
            user: None,
            user_scopes: Vec::new(),
            user_role: None,
        }
    }

    /// A kiosk-scoped key — the retired key lane's credential — resolves to
    /// nothing, so every route that authenticates a service key refuses it.
    /// Mixed with a live scope it is still refused: the key was minted for
    /// the lane, and half-honouring it would keep it alive.
    #[test]
    fn a_kiosk_scoped_key_is_refused_everywhere() {
        assert!(refuse_retired(Some(key(&[crate::auth::KIOSK_SCOPE]))).is_none());
        assert!(refuse_retired(Some(key(&["chat", crate::auth::KIOSK_SCOPE]))).is_none());
        assert!(refuse_retired(Some(key(&["chat"]))).is_some());
        assert!(refuse_retired(None).is_none());
    }

    #[test]
    fn retired_scopes_are_named_in_declaration_order() {
        let s: Vec<String> = vec!["chat".into(), "kiosk".into()];
        assert_eq!(retired_scopes_in(&s), vec!["kiosk"]);
        assert!(retired_scopes_in(&["mcp".to_string()]).is_empty());
    }
}

#[cfg(test)]
mod door_quota_tests {
    use super::*;

    fn c(rpm: Option<i64>) -> Consumer {
        Consumer {
            name: "self:alice".into(),
            scopes: vec!["mcp".into()],
            rpm_limit: rpm,
            user: Some("alice".into()),
            user_scopes: vec![],
            user_role: Some(crate::auth::Role::User),
        }
    }

    #[test]
    fn a_key_without_a_cap_gets_the_door_default_not_an_unbounded_budget() {
        assert_eq!(door_rpm(&c(None)), MCP_DOOR_DEFAULT_RPM);
        assert_eq!(door_rpm(&c(Some(0))), MCP_DOOR_DEFAULT_RPM);
        assert_eq!(door_rpm(&c(Some(-3))), MCP_DOOR_DEFAULT_RPM);
        assert_eq!(door_rpm(&c(Some(120))), 120);
    }

    #[test]
    fn the_process_local_meter_refuses_past_the_limit() {
        let name = "door-quota-test-consumer";
        for i in 1..=3 {
            assert!(local_quota_exceeded(name, 3).is_none(), "request {i} is within the cap");
        }
        let retry = local_quota_exceeded(name, 3).expect("4th request in the minute is refused");
        assert!((1..=60).contains(&retry));
        assert!(local_quota_exceeded("another-consumer", 3).is_none(), "buckets are per consumer");
    }

    #[test]
    fn the_cache_interval_is_short() {
        assert!(TTL <= Duration::from_secs(5));
    }
}
