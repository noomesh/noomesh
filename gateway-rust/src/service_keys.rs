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
//! attribution. Resolution is cached in-process (60s TTL) to avoid a DB hit
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
const TTL: Duration = Duration::from_secs(60);

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
                return c.map.get(&hash).map(|k| Consumer {
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
    let rows = sqlx::query_as::<_, (String, String, Value, Option<i64>, Option<String>, Option<Value>, Option<String>)>(
        "SELECT k.key_hash, k.consumer, k.scopes, k.rpm_limit, u.username, u.scopes, u.role \
         FROM noo_service_keys k \
         LEFT JOIN noo_users u ON u.username = k.user_id AND u.disabled = false \
         WHERE k.active = true",
    )
    .fetch_all(db)
    .await
    .ok()?;

    let mut map = HashMap::new();
    for (key_hash, consumer, scopes_json, rpm_limit, user, user_scopes_json, user_role_str) in rows {
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
            KeyInfo { consumer, scopes, rpm_limit, user, user_scopes, user_role },
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

/// Insert one audit/usage row into `noo_external_requests`. Designed to be
/// `tokio::spawn`-ed so it never blocks the response.
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
    let res = sqlx::query(
        "INSERT INTO noo_external_requests \
           (id, consumer, endpoint, kind, model, backend, units, status_code, latency_ms, trace_id, error) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(consumer)
    .bind(endpoint)
    .bind(kind)
    .bind(model)
    .bind(backend)
    .bind(units)
    .bind(status as i32)
    .bind(latency_ms as i32)
    .bind(trace_id)
    .bind(error)
    .execute(&db)
    .await;
    if let Err(e) = res {
        tracing::warn!("external audit insert failed: {e}");
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
