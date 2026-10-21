// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Core routes — health, metrics, auth.

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
    extract::State,
    response::{IntoResponse, Response},
    http::{self, StatusCode},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;
use crate::auth::{verify_token, jwt_secret};
use crate::auth_refresh;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(prometheus_metrics))
        .route("/auth/token", post(auth_token))
        // Two paths for the refresh + logout endpoints — `/auth/...` for
        // the existing convention, `/api/auth/...` for the dashboard's
        // base path. Same handler.
        .route("/auth/refresh", post(auth_refresh_handler))
        .route("/api/auth/refresh", post(auth_refresh_handler))
        .route("/auth/logout", post(auth_logout_handler))
        .route("/api/auth/logout", post(auth_logout_handler))
        .route("/auth/me", get(auth_me))
}

// ═══════════════════════════════════════════════════════════════
// Native handlers — Auth
// ═══════════════════════════════════════════════════════════════

/// Access-token expiry in minutes. Default short (15 min) since the
/// dashboard rotates via the httponly refresh cookie. Override via
/// `NOO_TOKEN_EXPIRE_MINUTES`.
fn token_expire_minutes() -> i64 {
    auth_refresh::default_access_minutes()
}

/// True when the SESSION is HTTPS — controls the `Secure` flag on the
/// refresh cookie.
///
/// The gateway's own certificate is one way to be sure; the other is
/// sitting behind a TLS-terminating proxy, where the gateway itself
/// speaks plain HTTP and would otherwise issue the cookie without
/// `Secure`. `SameSite=Strict` + the `/api/auth` path
/// still block CSRF either way; this is about transport exposure.
/// `NOO_BEHIND_TLS_PROXY=1` declares that deployment shape.
fn is_secure() -> bool {
    let own_tls = std::env::var("NOO_TLS_CERT").map(|s| !s.is_empty()).unwrap_or(false);
    let proxied = matches!(
        std::env::var("NOO_BEHIND_TLS_PROXY").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    );
    own_tls || proxied
}

/// The scopes a token carries during the dual-accept window:
/// the legacy tier scopes DERIVED from the role — the role column is the
/// source of truth, stored scopes are never copied verbatim — plus any
/// non-tier scopes (`ingest`, `peer`) the account holds, which are additive
/// capabilities outside the role cascade and would otherwise be silently
/// revoked (ingest) or, worse, un-confined (peer) by the derivation.
fn dual_emit_scopes(role: crate::auth::Role, stored_scopes: &[String]) -> Vec<String> {
    let mut scopes: Vec<String> =
        role.legacy_scopes().iter().map(|s| s.to_string()).collect();
    for s in stored_scopes {
        if !matches!(s.as_str(), "read" | "write" | "admin") && !scopes.contains(s) {
            scopes.push(s.clone());
        }
    }
    scopes
}

/// Issue a JWT access token for an authenticated user. Returns
/// (token, expires_in_seconds).
///
/// Dual-emit: the token carries BOTH the `role` claim and the
/// legacy `scopes` derived from it, so old and new validators agree for the
/// one-release dual-accept window.
/// Why a token could not be issued. Split from the raw jsonwebtoken error so
/// the caller can answer 503 ("this gateway has no usable JWT secret") rather
/// than 500 ("something went wrong encoding") — .
#[derive(Debug)]
enum TokenIssueError {
    /// `NOO_JWT_SECRET` is unset or the public development placeholder.
    InsecureSecret,
    Encode(jsonwebtoken::errors::Error),
}

fn issue_access_token(user: &UserRecord) -> Result<(String, i64), TokenIssueError> {
    let expire_minutes = token_expire_minutes();
    let now = chrono::Utc::now();
    let expire_secs = expire_minutes * 60;
    let exp = now + chrono::TimeDelta::seconds(expire_secs);

    let claims = serde_json::json!({
        "sub": user.username,
        "role": user.role.as_str(),
        "scopes": dual_emit_scopes(user.role, &user.scopes),
        "exp": exp.timestamp(),
        "iat": now.timestamp(),
        // Millisecond mint time: the session floor (`session_floor.rs`) is in
        // ms, so a token minted in the same second as a logout is ordered
        // against it correctly. Person sessions only; delegated tokens keep
        // their exact claim sets.
        "iat_ms": now.timestamp_millis(),
        "iss": crate::auth::JWT_ISSUER,
        "aud": crate::auth::JWT_AUDIENCE,
    });

    let secret = jwt_secret();
    // the middleware has refused bearer JWTs signed with the insecure
    // default since H-A2 (`jwt_secret_is_insecure`), but MINTING still used
    // it — so a fresh install handed out tokens anyone could forge and the
    // holder only found out when every request 401'd. Same predicate, same
    // answer, one release earlier in the lifecycle: no secret, no token.
    if crate::auth::jwt_secret_is_insecure(&secret) {
        return Err(TokenIssueError::InsecureSecret);
    }
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(secret.as_bytes());
    let token = jsonwebtoken::encode(&header, &claims, &key)
        .map_err(TokenIssueError::Encode)?;
    Ok((token, expire_secs))
}

/// The HTTP answer for a failed mint. One helper, two call sites, so the two
/// token-issuing paths cannot drift on this.
fn token_issue_response(e: TokenIssueError, context: &str) -> Response {
    match e {
        TokenIssueError::InsecureSecret => {
            tracing::error!(
                context = %context,
                "refusing to mint an access token: NOO_JWT_SECRET is unset or the \
                 insecure default. Set it (noo security secrets …) and restart."
            );
            (StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail": "Auth not configured"}))).into_response()
        }
        TokenIssueError::Encode(err) => {
            tracing::error!(error = %err, context = %context, "JWT encoding failed");
            (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail": "Token generation failed"}))).into_response()
        }
    }
}

/// Best-effort UA / IP extraction for the audit columns.
///
/// Forwarding headers are honoured ONLY when the direct peer is a trusted
/// proxy, exactly as the rate limiter does. Without that check a brute
/// forcer chooses the source IP written into `noo_security_audit` and the
/// refresh-token rows — the one place the record has to be trustworthy
/// No peer (a caller that did not carry ConnectInfo)
/// means the headers are not trusted either.
fn extract_client_meta(
    headers: &http::HeaderMap,
    peer: Option<&str>,
) -> (Option<String>, Option<String>) {
    let ua = headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(256).collect());
    let trusted = peer.map(crate::middleware::is_trusted_proxy).unwrap_or(false);
    let forwarded = if trusted {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            // Rightmost untrusted entry, the same rule as the rate limiter:
            // the leftmost is whatever the client chose to send.
            .and_then(crate::middleware::forwarded_client)
            .or_else(|| {
                headers
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
    } else {
        None
    };
    (ua, forwarded.or_else(|| peer.map(str::to_string)))
}

// ═══════════════════════════════════════════════════════════════
// /auth/token abuse controls
// ═══════════════════════════════════════════════════════════════
//
// The global limiter in `middleware::rate_limit` is 600 requests/min/IP and
// knows nothing about what a request costs. On `/auth/token` that is 600
// bcrypt verifies a minute from one address, and — because `record_failed_login`
// locks an account for 15 minutes after 5 failures — five of those requests
// lock any account the attacker can name, including the admin. So this
// surface gets its own, much smaller buckets, on two keys:
//
//   * per client IP   — caps credential stuffing from one source;
//   * per username    — caps the lockout DoS, and is the ONLY control on the
//     env bootstrap admin, which has no `noo_users` row to lock.
//
// Redis-backed (`check_named_limit`) with a process-local fallback, matching
// `middleware::fallback_allow`: a Redis outage must tighten the control, not
// remove it. Both are best-effort *counters*; the authorization decision is
// still bcrypt.

/// Login attempts allowed per minute from one client IP.
const LOGIN_IP_LIMIT: i64 = 20;
/// Login attempts allowed per minute for one username, from anywhere.
const LOGIN_USER_LIMIT: i64 = 10;
const LOGIN_WINDOW_SECS: i64 = 60;

/// Process-local fallback buckets, used when Redis is absent or erroring —
/// so a Redis outage tightens this control rather than removing it (the same
/// stance as `middleware::fallback_allow`).
///
/// `consume` distinguishes the two uses: the rate buckets spend one unit per
/// attempt, while the bootstrap-failure GATE only reads the count (a correct
/// password must not spend the failure budget).
fn local_login_bucket(key: &str, consume: bool) -> u32 {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static BUCKETS: OnceLock<Mutex<HashMap<String, (Instant, u32)>>> = OnceLock::new();
    let m = BUCKETS.get_or_init(|| Mutex::new(HashMap::new()));
    let window = Duration::from_secs(LOGIN_WINDOW_SECS as u64);
    let now = Instant::now();
    let mut map = match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if map.len() > 10_000 {
        map.retain(|_, (start, _)| now.duration_since(*start) <= window);
    }
    let entry = map.entry(key.to_string()).or_insert((now, 0));
    if now.duration_since(entry.0) > window {
        *entry = (now, 0);
    }
    if consume {
        entry.1 += 1;
    }
    entry.1
}

/// One bucket. `true` = allowed.
async fn login_bucket_allows(
    state: &AppState,
    ns: &str,
    subject: &str,
    limit: i64,
) -> bool {
    if let Some(redis) = state.redis.as_ref() {
        match redis
            .check_named_limit(ns, subject, limit, LOGIN_WINDOW_SECS)
            .await
        {
            Ok(crate::cache::RateResult::Allowed { .. }) => return true,
            Ok(crate::cache::RateResult::Limited { .. }) => return false,
            Err(e) => {
                tracing::warn!(error = %e, ns, "login_limiter_degraded_using_local_buckets");
            }
        }
    }
    local_login_bucket(&format!("{ns}:{subject}"), true) <= limit as u32
}

/// Refuse the login outright when either bucket is exhausted.
///
/// Returns the 429 to send, or `None` to continue. Note the username bucket
/// is consumed for EVERY attempt, existing account or not — an attacker must
/// not be able to probe for free by naming accounts that do not exist.
async fn login_rate_refusal(
    state: &AppState,
    username: &str,
    ip: Option<&str>,
) -> Option<Response> {
    let user_key = username.trim().to_lowercase();
    let ip_ok = match ip {
        Some(ip) => login_bucket_allows(state, "login-ip", ip, LOGIN_IP_LIMIT).await,
        // No ConnectInfo: there is no IP to key on, so only the username
        // bucket applies. Not a bypass — the username bucket still binds.
        None => true,
    };
    let user_ok = login_bucket_allows(state, "login-user", &user_key, LOGIN_USER_LIMIT).await;
    if ip_ok && user_ok {
        return None;
    }
    tracing::warn!(
        user = %user_key,
        ip = %ip.unwrap_or("-"),
        ip_ok,
        user_ok,
        "auth_token_rate_limited"
    );
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "detail": "Too many login attempts — try again shortly",
            "retry_after": LOGIN_WINDOW_SECS,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        "Retry-After",
        LOGIN_WINDOW_SECS
            .to_string()
            .parse()
            .unwrap_or_else(|_| http::HeaderValue::from_static("60")),
    );
    Some(response)
}

/// Failed bootstrap-admin logins tolerated per [`LOGIN_WINDOW_SECS`] window.
/// Matches the five-strike rule `record_failed_login` applies to real rows.
const BOOTSTRAP_FAILURE_LIMIT: i64 = 5;

/// `true` while the env bootstrap admin still has failures left in this
/// window. Peeks WITHOUT consuming: a correct password must not be penalised
/// for a previous attacker's failures beyond the threshold itself.
async fn bootstrap_failures_remaining(state: &AppState, username: &str) -> bool {
    let key = username.trim().to_lowercase();
    if let Some(redis) = state.redis.as_ref() {
        match redis.get_string(&format!("noo:nl:login-fail:{key}")).await {
            Some(raw) => {
                if let Ok(n) = raw.parse::<i64>() {
                    return n < BOOTSTRAP_FAILURE_LIMIT;
                }
            }
            // No key = no failures recorded in this window.
            None => return true,
        }
    }
    // No Redis (or an unparseable value): read the local bucket the failure
    // path writes, so the gate still exists in degraded mode instead of
    // silently reopening.
    (local_login_bucket(&format!("login-fail:{key}"), false) as i64) < BOOTSTRAP_FAILURE_LIMIT
}

/// A bcrypt hash of a value nobody knows, verified against when the named
/// account does not exist.
///
/// Without it `/auth/token` returned in microseconds for an unknown user and
/// in ~100ms for a known one, which is a free account-enumeration oracle over
/// an endpoint that is public by necessity. Computed once per process.
fn decoy_hash() -> &'static str {
    static DECOY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DECOY.get_or_init(|| {
        use rand::Rng;
        let mut b = [0u8; 32];
        rand::rng().fill_bytes(&mut b);
        bcrypt::hash(hex::encode(b), bcrypt::DEFAULT_COST)
            .unwrap_or_else(|_| "$2b$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin".into())
    })
}

#[derive(Deserialize)]
struct TokenRequest {
    username: String,
    password: String,
    /// Absent, or `password` (the OAuth2 form sends it): a password login.
    /// [`HOST_TICKET_GRANT`]: `password` carries a one-time host ticket.
    #[serde(default)]
    grant_type: Option<String>,
}

/// `grant_type` for a one-time login ticket minted on the controller host
/// (`noo_host_login_tickets`, migration 081). The ticket travels in the
/// `password` field, so the request shape is the ordinary login's.
pub(crate) const HOST_TICKET_GRANT: &str = "host_ticket";

/// POST /auth/token — Issue JWT token.
///
/// Validates username/password against:
///   1. DB-backed `noo_users` table (with account lockout)
///   2. The **bootstrap** env admin (`NOO_ADMIN_USER` / `NOO_ADMIN_PASSWORD`),
///      which is only consulted while `noo_users` holds no enabled admin —
///      see [`lookup_user_bootstrap_env`]. A successful bootstrap login seeds
///      the real row, which closes the door behind it.
///
/// If the user lookup itself FAILS (Postgres unreachable) this returns 503
/// and never reaches step 2: "unreachable" is not "absent", and letting an
/// outage re-open a standing admin credential turns downtime into privilege
/// escalation. With the DB down neither lockout nor audit works either, so
/// there is nothing safe to authenticate against.
///
/// With `grant_type=host_ticket` the `password` field is a one-time ticket
/// minted on the controller host instead ([`host_ticket_login`]): the
/// onboard wizard with no password to hand, and a lost-password recovery.
///
/// Returns a JWT with `sub`, `scopes`, `exp`, `iat` claims.
async fn auth_token(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: http::HeaderMap,
    // Accept both JSON and form-urlencoded (OAuth2 form)
    body: axum::body::Bytes,
) -> Response {
    // Parse as form-urlencoded first (OAuth2 standard), fall back to JSON
    let creds: TokenRequest = if let Ok(form) = serde_urlencoded::from_bytes::<TokenRequest>(&body) {
        form
    } else if let Ok(json_body) = serde_json::from_slice::<TokenRequest>(&body) {
        json_body
    } else {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"detail": "Invalid request body"}))).into_response();
    };

    // Client IP for audit attribution (brute-force / credential-stuffing).
    let peer_ip = peer.map(|axum::Extension(axum::extract::ConnectInfo(a))| a.ip().to_string());
    let (ua, ip) = extract_client_meta(&headers, peer_ip.as_deref());

    // per-IP AND per-username buckets, consumed before any DB work or
    // bcrypt. Keyed on the same `ip` the audit rows use — which is the
    // socket peer unless a TRUSTED proxy forwarded it, so the key is not
    // attacker-chosen.
    if let Some(refusal) = login_rate_refusal(&state, &creds.username, ip.as_deref()).await {
        return refusal;
    }

    // Any other `grant_type` (absent, `password`, or a value an OAuth2
    // client sends by habit) is the password login, as it always was.
    if creds.grant_type.as_deref().map(str::trim) == Some(HOST_TICKET_GRANT) {
        return host_ticket_login(&state, &creds.username, &creds.password, ua.as_deref(), ip.as_deref()).await;
    }

    // 1. Try DB user lookup. A lookup ERROR is fatal to the request — it
    //    must not fall through to the bootstrap credential.
    let db_user = match lookup_user_db(&state.db, &creds.username).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(
                error = %e,
                user = %creds.username,
                "auth_user_lookup_failed_refusing_login"
            );
            return (StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail": "Auth backend unavailable"}))).into_response();
        }
    };

    // 2. Bootstrap env admin — gated on there being no enabled admin yet.
    let mut used_bootstrap = false;
    let user = match db_user {
        Some(u) => Some(u),
        None => {
            let u = lookup_user_bootstrap_env(&state.db, &creds.username).await;
            used_bootstrap = u.is_some();
            u
        }
    };

    let user = match user {
        Some(u) => u,
        None => {
            // verify against a decoy hash so an unknown username costs
            // the same wall-clock time as a known one. Without this the
            // endpoint answers "does this account exist?" for free.
            let _ = bcrypt::verify(&creds.password, decoy_hash());
            audit_auth(&state.db, "auth_failure", &creds.username, "user_not_found", ip.as_deref()).await;
            return (StatusCode::UNAUTHORIZED,
                Json(json!({
                    "detail": "Incorrect username or password",
                }))).into_response();
        }
    };

    // Check disabled / locked
    if user.disabled {
        audit_auth(&state.db, "auth_failure", &creds.username, "account_locked", ip.as_deref()).await;
        return (StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "Incorrect username or password"}))).into_response();
    }

    // the bootstrap admin's lockout. Checked here rather than at the top
    // because `used_bootstrap` is only known after the lookup — and it must
    // be checked BEFORE bcrypt, or the brake is only a log line.
    if used_bootstrap
        && !bootstrap_failures_remaining(&state, &creds.username).await
    {
        tracing::warn!(
            user = %creds.username,
            "bootstrap_admin_login_locked_too_many_failures"
        );
        audit_auth(&state.db, "auth_failure", &creds.username, "account_locked", ip.as_deref()).await;
        return (StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"detail": "Too many login attempts — try again shortly"}))).into_response();
    }

    // Verify password (bcrypt). A malformed stored hash is a FAILED login
    // and an operator alert, never a plaintext string compare: the old
    // fallback turned a storage mistake (a row written unhashed by a manual
    // insert or an old script) into an authentication bypass, in
    // non-constant time.
    let password_ok = match bcrypt::verify(&creds.password, &user.hashed_password) {
        Ok(valid) => valid,
        Err(e) => {
            tracing::error!(
                username = %creds.username,
                error = %e,
                "stored password hash is not a valid bcrypt hash — refusing the login; reset it with `noo security user set-password <username>`"
            );
            false
        }
    };

    if !password_ok {
        audit_auth(&state.db, "auth_failure", &creds.username, "bad_password", ip.as_deref()).await;
        // `record_failed_login` is an UPDATE on `noo_users`, so it is a
        // no-op for the env bootstrap admin — that identity had NO failure
        // counting and NO lockout of any kind while no row existed. Count its
        // failures in the shared bucket instead, so the one credential that
        // is guessable from the outside is not the one with no brake. The
        // bucket is consumed on failure only; a correct password is free.
        if used_bootstrap {
            let _ = login_bucket_allows(
                &state,
                "login-fail",
                &creds.username.trim().to_lowercase(),
                BOOTSTRAP_FAILURE_LIMIT,
            )
            .await;
        }
        record_failed_login(&state.db, &creds.username).await;
        return (StatusCode::UNAUTHORIZED,
            Json(json!({
                "detail": "Incorrect username or password",
            }))).into_response();
    }

    // Success — issue JWT (access) + refresh cookie.
    audit_auth(&state.db, "auth_success", &creds.username, "ok", ip.as_deref()).await;
    record_successful_login(&state.db, &creds.username).await;

    // Bootstrap self-close: the first successful env-admin login materialises
    // a real `noo_users` row. From the next login on, the account is
    // DB-governed (lockout, `disabled`, scope edits, password change) and
    // `lookup_user_bootstrap_env` refuses because an enabled admin now
    // exists. The env var may then be removed at leisure.
    if used_bootstrap {
        seed_bootstrap_admin(&state.db, &user).await;
    }

    issue_login(&state, &user, ua.as_deref(), ip.as_deref()).await
}

/// The login answer: an access token, and a refresh token stored and set
/// as the cookie. Shared by the password login and the host ticket.
async fn issue_login(state: &AppState, user: &UserRecord, ua: Option<&str>, ip: Option<&str>) -> Response {
    let (access_token, expires_in) = match issue_access_token(user) {
        Ok(t) => t,
        Err(e) => return token_issue_response(e, "auth_token"),
    };

    // Issue + persist a refresh token. If storage fails, fall back to
    // returning just the access token (caller can still operate, just
    // re-prompts at the access-token TTL).
    let raw_refresh = auth_refresh::generate_raw_token();
    let refresh_ttl_days = auth_refresh::refresh_ttl_days();
    let refresh_expires_at = chrono::Utc::now()
        + chrono::TimeDelta::days(refresh_ttl_days);
    let stored = auth_refresh::store_token(
        &state.db,
        &user.username,
        &raw_refresh,
        refresh_expires_at,
        ua,
        ip,
        None, // fresh login, no rotation chain
    )
    .await;
    if let Err(e) = &stored {
        tracing::warn!(error = %e, "refresh_token_store_failed_returning_access_only");
        return Json(json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": expires_in,
        })).into_response();
    }

    // Build the Set-Cookie header for the refresh.
    let cookie = auth_refresh::build_refresh_cookie(&raw_refresh, is_secure(), refresh_ttl_days);
    let jar = CookieJar::new().add(cookie);

    (
        jar,
        Json(json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": expires_in,
            "refresh_ttl_days": refresh_ttl_days,
        })),
    ).into_response()
}

/// Spend a host ticket: `Some(purpose)` exactly once, for the account it
/// names, before it expires; `None` otherwise. One conditional UPDATE, so
/// two concurrent presentations cannot both win.
pub(crate) async fn spend_host_ticket(db: &sqlx::PgPool, ticket: &str, username: &str) -> Result<Option<String>, sqlx::Error> {
    let hash = auth_refresh::hash_token(ticket.trim());
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE noo_host_login_tickets SET used_at = now() \
         WHERE token_hash = $1 AND username = $2 AND used_at IS NULL AND expires_at > now() \
         RETURNING purpose",
    )
    .bind(&hash)
    .bind(username)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(p,)| p))
}

/// The one-time host ticket exchange (`grant_type=host_ticket`).
///
/// The ticket was minted on the controller host by `noo` (the onboard
/// wizard, or `noo security admin-password reset`), which wrote its sha256
/// into `noo_host_login_tickets` through the database's own superuser —
/// host-level access, the same that can rewrite `noo_users`. Spending it is
/// ONE conditional UPDATE, so a ticket logs in once, before it expires, for
/// the account it names, and never twice under a race.
///
/// What it buys is that account's ordinary login, nothing more: an
/// account that does not exist is refused (except the bootstrap env admin,
/// under the same gate a password login uses), a disabled account is
/// refused, and a LOCKED one is not — the lockout brakes password guessing,
/// and a ticket is not a guess. Every outcome is audited, as
/// `host_ticket:<purpose>` on success.
async fn host_ticket_login(
    state: &AppState,
    username: &str,
    ticket: &str,
    ua: Option<&str>,
    ip: Option<&str>,
) -> Response {
    let refused = || {
        (StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "host ticket refused: unknown, expired, already used, or for another account"})))
            .into_response()
    };
    let purpose = match spend_host_ticket(&state.db, ticket, username).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            audit_auth(&state.db, "auth_failure", username, "host_ticket_refused", ip).await;
            return refused();
        }
        Err(e) => {
            tracing::error!(error = %e, user = %username, "host_ticket_lookup_failed_refusing_login");
            return (StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail": "Auth backend unavailable"}))).into_response();
        }
    };
    let db_user = match lookup_user_db(&state.db, username).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, user = %username, "auth_user_lookup_failed_refusing_login");
            return (StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail": "Auth backend unavailable"}))).into_response();
        }
    };
    let (user, used_bootstrap) = match db_user {
        Some(mut u) => {
            // `lookup_user_db` folds a lockout into `disabled`; the ticket
            // honours `disabled` itself and nothing else.
            let disabled: Option<(bool,)> = sqlx::query_as("SELECT disabled FROM noo_users WHERE username = $1")
                .bind(username)
                .fetch_optional(&state.db)
                .await
                .unwrap_or(Some((true,)));
            if disabled.map(|(d,)| d).unwrap_or(true) {
                audit_auth(&state.db, "auth_failure", username, "account_disabled", ip).await;
                return refused();
            }
            u.disabled = false;
            (u, false)
        }
        None => match lookup_user_bootstrap_env(&state.db, username).await {
            Some(u) => (u, true),
            None => {
                audit_auth(&state.db, "auth_failure", username, "user_not_found", ip).await;
                return refused();
            }
        },
    };
    let outcome = format!("host_ticket:{purpose}");
    tracing::warn!(user = %username, purpose = %purpose, "login with a one-time HOST ticket (minted on the controller)");
    audit_auth(&state.db, "auth_success", username, &outcome, ip).await;
    record_successful_login(&state.db, username).await;
    if used_bootstrap {
        seed_bootstrap_admin(&state.db, &user).await;
    }
    issue_login(state, &user, ua, ip).await
}

/// POST /auth/refresh — Exchange the refresh cookie for a new access
/// token + a rotated refresh cookie.
///
/// Detection rule: if the presented refresh is *already revoked*, that's
/// a strong signal the chain has been stolen (the legitimate user's
/// rotation already retired this token, so something else is presenting
/// it). Revoke every live refresh for the user as a defensive sweep.
///
/// **The rotation is one conditional statement**.
/// This used to read the row, decide, then mint, store and revoke — four
/// statements with nothing holding the row across them, so two concurrent
/// presentations of the same cookie both read `revoked_at IS NULL`, both
/// got an access token, and both stored a rotated child. The detector
/// above never fired, because neither reader had seen the other's revoke;
/// the stolen-cookie race that rotation exists to catch was the one case
/// it could not catch. Now `auth_refresh::claim_token` spends the token in
/// the same `UPDATE … WHERE revoked_at IS NULL RETURNING …` that reads it,
/// inside a transaction: the second caller blocks on the row, loses the
/// predicate when the first commits, and takes the replay path — chain
/// swept, `critical` audit row, 401.
///
/// The claim is also the LAST thing that can fail benignly: the user lookup
/// and the JWT mint happen before it, so a database blip or an unmintable
/// token refuses the request without spending the caller's refresh. Only the
/// INSERT of the replacement follows the claim, and it shares the claim's
/// transaction — the old row's revocation and its child land together or not
/// at all.
async fn auth_refresh_handler(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: http::HeaderMap,
    jar: CookieJar,
) -> Response {
    let raw_token = match jar.get(auth_refresh::REFRESH_COOKIE_NAME) {
        Some(c) => c.value().to_string(),
        None => {
            return (StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "Missing refresh cookie"}))).into_response();
        }
    };

    // Client IP for audit attribution (reused for the rotated-token record below).
    let peer_ip = peer.map(|axum::Extension(axum::extract::ConnectInfo(a))| a.ip().to_string());
    let (ua, ip) = extract_client_meta(&headers, peer_ip.as_deref());

    match rotate_refresh(&state.db, &raw_token, ua.as_deref(), ip.as_deref()).await {
        Rotation::Rotated { access_token, expires_in, new_raw } => {
            // A cookie minted before the `noo-rt-` prefix
            // verified and is now rotated onto a prefixed one. Count it: the
            // evidence the bare form can be refused. Same family as #585.
            if !raw_token.starts_with(auth_refresh::REFRESH_TOKEN_PREFIX) {
                let labels = std::collections::HashMap::from([("lane".to_string(), "refresh_token_unprefixed".to_string())]);
                state.metrics.inc_counter("noo_legacy_lane_uses_total", Some(&labels), 1).await;
            }
            let cookie = auth_refresh::build_refresh_cookie(
                &new_raw,
                is_secure(),
                auth_refresh::refresh_ttl_days(),
            );
            let jar = CookieJar::new().add(cookie);
            (
                jar,
                Json(json!({
                    "access_token": access_token,
                    "token_type": "bearer",
                    "expires_in": expires_in,
                })),
            )
                .into_response()
        }
        Rotation::Replay => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "Refresh token already used (suspected reuse)"})),
        )
            .into_response(),
        // 409, not 401: the caller is not unauthenticated, it lost a race
        // with itself. A 401 here is what used to log the person out of
        // every session for a benign double-refresh. `Retry-After: 0`
        // because the winning rotation has already landed — the cookie jar
        // is shared across tabs, so the retry presents the successor.
        Rotation::Contended => (
            StatusCode::CONFLICT,
            [("Retry-After", "0")],
            Json(json!({
                "detail": "Refresh already rotated by another tab — retry with the current cookie",
                "retry": true,
            })),
        )
            .into_response(),
        Rotation::Refused(detail) => {
            (StatusCode::UNAUTHORIZED, Json(json!({"detail": detail}))).into_response()
        }
        Rotation::Unavailable(detail) => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"detail": detail}))).into_response()
        }
        Rotation::Failed(detail) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"detail": detail}))).into_response()
        }
        Rotation::Issue(e) => token_issue_response(e, "auth_refresh"),
    }
}

/// The outcome of one refresh presentation. Separated from the HTTP shell so
/// the rotation rule — the part that has to hold under concurrency — is
/// callable from a test without an axum stack (see `refresh_rotation_tests`).
enum Rotation {
    Rotated { access_token: String, expires_in: i64, new_raw: String },
    /// The token was already spent and the chain is not trustworthy.
    /// Chain already swept, `critical` audit row already written.
    Replay,
    /// The token was already spent, but by a rotation that happened moments
    /// ago whose replacement nobody has used — two tabs, not a thief. No
    /// sweep, no audit row; the caller retries and rides the successor.
    Contended,
    Refused(&'static str),
    Unavailable(&'static str),
    Failed(&'static str),
    Issue(TokenIssueError),
}

/// Rotate a presented refresh token. See `auth_refresh_handler` for why the
/// claim is a single conditional statement.
///
/// Order matters, and not only for tidiness. Everything that needs a second
/// database connection — the user lookup, the admin census behind the
/// bootstrap-env fallback — happens BEFORE the transaction opens, and the
/// transaction then does exactly two statements on the one connection it
/// holds: claim, then insert the child. Holding a pooled connection while
/// asking the same pool for another is how a burst of concurrent refreshes
/// deadlocks a small pool against itself, and a refresh burst is precisely
/// what a browser does when several tabs wake at once.
///
/// Nothing before the claim writes anything, so the work done for a loser is
/// a wasted JWT mint and no more: the claim is the only authority on who
/// spent the token.
async fn rotate_refresh(
    db: &sqlx::PgPool,
    raw_token: &str,
    ua: Option<&str>,
    ip: Option<&str>,
) -> Rotation {
    // Non-authoritative read, to learn whose token this is. The decision is
    // the claim below; this only tells us which user to resolve, and lets an
    // obvious replay skip the transaction entirely.
    let seen = match auth_refresh::lookup_token(db, raw_token).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            // Never existed: a forgery, or a row pruned long after expiry.
            // No chain to sweep, so no audit row either.
            return Rotation::Refused("Invalid refresh token");
        }
        Err(e) => {
            tracing::error!(error = %e, "refresh_lookup_failed");
            return Rotation::Failed("Auth lookup failed");
        }
    };

    // Theft detection: a token presented after it was spent.
    if seen.revoked_at.is_some() {
        return spent_token(db, &seen.user_id, &seen.id, ip).await;
    }

    if seen.expires_at < chrono::Utc::now() {
        // Spend it on the way out — it is dead either way, and leaving live
        // rows behind means the replay sweep has nothing to catch later.
        let _ = auth_refresh::revoke_token(db, &seen.id).await;
        return Rotation::Refused("Refresh token expired");
    }

    // Look up the user to get scopes (may have changed since issuance).
    // A lookup failure refuses the refresh rather than falling through to
    // the bootstrap credential (see `auth_token`), and leaves the token
    // alone: a database blip must not cost the caller a usable refresh.
    let db_user = match lookup_user_db(db, &seen.user_id).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "refresh_user_lookup_failed");
            return Rotation::Unavailable("Auth backend unavailable");
        }
    };
    let resolved = match db_user {
        Some(u) => Some(u),
        None => lookup_user_bootstrap_env(db, &seen.user_id).await,
    };
    let user = match resolved {
        Some(u) if !u.disabled => u,
        Some(_) => {
            let _ = auth_refresh::revoke_token(db, &seen.id).await;
            return Rotation::Refused("User disabled");
        }
        None => {
            let _ = auth_refresh::revoke_token(db, &seen.id).await;
            return Rotation::Refused("User no longer exists");
        }
    };

    let (access_token, expires_in) = match issue_access_token(&user) {
        Ok(t) => t,
        // Before the claim, so an unmintable JWT is not a reason to log the
        // user out of a working session.
        Err(e) => return Rotation::Issue(e),
    };

    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "refresh_tx_begin_failed");
            return Rotation::Failed("Refresh rotation failed");
        }
    };

    // THE CLAIM. One conditional statement reads the row
    // and spends it: `UPDATE … WHERE revoked_at IS NULL RETURNING …`. A second
    // caller presenting the same token blocks on this row until we commit,
    // then re-evaluates the predicate and gets nothing back.
    let claimed = match auth_refresh::claim_token(&mut tx, raw_token).await {
        Ok(auth_refresh::Claim::Won(r)) => r,
        Ok(auth_refresh::Claim::AlreadySpent { id, user_id }) => {
            // The losing side of a concurrent rotation, or a replay that
            // arrived between the read above and here. Same event, same
            // response. Roll back first: the sweep must touch rows this
            // transaction never locked, including the winner's fresh child.
            let _ = tx.rollback().await;
            return spent_token(db, &user_id, &id, ip).await;
        }
        Ok(auth_refresh::Claim::Unknown) => {
            let _ = tx.rollback().await;
            return Rotation::Refused("Invalid refresh token");
        }
        Err(e) => {
            tracing::error!(error = %e, "refresh_claim_failed");
            return Rotation::Failed("Refresh rotation failed");
        }
    };

    let new_raw = auth_refresh::generate_raw_token();
    let new_expires =
        chrono::Utc::now() + chrono::TimeDelta::days(auth_refresh::refresh_ttl_days());
    if let Err(e) = auth_refresh::store_token(
        &mut *tx,
        &user.username,
        &new_raw,
        new_expires,
        ua,
        ip,
        Some(claimed.id.clone()),
    )
    .await
    {
        tracing::error!(error = %e, "refresh_rotate_store_failed");
        return Rotation::Failed("Refresh rotation failed");
    }

    // The revocation of the old row and the birth of its child land together
    // or not at all — a rollback here leaves the caller's token still usable.
    if let Err(e) = tx.commit().await {
        tracing::error!(error = %e, "refresh_rotate_commit_failed");
        return Rotation::Failed("Refresh rotation failed");
    }

    Rotation::Rotated { access_token, expires_in, new_raw }
}

/// A spent refresh token was presented again. Decide whether that is a
/// stolen chain or two of the person's own tabs, and respond accordingly.
///
/// One helper because the two ways to get here — the pre-claim read and
/// losing the claim — are the same event, and a second copy of this is a
/// second place to forget the sweep.
///
/// **Why the grace window exists.** The cookie is single-use, so two tabs
/// whose access tokens expire in the same second both present it and the
/// loser trips theft detection: `revoke_all_for_user` logs the person out
/// of every session for a benign double-refresh. The browser side of this
/// is a `navigator.locks` mutex (#152, `ui/packages/api/src/auth.ts`), but
/// Web Locks is absent on older Safari and in some worker contexts, and a
/// mutex that is sometimes there cannot be the only control. The server
/// can decide it exactly, from `revoked_at` and the successor's state —
/// see `auth_refresh::Succession::is_benign_double_refresh` for the three
/// conditions and what each one rules out.
///
/// The successor is NOT returned, because it cannot be: only its sha256 is
/// stored, and the raw value exists in the winner's cookie jar and nowhere
/// else. A thief inside the window therefore gets a `409` and no session.
/// The loser gets the same `409` and succeeds on retry, because the cookie
/// jar is shared across the tabs of one browser.
async fn spent_token(
    db: &sqlx::PgPool,
    user_id: &str,
    token_id: &str,
    ip: Option<&str>,
) -> Rotation {
    // A read failure must NOT quietly become "benign": fall through to the
    // sweep, which is the safe direction when the chain cannot be inspected.
    let succession = auth_refresh::successor_state(db, token_id, user_id)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "refresh_succession_read_failed");
            None
        });
    if let Some(s) = succession {
        if s.is_benign_double_refresh(auth_refresh::refresh_grace()) {
            // Logged, not audited. One row per double-refresh would be
            // steady background noise in the same table and at the same
            // event type as the real thing, which is how the real one stops
            // being noticed.
            tracing::warn!(
                user = %user_id,
                token_id = %token_id,
                spent_secs_ago = ?s.spent_secs_ago,
                "refresh_token_contended_within_grace_window"
            );
            return Rotation::Contended;
        }
    }
    tracing::warn!(
        user = %user_id,
        token_id = %token_id,
        succession = ?succession,
        "refresh_token_replay_detected_revoking_all_chains"
    );
    let _ = auth_refresh::revoke_all_for_user(db, user_id).await;
    audit_auth(db, "auth_failure", user_id, "refresh_replay", ip).await;
    Rotation::Replay
}

#[cfg(test)]
#[path = "core/refresh_rotation_tests.rs"]
mod refresh_rotation_tests;

/// POST /auth/logout — Revoke the presented refresh cookie + clear it
/// from the browser. Idempotent.
async fn auth_logout_handler(
    State(state): State<Arc<AppState>>,
    headers: http::HeaderMap,
    jar: CookieJar,
) -> Response {
    // Whose session is this? The refresh cookie names the account (browser);
    // a CLI logout has no cookie but presents the bearer it is giving up.
    let mut account: Option<String> = None;
    if let Some(c) = jar.get(auth_refresh::REFRESH_COOKIE_NAME) {
        let raw = c.value().to_string();
        if let Ok(Some(rec)) = auth_refresh::lookup_token(&state.db, &raw).await {
            let _ = auth_refresh::revoke_token(&state.db, &rec.id).await;
            audit_auth(&state.db, "auth_logout", &rec.user_id, "ok", None).await;
            account = Some(rec.user_id);
        }
    }
    if account.is_none() {
        let secret = jwt_secret();
        if !crate::auth::jwt_secret_is_insecure(&secret) {
            if let Some(Ok(claims)) = headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|t| verify_token(t, &secret))
            {
                audit_auth(&state.db, "auth_logout", crate::auth::account_of(&claims.sub), "ok", None).await;
                account = Some(crate::auth::account_of(&claims.sub).to_string());
            }
        }
    }
    if let Some(account) = account {
        // The not-before floor kills the bearer this person is logging out
        // of (the access token used to live on for up to 15 minutes), the
        // refresh chains are left to the cookie revoke above, and every open
        // socket for the account closes with 4401 — a WebSocket
        // authenticates only at its handshake, and the floor stops it
        // reconnecting with the same JWT.
        let raised = crate::session_floor::raise(&state, &account, crate::session_floor::Reason::Logout).await;
        let closed = state.alert_hub.end_sessions(&account);
        tracing::info!(user_id = %account, sockets = closed, floor_shared = raised.shared, "auth_logout ended open sockets");
    }
    let clear = auth_refresh::build_clear_cookie(is_secure());
    let jar = CookieJar::new().add(clear);
    (jar, Json(json!({"ok": true}))).into_response()
}

/// GET /auth/me — Return current user from JWT.
///
/// Decodes the Authorization: Bearer <token> header, looks up the user
/// in DB/env, and returns user info. Mirrors Python `auth_router.py::read_users_me()`.
async fn auth_me(
    State(state): State<Arc<AppState>>,
    headers: http::HeaderMap,
) -> impl IntoResponse {
    let secret = jwt_secret();
    // this used to check only `is_empty()`, so with NOO_JWT_SECRET
    // unset it VERIFIED the presented token against the public placeholder
    // `dev-secret-change-in-production` — anyone could mint a bearer for any
    // subject and /auth/me would confirm it, while every other route
    // (`require_any_auth` → `jwt_secret_is_insecure`) refused. Same predicate
    // as the middleware now, so there is one answer to "is this secret
    // usable", not two.
    if crate::auth::jwt_secret_is_insecure(&secret) {
        crate::auth::warn_insecure_jwt();
        return (StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "Auth not configured"}))).into_response();
    }

    // Extract Bearer token
    let token = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let token = match token {
        Some(t) => t,
        None => {
            return (StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "Not authenticated"}))).into_response();
        }
    };

    // Decode JWT
    let claims = match verify_token(&token, &secret) {
        Ok(c) => c,
        Err(_) => {
            return (StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "Could not validate credentials"}))).into_response();
        }
    };

    // Same floor `require_any_auth` applies: a token issued before the
    // account was disabled/demoted/logged out is not an identity.
    if crate::session_floor::refuses(&state, &claims.sub, &token).await {
        return (StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "Session ended"}))).into_response();
    }

    // Look up user for full details (scopes may have changed since token was
    // issued). On lookup failure, say so — do not fall through to the
    // bootstrap credential, and do not report stale claims as current truth.
    let db_user = match lookup_user_db(&state.db, &claims.sub).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "auth_me_user_lookup_failed");
            return (StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail": "Auth backend unavailable"}))).into_response();
        }
    };
    let user = match db_user {
        Some(u) => Some(u),
        None => lookup_user_bootstrap_env(&state.db, &claims.sub).await,
    };

    match user {
        Some(u) if !u.disabled => {
            Json(json!({
                "username": u.username,
                "disabled": u.disabled,
                "scopes": u.scopes,
                "role": u.role.as_str(),
            })).into_response()
        }
        Some(_) => {
            (StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "User is disabled"}))).into_response()
        }
        None => {
            // The account no longer exists (deleted after the token was
            // issued). The token's claims are not a live identity: answer
            // 401 like the disabled branch instead of echoing them.
            (StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "User no longer exists"}))).into_response()
        }
    }
}

// ── User lookup helpers ──────────────────────────────────────

struct UserRecord {
    username: String,
    hashed_password: String,
    disabled: bool,
    scopes: Vec<String>,
    /// Source of truth for what a token grants; `scopes` above
    /// only contributes the non-tier extras at issuance (see
    /// [`dual_emit_scopes`]).
    role: crate::auth::Role,
}

/// Look up a user from the `noo_users` table.
///
/// Checks account lockout (locked_until > NOW).
///
/// `Ok(None)` means "no such account". `Err` means "could not ask" — the two
/// used to be collapsed into `None` by a `.ok()??`, which silently promoted a
/// Postgres outage into "the admin row does not exist" and re-opened the env
/// admin fallback. Callers must keep them apart.
async fn lookup_user_db(
    db: &sqlx::PgPool,
    username: &str,
) -> Result<Option<UserRecord>, sqlx::Error> {
    let row = sqlx::query_as::<_, (
        String,                                         // username
        String,                                         // hashed_password
        bool,                                           // disabled
        serde_json::Value,                              // scopes (JSONB)
        Option<i32>,                                    // failed_login_count
        Option<chrono::DateTime<chrono::Utc>>,          // locked_until
        String,                                         // role (migration 050)
    )>(
        "SELECT username, hashed_password, disabled, \
                COALESCE(scopes, '[\"read\"]'::jsonb), \
                COALESCE(failed_login_count, 0), locked_until, role \
         FROM noo_users WHERE username = $1"
    )
    .bind(username)
    .fetch_optional(db)
    .await?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    let (uname, hashed_pw, disabled, scopes_json, _fail_count, locked_until, role_str) = row;

    // Check lockout
    let is_locked = locked_until
        .map(|lu| lu > chrono::Utc::now())
        .unwrap_or(false);

    let scopes: Vec<String> = scopes_json.as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    // The DB CHECK constrains role to the enum; if a row somehow escapes it,
    // fail CLOSED to the lowest tier rather than erroring the login path open
    // or guessing upward.
    let role = role_str
        .parse::<crate::auth::Role>()
        .unwrap_or(crate::auth::Role::User);

    Ok(Some(UserRecord {
        username: uname,
        hashed_password: hashed_pw,
        disabled: disabled || is_locked,
        scopes,
        role,
    }))
}

/// What the DB can tell us about existing admin accounts.
///
/// Three states, not two: `Unknown` (the census query failed) must never be
/// treated as `NoneEnabled`, or a Postgres blip re-opens the bootstrap door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminCensus {
    /// Query succeeded: no enabled account holds the `admin` scope.
    NoneEnabled,
    /// Query succeeded: at least one enabled admin exists.
    AtLeastOne,
    /// Query failed. Unreachable ≠ absent.
    Unknown,
}

/// The whole gate, as a pure function so it can be tested without Postgres:
/// the env admin is a BOOTSTRAP credential, valid only in the one situation
/// that bootstrap exists for — an install with no admin account yet.
fn env_fallback_allowed(census: AdminCensus) -> bool {
    matches!(census, AdminCensus::NoneEnabled)
}

/// Count enabled admins. Deliberately ignores `locked_until`: a temporarily
/// locked-out admin still *exists*, and letting a brute-force lockout open
/// the env door would hand an attacker the escalation for free.
async fn admin_census(db: &sqlx::PgPool) -> AdminCensus {
    // Role OR legacy scope: during the dual-accept window either can make an
    // account an admin somewhere, and this gate must stay CLOSED if either
    // says one exists. (A drifted row — admin scope, non-admin role — cannot
    // mint admin tokens, but counting it still only keeps the bootstrap door
    // shut, which is the safe direction.)
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM noo_users \
         WHERE disabled = false \
           AND (role = 'admin' OR scopes @> '[\"admin\"]'::jsonb))",
    )
    .fetch_one(db)
    .await;

    match exists {
        Ok(true) => AdminCensus::AtLeastOne,
        Ok(false) => AdminCensus::NoneEnabled,
        Err(e) => {
            tracing::error!(
                error = %e,
                "admin_census_failed_refusing_bootstrap_admin"
            );
            AdminCensus::Unknown
        }
    }
}

/// Bootstrap env admin — `NOO_ADMIN_USER` / `NOO_ADMIN_PASSWORD`, gated.
///
/// `noo onboard` collects the admin credential on the HOST, before the
/// gateway (and therefore any `noo_users` row) exists, so the very first
/// login has nothing in the DB to match. That is the *only* case this
/// credential is for. Once an enabled admin exists it is refused, and a
/// successful use seeds the row that refuses it thereafter.
///
/// Every outcome is logged: a bootstrap login after first install means
/// something is wrong (the admin row was deleted), and a refusal means
/// someone is presenting the env password at a system that no longer
/// honours it.
async fn lookup_user_bootstrap_env(db: &sqlx::PgPool, username: &str) -> Option<UserRecord> {
    // Cheap checks first — no DB hit when the env admin isn't configured
    // or the username doesn't match it.
    let candidate = lookup_user_env(username)?;

    let census = admin_census(db).await;
    if !env_fallback_allowed(census) {
        tracing::warn!(
            user = %username,
            census = ?census,
            "bootstrap_admin_refused_env_fallback_is_closed"
        );
        return None;
    }

    tracing::warn!(
        user = %username,
        "bootstrap_admin_env_fallback_used_no_admin_row_exists"
    );
    Some(candidate)
}

/// Materialise the bootstrap admin as a real account, so the env credential
/// stops being an authentication path. Best-effort: if the insert fails the
/// login still succeeds and the fallback simply stays open until it lands.
/// `ON CONFLICT DO NOTHING` (in `repo::users::create`) makes it idempotent.
async fn seed_bootstrap_admin(db: &sqlx::PgPool, user: &UserRecord) {
    let scopes = serde_json::json!(user.scopes);
    match crate::repo::users::create(
        db,
        &user.username,
        &user.hashed_password,
        &scopes,
        None,
    )
    .await
    {
        Ok(n) if n > 0 => tracing::warn!(
            user = %user.username,
            "bootstrap_admin_seeded_env_fallback_now_closed"
        ),
        Ok(_) => tracing::warn!(
            user = %user.username,
            "bootstrap_admin_seed_skipped_row_already_present"
        ),
        Err(e) => tracing::error!(
            error = %e,
            user = %user.username,
            "bootstrap_admin_seed_failed_env_fallback_still_open"
        ),
    }
}

/// Raw env admin credential. Private on purpose — everything outside the
/// bootstrap gate must go through [`lookup_user_bootstrap_env`].
fn lookup_user_env(username: &str) -> Option<UserRecord> {
    let admin_user = std::env::var("NOO_ADMIN_USER").unwrap_or_else(|_| "admin".into());
    let admin_pw = crate::config::secret_env::secret_or_empty("NOO_ADMIN_PASSWORD");

    if admin_pw.is_empty() || username != admin_user {
        return None;
    }

    // Hash the env password with bcrypt so verify() works uniformly
    let hashed = bcrypt::hash(&admin_pw, bcrypt::DEFAULT_COST).unwrap_or_else(|_| admin_pw.clone());

    Some(UserRecord {
        username: admin_user,
        hashed_password: hashed,
        disabled: false,
        // Hardcoded, and correctly so: this identity exists to create the
        // first real account, which requires `admin`. It is not a general
        // login, so there is nothing to narrow it to — the scopes it grants
        // last exactly one login, then become an editable DB row.
        scopes: vec!["read".into(), "write".into(), "admin".into()],
        role: crate::auth::Role::Admin,
    })
}

/// Record a failed login attempt (increment counter, lock after threshold).
async fn record_failed_login(db: &sqlx::PgPool, username: &str) {
    let _ = sqlx::query(
        "UPDATE noo_users SET failed_login_count = COALESCE(failed_login_count, 0) + 1, \
         locked_until = CASE \
           WHEN COALESCE(failed_login_count, 0) + 1 >= 5 THEN NOW() + INTERVAL '15 minutes' \
           ELSE locked_until \
         END \
         WHERE username = $1"
    )
    .bind(username)
    .execute(db)
    .await;
}

/// Reset failed login count on successful login.
async fn record_successful_login(db: &sqlx::PgPool, username: &str) {
    let _ = sqlx::query(
        "UPDATE noo_users SET failed_login_count = 0, locked_until = NULL, \
         last_login_at = NOW() WHERE username = $1"
    )
    .bind(username)
    .execute(db)
    .await;
}

/// Severity for an auth audit event. Previously every row was hardcoded
/// `'info'`, so failed logins / replay attempts were indistinguishable from
/// success and could not drive threshold alerting.
fn audit_severity(event_type: &str, outcome: &str) -> &'static str {
    match (event_type, outcome) {
        ("auth_failure", "refresh_replay") => "critical",
        ("auth_failure", _) => "warning",
        _ => "info",
    }
}

/// General best-effort security-audit insert for privileged actions
/// (config changes, deletions). Never blocks/fails the caller's request.
/// `details` is serialized to the `details` jsonb column. (H-L1)
///
/// The row also records `source_ip` (the request's caller, same trusted-proxy
/// rule as the login rows) and `conversation_id` (inside an agent turn) when
/// known and not already in `details` — see `audit_context`.
pub(crate) async fn audit_event(
    db: &sqlx::PgPool,
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: serde_json::Value,
) {
    audit_insert(
        db, event_type, severity, actor, resource, outcome,
        &crate::audit_context::with_origin(details).to_string(),
    )
    .await;
}

/// [`audit_event`] for a read that must NOT happen unaudited (the admin
/// walks view): the same signed row through the same writer, but it says
/// whether the row landed, and the caller refuses to serve when it did not.
/// Everything else stays best-effort through [`audit_event`].
pub(crate) async fn audit_event_required(
    db: &sqlx::PgPool,
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: serde_json::Value,
) -> bool {
    let Some(key) = crate::audit_integrity::current_key() else {
        tracing::error!(
            event_type, actor,
            "audit_write_refused_no_key: NOO_AUDIT_HMAC_KEY is not set; a view that requires an \
             audit row was refused"
        );
        return false;
    };
    write_audit_row(
        db, &key, event_type, severity, actor, resource, outcome,
        &crate::audit_context::with_origin(details).to_string(), None,
    )
    .await
}

/// The ONE writer for `noo_security_audit`, with the missing-partition heal.
///
/// `noo_security_audit` is RANGE-partitioned by month, and an insert with no
/// partition for its timestamp fails outright — Postgres does not create one.
/// Both call sites used to be `let _ = sqlx::query(...)`, so that failure was
/// discarded without a word.
///
/// That is how the audit log died silently on every fresh install.
/// `audit_partition::ensure_current_and_next` runs at startup and asked for
/// `public.noo_ensure_audit_partition`, but a fresh install puts the whole
/// mesh schema in `mesh`, so the function was not found, the error was
/// swallowed as a startup `warn`, no partition was ever created — and then
/// every audit write here was swallowed too. Two layers of silence over a
/// security log, and the only visible symptom was an empty table.
///
/// So this function does three things the old one did not:
///   - heals a missing partition and retries ONCE, the same shape
///     `usage::record` already uses for `noo_token_usage` (which got this
///     right, unqualified call and all);
///   - covers the month boundary, not just startup: a gateway up for two
///     months would otherwise walk off the end of the partitions its own
///     startup created;
///   - logs a LOST audit row at `error!`. It stays best-effort — an audit
///     write must never fail the caller's request — but "best-effort" is not
///     "unobservable".
async fn audit_insert(
    db: &sqlx::PgPool,
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: &str,
) {
    // Signed with `NOO_AUDIT_HMAC_KEY` and NOTHING else: without it the row
    // is refused. The derivation from `NOO_JWT_SECRET` (and its public
    // "audit-integrity-fallback" literal) survives only as a VERIFY-ONLY key
    // for rows written before the checkpoint (`audit_integrity`).
    let Some(key) = crate::audit_integrity::current_key() else {
        // Refused, loudly, every time: a row signed with anything but the
        // audit key is a row whoever holds that other key could have forged.
        tracing::error!(
            event_type, actor,
            "audit_write_refused_no_key: NOO_AUDIT_HMAC_KEY is not set, so this security audit \
             row was NOT recorded — run `noo upgrade --stack`, which mints it when absent and \
             recreates the stack"
        );
        crate::audit_spool::note_lost();
        return;
    };
    // The database being away (a Postgres restart during a roll) is not a
    // reason to lose the row: it waits in `audit_spool` and is written as
    // soon as the database answers, stamped with when it happened.
    if write_audit_row_outcome(db, &key, event_type, severity, actor, resource, outcome, details, None).await
        == crate::audit_spool::Outcome::Transient
    {
        let held = crate::audit_spool::enqueue(crate::audit_spool::Pending::Security {
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            actor: actor.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            details: crate::audit_spool::stamp_queued_at(details),
        });
        if held {
            tracing::warn!(event_type, actor, "audit_write_queued: the database is away; this security audit row is held and will be written when it answers");
        } else {
            tracing::error!(event_type, actor, "audit_write_lost: the database is away and the audit queue is full; this security audit row was NOT recorded");
        }
    }
}

/// Sign one row with hash v2 under `key` and insert it. Returns whether the
/// row landed. Shared by [`audit_insert`] and the boot rows
/// (`audit_integrity::ensure_checkpoint`, which signs its one row with a
/// different key, and `ensure_hash_v2_marker`).
///
/// Every column v2 covers is fixed before signing, and bound explicitly —
/// none is left to a column default. `audit_chain::insert_in_tx` does it, under
/// the chain lock, so the row is linked after the newest one:
///   - `id`: a v4 uuid, as Postgres renders `uuid::text`;
///   - `timestamp`: now (never earlier than the previous row's), truncated to
///     MICROseconds, the precision `timestamptz` stores — the hashed value is
///     the stored value;
///   - `details`: Postgres's own jsonb text for the value (`$1::jsonb::text`),
///     which is what `details::text` reads back; jsonb re-orders keys and
///     re-spaces, so hashing our serde text would not survive the store.
///   - `request_id`: NULL (the gateway has none).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_audit_row(
    db: &sqlx::PgPool,
    key: &[u8],
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: &str,
    prev_hash: Option<&str>,
) -> bool {
    // Not queued: these callers act on the answer now (a required view
    // refuses, a boot row is retried at the next boot).
    match write_audit_row_outcome(db, key, event_type, severity, actor, resource, outcome, details, prev_hash).await {
        crate::audit_spool::Outcome::Landed => true,
        crate::audit_spool::Outcome::Transient => {
            tracing::error!(event_type, actor, "audit_write_lost: the database is away; this security audit row was NOT recorded");
            crate::audit_spool::note_lost();
            false
        }
        crate::audit_spool::Outcome::Lost => false,
    }
}

/// [`write_audit_row`], saying WHY a row did not land: `Transient` (the
/// database is away; the caller may hold the row for `audit_spool`) or
/// `Lost` (it would fail again). Only `Lost` logs `audit_write_lost` here; a
/// `Transient` row is the caller's to queue or report.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_audit_row_outcome(
    db: &sqlx::PgPool,
    key: &[u8],
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: &str,
    prev_hash: Option<&str>,
) -> crate::audit_spool::Outcome {
    use crate::audit_spool::{is_transient, Outcome};
    let details = match sqlx::query_scalar::<_, String>("SELECT $1::jsonb::text")
        .bind(details)
        .fetch_one(db)
        .await
    {
        Ok(d) => d,
        Err(e) if is_transient(&e) => return Outcome::Transient,
        Err(e) => {
            tracing::error!(
                event_type, actor, error = %e,
                "audit_write_lost: a security audit row was NOT recorded (its details are not jsonb)"
            );
            crate::audit_spool::note_lost();
            return Outcome::Lost;
        }
    };
    // The chain is always linked under the CURRENT audit key, even for the one
    // row (the key hand-over) whose own hash is signed under the retired one.
    let chain_key = crate::audit_integrity::current_key();
    let row = crate::audit_chain::NewRow {
        event_type,
        severity,
        actor,
        resource,
        outcome,
        details: &details,
        prev_hash,
    };
    // The id, the time and both hashes are fixed INSIDE the chain lock
    // (`audit_chain::insert_in_tx`), so a row's time is never earlier than its
    // predecessor's. A missing monthly partition is healed once, as before.
    for attempt in 0..2 {
        match crate::audit_chain::write_row(db, key, chain_key.as_deref(), &row).await {
            Ok(_) => return Outcome::Landed,
            Err(e) if attempt == 0 && is_missing_partition(&e) => {
                crate::audit_partition::ensure_for_heal(db).await;
            }
            Err(e) if is_transient(&e) => return Outcome::Transient,
            Err(e) => {
                tracing::error!(
                    event_type, actor, error = %e,
                    "audit_write_lost: a security audit row was NOT recorded"
                );
                crate::audit_spool::note_lost();
                return Outcome::Lost;
            }
        }
    }
    crate::audit_spool::note_lost();
    Outcome::Lost
}

/// Now, as `timestamptz` will store it: whole microseconds.
pub(crate) fn stored_now() -> chrono::DateTime<chrono::Utc> {
    let us = chrono::Utc::now().timestamp_micros();
    chrono::DateTime::from_timestamp_micros(us).expect("now is in range")
}

/// Insert one fully-formed, already-signed row, healing a missing partition
/// once. Returns whether the row landed. Unchained. Production signs and links
/// through [`write_audit_row`]; this is the test harness's way to plant a row of
/// any shape (v1 hashes, rows from a writer that predates the chain).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_signed_audit_row(
    db: &sqlx::PgPool,
    id: &str,
    ts: chrono::DateTime<chrono::Utc>,
    event_type: &str,
    severity: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
    details: &str,
    request_id: Option<&str>,
    entry_hash: &str,
    prev_hash: Option<&str>,
) -> bool {
    let run = || {
        sqlx::query(
            "INSERT INTO noo_security_audit \
               (id, \"timestamp\", event_type, severity, actor, resource, outcome, details, \
                request_id, entry_hash, prev_hash) \
             VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11)",
        )
        .bind(id)
        .bind(ts)
        .bind(event_type)
        .bind(severity)
        .bind(actor)
        .bind(resource)
        .bind(outcome)
        .bind(details)
        .bind(request_id)
        .bind(entry_hash)
        .bind(prev_hash)
        .execute(db)
    };

    match run().await {
        Ok(_) => true,
        Err(e) if is_missing_partition(&e) => {
            crate::audit_partition::ensure_for_heal(db).await;
            if let Err(e2) = run().await {
                tracing::error!(
                    event_type, actor, error = %e2,
                    "audit_write_lost_after_partition_heal: a security audit row was NOT recorded"
                );
                return false;
            }
            true
        }
        Err(e) => {
            tracing::error!(
                event_type, actor, error = %e,
                "audit_write_lost: a security audit row was NOT recorded"
            );
            false
        }
    }
}

/// Does this error mean "no monthly partition for that timestamp"?
///
/// Matched on the message because Postgres reports it as check_violation
/// (23514), the same SQLSTATE as an ordinary CHECK failure — which is not a
/// thing to heal by creating a partition.
pub(crate) fn is_missing_partition(e: &sqlx::Error) -> bool {
    e.to_string().contains("no partition of relation")
}

/// Best-effort security audit log. `source_ip` is recorded in `details` so a
/// failed-login spike can be attributed to an origin (the `failed_auth_spike`
/// autonomy evaluator's remediation text tells operators to "check
/// noo_security_audit for source IPs" — previously there were none).
async fn audit_auth(
    db: &sqlx::PgPool,
    event_type: &str,
    actor: &str,
    outcome: &str,
    source_ip: Option<&str>,
) {
    // Same table, same columns, same heal — through the one writer. These
    // were two hand-rolled copies of the same INSERT, and only one of them
    // would have been fixed by a reader who found the bug in the other.
    let severity = audit_severity(event_type, outcome);
    let details = serde_json::json!({ "source_ip": source_ip }).to_string();
    audit_insert(db, event_type, severity, actor, "gateway", outcome, &details).await;
}

#[cfg(test)]
mod audit_hash_tests {

    #[test]
    fn matches_python_vector() {
        // v1 — verify-only, but every row written before
        // v0.2.83 is checked with it. Same frozen vector as
        // tests/test_audit_integrity.py::test_known_vector_matches_rust.
        // Explicit key, not the env: tests share one process, and the env
        // form of this test raced every other test that reads the key.
        let h = crate::audit_integrity::row_hash_with(
            b"test-audit-key-123", "auth_failure", "warning", "alice", "gateway", "bad_password", "",
        );
        assert_eq!(h, "d7d4771f53f878b27d37dc4a0ee58e018e967d3d5de689eaa26c15fd1b2712e1");
    }

    #[test]
    fn without_the_audit_key_a_row_is_refused_not_signed_with_a_fallback() {
        // A process holding the login secret (and a file pointer to it) but
        // no audit key: the writer's key source must find NO key — not one
        // derived from NOO_JWT_SECRET, not the public "audit-integrity-fallback"
        // literal. `audit_insert` refuses the row when it finds none.
        let lookup = |name: &str| match name {
            "NOO_JWT_SECRET" => Some("a-login-secret".to_string()),
            _ => None,
        };
        assert_eq!(
            crate::audit_integrity::key_from(&lookup),
            None,
            "a key was found without NOO_AUDIT_HMAC_KEY — a fallback is back"
        );
        let with = |name: &str| (name == "NOO_AUDIT_HMAC_KEY").then(|| "k".to_string());
        assert_eq!(crate::audit_integrity::key_from(&with), Some(b"k".to_vec()));
    }

    #[test]
    fn the_writer_stamps_whole_microseconds() {
        // The hashed time is the stored time: timestamptz keeps microseconds.
        let t = super::stored_now();
        assert_eq!(t.timestamp_subsec_nanos() % 1_000, 0);
    }
}

/// Liveness for anyone; the inventory only for a credential.
///
/// The status CODE is identical either way, because everything that gates
/// a deploy or a rollback reads only that — the container healthcheck, the
/// compose healthcheck, `noo-host-watcher.sh::check_health`, hostd's
/// recreate gate. None of them can present a token, and none of them ever
/// read a field.
///
/// What the anonymous body loses is the part no consumer in this tree
/// branches on and an unauthenticated caller has no business with: the
/// gateway version, the engine name, the live peer count, the dependency
/// map and the add-on states. That is a fingerprint of the deployment,
/// readable until now by anything that could reach the port.
///
/// `status` stays, because it is the one field anonymous consumers do
/// read (`tests/integration/test_smoke_autonomy.py`), and because a
/// liveness endpoint that cannot say "degraded" is a status display.
async fn health(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> impl IntoResponse {
    let mut deps = serde_json::Map::new();
    let mut all_ok = true;

    // Check PostgreSQL
    let db_ok = sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .is_ok();
    deps.insert("postgresql".into(), json!({"healthy": db_ok}));
    if !db_ok { all_ok = false; }

    // Check NATS (flush acts as a ping — confirms the connection is live)
    let nats_ok = state.nats.flush().await.is_ok();
    deps.insert("nats".into(), json!({"healthy": nats_ok}));
    if !nats_ok { all_ok = false; }

    // Check Redis. `state` is the word `noo cluster verify` ("gateway redis")
    // and `noo upgrade`'s post-roll gate read: `connected`, `reconnecting`
    // (a client exists and is redialling — the boot-time race that left the
    // controller Redis-less for an hour on 2026-10-15 reported healthy here),
    // or `unavailable` (no client could be built: a configuration error).
    let (redis_ok, redis_state) = match state.redis.as_ref() {
        Some(cache) => {
            let ok = cache.is_healthy().await;
            (ok, if ok { "connected" } else { "reconnecting" })
        }
        None => match state.redis.state() {
            crate::cache::RedisState::Unavailable => (true, "unavailable"),
            s => (false, s.as_str()),
        },
    };
    let redis_optional = redis_state == "unavailable";
    deps.insert("redis".into(), json!({
        "healthy": redis_ok,
        "optional": redis_optional,
        "state": redis_state,
    }));
    if !redis_ok && !redis_optional { all_ok = false; }

    let status = if all_ok { "healthy" } else { "degraded" };
    let peers = state.gossip.alive_peers().len();

    // Add-on states: an operator who opted out must see
    // "disabled", never degraded-red. Config-driven on purpose — broken
    // vs turned-off stay distinguishable (watchdog owns broken).
    // Built from the addon table: a new add-on declares one row in
    // addons::ADDONS and appears here with no /health change.
    let addons = serde_json::Value::Object(
        crate::addons::health_names()
            .into_iter()
            .map(|name| {
                // Licensed add-ons have a third word: flag on, no
                // licence → "unlicensed".
                let word = json!(crate::addons::health_word(&name));
                (name, word)
            })
            .collect(),
    );

    // The body already said "degraded" — but this returned a bare `Json`, which
    // is ALWAYS HTTP 200, and every consumer keys on the status code:
    // the compose healthcheck tests `.status == 200`, and
    // `noo-host-watcher.sh::check_health` tests `[[ "$code" == "200" ]]`.
    //
    // So a gateway with no database at all reported `Up (healthy)`. That is not
    // theoretical: on 2026-08-03 it did exactly that for four hours while every
    // DB-backed subsystem failed — chat, service keys, heartbeat, autonomy,
    // ingest — with zero connections in `pg_stat_activity`. A health endpoint
    // that cannot say no is a status display, not a health check.
    //
    // 503 is scoped to the dependencies the gateway cannot do its job without.
    // Redis deliberately does NOT gate the status code even though it counts
    // toward `degraded`: it restarts on its own (observed mid-incident,
    // recovered in under a minute), the gateway keeps serving without it, and
    // `check_health` drives a post-recreate ROLLBACK — so letting a Redis blip
    // reach the status code would turn a transient cache bounce into a
    // reverted deploy.
    let code = if db_ok && nats_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let mut body = health_body(status, peers, deps, addons, ctx.is_some());
    // Add-ons only a temporary development key vouches for (i163 part A):
    // `addons.<name>` keeps its enum word (`enabled`; `unhealthy` once the
    // key expires) so every client still reads it, and this sibling map says
    // `dev (expires <date>)`. Absent when there is none.
    if ctx.is_some() {
        if let Some(dev) = crate::addons::health_dev_map() {
            body["addons_dev"] = dev;
        }
    }
    (code, Json(body))
}

/// The health body, by whether the caller presented a credential.
///
/// Separated from the handler so the difference is testable without a
/// database and a bus behind it — the shape IS the security property here,
/// and a property nothing can assert is one that drifts back.
fn health_body(
    status: &str,
    peers: usize,
    deps: serde_json::Map<String, Value>,
    addons: Value,
    authenticated: bool,
) -> Value {
    if !authenticated {
        // Liveness and nothing else. Everything below describes the
        // deployment: which version is running, which engine, how many
        // peers are alive, which dependencies are up and which add-ons
        // are licensed. An anonymous probe reads the status code.
        return json!({ "status": status });
    }
    json!({
        "status": status,
        "engine": "rust",
        "version": env!("CARGO_PKG_VERSION"),
        "peers": peers,
        "dependencies": deps,
        "addons": addons,
    })
}

/// Prometheus metrics endpoint. Renders:
///   - `noo_gateway_up` liveness gauge.
///   - All in-process counters/gauges (incl. NATS-pushed events from Python ML).
///   - DB-backed gauges (embedding backlog, temporal edges, DLQ depth, etc).
///   - Filesystem-backed gauge for recall-memory archive size.
async fn prometheus_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut body = String::with_capacity(8192);
    body.push_str(
        "# TYPE noo_gateway_up gauge\n\
         noo_gateway_up{engine=\"rust\"} 1\n",
    );
    // The window every `_total` counter below was counted over: counters reset with the process, so "0 uses" means nothing
    // without how long the process has been up.
    body.push_str(&format!(
        "# TYPE noo_gateway_start_time_seconds gauge\nnoo_gateway_start_time_seconds {}\n",
        crate::legacy_lanes::process_start_unix()
    ));

    // In-process counters/gauges (Phase 2 events + Python pushes)
    body.push_str(&state.metrics.render().await);

    // DB-backed gauges — one round-trip per scrape; cheap (each is a COUNT(*)).
    let gauges = crate::metrics::collect_db_gauges(&state.db).await;
    let mut emit = |name: &str, value: Option<i64>| {
        if let Some(v) = value {
            body.push_str(&format!("# TYPE {} gauge\n{} {}\n", name, name, v));
        }
    };
    emit("pages_embedding_backlog", gauges.pages_embedding_backlog);
    emit("temporal_edges_total", gauges.temporal_edges_total);
    emit("nats_dlq_pending", gauges.nats_dlq_pending);
    emit("nats_dlq_abandoned", gauges.nats_dlq_abandoned);
    emit("conversations_total", gauges.conversations_total);
    emit("entries_total", gauges.entries_total);
    emit("noo_auth_failures_5m", gauges.auth_failures_5m);
    emit("noo_exec_denials_5m", gauges.exec_denials_5m);

    // Cluster shape. `configs/grafana/dashboards/cluster-overview.json` has
    // queried these ten series since it was written and NOTHING emitted them,
    // so the default home dashboard showed "No data" on every cluster panel
    // while the node-exporter and NVIDIA panels beside it worked — which
    // reads as "the cluster is empty", not "this panel is unwired".
    //
    // Computed per scrape from `collect_cluster_nodes`, the SAME helper
    // behind `/api/cluster/status` and `/api/cluster/nodes`, so the dashboard
    // cannot disagree with the CLI about how many nodes exist. Absent
    // telemetry is OMITTED rather than zeroed: a node whose load is unknown
    // (not in gossip) must not graph as 0.0 — an idle-looking node is a node
    // you would send work to.
    body.push_str(&cluster_gauges(&state).await);

    (StatusCode::OK, [("content-type", "text/plain; version=0.0.4")], body)
}

/// The ten `noo_cluster_*` / `noo_node_*` series the shipped Grafana
/// dashboard queries, in Prometheus text format.
///
/// Per-node series carry a `node` label; the dashboard's tables key on it.
/// A value that is not known is not emitted — Prometheus reads an absent
/// series as "no data", which is the truth, whereas a 0 is a claim.
async fn cluster_gauges(state: &Arc<AppState>) -> String {
    let (nodes, _err) = crate::routes::cluster::collect_cluster_nodes(state).await;
    render_cluster_gauges(&nodes)
}

/// Pure renderer, so the emission rules — especially "absent telemetry is
/// omitted, not zeroed" — are testable without a cluster.
fn render_cluster_gauges(nodes: &[Value]) -> String {
    let mut out = String::with_capacity(1024);
    fn status_of(n: &Value) -> &str {
        n.get("status").and_then(|v| v.as_str()).unwrap_or("")
    }
    let count = |want: &str| nodes.iter().filter(|n| status_of(n) == want).count();
    let tier_of = |n: &Value| n.get("tier").and_then(|v| v.as_u64());

    let mut gauge = |name: &str, labels: &str, value: f64| {
        out.push_str(&format!("# TYPE {name} gauge\n{name}{labels} {value}\n"));
    };

    gauge("noo_cluster_nodes_total", "", nodes.len() as f64);
    gauge("noo_cluster_nodes_online", "", count("online") as f64);
    gauge("noo_cluster_nodes_busy", "", count("busy") as f64);
    gauge("noo_cluster_nodes_offline", "", count("offline") as f64);

    // Tiers 1-3 are the worker tiers the dashboard breaks out. Edge (4),
    // companion (5) and monitor (6) nodes are counted in the total but have
    // no panel of their own.
    for t in 1..=3u64 {
        let n = nodes.iter().filter(|n| tier_of(n) == Some(t)).count();
        gauge(&format!("noo_cluster_tier{t}_nodes"), "", n as f64);
    }

    let vram_total: f64 = nodes
        .iter()
        .filter_map(|n| n.get("vram_gb").and_then(|v| v.as_f64()))
        .sum();
    gauge("noo_cluster_vram_total_gb", "", vram_total);

    // Per-node. Emitted as one family with a `node` label rather than a
    // metric per node, so a node joining does not create a new series name.
    for n in nodes {
        let Some(id) = n.get("id").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else {
            continue;
        };
        let labels = format!("{{node=\"{}\"}}", crate::metrics::escape_label(id));
        // `current_load` is gossip-only; a node absent from gossip has an
        // UNKNOWN load, which is why this is a filter and not `unwrap_or(0.0)`.
        if let Some(load) = n.get("current_load").and_then(|v| v.as_f64()) {
            gauge("noo_node_load", &labels, load);
        }
        if let Some(t) = tier_of(n) {
            gauge("noo_node_tier", &labels, t as f64);
        }
        if let Some(v) = n.get("vram_gb").and_then(|v| v.as_f64()) {
            gauge("noo_node_vram_gb", &labels, v);
        }
        // What is running right now, not what the node could host.
        let running = match n.get("running_backends") {
            Some(Value::Object(m)) => Some(m.len()),
            Some(Value::Array(a)) => Some(a.len()),
            _ => None,
        };
        if let Some(r) = running {
            gauge("noo_node_backends_running", &labels, r as f64);
        }
    }
    out
}

fn shellexpand_home(path: &std::path::Path) -> std::path::PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── /health says less to a stranger ───────────────────────
    //
    // Until 2026-09-22 the full body went to anyone who could reach the
    // port: gateway version, engine, live peer count, every dependency's
    // health and every add-on's licence state. Nothing in the tree reads
    // those anonymously — the container healthcheck, the compose
    // healthcheck, the host watchdog and hostd's recreate gate all read
    // the status CODE — so the inventory was given away for nothing.

    fn deps_fixture() -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("postgresql".into(), json!({"healthy": true}));
        m.insert("nats".into(), json!({"healthy": true}));
        m
    }

    #[test]
    fn an_anonymous_caller_gets_liveness_and_nothing_else() {
        let b = health_body("healthy", 5, deps_fixture(), json!({"trellion": "enabled"}), false);
        let obj = b.as_object().expect("an object");
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["status"], "anonymous /health leaked {keys:?}");
        assert_eq!(b["status"], "healthy");
    }

    #[test]
    fn a_credential_gets_the_whole_picture() {
        let b = health_body("degraded", 5, deps_fixture(), json!({"trellion": "enabled"}), true);
        for k in ["status", "engine", "version", "peers", "dependencies", "addons"] {
            assert!(b.get(k).is_some(), "authenticated /health dropped {k}");
        }
        assert_eq!(b["peers"], 5);
        assert_eq!(b["dependencies"]["postgresql"]["healthy"], true);
        assert_eq!(b["addons"]["trellion"], "enabled");
    }

    /// `status` is the one field an anonymous consumer reads
    /// (`tests/integration/test_smoke_autonomy.py`), and a liveness
    /// endpoint that cannot say "degraded" is a status display.
    #[test]
    fn degraded_still_reaches_a_stranger() {
        let b = health_body("degraded", 0, deps_fixture(), json!({}), false);
        assert_eq!(b["status"], "degraded");
    }

    #[test]
    fn auth_failures_are_warning_replay_is_critical_success_is_info() {
        assert_eq!(audit_severity("auth_failure", "user_not_found"), "warning");
        assert_eq!(audit_severity("auth_failure", "account_locked"), "warning");
        assert_eq!(audit_severity("auth_failure", "bad_password"), "warning");
        assert_eq!(audit_severity("auth_failure", "refresh_replay"), "critical");
        assert_eq!(audit_severity("auth_success", "ok"), "info");
        assert_eq!(audit_severity("auth_logout", "ok"), "info");
    }

    // ── Bootstrap admin gate ──────────────────────────────────
    //
    // The three states the gate exists to separate. `Unknown` is the one
    // that matters: it is what a Postgres outage looks like, and it must
    // behave like "an admin exists", not like "no admin exists".

    #[test]
    fn fresh_install_no_admin_rows_allows_the_bootstrap_credential() {
        assert!(env_fallback_allowed(AdminCensus::NoneEnabled));
    }

    #[test]
    fn after_bootstrap_an_existing_admin_closes_the_env_fallback() {
        assert!(!env_fallback_allowed(AdminCensus::AtLeastOne));
    }

    #[test]
    fn db_unreachable_does_not_reopen_the_env_fallback() {
        // Unreachable ≠ absent. If this ever flips, a database outage
        // becomes a privilege escalation.
        assert!(!env_fallback_allowed(AdminCensus::Unknown));
    }

    #[test]
    fn only_none_enabled_opens_the_gate() {
        // Exhaustive: any future census state defaults to closed.
        let open: Vec<AdminCensus> = [
            AdminCensus::NoneEnabled,
            AdminCensus::AtLeastOne,
            AdminCensus::Unknown,
        ]
        .into_iter()
        .filter(|c| env_fallback_allowed(*c))
        .collect();
        assert_eq!(open, vec![AdminCensus::NoneEnabled]);
    }

    #[test]
    fn env_admin_is_only_a_candidate_when_configured_and_named() {
        std::env::set_var("NOO_ADMIN_USER", "bootstrap-admin");
        std::env::set_var("NOO_ADMIN_PASSWORD", "s3cret");

        // Wrong username → not a candidate at all (no DB hit needed).
        assert!(lookup_user_env("someone-else").is_none());

        let rec = lookup_user_env("bootstrap-admin").expect("candidate");
        assert_eq!(rec.username, "bootstrap-admin");
        assert!(!rec.disabled);
        // Bootstrap must be able to create the first real account.
        assert!(rec.scopes.contains(&"admin".to_string()));
        assert_eq!(rec.role, crate::auth::Role::Admin);
        // The record carries a bcrypt hash, never the plaintext.
        assert!(rec.hashed_password.starts_with("$2"));
        assert!(bcrypt::verify("s3cret", &rec.hashed_password).unwrap());

        // Unset password → no bootstrap identity at all.
        std::env::set_var("NOO_ADMIN_PASSWORD", "");
        assert!(lookup_user_env("bootstrap-admin").is_none());

        std::env::remove_var("NOO_ADMIN_USER");
        std::env::remove_var("NOO_ADMIN_PASSWORD");
    }

    #[test]
    fn dual_emit_derives_tier_scopes_from_role_and_keeps_extras() {
        use crate::auth::Role;
        let s = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // Role is the source of truth: stored tier scopes are NOT copied.
        assert_eq!(
            dual_emit_scopes(Role::User, &s(&["read", "write", "admin"])),
            s(&["read"]),
            "a demoted account's stale stored scopes must not leak into tokens"
        );
        assert_eq!(dual_emit_scopes(Role::Operator, &s(&["read"])), s(&["read", "write"]));
        assert_eq!(
            dual_emit_scopes(Role::Admin, &s(&[])),
            s(&["read", "write", "admin"])
        );
        // Non-tier scopes ride along: ingest (capability) and peer (confinement).
        assert_eq!(
            dual_emit_scopes(Role::User, &s(&["read", "ingest"])),
            s(&["read", "ingest"])
        );
        // `graph` (the six audience-scoped graph query routes) rides the same way.
        assert_eq!(
            dual_emit_scopes(Role::User, &s(&["read", "graph"])),
            s(&["read", "graph"])
        );
        assert_eq!(
            dual_emit_scopes(Role::User, &s(&["peer"])),
            s(&["read", "peer"]),
            "dropping 'peer' would UN-confine a peer-scoped account"
        );
    }

    #[test]
    fn extract_client_meta_trusts_forwarding_headers_only_behind_a_proxy() {
        let mut h = http::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        // Loopback peer = the reverse proxy. The client is what THAT proxy
        // appended — the rightmost entry — not the leftmost, which is
        // whatever the client wrote itself.
        let (_, ip) = extract_client_meta(&h, Some("127.0.0.1"));
        assert_eq!(ip.as_deref(), Some("10.0.0.1"));

        let mut h2 = http::HeaderMap::new();
        h2.insert("x-real-ip", "198.51.100.9".parse().unwrap());
        let (_, ip2) = extract_client_meta(&h2, Some("127.0.0.1"));
        assert_eq!(ip2.as_deref(), Some("198.51.100.9"));

        // A direct (untrusted) peer cannot choose what the audit log says:
        // its own socket address is recorded, not its header (U13).
        let (_, spoofed) = extract_client_meta(&h, Some("198.51.100.42"));
        assert_eq!(spoofed.as_deref(), Some("198.51.100.42"));

        // No forwarding headers → the peer; no peer either → no IP.
        let (_, ip3) = extract_client_meta(&http::HeaderMap::new(), Some("203.0.113.9"));
        assert_eq!(ip3.as_deref(), Some("203.0.113.9"));
        let (_, ip4) = extract_client_meta(&http::HeaderMap::new(), None);
        assert_eq!(ip4, None);
    }

    #[test]
    fn cluster_gauges_omit_unknown_telemetry_rather_than_zeroing_it() {
        // n2 is not in gossip: no `current_load`. Emitting 0.0 would graph it
        // as completely idle, which is the node an operator sends work to.
        let nodes = vec![
            json!({"id": "n1", "tier": 1, "status": "online", "current_load": 0.25,
                   "vram_gb": 24.0, "running_backends": {"vllm": "qwen3:8b"}}),
            json!({"id": "n2", "tier": 3, "status": "offline", "vram_gb": 0.0}),
        ];
        let out = render_cluster_gauges(&nodes);

        assert!(out.contains("noo_cluster_nodes_total 2\n"));
        assert!(out.contains("noo_cluster_nodes_online 1\n"));
        assert!(out.contains("noo_cluster_nodes_offline 1\n"));
        assert!(out.contains("noo_cluster_nodes_busy 0\n"));
        assert!(out.contains("noo_cluster_tier1_nodes 1\n"));
        assert!(out.contains("noo_cluster_tier3_nodes 1\n"));
        assert!(out.contains("noo_cluster_vram_total_gb 24\n"));

        assert!(out.contains("noo_node_load{node=\"n1\"} 0.25\n"));
        assert!(out.contains("noo_node_backends_running{node=\"n1\"} 1\n"));
        // The whole point: no load series at all for the node that reported none.
        assert!(!out.contains("noo_node_load{node=\"n2\"}"), "unknown load must be absent, not 0");
        assert!(!out.contains("noo_node_backends_running{node=\"n2\"}"));
        // Tier IS known for n2, so it is emitted.
        assert!(out.contains("noo_node_tier{node=\"n2\"} 3\n"));
    }

    #[test]
    fn a_node_without_an_id_produces_no_per_node_series() {
        // An unlabelled series would collide with every other node's.
        let nodes = vec![json!({"tier": 2, "status": "online", "current_load": 0.5})];
        let out = render_cluster_gauges(&nodes);
        assert!(out.contains("noo_cluster_nodes_total 1\n"));
        assert!(!out.contains("noo_node_load"));
    }

    // ── R5/D6: the placeholder JWT secret ─────────────────────────────

    fn a_user() -> UserRecord {
        UserRecord {
            username: "alice".into(),
            hashed_password: "x".into(),
            disabled: false,
            scopes: vec!["read".into()],
            role: crate::auth::Role::User,
        }
    }

    /// Minting with the public placeholder produces a FORGEABLE token, and
    /// the middleware refuses those anyway — so the mint must refuse first.
    /// FAILS on the unfixed code, which happily signed with it.
    ///
    /// Serialised with the `/auth/me` test below via one env var, so the two
    /// live in one `#[test]` rather than racing each other: cargo runs tests
    /// in the same process and `set_var` is global.
    #[test]
    fn the_insecure_default_secret_mints_nothing_and_validates_nothing() {
        let prev = std::env::var("NOO_JWT_SECRET").ok();

        // 1. Unset entirely → jwt_secret() falls back to the placeholder.
        std::env::remove_var("NOO_JWT_SECRET");
        std::env::remove_var("NOO_SECRET_NOO_JWT_SECRET");
        assert!(
            matches!(issue_access_token(&a_user()), Err(TokenIssueError::InsecureSecret)),
            "an unset NOO_JWT_SECRET must not mint a token"
        );

        // 2. Explicitly set TO the placeholder — the shape a .env.example
        //    copy-paste produces.
        std::env::set_var("NOO_JWT_SECRET", crate::auth::INSECURE_DEFAULT_JWT_SECRET);
        assert!(matches!(
            issue_access_token(&a_user()),
            Err(TokenIssueError::InsecureSecret)
        ));
        // …and the predicate /auth/me now shares with the middleware agrees.
        assert!(crate::auth::jwt_secret_is_insecure(&jwt_secret()));

        // 3. Empty string — the other state the old `is_empty()` check caught,
        //    which must keep failing.
        std::env::set_var("NOO_JWT_SECRET", "");
        assert!(crate::auth::jwt_secret_is_insecure(&jwt_secret()));

        // 4. A real secret mints, so the guard is a gate and not a wall.
        std::env::set_var("NOO_JWT_SECRET", "a-real-secret-value-not-the-placeholder");
        assert!(!crate::auth::jwt_secret_is_insecure(&jwt_secret()));
        let (token, expires_in) =
            issue_access_token(&a_user()).expect("a configured secret must mint");
        assert!(!token.is_empty() && expires_in > 0);

        match prev {
            Some(v) => std::env::set_var("NOO_JWT_SECRET", v),
            None => std::env::remove_var("NOO_JWT_SECRET"),
        }
    }

    /// `/auth/me` must use the SAME predicate as the middleware, not its own
    /// `is_empty()`. Pinned against the source so a future edit that
    /// reintroduces the narrower check fails here.
    #[test]
    fn auth_me_uses_the_shared_insecure_secret_predicate() {
        let src = include_str!("core.rs");
        let start = src.find("async fn auth_me(").expect("handler present");
        let rest = &src[start..];
        let end = rest.find("\n// ── User lookup helpers").unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("jwt_secret_is_insecure(&secret)"),
            "/auth/me must refuse via the shared predicate"
        );
        assert!(
            !body.contains("if secret.is_empty()"),
            "the narrower is_empty() check is exactly the D6 bug — it accepts the placeholder"
        );
    }

    // ── R6: /auth/token abuse controls ────────────────────────────────

    /// The per-subject bucket actually stops at its limit — and keeps
    /// stopping. A limiter that resets on every call is the classic
    /// passes-without-checking failure, so the over-limit case is asserted
    /// twice.
    #[test]
    fn the_local_login_bucket_stops_at_the_limit() {
        let key = "test-bucket-alpha";
        for i in 1..=5u32 {
            assert_eq!(local_login_bucket(key, true), i);
        }
        // Peeking must NOT consume: the bootstrap-failure gate reads this.
        assert_eq!(local_login_bucket(key, false), 5);
        assert_eq!(local_login_bucket(key, false), 5);
        // Consuming past the limit keeps climbing, so `count <= limit` stays
        // false rather than wrapping back to allowed.
        assert_eq!(local_login_bucket(key, true), 6);
        assert!(local_login_bucket(key, false) > 5);
    }

    /// Separate namespaces must not share a budget: an attacker hammering
    /// one username must not lock out a different one, and the IP bucket
    /// must not be drained by the username bucket.
    #[test]
    fn login_buckets_are_keyed_independently() {
        assert_eq!(local_login_bucket("login-user:bravo", true), 1);
        assert_eq!(local_login_bucket("login-user:charlie", true), 1);
        assert_eq!(local_login_bucket("login-ip:bravo", true), 1);
        assert_eq!(local_login_bucket("login-user:bravo", false), 1);
    }

    /// The caps are the point: the global 600/min/IP limiter is 600 bcrypt
    /// verifies on this route, and five failures lock a real account. If
    /// someone raises these back toward the global cap, the control is gone.
    ///
    /// `const` blocks, so raising a cap past its bound is a BUILD error
    /// rather than a red test — the values are compile-time known, and an
    /// invariant that can be checked then should be. (It is also what
    /// `clippy::assertions_on_constants` asks for.)
    ///
    /// Verified by setting `LOGIN_IP_LIMIT` to 600: `error[E0080]:
    /// evaluation panicked: per-IP login cap must stay tight`. Note WHERE
    /// that lands — post-monomorphization const evaluation runs at codegen,
    /// so `cargo check --tests` compiles this happily and only `cargo
    /// test` / `cargo clippy` / a real build catch it. Do not take a green
    /// `cargo check` as evidence these bounds hold.
    #[test]
    fn the_login_caps_stay_far_below_the_global_limiter() {
        const { assert!(LOGIN_IP_LIMIT <= 60, "per-IP login cap must stay tight") };
        const {
            assert!(
                LOGIN_USER_LIMIT < LOGIN_IP_LIMIT,
                "one username must be cheaper to exhaust than a whole IP"
            )
        };
        const {
            assert!(
                BOOTSTRAP_FAILURE_LIMIT == 5,
                "match the noo_users lockout threshold"
            )
        };
    }

    /// The bootstrap admin's failure gate and the decoy hash must both be
    /// wired into `auth_token`, in the right order: the gate BEFORE bcrypt
    /// (or it is only a log line), the decoy ON the not-found path (or the
    /// endpoint is an enumeration oracle).
    #[test]
    fn auth_token_gates_before_bcrypt_and_pays_the_decoy_cost() {
        let src = include_str!("core.rs");
        let start = src.find("async fn auth_token(").expect("handler present");
        let rest = &src[start..];
        let end = rest.find("\n/// POST /auth/refresh").unwrap_or(rest.len());
        let body = &rest[..end];

        let rate_gate = body.find("login_rate_refusal(").expect("rate gate present");
        let decoy = body.find("decoy_hash()").expect("decoy verify present");
        let boot_gate = body
            .find("bootstrap_failures_remaining(")
            .expect("bootstrap gate present");
        let verify = body.find("bcrypt::verify(&creds.password, &user.hashed_password)")
            .expect("the real verify");
        let lookup = body.find("lookup_user_db(").expect("db lookup");

        assert!(rate_gate < lookup, "rate limiting must precede the DB work it protects");
        assert!(decoy < verify, "the unknown-user decoy is on the early return path");
        assert!(boot_gate < verify, "the bootstrap lockout must gate BEFORE bcrypt");
    }

    /// The host ticket rides the same rate gate as a password login, and is
    /// dispatched before any password work.
    #[test]
    fn the_host_ticket_grant_is_rate_limited_like_a_login() {
        let src = include_str!("core.rs");
        let start = src.find("async fn auth_token(").expect("handler present");
        let body = &src[start..];
        let body = &body[..body.find("\nasync fn issue_login(").expect("issue_login follows")];
        let rate_gate = body.find("login_rate_refusal(").expect("rate gate present");
        let ticket = body.find("== Some(HOST_TICKET_GRANT)").expect("the host ticket grant is dispatched");
        let lookup = body.find("lookup_user_db(").expect("db lookup");
        assert!(rate_gate < ticket, "a ticket guess must cost the same rate budget as a password guess");
        assert!(ticket < lookup, "the ticket is dispatched before the password path");
    }

    /// A ticket logs in once, for the account it names, before it expires.
    /// Against the real migration's table. Skips without NOO_BROKER_TEST_DSN.
    #[tokio::test]
    async fn a_host_ticket_is_spent_exactly_once() {
        let Some(dsn) = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty()) else {
            return;
        };
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await.expect("connect");
        let _ = sqlx::raw_sql("DROP DATABASE IF EXISTS host_ticket_test (FORCE)").execute(&admin).await;
        sqlx::raw_sql("CREATE DATABASE host_ticket_test").execute(&admin).await.expect("create scratch db");
        let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!("{head}/host_ticket_test"))
            .await
            .expect("connect scratch");
        let m = crate::mesh_migrate::MIGRATIONS
            .iter()
            .find(|m| m.revision == "081_host_login_tickets")
            .expect("the migration exists");
        sqlx::raw_sql(m.sql).execute(&db).await.expect("the migration applies");
        let put = |raw: &'static str, user: &'static str, ttl: &'static str| {
            let db = db.clone();
            async move {
                sqlx::query(sqlx::AssertSqlSafe(format!(
                    "INSERT INTO noo_host_login_tickets (token_hash, username, purpose, expires_at) \
                     VALUES ($1, $2, 'test', now() + interval '{ttl}')"
                )))
                .bind(crate::auth_refresh::hash_token(raw))
                .bind(user)
                .execute(&db)
                .await
                .expect("insert");
            }
        };
        put("noo-ht-a", "admin", "5 minutes").await;
        put("noo-ht-old", "admin", "-1 minutes").await;
        assert_eq!(spend_host_ticket(&db, "noo-ht-a", "mallory").await.unwrap(), None, "for another account");
        assert_eq!(spend_host_ticket(&db, "noo-ht-a", "admin").await.unwrap().as_deref(), Some("test"));
        assert_eq!(spend_host_ticket(&db, "noo-ht-a", "admin").await.unwrap(), None, "spent once only");
        assert_eq!(spend_host_ticket(&db, "noo-ht-old", "admin").await.unwrap(), None, "expired");
        assert_eq!(spend_host_ticket(&db, "noo-ht-never", "admin").await.unwrap(), None, "unknown");
        drop(db);
        let _ = sqlx::raw_sql("DROP DATABASE IF EXISTS host_ticket_test (FORCE)").execute(&admin).await;
    }
}
