// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Refresh-token issuance, verification, rotation, and revocation.
//!
//! Pairs with the short-lived JWT access token from `routes/core.rs`.
//! Refresh tokens are:
//!
//! - **Random 32 bytes**, base64-url encoded (43 chars) behind the
//!   `noo-rt-` prefix ([`REFRESH_TOKEN_PREFIX`]).
//! - **Hashed (sha256) before storage**. The raw token only exists in
//!   the response cookie + the client's cookie jar; even a DB dump
//!   doesn't reveal usable refreshes.
//! - **Set as `HttpOnly; Secure; SameSite=Strict; Path=/api/auth`** so
//!   JS cannot read them — XSS in the dashboard can't steal a refresh
//!   the way it could a localStorage JWT.
//! - **Rotated on every successful use**: each refresh request issues
//!   a fresh refresh token, marks the old one revoked, and chains
//!   `rotated_from` to the previous row. If a *revoked* token is ever
//!   presented again, that's a strong signal the chain has been
//!   stolen — the entire chain (and all the user's other live
//!   refreshes) is revoked and a `critical` audit row is written.
//!
//! The rotation is **atomic**, and that is load-bearing rather than
//! tidy. It used to be four statements —
//! `lookup` → mint → `store` → `revoke` — with the revoked-token
//! check reading a row nothing held. Two concurrent presentations of
//! the SAME refresh token therefore both passed the check, both minted
//! an access token, and both stored a rotated child: two live chains
//! from one token, and the replay detector never fired, because by the
//! time either writer revoked anything both readers had already seen
//! `revoked_at IS NULL`. That is precisely the window a stolen cookie
//! races, and the whole point of rotation is to close it.
//!
//! [`claim_token`] replaces the read with a single conditional write —
//! `UPDATE … WHERE revoked_at IS NULL RETURNING …` — so the row itself
//! decides. Postgres row-locks the second writer until the first
//! commits, then re-evaluates the predicate and returns nothing: exactly
//! one caller wins, and the loser is indistinguishable from a replay
//! and treated as one.
//!
//! The access token (JWT) stays as the bearer for every API call;
//! refresh tokens never travel as bearers and never appear in the
//! Authorization header.

use std::env;
use std::time::Duration;

use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

pub const REFRESH_COOKIE_NAME: &str = "noo_refresh";

/// How long a refresh token is valid. Default 30 days; override via
/// `NOO_REFRESH_TOKEN_DAYS`.
pub fn refresh_ttl_days() -> i64 {
    env::var("NOO_REFRESH_TOKEN_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// Default access-token TTL — short by design (15 min). Refresh
/// rotates the access token transparently from the dashboard.
/// Backwards-compatible env var: `NOO_TOKEN_EXPIRE_MINUTES`.
pub fn default_access_minutes() -> i64 {
    env::var("NOO_TOKEN_EXPIRE_MINUTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15)
}

/// What every refresh token minted starts with, so a
/// log scrubber can redact it by shape (`refresh-token` row) instead of
/// guessing from a bare 43-character run.
pub const REFRESH_TOKEN_PREFIX: &str = "noo-rt-";

/// The same for a node-enrolment bootstrap token (`routes/bootstrap.rs`).
pub const BOOTSTRAP_TOKEN_PREFIX: &str = "noo-bt-";

/// 32 bytes of CSPRNG → URL-safe base64, unpadded: 43 characters. The body
/// of both token kinds; never handed out without its prefix.
fn random_body() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Generate a fresh raw refresh token: `noo-rt-` + 43 base64url.
///
/// Verification needs no change for the prefix and none is made: every
/// verifier ([`lookup_token`], [`claim_token`]) hashes the WHOLE presented
/// string, and a row stores the hash of the whole string it was minted as.
/// So a new cookie finds its `noo-rt-…` row, and a cookie minted before the
/// prefix (bare 43 characters, still in a browser) finds its own bare row —
/// no session is logged out by the roll, and its first refresh rotates it
/// onto a prefixed successor. Strip-then-hash would have orphaned every
/// live cookie.
pub fn generate_raw_token() -> String {
    format!("{REFRESH_TOKEN_PREFIX}{}", random_body())
}

/// Generate a fresh node-enrolment bootstrap token: `noo-bt-` + 43
/// base64url. Stored as [`hash_token`] of the whole string, and
/// `/api/cluster/bootstrap` hashes what it is presented, so a token minted
/// before the prefix (stored as the hash of the bare body, TTL ≤ 24 h)
/// still redeems.
pub fn generate_bootstrap_token() -> String {
    format!("{BOOTSTRAP_TOKEN_PREFIX}{}", random_body())
}

/// Prefix of a kiosk SEAT enrolment token (i77). Distinct from a node's
/// `noo-bt-` so a paste says what it is — but the separation that matters is
/// the TABLE: a seat token's hash lives in `noo_seat_tokens`, which only
/// `/api/cluster/seat-enroll` reads, and `/api/cluster/bootstrap` never does.
pub const SEAT_TOKEN_PREFIX: &str = "noo-st-";

/// A fresh one-time seat enrolment token: `noo-st-` + 43 base64url.
pub fn generate_seat_token() -> String {
    format!("{SEAT_TOKEN_PREFIX}{}", random_body())
}

/// Hash a raw refresh token for storage. Hex-encoded sha256 is plenty
/// — the input is already 256 bits of entropy, so we don't need a
/// stretching KDF.
pub fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    hex::encode(digest)
}

/// Build the `Set-Cookie` header value for a refresh token.
///
/// Always `Secure`: the gateway serves HTTPS and nothing else
/// (`tls::require_server_material` refuses to start without its leaf), so
/// there is no plain-HTTP session for a non-`Secure` cookie to serve.
pub fn build_refresh_cookie(raw_token: &str, ttl_days: i64) -> Cookie<'static> {
    let mut cookie = Cookie::new(REFRESH_COOKIE_NAME, raw_token.to_string());
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/api/auth");
    cookie.set_max_age(time::Duration::seconds(ttl_days * 86400));
    cookie
}

/// Build the `Set-Cookie` header to *clear* the refresh cookie on
/// logout. Same name + path as the live cookie, with `Max-Age=0`.
pub fn build_clear_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::new(REFRESH_COOKIE_NAME, "");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/api/auth");
    cookie.set_max_age(time::Duration::ZERO);
    cookie
}

/// Insert a freshly-issued refresh token into the DB. Caller has the
/// raw token (only used to set the response cookie); DB only ever
/// sees the hash.
///
/// `rotated_from` is `Some(prev_id)` when this token is replacing a
/// previous one (during a refresh flow); `None` for fresh logins.
/// Generic over the executor so the same INSERT serves a fresh login
/// (against the pool) and a rotation (inside the claiming transaction,
/// where the new row must land or not land together with the old row's
/// revocation).
#[allow(clippy::too_many_arguments)]
pub async fn store_token<'e, E: sqlx::PgExecutor<'e>>(
    db: E,
    user_id: &str,
    raw_token: &str,
    expires_at: DateTime<Utc>,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
    rotated_from: Option<String>,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let token_hash = hash_token(raw_token);
    sqlx::query(
        "INSERT INTO noo_refresh_tokens \
         (id, user_id, token_hash, expires_at, user_agent, ip_address, rotated_from) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(user_agent)
    .bind(ip_address)
    .bind(rotated_from)
    .execute(db)
    .await?;
    Ok(id)
}

/// A lookup result for a refresh token presented by the client.
#[derive(Debug)]
pub struct LookupResult {
    pub id: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Look up a refresh token by its raw value (hashed for the query).
/// Returns `None` only when the token has never existed; revoked /
/// expired tokens still return their record so the caller can react
/// (e.g. theft detection on revoked re-use).
pub async fn lookup_token(
    db: &PgPool,
    raw_token: &str,
) -> Result<Option<LookupResult>, sqlx::Error> {
    let token_hash = hash_token(raw_token);
    let row = sqlx::query(
        "SELECT id::text, user_id, expires_at, revoked_at \
         FROM noo_refresh_tokens WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| LookupResult {
        id: r.get(0),
        user_id: r.get(1),
        expires_at: r.get(2),
        revoked_at: r.get(3),
    }))
}

/// What happened when a caller tried to claim a presented refresh token.
#[derive(Debug)]
pub enum Claim {
    /// This caller won the row: it was live, and is now revoked and
    /// stamped `last_used_at`. Exactly one concurrent caller ever sees
    /// this for a given token.
    Won(LookupResult),
    /// The row exists but was already revoked. That is EITHER a genuine
    /// replay of a spent token OR the losing side of a concurrent
    /// rotation, and the caller tells them apart with
    /// [`successor_state`] — see [`Succession`]. `user_id` so the caller
    /// can sweep the chain when it is the former.
    AlreadySpent { id: String, user_id: String },
    /// No such token hash has ever existed (a forgery, or a row pruned
    /// long after expiry). Nothing to sweep.
    Unknown,
}

/// Atomically claim a presented refresh token.
///
/// One conditional `UPDATE` does the whole decision: it matches the hash,
/// requires `revoked_at IS NULL`, sets `revoked_at`/`last_used_at`, and
/// RETURNs the row. Whether the token was spendable and the act of
/// spending it are the same statement, so there is no window between
/// them for a second presentation to slip through.
///
/// Run this on a **transaction**, not the pool: the caller still has to
/// mint and store the replacement, and if that fails the claim must
/// unwind so the user's live token is not thrown away by a 500. Holding
/// the row lock for that span is also what makes the concurrent loser
/// block-then-lose rather than read stale.
pub async fn claim_token(
    conn: &mut sqlx::PgConnection,
    raw_token: &str,
) -> Result<Claim, sqlx::Error> {
    let token_hash = hash_token(raw_token);
    let claimed = sqlx::query(
        "UPDATE noo_refresh_tokens \
            SET revoked_at = NOW(), last_used_at = NOW() \
          WHERE token_hash = $1 AND revoked_at IS NULL \
      RETURNING id::text, user_id, expires_at, revoked_at",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(r) = claimed {
        return Ok(Claim::Won(LookupResult {
            id: r.get(0),
            user_id: r.get(1),
            expires_at: r.get(2),
            revoked_at: r.get(3),
        }));
    }
    // Zero rows means one of two things, and the difference matters: an
    // already-revoked row is a replay (sweep the chain, `critical` audit),
    // an absent row is a forgery with no chain to sweep.
    let row = sqlx::query(
        "SELECT id::text, user_id FROM noo_refresh_tokens WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match row {
        Some(r) => Claim::AlreadySpent { id: r.get(0), user_id: r.get(1) },
        None => Claim::Unknown,
    })
}

/// Mark a refresh token as revoked. Idempotent.
pub async fn revoke_token(db: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE noo_refresh_tokens SET revoked_at = NOW() \
         WHERE id = $1::uuid AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

// `touch_token` was DELETED with the atomic claim. It was a third
// statement stamping `last_used_at` after the revoke, and `claim_token` now
// sets both columns in the statement that decides — so the stamp cannot
// disagree with the revocation, and there is no separate write to forget.

/// What the chain looks like below a token that was presented after it was
/// spent. This is what tells a stolen chain apart from two browser tabs
/// refreshing in the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Succession {
    /// How long ago the presented token was spent. `None` when the row is
    /// somehow not revoked (it was, by definition, to get here).
    pub spent_secs_ago: Option<i64>,
    /// How many rows chain `rotated_from` to it. Exactly one under the
    /// atomic claim; a database written by the pre-R7 code can hold two,
    /// which is itself the evidence of the bug and is never "benign".
    pub successors: i64,
    /// Successors that are still live AND have never themselves been
    /// claimed (`revoked_at IS NULL AND last_used_at IS NULL`).
    pub fresh_successors: i64,
}

impl Succession {
    /// Is this a benign double-refresh rather than a stolen chain?
    ///
    /// Three conditions, all from columns the table already had:
    ///
    /// 1. the token was spent **within `grace`** — a thief presenting a
    ///    cookie harvested earlier is outside it;
    /// 2. it has **exactly one** successor — the shape the atomic claim
    ///    produces, so two means the row predates the fix and the chain
    ///    is not trustworthy;
    /// 3. that successor is **live and unused** — nobody has spent the
    ///    replacement yet, so the legitimate holder has not gone on to do
    ///    anything with it and handing the loser a retry costs nothing.
    ///
    /// Condition 3 is only a clean signal because of R7: `last_used_at`
    /// used to be stamped by a separate `touch_token` statement that ran
    /// after the revoke, so "used" and "revoked" could disagree. The claim
    /// now sets both in the statement that decides, so `last_used_at IS
    /// NULL` means exactly "this row has never been claimed".
    ///
    /// A `grace` of zero disables the window: every re-presentation is a
    /// replay, which is the pre-existing behaviour.
    pub fn is_benign_double_refresh(&self, grace: Duration) -> bool {
        if grace.is_zero() {
            return false;
        }
        match self.spent_secs_ago {
            Some(secs) if secs >= 0 && (secs as u64) <= grace.as_secs() => {}
            _ => return false,
        }
        self.successors == 1 && self.fresh_successors == 1
    }
}

/// Read the succession below a spent token.
///
/// Keyed on `(id, user_id)` so the query can use
/// `ix_noo_refresh_tokens_user_expires`'s leading column; there is no index
/// on `rotated_from`, and adding one is not worth a migration for a lookup
/// that runs only on the already-exceptional replay path, against the rows
/// of a single user.
///
/// A token revoked by LOGOUT, by the disabled-user path, or on expiry has no
/// successor row at all, so those can never be mistaken for a rotation —
/// which is why the successor is the test rather than `revoked_at` alone.
pub async fn successor_state(
    db: &PgPool,
    token_id: &str,
    user_id: &str,
) -> Result<Option<Succession>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT EXTRACT(EPOCH FROM (NOW() - p.revoked_at))::bigint, \
                COUNT(c.id), \
                COUNT(c.id) FILTER \
                  (WHERE c.revoked_at IS NULL AND c.last_used_at IS NULL) \
           FROM noo_refresh_tokens p \
           LEFT JOIN noo_refresh_tokens c ON c.rotated_from = p.id \
          WHERE p.id = $1::uuid AND p.user_id = $2 \
          GROUP BY p.revoked_at",
    )
    .bind(token_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| Succession {
        spent_secs_ago: r.get(0),
        successors: r.get(1),
        fresh_successors: r.get(2),
    }))
}

/// How long after a rotation a re-presentation of the OLD token is read as
/// a benign double-refresh rather than a stolen chain
/// (`NOO_REFRESH_GRACE_SECS`, default 10 s, `0` disables).
///
/// Ten seconds is chosen against what it has to cover: two browser tabs
/// whose access tokens expire in the same second and which both reach
/// `/auth/refresh` before either `Set-Cookie` lands. That is a
/// sub-second race in practice; ten seconds is slack for a slow link, not
/// a window sized to anything an attacker controls.
///
/// The cost is bounded and worth naming: a thief racing the legitimate
/// user inside the window gets a `409` and no session — the successor's
/// raw value exists only in the winner's cookie jar and is unrecoverable
/// from the hash — but the `critical` audit row is delayed until the thief
/// tries again outside the window. Detection is deferred, never lost, and
/// the contended presentation is logged when it happens.
pub fn refresh_grace() -> Duration {
    let secs = env::var("NOO_REFRESH_GRACE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10);
    Duration::from_secs(secs)
}

/// Theft response: revoke every live refresh for the user. Triggered
/// when a previously-revoked token is presented again — the most
/// likely cause is that the chain has been stolen and used somewhere
/// the legitimate user no longer controls.
pub async fn revoke_all_for_user(db: &PgPool, user_id: &str) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE noo_refresh_tokens SET revoked_at = NOW() \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

/// Convenience: how long until a `chrono::DateTime` from now, as a
/// `std::time::Duration`. Returns Duration::ZERO if already past.
pub fn time_until(when: DateTime<Utc>) -> Duration {
    let secs = (when - Utc::now()).num_seconds().max(0) as u64;
    Duration::from_secs(secs)
}

#[cfg(test)]
mod prefix_tests {
    use super::*;

    /// The refresh cookie and its clearing twin are `Secure` with no env at
    /// all (1242 finding 4). The gateway cannot boot without its TLS leaf
    /// (`tls::require_server_material`), so `NOO_TLS_CERT` and the retired
    /// `NOO_BEHIND_TLS_PROXY` decided nothing; an old `.env` that still sets
    /// the proxy variable is ignored because nothing reads it.
    #[test]
    fn refresh_cookies_are_always_secure() {
        assert_eq!(build_refresh_cookie("noo-rt-x", 1).secure(), Some(true));
        assert_eq!(build_clear_cookie().secure(), Some(true));
        for (name, src) in [("auth_refresh.rs", include_str!("auth_refresh.rs")), ("routes/core.rs", include_str!("routes/core.rs"))] {
            let code = src.split("#[cfg(test)]").next().unwrap_or(src);
            assert!(!code.contains("NOO_BEHIND_TLS_PROXY"), "{name} reads the retired proxy switch again");
            assert!(!code.contains("set_secure(secure)"), "{name}: the cookie's Secure flag is a parameter again");
        }
    }

    fn body_is_43_base64url(body: &str) -> bool {
        body.len() == 43
            && body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    }

    /// every new mint carries its kind's prefix, over the
    /// same 43-character body as before.
    #[test]
    fn new_mints_are_prefixed() {
        let rt = generate_raw_token();
        let body = rt.strip_prefix(REFRESH_TOKEN_PREFIX).unwrap_or_else(|| {
            panic!("a refresh token must start with {REFRESH_TOKEN_PREFIX}: {rt}")
        });
        assert!(body_is_43_base64url(body), "refresh body: {body}");

        let bt = generate_bootstrap_token();
        let body = bt.strip_prefix(BOOTSTRAP_TOKEN_PREFIX).unwrap_or_else(|| {
            panic!("a bootstrap token must start with {BOOTSTRAP_TOKEN_PREFIX}: {bt}")
        });
        assert!(body_is_43_base64url(body), "bootstrap body: {body}");
        assert_ne!(REFRESH_TOKEN_PREFIX, BOOTSTRAP_TOKEN_PREFIX);
    }

    /// Both forms verify: the verifier hashes the WHOLE presented string, so
    /// a prefixed token finds its prefixed row and a bare token minted
    /// before the prefix finds its bare row. Neither finds the other's —
    /// the prefix is part of the secret, not decoration stripped off.
    #[test]
    fn verifier_hashes_the_whole_string_so_both_forms_verify() {
        let legacy = random_body();
        let stored_legacy = hash_token(&legacy);
        assert_eq!(hash_token(&legacy), stored_legacy, "a pre-prefix token must still verify");

        let new = generate_raw_token();
        let stored_new = hash_token(&new);
        assert_eq!(hash_token(&new), stored_new);

        let body = new.strip_prefix(REFRESH_TOKEN_PREFIX).unwrap();
        assert_ne!(hash_token(body), stored_new, "the stored hash covers the prefix");
    }
}
