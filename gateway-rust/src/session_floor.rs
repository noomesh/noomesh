// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Per-account "not before" floor: how an account change ends a session that
//! is already in flight.
//!
//! An access JWT is self-contained and (for a plain user token) is never
//! re-read against the database, so `disable`, a role or scope change, a
//! password reset or a logout used to leave the bearer working until it
//! expired (15 minutes by default) and let an open dashboard socket reconnect
//! with it after the close frame. The floor closes that: each of those events
//! records `noo:auth:notbefore:<account> = <unix seconds>` and
//! `require_any_auth` — the one gate every bearer path passes, including the
//! `/ws/*` handshake — refuses a token whose `iat` is older than the floor.
//!
//! ## Failure semantics (decided, not defaulted)
//!
//! - **Written**: always to this process's memory first, then to Redis with a
//!   TTL of one maximum access-token lifetime plus margin (after that no
//!   token that predates the floor can still be valid, so the key retires
//!   itself). A Redis write that fails is reported to the caller
//!   (`shared: false`), logged, and does NOT fail the account change: the
//!   database row is already authoritative (refresh and login refuse it), the
//!   local floor already protects this process, and rolling back a disable
//!   because a cache was down would be the worse failure.
//! - **Read, Redis unavailable or erroring**: the process-local floors still
//!   apply (this is the rate limiter's precedent: degrade to a local control,
//!   never to no control). We do NOT fail closed on a Redis outage: that would
//!   refuse every authenticated request in the installation, operators trying
//!   to repair Redis included. The residual window is a floor written by a
//!   different gateway instance, or before this process restarted, while Redis
//!   is down — bounded by the token lifetime, and logged.
//! - **Token without an `iat`** while a floor exists for its account: refused
//!   (every token this gateway mints carries one; a floor makes "cannot prove
//!   it is newer" mean no).
//! - **No Redis configured at all**: local floors only; they do not survive a
//!   restart. Documented in the security reference.
//!
//! The floor is per ACCOUNT (`account_of(sub)`), so a name carrying a
//! connection label (`alice/laptop`) shares the account's floor.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::state::AppState;

const KEY_PREFIX: &str = "noo:auth:notbefore:";
/// How long a lookup (including "no floor") is trusted before Redis is asked
/// again. Bounds the Redis load to one GET per active account per interval and
/// the cross-instance propagation delay to the same number.
const RECHECK: Duration = Duration::from_secs(2);
/// Redis round-trip budget on the auth path.
const REDIS_BUDGET: Duration = Duration::from_millis(250);
/// Entries kept; past this the map is cleared (a floor re-learns from Redis).
const MAP_CAP: usize = 10_000;

/// Why a floor is being raised. Decides whether the floor sits one second
/// ahead of now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// An operator changed the account (disable, role, scopes, password): a
    /// token minted in the SAME second as the change must die too, and the
    /// person re-authenticates by hand anyway.
    AccountChange,
    /// The person logged out: tokens minted from now on are theirs.
    Logout,
}

/// How long a floor stays: the longest access token this gateway mints
/// (`NOO_TOKEN_EXPIRE_MINUTES`, never less than the 15-minute default),
/// plus the verifier's 60 s leeway and a margin.
pub fn floor_ttl_secs() -> i64 {
    crate::auth_refresh::default_access_minutes().max(15) * 60 + 300
}

/// The floor value for `reason` at unix time `now`.
pub fn floor_for(reason: Reason, now: i64) -> i64 {
    match reason {
        Reason::AccountChange => now + 1,
        Reason::Logout => now,
    }
}

/// Whether a token is refused by a floor. Pure.
pub fn refused(iat: Option<i64>, floor: i64) -> bool {
    if floor <= 0 {
        return false;
    }
    match iat {
        Some(i) => i < floor,
        None => true,
    }
}

/// `iat` of a JWT whose signature was ALREADY verified. Reads the payload
/// segment only; never use it to trust an unverified token.
pub fn token_iat(token: &str) -> Option<i64> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("iat")?.as_i64()
}

#[derive(Clone, Copy)]
struct Entry {
    /// Highest floor known for the account (0 = none).
    floor: i64,
    /// When a LOCALLY-raised floor stops mattering.
    floor_until: Instant,
    /// When Redis was last asked.
    checked: Instant,
}

/// The in-process half. A type of its own so tests drive it without the
/// global or a Redis.
#[derive(Default)]
pub struct Local {
    map: Mutex<HashMap<String, Entry>>,
}

impl Local {
    pub fn raise(&self, account: &str, floor: i64, ttl: Duration, now: Instant) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= MAP_CAP && !m.contains_key(account) {
            m.clear();
        }
        let e = m.entry(account.to_string()).or_insert(Entry { floor: 0, floor_until: now, checked: now });
        if floor >= e.floor || e.floor_until <= now {
            e.floor = floor;
            e.floor_until = now + ttl;
        }
        // A fresh local write is authoritative for RECHECK; Redis will be
        // consulted after it.
        e.checked = now;
    }

    /// The floor to apply now and whether Redis should be asked first.
    pub fn lookup(&self, account: &str, now: Instant) -> (i64, bool) {
        let m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        match m.get(account) {
            Some(e) => {
                let live = if e.floor_until > now { e.floor } else { 0 };
                (live, now.duration_since(e.checked) >= RECHECK)
            }
            None => (0, true),
        }
    }

    /// Fold a Redis answer in (`remote` = 0 for absent) and mark it checked.
    pub fn learn(&self, account: &str, remote: i64, ttl: Duration, now: Instant) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= MAP_CAP && !m.contains_key(account) {
            m.clear();
        }
        let e = m.entry(account.to_string()).or_insert(Entry { floor: 0, floor_until: now, checked: now });
        if remote > 0 && (remote > e.floor || e.floor_until <= now) {
            e.floor = remote;
            e.floor_until = now + ttl;
        }
        e.checked = now;
    }
}

fn local() -> &'static Local {
    static L: OnceLock<Local> = OnceLock::new();
    L.get_or_init(Local::default)
}

/// Outcome of [`raise`], for the caller's audit/log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Raised {
    pub floor: i64,
    /// Redis acknowledged the write (other instances and a restart see it).
    pub shared: bool,
}

/// Record the floor for `account`. Never fails the caller; see the module doc.
pub async fn raise(state: &AppState, account: &str, reason: Reason) -> Raised {
    let account = crate::auth::account_of(account);
    let floor = floor_for(reason, chrono::Utc::now().timestamp());
    let ttl = floor_ttl_secs();
    local().raise(account, floor, Duration::from_secs(ttl as u64), Instant::now());
    let shared = match state.redis.as_ref() {
        Some(r) => {
            let key = format!("{KEY_PREFIX}{account}");
            // Never lower a floor another event already raised.
            let current = match tokio::time::timeout(REDIS_BUDGET * 4, r.get_string_checked(&key)).await {
                Ok(Ok(Some(v))) => v.parse::<i64>().unwrap_or(0),
                _ => 0,
            };
            let value = floor.max(current).to_string();
            matches!(
                tokio::time::timeout(REDIS_BUDGET * 4, r.set_string_ex(&key, &value, ttl)).await,
                Ok(true)
            )
        }
        None => false,
    };
    if !shared {
        tracing::warn!(
            target: "security",
            account = %account,
            "session floor held in this gateway's memory only (Redis unavailable or unset): \
             another instance, or this one after a restart, will not see it until the access \
             token expires"
        );
    }
    Raised { floor, shared }
}

/// Whether a signature-verified `token` for `sub` predates its account's
/// floor and must be refused.
pub async fn refuses(state: &AppState, sub: &str, token: &str) -> bool {
    let account = crate::auth::account_of(sub);
    let now = Instant::now();
    let (mut floor, ask_redis) = local().lookup(account, now);
    if ask_redis {
        if let Some(r) = state.redis.as_ref() {
            let key = format!("{KEY_PREFIX}{account}");
            match tokio::time::timeout(REDIS_BUDGET, r.get_string_checked(&key)).await {
                Ok(Ok(v)) => {
                    let remote = v.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                    local().learn(account, remote, Duration::from_secs(floor_ttl_secs() as u64), now);
                    floor = floor.max(remote);
                }
                other => {
                    tracing::warn!(
                        target: "security",
                        outcome = if other.is_err() { "timeout" } else { "error" },
                        "session floor lookup failed; applying this process's floors only"
                    );
                    // Back off for RECHECK so an outage costs one attempt per
                    // interval, not one per request.
                    local().learn(account, 0, Duration::from_secs(floor_ttl_secs() as u64), now);
                }
            }
        } else {
            local().learn(account, 0, Duration::from_secs(floor_ttl_secs() as u64), now);
        }
    }
    refused(token_iat(token), floor)
}

/// Everything that must happen when an account's standing changes, in one
/// place so no caller can do half of it: revoke every refresh token, raise
/// the floor, close the account's open sockets (and drop an in-flight turn —
/// `AlertHub::end_sessions`), and drop the service-key cache so a bound MCP
/// key stops resolving at once instead of up to one cache interval later.
///
/// Unbound machine keys are deliberately NOT touched: `disable` has never
/// revoked them (`service-key revoke --disable-account` is the verb that
/// kills a consumer's keys and the account together).
pub async fn end_account_sessions(state: &AppState, account: &str, reason: Reason) -> Summary {
    let account = account.trim();
    let refresh_revoked = match crate::auth_refresh::revoke_all_for_user(&state.db, account).await {
        Ok(n) => Some(n),
        Err(e) => {
            // The floor and the socket close below still happen; the refresh
            // chain of a DISABLED account is refused at refresh time anyway.
            tracing::error!(target: "security", account = %account, error = %e,
                "could not revoke the account's refresh tokens");
            None
        }
    };
    let raised = raise(state, account, reason).await;
    let sockets = state.alert_hub.end_sessions(account);
    crate::service_keys::invalidate_cache();
    tracing::info!(
        target: "security",
        account = %account,
        refresh_revoked = ?refresh_revoked,
        floor = raised.floor,
        floor_shared = raised.shared,
        sockets,
        "account sessions ended"
    );
    Summary { refresh_revoked, floor: raised, sockets }
}

#[derive(Debug, Clone, Copy)]
pub struct Summary {
    pub refresh_revoked: Option<u64>,
    pub floor: Raised,
    pub sockets: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_older_than_the_floor_is_refused_and_a_newer_one_is_not() {
        assert!(refused(Some(99), 100));
        assert!(!refused(Some(100), 100));
        assert!(!refused(Some(101), 100));
    }

    #[test]
    fn no_floor_refuses_nothing_even_a_token_without_iat() {
        assert!(!refused(None, 0));
        assert!(!refused(Some(1), 0));
    }

    #[test]
    fn a_floor_refuses_a_token_that_cannot_prove_its_age() {
        assert!(refused(None, 100));
    }

    #[test]
    fn an_account_change_sits_one_second_ahead_and_a_logout_does_not() {
        assert_eq!(floor_for(Reason::AccountChange, 1000), 1001);
        assert_eq!(floor_for(Reason::Logout, 1000), 1000);
        // a token minted in the same second as the change is refused...
        assert!(refused(Some(1000), floor_for(Reason::AccountChange, 1000)));
        // ...a token minted in the same second as a logout is the person's next login.
        assert!(!refused(Some(1000), floor_for(Reason::Logout, 1000)));
    }

    #[test]
    fn iat_is_read_from_the_payload_segment() {
        use base64::Engine as _;
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let tok = format!("{}.{}.sig", e.encode(r#"{"alg":"HS256"}"#), e.encode(r#"{"sub":"a","iat":1234}"#));
        assert_eq!(token_iat(&tok), Some(1234));
        assert_eq!(token_iat("not-a-jwt"), None);
        let no_iat = format!("{}.{}.sig", e.encode("{}"), e.encode(r#"{"sub":"a"}"#));
        assert_eq!(token_iat(&no_iat), None);
    }

    #[test]
    fn a_local_floor_applies_at_once_and_expires_with_its_ttl() {
        let l = Local::default();
        let t0 = Instant::now();
        assert_eq!(l.lookup("alice", t0).0, 0);
        l.raise("alice", 500, Duration::from_secs(10), t0);
        assert_eq!(l.lookup("alice", t0).0, 500, "effective immediately, no Redis round trip needed");
        assert_eq!(l.lookup("alice", t0 + Duration::from_secs(11)).0, 0, "retired after the token lifetime");
        assert_eq!(l.lookup("bob", t0).0, 0, "other accounts are untouched");
    }

    #[test]
    fn a_lower_floor_never_replaces_a_higher_live_one() {
        let l = Local::default();
        let t0 = Instant::now();
        l.raise("alice", 500, Duration::from_secs(60), t0);
        l.raise("alice", 400, Duration::from_secs(60), t0);
        assert_eq!(l.lookup("alice", t0).0, 500);
    }

    #[test]
    fn learning_a_remote_floor_raises_but_an_outage_answer_of_zero_keeps_the_local_one() {
        let l = Local::default();
        let t0 = Instant::now();
        l.raise("alice", 500, Duration::from_secs(60), t0);
        let later = t0 + RECHECK + Duration::from_millis(1);
        assert!(l.lookup("alice", later).1, "due for a Redis recheck");
        l.learn("alice", 0, Duration::from_secs(60), later);
        assert_eq!(l.lookup("alice", later).0, 500, "Redis absent/failed does not forget a local floor");
        assert!(!l.lookup("alice", later).1, "and backs off for the interval");
        l.learn("alice", 900, Duration::from_secs(60), later);
        assert_eq!(l.lookup("alice", later).0, 900, "a floor another instance wrote is adopted");
    }

    #[test]
    fn the_ttl_covers_a_whole_access_token_lifetime() {
        assert!(floor_ttl_secs() >= 15 * 60 + 60);
    }
}
