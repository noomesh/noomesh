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
//! ## Three tiers (decided, not defaulted)
//!
//! A floor lives in three places, read in this order:
//!
//! 1. **Redis** (`noo:auth:notbefore:<account>`), shared by every gateway
//!    instance; asked at most every [`RECHECK`] per account.
//! 2. **This process's memory**, always written first, always applied.
//! 3. **Postgres** (`noo_session_floors`, migration 095), the durable copy:
//!    written on every raise, loaded for every live row at boot, and read on
//!    a miss or error of tier 1 (and every [`PG_RECHECK`] regardless, which is
//!    how a floor written by the host, `noo security admin-password reset`,
//!    reaches a running gateway).
//!
//! The applied floor is the MAX of what the tiers return, so a lower or
//! absent answer from one tier never forgets a higher one from another.
//!
//! - **Written**: memory, then Redis (TTL of one maximum access-token
//!   lifetime plus margin), then Postgres (a row with the same expiry). A
//!   write that fails is reported (`shared` / `durable` false), logged, and
//!   does NOT fail the account change: the user row is already authoritative
//!   (refresh and login refuse it), the local floor already protects this
//!   process, and rolling back a disable because a cache was down would be the
//!   worse failure.
//! - **Redis down, Postgres up**: the floor is read from Postgres. This is the
//!   case the durable copy exists for: a floor written by another instance or
//!   before a restart is honoured during the Redis outage.
//! - **Neither readable** for an account: this process's floors apply (the
//!   boot load plus its own raises) and the lookup backs off for [`RECHECK`],
//!   so an outage costs one attempt per interval, not one per request. We do
//!   NOT refuse every request: that would lock out every operator trying to
//!   repair the outage. The residual is a floor written by ANOTHER instance
//!   while both stores are unreachable from this one; with Postgres down the
//!   gateway cannot log anyone in, refresh a token or change an account
//!   either, so nothing new is being minted or raised in that window. Logged
//!   at warn, target `security`.
//! - **Token without an `iat`** while a floor exists for its account: refused
//!   (every token this gateway mints carries one; a floor makes "cannot prove
//!   it is newer" mean no).
//! - **No Redis configured at all**: memory plus Postgres. Floors now survive
//!   a restart.
//! - **Older gateway** (no `noo_session_floors`): it ignores the table; the
//!   CLI's write only reaches a gateway at 095 or later, and the migration
//!   runs before the reset can matter (the table is created at boot).
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
/// How long a Postgres answer (including "no floor") is trusted. The
/// propagation delay for a floor only the database knows (the host CLI's).
const PG_RECHECK: Duration = Duration::from_secs(5);
/// Postgres round-trip budget on the auth path.
const PG_BUDGET: Duration = Duration::from_millis(250);
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
    /// When Postgres was last asked (`None` = never).
    pg_checked: Option<Instant>,
}

/// One tier's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// Read fine, no floor.
    Absent,
    /// Read fine, this floor.
    Found(i64),
    /// Could not be read (unset counts as `Absent`, not this).
    Failed,
}

impl Tier {
    fn floor(self) -> i64 {
        match self {
            Tier::Found(v) => v,
            _ => 0,
        }
    }
}

/// The floor to apply given this process's own and the two shared tiers, and
/// whether NEITHER shared tier could be read (the caller logs that).
pub fn resolve(local: i64, redis: Option<Tier>, pg: Option<Tier>) -> (i64, bool) {
    let blind = matches!(redis, Some(Tier::Failed)) && matches!(pg, Some(Tier::Failed));
    (local.max(redis.map_or(0, Tier::floor)).max(pg.map_or(0, Tier::floor)), blind)
}

/// Whether Postgres should be asked now, given the age of its last answer.
/// Normally every [`PG_RECHECK`]; when Redis just failed, every [`RECHECK`]
/// (Postgres is then the only shared source).
pub fn pg_due(pg_age: Option<Duration>, redis_failed: bool) -> bool {
    match pg_age {
        None => true,
        Some(a) => a >= if redis_failed { RECHECK } else { PG_RECHECK },
    }
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
        let e = m.entry(account.to_string()).or_insert(Entry { floor: 0, floor_until: now, checked: now, pg_checked: None });
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

    /// Make `account` due for both shared reads on its next lookup.
    pub fn forget_checks(&self, account: &str) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = m.get_mut(account) {
            e.checked = e.checked.checked_sub(RECHECK).unwrap_or(e.checked);
            e.pg_checked = None;
        }
    }

    /// Age of the last Postgres answer for `account` (`None` = never asked).
    pub fn pg_age(&self, account: &str, now: Instant) -> Option<Duration> {
        let m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        m.get(account).and_then(|e| e.pg_checked).map(|t| now.duration_since(t))
    }

    /// Fold a Postgres answer in and mark it checked. A failed read changes
    /// no floor; it still counts as an attempt (the back-off).
    pub fn learn_pg(&self, account: &str, answer: Tier, ttl: Duration, now: Instant) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= MAP_CAP && !m.contains_key(account) {
            m.clear();
        }
        let e = m.entry(account.to_string()).or_insert(Entry { floor: 0, floor_until: now, checked: now, pg_checked: None });
        if let Tier::Found(v) = answer {
            if v > 0 && (v > e.floor || e.floor_until <= now) {
                e.floor = v;
                e.floor_until = now + ttl;
            }
        }
        e.pg_checked = Some(now);
    }

    /// Fold a Redis answer in (`remote` = 0 for absent) and mark it checked.
    pub fn learn(&self, account: &str, remote: i64, ttl: Duration, now: Instant) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= MAP_CAP && !m.contains_key(account) {
            m.clear();
        }
        let e = m.entry(account.to_string()).or_insert(Entry { floor: 0, floor_until: now, checked: now, pg_checked: None });
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
    /// Postgres acknowledged the write (survives a Redis outage and a restart).
    pub durable: bool,
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
    let durable = write_durable(&state.db, account, floor, ttl).await;
    if !shared && !durable {
        tracing::warn!(
            target: "security",
            account = %account,
            "session floor held in this gateway's memory only (neither Redis nor Postgres took \
             it): another instance, or this one after a restart, will not see it until the \
             access token expires"
        );
    } else if !durable {
        tracing::warn!(target: "security", account = %account,
            "session floor not written to Postgres; it will not survive a Redis outage");
    }
    Raised { floor, shared, durable }
}

/// The durable write. Never lowers a floor or its expiry.
const UPSERT_SQL: &str = "INSERT INTO noo_session_floors (account, floor, expires_at) \
     VALUES ($1, $2, now() + make_interval(secs => $3)) \
     ON CONFLICT (account) DO UPDATE SET \
     floor = GREATEST(noo_session_floors.floor, EXCLUDED.floor), \
     expires_at = GREATEST(noo_session_floors.expires_at, EXCLUDED.expires_at)";

async fn write_durable(db: &sqlx::PgPool, account: &str, floor: i64, ttl: i64) -> bool {
    let q = sqlx::query(UPSERT_SQL).bind(account).bind(floor).bind(ttl as f64).execute(db);
    match tokio::time::timeout(PG_BUDGET * 4, q).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            tracing::error!(target: "security", account = %account, error = %e, "could not persist the session floor");
            false
        }
        Err(_) => false,
    }
}

async fn read_durable(db: &sqlx::PgPool, account: &str) -> Tier {
    let q = sqlx::query_scalar::<_, i64>("SELECT floor FROM noo_session_floors WHERE account = $1 AND expires_at > now()")
        .bind(account)
        .fetch_optional(db);
    match tokio::time::timeout(PG_BUDGET, q).await {
        Ok(Ok(Some(v))) => Tier::Found(v),
        Ok(Ok(None)) => Tier::Absent,
        _ => Tier::Failed,
    }
}

/// Boot: adopt every live durable floor, so a restart does not forget one.
/// Also drops rows that expired more than a day ago. A failure is logged and
/// leaves the per-request Postgres read to find the floors lazily.
pub async fn load_durable(db: &sqlx::PgPool) -> usize {
    let _ = sqlx::query("DELETE FROM noo_session_floors WHERE expires_at < now() - interval '1 day'").execute(db).await;
    let rows = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT account, floor, GREATEST(extract(epoch FROM (expires_at - now())), 0)::bigint \
         FROM noo_session_floors WHERE expires_at > now()",
    )
    .fetch_all(db)
    .await;
    match rows {
        Ok(rows) => {
            let now = Instant::now();
            for (account, floor, secs) in &rows {
                local().raise(account, *floor, Duration::from_secs(*secs as u64), now);
                // not "checked": Redis and Postgres are still asked on first use
                local().forget_checks(account);
            }
            rows.len()
        }
        Err(e) => {
            tracing::warn!(target: "security", error = %e, "could not load the durable session floors at boot");
            0
        }
    }
}

/// Whether a signature-verified `token` for `sub` predates its account's
/// floor and must be refused.
pub async fn refuses(state: &AppState, sub: &str, token: &str) -> bool {
    let account = crate::auth::account_of(sub);
    let now = Instant::now();
    let ttl = Duration::from_secs(floor_ttl_secs() as u64);
    let (local_floor, ask_redis) = local().lookup(account, now);
    let mut redis: Option<Tier> = None;
    if ask_redis {
        let answer = match state.redis.as_ref() {
            Some(r) => {
                let key = format!("{KEY_PREFIX}{account}");
                match tokio::time::timeout(REDIS_BUDGET, r.get_string_checked(&key)).await {
                    Ok(Ok(v)) => v.and_then(|s| s.parse::<i64>().ok()).filter(|v| *v > 0).map_or(Tier::Absent, Tier::Found),
                    _ => Tier::Failed,
                }
            }
            None => Tier::Absent,
        };
        // Redis back-off is `learn`'s: an outage costs one attempt per interval.
        local().learn(account, answer.floor(), ttl, now);
        redis = Some(answer);
    }
    let redis_failed = matches!(redis, Some(Tier::Failed));
    let mut pg: Option<Tier> = None;
    if pg_due(local().pg_age(account, now), redis_failed) {
        let answer = read_durable(&state.db, account).await;
        local().learn_pg(account, answer, ttl, now);
        pg = Some(answer);
    }
    let (floor, blind) = resolve(local().lookup(account, now).0.max(local_floor), redis, pg);
    if blind {
        tracing::warn!(
            target: "security",
            "session floor unreadable from Redis and Postgres; applying this process's floors only"
        );
    }
    refused(token_iat(token), floor)
}

/// Everything that must happen when an account's standing changes, in one
/// place so no caller can do half of it: revoke every refresh token, raise
/// the floor, close the account's open sockets (and drop an in-flight turn —
/// `AlertHub::end_sessions`), drop the account's cached channel principal
/// (`bus_principal::invalidate_account`), and drop the service-key cache so a bound MCP
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
    // The 30 s channel-principal cache: a demoted or disabled account's next
    // channel turn must see the new row, not the old role.
    crate::bus_principal::invalidate_account(account);
    tracing::info!(
        target: "security",
        account = %account,
        refresh_revoked = ?refresh_revoked,
        floor = raised.floor,
        floor_shared = raised.shared,
        floor_durable = raised.durable,
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

    // ---- the three-tier read -------------------------------------------

    #[test]
    fn redis_down_postgres_up_applies_the_postgres_floor() {
        // a floor another instance wrote: this process knows nothing (local 0)
        let (floor, blind) = resolve(0, Some(Tier::Failed), Some(Tier::Found(700)));
        assert_eq!(floor, 700);
        assert!(!blind);
        assert!(refused(Some(699), floor), "the token that predates it is refused during the Redis outage");
        assert!(!refused(Some(700), floor));
    }

    #[test]
    fn redis_miss_still_consults_postgres_for_a_floor_only_the_host_wrote() {
        // the CLI's reset writes Postgres only; Redis answers "absent"
        let (floor, _) = resolve(0, Some(Tier::Absent), Some(Tier::Found(800)));
        assert_eq!(floor, 800);
    }

    #[test]
    fn the_highest_tier_wins_and_none_lowers_another() {
        assert_eq!(resolve(500, Some(Tier::Found(400)), Some(Tier::Found(900))).0, 900);
        assert_eq!(resolve(500, Some(Tier::Found(600)), Some(Tier::Absent)).0, 600);
        assert_eq!(resolve(500, Some(Tier::Absent), Some(Tier::Failed)).0, 500, "an unreadable tier forgets nothing");
        assert_eq!(resolve(0, None, None).0, 0);
    }

    #[test]
    fn neither_shared_tier_readable_falls_back_to_local_floors_and_says_so() {
        let (floor, blind) = resolve(500, Some(Tier::Failed), Some(Tier::Failed));
        assert_eq!(floor, 500, "this process's floors still apply; the request is not refused wholesale");
        assert!(blind, "and the caller is told it was blind");
        assert!(!resolve(0, Some(Tier::Failed), None).1, "Postgres not asked this round is not blindness");
        assert!(!refused(Some(1), resolve(0, Some(Tier::Failed), Some(Tier::Failed)).0), "no floor known, no refusal");
    }

    #[test]
    fn postgres_is_asked_on_its_own_interval_and_sooner_when_redis_failed() {
        assert!(pg_due(None, false));
        assert!(!pg_due(Some(Duration::from_secs(1)), false));
        assert!(!pg_due(Some(RECHECK), false), "healthy Redis: Postgres is not asked every interval");
        assert!(pg_due(Some(PG_RECHECK), false));
        assert!(pg_due(Some(RECHECK), true), "Redis failed: Postgres is the only shared source");
    }

    #[test]
    fn a_postgres_floor_is_adopted_into_memory_and_a_failed_read_keeps_the_old_one() {
        let l = Local::default();
        let t0 = Instant::now();
        assert_eq!(l.pg_age("alice", t0), None);
        l.learn_pg("alice", Tier::Found(900), Duration::from_secs(60), t0);
        assert_eq!(l.lookup("alice", t0).0, 900);
        let later = t0 + Duration::from_secs(6);
        assert_eq!(l.pg_age("alice", later), Some(Duration::from_secs(6)));
        l.learn_pg("alice", Tier::Failed, Duration::from_secs(60), later);
        l.learn_pg("alice", Tier::Absent, Duration::from_secs(60), later);
        assert_eq!(l.lookup("alice", later).0, 900, "a failed or empty read never forgets a floor");
        assert_eq!(l.pg_age("alice", later), Some(Duration::ZERO), "and backs off");
    }

    #[test]
    fn a_boot_loaded_floor_applies_at_once_and_is_due_for_both_shared_reads() {
        let l = Local::default();
        let t0 = Instant::now();
        l.raise("alice", 900, Duration::from_secs(120), t0);
        l.forget_checks("alice");
        let (floor, ask_redis) = l.lookup("alice", t0);
        assert_eq!(floor, 900, "a restart does not forget a floor");
        assert!(ask_redis);
        assert_eq!(l.pg_age("alice", t0), None);
    }

    #[test]
    fn every_raise_is_written_to_postgres_and_the_write_never_lowers() {
        let src = include_str!("session_floor.rs");
        let raise = &src[src.find("pub async fn raise").unwrap()..src.find("const UPSERT_SQL").unwrap()];
        assert!(raise.contains("write_durable("), "raise must persist the floor");
        assert!(UPSERT_SQL.contains("GREATEST(noo_session_floors.floor, EXCLUDED.floor)"));
        assert!(UPSERT_SQL.contains("GREATEST(noo_session_floors.expires_at, EXCLUDED.expires_at)"));
        assert!(src.contains("pub async fn load_durable"));
        assert!(include_str!("main.rs").contains("session_floor::load_durable("), "the floors are loaded at boot");
    }

    #[test]
    fn the_cli_and_the_gateway_name_the_same_table() {
        let cli = include_str!("../../noo-cli/src/host_access.rs");
        for needle in ["noo_session_floors", "account", "floor", "expires_at"] {
            assert!(UPSERT_SQL.contains(needle) && cli.contains(needle), "{needle}");
        }
    }

    #[test]
    fn the_ttl_covers_a_whole_access_token_lifetime() {
        assert!(floor_ttl_secs() >= 15 * 60 + 60);
    }
}
