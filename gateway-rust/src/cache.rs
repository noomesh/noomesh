// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Redis-backed caching and rate limiting.
//!
//! Key patterns (Rust-owned — the Python workers do NOT read or write
//! `noo:cache:*` / `noo:session:*` / `noo:rate:*`; the only Redis namespace
//! genuinely shared with Python is the per-consumer quota bucket
//! `noo:cq:{consumer}`, which `mcp/hub.py` uses with the same fixed-window
//! semantics as `check_consumer_quota` below):
//!   noo:rate:{ip}                    — request count (TTL: 60s)
//!   noo:cq:{consumer}                — per-consumer quota (TTL: 60s; shared with Python MCP hub)
//!   noo:cache:{hash}                 — LLM response cache (TTL: configurable)
//!   noo:session:{id}                 — session state snapshot (TTL: 1h)
//!   noo:security:violations:{type}   — security violation counters (TTL: 24h)

use anyhow::Result;
use fred::prelude::*;
use serde_json::Value;
use sha2::{Sha256, Digest};
use std::time::Duration;

// Rate limiting defaults
const RATE_WINDOW_SECS: i64 = 60;

/// Sliding retention for `noo:security:violations:{type}` counters — matches
/// the default `period_hours=24` of GET /api/security/violations.
const VIOLATION_TTL_SECS: i64 = 24 * 60 * 60;
const RATE_MAX_REQUESTS: i64 = 600;  // per minute per IP

// Cache TTL defaults
const LLM_CACHE_TTL: Duration = Duration::from_secs(300);  // 5 min
const SESSION_CACHE_TTL: Duration = Duration::from_secs(3600);  // 1 hour

/// Redis connection wrapper with helper methods.
pub struct RedisCache {
    /// Every command is sent fail-fast: while the connection is down and the
    /// reconnect policy is redialling, a command errors at once (the callers'
    /// existing `Err` path — the rate limiter's local fallback, a skipped
    /// cache write) instead of queueing behind the reconnect for the 10 s
    /// command timeout on every request.
    client: fred::clients::WithOptions<fred::clients::Client>,
}

/// How long boot waits for the first Redis connection before the gateway
/// starts serving without it. Short on purpose: the background half of
/// [`RedisSlot::connect`] fills the slot whenever Redis does come up, and a
/// long stall here only delays the listener toward the image healthcheck
/// (30 s x 3, no start period) and the recreate gate's rollback.
pub const REDIS_BOOT_BUDGET: Duration = Duration::from_secs(20);

/// One wait on the connection before a `warn!` says it is still down.
const REDIS_PROBE_EVERY: Duration = Duration::from_secs(5);

/// Where the gateway's Redis connection stands — the word `/health` reports
/// as `dependencies.redis.state` and `noo cluster verify` / `noo upgrade`
/// read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisState {
    /// A live connection.
    Connected,
    /// A client exists and is redialling (never connected yet, or dropped).
    Reconnecting,
    /// No client could be built (bad URL, unreadable TLS material): a
    /// configuration error, nothing retries it.
    Unavailable,
}

impl RedisState {
    pub fn as_str(self) -> &'static str {
        match self {
            RedisState::Connected => "connected",
            RedisState::Reconnecting => "reconnecting",
            RedisState::Unavailable => "unavailable",
        }
    }
}

#[derive(Default)]
struct SlotInner {
    cell: std::sync::OnceLock<RedisCache>,
    /// A client was built and is dialling: an empty cell means "not yet",
    /// not "never".
    configured: std::sync::atomic::AtomicBool,
}

/// `AppState.redis`: the Redis handle, filled the moment the first
/// connection lands — at boot, or later from a background task.
///
/// It used to be an `Option<RedisCache>` decided ONCE at boot by a one-shot
/// connect (5 s, no retry). When Redis was not accepting connections yet
/// (0.6.4: redis starts as `nonroot` and re-owns its data first) the gateway
/// ran without Redis until restarted — `/api/jobs/*` answered "Redis not
/// connected" for an hour on the controller (2026-10-15). Now the transition
/// is `None` -> `Some` exactly once and never back, so every caller keeps
/// its `Option<&RedisCache>` semantics; a connection that drops after that
/// is redialled by fred's reconnect policy and surfaces as command errors,
/// as a dropped connection always did.
#[derive(Clone, Default)]
pub struct RedisSlot {
    inner: std::sync::Arc<SlotInner>,
}

impl RedisSlot {
    /// The handle, once a first connection has landed.
    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> Option<&RedisCache> {
        self.inner.cell.get()
    }

    pub fn is_some(&self) -> bool {
        self.as_ref().is_some()
    }

    pub fn is_none(&self) -> bool {
        self.as_ref().is_none()
    }

    /// Whether a client was built and is (re)dialling.
    pub fn is_configured(&self) -> bool {
        self.inner.configured.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The connection state, without a round trip (`/health` adds a PING).
    pub fn state(&self) -> RedisState {
        match self.as_ref() {
            Some(c) if c.is_connected() => RedisState::Connected,
            Some(_) => RedisState::Reconnecting,
            None if self.is_configured() => RedisState::Reconnecting,
            None => RedisState::Unavailable,
        }
    }

    /// Dial `redis_url`: wait up to `budget` for the first connection (one
    /// loud `warn!` per [`REDIS_PROBE_EVERY`]), then return either way. If it
    /// is still down, a background task keeps waiting on the client's own
    /// reconnect loop and fills the slot when it connects — no restart.
    pub async fn connect(redis_url: &str, budget: Duration) -> Self {
        let slot = Self::default();
        let cache = match RedisCache::build(redis_url) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Redis client could not be built (configuration) — rate limiting and caching disabled"
                );
                return slot;
            }
        };
        slot.inner.configured.store(true, std::sync::atomic::Ordering::Release);
        // The connection task: with `fail_fast = false` and an unlimited
        // reconnect policy it dials until it connects, and redials after
        // every drop, for the life of the process.
        let _connection_task = cache.client.connect();
        let url = crate::redact::scrub_url_userinfo(redis_url).to_string();
        let started = std::time::Instant::now();
        if wait_connected(&cache, Some(budget), REDIS_PROBE_EVERY, &url).await {
            tracing::info!(url = %url, "Redis connected");
            let _ = slot.inner.cell.set(cache);
            return slot;
        }
        tracing::warn!(
            url = %url,
            waited_secs = started.elapsed().as_secs(),
            "Redis still not connected — serving WITHOUT Redis (rate limiting local, jobs/cache degraded); reconnecting in the background"
        );
        let late = slot.clone();
        tokio::spawn(async move {
            wait_connected(&cache, None, Duration::from_secs(30), &url).await;
            tracing::info!(
                url = %url,
                after_secs = started.elapsed().as_secs(),
                "Redis connected (late) — rate limiting, jobs and cache restored"
            );
            let _ = late.inner.cell.set(cache);
        });
        slot
    }

}

/// Wait until `cache` is connected, `warn!`-ing every `every` while it is
/// not. `None` budget = forever. Polls the state as well as the connect
/// notification, so a connect that lands between the two is not missed.
async fn wait_connected(cache: &RedisCache, budget: Option<Duration>, every: Duration, url: &str) -> bool {
    let started = std::time::Instant::now();
    let mut attempt: u32 = 0;
    loop {
        if cache.is_connected() {
            return true;
        }
        let step = match budget {
            Some(b) => match b.checked_sub(started.elapsed()) {
                Some(left) if !left.is_zero() => left.min(every),
                _ => return false,
            },
            None => every,
        };
        match tokio::time::timeout(step, cache.client.wait_for_connect()).await {
            Ok(Ok(())) if cache.is_connected() => return true,
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                // A lagged/closed notification channel: do not spin on it.
                tracing::debug!(error = %e, "Redis connect notification error");
                tokio::time::sleep(step).await;
            }
            Err(_) => {}
        }
        if !cache.is_connected() {
            attempt += 1;
            tracing::warn!(
                url = %url,
                attempt,
                elapsed_secs = started.elapsed().as_secs(),
                "Redis not accepting connections yet — still retrying"
            );
        }
    }
}

impl RedisCache {
    /// Build the client — URL, password, TLS, reconnect policy — without
    /// dialling. Errors here are configuration errors, which no retry fixes.
    fn build(redis_url: &str) -> Result<Self> {
        let mut config = fred::types::config::Config::from_url(redis_url)?;
        // Run the reconnect policy for the FIRST connection too, rather than
        // returning its error to a caller that would give up on Redis.
        config.fail_fast = false;

        // Add password from env if not in URL
        let password = crate::config::secret_env::secret_or_empty("REDIS_PASSWORD");
        if !password.is_empty() && config.password.is_none() {
            config.password = Some(password);
        }

        // Configure mTLS when cluster PKI is available
        // Redis is configured with --tls-auth-clients yes, so we must present client certs
        let ca_path = std::env::var("NOO_TLS_CA").unwrap_or_default();
        let cert_path = std::env::var("NOO_TLS_CERT").unwrap_or_default();
        let key_path = std::env::var("NOO_TLS_KEY").unwrap_or_default();

        let tls_config = if !ca_path.is_empty() && std::path::Path::new(&ca_path).exists() {
            let ca_pem = std::fs::read(&ca_path)?;
            let mut root_store = rustls::RootCertStore::empty();
            let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(&ca_pem[..]))
                .filter_map(|c| c.ok())
                .collect::<Vec<_>>();
            for cert in &certs {
                root_store.add(cert.clone())?;
            }

            if !cert_path.is_empty() && !key_path.is_empty()
                && std::path::Path::new(&cert_path).exists()
                && std::path::Path::new(&key_path).exists()
            {
                let cert_pem = std::fs::read(&cert_path)?;
                let key_pem = std::fs::read(&key_path)?;
                let client_certs = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..]))
                    .filter_map(|c| c.ok())
                    .collect::<Vec<_>>();
                let client_key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&key_pem[..]))
                    .ok()
                    .flatten()
                    .ok_or_else(|| anyhow::anyhow!("Failed to parse TLS key for Redis mTLS"))?;

                tracing::info!("Redis mTLS enabled (client cert + CA)");
                Some(rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_client_auth_cert(client_certs, client_key)?)
            } else {
                tracing::info!("Redis TLS enabled (CA only, no client cert)");
                Some(rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth())
            }
        } else {
            None
        };

        // Build with TLS if configured
        let perf = fred::prelude::PerformanceConfig {
            default_command_timeout: Duration::from_secs(10),
            ..Default::default()
        };

        let conn_config = fred::prelude::ConnectionConfig {
            connection_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        if let Some(tls) = tls_config {
            config.tls = fred::prelude::TlsConfig::from(tls).into();
        }

        let mut builder = fred::prelude::Builder::from_config(config);
        builder.set_performance_config(perf);
        builder.set_connection_config(conn_config);
        // Unlimited attempts (0), 250 ms doubling to a 5 s ceiling. Without a
        // policy fred never redials: a Redis restart left the client dead
        // until the gateway itself restarted.
        builder.set_policy(fred::prelude::ReconnectPolicy::new_exponential(0, 250, 5_000, 2));

        let client = builder.build()?;
        let client = client.with_options(&fred::prelude::Options {
            fail_fast: true,
            ..Default::default()
        });
        Ok(Self { client })
    }

    /// Whether the connection is up right now (no round trip).
    pub fn is_connected(&self) -> bool {
        self.client.is_connected()
    }

    // ── Rate Limiting ────────────────────────────────────────

    /// Check if a request from this IP is allowed.
    /// Returns Ok(remaining) if allowed, Err(retry_after_secs) if blocked.
    pub async fn check_rate_limit(&self, ip: &str) -> Result<RateResult> {
        self.check_rate_limit_capped(ip, RATE_MAX_REQUESTS).await
    }

    /// [`Self::check_rate_limit`] for a bucket with its own cap: a verified
    /// controller service gets `svc:<name>` and a wider one
    /// second review — the middleware's `service_rate_bucket`.
    pub async fn check_rate_limit_capped(&self, ip: &str, max: i64) -> Result<RateResult> {
        let key = format!("noo:rate:{ip}");

        let count: i64 = self.client.incr(&key).await?;

        // Ensure the window key ALWAYS carries a TTL. The old code set expiry
        // only on `count == 1`; if that single EXPIRE was ever lost (process
        // death between INCR and EXPIRE, or a concurrent race), the key lived
        // forever — `count` climbed unbounded past the cap and every request
        // 429'd permanently with `retry_after: -1` (Redis TTL for a key with
        // no expiry), unrecoverable without manual `DEL`. Re-assert the TTL
        // whenever it is missing so a stuck bucket self-heals on the very next
        // request. For a healthy key this is a cheap no-op read; setting it
        // again only happens when TTL < 0, so the fixed-window semantics for
        // normal traffic are preserved.
        let mut ttl: i64 = self.client.ttl::<i64, _>(&key).await.unwrap_or(-1);
        if ttl < 0 {
            self.client
                .expire::<(), _>(&key, RATE_WINDOW_SECS, None)
                .await
                .ok();
            ttl = RATE_WINDOW_SECS;
        }

        if count > max {
            // `ttl` is guaranteed >= 0 here, so callers always get a usable
            // Retry-After — never the old nonsensical -1.
            Ok(RateResult::Limited { retry_after: ttl })
        } else {
            Ok(RateResult::Allowed {
                remaining: max - count,
            })
        }
    }

    /// Per-consumer requests-per-minute quota, keyed by consumer name rather
    /// than client IP. Same fixed-window + self-healing-TTL logic as
    /// `check_rate_limit`, so a stuck bucket can never brick a consumer. Used
    /// by the external inference door and the MCP hub to stop one named
    /// consumer (noo-trading, codex, …) from monopolising shared compute.
    /// `limit` is the consumer's `rpm_limit`; callers skip this entirely when
    /// it is `None`.
    pub async fn check_consumer_quota(&self, consumer: &str, limit: i64) -> Result<RateResult> {
        let key = format!("noo:cq:{consumer}");

        let count: i64 = self.client.incr(&key).await?;

        let mut ttl: i64 = self.client.ttl::<i64, _>(&key).await.unwrap_or(-1);
        if ttl < 0 {
            self.client
                .expire::<(), _>(&key, RATE_WINDOW_SECS, None)
                .await
                .ok();
            ttl = RATE_WINDOW_SECS;
        }

        if count > limit {
            Ok(RateResult::Limited { retry_after: ttl })
        } else {
            Ok(RateResult::Allowed {
                remaining: (limit - count).max(0),
            })
        }
    }

    /// Generic fixed-window counter for a named subject.
    ///
    /// `check_rate_limit` is per-IP and global (600/min); that is far too
    /// loose for `/auth/token`, where 600 requests is 600 bcrypt verifies and
    /// the five-failure lockout means a handful of them can lock any account
    /// out. This gives a caller its own much smaller bucket, keyed by
    /// whatever identity the caller chooses — `("login", "alice")` and
    /// `("login-ip", "203.0.113.4")` are separate namespaces so one does not
    /// consume the other's budget.
    ///
    /// Same self-healing-TTL logic as `check_rate_limit`: a key that somehow
    /// lost its expiry re-acquires one on the next call rather than pinning a
    /// subject at 429 forever.
    pub async fn check_named_limit(
        &self,
        ns: &str,
        subject: &str,
        limit: i64,
        window_secs: i64,
    ) -> Result<RateResult> {
        let key = format!("noo:nl:{ns}:{subject}");
        let count: i64 = self.client.incr(&key).await?;
        let mut ttl: i64 = self.client.ttl::<i64, _>(&key).await.unwrap_or(-1);
        if ttl < 0 {
            self.client.expire::<(), _>(&key, window_secs, None).await.ok();
            ttl = window_secs;
        }
        if count > limit {
            Ok(RateResult::Limited { retry_after: ttl })
        } else {
            Ok(RateResult::Allowed { remaining: (limit - count).max(0) })
        }
    }

    // ── LLM Response Cache ───────────────────────────────────

    /// Build a cache key from model + messages + WHO is asking.
    ///
    /// The caller is part of the key because the answer is not a function of
    /// the prompt alone: the coordinator builds it from the caller's own
    /// conversation memory and from knowledge-base evidence filtered to the
    /// caller's audience. Keyed by prompt only, two people
    /// who typed the same words inside the TTL shared one answer, so the
    /// second got a reply composed from the first one's private documents.
    ///
    /// `caller` is the ACCOUNT (a connection `alice/laptop` and `alice` are the same
    /// person and share an entry); `None` is a machine caller that carries no
    /// user identity, which has its own bucket and never shares with a person.
    pub fn llm_cache_key(model: &str, messages: &[Value], caller: Option<&str>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(model.as_bytes());
        hasher.update(b"\0");
        // `\0` cannot occur in an account name, so ("ab","c") and ("a","bc")
        // never collide, and None cannot collide with Some("").
        match caller {
            Some(c) => {
                hasher.update(b"user:");
                hasher.update(crate::auth::account_of(c).as_bytes());
            }
            None => hasher.update(b"machine"),
        }
        hasher.update(b"\0");
        hasher.update(serde_json::to_string(messages).unwrap_or_default().as_bytes());
        let hash = hex::encode(hasher.finalize());
        format!("noo:cache:{hash}")
    }

    /// Get a cached LLM response.
    pub async fn get_llm_cache(&self, key: &str) -> Option<Value> {
        let data: Option<String> = self.client.get::<Option<String>, _>(key).await.ok()?;
        data.and_then(|s: String| serde_json::from_str(&s).ok())
    }

    /// Cache an LLM response.
    pub async fn set_llm_cache(&self, key: &str, response: &Value, ttl: Option<Duration>) {
        let ttl = ttl.unwrap_or(LLM_CACHE_TTL);
        if let Ok(data) = serde_json::to_string(response) {
            let _: Result<(), _> = self.client
                .set(key, data, Some(Expiration::EX(ttl.as_secs() as i64)), None, false)
                .await;
        }
    }

    // ── Session Cache ────────────────────────────────────────

    /// Cache session state for fast lookup.
    pub async fn cache_session(&self, session_id: &str, state: &Value) {
        let key = format!("noo:session:{session_id}");
        if let Ok(data) = serde_json::to_string(state) {
            let _: Result<(), _> = self.client
                .set(&key, data, Some(Expiration::EX(SESSION_CACHE_TTL.as_secs() as i64)), None, false)
                .await;
        }
    }

    /// Get cached session state.
    pub async fn get_session(&self, session_id: &str) -> Option<Value> {
        let key = format!("noo:session:{session_id}");
        let data: Option<String> = self.client.get::<Option<String>, _>(&key).await.ok()?;
        data.and_then(|s: String| serde_json::from_str(&s).ok())
    }

    /// Delete session cache (on logout, session end).
    pub async fn delete_session(&self, session_id: &str) {
        let key = format!("noo:session:{session_id}");
        let _: Result<(), _> = self.client.del(&key).await;
    }

    // ── Job Scheduler helpers (Redis-backed) ───────────────

    /// Get all members of a Redis SET (e.g. active job IDs).
    pub async fn smembers(&self, key: &str) -> Vec<String> {
        self.client.smembers::<Vec<String>, _>(key).await.unwrap_or_default()
    }

    /// Get members of a sorted set by index range (e.g. job queue).
    pub async fn zrange(&self, key: &str, start: i64, stop: i64) -> Vec<String> {
        self.client.zrange::<Vec<String>, _, i64, i64>(key, start, stop, None, false, None, false).await.unwrap_or_default()
    }

    /// Get all fields and values from a Redis HASH (e.g. a single job record).
    pub async fn hgetall(&self, key: &str) -> Option<std::collections::HashMap<String, String>> {
        let map: std::collections::HashMap<String, String> =
            self.client.hgetall::<std::collections::HashMap<String, String>, _>(key).await.ok()?;
        if map.is_empty() { None } else { Some(map) }
    }

    /// Get a range of elements from a Redis LIST (e.g. job history).
    pub async fn lrange(&self, key: &str, start: i64, stop: i64) -> Vec<String> {
        self.client.lrange::<Vec<String>, _>(key, start, stop).await.unwrap_or_default()
    }

    // ── Job Scheduler mutation helpers (Redis-backed) ──────

    /// Set one or more fields on a Redis HASH.
    pub async fn hset(&self, key: &str, fields: &[(&str, &str)]) -> bool {
        for (field, value) in fields {
            let res: Result<(), _> = self.client.hset(key, (field.to_string(), value.to_string())).await;
            if res.is_err() {
                return false;
            }
        }
        true
    }

    /// Remove a member from a Redis sorted set.
    pub async fn zrem(&self, key: &str, member: &str) -> bool {
        self.client.zrem::<i64, _, _>(key, member).await.unwrap_or(0) > 0
    }

    /// Remove a member from a Redis SET.
    pub async fn srem(&self, key: &str, member: &str) -> bool {
        self.client.srem::<i64, _, _>(key, member).await.unwrap_or(0) > 0
    }

    /// Add a member to a Redis sorted set with a score.
    pub async fn zadd(&self, key: &str, member: &str, score: f64) -> bool {
        self.client.zadd::<i64, _, _>(key, None, None, false, false, (score, member.to_string())).await.unwrap_or(0) >= 0
    }

    /// Get a single field from a Redis HASH.
    pub async fn hget(&self, key: &str, field: &str) -> Option<String> {
        self.client.hget::<Option<String>, _, _>(key, field).await.ok()?
    }

    // ── Scheduler helpers (additional Redis primitives) ─────

    /// Add a member to a Redis SET.
    pub async fn sadd(&self, key: &str, member: &str) -> bool {
        self.client.sadd::<i64, _, _>(key, member.to_string()).await.unwrap_or(0) > 0
    }

    /// Get the cardinality (member count) of a Redis SET.
    pub async fn scard(&self, key: &str) -> i64 {
        self.client.scard::<i64, _>(key).await.unwrap_or(0)
    }

    /// Get the cardinality (member count) of a Redis sorted set.
    pub async fn zcard(&self, key: &str) -> i64 {
        self.client.zcard::<i64, _>(key).await.unwrap_or(0)
    }

    /// Get the length of a Redis LIST.
    pub async fn llen(&self, key: &str) -> i64 {
        self.client.llen::<i64, _>(key).await.unwrap_or(0)
    }

    /// Get members of a sorted set by score range.
    pub async fn zrangebyscore(&self, key: &str, min: f64, max: f64) -> Vec<String> {
        self.client
            .zrangebyscore::<Vec<String>, _, f64, f64>(key, min, max, false, None)
            .await
            .unwrap_or_default()
    }

    /// Check if a member exists in a Redis SET.
    pub async fn sismember(&self, key: &str, member: &str) -> bool {
        self.client.sismember::<bool, _, _>(key, member.to_string()).await.unwrap_or(false)
    }

    /// Set a simple string key.
    pub async fn set_string(&self, key: &str, value: &str) -> bool {
        self.client.set::<(), _, _>(key, value.to_string(), None, None, false).await.is_ok()
    }

    /// Get a simple string key.
    pub async fn get_string(&self, key: &str) -> Option<String> {
        self.client.get::<Option<String>, _>(key).await.ok()?
    }

    /// Delete a key.
    pub async fn del_key(&self, key: &str) -> bool {
        self.client.del::<i64, _>(key).await.unwrap_or(0) > 0
    }

    /// Atomically increment a counter, returning the new value (or 0 on error).
    /// Used by autonomy_evaluators::bump_counter for "condition held N ticks" semantics.
    pub async fn incr(&self, key: &str) -> i64 {
        self.client.incr::<i64, _>(key).await.unwrap_or(0)
    }

    /// Record a security violation: INCR `noo:security:violations:{vtype}`
    /// with a self-healing 24h TTL (same pattern as `check_rate_limit` — the
    /// TTL is re-asserted whenever missing, so a counter can never live
    /// forever). These counters are the writers behind
    /// GET /api/security/violations (routes/admin.rs), which previously read
    /// keys nothing wrote and therefore reported 0 forever. Best-effort:
    /// errors are swallowed — recording must never fail the request path.
    pub async fn record_security_violation(&self, vtype: &str) {
        let key = format!("noo:security:violations:{vtype}");
        if self.client.incr::<i64, _>(&key).await.is_err() {
            return;
        }
        let ttl: i64 = self.client.ttl::<i64, _>(&key).await.unwrap_or(-1);
        if ttl < 0 {
            self.client
                .expire::<(), _>(&key, VIOLATION_TTL_SECS, None)
                .await
                .ok();
        }
    }

    /// SET key value NX EX <ttl> — atomically claim a cooldown/dedup slot.
    /// Returns true if the key was newly set (slot acquired), false if it
    /// already existed or on error. Used by operator_alert for per-condition
    /// alert cooldowns shared across gateway restarts.
    pub async fn set_nx_ex(&self, key: &str, value: &str, ttl_secs: i64) -> bool {
        self.client
            .set::<fred::types::Value, _, _>(
                key,
                value.to_string(),
                Some(fred::types::Expiration::EX(ttl_secs)),
                Some(fred::types::SetOptions::NX),
                false,
            )
            .await
            .map(|v| !v.is_null())
            .unwrap_or(false)
    }

    /// Set TTL on a key. Returns true if the TTL was set successfully.
    /// (Trait methods come in via `use fred::prelude::*` at module top.)
    pub async fn expire(&self, key: &str, seconds: i64) -> bool {
        self.client
            .expire::<i64, _>(key, seconds, None)
            .await
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// Push a value onto the right end of a Redis list.
    /// Returns the new list length (0 on error).
    pub async fn rpush(&self, key: &str, value: &str) -> i64 {
        self.client
            .rpush::<i64, _, _>(key, value.to_string())
            .await
            .unwrap_or(0)
    }

    /// Remaining TTL of a key in seconds. -1 = no TTL, -2 = missing.
    /// Mirrors Python's `redis.ttl()`, which the janitor uses to decide
    /// whether a terminal job hash still needs its 24h expiry set.
    pub async fn ttl(&self, key: &str) -> i64 {
        self.client.ttl::<i64, _>(key).await.unwrap_or(-2)
    }

    /// Members of a sorted set by score range, capped to `count`.
    ///
    /// The uncapped `zrangebyscore` above materialises the whole range;
    /// the dispatcher only ever wants the head, and Python asks for
    /// exactly one (`start=0, num=1`).
    pub async fn zrangebyscore_limit(
        &self,
        key: &str,
        min: f64,
        max: f64,
        count: i64,
    ) -> Vec<String> {
        self.client
            .zrangebyscore::<Vec<String>, _, f64, f64>(
                key,
                min,
                max,
                false,
                Some((0, count)),
            )
            .await
            .unwrap_or_default()
    }

    /// Run a Lua script server-side and return its integer reply.
    ///
    /// The scheduler uses this for the two transitions that must not be
    /// interleaved — claiming a queued job for dispatch, and flipping a
    /// job terminal. Everything else is a single command and needs no
    /// script. Returns `None` when the script errors or Redis is down, so
    /// callers can treat "unknown" as "did not happen" (fail closed: a
    /// missed dispatch is retried next tick, a phantom one is not).
    pub async fn eval_i64(&self, script: &str, keys: &[String], args: &[String]) -> Option<i64> {
        match self
            .client
            .eval::<i64, _, Vec<String>, Vec<String>>(script, keys.to_vec(), args.to_vec())
            .await
        {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "redis eval failed");
                None
            }
        }
    }

    // ── Generic helpers ──────────────────────────────────────

    /// Check if Redis is connected.
    pub async fn is_healthy(&self) -> bool {
        self.client.ping::<String>(None).await.is_ok()
    }

    /// Run Redis INFO command and return the raw response string.
    /// Used by the cache-stats admin endpoint.
    pub async fn info_raw(&self) -> Option<String> {
        self.client.info::<String>(None).await.ok()
    }
}

pub enum RateResult {
    Allowed { remaining: i64 },
    Limited { retry_after: i64 },
}

#[cfg(test)]
mod llm_cache_key_tests {
    use super::RedisCache;
    use serde_json::json;

    fn key(caller: Option<&str>) -> String {
        RedisCache::llm_cache_key("auto", &[json!({"role": "user", "content": "what did we decide?"})], caller)
    }

    /// the same words from two people must not share an entry,
    /// or the second gets an answer composed from the first one's documents.
    #[test]
    fn two_people_asking_the_same_thing_do_not_share_a_cache_entry() {
        assert_ne!(key(Some("a")), key(Some("b")));
        assert_eq!(key(Some("a")), key(Some("a")));
    }

    #[test]
    fn a_connection_and_its_account_are_one_person() {
        assert_eq!(key(Some("a/laptop")), key(Some("a")));
        assert_ne!(key(Some("a/laptop")), key(Some("b/laptop")));
    }

    #[test]
    fn a_machine_caller_has_its_own_bucket_and_never_shares_with_a_person() {
        assert_ne!(key(None), key(Some("a")));
        assert_ne!(key(None), key(Some("")));
        assert_ne!(key(None), key(Some("machine")));
    }
}

/// The 2026-10-15 defect: Redis not accepting connections when the gateway
/// boots must not leave it Redis-less until a restart.
#[cfg(test)]
mod reconnect_tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    /// A RESP2 responder just big enough for fred's handshake and a SET/GET:
    /// PING -> PONG, GET -> the last SET value (or nil), everything else OK.
    async fn fake_redis(port: u16) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let (r, mut w) = sock.into_split();
                    let mut r = BufReader::new(r);
                    let mut stored: Option<String> = None;
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).await.unwrap_or(0) == 0 { return; }
                        let Some(n) = line.trim_end().strip_prefix('*').and_then(|n| n.parse::<usize>().ok()) else { continue };
                        let mut args = Vec::with_capacity(n);
                        for _ in 0..n {
                            let mut len = String::new();
                            r.read_line(&mut len).await.unwrap();
                            let mut val = String::new();
                            r.read_line(&mut val).await.unwrap();
                            args.push(val.trim_end().to_string());
                        }
                        let reply = match args.first().map(|a| a.to_ascii_uppercase()).as_deref() {
                            Some("PING") => "+PONG\r\n".to_string(),
                            Some("SET") => { stored = args.get(2).cloned(); "+OK\r\n".to_string() }
                            Some("GET") => match &stored {
                                Some(v) => format!("${}\r\n{v}\r\n", v.len()),
                                None => "$-1\r\n".to_string(),
                            },
                            _ => "+OK\r\n".to_string(),
                        };
                        if w.write_all(reply.as_bytes()).await.is_err() { return; }
                    }
                });
            }
        });
    }

    async fn until_connected(slot: &RedisSlot, secs: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        while std::time::Instant::now() < deadline {
            if slot.state() == RedisState::Connected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    #[test]
    fn a_bad_url_is_unavailable_not_reconnecting() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let slot = rt.block_on(RedisSlot::connect("not a url", Duration::from_millis(10)));
        assert!(slot.is_none());
        assert_eq!(slot.state(), RedisState::Unavailable);
    }

    /// Redis down at boot -> the boot budget runs out -> the slot is empty
    /// and says `reconnecting` -> Redis comes up -> the slot fills on its
    /// own and commands work. No restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redis_down_at_boot_connects_later_without_a_restart() {
        let port = free_port();
        let url = format!("redis://127.0.0.1:{port}");
        let slot = RedisSlot::connect(&url, Duration::from_millis(500)).await;
        assert!(slot.is_none(), "nothing listens yet");
        assert_eq!(slot.state(), RedisState::Reconnecting);

        fake_redis(port).await;
        assert!(until_connected(&slot, 20).await, "the slot never filled: {:?}", slot.state());
        let cache = slot.as_ref().expect("filled");
        assert!(cache.is_healthy().await);
        assert!(cache.set_string("noo:test:k", "v").await);
        assert_eq!(cache.get_string("noo:test:k").await.as_deref(), Some("v"));
    }

    /// The same against a REAL redis in a throwaway container (opt-in: needs
    /// docker and the DHI redis image). `cargo test -- --ignored real_redis`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs docker + ghcr.io/noomesh/dhi/redis:8.6-debian13-dev"]
    async fn real_redis_down_at_boot_connects_later() {
        let port = free_port();
        let url = format!("redis://127.0.0.1:{port}");
        let slot = RedisSlot::connect(&url, Duration::from_millis(500)).await;
        assert_eq!(slot.state(), RedisState::Reconnecting);

        let name = format!("noo-test-redis-reconnect-{port}");
        let out = std::process::Command::new("docker")
            .args(["run", "--rm", "-d", "--name", &name, "-p", &format!("127.0.0.1:{port}:6379"),
                   "ghcr.io/noomesh/dhi/redis:8.6-debian13-dev", "redis-server", "--save", "", "--appendonly", "no", "--protected-mode", "no"])
            .output()
            .expect("docker");
        assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
        let connected = until_connected(&slot, 30).await;
        let roundtrip = match slot.as_ref() {
            Some(c) => c.set_string("noo:test:k", "v").await && c.get_string("noo:test:k").await.as_deref() == Some("v"),
            None => false,
        };
        let _ = std::process::Command::new("docker").args(["rm", "-f", &name]).output();
        assert!(connected, "the slot never filled: {:?}", slot.state());
        assert!(roundtrip);
    }
}
