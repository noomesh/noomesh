// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! In-process session cache (TTL + eviction) and history summarization
//! of dropped messages.

use serde_json::Value;

use std::time::{Duration, Instant};

use crate::session::{self, Session};
use crate::state::AppState;

#[allow(unused_imports)]
use super::*;

const SESSION_CACHE_TTL_SECS: u64 = 600; // 10 minutes

// ── Conversation ownership ──
//
// Every message is durable in Postgres; only this LRU cache is per-process.
// So the one way two processes — a second gateway, or a node-hosted
// harness — could disagree about a conversation is if BOTH had it cached
// while the other wrote. The invariant that prevents it: a conversation
// is OWNED by one process at a time. Ownership is a Redis key naming the
// instance, refreshed on every turn and expiring with the cache TTL. A
// process that finds the key naming someone else does not trust its own
// cache for that conversation: it drops the entry and reloads from the
// database, then takes ownership. With one gateway this never triggers;
// it is the seam the harness-on-node work stands on.

const OWNER_KEY_PREFIX: &str = "noo:conv:owner:";

/// This process, as the owner key names it. Stable for the process
/// lifetime; distinct across restarts (pid) and hosts (hostname).
fn instance_id() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        let host = std::env::var("HOSTNAME")
            .ok()
            .filter(|h| !h.is_empty())
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|h| h.trim().to_string()))
            .unwrap_or_else(|| "gateway".into());
        format!("{host}:{}", std::process::id())
    })
}

/// The pure decision: may this process trust its cached copy?
/// `owner` is what Redis holds (None = nobody yet, or Redis absent).
pub(crate) fn cache_trustworthy(owner: Option<&str>, me: &str) -> bool {
    match owner {
        None => true,
        Some(o) => o == me,
    }
}

/// Take (or renew) ownership. Best-effort: Redis down means single-process
/// semantics, which is exactly today's behaviour.
async fn claim_ownership(state: &AppState, conversation_id: &str) {
    if let Some(redis) = &state.redis {
        let key = format!("{OWNER_KEY_PREFIX}{conversation_id}");
        if redis.set_string(&key, instance_id()).await {
            let _ = redis.expire(&key, SESSION_CACHE_TTL_SECS as i64).await;
        }
    }
}

/// Get session from cache or load from DB. Updates last_access timestamp.
pub(super) async fn get_or_load_session(
    state: &AppState,
    conversation_id: &str,
    channel: &str,
) -> Session {
    // Ownership first: a cached copy is only ours to trust if no other
    // process has served this conversation since we cached it.
    let owner = match &state.redis {
        Some(redis) => redis.get_string(&format!("{OWNER_KEY_PREFIX}{conversation_id}")).await,
        None => None,
    };
    if !cache_trustworthy(owner.as_deref(), instance_id()) {
        let mut cache = state.session_cache.write().await;
        if cache.remove(conversation_id).is_some() {
            tracing::info!(
                conversation = %conversation_id, owner = owner.as_deref().unwrap_or("?"),
                "session_cache.dropped_after_foreign_owner"
            );
        }
    }
    claim_ownership(state, conversation_id).await;

    // Check cache first
    {
        let mut cache = state.session_cache.write().await;
        if let Some(cached) = cache.get_mut(conversation_id) {
            cached.last_access = Instant::now();
            return cached.session.clone();
        }
    }

    // Not cached — create new session, load history from DB
    let mut session = Session::new(conversation_id.to_string(), channel.to_string());
    if let Ok(history) = session::load_session(
        &state.db, conversation_id, state.config.coordinator.max_session_messages,
    ).await {
        for msg in history {
            session.messages.push(msg);
        }
    }
    session
}

/// Save session back to cache after request completes.
/// Evicts least-recently-used entries first if the cache is at capacity —
/// guard-rails the cache from growing unboundedly under bursty traffic.
pub(super) async fn cache_session(state: &AppState, conversation_id: &str, session: Session) {
    let max_count = session_cache_max_count();
    let mut cache = state.session_cache.write().await;
    if cache.len() >= max_count && !cache.contains_key(conversation_id) {
        // Evict the single least-recently-used entry. With TTL + this cap,
        // memory stays bounded under any traffic pattern.
        if let Some((evict_id, _)) = cache
            .iter()
            .min_by_key(|(_, cached)| cached.last_access)
            .map(|(id, c)| (id.clone(), c.last_access))
        {
            cache.remove(&evict_id);
            tracing::debug!(evicted = %evict_id, cap = max_count, "session_cache.lru_evicted");
        }
    }
    cache.insert(conversation_id.to_string(), crate::state::CachedSession {
        session,
        last_access: Instant::now(),
    });
}

/// Resolve the session-cache cap. Defaults to 1000; override via
/// `NOO_SESSION_CACHE_MAX_COUNT` env. Cached on first call so the env
/// read is cheap on the hot path.
fn session_cache_max_count() -> usize {
    static CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("NOO_SESSION_CACHE_MAX_COUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    })
}

/// Evict expired sessions from cache. Called periodically or on access.
pub async fn evict_stale_sessions(state: &AppState) {
    let mut cache = state.session_cache.write().await;
    let ttl = Duration::from_secs(SESSION_CACHE_TTL_SECS);
    cache.retain(|_id, cached| cached.last_access.elapsed() < ttl);
}

// ═══════════════════════════════════════════════════════════════
// Long-conversation context support (Options A + C)
// ═══════════════════════════════════════════════════════════════

/// Build a synthetic summary message describing dropped history.
/// Inserted as a system message so the model retains thread continuity
/// even when older messages get truncated. Adds ~150 tokens.
pub(super) fn build_history_summary(dropped_messages: &[Value], conversation_id: &str) -> Option<String> {
    if dropped_messages.is_empty() {
        return None;
    }

    let count = dropped_messages.len();
    let user_msgs: Vec<&str> = dropped_messages.iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
        .collect();

    let tool_calls: std::collections::HashSet<String> = dropped_messages.iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("assistant"))
        .filter_map(|m| m.get("tool_calls").and_then(|t| t.as_array()))
        .flatten()
        .filter_map(|tc| tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).map(String::from))
        .collect();

    let mut summary = format!("[Earlier in this conversation ({conversation_id}): {count} messages dropped from context.");

    if let Some(first) = user_msgs.first() {
        let preview: String = first.chars().take(200).collect();
        summary.push_str(&format!(" First user request: \"{preview}\"."));
    }

    if user_msgs.len() > 2 {
        let later: Vec<String> = user_msgs.iter()
            .skip(1)
            .map(|s| s.chars().take(80).collect::<String>())
            .collect();
        summary.push_str(&format!(" Subsequent topics: {}.", later.join(" / ")));
    }

    if !tool_calls.is_empty() {
        let mut names: Vec<&String> = tool_calls.iter().collect();
        names.sort();
        summary.push_str(&format!(" Tools used: {}.", names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }

    summary.push_str(" Use noo_memory_search if you need specific details.]");
    Some(summary)
}

#[cfg(test)]
mod ownership_tests {
    use super::cache_trustworthy;

    /// The invariant in one table: nobody / me → trust the cache; someone
    /// else → do not, reload from the database.
    #[test]
    fn a_foreign_owner_invalidates_the_local_cache() {
        assert!(cache_trustworthy(None, "gw-a:1"));
        assert!(cache_trustworthy(Some("gw-a:1"), "gw-a:1"));
        assert!(!cache_trustworthy(Some("gw-b:7"), "gw-a:1"));
        assert!(!cache_trustworthy(Some("node-phone:42"), "gw-a:1"), "a node-hosted harness counts as another process");
        // A restart is a new process: the old pid's ownership must not be
        // mistaken for ours (the cache is empty anyway, so this only costs a
        // DB load — the safe direction).
        assert!(!cache_trustworthy(Some("gw-a:1"), "gw-a:2"));
    }
}
