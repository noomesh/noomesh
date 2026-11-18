// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A node agent's restart, seen from the gateway (the 0.6.26 roll's chat
//! 502, 2026-11-17T17:01:09Z; option B, gateway half).
//!
//! On SIGTERM a node agent that knows this gateway can follow it (it reads
//! [`FEATURE`] in its desired-config) drains: it refuses NEW inference calls
//! with `503 {"error":{"code":"node_restarting"}}` and a `Retry-After` that
//! covers the rest of the drain and the restart, cuts at once the calls this
//! gateway marked [`RESEND_HEADER`]`: `[`RESEND_WHOLE`] (it re-sends them
//! whole: nothing of them has reached a caller), and lets every other stream
//! finish.
//!
//! Here: the marker the gateway puts on those calls; the reading of a
//! `node_restarting` answer ([`restart_wait`]); and the bound on how many
//! calls may wait out one node's restart at once ([`Waiters`]), so a node
//! that never comes back cannot absorb unbounded requests. The wait is an
//! async sleep: no worker thread, no in-flight ticket, no busy slot is held,
//! only the caller's own open request.
//!
//! Never `backend_draining`: that code is Ollama's GPU-hold drain, read as
//! BUSY (never retried, `raw_chat::is_busy_reply`), and a hold outlasts a
//! restart by far.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// The refusal code a draining node agent answers new calls with.
pub const CODE: &str = "node_restarting";
/// The desired-config feature that tells an agent this gateway reads
/// [`CODE`] (an agent refuses with it only when advertised; otherwise new
/// calls behave as before the drain existed).
pub const FEATURE: &str = "node_restarting";
/// The header on a call this gateway will re-send whole if the node cuts it.
pub const RESEND_HEADER: &str = "x-noo-resend";
pub const RESEND_WHOLE: &str = "whole";
/// The longest a call waits out one node's restart, in all.
pub const MAX_WAIT: Duration = Duration::from_secs(30);
/// The wait when a `node_restarting` answer carries no usable Retry-After.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(5);
/// How many calls may wait on one node at once; past it a call fails at
/// once with the node's 503 and Retry-After. ~1-2 chat calls/s at peak on
/// awolf (98k in 7 days) times a 30 s drain.
pub const MAX_WAITERS_PER_NODE: usize = 32;

/// Is this answer a node agent's restart refusal? Then how long to wait
/// before sending again: its Retry-After, else [`DEFAULT_WAIT`], never more
/// than [`MAX_WAIT`]. Decided on the code in the body's `error.code`, on a
/// 503 only.
pub fn restart_wait(status: u16, headers: &axum::http::HeaderMap, body: &str) -> Option<Duration> {
    if status != 503 {
        return None;
    }
    let code = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.pointer("/error/code").and_then(|c| c.as_str()).map(str::to_string));
    if code.as_deref() != Some(CODE) {
        return None;
    }
    let after = headers
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_WAIT);
    Some(after.min(MAX_WAIT))
}

/// How many calls are waiting on each node now (keyed by its URL).
static WAITING: std::sync::LazyLock<Mutex<HashMap<String, usize>>> = std::sync::LazyLock::new(Default::default);

/// One call's place among a node's waiters, given back when dropped.
pub struct Waiter {
    key: String,
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let mut w = WAITING.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = w.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                w.remove(&self.key);
            }
        }
    }
}

/// A place among `node`'s waiters, or `None` when [`MAX_WAITERS_PER_NODE`]
/// already wait on it.
pub fn try_wait(node: &str) -> Option<Waiter> {
    let mut w = WAITING.lock().unwrap_or_else(|e| e.into_inner());
    let n = w.entry(node.to_string()).or_insert(0);
    if *n >= MAX_WAITERS_PER_NODE {
        return None;
    }
    *n += 1;
    Some(Waiter { key: node.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn ra(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::RETRY_AFTER, HeaderValue::from_str(v).unwrap());
        h
    }

    const BODY: &str = r#"{"error":{"code":"node_restarting","message":"the node agent is restarting"}}"#;

    #[test]
    fn a_restart_refusal_says_how_long_to_wait_capped() {
        assert_eq!(restart_wait(503, &ra("12"), BODY), Some(Duration::from_secs(12)));
        assert_eq!(restart_wait(503, &ra("120"), BODY), Some(MAX_WAIT), "never past the cap");
        assert_eq!(restart_wait(503, &HeaderMap::new(), BODY), Some(DEFAULT_WAIT), "no Retry-After: the default");
        assert_eq!(restart_wait(503, &ra("soon"), BODY), Some(DEFAULT_WAIT), "an unreadable Retry-After: the default");
    }

    /// Only the agent's restart code on a 503 is a restart. The GPU-hold
    /// drain and the busy answer are load (never retried); other statuses
    /// and words are not this rule.
    #[test]
    fn nothing_else_is_a_restart() {
        let h = ra("5");
        assert_eq!(restart_wait(503, &h, r#"{"error":{"code":"backend_draining"}}"#), None);
        assert_eq!(restart_wait(503, &h, r#"{"error":{"code":"backend_busy"}}"#), None);
        assert_eq!(restart_wait(502, &h, BODY), None);
        assert_eq!(restart_wait(503, &h, "node_restarting"), None, "a word, not the code");
        assert_eq!(restart_wait(503, &h, r#"{"error":"node_restarting"}"#), None, "not error.code");
    }

    #[test]
    fn a_node_takes_at_most_its_bound_of_waiters_and_gives_places_back() {
        let node = "https://waiters.test:8081";
        let held: Vec<Waiter> = (0..MAX_WAITERS_PER_NODE).map(|_| try_wait(node).expect("a place")).collect();
        assert!(try_wait(node).is_none(), "past the bound: no place");
        assert!(try_wait("https://another.test:8081").is_some(), "per node, not global");
        drop(held);
        assert!(try_wait(node).is_some(), "places come back when the waits end");
    }
}
