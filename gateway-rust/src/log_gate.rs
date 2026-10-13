// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A per-key gate for a log line that repeats.
//!
//! The gateway's `embed_node_failed` WARN fired once per embed request
//! while one node's embedder was down: 11,751 of the ~42,600 lines the
//! gateway wrote in an hour on the live controller were that
//! one line — roughly half the fleet's log volume, saying nothing the first
//! line had not said. A line that repeats because a STATE persists should
//! be logged when the state begins, then once per window with a count of
//! what was suppressed, and again when the state ends.
//!
//! Pure over a caller-supplied clock so the decision is tested without
//! sleeping. The house shape for this is `middleware::refusal_storm_tick`
//! (once per peer per minute); this is the same idea with a longer window
//! and an explicit "recovered" reset.

use std::collections::HashMap;
use std::sync::Mutex;

struct Entry {
    last_logged: u64,
    suppressed: u32,
}

pub(crate) struct LogGate {
    window_secs: u64,
    inner: Mutex<HashMap<String, Entry>>,
}

/// Keys the gate remembers before it forgets everything — a runaway key
/// space (a node id per request, say) must not become a leak.
const MAX_KEYS: usize = 4096;

impl LogGate {
    pub(crate) fn new(window_secs: u64) -> Self {
        Self { window_secs, inner: Mutex::new(HashMap::new()) }
    }

    /// Should this occurrence of `key` be logged? `Some(n)` when it should,
    /// with `n` = how many occurrences were suppressed since the last one
    /// logged (0 on the first); `None` when it is inside the window.
    pub(crate) fn should_log(&self, key: &str, now_secs: u64) -> Option<u32> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > MAX_KEYS && !map.contains_key(key) {
            map.clear();
        }
        match map.get_mut(key) {
            None => {
                map.insert(key.to_string(), Entry { last_logged: now_secs, suppressed: 0 });
                Some(0)
            }
            Some(e) if now_secs.saturating_sub(e.last_logged) >= self.window_secs => {
                let n = e.suppressed;
                e.last_logged = now_secs;
                e.suppressed = 0;
                Some(n)
            }
            Some(e) => {
                e.suppressed = e.suppressed.saturating_add(1);
                None
            }
        }
    }

    /// The state behind `key` ended (the node answered again). Forget it,
    /// so the next failure is logged at once — a change of state is news
    /// even inside the window. Returns whether the key had been failing,
    /// so the caller can log the recovery exactly once.
    pub(crate) fn clear(&self, key: &str) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(key).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_occurrence_logs_and_the_window_suppresses_with_a_count() {
        let g = LogGate::new(300);
        assert_eq!(g.should_log("host3", 1000), Some(0), "the first failure is news");
        for t in 1001..1300 {
            assert_eq!(g.should_log("host3", t), None, "inside the window at t={t}");
        }
        assert_eq!(g.should_log("host3", 1300), Some(299), "the window's end logs once, with what it swallowed");
        assert_eq!(g.should_log("host3", 1301), None);
        assert_eq!(g.should_log("host3", 1600), Some(1));
    }

    #[test]
    fn keys_are_independent() {
        let g = LogGate::new(300);
        assert_eq!(g.should_log("host3", 10), Some(0));
        assert_eq!(g.should_log("host6", 10), Some(0), "another node's first failure is its own news");
        assert_eq!(g.should_log("host3", 11), None);
        assert_eq!(g.should_log("host6", 11), None);
    }

    #[test]
    fn a_recovery_resets_so_the_next_failure_logs_at_once() {
        let g = LogGate::new(300);
        assert_eq!(g.should_log("host3", 10), Some(0));
        assert_eq!(g.should_log("host3", 11), None);
        assert!(g.clear("host3"), "it had been failing");
        assert!(!g.clear("host3"), "cleared twice = nothing to say the second time");
        assert_eq!(g.should_log("host3", 12), Some(0), "a new outage inside the old window is a state change");
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_panic_or_flood() {
        let g = LogGate::new(300);
        assert_eq!(g.should_log("k", 1000), Some(0));
        assert_eq!(g.should_log("k", 900), None);
    }

    #[test]
    fn a_runaway_key_space_is_bounded() {
        let g = LogGate::new(300);
        for i in 0..(MAX_KEYS + 10) {
            g.should_log(&format!("k{i}"), 1);
        }
        assert!(g.inner.lock().unwrap().len() <= MAX_KEYS + 1);
    }
}
