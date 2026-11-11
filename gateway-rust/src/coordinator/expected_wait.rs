//! Expected wait for an interactive chat request (speed review 2026-11-11,
//! operator-approved rule; narrows the 2026-10-19 "preferences, not
//! selections" for interactive callers only).
//!
//! The rule, applied by [`plan`] to the candidates a request may ALREADY
//! use (class, audience, node pin and strictness are judged before it, and
//! it only drops or reorders; it never adds a candidate):
//!
//! 1. An interactive request never STARTS on a candidate whose slots are
//!    all full while an allowed candidate has a free slot. Full candidates
//!    are used only when no free one is allowed, shortest expected wait first.
//! 2. Expected wait = (ahead + 1) × that backend's recent p50 per request,
//!    where `ahead` is 0 for a free backend and, for a full one, its queue
//!    plus the slot it waits for (`queued + 1`); the `+ 1` is this
//!    request's own service. A candidate over [`MAX_WAIT`] is skipped. A
//!    candidate with no recent p50 is not skipped (no evidence), and keeps
//!    its place. When nothing is left, the answer is 503 with Retry-After
//!    and a reason an agent can read. The first choice failing is retried
//!    once after [`RETRY_FIRST_AFTER`] (raw_chat::failover_core).
//! 3. "GPU shared" only demotes in the class order (classes.rs); it never
//!    makes a free vLLM wait behind a full or slow fallback, because the
//!    expected wait, not the demotion, decides here.
//!
//! Which requests are interactive is the gateway's decision: the route
//! (`source`), never a caller header. Batch work (ingest, heartbeat tasks,
//! jobs) does not reach raw_chat.
//!
//! The p50s come from the request traces (`noo_request_trace`, which names
//! the backend and node of every chat, streams included, since
//! `request_trace::note_served`), read every [`REFRESH_SECS`] into memory:
//! routing never queries the database.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use super::classes::{self, Candidate};
use crate::state::AppState;

/// Over this, a candidate is too slow for an interactive request.
pub const MAX_WAIT: Duration = Duration::from_secs(60);
/// The first choice failing is retried once after this.
pub const RETRY_FIRST_AFTER: Duration = Duration::from_secs(2);
/// How often the p50s are re-read from the traces.
pub const REFRESH_SECS: u64 = 60;
/// The window and the evidence a p50 needs.
pub const WINDOW_MINUTES: i64 = 30;
pub const MIN_SAMPLES: i64 = 5;
pub const LOOP_NAME: &str = "chat_expected_wait";
/// Retry-After when a refusal has no measured wait to name (not reached in
/// practice: a refusal always comes from a measured wait over MAX_WAIT).
const UNMEASURED_RETRY_AFTER_SECS: u64 = 5;

/// The sources (routes) whose requests are interactive. Fixed by the
/// gateway; a caller cannot choose it.
pub fn interactive(source: &str) -> bool {
    matches!(source, "external" | "v1" | "api")
}

static P50: RwLock<Option<HashMap<(String, String), u64>>> = RwLock::new(None);

/// The recent p50 (ms) of `backend` on `node`, when there is enough evidence.
pub fn p50_ms(node: &str, backend: &str) -> Option<u64> {
    P50.read().ok()?.as_ref()?.get(&(node.to_string(), backend.to_string())).copied()
}

/// Replace the cached p50s (the refresh loop; tests).
pub fn set_p50s(rows: HashMap<(String, String), u64>) {
    if let Ok(mut g) = P50.write() {
        *g = Some(rows);
    }
}

/// One candidate's expected wait, or `None` when its backend has no recent
/// p50. `in_flight` is this gateway's own count for it (classes::in_flight).
pub fn expected_wait(c: &Candidate, in_flight: usize, p50: Option<u64>) -> Option<Duration> {
    let p50 = p50?;
    let ahead = if classes::full_rank(c, in_flight) > 0 { c.slots.map(|s| s.queued as u64).unwrap_or(0) + 1 } else { 0 };
    Some(Duration::from_millis((ahead + 1).saturating_mul(p50)))
}

/// What to do with an interactive request.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Try these candidates (indices into the input), in this order.
    Try(Vec<usize>),
    /// Nothing can answer within [`MAX_WAIT`]: 503, Retry-After `secs`.
    Refuse { retry_after_secs: u64, reason: String },
}

/// Apply rules 1 and 2 to `cands` (already in class order). `in_flight` and
/// `p50` are passed in so the rule is a pure function of what it is shown.
pub fn plan(cands: &[Candidate], in_flight: &dyn Fn(&Candidate) -> usize, p50: &dyn Fn(&Candidate) -> Option<u64>) -> Plan {
    let mut free = Vec::new();
    let mut full: Vec<(usize, Option<Duration>)> = Vec::new();
    let mut shortest_refused: Option<Duration> = None;
    for (i, c) in cands.iter().enumerate() {
        let n = in_flight(c);
        let wait = expected_wait(c, n, p50(c));
        if let Some(w) = wait.filter(|w| *w > MAX_WAIT) {
            shortest_refused = Some(shortest_refused.map_or(w, |s| s.min(w)));
            continue;
        }
        if classes::full_rank(c, n) > 0 {
            full.push((i, wait));
        } else {
            free.push(i);
        }
    }
    if !free.is_empty() {
        return Plan::Try(free);
    }
    if !full.is_empty() {
        // Known waits shortest first; unknown ones after, in class order.
        full.sort_by_key(|(i, w)| (w.is_none(), w.unwrap_or_default(), *i));
        return Plan::Try(full.into_iter().map(|(i, _)| i).collect());
    }
    let secs = shortest_refused.map(|d| d.as_secs().max(1)).unwrap_or(UNMEASURED_RETRY_AFTER_SECS);
    Plan::Refuse {
        retry_after_secs: secs,
        reason: format!("all chat backends busy; expected wait {secs} s"),
    }
}

/// The refresh loop: re-read the p50s every [`REFRESH_SECS`].
pub fn spawn(state: Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new(LOOP_NAME, REFRESH_SECS).immediate_first_tick().spawn(state, refresh_tick);
}

async fn refresh_tick(state: Arc<AppState>) -> anyhow::Result<()> {
    let rows = crate::repo::request_trace::chat_p50_by_node_backend(&state.db, WINDOW_MINUTES, MIN_SAMPLES).await?;
    set_p50s(rows.into_iter().map(|(node, backend, p50)| ((node, backend), p50)).collect());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use classes::Slots;

    /// Shapes from the gateway's logs on 2026-11-11.
    fn cand(node: &str, backend: &str, slots: Option<(u32, u32, u32)>) -> Candidate {
        let mut c = Candidate::synthetic(node.into(), backend.into(), "m".into(), format!("https://{node}:8081"));
        c.slots = slots.map(|(in_flight, total, queued)| Slots { in_flight, total, queued });
        c
    }

    fn p50s(map: &'static [(&'static str, u64)]) -> impl Fn(&Candidate) -> Option<u64> {
        move |c: &Candidate| map.iter().find(|(n, _)| *n == c.node_id).map(|(_, p)| *p)
    }

    fn none(_: &Candidate) -> usize {
        0
    }
    const NONE_IN_FLIGHT: &dyn Fn(&Candidate) -> usize = &none;

    #[test]
    fn a_full_slow_fallback_never_starts_while_a_free_one_is_allowed() {
        // mcmini slots_full=4/2,queued=2 listed FIRST (the 01:38 order); awolf free.
        let cands = [cand("mcmini", "ollama", Some((4, 2, 2))), cand("awolf", "vllm", Some((0, 8, 0)))];
        let p = plan(&cands, NONE_IN_FLIGHT, &p50s(&[("mcmini", 170_000), ("awolf", 3_300)]));
        assert_eq!(p, Plan::Try(vec![1]), "awolf only");
    }

    #[test]
    fn a_free_but_slow_backend_is_skipped_for_an_interactive_request() {
        let cands = [cand("mcmini", "ollama", Some((0, 2, 0))), cand("awolf", "vllm", Some((8, 8, 0)))];
        // mcmini is free but 170 s; awolf is full, 1 ahead × 3.3 s → 6.6 s.
        let p = plan(&cands, NONE_IN_FLIGHT, &p50s(&[("mcmini", 170_000), ("awolf", 3_300)]));
        assert_eq!(p, Plan::Try(vec![1]));
    }

    #[test]
    fn every_candidate_full_goes_shortest_expected_wait_first() {
        let cands = [cand("mcmini", "ollama", Some((2, 2, 0))), cand("awolf", "vllm", Some((8, 8, 3)))];
        // mcmini: (0+1+1) × 20 s = 40 s; awolf: (3+1+1) × 3.3 s = 16.5 s.
        let p = plan(&cands, NONE_IN_FLIGHT, &p50s(&[("mcmini", 20_000), ("awolf", 3_300)]));
        assert_eq!(p, Plan::Try(vec![1, 0]));
    }

    #[test]
    fn nothing_within_sixty_seconds_is_a_503_with_retry_after_and_a_reason() {
        let cands = [cand("mcmini", "ollama", Some((4, 2, 2)))];
        // (2+1+1) × 170 s = 680 s.
        match plan(&cands, NONE_IN_FLIGHT, &p50s(&[("mcmini", 170_000)])) {
            Plan::Refuse { retry_after_secs, reason } => {
                assert_eq!(retry_after_secs, 680);
                assert_eq!(reason, "all chat backends busy; expected wait 680 s");
            }
            other => panic!("want a refusal, got {other:?}"),
        }
    }

    #[test]
    fn no_evidence_is_not_a_reason_to_skip() {
        let cands = [cand("awolf", "vllm", None), cand("mcmini", "ollama", Some((0, 2, 0)))];
        assert_eq!(plan(&cands, NONE_IN_FLIGHT, &|_| None), Plan::Try(vec![0, 1]), "class order kept");
    }

    #[test]
    fn this_gateways_own_in_flight_count_makes_a_backend_full() {
        let cands = [cand("mcmini", "ollama", Some((0, 2, 0))), cand("awolf", "vllm", Some((0, 8, 0)))];
        let in_flight = |c: &Candidate| if c.node_id == "mcmini" { 2 } else { 0 };
        assert_eq!(plan(&cands, &in_flight, &|_| Some(1_000)), Plan::Try(vec![1]));
    }

    /// The rule only drops or reorders what it is given: every index it
    /// returns is one of the input's, each at most once, so a backend the
    /// caller may not reach (never in `cands`) can never be chosen, by the
    /// shortest-wait path or any other.
    #[test]
    fn it_never_returns_a_candidate_it_was_not_given() {
        let sets: Vec<Vec<Candidate>> = vec![
            vec![cand("awolf", "vllm", Some((8, 8, 9)))],
            vec![cand("a", "vllm", None), cand("b", "ollama", Some((2, 2, 0)))],
            vec![cand("a", "vllm", Some((0, 8, 0))), cand("b", "ollama", Some((2, 2, 1))), cand("c", "llamacpp", None)],
        ];
        for cands in &sets {
            for p50 in [None, Some(1_000), Some(3_300), Some(200_000)] {
                if let Plan::Try(order) = plan(cands, NONE_IN_FLIGHT, &|_| p50) {
                    let mut seen = order.clone();
                    seen.sort();
                    seen.dedup();
                    assert_eq!(seen.len(), order.len(), "an index twice: {order:?}");
                    assert!(order.iter().all(|i| *i < cands.len()), "{order:?}");
                }
            }
        }
    }

    #[test]
    fn only_the_gateways_own_routes_are_interactive() {
        for s in ["external", "v1", "api"] {
            assert!(interactive(s), "{s}");
        }
        for s in ["", "batch", "heartbeat", "ingest", "External"] {
            assert!(!interactive(s), "{s}");
        }
    }
}
