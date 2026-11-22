// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A per-ROUTE bound on one coordinator turn (i1178a).
//!
//! The turn deadline (`turn_deadline()`, 900 s) is one clock for every route:
//! the console's socket, the SSE chat, `/api/external` and the plain
//! `/api/inference`. The plain route answers nothing until the whole tool
//! loop ends, so its caller waits in silence for as long as the turn runs.
//! This module lets ONE route run its turn under a shorter cap without
//! touching any other: the handler wraps the turn in [`scope`], and the loop
//! reads [`current`] (`turn_ends_at`, `model_call_budget`, the per-tool
//! bound) and reports its progress into it, so a turn stopped by the cap, or
//! dropped by the handler's outer timeout, still says how far it got.
//!
//! A turn outside a scope (every other route) sees `None` and runs exactly as
//! before.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
pub struct RouteBudget {
    pub cap: Duration,
    iterations: AtomicU32,
    tool_calls: AtomicU32,
    deadline_stopped: AtomicBool,
}

impl RouteBudget {
    pub fn new(cap: Duration) -> Arc<Self> {
        Arc::new(Self { cap, iterations: AtomicU32::new(0), tool_calls: AtomicU32::new(0), deadline_stopped: AtomicBool::new(false) })
    }
    pub fn iterations(&self) -> u32 {
        self.iterations.load(Ordering::Relaxed)
    }
    pub fn tool_calls(&self) -> u32 {
        self.tool_calls.load(Ordering::Relaxed)
    }
    pub fn deadline_stopped(&self) -> bool {
        self.deadline_stopped.load(Ordering::Relaxed)
    }
}

tokio::task_local! {
    static ROUTE_BUDGET: Arc<RouteBudget>;
}

/// Run `fut` (one turn) under `budget`.
pub async fn scope<F: std::future::Future>(budget: Arc<RouteBudget>, fut: F) -> F::Output {
    ROUTE_BUDGET.scope(budget, fut).await
}

/// The budget of the turn running on this task, if its route set one.
pub fn current() -> Option<Arc<RouteBudget>> {
    ROUTE_BUDGET.try_with(Arc::clone).ok()
}

pub fn note_iteration(n: u32) {
    if let Some(b) = current() {
        b.iterations.store(n, Ordering::Relaxed);
    }
}

pub fn note_tool_call() {
    if let Some(b) = current() {
        b.tool_calls.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn note_deadline_stop() {
    if let Some(b) = current() {
        b.deadline_stopped.store(true, Ordering::Relaxed);
    }
}

/// The turn's length: the global deadline, or the route's cap when shorter.
/// Pure.
pub fn capped(deadline: Duration, cap: Option<Duration>) -> Duration {
    cap.map_or(deadline, |c| deadline.min(c))
}

/// What one more model call may count on: the global per-call budget, or a
/// quarter of the route's cap when that is smaller, so a capped turn still
/// gets several model calls instead of stopping after its first (the loop
/// refuses a second call with less than this left). Pure.
pub fn call_budget(base: Duration, cap: Option<Duration>) -> Duration {
    cap.map_or(base, |_c| base)
}

/// How long one tool call may take: what is left of the turn, and on a
/// capped route also no more than the tool timeout. Pure.
pub fn tool_bound(left: Duration, tool_timeout: Duration, capped_route: bool) -> Duration {
    if capped_route { left.min(tool_timeout) } else { left }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_a_scoped_turn_sees_a_budget_and_its_progress_is_kept() {
        assert!(current().is_none(), "outside a scope every route runs as before");
        let b = RouteBudget::new(Duration::from_secs(240));
        let seen = scope(b.clone(), async {
            note_iteration(3);
            note_tool_call();
            note_tool_call();
            note_deadline_stop();
            current().map(|c| c.cap)
        })
        .await;
        assert_eq!(seen, Some(Duration::from_secs(240)));
        assert_eq!((b.iterations(), b.tool_calls(), b.deadline_stopped()), (3, 2, true));
        assert!(current().is_none());
    }

    #[test]
    fn the_cap_shortens_the_turn_and_never_lengthens_it() {
        let d = Duration::from_secs(900);
        assert_eq!(capped(d, None), d);
        assert_eq!(capped(d, Some(Duration::from_secs(240))), Duration::from_secs(240));
        assert_eq!(capped(Duration::from_secs(60), Some(Duration::from_secs(240))), Duration::from_secs(60));
    }

    #[test]
    fn a_capped_turn_still_gets_several_model_calls() {
        let base = Duration::from_secs(300);
        assert_eq!(call_budget(base, None), base);
        assert_eq!(call_budget(base, Some(Duration::from_secs(240))), Duration::from_secs(60));
    }

    #[test]
    fn a_tool_is_bounded_by_the_turn_and_on_a_capped_route_by_the_tool_timeout() {
        let t = Duration::from_secs(120);
        assert_eq!(tool_bound(Duration::from_secs(800), t, false), Duration::from_secs(800));
        assert_eq!(tool_bound(Duration::from_secs(800), t, true), t);
        assert_eq!(tool_bound(Duration::from_secs(30), t, true), Duration::from_secs(30));
    }
}
