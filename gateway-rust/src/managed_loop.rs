// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Shared primitive for always-on periodic background loops.
//!
//! Why this exists: every gateway loop used to hand-roll the same four
//! lines of boilerplate — `tokio::time::interval`, discard-the-immediate
//! first tick, `loop_health::record_tick("name", SECS)` with the interval
//! duplicated as a magic literal, and `if let Err(e) = … tracing::warn!`
//! error wrapping. The dangerous part is the `record_tick` call:
//! `loop_health.rs` exists precisely because a background loop once died
//! silently in production and nobody noticed for weeks (the Python
//! autonomy loop; see the module docs in `loop_health.rs`),
//! and a hand-rolled loop that forgets to register is invisible to the
//! liveness monitor. By baking registration into this helper, any loop
//! spawned through it is automatically covered — forgetting is
//! impossible, and the tick name + interval live in exactly one place.
//!
//! Two entry points:
//! - [`spawn_managed_loop`] — the common case: fixed interval, first run
//!   happens one full interval after spawn (the interval's immediate
//!   first tick is discarded so the gateway can finish initialising).
//! - [`ManagedLoop`] — builder for loops that additionally need a
//!   startup grace sleep (worker warm-up) and/or an immediate first run.
//!
//! Loops that genuinely don't fit a single fixed cadence stay
//! hand-rolled — `heartbeat_loop`'s dual-interval `select!` and
//! `main.rs`'s worker-supervisor state machine — but they MUST still
//! call `loop_health::record_tick` manually each cycle.

use std::future::Future;
use std::sync::Arc;

use tokio::time::{interval, sleep, Duration};

use crate::state::AppState;

/// Builder for a managed background loop. See module docs.
pub struct ManagedLoop {
    name: &'static str,
    interval_secs: u64,
    startup_grace_secs: u64,
    immediate_first_tick: bool,
}

impl ManagedLoop {
    pub fn new(name: &'static str, interval_secs: u64) -> Self {
        Self {
            name,
            interval_secs,
            startup_grace_secs: 0,
            immediate_first_tick: false,
        }
    }

    /// Sleep this long before entering the loop (e.g. so the Python
    /// worker pool has time to come up before the first NATS call).
    pub fn startup_grace(mut self, secs: u64) -> Self {
        self.startup_grace_secs = secs;
        self
    }

    /// Run the first tick immediately (after any startup grace) instead
    /// of waiting one full interval. Matches the historical semantics of
    /// dlq_drain / session eviction / the ingest loops.
    pub fn immediate_first_tick(mut self) -> Self {
        self.immediate_first_tick = true;
        self
    }

    /// Spawn the loop. Each iteration stamps `loop_health::record_tick`
    /// (so the liveness monitor covers this loop from the first cycle),
    /// then runs `tick_fn`; errors are logged as `<name>_error` and never
    /// kill the loop.
    pub fn spawn<F, Fut>(self, state: Arc<AppState>, tick_fn: F)
    where
        F: Fn(Arc<AppState>) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let ManagedLoop {
            name,
            interval_secs,
            startup_grace_secs,
            immediate_first_tick,
        } = self;
        tracing::info!(
            interval_secs,
            startup_grace_secs,
            immediate_first_tick,
            "{}_spawned",
            name
        );
        tokio::spawn(async move {
            if startup_grace_secs > 0 {
                sleep(Duration::from_secs(startup_grace_secs)).await;
            }
            let mut tick = interval(Duration::from_secs(interval_secs));
            if !immediate_first_tick {
                // Discard the interval's immediate first tick — first run
                // happens one full interval from now.
                tick.tick().await;
            }
            loop {
                tick.tick().await;
                crate::loop_health::record_tick(name, interval_secs);
                if let Err(e) = tick_fn(state.clone()).await {
                    tracing::warn!(error = %e, "{}_error", name);
                }
            }
        });
    }
}

/// Spawn a managed background loop with default semantics: fixed
/// interval, first run one full interval after spawn. See [`ManagedLoop`]
/// for startup-grace / immediate-first-tick variants.
pub fn spawn_managed_loop<F, Fut>(
    name: &'static str,
    interval_secs: u64,
    state: Arc<AppState>,
    tick_fn: F,
) where
    F: Fn(Arc<AppState>) -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    ManagedLoop::new(name, interval_secs).spawn(state, tick_fn)
}
