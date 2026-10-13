// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Periodic archiver for recall memory (System 1 recall).
//!
//! Spawned once at startup from `main.rs`. Calls the Python worker's
//! `worker.recall.archive` NATS handler at a fixed interval. Mirrors the
//! pattern in `ingest_loop.rs` — Rust drives the schedule, Python does the
//! ML/DB work.
//!
//! Why this exists: when the gateway was ported to Rust, only the read API
//! and tool dispatch landed. The Python lifespan that used to schedule
//! `VideoMemoryManager.archive_all()` every 10 minutes never got a Rust
//! equivalent, so recall memory silently never ingested.
//!
//! Loop and event names: the loop registers with `loop_health` as
//! `recall_memory_archive` (renamed from the deprecated `video_memory_archive`)
//! and logs `recall_memory_archive.cycle_ok|cycle_failed`. Nothing persisted keys
//! on the old name: loop_health is in-memory, its stale alert is titled by
//! the loop name, and no dashboard or alert rule in `monitoring/` names it.
//!
//! The dashboard's "Archive Now" button hits the same Python code path
//! manually — this module just makes it happen automatically.

use std::sync::Arc;

use serde_json::json;
use tracing::{debug, info};

use crate::state::AppState;
use crate::worker_client;

/// Default 10 minutes — matches the dashboard "Archive Interval" label.
const ARCHIVE_INTERVAL_SECS: u64 = 600;

/// The loop's `loop_health` name.
pub const LOOP_NAME: &str = "recall_memory_archive";

/// Grace period at startup so the Python worker has time to come up
/// before we hit it. Same shape as ingest_loop.rs.
const STARTUP_GRACE_SECS: u64 = 30;

/// Spawn the archive loop. No-op if NATS isn't available (the request
/// would just fail every cycle).
pub fn spawn(state: Arc<AppState>) {
    // Startup grace so VideoMemoryManager finishes initializing in the
    // Python worker before the first call; first archive runs one full
    // interval after that (default first-tick semantics).
    crate::managed_loop::ManagedLoop::new(LOOP_NAME, ARCHIVE_INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .spawn(state, |state| async move {
            run_once(&state).await;
            Ok(())
        });
}

async fn run_once(state: &AppState) {
    // Lifecycle maintenance over everyone's recall rows: an internal
    // actor with exactly the scopes the handler needs, never admin.
    match crate::bus_principal::with_internal(
        "recall-archive",
        &["read", "write"],
        worker_client::request(&state.nats, "worker.recall.archive", &json!({})),
    )
    .await
    {
        Ok(resp) => {
            let archived = resp
                .get("data")
                .and_then(|d| d.get("archived"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if archived > 0 {
                info!(archived, "recall_memory_archive.cycle_ok");
            } else {
                debug!("recall_memory_archive.cycle_ok (no new records)");
            }
        }
        Err(e) => {
            // Most common cause: Python worker not running, or
            // VideoMemoryManager not initialized. Either way we just retry
            // next cycle — no point spamming errors.
            debug!(error = %e, "recall_memory_archive.cycle_failed");
        }
    }
}
