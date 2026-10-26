// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The scheduler loop in Rust — the dispatch half of the scheduler port.
//!
//! Phases 2-5 ported the pure logic (`scheduler_slots`, `scheduler_job`,
//! `scheduler_candidates`) and proved it against the live queue without
//! writing anything, via a dark run that phase 7 retired (there is no
//! longer a Python decision to diff against). This module is the Rust code
//! that can actually move a job: it claims from `noo:jobs:queue`, publishes
//! `tasks.dispatch.<node>`, reaps timeouts and runs the janitor.
//!
//! # Sole ownership
//!
//! Phase 6 shipped this behind `NOO_SCHEDULER_ENGINE=rust|python` so the
//! cutover could be rolled back by restarting with the flag unset. Phase 7
//! deleted the Python dispatch loop, so there is no second engine to select
//! and the flag is gone: these loops always run, and this module is the
//! only publisher of `tasks.dispatch.<node>` in the system.
//!
//! That is not a weaker guarantee than the flag was. Two dispatchers do not
//! surface as an error — they surface as the same job running twice on two
//! nodes — so the invariant is now enforced by there being exactly one
//! implementation, rather than by two processes agreeing on an env var.
//!
//! # Redis ordering
//!
//! Python ran this as one synchronous single-threaded loop, so
//! `ZREM` → `HSET` → `SADD` could not interleave with its own reaper or
//! janitor. Rust runs three loops concurrently on the tokio runtime
//! against async `fred`, so that assumption is gone. The two transitions
//! where an interleave is actually harmful are done as Lua scripts, which
//! Redis executes atomically:
//!
//! - [`CLAIM_SCRIPT`] — ZREM is the claim. Only the caller whose ZREM
//!   returned 1 writes the DISPATCHED state, so two dispatchers can never
//!   both place the same job, and no observer sees a job that is in
//!   neither the queue nor a node set.
//! - [`TERMINAL_SCRIPT`] — refuses to re-terminalise an already-terminal
//!   job, so the history LPUSH and the `noo_job_runs` row happen exactly
//!   once per job even if a completion event and the reaper race.
//!
//! Everything else is a single Redis command (atomic by construction) or a
//! requeue, where Python was not atomic either and a torn write self-heals
//! on the next janitor pass.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::scheduler_candidates::{self, CompanionPolicies, CompanionPolicy, NodeSnapshot, NodeStatus};
use crate::scheduler_job::{JobRecord, QueueClass};
use crate::state::AppState;

pub const QUEUE_KEY: &str = "noo:jobs:queue";
pub const JOB_KEY_PREFIX: &str = "noo:jobs:";
pub const NODE_JOBS_PREFIX: &str = "noo:jobs:node:";
pub const ACTIVE_SET: &str = "noo:jobs:active";
pub const DRAINED_KEY: &str = "noo:jobs:drained_nodes";
pub const HISTORY_KEY: &str = "noo:jobs:history";
pub const PAUSED_KEY: &str = "noo:scheduler:paused";

/// Must match Python `scheduler.py` constant for constant.
pub const HISTORY_MAX_LEN: i64 = 1000;
pub const JOB_TTL_AFTER_TERMINAL: i64 = 86400;
pub const DISPATCH_ACK_GRACE_SEC: f64 = 90.0;
const MAX_DISPATCH_PER_TICK: usize = 20;
/// How far down the regular lane one tick looks past jobs pinned to a node
/// that cannot take them (see [`dispatch_tick`]).
const PINNED_SKIP_SCAN: i64 = 50;
/// A job still QUEUED this long after submit is expired by the janitor.
///
/// Nothing that waits a day for placement is still wanted in the form it
/// was asked for: the live controller on 2026-10-10 held 21 queued jobs, the
/// oldest three days old, none ever dispatched. A caller with a tighter
/// deadline says so per job (`expire_after_sec` → `expires_at`).
pub const QUEUED_MAX_AGE_SECS: i64 = 86_400;

const DISPATCH_INTERVAL_SECS: u64 = 2;
const REAP_INTERVAL_SECS: u64 = 30;
const JANITOR_INTERVAL_SECS: u64 = 300;

pub const TERMINAL_STATES: &[&str] = &["completed", "cancelled", "dead"];

/// Claim a queued job for a node. Returns 1 if this caller won the claim.
///
/// KEYS: queue, job hash, node job set. ARGV: job_id, node_id, now.
const CLAIM_SCRIPT: &str = r#"
if redis.call('ZREM', KEYS[1], ARGV[1]) == 0 then return 0 end
redis.call('HSET', KEYS[2],
  'status', 'dispatched',
  'node_id', ARGV[2],
  'dispatched_at', ARGV[3],
  'updated_at', ARGV[3])
redis.call('SADD', KEYS[3], ARGV[1])
return 1
"#;

/// Flip a job terminal exactly once: state + active-set removal + node-set
/// removal + capped history + 24h TTL, all in one atomic step.
///
/// Returns 1 only for the caller that performed the transition — that
/// caller, and only it, writes the `noo_job_runs` row.
///
/// KEYS: job hash, active set, node job set, history list.
/// ARGV: job_id, status, now, result, error, history_json, history_max, ttl.
const TERMINAL_SCRIPT: &str = r#"
local cur = redis.call('HGET', KEYS[1], 'status')
if not cur then return 0 end
if cur == 'completed' or cur == 'cancelled' or cur == 'dead' then return 0 end
redis.call('HSET', KEYS[1],
  'status', ARGV[2],
  'updated_at', ARGV[3],
  'completed_at', ARGV[3],
  'result', ARGV[4],
  'error', ARGV[5])
redis.call('SREM', KEYS[2], ARGV[1])
redis.call('SREM', KEYS[3], ARGV[1])
redis.call('LPUSH', KEYS[4], ARGV[6])
redis.call('LTRIM', KEYS[4], 0, tonumber(ARGV[7]) - 1)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[8]))
return 1
"#;

// ── Spawn ──────────────────────────────────────────────────────

pub fn spawn(state: Arc<AppState>) {
    tracing::info!(
        engine = "rust",
        "scheduler_engine: RUST owns dispatch — the only dispatcher in the system"
    );

    // Requeue jobs stranded on dead nodes by the previous process, before
    // the dispatch loop starts placing new ones.
    let recover_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = recover_from_restart(&recover_state).await {
            tracing::warn!(error = %e, "scheduler_engine.recover_failed");
        }
    });

    crate::managed_loop::spawn_managed_loop(
        "scheduler_dispatch",
        DISPATCH_INTERVAL_SECS,
        state.clone(),
        move |state| async move {
            if let Err(e) = dispatch_tick(&state).await {
                tracing::warn!(error = %e, "scheduler_engine.dispatch_tick_failed");
            }
            Ok(())
        },
    );
    crate::managed_loop::spawn_managed_loop(
        "scheduler_reaper",
        REAP_INTERVAL_SECS,
        state.clone(),
        move |state| async move {
            if let Err(e) = reap_timeouts(&state).await {
                tracing::warn!(error = %e, "scheduler_engine.reap_failed");
            }
            // Bulk embedding jobs (i179) are judged here, on the reaper's
            // 30 s clock, not the janitor's 300 s: a pull job with nobody
            // pulling flips to a gateway run after 120 s, not after 420.
            if let Err(e) = crate::embed_jobs::sweep(&state).await {
                tracing::warn!(error = %e, "scheduler_engine.embed_sweep_failed");
            }
            Ok(())
        },
    );
    crate::managed_loop::spawn_managed_loop(
        "scheduler_janitor",
        JANITOR_INTERVAL_SECS,
        state,
        move |state| async move {
            if let Err(e) = janitor(&state).await {
                tracing::warn!(error = %e, "scheduler_engine.janitor_failed");
            }
            Ok(())
        },
    );
}

// ── Node snapshots ─────────────────────────────────────────────

/// Read the node registry out of `mesh_nodes` KV.
pub async fn load_nodes(state: &AppState) -> Vec<NodeSnapshot> {
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else {
        return Vec::new();
    };
    use tokio_stream::StreamExt;
    let Ok(keys) = kv.keys().await else {
        return Vec::new();
    };
    let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;

    let now = now_unix_secs();
    let mut out = Vec::new();
    for key in keys {
        if key == "gateway" {
            continue;
        }
        let Ok(Some(entry)) = kv.get(&key).await else {
            continue;
        };
        let Ok(data) = serde_json::from_slice::<Value>(&entry) else {
            continue;
        };
        out.push(snapshot_from_kv(&key, &data, now));
    }
    out
}

/// Per-node companion policies from desired state (`noo_node_config`,
/// migration 064). Read once per tick, next to the node snapshots; a
/// query failure degrades to "every node gets the default" with a warning,
/// never to a stalled scheduler.
pub async fn load_companion_policies(state: &AppState) -> CompanionPolicies {
    let mut out = CompanionPolicies::default();
    let rows: Result<Vec<(String, Value)>, _> = sqlx::query_as(
        "SELECT node_id, companion_policy FROM noo_node_config WHERE companion_policy IS NOT NULL",
    )
    .fetch_all(&state.db)
    .await;
    match rows {
        Ok(rows) => {
            for (node_id, v) in rows {
                out.per_node.insert(node_id, CompanionPolicy::from_json(&v));
            }
        }
        Err(e) => tracing::warn!(error = %e, "companion_policy_load_failed — using the default for every node"),
    }
    out
}

pub fn now_unix_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Build a snapshot from one KV record.
///
/// `last_heartbeat` is written as epoch seconds by the heartbeat handler,
/// but the dashboard read-path rewrites it to an ISO string — so accept
/// both rather than silently treating a live node as never-seen.
pub fn snapshot_from_kv(node_id: &str, data: &Value, now: f64) -> NodeSnapshot {
    let hb_age = data.get("last_heartbeat").and_then(|v| match v {
        Value::Number(n) => n.as_f64().map(|ts| now - ts),
        Value::String(s) => chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| now - dt.timestamp() as f64),
        _ => None,
    });

    // `capabilities.backends` is what the node CAN serve; `running_backends`
    // is what it is serving NOW. Placement uses the latter;
    // the former is kept for the "capable but not serving" diagnostics.
    let backends = data
        .get("capabilities")
        .and_then(|c| c.get("backends"))
        .and_then(|b| b.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .or_else(|| {
            data.get("running_backends")
                .and_then(|r| r.as_object())
                .map(|o| o.keys().cloned().collect())
        })
        .unwrap_or_default();

    let running_backends: Option<Vec<String>> = data
        .get("running_backends")
        .and_then(|r| r.as_object())
        .map(|o| o.keys().cloned().collect());

    let tier = data.get("tier").cloned().unwrap_or(Value::Null);
    let is_companion = data
        .get("node_type")
        .and_then(|v| v.as_str())
        .map(|s| s == "companion")
        .unwrap_or_else(|| crate::scheduler_slots::normalize_tier(&tier) == Some(5));

    NodeSnapshot {
        id: node_id.to_string(),
        status: data
            .get("status")
            .and_then(|v| v.as_str())
            .map(NodeStatus::parse)
            .unwrap_or(NodeStatus::Offline),
        tier,
        is_companion,
        heartbeat_age_secs: hb_age,
        current_load: data.get("current_load").and_then(|v| v.as_f64()).unwrap_or(0.0),
        vram_gb: data.get("vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0),
        vram_used_gb: data.get("vram_used_gb").and_then(|v| v.as_f64()),
        backends,
        running_backends,
        battery_pct: data.get("battery_pct").and_then(|v| v.as_f64()),
        network_type: data.get("network_type").and_then(|v| v.as_str()).map(String::from),
        thermal_state: data.get("thermal_state").and_then(|v| v.as_str()).map(String::from),
    }
}

// ── Dispatch ───────────────────────────────────────────────────

/// One dispatch tick — mirrors Python `_dispatch_next()`, with one change.
///
/// Regular jobs (score ≤ -1) first, background (score 0) only when no
/// regular job could be placed; up to [`MAX_DISPATCH_PER_TICK`] per tick.
///
/// The change: a regular job PINNED (`force_node`) to a node that is not
/// healthy, or not registered at all, no longer blocks the lane. Python
/// looked only at the head of the lane and stopped there, so one pinned job
/// for an offline node held every regular job behind it — and, because
/// background only runs when the regular lane is clear, every background
/// job too. On 2026-10-10 a `fetch_bundle` poke pinned to `host2` (not a
/// healthy mesh node) sat at the head from 17:09 on, and nothing queued
/// after it was dispatched again: 14 more pokes and 6 background jobs.
/// Such a job is skipped for this tick (it keeps its place for when the
/// node returns, and the janitor's age bound retires it if it never does).
/// A job that cannot be placed for any OTHER reason — busy nodes, an
/// unserved backend — still blocks the lane, as before.
pub async fn dispatch_tick(state: &AppState) -> anyhow::Result<()> {
    let Some(redis) = state.redis.as_ref() else {
        anyhow::bail!("no redis configured");
    };
    if redis.get_string(PAUSED_KEY).await.is_some() {
        return Ok(());
    }

    let nodes = load_nodes(state).await;
    let policies = load_companion_policies(state).await;
    let mut dispatched = 0usize;
    let mut skipped: std::collections::HashSet<String> = std::collections::HashSet::new();
    while dispatched < MAX_DISPATCH_PER_TICK {
        let regular = redis
            .zrangebyscore_limit(QUEUE_KEY, f64::NEG_INFINITY, -1.0, PINNED_SKIP_SCAN)
            .await;
        let scanned_all = (regular.len() as i64) < PINNED_SKIP_SCAN;
        let mut lane = LaneOutcome::Empty;
        for job_id in &regular {
            if skipped.contains(job_id) {
                continue;
            }
            match try_dispatch_job(state, job_id, QueueClass::Regular, &nodes, &policies).await {
                Dispatch::Placed => {
                    lane = LaneOutcome::Placed;
                    break;
                }
                Dispatch::NotPlaced { blocks_lane: false } => {
                    skipped.insert(job_id.clone());
                }
                Dispatch::NotPlaced { blocks_lane: true } => {
                    // A regular job that cannot be placed does NOT let
                    // background work (or later regular jobs) jump the
                    // queue — same as Python.
                    lane = LaneOutcome::Blocked;
                    break;
                }
            }
        }
        match lane {
            LaneOutcome::Placed => {
                dispatched += 1;
                continue;
            }
            LaneOutcome::Blocked => break,
            // Only skippable pinned jobs (or nothing) in the regular lane.
            // If the scan was cut short, a blocking job may sit unseen past
            // it, so stay conservative and let no background work jump.
            LaneOutcome::Empty if !scanned_all => break,
            LaneOutcome::Empty => {}
        }
        let bg = redis.zrangebyscore_limit(QUEUE_KEY, 0.0, 0.0, 1).await;
        let Some(job_id) = bg.into_iter().next() else {
            break;
        };
        if try_dispatch_job(state, &job_id, QueueClass::Background, &nodes, &policies).await != Dispatch::Placed {
            break;
        }
        dispatched += 1;
    }
    if dispatched > 0 {
        tracing::debug!(count = dispatched, "scheduler_engine.tick_dispatched");
    }
    Ok(())
}

/// What one pass over the regular lane found.
enum LaneOutcome {
    Placed,
    Blocked,
    Empty,
}

/// The result of one placement attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Claimed and published.
    Placed,
    /// Not placed. `blocks_lane` is false only when waiting on this job
    /// cannot help any other: it is pinned to a node that is not a healthy
    /// registered node, or its queue entry was stale and has been removed.
    NotPlaced { blocks_lane: bool },
}

/// Whether an unplaceable job should hold up the jobs behind it. Pure, so
/// the head-of-line rule is tested without Redis.
pub fn unplaceable_blocks_lane(force_node: Option<&str>, candidates_empty: bool) -> bool {
    !(force_node.is_some_and(|n| !n.is_empty()) && candidates_empty)
}

/// Place one job. `Placed` only when it was claimed AND published.
async fn try_dispatch_job(
    state: &AppState,
    job_id: &str,
    class: QueueClass,
    nodes: &[NodeSnapshot],
    policies: &CompanionPolicies,
) -> Dispatch {
    const BLOCKED: Dispatch = Dispatch::NotPlaced { blocks_lane: true };
    let Some(redis) = state.redis.as_ref() else {
        return BLOCKED;
    };
    let key = format!("{JOB_KEY_PREFIX}{job_id}");
    let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
    let Some(job) = JobRecord::from_hash(&hash) else {
        // Stale queue entry — Python removes it, so do we.
        redis.zrem(QUEUE_KEY, job_id).await;
        return Dispatch::NotPlaced { blocks_lane: false };
    };

    let candidates = scheduler_candidates::get_candidate_nodes(
        nodes,
        job.backend.as_deref(),
        job.force_node.as_deref(),
        job.task_priority(),
        job.min_vram_gb,
        policies,
    );
    if candidates.is_empty() {
        if let Some(pin) = job.force_node.as_deref().filter(|n| !n.is_empty()) {
            // Pinned to a node that is not a healthy registered node: say
            // so on the job, and let the jobs behind it go first.
            let reason = format!("waiting: pinned to node '{pin}', which is not a healthy registered node");
            if hash.get("status_detail") != Some(&reason) {
                redis.hset(&key, &[("status_detail", reason.as_str())]).await;
            }
            return Dispatch::NotPlaced {
                blocks_lane: unplaceable_blocks_lane(Some(pin), true),
            };
        }
        // A named backend that no healthy node serves would otherwise sit
        // queued with no explanation. Say why on the job (once per change).
        if let (Some(b), None) = (job.backend.as_deref().filter(|b| !b.is_empty()), job.force_node.as_deref()) {
            if let Some(reason) = scheduler_candidates::backend_unserved_reason(nodes, b) {
                if hash.get("status_detail").map(String::as_str) != Some(reason.as_str()) {
                    redis.hset(&key, &[("status_detail", reason.as_str())]).await;
                }
            }
        }
        return BLOCKED;
    }

    let mut occupancy: HashMap<String, u32> = HashMap::new();
    let mut eligible: Vec<&NodeSnapshot> = Vec::new();
    for c in &candidates {
        if redis.sismember(DRAINED_KEY, &c.id).await {
            continue;
        }
        let n = redis.scard(&format!("{NODE_JOBS_PREFIX}{}", c.id)).await;
        occupancy.insert(c.id.clone(), n.max(0) as u32);
        eligible.push(c);
    }

    let Some(node) = scheduler_candidates::pick_node(
        &eligible,
        job.last_failed_node.as_deref(),
        class.requires_all_slots_free(),
        |id| occupancy.get(id).copied().unwrap_or(0),
    ) else {
        return BLOCKED;
    };

    let now = chrono::Utc::now().to_rfc3339();
    let node_set = format!("{NODE_JOBS_PREFIX}{}", node.id);
    let claimed = redis
        .eval_i64(
            CLAIM_SCRIPT,
            &[QUEUE_KEY.to_string(), key.clone(), node_set],
            &[job_id.to_string(), node.id.clone(), now.clone()],
        )
        .await
        .unwrap_or(0);
    if claimed != 1 {
        return BLOCKED; // someone else grabbed it, or Redis is unhappy
    }

    let payload = json!({
        "job_id": job_id,
        "type": hash.get("type").cloned().unwrap_or_default(),
        "payload": hash.get("payload").cloned().unwrap_or_else(|| "{}".into()),
        "timeout_sec": hash
            .get("timeout_sec")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(300),
        "backend": job.backend.clone().unwrap_or_default(),
    });
    let subject = format!("tasks.dispatch.{}", node.id);
    match state
        .js
        .publish(subject.clone(), payload.to_string().into())
        .await
    {
        Ok(ack) => {
            // Await the JetStream ack: a publish that the server never
            // persisted looks identical to a successful one otherwise, and
            // the job would sit DISPATCHED until the janitor's 90s grace.
            if let Err(e) = ack.await {
                tracing::error!(job_id, error = %e, "scheduler_engine.dispatch_ack_failed");
                requeue_job(state, job_id, &node.id).await;
                return BLOCKED;
            }
        }
        Err(e) => {
            tracing::error!(job_id, error = %e, "scheduler_engine.dispatch_publish_failed");
            requeue_job(state, job_id, &node.id).await;
            return BLOCKED;
        }
    }

    tracing::info!(
        job_id,
        node = %node.id,
        job_type = %job.job_type,
        background = class.requires_all_slots_free(),
        "scheduler_engine.job_dispatched"
    );
    Dispatch::Placed
}

/// Put a job back in the queue after a failed dispatch — Python
/// `_requeue_job()`. Records the node that failed so the next placement
/// pass avoids it; goes DEAD past `max_retries` rather than ping-ponging.
pub async fn requeue_job(state: &AppState, job_id: &str, node_id: &str) {
    let Some(redis) = state.redis.as_ref() else {
        return;
    };
    let key = format!("{JOB_KEY_PREFIX}{job_id}");
    let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
    if hash.is_empty() {
        return;
    }
    let failures = num(&hash, "dispatch_failures", 0) + 1;
    let max_retries = num(&hash, "max_retries", 2);
    let now = chrono::Utc::now().to_rfc3339();

    if failures > max_retries {
        let error = format!("dispatch failed {failures}x (last node: {node_id} never acked)");
        redis
            .hset(&key, &[("dispatch_failures", failures.to_string().as_str())])
            .await;
        terminalize(state, job_id, "dead", "", &error).await;
        tracing::error!(job_id, failures, last_node = node_id, "scheduler_engine.job_dead_dispatch_failures");
        return;
    }

    let priority = num(&hash, "priority", 5);
    redis
        .hset(
            &key,
            &[
                ("status", "queued"),
                ("node_id", ""),
                ("dispatched_at", ""),
                ("updated_at", now.as_str()),
                ("dispatch_failures", failures.to_string().as_str()),
                ("last_failed_node", node_id),
            ],
        )
        .await;
    redis.zadd(QUEUE_KEY, job_id, -(priority as f64)).await;
    if !node_id.is_empty() {
        redis.srem(&format!("{NODE_JOBS_PREFIX}{node_id}"), job_id).await;
    }
    tracing::info!(job_id, failures, avoid_node = node_id, "scheduler_engine.job_requeued");
}

/// Requeue for a *retry* (timeout / node-reported failure) — Python's
/// reaper and `on_job_failed` share this shape: bump `retries`, clear the
/// assignment, and steer the next attempt away from the failing node.
pub async fn requeue_for_retry(
    state: &AppState,
    job_id: &str,
    node_id: &str,
    retries: i64,
    error: &str,
) {
    let Some(redis) = state.redis.as_ref() else {
        return;
    };
    let key = format!("{JOB_KEY_PREFIX}{job_id}");
    let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
    let priority = num(&hash, "priority", 5);
    let now = chrono::Utc::now().to_rfc3339();
    let mut fields: Vec<(&str, &str)> = vec![
        ("status", "queued"),
        ("node_id", ""),
        ("dispatched_at", ""),
    ];
    let retries_s = retries.to_string();
    fields.push(("retries", retries_s.as_str()));
    fields.push(("updated_at", now.as_str()));
    fields.push(("error", error));
    if !node_id.is_empty() {
        fields.push(("last_failed_node", node_id));
    }
    redis.hset(&key, &fields).await;
    redis.zadd(QUEUE_KEY, job_id, -(priority as f64)).await;
    if !node_id.is_empty() {
        redis.srem(&format!("{NODE_JOBS_PREFIX}{node_id}"), job_id).await;
    }
}

// ── Terminal transition (the single writer of durable history) ─

/// Compact summary pushed to `noo:jobs:history` — must stay field-for-field
/// with Python `_record_history()`, which the dashboard and
/// `GET /api/jobs/history` both parse.
///
/// One field is ADDED to that set: `owner`, copied from the job hash
/// `GET /api/jobs/history` narrows a User-tier caller to
/// their own entries, and it can only do that if the entry says whose it
/// was. Without it the filter would read a missing key as "unowned" and
/// show everyone everything — a scope that passes while it scopes nothing.
/// It is additive: nothing was renamed, so every existing parser is intact.
pub fn history_summary(hash: &HashMap<String, String>, status: &str, error: &str, now: &str) -> String {
    let truncated: String = error.chars().take(200).collect();
    json!({
        "id": hash.get("id").cloned().unwrap_or_default(),
        "owner": hash.get("owner").cloned().unwrap_or_default(),
        "type": hash.get("type").cloned().unwrap_or_default(),
        "status": status,
        "node_id": hash.get("node_id").cloned().unwrap_or_default(),
        "created_at": hash.get("created_at").cloned().unwrap_or_default(),
        "completed_at": now,
        "error": truncated,
        "retries": hash.get("retries").cloned().unwrap_or_else(|| "0".into()),
    })
    .to_string()
}

/// Flip a job terminal and record it — the ONE place that does so.
///
/// Returns true if this call performed the transition. The Lua script
/// makes that a genuine exactly-once signal, which is what lets the
/// `noo_job_runs` insert live here without risking duplicate rows when a
/// late `job.complete` races the reaper.
pub async fn terminalize(state: &AppState, job_id: &str, status: &str, result: &str, error: &str) -> bool {
    let Some(redis) = state.redis.as_ref() else {
        return false;
    };
    let key = format!("{JOB_KEY_PREFIX}{job_id}");
    let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
    if hash.is_empty() {
        return false;
    }
    let now = chrono::Utc::now().to_rfc3339();
    let node_id = hash.get("node_id").cloned().unwrap_or_default();
    let summary = history_summary(&hash, status, error, &now);

    let ok = redis
        .eval_i64(
            TERMINAL_SCRIPT,
            &[
                key.clone(),
                ACTIVE_SET.to_string(),
                format!("{NODE_JOBS_PREFIX}{node_id}"),
                HISTORY_KEY.to_string(),
            ],
            &[
                job_id.to_string(),
                status.to_string(),
                now.clone(),
                result.to_string(),
                error.to_string(),
                summary,
                HISTORY_MAX_LEN.to_string(),
                JOB_TTL_AFTER_TERMINAL.to_string(),
            ],
        )
        .await
        .unwrap_or(0);
    if ok != 1 {
        return false;
    }

    // Durable copy. Redis history is capped at 1000 entries and does not
    // survive a flush; this row is what makes "what ran, when, did it
    // fail" answerable later. Deliberately AFTER the Redis transition and
    // best-effort: a Postgres hiccup must not strand a finished job.
    if let Err(e) = insert_job_run(state, &hash, status, error, &now).await {
        tracing::warn!(job_id, error = %e, "scheduler_engine.job_run_insert_failed");
    }
    true
}

/// Write the durable run record (`noo_job_runs`, migration 035).
///
/// First writer of that table — the durable job history. `error` is stored UNTRUNCATED here; the 200-char cap belongs
/// to the Redis summary, and an uncapped copy is the point of this table.
async fn insert_job_run(
    state: &AppState,
    hash: &HashMap<String, String>,
    status: &str,
    error: &str,
    completed_at: &str,
) -> anyhow::Result<()> {
    let created = parse_ts(hash.get("created_at")).or_else(|| parse_ts(Some(&completed_at.to_string())));
    let Some(created) = created else {
        anyhow::bail!("job has no parseable created_at");
    };
    let started = parse_ts(hash.get("started_at")).or_else(|| parse_ts(hash.get("dispatched_at")));
    let completed = parse_ts(Some(&completed_at.to_string()));
    // NULL rather than 0 when the job never started — "ran for no time" and
    // "never ran" are different facts.
    let duration_ms: Option<i32> = match (started, completed) {
        (Some(s), Some(c)) => Some(((c - s).num_milliseconds()).clamp(0, i32::MAX as i64) as i32),
        _ => None,
    };
    let node_id = hash.get("node_id").filter(|v| !v.is_empty()).cloned();
    let details = json!({
        "priority": hash.get("priority"),
        "backend": hash.get("backend"),
        "force_node": hash.get("force_node"),
        "dispatch_failures": hash.get("dispatch_failures"),
        "engine": "rust",
    });

    sqlx::query(
        "INSERT INTO noo_job_runs \
         (job_id, job_type, node_id, status, created_at, started_at, completed_at, \
          duration_ms, retries, error, details) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(hash.get("id").cloned().unwrap_or_default())
    .bind(hash.get("type").cloned().unwrap_or_default())
    .bind(node_id)
    .bind(status)
    .bind(created)
    .bind(started)
    .bind(completed)
    .bind(duration_ms)
    .bind(num(hash, "retries", 0) as i32)
    .bind(if error.is_empty() { None } else { Some(error.to_string()) })
    .bind(details)
    .execute(&state.db)
    .await?;
    Ok(())
}

fn parse_ts(raw: Option<&String>) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// Every field in the job hash is a string (Python `decode_responses=True`
/// plus `str()` coercion), so numeric reads are parse-with-default.
pub fn num(hash: &HashMap<String, String>, key: &str, default: i64) -> i64 {
    hash.get(key)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

fn is_terminal(status: &str) -> bool {
    TERMINAL_STATES.contains(&status)
}

// ── Reaper ─────────────────────────────────────────────────────

/// Python `_reap_timeouts()` — DISPATCHED/RUNNING past `timeout_sec` are
/// retried, or marked dead once retries are exhausted.
pub async fn reap_timeouts(state: &AppState) -> anyhow::Result<()> {
    let Some(redis) = state.redis.as_ref() else {
        anyhow::bail!("no redis configured");
    };
    let now = chrono::Utc::now();
    for job_id in redis.smembers(ACTIVE_SET).await {
        let key = format!("{JOB_KEY_PREFIX}{job_id}");
        let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
        if hash.is_empty() {
            redis.srem(ACTIVE_SET, &job_id).await;
            continue;
        }
        let status = hash.get("status").cloned().unwrap_or_default();
        if is_terminal(&status) {
            redis.srem(ACTIVE_SET, &job_id).await;
            continue;
        }
        if status != "dispatched" && status != "running" {
            continue;
        }
        // An embed_batch job is not ours to retry: a pull job's redelivery
        // belongs to JetStream (`max_deliver`), and a requeue here would ZADD
        // it onto the node dispatch queue as well. `embed_jobs::sweep`
        // judges them, for both paths.
        if crate::embed_jobs::is_embed_job(&hash) {
            continue;
        }
        let Some(dispatch_time) = parse_ts(hash.get("dispatched_at")) else {
            continue;
        };
        let timeout_sec = num(&hash, "timeout_sec", 300);
        let elapsed = (now - dispatch_time).num_seconds();
        if elapsed <= timeout_sec {
            continue;
        }

        let retries = num(&hash, "retries", 0);
        let max_retries = num(&hash, "max_retries", 2);
        let node_id = hash.get("node_id").cloned().unwrap_or_default();
        if retries < max_retries {
            let msg = format!(
                "Timeout after {timeout_sec}s (retry {}/{max_retries})",
                retries + 1
            );
            requeue_for_retry(state, &job_id, &node_id, retries + 1, &msg).await;
            tracing::warn!(job_id, retry = retries + 1, "scheduler_engine.job_timeout_retry");
        } else {
            let msg =
                format!("Timeout after {timeout_sec}s, max retries ({max_retries}) exhausted");
            terminalize(state, &job_id, "dead", "", &msg).await;
            tracing::error!(job_id, "scheduler_engine.job_dead_timeout");
        }
    }
    Ok(())
}

// ── Janitor ────────────────────────────────────────────────────

#[derive(Default, Debug, PartialEq)]
pub struct JanitorStats {
    pub ttl_set: u32,
    pub active_cleaned: u32,
    pub node_set_cleaned: u32,
    pub dispatch_ack_requeued: u32,
    pub dead_node_requeued: u32,
    pub orphans_removed: u32,
    pub queued_expired: u32,
}

/// Why a QUEUED job should be expired now, or None to leave it queued.
///
/// Three reasons, checked in this order:
///
/// 1. its type has no node executor — retired (e.g. `background_embed`) or
///    never valid. Nothing will ever dispatch it, so it goes on the first
///    janitor pass after an upgrade, whatever its age;
/// 2. it carries its own `expires_at` and that has passed;
/// 3. it has been queued longer than [`QUEUED_MAX_AGE_SECS`].
///
/// The reason always starts with `expired:` so a reader of the history (or
/// `noo jobs list`) can tell a give-up from a failure.
pub fn queued_expiry_reason(hash: &HashMap<String, String>, now: chrono::DateTime<chrono::Utc>) -> Option<String> {
    if hash.get("status").map(String::as_str) != Some("queued") {
        return None;
    }
    let job_type = hash.get("type").map(String::as_str).unwrap_or("");
    if crate::job_types::executor_for(job_type) != Some(crate::job_types::Executor::Node) {
        return Some(format!(
            "expired: {} — nothing will ever dispatch it",
            crate::job_types::unconsumed_reason(job_type)
        ));
    }
    let waiting_on = || {
        let pin = hash.get("force_node").filter(|v| !v.is_empty());
        let backend = hash.get("backend").filter(|v| !v.is_empty());
        match (pin, backend) {
            (Some(n), _) => format!(" (pinned to node '{n}')"),
            (None, Some(b)) => format!(" (needs backend '{b}')"),
            (None, None) => String::new(),
        }
    };
    if let Some(deadline) = parse_ts(hash.get("expires_at")) {
        if now > deadline {
            return Some(format!(
                "expired: not placed before its own deadline {}{}",
                deadline.to_rfc3339(),
                waiting_on()
            ));
        }
    }
    if let Some(created) = parse_ts(hash.get("created_at")) {
        let age = (now - created).num_seconds();
        if age > QUEUED_MAX_AGE_SECS {
            return Some(format!(
                "expired: queued {}h without being placed (bound {}h){}",
                age / 3600,
                QUEUED_MAX_AGE_SECS / 3600,
                waiting_on()
            ));
        }
    }
    None
}

/// Python `_janitor()` — TTLs, orphan cleanup, hung dispatches, jobs
/// stranded on unhealthy nodes.
pub async fn janitor(state: &AppState) -> anyhow::Result<()> {
    let Some(redis) = state.redis.as_ref() else {
        anyhow::bail!("no redis configured");
    };
    let now = chrono::Utc::now();
    let mut stats = JanitorStats::default();
    let nodes = load_nodes(state).await;

    for job_id in redis.smembers(ACTIVE_SET).await {
        let key = format!("{JOB_KEY_PREFIX}{job_id}");
        let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
        if hash.is_empty() {
            redis.srem(ACTIVE_SET, &job_id).await;
            stats.active_cleaned += 1;
            continue;
        }
        let status = hash.get("status").cloned().unwrap_or_default();

        if is_terminal(&status) {
            // Terminalised somewhere that did not clean up (e.g. the admin
            // cancel route). History was already written by whoever set the
            // status, so this path only sweeps — it must NOT push history
            // again or the same job appears twice.
            redis.srem(ACTIVE_SET, &job_id).await;
            stats.active_cleaned += 1;
            if redis.ttl(&key).await == -1 {
                redis.expire(&key, JOB_TTL_AFTER_TERMINAL).await;
                stats.ttl_set += 1;
            }
            if let Some(node_id) = hash.get("node_id").filter(|v| !v.is_empty()) {
                if redis.srem(&format!("{NODE_JOBS_PREFIX}{node_id}"), &job_id).await {
                    stats.node_set_cleaned += 1;
                }
            }
            continue;
        }

        // The dispatch-ack and dead-node rules below requeue onto the node
        // dispatch queue. A pulled embed job was never dispatched and its
        // acking node is only a record, so neither rule applies to it.
        if crate::embed_jobs::is_embed_job(&hash) {
            continue;
        }

        if status == "dispatched" {
            if let Some(t) = parse_ts(hash.get("dispatched_at")) {
                let elapsed = (now - t).num_seconds() as f64;
                if elapsed > DISPATCH_ACK_GRACE_SEC {
                    let node_id = hash.get("node_id").cloned().unwrap_or_default();
                    requeue_job(state, &job_id, &node_id).await;
                    stats.dispatch_ack_requeued += 1;
                    tracing::warn!(
                        job_id,
                        elapsed = elapsed.round(),
                        node_id = %node_id,
                        "scheduler_engine.janitor_dispatch_ack_timeout"
                    );
                }
            }
        }

        if status == "running" {
            if let Some(node_id) = hash.get("node_id").filter(|v| !v.is_empty()) {
                let healthy = nodes
                    .iter()
                    .find(|n| &n.id == node_id)
                    .map(|n| n.is_healthy());
                // Only requeue a node we can SEE and that reports unhealthy.
                // An unknown node id is left alone, exactly as Python does
                // (`if node and not node.is_healthy()`).
                if healthy == Some(false) {
                    requeue_job(state, &job_id, node_id).await;
                    stats.dead_node_requeued += 1;
                    tracing::warn!(job_id, node_id = %node_id, "scheduler_engine.janitor_dead_node_requeue");
                }
            }
        }
    }

    // Terminal / vanished / expired entries still sitting in the queue.
    for job_id in redis.zrange(QUEUE_KEY, 0, -1).await {
        let key = format!("{JOB_KEY_PREFIX}{job_id}");
        let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
        if hash.is_empty() {
            redis.zrem(QUEUE_KEY, &job_id).await;
            stats.orphans_removed += 1;
            continue;
        }
        if is_terminal(hash.get("status").map(|s| s.as_str()).unwrap_or("")) {
            redis.zrem(QUEUE_KEY, &job_id).await;
            stats.active_cleaned += 1;
            continue;
        }
        if let Some(reason) = queued_expiry_reason(&hash, now) {
            // ZREM is the claim, exactly as in CLAIM_SCRIPT: if the
            // dispatcher took the job between our read and now, it is no
            // longer ours to expire.
            if redis.zrem(QUEUE_KEY, &job_id).await {
                redis.hset(&key, &[("status_detail", reason.as_str())]).await;
                terminalize(state, &job_id, "dead", "", &reason).await;
                stats.queued_expired += 1;
                tracing::warn!(
                    job_id,
                    job_type = hash.get("type").map(String::as_str).unwrap_or(""),
                    reason = %reason,
                    "scheduler_engine.janitor_queued_expired"
                );
            }
        }
    }

    // Orphaned entries in per-node sets.
    for node in &nodes {
        for job_id in redis.smembers(&format!("{NODE_JOBS_PREFIX}{}", node.id)).await {
            let hash: HashMap<String, String> = redis
                .hgetall(&format!("{JOB_KEY_PREFIX}{job_id}"))
                .await
                .unwrap_or_default();
            let set_key = format!("{NODE_JOBS_PREFIX}{}", node.id);
            if hash.is_empty() {
                redis.srem(&set_key, &job_id).await;
                stats.orphans_removed += 1;
            } else if is_terminal(hash.get("status").map(|s| s.as_str()).unwrap_or("")) {
                redis.srem(&set_key, &job_id).await;
                stats.node_set_cleaned += 1;
            }
        }
    }

    if stats != JanitorStats::default() {
        tracing::info!(?stats, "scheduler_engine.janitor_run");
    }
    Ok(())
}

// ── Restart recovery ───────────────────────────────────────────

/// Python `recover_from_restart()` — requeue in-flight jobs whose node is
/// gone, so a gateway restart does not strand them.
pub async fn recover_from_restart(state: &AppState) -> anyhow::Result<()> {
    let Some(redis) = state.redis.as_ref() else {
        anyhow::bail!("no redis configured");
    };
    let nodes = load_nodes(state).await;
    let mut recovered = 0u32;
    for job_id in redis.smembers(ACTIVE_SET).await {
        let key = format!("{JOB_KEY_PREFIX}{job_id}");
        let hash: HashMap<String, String> = redis.hgetall(&key).await.unwrap_or_default();
        if hash.is_empty() {
            redis.srem(ACTIVE_SET, &job_id).await;
            continue;
        }
        let status = hash.get("status").cloned().unwrap_or_default();
        if is_terminal(&status) {
            redis.srem(ACTIVE_SET, &job_id).await;
            continue;
        }
        // A pulled embed job survives a gateway restart in JetStream, and a
        // gateway-run one is judged by `embed_jobs::sweep`. Requeueing either
        // would put it on the node dispatch queue.
        if crate::embed_jobs::is_embed_job(&hash) {
            continue;
        }
        let node_id = hash.get("node_id").cloned().unwrap_or_default();
        if !node_id.is_empty() {
            let alive = nodes.iter().find(|n| n.id == node_id).map(|n| n.is_healthy());
            if alive == Some(true) {
                continue;
            }
        }
        if status == "dispatched" || status == "running" {
            let retries = num(&hash, "retries", 0);
            let msg = format!("Recovered after gateway restart (node {node_id} unavailable)");
            requeue_for_retry(state, &job_id, &node_id, retries + 1, &msg).await;
            recovered += 1;
        }
    }
    if recovered > 0 {
        tracing::info!(count = recovered, "scheduler_engine.jobs_recovered");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_keeps_capability_and_running_backends_apart() {
        let s = snapshot_from_kv(
            "host2",
            &json!({"capabilities": {"backends": ["ollama", "vllm"]},
                    "running_backends": {"ollama": "qwen"}, "last_heartbeat": 100.0}),
            101.0,
        );
        assert!(s.can_run_backend("ollama"));
        assert!(!s.can_run_backend("vllm"), "declared but not serving");
        assert!(s.declares_backend("vllm"));
    }

    // ── Redis contract shape ───────────────────────────────────

    fn hash() -> HashMap<String, String> {
        [
            ("id", "j-1"),
            ("type", "inference"),
            ("status", "running"),
            ("node_id", "worker-1"),
            ("created_at", "2026-08-01T00:00:00+00:00"),
            ("completed_at", ""),
            ("error", ""),
            ("retries", "1"),
            ("priority", "5"),
            ("owner", "ada"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    /// Field-for-field parity with Python `_record_history()`. The
    /// dashboard and `GET /api/jobs/history` parse this, so a renamed key
    /// silently empties the history view (`"id"` → `"job_id"` already did
    /// exactly that once — see admin.rs JobHashSpec).
    #[test]
    fn history_summary_matches_python_record_history() {
        let out = history_summary(&hash(), "completed", "", "2026-08-01T00:01:00+00:00");
        let v: Value = serde_json::from_str(&out).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "completed_at", "created_at", "error", "id", "node_id", "owner",
                "retries", "status", "type",
            ]
        );
        assert_eq!(v["id"], "j-1");
        // The scoping field carries through from the hash, not a default.
        assert_eq!(v["owner"], "ada");
        assert_eq!(v["status"], "completed");
        assert_eq!(v["retries"], "1");
    }

    #[test]
    fn history_error_is_truncated_at_200_like_python() {
        let long = "x".repeat(500);
        let out = history_summary(&hash(), "dead", &long, "2026-08-01T00:01:00+00:00");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["error"].as_str().unwrap().len(), 200);
    }

    // ── Queued-job expiry ──────────────────────────────────────

    fn queued(job_type: &str, created: &str) -> HashMap<String, String> {
        [
            ("id", "q-1"),
            ("type", job_type),
            ("status", "queued"),
            ("created_at", created),
            ("force_node", ""),
            ("backend", ""),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        parse_ts(Some(&s.to_string())).unwrap()
    }

    #[test]
    fn a_retired_type_expires_at_once_with_the_retirement_reason() {
        // The live leftovers: background_embed jobs from the heartbeat.
        let h = queued("background_embed", "2026-10-10T20:00:00+00:00");
        let r = queued_expiry_reason(&h, at("2026-10-10T20:00:01+00:00")).expect("must expire");
        assert!(r.starts_with("expired: job type 'background_embed' retired"), "{r}");
        assert!(r.contains("nothing will ever dispatch it"));
    }

    #[test]
    fn an_unknown_or_gateway_local_type_in_the_queue_expires() {
        let now = at("2026-10-10T00:00:01+00:00");
        let r = queued_expiry_reason(&queued("smoke", "2026-10-10T00:00:00+00:00"), now).unwrap();
        assert!(r.contains("has no executor"), "{r}");
        assert!(queued_expiry_reason(&queued("test_run", "2026-10-10T00:00:00+00:00"), now).is_some());
    }

    #[test]
    fn a_live_type_expires_only_past_the_age_bound() {
        let h = queued("fetch_bundle", "2026-10-09T00:00:00+00:00");
        assert_eq!(queued_expiry_reason(&h, at("2026-10-09T23:59:59+00:00")), None);
        let mut pinned = h.clone();
        pinned.insert("force_node".into(), "host2".into());
        let r = queued_expiry_reason(&pinned, at("2026-10-10T00:00:01+00:00")).expect("past 24h");
        assert!(r.starts_with("expired: queued 24h"), "{r}");
        assert!(r.contains("pinned to node 'host2'"), "{r}");
    }

    #[test]
    fn a_per_job_deadline_expires_before_the_age_bound() {
        let mut h = queued("fetch_bundle", "2026-10-10T00:00:00+00:00");
        h.insert("expires_at".into(), "2026-10-10T00:10:00+00:00".into());
        assert_eq!(queued_expiry_reason(&h, at("2026-10-10T00:09:59+00:00")), None);
        let r = queued_expiry_reason(&h, at("2026-10-10T00:10:01+00:00")).unwrap();
        assert!(r.starts_with("expired: not placed before its own deadline"), "{r}");
        // Empty = no per-job deadline (the hash field is absent on older jobs).
        h.insert("expires_at".into(), "".into());
        assert_eq!(queued_expiry_reason(&h, at("2026-10-10T00:10:01+00:00")), None);
    }

    #[test]
    fn only_queued_jobs_are_expired() {
        for status in ["dispatched", "running", "completed", "dead", "cancelled"] {
            let mut h = queued("background_embed", "2026-01-01T00:00:00+00:00");
            h.insert("status".into(), status.into());
            assert_eq!(queued_expiry_reason(&h, at("2026-10-10T00:00:00+00:00")), None, "{status}");
        }
    }

    #[test]
    fn only_a_pin_to_an_unavailable_node_stops_blocking_the_lane() {
        // The 2026-10-10 head-of-line block: pinned, no candidate → skip.
        assert!(!unplaceable_blocks_lane(Some("host2"), true));
        // Pinned but the node is healthy (busy/drained): keep its place.
        assert!(unplaceable_blocks_lane(Some("host3"), false));
        // Unpinned and unplaceable: blocks, as Python did.
        assert!(unplaceable_blocks_lane(None, true));
        assert!(unplaceable_blocks_lane(Some(""), true), "empty pin means no pin");
    }

    #[test]
    fn constants_match_python_scheduler() {
        assert_eq!(HISTORY_MAX_LEN, 1000);
        assert_eq!(JOB_TTL_AFTER_TERMINAL, 86400);
        assert_eq!(DISPATCH_ACK_GRACE_SEC, 90.0);
        assert_eq!(MAX_DISPATCH_PER_TICK, 20);
        assert_eq!(TERMINAL_STATES, &["completed", "cancelled", "dead"]);
    }

    // ── Atomicity choice, pinned as text ───────────────────────

    #[test]
    fn claim_script_only_writes_when_zrem_won() {
        // The ZREM result IS the claim; every write is downstream of it.
        assert!(CLAIM_SCRIPT.contains("if redis.call('ZREM', KEYS[1], ARGV[1]) == 0 then return 0 end"));
        let after = CLAIM_SCRIPT.split("return 0 end").nth(1).unwrap();
        assert!(after.contains("HSET"));
        assert!(after.contains("SADD"));
        // Nothing writes before the claim.
        let before = CLAIM_SCRIPT.split("if redis.call('ZREM'").next().unwrap();
        assert!(!before.contains("HSET") && !before.contains("SADD"));
    }

    #[test]
    fn terminal_script_refuses_to_re_terminalise() {
        // Exactly-once: this is what makes the noo_job_runs insert safe to
        // sit behind `terminalize()` returning true.
        for s in TERMINAL_STATES {
            assert!(
                TERMINAL_SCRIPT.contains(&format!("cur == '{s}'")),
                "terminal script must short-circuit on {s}"
            );
        }
        assert!(TERMINAL_SCRIPT.contains("LTRIM"));
        assert!(TERMINAL_SCRIPT.contains("EXPIRE"));
        assert!(TERMINAL_SCRIPT.contains("SREM"));
    }

    #[test]
    fn num_parses_python_string_fields() {
        let h = hash();
        assert_eq!(num(&h, "retries", 0), 1);
        assert_eq!(num(&h, "missing", 7), 7);
        // Empty string is Python's "unset" and must fall back, not become 0.
        let mut h2 = h.clone();
        h2.insert("max_retries".into(), "".into());
        assert_eq!(num(&h2, "max_retries", 2), 2);
    }

    #[test]
    fn parse_ts_treats_empty_as_absent() {
        assert!(parse_ts(Some(&String::new())).is_none());
        assert!(parse_ts(Some(&"   ".to_string())).is_none());
        assert!(parse_ts(Some(&"2026-08-01T00:00:00+00:00".to_string())).is_some());
        assert!(parse_ts(None).is_none());
    }
}

// ── The streams the job plane rides on ─────────────────────────────────────
//
// `TASKS` (tasks.>) carries every dispatch and `EVENTS` (events.>) every
// ack/complete/failed. They used to be declared by the Python worker at
// connect time (src/noomesh/cluster/messaging.py). Under per-principal bus
// credentials the worker's grant DENIES `$JS.API.STREAM.CREATE.>`, so on a
// fresh install that declaration fails ("permissions violation") and nothing
// else declares them: the completions consumer logged "stream not found"
// every 30s, a job dispatched to the first worker died with "no stream found
// for given subject", and the node's dispatch subscription stayed unbound
// forever (2026-09-28 newcomer rehearsal, fresh standalone controller + one
// LAN worker). Long-lived fleets never saw it because their streams predate
// the grants. The gateway is the only principal allowed to create streams
// and the only publisher of tasks.dispatch.*, so it declares them at boot,
// the way it already declares AGENT_MESSAGES.

/// The job-plane streams: `EVENTS` and `TASKS` as the Python declaration
/// defined them, plus `WORK_EMBED` (i179), the work queue nodes PULL bulk
/// embedding batches from. Nothing publishes to it yet.
pub fn job_plane_stream_configs() -> Vec<async_nats::jetstream::stream::Config> {
    use async_nats::jetstream::stream::{Config, DiscardPolicy, RetentionPolicy, StorageType};
    vec![
        Config {
            name: "EVENTS".to_string(),
            subjects: vec!["events.>".to_string()],
            description: Some("Cluster-wide events".to_string()),
            max_age: std::time::Duration::from_secs(24 * 60 * 60),
            storage: StorageType::File,
            ..Default::default()
        },
        Config {
            name: "TASKS".to_string(),
            subjects: vec!["tasks.>".to_string()],
            description: Some("Distributed task queue".to_string()),
            max_age: std::time::Duration::from_secs(7 * 24 * 60 * 60),
            storage: StorageType::File,
            ..Default::default()
        },
        // `work.` not `tasks.`: TASKS owns `tasks.>` and JetStream rejects
        // overlapping stream subjects. Not `worker.` either (denied to nodes).
        // WorkQueue + DiscardPolicy::New: a full queue refuses the publish, so
        // the submitter sees back-pressure instead of losing the oldest batch.
        Config {
            name: "WORK_EMBED".to_string(),
            subjects: vec!["work.embed.>".to_string()],
            description: Some("Bulk embedding batches pulled by nodes".to_string()),
            retention: RetentionPolicy::WorkQueue,
            max_age: std::time::Duration::from_secs(6 * 60 * 60),
            max_messages: 100_000,
            discard: DiscardPolicy::New,
            storage: StorageType::File,
            ..Default::default()
        },
    ]
}

/// Create `EVENTS`, `TASKS` and `WORK_EMBED` if they do not exist. Create-only, never
/// update: a fleet that has carried these streams for months keeps whatever
/// limits it has; this exists for the install that has none.
pub async fn ensure_job_plane_streams(js: &async_nats::jetstream::Context) {
    for cfg in job_plane_stream_configs() {
        let name = cfg.name.clone();
        if js.get_stream(&name).await.is_ok() {
            continue;
        }
        match js.create_stream(cfg).await {
            Ok(_) => tracing::info!(stream = %name, "job plane: stream created"),
            Err(e) => tracing::warn!(stream = %name, error = %e,
                "job plane: could not create stream — dispatch and completions will fail until it exists"),
        }
    }
}

#[cfg(test)]
mod job_plane_stream_tests {
    use super::job_plane_stream_configs;

    #[test]
    fn the_job_plane_streams_match_their_declaration() {
        let cfgs = job_plane_stream_configs();
        let names: Vec<&str> = cfgs.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["EVENTS", "TASKS", "WORK_EMBED"]);
        let tasks = &cfgs[1];
        assert_eq!(tasks.subjects, vec!["tasks.>".to_string()]);
        assert_eq!(tasks.max_age.as_secs(), 7 * 24 * 60 * 60);
        let events = &cfgs[0];
        assert_eq!(events.subjects, vec!["events.>".to_string()]);
        assert_eq!(events.max_age.as_secs(), 24 * 60 * 60);
        // tasks.dispatch.<node> — the scheduler's subject — must be covered
        assert!(tasks.subjects.iter().any(|s| s == "tasks.>"));
        // i179: the pulled-work stream. Its subject must overlap neither
        // `tasks.>` nor `events.>` (JetStream rejects overlap at create).
        let embed = &cfgs[2];
        assert_eq!(embed.subjects, vec!["work.embed.>".to_string()]);
        assert!(matches!(embed.retention, async_nats::jetstream::stream::RetentionPolicy::WorkQueue));
        assert!(matches!(embed.discard, async_nats::jetstream::stream::DiscardPolicy::New));
        assert_eq!(embed.max_age.as_secs(), 6 * 60 * 60);
        assert!(embed.max_messages > 0, "an unbounded work queue has no back-pressure");
        for other in [&cfgs[0], &cfgs[1]] {
            assert!(other.subjects.iter().all(|s| !s.starts_with("work.")));
        }
    }
}
