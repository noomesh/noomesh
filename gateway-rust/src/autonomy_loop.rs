// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Autonomy engine — periodic location evaluation loop.
//!
//! The retired Python `AutonomyEngine` (no longer in the tree) defined 15 default
//! "monitor locations" — condition+action pairs that fire periodically.
//! That Python loop doesn't run in production (Rust gateway owns the port).
//! This module restores the behavior for MESH-side locations.
//!
//! Design (keep harness boundary in mind):
//! - **MESH-native locations** (cluster state, backends, certs, audit,
//!   job queue) — evaluated inline in Rust SQL/Redis.
//! - **unembedded_documents / missing_graph_entities** — evaluated natively
//!   in SQL here (`autonomy_evaluators`). `unembedded_documents` is a
//!   backlog-stall alert; it submits no job (trellion embeds on its own). They were once dispatched over NATS
//!   to a Trellion worker; those Python handlers were deleted once the Rust
//!   evaluators took over.
//! - **HARNESS-native locations** (none today, but `custom_prompt`-style
//!   conditions could be added) — dispatched via NATS to harness worker.
//! - **Already-handled locations** (`watched_folders` is replaced by
//!   `ingest_loop.rs`) — explicitly skipped here.
//!
//! Locations + intervals are loaded from the `autonomy.locations` section
//! of `noomesh.yaml` (matches Python AutonomyEngine config).
//!
//! Status: all default locations have Rust evaluators (see
//! `autonomy_evaluators.rs`). Alert-action locations dispatch operator
//! notifications through `operator_alert` (cooldown-deduplicated);
//! `watched_folders` is handled by `ingest_loop.rs` and skipped here.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use tokio::sync::Mutex;

use crate::autonomy_evaluators;
use crate::state::AppState;

/// Master tick — evaluates whether any location is due. 30s is fine
/// because per-location intervals are typically minutes/hours; we just
/// don't want to oversleep past a due time.
const MASTER_TICK_SECS: u64 = 30;

/// Tracks last-eval time per location so we honor the configured interval.
type LastEvalMap = Arc<Mutex<HashMap<String, DateTime<Utc>>>>;

/// The live map, shared with `/api/autonomy/status` so it can report a real
/// `last_check` per location.
///
/// It is deliberately in-memory and lost on restart: "when did this location
/// last evaluate" is a liveness fact about THIS process, not history. The
/// durable half is `last_fired`, which comes from the audit table. Reporting
/// a stale pre-restart check time would be worse than reporting none.
static LAST_EVAL: std::sync::OnceLock<LastEvalMap> = std::sync::OnceLock::new();

/// Last-evaluation time per location, for the status route. Empty before the
/// engine's first tick — the caller renders absence as unknown, never as
/// "never ran".
pub(crate) async fn last_checks() -> HashMap<String, DateTime<Utc>> {
    match LAST_EVAL.get() {
        Some(m) => m.lock().await.clone(),
        None => HashMap::new(),
    }
}

pub fn spawn(state: Arc<AppState>) {
    let last_eval: LastEvalMap = LAST_EVAL
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone();
    crate::managed_loop::spawn_managed_loop(
        "autonomy_engine",
        MASTER_TICK_SECS,
        state.clone(),
        move |state| {
            let last_eval = last_eval.clone();
            async move {
                // Global kill switch checked AFTER record_tick (inside the
                // managed loop) so a disabled engine still reads as alive.
                if !is_enabled(&state).await {
                    return Ok(());
                }
                poll_locations(state, last_eval)
                    .await
                    .map_err(anyhow::Error::msg)
            }
        },
    );
    spawn_issue_subscriber(state);
}

/// Spawn a NATS subscriber for external issue reports from peer agents.
///
/// When a peer agent (hermes, claude-code, openclaw) detects a problem with
/// MESH it sends an `issue_report` WebSocket message. `ws_agent.rs` publishes
/// that to `agent.issue.report.{agent_id}`. This subscriber:
///   1. Parses the category (inference / cluster / nats / rag / memory / generic)
///   2. Runs the appropriate autonomy healing action immediately (push-not-poll)
///   3. Pushes a `heal_result` back to the peer via `state.peer_connections`
fn spawn_issue_subscriber(state: Arc<AppState>) {
    tokio::spawn(issue_subscriber_loop(state));
}

async fn issue_subscriber_loop(state: Arc<AppState>) {
    use tokio_stream::StreamExt;

    let sub = match state.nats.subscribe("agent.issue.report.>").await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "issue_subscriber_failed_to_subscribe");
            return;
        }
    };

    let mut sub = sub;
    while let Some(msg) = sub.next().await {
        if let Ok(report) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
            let agent_id = msg
                .subject
                .strip_prefix("agent.issue.report.")
                .unwrap_or("unknown")
                .to_string();
            tokio::spawn(handle_issue_report(state.clone(), agent_id, report));
        }
    }
}

/// Handle one external issue report: diagnose → heal → respond to peer.
async fn handle_issue_report(state: Arc<AppState>, agent_id: String, report: serde_json::Value) {
    let category = report.get("category").and_then(|v| v.as_str()).unwrap_or("generic");
    let severity  = report.get("severity").and_then(|v| v.as_str()).unwrap_or("error");
    let error_msg = report.get("error").and_then(|v| v.as_str()).unwrap_or("no details");
    let issue_id  = report
        .get("issue_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    tracing::info!(
        agent_id = %agent_id,
        category,
        severity,
        error = %error_msg,
        issue_id = %issue_id,
        "autonomy.external_issue_report"
    );

    let (action_taken, heal_status): (&str, &str) = match category {
        "inference" => {
            // Check if backends are available; auto-start Ollama if not.
            // Detection only: an external peer's issue report must not arm an
            // action the operator has not opted into, so this passes an empty
            // config (i.e. `enabled_action` false).
            match autonomy_evaluators::eval_backend_availability(&state, &serde_json::json!({})).await {
                Ok(true)  => ("no backends running — reported, not started", "escalated"),
                Ok(false) => ("inference backends healthy", "no_action_needed"),
                Err(e)    => {
                    tracing::warn!(error = %e, "heal.inference.eval_failed");
                    ("eval_failed", "failed")
                }
            }
        }
        "cluster" | "node" => {
            match autonomy_evaluators::eval_node_health(&state).await {
                Ok(true)  => ("node health alerts dispatched", "healing"),
                Ok(false) => ("cluster nodes healthy", "no_action_needed"),
                Err(e)    => {
                    tracing::warn!(error = %e, "heal.cluster.eval_failed");
                    ("eval_failed", "failed")
                }
            }
        }
        "nats" => {
            // Publish a probe message — if NATS is responsive the publish succeeds.
            match state.nats.publish(
                "agent.heal.nats_probe",
                b"ping".to_vec().into(),
            ).await {
                Ok(_)  => ("nats probe ok", "resolved"),
                Err(e) => {
                    tracing::warn!(error = %e, "heal.nats.probe_failed");
                    ("nats unreachable", "escalated")
                }
            }
        }
        "rag" | "memory" | "knowledge" => {
            // Dispatch to the Python worker pool (Trellion side).
            match crate::bus_principal::with_internal(
                "autonomy",
                &["read", "write"],
                crate::worker_client::request(
                    &state.nats,
                    "worker.autonomy.check_rag",
                    &serde_json::json!({"trigger": "external_report", "agent_id": &agent_id}),
                ),
            )
            .await
            {
                Ok(_)  => ("rag health check dispatched to worker", "healing"),
                // The check itself now fails loudly when the KB database is
                // unreachable (it used to answer "0 unembedded pages", so this
                // arm was only ever reached for a genuinely dead worker pool).
                // "worker pool unreachable" is therefore no longer the only
                // cause, and naming the wrong component sends the operator to
                // the wrong container.
                Err(_) => ("rag health check failed (worker pool or KB database unreachable)", "escalated"),
            }
        }
        _ => ("issue logged, no automated action", "acknowledged"),
    };

    // Operator alert (cooldown 5 min per reporting agent to avoid spam).
    // The peer's own error text is a stranger's string: it goes to the log
    // as the alert's detail, never verbatim to a channel.
    crate::operator_alert::send_operator_alert_with(
        &state,
        crate::operator_alert::OperatorAlert::new(
            "a2a.external_issue_report",
            &agent_id,
            format!("Peer agent [{agent_id}] reported {severity} in {category} → {action_taken}"),
        )
        .detail(error_msg.to_string())
        .investigate("noo agents peer list"),
        300,
    )
    .await;

    // Push heal_result back to the peer if it still has an active WS connection.
    let peer_tx = {
        let conns = state.peer_connections.read().await;
        conns.get(&agent_id).cloned()
    };

    if let Some(tx) = peer_tx {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = tx
            .send(serde_json::json!({
                "type": "heal_result",
                "issue_id": issue_id,
                "category": category,
                "severity": severity,
                "status": heal_status,
                "action_taken": action_taken,
                "ts": now,
            }))
            .await;
    }
}

/// Read the global enabled flag. Mirrors Python's Redis key
/// `noo:autonomy:enabled` (toggled via `/api/autonomy/{enable,disable}`).
pub async fn is_enabled(state: &AppState) -> bool {
    let Some(r) = state.redis.as_ref() else { return true; };
    match r.get_string("noo:autonomy:enabled").await {
        Some(s) => s == "1" || s.eq_ignore_ascii_case("true"),
        None => true, // default enabled (matches Python)
    }
}

async fn poll_locations(state: Arc<AppState>, last_eval: LastEvalMap) -> Result<(), String> {
    // Load location definitions from config. The Python AutonomyEngine
    // reads from a YAML/Postgres pair; the Rust gateway reads only the
    // YAML at startup (Python-stored runtime locations are ignored —
    // edits to runtime locations need a config-reload roundtrip).
    let locations = load_locations(&state).await;
    if locations.is_empty() {
        return Ok(());
    }

    let now = Utc::now();
    let mut last = last_eval.lock().await;

    for loc in locations {
        if !loc.enabled {
            continue;
        }
        let due = match last.get(&loc.name) {
            Some(prev) => *prev + ChronoDuration::seconds(loc.interval_seconds as i64) <= now,
            None => true, // never evaluated — fire immediately
        };
        if !due {
            continue;
        }
        last.insert(loc.name.clone(), now);
        // Drop the lock before evaluation — evaluations may be slow and
        // we don't want to block other location dues behind one slow eval.
        drop(last);
        evaluate_location(state.clone(), loc).await;
        last = last_eval.lock().await;
    }

    // Custom locations: same due-timing, evaluated by the native generic
    // rules engine (`autonomy_evaluators::eval_custom_location`). This was
    // a NATS dispatch to `worker.autonomy.evaluate_custom` until 2026-08-08
    // — the design's sharpest anti-pattern: Rust loop → NATS → Python →
    // HTTP GET back out, for a body that is a threshold comparison.
    for (name, definition, interval) in load_custom_locations(&state).await {
        let due = match last.get(&name) {
            Some(prev) => *prev + ChronoDuration::seconds(interval as i64) <= now,
            None => true,
        };
        if !due {
            continue;
        }
        last.insert(name.clone(), now);
        drop(last);
        let result = autonomy_evaluators::eval_custom_location(&state, &definition).await;
        let fired = result
            .get("fired")
            .and_then(|f| f.as_bool())
            .unwrap_or(false);
        if let Some(err) = result.get("error").and_then(|e| e.as_str()) {
            // An unevaluable location (endpoint down, bad definition) is
            // not "no alert" — surface it at warn.
            tracing::warn!(location = %name, error = %err, "autonomy.custom_eval_error");
        } else if fired {
            tracing::warn!(location = %name, ?result, "autonomy.custom_fired");
        } else {
            tracing::debug!(location = %name, "autonomy.custom_ok");
        }
        last = last_eval.lock().await;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct LocationDef {
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) interval_seconds: u64,
    /// Action keyword (e.g., "alert", "auto_start_ollama", "scale_backend").
    /// Reserved for follow-up ports — not all evaluators use it yet.
    #[allow(dead_code)]
    pub(crate) action: String,
    /// Free-form per-location config (thresholds, channels, etc.).
    /// Consumed today by `disk_watermark` (`enabled_action` / `dry_run`
    /// reclaim opt-ins); populated from the YAML overlay and DB overrides.
    pub(crate) config: serde_json::Value,
}

/// Locations whose evaluator takes `&loc.config` and can therefore be ARMED.
///
/// This is the list `evaluate_location` dispatches with a config argument —
/// keep the two together. Every other location alerts only and has no gate,
/// which is why `/api/autonomy/status` reports `armed` as absent for them
/// rather than false: "this location has no gate" and "this location's gate
/// is off" are different facts, and an operator deciding what to arm needs
/// to tell them apart.
pub(crate) const GATE_CAPABLE: &[&str] = &[
    "backend_availability",
    // Re-tiering moves scheduler slots under a running fleet, so it is
    // observe-only until explicitly armed.
    "node_tier_drift",
    "backend_idle_scaledown",
    "backend_scaling",
    "disk_watermark",
    // Gated as of this change: the dispatch now passes it `&loc.config` and
    // the evaluator requires `enabled_action` + `dry_run: false`. It was the
    // weakest gate on the highest-consequence action in the engine — enabling
    // the LOCATION queued a fleet-wide rotate/reload/revert.
    "cert_auto_rotate",
];

/// Locations whose gate is a DOUBLE opt-in: arming alone still previews,
/// because the action is expensive or hard to walk back. The others arm on
/// `enabled_action` alone.
/// `cert_auto_rotate` is listed ahead of its gate landing so the default is
/// already right when it does: arming it must still preview.
const DOUBLE_OPT_IN: &[&str] = &["disk_watermark", "cert_auto_rotate"];

/// The resolved gate for a location: `Some((armed, dry_run))` when the
/// location can be armed at all, `None` when it has no gate. `dry_run`
/// defaults true for `disk_watermark` (its reclaim is a double opt-in) and
/// false for the backend actions, matching each evaluator.
pub(crate) fn gate_of(name: &str, config: &serde_json::Value) -> Option<(bool, bool)> {
    if !GATE_CAPABLE.contains(&name) {
        return None;
    }
    let armed = config.get("enabled_action").and_then(|v| v.as_bool()).unwrap_or(false);
    let dry_run = config
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(DOUBLE_OPT_IN.contains(&name));
    Some((armed, dry_run))
}

/// Effective location defs, three layers (later wins):
///   1. builtin defaults (this file)
///   2. `autonomy.locations` YAML entries matching a builtin name
///      (seed/GitOps tier)
///   3. `noo_autonomy_overrides` DB rows (runtime-editable tier — this
///      is what the toggle API writes, so a dashboard toggle persists
///      without touching config files)
/// Config entries with non-builtin names are custom locations owned by
/// other machinery and are not returned here.
pub(crate) async fn load_locations(state: &AppState) -> Vec<LocationDef> {
    let mut locs = default_locations();

    // Layer 2: YAML overlay
    {
        let config = state.config_yaml.read().await;
        if let Some(entries) = config
            .get("autonomy")
            .and_then(|a| a.get("locations"))
            .and_then(|l| l.as_array())
        {
            for entry in entries {
                let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
                    continue;
                };
                if let Some(builtin) = locs.iter_mut().find(|l| l.name == name) {
                    if let Some(enabled) = entry.get("enabled").and_then(|v| v.as_bool()) {
                        builtin.enabled = enabled;
                    }
                    if let Some(interval) = entry
                        .get("check_interval_seconds")
                        .and_then(|v| v.as_u64())
                    {
                        builtin.interval_seconds = interval.max(10);
                    }
                    builtin.config = entry.clone();
                }
            }
        }
    }

    // Layer 3: DB overrides. Tolerate a missing table (pre-migration
    // startup ordering) — the loop must never die on this query.
    let rows: Vec<(String, Option<bool>, Option<i32>, Option<serde_json::Value>)> =
        sqlx::query_as(
            "SELECT name, enabled, check_interval_seconds, config \
             FROM noo_autonomy_overrides",
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    for (name, enabled, interval, config) in rows {
        if let Some(builtin) = locs.iter_mut().find(|l| l.name == name) {
            if let Some(e) = enabled {
                builtin.enabled = e;
            }
            if let Some(i) = interval {
                builtin.interval_seconds = (i.max(10)) as u64;
            }
            if let Some(c) = config {
                builtin.config = c;
            }
        }
    }
    locs
}


/// Custom location definitions: DB rows (noo_autonomy_locations) plus
/// YAML-seed entries whose names aren't in the DB yet. Only enabled ones
/// are returned. Evaluated by the native generic rules engine
/// (`autonomy_evaluators::eval_custom_location`) — the loop here is just
/// the scheduler for these.
pub(crate) async fn load_custom_locations(
    state: &AppState,
) -> Vec<(String, serde_json::Value, u64)> {
    let mut out: Vec<(String, serde_json::Value, u64)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let builtin_names: std::collections::HashSet<String> =
        default_locations().into_iter().map(|l| l.name).collect();

    let rows: Vec<(String, serde_json::Value, bool)> = sqlx::query_as(
        "SELECT name, definition, enabled FROM noo_autonomy_locations",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (name, definition, enabled) in rows {
        seen.insert(name.clone());
        if !enabled || builtin_names.contains(&name) {
            continue;
        }
        let interval = definition
            .get("check_interval_seconds")
            .and_then(|i| i.as_u64())
            .unwrap_or(60)
            .max(10);
        out.push((name, definition, interval));
    }

    let config = state.config_yaml.read().await;
    if let Some(entries) = config
        .get("autonomy")
        .and_then(|a| a.get("locations"))
        .and_then(|l| l.as_array())
    {
        for entry in entries {
            let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            if seen.contains(name) || builtin_names.contains(name) {
                continue; // DB wins; builtins have native evaluators
            }
            if !entry.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true) {
                continue;
            }
            let interval = entry
                .get("check_interval_seconds")
                .and_then(|i| i.as_u64())
                .unwrap_or(60)
                .max(10);
            out.push((name.to_string(), entry.clone(), interval));
        }
    }
    out
}

pub(crate) fn default_locations() -> Vec<LocationDef> {
    let mk = |name: &str, action: &str, interval: u64| LocationDef {
        name: name.to_string(),
        enabled: true,
        interval_seconds: interval,
        action: action.to_string(),
        config: serde_json::json!({}),
    };
    let mut v = vec![
        // ── MESH-native (Rust evaluators) ──────────────────────────
        mk("node_health",           "alert",                   60),
        mk("backend_availability",  "auto_start_ollama",       60),
        mk("backend_idle_scaledown", "stop_idle_backends",     600),
        mk("node_auto_quarantine",  "quarantine_node",         120),
        mk("job_queue_depth",       "warning_log",             60),
        mk("backend_scaling",       "scale_backend",           300),
        // 300s: a tier disagreement is a standing condition, not a blip, and
        // the evaluator needs several consecutive confirmations before it
        // reports anything — polling faster only lengthens the wall-clock
        // before the threshold is met.
        mk("node_tier_drift",       "retier_node",             300),
        mk("edge_node_health",      "alert",                   120),
        // 300s: a wedge persists until a reboot, so minute-level polling buys
        // nothing; 5min still turns "two silent weeks" into minutes.
        mk("gpu_health",            "alert",                   300),
        // 300s: drift is a persistent condition, not a blip — no value in
        // polling it every minute, and the alert itself is 1h-cooldowned.
        mk("node_placement_drift", "alert",                   300),
        // Hourly: a node's data root changes only on provision; the alert
        // itself is cooldowned 24h per node.
        mk("node_data_root_policy", "alert",                  3600),
        mk("companion_battery_low", "alert",                   300),
        mk("test_suite_health",     "alert",                   3600),
        mk("failed_auth_spike",     "alert",                   60),
        mk("cert_expiry_check",     "alert",                   86400),
        mk("cert_auto_rotate",      "rotate_certs",            86400),
        // Disk fills slowly, so 15min is plenty; the point is to catch it
        // at the watermark rather than when writes start failing. Alert by
        // default; reclaim is a per-location config opt-in
        // (`enabled_action` + `dry_run: false`) that queues a host-side
        // `disk-reclaim` watcher op — see eval_disk_watermark.
        mk("disk_watermark",        "alert",                   900),
        // Detects the moment the design's deferred obligation comes
        // due: source_cycle_id being written at all, or worse, dangling.
        // Hourly is plenty — the alert has a 24h cooldown of its own.
        mk("cross_domain_link_integrity", "alert",             3600),
        // the design's act-when trigger: chunk_embeddings > 100k rows means
        // the deliberate exact-KNN chunk plan is approaching its crossover.
        // Daily estimate check (n_live_tup), weekly alert cooldown.
        mk("kb_chunk_scale",        "alert",                   86400),

        // ── TRELLION-side (NATS dispatch to Trellion worker) ─────────
        // Alert-only since background_embed was retired: trellion's own
        // PageIndexEmbedder drains pages/chunks; this watches that it does.
        mk("unembedded_documents",  "alert",                   300),
        mk("missing_graph_entities", "submit_graph_job",       600),
        // Conversation memory (noo_entries): one bounded batch per pass.
        mk("unembedded_conversations", "embed_memory_batch",   300),

        // ── Self-healing: SSH back to a worker that stopped heartbeating
        //    and bring its node-agent back up. Detection is Rust SQL
        //    (state.db), action is a NATS dispatch to Python worker_pool
        //    which has the SSH machinery.
        mk("worker_node_agent_unreachable", "ssh_revive",       60),

        // ── Self-healing: nodes that LOOK healthy but can't take work —
        //    dispatch consumer unbound (→ revive proposal) or advertised
        //    backend unreachable at its contract port (→ operator alert).
        //    Catches the host9/host8 failure classes of 2026-07-03 that
        //    heartbeat-based checks are blind to.
        mk("node_dispatch_health",  "revive_or_alert",          300),

        // ── Already replaced by ingest_loop.rs (skip here) ──────────
        // mk("watched_folders", "ingest_files", 60),
    ];

    // Opt-in ACTORS ship disabled — the docs promise these are opt-in,
    // and until 2026-07-09 they were silently force-enabled here.
    // cert_auto_rotate especially runs a full rotate+reload+revert cycle;
    // enable deliberately via the toggle API / config overlay.
    for loc in v.iter_mut() {
        if matches!(loc.name.as_str(), "cert_auto_rotate" | "backend_scaling") {
            loc.enabled = false;
        }
    }
    v
}

/// Evaluate one location and fire its action if conditions are met.
/// Each `match` arm is a self-contained port of the retired Python
/// `AutonomyEngine._evaluate_location` (no longer in the tree).
async fn evaluate_location(state: Arc<AppState>, loc: LocationDef) {
    let result: Result<bool, String> = match loc.name.as_str() {
        // ── MESH-native (Rust SQL/Redis/NATS-KV) ───────────────────
        "node_health"            => autonomy_evaluators::eval_node_health(&state).await,
        "node_placement_drift"   => autonomy_evaluators::eval_node_placement_drift(&state).await,
        "node_data_root_policy"  => autonomy_evaluators::eval_node_data_root_policy(&state).await,
        "edge_node_health"       => autonomy_evaluators::eval_edge_node_health(&state).await,
        "gpu_health"             => autonomy_evaluators::eval_gpu_health(&state).await,
        // The three backend_* locations CHANGE cluster state when armed, so
        // each gets its own `&loc.config` — the `enabled_action` opt-in is
        // per location, never a master switch.
        "backend_availability"   => autonomy_evaluators::eval_backend_availability(&state, &loc.config).await,
        "backend_idle_scaledown" => autonomy_evaluators::eval_backend_idle_scaledown(&state, &loc.config).await,
        "backend_scaling"        => autonomy_evaluators::eval_backend_scaling(&state, &loc.config).await,
        "node_tier_drift"        => autonomy_evaluators::eval_node_tier_drift(&state, &loc.config).await,
        "node_auto_quarantine"   => autonomy_evaluators::eval_node_auto_quarantine(&state).await,
        "job_queue_depth"        => autonomy_evaluators::eval_job_queue_depth(&state).await,
        "failed_auth_spike"      => autonomy_evaluators::eval_failed_auth_spike(&state).await,
        "test_suite_health"      => autonomy_evaluators::eval_test_suite_health(&state).await,
        "cert_expiry_check"      => eval_cert_expiry(&state).await,
        // Two opt-ins like the reclaim gate — this queues a fleet-wide
        // backup→rotate→reload→probe→auto-revert cycle.
        "cert_auto_rotate"       => autonomy_evaluators::eval_cert_auto_rotate(&state, &loc.config).await,
        "companion_battery_low"  => autonomy_evaluators::eval_companion_battery_low(&state).await,
        "disk_watermark"         => autonomy_evaluators::eval_disk_watermark(&state, &loc.config).await,
        "cross_domain_link_integrity" =>
            autonomy_evaluators::eval_cross_domain_link_integrity(&state).await,
        "kb_chunk_scale"         => autonomy_evaluators::eval_kb_chunk_scale(&state).await,

        // ── TRELLION-dispatch (NATS request to Python worker) ──────
        "unembedded_documents"   => autonomy_evaluators::eval_unembedded_documents(&state).await,
        "missing_graph_entities" => autonomy_evaluators::eval_missing_graph_entities(&state).await,
        "unembedded_conversations" => autonomy_evaluators::eval_unembedded_conversations(&state).await,

        // ── Self-healing (NATS dispatch to Python worker for SSH) ──
        "worker_node_agent_unreachable" => autonomy_evaluators::eval_worker_node_agent_unreachable(&state).await,
        "node_dispatch_health"   => autonomy_evaluators::eval_node_dispatch_health(&state).await,

        // ── All 14 default locations now have Rust evaluators. ──────
        // `watched_folders` (15th) is intentionally skipped here —
        // Rust ingest_loop.rs handles it via NATS to a Python worker.
        _ => {
            tracing::debug!(location = %loc.name, "autonomy_location_not_yet_ported");
            return;
        }
    };

    match result {
        Ok(true) => tracing::info!(location = %loc.name, "autonomy_action_fired"),
        Ok(false) => {} // condition not met, no action — deliberately unrecorded
        Err(e) => {
            tracing::warn!(location = %loc.name, error = %e, "autonomy_eval_error");
            // An unevaluable location is NOT "no action needed": it is a
            // location watching nothing, and that failure has been invisible
            // outside the log. It belongs in the same stream as the actions.
            crate::autonomy_audit::record(
                &state,
                crate::autonomy_audit::Decision {
                    location: &loc.name,
                    action: &loc.action,
                    outcome: crate::autonomy_audit::Outcome::Error,
                    target: None,
                    detail: &e,
                    // No claim either way: most locations have no gate, and
                    // asserting `false` would invent one.
                    armed: None,
                    dry_run: None,
                    metrics: None,
                },
            )
            .await;
        }
    }
}

/// Alert if any TLS cert expires within 30 days. Reuses the
/// PKI walker shared with `eval_cert_auto_rotate`.
async fn eval_cert_expiry(state: &AppState) -> Result<bool, String> {
    let count = autonomy_evaluators::count_certs_expiring_within(30).await;
    if count > 0 {
        tracing::warn!(count, "autonomy.cert_expiry_check.alert_30d");
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.cert_expiry_check",
                "pki",
                format!("🔐 {count} cluster TLS certificate(s) expire within 30 days."),
            )
            .detail(
                "rotate with `noo security pki rotate-all`, or arm the cert_auto_rotate location",
            )
            .investigate("noo security pki status"),
            86_400,
        )
        .await;
    }
    Ok(count > 0)
}

#[cfg(test)]
mod gate_tests {
    #[test]
    fn gate_capable_matches_the_dispatch() {
        let src = include_str!("autonomy_loop.rs");
        let dispatch = src.split("async fn evaluate_location").nth(1).expect("present");
        let dispatch = &dispatch[..dispatch.find("\n}").unwrap_or(dispatch.len())];
        let mut with_config: Vec<String> = Vec::new();
        for line in dispatch.lines() {
            if !line.contains("&loc.config") { continue; }
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start + 1..].find('"') {
                    with_config.push(line[start + 1..start + 1 + end].to_string());
                }
            }
        }
        with_config.sort();
        let mut listed: Vec<String> = super::GATE_CAPABLE.iter().map(|s| s.to_string()).collect();
        listed.sort();
        assert_eq!(with_config, listed, "GATE_CAPABLE drifted from the dispatch");
    }
}
