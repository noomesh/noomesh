// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Autonomy location evaluators.
//!
//! Each `eval_*` returns `Ok(true)` if the location's condition is met
//! (so the loop can fire the action), `Ok(false)` if no action is needed,
//! or `Err(...)` for evaluation failures (logged, treated as no-op).
//!
//! Categorisation (keep harness boundary in mind):
//! - **MESH-native** (all below, including `unembedded_documents` and
//!   `missing_graph_entities`) — pure Rust SQL/Redis/NATS-KV queries. Both
//!   query Postgres directly (`pages`/`entries`/`entities` tables);
//!   `missing_graph_entities` submits a background job over Redis when it
//!   fires, `unembedded_documents` only alerts when the backlog stops
//!   draining (trellion embeds on its own) — no NATS round-trip to a
//!   Trellion/Python evaluator.
//! - **HARNESS-dispatch** — none today; could appear if a future location
//!   needs the LLM to compute its condition.
//!
//! Reference Python implementation: `noomesh/cluster/autonomy.py` and
//! `noomesh/cluster/default_locations.py` (preserved as the canonical
//! spec — Python autonomy loop is dead in prod per the Tier 3 audit).

use std::collections::HashMap;

use serde_json::json;

use crate::state::AppState;
use crate::worker_client;

/// Helper: borrow the optional RedisCache. Returns None if Redis isn't
/// configured for this gateway (rare; mostly affects test deployments).
fn redis(state: &AppState) -> Option<&crate::cache::RedisCache> {
    state.redis.as_ref()
}

// ─── MESH-native evaluators (pure Rust) ────────────────────────────────

/// Offline threshold for worker nodes (tier <= 3): 120s without a
/// heartbeat. Tier 4 (edge) and tier 5 (companion) get a more lenient
/// threshold because they heartbeat less frequently.
const WORKER_OFFLINE_THRESHOLD_SECS: f64 = 120.0;
const EDGE_OFFLINE_THRESHOLD_SECS: f64 = 300.0;
const COMPANION_OFFLINE_THRESHOLD_SECS: f64 = 900.0;

/// Decide whether a KV entry represents an offline node based on the
/// `last_heartbeat` timestamp it stores (Unix seconds, written by
/// `routes/cluster.rs::node_heartbeat` at line ~105).
///
/// This replaces the older gossip-absence check (which falsely flagged
/// the gateway's own host as offline because gossip excludes self).
pub(crate) fn is_node_offline(data: &serde_json::Value, now_secs: f64) -> bool {
    // `last_heartbeat` is written by the heartbeat handler. Registration
    // (`node_register`) writes the entry FIRST and carries only `ts`, so for
    // the seconds between a node's registration and its first heartbeat the
    // field is absent. That is a node that just arrived, not one that never
    // heartbeated — and every restage paged "1 worker node(s) offline" on
    // exactly that gap (2026-09-22, each `node registered` line was followed
    // within 30 s by an alert). Fall back to `ts` before calling it offline.
    let last_seen = data
        .get("last_heartbeat")
        .and_then(|v| v.as_f64())
        .or_else(|| data.get("ts").and_then(|v| v.as_f64()));
    let Some(last) = last_seen else {
        // Neither field → never heartbeated and never registered by a
        // gateway that stamps `ts` → offline.
        return true;
    };
    let tier = data.get("tier").and_then(|t| t.as_u64()).unwrap_or(3);
    let threshold = match tier {
        5 => COMPANION_OFFLINE_THRESHOLD_SECS,
        4 => EDGE_OFFLINE_THRESHOLD_SECS,
        _ => WORKER_OFFLINE_THRESHOLD_SECS,
    };
    (now_secs - last) > threshold
}

fn now_unix_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// node_health — fire when any registered node has missed enough
/// heartbeats to be considered offline (per-tier threshold).
pub async fn eval_node_health(state: &AppState) -> Result<bool, String> {
    let kv = state.js.get_key_value("mesh_nodes")
        .await
        .map_err(|e| format!("mesh_nodes KV unavailable: {e}"))?;
    use tokio_stream::StreamExt;
    let keys: Vec<String> = kv.keys().await
        .map_err(|e| format!("kv.keys: {e}"))?
        .filter_map(|k| k.ok())
        .collect()
        .await;

    let now = now_unix_secs();
    let mut offline_nodes: Vec<String> = Vec::new();
    let mut healthy_nodes: Vec<String> = Vec::new();
    for key in keys {
        if key == "gateway" { continue; }
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(data) = serde_json::from_slice::<serde_json::Value>(&entry) else { continue };
        if is_node_offline(&data, now) {
            offline_nodes.push(key);
        } else {
            healthy_nodes.push(key);
        }
    }
    alert_nodes_on_change(state, "autonomy.node_health", "worker", &offline_nodes, &healthy_nodes).await;
    Ok(!offline_nodes.is_empty())
}

/// One persisting alert per offline node (so each is silent while it stays
/// down, muted by maintenance, and closed by its own "back" message), and a
/// recovery for each node that heartbeats again. Alerts raised in one pass
/// leave as one grouped message.
async fn alert_nodes_on_change(
    state: &AppState,
    kind: &str,
    label: &str,
    offline: &[String],
    healthy: &[String],
) {
    if !offline.is_empty() {
        tracing::warn!(offline_count = offline.len(), nodes = ?offline, kind, "autonomy.node_health.alert");
    }
    for node in offline {
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(kind, node, node_offline_text(label, node))
                .investigate(format!("noo cluster verify {node}"))
                .persisting(),
            0,
        )
        .await;
    }
    for node in healthy {
        crate::operator_alert::clear_operator_alert(
            state,
            crate::operator_alert::OperatorAlert::new(kind, node, format!("Node '{node}' is heartbeating again."))
                .investigate(format!("noo cluster verify {node}")),
        )
        .await;
    }
}

/// The page names the node. "1 worker node(s) offline" sent the operator
/// to `noo cluster status` to learn which one; by then it was usually back.
pub fn node_offline_text(kind: &str, node: &str) -> String {
    format!("⚠️ Cluster health: {kind} node '{node}' is offline (missed heartbeat threshold).")
}

/// node_placement_drift — fire when an ONLINE node isn't running the
/// backends its desired state says it should.
///
/// `eval_node_health` only asks "is it heartbeating?", and that is exactly
/// how host8 hid a dead GPU for **8 days** (2026-07-18 → 07-26): its GPU
/// fell off the bus (Xid 79), the node-agent couldn't start, so it ran NONE
/// of its three declared backends — yet it heartbeated happily and showed
/// `online`, and the coordinator quietly failed inference over to other
/// nodes. Liveness is not health.
///
/// Compares desired placements (`noo_backend_placements`, desired_state
/// 'running') against what the node actually reports in `running_backends`
/// on each heartbeat. Offline nodes are skipped — `eval_node_health` owns
/// those, and we don't want two alerts for one outage.
///
/// Deliberately data-driven and OS-agnostic: no nvidia-smi, no /proc
/// probing, nothing per-platform. A node that loses its GPU, its docker
/// daemon, or its agent all surface the same way — declared work not being
/// done.
pub async fn eval_node_placement_drift(state: &AppState) -> Result<bool, String> {
    // Desired: node → backends that should be running.
    let rows = crate::repo::cluster::placements_desired_running(&state.db)
        .await
        .map_err(|e| format!("placements query: {e}"))?;

    if rows.is_empty() {
        return Ok(false);
    }

    let mut desired: HashMap<String, Vec<String>> = HashMap::new();
    for (node, backend) in rows {
        desired.entry(node).or_default().push(backend);
    }

    let kv = state
        .js
        .get_key_value("mesh_nodes")
        .await
        .map_err(|e| format!("mesh_nodes KV unavailable: {e}"))?;

    let now = now_unix_secs();
    let mut drifted: Vec<(String, Vec<String>)> = Vec::new();

    for (node_id, want) in &desired {
        let Ok(Some(entry)) = kv.get(node_id).await else {
            // No KV entry = not heartbeating = offline; node_health's job.
            continue;
        };
        let Ok(data) = serde_json::from_slice::<serde_json::Value>(&entry) else { continue };
        if is_node_offline(&data, now) {
            continue;
        }
        // `running_backends` is a map backend → model, written from the
        // node's own heartbeat (routes/cluster.rs). Absent/empty means the
        // agent is up but managing nothing.
        let running = data.get("running_backends").and_then(|v| v.as_object());
        let missing: Vec<String> = want
            .iter()
            .filter(|b| running.map(|m| !m.contains_key(b.as_str())).unwrap_or(true))
            .cloned()
            .collect();
        if !missing.is_empty() {
            drifted.push((node_id.clone(), missing));
        }
    }

    if drifted.is_empty() {
        return Ok(false);
    }

    for (node_id, missing) in &drifted {
        tracing::warn!(
            node = %node_id,
            missing = %missing.join(","),
            "autonomy.node_placement_drift.alert"
        );
        // Cooldown per NODE, not per cluster: one broken node shouldn't
        // mask a second one going bad. 1h — this is a persistent condition,
        // not a transient blip, so re-alerting every 30m would just be noise.
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.node_placement_drift",
                node_id,
                format!(
                    "⚠️ Node `{node_id}` is online but is NOT running {} of its declared \
                     backend(s): {}. It still heartbeats, so inference silently fails \
                     over elsewhere.",
                    missing.len(),
                    missing.join(", "),
                ),
            )
            .detail(
                "check the node-agent (`docker ps -a` on the node) and whether its GPU/driver \
                 is alive — a dead GPU used to stop the agent starting at all",
            )
            .investigate(format!("noo cluster verify {node_id}")),
            3600,
        )
        .await;
    }
    Ok(true)
}

/// The problem codes a node's own data-root check reports
/// (`data_roots.policy`), or None when the root passes or the agent
/// predates the policy (node-agent-go/internal/dataroots/policy.go).
pub(crate) fn data_root_policy_failures(data: &serde_json::Value) -> Option<Vec<String>> {
    let pol = data.get("data_roots")?.get("policy")?;
    if pol.get("ok").and_then(|v| v.as_bool()) != Some(false) {
        return None;
    }
    let codes: Vec<String> = pol
        .get("problems")
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|p| p.get("code")?.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    Some(if codes.is_empty() { vec!["unspecified".into()] } else { codes })
}

/// node_data_root_policy — one alert per node whose data root fails the
/// data-root policy (a dedicated, conventional `noo` directory owned by the
/// agent). The root becomes the node's allowed host root, so a root under
/// /home or a system path widens what may be mounted. Persistent, so a 24h
/// per-node cooldown; the channel line stays general, the codes go to the
/// detail and `noo cluster verify <node>` names the fix.
pub async fn eval_node_data_root_policy(state: &AppState) -> Result<bool, String> {
    let kv = state.js.get_key_value("mesh_nodes")
        .await
        .map_err(|e| format!("mesh_nodes KV unavailable: {e}"))?;
    use tokio_stream::StreamExt;
    let keys: Vec<String> = kv.keys().await
        .map_err(|e| format!("kv.keys: {e}"))?
        .filter_map(|k| k.ok())
        .collect()
        .await;
    let now = now_unix_secs();
    let mut fired = false;
    for key in keys {
        if key == "gateway" { continue; }
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(data) = serde_json::from_slice::<serde_json::Value>(&entry) else { continue };
        if is_node_offline(&data, now) { continue; }
        let Some(codes) = data_root_policy_failures(&data) else { continue };
        fired = true;
        tracing::warn!(node = %key, codes = %codes.join(","), "autonomy.node_data_root_policy.alert");
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.node_data_root_policy",
                &key,
                format!("⚠️ Node `{key}` keeps its data somewhere the data-root policy does not allow."),
            )
            .detail(format!("data root policy problems: {}", codes.join(", ")))
            .investigate(format!("noo cluster verify {key}")),
            86400,
        )
        .await;
    }
    Ok(fired)
}

/// edge_node_health — fire when any tier ≥ 4 node has missed heartbeats.
/// Uses the same `is_node_offline` helper as `eval_node_health`, which
/// applies the more lenient EDGE/COMPANION threshold automatically.
pub async fn eval_edge_node_health(state: &AppState) -> Result<bool, String> {
    let kv = state.js.get_key_value("mesh_nodes")
        .await
        .map_err(|e| format!("mesh_nodes KV unavailable: {e}"))?;
    use tokio_stream::StreamExt;
    let keys: Vec<String> = kv.keys().await
        .map_err(|e| format!("kv.keys: {e}"))?
        .filter_map(|k| k.ok())
        .collect()
        .await;

    let now = now_unix_secs();
    let mut edge_nodes: Vec<String> = Vec::new();
    let mut healthy_edge: Vec<String> = Vec::new();
    for key in keys {
        if key == "gateway" { continue; }
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(data) = serde_json::from_slice::<serde_json::Value>(&entry) else { continue };
        let tier = data.get("tier").and_then(|t| t.as_u64()).unwrap_or(3);
        if tier < 4 { continue; }
        if is_node_offline(&data, now) {
            edge_nodes.push(key);
        } else {
            healthy_edge.push(key);
        }
    }
    alert_nodes_on_change(state, "autonomy.edge_node_health", "edge (tier ≥ 4)", &edge_nodes, &healthy_edge).await;
    Ok(!edge_nodes.is_empty())
}

/// The single opt-in gate for the three `backend_*` locations that CHANGE
/// cluster state.
///
/// Same shape and same default as `disk_watermark`'s reclaim gate: the switch
/// is `enabled_action` on the LOCATION's own config (the `autonomy.locations`
/// YAML overlay, or the `config` column of a `noo_autonomy_overrides` row that
/// the toggle API now writes), and it defaults **false**.
///
/// Off is not silent: each location logs a `…would_*` line naming exactly the
/// node / backend / replica count it would have acted on, so the operator can
/// watch a location dry-run for a week before arming it. That is the whole
/// point of the gate — an autonomy action nobody has watched is a change
/// nobody consented to.
///
/// Non-boolean values fail closed, as with the reclaim gate: a `"true"` string
/// in a hand-edited YAML must not arm an action.
fn action_enabled(config: &serde_json::Value) -> bool {
    config
        .get("enabled_action")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Backend type `backend_availability` starts when it is armed. Ollama is the
/// default because it is the only backend that runs on every tier without a
/// GPU; override per location with `config.backend`.
fn availability_backend(config: &serde_json::Value) -> String {
    config
        .get("backend")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("ollama")
        .to_string()
}

/// backend_availability — fire when zero backends are running across the
/// whole cluster.
///
/// ARMED (`enabled_action: true`): start `config.backend` (default ollama) on
/// the first node-agent that is not inside a start-failure cooldown, through
/// the same `start_backend_core` path the /backends/start route drives — cooldown map,
/// controller image/parser forwarding and node-agent auth included. The
/// cooldown check is what keeps a flapping node from being hammered once a
/// minute by a loop that never gets bored.
///
/// DISARMED (default): logs what it would have started and, as before, that
/// there are no backends. Deliberately NO operator alert in this state —
/// upgrading to this build must not start paging an install that was quiet
/// yesterday.
pub async fn eval_backend_availability(
    state: &AppState,
    config: &serde_json::Value,
) -> Result<bool, String> {
    let running_count: usize = state
        .gossip
        .alive_peers()
        .iter()
        .map(|p| p.backends.len())
        .sum();
    if running_count > 0 {
        return Ok(false);
    }
    tracing::warn!("autonomy.backend_availability.no_backends");

    let backend = availability_backend(config);
    // Candidate = a registered node-agent whose cooldown for this backend has
    // expired. `all_node_agents` is the same list the start route auto-selects
    // from, so "who would autonomy pick" and "who does the route pick" agree.
    let candidate = crate::routes::admin::all_node_agents(state)
        .await
        .into_iter()
        .map(|(node_id, _url, _hostname)| node_id)
        .find(|node_id| crate::routes::cluster::backend_start_cooled_down(node_id, &backend));

    let Some(node_id) = candidate else {
        tracing::warn!(
            backend = %backend,
            "autonomy.backend_availability.no_candidate_node"
        );
        return Ok(true);
    };

    if !action_enabled(config) {
        tracing::warn!(
            node_id = %node_id,
            backend = %backend,
            "autonomy.backend_availability.would_start"
        );
        crate::autonomy_audit::record_would(
            state,
            "backend_availability",
            "auto_start_ollama",
            Some(&node_id),
            &format!(
                "no backends running anywhere; would start `{backend}` on node \
                 `{node_id}` (arm with `enabled_action: true`)"
            ),
        )
        .await;
        return Ok(true);
    }

    match crate::routes::cluster::start_backend_core(state, Some(&node_id), &backend, "").await {
        Ok(result) => {
            tracing::info!(
                node_id = %node_id,
                backend = %backend,
                ?result,
                "autonomy.backend_availability.started"
            );
            crate::autonomy_audit::record_fired(
                state,
                "backend_availability",
                "auto_start_ollama",
                Some(&node_id),
                &format!("started `{backend}` on node `{node_id}` — zero backends were running"),
            )
            .await;
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.backend_availability",
                    &node_id,
                    format!(
                        "🚀 Autonomy started `{backend}` on node `{node_id}`: the cluster \
                         was reporting zero running backends."
                    ),
                )
                .detail(format!(
                    "stop it with `noo cluster down {backend} --node {node_id}`; disarm with \
                     `enabled_action: false` on the backend_availability location"
                ))
                .investigate("noo autonomy audit"),
                1800,
            )
            .await;
        }
        Err(e) => {
            tracing::warn!(
                node_id = %node_id,
                backend = %backend,
                error = %e,
                "autonomy.backend_availability.start_failed"
            );
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.backend_availability",
                    &node_id,
                    format!(
                        "⚠️ Autonomy could not start `{backend}` on node `{node_id}` \
                         (cluster has zero running backends)."
                    ),
                )
                .detail(e.to_string())
                .investigate(format!("noo cluster verify {node_id}")),
                1800,
            )
            .await;
        }
    }
    Ok(true)
}

/// job_queue_depth — fire when the Redis job queue has > 10 pending jobs.
pub async fn eval_job_queue_depth(state: &AppState) -> Result<bool, String> {
    const THRESHOLD: i64 = 10;
    let Some(r) = redis(state) else { return Ok(false); };
    let depth: i64 = r.zcard("noo:jobs:queue").await;
    if depth > THRESHOLD {
        tracing::warn!(queue_depth = depth, threshold = THRESHOLD, "autonomy.job_queue_depth.warning");
    }
    Ok(depth > THRESHOLD)
}

/// Usage stats for the filesystem backing `path`: `(used_pct, avail_gb,
/// total_gb)`. `None` if the path can't be stat'd.
///
/// The percentage matches `df` exactly — `used / (used + available)`,
/// where `used` excludes the root-reserved blocks that `f_bfree` counts
/// but `f_bavail` doesn't. Using a naive `1 - avail/total` would read a
/// few points higher than `df` and make alerts look wrong when an
/// operator checks by hand.
fn fs_usage(path: &str) -> Option<(f64, f64, f64)> {
    let c_path = std::ffi::CString::new(path).ok()?;
    // SAFETY: `stat` is zeroed and correctly sized for statvfs; the path
    // is a valid NUL-terminated C string that outlives the call. statvfs
    // only writes into `stat` and returns a status code.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let frsize = stat.f_frsize as f64;
    let total = stat.f_blocks as f64 * frsize;
    let avail = stat.f_bavail as f64 * frsize;
    let used = (stat.f_blocks as f64 - stat.f_bfree as f64) * frsize;
    let denom = used + avail;
    if total <= 0.0 || denom <= 0.0 {
        return None;
    }
    const GB: f64 = 1_000_000_000.0;
    Some((used / denom * 100.0, avail / GB, total / GB))
}

/// Watermark percentage from the raw env value, defaulting to 85.
///
/// An EMPTY value must mean "unset". docker-compose has no way to omit a
/// variable from an explicit `environment:` list, so the standard
/// `${VAR:-}` passthrough delivers `""` when the operator hasn't set it.
fn parse_watermark(raw: Option<String>) -> f64 {
    raw.and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0 && *v <= 100.0)
        .unwrap_or(85.0)
}

/// Comma-separated watch paths from the raw env value, defaulting to "/".
///
/// Empty means "unset" for the same `${VAR:-}` reason as above. Getting
/// this wrong is silent and total: an empty string yields ZERO paths to
/// check, so the evaluator would return Ok(false) forever and the
/// location would look healthy while monitoring nothing.
fn parse_watch_paths(raw: Option<String>) -> String {
    raw.map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/".to_string())
}

/// Reclaim opt-ins from the disk_watermark LOCATION config (YAML overlay /
/// `noo_autonomy_overrides` row): `(action_enabled, dry_run)`.
///
/// Two deliberate defaults, following the usage_rollup / heartbeat_retention
/// convention in heartbeat_actions.rs — this action deletes data, so it must
/// be asked for TWICE:
/// - `enabled_action` defaults **false** — nothing is even queued until the
///   operator opts the location in.
/// - `dry_run` defaults **true** — the first enabled run PREVIEWS what each
///   rung would remove; `dry_run: false` is a second, separate opt-in.
fn parse_reclaim_config(config: &serde_json::Value) -> (bool, bool) {
    let enabled = config
        .get("enabled_action")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dry_run = config
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    (enabled, dry_run)
}

/// The optional per-builder build-cache cap from the location config.
fn cache_cap_bytes(config: &serde_json::Value) -> Option<i64> {
    config.get("cache_cap_bytes").and_then(|v| v.as_i64()).filter(|v| *v > 0)
}

/// The node disk-reclaim policy desired-config serves as `disk_reclaim`.
///
/// One gate for the fleet: a node's own ladder acts exactly when the
/// controller's would — the `disk_watermark` location enabled AND armed
/// (`enabled_action`), previewing while `dry_run` (the default). Nodes queue
/// the ladder into their own hostd; the controller never reaches a node's
/// disk.
pub(crate) async fn node_reclaim_policy(state: &AppState) -> serde_json::Value {
    let watermark = parse_watermark(std::env::var("NOO_DISK_WATERMARK_PERCENT").ok());
    let locs = crate::autonomy_loop::load_locations(state).await;
    let loc = locs.iter().find(|l| l.name == "disk_watermark");
    let (armed, dry_run) = loc
        .and_then(|l| crate::autonomy_loop::gate_of(&l.name, &l.config))
        .unwrap_or((false, true));
    let enabled = loc.map(|l| l.enabled).unwrap_or(false) && armed;
    node_reclaim_policy_json(enabled, dry_run, watermark, loc.and_then(|l| cache_cap_bytes(&l.config)))
}

fn node_reclaim_policy_json(enabled: bool, dry_run: bool, watermark: f64, cache_cap: Option<i64>) -> serde_json::Value {
    let mut p = serde_json::json!({
        "enabled": enabled,
        "dry_run": dry_run,
        "watermark": watermark.round() as i64,
    });
    if let Some(cap) = cache_cap {
        p["cache_cap_bytes"] = serde_json::json!(cap);
    }
    p
}

/// The chat line for a node over the watermark, from what the node's own
/// `/health` says its reclaim did. The per-run report stays in the alert's
/// detail (logs), never in the channel line.
fn node_disk_alert_summary(node_id: &str, watermark: f64, disks: usize, reclaim: Option<&serde_json::Value>) -> String {
    let head = format!("💾 Disk watermark on node {node_id} ({watermark:.0}%) on {disks} disk(s).");
    let Some(r) = reclaim else {
        return format!(
            "{head} This node's agent predates node disk reclaim — run `noo upgrade --nodes`; \
             meanwhile on the node: `docker image prune` (dangling images only)."
        );
    };
    let policy = r.get("policy");
    let enabled = policy.and_then(|p| p.get("enabled")).and_then(|v| v.as_bool()).unwrap_or(false);
    let dry_run = policy.and_then(|p| p.get("dry_run")).and_then(|v| v.as_bool()).unwrap_or(true);
    let last_failed = r.pointer("/last_result/ok").and_then(|v| v.as_bool()) == Some(false);
    if enabled && last_failed {
        return format!(
            "{head} The node's last reclaim run failed, so nothing was freed — \
             the alert detail carries its report."
        );
    }
    match (enabled, dry_run) {
        (false, _) => format!(
            "{head} Node disk reclaim is off — arm the disk_watermark location \
             (enabled_action, dry_run false) to let nodes reclaim on their own."
        ),
        (true, true) => format!(
            "{head} The node's reclaim ladder is previewing only (dry run) — set dry_run \
             false on the disk_watermark location to let it act."
        ),
        (true, false) => format!("{head} The node's own reclaim ladder is acting on it."),
    }
}

/// disk_watermark — fire when a watched filesystem crosses a usage
/// watermark, so the operator hears about it before writes start failing.
///
/// Why `/` is the default watch path: the gateway runs INSIDE a
/// container, so the host's image-layer store is not directly visible.
/// But the container's own rootfs is an overlay backed by that store, so
/// `statvfs("/")` reports exactly that filesystem. On this deployment
/// Docker's containerd snapshotter keeps image layers on a separate
/// 147 GB disk (`/var/lib/containerd`) while volumes live on a 1 TB disk
/// (`/var/lib/docker`) — so `df /` on the HOST looks fine while the disk
/// that actually matters is full.
///
/// This is not hypothetical: on 2026-07-26 the layer disk hit 100% and
/// the gateway crash-looped on `No space left on device: '/tmp/pki'`
/// while the host's other disk still had 700 GB free. Two vLLM images
/// alone were 62 GB. Docker's builder GC does not help — it prunes build
/// cache only, never images, and only for the default builder.
///
/// Alert-first by design: reclaiming space means deleting things, and
/// which images are expendable is a judgement call (a "stale" tag can be
/// a documented rollback target). Surfacing early beats guessing.
///
/// OPT-IN reclaim: with `enabled_action: true` in the
/// location config, a breach additionally queues a `disk-reclaim` op on
/// the host watcher spool. The action cannot run here — the gateway has
/// no docker socket by design — and the watcher is exactly the host-side
/// executor built for this class (same path cert_auto_rotate uses). The
/// watcher walks a strictly-bounded ladder, stopping as soon as usage
/// drops below the watermark:
///   1. dangling images (untagged only — never `-a`)
///   2. build cache older than 7 days
///   3. stopped rename-orphan containers matching `<12hex>_noo-*` ONLY
///
///   4. build-cache volumes carrying noo's `noo.cargo-docker-src` label,
///      unused, whose checkout is gone or that sat idle a week (98 of them
///      held ~117 GB on host3, 2026-10-03)
/// It never touches any other volume, tagged images, or anything running.
/// Containerd leases are NOT reclaimed (the rung this comment once listed
/// existed only in the archived shell watcher): removing leases by age
/// deleted live containers' snapshots on host3.
/// `dry_run` defaults true (preview-first, matching usage_rollup /
/// heartbeat_retention); freed bytes come back via the result file and
/// are reported per rung with before/after usage.
///
/// Tunables: `NOO_DISK_WATERMARK_PERCENT` (default 85),
/// `NOO_DISK_WATCH_PATHS` (comma-separated, default `/`); location config
/// `enabled_action` (default false), `dry_run` (default true),
/// `cache_cap_bytes` (optional per-builder build-cache cap, rung 2b).
/// The same gate governs every NODE's own ladder: desired-config carries it
/// as `disk_reclaim` (see [`node_reclaim_policy`]).
pub async fn eval_disk_watermark(
    state: &AppState,
    config: &serde_json::Value,
) -> Result<bool, String> {
    let watermark = parse_watermark(std::env::var("NOO_DISK_WATERMARK_PERCENT").ok());
    let paths = parse_watch_paths(std::env::var("NOO_DISK_WATCH_PATHS").ok());

    let mut breached: Vec<String> = Vec::new();
    for path in paths.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let Some((used_pct, avail_gb, total_gb)) = fs_usage(path) else {
            // A path that isn't mounted in this container is a config
            // nit, not an incident — don't let it fail the evaluation.
            tracing::debug!(path, "autonomy.disk_watermark.unstattable");
            continue;
        };
        tracing::debug!(path, used_pct, avail_gb, "autonomy.disk_watermark.checked");
        if used_pct >= watermark {
            breached.push(format!(
                "{path}: {used_pct:.0}% used, {avail_gb:.1} GB free of {total_gb:.0} GB"
            ));
        }
    }

    if breached.is_empty() {
        // Local disks fine — the fleet's may not be.
        return Ok(eval_node_disks(state, watermark).await);
    }

    let detail = breached.join("; ");
    tracing::warn!(detail, watermark, "autonomy.disk_watermark.alert");
    // Which paths, and how full, is evidence for the log; the channel gets
    // the count and the advice.
    crate::operator_alert::send_operator_alert_with(
        state,
        crate::operator_alert::OperatorAlert::new(
            "autonomy.disk_watermark",
            "gateway",
            format!(
                "💾 Disk watermark exceeded ({watermark:.0}%) on {n} controller disk(s). \
                 Image layers are the usual cause — `docker system df` to see \
                 sizes, then remove unused images (`docker builder prune` will \
                 NOT reclaim these). Note image layers may live on a different \
                 disk than volumes.",
                n = breached.len(),
            ),
        )
        .detail(detail.clone())
        .investigate("noo autonomy decisions --location disk_watermark"),
        21600, // 6h — a full disk is not fixed in minutes; don't spam.
    )
    .await;

    // Opt-in reclaim: both gates default off/safe — see
    // parse_reclaim_config.
    let (action_enabled, dry_run) = parse_reclaim_config(config);
    if action_enabled {
        queue_disk_reclaim(state, watermark, dry_run, cache_cap_bytes(config)).await;
    }
    // Node disks are checked regardless of the local outcome — one full
    // controller must not mask a full worker or vice versa.
    let _ = eval_node_disks(state, watermark).await;
    Ok(true)
}

/// Per-node disk breaches from an agent's `/health` payload. Same
/// affirmative-only skew contract as gpu_health's probes: agents predating
/// the `disk` field (or non-Linux ones, which report nothing) yield an
/// empty list — unknown is never a breach.
fn node_disk_breaches(body: &serde_json::Value, watermark: f64) -> Vec<String> {
    let Some(disks) = body.get("disk").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for d in disks {
        let (Some(path), Some(used)) = (
            d.get("path").and_then(|v| v.as_str()),
            d.get("used_percent").and_then(|v| v.as_f64()),
        ) else {
            continue;
        };
        if used >= watermark {
            let avail = d.get("avail_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let total = d.get("total_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            out.push(format!(
                "{path}: {used:.0}% used, {avail:.1} GB free of {total:.0} GB"
            ));
        }
    }
    out
}

/// Probe every online node's agent for disk usage and alert per node
/// (the local watch above sees only the CONTROLLER's
/// filesystems; host8 sat at 58% with the same lease-leak mechanics and
/// nothing watching). The controller cannot reclaim a node's disk; each
/// node runs the same ladder itself under [`node_reclaim_policy`] and
/// reports it in `/health` `disk_reclaim`, which this alert relays. It no
/// longer advises removing containerd leases by age — that deleted live
/// containers' snapshots on host3. Unreachable agents are
/// node_health's finding, skipped here (same scope discipline as gpu_health).
async fn eval_node_disks(state: &AppState, watermark: f64) -> bool {
    let nodes: Vec<(String,)> = sqlx::query_as(
        "SELECT node_id FROM cluster_nodes WHERE status = 'online'",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut any = false;
    for (node_id,) in nodes {
        let Ok(link) = crate::node_link::NodeLink::for_node(state, &node_id).await
        else {
            continue;
        };
        let req = link
            .request(reqwest::Method::GET, "/health")
            .timeout(std::time::Duration::from_secs(10));
        let Ok(resp) = req.send().await else { continue };
        let Ok(body) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        let breaches = node_disk_breaches(&body, watermark);
        if breaches.is_empty() {
            continue;
        }
        any = true;
        let reclaim = body.get("disk_reclaim");
        let mut detail = breaches.join("; ");
        if let Some(r) = reclaim {
            detail.push_str(&format!(" | node reclaim: {r}"));
        }
        tracing::warn!(node_id = %node_id, detail, "autonomy.node_disk_watermark");
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.node_disk_watermark",
                &node_id,
                node_disk_alert_summary(&node_id, watermark, breaches.len(), reclaim),
            )
            .detail(detail.clone())
            .investigate(format!("noo cluster show {node_id}")),
            21600, // 6h, same as the local watermark alert
        )
        .await;
    }
    any
}

/// Queue a `disk-reclaim` op on the host watcher spool and report the
/// outcome as an operator alert.
///
/// Runs host-side because that is where the disk IS: the gateway container
/// has no docker socket and no docker CLI (by design — docker belongs to
/// noo-hostd on the host), and the filesystem it watches is the host's
/// image-layer store seen through its own overlay rootfs. noo-hostd
/// measures usage on the host, walks the ladder, and writes freed-bytes
/// per rung plus before/after usage into the result file.
///
/// Redis-guarded to one queued reclaim per hour: the location re-evaluates
/// every 15 min and a still-breached disk must not stack identical spool
/// commands (same shape as the missing_graph_entities dedup). No Redis →
/// no reclaim; for a data-deleting action, failing to act is the safe
/// degradation, and the disk_watermark alert above still fired.
async fn queue_disk_reclaim(state: &AppState, watermark: f64, dry_run: bool, cache_cap: Option<i64>) {
    const DEDUP_KEY: &str = "noo:autonomy:dedup:disk_reclaim";
    const DEDUP_TTL_SECS: i64 = 3600;
    let Some(r) = redis(state) else {
        tracing::warn!("autonomy.disk_reclaim.skipped_no_redis");
        return;
    };
    if !r.set_nx_ex(DEDUP_KEY, "1", DEDUP_TTL_SECS).await {
        tracing::debug!("autonomy.disk_reclaim.dedup_skip");
        return;
    }

    let mut args = vec![
        format!("dry_run={dry_run}"),
        format!("watermark={:.0}", watermark),
    ];
    if let Some(cap) = cache_cap {
        args.push(format!("cache_cap_bytes={cap}"));
    }
    let Some(path) = crate::routes::admin::host_spool_write_command(
        "disk-reclaim",
        "docker",
        &args,
        "autonomy.disk_watermark",
    )
    .await
    else {
        // The condition was met and the action could not even be queued —
        // that must not stay log-only (same reasoning as cert_auto_rotate's
        // dispatch_failed arm).
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.disk_reclaim.queue_failed",
                "docker",
                "💾❗ Disk is past its watermark and the reclaim could not be queued: \
                 the host helper is not taking commands.",
            )
            .detail(
                "host spool unavailable — is noo-hostd running? (`systemctl --user status \
                 noo-hostd`). Reclaim space manually: `docker image prune -f`, \
                 `docker builder prune -f --filter until=168h`",
            )
            .investigate("noo logs search --name noo-hostd --since 1h"),
            21_600,
        )
        .await;
        return;
    };
    tracing::info!(dry_run, watermark, path = %path, "autonomy.disk_reclaim.queued");

    // Poll briefly for the watcher's result file (prunes usually finish in
    // seconds). Timing out is fine — the result lands in the spool dir and
    // the next breach's alert re-surfaces the state.
    let cmd_path = std::path::Path::new(&path);
    let Some(stem) = cmd_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".cmd.json"))
    else {
        tracing::warn!(path = %path, "autonomy.disk_reclaim.unexpected_spool_filename");
        return;
    };
    let result_path = cmd_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(format!("{stem}.result.json"));

    for _ in 0..12 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if !result_path.exists() {
            continue;
        }
        let (ok, report) = match std::fs::read_to_string(&result_path)
            .ok()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
        {
            Some(v) => (
                v.get("ok").and_then(|o| o.as_bool()).unwrap_or(false),
                v.get("stderr")
                    .and_then(|s| s.as_str())
                    .unwrap_or("(no detail)")
                    .to_string(),
            ),
            None => (false, format!("result file unreadable: {}", result_path.display())),
        };
        let header = if dry_run {
            "💾 Disk reclaim DRY RUN (nothing removed — set `dry_run: false` \
             on the disk_watermark location to act)"
        } else if ok {
            "💾 Disk reclaim completed"
        } else {
            "💾❗ Disk reclaim FAILED"
        };
        // The host's report (prune output, stderr) is evidence for the log;
        // the channel gets the verdict.
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.disk_reclaim",
                "docker",
                format!("{header}."),
            )
            .detail(report)
            .investigate("noo autonomy audit"),
            0, // outcome of an explicit action — always report
        )
        .await;
        return;
    }
    crate::operator_alert::send_operator_alert_with(
        state,
        crate::operator_alert::OperatorAlert::new(
            "autonomy.disk_reclaim",
            "docker",
            format!(
                "💾 Disk reclaim queued host-side (dry_run={dry_run}); no result \
                 after 60s — the host daemon's result and watcher log say why."
            ),
        )
        .detail(format!("result_path={}", result_path.display()))
        .investigate("noo logs search --name noo-hostd --since 1h"),
        0,
    )
    .await;
}

/// failed_auth_spike — fire when more than 10 auth failures in the last
/// 5 minutes. Reads from `noo_security_audit` (event_type='auth_failure').
pub async fn eval_failed_auth_spike(state: &AppState) -> Result<bool, String> {
    const THRESHOLD: i64 = 10;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM noo_security_audit \
         WHERE event_type = 'auth_failure' \
           AND timestamp > NOW() - INTERVAL '5 minutes'"
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| e.to_string())?;
    if count > THRESHOLD {
        tracing::warn!(auth_failures_5m = count, "autonomy.failed_auth_spike.alert");
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.failed_auth_spike",
                "gateway",
                format!(
                    "🔒 Security: {count} authentication failures in the last 5 minutes \
                     (threshold {THRESHOLD})."
                ),
            )
            .detail("source addresses are in the noo_security_audit table")
            .investigate("noo doctor strangers"),
            3600,
        )
        .await;
    }
    Ok(count > THRESHOLD)
}

// ─── Trellion-schema evaluators (native Rust SQL) ───────────────────────
//
// Originally these dispatched to Python via NATS (the design framing:
// "Trellion owns the schema, dispatch via NATS"). In practice that
// caused queue starvation (worker_pool processes non-priority subjects
// sequentially; graph_extractor's parallel `worker.temporal.extract`
// floods kept these requests from being serviced before Rust's 120s
// NATS timeout).
//
// The the design rule "schema owner = Python" really means "Python
// owns migrations + writes". Read-only SQL on a shared Postgres can
// come from anywhere — Rust already has a sqlx pool to the same DB.
// Sub-ms latency vs the NATS roundtrip + queue wait, no Python worker
// dependency. Schema queries are stable + tested via Trellion's
// migrations so the SQL doesn't drift.

/// Pages with no usable vector, NOT counting those of held documents
/// (`docs.held_at`): a held document is kept out of embedding on purpose, so
/// its pages are not a backlog. One definition for every surface that counts
/// the backlog (this evaluator, `/metrics`, `/api/v1/rag/status`).
/// `held` is [`crate::held_column::present`]: without the column (trellion
/// not yet migrated) the plain, unfiltered form is used.
pub fn sql_unembedded_pages(held: bool) -> String {
    format!(
        "SELECT COUNT(*) FROM pages p \
         JOIN docs d ON d.doc_id = p.doc_id \
         LEFT JOIN page_embeddings pe ON pe.page_id = p.page_id \
         WHERE {} AND (pe.page_id IS NULL OR pe.embedding IS NULL)",
        crate::held_column::not_held("d", held)
    )
}
/// The chunk twin of [`sql_unembedded_pages`].
pub fn sql_unembedded_chunks(held: bool) -> String {
    format!(
        "SELECT COUNT(*) FROM page_chunks c \
         JOIN pages p ON p.page_id = c.page_id \
         JOIN docs d ON d.doc_id = p.doc_id \
         LEFT JOIN chunk_embeddings ce ON ce.chunk_id = c.chunk_id \
         WHERE {} AND (ce.chunk_id IS NULL OR ce.embedding IS NULL)",
        crate::held_column::not_held("d", held)
    )
}
fn sql_unembedded_total(held: bool) -> String {
    format!(
        "SELECT ({}) + ({})",
        sql_unembedded_pages(held),
        sql_unembedded_chunks(held)
    )
}

/// Count pages + chunks with NO USABLE VECTOR: no embedding row at all, or
/// a row whose embedding is NULL.
///
/// Shared by the autonomy evaluator below and the heartbeat `rag_reindex`
/// action — one count, one truth. Two distinct silent bugs met in this
/// query, both presenting as "0 waiting" (indistinguishable from healthy):
///
/// 1. Matching only on a MISSING row reported 0 after the 768 -> 1024
///    migration, which keeps rows and blanks vectors. The embed job was
///    never submitted and the corpus could not re-embed.
/// 2. Counting only PAGES orphaned the chunks. Pages finished first, the
///    count went to 0, the evaluator concluded there was no work, and
///    6,068 unembedded chunks sat there indefinitely — while the page
///    backlog said everything was done.
pub async fn count_unembedded(db: &sqlx::PgPool) -> Result<i64, String> {
    let sql = sql_unembedded_total(crate::held_column::present(db).await);
    sqlx::query_scalar(sqlx::AssertSqlSafe(&*sql))
    .fetch_one(db)
    .await
    .map_err(|e| format!("unembedded count query failed: {e}"))
}

/// What the knowledge-base embedding backlog (pages + chunks) is doing.
///
/// The backlog is drained by trellion's own `PageIndexEmbedder` loop (a 5s
/// background loop started with the RAG integration, plus an immediate pass
/// on `ingest.doc.parsed`). Nothing here submits work for it any more: the
/// `background_embed` job this used to enqueue went node → controller
/// `/api/memory/embed/start`, which drains CONVERSATION memory
/// (`noo_entries`) — not the pages this count measures — and that drain
/// already has its own location (`unembedded_conversations`). So the job
/// counted one backlog and poked another, and on a queue blocked by a pinned
/// job it was never dispatched at all (2026-10-10: six of them queued for
/// days). What is left worth checking is whether the backlog DRAINS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbedBacklog {
    /// Nothing unembedded.
    Clear,
    /// Work waiting and the trellion add-on (the only embedder) is off.
    NoEmbedder { now: i64 },
    /// First sighting, or the comparison window has not elapsed yet.
    Watching { now: i64, prev: Option<i64> },
    /// Smaller than it was a window ago.
    Draining { prev: i64, now: i64 },
    /// Not smaller than it was at least a window ago.
    Stalled { prev: i64, now: i64, since_secs: i64 },
}

/// Redis key holding the last `(count, unix_secs)` snapshot, shared by the
/// `unembedded_documents` location and the `rag_reindex` heartbeat action so
/// both judge progress over the same window.
pub const EMBED_BACKLOG_SNAPSHOT_KEY: &str = "noo:embed_backlog:snapshot";
/// How long the backlog may sit without shrinking before it is "stalled".
/// An hour: the embedder loop runs every 5s, so a healthy one makes
/// visible progress in minutes; an hour of none is not a slow batch.
pub const EMBED_BACKLOG_STALL_SECS: i64 = 3600;

/// The pure verdict, and the snapshot to store (None = keep the old one).
///
/// The snapshot only moves forward when the window has elapsed and the
/// count went DOWN (or reached zero), so a stall keeps measuring from the
/// last time progress was seen instead of resetting itself every tick.
pub fn embed_backlog_verdict(
    now_count: i64,
    embedder_enabled: bool,
    snapshot: Option<(i64, i64)>,
    now_secs: i64,
    window_secs: i64,
) -> (EmbedBacklog, Option<(i64, i64)>) {
    if now_count <= 0 {
        return (EmbedBacklog::Clear, Some((0, now_secs)));
    }
    if !embedder_enabled {
        return (EmbedBacklog::NoEmbedder { now: now_count }, None);
    }
    let Some((prev, at)) = snapshot else {
        return (EmbedBacklog::Watching { now: now_count, prev: None }, Some((now_count, now_secs)));
    };
    if prev <= 0 {
        // Was clear; new work arrived. Start measuring from here.
        return (EmbedBacklog::Watching { now: now_count, prev: Some(prev) }, Some((now_count, now_secs)));
    }
    let age = now_secs - at;
    if age < window_secs {
        return (EmbedBacklog::Watching { now: now_count, prev: Some(prev) }, None);
    }
    if now_count < prev {
        (EmbedBacklog::Draining { prev, now: now_count }, Some((now_count, now_secs)))
    } else {
        (EmbedBacklog::Stalled { prev, now: now_count, since_secs: age }, None)
    }
}

/// Count the backlog, judge it against the stored snapshot, store the new
/// snapshot. Errors only when the count itself cannot be read.
pub async fn embed_backlog_status(state: &AppState) -> Result<EmbedBacklog, String> {
    let n = count_unembedded(&state.db).await?;
    let now_secs = chrono::Utc::now().timestamp();
    let snapshot = match redis(state) {
        Some(r) => r
            .get_string(EMBED_BACKLOG_SNAPSHOT_KEY)
            .await
            .and_then(|s| serde_json::from_str::<(i64, i64)>(&s).ok()),
        None => None,
    };
    let (verdict, store) = embed_backlog_verdict(
        n,
        crate::addons::trellion_enabled(),
        snapshot,
        now_secs,
        EMBED_BACKLOG_STALL_SECS,
    );
    if let (Some(snap), Some(r)) = (store, redis(state)) {
        if let Ok(v) = serde_json::to_string(&snap) {
            r.set_string(EMBED_BACKLOG_SNAPSHOT_KEY, &v).await;
        }
    }
    Ok(verdict)
}

/// unembedded_documents — alert when the knowledge-base embedding backlog
/// stops draining. It no longer submits anything (see [`EmbedBacklog`]).
///
/// A trellion-less install with a backlog is not alerted here, as before:
/// the disabled add-on is surfaced once in /health, and the `rag_reindex`
/// heartbeat action reports it as a failure on its own cadence.
pub async fn eval_unembedded_documents(state: &AppState) -> Result<bool, String> {
    if !crate::addons::trellion_enabled() {
        return Ok(false);
    }
    match embed_backlog_status(state).await? {
        EmbedBacklog::Stalled { prev, now, since_secs } => {
            tracing::warn!(prev, now, since_secs, "autonomy.unembedded_documents.backlog_stalled");
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.unembedded_documents",
                    "kb",
                    format!(
                        "📚 The knowledge-base embedding backlog is not draining: {now} page(s)/chunk(s) \
                         unembedded, {prev} about {}m ago.",
                        since_secs / 60
                    ),
                )
                .detail("trellion's PageIndexEmbedder loop embeds pages and chunks; check its embedder errors")
                .investigate("noo stack logs trellion"),
                6 * 3600,
            )
            .await;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// unembedded_conversations — conversation memory (`noo_entries`) has
/// entries with no embedding. Embeds ONE bounded batch per evaluation over
/// `worker.memory.batch_index`, so a backlog drains at ~100 entries per
/// interval and a live install keeps up with new turns.
///
/// This location exists because nothing else did it: after the Rust port
/// the only drain path had no caller, and host8 sat at 0 of 1439 entries
/// embedded for three weeks (2026-09-07 → 10-01) while memory search
/// answered "no relevant context". Skipped while an operator-started drain
/// (`noo memory embed`) is running, so the two never race the same rows.
pub async fn eval_unembedded_conversations(state: &AppState) -> Result<bool, String> {
    if !crate::addons::trellion_enabled() {
        return Ok(false); // memory's embedder lives in the trellion add-on
    }
    let unembedded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM noo_entries WHERE embedding IS NULL")
        .fetch_one(&state.db)
        .await
        .map_err(|e| format!("noo_entries count failed: {e}"))?;
    if unembedded == 0 {
        return Ok(false);
    }
    if let Some(redis) = state.redis.as_ref() {
        if redis.get_string("noo:embed:state").await.as_deref() == Some("running") {
            return Ok(false);
        }
    }
    match crate::routes::memory::embed_conversation_batch(state).await {
        Ok(reply) => match crate::routes::memory::drain_step(&reply) {
            crate::routes::memory::DrainStep::Stuck(why) => {
                tracing::warn!(unembedded, error = %why, "autonomy.unembedded_conversations.stuck");
            }
            _ => tracing::info!(
                unembedded,
                embedded = reply.get("embedded").and_then(serde_json::Value::as_i64).unwrap_or(0),
                "autonomy.unembedded_conversations.batch"
            ),
        },
        Err(e) => tracing::warn!(unembedded, error = %e, "autonomy.unembedded_conversations.dispatch_failed"),
    }
    Ok(true)
}

/// missing_graph_entities — fire when entity coverage gap > 5
/// (`page_count - entity_count`). Trellion's PageIndex KG entity table
/// is `entities` (see noo-trellion db/models.py::Entity; the knowledge
/// routes query the same table). An earlier port used the invented name
/// `trellion_kg_entities`, which never existed — entities always read 0
/// and this evaluator fired graph-extraction jobs on a bogus gap.
pub async fn eval_missing_graph_entities(state: &AppState) -> Result<bool, String> {
    if !crate::addons::trellion_enabled() {
        return Ok(false); // no extractor to feed — nothing would drain the job
    }
    const THRESHOLD: i64 = 5;

    // Held documents are never extracted, so their pages are not a gap.
    let pages_sql = format!(
        "SELECT COUNT(*) FROM pages p JOIN docs d ON d.doc_id = p.doc_id WHERE {}",
        crate::held_column::not_held("d", crate::held_column::present(&state.db).await)
    );
    let pages: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(&*pages_sql))
        .fetch_one(&state.db)
        .await
        .map_err(|e| format!("page count query failed: {e}"))?;

    // `entities` may not exist yet (Trellion graph migration applied
    // separately). Defensive: if the query fails, treat entities=0.
    let entities: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entities")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let gap = (pages - entities).max(0);
    let should_fire = gap > THRESHOLD;
    if should_fire {
        if let Some(redis) = state.redis.as_ref() {
            // Dedup guard. The Python producer self-dedups (skips when a
            // background job is already queued), but this Rust path historically
            // did not — so when graph extraction couldn't keep up or dispatch
            // stalled (e.g. the Python scheduler's node registry was empty), it
            // enqueued a fresh `background_graph` job on EVERY tick, piling up
            // thousands of identical jobs (observed: 3729). Claim a short-lived
            // NX slot so at most one is submitted per window regardless of how
            // often this evaluator fires. Background extraction is not
            // time-critical, so a coarse window is fine.
            const DEDUP_KEY: &str = "noo:autonomy:dedup:background_graph";
            const DEDUP_TTL_SECS: i64 = 600; // 10 min
            if !redis.set_nx_ex(DEDUP_KEY, "1", DEDUP_TTL_SECS).await {
                tracing::debug!(entity_gap = gap, "autonomy.missing_graph_entities.dedup_skip");
                return Ok(should_fire);
            }
            tracing::info!(entity_gap = gap, pages, entities, "autonomy.missing_graph_entities.submit_graph_job");
            let payload = serde_json::json!({"scope": "extract", "source": "autonomy"});
            // priority=0 → background lane. Matches Python
            // default_locations.py Action(config={"type":"background_graph","scope":"extract"}).
            let _ = crate::routes::admin::submit_job_to_redis(
                redis, "background_graph", &payload, 0,
                crate::routes::admin::JobOptions::default(),
            ).await;
        }
    }
    Ok(should_fire)
}

// ─── Failure-counter-based MESH evaluators ─────────────────────────────
//
// Several locations need "this condition has held for N consecutive ticks"
// semantics. The Python `AutonomyEngine` kept this in in-process state;
// since Rust's autonomy_loop is the only consumer we keep the counters in
// Redis so they survive gateway restarts.
//
// Key naming: `noo:autonomy:counter:{location}:{subject_id}`
// (e.g. `noo:autonomy:counter:node_offline:node-7`).

const QUARANTINE_THRESHOLD: i64 = 3;
const IDLE_BACKEND_THRESHOLD: i64 = 5; // 5 consecutive low-load ticks (~5min @ 60s)
const IDLE_LOAD_CEILING: f64 = 0.05;

/// Increment a counter and return the new value. Resets to 0 if the
/// `condition_met` flag flips from true→false.
async fn bump_counter(
    state: &AppState,
    key: &str,
    condition_met: bool,
) -> Result<i64, String> {
    let Some(r) = redis(state) else { return Ok(0); };
    if !condition_met {
        r.del_key(key).await;
        return Ok(0);
    }
    let n = r.incr(key).await;
    // Expire after 24h so dead keys don't accumulate.
    r.expire(key, 86400).await;
    Ok(n)
}

/// node_auto_quarantine — fire when any node has been offline (per
/// `is_node_offline`) for >= QUARANTINE_THRESHOLD consecutive autonomy
/// ticks (default 3 ticks × 30s = ~90s of confirmed offline).
///
/// Uses a Redis counter per node so the threshold survives gateway
/// restarts and tracks intermittent flapping.
pub async fn eval_node_auto_quarantine(state: &AppState) -> Result<bool, String> {
    let kv = state
        .js
        .get_key_value("mesh_nodes")
        .await
        .map_err(|e| format!("mesh_nodes KV unavailable: {e}"))?;
    use tokio_stream::StreamExt;
    let keys: Vec<String> = kv
        .keys()
        .await
        .map_err(|e| format!("kv.keys: {e}"))?
        .filter_map(|k| k.ok())
        .collect()
        .await;

    let now = now_unix_secs();
    let mut quarantine_targets: Vec<String> = Vec::new();
    for node_id in keys {
        if node_id == "gateway" {
            continue;
        }
        let counter_key = format!("noo:autonomy:counter:node_offline:{node_id}");
        let Ok(Some(entry)) = kv.get(&node_id).await else { continue };
        let Ok(data) = serde_json::from_slice::<serde_json::Value>(&entry) else { continue };
        let is_offline = is_node_offline(&data, now);
        let n = bump_counter(state, &counter_key, is_offline).await?;
        if n >= QUARANTINE_THRESHOLD {
            quarantine_targets.push(node_id.clone());
        }
    }

    if quarantine_targets.is_empty() {
        return Ok(false);
    }

    // Fire the action: mark each node QUARANTINED in NATS KV. Mirrors
    // Python NodeRegistry.record_heartbeat_failure → status transition.
    for node_id in &quarantine_targets {
        // Compare-and-swap update: re-read the entry with its revision and
        // update only if it hasn't changed since. Without this, a node's
        // heartbeat write (status=online) and this quarantine write race on the
        // same JSON blob and the later write silently clobbers the earlier one
        // (lost update). Retry a few times on revision conflict, then give up
        // for this tick (the next tick re-evaluates).
        for _ in 0..3 {
            let Ok(Some(entry)) = kv.entry(node_id).await else { break };
            let Ok(mut data) = serde_json::from_slice::<serde_json::Value>(&entry.value) else {
                break;
            };
            if data.get("status").and_then(|v| v.as_str()) == Some("quarantined") {
                break; // already quarantined — nothing to do
            }
            // This put resets the entry's TTL, once: the next
            // pass sees `quarantined` and breaks above, so nothing keeps the
            // entry alive and a silent node ages out within one TTL.
            data["status"] = serde_json::json!("quarantined");
            let Ok(bytes) = serde_json::to_vec(&data) else { break };
            match kv.update(node_id, bytes.into(), entry.revision).await {
                Ok(_) => break,
                Err(_) => continue, // revision moved under us — retry with fresh value
            }
        }
        tracing::warn!(node_id = %node_id, "autonomy.node_auto_quarantine.fired");
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.node_auto_quarantine",
                node_id,
                format!(
                    "⛔ Node `{node_id}` quarantined after {QUARANTINE_THRESHOLD} \
                     consecutive offline heartbeat checks. It will not receive \
                     work until re-enabled."
                ),
            )
            .investigate(format!("noo cluster verify {node_id}")),
            21_600,
        )
        .await;
    }
    Ok(true)
}

/// Split a node's running backends into the ones autonomy may stop and the
/// ones it must not, given the fleet's declared placements.
///
/// A backend with `desired_state = 'running'` is DECLARED: the node-agent's
/// reconciler restarts it within a cycle. Stopping one is not a scaledown, it
/// is a flap — and the operator sees a backend bouncing with no explanation.
/// This is why the idle signal alone is not enough to act on, and it is the
/// same set `node_placement_drift` alerts about.
///
/// Pure so it can be tested without a cluster.
fn split_pinned(
    node_id: &str,
    backends: &[String],
    pinned: &std::collections::HashSet<(String, String)>,
) -> (Vec<String>, Vec<String>) {
    backends
        .iter()
        .cloned()
        .partition(|b| !pinned.contains(&(node_id.to_string(), b.clone())))
}

/// backend_idle_scaledown — fire when any node has had load < IDLE_LOAD_CEILING
/// for IDLE_BACKEND_THRESHOLD consecutive ticks AND has running backends.
///
/// The idle signal is the location's OWN condition and nothing more: five
/// consecutive evaluations (≈50 minutes at the default 600s interval) of the
/// node self-reporting under 5% load. It is node-level, not per-backend, which
/// is exactly why the action is conservative — 50 minutes of a node doing
/// essentially nothing is evidence about the whole node, so it is safe to act
/// on for that node's undeclared backends and for nothing else.
///
/// Two guards make the action safe enough to arm:
/// - declared backends are never stopped (see [`split_pinned`]);
/// - the cluster's LAST running backend is never stopped, so an idle mesh
///   scales to one rather than to zero and `backend_availability` does not
///   immediately fight this location over the same box.
///
/// ARMED (`enabled_action: true`): stops each remaining backend through
/// `stop_backend_core`, the same path `noo cluster down` drives, and alerts
/// naming every backend stopped.
///
/// DISARMED (default): the existing alert is unchanged, plus a `would_stop`
/// log line naming exactly what arming would have stopped.
pub async fn eval_backend_idle_scaledown(
    state: &AppState,
    config: &serde_json::Value,
) -> Result<bool, String> {
    let mut targets: Vec<(String, Vec<String>)> = Vec::new(); // (node_id, backend_types)
    let mut total_running: usize = 0;
    for peer in state.gossip.alive_peers() {
        total_running += peer.backends.len();
        if peer.backends.is_empty() {
            continue;
        }
        let counter_key = format!("noo:autonomy:counter:idle_backend:{}", peer.node_id);
        let is_idle = peer.load < IDLE_LOAD_CEILING;
        let n = bump_counter(state, &counter_key, is_idle).await?;
        if n >= IDLE_BACKEND_THRESHOLD {
            targets.push((peer.node_id.clone(), peer.backends.keys().cloned().collect()));
        }
    }

    if targets.is_empty() {
        return Ok(false);
    }

    let pinned: std::collections::HashSet<(String, String)> =
        crate::repo::cluster::placements_desired_running(&state.db)
            .await
            .map_err(|e| format!("placements query: {e}"))?
            .into_iter()
            .collect();

    let armed = action_enabled(config);
    let mut remaining = total_running;

    for (node_id, backends) in &targets {
        let backend_list = backends.join(", ");
        let (stoppable, declared) = split_pinned(node_id, backends, &pinned);
        tracing::info!(
            node_id = %node_id,
            backends = %backend_list,
            declared = %declared.join(", "),
            "autonomy.backend_idle_scaledown.detected"
        );
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.backend_idle_scaledown",
                node_id,
                format!(
                    "💤 Node `{node_id}` has been idle for {IDLE_BACKEND_THRESHOLD} \
                     consecutive checks with running backend(s): {backend_list}."
                ),
            )
            .detail(
                "schedule the `idle_scaledown` heartbeat action (or stop them manually) \
                 to reclaim the resources",
            )
            .investigate(format!("noo cluster show {node_id}")),
            21_600,
        )
        .await;

        for backend in &stoppable {
            // Never take the cluster to zero backends.
            if remaining <= 1 {
                tracing::info!(
                    node_id = %node_id,
                    backend = %backend,
                    "autonomy.backend_idle_scaledown.kept_last_backend"
                );
                break;
            }
            if !armed {
                tracing::warn!(
                    node_id = %node_id,
                    backend = %backend,
                    "autonomy.backend_idle_scaledown.would_stop"
                );
                crate::autonomy_audit::record_would(
                    state,
                    "backend_idle_scaledown",
                    "stop_idle_backends",
                    Some(node_id),
                    &format!(
                        "would stop idle backend `{backend}` on node `{node_id}` \
                         (arm with `enabled_action: true`)"
                    ),
                )
                .await;
                remaining -= 1;
                continue;
            }
            match crate::routes::cluster::stop_backend_core(state, node_id, backend).await {
                Ok(_) => {
                    remaining -= 1;
                    tracing::info!(
                        node_id = %node_id,
                        backend = %backend,
                        "autonomy.backend_idle_scaledown.stopped"
                    );
                    crate::autonomy_audit::record_fired(
                        state,
                        "backend_idle_scaledown",
                        "stop_idle_backends",
                        Some(node_id),
                        &format!("stopped idle backend `{backend}` on node `{node_id}`"),
                    )
                    .await;
                    crate::operator_alert::send_operator_alert_with(
                        state,
                        crate::operator_alert::OperatorAlert::new(
                            "autonomy.backend_scaledown_stopped",
                            &format!("{node_id}:{backend}"),
                            format!(
                                "🛑 Autonomy stopped idle backend `{backend}` on node \
                                 `{node_id}` after {IDLE_BACKEND_THRESHOLD} consecutive idle checks."
                            ),
                        )
                        .detail(format!(
                            "under {IDLE_LOAD_CEILING} load; restart it with \
                             `noo cluster place {node_id} {backend} <model>`; disarm with \
                             `enabled_action: false` on the backend_idle_scaledown location"
                        ))
                        .investigate("noo autonomy audit"),
                        3600,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(
                        node_id = %node_id,
                        backend = %backend,
                        error = %e,
                        "autonomy.backend_idle_scaledown.stop_failed"
                    );
                }
            }
        }
    }
    Ok(true)
}

/// Replica target for `backend_scaling`: `config.replicas`, default 2, clamped
/// to a sane ceiling so a typo cannot ask for a hundred containers.
fn scaling_replicas(config: &serde_json::Value) -> u64 {
    config
        .get("replicas")
        .and_then(|v| v.as_u64())
        .unwrap_or(2)
        .clamp(1, 8)
}

/// backend_scaling — fire when average load across all alive peers exceeds 80%.
/// Ships DISABLED as a location (`autonomy_loop::default_locations`), and its
/// action is gated a second time by `enabled_action`.
///
/// ARMED: brings the busiest backend type up to `config.replicas` (default 2)
/// by starting it on an alive node that is not already running it, one replica
/// per evaluation — deliberately not a burst, so a load spike cannot conjure
/// six containers in one tick.
///
/// DISARMED (default): logs the high load, plus a `would_scale` line naming the
/// backend type, the node it would start on and the replica target.
pub async fn eval_backend_scaling(
    state: &AppState,
    config: &serde_json::Value,
) -> Result<bool, String> {
    let peers = state.gossip.alive_peers();
    if peers.is_empty() {
        return Ok(false);
    }
    let avg_load: f64 = peers.iter().map(|p| p.load).sum::<f64>() / peers.len() as f64;
    if avg_load <= 0.8 {
        return Ok(false);
    }
    tracing::warn!(avg_load, peer_count = peers.len(), "autonomy.backend_scaling.high_load");

    let want = scaling_replicas(config);

    // Which backend type is carrying the load? The one running on the most
    // nodes — scaling anything else would add capacity nobody is asking for.
    let mut counts: HashMap<String, u64> = HashMap::new();
    for peer in &peers {
        for bt in peer.backends.keys() {
            *counts.entry(bt.clone()).or_insert(0) += 1;
        }
    }
    let Some((backend, have)) = counts.into_iter().max_by_key(|(_, n)| *n) else {
        tracing::warn!("autonomy.backend_scaling.no_running_backend_to_scale");
        return Ok(true);
    };
    if have >= want {
        tracing::info!(
            backend = %backend, have, want,
            "autonomy.backend_scaling.already_at_target"
        );
        return Ok(true);
    }

    let already: std::collections::HashSet<&str> = peers
        .iter()
        .filter(|p| p.backends.contains_key(&backend))
        .map(|p| p.node_id.as_str())
        .collect();
    let candidate = crate::routes::admin::all_node_agents(state)
        .await
        .into_iter()
        .map(|(node_id, _url, _hostname)| node_id)
        .find(|node_id| {
            !already.contains(node_id.as_str())
                && crate::routes::cluster::backend_start_cooled_down(node_id, &backend)
        });

    let Some(node_id) = candidate else {
        tracing::warn!(
            backend = %backend, have, want,
            "autonomy.backend_scaling.no_candidate_node"
        );
        return Ok(true);
    };

    if !action_enabled(config) {
        tracing::warn!(
            node_id = %node_id, backend = %backend, have, want, avg_load,
            "autonomy.backend_scaling.would_scale"
        );
        crate::autonomy_audit::record_would(
            state,
            "backend_scaling",
            "scale_backend",
            Some(&node_id),
            &format!(
                "average load {avg_load:.2} over threshold; would scale `{backend}` \
                 from {have} to {want} by starting it on node `{node_id}` \
                 (arm with `enabled_action: true`)"
            ),
        )
        .await;
        return Ok(true);
    }

    match crate::routes::cluster::start_backend_core(state, Some(&node_id), &backend, "").await {
        Ok(result) => {
            tracing::info!(
                node_id = %node_id, backend = %backend, have, want, ?result,
                "autonomy.backend_scaling.scaled"
            );
            crate::autonomy_audit::record_fired(
                state,
                "backend_scaling",
                "scale_backend",
                Some(&node_id),
                &format!(
                    "scaled `{backend}` to replica {} of {want} on node `{node_id}` \
                     (average load {avg_load:.2})",
                    have + 1
                ),
            )
            .await;
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.backend_scaling",
                    &format!("{node_id}:{backend}"),
                    format!(
                        "📈 Autonomy scaled `{backend}` to replica {} of {want} by starting \
                         it on node `{node_id}`.",
                        have + 1
                    ),
                )
                .detail(format!(
                    "average cluster load {avg_load:.2}; stop it with \
                     `noo cluster down {backend} --node {node_id}`; disarm with \
                     `enabled_action: false` on the backend_scaling location"
                ))
                .investigate("noo autonomy audit"),
                3600,
            )
            .await;
        }
        Err(e) => {
            tracing::warn!(
                node_id = %node_id, backend = %backend, error = %e,
                "autonomy.backend_scaling.start_failed"
            );
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.backend_scaling",
                    &format!("{node_id}:{backend}"),
                    format!(
                        "⚠️ Autonomy could not scale `{backend}` onto node `{node_id}` \
                         (average cluster load {avg_load:.2})."
                    ),
                )
                .detail(e.to_string())
                .investigate(format!("noo cluster verify {node_id}")),
                3600,
            )
            .await;
        }
    }
    Ok(true)
}

/// test_suite_health — fire when the latest pytest run reports failures.
/// Reads the same .test-results.json files that
/// `routes/admin.rs::tests_status` reads. No HTTP self-call needed.
pub async fn eval_test_suite_health(state: &AppState) -> Result<bool, String> {
    let candidates = [".test-results.json", "test-results.json", "/data/test-results.json"];
    for path in &candidates {
        let Ok(contents) = tokio::fs::read_to_string(path).await else {
            continue;
        };
        let Ok(data): Result<serde_json::Value, _> = serde_json::from_str(&contents) else {
            continue;
        };
        // pytest-json-report stores `summary.failed` as the failure count.
        let failed = data
            .get("summary")
            .and_then(|s| s.get("failed"))
            .and_then(|v| v.as_i64())
            .or_else(|| data.get("failed").and_then(|v| v.as_i64()))
            .unwrap_or(0);
        if failed > 0 {
            tracing::warn!(failed, path, "autonomy.test_suite_health.regression");
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.test_suite_health",
                    "suite",
                    format!("🧪 Test suite regression: {failed} failing test(s) in the latest results."),
                )
                .detail(format!("results file: {path}"))
                .investigate("noo test run"),
                21_600,
            )
            .await;
            return Ok(true);
        }
        return Ok(false);
    }
    Ok(false) // no results file found — treat as no regression
}

// ─── Companion + cert evaluators (added 2026-04-29) ─────────────────────

/// companion_battery_low — fire when any tier ≥ 5 (companion) node has
/// reported battery_pct < 25.
///
/// Companion telemetry is already stored in NATS KV `mesh_nodes` per
/// `routes/cluster.rs::node_heartbeat` (line ~115 — extracts
/// `battery_pct`/`is_charging`/`thermal_state` from heartbeat body).
/// This evaluator just reads what's already there.
pub async fn eval_companion_battery_low(state: &AppState) -> Result<bool, String> {
    let kv = state
        .js
        .get_key_value("mesh_nodes")
        .await
        .map_err(|e| format!("mesh_nodes KV unavailable: {e}"))?;
    use tokio_stream::StreamExt;
    let keys: Vec<String> = kv
        .keys()
        .await
        .map_err(|e| format!("kv.keys: {e}"))?
        .filter_map(|k| k.ok())
        .collect()
        .await;

    let mut entries: Vec<(String, serde_json::Value)> = Vec::new();
    for key in keys {
        if key == "gateway" {
            continue;
        }
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(data) = serde_json::from_slice::<serde_json::Value>(&entry) else { continue };
        entries.push((key, data));
    }

    let low_battery = low_battery_nodes(&entries);
    if low_battery.is_empty() {
        return Ok(false);
    }
    for (node_id, pct) in &low_battery {
        tracing::warn!(node_id = %node_id, battery_pct = pct, "autonomy.companion_battery_low.alert");
        // Raise it, not just log it: the log line above was the whole
        // response, so a dying companion reached nobody. The funnel dedups
        // per (kind, node) for the cooldown, so a battery that stays low
        // across many 5-minute ticks alerts once per window.
        let (alert, cooldown) = battery_alert(node_id, *pct);
        crate::operator_alert::send_operator_alert_with(state, alert, cooldown).await;
    }
    Ok(true)
}

/// A companion's alert-worthy battery level (percent).
const BATTERY_THRESHOLD: f64 = 25.0;

/// One alert per low companion per window: the cooldown is per (kind, node).
const BATTERY_ALERT_COOLDOWN_SECS: i64 = 6 * 3600;

/// Tier >= 5 nodes reporting under the threshold and not charging.
fn low_battery_nodes(entries: &[(String, serde_json::Value)]) -> Vec<(String, f64)> {
    let mut low = Vec::new();
    for (key, data) in entries {
        let tier = data.get("tier").and_then(|t| t.as_u64()).unwrap_or(0);
        if tier < 5 {
            continue;
        }
        // battery_pct may be int or float depending on how the companion serializes.
        let battery = data
            .get("battery_pct")
            .and_then(|v| v.as_f64())
            .or_else(|| data.get("battery_pct").and_then(|v| v.as_i64()).map(|i| i as f64));
        let Some(pct) = battery else { continue };
        // Skip charging companions — they're not at risk.
        if data.get("is_charging").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        if pct < BATTERY_THRESHOLD {
            low.push((key.clone(), pct));
        }
    }
    low
}

/// The alert for one low companion, and its cooldown. The channel gets a
/// general line, a command and a ref id; the level goes in `detail`
/// (logged under the ref, never sent).
fn battery_alert(node_id: &str, pct: f64) -> (crate::operator_alert::OperatorAlert, i64) {
    (
        crate::operator_alert::OperatorAlert::new(
            "autonomy.companion_battery_low",
            node_id,
            format!("🔋 Companion {node_id} is running low on battery."),
        )
        .detail(format!("battery_pct={pct:.0} (threshold {BATTERY_THRESHOLD:.0}), not charging"))
        .investigate("noo autonomy decisions --location companion_battery_low"),
        BATTERY_ALERT_COOLDOWN_SECS,
    )
}

/// cert_auto_rotate — fire when any leaf cert expires within 30 days,
/// and queue the rotation on the host-watcher spool.
///
/// GATED like every other state-changing action. It previously
/// took no config at all: enabling the LOCATION armed a full
/// backup→rotate→reload→probe→auto-revert cycle across the fleet, with no
/// second opt-in — while starting a single backend needed two. That made the
/// highest-consequence action in the engine the one with the weakest gate,
/// and it sits next to `cert_expiry_check`, whose name does not suggest the
/// difference. An operator enabling this to get expiry visibility would have
/// armed a rotation. A new CA strands every remote agent on "certificate
/// signed by unknown authority", so this is not a recoverable mistake.
///
/// Now: `enabled_action` (default false) and `dry_run` (default true) — the
/// same two-step the disk reclaim uses. Disarmed, it alerts and records what
/// it WOULD rotate. The alert is unconditional either way: expiring certs
/// must be told to the operator whether or not anything is armed.
///
/// Detection logic mirrors `routes/admin.rs::security_pki_status` (PKI
/// directory walk + openssl notAfter check). The old NATS delegation to
/// `worker.security.pki_rotate` claimed "issuance uses the Python
/// cryptography library" — it never did: the Python handler's whole body
/// was the same spool write this now does directly (rotation MUST run
/// host-side; the CA key is 0600 operator-only and the closed
/// backup→rotate→reload→probe→auto-revert loop lives in the watcher).
pub async fn eval_cert_auto_rotate(
    state: &AppState,
    config: &serde_json::Value,
) -> Result<bool, String> {
    const WARN_DAYS: i64 = 30;
    const NEW_CERT_DAYS: i64 = 90;

    let count = count_certs_expiring_within(WARN_DAYS).await;
    if count == 0 {
        return Ok(false);
    }

    // Two opt-ins, both defaulting to the safe side, read through the same
    // fail-closed helpers the reclaim gate uses: a `"true"` STRING in a
    // hand-edited YAML arms nothing.
    let armed = action_enabled(config);
    let dry_run = config
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if !armed || dry_run {
        let why = if !armed {
            "disarmed (`enabled_action: false`)"
        } else {
            "dry run (`dry_run: true`)"
        };
        tracing::warn!(count, armed, dry_run, "autonomy.cert_auto_rotate.would_rotate");
        crate::autonomy_audit::record(
            state,
            crate::autonomy_audit::Decision {
                location: "cert_auto_rotate",
                action: "rotate_expiring_certs",
                outcome: crate::autonomy_audit::Outcome::Would,
                target: Some("pki"),
                detail: &format!(
                    "{count} cert(s) expire within {WARN_DAYS} days; would queue a \
                     host-side rotation ({NEW_CERT_DAYS}-day renewals) — not queued: {why}"
                ),
                armed: Some(armed),
                dry_run: Some(dry_run),
                metrics: None,
            },
        )
        .await;
        // Alert regardless: the CONDITION is what the operator needs to know.
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.cert_auto_rotate.would_rotate",
                "pki",
                format!(
                    "🔐 {count} cluster certificate(s) expire within {WARN_DAYS} days and \
                     auto-rotation is off — nothing was rotated."
                ),
            )
            .detail(format!(
                "auto-rotation is {why}. Rotate now with `noo security pki rotate-all`, or \
                 arm it with `enabled_action: true` AND `dry_run: false` on the \
                 cert_auto_rotate location"
            ))
            .investigate("noo security pki status"),
            86_400,
        )
        .await;
        return Ok(true);
    }

    tracing::warn!(count, "autonomy.cert_auto_rotate.fired");

    match crate::routes::admin::host_spool_write_command(
        "rotate",
        "pki",
        &[],
        "autonomy_cert_auto_rotate",
    )
    .await
    {
        Some(_path) => {
            crate::autonomy_audit::record_fired(
                state,
                "cert_auto_rotate",
                "rotate_expiring_certs",
                Some("pki"),
                &format!(
                    "queued a host-side rotation for {count} cert(s) expiring within \
                     {WARN_DAYS} days ({NEW_CERT_DAYS}-day renewals)"
                ),
            )
            .await;
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.cert_auto_rotate",
                    "pki",
                    format!(
                        "🔐 {count} cluster certificate(s) expire within {WARN_DAYS} days; \
                         a host-side rotation is queued."
                    ),
                )
                .detail(format!(
                    "{NEW_CERT_DAYS}-day renewals; backup→rotate→reload→probe→auto-revert"
                ))
                .investigate("noo security pki status"),
                86_400,
            )
            .await;
        }
        None => {
            let e = "host spool unavailable — is noo-hostd running? (systemctl --user status noo-hostd)";
            tracing::warn!(error = %e, "autonomy.cert_auto_rotate.dispatch_failed");
            // Condition was met even though the action failed — tell the
            // operator, since expiring certs with a broken rotation path
            // is exactly the failure that must not stay log-only.
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.cert_auto_rotate.dispatch_failed",
                    "pki",
                    format!(
                        "🔐❗ {count} cluster certificate(s) expire within {WARN_DAYS} days \
                         and the automatic rotation could not be queued."
                    ),
                )
                .detail(format!("{e}; run `noo security pki rotate-all` manually"))
                .investigate("noo security pki status"),
                21_600,
            )
            .await;
        }
    }
    Ok(true)
}

/// Count cluster TLS certs (CA + gateway + per-node leaf) that expire
/// within `days_threshold`. Walks the same PKI directory layout that
/// `routes/admin.rs::security_pki_status` reads. Shared between
/// `eval_cert_expiry_check` (in autonomy_loop.rs) and
/// `eval_cert_auto_rotate` (above) — both fire on the same condition,
/// they just take different actions (alert vs rotate).
///
/// Returns 0 if the PKI directory is missing (gateway not yet onboarded).
pub async fn count_certs_expiring_within(days_threshold: i64) -> usize {
    let pki_dir = std::env::var("NOO_PKI_DIR")
        .ok()
        .filter(|p| std::path::Path::new(p).join("ca.crt").exists())
        .or_else(|| {
            ["/tmp/pki", "/app/pki"]
                .iter()
                .find(|p| std::path::Path::new(p).join("ca.crt").exists())
                .map(|p| p.to_string())
        })
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            format!("{home}/.config/mesh/pki")
        });

    let pki_path = std::path::Path::new(&pki_dir);
    if !pki_path.exists() {
        return 0;
    }

    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    let ca = pki_path.join("ca.crt");
    if ca.exists() {
        paths.push(ca);
    }
    let gw = pki_path.join("gateway").join("gateway.crt");
    if gw.exists() {
        paths.push(gw);
    }
    let nodes_dir = pki_path.join("nodes");
    if nodes_dir.exists() {
        if let Ok(mut rd) = tokio::fs::read_dir(&nodes_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let node_cert = entry.path().join("node.crt");
                if node_cert.exists() {
                    paths.push(node_cert);
                }
            }
        }
    }

    // `notAfter` is read with cert_expiry::read_not_after (x509-cert), NOT by
    // shelling out to `openssl x509 -noout -enddate`.
    //
    // Two reasons, and the second is the one that mattered:
    //
    // 1. It was a SECOND implementation of a thing this codebase already
    //    does. cert_expiry.rs parses the same field off the same files for
    //    the cert_expiry_check / cert_auto_rotate heartbeat actions. Two
    //    readers of one value is the failure shape this repo keeps paying
    //    for — and here they did not even agree on the sad path: the
    //    subprocess treated an unparseable date as "not expiring", silently,
    //    with no way to tell that apart from a healthy cert.
    //
    // 2. It was the LAST subprocess in the binary (`Command::new` appears
    //    nowhere else), and therefore the last reason the runtime image
    //    needed a shell and a package manager. Dropping it is what lets the
    //    gateway move to the shell-less hardened base.
    let now = chrono::Utc::now().timestamp();
    let cutoff = (chrono::Utc::now() + chrono::Duration::days(days_threshold)).timestamp();
    let mut expiring = 0usize;
    for path in paths {
        // None = unreadable or unparseable. Same outcome as the subprocess's
        // non-zero exit, but now it is one code path instead of three.
        let Some(not_after) = crate::cert_expiry::read_not_after(&path) else {
            continue;
        };
        if not_after > now && not_after < cutoff {
            expiring += 1;
        }
    }
    expiring
}

// ─── worker_node_agent_unreachable ───────────────────────────────────────
//
// A worker we had a live relationship with (DB row says status='online'
// AND ip_address known) stops heartbeating. Until 2026-09-11 this queued a
// pre-approved `revive_node` proposal that the `cluster-executor` sidecar
// picked up and acted on by SSH-ing into the box as the operator and
// restarting the agent.
//
// That lane is GONE (track E,: the controller holds no SSH key,
// no container mounts ~/.ssh, and nothing polls noo_cluster_proposals any
// more. There is no rail replacement and there cannot be one — every rail
// the mesh has (dispatch, artifact pull, provisioning bundles) is
// COLLECTED BY THE NODE-AGENT, and the node-agent is precisely what is
// down. A "self-heal" that writes a row nothing will ever execute is the
// silent-success pattern this repo keeps paying for, so this evaluator now
// does the only honest thing: it tells the operator, with the exact
// command, and it keeps telling them on a widening cadence until the node
// comes back.
//
// Backoff: per-node Redis key holds the next-alert epoch, widening
// 60s → 5m → 15m → 1h so a long outage nags once an hour rather than once
// a minute. On recovery the heartbeat path calls `clear_revive_backoff`
// and the next outage starts at 60s again.

const REVIVE_STALE_SECS: i64 = 120; // last_heartbeat older than this → stale
const REVIVE_BACKOFF_INITIAL_SECS: i64 = 60;
const REVIVE_BACKOFF_MAX_SECS: i64 = 3600;
const REVIVE_BACKOFF_MULTIPLIER: i64 = 5;

/// The literal command an operator runs ON the node to bring its agent
/// back. Shared by both autonomy alerts that name a down agent (stale
/// heartbeat, failed dispatch-consumer restart) so the two can never drift
/// into telling different stories.
pub fn node_agent_revive_instructions(node_id: &str) -> String {
    format!(
        "On `{node_id}` — the controller cannot reach in, \
         so this is a hands-on-the-node step:\n\
         \n\
         ```\n\
         sudo systemctl restart noo-node-agent\n\
         systemctl is-active noo-node-agent\n\
         journalctl -u noo-node-agent -n 50 --no-pager\n\
         ```\n\
         \n\
         If the box itself is unreachable, power/network comes first. \
         There is no remote revive: the controller→node SSH lane was \
         removed 2026-09-11 and every mesh rail runs THROUGH the agent \
         that is down."
    )
}

/// worker_node_agent_unreachable — for each worker that's stale-online
/// (in DB as online but no recent heartbeat), raise an operator alert
/// carrying the manual revive command. Returns Ok(true) if at least one
/// alert fired this tick.
pub async fn eval_worker_node_agent_unreachable(state: &AppState) -> Result<bool, String> {
    // 1. Find stale-online nodes. Exclude ourselves — the controller's own
    //    agent is restarted by the operator who is already on this box,
    //    and an alert about the machine you are standing on is noise.
    let my_node_id = crate::self_node::self_node_id().unwrap_or_default();
    let rows = crate::repo::cluster::stale_online_nodes(
        &state.db,
        REVIVE_STALE_SECS,
        &my_node_id,
    )
    .await
    .map_err(|e| format!("stale node query failed: {e}"))?;

    if rows.is_empty() {
        return Ok(false);
    }

    let now = now_unix_secs() as i64;
    let mut dispatched = 0usize;

    for (node_id, ip_address, hostname) in rows {
        // 2. Backoff check — skip if we already alerted recently.
        let key = format!("noo:revive:{node_id}:next_attempt");
        let backoff_key = format!("noo:revive:{node_id}:backoff_secs");
        if let Some(r) = redis(state) {
            if let Some(s) = r.get_string(&key).await {
                if let Ok(next) = s.parse::<i64>() {
                    if now < next {
                        continue;
                    }
                }
            }
        }

        let cur_backoff: i64 = match redis(state) {
            Some(r) => r.get_string(&backoff_key).await
                .and_then(|s| s.parse().ok())
                .unwrap_or(REVIVE_BACKOFF_INITIAL_SECS),
            None => REVIVE_BACKOFF_INITIAL_SECS,
        };

        // 3. Tell the operator. The alert funnel's own cooldown is set to
        //    the current backoff so the two dedup windows agree.
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "cluster.node_agent_unreachable",
                &node_id,
                format!(
                    "🔌 Node `{node_id}` has not heartbeated for over \
                     {REVIVE_STALE_SECS}s. Its jobs will strand until the agent \
                     is back.\n\n{}",
                    node_agent_revive_instructions(&node_id)
                ),
            )
            // Hostname and address are for the log: an operator on the
            // node does not need them, and a channel must not carry them.
            .detail(format!("hostname={hostname} ip={ip_address}"))
            .investigate(format!("noo cluster verify {node_id}")),
            cur_backoff.max(REVIVE_BACKOFF_INITIAL_SECS),
        ).await;

        dispatched += 1;
        tracing::warn!(node = %node_id, ip = %ip_address,
                       "autonomy.node_agent_unreachable.alerted");

        // 4. Update backoff state — exponential, capped at 1h.
        if let Some(r) = redis(state) {
            let next_backoff =
                (cur_backoff.saturating_mul(REVIVE_BACKOFF_MULTIPLIER)).min(REVIVE_BACKOFF_MAX_SECS);
            let next_attempt = now + cur_backoff;
            r.set_string(&key, &next_attempt.to_string()).await;
            r.expire(&key, cur_backoff + 60).await;
            r.set_string(&backoff_key, &next_backoff.to_string()).await;
            r.expire(&backoff_key, REVIVE_BACKOFF_MAX_SECS * 2).await;
        }
    }

    Ok(dispatched > 0)
}

/// Called by the heartbeat handler (or any path that observes a node
/// successfully heartbeating) to clear its revive backoff state. Lets
/// the next outage start at the initial 60s backoff instead of inheriting
/// the previous outage's exponential decay.
///
/// No-op if Redis is unavailable.
pub async fn clear_revive_backoff(state: &AppState, node_id: &str) {
    if let Some(r) = redis(state) {
        let _ = r.set_string(&format!("noo:revive:{node_id}:next_attempt"), "0").await;
        let _ = r.set_string(&format!("noo:revive:{node_id}:backoff_secs"), "60").await;
    }
}

// ─── node_dispatch_health ────────────────────────────────────────────────
//
// The heartbeat path cannot see two failure classes (both observed
// 2026-07-03 while validating the /mcp/user harness contract):
//
//  (a) A node-agent that gossips/heartbeats fine but whose JetStream
//      dispatch consumer is UNBOUND — host9's `node_host9_dispatch`
//      sat push_bound=None after a server-side stream recreation, so
//      every job dispatched to it stranded until the janitor requeued.
//      Self-heal: ask the agent to restart ITSELF over the agent rail
//      (POST /restart — the node is up, only its durable is not), whose
//      startup Subscribe() re-binds it. If the rail call fails we say so
//      and hand the operator the manual command; there is no SSH lane
//      behind it any more.
//
//  (b) A backend advertised in mesh_nodes that refuses connections at
//      the cluster contract port — host8's llamacpp image drift left
//      llama-server on :8080 while everything dials :8085, and the
//      container healthcheck (which probes the same wrong port) stayed
//      green. Detection: probe through the node-agent inference proxy
//      with a deliberately-invalid tiny request; only a
//      `backend_unreachable` proxy error (or dial failure past a live
//      agent) means the backend is dark. Alert only. The hint follows the
//      CLASS of failure (`classify_backend_failure`): a refused port can be
//      image/env drift and wants a recreate, but a DNS or TLS failure is the
//      agent's door to the backend and a recreate cannot fix it — the first
//      version of this alert prescribed a recreate for everything.

const DISPATCH_UNBOUND_GRACE_SECS: i64 = 120;
const DISPATCH_REVIVE_COOLDOWN_SECS: i64 = 1800; // max one revive per node per 30 min
const BACKEND_UNREACHABLE_ALERT_COOLDOWN_SECS: i64 = 21_600; // 6h, matches revive_stuck

/// node_dispatch_health — verify each ALIVE node can actually receive
/// and serve work (consumer bound + advertised backends reachable).
/// Returns Ok(true) if any revive was queued or alert sent.
pub async fn eval_node_dispatch_health(state: &AppState) -> Result<bool, String> {
    let kv = state.js.get_key_value("mesh_nodes")
        .await
        .map_err(|e| format!("mesh_nodes KV unavailable: {e}"))?;
    use tokio_stream::StreamExt;
    let keys: Vec<String> = kv.keys().await
        .map_err(|e| format!("kv.keys: {e}"))?
        .filter_map(|k| k.ok())
        .collect()
        .await;

    let my_node_id = crate::self_node::self_node_id().unwrap_or_default();
    let now = now_unix_secs();
    let mut fired = false;

    let tasks_stream = state.js.get_stream("TASKS").await.ok();

    for node_id in keys {
        if node_id == "gateway" { continue; }
        let Ok(Some(entry)) = kv.get(&node_id).await else { continue };
        let Ok(data) = serde_json::from_slice::<serde_json::Value>(&entry) else { continue };

        // Offline nodes are worker_node_agent_unreachable's problem —
        // this evaluator is specifically for nodes that LOOK healthy.
        if is_node_offline(&data, now) { continue; }

        // ── (a) dispatch consumer bound? ────────────────────────────
        if let Some(stream) = tasks_stream.as_ref() {
            let consumer_name = format!("node_{node_id}_dispatch");
            let bound = match stream.consumer_info(&consumer_name).await {
                Ok(info) => info.push_bound,
                // Consumer missing entirely = agent never subscribed
                // (crashed before Subscribe, or JetStream state lost).
                // A restart recreates it, so treat like unbound.
                Err(_) => false,
            };

            let since_key = format!("noo:dispatch_unbound:{node_id}:since");
            if bound {
                if let Some(r) = redis(state) {
                    let _ = r.set_string(&since_key, "").await;
                }
            } else {
                // Grace window so agent restarts don't false-positive:
                // only act once unbound has persisted across evals.
                let first_seen: i64 = match redis(state) {
                    Some(r) => match r.get_string(&since_key).await
                        .and_then(|s| s.parse::<i64>().ok())
                    {
                        Some(t) if t > 0 => t,
                        _ => {
                            let _ = r.set_string(&since_key, &(now as i64).to_string()).await;
                            now as i64
                        }
                    },
                    // No Redis → no grace tracking; act immediately
                    // rather than never.
                    None => 0,
                };

                if (now as i64) - first_seen >= DISPATCH_UNBOUND_GRACE_SECS {
                    fired |= revive_for_unbound_consumer(
                        state, &node_id, &data, &my_node_id, now as i64,
                    ).await;
                }
            }
        }

        // ── (b) advertised inference backends reachable? ────────────
        let Some(backends) = data.get("running_backends").and_then(|v| v.as_object()) else { continue };
        for (backend_type, _info) in backends {
            if !matches!(backend_type.as_str(), "vllm" | "llamacpp" | "ollama") {
                continue; // embedding/reranker have their own mesh routing
            }
            match probe_backend_via_agent(state, &node_id, backend_type).await {
                BackendProbe::Unreachable(detail) => {
                    tracing::warn!(node = %node_id, backend = %backend_type,
                                   detail = %detail,
                                   "autonomy.node_dispatch_health.backend_unreachable");
                    let outcome = crate::operator_alert::send_operator_alert_with(
                        state,
                        backend_unreachable_alert(&node_id, backend_type, &detail),
                        BACKEND_UNREACHABLE_ALERT_COOLDOWN_SECS,
                    ).await;
                    let _ = outcome;
                    fired = true;
                }
                BackendProbe::Reachable | BackendProbe::AgentUnreachable => {}
            }
        }
    }

    Ok(fired)
}

/// Queue a revive proposal for a node whose dispatch consumer is unbound.
/// Own cooldown keys (NOT noo:revive:*) — those are reset every time the
/// node heartbeats, which an unbound-but-alive node does constantly.
async fn revive_for_unbound_consumer(
    state: &AppState,
    node_id: &str,
    data: &serde_json::Value,
    my_node_id: &str,
    now: i64,
) -> bool {
    // Controller: the operator is already on this box; just say so.
    if !my_node_id.is_empty() && node_id == my_node_id {
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.dispatch_consumer_unbound",
                node_id,
                format!(
                    "🧵 Controller node `{node_id}`'s job dispatch consumer is \
                     unbound — jobs routed to it will strand."
                ),
            )
            .detail("restart the local noo-node-agent to re-bind the durable")
            .investigate(format!("noo cluster verify {node_id}")),
            DISPATCH_REVIVE_COOLDOWN_SECS,
        ).await;
        return true;
    }

    let cooldown_key = format!("noo:dispatch_unbound:{node_id}:next_revive");
    if let Some(r) = redis(state) {
        if let Some(s) = r.get_string(&cooldown_key).await {
            if let Ok(next) = s.parse::<i64>() {
                if now < next { return false; }
            }
        }
    }

    let ip_address = data.get("ip_address").and_then(|v| v.as_str()).unwrap_or("");
    let hostname = data.get("hostname").and_then(|v| v.as_str()).unwrap_or(node_id);

    // THE RAIL, not SSH. This node heartbeats — its agent is answering —
    // so the agent can be told to restart itself over its own HTTP
    // endpoint, and its startup Subscribe() re-binds the durable. Before
    // 2026-09-11 this queued a `revive_node` proposal for the
    // cluster-executor to SSH in and force-recreate the container; the
    // executor and the whole SSH lane are gone, and the rail was always
    // the better answer for a node that is up.
    let outcome = crate::routes::cluster::restart_agent_via_rail(state, node_id).await;

    if let Some(r) = redis(state) {
        let _ = r.set_string(&cooldown_key,
                             &(now + DISPATCH_REVIVE_COOLDOWN_SECS).to_string()).await;
    }

    match outcome {
        Ok(()) => {
            tracing::warn!(node = %node_id,
                           "autonomy.node_dispatch_health.agent_restart_requested");
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.dispatch_consumer_unbound",
                    node_id,
                    format!(
                        "🧵 Node `{node_id}` heartbeats fine but its job dispatch \
                         consumer was unbound; its agent was asked to restart and re-bind."
                    ),
                )
                .detail("restart requested over the agent rail")
                .investigate(format!("noo cluster verify {node_id}")),
                DISPATCH_REVIVE_COOLDOWN_SECS,
            ).await;
            true
        }
        Err(e) => {
            // Fail LOUD. The old code could not distinguish "queued" from
            // "will ever run"; this one knows the restart did not happen,
            // so it says so and hands over the manual step.
            tracing::warn!(node = %node_id, error = %e,
                           "autonomy.node_dispatch_health.agent_restart_failed");
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "autonomy.dispatch_consumer_unbound",
                    node_id,
                    format!(
                        "🧵 Node `{node_id}` has an unbound job dispatch consumer \
                         and the agent-rail restart FAILED.\n\n{}",
                        node_agent_revive_instructions(node_id)
                    ),
                )
                .detail(format!("hostname={hostname} ip={ip_address} error={e}"))
                .investigate(format!("noo cluster verify {node_id}")),
                DISPATCH_REVIVE_COOLDOWN_SECS,
            ).await;
            false
        }
    }
}

/// Why the node agent could not reach a backend, read from the proxy's
/// structured error. The class picks the hint: the old alert told the
/// operator to recreate the container for EVERY failure, including a DNS
/// lookup failure no recreate can fix (2026-09-29, a `lookup … no such
/// host` from the node agent on host3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendFailure {
    /// The agent could not resolve the backend's address (DNS).
    Resolve,
    /// Nothing listening at the contract port.
    Refused,
    /// TLS handshake failed (untrusted CA, expired or wrong-name cert).
    Tls,
    /// The dial or the answer timed out.
    Timeout,
    /// No route / network unreachable.
    Network,
    /// The backend answered, but with an HTTP error the proxy reported.
    Http,
    /// Anything else.
    Other,
}

/// Classify the proxy's error body. Reads the JSON `error.message` when
/// there is one, else the raw text; matches on the Go net error phrases the
/// node agent's proxy passes through.
pub(crate) fn classify_backend_failure(body: &str) -> BackendFailure {
    let msg = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/message")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.to_string())
        .to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| msg.contains(n));
    if has(&["no such host", "lookup ", "server misbehaving", "name resolution", "name or service not known"]) {
        BackendFailure::Resolve
    } else if has(&["tls:", "x509", "certificate", "handshake", "unknown ca", "unknownissuer"]) {
        BackendFailure::Tls
    } else if has(&["connection refused"]) {
        BackendFailure::Refused
    } else if has(&["timeout", "timed out", "deadline exceeded"]) {
        BackendFailure::Timeout
    } else if has(&["no route to host", "network is unreachable", "host is unreachable"]) {
        BackendFailure::Network
    } else if has(&["status code", "http error", "bad gateway", "returned 5", "returned 4"]) {
        BackendFailure::Http
    } else {
        BackendFailure::Other
    }
}

/// The structured alert for an advertised backend the node agent cannot
/// reach. Channel text: the node, the backend, the class in plain words,
/// one command. The proxy's raw body is `detail` — logged, never sent.
pub(crate) fn backend_unreachable_alert(
    node_id: &str,
    backend: &str,
    detail: &str,
) -> crate::operator_alert::OperatorAlert {
    let class = classify_backend_failure(detail);
    let why = match class {
        BackendFailure::Resolve => {
            "the node agent cannot resolve the backend's address \u{2014} its door to the \
             backend is broken, not the model, so recreating the backend will not help"
        }
        BackendFailure::Refused => {
            "nothing is listening where the node agent expects it \u{2014} the backend is \
             stopped, still loading, or serving on a different port than its contract"
        }
        BackendFailure::Tls => {
            "the TLS handshake between the node agent and the backend failed \
             (certificate not trusted, expired, or naming something else)"
        }
        BackendFailure::Timeout => {
            "the backend did not answer the node agent in time \u{2014} overloaded, wedged, \
             or still loading"
        }
        BackendFailure::Network => "the node agent has no network path to the backend",
        BackendFailure::Http => "the backend answered the node agent with an error",
        BackendFailure::Other => "the node agent could not reach it",
    };
    let investigate = match class {
        BackendFailure::Timeout | BackendFailure::Http => {
            format!("noo logs search --node {node_id} --name {backend} --since 1h")
        }
        _ => format!("noo cluster verify {node_id}"),
    };
    crate::operator_alert::OperatorAlert::new(
        "autonomy.backend_unreachable",
        &format!("{node_id}:{backend}"),
        format!(
            "\u{1F50C} Backend `{backend}` on `{node_id}` is advertised in the mesh, but {why}."
        ),
    )
    .detail(format!("class={class:?} proxy_error={detail}"))
    .investigate(investigate)
}

#[cfg(test)]
mod backend_unreachable_alert_tests {
    use super::*;

    const FORBIDDEN: &[&str] = &[
        "noo-vllm", "100.100.100.100", "172.18.", ":8000", "dial tcp", "{\"error\"",
        "/app/", "NOO_",
    ];

    /// The proxy body behind the alert that reached Google Chat, 2026-09-29.
    const REAL_DNS: &str = r#"{"error":{"code":"backend_unreachable","message":"dial tcp: lookup noo-vllm on 100.100.100.100:53: no such host","type":"node_agent_proxy_error"}}"#;

    fn render(detail: &str) -> (BackendFailure, String, crate::operator_alert::OperatorAlert) {
        let a = backend_unreachable_alert("host3", "vllm", detail);
        let text = crate::egress::system(&a, "ref-1234567890").into_string();
        (classify_backend_failure(detail), text, a)
    }

    #[test]
    fn the_real_alert_is_a_dns_failure_and_says_so_without_internals() {
        let (class, text, a) = render(REAL_DNS);
        assert_eq!(class, BackendFailure::Resolve);
        for f in FORBIDDEN {
            assert!(!text.contains(f), "`{f}` reached the channel:\n{text}");
        }
        assert!(text.contains("`host3`") && text.contains("`vllm`"), "{text}");
        assert!(text.contains("noo cluster verify host3"), "{text}");
        // The old hint prescribed a recreate for a DNS failure.
        assert!(!text.contains("restart --force"), "{text}");
        assert!(text.contains("will not help"), "{text}");
        // And the evidence is kept — for the log.
        assert!(a.detail.contains("noo-vllm on 100.100.100.100:53"), "{}", a.detail);
    }

    #[test]
    fn each_failure_class_gets_its_own_hint_and_no_internals() {
        let cases: &[(&str, BackendFailure)] = &[
            (r#"{"error":{"code":"backend_unreachable","message":"dial tcp 172.18.0.2:8000: connect: connection refused","type":"node_agent_proxy_error"}}"#, BackendFailure::Refused),
            (r#"{"error":{"code":"backend_unreachable","message":"remote error: tls: unknown ca","type":"node_agent_proxy_error"}}"#, BackendFailure::Tls),
            (r#"{"error":{"code":"backend_unreachable","message":"dial tcp 100.64.0.11:8000: i/o timeout","type":"node_agent_proxy_error"}}"#, BackendFailure::Timeout),
            (r#"{"error":{"code":"backend_unreachable","message":"dial tcp 172.18.0.9:8000: connect: no route to host","type":"node_agent_proxy_error"}}"#, BackendFailure::Network),
            ("not json at all: /app/bin/proxy crashed", BackendFailure::Other),
        ];
        let mut hints = std::collections::HashSet::new();
        for (body, want) in cases {
            let (class, text, _) = render(body);
            assert_eq!(class, *want, "{body}");
            for f in FORBIDDEN {
                assert!(!text.contains(f), "`{f}` reached the channel for {want:?}:\n{text}");
            }
            assert!(text.contains("host3") && text.contains("vllm"));
            assert!(text.contains("Next: `noo "), "{text}");
            hints.insert(text.lines().next().unwrap_or_default().to_string());
        }
        assert_eq!(hints.len(), cases.len(), "two classes share a hint: {hints:?}");
    }
}

enum BackendProbe {
    Reachable,
    Unreachable(String),
    /// Node-agent itself didn't answer — not this evaluator's concern.
    AgentUnreachable,
}

/// Probe one backend through the node-agent inference proxy.
///
/// The body is deliberately invalid — `messages` omitted — so a REACHABLE
/// backend rejects it at validation in milliseconds without running
/// inference. Only a dial failure surfaces as the proxy's
/// `backend_unreachable` error; any other status proves the dial worked.
///
/// Why `{"model": ""}` and not `{"model": "", "messages": []}` (measured
/// on the live cluster, 2026-07-30):
///
///   body                          llama.cpp                vLLM
///   {"model":"","messages":[]}    500 + Jinja stack trace  400 one-liner
///   {"model":""}                  400 'messages' required  400 + field dump
///
/// Neither is quieter on both — an empty array passes validation and dies
/// inside gemma's chat template on llama.cpp, while omitting the key trips
/// vLLM's more verbose Pydantic error. The tiebreak is that a deliberately
/// invalid probe must never produce a 5xx: 500 means "server fault", and
/// this is a client-side bad request by construction. Uniform 4xx keeps
/// the probe from looking like — or tripping alerting for — a real
/// backend failure. llama.cpp logged that 500 with a template stack trace
/// every 5 minutes, which is indistinguishable from a genuinely broken
/// model.
///
/// Ollama is unverified (none running at the time of measurement); it
/// returns 4xx for both shapes as far as the API contract goes.
async fn probe_backend_via_agent(
    state: &AppState,
    node_id: &str,
    backend_type: &str,
) -> BackendProbe {
    let link = match crate::node_link::NodeLink::for_node(state, node_id).await {
        Ok(l) => l,
        Err(_) => return BackendProbe::AgentUnreachable,
    };
    let req = link
        .request(reqwest::Method::POST, "/v1/chat/completions")
        .header("X-Noo-Backend", backend_type)
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .json(&json!({"model": ""}));

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status == 502 && body.contains("backend_unreachable") {
                // The raw body is evidence for the LOG (it rides as the
                // alert's `detail`), never text for a channel.
                let detail = body.chars().take(500).collect::<String>();
                BackendProbe::Unreachable(detail)
            } else {
                // Any other answer (400 bad request, 200, backend error
                // JSON…) proves the dial from agent → backend worked.
                BackendProbe::Reachable
            }
        }
        // Couldn't reach the node-agent at all — offline/agent problems
        // belong to node_health / worker_node_agent_unreachable.
        Err(_) => BackendProbe::AgentUnreachable,
    }
}

/// gpu_health — a node that CLAIMS a GPU must be able to USE it.
///
/// The gap this closes, measured before it existed: host8 served its
/// embedding workload CPU-only for over two weeks with an RTX 3060 in
/// `cluster_nodes`, because every existing signal answers a different
/// question. `gpu_model` is populated (detected back when the card worked
/// and persisted), node_health only tests liveness (the agent heartbeats
/// fine), and llama.cpp degrades to CPU with a warning in its own log
/// rather than refusing. The recurrence is hardware (Xid 79 — the GPU
/// falls off the PCIe bus and the driver demands a reboot), so this WILL
/// happen again; the cluster's job is to notice in minutes, not weeks.
///
/// Probe: node-agent's `GET /gpu` runs nvidia-smi live and answers
/// `{"available": false}` on a wedged card — exactly the fact we need,
/// already served over the authenticated API.
///
/// Deliberately NOT auto-remediated: recovery is a kernel-module reload or
/// a reboot (Xid 154 says which), neither of which belongs in an unattended
/// loop against a node that may be mid-inference. Alert only.
///
/// Scope discipline: an unreachable AGENT is node_health's finding, not
/// ours — this evaluator skips those nodes rather than double-alerting.
pub async fn eval_gpu_health(state: &AppState) -> Result<bool, String> {
    // The registry row is the CLAIM being audited, so read it from the DB
    // rather than the mesh KV: gpu_model is what placement decisions see.
    let claimants: Vec<(String, String)> = sqlx::query_as(
        "SELECT node_id, COALESCE(gpu_model,'') FROM cluster_nodes          WHERE COALESCE(gpu_model,'') <> '' AND status = 'online'",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("cluster_nodes: {e}"))?;

    let mut wedged: Vec<String> = Vec::new();
    let mut container_faults: Vec<String> = Vec::new();
    for (node_id, gpu_model) in claimants {
        let Ok(link) = crate::node_link::NodeLink::for_node(state, &node_id).await
        else {
            continue; // no address on record — nothing to probe
        };
        let req = link
            .request(reqwest::Method::GET, "/gpu")
            .timeout(std::time::Duration::from_secs(10));
        let Ok(resp) = req.send().await else {
            continue; // agent unreachable → node_health's finding
        };
        let Ok(body) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        if gpu_probe_says_unavailable(&body) {
            tracing::warn!(
                node_id = %node_id,
                gpu_model = %gpu_model,
                "autonomy.gpu_health.wedged"
            );
            wedged.push(format!("{node_id} (claims {gpu_model})"));
        }
        // the agent-side GPU watchdog escalates a container that
        // still cannot see the GPU after a restart. That is the SOFT class
        // the wedge probe is blind to — host card fine, container's grant
        // broken. Agents predating the watchdog omit the field entirely.
        for fault in gpu_watchdog_faults(&body) {
            tracing::warn!(node_id = %node_id, fault = %fault, "autonomy.gpu_health.container_fault");
            container_faults.push(format!("{node_id}: {fault}"));
        }
    }

    if !container_faults.is_empty() {
        // Name the NODES; the per-container fault lines (container names,
        // device paths) are evidence for the log.
        let mut fault_nodes: Vec<&str> = container_faults
            .iter()
            .filter_map(|f| f.split(':').next())
            .collect();
        fault_nodes.dedup();
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.gpu_container_fault",
                "cluster",
                format!(
                    "🎮 GPU watchdog: {n} container(s) on {nodes} request a GPU they \
                     cannot reach, and one restart did not heal it. The host card \
                     itself probes fine — check the container's device grant (was it \
                     started before the driver?) and the agent journal on the node.",
                    n = container_faults.len(),
                    nodes = fault_nodes.join(", "),
                ),
            )
            .detail(container_faults.join("; "))
            .investigate("noo cluster status"),
            3600,
        )
        .await;
    }

    if wedged.is_empty() {
        return Ok(!container_faults.is_empty());
    }
    let nodes: Vec<&str> = wedged.iter().filter_map(|w| w.split(' ').next()).collect();
    // 1h cooldown: a wedged GPU stays wedged until someone reboots the node,
    // so a tighter repeat is pure noise.
    crate::operator_alert::send_operator_alert_with(
        state,
        crate::operator_alert::OperatorAlert::new(
            "autonomy.gpu_health",
            "cluster",
            format!(
                "🎮 GPU health: {n} node(s) advertise a GPU they cannot use: {}. \
                 Placement still trusts the registry row.",
                nodes.join(", "),
                n = wedged.len()
            ),
        )
        .detail(format!(
            "{}; recovery is usually a reboot (check `dmesg | grep Xid` on the node — \
             Xid 79 = fallen off the bus)",
            wedged.join(", ")
        ))
        .investigate("noo cluster status"),
        3600,
    )
    .await;
    Ok(true)
}

/// The probe decision, separated so the contract is pinned by tests: only an
/// EXPLICIT `available: false` counts. A missing field, null, or non-boolean
/// is an unknown answer — treating unknown as wedged would page the operator
/// on every agent version skew.
fn gpu_probe_says_unavailable(body: &serde_json::Value) -> bool {
    body.get("available").and_then(|v| v.as_bool()) == Some(false)
}

/// Container-level GPU faults from the agent's watchdog. Same
/// skew contract as `available`: a missing `watchdog` object, a missing
/// `faults` array, or non-string entries all read as "no faults" — only an
/// agent that AFFIRMATIVELY reports a fault can page the operator.
fn gpu_watchdog_faults(body: &serde_json::Value) -> Vec<String> {
    body.get("watchdog")
        .and_then(|w| w.get("faults"))
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {

    // ── companion_battery_low raises, deduped (audit 2026-10-08) ──────────
    fn node(tier: u64, pct: f64, charging: bool) -> serde_json::Value {
        serde_json::json!({"tier": tier, "battery_pct": pct, "is_charging": charging})
    }

    #[test]
    fn a_low_battery_raises_one_alert_per_node_deduped_across_ticks() {
        let entries = vec![
            ("phone".to_string(), node(5, 12.0, false)),
            ("charging".to_string(), node(5, 3.0, true)),
            ("full".to_string(), node(5, 90.0, false)),
            ("server".to_string(), node(2, 1.0, false)),
        ];
        let low = low_battery_nodes(&entries);
        assert_eq!(low, vec![("phone".to_string(), 12.0)]);
        let (a1, c1) = battery_alert(&low[0].0, low[0].1);
        let (a2, c2) = battery_alert(&low[0].0, 11.0); // next tick, lower still
        // Same funnel key => the second is suppressed within the cooldown.
        assert_eq!((a1.kind.as_str(), a1.target.as_str()), (a2.kind.as_str(), a2.target.as_str()));
        assert!(c1 > 0 && c1 == c2, "a cooldown must be set, or every tick re-alerts");
        assert!(c1 >= 3600, "longer than the 5-minute tick");
        // Channel text is general: no battery level, no detail.
        let text = crate::egress::system(&a1, "ref-test");
        assert!(text.as_str().contains("phone"));
        assert!(!text.as_str().contains("12"), "level stays in the log: {}", text.as_str());
        assert!(a1.detail.contains("battery_pct=12"));
    }
    use super::*;

    #[test]
    fn a_node_that_registered_but_has_not_heartbeated_yet_is_not_offline() {
        // node_register writes `ts` only; the first heartbeat adds
        // `last_heartbeat`. Between the two the node is arriving, not gone.
        let now = 1_700_000_000.0;
        let just_registered = serde_json::json!({"tier": 2, "ts": now - 20.0});
        assert!(!is_node_offline(&just_registered, now));
        // A registration that never turned into a heartbeat does go stale.
        let abandoned = serde_json::json!({"tier": 2, "ts": now - 121.0});
        assert!(is_node_offline(&abandoned, now));
        // The heartbeat field, when present, is the one that counts.
        let fresh = serde_json::json!({"tier": 2, "ts": now - 500.0, "last_heartbeat": now - 5.0});
        assert!(!is_node_offline(&fresh, now));
        // Neither field: nothing ever stamped this entry.
        assert!(is_node_offline(&serde_json::json!({"tier": 2}), now));
    }

    #[test]
    fn an_offline_page_names_the_node() {
        assert_eq!(
            node_offline_text("worker", "host2"),
            "⚠️ Cluster health: worker node 'host2' is offline (missed heartbeat threshold)."
        );
        assert!(node_offline_text("edge (tier ≥ 4)", "host9").contains("'host9'"));
    }

    #[test]
    fn node_heartbeat_alerts_are_persisting_and_have_a_clear_path() {
        // The wiring the schedule depends on: per-node, persisting, cleared.
        let src = include_str!("autonomy_evaluators.rs");
        let body = src
            .split("async fn alert_nodes_on_change(")
            .nth(1)
            .expect("alert_nodes_on_change not found");
        let body = &body[..body.find("\n}\n").unwrap()];
        assert!(body.contains(".persisting()"), "node-offline alerts must be persisting");
        assert!(body.contains("clear_operator_alert"), "a node that heartbeats again must be reported recovered");
    }

    #[test]
    fn gpu_probe_only_explicit_false_is_wedged() {
        // The wedged answer node-agent actually returns (handleGPUMetrics).
        assert!(gpu_probe_says_unavailable(&serde_json::json!({
            "available": false, "message": "GPU metrics not available"
        })));
        // Healthy.
        assert!(!gpu_probe_says_unavailable(&serde_json::json!({
            "available": true, "gpu_model": "NVIDIA GeForce RTX 3060 Laptop GPU"
        })));
        // Unknowns are NOT wedged: missing field (older agent), null, wrong
        // type, empty body. Alerting on these turns version skew into pages.
        for v in [
            serde_json::json!({}),
            serde_json::json!({"available": null}),
            serde_json::json!({"available": "false"}),
            serde_json::json!({"status": "ok"}),
        ] {
            assert!(!gpu_probe_says_unavailable(&v), "{v}");
        }
    }

    #[test]
    fn node_disk_breaches_affirmative_only() {
        // The breach answer a post-probe agent actually returns.
        let body = serde_json::json!({
            "status": "healthy",
            "disk": [
                {"path": "/", "used_percent": 91.0, "avail_gb": 12.5, "total_gb": 147.0},
                {"path": "/var/lib/containerd", "used_percent": 38.0, "avail_gb": 88.0, "total_gb": 147.0},
            ]
        });
        let b = node_disk_breaches(&body, 85.0);
        assert_eq!(b, vec!["/: 91% used, 12.5 GB free of 147 GB".to_string()]);

        // Unknowns are NO breach: pre-probe agent (no field), non-Linux
        // (empty list), malformed entries. Version skew must not page.
        for v in [
            serde_json::json!({"status": "healthy"}),
            serde_json::json!({"disk": []}),
            serde_json::json!({"disk": "full"}),
            serde_json::json!({"disk": [{"path": "/"}]}),
            serde_json::json!({"disk": [{"used_percent": 99.0}]}),
        ] {
            assert!(node_disk_breaches(&v, 85.0).is_empty(), "{v}");
        }
    }

    #[test]
    fn gpu_watchdog_faults_only_affirmative_reports_count() {
        // The fault answer the agent's watchdog actually returns.
        assert_eq!(
            gpu_watchdog_faults(&serde_json::json!({
                "available": true,
                "watchdog": {"host_gpu": "ok", "faults": ["noo-llamacpp: GPU still unreachable after restart"]}
            })),
            vec!["noo-llamacpp: GPU still unreachable after restart".to_string()]
        );
        // Unknowns are NO faults: pre-watchdog agent (no field), empty
        // list, malformed shapes. Same skew contract as `available`.
        for v in [
            serde_json::json!({"available": true}),
            serde_json::json!({"watchdog": {"faults": []}}),
            serde_json::json!({"watchdog": {}}),
            serde_json::json!({"watchdog": {"faults": "noo-llamacpp"}}),
            serde_json::json!({"watchdog": {"faults": [42]}}),
            serde_json::json!({"watchdog": null}),
        ] {
            assert!(gpu_watchdog_faults(&v).is_empty(), "{v}");
        }
    }


    /// `/` always exists and is always mountable, so this exercises the
    /// real statvfs path rather than a mock.
    #[test]
    fn fs_usage_reports_plausible_values_for_root() {
        let (used_pct, avail_gb, total_gb) =
            fs_usage("/").expect("statvfs on / must succeed");
        assert!(
            (0.0..=100.0).contains(&used_pct),
            "used_pct out of range: {used_pct}"
        );
        assert!(total_gb > 0.0, "total must be positive: {total_gb}");
        assert!(avail_gb >= 0.0, "avail must be non-negative: {avail_gb}");
        assert!(
            avail_gb <= total_gb,
            "avail {avail_gb} cannot exceed total {total_gb}"
        );
    }

    /// A path that cannot be stat'd must return None rather than panic —
    /// the evaluator relies on this to skip paths that aren't mounted
    /// inside the gateway container instead of failing the whole check.
    #[test]
    fn fs_usage_returns_none_for_missing_path() {
        assert!(fs_usage("/definitely/not/a/real/mount/point/xyzzy").is_none());
    }

    /// Interior NUL bytes must not panic (CString::new rejects them).
    #[test]
    fn fs_usage_returns_none_for_path_with_nul() {
        assert!(fs_usage("/tmp/\0/bad").is_none());
    }

    // ── env parsing ──────────────────────────────────────────────────
    //
    // These take the raw value rather than reading the environment so
    // they stay hermetic (env mutation races across parallel tests).

    #[test]
    fn watermark_defaults_when_unset_or_empty() {
        assert_eq!(parse_watermark(None), 85.0);
        // docker-compose's `${VAR:-}` passthrough delivers "" for a
        // variable the operator never set — must mean "unset", not 0.
        assert_eq!(parse_watermark(Some(String::new())), 85.0);
        assert_eq!(parse_watermark(Some("   ".into())), 85.0);
    }

    #[test]
    fn watermark_rejects_nonsense_and_out_of_range() {
        assert_eq!(parse_watermark(Some("abc".into())), 85.0);
        assert_eq!(parse_watermark(Some("0".into())), 85.0);
        assert_eq!(parse_watermark(Some("-5".into())), 85.0);
        assert_eq!(parse_watermark(Some("101".into())), 85.0);
    }

    #[test]
    fn watermark_accepts_valid_override() {
        assert_eq!(parse_watermark(Some("60".into())), 60.0);
        assert_eq!(parse_watermark(Some(" 92.5 ".into())), 92.5);
        assert_eq!(parse_watermark(Some("100".into())), 100.0);
    }

    /// The critical one: an empty value must NOT yield zero watch paths.
    /// It would make the loop return Ok(false) forever — the location
    /// would look healthy while monitoring nothing at all.
    #[test]
    fn watch_paths_never_empty() {
        assert_eq!(parse_watch_paths(None), "/");
        assert_eq!(parse_watch_paths(Some(String::new())), "/");
        assert_eq!(parse_watch_paths(Some("  ".into())), "/");

        for raw in [None, Some(String::new()), Some("   ".into())] {
            let paths = parse_watch_paths(raw);
            let count = paths
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .count();
            assert!(count > 0, "must always watch at least one path");
        }
    }

    #[test]
    fn watch_paths_accepts_override() {
        assert_eq!(parse_watch_paths(Some("/data".into())), "/data");
        assert_eq!(
            parse_watch_paths(Some("/,/var/lib/containerd".into())),
            "/,/var/lib/containerd"
        );
    }

    // ── disk reclaim opt-in gates ────────────────────────────────────
    //
    // The action deletes data, so BOTH defaults must be the safe side:
    // an empty/unset config must yield (disabled, dry_run) — never a live
    // reclaim. These pins are what keeps a bare `disk_watermark` override
    // row (someone toggling the interval, say) from arming deletion.

    #[test]
    fn reclaim_disabled_by_default() {
        assert_eq!(parse_reclaim_config(&json!({})), (false, true));
        // Unrelated config keys must not arm it either.
        assert_eq!(
            parse_reclaim_config(&json!({"check_interval_seconds": 900})),
            (false, true)
        );
        // Non-boolean values fail closed.
        assert_eq!(
            parse_reclaim_config(&json!({"enabled_action": "yes"})),
            (false, true)
        );
    }

    #[test]
    fn reclaim_enabled_still_previews_by_default() {
        // First opt-in (enabled_action) alone must still be a dry run —
        // acting requires the second, explicit `dry_run: false`.
        assert_eq!(
            parse_reclaim_config(&json!({"enabled_action": true})),
            (true, true)
        );
    }

    #[test]
    fn reclaim_live_requires_both_opt_ins() {
        assert_eq!(
            parse_reclaim_config(&json!({"enabled_action": true, "dry_run": false})),
            (true, false)
        );
        // dry_run:false WITHOUT enabled_action must not enable anything.
        assert_eq!(
            parse_reclaim_config(&json!({"dry_run": false})),
            (false, false)
        );
    }

    // ── node disk reclaim (nodes run the ladder themselves) ──────────

    /// An upgraded fleet must only LOG what it would reclaim: with no
    /// location config the node gate is off, and arming it still previews.
    #[test]
    fn node_reclaim_defaults_are_off_and_then_dry_run() {
        assert_eq!(crate::autonomy_loop::gate_of("disk_watermark", &json!({})), Some((false, true)));
        assert_eq!(
            crate::autonomy_loop::gate_of("disk_watermark", &json!({"enabled_action": true})),
            Some((true, true))
        );
    }

    #[test]
    fn node_policy_carries_the_gate_and_an_optional_cap() {
        assert_eq!(
            node_reclaim_policy_json(false, true, 85.0, None),
            json!({"enabled": false, "dry_run": true, "watermark": 85})
        );
        assert_eq!(
            node_reclaim_policy_json(true, false, 80.4, Some(25_000_000_000)),
            json!({"enabled": true, "dry_run": false, "watermark": 80, "cache_cap_bytes": 25_000_000_000i64})
        );
        assert_eq!(cache_cap_bytes(&json!({"cache_cap_bytes": 0})), None);
        assert_eq!(cache_cap_bytes(&json!({"cache_cap_bytes": 5})), Some(5));
    }

    /// The node alert relays what the node's own ladder is doing, and never
    /// again tells an operator to remove containerd leases by age — that
    /// deleted live containers' snapshots on host3.
    #[test]
    fn node_disk_alert_reports_the_nodes_ladder_and_drops_the_lease_advice() {
        let cases = [
            (None, "predates node disk reclaim"),
            (Some(json!({"status": "disabled", "policy": {"enabled": false, "dry_run": true}})), "reclaim is off"),
            (Some(json!({"status": "x", "policy": {"enabled": true, "dry_run": true}})), "previewing only"),
            (Some(json!({"status": "x", "policy": {"enabled": true, "dry_run": false}})), "is acting on it"),
            (Some(json!({"status": "waiting for policy"})), "reclaim is off"),
            (
                Some(json!({"policy": {"enabled": true, "dry_run": true},
                            "last_result": {"ok": false, "report": "cannot measure usage"}})),
                "last reclaim run failed",
            ),
            (
                Some(json!({"policy": {"enabled": true, "dry_run": true},
                            "last_result": {"ok": true, "report": "rung1: 0"}})),
                "previewing only",
            ),
        ];
        for (reclaim, want) in cases {
            let line = node_disk_alert_summary("host2", 85.0, 1, reclaim.as_ref());
            assert!(line.starts_with("💾 Disk watermark on node host2 (85%) on 1 disk(s)."), "{line}");
            assert!(line.contains(want), "{line} should contain {want:?}");
            assert!(!line.contains("lease") && !line.contains("ctr "), "lease advice is back: {line}");
        }
    }

    // ── backend_* action gates ─────────────────
    //
    // These three locations START and STOP containers on the fleet when
    // armed. The pin that matters most is the FIRST one: a stack that
    // upgrades to this build must behave exactly as it did before, which
    // means every config an existing install could possibly present —
    // empty, a bare interval override, a stale `dry_run` — resolves to
    // "do not act".

    #[test]
    fn backend_actions_disabled_by_default() {
        assert!(!action_enabled(&json!({})));
        assert!(!action_enabled(&json!(null)));
        // What a real `noo_autonomy_overrides` row from a toggle looks like.
        assert!(!action_enabled(&json!({"name": "backend_scaling", "enabled": true})));
        assert!(!action_enabled(&json!({"check_interval_seconds": 300})));
        // Non-boolean values fail closed, as with the reclaim gate.
        assert!(!action_enabled(&json!({"enabled_action": "true"})));
        assert!(!action_enabled(&json!({"enabled_action": 1})));
        // `dry_run` is not this gate's switch and must not arm it.
        assert!(!action_enabled(&json!({"dry_run": false})));
    }

    /// The gate that was missing entirely until 2026-09-04. Enabling the
    /// cert_auto_rotate LOCATION used to queue a fleet-wide
    /// backup→rotate→reload→probe→auto-revert immediately, with no second
    /// opt-in — the weakest gate on the highest-consequence action, sitting
    /// next to `cert_expiry_check`, which only alerts. A new CA strands every
    /// remote agent, so this one is not a recoverable mistake.
    #[test]
    fn cert_rotation_needs_both_opt_ins() {
        // Same helpers the evaluator reads, exercised the same way.
        let dry = |c: &serde_json::Value| {
            c.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(true)
        };
        let rotates = |c: &serde_json::Value| action_enabled(c) && !dry(c);

        // An operator who enables the location to SEE expiring certs must
        // not thereby rotate them.
        assert!(!rotates(&json!({})));
        assert!(!rotates(&json!({"enabled": true})));
        // One opt-in is not enough, in either direction.
        assert!(!rotates(&json!({"enabled_action": true})));
        assert!(!rotates(&json!({"dry_run": false})));
        // Fail closed on non-booleans, like every other gate here.
        assert!(!rotates(&json!({"enabled_action": "true", "dry_run": "false"})));
        // Both, explicitly, is the only way through.
        assert!(rotates(&json!({"enabled_action": true, "dry_run": false})));
    }

    #[test]
    fn backend_actions_arm_on_explicit_opt_in() {
        assert!(action_enabled(&json!({"enabled_action": true})));
        assert!(action_enabled(
            &json!({"name": "backend_idle_scaledown", "enabled": true, "enabled_action": true})
        ));
    }

    #[test]
    fn availability_backend_defaults_to_ollama() {
        assert_eq!(availability_backend(&json!({})), "ollama");
        assert_eq!(availability_backend(&json!({"backend": ""})), "ollama");
        assert_eq!(availability_backend(&json!({"backend": "llamacpp"})), "llamacpp");
    }

    #[test]
    fn scaling_replicas_defaults_to_two_and_is_clamped() {
        assert_eq!(scaling_replicas(&json!({})), 2);
        assert_eq!(scaling_replicas(&json!({"replicas": 3})), 3);
        // A typo must not conjure a hundred containers.
        assert_eq!(scaling_replicas(&json!({"replicas": 100})), 8);
        assert_eq!(scaling_replicas(&json!({"replicas": 0})), 1);
        assert_eq!(scaling_replicas(&json!({"replicas": "many"})), 2);
    }

    // ── declared-placement guard ─────────────────────────────────────

    fn pinned_set(pairs: &[(&str, &str)]) -> std::collections::HashSet<(String, String)> {
        pairs.iter().map(|(n, b)| (n.to_string(), b.to_string())).collect()
    }

    #[test]
    fn declared_backends_are_split_out_never_stopped() {
        let backends = vec!["vllm".to_string(), "ollama".to_string()];
        let pinned = pinned_set(&[("host8", "vllm")]);
        let (stoppable, declared) = split_pinned("host8", &backends, &pinned);
        assert_eq!(stoppable, vec!["ollama".to_string()]);
        assert_eq!(declared, vec!["vllm".to_string()]);
    }

    #[test]
    fn a_placement_on_another_node_does_not_protect_this_one() {
        // The guard is per (node, backend): `vllm` declared on host1
        // must not shield host8's unmanaged `vllm` from a scaledown.
        let backends = vec!["vllm".to_string()];
        let pinned = pinned_set(&[("host1", "vllm")]);
        let (stoppable, declared) = split_pinned("host8", &backends, &pinned);
        assert_eq!(stoppable, vec!["vllm".to_string()]);
        assert!(declared.is_empty());
    }

    #[test]
    fn no_placements_means_everything_is_stoppable() {
        let backends = vec!["ollama".to_string()];
        let (stoppable, declared) = split_pinned("host8", &backends, &pinned_set(&[]));
        assert_eq!(stoppable, vec!["ollama".to_string()]);
        assert!(declared.is_empty());
    }
}

/// cross_domain_link_integrity — the deferred half,
/// as a detector instead of a memory.
///
/// Phase C dropped `fk_temporal_edges_source_cycle` — safe at the time,
/// measured: 0 of 4474 `noo_temporal_edges` rows carried a `source_cycle_id`,
/// and nothing anywhere deletes a hofstadter cycle, so the FK guarded nothing
/// and its cascade could not fire. Per the design the link survives as a
/// VALUE, with enforcement deferred until there is a writer to enforce
/// against — a check written before its first caller is a guess at what it
/// should say.
///
/// This is what turns that deferral from a note someone must remember into a
/// condition that announces itself:
///
/// * rows with a non-null `source_cycle_id` exist at all → the write path is
///   LIVE, and the write-time validation owed is now due.
///   Alert once (24h cooldown), pointing at exactly that obligation.
/// * any of those rows reference a cycle id that does not exist → the
///   integrity the FK used to provide has actually been violated. Same
///   alert, harder wording, because now it is corruption and not just debt.
///
/// One query, LEFT JOIN, both counts. `to_regclass` guards make it a clean
/// no-op on an OSS install, where neither table exists.
pub async fn eval_cross_domain_link_integrity(state: &AppState) -> Result<bool, String> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE e.source_cycle_id IS NOT NULL),
                count(*) FILTER (WHERE e.source_cycle_id IS NOT NULL AND c.id IS NULL)
         FROM noo_temporal_edges e
         LEFT JOIN noo_hofstadter_loop_cycles c ON c.id = e.source_cycle_id
         WHERE to_regclass('noo_temporal_edges') IS NOT NULL
           AND to_regclass('noo_hofstadter_loop_cycles') IS NOT NULL",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        // An OSS install has neither table and the FROM clause itself fails
        // before the guard can help — that is fine and expected, not an
        // error worth a warn-level log every hour.
        if e.to_string().contains("does not exist") {
            return String::new();
        }
        format!("cross-domain link query failed: {e}")
    })
    .or_else(|e| if e.is_empty() { Ok(None) } else { Err(e) })?;

    let Some((linked, dangling)) = row else { return Ok(false) };
    if linked == 0 {
        return Ok(false);
    }

    let summary = if dangling > 0 {
        format!(
            "🚨 Cross-domain link integrity violation: {dangling} of {linked} temporal \
             edges point at loop cycles that do not exist."
        )
    } else {
        format!(
            "⚠️ Temporal edges now carry cross-domain links ({linked}, all valid); \
             the write-time validation they were waiting on is due."
        )
    };
    let msg = if dangling > 0 {
        format!(
            "🚨 Cross-domain link INTEGRITY VIOLATION: {dangling} of {linked} \
             noo_temporal_edges rows reference a noo_hofstadter_loop_cycles id \
             that does not exist. The FK that used to prevent this was dropped \
             on the measurement that nothing wrote these \
             values — something does now, and it is writing dangling ids. The \
             write-time validation is overdue, and the \
             existing dangling rows need reconciling."
        )
    } else {
        format!(
            "⚠️ noo_temporal_edges.source_cycle_id is now POPULATED ({linked} \
             row(s), all currently valid). the design dropped the FK \
             on the measurement that this column was never written — that \
             assumption just expired. Build the write-time validation from \
             the design before this becomes the integrity violation variant \
             of this alert."
        )
    };
    tracing::warn!(linked, dangling, "autonomy.cross_domain_link_integrity");
    crate::operator_alert::send_operator_alert_with(
        state,
        crate::operator_alert::OperatorAlert::new("autonomy.cross_domain_link_integrity", "database", summary)
            .detail(msg)
            .investigate("noo db status"),
        86400,
    )
    .await;
    Ok(true)
}

/// kb_chunk_scale — the design's trigger condition, as a monitor.
///
/// Chunk retrieval deliberately runs exact KNN over the page-filtered
/// candidate set instead of the HNSW index; at the measured selectivity
/// that is the CORRECT plan and its recall is perfect. What grows with the
/// corpus is the cold-cache cost of the per-candidate PK fetches. The
/// decision was: leave the plan alone, act (enable pgvector iterative
/// index scans in trellion's search_chunks) when chunk_embeddings passes
/// 100k rows. This evaluator is that tripwire — it does not change any
/// query, it just makes sure the crossover is noticed the week it happens
/// rather than as a latency regression months later.
///
/// n_live_tup (estimate) rather than COUNT(*): the threshold is an order-
/// of-magnitude marker, and an exact count over the very table we are
/// worried about scanning would be self-defeating.
pub async fn eval_kb_chunk_scale(state: &AppState) -> Result<bool, String> {
    const THRESHOLD: i64 = 100_000;
    let rows: Option<i64> = sqlx::query_scalar(
        "SELECT n_live_tup::bigint FROM pg_stat_user_tables \
         WHERE relname = 'chunk_embeddings'",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("chunk scale query failed: {e}"))?;

    let Some(rows) = rows else { return Ok(false) };
    if rows < THRESHOLD {
        return Ok(false);
    }

    let msg = format!(
        "📈 chunk_embeddings has reached ~{rows} rows (threshold {THRESHOLD}). \
         the design's trigger has fired: chunk retrieval is exact KNN over \
         the page-filtered set, and at this scale the cold-cache PK-fetch \
         term starts to dominate. Planned action: enable pgvector iterative \
         index scans (hnsw.iterative_scan) in trellion's search_chunks and \
         verify with EXPLAIN that the HNSW-driven plan is selected."
    );
    tracing::warn!(rows, threshold = THRESHOLD, "autonomy.kb_chunk_scale");
    crate::operator_alert::send_operator_alert_with(
        state,
        crate::operator_alert::OperatorAlert::new(
            "autonomy.kb_chunk_scale",
            "database",
            format!(
                "📈 The knowledge base passed {THRESHOLD} chunk embeddings (~{rows}); \
                 the planned retrieval change is now due."
            ),
        )
        .detail(msg)
        .investigate("noo rag status"),
        604800, // weekly — the condition is permanent once crossed
    )
    .await;
    Ok(true)
}

// ─── Custom locations (operator-defined rules engine) ───────────────────
//
// Port of `worker.autonomy.evaluate_custom` (reference implementation:
// `noomesh/workers/autonomy.py::_autonomy_evaluate_custom`, kept
// unregistered). This was the design's sharpest anti-pattern: the Rust
// autonomy loop scheduled the location, hopped to Python over NATS, and
// Python did an HTTP GET back out — the whole body is a threshold
// comparison. Builtins keep their hand-written evaluators above; this
// exists so operators can add monitoring rules from the dashboard
// without a deploy.
//
// Definition shape (noo_autonomy_locations.definition / YAML seed):
//   type: "endpoint" | "promql"
//   config: {url | query, ...}
//   conditions: [{metric, operator: gte|lte|gt|lt|eq|neq, threshold}]
//   actions: [{type: alert|webhook|nats|trellion_consolidate, config}]
//   cooldown_seconds: N   (action re-fire suppression)
//
// The result keeps the Python JSON shape ({"name", "fired", "conditions",
// ...} / {"name", "error", ...}) — the loop logs it and tests pin it.

const CUSTOM_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Dotted-path lookup into the fetched metrics ("a.b.c" → metrics.a.b.c).
fn lookup_metric<'a>(metrics: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = metrics;
    for part in path.split('.') {
        cur = cur.as_object()?.get(part)?;
    }
    Some(cur)
}

/// One condition comparison. Numeric when both sides parse as numbers
/// (matching Python's `float(value) op float(threshold)`, which also
/// accepted numeric strings); otherwise ordered/equality comparison on
/// strings, else equality only.
fn compare(op: &str, value: &serde_json::Value, threshold: &serde_json::Value) -> bool {
    fn as_num(v: &serde_json::Value) -> Option<f64> {
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            .or_else(|| v.as_bool().map(|b| if b { 1.0 } else { 0.0 }))
    }
    if let (Some(a), Some(b)) = (as_num(value), as_num(threshold)) {
        return match op {
            "gte" => a >= b,
            "lte" => a <= b,
            "gt" => a > b,
            "lt" => a < b,
            "eq" => a == b,
            "neq" => a != b,
            _ => false, // unknown operator — never true (Python: op None → ok False)
        };
    }
    if let (Some(a), Some(b)) = (value.as_str(), threshold.as_str()) {
        return match op {
            "gte" => a >= b,
            "lte" => a <= b,
            "gt" => a > b,
            "lt" => a < b,
            "eq" => a == b,
            "neq" => a != b,
            _ => false,
        };
    }
    match op {
        "eq" => value == threshold,
        "neq" => value != threshold,
        _ => false,
    }
}

/// Evaluate all conditions against the fetched metrics. ALL must hold;
/// an empty condition list never fires (matching Python's
/// `fired = bool(conditions)`). Returns (fired, evaluated-entries).
fn eval_conditions(
    metrics: &serde_json::Value,
    conditions: &[serde_json::Value],
) -> (bool, Vec<serde_json::Value>) {
    let mut fired = !conditions.is_empty();
    let mut evaluated = Vec::with_capacity(conditions.len());
    for cond in conditions {
        let metric_path = cond.get("metric").and_then(|m| m.as_str()).unwrap_or("value");
        let value = lookup_metric(metrics, metric_path);
        let op = cond.get("operator").and_then(|o| o.as_str()).unwrap_or("gte");
        let threshold = cond.get("threshold").unwrap_or(&serde_json::Value::Null);
        let ok = match value {
            Some(v) => compare(op, v, threshold),
            None => false, // missing metric — condition cannot hold
        };
        evaluated.push(json!({
            "metric": cond.get("metric"),
            "value": value,
            "ok": ok,
        }));
        fired = fired && ok;
    }
    (fired, evaluated)
}

/// Instant PromQL query against Prometheus. Returns (first value, series
/// count) — same projection as the Python `_metrics_query` consumer.
async fn prometheus_instant_value(query: &str) -> Result<(f64, usize), String> {
    if query.trim().is_empty() {
        return Err("query (PromQL) required".into());
    }
    let prom_url = crate::config::env_or_yaml(
        "NOO_PROMETHEUS_URL",
        |c| c.services.prometheus_url.clone(),
        "https://prometheus:9090",
    );
    let resp = crate::tls::cluster_client()
        .get(format!("{prom_url}/api/v1/query"))
        .query(&[("query", query)])
        .timeout(CUSTOM_FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("prometheus unreachable at {prom_url}: {e}"))?;
    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("prometheus returned non-JSON: {e}"))?;
    if data.get("status").and_then(|s| s.as_str()) != Some("success") {
        let err = data
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("query failed");
        return Err(err.to_string());
    }
    let results = data
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    // Instant-vector entries are ["<unix ts>", "<value as string>"].
    let value = results
        .first()
        .and_then(|r| r.get("value"))
        .and_then(|v| v.get(1))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);
    Ok((value, results.len()))
}

/// Fetch the observation a custom location is defined over.
async fn fetch_custom_metrics(
    name: &str,
    loc_type: &str,
    config: &serde_json::Value,
) -> Result<serde_json::Value, serde_json::Value> {
    match loc_type {
        "endpoint" => {
            let url = config.get("url").and_then(|u| u.as_str()).unwrap_or("");
            if url.is_empty() {
                return Err(json!({"name": name, "error": "endpoint type needs config.url"}));
            }
            // cluster_client trusts the cluster CA (the Python handler's
            // verify=NOO_TLS_CA) and falls back to system roots without one.
            let resp = crate::tls::cluster_client()
                .get(url)
                .timeout(CUSTOM_FETCH_TIMEOUT)
                .send()
                .await
                .map_err(|e| json!({"name": name, "error": format!("fetch failed: {e}")}))?;
            let status = resp.status().as_u16();
            if status != 200 {
                // A monitored endpoint failing to answer is the opposite of
                // "no alert" — report it as an error, not fired:false.
                return Err(json!({
                    "name": name,
                    "error": format!("endpoint returned HTTP {status}"),
                    "status_code": status,
                }));
            }
            let data: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| json!({"name": name, "error": format!("fetch failed: {e}")}))?;
            let mut metrics = if data.is_object() { data } else { json!({"value": data}) };
            if let Some(obj) = metrics.as_object_mut() {
                obj.entry("status_code").or_insert(json!(status));
            }
            Ok(metrics)
        }
        "promql" => {
            let query = config.get("query").and_then(|q| q.as_str()).unwrap_or("");
            match prometheus_instant_value(query).await {
                Ok((value, series)) => Ok(json!({"value": value, "series": series})),
                Err(e) => Err(json!({"name": name, "error": e})),
            }
        }
        other => Err(json!({"name": name, "error": format!("unknown location type '{other}'")})),
    }
}

/// Generic evaluator for CUSTOM autonomy locations. The loop
/// (`autonomy_loop.rs::poll_locations`) is the scheduler; this interprets
/// the declared definition and fires its actions.
pub async fn eval_custom_location(
    state: &AppState,
    definition: &serde_json::Value,
) -> serde_json::Value {
    let name = definition
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("custom")
        .to_string();
    let loc_type = definition
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("endpoint");
    let config = definition.get("config").cloned().unwrap_or_else(|| json!({}));
    let conditions = definition
        .get("conditions")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let actions = definition
        .get("actions")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let cooldown = definition
        .get("cooldown_seconds")
        .and_then(|c| c.as_i64())
        .unwrap_or(300)
        .max(0);

    let metrics = match fetch_custom_metrics(&name, loc_type, &config).await {
        Ok(m) => m,
        Err(err_result) => return err_result,
    };

    let (fired, evaluated) = eval_conditions(&metrics, &conditions);
    if !fired {
        return json!({"name": name, "fired": false, "conditions": evaluated});
    }

    // Cooldown — per-location action re-fire suppression. Redis NX rather
    // than the Python handler's in-process map: it survives gateway
    // restarts (the in-process version reset on restart, which at worst
    // repeated one alert; this one doesn't). No Redis → no suppression.
    if cooldown > 0 {
        if let Some(r) = redis(state) {
            let key = format!("noo:autonomy:custom_cooldown:{name}");
            if !r.set_nx_ex(&key, "1", cooldown).await {
                return json!({
                    "name": name,
                    "fired": true,
                    "suppressed": "cooldown",
                    "conditions": evaluated,
                });
            }
        }
    }

    // Fire declared actions.
    let mut ran: Vec<String> = Vec::new();
    for action in &actions {
        let a_type = action.get("type").and_then(|t| t.as_str()).unwrap_or("alert");
        let a_cfg = action.get("config").cloned().unwrap_or_else(|| json!({}));
        match a_type {
            "alert" => {
                tracing::warn!(
                    location = %name,
                    title = %a_cfg.get("title").and_then(|t| t.as_str()).unwrap_or(&name),
                    message = %a_cfg.get("message").and_then(|m| m.as_str()).unwrap_or(""),
                    ?evaluated,
                    "autonomy.custom_alert"
                );
                // The Python handler only logged; in Rust an "alert" action
                // goes to the operator like every builtin alert location.
                // cooldown 0 — the location's own cooldown already gates.
                crate::operator_alert::send_operator_alert_with(
                    state,
                    crate::operator_alert::OperatorAlert::new(
                        "autonomy.custom",
                        &name,
                        format!(
                            "⚠️ Custom autonomy location [{name}] fired: {}",
                            a_cfg.get("title").and_then(|t| t.as_str()).unwrap_or(&name),
                        ),
                    )
                    .detail(format!(
                        "{}; conditions: {evaluated:?}",
                        a_cfg.get("message").and_then(|m| m.as_str()).unwrap_or(""),
                    ))
                    .investigate("noo autonomy locations"),
                    0,
                )
                .await;
                ran.push("alert".into());
            }
            "webhook" => {
                let url = a_cfg.get("url").and_then(|u| u.as_str()).unwrap_or("");
                let res = crate::tls::external_client()
                    .post(url)
                    .timeout(CUSTOM_FETCH_TIMEOUT)
                    .json(&json!({"location": name, "conditions": evaluated}))
                    .send()
                    .await;
                match res {
                    Ok(_) => ran.push("webhook".into()),
                    Err(e) => tracing::warn!(
                        location = %name, r#type = "webhook", error = %e,
                        "autonomy.custom_action_failed"
                    ),
                }
            }
            "nats" | "trellion_consolidate" => {
                let subject = if a_type == "trellion_consolidate" {
                    "worker.api.snapshots.consolidate".to_string()
                } else {
                    a_cfg
                        .get("subject")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                if subject.is_empty() {
                    tracing::warn!(location = %name, subject = %subject,
                        "autonomy.custom_action_unknown_subject");
                    continue;
                }
                // The Python handler called the registered handler
                // in-process; from Rust the same handlers are reached over
                // NATS ({"params": ...} is the envelope they unwrap).
                // trellion_consolidate's config IS the slice ({kind, params,
                // label}, default_locations.py `consolidation_due`), not a
                // `payload` key: sending {"params": {}} made every armed run a
                // refused empty slice. Its time placeholders
                // are resolved here, where the Python autonomy loop used to.
                let payload = if a_type == "trellion_consolidate" {
                    consolidate_payload(&a_cfg, chrono::Utc::now())
                } else {
                    json!({"params": a_cfg.get("payload").cloned().unwrap_or_else(|| json!({}))})
                };
                // The subject here comes from operator-written autonomy
                // config, so this is the one call site that can name an
                // arbitrary `worker.*` handler. It signs as the autonomy
                // loop with read/write and nothing more — an operator who
                // can edit the action config still cannot escalate through
                // it, because the principal is not theirs to choose.
                match crate::bus_principal::with_internal(
                    "autonomy",
                    &["read", "write"],
                    worker_client::request(&state.nats, &subject, &payload),
                )
                .await
                {
                    // A handler that refuses answers `{"error": ...}` over a
                    // successful NATS reply; that is a failed action, not a run.
                    Ok(reply) => match reply_error(&reply) {
                        None => ran.push(subject),
                        Some(err) => tracing::warn!(
                            location = %name, r#type = %a_type, error = %err,
                            "autonomy.custom_action_refused"
                        ),
                    },
                    Err(e) => tracing::warn!(
                        location = %name, r#type = %a_type, error = %e,
                        "autonomy.custom_action_failed"
                    ),
                }
            }
            other => {
                tracing::warn!(location = %name, r#type = %other, "autonomy.custom_action_unknown");
            }
        }
    }

    crate::routes::admin::self_modify_audit(json!({
        "action": "autonomy_custom_fired",
        "location": name,
        "actions": ran,
        "result": "ok",
    }))
    .await;

    json!({"name": name, "fired": true, "actions_run": ran, "conditions": evaluated})
}

#[cfg(test)]
mod custom_location_tests {
    use super::*;

    #[test]
    fn lookup_follows_dotted_paths() {
        let m = json!({"a": {"b": {"c": 7}}, "value": 1});
        assert_eq!(lookup_metric(&m, "a.b.c"), Some(&json!(7)));
        assert_eq!(lookup_metric(&m, "value"), Some(&json!(1)));
        assert_eq!(lookup_metric(&m, "a.missing"), None);
        assert_eq!(lookup_metric(&m, "a.b.c.d"), None);
    }

    #[test]
    fn compare_covers_all_operators_numerically() {
        let v = json!(5.0);
        assert!(compare("gte", &v, &json!(5)));
        assert!(compare("lte", &v, &json!(5)));
        assert!(compare("gt", &v, &json!(4)));
        assert!(compare("lt", &v, &json!(6)));
        assert!(compare("eq", &v, &json!(5)));
        assert!(compare("neq", &v, &json!(4)));
        assert!(!compare("gt", &v, &json!(5)));
        // unknown operator is never true (matches Python's op-None → False)
        assert!(!compare("contains", &v, &json!(5)));
    }

    #[test]
    fn compare_accepts_numeric_strings_like_python_float() {
        // Python did float("12") — numeric strings compare numerically.
        assert!(compare("gte", &json!("12"), &json!(10)));
        assert!(compare("lt", &json!(3), &json!("4.5")));
        // Non-numeric strings fall back to string comparison.
        assert!(compare("eq", &json!("degraded"), &json!("degraded")));
        assert!(compare("neq", &json!("ok"), &json!("degraded")));
    }

    #[test]
    fn empty_conditions_never_fire() {
        let (fired, evaluated) = eval_conditions(&json!({"value": 99}), &[]);
        assert!(!fired);
        assert!(evaluated.is_empty());
    }

    #[test]
    fn all_conditions_must_hold() {
        let metrics = json!({"count": 5, "status_code": 200});
        let conds = vec![
            json!({"metric": "count", "operator": "gte", "threshold": 1}),
            json!({"metric": "status_code", "operator": "eq", "threshold": 200}),
        ];
        let (fired, evaluated) = eval_conditions(&metrics, &conds);
        assert!(fired);
        assert!(evaluated.iter().all(|e| e["ok"] == json!(true)));

        let conds = vec![
            json!({"metric": "count", "operator": "gte", "threshold": 1}),
            json!({"metric": "count", "operator": "gte", "threshold": 100}),
        ];
        let (fired, _) = eval_conditions(&metrics, &conds);
        assert!(!fired);
    }

    #[test]
    fn missing_metric_is_a_failed_condition_not_a_fire() {
        let conds = vec![json!({"metric": "nope", "operator": "gte", "threshold": 0})];
        let (fired, evaluated) = eval_conditions(&json!({"value": 1}), &conds);
        assert!(!fired);
        assert_eq!(evaluated[0]["ok"], json!(false));
        assert_eq!(evaluated[0]["value"], serde_json::Value::Null);
    }

    #[test]
    fn default_metric_path_is_value_and_default_operator_gte() {
        // A bare condition {"threshold": 1} reads metrics.value with gte.
        let conds = vec![json!({"threshold": 1})];
        let (fired, _) = eval_conditions(&json!({"value": 2}), &conds);
        assert!(fired);
    }
}

// ── node_tier_drift ─────────────────────────────────────────────────────

/// Consecutive disagreeing evaluations before a re-tier is considered.
///
/// Hysteresis, not politeness. A GPU that vanishes for one heartbeat — a
/// driver reset, which the design documents happening in the field — would
/// otherwise demote a tier-2 box, hand its slots elsewhere, and promote it
/// back on the next tick. The counter lives in Redis (`bump_counter`), so a
/// gateway restart costs a delay rather than a false positive, and a single
/// agreeing evaluation clears it.
const TIER_DRIFT_THRESHOLD: i64 = 5;

/// `node_tier_drift` — compare each node's DECLARED tier against what its
/// reported capabilities say, and (when armed) correct it.
///
/// Tier is frozen into `NODE_TIER` at provisioning and the agent only echoes
/// it back, so adding a GPU or moving a disk into different hardware leaves a
/// node asserting a class it no longer has. Tier feeds `slots_for_tier`,
/// placement and `CompanionPolicy`, and a stale one misroutes work rather
/// than failing — the same shape as the `upgrade-agents` incident, where the
/// DETECTED facts were right and the DECLARED classification was what
/// downstream trusted.
///
/// Disarmed — the default — this only reports. That is deliberate and is
/// the design's own Sketch item 4: a silent reclassification that moves
/// scheduler slots under a running fleet is the failure to avoid, so the
/// disagreement gets surfaced for a while before anything acts on it.
pub async fn eval_node_tier_drift(
    state: &AppState,
    config: &serde_json::Value,
) -> Result<bool, String> {
    let kv = state
        .js
        .get_key_value("mesh_nodes")
        .await
        .map_err(|e| format!("mesh_nodes KV unavailable: {e}"))?;
    use tokio_stream::StreamExt;
    let keys: Vec<String> = kv
        .keys()
        .await
        .map_err(|e| format!("kv.keys: {e}"))?
        .filter_map(|k| k.ok())
        .collect()
        .await;

    let mut confirmed: Vec<(String, i64, i64, String)> = Vec::new();
    for node_id in keys {
        if node_id == "gateway" {
            continue;
        }
        let Ok(Some(entry)) = kv.get(&node_id).await else { continue };
        let Ok(data) = serde_json::from_slice::<serde_json::Value>(&entry) else { continue };

        let counter_key = format!("noo:autonomy:counter:tier_drift:{node_id}");

        // A tier we cannot read is not a disagreement. `normalize_tier` is the
        // same coercion the scheduler uses, so "what autonomy compares" and
        // "what decides slots" cannot diverge.
        let Some(declared) =
            crate::scheduler_slots::normalize_tier(data.get("tier").unwrap_or(&serde_json::json!(null)))
        else {
            bump_counter(state, &counter_key, false).await?;
            continue;
        };

        // Tiers 5 and 6 are ROLES the operator chose — a sensor proxy and a
        // probe box classify like ordinary hardware, and re-tiering one into
        // schedulable work is precisely what must never happen. Derivation
        // covers 1-4; a companion is left alone even if it looks like a Pi,
        // because on the hardware it IS a Pi.
        if crate::node_tier::is_role_tier(declared) {
            bump_counter(state, &counter_key, false).await?;
            continue;
        }

        let caps = data.get("capabilities").cloned().unwrap_or(serde_json::json!({}));
        let facts = crate::node_tier::facts_from_capabilities(&caps);
        let verdict = crate::node_tier::derive(&facts);
        let Some(derived) = verdict.tier() else {
            // Unknown, not disagreement. An older agent build, or a capability
            // map that has not arrived, must never read as "this node is
            // misclassified" — that is how silence becomes an action.
            bump_counter(state, &counter_key, false).await?;
            continue;
        };

        let n = bump_counter(state, &counter_key, derived != declared).await?;
        if derived != declared && n >= TIER_DRIFT_THRESHOLD {
            confirmed.push((node_id, declared, derived, verdict.explain().to_string()));
        }
    }

    if confirmed.is_empty() {
        return Ok(false);
    }

    let armed = action_enabled(config);
    for (node_id, declared, derived, why) in &confirmed {
        let detail = format!(
            "node `{node_id}` declares tier {declared}; its reported capabilities \
             derive tier {derived} ({why}). Confirmed over {TIER_DRIFT_THRESHOLD} \
             consecutive evaluations."
        );
        let metrics = serde_json::json!({
            "declared_tier": declared,
            "derived_tier": derived,
            "declared_slots": crate::scheduler_slots::slots_for_tier(*declared),
            "derived_slots": crate::scheduler_slots::slots_for_tier(*derived),
        });

        if !armed {
            tracing::warn!(
                node_id = %node_id,
                declared, derived,
                "autonomy.node_tier_drift.would_retier"
            );
            crate::autonomy_audit::record(
                state,
                crate::autonomy_audit::Decision {
                    location: "node_tier_drift",
                    action: "retier_node",
                    outcome: crate::autonomy_audit::Outcome::Would,
                    target: Some(node_id),
                    detail: &format!("{detail} Arm with `enabled_action: true`."),
                    armed: Some(false),
                    dry_run: Some(false),
                    metrics: Some(metrics),
                },
            )
            .await;
            continue;
        }

        // Compare-and-swap, same as node_auto_quarantine: a heartbeat write
        // and this one race on the same JSON blob, and a plain put would
        // silently clobber whichever landed first.
        let mut wrote = false;
        for _ in 0..3 {
            let Ok(Some(entry)) = kv.entry(node_id).await else { break };
            let Ok(mut fresh) = serde_json::from_slice::<serde_json::Value>(&entry.value) else {
                break;
            };
            // Re-check against the FRESH value: the node may have been
            // re-tiered by an operator, or become a companion, between the
            // scan above and this write.
            let still =
                crate::scheduler_slots::normalize_tier(fresh.get("tier").unwrap_or(&serde_json::json!(null)));
            if still != Some(*declared) {
                break;
            }
            fresh["tier"] = serde_json::json!(derived);
            fresh["tier_source"] = serde_json::json!("derived");
            fresh["tier_reason"] = serde_json::json!(why);
            let Ok(bytes) = serde_json::to_vec(&fresh) else { break };
            match kv.update(node_id, bytes.into(), entry.revision).await {
                Ok(_) => {
                    wrote = true;
                    break;
                }
                Err(_) => continue,
            }
        }

        if !wrote {
            tracing::warn!(node_id = %node_id, "autonomy.node_tier_drift.write_lost");
            continue;
        }
        tracing::info!(
            node_id = %node_id,
            declared, derived,
            "autonomy.node_tier_drift.retiered"
        );
        crate::autonomy_audit::record(
            state,
            crate::autonomy_audit::Decision {
                location: "node_tier_drift",
                action: "retier_node",
                outcome: crate::autonomy_audit::Outcome::Fired,
                target: Some(node_id),
                detail: &detail,
                armed: Some(true),
                dry_run: Some(false),
                metrics: Some(metrics),
            },
        )
        .await;
        // Changing tier changes how many jobs the scheduler will give this
        // node. Worth an operator's attention even when they armed it.
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "autonomy.node_tier_drift",
                node_id,
                format!("🔁 Node `{node_id}` re-tiered {declared} → {derived}."),
            )
            .detail(why.to_string())
            .investigate(format!("noo cluster show {node_id}")),
            21_600,
        )
        .await;
    }
    Ok(true)
}

#[cfg(test)]
mod ssh_lane_removed_tests {
    //! The self-heal path must never again report a recovery it did not
    //! perform. Before 2026-09-11 `worker_node_agent_unreachable` wrote a
    //! pre-approved `revive_node` proposal and returned "acted" — true only
    //! for as long as a sidecar with the operator's SSH keys was polling the
    //! table. The sidecar is gone; these tests pin the replacement.

    use super::*;

    #[test]
    fn the_revive_instructions_are_a_command_someone_can_run() {
        let s = node_agent_revive_instructions("host9");
        // Names the box by the name the operator uses. NOT its address:
        // these instructions ride an operator alert to a chat channel,
        // which is outside the trust boundary (the address is logged).
        assert!(s.contains("host9"), "{s}");
        // Carries the actual command, not a description of one.
        assert!(s.contains("systemctl restart noo-node-agent"), "{s}");
        // And a way to see whether it worked — the executor's own lesson:
        // `systemctl restart` exiting 0 does not mean the unit stayed up.
        assert!(s.contains("is-active"), "{s}");
        assert!(s.contains("journalctl"), "{s}");
        // Says plainly that this is hands-on-the-node, so nobody waits for
        // an automatic recovery that is not coming.
        assert!(s.contains("no remote revive"), "{s}");
    }

    #[test]
    fn nothing_in_this_module_queues_a_revive_proposal() {
        // A source check, deliberately: the failure mode is a row written
        // for a consumer that does not exist, and no behavioural test
        // notices a row nobody reads. Watch it fail by putting
        // `INSERT INTO noo_cluster_proposals` back in this file.
        // Scan the MODULE, not this test mod — whose own assertions name
        // the very strings being banned. (It found itself on the first run,
        // which is the cheapest possible proof that the matcher works.)
        let src = include_str!("autonomy_evaluators.rs");
        let src = src
            .split("mod ssh_lane_removed_tests")
            .next()
            .expect("split always yields one part");
        assert!(
            src.contains("eval_worker_node_agent_unreachable"),
            "the scan is reading the wrong region"
        );
        let mut offenders = Vec::new();
        for (n, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue; // the tombstone comments are the point
            }
            if t.contains("INSERT INTO noo_cluster_proposals")
                || t.contains("queue_revive_proposal")
            {
                offenders.push(format!("{}: {}", n + 1, t));
            }
        }
        assert!(
            offenders.is_empty(),
            "autonomy writes a cluster proposal again, and nothing executes \
             those: {offenders:?}. A node that answers gets \
             routes::cluster::restart_agent_via_rail; one that does not gets \
             an operator alert carrying node_agent_revive_instructions."
        );
    }

    #[test]
    fn both_stale_node_paths_reach_an_operator() {
        // Each of the two locations that used to file a proposal must still
        // END somewhere honest. Assert the calls are present rather than
        // trusting that they are.
        let src = include_str!("autonomy_evaluators.rs");
        let src = src.split("mod ssh_lane_removed_tests").next().unwrap();
        let unreachable = src
            .split("pub async fn eval_worker_node_agent_unreachable")
            .nth(1)
            .expect("evaluator not found — this guard is reading the wrong file");
        let unreachable = &unreachable[..unreachable.find("\n}\n").unwrap_or(unreachable.len())];
        assert!(
            unreachable.contains("send_operator_alert"),
            "worker_node_agent_unreachable no longer tells anyone"
        );
        assert!(
            unreachable.contains("node_agent_revive_instructions"),
            "the alert must carry the manual command, not just the symptom"
        );

        let unbound = src
            .split("async fn revive_for_unbound_consumer")
            .nth(1)
            .expect("unbound-consumer path not found");
        let unbound = &unbound[..unbound.find("\n}\n").unwrap_or(unbound.len())];
        assert!(
            unbound.contains("restart_agent_via_rail"),
            "an agent that ANSWERS should be restarted over the rail, not alerted about"
        );
        assert!(
            unbound.contains("send_operator_alert"),
            "a failed rail restart must be reported, not swallowed"
        );
    }
}

/// The `trellion_consolidate` action's request: its config is the slice
/// (`{kind, params, label}`), with `{{ now }}` / `{{ now_minus_24h }}`
/// resolved to RFC 3339.
fn consolidate_payload(cfg: &serde_json::Value, now: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
    fn resolve(v: &serde_json::Value, now: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
        match v {
            serde_json::Value::String(s) => {
                let t = s.trim();
                let at = match t {
                    "{{ now }}" | "{{now}}" => Some(now),
                    "{{ now_minus_24h }}" | "{{now_minus_24h}}" => Some(now - chrono::Duration::hours(24)),
                    _ => None,
                };
                match at {
                    Some(at) => serde_json::Value::String(at.to_rfc3339()),
                    None => v.clone(),
                }
            }
            serde_json::Value::Object(m) => {
                serde_json::Value::Object(m.iter().map(|(k, v)| (k.clone(), resolve(v, now))).collect())
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(|v| resolve(v, now)).collect()),
            _ => v.clone(),
        }
    }
    let mut out = serde_json::Map::new();
    for key in ["kind", "params", "label"] {
        if let Some(v) = cfg.get(key) {
            out.insert(key.to_string(), resolve(v, now));
        }
    }
    serde_json::Value::Object(out)
}

/// The `error` a worker put in its reply (bare or inside the `data`
/// envelope), if any.
fn reply_error(reply: &serde_json::Value) -> Option<String> {
    let payload = reply.get("data").unwrap_or(reply);
    payload.get("error").map(|e| e.as_str().map(str::to_string).unwrap_or_else(|| e.to_string()))
}

#[cfg(test)]
mod consolidate_action_tests {
    #[test]
    fn data_root_policy_failures_reads_the_nodes_own_verdict() {
        use serde_json::json;
        assert_eq!(super::data_root_policy_failures(&json!({})), None, "older agent: nothing");
        assert_eq!(super::data_root_policy_failures(&json!({"data_roots": {"policy": {"ok": true, "problems": []}}})), None);
        let bad = json!({"data_roots": {"policy": {"ok": false, "problems": [
            {"code": "home_dir", "detail": "x"}, {"code": "wrong_owner", "detail": "y"}]}}});
        assert_eq!(super::data_root_policy_failures(&bad), Some(vec!["home_dir".to_string(), "wrong_owner".to_string()]));
        assert_eq!(super::data_root_policy_failures(&json!({"data_roots": {"policy": {"ok": false}}})),
            Some(vec!["unspecified".to_string()]));
    }

    use super::*;
    use chrono::TimeZone;

    #[test]
    fn the_shipped_consolidation_due_action_sends_its_slice_with_times_resolved() {
        // Mirrors default_locations.py `consolidation_due`.
        let cfg = json!({
            "kind": "time_window",
            "params": {"from": "{{ now_minus_24h }}", "to": "{{ now }}"},
            "label": "nightly time-window cycle",
        });
        let now = chrono::Utc.with_ymd_and_hms(2026, 10, 2, 3, 0, 0).unwrap();
        let p = consolidate_payload(&cfg, now);
        assert_eq!(p["kind"], "time_window");
        assert_eq!(p["label"], "nightly time-window cycle");
        assert_eq!(p["params"]["from"], "2026-10-01T03:00:00+00:00");
        assert_eq!(p["params"]["to"], "2026-10-02T03:00:00+00:00");
        assert!(p.get("payload").is_none() && p["params"].get("params").is_none());
    }

    #[test]
    fn a_refusal_in_the_reply_is_an_error_not_a_run() {
        assert_eq!(reply_error(&json!({"snapshot_id": "s", "status": "building"})), None);
        assert_eq!(reply_error(&json!({"error": "consolidate needs a slice"})).as_deref(), Some("consolidate needs a slice"));
        assert_eq!(reply_error(&json!({"data": {"error": "x"}})).as_deref(), Some("x"));
    }
}

#[cfg(test)]
mod embed_backlog_tests {
    use super::{embed_backlog_verdict as v, EmbedBacklog as B};
    const W: i64 = 3600;

    #[test]
    fn zero_is_clear_and_resets_the_snapshot() {
        assert_eq!(v(0, true, Some((50, 0)), 10, W), (B::Clear, Some((0, 10))));
        assert_eq!(v(0, false, None, 10, W).0, B::Clear, "nothing to embed needs no embedder");
    }

    #[test]
    fn work_without_the_embedder_is_its_own_verdict() {
        assert_eq!(v(7, false, Some((7, 0)), 99_999, W), (B::NoEmbedder { now: 7 }, None));
    }

    #[test]
    fn first_sighting_records_a_baseline() {
        assert_eq!(v(40, true, None, 100, W), (B::Watching { now: 40, prev: None }, Some((40, 100))));
    }

    #[test]
    fn inside_the_window_it_only_watches_and_keeps_the_old_snapshot() {
        assert_eq!(v(40, true, Some((40, 100)), 100 + W - 1, W), (B::Watching { now: 40, prev: Some(40) }, None));
    }

    #[test]
    fn shrinking_over_the_window_is_draining_and_advances_the_snapshot() {
        assert_eq!(v(30, true, Some((40, 0)), W, W), (B::Draining { prev: 40, now: 30 }, Some((30, W))));
    }

    #[test]
    fn not_shrinking_over_the_window_is_stalled_and_keeps_measuring_from_the_old_point() {
        assert_eq!(v(40, true, Some((40, 0)), W, W), (B::Stalled { prev: 40, now: 40, since_secs: W }, None));
        assert_eq!(v(41, true, Some((40, 0)), 2 * W, W), (B::Stalled { prev: 40, now: 41, since_secs: 2 * W }, None));
    }

    #[test]
    fn new_work_after_a_clear_snapshot_starts_a_fresh_window() {
        assert_eq!(v(12, true, Some((0, 0)), 5 * W, W), (B::Watching { now: 12, prev: Some(0) }, Some((12, 5 * W))));
    }
}
