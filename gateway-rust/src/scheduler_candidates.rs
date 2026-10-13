// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Candidate node selection for the scheduler port.
//!
//! Phase 4. This is the piece the
//! original plan understated: `_try_dispatch_job` asks
//! `router.get_candidate_nodes()` for nodes ranked best-fit-first, and
//! Rust had no equivalent — it reads `mesh_nodes` KV but never ranked.
//!
//! Placement is where a silent divergence would actually hurt: slot maths
//! wrong means a job waits, placement wrong means a job runs on the wrong
//! box (or a companion that cannot run it at all). So this mirrors the
//! Python pipeline step for step, in the same order, and the tests are
//! written against the ordering rather than a single "best" answer.
//!
//! Pure functions over a snapshot — no NATS, no Redis. Phase 5 feeds it
//! real `mesh_nodes` data and compares against Python's choices.
#![allow(dead_code)]

use crate::scheduler_job::TaskPriority;
use crate::scheduler_slots;
use serde_json::Value;

/// Node status, mirroring `cluster/node.py::NodeStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Online,
    Busy,
    Offline,
    Quarantined,
}

impl NodeStatus {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "online" => NodeStatus::Online,
            "busy" => NodeStatus::Busy,
            "quarantined" => NodeStatus::Quarantined,
            _ => NodeStatus::Offline,
        }
    }
}

/// The fields placement actually reads from a node record.
#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub id: String,
    pub status: NodeStatus,
    /// Raw tier as reported; normalised via `scheduler_slots::normalize_tier`.
    pub tier: Value,
    pub is_companion: bool,
    /// Seconds since the last heartbeat. `None` = never heartbeated.
    pub heartbeat_age_secs: Option<f64>,
    pub current_load: f64,
    pub vram_gb: f64,
    /// Live VRAM usage; `None` when the agent doesn't report it.
    pub vram_used_gb: Option<f64>,
    /// What the node CAN serve (`capabilities.backends`). Informational for
    /// placement: capable is not serving.
    pub backends: Vec<String>,
    /// What the node is serving NOW (keys of `running_backends`). `None` =
    /// the record never carried the field (pre-heartbeat / legacy record),
    /// in which case placement falls back to `backends`. `Some(vec![])` is a
    /// real answer: serving nothing.
    pub running_backends: Option<Vec<String>>,
    // Companion gating (CompanionPolicy). All optional — absent means
    // "not applicable", which the policy treats as passing.
    pub battery_pct: Option<f64>,
    pub network_type: Option<String>,
    pub thermal_state: Option<String>,
}

/// `None` when some healthy node is serving `backend` (the job can be
/// placed); otherwise the sentence explaining why not, naming who serves what
/// and who could but is not. Used at submit time (refuse) and by the
/// dispatcher (`status_detail` on a job that would otherwise sit silent).
pub fn backend_unserved_reason(nodes: &[NodeSnapshot], backend: &str) -> Option<String> {
    let healthy: Vec<&NodeSnapshot> = nodes.iter().filter(|n| n.is_healthy()).collect();
    if healthy.iter().any(|n| n.can_run_backend(backend)) {
        return None;
    }
    let capable: Vec<&str> = healthy
        .iter()
        .filter(|n| n.declares_backend(backend))
        .map(|n| n.id.as_str())
        .collect();
    let serving: Vec<String> = healthy
        .iter()
        .map(|n| {
            format!(
                "{}=[{}]",
                n.id,
                n.running_backends.as_deref().unwrap_or(&[]).join(",")
            )
        })
        .collect();
    Some(format!(
        "no node is serving {backend}; capable but not serving: [{}]; nodes serve: {}. \
         Start the backend (place it on a node) or pin with force_node",
        capable.join(", "),
        if serving.is_empty() { "no healthy nodes".to_string() } else { serving.join(" ") },
    ))
}

/// Heartbeat timeouts from `Node.is_healthy` — companions get 10 minutes
/// because they report every 10, workers 2.
const WORKER_HEARTBEAT_TIMEOUT_SECS: f64 = 120.0;
const COMPANION_HEARTBEAT_TIMEOUT_SECS: f64 = 600.0;

/// Load at or above which a node is considered full (`has_capacity`).
///
/// **Node load is normalised 0.0–1.0**, not a percentage: it is the 1-minute
/// load average divided by core count (`hardware/system.go` `CPULoad`), carried
/// verbatim through the heartbeat into the `mesh_nodes` KV. Every consumer must
/// spell the threshold on that scale, which is why this constant is shared
/// rather than re-written per call site — the chat resolver had its own copy as
/// `80.0`, so its guard could never fire for any node.
pub(crate) const LOAD_CEILING: f64 = 0.9;

impl NodeSnapshot {
    /// Mirrors `Node.is_healthy()`.
    pub fn is_healthy(&self) -> bool {
        if self.status == NodeStatus::Quarantined {
            return false;
        }
        let Some(age) = self.heartbeat_age_secs else {
            return false; // never heartbeated
        };
        let timeout = if self.is_companion {
            COMPANION_HEARTBEAT_TIMEOUT_SECS
        } else {
            WORKER_HEARTBEAT_TIMEOUT_SECS
        };
        age <= timeout
    }

    /// Mirrors `Node.free_vram_gb()`.
    ///
    /// Falls back to TOTAL when usage isn't reported, so a node that is
    /// simply blind to its own usage is never wrongly blocked — load% is
    /// the backstop. Strict only when there is real data.
    pub fn free_vram_gb(&self) -> f64 {
        let total = self.vram_gb.max(0.0);
        match self.vram_used_gb {
            None => total,
            Some(used) => (total - used).max(0.0),
        }
    }

    /// Mirrors `Node.has_capacity()`.
    ///
    /// Note this requires status ONLINE specifically — a BUSY node has
    /// no capacity even though `is_healthy()` would pass it.
    pub fn has_capacity(&self, min_vram_gb: f64) -> bool {
        if self.status != NodeStatus::Online {
            return false;
        }
        if self.current_load >= LOAD_CEILING {
            return false;
        }
        if min_vram_gb > 0.0 && self.free_vram_gb() < min_vram_gb {
            return false;
        }
        true
    }

    /// Whether this node is SERVING `backend` right now.
    ///
    /// Python's `can_run_backend()` checked declared capability, and every
    /// x86 node declares vllm/ollama/airllm/llamacpp. The node agent then
    /// dials the `noo-<backend>` container by name, which only resolves where
    /// that backend is up — so a capable-but-idle node cannot run the job
    /// and there is deliberately no capability fallback.
    /// Only a record that never reported `running_backends` is judged by
    /// capability, since "not reported" is not "not serving".
    pub fn can_run_backend(&self, backend: &str) -> bool {
        match &self.running_backends {
            Some(r) => r.iter().any(|b| b == backend),
            None => self.backends.iter().any(|b| b == backend),
        }
    }

    /// Whether `backend` is declared in `capabilities.backends`.
    pub fn declares_backend(&self, backend: &str) -> bool {
        self.backends.iter().any(|b| b == backend)
    }

    /// Mirrors `CompanionPolicy.is_eligible()` — non-companions pass
    /// through unconditionally.
    ///
    /// Each check is skipped when its telemetry is absent, matching
    /// Python's `if node.battery_pct is not None` / `if ... and
    /// node.network_type` guards. That is why a companion reporting
    /// `network_type: ""` (the honest "unknown" a bridged agent reports)
    /// is not blocked.
    pub fn passes_companion_policy(&self, policy: &CompanionPolicy) -> bool {
        if !self.is_companion {
            return true;
        }
        if let Some(pct) = self.battery_pct {
            if pct < policy.min_battery_pct {
                return false;
            }
        }
        if policy.require_wifi {
            if let Some(net) = self.network_type.as_deref().filter(|s| !s.is_empty()) {
                if !policy.allowed_network_types.iter().any(|a| a == net) {
                    return false;
                }
            }
        }
        if let Some(t) = self.thermal_state.as_deref().filter(|s| !s.is_empty()) {
            if policy.blocked_thermal_states.iter().any(|b| b == t) {
                return false;
            }
        }
        true
    }
}

/// When a companion may take work. The DEFAULT is the gateway's own; a
/// node may carry its own in desired state (`noo_node_config.companion_policy`,
/// migration 064), set with `noo cluster set-config`
/// or the seed file. Until 064 these values were fixed here while thirteen
/// `companion:` YAML fields nothing read described them.
#[derive(Debug, Clone, PartialEq)]
pub struct CompanionPolicy {
    pub min_battery_pct: f64,
    pub require_wifi: bool,
    pub allowed_network_types: Vec<String>,
    pub blocked_thermal_states: Vec<String>,
}

impl Default for CompanionPolicy {
    fn default() -> Self {
        Self {
            min_battery_pct: 25.0,
            require_wifi: true,
            allowed_network_types: vec!["wifi".into(), "ethernet".into()],
            blocked_thermal_states: vec!["serious".into(), "critical".into()],
        }
    }
}

/// The keys a stored policy may carry — the three checks the scheduler
/// actually enforces, and nothing else. `allowed_network_types` is derived
/// from `require_wifi`, not stored: the toggle is the operator's word,
/// the list is how the code spells it.
pub const COMPANION_POLICY_KEYS: &[&str] = &["min_battery_pct", "require_wifi", "blocked_thermal_states"];

impl CompanionPolicy {
    /// A stored policy overlaid on the default. Missing keys keep the
    /// default; a key of the wrong type is ignored rather than fatal,
    /// because a bad row must not stop the scheduler — `validate` is the
    /// write-time gate that keeps such rows from existing.
    pub fn from_json(v: &serde_json::Value) -> Self {
        let mut p = Self::default();
        if let Some(pct) = v.get("min_battery_pct").and_then(serde_json::Value::as_f64) {
            p.min_battery_pct = pct.clamp(0.0, 100.0);
        }
        if let Some(w) = v.get("require_wifi").and_then(serde_json::Value::as_bool) {
            p.require_wifi = w;
        }
        if let Some(arr) = v.get("blocked_thermal_states").and_then(serde_json::Value::as_array) {
            p.blocked_thermal_states = arr.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
        }
        p
    }

    /// The write-time gate for `PUT /api/cluster/nodes/{id}/config`: an
    /// object, known keys only, sane ranges. Returns the reason, not a bool,
    /// so the operator sees WHICH key was wrong.
    pub fn validate(v: &serde_json::Value) -> Result<(), String> {
        let Some(obj) = v.as_object() else {
            return Err("companion_policy must be an object".into());
        };
        for k in obj.keys() {
            if !COMPANION_POLICY_KEYS.contains(&k.as_str()) {
                return Err(format!("companion_policy: unknown key '{k}' (allowed: {})", COMPANION_POLICY_KEYS.join(", ")));
            }
        }
        if let Some(x) = obj.get("min_battery_pct") {
            match x.as_f64() {
                Some(pct) if (0.0..=100.0).contains(&pct) => {}
                _ => return Err("companion_policy.min_battery_pct must be a number in 0..=100".into()),
            }
        }
        if let Some(x) = obj.get("require_wifi") {
            if !x.is_boolean() {
                return Err("companion_policy.require_wifi must be true or false".into());
            }
        }
        if let Some(x) = obj.get("blocked_thermal_states") {
            let ok = x.as_array().is_some_and(|a| a.iter().all(|s| s.as_str().is_some_and(|t| !t.trim().is_empty())));
            if !ok {
                return Err("companion_policy.blocked_thermal_states must be a list of non-empty strings".into());
            }
        }
        Ok(())
    }
}

/// The scheduler's view: one default plus whatever nodes declared their
/// own. Loaded once per tick (`scheduler_engine::load_companion_policies`).
#[derive(Debug, Clone, Default)]
pub struct CompanionPolicies {
    pub default: CompanionPolicy,
    pub per_node: std::collections::HashMap<String, CompanionPolicy>,
}

impl CompanionPolicies {
    pub fn for_node(&self, node_id: &str) -> &CompanionPolicy {
        self.per_node.get(node_id).unwrap_or(&self.default)
    }
}

/// Mirrors `TaskRouter.get_candidate_nodes()` — all suitable nodes,
/// sorted best-first (least loaded).
///
/// Order of operations matters and matches Python exactly:
///   1. `force_node` short-circuits — that node if healthy, else NOTHING.
///      It does NOT fall back to other candidates; a pinned job either
///      runs where it was pinned or waits.
///   2. healthy + backend filter
///   3. capacity (status/load/VRAM)
///   4. companion policy
///   5. HIGH priority prefers tier 1 — but only if any tier-1 survived;
///      otherwise the full list stands (a preference, not a requirement)
///   6. sort by current_load ascending
pub fn get_candidate_nodes<'a>(
    nodes: &'a [NodeSnapshot],
    backend: Option<&str>,
    force_node: Option<&str>,
    priority: TaskPriority,
    min_vram_gb: f64,
    policies: &CompanionPolicies,
) -> Vec<&'a NodeSnapshot> {
    if let Some(pin) = force_node {
        return nodes
            .iter()
            .find(|n| n.id == pin && n.is_healthy())
            .into_iter()
            .collect();
    }

    let mut candidates: Vec<&NodeSnapshot> = nodes
        .iter()
        .filter(|n| n.is_healthy())
        .filter(|n| backend.is_none_or(|b| n.can_run_backend(b)))
        .filter(|n| n.has_capacity(min_vram_gb))
        .filter(|n| n.passes_companion_policy(policies.for_node(&n.id)))
        .collect();

    if priority == TaskPriority::High {
        let tier1: Vec<&NodeSnapshot> = candidates
            .iter()
            .copied()
            .filter(|n| scheduler_slots::normalize_tier(&n.tier) == Some(1))
            .collect();
        if !tier1.is_empty() {
            candidates = tier1;
        }
    }

    // Stable sort by load, so equal-load nodes keep registry order —
    // matching Python's list.sort(), which is also stable.
    candidates.sort_by(|a, b| {
        a.current_load
            .partial_cmp(&b.current_load)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    candidates
}

/// Mirrors the two-pass placement inside `_try_dispatch_job`.
///
/// First pass skips the node that most recently failed to ack this job;
/// second pass allows it again, because it may be the only node capable
/// of running the job. Returns the chosen node id.
///
/// `slots_for` supplies the node's current occupancy (cardinality of
/// `noo:jobs:node:<id>`); `require_all_slots_free` is set for background
/// jobs, which may only start on a completely idle node.
pub fn pick_node<'a, F>(
    candidates: &[&'a NodeSnapshot],
    last_failed_node: Option<&str>,
    require_all_slots_free: bool,
    mut slots_for: F,
) -> Option<&'a NodeSnapshot>
where
    F: FnMut(&str) -> u32,
{
    for skip_failed in [true, false] {
        for cand in candidates {
            if skip_failed {
                if let Some(avoid) = last_failed_node {
                    if cand.id == avoid {
                        continue;
                    }
                }
            }
            let current = slots_for(&cand.id);
            let ok = if require_all_slots_free {
                current == 0
            } else {
                scheduler_slots::has_slots(&cand.tier, false, current)
            };
            if ok {
                return Some(cand);
            }
        }
        // Only worth a second pass if the first actually skipped something.
        if last_failed_node.is_none() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(id: &str, tier: i64, load: f64) -> NodeSnapshot {
        NodeSnapshot {
            id: id.into(),
            status: NodeStatus::Online,
            tier: json!(tier),
            is_companion: tier == 5,
            heartbeat_age_secs: Some(10.0),
            current_load: load,
            vram_gb: 16.0,
            vram_used_gb: None,
            backends: vec!["vllm".into(), "llamacpp".into()],
            running_backends: None,
            battery_pct: None,
            network_type: None,
            thermal_state: None,
        }
    }

    /// three nodes all CAN run vllm, only one is serving it.
    fn three_capable_one_serving() -> Vec<NodeSnapshot> {
        let mut nodes = vec![node("host2", 1, 0.1), node("host8", 1, 0.2), node("host3", 1, 0.8)];
        for n in &mut nodes {
            n.backends = vec!["ollama".into(), "vllm".into(), "airllm".into(), "llamacpp".into()];
            n.running_backends = Some(vec!["ollama".into()]);
        }
        nodes[2].running_backends = Some(vec!["vllm".into()]);
        nodes
    }

    #[test]
    fn job_lands_on_the_node_serving_the_backend_not_one_that_could() {
        let nodes = three_capable_one_serving();
        // host2/host8 are less loaded and would win on load alone.
        let c = get_candidate_nodes(&nodes, Some("vllm"), None, TaskPriority::Medium, 0.0, &pol());
        assert_eq!(c.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), vec!["host3"]);
        // A pinned job is unchanged: force_node skips the filter.
        let c = get_candidate_nodes(&nodes, Some("vllm"), Some("host2"), TaskPriority::Medium, 0.0, &pol());
        assert_eq!(c.len(), 1);
        assert!(backend_unserved_reason(&nodes, "vllm").is_none());
    }

    #[test]
    fn a_backend_nobody_serves_is_refused_with_the_named_reason() {
        let mut nodes = three_capable_one_serving();
        nodes[2].running_backends = Some(vec!["ollama".into()]);
        let c = get_candidate_nodes(&nodes, Some("vllm"), None, TaskPriority::Medium, 0.0, &pol());
        assert!(c.is_empty(), "capable-but-idle nodes must not be candidates");
        let r = backend_unserved_reason(&nodes, "vllm").expect("nobody serves vllm");
        assert!(r.contains("no node is serving vllm"), "{r}");
        assert!(r.contains("host2") && r.contains("host8") && r.contains("host3=[ollama]"), "{r}");
    }

    #[test]
    fn a_record_that_never_reported_running_backends_falls_back_to_capability() {
        let mut n = node("old", 1, 0.1);
        n.running_backends = None;
        assert!(n.can_run_backend("vllm"));
        n.running_backends = Some(vec![]);
        assert!(!n.can_run_backend("vllm"));
    }

    fn pol() -> CompanionPolicies {
        CompanionPolicies::default()
    }

    #[test]
    fn stored_policy_overlays_the_default_and_validates() {
        use serde_json::json;
        let p = CompanionPolicy::from_json(&json!({"min_battery_pct": 40}));
        assert_eq!(p.min_battery_pct, 40.0);
        assert!(p.require_wifi, "untouched keys keep the default");
        assert_eq!(p.blocked_thermal_states, vec!["serious", "critical"]);
        // Out-of-range clamps on READ (a bad row must not stop dispatch)…
        assert_eq!(CompanionPolicy::from_json(&json!({"min_battery_pct": 250})).min_battery_pct, 100.0);
        // …but is refused on WRITE, naming the key.
        let e = CompanionPolicy::validate(&json!({"min_battery_pct": 250})).unwrap_err();
        assert!(e.contains("min_battery_pct"), "{e}");
        let e = CompanionPolicy::validate(&json!({"max_model_params_b": 3})).unwrap_err();
        assert!(e.contains("unknown key"), "{e}");
        assert!(CompanionPolicy::validate(&json!({"require_wifi": "yes"})).is_err());
        assert!(CompanionPolicy::validate(&json!({"blocked_thermal_states": ["", "critical"]})).is_err());
        assert!(CompanionPolicy::validate(&json!({"require_wifi": false, "blocked_thermal_states": ["critical"]})).is_ok());
        assert!(CompanionPolicy::validate(&json!([])).is_err());
    }

    #[test]
    fn a_node_with_its_own_policy_is_judged_by_it() {
        let mut lenient = CompanionPolicies::default();
        lenient.per_node.insert(
            "phone".into(),
            CompanionPolicy::from_json(&serde_json::json!({"min_battery_pct": 10, "require_wifi": false})),
        );
        let mut phone = node("phone", 5, 0.0);
        phone.is_companion = true;
        phone.battery_pct = Some(15.0);
        phone.network_type = Some("cellular".into());
        // Under the default it is out (battery < 25, not on wifi)…
        assert!(get_candidate_nodes(std::slice::from_ref(&phone), None, None, TaskPriority::Medium, 0.0, &pol()).is_empty());
        // …under its own policy it is in.
        assert_eq!(get_candidate_nodes(std::slice::from_ref(&phone), None, None, TaskPriority::Medium, 0.0, &lenient).len(), 1);
        // Another companion without a row still gets the default.
        let mut tablet = node("tablet", 5, 0.0);
        tablet.is_companion = true;
        tablet.battery_pct = Some(15.0);
        assert!(get_candidate_nodes(std::slice::from_ref(&tablet), None, None, TaskPriority::Medium, 0.0, &lenient).is_empty());
    }

    // ── health ──────────────────────────────────────────────────────

    #[test]
    fn quarantined_is_never_healthy() {
        let mut n = node("a", 1, 0.0);
        n.status = NodeStatus::Quarantined;
        assert!(!n.is_healthy());
    }

    #[test]
    fn never_heartbeated_is_not_healthy() {
        let mut n = node("a", 1, 0.0);
        n.heartbeat_age_secs = None;
        assert!(!n.is_healthy());
    }

    #[test]
    fn companions_get_a_longer_heartbeat_window() {
        let mut worker = node("w", 3, 0.0);
        worker.heartbeat_age_secs = Some(300.0); // 5 min
        assert!(!worker.is_healthy(), "worker times out at 2 min");

        let mut companion = node("c", 5, 0.0);
        companion.heartbeat_age_secs = Some(300.0);
        assert!(companion.is_healthy(), "companion has 10 min");

        companion.heartbeat_age_secs = Some(601.0);
        assert!(!companion.is_healthy());
    }

    // ── capacity ────────────────────────────────────────────────────

    #[test]
    fn busy_status_has_no_capacity_even_though_healthy() {
        let mut n = node("a", 1, 0.1);
        n.status = NodeStatus::Busy;
        assert!(n.is_healthy(), "BUSY still heartbeats");
        assert!(!n.has_capacity(0.0), "but ONLINE is required for capacity");
    }

    #[test]
    fn load_ceiling_is_ninety_percent() {
        assert!(node("a", 1, 0.89).has_capacity(0.0));
        assert!(!node("a", 1, 0.9).has_capacity(0.0), "boundary is inclusive");
    }

    #[test]
    fn missing_vram_telemetry_does_not_block_placement() {
        // vram_used_gb = None -> free == total, so a blind node stays
        // eligible; load% is the backstop.
        let n = node("a", 1, 0.0);
        assert_eq!(n.free_vram_gb(), 16.0);
        assert!(n.has_capacity(12.0));
    }

    #[test]
    fn vram_check_uses_free_not_total() {
        let mut n = node("a", 1, 0.0);
        n.vram_used_gb = Some(12.0); // 4 GB free of 16
        assert_eq!(n.free_vram_gb(), 4.0);
        assert!(n.has_capacity(4.0));
        assert!(!n.has_capacity(6.0), "a hosted model must not be double-booked");
    }

    #[test]
    fn over_reported_usage_clamps_to_zero() {
        let mut n = node("a", 1, 0.0);
        n.vram_used_gb = Some(99.0);
        assert_eq!(n.free_vram_gb(), 0.0, "must not go negative");
    }

    // ── companion policy ────────────────────────────────────────────

    #[test]
    fn non_companion_ignores_the_policy() {
        let mut n = node("w", 3, 0.0);
        n.battery_pct = Some(1.0);
        n.thermal_state = Some("critical".into());
        assert!(n.passes_companion_policy(&pol().default));
    }

    #[test]
    fn companion_blocked_by_low_battery_and_heat() {
        let mut n = node("c", 5, 0.0);
        n.battery_pct = Some(10.0);
        assert!(!n.passes_companion_policy(&pol().default));

        n.battery_pct = Some(80.0);
        n.thermal_state = Some("serious".into());
        assert!(!n.passes_companion_policy(&pol().default));
    }

    /// The honest "unknown" a bridged agent reports must not block —
    /// matching Python's `if ... and node.network_type` guard.
    #[test]
    fn empty_or_absent_telemetry_does_not_block() {
        let mut n = node("c", 5, 0.0);
        n.network_type = Some("".into());
        n.thermal_state = Some("".into());
        assert!(n.passes_companion_policy(&pol().default));

        n.network_type = None;
        assert!(n.passes_companion_policy(&pol().default));
    }

    #[test]
    fn cellular_is_not_an_allowed_network() {
        let mut n = node("c", 5, 0.0);
        n.network_type = Some("cellular".into());
        assert!(!n.passes_companion_policy(&pol().default));
    }

    // ── candidate pipeline ──────────────────────────────────────────

    #[test]
    fn sorted_least_loaded_first() {
        let nodes = vec![node("busy", 1, 0.7), node("idle", 1, 0.1), node("mid", 1, 0.4)];
        let got = get_candidate_nodes(&nodes, None, None, TaskPriority::Medium, 0.0, &pol());
        let ids: Vec<&str> = got.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["idle", "mid", "busy"]);
    }

    #[test]
    fn backend_filter_applies() {
        let mut only_ollama = node("o", 3, 0.0);
        only_ollama.backends = vec!["ollama".into()];
        let nodes = vec![node("v", 1, 0.5), only_ollama];

        let got = get_candidate_nodes(&nodes, Some("vllm"), None, TaskPriority::Medium, 0.0, &pol());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "v");
    }

    /// force_node either runs where pinned or waits — it must NOT fall
    /// back to another node.
    #[test]
    fn force_node_does_not_fall_back() {
        let nodes = vec![node("a", 1, 0.0), node("b", 1, 0.0)];
        let got = get_candidate_nodes(&nodes, None, Some("b"), TaskPriority::Medium, 0.0, &pol());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "b");

        let got = get_candidate_nodes(&nodes, None, Some("nope"), TaskPriority::Medium, 0.0, &pol());
        assert!(got.is_empty(), "unknown pin yields nothing, not a fallback");
    }

    #[test]
    fn force_node_must_still_be_healthy() {
        let mut n = node("b", 1, 0.0);
        n.status = NodeStatus::Quarantined;
        let nodes = vec![node("a", 1, 0.0), n];
        let got = get_candidate_nodes(&nodes, None, Some("b"), TaskPriority::Medium, 0.0, &pol());
        assert!(got.is_empty());
    }

    #[test]
    fn high_priority_prefers_tier1_when_present() {
        let nodes = vec![node("t3", 3, 0.0), node("t1", 1, 0.8)];
        let got = get_candidate_nodes(&nodes, None, None, TaskPriority::High, 0.0, &pol());
        let ids: Vec<&str> = got.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["t1"], "tier 1 wins even when more loaded");
    }

    /// The tier-1 preference is a PREFERENCE — with no tier 1 available
    /// the full list stands rather than the job stalling.
    #[test]
    fn high_priority_falls_back_when_no_tier1() {
        let nodes = vec![node("t3", 3, 0.2), node("t2", 2, 0.1)];
        let got = get_candidate_nodes(&nodes, None, None, TaskPriority::High, 0.0, &pol());
        let ids: Vec<&str> = got.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["t2", "t3"]);
    }

    #[test]
    fn ineligible_companion_is_filtered_out() {
        let mut c = node("c", 5, 0.0);
        c.battery_pct = Some(5.0);
        let nodes = vec![node("w", 3, 0.5), c];
        let got = get_candidate_nodes(&nodes, None, None, TaskPriority::Medium, 0.0, &pol());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "w");
    }

    // ── two-pass placement ──────────────────────────────────────────

    #[test]
    fn skips_last_failed_node_on_the_first_pass() {
        let nodes = [node("a", 1, 0.0), node("b", 1, 0.1)];
        let cands: Vec<&NodeSnapshot> = nodes.iter().collect();
        // "a" would sort first but previously failed to ack.
        let got = pick_node(&cands, Some("a"), false, |_| 0).unwrap();
        assert_eq!(got.id, "b");
    }

    /// …but takes it on the second pass if nothing else can run the job.
    #[test]
    fn falls_back_to_the_failed_node_when_it_is_the_only_option() {
        let nodes = [node("a", 1, 0.0)];
        let cands: Vec<&NodeSnapshot> = nodes.iter().collect();
        let got = pick_node(&cands, Some("a"), false, |_| 0).unwrap();
        assert_eq!(got.id, "a");
    }

    #[test]
    fn background_requires_a_completely_idle_node() {
        let nodes = [node("a", 1, 0.0)];
        let cands: Vec<&NodeSnapshot> = nodes.iter().collect();
        // Tier 1 has 2 slots, so 1 occupied still leaves room for a
        // regular job — but not for a background one.
        assert!(pick_node(&cands, None, false, |_| 1).is_some());
        assert!(pick_node(&cands, None, true, |_| 1).is_none());
        assert!(pick_node(&cands, None, true, |_| 0).is_some());
    }

    #[test]
    fn full_nodes_yield_nothing() {
        let nodes = [node("a", 1, 0.0)];
        let cands: Vec<&NodeSnapshot> = nodes.iter().collect();
        assert!(pick_node(&cands, None, false, |_| 2).is_none(), "tier 1 caps at 2");
    }

    /// A companion has 0 slots, so it can never be picked even after
    /// surviving the candidate filters.
    #[test]
    fn companion_is_never_picked() {
        let nodes = [node("c", 5, 0.0)];
        let cands: Vec<&NodeSnapshot> = nodes.iter().collect();
        assert!(pick_node(&cands, None, false, |_| 0).is_none());
    }
}
