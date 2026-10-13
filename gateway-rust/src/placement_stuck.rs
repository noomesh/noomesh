// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A placement that stays not-running pages someone.
//!
//! ## Why this exists
//!
//! `desired_state: running` is intent. The node's own report — the ACTUAL
//! column of `noo cluster desired` — is reality, and on 2026-09-14 a harness
//! failed to start every five minutes for over half an hour while the only
//! screen an operator reads said `Running`. The node now reports why
//! (`reconcile_refusals`), and the CLI shows it, but nothing *looked*: a
//! placement could sit not-running for days and no one was told.
//!
//! This loop compares every `running` placement against what its node
//! reports, remembers how long each has been missing, and raises ONE
//! `placement.stuck` through the operator-alert funnel once it has been
//! missing for [`STUCK_AFTER_SECS`]. The funnel dedups per (kind, target) and
//! the channel gets a general line, the command, and a ref id; the node's own
//! reason (`pull image …: unauthorized`) is logged under that ref, never sent.
//!
//! ## What it will not judge
//!
//! Absence of a report is not a negative. A node that is not `online`/`busy`,
//! that sent no `running_backends` object (an older agent, or no heartbeat
//! yet), or whose harness has no `host_services` entry says nothing about
//! whether the placement runs, so its clock is cleared rather than started.
//! Offline nodes have their own alerts; this one is for a node that is up,
//! talking, and not doing what it was told.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::Value;

use crate::state::AppState;

/// The node-agent reconciles every five minutes; three missed rounds is
/// "stuck", one is "pulling a large image".
const STUCK_AFTER_SECS: u64 = 900;
const INTERVAL_SECS: u64 = 300;
const STARTUP_GRACE_SECS: u64 = 180;
/// A stuck placement is a standing condition, not an event stream.
const ALERT_COOLDOWN_SECS: i64 = 21_600;

/// One placement the node is not running.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Missing {
    pub node: String,
    pub backend: String,
}

/// Is `backend` running, per what the NODE reports? `None` = the node has
/// not said, so nothing can be concluded. Same reading as the CLI's
/// ACTUAL column: host services report a state, containers are present or
/// absent in `running_backends`.
fn reported_running(node: &Value, backend: &str) -> Option<bool> {
    if !matches!(node["status"].as_str(), Some("online" | "busy")) {
        return None;
    }
    if let Some(st) = node["host_services"][backend]["state"].as_str() {
        return if st.is_empty() { None } else { Some(st == "running") };
    }
    // The harness is a host service: no entry means the agent has not
    // reported it, not that it is stopped.
    if backend == "harness" {
        return None;
    }
    let up = node["running_backends"].as_object().map(|rb| rb.contains_key(backend))?;
    // The container runs but the node reports its model absent: an Ollama that cannot serve the placement is not running it.
    // Only a REPORTED absence counts; silence leaves the container answer.
    if up && crate::model_presence::backend_model_missing(node, backend) {
        return Some(false);
    }
    Some(up)
}

/// The command that puts an import-only model back on its node, when the
/// node reports that is what is missing. Such a model is not on the public
/// registry, so the remedy is the import verb, never a pull.
fn import_remedy(node: &Value, node_id: &str, backend: &str) -> Option<String> {
    let e = crate::model_presence::missing_entry(node, backend)?;
    if e["import_only"].as_bool() != Some(true) {
        return None;
    }
    let model = e["model"].as_str().filter(|m| !m.is_empty())?;
    let role = e["role"].as_str().filter(|r| !r.is_empty()).unwrap_or("chat");
    Some(format!("noo cluster import-model {node_id} {model} --place --role {role}"))
}

/// The placements, among `wanted` (node, backend), that their node reports
/// not running.
pub fn not_running(wanted: &[(String, String)], nodes: &[Value]) -> Vec<Missing> {
    wanted
        .iter()
        .filter_map(|(node_id, backend)| {
            let n = nodes.iter().find(|n| n["id"].as_str() == Some(node_id.as_str()))?;
            (reported_running(n, backend) == Some(false))
                .then(|| Missing { node: node_id.clone(), backend: backend.clone() })
        })
        .collect()
}

/// How long each placement has been continuously missing.
#[derive(Default)]
pub struct Clock {
    since: HashMap<Missing, u64>,
}

impl Clock {
    /// Feed one observation; returns the placements that have now been
    /// missing for at least `after` seconds. Anything not in `missing`
    /// (started, unplaced, node stopped reporting) loses its clock — a
    /// placement that comes up and falls over again starts counting afresh.
    pub fn observe(&mut self, now: u64, missing: &[Missing], after: u64) -> Vec<Missing> {
        let current: HashSet<&Missing> = missing.iter().collect();
        self.since.retain(|k, _| current.contains(k));
        for m in missing {
            self.since.entry(m.clone()).or_insert(now);
        }
        missing
            .iter()
            .filter(|m| now.saturating_sub(self.since[*m]) >= after)
            .cloned()
            .collect()
    }
}

fn clock() -> &'static Mutex<Clock> {
    static C: OnceLock<Mutex<Clock>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(Clock::default()))
}

/// The node's own standing reason for a backend, from its heartbeat.
fn refusal_reason(node: &Value, backend: &str) -> Option<String> {
    node["reconcile_refusals"].as_array()?.iter().find_map(|r| {
        (r["target"].as_str() == Some(backend))
            .then(|| r["reason"].as_str().unwrap_or("refused").to_string())
    })
}

pub async fn tick(state: &Arc<AppState>) -> anyhow::Result<()> {
    // A DB failure is the loop's error (logged by the managed loop) and
    // leaves every clock where it was: an unreadable table is not "all
    // placements are fine".
    let mut wanted: Vec<(String, String)> = sqlx::query_as(
        "SELECT node_id, backend FROM noo_backend_placements WHERE desired_state = 'running'",
    )
    .fetch_all(&state.db)
    .await?;
    // Keyed (node, backend, role): one ollama serving chat + embed is two
    // rows and ONE stuck clock.
    wanted.sort();
    wanted.dedup();
    let (nodes, _merge_err) = crate::routes::cluster::collect_cluster_nodes(state).await;
    let missing = not_running(&wanted, &nodes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let stuck = {
        let mut c = clock().lock().unwrap_or_else(|p| p.into_inner());
        c.observe(now, &missing, STUCK_AFTER_SECS)
    };
    for m in stuck {
        let node = nodes.iter().find(|n| n["id"].as_str() == Some(m.node.as_str()));
        let reason = node
            .and_then(|n| refusal_reason(n, &m.backend))
            .unwrap_or_else(|| "the node reported no reason".to_string());
        tracing::warn!(node = %m.node, backend = %m.backend, reason = %reason, "placement_stuck");
        crate::operator_alert::send_operator_alert_with(
            state,
            crate::operator_alert::OperatorAlert::new(
                "placement.stuck",
                &format!("{}:{}", m.node, m.backend),
                format!(
                    "Placement '{}' on node '{}' is meant to be running and has not been for over {} minutes.",
                    m.backend,
                    m.node,
                    STUCK_AFTER_SECS / 60
                ),
            )
            .detail(format!("node reports: {reason}"))
            .investigate(
                node.and_then(|n| import_remedy(n, &m.node, &m.backend))
                    .unwrap_or_else(|| format!("noo cluster desired {}", m.node)),
            ),
            ALERT_COOLDOWN_SECS,
        )
        .await;
    }
    Ok(())
}

pub fn spawn(state: Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new("placement_stuck", INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .spawn(state, move |state| async move { tick(&state).await });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn w(n: &str, b: &str) -> (String, String) {
        (n.to_string(), b.to_string())
    }

    #[test]
    fn a_wanted_backend_absent_from_a_reporting_node_is_missing() {
        let nodes = vec![json!({"id": "host3", "status": "online", "running_backends": {"llamacpp": "x"}})];
        let m = not_running(&[w("host3", "vllm"), w("host3", "llamacpp")], &nodes);
        assert_eq!(m, vec![Missing { node: "host3".into(), backend: "vllm".into() }]);
    }

    #[test]
    fn silence_is_not_a_negative() {
        let nodes = vec![
            json!({"id": "old", "status": "online"}),                                         // no running_backends
            json!({"id": "down", "status": "offline", "running_backends": {}}),               // not up
            json!({"id": "unk", "status": "unknown", "running_backends": {}}),                // gossip/heartbeat disagree
            json!({"id": "h", "status": "online", "running_backends": {}}),                   // harness never reported
        ];
        let wanted = [w("old", "vllm"), w("down", "vllm"), w("unk", "vllm"), w("h", "harness"), w("gone", "vllm")];
        assert!(not_running(&wanted, &nodes).is_empty());
    }

    /// host9, 2026-10-03: container up, model absent. The node is reporting;
    /// what it reports is that the placement cannot serve.
    #[test]
    fn a_running_container_without_its_model_is_not_running_the_placement() {
        let host9 = vec![json!({"id": "host9", "status": "online", "running_backends": {"ollama": "harrier"},
            "model_presence": {"ollama": {"model": "harrier", "role": "embed", "present": false, "import_only": true}}})];
        assert_eq!(not_running(&[w("host9", "ollama")], &host9),
            vec![Missing { node: "host9".into(), backend: "ollama".into() }]);
        assert_eq!(import_remedy(&host9[0], "host9", "ollama").as_deref(),
            Some("noo cluster import-model host9 harrier --place --role embed"));
    }

    #[test]
    fn an_old_agent_with_the_container_up_still_reads_running() {
        let old = vec![json!({"id": "old", "status": "online", "running_backends": {"ollama": "harrier"}})];
        assert!(not_running(&[w("old", "ollama")], &old).is_empty());
        let held = vec![json!({"id": "n", "status": "online", "running_backends": {"ollama": "harrier"},
            "model_presence": {"ollama": {"model": "harrier", "role": "embed", "present": true}}})];
        assert!(not_running(&[w("n", "ollama")], &held).is_empty());
        assert_eq!(import_remedy(&held[0], "n", "ollama"), None);
    }

    #[test]
    fn the_harness_reads_its_host_service_state() {
        let nodes = vec![json!({"id": "a", "status": "online", "running_backends": {},
            "host_services": {"harness": {"state": "stopped"}}})];
        assert_eq!(not_running(&[w("a", "harness")], &nodes).len(), 1);
        let up = vec![json!({"id": "a", "status": "online", "running_backends": {},
            "host_services": {"harness": {"state": "running"}}})];
        assert!(not_running(&[w("a", "harness")], &up).is_empty());
    }

    #[test]
    fn stuck_only_after_the_window_and_only_while_continuously_missing() {
        let m = Missing { node: "host3".into(), backend: "vllm".into() };
        let mut c = Clock::default();
        assert!(c.observe(1000, std::slice::from_ref(&m), 900).is_empty());
        assert!(c.observe(1600, std::slice::from_ref(&m), 900).is_empty());
        assert_eq!(c.observe(1900, std::slice::from_ref(&m), 900), vec![m.clone()]);
        // It came up for one round: the clock is gone and the next absence
        // starts from zero.
        assert!(c.observe(2200, &[], 900).is_empty());
        assert!(c.observe(2500, std::slice::from_ref(&m), 900).is_empty());
        assert!(c.observe(3300, std::slice::from_ref(&m), 900).is_empty());
        assert_eq!(c.observe(3400, std::slice::from_ref(&m), 900), vec![m]);
    }

    #[test]
    fn the_nodes_reason_is_read_from_its_refusals() {
        let n = json!({"reconcile_refusals": [
            {"scope": "backend_start", "target": "vllm", "reason": "pull image: unauthorized"}]});
        assert_eq!(refusal_reason(&n, "vllm").as_deref(), Some("pull image: unauthorized"));
        assert_eq!(refusal_reason(&n, "ollama"), None);
    }
}
