// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Cluster management API for in-process Rust callers.
//!
//! Ports the never-wired Python `cluster/agent_api.py::ClusterManager`
//! into Rust. The original Python class wrapped HTTP calls back to the
//! gateway so agents could programmatically check status / start backends
//! / read queue depth. That functionality is now exposed to LLM agents
//! via MCP tools (`noo_cluster_status`, `noo_models_pull`, `noo_inference`),
//! but in-process Rust callers (heartbeat tasks, autonomy actions) still
//! need a clean API surface.
//!
//! This is MESH-side. It does NOT call out to NATS workers — it reads
//! state directly from the Rust gateway's `AppState` (gossip peers,
//! Redis job queue, NATS KV). For LLM-facing access, use the MCP tools.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::state::AppState;

/// Snapshot of cluster state suitable for in-process decisions.
pub struct ClusterStatus {
    pub alive_node_count: usize,
    pub running_backend_count: usize,
    pub avg_load: f64,
    pub job_queue_depth: i64,
}

impl ClusterStatus {
    pub async fn snapshot(state: &AppState) -> Self {
        let peers = state.gossip.alive_peers();
        let alive_node_count = peers.len();
        let running_backend_count: usize = peers.iter().map(|p| p.backends.len()).sum();
        let avg_load: f64 = if peers.is_empty() {
            0.0
        } else {
            peers.iter().map(|p| p.load).sum::<f64>() / peers.len() as f64
        };
        let job_queue_depth = read_queue_depth(state).await;
        Self {
            alive_node_count,
            running_backend_count,
            avg_load,
            job_queue_depth,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "alive_node_count": self.alive_node_count,
            "running_backend_count": self.running_backend_count,
            "avg_load": self.avg_load,
            "job_queue_depth": self.job_queue_depth,
        })
    }

    /// "Do we need a fast inference backend right now?" — convenience
    /// for autonomy/heartbeat callers. True if zero backends are running.
    pub fn needs_fast_backend(&self) -> bool {
        self.running_backend_count == 0
    }
}

async fn read_queue_depth(state: &AppState) -> i64 {
    match state.redis.as_ref() {
        Some(r) => r.zcard("noo:jobs:queue").await,
        None => 0,
    }
}

/// Identify nodes whose load is above `threshold` for capacity planning.
pub fn hot_nodes(state: &Arc<AppState>, threshold: f64) -> Vec<String> {
    state
        .gossip
        .alive_peers()
        .into_iter()
        .filter(|p| p.load > threshold)
        .map(|p| p.node_id)
        .collect()
}

/// Identify GPU (tier 1) nodes that are alive — useful for routing
/// inference-heavy tasks.
pub fn gpu_nodes(state: &Arc<AppState>) -> Vec<String> {
    state
        .gossip
        .alive_peers()
        .into_iter()
        .filter(|p| p.tier == 1)
        .map(|p| p.node_id)
        .collect()
}
