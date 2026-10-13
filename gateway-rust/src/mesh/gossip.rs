// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Gossip-based peer discovery — Rust implementation.
//!
//! Same NATS subjects and JSON protocol as Python's mesh_gossip.py.
//! A Python node-agent and Rust gateway interoperate transparently.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use serde::{Deserialize, Serialize};

const GOSSIP_ANNOUNCE: &str = "mesh.gossip.announce";
/// Node-scoped announce: `mesh.gossip.announce.<node_id>`.
///
/// Per-principal bus credentials grant a node
/// `mesh.gossip.announce.{id}` and nothing wider, so a node holding one CANNOT
/// publish the bare subject. The agent published the bare subject anyway, and
/// NATS reports permission violations asynchronously — `Publish` returned Ok,
/// the agent logged nothing, and gossip silently stopped. Every node that
/// received a per-principal credential went `unknown` and, because
/// `has_capacity` requires Online, became undispatchable while still
/// heartbeating and reporting a connected bus.
///
/// Both subjects are accepted: the bare one for the gateway's own announce and
/// for agents older than this change, the scoped one for current agents.
const GOSSIP_ANNOUNCE_SCOPED: &str = "mesh.gossip.announce.*";
const PEER_TTL_SECS: f64 = 90.0;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

// ── Announce hardening ──────
//
// `mesh.gossip.announce` carries NO per-message authentication: NATS does
// not surface the publisher, so any principal holding the (single, shared)
// cluster NATS credential can announce as any node id. Connection-level
// mTLS + user/password bounds that to "already a cluster node", but a peer
// must still not be able to hand the gateway unbounded or absurd values.
// These caps make an announce a *hint about resources*, never a source of
// addresses, identity, or authorization.
/// Announce payloads larger than this are dropped unparsed.
const MAX_ANNOUNCE_BYTES: usize = 8 * 1024;
/// Upper bound on distinct peers held in memory. Beyond this, only updates
/// to already-known peers are accepted — a peer cannot grow the map forever.
const MAX_PEERS: usize = 256;
const MAX_ID_LEN: usize = 64;
const MAX_HOSTNAME_LEN: usize = 128;
const MAX_CAPABILITIES: usize = 32;
const MAX_CAPABILITY_LEN: usize = 64;
const MAX_BACKENDS: usize = 8;
const MAX_BACKEND_KEY_LEN: usize = 32;
const MAX_MODEL_LEN: usize = 256;
/// Sanity ceiling on self-reported VRAM, so a peer cannot sort itself to the
/// front of every GPU-first ranking with an absurd number.
const MAX_VRAM_GB: f64 = 4096.0;
const MAX_TIER: u64 = 6;

/// Node ids and capability names are used in log lines, map keys and
/// comparisons — keep them to an unambiguous, non-injecting charset.
fn is_safe_token(s: &str, max_len: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_len
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Clamp a self-reported float into `[0, max]`, mapping NaN/inf to `on_bad`.
fn clamp_f64(v: f64, max: f64, on_bad: f64) -> f64 {
    if v.is_finite() {
        v.clamp(0.0, max)
    } else {
        on_bad
    }
}

/// Validate and bound one announce payload into a `Peer`.
///
/// Returns `None` when the announce must be ignored entirely (bad/absent id,
/// or the gateway's own id — a peer may not overwrite the controller's row).
/// Pure and side-effect free so it can be tested without a NATS server.
pub(crate) fn sanitize_announce(data: &serde_json::Value, my_id: &str) -> Option<Peer> {
    let nid = data.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
    if !is_safe_token(nid, MAX_ID_LEN) || nid == my_id {
        return None;
    }

    let hostname = data
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(MAX_HOSTNAME_LEN)
        .collect::<String>();

    // Backends: drop any entry whose url is not a plain http(s) URL. The url
    // is NOT used to dial anything (see routes/inference.rs), but keeping it
    // well-formed stops garbage propagating into status output.
    let mut backends: HashMap<String, BackendInfo> = HashMap::new();
    if let Some(obj) = data.get("backends").and_then(|v| v.as_object()) {
        for (k, v) in obj.iter().take(MAX_BACKENDS) {
            if !is_safe_token(k, MAX_BACKEND_KEY_LEN) {
                continue;
            }
            let url = v.get("url").and_then(|u| u.as_str()).unwrap_or("");
            if !url.is_empty() && !(url.starts_with("http://") || url.starts_with("https://")) {
                continue;
            }
            let model = v
                .get("model")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .chars()
                .take(MAX_MODEL_LEN)
                .collect::<String>();
            backends.insert(
                k.clone(),
                BackendInfo { model, url: url.chars().take(512).collect() },
            );
        }
    }

    let capabilities: Vec<String> = data
        .get("capabilities")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.as_str())
                .filter(|c| is_safe_token(c, MAX_CAPABILITY_LEN))
                .take(MAX_CAPABILITIES)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Some(Peer {
        node_id: nid.to_string(),
        hostname,
        backends,
        // A missing/NaN load means "assume busy" — fail closed, so a peer
        // cannot win least-load routing by omitting the field.
        load: clamp_f64(
            data.get("load").and_then(|v| v.as_f64()).unwrap_or(1.0),
            1.0,
            1.0,
        ),
        tier: data
            .get("tier")
            .and_then(|v| v.as_u64())
            .unwrap_or(3)
            .min(MAX_TIER) as u8,
        vram_gb: clamp_f64(
            data.get("vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0),
            MAX_VRAM_GB,
            0.0,
        ),
        capabilities,
        last_seen: now_ts(),
    })
}

fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub backends: HashMap<String, BackendInfo>,
    #[serde(default)]
    pub load: f64,
    #[serde(default = "default_tier")]
    pub tier: u8,
    #[serde(default)]
    pub vram_gb: f64,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub last_seen: f64,
}

fn default_tier() -> u8 { 3 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendInfo {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub url: String,
}

impl Peer {
    pub fn is_alive(&self) -> bool {
        (now_ts() - self.last_seen) < PEER_TTL_SECS
    }

    pub fn can_serve(&self, model: Option<&str>, backend_type: Option<&str>) -> bool {
        if self.load > 0.95 || self.backends.is_empty() {
            return false;
        }
        for (bt, info) in &self.backends {
            if let Some(req_bt) = backend_type {
                if bt != req_bt { continue; }
            }
            if let Some(req_model) = model {
                if info.model != req_model { continue; }
            }
            if !info.url.is_empty() {
                return true;
            }
        }
        false
    }
}

pub struct GossipMesh {
    nats: async_nats::Client,
    node_id: String,
    peers: Arc<RwLock<HashMap<String, Peer>>>,
}

impl GossipMesh {
    pub fn new(nats: async_nats::Client, node_id: String) -> Self {
        Self {
            nats,
            node_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start gossip: subscribe to announcements + start background loops.
    pub async fn start(&self) -> anyhow::Result<()> {
        // Subscribe to announce events
        // Two subscriptions, merged into one stream: see GOSSIP_ANNOUNCE_SCOPED.
        let announce_sub = self.nats.subscribe(GOSSIP_ANNOUNCE).await?;
        let scoped_sub = self.nats.subscribe(GOSSIP_ANNOUNCE_SCOPED).await?;
        let mut announce_sub = announce_sub.merge(scoped_sub);
        let peers = self.peers.clone();
        let my_id = self.node_id.clone();

        tokio::spawn(async move {
            while let Some(msg) = announce_sub.next().await {
                if msg.payload.len() > MAX_ANNOUNCE_BYTES {
                    tracing::warn!(bytes = msg.payload.len(), "gossip.announce_oversized");
                    continue;
                }
                let Ok(data) = serde_json::from_slice::<serde_json::Value>(&msg.payload) else {
                    continue;
                };
                let Some(peer) = sanitize_announce(&data, &my_id) else {
                    continue;
                };
                // On the SCOPED subject the last token is the publisher's own
                // id, and the credential only permits its own. That makes it
                // the one attributable fact in an announce — the header warns
                // the payload's `node_id` is self-asserted — so a mismatch is
                // one node claiming to be another and is dropped.
                if let Some(from) = msg.subject.as_str().strip_prefix("mesh.gossip.announce.") {
                    if from != peer.node_id {
                        tracing::warn!(
                            subject_id = %from, claimed = %peer.node_id,
                            "gossip.announce_id_mismatch",
                        );
                        continue;
                    }
                }
                let nid = peer.node_id.clone();

                let mut guard = peers.write().await;
                let is_new = !guard.contains_key(&nid);
                // Bound the map: a flood of fresh ids must not grow it without
                // limit. Known peers keep updating regardless of the cap.
                if is_new && guard.len() >= MAX_PEERS {
                    tracing::warn!(node_id = %nid, "gossip.peer_table_full");
                    continue;
                }
                guard.insert(nid.clone(), peer);
                drop(guard);

                if is_new {
                    tracing::info!(node_id = %nid, "gossip.peer_joined");
                }
            }
        });

        // NOTE: there is deliberately no `mesh.gossip.leave` subscriber.
        // Nothing in-tree publishes it, and because announce/leave carry no
        // sender identity, honouring it let ONE unattributable message evict a
        // healthy node from the peer table. Peers now age out via PEER_TTL_SECS
        // only. See the security documentation.

        // Prune loop — remove stale peers
        let peers_prune = self.peers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(PRUNE_INTERVAL).await;
                let mut peers = peers_prune.write().await;
                let stale: Vec<String> = peers.iter()
                    .filter(|(_, p)| !p.is_alive())
                    .map(|(k, _)| k.clone())
                    .collect();
                for nid in &stale {
                    peers.remove(nid);
                    tracing::info!(node_id = %nid, "gossip.peer_pruned");
                }
            }
        });

        // Announce loop — tell the mesh we exist
        let nats = self.nats.clone();
        let my_id_announce = self.node_id.clone();
        tokio::spawn(async move {
            loop {
                let announce = serde_json::json!({
                    "type": "announce",
                    "node_id": my_id_announce,
                    "hostname": "gateway",
                    "backends": {},
                    "load": 0.0,
                    "tier": 0,
                    "capabilities": ["gateway", "coordinator"],
                    "ts": now_ts(),
                });
                let _ = nats.publish(
                    GOSSIP_ANNOUNCE,
                    serde_json::to_vec(&announce).unwrap_or_default().into(),
                ).await;
                tokio::time::sleep(ANNOUNCE_INTERVAL).await;
            }
        });

        tracing::info!(node_id = %self.node_id, "gossip.started");
        Ok(())
    }

    /// Get alive peers (read lock, fast).
    pub fn alive_peers(&self) -> Vec<Peer> {
        // Use try_read for non-blocking; fall back to empty if locked
        match self.peers.try_read() {
            Ok(peers) => peers.values().filter(|p| p.is_alive()).cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Find peers that can serve a model, sorted by load.
    pub fn find_peers(
        &self,
        model: Option<&str>,
        backend_type: Option<&str>,
        max: usize,
    ) -> Vec<Peer> {
        match self.peers.try_read() {
            Ok(peers) => {
                let mut candidates: Vec<_> = peers
                    .values()
                    .filter(|p| p.is_alive() && p.can_serve(model, backend_type))
                    .cloned()
                    .collect();
                candidates.sort_by(|a, b| a.load.partial_cmp(&b.load).unwrap_or(std::cmp::Ordering::Equal));
                candidates.truncate(max);
                candidates
            }
            Err(_) => Vec::new(),
        }
    }

    /// Find peers that advertise a specific capability (e.g. "embedding", "whisper").
    /// Returns peers sorted by load (ascending).
    pub fn find_peers_by_capability(&self, capability: &str, max: usize) -> Vec<Peer> {
        match self.peers.try_read() {
            Ok(peers) => {
                let mut candidates: Vec<_> = peers
                    .values()
                    .filter(|p| {
                        p.is_alive()
                            && p.load <= 0.95
                            && p.capabilities.iter().any(|c| c == capability)
                    })
                    .cloned()
                    .collect();
                candidates.sort_by(|a, b| {
                    a.load.partial_cmp(&b.load).unwrap_or(std::cmp::Ordering::Equal)
                });
                candidates.truncate(max);
                candidates
            }
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn announce(v: serde_json::Value) -> Option<Peer> {
        sanitize_announce(&v, "gateway-self")
    }

    #[test]
    fn accepts_a_normal_node_agent_announce() {
        // Exactly the shape node-agent-go publishes (agent.go buildAnnounce).
        let p = announce(json!({
            "type": "announce", "node_id": "host8", "hostname": "host8",
            "backends": {"ollama": {"model": "qwen3:8b", "url": "https://noo-ollama:11434"}},
            "load": 0.25, "tier": 1, "vram_gb": 24.0,
            "capabilities": ["inference", "embed"], "timestamp": 1_754_000_000,
        }))
        .expect("valid announce must be accepted");
        assert_eq!(p.node_id, "host8");
        assert_eq!(p.tier, 1);
        assert_eq!(p.load, 0.25);
        assert_eq!(p.vram_gb, 24.0);
        assert_eq!(p.capabilities, vec!["inference", "embed"]);
        assert_eq!(p.backends["ollama"].model, "qwen3:8b");
        // A well-formed announce must still be routable end-to-end.
        assert!(p.can_serve(None, Some("ollama")));
    }

    #[test]
    fn rejects_missing_absurd_or_self_node_ids() {
        assert!(announce(json!({"load": 0.1})).is_none(), "no node_id");
        assert!(announce(json!({"node_id": ""})).is_none(), "empty id");
        assert!(announce(json!({"node_id": "gateway-self"})).is_none(), "own id");
        assert!(announce(json!({"node_id": "a".repeat(65)})).is_none(), "over-long id");
        // Charset: no spaces, slashes, newlines or log-injecting control chars.
        for bad in ["node one", "../etc", "a\nb", "no de\t", "id;rm"] {
            assert!(announce(json!({"node_id": bad})).is_none(), "must reject {bad:?}");
        }
    }

    #[test]
    fn missing_or_nan_load_fails_closed_to_busy() {
        // A peer must not win least-load routing by omitting `load`.
        assert_eq!(announce(json!({"node_id": "n1"})).unwrap().load, 1.0);
        assert_eq!(announce(json!({"node_id": "n1", "load": "0.0"})).unwrap().load, 1.0);
        // Out-of-range values clamp rather than pass through.
        assert_eq!(announce(json!({"node_id": "n1", "load": -5.0})).unwrap().load, 0.0);
        assert_eq!(announce(json!({"node_id": "n1", "load": 99.0})).unwrap().load, 1.0);
    }

    #[test]
    fn clamps_self_reported_resource_claims() {
        let p = announce(json!({
            "node_id": "liar", "load": 0.0, "tier": 250, "vram_gb": 1.0e18,
        }))
        .unwrap();
        // Can't sort itself to the front of every GPU-first ranking.
        assert_eq!(p.vram_gb, MAX_VRAM_GB);
        assert_eq!(p.tier, MAX_TIER as u8);
    }

    #[test]
    fn drops_non_http_backend_urls() {
        let p = announce(json!({
            "node_id": "n1", "load": 0.1,
            "backends": {
                "ollama": {"model": "m", "url": "file:///etc/shadow"},
                "vllm":   {"model": "m", "url": "https://10.0.0.9:8000"},
            },
        }))
        .unwrap();
        assert!(!p.backends.contains_key("ollama"), "file:// url must be dropped");
        assert!(p.backends.contains_key("vllm"));
    }

    #[test]
    fn bounds_capability_and_backend_lists() {
        let caps: Vec<String> = (0..500).map(|i| format!("cap{i}")).collect();
        let p = announce(json!({"node_id": "n1", "load": 0.1, "capabilities": caps})).unwrap();
        assert!(p.capabilities.len() <= MAX_CAPABILITIES);

        // Non-token capability names are filtered, not truncated silently.
        let p = announce(json!({
            "node_id": "n1", "load": 0.1,
            "capabilities": ["embed", "has space", "a".repeat(999)],
        }))
        .unwrap();
        assert_eq!(p.capabilities, vec!["embed"]);
    }

    #[test]
    fn hostname_and_model_are_length_bounded() {
        let p = announce(json!({
            "node_id": "n1", "load": 0.1,
            "hostname": "h".repeat(9999),
            "backends": {"vllm": {"model": "m".repeat(9999), "url": "https://x:1"}},
        }))
        .unwrap();
        assert_eq!(p.hostname.chars().count(), MAX_HOSTNAME_LEN);
        assert_eq!(p.backends["vllm"].model.chars().count(), MAX_MODEL_LEN);
    }

    #[test]
    fn peer_table_cap_is_a_sane_bound() {
        // The cap itself is enforced in the subscribe loop (needs a NATS
        // server); assert the constant stays large enough for a real fleet
        // and small enough to bound memory.
        let (peers, bytes) = (MAX_PEERS, MAX_ANNOUNCE_BYTES);
        assert!((64..=4096).contains(&peers));
        assert!(bytes >= 2048);
    }
}
