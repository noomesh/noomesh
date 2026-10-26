// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Cluster routes — node management, backends, GPU metrics.

use crate::audit::{AuditEvent, AuditKind};
use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post, put, delete},
    extract::{State, Path, Query},
    Json,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;
use super::{AppJson, AppError, AppResult};
use super::admin::all_node_agents;


/// Is this capability map's node an ARM box? `None` = it doesn't say.
///
/// `capabilities.arch` is the node's own `runtime.GOARCH` and is checked
/// first; `capabilities.is_arm` is the older boolean. An unrecognised arch
/// string yields `None` rather than a guess — a wrong architecture makes
/// `upgrade-agents` install an unrunnable binary on the node.
fn arch_is_arm(caps: &Value) -> Option<bool> {
    if let Some(a) = caps.get("arch").and_then(|v| v.as_str()) {
        match a.trim().to_ascii_lowercase().as_str() {
            "arm64" | "aarch64" | "arm" | "armv6l" | "armv7l" | "armhf" | "armel" => return Some(true),
            "amd64" | "x86_64" | "x64" | "x86" | "i386" | "i686" => return Some(false),
            _ => {}
        }
    }
    caps.get("is_arm").and_then(|v| v.as_bool())
}

/// A node with no usable VRAM has no discrete GPU to advertise. Some
/// node-agents carry a stale `GPU_MODEL` env (e.g. copied from another
/// host during provisioning) and report it even with zero VRAM — which
/// is how a Raspberry Pi ended up showing a laptop's RTX 3080. Clamp
/// `gpu_model` to null whenever `vram_gb` resolves to 0 so a node never
/// displays a GPU it doesn't have (or another node's GPU). Mutates in
/// place; safe to call on any node JSON object.
fn clamp_gpu_model(data: &mut Value) {
    let vram = data.get("vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
    if vram <= 0.0
        && data.get("gpu_model").map(|v| !v.is_null()).unwrap_or(false) {
            data["gpu_model"] = Value::Null;
        }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Native Rust ──
        .route("/api/cluster/status", get(cluster_status))
        .route("/api/cluster/nodes", get(cluster_nodes))
        .route("/api/cluster/nodes/register", post(node_register_body))
        .route("/api/cluster/nodes/{id}/heartbeat", post(node_heartbeat))
        // Node log ingest (fleet logging phase 2): a node pushes its own
        // log batch, the gateway stamps the verified `node` label and
        // relays it to Loki. Node credential only, self only — see
        // `logs_ingest.rs` for the wire contract. Its own body cap sits
        // ABOVE the module's decoded cap so the 413 comes from the module
        // with a reason, not from the extractor with none.
        .route(
            "/api/cluster/nodes/{node_id}/logs",
            post(super::logs_ingest::node_logs_ingest)
                .layer(axum::extract::DefaultBodyLimit::max(super::logs_ingest::MAX_BODY + 1024)),
        )
        .route("/api/cluster/nodes/{id}/register", post(node_register))
        .route("/api/cluster/nodes/{id}/forget", delete(node_forget))
        .route("/api/cluster/backends", get(cluster_backends))
        .route("/api/cluster/gpu-metrics", get(cluster_gpu_metrics))

        // ── Native Rust (node-agent HTTP proxies) ──
        // ── Desired-state config (DESIRED_STATE_CONFIG.md) ──
        .route("/api/cluster/nodes/{node_id}/desired-config", get(desired_config_get))
        .route("/api/cluster/nodes/{node_id}/config", put(node_config_put))
        .route("/api/cluster/nodes/{node_id}/placements/{backend}", put(placement_put))
        .route("/api/cluster/nodes/{node_id}/placements/{backend}", delete(placement_delete))
        .route("/api/cluster/nodes/{node_id}/fit", post(placement_fit_post))
        // ── Model classes ──
        .route("/api/cluster/model-classes", get(model_classes_get))
        .route("/api/cluster/model-classes/{class}", put(model_class_put))
        .route("/api/cluster/model-classes/{class}", delete(model_class_delete))
        .route("/api/cluster/model-aliases/{alias}", put(model_alias_put))
        .route("/api/cluster/model-aliases/{alias}", delete(model_alias_delete))
        .route("/api/cluster/embedding-spaces", get(embedding_spaces_get))
        .route("/api/cluster/embedding-spaces/{space}", put(embedding_space_put))
        .route("/api/cluster/embedding-spaces/{space}", delete(embedding_space_delete))
        .route(
            "/api/cluster/embedding-spaces/{space}/migration",
            post(embedding_space_migration_start).delete(embedding_space_migration_cancel),
        )
        .route("/api/cluster/embedding-spaces/{space}/migration/complete", post(embedding_space_migration_complete))
        // Operator-only mute for a known-down node's alerts (maintenance.rs).
        .route(
            "/api/cluster/nodes/{node_id}/maintenance",
            put(crate::maintenance::maintenance_on).delete(crate::maintenance::maintenance_off),
        )
        .route("/api/cluster/maintenance", get(crate::maintenance::maintenance_list))
        .route("/api/cluster/nodes/{node_id}/restart-agent", post(restart_node_agent))
        // "control over bus" verify row: one health round trip over NATS.
        .route("/api/cluster/nodes/{node_id}/control-probe", get(control_probe))
        .route("/api/cluster/nodes/{node_id}/pull", post(pull_node_artifact))
        .route("/api/cluster/nodes/{node_id}/clean", post(clean_node))
        // Shared-GPU operator hold (node agent `internal/gpuyield`).
        .route("/api/cluster/nodes/{node_id}/gpu/hold", post(gpu_hold))
        .route("/api/cluster/nodes/{node_id}/gpu/release", post(gpu_release))
        // Measure the node's chat model (harness profile: first_byte_secs).
        .route("/api/cluster/nodes/{node_id}/bench", post(node_bench))
        // ── Native Rust [ported from workers/cluster.py 2026-07-18] ──
        .route("/api/cluster/mint-join-key", post(mint_join_key))
        .route("/api/cluster/delete-tailscale-device", post(delete_tailscale_device))
        .route("/api/cluster/replication-status", get(replication_status))
        .route("/api/cluster/suggest-placement", post(suggest_placement))
        .route("/api/cluster/discover", post(cluster_discover))
        .route("/api/cluster/propose", post(cluster_propose))
        // NOTE: underscore spelling is load-bearing — the catch-all maps
        // /api/cluster/enroll_now → worker.api.cluster.enroll_now, and the
        // MCP tool def uses the same path.
        .route("/api/cluster/proposals", post(proposals_list))
        .route("/api/cluster/proposals/decide", post(proposals_decide))
        .route("/api/cluster/proposals/{id}", get(proposal_status))
        .route("/api/cluster/backends/start", post(backends_start))
        .route("/api/cluster/backends/stop", post(backends_stop))
        .route("/api/cluster/backends/clear-cooldowns", post(backends_clear_cooldowns))
        // /api/cluster/backends/{type}/scale REMOVED — it never worked. The
        // Python handler called BackendManager.scale_backend, which does not
        // exist; the method is scale_replicas. Probed live:
        //   POST /api/cluster/backends/__nope__/scale
        //     -> 400 {"error":"'BackendManager' object has no attribute 'scale_backend'"}
        //
        // Scaling is unaffected and already works two other ways:
        //   - `noo cluster scale` (retired) composed it CLIENT-side from the native
        //     /backends/start and /backends/stop routes below
        //   - the autonomy engine's scale_backend action calls scale_replicas
        //     directly, with the correct name
        .route("/api/terminal/backends", get(terminal_backends))
        .route("/api/terminal/backends/stop", post(terminal_backends_stop))
        // ── Models: Native Rust (ported from NATS delegation 2026-03-31) ──
        .route("/api/models/pull", post(models_pull))
        .route("/api/models/cached", get(models_cached))
        .route("/api/models/cache", post(models_cache))
        .route("/api/ollama/models", get(ollama_models))
}

pub(super) async fn cluster_status(State(state): State<Arc<AppState>>) -> AppJson {
    // This endpoint used to count `gossip.alive_peers()` and nothing else: no
    // `offline` bucket existed, so a node going dark made `total_nodes` shrink
    // and the cluster looked smaller-but-healthy, while /api/nodes — reading
    // NATS KV plus the persistent cluster_nodes table — still reported it as a
    // 4th, offline bucket. Two endpoints, one fact, two answers.
    //
    // Both now derive from collect_cluster_nodes, so the totals agree by
    // construction.
    let (nodes, offline_merge_error) = collect_cluster_nodes(&state).await;
    let stats = node_stats(&nodes, offline_merge_error.as_deref());

    // Slim per-node projection kept for this endpoint's existing consumers.
    let peers = state.gossip.alive_peers();
    let summaries: Vec<Value> = nodes
        .iter()
        .map(|n| {
            let id = n.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let peer = peers.iter().find(|p| p.node_id == id);
            json!({
                "id": id,
                "hostname": n.get("hostname").cloned().unwrap_or(Value::Null),
                "status": n.get("status").cloned().unwrap_or(Value::Null),
                // `load` is a gossip-only measurement. For a node absent from
                // gossip it is unknown, not 0.0 — a fabricated 0.0 reads as
                // "completely idle, send it work".
                "load": peer.map(|p| json!(p.load)).unwrap_or(Value::Null),
                "tier": n.get("tier").cloned().unwrap_or(Value::Null),
                "vram_gb": n.get("vram_gb").cloned().unwrap_or(Value::Null),
                "backends": n.get("backends").cloned().unwrap_or(Value::Null),
                // Served-cert expiry (unix secs) from the agent heartbeat —
                // rotate-all's delivery verification reads this to prove the
                // node is PRESENTING the re-issued cert, not merely alive on
                // the old one. Null = agent build predates it.
                "cert_not_after": n.get("cert_not_after").cloned().unwrap_or(Value::Null),
                // What is ACTUALLY running (agent-reported every beat) —
                // the other half of the #50 answer: `backends` is what the
                // node CAN host, this is what it IS hosting right now.
                "running_backends": n.get("running_backends").cloned().unwrap_or(Value::Null),
                "self_node": n.get("self_node").cloned().unwrap_or(Value::Null),
                // How the controller can reach this agent (Null = a node
                // known only from the table, never beat since this field).
                "control_transports": n.get("control_transports").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();

    Json(json!({
        "total_nodes": stats.get("total_nodes").cloned().unwrap_or(Value::Null),
        "online": stats.get("online").cloned().unwrap_or(Value::Null),
        "busy": stats.get("busy").cloned().unwrap_or(Value::Null),
        "unknown": stats.get("unknown").cloned().unwrap_or(Value::Null),
        "offline": stats.get("offline").cloned().unwrap_or(Value::Null),
        "nodes": summaries,
        "error": offline_merge_error,
        "engine": "rust",
    }))
}

/// Can the controller dial `ip` to reach ANOTHER host?
///
/// Loopback, unspecified, link-local, multicast and broadcast never name a
/// remote machine; a non-IP string cannot be dialled without a resolver the
/// controller does not have for node hostnames (`HOST3` resolves on host3,
/// not here). Pure, so every class is pinned without a heartbeat.
pub(crate) fn acceptable_node_ip(ip: &str) -> bool {
    let Ok(addr) = ip.trim().parse::<std::net::IpAddr>() else { return false };
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    match addr {
        std::net::IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// Carry a heartbeat field onto the node record when the agent reported it;
/// leave the record's copy alone when the beat omits it (an older agent) or
/// sends null. Never synthesised: absence on the record means "this agent
/// has not said", which `cluster verify` reads as exactly that.
pub(crate) fn carry_reported(data: &mut Value, body: &Value, key: &str) {
    if let Some(v) = body.get(key) {
        if !v.is_null() {
            data[key] = v.clone();
        }
    }
}

async fn node_heartbeat(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(body): Json<Value>,
) -> AppJson {
    // Merge heartbeat data with existing KV entry (preserves registration data
    // like gpu_model, cpu_cores, ram_gb while updating live metrics)
    let mut data = if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        kv.get(&node_id).await.ok().flatten()
            .and_then(|v| serde_json::from_slice::<Value>(&v).ok())
            .unwrap_or(json!({}))
    } else {
        json!({})
    };

    // Update live + static fields from heartbeat
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    // Always update
    data["id"] = json!(node_id);
    data["hostname"] = json!(node_id);  // Use node_id, not container hostname
    data["status"] = json!("online");
    data["current_load"] = json!(body.get("load").and_then(|v| v.as_f64()).unwrap_or(0.0));
    data["running_backends"] = body.get("running_backends").cloned().unwrap_or(json!({}));
    // The node on the controller's own device says so (NOO_SELF_NODE);
    // fleet views and node verbs branch on it.
    if let Some(v) = body.get("self_node") { if !v.is_null() { data["self_node"] = v.clone(); } }
    data["cpu_load"] = body.get("cpu_load").cloned().unwrap_or(json!(null));
    data["mem_used_gb"] = body.get("mem_used_gb").cloned().unwrap_or(json!(null));
    data["vram_used_gb"] = body.get("vram_used_gb").cloned().unwrap_or(json!(null));
    data["ts"] = json!(now);
    data["last_heartbeat"] = json!(now);

    // Static fields — set from heartbeat if present (survives KV TTL expiry)
    // A node's self-reported address becomes `https://{ip}:8081` for every
    // inference the gateway routes to it (`resolve_backend_url`). One it
    // cannot dial is worse than none: `data` is seeded from the existing KV
    // entry, so REJECTING keeps the last good address, while accepting
    // `127.0.1.1` — what host3's hostname resolves to, and what its agent
    // registered on 2026-09-22 whenever source-IP detection failed — had the
    // gateway dial itself and answer ~200 chat completions a minute with 502.
    if let Some(v) = body.get("ip_address") {
        match v.as_str() {
            Some(ip) if acceptable_node_ip(ip) => data["ip_address"] = v.clone(),
            Some(ip) if !ip.trim().is_empty() => tracing::warn!(
                node = %node_id, offered = %ip,
                "heartbeat named an address the controller cannot dial a node at — keeping the registered one"
            ),
            _ => {}
        }
    }
    if let Some(v) = body.get("gpu_model") { if !v.is_null() { data["gpu_model"] = v.clone(); } }
    if let Some(v) = body.get("cpu_cores") { if !v.is_null() { data["cpu_cores"] = v.clone(); } }
    if let Some(v) = body.get("ram_gb") { if !v.is_null() { data["ram_gb"] = v.clone(); } }
    if let Some(v) = body.get("vram_gb") { if !v.is_null() { data["vram_gb"] = v.clone(); } }
    // Node-broadcast network identity: geographic/site label and the interface
    // the node published its control API on (surfaced for the eval report +
    // dashboard; see NODE_LOCATION and the H-N5 bind_addr broadcast).
    if let Some(v) = body.get("location") { if !v.is_null() { data["location"] = v.clone(); } }
    if let Some(v) = body.get("bind_addr") { if !v.is_null() { data["bind_addr"] = v.clone(); } }
    // Model inventory this node has cached (Ollama tags + local GGUFs) so
    // placement can match by availability, not just capability.
    if let Some(v) = body.get("available_models") { if !v.is_null() { data["available_models"] = v.clone(); } }
    // Desired-state instructions the NODE declined (node-agent
    // internal/refusals). `noo_backend_placements` records intent and
    // nothing else, so before this a node that refused a placement — a
    // mount outside its declared roots, an MCP command it does not
    // allow-list, a placement env key that is not tuning — looked from here
    // exactly like a node that had never been asked. Carried onto the node
    // record so every reader sees it, and alerted once a day so an operator
    // is not the last to know.
    //
    // ABSENT is not EMPTY: an agent too old to send the field says nothing,
    // which must not clear a standing refusal. An agent that sends an empty
    // list IS saying "nothing refused", and that does clear it.
    // What this node's HOST services are actually doing (the
    // harness), as opposed to what was placed. Intent has always been
    // readable here; reality never was, so `desired: running` with no
    // refusal was indistinguishable from running — and a unit stopped by
    // hand, or never installed, refuses nothing. Omitted by an agent that
    // does not report it; never synthesised here.
    if let Some(v) = body.get("host_services") { if !v.is_null() { data["host_services"] = v.clone(); } }
    // What an adopted backend has LOADED right now, distinct from the model
    // it is placed to serve (`running_backends`). Replaced each beat, and
    // cleared when the beat omits it: "nothing loaded" is a fact too.
    match body.get("loaded_models") {
        Some(v) if !v.is_null() => { data["loaded_models"] = v.clone(); }
        _ => { data.as_object_mut().map(|o| o.remove("loaded_models")); }
    }
    // The node's confined-root daemon: alive, its version, and the op
    // names it advertises. The agent delegates every privileged op to it,
    // so a dead one makes the agent look merely idle. `ops` is what lets a
    // caller tell "this daemon is too old for that op" from "that op
    // failed".
    if let Some(v) = body.get("hostd") { if !v.is_null() { data["hostd"] = v.clone(); } }
    // The log shipper's own account (fleet logging phase 3): `{enabled,
    // queued, shipped_total, dropped_total, last_accepted_unix, last_error,
    // route_ready, spill_pending, journal}`. `noo cluster verify <node>`
    // judges its `log shipper` row on this. Phase 6 found it was never
    // carried onto the record: this handler names each field it keeps, so
    // a new heartbeat field is dropped by default, and the row would have
    // read every node as "agent predates the shipper".
    carry_reported(&mut data, &body, "log_ship");
    // The node's measured model speed (`POST /bench` on the agent,
    // `noo cluster profile <node> --bench`): `{model, backend, load_secs,
    // prefill_tps, decode_tps, prompt_tokens, at}`. Absent until a bench has
    // run; the agent reports its last one on every beat after. desired-config
    // resolves `harness_profile.first_byte_secs` from it.
    carry_reported(&mut data, &body, "model_bench");
    // The agent's posture: whether its control API requires a client
    // certificate. A running agent on the mTLS-only build always says true;
    // an older build can say false, and `noo cluster verify` fails it.
    carry_reported(&mut data, &body, "peer_identity_enforced");
    // The backend door leaves the node HOLDS: per door
    // service under $NOO_PKI_DIR/services/, `{dns, not_after}`. `noo cluster
    // verify`'s `backend doors` row reads it off the record; without this
    // carry every node reads "agent predates backend doors reporting".
    carry_reported(&mut data, &body, "backend_leaves");
    // The data roots the node resolves and the host paths its managed
    // backends mount. `noo cluster provision` compares it
    // with the root a bundle would render before staging; `verify`'s
    // `data root` row reads it. Replaced whole on every beat.
    carry_reported(&mut data, &body, "data_roots");
    // Legacy credential lanes the agent admitted since it started
    // `{since_unix, static_token, cluster_hmac_v1_refused}`.
    // `noo cluster verify --controller`'s `legacy lanes` row reads it.
    carry_reported(&mut data, &body, "legacy_lanes");
    // Whether the agent admits the gateway's leaf with no bearer. Written EVERY beat, false when absent: unlike the reports
    // above this is a capability the gateway acts on, so an agent rolled
    // back to a build that does not say must get the bearer again, not
    // inherit the record's old `true`.
    data[crate::node_agent_auth::CAPABILITY] = json!(crate::node_agent_auth::reported(&body));
    // The control transports the agent offers (https listener / NATS RPC /
    // tunnel). Written every beat; an agent that does not say is an older
    // one and reads as the HTTPS listener only.
    data[crate::node_link::TRANSPORTS_FIELD] = crate::node_link::reported_transports(&body);
    // Which image the node's backend-door sidecars run on
    // B: "published", or "fallback-alpine" — stunnel installed from the
    // alpine mirror at every sidecar start. `noo cluster verify <node>`
    // WARNs on the fallback. Omitted by an agent that has started no
    // sidecar yet (and by an older one); the record keeps its last value.
    carry_reported(&mut data, &body, "stunnel_image");
    // Where each image the agent started a container from came from:
    // rail | local | registry (`internal/imagesource`). `noo cluster verify`
    // WARNs on anything not from the rail.
    carry_reported(&mut data, &body, "image_sources");
    carry_reported(&mut data, &body, "image_source_mode");
    // Per running backend container: start time + health.
    // `backend doors` reads a door miss on a container still warming up as
    // `starting` only from this; an agent that omits it changes nothing.
    carry_reported(&mut data, &body, "backend_containers");
    // Shared-GPU contention (node agent `internal/gpuyield`): whether work
    // outside noomesh holds the GPU and which GPU backends are paused for
    // it. The node stays online while yielded; this is the WHY behind its
    // missing backend. Field names are a contract with the router and the
    // CLI: {state, foreign_mb, total_mb, free_mb, method, since,
    // paused_backends, need_mb, reason, policy}. An older agent omits it.
    carry_reported(&mut data, &body, "gpu_contention");
    // Per placed backend: does its model server HOLD the placement's model
    // (`crate::model_presence`). Unlike the reports above this
    // is REPLACED every beat and dropped when the beat omits it: a stale
    // `present: false` from an agent since rolled back would cut the node
    // out of routing for good, and an older agent saying nothing must read as
    // unknown.
    match body.get("model_presence").filter(|v| v.is_object()) {
        Some(v) => data["model_presence"] = v.clone(),
        None => {
            if let Some(o) = data.as_object_mut() {
                o.remove("model_presence");
            }
        }
    }
    // What each held model weighs on the node (ollama /api/tags size, and the
    // resident size of a loaded one from /api/ps): the MEASURED inputs of the
    // memory-fit check. Replaced every beat for the same reason as
    // model_presence: a stale resident size would mis-judge a fit.
    match body.get("model_stats").filter(|v| v.is_array()) {
        Some(v) => data["model_stats"] = v.clone(),
        None => {
            if let Some(o) = data.as_object_mut() {
                o.remove("model_stats");
            }
        }
    }
    if let Some(v) = body.get("reconcile_refusals") {
        data["reconcile_refusals"] = v.clone();
        if let Some(items) = v.as_array() {
            if !items.is_empty() {
                let detail = items
                    .iter()
                    .take(5)
                    .map(|r| {
                        format!(
                            "{}={}: {}",
                            r.get("scope").and_then(|x| x.as_str()).unwrap_or("?"),
                            r.get("target").and_then(|x| x.as_str()).unwrap_or("?"),
                            r.get("reason").and_then(|x| x.as_str()).unwrap_or("?")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                tracing::warn!(node_id = %node_id, detail, "node_reconcile_refusals");
                // Which instruction and why is the logged detail (the
                // reasons can name paths and settings on the node).
                crate::operator_alert::send_operator_alert_with(
                    &state,
                    crate::operator_alert::OperatorAlert::new(
                        "node.reconcile_refused",
                        &node_id,
                        format!(
                            "🧱 Node `{node_id}` refused {} desired-state instruction(s). \
                             The node bounds what the controller may make it do (see the \
                             node-agent trust contract); fix the instruction, or widen the \
                             node's own declaration in its agent env file and restart its agent.",
                            items.len()
                        ),
                    )
                    .detail(detail.clone())
                    .investigate(format!("noo cluster verify {node_id}")),
                    RECONCILE_REFUSAL_ALERT_COOLDOWN_SECS,
                )
                .await;
            }
        }
    }
    if let Some(v) = body.get("tier") { if !v.is_null() { data["tier"] = v.clone(); } }

    // The agent re-sends its full capability map every heartbeat *specifically*
    // so the controller can heal a KV/DB record that lost it (see
    // heartbeat.go). Until 2026-08-04 this handler dropped it on the floor, so
    // a node whose KV entry aged out and was rebuilt from heartbeats alone
    // never got its capabilities — or its architecture — back.
    if let Some(v) = body.get("capabilities") { if !v.is_null() { data["capabilities"] = v.clone(); } }

    // Architecture. The Go agent sends `runtime.GOARCH` inside capabilities and
    // never as a top-level `is_arm`, so deriving it here is the only way the
    // flat field stays true. It matters operationally: `noo cluster
    // upgrade-agents` picks the amd64 vs arm64 image path from it, and a wrong
    // answer installs an unrunnable binary ("exec format error") and strands
    // the node — which is what a stale `is_arm=f` on the aarch64 `host9-sensors`
    // did on 2026-08-04. An UNKNOWN architecture stays absent: null is a real
    // answer here and must not collapse into "x86".
    if let Some(v) = body.get("is_arm") { if !v.is_null() { data["is_arm"] = v.clone(); } }
    if data.get("is_arm").map(|v| v.is_null()).unwrap_or(true) {
        if let Some(a) = arch_is_arm(data.get("capabilities").unwrap_or(&json!({}))) {
            data["is_arm"] = json!(a);
        }
    }
    // The agent's own control-API URL. Without copying it here, agent_url
    // stays empty and get_node_agent_url() falls back to {ip}:8081 — which
    // silently routes a SECOND agent's traffic (e.g. a Tier 5 sensor
    // companion on :8082) to the first agent on that host.
    if let Some(v) = body.get("agent_url") { if !v.is_null() { data["agent_url"] = v.clone(); } }
    // node-agent build version — refresh from the heartbeat so a redeployed
    // node reflects its new binary without waiting for re-registration.
    if let Some(v) = body.get("app_version") { if !v.is_null() { data["app_version"] = v.clone(); } }
    // NotAfter (unix secs) of the cert the agent is PRESENTING — the
    // positive proof cert rotation actually landed. Absent =
    // older agent build; keep the third answer distinct, like nats_status.
    if let Some(v) = body.get("cert_not_after") { if !v.is_null() { data["cert_not_after"] = v.clone(); } }
    // The node's OWN view of its NATS bus: {state, connected,
    // job_dispatch_bound, last_connected_at, ...}. A node can be HTTP-alive
    // (this very request proves it) and bus-deaf at the same time, in which
    // case every job dispatched to it strands — that is what happened to
    // host9 and host9-sensors on 2026-08-02, invisibly, for two days.
    //
    // Absent means "this agent build does not report it", which is a third
    // answer and must not be collapsed into either connected or down. So it
    // is only overwritten when actually present and non-null.
    if let Some(v) = body.get("nats_status") { if !v.is_null() { data["nats_status"] = v.clone(); } }

    // Companion telemetry (tier >= 4)
    for field in &["battery_pct", "is_charging", "network_type", "thermal_state",
                   "active_sensors", "active_model", "platform"] {
        if let Some(v) = body.get(*field) {
            if !v.is_null() {
                data[*field] = v.clone();
            }
        }
    }

    // Operator override from noo_node_config (DB-backed desired config):
    // when BOTH gpu_model and vram_gb are set there, they beat detection —
    // for nodes where nvidia-smi is broken/unavailable. Requiring both
    // mirrors the node-agent rule (a GPU claim without VRAM isn't real).
    if let Ok(Some((Some(gm), Some(vg)))) =
        crate::repo::cluster::node_gpu_override(&state.db, &node_id).await
    {
        data["gpu_model"] = json!(gm);
        data["vram_gb"] = json!(vg);
    }

    // No VRAM → no GPU. Drops a stale gpu_model (e.g. a Pi carrying a
    // copied GPU_MODEL env) before it's persisted to KV or mirrored to DB.
    clamp_gpu_model(&mut data);

    // Which credential the gateway presents to this agent from now on.
    crate::node_agent_auth::note(&node_id, &data);

    // Write to NATS KV mesh_nodes bucket (live source of truth)
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        let payload = serde_json::to_vec(&data).unwrap_or_default();
        if let Err(e) = kv.put(&node_id, payload.into()).await {
            tracing::debug!(error = %e, "NATS KV heartbeat write failed");
        }
    }

    // Mirror to noo_cluster_nodes Postgres (audit/analytics).
    // Restored 2026-04-29 — Python `cluster/node_store.py` was the original
    // writer (now archived); this Rust UPSERT keeps the table populated so
    // historical queries (which nodes ever joined, what tiers, when last seen)
    // survive even though the live read path is NATS KV.
    let hostname = data.get("hostname").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let ip_address = data.get("ip_address").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tier = data.get("tier").and_then(|v| v.as_i64()).unwrap_or(3) as i32;
    let vram_gb = data.get("vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let cpu_cores = data.get("cpu_cores").and_then(|v| v.as_i64()).unwrap_or(4) as i32;
    let ram_gb = data.get("ram_gb").and_then(|v| v.as_f64()).unwrap_or(8.0);
    let current_load = data.get("current_load").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("online").to_string();
    let running_backends = data.get("running_backends").cloned().unwrap_or_else(|| json!({}));
    let agent_url = data.get("agent_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // gpu_model/is_arm persisted so the offline-node view (which reads this
    // table, not KV) can show last-known hardware after the node ages out.
    let gpu_model = data.get("gpu_model").and_then(|v| v.as_str()).map(|s| s.to_string());
    // Option, NOT `unwrap_or(false)`: this UPSERT sets `is_arm = EXCLUDED.is_arm`
    // on EVERY heartbeat, so a default-false here overwrites a correct
    // `is_arm=true` with a lie the moment one heartbeat lacks the field. NULL
    // means "unknown", and the consumers of this column (upgrade-agents picks
    // an image architecture from it) must be able to tell that apart from x86.
    let is_arm = data
        .get("is_arm")
        .and_then(|v| v.as_bool())
        .or_else(|| arch_is_arm(data.get("capabilities").unwrap_or(&json!({}))));

    // Table name is `cluster_nodes` (not `noo_cluster_nodes` — verified
    // against the live schema 2026-04-29). Schema doesn't NOT NULL the
    // ip_address column even though models.py declares it nullable=False;
    // we COALESCE to empty string defensively.
    // Companion telemetry (battery/network/thermal/sensors).
    //
    // These reached the NATS KV live view but were dropped from this
    // Postgres mirror, and Python's NodeRegistry reads Postgres — so
    // `device_sensors.py` saw active_sensors=[] for every node no matter
    // what the agent reported, and would never route a tool call to a
    // companion that genuinely had a camera.
    //
    // `has_telemetry` gates the whole group rather than COALESCEing each
    // column, because absent and null mean different things here:
    //   - an agent older than the sensor-reporting build omits them
    //     entirely, and must NOT wipe a hand-registered companion's
    //     sensor list;
    //   - a current agent on a mains host sends battery_pct = null
    //     deliberately, and that null must be stored, not coalesced away
    //     into a stale 100% left over from `add-companion`.
    // A per-column COALESCE cannot tell those apart; one flag can, and the
    // agent always sends the group together.
    // Derive node_type from tier.
    //
    // The column defaults to 'worker' and NOTHING ever set it, so every
    // heartbeat-registered node landed as a worker regardless of tier — and
    // cluster/node.py prefers the stored node_type over its own tier mapping
    // (`row["node_type"] if row.get("node_type") else _type_map.get(tier)`).
    // Net effect: a Tier 5 node could never become a COMPANION, and
    // device_sensors.py — which matches on NodeType.COMPANION — would never
    // route a sensor call to it no matter what hardware it advertised.
    //
    // Mirrors _type_map in cluster/node.py so both sides agree.
    let node_type = match tier {
        4 => "edge",
        5 => "companion",
        6 => "monitor",
        _ => "worker",
    };

    // Node capabilities (which backends this node CAN run, tools, arch...).
    //
    // Sourced from the heartbeat BODY first, falling back to the merged KV
    // record. Body is authoritative because the agent now echoes
    // capabilities on every heartbeat: sending them only at registration
    // meant a node whose KV entry was later rebuilt by plain heartbeats
    // lost them permanently, and Python's `Node.can_run_backend()` then
    // evaluated `backend in []`, silently excluding it from every
    // backend-filtered job while it kept heartbeating and looking healthy.
    //
    // MUST stay in the INSERT column list. An earlier version added only
    // the ON CONFLICT SET clause, so `EXCLUDED.capabilities` resolved to
    // the column DEFAULT ('[]'::jsonb) — non-NULL, so COALESCE preferred
    // it and the upsert WIPED capabilities on every heartbeat instead of
    // preserving them. That is how HOST3 lost a populated list.
    //
    // Empty objects/arrays are treated as "nothing to say" rather than an
    // instruction to clear, so an older agent that sends no capabilities
    // cannot destroy good data.
    let non_empty = |v: &serde_json::Value| match v {
        serde_json::Value::Object(o) => !o.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        _ => false,
    };
    let capabilities = body
        .get("capabilities")
        .filter(|v| non_empty(v))
        .or_else(|| data.get("capabilities").filter(|v| non_empty(v)))
        .cloned();

    let has_telemetry = body.get("active_sensors").is_some();
    let active_sensors = body.get("active_sensors").cloned();
    let battery_pct = body.get("battery_pct").and_then(|v| v.as_f64());
    let is_charging = body.get("is_charging").and_then(|v| v.as_bool());
    let network_type = body.get("network_type").and_then(|v| v.as_str()).map(str::to_string);
    let thermal_state = body.get("thermal_state").and_then(|v| v.as_str()).map(str::to_string);
    // node-agent build version. Empty-string default rather than NULL so the
    // COALESCE(NULLIF(...)) in the upsert keeps a previously-reported version
    // when a heartbeat omits it, instead of blanking it.
    let app_version = body
        .get("app_version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let upsert = sqlx::query(
        "INSERT INTO cluster_nodes \
            (node_id, hostname, ip_address, tier, vram_gb, cpu_cores, ram_gb, \
             current_load, status, running_backends, agent_url, gpu_model, is_arm, \
             active_sensors, battery_pct, is_charging, network_type, thermal_state, \
             node_type, app_version, capabilities, last_heartbeat, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                 $14, $15, $16, $17, $18, $20, $21, $22, NOW(), NOW()) \
         ON CONFLICT (node_id) DO UPDATE SET \
            hostname = EXCLUDED.hostname, \
            ip_address = COALESCE(NULLIF(EXCLUDED.ip_address, ''), cluster_nodes.ip_address), \
            tier = EXCLUDED.tier, \
            vram_gb = EXCLUDED.vram_gb, \
            cpu_cores = EXCLUDED.cpu_cores, \
            ram_gb = EXCLUDED.ram_gb, \
            current_load = EXCLUDED.current_load, \
            status = EXCLUDED.status, \
            running_backends = EXCLUDED.running_backends, \
            agent_url = COALESCE(NULLIF(EXCLUDED.agent_url, ''), cluster_nodes.agent_url), \
            app_version = COALESCE(NULLIF(EXCLUDED.app_version, ''), cluster_nodes.app_version), \
            gpu_model = EXCLUDED.gpu_model, \
            is_arm = EXCLUDED.is_arm, \
            active_sensors = CASE WHEN $19 THEN EXCLUDED.active_sensors \
                                  ELSE cluster_nodes.active_sensors END, \
            battery_pct = CASE WHEN $19 THEN EXCLUDED.battery_pct \
                               ELSE cluster_nodes.battery_pct END, \
            is_charging = CASE WHEN $19 THEN EXCLUDED.is_charging \
                               ELSE cluster_nodes.is_charging END, \
            network_type = CASE WHEN $19 THEN EXCLUDED.network_type \
                                ELSE cluster_nodes.network_type END, \
            thermal_state = CASE WHEN $19 THEN EXCLUDED.thermal_state \
                                 ELSE cluster_nodes.thermal_state END, \
            node_type = EXCLUDED.node_type, \
            capabilities = COALESCE(EXCLUDED.capabilities, cluster_nodes.capabilities), \
            last_heartbeat = NOW(), \
            updated_at = NOW()"
    )
    .bind(&node_id)
    .bind(&hostname)
    .bind(&ip_address)
    .bind(tier)
    .bind(vram_gb)
    .bind(cpu_cores)
    .bind(ram_gb)
    .bind(current_load)
    .bind(&status)
    .bind(&running_backends)
    .bind(&agent_url)
    .bind(&gpu_model)
    .bind(is_arm)
    .bind(&active_sensors)
    .bind(battery_pct)
    .bind(is_charging)
    .bind(&network_type)
    .bind(&thermal_state)
    .bind(has_telemetry)
    .bind(node_type)
    .bind(app_version)
    .bind(&capabilities)
    .execute(&state.db)
    .await;
    if let Err(e) = upsert {
        // Was debug: an upsert failure means the node's row silently stops
        // reflecting reality (load, backends, version), and every surface
        // built on this table then reasons from stale data. WARN so a broken
        // heartbeat write is visible rather than inferred later from
        // impossible values.
        tracing::warn!(error = %e, node_id = %node_id, "cluster_nodes upsert failed");
    }

    // A node that's heartbeating again is recovered — reset its revive
    // backoff so the next outage starts fresh at 60s instead of inheriting
    // the previous outage's capped 1h delay.
    crate::autonomy_evaluators::clear_revive_backoff(&state, &node_id).await;

    tracing::debug!(node_id = %node_id, "heartbeat received");
    Json(json!({"status": "ok"}))
}

/// DELETE /api/cluster/nodes/{id}/forget — drop a node's controller-side
/// state WITHOUT contacting it (finding #76): DB row + mesh KV entry. The
/// only row-delete used to live inside clean_node, which needs a LIVE
/// agent — useless after a teardown just dismantled it, so teardown ended
/// with "still yours: clear the cluster DB row" and no command to do it.
/// Teardown now calls this as its final controller-side act.
async fn node_forget(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> AppResult {
    let deleted = sqlx::query("DELETE FROM cluster_nodes WHERE node_id = $1")
        .bind(&node_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    // The node's DECLARED state goes too: its config row (address, policy,
    // tier — what `noo cluster set-config` writes) and its placements.
    // Neither was touched before, so a forgotten node lived on in
    // `noo_node_config` with no verb able to remove it; on host8 a stale
    // `host8` row (an earlier enrolment of the controller under its
    // hostname without the hyphen) sat beside the live `host8` at the
    // same address for eleven days, and the first thing to look a node up
    // by address found it (2026-09-22, the first dispatched turn).
    let config_rows = sqlx::query("DELETE FROM noo_node_config WHERE node_id = $1")
        .bind(&node_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    let placements = sqlx::query("DELETE FROM noo_backend_placements WHERE node_id = $1")
        .bind(&node_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    // The node's redeemed enrollments go with the row. They are what
    // `noo cluster provision` resolves a node from and what `noo upgrade
    // --nodes` enumerates; left live, a forgotten node kept being restaged
    // and its name kept resolving. Revoked, not deleted: the
    // record of who enrolled what, when, stays.
    let enrollments_revoked = sqlx::query(
        "UPDATE noo_bootstrap_tokens SET revoked = true \
         WHERE node_name = $1 AND used_at IS NOT NULL AND NOT revoked",
    )
    .bind(&node_id)
    .execute(&state.db)
    .await?
    .rows_affected();
    let mut kv_had_entry = false;
    let mut kv_purged = false;
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        kv_had_entry = matches!(kv.entry(&node_id).await, Ok(Some(_)));
        kv_purged = kv.purge(&node_id).await.is_ok();
    }
    // Nothing anywhere answered to that name: say so, rather than report a
    // typo as a node forgotten. A verb that returns "ok" for a name it
    // never held teaches the operator nothing about the row they meant.
    if deleted == 0 && config_rows == 0 && placements == 0 && enrollments_revoked == 0 && !kv_had_entry {
        return Err(AppError::NotFound(format!(
            "no node named '{node_id}' in the registry, its config, its placements, its enrollments or the mesh — nothing to forget"
        )));
    }
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::NodeForgotten, "gateway", &format!("node:{node_id}"))
            .details(json!({ "node": node_id, "db_rows": deleted, "config_rows": config_rows,
                "placements": placements, "kv_purged": kv_purged,
                "enrollments_revoked": enrollments_revoked })),
    ).await;
    Ok(Json(json!({
        "status": "forgotten", "node": node_id,
        "db_rows": deleted, "config_rows": config_rows, "placements": placements,
        "kv_purged": kv_purged, "enrollments_revoked": enrollments_revoked,
    })))
}

async fn node_register(
    State(_state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(_body): Json<Value>,
) -> AppJson {
    tracing::info!(node_id = %node_id, "node registered via path");
    Json(json!({"status": "registered", "node_id": node_id}))
}

/// Node registration — stores static data (GPU, CPU, RAM, capabilities).
/// One alert per node per day. The condition is a standing posture, not an
/// event: a node re-registers on every agent restart, and paging on each
/// would train the operator to ignore the one alert that matters.
const PEER_IDENTITY_ALERT_COOLDOWN_SECS: i64 = 86_400;

/// Same cadence as the peer-identity alert: a refusal is a standing
/// condition an operator fixes once, not an event stream.
const RECONCILE_REFUSAL_ALERT_COOLDOWN_SECS: i64 = 86_400;

/// Heartbeats later update only live metrics without overwriting this.
async fn node_register_body(
    State(state): State<Arc<AppState>>,
    caller: Option<axum::Extension<crate::auth::ClusterNode>>,
    Json(body): Json<Value>,
) -> Result<AppJson, AppError> {
    let node_id = body.get("node_id")
        .or(body.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    // A node registers ITSELF: the record it writes (ip_address, agent
    // URL, capabilities) is what the gateway later dials for that node id.
    // the design — a node token must not register as another node.
    if let Some(axum::Extension(crate::auth::ClusterNode(actor, crate::auth::ClusterKind::Node))) = &caller {
        if actor != node_id {
            tracing::warn!(actor = %actor, claimed = %node_id, "node_register refused: token actor is not the registered node");
            return Err(AppError::Forbidden(format!("node token for '{actor}' cannot register '{node_id}'")));
        }
    }

    // A node that cannot tell the controller from a peer serves its
    // start/stop/pull/clean routes to any holder of the shared fleet
    // secret — which is every node. The agent knows; until it reported
    // this the only trace was a line in its own journal, invisible here.
    // Absence is not "fine": an agent too old to send the field has not
    // said it is enforcing, so it is reported as unknown, not as safe.
    match body.get("peer_identity_enforced").and_then(|v| v.as_bool()) {
        Some(true) => {}
        Some(false) => {
            tracing::warn!(node_id = %node_id, "node_register_peer_identity_unenforced");
            crate::operator_alert::send_operator_alert_with(
                &state,
                crate::operator_alert::OperatorAlert::new(
                    "node.peer_identity_unenforced",
                    node_id,
                    format!(
                        "⚠️ Node `{node_id}` registered without peer identity \
                         enforcement: any holder of the fleet secret can drive its agent."
                    ),
                )
                .detail(
                    "its agent has no TLS cert/key/CA, so its start/stop/pull/clean routes \
                     accept any holder of the fleet secret; re-run host prep to install \
                     the node's PKI material",
                )
                .investigate(format!("noo cluster verify {node_id}")),
                PEER_IDENTITY_ALERT_COOLDOWN_SECS,
            )
            .await;
        }
        None => {
            tracing::info!(node_id = %node_id, "node_register_peer_identity_unknown");
        }
    }

    // Flatten capabilities into top-level fields for dashboard compatibility
    let caps = body.get("capabilities").cloned().unwrap_or(json!({}));
    let data = json!({
        "id": node_id,
        "hostname": body.get("hostname").and_then(|h| h.as_str()).unwrap_or(node_id),
        "ip_address": body.get("ip_address"),
        "tier": caps.get("tier").or(body.get("tier")),
        "gpu_model": caps.get("gpu_model"),
        "gpu_count": caps.get("gpu_count"),
        "vram_gb": caps.get("vram_gb"),
        "cpu_cores": caps.get("cpu_cores"),
        "ram_gb": caps.get("ram_gb"),
        "is_arm": caps.get("is_arm"),
        "backends": caps.get("backends").or(body.get("backends")),
        "tools": caps.get("tools").or(body.get("tools")),
        "platform": caps.get("platform").or(body.get("platform")),
        "app_version": caps.get("app_version").or(body.get("app_version")),
        // Kept on the record (and refreshed by every heartbeat) so `noo
        // cluster verify` can fail a node whose agent does not require a
        // client certificate — it used to be alerted on and then dropped.
        "peer_identity_enforced": body.get("peer_identity_enforced"),
        "npu_tops": caps.get("npu_tops").or(body.get("npu_tops")),
        "power_budget_watts": caps.get("power_budget_watts").or(body.get("power_budget_watts")),
        "capabilities": caps,
        "status": "online",
        "running_backends": {},
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64(),
    });

    // No VRAM → no GPU (drops a stale/copied GPU_MODEL at registration too).
    let mut data = data;
    clamp_gpu_model(&mut data);
    // A registration rebuilds the record from scratch, so the leaves the
    // node holds ride it too, or `cluster verify` reads the gap until the
    // next beat as an agent that does not report them.
    carry_reported(&mut data, &body, "backend_leaves");
    // And the data roots, or a re-registration hides the
    // root the node runs on from provision until the next beat.
    carry_reported(&mut data, &body, "data_roots");
    // And the legacy-lane counts.
    carry_reported(&mut data, &body, "legacy_lanes");
    // And the last model bench (the harness profile's measured speed).
    carry_reported(&mut data, &body, "model_bench");
    // Same for the sidecar image report and the backend
    // container start times + health.
    carry_reported(&mut data, &body, "stunnel_image");
    carry_reported(&mut data, &body, "image_sources");
    carry_reported(&mut data, &body, "image_source_mode");
    carry_reported(&mut data, &body, "backend_containers");
    carry_reported(&mut data, &body, "gpu_contention");
    carry_reported(&mut data, &body, "model_presence");
    carry_reported(&mut data, &body, "model_stats");
    // The agent admits the gateway's leaf with no bearer;
    // false when the registration does not say, and noted at once so the
    // first call after a registration already uses the right credential.
    data[crate::node_agent_auth::CAPABILITY] = json!(crate::node_agent_auth::reported(&body));
    // The control transports the agent offers (https listener / NATS RPC /
    // tunnel). Written every beat; an agent that does not say is an older
    // one and reads as the HTTPS listener only.
    data[crate::node_link::TRANSPORTS_FIELD] = crate::node_link::reported_transports(&body);
    crate::node_agent_auth::note(node_id, &data);

    // Write full registration to NATS KV
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        let payload = serde_json::to_vec(&data).unwrap_or_default();
        let _ = kv.put(node_id, payload.into()).await;
    }

    tracing::info!(node_id = %node_id, "node registered");
    Ok(Json(json!({"status": "registered", "node_id": node_id})))
}

/// Build the canonical cluster node list — NATS KV (full registration data)
/// merged with gossip (live load) and with the persistent `cluster_nodes`
/// table (offline stragglers).
///
/// Extracted from `cluster_nodes` so that `/api/cluster/status` can count the
/// SAME population. Previously the two endpoints derived `total_nodes` from
/// different sources — /api/cluster/status counted only `gossip.alive_peers()`
/// and had no `offline` bucket at all — so a node dying made one endpoint's
/// total shrink while the other's held steady. Same fact, two answers.
///
/// Returns `(nodes, offline_merge_error)`. The second element is `Some(msg)`
/// when the DB half could not be read, so callers can say so instead of
/// silently serving a short list.
/// Render the node's self-reported NATS bus state into `(nats_state,
/// nats_state_detail)`.
///
/// Three-valued on purpose. `null` means the node-agent never sent the
/// field — an older binary, or one with no messaging subsystem — and that is
/// a different answer from "reported as down". Collapsing the two would
/// recreate the exact failure this change exists to expose: a node that is
/// HTTP-alive and bus-deaf reading as fine.
fn derive_nats_state(reported: Option<&Value>) -> (Value, String) {
    let Some(bus) = reported.filter(|v| !v.is_null()) else {
        return (
            Value::Null,
            "not reported — this node-agent build does not send nats_status".to_string(),
        );
    };

    let state = bus
        .get("state")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown")
        .to_string();
    let connected = bus.get("connected").and_then(|c| c.as_bool());
    let bound = bus.get("job_dispatch_bound").and_then(|b| b.as_bool());

    let detail = match (connected, bound) {
        (Some(true), Some(true)) => {
            "as reported by the node-agent: connected, dispatch durable bound".to_string()
        }
        (Some(true), Some(false)) => "as reported by the node-agent: connected but the dispatch \
             durable is NOT bound — dispatched jobs will strand"
            .to_string(),
        (Some(true), None) => "as reported by the node-agent: connected".to_string(),
        (Some(false), _) => {
            format!("as reported by the node-agent: NOT connected ({state}) — jobs dispatched to this node will strand")
        }
        (None, _) => format!("reported without a connected flag ({state})"),
    };

    (json!(state), detail)
}

/// A node that gossip calls alive but whose last HEARTBEAT is older than the
/// offline threshold is not `online`.
///
/// `mesh_nodes` entries expire after 120 s, and that expiry is the liveness
/// signal — but `node_reachability` and the quarantine evaluator rewrite the
/// entry without touching `last_heartbeat`, resetting the TTL. A node that
/// stopped heartbeating therefore stayed in the bucket, stayed a gossip peer,
/// and read `online` for 267 s at a time while the
/// DB-backed evaluator, using the same threshold below, paged that it was
/// gone. The heartbeat is the authority for `online`; gossip only supplies
/// load. Same predicate and thresholds as the evaluator, so the two agree.
///
/// `unknown`, not `offline`: gossip says the node is up, the heartbeat says
/// it is not, and the controller cannot decide between them — which is what
/// `unknown` means everywhere else in this list. No timestamp at all (an
/// entry that predates both fields) is left as gossip reported: nothing to
/// contradict it with.
fn demote_if_heartbeat_stale(data: &mut Value, now: f64) {
    let has_stamp = data.get("last_heartbeat").and_then(|v| v.as_f64()).is_some()
        || data.get("ts").and_then(|v| v.as_f64()).is_some();
    if !has_stamp || !crate::autonomy_evaluators::is_node_offline(data, now) {
        return;
    }
    let age = data
        .get("last_heartbeat")
        .and_then(|v| v.as_f64())
        .or_else(|| data.get("ts").and_then(|v| v.as_f64()))
        .map(|t| (now - t).max(0.0) as i64)
        .unwrap_or(0);
    data["status"] = json!("unknown");
    data["status_detail"] = json!(format!(
        "unknown — gossip lists the node as alive but its last heartbeat was {age}s ago; \
         it is not reporting"
    ));
}

pub(crate) async fn collect_cluster_nodes(state: &Arc<AppState>) -> (Vec<Value>, Option<String>) {
    let mut nodes: Vec<Value> = Vec::new();
    // The declared harness policy per node. It lives in `noo_node_config`, so
    // it reaches a record only if something reads that table — and this list
    // never did, while `/api/cluster/<id>` did. `noo cluster verify` reads THIS
    // list and resolved the absent field to its own `"manual"` default, so the
    // harness invariant printed a green `policy manual` for all five nodes of a
    // fleet whose policies it had not looked at. One query for the
    // whole fleet, resolved exactly as the single-node route resolves it.
    let harness_policies: std::collections::HashMap<String, String> =
        sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT node_id, harness_policy FROM noo_node_config",
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(id, p)| p.map(|p| (id, p)))
        .collect();
    let task_holds = node_task_holds(&state.db).await;
    // node_ids seen live in KV — used to suppress duplicate DB rows when
    // merging known-but-missing (offline) nodes below.
    let mut live_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Try NATS KV first (has full registration data from node-agent)
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        use tokio_stream::StreamExt;
        if let Ok(keys) = kv.keys().await {
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
            for key in keys {
                if key == "gateway" { continue; } // Skip gateway's own entry
                if let Ok(Some(entry)) = kv.get(&key).await {
                    if let Ok(mut data) = serde_json::from_slice::<Value>(&entry) {
                        // Skip non-worker nodes (tier 0 = gateway)
                        if data.get("tier").and_then(|t| t.as_u64()) == Some(0) { continue; }
                        // Inbound reachability lives outside the TTL'd entry
                        // merge it back so the record keeps
                        // the shape readers parse. Absent = "not yet checked".
                        let inbound = crate::node_reachability::read_inbound(state, &key).await;
                        crate::node_reachability::apply_inbound(&mut data, inbound.as_deref());
                        // Merge live load from gossip if available
                        let peers = state.gossip.alive_peers();
                        if let Some(peer) = peers.iter().find(|p| p.node_id == key) {
                            data["current_load"] = json!(peer.load);
                            data["status"] = json!(if peer.load < 0.9 { "online" } else { "busy" });
                            data["status_detail"] =
                                json!("live from gossip (node is an alive peer)");
                            // Gossip presence is not a heartbeat:
                            // the entry is kept alive by writers that never
                            // touch `last_heartbeat`, so a node silent for
                            // minutes still gossips "alive".
                            demote_if_heartbeat_stale(&mut data, unix_now_f64());
                            // Update backends from gossip (more current than KV)
                            if !peer.backends.is_empty() {
                                let mut rb = serde_json::Map::new();
                                for (bt, info) in &peer.backends {
                                    rb.insert(bt.clone(), json!(info.model));
                                }
                                data["running_backends"] = Value::Object(rb);
                            }
                        } else {
                            // Absent from gossip. The old code left whatever
                            // `status` the KV entry carried — and node_heartbeat
                            // unconditionally writes "online", while
                            // node_register defaults to "online" too. So a node
                            // that stopped gossiping kept asserting "online"
                            // until its KV entry TTL-expired. Liveness we cannot
                            // observe is "unknown", not "online"; "offline" is
                            // reserved for the DB-merge path below, where the
                            // node is absent from the live view entirely.
                            data["status"] = json!("unknown");
                            data["status_detail"] = json!(
                                "unknown — registration is present in NATS KV but \
                                 the node is not an alive gossip peer, so its \
                                 liveness cannot be confirmed from here"
                            );

                            // The node may have told us WHY. `nats_status` is
                            // its own report of its bus (heartbeat POST), and
                            // gossip absence is exactly what a dead bus looks
                            // like from here. Naming it turns an unexplained
                            // "unknown" into a diagnosis — without inventing a
                            // second liveness verdict: `status` stays
                            // "unknown", because this is still the node's
                            // claim, not our measurement.
                            if let Some(bus) = data.get("nats_status").cloned() {
                                let connected = bus.get("connected")
                                    .and_then(|c| c.as_bool());
                                let bus_state = bus.get("state")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                if connected == Some(false) {
                                    data["status_detail"] = json!(format!(
                                        "unknown — no gossip, and the node itself reports its \
                                         NATS client is {bus_state}: it is HTTP-alive but \
                                         bus-deaf, so jobs dispatched to it will strand"
                                    ));
                                } else if connected == Some(true) {
                                    data["status_detail"] = json!(
                                        "unknown — no gossip, yet the node reports its NATS \
                                         client as connected. Either its gossip publisher is \
                                         stuck or this gateway's gossip subscriber is"
                                    );
                                }
                            }
                        }

                        // Surface the node-reported bus state on every node,
                        // gossiping or not, with an explicit detail string.
                        // Derived HERE only — one authoritative source per
                        // fact; every
                        // other endpoint reads this, none recomputes it.
                        let (bus_state, bus_detail) = derive_nats_state(data.get("nats_status"));
                        data["nats_state"] = bus_state;
                        data["nats_state_detail"] = json!(bus_detail);
                        // Which PRINCIPAL the node authenticates as, surfaced
                        // beside the state it belongs to. "node" = its own
                        // per-principal credential, "shared" = the fleet-wide
                        // fallback, "anonymous" = none. Absent when the agent
                        // predates the field — which is "not reported", never
                        // "anonymous", so it is left absent rather than
                        // defaulted.
                        //
                        // Two nodes on different credentials report identical
                        // `connected: true`; on 2026-09-05 telling them apart
                        // was the whole diagnosis of a gossip outage, and it
                        // was not visible anywhere.
                        if let Some(role) = data.get("nats_status")
                            .and_then(|b| b.get("role"))
                            .and_then(|r| r.as_str())
                            .filter(|r| !r.is_empty())
                            .map(str::to_string)
                        {
                            data["nats_role"] = json!(role);
                        }
                        // The tier this node's LIVE facts imply, beside the
                        // one it declares. node_tier::derive already runs on
                        // every autonomy tick, but its answer only reached an
                        // audit row — so an operator comparing "what this box
                        // is" against "what it says it is" had nowhere to look.
                        //
                        // Declared tier changes only when a bundle re-renders
                        // the agent env, and node_tier_drift is disarmed by
                        // default, so a disagreement persists silently: host6
                        // declared 4 while deriving 2 on a 24 GB Mac.
                        //
                        // OMITTED, not defaulted, when the facts do not decide.
                        // `derive` returns Unknown rather than guessing, and
                        // turning that into a number here would manufacture a
                        // disagreement out of silence — the exact thing that
                        // module header warns against.
                        if let crate::node_tier::TierVerdict::Derived { tier, reason } =
                            crate::node_tier::derive(&crate::node_tier::facts_from_capabilities(
                                data.get("capabilities").unwrap_or(&json!({})),
                            ))
                        {
                            data["derived_tier"] = json!(tier);
                            data["derived_tier_reason"] = json!(reason);
                        }
                        // Ensure required fields exist
                        if data.get("id").is_none() {
                            data["id"] = json!(key);
                        }
                        // Use node ID as hostname if hostname is a container ID
                        let hostname = data.get("hostname").and_then(|h| h.as_str()).unwrap_or("");
                        let id = data.get("id").and_then(|i| i.as_str()).unwrap_or(&key);
                        if hostname.is_empty() || (hostname.len() == 12 && hostname.chars().all(|c| c.is_ascii_hexdigit())) {
                            data["hostname"] = json!(id);
                        }

                        // Dashboard expects `backends` as array of "type: model" strings
                        if let Some(rb) = data.get("running_backends").and_then(|r| r.as_object()) {
                            let arr: Vec<String> = rb.iter()
                                .map(|(k, v)| format!("{}: {}", k, v.as_str().unwrap_or("?")))
                                .collect();
                            data["backends"] = json!(arr);
                        }

                        // Dashboard expects `last_heartbeat` as ISO string with Z suffix
                        if let Some(ts) = data.get("last_heartbeat").and_then(|t| t.as_f64()) {
                            // Say which store answered and how old it is, so no
                            // reader has to infer it from the timestamp's
                            // precision.
                            data["last_heartbeat_source"] = json!("gossip-kv");
                            data["heartbeat_age_secs"] = json!((unix_now_f64() - ts).max(0.0) as i64);
                            let secs = ts as i64;
                            let dt = chrono::DateTime::from_timestamp(secs, 0)
                                .map(|d| d.to_rfc3339());
                            if let Some(iso) = dt {
                                data["last_heartbeat"] = json!(iso.replace("+00:00", "Z"));
                            }
                        }

                        // ip alias for dashboard compatibility
                        data["ip"] = data.get("ip_address").cloned().unwrap_or(json!(null));

                        // Declared harness policy — the row when there is one,
                        // otherwise the same fleet default the single-node
                        // route applies. Never absent, so a consumer cannot
                        // quietly substitute a default of its own.
                        // Own the key: `id` above borrows `data`, and reading
                        // it here would hold that borrow across the writes.
                        let policy_key =
                            data.get("id").and_then(|i| i.as_str()).unwrap_or(&key).to_string();
                        data["harness_policy"] = json!(harness_policies
                            .get(&policy_key)
                            .cloned()
                            .unwrap_or_else(crate::coordinator::harness_default_policy));
                        // What the node's harness holds (i227 fix 4): absent
                        // only when the query failed, never defaulted.
                        if let Some(holds) = task_holds.as_ref() {
                            data["tasks"] = holds.get(&policy_key).cloned().unwrap_or_else(|| json!({"running": 0, "queued": 0}));
                        }

                        // Companion telemetry fields (tier >= 4) — preserve from KV if present
                        // These are already in the KV data if heartbeat wrote them;
                        // no filtering needed, they pass through naturally.

                        // No VRAM → no GPU. Defensive at read time so a
                        // bad gpu_model already sitting in KV (written
                        // before the heartbeat clamp existed) still
                        // displays correctly without waiting for the next
                        // heartbeat to overwrite it.
                        clamp_gpu_model(&mut data);

                        live_ids.insert(key.clone());
                        nodes.push(data);
                    }
                }
            }
        }
    }

    // Fallback: if KV had no data, use gossip peers (exclude gateway itself)
    if nodes.is_empty() {
        let peers = state.gossip.alive_peers();
        for p in peers.iter().filter(|p| p.tier > 0) {
            nodes.push(json!({
                "id": p.node_id,
                "hostname": p.hostname,
                "status": if p.load < 0.9 { "online" } else { "busy" },
                "current_load": p.load,
                "tier": p.tier,
                "vram_gb": p.vram_gb,
                "running_backends": p.backends.iter()
                    .map(|(k, v)| (k.clone(), json!(v.model)))
                    .collect::<serde_json::Map<String, Value>>(),
                "capabilities": {"backends": p.backends.keys().collect::<Vec<_>>()},
            }));
        }
    }

    // Merge known-but-missing nodes from the persistent cluster_nodes table.
    // KV entries TTL-expire, so a node that stops heartbeating vanishes from
    // the live view above. The DB row survives — surface it as `offline` (with
    // last-known hardware + last_heartbeat) so an enrolled node never silently
    // disappears. `noo cluster restart-agent` (POST
    // /api/cluster/nodes/{node_id}/restart-agent) is the remote action on these.
    let db_rows = sqlx::query_as::<_, (
        String, String, Option<String>, i32, Option<String>,
        Option<f64>, Option<i32>, Option<f64>, Option<bool>,
        Option<Value>, Option<chrono::DateTime<chrono::Utc>>,
    )>(
        // 30-day window: a node not seen in a month is decommissioned, not
        // "temporarily offline" — don't resurrect ancient rows as cards.
        "SELECT node_id, hostname, ip_address, tier, gpu_model, \
                vram_gb, cpu_cores, ram_gb, is_arm, running_backends, last_heartbeat \
         FROM cluster_nodes \
         WHERE last_heartbeat IS NOT NULL \
           AND last_heartbeat > NOW() - INTERVAL '30 days' \
         ORDER BY node_id"
    )
    .fetch_all(&state.db)
    .await;

    // `.unwrap_or_default()` used to sit here: a database outage silently
    // DELETED every offline node from the listing, so the dashboard showed a
    // smaller, all-healthy cluster and an operator lost exactly the nodes they
    // needed to see. Surface the failure instead of shrinking the fleet.
    let (db_rows, offline_merge_error) = match db_rows {
        Ok(rows) => (rows, None),
        Err(e) => (
            Vec::new(),
            Some(format!(
                "offline nodes are missing from this list: cannot read \
                 cluster_nodes: {e}"
            )),
        ),
    };

    for (node_id, hostname, ip, tier, gpu_model, vram, cpu_cores, ram, is_arm, rb, last_hb) in db_rows {
        if live_ids.contains(&node_id) {
            continue; // already shown live
        }
        let backends: Vec<String> = rb
            .as_ref()
            .and_then(|v| v.as_object())
            .map(|m| m.iter().map(|(k, v)| format!("{}: {}", k, v.as_str().unwrap_or("?"))).collect())
            .unwrap_or_default();
        let mut node = json!({
            "id": node_id,
            "hostname": hostname,
            "ip": ip.clone(),
            "ip_address": ip,
            "tier": tier,
            "gpu_model": gpu_model,
            "vram_gb": vram.unwrap_or(0.0),
            "cpu_cores": cpu_cores,
            "ram_gb": ram,
            // NULL stays null — "we never learned this node's architecture" is
            // not the same claim as "it is x86", and a consumer that ships an
            // image based on the difference must see the difference.
            "is_arm": is_arm,
            "backends": backends,
            "running_backends": rb.unwrap_or_else(|| json!({})),
            "status": "offline",
            "last_heartbeat": last_hb.map(|t| t.to_rfc3339().replace("+00:00", "Z")),
            "last_heartbeat_source": "database",
            "heartbeat_age_secs": last_hb.map(|t| (chrono::Utc::now() - t).num_seconds().max(0)),
        });
        clamp_gpu_model(&mut node);
        nodes.push(node);
    }

    // Role capabilities: what each node serves, DERIVED from its role
    // placements + its heartbeat (`role_capability`). The one place this is
    // computed; `noo cluster status/show`, the UI and routing all read it.
    // A failed read leaves the field off rather than claiming "serves nothing".
    if let Ok(facts) = crate::role_capability::all_facts(&state.db).await {
        for n in nodes.iter_mut() {
            let id = n.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
            let mine: Vec<crate::role_capability::PlacementFact> = facts.iter().filter(|f| f.node_id == id).cloned().collect();
            let caps = crate::role_capability::derive(n, &mine);
            n["capabilities_summary"] = json!(crate::role_capability::summary(&caps));
            n["role_capabilities"] = json!(caps);
        }
    }

    (nodes, offline_merge_error)
}

/// Count nodes by the `status` string `collect_cluster_nodes` assigned.
fn count_status(nodes: &[Value], want: &str) -> usize {
    nodes
        .iter()
        .filter(|n| n.get("status").and_then(|s| s.as_str()) == Some(want))
        .count()
}

/// Cluster-wide counts derived from one node list, so every endpoint that
/// reports them reports the same numbers.
///
/// `total_nodes` and `offline` become `null` when the offline merge failed:
/// both are understated by an unknown amount in that case, and an understated
/// total is the failure mode this audit exists to remove. `online` / `busy` /
/// `unknown` stay real — they are derived wholly from the live sources.
fn node_stats(nodes: &[Value], offline_merge_error: Option<&str>) -> Value {
    let online = count_status(nodes, "online");
    let busy = count_status(nodes, "busy");
    let unknown = count_status(nodes, "unknown");
    let offline = count_status(nodes, "offline");

    match offline_merge_error {
        None => json!({
            "total_nodes": nodes.len(),
            "online": online,
            "busy": busy,
            "unknown": unknown,
            "offline": offline,
        }),
        Some(err) => json!({
            "total_nodes": Value::Null,
            "online": online,
            "busy": busy,
            "unknown": unknown,
            "offline": Value::Null,
            "error": err,
        }),
    }
}

/// List all cluster nodes — dashboard-expected format.
pub(crate) async fn cluster_nodes(State(state): State<Arc<AppState>>) -> AppJson {
    let (mut nodes, offline_merge_error) = collect_cluster_nodes(&state).await;
    let stats = node_stats(&nodes, offline_merge_error.as_deref());
    // Control calls by transport since this gateway started, per node: the
    // number the "outbound-only" gate (i131 phase 3) reads. Zeros for a node
    // this gateway has not called.
    for n in nodes.iter_mut() {
        if let Some(id) = n.get("id").and_then(Value::as_str).map(str::to_string) {
            n["control_calls"] = crate::node_rpc::counts_json(&id);
        }
    }

    Json(json!({
        "nodes": nodes,
        "stats": stats,
        "error": offline_merge_error,
    }))
}

/// Annotate a backend list with the two facts an idle-scaledown decision
/// needs and the payload never carried.
///
/// - `pinned` — the fleet DECLARED this backend should be running
///   (`noo_backend_placements.desired_state = 'running'`). Stopping one is
///   pointless and harmful: the node-agent's desired-state reconciler starts
///   it straight back up, so all an automated scaledown achieves is a flap.
///   This is the real, sourced meaning of the `pinned` field the heartbeat
///   `idle_scaledown` action has always read and nothing ever wrote.
/// - `last_inference_ts` — Unix seconds of the most recent completion
///   attributed to this `(node_id, backend)` in `noo_token_usage`, the one
///   place the gateway records that a backend actually served something
///   (`usage.rs`). **Absent** when there is no such row — which means "not
///   known to have served anything", NOT "idle since forever". Consumers must
///   treat absence as unknown; see `heartbeat_actions::action_idle_scaledown`.
///
/// Both lookups are best-effort: a failed query annotates nothing rather than
/// failing the listing, because this endpoint is also the dashboard's.
async fn annotate_backend_activity(state: &AppState, backends: &mut [Value]) {
    let pinned: std::collections::HashSet<(String, String)> =
        crate::repo::cluster::placements_desired_running(&state.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();

    // Runtime API, not the `query!` macro: `noo_token_usage` postdates the
    // offline cache and is written the same way in `usage.rs`.
    let usage: Vec<(Option<String>, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT node_id, backend, MAX(ts) FROM noo_token_usage \
         WHERE ts > now() - interval '30 days' GROUP BY node_id, backend",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let last_seen: std::collections::HashMap<(String, String), i64> = usage
        .into_iter()
        .filter_map(|(node, backend, ts)| node.map(|n| ((n, backend), ts.timestamp())))
        .collect();

    for b in backends.iter_mut() {
        let node = b.get("node_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bt = b
            .get("backend_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let key = (node, bt);
        b["pinned"] = json!(pinned.contains(&key));
        if let Some(ts) = last_seen.get(&key) {
            b["last_inference_ts"] = json!(ts);
        }
    }
}

/// List running backends across all nodes
pub(crate) async fn cluster_backends(State(state): State<Arc<AppState>>) -> AppJson {
    let mut backends: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Primary source: NATS KV heartbeat data (has running_backends from all nodes)
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        use tokio_stream::StreamExt;
        if let Ok(keys) = kv.keys().await {
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
            for key in keys {
                if key == "gateway" { continue; }
                if let Ok(Some(entry)) = kv.get(&key).await {
                    if let Ok(data) = serde_json::from_slice::<Value>(&entry) {
                        let hostname = data.get("hostname").and_then(|h| h.as_str()).unwrap_or(&key);
                        let load = data.get("load").and_then(|l| l.as_f64()).unwrap_or(0.0);
                        if let Some(rb) = data.get("running_backends").and_then(|r| r.as_object()) {
                            for (bt, model_val) in rb {
                                let model = model_val.as_str().unwrap_or("?");
                                let sig = format!("{}:{}:{}", key, bt, model);
                                if seen.insert(sig) {
                                    backends.push(json!({
                                        "node_id": key,
                                        "backend": bt,
                                        "backend_type": bt,
                                        "model": model,
                                        "status": "running",
                                        "hostname": hostname,
                                        "load": load,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: gossip peers (for nodes not yet in NATS KV)
    for p in &state.gossip.alive_peers() {
        for (bt, info) in &p.backends {
            let sig = format!("{}:{}:{}", p.node_id, bt, info.model);
            if seen.insert(sig) {
                backends.push(json!({
                    "node_id": p.node_id,
                    "backend": bt,
                    "backend_type": bt,
                    "model": info.model,
                    "url": info.url,
                    "status": "running",
                    "hostname": p.hostname,
                    "load": p.load,
                }));
            }
        }
    }

    annotate_backend_activity(&state, &mut backends).await;

    // Build grouped view
    let mut grouped: serde_json::Map<String, Value> = serde_json::Map::new();
    for b in &backends {
        let bt = b.get("backend_type").and_then(|v| v.as_str()).unwrap_or("unknown");
        let entry = grouped.entry(bt.to_string()).or_insert(json!({"name": bt, "replicas": 0, "nodes": []}));
        if let Some(count) = entry.get("replicas").and_then(|v| v.as_u64()) {
            entry["replicas"] = json!(count + 1);
        }
        if let Some(arr) = entry.get_mut("nodes").and_then(|v| v.as_array_mut()) {
            arr.push(json!({"node_id": b.get("node_id"), "model": b.get("model")}));
        }
    }

    Json(json!({"backends": backends, "grouped": grouped}))
}

/// GPU metrics — fetches Prometheus metrics from nvidia-exporter and parses
/// per-GPU data (temperature, power, memory, utilization). Falls back to
/// gossip-based node data if the exporter is unreachable.
pub(super) async fn cluster_gpu_metrics(State(state): State<Arc<AppState>>) -> AppJson {
    let exporter_url = crate::config::env_or_yaml(
        "NVIDIA_EXPORTER_URL",
        |c| c.services.nvidia_exporter_url.clone(),
        // The exporter refuses to serve without mTLS (docker/nvidia-smi-exporter.py),
        // so a plaintext default was a URL that could never answer.
        "https://nvidia-exporter:9400/metrics",
    );

    let client = crate::tls::cluster_client();

    match client.get(&exporter_url).timeout(std::time::Duration::from_secs(5)).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            let mut gpus = parse_prometheus_gpu_metrics(&body);
            // The exporter is the controller's own, so these GPUs belong
            // to the controller node. Name it: the kiosk (and anything
            // else) joins GPU ↔ node on `node_id`/`hostname`, and until
            // 2026-09-12 neither path carried them.
            let (self_id, self_host) = controller_identity();
            for g in gpus.iter_mut() {
                if let Value::Object(m) = g {
                    m.entry("node_id").or_insert(json!(self_id));
                    m.entry("hostname").or_insert(json!(self_host));
                }
            }
            Json(json!({"gpus": gpus}))
        }
        Ok(resp) => {
            Json(json!({
                "error": format!("nvidia-exporter returned {}", resp.status()),
                "gpus": [],
            }))
        }
        Err(_) => {
            // Fallback: proxy to node agents' /gpu endpoint
            let agents = all_node_agents(&state).await;
            let mut all_gpus = Vec::new();
            for (node_id, agent_url, hostname) in &agents {
                let req = crate::node_link::NodeLink::for_base(agent_url)
                    .request(reqwest::Method::GET, "/gpu")
                    .timeout(std::time::Duration::from_secs(3));
                if let Ok(resp) = req.send().await {
                    if let Ok(data) = resp.json::<Value>().await {
                        if data.get("available").and_then(|v| v.as_bool()) == Some(true) {
                            // Node agent returns flat metrics; transform to match observe.js format
                            // observe.js expects: temperature, memory_used (MB, /1024 → GB), power, utilization, name
                            let gpu_model = data.get("gpu_model").and_then(|v| v.as_str()).unwrap_or("GPU");
                            // Each of these was `.unwrap_or(0.0)`: a field the
                            // node-agent omitted or renamed rendered as a real
                            // reading of 0 °C / 0 W / 0% utilization. "0%
                            // utilization" is not cosmetic — it is an input to
                            // placement decisions and to the operator's read of
                            // whether a GPU is busy. An absent metric is now
                            // null, which consumers can render as "—" instead
                            // of as an idle, ice-cold GPU.
                            all_gpus.push(json!({
                                // The GPU's MODEL, not the machine it is in.
                                // This was `hostname`, so every tile on this
                                // path was labelled with its own host — and
                                // since the tile already shows the node, an
                                // operator saw "host3 host3" and "host8
                                // host8" (the two spellings being node_id and
                                // hostname) and read one machine as two.
                                // `gpu_model` was already being read two lines
                                // up and then ignored. Where the node-agent
                                // reports no model it is "GPU", which is
                                // uninformative but true; the hostname here
                                // was informative and false.
                                "name": gpu_model,
                                "node_id": node_id.clone(),
                                "hostname": hostname.clone(),
                                "gpu_model": gpu_model,
                                "index": all_gpus.len().to_string(),
                                "temperature": metric_or_null(&data, "temperature_c"),
                                "memory_used": metric_or_null(&data, "memory_used_mb"),
                                "power": metric_or_null(&data, "power_draw_w"),
                                "utilization": metric_or_null(&data, "gpu_utilization_percent"),
                            }));
                        }
                    }
                }
            }
            Json(json!({"gpus": all_gpus, "source": if all_gpus.is_empty() { "none" } else { "node_agent" }}))
        }
    }
}

/// The controller's own node identity, for telemetry that is sampled
/// locally (the nvidia-exporter path above) and therefore never passed
/// through a node-agent that would have named itself. `NOO_CONTROLLER_NODE_ID`
/// is what the self-node lane registers under; the hostname falls back to
/// the container's, which is at least stable per deployment.
fn controller_identity() -> (String, String) {
    let host = std::env::var("NOO_CONTROLLER_HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "controller".to_string());
    let id = crate::self_node::self_node_id().unwrap_or_else(|| host.clone());
    (id, host)
}

/// Read one numeric telemetry field, returning JSON `null` when it is absent
/// or not a number — never a substituted `0.0`.
///
/// A missing measurement and a measurement of zero are different facts. The
/// previous `.and_then(as_f64).unwrap_or(0.0)` conflated them, so a renamed
/// node-agent field became "0 °C, 0 W, 0% used".
fn metric_or_null(data: &Value, key: &str) -> Value {
    match data.get(key).and_then(|v| v.as_f64()) {
        Some(n) => json!(n),
        None => Value::Null,
    }
}

/// Parse Prometheus text-format GPU metrics from nvidia-exporter.
///
/// Handles lines like:
///   nvidia_gpu_temperature_celsius{gpu="0",name="NVIDIA RTX 4090"} 45.0
///
/// Groups metrics by GPU index and returns a Vec of per-GPU JSON objects.
fn parse_prometheus_gpu_metrics(text: &str) -> Vec<Value> {
    use std::collections::HashMap;

    // Accumulate metrics per GPU index
    let mut gpus: HashMap<String, serde_json::Map<String, Value>> = HashMap::new();

    for line in text.lines() {
        let line = line.trim();
        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split into metric+labels and value: "metric_name{labels} value"
        let (metric_part, value_str) = match line.rsplit_once(' ') {
            Some((m, v)) => (m.trim(), v.trim()),
            None => continue,
        };

        let value: f64 = match value_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Parse metric name and labels
        let (metric_name, labels) = if let Some(brace_start) = metric_part.find('{') {
            let name = &metric_part[..brace_start];
            let label_str = metric_part[brace_start..]
                .trim_start_matches('{')
                .trim_end_matches('}');
            let labels = parse_prometheus_labels(label_str);
            (name, labels)
        } else {
            (metric_part, HashMap::new())
        };

        // Only process nvidia_gpu_* metrics that have a gpu label
        if !metric_name.starts_with("nvidia_gpu") {
            continue;
        }
        let gpu_index = match labels.get("gpu") {
            Some(idx) => idx.clone(),
            None => continue,
        };

        let entry = gpus.entry(gpu_index.clone()).or_insert_with(|| {
            let mut m = serde_json::Map::new();
            m.insert("index".into(), json!(gpu_index));
            if let Some(name) = labels.get("name") {
                m.insert("name".into(), json!(name));
            }
            m
        });

        // Map metric names to JSON field names
        // Frontend (observe.js) expects: temperature, memory_used, power, utilization
        let field = match metric_name {
            "nvidia_gpu_temperature_celsius" => "temperature",
            "nvidia_gpu_power_watts" => "power",
            "nvidia_gpu_memory_used_bytes" => "memory_used",
            "nvidia_gpu_memory_total_bytes" => "memory_total",
            "nvidia_gpu_utilization_pct" => "utilization",
            "nvidia_gpu_fan_speed_pct" => "fan_speed_pct",
            "nvidia_gpu_clock_mhz" => "clock_mhz",
            "nvidia_gpu_memory_clock_mhz" => "memory_clock_mhz",
            "nvidia_gpu_power_limit_watts" => "power_limit_watts",
            "nvidia_gpu_pcie_tx_bytes" => "pcie_tx_bytes",
            "nvidia_gpu_pcie_rx_bytes" => "pcie_rx_bytes",
            other => {
                // Strip nvidia_gpu_ prefix for unknown metrics
                other.strip_prefix("nvidia_gpu_").unwrap_or(other)
            }
        };

        // Convert bytes → MB for memory fields (observe.js does /1024 to get GB)
        let converted = if field == "memory_used" || field == "memory_total" {
            value / (1024.0 * 1024.0)
        } else {
            value
        };
        entry.insert(field.into(), json!(converted));

        // Also store the GPU name from labels if not set yet
        if !entry.contains_key("name") {
            if let Some(name) = labels.get("name") {
                entry.insert("name".into(), json!(name));
            }
        }
    }

    // Sort by GPU index and return
    let mut result: Vec<(String, serde_json::Map<String, Value>)> =
        gpus.into_iter().collect();
    result.sort_by(|a, b| {
        let a_idx: i64 = a.0.parse().unwrap_or(999);
        let b_idx: i64 = b.0.parse().unwrap_or(999);
        a_idx.cmp(&b_idx)
    });

    result.into_iter().map(|(_, m)| Value::Object(m)).collect()
}

/// Parse Prometheus label string like: gpu="0",name="NVIDIA RTX 4090"
fn parse_prometheus_labels(label_str: &str) -> std::collections::HashMap<String, String> {
    let mut labels = std::collections::HashMap::new();
    // State machine: handle commas inside quoted values
    let mut key = String::new();
    let mut val = String::new();
    let mut in_val = false;
    let mut in_quotes = false;

    for ch in label_str.chars() {
        match ch {
            '=' if !in_val && !in_quotes => {
                in_val = true;
            }
            '"' if in_val => {
                in_quotes = !in_quotes;
                if !in_quotes {
                    // End of quoted value
                    labels.insert(key.trim().to_string(), val.clone());
                    key.clear();
                    val.clear();
                    in_val = false;
                }
            }
            ',' if !in_quotes => {
                // If we have an unquoted value pending, store it
                if in_val && !val.is_empty() {
                    labels.insert(key.trim().to_string(), val.trim().to_string());
                    key.clear();
                    val.clear();
                    in_val = false;
                }
            }
            _ if in_val => {
                val.push(ch);
            }
            _ => {
                key.push(ch);
            }
        }
    }
    // Handle trailing unquoted value
    if in_val && !val.is_empty() {
        labels.insert(key.trim().to_string(), val.trim().to_string());
    }

    labels
}

// ── Shared helpers ──────────────────────────────────────────────────

// The agent address, the client and the credential for every controller ->
// node call live in `crate::node_link` (`NodeLink::for_node`); the
// credential decision itself is `crate::node_agent_auth`.
// The per-agent bearer decision is `crate::node_agent_auth::header_for`: no
// bearer for an agent that reports `controller_leaf_only`, the legacy bearer
// below for one that has not said.

/// The credential choice, with no environment in it so it can be tested.
///
/// The only bearer the gateway ever sends an agent is the static
/// `NOO_NODE_AGENT_TOKEN`. There is NO minted fallback: the v1 cluster token
/// (`mint_cluster_token`) is refused by every agent, and a v2 token is bound
/// to a request that does not exist yet where this is called. An agent that
/// has not reported `controller_leaf_only` and has no static token gets no
/// bearer; the gateway's leaf authenticates the handshake, and
/// `node_agent_auth::header_for` logs the decision. The fleet and controller
/// secrets are not parameters because they are not options.
pub(crate) fn node_agent_bearer(static_token: Option<&str>) -> Option<String> {
    static_token.filter(|t| !t.is_empty()).map(|t| format!("Bearer {t}"))
}

#[cfg(test)]
mod node_agent_auth_tests {
    use super::*;

    #[test]
    fn the_static_token_is_the_only_bearer() {
        assert_eq!(node_agent_bearer(Some("abc")), Some("Bearer abc".into()));
    }

    #[test]
    fn no_v1_token_is_ever_minted_for_an_agent() {
        // Without a static token there is no bearer at all: not a v1
        // `<actor>:<ts>:<hmac>`, not anything signed with a shared secret.
        assert_eq!(node_agent_bearer(None), None);
        assert_eq!(node_agent_bearer(Some("")), None);
        // ...and the function cannot even be handed a secret to sign with.
        let src = include_str!("cluster.rs");
        let body = src.split("pub(crate) fn node_agent_bearer(").nth(1).unwrap().split("\n}\n").next().unwrap();
        assert!(!body.contains(&["mint_cluster", "_token"].concat()), "the fallback is back: {body}");
    }
}

/// INTERNAL ONLY. Never send the result to an agent or the gateway: v1 cluster
/// tokens are refused everywhere (`cluster_token_v1_refused`). It exists for
/// the v2-admission path's internal re-mint (`auth.rs`), the browser door's
/// own-key bearer (`routes/ui.rs`) and tests. A controller->agent credential
/// is `node_agent_auth::header_for`, which never calls this
/// (`node_agent_auth::tests::no_agent_credential_path_mints_a_v1_token`).
///
/// Mint a cluster-HMAC time-bearer token: `<actor>:<ts>:<hmac64>` with the
/// FULL 64-hex HMAC-SHA256 signature over `"actor:ts"`.
///
/// Width contract (2026-08 seam fix): the Go node-agent verifier
/// (internal/auth/middleware.go) only accepts the full 64-hex signature, so
/// every node-agent-bound token must be full-width. The gateway's own
/// verifier (auth.rs verify_cluster_token) accepts 32 or 64, so gateway →
/// gateway loopback keeps working too. Do NOT truncate to 32 here — that
/// was the bug that made HMAC fallback auth to node-agents never succeed.
pub(crate) fn mint_cluster_token(actor: &str, secret: &str, ts: u64) -> Option<String> {
    let message = format!("{actor}:{ts}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(message.as_bytes());
    let hmac_hex = hex::encode(mac.finalize().into_bytes());
    Some(format!("{actor}:{ts}:{hmac_hex}"))
}

// `cluster_hmac_auth_header` (a controller-secret HMAC for gateway
// self-calls) is gone: its last callers were the heartbeat,
// operator_alert (both in-process since #655) and the caller-less
// `mcp-local` dispatch, which was unreachable once the loopback MCP listener
// was removed. A gateway that needs its own handler calls it in process.
// `mcp_local::tests::no_gateway_code_signs_a_self_call_with_the_controller_secret`
// keeps it gone.

// ── Node-agent proxy handlers ──────────────────────────────────────

/// Restart a node's agent by proxying to its `/restart` endpoint.
///
/// POST /api/cluster/nodes/{node_id}/restart-agent
async fn restart_node_agent(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> AppResult {
    restart_agent_via_rail(&state, &node_id)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(json!({
        "status": "ok",
        "message": format!("Restart triggered on {node_id}"),
    })))
}

/// Ask a node's agent to restart ITSELF, over the agent HTTP rail.
///
/// This is the ONLY remote restart the mesh has. It needs the agent to be
/// answering — which is the case the autonomy `node_dispatch_health`
/// evaluator uses it for (an agent that heartbeats but whose JetStream
/// consumer is unbound). A node whose agent is DOWN cannot be reached this
/// way, and there is no second lane: the controller→node SSH lane was
/// removed 2026-09-11. That case raises an operator alert instead
/// (`autonomy_evaluators::node_agent_revive_instructions`).
pub(crate) async fn restart_agent_via_rail(
    state: &AppState,
    node_id: &str,
) -> Result<(), String> {
    let link = crate::node_link::NodeLink::for_node(state, node_id)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!(node_id = %node_id, url = %link.base(), "restarting node agent");

    let req = link.request(reqwest::Method::POST, "/restart");

    match req.send().await {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(format!("Node agent returned {status}: {body}"))
        }
        Err(e) => {
            tracing::error!(node_id = %node_id, error = %e, "restart agent failed");
            Err(format!("Failed to contact node agent: {e}"))
        }
    }
}

/// GET /api/cluster/nodes/{node_id}/control-probe
///
/// One `health` round trip over the bus, for `noo cluster verify`'s "control
/// over bus" row. Never falls back to HTTPS: the point is to learn whether
/// the BUS works. A node that does not advertise `nats_rpc` answers
/// `checked: false` (the row reads NOT CHECKED, never ok).
async fn control_probe(
    State(state): State<Arc<AppState>>,
    caller: Option<axum::Extension<crate::auth::ClusterNode>>,
    _op: crate::authz::OperatorOrInternal,
    Path(node_id): Path<String>,
) -> AppResult {
    if caller.is_some() {
        return Err(AppError::Forbidden("a node may not probe the controller's control paths".into()));
    }
    let link = crate::node_link::NodeLink::for_node(&state, &node_id).await?;
    Ok(Json(link.probe_bus().await))
}

/// Proxy an artifact pull to a node's `/pull` endpoint.
///
/// POST /api/cluster/nodes/{node_id}/pull
///
/// The body travels verbatim (`{kind, image, image_id?, remove_container?}`);
/// the agent fetches the digest-verified tar from the model-cache data plane
/// and `docker load`s it. SYNCHRONOUS on purpose — the caller is an operator
/// command that wants the real outcome, and a multi-GB tar over the LAN takes
/// minutes, so this request (alone) overrides the shared client's timeout.
async fn pull_node_artifact(
    State(state): State<Arc<AppState>>,
    caller: Option<axum::Extension<crate::auth::ClusterNode>>,
    Path(node_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    // Same per-node authz as desired_config_get (landed
    // with step 9): a NODE-token caller may trigger a pull on itself and
    // nowhere else — with the fleet-wide cluster secret, one
    // compromised node must not be able to command image loads across the
    // fleet. Operator callers (JWT — no ClusterNode extension) are
    // unaffected: this route exists FOR `noo cluster sync-images`.
    if let Some(axum::Extension(crate::auth::ClusterNode(caller_node, _))) = caller {
        if caller_node != node_id {
            tracing::warn!(caller = %caller_node, requested = %node_id, "pull_cross_node_denied");
            return Err(AppError::Forbidden(format!(
                "node {caller_node} may not trigger artifact pulls on {node_id}"
            )));
        }
    }
    let link = crate::node_link::NodeLink::for_node(&state, &node_id).await?;
    tracing::info!(node_id = %node_id, url = %link.base(), body = %body, "proxying artifact pull");

    let req = link
        .request(reqwest::Method::POST, "/pull")
        .timeout(std::time::Duration::from_secs(2700))
        .json(&body);

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let parsed: Value =
                serde_json::from_str(&text).unwrap_or_else(|_| json!({"detail": text}));
            if status.is_success() {
                Ok(Json(parsed))
            } else {
                Err(AppError::Upstream(format!(
                    "Node agent /pull returned {}: {}",
                    status.as_u16(),
                    parsed["detail"].as_str().unwrap_or(&text)
                )))
            }
        }
        Err(e) => {
            tracing::error!(node_id = %node_id, error = %e, "artifact pull proxy failed");
            Err(AppError::Upstream(format!("Failed to contact node agent: {e}")))
        }
    }
}

#[derive(Deserialize)]
struct CleanRequest {
    #[serde(default)]
    remove_folder: bool,
    /// Also remove the stack's images (`noo cluster clean --deep`).
    #[serde(default)]
    deep: bool,
}

/// Clean a node by proxying to its `/clean` endpoint.
///
/// POST /api/cluster/nodes/{node_id}/clean
///
/// Body `{"deep": bool, "remove_folder": bool}`, both forwarded to the agent.
///
/// CLEANS, and nothing else. It used to also delete the node's
/// `cluster_nodes` row and purge its `mesh_nodes` entry — a decommission
/// nobody asked for: `noo cluster clean` documents "remove this stack's
/// containers", the node kept running, and it dropped out of the cluster
/// until its next heartbeat re-registered it. It also dropped `deep`, so
/// `--deep` never removed an image. Taking a node out is its own verb:
/// `noo cluster teardown-node` (dismantle, verify silence, forget) or
/// `noo cluster forget` (a dead node's row, KV entry and enrollments).
async fn clean_node(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    body: Option<Json<CleanRequest>>,
) -> AppResult {
    let link = crate::node_link::NodeLink::for_node(&state, &node_id).await?;
    let (remove_folder, deep) = body.map(|b| (b.remove_folder, b.deep)).unwrap_or((false, false));

    tracing::info!(node_id = %node_id, url = %link.base(), remove_folder, deep, "cleaning node");

    let req = link
        .request(reqwest::Method::POST, "/clean")
        .json(&json!({"remove_folder": remove_folder, "deep": deep}));

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let mut result = resp.json::<Value>().await.unwrap_or(json!({}));
            result["status"] = json!("ok");
            tracing::info!(node_id = %node_id, "node cleaned");
            Ok(Json(result))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(AppError::Upstream(format!("Node agent returned {status}: {body}")))
        }
        Err(e) => {
            tracing::error!(node_id = %node_id, error = %e, "clean node failed");
            Err(AppError::Upstream(format!("Failed to contact node agent: {e}")))
        }
    }
}

/// Operator hold on a node's GPU: an owned lease. The node's GPU backends
/// are drained (nothing new routed or admitted; what runs finishes) and then
/// paused, and stay paused (no automatic resume) until a release that quotes
/// the lease. For handing the GPU to work outside noomesh that will not
/// start while the GPU is occupied (noomesh-internal i163 parts C and D).
///
/// POST /api/cluster/nodes/{node_id}/gpu/hold — body `{reason?, operation_id?,
/// owner?, workload?, mode?: drain|immediate, timeout_secs?, force?}`. Operator only;
/// audited (`node_gpu_hold`, with the lease and whether it was a force).
///
/// - `operation_id` names the caller's operation; the answer's
///   `gpu_contention.lease` carries it with the node's `generation`, which
///   the release must quote. **A body with no `operation_id` is a legacy
///   hold** (an older CLI): mode immediate and a force, audited `legacy`.
/// - `mode` defaults to `drain`: the node's lanes leave routing at once,
///   the agent closes admission on its GPU backends and waits up to
///   `timeout_secs` (default 120, max 900) for them to go idle before it
///   stops them. A drain that times out aborts the hold (409
///   `drain_timeout`, status `needs_attention`, the counts still in flight):
///   nothing is stopped, nothing is cut. `immediate` is the old behaviour
///   (stop after a 30 s grace, requests in flight included): for emergencies.
/// - `force: true` takes over a hold owned by another operation (409
///   `held_by_other` with the current lease otherwise). A takeover is the
///   hand-over primitive: the backends stay paused throughout, the pool never
///   gets the GPU in between. `workload` (`<addon>/<workload>`) names what
///   the GPU went to; the reservation layer keys on it and `operation_id`.
/// - One hold or release runs on a node at a time (409 `transition_in_progress`).
async fn gpu_hold(
    State(state): State<Arc<AppState>>,
    operator: crate::authz::Operator,
    Path(node_id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult {
    let actor = operator.sub().to_string();
    let b = body.map(|Json(b)| b).unwrap_or_else(|| json!({}));
    let text = |k: &str, max: usize| -> String {
        b.get(k).and_then(Value::as_str).unwrap_or("").trim().chars().take(max).collect()
    };
    let reason = text("reason", 200);
    let operation_id = text("operation_id", 64);
    let workload = text("workload", 120);
    let legacy = operation_id.is_empty();
    let mut owner = text("owner", 200);
    if owner.is_empty() {
        owner = actor.clone();
    }
    let mode = match text("mode", 16).as_str() {
        "" if legacy => "immediate".to_string(),
        "" => "drain".to_string(),
        m @ ("drain" | "immediate") => m.to_string(),
        other => return Err(AppError::BadRequest(format!("mode must be drain or immediate, not {other:?}"))),
    };
    let timeout_secs = b
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .unwrap_or(GPU_DRAIN_TIMEOUT_DEFAULT_SECS)
        .clamp(1, GPU_DRAIN_TIMEOUT_MAX_SECS);
    let force = legacy || b.get("force").and_then(Value::as_bool).unwrap_or(false);
    let payload = json!({
        "reason": reason, "operation_id": operation_id, "owner": owner, "workload": workload, "mode": mode,
        "timeout_secs": timeout_secs, "force": force, "legacy": legacy,
    });
    let wait = std::time::Duration::from_secs(if mode == "drain" { timeout_secs + 60 } else { 90 });
    gpu_hold_op(&state, actor, &node_id, "hold", payload, wait).await
}

/// End an operator GPU hold: the node returns to the automatic shared-GPU
/// policy and resumes its GPU backends once the GPU has stayed free (or at
/// once with `resume: "now"`).
///
/// POST /api/cluster/nodes/{node_id}/gpu/release — body `{operation_id?,
/// generation?, force?, resume?: "now"}`. Operator only; audited. The ids
/// must match the lease (compare-and-set; 409 `held_by_other` with the
/// current lease otherwise). `force: true` ends any hold. **A body with no
/// `operation_id` is a legacy release** (an older CLI): a force, audited so.
async fn gpu_release(
    State(state): State<Arc<AppState>>,
    operator: crate::authz::Operator,
    Path(node_id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult {
    let actor = operator.sub().to_string();
    let b = body.map(|Json(b)| b).unwrap_or_else(|| json!({}));
    let operation_id: String = b.get("operation_id").and_then(Value::as_str).unwrap_or("").trim().chars().take(64).collect();
    let legacy = operation_id.is_empty();
    let generation = b.get("generation").and_then(Value::as_u64).unwrap_or(0);
    let force = legacy || b.get("force").and_then(Value::as_bool).unwrap_or(false);
    let resume_now = b.get("resume").and_then(Value::as_str).is_some_and(|r| r.eq_ignore_ascii_case("now"));
    let payload = json!({
        "operation_id": operation_id, "generation": generation, "force": force, "legacy": legacy,
        "resume": if resume_now { "now" } else { "" },
    });
    gpu_hold_op(&state, actor, &node_id, "release", payload, std::time::Duration::from_secs(90)).await
}

/// A drain hold waits this long for the GPU backends to go idle unless the
/// request says otherwise; the cap keeps a typo from parking a node.
pub(crate) const GPU_DRAIN_TIMEOUT_DEFAULT_SECS: u64 = 120;
pub(crate) const GPU_DRAIN_TIMEOUT_MAX_SECS: u64 = 900;

/// The per-node transition lock: one hold or release in flight per node at
/// a time, across every caller of this gateway (the agent refuses a second
/// one too; this answers it before a node round-trip).
static GPU_TRANSITIONS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();

/// Holds the node's transition slot for as long as it lives.
pub(crate) struct GpuTransition(String);

impl GpuTransition {
    pub(crate) fn take(node_id: &str) -> Result<Self, AppError> {
        let set = GPU_TRANSITIONS.get_or_init(Default::default);
        let mut g = set.lock().unwrap_or_else(|e| e.into_inner());
        if !g.insert(node_id.to_string()) {
            return Err(AppError::Conflict(format!("a GPU hold or release on {node_id} is already in progress")));
        }
        Ok(Self(node_id.to_string()))
    }
}

impl Drop for GpuTransition {
    fn drop(&mut self) {
        if let Some(set) = GPU_TRANSITIONS.get() {
            set.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0);
        }
    }
}

/// The node's KV record (`mesh_nodes`), as the heartbeat last wrote it.
pub(crate) async fn node_record(state: &AppState, node_id: &str) -> Option<Value> {
    let kv = state.js.get_key_value("mesh_nodes").await.ok()?;
    let entry = kv.get(node_id).await.ok()??;
    serde_json::from_slice::<Value>(&entry).ok()
}

/// The lanes a hold will pause, as the node last reported them
/// (`gpu_contention.gpu_backends`, agents from 0.6.10); empty when unknown.
pub(crate) async fn reported_gpu_lanes(state: &AppState, node_id: &str) -> Vec<String> {
    node_record(state, node_id)
        .await
        .as_ref()
        .and_then(|r| r.pointer("/gpu_contention/gpu_backends"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// The node record with the agent's `gpu_contention` in place of the one the
/// last heartbeat carried. Pure, so the merge is tested without a KV.
pub(crate) fn with_contention(mut record: Value, gc: Value) -> Value {
    if let Some(obj) = record.as_object_mut() {
        obj.insert("gpu_contention".to_string(), gc);
    }
    record
}

/// Write the agent-returned `gpu_contention` into the node's `mesh_nodes`
/// record by compare-and-swap on the revision (a heartbeat write racing this
/// one wins; it carries the same value). Best effort: any failure is logged
/// and swallowed, the user's hold/release already succeeded on the node.
async fn write_back_contention(state: &AppState, node_id: &str, gc: Value) {
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else { return };
    for _ in 0..3 {
        let Ok(Some(entry)) = kv.entry(node_id).await else { return };
        let Ok(record) = serde_json::from_slice::<Value>(&entry.value) else { return };
        let Ok(bytes) = serde_json::to_vec(&with_contention(record, gc.clone())) else { return };
        match kv.update(node_id, bytes.into(), entry.revision).await {
            Ok(_) => return,
            Err(e) => tracing::debug!(node_id = %node_id, error = %e, "gpu_contention write-back lost a revision race; retrying"),
        }
    }
    tracing::warn!(node_id = %node_id, "gpu_contention write-back gave up; the next heartbeat carries it");
}

pub(crate) async fn gpu_hold_op(
    state: &AppState,
    actor: String,
    node_id: &str,
    op: &str,
    payload: Value,
    wait: std::time::Duration,
) -> AppResult {
    let _slot = GpuTransition::take(node_id)?;
    let draining = op == "hold" && payload["mode"] == "drain";
    // Which lanes leave routing while the hold drains: the GPU lanes the
    // node reported, so its CPU lanes keep serving; a node that reports
    // none (an older agent) loses every lane for the drain.
    let mut drain_lanes: Vec<String> = Vec::new();
    if draining {
        drain_lanes = reported_gpu_lanes(state, node_id).await;
        // Nothing new is routed to those lanes from this moment: before the
        // agent closes admission, before anything stops.
        if drain_lanes.is_empty() {
            crate::coordinator::classes::set_node_draining(node_id, true);
        } else {
            crate::coordinator::classes::set_lanes_paused(node_id, &drain_lanes);
        }
    }
    let link = crate::node_link::NodeLink::for_node(state, node_id).await?;
    let req = link.request(reqwest::Method::POST, &format!("/gpu/{op}")).json(&payload).timeout(wait);
    let outcome = req.send().await;
    let (ok, result) = match outcome {
        Ok(resp) if resp.status().is_success() => (true, Ok(resp.json::<Value>().await.unwrap_or(json!({})))),
        Ok(resp) if resp.status() == reqwest::StatusCode::CONFLICT => {
            // The agent's refusal is the answer: a lease someone else holds,
            // a drain that did not finish, a transition in progress.
            let body = resp.json::<Value>().await.unwrap_or(json!({}));
            let code = body.get("error").and_then(Value::as_str).unwrap_or("refused").to_string();
            let detail = body.get("detail").and_then(Value::as_str).unwrap_or("").to_string();
            (false, Err(AppError::Conflict(format!("{code}: {detail}"))))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            (false, Err(AppError::Upstream(format!("Node agent returned {status}: {body}"))))
        }
        Err(e) => (false, Err(AppError::Upstream(format!("Failed to contact node agent: {e}")))),
    };
    match (op, ok) {
        ("hold", true) => {
            // The hold is on: the agent reports the paused lanes; keep the
            // node out of routing until the heartbeat carries them.
            let paused: Vec<String> = result
                .as_ref()
                .ok()
                .and_then(|v| v.pointer("/gpu_contention/paused_backends"))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            crate::coordinator::classes::set_node_draining(node_id, false);
            crate::coordinator::classes::set_lanes_paused(node_id, &paused);
        }
        ("hold", false) if draining => {
            crate::coordinator::classes::set_node_draining(node_id, false);
            if !drain_lanes.is_empty() {
                crate::coordinator::classes::set_lanes_paused(node_id, &[]);
            }
        }
        ("release", true) => crate::coordinator::classes::set_lanes_paused(node_id, &[]),
        _ => {}
    }
    // Read-after-write: the lease the agent just returned goes into the
    // node's KV record now, so reservation list/status/release see it
    // before the next heartbeat (up to 30 s later) carries the same value.
    if ok {
        if let Some(gc) = result.as_ref().ok().and_then(|v| v.get("gpu_contention")).cloned() {
            write_back_contention(state, node_id, gc).await;
        }
    }
    tracing::info!(node_id = %node_id, op, ok, actor = %actor, force = payload["force"].as_bool().unwrap_or(false),
        legacy = payload["legacy"].as_bool().unwrap_or(false), operation_id = %payload["operation_id"].as_str().unwrap_or(""), "node_gpu_hold");
    let lease = result.as_ref().ok().and_then(|v| v.pointer("/gpu_contention/lease").cloned()).unwrap_or(Value::Null);
    crate::audit::record(
        &state.db,
        AuditEvent::new(
            if op == "hold" { AuditKind::NodeGpuHold } else { AuditKind::NodeGpuRelease },
            &actor,
            &format!("node:{node_id}"),
        )
        .outcome(if ok { crate::audit::Outcome::Ok } else { crate::audit::Outcome::Error })
        .details(json!({"node": node_id, "op": op, "request": payload, "lease": lease,
               "force": payload["force"], "legacy": payload["legacy"]})),
    ).await;
    let mut out = result?;
    out["node"] = json!(node_id);
    Ok(Json(out))
}

/// How long the gateway waits on a node's bench: a cold load of a large
/// model on a CPU worker plus a 30k-token prefill can take many minutes.
const NODE_BENCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

/// Measure a node's chat model: the gateway asks the node agent's
/// `POST /bench`, which loads the model, times a reference prefill and
/// decode, keeps the result and reports it as `model_bench` on every
/// heartbeat after. The answer is that `model_bench` object (`{model,
/// backend, load_secs, prefill_tps, decode_tps, prompt_tokens, at}`); the
/// node's resolved harness profile (`desired-config`) derives its
/// `first_byte_secs` from it. Operator only; audited. Up to 900 s.
///
/// POST /api/cluster/nodes/{node_id}/bench
async fn node_bench(
    State(state): State<Arc<AppState>>,
    operator: crate::authz::Operator,
    Path(node_id): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let actor = operator.sub().to_string();
    let link = match crate::node_link::NodeLink::for_node(&state, &node_id).await {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };
    let started = std::time::Instant::now();
    let outcome = link
        .request(reqwest::Method::POST, "/bench")
        .timeout(NODE_BENCH_TIMEOUT)
        .send()
        .await;
    let (ok, response, detail) = match outcome {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(body) => {
                let detail = body.clone();
                (true, Json(body).into_response(), detail)
            }
            Err(e) => {
                let body = json!({"error": format!("node agent {node_id} answered /bench with a body that is not JSON: {e}")});
                (false, (axum::http::StatusCode::BAD_GATEWAY, Json(body.clone())).into_response(), body)
            }
        },
        Ok(resp) => {
            // The agent's own refusal (no chat model to bench, a bench
            // already running, an older agent with no /bench), passed
            // through with its status so the CLI can say which.
            let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            let text = resp.text().await.unwrap_or_default();
            let body = serde_json::from_str::<Value>(&text)
                .ok()
                .filter(|v| v.is_object())
                .unwrap_or_else(|| json!({"error": format!("node agent {node_id} returned {}: {}", status.as_u16(), text.trim())}));
            (false, (status, Json(body.clone())).into_response(), body)
        }
        Err(e) => {
            let body = json!({"error": format!("could not reach the node agent on {node_id} for /bench: {e}")});
            (false, (axum::http::StatusCode::BAD_GATEWAY, Json(body.clone())).into_response(), body)
        }
    };
    // Put the bench on the node record now, so the very next desired-config
    // (the CLI's re-resolved profile, the agent's next poll) reads it; the
    // agent reports it on every heartbeat after, which keeps it there.
    if ok && crate::harness_profile::ModelBench::from_record(&json!({"model_bench": detail.clone()})).is_some() {
        if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
            if let Ok(Some(entry)) = kv.get(&node_id).await {
                if let Ok(mut record) = serde_json::from_slice::<Value>(&entry) {
                    record["model_bench"] = detail.clone();
                    let _ = kv.put(&node_id, serde_json::to_vec(&record).unwrap_or_default().into()).await;
                }
            }
        }
    }
    let secs = started.elapsed().as_secs_f64();
    tracing::info!(node_id = %node_id, ok, actor = %actor, secs, "node_bench");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::NodeBench, &actor, &format!("node:{node_id}"))
            .outcome(if ok { crate::audit::Outcome::Ok } else { crate::audit::Outcome::Error })
            .details(json!({"node": node_id, "secs": secs, "result": detail})),
    ).await;
    response
}

/// GET /api/cluster/proposals/{id}
///
/// Single-proposal status + execution log, so a caller can poll an
/// executor action to completion and surface the
/// failure note inline. The list endpoint only returns pending proposals,
/// so terminal outcomes (executed/failed) are otherwise invisible.
async fn proposal_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult {
    let row: Option<(String, String, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT status, host, role, execution_log, executed_at \
             FROM noo_cluster_proposals WHERE id = $1::uuid"
        )
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    match row {
        Some((status, host, role, log, executed_at)) => Ok(Json(json!({
            "id": id,
            "status": status,
            "host": host,
            "role": role,
            "execution_log": log,
            "executed_at": executed_at.map(|t| t.to_rfc3339()),
        }))),
        None => Err(AppError::NotFound(format!("Proposal '{id}' not found"))),
    }
}

/// POST /api/cluster/proposals
///
/// List proposals, optionally filtered by status. Body: `{status?, limit?}`.
/// POST (not GET) so the filter travels as JSON like the rest of the
/// dashboard's list endpoints.
async fn proposals_list(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppResult {
    let status = body.get("status").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let limit = body.get("limit").and_then(|v| v.as_i64()).unwrap_or(50).clamp(1, 200);

    let rows: Vec<(String, String, String, Option<String>, String, String,
                   chrono::DateTime<chrono::Utc>, String,
                   Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT id::text, host, user_name, role, reason, proposed_by, \
                    proposed_at, status, executed_at, execution_log, decided_by \
             FROM noo_cluster_proposals \
             WHERE ($1::text IS NULL OR status = $1) \
             ORDER BY proposed_at DESC \
             LIMIT $2"
        )
        .bind(status)
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let proposals: Vec<Value> = rows.into_iter().map(
        |(id, host, user_name, role, reason, proposed_by, proposed_at, status, executed_at, execution_log, decided_by)| {
            json!({
                "id": id,
                "host": host,
                "user_name": user_name,
                "user": user_name,
                "role": role,
                "reason": reason,
                "proposed_by": proposed_by,
                "created_at": proposed_at.to_rfc3339(),
                "status": status,
                "executed_at": executed_at.map(|t| t.to_rfc3339()),
                "execution_log": execution_log,
                "decided_by": decided_by,
            })
        }).collect();

    Ok(Json(json!({ "proposals": proposals })))
}

/// POST /api/cluster/proposals/decide
///
/// Body: `{id, decision: "approve"|"reject"}`. Only pending proposals can be
/// decided; approved rows are picked up by the cluster executor
/// (`status='approved' AND executed_at IS NULL`).
async fn proposals_decide(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> AppResult {
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let decision = body.get("decision").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() {
        return Err(AppError::BadRequest("'id' is required".into()));
    }
    let new_status = match decision {
        "approve" => "approved",
        "reject" => "rejected",
        _ => return Err(AppError::BadRequest("'decision' must be 'approve' or 'reject'".into())),
    };

    let updated: Option<(String,)> = sqlx::query_as(
        "UPDATE noo_cluster_proposals \
         SET status = $2, decided_at = NOW(), decided_by = 'dashboard', decided_via = 'ui' \
         WHERE id = $1::uuid AND status = 'pending' \
         RETURNING id::text"
    )
    .bind(id)
    .bind(new_status)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match updated {
        Some((_,)) => {
            // An approved enrolment proposal used to sit in the queue for
            // the cluster-executor sidecar, which resolved it to
            // bootstrap-token INSTRUCTIONS (it had not push-enrolled
            // anything since). The sidecar is gone, so the gateway
            // does that one useful step itself, now, rather than leaving a
            // row in 'approved' that nothing will ever pick up.
            let final_status = if new_status == "approved" {
                resolve_enrolment_proposal(&state, id).await
            } else {
                new_status.to_string()
            };
            Ok(Json(json!({ "id": id, "status": final_status })))
        }
        None => Err(AppError::NotFound(format!(
            "Proposal '{id}' not found or not pending"
        ))),
    }
}

/// The bootstrap-token enrolment procedure for `host`, as an operator runs
/// it. Enrolment is a pull-rail one-liner executed ON the node — there is
/// no unattended push and (since 2026-09-11) no SSH lane that could fake
/// one.
pub(crate) fn bootstrap_instructions(host: &str) -> String {
    format!(
        "Automated push enrollment does not exist (pull architecture) \
         and the controller\u{2192}node SSH lane was removed 2026-09-11. \
         Enrol {host} with the token rail \u{2014} on the controller:\n\n  \
         noo cluster bootstrap-token create --node {host}\n\n\
         then run the printed one-liner ON {host}. It enrols against the \
         cluster CA (fingerprint-pinned) and provisions via the encrypted \
         pull bundle."
    )
}

/// Move an approved enrolment proposal straight to its real terminal
/// state: `needs_bootstrap`, with the procedure in `execution_log`.
///
/// Returns the status actually written, so the caller reports what is
/// true rather than what it hoped for. A DB failure leaves the row
/// 'approved' and says 'approved'.
pub(crate) async fn resolve_enrolment_proposal(state: &AppState, id: &str) -> String {
    let host: Option<(String,)> = sqlx::query_as(
        "SELECT host FROM noo_cluster_proposals WHERE id = $1::uuid"
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some((host,)) = host else { return "approved".to_string() };

    let log = bootstrap_instructions(&host);
    let res = sqlx::query(
        "UPDATE noo_cluster_proposals \
         SET status = 'needs_bootstrap', executed_at = NOW(), execution_log = $2 \
         WHERE id = $1::uuid"
    )
    .bind(id)
    .bind(&log)
    .execute(&state.db)
    .await;

    match res {
        Ok(_) => "needs_bootstrap".to_string(),
        Err(e) => {
            tracing::warn!(proposal = %id, error = %e, "proposal_resolve_failed");
            "approved".to_string()
        }
    }
}

// REMOVED 2026-09-11 — POST /api/cluster/proposals/{id}/retry.
// It re-queued a needs_bootstrap/failed row to status='approved' for the
// cluster-executor to pick up. Nothing polls that status any more, so the
// button could only ever move a row sideways and report success. An
// enrolment that needs re-doing is `noo cluster bootstrap-token create`
// again; a node that needs reviving is a command run ON the node.

// ── Cluster provision (native Rust, background process) ────────────

// Retired (#116): POST /api/cluster/nodes/provision spawned
// `python3 -m noomesh.cluster.provisioner` — a module with no __main__,
// in an image with no noomesh at all (Dockerfile.gateway-rust ships no
// src). Every invocation failed. Native `noo cluster provision` + the
// pull rail are the living path.
// ── Native handlers (ollama/models) ─────────────────────────────────
//
// POST /api/cluster/companion-token/{node_id} was removed 2026-09-27: it
// had no caller, and it minted a fleet-secret HMAC cluster token for any
// subject the requester named. A companion app authenticates through the
// identity plane instead.

type HmacSha256 = Hmac<Sha256>;

/// List models available in the local Ollama instance.
///
/// GET /api/ollama/models
///
/// Proxies to Ollama's /api/tags endpoint. Returns the raw JSON from Ollama
/// or an error object if the request fails.
async fn ollama_models() -> AppJson {
    // The stunnel-fronted ollama door on the compose network (the same
    // default the gateway service carries in docker-compose.cluster.yml).
    // `http://localhost:11434` was the old default — dead inside the
    // container, and plain.
    let base_url = crate::config::env_or_yaml(
        "OLLAMA_URL",
        |c| c.services.ollama_url.clone(),
        "https://stunnel-ollama:11434",
    );
    let url = format!("{}/api/tags", base_url.trim_end_matches('/'));

    let client = crate::tls::cluster_client();

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Value>().await {
                Ok(body) => Json(body),
                Err(e) => Json(json!({
                    "error": format!("Failed to parse Ollama response: {e}"),
                    "models": [],
                })),
            }
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Json(json!({
                "error": format!("Ollama returned {status}: {body}"),
                "models": [],
            }))
        }
        Err(e) => {
            tracing::warn!(error = %e, url = %url, "Ollama unreachable");
            Json(json!({
                "error": format!("Ollama unreachable at {url}: {e}"),
                "models": [],
            }))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Native backend start/stop — avoids Python worker pool bottleneck
// ═══════════════════════════════════════════════════════════════

/// Backend health endpoint paths and ports.
fn backend_health(bt: &str) -> Option<(u16, &'static str)> {
    match bt {
        "vllm" => Some((8000, "/health")),
        "ollama" => Some((11434, "/api/tags")),
        "llamacpp" => Some((8085, "/v1/models")),
        _ => None,
    }
}

/// In-memory cooldown tracker for backend start failures.
/// Uses a static Mutex to persist across requests.
mod cooldowns {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    static COOLDOWNS: Mutex<Option<HashMap<String, (Instant, u32)>>> = Mutex::new(None);

    const BASE_COOLDOWN_SECS: u64 = 300;  // 5 min
    const MAX_COOLDOWN_SECS: u64 = 3600;  // 1 hour

    fn map() -> std::sync::MutexGuard<'static, Option<HashMap<String, (Instant, u32)>>> {
        COOLDOWNS.lock().unwrap()
    }

    pub fn is_cooled_down(key: &str) -> bool {
        let guard = map();
        let map = match guard.as_ref() {
            Some(m) => m,
            None => return true,
        };
        match map.get(key) {
            None => true,
            Some((last_fail, failures)) => {
                let cooldown = std::cmp::min(
                    BASE_COOLDOWN_SECS * 2u64.pow(failures.saturating_sub(1)),
                    MAX_COOLDOWN_SECS,
                );
                last_fail.elapsed().as_secs() >= cooldown
            }
        }
    }

    pub fn record_failure(key: &str) {
        let mut guard = map();
        let map = guard.get_or_insert_with(HashMap::new);
        let entry = map.entry(key.to_string()).or_insert((Instant::now(), 0));
        entry.0 = Instant::now();
        entry.1 += 1;
    }

    pub fn record_success(key: &str) {
        let mut guard = map();
        if let Some(map) = guard.as_mut() {
            map.remove(key);
        }
    }

    pub fn clear_all() -> usize {
        let mut guard = map();
        match guard.as_mut() {
            Some(map) => { let n = map.len(); map.clear(); n }
            None => 0,
        }
    }
}

#[derive(Deserialize)]
struct BackendStartBody {
    backend: Option<String>,
    backend_type: Option<String>,
    #[serde(rename = "type")]
    type_field: Option<String>,
    node_id: Option<String>,
    model: Option<String>,
}

/// True when `backend` on `node_id` is NOT inside a start-failure cooldown.
///
/// Exposed for the autonomy engine: `backend_availability` must consult the
/// same map the HTTP route does, or a flapping node would be hammered every
/// 60s by the loop while the operator's own direct /backends/start call is politely
/// refused.
pub(crate) fn backend_start_cooled_down(node_id: &str, backend: &str) -> bool {
    cooldowns::is_cooled_down(&format!("{node_id}:{backend}"))
}

/// The image ref the controller tells a node to run for `backend`, or None
/// (the node then uses its own versioned default, which a registry node
/// refuses and a rail node takes only from the controller's staged tar).
///
/// Order: an operator override in this process's own environment
/// (`VLLM_IMAGE` ...), else the compose-rendered `NOO_BACKEND_IMAGE_<X>`,
/// which carries the digest-pinned ref from the signed stack lock
/// (`tag@sha256:...`, docker-compose.cluster.yml). Blank values are absent.
///
/// A FLOATING ref (`:latest`, or no tag, and no digest) is never sent, from
/// either variable: it can change under the node with no check, and a
/// 0.6.7+ agent refuses it anyway. Compose renders `VLLM_IMAGE` into the
/// locked variable too, so an operator's `VLLM_IMAGE=vllm/vllm-openai:latest`
/// used to replace the lock's digest-pinned ref outright (awolf ran
/// `:latest` from a 0.6.6 agent, 2026-10-20). It is skipped, logged, and the
/// next candidate (or the node's own versioned default) is used.
pub(crate) fn backend_image_ref(backend: &str, get: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let (operator, locked) = match backend {
        "vllm" => ("VLLM_IMAGE", "NOO_BACKEND_IMAGE_VLLM"),
        "vllm-secondary" => ("VLLM2_IMAGE", "NOO_BACKEND_IMAGE_VLLM_SECONDARY"),
        "ollama" => ("OLLAMA_IMAGE", "NOO_BACKEND_IMAGE_OLLAMA"),
        // First-party / per-architecture images: the node derives its own
        // release ref (prefix:tag, rail-staged); only an operator override
        // is forwarded.
        "llamacpp" => ("LLAMACPP_IMAGE", ""),
        "embedding" => ("TEI_IMAGE", ""),
        _ => return None,
    };
    [operator, locked]
        .iter()
        .filter(|k| !k.is_empty())
        .filter_map(|k| get(k).map(|v| (*k, v.trim().to_string())))
        .filter(|(_, v)| !v.is_empty())
        .find(|(k, v)| {
            if is_floating_image_ref(v) {
                if crate::legacy_lanes::log_due(&format!("floating_backend_image|{k}"), std::time::Duration::from_secs(3600)) {
                    tracing::warn!(
                        var = %k, image = %v, backend,
                        "backend image: refusing to send a floating ref (no digest, tag latest or none) — set it to \
                         `repo:version@sha256:…`, or unset it to use the signed stack lock's pinned ref"
                    );
                }
                return false;
            }
            true
        })
        .map(|(_, v)| v)
}

/// The image a desired-config placement carries: the placement's own image
/// when it names one, else [`backend_image_ref`] (the signed stack lock's
/// digest-pinned ref, or an operator override that is not floating).
///
/// Until 0.6.9 desired-config sent the placement's column alone, which is
/// null unless an operator set one, so the reconciler — how a node normally
/// starts a backend — never received the lock's digest (only the manual
/// `/start` route did). A node then fell back to its own versioned default
/// with no digest, and a 0.6.8 agent refuses that: aserve and robopi could
/// not recreate `noo-ollama` after its floating container was removed
/// (`refusing image "ollama/ollama:0.40.5": it has no @sha256 digest`).
pub(crate) fn placement_image(backend: &str, image: Option<String>, get: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    image.filter(|i| !i.trim().is_empty()).or_else(|| backend_image_ref(backend, get))
}

/// `:latest` or no tag, and no `@sha256:` digest. A registry host with a
/// port (`host:5000/repo`) is not a tag.
pub(crate) fn is_floating_image_ref(r: &str) -> bool {
    let r = r.trim();
    if r.contains("@sha256:") {
        return false;
    }
    let last = r.rsplit('/').next().unwrap_or(r);
    match last.rsplit_once(':') {
        Some((_, tag)) => tag.is_empty() || tag == "latest",
        None => true,
    }
}

/// POST /api/cluster/backends/start — Start a backend on a node.
///
/// Native Rust: resolves node, sends POST to node-agent, polls health.
/// No Python worker pool involvement.
async fn backends_start(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BackendStartBody>,
) -> AppResult {
    let backend = body.backend
        .or(body.backend_type)
        .or(body.type_field)
        .unwrap_or_else(|| "ollama".into());
    let model = body.model.unwrap_or_default();
    Ok(Json(
        start_backend_core(&state, body.node_id.as_deref(), &backend, &model).await?,
    ))
}

/// The backend START path, shared by the HTTP route and the autonomy engine
/// (`backend_availability`, `backend_scaling`).
///
/// There is exactly one of these on purpose: the cooldown map, the controller's
/// image/parser env forwarding and the node-agent auth headers all
/// live here, and an autonomy engine that reimplemented "start a backend" would
/// drift from the /backends/start route the first time any of the three changed.
///
/// `node_id: None` auto-selects a node the same way the route does.
pub(crate) async fn start_backend_core(
    state: &AppState,
    node_id: Option<&str>,
    backend: &str,
    model: &str,
) -> Result<Value, AppError> {
    let backend = backend.to_string();
    let model = model.to_string();

    // Find target node
    let (node_id, ip_address) = if let Some(nid) = node_id {
        // Get IP from KV
        let ip = if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
            if let Ok(Some(entry)) = kv.get(nid).await {
                serde_json::from_slice::<Value>(&entry).ok()
                    .and_then(|d| d.get("ip_address").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    .unwrap_or_default()
            } else { String::new() }
        } else { String::new() };
        (nid.to_string(), ip)
    } else {
        // Auto-select: find node with lowest load from NATS KV
        let agents = super::admin::all_node_agents(state).await;
        if agents.is_empty() {
            return Err(AppError::NotFound("No nodes available".into()));
        }
        // Pick first available (already sorted or just use first)
        let (nid, _url, _hostname) = agents.into_iter().next().unwrap();
        let ip = if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
            if let Ok(Some(entry)) = kv.get(nid.as_str()).await {
                serde_json::from_slice::<Value>(&entry).ok()
                    .and_then(|d| d.get("ip_address").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    .unwrap_or_default()
            } else { String::new() }
        } else { String::new() };
        (nid, ip)
    };

    // Check cooldown
    let cooldown_key = format!("{node_id}:{backend}");
    if !cooldowns::is_cooled_down(&cooldown_key) {
        return Err(AppError::BadRequest(format!(
            "Node {node_id} backend {backend} is in cooldown after recent failure"
        )));
    }

    tracing::info!(node_id = %node_id, backend = %backend, model = %model, "starting backend");

    // Send start request to node agent.
    //
    // controller is the canonical source of truth for image
    // + parser config. Pass the controller's own env values so workers
    // run the same vLLM tag / parser the controller uses, regardless of
    // what their local .env says. Empty/missing fields fall through to
    // the worker's env (backwards compat for hand-started backends).
    let mut start_body = json!({"backend": backend, "model": model});
    if backend == "vllm" {
        start_body["gpu_count"] = json!(1);
    }
    if let Some(image) = backend_image_ref(backend.as_str(), &|k: &str| std::env::var(k).ok()) {
        start_body["image"] = json!(image);
    }
    let env = std::env::var;
    if backend == "vllm" {
        for (key, json_field) in [
            ("VLLM_TOOL_PARSER", "tool_parser"),
            ("VLLM_REASONING_PARSER", "reasoning_parser"),
            ("VLLM_QUANTIZATION", "quantization"),
            ("GPU_MEM_UTIL", "gpu_mem_util"),
        ] {
            if let Ok(v) = env(key) {
                if !v.is_empty() {
                    start_body[json_field] = json!(v);
                }
            }
        }
        if let Ok(v) = env("VLLM_MAX_MODEL_LEN") {
            if let Ok(n) = v.parse::<i64>() {
                start_body["max_model_len"] = json!(n);
            }
        }
    }
    // Resolved by id, so `/start` rides the bus when the node advertises
    // it; an address alone would always go over HTTPS.
    let req = crate::node_link::NodeLink::for_node(state, &node_id).await?
        .request(reqwest::Method::POST, "/start")
        .json(&start_body);

    match req.timeout(std::time::Duration::from_secs(30)).send().await {
        Ok(resp) if resp.status().is_success() => {
            // Clear the backoff. `record_success` existed from the start and
            // was never called, so a node that failed one start carried its
            // penalty (300s doubling to 3600s) until the entry aged out on
            // its own — even after several clean starts. That mattered once
            // `backend_availability` could act unattended: the autonomy
            // evaluator honours this same map, so a single transient failure
            // could suppress an armed auto-start for the next hour.
            cooldowns::record_success(&cooldown_key);
            tracing::info!(node_id = %node_id, backend = %backend, "start request accepted by node agent");
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            cooldowns::record_failure(&cooldown_key);
            return Err(AppError::Upstream(format!("Node agent returned {status}: {body}")));
        }
        Err(e) => {
            cooldowns::record_failure(&cooldown_key);
            return Err(AppError::Upstream(format!("Failed to contact node agent: {e}")));
        }
    }

    // Return immediately — the node-agent starts backends in the background.
    // Large models (vLLM) take 5-10 min to load; blocking here would timeout.
    // The node heartbeat will report backend status once it's healthy.
    let (port, health_path) = backend_health(&backend).unwrap_or((8000, "/health"));
    // https unconditionally: every backend listener is mTLS (#538) and the
    // gateway itself cannot start without the cluster CA, so the old
    // `NOO_TLS_CA`-gated plain form described no reachable door.
    let health_url = if !ip_address.is_empty() {
        format!("https://{ip_address}:{port}{health_path}")
    } else {
        // Controller-local: the same door the coordinator dials (llama.cpp
        // and ollama at their stunnel sidecars, not the plain container).
        format!("{}{health_path}", crate::coordinator::local_backend_url(&backend, port))
    };

    Ok(json!({
        "status": "starting",
        "backend": backend,
        "model": model,
        "node_id": node_id,
        "ip_address": ip_address,
        "health_url": health_url,
    }))
}

#[derive(Deserialize)]
pub(crate) struct BackendStopBody {
    node_id: String,
    backend: Option<String>,
    backend_type: Option<String>,
    #[serde(rename = "type")]
    type_field: Option<String>,
}

/// POST /api/cluster/backends/stop — Stop a backend on a node.
pub(crate) async fn backends_stop(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BackendStopBody>,
) -> AppResult {
    let backend = body.backend
        .or(body.backend_type)
        .or(body.type_field)
        .ok_or_else(|| AppError::BadRequest("backend type required".into()))?;
    Ok(Json(stop_backend_core(&state, &body.node_id, &backend).await?))
}

/// The backend STOP path, shared by the HTTP route and the autonomy engine
/// (`backend_idle_scaledown`). Same rationale as [`start_backend_core`].
pub(crate) async fn stop_backend_core(
    state: &AppState,
    node_id: &str,
    backend: &str,
) -> Result<Value, AppError> {
    let link = crate::node_link::NodeLink::for_node(state, node_id).await?;

    tracing::info!(node_id = %node_id, backend = %backend, "stopping backend");

    let req = link
        .request(reqwest::Method::POST, "/stop")
        .json(&json!({"backend": backend}));

    match req.timeout(std::time::Duration::from_secs(30)).send().await {
        Ok(resp) if resp.status().is_success() => {
            Ok(json!({
                "status": "stopped",
                "backend": backend,
                "node_id": node_id,
            }))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Err(AppError::Upstream(format!("Stop failed ({status}): {text}")))
        }
        Err(e) => Err(AppError::Upstream(format!("Failed to contact node agent: {e}"))),
    }
}

/// POST /api/cluster/backends/clear-cooldowns — Reset all failure cooldowns.
async fn backends_clear_cooldowns() -> AppJson {
    let cleared = cooldowns::clear_all();
    Json(json!({"cleared": cleared, "status": "ok"}))
}

// ═══════════════════════════════════════════════════════════════
// Terminal backend endpoints — same logic as cluster backends
// but served at /api/terminal/backends/* for the terminal UI
// ═══════════════════════════════════════════════════════════════

/// GET /api/terminal/backends — list running backends across all nodes.
///
/// Reuses the same NATS KV + gossip logic as cluster_backends, returning
/// the same shape so the terminal dashboard can consume it directly.
async fn terminal_backends(State(state): State<Arc<AppState>>) -> AppJson {
    let mut backends: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Primary source: NATS KV heartbeat data (has running_backends from all nodes)
    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        use tokio_stream::StreamExt;
        if let Ok(keys) = kv.keys().await {
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
            for key in keys {
                if key == "gateway" { continue; }
                if let Ok(Some(entry)) = kv.get(&key).await {
                    if let Ok(data) = serde_json::from_slice::<Value>(&entry) {
                        let hostname = data.get("hostname").and_then(|h| h.as_str()).unwrap_or(&key);
                        let load = data.get("load").and_then(|l| l.as_f64()).unwrap_or(0.0);
                        if let Some(rb) = data.get("running_backends").and_then(|r| r.as_object()) {
                            for (bt, model_val) in rb {
                                let model = model_val.as_str().unwrap_or("?");
                                let sig = format!("{}:{}:{}", key, bt, model);
                                if seen.insert(sig) {
                                    backends.push(json!({
                                        "node_id": key,
                                        "backend": bt,
                                        "backend_type": bt,
                                        "model": model,
                                        "status": "running",
                                        "hostname": hostname,
                                        "load": load,
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: gossip peers (for nodes not yet in NATS KV)
    for p in &state.gossip.alive_peers() {
        for (bt, info) in &p.backends {
            let sig = format!("{}:{}:{}", p.node_id, bt, info.model);
            if seen.insert(sig) {
                backends.push(json!({
                    "node_id": p.node_id,
                    "backend": bt,
                    "backend_type": bt,
                    "model": info.model,
                    "url": info.url,
                    "status": "running",
                    "hostname": p.hostname,
                    "load": p.load,
                }));
            }
        }
    }

    annotate_backend_activity(&state, &mut backends).await;

    Json(json!({"backends": backends}))
}

/// POST /api/terminal/backends/stop — Stop a backend on a node.
///
/// Identical to backends_stop: resolves node from NATS KV, builds auth
/// headers, proxies POST /stop to the node agent.
async fn terminal_backends_stop(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BackendStopBody>,
) -> AppResult {
    // Delegate to the same logic as backends_stop
    backends_stop(State(state), Json(body)).await
}

// ═══════════════════════════════════════════════════════════════
// Native model handlers (ported from Python NATS 2026-03-31)
// ═══════════════════════════════════════════════════════════════

/// GET /api/models/cached
///
/// Aggregate cached models from running node backends. Reads from NATS KV
/// mesh_nodes to find running_backends on each node, then groups by model name.
pub(crate) async fn models_cached(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    let mut model_map: std::collections::HashMap<String, Value> = std::collections::HashMap::new();

    if let Ok(kv) = state.js.get_key_value("mesh_nodes").await {
        use tokio_stream::StreamExt;
        if let Ok(keys) = kv.keys().await {
            let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
            for key in keys {
                if key == "gateway" { continue; }
                if let Ok(Some(entry)) = kv.get(&key).await {
                    if let Ok(data) = serde_json::from_slice::<Value>(&entry) {
                        let hostname = data.get("hostname")
                            .and_then(|h| h.as_str())
                            .unwrap_or(&key);
                        let vram_gb = data.get("vram_gb")
                            .and_then(|v| v.as_f64());

                        if let Some(backends) = data.get("running_backends").and_then(|b| b.as_object()) {
                            for (backend_type, model_val) in backends {
                                let model_name = model_val.as_str().unwrap_or("");
                                if model_name.is_empty() { continue; }

                                let entry = model_map.entry(model_name.to_string())
                                    .or_insert_with(|| json!({
                                        "name": model_name,
                                        "backend": backend_type,
                                        "size": if backend_type != "embedding" {
                                            format!("{} GB VRAM", vram_gb.map(|v| format!("{v}")).unwrap_or_else(|| "?".into()))
                                        } else {
                                            "CPU/GPU".to_string()
                                        },
                                        "nodes": [],
                                    }));

                                if let Some(nodes) = entry.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                                    let h = json!(hostname);
                                    if !nodes.contains(&h) {
                                        nodes.push(h);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let models: Vec<Value> = model_map.into_values().collect();
    Ok(Json(json!({ "models": models })))
}

#[derive(Deserialize)]
struct ModelCacheBody {
    model: Option<String>,
    node_id: Option<String>,
}

/// POST /api/models/cache -- Cache (pre-pull) a model on a node.
///
/// Similar to models_pull: resolves target node, sends POST /start to node-agent.
/// Auto-selects least-loaded node if node_id not specified.
async fn models_cache(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ModelCacheBody>,
) -> AppResult {
    let model = body.model.unwrap_or_default();
    if model.is_empty() {
        return Err(AppError::BadRequest("model is required".into()));
    }

    let node_id = if let Some(ref nid) = body.node_id {
        nid.clone()
    } else {
        let agents = all_node_agents(&state).await;
        if agents.is_empty() {
            return Err(AppError::NotFound("No nodes available for model cache".into()));
        }
        let peers = state.gossip.alive_peers();
        let best = agents.into_iter()
            .min_by(|(a_id, _, _), (b_id, _, _)| {
                let a_load = peers.iter().find(|p| &p.node_id == a_id)
                    .map(|p| p.load).unwrap_or(0.5);
                let b_load = peers.iter().find(|p| &p.node_id == b_id)
                    .map(|p| p.load).unwrap_or(0.5);
                a_load.partial_cmp(&b_load).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();
        best.0
    };

    tracing::info!(node_id = %node_id, model = %model, "caching model");

    // Resolved by id, so `/start` rides the bus when the node advertises
    // it; an address alone would always go over HTTPS.
    let req = crate::node_link::NodeLink::for_node(&state, &node_id).await?
        .request(reqwest::Method::POST, "/start")
        .json(&json!({"backend": "ollama", "model": model}));

    match req.timeout(std::time::Duration::from_secs(30)).send().await {
        Ok(resp) if resp.status().is_success() => {
            Ok(Json(json!({
                "status": "caching",
                "model": model,
                "node_id": node_id,
            })))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Err(AppError::Upstream(format!(
                "Node agent returned {status}: {text}"
            )))
        }
        Err(e) => {
            tracing::error!(node_id = %node_id, error = %e, "model cache failed");
            Err(AppError::Upstream(format!("Failed to contact node agent: {e}")))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Native model pull — proxies to node-agent /start endpoint
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub(crate) struct ModelPullBody {
    model: Option<String>,
    backend: Option<String>,
    node_id: Option<String>,
}

/// POST /api/models/pull — Trigger model download on a node.
///
/// Native Rust: resolves node from NATS KV, sends POST /start to node-agent.
/// Auto-selects least-loaded node if node_id not specified.
/// Returns immediately — the pull runs in the background on the node agent.
pub(crate) async fn models_pull(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ModelPullBody>,
) -> AppResult {
    let model = body.model.unwrap_or_default();
    if model.is_empty() {
        return Err(AppError::BadRequest("model is required".into()));
    }
    let backend = body.backend.unwrap_or_else(|| "ollama".into());

    // Resolve target node
    let node_id = if let Some(ref nid) = body.node_id {
        nid.clone()
    } else {
        // Auto-select: pick first available node from NATS KV
        // (all_node_agents returns nodes sorted by KV iteration order;
        //  for smarter selection, could sort by load from gossip)
        let agents = super::admin::all_node_agents(&state).await;
        if agents.is_empty() {
            return Err(AppError::NotFound("No nodes available for model pull".into()));
        }

        // Prefer the node with the lowest live load from gossip
        let peers = state.gossip.alive_peers();
        let best = agents.into_iter()
            .min_by(|(a_id, _, _), (b_id, _, _)| {
                let a_load = peers.iter().find(|p| &p.node_id == a_id)
                    .map(|p| p.load).unwrap_or(0.5);
                let b_load = peers.iter().find(|p| &p.node_id == b_id)
                    .map(|p| p.load).unwrap_or(0.5);
                a_load.partial_cmp(&b_load).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap(); // safe: agents is non-empty
        best.0
    };

    tracing::info!(node_id = %node_id, backend = %backend, model = %model, "pulling model");

    // Send start request to node agent (triggers pull + start in background)
    // Resolved by id, so `/start` rides the bus when the node advertises
    // it; an address alone would always go over HTTPS.
    let req = crate::node_link::NodeLink::for_node(&state, &node_id).await?
        .request(reqwest::Method::POST, "/start")
        .json(&json!({"backend": backend, "model": model}));

    match req.timeout(std::time::Duration::from_secs(30)).send().await {
        Ok(resp) if resp.status().is_success() => {
            Ok(Json(json!({
                "status": "pulling",
                "model": model,
                "backend": backend,
                "node_id": node_id,
            })))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Err(AppError::Upstream(format!(
                "Node agent returned {status}: {text}"
            )))
        }
        Err(e) => {
            tracing::error!(node_id = %node_id, error = %e, "model pull failed");
            Err(AppError::Upstream(format!("Failed to contact node agent: {e}")))
        }
    }
}

// POST /api/models/switch (hot model swap) was removed 2026-09-27: no
// caller, never tested, and it mutated the in-memory config and stopped a
// node's backend outside the desired-state reconciler. Placements go
// through `noo cluster place` / the reconciler instead.

// ═══════════════════════════════════════════════════════════════
// Desired-state config — Postgres-authoritative node + placement
// records that node-agents pull and reconcile against. Pure SQL →
// native Rust per RUST_PYTHON_SPLIT. See DESIRED_STATE_CONFIG.md.
// ═══════════════════════════════════════════════════════════════

/// GET /api/cluster/nodes/{node_id}/desired-config
///
/// Returns the node's config row plus all placements. Agents poll this
/// (node-agent token) at startup + every reconcile interval.
async fn desired_config_get(
    State(state): State<Arc<AppState>>,
    caller: Option<axum::Extension<crate::auth::ClusterNode>>,
    _op: crate::authz::OperatorOrInternal,
    Path(node_id): Path<String>,
) -> AppResult {
    // A JWT caller below Operator is refused (a `read` account used to pass:
    // the tier gate let every GET through and this handler assumed any
    // non-node caller was an operator). A node carries ClusterNode and no
    // RequesterCtx, so this does not touch the node path below. The refusal is
    // the `OperatorOrInternal` extractor in the signature.
    // A node may read its OWN config and no other. the design
    //
    // Before this, the handler took node_id from the PATH and returned that
    // node's row with no check on who was asking. Combined with the
    // fleet-wide NOO_CLUSTER_SECRET — host8 and host9 carry the
    // identical value), one compromised node could enumerate the whole
    // fleet's configuration, including the `env` blob each placement carries.
    //
    // The identity is not new: the cluster token has always been
    // `<node>:<ts>:<hmac>`, so the caller has been signing its own name all
    // along and nobody read it.
    //
    // Operator callers are deliberately unaffected. A JWT request carries no
    // ClusterNode extension, so `caller` is None and the check does not
    // apply: an admin reading a node's desired config is a legitimate and
    // different act from a node reading its neighbour's. Narrowing that would
    // break the UI and CLI to no security end.
    if let Some(axum::Extension(crate::auth::ClusterNode(caller_node, _))) = caller {
        if caller_node != node_id {
            tracing::warn!(
                caller = %caller_node,
                requested = %node_id,
                "desired_config_cross_node_denied"
            );
            return Err(AppError::Forbidden(format!(
                "node {caller_node} may not read the desired config of {node_id}"
            )));
        }
    }
    #[allow(clippy::type_complexity)]
    let node: Option<(Option<String>, Option<String>, Option<i32>, Option<String>, Option<String>, Option<String>, Option<f64>, Option<Value>, String, Option<i32>, Option<String>, Vec<String>, Value)> =
        sqlx::query_as(
            "SELECT ip_address, ssh_user, tier, data_root, models_dir, gpu_model, vram_gb, companion_policy, harness_policy, default_loop_budget, usage_profile, vendor_kinds, harness_profile \
             FROM noo_node_config WHERE node_id = $1",
        )
        .bind(&node_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("node_config query: {e}")))?;

    // `role` ships to the node so its proxies can tell WHICH local backend
    // serves embeddings. Without it the node-agent has only container names
    // to go on, and ollama is a general runtime — the same ambiguity that
    // had the coordinator routing chat at an embedding model (migration 032).
    #[allow(clippy::type_complexity)]
    let placements: Vec<(
        String,
        Option<String>,
        Option<String>,
        Option<i32>,
        bool,
        Value,
        String,
        String,
        Option<String>,
        Option<i64>,
    )> = sqlx::query_as(
        "SELECT backend, model, image, port, tls, env, desired_state, role, target, memory_limit_bytes \
             FROM noo_backend_placements WHERE node_id = $1 ORDER BY backend, role",
    )
    .bind(&node_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("placements query: {e}")))?;

    let placement_json: Vec<Value> = placements
        .into_iter()
        .map(
            |(backend, model, image, port, tls, env, desired_state, role, target, memory_limit_bytes)| {
                let image = placement_image(&backend, image, &|k: &str| std::env::var(k).ok());
                json!({
                    "backend": backend,
                    "model": model,
                    "image": image,
                    "port": port,
                    "tls": tls,
                    "env": env,
                    "desired_state": desired_state,
                    "role": role,
                    // `cpu` | `gpu` | null (undeclared): the agent gives a
                    // `cpu` container no GPU device.
                    "target": target,
                    // llama.cpp container memory limit; null = the agent's default.
                    "memory_limit_bytes": memory_limit_bytes,
                })
            },
        )
        .collect();

    // External MCP servers placed on THIS node: the
    // registry row joined to its placement, enabled servers only. The
    // agent starts stdio ones, dials http ones, and reports each catalog
    // back on the node rail.
    let mcp_rows: Vec<(String, String, Value, String, String)> = sqlx::query_as(
        "SELECT s.id, s.transport, s.spec, s.kind, p.desired_state \
         FROM noo_mcp_server_placements p JOIN noo_mcp_servers s ON s.id = p.server_id \
         WHERE p.node_id = $1 AND s.enabled ORDER BY s.id",
    )
    .bind(&node_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("mcp placements query: {e}")))?;
    let mcp_json: Vec<Value> = mcp_rows
        .into_iter()
        .map(|(id, transport, spec, kind, desired_state)| {
            json!({ "id": id, "transport": transport, "spec": spec, "kind": kind, "desired_state": desired_state })
        })
        .collect();

    let harness_policy = node.as_ref().map(|n| n.8.clone()).unwrap_or_else(crate::coordinator::harness_default_policy);
    let (usage_effective, usage_source) = crate::placement_fit::effective_usage(
        node.as_ref().and_then(|n| n.10.as_deref()),
        crate::self_node::is_self_node(&node_id),
    );
    let placement_json = apply_harness_policy(&harness_policy, placement_json);

    // The harness profile, RESOLVED (`harness_profile::resolve`): per field
    // override > measured > tier default. The tier is the one the node's
    // live facts derive (as `collect_cluster_nodes` derives it), the
    // measured speed the record's `model_bench`, applied only when it is of
    // the model the node's chat backend runs now.
    let harness_profile = {
        let record: Value = match state.js.get_key_value("mesh_nodes").await {
            Ok(kv) => match kv.get(&node_id).await {
                Ok(Some(e)) => serde_json::from_slice::<Value>(&e).unwrap_or_else(|_| json!({})),
                _ => json!({}),
            },
            Err(_) => json!({}),
        };
        let derived_tier = crate::node_tier::derive(&crate::node_tier::facts_from_capabilities(
            record.get("capabilities").unwrap_or(&json!({})),
        ))
        .tier()
        .and_then(|t| u8::try_from(t).ok());
        let bench = crate::harness_profile::ModelBench::from_record(&record);
        let running_chat = crate::harness_profile::running_chat_model(
            &record,
            &placement_json,
            bench.as_ref().and_then(|b| b.backend.as_deref()),
            bench.as_ref().map(|b| b.model.as_str()),
        );
        let overrides = node.as_ref().map(|n| n.12.clone()).unwrap_or_else(|| json!({}));
        let resolved = crate::harness_profile::resolve(derived_tier, &overrides, bench.as_ref(), running_chat.as_deref());
        serde_json::to_value(&resolved).unwrap_or(Value::Null)
    };

    let node_json = match node {
        Some((ip, user, tier, data_root, models_dir, gpu_model, vram_gb, companion_policy, harness_policy, default_loop_budget, usage_profile, vendor_kinds, harness_profile_overrides)) => json!({
            "node_id": node_id,
            "ip_address": ip,
            "ssh_user": user,
            "tier": tier,
            "data_root": data_root,
            "models_dir": models_dir,
            "gpu_model": gpu_model,
            "vram_gb": vram_gb,
            "companion_policy": companion_policy,
            "harness_policy": harness_policy,
            "default_loop_budget": default_loop_budget,
            "usage_profile": usage_profile,
            "usage_profile_effective": usage_effective,
            "usage_profile_source": usage_source,
            // The vendor CLIs this node's bundle carries besides its
            // harness placement's (`noo cluster vendor install`).
            "vendor_kinds": vendor_kinds,
            // The STORED per-node harness profile overrides (`noo cluster
            // profile <node> --set`), as written. What the node applies is
            // the resolved `harness_profile` at the top level.
            "harness_profile_overrides": harness_profile_overrides,
        }),
        None => json!(null),
    };

    Ok(Json(json!({
        "node": node_json,
        "placements": placement_json,
        "mcp_servers": mcp_json,
        // The resolved harness profile (config/harness-profiles.json):
        // `{tier, first_byte_secs, stream_idle_secs, thinking,
        // context, ollama_context (the same value, for agents older than
        // 0.6.13), claude_prompt, foreign_kinds, sources, bench}`.
        // The agent applies first_byte_secs, context and
        // foreign_kinds, and hands the whole object to its harness.
        "harness_profile": harness_profile,
        // Every verified add-on bundle's declared workloads (i163 part B):
        // what the node's actuator may start and stop. The node acts only
        // on a container that exists there with the declared labels.
        "addon_workloads": crate::addon_workloads::for_nodes(),
        // The fleet's node disk-reclaim gate (disk_watermark location): the
        // agent queues its own ladder under it. Absent on older gateways.
        "disk_reclaim": crate::autonomy_evaluators::node_reclaim_policy(&state).await,
        "engine": "rust",
    })))
}

/// Per node, the live tasks it holds (i227 fix 4): `running` (running or
/// checkpointed) with the age of the oldest one's last progress, and
/// `queued` (open, waiting for the node's busy harness) with the oldest
/// wait. Children count: they hold a harness permit like any task. Parked
/// tasks and aggregation parents do not. `None` when the query fails, so
/// the field is left out rather than reading as "nothing held".
async fn node_task_holds(db: &sqlx::PgPool) -> Option<std::collections::HashMap<String, Value>> {
    let rows = crate::repo::tasks::holds_by_node(db)
        .await
        .map_err(|e| tracing::warn!(error = %e, "cluster_nodes: task holds not read"))
        .ok()?;
    Some(rows.into_iter().map(|(node, running, queued, progress, waited)| (node, task_holds_json(running, queued, progress, waited))).collect())
}

fn task_holds_json(running: i64, queued: i64, oldest_progress_secs: Option<f64>, oldest_queued_secs: Option<f64>) -> Value {
    let mut v = json!({"running": running, "queued": queued});
    if let Some(p) = oldest_progress_secs {
        v["oldest_progress_secs"] = json!(p.max(0.0) as i64);
    }
    if let Some(w) = oldest_queued_secs {
        v["oldest_queued_secs"] = json!(w.max(0.0) as i64);
    }
    v
}

#[derive(Deserialize)]
struct NodeConfigBody {
    ip_address: Option<String>,
    ssh_user: Option<String>,
    tier: Option<i32>,
    data_root: Option<String>,
    models_dir: Option<String>,
    notes: Option<String>,
    gpu_model: Option<String>,
    vram_gb: Option<f64>,
    /// Companion gating for THIS node: keys
    /// `min_battery_pct`, `require_wifi`, `blocked_thermal_states`. Omitted
    /// = keep what is stored; `null` = clear it (back to the gateway
    /// default). Validated by `CompanionPolicy::validate`.
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    companion_policy: Option<Option<Value>>,
    /// `auto` — a harness follows any running chat backend on this node;
    /// `manual` (default) — only an explicit harness placement; `off` —
    /// never.
    harness_policy: Option<String>,
    /// The loop budget a task gets when it lands here and named none
    /// `null` clears it (back to the cluster default).
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    default_loop_budget: Option<Option<Value>>,
    /// `shared` | `dedicated` (`noo cluster set-config --usage`): how much of
    /// the node a placement may assume. `null` clears it (back to the
    /// default: dedicated on the controller, shared elsewhere).
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    usage_profile: Option<Option<Value>>,
    /// The harness kinds whose vendor CLI this node carries whatever its
    /// placement names (`noo cluster vendor install`). Omitted = keep;
    /// `[]` or `null` = none.
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    vendor_kinds: Option<Option<Value>>,
    /// The per-node harness profile overrides (`noo cluster profile <node>
    /// --set k=v`): any subset of the fields in
    /// config/harness-profiles.json, the whole object replaced. Omitted =
    /// keep; `{}` or `null` = clear (the node resolves to its tier
    /// defaults and measured speed). Validated by
    /// `harness_profile::validate_overrides`.
    #[serde(default, deserialize_with = "deserialize_optional_nullable")]
    harness_profile: Option<Option<Value>>,
}

/// Judge a `vendor_kinds` value: kinds from the harness-kinds table that
/// run a vendor CLI (`noo` runs none), at most eight, deduplicated in name
/// order. `null` is none.
pub(crate) fn validate_vendor_kinds(v: Option<&Value>) -> Result<Vec<String>, String> {
    let Some(v) = v.filter(|v| !v.is_null()) else { return Ok(Vec::new()) };
    let arr = v.as_array().ok_or("vendor_kinds must be a list of harness kind names")?;
    let mut out = std::collections::BTreeSet::new();
    for k in arr {
        let k = k.as_str().map(str::trim).ok_or("vendor_kinds must be a list of harness kind names")?;
        match crate::harness_kinds::get(k) {
            Some(row) if row.cli.is_some() => {
                out.insert(k.to_string());
            }
            _ => {
                let vendor: Vec<&str> = crate::harness_kinds::all().iter().filter(|r| r.cli.is_some()).map(|r| r.kind.as_str()).collect();
                return Err(format!("'{k}' is not a harness kind that runs a vendor CLI (one of {})", vendor.join(", ")));
            }
        }
    }
    if out.len() > 8 {
        return Err("vendor_kinds names at most 8 kinds".into());
    }
    Ok(out.into_iter().collect())
}

/// `Option<Option<T>>` so the handler can tell "field absent" (keep) from
/// "field null" (clear) — the COALESCE upsert cannot express a clear.
fn deserialize_optional_nullable<'de, D>(d: D) -> Result<Option<Option<Value>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::<Value>::deserialize(d)?))
}

/// The node-config upsert. A const so the
/// column/value arity is pinned by a test — the 2026-09-11 cut listed
/// twelve columns and supplied eleven values, which no compiler sees.
const NODE_CONFIG_UPSERT: &str =
        "INSERT INTO noo_node_config (node_id, ip_address, ssh_user, tier, data_root, models_dir, notes, gpu_model, vram_gb, companion_policy, harness_policy, default_loop_budget, usage_profile, vendor_kinds, harness_profile, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, COALESCE($12, $13), $14, $16, $18, $20, NOW()) \
         ON CONFLICT (node_id) DO UPDATE SET \
           ip_address = COALESCE($2, noo_node_config.ip_address), \
           ssh_user   = COALESCE($3, noo_node_config.ssh_user), \
           tier       = COALESCE($4, noo_node_config.tier), \
           data_root  = COALESCE($5, noo_node_config.data_root), \
           models_dir = COALESCE($6, noo_node_config.models_dir), \
           notes      = COALESCE($7, noo_node_config.notes), \
           gpu_model  = COALESCE($8, noo_node_config.gpu_model), \
           vram_gb    = COALESCE($9, noo_node_config.vram_gb), \
           companion_policy = CASE WHEN $11 THEN $10 ELSE noo_node_config.companion_policy END, \
           harness_policy = COALESCE($12, noo_node_config.harness_policy), \
           default_loop_budget = CASE WHEN $15 THEN $14 ELSE noo_node_config.default_loop_budget END, \
           usage_profile = CASE WHEN $17 THEN $16 ELSE noo_node_config.usage_profile END, \
           vendor_kinds = CASE WHEN $19 THEN $18 ELSE noo_node_config.vendor_kinds END, \
           harness_profile = CASE WHEN $21 THEN $20 ELSE noo_node_config.harness_profile END, \
           updated_at = NOW()";
/// PUT /api/cluster/nodes/{node_id}/config — upsert the node config row.
/// COALESCE keeps existing values for fields omitted from the body.
async fn node_config_put(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    Json(body): Json<NodeConfigBody>,
) -> AppResult {
    // Default models_dir to {data_root}/models when data_root given
    // without an explicit models_dir.
    let models_dir = body.models_dir.clone().or_else(|| {
        body.data_root.as_ref().map(|d| format!("{}/models", d.trim_end_matches('/')))
    });
    // Absent → keep ($10 NULL, $11 false); present → set or clear ($11 true).
    if let Some(hp) = body.harness_policy.as_deref() {
        if !matches!(hp, "auto" | "manual" | "off") {
            return Err(AppError::BadRequest("harness_policy must be 'auto', 'manual' or 'off'".into()));
        }
    }
    let (budget_value, budget_set): (Option<i32>, bool) = match &body.default_loop_budget {
        None => (None, false),
        Some(None) => (None, true),
        Some(Some(v)) => match v.as_i64() {
            Some(b) if (1..=500).contains(&b) => (Some(b as i32), true),
            _ => return Err(AppError::BadRequest("default_loop_budget must be 1..=500 or null".into())),
        },
    };
    let (usage_value, usage_set): (Option<String>, bool) = match &body.usage_profile {
        None => (None, false),
        Some(None) => (None, true),
        Some(Some(v)) => match v.as_str() {
            Some(u) if crate::placement_fit::USAGE_PROFILES.contains(&u) => (Some(u.to_string()), true),
            _ => return Err(AppError::BadRequest("usage_profile must be 'shared', 'dedicated' or null".into())),
        },
    };
    // Absent → keep ($18 empty, $19 false); present → set ($19 true).
    let (vendor_value, vendor_set): (Vec<String>, bool) = match &body.vendor_kinds {
        None => (Vec::new(), false),
        Some(v) => (validate_vendor_kinds(v.as_ref()).map_err(AppError::BadRequest)?, true),
    };
    // Absent → keep ($20 `{}`, $21 false: an INSERT starts with none);
    // `null`/`{}` → clear; an object → validated, then replaces the stored one.
    let (profile_value, profile_set): (Value, bool) = match &body.harness_profile {
        None => (json!({}), false),
        Some(v) => (
            crate::harness_profile::validate_overrides(v.as_ref().unwrap_or(&Value::Null)).map_err(AppError::BadRequest)?,
            true,
        ),
    };
    let (policy_value, policy_set) = match &body.companion_policy {
        None => (None, false),
        Some(None) => (None, true),
        Some(Some(v)) => {
            crate::scheduler_candidates::CompanionPolicy::validate(v).map_err(AppError::BadRequest)?;
            (Some(v.clone()), true)
        }
    };

    sqlx::query(
        NODE_CONFIG_UPSERT,

    )
    .bind(&node_id)
    .bind(&body.ip_address)
    .bind(&body.ssh_user)
    .bind(body.tier)
    .bind(&body.data_root)
    .bind(&models_dir)
    .bind(&body.notes)
    .bind(&body.gpu_model)
    .bind(body.vram_gb)
    .bind(policy_value)
    .bind(policy_set)
    .bind(&body.harness_policy)
    .bind(crate::coordinator::harness_default_policy())
    .bind(budget_value)
    .bind(budget_set)
    .bind(usage_value)
    .bind(usage_set)
    .bind(vendor_value)
    .bind(vendor_set)
    .bind(profile_value)
    .bind(profile_set)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("node_config upsert: {e}")))?;

    tracing::info!(node = %node_id, "node_config_updated");
    // Every column here is served by desired-config (harness policy,
    // vendor kinds, profile overrides, usage, data root …), so a change
    // reaches the node now rather than at its next tick (i256 fix 3).
    nudge_reconcile(state.clone(), node_id.clone());
    Ok(Json(json!({"ok": true, "node_id": node_id})))
}

#[derive(Deserialize)]
struct PlacementBody {
    model: Option<String>,
    image: Option<String>,
    port: Option<i32>,
    tls: Option<bool>,
    env: Option<Value>,
    desired_state: Option<String>,
    /// What the backend SERVES: chat (default) | embed | rerank. With the key
    /// (node, backend, ROLE), the role NAMES the placement: a place with no
    /// role is the default role (`chat`; `harness` for the harness backend),
    /// never "whatever role the row happened to have".
    role: Option<String>,
    /// Place even when the memory-fit check says it does not fit.
    #[serde(default)]
    force: bool,
    /// The hardware the placement runs on: `cpu` | `gpu` (`noo cluster place
    /// --on`). Absent keeps the stored target for the same model and clears
    /// it on a model change (the same rule as env).
    target: Option<String>,
    /// The model's on-disk size as the CLI found it in the controller model
    /// store (a GGUF file). Used for this request's fit check only; never
    /// stored.
    model_size_bytes: Option<u64>,
}

/// Check a requested hardware target against the backend and the node:
/// vLLM has no CPU build here, and `gpu` on a node that reports memory but no
/// GPU would be a placement that can never run as declared. A node that
/// reports nothing is not refused (unknown is not "no GPU").
pub(crate) fn validate_target(backend: &str, target: Option<&str>, node: &Value) -> Result<(), String> {
    let Some(t) = target else { return Ok(()) };
    if !crate::placement_fit::TARGETS.contains(&t) {
        return Err(format!("target must be one of {}", crate::placement_fit::TARGETS.join(", ")));
    }
    if backend == "harness" {
        return Err("the harness is a host service: it has no hardware target".into());
    }
    if t == "cpu" && (backend == "vllm" || backend == "vllm-secondary") {
        return Err("vLLM runs on a GPU only: place a llamacpp or ollama model to run on cpu".into());
    }
    if t == "gpu" && crate::placement_fit::node_reports_memory(node) && !crate::placement_fit::node_has_gpu(node) {
        return Err("this node reports no GPU: place it with target cpu".into());
    }
    Ok(())
}

/// The roles a placement may name.
pub const PLACEMENT_ROLES: &[&str] = &["chat", "embed", "rerank", "harness"];

/// The role a placement request names: explicit, else the backend's default
/// (`harness` for the harness backend, `chat` for everything else).
pub(crate) fn resolve_role(backend: &str, role: Option<&str>) -> Result<String, String> {
    let r = match (backend, role.map(str::trim).filter(|r| !r.is_empty())) {
        ("harness", None) | ("harness", Some("harness")) => "harness",
        ("harness", Some(other)) => return Err(format!("the harness has no role {other:?}")),
        (_, None) => "chat",
        (_, Some(r)) => r,
    };
    if !PLACEMENT_ROLES.contains(&r) {
        return Err(format!("role must be one of {}", PLACEMENT_ROLES.join(", ")));
    }
    if r == "harness" && backend != "harness" {
        return Err("role 'harness' belongs to the 'harness' backend only".into());
    }
    Ok(r.to_string())
}

/// The placement upsert, keyed (node, backend, ROLE) -- and, for role=embed
/// only, the MODEL (a node may serve several embedding spaces: one embed row
/// per model; migration 098). A const so the
/// column/value arity is test-pinned and the DB test runs the real text.
///
/// When the MODEL changes, env does not carry over from the previous model
/// (2026-10-08: re-placing gemma over harrier inherited harrier's
/// OLLAMA_NUM_PARALLEL=4): the new env is the one given, or empty. Within the
/// same model an omitted env keeps the stored one. The role is part of the key,
/// so it can never be inherited either. Every `SET` expression reads the OLD
/// row, so `model` comparisons are against what was stored.
pub(crate) const PLACEMENT_UPSERT: &str =
    "INSERT INTO noo_backend_placements (node_id, backend, model, image, port, tls, env, desired_state, role, target, memory_limit_bytes, updated_at) \
     VALUES ($1, $2, $3, $4, $5, COALESCE($6, false), COALESCE($7, '{}'::jsonb), $8, $9, $10, $11, NOW()) \
     ON CONFLICT (node_id, backend, role, (CASE WHEN role = 'embed' THEN model ELSE '' END)) DO UPDATE SET \
       env   = CASE WHEN $3::text IS NOT NULL AND $3::text IS DISTINCT FROM noo_backend_placements.model \
                    THEN COALESCE($7, '{}'::jsonb) ELSE COALESCE($7, noo_backend_placements.env) END, \
       target = CASE WHEN $10::text IS NOT NULL THEN $10::text \
                     WHEN $3::text IS NOT NULL AND $3::text IS DISTINCT FROM noo_backend_placements.model THEN NULL \
                     ELSE noo_backend_placements.target END, \
       memory_limit_bytes = CASE WHEN $11::bigint IS NOT NULL THEN $11::bigint \
                     WHEN $3::text IS NOT NULL AND $3::text IS DISTINCT FROM noo_backend_placements.model THEN NULL \
                     ELSE noo_backend_placements.memory_limit_bytes END, \
       model = COALESCE($3, noo_backend_placements.model), \
       image = COALESCE($4, noo_backend_placements.image), \
       port  = COALESCE($5, noo_backend_placements.port), \
       tls   = COALESCE($6, noo_backend_placements.tls), \
       desired_state = $8, \
       updated_at = NOW()";

/// One stored placement, as the fit check needs it.
#[derive(Clone, Debug)]
pub(crate) struct StoredPlacement {
    pub backend: String,
    pub role: String,
    pub model: Option<String>,
    pub env: Value,
    pub desired_state: String,
    /// The declared hardware target (`cpu` | `gpu`), NULL when undeclared.
    pub target: Option<String>,
}

/// The target a placement would have AFTER the upsert: the given one, else the
/// stored one while the model is unchanged ([`PLACEMENT_UPSERT`]'s rule).
pub(crate) fn effective_target_after_upsert(
    existing: Option<&StoredPlacement>,
    body_model: Option<&str>,
    body_target: Option<&str>,
) -> Option<String> {
    if let Some(t) = body_target {
        return Some(t.to_string());
    }
    let changed = matches!((body_model, existing.and_then(|e| e.model.as_deref())), (Some(n), Some(o)) if n != o);
    if changed {
        return None;
    }
    existing.and_then(|e| e.target.clone())
}

/// The model and env a placement would have AFTER the upsert, mirroring
/// [`PLACEMENT_UPSERT`]'s carry-over rule in Rust for the fit check.
pub(crate) fn effective_after_upsert(
    existing: Option<&StoredPlacement>,
    body_model: Option<&str>,
    body_env: Option<&Value>,
) -> (Option<String>, Value) {
    let model = body_model.map(str::to_string).or_else(|| existing.and_then(|e| e.model.clone()));
    let changed = matches!((body_model, existing.and_then(|e| e.model.as_deref())), (Some(n), Some(o)) if n != o)
        || (body_model.is_some() && existing.is_none());
    let env = match (body_env, existing) {
        (Some(e), _) => e.clone(),
        (None, Some(e)) if !changed => e.env.clone(),
        _ => json!({}),
    };
    (model, env)
}

fn spec_of(sp: &StoredPlacement) -> Option<crate::placement_fit::Spec> {
    let model = sp.model.clone().filter(|m| !m.is_empty())?;
    Some(crate::placement_fit::Spec {
        backend: sp.backend.clone(),
        role: sp.role.clone(),
        model,
        env: sp.env.as_object().cloned().unwrap_or_default(),
        target: sp.target.clone(),
    })
}

/// Whether `e` occupies the slot (backend, role, model): the unique key of
/// `noo_backend_placements`. The model is part of the key for role=embed only
/// (migration 098); `None` there matches any embed row on the backend.
pub(crate) fn same_placement_slot(e: &StoredPlacement, backend: &str, role: &str, model: Option<&str>) -> bool {
    e.backend == backend
        && e.role == role
        && (role != "embed" || model.is_none_or(|m| e.model.as_deref() == Some(m)))
}

/// Running placements on a node that hold memory (the harness is a host
/// service, not a model).
///
/// `replacing` is the (backend, role, model) slot the new row takes over; the
/// model only matters for role=embed, where each model is its own row.
pub(crate) fn fit_specs(existing: &[StoredPlacement], replacing: Option<(&str, &str, Option<&str>)>, new: Option<&StoredPlacement>) -> Vec<crate::placement_fit::Spec> {
    let mut specs: Vec<crate::placement_fit::Spec> = existing
        .iter()
        .filter(|e| e.desired_state == "running" && e.backend != "harness")
        .filter(|e| replacing.map(|(b, r, m)| !same_placement_slot(e, b, r, m)).unwrap_or(true))
        .filter_map(spec_of)
        .collect();
    if let Some(n) = new.filter(|n| n.desired_state == "running" && n.backend != "harness") {
        specs.extend(spec_of(n));
    }
    specs
}

async fn stored_placements(state: &AppState, node_id: &str) -> Result<Vec<StoredPlacement>, AppError> {
    let rows: Vec<(String, String, Option<String>, Value, String, Option<String>)> = sqlx::query_as(
        "SELECT backend, role, model, env, desired_state, target FROM noo_backend_placements WHERE node_id = $1 ORDER BY backend, role",
    )
    .bind(node_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("placements query: {e}")))?;
    Ok(rows
        .into_iter()
        .map(|(backend, role, model, env, desired_state, target)| StoredPlacement { backend, role, model, env, desired_state, target })
        .collect())
}

/// The node's memory facts for the fit check: its heartbeat record (the
/// `mesh_nodes` KV), topped up from `cluster_nodes` and the operator's
/// `noo_node_config.vram_gb` override. Nothing is probed.
pub(crate) async fn node_fit_facts(state: &AppState, node_id: &str) -> Value {
    let mut node = match state.js.get_key_value("mesh_nodes").await {
        Ok(kv) => match kv.get(node_id).await {
            Ok(Some(e)) => serde_json::from_slice::<Value>(&e).unwrap_or_else(|_| json!({})),
            _ => json!({}),
        },
        Err(_) => json!({}),
    };
    let has = |n: &Value, k: &str| n.get(k).and_then(|v| v.as_f64()).is_some_and(|v| v > 0.0);
    if !has(&node, "vram_gb") || !has(&node, "ram_gb") {
        if let Ok(Some((vram, ram))) = sqlx::query_as::<_, (Option<f64>, Option<f64>)>(
            "SELECT vram_gb, ram_gb FROM cluster_nodes WHERE node_id = $1",
        )
        .bind(node_id)
        .fetch_optional(&state.db)
        .await
        {
            if !has(&node, "vram_gb") { if let Some(v) = vram { node["vram_gb"] = json!(v); } }
            if !has(&node, "ram_gb") { if let Some(v) = ram { node["ram_gb"] = json!(v); } }
        }
    }
    let mut usage_stored: Option<String> = None;
    if let Ok(Some((v, usage))) = sqlx::query_as::<_, (Option<f64>, Option<String>)>(
        "SELECT vram_gb, usage_profile FROM noo_node_config WHERE node_id = $1",
    )
    .bind(node_id)
    .fetch_optional(&state.db)
    .await
    {
        if let Some(v) = v.filter(|v| *v > 0.0) { node["vram_gb"] = json!(v); }
        usage_stored = usage;
    }
    let (usage, usage_source) = crate::placement_fit::effective_usage(usage_stored.as_deref(), crate::self_node::is_self_node(node_id));
    node["usage_profile"] = json!(usage);
    node["usage_profile_source"] = json!(usage_source);
    node["fleet_model_stats"] = Value::Array(fleet_model_sizes(state, node_id).await);
    node
}

/// Every OTHER node's reported model sizes (`model_stats[].size_bytes` from
/// the `mesh_nodes` KV), as `{name, size_bytes}`: how the fit check sizes a
/// model this node has not pulled yet but a neighbour has.
async fn fleet_model_sizes(state: &AppState, node_id: &str) -> Vec<Value> {
    use tokio_stream::StreamExt;
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else { return Vec::new() };
    let Ok(keys) = kv.keys().await else { return Vec::new() };
    let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
    let mut out = Vec::new();
    for key in keys.into_iter().filter(|k| k != node_id && k != "gateway") {
        let Ok(Some(entry)) = kv.get(&key).await else { continue };
        let Ok(data) = serde_json::from_slice::<Value>(&entry) else { continue };
        out.extend(sizes_of(&data));
    }
    out
}

/// The `{name, size_bytes}` pairs a node record reports.
pub(crate) fn sizes_of(node: &Value) -> Vec<Value> {
    node["model_stats"]
        .as_array()
        .map(|ms| {
            ms.iter()
                .filter_map(|m| {
                    let name = m["name"].as_str()?;
                    let size = m["size_bytes"].as_u64().filter(|b| *b > 0)?;
                    Some(json!({"name": name, "size_bytes": size}))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Add the controller-store size the CLI found for `model` to the node facts.
fn with_size_hint(node: &mut Value, model: Option<&str>, size: Option<u64>) {
    if let (Some(m), Some(b)) = (model, size.filter(|b| *b > 0)) {
        node["model_size_hints"] = json!([{"name": m, "size_bytes": b}]);
    }
}

/// The not-staged refusal for a placement, or None (staged, nothing the
/// gateway can name, no store mounted, or the node's arch unknown).
/// The bool is whether the node runs NOO_IMAGE_SOURCE=rail (refuse) or not
/// (warn only).
async fn placement_staging_refusal(state: &AppState, node_id: &str, backend: &str, body_image: Option<&str>) -> Option<(String, bool)> {
    use crate::routes::artifacts as art;
    let dir = art::image_store_dir();
    if !dir.is_dir() {
        return None;
    }
    let node = node_fit_facts(state, node_id).await;
    let arch = node["capabilities"]["arch"].as_str().or_else(|| node["arch"].as_str()).unwrap_or("").to_string();
    if arch.is_empty() {
        return None;
    }
    let index = art::read_staged_index(&dir);
    let image = art::placement_required_image(backend, body_image, &arch, index.release.as_ref(), &index.own_roots)?;
    if art::image_is_staged(&dir, &image, &arch) {
        return None;
    }
    tracing::warn!(node = %node_id, backend = %backend, image = %image, arch = %arch, "placement.image_not_staged");
    let rail = node["image_source_mode"].as_str() == Some("rail");
    Some((art::not_staged_refusal(node_id, &image, &arch), rail))
}

/// PUT /api/cluster/nodes/{node_id}/placements/{backend} — upsert.
///
/// Keyed (node, backend, ROLE). The role comes from the body (`role`); the
/// legacy path with no role is the default role, `chat`. A second role on the
/// same backend is a NEW placement beside the first, never a replacement.
/// Before a running model placement is written the memory-fit check runs
/// ([`crate::placement_fit`]): does-not-fit is a 409 naming the budget, each
/// model and the shortfall, unless `force`; tight succeeds with a warning.
/// Ask the node to reconcile now rather than at its next 5-minute tick
/// (`POST /reconcile`, the `reconcile` control op; the agent coalesces
/// nudges). Fire-and-forget: the placement is stored either way and the
/// tick is the fallback, so a node that is off the bus, older than the op
/// (404) or unreachable costs a log line and nothing else. Without this a
/// harness kind change landed up to 5 min after `noo cluster place`
/// (both awolf and mcmini, harness compare 2026-10-24).
fn nudge_reconcile(state: Arc<AppState>, node_id: String) {
    tokio::spawn(async move {
        let link = match crate::node_link::NodeLink::for_node(&state, &node_id).await {
            Ok(l) => l,
            Err(e) => {
                tracing::info!(node = %node_id, error = %e, "reconcile_nudge_skipped");
                return;
            }
        };
        match link.request(reqwest::Method::POST, "/reconcile").send().await {
            Ok(r) if r.status().is_success() => tracing::info!(node = %node_id, "reconcile_nudged"),
            Ok(r) => tracing::info!(node = %node_id, status = r.status().as_u16(), "reconcile_nudge_declined"),
            Err(e) => tracing::info!(node = %node_id, error = %e, "reconcile_nudge_failed"),
        }
    });
}

async fn placement_put(
    State(state): State<Arc<AppState>>,
    Path((node_id, backend)): Path<(String, String)>,
    Json(mut body): Json<PlacementBody>,
) -> AppResult {
    let desired = body.desired_state.clone().unwrap_or_else(|| "running".into());
    if !matches!(desired.as_str(), "running" | "stopped") {
        return Err(AppError::BadRequest(
            "desired_state must be 'running' or 'stopped'".into(),
        ));
    }
    // The harness placement: backend `harness` is always role
    // `harness` and nothing else may claim that role.
    let role = resolve_role(&backend, body.role.as_deref()).map_err(AppError::BadRequest)?;
    // i150 E1: a node may serve several embedding spaces, so an embed row is
    // keyed by its model too. A body that names none (a bare stop/start, a
    // tuning edit) can only mean "the" embed row there is exactly one of.
    if role == "embed" {
        let named = body.model.as_deref().map(str::trim).filter(|m| !m.is_empty()).map(str::to_string);
        body.model = match named {
            Some(m) => Some(m),
            None => {
                let existing = stored_placements(&state, &node_id).await?;
                let models: Vec<String> = existing
                    .iter()
                    .filter(|e| e.backend == backend && e.role == "embed")
                    .filter_map(|e| e.model.clone().filter(|m| !m.is_empty()))
                    .collect();
                match models.as_slice() {
                    [one] => Some(one.clone()),
                    [] => return Err(AppError::BadRequest(format!("an embed placement names its model: pass model=<model> ({backend} on {node_id} has none)"))),
                    many => return Err(AppError::Conflict(format!("{backend} on {node_id} embeds with several models ({}): name one with model=<model>", many.join(", ")))),
                }
            }
        };
    }
    // i145: every embedding node serves its space's model, so vectors stay
    // comparable. A model no space uses is refused with the way to add one.
    if role == "embed" && desired == "running" {
        if let Some(m) = body.model.as_deref().map(str::trim).filter(|m| !m.is_empty()) {
            if let Some(why) = crate::embedding_spaces::placement_refusal(&crate::embedding_spaces::all(), m) {
                return Err(AppError::Conflict(why));
            }
        }
    }
    // A harness placement may name its KIND in env (followup
    // 1233): `noo` (this gateway's loop, the default) or a foreign kind
    // from config/harness-kinds.json. The node agent enforces what each
    // kind can talk to.
    if backend == "harness" {
        if let Some(kind) = body.env.as_ref().and_then(|e| e.get("NOO_HARNESS_KIND")).and_then(|k| k.as_str()) {
            // The kinds are declared once, in config/harness-kinds.json
            // (crate::harness_kinds); the node agent refuses one whose
            // runner is absent.
            let kinds = crate::harness_kinds::names();
            if !kinds.contains(&kind) {
                return Err(AppError::BadRequest(format!("NOO_HARNESS_KIND must be one of {}", kinds.join(", "))));
            }
        }
    }

    let target = body.target.as_deref().map(str::trim).filter(|t| !t.is_empty());
    if target.is_some() {
        let node = node_fit_facts(&state, &node_id).await;
        validate_target(&backend, target, &node).map_err(AppError::BadRequest)?;
    }

    // The memory-fit check (multi-role placements). A stopped placement holds
    // no memory and a harness is a host service; neither is judged.
    let mut fit_json = Value::Null;
    let mut fit_warnings: Vec<String> = Vec::new();
    let mut memory_limit: Option<(u64, String)> = None;
    if desired == "running" && backend != "harness" {
        let existing = stored_placements(&state, &node_id).await?;
        let mine = existing.iter().find(|e| same_placement_slot(e, &backend, &role, body.model.as_deref()));
        let (model, env) = effective_after_upsert(mine, body.model.as_deref(), body.env.as_ref());
        let ptarget = effective_target_after_upsert(mine, body.model.as_deref(), target);
        let proposed = StoredPlacement { backend: backend.clone(), role: role.clone(), model, env, desired_state: "running".into(), target: ptarget };
        if proposed.model.as_deref().is_some_and(|m| !m.is_empty()) {
            let mut node = node_fit_facts(&state, &node_id).await;
            with_size_hint(&mut node, proposed.model.as_deref(), body.model_size_bytes);
            let embed_ctx = crate::embedding_client::EMBED_NUM_CTX;
            let after = crate::placement_fit::evaluate(&node, &fit_specs(&existing, Some((&backend, &role, body.model.as_deref())), Some(&proposed)), embed_ctx);
            let before = crate::placement_fit::evaluate(&node, &fit_specs(&existing, None, None), embed_ctx);
            // Refuse only a placement that is over budget AND makes it worse:
            // an edit to a node that was already over (a tuning change) is not
            // the placement that broke it.
            if after.verdict == crate::placement_fit::Verdict::DoesNotFit && after.total_gb > before.total_gb + 1e-9 {
                if !body.force {
                    return Err(AppError::Conflict(after.refusal_message(&node_id)));
                }
                fit_warnings.push(format!("forced past a does-not-fit verdict: {}", after.refusal_message(&node_id)));
            }
            fit_warnings.extend(after.warnings.iter().cloned());
            // The llama.cpp container's memory limit, from this placement's row.
            if backend == "llamacpp" {
                if let Some(r) = after.rows.iter().find(|r| r.backend == backend && r.role == role && body.model.as_deref().is_none_or(|m| r.model == m)) {
                    let known = r.weights_gb.is_some() || r.source == "measured";
                    memory_limit = crate::placement_fit::llamacpp_memory_limit(&node, r.total_gb, known, r.target);
                }
            }
            fit_json = after.to_json();
        }
    }

    // Is the image this placement needs staged on the controller's artifact
    // rail? A node pulls images only from there (it holds no registry
    // credential), so an unstaged image is a placement that cannot start —
    // say so now, with the command, instead of as a start failure on the
    // node minutes later (host8-ma, llamacpp:v0.2.103 "unauthorized").
    // Judged only when the store is mounted here and the node reports its
    // architecture; `noo cluster place` stages and retries on this refusal.
    if desired == "running" && backend != "harness" {
        if let Some((msg, rail)) = placement_staging_refusal(&state, &node_id, &backend, body.image.as_deref()).await {
            if rail && !body.force {
                return Err(AppError::Conflict(msg));
            }
            // A node still on NOO_IMAGE_SOURCE=legacy (the rollout default)
            // takes images the pre-rail way: say it, do not refuse.
            fit_warnings.push(if rail { format!("forced past an unstaged image: {msg}") } else { format!("legacy image source on this node: {msg}") });
        }
    }

    // Ensure a node_config row exists so the FK-ish relationship holds
    // (no hard FK to allow placing ahead of enrollment, but keep a stub).
    sqlx::query(
        "INSERT INTO noo_node_config (node_id, harness_policy, updated_at) VALUES ($1, $2, NOW()) \
         ON CONFLICT (node_id) DO NOTHING",
    )
    .bind(&node_id)
    .bind(crate::coordinator::harness_default_policy())
    .execute(&state.db)
    .await
    .ok();

    // Only ollama hosts several models in one daemon (the node agent honours
    // just the primary row of any other backend), so a second embed model on
    // TEI/llamacpp REPLACES the first, as it always did, instead of adding a
    // row the node could not serve.
    if role == "embed" && desired == "running" && backend != "ollama" {
        sqlx::query(
            "DELETE FROM noo_backend_placements WHERE node_id = $1 AND backend = $2 AND role = 'embed' AND model IS DISTINCT FROM $3",
        )
        .bind(&node_id)
        .bind(&backend)
        .bind(&body.model)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("placement replace: {e}")))?;
    }

    sqlx::query(PLACEMENT_UPSERT)
        .bind(&node_id)
        .bind(&backend)
        .bind(&body.model)
        .bind(&body.image)
        .bind(body.port)
        .bind(body.tls)
        .bind(&body.env)
        .bind(&desired)
        .bind(&role)
        .bind(target)
        .bind(memory_limit.as_ref().map(|(b, _)| *b as i64))
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("placement upsert: {e}")))?;
    crate::role_capability::invalidate();

    tracing::info!(node = %node_id, backend = %backend, role = %role, desired = %desired, "placement_updated");
    nudge_reconcile(state.clone(), node_id.clone());
    Ok(Json(json!({
        "ok": true, "node_id": node_id, "backend": backend, "role": role,
        "fit": fit_json, "warnings": fit_warnings,
        "memory_limit": memory_limit.map(|(b, why)| json!({"bytes": b, "why": why})),
    })))
}

#[derive(Deserialize)]
struct PlacementRoleQuery {
    role: Option<String>,
    /// With `role=embed`: which embed model to remove (a node may serve several).
    model: Option<String>,
}

/// DELETE /api/cluster/nodes/{node_id}/placements/{backend}[?role=<role>|all][&model=<model>]
///
/// With `role`, removes that role's placement only. Without one it keeps the
/// old meaning when it is unambiguous - the backend has exactly one placement,
/// whatever its role - and is a 409 naming the roles when it has several
/// (`role=all` removes them all). A node may serve several embed models (one
/// row each): `model` names which one `role=embed` removes, and an embed
/// removal that leaves the choice open between several models is a 409
/// naming them.
async fn placement_delete(
    State(state): State<Arc<AppState>>,
    Path((node_id, backend)): Path<(String, String)>,
    Query(q): Query<PlacementRoleQuery>,
) -> AppResult {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT role, model FROM noo_backend_placements WHERE node_id = $1 AND backend = $2 ORDER BY role, model",
    )
    .bind(&node_id)
    .bind(&backend)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("placement lookup: {e}")))?;
    let mut roles: Vec<String> = rows.iter().map(|(r, _)| r.clone()).collect();
    roles.dedup();
    let model = q.model.as_deref().map(str::trim).filter(|m| !m.is_empty());
    let target: Option<String> = match q.role.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        Some("all") => None,
        Some(r) => Some(r.to_string()),
        None if roles.len() > 1 => {
            return Err(AppError::Conflict(format!(
                "{backend} on {node_id} has several role placements ({}): name one with role=<role>, or role=all to remove them all",
                roles.join(", ")
            )))
        }
        // One role: the old unambiguous meaning, unless that role is embed
        // with several models (then the model must be named below).
        None => roles.first().filter(|r| r.as_str() == "embed").cloned(),
    };
    if target.as_deref() == Some("embed") && model.is_none() {
        let models: Vec<&str> = rows.iter().filter(|(r, _)| r == "embed").filter_map(|(_, m)| m.as_deref()).collect();
        if models.len() > 1 {
            return Err(AppError::Conflict(format!(
                "{backend} on {node_id} embeds with several models ({}): name one with model=<model>",
                models.join(", ")
            )));
        }
    }
    let res = match target.as_deref() {
        Some("embed") if model.is_some() => sqlx::query(
            "DELETE FROM noo_backend_placements WHERE node_id = $1 AND backend = $2 AND role = 'embed' AND model = $3",
        )
        .bind(&node_id).bind(&backend).bind(model).execute(&state.db).await,
        Some(r) => sqlx::query("DELETE FROM noo_backend_placements WHERE node_id = $1 AND backend = $2 AND role = $3")
            .bind(&node_id).bind(&backend).bind(r).execute(&state.db).await,
        None => sqlx::query("DELETE FROM noo_backend_placements WHERE node_id = $1 AND backend = $2")
            .bind(&node_id).bind(&backend).execute(&state.db).await,
    }
    .map_err(|e| AppError::Internal(format!("placement delete: {e}")))?;
    crate::role_capability::invalidate();

    nudge_reconcile(state.clone(), node_id.clone());
    Ok(Json(json!({"ok": true, "deleted": res.rows_affected()})))
}

#[derive(Deserialize)]
struct FitBody {
    /// A placement to try, beside the node's existing ones. Optional: absent
    /// judges the node as it is.
    with: Option<FitWith>,
}

#[derive(Deserialize)]
struct FitWith {
    backend: String,
    model: String,
    role: Option<String>,
    env: Option<Value>,
    /// `cpu` | `gpu` (`noo cluster fit --on`).
    target: Option<String>,
    /// The controller-store file size the CLI found (see `PlacementBody`).
    model_size_bytes: Option<u64>,
}

/// POST /api/cluster/nodes/{node_id}/fit — read-only memory-fit verdict for
/// the node's placements, optionally with one more (`noo cluster fit`). Changes
/// nothing.
async fn placement_fit_post(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    body: Option<Json<FitBody>>,
) -> AppResult {
    let with = body.and_then(|Json(b)| b.with);
    let existing = stored_placements(&state, &node_id).await?;
    let mut node = node_fit_facts(&state, &node_id).await;
    let (replacing, proposed) = match &with {
        Some(w) => {
            let role = resolve_role(&w.backend, w.role.as_deref()).map_err(AppError::BadRequest)?;
            let target = w.target.as_deref().map(str::trim).filter(|t| !t.is_empty());
            validate_target(&w.backend, target, &node).map_err(AppError::BadRequest)?;
            let mine = existing.iter().find(|e| same_placement_slot(e, &w.backend, &role, Some(&w.model)));
            let (model, env) = effective_after_upsert(mine, Some(&w.model), w.env.as_ref());
            let target = effective_target_after_upsert(mine, Some(&w.model), target);
            with_size_hint(&mut node, Some(&w.model), w.model_size_bytes);
            (Some((w.backend.clone(), role.clone(), Some(w.model.clone()))), Some(StoredPlacement { backend: w.backend.clone(), role, model, env, desired_state: "running".into(), target }))
        }
        None => (None, None),
    };
    let report = crate::placement_fit::evaluate(
        &node,
        &fit_specs(&existing, replacing.as_ref().map(|(b, r, m)| (b.as_str(), r.as_str(), m.as_deref())), proposed.as_ref()),
        crate::embedding_client::EMBED_NUM_CTX,
    );
    let mut out = report.to_json();
    out["node_id"] = json!(node_id);
    out["would_refuse"] = json!(report.verdict == crate::placement_fit::Verdict::DoesNotFit);
    out["usage_profile_source"] = node["usage_profile_source"].clone();
    // What `noo cluster place` tunes from: the node's reported hardware.
    out["hardware"] = json!({
        "cpu_cores": node.get("cpu_cores").cloned().or_else(|| node["capabilities"].get("cpu_cores").cloned()),
        "ram_gb": node.get("ram_gb").cloned(),
        "vram_gb": node.get("vram_gb").cloned(),
        "has_gpu": crate::placement_fit::node_has_gpu(&node),
    });
    Ok(Json(out))
}

// ═══════════════════════════════════════════════════════════════════
// Model classes — the names a consumer may send as `model`, and the
// ordered candidates behind each (coordinator::classes; the design)
// ═══════════════════════════════════════════════════════════════════

/// GET /api/cluster/model-classes — the live class table: declared and
/// derived classes with every candidate's status (`placed` / `available` /
/// `unplaced`) and health, plus the aliases. What `noo cluster class list`
/// prints and the `model classes` row of `noo cluster verify` judges.
async fn model_classes_get(State(state): State<Arc<AppState>>) -> AppResult {
    let table = crate::coordinator::classes::load_table(&state)
        .await
        .map_err(|e| AppError::Unavailable(format!("model classes unavailable: {e}")))?;
    let classes: Vec<Value> = table
        .classes
        .iter()
        .map(|c| {
            // The order a request would take right now (in-flight and stall
            // memory included), and who is left out — `noo cluster verify`'s
            // `default chat` row lists it.
            let ranked = crate::coordinator::classes::rank(
                c,
                &|_| false,
                &|x| crate::coordinator::classes::in_flight(&x.url, &x.backend),
                &|x| crate::coordinator::classes::recently_stalled(&x.url, &x.backend),
            );
            let order: Vec<Value> = ranked
                .order
                .iter()
                .map(|x| {
                    let busy = crate::coordinator::classes::in_flight(&x.url, &x.backend);
                    let stalled = crate::coordinator::classes::recently_stalled(&x.url, &x.backend);
                    json!({
                        "node_id": x.node_id, "backend": x.backend, "model": x.model,
                        "gpu": x.gpu || x.backend.starts_with("vllm"),
                        "reason": crate::coordinator::classes::rank_reason(x, busy, stalled),
                    })
                })
                .collect();
            let skipped: Vec<Value> = ranked.skipped.iter().map(|(x, why)| json!({"node_id": x.node_id, "backend": x.backend, "reason": why})).collect();
            json!({
                "name": c.name,
                "declared": c.declared,
                "pool": c.pool,
                "dynamic": c.dynamic,
                "routable": c.routable_count(),
                "healthy": c.healthy_count(),
                "candidates": c.candidates,
                "routing_order": order,
                "skipped": skipped,
                "last_resort": ranked.last_resort,
            })
        })
        .collect();
    let aliases: Vec<Value> = table.aliases.iter().map(|(a, c)| json!({"alias": a, "class": c, "builtin": crate::coordinator::classes::BUILTIN_ALIASES.contains(&a.as_str()), "purpose": crate::coordinator::classes::PURPOSE_ALIASES.iter().any(|p| p.eq_ignore_ascii_case(a))})).collect();
    Ok(Json(json!({"classes": classes, "aliases": aliases})))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ModelClassCandidateBody {
    pub node: String,
    pub backend: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub degraded: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ModelClassBody {
    pub candidates: Vec<ModelClassCandidateBody>,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Peers sharing the load instead of a failover order
    /// (`noo cluster class set … --pool`).
    #[serde(default)]
    pub pool: bool,
}

/// Validate a class declaration. Pure, so the rules are tested: a valid
/// name (compared case-insensitively — `Chat-Default` IS `chat-default`,
/// and is stored lowercase), at least one candidate, inference backends
/// only, a well-formed `model` where given, no duplicate (node, backend),
/// the first candidate not degraded (a class whose first choice is already
/// "a different model" declares nothing), aliases valid and NOT the name of
/// any class — declared or derived, so an alias can never shadow a served
/// model (`gemma4:26b` → chat-default would turn an exact 26b pin into the
/// 12B) — and not owned by another class (an alias is one class's).
///
/// A class NAMED after a served model must serve it: its first candidate's
/// resolved model (the declared one, else what `served_by(node, backend)`
/// reports that backend running) must be that model — otherwise an exact
/// pin of `gemma4:26b` would silently get whatever the class serves, the
/// alias-shadowing hole through the class-name door.
///
/// `all_classes` is every class name in the live table except this one;
/// `owned_aliases` is `(alias, class)` for every declared alias;
/// `served_by` answers what a (node, backend) currently serves, `None` when
/// the gateway cannot tell.
pub(crate) fn validate_model_class(
    name: &str,
    body: &ModelClassBody,
    all_classes: &[String],
    owned_aliases: &[(String, String)],
    served_by: &dyn Fn(&str, &str) -> Option<String>,
) -> Result<crate::coordinator::classes::DeclaredClass, String> {
    use crate::coordinator::classes::{norm_model, valid_model, valid_name, DeclaredCandidate, DeclaredClass};
    valid_name(name)?;
    let name = name.trim().to_ascii_lowercase();
    if body.candidates.is_empty() {
        return Err("a class needs at least one candidate".into());
    }
    let mut seen = std::collections::HashSet::new();
    let mut candidates = Vec::with_capacity(body.candidates.len());
    for (i, c) in body.candidates.iter().enumerate() {
        let node = c.node.trim();
        let backend = c.backend.trim();
        if node.is_empty() || backend.is_empty() {
            return Err(format!("candidate {i}: node and backend are required"));
        }
        if !matches!(backend, "vllm" | "vllm-secondary" | "ollama" | "llamacpp") {
            return Err(format!("candidate {i}: backend must be vllm, vllm-secondary, ollama or llamacpp (got '{backend}')"));
        }
        if !seen.insert((node.to_string(), backend.to_string())) {
            return Err(format!("candidate {i}: {node}/{backend} is listed twice"));
        }
        if i == 0 && c.degraded {
            return Err("the first candidate cannot be degraded — it defines the class's model".into());
        }
        let model = c.model.as_deref().map(str::trim).filter(|m| !m.is_empty()).map(str::to_string);
        if let Some(m) = &model {
            valid_model(m).map_err(|e| format!("candidate {i}: {e}"))?;
        }
        candidates.push(DeclaredCandidate { node_id: node.to_string(), backend: backend.to_string(), model, degraded: c.degraded });
    }
    if let Some(served) = all_classes.iter().find(|c| norm_model(c) == norm_model(&name)) {
        let first = &candidates[0];
        let first_model = first.model.clone().or_else(|| served_by(&first.node_id, &first.backend));
        match first_model {
            Some(m) if norm_model(&m) == norm_model(served) => {}
            Some(m) => {
                return Err(format!(
                    "a class named after a served model must serve it: '{served}' is served, but the first candidate {}/{} serves '{m}'",
                    first.node_id, first.backend
                ))
            }
            None => {
                return Err(format!(
                    "a class named after a served model must serve it: '{served}' is served, and the gateway cannot tell what {}/{} serves — name the model on the candidate",
                    first.node_id, first.backend
                ))
            }
        }
    }
    let mut aliases_seen = std::collections::HashSet::new();
    for a in &body.aliases {
        let a = a.trim();
        valid_name(a)?;
        if a.eq_ignore_ascii_case(&name) {
            return Err(format!("alias '{a}' is the class's own name"));
        }
        if let Some(c) = all_classes.iter().find(|c| norm_model(c) == norm_model(a)) {
            return Err(format!("alias '{a}' is the name of class '{c}' (a served model or a declared class) — an alias may not shadow one"));
        }
        if let Some((_, owner)) = owned_aliases.iter().find(|(x, owner)| norm_model(x) == norm_model(a) && !owner.eq_ignore_ascii_case(&name)) {
            return Err(format!("alias '{a}' already belongs to class '{owner}' — unset it there first"));
        }
        if !aliases_seen.insert(norm_model(a)) {
            return Err(format!("alias '{a}' is listed twice"));
        }
    }
    Ok(DeclaredClass { name, candidates, pool: body.pool })
}

/// PUT /api/cluster/model-classes/{class} — declare (replace) a class:
/// `{candidates: [{node, backend, model?, degraded?}], aliases?: [..]}`.
/// `model` omitted = the placement's model on that node. Operator role
/// (every non-GET under `/api/cluster` is).
async fn model_class_put(
    State(state): State<Arc<AppState>>,
    Path(class): Path<String>,
    Json(body): Json<ModelClassBody>,
) -> AppResult {
    use crate::coordinator::classes;
    let decl = classes::load_declarations(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("model classes read: {e}")))?;
    // Every class name the live table knows — derived ones included, since
    // those are the served models an alias must not shadow.
    let table = classes::load_table(&state)
        .await
        .map_err(|e| AppError::Unavailable(format!("model classes unavailable: {e}")))?;
    let others: Vec<String> = table.classes.iter().map(|c| c.name.clone()).filter(|n| !n.eq_ignore_ascii_case(&class)).collect();
    let served_by = |node: &str, backend: &str| served_model_in(&table, node, backend);
    let declared = validate_model_class(&class, &body, &others, &decl.aliases, &served_by).map_err(AppError::BadRequest)?;
    let aliases: Vec<String> = body.aliases.iter().map(|a| a.trim().to_string()).collect();
    classes::save_class(&state.db, &declared, &aliases)
        .await
        .map_err(|e| AppError::Internal(format!("model class write: {e}")))?;
    // A node nobody has heard from is allowed (the placement may be on its
    // way; `cluster verify` flags it) — but say so now, not later.
    let unknown_nodes: Vec<String> = match classes::load_table(&state).await {
        Ok(t) => t
            .class(&declared.name)
            .map(|c| c.candidates.iter().filter(|c| c.health == "no heartbeat record").map(|c| c.node_id.clone()).collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    tracing::info!(class = %declared.name, candidates = declared.candidates.len(), aliases = aliases.len(), unknown_nodes = ?unknown_nodes, "model_class_declared");
    // A class write changes routing for every consumer: audited like a
    // placement change or a node forget.
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::ModelClassDeclared, "gateway", &format!("class:{}", declared.name))
            .details(json!({
            "class": declared.name,
            "candidates": declared.candidates.iter().map(|c| json!({"node": c.node_id, "backend": c.backend, "model": c.model, "degraded": c.degraded})).collect::<Vec<_>>(),
            "aliases": aliases,
            "unknown_nodes": unknown_nodes,
        })),
    ).await;
    let mut out = json!({"ok": true, "class": declared.name, "candidates": declared.candidates.len(), "aliases": aliases});
    if let Some(note) = unknown_nodes_note(&unknown_nodes) {
        out["unknown_nodes"] = json!(unknown_nodes);
        out["note"] = json!(note);
    }
    Ok(Json(out))
}

/// What a (node, backend) is serving right now, from the live table: the
/// model of any PLACED candidate on it (a derived class lists every served
/// backend). `None` when nothing reports it.
pub(crate) fn served_model_in(table: &crate::coordinator::classes::ClassTable, node: &str, backend: &str) -> Option<String> {
    table
        .classes
        .iter()
        .flat_map(|c| c.candidates.iter())
        .find(|c| c.node_id == node && c.backend == backend && c.status == crate::coordinator::classes::CandidateStatus::Placed)
        .map(|c| c.model.clone())
}

/// The PUT response's note when a candidate names a node nobody has heard
/// from: allowed (the placement may be on its way), said at once.
pub(crate) fn unknown_nodes_note(unknown: &[String]) -> Option<String> {
    if unknown.is_empty() {
        return None;
    }
    Some(format!(
        "no heartbeat record for {}: those candidates are unplaced until the node reports; `noo cluster verify --controller` flags them",
        unknown.join(", ")
    ))
}

/// DELETE /api/cluster/model-classes/{class} — forget a declaration (and its
/// aliases). The derived class of the same model, if any, takes over.
async fn model_class_delete(
    State(state): State<Arc<AppState>>,
    Path(class): Path<String>,
) -> AppResult {
    let class = class.trim().to_ascii_lowercase();
    let n = crate::coordinator::classes::delete_class(&state.db, &class)
        .await
        .map_err(|e| AppError::Internal(format!("model class delete: {e}")))?;
    if n == 0 {
        return Err(AppError::NotFound(format!("no declared class '{class}'")));
    }
    tracing::info!(class = %class, "model_class_removed");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::ModelClassRemoved, "gateway", &format!("class:{class}"))
            .details(json!({"class": class, "deleted": n})),
    ).await;
    Ok(Json(json!({"ok": true, "class": class, "deleted": n})))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ModelAliasBody {
    class: String,
}

/// PUT /api/cluster/model-aliases/{alias} — point one alias (a purpose such
/// as `knowledge`, or any other) at a class or a served model: `{class}`.
/// That target is tried first and the mesh answers behind it (i145 phase D,
/// `noo cluster prefer`). A target nothing serves is accepted with a note.
async fn model_alias_put(
    State(state): State<Arc<AppState>>,
    Path(alias): Path<String>,
    Json(body): Json<ModelAliasBody>,
) -> AppResult {
    use crate::coordinator::classes;
    let alias = alias.trim().to_ascii_lowercase();
    let class = body.class.trim().to_string();
    classes::valid_name(&alias).map_err(AppError::BadRequest)?;
    classes::valid_model(&class).map_err(AppError::BadRequest)?;
    let table = classes::load_table(&state)
        .await
        .map_err(|e| AppError::Unavailable(format!("model classes unavailable: {e}")))?;
    if let Some(why) = classes::alias_refusal(&table, &alias, &class) {
        return Err(AppError::Conflict(why));
    }
    classes::save_alias(&state.db, &alias, &class)
        .await
        .map_err(|e| AppError::Internal(format!("model alias write: {e}")))?;
    let served = table.class(&class).is_some();
    tracing::info!(alias = %alias, class = %class, served, "model_alias_declared");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::ModelAliasDeclared, "gateway", &format!("alias:{alias}"))
            .details(json!({"alias": alias, "class": class, "served": served})),
    ).await;
    let mut out = json!({"ok": true, "alias": alias, "class": class, "served": served});
    if !served {
        out["note"] = json!(format!("nothing serves '{class}' right now: requests for '{alias}' go to any live chat node until something does"));
    }
    Ok(Json(out))
}

/// DELETE /api/cluster/model-aliases/{alias} — forget one alias. A purpose
/// then means `chat-default` (the whole mesh) again.
async fn model_alias_delete(
    State(state): State<Arc<AppState>>,
    Path(alias): Path<String>,
) -> AppResult {
    let alias = alias.trim().to_ascii_lowercase();
    if !crate::coordinator::classes::delete_alias(&state.db, &alias)
        .await
        .map_err(|e| AppError::Internal(format!("model alias delete: {e}")))?
    {
        return Err(AppError::NotFound(format!("no declared alias '{alias}'")));
    }
    tracing::info!(alias = %alias, "model_alias_removed");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::ModelAliasRemoved, "gateway", &format!("alias:{alias}"))
            .details(json!({"alias": alias})),
    ).await;
    Ok(Json(json!({"ok": true, "alias": alias})))
}

// ── embedding spaces (i145) ──────────────────────────────────────────

/// One space's pool for GET: every role=embed placement on its model, and
/// whether that node advertises `embed` right now. Placements on a model no
/// space uses are listed apart (`unmatched`): they serve nobody.
///
/// `statics[i]` is space i's static endpoints (the compose embedder,
/// `PAGEINDEX_EMBEDDING_URL` + extras) and whether each answered a probe
/// embed with the space's model. They are peers of the mesh nodes in every
/// embed, so `static_live` counts toward serving the space; `live` stays the
/// node count.
pub(crate) fn embedding_space_view(
    spaces: &[crate::embedding_spaces::Space],
    placements: &[(String, String, Option<String>, String)],
    advertising: &[String],
    statics: &[Vec<(String, bool)>],
) -> Value {
    use crate::embedding_spaces::same_model;
    let node = |(n, b, m, d): &(String, String, Option<String>, String)| {
        json!({
            "node": n, "backend": b, "model": m, "desired_state": d,
            "advertising": advertising.iter().any(|a| a.eq_ignore_ascii_case(n)),
        })
    };
    let out: Vec<Value> = spaces
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let pool: Vec<Value> = placements
                .iter()
                .filter(|p| p.2.as_deref().is_some_and(|m| same_model(m, &s.model)))
                .map(node)
                .collect();
            let live = pool.iter().filter(|n| n["advertising"] == json!(true) && n["desired_state"] == json!("running")).count();
            let st = statics.get(i).map(Vec::as_slice).unwrap_or(&[]);
            let static_live = st.iter().filter(|(_, ok)| *ok).count();
            let static_eps: Vec<Value> = st.iter().map(|(url, ok)| json!({"url": url, "live": ok})).collect();
            // i150: while migrating, the nodes that already hold the next model.
            let next_pool: Vec<Value> = match &s.migration {
                Some(m) => placements.iter().filter(|p| p.2.as_deref().is_some_and(|x| same_model(x, &m.next_model))).map(node).collect(),
                None => Vec::new(),
            };
            json!({
                "space": s.space, "model": s.model, "dims": s.dims,
                "default": s.space == crate::embedding_spaces::DEFAULT_SPACE,
                "pool": pool, "live": live,
                "static": static_eps, "static_live": static_live,
                "migration": s.migration, "next_pool": next_pool,
            })
        })
        .collect();
    let unmatched: Vec<Value> = placements
        .iter()
        .filter(|p| {
            !spaces.iter().any(|s| {
                p.2.as_deref().is_some_and(|m| {
                    same_model(m, &s.model) || s.migration.as_ref().is_some_and(|g| same_model(m, &g.next_model))
                })
            })
        })
        .map(node)
        .collect();
    json!({"spaces": out, "unmatched": unmatched})
}

/// GET /api/cluster/embedding-spaces — every space, its model and its pool.
async fn embedding_spaces_get(State(state): State<Arc<AppState>>) -> AppResult {
    let spaces = crate::embedding_spaces::load(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("embedding spaces read: {e}")))?;
    let placements = sqlx::query_as::<_, (String, String, Option<String>, String)>(
        "SELECT node_id, backend, model, desired_state FROM noo_backend_placements WHERE role = 'embed' ORDER BY node_id, backend",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("embed placements read: {e}")))?;
    let advertising: Vec<String> = state.gossip.find_peers_by_capability("embed", 256).into_iter().map(|p| p.node_id).collect();
    // F1 (0.6.8 rehearsal): a fresh install embeds through the compose
    // embedder alone, so a space served only by it must not read as dead.
    // Each static endpoint is probed with one embed of the space's model:
    // declared is not the same as answering.
    let statics = futures::future::join_all(spaces.iter().map(|s| async move {
        let eps = crate::embedding_client::resolve_space(Some(s.space.as_str())).map(|e| e.static_endpoints()).unwrap_or_default();
        let mut out = Vec::with_capacity(eps.len());
        for ep in eps {
            let ok = ep.embed(&["ping".to_string()], std::time::Duration::from_secs(5)).await.is_ok();
            out.push((ep.url.clone(), ok));
        }
        out
    }))
    .await;
    Ok(Json(embedding_space_view(&spaces, &placements, &advertising, &statics)))
}

#[derive(Debug, Deserialize)]
pub(crate) struct EmbeddingSpaceBody {
    model: String,
    dims: Option<u64>,
}

/// PUT /api/cluster/embedding-spaces/{space} — declare a space (`{model,
/// dims?}`). A new space is fine; an existing one keeps its model (changing
/// it is a re-embed, refused with 409), and may have `dims` filled in.
async fn embedding_space_put(
    State(state): State<Arc<AppState>>,
    Path(space): Path<String>,
    Json(body): Json<EmbeddingSpaceBody>,
) -> AppResult {
    use crate::embedding_spaces as es;
    let space = space.trim().to_ascii_lowercase();
    es::valid_space_name(&space).map_err(AppError::BadRequest)?;
    let model = body.model.trim().to_string();
    crate::coordinator::classes::valid_model(&model).map_err(AppError::BadRequest)?;
    let spaces = es::load(&state.db).await.map_err(|e| AppError::Internal(format!("embedding spaces read: {e}")))?;
    let existing = spaces.iter().find(|s| s.space == space);
    if let Some(why) = es::change_refusal(existing, &model) {
        return Err(AppError::Conflict(why));
    }
    if let Some(other) = spaces.iter().find(|s| {
        s.space != space
            && (es::same_model(&s.model, &model) || s.migration.as_ref().is_some_and(|m| es::same_model(&m.next_model, &model)))
    }) {
        return Err(AppError::Conflict(format!(
            "space '{}' already embeds with '{model}': one model, one space",
            other.space
        )));
    }
    let dims = body.dims.filter(|d| *d > 0).or(existing.and_then(|e| e.dims));
    if let (Some(e), Some(d)) = (existing.and_then(|e| e.dims), body.dims.filter(|d| *d > 0)) {
        if e != d {
            return Err(AppError::Conflict(format!("space '{space}' has {e}-dim vectors; {d} would be another model's width")));
        }
    }
    let rec = es::Space { space: space.clone(), model: existing.map(|e| e.model.clone()).unwrap_or(model), dims, migration: None };
    es::upsert(&state.db, &rec, "operator").await.map_err(|e| AppError::Internal(format!("embedding space write: {e}")))?;
    if let Ok(all) = es::load(&state.db).await {
        es::set_cache(all);
    }
    tracing::info!(space = %rec.space, model = %rec.model, dims = ?rec.dims, created = existing.is_none(), "embedding_space_declared");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::EmbeddingSpaceDeclared, "gateway", &format!("embedding_space:{}", rec.space))
            .details(json!({"space": rec.space, "model": rec.model, "dims": rec.dims, "created": existing.is_none()})),
    ).await;
    Ok(Json(json!({"ok": true, "space": rec.space, "model": rec.model, "dims": rec.dims, "created": existing.is_none()})))
}

/// DELETE /api/cluster/embedding-spaces/{space} — forget a space. The
/// default space cannot be removed: every unqualified embed means it.
async fn embedding_space_delete(
    State(state): State<Arc<AppState>>,
    Path(space): Path<String>,
) -> AppResult {
    use crate::embedding_spaces as es;
    let space = space.trim().to_ascii_lowercase();
    if crate::embedding_spaces::load(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("embedding spaces read: {e}")))?
        .iter()
        .any(|s| s.space == space && s.migration.is_some())
    {
        return Err(AppError::Conflict(format!(
            "cancel the migration first: noo cluster embedding-space migrate {space} --cancel"
        )));
    }
    if space == es::DEFAULT_SPACE {
        return Err(AppError::Conflict(format!("'{space}' is the default embedding space; every unqualified embed uses it")));
    }
    if !es::delete(&state.db, &space).await.map_err(|e| AppError::Internal(format!("embedding space delete: {e}")))? {
        return Err(AppError::NotFound(format!("no embedding space '{space}'")));
    }
    if let Ok(all) = es::load(&state.db).await {
        es::set_cache(all);
    }
    tracing::info!(space = %space, "embedding_space_removed");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::EmbeddingSpaceRemoved, "gateway", &format!("embedding_space:{space}"))
            .details(json!({"space": space})),
    ).await;
    Ok(Json(json!({"ok": true, "space": space})))
}

#[derive(Debug, Deserialize)]
pub(crate) struct EmbeddingMigrationBody {
    model: String,
}

/// Reload the cache after a migration write, so this gateway answers from
/// the new state at once instead of in up to 15 s.
async fn refresh_embedding_spaces(state: &AppState) {
    if let Ok(all) = crate::embedding_spaces::load(&state.db).await {
        crate::embedding_spaces::set_cache(all);
    }
}

/// POST /api/cluster/embedding-spaces/{space}/migration `{model}` -- start
/// re-embedding a space into another model (i150). The gateway PROBES the
/// new model (one short text across the mesh nodes declaring it, its own
/// balancer, no static endpoints); the answer's width must equal the
/// space's, because trellion's `vector(N)` columns are fixed. 409 on a
/// running migration, a model another space has, or a different width. When
/// no node serves the model yet: 202 and the migration waits as `pending`.
async fn embedding_space_migration_start(
    State(state): State<Arc<AppState>>,
    Path(space): Path<String>,
    Json(body): Json<EmbeddingMigrationBody>,
) -> Result<(axum::http::StatusCode, Json<Value>), AppError> {
    use crate::embedding_spaces as es;
    let space = space.trim().to_ascii_lowercase();
    let model = body.model.trim().to_string();
    crate::coordinator::classes::valid_model(&model).map_err(AppError::BadRequest)?;
    let spaces = es::load(&state.db).await.map_err(|e| AppError::Internal(format!("embedding spaces read: {e}")))?;
    if let Some(why) = es::start_refusal(&spaces, &space, &model) {
        return Err(AppError::Conflict(why));
    }
    let want = spaces.iter().find(|s| s.space == space).and_then(|s| s.dims);
    // Nothing serving the model yet is not a refusal: the migration waits as
    // `pending` and starts itself when a node does (`advance_pending`).
    let next_dims = match es::probe_decision(want, es::probe_width(&state, &model).await) {
        es::ProbeDecision::Filling { next_dims } => Some(next_dims),
        es::ProbeDecision::Pending => None,
        es::ProbeDecision::WrongWidth(why) => return Err(AppError::Conflict(why)),
    };
    if !es::start_migration(&state.db, &space, &model, next_dims).await.map_err(|e| AppError::Internal(format!("migration write: {e}")))? {
        return Err(AppError::Conflict(format!("space '{space}' started another migration first")));
    }
    refresh_embedding_spaces(&state).await;
    let st = if next_dims.is_some() { es::MIGRATION_FILLING } else { es::MIGRATION_PENDING };
    tracing::info!(space = %space, next_model = %model, next_dims = ?next_dims, state = st, "embedding_migration_started");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::EmbeddingMigrationStarted, "gateway", &format!("embedding_space:{space}"))
            .details(json!({"space": space, "next_model": model, "next_dims": next_dims, "state": st})),
    ).await;
    if next_dims.is_some() {
        return Ok((axum::http::StatusCode::OK, Json(json!({"ok": true, "space": space, "next_model": model, "next_dims": next_dims, "state": st}))));
    }
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(json!({
            "ok": true, "space": space, "next_model": model, "next_dims": null, "state": st,
            "message": format!(
                "no node serves '{model}' yet; the migration is pending and starts on its own once one does: \
                 noo cluster place <node> ollama {model} --role embed"
            ),
        })),
    ))
}

/// POST /api/cluster/embedding-spaces/{space}/migration/complete -- the
/// operator's go: refused unless trellion reported (fresh, about this model)
/// every table fully re-embedded. Moves the migration to `cutover`; trellion
/// swaps its columns and its `cutover_done` report flips the space's model.
async fn embedding_space_migration_complete(
    State(state): State<Arc<AppState>>,
    Path(space): Path<String>,
) -> AppResult {
    use crate::embedding_spaces as es;
    let space = space.trim().to_ascii_lowercase();
    let spaces = es::load(&state.db).await.map_err(|e| AppError::Internal(format!("embedding spaces read: {e}")))?;
    let Some(s) = spaces.iter().find(|s| s.space == space) else {
        return Err(AppError::NotFound(format!("no embedding space '{space}'")));
    };
    if let Some(why) = es::complete_refusal(s, chrono::Utc::now()) {
        return Err(AppError::Conflict(why));
    }
    let next = s.migration.as_ref().map(|m| m.next_model.clone()).unwrap_or_default();
    if !es::begin_cutover(&state.db, &space, &next).await.map_err(|e| AppError::Internal(format!("migration write: {e}")))? {
        return Err(AppError::Conflict(format!("space '{space}' changed under this request; retry")));
    }
    refresh_embedding_spaces(&state).await;
    tracing::info!(space = %space, next_model = %next, "embedding_migration_cutover");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::EmbeddingMigrationCutover, "gateway", &format!("embedding_space:{space}"))
            .details(json!({"space": space, "next_model": next})),
    ).await;
    Ok(Json(json!({"ok": true, "space": space, "next_model": next, "state": es::MIGRATION_CUTOVER})))
}

/// DELETE /api/cluster/embedding-spaces/{space}/migration -- cancel while
/// filling. Once the cutover has begun trellion is swapping columns, so the
/// model must follow: 409.
async fn embedding_space_migration_cancel(
    State(state): State<Arc<AppState>>,
    Path(space): Path<String>,
) -> AppResult {
    use crate::embedding_spaces as es;
    let space = space.trim().to_ascii_lowercase();
    let spaces = es::load(&state.db).await.map_err(|e| AppError::Internal(format!("embedding spaces read: {e}")))?;
    match spaces.iter().find(|s| s.space == space).map(|s| s.migration.as_ref().map(|m| m.state.clone())) {
        None => return Err(AppError::NotFound(format!("no embedding space '{space}'"))),
        Some(None) => return Err(AppError::NotFound(format!("space '{space}' has no migration"))),
        Some(Some(st)) if st == es::MIGRATION_CUTOVER => {
            return Err(AppError::Conflict(format!("space '{space}': the swap is under way and cannot be cancelled; it finishes when trellion reports cutover_done")));
        }
        Some(Some(_)) => {}
    }
    if !es::cancel_migration(&state.db, &space).await.map_err(|e| AppError::Internal(format!("migration write: {e}")))? {
        return Err(AppError::Conflict(format!("space '{space}' changed under this request; retry")));
    }
    refresh_embedding_spaces(&state).await;
    tracing::info!(space = %space, "embedding_migration_cancelled");
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::EmbeddingMigrationCancelled, "gateway", &format!("embedding_space:{space}"))
            .details(json!({"space": space})),
    ).await;
    Ok(Json(json!({"ok": true, "space": space})))
}

// ═══════════════════════════════════════════════════════════════════
// Agentic mesh ops — mint-join-key / replication-status /
// suggest-placement / discover / propose / enroll_now
// [ported from workers/cluster.py 2026-07-18]
// ═══════════════════════════════════════════════════════════════════

/// Current Unix time as float seconds (matches Python `time.time()`).
fn unix_now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Resolve a Tailscale API bearer for gateway-side calls. Prefers the
/// OAuth client (scoped keys+acl, non-expiring secret — a fresh
/// short-lived token is minted per call), falls back to the legacy API
/// key. Mirrors noo-cli's `tailscale_api_key()` resolution.
/// Resolve a Tailscale API bearer, or say precisely WHY there is none
/// (finding #53): the old `-> String` conflated "no client configured"
/// with "the configured client's token exchange FAILED" — a deleted or
/// secret-rotated OAuth client produced "No Tailscale credential" hours
/// after the same process had minted keys with it, sending the operator
/// to check a secret store that was configured fine.
async fn tailscale_bearer() -> Result<String, String> {
    let id = std::env::var("NOO_TAILSCALE_OAUTH_CLIENT_ID").unwrap_or_default().trim().to_string();
    let secret = crate::config::secret_env::secret_or_empty("NOO_TAILSCALE_OAUTH_CLIENT_SECRET").trim().to_string();
    let mut mint_err: Option<String> = None;
    if !id.is_empty() && !secret.is_empty() {
        let client = crate::tls::external_client();
        let resp = client
            .post("https://api.tailscale.com/api/v2/oauth/token")
            .form(&[
                ("client_id", id.as_str()),
                ("client_secret", secret.as_str()),
                ("grant_type", "client_credentials"),
            ])
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                if let Ok(v) = r.json::<Value>().await {
                    if let Some(tok) = v.get("access_token").and_then(|t| t.as_str()) {
                        return Ok(tok.to_string());
                    }
                }
                mint_err = Some("token response carried no access_token".into());
            }
            Ok(r) => mint_err = Some(format!("token exchange failed (HTTP {})", r.status())),
            Err(e) => mint_err = Some(format!("token exchange transport error: {e}")),
        }
        tracing::warn!(error = mint_err.as_deref().unwrap_or(""),
            "tailscale oauth token mint failed — falling back to API key");
    }
    let key = crate::config::secret_env::secret_or_empty("NOO_TAILSCALE_API_KEY").trim().to_string();
    if !key.is_empty() {
        return Ok(key);
    }
    Err(match mint_err {
        Some(m) => format!(
            "Tailscale OAuth client is configured but unusable — {m}. The client \
             may have been deleted or its secret rotated in the console: mint a \
             new client, re-store NOO_TAILSCALE_OAUTH_CLIENT_ID/_SECRET \
             (`sops secrets/env.sops`), then restart the gateway."),
        None =>
            "No Tailscale credential — store an OAuth client \
             (NOO_TAILSCALE_OAUTH_CLIENT_ID/_SECRET, preferred: scoped, \
             non-expiring) or NOO_TAILSCALE_API_KEY in the secret store \
             (`sops secrets/env.sops`), then restart the gateway. Never \
             put credentials in .env.".into(),
    })
}

/// Mint one pre-authorized Tailscale auth key carrying `tag`. Shared by
/// `POST /api/cluster/mint-join-key` and the bootstrap-token mint (which puts
/// the key in the enrollment blob), so the two cannot drift on the payload
/// Tailscale accepts.
pub(crate) async fn mint_tailscale_auth_key(
    tag: &str,
    expiry_minutes: i64,
    reusable: bool,
) -> Result<String, String> {
    let api_key = tailscale_bearer().await?;
    let tailnet = tailnet_api_name();

    // Same payload as the retired Python tailscale module's _key_payload (Tailscale rejects
    // punctuation like ():/ in descriptions).
    let payload = json!({
        "capabilities": {"devices": {"create": {
            "reusable": reusable,
            "ephemeral": false,
            "preauthorized": true,
            "tags": [tag],
        }}},
        "expirySeconds": expiry_minutes * 60,
        "description": format!("noo-join-{}", tag.replace(':', "-")),
    });

    let client = crate::tls::external_client();
    let resp = client
        .post(format!("https://api.tailscale.com/api/v2/tailnet/{tailnet}/keys"))
        .basic_auth(&api_key, Some(""))
        .json(&payload)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("mint failed: {e}"))?;

    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if status != 200 {
        let hint = if text.to_lowercase().contains("tag") {
            format!(" (is '{tag}' declared under tagOwners in the tailnet ACL policy?)")
        } else {
            String::new()
        };
        let snippet: String = text.chars().take(300).collect();
        return Err(format!("Tailscale API {status}: {snippet}{hint}"));
    }
    let auth_key = serde_json::from_str::<Value>(&text).ok()
        .and_then(|v| v.get("key").and_then(|k| k.as_str()).map(String::from))
        .unwrap_or_default();
    if auth_key.is_empty() {
        let snippet: String = text.chars().take(200).collect();
        return Err(format!("Tailscale API returned no key: {snippet}"));
    }

    Ok(auth_key)
}

/// POST /api/cluster/mint-join-key — mint a Tailscale enrollment key.
/// [ported from workers/cluster.py::_cluster_mint_join_key 2026-07-18]
///
/// Agentic surface for remote-node enrollment: the coordinator can hand a
/// user the bootstrap one-liner from chat. Minting grants mesh admission
/// (HIGH risk at the tool layer), but defense in depth holds: the key is
/// single-use + short-expiry by default, the joining node is ACL-clamped
/// by its tag from the first packet, and it still needs an operator-run
/// `noo cluster provision` to be provisioned into the cluster.
///
/// The key is minted BY (and verified by) the Tailscale control plane —
/// there is no local join-key verifier.
///
/// The response is the key and its parameters only. The `one_liner` /
/// `script_url` fields that composed the retired bootstrap-node.sh lane were
/// dropped with the Python CLI, their last reader; use the invite /
/// bootstrap-token flows to enroll a node.
async fn mint_join_key(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));

    let tag = body.get("tag").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("tag:worker")
        .to_string();
    // Python: min(int(body.get("expiry_minutes") or 60), 24 * 60)
    let expiry_minutes = body.get("expiry_minutes").and_then(|v| v.as_i64())
        .filter(|n| *n != 0)
        .unwrap_or(60)
        .min(24 * 60);
    let reusable = body.get("reusable").and_then(|v| v.as_bool()).unwrap_or(false);

    let auth_key = mint_tailscale_auth_key(&tag, expiry_minutes, reusable)
        .await
        .map_err(AppError::Internal)?;

    // Audit the mint. Python appended to the self-modify JSONL file
    // (workers/admin.py::_audit_log {action, tag, reusable, expiry_minutes,
    // result}); the Rust-side convention is the noo_security_audit table.
    let actor = ctx.as_ref().map(|axum::Extension(r)| r.sub.clone())
        .unwrap_or_else(|| "gateway".into());
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::MintJoinKey, &actor, "cluster:tailscale")
            .details(json!({"tag": tag, "reusable": reusable, "expiry_minutes": expiry_minutes})),
    ).await;

    Ok(Json(json!({
        "auth_key": auth_key,
        "tag": tag,
        "expiry_minutes": expiry_minutes,
        "reusable": reusable,
        "next_step": "enroll the node with `noo cluster invite` (or a bootstrap \
token), then `noo cluster provision <node-name> --wait` on the controller",
    })))
}

/// POST /api/cluster/delete-tailscale-device — remove a node's device from
/// the tailnet (teardown's "still yours: delete the tailscale device" step,
/// automated 2026-08-19).
///
/// The teardown-node CLI holds the node's tailnet IP (inventory ansible_host
/// is the 100.x address), so it posts `{"ip": "100.x"}`. We resolve that to a
/// device id via the tailnet device list, then DELETE it. Matching by IP —
/// NOT by name — is deliberate: a node's PAI name (e.g. host5) is ADOPTED
/// and decoupled from its tailscale hostname (e.g. host4), so a
/// name-match would silently delete nothing. `hostname` is offered as a
/// secondary key for callers that only know the machine name.
///
/// Credential is `tailscale_bearer()` — the SAME auth abstraction as
/// mint_join_key, so this endpoint is identical whether the gateway runs on
/// an OAuth client (preferred) or a personal API key. Requires the tailnet
/// credential to carry the `devices` write scope (OAuth) / be an admin key.
/// The tailnet name the Tailscale API is addressed with (`-` = the
/// credential's own tailnet).
fn tailnet_api_name() -> String {
    let t = std::env::var("NOO_TAILSCALE_TAILNET").unwrap_or_default().trim().to_string();
    if t.is_empty() { "-".to_string() } else { t }
}

/// Every device on the tailnet, as the Tailscale API lists them.
async fn list_tailnet_devices(bearer: &str) -> Result<Vec<Value>, String> {
    let list = crate::tls::external_client()
        .get(format!("https://api.tailscale.com/api/v2/tailnet/{}/devices", tailnet_api_name()))
        .basic_auth(bearer, Some(""))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("device list failed: {e}"))?;
    let status = list.status().as_u16();
    let text = list.text().await.unwrap_or_default();
    if status != 200 {
        let snippet: String = text.chars().take(300).collect();
        return Err(format!("Tailscale API {status}: {snippet}"));
    }
    Ok(serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.get("devices").and_then(|d| d.as_array()).cloned())
        .unwrap_or_default())
}

/// Delete stale device records that carry `hostname`, returning their names.
///
/// A node re-enrolled under a name the tailnet still holds a record for
/// lands as `<name>-1`, and every address, ACL target and `cluster status`
/// row then disagrees about what it is called. The CLI has cleared these
/// before minting a key since the pull rail landed; the console minted
/// through the gateway and could not, so a node re-added from it came up
/// renamed. Only records not seen for `max_age` go: a live device with the
/// same hostname is left alone, and the enrolment then fails visibly
/// instead of quietly deleting a running node's identity.
pub(crate) async fn clear_stale_tailnet_devices(
    hostname: &str,
    max_age: std::time::Duration,
) -> Result<Vec<String>, String> {
    let bearer = tailscale_bearer().await?;
    let devices = list_tailnet_devices(&bearer).await?;
    let now = chrono::Utc::now();
    let want = hostname.to_lowercase();
    let mut removed = Vec::new();
    for dev in devices {
        let dh = dev.get("hostname").and_then(|h| h.as_str()).unwrap_or("").to_lowercase();
        let dn_leaf = dev.get("name").and_then(|n| n.as_str()).unwrap_or("")
            .split('.').next().unwrap_or("").to_lowercase();
        if dh != want && dn_leaf != want {
            continue;
        }
        let seen = dev.get("lastSeen").and_then(|v| v.as_str())
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&chrono::Utc));
        let stale = match seen {
            Some(t) => now.signed_duration_since(t).to_std().map(|d| d >= max_age).unwrap_or(false),
            None => false, // never seen = mid-join; not ours to remove
        };
        if !stale {
            continue;
        }
        let Some(id) = dev.get("id").and_then(|i| i.as_str()).filter(|s| !s.is_empty()) else { continue };
        let name = dev.get("name").and_then(|n| n.as_str()).unwrap_or(hostname).to_string();
        let del = crate::tls::external_client()
            .delete(format!("https://api.tailscale.com/api/v2/device/{id}"))
            .basic_auth(&bearer, Some(""))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| format!("device delete failed: {e}"))?;
        let st = del.status().as_u16();
        if st != 200 && st != 204 {
            let hint = if st == 403 { " (does the credential carry the `devices` write scope?)" } else { "" };
            return Err(format!("delete of stale record {name}: Tailscale API {st}{hint}"));
        }
        removed.push(name);
    }
    Ok(removed)
}

async fn delete_tailscale_device(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let ip = body.get("ip").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let hostname = body.get("hostname").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if ip.is_empty() && hostname.is_empty() {
        return Err(AppError::BadRequest("provide `ip` (preferred) or `hostname`".into()));
    }

    let bearer = tailscale_bearer().await.map_err(AppError::Internal)?;
    let client = crate::tls::external_client();
    // 1. List devices, find the one whose addresses include `ip` (or whose
    //    hostname matches). The list carries id/name/hostname/addresses.
    let devices = list_tailnet_devices(&bearer).await.map_err(AppError::Internal)?;

    let hostname_l = hostname.to_lowercase();
    let matched = devices.iter().find(|d| {
        if !ip.is_empty() {
            if let Some(addrs) = d.get("addresses").and_then(|a| a.as_array()) {
                if addrs.iter().any(|a| a.as_str() == Some(ip.as_str())) {
                    return true;
                }
            }
        }
        if !hostname_l.is_empty() {
            let dh = d.get("hostname").and_then(|h| h.as_str()).unwrap_or("").to_lowercase();
            // device `name` is the FQDN (host.tailnet.ts.net); match its leaf too.
            let dn = d.get("name").and_then(|n| n.as_str()).unwrap_or("").to_lowercase();
            let dn_leaf = dn.split('.').next().unwrap_or("");
            if dh == hostname_l || dn_leaf == hostname_l {
                return true;
            }
        }
        false
    });

    let Some(dev) = matched else {
        // Idempotent: a device already gone (or never joined) is success for
        // teardown's purposes — nothing left to clean.
        return Ok(Json(json!({
            "status": "not_found",
            "ip": ip, "hostname": hostname,
            "note": "no matching tailnet device — already removed or never joined",
        })));
    };
    let dev_id = dev.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
    let dev_name = dev.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
    if dev_id.is_empty() {
        return Err(AppError::Internal("matched device has no id".into()));
    }

    // 2. Delete it.
    let del = client
        .delete(format!("https://api.tailscale.com/api/v2/device/{dev_id}"))
        .basic_auth(&bearer, Some(""))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("device delete failed: {e}")))?;
    let dstatus = del.status().as_u16();
    if dstatus != 200 && dstatus != 204 {
        let dtext = del.text().await.unwrap_or_default();
        let snippet: String = dtext.chars().take(300).collect();
        let hint = if dstatus == 403 {
            " (does the credential carry the `devices` write scope?)"
        } else { "" };
        return Err(AppError::Internal(format!("Tailscale API {dstatus}: {snippet}{hint}")));
    }

    let actor = ctx.as_ref().map(|axum::Extension(r)| r.sub.clone())
        .unwrap_or_else(|| "gateway".into());
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::DeleteTailscaleDevice, &actor, "cluster:tailscale")
            .details(json!({"device_id": dev_id, "device_name": dev_name, "ip": ip, "hostname": hostname})),
    ).await;

    Ok(Json(json!({
        "status": "deleted",
        "device_id": dev_id,
        "device_name": dev_name,
        "ip": ip, "hostname": hostname,
    })))
}

/// GET /api/cluster/replication-status — Postgres replication view.
/// [ported from workers/cluster.py::_cluster_replication_status 2026-07-18]
///
/// Primary: connected standbys + slot WAL retention (a dead standby's
/// slot silently retains WAL — this is where you see it). Standby:
/// wal receiver state. Feeds the future replication_health autonomy
/// location and the standby runbook.
async fn replication_status(State(state): State<Arc<AppState>>) -> AppResult {
    let db_err = |e: sqlx::Error| AppError::Internal(format!("replication query failed: {e}"));

    let in_recovery: bool = sqlx::query_scalar("SELECT pg_is_in_recovery()")
        .fetch_one(&state.db)
        .await
        .map_err(db_err)?;

    let mut out = serde_json::Map::new();
    out.insert("role".into(), json!(if in_recovery { "standby" } else { "primary" }));

    if in_recovery {
        let rows: Vec<(Option<String>, Option<String>, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT status, sender_host, received_lsn::text AS received_lsn, \
                 last_msg_receipt_time::text AS last_msg_receipt_time \
                 FROM pg_stat_wal_receiver"
            )
            .fetch_all(&state.db)
            .await
            .map_err(db_err)?;
        let receivers: Vec<Value> = rows.into_iter()
            .map(|(status, sender_host, received_lsn, last_msg_receipt_time)| json!({
                "status": status,
                "sender_host": sender_host,
                "received_lsn": received_lsn,
                "last_msg_receipt_time": last_msg_receipt_time,
            }))
            .collect();
        out.insert("wal_receiver".into(), json!(receivers));
    } else {
        let rows: Vec<(Option<String>, Option<String>, Option<String>,
                       Option<String>, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT application_name, client_addr::text AS client_addr, state, \
                 sent_lsn::text AS sent_lsn, replay_lsn::text AS replay_lsn, \
                 replay_lag::text AS replay_lag FROM pg_stat_replication"
            )
            .fetch_all(&state.db)
            .await
            .map_err(db_err)?;
        let standbys: Vec<Value> = rows.into_iter()
            .map(|(application_name, client_addr, st, sent_lsn, replay_lsn, replay_lag)| json!({
                "application_name": application_name,
                "client_addr": client_addr,
                "state": st,
                "sent_lsn": sent_lsn,
                "replay_lsn": replay_lsn,
                "replay_lag": replay_lag,
            }))
            .collect();
        out.insert("standbys".into(), json!(standbys));

        let slot_rows: Vec<(Option<String>, Option<bool>, Option<String>)> =
            sqlx::query_as(
                "SELECT slot_name, active, \
                 pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) \
                 AS retained_wal FROM pg_replication_slots"
            )
            .fetch_all(&state.db)
            .await
            .map_err(db_err)?;
        let slots: Vec<Value> = slot_rows.into_iter()
            .map(|(slot_name, active, retained_wal)| json!({
                "slot_name": slot_name,
                "active": active,
                "retained_wal": retained_wal,
            }))
            .collect();
        out.insert("slots".into(), json!(slots));
    }

    Ok(Json(Value::Object(out)))
}

// ── Capability-based placement advisory (pure logic) ────────────────
// [ported from cluster/placement.py 2026-07-18 — same Backend Selection
// Matrix; hardware, not config, is authority.]

/// Default VRAM (GB) at/above which a CUDA node is vLLM-worthy.
const VLLM_MIN_VRAM_GB: f64 = 10.0;

#[derive(Deserialize)]
#[serde(default)]
struct CapabilityManifest {
    os: String,
    #[allow(dead_code)]
    arch: String,
    gpu_api: String,
    gpu_model: String,
    vram_gb: f64,
    unified_memory: bool,
    can_gpu_passthrough: bool,
    #[allow(dead_code)]
    ram_gb: f64,
    #[allow(dead_code)]
    cpu_cores: i64,
    #[allow(dead_code)]
    container_runtime: String,
}

impl Default for CapabilityManifest {
    fn default() -> Self {
        Self {
            os: "linux".into(),
            arch: "amd64".into(),
            gpu_api: "none".into(),
            gpu_model: String::new(),
            vram_gb: 0.0,
            unified_memory: false,
            can_gpu_passthrough: true,
            ram_gb: 0.0,
            cpu_cores: 0,
            container_runtime: "docker".into(),
        }
    }
}

struct BackendPlan {
    backend: String,
    launch_mode: String,
    reason: String,
    warnings: Vec<String>,
    viable: bool,
}

/// Python `f"{x:g}"` — trims the trailing `.0` on whole floats.
fn fmt_g(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// Map a manifest to a backend plan via the Backend Selection Matrix.
/// [ported from cluster/placement.py::plan_placement 2026-07-18]
fn plan_placement(m: &CapabilityManifest, override_backend: Option<&str>) -> BackendPlan {
    let api = if m.gpu_api.is_empty() { "none".to_string() } else { m.gpu_api.to_lowercase() };
    let osname = if m.os.is_empty() { "linux".to_string() } else { m.os.to_lowercase() };

    // Native Windows: not a runnable node — steer to WSL2.
    if osname == "windows" {
        let plan = BackendPlan {
            backend: "none".into(), launch_mode: "container".into(), viable: false,
            reason: "native Windows has no supported inference backend".into(),
            warnings: vec!["run the node under WSL2 (a first-class Linux node with \
CUDA passthrough) instead of native Windows".into()],
        };
        return apply_override(plan, override_backend, m, &api);
    }

    // macOS: Metal only via a NATIVE process (Docker can't pass it).
    if osname == "darwin" {
        let mut plan = if api == "metal" && !m.can_gpu_passthrough {
            BackendPlan {
                backend: "ollama".into(), launch_mode: "native".into(), viable: true,
                reason: "Apple Silicon / Metal — Ollama run as a native host \
process (Docker-for-Mac can't pass the GPU through)".into(),
                warnings: if m.unified_memory {
                    vec!["unified memory: size models against shared RAM, \
not discrete VRAM".into()]
                } else { vec![] },
            }
        } else {
            BackendPlan {
                backend: "ollama".into(), launch_mode: "native".into(), viable: true,
                reason: "macOS without usable GPU passthrough — Ollama (CPU) \
as a native host process".into(),
                warnings: vec![],
            }
        };
        if api != "metal" && api != "none" {
            plan.warnings.push(format!("unexpected gpu_api='{api}' on darwin"));
        }
        return apply_override(plan, override_backend, m, &api);
    }

    // Linux (and WSL2, which presents as linux).
    if osname == "linux" {
        let plan = if api == "cuda" {
            if m.vram_gb >= VLLM_MIN_VRAM_GB {
                BackendPlan {
                    backend: "vllm".into(), launch_mode: "container".into(), viable: true,
                    reason: format!("Linux + CUDA + {}GB VRAM (>= {}) — vLLM",
                                    fmt_g(m.vram_gb), fmt_g(VLLM_MIN_VRAM_GB)),
                    warnings: vec![],
                }
            } else {
                BackendPlan {
                    backend: "llamacpp".into(), launch_mode: "container".into(), viable: true,
                    reason: format!("Linux + CUDA + {}GB VRAM (< {}) — llama.cpp GPU build",
                                    fmt_g(m.vram_gb), fmt_g(VLLM_MIN_VRAM_GB)),
                    warnings: vec![],
                }
            }
        } else if api == "rocm" {
            BackendPlan {
                backend: "llamacpp".into(), launch_mode: "container".into(), viable: true,
                reason: "Linux + AMD/ROCm — llama.cpp (ROCm build)".into(),
                warnings: vec!["vLLM-ROCm not wired yet; llama.cpp is the ROCm path".into()],
            }
        } else if api == "vulkan" || api == "metal" {
            BackendPlan {
                backend: "llamacpp".into(), launch_mode: "container".into(), viable: true,
                reason: format!("Linux + {api} — llama.cpp"),
                warnings: vec![format!("{api} on Linux is untested in this fleet")],
            }
        } else {
            BackendPlan {
                backend: "llamacpp".into(), launch_mode: "container".into(), viable: true,
                reason: "Linux, no GPU — llama.cpp (CPU/OpenBLAS)".into(),
                warnings: vec![],
            }
        };
        return apply_override(plan, override_backend, m, &api);
    }

    // Unknown OS.
    let plan = BackendPlan {
        backend: "llamacpp".into(), launch_mode: "container".into(), viable: true,
        reason: format!("unknown os='{osname}' — defaulting to llama.cpp (CPU)"),
        warnings: vec![format!("unrecognized os '{osname}'; treated as generic CPU node")],
    };
    apply_override(plan, override_backend, m, &api)
}

/// Honor an operator override, but keep a warning when it contradicts
/// the hardware. [ported from cluster/placement.py::_apply_override]
fn apply_override(
    plan: BackendPlan,
    override_backend: Option<&str>,
    m: &CapabilityManifest,
    api: &str,
) -> BackendPlan {
    let ov = match override_backend.filter(|s| !s.is_empty()) {
        Some(o) => o,
        None => return plan,
    };
    let mut warn: Vec<String> = Vec::new();
    if ov == "vllm" && api != "cuda" {
        warn.push(format!("override=vllm but gpu_api='{api}' (vLLM needs CUDA — \
it will likely fail to start on this node)"));
    }
    if matches!(ov, "vllm" | "llamacpp" | "tgi" | "sglang") && m.os == "darwin" {
        warn.push(format!("override={ov} on macOS runs in Docker (CPU-only — \
no Metal); Ollama-native is the GPU path"));
    }
    let mut warnings = plan.warnings;
    warnings.extend(warn);
    BackendPlan {
        backend: ov.to_string(),
        launch_mode: if m.os == "darwin" && ov == "ollama" { "native".into() }
                     else { "container".into() },
        reason: format!("operator override → {ov} (auto-plan was: {})", plan.backend),
        warnings,
        viable: plan.viable || ov != "none",
    }
}

/// POST /api/cluster/suggest-placement — read-only placement advisory.
/// [ported from workers/cluster.py::_suggest_placement +
/// cluster/placement.py::suggest_placement 2026-07-18]
///
/// Body: a capability manifest (os, arch, gpu_api, vram_gb,
/// unified_memory, can_gpu_passthrough, …) — either nested under
/// `manifest` or at the top level — and optional `override_backend`.
/// Returns the recommended backend + launch mode + reason, plus what is
/// NOT viable on this hardware (e.g. vLLM without CUDA). Never mutates
/// cluster state — it's guidance for the coordinator / autonomy.
///
/// With `node_id` (and optionally `with: {backend, model, role, env}`) the
/// answer also carries `fit`: the same memory-fit verdict `noo cluster fit`
/// and the placement route use ([`crate::placement_fit`]), so a suggestion
/// never recommends what a place would refuse.
async fn suggest_placement(State(state): State<Arc<AppState>>, body: Option<Json<Value>>) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let manifest_src = body.get("manifest").cloned()
        .filter(|v| !v.is_null())
        .unwrap_or_else(|| body.clone());
    let manifest: CapabilityManifest = serde_json::from_value(manifest_src)
        .map_err(|e| AppError::BadRequest(format!("invalid manifest: {e}")))?;
    let override_backend = body.get("override_backend").and_then(|v| v.as_str());

    let api = if manifest.gpu_api.is_empty() { "none".to_string() }
              else { manifest.gpu_api.to_lowercase() };
    let plan = plan_placement(&manifest, override_backend);

    let mut not_viable: Vec<String> = Vec::new();
    if api != "cuda" {
        not_viable.push("vllm (requires an NVIDIA CUDA GPU)".into());
    }
    if manifest.os == "darwin" && !manifest.can_gpu_passthrough {
        not_viable.push("any containerized GPU backend (Docker-for-Mac \
can't pass the Metal GPU through — GPU needs a \
native process)".into());
    }

    let fit = match body.get("node_id").and_then(|v| v.as_str()) {
        Some(node_id) => {
            let existing = stored_placements(&state, node_id).await?;
            let proposed = match body.get("with").filter(|w| w.is_object()) {
                Some(w) => {
                    let backend = w["backend"].as_str().unwrap_or(&plan.backend).to_string();
                    let role = resolve_role(&backend, w["role"].as_str()).map_err(AppError::BadRequest)?;
                    let mine = existing.iter().find(|e| same_placement_slot(e, &backend, &role, w["model"].as_str()));
                    let (model, env) = effective_after_upsert(mine, w["model"].as_str(), w.get("env").filter(|e| e.is_object()));
                    let target = effective_target_after_upsert(mine, w["model"].as_str(), w["target"].as_str());
                    Some(StoredPlacement { backend, role, model, env, desired_state: "running".into(), target })
                }
                None => None,
            };
            let node = node_fit_facts(&state, node_id).await;
            let replacing = proposed.as_ref().map(|p| (p.backend.clone(), p.role.clone(), p.model.clone()));
            Some(crate::placement_fit::evaluate(
                &node,
                &fit_specs(&existing, replacing.as_ref().map(|(b, r, m)| (b.as_str(), r.as_str(), m.as_deref())), proposed.as_ref()),
                crate::embedding_client::EMBED_NUM_CTX,
            ).to_json())
        }
        None => None,
    };

    Ok(Json(json!({
        "fit": fit,
        "recommended": {
            "backend": plan.backend,
            "launch_mode": plan.launch_mode,
            "reason": plan.reason,
            "warnings": plan.warnings,
            "viable": plan.viable,
        },
        "not_viable": not_viable,
        "manifest": {
            "os": manifest.os,
            "arch": manifest.arch,
            "gpu_api": api,
            "gpu_model": manifest.gpu_model,
            "vram_gb": manifest.vram_gb,
            "unified_memory": manifest.unified_memory,
            "can_gpu_passthrough": manifest.can_gpu_passthrough,
        },
    })))
}

// ── Cluster inventory (read-only) ───────────────────────────────────
// [ported from cluster/inventory.py 2026-07-18 — YAML file at
// $NOO_CLUSTER_INVENTORY or $XDG_CONFIG_HOME/noo/cluster-inventory.yaml]

#[derive(Clone, Debug)]
struct TrustedHost {
    host: Option<String>,
    subnet: Option<String>,
    user: String,
    role: String,
    notes: String,
}

struct ClusterInventory {
    path: std::path::PathBuf,
    hosts: Vec<TrustedHost>,
}

fn expand_tilde(p: &str) -> std::path::PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::Path::new(&home).join(rest);
        }
    }
    std::path::PathBuf::from(p)
}

/// Resolve the inventory file path with override + XDG fallback.
/// The env-var path is honored only if its parent directory exists (or
/// can be created) — protects against a container-internal path (e.g.
/// /data/config/…) leaking into an environment that has no /data.
fn inventory_file_path() -> std::path::PathBuf {
    let explicit = std::env::var("NOO_CLUSTER_INVENTORY").unwrap_or_default();
    let explicit = explicit.trim();
    if !explicit.is_empty() {
        let p = expand_tilde(explicit);
        if let Some(parent) = p.parent() {
            if parent.exists() || std::fs::create_dir_all(parent).is_ok() {
                return p;
            }
        }
    }
    let base = std::env::var("XDG_CONFIG_HOME").ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            format!("{}/.config", std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
        });
    std::path::Path::new(&base).join("noo").join("cluster-inventory.yaml")
}

/// Read + parse the inventory file. Returns an empty inventory when the
/// file is missing or malformed — that's a valid state, not an error.
fn load_cluster_inventory(override_path: Option<&str>) -> ClusterInventory {
    let path = match override_path.filter(|s| !s.is_empty()) {
        Some(p) => expand_tilde(p),
        None => inventory_file_path(),
    };
    let mut hosts: Vec<TrustedHost> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(raw) = serde_yaml::from_str::<Value>(&text) {
            if let Some(rows) = raw.get("trusted_hosts").and_then(|v| v.as_array()) {
                for row in rows {
                    let Some(obj) = row.as_object() else { continue };
                    hosts.push(TrustedHost {
                        host: obj.get("host").and_then(|v| v.as_str()).map(String::from),
                        subnet: obj.get("subnet").and_then(|v| v.as_str()).map(String::from),
                        user: obj.get("user").and_then(|v| v.as_str())
                            .unwrap_or("noo").to_string(),
                        role: obj.get("role").and_then(|v| v.as_str())
                            .unwrap_or("").to_string(),
                        notes: obj.get("notes").and_then(|v| v.as_str())
                            .unwrap_or("").to_string(),
                    });
                }
            }
        }
    }
    ClusterInventory { path, hosts }
}

impl ClusterInventory {
    /// Inventory entries with an explicit host (not subnet).
    fn trusted_concrete(&self) -> impl Iterator<Item = &TrustedHost> {
        self.hosts.iter().filter(|h| h.host.is_some() && h.subnet.is_none())
    }

    /// Inventory entries that are subnet ranges (for discovery scans).
    fn discovery_subnets(&self) -> impl Iterator<Item = &TrustedHost> {
        self.hosts.iter().filter(|h| h.subnet.is_some())
    }

    /// Look up a host. Matches concrete entries first, then any subnet
    /// that contains the host's IP (IPv4 only — see cidr helpers).
    fn find(&self, host: &str) -> Option<&TrustedHost> {
        for h in self.trusted_concrete() {
            if h.host.as_deref() == Some(host) {
                return Some(h);
            }
        }
        let ip: std::net::Ipv4Addr = host.parse().ok()?;
        self.discovery_subnets()
            .find(|entry| entry.subnet.as_deref()
                .map(|s| cidr_contains(s, ip)).unwrap_or(false))
    }
}

/// Parse an IPv4 CIDR (strict=false semantics: host bits are masked off).
/// Returns (network_u32, prefix). IPv6 is not supported (deviation from
/// Python's `ipaddress` — the fleet inventory is IPv4).
fn parse_ipv4_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr, prefix) = match cidr.split_once('/') {
        Some((a, p)) => (a.trim(), p.trim().parse::<u32>().ok()?),
        None => (cidr.trim(), 32),
    };
    if prefix > 32 {
        return None;
    }
    let ip: std::net::Ipv4Addr = addr.parse().ok()?;
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some((u32::from(ip) & mask, prefix))
}

fn cidr_contains(cidr: &str, ip: std::net::Ipv4Addr) -> bool {
    match parse_ipv4_cidr(cidr) {
        Some((network, prefix)) => {
            let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            (u32::from(ip) & mask) == network
        }
        None => false,
    }
}

/// Subnet expansion, bounded to /20 (4096 hosts). Mirrors Python
/// `ip_network(...).hosts()`: /31 + /32 yield every address, larger
/// nets exclude network + broadcast. Returns None for oversized or
/// unparseable ranges (they are skipped, matching Python).
fn expand_ipv4_cidr(cidr: &str) -> Option<Vec<String>> {
    const MAX_SUBNET_HOSTS: u64 = 4096; // /20
    let (network, prefix) = parse_ipv4_cidr(cidr)?;
    let size: u64 = 1u64 << (32 - prefix);
    if size > MAX_SUBNET_HOSTS {
        return None; // refuse huge ranges
    }
    let (start, end) = if prefix >= 31 {
        (network as u64, network as u64 + size)
    } else {
        (network as u64 + 1, network as u64 + size - 1)
    };
    Some((start..end)
        .map(|v| std::net::Ipv4Addr::from(v as u32).to_string())
        .collect())
}

/// TCP connect to host:22 with a short timeout. No auth attempted —
/// that would need credentials and would generate failed-login noise.
async fn probe_ssh(host: String) -> bool {
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            tokio::net::TcpStream::connect((host.as_str(), 22)),
        ).await,
        Ok(Ok(_))
    )
}

/// POST /api/cluster/discover
/// [ported from workers/cluster.py::_cluster_discover +
/// cluster/discovery.py::discover 2026-07-18]
///
/// Body (all optional):
///   subnet            CIDR for ad-hoc scan (in addition to inventory)
///   skip_unreachable  When true (default), omits non-reachable hosts
///                     unless they're in the inventory
///   inventory_path    Override inventory file location
///
/// Returns inventory_path, trusted_hosts (in inventory),
/// discovered_hosts (subnet scans), cluster_registered.
///
/// Hard cap at 30s (tokio timeout, same semantics as the Python
/// asyncio.wait_for): a /24 should finish in <5s; if probes are hanging
/// something deeper is wrong and we want to fail visibly.
async fn cluster_discover(
    State(state): State<Arc<AppState>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let subnet = body.get("subnet").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty()).map(String::from);
    let skip_unreachable = body.get("skip_unreachable")
        .and_then(|v| v.as_bool()).unwrap_or(true);
    let inventory_path = body.get("inventory_path").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty()).map(String::from);

    tracing::info!("cluster_discover.start");

    let work = async {
        let inv = load_cluster_inventory(inventory_path.as_deref());

        // Build the full candidate list: concrete inventory entries,
        // inventory subnet expansion, then the ad-hoc subnet.
        let mut candidates: Vec<TrustedHost> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for h in inv.trusted_concrete() {
            if let Some(ref host) = h.host {
                if !host.is_empty() && seen.insert(host.clone()) {
                    candidates.push(h.clone());
                }
            }
        }
        for entry in inv.discovery_subnets() {
            let Some(ips) = entry.subnet.as_deref().and_then(expand_ipv4_cidr) else { continue };
            for ip in ips {
                if seen.insert(ip.clone()) {
                    candidates.push(TrustedHost {
                        host: Some(ip),
                        subnet: None,
                        user: entry.user.clone(),
                        role: entry.role.clone(),
                        notes: format!("discovered in {}", entry.subnet.as_deref().unwrap_or("")),
                    });
                }
            }
        }
        if let Some(ref cidr) = subnet {
            if let Some(ips) = expand_ipv4_cidr(cidr) {
                for ip in ips {
                    if seen.insert(ip.clone()) {
                        candidates.push(TrustedHost {
                            host: Some(ip),
                            subnet: None,
                            user: "noo".into(),
                            role: String::new(),
                            notes: format!("ad-hoc scan of {cidr}"),
                        });
                    }
                }
            }
        }

        let inv_hosts: std::collections::HashSet<String> = inv.trusted_concrete()
            .filter_map(|h| h.host.clone())
            .filter(|h| !h.is_empty())
            .collect();

        // Probe SSH reachability in parallel (64-way cap, 1.5s each).
        let sem = Arc::new(tokio::sync::Semaphore::new(64));
        let mut join = tokio::task::JoinSet::new();
        for h in candidates.iter().filter_map(|c| c.host.clone()) {
            let sem = sem.clone();
            join.spawn(async move {
                let _permit = sem.acquire().await;
                let ok = probe_ssh(h.clone()).await;
                (h, ok)
            });
        }
        let mut reach: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        while let Some(res) = join.join_next().await {
            if let Ok((h, ok)) = res {
                reach.insert(h, ok);
            }
        }

        // Cross-check enrolled nodes. Python consulted the node registry;
        // the Rust source of truth for "already enrolled" is the
        // persistent cluster_nodes table (ip + hostname both match).
        let mut registered: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let rows = crate::repo::cluster::all_nodes(&state.db)
            .await
            .unwrap_or_default();
        // Both columns are NOT NULL, so only emptiness needs guarding — the
        // previous `Option::filter` was doing a null check that could not fire.
        for (node_id, ip, hostname) in rows {
            if !ip.is_empty() {
                registered.insert(ip, node_id.clone());
            }
            if !hostname.is_empty() {
                registered.insert(hostname, node_id);
            }
        }

        let mut trusted: Vec<Value> = Vec::new();
        let mut discovered: Vec<Value> = Vec::new();
        for h in &candidates {
            let Some(ref host) = h.host else { continue };
            let ssh_ok = reach.get(host).copied().unwrap_or(false);
            let in_inventory = inv_hosts.contains(host);
            if skip_unreachable && !ssh_ok && !in_inventory {
                continue;
            }
            let node_id = registered.get(host).cloned();
            let probe = json!({
                "host": host,
                "user": h.user,
                "role": h.role,
                "notes": h.notes,
                "in_inventory": in_inventory,
                "ssh_reachable": ssh_ok,
                "already_registered": node_id.is_some(),
                "registered_node_id": node_id,
            });
            if in_inventory {
                trusted.push(probe);
            } else if ssh_ok || !skip_unreachable {
                discovered.push(probe);
            }
        }

        json!({
            "inventory_path": inv.path.to_string_lossy(),
            "inventory_exists": inv.path.exists(),
            "trusted_hosts": trusted,
            "discovered_hosts": discovered,
            "cluster_registered": registered.iter()
                .map(|(addr, nid)| json!({"node_id": nid, "address": addr}))
                .collect::<Vec<_>>(),
        })
    };

    match tokio::time::timeout(std::time::Duration::from_secs(30), work).await {
        Ok(result) => {
            tracing::info!(
                trusted = result.get("trusted_hosts").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                discovered = result.get("discovered_hosts").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                "cluster_discover.done"
            );
            Ok(Json(result))
        }
        Err(_) => {
            tracing::warn!("cluster_discover.timeout");
            Err(AppError::Internal(
                "discovery timed out after 30s — probes may be hanging".into()))
        }
    }
}

// ── Tier 2: proposal queue (agent proposes, human approves) ─────────

/// Publish a proposal-lifecycle observability event to NATS. Best-effort,
/// never fails the caller. Subject: `events.cluster.<kind>` — same as
/// Python's workers/cluster.py::_emit_cluster_event (which emits the
/// complementary `proposal.approved/rejected` kinds).
///
/// NOTE (2026-08 zombie sweep): there is NO in-tree subscriber — the
/// once-planned dashboard WebSocket relay was never built. Events are
/// retained in the JetStream EVENTS stream (`events.>`, 24h — see
/// cluster/messaging.py::_init_streams) so external tooling / `nats sub`
/// can observe the proposal trail. If you add an in-tree consumer,
/// update this comment.
pub(crate) async fn emit_cluster_event(state: &AppState, kind: &str, payload: Value) {
    let mut body = match payload {
        Value::Object(m) => m,
        other => {
            let mut m = serde_json::Map::new();
            m.insert("payload".into(), other);
            m
        }
    };
    body.insert("kind".into(), json!(kind));
    body.insert("ts".into(), json!(unix_now_f64()));
    let bytes = serde_json::to_vec(&Value::Object(body)).unwrap_or_default();
    if let Err(e) = state.nats.publish(format!("events.cluster.{kind}"), bytes.into()).await {
        tracing::debug!(kind = %kind, error = %e, "emit_cluster_event_failed");
    }
}

/// Send approval-notification messages to configured channels.
/// [ported from workers/cluster.py::_notify_an earlier change-07-18]
///
/// Reads the recipient + channel from env vars:
///   NOO_APPROVAL_GCHAT_SPACE     (e.g. spaces/<space-id>)
///   NOO_APPROVAL_TELEGRAM_CHAT   (chat_id)
/// Best-effort — never fails the proposal if a notification can't be
/// sent. Returns the list of channels that accepted the message.
///
/// Google Chat goes out as plain text via the native SA-OAuth2 sender.
/// (Python attempted a rich card with Approve/Reject buttons first, but
/// GoogleChatAdapter.send_rich has no handler for the "buttons" widget
/// type, so the buttons were dropped and the effective payload was
/// informational either way; approval happens via dashboard/Telegram.)
/// Telegram keeps full parity: inline Approve/Reject keyboard whose
/// callback_data (`noo-cluster-approve:<id>`) the webhook routes via
/// PARSE_CALLBACK_DATA. UUIDs are 36 chars + ~22 prefix → fits the
/// 64-byte callback_data cap.
async fn notify_proposal(
    proposal_id: &str, host: &str, user_name: &str, role: &str, reason: &str,
) -> Vec<String> {
    let mut notified: Vec<String> = Vec::new();
    let title = format!("Cluster enrollment proposal: {host}");
    let mut body = format!("*Host:* {host}\n*User:* {user_name}");
    if !role.is_empty() {
        body.push_str(&format!("\n*Role:* {role}"));
    }
    body.push_str(&format!("\n*Reason:* {reason}\n\nProposal ID: `{proposal_id}`"));
    // The channel floor masks a tailnet host, so the notice alone may not
    // say which machine is asking; the command lists every proposal with
    // its host in full.
    body.push_str("\nNext: `noo cluster proposals --status pending`");
    let payload_text = format!("{title}\n\n{body}");

    let gchat_space = std::env::var("NOO_APPROVAL_GCHAT_SPACE")
        .unwrap_or_default().trim().to_string();
    if !gchat_space.is_empty() {
        match super::communication::send_channel_message(
            "google_chat", &gchat_space, &payload_text, None, None, None,
        ).await {
            Ok(()) => notified.push("google_chat".into()),
            Err(e) => tracing::debug!(error = %e, "notify_proposal_gchat_failed"),
        }
    }

    let tg_chat = std::env::var("NOO_APPROVAL_TELEGRAM_CHAT")
        .unwrap_or_default().trim().to_string();
    if !tg_chat.is_empty() {
        let inline_kbd = json!({
            "inline_keyboard": [[
                {"text": "✓ Approve",
                 "callback_data": format!("noo-cluster-approve:{proposal_id}")},
                {"text": "✗ Reject",
                 "callback_data": format!("noo-cluster-reject:{proposal_id}")},
            ]]
        });
        match super::communication::send_telegram_keyboard(&tg_chat, &payload_text, &inline_kbd).await {
            Ok(()) => notified.push("telegram".into()),
            Err(e) => tracing::debug!(error = %e, "notify_proposal_telegram_failed"),
        }
    }

    notified
}

/// Who a proposal is attributed to: the authenticated account (JWT `sub`,
/// including the connection label), else the authenticated node, else
/// `unknown`. Pure so a test pins that no request field can set it.
fn proposer_of(actor: Option<&str>, node: Option<&str>) -> String {
    actor
        .or(node)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

/// POST /api/cluster/propose — Agent proposes adding a node.
/// [ported from workers/cluster.py::_cluster_propose 2026-07-18]
///
/// Always creates a row in `noo_cluster_proposals` (columns per migration
/// 004_cluster_proposals) with status='pending' and returns the
/// proposal id so the agent can track it.
///
/// Body: {host, user, role?, reason} — matches the
/// noo_cluster_propose_node MCP tool + static/modules/proposals.js.
async fn cluster_propose(
    State(state): State<Arc<AppState>>,
    actor: Option<axum::Extension<crate::auth::AuthActor>>,
    node: Option<axum::Extension<crate::auth::ClusterNode>>,
    body: Option<Json<Value>>,
) -> AppResult {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let get_trimmed = |key: &str| -> String {
        body.get(key).and_then(|v| v.as_str()).unwrap_or("").trim().to_string()
    };
    let host = get_trimmed("host");
    let user_name = {
        let u = get_trimmed("user");
        if u.is_empty() { get_trimmed("user_name") } else { u }
    };
    let role = get_trimmed("role");
    let reason = get_trimmed("reason");
    // Provenance comes from the verified credential, never the body: a
    // `proposed_by` field the caller supplies is ignored (an operator-door
    // agent could otherwise file a proposal "from" any account).
    let proposed_by = proposer_of(actor.as_ref().map(|e| e.0 .0.as_str()), node.as_ref().map(|e| e.0 .0.as_str()));

    if host.is_empty() {
        return Err(AppError::BadRequest("host required".into()));
    }
    if user_name.is_empty() {
        return Err(AppError::BadRequest("user required (the login an operator will use on the target when they run the bootstrap one-liner; audit only \u{2014} the controller never logs in)".into()));
    }
    if reason.is_empty() {
        return Err(AppError::BadRequest(
            "reason required (audit + UX — what's the agent's justification?)".into()));
    }

    // No pre-approval short-circuit. `auto_enroll: true` used to return
    // here and skip the proposal row entirely, on the premise that the
    // enroller could then add the host without a human. That premise is
    // gone: push enrolment was retired (verb deleted)
    // and an enrolment proposal now resolves to bootstrap-token
    // INSTRUCTIONS that a person runs on the target machine. So the flag
    // authorised nothing it could still deliver, while reading like a
    // standing grant to add machines unattended.
    //
    // Every proposal is a row now, and every enrolment needs someone on
    // the node. Discovery and the proposal queue stay.

    let proposal_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO noo_cluster_proposals \
         (id, host, user_name, role, reason, proposed_by, status) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6, 'pending')"
    )
    .bind(&proposal_id)
    .bind(&host)
    .bind(&user_name)
    .bind(if role.is_empty() { None } else { Some(role.as_str()) })
    .bind(&reason)
    .bind(&proposed_by)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "cluster_propose_insert_failed");
        AppError::Internal(format!("could not file proposal: {e}"))
    })?;

    // Fire approval notifications to configured channels (best-effort).
    let notified = notify_proposal(&proposal_id, &host, &user_name, &role, &reason).await;

    // Live event for the dashboard's WebSocket listener.
    emit_cluster_event(&state, "proposal.created", json!({
        "id": proposal_id, "host": host, "user": user_name,
        "role": role, "reason": reason, "status": "pending",
    })).await;

    Ok(Json(json!({
        "proposal_id": proposal_id,
        "host": host,
        "user": user_name,
        "status": "pending",
        "dashboard_url": format!("/dashboard/proposals/{proposal_id}"),
        "notified": notified,
        "note": "Awaiting human approval via dashboard, Google Chat card, or Telegram button.",
    })))
}


#[cfg(test)]
mod heartbeat_carry_tests {
    use super::*;

    /// The shipper's account rides the record (fleet logging phase 6): a
    /// beat that carries `log_ship` replaces the record's copy; one that
    /// omits it, or sends null, leaves the last report where it was.
    #[test]
    fn log_ship_is_carried_when_reported_and_kept_when_not() {
        let mut data = json!({"id": "host3"});
        let beat = json!({"load": 0.1, "log_ship": {"enabled": true, "queued": 0, "shipped_total": 12}});
        carry_reported(&mut data, &beat, "log_ship");
        assert_eq!(data["log_ship"]["shipped_total"], 12);

        carry_reported(&mut data, &json!({"load": 0.2}), "log_ship");
        assert_eq!(data["log_ship"]["shipped_total"], 12, "an omitted field keeps the last report");
        carry_reported(&mut data, &json!({"log_ship": null}), "log_ship");
        assert_eq!(data["log_ship"]["shipped_total"], 12, "null is not a report");

        let mut fresh = json!({"id": "host9"});
        carry_reported(&mut fresh, &json!({"load": 0.0}), "log_ship");
        assert!(fresh.get("log_ship").is_none(), "never synthesised for an agent that has not said");
    }

    /// And the handler must call it for `log_ship`, or the row above only
    /// ever reads "agent predates the shipper". A source pin, because the
    /// handler needs an AppState no unit test can build.
    #[test]
    fn the_heartbeat_handler_carries_log_ship() {
        let src = include_str!("cluster.rs");
        let handler = src.split("async fn node_heartbeat(").nth(1).expect("the handler")
            .split("\nasync fn ").next().unwrap();
        assert!(handler.contains("carry_reported(&mut data, &body, \"log_ship\")"), "node_heartbeat does not carry log_ship");
        assert!(handler.contains("carry_reported(&mut data, &body, \"peer_identity_enforced\")"),
            "node_heartbeat does not carry peer_identity_enforced — the verify row would judge a stale registration");
    }

    /// The node's held door leaves ride the record from
    /// both writers: every heartbeat, and the registration that rebuilds
    /// the record from scratch. Source pins, as above.
    #[test]
    fn heartbeat_and_register_carry_backend_leaves() {
        let src = include_str!("cluster.rs");
        let body_of = |sig: &str| src.split(sig).nth(1).expect("the handler")
            .split("\nasync fn ").next().unwrap().to_string();
        assert!(body_of("async fn node_heartbeat(").contains("carry_reported(&mut data, &body, \"backend_leaves\")"),
            "node_heartbeat does not carry backend_leaves — `backend doors` reads every node as an agent that predates the report");
        assert!(body_of("async fn node_register_body(").contains("carry_reported(&mut data, &body, \"backend_leaves\")"),
            "node_register_body does not carry backend_leaves — a re-registration wipes the report until the next beat");

        // The shape the CLI reads survives the carry untouched.
        let mut data = json!({"id": "host3"});
        let beat = json!({"backend_leaves": {"vllm": {"dns": ["noo-vllm"], "not_after": 1_790_000_000}}});
        carry_reported(&mut data, &beat, "backend_leaves");
        assert_eq!(data["backend_leaves"]["vllm"]["not_after"], 1_790_000_000);
        // `{}` is a report ("holds none") and replaces an older one.
        carry_reported(&mut data, &json!({"backend_leaves": {}}), "backend_leaves");
        assert_eq!(data["backend_leaves"], json!({}));
    }

    /// `data_roots` rides the record from both writers, is
    /// replaced whole by a newer report (a stale `running_mounts` cannot
    /// survive a beat that omits it inside `data_roots`), and a beat with no
    /// `data_roots` (older agent) or null leaves the record's copy alone,
    /// exactly like `backend_leaves`.
    #[test]
    fn heartbeat_and_register_carry_data_roots() {
        let src = include_str!("cluster.rs");
        let body_of = |sig: &str| src.split(sig).nth(1).expect("the handler")
            .split("\nasync fn ").next().unwrap().to_string();
        for sig in ["async fn node_heartbeat(", "async fn node_register_body("] {
            assert!(body_of(sig).contains("carry_reported(&mut data, &body, \"data_roots\")"),
                "{sig} does not carry data_roots — provision cannot see the root the node runs on");
        }
        let mut data = json!({"id": "host3"});
        let beat = json!({"data_roots": {"noo_data_root": "/data/noo", "running_mounts": {"vllm": ["/data/noo/hf-cache"]}}});
        carry_reported(&mut data, &beat, "data_roots");
        assert_eq!(data["data_roots"]["running_mounts"]["vllm"][0], "/data/noo/hf-cache");
        // A newer report replaces the old whole: no stale running_mounts.
        let newer = json!({"data_roots": {"noo_data_root": "/data/noo", "running_mounts_error": "docker down"}});
        carry_reported(&mut data, &newer, "data_roots");
        assert!(data["data_roots"].get("running_mounts").is_none());
        assert_eq!(data["data_roots"]["running_mounts_error"], "docker down");
        // An older agent's beat (absent) and a null leave the record alone.
        carry_reported(&mut data, &json!({"load": 1}), "data_roots");
        carry_reported(&mut data, &json!({"data_roots": null}), "data_roots");
        assert_eq!(data["data_roots"]["noo_data_root"], "/data/noo");
        // A record that never had one stays absent (not null).
        let mut fresh = json!({"id": "old"});
        carry_reported(&mut fresh, &json!({"load": 1}), "data_roots");
        assert!(fresh.get("data_roots").is_none());
    }

    /// `legacy_lanes` rides the record from both writers,
    /// or the `legacy lanes` verify row reads every node as an agent that
    /// does not report — and a re-registration would reset the evidence.
    #[test]
    fn heartbeat_and_register_carry_legacy_lanes() {
        let src = include_str!("cluster.rs");
        let body_of = |sig: &str| src.split(sig).nth(1).expect("the handler")
            .split("\nasync fn ").next().unwrap().to_string();
        assert!(body_of("async fn node_heartbeat(").contains("carry_reported(&mut data, &body, \"legacy_lanes\")"),
            "node_heartbeat does not carry legacy_lanes");
        assert!(body_of("async fn node_register_body(").contains("carry_reported(&mut data, &body, \"legacy_lanes\")"),
            "node_register_body does not carry legacy_lanes");
        let mut data = json!({"id": "host3"});
        carry_reported(&mut data, &json!({"legacy_lanes": {"since_unix": 1_790_000_000, "static_token": 3, "cluster_hmac_v1_refused": 0}}), "legacy_lanes");
        assert_eq!(data["legacy_lanes"]["static_token"], 3);
    }

    /// `backend_containers` rides the record from both
    /// writers, or `cluster verify <node>` cannot tell a backend still
    /// warming up from a broken door. Source pins, as above.
    #[test]
    fn heartbeat_and_register_carry_backend_containers() {
        let src = include_str!("cluster.rs");
        let body_of = |sig: &str| src.split(sig).nth(1).expect("the handler")
            .split("\nasync fn ").next().unwrap().to_string();
        assert!(body_of("async fn node_heartbeat(").contains("carry_reported(&mut data, &body, \"backend_containers\")"),
            "node_heartbeat does not carry backend_containers — `backend doors` can never read a warming backend as starting");
        assert!(body_of("async fn node_register_body(").contains("carry_reported(&mut data, &body, \"backend_containers\")"),
            "node_register_body does not carry backend_containers — a re-registration wipes the report until the next beat");

        let mut data = json!({"id": "host3"});
        let beat = json!({"backend_containers": {"vllm": {"running": true, "started_at": 1_790_000_000, "health": "starting"}}});
        carry_reported(&mut data, &beat, "backend_containers");
        assert_eq!(data["backend_containers"]["vllm"]["started_at"], 1_790_000_000);
        assert_eq!(data["backend_containers"]["vllm"]["health"], "starting");
        // An older agent omits it: the record keeps what it had, never synthesised.
        let mut old = json!({"id": "host9"});
        carry_reported(&mut old, &json!({"load": 0.1}), "backend_containers");
        assert!(old.get("backend_containers").is_none());
        // `{}` (nothing running) replaces an older report.
        carry_reported(&mut data, &json!({"backend_containers": {}}), "backend_containers");
        assert_eq!(data["backend_containers"], json!({}));
    }

    /// `gpu_contention` rides the record from both writers,
    /// so `noo cluster status`/`verify` and the router can see a node that
    /// yielded its GPU to other work (and why its backend is gone).
    #[test]
    fn heartbeat_and_register_carry_gpu_contention() {
        let src = include_str!("cluster.rs");
        let body_of = |sig: &str| src.split(sig).nth(1).expect("the handler")
            .split("\nasync fn ").next().unwrap().to_string();
        assert!(body_of("async fn node_heartbeat(").contains("carry_reported(&mut data, &body, \"gpu_contention\")"),
            "node_heartbeat does not carry gpu_contention");
        assert!(body_of("async fn node_register_body(").contains("carry_reported(&mut data, &body, \"gpu_contention\")"),
            "node_register_body does not carry gpu_contention");
        let mut data = json!({"id": "host3"});
        let beat = json!({"gpu_contention": {"state": "yielded", "foreign_mb": 11468, "total_mb": 16376,
            "free_mb": 4908, "method": "memory-accounting", "since": "2026-10-17T12:00:00Z",
            "paused_backends": ["vllm"]}});
        carry_reported(&mut data, &beat, "gpu_contention");
        assert_eq!(data["gpu_contention"]["state"], "yielded");
        assert_eq!(data["gpu_contention"]["paused_backends"], json!(["vllm"]));
        assert_eq!(data["gpu_contention"]["method"], "memory-accounting");
        // Resumed: the next beat replaces it.
        carry_reported(&mut data, &json!({"gpu_contention": {"state": "free", "paused_backends": []}}), "gpu_contention");
        assert_eq!(data["gpu_contention"]["state"], "free");
        // An older agent omits it: nothing synthesised.
        let mut old = json!({"id": "host9"});
        carry_reported(&mut old, &json!({"load": 0.1}), "gpu_contention");
        assert!(old.get("gpu_contention").is_none());
    }

    /// The GPU hold routes are operator-only, and both are audited.
    #[test]
    fn gpu_hold_is_operator_only_and_audited() {
        // The code above the tests only: this test's own literals would
        // otherwise satisfy every `contains` below.
        let src = include_str!("cluster.rs").split("fn gpu_hold_is_operator_only_and_audited").next().unwrap();
        for name in ["async fn gpu_hold(", "async fn gpu_release("] {
            let h = src.split(name).nth(1).expect(name).split("\nasync fn ").next().unwrap();
            // The extractor runs before the handler body, so the body can never be read first.
            assert!(h.contains("operator: crate::authz::Operator"), "{name}: the operator gate");
            assert!(h.contains("\"legacy\": legacy"), "{name}: a legacy call is audited as such");
        }
        let op = src.split("async fn gpu_hold_op(").nth(1).expect("gpu_hold_op")
            .split("\nasync fn ").next().unwrap();
        assert!(op.contains("GpuTransition::take(node_id)?"), "one transition per node at a time");
        assert!(op.contains("audit::record("), "hold/release must be audited");
        assert!(op.contains("\"force\": payload[\"force\"]"), "the audit row says whether it was a force");
        let drain = op.find("set_node_draining(node_id, true)").expect("drain mark");
        let lanes = op.find("set_lanes_paused(node_id, &drain_lanes)").expect("GPU-lane mark");
        let call = op.find("NodeLink::for_node(").expect("node call");
        assert!(drain < call && lanes < call, "the lanes leave routing before the agent is asked to stop anything");
        assert!(src.contains(".route(\"/api/cluster/nodes/{node_id}/gpu/hold\", post(gpu_hold))"));
        assert!(src.contains(".route(\"/api/cluster/nodes/{node_id}/gpu/release\", post(gpu_release))"));
    }

    #[test]
    fn with_contention_replaces_only_the_contention() {
        let rec = json!({"id": "awolf", "status": "online", "gpu_contention": {"state": "free"}});
        let gc = json!({"state": "held", "lease": {"operation_id": "op-1", "owner": "op"}});
        let merged = with_contention(rec, gc.clone());
        assert_eq!(merged["gpu_contention"], gc);
        assert_eq!(merged["status"], "online");
        assert_eq!(merged["id"], "awolf");
        // A record with no prior contention gains it.
        assert_eq!(with_contention(json!({"id": "x"}), gc.clone())["gpu_contention"], gc);
    }

    /// One hold or release per node at a time; the slot frees when the
    /// guard drops, and other nodes are not affected.
    #[test]
    fn gpu_transition_lock_is_per_node() {
        let a = GpuTransition::take("lock-test-a").expect("free");
        assert!(GpuTransition::take("lock-test-a").is_err(), "a second transition on the node is refused");
        let _b = GpuTransition::take("lock-test-b").expect("another node is free");
        drop(a);
        let _a2 = GpuTransition::take("lock-test-a").expect("freed on drop");
        assert_eq!(GPU_DRAIN_TIMEOUT_DEFAULT_SECS, 120);
        assert_eq!(GPU_DRAIN_TIMEOUT_MAX_SECS, 900);
    }

    /// The bench route is operator-only, audited, one NodeLink call with its
    /// own 900 s timeout, and the bench rides both record writers.
    #[test]
    fn node_bench_is_operator_only_audited_and_generous() {
        assert_eq!(NODE_BENCH_TIMEOUT, std::time::Duration::from_secs(900));
        let src = include_str!("cluster.rs").split("fn node_bench_is_operator_only_audited_and_generous").next().unwrap();
        let h = src.split("async fn node_bench(").nth(1).expect("node_bench").split("\nasync fn ").next().unwrap();
        assert!(h.contains("operator: crate::authz::Operator"), "the operator gate");
        assert!(h.contains(".request(reqwest::Method::POST, \"/bench\")"));
        assert!(h.contains(".timeout(NODE_BENCH_TIMEOUT)"));
        assert!(h.contains("audit::record("), "a bench must be audited");
        assert!(src.contains(".route(\"/api/cluster/nodes/{node_id}/bench\", post(node_bench))"));
        assert_eq!(src.matches("carry_reported(&mut data, &body, \"model_bench\");").count(), 2, "heartbeat and registration");
        assert!(src.contains("\"harness_profile\": harness_profile,"), "desired-config carries the resolved profile");
    }

    /// Every desired-state writer nudges the node after it stores, or the
    /// change lands at the next 5-minute tick (i256): placement put, delete
    /// and the node-config upsert. Source pins, as above.
    #[test]
    fn desired_state_writers_nudge_the_node() {
        let src = include_str!("cluster.rs").split("fn desired_state_writers_nudge_the_node").next().unwrap();
        for f in ["async fn placement_put(", "async fn placement_delete(", "async fn node_config_put("] {
            let h = src.split(f).nth(1).unwrap_or_else(|| panic!("{f}")).split("\nasync fn ").next().unwrap();
            assert!(h.contains("nudge_reconcile(state.clone(), node_id.clone());"), "{f} must nudge");
        }
    }

    /// `stunnel_image` rides the record from both
    /// writers, or `cluster verify <node>` cannot see a node on the
    /// alpine + apk sidecar fallback. Source pins, as above.
    #[test]
    fn heartbeat_and_register_carry_stunnel_image() {
        let src = include_str!("cluster.rs");
        let body_of = |sig: &str| src.split(sig).nth(1).expect("the handler")
            .split("\nasync fn ").next().unwrap().to_string();
        assert!(body_of("async fn node_heartbeat(").contains("carry_reported(&mut data, &body, \"stunnel_image\")"),
            "node_heartbeat does not carry stunnel_image — a node on the alpine sidecar fallback is invisible to `cluster verify`");
        assert!(body_of("async fn node_register_body(").contains("carry_reported(&mut data, &body, \"stunnel_image\")"),
            "node_register_body does not carry stunnel_image — a re-registration wipes the report until the next beat");

        let mut data = json!({"id": "host3"});
        carry_reported(&mut data, &json!({"stunnel_image": "fallback-alpine"}), "stunnel_image");
        assert_eq!(data["stunnel_image"], "fallback-alpine");
        // A beat that omits it (no sidecar started yet) keeps the last value.
        carry_reported(&mut data, &json!({"load": 0.1}), "stunnel_image");
        assert_eq!(data["stunnel_image"], "fallback-alpine");
        carry_reported(&mut data, &json!({"stunnel_image": "published"}), "stunnel_image");
        assert_eq!(data["stunnel_image"], "published");
    }
}

#[cfg(test)]
mod honesty_tests {
    use super::*;

    /// i145: a space's pool is the embed placements on its model; one on a
    /// model no space uses is listed apart, not silently in a pool.
    #[test]
    fn an_embedding_spaces_pool_is_the_placements_on_its_model() {
        use crate::embedding_spaces::Space;
        let spaces = vec![
            Space { space: "knowledge".into(), model: "harrier".into(), dims: Some(1024), migration: None },
            Space { space: "code".into(), model: "nomic-embed-code".into(), dims: None, migration: None },
        ];
        let p = |n: &str, m: &str, d: &str| (n.to_string(), "ollama".to_string(), Some(m.to_string()), d.to_string());
        let placements = vec![
            p("host2", "harrier:latest", "running"),
            p("host6", "harrier", "stopped"),
            p("awolf", "nomic-embed-code", "running"),
            p("host9", "bge-m3", "running"),
        ];
        let v = embedding_space_view(&spaces, &placements, &["HOST2".to_string(), "awolf".to_string()], &[]);
        let k = &v["spaces"][0];
        assert_eq!(k["space"], "knowledge");
        assert_eq!(k["default"], true);
        assert_eq!(k["pool"].as_array().unwrap().len(), 2);
        assert_eq!(k["live"], 1, "host6 is stopped: in the pool, not live");
        assert_eq!(v["spaces"][1]["pool"][0]["node"], "awolf");
        assert_eq!(v["spaces"][1]["live"], 1);
        assert_eq!(v["unmatched"][0]["node"], "host9");
    }

    /// i150: one node serving two spaces has two embed rows; it is in both
    /// pools, once each.
    #[test]
    fn a_node_with_two_embed_rows_is_in_both_spaces_pools() {
        use crate::embedding_spaces::Space;
        let spaces = vec![
            Space { space: "knowledge".into(), model: "harrier".into(), dims: Some(1024), migration: None },
            Space { space: "code".into(), model: "nomic-embed-code".into(), dims: None, migration: None },
        ];
        let p = |m: &str| ("awolf".to_string(), "ollama".to_string(), Some(m.to_string()), "running".to_string());
        let v = embedding_space_view(&spaces, &[p("harrier"), p("nomic-embed-code")], &["awolf".to_string()], &[]);
        for i in 0..2 {
            assert_eq!(v["spaces"][i]["pool"].as_array().unwrap().len(), 1, "{v}");
            assert_eq!(v["spaces"][i]["pool"][0]["node"], "awolf");
            assert_eq!(v["spaces"][i]["live"], 1);
        }
        assert!(v["unmatched"].as_array().unwrap().is_empty());
    }

    /// F1: a space with no embed placement but an answering static endpoint
    /// (the compose embedder on a fresh install) reports it; a static that
    /// did not answer is listed and not counted.
    #[test]
    fn a_spaces_static_endpoints_are_reported_with_their_probe() {
        use crate::embedding_spaces::Space;
        let spaces = vec![
            Space { space: "knowledge".into(), model: "harrier".into(), dims: Some(1024), migration: None },
            Space { space: "code".into(), model: "nomic-embed-code".into(), dims: None, migration: None },
        ];
        let statics = vec![
            vec![("https://stunnel-ollama-embed:11434".to_string(), true), ("http://cpu-embed:11434".to_string(), false)],
            vec![("https://stunnel-ollama-embed:11434".to_string(), false)],
        ];
        let v = embedding_space_view(&spaces, &[], &[], &statics);
        let k = &v["spaces"][0];
        assert_eq!((k["live"].as_u64(), k["static_live"].as_u64()), (Some(0), Some(1)), "{v}");
        assert_eq!(k["static"][1]["live"], false);
        assert_eq!(v["spaces"][1]["static_live"], 0);
    }

    // "The system must not lie" audit. Both helpers below exist so the
    // never-fabricate rules are testable without an AppState (repo
    // convention — no DB-backed route harness exists).

    #[test]
    fn absent_metric_is_null_not_zero() {
        let data = json!({"temperature_c": 61.0, "gpu_utilization_percent": 0.0});
        // Present and non-zero: passed through.
        assert_eq!(metric_or_null(&data, "temperature_c"), json!(61.0));
        // A REAL zero is still a real zero — the point is not to suppress 0,
        // it is to stop inventing it.
        assert_eq!(metric_or_null(&data, "gpu_utilization_percent"), json!(0.0));
        // Absent (e.g. the node-agent renamed the field) → null, where the
        // old code emitted 0.0 and made a hot GPU look idle and ice-cold.
        assert!(metric_or_null(&data, "power_draw_w").is_null());
        // Present but not a number → also null, not 0.0.
        let junk = json!({"power_draw_w": "n/a"});
        assert!(metric_or_null(&junk, "power_draw_w").is_null());
    }

    #[test]
    fn stats_count_every_bucket_including_unknown() {
        let nodes = vec![
            json!({"id": "a", "status": "online"}),
            json!({"id": "b", "status": "busy"}),
            json!({"id": "c", "status": "offline"}),
            json!({"id": "d", "status": "unknown"}),
        ];
        let stats = node_stats(&nodes, None);
        assert_eq!(stats["total_nodes"], json!(4));
        assert_eq!(stats["online"], json!(1));
        assert_eq!(stats["busy"], json!(1));
        assert_eq!(stats["offline"], json!(1));
        // "unknown" is its own bucket: a node in NATS KV but absent from
        // gossip used to inherit its registration-time "online".
        assert_eq!(stats["unknown"], json!(1));
        assert!(stats.get("error").is_none());
    }

    #[test]
    fn failed_offline_merge_nulls_the_totals_rather_than_understating_them() {
        let nodes = vec![json!({"id": "a", "status": "online"})];
        let stats = node_stats(&nodes, Some("db down"));
        // total_nodes and offline are understated by an unknown amount when
        // the cluster_nodes read failed — the old `.unwrap_or_default()`
        // served them anyway, silently deleting every offline node.
        assert!(stats["total_nodes"].is_null());
        assert!(stats["offline"].is_null());
        // Live-derived counts remain real.
        assert_eq!(stats["online"], json!(1));
        assert_eq!(stats["error"], json!("db down"));
    }

    // --- node-reported NATS bus state (2026-08-02 bus-deaf incident) ---

    #[test]
    fn nats_state_absent_is_null_not_a_default() {
        // An older node-agent sends no nats_status. "We do not know" must not
        // render as connected — nor as disconnected.
        let (state, detail) = derive_nats_state(None);
        assert_eq!(state, Value::Null);
        assert!(detail.contains("not reported"), "detail was: {detail}");

        let (state, _) = derive_nats_state(Some(&Value::Null));
        assert_eq!(state, Value::Null);
    }

    #[test]
    fn nats_state_reports_a_bus_deaf_node() {
        let reported = json!({
            "state": "reconnecting",
            "connected": false,
            "job_dispatch_bound": false,
        });
        let (state, detail) = derive_nats_state(Some(&reported));
        assert_eq!(state, json!("reconnecting"));
        assert!(detail.contains("NOT connected"), "detail was: {detail}");
        assert!(detail.contains("strand"), "detail must say what it costs: {detail}");
    }

    #[test]
    fn nats_state_flags_connected_but_unbound() {
        // The 2026-07-03 shape: socket is up, the dispatch durable is not
        // bound, and jobs silently rot. Connected alone is not enough.
        let reported = json!({
            "state": "connected",
            "connected": true,
            "job_dispatch_bound": false,
        });
        let (state, detail) = derive_nats_state(Some(&reported));
        assert_eq!(state, json!("connected"));
        assert!(detail.contains("NOT bound"), "detail was: {detail}");
    }

    #[test]
    fn nats_state_healthy_node_reads_healthy() {
        let reported = json!({
            "state": "connected",
            "connected": true,
            "job_dispatch_bound": true,
        });
        let (state, detail) = derive_nats_state(Some(&reported));
        assert_eq!(state, json!("connected"));
        assert!(detail.contains("durable bound"), "detail was: {detail}");
        assert!(!detail.contains("NOT"), "detail was: {detail}");
    }

    #[test]
    fn nats_state_attributes_the_claim_to_the_node() {
        // Honest-status discipline: this is the node's claim, not the
        // gateway's measurement, and the string must say so.
        for reported in [
            json!({"state": "connected", "connected": true, "job_dispatch_bound": true}),
            json!({"state": "closed", "connected": false, "job_dispatch_bound": false}),
        ] {
            let (_, detail) = derive_nats_state(Some(&reported));
            assert!(
                detail.contains("as reported by the node-agent"),
                "detail must attribute the claim: {detail}"
            );
        }
    }
}

#[cfg(test)]
mod arch_tests {
    use super::*;

    #[test]
    fn arch_string_beats_the_boolean_and_unknown_stays_unknown() {
        // host9-sensors on 2026-08-04: the agent's own capabilities were
        // right all along; only the flattened column had gone stale.
        assert_eq!(arch_is_arm(&json!({"arch": "arm64", "is_arm": true})), Some(true));
        assert_eq!(arch_is_arm(&json!({"arch": "x86_64"})), Some(false));
        assert_eq!(arch_is_arm(&json!({"is_arm": true})), Some(true));
        assert_eq!(arch_is_arm(&json!({"is_arm": false})), Some(false));
        // No signal, or a signal we cannot read, must NOT become "x86".
        assert_eq!(arch_is_arm(&json!({})), None);
        assert_eq!(arch_is_arm(&json!({"arch": "riscv64"})), None);
        // An unreadable arch string still defers to the boolean.
        assert_eq!(arch_is_arm(&json!({"arch": "", "is_arm": true})), Some(true));
    }
}

#[cfg(test)]
mod node_config_upsert_tests {
    use super::NODE_CONFIG_UPSERT;

    #[test]
    fn vendor_kinds_name_vendor_cli_kinds_only() {
        use serde_json::json;
        let v = |x: serde_json::Value| super::validate_vendor_kinds(Some(&x));
        // The shipped table's foreign kinds all run a CLI.
        let foreign: Vec<&str> = crate::harness_kinds::all().iter().filter(|r| r.cli.is_some()).map(|r| r.kind.as_str()).collect();
        assert!(!foreign.is_empty(), "the shipped table has a vendor kind");
        let mut want: Vec<String> = foreign.iter().map(|s| s.to_string()).collect();
        want.sort();
        let mut twice: Vec<&str> = foreign.clone();
        twice.extend(foreign.iter());
        assert_eq!(v(json!(twice)).unwrap(), want, "deduplicated, name order");
        assert!(v(json!([])).unwrap().is_empty());
        assert!(super::validate_vendor_kinds(None).unwrap().is_empty());
        assert!(v(serde_json::Value::Null).unwrap().is_empty(), "null clears");
        assert!(v(json!(["noo"])).unwrap_err().contains("runs a vendor CLI"), "noo runs no CLI");
        assert!(v(json!(["nope"])).is_err());
        assert!(v(json!("copilot")).is_err(), "a list, not a string");
        assert!(v(json!([1])).is_err());
    }

    /// PINNED: every column named in the INSERT gets exactly one value.
    #[test]
    fn upsert_columns_match_values() {
        let sql = NODE_CONFIG_UPSERT;
        let cols = sql[sql.find('(').unwrap() + 1..sql.find(')').unwrap()].split(',').count();
        let v = sql.find("VALUES (").unwrap() + "VALUES (".len();
        let mut depth = 0usize;
        let mut end = v;
        for (i, c) in sql[v..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' if depth == 0 => {
                    end = v + i;
                    break;
                }
                ')' => depth -= 1,
                _ => {}
            }
        }
        let mut vals = 1;
        let mut d = 0usize;
        for c in sql[v..end].chars() {
            match c {
                '(' => d += 1,
                ')' => d -= 1,
                ',' if d == 0 => vals += 1,
                _ => {}
            }
        }
        assert_eq!(cols, vals, "columns {cols} vs values {vals} in:\n{sql}");
    }
}

#[cfg(test)]
mod gpu_label_tests {
    /// A GPU tile's `name` is the GPU's MODEL, never the machine it sits in.
    ///
    /// The node-agent fallback used to emit `"name": hostname`. The display
    /// shows the node beside the label, so an operator saw "host3 host3" and
    /// "host8 host8" — the two spellings being `node_id` and `hostname` —
    /// and read one machine as two. Found on the first live display, 2026-09-14.
    ///
    /// Asserted on the source of the emit, because the value is built inside
    /// an async handler that needs a live node-agent to reach: a behavioural
    /// test here would need the fleet, and the defect is one word.
    #[test]
    fn the_fallback_labels_a_gpu_with_its_model_not_its_host() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes/cluster.rs"),
        )
        .expect("own source unreadable");

        // Guard the guard: anchor on something unrelated that must exist, so
        // a moved or emptied file fails loudly instead of passing vacuously.
        assert!(
            src.contains("fn cluster_gpu_metrics"),
            "cluster_gpu_metrics is gone — this guard is stale, not satisfied"
        );

        let at = src
            .find("all_gpus.push(json!({")
            .expect("the fallback's GPU emit is gone — this guard is stale");
        // Bound the block at its own terminator rather than by a character
        // count. The first version read a fixed 900 chars and broke the
        // moment the comment above the emit grew — a guard that depends on
        // how much prose sits near the code is a guard that fails for the
        // wrong reason.
        let close = src[at..]
            .find("}));")
            .expect("the GPU emit is not terminated — this guard is stale");
        let emit = &src[at..at + close];
        let name_line = emit
            .lines()
            .find(|l| l.trim_start().starts_with("\"name\":"))
            .expect("the fallback emits no `name` at all");

        assert!(
            name_line.contains("gpu_model"),
            "the fallback labels a GPU with something other than its model: {name_line}"
        );
        assert!(
            !name_line.contains("hostname"),
            "the fallback labels a GPU with its HOSTNAME again — the tile already shows the \
             node, so this renders the machine twice and reads as two machines: {name_line}"
        );
    }
}

/// Apply a node's harness policy to its declared placements.
///
/// Extracted from `desired_config_get` so it can be tested: the whole of
/// this is a decision about what the node is TOLD, and it was previously
/// only reachable by standing up a gateway and a database.
///
/// - `auto`   — synthesise a RUNNING harness when a chat backend runs here
///              and none is declared. This is why most harnesses exist.
/// - `off`    — the node must end up with a STOPPED harness placement,
///              whether or not one was declared.
/// - anything else (`manual`, unset) — leave the declared set alone.
///
/// The `off` branch is the fix for the design. It used to rewrite
/// existing rows only, which did nothing in the common case: a
/// synthesised placement is not a row, so `auto` -> `off` left NOTHING in
/// desired-config, and the agent only converges a harness it can see
/// (`reconcile.go` iterates placements). The service kept running,
/// unmanaged, while `noo cluster desired` showed no harness at all.
/// Found on host3, 2026-09-21, by switching the policy and watching the
/// harness stay up for nine minutes.
///
/// `manual` deliberately still leaves a running harness alone: it means
/// "I will declare placements myself", not "stop what is running". That
/// asymmetry is the point of having two names.
pub(crate) fn apply_harness_policy(policy: &str, mut placements: Vec<Value>) -> Vec<Value> {
    let has_harness = placements.iter().any(|p| p["backend"] == "harness");
    let has_chat = placements.iter().any(|p| {
        p["backend"] != "harness"
            && p["desired_state"] == "running"
            && matches!(p["role"].as_str(), None | Some("") | Some("chat"))
    });
    let synthesised = |state: &str| {
        json!({
            "backend": "harness", "model": "auto", "image": null, "port": null, "tls": false,
            "env": {}, "desired_state": state, "role": "harness", "synthesized": true,
        })
    };
    match policy {
        "auto" if !has_harness && has_chat => placements.push(synthesised("running")),
        "off" if has_harness => {
            for p in placements.iter_mut().filter(|p| p["backend"] == "harness") {
                p["desired_state"] = json!("stopped");
            }
        }
        "off" => placements.push(synthesised("stopped")),
        _ => {}
    }
    placements
}

#[cfg(test)]
mod harness_policy_tests {
    use super::apply_harness_policy;
    use serde_json::{json, Value};

    fn chat() -> Value {
        json!({"backend":"vllm","desired_state":"running","role":"chat"})
    }
    fn harness_state(v: &[Value]) -> Option<String> {
        v.iter()
            .find(|p| p["backend"] == "harness")
            .map(|p| p["desired_state"].as_str().unwrap_or("?").to_string())
    }

    #[test]
    fn auto_synthesises_a_running_harness_beside_a_chat_backend() {
        let out = apply_harness_policy("auto", vec![chat()]);
        assert_eq!(harness_state(&out).as_deref(), Some("running"));
    }

    #[test]
    fn auto_needs_a_chat_backend() {
        let embed = json!({"backend":"ollama","desired_state":"running","role":"embed"});
        let out = apply_harness_policy("auto", vec![embed]);
        assert_eq!(harness_state(&out), None, "an embedder must not get a harness");
    }

    /// `off` has to leave the node something to converge, or
    /// a running harness is never stopped — it is merely forgotten.
    #[test]
    fn off_stops_a_harness_that_was_only_ever_synthesised() {
        // Exactly the host3 case: policy flipped auto -> off, nothing declared.
        let out = apply_harness_policy("off", vec![chat()]);
        assert_eq!(
            harness_state(&out).as_deref(),
            Some("stopped"),
            "`off` produced no harness placement, so the agent has nothing to              converge and the running harness stays up"
        );
    }

    #[test]
    fn off_stops_a_declared_harness_too() {
        let declared = json!({"backend":"harness","desired_state":"running","role":"harness"});
        let out = apply_harness_policy("off", vec![chat(), declared]);
        assert_eq!(harness_state(&out).as_deref(), Some("stopped"));
        assert_eq!(out.iter().filter(|p| p["backend"] == "harness").count(), 1, "no duplicate row");
    }

    /// `manual` is not `off`. It means "I declare placements myself", and
    /// must not silently stop a harness somebody declared.
    #[test]
    fn manual_leaves_a_declared_harness_alone() {
        let declared = json!({"backend":"harness","desired_state":"running","role":"harness"});
        let out = apply_harness_policy("manual", vec![chat(), declared]);
        assert_eq!(harness_state(&out).as_deref(), Some("running"));
    }

    #[test]
    fn manual_synthesises_nothing() {
        let out = apply_harness_policy("manual", vec![chat()]);
        assert_eq!(harness_state(&out), None);
    }
}

#[cfg(test)]
mod node_ip_tests {
    use super::acceptable_node_ip;

    /// The exact value that took ~200 chat completions a minute to 502.
    #[test]
    fn the_debian_hostname_address_is_refused() {
        assert!(!acceptable_node_ip("127.0.1.1"));
    }

    #[test]
    fn nothing_that_names_this_host_or_no_host_is_accepted() {
        for bad in ["127.0.0.1", "0.0.0.0", "::1", "::", "169.254.10.4", "fe80::1", "224.0.0.1",
                    "255.255.255.255", "", "   ", "HOST3", "host3.localdomain", "not-an-ip"] {
            assert!(!acceptable_node_ip(bad), "{bad:?} must be refused");
        }
    }

    /// What a node actually registers: a tailnet or LAN address.
    #[test]
    fn a_routable_address_is_accepted() {
        for good in ["100.64.0.1", "192.0.2.10", "10.0.0.42", " 100.64.7.7 ", "2001:db8::1"] {  // leak-ok: CGNAT range-edge test, not a real node
            assert!(acceptable_node_ip(good), "{good:?} must be accepted");
        }
    }
}

#[cfg(test)]
mod heartbeat_freshness_tests {
    use super::*;

    #[test]
    fn a_gossiping_node_with_a_stale_heartbeat_is_not_online() {
        // host3, 2026-09-21: heartbeat frozen, entry kept alive by the
        // reachability prober, gossip still listing it — and `online`.
        let now = 10_000.0;
        let mut n = json!({"tier": 3, "status": "online", "last_heartbeat": now - 267.0, "ts": now - 5.0});
        demote_if_heartbeat_stale(&mut n, now);
        assert_eq!(n["status"], "unknown");
        assert!(n["status_detail"].as_str().unwrap().contains("267s"));
    }

    #[test]
    fn a_fresh_heartbeat_keeps_gossips_verdict() {
        let now = 10_000.0;
        for st in ["online", "busy"] {
            let mut n = json!({"tier": 3, "status": st, "last_heartbeat": now - 30.0});
            demote_if_heartbeat_stale(&mut n, now);
            assert_eq!(n["status"], st);
        }
    }

    #[test]
    fn registration_before_the_first_heartbeat_is_not_stale() {
        let now = 10_000.0;
        let mut n = json!({"tier": 3, "status": "online", "ts": now - 10.0});
        demote_if_heartbeat_stale(&mut n, now);
        assert_eq!(n["status"], "online");
    }

    #[test]
    fn no_timestamp_at_all_is_left_as_gossip_said() {
        let mut n = json!({"tier": 3, "status": "online"});
        demote_if_heartbeat_stale(&mut n, 10_000.0);
        assert_eq!(n["status"], "online");
    }

    #[test]
    fn edge_tiers_get_their_longer_window() {
        // 200 s of silence is a missed beat for a companion, not an outage.
        let now = 10_000.0;
        let mut n = json!({"tier": 4, "status": "online", "last_heartbeat": now - 200.0});
        demote_if_heartbeat_stale(&mut n, now);
        assert_eq!(n["status"], "online");
    }
}

#[cfg(test)]
mod model_class_tests {
    use super::{validate_model_class, ModelClassBody, ModelClassCandidateBody};

    fn cand(node: &str, backend: &str, model: Option<&str>, degraded: bool) -> ModelClassCandidateBody {
        ModelClassCandidateBody { node: node.into(), backend: backend.into(), model: model.map(str::to_string), degraded }
    }

    /// The live fleet as `served_by` sees it.
    fn served_by(node: &str, backend: &str) -> Option<String> {
        match (node, backend) {
            ("host3", "vllm") => Some("google/gemma-4-12B-it-qat-w4a16-ct".into()),
            ("host6", "ollama") => Some("gemma4:26b".into()),
            ("host8", "ollama") => Some("gemma4:e2b-it-qat".into()),
            _ => None,
        }
    }
    const NONE: &dyn Fn(&str, &str) -> Option<String> = &|_, _| None;

    /// The operator's intended declaration round-trips: order kept, NULL model
    /// kept NULL (the placement's), degraded kept, aliases accepted.
    #[test]
    fn a_valid_declaration_is_kept_in_order() {
        let body = ModelClassBody {
            candidates: vec![cand("host3", "vllm", None, false), cand("host6", "ollama", Some("gemma4:12b"), false), cand("host8", "ollama", None, true)],
            aliases: vec!["gemma4:12b-any".into()],
            pool: false,
        };
        let d = validate_model_class("Chat-Default", &body, &["fast".into()], &[], NONE).expect("valid");
        assert_eq!(d.name, "chat-default", "stored lowercase");
        assert_eq!(d.candidates.len(), 3);
        assert_eq!(d.candidates[0].model, None);
        assert_eq!(d.candidates[1].model.as_deref(), Some("gemma4:12b"));
        assert!(d.candidates[2].degraded);
        assert_eq!(d.candidates.iter().map(|c| c.node_id.as_str()).collect::<Vec<_>>(), ["host3", "host6", "host8"]);
    }

    #[test]
    fn the_rules_refuse_what_they_say_they_refuse() {
        let ok = |cands: Vec<ModelClassCandidateBody>, aliases: Vec<&str>| ModelClassBody { candidates: cands, aliases: aliases.into_iter().map(String::from).collect(), pool: false };
        let e = validate_model_class("chat-default", &ok(vec![], vec![]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("at least one candidate"), "{e}");
        let e = validate_model_class("default", &ok(vec![cand("a", "vllm", None, false)], vec![]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("built-in alias"), "{e}");
        let e = validate_model_class("c", &ok(vec![cand("a", "harness", None, false)], vec![]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("backend must be"), "{e}");
        let e = validate_model_class("c", &ok(vec![cand("a", "ollama", None, true)], vec![]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("first candidate cannot be degraded"), "{e}");
        let e = validate_model_class("c", &ok(vec![cand("a", "ollama", None, false), cand("a", "ollama", Some("x"), false)], vec![]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("listed twice"), "{e}");
        let e = validate_model_class("c", &ok(vec![cand("a", "ollama", Some("has space"), false)], vec![]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("characters outside"), "{e}");
        let e = validate_model_class("c", &ok(vec![cand("a", "ollama", None, false)], vec!["fast"]), &["fast".into()], &[], NONE).unwrap_err();
        assert!(e.contains("may not shadow"), "{e}");
        let e = validate_model_class("c", &ok(vec![cand("a", "ollama", None, false)], vec!["c"]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("own name"), "{e}");
        let e = validate_model_class("c", &ok(vec![cand("a", "ollama", None, false)], vec!["auto"]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("built-in alias"), "{e}");
        // duplicate aliases dedup with the same rule as the cross-class check.
        let e = validate_model_class("c", &ok(vec![cand("a", "ollama", None, false)], vec!["x:latest", "X"]), &[], &[], NONE).unwrap_err();
        assert!(e.contains("listed twice"), "{e}");
    }

    /// An alias may not shadow a SERVED model (a derived class), with Ollama
    /// tag rules applied: `gemma4:26b` → chat-default would turn an exact 26b
    /// pin into whatever chat-default serves.
    #[test]
    fn an_alias_may_not_shadow_a_served_model() {
        let body = ModelClassBody { candidates: vec![cand("host3", "vllm", None, false)], aliases: vec!["GEMMA4:26B:latest".into()], pool: false };
        let live: Vec<String> = vec!["gemma4:26b".into(), "google/gemma-4-12B-it-qat-w4a16-ct".into()];
        let e = validate_model_class("chat-default", &body, &live, &[], NONE).unwrap_err();
        assert!(e.contains("gemma4:26b") && e.contains("may not shadow"), "{e}");
        // A name no class carries is fine.
        let body = ModelClassBody { candidates: vec![cand("host3", "vllm", None, false)], aliases: vec!["gemma4:12b-any".into()], pool: false };
        assert!(validate_model_class("chat-default", &body, &live, &[], NONE).is_ok());
    }

    /// A class named after a served model must serve it (N2): the class-name
    /// door to the same shadowing the alias check closes.
    #[test]
    fn a_class_named_after_a_served_model_must_serve_it() {
        let live: Vec<String> = vec!["gemma4:26b".into(), "google/gemma-4-12B-it-qat-w4a16-ct".into()];
        // host3's vLLM serves the 12B, not the 26b the name promises.
        let body = ModelClassBody { candidates: vec![cand("host3", "vllm", None, false), cand("host6", "ollama", None, true)], aliases: vec![], pool: false };
        let e = validate_model_class("gemma4:26b", &body, &live, &[], &served_by).unwrap_err();
        assert!(e.contains("must serve it") && e.contains("gemma4:26b") && e.contains("host3/vllm"), "{e}");
        // The 26b-serving node first: fine, and the ordering is the point.
        let body = ModelClassBody { candidates: vec![cand("host6", "ollama", None, false), cand("host3", "vllm", None, true)], aliases: vec![], pool: false };
        assert!(validate_model_class("GEMMA4:26B", &body, &live, &[], &served_by).is_ok(), "case does not matter");
        // An explicit model on the first candidate counts as what it serves.
        let body = ModelClassBody { candidates: vec![cand("ghost", "ollama", Some("gemma4:26b:latest"), false)], aliases: vec![], pool: false };
        assert!(validate_model_class("gemma4:26b", &body, &live, &[], &served_by).is_ok());
        // An unknown first candidate with no model named: refused, not guessed.
        let body = ModelClassBody { candidates: vec![cand("ghost", "ollama", None, false)], aliases: vec![], pool: false };
        let e = validate_model_class("gemma4:26b", &body, &live, &[], &served_by).unwrap_err();
        assert!(e.contains("cannot tell"), "{e}");
        // A class not named after a served model has no such rule.
        assert!(validate_model_class("fast", &body, &live, &[], &served_by).is_ok());
    }

    #[test]
    fn served_model_lookup_and_the_unknown_nodes_note() {
        use super::{served_model_in, unknown_nodes_note};
        use crate::coordinator::classes::{build_table, Declarations, NodeFacts};
        let nodes = vec![NodeFacts {
            node_id: "host3".into(), ip: "10.0.0.1".into(),
            running: vec![("vllm".into(), "HF".into()), ("ollama".into(), "gemma4:26b".into())],
            heartbeat_age_secs: Some(1.0), inbound_ok: true, gpu: true, ..Default::default()
        }];
        let t = build_table(&nodes, &[], &Declarations::default());
        assert_eq!(served_model_in(&t, "host3", "vllm").as_deref(), Some("HF"));
        assert_eq!(served_model_in(&t, "host3", "ollama").as_deref(), Some("gemma4:26b"));
        assert_eq!(served_model_in(&t, "host3", "llamacpp"), None);
        assert_eq!(served_model_in(&t, "ghost", "vllm"), None);
        assert_eq!(unknown_nodes_note(&[]), None);
        let note = unknown_nodes_note(&["ghost".into(), "phone".into()]).unwrap();
        assert!(note.contains("ghost, phone") && note.contains("cluster verify"), "{note}");
    }

    /// A class write changes routing for every consumer: both write handlers
    /// audit, GET does not.
    #[test]
    fn model_class_writes_are_audited() {
        let src = include_str!("cluster.rs");
        let put = src.split("async fn model_class_put(").nth(1).unwrap().split("\n}\n").next().unwrap();
        let del = src.split("async fn model_class_delete(").nth(1).unwrap().split("\n}\n").next().unwrap();
        let get = src.split("async fn model_classes_get(").nth(1).unwrap().split("\n}\n").next().unwrap();
        assert!(put.contains("audit::record(") && put.contains("AuditKind::ModelClassDeclared"), "PUT audits");
        assert!(put.contains("\"unknown_nodes\": unknown_nodes"), "the audit row names the unknown nodes");
        assert!(del.contains("audit::record(") && del.contains("AuditKind::ModelClassRemoved"), "DELETE audits");
        assert!(!get.contains("audit::record("), "GET is a read");
        // The audit happens after the write succeeded, never before.
        assert!(put.find("save_class(").unwrap() < put.find("audit::record(").unwrap());
        assert!(del.find("delete_class(").unwrap() < del.find("audit::record(").unwrap());
    }

    /// An alias is one class's: class B may not silently re-point A's alias.
    #[test]
    fn an_alias_owned_by_another_class_is_refused() {
        let owned = vec![("quick".to_string(), "fast".to_string())];
        let body = ModelClassBody { candidates: vec![cand("host3", "vllm", None, false)], aliases: vec!["Quick".into()], pool: false };
        let e = validate_model_class("chat-default", &body, &["fast".into()], &owned, NONE).unwrap_err();
        assert!(e.contains("belongs to class 'fast'"), "{e}");
        // The owner may restate its own alias.
        assert!(validate_model_class("fast", &body, &["chat-default".into()], &owned, NONE).is_ok());
    }
}

#[cfg(test)]
mod placement_role_tests {
    //! Placements keyed (node, backend, ROLE): the pure rules, then the real
    //! upsert and migration against Postgres (opt-in: `NOO_BROKER_TEST_DSN`).
    use super::*;

    fn stored(backend: &str, role: &str, model: &str, env: Value) -> StoredPlacement {
        StoredPlacement { backend: backend.into(), role: role.into(), model: Some(model.into()), env, desired_state: "running".into(), target: None }
    }

    #[test]
    fn a_target_follows_the_env_rule_kept_for_the_same_model_cleared_on_a_new_one() {
        let mut gemma = stored("llamacpp", "chat", "gemma.gguf", json!({}));
        gemma.target = Some("cpu".into());
        assert_eq!(effective_target_after_upsert(Some(&gemma), Some("gemma.gguf"), None).as_deref(), Some("cpu"));
        assert_eq!(effective_target_after_upsert(Some(&gemma), None, None).as_deref(), Some("cpu"));
        assert_eq!(effective_target_after_upsert(Some(&gemma), Some("other.gguf"), None), None);
        assert_eq!(effective_target_after_upsert(Some(&gemma), Some("gemma.gguf"), Some("gpu")).as_deref(), Some("gpu"));
        assert_eq!(effective_target_after_upsert(None, Some("x"), None), None);
    }

    #[test]
    fn targets_are_checked_against_the_backend_and_the_node() {
        let gpu_node = json!({"vram_gb": 24.0, "ram_gb": 64.0});
        let cpu_node = json!({"vram_gb": 0, "ram_gb": 16.0});
        assert!(validate_target("llamacpp", Some("cpu"), &gpu_node).is_ok());
        assert!(validate_target("ollama", Some("gpu"), &gpu_node).is_ok());
        assert!(validate_target("ollama", None, &cpu_node).is_ok(), "no target is not checked");
        let e = validate_target("vllm", Some("cpu"), &gpu_node).unwrap_err();
        assert!(e.contains("vLLM runs on a GPU only"), "{e}");
        let e = validate_target("ollama", Some("gpu"), &cpu_node).unwrap_err();
        assert!(e.contains("no GPU"), "{e}");
        assert!(validate_target("ollama", Some("gpu"), &json!({})).is_ok(), "a node that reports nothing is not refused");
        assert!(validate_target("ollama", Some("tpu"), &gpu_node).is_err());
        assert!(validate_target("harness", Some("cpu"), &gpu_node).is_err());
    }

    #[test]
    fn a_neighbours_reported_sizes_are_read_as_name_and_bytes() {
        let n = json!({"model_stats": [
            {"name": "gemma4:26b", "size_bytes": 17_000_000_000u64},
            {"name": "nosize"},
            {"name": "zero", "size_bytes": 0}]});
        assert_eq!(sizes_of(&n), vec![json!({"name": "gemma4:26b", "size_bytes": 17_000_000_000u64})]);
        assert!(sizes_of(&json!({})).is_empty());
    }

    #[test]
    fn no_role_means_the_default_role_never_what_the_row_had() {
        assert_eq!(resolve_role("ollama", None).unwrap(), "chat");
        assert_eq!(resolve_role("ollama", Some("")).unwrap(), "chat");
        assert_eq!(resolve_role("ollama", Some("embed")).unwrap(), "embed");
        assert_eq!(resolve_role("harness", None).unwrap(), "harness");
        assert!(resolve_role("harness", Some("chat")).is_err());
        assert!(resolve_role("ollama", Some("harness")).is_err());
        assert!(resolve_role("ollama", Some("bogus")).is_err());
    }

    #[test]
    fn a_model_change_does_not_carry_env_over_but_the_same_model_keeps_it() {
        let harrier = stored("ollama", "embed", "harrier", json!({"OLLAMA_NUM_PARALLEL": "4"}));
        // gemma over harrier, same role, no --env: clean.
        let (m, env) = effective_after_upsert(Some(&harrier), Some("gemma4:26b-a4b-it-qat"), None);
        assert_eq!(m.as_deref(), Some("gemma4:26b-a4b-it-qat"));
        assert_eq!(env, json!({}));
        // --env given: exactly what was given.
        let (_, env) = effective_after_upsert(Some(&harrier), Some("other"), Some(&json!({"A": "1"})));
        assert_eq!(env, json!({"A": "1"}));
        // Same model re-placed with no env: kept.
        let (_, env) = effective_after_upsert(Some(&harrier), Some("harrier"), None);
        assert_eq!(env, json!({"OLLAMA_NUM_PARALLEL": "4"}));
        // No model given (a state change): kept.
        let (m, env) = effective_after_upsert(Some(&harrier), None, None);
        assert_eq!((m.as_deref(), env), (Some("harrier"), json!({"OLLAMA_NUM_PARALLEL": "4"})));
    }

    #[test]
    fn the_fit_set_replaces_only_the_same_backend_and_role() {
        let existing = vec![
            stored("ollama", "chat", "gemma4:26b-a4b-it-qat", json!({})),
            stored("ollama", "embed", "harrier", json!({})),
            stored("harness", "harness", "auto", json!({})),
        ];
        let new = stored("ollama", "embed", "bge-m3", json!({}));
        let specs = fit_specs(&existing, Some(("ollama", "embed", Some("harrier"))), Some(&new));
        let names: Vec<_> = specs.iter().map(|s| format!("{}/{}", s.role, s.model)).collect();
        assert_eq!(names, vec!["chat/gemma4:26b-a4b-it-qat", "embed/bge-m3"], "harness holds no model memory");
    }

    #[test]
    fn the_fit_set_keeps_other_embed_models_when_one_is_added_or_replaced() {
        let existing = vec![
            stored("ollama", "embed", "harrier", json!({})),
            stored("ollama", "embed", "nomic-embed-code", json!({})),
        ];
        // Re-placing nomic replaces only nomic.
        let new = stored("ollama", "embed", "nomic-embed-code", json!({}));
        let specs = fit_specs(&existing, Some(("ollama", "embed", Some("nomic-embed-code"))), Some(&new));
        assert_eq!(specs.iter().map(|s| s.model.as_str()).collect::<Vec<_>>(), vec!["harrier", "nomic-embed-code"]);
        // Placing a third replaces neither.
        let third = stored("ollama", "embed", "bge-m3", json!({}));
        let specs = fit_specs(&existing, Some(("ollama", "embed", Some("bge-m3"))), Some(&third));
        assert_eq!(specs.len(), 3);
        // A chat slot ignores the model: chat is one row per backend.
        let chat = vec![stored("ollama", "chat", "a", json!({}))];
        let newer = stored("ollama", "chat", "b", json!({}));
        let specs = fit_specs(&chat, Some(("ollama", "chat", Some("b"))), Some(&newer));
        assert_eq!(specs.iter().map(|s| s.model.as_str()).collect::<Vec<_>>(), vec!["b"]);
    }

    #[test]
    fn placement_slot_is_keyed_by_model_for_embed_only() {
        let h = stored("ollama", "embed", "harrier", json!({}));
        assert!(same_placement_slot(&h, "ollama", "embed", Some("harrier")));
        assert!(!same_placement_slot(&h, "ollama", "embed", Some("bge-m3")));
        assert!(same_placement_slot(&h, "ollama", "embed", None), "no model names any embed row");
        let c = stored("ollama", "chat", "a", json!({}));
        assert!(same_placement_slot(&c, "ollama", "chat", Some("other")), "chat is one row per backend");
        assert!(!same_placement_slot(&c, "vllm", "chat", None));
    }

    #[test]
    fn the_upsert_text_is_keyed_by_role_and_resets_env_on_a_model_change() {
        assert!(
            PLACEMENT_UPSERT.contains("ON CONFLICT (node_id, backend, role, (CASE WHEN role = 'embed' THEN model ELSE '' END)) DO UPDATE"),
            "the conflict target must be migration 098's index expression: embed rows are keyed by model"
        );
        assert!(!PLACEMENT_UPSERT.contains("role  = COALESCE"), "role is the key, never inherited");
        // 11 binds, $1..$11 ($10 = the hardware target, $11 = the memory limit).
        assert!(PLACEMENT_UPSERT.contains("$11") && !PLACEMENT_UPSERT.contains("$12"));
    }

    async fn scratch(name: &str) -> Option<(sqlx::PgPool, sqlx::PgPool)> {
        let dsn = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty())?;
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await.expect("connect");
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name} (FORCE)"))).execute(&admin).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.expect("create scratch db");
        let db = pool(&dsn, name).await;
        Some((admin, db))
    }

    /// A pool on the scratch database. A fresh install lands its tables in
    /// schema `mesh`; the runtime role finds them through this search_path
    /// (public when no mesh schema exists). The migrator resets search_path on
    /// the connection it used, so reconnect after `apply`.
    async fn pool(dsn: &str, name: &str) -> sqlx::PgPool {
        use std::str::FromStr as _;
        let (head, _) = dsn.rsplit_once('/').expect("dsn path");
        let opts = sqlx::postgres::PgConnectOptions::from_str(&format!("{head}/{name}")).expect("dsn").options([("search_path", "mesh,public")]);
        sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect scratch")
    }

    async fn drop_db(admin: &sqlx::PgPool, db: sqlx::PgPool, name: &str) {
        db.close().await;
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name} (FORCE)"))).execute(admin).await;
    }

    async fn upsert(db: &sqlx::PgPool, backend: &str, model: Option<&str>, env: Option<Value>, role: &str) {
        sqlx::query(PLACEMENT_UPSERT)
            .bind("host6").bind(backend).bind(model.map(str::to_string)).bind(None::<String>).bind(None::<i32>)
            .bind(None::<bool>).bind(env).bind("running").bind(role).bind(None::<String>).bind(None::<i64>)
            .execute(db).await.expect("upsert");
    }

    async fn rows(db: &sqlx::PgPool) -> Vec<(String, String, Option<String>, Value)> {
        sqlx::query_as("SELECT backend, role, model, env FROM noo_backend_placements WHERE node_id = 'host6' ORDER BY role, model")
            .fetch_all(db).await.unwrap()
    }

    /// The live incident, on the real upsert and the real migrated schema.
    #[tokio::test]
    async fn two_roles_on_one_backend_coexist_and_nothing_carries_over() {
        let Some((admin, db)) = scratch("mrp_roles_test").await else { return };
        std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret");
        for ext in ["vector", "pg_trgm"] {
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}"))).execute(&db).await.expect("extension");
        }
        crate::mesh_migrate::apply(&db).await.expect("apply");
        db.close().await;
        let db = pool(&std::env::var("NOO_BROKER_TEST_DSN").unwrap(), "mrp_roles_test").await;

        // chat first, then the embedder beside it: the second place must not replace the first.
        upsert(&db, "ollama", Some("gemma4:26b-a4b-it-qat"), None, "chat").await;
        upsert(&db, "ollama", Some("harrier"), Some(json!({"OLLAMA_NUM_PARALLEL": "4"})), "embed").await;
        let r = rows(&db).await;
        assert_eq!(r.len(), 2, "{r:?}");
        assert_eq!((r[0].1.as_str(), r[0].2.as_deref()), ("chat", Some("gemma4:26b-a4b-it-qat")));
        assert_eq!((r[1].1.as_str(), r[1].2.as_deref()), ("embed", Some("harrier")));
        assert_eq!(r[0].3, json!({}), "the chat role does not inherit the embedder's env");

        // The incident sequence: re-place gemma with no role and no env. It is the CHAT
        // role, and the embed row is untouched.
        upsert(&db, "ollama", Some("gemma4:26b-a4b-it-qat"), None, "chat").await;
        let r = rows(&db).await;
        assert_eq!(r.len(), 2);
        assert_eq!((r[1].1.as_str(), r[1].3.clone()), ("embed", json!({"OLLAMA_NUM_PARALLEL": "4"})));
        assert_eq!(r[0].3, json!({}));

        // i150: a NEW embed model is a second row (a second space on this node), and the first
        // is untouched. Same model, no env: env is kept.
        upsert(&db, "ollama", Some("bge-m3"), None, "embed").await;
        let r = rows(&db).await;
        assert_eq!(r.len(), 3, "{r:?}");
        assert_eq!((r[1].2.as_deref(), r[1].3.clone()), (Some("bge-m3"), json!({})));
        assert_eq!((r[2].2.as_deref(), r[2].3.clone()), (Some("harrier"), json!({"OLLAMA_NUM_PARALLEL": "4"})));
        upsert(&db, "ollama", Some("bge-m3"), Some(json!({"OLLAMA_NUM_PARALLEL": "2"})), "embed").await;
        upsert(&db, "ollama", Some("bge-m3"), None, "embed").await;
        assert_eq!(rows(&db).await[1].3, json!({"OLLAMA_NUM_PARALLEL": "2"}), "same model keeps env");
        // chat (one row per backend+role) still REPLACES: a new chat model resets env.
        upsert(&db, "ollama", Some("gemma4:12b"), None, "chat").await;
        let r = rows(&db).await;
        assert_eq!(r.len(), 3, "a new chat model replaces, never adds");
        assert_eq!((r[0].1.as_str(), r[0].2.as_deref(), r[0].3.clone()), ("chat", Some("gemma4:12b"), json!({})));

        // The non-chat set: this ollama has a chat row, so it stays a chat target.
        let nc = crate::repo::cluster::placements_non_chat(&db).await.unwrap();
        assert!(nc.is_empty(), "a backend with a running chat row is not non-chat: {nc:?}");
        sqlx::query("DELETE FROM noo_backend_placements WHERE role = 'chat'").execute(&db).await.unwrap();
        let nc = crate::repo::cluster::placements_non_chat(&db).await.unwrap();
        assert_eq!(nc, vec![("host6".to_string(), "ollama".to_string())], "embed-only ollama is excluded from chat");
        drop_db(&admin, db, "mrp_roles_test").await;
    }

    /// Migration 087 on a database that already has rows in the OLD shape:
    /// nothing lost, the old unique pair replaced by the triple.
    #[tokio::test]
    async fn migration_087_backfills_and_rekeys_existing_rows() {
        let Some((admin, db)) = scratch("mrp_migrate_test").await else { return };
        sqlx::raw_sql(
            "CREATE TABLE noo_backend_placements (
                 id serial PRIMARY KEY, node_id text NOT NULL, backend text NOT NULL, model text, image text,
                 port integer, tls boolean NOT NULL DEFAULT false, env jsonb NOT NULL DEFAULT '{}'::jsonb,
                 desired_state text NOT NULL DEFAULT 'running', role text,
                 updated_at timestamptz NOT NULL DEFAULT now(),
                 CONSTRAINT uq_placement_node_backend UNIQUE (node_id, backend));
             INSERT INTO noo_backend_placements (node_id, backend, model, role) VALUES
                 ('host6', 'ollama', 'gemma4:26b-a4b-it-qat', NULL),
                 ('host2', 'ollama', 'harrier', 'embed'),
                 ('host8', 'vllm', 'qwen', '');",
        )
        .execute(&db).await.expect("old-shape fixture");

        // The OLD shape cannot take a second role: the new upsert has no key to conflict on.
        let old = sqlx::query(PLACEMENT_UPSERT)
            .bind("host6").bind("ollama").bind(Some("harrier".to_string())).bind(None::<String>).bind(None::<i32>)
            .bind(None::<bool>).bind(None::<Value>).bind("running").bind("embed").bind(None::<String>).bind(None::<i64>)
            .execute(&db).await;
        assert!(old.is_err(), "before 087 there is no (node, backend, role) key");

        let mig = crate::mesh_migrate::MIGRATIONS.iter().find(|m| m.revision == "087_placement_role_key").expect("087");
        sqlx::raw_sql(mig.sql).execute(&db).await.expect("087");
        // 088 adds the target column the upsert writes.
        let m088 = crate::mesh_migrate::MIGRATIONS.iter().find(|m| m.revision == "088_placement_target_usage").expect("088");
        sqlx::raw_sql(m088.sql).execute(&db).await.expect("088");

        let r: Vec<(String, String, Option<String>)> =
            sqlx::query_as("SELECT node_id, role, model FROM noo_backend_placements ORDER BY node_id").fetch_all(&db).await.unwrap();
        assert_eq!(r, vec![
            ("host2".into(), "embed".into(), Some("harrier".into())),
            ("host6".into(), "chat".into(), Some("gemma4:26b-a4b-it-qat".into())),
            ("host8".into(), "chat".into(), Some("qwen".into())),
        ], "NULL and blank roles become chat; no row lost");

        // Re-running is harmless.
        sqlx::raw_sql(mig.sql).execute(&db).await.expect("087 is idempotent");

        // 098 widens the key with the model for embed rows (the upsert's ON CONFLICT names it).
        let m098 = crate::mesh_migrate::MIGRATIONS.iter().find(|m| m.revision == crate::mesh_migrate::EMBED_PLACEMENT_MODEL_REVISION).expect("embed placement model revision");
        sqlx::raw_sql(m098.sql).execute(&db).await.expect("098");
        sqlx::raw_sql(m098.sql).execute(&db).await.expect("098 is idempotent");

        // And now the second role lands beside the first.
        upsert(&db, "ollama", Some("harrier"), None, "embed").await;
        assert_eq!(rows(&db).await.len(), 2);
        // A second embed MODEL on the same (node, backend) is its own row; chat is still one row.
        upsert(&db, "ollama", Some("nomic-embed-code"), None, "embed").await;
        upsert(&db, "ollama", Some("gemma4:12b"), None, "chat").await;
        let r = rows(&db).await;
        assert_eq!(r.len(), 3, "{r:?}");
        assert_eq!(
            r.iter().map(|x| (x.1.as_str(), x.2.as_deref())).collect::<Vec<_>>(),
            vec![("chat", Some("gemma4:12b")), ("embed", Some("harrier")), ("embed", Some("nomic-embed-code"))],
            "chat replaced in place; both embed models kept"
        );
        drop_db(&admin, db, "mrp_migrate_test").await;
    }
}

#[cfg(test)]
mod proposer_tests {
    use super::proposer_of;

    #[test]
    fn provenance_is_the_verified_caller_never_a_request_field() {
        assert_eq!(proposer_of(Some("alice/laptop"), Some("host3")), "alice/laptop");
        assert_eq!(proposer_of(None, Some("host3")), "host3");
        assert_eq!(proposer_of(None, None), "unknown");
        assert_eq!(proposer_of(Some(""), None), "unknown");
    }

    #[test]
    fn the_handler_does_not_read_proposed_by_from_the_body() {
        let src = include_str!("cluster.rs");
        let start = src.find("async fn cluster_propose(").unwrap();
        let rest = &src[start..];
        let end = rest.find("\n}\n").unwrap();
        let body = &rest[..end];
        assert!(body.contains("proposer_of("));
        assert!(!body.contains("body.get(\"proposed_by\")"), "caller-asserted provenance is back");
        assert!(!body.contains("body.get(\"conversation_id\")"));
    }
}

#[cfg(test)]
mod backend_image_ref_tests {
    use super::backend_image_ref;
    use std::collections::HashMap;

    fn with(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned()
    }

    const PINNED: &str = "vllm/vllm-openai:v0.25.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// desired-config (the reconciler's source) carries the lock's digest for
    /// a placement with no image of its own — from the REAL 0.6.8 signed
    /// lock rows, through the compose line that renders the gateway's env,
    /// exactly as the launcher exports them (lib-dist.sh
    /// dist_load_stack_lock: `<name>@sha256:…` → `NOO_IMAGE_DIGEST_<NAME>=@sha256:…`).
    #[test]
    fn desired_config_sends_the_lock_digest_from_a_real_lock() {
        const LOCK: &str = "# stack v0.6.8\n\
            ollama@sha256:5d3a2f25f9825628daba94dc0b1d421c7d57d6c03ae5faa9ba050e058bab8241\n\
            source:trellion@bf4de8b20df97648a6ee1150cb073e738762dcc4\n\
            vllm@sha256:fc56161ee42a011aeee78b65d0a81b6683c7d04402fd40503d14d4d6c98f07cb\n";
        let mut env: HashMap<String, String> = HashMap::new();
        for line in LOCK.lines().filter(|l| !l.starts_with('#')) {
            let Some((img, dig)) = line.split_once('@') else { continue };
            if dig.starts_with("sha256:") && img.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
                env.insert(format!("NOO_IMAGE_DIGEST_{}", img.to_uppercase().replace('-', "_")), format!("@{dig}"));
            }
        }
        let compose = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docker-compose.cluster.yml")).unwrap();
        for var in ["NOO_BACKEND_IMAGE_OLLAMA", "NOO_BACKEND_IMAGE_VLLM"] {
            let line = compose.lines().find_map(|l| l.trim().strip_prefix(&format!("- {var}="))).unwrap_or_else(|| panic!("{var} not in compose"));
            env.insert(var.into(), interpolate(line, &env));
        }
        let get = |k: &str| env.get(k).cloned();
        assert_eq!(
            super::placement_image("ollama", None, &get).as_deref(),
            Some("ollama/ollama:0.40.5@sha256:5d3a2f25f9825628daba94dc0b1d421c7d57d6c03ae5faa9ba050e058bab8241"),
        );
        let vllm = super::placement_image("vllm", Some(String::new()), &get).unwrap();
        assert!(vllm.starts_with("vllm/vllm-openai:") && vllm.ends_with("@sha256:fc56161ee42a011aeee78b65d0a81b6683c7d04402fd40503d14d4d6c98f07cb"), "{vllm}");
        // The operator's workaround: an override with a digest goes out as given.
        let mut over = env.clone();
        over.insert("OLLAMA_IMAGE".into(), "ollama/ollama:0.40.5@sha256:5d3a".into());
        assert_eq!(super::placement_image("ollama", None, &|k: &str| over.get(k).cloned()).as_deref(), Some("ollama/ollama:0.40.5@sha256:5d3a"));
        // A placement that names its own image keeps it.
        assert_eq!(super::placement_image("ollama", Some("my/ollama:1@sha256:cc".into()), &get).as_deref(), Some("my/ollama:1@sha256:cc"));
        // A backend the controller pins nothing for still sends nothing.
        assert_eq!(super::placement_image("reranker", None, &get), None);
    }

    /// Structural: desired-config fills every placement's image through
    /// `placement_image`, not the raw column.
    #[test]
    fn desired_config_fills_placement_images_from_the_lock() {
        let src = include_str!("cluster.rs");
        let body = src.split("async fn desired_config_get(").nth(1).unwrap().split("\nasync fn ").next().unwrap();
        assert!(body.contains("let image = placement_image(&backend, image, "), "desired-config must send placement_image(..), not the raw column");
    }

    /// `${A:-default}` (nested) as compose interpolates it, for the test above.
    fn interpolate(s: &str, env: &HashMap<String, String>) -> String {
        let mut out = String::new();
        let mut rest = s;
        while let Some(i) = rest.find("${") {
            out.push_str(&rest[..i]);
            let body = &rest[i + 2..];
            let (mut depth, mut end) = (1, 0);
            for (j, c) in body.char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => { depth -= 1; if depth == 0 { end = j; break; } }
                    _ => {}
                }
            }
            let inner = &body[..end];
            let (name, default) = inner.split_once(":-").unwrap_or((inner, ""));
            match env.get(name).filter(|v| !v.is_empty()) {
                Some(v) => out.push_str(v),
                None => out.push_str(&interpolate(default, env)),
            }
            rest = &body[end + 1..];
        }
        out.push_str(rest);
        out
    }

    /// The controller sends the lock-pinned ref even when no operator override
    /// is set (until now it sent one only when VLLM_IMAGE was in its env).
    #[test]
    fn the_locked_digest_ref_is_sent_without_an_operator_override() {
        let get = with(&[("NOO_BACKEND_IMAGE_VLLM", PINNED)]);
        assert_eq!(backend_image_ref("vllm", &get).as_deref(), Some(PINNED));
    }

    #[test]
    fn an_operator_override_wins_and_blank_values_are_absent() {
        let get = with(&[("VLLM_IMAGE", "my/vllm:1@sha256:aa"), ("NOO_BACKEND_IMAGE_VLLM", PINNED)]);
        assert_eq!(backend_image_ref("vllm", &get).as_deref(), Some("my/vllm:1@sha256:aa"));
        let blank = with(&[("VLLM_IMAGE", "  "), ("NOO_BACKEND_IMAGE_VLLM", PINNED)]);
        assert_eq!(backend_image_ref("vllm", &blank).as_deref(), Some(PINNED));
        assert_eq!(backend_image_ref("vllm", &with(&[])), None);
        assert_eq!(backend_image_ref("reranker", &get), None);
    }

    #[test]
    fn each_node_backend_has_its_own_locked_variable() {
        for (b, v) in [("vllm-secondary", "NOO_BACKEND_IMAGE_VLLM_SECONDARY"), ("ollama", "NOO_BACKEND_IMAGE_OLLAMA")] {
            assert_eq!(backend_image_ref(b, &with(&[(v, "x/y:1@sha256:bb")])).as_deref(), Some("x/y:1@sha256:bb"), "{b}");
        }
        // llamacpp / embedding forward only an operator override
        assert_eq!(backend_image_ref("llamacpp", &with(&[("LLAMACPP_IMAGE", "a/b:2")])).as_deref(), Some("a/b:2"));
        assert_eq!(backend_image_ref("llamacpp", &with(&[("NOO_BACKEND_IMAGE_LLAMACPP", "a/b:2")])), None);
    }

    /// A floating override is never forwarded: `VLLM_IMAGE=…:latest` used to
    /// replace the lock's pinned ref (and compose renders it into the locked
    /// variable too, so both are skipped and the node keeps its own default).
    #[test]
    fn a_floating_ref_is_never_sent() {
        let over = with(&[("VLLM_IMAGE", "vllm/vllm-openai:latest"), ("NOO_BACKEND_IMAGE_VLLM", PINNED)]);
        assert_eq!(backend_image_ref("vllm", &over).as_deref(), Some(PINNED), "the lock's ref, not the floating override");
        let both = with(&[("VLLM_IMAGE", "vllm/vllm-openai:latest"), ("NOO_BACKEND_IMAGE_VLLM", "vllm/vllm-openai:latest")]);
        assert_eq!(backend_image_ref("vllm", &both), None, "nothing floating is sent; the node uses its versioned default");
        assert_eq!(backend_image_ref("ollama", &with(&[("OLLAMA_IMAGE", "ollama/ollama")])), None, "no tag is floating");
        // A version tag without a digest is not floating (a rail node verifies the staged tar).
        assert_eq!(backend_image_ref("vllm", &with(&[("VLLM_IMAGE", "vllm/vllm-openai:v0.29.0")])).as_deref(), Some("vllm/vllm-openai:v0.29.0"));
    }

    #[test]
    fn floating_means_latest_or_untagged_without_a_digest() {
        for f in ["vllm/vllm-openai:latest", "vllm/vllm-openai", "ollama/ollama", "registry:5000/x/y", "registry:5000/x/y:latest", "x:"] {
            assert!(super::is_floating_image_ref(f), "{f}");
        }
        for p in ["vllm/vllm-openai:v0.25.0", "registry:5000/x/y:1.2", PINNED, "vllm/vllm-openai:latest@sha256:00", "ghcr.io/noomesh/llamacpp:v0.6.7"] {
            assert!(!super::is_floating_image_ref(p), "{p}");
        }
    }
}

#[cfg(test)]
mod no_address_tests {
    use crate::node_link::no_address_message;

    #[test]
    fn a_known_node_without_an_address_is_not_called_not_found() {
        let m = no_address_message("gpu-box");
        assert!(m.contains("gpu-box") && m.contains("no reachable address"), "{m}");
        assert!(m.contains("NODE_IP"), "{m}");
        assert!(!m.contains("not found"), "{m}");
    }
}

#[cfg(test)]
mod start_over_the_bus_tests {
    /// `/start` is a bus op (`node-agent-go/internal/api/rpc.go`). A link
    /// built from an address alone has no node id and never uses the bus,
    /// so each `/start` caller must resolve its link by id. A source pin,
    /// because the handlers need an AppState no unit test can build.
    #[test]
    fn every_start_caller_resolves_its_link_by_node_id() {
        let src = include_str!("cluster.rs");
        let src = src.split("mod start_over_the_bus_tests").next().unwrap();
        for f in ["async fn start_backend_core(", "async fn models_cache(", "async fn models_pull("] {
            let body = src.split(f).nth(1).expect(f).split("\n}\n").next().unwrap();
            assert!(body.contains("NodeLink::for_node("), "{f} must resolve its link with for_node");
            assert!(!body.contains("NodeLink::for_base("), "{f} sends /start by address: it never rides the bus");
        }
    }
}
