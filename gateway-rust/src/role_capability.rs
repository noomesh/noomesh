// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A node's capabilities, DERIVED from its role placements.
//!
//! One chain, no second source of truth:
//!
//! ```text
//! noo_backend_placements (node, backend, ROLE, model)     <- the declaration
//!        +  the node's heartbeat (model_presence, running_backends, model_stats)
//!        =  role capabilities  {role, backend, model, state, resident}
//!        ->  `noo cluster status/show`, /api/cluster/nodes, and ROUTING
//! ```
//!
//! Routing used to infer what a node could do some other way: the agent's
//! gossip `capabilities` (container names, model-name substrings, a single
//! embed target), the backend kind, "the first placement". The result, live on
//! 2026-10-08: an host6 whose embed placement had been replaced by chat kept
//! being offered every embedding request (`mesh_targets_resolved
//! kept_nodes=host6,...`, then `embed_node_failed`), until its agent next
//! reconciled and gossiped again. The declaration is the gateway's own; it does
//! not need to wait for a node to stop saying something.
//!
//! ## States
//!
//! * `live`    - the node reports the placed model present (ollama), or the
//!   backend's container is running (every other kind).
//! * `unknown` - the node says nothing about it (an agent that predates
//!   `model_presence`, or a check that could not run). Routable: today's
//!   behaviour, unchanged for an old agent.
//! * `missing` - the node reports the placed model ABSENT. Not routable.
//! * `down`    - the node reports its backend not running. Not routable.
//! * `stopped` - the placement is declared `stopped`. Not routable.

use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// One row of `noo_backend_placements`, as the derivation needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementFact {
    pub node_id: String,
    pub backend: String,
    pub model: Option<String>,
    pub role: String,
    pub desired_state: String,
}

/// The roles routing reads. Anything else in the vocabulary (chat, harness) is
/// derived and displayed identically; only these gate a mesh capability.
pub fn role_for_capability(capability: &str) -> Option<&'static str> {
    match capability {
        "embed" => Some("embed"),
        "rerank" => Some("rerank"),
        _ => None,
    }
}

/// The backend that serves the rerank role and nothing else: llama.cpp run
/// with `--reranking` (`noo cluster place <node> reranker <file>.gguf`).
pub(crate) const RERANKER_BACKEND: &str = "reranker";

/// The role a placement SERVES, from its backend and its stored role.
///
/// A `reranker` serves `rerank`, whatever its row says. Until 0.6.30-rc.6 a
/// bare `noo cluster place <node> reranker <file>.gguf` (the documented form)
/// stored role `chat`, so routing never found a rerank node. Those rows are
/// not migrated: [`derive`] (the rerank gate and the capabilities) and
/// [`placed_model`] read them as rerank. Every other backend's role is what
/// was stored.
pub(crate) fn effective_role<'a>(backend: &str, stored: &'a str) -> &'a str {
    if backend == RERANKER_BACKEND {
        "rerank"
    } else {
        stored
    }
}

fn norm(m: &str) -> String {
    m.trim().strip_suffix(":latest").unwrap_or(m.trim()).to_string()
}

fn entry_role(e: &Value) -> &str {
    match e["role"].as_str() {
        Some("") | None => "chat",
        Some(r) => r,
    }
}

/// Resident bytes the node MEASURED for `model` (ollama /api/ps), if reported.
fn resident_bytes(node: &Value, model: &str) -> Option<u64> {
    let want = norm(model);
    node.get("model_stats")?.as_array()?.iter().find_map(|s| {
        (norm(s["name"].as_str()?) == want)
            .then(|| s["resident_bytes"].as_u64().filter(|b| *b > 0))
            .flatten()
    })
}

/// Derive the role capabilities of one node from its placements and heartbeat.
pub fn derive(node: &Value, rows: &[PlacementFact]) -> Vec<Value> {
    let running = node.get("running_backends").and_then(|v| v.as_object());
    let presence = node.get("model_presence").and_then(|v| v.as_object());
    let mut out = Vec::new();
    for r in rows {
        let role = effective_role(&r.backend, &r.role);
        let model = r.model.clone().unwrap_or_default();
        let mut present: Option<bool> = None;
        if let Some(p) = presence {
            for (k, e) in p {
                let of_backend = k == &r.backend || k.strip_prefix(r.backend.as_str()).is_some_and(|s| s.starts_with('#'));
                if of_backend && effective_role(&r.backend, entry_role(e)) == role && (model.is_empty() || e["model"].as_str().map(norm) == Some(norm(&model))) {
                    present = e["present"].as_bool();
                    break;
                }
            }
        }
        let state = if r.desired_state != "running" {
            "stopped"
        } else if running.is_some_and(|m| !m.contains_key(&r.backend)) && r.backend != "harness" {
            "down"
        } else if present == Some(false) {
            "missing"
        } else if present == Some(true) || (running.is_some_and(|m| m.contains_key(&r.backend)) && r.backend != "ollama") {
            // Reported present, or a non-ollama backend whose container runs
            // (there is no model server to ask).
            "live"
        } else {
            "unknown"
        };
        out.push(json!({
            "role": role,
            "backend": r.backend,
            "model": r.model,
            "state": state,
            "present": present,
            "resident_bytes": resident_bytes(node, &model),
        }));
    }
    out.sort_by(|a, b| {
        let key = |v: &Value| (if v["role"] == "chat" { 0 } else { 1 }, v["role"].as_str().unwrap_or("").to_string());
        key(a).cmp(&key(b))
    });
    out
}

/// A routable state: the node can be handed work for this role.
pub fn routable(state: &str) -> bool {
    matches!(state, "live" | "unknown")
}

/// `chat:gemma4:26b · embed:harrier` - what a node serves, for one line.
/// A placed-but-missing model shows as such; a stopped one is omitted.
pub fn summary(caps: &[Value]) -> String {
    caps.iter()
        .filter(|c| c["state"] != "stopped")
        .map(|c| {
            let base = format!("{}:{}", c["role"].as_str().unwrap_or("?"), c["model"].as_str().unwrap_or("?"));
            match c["state"].as_str() {
                Some("missing") => format!("{base} (missing)"),
                Some("down") => format!("{base} (down)"),
                _ => base,
            }
        })
        .collect::<Vec<_>>()
        .join(" \u{b7} ")
}

/// Does a node serve `role` right now, judged from its capabilities?
pub fn serves(caps: &[Value], role: &str) -> bool {
    caps.iter().any(|c| c["role"] == role && routable(c["state"].as_str().unwrap_or("")))
}

type FactCache = Mutex<Option<(Instant, Vec<PlacementFact>)>>;

fn cache() -> &'static FactCache {
    static CACHE: OnceLock<FactCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

/// Every placement row (all states), cached for a few seconds: this sits on
/// the embed/rerank request path, and placements change at operator speed.
/// A stale entry costs at most one TTL of the old routing.
pub async fn all_facts(db: &sqlx::PgPool) -> Result<Vec<PlacementFact>, sqlx::Error> {
    const TTL: Duration = Duration::from_secs(3);
    if let Ok(g) = cache().lock() {
        if let Some((at, rows)) = g.as_ref() {
            if at.elapsed() < TTL {
                return Ok(rows.clone());
            }
        }
    }
    let rows: Vec<(String, String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT node_id, backend, model, role, desired_state FROM noo_backend_placements ORDER BY node_id, backend, role",
    )
    .fetch_all(db)
    .await?;
    let facts: Vec<PlacementFact> = rows
        .into_iter()
        .map(|(node_id, backend, model, role, desired_state)| PlacementFact { node_id, backend, model, role, desired_state })
        .collect();
    if let Ok(mut g) = cache().lock() {
        *g = Some((Instant::now(), facts.clone()));
    }
    Ok(facts)
}

/// The model `node_id`'s running placement for `role` declares, read through
/// [`effective_role`]. For naming what a reranker serves when its agent
/// reports no `model_presence` for it (only ollama reports presence).
pub fn placed_model(facts: &[PlacementFact], node_id: &str, role: &str) -> Option<String> {
    facts
        .iter()
        .filter(|f| f.node_id == node_id && f.desired_state == "running" && effective_role(&f.backend, &f.role) == role)
        .find_map(|f| f.model.clone().filter(|m| !m.trim().is_empty()))
}

/// [`placed_model`] over the cached placement facts; None when unreadable.
pub async fn node_placed_model(db: &sqlx::PgPool, node_id: &str, role: &str) -> Option<String> {
    placed_model(&all_facts(db).await.ok()?, node_id, role)
}

/// Drop the cache after a placement write, so routing sees the write at once.
pub fn invalidate() {
    if let Ok(mut g) = cache().lock() {
        *g = None;
    }
}

/// Can `node_id` be handed `role` work (embed, rerank) right now?
///
/// `Some(false)` when the node has no running placement for the role (a
/// chat-only node never gets embed traffic) or every one is missing/down.
/// `None` when the declaration cannot be read: not being able to look is not a
/// reason to drop a candidate.
pub async fn node_serves_role(state: &crate::state::AppState, node_id: &str, role: &str) -> Option<bool> {
    let facts = all_facts(&state.db).await.ok()?;
    let mine: Vec<PlacementFact> = facts.into_iter().filter(|f| f.node_id == node_id).collect();
    let node = match state.js.get_key_value("mesh_nodes").await {
        Ok(kv) => match kv.get(node_id).await {
            Ok(Some(e)) => serde_json::from_slice::<Value>(&e).unwrap_or_else(|_| json!({})),
            _ => json!({}),
        },
        Err(_) => json!({}),
    };
    Some(serves(&derive(&node, &mine), role))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(backend: &str, model: &str, role: &str) -> PlacementFact {
        PlacementFact { node_id: "host6".into(), backend: backend.into(), model: Some(model.into()), role: role.into(), desired_state: "running".into() }
    }

    fn host6() -> Value {
        json!({
            "running_backends": {"ollama": "gemma4:26b-a4b-it-qat"},
            "model_presence": {
                "ollama": {"model": "gemma4:26b-a4b-it-qat", "role": "chat", "present": true},
                "ollama#embed": {"model": "harrier", "role": "embed", "present": true}
            },
            "model_stats": [{"name": "harrier:latest", "resident_bytes": 1_100_000_000u64}]
        })
    }

    #[test]
    fn one_ollama_with_chat_and_embed_serves_both_roles() {
        let caps = derive(&host6(), &[fact("ollama", "gemma4:26b-a4b-it-qat", "chat"), fact("ollama", "harrier", "embed")]);
        assert!(serves(&caps, "chat") && serves(&caps, "embed"), "{caps:?}");
        assert_eq!(summary(&caps), "chat:gemma4:26b-a4b-it-qat \u{b7} embed:harrier");
        assert_eq!(caps[1]["resident_bytes"], json!(1_100_000_000u64), "measured size rides along");
    }

    #[test]
    fn a_chat_only_node_serves_no_embed() {
        let caps = derive(&host6(), &[fact("ollama", "gemma4:26b-a4b-it-qat", "chat")]);
        assert!(serves(&caps, "chat"));
        assert!(!serves(&caps, "embed"), "no embed placement -> zero embed traffic, whatever gossip says");
    }

    #[test]
    fn replacing_the_embed_role_flips_routing_with_no_agent_involvement() {
        let node = host6();
        let before = derive(&node, &[fact("ollama", "gemma4:26b-a4b-it-qat", "chat"), fact("ollama", "harrier", "embed")]);
        // The operator unplaces the embed role; the node's heartbeat is unchanged.
        let after = derive(&node, &[fact("ollama", "gemma4:26b-a4b-it-qat", "chat")]);
        assert!(serves(&before, "embed") && !serves(&after, "embed"));
    }

    #[test]
    fn a_placed_but_missing_model_is_shown_and_not_routable() {
        let mut node = host6();
        node["model_presence"]["ollama#embed"]["present"] = json!(false);
        let caps = derive(&node, &[fact("ollama", "gemma4:26b-a4b-it-qat", "chat"), fact("ollama", "harrier", "embed")]);
        assert!(!serves(&caps, "embed") && serves(&caps, "chat"));
        assert!(summary(&caps).contains("embed:harrier (missing)"), "{}", summary(&caps));
    }

    #[test]
    fn an_old_agent_that_reports_nothing_keeps_todays_behaviour() {
        let caps = derive(&json!({}), &[fact("ollama", "harrier", "embed")]);
        assert_eq!(caps[0]["state"], "unknown");
        assert!(serves(&caps, "embed"));
    }

    #[test]
    fn a_stopped_or_down_placement_is_not_routable() {
        let mut stopped = fact("ollama", "harrier", "embed");
        stopped.desired_state = "stopped".into();
        assert!(!serves(&derive(&host6(), &[stopped]), "embed"));
        let node = json!({"running_backends": {"vllm": "m"}});
        assert!(!serves(&derive(&node, &[fact("ollama", "harrier", "embed")]), "embed"));
    }

    /// The documented placement (0.6.30-rc.5 rehearsal): `noo cluster place
    /// <node> reranker <file>.gguf`, no `--role`. The gateway stores role
    /// rerank, and once the agent reports the container running the node
    /// serves rerank (and never chat). Until rc.6 this stored `chat`, and
    /// `/api/external/rerank` always fell back to the chat model.
    #[test]
    fn a_bare_placed_reranker_serves_rerank_once_its_container_runs() {
        let role = crate::routes::cluster::resolve_role("reranker", None).expect("a bare reranker place is accepted");
        assert_eq!(role, "rerank", "a bare reranker place stores the rerank role");
        let rows = [fact("reranker", "bge-reranker-v2-m3-Q8_0.gguf", &role)];
        let running = json!({"running_backends": {"reranker": "bge-reranker-v2-m3-Q8_0.gguf"}});
        let caps = derive(&running, &rows);
        let wanted = role_for_capability("rerank").expect("rerank is a routed role");
        assert!(serves(&caps, wanted), "{caps:?}");
        assert_eq!(caps[0]["state"], "live", "a non-ollama backend whose container runs is live");
        assert!(!serves(&caps, "chat"), "a reranker serves no chat: {caps:?}");
        assert_eq!(placed_model(&rows, "host6", "rerank").as_deref(), Some("bge-reranker-v2-m3-Q8_0.gguf"));
        // Not running yet: placed, not routable.
        assert!(!serves(&derive(&json!({"running_backends": {"ollama": "gemma4:12b"}}), &rows), wanted));
    }

    /// A row stored by an rc.5 (or older) gateway: backend reranker, role chat.
    /// No migration rewrites it; every reader sees rerank.
    #[test]
    fn an_old_chat_roled_reranker_row_reads_as_rerank() {
        let rows = [fact("reranker", "bge-reranker-v2-m3-Q8_0.gguf", "chat")];
        let caps = derive(&json!({"running_backends": {"reranker": "bge-reranker-v2-m3-Q8_0.gguf"}}), &rows);
        assert!(serves(&caps, "rerank") && !serves(&caps, "chat"), "{caps:?}");
        assert_eq!(summary(&caps), "rerank:bge-reranker-v2-m3-Q8_0.gguf");
        assert_eq!(placed_model(&rows, "host6", "rerank").as_deref(), Some("bge-reranker-v2-m3-Q8_0.gguf"));
        assert_eq!(placed_model(&rows, "host6", "chat"), None);
        // Only the reranker is read this way: an llamacpp placed for rerank
        // keeps its stored role, and so does an llamacpp chat row.
        assert_eq!(effective_role("reranker", "chat"), "rerank");
        assert_eq!(effective_role("llamacpp", "rerank"), "rerank");
        assert_eq!(effective_role("llamacpp", "chat"), "chat");
        assert_eq!(effective_role("ollama", "embed"), "embed");
    }

    #[test]
    fn capabilities_map_to_roles() {
        assert_eq!(role_for_capability("embed"), Some("embed"));
        assert_eq!(role_for_capability("rerank"), Some("rerank"));
        assert_eq!(role_for_capability("whisper"), None);
    }
}
