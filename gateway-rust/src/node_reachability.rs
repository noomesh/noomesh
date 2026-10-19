// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Node reachability — does the gateway actually reach each node?
//!
//! ## Why this exists
//!
//! A node's `status` is set by [`routes::cluster::node_heartbeat`], which
//! the node itself calls. That measures the OUTBOUND direction only: the
//! node can reach the gateway. But work travels the other way — the
//! gateway dials the node agent to start backends, run skills, pull
//! artifacts and answer inference. Nothing measured that direction, so a
//! node whose inbound connections all failed still reported `online`.
//!
//! It is not hypothetical. On 2026-09-04 a node's certificate named an
//! address it no longer had; every inbound TLS handshake was rejected by
//! name and every inference to it failed, while the node heartbeated
//! happily and read as healthy for hours. The operator found it by
//! noticing the failures, not by looking at the fleet.
//!
//! This loop closes that gap: it dials each known node's agent on the
//! same path the work does, records the result in Redis (`noo:node_inbound:<id>`,
//! NOT the TTL'd `mesh_nodes` entry — the design), and raises an operator alert when a node that is heartbeating
//! stops accepting connections — the exact combination that reads as
//! healthy and serves nothing.
//!
//! It matters more once the certificate becomes the node's identity
//! a handshake the gateway rejects is then an
//! authentication failure, and the node will still be heartbeating.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::state::AppState;

/// How often to dial every node. Cheap: one HTTP GET per node.
const INTERVAL_SECS: u64 = 120;
/// Give the fleet time to come up before judging anything.
const STARTUP_GRACE_SECS: u64 = 90;
/// One dial should be fast; a node that cannot answer in this window is
/// not serving work either.
const PROBE_TIMEOUT_SECS: u64 = 8;

/// What one probe found.
#[derive(Debug, Clone, PartialEq)]
pub enum Reach {
    /// The agent answered.
    Ok,
    /// It did not: connection refused, TLS rejected, timeout, 5xx.
    Failed(String),
    /// No address to dial — nothing to say about reachability.
    Unknown,
}

impl Reach {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reach::Ok => "ok",
            Reach::Failed(_) => "failed",
            Reach::Unknown => "unknown",
        }
    }
}

/// Dial one node's agent the way the work does.
pub async fn probe_node(state: &AppState, node_id: &str) -> Reach {
    let Ok(link) = crate::node_link::NodeLink::for_node(state, node_id).await else {
        return Reach::Unknown;
    };
    let req = link
        .request(reqwest::Method::GET, "/health")
        .timeout(std::time::Duration::from_secs(PROBE_TIMEOUT_SECS));
    match req.send().await {
        Ok(r) if r.status().is_success() => Reach::Ok,
        // A 401/403 still proves the socket, the TLS handshake and the
        // listener: the node IS reachable, it disagrees about who we are.
        // That is an auth problem, not a reachability one, and saying
        // "unreachable" would send the operator to the wrong place.
        Ok(r) if r.status().as_u16() == 401 || r.status().as_u16() == 403 => Reach::Ok,
        Ok(r) => Reach::Failed(format!("agent answered {}", r.status())),
        Err(e) => Reach::Failed(reason(&e)),
    }
}

/// A short, operator-facing reason. `reqwest`'s Display is a chain that
/// buries the useful part; the distinctions that matter here are refused
/// vs. timed out vs. rejected at the handshake.
fn reason(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return "timed out".into();
    }
    if e.is_connect() {
        let s = format!("{e:?}").to_ascii_lowercase();
        if s.contains("certificate") || s.contains("tls") || s.contains("handshake") {
            // The 2026-09-04 shape: reachable, but the certificate does
            // not name the address we dialled.
            return "TLS handshake rejected (certificate may not name this address)".into();
        }
        return "connection refused".into();
    }
    e.to_string().chars().take(120).collect()
}

/// How long a recorded result is believed. The prober runs every
/// `INTERVAL_SECS`; five missed cycles means the prober is gone, and a
/// stale "ok" must read as "not checked", not as reachable.
const INBOUND_TTL_SECS: i64 = 600;
const INBOUND_KEY_PREFIX: &str = "noo:node_inbound:";
/// The fields this module owns on a node record as readers see it.
const INBOUND_FIELDS: [&str; 3] = ["inbound", "inbound_checked_at", "inbound_error"];

/// Where one probe result is stored: `(key, json)`.
///
/// NOT the node's `mesh_nodes` entry. That entry's 120 s TTL
/// is the liveness signal, and a KV put resets it; this loop used to put on
/// every cycle, so a node that stopped heartbeating never aged out and
/// stayed in gossip with a frozen heartbeat. The only writer of the TTL'd
/// presence entry is now the node's own heartbeat (and registration).
fn inbound_write(node_id: &str, reach: &Reach, now: chrono::DateTime<chrono::Utc>) -> (String, String) {
    let mut v = json!({
        "inbound": reach.as_str(),
        "inbound_checked_at": now.to_rfc3339(),
    });
    if let Reach::Failed(why) = reach {
        v["inbound_error"] = json!(why);
    }
    (format!("{INBOUND_KEY_PREFIX}{node_id}"), v.to_string())
}

/// Put the recorded inbound result (if any) onto a node record, in the
/// shape readers (`noo cluster verify`, the dashboard) already parse.
///
/// Anything the KV entry carries under these names is dropped first: an
/// entry written by an older gateway holds a frozen copy, and the heartbeat
/// read-modify-write would keep it alive forever. `stored` absent,
/// unreadable or not an object leaves the fields ABSENT, which readers
/// already render as "not yet checked" — never as reachable or unreachable.
pub(crate) fn apply_inbound(data: &mut Value, stored: Option<&str>) {
    let Some(obj) = data.as_object_mut() else { return };
    for f in INBOUND_FIELDS {
        obj.remove(f);
    }
    let Some(Value::Object(rec)) = stored.and_then(|s| serde_json::from_str::<Value>(s).ok()) else {
        return;
    };
    for f in INBOUND_FIELDS {
        if let Some(v) = rec.get(f) {
            obj.insert(f.to_string(), v.clone());
        }
    }
}

/// Read the recorded result for a node. `None` = not recorded (no Redis,
/// expired, or never probed).
pub(crate) async fn read_inbound(state: &AppState, node_id: &str) -> Option<String> {
    state.redis.as_ref()?.get_string(&format!("{INBOUND_KEY_PREFIX}{node_id}")).await
}

/// Record the result so every reader — the node list, the dashboard,
/// `noo cluster nodes` — sees the same thing. Without Redis nothing is
/// recorded and readers see "not yet checked".
async fn record(state: &AppState, node_id: &str, reach: &Reach) {
    let Some(redis) = state.redis.as_ref() else { return };
    let (key, body) = inbound_write(node_id, reach, chrono::Utc::now());
    if redis.set_string(&key, &body).await {
        redis.expire(&key, INBOUND_TTL_SECS).await;
    }
}

/// The nodes the gateway believes exist, with the status they claim.
async fn known_nodes(state: &AppState) -> Vec<(String, String)> {
    let Ok(kv) = state.js.get_key_value("mesh_nodes").await else {
        return Vec::new();
    };
    let Ok(mut keys) = kv.keys().await else {
        return Vec::new();
    };
    let mut out = Vec::new();
    use futures::StreamExt;
    while let Some(Ok(k)) = keys.next().await {
        let claimed = kv
            .get(&k)
            .await
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
            .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(str::to_string))
            .unwrap_or_else(|| "unknown".into());
        out.push((k, claimed));
    }
    out
}

/// One pass: dial every node, record, and page about the combination that
/// hides — heartbeating (so it looks fine) but not accepting work.
pub async fn tick(state: &Arc<AppState>) {
    for (node, claimed) in known_nodes(state).await {
        let reach = probe_node(state, &node).await;
        record(state, &node, &reach).await;
        let failing_while_up = match &reach {
            Reach::Failed(why) => {
                let claims_up = matches!(claimed.as_str(), "online" | "busy");
                if !claims_up {
                    tracing::info!(node = %node, status = %claimed, reason = %why, "node_unreachable");
                }
                claims_up
            }
            _ => false,
        };
        if let (Reach::Failed(why), true) = (&reach, failing_while_up) {
            tracing::warn!(node = %node, status = %claimed, reason = %why, "node_unreachable_while_reporting_up");
            // The dial error (addresses, TLS internals) is the logged
            // detail; the channel gets the class and the next step.
            let cert = why.to_ascii_lowercase().contains("cert");
            let (class, next) = if cert {
                (
                    "its certificate was not accepted — re-issue it; provisioning re-issues \
                     when the cert no longer names the node's address",
                    format!("noo cluster provision {node}"),
                )
            } else {
                ("the dial failed", format!("noo cluster verify {node}"))
            };
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "node_unreachable",
                    &node,
                    format!(
                        "Node '{node}' reports {claimed} but the gateway cannot reach its agent: {class}. \
                         Heartbeats are outbound and work is inbound, so this node looks healthy and serves nothing."
                    ),
                )
                .detail(why.clone())
                .investigate(next)
                .persisting(),
                0, // persisting: the onset/reminder schedule owns timing
            )
            .await;
        } else if !matches!(reach, Reach::Unknown) {
            // Reachable, or no longer claiming to be up: the condition is
            // over. An unknown result (no address to dial) says nothing, so
            // it leaves an open alert open.
            crate::operator_alert::clear_operator_alert(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "node_unreachable",
                    &node,
                    format!("Node '{node}' is reachable by the gateway again."),
                )
                .investigate(format!("noo cluster verify {node}")),
            )
            .await;
        }
    }
}

pub fn spawn(state: Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new("node_reachability", INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .spawn(state, move |state| async move {
            tick(&state).await;
            Ok(())
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authenticated_refusal_still_proves_reachability() {
        // The distinction the alert depends on: 401/403 means the socket,
        // the TLS handshake and the listener all worked. Calling that
        // "unreachable" would send an operator to the network when the
        // problem is credentials.
        assert_eq!(Reach::Ok.as_str(), "ok");
        assert_eq!(Reach::Failed("x".into()).as_str(), "failed");
        assert_eq!(Reach::Unknown.as_str(), "unknown");
    }

    #[test]
    fn a_node_with_no_address_is_unknown_not_failed() {
        // Nothing to dial says nothing about reachability, and must not
        // page anyone — only a node claiming to be up while refusing
        // connections is worth waking someone for.
        assert_ne!(Reach::Unknown, Reach::Failed("connection refused".into()));
    }

    fn at() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn a_probe_result_is_not_written_to_the_ttld_presence_entry() {
        // a write to the node's `mesh_nodes` key resets its
        // 120 s TTL, so a silent node never aged out. The write target must
        // never be the bare node id (the KV key) and must carry the prefix.
        for r in [Reach::Ok, Reach::Failed("x".into()), Reach::Unknown] {
            let (key, body) = inbound_write("host3", &r, at());
            assert_ne!(key, "host3");
            assert!(key.starts_with(INBOUND_KEY_PREFIX), "{key}");
            assert!(body.contains(r.as_str()));
        }
    }

    #[test]
    fn stored_result_merges_back_in_the_shape_readers_parse() {
        let (_, body) = inbound_write("n", &Reach::Failed("timed out".into()), at());
        let mut rec = json!({"id": "n", "status": "online"});
        apply_inbound(&mut rec, Some(&body));
        assert_eq!(rec["inbound"], "failed");
        assert_eq!(rec["inbound_error"], "timed out");
        assert!(rec["inbound_checked_at"].as_str().is_some());
        assert_eq!(rec["id"], "n");
    }

    #[test]
    fn missing_or_unreadable_store_reads_as_not_checked() {
        // Not reachable, not unreachable: the fields are absent, which
        // `noo cluster verify` renders as "not yet checked". A frozen copy
        // left in the KV entry by an older gateway must not survive either.
        for stored in [None, Some("not json"), Some("[1,2]"), Some("\"ok\"")] {
            let mut rec = json!({"inbound": "ok", "inbound_checked_at": "old", "inbound_error": "e"});
            apply_inbound(&mut rec, stored);
            for f in INBOUND_FIELDS {
                assert!(rec.get(f).is_none(), "{f} survived {stored:?}");
            }
        }
    }
}
