// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The controller-secret HMAC is REFUSED from every caller.
//!
//! `NOO_CONTROLLER_SECRET` once signed every self-call the controller's own
//! services made. One caller after another moved onto a key of its own: the
//! gateway's own loops, the `noo` CLI (#702,
//! refused as `cli_shared_secret_refused`), the add-ons (refused as
//! `addon_shared_secret_refused`). The last one was the worker plane's
//! fallback — `cluster_auth.internal_gateway_headers` signed as `internal`,
//! `worker-channels`, `heartbeat`, `mcp-server`, … whenever its container had
//! no `NOO_GATEWAY_KEY`. Every worker-plane container holds its own key
//! (`svc:worker`, `svc:trellion`, `svc:trellion-intel`; `noo cluster verify`'s
//! `service keys` row), the fallback is deleted on the Python side, and the
//! live counter `cluster_hmac_non_inference{kind="controller"}` read 0 for the
//! six days before this change.
//!
//! So the controller door admits nothing. Once the CLI and add-on refusals
//! (which carry their own, more specific remedies) have had their say, any
//! other controller-secret HMAC is answered 403 here — on every route, the
//! inference surface included — counted as
//! `noo_legacy_lane_uses_total{lane="controller_shared_secret_refused",caller,route_class}`
//! and WARNed once per (caller, route class) per 10 minutes. There is no
//! grace path and no posture switch: a caller that still signs with the
//! controller secret is a container without its key, and the fix is the key.
//!
//! Logs only, per the channel egress rule (#568): nothing here reaches a
//! channel.

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::legacy_lanes::{bounded_name, log_due, route_class, LaneUse, PeerFacts};

/// REFUSED, not admitted: a controller-secret HMAC from anyone.
pub const LANE_CONTROLLER_HMAC_REFUSED: &str = "controller_shared_secret_refused";

/// The `code` field of the 403 body.
pub const REFUSAL_CODE: &str = "controller_shared_secret_retired";

/// How often the refusal WARN repeats per (caller, route class).
pub const LOG_EVERY: Duration = Duration::from_secs(600);

/// The command that ends the refusal: the container gets its own key.
pub const FIX: &str = "noo security service-key provision worker   # trellion / trellion-intel for the add-on containers";

/// The 403 a controller-secret HMAC gets.
pub fn refusal() -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "detail": format!(
                "the gateway no longer accepts an HMAC signed with the controller secret from any \
                 caller: every controller service presents its own service key \
                 (NOO_GATEWAY_KEY). This caller is a container without its key, or an image from \
                 before the worker plane dropped that fallback. Fix: {FIX}"
            ),
            "hint": FIX,
            "code": REFUSAL_CODE,
        })),
    )
        .into_response()
}

/// The lane use a refusal is counted as.
pub fn refusal_use(actor: &str, path: &str) -> LaneUse {
    LaneUse {
        lane: LANE_CONTROLLER_HMAC_REFUSED,
        labels: vec![("caller", bounded_name("caller", actor)), ("route_class", route_class(path).into())],
    }
}

/// The controller door's last word: count, log (rate-limited) and refuse.
pub async fn refuse(metrics: &crate::metrics::MetricsState, actor: &str, path: &str, peer: &PeerFacts) -> Response {
    let u = refusal_use(actor, path);
    let key = format!(
        "{LANE_CONTROLLER_HMAC_REFUSED}|{}|{}",
        u.labels.iter().find(|(k, _)| *k == "caller").map(|(_, v)| v.as_str()).unwrap_or(""),
        route_class(path)
    );
    crate::legacy_lanes::observe(metrics, std::slice::from_ref(&u), peer).await;
    if log_due(&key, LOG_EVERY) {
        tracing::warn!(
            caller = %actor, route_class = route_class(path), peer = %peer.describe(), fix = FIX,
            "REFUSED: a caller signed with the controller secret, which the gateway no longer \
             accepts from anyone — it must present its own service key (once per \
             caller and route class per 10 min; the count is \
             noo_legacy_lane_uses_total{{lane=\"controller_shared_secret_refused\"}})"
        );
    }
    refusal()
}

// ── The fleet secret off a node ─────────

/// REFUSED: a fleet-secret HMAC that did not come from a node.
pub const LANE_FLEET_OFF_NODE_REFUSED: &str = "fleet_secret_off_node_refused";

/// The `code` field of that 403.
pub const FLEET_REFUSAL_CODE: &str = "fleet_secret_off_node";

/// Why a fleet token is out of place, or `None` when it may go on to the
/// node-route check. The fleet secret is a NODE's credential; no controller
/// service holds it any more (the browser door has its own key), so a fleet
/// token is refused when it is plainly a controller service presenting one
/// it should not have:
///
/// * the connection presented a controller SERVICE leaf
///   (`O=Mesh Cluster Service`) — a node presents a node leaf;
/// * it comes from a container on the gateway's own compose network and
///   presented no node leaf. A node — the containerised node agent included
///   — presents its own certificate (every node did, live: `node_token_no_cert`
///   read 0 for seven days); published-port traffic arrives from the bridge
///   address and is not a compose peer.
pub fn fleet_token_out_of_place(service_leaf: Option<&str>, node_leaf: bool, compose_peer: bool) -> Option<String> {
    if let Some(svc) = service_leaf {
        return Some(format!("the connection presented the controller service leaf `{svc}`, not a node's"));
    }
    if compose_peer && !node_leaf {
        return Some("it came from a container on the gateway's own network with no node certificate".into());
    }
    None
}

/// REFUSED: a fleet-secret HMAC with NO node certificate while mTLS is
/// enforcing (`tls::mtls_enabled`). The token's actor is a claim any node
/// can make about any other; only the node's leaf makes it an identity.
pub const LANE_FLEET_NO_CERT_REFUSED: &str = "fleet_token_no_cert_refused";

/// The `code` field of that 403.
pub const FLEET_NO_CERT_CODE: &str = "fleet_token_needs_node_certificate";

/// Is `ip` this host talking to itself? Decided by the socket's peer
/// address (never a header); an IPv4-mapped IPv6 loopback counts.
pub fn is_loopback_peer(ip: Option<&str>) -> bool {
    ip.and_then(|s| s.parse::<std::net::IpAddr>().ok()).is_some_and(|a| a.to_canonical().is_loopback())
}

/// The whole fleet-token placement decision: `(reason, lane)` when the token
/// must be refused, `None` when it may go on to the node-route check.
///
/// Callers that mint a fleet bearer (checked 2026-10, every one):
/// * node agent (Go: heartbeat, reconcile, artifacts, MCP tool report, log
///   ship): its HTTP transport loads `NOO_TLS_CERT/KEY` — presents the leaf;
/// * `noo-fetch.sh` / `noo node fetch` apply report: the shell sends the
///   token only together with `--cert/--key` (else birth proof alone), the
///   Mac fetcher sends no bearer at all;
/// * the harness reaches the node agent, not the gateway, with this secret;
/// * the gateway's own loops, workers, the CLI, the MCP doors and add-ons
///   hold service keys or user credentials — the fleet token is refused to
///   them already (`fleet_token_out_of_place`, `cli_shared_secret_refused`);
/// * anything on this host's loopback is allowed (the gateway talking to
///   itself); a legitimate leaf-less remote caller does not exist.
///
/// Not enforcing: the leaf-less token is admitted as before and counted by
/// the existing `node_token_no_cert` lane, so an operator can see the fleet
/// is clean before turning enforcement on.
pub fn fleet_token_placement(
    service_leaf: Option<&str>,
    node_leaf: bool,
    compose_peer: bool,
    loopback: bool,
    enforcing: bool,
) -> Option<(String, &'static str)> {
    if let Some(why) = fleet_token_out_of_place(service_leaf, node_leaf, compose_peer) {
        return Some((why, LANE_FLEET_OFF_NODE_REFUSED));
    }
    if enforcing && !node_leaf && !loopback {
        return Some((
            "it carried no node certificate (mTLS is enforced: a fleet token only proves \"some node\", \
             the node's own certificate says which)"
                .into(),
            LANE_FLEET_NO_CERT_REFUSED,
        ));
    }
    None
}

/// Count, log (rate-limited) and refuse an out-of-place fleet token.
pub async fn refuse_fleet_off_node(
    metrics: &crate::metrics::MetricsState,
    actor: &str,
    path: &str,
    peer: &PeerFacts,
    why: &str,
) -> Response {
    refuse_fleet(metrics, LANE_FLEET_OFF_NODE_REFUSED, actor, path, peer, why).await
}

/// [`refuse_fleet_off_node`] for the lane `fleet_token_placement` chose.
pub async fn refuse_fleet(
    metrics: &crate::metrics::MetricsState,
    lane: &'static str,
    actor: &str,
    path: &str,
    peer: &PeerFacts,
    why: &str,
) -> Response {
    let caller = bounded_name("caller", actor);
    // The log key is built from the BOUNDED name: the actor is whatever the
    // token claims, and a raw one would let a caller grow the rate-limit
    // table without bound (review, second pass).
    let key = format!("{lane}|{caller}|{}", route_class(path));
    let u = LaneUse {
        lane,
        labels: vec![("caller", caller), ("route_class", route_class(path).into())],
    };
    crate::legacy_lanes::observe(metrics, std::slice::from_ref(&u), peer).await;
    if log_due(&key, LOG_EVERY) {
        tracing::warn!(
            caller = %actor, route_class = route_class(path), peer = %peer.describe(), why, lane,
            "REFUSED: a fleet-secret token that is not a node's own — the fleet secret \
             is a node's credential and a node proves WHICH node with its certificate; a \
             controller service presents its own key"
        );
    }
    let (detail, code) = if lane == LANE_FLEET_NO_CERT_REFUSED {
        (
            format!(
                "a fleet token must come with the node's own certificate: {why}. Fix: re-run \
                 `noo cluster provision <node> --wait` so the node's agent has its certificate, \
                 or (a stopgap) set NOO_MTLS_GATEWAY=false on the controller"
            ),
            FLEET_NO_CERT_CODE,
        )
    } else {
        (
            format!(
                "the fleet secret is a node's credential and this caller is not a node: {why}. \
                 A controller service presents its own service key (NOO_GATEWAY_KEY)."
            ),
            FLEET_REFUSAL_CODE,
        )
    };
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "detail": detail, "hint": FIX, "code": code })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MetricsState;

    #[tokio::test]
    async fn an_out_of_place_fleet_token_is_a_counted_403() {
        let m = MetricsState::new();
        let r = refuse_fleet_off_node(&m, "worker", "/api/cluster/nodes/x/heartbeat", &PeerFacts::default(), "a service leaf").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], FLEET_REFUSAL_CODE);
        let out = m.render().await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="worker",lane="fleet_secret_off_node_refused",route_class="cluster"} 1"#), "{out}");
    }

    #[test]
    fn a_fleet_token_is_out_of_place_on_a_service_leaf_or_a_keyless_compose_peer() {
        assert!(fleet_token_out_of_place(Some("worker"), false, true).unwrap().contains("`worker`"));
        assert!(fleet_token_out_of_place(Some("trellion"), false, false).is_some(), "a service leaf from anywhere");
        assert!(fleet_token_out_of_place(None, false, true).is_some(), "the worker plane on the compose network");
        assert!(fleet_token_out_of_place(None, true, true).is_none(), "a containerised node agent on its own leaf");
        assert!(fleet_token_out_of_place(None, true, false).is_none(), "a node over the published port");
        assert!(fleet_token_out_of_place(None, false, false).is_none(), "judged by the node-route check as before");
    }

    #[test]
    fn fleet_token_placement_matrix() {
        // (service_leaf, node_leaf, compose_peer, loopback, enforcing) -> lane
        let off = Some(LANE_FLEET_OFF_NODE_REFUSED);
        let nocert = Some(LANE_FLEET_NO_CERT_REFUSED);
        let cases: &[(Option<&str>, bool, bool, bool, bool, Option<&str>)] = &[
            // a node on its own leaf passes in every placement
            (None, true, false, false, true, None),
            (None, true, true, false, true, None),
            (None, true, false, false, false, None),
            // the spoof: tailnet node, no leaf
            (None, false, false, false, true, nocert),
            (None, false, false, false, false, None), // observe only (node_token_no_cert counts it)
            // loopback self-call stays allowed
            (None, false, false, true, true, None),
            (None, false, false, true, false, None),
            // compose peer without a leaf: refused as before, enforcing or not
            (None, false, true, false, true, off),
            (None, false, true, false, false, off),
            // a service leaf is never a node
            (Some("worker"), false, false, false, true, off),
            (Some("worker"), true, false, true, false, off),
        ];
        for &(svc, leaf, compose, lo, enf, want) in cases {
            let got = fleet_token_placement(svc, leaf, compose, lo, enf).map(|(_, lane)| lane);
            assert_eq!(got, want, "svc={svc:?} leaf={leaf} compose={compose} loopback={lo} enforcing={enf}");
        }
    }

    #[test]
    fn loopback_is_decided_by_the_socket_address() {
        assert!(is_loopback_peer(Some("127.0.0.1")));
        assert!(is_loopback_peer(Some("::1")));
        assert!(is_loopback_peer(Some("::ffff:127.0.0.1")));
        assert!(!is_loopback_peer(Some("100.64.0.7")));
        assert!(!is_loopback_peer(Some("172.19.0.5")));
        assert!(!is_loopback_peer(Some("localhost")), "a name is not an address");
        assert!(!is_loopback_peer(None), "unknown peer is not loopback");
    }

    #[tokio::test]
    async fn a_leafless_fleet_token_is_a_counted_403_on_its_own_lane() {
        let m = MetricsState::new();
        let r = refuse_fleet(&m, LANE_FLEET_NO_CERT_REFUSED, "host3", "/api/cluster/nodes/host4/heartbeat", &PeerFacts::default(), "no cert").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], FLEET_NO_CERT_CODE);
        assert!(v["detail"].as_str().unwrap().contains("noo cluster provision"), "{v}");
        let out = m.render().await;
        assert!(out.contains(r#"lane="fleet_token_no_cert_refused""#), "{out}");
    }

    #[tokio::test]
    async fn the_refusal_is_a_403_naming_the_reason_and_the_command() {
        let r = refusal();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], REFUSAL_CODE);
        assert!(v["hint"].as_str().unwrap().starts_with("noo security service-key provision worker"));
        assert!(v["detail"].as_str().unwrap().contains("controller secret"), "{v}");
    }

    /// Counted as a REFUSAL — never as an admitted `cluster_hmac_non_inference`
    /// or `self_call_shared_secret` use, the two lanes the old admission fed.
    #[tokio::test]
    async fn every_worker_plane_actor_is_refused_and_counted() {
        let m = MetricsState::new();
        let peer = PeerFacts::default();
        for (actor, path) in [
            ("internal", "/api/v1/graph/extract"),
            ("worker-channels", "/api/channels/send"),
            ("heartbeat", "/api/channels/send"),
            ("mcp-server", "/api/cluster/nodes"),
            ("worker", "/v1/chat/completions"),
        ] {
            let r = refuse(&m, actor, path, &peer).await;
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{actor} {path}");
        }
        let out = m.render().await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="heartbeat",lane="controller_shared_secret_refused",route_class="channels"} 1"#), "{out}");
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="worker",lane="controller_shared_secret_refused",route_class="inference"} 1"#), "{out}");
        assert!(!out.contains("cluster_hmac_non_inference") && !out.contains("self_call_shared_secret"), "{out}");
    }
}
