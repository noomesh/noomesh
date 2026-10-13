// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The add-ons' shared-secret HMAC is REFUSED.
//!
//! trellion, trellion-intel and evolve each hold a key of their own
//! (`svc:<addon>`, exchanged at `/api/addon/token`). each
//! fell back to a cluster HMAC — signed with `NOO_CONTROLLER_SECRET`, or the
//! fleet's `NOO_CLUSTER_SECRET` — when that key was missing: trellion as actor
//! `trellion` (intel runs the same code), evolve as `pai-evolve`. The evidence
//! for retiring it is `cluster_hmac_non_inference` reading 0 for those callers
//! on the controller while `addon_exchanged_token` counted their exchanged path.
//!
//! The add-on images stopped sending it first: with no key they refuse
//! in-process and name the fix. This is the gateway's half: an HMAC whose
//! actor is an add-on is answered 403 on EITHER shared-secret door, on every HTTP route, before any
//! admission — the inference bridge, the lane count, the `Internal` / `Node`
//! classification. Each refusal is counted as
//! `noo_legacy_lane_uses_total{lane="addon_shared_secret_refused",door,caller,route_class}`
//! and WARNed once per (door, caller, route class) per 10 minutes, so an old
//! add-on image still in use is a 403 with a name, not a mystery.
//!
//! Logs only, per the channel egress rule (#568): nothing here reaches a
//! channel.

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::legacy_lanes::{bounded_name, log_due, route_class, HmacDoor, LaneUse, PeerFacts};

/// REFUSED, not admitted: a shared-secret HMAC whose actor is an add-on.
pub const LANE_ADDON_HMAC_REFUSED: &str = "addon_shared_secret_refused";

/// The `code` field of the 403 body.
pub const REFUSAL_CODE: &str = "addon_shared_secret_retired";

/// How often the refusal WARN repeats per (door, caller, route class).
pub const LOG_EVERY: Duration = Duration::from_secs(600);

/// The HMAC actors the add-ons signed as, mapped to the name
/// `noo security service-key provision` takes. A fixed list on purpose: these
/// are the strings the retired fallbacks put in the token, not a
/// declaration — no add-on will ever sign a new one. Case and surrounding
/// whitespace are ignored; anything else (a node id, `cli-*`, a core
/// service's actor) is not an add-on and is judged as before.
const ADDON_ACTORS: &[(&str, &str)] = &[
    ("trellion", "trellion"),
    ("noo-trellion", "trellion"),
    ("trellion-intel", "trellion-intel"),
    ("trellion_intel", "trellion-intel"),
    ("noo-trellion-intel", "trellion-intel"),
    ("pai-evolve", "evolve"),
    ("evolve", "evolve"),
    ("noo-evolve", "evolve"),
];

/// The add-on an HMAC actor names, as `noo security service-key provision`
/// spells it, or `None` when the actor is not an add-on's.
pub fn addon_for_actor(actor: &str) -> Option<&'static str> {
    let a = actor.trim().to_ascii_lowercase();
    ADDON_ACTORS.iter().find(|(k, _)| *k == a).map(|(_, v)| *v)
}

/// The command that ends the refusal. trellion's actor was shared by the
/// Intelligent tier's container (the same code signed it), so its hint
/// names both.
pub fn fix_for(addon: &str) -> String {
    match addon {
        "trellion" => "noo security service-key provision trellion   # trellion-intel for the Intelligent tier's container".into(),
        other => format!("noo security service-key provision {other}"),
    }
}

/// The 403 an add-on's HMAC gets: the reason, and the command.
pub fn refusal(addon: &str) -> Response {
    let fix = fix_for(addon);
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "detail": format!(
                "the gateway no longer accepts a shared-secret HMAC from an add-on ({addon}): \
                 an add-on authenticates with its own service key, exchanged at \
                 /api/addon/token. This caller is an add-on image from before the add-ons dropped that fallback, \
                 or one with no key. Fix: {fix}"
            ),
            "hint": fix,
            "code": REFUSAL_CODE,
        })),
    )
        .into_response()
}

/// The lane use a refusal is counted as.
pub fn refusal_use(door: HmacDoor, actor: &str, path: &str) -> LaneUse {
    LaneUse {
        lane: LANE_ADDON_HMAC_REFUSED,
        labels: vec![
            ("door", door.as_str().into()),
            ("caller", bounded_name("caller", actor)),
            ("route_class", route_class(path).into()),
        ],
    }
}

/// Called FIRST on each shared-secret door, once the signature verified:
/// `Some(403)` when the actor is an add-on (counted and logged), `None`
/// otherwise — the door then judges the request exactly as before.
pub async fn refuse_addon_hmac(
    metrics: &crate::metrics::MetricsState,
    door: HmacDoor,
    actor: &str,
    path: &str,
    peer: &PeerFacts,
) -> Option<Response> {
    let addon = addon_for_actor(actor)?;
    let u = refusal_use(door, actor, path);
    let key = format!(
        "{LANE_ADDON_HMAC_REFUSED}|{}|{}|{}",
        door.as_str(),
        u.labels.iter().find(|(k, _)| *k == "caller").map(|(_, v)| v.as_str()).unwrap_or(""),
        route_class(path)
    );
    crate::legacy_lanes::observe(metrics, std::slice::from_ref(&u), peer).await;
    if log_due(&key, LOG_EVERY) {
        tracing::warn!(
            door = door.as_str(), caller = %actor, addon, route_class = route_class(path),
            peer = %peer.describe(), fix = %fix_for(addon),
            "REFUSED: an add-on signed with a shared secret, which the gateway no longer accepts \
             from an add-on — it must present its own service key (once per door, \
             caller and route class per 10 min; the count is \
             noo_legacy_lane_uses_total{{lane=\"addon_shared_secret_refused\"}})"
        );
    }
    Some(refusal(addon))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MetricsState;

    #[test]
    fn the_add_on_actors_map_to_their_provision_names_and_nothing_else_does() {
        for (actor, want) in [
            ("trellion", "trellion"),
            (" Trellion ", "trellion"),
            ("trellion-intel", "trellion-intel"),
            ("pai-evolve", "evolve"),
            ("evolve", "evolve"),
            ("noo-evolve", "evolve"),
        ] {
            assert_eq!(addon_for_actor(actor), Some(want), "{actor}");
        }
        // Core services, nodes, the CLI and empty actors are not add-ons:
        // the doors judge them exactly as before.
        for actor in ["worker", "worker-channels", "internal", "gateway", "heartbeat", "host3", "host8", "cli", "cli-break-glass", "", "trellionx", "evolve2"] {
            assert_eq!(addon_for_actor(actor), None, "{actor:?}");
        }
    }

    #[tokio::test]
    async fn the_refusal_is_a_403_naming_the_reason_and_the_command() {
        let r = refusal("evolve");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], REFUSAL_CODE);
        assert_eq!(v["hint"], "noo security service-key provision evolve");
        let d = v["detail"].as_str().unwrap();
        assert!(d.contains("shared-secret HMAC") && d.contains("noo security service-key provision evolve"), "{d}");
        let t = refusal("trellion");
        let body = axum::body::to_bytes(t.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let hint = v["hint"].as_str().unwrap();
        assert!(hint.contains("provision trellion") && hint.contains("trellion-intel"), "{hint}");
    }

    /// Counted under the legacy-lane family, per door, as a REFUSAL — never
    /// as an admitted `cluster_hmac_non_inference` / `self_call_shared_secret` use.
    #[tokio::test]
    async fn a_refusal_is_counted_per_door_and_never_as_an_admission() {
        let m = MetricsState::new();
        let peer = PeerFacts::default();
        assert!(refuse_addon_hmac(&m, HmacDoor::Controller, "trellion", "/api/v1/graph/extract", &peer).await.is_some());
        assert!(refuse_addon_hmac(&m, HmacDoor::Controller, "trellion", "/api/v1/graph/extract", &peer).await.is_some());
        assert!(refuse_addon_hmac(&m, HmacDoor::Cluster, "pai-evolve", "/v1/chat/completions", &peer).await.is_some());
        assert!(refuse_addon_hmac(&m, HmacDoor::Controller, "worker", "/api/v1/graph/extract", &peer).await.is_none());
        let out = m.render().await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="trellion",door="controller",lane="addon_shared_secret_refused",route_class="graph"} 2"#), "{out}");
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="pai-evolve",door="cluster",lane="addon_shared_secret_refused",route_class="inference"} 1"#), "{out}");
        assert!(!out.contains("cluster_hmac_non_inference") && !out.contains("self_call_shared_secret"), "{out}");
        assert!(!out.contains(r#"caller="worker""#), "a non-add-on actor is not refused here: {out}");
    }

    /// BOTH shared-secret doors call this FIRST — before the inference
    /// bridge, the lane count, the route check and the admission — and
    /// return its 403. One door guarded would leave the other open while
    /// reading as done (the bridge's own lesson, auth.rs).
    #[test]
    fn both_doors_refuse_an_add_on_before_admitting_anything() {
        let src = include_str!("auth.rs");
        let body = src
            .split("pub async fn require_any_auth(").nth(1).expect("the middleware")
            .split("\npub async fn ").next().unwrap();
        let ctl = src.split("pub async fn controller_door(").nth(1).expect("the controller door")
            .split("\npub async fn ").next().unwrap();
        let fleet = body.split("    if verify_cluster_token(&t) {").nth(1).expect("the fleet door");
        for (name, door, call, later) in [
            // The controller door admits nothing: what
            // follows the add-on refusal is the refusal of everyone else.
            ("controller", ctl, "crate::addon_hmac_refusal::refuse_addon_hmac(metrics, crate::legacy_lanes::HmacDoor::Controller, actor, path, peer).await",
                &["crate::controller_hmac_refusal::refuse("][..]),
            ("fleet", fleet, "crate::addon_hmac_refusal::refuse_addon_hmac(&state.metrics, crate::legacy_lanes::HmacDoor::Cluster, &actor, &path, &peer).await",
                &["node_route_allowed(", "if is_inference_surface {", "hmac_lane_uses(", "ClusterNode(actor"][..]),
        ] {
            let at = door.find(call).unwrap_or_else(|| panic!("the {name} door does not refuse an add-on's HMAC: `{call}` missing"));
            let tail = &door[at..];
            assert!(tail.split('\n').take(3).any(|l| l.contains("return Ok(r);") || l.contains("return r;")), "the {name} door computes the refusal but does not return it");
            for l in later {
                let after = door.find(l).unwrap_or_else(|| panic!("{l} missing from the {name} door"));
                assert!(at < after, "the {name} door must refuse an add-on before {l}");
            }
        }
    }
}
