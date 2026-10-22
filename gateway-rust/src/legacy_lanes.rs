// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Legacy credential lanes, OBSERVED.
//!
//! Four ways in are kept only for callers nobody has proven are gone:
//!
//! | lane | what admits the request |
//! |---|---|
//! | `self_call_shared_secret` | a controller- or fleet-secret HMAC buying inference (transitional bridge, `NOO_SELF_CALL_SHARED_SECRET`) |
//! | `cluster_hmac_non_inference` | a controller-secret HMAC (or a fleet HMAC in the legacy full-access mode) resolving to `ClusterKind::Internal` on any other route. The add-ons' HMAC is no longer admitted here: it is REFUSED first and counted as `addon_shared_secret_refused` (`addon_hmac_refusal.rs`) |
//! | `node_token_no_cert` | a fleet-secret HMAC resolving to `ClusterKind::Node` with no client certificate on the connection |
//! | `cluster_hmac_v1` | a fleet-secret HMAC in the v1 wire form, which is not bound to its request (the v2 form is the comparator `cluster_hmac_v2`); refused once `NOO_CLUSTER_TOKEN_V1=0`, and then counted as `cluster_hmac_v1_refused` instead |
//! | (node side) `static_token` / `whois_non_controller` | reported by each node agent on its heartbeat as `legacy_lanes` |
//!
//! The `noo` CLI is no longer on any of these lanes. Its controller-secret
//! actors (`cli`, `cli-posture`, `cli-onboard`, `cli-break-glass`) are
//! REFUSED by the middleware on every route, never admitted (operator
//! decision 2026-10-03: no break-glass, no onboard bootstrap). Each refusal
//! is counted under the same family as
//! `noo_legacy_lane_uses_total{lane="cli_shared_secret_refused",caller,route_class}`
//! ([`LANE_CLI_REFUSED`]), so an old binary still in use is visible by name
//! — and `cluster_hmac_non_inference` holds only the add-ons' fallback.
//!
//! Apart from that one refused lane, this module decides nothing and
//! refuses nothing. It classifies an
//! ADMITTED request into the lanes it used and counts them under one
//! Prometheus family, `noo_legacy_lane_uses_total{lane=…}`, beside the
//! comparator lanes that are the replacement (`node_token_with_cert`,
//! `addon_exchanged_token`, `operator_client_cert`) so a ratio is visible. `noo cluster verify
//! --controller` reads the counters back as its `legacy lanes` row.
//!
//! Every label is bounded: route paths are bucketed ([`route_class`]),
//! and the free-text names a credential carries (an HMAC actor, a claimed
//! node) are admitted to a fixed-size set per label and read `other` past
//! it — a fleet-secret holder can put any string in its actor field, and a
//! counter must not be the way it grows the registry.
//!
//! Logs only, per the channel egress rule (#568): nothing here reaches a
//! channel.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The one metric family every lane is counted under.
pub const METRIC: &str = "noo_legacy_lane_uses_total";

pub const LANE_SELF_CALL: &str = "self_call_shared_secret";
pub const LANE_HMAC_NON_INFERENCE: &str = "cluster_hmac_non_inference";
pub const LANE_NODE_NO_CERT: &str = "node_token_no_cert";
/// Comparator: the good case of [`LANE_NODE_NO_CERT`].
pub const LANE_NODE_WITH_CERT: &str = "node_token_with_cert";
/// Comparator: the add-on's own exchanged token, the replacement for
/// [`LANE_HMAC_NON_INFERENCE`] when the caller is an add-on.
pub const LANE_ADDON_EXCHANGED: &str = "addon_exchanged_token";
/// Comparator: a posture write on an operator client certificate plus a
/// token bound to it — the replacement for the CLI's
/// `cli-posture` use of [`LANE_HMAC_NON_INFERENCE`].
pub const LANE_OPERATOR_CERT: &str = "operator_client_cert";
/// A fleet-secret HMAC in the v1 wire form (`<actor>:<ts>:<hmac>`): signed
/// over actor and time only, so a captured header replays on any route for
/// five minutes. Admitted while `NOO_CLUSTER_TOKEN_V1` is open; every count
/// is a caller that still has to upgrade to v2. Admissions only: when the
/// gate is closed the token is counted as [`LANE_HMAC_V1_REFUSED`] instead.
pub const LANE_HMAC_V1: &str = "cluster_hmac_v1";
/// REFUSED, not admitted: a v1 cluster token after `NOO_CLUSTER_TOKEN_V1=0`
/// closed the gate. Every count is a caller (by name) whose calls all fail
/// until it signs v2.
pub const LANE_HMAC_V1_REFUSED: &str = "cluster_hmac_v1_refused";
/// Comparator: the request-bound v2 form, the replacement for [`LANE_HMAC_V1`].
pub const LANE_HMAC_V2: &str = "cluster_hmac_v2";
/// REFUSED, not admitted: a controller-secret HMAC signed by the `noo` CLI
/// (`operator_auth::is_cli_actor`). Every count is an old `noo` binary that
/// needs `noo upgrade --all`.
pub const LANE_CLI_REFUSED: &str = "cli_shared_secret_refused";

/// Which shared secret verified an HMAC bearer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacDoor {
    /// `NOO_CONTROLLER_SECRET` — the controller's own services.
    Controller,
    /// `NOO_CLUSTER_SECRET` — every node holds it.
    Cluster,
}

impl HmacDoor {
    pub fn as_str(self) -> &'static str {
        match self {
            HmacDoor::Controller => "controller",
            HmacDoor::Cluster => "cluster",
        }
    }
}

/// An HMAC-authenticated request the middleware has decided to ADMIT.
#[derive(Debug, Clone)]
pub struct HmacAdmission<'a> {
    pub door: HmacDoor,
    /// The kind it resolved to was `ClusterKind::Internal` (full access).
    pub internal: bool,
    /// `/v1/*` or `/api/external/*`.
    pub inference: bool,
    pub path: &'a str,
    /// The actor field of the token — a claim, not a proof.
    pub actor: &'a str,
    /// The node a VERIFIED client certificate names, when one was presented.
    pub presented_node: Option<&'a str>,
}

/// One lane a request used, with its (already bounded) labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneUse {
    pub lane: &'static str,
    pub labels: Vec<(&'static str, String)>,
}

impl LaneUse {
    fn label(&self, k: &str) -> &str {
        self.labels.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str()).unwrap_or("")
    }
}

/// The route classes a path is bucketed into. Anything else is `other`.
/// Label by class, never by path: a path carries ids.
const ROUTE_CLASSES: &[&str] = &[
    "cluster", "agents", "memory", "rag", "graph", "embed", "artifacts", "bootstrap", "metrics",
    "logs", "heartbeat", "scheduler", "jobs", "knowledge", "recall", "config", "admin",
    "security", "autonomy", "chat", "conversations", "hofstadter", "ga", "rl", "agent", "mcp",
    "ws", "users", "settings", "workflows", "temporal", "snapshots", "addons", "tools",
    "models", "coding", "channels", "approvals", "usage", "prompt-skills", "posture",
];

/// `/api/v1/rag/extract` → `rag`; `/v1/chat/completions` and
/// `/api/external/*` → `inference`; an unknown first segment → `other`.
pub fn route_class(path: &str) -> &'static str {
    let p = path.trim_start_matches('/');
    if p.starts_with("v1/") || p.starts_with("api/external/") {
        return "inference";
    }
    let rest = p.strip_prefix("api/v1/").or_else(|| p.strip_prefix("api/")).unwrap_or(p);
    let seg = rest.split(['/', '?']).next().unwrap_or("");
    ROUTE_CLASSES.iter().find(|c| **c == seg).copied().unwrap_or("other")
}

/// Distinct values one free-text label may take before it reads `other`.
const MAX_NAMES_PER_LABEL: usize = 32;

static NAMES: Mutex<Option<HashMap<&'static str, HashSet<String>>>> = Mutex::new(None);

/// A free-text name as a bounded label value: `[a-z0-9._-]`, at most 48
/// chars, `unknown` when empty, `other` once the label already holds
/// [`MAX_NAMES_PER_LABEL`] distinct values.
pub fn bounded_name(label: &'static str, raw: &str) -> String {
    let clean: String = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(48)
        .collect();
    if clean.is_empty() {
        return "unknown".into();
    }
    let mut g = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    let set = g.get_or_insert_with(HashMap::new).entry(label).or_default();
    if set.contains(&clean) {
        return clean;
    }
    if set.len() >= MAX_NAMES_PER_LABEL {
        return "other".into();
    }
    set.insert(clean.clone());
    clean
}

/// The lanes an admitted HMAC request used. Pure except for the bounded
/// name set; the caller records and logs what this returns.
pub fn hmac_lane_uses(a: &HmacAdmission<'_>) -> Vec<LaneUse> {
    let mut out = Vec::new();
    let caller = bounded_name("caller", a.actor);
    if a.inference {
        out.push(LaneUse {
            lane: LANE_SELF_CALL,
            labels: vec![("door", a.door.as_str().into()), ("caller", caller.clone())],
        });
    } else if a.internal {
        out.push(LaneUse {
            lane: LANE_HMAC_NON_INFERENCE,
            labels: vec![
                ("kind", a.door.as_str().into()),
                ("route_class", route_class(a.path).into()),
                ("caller", caller.clone()),
            ],
        });
    }
    if !a.internal {
        // ClusterKind::Node: the fleet secret proved "a node". Was the
        // node's certificate on the connection too?
        match a.presented_node {
            Some(node) => out.push(LaneUse {
                lane: LANE_NODE_WITH_CERT,
                labels: vec![("node", bounded_name("node", node))],
            }),
            None => out.push(LaneUse {
                lane: LANE_NODE_NO_CERT,
                labels: vec![("node", bounded_name("node", a.actor)), ("route_class", route_class(a.path).into())],
            }),
        }
    }
    out
}

/// The comparator for the add-on HMAC fallback: an exchanged add-on token
/// (`sub = addon:<name>`) admitted anywhere. `None` for any other subject.
pub fn addon_token_use(sub: &str, path: &str) -> Option<LaneUse> {
    let name = sub.strip_prefix(crate::auth::ADDON_SUBJECT_PREFIX)?;
    if name.is_empty() {
        return None;
    }
    Some(LaneUse {
        lane: LANE_ADDON_EXCHANGED,
        labels: vec![("caller", bounded_name("caller", name)), ("route_class", route_class(path).into())],
    })
}

/// The comparator for the CLI's `cli-posture` HMAC: a posture write
/// admitted on an operator certificate and a token bound to it.
pub fn operator_cert_use(operator: &str, path: &str) -> LaneUse {
    LaneUse {
        lane: LANE_OPERATOR_CERT,
        labels: vec![("caller", bounded_name("caller", operator)), ("route_class", route_class(path).into())],
    }
}

/// A fleet-secret HMAC admitted in the v1 form.
pub fn hmac_v1_use(actor: &str, path: &str) -> LaneUse {
    LaneUse {
        lane: LANE_HMAC_V1,
        labels: vec![("caller", bounded_name("caller", actor)), ("route_class", route_class(path).into())],
    }
}

/// A fleet-secret HMAC in the v1 form, refused because the gate is closed.
pub fn hmac_v1_refused_use(actor: &str, path: &str) -> LaneUse {
    LaneUse {
        lane: LANE_HMAC_V1_REFUSED,
        labels: vec![("caller", bounded_name("caller", actor)), ("route_class", route_class(path).into())],
    }
}

/// The comparator: a fleet-secret HMAC admitted in the request-bound form.
pub fn hmac_v2_use(actor: &str) -> LaneUse {
    LaneUse { lane: LANE_HMAC_V2, labels: vec![("caller", bounded_name("caller", actor))] }
}

/// A controller-secret HMAC from the `noo` CLI, refused by the middleware.
pub fn cli_refusal_use(actor: &str, path: &str) -> LaneUse {
    LaneUse {
        lane: LANE_CLI_REFUSED,
        labels: vec![("caller", bounded_name("caller", actor)), ("route_class", route_class(path).into())],
    }
}

/// Who is on the other end of the socket, as far as the gateway knows
/// without believing the token: the peer IP and a verified service leaf.
#[derive(Debug, Clone, Default)]
pub struct PeerFacts {
    pub ip: Option<String>,
    pub service: Option<String>,
}

impl PeerFacts {
    pub fn of(request: &axum::extract::Request) -> Self {
        let ip = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|axum::extract::ConnectInfo(a)| a.ip().to_string());
        let service = request
            .extensions()
            .get::<Option<crate::node_identity::VerifiedService>>()
            .and_then(|s| s.as_ref())
            .map(|s| s.0.clone());
        PeerFacts { ip, service }
    }

    /// `ip=… leaf=…`, for a log line. Never a secret, never a token.
    pub fn describe(&self) -> String {
        format!(
            "ip={} leaf={}",
            self.ip.as_deref().unwrap_or("unknown"),
            self.service.as_deref().unwrap_or("none")
        )
    }
}

static LAST_LOGGED: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// True at most once per `every` for `key`. The key space is built from
/// bounded labels only; the map is cleared if it ever grows past 1024.
pub fn log_due(key: &str, every: Duration) -> bool {
    let now = Instant::now();
    let mut g = LAST_LOGGED.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() > 1024 {
        m.clear();
    }
    match m.get(key) {
        Some(t) if now.duration_since(*t) < every => false,
        _ => {
            m.insert(key.to_string(), now);
            true
        }
    }
}

/// How often the node-token-without-a-certificate WARN repeats per node.
pub const NODE_NO_CERT_LOG_EVERY: Duration = Duration::from_secs(3600);
/// How often the HMAC-on-a-non-inference-route DEBUG repeats per
/// (kind, route class, caller).
pub const HMAC_NON_INFERENCE_LOG_EVERY: Duration = Duration::from_secs(600);
/// How often the v1-token INFO repeats per caller.
pub const HMAC_V1_LOG_EVERY: Duration = Duration::from_secs(3600);
/// How often the v1 request detail (method, path, body-hash header, token
/// age) repeats per caller: often enough to catch an intermittent sender.
pub const HMAC_V1_DETAIL_LOG_EVERY: Duration = Duration::from_secs(300);
/// How often the old-CLI refusal WARN repeats per (caller, route class).
pub const CLI_REFUSED_LOG_EVERY: Duration = Duration::from_secs(600);

/// Count every use, and log the lanes that have no per-request log of their
/// own (the self-call lane logs at its door, every time, already).
pub async fn observe(metrics: &crate::metrics::MetricsState, uses: &[LaneUse], peer: &PeerFacts) {
    for u in uses {
        let mut labels: HashMap<String, String> =
            u.labels.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        labels.insert("lane".into(), u.lane.into());
        metrics.inc_counter(METRIC, Some(&labels), 1).await;
        match u.lane {
            LANE_NODE_NO_CERT => {
                let node = u.label("node");
                if log_due(&format!("{LANE_NODE_NO_CERT}|{node}"), NODE_NO_CERT_LOG_EVERY) {
                    tracing::warn!(
                        node, route_class = u.label("route_class"), peer = %peer.describe(),
                        "legacy lane: a node token was admitted with NO client certificate on the \
                         connection (once per node per hour — the count is \
                         noo_legacy_lane_uses_total{{lane=\"node_token_no_cert\"}})"
                    );
                }
            }
            LANE_HMAC_NON_INFERENCE => {
                let key = format!("{LANE_HMAC_NON_INFERENCE}|{}|{}|{}", u.label("kind"), u.label("route_class"), u.label("caller"));
                if log_due(&key, HMAC_NON_INFERENCE_LOG_EVERY) {
                    tracing::debug!(
                        kind = u.label("kind"), route_class = u.label("route_class"), caller = u.label("caller"),
                        peer = %peer.describe(),
                        "legacy lane: a shared-secret HMAC was admitted as Internal on a non-inference \
                         route (an add-on here is on its HMAC fallback, not its own key)"
                    );
                }
            }
            LANE_HMAC_V1 => {
                let key = format!("{LANE_HMAC_V1}|{}", u.label("caller"));
                if log_due(&key, HMAC_V1_LOG_EVERY) {
                    tracing::info!(
                        caller = u.label("caller"), route_class = u.label("route_class"), peer = %peer.describe(),
                        "legacy lane: a v1 cluster token (not bound to its request) — that caller must upgrade \
                         to sign v2 (once per caller per hour; the count is \
                         noo_legacy_lane_uses_total{{lane=\"cluster_hmac_v1\"}})"
                    );
                }
            }
            LANE_CLI_REFUSED => {
                let key = format!("{LANE_CLI_REFUSED}|{}|{}", u.label("caller"), u.label("route_class"));
                if log_due(&key, CLI_REFUSED_LOG_EVERY) {
                    tracing::warn!(
                        caller = u.label("caller"), route_class = u.label("route_class"),
                        peer = %peer.describe(),
                        "REFUSED: a `noo` CLI signed with the controller's shared secret, which the \
                         gateway no longer accepts from the CLI — that binary is older than the \
                         break-glass removal; upgrade it: noo upgrade --all (once per caller and \
                         route class per 10 min; the count is \
                         noo_legacy_lane_uses_total{{lane=\"cli_shared_secret_refused\"}})"
                    );
                }
            }
            _ => {}
        }
    }
}

/// Unix seconds this gateway process started, for `/metrics`
/// (`noo_gateway_start_time_seconds`). A counter since start is evidence
/// only with its window beside it — "0 uses in 15 minutes" is not.
pub fn process_start_unix() -> u64 {
    static START: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *START.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MetricsState;

    fn adm<'a>(door: HmacDoor, internal: bool, inference: bool, path: &'a str, actor: &'a str, cert: Option<&'a str>) -> HmacAdmission<'a> {
        HmacAdmission { door, internal, inference, path, actor, presented_node: cert }
    }

    async fn rendered(uses: &[LaneUse]) -> String {
        let m = MetricsState::new();
        observe(&m, uses, &PeerFacts::default()).await;
        m.render().await
    }

    #[test]
    fn routes_bucket_into_bounded_classes() {
        assert_eq!(route_class("/v1/chat/completions"), "inference");
        assert_eq!(route_class("/api/external/embeddings"), "inference");
        assert_eq!(route_class("/api/v1/rag/extract"), "rag");
        assert_eq!(route_class("/api/cluster/nodes/host3/heartbeat"), "cluster");
        assert_eq!(route_class("/api/hofstadter/state"), "hofstadter");
        assert_eq!(route_class("/bootstrap/bundle/host3/applied"), "bootstrap");
        assert_eq!(route_class("/api/0123456789abcdef/x"), "other");
        assert_eq!(route_class("/"), "other");
    }

    /// Lane 1: either secret buying inference.
    #[tokio::test]
    async fn the_self_call_lane_counts_per_door() {
        let c = hmac_lane_uses(&adm(HmacDoor::Controller, true, true, "/v1/chat/completions", "trellion", None));
        assert_eq!(c.len(), 1);
        let out = rendered(&c).await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="trellion",door="controller",lane="self_call_shared_secret"} 1"#), "{out}");
        // A node on the fleet secret buying embeddings: lane 1 AND lane 3.
        let n = hmac_lane_uses(&adm(HmacDoor::Cluster, false, true, "/api/external/embeddings", "host3", None));
        let out = rendered(&n).await;
        assert!(out.contains(r#"door="cluster",lane="self_call_shared_secret""#), "{out}");
        assert!(out.contains(r#"lane="node_token_no_cert",node="host3",route_class="inference""#), "{out}");
    }

    /// Lane 2: Internal on anything but inference, bucketed by class.
    #[tokio::test]
    async fn the_hmac_non_inference_lane_counts_by_kind_and_route_class() {
        let u = hmac_lane_uses(&adm(HmacDoor::Controller, true, false, "/api/v1/graph/extract", "trellion", None));
        assert_eq!(u.len(), 1);
        let out = rendered(&u).await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="trellion",kind="controller",lane="cluster_hmac_non_inference",route_class="graph"} 1"#), "{out}");
        // The legacy full-access mode: a fleet HMAC resolving Internal.
        let l = hmac_lane_uses(&adm(HmacDoor::Cluster, true, false, "/api/cluster/placements", "x", None));
        assert_eq!(l[0].lane, LANE_HMAC_NON_INFERENCE);
        assert_eq!(l[0].label("kind"), "cluster");
        assert!(l.iter().all(|u| u.lane != LANE_NODE_NO_CERT), "an Internal caller is not a node token");
    }

    /// Lane 3 and its comparator.
    #[tokio::test]
    async fn node_tokens_count_with_and_without_a_certificate() {
        let without = hmac_lane_uses(&adm(HmacDoor::Cluster, false, false, "/api/cluster/nodes/host9/heartbeat", "host9", None));
        assert_eq!(without, vec![LaneUse { lane: LANE_NODE_NO_CERT, labels: vec![("node", "host9".into()), ("route_class", "cluster".into())] }]);
        let with = hmac_lane_uses(&adm(HmacDoor::Cluster, false, false, "/api/cluster/nodes/host9/heartbeat", "host9", Some("host9")));
        assert_eq!(with, vec![LaneUse { lane: LANE_NODE_WITH_CERT, labels: vec![("node", "host9".into())] }]);
        let out = rendered(&[without[0].clone(), without[0].clone(), with[0].clone()]).await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{lane="node_token_no_cert",node="host9",route_class="cluster"} 2"#), "{out}");
        assert!(out.contains(r#"noo_legacy_lane_uses_total{lane="node_token_with_cert",node="host9"} 1"#), "{out}");
    }

    #[tokio::test]
    async fn an_exchanged_addon_token_is_the_comparator_and_nothing_else_is() {
        let u = addon_token_use("addon:evolve", "/api/hofstadter/state").expect("an add-on subject");
        let out = rendered(&[u]).await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="evolve",lane="addon_exchanged_token",route_class="hofstadter"} 1"#), "{out}");
        assert!(addon_token_use("alice", "/api/chat").is_none());
        assert!(addon_token_use("addon:", "/api/chat").is_none());
    }

    /// The CLI's controller-secret HMAC is refused and counted as a refusal,
    /// never as an admitted `cluster_hmac_non_inference` use.
    #[tokio::test]
    async fn an_old_cli_is_counted_as_refused() {
        let u = cli_refusal_use("cli-posture", "/api/security/posture");
        let out = rendered(&[u.clone(), u]).await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="cli-posture",lane="cli_shared_secret_refused",route_class="security"} 2"#), "{out}");
        assert!(!out.contains("cluster_hmac_non_inference"), "a refusal is not an admitted use: {out}");
    }

    /// A v1 token refused at a closed gate is its own lane: the admitted
    /// `cluster_hmac_v1` series does not move.
    #[tokio::test]
    async fn a_refused_v1_token_is_not_counted_as_admitted() {
        let out = rendered(&[hmac_v1_refused_use("pop-os", "/api/cluster/nodes/pop-os/heartbeat")]).await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="pop-os",lane="cluster_hmac_v1_refused",route_class="cluster"} 1"#), "{out}");
        assert!(!out.contains(r#"lane="cluster_hmac_v1""#), "a refusal is not an admitted use: {out}");
    }

    /// The controller door refuses the CLI's actors BEFORE it classifies or
    /// admits anything, and counts each refusal. Without the count, an old
    /// binary still in use would be a 403 nobody can attribute.
    #[test]
    fn the_controller_door_refuses_and_counts_the_cli_before_admitting() {
        let src = include_str!("auth.rs");
        let door = src.split("pub async fn controller_door(").nth(1).expect("the controller door")
            .split("\npub async fn ").next().unwrap();
        let refusal = door.split("if crate::operator_auth::is_cli_actor(actor) {").nth(1)
            .expect("the controller door must refuse the CLI's actors first");
        let refusal = refusal.split("\n    }\n").next().unwrap();
        assert!(refusal.contains("crate::legacy_lanes::cli_refusal_use(actor, path)"), "the refusal is not classified: {refusal}");
        assert!(refusal.contains("crate::legacy_lanes::observe(metrics, &[u], peer).await"), "the refusal is not counted: {refusal}");
        assert!(refusal.contains("return old_cli_refusal();"), "the refusal does not answer with the upgrade: {refusal}");
    }

    #[test]
    fn free_text_names_are_bounded() {
        assert_eq!(bounded_name("test_label", "  Trel\"lion}\n "), "trellion");
        assert_eq!(bounded_name("test_label", ""), "unknown");
        for i in 0..(MAX_NAMES_PER_LABEL * 2) {
            let _ = bounded_name("test_bound", &format!("n{i}"));
        }
        assert_eq!(bounded_name("test_bound", "brand-new"), "other");
        assert_eq!(bounded_name("test_bound", "n0"), "n0", "an admitted name keeps its series");
    }

    #[test]
    fn a_log_key_fires_once_per_window() {
        assert!(log_due("test|a", Duration::from_secs(3600)));
        assert!(!log_due("test|a", Duration::from_secs(3600)));
        assert!(log_due("test|b", Duration::from_secs(3600)));
        assert!(log_due("test|c", Duration::ZERO));
        assert!(log_due("test|c", Duration::ZERO));
    }

    /// The doors call this module. A classification nobody calls is the
    /// silent-success shape: every test here green, no counter on /metrics.
    #[test]
    fn both_hmac_doors_and_the_addon_token_path_record_their_lanes() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).expect("the middleware")
            .split("\npub async fn ").next().unwrap();
        // Each ADMITTING door classifies AND records before it admits: the
        // text from its HmacDoor to the door's `return Ok(` must hold the
        // observe(). The controller door admits nothing;
        // its refusal records through controller_hmac_refusal::refuse
        // (pinned by auth.rs `the_controller_door_admits_nothing`).
        assert!(!body.contains("door: crate::legacy_lanes::HmacDoor::Controller,"),
            "the controller door classifies an admission again — it admits nothing");
        let after = body.split("door: crate::legacy_lanes::HmacDoor::Cluster,").nth(1)
            .expect("the Cluster door classifies no lane");
        let until_admit = after.split("return Ok(").next().unwrap();
        assert!(until_admit.contains("crate::legacy_lanes::observe(&state.metrics, &uses, &peer).await"),
            "the Cluster door classifies but never records its lane");
        // Both admission points of an exchanged add-on token count it.
        let addon: Vec<&str> = body.split("crate::legacy_lanes::addon_token_use(").skip(1).collect();
        assert_eq!(addon.len(), 2, "expected the inference and the general JWT admission to count an add-on token");
        for a in addon {
            assert!(a.split("return Ok(").next().unwrap().contains("crate::legacy_lanes::observe("),
                "an add-on token use is classified but not recorded");
        }
        let core = include_str!("routes/core.rs");
        assert!(core.contains("noo_gateway_start_time_seconds"), "/metrics must carry the counters' window");
    }
}
