// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Legacy credential lanes, OBSERVED.
//!
//! One way in is still ADMITTED, kept only for callers nobody has proven
//! are gone; the rest of what this module counts is refusals and comparators:
//!
//! | lane | what happens |
//! |---|---|
//! | `node_token_no_cert` | ADMITTED: a fleet-secret HMAC resolving to `ClusterKind::Node` with no client certificate on the connection (mTLS not enforcing) |
//! | `cluster_hmac_v1_refused` | REFUSED: a fleet-secret HMAC in the v1 wire form (not bound to its request) answers `401 cluster_token_v1_refused`; the v2 form is the comparator `cluster_hmac_v2`. The v1 admission lane and its `NOO_CLUSTER_TOKEN_V1` gate are deleted |
//! | `self_call_shared_secret_refused` | REFUSED: a fleet-secret HMAC on the inference surface (`/v1/*`, `/api/external/*`). The shared secret never buys inference; the `NOO_SELF_CALL_SHARED_SECRET` bridge that once could is deleted |
//! | `cli_shared_secret_refused` | REFUSED: a controller-secret HMAC signed by an old `noo` CLI (`controller_door`) |
//! | `controller_shared_secret_refused`, `fleet_secret_off_node_refused`, `fleet_token_no_cert_refused`, `addon_shared_secret_refused` | REFUSED: see `controller_hmac_refusal.rs` and `addon_hmac_refusal.rs` |
//! | `node_token_with_cert`, `cluster_hmac_v2`, `addon_exchanged_token`, `operator_client_cert` | comparators: the good case of the lane they sit beside |
//! | (node side) `static_token`, `cluster_hmac_v1_refused` | reported by each node agent on its heartbeat as `legacy_lanes` |
//!
//! Retired lanes, no longer counted: `cluster_hmac_v1` (v1 admissions: the
//! `NOO_CLUSTER_TOKEN_V1` gate was closed fleet-wide 2026-10-26 and the lane
//! deleted; only `cluster_hmac_v1_refused` remains, for one release), `self_call_shared_secret` (the
//! `NOO_SELF_CALL_SHARED_SECRET` bridge: 0 uses live, and the fleet door
//! refuses the inference surface before the bridge could be consulted) and
//! `cluster_hmac_non_inference` (a shared-secret HMAC resolving to
//! `ClusterKind::Internal`: the controller door admits nothing and the fleet
//! door only ever grants `Node`, so nothing can set it).
//!
//! The `noo` CLI is no longer on any of these lanes. Its controller-secret
//! actors (`cli`, `cli-posture`, `cli-onboard`, `cli-break-glass`) are
//! REFUSED by the middleware on every route, never admitted (operator
//! decision 2026-10-03: no break-glass, no onboard bootstrap). Each refusal
//! is counted under the same family as
//! `noo_legacy_lane_uses_total{lane="cli_shared_secret_refused",caller,route_class}`
//! ([`LANE_CLI_REFUSED`]), so an old binary still in use is visible by name.
//!
//! Apart from the refused lanes, this module decides nothing and
//! refuses nothing. It classifies an
//! ADMITTED request into the lanes it used and counts them under one
//! Prometheus family, `noo_legacy_lane_uses_total{lane=…}`, beside the
//! comparator lanes that are the replacement so a ratio is visible. `noo cluster verify
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

/// REFUSED, not admitted: a fleet-secret HMAC on the inference surface. The
/// shared secret never buys inference (the `NOO_SELF_CALL_SHARED_SECRET`
/// bridge is deleted). Every count is a caller that must present its own
/// service key.
pub const LANE_SELF_CALL_REFUSED: &str = "self_call_shared_secret_refused";
pub const LANE_NODE_NO_CERT: &str = "node_token_no_cert";
/// Comparator: the good case of [`LANE_NODE_NO_CERT`].
pub const LANE_NODE_WITH_CERT: &str = "node_token_with_cert";
/// Comparator: the add-on's own exchanged token, the replacement for the
/// add-on HMAC fallback (now refused as `addon_shared_secret_refused`).
pub const LANE_ADDON_EXCHANGED: &str = "addon_exchanged_token";
/// Comparator: a posture write on an operator client certificate plus a
/// token bound to it — the replacement for the CLI's `cli-posture` HMAC
/// (now refused as `cli_shared_secret_refused`).
pub const LANE_OPERATOR_CERT: &str = "operator_client_cert";
/// REFUSED, not admitted: a fleet-secret HMAC in the v1 wire form
/// (`<actor>:<ts>:<hmac>`, signed over actor and time only, so a captured
/// header replays on any route for five minutes). The v1 lane and its
/// `NOO_CLUSTER_TOKEN_V1` gate are deleted; v1 is always refused. Every count
/// is a caller (by name) whose calls all fail until it signs v2.
pub const LANE_HMAC_V1_REFUSED: &str = "cluster_hmac_v1_refused";
/// Comparator: the request-bound v2 form, the only form admitted.
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

/// A fleet-secret HMAC request (a `ClusterKind::Node` admission) the
/// middleware has decided to ADMIT. The inference surface is refused before
/// this is built, and the fleet door never grants `Internal`.
#[derive(Debug, Clone)]
pub struct HmacAdmission<'a> {
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

/// The lanes an admitted fleet-secret HMAC request used. Pure except for
/// the bounded name set; the caller records and logs what this returns.
pub fn hmac_lane_uses(a: &HmacAdmission<'_>) -> Vec<LaneUse> {
    // ClusterKind::Node: the fleet secret proved "a node". Was the node's
    // certificate on the connection too?
    let used = match a.presented_node {
        Some(node) => LaneUse {
            lane: LANE_NODE_WITH_CERT,
            labels: vec![("node", bounded_name("node", node))],
        },
        None => LaneUse {
            lane: LANE_NODE_NO_CERT,
            labels: vec![("node", bounded_name("node", a.actor)), ("route_class", route_class(a.path).into())],
        },
    };
    vec![used]
}

/// A fleet-secret HMAC on the inference surface, refused.
pub fn self_call_refusal_use(actor: &str, door: HmacDoor) -> LaneUse {
    LaneUse {
        lane: LANE_SELF_CALL_REFUSED,
        labels: vec![("door", door.as_str().into()), ("caller", bounded_name("caller", actor))],
    }
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

/// A fleet-secret HMAC in the v1 form, refused.
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
/// How often the inference-surface refusal WARN repeats per (door, caller).
pub const SELF_CALL_REFUSED_LOG_EVERY: Duration = Duration::from_secs(600);
/// How often the v1-token refusal WARN repeats per caller.
pub const HMAC_V1_LOG_EVERY: Duration = Duration::from_secs(3600);
/// How often the v1 request detail (method, path, body-hash header, token
/// age) repeats per caller: often enough to catch an intermittent sender.
pub const HMAC_V1_DETAIL_LOG_EVERY: Duration = Duration::from_secs(300);
/// How often the old-CLI refusal WARN repeats per (caller, route class).
pub const CLI_REFUSED_LOG_EVERY: Duration = Duration::from_secs(600);

/// Count every use, and log the lanes that have no per-request log of their
/// own.
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
            LANE_SELF_CALL_REFUSED => {
                let key = format!("{LANE_SELF_CALL_REFUSED}|{}|{}", u.label("door"), u.label("caller"));
                if log_due(&key, SELF_CALL_REFUSED_LOG_EVERY) {
                    tracing::warn!(
                        door = u.label("door"), caller = u.label("caller"), peer = %peer.describe(),
                        "REFUSED: a shared-secret HMAC on the inference surface — the shared secret \
                         never buys inference; the caller must present its own service key (mint \
                         one with `noo security service-key issue <consumer>`) (once per caller \
                         per 10 min; the count is \
                         noo_legacy_lane_uses_total{{lane=\"self_call_shared_secret_refused\"}})"
                    );
                }
            }
            LANE_HMAC_V1_REFUSED => {
                let key = format!("{LANE_HMAC_V1_REFUSED}|{}", u.label("caller"));
                if log_due(&key, HMAC_V1_LOG_EVERY) {
                    tracing::warn!(
                        caller = u.label("caller"), route_class = u.label("route_class"), peer = %peer.describe(),
                        "REFUSED: a v1 cluster token (not bound to its request) — that caller must upgrade \
                         to sign v2 (`noo upgrade --nodes`) (once per caller per hour; the count is \
                         noo_legacy_lane_uses_total{{lane=\"cluster_hmac_v1_refused\"}})"
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

    fn adm<'a>(path: &'a str, actor: &'a str, cert: Option<&'a str>) -> HmacAdmission<'a> {
        HmacAdmission { path, actor, presented_node: cert }
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

    /// The retired self-call lane is a REFUSAL now, counted per door and
    /// caller; an admission is only ever a node token with or without a cert.
    #[tokio::test]
    async fn the_self_call_refusal_counts_per_door_and_is_never_an_admission() {
        let u = self_call_refusal_use("host3", HmacDoor::Cluster);
        let out = rendered(&[u.clone(), u]).await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="host3",door="cluster",lane="self_call_shared_secret_refused"} 2"#), "{out}");
        for u in hmac_lane_uses(&adm("/api/embed", "host3", None)) {
            assert_eq!(u.lane, LANE_NODE_NO_CERT);
        }
    }

    /// Lane 3 and its comparator.
    #[tokio::test]
    async fn node_tokens_count_with_and_without_a_certificate() {
        let without = hmac_lane_uses(&adm("/api/cluster/nodes/host9/heartbeat", "host9", None));
        assert_eq!(without, vec![LaneUse { lane: LANE_NODE_NO_CERT, labels: vec![("node", "host9".into()), ("route_class", "cluster".into())] }]);
        let with = hmac_lane_uses(&adm("/api/cluster/nodes/host9/heartbeat", "host9", Some("host9")));
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
    /// never as an admitted use of a retired lane.
    #[tokio::test]
    async fn an_old_cli_is_counted_as_refused() {
        let u = cli_refusal_use("cli-posture", "/api/security/posture");
        let out = rendered(&[u.clone(), u]).await;
        assert!(out.contains(r#"noo_legacy_lane_uses_total{caller="cli-posture",lane="cli_shared_secret_refused",route_class="security"} 2"#), "{out}");
        assert!(!out.contains("cluster_hmac_non_inference") && !out.contains(r#"lane="self_call_shared_secret""#), "a refusal is not an admitted use: {out}");
    }

    /// A refused v1 token is counted on its own lane; there is no admitted
    /// `cluster_hmac_v1` series any more.
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
    fn the_fleet_door_and_the_addon_token_path_record_their_lanes() {
        let src = include_str!("auth.rs");
        let body = src.split("pub async fn require_any_auth(").nth(1).expect("the middleware")
            .split("\npub async fn ").next().unwrap();
        // The ADMITTING door (the fleet door) classifies AND records before
        // it admits: the text from its HmacAdmission to the door's
        // `return Ok(` must hold the observe(). The controller door admits nothing;
        // its refusal records through controller_hmac_refusal::refuse
        // (pinned by auth.rs `the_controller_door_admits_nothing`).
        assert_eq!(body.matches("crate::legacy_lanes::HmacAdmission {").count(), 1,
            "exactly one door (the fleet door) classifies an admission — the controller door admits nothing");
        let after = body.split("crate::legacy_lanes::HmacAdmission {").nth(1)
            .expect("the fleet door classifies no lane");
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
