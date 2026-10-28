// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Which credential the gateway presents to a node agent.
//!
//! Every controller-only route on a node agent admits a caller by its
//! verified client certificate: the gateway's leaf (O="Mesh Cluster
//! Gateway") is what tells the controller from a peer. The bearer the
//! gateway sent beside it — `NOO_NODE_AGENT_TOKEN`, else an HMAC over the
//! fleet secret — is a secret EVERY node holds, so it never identified the
//! controller. It only kept the agent's `static_token` legacy lane busy
//! (7,900 uses in 27 minutes across 6 nodes on host8, most of it the /gpu
//! and inference traffic).
//!
//! An agent that admits the controller's leaf with no bearer says so on
//! registration and every heartbeat (`controller_leaf_only: true`,
//! node-agent-go `auth.ControllerLeafOrToken`). For those agents the
//! gateway sends no bearer at all. Every other agent — older builds, a
//! node whose record has not said — keeps receiving the bearer, so the
//! gateway and the agents can roll in either order.
//!
//! Never the fleet HMAC as a substitute: that is the same shared-secret
//! lane under another name.
//!
//! The capability is held in memory, keyed by the agent's address
//! (`host:port`), because the call sites hold a URL and one of them
//! (`coordinator::backend::with_backend_hint_url`) is synchronous. It is
//! fed by `node_heartbeat` / `node_register_body` and seeded from the
//! `mesh_nodes` KV at startup, so a gateway restart does not fall back to
//! the bearer until every node has beaten again.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

/// The heartbeat / registration field, and the node-record field.
pub(crate) const CAPABILITY: &str = "controller_leaf_only";

#[derive(Clone, Default)]
struct Agent {
    /// `host:port` the gateway dials this node's agent at.
    authorities: Vec<String>,
    /// The node on the controller's own device (`self_node`); the
    /// enrollment routes reach it by a configured URL, not its record.
    self_node: bool,
}

/// Nodes whose agent reported the capability, by node id.
static LEAF_ONLY: LazyLock<RwLock<HashMap<String, Agent>>> = LazyLock::new(Default::default);

/// Did this registration / heartbeat body (or node record) report the
/// capability? Absent, null or false all read as "no": an agent that has
/// not said keeps receiving the bearer.
pub(crate) fn reported(body: &Value) -> bool {
    body.get(CAPABILITY).and_then(Value::as_bool) == Some(true)
}

/// `host:port`, lower-cased, of a URL; `None` when it does not parse.
fn authority(url: &str) -> Option<String> {
    let u = reqwest::Url::parse(url.trim()).ok()?;
    let host = u.host_str()?.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    let port = u.port_or_known_default()?;
    Some(format!("{host}:{port}"))
}

/// The addresses the gateway dials this node's agent at: the record's
/// `agent_url` (`get_node_agent_url`), and `https://{ip}:8081` — which the
/// inference and coordinator paths build directly — unless `agent_url`
/// names another port (a second agent on the same host is a different node).
fn record_authorities(record: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let agent_url = record.get("agent_url").and_then(Value::as_str).and_then(authority);
    let ip = record
        .get("ip_address")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|ip| authority(&format!("https://{ip}:8081")));
    let ip_ok = agent_url.as_deref().is_none_or(|a| a.ends_with(":8081"));
    if let Some(a) = agent_url {
        out.push(a);
    }
    if let (Some(a), true) = (ip, ip_ok) {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// Record what a node's latest registration / heartbeat said, from the node
/// record as written (`data`, which carries `CAPABILITY` and the address).
///
/// The newest report OWNS its addresses: they are struck from every other
/// node first, so an address that moved to an agent that does not report
/// the capability gets the bearer again.
pub(crate) fn note(node_id: &str, record: &Value) {
    let authorities = record_authorities(record);
    let flagged = reported(record);
    let self_node = record.get("self_node").and_then(Value::as_bool) == Some(true);
    let Ok(mut map) = LEAF_ONLY.write() else { return };
    map.remove(node_id);
    if self_node {
        // The self node's own report is authoritative from its first beat:
        // what the startup probe learned before it is dropped either way.
        map.remove(SELF_PROBE_KEY);
        SELF_BEAT_SEEN.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    for agent in map.values_mut() {
        agent.authorities.retain(|a| !authorities.contains(a));
    }
    if flagged {
        map.insert(node_id.to_string(), Agent { authorities, self_node });
    }
}

/// Seed from the `mesh_nodes` KV so a restarted gateway does not resend the
/// bearer until each node beats again. Bounded: a slow KV leaves the map
/// empty, which only means the bearer is sent (the safe direction).
pub(crate) async fn seed(state: &crate::state::AppState) {
    let work = async {
        let Ok(kv) = state.js.get_key_value("mesh_nodes").await else { return 0usize };
        let Ok(keys) = kv.keys().await else { return 0 };
        use tokio_stream::StreamExt;
        let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
        let mut n = 0;
        for key in keys {
            if let Ok(Some(raw)) = kv.get(&key).await {
                if let Ok(record) = serde_json::from_slice::<Value>(&raw) {
                    if reported(&record) {
                        n += 1;
                    }
                    note(&key, &record);
                }
            }
        }
        n
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), work).await {
        Ok(n) => tracing::info!(nodes = n, "node_agent_leaf_only_seeded"),
        Err(_) => tracing::warn!("node_agent_leaf_only_seed_timed_out — bearer sent until each node beats"),
    }
    // The KV is empty after the bus was down longer than its TTL (a reboot,
    // a stack upgrade): ask the controller's own agent directly, so the
    // first self-agent call (a kiosk mint's whois) does not carry the bearer.
    if let Ok(base) = crate::routes::self_agent_base() {
        learn_self_agent(crate::tls::cluster_client(), base, SELF_PROBE_TRIES, SELF_PROBE_GAP).await;
    }
}

/// Does the agent at `url` admit the controller's leaf with no bearer?
pub(crate) fn leaf_only(url: &str) -> bool {
    let Some(a) = authority(url) else { return false };
    let Ok(map) = LEAF_ONLY.read() else { return false };
    map.values().any(|agent| agent.authorities.contains(&a))
}

/// The bearer for a call to the node agent at `url`, or `None` when that
/// agent admits the gateway's leaf alone (or no credential is configured).
pub(crate) fn header_for(url: &str) -> Option<(String, String)> {
    if leaf_only(url) {
        return None;
    }
    let b = bearer();
    if b.is_none() {
        // Not silent: no static token and the agent has not (yet) said
        // `controller_leaf_only`, so it gets no bearer and relies on the
        // gateway's leaf. A current agent admits that; a pre-0.6.0 agent
        // refuses it and the node reads as unreachable.
        if let Some(a) = authority(url) {
            if crate::legacy_lanes::log_due(&format!("no_leaf_only|{a}"), NO_LEAF_ONLY_LOG_EVERY) {
                tracing::warn!(
                    agent = %a,
                    "node agent at {a} has not reported controller_leaf_only and NOO_NODE_AGENT_TOKEN is unset: \
                     sending no bearer (the gateway's client certificate is the credential). \
                     Fix: upgrade the agent (`noo upgrade --nodes`) or set NOO_NODE_AGENT_TOKEN"
                );
            }
        }
    }
    b
}

/// How often the missing-`controller_leaf_only` WARN repeats per agent.
const NO_LEAF_ONLY_LOG_EVERY: std::time::Duration = std::time::Duration::from_secs(900);

/// [`header_for`] for the controller's OWN agent, reached by
/// `bootstrap::self_agent_base` (a configured URL that need not match the
/// address on its record): leaf-only also when the self node reported it,
/// or, before its first beat, when the startup probe found it admits the leaf.
pub(crate) fn header_for_self(url: &str) -> Option<(String, String)> {
    if self_flagged() {
        return None;
    }
    header_for(url)
}

/// The self agent admits the leaf alone: its node reported it, or (before
/// its first beat) the startup probe found it does.
fn self_flagged() -> bool {
    LEAF_ONLY.read().map(|m| m.values().any(|a| a.self_node)).unwrap_or(false)
}

// ── The controller's own agent, before its first heartbeat ─────────
//
// `header_for_self` used to know the self agent only from its heartbeat.
// The `mesh_nodes` KV has a 120 s TTL, so after the bus was down longer than
// that (a reboot, a stack upgrade that recreates NATS) `seed` finds nothing,
// and every self-agent call before that agent's first beat carried
// `NOO_NODE_AGENT_TOKEN`. On pop-os 2026-10-28 the kiosk seat's keyless mint
// (`/api/kiosk/token/tailnet` → `GET /tailnet/whois`) landed 17 s after the
// gateway started and before the beat: the agent's `static_token` lane
// counted it, the only static-token use left in the fleet.
//
// So at startup the gateway asks its own agent's `/health` with its leaf and
// NO bearer. The agent answers the node detail (`node_id`) without a bearer
// only to a caller it admits by the controller's leaf
// (`auth.IsControllerLeafWithoutBearer`, the predicate `ControllerLeafOrToken`
// admits on), so a detailed answer IS the capability. A bare answer (an agent
// that does not verify client certificates) keeps the bearer; no answer
// leaves it too, and the probe is retried until the agent answers or beats.

/// Map key for what the startup probe learned. Not a node id (node ids never
/// start with a NUL); [`note`] for the self node replaces it.
const SELF_PROBE_KEY: &str = "\u{0}self-agent-probe";
const SELF_PROBE_TRIES: u32 = 30;
/// The self node has beaten since this gateway started: the probe is moot.
static SELF_BEAT_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn self_beat_seen() -> bool {
    SELF_BEAT_SEEN.load(std::sync::atomic::Ordering::Relaxed)
}
const SELF_PROBE_GAP: std::time::Duration = std::time::Duration::from_secs(2);

/// Did the self agent's `/health`, asked with no bearer, answer with the node
/// detail? It does only for a caller it admitted by the controller's leaf.
pub(crate) fn self_agent_admits_leaf(health: &Value) -> bool {
    health.get("node_id").and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty())
}

/// Record the startup probe's answer. Ignored once the self node has beaten:
/// its report is the authority.
fn note_self_probe(admitted: bool) {
    let Ok(mut map) = LEAF_ONLY.write() else { return };
    if self_beat_seen() {
        return;
    }
    map.remove(SELF_PROBE_KEY);
    if admitted {
        map.insert(SELF_PROBE_KEY.to_string(), Agent { authorities: Vec::new(), self_node: true });
    }
}

/// Ask the self agent at `base` once (its `/health`, no bearer, the
/// gateway's leaf on `client`). `None`: no answer.
pub(crate) async fn probe_self_agent(client: &reqwest::Client, base: &str) -> Option<bool> {
    let mut u = reqwest::Url::parse(base.trim()).ok()?;
    u.set_path("/health");
    u.set_query(None);
    let resp = client.get(u).timeout(std::time::Duration::from_secs(3)).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    Some(self_agent_admits_leaf(&resp.json::<Value>().await.ok()?))
}

/// Learn the self agent's credential before its first beat. The first try is
/// awaited (startup, before the router serves); while the agent does not
/// answer, the rest run in the background every `gap`, stopping at the first
/// answer or once its heartbeat has said.
pub(crate) async fn learn_self_agent(client: reqwest::Client, base: String, tries: u32, gap: std::time::Duration) {
    if self_beat_seen() {
        return;
    }
    if let Some(admitted) = probe_self_agent(&client, &base).await {
        note_self_probe(admitted);
        tracing::info!(agent = %base, leaf_only = admitted, "self agent credential learned before its first heartbeat");
        return;
    }
    tokio::spawn(async move {
        for _ in 1..tries {
            tokio::time::sleep(gap).await;
            if self_beat_seen() {
                return;
            }
            if let Some(admitted) = probe_self_agent(&client, &base).await {
                note_self_probe(admitted);
                tracing::info!(agent = %base, leaf_only = admitted, "self agent credential learned before its first heartbeat");
                return;
            }
        }
    });
}

/// The legacy bearer: `NOO_NODE_AGENT_TOKEN` when set, else none. Never a
/// minted HMAC (v1 is refused by every agent; see
/// `routes::cluster::node_agent_bearer`). Private: a call site asks
/// [`header_for`], which decides per agent.
fn bearer() -> Option<(String, String)> {
    crate::routes::cluster::node_agent_bearer(crate::config::secret_env::secret_opt("NOO_NODE_AGENT_TOKEN").as_deref())
        .map(|b| ("Authorization".into(), b))
}

// ── The harness and its own agent ─────────
//
// `noo-gateway harness` runs this binary on a node and calls ITS OWN agent
// (`NOO_HARNESS_MODEL_URL`, `https://127.0.0.1:8081`) for a model, with this
// node's leaf. It has no heartbeat feed, so the map above is never fed for
// it by `note`. Instead it asks the agent: a new agent answers the harness's
// own leaf on `/health` with `own_harness_leaf_only: true`
// (node-agent-go `auth.OwnHarnessLeafOrToken`), and only then does the
// harness drop the bearer. An older agent omits the field and keeps getting
// it; a probe that fails also keeps it. Re-asked every
// [`OWN_AGENT_RECHECK`], so a rolled-back agent gets the bearer back.

/// The `/health` field the agent writes for its own harness.
pub(crate) const OWN_HARNESS_CAPABILITY: &str = "own_harness_leaf_only";

/// Map key for the harness's own agent. Not a node id: node ids never start
/// with a NUL, so `note` for a real node never replaces it.
const OWN_AGENT_KEY: &str = "\u{0}own-agent";

/// How often the harness re-reads its agent's capability.
pub(crate) const OWN_AGENT_RECHECK: std::time::Duration = std::time::Duration::from_secs(60);

/// Did the agent's `/health` answer say it admits the harness's own leaf?
pub(crate) fn own_harness_admitted(health: &Value) -> bool {
    health.get(OWN_HARNESS_CAPABILITY).and_then(Value::as_bool) == Some(true)
}

/// Record whether the harness's own agent at `url` admits its leaf alone.
/// `false` removes the entry, so [`header_for`] sends the bearer again.
pub(crate) fn note_own_agent(url: &str, admitted: bool) {
    let Ok(mut map) = LEAF_ONLY.write() else { return };
    map.remove(OWN_AGENT_KEY);
    if let (true, Some(a)) = (admitted, authority(url)) {
        map.insert(OWN_AGENT_KEY.to_string(), Agent { authorities: vec![a], self_node: false });
    }
}

/// Ask the agent at `model_url` (its `/health`, no bearer, the caller's
/// leaf on `client`) and record the answer.
///
/// - an answer carrying the field → no bearer from now on;
/// - an answer without it (an older or rolled-back agent) → the bearer;
/// - no answer at all (agent restarting, transport error) → `None`, and the
///   previous decision stands. Flipping to the bearer there would put a
///   burst of static-token uses on the agent right after every restart, the
///   very count the retirement window reads. A harness that has never had
///   an answer has no entry, so it sends the bearer.
pub(crate) async fn probe_own_agent(client: &reqwest::Client, model_url: &str) -> Option<bool> {
    let answer = async {
        let mut u = reqwest::Url::parse(model_url.trim()).ok()?;
        u.set_path("/health");
        u.set_query(None);
        let resp = client.get(u).timeout(std::time::Duration::from_secs(10)).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        Some(own_harness_admitted(&resp.json::<Value>().await.ok()?))
    }
    .await;
    if let Some(admitted) = answer {
        note_own_agent(model_url, admitted);
    }
    answer
}

/// The harness's watch on its own agent: probe now, then every
/// [`OWN_AGENT_RECHECK`]. Logs only when the decision changes.
///
/// The first answer is waited for (up to ~30 s, before any turn is taken):
/// after a host reboot the harness can start before its agent listens, and
/// turns taken then would carry the bearer onto the freshly started agent.
pub(crate) async fn watch_own_agent(client: reqwest::Client, model_url: String) {
    let mut first = None;
    for _ in 0..15 {
        first = probe_own_agent(&client, &model_url).await;
        if first.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut last = first.unwrap_or(false);
    tracing::info!(endpoint = %model_url, leaf_only = last, answered = first.is_some(), "harness: own agent credential");
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(OWN_AGENT_RECHECK).await;
            if let Some(now) = probe_own_agent(&client, &model_url).await {
                if now != last {
                    tracing::info!(endpoint = %model_url, leaf_only = now, "harness: own agent credential changed");
                    last = now;
                }
            }
        }
    });
}

/// One lock for every test that reads or writes the process-global map
/// (here and in `node_link`): cargo runs tests in threads.
#[cfg(test)]
pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn clear_for_test() {
    if let Ok(mut m) = LEAF_ONLY.write() {
        m.clear();
    }
    SELF_BEAT_SEEN.store(false, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // One lock: the map is process-global and cargo runs tests in threads.
    use super::TEST_SERIAL as SERIAL;

    fn with_token<R>(f: impl FnOnce() -> R) -> R {
        // The bearer reads the environment; give it a value to send. No
        // other test reads or writes this variable.
        std::env::set_var("NOO_NODE_AGENT_TOKEN", "static-test-token");
        f()
    }

    #[test]
    fn a_flagged_node_gets_no_bearer_and_an_unflagged_one_keeps_it() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            note("host3", &json!({"ip_address": "10.0.0.2", CAPABILITY: true}));
            note("host6", &json!({"ip_address": "10.0.0.3"}));
            assert_eq!(header_for("https://10.0.0.2:8081/gpu"), None, "flagged node must get no bearer");
            assert_eq!(
                header_for("https://10.0.0.3:8081/gpu"),
                Some(("Authorization".into(), "Bearer static-test-token".into())),
                "an unflagged (older) agent keeps the bearer"
            );
            // An address the gateway has never heard of keeps the bearer.
            assert!(header_for("https://10.9.9.9:8081/gpu").is_some());
        });
    }

    /// With no static token an unflagged or unknown agent gets NO bearer (and
    /// above all no minted v1 token), flagged or not.
    #[test]
    fn without_a_static_token_no_agent_gets_any_bearer() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        std::env::remove_var("NOO_NODE_AGENT_TOKEN");
        std::env::set_var("NOO_CLUSTER_SECRET", "fleet-secret-for-test");
        note("host6", &json!({"ip_address": "10.0.0.3"}));
        assert_eq!(header_for("https://10.0.0.3:8081/gpu"), None, "unflagged, no token: no bearer");
        assert_eq!(header_for("https://10.9.9.9:8081/gpu"), None, "unknown agent: no bearer");
        assert_eq!(header_for_self("https://controller.tail:8081"), None);
        std::env::remove_var("NOO_CLUSTER_SECRET");
    }

    /// No controller->agent credential path may call the v1 minter.
    #[test]
    fn no_agent_credential_path_mints_a_v1_token() {
        let needle = ["mint_cluster", "_token("].concat();
        for (name, src) in [
            ("node_agent_auth.rs", include_str!("node_agent_auth.rs")),
            ("node_link.rs", include_str!("node_link.rs")),
            ("coordinator/backend.rs", include_str!("coordinator/backend.rs")),
        ] {
            assert!(src.len() > 1000, "{name} did not load");
            let prod = src.split("#[cfg(test)]").next().unwrap();
            assert!(!prod.contains(&needle), "{name} mints a v1 token for an agent");
        }
    }

    #[test]
    fn a_node_that_stops_reporting_gets_the_bearer_back() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            note("host3", &json!({"ip_address": "10.0.0.2", CAPABILITY: true}));
            assert!(header_for("https://10.0.0.2:8081/v1/chat/completions").is_none());
            // Downgraded agent: the next beat omits the field.
            note("host3", &json!({"ip_address": "10.0.0.2"}));
            assert!(header_for("https://10.0.0.2:8081/v1/chat/completions").is_some());
        });
    }

    #[test]
    fn an_address_belongs_to_the_newest_report() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            note("old-node", &json!({"ip_address": "10.0.0.7", CAPABILITY: true}));
            // A different, unflagged node now registers at that address.
            note("new-node", &json!({"ip_address": "10.0.0.7"}));
            assert!(header_for("https://10.0.0.7:8081/start").is_some());
        });
    }

    #[test]
    fn agent_url_and_ip_both_match_and_a_second_agent_port_does_not_claim_8081() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            note("a", &json!({"agent_url": "https://Node-1.tail:8081", "ip_address": "100.64.0.5", CAPABILITY: true}));
            assert!(header_for("https://node-1.tail:8081/gpu").is_none());
            assert!(header_for("https://100.64.0.5:8081/gpu").is_none());
            note("b", &json!({"agent_url": "https://10.0.0.9:8082", "ip_address": "10.0.0.9", CAPABILITY: true}));
            assert!(header_for("https://10.0.0.9:8082/gpu").is_none());
            assert!(header_for("https://10.0.0.9:8081/gpu").is_some(), "8081 on that host is another agent");
        });
    }

    #[test]
    fn the_self_agent_follows_the_self_node() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            assert!(header_for_self("https://controller.tail:8081").is_some());
            note("host8", &json!({"ip_address": "100.64.0.1", "self_node": true, CAPABILITY: true}));
            assert!(header_for_self("https://controller.tail:8081").is_none());
        });
    }

    // ── the self agent before its first beat ─────────────────────────

    /// A stand-in controller self agent. `/health` answers the node detail
    /// to a caller with no bearer only when `admits_leaf` (what a current
    /// agent does for the controller's leaf), the bare liveness shape
    /// otherwise; `/tailnet/whois` records the Authorization header each call
    /// carried (`None` = none), which is what the agent's `static_token`
    /// lane counts.
    async fn fake_self_agent(admits_leaf: bool) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>) {
        use axum::routing::get;
        let seen: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>> = Default::default();
        let seen_c = seen.clone();
        let app = axum::Router::new()
            .route(
                "/health",
                get(move |h: axum::http::HeaderMap| async move {
                    let mut body = json!({"status": "healthy", "version": "0.6.13"});
                    if admits_leaf && h.get("authorization").is_none() {
                        body["node_id"] = json!("pop-os");
                    }
                    axum::Json(body)
                }),
            )
            .route(
                "/tailnet/whois",
                get(move |h: axum::http::HeaderMap| async move {
                    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
                    seen_c.lock().unwrap().push(auth);
                    axum::Json(json!({"name": "homeserver"}))
                }),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, seen)
    }

    /// The kiosk mint's whois, as `routes::kiosk` sends it.
    async fn self_whois(base: &str) {
        crate::node_link::NodeLink::self_agent_at(base.to_string())
            .request(reqwest::Method::GET, "/tailnet/whois?ip=100.111.73.72")
            .into_http()
            .send()
            .await
            .unwrap();
    }

    /// The pop-os 2026-10-28 case: the gateway starts with an empty
    /// `mesh_nodes` KV (the bus was down past its TTL), and the first call to
    /// its own agent comes before that agent's first heartbeat. The startup
    /// step must already have learned that the agent admits the leaf, so the
    /// call carries no bearer and the agent's `static_token` lane stays 0.
    #[test]
    fn the_first_self_agent_call_after_a_restart_with_an_empty_kv_carries_no_bearer() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            rt().block_on(async {
                let (agent, seen) = fake_self_agent(true).await;
                // Startup: the KV seed found nothing (cleared above), then
                // the self-agent step.
                learn_self_agent(reqwest::Client::new(), agent.clone(), 1, std::time::Duration::ZERO).await;
                self_whois(&agent).await;
                assert_eq!(
                    seen.lock().unwrap().as_slice(),
                    &[None],
                    "a self agent that admits the controller's leaf must get no bearer before its first beat"
                );
            });
        });
    }

    /// An agent that answers only the bare liveness shape (it does not verify
    /// client certificates) keeps the bearer, and so does one that never
    /// answers.
    #[test]
    fn a_self_agent_that_does_not_admit_the_leaf_or_does_not_answer_keeps_the_bearer() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            rt().block_on(async {
                let (agent, seen) = fake_self_agent(false).await;
                learn_self_agent(reqwest::Client::new(), agent.clone(), 1, std::time::Duration::ZERO).await;
                self_whois(&agent).await;
                assert_eq!(seen.lock().unwrap().as_slice(), &[Some("Bearer static-test-token".to_string())]);

                clear_for_test();
                learn_self_agent(reqwest::Client::new(), "http://127.0.0.1:9".into(), 1, std::time::Duration::ZERO).await;
                assert!(header_for_self("http://127.0.0.1:9").is_some(), "no answer: the bearer stays");
            });
        });
    }

    /// The self node's first beat is the authority over what the probe
    /// learned: a beat that does not report the capability brings the
    /// bearer back, and a late probe answer does not override a beat.
    #[test]
    fn the_self_nodes_beat_replaces_the_probe() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            note_self_probe(true);
            assert!(header_for_self("https://controller.tail:8081").is_none());
            note("pop-os", &json!({"ip_address": "100.72.99.2", "self_node": true}));
            assert!(header_for_self("https://controller.tail:8081").is_some(), "the beat said no: bearer");
            note_self_probe(true);
            assert!(header_for_self("https://controller.tail:8081").is_some(), "a late probe never overrides a beat");
            note("pop-os", &json!({"ip_address": "100.72.99.2", "self_node": true, CAPABILITY: true}));
            note_self_probe(false);
            assert!(header_for_self("https://controller.tail:8081").is_none(), "nor the other way");
        });
    }

    #[test]
    fn the_leaf_capability_is_read_only_from_a_node_id_in_the_answer() {
        assert!(self_agent_admits_leaf(&json!({"status": "healthy", "node_id": "pop-os"})));
        for v in [json!({"status": "healthy", "version": "0.6.13"}), json!({"node_id": ""}), json!({"node_id": 1}), json!({})] {
            assert!(!self_agent_admits_leaf(&v), "{v}");
        }
    }

    // ── the harness and its own agent ────────────────────────────────

    /// A stand-in agent: `/health` answers `health`, and the chat route
    /// records the Authorization header each call carried (`None` = none).
    async fn fake_agent(health: Value) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>) {
        use axum::routing::{get, post};
        let seen: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>> = Default::default();
        let seen_c = seen.clone();
        let app = axum::Router::new()
            .route("/health", get(move || async move { axum::Json(health) }))
            .route(
                "/v1/chat/completions",
                post(move |h: axum::http::HeaderMap| async move {
                    let auth = h.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
                    seen_c.lock().unwrap().push(auth);
                    axum::Json(json!({"choices": []}))
                }),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, seen)
    }

    /// The harness's model call, as the coordinator builds it: the bearer
    /// is whatever `header_for` decides for the model URL.
    async fn harness_chat(client: &reqwest::Client, base: &str) {
        let url = format!("{base}/v1/chat/completions");
        let mut req = client.post(&url).json(&json!({"model": "m", "messages": []}));
        if let Some((k, v)) = header_for(&url) {
            req = req.header(k, v);
        }
        req.send().await.unwrap();
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn the_harness_drops_the_bearer_only_against_a_capable_agent() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            rt().block_on(async {
                let client = reqwest::Client::new();
                // Before any answer: the bearer.
                let (agent, seen) = fake_agent(json!({"status": "healthy", OWN_HARNESS_CAPABILITY: true})).await;
                harness_chat(&client, &agent).await;
                // A new agent says so on /health → no bearer reaches it.
                assert_eq!(probe_own_agent(&client, &format!("{agent}/ignored?x=1")).await, Some(true));
                harness_chat(&client, &agent).await;
                assert_eq!(
                    seen.lock().unwrap().as_slice(),
                    &[Some("Bearer static-test-token".to_string()), None],
                    "the bearer goes only before the capable agent has answered"
                );

                // An old agent: no field → the bearer is still sent.
                clear_for_test();
                let (old_agent, seen) = fake_agent(json!({"status": "healthy"})).await;
                assert_eq!(probe_own_agent(&client, &old_agent).await, Some(false));
                harness_chat(&client, &old_agent).await;
                assert_eq!(
                    seen.lock().unwrap().as_slice(),
                    &[Some("Bearer static-test-token".to_string())],
                    "an older agent keeps the bearer"
                );
            });
        });
    }

    #[test]
    fn a_rolled_back_agent_gets_the_bearer_back_and_a_restart_changes_nothing() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clear_for_test();
        with_token(|| {
            rt().block_on(async {
                let client = reqwest::Client::new();
                let (agent, _) = fake_agent(json!({OWN_HARNESS_CAPABILITY: true})).await;
                let chat = format!("{agent}/v1/chat/completions");
                assert_eq!(probe_own_agent(&client, &agent).await, Some(true));
                assert!(header_for(&chat).is_none());
                // No answer (the agent is restarting): the decision stands,
                // so no burst of bearer calls lands on the restarted agent.
                note_own_agent(&agent, true);
                let unreachable = "http://127.0.0.1:9";
                assert_eq!(probe_own_agent(&client, unreachable).await, None);
                assert!(header_for(&chat).is_none(), "a missed probe must not resend the bearer");
                // An answer WITHOUT the field (rolled back): the bearer again.
                let (old, _) = fake_agent(json!({"status": "healthy"})).await;
                assert_eq!(probe_own_agent(&client, &old).await, Some(false));
                assert!(header_for(&chat).is_some());
                assert!(header_for(&format!("{old}/v1/chat/completions")).is_some());
            });
        });
    }

    #[test]
    fn the_harness_capability_is_read_only_from_a_true_field() {
        assert!(own_harness_admitted(&json!({OWN_HARNESS_CAPABILITY: true})));
        for v in [json!({}), json!({OWN_HARNESS_CAPABILITY: false}), json!({OWN_HARNESS_CAPABILITY: "true"}), json!({CAPABILITY: true})] {
            assert!(!own_harness_admitted(&v), "{v}");
        }
    }

    /// Every node-agent call site asks per agent. The unconditional bearer
    /// is private to this module; a call site that mints its own (the old
    /// `node_agent_auth_header()`) would re-open the lane for flagged nodes.
    #[test]
    fn no_call_site_sends_the_bearer_unconditionally() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|e| e == "rs") && !p.ends_with("node_agent_auth.rs") {
                    let text = std::fs::read_to_string(&p).unwrap();
                    if text.contains("node_agent_auth_header()") {
                        offenders.push(p.display().to_string());
                    }
                }
            }
        }
        assert!(offenders.is_empty(), "unconditional node-agent bearer at: {offenders:?}");
    }
}
