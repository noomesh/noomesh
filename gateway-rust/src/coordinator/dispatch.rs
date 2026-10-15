// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Handing a turn to a node-hosted harness.
//!
//! The rule: a turn runs on the node that holds its model, when that node
//! has a running `harness` placement and the harness answers. Otherwise it
//! runs here, in the gateway, exactly as before. The operator arms
//! dispatch by placing a harness (`noo cluster place <node> harness
//! <model|auto>`); nothing here fires without that row.
//!
//! What crosses the bus:
//!
//! - `harness.run.<node>` — a request carrying the [`TurnRequest`]; the
//!   harness acks it (or nobody does, and the gateway runs the turn).
//! - `harness.turn.<conversation>` — the loop's events, relayed onto the
//!   caller's sink by [`crate::websocket::relay_turn`], ending with the
//!   harness's `harness_result` carrying the `CoordinatorResult`.
//!
//! The credential the harness gets is a user JWT for the turn
//! (`auth::mint_harness_jwt`), so everything it does on the rail is done
//! as the person. Unattended turns (no user — heartbeat, research) are not
//! dispatched: a harness acts as someone.

use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::auth::Role;
use crate::state::AppState;
use crate::websocket::{legacy_turn_subject, relay_turn, turn_subject, TurnSink, HARNESS_RESULT_EVENT};

use super::CoordinatorResult;

/// One turn, as handed to a harness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TurnRequest {
    pub conversation_id: String,
    pub prompt: String,
    pub channel: String,
    pub max_iterations: u32,
    #[serde(default)]
    pub model: Option<String>,
    pub user: String,
    #[serde(default)]
    pub enable_thinking: bool,
    #[serde(default)]
    pub role_prompt: Option<String>,
    /// Stream events on `harness.turn.<node>.<conversation>` (a dashboard
    /// socket is waiting) or run quietly and send only the result.
    #[serde(default)]
    pub stream: bool,
    /// The rail credential for this turn.
    pub token: String,
}

/// The subject a node's harness takes turns on.
pub fn harness_run_subject(node: &str) -> String {
    format!("harness.run.{}", node.replace(['.', '*', '>', ' '], "_"))
}

/// A request a node's principal answers, with its reply addressed to that
/// node's own inbox prefix (`_INBOX_gw.node.<token>.<nuid>`).
///
/// `allow_responses` alone does not survive a NATS config reload (the
/// server rebuilds each connection's reply map empty on every SIGHUP), so
/// a node that took a request before a reload could not answer it. The
/// node's grant carries a static publish on exactly this prefix, and no
/// other node's (noo-cli `nats_users.rs`, i70).
pub fn node_request(nats: &async_nats::Client, node: &str, payload: Vec<u8>) -> async_nats::Request {
    async_nats::Request::new()
        .payload(payload.into())
        .inbox(crate::nats_credentials::scoped_inbox(nats, &crate::nats_credentials::node_reply_prefix(node)))
}

/// `NOO_HARNESS_DISPATCH=0` keeps every turn on the controller even
/// where a harness is placed — the operator's brake.
pub fn dispatch_enabled() -> bool {
    !matches!(std::env::var("NOO_HARNESS_DISPATCH").as_deref(), Ok("0") | Ok("false") | Ok("off"))
}

/// How long the harness has to ack a handoff before the gateway runs
/// the turn itself.
const ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a dispatched turn may take end to end.
pub fn turn_deadline() -> Duration {
    Duration::from_secs(
        std::env::var("NOO_HARNESS_TURN_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(900),
    )
}

/// The harness policy a node gets when nothing was said about it: the
/// cluster-wide default (`NOO_HARNESS_DEFAULT_POLICY`, a `noo_settings`
/// override or the env), `auto` when UNSET. Stamped onto a node's config
/// row when provisioning creates it, and applied to a node that has no row
/// at all.
///
/// WHY AUTO AND NOT MANUAL. A harness is not a worker pool an operator
/// sizes — dispatch requires it to be on the node that already serves the
/// task's model (`harness_node_explained`). So a node serving a chat
/// backend WITHOUT a harness does not shed load; it makes every task for
/// that model fall back to running in the gateway process, silently.
///
/// That fallback is the fragile path: an in-process run is stamped with the
/// controller's own name, so a container recreate orphans it. Five tasks
/// were sitting stale that way when this was found.
///
/// The cost the other way is small. A harness is a thin agent-loop process
/// of kind `noo` (the node-agent's own default); the model is already
/// running on that node either way, and one nobody dispatches to idles.
/// Trading a silent fallback for an idle process is the right side of that.
///
/// An operator who wants the old behaviour sets the value explicitly, and
/// `off` still means off.
pub fn harness_default_policy() -> String {
    match crate::settings::get("NOO_HARNESS_DEFAULT_POLICY") {
        Some(v) if !v.trim().is_empty() => parse_policy(Some(v.as_str())),
        // UNSET is the new-install default, and it is not the same as a
        // value that failed to parse — see `parse_policy`.
        _ => "auto".into(),
    }
}

/// `auto|manual|off`; anything else is `manual`.
///
/// A typo stays conservative on purpose. "The operator meant something and
/// mistyped it" must not resolve to the wider behaviour, so only an UNSET
/// policy takes the `auto` default — not a misspelled one.
pub fn parse_policy(v: Option<&str>) -> String {
    match v.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("auto") => "auto".into(),
        Some("off") => "off".into(),
        _ => "manual".into(),
    }
}

/// Does `node` have a harness, as the operator declared it: an explicit
/// running `harness` placement, or `harness_policy = auto` on the node's
/// config with a running chat backend to follow. `off` wins over both.
/// The same rule the desired-config route uses to tell the node agent.
pub async fn harness_effective(state: &AppState, node: &str) -> bool {
    let policy: Option<String> = sqlx::query_scalar("SELECT harness_policy FROM noo_node_config WHERE node_id = $1")
        .bind(node)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let policy = policy.unwrap_or_else(harness_default_policy);
    if policy == "off" {
        return false;
    }
    let placed: Option<String> = sqlx::query_scalar(
        "SELECT desired_state FROM noo_backend_placements WHERE node_id = $1 AND backend = 'harness'",
    )
    .bind(node)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    if placed.as_deref() == Some("running") {
        return true;
    }
    if policy != "auto" || placed.is_some() {
        return false;
    }
    let chat: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM noo_backend_placements WHERE node_id = $1 AND backend <> 'harness'          AND desired_state = 'running' AND (role IS NULL OR role = '' OR role = 'chat')",
    )
    .bind(node)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    chat.unwrap_or(0) > 0
}

/// Which node, if any, should run a turn for `model`: the node holding
/// the resolved backend, provided it has a harness ([`harness_effective`]).
pub async fn harness_node_for(state: &AppState, model: Option<&str>) -> Option<String> {
    harness_node_explained(state, model).await.ok()
}

/// The same answer, with the reason when there is none.
///
/// Both questions come off ONE derivation on purpose. A separate "why"
/// that re-derived the decision could disagree with the decision — and a
/// diagnostic that contradicts what happened is worse than no diagnostic,
/// because it is believed.
///
/// The reasons exist because "it ran in process" is invisible from the
/// outside: the task record carries the controller's container id, which
/// reads as a node nobody recognises. An operator with a GPU node, a
/// placed harness and a running service saw exactly that and concluded
/// their credentials were wrong.
pub async fn harness_node_explained(state: &AppState, model: Option<&str>) -> Result<String, String> {
    let named = model.map(|m| format!("'{m}'")).unwrap_or_else(|| "the default model".into());
    // A cloud model's turn runs where the provider keys are: here.
    if let Some(m) = super::backend::model_hint(model).filter(|m| super::backend::is_cloud_model(m)) {
        return Err(format!("'{m}' is a cloud model, served by its provider from the controller — nothing to dispatch"));
    }
    let (backend, known_node) = super::backend::resolve_backend_and_node(state, model, &[]).await.map_err(|e| {
        format!("no backend resolved for {named}: {e}")
    })?;
    // Prefer the name the resolver already had. Only a discovery offer or a
    // static backend leaves us with just an address, and only then do we
    // resolve it — refusing an ambiguous one rather than guessing (two
    // `noo_node_config` rows shared the controller's IP on 2026-09-22 and
    // the guess landed on the stale one).
    let node = match known_node {
        Some(n) => n,
        None => {
            let Some(host) = super::backend::node_from_backend_url(&backend.url) else {
                return Err(format!(
                    "{named} is served by a backend that is not on a node ({}), so there is no harness to dispatch to",
                    backend.url
                ));
            };
            resolve_node_id(state, &host).await.map_err(|why| format!("{named} is served by {host}: {why}"))?
        }
    };
    // The controller's own node runs turns in process by design (its bundle
    // carries no harness). Say that, rather than "has no harness".
    if is_controller_node(&node) {
        return Err(format!(
            "{named} is served by the controller's own node ('{node}'), which runs turns in process — nothing to dispatch"
        ));
    }
    if !harness_effective(state, &node).await {
        return Err(format!(
            "node '{node}' serves {named} but has no harness: place one with `noo cluster place {node} harness`"
        ));
    }
    Ok(node)
}

/// Is `node` the controller's own node? Its bundle carries no harness and
/// its gateway IS the harness, in process.
///
/// It read `NOO_CONTROLLER_NODE_ID` / `NODE_ID` here while compose exports
/// `NOO_CONTROLLER_HOSTNAME`, so the controller never recognised itself:
/// every controller-placed turn tried the bus, waited 3 s, and fell back in
/// process. One reader now, `self_node`.
fn is_controller_node(node: &str) -> bool {
    crate::self_node::is_self_node(node)
}

/// Choose the node a backend ADDRESS belongs to, given what the registry
/// knows. Pure, so the ambiguity rule is testable without a database.
///
/// `live` is `(node_id, ip_address)` for every node in `cluster_nodes` —
/// the nodes that are actually enrolled and reporting. `configured` is
/// every `noo_node_config.node_id` sharing the address — rows that can
/// outlive the node they described. A live match wins outright. Among
/// configured-only rows, one is an answer and two is a refusal that names
/// both: guessing between a live node's row and a stale twin of it is how
/// the second dispatched turn was told the model lived on 'host8'.
pub(crate) fn choose_node_for_address(live: &[(String, String)], configured: &[String], host: &str) -> Result<String, String> {
    // Already a node id, and a live one.
    if live.iter().any(|(id, _)| id == host) {
        return Ok(host.to_string());
    }
    let live_hits: Vec<&String> = live.iter().filter(|(_, ip)| ip == host).map(|(id, _)| id).collect();
    match live_hits.as_slice() {
        [one] => return Ok((*one).clone()),
        [_, _, ..] => {
            return Err(format!(
                "address {host} is registered to more than one live node ({}) — cannot pick one",
                live_hits.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ))
        }
        [] => {}
    }
    match configured {
        [] => Err(format!("{host} matches no enrolled node")),
        [one] => Ok(one.clone()),
        many => Err(format!(
            "{host} matches {} node config rows and none is live ({}) — a stale row is shadowing a real node; remove it before dispatching here",
            many.len(),
            many.join(", ")
        )),
    }
}

/// Map an address or name onto a `node_id`, through the live registry
/// first. See `choose_node_for_address` for the rule.
pub async fn resolve_node_id(state: &AppState, host: &str) -> Result<String, String> {
    let live: Vec<(String, String)> = crate::repo::cluster::all_nodes(&state.db)
        .await
        .map(|rows| rows.into_iter().map(|(id, ip, _)| (id, ip)).collect())
        .unwrap_or_default();
    let configured: Vec<String> = sqlx::query_scalar(
        "SELECT node_id FROM noo_node_config WHERE node_id = $1 OR ip_address = $1 ORDER BY node_id",
    )
    .bind(host)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    choose_node_for_address(&live, &configured, host)
}

#[cfg(test)]
mod node_choice_tests {
    use super::choose_node_for_address;

    fn live() -> Vec<(String, String)> {
        vec![("node-1".into(), "100.64.0.11".into()), ("node-2".into(), "100.64.0.12".into())]
    }

    /// The bug: two config rows share the controller's IP, one of them a
    /// stale twin. The live registry knows which is real.
    #[test]
    fn a_live_node_wins_over_a_stale_config_twin_on_the_same_address() {
        let got = choose_node_for_address(&live(), &["node-2".into(), "node2".into()], "100.64.0.12");
        assert_eq!(got.as_deref(), Ok("node-2"));
    }

    /// With NO live node on the address, two config rows is a refusal that
    /// names both — never a pick.
    #[test]
    fn two_stale_rows_and_no_live_node_is_a_named_refusal() {
        let err = choose_node_for_address(&[], &["node-2".into(), "node2".into()], "100.64.0.12").unwrap_err();
        assert!(err.contains("node2") && err.contains("node-2"), "must name both rows: {err}");
        assert!(err.contains("stale"), "must say why: {err}");
    }

    #[test]
    fn a_single_config_row_is_an_answer_and_none_is_a_refusal() {
        assert_eq!(choose_node_for_address(&[], &["node-3".into()], "100.64.0.13").as_deref(), Ok("node-3"));
        assert!(choose_node_for_address(&[], &[], "10.0.0.9").is_err());
    }

    #[test]
    fn a_live_node_id_passes_straight_through() {
        assert_eq!(choose_node_for_address(&live(), &[], "node-1").as_deref(), Ok("node-1"));
    }
}

pub async fn role_of(state: &AppState, user: &str) -> Option<Role> {
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM noo_users WHERE username = $1 AND NOT disabled")
        .bind(user)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    role.and_then(|r| r.parse().ok())
}

/// Try to run this turn on a node. `Ok(None)` = not dispatched (no
/// harness for the model's node, no user, the brake, or nobody acked):
/// the caller runs the turn in process. `Ok(Some(result))` = the node
/// ran it. `Err` = the node took it and failed or timed out — the turn
/// is NOT re-run here, because its tools may already have executed.
#[allow(clippy::too_many_arguments)]
pub async fn try_dispatch<S: TurnSink>(
    state: &AppState,
    sink: &S,
    stream: bool,
    prompt: &str,
    conversation_id: &str,
    channel: &str,
    max_iterations: u32,
    model: Option<&str>,
    user_id: Option<&str>,
    role_prompt: Option<&str>,
    enable_thinking: bool,
) -> Result<Option<CoordinatorResult>> {
    if !dispatch_enabled() {
        return Ok(None);
    }
    let Some(user) = user_id.filter(|u| !u.is_empty()) else { return Ok(None) };
    // With no model named, the turn runs on the user's saved preference; a
    // cloud preference runs in process (the keys are here), not on the node
    // that serves the default model.
    if super::backend::model_hint(model).is_none() {
        if let Some(pref) = super::backend::fetch_user_model_preference(state, user).await {
            if super::backend::is_cloud_model(&pref) {
                return Ok(None);
            }
        }
    }
    let Some(node) = harness_node_for(state, model).await else { return Ok(None) };
    let Some(role) = role_of(state, user).await else {
        tracing::warn!(user, node = %node, "harness dispatch: unknown or disabled user; running in process");
        return Ok(None);
    };
    let deadline = turn_deadline();
    let Some(token) = crate::auth::mint_harness_jwt(user, role, &node, conversation_id, deadline.as_secs() + 60) else {
        tracing::warn!("harness dispatch: cannot mint a harness token (NOO_JWT_SECRET unset or insecure); running in process");
        return Ok(None);
    };

    // Subscribe BEFORE the handoff so no event can slip past.
    //
    // The scoped subject names the node we are handing this turn to, so
    // only a harness holding THAT node's credential can reach this
    // subscription. The legacy subject is listened on as
    // well, for one release: the harness is a rail asset, and a node whose
    // harness has not been upgraded yet still publishes the old shape.
    // While the legacy subscription exists, the pre-246 exposure exists on
    // it too — remove it, and `legacy_turn_subject`, once every node's
    // harness is at noo-cli 0.5.41 or later — the release this shipped in.
    let scoped = state.nats.subscribe(turn_subject(&node, conversation_id)).await?;
    let legacy = state.nats.subscribe(legacy_turn_subject(conversation_id)).await?;
    let events = futures::stream::select(scoped, legacy);
    let req = TurnRequest {
        conversation_id: conversation_id.to_string(),
        prompt: prompt.to_string(),
        channel: channel.to_string(),
        max_iterations,
        model: model.map(str::to_string),
        user: user.to_string(),
        enable_thinking,
        role_prompt: role_prompt.map(str::to_string),
        stream,
        token,
    };
    let ack = tokio::time::timeout(
        ACK_TIMEOUT,
        // The ack comes back on THIS node's reply prefix, which its principal
        // holds a static grant on: it survives a NATS reload (i70).
        state.nats.send_request(harness_run_subject(&node), node_request(&state.nats, &node, serde_json::to_vec(&req)?)),
    )
    .await;
    match ack {
        Ok(Ok(msg)) => {
            let body: Value = serde_json::from_slice(&msg.payload).unwrap_or(Value::Null);
            if body.get("ack").and_then(|a| a.as_bool()) != Some(true) {
                tracing::warn!(node = %node, reply = %body, "harness dispatch: refused; running in process");
                return Ok(None);
            }
        }
        Ok(Err(e)) => {
            tracing::info!(node = %node, error = %e, "harness dispatch: no responder; running in process");
            return Ok(None);
        }
        Err(_) => {
            tracing::info!(node = %node, "harness dispatch: no ack within {:?}; running in process", ACK_TIMEOUT);
            return Ok(None);
        }
    }
    tracing::info!(node = %node, conversation = conversation_id, user, stream, "harness_dispatched");

    // The turn's tools run on the rail, in another task, where this
    // task's approval task-locals are unset. Register where this turn came
    // from (the dashboard socket, the channel that asked) for as long as
    // it is in flight, so the rail can route approval cards back here.
    let origin = crate::routes::communication::TurnOrigin::capture();
    let _guard = crate::routes::communication::register_origin(conversation_id, origin.clone());

    let terminal = relay_turn(events, sink, deadline).await;
    // Whatever the turn's tools did NOT do, the channel pipeline reads
    // from THIS task's locals after we return: replay the remote record.
    origin.gated_record().replay();
    let terminal = terminal.ok_or_else(|| anyhow!("harness on {node} did not finish the turn within {deadline:?}"))?;
    let kind = terminal.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if kind != HARNESS_RESULT_EVENT {
        let msg = terminal.get("text").and_then(|t| t.as_str()).unwrap_or("harness error");
        return Err(anyhow!("harness on {node}: {msg}"));
    }
    let result: CoordinatorResult = serde_json::from_value(terminal.get("result").cloned().unwrap_or(json!(null)))
        .map_err(|e| anyhow!("harness on {node}: unreadable result: {e}"))?;
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_requests_round_trip_and_subjects_are_safe() {
        let req = TurnRequest {
            conversation_id: "c1".into(),
            prompt: "hi".into(),
            channel: "dashboard".into(),
            max_iterations: 5,
            model: None,
            user: "alice".into(),
            enable_thinking: true,
            role_prompt: None,
            stream: true,
            token: "t".into(),
        };
        let back: TurnRequest = serde_json::from_value(serde_json::to_value(&req).unwrap()).unwrap();
        assert_eq!(back, req);
        assert_eq!(harness_run_subject("host8"), "harness.run.host8");
        assert_eq!(harness_run_subject("a.b c"), "harness.run.a_b_c");
    }

    #[test]
    fn policy_parses_strictly_but_an_unset_default_is_auto() {
        // `parse_policy` is UNCHANGED and still strict: a value it does not
        // recognise is `manual`, so a typo never widens behaviour.
        assert_eq!(parse_policy(Some("auto")), "auto");
        assert_eq!(parse_policy(Some(" OFF ")), "off");
        assert_eq!(parse_policy(Some("manual")), "manual");
        assert_eq!(parse_policy(Some("yes")), "manual");
        assert_eq!(parse_policy(None), "manual");

        std::env::set_var("NOO_HARNESS_DEFAULT_POLICY", "auto");
        assert_eq!(harness_default_policy(), "auto");

        // CHANGED, deliberately. This used to assert `manual`, and that
        // contract is what left a node serving a chat backend with no
        // harness — which does not shed load, because dispatch requires the
        // harness to be ON the node serving the model. It makes every task
        // for that model fall back into the gateway process, where an
        // in-process run is stamped with the controller's own name and a
        // recreate orphans it. Five tasks were stale that way.
        //
        // Only an UNSET policy takes the wide default; the strict parsing
        // above is what keeps that safe.
        std::env::remove_var("NOO_HARNESS_DEFAULT_POLICY");
        assert_eq!(harness_default_policy(), "auto");
    }

    #[test]
    fn the_brake_is_an_explicit_off() {
        std::env::remove_var("NOO_HARNESS_DISPATCH");
        assert!(dispatch_enabled());
        std::env::set_var("NOO_HARNESS_DISPATCH", "0");
        assert!(!dispatch_enabled());
        std::env::set_var("NOO_HARNESS_DISPATCH", "1");
        assert!(dispatch_enabled());
        std::env::remove_var("NOO_HARNESS_DISPATCH");
    }
}

#[cfg(test)]
mod node_address_tests {
    use super::super::backend::node_from_backend_url;

    /// The bug that kept every turn on the controller: a node backend is
    /// addressed by IP, and the host was handed straight to a lookup keyed
    /// on `node_id`. It matched nothing, which reads as "that node has no
    /// harness" — for every node, every model, always.
    ///
    /// This pins the SHAPE that made translation necessary: what comes out
    /// of a node's backend URL is an address, not a name.
    #[test]
    fn a_node_backend_url_yields_an_address_not_a_node_id() {
        let host = node_from_backend_url("http://100.64.0.11:8000/v1").expect("a host");
        assert_eq!(host, "100.64.0.11");
        assert!(
            host.parse::<std::net::IpAddr>().is_ok(),
            "a node backend is addressed by IP, so this must be translated to a node_id before any \
             node_id-keyed lookup — see resolve_node_id"
        );
    }

    /// Loopback still means "here", which is what keeps a controller-local
    /// backend from being mistaken for a node.
    #[test]
    fn loopback_is_not_a_node_address() {
        let h = node_from_backend_url("http://127.0.0.1:11434").expect("a host");
        assert!(h == "controller" || !h.contains('.'), "loopback resolved to {h}");
    }
}

#[cfg(test)]
mod harness_policy_default_tests {
    use super::parse_policy;

    #[test]
    fn the_three_real_values_round_trip() {
        assert_eq!(parse_policy(Some("auto")), "auto");
        assert_eq!(parse_policy(Some("off")), "off");
        assert_eq!(parse_policy(Some("manual")), "manual");
    }

    #[test]
    fn case_and_padding_do_not_matter() {
        assert_eq!(parse_policy(Some("  AUTO ")), "auto");
        assert_eq!(parse_policy(Some("Off")), "off");
    }

    #[test]
    fn a_typo_stays_conservative() {
        // The asymmetry that makes defaulting to `auto` safe: only an UNSET
        // policy takes the wide default. "The operator meant something and
        // mistyped it" must not resolve to the wider behaviour.
        for typo in ["atuo", "on", "yes", "true", "AUTOMATIC", ""] {
            assert_eq!(parse_policy(Some(typo)), "manual", "{typo:?}");
        }
    }

    #[test]
    fn off_is_still_off() {
        // An operator who turned harnesses off must keep them off through a
        // default change.
        assert_eq!(parse_policy(Some("off")), "off");
    }
}
