// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `retry now` for a refused model-set fetch (i607b B3).
//!
//! ```text
//! POST /api/cluster/nodes/{node_id}/model-set-retry
//!      {"set": "<id>@<rev>"}      one set
//!      {}                         every refused set on the node
//! ```
//!
//! A node's agent backs a refused set off for 30 minutes, in memory. This
//! route bumps the node's retry epoch (`repo::node_model_set_retry`, a
//! monotonic integer that survives a gateway restart) and records the set the
//! bump names. desired-config then carries a NEW TOP-LEVEL key
//! `model_set_retry: {"epoch": N, "sets": ["id@rev", ...]}` (omitted while the
//! epoch is 0); the agent clears the matching refused entries when N is past
//! the last epoch it saw. After the bump the handler nudges the node to
//! reconcile now (`nudge_reconcile`); a node that cannot be reached picks the
//! epoch up on its own reconcile tick (within ~5 minutes).
//!
//! The key is top-level on purpose. The agent decodes desired-config
//! leniently at the top level (an unknown key is ignored), but the
//! `node_workloads` fragment and its entries are decoded STRICTLY, so a new
//! field inside them would make an old agent refuse with `desired_invalid`.
//!
//! The route is operator-only and touches NO placement: it cannot add,
//! change or remove which sets or workloads a node runs, only end a backoff.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::repo::node_model_set_retry::{self as repo, Retry};
use crate::state::AppState;

/// The optional `set` of the body: `Ok(None)` for `{}` (every refused set),
/// `Ok(Some("id@rev"))` for a well-formed one. Anything else is an error
/// sentence: an unknown key, a `set` that is not a string, or a string that
/// is not `<id>@<rev>` in the shapes a placement's sets are held to.
pub fn parse_set(body: &Value) -> Result<Option<String>, String> {
    let obj = match body {
        Value::Null => return Ok(None),
        Value::Object(o) => o,
        _ => return Err("the body must be a JSON object: {\"set\": \"<id>@<rev>\"} or {}".to_string()),
    };
    if let Some(k) = obj.keys().find(|k| k.as_str() != "set") {
        return Err(format!("unknown field {k:?}: the body is {{\"set\": \"<id>@<rev>\"}} or {{}}"));
    }
    match obj.get("set") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => match s.split_once('@') {
            Some((id, rev)) if crate::node_workloads::valid_set_ref(id, rev) => Ok(Some(s.clone())),
            _ => Err(format!("set {s:?} is not <id>@<rev>")),
        },
        Some(_) => Err("set must be a string <id>@<rev>".to_string()),
    }
}

/// desired-config's `model_set_retry` for a node's retry state: `None` (the
/// key is left out) while the epoch is 0 or the node was never bumped.
pub fn fragment(retry: Option<&Retry>) -> Option<Value> {
    let r = retry.filter(|r| r.epoch > 0)?;
    Some(json!({"epoch": r.epoch, "sets": r.sets}))
}

/// Set the top-level `model_set_retry` key of a desired-config `body`, or
/// leave it out. Never inside `node_workloads`.
pub fn apply(body: &mut Value, retry: Option<&Retry>) {
    if let Some(f) = fragment(retry) {
        body["model_set_retry"] = f;
    }
}

/// The node's retry state for desired-config; `None` when the row cannot be
/// read (the key is then left out: the agent keeps the epoch it has).
pub async fn retry_for(state: &AppState, node_id: &str) -> Option<Retry> {
    match repo::get(&state.db, node_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%node_id, error = %e, "desired_model_set_retry_withheld");
            None
        }
    }
}

fn plain(status: StatusCode, code: &str, detail: impl Into<String>) -> Response {
    (status, Json(json!({"error": code, "detail": detail.into()}))).into_response()
}

/// A refused or failed retry: status, error code, sentence.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: String,
}

/// The retry itself, on the pool alone (no AppState, no node lookup): check
/// the body, bump the node's epoch, record the actor. It touches the retry
/// table ONLY, never a placement row. The handler gates on the operator and
/// the node before calling it.
pub async fn request_retry(db: &sqlx::PgPool, node_id: &str, body: &Value, actor: &str) -> Result<Retry, Failure> {
    let set = parse_set(body).map_err(|detail| Failure { status: StatusCode::BAD_REQUEST, code: "bad_request", detail })?;
    let r = repo::bump(db, node_id, set.as_deref(), actor).await.map_err(|e| Failure {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "internal",
        detail: format!("retrying model sets on {node_id}: {e}"),
    })?;
    let _ = crate::repo::node_workload_placements::remove(db, node_id, "rhaddon", "worker").await;
    tracing::info!(%node_id, epoch = r.epoch, set = ?set, %actor, "model_set_retry_bumped");
    Ok(r)
}

/// POST /api/cluster/nodes/{node_id}/model-set-retry
///
/// Operator only. Body `{"set": "<id>@<rev>"}` or `{}`. Bumps the node's
/// retry epoch so its agent clears the refused backoff of that set (or of
/// every refused set) on its next reconcile. Changes no placement.
pub async fn retry_model_set(
    State(state): State<Arc<AppState>>,
    operator: crate::authz::Operator,
    Path(node_id): Path<String>,
    body: Option<Json<Value>>,
) -> Response {
    let b = body.map(|Json(b)| b).unwrap_or(Value::Null);
    match super::node_workload_placements::node_record(&state, &node_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return plain(StatusCode::NOT_FOUND, "not_found", format!("no node {node_id:?} reports to this controller")),
        Err(e) => return plain(StatusCode::SERVICE_UNAVAILABLE, "unavailable", e),
    }
    match request_retry(&state.db, &node_id, &b, operator.sub()).await {
        Ok(r) => {
            // Fire-and-forget: ask the node to reconcile now (the signed
            // `reconcile` control op, HTTPS fallback). Not reachable or older
            // than the op: a log line, and the node's own tick picks it up.
            super::cluster::nudge_reconcile(state.clone(), node_id.clone());
            (StatusCode::OK, Json(json!({"node_id": node_id, "epoch": r.epoch, "sets": r.sets}))).into_response()
        }
        Err(f) => plain(f.status, f.code, f.detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retry(epoch: u64, sets: &[&str]) -> Retry {
        Retry { epoch, sets: sets.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn the_body_names_one_set_or_none() {
        assert_eq!(parse_set(&json!({})), Ok(None));
        assert_eq!(parse_set(&Value::Null), Ok(None));
        assert_eq!(parse_set(&json!({"set": null})), Ok(None));
        assert_eq!(parse_set(&json!({"set": "rh-main-v1@fdaf4090a61c"})), Ok(Some("rh-main-v1@fdaf4090a61c".to_string())));
    }

    #[test]
    fn a_set_that_is_not_id_at_rev_is_refused() {
        for bad in ["", "rh-main", "@r1", "rh-main@", "rh-main@r1@r2", "RH@r1", "../x@r1", "rh-main@../x", "a b@r1", "rh-main@r 1"] {
            assert!(parse_set(&json!({"set": bad})).is_err(), "{bad:?} must be refused");
        }
        assert!(parse_set(&json!({"set": 7})).is_err(), "not a string");
        assert!(parse_set(&json!({"set": ["a@b"]})).is_err(), "not a list");
        assert!(parse_set(&json!({"sets": "a@b"})).is_err(), "an unknown key is not a silent retry-all");
        assert!(parse_set(&json!("a@b")).is_err(), "not an object");
    }

    #[test]
    fn desired_config_carries_the_key_at_the_top_level_after_a_bump_and_omits_it_at_epoch_0() {
        let mut body = json!({"node_workloads": []});
        apply(&mut body, None);
        assert!(body.get("model_set_retry").is_none(), "never bumped: no key");
        apply(&mut body, Some(&retry(0, &[])));
        assert!(body.get("model_set_retry").is_none(), "epoch 0: no key");
        apply(&mut body, Some(&retry(3, &["rh-main@r1"])));
        assert_eq!(body["model_set_retry"], json!({"epoch": 3, "sets": ["rh-main@r1"]}));
        assert_eq!(body["node_workloads"], json!([]), "the strict fragment is untouched");
        let mut all = json!({});
        apply(&mut all, Some(&retry(1, &[])));
        assert_eq!(all["model_set_retry"], json!({"epoch": 1, "sets": []}), "empty sets = every refused set");
    }

    /// Structural: desired-config sets the key through `apply`, at the top
    /// level of the body, and never builds it into `node_workloads`.
    #[test]
    fn desired_config_wires_the_key_at_the_top_level() {
        let own = crate::test_src::own_code(include_str!("cluster.rs"));
        let body = crate::test_src::fn_body(&own, "async fn desired_config_get(");
        assert!(body.contains("super::model_set_retry::apply(&mut body, super::model_set_retry::retry_for(&state, &node_id).await.as_ref());"), "{body}");
        assert!(!body.contains("\"node_workloads\": {\"model_set_retry\""), "never inside the strict fragment");
    }

    /// Structural: the route is operator-gated by an extractor (so it runs
    /// before the body, and a non-operator never reaches the DB), it writes
    /// only the retry table, and it touches no placement.
    #[test]
    fn the_route_is_operator_only_and_touches_no_placement() {
        let own = crate::test_src::own_code(include_str!("model_set_retry.rs"));
        let h = crate::test_src::fn_body(&own, "pub async fn retry_model_set(");
        assert!(h.contains("operator: crate::authz::Operator"), "operator gate (an extractor)");
        let sig = h.split("-> Response").next().unwrap();
        assert!(sig.find("operator: crate::authz::Operator").unwrap() < sig.find("body: Option<Json<Value>>").unwrap(), "the gate sits before the body extractor");
        assert!(h.contains("request_retry(&state.db, &node_id, &b, operator.sub())"), "the handler hands the pool, not AppState, to the retry");
        assert!(h.find("request_retry(").unwrap() < h.find("nudge_reconcile(state.clone(), node_id.clone())").unwrap(), "the nudge follows a successful bump, in the handler");
        let r = crate::test_src::fn_body(&own, "pub async fn request_retry(");
        assert!(!r.contains("nudge"), "request_retry stays pool-only: no nudge inside it");
        assert!(r.contains("repo::bump("), "{r}");
        assert!(!r.contains("AppState") && !r.contains("state."), "request_retry takes the pool only");
        for placement in ["node_workload_placements::place", "node_workload_placements::remove", "node_workload_placements::set_", "repo::place(", "repo::remove("] {
            assert!(!own.contains(placement), "the retry route must not touch placements: {placement}");
        }
        // The route is registered, once, on the cluster router.
        let cluster = include_str!("cluster.rs");
        assert!(cluster.contains("\"/api/cluster/nodes/{node_id}/model-set-retry\", post(super::model_set_retry::retry_model_set)"));
    }

    /// SECURITY, against Postgres: a retry never changes a placement. Place a
    /// node workload, snapshot every column of the node's placement rows, retry
    /// twice (bare, then named), and the rows are identical while the epoch
    /// moved by 2.
    #[tokio::test]
    async fn a_retry_leaves_the_nodes_placement_rows_byte_for_byte_unchanged() {
        let Some(db) = crate::repo::node_model_set_retry::test_pool().await else {
            eprintln!("NOO_TEST_DSN unset — retry-leaves-placements not exercised");
            return;
        };
        use crate::repo::node_model_set_retry::{forget_for_test, placement_snapshot};
        let node = format!("msr-plc-{}", std::process::id());
        let _ = crate::repo::node_workload_placements::remove(&db, &node, "rhaddon", "worker").await;
        forget_for_test(&db, &node).await;

        let row = crate::repo::node_workload_placements::Placement {
            addon: "rhaddon".into(),
            workload: "worker".into(),
            node_id: node.clone(),
            profile: Some("int8".into()),
            sets: json!({"main": [{"id": "rh-s2s-7b", "revision": "r1"}]}),
            env: json!({"RHADDON_SLOTS": "1"}),
            on_controller: false,
            desired_state: "provisioned".into(),
            reservation: None,
        };
        crate::repo::node_workload_placements::place(&db, &row).await.expect("place");
        let before = placement_snapshot(&db, &node).await;
        assert_eq!(before.len(), 1, "the fixture row is there");
        let epoch0 = repo::get(&db, &node).await.expect("get").map_or(0, |r| r.epoch);

        let a = request_retry(&db, &node, &json!({}), "alice").await.expect("bare retry");
        let b = request_retry(&db, &node, &json!({"set": "rh-s2s-7b@r1"}), "alice").await.expect("named retry");
        assert_eq!((a.epoch, b.epoch), (epoch0 + 1, epoch0 + 2), "the epoch moved by 2");

        assert_eq!(placement_snapshot(&db, &node).await, before, "a retry changed a placement row");
        assert_eq!(crate::repo::node_workload_placements::for_node(&db, &node).await.expect("for_node"), vec![row]);

        let _ = crate::repo::node_workload_placements::remove(&db, &node, "rhaddon", "worker").await;
        forget_for_test(&db, &node).await;
    }
}
