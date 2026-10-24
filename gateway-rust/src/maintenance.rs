// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Node maintenance: "this node is known to be down, stop telling me".
//!
//! An operator marks a node `on` with a reason (and optionally an expiry);
//! while it is on, operator alerts whose target is that node are NOT
//! delivered to the channel. They are still published to the alert stream
//! (outcome `maintenance`) and logged, so nothing is lost and the daily
//! summary can say the node is down and in maintenance. `off` (or the expiry
//! passing) restores delivery.
//!
//! Persisted in a NATS KV bucket (no TTL, file-backed with the rest of
//! JetStream) so it survives a gateway restart; each entry carries its own
//! expiry, which is checked on read.
//!
//! The three routes take the `authz::Operator` extractor: a logged-in
//! Operator or above, and a call with no user (cluster HMAC) is refused.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::authz::Operator;
use crate::routes::{AppError, AppResult};
use crate::state::AppState;

pub const BUCKET: &str = "node_maintenance";

/// Longest a maintenance window may be set for. Forgotten mutes are the
/// failure this bounds; an operator who needs longer can set it again.
pub const MAX_UNTIL_SECS: i64 = 30 * 86_400;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Maintenance {
    pub node: String,
    pub reason: String,
    /// Unix seconds the window opened.
    pub since: i64,
    /// Unix seconds it closes; `None` = until turned off.
    pub until: Option<i64>,
    /// Who set it (the requester's subject).
    pub by: String,
}

impl Maintenance {
    pub fn active(&self, now: i64) -> bool {
        self.until.is_none_or(|u| u > now)
    }
}

/// An alert's `target` belongs to a node when it is the node id, or a
/// `node:something` scope (`host3:vllm`).
pub fn covers(node: &str, target: &str) -> bool {
    target == node
        || target
            .strip_prefix(node)
            .is_some_and(|rest| rest.starts_with(':'))
}

/// True when any active window covers the alert's target.
pub fn is_muted(entries: &[Maintenance], target: &str, now: i64) -> bool {
    entries.iter().any(|m| m.active(now) && covers(&m.node, target))
}

fn valid_node(node: &str) -> bool {
    !node.is_empty()
        && node.len() <= 128
        && node
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

async fn store(js: &async_nats::jetstream::Context) -> Result<async_nats::jetstream::kv::Store, String> {
    if let Ok(kv) = js.get_key_value(BUCKET).await {
        return Ok(kv);
    }
    js.create_key_value(async_nats::jetstream::kv::Config {
        bucket: BUCKET.into(),
        description: "nodes whose operator alerts are muted (maintenance)".into(),
        history: 1,
        ..Default::default()
    })
    .await
    .map_err(|e| format!("maintenance store unavailable: {e}"))
}

/// Every window that is still open. A store that cannot be read yields an
/// empty list: muting is a convenience, and failing open (deliver the alert)
/// is the safe direction.
pub async fn active(js: &async_nats::jetstream::Context, now: i64) -> Vec<Maintenance> {
    use tokio_stream::StreamExt;
    let Ok(kv) = js.get_key_value(BUCKET).await else {
        return Vec::new();
    };
    let Ok(keys) = kv.keys().await else {
        return Vec::new();
    };
    let keys: Vec<String> = keys.filter_map(|k| k.ok()).collect().await;
    let mut out = Vec::new();
    for k in keys {
        if let Ok(Some(raw)) = kv.get(&k).await {
            if let Ok(m) = serde_json::from_slice::<Maintenance>(&raw) {
                if m.active(now) {
                    out.push(m);
                }
            }
        }
    }
    out.sort_by(|a, b| a.node.cmp(&b.node));
    out
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// PUT /api/cluster/nodes/{node_id}/maintenance — body `{reason, until_secs?}`.
pub async fn maintenance_on(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(node_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult {
    let by = operator.sub().to_string();
    if !valid_node(&node_id) {
        return Err(AppError::BadRequest("invalid node id".into()));
    }
    let reason = body["reason"].as_str().unwrap_or("").trim().to_string();
    if reason.is_empty() {
        return Err(AppError::BadRequest("a reason is required".into()));
    }
    let now = now_secs();
    let until = match body.get("until_secs") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_i64() {
            Some(s) if (1..=MAX_UNTIL_SECS).contains(&s) => Some(now + s),
            _ => {
                return Err(AppError::BadRequest(format!(
                    "until_secs must be between 1 and {MAX_UNTIL_SECS}"
                )))
            }
        },
    };
    let m = Maintenance { node: node_id.clone(), reason, since: now, until, by };
    let kv = store(&state.js).await.map_err(AppError::Internal)?;
    let bytes = serde_json::to_vec(&m).map_err(|e| AppError::Internal(e.to_string()))?;
    kv.put(&node_id, bytes.into())
        .await
        .map_err(|e| AppError::Internal(format!("maintenance not saved: {e}")))?;
    tracing::info!(node = %node_id, until = ?until, "node_maintenance_on");
    Ok(Json(json!({"status": "ok", "maintenance": m})))
}

/// DELETE /api/cluster/nodes/{node_id}/maintenance.
pub async fn maintenance_off(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(node_id): Path<String>,
) -> AppResult {
    if !valid_node(&node_id) {
        return Err(AppError::BadRequest("invalid node id".into()));
    }
    let kv = store(&state.js).await.map_err(AppError::Internal)?;
    let was_on = kv.get(&node_id).await.ok().flatten().is_some();
    kv.purge(&node_id)
        .await
        .map_err(|e| AppError::Internal(format!("maintenance not cleared: {e}")))?;
    tracing::info!(node = %node_id, was_on, "node_maintenance_off");
    Ok(Json(json!({"status": "ok", "was_on": was_on})))
}

/// GET /api/cluster/maintenance — the windows currently open.
pub async fn maintenance_list(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
) -> AppResult {
    let entries = active(&state.js, now_secs()).await;
    Ok(Json(json!({"maintenance": entries})))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(node: &str, until: Option<i64>) -> Maintenance {
        Maintenance { node: node.into(), reason: "disk swap".into(), since: 0, until, by: "op".into() }
    }

    #[test]
    fn a_node_scope_matches_the_node_and_its_backends_only() {
        assert!(covers("alpha", "alpha"));
        assert!(covers("alpha", "alpha:vllm"));
        assert!(!covers("alpha", "alphabet"));
        assert!(!covers("alpha", "cluster"));
    }

    #[test]
    fn an_expired_window_no_longer_mutes() {
        let w = [m("alpha", Some(100))];
        assert!(is_muted(&w, "alpha", 99));
        assert!(!is_muted(&w, "alpha", 100));
        assert!(is_muted(&[m("alpha", None)], "alpha:vllm", 1_000_000));
        assert!(!is_muted(&[], "alpha", 0));
    }

    #[test]
    fn node_ids_are_vetted_before_they_become_store_keys() {
        assert!(valid_node("host8"));
        assert!(!valid_node(""));
        assert!(!valid_node("a b"));
        assert!(!valid_node("a/b"));
    }
}
