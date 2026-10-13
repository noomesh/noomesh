// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Snapshot endpoints — the `snapshots` capability group of the memory
//! provider (: all handlers go through
//! `state.memory()`; the NatsTrellion impl keeps the exact SQL and NATS
//! subjects these routes issued directly before, so behavior is
//! unchanged).
//!
//! Until 2026-04-27 the gateway routed all `/api/snapshots/*` requests
//! through the catchall to Python NATS handlers. List / get / diff are
//! pure SELECTs against `trellion_snapshots` + `trellion_concepts` —
//! no ML, no embeddings, no LLM — so each request was paying a NATS
//! round-trip + Python overhead for what's a single SQL statement.
//! Those stay SQL inside the provider; consolidate / curriculum remain
//! LLM/embedding work on trellion's NATS wire.
//!
//!   (list / get / diff serve a RESTRICTED caller from the worker's scoped
//!   view; the SQL below is the unrestricted path.)
//!   GET  /api/snapshots                       → list snapshots
//!   GET  /api/snapshots/{snapshot_id}         → fetch one snapshot
//!   POST /api/snapshots/diff                  → diff two snapshots
//!   POST /api/snapshots/consolidate           → temporal-graph extraction
//!   GET  /api/snapshots/{id}/curriculum       → CKG materialization
//!
//! the design port. The Python handlers stay subscribed in
//! worker_pool.py as a fallback for Python-primary deployments.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::delegation;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // The diff route MUST be registered before the {snapshot_id} catchall
        // pattern below or "diff" gets matched as the literal id.
        .route("/api/snapshots/diff", post(snapshots_diff))
        // Consolidation stays Python: it drives trellion.snapshots
        // (SnapshotOrchestrator / SliceSpec), which is memory-plane work and
        // stays Python by design. It needs an EXPLICIT route
        // because the /api/{*path} catchall it used to arrive through has
        // been removed — delegation is now declared, never implicit.
        .route("/api/snapshots/consolidate", post(snapshots_consolidate))
        // Curriculum logic stays Python (worker.api.snapshots.curriculum),
        // but it needs an explicit route: the generic catchall would derive
        // subject worker.api.snapshots.<id>.curriculum (never registered)
        // AND drop the ?q= query param, so every curriculum query failed.
        .route("/api/snapshots/{snapshot_id}/curriculum", get(snapshots_curriculum))
        .route("/api/snapshots", get(snapshots_list))
        .route("/api/snapshots/{snapshot_id}", get(snapshots_get))
}

/// POST /api/snapshots/consolidate — an ASYNCHRONOUS-OPERATION route
/// (`ops.rs`, type `snapshots.consolidate`).
///
/// The worker already answers at once with a snapshot row in `building`
/// status; the op WRAPS that flow rather than replacing it (it calls
/// [`consolidate_core`] exactly once, then follows the snapshot to `complete`
/// or `failed`), so a consolidation is never started twice. The route answers
/// 200 if the snapshot finished within `default_wait` (or `?wait=`), else 202
/// with the op handle. `GET /api/snapshots/{id}` still reports the snapshot.
async fn snapshots_consolidate(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(w): Query<super::ops::WaitQuery>,
    Json(body): Json<Value>,
) -> delegation::StatusJson {
    super::ops::route_start(&state, &ctx, "snapshots.consolidate", body, w.wait).await
}

/// What `POST /api/snapshots/consolidate` does: the same requester
/// attachment and status mapping `delegate_post` gave this route, with the
/// facade issuing the NATS request.
pub(super) async fn consolidate_core(
    state: &Arc<AppState>,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
    mut body: Value,
) -> delegation::StatusJson {
    delegation::attach_requester(&mut body, ctx);
    match state.memory().snapshots_consolidate(&body).await {
        Ok(response) => delegation::worker_ok(response),
        Err(e) => delegation::worker_unavailable(e, None),
    }
}

#[derive(Deserialize, Default)]
struct CurriculumParams {
    q: Option<String>,
    max_hops: Option<i64>,
}

/// GET /api/snapshots/{snapshot_id}/curriculum — delegate to the flat
/// Python subject with the id and query folded into the body, which is
/// the shape workers/snapshots.py::_snapshots_curriculum expects.
async fn snapshots_curriculum(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(snapshot_id): Path<String>,
    Query(params): Query<CurriculumParams>,
) -> (axum::http::StatusCode, Json<Value>) {
    // The curriculum is a concept graph materialised from a
    // snapshot; the worker answers a restricted caller from the concepts and
    // edges they may read (`workers/snapshot_audience.py`) given `roles`.
    // The worker is not pinned to this gateway, so a restricted caller is only
    // given a reply that says it was filtered (`scope::confirm_audience`);
    // anything else is dropped (503). Unrestricted callers are unaffected.
    let audience = match crate::memory::scope::resolve(&state, &ctx).await {
        Ok(a) => a,
        Err(e) => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": e.to_string()})),
            );
        }
    };
    let body = curriculum_request_body(&snapshot_id, &params, &audience);
    match state.memory().snapshots_curriculum(&body).await {
        Ok(resp) => curriculum_reply(&audience, resp),
        Err(e) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("curriculum worker unavailable: {e}")})),
        ),
    }
}

/// The body for `worker.api.snapshots.curriculum`: id and query as before,
/// plus the caller's audience as `roles` when it is restricted (absent =
/// unrestricted). Built from the path and query only, so nothing the client
/// sends can name its own audience.
fn curriculum_request_body(
    snapshot_id: &str,
    params: &CurriculumParams,
    audience: &crate::memory::scope::Audience,
) -> Value {
    let mut body = json!({
        "snapshot_id": snapshot_id,
        "q": params.q,
        "max_hops": params.max_hops,
    });
    if let crate::memory::scope::Audience::Roles(roles) = audience {
        body["roles"] = json!(roles);
    }
    body
}

/// The worker's answer as HTTP. A restricted caller gets it only if the
/// worker confirmed it was built from what they may read; otherwise 503.
fn curriculum_reply(
    audience: &crate::memory::scope::Audience,
    resp: Value,
) -> (axum::http::StatusCode, Json<Value>) {
    match crate::memory::scope::confirm_audience(audience, resp) {
        Some(resp) => {
            let payload = resp.get("data").cloned().unwrap_or(resp);
            (axum::http::StatusCode::OK, Json(payload))
        }
        None => {
            tracing::warn!("curriculum reply carried no audience confirmation; refused for a restricted caller");
            crate::memory::scope::unconfirmed_response("snapshot curriculum")
        }
    }
}

#[derive(Deserialize, Default)]
struct ListParams {
    kind: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
}

type Reply = (axum::http::StatusCode, Json<Value>);

fn ok(v: Value) -> Reply {
    (axum::http::StatusCode::OK, Json(v))
}

// ── restricted callers ───────────────────────────────────
//
// List, get and diff read `trellion_snapshots` / `trellion_concepts` in the
// gateway's own SQL, which carries every person's concept names, the stored
// label and the whole-graph stats. The ownership rule lives in the worker
// (`snapshot_audience._scope_sql`, one place), so a restricted caller's
// request is served from `worker.api.snapshots.scoped`, never from that SQL,
// and only on the worker's confirmation (`scope::confirm_audience`). An
// unrestricted caller keeps the original statements and handlers below.

/// The worker's confirmed payload for a restricted caller, or the response to
/// send instead (503 when it did not say it filtered; the worker's own error
/// otherwise).
fn scoped_payload(
    audience: &crate::memory::scope::Audience,
    resp: anyhow::Result<Value>,
) -> Result<Value, Reply> {
    let resp = resp.map_err(|e| {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("snapshot worker unavailable: {e}")})),
        )
    })?;
    match crate::memory::scope::confirm_audience(audience, resp) {
        Some(resp) => Ok(resp.get("data").cloned().unwrap_or(resp)),
        None => {
            tracing::warn!("snapshot reply carried no audience confirmation; refused for a restricted caller");
            Err(crate::memory::scope::unconfirmed_response("snapshots"))
        }
    }
}

/// A snapshot as a restricted caller sees it: lifecycle fields as stored, the
/// label and slice spec (free text, built from the whole graph) replaced, the
/// whole-graph stats replaced by what THEY may read.
fn neutral_summary(row: &Value, counts: Option<&Value>) -> Value {
    let kind = row.get("kind").and_then(Value::as_str).unwrap_or("snapshot");
    let day = row
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|d| d.get(..10))
        .unwrap_or("undated");
    let n = |k: &str| counts.and_then(|c| c.get(k)).and_then(Value::as_i64).unwrap_or(0);
    json!({
        "id": row["id"],
        "generation": row["generation"],
        "kind": kind,
        "spec": {},
        "status": row["status"],
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
        "stats": {"concepts": n("concepts"), "dag_edges": n("dag_edges")},
        "label": format!("{kind} snapshot {day}"),
    })
}

/// Readable concept / DAG-edge counts for these snapshots, from the worker.
async fn scoped_counts(
    state: &AppState,
    audience: &crate::memory::scope::Audience,
    ids: Vec<String>,
) -> Result<Value, Reply> {
    let mut body = json!({"op": "counts", "snapshot_ids": ids});
    if let Some(roles) = audience.roles() {
        body["roles"] = json!(roles);
    }
    let payload = scoped_payload(audience, state.memory().snapshots_scoped(&body).await)?;
    if let Some(e) = payload.get("error").and_then(Value::as_str) {
        return Err(ok(json!({"error": format!("snapshot lookup failed: {e}")})));
    }
    Ok(payload.get("counts").cloned().unwrap_or_else(|| json!({})))
}

/// `(name, type)` of the concepts of one snapshot the caller may read.
async fn scoped_concepts(
    state: &AppState,
    audience: &crate::memory::scope::Audience,
    snapshot_id: &str,
    side: &str,
) -> Result<Vec<(String, String)>, Reply> {
    let mut body = json!({"op": "concepts", "snapshot_id": snapshot_id});
    if let Some(roles) = audience.roles() {
        body["roles"] = json!(roles);
    }
    let payload = scoped_payload(audience, state.memory().snapshots_scoped(&body).await)?;
    if let Some(e) = payload.get("error").and_then(Value::as_str) {
        return Err(ok(json!({"error": format!("{side} load failed: {e}")})));
    }
    let rows = payload.get("concepts").and_then(Value::as_array).cloned().unwrap_or_default();
    Ok(rows
        .iter()
        .filter_map(|r| Some((r.get(0)?.as_str()?.to_string(), r.get(1)?.as_str()?.to_string())))
        .collect())
}

async fn resolve_audience(
    state: &AppState,
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> Result<crate::memory::scope::Audience, Reply> {
    crate::memory::scope::resolve(state, ctx).await.map_err(|e| {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": e.to_string()})),
        )
    })
}

async fn snapshots_list(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Query(params): Query<ListParams>,
) -> Reply {
    let audience = match resolve_audience(&state, &ctx).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let snapshots = match state
        .memory()
        .snapshots_list(params.kind.as_deref(), params.status.as_deref(), limit)
        .await
    {
        Ok(rs) => rs,
        Err(e) => {
            tracing::warn!(error = %e, "snapshots_list_failed");
            return ok(json!({"error": format!("snapshot list failed: {e}")}));
        }
    };
    if matches!(audience, crate::memory::scope::Audience::Roles(_)) {
        let ids: Vec<String> =
            snapshots.iter().filter_map(|s| s["id"].as_str().map(String::from)).collect();
        let counts = match scoped_counts(&state, &audience, ids).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        let shown: Vec<Value> = snapshots
            .iter()
            .map(|s| neutral_summary(s, s["id"].as_str().and_then(|i| counts.get(i))))
            .collect();
        return ok(json!({"snapshots": shown}));
    }
    ok(json!({"snapshots": snapshots}))
}

async fn snapshots_get(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Path(snapshot_id): Path<String>,
) -> Reply {
    let audience = match resolve_audience(&state, &ctx).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match state.memory().snapshots_get(&snapshot_id).await {
        Ok(Some(summary)) => {
            if matches!(audience, crate::memory::scope::Audience::Roles(_)) {
                let counts = match scoped_counts(&state, &audience, vec![snapshot_id.clone()]).await {
                    Ok(c) => c,
                    Err(r) => return r,
                };
                return ok(neutral_summary(&summary, counts.get(&snapshot_id)));
            }
            ok(summary)
        }
        Ok(None) => ok(json!({"error": "snapshot not found", "id": snapshot_id})),
        Err(e) => {
            tracing::warn!(error = %e, snapshot_id, "snapshots_get_failed");
            ok(json!({"error": format!("snapshot lookup failed: {e}")}))
        }
    }
}

#[derive(Deserialize)]
struct DiffBody {
    snapshot_a: String,
    snapshot_b: String,
}

/// The diff document over two concept sets (shared by both paths).
fn diff_response(
    snapshot_a: &str,
    snapshot_b: &str,
    a_rows: Vec<(String, String)>,
    b_rows: Vec<(String, String)>,
) -> Value {
    use std::collections::BTreeSet;
    let a: BTreeSet<(String, String)> = a_rows.into_iter().collect();
    let b: BTreeSet<(String, String)> = b_rows.into_iter().collect();
    let added: Vec<Value> = b.difference(&a).map(|(n, t)| json!([n, t])).collect();
    let removed: Vec<Value> = a.difference(&b).map(|(n, t)| json!([n, t])).collect();
    let in_both: usize = a.intersection(&b).count();

    json!({
        "snapshot_a": snapshot_a,
        "snapshot_b": snapshot_b,
        "concepts_added": added,
        "concepts_removed": removed,
        "concepts_in_both": in_both,
    })
}

/// POST /api/snapshots/diff — set-diff the concepts of two memory snapshots.
///
/// Body: `snapshot_a`, `snapshot_b` (snapshot ids). Loads each snapshot's
/// (concept, type) pairs and returns `concepts_added` (in B not A),
/// `concepts_removed` (in A not B) and a `concepts_in_both` count — i.e.
/// "what did the knowledge base learn or forget between these two points".
/// A load failure reports which side failed rather than a bare 500.
///
/// A restricted caller diffs the two READABLE slices, so a
/// concept they cannot read is neither added, removed nor counted.
async fn snapshots_diff(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<crate::auth::RequesterCtx>>,
    Json(body): Json<DiffBody>,
) -> Reply {
    let audience = match resolve_audience(&state, &ctx).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if matches!(audience, crate::memory::scope::Audience::Roles(_)) {
        let a_rows = match scoped_concepts(&state, &audience, &body.snapshot_a, "snapshot_a").await {
            Ok(r) => r,
            Err(r) => return r,
        };
        let b_rows = match scoped_concepts(&state, &audience, &body.snapshot_b, "snapshot_b").await {
            Ok(r) => r,
            Err(r) => return r,
        };
        return ok(diff_response(&body.snapshot_a, &body.snapshot_b, a_rows, b_rows));
    }
    let a_rows = match state.memory().snapshot_concepts(&body.snapshot_a).await {
        Ok(rs) => rs,
        Err(e) => return ok(json!({"error": format!("snapshot_a load failed: {e}")})),
    };
    let b_rows = match state.memory().snapshot_concepts(&body.snapshot_b).await {
        Ok(rs) => rs,
        Err(e) => return ok(json!({"error": format!("snapshot_b load failed: {e}")})),
    };
    ok(diff_response(&body.snapshot_a, &body.snapshot_b, a_rows, b_rows))
}

/// the curriculum serves a restricted caller a FILTERED answer
/// (it used to 403), and only on the worker's confirmation.
#[cfg(test)]
mod curriculum_audience_tests {
    use super::*;
    use crate::memory::scope::Audience;

    fn restricted() -> Audience {
        Audience::Roles(vec!["company".into(), "user:a".into()])
    }

    #[test]
    fn a_restricted_caller_gets_the_confirmed_answer_without_the_marker() {
        let (status, body) = curriculum_reply(
            &restricted(),
            json!({"data": {"content": "none", "audience_filtered": true}}),
        );
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body.0, json!({"content": "none"}));
    }

    #[test]
    fn an_unconfirmed_curriculum_is_never_forwarded_to_a_restricted_caller() {
        for stale in [
            json!({"data": {"content": "tpc-bonly; tpc-adm"}}),
            json!({"content": "tpc-bonly"}),
            json!({"data": {"content": "x", "audience_filtered": false}}),
            json!({"data": {"error": "a restricted caller reached this worker without an audience"}}),
        ] {
            let (status, body) = curriculum_reply(&restricted(), stale);
            assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
            assert!(!body.0.to_string().contains("tpc-"));
        }
    }

    #[test]
    fn an_unrestricted_caller_is_unaffected_by_the_confirmation() {
        let (status, body) = curriculum_reply(&Audience::Unrestricted, json!({"data": {"content": "tpc-bonly"}}));
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body.0["content"], "tpc-bonly");
    }

    #[test]
    fn the_audience_travels_as_roles_and_only_when_restricted() {
        let p = CurriculumParams { q: Some("q".into()), max_hops: Some(3) };
        let b = curriculum_request_body("s1", &p, &restricted());
        assert_eq!(b["roles"], json!(["company", "user:a"]));
        assert_eq!((b["snapshot_id"].as_str(), b["q"].as_str(), b["max_hops"].as_i64()), (Some("s1"), Some("q"), Some(3)));
        assert!(curriculum_request_body("s1", &p, &Audience::Unrestricted).get("roles").is_none());
    }

    #[test]
    fn the_blanket_403_is_gone() {
        let src = include_str!("snapshots.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        let f = &code[code.find("async fn snapshots_curriculum(").unwrap()..];
        let f = &f[..f.find("\n}\n").unwrap()];
        assert!(!f.contains("FORBIDDEN"));
        assert!(f.contains("resolve("));
    }
}

/// list / get / diff for a restricted caller.
#[cfg(test)]
mod snapshot_audience_tests {
    use super::*;
    use crate::memory::scope::Audience;

    fn restricted() -> Audience {
        Audience::Roles(vec!["company".into(), "user:a".into()])
    }

    fn row() -> Value {
        json!({
            "id": "s1", "generation": 3, "kind": "topic",
            "spec": {"topic": "B-private-topic"}, "status": "complete",
            "created_at": "2026-10-01T10:00:00+00:00", "completed_at": "2026-10-01T10:05:00+00:00",
            "stats": {"concepts": 99, "dag_edges": 98, "live_entities": 97},
            "label": "Everything about B-private-topic",
        })
    }

    #[test]
    fn a_restricted_summary_carries_no_stored_text_and_only_readable_counts() {
        let v = neutral_summary(&row(), Some(&json!({"concepts": 2, "dag_edges": 1})));
        let text = v.to_string();
        assert!(!text.contains("B-private-topic") && !text.contains("99") && !text.contains("97"));
        assert_eq!(v["stats"], json!({"concepts": 2, "dag_edges": 1}));
        assert_eq!(v["label"], "topic snapshot 2026-10-01");
        assert_eq!(v["spec"], json!({}));
        assert_eq!((v["id"].as_str(), v["status"].as_str(), v["generation"].as_i64()), (Some("s1"), Some("complete"), Some(3)));
        // No counts from the worker is zero, never the global figure.
        assert_eq!(neutral_summary(&row(), None)["stats"], json!({"concepts": 0, "dag_edges": 0}));
    }

    #[test]
    fn an_unconfirmed_worker_reply_is_never_forwarded_to_a_restricted_caller() {
        for stale in [
            Ok(json!({"data": {"concepts": [["tpc-bonly", "topic"]]}})),
            Ok(json!({"concepts": [["tpc-bonly", "topic"]]})),
            Ok(json!({"data": {"counts": {}, "audience_filtered": false}})),
        ] {
            let (status, body) = scoped_payload(&restricted(), stale).unwrap_err();
            assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
            assert!(!body.0.to_string().contains("tpc-"));
        }
        let (status, _) = scoped_payload(&restricted(), Err(anyhow::anyhow!("no responders"))).unwrap_err();
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let ok_reply = scoped_payload(
            &restricted(),
            Ok(json!({"data": {"concepts": [["x", "topic"]], "audience_filtered": true}})),
        )
        .unwrap();
        assert_eq!(ok_reply, json!({"concepts": [["x", "topic"]]}));
    }

    #[test]
    fn the_diff_shape_is_the_one_the_unscoped_path_always_returned() {
        let t = |n: &str| (n.to_string(), "topic".to_string());
        let v = diff_response("a", "b", vec![t("keep"), t("gone")], vec![t("keep"), t("new")]);
        assert_eq!(
            v,
            json!({
                "snapshot_a": "a", "snapshot_b": "b",
                "concepts_added": [["new", "topic"]],
                "concepts_removed": [["gone", "topic"]],
                "concepts_in_both": 1,
            })
        );
    }

    #[test]
    fn only_a_restricted_caller_takes_the_scoped_path() {
        let src = include_str!("snapshots.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        for f in ["async fn snapshots_list(", "async fn snapshots_get(", "async fn snapshots_diff("] {
            let body = &code[code.find(f).unwrap()..];
            let body = &body[..body.find("\n}\n").unwrap()];
            assert!(body.contains("resolve_audience("), "{f}");
            assert!(body.contains("Audience::Roles(_)"), "{f}");
        }
        // The original SQL-backed calls are still there for the unrestricted path.
        assert!(code.contains("snapshot_concepts(&body.snapshot_a)"));
        assert!(code.contains(".snapshots_get(&snapshot_id)"));
    }
}
