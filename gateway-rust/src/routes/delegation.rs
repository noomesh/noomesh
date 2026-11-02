// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! NATS delegation helpers — shared by all route modules.
//!
//! - `delegate_get` / `delegate_post`: closure factories for explicit NATS delegation
//!
//! HTTP status contract: worker failures are NOT wrapped in 200. Before
//! 2026-07-09 every response here was 200 with an optional `error` body
//! field — clients checking status codes read failures as success (ten
//! runbook ingestions "succeeded" while writing nothing). Mapping:
//!   - transport failure (NATS down / no responders)  → 503
//!   - worker handler exception ("Worker error: ...") → 500
//!   - handler-level {"error": ...} (validation etc.) → 400
//!   - anything else                                  → 200

use std::sync::Arc;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
};
use serde_json::{json, Value};

use crate::auth::RequesterCtx;
use crate::state::AppState;
use crate::trellion_client::TrellionClient;

pub(crate) use crate::trellion_client::StatusJson;

// `worker_ok` (the reply -> HTTP status contract) lives in `trellion_client`
// next to the call shape it belongs to. Re-exported here because the facade
// routes in knowledge.rs / snapshots.rs hand-roll attach -> call -> map with
// the facade in the middle, and MUST reuse it so their status contract
// cannot drift from the delegated routes'.
pub(super) use crate::trellion_client::worker_ok;

/// Attach the authenticated requester (if any) to a delegated body so
/// Python workers can resolve KB roles / attribution. Cluster-HMAC and
/// service-key callers carry no RequesterCtx and stay unrestricted.
/// The one implementation is `trellion_client::attach_requester_ctx`.
pub(super) fn attach_requester(body: &mut Value, ctx: &Option<axum::Extension<RequesterCtx>>) {
    if let Some(axum::Extension(r)) = ctx {
        crate::trellion_client::attach_requester_ctx(body, r);
    }
}

/// 503 `bus_unavailable` when the request never left because the gateway is
/// not connected to NATS (i301 a.3), the same body every bus route answers;
/// `None` for any other failure.
pub(super) fn bus_down(e: &anyhow::Error) -> Option<StatusJson> {
    e.downcast_ref::<crate::worker_client::BusUnavailable>()?;
    Some((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": super::BUS_UNAVAILABLE,
            "detail": super::BUS_UNAVAILABLE_DETAIL,
            "retry_after_secs": super::BUS_RETRY_AFTER_SECS,
        })),
    ))
}

pub(super) fn worker_unavailable(e: impl std::fmt::Display, path: Option<&str>) -> StatusJson {
    let msg = e.to_string();
    // Deliberate refusal (trellion add-on off) gets the operator-facing
    // explanation, not a "Worker unavailable" that reads like an outage.
    if msg.starts_with(crate::addons::DISABLED_MARKER) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": crate::addons::DISABLED_MSG, "addon": "trellion"})),
        );
    }
    let mut body = json!({"error": format!("Worker unavailable: {e}")});
    if let Some(p) = path {
        body["path"] = json!(p);
    }
    (StatusCode::SERVICE_UNAVAILABLE, Json(body))
}

/// The answer for a failed worker request. A worker that REFUSED on purpose
/// and said so with the structured `error_kind` field (see
/// [`crate::worker_client::WorkerRefusal`]) is a client error: 403 for a
/// policy refusal (the request is not permitted; the gateway already answers
/// 403 for its own confinement, e.g. the ops tool-route gate), 422 for an
/// invalid request. Retrying can never succeed, so it must not be a 5xx.
/// Everything else (timeout, no responder, an old worker that sends no kind)
/// stays 503 via [`worker_unavailable`].
pub(super) fn worker_failed(e: &anyhow::Error, path: Option<&str>) -> StatusJson {
    use crate::worker_client::{RefusalKind, WorkerRefusal};
    if let Some(r) = bus_down(e) {
        return r;
    }
    if let Some(r) = e.downcast_ref::<WorkerRefusal>() {
        let status = match r.kind {
            RefusalKind::Policy => StatusCode::FORBIDDEN,
            RefusalKind::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
        };
        // The worker's text is the refusal itself, without the transport
        // prefix `Worker error on <subject>: `.
        let text = r.message.split_once(": ").map(|(_, t)| t).unwrap_or(&r.message);
        return (status, Json(json!({"error": text})));
    }
    worker_unavailable(e, path)
}

/// Create a GET handler that delegates to a Python worker via NATS.
pub fn delegate_get(subject: &'static str) -> impl Fn(State<Arc<AppState>>, Option<axum::Extension<RequesterCtx>>) -> std::pin::Pin<Box<dyn std::future::Future<Output = StatusJson> + Send>> + Clone {
    move |State(state): State<Arc<AppState>>, ctx: Option<axum::Extension<RequesterCtx>>| {
        Box::pin(async move {
            let requester = ctx.as_ref().map(|e| &e.0);
            let client = TrellionClient::new(&state.nats).with_requester(requester);
            match client.call_raw(subject, json!({})).await {
                Ok(response) => worker_ok(response),
                Err(e) => bus_down(&e).unwrap_or_else(|| worker_unavailable(e, None)),
            }
        })
    }
}

/// Create a POST handler that delegates to a Python worker via NATS.
pub fn delegate_post(subject: &'static str) -> impl Fn(State<Arc<AppState>>, Option<axum::Extension<RequesterCtx>>, Json<Value>) -> std::pin::Pin<Box<dyn std::future::Future<Output = StatusJson> + Send>> + Clone {
    move |State(state): State<Arc<AppState>>, ctx: Option<axum::Extension<RequesterCtx>>, Json(body): Json<Value>| {
        Box::pin(async move {
            let requester = ctx.as_ref().map(|e| &e.0);
            let client = TrellionClient::new(&state.nats).with_requester(requester);
            match client.call_raw(subject, body).await {
                Ok(response) => worker_ok(response),
                Err(e) => bus_down(&e).unwrap_or_else(|| worker_unavailable(e, None)),
            }
        })
    }
}

// The catch-all handlers (`catchall_get` / `catchall_post`) and
// `path_to_nats_subject` were removed with the `/api/{*path}` route. Any
// remaining delegation is explicit: a named route calling `delegate_post`
// with a subject spelled out in source, which is greppable. Path-derived
// subjects were not.
#[cfg(test)]
mod tests {
    use super::*;

    /// i301 a.3: a delegated route answers 503 `bus_unavailable` when the
    /// request never left; any other worker failure keeps its own answer.
    #[test]
    fn a_delegated_route_without_the_bus_is_503_bus_unavailable() {
        let e = anyhow::Error::new(crate::worker_client::BusUnavailable { subject: "worker.recall.videos".into() });
        let (status, Json(body)) = worker_failed(&e, None);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "bus_unavailable");
        assert!(body["detail"].as_str().is_some_and(|d| d.contains("noo stack start")), "{body}");
        assert!(bus_down(&anyhow::anyhow!("NATS request failed: no responders")).is_none());
        // The code above the tests only: this test's own literal would count.
        let src = include_str!("delegation.rs").split("\n#[cfg(test)]").next().unwrap();
        assert_eq!(src.matches("Err(e) => bus_down(&e).unwrap_or_else(|| worker_unavailable(e, None)),").count(), 2, "both delegate helpers");
    }

    const REFUSAL: &str = "refusing '/etc/passwd': it is outside the directories noomesh may ingest from. allowed roots: /data/ingest/working";

    #[test]
    fn a_structured_policy_refusal_is_403_with_the_text() {
        let reply = json!({"success": false, "error": REFUSAL, "error_kind": "policy_refusal"});
        let e = crate::worker_client::reply_result("worker.rag.ingest", reply).expect_err("must be an error");
        let (status, Json(body)) = worker_failed(&e, None);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], REFUSAL, "the refusal text, not a 'Worker unavailable' wrapper");
        let reply = json!({"success": false, "error": "no such file: 'x'", "error_kind": "invalid_request"});
        let e = crate::worker_client::reply_result("worker.rag.ingest", reply).unwrap_err();
        assert_eq!(worker_failed(&e, None).0, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn an_old_worker_without_a_kind_keeps_503() {
        let reply = json!({"success": false, "error": REFUSAL});
        let e = crate::worker_client::reply_result("worker.rag.ingest", reply).unwrap_err();
        let (status, Json(body)) = worker_failed(&e, None);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body["error"].as_str().unwrap().contains("allowed roots"), "{body}");
        // an unrecognised kind is not trusted either
        let reply = json!({"success": false, "error": "x", "error_kind": "bogus"});
        let e = crate::worker_client::reply_result("worker.rag.ingest", reply).unwrap_err();
        assert_eq!(worker_failed(&e, None).0, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn an_unreachable_worker_is_503() {
        for msg in ["Worker timeout on worker.rag.ingest", "NATS request failed: no responders"] {
            let e = anyhow::anyhow!(msg);
            let (status, Json(body)) = worker_failed(&e, None);
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{msg}");
            assert!(body["error"].as_str().unwrap().starts_with("Worker unavailable: "), "{body}");
        }
    }

    fn ctx(sub: &str) -> Option<axum::Extension<RequesterCtx>> {
        Some(axum::Extension(RequesterCtx {
            sub: sub.into(),
            scopes: vec!["read".into(), "write".into()],
            role: crate::auth::Role::User,
            harness: None,
            act: None,
        }))
    }

    /// The worker defaults an upload's audience to `user:<sub>`, so `sub`
    /// must be the ACCOUNT. An MCP-door subject is `user/label`; sending it
    /// raw would tag the document into a tier no one can read.
    #[test]
    fn attach_requester_sends_the_account_not_the_connection() {
        let mut body = json!({"text": "x"});
        attach_requester(&mut body, &ctx("alice/laptop"));
        assert_eq!(body["_requester"]["sub"], "alice");
        assert_eq!(body["_requester"]["connection"], "alice/laptop");
    }

    /// The credential's harness claim reaches the worker (and only that: it
    /// is read from the validated context, never from the body).
    #[test]
    fn attach_requester_carries_the_credential_harness() {
        let mut body = json!({"text": "x", "_requester": {"harness": "forged"}});
        let mut c = ctx("alice/laptop");
        c.as_mut().unwrap().0.harness = Some("mcp-external:codex".into());
        attach_requester(&mut body, &c);
        assert_eq!(body["_requester"]["harness"], "mcp-external:codex");
        let mut plain = json!({"text": "x"});
        attach_requester(&mut plain, &ctx("alice"));
        assert!(plain["_requester"]["harness"].is_null());
    }
}
