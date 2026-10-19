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
use crate::worker_client;

pub(crate) type StatusJson = (StatusCode, Json<Value>);

/// Map a successful NATS round-trip to an honest HTTP status (the worker
/// may still have reported a failure inside the payload).
///
/// `pub(super)` (with the two helpers below): the memory-provider facade
/// routes in knowledge.rs / snapshots.rs hand-roll what `delegate_post`
/// did — attach requester, call, map status — with the facade in the
/// middle, and MUST reuse these so their status contract cannot drift
/// from the delegated routes'.
pub(super) fn worker_ok(response: Value) -> StatusJson {
    let payload = response.get("data").cloned().unwrap_or(response);
    let status = match payload.get("error").and_then(|e| e.as_str()) {
        None => StatusCode::OK,
        Some(msg) if msg.starts_with("Worker error:") => StatusCode::INTERNAL_SERVER_ERROR,
        Some(_) => StatusCode::BAD_REQUEST,
    };
    (status, Json(payload))
}

/// Attach the authenticated requester (if any) to a delegated body so
/// Python workers can resolve KB roles / attribution. Cluster-HMAC and
/// service-key callers carry no RequesterCtx and stay unrestricted.
pub(super) fn attach_requester(body: &mut Value, ctx: &Option<axum::Extension<RequesterCtx>>) {
    if let Some(axum::Extension(r)) = ctx {
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "_requester".into(),
                // `role` is additive: Python readers use
                // `.get()`, so old workers ignore it and new ones can prefer
                // it over the scope strings.
                // `sub` is the ACCOUNT, never the connection:
                // the Python workers resolve KB roles and audience by
                // username, and a compound subject would match no user and
                // silently strip the session of every role it holds. The
                // connection rides beside it for anything that wants the
                // live session rather than the person.
                json!({
                    "sub": crate::auth::account_of(&r.sub),
                    "connection": r.sub,
                    "scopes": r.scopes,
                    "role": r.role.as_str(),
                    // The credential's signed `harness` claim (`mcp-external:
                    // <consumer>` from the MCP door, `node:<id>` from a
                    // node-hosted harness), null for an ordinary login. Not a
                    // request header: the design's ingest provenance reads
                    // it to say an upload came through the MCP door.
                    "harness": r.harness,
                }),
            );
        }
    }
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
            let mut body = json!({});
            attach_requester(&mut body, &ctx);
            match worker_client::request(&state.nats, subject, &body).await {
                Ok(response) => worker_ok(response),
                Err(e) => worker_unavailable(e, None),
            }
        })
    }
}

/// Create a POST handler that delegates to a Python worker via NATS.
pub fn delegate_post(subject: &'static str) -> impl Fn(State<Arc<AppState>>, Option<axum::Extension<RequesterCtx>>, Json<Value>) -> std::pin::Pin<Box<dyn std::future::Future<Output = StatusJson> + Send>> + Clone {
    move |State(state): State<Arc<AppState>>, ctx: Option<axum::Extension<RequesterCtx>>, Json(mut body): Json<Value>| {
        Box::pin(async move {
            attach_requester(&mut body, &ctx);
            match worker_client::request(&state.nats, subject, &body).await {
                Ok(response) => worker_ok(response),
                Err(e) => worker_unavailable(e, None),
            }
        })
    }
}

// The catch-all handlers (`catchall_get` / `catchall_post`) and
// `path_to_nats_subject` were removed with the `/api/{*path}` route. Any
// remaining delegation is explicit: a named route calling `delegate_post`
// with a subject spelled out in source, which is greppable and appears in
// the ported ledger. Path-derived subjects were neither.
#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn worker_ok_maps_statuses() {
        assert_eq!(worker_ok(json!({"answer": "hi"})).0, StatusCode::OK);
        assert_eq!(
            worker_ok(json!({"error": "question required"})).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            worker_ok(json!({"error": "Worker error: [Errno 36] File name too long"})).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // data envelope unwrapping still applies
        assert_eq!(
            worker_ok(json!({"data": {"error": "bad input"}})).0,
            StatusCode::BAD_REQUEST
        );
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
