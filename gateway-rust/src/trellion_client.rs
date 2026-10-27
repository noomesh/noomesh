// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The gateway's API to the Python/trellion workers.
//!
//! `worker_client` is the TRANSPORT (NATS request/reply, signing, the DLQ,
//! streams); this module is the API the rest of the gateway calls. One door
//! for the three things every caller used to redo by hand:
//!
//!   1. attach the authenticated requester to the body (one implementation,
//!      [`attach_requester_ctx`]);
//!   2. go through `worker_client::request_with_timeout`, which owns the
//!      add-on degradation choke point (a trellion subject on a trellion-less
//!      install refuses instantly, it does not wait out the NATS timeout);
//!   3. map the outcome: the add-on refusal, a timeout, a worker's structured
//!      refusal, and the reply's `error` field ([`worker_ok`]).
//!
//! Two flavours, because the gateway has two kinds of caller:
//!   - [`TrellionClient::call_raw`] keeps the `anyhow` error the transport
//!     produces. HTTP routes that already answer a `(StatusCode, Json)` pair
//!     (`delegation::worker_unavailable` / `worker_failed`) and background
//!     callers that only log use it, so their wire behaviour is unchanged.
//!   - [`TrellionClient::call`] answers an [`AppError`] for handlers that
//!     return `AppResult`.
//!
//! SUBJECTS ARE A BUS GRANT CONTRACT. A `worker.*` subject is named in the
//! NATS publish grants and the signed principal header; a respelled subject
//! is an outage, not a refactor (three silent NATS outages so far). The
//! constants in [`subjects`] hold the exact strings the call sites used
//! before they moved here, and a test pins the set. The grant lists in
//! `addons.rs`, `nats_credentials.rs` and `bus_principal.rs` enumerate
//! subjects as data for policy and deliberately do NOT read from here.
//!
//! Not in this module on purpose: fire-and-forget + DLQ and `request_stream`
//! (still `worker_client`), the HTTP add-on forward (`addon_proxy.rs`), and
//! direct SQL against trellion tables (the D11 residue, see the PR body).

use axum::{http::StatusCode, Json};
use serde_json::{json, Value};
use std::time::Duration;

use crate::auth::RequesterCtx;
use crate::routes::AppError;

/// Every request subject the gateway sends to a Python worker.
///
/// Excluded (and still spelled as literals where they are used): the
/// fire-and-forget publishes (`worker.temporal.extract`,
/// `worker.retrieval.feedback`), the autonomy health dispatch
/// (`worker.autonomy.check_rag`) and the core tool pool (`worker.tool.generic`).
pub mod subjects {
    pub const RAG_QUERY: &str = "worker.rag.query";
    pub const RAG_INGEST: &str = "worker.rag.ingest";
    pub const RAG_DEDUPLICATE: &str = "worker.rag.deduplicate";
    pub const RAG_RETAG: &str = "worker.rag.retag";
    pub const RAG_HOLD: &str = "worker.rag.hold";
    pub const RAG_UNHOLD: &str = "worker.rag.unhold";
    pub const RAG_HELD: &str = "worker.rag.held";
    pub const RAG_PURGE: &str = "worker.rag.purge";
    pub const RAG_AUDIENCE: &str = "worker.rag.audience";
    pub const RAG_ENTITY_CLEANUP: &str = "worker.rag.entity_cleanup";
    pub const RAG_CONTEXT: &str = "worker.rag.context";
    pub const GRAPH_RECLUSTER: &str = "worker.graph.recluster";
    pub const GRAPH_NAVIGATE: &str = "worker.graph.navigate";
    pub const GRAPH_TRAVERSE: &str = "worker.graph.traverse";
    pub const GRAPH_EXPLAIN_PATH: &str = "worker.graph.explain_path";
    pub const GRAPH_SEMANTIC_SEARCH: &str = "worker.graph.semantic_search";
    pub const GRAPH_SEARCH_CLUSTERS: &str = "worker.graph.search_clusters";
    pub const GRAPH_CLASSIFY_INTENT: &str = "worker.graph.classify_intent";
    pub const GRAPH_EXTRACT_RELATIONS: &str = "worker.graph.extract_relations";
    pub const GRAPH_RECALL_TRAVERSALS: &str = "worker.graph.recall_traversals";
    pub const GRAPH_RECALL_WALKS: &str = "worker.graph.recall_walks";
    pub const GRAPH_CONSOLE_PIECE: &str = "worker.graph.console_piece";
    pub const RECALL_SEARCH: &str = "worker.recall.search";
    pub const RECALL_ARCHIVE: &str = "worker.recall.archive";
    pub const RECALL_VIDEOS: &str = "worker.recall.videos";
    pub const RECALL_ARCHIVE_STATUS: &str = "worker.recall.archive_status";
    pub const RECALL_LIFECYCLE: &str = "worker.recall.lifecycle";
    pub const RECALL_LIFECYCLE_STATS: &str = "worker.recall.lifecycle_stats";
    pub const RECALL_REFRESH: &str = "worker.recall.refresh";
    pub const RECALL_LIFECYCLE_PREVIEW: &str = "worker.recall.lifecycle_preview";
    pub const RECALL_PROMINENT: &str = "worker.recall.prominent";
    pub const RECALL_STATUS: &str = "worker.recall.status";
    pub const RECALL_PACKS: &str = "worker.recall.packs";
    pub const MEMORY_BATCH_INDEX: &str = "worker.memory.batch_index";
    pub const MEMORY_SEARCH: &str = "worker.memory.search";
    pub const MEMORY_CROSS_CHANNEL: &str = "worker.memory.cross_channel";
    pub const MEMORY_RESOLVE_CONVERSATION: &str = "worker.memory.resolve_conversation";

    /// Every constant above, for the pin test.
    pub const ALL: &[&str] = &[
        RAG_QUERY,
        RAG_INGEST,
        RAG_DEDUPLICATE,
        RAG_RETAG,
        RAG_HOLD,
        RAG_UNHOLD,
        RAG_HELD,
        RAG_PURGE,
        RAG_AUDIENCE,
        RAG_ENTITY_CLEANUP,
        RAG_CONTEXT,
        GRAPH_RECLUSTER,
        GRAPH_NAVIGATE,
        GRAPH_TRAVERSE,
        GRAPH_EXPLAIN_PATH,
        GRAPH_SEMANTIC_SEARCH,
        GRAPH_SEARCH_CLUSTERS,
        GRAPH_CLASSIFY_INTENT,
        GRAPH_EXTRACT_RELATIONS,
        GRAPH_RECALL_TRAVERSALS,
        GRAPH_RECALL_WALKS,
        GRAPH_CONSOLE_PIECE,
        RECALL_SEARCH,
        RECALL_ARCHIVE,
        RECALL_VIDEOS,
        RECALL_ARCHIVE_STATUS,
        RECALL_LIFECYCLE,
        RECALL_LIFECYCLE_STATS,
        RECALL_REFRESH,
        RECALL_LIFECYCLE_PREVIEW,
        RECALL_PROMINENT,
        RECALL_STATUS,
        RECALL_PACKS,
        MEMORY_BATCH_INDEX,
        MEMORY_SEARCH,
        MEMORY_CROSS_CHANNEL,
        MEMORY_RESOLVE_CONVERSATION,
    ];
}

pub(crate) type StatusJson = (StatusCode, Json<Value>);

/// Map a successful NATS round-trip to an honest HTTP status (the worker
/// may still have reported a failure inside the payload).
///
///   - no `error`                         -> 200
///   - `error` starting "Worker error:"   -> 500 (handler exception)
///   - any other `error`                  -> 400 (handler-level validation)
///
/// Pure on purpose. `routes/delegation.rs` re-exports it for the facade
/// routes in knowledge.rs / snapshots.rs, which MUST share it so their
/// status contract cannot drift from the delegated routes'.
pub(crate) fn worker_ok(response: Value) -> StatusJson {
    let payload = response.get("data").cloned().unwrap_or(response);
    let status = match payload.get("error").and_then(|e| e.as_str()) {
        None => StatusCode::OK,
        Some(msg) if msg.starts_with("Worker error:") => StatusCode::INTERNAL_SERVER_ERROR,
        Some(_) => StatusCode::BAD_REQUEST,
    };
    (status, Json(payload))
}

/// Attach the authenticated requester to a body so Python workers can
/// resolve KB roles / attribution. Cluster-HMAC and service-key callers
/// carry no RequesterCtx and stay unrestricted (nothing is attached).
pub(crate) fn attach_requester_ctx(body: &mut Value, r: &RequesterCtx) {
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "_requester".into(),
            // `role` is additive: Python readers use `.get()`, so old
            // workers ignore it and new ones can prefer it over the scope
            // strings.
            // `sub` is the ACCOUNT, never the connection: the Python
            // workers resolve KB roles and audience by username, and a
            // compound subject would match no user and silently strip the
            // session of every role it holds. The connection rides beside
            // it for anything that wants the live session rather than the
            // person.
            json!({
                "sub": crate::auth::account_of(&r.sub),
                "connection": r.sub,
                "scopes": r.scopes,
                "role": r.role.as_str(),
                // The credential's signed `harness` claim (`mcp-external:
                // <consumer>` from the MCP door, `node:<id>` from a
                // node-hosted harness), null for an ordinary login. Not a
                // request header: the design's ingest provenance reads it
                // to say an upload came through the MCP door.
                "harness": r.harness,
            }),
        );
    }
}

/// Which add-on refused, when `msg` is the transport's degradation refusal.
fn refusing_addon(msg: &str) -> Option<&'static str> {
    if msg.starts_with(crate::addons::DISABLED_MARKER) {
        Some("trellion")
    } else if msg.starts_with(crate::addons::INTEL_DISABLED_MARKER) {
        Some("trellion_intel")
    } else {
        None
    }
}

/// Map a transport error to an [`AppError`]. Pure, so the mapping is tested
/// without a bus.
///
///   - add-on off            -> `Unavailable` with the add-on's own refusal
///                              sentence (the one `require_trellion` serves)
///   - worker timeout        -> `Upstream` (502) naming the subject
///   - structured refusal    -> `Forbidden` (policy) / `BadRequest` (invalid)
///   - anything else         -> `Unavailable("Worker unavailable: ...")`
pub(crate) fn map_error(subject: &str, e: &anyhow::Error) -> AppError {
    use crate::worker_client::{RefusalKind, WorkerRefusal, WorkerTimeout};
    if let Some(addon) = refusing_addon(&e.to_string()) {
        return AppError::Unavailable(crate::addons::refusal_msg(addon));
    }
    if e.downcast_ref::<WorkerTimeout>().is_some() {
        return AppError::Upstream(format!("worker timed out on {subject}"));
    }
    if let Some(r) = e.downcast_ref::<WorkerRefusal>() {
        // The worker's text without the transport prefix `Worker error on <subject>: `.
        let text = r.message.split_once(": ").map(|(_, t)| t).unwrap_or(&r.message).to_string();
        return match r.kind {
            RefusalKind::Policy => AppError::Forbidden(text),
            RefusalKind::Invalid => AppError::BadRequest(text),
        };
    }
    AppError::Unavailable(format!("Worker unavailable: {e}"))
}

/// One call shape to the Python workers.
pub struct TrellionClient<'a> {
    nats: &'a async_nats::Client,
    requester: Option<&'a RequesterCtx>,
}

impl<'a> TrellionClient<'a> {
    /// A client with no requester: internal callers (coordinator, loops).
    pub fn new(nats: &'a async_nats::Client) -> Self {
        Self { nats, requester: None }
    }

    /// Attach the caller's identity to every body this client sends.
    pub fn with_requester(mut self, requester: Option<&'a RequesterCtx>) -> Self {
        self.requester = requester;
        self
    }

    /// The call, keeping the transport's `anyhow` error. Default timeout.
    pub async fn call_raw(&self, subject: &str, payload: Value) -> anyhow::Result<Value> {
        self.call_raw_with_timeout(subject, payload, crate::worker_client::worker_timeout())
            .await
    }

    /// [`Self::call_raw`] with an explicit timeout, for the few subjects
    /// whose work is genuinely long.
    pub async fn call_raw_with_timeout(
        &self,
        subject: &str,
        mut payload: Value,
        timeout: Duration,
    ) -> anyhow::Result<Value> {
        if let Some(r) = self.requester {
            attach_requester_ctx(&mut payload, r);
        }
        crate::worker_client::request_with_timeout(self.nats, subject, &payload, timeout).await
    }

    /// The call, answering an [`AppError`] (see [`map_error`]).
    pub async fn call(&self, subject: &'static str, payload: Value) -> Result<Value, AppError> {
        self.call_raw(subject, payload).await.map_err(|e| map_error(subject, &e))
    }

    /// [`Self::call`] with an explicit timeout.
    pub async fn call_with_timeout(
        &self,
        subject: &'static str,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value, AppError> {
        self.call_raw_with_timeout(subject, payload, timeout)
            .await
            .map_err(|e| map_error(subject, &e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned subject set. Regenerate from the tree with
    /// `grep -rohE '"worker\.[a-z_]+\.[a-z_]+"' gateway-rust/src | sort -u`
    /// on origin/dev and keep the request-position subset (the 37 here; the
    /// other four of the 41 are named in the `subjects` doc comment).
    const PINNED: &[&str] = &[
        "worker.graph.classify_intent",
        "worker.graph.console_piece",
        "worker.graph.explain_path",
        "worker.graph.extract_relations",
        "worker.graph.navigate",
        "worker.graph.recall_traversals",
        "worker.graph.recall_walks",
        "worker.graph.recluster",
        "worker.graph.search_clusters",
        "worker.graph.semantic_search",
        "worker.graph.traverse",
        "worker.memory.batch_index",
        "worker.memory.cross_channel",
        "worker.memory.resolve_conversation",
        "worker.memory.search",
        "worker.rag.audience",
        "worker.rag.context",
        "worker.rag.deduplicate",
        "worker.rag.entity_cleanup",
        "worker.rag.held",
        "worker.rag.hold",
        "worker.rag.ingest",
        "worker.rag.purge",
        "worker.rag.query",
        "worker.rag.retag",
        "worker.rag.unhold",
        "worker.recall.archive",
        "worker.recall.archive_status",
        "worker.recall.lifecycle",
        "worker.recall.lifecycle_preview",
        "worker.recall.lifecycle_stats",
        "worker.recall.packs",
        "worker.recall.prominent",
        "worker.recall.refresh",
        "worker.recall.search",
        "worker.recall.status",
        "worker.recall.videos",
    ];

    #[test]
    fn the_subject_constants_are_exactly_the_pinned_strings() {
        let mut got: Vec<&str> = subjects::ALL.to_vec();
        got.sort_unstable();
        let mut want: Vec<&str> = PINNED.to_vec();
        want.sort_unstable();
        assert_eq!(got, want);
        assert_eq!(got.len(), 37);
        let mut dedup = got.clone();
        dedup.dedup();
        assert_eq!(dedup.len(), got.len(), "a subject constant is duplicated");
    }

    #[test]
    fn every_subject_has_the_worker_shape() {
        for s in subjects::ALL {
            let parts: Vec<&str> = s.split('.').collect();
            assert_eq!(parts.len(), 3, "{s}");
            assert_eq!(parts[0], "worker", "{s}");
            assert!(parts[1..].iter().all(|p| !p.is_empty()
                && p.chars().all(|c| c.is_ascii_lowercase() || c == '_')), "{s}");
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

    #[test]
    fn the_addon_refusal_is_unavailable_with_the_operator_sentence() {
        let e = anyhow::anyhow!("{}: worker.rag.query", crate::addons::DISABLED_MARKER);
        match map_error(subjects::RAG_QUERY, &e) {
            AppError::Unavailable(m) => assert_eq!(m, crate::addons::refusal_msg("trellion")),
            other => panic!("{other:?}"),
        }
        let e = anyhow::anyhow!("{}: worker.graph.navigate", crate::addons::INTEL_DISABLED_MARKER);
        match map_error(subjects::GRAPH_NAVIGATE, &e) {
            AppError::Unavailable(m) => assert_eq!(m, crate::addons::refusal_msg("trellion_intel")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_timeout_is_a_502_naming_the_subject() {
        let e = anyhow::Error::new(crate::worker_client::WorkerTimeout {
            subject: subjects::RAG_QUERY.to_string(),
        });
        match map_error(subjects::RAG_QUERY, &e) {
            AppError::Upstream(m) => assert!(m.contains("worker.rag.query"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_structured_refusal_is_a_client_error_and_the_rest_is_unavailable() {
        use crate::worker_client::{RefusalKind, WorkerRefusal};
        let policy = anyhow::Error::new(WorkerRefusal {
            kind: RefusalKind::Policy,
            message: "Worker error on worker.rag.ingest: refusing '/etc/passwd'".into(),
        });
        assert!(matches!(map_error(subjects::RAG_INGEST, &policy),
            AppError::Forbidden(m) if m.as_str() == "refusing '/etc/passwd'"));
        let invalid = anyhow::Error::new(WorkerRefusal {
            kind: RefusalKind::Invalid,
            message: "Worker error on worker.rag.ingest: no such file".into(),
        });
        assert!(matches!(map_error(subjects::RAG_INGEST, &invalid), AppError::BadRequest(_)));
        let other = anyhow::anyhow!("NATS request failed: no responders");
        assert!(matches!(map_error(subjects::RAG_INGEST, &other),
            AppError::Unavailable(m) if m.starts_with("Worker unavailable: ")));
    }

    #[test]
    fn attach_requester_ctx_sends_the_account_not_the_connection() {
        let r = RequesterCtx {
            sub: "alice/laptop".into(),
            scopes: vec!["read".into()],
            role: crate::auth::Role::User,
            harness: None,
            act: None,
        };
        let mut body = json!({"q": 1});
        attach_requester_ctx(&mut body, &r);
        assert_eq!(body["_requester"]["sub"], "alice");
        assert_eq!(body["_requester"]["connection"], "alice/laptop");
        assert_eq!(body["q"], 1);
    }
}
