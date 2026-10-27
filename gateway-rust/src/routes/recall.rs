// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Recall memory routes.
//!
//! All routes delegate to the Python worker pool via NATS — Trellion's
//! `VideoMemoryManager` owns the storage layout (postgres+faiss in v2),
//! and the dashboard needs the trellion-backed view of state. Earlier
//! versions of this module scanned a legacy `/data/video-memory/*.mp4`
//! directory natively in Rust, which silently returned zeros after
//! Trellion switched to the postgres+faiss backend.

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post},
    extract::State,
    Json,
};
use serde_json::json;

use crate::measured::{put_into, Measured};
use crate::state::AppState;
use crate::trellion_client::{subjects, TrellionClient};
use super::AppResult;
use super::delegation::{delegate_get, delegate_post};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // Episodic recall (renamed from "video memory" 2026-08-29; the
        // internals followed). `/api/v1/recall/*` is
        // canonical. Every `/api/v1/video-memory/*` row below is a
        // DEPRECATED alias with the SAME handler, kept for one release
        // after 0.6.0 so a pinned console, an older evolve image or a
        // script keeps working; `aliases_mirror_the_canonical_paths`
        // pins the two lists to each other. Each delegated row maps to a
        // `worker.recall.*` NATS subject (Trellion's VideoMemoryManager
        // owns storage layout + lifecycle policy).
        .route("/api/v1/recall/status",            get(recall_status))
        .route("/api/v1/recall/search",            post(delegate_post(subjects::RECALL_SEARCH)))
        .route("/api/v1/recall/archive",           post(delegate_post(subjects::RECALL_ARCHIVE)))
        .route("/api/v1/recall/videos",            get(delegate_get(subjects::RECALL_VIDEOS)))
        .route("/api/v1/recall/archive-status",    get(delegate_get(subjects::RECALL_ARCHIVE_STATUS)))
        .route("/api/v1/recall/lifecycle",         post(delegate_post(subjects::RECALL_LIFECYCLE)))
        .route("/api/v1/recall/lifecycle-stats",   get(delegate_get(subjects::RECALL_LIFECYCLE_STATS)))
        .route("/api/v1/recall/refresh",           post(delegate_post(subjects::RECALL_REFRESH)))
        .route("/api/v1/recall/lifecycle-preview", get(delegate_get(subjects::RECALL_LIFECYCLE_PREVIEW)))
        .route("/api/v1/recall/prominent",         get(delegate_get(subjects::RECALL_PROMINENT)))
        // Deprecated aliases — removed in the release after 0.6.0.
        .route("/api/v1/video-memory/status",            get(recall_status))
        .route("/api/v1/video-memory/search",            post(delegate_post(subjects::RECALL_SEARCH)))
        .route("/api/v1/video-memory/archive",           post(delegate_post(subjects::RECALL_ARCHIVE)))
        .route("/api/v1/video-memory/videos",            get(delegate_get(subjects::RECALL_VIDEOS)))
        .route("/api/v1/video-memory/archive-status",    get(delegate_get(subjects::RECALL_ARCHIVE_STATUS)))
        .route("/api/v1/video-memory/lifecycle",         post(delegate_post(subjects::RECALL_LIFECYCLE)))
        .route("/api/v1/video-memory/lifecycle-stats",   get(delegate_get(subjects::RECALL_LIFECYCLE_STATS)))
        .route("/api/v1/video-memory/refresh",           post(delegate_post(subjects::RECALL_REFRESH)))
        .route("/api/v1/video-memory/lifecycle-preview", get(delegate_get(subjects::RECALL_LIFECYCLE_PREVIEW)))
        .route("/api/v1/video-memory/prominent",         get(delegate_get(subjects::RECALL_PROMINENT)))
}

// ═══════════════════════════════════════════════════════════════
// Recall memory status — delegated to Python worker (Trellion-backed)
// ═══════════════════════════════════════════════════════════════
//
// `worker.recall.status` (in worker_pool.py) calls
// `VideoMemoryManager.status()` and queries the trellion_video_frames /
// trellion_traversal_records tables. That's the source of truth in the
// postgres+faiss v2 backend; the legacy file-scan path missed all of it.

/// GET /api/v1/recall/status — recall memory system status.
///
/// Pure NATS delegation — keeps Trellion's storage-layout knowledge in
/// Python so this route stays correct when Trellion's internals evolve.
async fn recall_status(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    let resp = TrellionClient::new(&state.nats).call_raw(subjects::RECALL_STATUS, json!({})).await;

    match resp {
        Ok(v) => {
            // Worker returns {"success": true, "data": {...}} — unwrap to the
            // dashboard-expected flat shape, falling back to the raw value
            // if the worker is on an older schema.
            match unwrap_status(v) {
                Ok(payload) => Ok(Json(payload)),
                Err(e) => Ok(Json(unreachable_status(&e))),
            }
        }
        Err(_) => Ok(Json(unreachable_status(
            "recall memory worker unreachable — check noo-gateway python worker",
        ))),
    }
}

/// Peel the reply envelopes off a `worker.recall.status` answer.
///
/// The worker pool wraps every handler's return in `{"success", "data"}`, and
/// the recall handlers already return their own `{"success", "data"}`, so the
/// real status sits one level deeper than the single `data` unwrap reached.
/// The console then read `started`/`total_records` off the envelope, found
/// neither, and drew "Off / 0 records" for a healthy system. Peel while the
/// value is an envelope; an inner `success: false` is an error, not a status.
fn unwrap_status(mut v: serde_json::Value) -> Result<serde_json::Value, String> {
    for _ in 0..4 {
        let Some(obj) = v.as_object() else { break };
        // A failed handler replies {"success": false, "error"} with no `data`.
        if !(obj.contains_key("success") && (obj.contains_key("data") || obj.contains_key("error"))) {
            break;
        }
        if obj.get("success") == Some(&json!(false)) {
            let msg = obj
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("recall status reported success=false");
            return Err(msg.to_string());
        }
        v = obj.get("data").cloned().unwrap_or(json!({}));
    }
    Ok(v)
}

/// The dashboard-shaped answer when the status cannot be read: the counts are
/// null with a `_detail` saying why, never 0 (the store may hold thousands).
fn unreachable_status(error: &str) -> serde_json::Value {
    let mut body = json!({
        "engine": "rust+offline",
        "videos": [],
        "lifecycle": {},
        "traversals": {},
        "error": error,
    });
    put_into(&mut body, "started", Measured::<bool>::unmeasured("worker unreachable"));
    put_into(&mut body, "enabled", Measured::<bool>::unmeasured("worker unreachable"));
    put_into(&mut body, "video_count", Measured::<u64>::unmeasured(error));
    put_into(&mut body, "total_records", Measured::<u64>::unmeasured(error));
    put_into(&mut body, "total_size_mb", Measured::<f64>::unmeasured(error));
    body
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    /// `(suffix, handler expression)` for every row under `prefix`.
    fn rows(prefix: &str) -> BTreeMap<String, String> {
        let src = include_str!("recall.rs");
        let body = &src[src.find("pub fn router()").unwrap()..src.find("#[cfg(test)]").unwrap()];
        body.lines()
            .filter_map(|l| l.trim().strip_prefix(".route(\""))
            .filter_map(|l| l.strip_prefix(prefix))
            .map(|l| {
                let (suffix, rest) = l.split_once('"').unwrap();
                let handler = rest.trim_start_matches(',').trim().trim_end_matches(')').trim();
                (suffix.to_string(), handler.to_string())
            })
            .collect()
    }

    /// the old `/api/v1/video-memory/*` paths answer exactly
    /// like the canonical `/api/v1/recall/*` ones — same suffixes, same
    /// method, same handler or NATS subject — until the alias is dropped.
    #[test]
    fn aliases_mirror_the_canonical_paths() {
        let canonical = rows("/api/v1/recall/");
        let legacy = rows("/api/v1/video-memory/");
        assert_eq!(canonical.len(), 10, "{canonical:?}");
        assert_eq!(canonical, legacy, "every recall path needs its video-memory alias, same handler");
    }

    #[test]
    fn status_envelope_is_peeled_to_the_real_status() {
        let inner = serde_json::json!({"started": true, "total_records": 7});
        let wrapped = serde_json::json!({"success": true, "data": {"success": true, "data": inner.clone()}});
        assert_eq!(super::unwrap_status(wrapped).unwrap(), inner);
        // Already flat (older worker): untouched.
        assert_eq!(super::unwrap_status(inner.clone()).unwrap(), inner);
        // One layer only (worker already unwrapped): peeled once.
        let one = serde_json::json!({"success": true, "data": inner.clone()});
        assert_eq!(super::unwrap_status(one).unwrap(), inner);
    }

    #[test]
    fn inner_failure_is_an_error_not_a_status() {
        let failed = serde_json::json!({"success": true, "data": {"success": false, "error": "db down"}});
        assert_eq!(super::unwrap_status(failed).unwrap_err(), "db down");
    }
}
