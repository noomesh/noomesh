// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Reading request traces (i359): what an operator, or an agent on the
//! operator door, learns from `noo_request_trace`.
//!
//! - `GET /api/traces/requests`: recent requests, newest first, filtered.
//! - `GET /api/traces/summary`: the same window grouped by route, model,
//!   node, backend or actor: count, errors, latency percentiles, tokens.
//!
//! Both are Operator/Admin only twice over: `auth::TRACES_READ_PREFIX`
//! refuses every `/api/traces/*` path below Operator, and each handler takes
//! the [`Operator`] extractor. A trace names who made each request and which
//! routes they used, across every account (P1); a per-user "my own
//! requests" view would be a separate, scoped route.
//!
//! Rows hold metadata and sizes only (`request_trace.rs`); nothing here can
//! return prompt or answer text, because none is stored.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use super::{AppError, AppResult};
use crate::authz::Operator;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/traces/requests", get(requests))
        .route("/api/traces/summary", get(summary))
}

/// The widest window either route reads: the table keeps 30 days.
pub const MAX_HOURS: i64 = crate::request_trace::RETENTION_DAYS * 24;

fn hours_of(h: Option<i64>) -> i64 {
    h.unwrap_or(24).clamp(1, MAX_HOURS)
}

#[derive(Deserialize, Default)]
pub struct RequestsQuery {
    /// Look back this many hours (default 24, at most 720).
    hours: Option<i64>,
    /// Exact route template (`/v1/chat/completions`).
    route: Option<String>,
    model: Option<String>,
    node: Option<String>,
    /// The caller's subject (a username, a service-key consumer).
    actor: Option<String>,
    /// Only requests answered with at least this status (500 = errors).
    min_status: Option<i32>,
    /// Only requests that took at least this long.
    min_ms: Option<i64>,
    /// Rows to return (default 100, at most 1000).
    limit: Option<i64>,
}

/// `GET /api/traces/requests` — recent requests from `noo_request_trace`,
/// newest first. Filters: `hours` (default 24, max 720), `route`, `model`,
/// `node`, `actor`, `min_status`, `min_ms`, `limit` (default 100, max 1000).
/// Each row: when, trace id (look it up in Grafana's Tempo data source),
/// method, route template, status, duration, actor, model, backend, node,
/// tokens, span count and sizes. Operator/Admin only.
async fn requests(_op: Operator, State(state): State<Arc<AppState>>, Query(q): Query<RequestsQuery>) -> AppResult {
    let hours = hours_of(q.hours);
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let filter = crate::repo::request_trace::Filter {
        hours,
        route: q.route.as_deref(),
        model: q.model.as_deref(),
        node: q.node.as_deref(),
        actor: q.actor.as_deref(),
        min_status: q.min_status,
        min_ms: q.min_ms,
        limit,
    };
    let rows = crate::repo::request_trace::recent(&state.db, &filter).await?;
    let out: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("at").ok(),
                "trace_id": r.try_get::<String, _>("trace_id").ok(),
                "method": r.try_get::<String, _>("method").ok(),
                "route": r.try_get::<String, _>("route").ok(),
                "status": r.try_get::<i32, _>("status").ok(),
                "duration_ms": r.try_get::<i64, _>("duration_ms").ok(),
                "actor": r.try_get::<Option<String>, _>("actor").ok().flatten(),
                "actor_kind": r.try_get::<Option<String>, _>("actor_kind").ok().flatten(),
                "model": r.try_get::<Option<String>, _>("model").ok().flatten(),
                "backend": r.try_get::<Option<String>, _>("backend").ok().flatten(),
                "node": r.try_get::<Option<String>, _>("node_id").ok().flatten(),
                "prompt_tokens": r.try_get::<i64, _>("prompt_tokens").ok(),
                "completion_tokens": r.try_get::<i64, _>("completion_tokens").ok(),
                "span_count": r.try_get::<i64, _>("span_count").ok(),
                "request_bytes": r.try_get::<Option<i64>, _>("request_bytes").ok().flatten(),
                "response_bytes": r.try_get::<Option<i64>, _>("response_bytes").ok().flatten(),
            })
        })
        .collect();
    Ok(Json(json!({"hours": hours, "count": out.len(), "requests": out})))
}

/// What `summary` may group by: the query parameter and the column it
/// reads. A fixed list, so a parameter never becomes SQL.
pub const GROUP_BY: &[(&str, &str)] =
    &[("route", "route"), ("model", "model"), ("node", "node_id"), ("backend", "backend"), ("actor", "actor")];

pub fn group_column(by: Option<&str>) -> Result<&'static str, String> {
    let by = by.unwrap_or("route");
    GROUP_BY.iter().find(|(k, _)| *k == by).map(|(_, c)| *c).ok_or_else(|| {
        let keys: Vec<&str> = GROUP_BY.iter().map(|(k, _)| *k).collect();
        format!("`by` is one of {}; got {by:?}", keys.join(", "))
    })
}

#[derive(Deserialize, Default)]
pub struct SummaryQuery {
    hours: Option<i64>,
    /// route (default), model, node, backend or actor.
    by: Option<String>,
    /// Only this route template.
    route: Option<String>,
}

/// `GET /api/traces/summary` — the window grouped by `by` (route by
/// default; model, node, backend or actor), busiest first: requests,
/// errors (status >= 500), p50/p95/max duration, prompt and completion
/// tokens. `hours` defaults to 24 (max 720); `route` narrows to one route.
/// Operator/Admin only.
async fn summary(_op: Operator, State(state): State<Arc<AppState>>, Query(q): Query<SummaryQuery>) -> AppResult {
    let hours = hours_of(q.hours);
    let col = group_column(q.by.as_deref()).map_err(AppError::BadRequest)?;
    let rows = crate::repo::request_trace::grouped(&state.db, col, hours, q.route.as_deref()).await?;
    let groups: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "key": r.try_get::<Option<String>, _>("key").ok().flatten(),
                "requests": r.try_get::<i64, _>("requests").ok(),
                "errors": r.try_get::<i64, _>("errors").ok(),
                "p50_ms": r.try_get::<Option<f64>, _>("p50_ms").ok().flatten(),
                "p95_ms": r.try_get::<Option<f64>, _>("p95_ms").ok().flatten(),
                "max_ms": r.try_get::<Option<i64>, _>("max_ms").ok().flatten(),
                "prompt_tokens": r.try_get::<i64, _>("prompt_tokens").ok(),
                "completion_tokens": r.try_get::<i64, _>("completion_tokens").ok(),
            })
        })
        .collect();
    Ok(Json(json!({"hours": hours, "by": q.by.as_deref().unwrap_or("route"), "groups": groups})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_by_is_a_fixed_list_of_columns() {
        assert_eq!(group_column(None), Ok("route"));
        assert_eq!(group_column(Some("node")), Ok("node_id"));
        assert_eq!(group_column(Some("actor")), Ok("actor"));
        for bad in ["status; DROP TABLE noo_request_trace", "user_uuid", "", "Route"] {
            let e = group_column(Some(bad)).expect_err(bad);
            assert!(e.contains("route, model, node, backend, actor"), "{e}");
        }
    }

    #[test]
    fn the_window_is_bounded_by_retention() {
        assert_eq!(hours_of(None), 24);
        assert_eq!(hours_of(Some(0)), 1);
        assert_eq!(hours_of(Some(100_000)), MAX_HOURS);
        assert_eq!(MAX_HOURS, 720);
    }

    /// Every column the readers select is one the migration creates.
    #[test]
    fn the_readers_select_only_created_columns() {
        let created = crate::mesh_migrate::MIGRATIONS
            .iter()
            .find(|m| m.revision == crate::mesh_migrate::REQUEST_TRACE_REVISION)
            .expect("the request-trace migration")
            .sql;
        let src = include_str!("../repo/request_trace.rs");
        let select = src.split("SELECT at, trace_id").nth(1).and_then(|s| s.split("FROM").next()).expect("the select");
        for col in std::iter::once("trace_id").chain(select.split(',').map(str::trim)).filter(|c| !c.is_empty()) {
            assert!(created.contains(&format!("\n    {col} ")), "{col} is selected but not created");
        }
        for (_, col) in GROUP_BY {
            assert!(created.contains(&format!("\n    {col} ")), "{col} is grouped by but not created");
            assert!(
                src.contains(&format!("\"{col}\" => by!(\"{col}\")")),
                "{col} has no literal statement in repo::request_trace::grouped"
            );
        }
    }
}
