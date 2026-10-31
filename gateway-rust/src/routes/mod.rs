// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! HTTP + WebSocket routes.
//!
//! Each API group lives in its own submodule.
//! This module merges them into the final application Router.
//!
//! Who may call a handler (Operator / Admin / OperatorOrInternal) is decided by
//! the extractors in `crate::authz`, named in the handler's signature; this
//! module holds no permission checks of its own.
//!
//! The full API surface is the OpenAPI spec,
//! src/noomesh/gateway/static/openapi.json (checked against this router by
//! scripts/check-openapi-drift.py).

pub(crate) mod admin;
mod traces;
mod agents;
mod cli_piece;
mod console_piece;
mod artifacts;
mod bootstrap;
pub(crate) use bootstrap::self_agent_base;
mod seats;
pub(crate) mod cluster;
pub(crate) mod communication;
pub(crate) mod core;
pub mod delegation;
pub(crate) mod external;
pub(crate) mod inference;
pub(crate) mod chat_aggregate;
pub(crate) mod raw_chat;
pub(crate) mod responses_shim;
mod intelligence;
// The unattended display's read surface: projections of the routes above,
// shaped to what one screen draws.
mod addon_access;
mod addon_token;
mod kiosk;
mod reservations;
pub(crate) mod knowledge;
pub(crate) mod memory;
mod monitoring;
mod grafana_ds;
mod logs_ingest;
mod traces_ingest;
pub mod logs_search;
mod other;
pub mod peers;
// Evolve add-on proxy — OSS-safe, always compiled. The
// pro-only routes/pro.rs + its has_pro_routes build gate are retired: the
// routes forward to the noo-evolve container, and answer an explained 503
// when the add-on is disabled or down (addons.rs contract).
pub(crate) mod settings;
mod mcp_registry;
mod snapshots;
mod temporal;
mod ui;
mod usage;
mod harness;
mod identity;
mod operator_certs;
mod tasks;
pub mod users;
pub(crate) mod erase_kb;
mod recall;
mod walks;
mod audit_read;
pub mod ops;
mod websocket;

/// The per-user scoping predicates, against a real migrated schema
/// DSN-gated; skips silently without
/// `NOO_BROKER_TEST_DSN`, which CI sets.
#[cfg(test)]
mod ownership_scoping_tests;

/// The real router on a throwaway Postgres: authz, `redis_reconnecting` and
/// `Measured`, asserted by request. DSN-gated like the module above.
#[cfg(test)]
mod router_harness_tests;

use std::sync::Arc;
use axum::{Router, Json, middleware as axum_mw};
use axum::http::StatusCode;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use tower_http::services::ServeDir;

use crate::state::AppState;

/// Type alias used by all route handlers.
pub type AppJson = Json<Value>;

/// Unified error type for route handlers.
///
/// Implements `IntoResponse` so handlers can return `Result<Json<Value>, AppError>`
/// and use the `?` operator for concise error propagation.
#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    Internal(String),
    /// A node agent, device, or the controller's own self-agent answered with
    /// a failure or did not answer; the message says what it said. 502, never
    /// 500: the gateway is not what broke.
    Upstream(String),
    BadRequest(String),
    Conflict(String),
    Forbidden(String),
    /// The surface is deliberately not here — a disabled or unlicensed
    /// add-on, or a dependency the gateway knows is absent. 503 with an
    /// explanation, never a 500: "turned off" and "broken" must not read
    /// the same to an operator.
    Unavailable(String),
    /// 409 with a `Retry-After` header: the operation cannot happen yet, and
    /// the message says when to ask again.
    RetryLater { msg: String, retry_after_secs: u64 },
    /// 429 with a `Retry-After` header: a per-caller quota is spent.
    TooManyRequests { msg: String, retry_after_secs: u64 },
    /// 503 with a `Retry-After` header and a MACHINE-READABLE `error` code
    /// (`detail` carries the prose): a dependency is not connected yet, so a
    /// caller may retry on the code instead of matching an English sentence.
    /// First use: `redis_reconnecting` from `/api/jobs/submit`, which used to
    /// answer a bare `500 {"error":"Redis not connected"}` to every node poke
    /// of a `noo upgrade --all` that ran while the gateway had no Redis
    /// client (0.6.3 -> 0.6.4 roll, 2026-10-15).
    UnavailableRetry { code: &'static str, detail: String, retry_after_secs: u64 },
}

/// The message the error carries, without the variant name.
///
/// Route handlers only ever need `IntoResponse`, but some route BODIES are now
/// shared with non-HTTP callers — the autonomy engine drives
/// `cluster::start_backend_core` / `stop_backend_core` — and those need the
/// text for a log field or an operator alert. `{e:?}` would put `Internal(...)`
/// in front of an operator mid-incident.
impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::NotFound(m)
            | Self::Internal(m)
            | Self::Upstream(m)
            | Self::BadRequest(m)
            | Self::Conflict(m)
            | Self::Forbidden(m)
            | Self::Unavailable(m) => m,
            Self::RetryLater { msg, .. } | Self::TooManyRequests { msg, .. } => msg,
            Self::UnavailableRetry { detail, .. } => detail,
        };
        f.write_str(msg)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Self::NotFound(m) => (StatusCode::NOT_FOUND, m),
            Self::Internal(m) => return internal_response(&m),
            Self::Upstream(m) => (StatusCode::BAD_GATEWAY, m),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Self::Conflict(m) => (StatusCode::CONFLICT, m),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            Self::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            Self::TooManyRequests { msg, retry_after_secs } => {
                let mut r = (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": msg, "retry_after_secs": retry_after_secs}))).into_response();
                if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                    r.headers_mut().insert(axum::http::header::RETRY_AFTER, v);
                }
                return r;
            }
            Self::UnavailableRetry { code, detail, retry_after_secs } => {
                let body = json!({"error": code, "detail": detail, "retry_after_secs": retry_after_secs});
                let mut r = (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
                if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                    r.headers_mut().insert(axum::http::header::RETRY_AFTER, v);
                }
                return r;
            }
            Self::RetryLater { msg, retry_after_secs } => {
                let mut r = (StatusCode::CONFLICT, Json(json!({"error": msg, "retry_after_secs": retry_after_secs}))).into_response();
                if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                    r.headers_mut().insert(axum::http::header::RETRY_AFTER, v);
                }
                return r;
            }
        };
        (status, Json(json!({"error": msg}))).into_response()
    }
}

/// Map a `(StatusCode, msg)` pair from a helper that answers in HTTP terms
/// (e.g. `settings::mutate_config`) back onto the matching `AppError`, so a
/// 404/409/503 is not flattened into an anonymous 500.
pub(crate) fn from_status(status: StatusCode, msg: String) -> AppError {
    match status {
        StatusCode::BAD_REQUEST => AppError::BadRequest(msg),
        StatusCode::NOT_FOUND => AppError::NotFound(msg),
        StatusCode::CONFLICT => AppError::Conflict(msg),
        StatusCode::FORBIDDEN => AppError::Forbidden(msg),
        StatusCode::SERVICE_UNAVAILABLE => AppError::Unavailable(msg),
        _ => AppError::Internal(msg),
    }
}

/// The ONE place an internal failure becomes an HTTP body (i191 D3). The
/// full message goes to the log under a short ref; the caller gets only the
/// ref, so SQL text, hostnames and paths never leave in a response.
fn internal_response(msg: &str) -> Response {
    let r = short_ref();
    tracing::error!(ref_id = %r, error = %msg, "internal error returned to a caller as a fixed body");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(internal_body(&r))).into_response()
}

pub(crate) fn short_ref() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn internal_body(r: &str) -> Value {
    // `detail` is the key the noo CLI and the console read off every error
    // body; keep it so an operator sees the ref without a log in front of them.
    json!({"error": "internal error", "detail": format!("internal error (ref {r}); the gateway log has the cause"), "ref": r})
}

/// Map a SQLSTATE to the client-fault variant it means, if any.
/// 23505 unique_violation -> Conflict; 23503 foreign_key, 23502 not_null,
/// 23514 check -> BadRequest. Anything else stays internal.
fn client_fault_for_sqlstate(code: &str) -> Option<AppError> {
    match code {
        "23505" => Some(AppError::Conflict("resource already exists".into())),
        "23503" | "23502" | "23514" => Some(AppError::BadRequest("request violates a data constraint".into())),
        _ => None,
    }
}

/// Convenience: convert sqlx errors to AppError.
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(d) = &e {
            if let Some(fault) = d.code().and_then(|c| client_fault_for_sqlstate(&c)) {
                return fault;
            }
        }
        AppError::Internal(format!("Database error: {e}"))
    }
}

/// Result type alias for handlers that return JSON on success or AppError on failure.
pub type AppResult = Result<Json<Value>, AppError>;

/// Refuse a whole router when the trellion add-on is absent.
///
/// Applied by `temporal` (6 routes) and `knowledge` (16). Both reach
/// TRELLION-OWNED tables — `pages`, `entities`, `edges`, `noo_temporal_edges`,
/// `noo_entities_typed`, none of which the mesh baseline creates — directly
/// over SQL. The gateway's trellion gate lives at the NATS boundary
/// (`worker_client::is_trellion_subject`), so it never saw a single one of
/// them: without the add-on all 22 answered a raw `relation does not exist`
/// 500 where the add-on contract promises an explained 503.
///
/// A LAYER rather than a check per handler, and that is the point: 22 copies
/// of a guard is 21 chances to forget one, and the forgotten one answers a
/// raw SQL error. The next route added to either file inherits the gate.
///
/// Newly reachable rather than theoretical: the `baseline_tables` preflight
/// fix in this same batch made trellion-free installs bootable for the first
/// time, and these are the routes such an install hits.
///
/// The body shape matches `addon_proxy.rs` and what
/// `docs/getting-started/add-ons.md` promises: `error`, `addon`, and a
/// `state` that keeps "the operator turned it off" separate from "the licence
/// does not cover it".
///
/// A 503 rather than an empty 200. An empty result would read as "the graph
/// knows nothing about you" — a claim about your DATA — when the truth is a
/// claim about your INSTALL.
pub(super) async fn require_trellion(req: Request, next: Next) -> Response {
    match trellion_refusal() {
        Some(refusal) => refusal,
        None => next.run(req).await,
    }
}

/// The refusal itself, or `None` when trellion is present.
///
/// Split from the layer so the decision and the body shape are testable
/// without constructing an axum `Next`.
pub(super) fn trellion_refusal() -> Option<Response> {
    if crate::addons::trellion_enabled() {
        return None;
    }
    Some(trellion_refusal_body())
}

/// The 503 body itself, with no gate in front of it.
///
/// Split out so the SHAPE is testable without process-wide add-on state.
/// Since add-ons moved to the `addons:` map in noomesh.yaml, setting
/// `NOO_TRELLION_ENABLED` in a test controls nothing — the two tests that did
/// so passed and failed for reasons unrelated to what they claimed to check.
/// Same reasoning as `addons::state_from`, which is pure "so the two-switch
/// contract is testable without racing on process env".
pub(super) fn trellion_refusal_body() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": crate::addons::refusal_msg("trellion"),
            "addon": "trellion",
            "state": crate::addons::health_word("trellion"),
        })),
    )
        .into_response()
}


pub fn build_router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        // ── Group routers (all 14 API groups) ──
        .merge(ui::router())
        .merge(core::router())
        .merge(cluster::router())
        .merge(reservations::router())
        .merge(artifacts::router())
        .merge(bootstrap::router())
        .merge(seats::router())
        .merge(inference::router())
        .merge(traces::router())
        .merge(addon_token::router())
        .merge(addon_access::router())
        .merge(kiosk::router())
        .merge(identity::router())
        .merge(operator_certs::router())
        .merge(external::router())
        // External MCP door. Always mounted; the handler itself 404s unless
        // NOO_MCP_EXTERNAL_ENABLED is set, so "is it routed" and "is it open"
        // stay one decision made in one place rather than two that can drift.
        .merge(crate::mcp_external::router())
        // The operator door over the gateway's own TLS, so a remote harness
        // does not need a second published port (token always required).
        .merge(crate::mcp_local::shared_router())
        .merge(knowledge::router())
        .merge(memory::router())
        .merge(temporal::router())
        .merge(recall::router())
        .merge(walks::router())
        .merge(ops::router())
        .merge(settings::router())
        .merge(intelligence::router())
        .merge(admin::router())
        .merge(audit_read::router())
        .merge(monitoring::router())
        .merge(grafana_ds::router())
        .merge(users::router())
        .merge(agents::router())
        .merge(communication::router())
        .merge(other::router())
        .merge(peers::router())
        .merge(snapshots::router())
        .merge(usage::router())
        .merge(harness::router())
        .merge(tasks::router())
        .merge(mcp_registry::router())
        .merge(console_piece::router())
        .merge(cli_piece::router())
        // An add-on's own web UI (`/addons/<addon>/ui/…`, its session
        // cookie) and its WebSocket tickets: core routes that look up the
        // add-on's manifest per request, so they name no add-on.
        .merge(crate::addon_ui::router())
        .merge(crate::addon_ws::router())
        .merge(crate::tunnel::router())
        .merge(websocket::router());

    // ── HTTP add-ons: routes from the manifest each add-on SHIPS ──
    // Read once, here, for every add-on whose switch is on, from
    // `<addon>/routes.json` (the launcher's read-only copy from the add-on's
    // signed bundle under `addon_proxy::BUNDLE_ROUTES_DIR`, else what a
    // shipped add-on's overlay delivers under `addon_proxy::ROUTES_DIR`),
    // validated, and merged last so a collision with any core route above
    // refuses the add-on instead of replacing a core handler. Off → nothing mounted. On with a missing/invalid manifest →
    // nothing mounted, `/health` says `unhealthy`, the log says why. The
    // core names no add-on route.
    let router = crate::addon_proxy::mount(router);

    router
        // ── Static files (dashboard) ──
        .nest_service("/static", ServeDir::new(crate::paths::STATIC_DIR))
        // Dashboard assets: the tagged noo-mesh-ui-web dist is vite-default
        // layout, so its index references /assets/…. Every image carries it
        // now that the artifact is the only UI source.
        .nest_service(
            "/assets",
            ServeDir::new(format!("{}/assets", crate::paths::UI_WWW_DIR)),
        )

        // ── No catch-all. ──
        // `/api/{*path}` used to delegate any unmatched route to Python by
        // deriving a subject from the path. It is gone: an unmatched /api
        // path now 404s instead of silently becoming a NATS request.
        //
        // It could not have worked anyway. The Python end of that fallback
        // (`worker_pool._handle_catchall_api`) tried `from .app import app`
        // as its last resort, and gateway/app.py was deleted in the Rust
        // port — so an unmatched path produced an error via a fallback that
        // could not serve, which reads exactly like an outage.
        //
        // The two handlers that genuinely still live in Python have explicit
        // delegating routes (POST /api/coding/task, POST
        // /api/snapshots/consolidate). Delegation is declared, never implicit.

        // ── Middleware (applied to all routes above) ──
        // Auth is the OUTERMOST gate — request_logger and rate_limit
        // run first (so denied requests still get logged/rate-limited),
        // then auth decides allow/401. Public paths (/health, /metrics,
        // /static/, webhooks with their own per-handler signatures)
        // bypass via PUBLIC_PATH_PREFIXES inside the middleware.
        // Applied BEFORE the auth layer and therefore INNER to it: axum wraps
        // earlier layers in later ones, so this one runs after auth has
        // decided and inserted its extensions. It reads them and puts the
        // caller in scope for the whole handler, which is what every
        // `worker.*` publish then signs itself with.
        // Route code does not opt in, and so cannot forget.
        .layer(axum_mw::from_fn(crate::bus_principal::principal_layer))
        .layer(axum_mw::from_fn_with_state(state.clone(), crate::auth::require_any_auth))
        // Outside auth: the Grafana session route never answers a bare 403
        // — it says why and which tiers open Grafana.
        .layer(axum_mw::from_fn(crate::auth::explain_grafana_refusal))
        // The caller's address (same trusted-proxy rule as the rate limiter),
        // bound for the handler so every audit row records where it came from.
        .layer(axum_mw::from_fn(crate::audit_context::origin_layer))
        .layer(axum_mw::from_fn_with_state(state.clone(), crate::middleware::rate_limit))
        .layer(axum_mw::from_fn_with_state(state.clone(), crate::middleware::request_logger))
        // Request tracing (i359), outside the logger so the trace covers it,
        // inside security_headers so the `traceparent` it adds is kept. A
        // `Router::layer`, so the matched route template is known here.
        .layer(axum_mw::from_fn(crate::request_trace::trace_layer))
        // Outermost so every response carries them, including 401s from the
        // auth gate and static files.
        .layer(axum_mw::from_fn(crate::middleware::security_headers))
        // A handler that panics answers 500 with a logged reason instead
        // of dropping the connection with nothing in the log
        // Outermost, so it also covers the middleware stack.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(crate::middleware::panic_response))

        .with_state(state)
}

#[cfg(test)]
mod internal_body_tests {
    use super::*;

    async fn body_of(resp: Response) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// The body never carries the internal message, only a fixed string and a ref.
    #[tokio::test]
    async fn internal_error_body_hides_detail() {
        let secret = "Database error: relation \"noo_users\" does not exist at db.internal:5432";
        let (status, v) = body_of(AppError::Internal(secret.into()).into_response()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(v["error"], "internal error");
        let r = v["ref"].as_str().unwrap();
        assert_eq!(r.len(), 8);
        assert!(!v.to_string().contains("noo_users"));
        assert!(!v.to_string().contains("db.internal"));
    }

    /// An upstream failure is a 502 that says what the upstream said.
    #[tokio::test]
    async fn upstream_error_is_502_with_message() {
        let msg = "Node agent returned 409: lease held by job 7";
        let (status, v) = body_of(AppError::Upstream(msg.into()).into_response()).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(v["error"], msg);
    }

    #[test]
    fn from_status_keeps_the_class() {
        assert!(matches!(from_status(StatusCode::BAD_REQUEST, "m".into()), AppError::BadRequest(_)));
        assert!(matches!(from_status(StatusCode::NOT_FOUND, "m".into()), AppError::NotFound(_)));
        assert!(matches!(from_status(StatusCode::CONFLICT, "m".into()), AppError::Conflict(_)));
        assert!(matches!(from_status(StatusCode::FORBIDDEN, "m".into()), AppError::Forbidden(_)));
        assert!(matches!(from_status(StatusCode::SERVICE_UNAVAILABLE, "m".into()), AppError::Unavailable(_)));
        assert!(matches!(from_status(StatusCode::IM_A_TEAPOT, "m".into()), AppError::Internal(_)));
    }

    #[test]
    fn constraint_sqlstates_map_to_client_faults() {
        assert!(matches!(client_fault_for_sqlstate("23505"), Some(AppError::Conflict(_))));
        for c in ["23503", "23502", "23514"] {
            assert!(matches!(client_fault_for_sqlstate(c), Some(AppError::BadRequest(_))), "{c}");
        }
        assert!(client_fault_for_sqlstate("42P01").is_none());
        assert!(client_fault_for_sqlstate("40001").is_none());
    }
}
