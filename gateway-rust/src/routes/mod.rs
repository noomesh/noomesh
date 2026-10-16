// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! HTTP + WebSocket routes.
//!
//! Each API group lives in its own submodule.
//! This module merges them into the final application Router.
//!
//! The full API surface is the OpenAPI spec,
//! src/noomesh/gateway/static/openapi.json (checked against this router by
//! scripts/check-openapi-drift.py).

pub(crate) mod admin;
mod agents;
mod cli_piece;
mod console_piece;
mod artifacts;
mod bootstrap;
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
mod addon_token;
mod kiosk;
pub(crate) mod knowledge;
pub(crate) mod memory;
mod monitoring;
mod grafana_ds;
mod logs_ingest;
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
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
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

/// Convenience: convert sqlx errors to AppError.
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(format!("Database error: {e}"))
    }
}

/// Result type alias for handlers that return JSON on success or AppError on failure.
pub type AppResult = Result<Json<Value>, AppError>;

/// Second lock behind the tier gate for GET handlers that return
/// installation-wide data (audit views, config, fleet desired-config, PKI).
/// `auth::USER_READ_PATHS` already keeps a `User`-tier token off these
/// paths; this check holds if a path is ever added to that list by mistake or
/// the handler is mounted somewhere else. `None` is a caller with no
/// requester context (an internal call that passed the auth layer), the same
/// reading `users_admin_read_guard` makes.
pub(crate) fn operator_read_guard(
    ctx: &Option<axum::Extension<crate::auth::RequesterCtx>>,
) -> Result<(), AppError> {
    match ctx {
        None => Ok(()),
        Some(axum::Extension(r)) if r.role >= crate::auth::Role::Operator => Ok(()),
        Some(_) => Err(AppError::Forbidden("operator role required".into())),
    }
}

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
        .merge(artifacts::router())
        .merge(bootstrap::router())
        .merge(seats::router())
        .merge(inference::router())
        .merge(addon_token::router())
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
        .merge(websocket::router());

    // ── HTTP add-ons: routes from the manifest each add-on SHIPS ──
    // Read once, here, for every add-on whose switch is on, from
    // `addon_proxy::ROUTES_DIR/<addon>/routes.json` (delivered read-only by
    // the add-on's overlay), validated, and merged last so a collision with
    // any core route above refuses the add-on instead of replacing a core
    // handler. Off → nothing mounted. On with a missing/invalid manifest →
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
        // Outermost so every response carries them, including 401s from the
        // auth gate and static files.
        .layer(axum_mw::from_fn(crate::middleware::security_headers))
        // A handler that panics answers 500 with a logged reason instead
        // of dropping the connection with nothing in the log
        // Outermost, so it also covers the middleware stack.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(crate::middleware::panic_response))

        .with_state(state)
}

/// The second lock behind the tier gate: GET handlers that return
/// installation-wide data refuse a `User` account themselves.
#[cfg(test)]
mod operator_read_guard_tests {
    use super::operator_read_guard;
    use crate::auth::{RequesterCtx, Role};
    use axum::{http::StatusCode, response::IntoResponse, Extension};

    fn ctx(role: Role) -> Option<Extension<RequesterCtx>> {
        Some(Extension(RequesterCtx {
            sub: "alice".into(),
            scopes: vec!["read".into()],
            role,
            harness: None,
            act: None,
        }))
    }

    #[test]
    fn a_user_is_forbidden_and_operators_admins_and_internal_callers_pass() {
        let code = |c| match operator_read_guard(&c) {
            Ok(()) => StatusCode::OK,
            Err(e) => e.into_response().status(),
        };
        assert_eq!(code(ctx(Role::User)), StatusCode::FORBIDDEN);
        assert_eq!(code(ctx(Role::Operator)), StatusCode::OK);
        assert_eq!(code(ctx(Role::Admin)), StatusCode::OK);
        assert_eq!(code(None), StatusCode::OK);
    }

    /// Each handler the audit named calls the guard BEFORE it reads anything.
    #[test]
    fn every_installation_wide_read_calls_the_guard_first() {
        let admin = include_str!("admin.rs");
        let cluster = include_str!("cluster.rs");
        let settings = include_str!("settings.rs");
        let other = include_str!("other.rs");
        let cases: [(&str, &str, &str); 11] = [
            (admin, "async fn security_audit_history(", "operator_read_guard(&ctx)"),
            (admin, "async fn security_audit_stats(", "operator_read_guard(&ctx)"),
            (admin, "async fn security_violations(", "operator_read_guard(&ctx)"),
            (admin, "async fn security_pki_status(", "operator_read_guard(&ctx)"),
            (cluster, "async fn desired_config_get(", "operator_read_guard(&requester)"),
            (settings, "async fn config_get(", "operator_read_guard(&requester)"),
            (settings, "async fn config_get_section(", "operator_read_guard(&requester)"),
            (settings, "async fn settings_get(", "operator_read_guard(&requester)"),
            (settings, "async fn settings_export(", "operator_read_guard(&requester)"),
            (settings, "async fn settings_flags_list(", "operator_read_guard(&requester)"),
            (other, "async fn coordinator_context(", "operator_read_guard(&requester)"),
        ];
        for (src, sig, call) in cases {
            let start = src.find(sig).unwrap_or_else(|| panic!("{sig} not found"));
            let rest = &src[start..];
            let end = rest[sig.len()..].find("\nasync fn ").map(|i| i + sig.len()).unwrap_or(rest.len());
            let body = &rest[..end];
            let at = body.find(call).unwrap_or_else(|| panic!("{sig} does not call {call}"));
            let first_read = ["state.db", "state.config_yaml", ".fetch_", "read_to_string", "state.redis", "resolve_backend"]
                .iter()
                .filter_map(|m| body.find(m))
                .min()
                .unwrap_or(usize::MAX);
            assert!(at < first_read, "{sig}: the guard must come before the first read");
        }
    }
}
