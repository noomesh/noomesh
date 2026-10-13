// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The door an add-on exchanges its key at.
//!
//! the design's inbound leg, upgraded. Phase A and B gave each add-on its own
//! `noo_service_keys` row presented as a bearer on every call; this trades that
//! row for a token that expires on its own, so what travels on each request is
//! worth minutes rather than until someone notices.
//!
//! Deliberately not the identity plane. That one issues `<account>/<label>`
//! connections which must also be usable agent IDs — an add-on container is not
//! an account with personas, and giving it one would have been inventing
//! structure to satisfy a rule written for something else. What is shared is
//! the part that is genuinely common: the exchange door table, the claim core
//! (`auth::scoped_claims`), and `noo_service_keys` for the long-lived
//! credential — which keeps `last_used_at`, the evidence phase C closes the
//! shared-secret bridge on.
//!
//! The opposite leg, gateway → add-on, is `addon_auth.rs`. Same table,
//! reversed direction, and the two must not be conflated.

use axum::{extract::Extension, http::StatusCode, response::{IntoResponse, Response}, routing::post, Json, Router};
use serde_json::json;
use std::sync::Arc;

use crate::service_keys::Consumer;
use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    // The LITERAL, not `auth::ADDON_TOKEN_PATH`, because the OpenAPI
    // generator reads route literals — a constant here makes the route
    // invisible to it and to the drift checker, which is how this one first
    // went in. Kiosk does the same for the same reason. The two are held
    // together by tests/test_exchange_doors_are_documented.py.
    Router::new().route("/api/addon/token", post(token))
}

/// `POST /api/addon/token`
///
/// The middleware has already resolved the bearer to a `Consumer` and checked
/// it carries the `addon` scope — this handler is unreachable by any other
/// credential (`auth::require_any_auth`, via `exchange_scope_for`).
///
/// The minted token carries the key's scopes MINUS `addon`: it may do what the
/// add-on was granted and may not open this door again. A token that could
/// re-exchange would outlive the revocation of the key it came from, which is
/// the one thing the short lifetime is for.
///
/// Response: `{"token", "expires_in", "consumer", "scopes"}`.
async fn token(Extension(consumer): Extension<Consumer>) -> Response {
    let ttl = crate::auth::ADDON_TOKEN_TTL_SECS;
    let scopes = crate::auth::addon_token_scopes(&consumer.scopes);
    if scopes.is_empty() {
        // A key carrying `addon` and nothing else buys a token that can do
        // nothing. Minting it would be a success the caller cannot use, and
        // the caller would look for the fault at the routes it then cannot
        // reach rather than at the key.
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": {"type": "addon_key_has_no_scopes",
                "message": format!(
                    "service key '{}' carries only the `addon` scope, so an exchanged token \
                     would grant nothing. Re-issue it with the scopes the add-on needs.",
                    consumer.name)}})),
        )
            .into_response();
    }
    // secret_env, not std::env: NOO_JWT_SECRET arrives as a file
    // (NOO_JWT_SECRET_FILE); a raw env read would refuse every exchange.
    let secret = match crate::config::secret_env::secret_opt("NOO_JWT_SECRET") {
        Some(s) => s,
        None => return no_secret(),
    };
    match crate::auth::mint_addon_jwt(&consumer.name, &scopes, ttl, &secret, crate::jwks::signing_key()) {
        Some(tok) => {
            tracing::info!(consumer = %consumer.name, ttl, scopes = ?scopes, "addon_token_minted");
            Json(json!({
                "token": tok,
                "expires_in": ttl,
                "consumer": consumer.name,
                "scopes": scopes,
            }))
            .into_response()
        }
        None => no_secret(),
    }
}

fn no_secret() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": {"type": "no_jwt_secret",
            "message": "the gateway has no usable NOO_JWT_SECRET; add-on tokens cannot be minted"}})),
    )
        .into_response()
}
