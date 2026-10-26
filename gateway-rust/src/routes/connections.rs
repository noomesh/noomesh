// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Private provider connections; OAuth exchange requires the signed-in owner.

use super::{AppError, AppResult};
use crate::{
    audit::{AuditEvent, AuditKind},
    auth::{account_of, RequesterCtx},
    connections::{AccountDraft, SourceDraft},
    repo::connections as repo,
    state::AppState,
};
use axum::{
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/connections", get(list))
        .route("/api/connections/accounts", post(create_account))
        .route("/api/connections/accounts/{id}", delete(remove_account))
        .route("/api/connections/sources", post(create_source))
        .route("/api/connections/sources/{id}", delete(remove_source))
        .route("/api/connections/oauth/start", post(oauth_start))
        .route("/api/connections/oauth/complete", post(oauth_complete))
        .route("/api/connections/oauth/cancel", post(oauth_cancel))
        .route("/api/connections/oauth/callback", get(oauth_callback))
        .route("/api/connections/pairing/start", post(pairing_start))
        .route("/api/connections/pairing/lookup", post(pairing_lookup))
        .route("/api/connections/pairing/approve", post(pairing_approve))
        .route(
            "/api/connections/pairing/{id}",
            get(pairing_status).delete(pairing_cancel),
        )
        .route("/api/connections/accounts/{id}/resources", get(resources))
        .layer(middleware::from_fn(private_response_headers))
}

/// Pairing codes, OAuth tickets and personal metadata must not persist in
/// browser/proxy HTTP caches, including responses produced by this router's
/// handlers on error. The callback also keeps its stricter script policy.
async fn private_response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}

async fn pairing_start(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(request): Json<crate::integrations::pairing::Start>,
) -> AppResult {
    let result = crate::integrations::pairing::start(
        &state.db,
        &state.config.integrations,
        owner_id(&state, &ctx).await?,
        request,
    )
    .await?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(
            AuditKind::IntegrationPairingStarted,
            owner(&ctx)?,
            &format!("pairing/{}", result["id"].as_str().unwrap_or_default()),
        ),
    )
    .await;
    Ok(Json(result))
}
async fn pairing_lookup(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(request): Json<crate::integrations::pairing::Code>,
) -> AppResult {
    Ok(Json(
        crate::integrations::pairing::lookup(
            &state.db,
            owner_id(&state, &ctx).await?,
            &request.code,
        )
        .await?,
    ))
}
async fn pairing_approve(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    headers: HeaderMap,
    Json(request): Json<crate::integrations::pairing::Code>,
) -> AppResult {
    Ok(Json(
        crate::integrations::pairing::approve(
            &state.db,
            &state.config.integrations,
            owner_id(&state, &ctx).await?,
            &request.code,
            headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()),
        )
        .await?,
    ))
}
async fn pairing_status(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(id): Path<Uuid>,
) -> AppResult {
    Ok(Json(
        crate::integrations::pairing::status(&state.db, owner_id(&state, &ctx).await?, id).await?,
    ))
}
async fn pairing_cancel(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(id): Path<Uuid>,
) -> AppResult {
    if crate::integrations::pairing::cancel(&state.db, owner_id(&state, &ctx).await?, id).await? {
        crate::audit::record(
            &state.db,
            AuditEvent::new(
                AuditKind::IntegrationAuthorizationCancelled,
                owner(&ctx)?,
                &format!("pairing/{id}"),
            ),
        )
        .await;
    }
    Ok(Json(json!({"cancelled":true})))
}

async fn owner_id(
    state: &AppState,
    ctx: &Option<Extension<RequesterCtx>>,
) -> Result<Uuid, AppError> {
    crate::repo::integrations::owner_uuid(&state.db, owner(ctx)?)
        .await
        .map_err(db_error)?
        .ok_or_else(|| AppError::Forbidden("A registered Noomesh account is required".into()))
}

async fn oauth_start(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    headers: HeaderMap,
    Json(request): Json<crate::integrations::oauth::Start>,
) -> AppResult {
    let owner = owner_id(&state, &ctx).await?;
    Ok(Json(
        crate::integrations::oauth::start(
            &state.db,
            &state.config.integrations,
            owner,
            request,
            headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()),
        )
        .await?,
    ))
}

async fn oauth_complete(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(request): Json<crate::integrations::oauth::Complete>,
) -> AppResult {
    let owner = owner_id(&state, &ctx).await?;
    let id =
        crate::integrations::oauth::complete(&state.db, &state.config.integrations, owner, request)
            .await?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(
            AuditKind::IntegrationConnected,
            self::owner(&ctx)?,
            &format!("account/{id}"),
        ),
    )
    .await;
    Ok(Json(json!({"id":id,"status":"connected"})))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancel {
    session_id: Uuid,
}
async fn oauth_cancel(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(request): Json<Cancel>,
) -> AppResult {
    if crate::repo::integrations::cancel(
        &state.db,
        owner_id(&state, &ctx).await?,
        request.session_id,
    )
    .await
    .map_err(db_error)?
    {
        crate::audit::record(
            &state.db,
            AuditEvent::new(
                AuditKind::IntegrationAuthorizationCancelled,
                owner(&ctx)?,
                &format!("oauth/{}", request.session_id),
            ),
        )
        .await;
    }
    Ok(Json(json!({"cancelled":true})))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Resources {
    service: String,
    page: Option<String>,
}
async fn resources(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(id): Path<Uuid>,
    Query(query): Query<Resources>,
) -> AppResult {
    let owner = owner_id(&state, &ctx).await?;
    Ok(Json(
        crate::integrations::oauth::resources(
            &state.db,
            &state.config.integrations,
            owner,
            id,
            &query.service,
            query.page.as_deref(),
        )
        .await?,
    ))
}

/// Inert public landing page: never exchanges codes, reads cookies or changes
/// accounts. Only the authenticated opener can complete its one-time session.
async fn oauth_callback() -> impl IntoResponse {
    ([(header::CACHE_CONTROL,"no-store"), (header::REFERRER_POLICY,"no-referrer"),
      (header::CONTENT_SECURITY_POLICY,"default-src 'none'; script-src 'sha256-cU6HJtNo/BfDK1VP5yVrbp4G5vigGSrVQCKScM8G/nE='; base-uri 'none'; frame-ancestors 'none'")],
      Html(include_str!("../integrations/callback.html")))
}

fn owner(ctx: &Option<Extension<RequesterCtx>>) -> Result<&str, AppError> {
    ctx.as_ref()
        .map(|Extension(c)| account_of(&c.sub))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Forbidden("Connections require a signed-in Noomesh account".into())
        })
}

fn db_error(error: sqlx::Error) -> AppError {
    tracing::error!(error = %error, "connection metadata operation failed");
    AppError::Internal("Unable to save or load connections".into())
}

/// List the signed-in account's Google account and source drafts, and provider readiness.
async fn list(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
) -> AppResult {
    let owner = owner(&ctx)?;
    let accounts = repo::accounts(&state.db, owner).await.map_err(db_error)?;
    let sources = repo::sources(&state.db, owner).await.map_err(db_error)?;
    let web = crate::integrations::oauth::ready(
        &state.config.integrations,
        "google",
        crate::integrations::ClientKind::Web,
    );
    let desktop = crate::integrations::oauth::ready(
        &state.config.integrations,
        "google",
        crate::integrations::ClientKind::Desktop,
    );
    Ok(Json(json!({
        "accounts": accounts, "sources": sources,
        "providers": [{"id":"google", "name":"Google", "services":["google_drive","gmail"],
            "authorization_available":web, "desktop_authorization_available":desktop,
            "authorization_detail": if web { "Connect Google, approve Drive or Gmail, then choose what Noomesh should use. Content import is not enabled by this setup." } else if desktop { "Use `noo auth connect google` on the computer running your browser. Your installer can also enable browser sign-in for this console." } else { "Google sign-in needs installer configuration: an OAuth client ID and an integration encryption key. You can prepare account and source drafts now." }}],
    })))
}

/// Prepare another Google account. The email is an unverified sign-in hint, not identity.
async fn create_account(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(mut draft): Json<AccountDraft>,
) -> AppResult {
    let owner = owner(&ctx)?;
    draft.validate().map_err(AppError::BadRequest)?;
    let id = repo::create_account(&state.db, owner, Uuid::new_v4(), &draft)
        .await
        .map_err(db_error)?
        .ok_or_else(|| AppError::Forbidden("A registered Noomesh account is required".into()))?;
    Ok(Json(json!({"id":id,"status":"needs_auth"})))
}

/// Remove one of the caller's account drafts and its source drafts. Does not revoke Google access.
async fn remove_account(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(id): Path<Uuid>,
) -> AppResult {
    if !repo::delete_account(&state.db, owner(&ctx)?, id)
        .await
        .map_err(db_error)?
    {
        return Err(AppError::NotFound("Account draft not found".into()));
    }
    crate::audit::record(
        &state.db,
        AuditEvent::new(
            AuditKind::IntegrationDisconnected,
            owner(&ctx)?,
            &format!("account/{id}"),
        ),
    )
    .await;
    Ok(Json(json!({"removed":true})))
}

/// Add a private, read-only Drive or Gmail source draft to an owned account.
async fn create_source(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Json(mut draft): Json<SourceDraft>,
) -> AppResult {
    let owner = owner(&ctx)?;
    draft.validate().map_err(AppError::BadRequest)?;
    let policy = serde_json::to_value(&draft.policy)
        .map_err(|_| AppError::Internal("Invalid source policy".into()))?;
    let id = repo::create_source(&state.db, owner, Uuid::new_v4(), &draft, &policy)
        .await
        .map_err(db_error)?
        .ok_or_else(|| AppError::NotFound("Account draft not found".into()))?;
    Ok(Json(json!({"id":id,"status":"draft"})))
}

/// Remove one of the caller's source drafts. No imported content exists in a draft.
async fn remove_source(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(id): Path<Uuid>,
) -> AppResult {
    if !repo::delete_source(&state.db, owner(&ctx)?, id)
        .await
        .map_err(db_error)?
    {
        return Err(AppError::NotFound("Source draft not found".into()));
    }
    Ok(Json(json!({"removed":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;

    #[tokio::test]
    async fn private_success_and_error_responses_are_not_cacheable() {
        const OK_PATH: &str = "/test-success";
        const ERROR_PATH: &str = "/test-error";
        let app = Router::new()
            .route(
                OK_PATH,
                get(|| async { Json(json!({"completion_token":"test-only-ticket"})) }),
            )
            .route(
                ERROR_PATH,
                get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
            )
            .layer(middleware::from_fn(private_response_headers));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = crate::tls::client_builder().build().unwrap();
        for path in [OK_PATH, ERROR_PATH] {
            let response = client
                .get(format!("http://{addr}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        server.abort();
    }

    #[tokio::test]
    async fn public_callback_is_inert_no_store_and_its_exact_script_is_allowed() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let response = oauth_callback().await.into_response();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let policy = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let bytes = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        let script = html
            .split("<script>")
            .nth(1)
            .unwrap()
            .split("</script>")
            .next()
            .unwrap();
        let hash =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()));
        assert!(policy.contains(&format!("'sha256-{hash}'")));
        assert!(script.contains("history.replaceState"));
        assert!(!script.contains("fetch("));
        assert!(crate::auth::PUBLIC_PATHS_EXACT.contains(&"/api/connections/oauth/callback"));
    }

    #[test]
    fn every_tier_is_pinned_to_its_own_account_and_internal_has_none() {
        assert!(owner(&None).is_err());
        for role in [Role::User, Role::Operator, Role::Admin] {
            let ctx = Some(Extension(RequesterCtx {
                sub: "alice/laptop".into(),
                scopes: vec!["read".into()],
                role,
                harness: None,
                act: None,
            }));
            assert_eq!(owner(&ctx).unwrap(), "alice");
            let requester = &ctx.as_ref().unwrap().0;
            let pairing = format!("/api/connections/pairing/{}", Uuid::new_v4());
            for method in [axum::http::Method::GET, axum::http::Method::DELETE] {
                assert!(crate::auth::requester_allows(requester, &method, &pairing));
            }
            assert!(!crate::auth::PUBLIC_PATHS_EXACT.contains(&"/api/connections/pairing/lookup"));
            assert!(crate::auth::requester_allows(
                requester,
                &axum::http::Method::GET,
                "/api/connections"
            ));
            assert!(crate::auth::requester_allows(
                requester,
                &axum::http::Method::POST,
                "/api/connections/accounts"
            ));
            for path in [
                "/api/connections/oauth/start",
                "/api/connections/oauth/complete",
                "/api/connections/oauth/cancel",
                "/api/connections/pairing/start",
                "/api/connections/pairing/lookup",
                "/api/connections/pairing/approve",
            ] {
                assert!(crate::auth::requester_allows(
                    requester,
                    &axum::http::Method::POST,
                    path
                ));
            }
            assert!(crate::auth::requester_allows(
                requester,
                &axum::http::Method::GET,
                &format!("/api/connections/accounts/{}/resources", Uuid::new_v4())
            ));
        }
    }
}
