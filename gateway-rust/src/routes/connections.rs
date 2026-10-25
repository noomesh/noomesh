// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Owner-only connection drafts. No tokens, imports or provider calls.

use super::{AppError, AppResult};
use crate::{
    auth::{account_of, RequesterCtx},
    connections::{AccountDraft, SourceDraft},
    repo::connections as repo,
    state::AppState,
};
use axum::{
    extract::{Path, State},
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
    Ok(Json(json!({
        "accounts": accounts, "sources": sources,
        "providers": [{"id":"google", "name":"Google", "services":["google_drive","gmail"],
            "authorization_available":false,
            "authorization_detail":"Google sign-in is not available yet. Prepare your accounts and sources now; sign-in will be required before any Google data is accessed."}],
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
        }
    }
}
