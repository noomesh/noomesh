// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

use super::{
    crypto::{hash, random_token, Vault},
    provider, ClientKind, Error, IntegrationConfig,
};
use crate::repo::integrations as repo;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub provider: String,
    pub services: Vec<String>,
    pub client_kind: ClientKind,
    pub redirect_uri: Option<String>,
    pub account_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Complete {
    pub session_id: Uuid,
    pub completion_token: String,
    pub state: String,
    pub code: String,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    verifier: String,
    client_kind: ClientKind,
    client_id: String,
    redirect_uri: String,
}

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub scopes: Vec<String>,
    client_kind: ClientKind,
    client_id: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.verifier.zeroize();
    }
}

pub fn credential_context(owner: Uuid, provider: &str, account: Uuid) -> String {
    format!("noomesh/credentials/v1/{owner}/{provider}/{account}")
}
fn session_context(owner: Uuid, session: Uuid) -> String {
    format!("noomesh/oauth-session/v1/{owner}/{session}")
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn client_secret(
    provider: &str,
    kind: ClientKind,
) -> Result<Option<zeroize::Zeroizing<String>>, Error> {
    if kind == ClientKind::Desktop {
        return Ok(None);
    }
    let name = match provider {
        "google" => "NOO_GOOGLE_OAUTH_CLIENT_SECRET",
        _ => return Err(Error::Invalid("Unsupported provider".into())),
    };
    crate::config::secret_env::secret(name)
        .map_err(|_| Error::Unavailable("Cannot read the web OAuth client secret".into()))?
        .filter(|s| !s.trim().is_empty())
        .map(zeroize::Zeroizing::new)
        .map(Some)
        .ok_or_else(|| {
            Error::Unavailable(
                "Installer setup required: configure the web OAuth client secret".into(),
            )
        })
}

pub fn ready(config: &IntegrationConfig, provider: &str, kind: ClientKind) -> bool {
    Vault::configured().is_ok()
        && !config.client_id(provider, kind).is_empty()
        && client_secret(provider, kind).is_ok()
        && (kind == ClientKind::Desktop
            || provider::redirect(&config.app(provider), kind, None).is_ok())
}

pub async fn start(
    db: &sqlx::PgPool,
    config: &IntegrationConfig,
    owner: Uuid,
    request: Start,
    origin: Option<&str>,
) -> Result<serde_json::Value, Error> {
    let p = provider::get(&request.provider)?;
    let scopes = p.scopes(&request.services)?;
    let vault = Vault::configured()?;
    let client_id = config.client_id(p.id, request.client_kind);
    if client_id.is_empty() {
        return Err(Error::Unavailable("Installer setup required: register a Google OAuth application and configure its public client ID".into()));
    }
    let _secret = client_secret(p.id, request.client_kind)?;
    let redirect_uri = provider::redirect(
        &config.app(p.id),
        request.client_kind,
        request.redirect_uri.as_deref(),
    )?;
    if request.client_kind == ClientKind::Web {
        let redirect = reqwest::Url::parse(&redirect_uri).expect("validated URL");
        if origin != Some(redirect.origin().ascii_serialization().as_str()) {
            return Err(Error::Invalid(
                "Open Connections at the origin registered for Google sign-in".into(),
            ));
        }
    }
    if let Some(id) = request.account_id {
        if repo::target(db, owner, id, p.id).await?.is_none() {
            return Err(Error::NotFound);
        }
    }
    let id = Uuid::new_v4();
    let state = random_token();
    let ticket = random_token();
    let verifier = random_token();
    let mut url = reqwest::Url::parse(p.authorize_url).expect("provider URL");
    url.query_pairs_mut().extend_pairs([
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("response_type", "code"),
        ("scope", &scopes.join(" ")),
        ("state", state.as_str()),
        ("code_challenge", &hash(&verifier)),
        ("code_challenge_method", "S256"),
        ("access_type", "offline"),
        ("prompt", "consent select_account"),
    ]);
    let pending = Pending {
        verifier,
        client_kind: request.client_kind,
        client_id,
        redirect_uri,
    };
    repo::session(
        db,
        owner,
        id,
        p.id,
        request.account_id,
        &hash(&ticket),
        &hash(&state),
        &vault.seal(&pending, &session_context(owner, id))?,
    )
    .await?;
    Ok(
        serde_json::json!({"session_id":id,"completion_token":ticket,"state":state,"authorization_url":url.as_str(),"expires_in":600}),
    )
}

fn validate_token(reply: &provider::TokenReply) -> Result<(), Error> {
    if reply.access_token.is_empty()
        || !reply.token_type.eq_ignore_ascii_case("bearer")
        || !(1..=86400).contains(&reply.expires_in)
    {
        return Err(Error::Unavailable(
            "Google returned an unusable token".into(),
        ));
    }
    Ok(())
}

pub async fn complete(
    db: &sqlx::PgPool,
    config: &IntegrationConfig,
    owner: Uuid,
    request: Complete,
) -> Result<Uuid, Error> {
    if request.code.is_empty()
        || request.code.len() > 8192
        || request.state.len() > 128
        || request.completion_token.len() > 128
    {
        return Err(Error::Invalid("Invalid sign-in response".into()));
    }
    let vault = Vault::configured()?;
    let (provider, target, sealed) = repo::take_session(
        db,
        owner,
        request.session_id,
        &hash(&request.completion_token),
        &hash(&request.state),
    )
    .await?
    .ok_or_else(|| Error::Invalid("Sign-in expired or already used. Connect again".into()))?;
    let pending: Pending = vault.open(&sealed, &session_context(owner, request.session_id))?;
    let p = provider::get(&provider)?;
    if config.client_id(p.id, pending.client_kind) != pending.client_id {
        return Err(Error::Reauth);
    }
    let (identity, credentials) = exchange(p, &pending, &request.code).await?;
    let scopes = credentials.scopes.clone();
    repo::connect(
        db,
        owner,
        p.id,
        &identity.sub,
        &identity.email,
        target,
        &scopes,
        &vault,
        &credentials,
        request.session_id,
    )
    .await
}

async fn exchange(
    p: &provider::Provider,
    pending: &Pending,
    code: &str,
) -> Result<(provider::Identity, Credentials), Error> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("client_id", &pending.client_id),
        ("redirect_uri", &pending.redirect_uri),
        ("code_verifier", &pending.verifier),
        ("code", code),
    ];
    let secret = client_secret(p.id, pending.client_kind)?;
    if let Some(ref secret) = secret {
        form.push(("client_secret", secret.as_str()));
    }
    let client = provider::http_client();
    let response = client
        .post(p.token_url)
        .form(&form)
        .send()
        .await
        .map_err(|_| Error::Unavailable("Cannot reach Google. Try connecting again".into()))?;
    let reply: provider::TokenReply = provider::json_response(response).await?;
    validate_token(&reply)?;
    let identity: provider::Identity = provider::json_response(
        client
            .get(p.userinfo_url)
            .bearer_auth(&reply.access_token)
            .send()
            .await
            .map_err(|_| Error::Unavailable("Cannot verify the Google account".into()))?,
    )
    .await?;
    if identity.sub.is_empty()
        || identity.sub.len() > 255
        || !identity.email_verified
        || identity.email.len() > 254
        || identity.email.is_empty()
    {
        return Err(Error::Invalid(
            "Google did not provide a verified account identity".into(),
        ));
    }
    let refresh_token = reply
        .refresh_token
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::Invalid(
                "Offline access was not granted. Connect again and approve access".into(),
            )
        })?;
    // Never infer permissions from the request: consent may be partial.
    let scopes: Vec<String> = reply
        .scope
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if p.granted_services(&scopes).is_empty() {
        return Err(Error::Invalid(
            "Approve Drive or Gmail access to connect this account".into(),
        ));
    }
    let credentials = Credentials {
        access_token: reply.access_token,
        refresh_token,
        expires_at: now() + reply.expires_in,
        scopes: scopes.clone(),
        client_kind: pending.client_kind,
        client_id: pending.client_id.clone(),
    };
    Ok((identity, credentials))
}

/// Serialize refreshes for one account so concurrent readers do not lose a
/// rotated refresh token. Neither access nor refresh tokens leave this module.
async fn credential(
    db: &sqlx::PgPool,
    config: &IntegrationConfig,
    owner: Uuid,
    account: Uuid,
) -> Result<Credentials, Error> {
    let vault = Vault::configured()?;
    let mut tx = db.begin().await?;
    let (provider, sealed) = repo::lock_credential(&mut tx, owner, account)
        .await?
        .ok_or(Error::NotFound)?;
    let context = credential_context(owner, &provider, account);
    let mut c: Credentials = vault.open(&sealed, &context)?;
    let p = provider::get(&provider)?;
    if config.client_id(p.id, c.client_kind) != c.client_id {
        return Err(Error::Reauth);
    }
    if c.expires_at > now() + 60 {
        tx.commit().await?;
        return Ok(c);
    }
    match refresh(p, &mut c).await {
        Err(Error::Reauth) => {
            repo::reauth(&mut tx, owner, account).await?;
            tx.commit().await?;
            return Err(Error::Reauth);
        }
        result => result?,
    }
    repo::save_refreshed(
        &mut tx,
        owner,
        account,
        &vault.seal(&c, &context)?,
        &c.scopes,
    )
    .await?;
    tx.commit().await?;
    Ok(c)
}

async fn refresh(p: &provider::Provider, c: &mut Credentials) -> Result<(), Error> {
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("client_id", c.client_id.as_str()),
        ("refresh_token", c.refresh_token.as_str()),
    ];
    let secret = client_secret(p.id, c.client_kind)?;
    if let Some(ref secret) = secret {
        form.push(("client_secret", secret.as_str()));
    }
    let response = provider::http_client()
        .post(p.token_url)
        .form(&form)
        .send()
        .await
        .map_err(|_| Error::Unavailable("Cannot reach Google".into()))?;
    let reply: provider::TokenReply = provider::json_response(response).await?;
    validate_token(&reply)?;
    c.access_token = reply.access_token;
    if let Some(token) = reply.refresh_token.filter(|s| !s.is_empty()) {
        c.refresh_token = token;
    }
    if let Some(scopes) = reply.scope {
        c.scopes = scopes.split_whitespace().map(str::to_string).collect();
    }
    c.expires_at = now() + reply.expires_in;
    Ok(())
}

pub async fn resources(
    db: &sqlx::PgPool,
    config: &IntegrationConfig,
    owner: Uuid,
    account: Uuid,
    service: &str,
    page: Option<&str>,
) -> Result<serde_json::Value, Error> {
    let c = credential(db, config, owner, account).await?;
    if !provider::GOOGLE
        .granted_services(&c.scopes)
        .iter()
        .any(|s| {
            s == if service == "gmail" {
                "gmail"
            } else {
                "google_drive"
            }
        })
    {
        return Err(Error::Invalid(
            "Reconnect and approve this service first".into(),
        ));
    }
    let endpoint = match service {
        "gmail" => "https://gmail.googleapis.com/gmail/v1/users/me/labels",
        "folders" => "https://www.googleapis.com/drive/v3/files",
        "drives" => "https://www.googleapis.com/drive/v3/drives",
        _ => {
            return Err(Error::Invalid(
                "Choose folders, drives, or gmail labels".into(),
            ))
        }
    };
    let mut url = reqwest::Url::parse(endpoint).expect("provider URL");
    if service == "folders" {
        url.query_pairs_mut().extend_pairs([
            (
                "q",
                "mimeType='application/vnd.google-apps.folder' and trashed=false",
            ),
            ("fields", "nextPageToken,files(id,name)"),
            ("pageSize", "100"),
            ("supportsAllDrives", "true"),
            ("includeItemsFromAllDrives", "true"),
        ]);
    }
    if service == "drives" {
        url.query_pairs_mut().extend_pairs([
            ("pageSize", "100"),
            ("fields", "nextPageToken,drives(id,name)"),
        ]);
    }
    if let Some(page) = page {
        if service == "gmail" || page.len() > 4096 {
            return Err(Error::Invalid("Invalid page token".into()));
        }
        url.query_pairs_mut().append_pair("pageToken", page);
    }
    let response = provider::http_client()
        .get(url)
        .bearer_auth(&c.access_token)
        .send()
        .await
        .map_err(|_| Error::Unavailable("Cannot reach Google".into()))?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Error::Reauth);
    }
    let data: serde_json::Value = provider::json_response(response).await?;
    let key = match service {
        "gmail" => "labels",
        "folders" => "files",
        _ => "drives",
    };
    let items: Vec<serde_json::Value> = data
        .get(key)
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| {
            Some(serde_json::json!({"id":v.get("id")?.as_str()?,"name":v.get("name")?.as_str()?}))
        })
        .collect();
    Ok(
        serde_json::json!({"items":items,"next_page_token":data.get("nextPageToken").and_then(|v| v.as_str())}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;

    #[tokio::test]
    async fn provider_exchange_uses_pkce_and_accepts_only_verified_offline_grants() {
        for (verified, offline, scope, succeeds) in [
            (
                true,
                true,
                "openid email https://www.googleapis.com/auth/gmail.readonly",
                true,
            ),
            (
                false,
                true,
                "https://www.googleapis.com/auth/gmail.readonly",
                false,
            ),
            (
                true,
                false,
                "https://www.googleapis.com/auth/gmail.readonly",
                false,
            ),
            (true, true, "openid email", false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let token = post(
                move |axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| async move {
                    assert_eq!(form.get("grant_type").unwrap(), "authorization_code");
                    assert_eq!(form.get("code_verifier").unwrap(), "private-verifier");
                    assert_eq!(form.get("code").unwrap(), "single-code");
                    assert!(!form.contains_key("client_secret"));
                    Json(
                        json!({"access_token":"only-server","refresh_token":if offline {Some("offline-server")} else {None},"expires_in":3600,"scope":scope,"token_type":"Bearer"}),
                    )
                },
            );
            let info = get(move |headers: axum::http::HeaderMap| async move {
                assert_eq!(headers.get("authorization").unwrap(), "Bearer only-server");
                Json(
                    json!({"sub":"immutable-sub","email":"verified@example.test","email_verified":verified}),
                )
            });
            // Constants keep test-only mounts out of the gateway route scan.
            const TOKEN_PATH: &str = "/token";
            const INFO_PATH: &str = "/userinfo";
            let app = Router::new()
                .route(TOKEN_PATH, token)
                .route(INFO_PATH, info);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let p = provider::Provider {
                token_url: Box::leak(format!("http://{address}/token").into_boxed_str()),
                userinfo_url: Box::leak(format!("http://{address}/userinfo").into_boxed_str()),
                ..provider::GOOGLE
            };
            let pending = Pending {
                verifier: "private-verifier".into(),
                client_kind: ClientKind::Desktop,
                client_id: "public-client".into(),
                redirect_uri: "http://127.0.0.1:3333/noomesh/oauth/callback".into(),
            };
            let result = exchange(&p, &pending, "single-code").await;
            assert_eq!(result.is_ok(), succeeds);
            if let Ok((identity, credentials)) = result {
                assert_eq!(identity.sub, "immutable-sub");
                assert_eq!(
                    p.granted_services(&credentials.scopes),
                    vec!["gmail".to_string()],
                    "partial consent must not imply Drive access"
                );
                assert_eq!(credentials.refresh_token, "offline-server");
                assert!(credentials.expires_at > now() + 3500);
            }
            server.abort();
        }
    }

    #[test]
    fn sessions_and_credentials_use_different_authenticated_contexts() {
        let owner = Uuid::new_v4();
        let id = Uuid::new_v4();
        assert_ne!(
            session_context(owner, id),
            credential_context(owner, "google", id)
        );
        assert_ne!(
            credential_context(owner, "google", id),
            credential_context(Uuid::new_v4(), "google", id)
        );
    }

    #[tokio::test]
    async fn refresh_keeps_or_rotates_offline_tokens_and_rejects_revoked_grants() {
        for (reply, expected_refresh, revoked) in [
            (
                json!({"access_token":"new-access","expires_in":3600,"token_type":"Bearer"}),
                "old-refresh",
                false,
            ),
            (
                json!({"access_token":"new-access","refresh_token":"rotated-refresh","expires_in":3600,"token_type":"Bearer"}),
                "rotated-refresh",
                false,
            ),
            (
                json!({"error":"invalid_grant","error_description":"PRIVATE_PROVIDER_DETAIL"}),
                "old-refresh",
                true,
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let route = post(
                move |axum::Form(form): axum::Form<std::collections::HashMap<String, String>>| {
                    let reply = reply.clone();
                    async move {
                        assert_eq!(form.get("refresh_token").unwrap(), "old-refresh");
                        assert_eq!(form.get("grant_type").unwrap(), "refresh_token");
                        (
                            if revoked {
                                axum::http::StatusCode::BAD_REQUEST
                            } else {
                                axum::http::StatusCode::OK
                            },
                            Json(reply),
                        )
                    }
                },
            );
            const TOKEN_PATH: &str = "/token";
            let server = tokio::spawn(async move {
                axum::serve(listener, Router::new().route(TOKEN_PATH, route))
                    .await
                    .unwrap()
            });
            let p = provider::Provider {
                token_url: Box::leak(format!("http://{address}/token").into_boxed_str()),
                ..provider::GOOGLE
            };
            let mut c = Credentials {
                access_token: "old-access".into(),
                refresh_token: "old-refresh".into(),
                expires_at: 0,
                scopes: vec!["old-scope".into()],
                client_kind: ClientKind::Desktop,
                client_id: "public-client".into(),
            };
            let result = refresh(&p, &mut c).await;
            if revoked {
                assert!(matches!(result, Err(Error::Reauth)));
                assert_eq!(c.access_token, "old-access");
            } else {
                result.unwrap();
                assert_eq!(c.access_token, "new-access");
                assert_eq!(c.refresh_token, expected_refresh);
                assert_eq!(c.scopes, vec!["old-scope".to_string()]);
            }
            server.abort();
        }
    }
}
