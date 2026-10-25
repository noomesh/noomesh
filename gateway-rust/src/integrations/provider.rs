// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

use super::{ClientKind, Error, OAuthApps};
use serde::Deserialize;

/// Adding another integration means supplying a reviewed definition and
/// identity/resource adapter; transaction and vault code stays shared.
pub struct Provider {
    pub id: &'static str,
    pub authorize_url: &'static str,
    pub token_url: &'static str,
    pub userinfo_url: &'static str,
    pub services: &'static [(&'static str, &'static str)],
}

pub const GOOGLE: Provider = Provider {
    id: "google",
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
    services: &[
        (
            "google_drive",
            "https://www.googleapis.com/auth/drive.readonly",
        ),
        ("gmail", "https://www.googleapis.com/auth/gmail.readonly"),
    ],
};

pub fn get(id: &str) -> Result<&'static Provider, Error> {
    match id {
        "google" => Ok(&GOOGLE),
        _ => Err(Error::Invalid("Unsupported integration provider".into())),
    }
}

impl Provider {
    pub fn scopes(&self, services: &[String]) -> Result<Vec<String>, Error> {
        if services.is_empty() || services.len() > self.services.len() {
            return Err(Error::Invalid("Choose Drive, Gmail, or both".into()));
        }
        let mut scopes = vec!["openid".into(), "email".into()];
        for name in services {
            let (_, scope) = self
                .services
                .iter()
                .find(|(id, _)| *id == name)
                .ok_or_else(|| Error::Invalid("Unsupported integration service".into()))?;
            if scopes.iter().any(|s| s == scope) {
                return Err(Error::Invalid("A service can only be selected once".into()));
            }
            scopes.push((*scope).into());
        }
        Ok(scopes)
    }
    pub fn granted_services(&self, scopes: &[String]) -> Vec<String> {
        self.services
            .iter()
            .filter(|(_, scope)| scopes.iter().any(|s| s == scope))
            .map(|(s, _)| (*s).into())
            .collect()
    }
}

pub fn redirect(
    config: &OAuthApps,
    kind: ClientKind,
    requested: Option<&str>,
) -> Result<String, Error> {
    let raw = match kind {
        ClientKind::Web => {
            if requested.is_some() {
                return Err(Error::Invalid(
                    "Web redirects come from installer configuration".into(),
                ));
            }
            config.web_redirect_uri.as_str()
        }
        ClientKind::Desktop => requested.ok_or_else(|| {
            Error::Invalid("The local setup helper must supply its callback".into())
        })?,
    };
    let url = reqwest::Url::parse(raw)
        .map_err(|_| Error::Invalid("Invalid OAuth callback URL".into()))?;
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Invalid(
            "Callback URLs cannot contain credentials, queries or fragments".into(),
        ));
    }
    match kind {
        ClientKind::Desktop
            if url.scheme() == "http"
                && url.host_str() == Some("127.0.0.1")
                && url.port().is_some()
                && url.path() == "/noomesh/oauth/callback" => {}
        ClientKind::Web
            if url.scheme() == "https"
                && url.host_str().is_some()
                && url.path() == "/api/connections/oauth/callback" => {}
        _ => {
            return Err(Error::Invalid(
                "Use the registered HTTPS web callback or the helper's HTTP loopback callback"
                    .into(),
            ))
        }
    }
    Ok(url.to_string())
}

#[derive(Deserialize)]
pub struct Identity {
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
}

#[derive(Deserialize)]
pub struct TokenReply {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub scope: Option<String>,
    pub token_type: String,
}

pub fn http_client() -> reqwest::Client {
    crate::tls::client_builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("integration HTTP client")
}

pub async fn json_response<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, Error> {
    let mut data = zeroize::Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error::Unavailable("Provider response interrupted".into()))?
    {
        if data.len() + chunk.len() > 128 * 1024 {
            return Err(Error::Unavailable(
                "Provider response exceeded its limit".into(),
            ));
        }
        data.extend_from_slice(&chunk);
    }
    if !response.status().is_success() {
        let value: serde_json::Value = serde_json::from_slice(&data).unwrap_or_default();
        return Err(
            if value.get("error").and_then(|e| e.as_str()) == Some("invalid_grant") {
                Error::Reauth
            } else {
                Error::Unavailable(
                    "Google could not complete the request; try connecting again".into(),
                )
            },
        );
    }
    serde_json::from_slice(&data)
        .map_err(|_| Error::Unavailable("Provider returned an invalid response".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_policy_refuses_remote_desktop_redirects_and_unregistered_web_urls() {
        let c = OAuthApps {
            web_redirect_uri: "https://controller.example/api/connections/oauth/callback".into(),
            ..Default::default()
        };
        assert!(redirect(&c, ClientKind::Web, None).is_ok());
        assert!(redirect(
            &c,
            ClientKind::Desktop,
            Some("http://127.0.0.1:9911/noomesh/oauth/callback")
        )
        .is_ok());
        for url in [
            "http://192.168.1.1:9911/noomesh/oauth/callback",
            "http://localhost:9911/noomesh/oauth/callback",
            "http://127.0.0.1:9911/noomesh/oauth/callback?x=1",
            "https://evil.example/cb",
        ] {
            assert!(redirect(&c, ClientKind::Desktop, Some(url)).is_err());
        }
        assert!(redirect(&c, ClientKind::Web, Some("https://evil.example/cb")).is_err());
    }
}
