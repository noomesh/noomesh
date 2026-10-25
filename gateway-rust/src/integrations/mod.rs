// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Shared authorization and encrypted credential lifecycle. Provider endpoints
//! and permissions are reviewed code, not URLs supplied by a connection owner.
pub mod crypto;
pub mod oauth;
pub mod provider;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct IntegrationConfig {
    #[serde(default)]
    pub providers: std::collections::BTreeMap<String, OAuthApps>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct OAuthApps {
    #[serde(default)]
    pub desktop_client_id: String,
    #[serde(default)]
    pub web_client_id: String,
    #[serde(default)]
    pub web_redirect_uri: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Desktop,
    Web,
}

impl ClientKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Web => "web",
        }
    }
}

impl OAuthApps {
    pub fn client_id(&self, kind: ClientKind) -> &str {
        match kind {
            ClientKind::Web => self.web_client_id.trim(),
            ClientKind::Desktop if !self.desktop_client_id.trim().is_empty() => {
                self.desktop_client_id.trim()
            }
            ClientKind::Desktop => "",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("Sign in to Google again to restore this connection")]
    Reauth,
    #[error("Connection not found")]
    NotFound,
    #[error("Connection storage is unavailable")]
    Storage(#[from] sqlx::Error),
}

impl From<Error> for crate::routes::AppError {
    fn from(e: Error) -> Self {
        use crate::routes::AppError;
        match e {
            Error::Invalid(m) => AppError::BadRequest(m),
            Error::Unavailable(m) => AppError::Unavailable(m),
            Error::Reauth => AppError::Conflict(e.to_string()),
            Error::NotFound => AppError::NotFound(e.to_string()),
            Error::Storage(_) => {
                tracing::error!("integration database operation failed");
                AppError::Internal(e.to_string())
            }
        }
    }
}

impl IntegrationConfig {
    pub fn app(&self, provider: &str) -> OAuthApps {
        self.providers.get(provider).cloned().unwrap_or_default()
    }
    pub fn client_id(&self, provider: &str, kind: ClientKind) -> String {
        let app = self.app(provider);
        let configured = app.client_id(kind);
        if !configured.is_empty() {
            configured.to_string()
        } else if provider == "google" && kind == ClientKind::Desktop {
            option_env!("NOO_GOOGLE_DESKTOP_CLIENT_ID")
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        }
    }
}
