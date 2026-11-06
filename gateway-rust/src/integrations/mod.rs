// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Shared authorization and encrypted credential lifecycle. Provider endpoints
//! and permissions are reviewed code, not URLs supplied by a connection owner.
pub use crate::repo::integration_content as content;
pub mod crypto;
pub mod oauth;
pub use crate::repo::integration_pairing as pairing;
pub mod provider;
pub mod sync;

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
    /// Google refused for rate or quota (429, or a 403 naming a rate or
    /// quota reason). `retry_after` is Google's own Retry-After, in seconds.
    #[error("Google is limiting requests for this account; sync resumes by itself")]
    Throttled { retry_after: Option<u64>, quota: bool },
}

impl Error {
    /// What a log line may say about this error (i460: name the cause). The
    /// database's own message for storage; a fixed category otherwise, since
    /// provider-facing text can echo request material and never reaches logs.
    pub fn log_cause(&self) -> String {
        // MUTANT: the user-facing line, provider text and all.
        self.to_string()
    }
}

impl From<Error> for crate::routes::AppError {
    fn from(e: Error) -> Self {
        use crate::routes::AppError;
        match e {
            Error::Invalid(m) => AppError::BadRequest(m),
            Error::Unavailable(m) => AppError::Unavailable(m),
            Error::Reauth => AppError::Conflict(e.to_string()),
            Error::NotFound => AppError::NotFound(e.to_string()),
            Error::Throttled { .. } => AppError::Unavailable(e.to_string()),
            Error::Storage(_) => {
                tracing::error!(error = %e.log_cause(), "integration database operation failed");
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
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod log_cause_tests {
    use super::Error;

    /// i460: a log line names the database's own cause, and only a fixed
    /// category for anything a provider could have shaped.
    #[test]
    fn a_log_names_the_storage_cause_and_never_provider_text() {
        let storage = Error::Storage(sqlx::Error::PoolTimedOut);
        assert_eq!(storage.log_cause(), sqlx::Error::PoolTimedOut.to_string());
        assert_ne!(storage.log_cause(), storage.to_string(), "the log names the cause, not the user line");
        for (error, word) in [
            (Error::Invalid("fixture-provider-text-a".into()), "invalid"),
            (Error::Unavailable("fixture-provider-text-b".into()), "unavailable"),
            (Error::Reauth, "reauth"),
            (Error::NotFound, "not_found"),
        ] {
            assert_eq!(error.log_cause(), word);
        }
    }

    /// The sites that used to drop the error now log its cause.
    #[test]
    fn the_sync_and_retrieval_failures_name_their_cause() {
        let sync = crate::test_src::own_code(include_str!("sync.rs"));
        assert!(!sync.contains(".await.is_err()"), "a failed retry record is logged with its cause");
        assert!(!sync.contains("Err(_) => tracing::warn!"), "a queue failure is logged with its cause");
        assert!(sync.matches(".log_cause()").count() >= 3, "sync names the queue, retry and record causes");
        let provider = crate::test_src::own_code(include_str!("../memory/provider.rs"));
        let reply = crate::test_src::fn_body(&provider, "async fn kb_reply_with_personal(");
        assert!(reply.contains("error.log_cause()"), "a private retrieval failure names its cause");
        assert!(!reply.contains("Err(_) =>") && !reply.contains("|_|"), "no failure in the reply is dropped unnamed");
        let content = crate::test_src::own_code(include_str!("../repo/integration_content.rs"));
        assert!(!content.contains("unreadable = true") && !content.contains("unavailable = true"),
            "unreadable sealed documents are counted, not flagged");
    }
}
