// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Connection metadata and read-only source policies. Drafts grant no access.
//! Provider identity, credentials and granted scopes can only come from a
//! future verified OAuth callback, never from these request bodies.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDraft {
    pub label: String,
    pub email_hint: Option<String>,
}

impl AccountDraft {
    pub fn validate(&mut self) -> Result<(), String> {
        self.label = name(&self.label)?;
        self.email_hint = self
            .email_hint
            .take()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if self.email_hint.as_ref().is_some_and(|s| {
            s.len() > 254
                || !s.contains('@')
                || s.chars().any(char::is_whitespace)
                || s.chars().any(char::is_control)
        }) {
            return Err("Enter an email address, or leave the account hint empty".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDraft {
    pub account_id: Uuid,
    pub name: String,
    pub policy: SourcePolicy,
}

impl SourceDraft {
    pub fn validate(&mut self) -> Result<(), String> {
        self.name = name(&self.name)?;
        self.policy.validate()
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriveExposure {
    SelectedFolders,
    SelectedDrive,
    AllAccessible,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GmailExposure {
    SelectedLabels,
    Mailbox,
}

/// The selection is Noomesh's data-use boundary, not a claim about the
/// provider's OAuth scopes. No write/send or team-sharing modes exist yet.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourcePolicy {
    GoogleDrive {
        exposure: DriveExposure,
        #[serde(default)]
        folder_ids: Vec<String>,
        drive_id: Option<String>,
    },
    Gmail {
        exposure: GmailExposure,
        #[serde(default)]
        label_ids: Vec<String>,
        #[serde(default = "default_lookback")]
        lookback_days: u16,
    },
}

fn default_lookback() -> u16 {
    30
}

/// Explicit self-service routes; adding a future provider operation does
/// not accidentally make it writable by every user.
pub fn user_write_allowed(method: &axum::http::Method, path: &str) -> bool {
    if *method == axum::http::Method::POST {
        return matches!(
            path,
            "/api/connections/accounts"
                | "/api/connections/sources"
                | "/api/connections/oauth/start"
                | "/api/connections/oauth/complete"
                | "/api/connections/oauth/cancel"
                | "/api/connections/pairing/start"
                | "/api/connections/pairing/lookup"
                | "/api/connections/pairing/approve"
        );
    }
    if *method != axum::http::Method::DELETE {
        return false;
    }
    [
        "/api/connections/accounts/",
        "/api/connections/sources/",
        "/api/connections/pairing/",
    ]
    .iter()
    .any(|p| {
        path.strip_prefix(p)
            .is_some_and(|id| Uuid::parse_str(id).is_ok())
    })
}

impl SourcePolicy {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::GoogleDrive { .. } => "google_drive",
            Self::Gmail { .. } => "gmail",
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::GoogleDrive {
                exposure,
                folder_ids,
                drive_id,
            } => {
                ids(folder_ids)?;
                if let Some(id) = drive_id {
                    ids(std::slice::from_ref(id))?;
                }
                match exposure {
                    DriveExposure::SelectedFolders if drive_id.is_some() => {
                        Err("A folder selection cannot also select a drive".into())
                    }
                    DriveExposure::SelectedDrive if !folder_ids.is_empty() => {
                        Err("A drive selection cannot also select folders".into())
                    }
                    DriveExposure::AllAccessible
                        if drive_id.is_some() || !folder_ids.is_empty() =>
                    {
                        Err("Broader Drive access cannot also select folders or a drive".into())
                    }
                    _ => Ok(()),
                }
            }
            Self::Gmail {
                exposure,
                label_ids,
                lookback_days,
            } => {
                ids(label_ids)?;
                if !(1..=3650).contains(lookback_days) {
                    return Err("Mail history must be between 1 and 3650 days".into());
                }
                if *exposure == GmailExposure::Mailbox && !label_ids.is_empty() {
                    return Err("Mailbox access cannot also select labels".into());
                }
                Ok(())
            }
        }
    }
}

fn name(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() || s.chars().count() > 100 || s.chars().any(char::is_control) {
        return Err("Use a name between 1 and 100 characters".into());
    }
    Ok(s.to_string())
}

fn ids(values: &[String]) -> Result<(), String> {
    if values.len() > 100
        || values.iter().any(|s| {
            s.is_empty()
                || s.len() > 256
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
    {
        return Err("Select up to 100 valid Google resources".into());
    }
    let unique: std::collections::HashSet<_> = values.iter().collect();
    if unique.len() != values.len() {
        return Err("A resource can only be selected once".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn clients_cannot_assert_identity_grants_or_activation() {
        for field in [
            "provider_subject",
            "credential_ref",
            "access_token",
            "refresh_token",
            "granted_scopes",
            "status",
            "owner_uuid",
            "provider",
        ] {
            let mut body = json!({"label":"Work"});
            body[field] = json!("forged");
            assert!(
                serde_json::from_value::<AccountDraft>(body).is_err(),
                "accepted {field}"
            );
        }
        for field in ["send", "write", "roles", "sync_enabled"] {
            let mut body = json!({"kind":"gmail","exposure":"mailbox"});
            body[field] = json!(true);
            assert!(
                serde_json::from_value::<SourcePolicy>(body).is_err(),
                "accepted {field}"
            );
        }
        for field in ["owner_uuid", "status", "access", "visibility"] {
            let mut body = json!({"account_id":Uuid::new_v4(),"name":"Mail","policy":{"kind":"gmail","exposure":"mailbox"}});
            body[field] = json!("forged");
            assert!(
                serde_json::from_value::<SourceDraft>(body).is_err(),
                "accepted {field}"
            );
        }
    }

    #[test]
    fn drafts_allow_empty_picker_selections_but_reject_conflicting_exposure() {
        for body in [
            json!({"kind":"google_drive","exposure":"selected_folders"}),
            json!({"kind":"google_drive","exposure":"selected_drive"}),
            json!({"kind":"gmail","exposure":"selected_labels"}),
        ] {
            assert!(serde_json::from_value::<SourcePolicy>(body)
                .unwrap()
                .validate()
                .is_ok());
        }
        for body in [
            json!({"kind":"google_drive","exposure":"selected_drive","folder_ids":["folder"]}),
            json!({"kind":"google_drive","exposure":"all_accessible","folder_ids":["folder"]}),
            json!({"kind":"gmail","exposure":"mailbox","label_ids":["INBOX"]}),
            json!({"kind":"gmail","exposure":"selected_labels","label_ids":["INBOX","INBOX"]}),
            json!({"kind":"gmail","exposure":"mailbox","lookback_days":0}),
        ] {
            assert!(serde_json::from_value::<SourcePolicy>(body)
                .unwrap()
                .validate()
                .is_err());
        }
    }

    #[test]
    fn account_hints_are_optional_and_names_are_normalized() {
        let mut draft: AccountDraft =
            serde_json::from_value(json!({"label":" Work ","email_hint":" "})).unwrap();
        draft.validate().unwrap();
        assert_eq!(draft.label, "Work");
        assert_eq!(draft.email_hint, None);
    }

    #[test]
    fn self_service_does_not_open_future_provider_actions() {
        use axum::http::Method;
        assert!(user_write_allowed(
            &Method::POST,
            "/api/connections/accounts"
        ));
        assert!(user_write_allowed(
            &Method::DELETE,
            &format!("/api/connections/sources/{}", Uuid::new_v4())
        ));
        for path in [
            "/api/connections",
            "/api/connections/accounts/x/revoke",
            "/api/connections/send",
            "/api/connections/accounts/",
        ] {
            for method in [Method::POST, Method::PUT, Method::DELETE] {
                assert!(!user_write_allowed(&method, path));
            }
        }
    }
}

/// Only the owner-filtered resource listing, not arbitrary descendants.
pub fn user_read_allowed(path: &str) -> bool {
    path.strip_prefix("/api/connections/pairing/")
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        || path
            .strip_prefix("/api/connections/accounts/")
            .and_then(|s| s.strip_suffix("/resources"))
            .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
}
