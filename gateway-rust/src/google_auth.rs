// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Google service-account OAuth2 helpers.
//!
//! Loads `GOOGLE_CHAT_CREDENTIALS` (path to a service-account JSON key),
//! signs the SA JWT, exchanges it at `oauth2.googleapis.com/token`, and
//! caches the resulting access token until ~5 min before expiry. The
//! `yup-oauth2` SA authenticator is rebuilt on each refresh — cheap
//! relative to outbound rate, and avoids leaking yup-oauth2's concrete
//! connector type into our signatures (the type names changed across
//! yup-oauth2 versions and again with the hyper 1.x migration).
//!
//! Why this exists: when channel routes were ported to Rust on
//! 2026-03-31, `send_google_chat` substituted the inbound webhook
//! verification token (`GOOGLE_CHAT_BEARER_TOKEN`) for what should
//! have been an OAuth2 access token. Every outbound call returned 403.
//! the design replaced the band-aid (NATS round-trip to Python) with
//! this native Rust path. 2026-04-28 expanded to multi-scope so the
//! shared-drive ingest loop can mint `drive.readonly` tokens from the
//! same SA without a second credentials file.
//!

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use yup_oauth2::{parse_service_account_key, read_service_account_key, ServiceAccountAuthenticator};

pub const CHAT_BOT_SCOPE: &str = "https://www.googleapis.com/auth/chat.bot";
pub const DRIVE_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";
/// Narrow write scope: SA can create/modify only files it owns. Used for
/// Shared-Drive uploads where the bot writes reports the SA is a member of.
pub const DRIVE_FILE_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";

/// Refresh the cached token at least this far ahead of expiry.
const REFRESH_SKEW: Duration = Duration::from_secs(300);
/// Conservative SA token lifetime — Google issues 3600s, refresh after 50 min.
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);

#[derive(Clone)]
struct CachedToken {
    token: String,
    refresh_after: Instant,
}

/// Cache keyed by joined-and-sorted scope string. One entry per scope set.
static TOKEN_CACHE: Mutex<Option<HashMap<String, CachedToken>>> = Mutex::const_new(None);

fn cache_key(scopes: &[&str]) -> String {
    let mut owned: Vec<&str> = scopes.to_vec();
    owned.sort_unstable();
    owned.join(" ")
}


/// The service-account key, from the ENVIRONMENT first and a file second.
///
/// Google hands you a JSON file once; that file is absorbed into the SOPS
/// store at onboarding and never needs to exist again. Until now the
/// launcher decoded it back onto the disk at every start and bind-mounted
/// it into three containers, because this function could only read a path.
///
/// That file was measured at 0644 on the live controller: the launcher
/// wants 0640 owned by the gateway's group, cannot chgrp without being a
/// member of it, and widens rather than fail. The 0700 parent directory
/// guards it on the HOST — but the file is mounted into the container, and
/// at 0644 anything running in there can read a key that can act as the
/// Chat bot.
///
/// So: take it from the environment, where every other secret in this
/// stack already lives, and parse it in memory. The variable holds either
/// raw JSON or the base64 the store keeps it as — detected, not
/// configured, because one more flag to set wrongly is one more way for
/// this to be off.
///
/// The PATH is kept as a fallback on purpose. A gateway carrying this
/// change can run against a launcher that still materialises the file, and
/// a launcher that has stopped can run against an older gateway only if
/// the variable reaches it. Removing the file, the mounts and the 0644
/// fallback is the next step, once an image with this in it is deployed.
async fn service_account_key() -> Result<yup_oauth2::ServiceAccountKey, String> {
    const ENV_JSON: &str = "GOOGLE_CHAT_CREDENTIALS_JSON";
    const ENV_PATH: &str = "GOOGLE_CHAT_CREDENTIALS";

    // Through `secret_env`: compose delivers the key as a `/run/secrets`
    // file (`GOOGLE_CHAT_CREDENTIALS_JSON_FILE`), never as environment.
    if let Some(raw) = crate::config::secret_env::secret(ENV_JSON).map_err(|e| e.to_string())? {
        let raw = raw.trim();
        if !raw.is_empty() {
            let bytes = decode_sa_json(raw)?;
            // The error deliberately says nothing about the VALUE. A
            // malformed key is a config mistake, and a message that echoes
            // part of a private key to a log is a worse bug than the one
            // it is reporting.
            return parse_service_account_key(bytes)
                .map_err(|e| format!("${ENV_JSON} is not a service-account JSON key: {e}"));
        }
    }

    let creds_path = std::env::var(ENV_PATH).map_err(|_| {
        format!("neither ${ENV_JSON} nor ${ENV_PATH} is set — the Google service account is not configured")
    })?;
    read_service_account_key(&creds_path)
        .await
        .map_err(|e| format!("read SA key {creds_path}: {e}"))
}

/// Raw JSON or base64-wrapped JSON, whichever the variable holds.
///
/// The store keeps it base64 (one line, no quoting hazards through compose
/// interpolation); a human setting it by hand will paste the JSON. Both
/// work, and neither needs a second variable to say which.
fn decode_sa_json(raw: &str) -> Result<Vec<u8>, String> {
    if raw.starts_with('{') {
        return Ok(raw.as_bytes().to_vec());
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .map_err(|e| format!("$GOOGLE_CHAT_CREDENTIALS_JSON is neither JSON nor valid base64: {e}"))
}

/// Mint (or return cached) access token for the given scope set.
///
/// Reads `GOOGLE_CHAT_CREDENTIALS` for the SA JSON key (the env var name
/// is historical — same SA powers Chat, Drive, etc.). Token is cached
/// per scope set with a 50-min lifetime and 5-min refresh skew.
///
/// All current callers use bot-context (no DWD impersonation). If a
/// future caller needs to impersonate a Workspace user, add a
/// `subject: Option<&str>` parameter and thread it through
/// `ServiceAccountAuthenticator::builder(...).subject(...)` — the
/// pattern lived here briefly for Chat media:upload before that path
/// was abandoned in favor of Shared-Drive uploads + link in chat.
pub async fn access_token(scopes: &[&str]) -> Result<String, String> {
    if scopes.is_empty() {
        return Err("access_token requires at least one scope".to_string());
    }
    let key = cache_key(scopes);
    let mut guard = TOKEN_CACHE.lock().await;
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some(entry) = cache.get(&key) {
        if Instant::now() < entry.refresh_after {
            return Ok(entry.token.clone());
        }
    }

    let sa_key = service_account_key().await?;
    let auth = ServiceAccountAuthenticator::builder(sa_key)
        .build()
        .await
        .map_err(|e| format!("build SA authenticator: {e}"))?;
    let token_resp = auth
        .token(scopes)
        .await
        .map_err(|e| format!("token exchange for {key}: {e}"))?;
    let token_str = token_resp
        .token()
        .ok_or_else(|| "empty access token from yup-oauth2".to_string())?
        .to_string();

    let refresh_after = Instant::now() + TOKEN_LIFETIME.saturating_sub(REFRESH_SKEW);
    cache.insert(
        key,
        CachedToken {
            token: token_str.clone(),
            refresh_after,
        },
    );
    Ok(token_str)
}

/// Return an OAuth2 access token for the Google Chat bot scope.
/// Used for `messages.create` (text/markdown sends without attachments).
pub async fn chat_access_token() -> Result<String, String> {
    access_token(&[CHAT_BOT_SCOPE]).await
}

/// Return an OAuth2 access token for read-only Drive access.
/// Used by the shared-drive ingest loop.
pub async fn drive_readonly_token() -> Result<String, String> {
    access_token(&[DRIVE_READONLY_SCOPE]).await
}

/// Return an OAuth2 access token for narrow Drive write access (only
/// files the SA owns). Used by the heartbeat report-upload path: the SA
/// is a member of a Shared Drive, writes the report there, and posts a
/// link back to chat. No DWD required — the SA acts as itself.
pub async fn drive_file_token() -> Result<String, String> {
    access_token(&[DRIVE_FILE_SCOPE]).await
}

#[cfg(test)]
mod credential_source_tests {
    use super::decode_sa_json;

    /// The store holds the key base64-encoded, on one line, because that
    /// is what survives compose interpolation without quoting games.
    #[test]
    fn base64_is_decoded_to_the_json_underneath() {
        use base64::Engine as _;
        let json = r#"{"type":"service_account","project_id":"p"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        assert_eq!(decode_sa_json(&b64).unwrap(), json.as_bytes());
    }

    /// A human setting it by hand pastes the JSON. Detected, not
    /// configured — one more flag to set wrongly is one more way for a
    /// credential path to be silently off.
    #[test]
    fn raw_json_is_taken_as_it_stands() {
        let json = r#"{"type":"service_account"}"#;
        assert_eq!(decode_sa_json(json).unwrap(), json.as_bytes());
    }

    /// Neither shape: a named error, and NOT one that echoes the value.
    /// A malformed key is a config mistake; a message that prints part of
    /// a private key into a log is a worse bug than the one it reports.
    #[test]
    fn anything_else_is_refused_without_quoting_the_value() {
        let secret = "not-base64-!!! and not json";
        let err = decode_sa_json(secret).unwrap_err();
        assert!(err.contains("GOOGLE_CHAT_CREDENTIALS_JSON"), "must name the variable: {err}");
        assert!(!err.contains(secret), "the error quoted the value back: {err}");
    }
}
