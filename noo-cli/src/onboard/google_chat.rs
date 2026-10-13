// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Google Chat discovery from the service-account key (2026-09-02).
//!
//! The wizard used to take the SA key and stop: the Pub/Sub subscription
//! the gateway pulls Chat events from was never asked for, so inbound Chat
//! silently never started after a fresh walk (host8). The key already
//! names the project and can mint its own token, so everything the
//! adapter needs is discoverable: the project id, the project's
//! subscriptions, and the spaces the bot is a member of.
//!
//! Signing: the JWT-bearer grant needs an RS256 signature and this crate
//! carries no RSA implementation — `openssl dgst -sha256 -sign` does it
//! (openssl is already a hard dependency of `noo migrate`). The private
//! key touches disk only as a 0600 file in a 0700 temp dir, removed
//! before this returns.

use super::Ctx;
use super::yamlcfg;
use base64::Engine;
use serde_json::Value;
use std::io::Write;
use std::path::Path;

const PUBSUB_SCOPE: &str = "https://www.googleapis.com/auth/pubsub";
const CHAT_SCOPE: &str = "https://www.googleapis.com/auth/chat.bot";

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The SA key JSON: the plaintext file the operator just named, or the
/// absorbed copy in the encrypted store (reconfigure after fu76 absorb).
pub fn load_sa_key(ctx: &Ctx, key_file: &str) -> Option<Value> {
    if !key_file.is_empty() && Path::new(key_file).is_file() {
        if let Ok(text) = std::fs::read_to_string(key_file) {
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                return Some(v);
            }
        }
    }
    let store = ctx.repo_root.join("secrets/env.sops");
    if !store.is_file() {
        return None;
    }
    let loaded = crate::commands::secrets::SecretStore::load_sops(&store).ok()?;
    let b64 = loaded.get("NOO_FILECRED_GOOGLE_CHAT_B64")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Mint a short-lived access token for `scope` from the SA key
/// (JWT-bearer grant, RS256 via openssl).
pub fn access_token(key: &Value, scope: &str) -> Result<String, String> {
    let email = key["client_email"].as_str().ok_or("SA key has no client_email")?;
    let pem = key["private_key"].as_str().ok_or("SA key has no private_key")?;
    let token_uri = key["token_uri"].as_str().unwrap_or("https://oauth2.googleapis.com/token");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "iss": email, "scope": scope, "aud": token_uri, "iat": now, "exp": now + 600,
    });
    let claims = b64url(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{claims}");

    // Sign with openssl; key on disk only inside a private temp dir.
    let dir = std::env::temp_dir().join(format!("noo-gsa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("temp dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let key_path = dir.join("key.pem");
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&key_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(pem.as_bytes())
    })();
    let signed = write.map_err(|e| format!("temp key: {e}")).and_then(|_| {
        let mut child = std::process::Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(&key_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("openssl not runnable: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = crate::child_stdin::write_child_stdin(&mut stdin, signing_input.as_bytes());
        }
        let out = child.wait_with_output().map_err(|e| format!("openssl: {e}"))?;
        if !out.status.success() || out.stdout.is_empty() {
            return Err("openssl could not sign with the SA private key (malformed key JSON?)".into());
        }
        Ok(out.stdout)
    });
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&dir);
    let signature = signed?;
    let jwt = format!("{signing_input}.{}", b64url(&signature));

    let mut resp = agent()
        .post(token_uri)
        .send_form([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", jwt.as_str()),
        ])
        .map_err(|e| format!("token request: {e}"))?;
    let body: Value = serde_json::from_str(
        &resp.body_mut().read_to_string().map_err(|e| format!("token body: {e}"))?,
    )
    .map_err(|e| format!("token json: {e}"))?;
    body["access_token"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("no access_token in response: {}", body["error_description"].as_str().unwrap_or("?")))
}

/// An agent that hands 4xx/5xx bodies back instead of turning them into
/// "http status: 403": Google's error JSON says WHY (API not enabled vs
/// permission denied vs unknown name), and the operator needs that text.
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .into()
}

fn get_json(token: &str, url: &str) -> Result<Value, String> {
    let mut resp = agent()
        .get(url)
        .header("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().map_err(|e| format!("body: {e}"))?;
    let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({}));
    if status >= 400 {
        let msg = body["error"]["message"].as_str().unwrap_or(text.trim()).to_string();
        return Err(format!("HTTP {status}: {msg}"));
    }
    Ok(body)
}

/// `projects/<p>/subscriptions/<name>` for every subscription in the project.
pub fn list_subscriptions(token: &str, project: &str) -> Result<Vec<String>, String> {
    let body = get_json(token, &format!("https://pubsub.googleapis.com/v1/projects/{project}/subscriptions"))?;
    if let Some(err) = body.get("error") {
        return Err(err["message"].as_str().unwrap_or("pubsub error").to_string());
    }
    Ok(body["subscriptions"]
        .as_array()
        .map(|a| a.iter().filter_map(|s| s["name"].as_str().map(str::to_string)).collect())
        .unwrap_or_default())
}

/// Fetch one subscription by full name — `roles/pubsub.subscriber` on the
/// subscription allows `get` even when project-level `list` is refused.
pub fn get_subscription(token: &str, full_name: &str) -> Result<Value, String> {
    let body = get_json(token, &format!("https://pubsub.googleapis.com/v1/{full_name}"))?;
    if let Some(err) = body.get("error") {
        return Err(err["message"].as_str().unwrap_or("pubsub error").to_string());
    }
    Ok(body)
}

/// `(spaces/<id>, display name)` for every space the bot is a member of.
pub fn list_spaces(token: &str) -> Result<Vec<(String, String)>, String> {
    let body = get_json(token, "https://chat.googleapis.com/v1/spaces?pageSize=100")?;
    if let Some(err) = body.get("error") {
        return Err(err["message"].as_str().unwrap_or("chat error").to_string());
    }
    Ok(body["spaces"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| {
                    let name = s["name"].as_str()?.to_string();
                    let display = s["displayName"].as_str().unwrap_or("").to_string();
                    Some((name, display))
                })
                .collect()
        })
        .unwrap_or_default())
}

/// The wizard step: discover project + subscription (+ spaces, shown for
/// the team link), write the non-secret ids to `compose_env`, report.
/// Returns true when the subscription is configured.
pub fn discover(ctx: &mut Ctx, key_file: &str) -> bool {
    let Some(key) = load_sa_key(ctx, key_file) else {
        ctx.warn("Could not read the service-account key (file or encrypted store) — Pub/Sub not configured.");
        return false;
    };
    let project = key["project_id"].as_str().unwrap_or("").to_string();
    if project.is_empty() {
        ctx.warn("SA key carries no project_id — Pub/Sub not configured.");
        return false;
    }
    let current = yamlcfg::read_yaml_compose_env(ctx, "GOOGLE_CHAT_PUBSUB_SUBSCRIPTION");
    // Name the principal: IAM grants go to THIS email, and "which service
    // account is the key?" was the question on host8 (2026-09-02).
    ctx.info(&format!(
        "Service account: {} (grant roles to this principal; guide: docs/channels/google-chat.md)",
        key["client_email"].as_str().unwrap_or("?")
    ));
    ctx.progress(&format!("Discovering Pub/Sub subscriptions in project {project} with the key's own credentials..."));
    let token = match access_token(&key, PUBSUB_SCOPE) {
        Ok(t) => t,
        Err(e) => {
            ctx.warn(&format!("Could not mint a Pub/Sub token from the SA key: {e}"));
            ctx.info("Set it by hand: noo config set compose_env '{\"GOOGLE_CHAT_PUBSUB_SUBSCRIPTION\":\"projects/<p>/subscriptions/<n>\"}'");
            return false;
        }
    };
    let subs = match list_subscriptions(&token, &project) {
        Ok(s) => s,
        Err(e) => {
            // Listing needs project-level Pub/Sub Viewer; the usual SA has
            // only subscriber on ITS subscription (host8 2026-09-02: 403).
            // Subscriber still allows `get`, so ask for the name and verify.
            ctx.warn(&format!("Subscription list refused: {e}"));
            ctx.info("Grant the service account \"Pub/Sub Viewer\" on the project to make this automatic, or name the subscription:");
            ctx.raw(&format!("    https://console.cloud.google.com/cloudpubsub/subscription/list?project={project}"));
            let default_name = current
                .as_deref()
                .and_then(|c| c.rsplit('/').next())
                .unwrap_or("")
                .to_string();
            let a = ctx.asker.ask(&super::prompt::Prompt::new("Subscription name (blank = skip)").default(default_name));
            let name = a.trim().trim_start_matches(&format!("projects/{project}/subscriptions/")).to_string();
            if name.is_empty() {
                ctx.info("Pub/Sub not configured — inbound Chat stays off until it is.");
                return false;
            }
            let full = format!("projects/{project}/subscriptions/{name}");
            match get_subscription(&token, &full) {
                Ok(sub) => {
                    ctx.success(&format!("Subscription verified: {full} (topic {})", sub["topic"].as_str().unwrap_or("?")));
                    vec![full]
                }
                Err(e) => {
                    ctx.warn(&format!("Subscription {full} not readable with this key: {e}"));
                    return false;
                }
            }
        }
    };
    let chosen = match subs.len() {
        0 => {
            ctx.warn(&format!("No Pub/Sub subscriptions in project {project}. Create one on the topic your Chat app publishes to:"));
            ctx.raw(&format!("    https://console.cloud.google.com/cloudpubsub/subscription/list?project={project}"));
            return false;
        }
        1 => {
            ctx.success(&format!("One subscription found: {}", subs[0]));
            subs[0].clone()
        }
        _ => {
            ctx.info("Several subscriptions — pick the one attached to the Chat app's topic:");
            for (i, s) in subs.iter().enumerate() {
                ctx.raw(&format!("    {}. {s}", i + 1));
            }
            let default_idx = subs
                .iter()
                .position(|s| Some(s.as_str()) == current.as_deref())
                .map(|i| (i + 1).to_string())
                .unwrap_or_else(|| "1".to_string());
            let a = ctx.asker.ask(&super::prompt::Prompt::new("Subscription (number)").default(default_idx));
            match a.trim().parse::<usize>() {
                Ok(n) if n >= 1 && n <= subs.len() => subs[n - 1].clone(),
                _ => {
                    ctx.warn("No subscription chosen — Pub/Sub not configured.");
                    return false;
                }
            }
        }
    };
    yamlcfg::update_yaml_compose_env(
        ctx,
        &[
            ("GOOGLE_CHAT_PUBSUB_SUBSCRIPTION".to_string(), chosen.clone()),
            ("GOOGLE_CHAT_PROJECT_ID".to_string(), project.clone()),
        ],
    );
    ctx.success(&format!("Google Chat inbound: {chosen} (noomesh.yaml compose_env)"));

    // Spaces are informational here: the ids feed `noo security team
    // link-space` once the space→team scope has a runtime reader.
    match access_token(&key, CHAT_SCOPE).and_then(|t| list_spaces(&t)) {
        Ok(spaces) if !spaces.is_empty() => {
            ctx.info(&format!("The bot is a member of {} space(s):", spaces.len()));
            for (name, display) in spaces.iter().take(20) {
                ctx.raw(&format!("    {name}  {display}"));
            }
        }
        Ok(_) => ctx.info("The bot is not a member of any space yet — add it to a space in Google Chat."),
        Err(e) => ctx.info(&format!("(space list unavailable: {e})")),
    }
    true
}
