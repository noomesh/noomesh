// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! CLI credential resolution.
//!
//! ## Resolution order
//!
//! 1. `--token <t>` — explicit, wins over everything (scripts, CI, one-shots).
//! 2. `NOO_TOKEN` — same, from the environment.
//! 3. The stored per-user credential (`~/.config/mesh/credentials.json`,
//!    written by `noo auth login`), refreshed in place when the short-lived
//!    access token has expired and a refresh token is stored.
//! 4. Nothing — requests go out unauthenticated and the gateway 401s, which
//!    the 401 message then explains.
//!
//! There is no fourth credential. The CLI used to offer the controller's
//! shared secret as `--break-glass` (and the onboard wizard signed with it as
//! `cli-onboard`); both were removed by design (there is no break-glass; recovery uses
//! the same path end users see), and the gateway now refuses any HMAC a
//! `noo` CLI signs. Recovery is the ordinary path, on the
//! controller host: `noo security admin-password reset` (host-level; needs no
//! login), then `noo auth login`, then `noo security pki issue-client <you>`.
//!
//! The CLI holds no HMAC signer at all: `noo skills run` goes through the
//! gateway since the earlier browser/sandbox move, so the last caller of
//! the old `cluster_token` is gone, and the function with it.
//!
//! ## Refresh (phase 2)
//!
//! Access tokens live 15 minutes; the stored refresh lives 30 days. Two
//! triggers keep the stored credential usable across that gap:
//!
//! - **On expiry** — [`resolve`] refreshes before the first request when the
//!   access token is expired or within [`credentials::REFRESH_SKEW_SECS`].
//! - **On 401** — [`refresh_after_unauthorized`], called by `http.rs` when a
//!   request comes back 401 anyway (early revocation, a rotated JWT secret, a
//!   skewed clock). **Exactly once per process**, then one retry of the same
//!   request. A 403 never triggers a refresh: that is an authorisation answer
//!   about a credential the gateway accepted, and re-minting it changes
//!   nothing.
//!
//! Refresh is serialised across processes by an advisory lock
//! ([`credentials::lock_for_refresh`]) because the gateway rotates refresh
//! tokens on use and treats a replayed revoked one as theft — see that
//! function's docs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::credentials::{self, Credentials};
use crate::Globals;

/// Which credential the CLI resolved for this process. Surfaced in the 401
/// message so an operator is never left guessing which of five possible
/// credentials the gateway just rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `--token`
    Flag,
    /// `NOO_TOKEN`
    Env,
    /// The stored per-user credential file.
    File,
    /// No credential at all.
    None,
}

impl Source {
    /// Short label for `auth status --json` and error envelopes.
    pub fn label(self) -> &'static str {
        match self {
            Source::Flag => "flag",
            Source::Env => "env",
            Source::File => "file",
            Source::None => "none",
        }
    }

    /// One human sentence naming the credential, for the 401 message.
    pub fn describe(self) -> String {
        match self {
            Source::Flag => "the token passed with --token".into(),
            Source::Env => "the token in $NOO_TOKEN".into(),
            Source::File => format!(
                "the stored credential in {}",
                credentials::credentials_path().display()
            ),
            Source::None => "no credential (none was resolved)".into(),
        }
    }

    /// What to do about a 401 with this credential.
    pub fn fix_hint(self) -> &'static str {
        match self {
            Source::Flag | Source::Env => {
                "that token is invalid or expired — run `noo auth login` and drop the override"
            }
            Source::File => {
                "the stored credential is expired or revoked — run `noo auth login` again"
            }
            Source::None => {
                "run `noo auth login` for a per-user credential (lost the password? on the \
                 controller: noo security admin-password reset)"
            }
        }
    }
}

/// A resolved credential: the header value to send, and where it came from.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub header: Option<String>,
    pub source: Source,
}

/// Resolve without side effects on the network: steps 1, 2, 4 plus the
/// stored credential AS-IS (no refresh). Split out from [`resolve`] so the
/// precedence rules are unit-testable with no gateway in the picture.
fn resolve_local(
    token_override: &Option<String>,
    stored: Option<Credentials>,
) -> (Resolved, Option<Credentials>) {
    if let Some(t) = token_override.as_ref().filter(|t| !t.is_empty()) {
        return (
            Resolved { header: Some(format!("Bearer {t}")), source: Source::Flag },
            stored,
        );
    }
    if let Ok(t) = std::env::var("NOO_TOKEN") {
        if !t.is_empty() {
            return (
                Resolved { header: Some(format!("Bearer {t}")), source: Source::Env },
                stored,
            );
        }
    }
    if let Some(c) = stored {
        return (
            Resolved {
                header: Some(format!("Bearer {}", c.access_token)),
                source: Source::File,
            },
            Some(c),
        );
    }
    (Resolved { header: None, source: Source::None }, None)
}

/// Scheme, host and port of a URL, lower-cased, without path or trailing
/// slash — what "the same gateway" means for a stored credential.
fn origin_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let hostport = rest.split('/').next().unwrap_or("").trim_end_matches('/');
    format!("{}://{}", scheme.to_ascii_lowercase(), hostport.to_ascii_lowercase())
}

/// May the credential issued by `stored_gateway` be sent to `base`?
///
/// Written for PR #99, which was reverted whole on 2026-09-11 (`413868ad`);
/// this branch carries it because the wall is wanted and the revert was
/// about #99's TLS half, not this. It is the SECOND wall and it is
/// independent of the first: even if a URL somehow reached an unverified
/// gateway, that gateway still does not get the operator's token.
/// Yes when the origins match, when the file predates the field (empty),
/// or when `base` is loopback — the box's own gateway under another name.
pub(crate) fn credential_usable_for(stored_gateway: &str, base: &str) -> bool {
    if stored_gateway.trim().is_empty() || crate::http::is_loopback(base) {
        return true;
    }
    origin_of(stored_gateway) == origin_of(base)
}

fn warn_withheld_once(issuer: &str, base: &str) {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if std::env::var("NOO_AUTH_QUIET").map(|v| v == "1").unwrap_or(false) {
        return;
    }
    WARNED.get_or_init(|| {
        eprintln!(
            "note: the stored credential was issued by {issuer}, not {base} — not sending it there; \
             `noo auth login` against {base}, or `--gateway {issuer}`"
        );
    });
}

/// The resolution answer for this process. Not a `OnceLock`: a successful
/// refresh-on-401 replaces it, so later requests in the same command carry the
/// new token instead of the one the gateway just rejected.
fn cache() -> &'static Mutex<Option<Resolved>> {
    static CACHE: std::sync::OnceLock<Mutex<Option<Resolved>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

/// Why the last refresh attempt failed, verbatim, for the 401 message. An
/// operator who is told only "401" cannot tell an expired refresh from a
/// revoked one from a disabled account.
fn last_refresh_error() -> &'static Mutex<Option<String>> {
    static E: std::sync::OnceLock<Mutex<Option<String>>> = std::sync::OnceLock::new();
    E.get_or_init(|| Mutex::new(None))
}

fn set_refresh_error(msg: String) {
    if let Ok(mut slot) = last_refresh_error().lock() {
        *slot = Some(msg);
    }
}

/// The reason the automatic refresh failed this process, if it did. Rendered
/// by `http.rs::auth_failed` so a 401 on the stored credential says *why* the
/// CLI could not fix it itself.
pub fn refresh_failure() -> Option<String> {
    last_refresh_error().lock().ok().and_then(|s| s.clone())
}

/// True when `--token`/`$NOO_TOKEN` outrank the stored credential, so the file
/// is not the credential we'd send and refreshing it would be pointless.
fn token_overridden(g: &Globals) -> bool {
    g.token.as_ref().is_some_and(|t| !t.is_empty())
        || std::env::var("NOO_TOKEN").map(|t| !t.is_empty()).unwrap_or(false)
}

/// Full resolution, including a refresh round-trip when the stored access
/// token is stale. Computed once per process (a single `noo` invocation talks
/// to one gateway) so a multi-request command doesn't refresh repeatedly.
pub fn resolve(g: &Globals) -> Resolved {
    if let Ok(slot) = cache().lock() {
        if let Some(r) = slot.as_ref() {
            return r.clone();
        }
    }
    crate::envfile::ensure_repo_env();

    let mut stored = credentials::load();
    // The stored credential goes only to the gateway that issued it
    // A checkout's `.env` — or anything else — that
    // points this process at another host does not get to spend it, and
    // does not get to spend the REFRESH token either: the check comes
    // before the refresh. Loopback is exempt: the controller answers to
    // `localhost` on its own box and to its tailnet name from everywhere
    // else, and that is the same gateway (host8, 2026-09-05).
    let base = crate::envfile::gateway_url(&g.gateway_override);
    if let Some(c) = stored.as_ref() {
        if !credential_usable_for(&c.gateway, &base) {
            warn_withheld_once(&c.gateway, &base);
            stored = None;
        }
    }
    // Refresh only matters when the file is the credential we'd actually use.
    if !token_overridden(g) {
        if let Some(c) = stored.clone() {
            let now = credentials::now_secs();
            if c.access_stale_at(now) {
                stored = match refresh_locked(g, None) {
                    Ok(updated) => Some(updated),
                    Err(why) => {
                        set_refresh_error(why);
                        None
                    }
                };
            }
        }
    }

    let (resolved, _) = resolve_local(&g.token, stored);
    if let Ok(mut slot) = cache().lock() {
        *slot = Some(resolved.clone());
    }
    resolved
}

/// Refresh after a request came back **401**, for `http.rs` to retry with.
///
/// Returns the new `Authorization` header value, or `None` when there is
/// nothing to do (the credential in play is not the stored one, no refresh
/// token, the refresh was rejected). At most **one** attempt per process: a
/// second 401 after a successful refresh is the gateway's real answer about a
/// freshly-minted token, and retrying again could only loop.
pub fn refresh_after_unauthorized(g: &Globals) -> Option<String> {
    static ATTEMPTED: AtomicBool = AtomicBool::new(false);

    let current = resolve(g);
    // Only the stored credential is refreshable. An explicit --token/$NOO_TOKEN
    // is the caller's to manage.
    if current.source != Source::File || token_overridden(g) {
        return None;
    }
    if ATTEMPTED.swap(true, Ordering::SeqCst) {
        return None;
    }
    let sent = current
        .header
        .as_deref()
        .and_then(|h| h.strip_prefix("Bearer "))?
        .to_string();

    let updated = match refresh_locked(g, Some(&sent)) {
        Ok(c) => c,
        Err(why) => {
            set_refresh_error(why);
            return None;
        }
    };
    if updated.access_token == sent {
        // Nothing changed — resending the same rejected token is not a retry.
        return None;
    }
    let header = format!("Bearer {}", updated.access_token);
    if let Ok(mut slot) = cache().lock() {
        *slot = Some(Resolved { header: Some(header.clone()), source: Source::File });
    }
    Some(header)
}

/// The `Authorization` header value for gateway requests, or `None`.
pub fn bearer(g: &Globals) -> Option<String> {
    resolve(g).header
}

/// Drop this process's cached resolution, so the next request resolves
/// again. For a command that LOGS IN mid-process (the onboard wizard): a
/// request made before the login cached "no credential", and without this
/// every later request in the same run kept sending nothing.
pub(crate) fn forget_resolution() {
    if let Ok(mut slot) = cache().lock() {
        *slot = None;
    }
}

/// Which credential this process is using — for the 401 message.
pub fn source(g: &Globals) -> Source {
    resolve(g).source
}

/// How long to wait for another `noo` process to finish its refresh before
/// giving up. Generous: the round trip is one HTTP call, and waiting is always
/// better than double-spending a single-use refresh token.
const REFRESH_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// Exchange the stored refresh token for a new access token via
/// `POST /api/auth/refresh`, persisting the rotated pair.
///
/// `sent` is the access token a request just had rejected with a 401 (the
/// refresh-on-401 path), or `None` when we are refreshing because the stored
/// token is expiring (the pre-request path). Either way the check that decides
/// whether to spend the refresh token is re-made *under the lock*, against the
/// file as it is on disk — that is what makes two concurrent `noo` processes
/// safe:
///
/// - the winner refreshes and writes the rotated pair;
/// - the loser wakes up, sees a credential that is no longer the one it was
///   about to replace, and uses it **without** a second refresh call.
///
/// This matters more than an ordinary file race because the gateway rotates
/// refresh tokens on use and revokes the user's whole chain when a revoked one
/// is replayed — a naive race logs the operator out of every session.
///
/// The gateway hands the refresh out as an httpOnly cookie; a CLI has no
/// cookie jar, so we replay the stored value as a `Cookie:` header and read
/// the rotated one back out of `Set-Cookie`.
///
/// `Err` carries a sentence naming what failed, which the 401 message prints.
fn refresh_locked(g: &Globals, sent: Option<&str>) -> Result<Credentials, String> {
    // A lock we cannot take is not a reason to skip refreshing — but it IS a
    // reason to say so, because the alternative (silently double-spending)
    // ends in a chain-wide revoke.
    let _lock = credentials::lock_for_refresh(REFRESH_LOCK_WAIT)
        .map_err(|e| format!("could not serialise the refresh: {e}"))?;

    let disk = credentials::load()
        .ok_or_else(|| format!("no stored credential at {}", credentials::credentials_path().display()))?;
    let now = credentials::now_secs();

    // Double-check under the lock: has another process already rotated this?
    let superseded = match sent {
        // 401 path: any token other than the one that was rejected is newer.
        Some(s) => disk.access_token != s,
        // Expiry path: someone else refreshed if the file is no longer stale.
        None => !disk.access_stale_at(now),
    };
    if superseded {
        return Ok(disk);
    }

    if disk.refresh_token.is_none() {
        return Err("no refresh token is stored (the gateway issued none at login)".into());
    }
    if !disk.refresh_usable_at(now) {
        return Err(format!(
            "the stored refresh token expired at unix {} (30-day lifetime)",
            disk.refresh_expires_at.unwrap_or(0)
        ));
    }
    let raw = disk.refresh_token.clone().unwrap_or_default();

    let base = crate::envfile::gateway_url(&g.gateway_override);
    let agent = crate::http::agent(g, &base, 15);
    let mut resp = agent
        .post(format!("{base}/api/auth/refresh"))
        .header("Cookie", format!("{}={raw}", REFRESH_COOKIE_NAME))
        .send_empty()
        .map_err(|e| format!("could not reach {base}/api/auth/refresh: {e}"))?;
    let status = resp.status().as_u16();
    let set_cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let body_text = resp.body_mut().read_to_string().unwrap_or_default();
    if !(200..=299).contains(&status) {
        let detail = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .and_then(|v| v["detail"].as_str().map(str::to_string))
            .unwrap_or_else(|| body_text.trim().to_string());
        return Err(format!(
            "the gateway rejected the stored refresh token (HTTP {status}{})",
            if detail.is_empty() { String::new() } else { format!(": {detail}") }
        ));
    }
    let body: serde_json::Value = serde_json::from_str(&body_text)
        .map_err(|_| "the gateway's refresh response was not JSON".to_string())?;
    let updated = apply_refresh(&disk, &body, &set_cookie, now)
        .ok_or_else(|| "the gateway's refresh response carried no access_token".to_string())?;
    // A failed write is not fatal — the in-memory token still works for this
    // command; the next invocation just refreshes again.
    if let Err(e) = credentials::save(&updated) {
        eprintln!("warning: could not update {}: {e}", credentials::credentials_path().display());
    }
    Ok(updated)
}

/// The gateway's refresh cookie name (`auth_refresh::REFRESH_COOKIE_NAME`).
const REFRESH_COOKIE_NAME: &str = "noo_refresh";

/// Pure merge of a refresh response into the stored credential — no I/O, so
/// the Set-Cookie parsing and expiry arithmetic are unit-testable.
fn apply_refresh(
    prev: &Credentials,
    body: &serde_json::Value,
    set_cookie: &[String],
    now: u64,
) -> Option<Credentials> {
    let access_token = body["access_token"].as_str()?.to_string();
    if access_token.is_empty() {
        return None;
    }
    let expires_in = body["expires_in"].as_u64().unwrap_or(900);
    let mut out = prev.clone();
    out.access_token = access_token;
    out.expires_at = now.saturating_add(expires_in);
    if let Some(rotated) = cookie_value(set_cookie, REFRESH_COOKIE_NAME) {
        if !rotated.is_empty() {
            out.refresh_token = Some(rotated);
            // The gateway does not report the refresh TTL on this path; keep
            // whatever ceiling we already knew rather than inventing one.
        }
    }
    Some(out)
}

/// Extract `name`'s value from a set of `Set-Cookie` header values.
fn cookie_value(set_cookie: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    set_cookie.iter().find_map(|h| {
        h.split(';')
            .next()
            .map(str::trim)
            .and_then(|first| first.strip_prefix(&prefix))
            .map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn globals(token: Option<&str>) -> Globals {
        Globals {
            json: false,
            verbose: false,
            gateway_override: None,
            timeout_secs: None,
            token: token.map(str::to_string),
            quiet: false,
        }
    }

    /// PINNED: a credential travels only to its issuer.
    /// Originally PR #99's; kept here after that PR was reverted.
    #[test]
    fn stored_credentials_are_bound_to_their_issuer() {
        let issuer = "https://noo-controller.example.ts.net:8080";
        assert!(credential_usable_for(issuer, issuer));
        assert!(credential_usable_for(issuer, "https://NOO-Controller.example.ts.net:8080/"));
        assert!(credential_usable_for(issuer, "https://localhost:8080"), "loopback is the same box");
        assert!(credential_usable_for("", "https://anywhere.example:8080"), "a pre-field file is not withheld");
        assert!(!credential_usable_for(issuer, "https://evil.example:8080"));
        assert!(!credential_usable_for(issuer, "http://noo-controller.example.ts.net:8080"), "scheme is part of the origin");
        assert!(!credential_usable_for(issuer, "https://noo-controller.example.ts.net:9080"), "so is the port");
        assert!(!credential_usable_for(issuer, "https://localhost.evil.example:8080"));
    }

    fn creds(access: &str) -> Credentials {
        Credentials {
            gateway: "http://localhost:8080".into(),
            subject: "alice".into(),
            scopes: vec!["admin".into()],
            access_token: access.into(),
            expires_at: u64::MAX,
            refresh_token: Some("r".into()),
            refresh_expires_at: None,
        }
    }

    /// `NOO_TOKEN` and the secrets are process-global; serialise the tests
    /// that set them.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// By design, no break-glass. A box holding the
    /// controller secret, the fleet secret and the old opt-in still resolves
    /// NOTHING without a login — the shared secret is never a CLI credential.
    #[test]
    fn a_shared_secret_is_never_a_credential() {
        let _g = env_lock();
        std::env::remove_var("NOO_TOKEN");
        std::env::set_var("NOO_CLUSTER_SECRET", "s");
        std::env::set_var("NOO_CONTROLLER_SECRET", "c");
        std::env::set_var("NOO_BREAK_GLASS", "1");
        let (r, _) = resolve_local(&None, None);
        assert_eq!(r.source, Source::None);
        assert!(r.header.is_none(), "{:?}", r.header);
        for k in ["NOO_CLUSTER_SECRET", "NOO_CONTROLLER_SECRET", "NOO_BREAK_GLASS"] {
            std::env::remove_var(k);
        }
    }

    /// The removal is in the code, not only in the docs: nothing in the CLI
    /// reads the controller secret to sign a request, and no actor the
    /// gateway now refuses is spelled anywhere outside a test.
    #[test]
    fn no_cli_code_signs_with_the_controller_secret() {
        for (name, src) in [
            ("auth.rs", include_str!("auth.rs")),
            ("http.rs", include_str!("http.rs")),
            ("main.rs", include_str!("main.rs")),
            ("onboard/steps.rs", include_str!("onboard/steps.rs")),
            ("commands/security.rs", include_str!("commands/security.rs")),
            ("commands/pki.rs", include_str!("commands/pki.rs")),
            ("commands/upgrade.rs", include_str!("commands/upgrade.rs")),
            ("host_access.rs", include_str!("host_access.rs")),
        ] {
            let code = src.split("#[cfg(test)]").next().unwrap();
            for needle in ["\"cli-onboard\"", "\"cli-break-glass\"", "\"cli-posture\"", "NOO_BREAK_GLASS\")", "shared_secret_bearer", "HMAC_ACTOR_"] {
                assert!(!code.contains(needle), "{name} still carries {needle}");
            }
        }
        let code = include_str!("auth.rs").split("#[cfg(test)]").next().unwrap();
        assert!(!code.contains("NOO_CONTROLLER_SECRET"), "auth.rs must not read the controller secret");
    }

    /// The CLI signs nothing with a shared secret: there is no HMAC signer
    /// anywhere in its source. A signer coming back (an onboard step, a
    /// posture write, a recovery command, a node-agent call) is the shared
    /// secret coming back.
    #[test]
    fn the_cli_has_no_hmac_signer() {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push((p.display().to_string(), std::fs::read_to_string(&p).unwrap()));
                }
            }
        }
        let mut files = Vec::new();
        walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        let mut signers = Vec::new();
        for (name, src) in &files {
            for needle in ["Hmac::<", "hmac::", "cluster_token("] {
                // Every line, test modules included, except this test's own
                // needle list and the comments that name the removed function.
                for (i, line) in src.lines().enumerate() {
                    let t = line.trim_start();
                    if t.starts_with("//") || t.contains("for needle in [") {
                        continue;
                    }
                    if line.contains(needle) {
                        signers.push(format!("{name}:{}: {}", i + 1, line.trim()));
                    }
                }
            }
        }
        assert!(signers.is_empty(), "an HMAC signer in the CLI: {signers:#?}");
    }

    #[test]
    fn explicit_flag_beats_env_file_and_hmac() {
        let _g = env_lock();
        std::env::set_var("NOO_TOKEN", "from-env");
        std::env::set_var("NOO_CLUSTER_SECRET", "s");
        let (r, _) = resolve_local(&globals(Some("from-flag")).token, Some(creds("from-file")));
        assert_eq!(r.source, Source::Flag);
        assert_eq!(r.header.unwrap(), "Bearer from-flag");
        std::env::remove_var("NOO_TOKEN");
        std::env::remove_var("NOO_CLUSTER_SECRET");
    }

    #[test]
    fn env_beats_file_and_hmac() {
        let _g = env_lock();
        std::env::set_var("NOO_TOKEN", "from-env");
        std::env::set_var("NOO_CLUSTER_SECRET", "s");
        let (r, _) = resolve_local(&None, Some(creds("from-file")));
        assert_eq!(r.source, Source::Env);
        assert_eq!(r.header.unwrap(), "Bearer from-env");
        std::env::remove_var("NOO_TOKEN");
        std::env::remove_var("NOO_CLUSTER_SECRET");
    }

    #[test]
    fn file_beats_hmac() {
        let _g = env_lock();
        std::env::remove_var("NOO_TOKEN");
        std::env::set_var("NOO_CLUSTER_SECRET", "s");
        let (r, _) = resolve_local(&None, Some(creds("from-file")));
        assert_eq!(r.source, Source::File);
        assert_eq!(r.header.unwrap(), "Bearer from-file");
        std::env::remove_var("NOO_CLUSTER_SECRET");
    }

    #[test]
    fn empty_overrides_are_ignored() {
        // `--token ""` / `NOO_TOKEN=` are configuration mistakes, not a
        // request to authenticate as the empty string.
        let _g = env_lock();
        std::env::set_var("NOO_TOKEN", "");
        std::env::remove_var("NOO_CLUSTER_SECRET");
        let (r, _) = resolve_local(&Some(String::new()), Some(creds("from-file")));
        assert_eq!(r.source, Source::File);
        std::env::remove_var("NOO_TOKEN");
    }

    #[test]
    fn refresh_response_updates_access_token_and_rotates_cookie() {
        let prev = creds("old");
        let body = serde_json::json!({"access_token": "new", "expires_in": 900});
        let cookies = vec![
            "other=x; Path=/".to_string(),
            "noo_refresh=rotated; HttpOnly; Path=/api/auth; Max-Age=2592000".to_string(),
        ];
        let out = apply_refresh(&prev, &body, &cookies, 1_000).unwrap();
        assert_eq!(out.access_token, "new");
        assert_eq!(out.expires_at, 1_900);
        assert_eq!(out.refresh_token.as_deref(), Some("rotated"));
        assert_eq!(out.subject, prev.subject, "identity fields survive a refresh");
    }

    #[test]
    fn refresh_without_a_new_cookie_keeps_the_old_refresh_token() {
        let prev = creds("old");
        let body = serde_json::json!({"access_token": "new"});
        let out = apply_refresh(&prev, &body, &[], 1_000).unwrap();
        assert_eq!(out.refresh_token.as_deref(), Some("r"));
        assert_eq!(out.expires_at, 1_900, "default 15-minute access TTL");
    }

    #[test]
    fn refresh_rejects_a_body_with_no_access_token() {
        let prev = creds("old");
        assert!(apply_refresh(&prev, &serde_json::json!({"detail": "nope"}), &[], 1).is_none());
        assert!(apply_refresh(&prev, &serde_json::json!({"access_token": ""}), &[], 1).is_none());
    }

    #[test]
    fn every_source_names_itself_and_a_fix() {
        for s in [Source::Flag, Source::Env, Source::File, Source::None] {
            assert!(!s.label().is_empty());
            assert!(!s.describe().is_empty());
            assert!(s.fix_hint().contains("noo auth login"));
        }
    }
}
