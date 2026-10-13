// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo auth login / status / logout` — per-user CLI credentials.
//!
//! These commands are pure
//! clients of endpoints the gateway ALREADY serves (`POST /auth/token`,
//! `GET /auth/me`, `POST /api/auth/logout`) — nothing gateway-side changed,
//! and nothing about inter-node or node-agent auth is touched.

use serde_json::{json, Value};

use crate::credentials::{self, Credentials};
use crate::envfile;
use crate::http::agent;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Glyph};
use crate::{Globals, Unhandled};

const TIMEOUT: u64 = 20;

/// Read one secret line with echo disabled (getpass parity). Prompt goes to
/// stderr so `--json` stdout stays clean. Mirrors `security.rs::prompt_secret`.
fn prompt_secret(label: &str) -> String {
    use std::io::{BufRead as _, Write as _};
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let fd = 0;
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let have_termios = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let saved = term;
    if have_termios {
        term.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    if have_termios {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        eprintln!();
    }
    line.trim_end_matches(['\n', '\r']).to_string()
}

/// Read one plain line from the terminal (username prompt).
fn prompt_line(label: &str) -> String {
    use std::io::{BufRead as _, Write as _};
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line.trim_end_matches(['\n', '\r']).to_string()
}

/// `noo auth login [username] [--username U] [--password-stdin]`
///
/// POSTs to the gateway's `/auth/token` and stores the returned access token
/// (plus the refresh cookie the gateway sets) in the per-user credential file.
///
/// Agent-first contract, same as `security user create`: `--password-stdin`
/// reads one line; `--json` without it refuses to prompt; a non-TTY stdin
/// errors instead of blocking on a pipe.
pub fn auth_login(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut username: Option<String> = None;
    let mut password_stdin = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--username" | "-u" => username = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--password-stdin" => password_stdin = true,
            s if !s.starts_with('-') && username.is_none() => username = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }

    let username = match username {
        Some(u) => u,
        None => {
            if g.json || unsafe { libc::isatty(0) } != 1 {
                fail(
                    g.json,
                    ExitCode::Usage,
                    "username_required",
                    "no username given and stdin is not a TTY to prompt on",
                    Some("noo auth login <username> --password-stdin"),
                );
            }
            prompt_line("Username: ")
        }
    };

    let password = if password_stdin {
        use std::io::BufRead as _;
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        line.trim_end_matches(['\n', '\r']).to_string()
    } else if g.json {
        fail(
            true,
            ExitCode::Usage,
            "password_required",
            "refusing to prompt for a password in --json mode",
            Some("pipe it via --password-stdin (one line)"),
        );
    } else if unsafe { libc::isatty(0) } != 1 {
        fail(
            false,
            ExitCode::Usage,
            "password_required",
            "stdin is not a TTY — cannot prompt for a password",
            Some("pipe it via --password-stdin (one line)"),
        );
    } else {
        prompt_secret("Password: ")
    };

    let base = envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}/auth/token");
    if g.verbose {
        eprintln!("POST {url}");
    }
    // NOTE: no Authorization header — /auth/ is a public prefix on the
    // gateway (it must be reachable before you have a token).
    let mut resp = match agent(g, &base, TIMEOUT)
        .post(&url)
        .send_json(json!({"username": username, "password": password}))
    {
        Ok(r) => r,
        Err(e) => crate::http::fail_send(g, &base, &e, TIMEOUT),
    };
    let status = resp.status().as_u16();
    let set_cookie: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if status == 401 || status == 403 {
        fail(
            g.json,
            ExitCode::AuthFailed,
            "auth_failed",
            &format!("gateway rejected the login for '{username}'"),
            Some(&format!("check the username/password; an operator can reset it with `noo security user set-password {username}`")),
        );
    }
    if !(200..=299).contains(&status) {
        fail(
            g.json,
            ExitCode::RemoteError,
            "remote_error",
            &format!("gateway returned {status} for /auth/token: {text}"),
            None,
        );
    }
    let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| {
        fail(
            g.json,
            ExitCode::Generic,
            "bad_response",
            "gateway returned a non-JSON body from /auth/token",
            None,
        )
    });

    let creds = build_credentials(&base, &username, &body, &set_cookie, credentials::now_secs())
        .unwrap_or_else(|| {
            fail(
                g.json,
                ExitCode::Generic,
                "bad_response",
                "gateway login response carried no access_token",
                None,
            )
        });

    // Fill in the scopes the gateway actually granted (the token response
    // doesn't carry them; /auth/me does). Best-effort: a login is still a
    // login if this probe fails.
    let mut creds = creds;
    if let Some(scopes) = fetch_scopes(g, &base, &creds.access_token) {
        creds.scopes = scopes;
    }

    let path = match credentials::save(&creds) {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "credential_write_failed", &e, None),
    };

    if g.json {
        println!(
            "{}",
            json!({
                "status": "ok",
                "subject": creds.subject,
                "scopes": creds.scopes,
                "gateway": creds.gateway,
                "expires_at": creds.expires_at,
                "credentials_file": path.display().to_string(),
            })
        );
    } else {
        ui::done(&format!("logged in as {} on {}", creds.subject, creds.gateway));
        print!("{}", ui::kv(&[
            ("scopes", scopes_or_unknown(&creds.scopes)),
            ("stored", format!("{}  {}", path.display(), ui::muted("0600"))),
        ]));
        if creds.refresh_token.is_none() {
            ui::warned(&format!(
                "the gateway issued no refresh token: this credential expires in {} min and you will need to log in again",
                (creds.expires_at.saturating_sub(credentials::now_secs())) / 60
            ));
        }
        ui::guide(&[
            ("noo auth status", "shows the stored credential, its scopes and expiry"),
            ("noo whoami", "what this box is and which gateway you are talking to"),
        ]);
    }
    Ok(0)
}

/// `noo auth status` — which credential would this process use, and is it live?
///
/// Deliberately works offline: the resolution answer (source + subject +
/// expiry) comes from local state, and the gateway probe is best-effort so
/// `auth status` still explains itself when the gateway is down.
pub fn auth_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let (base, base_from) = envfile::gateway_url_source(&g.gateway_override);
    // Where the config came from and what verifies the transport. `noo auth
    // status` is the one place an operator can ask "which credential, which
    // URL, which CA, from where" and get all four — the three used to be
    // resolved silently in three different files.
    let (cfg_root, cfg_root_from) = envfile::repo_root_source();
    let trust = crate::http::resolve_trust(&base);
    let ignored = envfile::ignored_config_notes();
    // Resolve FIRST: resolution may refresh an expiring credential, and status
    // must describe the file as it is after that, not the state it replaced.
    let resolved = crate::auth::resolve(g);
    let stored = credentials::load();
    let source = resolved.source;
    let now = credentials::now_secs();

    // Best-effort identity probe with whatever credential resolution picked.
    let me = resolved.header.as_ref().and_then(|h| fetch_me(g, &base, h));

    if g.json {
        let mut out = json!({
            "source": source.label(),
            "credential": source.describe(),
            "gateway": base,
            "gateway_source": base_from.label(),
            "gateway_source_detail": base_from.describe(),
            "authenticated": me.is_some(),
            "config_root": cfg_root.display().to_string(),
            "config_root_source": cfg_root_from.label(),
            "config_root_detail": cfg_root_from.describe(),
            "tls_trust": match &trust {
                Ok(t) => json!(t.label()),
                Err(_) => json!("none"),
            },
            "tls_trust_detail": match &trust {
                Ok(t) => t.describe(),
                Err(e) => e.clone(),
            },
            "ignored_config": ignored,
        });
        if let Some(c) = &stored {
            let (auto, auto_detail) = auto_refresh_verdict(c, now);
            out["stored"] = json!({
                "path": credentials::credentials_path().display().to_string(),
                "subject": c.subject,
                "scopes": c.scopes,
                "gateway": c.gateway,
                // `expires_at: 0` is the file saying it does not know; report
                // null + a detail rather than "expired at the epoch".
                "expires_at": if c.expires_at == 0 { Value::Null } else { json!(c.expires_at) },
                "expires_in_secs": if c.expires_at == 0 {
                    Value::Null
                } else {
                    json!(c.expires_at.saturating_sub(now))
                },
                "expires_detail": if c.expires_at == 0 {
                    json!("unknown — the stored credential records no expiry")
                } else {
                    Value::Null
                },
                "expired": c.access_stale_at(now),
                "has_refresh": c.refresh_token.is_some(),
                "auto_refresh": auto,
                "auto_refresh_detail": auto_detail,
                "refresh_expires_at": match c.refresh_expires_at {
                    Some(e) => json!(e),
                    None => Value::Null,
                },
                "refresh_expires_detail": if c.refresh_token.is_none() {
                    json!("no refresh token is stored")
                } else if c.refresh_expires_at.is_none() {
                    json!("unknown — the gateway did not report a refresh lifetime at login")
                } else {
                    Value::Null
                },
                "access_token": credentials::redact(&c.access_token),
            });
        }
        if let Some(m) = &me {
            out["identity"] = m.clone();
        }
        println!("{out}");
        return Ok(0);
    }

    println!("{}", ui::header("auth", Some(&base)));
    print!(
        "{}",
        ui::kv(&[
            ("gateway", format!("{base}  {}", ui::muted(&crate::role::gateway_provenance(&base_from)))),
            ("credential", source.describe()),
            (
                "tls",
                match &trust {
                    Ok(t) => t.describe(),
                    Err(e) => format!("NO TRUST ANCHOR — {e}"),
                },
            ),
            (
                "config",
                format!("{}  {}", cfg_root.display(), ui::muted(cfg_root_from.describe())),
            ),
        ])
    );
    for note in ignored {
        ui::warned(note);
    }
    match &stored {
        Some(c) => {
            println!("{}", ui::section("stored credential"));
            let mut rows: Vec<(&str, String)> = vec![
                ("file", credentials::credentials_path().display().to_string()),
                ("subject", if c.subject.is_empty() { ui::muted("unknown") } else { c.subject.clone() }),
                ("scopes", scopes_or_unknown(&c.scopes)),
                ("token", ui::muted(&credentials::redact(&c.access_token))),
            ];
            let expires = if c.expires_at == 0 {
                ui::warn("unknown: the stored credential records no expiry")
            } else if c.access_stale_at(now) {
                format!("{} at {}", ui::err("expired"), stamp(c.expires_at))
            } else {
                format!("in {} min, at {}", (c.expires_at - now) / 60, stamp(c.expires_at))
            };
            rows.push(("expires", expires));
            let (auto, auto_detail) = auto_refresh_verdict(c, now);
            rows.push(("auto-refresh", format!("{}  {}", if auto { ui::ok("yes") } else { ui::warn("no") }, ui::muted(&auto_detail))));
            match (&c.refresh_token, c.refresh_expires_at) {
                (None, _) => {}
                (Some(_), Some(exp)) if exp > now => {
                    rows.push(("refresh", format!("valid until {} (~{} days)", stamp(exp), (exp - now) / 86_400)));
                }
                (Some(_), Some(exp)) => rows.push(("refresh", format!("{} at {}", ui::err("expired"), stamp(exp)))),
                (Some(_), None) => rows.push(("refresh", ui::warn("unknown: the gateway did not report a refresh lifetime at login"))),
            }
            // A URL-string difference is NOT proof of a different gateway:
            // the controller answers to `localhost` from its own box and to
            // its tailnet name from everywhere else, so the operator who
            // logged in over the tailnet saw a mismatch warning about the
            // machine they were standing on (host8, 2026-09-05). The probe
            // settles it — a gateway that accepted this credential and named
            // its subject is the issuer, whatever it is called here.
            if !c.gateway.is_empty() && c.gateway != base {
                rows.push(match &me {
                    Some(_) => (
                        "note",
                        ui::muted(&format!(
                            "issued as {}; the current target accepts it, so it is the same gateway under another name",
                            c.gateway
                        )),
                    ),
                    None => (
                        "note",
                        ui::warn(&format!("issued by {}, not the current target", c.gateway)),
                    ),
                });
            }
            print!("{}", ui::kv(&rows));
        }
        None => print!("{}", ui::kv(&[("stored", format!("{}  {}", ui::muted("none"), ui::muted(&credentials::credentials_path().display().to_string())))])),
    }
    println!();
    match me {
        Some(m) => println!(
            "{}",
            ui::status_line(
                Glyph::Ok,
                &format!(
                    "gateway says {}  {}",
                    m["username"].as_str().unwrap_or("?"),
                    ui::muted(&format!(
                        "scopes {}",
                        m["scopes"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(","))
                            .unwrap_or_default()
                    ))
                )
            )
        ),
        None => println!("{}", ui::status_line(Glyph::Warn, "gateway identity unverified: no response from the identity endpoint")),
    }
    Ok(0)
}

/// `noo auth logout` — revoke the stored refresh token server-side (so the
/// credential can't be rotated forward) and delete the local file.
///
/// The already-issued ACCESS token stays valid until it expires; JWTs are not
/// revocable per-token by design. That window is the access TTL (15 min by
/// default) — documented, not hidden.
pub fn auth_logout(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let stored = credentials::load();
    let mut revoked = false;
    if let Some(c) = &stored {
        if let Some(raw) = &c.refresh_token {
            let base = envfile::gateway_url(&g.gateway_override);
            let ok = agent(g, &base, TIMEOUT)
                .post(format!("{base}/api/auth/logout"))
                .header("Cookie", format!("noo_refresh={raw}"))
                        .send_empty()
                .map(|r| (200..=299).contains(&r.status().as_u16()))
                .unwrap_or(false);
            revoked = ok;
            if !ok && !g.json {
                ui::warned(
                    "could not revoke the refresh token server-side (gateway unreachable?); \
                     removing the local credential anyway",
                );
            }
        }
    }
    let removed = match credentials::delete() {
        Ok(r) => r,
        Err(e) => fail(g.json, ExitCode::Generic, "credential_remove_failed", &e, None),
    };
    if g.json {
        println!("{}", json!({"status": "ok", "removed": removed, "refresh_revoked": revoked}));
    } else if removed {
        ui::done(&format!("logged out: removed {}", credentials::credentials_path().display()));
        if !revoked {
            println!("{}", ui::note("no refresh token to revoke server-side"));
        }
        ui::guide(&[("noo auth login", "signs in again; --token <jwt> works for one-off calls")]);
    } else {
        println!("{}", ui::muted(&format!("no stored credential at {}", credentials::credentials_path().display())));
    }
    Ok(0)
}

// ── helpers ────────────────────────────────────────────────────────────────

/// A unix second as something an operator can read, with the raw value kept
/// so it can still be matched against gateway logs.
fn stamp(secs: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .ok()
        .and_then(|d| d.format(&time::format_description::well_known::Rfc3339).ok())
    {
        Some(s) => format!("{s} (unix {secs})"),
        None => format!("unix {secs}"),
    }
}

/// Will the CLI renew this credential by itself, and on what evidence?
///
/// Honest-status rule: a "yes" here is
/// a claim about future behaviour, so it must be backed by something the file
/// actually records. An unknown refresh lifetime is reported as unknown — the
/// CLI will still *try*, and says so, rather than promising success.
fn auto_refresh_verdict(c: &Credentials, now: u64) -> (bool, String) {
    match (&c.refresh_token, c.refresh_expires_at) {
        (None, _) => (
            false,
            "no refresh token is stored; when the access token expires you must run \
             `noo auth login` again"
                .into(),
        ),
        (Some(_), Some(exp)) if exp <= now => (
            false,
            format!("the stored refresh token expired at {}; run `noo auth login` again", stamp(exp)),
        ),
        (Some(_), Some(exp)) => (
            true,
            format!("a refresh token is stored and valid until {}", stamp(exp)),
        ),
        (Some(_), None) => (
            true,
            "a refresh token is stored, but its lifetime is unknown (the gateway reported none \
             at login) — the CLI will try, and say so if the gateway refuses"
                .into(),
        ),
    }
}

fn scopes_or_unknown(scopes: &[String]) -> String {
    if scopes.is_empty() {
        "(unknown)".into()
    } else {
        scopes.join(",")
    }
}

/// Pure construction of the stored credential from a `/auth/token` response.
/// Split out so the cookie/expiry handling is unit-testable without a gateway.
/// Quiet login core (finding #32): POST /auth/token, store the credential,
/// return the subject. No process-exits — the onboarding wizard calls this
/// to log the operator's CLI in the moment the gateway answers.
pub(crate) fn login_and_store(
    g: &Globals,
    username: &str,
    password: &str,
) -> Result<String, String> {
    login_with(g, username, &json!({"username": username, "password": password}))
}

/// [`login_and_store`] with a one-time HOST ticket instead of the password
/// (`grant_type=host_ticket`, minted by `crate::host_access`). The answer is
/// the account's ordinary login, stored the same way.
pub(crate) fn login_with_host_ticket(g: &Globals, username: &str, ticket: &str) -> Result<String, String> {
    login_with(
        g,
        username,
        &json!({"username": username, "password": ticket, "grant_type": crate::host_access::HOST_TICKET_GRANT}),
    )
}

fn login_with(g: &Globals, username: &str, body: &Value) -> Result<String, String> {
    let base = envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}/auth/token");
    let mut resp = agent(g, &base, TIMEOUT)
        .post(&url)
        .send_json(body)
        .map_err(|e| crate::http::describe_send_error(&base, &e, crate::http::effective_timeout(g, TIMEOUT)))?;
    let status = resp.status().as_u16();
    let set_cookie: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if status == 401 || status == 403 {
        return Err(format!("gateway rejected the login for '{username}'"));
    }
    if !(200..=299).contains(&status) {
        return Err(format!("gateway returned {status} for /auth/token"));
    }
    let body: Value =
        serde_json::from_str(&text).map_err(|_| "non-JSON body from /auth/token".to_string())?;
    let mut creds = build_credentials(&base, username, &body, &set_cookie, credentials::now_secs())
        .ok_or("login response carried no access_token")?;
    if let Some(scopes) = fetch_scopes(g, &base, &creds.access_token) {
        creds.scopes = scopes;
    }
    credentials::save(&creds)?;
    // A request earlier in this process may have cached "no credential";
    // the onboard wizard logs in mid-run, and its later calls must send it.
    crate::auth::forget_resolution();
    Ok(creds.subject)
}

fn build_credentials(
    gateway: &str,
    username: &str,
    body: &Value,
    set_cookie: &[String],
    now: u64,
) -> Option<Credentials> {
    let access_token = body["access_token"].as_str()?.to_string();
    if access_token.is_empty() {
        return None;
    }
    let expires_in = body["expires_in"].as_u64().unwrap_or(900);
    let refresh_token = set_cookie.iter().find_map(|h| {
        h.split(';')
            .next()
            .map(str::trim)
            .and_then(|first| first.strip_prefix("noo_refresh="))
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    });
    let refresh_expires_at = body["refresh_ttl_days"]
        .as_u64()
        .map(|d| now.saturating_add(d.saturating_mul(86_400)));
    Some(Credentials {
        gateway: gateway.to_string(),
        subject: username.to_string(),
        scopes: Vec::new(),
        access_token,
        expires_at: now.saturating_add(expires_in),
        refresh_token,
        refresh_expires_at,
    })
}

/// Best-effort `GET /auth/me` with an explicit bearer.
fn fetch_me(g: &Globals, base: &str, header: &str) -> Option<Value> {
    let mut resp = agent(g, base, TIMEOUT)
        .get(format!("{base}/auth/me"))
        .header("Authorization", header)
        .call()
        .ok()?;
    if !(200..=299).contains(&resp.status().as_u16()) {
        return None;
    }
    serde_json::from_str(&resp.body_mut().read_to_string().ok()?).ok()
}

fn fetch_scopes(g: &Globals, base: &str, access_token: &str) -> Option<Vec<String>> {
    let me = fetch_me(g, base, &format!("Bearer {access_token}"))?;
    Some(
        me["scopes"]
            .as_array()?
            .iter()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_response_becomes_a_stored_credential() {
        let body = json!({"access_token": "jwt", "expires_in": 900, "refresh_ttl_days": 30});
        let cookies = vec![
            "noo_refresh=raw-refresh; HttpOnly; Path=/api/auth; SameSite=Strict".to_string(),
        ];
        let c = build_credentials("http://gw:8080", "alice", &body, &cookies, 1_000).unwrap();
        assert_eq!(c.subject, "alice");
        assert_eq!(c.gateway, "http://gw:8080");
        assert_eq!(c.access_token, "jwt");
        assert_eq!(c.expires_at, 1_900);
        assert_eq!(c.refresh_token.as_deref(), Some("raw-refresh"));
        assert_eq!(c.refresh_expires_at, Some(1_000 + 30 * 86_400));
    }

    #[test]
    fn login_without_a_refresh_cookie_still_stores_the_access_token() {
        // The gateway degrades to access-token-only when refresh storage
        // fails; the CLI must not lose the login over it.
        let body = json!({"access_token": "jwt", "expires_in": 60});
        let c = build_credentials("http://gw:8080", "alice", &body, &[], 10).unwrap();
        assert!(c.refresh_token.is_none());
        assert_eq!(c.expires_at, 70);
    }

    #[test]
    fn login_response_without_a_token_is_rejected() {
        assert!(build_credentials("g", "u", &json!({"detail": "no"}), &[], 0).is_none());
        assert!(build_credentials("g", "u", &json!({"access_token": ""}), &[], 0).is_none());
    }

    #[test]
    fn unrelated_cookies_are_not_mistaken_for_the_refresh() {
        let cookies = vec!["session=abc; Path=/".to_string()];
        let c = build_credentials("g", "u", &json!({"access_token": "t"}), &cookies, 0).unwrap();
        assert!(c.refresh_token.is_none());
    }
}
