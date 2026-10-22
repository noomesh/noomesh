// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security …` — the HTTP command surface (users, teams, orgs, posture,
//! service keys), WP-A3 of the CLI Rust port. The `security pki` group lives
//! in pki.rs (local cert operations); `generate-secret`, `scan`,
//! `trust-ca`/`untrust-ca` and `pki rotate-all` are native too, in
//! security_local.rs (the "stay Python" plan was overtaken by the port).
//!
//! Every command here is a thin call to the gateway — the Python `_api()` /
//! `_team_api()` helpers in `security_cli.py` — under the standard
//! envelope/exit-code contract (15s default timeout, matching Python's
//! httpx.Client(timeout=15.0)). Parity notes:
//!   - The team-registry endpoints (`/api/kb/teams*`) can return 200 with an
//!     `{"error": …}` body; Python's `_team_api` treats that as failure
//!     (exit 1) — mirrored here for `team list/create/delete`.
//!   - `user create --password-stdin` reads one line from stdin (the agent
//!     path). `set-password` accepts the same flag (a Rust addition — the
//!     prompt-only Python surface would hang agents), and both refuse to
//!     prompt in `--json` mode or on a non-TTY stdin instead of blocking.
//!   - `user erase` keeps Python's contract exactly: WITHOUT `--yes` it is a
//!     server-side DRY-RUN preview (no prompt needed — nothing is deleted);
//!     `--yes` executes. `team delete` gains the agent-first confirm used by
//!     `stack clean` (`--yes` skips, `--json` requires `--yes`, non-TTY
//!     errors instead of hanging).

use serde_json::{json, Value};

use crate::http::{get_json, post_json, post_json_operator, put_json};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// Python `_api()`/`_team_api()` both use httpx.Client(timeout=15.0).
const TIMEOUT: u64 = 15;

/// Operations an external consumer may be granted (SERVICE_KEY_SCOPES).
/// This is the DEFAULT set when `--scopes` is omitted. `mcp:operator` is
/// deliberately absent: it opens the full-catalog operator MCP door and is
/// only ever granted explicitly (`--scopes mcp:operator --user <admin>`).
const SERVICE_KEY_SCOPES: &[&str] = &["chat", "embeddings", "rerank", "classify", "mcp"];

// ── shared helpers ──────────────────────────────────────────────────────────

/// Python `_team_api` parity: a 2xx body carrying a truthy `error` field is a
/// failure (print the message, exit 1). Non-2xx statuses already exited via
/// the shared `request()` mapping before we get here.
fn team_guard(g: &Globals, body: &Value) {
    let msg = match body.get("error") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(v) if !v.is_null() && *v != json!(false) => v.to_string(),
        _ => return,
    };
    fail(g.json, ExitCode::Generic, "remote_error", &msg, None);
}

/// Render a JSON scalar/array compactly for table cells (Python str()-ish).
fn cell(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string()))
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

/// First 19 chars of a timestamp-ish field (Python's `str(...)[:19]`).
fn ts(v: &Value, fallback: &str) -> String {
    let s = match v {
        Value::Null => fallback.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    s.chars().take(19).collect()
}

/// Read one secret line from the terminal with echo disabled (getpass parity).
/// Prompt goes to stderr; falls back to a plain read if termios is absent.
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
        eprintln!(); // the user's Enter wasn't echoed
    }
    line.trim_end_matches(['\n', '\r']).to_string()
}

/// Obtain a password with the agent-first contract:
///   `--password-stdin`  → one line from stdin, no confirm (the shared
///                         password policy: 12 characters, not a common
///                         password, not containing the username);
///   `--json` w/o flag   → error (never prompt in machine mode);
///   non-TTY w/o flag    → error instead of blocking on a pipe;
///   TTY                 → getpass-style double prompt, echo off, must match.
/// The password itself is never echoed or printed anywhere.
fn read_password(g: &Globals, password_stdin: bool, prompt: &str, confirm: &str, username: &str) -> String {
    use std::io::BufRead as _;
    if password_stdin {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        let password = line.trim_end_matches(['\n', '\r']).to_string();
        refuse_weak(g, &password, username);
        return password;
    }
    if g.json {
        fail(
            true,
            ExitCode::Generic,
            "password_required",
            "refusing to prompt for a password in --json mode",
            Some("pipe it via --password-stdin (one line)"),
        );
    }
    if unsafe { libc::isatty(0) } != 1 {
        fail(
            false,
            ExitCode::Generic,
            "password_required",
            "stdin is not a TTY — cannot prompt for a password",
            Some("pipe it via --password-stdin (one line)"),
        );
    }
    let password = prompt_secret(prompt);
    let confirmed = prompt_secret(confirm);
    if password != confirmed {
        fail(false, ExitCode::Generic, "password_mismatch", "Passwords do not match", None);
    }
    refuse_weak(g, &password, username);
    password
}

/// Exit with `weak_password` unless the shared policy
/// ([`crate::password_policy`]) accepts `password` for `username`. The gateway
/// applies the same rule; checking here saves the round trip and keeps the
/// password off the wire when it would be refused. Only a password being SET
/// is checked: existing accounts keep logging in.
fn refuse_weak(g: &Globals, password: &str, username: &str) {
    if let Some(why) = crate::password_policy::weak_password(password, username) {
        fail(
            g.json,
            ExitCode::Generic,
            "weak_password",
            why,
            Some("use at least 12 characters that are not a common password and do not contain the username"),
        );
    }
}

// ── security user ───────────────────────────────────────────────────────────

/// `noo security user list` — GET /api/security/users.
pub fn security_user_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/security/users", true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let users = body["users"].as_array().unwrap_or(&empty);
    if users.is_empty() {
        println!("{}", ui::muted("no users"));
        ui::guide(&[("noo security user create <username>", "creates the first account; the gateway prompts for a password on stdin")]);
        return Ok(0);
    }
    println!("{}", ui::header("users", Some(&format!("{} accounts", users.len()))));
    println!("{}", ui::section("accounts"));
    let rows: Vec<Vec<String>> = users
        .iter()
        .map(|u| {
            let disabled = u["disabled"].as_bool().unwrap_or(false);
            vec![
                ui::glyph_cell(if disabled { Glyph::Warn } else { Glyph::Ok }),
                cell(&u["username"]),
                if disabled { ui::warn("disabled") } else { ui::ok("active") },
                // Absent on a pre-050 gateway — render the dash rather than "null".
                u["role"].as_str().unwrap_or("").to_string(),
                cell(&u["scopes"]),
                ts(&u["created_at"], ""),
                ts(&u["last_login_at"], "never"),
                u["failed_login_count"].as_u64().unwrap_or(0).to_string(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("username"),
                Col::left("state"),
                Col::left("role"),
                Col::left("scopes"),
                Col::left("created"),
                Col::left("last login"),
                Col::right("failed logins"),
            ],
            &rows,
        )
    );
    Ok(0)
}

/// `noo security user create USERNAME [--scope S]… [--password-stdin]`
/// POST /api/security/users. Scopes default to ["read","write"].
pub fn security_user_create(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut username: Option<String> = None;
    let mut scopes: Vec<String> = Vec::new();
    let mut password_stdin = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--scope" => scopes.push(iter.next().ok_or(Unhandled)?.clone()),
            "--password-stdin" => password_stdin = true,
            s if !s.starts_with('-') && username.is_none() => username = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let username = username.ok_or(Unhandled)?;
    if scopes.is_empty() {
        // Read-only by default: `read` +
        // `write` resolves to the OPERATOR tier, so the old default made
        // every account an operator. Add capability deliberately:
        // `noo security users set-scopes <user> read write`.
        scopes = vec!["read".into()];
    }
    let password = read_password(g, password_stdin, "Password: ", "Confirm password: ", &username);
    let body = post_json(
        g,
        "/api/security/users",
        &json!({"username": username, "password": password, "scopes": scopes}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("user '{username}' created with scopes {}", scopes.join(", ")));
        ui::guide(&[
            (&format!("noo security user grant-role {username} --role <role>"), "knowledge-base roles beyond the scopes"),
            (&format!("noo security user link {username} <channel> <channel-user-id>"), "ties a chat identity to the account"),
            ("noo auth login", "as the new user, to verify the password and scopes"),
        ]);
    }
    Ok(0)
}

/// `noo security user grant-role USERNAME --role/-r R…`
/// POST /api/security/users/{u}/roles.
pub fn security_user_grant_role(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    roles_call(g, args, "roles")
}

/// `noo security user revoke-role USERNAME --role/-r R…`
/// POST /api/security/users/{u}/roles/revoke.
pub fn security_user_revoke_role(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    roles_call(g, args, "roles/revoke")
}

/// `noo security user set-scopes USERNAME --scope/-s S…`
/// POST /api/security/users/{u}/scopes. **Admin-only** — `write` cannot
/// promote itself (gateway `scope_mutation_guard`).
///
/// Note this is auth *scopes* (read/write/admin/peer), not the KB *roles* that
/// `grant-role` handles — a different axis, and easy to confuse.
///
/// The list REPLACES the account's scopes rather than merging, so pass the
/// full intended set: `--scope read --scope write`, not just `--scope write`.
/// An empty list is refused locally rather than sent, because the gateway
/// would reject it anyway and a local error names the mistake better.
/// `noo security user allowance <username> [--tokens <n>] [--period day|week|month] [--clear]`
/// — a person's standing token allowance (i83 G). With no flag it shows the
/// allowance and its use; `--tokens` sets it (Admin); `--clear` removes it.
pub fn security_user_allowance(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut username: Option<String> = None;
    let mut tokens: Option<i64> = None;
    let mut period: Option<String> = None;
    let mut clear = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--tokens" | "-t" => tokens = Some(iter.next().and_then(|v| v.parse().ok()).filter(|n: &i64| *n >= 0).ok_or(Unhandled)?),
            "--period" | "-p" => period = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--clear" => clear = true,
            s if !s.starts_with('-') && username.is_none() => username = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let username = username.ok_or(Unhandled)?;
    if clear && (tokens.is_some() || period.is_some()) {
        fail(g.json, ExitCode::Usage, "usage", "--clear takes no --tokens or --period", None);
    }
    if let Some(p) = &period {
        if !super::usage::valid_period(p) {
            fail(g.json, ExitCode::Usage, "usage", &format!("invalid --period '{p}' (expected day|week|month)"), None);
        }
        if tokens.is_none() {
            fail(g.json, ExitCode::Usage, "usage", "--period sets the allowance's period: give --tokens too", None);
        }
    }
    let path = format!("/api/users/{}/allowance", super::urlencode(&username));
    let body = if clear {
        crate::http::delete_json(g, &path, true, TIMEOUT)
    } else if let Some(n) = tokens {
        let mut b = json!({"tokens": n});
        if let Some(p) = &period {
            b["period"] = json!(p);
        }
        put_json(g, &path, &b, true, TIMEOUT)
    } else {
        get_json(g, &path, true, TIMEOUT)
    };
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    if clear {
        ui::done(&format!("{username} has no token allowance now (no standing cap)"));
        return Ok(0);
    }
    match body["allowance"].as_object() {
        Some(a) => {
            let line = format!(
                "{username}: {} of {} tokens this {} — {} left",
                a.get("spent").and_then(Value::as_i64).unwrap_or(0),
                a.get("limit").and_then(Value::as_i64).unwrap_or(0),
                a.get("period").and_then(Value::as_str).unwrap_or("month"),
                a.get("remaining").and_then(Value::as_i64).unwrap_or(0)
            );
            if tokens.is_some() {
                ui::done(&line);
            } else {
                println!("{line}");
            }
        }
        None => println!("{}", ui::muted(&format!("{username} has no token allowance (no standing cap)"))),
    }
    ui::guide(&[("noo usage me --user <user>", "their node, cloud and harness spend this period")]);
    Ok(0)
}

pub fn security_user_set_scopes(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut username: Option<String> = None;
    let mut scopes: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--scope" | "-s" => scopes.push(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') && username.is_none() => username = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let username = username.ok_or(Unhandled)?;
    if scopes.is_empty() {
        ui::failed(
            "at least one --scope is required, and the list replaces the existing \
             scopes rather than merging: pass the full set",
            Some("noo security user set-scopes <user> --scope read --scope write"),
        );
        return Ok(2);
    }
    let body = post_json(
        g,
        &format!("/api/security/users/{username}/scopes"),
        &json!({"scopes": scopes}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::step(&format!("replacing scopes for {username}"));
        println!("{}", ui::sub(&ui::status_line(Glyph::Ok, &format!("scopes now {}", cell(&body["scopes"])))));
        println!("{}", ui::sub(&ui::status_line(Glyph::Warn, "baked into the JWT at login — takes effect at the user's next login")));
        ui::close_done(&format!("{username} scopes set"));
        ui::guide(&[
            ("noo security user list", "shows the stored scopes per user"),
            ("noo auth logout && noo auth login", "as that user, to pick up the new scopes"),
        ]);
    }
    Ok(0)
}

fn roles_call(g: &Globals, args: &[String], suffix: &str) -> Result<i32, Unhandled> {
    let mut username: Option<String> = None;
    let mut roles: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--role" | "-r" => roles.push(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') && username.is_none() => username = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let username = username.ok_or(Unhandled)?;
    if roles.is_empty() {
        return Err(Unhandled); // Python: --role is a required option
    }
    let body = post_json(
        g,
        &format!("/api/security/users/{username}/{suffix}"),
        &json!({"roles": roles}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        let shown = match &body["roles"] {
            Value::Null => "(defaults only)".to_string(),
            Value::Array(a) if a.is_empty() => "(defaults only)".to_string(),
            v => cell(v),
        };
        ui::done(&format!("{username} KB roles: {shown}"));
        ui::guide(&[
            ("noo security user list-roles", "the role grants across users"),
            (&format!("noo security user revoke-role {username} --role <role>"), "undoes a grant"),
        ]);
    }
    Ok(0)
}

/// `noo security user list-roles` — GET /api/security/role-grants.
pub fn security_user_list_roles(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/security/role-grants", true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let grants = body["grants"].as_array().unwrap_or(&empty);
    if grants.is_empty() {
        println!("{}", ui::muted("no extra grants: everyone has their defaults (user:<name>, company, system; operators unrestricted)"));
        return Ok(0);
    }
    println!("{}", ui::header("role grants", Some(&format!("{} users", grants.len()))));
    println!("{}", ui::section("extra roles"));
    let rows: Vec<Vec<String>> = grants
        .iter()
        .map(|gr| vec![cell(&gr["username"]), cell(&gr["roles"]), ts(&gr["updated_at"], ""), cell(&gr["updated_by"])])
        .collect();
    print!("{}", ui::table(&[Col::left("username"), Col::left("extra roles"), Col::left("updated"), Col::left("by")], &rows));
    Ok(0)
}

/// `noo security user link USERNAME CHANNEL CHANNEL_USER_ID [--name NAME]`
/// POST /api/security/users/{u}/links.
pub fn security_user_link(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut pos: Vec<String> = Vec::new();
    let mut display_name: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--name" => display_name = Some(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') => pos.push(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let [username, channel, channel_user_id] = pos.try_into().map_err(|_| Unhandled)?;
    let mut payload = json!({"channel": channel, "channel_user_id": channel_user_id});
    if let Some(name) = display_name {
        payload["display_name"] = Value::String(name);
    }
    let body = post_json(
        g,
        &format!("/api/security/users/{username}/links"),
        &payload,
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("linked {channel}/{channel_user_id} to {username}"));
        ui::guide(&[
            (&format!("noo security user links {username}"), "every channel identity on the account"),
            (&format!("noo security user unlink {channel} {channel_user_id}"), "reverses the link"),
        ]);
    }
    Ok(0)
}

/// `noo security user unlink CHANNEL CHANNEL_USER_ID`
/// POST /api/security/channel-links/unlink.
pub fn security_user_unlink(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [channel, channel_user_id] = positional::<2>(args)?;
    let body = post_json(
        g,
        "/api/security/channel-links/unlink",
        &json!({"channel": channel, "channel_user_id": channel_user_id}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("unlinked {channel}/{channel_user_id}"));
        ui::guide(&[("noo security user links <username>", "confirms the remaining channel identities")]);
    }
    Ok(0)
}

/// `noo security user links USERNAME` — GET /api/security/users/{u}/links.
pub fn security_user_links(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [username] = positional::<1>(args)?;
    let body = get_json(g, &format!("/api/security/users/{username}/links"), true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let links = body["links"].as_array().unwrap_or(&empty);
    if links.is_empty() {
        println!("{}", ui::muted(&format!("no channel links for '{}'", body["username"].as_str().unwrap_or(&username))));
        ui::guide(&[("noo security user link <username> <channel> <id>", "binds a channel identity (telegram, gchat, …) to this account so messages resolve to it")]);
        return Ok(0);
    }
    println!("{}", ui::header("channel links", Some(body["username"].as_str().unwrap_or(&username))));
    println!("{}", ui::section("links"));
    let rows: Vec<Vec<String>> = links
        .iter()
        .map(|ln| vec![cell(&ln["channel"]), cell(&ln["channel_user_id"]), cell(&ln["display_name"]), ts(&ln["linked_at"], "")])
        .collect();
    print!("{}", ui::table(&[Col::left("channel"), Col::left("channel user id"), Col::left("display name"), Col::left("linked")], &rows));
    Ok(0)
}

/// `noo security user set-password USERNAME [--password-stdin]`
/// PUT /api/security/users/{u}/password. Prompt path matches Python's
/// getpass ("New password:"/"Confirm:"); the flag is the agent path.
pub fn security_user_set_password(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut username: Option<String> = None;
    let mut password_stdin = false;
    for tok in args {
        match tok.as_str() {
            "--password-stdin" => password_stdin = true,
            s if !s.starts_with('-') && username.is_none() => username = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let username = username.ok_or(Unhandled)?;
    let password = read_password(g, password_stdin, "New password: ", "Confirm: ", &username);
    let body = put_json(
        g,
        &format!("/api/security/users/{username}/password"),
        &json!({"password": password}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("password updated for '{username}'"));
        ui::guide(&[("noo auth login", "as that user, to confirm the new password")]);
    }
    Ok(0)
}

/// `noo security admin-password reset [--stdout] [--yes]` — on the
/// controller host.
///
/// A `--ci` install generates the dashboard admin password, stores it
/// encrypted, and deliberately never prints it — so an unattended install
/// had no supported way to learn its own login: the wizard pointed at
/// `secrets reveal NOO_ADMIN_PASSWORD`, which the reveal allow-list refuses.
/// The operator chose (2026-09-28) to REPLACE the password rather than make
/// the old one readable: nothing that was never shown is ever read back out.
///
/// **This is the recovery path, so it needs no login.** It used to change
/// the password through the gateway's user route, which takes a logged-in
/// operator — so it could not recover a LOST password, and the shared
/// secret that might have stood in was refused by that route too. Now it
/// writes the account through the database on the controller host
/// (`crate::host_access`, `docker exec <postgres> psql`): root or the
/// operator account there, never the network. It works with the gateway
/// down, on a locked or disabled account, and with no admin row at all —
/// the row is recreated with the admin tier.
///
/// Order is the safety property. Where the new password may be printed is
/// decided FIRST, by the same rule `secrets reveal` uses: a reset whose
/// output would land in a pipe must refuse before the old password stops
/// working, not after — the other order changes the login and then declines
/// to say what it became, which locks the operator out.
///
/// The database row is the password; `NOO_ADMIN_PASSWORD` in the store only
/// seeds the first account and is inert once that row exists. The copy is
/// still updated, so the store never claims a password that no longer works.
/// Then the CLI logs in with the new password, so the next command — `noo
/// security pki issue-client <you>` — has the login it needs.
pub fn security_admin_password_reset(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    use std::io::IsTerminal as _;
    let (mut stdout_flag, mut yes) = (false, false);
    for tok in args {
        match tok.as_str() {
            "--stdout" => stdout_flag = true,
            "--yes" | "-y" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    // 1. Can the new password be shown? Decided before anything changes.
    if let crate::commands::secrets_reveal::Guard::Refuse(why) =
        crate::commands::secrets_reveal::reveal_guard(std::io::stdout().is_terminal(), stdout_flag, g.json)
    {
        fail(g.json, ExitCode::Generic, "reset_output_refused",
            &format!("not resetting: {why}"),
            Some("run it from a terminal you are sitting at — nothing has been changed"));
    }
    crate::envfile::ensure_repo_env();
    let username = std::env::var("NOO_ADMIN_USER").ok().filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "admin".to_string());
    crate::commands::confirm_destructive(g, yes,
        &format!("RESET the password for '{username}'"),
        "(the current one stops working; the account is re-enabled and unlocked, or recreated as admin if it is missing)");

    // 2. Change the login, on the host — no gateway, no login, no secret.
    let password = crate::onboard::util::token_urlsafe(16);
    let db = crate::host_access::HostDb::resolve();
    if let Err(e) = crate::host_access::reset_admin(&db, &username, &password) {
        fail(g.json, ExitCode::Generic, "reset_failed", &format!("the password was NOT changed: {e}"),
            Some("run it on the controller, as root or an account in the docker group, with the stack's postgres running (noo stack start postgres)"));
    }

    // 3. Keep the stored copy honest. A failure here does not undo the reset
    //    — the login already changed — so it is reported, not fatal.
    let stored = crate::commands::secrets::store_upsert(&[("NOO_ADMIN_PASSWORD".to_string(), password.clone())]);

    // 4. Log the CLI in with it. Best-effort: the reset stands either way.
    let login = crate::commands::auth::login_and_store(g, &username, &password);

    // 5. Say it, once.
    println!("{}", ui::status_line(Glyph::Ok, &format!("password reset for '{username}'")));
    println!();
    println!("    {password}");
    println!();
    println!("{}", ui::muted("shown once — store it now; run this again to replace it"));
    println!("{}", ui::muted(&format!("every open session of '{username}' ends: refresh tokens are revoked and the gateway refuses older access tokens within a few seconds")));
    if let Err(e) = stored {
        ui::warned(&format!("the stored NOO_ADMIN_PASSWORD copy was not updated ({e}); the login above is what works"));
    }
    match login {
        Ok(sub) => ui::guide(&[
            (&format!("noo security pki issue-client {sub} --force"), "a new operator certificate, if yours is lost or expired"),
            ("noo security posture list", "confirms the login"),
        ]),
        Err(e) => {
            ui::warned(&format!("the CLI is not logged in yet ({e})"));
            ui::guide(&[(&format!("noo auth login {username}"), "with the password above, once the gateway answers")]);
        }
    }
    Ok(0)
}

/// `noo security user set-org USERNAME ORG_ID` — POST /api/security/users/{u}/org.
pub fn security_user_set_org(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [username, org_id] = positional::<2>(args)?;
    let body = post_json(
        g,
        &format!("/api/security/users/{username}/org"),
        &json!({"org_id": org_id}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("{username} moved to org '{org_id}'"));
        ui::guide(&[
            ("noo security org list", "member counts per org"),
            ("noo security user list-roles", "team grants outside the new org no longer apply — review them"),
        ]);
    }
    Ok(0)
}

/// `noo security user disable USERNAME [--yes/-y]` —
/// POST /api/security/users/{u}/disable. Locks the account out at once;
/// `user enable` undoes it. Confirms like every destructive verb.
pub fn security_user_disable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (username, yes) = username_and_yes(args)?;
    super::confirm_destructive(g, yes, "disable", &format!("user '{username}' (they are locked out until `user enable`)"));
    let body = post_json(
        g,
        &format!("/api/security/users/{username}/disable"),
        &json!({}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("user '{username}' disabled"));
        ui::guide(&[
            ("noo security user list", "shows the account as disabled"),
            (&format!("noo security user enable {username}"), "re-enables the account"),
            (&format!("noo security user erase {username}"), "previews, then removes the user's data (a copy is kept 30 days, then purged)"),
        ]);
    }
    Ok(0)
}

/// `noo security user enable USERNAME` — POST /api/users/disable with
/// `{"disabled": false}`, the route that re-enables (the per-user `/disable`
/// route only disables). Not destructive, so no confirmation.
pub fn security_user_enable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [username] = positional::<1>(args)?;
    let body = post_json(g, "/api/users/disable", &enable_body(&username), true, TIMEOUT);
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("user '{username}' enabled"));
        ui::guide(&[("noo security user list", "shows the account as active")]);
    }
    Ok(0)
}

/// The request body that re-enables an account on `POST /api/users/disable`
/// (handler `api_users_disable`: `{username, disabled: bool}`).
pub(crate) fn enable_body(username: &str) -> Value {
    json!({"username": username, "disabled": false})
}

/// `<username> [-y|--yes]` — exactly one name, any order.
fn username_and_yes(args: &[String]) -> Result<(String, bool), Unhandled> {
    let mut name: Option<String> = None;
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--yes" | "-y" => yes = true,
            s if !s.starts_with('-') && name.is_none() => name = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    Ok((name.ok_or(Unhandled)?, yes))
}

/// `noo security user erase USERNAME [--yes/-y] [--keep-account]`
/// POST /api/security/users/{u}/erase. Python contract preserved: without
/// `--yes` this is a server-side DRY-RUN preview (`dry_run: true` — nothing
/// is deleted, so no confirmation prompt is needed); `--yes` executes.
pub fn security_user_erase(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut username: Option<String> = None;
    let mut yes = false;
    let mut keep_account = false;
    for tok in args {
        match tok.as_str() {
            "--yes" | "-y" => yes = true,
            "--keep-account" => keep_account = true,
            s if !s.starts_with('-') && username.is_none() => username = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let username = username.ok_or(Unhandled)?;
    let body = post_json(
        g,
        &format!("/api/security/users/{username}/erase"),
        &json!({"dry_run": !yes, "keep_account": keep_account}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    if body["dry_run"].as_bool().unwrap_or(false) {
        let plan: Vec<&Value> = body["plan"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter(|p| p["rows"].as_u64().unwrap_or(0) > 0)
            .collect();
        if plan.is_empty() {
            println!("{}", ui::muted(&format!("nothing to erase for '{username}'")));
            return Ok(0);
        }
        println!("{}", ui::header("erase preview", Some(&format!("{username} · {}", ui::warn("dry-run")))));
        println!("{}", ui::section("would erase"));
        let rows: Vec<Vec<String>> = plan
            .iter()
            .map(|p| vec![cell(&p["store"]), p["rows"].as_u64().unwrap_or(0).to_string()])
            .collect();
        print!("{}", ui::table(&[Col::left("store"), Col::right("rows")], &rows));
        println!();
        print!("{}", ui::kv(&[("total", format!("{} rows across {} stores", body["total_rows"].as_u64().unwrap_or(0), plan.len()))]));
        ui::guide(&[(&format!("noo security user erase {username} --yes"), "erases the rows above; a copy is kept for 30 days so a mistake can be undone, then purged automatically")]);
    } else {
        let total: u64 = body["deleted"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter_map(|p| p["rows"].as_u64())
            .sum();
        ui::done(&format!(
            "erased {total} rows for '{username}'  {}",
            ui::muted(&format!("run_id {}, a copy is kept 30 days, then purged", body["run_id"]))
        ));
    }
    Ok(0)
}

/// `noo security user proposals` — GET /api/security/user-proposals.
pub fn security_user_proposals(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/security/user-proposals", true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let proposals = body["proposals"].as_array().unwrap_or(&empty);
    if proposals.is_empty() {
        println!("{}", ui::muted("no proposals: agents file them via noo_user_propose"));
        return Ok(0);
    }
    println!("{}", ui::header("user proposals", Some(&format!("{} total", proposals.len()))));
    println!("{}", ui::section("proposals"));
    let mut any_pending = false;
    let mut rows: Vec<Vec<String>> = Vec::new();
    for p in proposals {
        let payload = p["payload"].as_object();
        // A task proposal (`noo heartbeat proposals` shows it in full) names its task, not an account.
        let task_proposal = p["action"].as_str() == Some("heartbeat_task");
        let user = if task_proposal {
            cell(&p["payload"]["task"]["id"])
        } else {
            payload.and_then(|m| m.get("username")).map(cell).unwrap_or_default()
        };
        let rest: String = if task_proposal {
            cell(&p["payload"]["why"])
        } else {
            payload
                .map(|m| {
                    m.iter()
                        .filter(|(k, _)| *k != "username")
                        .map(|(k, v)| format!("{k}={}", cell(v)))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        };
        let status = cell(&p["status"]);
        if status == "pending" {
            any_pending = true;
        }
        rows.push(vec![
            p["id"].to_string(),
            ui::state(&status),
            cell(&p["action"]),
            user,
            super::truncate(&rest, 30),
            cell(&p["requested_by"]),
            cell(&p["decided_by"]),
        ]);
    }
    print!(
        "{}",
        ui::table(
            &[Col::right("id"), Col::left("status"), Col::left("action"), Col::left("user"), Col::left("payload"), Col::left("by"), Col::left("decided by")],
            &rows,
        )
    );
    if any_pending {
        ui::guide(&[("noo security user decide <id> --approve | --deny", "resolves a pending proposal; approve applies it, deny discards it")]);
    }
    Ok(0)
}

/// `noo security user decide ID (--approve | --deny) [--reason R]`
/// POST /api/security/user-proposals/{id}/decide. Approve-create prints the
/// generated password once — it is not stored.
pub fn security_user_decide(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut id: Option<i64> = None;
    let mut approve = false;
    let mut deny = false;
    let mut reason: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--approve" => approve = true,
            "--deny" => deny = true,
            "--reason" => reason = Some(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') && id.is_none() => {
                id = Some(s.parse().map_err(|_| Unhandled)?)
            }
            _ => return Err(Unhandled),
        }
    }
    let id = id.ok_or(Unhandled)?;
    // A scheduled-task proposal is a person's decision at a terminal, with the whole task shown and
    // the task id typed. This command has neither, so it will not decide one.
    // By id, not out of the newest-50 list: the answer must not depend on where the proposal sits in it.
    let one = get_json(g, &format!("/api/security/user-proposals/{id}"), true, TIMEOUT);
    let is_task = one["action"].as_str() == Some("heartbeat_task");
    if is_task {
        fail(
            g.json,
            ExitCode::Usage,
            "usage",
            &format!("proposal {id} is a scheduled-task proposal: it is decided with `noo heartbeat approve {id}` (or `reject`), which shows the whole task first"),
            Some(&format!("noo heartbeat proposals {id}")),
        );
    }
    if approve == deny {
        fail(
            g.json,
            ExitCode::Usage,
            "usage",
            "Pass exactly one of --approve / --deny",
            None,
        );
    }
    let body = post_json(
        g,
        &format!("/api/security/user-proposals/{id}/decide"),
        &json!({"approve": approve, "reason": reason}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    if body["status"].as_str() == Some("denied") {
        ui::done(&format!("proposal {id} denied"));
        return Ok(0);
    }
    ui::done(&format!("proposal {id} approved: {} {}", cell(&body["action"]), cell(&body["username"])));
    if let Some(pw) = body["generated_password"].as_str().filter(|s| !s.is_empty()) {
        // The generated password is the value: stdout, plain, shown once.
        println!("  {}", ui::muted("generated password (shown once):"));
        ui::value(pw);
        println!("  {}", ui::muted("share it with the user and have them change it"));
        ui::guide(&[("noo security user set-password <username>", "lets the user replace the generated password")]);
    }
    Ok(0)
}

// ── security team ───────────────────────────────────────────────────────────

/// `noo security team list` — GET /api/kb/teams (team-api error contract).
pub fn security_team_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/kb/teams", true, TIMEOUT);
    team_guard(g, &body);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let teams = body["teams"].as_array().unwrap_or(&empty);
    if teams.is_empty() {
        println!("{}", ui::muted("no teams"));
        ui::guide(&[("noo security team create <name>", "creates a team and its team:<name> role")]);
        return Ok(0);
    }
    println!("{}", ui::header("teams", Some(&format!("{} registered", teams.len()))));
    println!("{}", ui::section("teams"));
    let rows: Vec<Vec<String>> = teams
        .iter()
        .map(|t| {
            let name = cell(&t["name"]);
            vec![
                name.clone(),
                ui::muted(&format!("team:{name}")),
                cell(&t["members"]),
                t["doc_count"].as_u64().unwrap_or(0).to_string(),
                cell(&t["description"]),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(&[Col::left("team"), Col::left("role"), Col::left("members"), Col::right("docs"), Col::left("description")], &rows)
    );
    Ok(0)
}

/// `noo security team create NAME [--description/-d D]`
/// POST /api/kb/teams/create (team-api error contract).
pub fn security_team_create(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--description" | "-d" => description = Some(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') && name.is_none() => name = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let name = name.ok_or(Unhandled)?;
    let body = post_json(
        g,
        "/api/kb/teams/create",
        &json!({"name": name, "description": description}),
        true,
        TIMEOUT,
    );
    team_guard(g, &body);
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("team '{}' created", body["name"].as_str().unwrap_or(&name)));
        ui::guide(&[
            (&format!("noo security user grant-role <user> -r {}", body["role"].as_str().unwrap_or("team:<name>")), "adds a member"),
            ("noo security team link-space <team> <channel> <space_id>", "routes a chat space to the team"),
        ]);
    }
    Ok(0)
}

/// `noo security team delete NAME [--force] [--yes/-y]`
/// DELETE /api/security/teams/{team}[?force=true]. Destructive → agent-first confirm contract
/// (`--yes` skips, `--json` requires `--yes`, non-TTY errors, TTY prompts).
/// `--force` is the SERVER-side gate (delete even with members/docs) and is
/// passed through in the payload, exactly like Python.
pub fn security_team_delete(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name: Option<String> = None;
    let mut force = false;
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--force" => force = true,
            "--yes" | "-y" => yes = true,
            s if !s.starts_with('-') && name.is_none() => name = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let name = name.ok_or(Unhandled)?;
    super::confirm_destructive(g, yes, "Delete", &format!("team '{name}'"));
    let body = crate::http::delete_json(g, &team_delete_path(&name, force), true, TIMEOUT);
    team_guard(g, &body);
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!(
            "team '{}' deleted  {}",
            body["deleted"].as_str().unwrap_or(&name),
            ui::muted(&format!("{} grant(s) stripped, {} doc(s) keep an inert tag", body["members_stripped"], body["docs_orphaned"]))
        ));
        ui::guide(&[
            ("noo security team list", "confirms the team is gone"),
            ("noo security user list-roles", "shows which users lost a team grant"),
        ]);
    }
    Ok(0)
}

/// The path `team delete` calls: the path-addressed route the console-free
/// `/api/security/*` surface uses, with `force` as the query flag the
/// gateway reads (`TeamDeleteQuery`). A `team:` prefix is accepted by the
/// gateway and stripped there.
pub(crate) fn team_delete_path(name: &str, force: bool) -> String {
    format!("/api/security/teams/{name}{}", if force { "?force=true" } else { "" })
}

/// `noo security team link-space TEAM CHANNEL SPACE_ID`
/// POST /api/security/teams/{team}/spaces.
pub fn security_team_link_space(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [team, channel, space_id] = positional::<3>(args)?;
    let body = post_json(
        g,
        &format!("/api/security/teams/{team}/spaces"),
        &json!({"channel": channel, "space_id": space_id}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("linked {channel} space '{space_id}' to team '{team}' (shared)"));
        ui::guide(&[
            (&format!("noo security team spaces {team}"), "lists the spaces the team now shares"),
            (&format!("noo security team unlink-space {channel} {space_id}"), "reverses the link"),
        ]);
    }
    Ok(0)
}

/// `noo security team unlink-space CHANNEL SPACE_ID`
/// POST /api/security/channel-team-links/unlink.
pub fn security_team_unlink_space(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [channel, space_id] = positional::<2>(args)?;
    let body = post_json(
        g,
        "/api/security/channel-team-links/unlink",
        &json!({"channel": channel, "space_id": space_id}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("unlinked {channel} space '{space_id}'"));
        ui::guide(&[("noo security team spaces <team>", "confirms the space is no longer shared")]);
    }
    Ok(0)
}

/// `noo security team spaces TEAM` — GET /api/security/teams/{team}/spaces.
pub fn security_team_spaces(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [team] = positional::<1>(args)?;
    let body = get_json(g, &format!("/api/security/teams/{team}/spaces"), true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let spaces = body["spaces"].as_array().unwrap_or(&empty);
    if spaces.is_empty() {
        println!("{}", ui::muted(&format!("no spaces linked to team '{team}'")));
        ui::guide(&[("noo security team link-space <team> <channel> <space_id>", "routes messages from that chat space to this team's knowledge base")]);
        return Ok(0);
    }
    println!("{}", ui::header("team spaces", Some(&team)));
    println!("{}", ui::section("spaces"));
    let rows: Vec<Vec<String>> = spaces
        .iter()
        .map(|s| vec![cell(&s["channel"]), cell(&s["space_id"]), ts(&s["created_at"], "")])
        .collect();
    print!("{}", ui::table(&[Col::left("channel"), Col::left("space id"), Col::left("linked")], &rows));
    Ok(0)
}

// ── security org ────────────────────────────────────────────────────────────

/// `noo security org list` — GET /api/security/orgs.
pub fn security_org_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/security/orgs", true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let orgs = body["orgs"].as_array().unwrap_or(&empty);
    if orgs.is_empty() {
        println!("{}", ui::muted("no orgs"));
        ui::guide(&[("noo security org create <id>", "creates an organisation; teams and users are scoped under it")]);
        return Ok(0);
    }
    println!("{}", ui::header("orgs", Some(&format!("{} registered", orgs.len()))));
    println!("{}", ui::section("orgs"));
    let rows: Vec<Vec<String>> = orgs
        .iter()
        .map(|o| vec![cell(&o["id"]), cell(&o["name"]), o["members"].as_u64().unwrap_or(0).to_string(), cell(&o["description"])])
        .collect();
    print!("{}", ui::table(&[Col::left("id"), Col::left("name"), Col::right("members"), Col::left("description")], &rows));
    Ok(0)
}

/// `noo security org create ORG_ID [--name N] [--description/-d D]`
/// POST /api/security/orgs. Only the provided fields go in the payload
/// (Python builds it conditionally too).
pub fn security_org_create(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut org_id: Option<String> = None;
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--name" => name = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--description" | "-d" => description = Some(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') && org_id.is_none() => org_id = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let org_id = org_id.ok_or(Unhandled)?;
    let mut payload = json!({"id": org_id});
    if let Some(n) = name {
        payload["name"] = Value::String(n);
    }
    if let Some(d) = description {
        payload["description"] = Value::String(d);
    }
    let body = post_json(g, "/api/security/orgs", &payload, true, TIMEOUT);
    if g.json {
        println!("{body}");
    } else {
        ui::done(&format!("org '{org_id}' created"));
        ui::guide(&[
            ("noo security team create <name>", "teams scope knowledge and channels; members inherit the org via set-org"),
            (&format!("noo security user set-org <user> {org_id}"), "moves a user into the new org"),
            ("noo security org list", "confirms the org and its counts"),
        ]);
    }
    Ok(0)
}

// ── security audit verify ───────────────────────────────────────────────────

/// `noo security audit verify` — GET /api/security/audit/verify.
///
/// Recomputes every security-audit row's hash in the GATEWAY (only it holds
/// both keys the log was ever signed with: the retired NOO_JWT_SECRET
/// derivation before the audit-key checkpoint, NOO_AUDIT_HMAC_KEY after) and
/// prints the verdict, naming each row that failed. Exit 1 on a failure.
pub fn security_audit_verify(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    // The operator's own credential: the route takes an
    // Operator-role login, so there is no reason to sign it with the
    // controller's shared secret — that made every `cluster verify` a
    // `cluster_hmac_non_inference` use attributed to nobody.
    let body = get_json(g, "/api/security/audit/verify", true, 120);
    let failed = body["verdict"].as_str() != Some("ok");
    if g.json {
        println!("{body}");
        return Ok(if failed { 1 } else { 0 });
    }
    let n = |k: &str| body[k].as_u64().unwrap_or(0);
    println!(
        "{}",
        ui::header("security audit verify", Some(&format!("{} rows", n("checked"))))
    );
    let cp = &body["checkpoint"];
    let cp_text = if cp.is_object() {
        format!(
            "{} {} {}",
            cp["timestamp"].as_str().unwrap_or("?"),
            if cp["genesis"].as_bool().unwrap_or(false) { "genesis" } else { "hand-over" },
            ui::muted(&format!("id {}", cp["id"].as_str().unwrap_or("?")))
        )
    } else {
        ui::muted("none")
    };
    print!(
        "{}",
        ui::kv(&[
            ("audit key", match body["key_fingerprint"].as_str() {
                Some(fp) => format!("present {}", ui::muted(&format!("fp {fp}"))),
                None => ui::err("MISSING"),
            }),
            ("checkpoint", cp_text),
            ("verified", format!(
                "{} {}",
                n("ok"),
                ui::muted(&format!(
                    "({} before the checkpoint, {} under the audit key)",
                    n("retired_epoch_rows"),
                    n("current_epoch_rows")
                ))
            )),
            ("unhashed", format!("{} {}", n("unhashed"), ui::muted("(written before hashing existed)"))),
            ("unverifiable", n("unverifiable").to_string()),
            ("public fallback", n("public_fallback").to_string()),
            ("roll window", if n("roll_window_rows") > 0 {
                ui::warn(&format!(
                    "{} (retired key, old-image writer, just after the checkpoint)",
                    n("roll_window_rows")
                ))
            } else {
                "0".to_string()
            }),
            // Hash v2 covers the row's time; v1 did not.
            ("hash v2", match body["hash_v2_marker"]["timestamp"].as_str() {
                Some(t) => format!(
                    "since {t} {}",
                    ui::muted(&format!("({} v2, {} v1 rows)", n("v2_rows"), n("v1_rows")))
                ),
                None => ui::muted("no marker yet"),
            }),
            ("v1 roll window", if n("v1_roll_window_rows") > 0 {
                ui::warn(&format!(
                    "{} (hashed v1, old-image writer, just after the hash-v2 marker)",
                    n("v1_roll_window_rows")
                ))
            } else {
                "0".to_string()
            }),
        ])
    );
    // The hash chain: deletion and reordering evidence. Said plainly when it
    // could not be judged; "not checked" is never shown as ok.
    let chain = &body["chain"];
    if chain["checked"].as_bool() == Some(true) {
        let head = match chain["head"]["seq"].as_i64() {
            Some(seq) => format!(
                "seq {seq} {}",
                ui::muted(&format!("hash {}", chain["head"]["chain_hash"].as_str().unwrap_or("?")))
            ),
            None => ui::muted("none"),
        };
        print!(
            "{}",
            ui::kv(&[
                ("chain", format!(
                    "{} chained, {} before the chain {}",
                    chain["chained_rows"].as_u64().unwrap_or(0),
                    chain["unchained_rows"].as_u64().unwrap_or(0),
                    ui::muted(&format!("({} removed by retention)", chain["retired_rows"].as_u64().unwrap_or(0)))
                )),
                ("chain head", head),
            ])
        );
        // The head against the copy the gateway keeps outside the database.
        // Absent on an older gateway: said as NOT CHECKED, never as ok.
        let (glyph, text) = exported_head_line(&chain["export"]);
        println!("{}", ui::status_line(glyph, &text));
    } else {
        println!(
            "{}",
            ui::status_line(
                Glyph::Warn,
                &format!("chain not checked: {}", chain["note"].as_str().unwrap_or("the gateway did not report a chain section (older gateway?)"))
            )
        );
    }
    let empty = Vec::new();
    let breaks = body["breaks"].as_array().unwrap_or(&empty);
    if !breaks.is_empty() {
        println!("{}", ui::section("rows that do not verify"));
        let rows: Vec<Vec<String>> = breaks
            .iter()
            .map(|b| {
                vec![
                    ui::glyph_cell(Glyph::Err),
                    cell(&b["id"]),
                    ui::muted(b["timestamp"].as_str().unwrap_or("")),
                    b["reason"].as_str().unwrap_or("").to_string(),
                ]
            })
            .collect();
        print!(
            "{}",
            ui::table(&[Col::left(""), Col::left("row"), Col::left("at"), Col::left("why")], &rows)
        );
    }
    for p in body["problems"].as_array().unwrap_or(&empty) {
        println!("{}", ui::status_line(Glyph::Err, p.as_str().unwrap_or("")));
    }
    for w in body["warnings"].as_array().unwrap_or(&empty) {
        println!("{}", ui::status_line(Glyph::Warn, w.as_str().unwrap_or("")));
    }
    if failed {
        ui::failed("the security audit log does not verify", None);
        Ok(1)
    } else {
        println!("{}", ui::status_line(Glyph::Ok, "every hashed row verifies under the key of its epoch"));
        Ok(0)
    }
}

/// What `audit verify` says about the exported chain head: `(glyph, text)`.
/// A regression is an error (the verdict also fails through `problems`);
/// anything that could not be compared is a warning that says NOT CHECKED.
pub(crate) fn exported_head_line(export: &Value) -> (Glyph, String) {
    if export.is_null() {
        return (
            Glyph::Warn,
            "chain head NOT CHECKED against an exported head: this gateway predates the head export (update the controller)".into(),
        );
    }
    if export["checked"].as_bool() != Some(true) {
        return (
            Glyph::Warn,
            export["note"].as_str().unwrap_or("chain head NOT CHECKED against an exported head").to_string(),
        );
    }
    let last = &export["last_exported"];
    let at = format!("seq {} at {}", last["seq"].as_i64().unwrap_or(0), last["time"].as_str().unwrap_or("?"));
    if export["regression"].as_bool() == Some(true) {
        (Glyph::Err, format!("chain head is BEHIND or differs from the exported head ({at}): the newest rows were cut off or rewritten"))
    } else {
        (Glyph::Ok, format!("chain head is at or past the last exported head ({at})"))
    }
}

// ── security audit list ─────────────────────────────────────────────────────

/// `noo security audit list` — GET /api/security/audit/list.
///
/// Reads the security audit log (Operator and above), newest first. Filters are
/// applied by the gateway; `--cursor` continues from a previous page's
/// `next_cursor`. Reading is itself recorded as an `audit_log_read` row.
pub fn security_audit_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut query: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        let key = match tok.as_str() {
            "--since" => "since",
            "--event" | "--event-type" => "event_type",
            "--actor" => "actor",
            "--limit" | "-n" => "limit",
            "--cursor" => "cursor",
            _ => return Err(Unhandled),
        };
        let v = iter.next().ok_or(Unhandled)?;
        if key == "limit" && v.parse::<u32>().is_err() {
            return Err(Unhandled);
        }
        query.push(format!("{key}={}", super::urlencode(v)));
    }
    let path = if query.is_empty() {
        "/api/security/audit/list".to_string()
    } else {
        format!("/api/security/audit/list?{}", query.join("&"))
    };
    let body = get_json(g, &path, true, 30);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let events = body["events"].as_array().unwrap_or(&empty);
    if events.is_empty() {
        println!("{}", ui::muted("no audit rows match"));
        return Ok(0);
    }
    println!("{}", ui::header("security audit", Some(&format!("{} rows, newest first", events.len()))));
    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|e| {
            let glyph = match e["severity"].as_str().unwrap_or("info") {
                "critical" | "error" => Glyph::Err,
                "warning" => Glyph::Warn,
                _ => Glyph::Bullet,
            };
            let ip = e["details"]["source_ip"].as_str().unwrap_or("");
            vec![
                ui::glyph_cell(glyph),
                ui::muted(e["timestamp"].as_str().unwrap_or("")),
                cell(&e["event_type"]),
                cell(&e["actor"]),
                cell(&e["resource"]),
                cell(&e["outcome"]),
                ui::muted(ip),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left(""), Col::left("at"), Col::left("event"), Col::left("actor"), Col::left("resource"), Col::left("outcome"), Col::left("from")],
            &rows,
        )
    );
    if let Some(next) = body["next_cursor"].as_str() {
        println!();
        ui::guide(&[("noo security audit list --cursor <next>", &format!("more rows; cursor {next}"))]);
    }
    println!("{}", ui::muted("--json shows each row's details (source_ip, conversation_id) and chain position"));
    Ok(0)
}

// ── security posture ────────────────────────────────────────────────────────

/// `noo security posture list` — GET /api/security/posture.
pub fn security_posture_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    // Reading posture takes an Operator-role login (`users_admin_read_guard`);
    // the WRITES below take the operator certificate + a bound token
    let mut body = get_json(g, "/api/security/posture", true, TIMEOUT);
    // The gateway cannot see containers; this host can. Without this the
    // node-agent row's "running" was the gateway's own env var, which no
    // container ever read.
    annotate_actual(&mut body, &node_agent_privileged_actual());
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let gates = body["posture"].as_array().unwrap_or(&empty);
    if gates.is_empty() {
        println!("{}", ui::muted("no posture gates"));
        return Ok(0);
    }
    let drifted = |g: &Value| g["actual_drift"].as_bool().unwrap_or(false);
    let pending = gates.iter().filter(|g| g["pending_restart"].as_bool().unwrap_or(false) || drifted(g)).count();
    // An OPEN bridge is the most perishable thing in the install: a
    // compatibility window someone is holding open on purpose and is expected
    // to shut. Printed among thirty gates it reads as one more row, which is
    // how `noo-cluster-executor` stayed up for two days after its own removal
    // It leads, with its age.
    let open_bridges: Vec<&Value> = gates.iter().filter(|g| g["bridge"].is_object()).collect();
    let overdue = open_bridges
        .iter()
        .filter(|b| b["bridge"]["overdue"].as_bool().unwrap_or(false))
        .count();
    println!("{}", ui::header("security posture", Some(&format!("{} gates · {pending} pending restart", gates.len()))));
    if !open_bridges.is_empty() {
        println!("{}", ui::section("compatibility bridges OPEN"));
        let brows: Vec<Vec<String>> = open_bridges
            .iter()
            .map(|b| {
                let d = &b["bridge"];
                let (open_days, window) = (
                    d["open_days"].as_i64().unwrap_or(0),
                    d["window_days"].as_i64().unwrap_or(0),
                );
                let od = d["overdue"].as_bool().unwrap_or(false);
                let age = if d["dated_from_update"].as_bool().unwrap_or(false) {
                    // Say it plainly. A row that predates the opened_at column
                    // was dated from its last write, which may be long after it
                    // opened — presenting that as the open date would be
                    // inference wearing evidence's clothes.
                    format!("{open_days}d {}", ui::muted("(from last write)"))
                } else {
                    format!("{open_days}d")
                };
                vec![
                    ui::glyph_cell(if od { Glyph::Err } else { Glyph::Warn }),
                    cell(&b["key"]),
                    match &b["db_value"] { Value::Null => ui::muted("unset"), v => cell(v) },
                    age,
                    if od {
                        ui::warn(&format!("{}d OVERDUE", d["overdue_days"].as_i64().unwrap_or(0)))
                    } else {
                        ui::muted(&format!("of {window}d"))
                    },
                ]
            })
            .collect();
        print!(
            "{}",
            ui::table(
                &[Col::left(""), Col::left("bridge"), Col::left("value"), Col::left("open"), Col::left("window")],
                &brows,
            )
        );
        println!();
        println!("{}", ui::muted("a bridge is a rollout window, not a setting — close it when the fleet has crossed"));
        if overdue > 0 {
            println!("{}", ui::warn(&format!(
                "{overdue} bridge(s) past their declared window — nothing closes one automatically, \
                 and nothing should: only you know whether the last node has crossed"
            )));
        }
        println!();
    }
    println!("{}", ui::section("gates"));
    let rows: Vec<Vec<String>> = gates
        .iter()
        .map(|gate| {
            let pending = gate["pending_restart"].as_bool().unwrap_or(false);
            let drift = drifted(gate);
            let unseen = gate["actual_error"].is_string();
            vec![
                ui::glyph_cell(if pending || drift || unseen { Glyph::Warn } else { Glyph::Ok }),
                cell(&gate["key"]),
                // A gate whose truth lives in a container shows THE
                // CONTAINER's state, or that it could not be read.
                match (&gate["actual"], &gate["running"]) {
                    (Value::String(a), _) => format!("{a} (container)"),
                    _ if unseen => ui::muted("container not checked"),
                    (_, Value::Null) => ui::muted("unset"),
                    (_, v) => cell(v),
                },
                match &gate["db_value"] {
                    Value::Null => String::new(),
                    v => cell(v),
                },
                cell(&gate["source"]),
                if drift {
                    ui::warn("recreate node-agent")
                } else if pending {
                    ui::warn("pending")
                } else {
                    ui::muted("no")
                },
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left(""), Col::left("gate"), Col::left("running"), Col::left("desired (db)"), Col::left("source"), Col::left("restart")],
            &rows,
        )
    );
    println!();
    println!("{}", ui::muted("bootstrap-tier gates (TLS, secrets) are managed via the secrets backend, not here"));
    if pending > 0 {
        ui::guide(&[("noo stack restart gateway", "posture gates are read at start; the desired values above take effect after a restart")]);
    }
    Ok(0)
}

/// `noo security posture set KEY VALUE` — POST /api/security/posture.
/// Posture gates that a process reads BEFORE any database is reachable, and
/// which therefore also have to be mirrored into `.env`.
///
/// Posture is DB-authoritative by design and that is right for a gate the
/// gateway consults while serving. It cannot work for a gate consulted
/// while CONNECTING to the bus: the gateway, the Python worker pool and the
/// node-agent all open their NATS connection before their database handle
/// exists (and the node-agent has no database at all). A DB row alone would
/// silently reach one reader out of three.
///
/// So such a key is written to both places by one command, and the CLI
/// says it did. The alternative — an operator setting posture, watching two
/// of three processes ignore it, and finding out from an outage — is the
/// failure this list exists to prevent.
///
/// `NOO_NODE_AGENT_PRIVILEGED` is the one entry, for a different reason: it is
/// consumed by COMPOSE INTERPOLATION (`privileged: ${NOO_NODE_AGENT_PRIVILEGED}`
/// in `docker-compose.cluster.yml`), which reads `.env` and nothing else. A DB
/// row alone reached no reader at all — `apply-profile hardened` reported the
/// node-agent unprivileged while its container kept `--privileged`. Its
/// mirror is written as `true`/`false` (never dropped: an absent line means
/// "compose's default"), and a change recreates the container
/// ([`converge_node_agent`]).
///
/// The previous entry, `NOO_NATS_LEGACY_SHARED_CREDS`, bridged to the shared
/// bus user, and that user is retired.
const POSTURE_KEYS_MIRRORED_TO_ENV: &[&str] = &[NODE_AGENT_PRIVILEGED_KEY];

/// The posture key whose truth is a container's `HostConfig.Privileged`.
const NODE_AGENT_PRIVILEGED_KEY: &str = "NOO_NODE_AGENT_PRIVILEGED";

fn truthy_posture_value(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Of the keys a posture command just WROTE to the DB, which also need the
/// `.env` mirror? Pure, so the rule can be tested without a gateway or a
/// filesystem.
///
/// This exists because the rule was applied in one place and not the other.
/// `posture set` mirrored; `apply-profile` did not — and on host8 during the
/// v0.2.39 rollout `apply-profile hardened` put the bus-bridge DB row to 0
/// while `.env` kept saying 1. The gateway read the row and refused to serve;
/// the workers and the node-agent read the environment and carried on. A
/// split brain across three processes, from one command that mirrored nothing
/// Both commands now go through here.
fn keys_to_mirror(written: &[(String, String)]) -> Vec<(String, String)> {
    keys_to_mirror_from(POSTURE_KEYS_MIRRORED_TO_ENV, written)
}

/// [`keys_to_mirror`] over an explicit list, so the rule stays testable while
/// the shipped list is empty.
fn keys_to_mirror_from(mirrored: &[&str], written: &[(String, String)]) -> Vec<(String, String)> {
    written
        .iter()
        .filter(|(k, _)| mirrored.contains(&k.as_str()))
        .cloned()
        .collect()
}

/// Write the `.env` mirror for each key that needs one, reporting per key.
/// `Ok(key)` mirrored, `Err((key, message))` did not — the caller prints the
/// failure, because a mirror that silently fails is the split brain again.
fn mirror_into_env(written: &[(String, String)]) -> Vec<Result<String, (String, String)>> {
    keys_to_mirror(written)
        .into_iter()
        .map(|(key, value)| {
            let on = truthy_posture_value(&value);
            let wrote = if key == NODE_AGENT_PRIVILEGED_KEY {
                crate::envfile::set_env_value(&key, Some(if on { "true" } else { "false" }))
            } else {
                crate::envfile::set_env_flag(&key, on)
            };
            match wrote {
                Ok(()) => Ok(key),
                Err(e) => Err((key.clone(), format!("could not mirror {key} into .env: {e}"))),
            }
        })
        .collect()
}

/// Print the mirror outcome in the human renderer. Shared so the two commands
/// cannot describe the same action differently.
fn print_mirror_outcome(results: &[Result<String, (String, String)>]) {
    for r in results {
        match r {
            Ok(key) if key == NODE_AGENT_PRIVILEGED_KEY => ui::done(&format!(
                "{key} mirrored into .env — compose reads it when the node-agent container is created"
            )),
            Ok(key) => ui::done(&format!(
                "{key} mirrored into .env — the workers and the node-agent read it before any DB exists"
            )),
            Err((_, msg)) => {
                println!("{}", ui::status_line(Glyph::Warn, msg));
                println!("{}", ui::note("the DB row IS set; the workers and node-agent read this one from .env, so set it there by hand"));
            }
        }
    }
}

/// Parse `docker inspect -f '{{.HostConfig.Privileged}}'`. Pure so every arm
/// (running, absent, docker failing, garbage) is pinned without docker.
pub(crate) fn parse_privileged_inspect(success: bool, stdout: &str, stderr: &str, container: &str) -> Result<bool, String> {
    if !success {
        let why = stderr.trim();
        return Err(if why.contains("No such") || why.contains("no such") {
            format!("no {container} container on this host (the node-agent here is not compose-managed, or the stack is down)")
        } else if why.is_empty() {
            format!("docker inspect {container} failed with no message")
        } else {
            format!("docker inspect {container} failed: {why}")
        });
    }
    match stdout.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("docker inspect {container} answered {other:?}, expected true or false")),
    }
}

/// Is the node-agent container privileged RIGHT NOW (docker's own answer,
/// not the posture row and not an env var). `Err` = could not be seen; a
/// caller must say "not checked", never treat it as unprivileged.
pub(crate) fn node_agent_privileged_actual() -> Result<bool, String> {
    let container = crate::envfile::container("node-agent");
    match std::process::Command::new("docker")
        .args(["inspect", "-f", "{{.HostConfig.Privileged}}", &container])
        .output()
    {
        Ok(o) => parse_privileged_inspect(
            o.status.success(),
            &String::from_utf8_lossy(&o.stdout),
            &String::from_utf8_lossy(&o.stderr),
            &container,
        ),
        Err(e) => Err(format!("docker is not runnable: {e}")),
    }
}

/// Does the container's actual state disagree with the desired posture value?
/// `None` when either side is unknown (nothing to compare is not a match).
pub(crate) fn privileged_drift(desired: Option<&str>, actual: Option<bool>) -> Option<bool> {
    Some(truthy_posture_value(desired?) != actual?)
}

/// Add the node-agent's ACTUAL container state to a `posture list` body:
/// `actual` ("true"/"false") or `actual_error`, and `actual_drift`. The
/// gateway cannot inspect containers (it has no docker access by design), so
/// this host-local fact is added here, where docker is. `actual` is the word
/// "at desired" has to mean.
fn annotate_actual(body: &mut Value, actual: &Result<bool, String>) {
    let Some(gates) = body["posture"].as_array_mut() else { return };
    for gate in gates.iter_mut().filter(|g| g["key"] == NODE_AGENT_PRIVILEGED_KEY) {
        match actual {
            Ok(a) => {
                gate["actual"] = json!(a.to_string());
                let desired = gate["db_value"].as_str().map(String::from);
                gate["actual_drift"] = json!(privileged_drift(desired.as_deref(), Some(*a)).unwrap_or(false));
            }
            Err(why) => gate["actual_error"] = json!(why),
        }
    }
}

/// After the node-agent's posture value was written and mirrored: make the
/// container match, by recreating it when it does not. `Ok(true)` = it was
/// recreated and now matches, `Ok(false)` = already matched. `Err` = could not
/// be seen, or the recreate did not take.
fn converge_node_agent(desired_on: bool) -> Result<bool, String> {
    let before = node_agent_privileged_actual()?;
    if before == desired_on {
        return Ok(false);
    }
    super::mesh::recreate_service("node-agent")?;
    let after = node_agent_privileged_actual()?;
    if after == desired_on {
        Ok(true)
    } else {
        Err(format!(
            "recreated the node-agent but docker still reports privileged={after} (wanted {desired_on}); is .env being read by the launcher?"
        ))
    }
}

/// Run [`converge_node_agent`] for a just-written posture and say what happened.
/// `None` when the node-agent key was not part of this write (or its mirror
/// failed, which has already been reported).
fn converge_after_write(written: &[(String, String)], results: &[Result<String, (String, String)>]) -> Option<Value> {
    let (_, value) = written.iter().find(|(k, _)| k == NODE_AGENT_PRIVILEGED_KEY)?;
    if !results.iter().any(|r| matches!(r, Ok(k) if k == NODE_AGENT_PRIVILEGED_KEY)) {
        return None;
    }
    let desired = truthy_posture_value(value);
    Some(match converge_node_agent(desired) {
        Ok(recreated) => json!({"desired_privileged": desired, "recreated": recreated, "matches": true}),
        Err(e) => json!({"desired_privileged": desired, "recreated": false, "matches": false, "error": e}),
    })
}

fn print_converge_outcome(outcome: &Option<Value>) {
    let Some(o) = outcome else { return };
    let want = o["desired_privileged"].as_bool().unwrap_or(false);
    let state = if want { "privileged" } else { "unprivileged" };
    if o["matches"].as_bool() == Some(true) {
        if o["recreated"].as_bool() == Some(true) {
            ui::done(&format!("node-agent container recreated: it is now {state} (docker inspect)"));
        } else {
            ui::done(&format!("node-agent container already {state} (docker inspect)"));
        }
    } else {
        println!("{}", ui::status_line(Glyph::Warn, &format!(
            "node-agent container NOT confirmed {state}: {}",
            o["error"].as_str().unwrap_or("unknown")
        )));
        println!("{}", ui::note("the posture row and .env are set; apply them with: noo stack restart --force node-agent"));
    }
}

pub fn security_posture_set(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [key, value] = positional::<2>(args)?;
    let body = post_json_operator(
        g,
        "/api/security/posture",
        &json!({"key": key, "value": value}),
        TIMEOUT,
    );
    let written = vec![(key.clone(), value.clone())];
    let needs_mirror = !keys_to_mirror(&written).is_empty();
    let results = mirror_into_env(&written);
    let mirrored = needs_mirror.then(|| results.iter().all(|r| r.is_ok()));
    let node_agent = converge_after_write(&written, &results);
    if g.json {
        if let Some(ok) = mirrored {
            println!("{}", json!({"posture": body, "env_mirrored": ok, "node_agent": node_agent}));
        } else {
            println!("{body}");
        }
    } else {
        ui::done(&format!("posture {key} = {value}"));
        print_mirror_outcome(&results);
        print_converge_outcome(&node_agent);
        ui::warned("restart the gateway to apply");
        ui::guide(&[("noo stack restart gateway", "posture gates are read at start; the change is live after the restart")]);
    }
    Ok(0)
}

/// `noo security posture apply-profile PROFILE [--include-bridges]` —
/// POST /api/security/posture/profile.
///
/// Prints a before/after line for every key the profile moved, and names the
/// BRIDGE keys it deliberately left alone with their current values. Both
/// halves come from the command used to print "applied 7 gates",
/// which said nothing about which of the seven had changed — and one of them
/// was a rollout bridge it should never have touched.
///
/// `--include-bridges` closes the bridges too, to the safe value the gateway's
/// catalog carries for each. It is opt-in because only the operator knows
/// whether the last node has crossed the boundary the bridge exists for.
pub fn security_posture_apply_profile(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut include_bridges = false;
    let mut rest: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "--include-bridges" => include_bridges = true,
            other => rest.push(other.to_string()),
        }
    }
    let [profile] = positional::<1>(&rest)?;
    let body = post_json_operator(
        g,
        "/api/security/posture/profile",
        &json!({"profile": profile, "include_bridges": include_bridges}),
        TIMEOUT,
    );

    // Mirror every key the gateway actually WROTE — changed and unchanged
    // alike, because an unchanged DB row can still sit opposite a stale `.env`
    // line. `posture set` and this command share `mirror_into_env`, so the
    // rule cannot apply in one place and not the other again (R43).
    let written: Vec<(String, String)> = ["changed", "unchanged"]
        .iter()
        .filter_map(|k| body[*k].as_array())
        .flatten()
        .filter_map(|row| {
            Some((row["key"].as_str()?.to_string(), row["to"].as_str()?.to_string()))
        })
        .collect();
    let results = mirror_into_env(&written);
    let node_agent = converge_after_write(&written, &results);

    if g.json {
        println!(
            "{}",
            json!({
                "posture": body,
                "env_mirrored": results.iter().map(|r| match r {
                    Ok(k) => json!({"key": k, "ok": true}),
                    Err((k, msg)) => json!({"key": k, "ok": false, "error": msg}),
                }).collect::<Vec<_>>(),
                "node_agent": node_agent,
            })
        );
        return Ok(0);
    }

    let changed = body["changed"].as_array().cloned().unwrap_or_default();
    let skipped = body["bridges_skipped"].as_array().cloned().unwrap_or_default();
    let applied = body["applied"].as_u64().unwrap_or(0);

    println!("{}", ui::header("posture profile applied", Some(&profile)));
    if changed.is_empty() {
        println!("{}", ui::note("every gate already had the profile's value — nothing moved"));
    } else {
        println!("{}", ui::section("changed"));
        let rows: Vec<(String, String)> = changed
            .iter()
            .map(|r| {
                let from = match r["from"].as_str() {
                    Some(v) => v.to_string(),
                    None => "(unset)".to_string(),
                };
                (cell(&r["key"]), format!("{from} → {}", cell(&r["to"])))
            })
            .collect();
        print!("{}", ui::kv(&rows.iter().map(|(k, v)| (k.as_str(), v.clone())).collect::<Vec<_>>()));
    }

    if !skipped.is_empty() {
        println!("{}", ui::section("bridges left untouched"));
        let rows: Vec<(String, String)> = skipped
            .iter()
            .map(|b| {
                let value = match b["value"].as_str() {
                    Some(v) => v.to_string(),
                    None => "(unset)".to_string(),
                };
                (cell(&b["key"]), value)
            })
            .collect();
        print!("{}", ui::kv(&rows.iter().map(|(k, v)| (k.as_str(), v.clone())).collect::<Vec<_>>()));
        // An OPEN bridge is a weakening the operator should see every single
        // time they harden an install — not something to notice later.
        let open: Vec<&str> = skipped
            .iter()
            .filter(|b| b["open"] == json!(true))
            .filter_map(|b| b["key"].as_str())
            .collect();
        if open.is_empty() {
            println!("{}", ui::note("a profile never moves a rollout bridge — none of these is currently open"));
        } else {
            println!(
                "{}",
                ui::status_line(
                    Glyph::Warn,
                    &format!("still open: {} — this install is NOT fully hardened", open.join(", "))
                )
            );
            println!("{}", ui::note("close them when the last node has crossed: apply-profile --include-bridges, or posture set <key> 0"));
        }
    }

    print_mirror_outcome(&results);
    print_converge_outcome(&node_agent);
    ui::done(&format!("'{profile}' applied ({applied} key(s) written)"));
    ui::warned("restart the gateway to apply");
    ui::guide(&[
        ("noo stack restart gateway", "posture gates are read at start; the change is live after the restart"),
        ("noo security posture list", "every key, its kind (gate or bridge), and what is pending a restart"),
    ]);
    Ok(0)
}

// ── security service-key ────────────────────────────────────────────────────

/// Python `_print_issued` parity — the raw key is shown ONCE by design (the
/// gateway stores only its hash), so printing it here is the contract.
fn print_issued(body: &Value) {
    println!("{}", ui::header("service key issued", Some(&cell(&body["consumer"]))));
    let rpm = match &body["rpm_limit"] {
        Value::Null => "uncapped".to_string(),
        v => v.to_string(),
    };
    print!("{}", ui::kv(&[("consumer", cell(&body["consumer"])), ("scopes", cell(&body["scopes"])), ("rpm cap", rpm)]));
    println!("{}", ui::section("raw key (shown once, store it now)"));
    // The key itself: the captured value (plain; the only line under --quiet).
    ui::value(&cell(&body["key"]));
    println!();
    println!("{}", ui::muted("client config: base_url=https://<gateway>:8080/api/external, Authorization: Bearer <key>"));
    ui::guide(&[
        ("noo security service-key list", "shows every consumer and its last use"),
        (&format!("noo security service-key rotate {}", cell(&body["consumer"])), "mints a new key; the old one stays live until `retire`"),
    ]);
}

/// `noo security service-key issue CONSUMER [--scopes S]… [--note N] [--rpm N] [--user U]`
/// POST /api/security/service-keys. Scopes default to the full set.
///
/// `--user` binds the key to a `noo_users` account, which is the ONLY way an
/// operator can mint a key the external MCP door will accept: that door
/// refuses an unbound key (it would act with more authority than any human
/// account), and the alternative — `service-key self` — requires logging in
/// AS the consumer. The route has taken `user_id` since the door was built
/// and validates it against `noo_users`; the flag was simply never added, so
/// the documented CI-bot recipe failed as an unknown argument.
pub fn security_service_key_issue(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut consumer: Option<String> = None;
    let mut scopes: Vec<String> = Vec::new();
    let mut note: Option<String> = None;
    let mut rpm: Option<i64> = None;
    let mut user: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--scopes" => scopes.push(iter.next().ok_or(Unhandled)?.clone()),
            "--note" => note = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--rpm" => rpm = Some(iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?),
            "--user" => user = Some(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') && consumer.is_none() => consumer = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let consumer = consumer.ok_or(Unhandled)?;
    if scopes.is_empty() {
        scopes = SERVICE_KEY_SCOPES.iter().map(|s| s.to_string()).collect();
    }
    let body = post_json(
        g,
        "/api/security/service-keys",
        &json!({"consumer": consumer, "scopes": scopes, "note": note, "rpm": rpm, "user_id": user}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
    } else {
        print_issued(&body);
    }
    Ok(0)
}

/// Which revoked rows the table adds to the active ones.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Revoked {
    /// Default: none.
    Hidden,
    /// `--all`: the revoked keys a human issued, not the gateway's own
    /// retired add-on caller rows.
    Issued,
    /// `--callers`: every revoked row, the caller rows included.
    Every,
}

/// A row the gateway minted for itself to call add-ons (`addon_auth.rs`).
/// Same prefix the gateway's prune and the 077 view match.
fn is_addon_caller(k: &Value) -> bool {
    k["consumer"].as_str().is_some_and(|c| c.starts_with("addon-caller:"))
}

/// The rows the table shows: every active key (a superseded one is active
/// and waiting to be retired, so it stays), and revoked ones per [`Revoked`].
/// Every gateway start mints an `addon-caller:gateway` row and revokes the
/// previous, so a controller a few weeks old carried dozens of revoked rows
/// that buried the seven live keys (operator, 2026-09-24). The gateway now
/// prunes them after a week; `--all` still leaves the week's worth out,
/// because what `--all` is read for is the history of keys someone issued.
pub(crate) fn visible_keys(keys: &[Value], revoked: Revoked) -> Vec<&Value> {
    keys.iter()
        .filter(|k| {
            k["active"].as_bool().unwrap_or(false)
                || match revoked {
                    Revoked::Hidden => false,
                    Revoked::Issued => !is_addon_caller(k),
                    Revoked::Every => true,
                }
        })
        .collect()
}

/// Active keys that carry a RETIRED scope (the gateway's `retired_scopes`,
/// e.g. `kiosk` since the key lane went on 2026-09-30). The gateway refuses
/// them on every route already; they are listed so the operator revokes
/// them rather than reading them as live. Never revoked automatically.
pub(crate) fn retired_scope_keys(keys: &[&Value]) -> Vec<(String, String)> {
    keys.iter()
        .filter(|k| k["active"].as_bool().unwrap_or(false))
        .filter_map(|k| {
            let words: Vec<&str> = k["retired_scopes"].as_array()?.iter().filter_map(Value::as_str).collect();
            (!words.is_empty()).then(|| (cell(&k["consumer"]), words.join(",")))
        })
        .collect()
}

/// `noo security service-key list [--all] [--callers]` — GET
/// /api/security/service-keys (never shows raw keys — the gateway stores only
/// hashes). Active keys by default; `--all` adds the revoked ones a human
/// issued; `--callers` adds the gateway's retired add-on caller rows as well.
/// `--json` is always complete.
pub fn security_service_key_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut revoked = Revoked::Hidden;
    for a in args {
        match a.as_str() {
            "--all" if revoked == Revoked::Hidden => revoked = Revoked::Issued,
            "--all" => {}
            "--callers" => revoked = Revoked::Every,
            _ => return Err(Unhandled),
        }
    }
    let all = revoked != Revoked::Hidden;
    let body = get_json(g, "/api/security/service-keys", true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let every = body["keys"].as_array().unwrap_or(&empty);
    let keys = visible_keys(every, revoked);
    // Everything not shown is revoked; split it by what brings it back.
    let hidden_callers = if revoked == Revoked::Every {
        0
    } else {
        every.iter().filter(|k| !k["active"].as_bool().unwrap_or(false) && is_addon_caller(k)).count()
    };
    let hidden_issued = every.len() - keys.len() - hidden_callers;
    if every.is_empty() {
        println!("{}", ui::muted("no service keys"));
        ui::guide(&[("noo security service-key issue <consumer>", "mints a key for an external system; the raw key is shown once")]);
        return Ok(0);
    }
    let count = if all { format!("{} keys", keys.len()) } else { format!("{} active", keys.len()) };
    println!("{}", ui::header("service keys", Some(&count)));
    println!("{}", ui::section("keys"));
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            let active = k["active"].as_bool().unwrap_or(false);
            vec![
                ui::glyph_cell(if active { Glyph::Ok } else { Glyph::Warn }),
                cell(&k["consumer"]),
                super::truncate(&cell(&k["scopes"]), 34),
                // An unfinished rotation must READ as unfinished. "active"
                // beside "active" says two keys are fine; "superseded" says
                // one of them is waiting to be retired.
                if !active {
                    ui::warn("revoked")
                } else if k["retired_scopes"].as_array().is_some_and(|a| !a.is_empty()) {
                    // Refused on every route; still a row until revoked.
                    ui::warn("retired scope")
                } else if k["superseded_at"].is_string() {
                    ui::warn("superseded")
                } else {
                    ui::ok("active")
                },
                match &k["rpm_limit"] {
                    Value::Null => String::new(),
                    v => v.to_string(),
                },
                ts(&k["created_at"], ""),
                ts(&k["last_used_at"], "never"),
                cell(&k["note"]),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("consumer"),
                Col::left("scopes"),
                Col::left("state"),
                Col::right("rpm"),
                Col::left("created"),
                Col::left("last used"),
                Col::left("note"),
            ],
            &rows,
        )
    );
    if hidden_issued > 0 {
        println!("{}", ui::muted(&format!("{hidden_issued} revoked key(s) not shown — noo security service-key list --all")));
    }
    if hidden_callers > 0 {
        println!(
            "{}",
            ui::muted(&format!(
                "{hidden_callers} retired add-on caller row(s) not shown — noo security service-key list --callers"
            ))
        );
    }
    let retired = retired_scope_keys(&keys);
    if !retired.is_empty() {
        println!(
            "{}",
            ui::warn(&format!(
                "{} key(s) carry a retired scope and are refused on every route — revoke them:",
                retired.len()
            ))
        );
        let lines: Vec<(String, String)> = retired
            .iter()
            .map(|(c, s)| (format!("noo security service-key revoke {c}"), format!("retired scope: {s}")))
            .collect();
        let refs: Vec<(&str, &str)> = lines.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        ui::guide(&refs);
    }
    Ok(0)
}

#[cfg(test)]
mod service_key_list_tests {
    use super::{visible_keys, Revoked};

    #[test]
    fn a_retired_scope_key_is_named_with_its_revoke_command() {
        let keys = [
            serde_json::json!({"consumer": "kiosk-hall", "active": true, "scopes": ["kiosk"], "retired_scopes": ["kiosk"]}),
            serde_json::json!({"consumer": "ci-bot", "active": true, "scopes": ["chat"], "retired_scopes": []}),
            serde_json::json!({"consumer": "old", "active": false, "scopes": ["kiosk"], "retired_scopes": ["kiosk"]}),
            // A gateway that predates the field: nothing to say.
            serde_json::json!({"consumer": "legacy", "active": true, "scopes": ["kiosk"]}),
        ];
        let refs: Vec<&serde_json::Value> = keys.iter().collect();
        assert_eq!(
            super::retired_scope_keys(&refs),
            vec![("kiosk-hall".to_string(), "kiosk".to_string())],
            "only an ACTIVE key with a retired scope needs revoking"
        );
    }

    #[test]
    fn revoked_rows_are_hidden_by_default_and_superseded_ones_stay() {
        let keys = vec![
            serde_json::json!({ "consumer": "svc:worker", "active": true }),
            serde_json::json!({ "consumer": "svc:worker", "active": true, "superseded_at": "2026-09-24T19:22:46Z" }),
            serde_json::json!({ "consumer": "addon-caller:gateway", "active": false }),
        ];
        let shown: Vec<&str> = visible_keys(&keys, Revoked::Hidden).iter().map(|k| k["consumer"].as_str().unwrap()).collect();
        assert_eq!(shown, ["svc:worker", "svc:worker"], "a superseded key is active and awaiting retire");
        assert_eq!(visible_keys(&keys, Revoked::Every).len(), 3);
    }

    /// `--all` is read for the history of keys someone issued; the gateway's
    /// own retired caller rows (one per boot) stay out of it unless asked for.
    #[test]
    fn all_leaves_out_retired_caller_rows_and_callers_brings_them_back() {
        let keys = vec![
            serde_json::json!({ "consumer": "addon-caller:gateway", "active": true }),
            serde_json::json!({ "consumer": "addon-caller:gateway", "active": false }),
            serde_json::json!({ "consumer": "ci-bot", "active": false }),
            serde_json::json!({ "consumer": "x-addon-caller:gateway", "active": false }),
        ];
        let names = |r: Revoked| -> Vec<(String, bool)> {
            visible_keys(&keys, r)
                .iter()
                .map(|k| (k["consumer"].as_str().unwrap().to_string(), k["active"].as_bool().unwrap()))
                .collect()
        };
        assert_eq!(names(Revoked::Hidden), [("addon-caller:gateway".into(), true)], "the LIVE caller row always shows");
        assert_eq!(
            names(Revoked::Issued),
            [
                ("addon-caller:gateway".into(), true),
                ("ci-bot".into(), false),
                ("x-addon-caller:gateway".into(), false)
            ],
            "--all: a human-issued revoked key shows; a retired caller row does not"
        );
        assert_eq!(names(Revoked::Every).len(), 4);
    }
}

// ── self-service mcp key ────────────────────────────────────────────────────
//
// The CLI peer of the dashboard button. Same endpoint, so the two cannot
// drift: identity and scopes come from the caller's JWT server-side, and
// neither frontend can name a consumer or pick a scope set.

/// `noo security service-key self [--note LABEL]`
/// POST /api/security/service-keys/self — mint or rotate the CALLER's mcp key.
pub fn security_service_key_self(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut note: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--note" => note = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let body = post_json(
        g,
        "/api/security/service-keys/self",
        &json!({ "note": note }),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    if body["replaced_active"].as_u64().unwrap_or(0) > 0 {
        ui::warned("rotated: your previous key has been revoked and will stop working");
    }
    println!("{}", ui::header("mcp key issued", Some(&cell(&body["user_id"]))));
    print!("{}", ui::kv(&[("user", cell(&body["user_id"])), ("rpm cap", cell(&body["rpm_limit"]))]));
    println!("{}", ui::section("raw key (shown once, store it now)"));
    // The key itself: plain, on its own line, so a script can capture it.
    ui::value(&cell(&body["key"]));
    println!("{}", ui::section("add to ~/.claude.json under \"mcpServers\""));
    println!(
        "  \"mesh\": {{\n\
         \x20   \"type\": \"http\",\n\
         \x20   \"url\": \"https://<gateway>/mcp\",\n\
         \x20   \"headers\": {{ \"Authorization\": \"Bearer <key>\" }}\n\
         \x20 }}"
    );
    println!();
    println!("{}", ui::muted("the key carries your account: tool calls run with your scopes and knowledge-base access, not more"));
    ui::guide(&[
        ("noo security service-key self-status", "shows the key's id, cap and last use"),
        ("noo security service-key self-revoke", "kills it if it leaks"),
    ]);
    Ok(0)
}

/// `noo security service-key self-status` — GET /api/security/service-keys/self
pub fn security_service_key_self_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/security/service-keys/self", true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    if !body["active"].as_bool().unwrap_or(false) {
        println!("{}", ui::muted("no active MCP key"));
        ui::guide(&[("noo security service-key self", "issues your personal MCP key for Claude / MCP clients")]);
        return Ok(0);
    }
    println!("{}", ui::header("mcp key", Some(&cell(&body["user_id"]))));
    let last = &body["last_used_at"];
    print!(
        "{}",
        ui::kv(&[
            ("state", ui::ok("active")),
            ("issued", cell(&body["created_at"])),
            ("last used", if last.is_null() { "never".into() } else { cell(last) }),
            ("note", cell(&body["note"])),
        ])
    );
    println!();
    println!("{}", ui::muted("the raw key is not recoverable"));
    ui::guide(&[
        ("noo security service-key self", "re-issues your key (the old one is revoked)"),
        ("noo security service-key self-revoke", "revokes it without issuing a new one"),
    ]);
    Ok(0)
}

/// `noo security service-key self-revoke`
/// POST /api/security/service-keys/self/revoke.
pub fn security_service_key_self_revoke(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = post_json(
        g,
        "/api/security/service-keys/self/revoke",
        &json!({}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let n = body["revoked"].as_u64().unwrap_or(0);
    if n > 0 {
        ui::done("revoked your MCP key");
        println!("{}", ui::note("the gateway reflects this within ~60s (key cache TTL)"));
    } else {
        println!("{}", ui::muted("you have no active MCP key"));
    }
    ui::guide(&[("noo security service-key self", "issues a fresh key when you need MCP access again")]);
    Ok(0)
}

/// `noo security service-key revoke CONSUMER`
/// POST /api/security/service-keys/{c}/revoke.
/// `noo security service-key retire <consumer>` — finish a rotation.
///
/// POST /api/security/service-keys/{consumer}/retire. The gateway REFUSES
/// while the new key has not been seen in use, and that refusal is the
/// useful half: it is the difference between "I installed it" and "the
/// consumer is presenting it".
/// `noo security service-key provision <name> [--scopes <s>]... [--wait <secs>] [-y]`
///
/// Step 0 is the REQUEST: an add-on's overlay declares
/// the grant its key asks for (`x-noo-addon`), and this shows the operator
/// each word and the route it opens — from the gateway's own listing, not a
/// CLI copy — plus, on a rotate, what changes against the key in use. The
/// overlay only asks; the operator grants here. A TTY is asked y/N; `-y`
/// skips the question; a non-TTY without `-y` refuses rather than granting
/// unseen; `--json` without `-y` prints the request and mints nothing.
///
/// The four commands of an earlier release as one, and — the point — one that
/// cannot report a success it has not seen. Mint, store, recreate, then watch
/// `last_used_at`.
///
/// Each step's partial failure is handled as its own outcome rather than a
/// generic error, because three of the four look like success if you only
/// check the step you just ran:
///
///   * mint then store fails  -> the minted key is REVOKED before returning.
///     Left alone it sits in `service-key list` as a row whose `last_used_at`
///     is `never`, which is indistinguishable from a key that was installed
///     and simply has not been called yet.
///   * store then recreate fails -> reported, not celebrated. The value is in
///     the store and no container holds it, and the next reader of
///     `secrets audit` would assume it is live.
///   * everything works but nothing calls -> "installed, not yet in use",
///     with a non-zero exit. A key that is stored but never presented is
///     indistinguishable from no key at all (#258's rule, applied to a mint).
pub fn security_service_key_provision(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name: Option<String> = None;
    let mut scopes: Vec<String> = Vec::new();
    let mut wait_secs: u64 = 90;
    let mut yes = false;
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--scopes" => scopes.push(it.next().ok_or(Unhandled)?.to_string()),
            "--wait" => wait_secs = it.next().ok_or(Unhandled)?.parse().map_err(|_| Unhandled)?,
            "-y" | "--yes" => yes = true,
            s if !s.starts_with('-') && name.is_none() => name = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let name = name.ok_or(Unhandled)?;
    let Some(t) = crate::commands::secrets::provision_targets(&name) else {
        fail(
            g.json,
            ExitCode::Usage,
            "unknown_consumer",
            &format!("'{name}' is not a per-consumer key in the secret registry"),
            Some("`noo security secrets list` shows the NOO_SVC_KEY_* keys that exist"),
        );
    };
    let requested = scopes;
    // `addon` always, so the key can open the exchange door (see
    // provisioned_scopes). A key that cannot is half-provisioned.
    let scopes = crate::commands::secrets::provisioned_scopes(&t.consumer, &requested);

    // ── 0. is this consumer already provisioned? ─────────────────────────
    // Then ROTATE (supersede, #325) rather than issue a second active row.
    let listing = get_json(g, "/api/security/service-keys", true, TIMEOUT);
    let has_active = listing["keys"].as_array().map(|ks| ks.iter().any(|k| {
        k["consumer"].as_str() == Some(t.consumer.as_str()) && k["active"].as_bool().unwrap_or(false)
    })).unwrap_or(false);
    let mode = crate::commands::secrets::mint_mode(has_active);

    // ── 0b. the request: what is asked for, what it opens, confirm ───────
    // A gateway older than the listing answers 404: show the words without
    // routes and let the mint's own 400 speak, as before.
    let vocab = crate::http::get_json_try(g, "/api/security/service-keys/scopes", true, TIMEOUT).ok();
    let current = match mode {
        crate::commands::secrets::MintMode::Rotate => crate::commands::secrets::current_key(&listing, &t.consumer),
        crate::commands::secrets::MintMode::Issue => None,
    };
    let req = crate::commands::secrets::provision_request(&t.consumer, &requested, vocab.as_ref(), current);
    let stale_slice = t.overlay.as_deref().and_then(|o| {
        let text = std::fs::read_to_string(crate::envfile::repo_root().join(o)).ok()?;
        crate::commands::secrets::on_disk_scopes_differ(&text, crate::commands::secrets::default_scopes_for(&t.consumer))
            .map(|on_disk| (o.to_string(), on_disk))
    });
    if g.json && !yes {
        println!("{}", provision_request_json(&t, &req, mode, vocab.is_some(), stale_slice.as_ref()));
        return Ok(if req.refused.is_empty() { 0 } else { 1 });
    }
    if !g.json {
        render_provision_request(&t, &req, mode, vocab.is_some(), stale_slice.as_ref());
    }
    if !req.refused.is_empty() {
        let who = t.overlay.as_deref().map(|o| format!("{o} asks for")).unwrap_or_else(|| "requested".into());
        fail(
            g.json,
            ExitCode::Usage,
            "scope_refused",
            &format!("{who} {} — the gateway does not issue {}; nothing was minted",
                req.refused.join(", "), if req.refused.len() == 1 { "it" } else { "them" }),
            Some("GET /api/security/service-keys/scopes lists every word it issues; fix the overlay's x-noo-addon or pass --scopes"),
        );
    }
    if !yes {
        confirm_grant(&t.consumer)?;
    }

    // ── 1. mint ──────────────────────────────────────────────────────────
    let minted = match mode {
        crate::commands::secrets::MintMode::Issue => post_json(
            g,
            "/api/security/service-keys",
            &json!({ "consumer": t.consumer, "scopes": scopes }),
            true,
            TIMEOUT,
        ),
        crate::commands::secrets::MintMode::Rotate => post_json(
            g,
            &format!("/api/security/service-keys/{}/rotate", t.consumer),
            &json!({ "scopes": scopes }),
            true,
            TIMEOUT,
        ),
    };
    let Some(raw) = minted["key"].as_str().map(str::to_string) else {
        // post_json already printed the gateway's error.
        return Ok(1);
    };
    match mode {
        crate::commands::secrets::MintMode::Issue => ui::done(&format!("minted a key for '{}'", t.consumer)),
        crate::commands::secrets::MintMode::Rotate => ui::done(&format!(
            "rotated '{}' — the previous key stays live until the new one is proven", t.consumer)),
    }

    // ── 2. store ─────────────────────────────────────────────────────────
    let stored = crate::commands::secrets::store_provisioned(&t.secret_key, &raw);
    if let Err(why) = &stored {
        if mode == crate::commands::secrets::MintMode::Rotate {
            // Cannot revoke ONLY the new key: `/revoke` takes every active
            // key for the consumer, the previous one included. Say what is
            // true instead.
            return finish(
                g,
                &t,
                crate::commands::secrets::ProvisionOutcome::MintedNotStored,
                &format!("could not store it: {why}"),
            );
        }
        // REVOKE what we minted. An active row nobody holds is worse than no
        // row: it is the one state that reads as "installed, not yet called".
        let revoked = post_json(
            g,
            &format!("/api/security/service-keys/{}/revoke", t.consumer),
            &json!({}),
            true,
            TIMEOUT,
        );
        let n = revoked["revoked"].as_u64().unwrap_or(0);
        return finish(
            g,
            &t,
            crate::commands::secrets::ProvisionOutcome::MintedThenRevoked,
            &format!("could not store it: {why} — revoked {n} key(s) so none is left orphaned"),
        );
    }

    // ── 3. recreate ──────────────────────────────────────────────────────
    let root = crate::envfile::repo_root();
    let before: std::collections::BTreeMap<String, Option<String>> = t.containers.iter()
        .map(|c| (c.clone(), crate::commands::secrets::container_created_pub(c))).collect();
    // current_dir, which the first version of this omitted and the controller
    // caught within a minute: noomesh-restart.sh resolves `secrets/env.sops`
    // RELATIVE TO ITS CWD, so run from anywhere else it aborts with "secrets
    // load failed" before touching a container. `rotate` has always passed
    // this; the new verb had to as well, and did not.
    // Same binary as this process — see mesh.rs::run_script for why.
    let cli_bin = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    // Scoped: recreate the consumer's own container(s), not the stack. The
    // same decision the plan printed (a key change reaches the gateway
    // through the DB within its 60s cache TTL; nothing there needs a restart).
    let scope = crate::commands::secrets::launcher_scope(&t.containers, &container_prefix(), &crate::commands::secrets::DockerProbe);
    let st = match scope.launcher_args() {
        Some(args) => {
            if let crate::commands::secrets::LauncherScope::Full { reason } = &scope {
                println!("{}", ui::muted(&format!("restarting the whole stack: {reason}")));
            }
            std::process::Command::new("bash")
                .arg(root.join("scripts/noomesh-restart.sh"))
                .args(&args)
                .current_dir(&root)
                .env("NOO_CLI_BIN", &cli_bin)
                .status()
        }
        None => Ok(std::process::ExitStatus::default()),
    };
    if !matches!(st, Ok(s) if s.success()) {
        // Name the launcher, not the consumers. "a consumer did not come back"
        // is true here and sends the reader to look at containers, when what
        // failed was the script — which printed its own reason above.
        return finish(
            g,
            &t,
            crate::commands::secrets::ProvisionOutcome::StoredNotRecreated,
            "the launcher failed (its error is above); the value IS in the store",
        );
    }
    let after: std::collections::BTreeMap<String, Option<String>> = t.containers.iter()
        .map(|c| (c.clone(), crate::commands::secrets::container_created_pub(c))).collect();
    // The launcher's exit status says the launcher ran, not that every
    // consumer was recreated (#258). Same verdict function `rotate` uses, so
    // there is one answer to "was this container recreated", not two.
    let verdicts = crate::commands::secrets::recreate_verdicts(&t.containers, &before, &after);
    let stale: Vec<&str> = verdicts.iter()
        .filter(|(_, v)| matches!(v, crate::commands::secrets::RecreateVerdict::Unchanged
                                    | crate::commands::secrets::RecreateVerdict::Vanished))
        .map(|(c, _)| c.as_str())
        .collect();
    if !stale.is_empty() {
        return finish(
            g,
            &t,
            crate::commands::secrets::ProvisionOutcome::StoredNotRecreated,
            &format!("these consumers did not come back on the new value: {}", stale.join(", ")),
        );
    }

    // ── 4. prove it is in use ────────────────────────────────────────────
    println!("{}", ui::muted(&format!("waiting up to {wait_secs}s for '{}' to present it", t.consumer)));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    let mut used = false;
    while std::time::Instant::now() < deadline {
        // TOLERANT, not fatal: this verb just recreated the gateway, and the
        // first poll after a recreate lands before it listens. The fatal
        // `get_json` here aborted the whole verb with "Connection refused"
        // on the controller (2026-09-22) — after the rotate had succeeded
        // and the new key was already in use. A refused connection during
        // the wait is "not yet", and only the deadline says "no".
        if let Ok(body) = crate::http::get_json_try(g, "/api/security/service-keys", true, TIMEOUT) {
            if let Some(keys) = body["keys"].as_array() {
                used = crate::commands::secrets::proven_in_use(keys, &t.consumer);
            }
        }
        if used {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    let outcome = crate::commands::secrets::classify_provision(mode, true, true, used);
    if outcome.is_success() && mode == crate::commands::secrets::MintMode::Rotate {
        // Proven in use: finish the rotation. `retire` refuses on its own if
        // the new key has somehow not been seen, so this cannot strand it.
        let r = post_json(g, &format!("/api/security/service-keys/{}/retire", t.consumer), &json!({}), true, TIMEOUT);
        let n = r["retired"].as_u64().unwrap_or(0);
        return finish(g, &t, outcome, &format!("retired {n} superseded key(s)"));
    }
    finish(g, &t, outcome, "")
}

/// The compose container-name prefix of this instance (`noo` by default).
fn container_prefix() -> String {
    crate::envfile::container_prefix()
}

/// The request `provision` shows before minting, as JSON (`--json` without
/// `-y`: the plan, nothing minted).
fn provision_request_json(
    t: &crate::commands::secrets::ProvisionTargets,
    req: &crate::commands::secrets::ProvisionRequest,
    mode: crate::commands::secrets::MintMode,
    vocab_known: bool,
    stale: Option<&(String, Vec<String>)>,
) -> Value {
    json!({
        "consumer": t.consumer,
        "secret": t.secret_key,
        "containers": t.containers,
        "recreate_plan": crate::commands::secrets::launcher_scope(&t.containers, &container_prefix(), &crate::commands::secrets::DockerProbe).plan_line(),
        "addon": t.addon,
        "declared_in": t.overlay.clone().unwrap_or_else(|| "core service (docker-compose.cluster.yml)".into()),
        "declared": req.declared,
        "override": req.overridden,
        "mode": match mode {
            crate::commands::secrets::MintMode::Issue => "issue",
            crate::commands::secrets::MintMode::Rotate => "rotate",
        },
        "scopes": req.rows.iter().map(|(s, o)| json!({ "scope": s, "opens": o })).collect::<Vec<_>>(),
        "routes_known": vocab_known,
        "refused": req.refused,
        "diff": req.diff.as_ref().map(|(a, r)| json!({ "added": a, "removed": r })),
        "on_disk_overlay_differs": stale.map(|(o, s)| json!({ "overlay": o, "scopes": s })),
        "minted": false,
        "hint": "pass -y to grant and mint",
    })
}

pub(crate) fn render_provision_request(
    t: &crate::commands::secrets::ProvisionTargets,
    req: &crate::commands::secrets::ProvisionRequest,
    mode: crate::commands::secrets::MintMode,
    vocab_known: bool,
    stale: Option<&(String, Vec<String>)>,
) {
    let who = t.addon.as_deref().map(|a| a.replace('_', "-")).unwrap_or_else(|| {
        t.consumer.trim_start_matches("svc:").to_string()
    });
    let whence = t.overlay.as_deref().map(|o| format!("declared in {o}"))
        .unwrap_or_else(|| "core service (docker-compose.cluster.yml)".into());
    println!("{}", ui::header(&format!("{who} asks for a gateway key"), Some(&whence)));
    println!("{}", ui::kv(&[
        ("consumer", t.consumer.clone()),
        ("store key", t.secret_key.clone()),
        ("recreates", crate::commands::secrets::launcher_scope(&t.containers, &container_prefix(), &crate::commands::secrets::DockerProbe).plan_line()),
    ]));
    if let Some(why) = t.addon.as_deref().and_then(crate::commands::secrets::addon_decl).and_then(|d| d.why) {
        println!("{}", ui::note(why));
    }
    let rows: Vec<Vec<String>> = req.rows.iter().map(|(s, opens)| {
        let what = if req.refused.contains(s) {
            ui::err("REFUSED — the gateway does not issue this word")
        } else if s == "addon" {
            format!("{} {}", opens.join(", "), ui::muted("(always added)"))
        } else if opens.is_empty() {
            ui::muted(if vocab_known { "-" } else { "(this gateway does not list routes)" })
        } else {
            opens.join(", ")
        };
        vec![s.clone(), what]
    }).collect();
    print!("{}", ui::table(&[Col::left("scope"), Col::left("opens")], &rows));
    if req.overridden {
        println!("{}", ui::note(&format!("operator override (--scopes); the declaration asks for: {}",
            req.declared.join(", "))));
    }
    if let Some((added, removed)) = &req.diff {
        let list = |v: &Vec<String>| if v.is_empty() { "(none)".to_string() } else { v.join(", ") };
        println!("{}", ui::kv(&[(
            "vs current key",
            format!("+ {}   − {}", list(added), list(removed)),
        )]));
    }
    if let Some((overlay, on_disk)) = stale {
        println!("{}", ui::status_line(Glyph::Warn, &format!(
            "~/.noo's {overlay} asks for {}; this noo was released asking for the above — \
             run `noo upgrade --stack` to align them",
            on_disk.join(", "))));
    }
    if mode == crate::commands::secrets::MintMode::Rotate {
        println!("{}", ui::muted("an active key exists: this ROTATES it (the previous key stays live until the new one is proven)"));
    }
}

/// Ask y/N on a TTY. A non-TTY without `-y` refuses: a grant nobody saw is
/// the thing this step exists to prevent.
fn confirm_grant(consumer: &str) -> Result<(), Unhandled> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};
    if !std::io::stdin().is_terminal() {
        fail(
            false,
            ExitCode::Usage,
            "confirmation_required",
            &format!("not granting {consumer} a key unseen: stdin is not a terminal"),
            Some("read the request above, then re-run with -y (or --json to print it without minting)"),
        );
    }
    eprint!("Grant these to {consumer}? [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        eprintln!("Not granted — nothing was minted.");
        std::process::exit(ExitCode::Generic as i32);
    }
    Ok(())
}

/// Report one outcome, and return the exit status it deserves.
fn finish(
    g: &Globals,
    t: &crate::commands::secrets::ProvisionTargets,
    outcome: crate::commands::secrets::ProvisionOutcome,
    detail: &str,
) -> Result<i32, Unhandled> {
    use crate::commands::secrets::ProvisionOutcome as O;
    if g.json {
        println!("{}", json!({
            "consumer": t.consumer,
            "secret": t.secret_key,
            "outcome": format!("{outcome:?}"),
            "success": outcome.is_success(),
            "detail": detail,
        }));
        return Ok(if outcome.is_success() { 0 } else { 1 });
    }
    match outcome {
        O::InUse => {
            ui::done(&format!("'{}' is live: minted, stored, recreated, and PRESENTED{}", t.consumer,
                if detail.is_empty() { String::new() } else { format!(" — {detail}") }));
            println!("{}", ui::note(
                "the key has authenticated a real call — that, not the install, is what \
                 makes it in use",
            ));
        }
        O::InstalledNotYetUsed => {
            println!("{}", ui::status_line(Glyph::Warn, &format!(
                "'{}' is installed but has NOT been presented yet", t.consumer)));
            println!("{}", ui::note(
                "not a failure and not success. An idle consumer may not call for minutes; \
                 a misconfigured one never will, and the two look identical until it does",
            ));
            println!("{}", ui::hint("noo security service-key list"));
        }
        O::MintedThenRevoked => {
            println!("{}", ui::status_line(Glyph::Err, &format!(
                "'{}' was NOT provisioned — {detail}", t.consumer)));
            println!("{}", ui::note(
                "nothing was left behind: an active key no container holds reads exactly \
                 like one that is installed and simply has not been called",
            ));
        }
        O::MintedNotStored => {
            println!("{}", ui::status_line(Glyph::Err, &format!(
                "'{}' rotated but NOT stored — {detail}", t.consumer)));
            println!("{}", ui::note(
                "the previous key keeps working, so nothing is broken. The new key is active \
                 and unused, and cannot be revoked on its own without taking the previous one \
                 too — run `provision` again: it supersedes both and retires both once the \
                 newest is proven",
            ));
        }
        O::StoredNotRecreated => {
            println!("{}", ui::status_line(Glyph::Err, &format!(
                "'{}' is stored but not live — {detail}", t.consumer)));
            println!("{}", ui::note(
                "the consumer keeps its previous credential, so nothing is broken — but \
                 `secrets audit` will show a stored key that nothing presents",
            ));
            println!("{}", ui::hint("noo stack restart --force"));
        }
    }
    Ok(if outcome.is_success() { 0 } else { 1 })
}

pub fn security_service_key_retire(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut consumer: Option<String> = None;
    for tok in args {
        match tok.as_str() {
            s if !s.starts_with('-') && consumer.is_none() => consumer = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let consumer = consumer.ok_or(Unhandled)?;
    let body = post_json(
        g,
        &format!("/api/security/service-keys/{consumer}/retire"),
        &json!({}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let n = body["retired"].as_u64().unwrap_or(0);
    if n == 0 {
        println!("{}", ui::muted(&format!(
            "nothing retired for '{consumer}' — see the error above, or there was no \
             superseded key left to retire"
        )));
        return Ok(0);
    }
    ui::done(&format!("retired {n} superseded key(s) for '{consumer}'"));
    println!("{}", ui::note(
        "the rotation is finished: only the key the consumer is actually presenting is \
         active now",
    ));
    Ok(0)
}

pub fn security_service_key_revoke(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    // `--disable-account` is the kill switch. Revoking a key
    // stops the NEXT mint; a token already issued keeps working until it
    // expires. Disabling the bound account is what reaches those, because
    // the gateway re-checks a delegated token's subject on every request.
    // An operator stopping a runaway agent almost always means both, and
    // the gateway does them in one transaction so there is no half-state.
    let mut consumer: Option<String> = None;
    let mut disable_account = false;
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--disable-account" => disable_account = true,
            "--yes" | "-y" => yes = true,
            s if !s.starts_with('-') && consumer.is_none() => consumer = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let consumer = consumer.ok_or(Unhandled)?;
    // Irreversible: a revoked key cannot be brought back, only replaced, and
    // --disable-account also locks the bound user out.
    super::confirm_destructive(
        g,
        yes,
        if disable_account { "revoke every key of, and DISABLE the bound account of," } else { "revoke every key of" },
        &format!("consumer '{consumer}'"),
    );
    let path = if disable_account {
        format!("/api/security/service-keys/{consumer}/revoke-and-disable")
    } else {
        format!("/api/security/service-keys/{consumer}/revoke")
    };
    let body = post_json(g, &path, &json!({}), true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let n = body["revoked"].as_u64().unwrap_or(0);
    if disable_account {
        // The gateway refuses an unbound key rather than doing half the
        // job, so a missing `user_id` here means the call did not happen —
        // say so instead of printing a success line for nothing.
        match body["user_id"].as_str() {
            Some(user) => {
                ui::done(&format!("revoked {n} key(s) for '{consumer}' and disabled '{user}'"));
                println!("{}", ui::note(
                    "tokens already issued stop working within ~10s — the account is \
                     re-checked on every request made with a delegated token",
                ));
            }
            None => {
                println!("{}", ui::muted(&format!(
                    "nothing changed for '{consumer}' — see the error above; a key bound to no \
                     account has nothing to disable, so use `revoke` without --disable-account",
                )));
                return Ok(1);
            }
        }
    } else if n > 0 {
        ui::done(&format!("revoked {n} key(s) for '{consumer}'"));
        println!("{}", ui::note("the gateway reflects this within ~60s (key cache TTL)"));
        println!("{}", ui::note(
            "tokens ALREADY minted from this key keep working until they expire (up to 5 min). \
             To stop those too: --disable-account",
        ));
    } else {
        println!("{}", ui::muted(&format!("no active keys found for '{consumer}'")));
    }
    ui::guide(&[
        ("noo security service-key list", "confirms nothing active remains for the consumer"),
        (&format!("noo security service-key issue {consumer} --scope <scope>"), "issues a replacement if the consumer still needs access"),
    ]);
    Ok(0)
}

/// The scopes a rotation should carry when `--scopes` is not given: those of
/// the consumer's newest ACTIVE key, minus any the gateway has retired (it
/// refuses those on issue). `None` when the consumer holds no active key,
/// so the caller falls back to the default set. The gateway lists keys
/// oldest first, so the last matching row is the newest.
pub(crate) fn current_scopes(keys: &[Value], consumer: &str) -> Option<Vec<String>> {
    let key = keys
        .iter()
        .rev()
        .find(|k| k["consumer"].as_str() == Some(consumer) && k["active"].as_bool().unwrap_or(false))?;
    let words = |v: &Value| -> Vec<String> {
        v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
    };
    let retired = words(&key["retired_scopes"]);
    let kept: Vec<String> = words(&key["scopes"]).into_iter().filter(|s| !retired.contains(s)).collect();
    (!kept.is_empty()).then_some(kept)
}

/// `noo security service-key rotate CONSUMER [--scopes S]… [--note N]`
/// POST /api/security/service-keys/{c}/rotate (rpm quota is preserved).
/// The gateway SUPERSEDES the previous keys (they stay live until `retire`);
/// without `--scopes` the new key keeps the current key's scopes.
pub fn security_service_key_rotate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut consumer: Option<String> = None;
    let mut scopes: Vec<String> = Vec::new();
    let mut note: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--scopes" => scopes.push(iter.next().ok_or(Unhandled)?.clone()),
            "--note" => note = Some(iter.next().ok_or(Unhandled)?.clone()),
            s if !s.starts_with('-') && consumer.is_none() => consumer = Some(s.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let consumer = consumer.ok_or(Unhandled)?;
    let mut kept = false;
    if scopes.is_empty() {
        // Rotating must not silently narrow (or widen) a key: carry the
        // current scopes across, as the gateway carries the quota and user.
        let listing = get_json(g, "/api/security/service-keys", true, TIMEOUT);
        let keys = listing["keys"].as_array().cloned().unwrap_or_default();
        match current_scopes(&keys, &consumer) {
            Some(current) => {
                scopes = current;
                kept = true;
            }
            None => scopes = SERVICE_KEY_SCOPES.iter().map(|s| s.to_string()).collect(),
        }
    }
    let body = post_json(
        g,
        &format!("/api/security/service-keys/{consumer}/rotate"),
        &json!({"scopes": scopes, "note": note}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    print_issued(&body);
    if kept {
        println!("{}", ui::muted("scopes kept from the current key (pass --scopes to change them)"));
    }
    ui::warned("the previous key(s) are still live: switch the consumer to the new key, then retire the old");
    ui::guide(&[
        ("noo security service-key list", "shows the new key and the old one as superseded"),
        (&format!("noo security service-key retire {consumer}"), "deactivates the superseded key once the new one has been used"),
        (&format!("noo security service-key set-quota {consumer} <rpm>"), "re-applies a rate cap; rotation keeps the consumer's cap as issued"),
    ]);
    Ok(0)
}

/// `noo security service-key set-quota CONSUMER RPM`
/// POST /api/security/service-keys/{c}/quota (0 = uncapped).
pub fn security_service_key_set_quota(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [consumer, rpm_raw] = positional::<2>(args)?;
    let rpm: i64 = rpm_raw.parse().map_err(|_| Unhandled)?;
    let body = post_json(
        g,
        &format!("/api/security/service-keys/{consumer}/quota"),
        &json!({"rpm": rpm}),
        true,
        TIMEOUT,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let shown = match &body["rpm_limit"] {
        Value::Null => "uncapped".to_string(),
        v => v.to_string(),
    };
    ui::done(&format!(
        "rpm cap for '{consumer}' set to {shown}  {}",
        ui::muted(&format!("{} active key(s)", body["updated_keys"].as_u64().unwrap_or(0)))
    ));
    ui::guide(&[("noo security service-key list", "shows the cap next to each active key")]);
    Ok(0)
}

// ── arg-parsing helper ──────────────────────────────────────────────────────

/// Exactly N positional arguments, no flags — anything else is `Unhandled`
/// (Python serves the rich usage error, matching the other command modules).
fn positional<const N: usize>(args: &[String]) -> Result<[String; N], Unhandled> {
    if args.len() != N || args.iter().any(|a| a.starts_with('-')) {
        return Err(Unhandled);
    }
    let mut out: Vec<String> = args.to_vec();
    out.truncate(N);
    out.try_into().map_err(|_| Unhandled)
}

#[cfg(test)]
mod posture_mirror_tests {
    use super::*;

    fn w(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// R43, the split-brain half. `apply-profile` wrote the bus-bridge row to
    /// 0 and left `.env` saying 1: the gateway consulted the row and refused
    /// to serve, the workers and the node-agent consulted the environment and
    /// carried on. The mirror rule lived inside `security_posture_set` and no
    /// other command could reach it.
    ///
    /// This asserts the rule is a shared FUNCTION over "keys I just wrote",
    /// which is the only shape both commands can share. It fails on the old
    /// code because there was no such function — the rule was an inline
    /// `if POSTURE_KEYS_MIRRORED_TO_ENV.contains(...)` in one command body.
    /// A stand-in pre-DB gate: the shipped list is empty since an earlier release
    /// retired its only entry, and the rule must stay pinned for the next one.
    const MIRRORED: &[&str] = &["NOO_EXAMPLE_PRE_DB_GATE"];

    #[test]
    fn a_mirrored_key_is_mirrored_whoever_wrote_it() {
        let from_profile = w(&[
            ("NOO_EXEC_APPROVAL_MODE", "approval"),
            ("NOO_EXAMPLE_PRE_DB_GATE", "0"),
        ]);
        let targets = keys_to_mirror_from(MIRRORED, &from_profile);
        assert_eq!(
            targets,
            w(&[("NOO_EXAMPLE_PRE_DB_GATE", "0")]),
            "a profile that writes a pre-DB gate must mirror it into .env, \
             or the gateway and the workers disagree"
        );

        // Same rule, same answer, from the single-key command.
        let from_set = w(&[("NOO_EXAMPLE_PRE_DB_GATE", "1")]);
        assert_eq!(keys_to_mirror_from(MIRRORED, &from_set).len(), 1);
    }

    /// The node-agent gate was cosmetic: `POSTURE_KEYS_MIRRORED_TO_ENV` was
    /// empty and only compose interpolation reads the key. It now reaches
    /// `.env`, whoever wrote it.
    #[test]
    fn the_node_agent_gate_is_mirrored_for_compose() {
        let from_profile = w(&[("NOO_NODE_AGENT_PRIVILEGED", "false"), ("NOO_EXEC_APPROVAL_MODE", "approval")]);
        assert_eq!(keys_to_mirror(&from_profile), w(&[("NOO_NODE_AGENT_PRIVILEGED", "false")]));
    }

    #[test]
    fn docker_inspect_answers_are_parsed_without_guessing() {
        let p = |ok, out, err| parse_privileged_inspect(ok, out, err, "noo-node-agent");
        assert_eq!(p(true, "true\n", ""), Ok(true));
        assert_eq!(p(true, "false\n", ""), Ok(false));
        assert!(p(false, "", "Error: No such object: noo-node-agent").unwrap_err().contains("no noo-node-agent container"));
        assert!(p(false, "", "").unwrap_err().contains("failed with no message"));
        assert!(p(true, "<no value>", "").is_err(), "garbage is not unprivileged");
    }

    /// "At desired" has to mean the container: a privileged container under a
    /// `false` row is drift, an unreadable container is not a match.
    #[test]
    fn the_listing_reports_the_container_not_the_gateways_env() {
        assert_eq!(privileged_drift(Some("false"), Some(true)), Some(true));
        assert_eq!(privileged_drift(Some("false"), Some(false)), Some(false));
        assert_eq!(privileged_drift(Some("true"), Some(true)), Some(false));
        assert_eq!(privileged_drift(None, Some(true)), None);
        assert_eq!(privileged_drift(Some("false"), None), None);
        let mut body = json!({"posture": [
            {"key": "NOO_NODE_AGENT_PRIVILEGED", "running": "false", "db_value": "false"},
            {"key": "NOO_EXEC_APPROVAL_MODE", "running": "strict", "db_value": "strict"},
        ]});
        annotate_actual(&mut body, &Ok(true));
        assert_eq!(body["posture"][0]["actual"], "true");
        assert_eq!(body["posture"][0]["actual_drift"], true);
        assert!(body["posture"][1]["actual"].is_null(), "only the container-backed gate is annotated");
        let mut body = json!({"posture": [{"key": "NOO_NODE_AGENT_PRIVILEGED", "running": "false", "db_value": "false"}]});
        annotate_actual(&mut body, &Err("no container".into()));
        assert_eq!(body["posture"][0]["actual_error"], "no container");
        assert!(body["posture"][0]["actual"].is_null());
    }

    /// The retired bus bridge is no longer mirrored — a posture
    /// write of it (an unknown key now) must not re-create a `.env` line.
    #[test]
    fn the_retired_bus_bridge_is_not_mirrored() {
        assert!(keys_to_mirror(&w(&[("NOO_NATS_LEGACY_SHARED_CREDS", "1")])).is_empty());
    }

    #[test]
    fn an_unmirrored_key_is_left_alone() {
        // Mirroring everything would put security gates into `.env`, where a
        // write-scope user could reach them — the opposite of posture.
        let only_gates = w(&[
            ("NOO_EXEC_APPROVAL_MODE", "strict"),
            ("NOO_MCP_EXTERNAL_ENABLED", "0"),
        ]);
        assert!(keys_to_mirror_from(MIRRORED, &only_gates).is_empty());
    }

    /// The mirror must fire for a key the profile did NOT change, too. An
    /// unchanged DB row can still sit opposite a stale `.env` line — which is
    /// precisely the state host8 was left in, and re-running the command
    /// would have "changed nothing" and fixed nothing.
    #[test]
    fn an_unchanged_row_still_gets_mirrored() {
        let unchanged_but_mirrored = w(&[("NOO_EXAMPLE_PRE_DB_GATE", "0")]);
        assert_eq!(keys_to_mirror_from(MIRRORED, &unchanged_but_mirrored).len(), 1);
    }

    #[test]
    fn truthy_values_cover_what_an_operator_types() {
        for on in ["1", "true", "TRUE", "yes", "on", " 1 "] {
            assert!(truthy_posture_value(on), "{on} should be truthy");
        }
        for off in ["0", "false", "no", "off", "", "  "] {
            assert!(!truthy_posture_value(off), "{off} should be falsy");
        }
    }

    /// Every mirrored key must be one the gateway also knows about. A typo
    /// here would write a `.env` line no reader consults, and the command
    /// would report a successful mirror.
    #[test]
    fn mirrored_keys_are_spelled_like_posture_keys() {
        for key in POSTURE_KEYS_MIRRORED_TO_ENV {
            assert!(
                key.starts_with("NOO_") && key.to_uppercase() == **key,
                "{key} is not an env-var-shaped posture key"
            );
        }
    }
}


#[cfg(test)]
mod audit_verify_export_tests {
    use super::*;

    #[test]
    fn a_regression_is_an_error_and_names_the_exported_head() {
        let (g, t) = exported_head_line(&json!({"checked": true, "regression": true,
            "last_exported": {"seq": 10, "time": "2026-10-19T04:00:00+00:00"}}));
        assert!(matches!(g, Glyph::Err));
        assert!(t.contains("BEHIND") && t.contains("seq 10"), "{t}");
    }

    #[test]
    fn an_intact_head_is_ok_and_an_uncompared_one_is_never_ok() {
        let (g, _) = exported_head_line(&json!({"checked": true, "regression": false,
            "last_exported": {"seq": 4, "time": "t"}}));
        assert!(matches!(g, Glyph::Ok));
        for v in [json!(null), json!({"checked": false, "note": "NOT CHECKED: no file"}), json!({})] {
            let (g, t) = exported_head_line(&v);
            assert!(matches!(g, Glyph::Warn), "{v}");
            assert!(t.contains("NOT CHECKED"), "{t}");
        }
    }
}

#[cfg(test)]
mod admin_password_reset_tests {
    /// The function body, from its signature to the next top-level fn.
    fn body() -> &'static str {
        let src = include_str!("security.rs");
        let src = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        let start = src.find("pub fn security_admin_password_reset").expect("the verb exists");
        let rest = &src[start..];
        &rest[..rest[1..].find("\npub fn ").map(|i| i + 1).unwrap_or(rest.len())]
    }

    /// Whether the new password may be printed is decided BEFORE the old one
    /// stops working. The other order changes the login and then refuses to
    /// say what it became — a lockout. Pinned as source because the property
    /// is the order of three calls, not any one call's result.
    #[test]
    fn the_output_is_judged_before_the_password_changes() {
        let b = body();
        let guard = b.find("reveal_guard(").expect("uses the reveal destination rule");
        let mint = b.find("token_urlsafe(").expect("generates the new password");
        let change = b.find("host_access::reset_admin(").expect("changes the login");
        assert!(guard < mint && mint < change, "guard → generate → change, in that order");
    }

    /// The stored copy is updated AFTER the login changes, never instead of it.
    #[test]
    fn the_store_follows_the_login() {
        let b = body();
        assert!(b.find("host_access::reset_admin(").unwrap() < b.find("store_upsert(").expect("keeps the store honest"));
    }

    /// The recovery path cannot need what it recovers: no login, no gateway
    /// route, no shared secret. It writes the account on the host.
    #[test]
    fn the_reset_needs_no_login_and_no_secret() {
        let b = body();
        for needle in ["put_json(", "post_json(", "operator_login(", "auth::resolve(", "auth::bearer(", "NOO_CONTROLLER_SECRET", "cluster_token("] {
            assert!(!b.contains(needle), "the reset must not depend on {needle}");
        }
        let change = b.find("host_access::reset_admin(").unwrap();
        let login = b.find("login_and_store(").expect("logs in with the new password afterwards");
        assert!(change < login, "the login follows the reset");
    }

    /// A --ci install must point at a command that works. It pointed at
    /// `secrets reveal NOO_ADMIN_PASSWORD`, which the allow-list refuses.
    #[test]
    fn the_wizard_points_at_the_reset_not_the_refused_reveal() {
        let steps = include_str!("../onboard/steps.rs");
        assert!(steps.contains("noo security admin-password reset"));
        assert!(!steps.contains("secrets reveal NOO_ADMIN_PASSWORD"));
    }
}

#[cfg(test)]
mod clifix_security_tests {
    use super::*;

    /// The body of the first `pub fn` named `sig` (up to the next top-level item).
    fn body_of<'a>(src: &'a str, sig: &str) -> &'a str {
        let start = src.find(sig).unwrap_or_else(|| panic!("{sig} not found"));
        let rest = &src[start + sig.len()..];
        let end = rest.find("\n}\n").map(|i| i + 3).unwrap_or(rest.len());
        &rest[..end]
    }

    /// A confirmation that comes after the request is a notice, not a gate.
    fn confirm_precedes(src: &str, sig: &str, request: &str) {
        let body = body_of(src, sig);
        let c = body.find("confirm_destructive(").unwrap_or_else(|| panic!("{sig} never confirms"));
        let r = body.find(request).unwrap_or_else(|| panic!("{sig} never calls {request}"));
        assert!(c < r, "{sig} must confirm BEFORE {request}");
    }

    /// The shape the gateway's list handler sends (`service_keys_list`):
    /// oldest first, scopes as an array, `retired_scopes` on every row.
    fn listing() -> Vec<Value> {
        vec![
            json!({"consumer": "ci", "scopes": ["chat"], "retired_scopes": [], "active": false}),
            json!({"consumer": "ci", "scopes": ["chat", "mcp:operator"], "retired_scopes": [], "active": true, "superseded_at": "2026-10-01T00:00:00Z"}),
            json!({"consumer": "ci", "scopes": ["chat", "embeddings", "kiosk"], "retired_scopes": ["kiosk"], "active": true, "superseded_at": null}),
            json!({"consumer": "other", "scopes": ["rerank"], "retired_scopes": [], "active": true}),
        ]
    }

    #[test]
    fn rotate_keeps_the_newest_active_keys_scopes_and_drops_retired_words() {
        assert_eq!(current_scopes(&listing(), "ci"), Some(vec!["chat".to_string(), "embeddings".to_string()]));
        assert_eq!(current_scopes(&listing(), "other"), Some(vec!["rerank".to_string()]));
    }

    #[test]
    fn rotate_falls_back_to_the_defaults_only_when_nothing_is_active() {
        assert_eq!(current_scopes(&listing(), "nobody"), None);
        let revoked = vec![json!({"consumer": "gone", "scopes": ["chat"], "active": false})];
        assert_eq!(current_scopes(&revoked, "gone"), None);
    }

    #[test]
    fn rotate_does_not_claim_the_old_key_was_revoked() {
        let body = body_of(include_str!("security.rs"), "pub fn security_service_key_rotate(");
        assert!(!body.contains("were revoked"), "the gateway supersedes; it does not revoke");
        assert!(body.contains("still live"));
        assert!(body.contains("service-key retire"), "the next step is retire");
    }

    /// `POST /api/users/disable` reads `{username, disabled: bool}`
    /// (`api_users_disable`); anything else is a 400 "disabled (bool) required".
    #[test]
    fn enable_sends_the_body_the_gateway_handler_reads() {
        let b = enable_body("alice");
        assert_eq!(b["username"], "alice");
        assert_eq!(b["disabled"], Value::Bool(false), "a bool false, not a string and not absent");
        assert_eq!(b.as_object().unwrap().len(), 2);
        let src = body_of(include_str!("security.rs"), "pub fn security_user_enable(");
        assert!(src.contains("\"/api/users/disable\""), "the per-user /disable route only disables");
    }

    #[test]
    fn team_delete_uses_the_path_route_and_passes_force_as_the_query_flag() {
        assert_eq!(team_delete_path("eng", false), "/api/security/teams/eng");
        assert_eq!(team_delete_path("eng", true), "/api/security/teams/eng?force=true");
        let src = body_of(include_str!("security.rs"), "pub fn security_team_delete(");
        assert!(!src.contains("kb/teams"), "the legacy POST route is for the console only");
    }

    #[test]
    fn username_and_yes_takes_one_name_and_the_flag_in_either_order() {
        let a = |v: &[&str]| username_and_yes(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).ok();
        assert_eq!(a(&["bob"]), Some(("bob".into(), false)));
        assert_eq!(a(&["-y", "bob"]), Some(("bob".into(), true)));
        assert_eq!(a(&["bob", "--yes"]), Some(("bob".into(), true)));
        assert_eq!(a(&[]), None);
        assert_eq!(a(&["bob", "alice"]), None);
        assert_eq!(a(&["bob", "--force"]), None);
    }

    #[test]
    fn destructive_verbs_confirm_before_they_call_the_gateway() {
        let src = include_str!("security.rs");
        confirm_precedes(src, "pub fn security_user_disable(", "post_json(");
        confirm_precedes(src, "pub fn security_service_key_revoke(", "post_json(");
        confirm_precedes(src, "pub fn security_team_delete(", "delete_json(");
    }
}

#[cfg(test)]
mod password_policy_tests {
    /// Both the `--password-stdin` path and the prompt path run the shared
    /// policy before the password is sent anywhere.
    #[test]
    fn read_password_applies_the_shared_policy_on_both_paths() {
        let src = include_str!("security.rs");
        let start = src.find("fn read_password(").expect("read_password");
        let rest = &src[start..];
        let end = rest.find("\n/// Exit with `weak_password`").expect("refuse_weak follows");
        let body = &rest[..end];
        assert_eq!(body.matches("refuse_weak(g, &password, username)").count(), 2, "stdin and prompt paths");
        assert!(!body.contains(".len() < 8"), "the old 8-character rule is gone");
        for sig in ["pub fn security_user_create(", "pub fn security_user_set_password("] {
            let s = src.find(sig).unwrap_or_else(|| panic!("{sig}"));
            let r = &src[s..];
            let e = r[sig.len()..].find("\npub fn ").map(|i| i + sig.len()).unwrap_or(r.len());
            assert!(r[..e].contains("&username)"), "{sig} must pass the username to the policy");
        }
    }

    #[test]
    fn a_short_or_common_password_is_refused_by_the_shared_rule() {
        assert!(crate::password_policy::weak_password("hunter22", "alice").is_some());
        assert!(crate::password_policy::weak_password("Password123!", "alice").is_some());
        assert!(crate::password_policy::weak_password("a-long-enough-phrase", "alice").is_none());
    }
}
