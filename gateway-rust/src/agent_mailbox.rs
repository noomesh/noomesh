// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Agent mailboxes owned by a CONVERSATION (0.6.24).
//!
//! ## Why
//!
//! A mailbox used to live on a server-assigned MCP session
//! (`mcp_session.rs`): `initialize` opened one, the client echoed its id,
//! and `noo_agent_name` renamed it. The 2026-07-28 MCP revision has no
//! `initialize`, so a modern client (Claude Code from 2.1.3xx) never holds
//! a session: every call fell to the per-key label (`rbwolf/self-rbwolf`)
//! and `noo_agent_name` answered "no live MCP session". Nothing about a
//! connection can carry a mailbox any more, so nothing here depends on one.
//!
//! ## How
//!
//! - A name belongs to a conversation. The client presents its own stable
//!   conversation id (`session`, for Claude Code its session id) to
//!   `noo_agent_name`; the gateway stores it hashed and answers with the
//!   name bound to it. The same id later — a resumed conversation, a
//!   restarted gateway, a new connection — gets the same name and inbox. A
//!   new conversation gets a new DEFAULT name (`claude-x7k2qa`); it never
//!   inherits a previous conversation's name unless it asks (`join`).
//! - Every agent-mail call then states the mailbox: `as="claude-general"`.
//!   The door resolves it here and mints that call's `sub` with it, so the
//!   routes see one identity and their rules (owns, acks, threads) are
//!   unchanged. Stateless by construction.
//! - A legacy client that does hold an MCP session keeps working: its
//!   session id is its conversation key, and its session label follows the
//!   name it registers.
//!
//! ## States
//!
//! `online` (seen within [`Windows::online`]), `recent` (within
//! [`Windows::recent`]), `idle` (resumable), `retired` (past its kind's
//! window: default names after [`Windows::default_retire`], chosen ones after
//! [`Windows::chosen_retire`]). A retired name is not a recipient; its unread
//! mail becomes the account's orphaned mail, re-attached if the same
//! conversation resumes. The windows are settings, not constants.
//!
//! ## Boundary
//!
//! `as` names a mailbox of the caller's OWN account only; anything else is
//! one fixed refusal that says nothing about the other account. Within an
//! account any key may state any registered name of it: sessions of one
//! account are one person's trust, the join rule `mcp_session::rename`
//! already had. The doors accept only user-bound `mcp` service keys, so
//! delegated agent tokens, add-on tokens and kiosk seats (all JWTs) never
//! reach `as`; the trust tools do not take it at all.

use serde_json::{json, Map, Value};
use sqlx::PgPool;
use std::time::Duration;

/// The agent-mail tools that take `as`. The trust tools are deliberately
/// absent: a stated name must not let one window rewrite who may instruct
/// another.
pub const AS_TOOLS: &[&str] = &["noo_agent_inbox", "noo_agent_send", "noo_agent_ack", "noo_agent_thread", "noo_agent_whoami"];

/// The tool that registers a conversation's mailbox.
pub const NAME_TOOL: &str = "noo_agent_name";

/// The one refusal for `as` naming another account. Fixed text: it must not
/// say whether that account or name exists.
pub const NOT_YOURS: &str = "`as` names a mailbox of your own account only (as=\"<name>\" or as=\"<your account>/<name>\")";

/// What both doors tell every client, in `server/discover` and legacy
/// `initialize`: the one place a hookless client learns the protocol.
pub const MAILBOX_INSTRUCTIONS: &str = "Agent mail: call noo_agent_name once with session=<a stable id you keep for this conversation> (and name=<a durable name> if you want one); it returns your mailbox name. Pass as=<that name> on every noo_agent_* call. The same session id later resumes the same mailbox and its unread mail; with no session id you get a one-shot mailbox that retires after 24 h.";

/// The lifecycle windows, from settings (`noo_settings` row → env →
/// default). Read per use, so a change applies without a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Windows {
    pub online: Duration,
    pub recent: Duration,
    pub default_retire: Duration,
    pub chosen_retire: Duration,
    pub session_reap: Duration,
}

impl Default for Windows {
    fn default() -> Self {
        Windows {
            online: Duration::from_secs(5 * 60),
            recent: Duration::from_secs(24 * 3600),
            default_retire: Duration::from_secs(24 * 3600),
            chosen_retire: Duration::from_secs(7 * 24 * 3600),
            session_reap: Duration::from_secs(30 * 24 * 3600),
        }
    }
}

impl Windows {
    pub fn current() -> Self {
        let d = Self::default();
        let secs = |key: &str, dflt: Duration| {
            crate::settings::get(key)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|s| *s > 0)
                .map(Duration::from_secs)
                .unwrap_or(dflt)
        };
        Windows {
            online: secs("NOO_AGENT_ONLINE_SECS", d.online),
            recent: secs("NOO_AGENT_RECENT_SECS", d.recent),
            default_retire: secs("NOO_AGENT_DEFAULT_RETIRE_SECS", d.default_retire),
            chosen_retire: secs("NOO_AGENT_CHOSEN_RETIRE_SECS", d.chosen_retire),
            session_reap: secs("NOO_MCP_SESSION_REAP_SECS", d.session_reap),
        }
    }
}

/// Where a name stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Online,
    Recent,
    Idle,
    Retired,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Online => "online",
            Tier::Recent => "recent",
            Tier::Idle => "idle",
            Tier::Retired => "retired",
        }
    }
}

/// The tier of a name last seen `age` ago. Retirement is the sweep's
/// decision (it orphans the mail at the same moment), so a name past its
/// window that the sweep has not reached yet is still `idle`.
pub fn tier(age: Duration, retired: bool, w: &Windows) -> Tier {
    if retired {
        Tier::Retired
    } else if age <= w.online {
        Tier::Online
    } else if age <= w.recent {
        Tier::Recent
    } else {
        Tier::Idle
    }
}

fn age_of(last_seen: chrono::DateTime<chrono::Utc>) -> Duration {
    (chrono::Utc::now() - last_seen).to_std().unwrap_or_default()
}

/// The tier of a directory row now.
pub fn tier_of(r: &crate::repo::agent_names::NameRow, w: &Windows) -> Tier {
    tier(age_of(r.last_seen), r.retired_at.is_some(), w)
}

/// The stored form of a conversation key: a SHA-256 of its kind and value.
/// `client` = an id the client presents; `mcp` = a legacy session id. The
/// raw key is never stored.
pub fn key_hash(kind: &str, raw: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("{kind}:{raw}").as_bytes()))
}

/// The client TYPE a minted or claimed name starts with: a legacy session
/// label's known prefix (`claude-…`), else the client's own User-Agent or
/// key name (`mcp_session::session_type`), else `agent`. Display-grade: it
/// chooses the label, never a permission.
pub fn client_type(consumer: &str, user_agent: Option<&str>, legacy_label: Option<&str>) -> String {
    if let Some((prefix, _)) = legacy_label.and_then(|l| l.split_once('-')) {
        if crate::mcp_session::KNOWN_TYPES.contains(&prefix) {
            return prefix.to_string();
        }
    }
    crate::mcp_session::session_type(consumer, user_agent).unwrap_or_else(|| "agent".into())
}

/// Why `as` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsRefusal {
    /// Another account (or a malformed account part): [`NOT_YOURS`].
    NotYours,
    Invalid(String),
    Unregistered(String),
    Retired(String, chrono::DateTime<chrono::Utc>),
}

impl AsRefusal {
    pub fn message(&self) -> String {
        match self {
            AsRefusal::NotYours => NOT_YOURS.to_string(),
            AsRefusal::Invalid(v) => format!("as='{v}' is not a mailbox name: 1-64 of A-Z a-z 0-9 _ -"),
            AsRefusal::Unregistered(v) => format!(
                "no mailbox '{v}' is registered in your account. Call noo_agent_name(session=<your conversation id>) \
                 for yours, then pass as=<the name it returns>"
            ),
            AsRefusal::Retired(v, at) => format!(
                "mailbox '{v}' retired {}. Resume it with noo_agent_name(session=<the same conversation id>), \
                 or register a new one",
                at.to_rfc3339()
            ),
        }
    }
}

/// Is `part` the shape of a gateway-minted default suffix (six lowercase
/// letters and digits, at least one digit)? Reserved: a chosen name of that
/// shape could collide with a default the gateway mints later, or take over
/// a retired one.
pub fn reserved_default_part(part: &str) -> bool {
    part.len() == 6
        && part.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && part.bytes().any(|c| c.is_ascii_digit())
}

/// A chosen name as stored: lowercased (names compare case-insensitively;
/// they are ASCII by `auth::valid_name_segment`), typed (`claude-general`),
/// and refused when its own part has the reserved default shape.
pub fn chosen_label(ty: &str, wanted: &str) -> Result<String, String> {
    let lower = wanted.trim().to_ascii_lowercase();
    let label = crate::mcp_session::claimed_label(ty, &lower)?;
    let part = label.strip_prefix(&format!("{ty}-")).unwrap_or(&label);
    if reserved_default_part(part) {
        return Err(format!(
            "'{wanted}' has the shape of a default name (six letters and digits, at least one digit), which the gateway \
             reserves; choose a name that is not"
        ));
    }
    Ok(label)
}

/// The account and label part of an `as` value, before any lookup. The
/// account check comes FIRST and is answered the same whatever exists.
pub fn parse_as(raw: &str, account: &str) -> Result<String, AsRefusal> {
    let raw = raw.trim();
    let part = match raw.split_once(crate::auth::CONNECTION_SEP) {
        Some((a, p)) if a == account => p,
        Some(_) => return Err(AsRefusal::NotYours),
        None => raw,
    };
    if part.is_empty() || part.chars().count() > crate::mcp_session::MAX_CLAIMED || !crate::auth::valid_name_segment(part) {
        return Err(AsRefusal::Invalid(raw.to_string()));
    }
    // Names compare case-insensitively (stored lowercase).
    Ok(part.to_ascii_lowercase())
}

/// Resolve `as` to a registered, unretired label of `account`. The key's
/// own per-key label (`self-rbwolf`) is always its own mailbox.
pub async fn resolve_as(db: &PgPool, account: &str, consumer: &str, ty: &str, raw: &str) -> Result<String, AsRefusal> {
    let part = parse_as(raw, account)?;
    if let Some(own) = crate::auth::connection_label(consumer).filter(|l| l.eq_ignore_ascii_case(&part)) {
        return Ok(own);
    }
    let mut candidates = vec![part.clone()];
    if let Ok(c) = crate::mcp_session::claimed_label(ty, &part) {
        if c != part {
            candidates.push(c);
        }
    }
    for c in candidates {
        match crate::repo::agent_names::name(db, account, &c).await {
            Ok(Some(r)) => {
                return match r.retired_at {
                    Some(at) => Err(AsRefusal::Retired(c, at)),
                    None => Ok(c),
                };
            }
            Ok(None) => return Ok(c),
            Err(e) => {
                tracing::warn!(error = %e, account, "mailbox lookup failed");
                return Err(AsRefusal::Unregistered(part));
            }
        }
    }
    Err(AsRefusal::Unregistered(part))
}

/// What [`register`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub label: String,
    pub kind: &'static str,
    /// The conversation already held this name (a resume).
    pub resumed: bool,
    /// Other conversations already holding it (a join).
    pub shared_with: i64,
    /// Orphaned unread mail given back on resume.
    pub reattached: u64,
    pub note: Option<String>,
}

/// Mint a fresh default name `<ty>-<6>` for `key` (or for no key: a
/// one-shot mailbox nothing can resume).
async fn mint_default(
    tx: &mut sqlx::PgConnection,
    account: &str,
    consumer: &str,
    ty: &str,
    key: Option<&str>,
) -> Result<String, String> {
    for _ in 0..32 {
        let Some(label) = crate::mcp_session::session_label(consumer, Some(ty)) else {
            return Err("no name type for this client".into());
        };
        // Defaults always carry a digit: that is the reserved shape a
        // chosen name may not take ([`reserved_default_part`]).
        let label = label.to_ascii_lowercase();
        if !label.rsplit('-').next().is_some_and(reserved_default_part) {
            continue;
        }
        if crate::repo::agent_names::insert_name(tx, account, &label, "default", consumer).await.map_err(|e| e.to_string())? {
            if let Some(k) = key {
                crate::repo::agent_names::bind_key(tx, account, k, &label, 1).await.map_err(|e| e.to_string())?;
            }
            return Ok(label);
        }
    }
    Err("could not mint a free default name; try again".into())
}

/// Register a conversation's mailbox (see the module doc). `key` is the
/// hashed conversation key; `None` mints a one-shot default. `wanted` is a
/// chosen name; `join` shares a name another live or idle conversation
/// holds instead of refusing.
pub async fn register(
    db: &PgPool,
    account: &str,
    consumer: &str,
    ty: &str,
    key: Option<&str>,
    wanted: Option<&str>,
    join: bool,
) -> Result<Registered, String> {
    use crate::repo::agent_names as names;
    let w = Windows::current();
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    let e = |e: sqlx::Error| e.to_string();
    // What this conversation holds now, if its generation is still current.
    let mut lost: Option<String> = None;
    let mut held: Option<(String, names::NameRow)> = None;
    if let Some(k) = key {
        if let Some((label, gen)) = names::key_binding(&mut tx, account, k).await.map_err(e)? {
            match names::name_for_update(&mut tx, account, &label).await.map_err(e)? {
                Some(r) if r.gen == gen => held = Some((label, r)),
                _ => lost = Some(label),
            }
        }
    }
    let lost_note = |l: &str| format!("your earlier name '{l}' was taken by another conversation after it retired; this one has a new mailbox");
    let wanted_label = match wanted.map(str::trim).filter(|w| !w.is_empty()) {
        Some(wn) => Some(chosen_label(ty, wn)?),
        None => None,
    };

    // Resume: this conversation's own name (asked for, or not asked at all).
    if let Some((label, row)) = held.as_ref() {
        if wanted_label.as_deref().is_none_or(|wl| wl == label) {
            let mut reattached = 0;
            if row.retired_at.is_some() {
                names::unretire(&mut tx, account, label, consumer).await.map_err(e)?;
                reattached = names::reattach_orphans(&mut tx, account, label, row.gen).await.map_err(e)?;
            }
            let kind = if wanted_label.is_some() && row.kind == "default" {
                names::set_kind(&mut tx, account, label, "chosen").await.map_err(e)?;
                "chosen"
            } else if row.kind == "chosen" {
                "chosen"
            } else {
                "default"
            };
            names::bind_key(&mut tx, account, key.unwrap_or_default(), label, row.gen).await.map_err(e)?;
            let shared = (names::holders(&mut tx, account, label, row.gen).await.map_err(e)? - 1).max(0);
            tx.commit().await.map_err(e)?;
            let _ = names::touch(db, account, label, consumer).await;
            return Ok(Registered { label: label.clone(), kind, resumed: true, shared_with: shared, reattached, note: None });
        }
    }

    let Some(label) = wanted_label else {
        let label = mint_default(&mut tx, account, consumer, ty, key).await?;
        tx.commit().await.map_err(e)?;
        return Ok(Registered { label, kind: "default", resumed: false, shared_with: 0, reattached: 0, note: lost.as_deref().map(lost_note) });
    };

    let out = match names::name_for_update(&mut tx, account, &label).await.map_err(e)? {
        None => {
            if !names::insert_name(&mut tx, account, &label, "chosen", consumer).await.map_err(e)? {
                // Lost a race for a new name: the winner holds it now. The
                // same refusal as a held name, never a silent share.
                return Err(format!(
                    "'{account}/{label}' is held by another conversation (online, registered a moment ago). Pass join=true \
                     to share its mailbox, or choose another name"
                ));
            }
            if let Some(k) = key {
                names::bind_key(&mut tx, account, k, &label, 1).await.map_err(e)?;
            }
            Registered { label, kind: "chosen", resumed: false, shared_with: 0, reattached: 0, note: lost.as_deref().map(lost_note) }
        }
        // Retired: released for reuse by this account. A new generation,
        // so the earlier holder's key no longer reaches it and the earlier
        // unread mail stays with the account owner.
        Some(r) if r.retired_at.is_some() => {
            let gen = names::take_over(&mut tx, account, &label, "chosen", consumer).await.map_err(e)?;
            if let Some(k) = key {
                names::bind_key(&mut tx, account, k, &label, gen).await.map_err(e)?;
            }
            Registered {
                label,
                kind: "chosen",
                resumed: false,
                shared_with: 0,
                reattached: 0,
                note: Some("took over a retired name; mail it had not read stays with the account (noo_agent_inbox orphaned=true)".into()),
            }
        }
        Some(r) => {
            if !join {
                let t = tier_of(&r, &w);
                return Err(format!(
                    "'{account}/{label}' is held by another conversation ({}, last seen {}). Pass join=true to share its \
                     mailbox, or choose another name",
                    t.as_str(),
                    r.last_seen.to_rfc3339()
                ));
            }
            let shared = names::holders(&mut tx, account, &label, r.gen).await.map_err(e)?;
            if let Some(k) = key {
                names::bind_key(&mut tx, account, k, &label, r.gen).await.map_err(e)?;
            }
            Registered { label, kind: if r.kind == "chosen" { "chosen" } else { "default" }, resumed: false, shared_with: shared, reattached: 0, note: None }
        }
    };
    tx.commit().await.map_err(e)?;
    let _ = names::touch(db, account, &out.label, consumer).await;
    Ok(out)
}

/// Mark a name seen, at most once a minute per name (every agent call
/// states one; `online` is minutes wide).
pub async fn touch(db: &PgPool, account: &str, label: &str, consumer: &str) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;
    static LAST: OnceLock<Mutex<HashMap<(String, String), Instant>>> = OnceLock::new();
    let k = (account.to_string(), label.to_string());
    {
        let mut m = LAST.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner());
        if m.get(&k).is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            return;
        }
        if m.len() > 50_000 {
            m.clear();
        }
        m.insert(k, Instant::now());
    }
    if let Err(e) = crate::repo::agent_names::touch(db, account, label, consumer).await {
        tracing::warn!(error = %e, account, label, "mailbox touch failed");
    }
}

/// What the door does with one agent-mail tool call.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Mint this label (`None` = the per-key label, the pre-0.6.24 path)
    /// and run the tool; `note` rides along on the answer.
    Proceed { label: Option<String>, note: Option<String> },
    /// Answer without running the tool (guidance, not a failure).
    Answer(Value),
    /// Refuse with this message; nothing ran.
    Refuse(String),
}

/// How to get a mailbox, for a sessionless call that stated none.
pub fn no_mailbox_yet() -> String {
    "no mailbox yet: call noo_agent_name(session=<a stable id you keep for this conversation>) once; it returns your \
     mailbox name. Then pass as=<that name> on every noo_agent_* call"
        .into()
}

/// The door's decision for `tool` (see [`Outcome`]). `legacy` is a live
/// legacy MCP session's label. `as` is removed from `args` before the tool
/// runs, so it never reaches a route.
pub async fn for_call(
    db: &PgPool,
    account: &str,
    consumer: &str,
    ty: &str,
    legacy: Option<&str>,
    tool: &str,
    args: &mut Map<String, Value>,
) -> Outcome {
    if !AS_TOOLS.contains(&tool) {
        // Not agent mail: `as` stays in the arguments and the tool's own
        // schema refuses it (the trust tools never take it).
        return Outcome::Proceed { label: legacy.map(str::to_string), note: None };
    }
    if let Some(raw) = args.remove("as") {
        let Some(raw) = raw.as_str() else {
            return Outcome::Refuse("as must be a string: your mailbox name".into());
        };
        return match resolve_as(db, account, consumer, ty, raw).await {
            Ok(label) => {
                touch(db, account, &label, consumer).await;
                Outcome::Proceed { label: Some(label), note: None }
            }
            Err(r) => Outcome::Refuse(r.message()),
        };
    }
    if let Some(l) = legacy {
        touch(db, account, l, consumer).await;
        return Outcome::Proceed { label: Some(l.to_string()), note: None };
    }
    // A sessionless client that stated no mailbox.
    match tool {
        "noo_agent_whoami" => Outcome::Answer(json!({
            "name": null,
            "account": account,
            "mailbox": "none yet",
            "how": no_mailbox_yet(),
        })),
        // Never send from the per-key mailbox by accident: mint a one-shot
        // default, send from it, and say how to read the replies.
        "noo_agent_send" => match register(db, account, consumer, ty, None, None, false).await {
            Ok(r) => Outcome::Proceed {
                label: Some(r.label.clone()),
                note: Some(format!(
                    "sent from a one-shot mailbox '{account}/{}' that retires after 24 h; pass as='{}' to read replies, \
                     or {}",
                    r.label,
                    r.label,
                    no_mailbox_yet()
                )),
            },
            Err(e) => Outcome::Refuse(e),
        },
        _ => Outcome::Refuse(no_mailbox_yet()),
    }
}

/// `noo_agent_name` at the door: register the conversation's mailbox.
/// `legacy_id` is a live legacy MCP session id: its conversation key when
/// no `session` is given, and the session's label then follows the name.
pub async fn name_call(
    db: &PgPool,
    account: &str,
    consumer: &str,
    ty: &str,
    legacy_id: Option<&str>,
    args: &Map<String, Value>,
) -> Result<Value, String> {
    for k in args.keys() {
        if !matches!(k.as_str(), "name" | "session" | "join") {
            return Err(format!("noo_agent_name takes name, session and join; not '{k}'"));
        }
    }
    let wanted = args.get("name").and_then(Value::as_str);
    let join = args.get("join").and_then(Value::as_bool).unwrap_or(false);
    let session = args.get("session").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    if session.is_some_and(|s| s.chars().count() > 256 || s.chars().any(char::is_control)) {
        return Err("session is the id you keep for this conversation: up to 256 printable characters".into());
    }
    let key = match (session, legacy_id) {
        (Some(s), _) => Some(key_hash("client", s)),
        (None, Some(id)) => Some(key_hash("mcp", id)),
        (None, None) => None,
    };
    let r = register(db, account, consumer, ty, key.as_deref(), wanted, join).await?;
    if let Some(id) = legacy_id {
        crate::mcp_session::follow_name(db, account, id, &r.label).await;
    }
    let name = format!("{account}{}{}", crate::auth::CONNECTION_SEP, r.label);
    let how = match (key.is_some(), session.is_some()) {
        (false, _) => format!("a one-shot mailbox: it retires after 24 h and cannot be resumed. Pass as='{}' on every noo_agent_* call", r.label),
        (true, true) => format!("pass as='{}' on every noo_agent_* call; noo_agent_name(session=<the same id>) resumes it", r.label),
        (true, false) => format!("this MCP session now mails as '{}'; a client without a session passes as='{}'", r.label, r.label),
    };
    Ok(json!({
        "name": name,
        "account": account,
        "kind": r.kind,
        "resumed": r.resumed,
        "shared_with": r.shared_with,
        "reattached_unread": r.reattached,
        "note": r.note,
        "how": how,
    }))
}

/// What a door does with a tool call, after the mailbox step.
#[derive(Debug)]
pub enum DoorStep {
    /// Run the tool with these arguments (`as` removed), minting `label`
    /// (`None` = the per-key label); add `note` to its answer.
    Run { args: Map<String, Value>, label: Option<String>, note: Option<String> },
    /// The answer, without running the tool.
    Done(Result<Value, String>),
}

/// The one mailbox step both doors take before running a tool.
/// `consumer` is the door's session consumer (`self:rbwolf`,
/// `operator:rbwolf`); `legacy_label` the label of a live legacy session.
pub async fn door_step(
    db: &PgPool,
    account: &str,
    consumer: &str,
    headers: &axum::http::HeaderMap,
    legacy_label: Option<&str>,
    tool: &str,
    args: &Map<String, Value>,
) -> DoorStep {
    let ua = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok());
    let ty = client_type(consumer, ua, legacy_label);
    if tool == NAME_TOOL {
        let legacy_id = legacy_label.and(crate::mcp_session::presented_id(headers));
        return DoorStep::Done(name_call(db, account, consumer, &ty, legacy_id, args).await);
    }
    let mut args = args.clone();
    match for_call(db, account, consumer, &ty, legacy_label, tool, &mut args).await {
        Outcome::Proceed { label, note } => DoorStep::Run { args, label, note },
        Outcome::Answer(v) => DoorStep::Done(Ok(v)),
        Outcome::Refuse(m) => DoorStep::Done(Err(m)),
    }
}

/// Put a mailbox note on a tool's answer.
pub fn with_note(v: Value, note: Option<String>) -> Value {
    match (v, note) {
        (Value::Object(mut m), Some(n)) => {
            m.insert("mailbox_note".into(), Value::String(n));
            Value::Object(m)
        }
        (v, Some(n)) => json!({ "result": v, "mailbox_note": n }),
        (v, None) => v,
    }
}

/// The delivery word for a send to `to`, when it is a registered name
/// (`Ok(None)`: not one). A database that cannot answer is an error, never
/// "no state".
pub async fn delivery(db: &PgPool, to: &str) -> Result<Option<(Tier, chrono::DateTime<chrono::Utc>)>, sqlx::Error> {
    let Some((account, label)) = to.split_once(crate::auth::CONNECTION_SEP) else { return Ok(None) };
    Ok(crate::repo::agent_names::name(db, account, label)
        .await?
        .map(|r| (tier_of(&r, &Windows::current()), r.last_seen)))
}

/// One pass of the lifecycle: retire names past their window (orphaning
/// their unread mail) and reap idle MCP session rows.
pub async fn sweep(db: &PgPool) -> Result<(), String> {
    let w = Windows::current();
    let (retired, orphaned) = crate::repo::agent_names::retire_due(db, w.default_retire.as_secs() as i64, w.chosen_retire.as_secs() as i64)
        .await
        .map_err(|e| e.to_string())?;
    let reaped = crate::repo::agent_names::reap_sessions(db, w.session_reap.as_secs() as i64).await.map_err(|e| e.to_string())?;
    if retired + reaped > 0 {
        tracing::info!(retired, orphaned, reaped_sessions = reaped, "agent mailbox sweep");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w() -> Windows {
        Windows::default()
    }

    #[test]
    fn the_default_windows_are_the_operators() {
        let d = w();
        assert_eq!(d.online, Duration::from_secs(300));
        assert_eq!(d.recent, Duration::from_secs(86_400));
        assert_eq!(d.default_retire, Duration::from_secs(86_400), "a name nobody chose retires after a day");
        assert_eq!(d.chosen_retire, Duration::from_secs(7 * 86_400), "a chosen name stays resumable a week");
        assert_eq!(d.session_reap, Duration::from_secs(30 * 86_400));
    }

    #[test]
    fn four_states_by_age_and_retirement() {
        let d = w();
        assert_eq!(tier(Duration::from_secs(0), false, &d), Tier::Online);
        assert_eq!(tier(Duration::from_secs(300), false, &d), Tier::Online);
        assert_eq!(tier(Duration::from_secs(301), false, &d), Tier::Recent);
        assert_eq!(tier(Duration::from_secs(86_400), false, &d), Tier::Recent);
        assert_eq!(tier(Duration::from_secs(86_401), false, &d), Tier::Idle);
        assert_eq!(tier(Duration::from_secs(0), true, &d), Tier::Retired, "retired is the sweep's word, whatever the age");
    }

    /// The account check is first and its answer is fixed: an existing and
    /// a non-existent foreign account read the same, and no lookup runs.
    #[test]
    fn as_names_only_your_own_account_and_says_nothing_else() {
        assert_eq!(parse_as("general", "rbwolf"), Ok("general".into()));
        assert_eq!(parse_as("claude-general", "rbwolf"), Ok("claude-general".into()));
        assert_eq!(parse_as("rbwolf/claude-general", "rbwolf"), Ok("claude-general".into()));
        for foreign in ["bob/claude-general", "nosuchaccount/x", "RBWOLF/claude-general", "/claude-general"] {
            let e = parse_as(foreign, "rbwolf").unwrap_err();
            assert_eq!(e, AsRefusal::NotYours, "{foreign}");
            assert_eq!(e.message(), NOT_YOURS);
            assert!(!e.message().contains("bob") && !e.message().contains("nosuch"), "the refusal names nothing of the other account");
        }
        assert!(matches!(parse_as("a b", "rbwolf"), Err(AsRefusal::Invalid(_))));
        assert!(matches!(parse_as("", "rbwolf"), Err(AsRefusal::Invalid(_))));
    }

    #[test]
    fn conversation_keys_are_stored_hashed_and_namespaced() {
        let a = key_hash("client", "8f1c-session");
        assert_eq!(a.len(), 64);
        assert!(!a.contains("8f1c"));
        assert_ne!(a, key_hash("mcp", "8f1c-session"), "a client id and a legacy session id never collide");
        assert_eq!(a, key_hash("client", "8f1c-session"), "the same conversation id is the same key");
    }

    #[test]
    fn the_client_type_comes_from_the_session_then_the_user_agent() {
        assert_eq!(client_type("self:rbwolf", Some("claude-code/2.1.322 (cli)"), None), "claude");
        assert_eq!(client_type("self:rbwolf", Some("Python-urllib/3.12"), Some("claude-general")), "claude");
        assert_eq!(client_type("rbwolf-mcp-user", Some("codex_cli_rs/0.40"), None), "codex");
    }

    #[test]
    fn the_instructions_teach_the_protocol_to_a_hookless_client() {
        for must in ["noo_agent_name", "session=", "as=", "resumes", "one-shot", "24 h"] {
            assert!(MAILBOX_INSTRUCTIONS.contains(must), "{must}");
        }
        assert!(no_mailbox_yet().contains("noo_agent_name(session="));
    }

    /// Both doors take the mailbox step before running a tool and teach
    /// it in both eras' instructions; the minted identity is the step's.
    #[test]
    fn both_doors_take_the_mailbox_step_and_teach_it() {
        for (f, src) in [("mcp_external.rs", include_str!("mcp_external.rs")), ("mcp_local.rs", include_str!("mcp_local.rs"))] {
            assert!(src.contains("crate::agent_mailbox::door_step("), "{f}: no mailbox step");
            assert!(src.contains("crate::agent_mailbox::MAILBOX_INSTRUCTIONS"), "{f}: instructions do not teach the mailbox");
            assert!(src.contains("env.discover(SERVER_NAME, &instructions())"), "{f}: discover");
            assert!(src.contains("env.initialize(SERVER_NAME, &instructions())"), "{f}: initialize");
            assert!(src.contains("mailbox.as_deref()"), "{f}: the minted identity must be the mailbox step's");
        }
    }

    #[test]
    fn the_trust_tools_never_take_as() {
        for t in AS_TOOLS {
            assert!(!t.contains("trust"), "{t}");
        }
        assert!(!AS_TOOLS.contains(&NAME_TOOL), "noo_agent_name registers; it does not state a mailbox");
    }

    // ── the database half (CI's DSN: the real, migrated catalogue) ──────

    /// A scratch database with the real migration chain
    /// (`repo::agent_names::fixtures::scratch`): CI's shared catalogue is the
    /// Alembic chain (046), which has none of migration 119's tables.
    async fn database() -> Option<PgPool> {
        crate::repo::agent_names::fixtures::scratch().await
    }

    fn acct() -> String {
        format!("mbx{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
    }

    async fn mail_to(db: &PgPool, to: &str) -> String {
        mail(db, "tester/agent", to, None).await
    }

    async fn mail(db: &PgPool, from: &str, to: &str, thread: Option<&str>) -> String {
        let env = crate::agent_messages::Envelope::new(from, to, "message", json!({"text": "hi"}), thread, vec![]);
        crate::repo::agent_messages::insert(db, &env, false).await.unwrap();
        env.id.clone()
    }

    /// The restart: the in-memory session registry is gone, and a modern
    /// client presents no session at all. The same conversation id still
    /// reaches the same mailbox.
    #[tokio::test]
    async fn the_same_conversation_resumes_its_mailbox_after_a_restart() {
        let Some(db) = database().await else { return };
        let a = acct();
        let k = key_hash("client", "conv-1");
        let first = register(&db, &a, "self:x", "claude", Some(&k), None, false).await.unwrap();
        assert_eq!(first.kind, "default");
        assert!(first.label.starts_with("claude-"));
        crate::mcp_session::clear_local_for_tests();
        let again = register(&db, &a, "self:x", "claude", Some(&k), None, false).await.unwrap();
        assert_eq!(again.label, first.label);
        assert!(again.resumed);
        assert_eq!(resolve_as(&db, &a, "self:x", "claude", &first.label).await, Ok(first.label.clone()));
    }

    #[tokio::test]
    async fn a_new_conversation_gets_its_own_name_never_a_previous_one() {
        let Some(db) = database().await else { return };
        let a = acct();
        let one = register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c1")), Some("general"), false).await.unwrap();
        assert_eq!((one.label.as_str(), one.kind), ("claude-general", "chosen"));
        let two = register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c2")), None, false).await.unwrap();
        assert_ne!(two.label, "claude-general");
        assert_eq!(two.kind, "default");
    }

    #[tokio::test]
    async fn a_held_name_is_refused_without_join_and_shared_with_it() {
        let Some(db) = database().await else { return };
        let a = acct();
        register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c1")), Some("general"), false).await.unwrap();
        let e = register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c2")), Some("general"), false).await.unwrap_err();
        assert!(e.contains("held by another conversation") && e.contains("join=true"), "{e}");
        let j = register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c2")), Some("general"), true).await.unwrap();
        assert_eq!((j.label.as_str(), j.shared_with), ("claude-general", 1));
    }

    /// The operator's recovery case: retire, resume with the same key →
    /// the same name, and its unread mail is back.
    #[tokio::test]
    async fn a_retired_name_comes_back_with_its_unread_mail_for_the_same_conversation() {
        let Some(db) = database().await else { return };
        let a = acct();
        let k = key_hash("client", "weekly");
        let r = register(&db, &a, "self:x", "claude", Some(&k), Some("weekly"), false).await.unwrap();
        let to = format!("{a}/{}", r.label);
        let m = mail_to(&db, &to).await;
        crate::repo::agent_names::fixtures::backdate(&db, &a, &r.label, 8 * 86_400).await;
        crate::repo::agent_names::retire_due(&db, 86_400, 7 * 86_400).await.unwrap();
        assert_eq!(crate::repo::agent_names::fixtures::orphans_of(&db, &a, &r.label).await, 1);
        assert!(matches!(resolve_as(&db, &a, "self:x", "claude", &r.label).await, Err(AsRefusal::Retired(..))));
        // Hidden from the name's inbox, visible to the owner.
        let hidden = crate::repo::agent_messages::list(&db, &crate::repo::agent_messages::Filter { to: Some(&to), limit: 10, ..Default::default() }).await.unwrap();
        assert!(hidden.is_empty());
        let owner = crate::repo::agent_messages::list(&db, &crate::repo::agent_messages::Filter { orphans: crate::repo::agent_messages::OrphanView::OnlyOf(&a), limit: 10, ..Default::default() }).await.unwrap();
        assert_eq!(owner.len(), 1);
        // Resume.
        let back = register(&db, &a, "self:x", "claude", Some(&k), None, false).await.unwrap();
        assert_eq!((back.label.as_str(), back.resumed, back.reattached), (r.label.as_str(), true, 1));
        let inbox = crate::repo::agent_messages::list(&db, &crate::repo::agent_messages::Filter { to: Some(&to), limit: 10, ..Default::default() }).await.unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0]["id"], m);
    }

    /// Takeover: another conversation of the SAME account may take a
    /// retired name, as a new generation with an EMPTY inbox. Everything
    /// the earlier generation sent or received (read or not) stays with the
    /// account owner; the new holder is no party to its threads, and a
    /// reply there to the name is refused. The earlier conversation
    /// resuming gets a new name and a note.
    #[tokio::test]
    async fn a_retired_name_is_released_to_the_account_but_not_its_mail() {
        let Some(db) = database().await else { return };
        let a = acct();
        let name = format!("{a}/claude-general");
        let old = key_hash("client", "old");
        register(&db, &a, "self:x", "claude", Some(&old), Some("general"), false).await.unwrap();
        let thread = format!("thr_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        mail(&db, "tester/agent", &name, Some(&thread)).await;
        let read = mail(&db, "tester/agent", &name, None).await;
        crate::repo::agent_messages::mark_read(&db, &read, &name).await.unwrap();
        mail(&db, &name, "tester/agent", Some(&thread)).await;
        crate::repo::agent_names::fixtures::backdate(&db, &a, "claude-general", 8 * 86_400).await;
        crate::repo::agent_names::retire_due(&db, 86_400, 7 * 86_400).await.unwrap();
        let new = register(&db, &a, "self:x", "claude", Some(&key_hash("client", "new")), Some("general"), false).await.unwrap();
        assert_eq!(new.label, "claude-general");
        assert!(new.note.as_deref().unwrap_or("").contains("took over"));
        assert_eq!(crate::repo::agent_names::fixtures::orphans_of(&db, &a, "claude-general").await, 3, "the old generation's whole history");
        let inbox = crate::repo::agent_messages::list(&db, &crate::repo::agent_messages::Filter { owner: Some(&name), limit: 50, ..Default::default() }).await.unwrap();
        assert!(inbox.is_empty(), "the new holder starts empty: {inbox:?}");
        assert_eq!(crate::repo::agent_messages::is_party(&db, &thread, &name).await.unwrap(), Some(false));
        assert!(crate::agent_recipient::thread_reply_refusal(&db, &name, Some(&thread)).await.unwrap().is_some_and(|w| w.contains("retired")));
        // Counted as orphaned: the unread one only.
        let counts = crate::repo::agent_names::orphan_counts(&db, Some(&a)).await.unwrap();
        assert_eq!(counts, vec![(a.clone(), "claude-general".to_string(), 1)]);
        // New mail to the name is the new holder's.
        mail_to(&db, &name).await;
        let inbox = crate::repo::agent_messages::list(&db, &crate::repo::agent_messages::Filter { owner: Some(&name), limit: 50, ..Default::default() }).await.unwrap();
        assert_eq!(inbox.len(), 1);
        let back = register(&db, &a, "self:x", "claude", Some(&old), None, false).await.unwrap();
        assert_ne!(back.label, "claude-general");
        assert!(back.note.as_deref().unwrap_or("").contains("taken by another conversation"));
        // Another account cannot reach the name at all: names are per account.
        let other = acct();
        let theirs = register(&db, &other, "self:y", "claude", Some(&key_hash("client", "x")), Some("general"), false).await.unwrap();
        assert_eq!(theirs.label, "claude-general");
        assert_eq!(resolve_as(&db, &other, "self:y", "claude", &format!("{a}/claude-general")).await, Err(AsRefusal::NotYours));
    }

    /// Collisions: names compare case-insensitively; non-ASCII is refused;
    /// a chosen name may not take the reserved default shape; two
    /// conversations racing for one new name: one wins, the other gets the
    /// join refusal, never a silent share.
    #[tokio::test]
    async fn names_do_not_collide_by_case_shape_or_race() {
        let Some(db) = database().await else { return };
        let a = acct();
        let g = register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c1")), Some("General"), false).await.unwrap();
        assert_eq!(g.label, "claude-general");
        let e = register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c2")), Some("GENERAL"), false).await.unwrap_err();
        assert!(e.contains("join=true"), "{e}");
        assert_eq!(resolve_as(&db, &a, "self:x", "claude", "Claude-General").await, Ok("claude-general".into()));
        assert!(register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c3")), Some("généräl"), false).await.is_err());
        let r = register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c4")), Some("abc123"), false).await.unwrap_err();
        assert!(r.contains("reserves"), "{r}");
        assert!(register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c5")), Some("weekly"), false).await.is_ok(), "six letters, no digit: not the default shape");
        let (k1, k2) = (key_hash("client", "r1"), key_hash("client", "r2"));
        let (x, y) = tokio::join!(
            register(&db, &a, "self:x", "claude", Some(&k1), Some("raced"), false),
            register(&db, &a, "self:x", "claude", Some(&k2), Some("raced"), false),
        );
        assert_eq!([x.is_ok(), y.is_ok()].iter().filter(|o| **o).count(), 1, "exactly one wins: {x:?} {y:?}");
        let lost = if x.is_ok() { y.unwrap_err() } else { x.unwrap_err() };
        assert!(lost.contains("held by another conversation") && lost.contains("join=true"), "{lost}");
    }

    #[test]
    fn the_default_shape_is_reserved_and_minted_defaults_have_it() {
        assert!(reserved_default_part("x7k2qa"));
        assert!(!reserved_default_part("weekly"), "no digit");
        assert!(!reserved_default_part("x7k2q"), "five");
        assert!(!reserved_default_part("X7K2QA"), "uppercase is not minted");
        assert!(chosen_label("claude", "x7k2qa").is_err());
        assert!(chosen_label("claude", "claude-x7k2qa").is_err(), "with the type prefix too");
        assert_eq!(chosen_label("claude", "General"), Ok("claude-general".into()));
    }

    #[tokio::test]
    async fn as_must_name_a_registered_mailbox() {
        let Some(db) = database().await else { return };
        let a = acct();
        assert!(matches!(resolve_as(&db, &a, "self:x", "claude", "ghost").await, Err(AsRefusal::Unregistered(_))));
        // The key's own per-key mailbox is always its own.
        assert_eq!(resolve_as(&db, &a, &format!("self:{a}"), "claude", &format!("self-{a}")).await, Ok(format!("self-{a}")));
        register(&db, &a, "self:x", "claude", Some(&key_hash("client", "c")), Some("general"), false).await.unwrap();
        assert_eq!(resolve_as(&db, &a, "self:x", "claude", "general").await, Ok("claude-general".into()), "the type is added as on claim");
    }

    #[tokio::test]
    async fn a_default_name_retires_after_a_day_and_a_chosen_one_after_a_week() {
        let Some(db) = database().await else { return };
        let a = acct();
        let d = register(&db, &a, "self:x", "codex", Some(&key_hash("client", "d")), None, false).await.unwrap();
        let c = register(&db, &a, "self:x", "codex", Some(&key_hash("client", "c")), Some("weekly"), false).await.unwrap();
        for l in [&d.label, &c.label] {
            crate::repo::agent_names::fixtures::backdate(&db, &a, l, 2 * 86_400).await;
        }
        crate::repo::agent_names::retire_due(&db, 86_400, 7 * 86_400).await.unwrap();
        let w = Windows::default();
        let dr = crate::repo::agent_names::name(&db, &a, &d.label).await.unwrap().unwrap();
        let cr = crate::repo::agent_names::name(&db, &a, &c.label).await.unwrap().unwrap();
        assert_eq!(tier_of(&dr, &w), Tier::Retired);
        assert_eq!(tier_of(&cr, &w), Tier::Idle, "a chosen name is resumable for a week");
    }

    /// A retired name is not a recipient: refused, with the account's
    /// recently seen chosen names when the sender may see them, and none
    /// when it is another account.
    #[tokio::test]
    async fn a_send_to_a_retired_name_is_refused_with_who_to_try() {
        let Some(db) = database().await else { return };
        let a = acct();
        register(&db, &a, "self:x", "claude", Some(&key_hash("client", "old")), Some("old"), false).await.unwrap();
        register(&db, &a, "self:x", "claude", Some(&key_hash("client", "now")), Some("general"), false).await.unwrap();
        crate::repo::agent_names::fixtures::backdate(&db, &a, "claude-old", 8 * 86_400).await;
        crate::repo::agent_names::retire_due(&db, 86_400, 7 * 86_400).await.unwrap();
        let to = format!("{a}/claude-old");
        match crate::agent_recipient::check(&db, &to, Some(&a)).await.unwrap() {
            crate::agent_recipient::Recipient::Retired(_, names) => assert_eq!(names, vec![format!("{a}/claude-general")]),
            other => panic!("{other:?}"),
        }
        match crate::agent_recipient::check(&db, &to, Some("someone-else")).await.unwrap() {
            crate::agent_recipient::Recipient::Retired(_, names) => assert!(names.is_empty(), "another account learns no names"),
            other => panic!("{other:?}"),
        }
        assert_eq!(crate::agent_recipient::check(&db, &format!("{a}/claude-general"), Some(&a)).await.unwrap(), crate::agent_recipient::Recipient::Known);
        assert_eq!(delivery(&db, &format!("{a}/claude-general")).await.unwrap().map(|(t, _)| t), Some(Tier::Online));
    }

    /// The door step for a sessionless client: a send without `as` never
    /// goes out from the per-key mailbox (it gets a one-shot mailbox and is
    /// told); whoami says how to get one; `as` naming another account is
    /// the fixed refusal; `as` is stripped before the tool runs.
    #[tokio::test]
    async fn the_door_step_never_sends_from_the_per_key_mailbox_by_accident() {
        let Some(db) = database().await else { return };
        let a = acct();
        let consumer = format!("self:{a}");
        let mut args = Map::new();
        args.insert("to".into(), json!(format!("{a}/claude-x")));
        match for_call(&db, &a, &consumer, "claude", None, "noo_agent_send", &mut args).await {
            Outcome::Proceed { label: Some(l), note: Some(n) } => {
                assert_ne!(l, format!("self-{a}"), "not the per-key mailbox");
                assert!(l.starts_with("claude-") && n.contains("one-shot"), "{l} {n}");
            }
            other => panic!("{other:?}"),
        }
        let mut none = Map::new();
        match for_call(&db, &a, &consumer, "claude", None, "noo_agent_whoami", &mut none).await {
            Outcome::Answer(v) => assert!(v["how"].as_str().unwrap().contains("noo_agent_name(session=")),
            other => panic!("{other:?}"),
        }
        let mut foreign = Map::new();
        foreign.insert("as".into(), json!("bob/claude-general"));
        assert_eq!(for_call(&db, &a, &consumer, "claude", None, "noo_agent_inbox", &mut foreign).await, Outcome::Refuse(NOT_YOURS.into()));
        assert!(foreign.get("as").is_none(), "as never reaches the route");
        register(&db, &a, &consumer, "claude", Some(&key_hash("client", "c")), Some("general"), false).await.unwrap();
        let mut mine = Map::new();
        mine.insert("as".into(), json!("general"));
        assert_eq!(
            for_call(&db, &a, &consumer, "claude", None, "noo_agent_inbox", &mut mine).await,
            Outcome::Proceed { label: Some("claude-general".into()), note: None }
        );
    }

    #[tokio::test]
    async fn a_one_shot_mailbox_has_no_key_and_cannot_be_resumed() {
        let Some(db) = database().await else { return };
        let a = acct();
        let one = register(&db, &a, "self:x", "codex", None, None, false).await.unwrap();
        let two = register(&db, &a, "self:x", "codex", None, None, false).await.unwrap();
        assert_ne!(one.label, two.label);
        assert_eq!(one.kind, "default");
    }
}
