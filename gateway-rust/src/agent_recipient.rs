// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Does an agent message's `to` reach a mailbox anyone reads? (i277g)
//!
//! Since #372 an inbox name is `<account>/<type>-<session>`. A handoff
//! addressed to plain `general` was stored under a name nobody reads, and the
//! sender was told `"sent": true` and carried on as if it had arrived. The
//! HTTP route checked only that the ACCOUNT part existed, and only for an
//! unprivileged caller, so an operator session's message to `general` was
//! accepted without a look; the loop's `noo_agent_send` checked nothing.
//!
//! Three answers:
//!
//!   - **held**: an account or a node (mail to a bare account fans out to
//!     every session under it); anything under a node (`host3/agent`, the
//!     controller's `host8/mcp-server`: node-hosted agents are not listed
//!     anywhere); an MCP session name of any age (a name is a mailbox); an
//!     active service key's connection. Delivered.
//!   - **account only**: `<account>/<label>` under a real account that no
//!     session or key holds. Delivered, because the account's inbox reads
//!     every name under it and a connection minted by token exchange has no
//!     row of its own by design (`routes/identity.rs`). But the result WARNS
//!     and names the registered names it may have meant: a typo here lands
//!     where nobody is looking.
//!   - **nobody**: a bare name that is no account or node, or a name under
//!     an account that does not exist. Refused with the closest registered
//!     names; nothing is sent.
//!
//! What does not count: a name that once SENT mail. Senders include the bare
//! pre-#372 names, and counting them would make `general` deliverable again.
//!
//! A near name is suggested, never substituted. A prefix of one registered
//! name is not a typo for it with any certainty: a minted window `alice/w1`
//! is a real, unregistered mailbox while `alice/w10` is registered, and
//! rewriting the address would deliver to the wrong window.

use sqlx::PgPool;

/// Where `to` stands, from the database (see the module doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Standing {
    Held,
    AccountOnly,
    Nobody,
}

/// What a recipient check decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recipient {
    /// `to` is held; deliver.
    Known,
    /// Deliver, and warn with the registered names it may have meant.
    Unheld(Vec<String>),
    /// Refuse: nothing reads `to`. The closest registered names, if any.
    Unknown(Vec<String>),
}

/// How many close names a refusal or a warning lists.
const MAX_CANDIDATES: usize = 8;
/// How many registered names a check reads to choose from.
const NAME_SCAN: i64 = 500;

/// The pure decision: `registered` = the compound names the caller may see,
/// most recently used first.
pub(crate) fn decide(to: &str, standing: Standing, registered: &[String]) -> Recipient {
    match standing {
        Standing::Held => Recipient::Known,
        Standing::AccountOnly => Recipient::Unheld(candidates(to, registered)),
        Standing::Nobody => Recipient::Unknown(candidates(to, registered)),
    }
}

/// Registered names that look like `to`: those it is the start of
/// (`rbpai/claude-gen`), then those containing its session part (`general`
/// in `rbpai/claude-general`), case-insensitively; failing both, the names
/// under `to`'s account.
fn candidates(to: &str, registered: &[String]) -> Vec<String> {
    let lower = to.to_ascii_lowercase();
    let (account, part) = match lower.split_once(crate::auth::CONNECTION_SEP) {
        Some((a, p)) => (Some(a.to_string()), p.to_string()),
        None => (None, lower.clone()),
    };
    let mut out: Vec<String> = Vec::new();
    let add = |out: &mut Vec<String>, n: &String| {
        if out.len() < MAX_CANDIDATES && !out.contains(n) && n.to_ascii_lowercase() != lower {
            out.push(n.clone());
        }
    };
    for n in registered.iter().filter(|n| n.to_ascii_lowercase().starts_with(&lower)) {
        add(&mut out, n);
    }
    if !part.is_empty() {
        for n in registered.iter().filter(|n| n.to_ascii_lowercase().contains(&part)) {
            add(&mut out, n);
        }
    }
    if out.is_empty() {
        if let Some(a) = account {
            for n in registered.iter().filter(|n| crate::auth::account_of(n).eq_ignore_ascii_case(&a)) {
                add(&mut out, n);
            }
        }
    }
    out
}

/// The refusal for a [`Recipient::Unknown`]: says nothing was sent, and why.
pub(crate) fn refusal(to: &str, candidates: &[String]) -> String {
    let head = format!(
        "no inbox named '{to}': nothing reads mail sent there, so the message was not sent. \
         Names are <account>/<type>-<session> (noo_agent_whoami shows yours)"
    );
    if candidates.is_empty() {
        format!("{head}; no registered name is close")
    } else {
        format!("{head}; did you mean: {}", candidates.join(", "))
    }
}

/// The warning a [`Recipient::Unheld`] send carries.
pub(crate) fn unheld_warning(to: &str, candidates: &[String]) -> String {
    let head = format!(
        "no session or key holds '{to}': it was delivered to that name, which only the account's \
         inbox reads (a connection minted by token exchange is fine; a typo is not)"
    );
    if candidates.is_empty() {
        head
    } else {
        format!("{head}; did you mean: {}", candidates.join(", "))
    }
}

/// `to: "thread"` posts into an existing thread; without a thread id it
/// would open a new thread nobody is in, which is the same lost message.
pub(crate) fn thread_needs_an_id(to: &str, thread_id: Option<&str>) -> Result<(), String> {
    if to == "thread" && thread_id.is_none_or(|t| t.trim().is_empty()) {
        return Err("to: \"thread\" posts into an existing thread and needs thread_id; nothing was sent".into());
    }
    Ok(())
}

/// Check `to` against the database. `scope` is the account whose names a
/// refusal or warning may list (`None` = every account: an operator); a name
/// in another account is still delivered when it is held, only not suggested.
pub(crate) async fn check(db: &PgPool, to: &str, scope: Option<&str>) -> Result<Recipient, sqlx::Error> {
    let standing = standing(db, to).await?;
    if standing == Standing::Held {
        return Ok(Recipient::Known);
    }
    let mut registered = crate::repo::agent_recipients::session_names(db, scope, NAME_SCAN).await?;
    for n in key_connections(db, scope).await? {
        if !registered.contains(&n) {
            registered.push(n);
        }
    }
    Ok(decide(to, standing, &registered))
}

async fn standing(db: &PgPool, to: &str) -> Result<Standing, sqlx::Error> {
    if matches!(to, "*" | "broadcast" | "thread") {
        // Not names: fan-out has its own rule (check_broadcast), and
        // "thread" posts to a thread's members, which the caller's seat in
        // it (and a thread_id, `thread_needs_an_id`) decides.
        return Ok(Standing::Held);
    }
    let Some((account, label)) = to.split_once(crate::auth::CONNECTION_SEP) else {
        let held = crate::repo::users::exists(db, to).await? || crate::repo::agent_recipients::node_exists(db, to).await?;
        return Ok(if held { Standing::Held } else { Standing::Nobody });
    };
    if crate::repo::agent_recipients::node_exists(db, account).await?
        || crate::repo::agent_recipients::session_exists(db, account, label).await?
        || key_connections(db, Some(account)).await?.iter().any(|n| n == to)
    {
        return Ok(Standing::Held);
    }
    Ok(if crate::repo::users::exists(db, account).await? { Standing::AccountOnly } else { Standing::Nobody })
}

/// `<account>/<label>` of the active service keys' connections.
async fn key_connections(db: &PgPool, account: Option<&str>) -> Result<Vec<String>, sqlx::Error> {
    Ok(crate::repo::agent_recipients::key_consumers(db, account)
        .await?
        .into_iter()
        .filter_map(|(acct, consumer)| crate::auth::connection_label(&consumer).map(|l| format!("{acct}{}{l}", crate::auth::CONNECTION_SEP)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        ["rbpai/claude-general", "rbpai/claude-harness", "rbwolf/claude-self-rbwolf", "rbwolf/codex-general2"].map(String::from).to_vec()
    }

    /// The i277g case: a bare `general` reaches nobody. It is refused, naming
    /// the sessions it probably meant, and the refusal says nothing was sent.
    #[test]
    fn an_unknown_name_is_refused_with_candidates() {
        let Recipient::Unknown(c) = decide("general", Standing::Nobody, &names()) else { panic!("general must be refused") };
        assert_eq!(c, ["rbpai/claude-general", "rbwolf/codex-general2"]);
        let msg = refusal("general", &c);
        assert!(msg.contains("was not sent") && msg.contains("did you mean: rbpai/claude-general"), "{msg}");
        // Nothing close at all: still refused, and says so.
        let Recipient::Unknown(c) = decide("nobody", Standing::Nobody, &names()) else { panic!() };
        assert!(c.is_empty());
        assert!(refusal("nobody", &c).ends_with("no registered name is close"));
    }

    /// A held name is delivered as written, with nothing to warn about.
    #[test]
    fn a_known_name_is_delivered_as_written() {
        assert_eq!(decide("rbpai/claude-general", Standing::Held, &names()), Recipient::Known);
        assert_eq!(decide("rbwolf", Standing::Held, &names()), Recipient::Known);
    }

    /// Under a real account but held by nobody: delivered (the account's
    /// inbox reads it, and a minted connection has no row), with a warning
    /// that names the registered names it may have meant. The prefix of one
    /// name is offered first, never substituted.
    #[test]
    fn an_unheld_name_under_an_account_is_delivered_with_a_warning() {
        let Recipient::Unheld(c) = decide("rbpai/claude-gen", Standing::AccountOnly, &names()) else { panic!() };
        assert_eq!(c, ["rbpai/claude-general"], "the one name it is the start of");
        let w = unheld_warning("rbpai/claude-gen", &c);
        assert!(w.contains("delivered to that name") && w.ends_with("did you mean: rbpai/claude-general"), "{w}");
        // A typo inside the account: nothing starts with or contains it, so
        // the account's own names are offered.
        let Recipient::Unheld(c) = decide("rbpai/claude-genreal", Standing::AccountOnly, &names()) else { panic!() };
        assert_eq!(c, ["rbpai/claude-general", "rbpai/claude-harness"]);
        // A minted window with a registered namesake is not rewritten: the
        // namesake is only suggested.
        let reg = vec!["alice/w10".to_string()];
        assert_eq!(decide("alice/w1", Standing::AccountOnly, &reg), Recipient::Unheld(vec!["alice/w10".into()]));
        // The name itself is never offered as its own alternative.
        let Recipient::Unheld(c) = decide("rbpai/claude-general", Standing::AccountOnly, &names()) else { panic!() };
        assert!(!c.contains(&"rbpai/claude-general".to_string()), "{c:?}");
    }

    #[test]
    fn a_thread_post_needs_its_thread() {
        assert!(thread_needs_an_id("thread", None).unwrap_err().contains("nothing was sent"));
        assert!(thread_needs_an_id("thread", Some(" ")).is_err());
        assert!(thread_needs_an_id("thread", Some("thr_a")).is_ok());
        assert!(thread_needs_an_id("rbpai/claude-general", None).is_ok());
    }

    /// Both ways a message is sent check the recipient before publishing:
    /// the HTTP route the MCP doors call, and the loop's native tool.
    #[test]
    fn both_send_paths_check_before_they_publish() {
        for (file, src, f) in [
            ("routes/agents.rs", include_str!("routes/agents.rs"), "async fn messages_send("),
            ("tools.rs", include_str!("tools.rs"), "async fn native_agent_message("),
        ] {
            let start = src.find(f).unwrap_or_else(|| panic!("{file}: {f} not found"));
            let body = &src[start..];
            let check = body.find("agent_recipient::check(").unwrap_or_else(|| panic!("{file}: {f} does not check the recipient"));
            let publish = body.find("agent_messages::publish(").unwrap_or_else(|| panic!("{file}: {f} does not publish"));
            assert!(check < publish, "{file}: {f} publishes before it checks the recipient");
        }
    }
}
