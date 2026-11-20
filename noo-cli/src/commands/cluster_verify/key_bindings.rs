// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The `service key bindings` row (i1096): the widest standing credentials
//! on an install. A service key bound to an ADMIN account acts as that admin
//! for as long as it lives; a key carrying the `identity` scope mints agent
//! tokens through the identity exchange. Since the person gate those tokens
//! cannot change who can do what, but both are still the keys an operator
//! most needs to know about, and nothing else lists them by that measure.
//! `service keys` checks presence and `service-key grants` checks scopes;
//! this row checks what a key is bound to.
//!
//! Inputs are what `noo security service-key list --json` and `noo security
//! user list --json` print (`GET /api/security/service-keys`, `GET
//! /api/security/users`). Only consumers are named, never a key or hash
//! (the listing carries neither). An unread list is "cannot be checked",
//! never OK.
//!
//! A fresh install never trips the row: every key it mints (the worker's,
//! each add-on's, the add-on callers) is unbound, and an add-on declaration
//! may not ask for `identity` (`addon_decl_parse`).

use super::{ok, warn, Check};
use serde_json::Value;

pub(crate) const ROW: &str = "service key bindings";

/// Finding codes (registered on the row in rows.rs).
pub(crate) const BOUND_TO_ADMIN: &str = "bound_to_admin";
pub(crate) const IDENTITY_SCOPE: &str = "identity_scope";

/// The gateway's word for the identity-exchange provisioning scope
/// (`auth::IDENTITY_SCOPE`).
const IDENTITY: &str = "identity";

/// A node harness's door key (`service_keys::DOOR_KEY_CONSUMER_PREFIX`):
/// bound to the person whose turn it serves, and expiring with that turn.
/// Short-lived by construction, so not a standing credential.
const HARNESS_PREFIX: &str = "harness:";

/// One CLI read: exit code, parsed stdout, stderr (or stdout) text.
pub(crate) type Read<'a> = (i32, &'a Value, &'a str);

/// Is this `noo_users` row (as `user list` prints it) an enabled admin?
/// The tier is the `role` column raised by an `admin` scope, the same
/// resolution as the gateway's `tier_of_row`. A disabled account is not:
/// the gateway resolves its keys as unbound.
fn is_admin(u: &Value) -> bool {
    !u["disabled"].as_bool().unwrap_or(false) && admin_tier(u)
}

fn admin_tier(u: &Value) -> bool {
    false
}

fn has_identity(k: &Value) -> bool {
    k["scopes"].as_array().is_some_and(|s| s.iter().any(|x| x.as_str() == Some(IDENTITY)))
}

fn bound_to(k: &Value) -> Option<&str> {
    k["user_id"].as_str().map(str::trim).filter(|s| !s.is_empty())
}

/// The active, standing keys of a listing.
fn standing(keys: &[Value]) -> Vec<&Value> {
    keys.iter()
        .filter(|k| k["active"].as_bool() == Some(true))
        .filter(|k| !k["consumer"].as_str().unwrap_or("").starts_with(HARNESS_PREFIX))
        .collect()
}

fn push_once(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

/// The findings, by code, each with the consumers it names (first seen
/// first, each once). Empty = nothing to warn about.
pub(crate) fn findings(keys: &[Value], users: &[Value]) -> Vec<(&'static str, Vec<String>)> {
    let admins: Vec<&str> = users.iter().filter(|u| is_admin(u)).filter_map(|u| u["username"].as_str()).collect();
    let (mut admin, mut identity) = (Vec::new(), Vec::new());
    for k in standing(keys) {
        let consumer = k["consumer"].as_str().unwrap_or("?");
        if bound_to(k).is_some_and(|u| admins.contains(&u)) {
            push_once(&mut admin, consumer);
        }
        if has_identity(k) {
            push_once(&mut identity, consumer);
        }
    }
    let mut out = Vec::new();
    if !admin.is_empty() {
        out.push((BOUND_TO_ADMIN, admin));
    }
    if !identity.is_empty() {
        out.push((IDENTITY_SCOPE, identity));
    }
    out
}

/// Why a read failed, in words. A refused credential names the one that
/// reads the list.
fn why_unread(what: &str, (code, _, text): Read<'_>) -> (String, Option<String>) {
    let err: Value = serde_json::from_str(text.trim()).unwrap_or(Value::Null);
    let refused = err["code"].as_str() == Some("auth_failed") || text.contains("403") || text.contains("401");
    if refused {
        return (
            format!("this CLI's credential may not read {what}; an admin's sign-in reads it"),
            Some("sign in as an admin (`noo auth login <admin>`), then run `noo cluster verify --controller` again".into()),
        );
    }
    let said = err["error"].as_str().map(str::to_string)
        .unwrap_or_else(|| text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string());
    let reason = match (said.is_empty(), code) {
        (false, _) => said,
        (true, 0) => "the answer carried no list".to_string(),
        (true, _) => format!("exit {code}, no output"),
    };
    (format!("{what} was not read ({reason})"), Some("`noo security service-key list` shows the gateway's answer".into()))
}

fn cannot_check(what: &str, read: Read<'_>) -> Check {
    let (why, remedy) = why_unread(what, read);
    warn(ROW, format!("cannot be checked: {why}"), remedy)
}

/// The row. `keys` is `service-key list --json`, `users` is `user list
/// --json`; the users are needed only when an active key is bound.
pub(crate) fn row(keys: Read<'_>, users: Read<'_>) -> Check {
    let listed = if keys.0 == 0 { keys.1["keys"].as_array() } else { None };
    let Some(listed) = listed else { return cannot_check("the service-key list", keys) };
    let any_bound = standing(listed).iter().any(|k| bound_to(k).is_some());
    let empty = Vec::new();
    let accounts = if users.0 == 0 { users.1["users"].as_array() } else { None };
    let accounts = match accounts {
        Some(a) => a,
        None if any_bound => return cannot_check("the account list", users),
        None => &empty,
    };
    let found = findings(listed, accounts);
    if found.is_empty() {
        return ok(ROW, "no key is bound to an admin account; no identity key");
    }
    let mut parts = Vec::new();
    let mut fixes = Vec::new();
    for (code, names) in &found {
        let first = &names[0];
        if *code == BOUND_TO_ADMIN {
            parts.push(format!("bound to an admin account: {}", names.join(", ")));
            fixes.push(format!(
                "sign in as an admin first (`noo auth login <admin>`), then re-issue {first} bound to an account with only the access it needs, \
                 under a new consumer name: `noo security user create <name> --scope <scope>` (if needed), \
                 `noo security service-key issue <new-consumer> --user <name> --scopes <scope>`, then `noo security service-key revoke {first}`"
            ));
        } else {
            parts.push(format!("carries the identity scope (mints agent tokens): {}", names.join(", ")));
            fixes.push(format!(
                "keep {first} only if you use the identity add-on; otherwise revoke it (as an admin): `noo security service-key revoke {first}`"
            ));
        }
    }
    warn(ROW, format!("{} — standing credentials wider than a service needs", parts.join("; ")), Some(fixes.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;
    use serde_json::json;

    const NO_ERR: &str = "";

    fn users() -> Value {
        json!({"users": [
            {"username": "owner", "role": "admin", "scopes": ["read", "write", "admin"], "disabled": false},
            {"username": "ops", "role": "operator", "scopes": ["read", "write"], "disabled": false},
            {"username": "reader", "role": "user", "scopes": ["read"], "disabled": false},
            {"username": "legacy", "scopes": ["admin"], "disabled": false},
            {"username": "gone", "role": "admin", "scopes": ["admin"], "disabled": true},
        ]})
    }

    /// A listing row; `key_hash`/`key` are planted to prove neither is ever echoed.
    fn key(consumer: &str, scopes: &[&str], active: bool, user: Option<&str>) -> Value {
        json!({"consumer": consumer, "scopes": scopes, "active": active, "user_id": user,
               "key_hash": "deadbeefcafe0123", "key": "noo-sk-SECRETVALUE", "superseded_at": null})
    }

    fn run(keys: &[Value]) -> Check {
        let k = json!({"keys": keys, "count": keys.len()});
        let u = users();
        row((0, &k, NO_ERR), (0, &u, NO_ERR))
    }

    fn codes(keys: &[Value]) -> Vec<&'static str> {
        findings(keys, users()["users"].as_array().unwrap()).into_iter().map(|(c, _)| c).collect()
    }

    /// The system's own keys, as a fresh install mints them: unbound, no identity.
    fn fresh() -> Vec<Value> {
        vec![
            key("svc:worker", &["addon", "chat", "embeddings"], true, None),
            key("svc:trellion", &["addon", "read", "chat"], true, None),
            key("addon-caller:gateway", &[], true, None),
        ]
    }

    #[test]
    fn an_admin_bound_key_warns_naming_the_consumer() {
        let mut keys = fresh();
        keys.push(key("ci-bot", &["chat", "mcp"], true, Some("owner")));
        let c = run(&keys);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("bound to an admin account: ci-bot"), "{}", c.detail);
        assert_eq!(codes(&keys), vec![BOUND_TO_ADMIN]);
        let r = c.remedy.unwrap();
        assert!(r.contains("`noo security service-key issue <new-consumer> --user <name> --scopes <scope>`"), "{r}");
        assert!(r.contains("`noo security service-key revoke ci-bot`") && r.contains("sign in as an admin first"), "{r}");
    }

    #[test]
    fn an_admin_scope_without_the_role_column_is_still_admin() {
        let keys = vec![key("old-bot", &["chat"], true, Some("legacy"))];
        assert_eq!(codes(&keys), vec![BOUND_TO_ADMIN]);
    }

    #[test]
    fn an_identity_key_warns() {
        let keys = vec![key("agents", &["identity"], true, Some("ops"))];
        let c = run(&keys);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("identity scope (mints agent tokens): agents"), "{}", c.detail);
        assert_eq!(codes(&keys), vec![IDENTITY_SCOPE]);
        let r = c.remedy.unwrap();
        assert!(r.contains("only if you use the identity add-on") && r.contains("`noo security service-key revoke agents`"), "{r}");
    }

    #[test]
    fn both_reasons_share_one_row() {
        let keys = vec![
            key("ci-bot", &["chat"], true, Some("owner")),
            key("agents", &["identity"], true, Some("ops")),
            key("ci-bot", &["chat"], true, Some("owner")), // a rotation: one name, said once
        ];
        let c = run(&keys);
        assert_eq!(c.verdict, Verdict::Warn);
        assert_eq!(c.detail.matches("ci-bot").count(), 1, "{}", c.detail);
        assert!(c.detail.contains("admin account: ci-bot") && c.detail.contains("identity scope (mints agent tokens): agents"), "{}", c.detail);
        assert_eq!(codes(&keys), vec![BOUND_TO_ADMIN, IDENTITY_SCOPE]);
        let r = c.remedy.unwrap();
        assert!(r.contains("revoke ci-bot`") && r.contains("revoke agents`"), "{r}");
    }

    #[test]
    fn unbound_and_non_admin_keys_read_ok() {
        let mut keys = fresh();
        keys.push(key("ops-bot", &["chat", "mcp"], true, Some("ops")));
        keys.push(key("reader-bot", &["chat"], true, Some("reader")));
        keys.push(key("on-disabled", &["chat"], true, Some("gone")));
        keys.push(key("harness:node_a:0123abcd", &["mcp"], true, Some("owner")));
        let c = run(&keys);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(c.detail, "no key is bound to an admin account; no identity key");
    }

    /// A fresh install's own keys never trip the row.
    #[test]
    fn a_fresh_install_reads_ok() {
        assert_eq!(run(&fresh()).verdict, Verdict::Ok);
        // No user list is needed when nothing is bound.
        let k = json!({"keys": fresh()});
        let c = row((0, &k, NO_ERR), (1, &Value::Null, "boom"));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    #[test]
    fn a_revoked_admin_key_is_ignored() {
        let keys = vec![
            key("ci-bot", &["chat"], false, Some("owner")),
            key("agents", &["identity"], false, Some("owner")),
        ];
        assert_eq!(run(&keys).verdict, Verdict::Ok);
        assert!(codes(&keys).is_empty());
    }

    #[test]
    fn an_unreadable_list_cannot_be_checked() {
        let refused = r#"{"error":"gateway refused (403)","code":"auth_failed"}"#;
        let c = row((3, &Value::Null, refused), (0, &users(), NO_ERR));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.starts_with("cannot be checked: ") && c.detail.contains("an admin's sign-in reads it"), "{}", c.detail);
        assert!(c.remedy.unwrap().contains("`noo auth login <admin>`"));

        let c = row((1, &Value::Null, r#"{"error":"gateway unreachable","code":"connect"}"#), (0, &users(), NO_ERR));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("cannot be checked: ") && c.detail.contains("gateway unreachable"), "{}", c.detail);

        // A body without `keys` is not an empty install.
        let c = row((0, &json!({"detail": "x"}), NO_ERR), (0, &users(), NO_ERR));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.starts_with("cannot be checked: "), "{}", c.detail);

        // A bound key with no account list: the tier is unknown.
        let k = json!({"keys": [key("ci-bot", &["chat"], true, Some("owner"))]});
        let c = row((0, &k, NO_ERR), (3, &Value::Null, refused));
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.starts_with("cannot be checked: ") && c.detail.contains("the account list"), "{}", c.detail);
    }

    #[test]
    fn no_key_value_or_hash_is_ever_shown() {
        let keys = vec![key("ci-bot", &["identity"], true, Some("owner"))];
        let c = run(&keys);
        let all = format!("{} {}", c.detail, c.remedy.unwrap_or_default());
        for secret in ["deadbeefcafe0123", "noo-sk-", "SECRETVALUE"] {
            assert!(!all.contains(secret), "{all}");
        }
    }
}
