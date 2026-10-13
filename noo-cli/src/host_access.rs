// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Host-level access to the gateway's accounts — no login, no shared secret.
//!
//! Two jobs must work on a controller where nobody holds a login:
//!
//! - **the onboard wizard on a re-run** that has no password in hand (a
//!   `--non-interactive` run, or the operator declined to type it) but must
//!   still mint the stack's service keys and write the hardened posture;
//! - **recovering the admin account**: a lost password, a locked or disabled
//!   account, or no admin row at all (`noo security admin-password reset`).
//!
//! Both used to lean on the controller's shared secret (`cli-onboard`,
//! `--break-glass`). That is gone
//! by design (no break-glass; recovery uses the same path end users see).
//! What replaces it is the access
//! the controller HOST already has: `docker exec <postgres> psql` as the
//! database's own superuser, over the container's unix socket — the same
//! path `noo db status` and `noo security secrets rotate` use.
//!
//! **The threat model, stated once.** Anyone who is root on the controller,
//! or is the operator account there (docker group), already owns the
//! install: the CA key, the sops age key, and this database. Nothing here
//! adds to that: it needs exactly that access, and it is not reachable from
//! the network — a request to the gateway can neither write a ticket nor
//! reset a password. The one thing the gateway accepts that it did not
//! before is `grant_type=host_ticket` at `/auth/token`, and only a ticket
//! whose hash THIS host wrote into `noo_host_login_tickets`: 256 random
//! bits, five minutes, one use, for one named account.

use sha2::{Digest, Sha256};

use crate::Globals;

/// The gateway's grant (`routes/core.rs::HOST_TICKET_GRANT`).
pub const HOST_TICKET_GRANT: &str = "host_ticket";
/// Every ticket starts with this, so a log scrubber can recognise one.
pub const TICKET_PREFIX: &str = "noo-ht-";
/// How long a ticket lives. It is exchanged within the second it is minted.
pub const TICKET_TTL_MINUTES: u32 = 5;
/// The scopes a recreated admin row carries (`repo::users::create` derives
/// `role = admin` from the same set).
const ADMIN_SCOPES: &str = r#"["read","write","admin"]"#;

/// Where the gateway's database is, from the controller's side.
#[derive(Debug, Clone)]
pub(crate) struct HostDb {
    pub container: String,
    pub superuser: String,
    pub db: String,
}

impl HostDb {
    /// The same resolution `noo security secrets rotate` uses.
    pub fn resolve() -> Self {
        crate::envfile::ensure_repo_env();
        HostDb {
            container: std::env::var("PGCONTAINER").unwrap_or_else(|_| crate::envfile::container("postgres")),
            superuser: std::env::var("POSTGRES_USER").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "noo".into()),
            db: crate::commands::secrets::postgres_db(),
        }
    }

    fn run(&self, sql: &str) -> Result<(), String> {
        #[cfg(test)]
        if let Some(()) = TEST_SQL.with(|t| t.borrow_mut().as_mut().map(|v| v.push(sql.to_string()))) {
            return Ok(());
        }
        crate::commands::secrets::psql_stdin(&self.container, &self.superuser, &self.db, sql).map_err(|e| {
            format!(
                "could not write to the gateway's database through `docker exec {} psql` ({e}) — this \
                 runs on the controller host, as root or an account in the docker group",
                self.container
            )
        })
    }
}

#[cfg(test)]
thread_local! {
    /// In-process tests capture the SQL instead of running `docker exec`.
    /// `Some` = capture on this thread; `None` (the default) = really run.
    pub(crate) static TEST_SQL: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

/// An account name safe to put in SQL and in a log line.
pub(crate) fn validate_account(account: &str) -> Result<(), String> {
    let ok = !account.is_empty()
        && account.len() <= 64
        && account.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    if ok {
        Ok(())
    } else {
        Err(format!("'{account}' is not an account name (letters, digits, . _ - @; at most 64)"))
    }
}

fn quote(v: &str) -> String {
    crate::commands::secrets::sql_quote(v)
}

/// The mesh tables live in schema `mesh` on a fresh install and `public` on
/// a legacy one — the gateway pins the same path for its own pool.
const SEARCH_PATH: &str = "SET search_path TO mesh, public;\n";

/// The SQL that records one ticket. Only the sha256 of the ticket is in it.
pub(crate) fn ticket_sql(hash: &str, account: &str, purpose: &str) -> String {
    format!(
        "{SEARCH_PATH}INSERT INTO noo_host_login_tickets (token_hash, username, purpose, expires_at) \
         VALUES ({}, {}, {}, now() + interval '{TICKET_TTL_MINUTES} minutes');\n",
        quote(hash),
        quote(account),
        quote(purpose)
    )
}

/// sha256 hex, the gateway's `auth_refresh::hash_token`.
pub(crate) fn ticket_hash(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Mint a one-time ticket for `account` and return it. Never printed.
pub(crate) fn mint_ticket(db: &HostDb, account: &str, purpose: &str) -> Result<String, String> {
    validate_account(account)?;
    let raw = format!("{TICKET_PREFIX}{}", crate::onboard::util::token_urlsafe(32));
    db.run(&ticket_sql(&ticket_hash(&raw), account, purpose))?;
    Ok(raw)
}

/// Log the CLI in as `account` with a fresh host ticket, storing the
/// credential exactly as `noo auth login` does. `Ok(subject)`.
pub(crate) fn login_with_ticket(g: &Globals, account: &str, purpose: &str) -> Result<String, String> {
    let ticket = mint_ticket(&HostDb::resolve(), account, purpose)?;
    crate::commands::auth::login_with_host_ticket(g, account, &ticket)
}

/// The SQL that makes `account` a working admin with `bcrypt_hash` as its
/// password: created when the row is missing, and otherwise re-enabled,
/// unlocked and given back the admin tier. One transaction.
pub(crate) fn reset_admin_sql(account: &str, bcrypt_hash: &str) -> String {
    let (u, h) = (quote(account), quote(bcrypt_hash));
    format!(
        "{SEARCH_PATH}BEGIN;\n\
         INSERT INTO noo_users (username, hashed_password, scopes, disabled, failed_login_count, org_id, role) \
         VALUES ({u}, {h}, '{ADMIN_SCOPES}'::jsonb, false, 0, 'default', 'admin') \
         ON CONFLICT (username) DO UPDATE SET \
         hashed_password = EXCLUDED.hashed_password, password_changed_at = now(), \
         failed_login_count = 0, locked_until = NULL, disabled = false, \
         scopes = CASE WHEN COALESCE(noo_users.scopes, '[]'::jsonb) @> '[\"admin\"]'::jsonb \
         THEN noo_users.scopes ELSE '{ADMIN_SCOPES}'::jsonb END, \
         role = 'admin';\n\
         COMMIT;\n"
    )
}

/// Write `account`'s new password straight into the gateway's database.
/// Works with the gateway down, with no admin row left, and on a locked or
/// disabled account.
pub(crate) fn reset_admin(db: &HostDb, account: &str, password: &str) -> Result<(), String> {
    validate_account(account)?;
    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| format!("bcrypt: {e}"))?;
    db.run(&reset_admin_sql(account, &hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_row_carries_only_the_hash() {
        let raw = format!("{TICKET_PREFIX}abc");
        let sql = ticket_sql(&ticket_hash(&raw), "admin", "onboard");
        assert!(!sql.contains(&raw), "the ticket itself must never reach psql: {sql}");
        assert!(sql.contains(&ticket_hash(&raw)));
        assert!(sql.contains("'admin'") && sql.contains("'onboard'"));
        assert!(sql.starts_with("SET search_path TO mesh, public;"), "{sql}");
        assert!(sql.contains("interval '5 minutes'"), "{sql}");
    }

    /// The gateway hashes a presented ticket with `auth_refresh::hash_token`
    /// (sha256, lowercase hex); the row must hold the same string.
    #[test]
    fn the_hash_is_the_gateways() {
        assert_eq!(ticket_hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn the_reset_recreates_reenables_and_unlocks_the_admin() {
        let sql = reset_admin_sql("admin", "$2b$12$abcdefghijklmnopqrstuv");
        for needle in [
            "INSERT INTO noo_users",
            "ON CONFLICT (username) DO UPDATE",
            "disabled = false",
            "locked_until = NULL",
            "failed_login_count = 0",
            "role = 'admin'",
            "'$2b$12$abcdefghijklmnopqrstuv'",
            "BEGIN;",
            "COMMIT;",
        ] {
            assert!(sql.contains(needle), "missing {needle}: {sql}");
        }
    }

    /// The SQL is built by quoting, and the name is checked first: an
    /// account name is the one value here an operator types.
    #[test]
    fn account_names_are_checked_before_they_reach_sql() {
        for bad in ["", "a'b", "a b", "a;b", "x\\", &"a".repeat(65)] {
            assert!(validate_account(bad).is_err(), "{bad:?}");
        }
        for good in ["admin", "alice.b", "ops-1", "a_b", "me@example.com"] {
            assert!(validate_account(good).is_ok(), "{good}");
        }
    }

    /// The gateway's migration and this module name the same table and
    /// columns. A rename on one side would be a ticket nobody can spend.
    #[test]
    fn the_ticket_table_matches_the_gateways_migration() {
        let mig = include_str!("../../gateway-rust/src/mesh_migrate.rs");
        let m = mig.split("revision: \"081_host_login_tickets\"").nth(1).expect("migration 081");
        for col in ["noo_host_login_tickets", "token_hash", "username", "purpose", "expires_at", "used_at"] {
            assert!(m.contains(col), "migration 081 lacks {col}");
        }
        let core = include_str!("../../gateway-rust/src/routes/core.rs");
        assert!(core.contains(&format!("pub(crate) const HOST_TICKET_GRANT: &str = \"{HOST_TICKET_GRANT}\";")));
        assert!(core.contains("auth_refresh::hash_token(ticket.trim())"), "the gateway hashes the ticket as sha256 hex");
    }
}
