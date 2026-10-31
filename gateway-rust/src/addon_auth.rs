// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The credential the gateway presents when it calls an add-on.
//!
//! Until this existed, `addon_proxy::forward` opened an outbound request and
//! sent nothing: no bearer, no caller name, no user. An add-on on the mesh
//! network answered anything that could reach its port, and it could not tell
//! an operator's request from the meta-loop's own. "Which add-on" was the only
//! thing either side knew about the other.
//!
//! ## Why a DB row and not an env var
//!
//! A shared `NOO_ADDON_SECRET` in `secrets/env.sops` would be one string in
//! two containers, rotated by editing the secret store and recreating both —
//! the shape that `noo_service_keys` replaced on the external boundary in
//! August (`service_keys.rs`). Reusing that table instead buys the properties
//! it already has: hashed at rest, attributable per consumer, revocable one
//! row at a time, and rotatable without a secret-store edit.
//!
//! ## Not the same key as the shared secret
//!
//! Each internal service has its own `noo_service_keys` row for
//! calling the GATEWAY — `NOO_GATEWAY_KEY`, minted when the service is
//! enabled, replacing the shared controller secret. This is the opposite leg:
//! the gateway calling the ADD-ON. Same table, same properties, reversed
//! direction, and the two must not be conflated — a row named
//! `addon-caller:gateway` is presented BY the gateway and is meaningless at
//! the gateway's own door, which is why it is minted with no scopes.
//!
//! ## Rotation is a gateway start
//!
//! [`init`] mints a fresh token on every boot, writes its hash, and
//! deactivates the previous row for the same consumer. The raw token exists
//! only in this process's memory — it is never logged, never written, never
//! read back. An add-on verifies by hashing what it was presented and looking
//! the hash up, so a restart re-keys the pair with no coordination and a
//! `noo security service-key revoke addon-caller:gateway` cuts the gateway
//! off until it restarts.
//!
//! This assumes ONE gateway per mesh, which is what the controller is. Two
//! would each mint and deactivate the other's row; the loser's calls would
//! fail closed (401), not silently succeed, but it is not a supported shape.
//!
//! ## What the add-on does with it
//!
//! The add-on's DB role cannot read `noo_service_keys` — `034_evolve_role`
//! grants ownership of five tables and nothing else. Mesh revision
//! `077_addon_caller_verify_view` adds a view over the add-on-caller rows
//! alone, so an add-on verifies offline against the shared Postgres without
//! gaining sight of any other consumer's key. An add-on gets SELECT on it by
//! declaring `verify_callers` in its signed `system.json`
//! (`system_provision::sync_caller_verifier`). The contract is written up in
//! `docs/development/addons.md`.
//!
//! ## The `noo-ak-` prefix
//!
//! Until 1281 the token was 64 bare hex, which no log scrubber can tell from
//! an image digest — and digests must not be scrubbed. It now carries
//! [`KEY_PREFIX`], as service keys carry `noo-sk-`, and the hash published is
//! of the WHOLE presented string, prefix included. An add-on verifies by
//! hashing what it was presented, so one built before the prefix (it never
//! parsed the value) verifies the new form unchanged. No unprefixed key can
//! outlive the roll: the only holder is the gateway process that minted it,
//! and the next gateway start retires its row. An add-on may still count a
//! bare-hex bearer it is shown — that is an older gateway, and the evidence
//! the "both forms" window can close on.

use std::sync::OnceLock;

use sqlx::PgPool;

/// The single consumer name the gateway issues itself. An add-on that reads
/// the view sees this and nothing else, so the name is part of the contract.
pub const CALLER_CONSUMER: &str = "addon-caller:gateway";

/// What every caller key starts with. The scrubbers (`redact.rs`, the Go
/// twin) key the `addon-key` row on it; changing it here without them puts
/// the key back among the shapes a log line ships in the clear.
pub const KEY_PREFIX: &str = "noo-ak-";

static TOKEN: OnceLock<String> = OnceLock::new();

/// Why this boot has no caller credential, when [`init`] ran and could not
/// mint one. `/health` reports it and `noo cluster verify` fails on it.
static FAILURE: OnceLock<String> = OnceLock::new();

/// What a boot without the credential costs and what fixes it, in the ERROR
/// line and in `/health`. An add-on that checks the caller (evolve since
/// noomesh followup 304) refuses every unsigned call with 401, so this is
/// never only a warning.
pub const MISSING_REMEDY: &str = "every add-on call from this gateway goes out unsigned, and an add-on that checks \
     its caller (evolve) refuses each one with 401. Fix the database error and restart the gateway \
     (`noo stack restart gateway`): each start mints a new key";

/// The bearer to present to an add-on, or `None` when [`init`] has not run or
/// could not write the row.
///
/// `None` is deliberately not fatal: an add-on built before this contract
/// ignores the header, and the gateway refusing to call it over a missing
/// credential would turn a hardening step into an outage.
pub fn token() -> Option<&'static str> {
    TOKEN.get().map(String::as_str)
}

/// Why [`init`] could not mint this boot's credential, or `None` when it
/// minted one or has not run.
pub fn failure() -> Option<&'static str> {
    FAILURE.get().map(String::as_str)
}

/// Record a failed mint and say so at ERROR level with the remedy.
fn failed(step: &str, e: &sqlx::Error) {
    let why = format!("could not {step}: {e}");
    tracing::error!(consumer = CALLER_CONSUMER, "addon caller credential NOT minted: {why}; {MISSING_REMEDY}");
    let _ = FAILURE.set(why);
}

/// How long a retired caller row is kept before [`prune_retired`] deletes it.
///
/// A caller row is retired by the NEXT gateway start (or by an operator's
/// `service-key revoke`), and nothing ever presents it again: the only holder
/// of the raw token was the process that minted it. What a retired row still
/// answers is "which boot's key signed the add-on call in this log line", and
/// that question is asked during an incident, days not weeks after. Seven
/// days covers a long weekend plus the time to notice; past that the rows are
/// the noise that buried the live keys in `service-key list --all` (twenty-one
/// rows in two days of provisioning churn, 2026-09-22).
///
/// Age is `created_at`: the table has no revoked-at column, and a caller
/// row's creation is the previous boot, so this errs toward keeping a row
/// for at least the week after it was minted — never toward deleting a live
/// one, which the `active = false` clause rules out on its own.
pub const RETIRED_KEEP_DAYS: i32 = 7;

/// Revoked rows only, add-on CALLER rows only. The prefix is the same
/// `starts_with(consumer, 'addon-caller:')` the `noo_addon_caller_keys` view
/// (077) matches, so the prune and the view agree on what a caller row is.
/// Every other consumer's revoked row is the audit trail of a key a human
/// issued, and stays forever.
const PRUNE_RETIRED_SQL: &str = "DELETE FROM noo_service_keys \
     WHERE active = false \
       AND starts_with(consumer, 'addon-caller:') \
       AND created_at < now() - make_interval(days => $1)";

/// Delete retired add-on caller rows older than [`RETIRED_KEEP_DAYS`];
/// returns how many went.
pub(crate) async fn prune_retired(db: &PgPool) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(PRUNE_RETIRED_SQL).bind(RETIRED_KEEP_DAYS).execute(db).await?.rows_affected())
}

fn mint() -> String {
    use rand::Rng;
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{KEY_PREFIX}{hex}")
}

/// Mint this boot's caller credential and publish its hash.
///
/// A failure does not stop the gateway: it serves everything else, logs at
/// ERROR with [`MISSING_REMEDY`], leaves [`token`] at `None` and [`failure`]
/// set, and `noo cluster verify` fails its `add-on caller key` row.
pub async fn init(db: &PgPool) {
    let token = mint();
    let hash = crate::service_keys::sha256_hex(&token);

    // Deactivate first, insert second, in one statement each. A crash between
    // them leaves NO active caller row, which fails closed; the reverse order
    // would leave two valid tokens, one of which no process holds.
    if let Err(e) = sqlx::query(
        "UPDATE noo_service_keys SET active = false WHERE consumer = $1 AND active = true",
    )
    .bind(CALLER_CONSUMER)
    .execute(db)
    .await
    {
        failed("retire the previous key", &e);
        return;
    }

    // Scopes are empty on purpose. This key names a CALLER; it is not a grant.
    // Anything the gateway is allowed to ask an add-on for is decided by the
    // route manifest and by the requester headers that ride beside it, and a
    // key that resolved to the four inference scopes would read like one that
    // could be presented back at `/api/external/*`.
    if let Err(e) = sqlx::query(
        "INSERT INTO noo_service_keys (id, consumer, key_hash, scopes, active, note) \
         VALUES ($1, $2, $3, '[]'::jsonb, true, $4)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(CALLER_CONSUMER)
    .bind(&hash)
    .bind("minted at gateway start; the raw token lives only in the gateway process")
    .execute(db)
    .await
    {
        failed("publish this boot's key", &e);
        return;
    }

    match prune_retired(db).await {
        // Logged at zero too: "pruned=0" is the line that says the prune
        // ran, which is what to look for when the rows pile up again.
        Ok(n) => tracing::info!(
            pruned = n,
            days = RETIRED_KEEP_DAYS,
            "addon caller credential: pruned retired caller rows"
        ),
        Err(e) => tracing::warn!("addon caller credential: could not prune retired rows: {e}"),
    }

    let _ = TOKEN.set(token);
    tracing::info!(consumer = CALLER_CONSUMER, "addon caller credential minted");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_missing_key_remedy_names_the_cost_and_the_fix() {
        assert!(MISSING_REMEDY.contains("401"), "{MISSING_REMEDY}");
        assert!(MISSING_REMEDY.contains("noo stack restart gateway"), "{MISSING_REMEDY}");
    }

    #[test]
    fn a_minted_token_is_the_prefix_then_64_hex_characters() {
        let t = mint();
        let hex = t.strip_prefix(KEY_PREFIX).expect("a new mint carries the noo-ak- prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn the_prefix_is_the_one_the_scrubbers_key_on() {
        assert_eq!(KEY_PREFIX, "noo-ak-");
        let line = format!("calling evolve with {}", mint());
        assert_eq!(crate::redact::scrub_secrets(&line).0, "calling evolve with <redacted:addon-key>");
    }

    /// The published hash is of the whole presented string, so an add-on
    /// that hashes what it was shown (evolve's `verify_bearer`, unchanged)
    /// finds the new form's row, and a bare-hex key from an older gateway
    /// still finds its own. Stripping the prefix before hashing would have
    /// broken every add-on built before 1281.
    #[test]
    fn both_forms_verify_by_hashing_what_is_presented() {
        let new = mint();
        let old = new.strip_prefix(KEY_PREFIX).unwrap().to_string();
        let rows = [crate::service_keys::sha256_hex(&new), crate::service_keys::sha256_hex(&old)];
        for presented in [&new, &old] {
            assert!(rows.contains(&crate::service_keys::sha256_hex(presented)));
        }
        assert_ne!(rows[0], rows[1], "the two forms are distinct rows, not one hash");
    }

    #[test]
    fn two_mints_differ() {
        assert_ne!(mint(), mint());
    }

    /// The prune against a real database: only RETIRED rows, only add-on
    /// CALLER rows, only past the keep window. The one that matters most is
    /// `svc:worker` — another consumer's revoked row is the audit trail of a
    /// key a human issued, and widening the WHERE clause to "every revoked
    /// row" must turn this red.
    ///
    /// Skips silently without NOO_BROKER_TEST_DSN — CI sets it.
    #[tokio::test]
    async fn the_prune_takes_old_retired_caller_rows_and_nothing_else() {
        let Some(dsn) = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty()) else {
            return;
        };
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await.expect("connect");
        let _ = sqlx::raw_sql("DROP DATABASE IF EXISTS addon_caller_prune_test (FORCE)").execute(&admin).await;
        sqlx::raw_sql("CREATE DATABASE addon_caller_prune_test").execute(&admin).await.expect("create scratch db");
        let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!("{head}/addon_caller_prune_test"))
            .await
            .expect("connect scratch");
        sqlx::raw_sql(
            "CREATE TABLE noo_service_keys ( \
                 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), \
                 consumer text NOT NULL, \
                 key_hash text NOT NULL UNIQUE, \
                 scopes jsonb NOT NULL DEFAULT '[]'::jsonb, \
                 active boolean NOT NULL DEFAULT true, \
                 created_at timestamptz NOT NULL DEFAULT NOW(), \
                 last_used_at timestamptz, \
                 superseded_at timestamptz )",
        )
        .execute(&db)
        .await
        .expect("create table");

        // (key_hash, consumer, active, age in days, survives?)
        let rows: [(&str, &str, bool, i32, bool); 7] = [
            ("live", CALLER_CONSUMER, true, 30, true),
            ("old-retired", CALLER_CONSUMER, false, 30, false),
            ("just-past", CALLER_CONSUMER, false, RETIRED_KEEP_DAYS + 1, false),
            ("other-caller-old", "addon-caller:other", false, 10, false),
            ("recent-retired", CALLER_CONSUMER, false, 2, true),
            ("human-revoked", "svc:worker", false, 30, true),
            ("not-a-prefix", "x-addon-caller:gateway", false, 30, true),
        ];
        for (hash, consumer, active, days, _) in rows {
            sqlx::query(
                "INSERT INTO noo_service_keys (consumer, key_hash, active, created_at) \
                 VALUES ($1, $2, $3, now() - make_interval(days => $4))",
            )
            .bind(consumer)
            .bind(hash)
            .bind(active)
            .bind(days)
            .execute(&db)
            .await
            .expect("insert");
        }

        let pruned = prune_retired(&db).await.expect("prune");
        let mut left: Vec<String> = sqlx::query_scalar("SELECT key_hash FROM noo_service_keys")
            .fetch_all(&db)
            .await
            .expect("select");
        left.sort();
        let mut want: Vec<String> = rows.iter().filter(|r| r.4).map(|r| r.0.to_string()).collect();
        want.sort();
        db.close().await;
        let _ = sqlx::raw_sql("DROP DATABASE IF EXISTS addon_caller_prune_test (FORCE)").execute(&admin).await;

        assert_eq!(left, want, "the prune took the wrong rows");
        assert_eq!(pruned, 3, "rows_affected is the count the gateway logs");
    }

    #[test]
    fn the_consumer_name_is_namespaced_so_the_view_can_match_it() {
        assert!(CALLER_CONSUMER.starts_with("addon-caller:"));
    }
}
