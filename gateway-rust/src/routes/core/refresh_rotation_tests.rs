// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Refresh-token rotation under real concurrency.
//!
//! The property under test is not expressible against a mock: "exactly one of
//! two simultaneous presentations of the same refresh token succeeds" is a
//! statement about a Postgres row lock and the `WHERE revoked_at IS NULL`
//! predicate on an `UPDATE … RETURNING`. A fake store would either serialise
//! the two calls (and pass on the broken code) or not model the lock at all.
//!
//! Before the fix the handler was `lookup` → mint → `store` → `revoke`, four
//! statements with nothing holding the row. Both callers read
//! `revoked_at IS NULL`, both minted, both stored a child, and the replay
//! detector never fired — the exact race a stolen cookie runs. Running
//! `two_concurrent_presentations_exactly_one_wins` against that code gives two
//! winners, no replay and no audit row.
//!
//! Gated on `NOO_BROKER_TEST_DSN` and built the way `routes::ownership_scoping_tests`
//! (#126) and `channels::ingress_and_approval_binding_tests` (#118) are: a
//! scratch DATABASE, the real `mesh_migrate::apply`, and the schema proved
//! reachable before anything is concluded from a query against it.

#![cfg(test)]

use sqlx::PgPool;

use crate::auth_refresh;
use super::{rotate_refresh, Rotation};

const DB_NAME: &str = "refresh_rotation_test";

async fn scratch() -> Option<PgPool> {
    let dsn = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty())?;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&dsn)
        .await
        .expect("connect to NOO_BROKER_TEST_DSN");
    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {DB_NAME} (FORCE)")))
        .execute(&admin)
        .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {DB_NAME}")))
        .execute(&admin)
        .await
        .expect("create scratch db");
    let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
    let scratch_dsn = format!("{head}/{DB_NAME}");

    let build = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&scratch_dsn)
        .await
        .expect("connect scratch");
    unsafe { std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret") };
    for ext in ["vector", "pg_trgm"] {
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}")))
            .execute(&build)
            .await
            .expect("extension");
    }
    crate::mesh_migrate::apply(&build).await.expect("apply migrations");
    build.close().await;

    use std::str::FromStr as _;
    let opts = sqlx::postgres::PgConnectOptions::from_str(&scratch_dsn)
        .expect("scratch dsn")
        .options([("search_path", "mesh,public")]);
    let db = sqlx::postgres::PgPoolOptions::new()
        // Deliberately small. Two concurrent rotations must not need more than
        // one connection each: a rotation that holds its transaction open
        // while asking the same pool for a second connection deadlocks here,
        // which is what this number is for.
        .max_connections(4)
        .connect_with(opts)
        .await
        .expect("connect scratch");

    // Prove the fixture before trusting any assertion made against it. A
    // missing column would read as "the rotation refused", which is the
    // answer these tests are trying to earn honestly.
    for (table, column) in [
        ("noo_refresh_tokens", "revoked_at"),
        ("noo_refresh_tokens", "rotated_from"),
        ("noo_refresh_tokens", "last_used_at"),
        ("noo_users", "role"),
        ("noo_security_audit", "severity"),
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
              WHERE table_name = $1 AND column_name = $2)",
        )
        .bind(table)
        .bind(column)
        .fetch_one(&db)
        .await
        .expect("read information_schema");
        assert!(
            exists,
            "{table}.{column} must exist in the migrated schema — without it \
             every assertion below would pass by accident"
        );
    }

    // The rotation mints a JWT, which refuses on an unset/placeholder secret
    // (R5). Give it a real one so a refusal here can only mean the rule.
    unsafe { std::env::set_var("NOO_JWT_SECRET", "refresh-rotation-test-secret-not-a-real-key") };
    Some(db)
}

async fn user(db: &PgPool, username: &str) {
    sqlx::query(
        "INSERT INTO noo_users (username, hashed_password, role, scopes, disabled) \
         VALUES ($1, 'x', 'user', '[\"read\"]'::jsonb, false)",
    )
    .bind(username)
    .execute(db)
    .await
    .expect("insert user");
}

/// Issue a live refresh token for `username` and return its raw value.
async fn live_token(db: &PgPool, username: &str) -> String {
    let raw = auth_refresh::generate_raw_token();
    auth_refresh::store_token(
        db,
        username,
        &raw,
        chrono::Utc::now() + chrono::TimeDelta::days(30),
        Some("test-agent"),
        Some("198.51.100.4"),
        None,
    )
    .await
    .expect("store token");
    raw
}

/// Backdate a token's `revoked_at`. The window decision reads that column,
/// so moving it is moving the clock — and a test that slept through a real
/// 10 s window would be a 10 s test that still proved only one boundary.
async fn age_rotation(db: &PgPool, raw: &str, interval: &str) {
    let n = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE noo_refresh_tokens SET revoked_at = NOW() - INTERVAL '{interval}' \
          WHERE token_hash = $1 AND revoked_at IS NOT NULL"
    )))
    .bind(auth_refresh::hash_token(raw))
    .execute(db)
    .await
    .expect("age the rotation")
    .rows_affected();
    // Prove the backdate landed: a no-op UPDATE would leave the row at
    // "just now" and the window assertion below would pass for the wrong
    // reason.
    assert_eq!(n, 1, "expected to backdate exactly one spent token, moved {n}");
}

async fn live_row_count(db: &PgPool, username: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM noo_refresh_tokens \
          WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(username)
    .fetch_one(db)
    .await
    .expect("count live rows")
}

async fn replay_audit_rows(db: &PgPool, username: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT severity FROM noo_security_audit \
          WHERE event_type = 'auth_failure' AND outcome = 'refresh_replay' \
            AND actor = $1",
    )
    .bind(username)
    .fetch_all(db)
    .await
    .expect("read audit rows")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_presentations_exactly_one_wins() {
    let Some(db) = scratch().await else { return };
    user(&db, "alice").await;
    let raw = live_token(&db, "alice").await;

    // Two tasks, one token, released together. On the pre-fix code both come
    // back Rotated: the revoked-token check read a row nothing held.
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let db = db.clone();
        let raw = raw.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            match rotate_refresh(&db, &raw, Some("test-agent"), Some("198.51.100.4")).await {
                Rotation::Rotated { access_token, new_raw, .. } => {
                    assert!(!access_token.is_empty(), "a winner must carry an access token");
                    assert_ne!(new_raw, raw, "the rotated cookie must be a NEW token");
                    "rotated"
                }
                Rotation::Replay => "replay",
                Rotation::Contended => "contended",
                Rotation::Refused(d) => panic!("unexpected refusal: {d}"),
                Rotation::Unavailable(d) => panic!("unexpected 503: {d}"),
                Rotation::Failed(d) => panic!("unexpected 500: {d}"),
                Rotation::Issue(_) => panic!("could not mint an access token"),
            }
        }));
    }
    let mut outcomes = Vec::new();
    for t in tasks {
        outcomes.push(t.await.expect("task panicked"));
    }
    outcomes.sort_unstable();

    assert_eq!(
        outcomes,
        ["contended", "rotated"],
        "exactly one of two simultaneous presentations of the same refresh \
         token may succeed. Two 'rotated' means the claim is not atomic: both \
         callers read revoked_at IS NULL and both minted a live chain from one \
         stolen cookie. The loser is 'contended', not 'replay': its \
         token was spent moments ago by a rotation whose successor nobody has \
         used, which is two tabs and not a thief"
    );

    // The winner's session SURVIVES. This is the whole point of the window:
    // before it, the loser's 'replay' swept every live refresh for the user
    // and logged the person out everywhere for a benign double-refresh.
    assert_eq!(
        live_row_count(&db, "alice").await,
        1,
        "a contended double-refresh must leave the winner's successor alone"
    );
    assert!(
        replay_audit_rows(&db, "alice").await.is_empty(),
        "a benign double-refresh must not write a critical audit row — one per \
         tab race is how the real one stops being noticed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_outside_the_grace_window_still_burns_the_chain() {
    let Some(db) = scratch().await else { return };
    user(&db, "dave").await;
    let raw = live_token(&db, "dave").await;
    assert!(matches!(
        rotate_refresh(&db, &raw, None, None).await,
        Rotation::Rotated { .. }
    ));

    // Three seconds later — inside the 10 s window — is still a tab race.
    // Explicitly aged rather than tested at ~0 s elapsed, because a sign or
    // unit error in `spent_secs_ago` would pass at zero and fail here.
    age_rotation(&db, &raw, "3 seconds").await;
    match rotate_refresh(&db, &raw, None, None).await {
        Rotation::Contended => {}
        other => panic!(
            "3 s after the rotation, with the successor unused, is inside the \
             window — got {}",
            name(&other)
        ),
    }
    assert_eq!(live_row_count(&db, "dave").await, 1);
    assert!(
        replay_audit_rows(&db, "dave").await.is_empty(),
        "a double-refresh 3 s later must write NO critical audit row"
    );

    // Age the rotation past the window rather than sleeping through it: the
    // decision reads `revoked_at`, so moving it is moving the clock.
    age_rotation(&db, &raw, "1 hour").await;

    match rotate_refresh(&db, &raw, None, None).await {
        Rotation::Replay => {}
        other => panic!(
            "a token spent an hour ago is a stolen chain, not a tab race — got {}",
            name(&other)
        ),
    }
    assert_eq!(
        live_row_count(&db, "dave").await,
        0,
        "a replay outside the window must still sweep the chain"
    );
    assert_eq!(replay_audit_rows(&db, "dave").await, ["critical"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_whose_successor_was_used_still_burns_the_chain() {
    let Some(db) = scratch().await else { return };
    user(&db, "erin").await;
    let raw = live_token(&db, "erin").await;
    let child = match rotate_refresh(&db, &raw, None, None).await {
        Rotation::Rotated { new_raw, .. } => new_raw,
        other => panic!("expected a rotation, got {}", name(&other)),
    };
    // The successor has now been SPENT, so the person has gone on with the
    // session. A re-presentation of the parent inside the window is no longer
    // a tab race: somebody is holding a cookie they should not have.
    assert!(matches!(
        rotate_refresh(&db, &child, None, None).await,
        Rotation::Rotated { .. }
    ));

    match rotate_refresh(&db, &raw, None, None).await {
        Rotation::Replay => {}
        other => panic!(
            "the successor was already consumed, so this is a stolen chain \
             however recent the rotation — got {}",
            name(&other)
        ),
    }
    assert_eq!(live_row_count(&db, "erin").await, 0);
    assert_eq!(replay_audit_rows(&db, "erin").await, ["critical"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_grace_window_can_be_switched_off() {
    let Some(db) = scratch().await else { return };
    user(&db, "frank").await;
    let raw = live_token(&db, "frank").await;
    assert!(matches!(
        rotate_refresh(&db, &raw, None, None).await,
        Rotation::Rotated { .. }
    ));

    // An install that wants the strict pre-window behaviour back sets 0.
    unsafe { std::env::set_var("NOO_REFRESH_GRACE_SECS", "0") };
    let outcome = rotate_refresh(&db, &raw, None, None).await;
    unsafe { std::env::set_var("NOO_REFRESH_GRACE_SECS", "10") };

    match outcome {
        Rotation::Replay => {}
        other => panic!("NOO_REFRESH_GRACE_SECS=0 must disable the window — got {}", name(&other)),
    }
    assert_eq!(live_row_count(&db, "frank").await, 0);
    assert_eq!(replay_audit_rows(&db, "frank").await, ["critical"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lone_rotation_chains_its_child_and_spends_its_parent() {
    let Some(db) = scratch().await else { return };
    user(&db, "bob").await;
    let raw = live_token(&db, "bob").await;

    let new_raw = match rotate_refresh(&db, &raw, Some("ua"), Some("203.0.113.5")).await {
        Rotation::Rotated { new_raw, .. } => new_raw,
        other => panic!("expected a rotation, got {}", name(&other)),
    };

    // Exactly one live row, and it is the child, chained to the parent it
    // replaced. The parent is spent and stamped.
    assert_eq!(live_row_count(&db, "bob").await, 1);
    let (parent_revoked, parent_used): (bool, bool) = sqlx::query_as(
        "SELECT revoked_at IS NOT NULL, last_used_at IS NOT NULL \
           FROM noo_refresh_tokens WHERE token_hash = $1",
    )
    .bind(auth_refresh::hash_token(&raw))
    .fetch_one(&db)
    .await
    .expect("read parent");
    assert!(parent_revoked, "the claim must spend the presented token");
    assert!(parent_used, "the claim must stamp last_used_at in the same statement");

    let chained: bool = sqlx::query_scalar(
        "SELECT rotated_from IS NOT NULL FROM noo_refresh_tokens WHERE token_hash = $1",
    )
    .bind(auth_refresh::hash_token(&new_raw))
    .fetch_one(&db)
    .await
    .expect("read child");
    assert!(chained, "the child must chain rotated_from to its parent");

    // No replay happened, so no audit row and no sweep.
    assert!(replay_audit_rows(&db, "bob").await.is_empty());

    // The spent parent presented again a moment later, with its successor
    // still unused, is a tab race and not a theft — see the three window
    // tests below for each way out of that.
    assert!(matches!(
        rotate_refresh(&db, &raw, None, None).await,
        Rotation::Contended
    ));
    assert_eq!(live_row_count(&db, "bob").await, 1);
    assert!(replay_audit_rows(&db, "bob").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_token_is_refused_without_a_sweep() {
    let Some(db) = scratch().await else { return };
    user(&db, "carol").await;
    let keep = live_token(&db, "carol").await;

    // A forgery must not be able to sweep somebody's live sessions: the
    // replay path is the expensive one, and it is reachable only by a row
    // that actually existed.
    match rotate_refresh(&db, "not-a-real-token", None, None).await {
        Rotation::Refused(d) => assert_eq!(d, "Invalid refresh token"),
        other => panic!("expected a refusal, got {}", name(&other)),
    }
    assert_eq!(live_row_count(&db, "carol").await, 1);
    assert!(replay_audit_rows(&db, "carol").await.is_empty());
    // ...and carol's real token still works.
    assert!(matches!(
        rotate_refresh(&db, &keep, None, None).await,
        Rotation::Rotated { .. }
    ));
}

/// A browser holding a cookie minted before the `noo-rt-` prefix is not logged out by the roll: its bare 43-character token still
/// finds its row, rotates, and comes back as a prefixed successor that
/// rotates in turn.
#[tokio::test]
async fn a_cookie_minted_before_the_prefix_still_rotates_onto_a_prefixed_one() {
    let Some(db) = scratch().await else { return };
    user(&db, "dave").await;
    // Exactly what the pre-1281 gateway minted: 32 CSPRNG bytes, unpadded
    // base64url, no prefix — stored as the hash of that bare string.
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rand::Rng as _;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let legacy = URL_SAFE_NO_PAD.encode(buf);
    assert_eq!(legacy.len(), 43);
    assert!(!legacy.starts_with(auth_refresh::REFRESH_TOKEN_PREFIX));
    auth_refresh::store_token(
        &db,
        "dave",
        &legacy,
        chrono::Utc::now() + chrono::TimeDelta::days(30),
        None,
        None,
        None,
    )
    .await
    .expect("store legacy token");

    let successor = match rotate_refresh(&db, &legacy, None, None).await {
        Rotation::Rotated { new_raw, .. } => new_raw,
        other => panic!("a pre-prefix cookie must still rotate, got {}", name(&other)),
    };
    assert!(
        successor.starts_with(auth_refresh::REFRESH_TOKEN_PREFIX),
        "the successor of a legacy cookie must carry the prefix: {successor}"
    );
    assert!(matches!(
        rotate_refresh(&db, &successor, None, None).await,
        Rotation::Rotated { .. }
    ));
}

fn name(r: &Rotation) -> &'static str {
    match r {
        Rotation::Rotated { .. } => "Rotated",
        Rotation::Replay => "Replay",
        Rotation::Contended => "Contended",
        Rotation::Refused(_) => "Refused",
        Rotation::Unavailable(_) => "Unavailable",
        Rotation::Failed(_) => "Failed",
        Rotation::Issue(_) => "Issue",
    }
}
