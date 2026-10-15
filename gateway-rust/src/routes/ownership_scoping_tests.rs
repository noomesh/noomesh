// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The per-user scoping predicates, against a REAL migrated schema
//!
//!
//! These rules are SQL — "whose contacts are these", "whose approval
//! requests are pending" — so a mock proves nothing about them. They are
//! exactly the kind of check that passes while the column it reads does not
//! exist: migration 071 adds `noo_channel_recipients.owner`, and a test that
//! hand-rolled its own fixture table would keep passing if the migration
//! were dropped from the chain.
//!
//! Gated on `NOO_BROKER_TEST_DSN` like `channels::ingress_and_approval_binding_tests`
//! (PR #118), and built the same way: a scratch DATABASE, the real
//! `mesh_migrate::apply`, and the migration under test exercised by the
//! tests that depend on it.

#![cfg(test)]

use sqlx::PgPool;

const DB_NAME: &str = "ownership_scoping_test";

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
        .max_connections(4)
        .connect_with(opts)
        .await
        .expect("connect scratch");

    // Prove the fixture before trusting an assertion made against it. A
    // missing column here would otherwise read as "the scope refused",
    // which is the answer these tests are trying to earn honestly.
    let owner_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_name = 'noo_channel_recipients' AND column_name = 'owner')",
    )
    .fetch_one(&db)
    .await
    .expect("read information_schema");
    assert!(
        owner_exists,
        "migration 071 must have added noo_channel_recipients.owner — without \
         it every scoping assertion below would pass by accident"
    );
    Some(db)
}

async fn recipient(db: &PgPool, id: &str, channel: &str, owner: Option<&str>) {
    sqlx::query(
        "INSERT INTO noo_channel_recipients \
           (id, channel, recipient_id, display_name, notes, is_default, metadata, owner) \
         VALUES ($1, $2, $1, $1, '', false, '{}'::jsonb, $3)",
    )
    .bind(id)
    .bind(channel)
    .bind(owner)
    .execute(db)
    .await
    .expect("insert recipient");
}

async fn visible_recipients(db: &PgPool, scope: Option<&str>, channel: Option<&str>) -> Vec<String> {
    sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(super::communication::RECIPIENT_LIST_SQL.replace(
        "SELECT id, channel, recipient_id, display_name, notes, \
        is_default, metadata, created_at, updated_at, owner",
        "SELECT id",
    )))
    .bind(scope)
    .bind(channel)
    .fetch_all(db)
    .await
    .expect("list recipients")
}

// ── 1. Migration 071: the column arrives, and nothing is guessed ─────────

#[tokio::test]
async fn migration_071_leaves_existing_rows_unowned() {
    let Some(db) = scratch().await else { return };
    // A row as it stood BEFORE the column existed — no owner named.
    sqlx::query(
        "INSERT INTO noo_channel_recipients \
           (id, channel, recipient_id, display_name, notes, is_default, metadata) \
         VALUES ('legacy', 'telegram', '1', 'Legacy', '', false, '{}'::jsonb)",
    )
    .execute(&db)
    .await
    .expect("insert legacy row");
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner FROM noo_channel_recipients WHERE id = 'legacy'")
            .fetch_one(&db)
            .await
            .expect("read owner");
    assert_eq!(
        owner, None,
        "the backfill must leave an existing row NULL — a guessed owner is \
         worse than an honest shared row"
    );
}

// ── 2. Saved recipients: own + shared, never another tenant's ────────────

#[tokio::test]
async fn a_user_sees_its_own_contacts_and_the_shared_ones() {
    let Some(db) = scratch().await else { return };
    recipient(&db, "ada-1", "telegram", Some("ada")).await;
    recipient(&db, "bob-1", "telegram", Some("bob")).await;
    recipient(&db, "shared-1", "telegram", None).await;

    let mut ada = visible_recipients(&db, Some("ada"), None).await;
    ada.sort();
    assert_eq!(ada, vec!["ada-1".to_string(), "shared-1".to_string()]);

    let mut bob = visible_recipients(&db, Some("bob"), None).await;
    bob.sort();
    assert_eq!(bob, vec!["bob-1".to_string(), "shared-1".to_string()]);
}

#[tokio::test]
async fn an_operator_sees_every_contact() {
    let Some(db) = scratch().await else { return };
    recipient(&db, "ada-1", "telegram", Some("ada")).await;
    recipient(&db, "bob-1", "telegram", Some("bob")).await;
    recipient(&db, "shared-1", "telegram", None).await;

    let mut all = visible_recipients(&db, None, None).await;
    all.sort();
    assert_eq!(
        all,
        vec!["ada-1".to_string(), "bob-1".to_string(), "shared-1".to_string()]
    );
}

#[tokio::test]
async fn the_channel_filter_narrows_inside_the_scope_not_past_it() {
    let Some(db) = scratch().await else { return };
    recipient(&db, "ada-tg", "telegram", Some("ada")).await;
    recipient(&db, "ada-gc", "google_chat", Some("ada")).await;
    recipient(&db, "bob-tg", "telegram", Some("bob")).await;

    let ada = visible_recipients(&db, Some("ada"), Some("telegram")).await;
    assert_eq!(ada, vec!["ada-tg".to_string()]);
    // The filter must not be a way back out of the scope.
    assert!(!ada.contains(&"bob-tg".to_string()));
}

// ── 3. Pending approvals: bound to the requester by migration 070 ────────

async fn pending(db: &PgPool, request_id: &str, requester: Option<&str>) {
    sqlx::query(
        "INSERT INTO noo_approval_requests \
           (request_id, tool_name, risk_level, reason, status, created_at, requester) \
         VALUES ($1, 'shell', 'high', 'test', 'pending', NOW(), $2)",
    )
    .bind(request_id)
    .bind(requester)
    .execute(db)
    .await
    .expect("insert pending request");
}

async fn pending_ids(db: &PgPool, scope: Option<&str>) -> Vec<String> {
    let sql = super::admin::APPROVAL_PENDING_SQL.replace(
        "SELECT request_id, tool_name, risk_level, reason, created_at, \
        requester, conversation_id, channel, chat_id",
        "SELECT request_id",
    );
    sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(&*sql))
        .bind(scope)
        .fetch_all(db)
        .await
        .expect("list pending")
}

#[tokio::test]
async fn a_user_sees_only_the_approvals_it_raised() {
    let Some(db) = scratch().await else { return };
    pending(&db, "r-ada", Some("ada")).await;
    pending(&db, "r-bob", Some("bob")).await;
    pending(&db, "r-unattended", None).await;

    assert_eq!(pending_ids(&db, Some("ada")).await, vec!["r-ada".to_string()]);
    assert_eq!(pending_ids(&db, Some("bob")).await, vec!["r-bob".to_string()]);
}

/// An UNBOUND row (an unattended heartbeat/autonomy turn, and every row
/// written before migration 070) belongs to nobody. It must not fall into
/// everybody's queue — `= $1` and not `IS NOT DISTINCT FROM $1`.
#[tokio::test]
async fn an_unattended_request_stays_operator_only() {
    let Some(db) = scratch().await else { return };
    pending(&db, "r-unattended", None).await;
    assert!(pending_ids(&db, Some("ada")).await.is_empty());
    assert_eq!(
        pending_ids(&db, None).await,
        vec!["r-unattended".to_string()],
        "an operator must still see it — it is decidable only by its id"
    );
}

#[tokio::test]
async fn an_operator_sees_every_pending_request() {
    let Some(db) = scratch().await else { return };
    pending(&db, "r-ada", Some("ada")).await;
    pending(&db, "r-bob", Some("bob")).await;
    let mut all = pending_ids(&db, None).await;
    all.sort();
    assert_eq!(all, vec!["r-ada".to_string(), "r-bob".to_string()]);
}

/// Resolved rows are not pending, whoever asks. The scope narrows the
/// queue; it must not widen it.
#[tokio::test]
async fn the_scope_does_not_resurrect_resolved_rows() {
    let Some(db) = scratch().await else { return };
    pending(&db, "r-ada", Some("ada")).await;
    sqlx::query("UPDATE noo_approval_requests SET status = 'approved' WHERE request_id = 'r-ada'")
        .execute(&db)
        .await
        .expect("resolve");
    assert!(pending_ids(&db, Some("ada")).await.is_empty());
    assert!(pending_ids(&db, None).await.is_empty());
}

// ── 4. Temporal: the subject's identity is what decides the scope ────────

#[tokio::test]
async fn entity_identity_reports_the_subject_type_and_name() {
    let Some(db) = scratch().await else { return };
    // `noo_entities_typed` belongs to TRELLION's chain, not the mesh one, so
    // `mesh_migrate::apply` does not create it and this fixture must. The
    // shape is the two columns `entity_identity` reads plus the key
    // `upsert_entity` conflicts on — if either name drifts, the helper under
    // test fails here rather than silently returning None.
    sqlx::raw_sql(
        "CREATE TABLE noo_entities_typed (           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),            type text NOT NULL,            canonical_name text NOT NULL,            UNIQUE (type, canonical_name))",
    )
    .execute(&db)
    .await
    .expect("trellion entity table");

    let user_id = crate::temporal_graph::upsert_entity(&db, "user", "ada")
        .await
        .expect("upsert user entity");
    let project_id = crate::temporal_graph::upsert_entity(&db, "project", "noomesh")
        .await
        .expect("upsert project entity");

    assert_eq!(
        crate::temporal_graph::entity_identity(&db, &user_id).await,
        Some(("user".to_string(), "ada".to_string())),
        "a 'user' subject is per-person data and must be scopeable by name"
    );
    assert_eq!(
        crate::temporal_graph::entity_identity(&db, &project_id).await,
        Some(("project".to_string(), "noomesh".to_string())),
        "a 'project' subject is the shared brain — global by design"
    );
    assert_eq!(
        crate::temporal_graph::entity_identity(&db, "00000000-0000-0000-0000-000000000000").await,
        None,
    );
}

// ── 5. Usage: every assembled statement must PARSE, scoped and not ───────

/// `summary_sql` splices a per-user predicate into six query shapes. A
/// string that compiles is not a string Postgres accepts, and the failure
/// mode here is a 500 on a report route rather than anything the type
/// system can see — so hand every (group × window × scoped) combination to
/// the real planner.
///
/// `EXPLAIN` is enough: it parses, resolves every column against the real
/// schema, and type-checks the placeholders, without needing rows in a
/// partitioned table.
#[tokio::test]
async fn every_usage_summary_shape_parses_against_the_real_schema() {
    let Some(db) = scratch().await else { return };

    let groups = ["node", "model", "backend", "source", "user", "consumer", "day"];
    let windows = ["month", "all", "2026-08"];
    let mut checked = 0usize;

    for group in groups {
        let (key_expr, monthly_key_expr) =
            super::usage::group_exprs(group).expect("whitelisted group");
        for window in windows {
            let month_window = window == "2026-08";
            for scoped in [false, true] {
                let (sql, _note) =
                    super::usage::summary_sql(key_expr, monthly_key_expr, window, month_window, scoped);
                // The planner needs the parameter TYPES; the statement takes
                // ($1,$2) = the month ints and/or the username, so declare
                // exactly what this shape binds.
                let explain = format!("EXPLAIN {sql}");
                let mut q = sqlx::query(sqlx::AssertSqlSafe(&*explain));
                if month_window {
                    q = q.bind(2026_i32).bind(8_i32);
                }
                if scoped {
                    q = q.bind("ada");
                }
                q.fetch_all(&db).await.unwrap_or_else(|e| {
                    panic!("group={group} window={window} scoped={scoped} did not parse: {e}\n{sql}")
                });
                checked += 1;

                // And the rolled-up fallback, which only exists for a
                // YYYY-MM window on a group the monthly table can serve.
                if let (true, Some(monthly_key)) = (month_window, monthly_key_expr) {
                    let sql = super::usage::monthly_fallback_sql(monthly_key, scoped);
                    let explain = format!("EXPLAIN {sql}");
                    let mut q = sqlx::query(sqlx::AssertSqlSafe(&*explain)).bind(2026_i32).bind(8_i32);
                    if scoped {
                        q = q.bind("ada");
                    }
                    q.fetch_all(&db).await.unwrap_or_else(|e| {
                        panic!("monthly fallback group={group} scoped={scoped} did not parse: {e}\n{sql}")
                    });
                    checked += 1;
                }
            }
        }
    }

    // Guard the loop itself: a typo that skipped every iteration would leave
    // this test green while proving nothing.
    assert_eq!(
        checked,
        7 * 3 * 2 + 6 * 2,
        "every group x window x scoped combination, plus the monthly fallback \
         for the six groups the rollup can serve"
    );
}
