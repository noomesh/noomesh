// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Recallable walks: a user's own saved threads.
//!
//! A signed-in user's `navigate` / `traverse` / `rag` walks are saved by the
//! worker as `kind='thread'` rows of `trellion_traversal_records`
//! (`workers/walks.py`). This is the HTTP surface over them.
//!
//! Who sees what (by design):
//!
//! | route | who | shows |
//! |---|---|---|
//! | `GET /api/v1/walks?q=` | any signed-in account | their OWN threads, verbatim, revalidated against the graph NOW for their audience |
//! | `GET /api/v1/walks/{id}` | any signed-in account | one of their own |
//! | `GET/PUT /api/v1/walks/settings` | any signed-in account | the per-account switch `walks.save_threads` (default ON) |
//! | `GET /api/v1/walks/stats` | Operator and above | COUNTS only |
//! | `GET /api/v1/admin/walks?user=` | Admin only | a user's threads, and writes ONE `noo_security_audit` row per view |
//!
//! The two role-gated routes take the `authz::Operator` / `authz::Admin`
//! extractors; a credential with no account (cluster HMAC) is refused by both.
//!
//! Recall is delegated to trellion-intel's `recall_walks` through the same
//! helper every Intelligent-tier graph route uses (`knowledge::intel_graph`):
//! the caller's audience is resolved by `scope::resolve`, any client-supplied
//! `roles` is dropped, and a restricted caller is only ever handed a reply the
//! worker stamped `audience_filtered: true` (`scope::confirm_audience`), else
//! 503. The account the worker looks up is the VERIFIED principal's, never a
//! field of the request, so there is no parameter that names somebody else.
//!
//! Turning saving OFF stops new saves; it deletes nothing (an explicit delete
//! is a separate act). The setting lives in `noo_user_settings` and is erased
//! with the account (`users.rs::erase_targets`).

use crate::audit::{AuditEvent, AuditKind, Outcome, Severity};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;

use super::{delegation, knowledge, AppError, AppResult};
use crate::auth::{account_of, RequesterCtx};
use crate::authz::{Admin, Operator};
use crate::state::AppState;

/// `noo_user_settings.key` of the per-account switch. The worker reads the
/// same string (`workers/walks.py::SETTING_KEY`); a test pins both.
pub const SAVE_KEY: &str = "walks.save_threads";

/// Most threads one admin view returns.
const ADMIN_VIEW_MAX: i64 = 200;

pub fn router() -> Router<Arc<AppState>> {
    // Both of these read trellion's table directly, so they carry the same
    // add-on gate the graph routes do (an explained 503, not `relation does
    // not exist`). Recall goes through `intel_graph`, which gates itself.
    let direct = Router::new()
        .route("/api/v1/walks/stats", get(walks_stats))
        .route("/api/v1/admin/walks", get(admin_walks))
        .route_layer(axum::middleware::from_fn(super::require_trellion));
    Router::new()
        .route("/api/v1/walks", get(walks_recall))
        .route("/api/v1/walks/settings", get(walks_settings_get).put(walks_settings_put))
        .route("/api/v1/walks/{id}", get(walks_show))
        .merge(direct)
}

// ───────────────────────────── who is asking ─────────────────────────────

/// The verified caller, reduced to what these routes decide on.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    /// The bare ACCOUNT (`alice`, never the connection `alice/laptop`).
    pub account: String,
    /// Who caused the call, when the credential is a delegation.
    pub act: Option<String>,
}

impl Caller {
    fn from_ctx(c: &RequesterCtx) -> Caller {
        Caller {
            account: account_of(&c.sub).to_string(),
            act: c.act.as_ref().map(|a| a.sub.clone()),
        }
    }

    fn of(ctx: &Option<axum::Extension<RequesterCtx>>) -> Option<Caller> {
        ctx.as_ref().map(|axum::Extension(c)| Caller::from_ctx(c))
    }
}

/// A signed-in account is required: a cluster-HMAC or unsigned call has no
/// account whose threads or switch these could be.
fn signed_in(ctx: &Option<axum::Extension<RequesterCtx>>) -> Result<Caller, AppError> {
    Caller::of(ctx).ok_or_else(|| {
        AppError::Forbidden("saved walks belong to a signed-in account; this credential has none".into())
    })
}

// ───────────────────────────── recall (own) ─────────────────────────────

#[derive(Deserialize)]
struct RecallQuery {
    /// What to recall against. Absent = the most recent threads.
    q: Option<String>,
    top_k: Option<u32>,
}

/// GET /api/v1/walks?q=…&top_k= — the caller's OWN saved threads.
///
/// With `q`: the threads nearest the question, revalidated against the current
/// graph and documents for the caller's audience (an unreadable step, a
/// snipped edge, a deleted or superseded fact drops a walk). Without: the most
/// recent. Verbatim, because they are the caller's own. Another user's threads
/// are never returned here, whatever the caller's role.
async fn walks_recall(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
    Query(q): Query<RecallQuery>,
) -> delegation::StatusJson {
    let mut body = json!({ "top_k": q.top_k.unwrap_or(5).clamp(1, 50) });
    if let Some(query) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        body["query"] = json!(query);
    }
    knowledge::intel_graph(&state, ctx, "recall_walks", "saved-walk recall", body).await
}

/// GET /api/v1/walks/{id} — one of the caller's own threads. Somebody else's
/// id and a missing one are the same answer.
async fn walks_show(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
    Path(id): Path<String>,
) -> delegation::StatusJson {
    knowledge::intel_graph(&state, ctx, "recall_walks", "saved-walk recall", json!({ "id": id })).await
}

// ───────────────────────────── the per-account switch ─────────────────────────────

#[derive(Deserialize)]
struct SettingsBody {
    save_threads: bool,
}

/// The switch for `account`: ON unless a row says otherwise.
pub(crate) async fn save_threads_enabled(db: &PgPool, account: &str) -> Result<bool, sqlx::Error> {
    let v: Option<Value> = sqlx::query_scalar(
        "SELECT value FROM noo_user_settings WHERE username = $1 AND key = $2",
    )
    .bind(account)
    .bind(SAVE_KEY)
    .fetch_optional(db)
    .await?;
    Ok(!matches!(v, Some(Value::Bool(false))))
}

pub(crate) async fn set_save_threads(db: &PgPool, account: &str, on: bool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO noo_user_settings (username, key, value) VALUES ($1, $2, $3) \
         ON CONFLICT (username, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(account)
    .bind(SAVE_KEY)
    .bind(json!(on))
    .execute(db)
    .await?;
    Ok(())
}

/// GET /api/v1/walks/settings — `{save_threads: bool}` for the caller's account.
async fn walks_settings_get(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
) -> AppResult {
    let who = signed_in(&ctx)?;
    let on = save_threads_enabled(&state.db, &who.account).await?;
    Ok(Json(json!({ "save_threads": on, "default": true, "key": SAVE_KEY })))
}

/// PUT /api/v1/walks/settings — body `{"save_threads": false}`.
///
/// Off stops NEW saves and deletes nothing. The account is the verified
/// caller's; the body has no way to name another.
async fn walks_settings_put(
    State(state): State<Arc<AppState>>,
    ctx: Option<axum::Extension<RequesterCtx>>,
    Json(body): Json<SettingsBody>,
) -> AppResult {
    let who = signed_in(&ctx)?;
    set_save_threads(&state.db, &who.account, body.save_threads).await?;
    Ok(Json(json!({
        "save_threads": body.save_threads,
        "note": if body.save_threads {
            "new walks will be saved as threads"
        } else {
            "new walks are no longer saved; threads already saved are kept"
        },
    })))
}

// ───────────────────────────── counts (operators) ─────────────────────────────

/// Counts by kind and status, per user, and how many accounts opted out.
/// Never a query, a path, or an entity name.
pub(crate) async fn stats_core(db: &PgPool, user: Option<&str>) -> Result<Value, sqlx::Error> {
    let by: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT kind, status, COUNT(*)::bigint FROM trellion_traversal_records \
         WHERE ($1::text IS NULL OR user_id = $1) GROUP BY kind, status ORDER BY kind, status",
    )
    .bind(user)
    .fetch_all(db)
    .await?;
    let per_user: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT user_id, COUNT(*) FILTER (WHERE status = 'active')::bigint, COUNT(*)::bigint \
         FROM trellion_traversal_records WHERE kind = 'thread' AND user_id IS NOT NULL \
           AND ($1::text IS NULL OR user_id = $1) \
         GROUP BY user_id ORDER BY 3 DESC, user_id LIMIT 200",
    )
    .bind(user)
    .fetch_all(db)
    .await?;
    let opted_out: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM noo_user_settings WHERE key = $1 AND value = 'false'::jsonb",
    )
    .bind(SAVE_KEY)
    .fetch_one(db)
    .await?;
    Ok(json!({
        "view": "counts_only",
        "by_kind_status": by.iter().map(|(k, s, n)| json!({"kind": k, "status": s, "count": n})).collect::<Vec<_>>(),
        "per_user": per_user.iter().map(|(u, a, t)| json!({"user": u, "active": a, "total": t})).collect::<Vec<_>>(),
        "opted_out_accounts": opted_out,
        "user": user,
    }))
}

#[derive(Deserialize)]
struct StatsQuery {
    user: Option<String>,
}

/// GET /api/v1/walks/stats[?user=] — COUNTS ONLY, Operator and above.
///
/// An operator sees how many threads exist, by kind and status and per
/// account, and how many accounts turned saving off: enough to run the
/// feature, nothing of what anyone asked. Content is the audited admin view.
async fn walks_stats(
    State(state): State<Arc<AppState>>,
    _op: Operator,
    Query(q): Query<StatsQuery>,
) -> AppResult {
    Ok(Json(stats_core(&state.db, q.user.as_deref().map(str::trim).filter(|s| !s.is_empty())).await?))
}

// ───────────────────────────── the audited admin view ─────────────────────────────

/// The `noo_security_audit` row for one admin view: `(kind, severity,
/// resource, outcome, details)`. Pure so a test pins what is recorded: who
/// looked at whose threads, how many came back, and the delegation if any.
pub(crate) fn admin_view_audit_row(
    caller: &Caller,
    user: &str,
    limit: i64,
    returned: usize,
) -> (AuditKind, Severity, String, Outcome, Value) {
    (
        AuditKind::WalksAdminView,
        // A named admin reading another person's questions is exactly what an
        // audit log exists to make visible.
        Severity::Warning,
        format!("walks:{user}"),
        Outcome::custom("success"),
        json!({
            "viewer": caller.account,
            "viewed_user": user,
            "limit": limit,
            "returned": returned,
            "act": caller.act,
            "route": "GET /api/v1/admin/walks",
        }),
    )
}

/// Read `user`'s threads for an admin, then write the audit row. The role gate
/// is the `Admin` extractor on the route, so this is only reachable past it;
/// the audit row is written whether or not there is anything to show: the view
/// happened.
pub(crate) async fn admin_view_core(
    db: &PgPool,
    caller: &Caller,
    user: &str,
    limit: i64,
) -> Result<Value, AppError> {
    let user = user.trim();
    if user.is_empty() {
        return Err(AppError::BadRequest("`user` (an account name) is required".into()));
    }
    let limit = limit.clamp(1, ADMIN_VIEW_MAX);
    let rows: Vec<(String, Option<String>, String, Option<String>, Value, String, Option<f64>, f64, Option<String>, i32, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT id::text, thread_id::text, query_text, intent, traversal_path, status, usefulness, \
                    outcome_score, provenance->>'via', recall_count, created_at, expires_at \
             FROM trellion_traversal_records \
             WHERE user_id = $1 AND kind = 'thread' ORDER BY created_at DESC LIMIT $2",
        )
        .bind(user)
        .bind(limit)
        .fetch_all(db)
        .await?;
    let threads: Vec<Value> = rows
        .into_iter()
        .map(|(id, thread_id, query, intent, path, status, usefulness, score, via, recalls, created, expires)| {
            json!({
                "id": id, "thread_id": thread_id, "query": query, "intent": intent, "path": path,
                "status": status, "usefulness": usefulness, "score": score, "via": via,
                "recall_count": recalls, "created_at": created, "expires_at": expires,
            })
        })
        .collect();
    let (kind, severity, resource, outcome, details) =
        admin_view_audit_row(caller, user, limit, threads.len());
    // The operator's rule: an admin may read a user's threads only AUDITED.
    // So the row must land BEFORE the content leaves; if it cannot (no audit
    // key, the partition heal failed, the database refused), the view is
    // refused rather than served unaudited.
    if !crate::audit::record_required(
        db,
        AuditEvent::new(kind, &caller.account, &resource)
            .outcome(outcome)
            .severity(severity)
            .details(details),
    )
    .await
    {
        return Err(AppError::Unavailable(
            "the security audit log could not record this view, so it was not served; \
             check the gateway log for audit_write_* and retry"
                .into(),
        ));
    }
    Ok(json!({ "view": "admin", "user": user, "count": threads.len(), "threads": threads, "audited": true }))
}

#[derive(Deserialize)]
struct AdminQuery {
    user: Option<String>,
    limit: Option<i64>,
}

/// GET /api/v1/admin/walks?user=<account>[&limit=] — ADMIN ONLY, AUDITED.
///
/// A user's saved threads, verbatim. Each call writes one `noo_security_audit`
/// row (`walks_admin_view`: who viewed whose, how many). Everyone below Admin,
/// operators included, is refused with 403; operators have
/// `GET /api/v1/walks/stats`.
async fn admin_walks(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Query(q): Query<AdminQuery>,
) -> AppResult {
    let caller = Caller::from_ctx(&admin.0);
    Ok(Json(
        admin_view_core(&state.db, &caller, q.user.as_deref().unwrap_or(""), q.limit.unwrap_or(50)).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    fn caller() -> Caller {
        Caller { account: "root".into(), act: None }
    }

    #[test]
    fn the_audit_row_names_who_viewed_whose_and_how_many() {
        let mut c = caller();
        c.act = Some("agent-7".into());
        let (event, severity, resource, outcome, d) = admin_view_audit_row(&c, "alice", 50, 3);
        assert_eq!(
            (event, severity, resource.as_str(), outcome),
            (AuditKind::WalksAdminView, Severity::Warning, "walks:alice", Outcome::custom("success"))
        );
        assert_eq!(d["viewer"], "root");
        assert_eq!(d["viewed_user"], "alice");
        assert_eq!(d["returned"], 3);
        assert_eq!(d["act"], "agent-7");
        // the audit row never carries what was read
        assert!(!d.to_string().contains("query"), "{d}");
    }

    /// The key the worker reads is pinned from the Python side
    /// (`tests/test_walks_worker.py`), which reads this constant.
    #[test]
    fn the_setting_key_is_the_documented_one() {
        assert_eq!(SAVE_KEY, "walks.save_threads");
    }

    #[test]
    fn a_user_may_reach_only_the_settings_write_by_self_service() {
        // (scope_allows itself is tested in auth.rs; this pins the constant the route is mounted on.)
        assert_eq!(crate::auth::WALKS_SETTINGS_PATH, "/api/v1/walks/settings");
    }

    #[test]
    fn no_route_here_takes_an_account_from_the_request_except_the_audited_admin_view() {
        let src = include_str!("walks.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap()];
        // the only handler that reads a `user` parameter is the admin view (and the counts filter)
        assert_eq!(code.matches("user: Option<String>").count(), 2, "AdminQuery and StatsQuery");
        assert!(code.contains("signed_in(&ctx)?"), "settings routes derive the account from the credential");
        // the recall bodies carry no account field at all
        assert!(!code.contains("body[\"user"), "recall must not forward an account from the request");
    }

    // ── Against a real schema ───────────────────────────────────────────
    //
    // Built the way `routes::core::refresh_rotation_tests` is: a scratch
    // DATABASE, the real `mesh_migrate::apply` (so migration 080 is what makes
    // `noo_user_settings`), and the audit table the real writer inserts into.
    // Gated on NOO_BROKER_TEST_DSN; CI sets it. The trellion table is trellion's,
    // so the test creates the slice of it these routes read.

    /// One scratch database PER TEST: `cargo test` runs tests in parallel, and
    /// a shared name would let one test's `DROP DATABASE ... (FORCE)` kill
    /// another's connections mid-run.
    /// Migrations create cluster-global objects (the `noo_app` login role), so
    /// two tests migrating their own databases at once still collide. These
    /// DB tests take this lock for their whole body.
    static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn scratch(test: &str) -> Option<PgPool> {
        let db_name = format!("walks_routes_test_{test}");
        let dsn = std::env::var("NOO_BROKER_TEST_DSN").ok().filter(|s| !s.is_empty())?;
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await.expect("connect");
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {db_name} (FORCE)"))).execute(&admin).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}"))).execute(&admin).await.expect("create scratch db");
        let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
        let scratch_dsn = format!("{head}/{db_name}");
        let build = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect(&scratch_dsn).await.expect("connect scratch");
        unsafe { std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret") };
        for ext in ["vector", "pg_trgm"] {
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}"))).execute(&build).await.expect("extension");
        }
        crate::mesh_migrate::apply(&build).await.expect("apply migrations");
        build.close().await;
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&scratch_dsn)
            .expect("scratch dsn")
            .options([("search_path", "mesh,public")]);
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(4).connect_with(opts).await.expect("connect scratch");
        // trellion's table (the columns these routes read), in public.
        sqlx::query(
            "CREATE TABLE public.trellion_traversal_records (id uuid PRIMARY KEY, thread_id uuid, \
             query_text text NOT NULL, intent text, traversal_path jsonb NOT NULL DEFAULT '[]', \
             outcome_score double precision NOT NULL DEFAULT 0.5, usefulness double precision, \
             status text NOT NULL DEFAULT 'active', kind text NOT NULL DEFAULT 'simulated', \
             user_id text, provenance jsonb NOT NULL DEFAULT '{}', recall_count integer NOT NULL DEFAULT 0, \
             created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz)",
        )
        .execute(&db)
        .await
        .expect("trellion table");
        Some(db)
    }

    async fn thread(db: &PgPool, user: Option<&str>, kind: &str, query: &str) {
        sqlx::query("INSERT INTO trellion_traversal_records (id, query_text, user_id, kind) VALUES (gen_random_uuid(), $1, $2, $3)")
            .bind(query).bind(user).bind(kind).execute(db).await.expect("insert walk");
    }

    async fn view_rows(db: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM noo_security_audit WHERE event_type = 'walks_admin_view'")
            .fetch_one(db).await.expect("count audit rows")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_setting_defaults_on_and_opting_out_is_per_account() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("setting").await else { return };
        assert!(save_threads_enabled(&db, "alice").await.unwrap(), "no row = the default, ON");
        set_save_threads(&db, "alice", false).await.unwrap();
        assert!(!save_threads_enabled(&db, "alice").await.unwrap());
        assert!(save_threads_enabled(&db, "bob").await.unwrap(), "one account's switch is not another's");
        set_save_threads(&db, "alice", true).await.unwrap();
        assert!(save_threads_enabled(&db, "alice").await.unwrap());
        set_save_threads(&db, "alice", false).await.unwrap();
        set_save_threads(&db, "alice", false).await.unwrap(); // idempotent upsert
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM noo_user_settings WHERE username = 'alice'")
            .fetch_one(&db).await.unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_admin_view_writes_exactly_one_audit_row_per_call_and_others_are_refused_without_one() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("admin_view").await else { return };
        thread(&db, Some("alice"), "thread", "ALICE-PRIVATE-QUESTION").await;
        thread(&db, Some("alice"), "thread", "ALICE-SECOND").await;
        thread(&db, Some("bob"), "thread", "BOB-QUESTION").await;
        thread(&db, None, "simulated", "a rehearsal").await;
        let admin = caller();

        assert_eq!(view_rows(&db).await, 0);
        let v = admin_view_core(&db, &admin, "alice", 50).await.expect("admin may view");
        assert_eq!(v["count"], 2);
        let blob = v.to_string();
        assert!(blob.contains("ALICE-PRIVATE-QUESTION") && blob.contains("ALICE-SECOND"));
        assert!(!blob.contains("BOB-QUESTION") && !blob.contains("a rehearsal"), "only alice's threads: {blob}");
        assert_eq!(view_rows(&db).await, 1, "one audit row for one view");
        let (actor, resource, outcome, details): (String, String, String, serde_json::Value) = sqlx::query_as(
            "SELECT actor, resource, outcome, details FROM noo_security_audit WHERE event_type = 'walks_admin_view'",
        ).fetch_one(&db).await.unwrap();
        assert_eq!((actor.as_str(), resource.as_str(), outcome.as_str()), ("root", "walks:alice", "success"));
        assert_eq!(details["viewed_user"], "alice");
        assert_eq!(details["returned"], 2);
        assert!(!details.to_string().contains("ALICE-PRIVATE-QUESTION"), "the audit row records the view, not the content");

        // A second view is a second row, even when there is nothing to show.
        let empty = admin_view_core(&db, &admin, "nobody", 50).await.unwrap();
        assert_eq!(empty["count"], 0);
        assert_eq!(view_rows(&db).await, 2);

        // Refusing a caller below Admin is the `Admin` extractor's job
        // (`authz::tests` drives it through a router); the core is only
        // reachable past it.
        // ...and a missing user is a 400, before any read or audit row.
        let err = admin_view_core(&db, &admin, "  ", 50).await.expect_err("user required");
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
        assert_eq!(view_rows(&db).await, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_admin_view_whose_audit_row_cannot_land_is_refused_and_serves_nothing() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("admin_unaudited").await else { return };
        thread(&db, Some("alice"), "thread", "ALICE-PRIVATE-QUESTION").await;
        // The audit table is gone: the row cannot land, so the view must not be served.
        sqlx::raw_sql("DROP TABLE noo_security_audit CASCADE").execute(&db).await.expect("drop audit table");
        let admin = caller();
        let err = admin_view_core(&db, &admin, "alice", 50)
            .await
            .expect_err("an unaudited admin view must be refused");
        let msg = format!("{err:?}");
        assert!(matches!(err, AppError::Unavailable(_)), "refused as unavailable, got {msg}");
        assert!(!msg.contains("ALICE-PRIVATE-QUESTION"), "the refusal carries no content");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_operators_stats_are_counts_and_never_a_question_or_a_path() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("stats").await else { return };
        thread(&db, Some("alice"), "thread", "ALICE-PRIVATE-QUESTION").await;
        thread(&db, Some("alice"), "thread", "ALICE-SECOND").await;
        thread(&db, Some("bob"), "thread", "BOB-QUESTION").await;
        thread(&db, None, "simulated", "a rehearsal").await;
        sqlx::query("UPDATE trellion_traversal_records SET status = 'stale' WHERE query_text = 'ALICE-SECOND'")
            .execute(&db).await.unwrap();
        set_save_threads(&db, "carol", false).await.unwrap();

        let s = stats_core(&db, None).await.unwrap();
        assert_eq!(s["view"], "counts_only");
        assert_eq!(s["opted_out_accounts"], 1);
        let kinds: Vec<(String, String, i64)> = s["by_kind_status"].as_array().unwrap().iter()
            .map(|r| (r["kind"].as_str().unwrap().into(), r["status"].as_str().unwrap().into(), r["count"].as_i64().unwrap()))
            .collect();
        assert_eq!(kinds, vec![
            ("simulated".to_string(), "active".to_string(), 1),
            ("thread".to_string(), "active".to_string(), 2),
            ("thread".to_string(), "stale".to_string(), 1),
        ]);
        let alice = s["per_user"].as_array().unwrap().iter().find(|r| r["user"] == "alice").unwrap();
        assert_eq!((alice["active"].as_i64(), alice["total"].as_i64()), (Some(1), Some(2)));
        let blob = s.to_string();
        for secret in ["ALICE-PRIVATE-QUESTION", "ALICE-SECOND", "BOB-QUESTION", "rehearsal", "traversal_path"] {
            assert!(!blob.contains(secret), "stats leaked {secret}: {blob}");
        }
        // narrowed to one account
        let one = stats_core(&db, Some("bob")).await.unwrap();
        assert_eq!(one["per_user"].as_array().unwrap().len(), 1);
    }
}
