// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Tests for the async-operation engine and its HTTP behaviour, against a REAL
//! migrated schema (migration 082 is what makes `noo_ops`).
//!
//! The harness is `routes/walks.rs`'s: a scratch DATABASE per test, the real
//! `mesh_migrate::apply`, gated on `NOO_BROKER_TEST_DSN` (CI sets it; without
//! it the DB tests print SKIPPED and pass), and a process-wide lock because
//! migrations create cluster-global objects. The route logic under test is
//! the same functions the handlers call (`serve`, `read_op`, `cancel_op`,
//! `list_ops`), which take a `PgPool` rather than a whole `AppState`, so no
//! gateway, NATS or worker is needed. The operations themselves are TEST
//! types whose duration and outcome the test controls.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

use super::*;
use crate::auth::{RequesterCtx, Role};
use crate::bus_principal::{self, for_requester};
use crate::routes::ops as api;

// ───────────────────────────── harness ─────────────────────────────

/// Migrations create cluster-global objects (the `noo_app` role), so two
/// tests migrating at once collide. DB tests hold this for their whole body.
pub(crate) static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A migrated scratch database for one test, or `None` (skip) without a DSN.
pub(crate) async fn scratch(test: &str) -> Option<PgPool> {
    let dsn = ["NOO_BROKER_TEST_DSN", "NOO_KB_AUDIENCE_TEST_DSN"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
    let Some(dsn) = dsn else {
        eprintln!("SKIPPED: set NOO_BROKER_TEST_DSN to run the DB-backed ops tests");
        return None;
    };
    let db_name = format!("ops_test_{test}");
    let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&dsn).await.expect("connect");
    let _ = sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS {db_name} (FORCE)")).execute(&admin).await;
    sqlx::raw_sql(&format!("CREATE DATABASE {db_name}")).execute(&admin).await.expect("create scratch db");
    let (head, _) = dsn.rsplit_once('/').expect("dsn has a path");
    let scratch_dsn = format!("{head}/{db_name}");
    let build = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect(&scratch_dsn).await.expect("connect scratch");
    unsafe { std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret") };
    for ext in ["vector", "pg_trgm"] {
        sqlx::query(&format!("CREATE EXTENSION IF NOT EXISTS {ext}")).execute(&build).await.expect("extension");
    }
    crate::mesh_migrate::apply(&build).await.expect("apply migrations");
    build.close().await;
    use std::str::FromStr as _;
    let opts = sqlx::postgres::PgConnectOptions::from_str(&scratch_dsn)
        .expect("scratch dsn")
        .options([("search_path", "mesh,public")]);
    Some(sqlx::postgres::PgPoolOptions::new().max_connections(8).connect_with(opts).await.expect("connect scratch"))
}

pub(crate) async fn account(db: &PgPool, name: &str, role: Role) -> RequesterCtx {
    sqlx::query("INSERT INTO noo_users (username, hashed_password, scopes) VALUES ($1, 'x', '[\"read\"]') ON CONFLICT DO NOTHING")
        .bind(name)
        .execute(db)
        .await
        .expect("insert user");
    let scopes: Vec<String> = match role {
        Role::User => vec!["read".into()],
        Role::Operator => vec!["read".into(), "write".into()],
        Role::Admin => vec!["read".into(), "write".into(), "admin".into()],
    };
    RequesterCtx { sub: name.to_string(), scopes, role, harness: None, act: None }
}

fn ctx_of(r: &RequesterCtx) -> Option<axum::Extension<RequesterCtx>> {
    Some(axum::Extension(r.clone()))
}

fn t30() -> Duration {
    Duration::from_secs(30)
}
fn t1() -> Duration {
    Duration::from_secs(1)
}
fn no_refusal() -> Option<crate::routes::delegation::StatusJson> {
    None
}

/// A test operation type. `route` decides who may start it (the real
/// `requester_allows` rule): `/api/v1/rag/query` admits a User,
/// `/api/v1/graph/recluster` needs an Operator.
fn spec(name: &'static str, route: &'static str, default_wait: u64, exclusive: bool, timeout: fn() -> Duration) -> &'static OpSpec {
    Box::leak(Box::new(OpSpec {
        name,
        summary: "test",
        route,
        timeout,
        default_wait_secs: default_wait,
        poll_interval_ms: 100,
        cancel_note: "the test worker is not stopped",
        exclusive,
        retry_safe: true,
        writes_user_data: false,
        admin_only: false,
        human_only_apply: false,
        redact: redact_default,
    }))
}

type Runner = Box<dyn FnOnce(OpCtx, Value) -> RunFuture + Send + 'static>;

fn runner<F, Fut>(f: F) -> Runner
where
    F: FnOnce(OpCtx, Value) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Outcome> + Send + 'static,
{
    Box::new(move |c, p| Box::pin(f(c, p)))
}

/// Start through the route layer as the auth middleware + principal layer
/// would have: the caller's principal is in scope.
async fn serve_as(
    db: &PgPool,
    who: &RequesterCtx,
    spec: &'static OpSpec,
    params: Value,
    wait: Option<u64>,
    run: Runner,
) -> (StatusCode, Value) {
    let ctx = ctx_of(who);
    let (st, axum::Json(body)) =
        bus_principal::with_principal(for_requester(who), api::serve(db, &ctx, spec, no_refusal, params, wait, StatusCode::OK, run)).await;
    (st, body)
}

fn id_of(handle: &Value) -> String {
    handle["op_id"].as_str().expect("a handle carries op_id").to_string()
}

async fn read(db: &PgPool, who: &RequesterCtx, id: &str, wait: Option<u64>) -> (StatusCode, Value) {
    let (st, axum::Json(b)) = api::read_op(db, Some(who), id, wait).await;
    (st, b)
}

async fn until_status(db: &PgPool, who: &RequesterCtx, id: &str, want: &str) -> Value {
    for _ in 0..100 {
        let (_, v) = read(db, who, id, None).await;
        if v["status"] == want {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("op {id} never reached {want}");
}

// ───────────────────────────── start, poll, result ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_then_poll_reaches_succeeded_with_the_result() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("lifecycle").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.life", "/api/v1/rag/query", 0, false, t30);

    let (st, handle) = serve_as(&db, &alice, s, json!({"q": "x"}), None, runner(|c, p| async move {
        c.progress(json!({"stage": "working"})).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        Outcome::done(200, json!({"echo": p, "answer": 42}))
    }))
    .await;

    // default_wait 0: the handle comes back at once, with a poll URL.
    assert_eq!(st, StatusCode::ACCEPTED);
    let id = id_of(&handle);
    assert_eq!(handle["poll"], format!("/api/v1/ops/{id}"));
    assert_eq!(handle["type"], "test.life");
    assert!(handle["poll_interval_ms"].as_u64().unwrap() > 0);

    let running = until_status(&db, &alice, &id, "running").await;
    assert!(running["result"].is_null(), "no result while running");

    let done = until_status(&db, &alice, &id, "succeeded").await;
    assert_eq!(done["result"], json!({"echo": {"q": "x"}, "answer": 42}));
    assert_eq!(done["result_status"], 200);
    assert!(done["finished_at"].is_string() && done["started_at"].is_string());
    assert!(done["expires_at"].is_string());
    assert_eq!(done["progress"], json!({"stage": "working"}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failure_is_recorded_with_its_error_and_the_workers_own_body() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("failure").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.fail", "/api/v1/rag/query", 0, false, t30);

    let (_, handle) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        Outcome::from_http(400, json!({"error": "question required"}))
    }))
    .await;
    let v = until_status(&db, &alice, &id_of(&handle), "failed").await;
    assert_eq!(v["error"], "question required");
    assert_eq!(v["result"], json!({"error": "question required"}), "the worker's body is kept");
    assert_eq!(v["result_status"], 400);
    assert_eq!(v["retry_safe"], json!(null), "retry_safe is named only for types in the registry");

    // A panic is a failure with a reason, not a row stuck `running`.
    let (_, h2) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        if true {
            panic!("boom");
        }
        Outcome::done(200, json!({}))
    }))
    .await;
    let v = until_status(&db, &alice, &id_of(&h2), "failed").await;
    assert!(v["error"].as_str().unwrap().contains("panicked"), "{v}");

    // So is a run that outlives its type's timeout.
    let slow = spec("test.slow", "/api/v1/rag/query", 0, false, t1);
    let (_, h3) = serve_as(&db, &alice, slow, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    let v = until_status(&db, &alice, &id_of(&h3), "failed").await;
    assert!(v["error"].as_str().unwrap().contains("did not finish within 1s"), "{v}");
    assert_eq!(v["result_status"], 504);
}

// ───────────────────────────── adaptive wait ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_route_answers_200_for_a_fast_run_and_202_for_a_slow_one() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("adaptive").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    // default_wait 1 s.
    let s = spec("test.adaptive", "/api/v1/rag/query", 1, false, t30);

    // Fast: finishes inside the window -> 200, the result in the OLD shape (the
    // bare body, with the status the synchronous route would have given).
    let (st, body) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Outcome::done(200, json!({"clusters": 3}))
    }))
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, json!({"clusters": 3}), "no envelope: today's shape");

    // A failure that finished inside the window keeps today's status AND body.
    let (st, body) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        Outcome::from_http(400, json!({"error": "bad page"}))
    }))
    .await;
    assert_eq!((st, body), (StatusCode::BAD_REQUEST, json!({"error": "bad page"})));

    // Slow: still running when the window closes -> 202 with the handle.
    let (st, handle) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_millis(2500)).await;
        Outcome::done(200, json!({"clusters": 9}))
    }))
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let id = id_of(&handle);
    assert_eq!(handle["status"], "running");
    assert_eq!(until_status(&db, &alice, &id, "succeeded").await["result"], json!({"clusters": 9}));

    // `?wait=` overrides the default: the same slow run, given 5 s, is a 200.
    let (st, body) = serve_as(&db, &alice, s, json!({}), Some(5), runner(|_, _| async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        Outcome::done(200, json!({"clusters": 9}))
    }))
    .await;
    assert_eq!((st, body), (StatusCode::OK, json!({"clusters": 9})));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_default_wait_of_zero_always_answers_with_a_handle_even_for_an_instant_run() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("wait_zero").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.zero", "/api/v1/rag/query", 0, false, t30);
    let (st, body) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({"x": 1})) })).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{body}");
    assert!(body["op_id"].is_string());
    // `?wait=0` is the same, whatever the type's default.
    let fast = spec("test.zero2", "/api/v1/rag/query", 20, false, t30);
    let (st, _) = serve_as(&db, &alice, fast, json!({}), Some(0), runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!(st, StatusCode::ACCEPTED);
}

#[test]
fn default_wait_is_per_type_bounded_and_overridable_by_setting() {
    let s = spec("test.cfgwait", "/x", 3, false, t30);
    assert_eq!(s.wait_key(), "NOO_OPS_WAIT_TEST_CFGWAIT_SECS");
    assert_eq!(s.default_wait(), 3);
    unsafe { std::env::set_var("NOO_OPS_WAIT_TEST_CFGWAIT_SECS", "9") };
    assert_eq!(s.default_wait(), 9);
    unsafe { std::env::set_var("NOO_OPS_WAIT_TEST_CFGWAIT_SECS", "9999") };
    assert_eq!(s.default_wait(), MAX_WAIT_SECS, "never longer than the bound");
    unsafe { std::env::set_var("NOO_OPS_WAIT_TEST_CFGWAIT_SECS", "not a number") };
    assert_eq!(s.default_wait(), 3, "junk falls back to the type's default");
    unsafe { std::env::remove_var("NOO_OPS_WAIT_TEST_CFGWAIT_SECS") };
}

#[test]
fn the_registered_types_carry_the_agreed_default_waits() {
    let wait = |n: &str| api::find(n).unwrap_or_else(|| panic!("{n} registered")).spec.default_wait_secs;
    assert_eq!(wait("graph.recluster"), 0, "a recluster is minutes: always a handle");
    for n in ["graph.extract_relations", "snapshots.consolidate", "rag.ingest", "docs.ingest"] {
        assert!((2..=5).contains(&wait(n)), "{n}");
    }
    for n in ["graph.navigate", "graph.traverse"] {
        assert!((10..=15).contains(&wait(n)), "{n}");
    }
    assert!(api::TYPES.iter().all(|t| t.spec.default_wait_secs <= MAX_WAIT_SECS));
}

// ───────────────────────────── long-poll ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_long_polls_until_the_op_finishes_and_is_bounded_otherwise() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("longpoll").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.poll", "/api/v1/rag/query", 0, false, t30);

    let (_, h) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_millis(700)).await;
        Outcome::done(200, json!({"ok": true}))
    }))
    .await;
    let id = id_of(&h);

    let t0 = std::time::Instant::now();
    let (st, v) = read(&db, &alice, &id, Some(10)).await;
    let took = t0.elapsed();
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["status"], "succeeded", "the wait returned the FINISHED op, not a snapshot of it running");
    assert_eq!(v["result"], json!({"ok": true}));
    assert!(took >= Duration::from_millis(500) && took < Duration::from_secs(5), "returned on completion, not on timeout: {took:?}");

    // Without wait: an immediate read of a running op.
    let (_, h2) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    let id2 = id_of(&h2);
    let t0 = std::time::Instant::now();
    let (_, v) = read(&db, &alice, &id2, None).await;
    assert!(t0.elapsed() < Duration::from_millis(400));
    assert_ne!(v["status"], "succeeded");
    // A bounded wait that times out answers with the op as it is.
    let t0 = std::time::Instant::now();
    let (_, v) = read(&db, &alice, &id2, Some(1)).await;
    assert!(t0.elapsed() >= Duration::from_millis(900));
    assert_eq!(v["status"], "running");
    // The bound itself: asking for an hour is clamped, never honoured.
    assert_eq!(MAX_WAIT_SECS, 25);
}

// ───────────────────────────── cancel ─────────────────────────────

struct SetOnDrop(Arc<AtomicBool>);
impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_stops_the_gateway_side_run_and_says_the_worker_is_not_stopped() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cancel").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.cancel", "/api/v1/rag/query", 0, false, t30);

    let dropped = Arc::new(AtomicBool::new(false));
    let d2 = dropped.clone();
    let (_, h) = serve_as(&db, &alice, s, json!({}), None, runner(move |_, _| async move {
        let _guard = SetOnDrop(d2);
        tokio::time::sleep(Duration::from_secs(60)).await;
        Outcome::done(200, json!({"late": true}))
    }))
    .await;
    let id = id_of(&h);
    until_status(&db, &alice, &id, "running").await;

    let (st, axum::Json(v)) = api::cancel_op(&db, Some(&alice), &id).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "cancelled");
    assert_eq!(v["cancel"]["gateway_aborted"], true);
    assert_eq!(v["cancel"]["worker_stopped"], false, "the row must not claim it stopped the worker");
    // (A type that is not in the registry gets the generic note; registered types carry their own.)
    assert!(v["cancel"]["note"].as_str().unwrap().contains("not stopped"), "{v}");

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(dropped.load(Ordering::SeqCst), "the detached run was actually aborted, not merely marked");
    let (_, v) = read(&db, &alice, &id, None).await;
    assert_eq!(v["status"], "cancelled", "nothing resurrects a cancelled op");
    assert!(v["result"].is_null());

    // Cancelling again is idempotent; cancelling a finished op is a conflict.
    let (st, _) = api::cancel_op(&db, Some(&alice), &id).await.pipe_status();
    assert_eq!(st, StatusCode::OK);
    let (_, h) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    let id_done = id_of(&h);
    until_status(&db, &alice, &id_done, "succeeded").await;
    let (st, axum::Json(v)) = api::cancel_op(&db, Some(&alice), &id_done).await;
    assert_eq!(st, StatusCode::CONFLICT, "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_finish_cannot_overwrite_a_cancel_nor_an_expiry() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("finality").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.final", "/api/v1/rag/query", 0, false, t30);
    let (_, h) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    let id: Uuid = id_of(&h).parse().unwrap();
    // Simulate the race the conditional write exists for: the row is already
    // terminal when the run's own write arrives.
    sqlx::query("UPDATE noo_ops SET status = 'cancelled' WHERE op_id = $1").bind(id).execute(&db).await.unwrap();
    finish(&db, id, SUCCEEDED, Some(json!({"late": true})), Some(200), None).await;
    let row = get_row(&db, id).await.unwrap().unwrap();
    assert_eq!(row.status, "cancelled");
    assert!(row.result.is_none());
}

trait PipeStatus {
    fn pipe_status(self) -> (StatusCode, Value);
}
impl PipeStatus for crate::routes::delegation::StatusJson {
    fn pipe_status(self) -> (StatusCode, Value) {
        (self.0, self.1 .0)
    }
}

// ───────────────────────────── visibility ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_users_op_is_not_found_exactly_like_an_id_that_never_existed() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("visibility").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let bob = account(&db, "bob", Role::User).await;
    let root = account(&db, "root", Role::Admin).await;
    let s = spec("test.vis", "/api/v1/rag/query", 0, false, t30);
    let (_, h) = serve_as(&db, &alice, s, json!({"secret": "alice-only"}), None, runner(|_, _| async move {
        Outcome::done(200, json!({"private": "alice's result"}))
    }))
    .await;
    let id = id_of(&h);
    until_status(&db, &alice, &id, "succeeded").await;

    // Bob: not found. The body is IDENTICAL to a never-existed id's: no "forbidden", no hint it exists.
    let (st_bob, body_bob) = read(&db, &bob, &id, None).await;
    let (st_none, body_none) = read(&db, &bob, &Uuid::new_v4().to_string(), None).await;
    assert_eq!(st_bob, StatusCode::NOT_FOUND);
    assert_eq!((st_bob, &body_bob), (st_none, &body_none));
    assert!(!body_bob.to_string().contains("alice"));
    // ...and for a malformed id, and for cancel, and for the list.
    assert_eq!(read(&db, &bob, "not-a-uuid", None).await.0, StatusCode::NOT_FOUND);
    let (st, axum::Json(b)) = api::cancel_op(&db, Some(&bob), &id).await;
    assert_eq!((st, &b), (StatusCode::NOT_FOUND, &body_none));
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&bob), false, None, 50).await;
    assert_eq!(l["count"], 0, "bob's list does not contain alice's op");
    // Bob's wait does not leak completion either.
    let (st, _) = read(&db, &bob, &id, Some(2)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // The op is untouched by bob's cancel attempt.
    assert_eq!(read(&db, &alice, &id, None).await.1["status"], "succeeded");

    // The owner sees it; an admin sees it; `mine=1` narrows an admin to their own.
    assert_eq!(read(&db, &alice, &id, None).await.0, StatusCode::OK);
    assert_eq!(read(&db, &root, &id, None).await.0, StatusCode::OK);
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&root), false, None, 50).await;
    assert_eq!(l["count"], 1);
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&root), true, None, 50).await;
    assert_eq!(l["count"], 0);
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&alice), true, Some("succeeded"), 50).await;
    assert_eq!(l["count"], 1);
    assert!(l["operations"][0].get("result").is_none(), "a listing carries no results");
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&alice), true, Some("failed"), 50).await;
    assert_eq!(l["count"], 0);
    assert_eq!(api::list_ops(&db, Some(&alice), true, Some("bogus"), 50).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_harness_caller_sees_only_its_own_consumers_ops_the_person_sees_all_their_own() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("consumer").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let codex = RequesterCtx { harness: Some("mcp-external:codex".into()), ..alice.clone() };
    let other = RequesterCtx { harness: Some("mcp-external:other".into()), ..alice.clone() };
    let s = spec("test.consumer", "/api/v1/rag/query", 0, false, t30);
    let (_, h) = serve_as(&db, &codex, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    let id = id_of(&h);
    until_status(&db, &codex, &id, "succeeded").await;
    assert_eq!(read(&db, &alice, &id, None).await.0, StatusCode::OK, "the person behind the consumer sees it");
    assert_eq!(read(&db, &other, &id, None).await.0, StatusCode::NOT_FOUND, "another consumer of the same account does not");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_machine_caller_owns_null_owner_ops_only_admins_and_machines_see() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("machine").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let root = account(&db, "root", Role::Admin).await;
    let s = spec("test.machine", "/api/v1/rag/query", 0, false, t30);
    let (st, axum::Json(h)) = bus_principal::with_principal(
        bus_principal::Principal::internal("cluster:heartbeat", &[]),
        api::serve(&db, &None, s, no_refusal, json!({}), None, StatusCode::OK, runner(|c, _| async move {
            // A machine op is run as "no requester": the route's unrestricted internal path, unchanged.
            Outcome::done(200, json!({"requester_is_none": c.ctx().is_none()}))
        })),
    )
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let id = id_of(&h);
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_uuid FROM noo_ops WHERE op_id = $1::uuid").bind(&id).fetch_one(&db).await.unwrap();
    assert!(owner.is_none());
    let (_, axum::Json(v)) = api::read_op(&db, None, &id, Some(5)).await;
    assert_eq!(v["result"], json!({"requester_is_none": true}));
    assert_eq!(read(&db, &root, &id, None).await.0, StatusCode::OK);
    assert_eq!(read(&db, &alice, &id, None).await.0, StatusCode::NOT_FOUND, "a user never sees a machine op");
}

// ───────────────────────────── authorisation ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starting_a_type_needs_what_its_synchronous_route_needs() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("authz").await else { return };
    let user = account(&db, "usr", Role::User).await;
    let operator = account(&db, "oper", Role::Operator).await;
    // `/api/v1/graph/recluster` is a mutating route outside the chat/query
    // surface: the front door refuses a User-tier token there (403). The op
    // for it must refuse the same caller, with the same status, and create nothing.
    let restricted = spec("test.restricted", "/api/v1/graph/recluster", 0, false, t30);
    let ran = Arc::new(AtomicBool::new(false));
    let r2 = ran.clone();
    let (st, body) = serve_as(&db, &user, restricted, json!({}), None, runner(move |_, _| async move {
        r2.store(true, Ordering::SeqCst);
        Outcome::done(200, json!({}))
    }))
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap().contains("/api/v1/graph/recluster"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!ran.load(Ordering::SeqCst), "a refused start must not run anything");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_ops").fetch_one(&db).await.unwrap();
    assert_eq!(n, 0, "and must not leave a row");

    // The rule is the auth module's, not a copy: both entry points agree.
    for who in [&user, &operator] {
        let front_door = crate::auth::requester_allows(who, &axum::http::Method::POST, "/api/v1/graph/recluster");
        let (st, _) = serve_as(&db, who, restricted, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
        assert_eq!(st != StatusCode::FORBIDDEN, front_door, "{}", who.sub);
    }
    // ...and a User may start what the chat/query surface lets a User do.
    let open = spec("test.open", "/api/v1/rag/query", 0, false, t30);
    let (st, _) = serve_as(&db, &user, open, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!(st, StatusCode::ACCEPTED);

    // A pre-dispatch refusal (an add-on that is off) is answered as the route
    // answered it, before any op exists.
    fn refuse503() -> Option<crate::routes::delegation::StatusJson> {
        Some((StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({"error": "needs the add-on"}))))
    }
    let (st, axum::Json(b)) = api::serve(&db, &ctx_of(&operator), open, refuse503, json!({}), None, StatusCode::OK, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!((st, b), (StatusCode::SERVICE_UNAVAILABLE, json!({"error": "needs the add-on"})));

    // Params must be an object.
    let (st, _) = serve_as(&db, &operator, open, json!([1, 2]), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

// ───────────────────────────── identity ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_op_runs_as_its_owner_never_as_the_gateway_or_unrestricted() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("identity").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let bob = account(&db, "bob", Role::Operator).await;
    let s = spec("test.identity", "/api/v1/rag/query", 0, false, t30);
    let probe = || {
        runner(|c: OpCtx, _| async move {
            // What `scope::resolve` is handed: Some(owner), never None (None = unrestricted).
            let ctx = c.ctx();
            // What every `worker.*` publish signs as, inside this DETACHED task.
            let p = bus_principal::current();
            Outcome::done(
                200,
                json!({
                    "ctx_sub": ctx.as_ref().map(|axum::Extension(r)| r.sub.clone()),
                    "ctx_present": ctx.is_some(),
                    "principal_sub": p.sub,
                    "principal_role": p.role,
                    "principal_scopes": p.scopes,
                }),
            )
        })
    };
    let (_, ha) = serve_as(&db, &alice, s, json!({}), None, probe()).await;
    let (_, hb) = serve_as(&db, &bob, s, json!({}), None, probe()).await;
    let a = until_status(&db, &alice, &id_of(&ha), "succeeded").await;
    let b = until_status(&db, &bob, &id_of(&hb), "succeeded").await;
    assert_eq!(a["result"]["ctx_present"], true);
    assert_eq!(a["result"]["ctx_sub"], "alice");
    assert_eq!(a["result"]["principal_sub"], "alice", "the detached task signs as its owner, not as `internal:unattributed`");
    assert_eq!(a["result"]["principal_role"], "user");
    assert_eq!(a["result"]["principal_scopes"], json!(["read"]));
    assert_eq!(b["result"]["ctx_sub"], "bob");
    assert_eq!(b["result"]["principal_sub"], "bob");
    assert_eq!(b["result"]["principal_role"], "operator", "each op carries ITS owner's authority, not the neighbour's");
    assert_ne!(a["result"]["principal_sub"], bus_principal::UNATTRIBUTED);
}

// ───────────────────────────── concurrency ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exclusive_type_joins_the_owners_own_run_and_refuses_another_accounts() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("exclusive").await else { return };
    let alice = account(&db, "alice", Role::Operator).await;
    let bob = account(&db, "bob", Role::Operator).await;
    let s = spec("test.exclusive", "/api/v1/rag/query", 0, true, t30);
    let slow = || runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        Outcome::done(200, json!({}))
    });
    let (st, first) = serve_as(&db, &alice, s, json!({}), None, slow()).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert!(first.get("joined").is_none());

    // Same owner: JOINS the run in flight (same id), starts nothing.
    let (st, second) = serve_as(&db, &alice, s, json!({}), None, slow()).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(second["op_id"], first["op_id"]);
    assert_eq!(second["joined"], true);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_ops").fetch_one(&db).await.unwrap();
    assert_eq!(n, 1, "exactly one run exists");

    // Another account: refused as the worker refuses ("already_running"), and
    // the other account's op id is NOT disclosed.
    let (st, busy) = serve_as(&db, &bob, s, json!({}), None, slow()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(busy["status"], "already_running");
    assert!(!busy.to_string().contains(first["op_id"].as_str().unwrap()));
    // The generic API answers the same situation 409.
    let (st, _) = api::serve(&db, &ctx_of(&bob), s, no_refusal, json!({}), Some(0), StatusCode::CONFLICT, slow()).await.pipe_status();
    assert_eq!(st, StatusCode::CONFLICT);

    // When the run ends, the next start is a NEW run.
    let _ = api::cancel_op(&db, Some(&alice), first["op_id"].as_str().unwrap()).await;
    let (st, third) = serve_as(&db, &bob, s, json!({}), None, slow()).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_ne!(third["op_id"], first["op_id"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_account_cannot_have_more_than_the_cap_of_live_ops() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cap").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.cap", "/api/v1/rag/query", 0, false, t30);
    let cap = max_active_per_owner();
    for _ in 0..cap {
        let (st, _) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Outcome::done(200, json!({}))
        }))
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
    }
    let (st, b) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{b}");
}

// ───────────────────────────── restart reconciliation ─────────────────────────────

async fn insert_live(db: &PgPool, status: &str, instance: &str, beat_age_secs: i64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO noo_ops (op_id, op_type, status, runner_instance, heartbeat_at, expires_at) \
         VALUES ($1, 'test.orphan', $2, $3, now() - make_interval(secs => $4), now() + interval '1 day')",
    )
    .bind(id)
    .bind(status)
    .bind(instance)
    .bind(beat_age_secs as f64)
    .execute(db)
    .await
    .expect("insert op");
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_fails_its_own_orphans_and_never_another_gateways_live_run() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("reconcile").await else { return };
    let mine_running = insert_live(&db, "running", "gw-a", 5).await;
    let mine_queued = insert_live(&db, "queued", "gw-a", 5).await;
    let other_live = insert_live(&db, "running", "gw-b", 5).await;
    let other_lost = insert_live(&db, "running", "gw-c", 600).await;
    let finished = {
        let id = insert_live(&db, "running", "gw-a", 5).await;
        sqlx::query("UPDATE noo_ops SET status = 'succeeded', result = '{\"kept\":1}'::jsonb WHERE op_id = $1").bind(id).execute(&db).await.unwrap();
        id
    };

    // Boot of gateway `gw-a`: its own live rows can never report; fail them now.
    let failed = reconcile_boot(&db, "gw-a").await.unwrap();
    assert_eq!(failed, 2);
    for id in [mine_running, mine_queued] {
        let r = get_row(&db, id).await.unwrap().unwrap();
        assert_eq!(r.status, "failed");
        assert!(r.error.unwrap().contains("gateway restarted"));
        assert!(r.finished_at.is_some());
    }
    // Another gateway's LIVE run is not ours to touch...
    assert_eq!(get_row(&db, other_live).await.unwrap().unwrap().status, "running");
    // ...and a finished op's result survives the boot.
    let f = get_row(&db, finished).await.unwrap().unwrap();
    assert_eq!((f.status.as_str(), f.result), ("succeeded", Some(json!({"kept": 1}))));

    // The sweeper handles an instance that simply STOPPED reporting: its
    // heartbeat is stale, so its run is failed; gw-b's fresh one is left alone.
    let report = sweep(&db).await.unwrap();
    assert_eq!(report.lost, 1);
    let lost = get_row(&db, other_lost).await.unwrap().unwrap();
    assert_eq!(lost.status, "failed");
    assert!(lost.error.unwrap().contains("stopped reporting"));
    assert_eq!(get_row(&db, other_live).await.unwrap().unwrap().status, "running");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_keeps_a_live_run_alive_with_a_heartbeat() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("heartbeat").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.beat", "/api/v1/rag/query", 0, false, t30);
    let (_, h) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    let id: Uuid = id_of(&h).parse().unwrap();
    until_status(&db, &alice, &id.to_string(), "running").await;
    // Its heartbeat is old, but THIS gateway holds the task: the sweep refreshes it first.
    sqlx::query("UPDATE noo_ops SET heartbeat_at = now() - interval '1 hour' WHERE op_id = $1").bind(id).execute(&db).await.unwrap();
    let report = sweep(&db).await.unwrap();
    assert_eq!(report.lost, 0, "a run this process is holding is never declared lost");
    assert_eq!(get_row(&db, id).await.unwrap().unwrap().status, "running");
}

// ───────────────────────────── expiry ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn results_expire_then_are_purged_and_a_live_op_is_never_expired() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("expiry").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.expiry", "/api/v1/rag/query", 0, false, t30);
    let (_, h) = serve_as(&db, &alice, s, json!({"keep": "me"}), None, runner(|_, _| async move {
        Outcome::done(200, json!({"private": "result"}))
    }))
    .await;
    let id = id_of(&h);
    let done = until_status(&db, &alice, &id, "succeeded").await;
    // The TTL default is a day after FINISHING.
    let exp: chrono::DateTime<chrono::Utc> = done["expires_at"].as_str().unwrap().parse().unwrap();
    let fin: chrono::DateTime<chrono::Utc> = done["finished_at"].as_str().unwrap().parse().unwrap();
    assert_eq!((exp - fin).num_seconds(), result_ttl().as_secs() as i64);

    // A running op past its expires_at is not touched by the expiry sweep.
    let (_, live) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    let live_id = id_of(&live);
    until_status(&db, &alice, &live_id, "running").await;
    sqlx::query("UPDATE noo_ops SET expires_at = now() - interval '1 hour' WHERE op_id = $1::uuid").bind(&live_id).execute(&db).await.unwrap();

    // Not yet expired: nothing to do.
    assert_eq!(sweep(&db).await.unwrap(), SweepReport::default());

    sqlx::query("UPDATE noo_ops SET expires_at = now() - interval '1 minute' WHERE op_id = $1::uuid").bind(&id).execute(&db).await.unwrap();
    let report = sweep(&db).await.unwrap();
    assert_eq!(report, SweepReport { lost: 0, expired: 1, purged: 0 });
    let (st, v) = read(&db, &alice, &id, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["status"], "expired", "a poll says it expired, not that it never existed");
    assert!(v["result"].is_null(), "the payload is gone");
    assert_eq!(v["params"], json!({}), "so are the params");
    assert_eq!(read(&db, &alice, &live_id, None).await.1["status"], "running");

    // A day after that the tombstone is deleted and the id is simply unknown.
    sqlx::query("UPDATE noo_ops SET expires_at = now() - interval '2 days' WHERE op_id = $1::uuid").bind(&id).execute(&db).await.unwrap();
    assert_eq!(sweep(&db).await.unwrap().purged, 1);
    assert_eq!(read(&db, &alice, &id, None).await.0, StatusCode::NOT_FOUND);
}

// ───────────────────────────── the store itself ─────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_store_has_the_indexes_the_design_relies_on() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("schema").await else { return };
    let idx: Vec<String> = sqlx::query_scalar("SELECT indexname FROM pg_indexes WHERE tablename = 'noo_ops' ORDER BY 1")
        .fetch_all(&db)
        .await
        .unwrap();
    for want in ["noo_ops_owner_created", "noo_ops_status_expires", "noo_ops_one_exclusive_live", "noo_ops_pkey"] {
        assert!(idx.iter().any(|i| i == want), "missing index {want}: {idx:?}");
    }
    // The status vocabulary is closed at the database.
    let bad = sqlx::query("INSERT INTO noo_ops (op_type, status, runner_instance, expires_at) VALUES ('x', 'weird', 'i', now())")
        .execute(&db)
        .await;
    assert!(bad.is_err());
}

// ───────────────────────────── pure units ─────────────────────────────

#[test]
fn outcome_classification_follows_the_status_line_and_names_the_reason() {
    assert!(Outcome::from_http(200, json!({"a": 1})).failure.is_none());
    assert!(Outcome::from_http(202, json!({})).failure.is_none());
    let f = Outcome::from_http(400, json!({"error": "question required"}));
    assert_eq!(f.failure.as_deref(), Some("question required"));
    let f = Outcome::from_http(503, json!({"nothing": "here"}));
    assert!(f.failure.unwrap().contains("503"));
}

#[test]
fn ingest_params_are_stored_without_the_document() {
    let t = api::find("rag.ingest").unwrap();
    let stored = (t.spec.redact)(&json!({"text": "SECRET DOCUMENT BODY", "title": "Q3", "_requester": {"sub": "x"}, "roles": ["company"]}));
    let s = stored.to_string();
    assert!(!s.contains("SECRET DOCUMENT BODY"), "{s}");
    assert!(!s.contains("_requester"), "{s}");
    assert_eq!(stored["title"], "Q3");
    assert_eq!(stored["text"]["_omitted_bytes"], 20);
    // And anything huge is replaced by a marker, whatever the type.
    let big = json!({"blob": "x".repeat(MAX_PARAMS_BYTES + 1)});
    assert_eq!(redact_default(&big)["_omitted"], "params too large to store");
}

#[test]
fn every_status_is_one_of_the_documented_six() {
    for s in [QUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED, EXPIRED] {
        assert_eq!(is_terminal(s), !matches!(s, QUEUED | RUNNING));
    }
}

#[test]
fn every_registered_type_has_a_unique_name_and_a_real_route() {
    let mut names: Vec<_> = api::TYPES.iter().map(|t| t.spec.name).collect();
    names.sort_unstable();
    let n = names.len();
    names.dedup();
    assert_eq!(names.len(), n, "type names are the public contract: unique");
    assert_eq!(n, 8);
    let routes = include_str!("../routes/knowledge.rs").to_string() + include_str!("../routes/snapshots.rs");
    for t in api::TYPES {
        assert!(routes.contains(&format!("\"{}\"", t.spec.route)), "{} names a route nobody serves: {}", t.spec.name, t.spec.route);
        assert!(!t.spec.cancel_note.is_empty() && !t.spec.summary.is_empty());
        assert!(t.spec.name.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'));
    }
}

// ───────────────────────────── one code path ─────────────────────────────

/// The body of `fn <name>(` up to the next top-level item.
fn fn_body(src: &str, name: &str) -> String {
    let code = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
    let start = code.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("fn {name} not found"));
    let rest = &code[start..];
    let end = ["\nasync fn ", "\npub(super) async fn ", "\npub(crate) async fn ", "\nfn ", "\npub(super) fn ", "\npub(super) const ", "\npub(crate) fn ", "\n/// "]
        .iter()
        .filter_map(|m| rest[1..].find(m))
        .min()
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    // Comments are prose about the code, not the code: a guard that reads
    // them would pass or fail on a sentence.
    rest[..end].lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n")
}

#[test]
fn the_long_routes_and_their_ops_run_one_code_path() {
    let knowledge = include_str!("../routes/knowledge.rs");
    let snapshots = include_str!("../routes/snapshots.rs");
    let ops_routes = include_str!("../routes/ops.rs");

    // (route handler, its source file, op type, the shared core the type's adapter runs)
    let table: [(&str, &str, &str, &str, &str); 7] = [
        ("graph_recluster", knowledge, "graph.recluster", "run_recluster", "recluster_core"),
        ("graph_extract_relations", knowledge, "graph.extract_relations", "run_extract_relations", "extract_relations_core"),
        ("graph_navigate", knowledge, "graph.navigate", "run_navigate", "navigate_core"),
        ("graph_traverse", knowledge, "graph.traverse", "run_traverse", "traverse_core"),
        ("rag_ingest", knowledge, "rag.ingest", "run_rag_ingest", "rag_ingest_core"),
        ("docs_ingest", knowledge, "docs.ingest", "run_docs_ingest", "docs_ingest_core"),
        ("snapshots_consolidate", snapshots, "snapshots.consolidate", "run_consolidate", "consolidate_core"),
    ];
    for (handler, src, ty, adapter, core) in table {
        // The route does NOTHING but start its op: no provider call, no worker call, no inline work.
        let h = fn_body(src, handler);
        assert!(h.contains(&format!("route_start(&state, &ctx, \"{ty}\"")), "{handler} must start the {ty} op");
        for forbidden in ["state.memory()", "worker_client", "intel_graph(", "attach_requester"] {
            assert!(!h.contains(forbidden), "{handler} does work inline ({forbidden}); that belongs in {core}, which the op runs");
        }
        // The op's adapter runs the SAME shared function...
        let a = fn_body(ops_routes, adapter);
        assert!(a.contains(&format!("{core}(")), "{adapter} must run {core}");
        // ...and that function is where the work lives.
        let c = fn_body(src, core);
        assert!(c.contains("state.memory()") || c.contains("intel_graph("), "{core} is the shared body");
    }
}

#[test]
fn audience_filtered_ops_hand_the_owners_identity_to_scope_resolve() {
    let knowledge = include_str!("../routes/knowledge.rs");
    let ops_routes = include_str!("../routes/ops.rs");
    // navigate/traverse/extract all go through `intel_graph`, which resolves the audience and confirms the reply...
    let helper = fn_body(knowledge, "intel_graph");
    assert!(helper.contains("scope::resolve(") && helper.contains("graph_reply("));
    for core in ["navigate_core", "traverse_core", "extract_relations_core"] {
        assert!(fn_body(knowledge, core).contains("intel_graph("), "{core}");
    }
    // ...and the op hands them the OWNER's captured ctx. Never `None`, never the gateway's.
    for adapter in ["run_navigate", "run_traverse", "run_extract_relations", "run_recluster", "run_consolidate", "run_rag_ingest", "run_docs_ingest"] {
        let body = fn_body(ops_routes, adapter);
        assert!(body.contains("c.ctx()"), "{adapter} must pass the owner's ctx");
        assert!(!body.contains("&None") && !body.contains("ctx: None"), "{adapter} must never run as no caller");
        assert!(!body.contains("Unrestricted"), "{adapter} must never name an audience of its own");
    }
    // The engine rebinds the owner's bus principal around the detached task.
    let engine = include_str!("../ops.rs");
    assert!(fn_body(engine, "supervise").contains("with_principal("));
}

// ───────────────────────────── MCP ─────────────────────────────

/// The user-door tools `noo_op_start` / `noo_op_status` / `noo_op_cancel` are
/// declarative: the door builds each request from the manifest and self-calls
/// the gateway as the caller. Drive a whole round trip through exactly what the
/// door would build.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_mcp_op_tool_round_trip_start_status_cancel() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("mcp_roundtrip").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let door = RequesterCtx { harness: Some("mcp-external:codex".into()), ..alice.clone() };

    let start = crate::mcp_external::tool("noo_op_start").expect("noo_op_start is in the user-door manifest");
    let status = crate::mcp_external::tool("noo_op_status").expect("noo_op_status is in the user-door manifest");
    let cancel = crate::mcp_external::tool("noo_op_cancel").expect("noo_op_cancel is in the user-door manifest");
    assert_eq!((start.method.as_str(), start.path.as_str()), ("POST", "/api/v1/ops"));
    assert_eq!(status.method.as_str(), "GET");
    assert_eq!(cancel.method.as_str(), "DELETE");

    // What the door would send for a start: the args ARE the body.
    let args = json!({"type": "rag.ingest", "params": {"title": "t"}});
    let (path, _) = crate::mcp_external::build_path(start, args.as_object().unwrap()).unwrap();
    assert_eq!(path, "/api/v1/ops");

    // The gateway answers a start with the handle (default_wait 0 here).
    let s = spec("test.mcp", "/api/v1/rag/query", 0, false, t30);
    let (st, handle) = serve_as(&db, &door, s, json!({"title": "t"}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        Outcome::done(200, json!({"doc_ids": ["d1"]}))
    }))
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let op_id = id_of(&handle);

    // The model passes op_id to noo_op_status; the door substitutes it into the path.
    let sargs = json!({"op_id": op_id, "wait": 10});
    let (spath, consumed) = crate::mcp_external::build_path(status, sargs.as_object().unwrap()).unwrap();
    assert_eq!(spath, format!("/api/v1/ops/{op_id}"));
    assert!(consumed.contains(&"op_id".to_string()), "op_id goes in the path, not the query");
    let rest = crate::mcp_external::remaining_args(status, sargs.as_object().unwrap(), &consumed);
    assert_eq!(rest.get("wait"), Some(&json!(10)), "wait is the only query parameter");

    // ...and the gateway answers that GET with the finished result, to the same consumer.
    let (st, v) = read(&db, &door, spath.rsplit('/').next().unwrap(), Some(10)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["status"], "succeeded");
    assert_eq!(v["result"], json!({"doc_ids": ["d1"]}));

    // Cancel goes through the same visibility rule.
    let (cpath, _) = crate::mcp_external::build_path(cancel, json!({"op_id": op_id}).as_object().unwrap()).unwrap();
    assert_eq!(cpath, format!("/api/v1/ops/{op_id}"));
    let (st, _) = api::cancel_op(&db, Some(&door), &op_id).await.pipe_status();
    assert_eq!(st, StatusCode::CONFLICT, "already finished");
}

// ───────────────────────────── configuration ─────────────────────────────

#[test]
fn every_types_default_wait_is_a_registered_hot_reloadable_setting_with_the_same_default() {
    for t in api::TYPES {
        let key = t.spec.wait_key();
        let registered = crate::routes::settings::string_setting_default(&key)
            .unwrap_or_else(|| panic!("{key} must be a registered string setting (routes/settings.rs STRING_REGISTRY), or an admin cannot change it"));
        assert_eq!(registered, t.spec.default_wait_secs.to_string(), "{key}: the registry's default must be the type's");
    }
    assert_eq!(crate::routes::settings::string_setting_default("NOO_OPS_RESULT_TTL_SECS"), Some("86400"));
    assert_eq!(result_ttl().as_secs(), 86400);
}

#[test]
fn the_generic_start_never_holds_the_request_and_answers_409_when_busy() {
    let src = include_str!("../routes/ops.rs");
    let body = fn_body(src, "ops_start");
    assert!(body.contains("Some(0)"), "POST /api/v1/ops answers with the handle at once");
    assert!(body.contains("StatusCode::CONFLICT"), "a busy exclusive type is a 409 here (the long routes keep the worker's 200)");
    let route = fn_body(src, "route_start");
    assert!(route.contains("StatusCode::OK"), "the long routes answer a busy run as the worker always did");
}

#[test]
fn the_ops_routes_are_registered_and_types_precedes_the_id_pattern() {
    let src = include_str!("../routes/ops.rs");
    let types = src.find("\"/api/v1/ops/types\"").expect("types route");
    let id = src.find("\"/api/v1/ops/{id}\"").expect("id route");
    assert!(types < id, "`types` must be registered before `{{id}}` or it is read as an id");
    assert!(include_str!("../routes/mod.rs").contains(".merge(ops::router())"));
}

#[test]
fn the_sweeper_and_boot_reconcile_are_wired_through_the_loop_health_primitive() {
    let engine = include_str!("../ops.rs");
    assert!(engine.contains("spawn_managed_loop(\"ops_sweep\""), "every gateway loop must report health; managed_loop does it");
    assert!(engine.contains("reconcile_boot("));
    let main = include_str!("../main.rs");
    assert!(main.contains("ops::spawn(state.clone())"), "main must start the sweeper");
    assert!(main.contains("\nmod ops;"));
}

// ───────────────────────── security review fixes (PR 746) ─────────────────────────

async fn live_rows(db: &PgPool, who: &RequesterCtx, n: i64, status: &str) {
    for _ in 0..n {
        sqlx::query(
            "INSERT INTO noo_ops (op_type, status, owner_uuid, runner_instance, expires_at) \
             VALUES ('test.fill', $1, (SELECT user_uuid FROM noo_users WHERE username = $2), 'gw-fill', now() + interval '1 day')",
        )
        .bind(status)
        .bind(&who.sub)
        .execute(db)
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_op_keeps_its_cap_slot_while_its_worker_run_may_still_be_going() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cancel_cap").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.cancelcap", "/api/v1/rag/query", 0, false, t30);
    let cap = max_active_per_owner();
    let slow = || runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Outcome::done(200, json!({}))
    });
    let mut ids = vec![];
    for _ in 0..cap {
        let (st, h) = serve_as(&db, &alice, s, json!({}), None, slow()).await;
        assert_eq!(st, StatusCode::ACCEPTED);
        ids.push(id_of(&h));
    }
    for id in &ids {
        assert_eq!(api::cancel_op(&db, Some(&alice), id).await.0, StatusCode::OK);
    }
    // Every op is cancelled, but the workers they started may still be running: still at the cap.
    let (st, b) = serve_as(&db, &alice, s, json!({}), None, slow()).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "start-then-cancel in a loop must not be unbounded worker load: {b}");
    let note: Value = sqlx::query_scalar("SELECT cancel_note FROM noo_ops WHERE op_id = $1::uuid").bind(&ids[0]).fetch_one(&db).await.unwrap();
    assert!(note["worker_may_run_until"].is_string());
    // Once the run limit has passed the slots come back.
    sqlx::query("UPDATE noo_ops SET worker_may_run_until = now() - interval '1 second'")
        .execute(&db)
        .await
        .unwrap();
    let (st, _) = serve_as(&db, &alice, s, json!({}), None, slow()).await;
    assert_eq!(st, StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_starts_at_cap_minus_one_admit_exactly_one() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cap_race").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    live_rows(&db, &alice, max_active_per_owner() - 1, "running").await;
    let s = spec("test.caprace", "/api/v1/rag/query", 0, false, t30);
    let mut tasks = vec![];
    for _ in 0..8 {
        let (db, alice) = (db.clone(), alice.clone());
        tasks.push(tokio::spawn(async move {
            serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
                tokio::time::sleep(Duration::from_secs(20)).await;
                Outcome::done(200, json!({}))
            }))
            .await
            .0
        }));
    }
    let mut ok = 0;
    let mut refused = 0;
    for t in tasks {
        match t.await.unwrap() {
            StatusCode::ACCEPTED => ok += 1,
            StatusCode::TOO_MANY_REQUESTS => refused += 1,
            other => panic!("{other}"),
        }
    }
    assert_eq!((ok, refused), (1, 7), "count-then-insert raced");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegated_agent_run_sees_and_cancels_only_its_own_dispatchs_ops() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("delegated").await else { return };
    let alice = account(&db, "alice", Role::User).await; // the person / web session: no harness
    let mcp_b = RequesterCtx { harness: Some("mcp-external:b".into()), ..alice.clone() };
    let agent_1 = RequesterCtx { harness: Some(format!("{}t1", crate::worker_delegation::HARNESS_PREFIX)), ..alice.clone() };
    let agent_2 = RequesterCtx { harness: Some(format!("{}t2", crate::worker_delegation::HARNESS_PREFIX)), ..alice.clone() };
    let s = spec("test.deleg", "/api/v1/rag/query", 0, false, t30);
    let slow = || runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Outcome::done(200, json!({}))
    });
    let (_, web) = serve_as(&db, &alice, s, json!({}), None, slow()).await;
    let (_, mcp) = serve_as(&db, &mcp_b, s, json!({}), None, slow()).await;
    let (_, own) = serve_as(&db, &agent_1, s, json!({}), None, slow()).await;
    let (_, other) = serve_as(&db, &agent_2, s, json!({}), None, slow()).await;
    for foreign in [&web, &mcp, &other] {
        let id = id_of(foreign);
        assert_eq!(read(&db, &agent_1, &id, None).await.0, StatusCode::NOT_FOUND, "an agent run must not read {foreign}");
        let (st, _) = api::cancel_op(&db, Some(&agent_1), &id).await.pipe_status();
        assert_eq!(st, StatusCode::NOT_FOUND, "an agent run must not cancel another consumer's or a web op");
        assert_ne!(read(&db, &alice, &id, None).await.1["status"], "cancelled");
    }
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&agent_1), false, None, 50).await;
    assert_eq!(l["count"], 1, "its own op only: {l}");
    assert_eq!(api::cancel_op(&db, Some(&agent_1), &id_of(&own)).await.0, StatusCode::OK);
}

#[test]
fn a_delegated_token_carries_its_dispatch_as_the_harness() {
    let p = bus_principal::Principal::user("alice", Role::User, vec!["read".into()]);
    let c = crate::worker_delegation::claims(&p, "call-77", 60, "a-long-enough-test-secret-for-the-jwt-0123456789").expect("claims");
    assert_eq!(c["harness"], "worker:call-77");
    // The ops routes stay reachable for the dispatcher to follow its own handle; the harness is what bounds them.
    assert!(crate::worker_delegation::route_allowed("GET", "/api/v1/ops/abc"));
}

#[test]
fn ingest_params_are_stored_by_allow_list_including_nested_params() {
    let t = api::find("docs.ingest").unwrap();
    let stored = (t.spec.redact)(&json!({
        "params": {"text": "NESTED SECRET DOCUMENT", "title": "Q3", "metadata": {"k": "NESTED-META-SECRET"}},
        "text": "TOP SECRET DOCUMENT",
        "future_field": "FUTURE-SECRET",
        "roles": ["company"],
    }))
    .to_string();
    for secret in ["NESTED SECRET DOCUMENT", "NESTED-META-SECRET", "TOP SECRET DOCUMENT", "FUTURE-SECRET"] {
        assert!(!stored.contains(secret), "{secret} was stored: {stored}");
    }
    assert!(stored.contains("Q3") && stored.contains("company"), "{stored}");
    assert!(stored.contains("_omitted_bytes"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_with_no_account_must_be_a_controller_service() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("machine_gate").await else { return };
    let s = spec("test.mgate", "/api/v1/rag/query", 0, false, t30);
    let go = |p: Option<bus_principal::Principal>| {
        let db = db.clone();
        async move {
            let fut = api::serve(&db, &None, s, no_refusal, json!({}), None, StatusCode::OK, runner(|_, _| async move { Outcome::done(200, json!({})) }));
            let (st, _) = match p {
                Some(p) => bus_principal::with_principal(p, fut).await,
                None => fut.await,
            };
            st
        }
    };
    assert_eq!(go(Some(bus_principal::Principal::internal("cluster:heartbeat", &[]))).await, StatusCode::ACCEPTED);
    for refused in [
        None, // no principal in scope: unattributed
        Some(bus_principal::Principal::internal("node:n1", &[])),
        Some(bus_principal::Principal::internal("key:some-addon", &[])),
        Some(bus_principal::Principal::user("mallory", Role::Admin, vec!["admin".into()])),
    ] {
        assert_eq!(go(refused).await, StatusCode::FORBIDDEN, "a credential class that is not a controller service is refused");
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_ops").fetch_one(&db).await.unwrap();
    assert_eq!(n, 1, "refused starts leave no row");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_other_instance_refusal_does_not_name_the_host() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("other_host").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    live_rows(&db, &alice, 1, "running").await;
    sqlx::query("UPDATE noo_ops SET runner_instance = 'secret-host-9'").execute(&db).await.unwrap();
    let id: String = sqlx::query_scalar("SELECT op_id::text FROM noo_ops").fetch_one(&db).await.unwrap();
    let (st, axum::Json(b)) = api::cancel_op(&db, Some(&alice), &id).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(!b.to_string().contains("secret-host-9"), "{b}");
}

// ───────────────────── second security pass (PR 748) ─────────────────────

/// A delegated agent run: a user token whose `act` is the worker and whose
/// `harness` is the run id (what `worker_delegation::claims` mints).
fn delegated(base: &RequesterCtx, run: &str) -> RequesterCtx {
    RequesterCtx {
        harness: Some(format!("{}{run}", crate::worker_delegation::HARNESS_PREFIX)),
        act: Some(crate::auth::Actor {
            sub: crate::worker_delegation::WORKER_ACTOR.to_string(),
            iss_user: None,
            task: Some(run.to_string()),
        }),
        ..base.clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_run_follows_and_cancels_its_own_ops_across_tool_calls_and_no_other_run_can() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("run_binding").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.run", "/api/v1/rag/query", 0, false, t30);
    // Tool call A (noo_op_start) and tool call B (status, cancel) of the SAME run carry the same
    // delegated token identity: the harness is the run id, not the call id.
    let run_1 = delegated(&alice, "run-1");
    let call_a = run_1.clone();
    let call_b = run_1.clone();
    let (st, h) = serve_as(&db, &call_a, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let id = id_of(&h);
    assert_eq!(read(&db, &call_b, &id, None).await.0, StatusCode::OK, "a later call of the same run follows its op");
    // A different run, concurrent or later, never sees it.
    let run_2 = delegated(&alice, "run-2");
    assert_eq!(read(&db, &run_2, &id, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(api::cancel_op(&db, Some(&run_2), &id).await.0, StatusCode::NOT_FOUND);
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&run_2), false, None, 50).await;
    assert_eq!(l["count"], 0);
    // ...and the later call can cancel it, freeing the agent's own work.
    assert_eq!(api::cancel_op(&db, Some(&call_b), &id).await.0, StatusCode::OK);
}

#[test]
fn every_tool_call_of_a_run_shares_the_delegation_binding_and_runs_never_do() {
    use crate::routes::communication::TurnPrincipal;
    let turn = |run: &str| TurnPrincipal { requester: "alice".into(), run_id: run.into(), ..Default::default() };
    // two calls (different, predictable call ids) in one run: one binding
    assert_eq!(crate::tools::delegation_task(&turn("r-1")), crate::tools::delegation_task(&turn("r-1")));
    assert_eq!(crate::tools::delegation_task(&turn("r-1")), "r-1");
    assert_ne!(crate::tools::delegation_task(&turn("r-1")), crate::tools::delegation_task(&turn("r-2")));
    // outside a coordinator turn there is no run: each dispatch gets its own random binding
    assert_ne!(crate::tools::delegation_task(&turn("")), crate::tools::delegation_task(&turn("")));
    // the run id is minted once per turn, fresh each turn
    let src = include_str!("../coordinator/agent_loop.rs");
    let f = fn_body(src, "turn_principal");
    assert!(f.contains("run_id: uuid::Uuid::new_v4().to_string()"), "a turn needs its own nonce: {f}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegated_token_cannot_start_an_op_whose_route_it_cannot_call_directly() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("deleg_bypass").await else { return };
    let admin = account(&db, "adm", Role::Admin).await; // role is no excuse: only the route confinement can refuse
    let agent = delegated(&admin, "run-x");
    let mut refused = 0;
    let mut allowed = 0;
    for t in api::TYPES {
        let direct = crate::worker_delegation::route_allowed("POST", t.spec.route);
        if t.spec.admin_only {
            // A destructive admin run is refused to an agent token even where the route is a tool
            // route (the operator door's tool for it makes it one): the type says so itself.
            let (st, body) = serve_as(&db, &agent, &t.spec, json!({}), Some(0), runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
            assert_eq!(st, StatusCode::FORBIDDEN, "{} is admin-only: no agent token may start it: {body}", t.spec.name);
            assert!(body["error"].as_str().unwrap_or("").contains("delegated or exchanged credential"), "{body}");
            continue;
        }
        let (st, body) = serve_as(&db, &agent, &t.spec, json!({}), Some(0), runner(|_, _| async move {
            tokio::time::sleep(Duration::from_secs(20)).await;
            Outcome::done(200, json!({}))
        }))
        .await;
        if direct {
            allowed += 1;
            assert_ne!(st, StatusCode::FORBIDDEN, "{} is a tool route, so an agent may start it: {body}", t.spec.name);
        } else {
            refused += 1;
            assert_eq!(st, StatusCode::FORBIDDEN, "{} is not a tool route: an agent token must not start it through /ops: {body}", t.spec.name);
        }
    }
    assert!(refused >= 1, "rag.ingest (not in TOOL_ROUTES) must be among the refused: otherwise this test guards nothing");
    assert!(allowed >= 1);
    // The non-delegated admin may start them all (the confinement is about the delegated token).
    let (st, _) = serve_as(&db, &admin, &api::find("rag.ingest").unwrap().spec, json!({}), Some(0), runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!(st, StatusCode::ACCEPTED);
}

/// Stores `erase_targets` reads that a mesh-only scratch database does not have (they are the
/// memory plane's): minimal stand-ins with the columns the targets filter on.
pub(crate) async fn stub_erase_stores(db: &PgPool) {
    for t in crate::routes::users::erase_store_tables() {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL").bind(t).fetch_one(db).await.unwrap();
        if !exists {
            sqlx::query(&format!(
                "CREATE TABLE {t} (id uuid, user_id text, conversation_id uuid, username text, from_user text, to_user text, \
                 video_frame_id uuid, content_summary text)"
            ))
            .execute(db)
            .await
            .unwrap();
        }
    }
}

async fn insert_op(db: &PgPool, who: &str, op_type: &str, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO noo_ops (op_id, op_type, status, owner_uuid, runner_instance, started_at, expires_at) \
         VALUES ($1, $2, $3, (SELECT user_uuid FROM noo_users WHERE username = $4), 'gw-x', now(), now() + interval '1 day')",
    )
    .bind(id)
    .bind(op_type)
    .bind(status)
    .bind(who)
    .execute(db)
    .await
    .unwrap();
    id
}

fn retry_after(e: &crate::routes::AppError) -> Option<u64> {
    match e {
        crate::routes::AppError::RetryLater { retry_after_secs, .. } => Some(*retry_after_secs),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erase_waits_for_a_live_write_op_then_refuses_new_starts_then_succeeds() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("erase_block").await else { return };
    stub_erase_stores(&db).await;
    let alice = account(&db, "alice", Role::User).await;
    let bob = account(&db, "bob", Role::User).await;
    let live = insert_op(&db, "alice", "docs.ingest", "running").await;
    let _bobs = insert_op(&db, "bob", "docs.ingest", "running").await;

    // A dry run is a plan, never a refusal.
    assert!(crate::routes::users::erase_account(&db, "alice", true, false).await.is_ok());

    // The real erase: 409 + Retry-After, bounded by the type's run limit, and nothing deleted.
    let err = crate::routes::users::erase_account(&db, "alice", false, false).await.unwrap_err();
    let wait = retry_after(&err).unwrap_or_else(|| panic!("expected RetryLater, got {err}"));
    assert!((1..=api::find("docs.ingest").map(|t| (t.spec.timeout)().as_secs()).unwrap()).contains(&wait), "{wait}");
    assert!(err.to_string().contains(&format!("retry in {wait}s")), "the message says when to retry: {err}");
    let still: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_ops WHERE op_id = $1").bind(live).fetch_one(&db).await.unwrap();
    assert_eq!(still, 1, "a refused erase deletes nothing");
    let resp = axum::response::IntoResponse::into_response(err);
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(resp.headers().get("retry-after").unwrap().to_str().unwrap(), wait.to_string());

    // The refusal MARKED the account: a new start (any type) is refused, so a caller that keeps
    // starting writes cannot starve the erase. Another account is untouched.
    let s = spec("test.starve", "/api/v1/rag/query", 0, false, t30);
    let (st, b) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!(st, StatusCode::LOCKED, "{b}");
    assert!(b["error"].as_str().unwrap().contains("erasure is pending"));
    assert_eq!(serve_as(&db, &bob, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await.0, StatusCode::ACCEPTED);

    // The write op ends (or its window passes): the erase now succeeds, clears the mark, deletes the rows.
    sqlx::query("UPDATE noo_ops SET status = 'succeeded' WHERE op_id = $1").bind(live).execute(&db).await.unwrap();
    let done = crate::routes::users::erase_account(&db, "alice", false, true).await.expect("erase after the window");
    assert_eq!(done["dry_run"], false);
    let ops_left: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_ops WHERE owner_uuid = (SELECT user_uuid FROM noo_users WHERE username = 'alice')").fetch_one(&db).await.unwrap();
    assert_eq!(ops_left, 0);
    let marks: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_ops_erase_pending").fetch_one(&db).await.unwrap();
    assert_eq!(marks, 0, "the successful erase clears the mark");
    // keep_account: the account is still there and may start work again.
    assert_eq!(serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await.0, StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recently_cancelled_write_op_blocks_an_erase_until_its_worker_window_passes() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("erase_cancelled").await else { return };
    stub_erase_stores(&db).await;
    let alice = account(&db, "alice", Role::User).await;
    let id = insert_op(&db, "alice", "rag.ingest", "cancelled").await;
    sqlx::query("UPDATE noo_ops SET worker_may_run_until = now() + interval '100 seconds' WHERE op_id = $1").bind(id).execute(&db).await.unwrap();
    let err = crate::routes::users::erase_account(&db, "alice", false, false).await.unwrap_err();
    let wait = retry_after(&err).expect("blocked");
    assert!((90..=101).contains(&wait), "retry-after tracks worker_may_run_until: {wait}");
    sqlx::query("UPDATE noo_ops SET worker_may_run_until = now() - interval '1 second'").execute(&db).await.unwrap();
    assert!(crate::routes::users::erase_account(&db, "alice", false, false).await.is_ok(), "after the window it succeeds");
    let _ = alice;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_erase_pending_mark_expires_so_an_abandoned_erase_cannot_lock_an_account() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("erase_mark_expiry").await else { return };
    stub_erase_stores(&db).await;
    let alice = account(&db, "alice", Role::User).await;
    insert_op(&db, "alice", "docs.ingest", "running").await;
    assert!(crate::routes::users::erase_account(&db, "alice", false, false).await.is_err());
    let s = spec("test.markexp", "/api/v1/rag/query", 0, false, t30);
    assert_eq!(serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await.0, StatusCode::LOCKED);
    // twice the longest run limit
    let longest = api::TYPES.iter().map(|t| (t.spec.timeout)().as_secs()).max().unwrap();
    assert_eq!(crate::routes::ops::erase_pending_ttl_secs(), longest * 2);
    let (ttl,): (f64,) = sqlx::query_as("SELECT extract(epoch FROM expires_at - marked_at)::float8 FROM noo_ops_erase_pending").fetch_one(&db).await.unwrap();
    assert!((ttl - (longest * 2) as f64).abs() < 5.0, "{ttl}");
    sqlx::query("UPDATE noo_ops_erase_pending SET expires_at = now() - interval '1 second'").execute(&db).await.unwrap();
    assert_eq!(serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await.0, StatusCode::ACCEPTED, "an expired mark no longer locks the account");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erase_stops_read_side_live_ops_and_a_refused_erase_stops_nothing() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("erase_abort").await else { return };
    stub_erase_stores(&db).await;
    // an Admin who is the LAST enabled admin: the erase is refused (403), and must not kill its ops
    sqlx::query("INSERT INTO noo_users (username, hashed_password, scopes) VALUES ('root', 'x', '[\"read\",\"write\",\"admin\"]')").execute(&db).await.unwrap();
    let root = RequesterCtx { sub: "root".into(), scopes: vec!["read".into(), "write".into(), "admin".into()], role: Role::Admin, harness: None, act: None };
    let recluster = &api::find("graph.recluster").unwrap().spec; // read-side: writes no user data
    assert!(!recluster.writes_user_data);
    let dropped = Arc::new(AtomicBool::new(false));
    let d2 = dropped.clone();
    let (_, h) = serve_as(&db, &root, recluster, json!({}), None, runner(move |_, _| async move {
        let _g = SetOnDrop(d2);
        tokio::time::sleep(Duration::from_secs(60)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    until_status(&db, &root, &id_of(&h), "running").await;
    let err = crate::routes::users::erase_account(&db, "root", false, false).await.unwrap_err();
    assert!(matches!(err, crate::routes::AppError::Forbidden(_)), "the last admin: {err}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!dropped.load(Ordering::SeqCst), "a REFUSED erase must not abort the account's ops");
    // (recluster is one-at-a-time: free the slot, the refused erase having left the op alone)
    assert_eq!(api::cancel_op(&db, Some(&root), &id_of(&h)).await.0, StatusCode::OK);
    // an ordinary account with a read-side live op: the erase proceeds, and the task is aborted
    let alice = account(&db, "alice", Role::Operator).await;
    let dropped2 = Arc::new(AtomicBool::new(false));
    let d3 = dropped2.clone();
    let (_, h2) = serve_as(&db, &alice, recluster, json!({}), None, runner(move |_, _| async move {
        let _g = SetOnDrop(d3);
        tokio::time::sleep(Duration::from_secs(60)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    until_status(&db, &alice, &id_of(&h2), "running").await;
    crate::routes::users::erase_account(&db, "alice", false, false).await.expect("a read-side op does not block an erase");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(dropped2.load(Ordering::SeqCst), "the erase aborted the live read-side task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_op_whose_row_was_erased_does_not_dispatch_even_when_the_account_remains() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("still_live").await else { return };
    stub_erase_stores(&db).await;
    let alice = account(&db, "alice", Role::User).await;
    let id = insert_op(&db, "alice", "docs.ingest", "queued").await;
    let ctx = OpCtx { op_id: id, requester: Some(alice.clone()), db: db.clone() };
    assert!(ctx.still_live().await);
    // keep_account erase: the account stays in noo_users, but its op rows go (it was queued, not a
    // blocker only because the test finishes it first)
    sqlx::query("UPDATE noo_ops SET status = 'cancelled', cancel_note = '{}'::jsonb").execute(&db).await.unwrap();
    crate::routes::users::erase_account(&db, "alice", false, true).await.expect("erase keep_account");
    let present: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM noo_users WHERE username = 'alice')").fetch_one(&db).await.unwrap();
    assert!(present, "keep_account keeps the login");
    assert!(!ctx.still_live().await, "the owner row check would still say yes here; the OP row check says no");
    // and without keep_account
    let alice2 = account(&db, "carol", Role::User).await;
    let id2 = insert_op(&db, "carol", "docs.ingest", "queued").await;
    let ctx2 = OpCtx { op_id: id2, requester: Some(alice2), db: db.clone() };
    sqlx::query("UPDATE noo_ops SET status = 'cancelled', cancel_note = '{}'::jsonb WHERE op_id = $1").bind(id2).execute(&db).await.unwrap();
    crate::routes::users::erase_account(&db, "carol", false, false).await.expect("erase");
    assert!(!ctx2.still_live().await);
}

#[test]
fn every_write_side_adapter_checks_its_row_before_it_writes_and_the_erase_takes_the_lock_first() {
    let routes = include_str!("../routes/ops.rs");
    let writers = [
        "run_extract_relations", "run_consolidate", "run_navigate", "run_traverse", "run_rag_ingest", "run_docs_ingest",
        "run_entity_cleanup",
    ];
    for a in writers {
        let b = fn_body(routes, a);
        let live = b.find("still_live()").unwrap_or_else(|| panic!("{a} must check its row first"));
        let core = b.find("_core(").expect("core call");
        assert!(live < core, "{a}: check BEFORE the write");
    }
    assert!(!fn_body(routes, "run_recluster").contains("still_live"), "recluster writes no user-owned data");
    // every registered type declares whether it writes user data; only recluster does not
    for t in api::TYPES {
        assert_eq!(t.spec.writes_user_data, t.spec.name != "graph.recluster", "{}", t.spec.name);
    }
    // erase order: lock, then the block check (+mark), then abort, then the deletes; the abort only
    // after the last-admin refusal
    let users = include_str!("../routes/users.rs");
    let f = fn_body(users, "erase_account");
    let pos = |needle: &str| f.find(needle).unwrap_or_else(|| panic!("{needle} missing from erase_account"));
    assert!(pos("require_not_last_admin(") < pos("lock_owner("), "a refused erase must not touch ops");
    assert!(pos("lock_owner(") < pos("erase_block("));
    assert!(pos("erase_block(") < pos("mark_erase_pending("));
    assert!(pos("mark_erase_pending(") < pos("abort_live_for_account("));
    assert!(pos("abort_live_for_account(") < pos("t.delete_sql()") || pos("abort_live_for_account(") < pos("delete_sql()"));
    // the handler goes through the same function the tests drive
    assert!(fn_body(users, "user_erase").contains("erase_account("));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_does_not_wait_for_the_account_lock_it_is_refused_429() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("try_lock").await else { return };
    let alice = account(&db, "alice", Role::User).await;
    let owner: Uuid = sqlx::query_scalar("SELECT user_uuid FROM noo_users WHERE username = 'alice'").fetch_one(&db).await.unwrap();
    let mut held = db.begin().await.unwrap();
    lock_owner(&mut held, owner).await.unwrap(); // an erase (or another start) holds it
    let s = spec("test.trylock", "/api/v1/rag/query", 0, false, t30);
    let t0 = std::time::Instant::now();
    let (st, _) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert!(t0.elapsed() < Duration::from_secs(2), "it must not park a pool connection behind the lock");
    held.rollback().await.unwrap();
    assert_eq!(serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await.0, StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_op_outlives_its_short_ttl_until_the_worker_window_passes() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cancel_ttl").await else { return };
    unsafe { std::env::set_var("NOO_OPS_RESULT_TTL_SECS", "60") };
    let alice = account(&db, "alice", Role::User).await;
    let s = spec("test.cancelttl", "/api/v1/rag/query", 0, false, t30);
    let (_, h) = serve_as(&db, &alice, s, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    let id = id_of(&h);
    until_status(&db, &alice, &id, "running").await;
    assert_eq!(api::cancel_op(&db, Some(&alice), &id).await.0, StatusCode::OK);
    unsafe { std::env::remove_var("NOO_OPS_RESULT_TTL_SECS") };
    let (exp, until): (chrono::DateTime<chrono::Utc>, String) =
        sqlx::query_as("SELECT expires_at, cancel_note->>'worker_may_run_until' FROM noo_ops WHERE op_id = $1::uuid").bind(&id).fetch_one(&db).await.unwrap();
    let until: chrono::DateTime<chrono::Utc> = until.parse().unwrap();
    assert!(exp >= until - chrono::Duration::seconds(1), "expires_at {exp} must not precede worker_may_run_until {until}: the sweeper nulls cancel_note at expiry");
    assert!((exp - chrono::Utc::now()).num_seconds() > 600, "a 60s TTL must not release the cap slot early");
}

// ───────────────────────── third pass (F1, F2) ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admins_delegated_agent_run_gets_the_run_scoped_view_not_the_admins() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("admin_agent").await else { return };
    let admin = account(&db, "adm", Role::Admin).await;
    let bob = account(&db, "bob", Role::User).await;
    let s = spec("test.adminagent", "/api/v1/rag/query", 0, false, t30);
    let slow = || runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Outcome::done(200, json!({}))
    });
    let (_, web) = serve_as(&db, &admin, s, json!({}), None, slow()).await; // the admin's own web op
    let (_, others) = serve_as(&db, &bob, s, json!({}), None, slow()).await; // another user's ingest
    let run_1 = delegated(&admin, "run-1");
    let run_2 = delegated(&admin, "run-2");
    let (_, own) = serve_as(&db, &run_1, s, json!({}), None, slow()).await;
    let (_, other_run) = serve_as(&db, &run_2, s, json!({}), None, slow()).await;
    for foreign in [&web, &others, &other_run] {
        let id = id_of(foreign);
        assert_eq!(read(&db, &run_1, &id, None).await.0, StatusCode::NOT_FOUND, "a delegated ADMIN run must not read {foreign}");
        assert_eq!(api::cancel_op(&db, Some(&run_1), &id).await.0, StatusCode::NOT_FOUND, "...nor cancel it");
    }
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&run_1), false, None, 50).await;
    assert_eq!(l["count"], 1, "a delegated admin lists only its own run's ops: {l}");
    assert_eq!(read(&db, &run_1, &id_of(&own), None).await.0, StatusCode::OK);
    // A direct, non-delegated admin still sees and can cancel everyone's.
    for id in [&web, &others, &own, &other_run] {
        assert_eq!(read(&db, &admin, &id_of(id), None).await.0, StatusCode::OK);
    }
    let (_, axum::Json(l)) = api::list_ops(&db, Some(&admin), false, None, 50).await;
    assert_eq!(l["count"], 4);
    assert_eq!(api::cancel_op(&db, Some(&admin), &id_of(&others)).await.0, StatusCode::OK);
}

/// A write op the gateway lost track of while its worker may still be mid-write must still block
/// an erase: dispatch -> the row turns `failed` by `how` -> erase -> 409 with Retry-After.
async fn failed_write_op_blocks_erase(db: &PgPool, user: &str, how: &str) {
    let alice = account(db, user, Role::User).await;
    let id = insert_op(db, user, "docs.ingest", "running").await;
    sqlx::query("UPDATE noo_ops SET worker_limit_secs = 120, runner_instance = $2 WHERE op_id = $1").bind(id).bind(how).execute(db).await.unwrap();
    match how {
        "boot" => assert_eq!(reconcile_boot(db, "boot").await.unwrap(), 1),
        "lost" => {
            sqlx::query("UPDATE noo_ops SET heartbeat_at = now() - interval '1 hour' WHERE op_id = $1").bind(id).execute(db).await.unwrap();
            assert_eq!(sweep(db).await.unwrap().lost, 1);
        }
        _ => unreachable!(),
    }
    let st: String = sqlx::query_scalar("SELECT status FROM noo_ops WHERE op_id = $1").bind(id).fetch_one(db).await.unwrap();
    assert_eq!(st, "failed", "{how}: the row is no longer live");
    let err = crate::routes::users::erase_account(db, user, false, false).await.unwrap_err();
    let wait = retry_after(&err).unwrap_or_else(|| panic!("{how}: expected a 409 Retry-After, got {err}"));
    assert!((1..=121).contains(&wait), "{how}: bounded by the type's run limit stamped at start: {wait}");
    let (exp, until): (chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT expires_at, worker_may_run_until FROM noo_ops WHERE op_id = $1").bind(id).fetch_one(db).await.unwrap();
    assert!(exp >= until, "{how}: the row outlives its worker window");
    // the starvation mark still applies
    let s = spec("test.f2", "/api/v1/rag/query", 0, false, t30);
    assert_eq!(serve_as(db, &alice, s, json!({}), None, runner(|_, _| async move { Outcome::done(200, json!({})) })).await.0, StatusCode::LOCKED);
    // once the window passes the erase goes through
    sqlx::query("UPDATE noo_ops SET worker_may_run_until = now() - interval '1 second'").execute(db).await.unwrap();
    assert!(crate::routes::users::erase_account(db, user, false, false).await.is_ok(), "{how}: after the window");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_op_failed_by_a_restart_or_a_lost_runner_still_blocks_an_erase_while_its_worker_may_run() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("f2_reconcile").await else { return };
    stub_erase_stores(&db).await;
    failed_write_op_blocks_erase(&db, "alice", "boot").await;
    failed_write_op_blocks_erase(&db, "carol", "lost").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_op_failed_by_the_supervisor_timeout_still_blocks_an_erase() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("f2_timeout").await else { return };
    stub_erase_stores(&db).await;
    let alice = account(&db, "alice", Role::User).await;
    let slow = spec("test.f2timeout", "/api/v1/rag/query", 0, false, t1);
    let (_, h) = serve_as(&db, &alice, slow, json!({}), None, runner(|_, _| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Outcome::done(200, json!({}))
    }))
    .await;
    let v = until_status(&db, &alice, &id_of(&h), "failed").await;
    assert_eq!(v["result_status"], 504);
    // the test type is not in the registry: it is treated as write-side. The row carries the window.
    let (until, fin, exp): (Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT worker_may_run_until, finished_at, expires_at FROM noo_ops WHERE op_id = $1::uuid").bind(id_of(&h)).fetch_one(&db).await.unwrap();
    let until = until.expect("the supervisor timeout stamps the worker window");
    // a full run limit (1s for this test type's spec) from the moment the gateway stopped listening
    assert!((until - fin).num_milliseconds() >= 900, "window {until} must run a run limit past {fin}");
    assert!(exp >= until, "the row outlives its worker window");
    // with the window open (stretched here to the type's real scale) the erase blocks
    sqlx::query("UPDATE noo_ops SET worker_may_run_until = now() + interval '60 seconds'").execute(&db).await.unwrap();
    let err = crate::routes::users::erase_account(&db, "alice", false, false).await.unwrap_err();
    assert!(retry_after(&err).is_some(), "{err}");
}

// ───────────────────── graph.entity_cleanup (the junk-entity cleanup) ─────────────────────

use crate::routes::knowledge::{entity_cleanup_audit_details, entity_cleanup_request, entity_cleanup_with};

fn cleanup_spec() -> &'static OpSpec {
    &api::find("graph.entity_cleanup").expect("graph.entity_cleanup is registered").spec
}

async fn audit_rows(db: &PgPool, outcome: Option<&str>) -> Vec<(String, String, String, Value)> {
    sqlx::query_as(
        "SELECT actor, severity, outcome, details FROM noo_security_audit \
         WHERE event_type = 'graph_entity_cleanup' AND ($1::text IS NULL OR outcome = $1) ORDER BY \"timestamp\", id",
    )
    .bind(outcome)
    .fetch_all(db)
    .await
    .expect("read audit rows")
}

/// What the worker answers for an applied run. The `examples` carry entity NAMES, which must
/// never reach the audit row.
fn applied_report() -> Value {
    json!({
        "status": "applied", "dry_run": false, "scanned": 1200, "junk": 3, "staged": 3, "skipped_over_cap": 0,
        "run_id": "entq-1a2b3c4d", "by_reason": {"math_symbol": 2, "bare_number": 1}, "by_type": {"parameter": 3},
        "examples": [{"name": "patient zero", "type": "parameter", "edges": 7}],
        "note": "patient zero was here",
    })
}

#[test]
fn the_entity_cleanup_type_is_registered_admin_only_and_the_others_are_not() {
    let s = cleanup_spec();
    assert_eq!(s.route, "/api/v1/graph/entity-cleanup");
    assert!(s.admin_only, "a destructive graph run is Admin only");
    assert!(s.writes_user_data, "an erase waits for a live cleanup, so its audit row is not lost to an abort");
    assert!(!s.exclusive, "joining a live dry run would hand an apply request somebody's preview");
    assert_eq!(s.default_wait_secs, 3);
    assert!((s.timeout)() >= Duration::from_secs(600), "a scan and up to 5,000 staged deletes take minutes");
    assert_eq!(s.wait_key(), "NOO_OPS_WAIT_GRAPH_ENTITY_CLEANUP_SECS");
    for t in api::TYPES {
        assert_eq!(t.spec.admin_only, t.spec.name == "graph.entity_cleanup", "{}", t.spec.name);
    }
    // the per-type wait setting is registered (the settings page lists every op type's)
    assert!(crate::routes::settings::string_setting_default("NOO_OPS_WAIT_GRAPH_ENTITY_CLEANUP_SECS").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_an_admin_can_start_the_cleanup_an_operator_a_user_and_an_agent_token_are_refused() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_gate").await else { return };
    let root = account(&db, "root", Role::Admin).await;
    let op = account(&db, "olive", Role::Operator).await;
    let bob = account(&db, "bob", Role::User).await;
    let ran = Arc::new(AtomicBool::new(false));
    for (who, label) in [(&op, "operator"), (&bob, "user"), (&delegated(&root, "run-9"), "agent token acting for an admin")] {
        let r = ran.clone();
        let (st, body) = serve_as(&db, who, cleanup_spec(), json!({"apply": true}), None, runner(move |_, _| async move {
            r.store(true, Ordering::SeqCst);
            Outcome::done(200, json!({}))
        }))
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{label}: {body}");
    }
    // a credential with no account (a controller service) is refused as well
    let none: Option<axum::Extension<RequesterCtx>> = None;
    let r = ran.clone();
    let (st, _) = {
        let (st, axum::Json(b)) = api::serve(&db, &none, cleanup_spec(), no_refusal, json!({}), Some(0), StatusCode::CONFLICT,
            runner(move |_, _| async move { r.store(true, Ordering::SeqCst); Outcome::done(200, json!({})) })).await;
        (st, b)
    };
    assert_eq!(st, StatusCode::FORBIDDEN);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!ran.load(Ordering::SeqCst), "a refused start runs nothing");
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM noo_ops WHERE op_type = 'graph.entity_cleanup'").fetch_one(&db).await.unwrap();
    assert_eq!(n, 0, "a refused start leaves no op row");
    // an Admin starts it, and the op finishes
    let (st, body) = serve_as(&db, &root, cleanup_spec(), json!({}), Some(5), runner(|_, _| async move {
        Outcome::done(200, json!({"status": "dry-run"}))
    }))
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "dry-run");
}

#[test]
fn the_cleanup_request_carries_three_fields_and_nothing_the_caller_names() {
    let (apply, req) = entity_cleanup_request(&json!({})).unwrap();
    assert!(!apply, "absent apply is a dry run");
    assert_eq!(req, json!({"apply": false, "examples": 20, "max_delete": 5000}));
    let (apply, req) = entity_cleanup_request(&json!({
        "apply": true, "examples": 5, "max_delete": 10,
        "engine": "x", "dsn": "postgresql://evil", "restrict_to": ["1"], "_requester": {"role": "admin"},
    }))
    .unwrap();
    assert!(apply);
    assert_eq!(req, json!({"apply": true, "examples": 5, "max_delete": 10}));
    for bad in [json!({"apply": "true"}), json!({"apply": 1}), json!({"examples": 201}), json!({"examples": -1}),
                json!({"max_delete": 0}), json!({"max_delete": 5001}), json!({"max_delete": "9"}), json!({"examples": 2.5})] {
        assert!(entity_cleanup_request(&bad).is_err(), "{bad}");
    }
}

#[test]
fn the_audit_details_hold_counts_and_the_run_id_and_never_an_entity_name() {
    let d = entity_cleanup_audit_details(&json!({"max_delete": 100}), Some(&applied_report()), "apply");
    assert_eq!(d["run_id"], "entq-1a2b3c4d");
    assert_eq!((d["junk"].as_i64(), d["staged"].as_i64(), d["scanned"].as_i64()), (Some(3), Some(3), Some(1200)));
    assert_eq!(d["by_reason"]["math_symbol"], 2);
    assert_eq!(d["max_delete"], 100);
    let text = d.to_string();
    assert!(!text.contains("patient zero") && !text.contains("examples") && !text.contains("note"), "{text}");
    // a hostile or buggy report cannot smuggle a string through a numeric slot or the run id
    let evil = json!({"junk": "patient zero", "run_id": "patient zero", "by_type": {"x": "patient zero"}, "staged": 1});
    let t = entity_cleanup_audit_details(&json!({}), Some(&evil), "apply").to_string();
    assert!(!t.contains("patient zero"), "{t}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dry_run_asks_the_worker_for_a_preview_and_writes_no_audit_row() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_dry").await else { return };
    let root = account(&db, "root", Role::Admin).await;
    let sent = Arc::new(std::sync::Mutex::new(None));
    let s2 = sent.clone();
    let out = entity_cleanup_with(&db, &ctx_of(&root), json!({}), move |b| async move {
        *s2.lock().unwrap() = Some(b);
        Ok(json!({"success": true, "data": {"status": "dry-run", "dry_run": true, "junk": 3, "examples": []}}))
    })
    .await;
    assert!(out.failure.is_none() && out.http_status == 200, "{out:?}");
    let b = sent.lock().unwrap().clone().expect("the worker was asked");
    assert_eq!(b["apply"], false, "absent apply is a dry run");
    assert_eq!(b["_requester"]["role"], "admin");
    assert!(audit_rows(&db, None).await.is_empty(), "a dry run is a read: no audit row");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_run_writes_a_started_row_before_and_a_result_row_after_neither_naming_an_entity() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_apply").await else { return };
    let root = account(&db, "root", Role::Admin).await;
    let db2 = db.clone();
    let out = entity_cleanup_with(&db, &ctx_of(&root), json!({"apply": true, "max_delete": 100}), move |_| async move {
        // the started row is already there when the worker is asked: audit first, then delete
        let started = audit_rows(&db2, Some("started")).await;
        assert_eq!(started.len(), 1, "the intent row lands BEFORE the worker is asked");
        Ok(json!({"success": true, "data": applied_report()}))
    })
    .await;
    assert!(out.failure.is_none(), "{out:?}");
    let rows = audit_rows(&db, None).await;
    assert_eq!(rows.iter().map(|r| r.2.as_str()).collect::<Vec<_>>(), vec!["started", "ok"]);
    for (actor, _, _, details) in &rows {
        assert_eq!(actor, "root");
        assert!(!details.to_string().contains("patient zero"), "no entity name in the audit: {details}");
    }
    let done = &rows[1].3;
    assert_eq!(done["run_id"], "entq-1a2b3c4d");
    assert_eq!(done["staged"], 3);
    assert_eq!(done["max_delete"], 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_applied_run_that_cannot_be_audited_deletes_nothing() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_unaudited").await else { return };
    let root = account(&db, "root", Role::Admin).await;
    sqlx::raw_sql("DROP TABLE noo_security_audit CASCADE").execute(&db).await.expect("drop audit table");
    let asked = Arc::new(AtomicBool::new(false));
    let a2 = asked.clone();
    let out = entity_cleanup_with(&db, &ctx_of(&root), json!({"apply": true}), move |_| async move {
        a2.store(true, Ordering::SeqCst);
        Ok(json!({"success": true, "data": applied_report()}))
    })
    .await;
    assert_eq!(out.http_status, 503, "{out:?}");
    assert!(out.failure.is_some());
    assert!(!asked.load(Ordering::SeqCst), "the worker is never asked when the audit row cannot land");
    // ...but a dry run needs no audit and still works
    let dry = entity_cleanup_with(&db, &ctx_of(&root), json!({}), |_| async move {
        Ok(json!({"data": {"status": "dry-run", "junk": 0}}))
    })
    .await;
    assert!(dry.failure.is_none(), "{dry:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_is_said_plainly_when_prune_holds_the_lock_or_a_recluster_is_running() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_busy").await else { return };
    let root = account(&db, "root", Role::Admin).await;
    // the worker reports graph prune's advisory lock held
    let out = entity_cleanup_with(&db, &ctx_of(&root), json!({"apply": true}), |_| async move {
        Ok(json!({"data": {"status": "busy", "error": "busy: graph prune (or another cleanup) holds the lock right now; nothing was changed"}}))
    })
    .await;
    assert_eq!(out.http_status, 409, "{out:?}");
    assert!(out.failure.as_deref().unwrap_or("").starts_with("busy"), "{out:?}");
    assert_eq!(audit_rows(&db, Some("busy")).await.len(), 1, "a busy refusal is recorded");
    // a live recluster op: refused before the worker is asked or anything is audited as started
    insert_op(&db, "root", "graph.recluster", "running").await;
    let asked = Arc::new(AtomicBool::new(false));
    let a2 = asked.clone();
    let before = audit_rows(&db, None).await.len();
    let out = entity_cleanup_with(&db, &ctx_of(&root), json!({"apply": true}), move |_| async move {
        a2.store(true, Ordering::SeqCst);
        Ok(json!({"data": applied_report()}))
    })
    .await;
    assert_eq!(out.http_status, 409);
    assert!(out.failure.as_deref().unwrap_or("").contains("recluster"), "{out:?}");
    assert!(!asked.load(Ordering::SeqCst));
    assert_eq!(audit_rows(&db, None).await.len(), before);
    // a dry run is harmless while a recluster runs
    let dry = entity_cleanup_with(&db, &ctx_of(&root), json!({}), |_| async move {
        Ok(json!({"data": {"status": "dry-run", "junk": 1}}))
    })
    .await;
    assert!(dry.failure.is_none(), "{dry:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_error_fails_the_op_and_is_audited_without_its_text() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_error").await else { return };
    let root = account(&db, "root", Role::Admin).await;
    let out = entity_cleanup_with(&db, &ctx_of(&root), json!({"apply": true}), |_| async move {
        Ok(json!({"data": {"error": "this trellion build has no entity cleanup (trellion.live.junk_entity_cleanup); upgrade the trellion image, then retry"}}))
    })
    .await;
    assert!(out.failure.as_deref().unwrap_or("").contains("upgrade"), "{out:?}");
    let failed = audit_rows(&db, Some("failed")).await;
    assert_eq!(failed.len(), 1);
    assert!(failed[0].3.get("error").is_none(), "the worker's error text stays out of the audit row");
}

#[test]
fn the_audit_intent_row_precedes_the_worker_call_in_the_source() {
    let src = include_str!("../routes/knowledge.rs");
    let start = src.find("pub(crate) async fn entity_cleanup_run").expect("entity_cleanup_run");
    let b = &src[start..];
    let b = &b[..b.find("\n}\n").unwrap()];
    let required = b.find("audit_event_required(").expect("an applied run is audited through audit_event_required");
    let worker = b.find("ask_worker(").expect("asks the worker");
    assert!(required < worker, "audit first, then delete");
    assert!(b.find("graph.recluster").unwrap() < required, "the busy check precedes the intent row");
}

// ───────────────────── review round: exchanged tokens, restore, the staged-names gate ─────────────────────

/// An identity-exchange token: `act.sub = key:<consumer>`, role = min(subject, issuer).
fn exchanged(base: &RequesterCtx, consumer: &str) -> RequesterCtx {
    RequesterCtx {
        harness: Some(format!("mcp-external:{consumer}")),
        act: Some(crate::auth::Actor { sub: format!("key:{consumer}"), iss_user: Some("root".into()), task: None }),
        ..base.clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admin_role_exchange_token_cannot_start_the_cleanup_and_the_worker_actor_still_cannot() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_exchange").await else { return };
    let root = account(&db, "root", Role::Admin).await;
    let ran = Arc::new(AtomicBool::new(false));
    for (who, label) in [(exchanged(&root, "x"), "key:x exchange token (Admin role)"), (delegated(&root, "run-3"), "worker-delegated token")] {
        assert_eq!(who.role, Role::Admin);
        let r = ran.clone();
        let (st, body) = serve_as(&db, &who, cleanup_spec(), json!({"apply": true}), None, runner(move |_, _| async move {
            r.store(true, Ordering::SeqCst);
            Outcome::done(200, json!({}))
        }))
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{label}: {body}");
        assert!(body["error"].as_str().unwrap_or("").contains("delegated or exchanged credential"), "{label}: {body}");
    }
    // the shared core refuses it too (the op path is not the only way in)
    let out = entity_cleanup_with(&db, &ctx_of(&exchanged(&root, "x")), json!({"apply": true}), |_| async move {
        panic!("the worker must not be asked");
        #[allow(unreachable_code)]
        Ok(json!({}))
    })
    .await;
    assert_eq!(out.http_status, 403, "{out:?}");
    assert!(!ran.load(Ordering::SeqCst));
    // the person's own Admin credential still works
    let (st, _) = serve_as(&db, &root, cleanup_spec(), json!({}), Some(5), runner(|_, _| async move { Outcome::done(200, json!({})) })).await;
    assert_eq!(st, StatusCode::OK);
}

#[test]
fn the_audit_keys_of_by_type_are_allow_listed_and_the_rest_fold_into_other() {
    let report = json!({"by_type": {
        "parameter": 2, "Person_Name": 1,
        "patient zero": 4, "x-ray": 1, "d3": 1, "": 1, "a_very_long_type_name_that_is_over_32_chars": 3,
    }, "by_reason": {"math_symbol": 5, "weird reason!": 2}});
    let d = entity_cleanup_audit_details(&json!({}), Some(&report), "apply");
    assert_eq!(d["by_type"], json!({"parameter": 2, "Person_Name": 1, "other": 10}));
    assert_eq!(d["by_reason"], json!({"math_symbol": 5, "other": 2}));
    let t = d.to_string();
    for leak in ["patient zero", "x-ray", "d3", "very_long"] {
        assert!(!t.contains(leak), "{leak} leaked into {t}");
    }
}

#[test]
fn the_staged_names_listing_is_operator_and_up_and_restore_by_run_is_too() {
    use crate::routes::knowledge::prune_operator_gate;
    let mk = |role, scopes: &[&str]| RequesterCtx { sub: "u".into(), scopes: scopes.iter().map(|s| s.to_string()).collect(), role, harness: None, act: None };
    let user = mk(Role::User, &["read"]);
    let op = mk(Role::Operator, &["read", "write"]);
    let admin = mk(Role::Admin, &["read", "write", "admin"]);
    assert!(prune_operator_gate(&ctx_of(&user)).is_err(), "a User must not list staged entity names");
    assert!(prune_operator_gate(&ctx_of(&op)).is_ok());
    assert!(prune_operator_gate(&ctx_of(&admin)).is_ok());
    assert!(prune_operator_gate(&None).is_ok(), "a controller service has no account and is admitted to prune/restore too");
    let err = prune_operator_gate(&ctx_of(&user)).unwrap_err();
    assert_eq!(axum::response::IntoResponse::into_response(err).status(), StatusCode::FORBIDDEN);
    // the restore (POST) is closed to a User at the front door, as before; a run_id restore is the same route
    let p = "/api/v1/graph/prune/restore";
    assert!(!crate::auth::requester_allows(&user, &axum::http::Method::POST, p));
    assert!(crate::auth::requester_allows(&op, &axum::http::Method::POST, p));
    // and the handler really calls the gate before reading anything
    let src = include_str!("../routes/knowledge.rs");
    let start = src.find("async fn graph_prune_staged(").unwrap();
    let body = &src[start..start + 900];
    assert!(body.contains("prune_operator_gate(&ctx)?;") && body.find("prune_operator_gate").unwrap() < body.find(".graph_prune_staged(").unwrap());
}

async fn prune_tables(db: &PgPool) {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS entities (entity_id uuid PRIMARY KEY, canonical_name text NOT NULL, type text NOT NULL, \
            aliases_json jsonb, created_at timestamptz NOT NULL DEFAULT now(), user_id text); \
         ALTER TABLE entities ADD COLUMN IF NOT EXISTS user_id text; \
         CREATE UNIQUE INDEX IF NOT EXISTS entities_name_type_idx ON entities (canonical_name, type); \
         CREATE TABLE IF NOT EXISTS edges (edge_id uuid PRIMARY KEY, src_entity_id uuid NOT NULL REFERENCES entities ON DELETE CASCADE, \
            rel_type text NOT NULL, dst_entity_id uuid NOT NULL REFERENCES entities ON DELETE CASCADE, evidence_json jsonb, \
            created_at timestamptz NOT NULL DEFAULT now(), confidence float8, classified_at timestamptz, classifier_model text); \
         CREATE TABLE IF NOT EXISTS mentions (mention_id uuid PRIMARY KEY, entity_id uuid NOT NULL REFERENCES entities ON DELETE CASCADE, \
            page_id uuid NOT NULL, span_json jsonb, quote text); \
         CREATE TABLE IF NOT EXISTS graph_prune_staging (staging_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), entity_id uuid NOT NULL, \
            canonical_name text NOT NULL, entity_type text NOT NULL, reason text NOT NULL, payload jsonb NOT NULL, \
            staged_at timestamptz NOT NULL DEFAULT now(), restored_at timestamptz, run_id text);",
    )
    .execute(db)
    .await
    .expect("prune tables");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_junk_entity_payload_with_cluster_members_restores_by_run_id_edges_between_junk_entities_included() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_restore").await else { return };
    prune_tables(&db).await;
    let (real, a, b) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    for (id, name, ty) in [(real, "jepa", "concept"), (a, "a", "variable"), (b, "x_t", "variable")] {
        sqlx::query("INSERT INTO entities (entity_id, canonical_name, type) VALUES ($1, $2, $3)").bind(id).bind(name).bind(ty).execute(&db).await.unwrap();
    }
    let page = Uuid::new_v4();
    let (e_ra, e_ab, m_a) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    for (e, s, d) in [(e_ra, real, a), (e_ab, a, b)] {
        sqlx::query("INSERT INTO edges (edge_id, src_entity_id, rel_type, dst_entity_id, evidence_json) VALUES ($1,$2,'RELATED_TO',$3,'{}')").bind(e).bind(s).bind(d).execute(&db).await.unwrap();
    }
    sqlx::query("INSERT INTO mentions (mention_id, entity_id, page_id, quote) VALUES ($1,$2,$3,'q')").bind(m_a).bind(a).bind(page).execute(&db).await.unwrap();
    // exactly what trellion.live.junk_entity_cleanup._snapshot writes: the prune payload plus
    // `cluster_members` and `quality_rule`. `a` is staged first, so it alone holds the a<->x_t edge.
    let payload_a = json!({
        "entity": {"entity_id": a.to_string(), "canonical_name": "a", "type": "variable", "aliases_json": null, "created_at": "2026-10-01T00:00:00+00:00"},
        "edges": [
            {"edge_id": e_ra.to_string(), "src_entity_id": real.to_string(), "rel_type": "RELATED_TO", "dst_entity_id": a.to_string(), "evidence_json": {}, "created_at": "2026-10-01T00:00:00+00:00", "confidence": null, "classified_at": null, "classifier_model": null},
            {"edge_id": e_ab.to_string(), "src_entity_id": a.to_string(), "rel_type": "RELATED_TO", "dst_entity_id": b.to_string(), "evidence_json": {}, "created_at": "2026-10-01T00:00:00+00:00", "confidence": null, "classified_at": null, "classifier_model": null},
        ],
        "mentions": [{"mention_id": m_a.to_string(), "entity_id": a.to_string(), "page_id": page.to_string(), "span_json": null, "quote": "q"}],
        "cluster_members": [{"cluster_id": Uuid::new_v4().to_string(), "membership_score": 0.4}],
        "quality_rule": "single_letter", "user_id": null,
    });
    let payload_b = json!({
        "entity": {"entity_id": b.to_string(), "canonical_name": "x_t", "type": "variable", "aliases_json": null, "created_at": "2026-10-01T00:00:00+00:00"},
        "edges": [], "mentions": [], "cluster_members": [], "quality_rule": "math_symbol", "user_id": null,
    });
    for (id, name, p) in [(a, "a", &payload_a), (b, "x_t", &payload_b)] {
        sqlx::query("INSERT INTO graph_prune_staging (entity_id, canonical_name, entity_type, reason, payload, run_id) VALUES ($1,$2,'variable','junk_entity',$3,'entq-test0001')")
            .bind(id).bind(name).bind(p).execute(&db).await.unwrap();
        sqlx::query("DELETE FROM entities WHERE entity_id = $1").bind(id).execute(&db).await.unwrap();
    }
    let n = |sql: &'static str| { let db = db.clone(); async move { sqlx::query_scalar::<_, i64>(sql).fetch_one(&db).await.unwrap() } };
    assert_eq!(n("SELECT COUNT(*) FROM edges").await, 0, "the cascade took every edge that touched the junk");

    let out = crate::memory::provider::prune_restore_run(&db, "entq-test0001", 500).await;
    assert_eq!((out["status"].as_str(), out["restored"].as_i64(), out["remaining"].as_i64()), (Some("ok"), Some(2), Some(0)), "{out}");
    assert_eq!(n("SELECT COUNT(*) FROM entities WHERE canonical_name IN ('a','x_t')").await, 2);
    assert_eq!(n("SELECT COUNT(*) FROM edges").await, 2, "BOTH edges are back, the one between the two junk entities too");
    assert_eq!(n("SELECT COUNT(*) FROM mentions").await, 1);
    assert_eq!(n("SELECT COUNT(*) FROM graph_prune_staging WHERE restored_at IS NULL").await, 0);
    // idempotent: nothing left to restore
    let again = crate::memory::provider::prune_restore_run(&db, "entq-test0001", 500).await;
    assert_eq!((again["restored"].as_i64(), again["remaining"].as_i64()), (Some(0), Some(0)), "{again}");
    // another run's rows are not touched
    let other = crate::memory::provider::prune_restore_run(&db, "entq-nope", 500).await;
    assert_eq!(other["restored"], 0);
}

/// Stage one entity (and delete the live row, as a prune does) with the given owner stamped in the payload
/// (`None` = a shared row: an explicit `"user_id": null`, as both prune writers record it).
/// `seq` fixes the staging_id, so the restore walks the rows in a known order (the edge holder first).
async fn stage_owned(db: &PgPool, run: &str, seq: u8, id: Uuid, name: &str, owner: Option<&str>, edges: Value) {
    let payload = json!({
        "entity": {"entity_id": id.to_string(), "canonical_name": name, "type": "variable", "aliases_json": null, "created_at": "2026-10-01T00:00:00+00:00"},
        "edges": edges, "mentions": [], "cluster_members": [], "quality_rule": "single_letter",
        "user_id": owner,
    });
    sqlx::query("INSERT INTO graph_prune_staging (entity_id, canonical_name, entity_type, reason, payload, run_id) VALUES ($1,$2,'variable','junk_entity',$3,$4)")
        .bind(id).bind(name).bind(&payload).bind(run).bind(Uuid::from_u128(seq as u128)).execute(db).await.unwrap();
    sqlx::query("DELETE FROM entities WHERE entity_id = $1").bind(id).execute(db).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_restore_keeps_the_owner_and_the_edge_between_two_owned_entities_and_never_brings_back_an_erased_users_row() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_restore_owners").await else { return };
    prune_tables(&db).await;
    account(&db, "alice", Role::User).await;
    // `ghost` has no account: erased.
    let (a, b, c, d, g) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    // live endpoints must exist for the FK while the edges are created; stage after.
    for (id, name) in [(a, "oa"), (b, "ob"), (c, "unowned"), (d, "ghost_other"), (g, "ghost_row")] {
        sqlx::query("INSERT INTO entities (entity_id, canonical_name, type) VALUES ($1, $2, 'variable')").bind(id).bind(name).execute(&db).await.unwrap();
    }
    let e_ab = Uuid::new_v4();
    let edge = |e: Uuid, s: Uuid, t: Uuid| json!({"edge_id": e.to_string(), "src_entity_id": s.to_string(), "rel_type": "RELATED_TO", "dst_entity_id": t.to_string(), "evidence_json": {}, "created_at": "2026-10-01T00:00:00+00:00", "confidence": null, "classified_at": null, "classifier_model": null});
    // two alice-owned entities; only the first staged holds the edge between them
    stage_owned(&db, "restown-1", 1, a, "oa", Some("alice"), json!([edge(e_ab, a, b)])).await;
    stage_owned(&db, "restown-1", 2, b, "ob", Some("alice"), json!([])).await;
    // mixed batch: unowned, and one owned by an erased user
    stage_owned(&db, "restown-2", 3, c, "unowned", None, json!([])).await;
    stage_owned(&db, "restown-2", 4, g, "ghost_row", Some("ghost"), json!([])).await;
    let owner_of = |id: Uuid| { let db = db.clone(); async move { sqlx::query_scalar::<_, Option<String>>("SELECT user_id FROM entities WHERE entity_id = $1").bind(id).fetch_optional(&db).await.unwrap() } };

    let out = crate::memory::provider::prune_restore_run(&db, "restown-1", 500).await;
    assert_eq!((out["restored"].as_i64(), out["remaining"].as_i64()), (Some(2), Some(0)), "{out}");
    assert_eq!(owner_of(a).await, Some(Some("alice".to_string())), "owner kept, never NULL");
    assert_eq!(owner_of(b).await, Some(Some("alice".to_string())), "owner kept, never NULL");
    let edges: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges WHERE edge_id = $1").bind(e_ab).fetch_one(&db).await.unwrap();
    assert_eq!(edges, 1, "the edge between the two owned entities is back");

    let out = crate::memory::provider::prune_restore_run(&db, "restown-2", 500).await;
    assert_eq!((out["restored"].as_i64(), out["not_restored"].as_i64()), (Some(1), Some(1)), "{out}");
    assert_eq!(owner_of(c).await, Some(None), "the unowned row is back, unowned");
    assert_eq!(owner_of(g).await, None, "the erased user's row is neither pre-inserted nor restored");
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM graph_prune_staging WHERE run_id = 'restown-2' AND restored_at IS NULL").fetch_one(&db).await.unwrap();
    assert_eq!(left, 1, "the erased user's staged row is left for the erase's own purge");
}

/// A restore the database refuses answers with a fixed message, never the database's own text
/// (which can quote somebody's staged values). An edge whose endpoint entity is gone says so in
/// words an operator can act on; the raw FK error stays in the log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_restore_names_no_database_text() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("restore_error_body").await else { return };
    prune_tables(&db).await;
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS graph_edge_prune_staging (staging_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), \
            edge_id uuid NOT NULL, src_entity_id uuid NOT NULL, rel_type text NOT NULL, dst_entity_id uuid NOT NULL, \
            confidence double precision, evidence_json jsonb, reason text NOT NULL, run_id text, user_id text, \
            staged_at timestamptz NOT NULL DEFAULT now(), restored_at timestamptz); \
         ALTER TABLE edges ADD COLUMN IF NOT EXISTS user_id text",
    ).execute(&db).await.unwrap();
    // both endpoints are gone: the edge cannot come back before they do
    let sid: String = sqlx::query_scalar(
        "INSERT INTO graph_edge_prune_staging (edge_id, src_entity_id, rel_type, dst_entity_id, reason) \
         VALUES (gen_random_uuid(), gen_random_uuid(), 'RELATED_TO', gen_random_uuid(), 'low') RETURNING staging_id::text",
    ).fetch_one(&db).await.unwrap();
    let r = crate::memory::provider::prune_restore_edge(&db, &sid).await;
    assert_eq!((r["status"].as_str(), r["error"].as_str()),
               (Some("error"), Some("an endpoint of this edge is not present; restore that entity first")), "{r}");
    let staged: bool = sqlx::query_scalar("SELECT restored_at IS NULL FROM graph_edge_prune_staging WHERE staging_id = $1::uuid")
        .bind(&sid).fetch_one(&db).await.unwrap();
    assert!(staged, "a failed restore leaves the edge staged");
    // any other refusal: the fixed message, no SQL in it
    sqlx::raw_sql("ALTER TABLE edges RENAME TO edges_aside").execute(&db).await.unwrap();
    let r = crate::memory::provider::prune_restore_edge(&db, &sid).await;
    sqlx::raw_sql("ALTER TABLE edges_aside RENAME TO edges").execute(&db).await.unwrap();
    assert_eq!(r["error"].as_str(), Some("the restore could not complete; see the gateway log"), "{r}");
}

/// A staged row whose payload never recorded its owner (what trellion's entity cleanup wrote
/// before it carried `user_id`) is refused by BOTH restore paths: guessing "shared" would turn a
/// private entity into one everybody sees. Nothing is pre-inserted and the row stays staged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_staged_row_that_does_not_record_its_owner_is_never_restored_as_shared() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_restore_ownerless").await else { return };
    prune_tables(&db).await;
    account(&db, "alice", Role::User).await;
    let (k, s) = (Uuid::new_v4(), Uuid::new_v4());
    for (id, name) in [(k, "keyless"), (s, "shared")] {
        sqlx::query("INSERT INTO entities (entity_id, canonical_name, type, user_id) VALUES ($1, $2, 'variable', 'alice')").bind(id).bind(name).execute(&db).await.unwrap();
    }
    stage_owned(&db, "restown-3", 5, s, "shared", None, json!([])).await;
    // the keyless shape: no `user_id` key at all
    let keyless = json!({
        "entity": {"entity_id": k.to_string(), "canonical_name": "keyless", "type": "variable", "aliases_json": null, "created_at": "2026-10-01T00:00:00+00:00"},
        "edges": [], "mentions": [], "cluster_members": [],
    });
    let sid: String = sqlx::query_scalar("INSERT INTO graph_prune_staging (entity_id, canonical_name, entity_type, reason, payload, run_id, staging_id) VALUES ($1,'keyless','variable','junk_entity',$2,'restown-3',$3) RETURNING staging_id::text")
        .bind(k).bind(&keyless).bind(Uuid::from_u128(6)).fetch_one(&db).await.unwrap();
    sqlx::query("DELETE FROM entities WHERE entity_id = $1").bind(k).execute(&db).await.unwrap();
    let live = |id: Uuid| { let db = db.clone(); async move { sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM entities WHERE entity_id = $1").bind(id).fetch_one(&db).await.unwrap() } };

    let out = crate::memory::provider::prune_restore_run(&db, "restown-3", 500).await;
    assert_eq!((out["restored"].as_i64(), out["not_restored"].as_i64(), out["remaining"].as_i64()), (Some(1), Some(1), Some(1)), "{out}");
    assert_eq!(live(k).await, 0, "the keyless row is neither pre-inserted nor restored");
    assert_eq!(live(s).await, 1, "an explicit null owner is a shared row and comes back");
    let r = crate::memory::provider::prune_restore_entity(&db, &sid).await;
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("this row does not record its owner; it is not restored")), "{r}");
    assert_eq!(live(k).await, 0);
    let staged: bool = sqlx::query_scalar("SELECT restored_at IS NULL FROM graph_prune_staging WHERE staging_id = $1::uuid").bind(&sid).fetch_one(&db).await.unwrap();
    assert!(staged, "a refused restore leaves the row staged");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_the_mcp_operator_door_the_cleanup_previews_and_only_a_persons_own_credential_applies() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("cleanup_human_apply").await else { return };
    let root = account(&db, "root", Role::Admin).await;
    // what mcp_local.rs mints: Role::Admin, harness `operator:<consumer>`, no `act`
    let door = RequesterCtx { harness: Some("operator:x".into()), act: None, ..root.clone() };
    let user_door = RequesterCtx { harness: Some("mcp-external:x".into()), act: None, ..root.clone() };
    let node = RequesterCtx { harness: Some("node:host3".into()), act: None, ..root.clone() };
    assert!(cleanup_spec().human_only_apply, "the type declares it; nothing special-cases the name");
    for t in api::TYPES {
        assert_eq!(t.spec.human_only_apply, t.spec.name == "graph.entity_cleanup", "{}", t.spec.name);
    }
    for who in [&door, &user_door, &node] {
        // a dry run is allowed
        let (st, body) = serve_as(&db, who, cleanup_spec(), json!({}), Some(5), runner(|_, _| async move { Outcome::done(200, json!({"status": "dry-run"})) })).await;
        assert_eq!(st, StatusCode::OK, "{:?}: {body}", who.harness);
        // an apply is refused with 403 and the message names the command
        let ran = Arc::new(AtomicBool::new(false));
        let r = ran.clone();
        let (st, body) = serve_as(&db, who, cleanup_spec(), json!({"apply": true}), None, runner(move |_, _| async move {
            r.store(true, Ordering::SeqCst);
            Outcome::done(200, json!({}))
        }))
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{:?}: {body}", who.harness);
        assert!(body["error"].as_str().unwrap_or("").contains("noo graph entity-cleanup --apply"), "{body}");
        assert!(!ran.load(Ordering::SeqCst));
        // the shared core refuses it too, before the worker is asked or anything is audited
        let out = entity_cleanup_with(&db, &ctx_of(who), json!({"apply": true}), |_| async move {
            panic!("the worker must not be asked");
            #[allow(unreachable_code)]
            Ok(json!({}))
        })
        .await;
        assert_eq!(out.http_status, 403, "{out:?}");
    }
    assert!(audit_rows(&db, None).await.is_empty(), "a refused harness apply wrote nothing");
    // the same person's DIRECT Admin credential can apply
    let (st, body) = serve_as(&db, &root, cleanup_spec(), json!({"apply": true}), Some(5), runner(|_, _| async move {
        Outcome::done(200, json!({"status": "applied"}))
    }))
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let out = entity_cleanup_with(&db, &ctx_of(&root), json!({"apply": true}), |_| async move {
        Ok(json!({"data": applied_report()}))
    })
    .await;
    assert!(out.failure.is_none(), "{out:?}");
}
