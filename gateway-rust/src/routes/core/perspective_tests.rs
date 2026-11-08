// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! "View as" (i538 P1) against a REAL migrated schema: start, switch, Back
//! to me, the middleware's liveness check, the refresh carrying a
//! perspective, the cap, and the audit rows.
//!
//! The harness is `ops::tests`' (a scratch database per test, the real
//! `mesh_migrate::apply`, gated on `NOO_BROKER_TEST_DSN`: without it the DB
//! tests print SKIPPED and pass; CI's `sqlx-drift` job runs them). The flows
//! under test are the functions the handlers call (`perspective::begin`,
//! `switch`, `back_to_me`, `admit`, and this module's `rotate_refresh`), so
//! no gateway is needed. `me_answer` and the view are pure and run anywhere.
//!
//! Each test names the single-check mutant of the design's §8 it turns red.

#![cfg(test)]

use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

use super::{me_answer, rotate_refresh, Rotation, UserRecord};
use crate::auth::{Claims, Role};
use crate::auth_refresh;
use crate::ops::tests::{scratch, DB_LOCK};
use crate::perspective::{self, Perspective, PrsClaim, Refusal, SessionRow, Started, Switched};

const SECRET: &str = "perspective-test-signing-key-not-a-secret-0001";

async fn person(db: &PgPool, name: &str, role: Role) {
    sqlx::query(
        "INSERT INTO noo_users (username, hashed_password, role, scopes, disabled) \
         VALUES ($1, 'x', $2, '[\"read\"]'::jsonb, false)",
    )
    .bind(name)
    .bind(role.as_str())
    .execute(db)
    .await
    .expect("insert user");
}

/// A live session (refresh row) for `name`: its raw cookie and the row.
async fn session(db: &PgPool, name: &str) -> (String, SessionRow) {
    let raw = auth_refresh::generate_raw_token();
    auth_refresh::store_token(db, name, &raw, chrono::Utc::now() + chrono::TimeDelta::days(30), None, None, None, None)
        .await
        .expect("store token");
    let row = reread(db, &raw, name).await;
    (raw, row)
}

async fn reread(db: &PgPool, raw: &str, name: &str) -> SessionRow {
    perspective::session_row(db, raw, name).await.expect("read the session").expect("a live session")
}

fn claims(name: &str, role: Role, prs: Option<PrsClaim>) -> Claims {
    Claims {
        sub: name.to_string(),
        exp: 4_102_444_800,
        role: role.as_str().to_string(),
        scopes: role.legacy_scopes().iter().map(|s| s.to_string()).collect(),
        harness: None,
        conv: None,
        act: None,
        cnf: None,
        prs,
    }
}

fn dims(v: Value) -> Perspective {
    serde_json::from_value(v).expect("dims")
}

/// The claims of a JWT, read without verifying (the test minted it).
fn payload(token: &str) -> Value {
    use base64::Engine as _;
    let mid = token.split('.').nth(1).expect("a JWT");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(mid).expect("base64url");
    serde_json::from_slice(&raw).expect("json claims")
}

async fn is_live(db: &PgPool, id: &str) -> bool {
    sqlx::query_scalar("SELECT ended_at IS NULL FROM noo_perspectives WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(db)
        .await
        .expect("read the perspective")
}

async fn end_reason(db: &PgPool, id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT end_reason FROM noo_perspectives WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(db)
        .await
        .expect("read the perspective")
}

/// An operator `name` with a session in a `user` view.
async fn user_view(db: &PgPool, name: &str) -> (String, Started) {
    person(db, name, Role::Operator).await;
    let (raw, s) = session(db, name).await;
    let started = perspective::begin(db, &claims(name, Role::Operator, None), &s, &dims(json!({"role_cap": "user"})))
        .await
        .expect("an operator starts a user view");
    (raw, started)
}

fn signing_key() {
    unsafe { std::env::set_var("NOO_JWT_SECRET", SECRET) };
}

/// M4 (barrier 2): a cap at or above the LIVE role is refused as a
/// widening, not quietly accepted as "no change".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_refuses_a_wider_role() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_wider").await else { return };
    person(&db, "olive", Role::Operator).await;
    let (_raw, s) = session(&db, "olive").await;
    let c = claims("olive", Role::Operator, None);
    for cap in ["operator", "admin"] {
        let r = perspective::begin(&db, &c, &s, &dims(json!({"role_cap": cap})))
            .await
            .expect_err("a cap at or above the live role");
        assert_eq!((r.status, r.detail), (StatusCode::UNPROCESSABLE_ENTITY, perspective::CANNOT_WIDEN), "cap {cap}");
    }
    let ok = perspective::begin(&db, &c, &s, &dims(json!({"role_cap": "user"}))).await.expect("a lower cap starts");
    assert_eq!(ok.role, Role::User);
}

/// M5: starting needs a LIVE operator role — a user account is refused,
/// even with a token that claims more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_an_operator_starts_a_perspective() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_operator_only").await else { return };
    person(&db, "uma", Role::User).await;
    let (_raw, s) = session(&db, "uma").await;
    for token_role in [Role::User, Role::Operator] {
        let r = perspective::begin(&db, &claims("uma", token_role, None), &s, &dims(json!({"role_cap": "user"})))
            .await
            .expect_err("a user account may not start a perspective");
        assert_eq!((r.status, r.detail), (StatusCode::FORBIDDEN, perspective::NEEDS_OPERATOR), "token role {token_role:?}");
    }
    let (_raw, started) = user_view(&db, "olive").await;
    assert_eq!(started.role, Role::User, "an operator may");
}

/// M6: once a perspective has ended its token is refused (401
/// `perspective_ended`), and the middleware asks for every `prs` token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ended_perspective_token_is_refused() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_ended").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    let prs = started.claim();
    assert!(perspective::admit(&db, "olive", &prs).await.is_ok(), "a live perspective is admitted");
    let s = reread(&db, &raw, "olive").await;
    perspective::back_to_me(&db, &claims("olive", Role::User, Some(prs.clone())), &s).await.expect("back to me");
    assert_eq!(perspective::admit(&db, "olive", &prs).await, Err(Refusal::Ended));
    assert_eq!(perspective::refusal_response(Refusal::Ended).status(), StatusCode::UNAUTHORIZED);
}

/// M7: a `prs` naming another account's perspective is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_perspective_of_another_account_is_refused() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_other_account").await else { return };
    let (_raw, started) = user_view(&db, "olive").await;
    person(&db, "bob", Role::Operator).await;
    let prs = started.claim();
    assert_eq!(perspective::admit(&db, "bob", &prs).await, Err(Refusal::NotOwner));
    assert!(perspective::admit(&db, "olive", &prs).await.is_ok(), "its owner is admitted");
    let (_braw, bob_s) = session(&db, "bob").await;
    let r = perspective::back_to_me(&db, &claims("bob", Role::Operator, Some(prs.clone())), &bob_s)
        .await
        .expect_err("bob cannot end olive's perspective");
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(is_live(&db, &prs.id).await);
}

/// M8: a refresh after the row ended mints a REAL token and a clean child,
/// even when the session row still carries the stamp.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_after_end_is_real() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_refresh_after_end").await else { return };
    signing_key();
    let (raw, started) = user_view(&db, "olive").await;
    // End the row but leave the session's stamp: what a crash between the
    // two writes, or another gateway, leaves behind.
    sqlx::query("UPDATE noo_perspectives SET ended_at = now(), end_reason = 'back_to_me' WHERE id = $1::uuid")
        .bind(&started.id)
        .execute(&db)
        .await
        .expect("end the row");
    assert_eq!(reread(&db, &raw, "olive").await.perspective_id.as_deref(), Some(started.id.as_str()));
    match rotate_refresh(&db, &raw, None, None).await {
        Rotation::Rotated { access_token, new_raw, .. } => {
            let c = payload(&access_token);
            assert!(c.get("prs").is_none(), "an ended perspective must not be minted again: {c}");
            assert_eq!(c["role"], "operator");
            assert_eq!(reread(&db, &new_raw, "olive").await.perspective_id, None, "the child carries no perspective");
        }
        _ => panic!("the refresh must rotate"),
    }
}

/// M9: a refresh before the end keeps the perspective: the token is the
/// perspective token and the child row inherits it, refresh after refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_keeps_the_perspective() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_refresh_keeps").await else { return };
    signing_key();
    let (mut raw, started) = user_view(&db, "olive").await;
    for round in 0..2 {
        match rotate_refresh(&db, &raw, None, None).await {
            Rotation::Rotated { access_token, new_raw, .. } => {
                let c = payload(&access_token);
                assert_eq!(c["prs"]["id"], started.id, "round {round}: the perspective was dropped: {c}");
                assert_eq!(c["role"], "user", "round {round}");
                assert_eq!(c["scopes"], json!(["read"]), "round {round}");
                assert_eq!(
                    reread(&db, &new_raw, "olive").await.perspective_id.as_deref(),
                    Some(started.id.as_str()),
                    "round {round}: the child must inherit the perspective"
                );
                raw = new_raw;
            }
            _ => panic!("the refresh must rotate"),
        }
    }
}

/// M10: `/auth/me` answers the narrowed role and the scopes it expands to,
/// and names the perspective; without one it is unchanged.
#[test]
fn me_answers_as_the_perspective() {
    let u = UserRecord {
        username: "olive".into(),
        hashed_password: "x".into(),
        disabled: false,
        scopes: vec!["read".into(), "write".into(), "ingest".into()],
        role: Role::Operator,
    };
    let real = me_answer(&u, None);
    assert_eq!(real["role"], "operator");
    assert_eq!(real["scopes"], json!(["read", "write", "ingest"]));
    assert!(real.get("perspective").is_none());

    let prs = PrsClaim {
        id: "0f9c1d2e-0000-4000-8000-000000000001".into(),
        dims: Perspective { role_cap: Some(Role::User), ..Perspective::default() },
    };
    let seen = me_answer(&u, Some((&prs, chrono::Utc::now())));
    assert_eq!(seen["role"], "user");
    assert_eq!(seen["scopes"], json!(["read"]), "the real scopes leaked into a user view");
    assert_eq!(seen["perspective"]["id"], prs.id);
    assert_eq!(seen["perspective"]["dims"], json!({"role_cap": "user"}));

    let own = crate::test_src::own_code(include_str!("../core.rs"));
    let body = crate::test_src::fn_body(&own, "async fn auth_me(");
    assert!(body.contains("crate::perspective::admit(&state.db, &claims.sub, prs).await"));
    assert!(body.contains("Json(me_answer(&u, seen))"));
}

/// M15: a start writes `PerspectiveStarted` with the id and the dims; Back
/// to me writes `PerspectiveEnded` once, with its reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_is_audited() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_audited").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details::text FROM noo_security_audit WHERE event_type = 'perspective_started' AND actor = $1",
    )
    .bind("olive")
    .fetch_all(&db)
    .await
    .expect("read audit rows");
    assert_eq!(rows.len(), 1, "one start, one PerspectiveStarted row");
    let details: Value = serde_json::from_str(&rows[0]).expect("details json");
    assert_eq!(details["id"], started.id);
    assert_eq!(details["dims"], json!({"role_cap": "user"}));

    let s = reread(&db, &raw, "olive").await;
    let c = claims("olive", Role::User, Some(started.claim()));
    perspective::back_to_me(&db, &c, &s).await.expect("back to me");
    assert!(!perspective::end(&db, &started.id, perspective::EndReason::Logout).await.expect("end again"), "already ended");
    let ended: Vec<String> = sqlx::query_scalar(
        "SELECT outcome FROM noo_security_audit WHERE event_type = 'perspective_ended' AND actor = $1",
    )
    .bind("olive")
    .fetch_all(&db)
    .await
    .expect("read audit rows");
    assert_eq!(ended, vec!["back_to_me".to_string()], "ended exactly once");
}

/// M19: a switch is validated against the LIVE role. A cap at the live
/// role is refused even though the token's role is lower, and an operator
/// in a user view can still switch to another narrowing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn switch_cannot_widen() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_switch_widen").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    let s = reread(&db, &raw, "olive").await;
    let c = claims("olive", Role::User, Some(started.claim()));
    let r = perspective::switch(&db, &c, &s, &dims(json!({"role_cap": "operator"})))
        .await
        .expect_err("a cap at the live role is no narrowing");
    assert_eq!((r.status, r.detail), (StatusCode::UNPROCESSABLE_ENTITY, perspective::CANNOT_WIDEN));
    assert!(is_live(&db, &started.id).await, "a refused switch leaves the current perspective on");
    match perspective::switch(&db, &c, &s, &dims(json!({"role_cap": "user"}))).await.expect("a narrowing switch") {
        Switched::To(next) => {
            assert_eq!(next.role, Role::User);
            assert!(!is_live(&db, &started.id).await);
            assert_eq!(end_reason(&db, &started.id).await.as_deref(), Some("switched"));
            assert_eq!(reread(&db, &raw, "olive").await.perspective_id.as_deref(), Some(next.id.as_str()));
        }
        Switched::Back => panic!("a non-empty switch is not Back to me"),
    }
}

/// M20: Back to me works from a `user` view: it is authorized on the row,
/// never on the token's (narrowed) role.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn back_to_me_works_from_a_user_view() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_back_from_user").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    let s = reread(&db, &raw, "olive").await;
    let c = claims("olive", Role::User, Some(started.claim()));
    assert_eq!(c.resolved_role(), Role::User, "the token really is a user token");
    perspective::back_to_me(&db, &c, &s).await.expect("a user view must always be able to go back");
    assert!(!is_live(&db, &started.id).await);
    assert_eq!(end_reason(&db, &started.id).await.as_deref(), Some("back_to_me"));
    assert_eq!(reread(&db, &raw, "olive").await.perspective_id, None, "the session is real again");
}

/// M21: a switch ends the old perspective and starts the new one in ONE
/// transaction: when the session cannot be re-stamped, the old one is still
/// on and no new row exists, so there is never a moment with neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn switch_is_atomic() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_switch_atomic").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    // A second session of olive's that does NOT carry the perspective,
    // presented as if it did: the re-stamp inside the switch finds no row.
    let (_other_raw, other) = session(&db, "olive").await;
    let forged = SessionRow { id: other.id.clone(), perspective_id: Some(started.id.clone()) };
    let c = claims("olive", Role::User, Some(started.claim()));
    let r = perspective::switch(&db, &c, &forged, &dims(json!({"role_cap": "user"})))
        .await
        .expect_err("the re-stamp fails");
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert!(is_live(&db, &started.id).await, "the old perspective must survive a failed switch");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM noo_perspectives WHERE account = 'olive'")
        .fetch_one(&db)
        .await
        .expect("count");
    assert_eq!(rows, 1, "the new perspective must not survive a failed switch");
    assert_eq!(reread(&db, &raw, "olive").await.perspective_id.as_deref(), Some(started.id.as_str()));

    let own = crate::test_src::own_code(include_str!("../../perspective.rs"));
    let body = crate::test_src::fn_body(&own, "pub async fn switch(");
    assert_eq!(body.matches(".begin()").count(), 1, "one transaction");
    assert_eq!(body.matches(".commit()").count(), 1, "one commit");
}

/// M22: a perspective past its cap is refused and ended with reason `cap`,
/// and the session is real again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cap_ends_an_orphaned_perspective() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_cap").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    sqlx::query("UPDATE noo_perspectives SET cap_at = now() - interval '1 second' WHERE id = $1::uuid")
        .bind(&started.id)
        .execute(&db)
        .await
        .expect("age the cap");
    assert_eq!(perspective::admit(&db, "olive", &started.claim()).await, Err(Refusal::Ended));
    assert_eq!(end_reason(&db, &started.id).await.as_deref(), Some("cap"));
    assert_eq!(reread(&db, &raw, "olive").await.perspective_id, None);
}

/// M23: the cap is never sent: not in the perspective view (the start and
/// switch answers), not on `/auth/me`.
#[test]
fn the_cap_is_not_advertised() {
    let dims = Perspective { role_cap: Some(Role::User), core_only: true, ..Perspective::default() };
    let at = chrono::Utc::now();
    let v = perspective::view("0f9c1d2e-0000-4000-8000-000000000001", &dims, at);
    let mut keys: Vec<&str> = v.as_object().expect("an object").keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["dims", "id", "started_at"]);
    assert!(!v.to_string().contains("cap_at"), "{v}");

    let u = UserRecord {
        username: "olive".into(),
        hashed_password: "x".into(),
        disabled: false,
        scopes: vec!["read".into(), "write".into()],
        role: Role::Operator,
    };
    let prs = PrsClaim { id: "0f9c1d2e-0000-4000-8000-000000000001".into(), dims };
    let me = me_answer(&u, Some((&prs, at)));
    assert!(!me.to_string().contains("cap_at"), "{me}");

    let own = crate::test_src::own_code(include_str!("../core.rs"));
    let answer = crate::test_src::fn_body(&own, "fn perspective_answer(");
    assert!(answer.contains("\"perspective\": started.view()"));
    assert!(!answer.contains("cap_at"));
}

fn view_of(started: &Started) -> perspective::RequesterPerspective {
    perspective::RequesterPerspective { id: started.id.clone(), dims: started.dims.clone() }
}

/// The catalog clamp: inside a turn under a `user` view an operator's
/// external-tool audience role is `user`; outside it, the live role.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_for_answers_a_user_perspective_as_a_user() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_catalog").await else { return };
    let (_raw, started) = user_view(&db, "olive").await;
    let (role, _kb) = crate::mcp_bridge::identity(&db, Some("olive")).await.expect("identity");
    assert_eq!(role, Some(Role::Operator), "no turn in scope: the live role");
    let (role, _kb) = perspective::scope(Some(view_of(&started)), crate::mcp_bridge::identity(&db, Some("olive")))
        .await
        .expect("identity");
    assert_eq!(role, Some(Role::User), "a user view is shown a user's external tools");
}

async fn task_under(db: &PgPool, owner: &str, snapshot: Option<perspective::RequesterPerspective>) -> uuid::Uuid {
    let new = crate::tasks::NewTask {
        owner: Some(owner),
        objective: "check the view",
        model: None,
        loop_budget: None,
        parent: None,
        role: None,
        token_budget: None,
        created_via: None,
    };
    let task = perspective::scope(snapshot, crate::tasks::create_task(db, new)).await.expect("create the task");
    uuid::Uuid::parse_str(&task.id).expect("a task id")
}

/// The owner clamp, and the snapshot rule: a task submitted under a `user`
/// view is delivered at `user`, still after Back to me, and a demotion of
/// the live role below a snapshot wins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_role_answers_a_user_perspective_as_a_user() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_owner").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    let real = task_under(&db, "olive", None).await;
    assert_eq!(crate::task_events::task_owner_role(&db, real, "olive").await, Ok(Role::Operator));
    let narrowed = task_under(&db, "olive", Some(view_of(&started))).await;
    assert_eq!(crate::task_events::task_owner_role(&db, narrowed, "olive").await, Ok(Role::User));

    let s = reread(&db, &raw, "olive").await;
    perspective::back_to_me(&db, &claims("olive", Role::User, Some(started.claim())), &s).await.expect("back to me");
    assert_eq!(
        crate::task_events::task_owner_role(&db, narrowed, "olive").await,
        Ok(Role::User),
        "a task submitted under a user view still runs as one after Back to me"
    );
    // A turn submitted under the view mints at user too, after the end.
    let live = Role::Operator;
    let turn = perspective::scope(Some(view_of(&started)), async { perspective::snapshot_role(live, perspective::current().as_ref()) }).await;
    assert_eq!(turn, Role::User);

    // A demotion below the snapshot wins: an admin's task under an
    // operator view, then the admin is made a user.
    person(&db, "ada", Role::Admin).await;
    let op_view = perspective::RequesterPerspective {
        id: uuid::Uuid::new_v4().to_string(),
        dims: Perspective { role_cap: Some(Role::Operator), ..Perspective::default() },
    };
    let t = task_under(&db, "ada", Some(op_view)).await;
    assert_eq!(crate::task_events::task_owner_role(&db, t, "ada").await, Ok(Role::Operator));
    sqlx::query("UPDATE noo_users SET role = 'user' WHERE username = 'ada'").execute(&db).await.expect("demote");
    assert_eq!(crate::task_events::task_owner_role(&db, t, "ada").await, Ok(Role::User), "the demotion wins");
}

/// A perspective whose dimensions this gateway cannot read (a newer one
/// wrote a dimension it does not know) is ENDED at the refresh, reason
/// `unreadable`, and the refresh is real.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_dims_end_the_perspective() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_unreadable").await else { return };
    signing_key();
    let (raw, started) = user_view(&db, "olive").await;
    sqlx::query("UPDATE noo_perspectives SET dims = jsonb_build_object('seat', 'hall') WHERE id = $1::uuid")
        .bind(&started.id)
        .execute(&db)
        .await
        .expect("a P4 dimension");
    match rotate_refresh(&db, &raw, None, None).await {
        Rotation::Rotated { access_token, .. } => {
            assert!(payload(&access_token).get("prs").is_none(), "the refresh is real");
        }
        _ => panic!("the refresh must rotate"),
    }
    assert!(!is_live(&db, &started.id).await, "an unreadable perspective must end, not linger");
    assert_eq!(end_reason(&db, &started.id).await.as_deref(), Some("unreadable"));
    assert_eq!(perspective::admit(&db, "olive", &started.claim()).await, Err(Refusal::Ended));
}

/// Back to me and switch answer only the session that carries the
/// perspective: another session of the same account is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn back_to_me_only_from_its_own_session() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_own_session").await else { return };
    let (_raw, started) = user_view(&db, "olive").await;
    let (_other_raw, other) = session(&db, "olive").await;
    let c = claims("olive", Role::User, Some(started.claim()));
    let r = perspective::back_to_me(&db, &c, &other).await.expect_err("another session");
    assert_eq!((r.status, r.detail), (StatusCode::UNAUTHORIZED, perspective::NOT_THIS_SESSION));
    assert!(is_live(&db, &started.id).await);
}

/// A cookie names a session only for its own account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_names_only_its_own_accounts_session() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_cookie_owner").await else { return };
    person(&db, "olive", Role::Operator).await;
    person(&db, "bob", Role::Operator).await;
    let (raw, _s) = session(&db, "olive").await;
    assert!(perspective::session_row(&db, &raw, "bob").await.expect("read").is_none(), "olive's cookie is not bob's session");
    assert!(perspective::session_row(&db, &raw, "olive").await.expect("read").is_some());
}

/// A perspective token carries the narrowed role's legacy scopes and
/// nothing else: the account's additive extras are capabilities too.
#[test]
fn a_perspective_token_drops_the_additive_scopes() {
    let u = UserRecord {
        username: "olive".into(),
        hashed_password: "x".into(),
        disabled: false,
        scopes: vec!["read".into(), "write".into(), "ingest".into(), "graph".into()],
        role: Role::Operator,
    };
    let prs = PrsClaim {
        id: "0f9c1d2e-0000-4000-8000-000000000001".into(),
        dims: Perspective { role_cap: Some(Role::User), ..Perspective::default() },
    };
    let (token, _exp) = super::perspective_token_with(&u, Role::User, &prs, SECRET).expect("mint");
    let c = payload(&token);
    assert_eq!(c["scopes"], json!(["read"]));
    assert_eq!(c["role"], "user");
    assert_eq!(c["prs"]["id"], prs.id);
}

/// Logout ends the session's perspective (reason `logout`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_ends_the_perspective() {
    let own = crate::test_src::own_code(include_str!("../core.rs"));
    let body = crate::test_src::fn_body(&own, "async fn auth_logout_handler(");
    let looked = body.find("auth_refresh::lookup_token(&state.db, &raw).await").expect("the cookie's row");
    let ended = body
        .find("crate::perspective::end(&state.db, pid, crate::perspective::EndReason::Logout)")
        .expect("logout must end the cookie row's perspective");
    let revoked = body.find("auth_refresh::revoke_token(&state.db, &rec.id)").expect("the revoke");
    assert!(looked < ended && ended < revoked);

    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_logout").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    let rec = auth_refresh::lookup_token(&db, &raw).await.expect("read").expect("the row");
    assert_eq!(rec.perspective_id.as_deref(), Some(started.id.as_str()), "the row the logout reads carries it");
    assert!(perspective::end(&db, &started.id, perspective::EndReason::Logout).await.expect("end"));
    assert_eq!(end_reason(&db, &started.id).await.as_deref(), Some("logout"));
}

/// Revoking the account's refresh family (replay, password change,
/// disable) ends every live perspective of the account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_family_ends_its_perspectives() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_family").await else { return };
    let (_raw, started) = user_view(&db, "olive").await;
    auth_refresh::revoke_all_for_user(&db, "olive").await.expect("revoke");
    assert!(!is_live(&db, &started.id).await);
    assert_eq!(end_reason(&db, &started.id).await.as_deref(), Some("family_revoked"));
}

/// Perspectives are never nested: a token already carrying one is refused
/// a start, even on a session that does not carry it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn begin_refuses_a_nested_perspective() {
    let _serial = DB_LOCK.lock().await;
    let Some(db) = scratch("va_nested").await else { return };
    let (raw, started) = user_view(&db, "olive").await;
    let (_other_raw, other) = session(&db, "olive").await;
    let c = claims("olive", Role::User, Some(started.claim()));
    let r = perspective::begin(&db, &c, &other, &dims(json!({"role_cap": "user"}))).await.expect_err("nested");
    assert_eq!((r.status, r.detail), (StatusCode::CONFLICT, perspective::ACTIVE));
    let carrying = reread(&db, &raw, "olive").await;
    let r = perspective::begin(&db, &claims("olive", Role::Operator, None), &carrying, &dims(json!({"role_cap": "user"})))
        .await
        .expect_err("the session already carries one");
    assert_eq!(r.status, StatusCode::CONFLICT);
}
