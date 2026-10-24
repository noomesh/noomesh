// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Channel plane — Rust implementations of the messaging adapters.
//!
//! the design (retire `noomesh/channels/`), complete through stage 4:
//! transport, pipeline, approvals and outbound send are all native here.
//! Conversation identity deliberately stays with Trellion via
//! `worker.memory.*`, since that is memory, not channel logic.
pub mod approvals;
pub mod conversation;
pub mod google_chat_format;
pub mod identity;
pub mod ingress;
pub mod google_chat_pipeline;
pub mod telegram;

/// Whether a chat is a ROOM rather than a one-to-one conversation: anything
/// that is not explicitly `private` (a Telegram group, supergroup or channel,
/// a Google Chat space). An unknown or empty type counts as a room - the
/// reply is posted where everyone can read it, so doubt narrows.
pub fn is_shared_room(chat_type: &str) -> bool {
    chat_type != "private"
}

/// What a refused channel turn says. The account is linked, but cannot act.
pub const ACCOUNT_UNAVAILABLE_REPLY: &str = "I can't act for your noomesh account right now \
(it is disabled or could not be checked). Ask an operator to check it with `noo security user list`.";

/// Run one channel turn as the linked account's REAL principal, in a shared
/// room when `chat_type` says so.
///
/// `principal` is what `bus_principal::account_principal` resolved (role and
/// scopes from the account row), so every `worker.*` message the turn sends
/// is signed with that and not with a blanket operator tier.
pub async fn scoped_turn<F: std::future::Future>(
    principal: crate::bus_principal::Principal,
    chat_type: &str,
    fut: F,
) -> F::Output {
    let shared = is_shared_room(chat_type);
    crate::bus_principal::with_principal(
        room_principal(principal, shared),
        crate::coordinator::with_shared_room(shared, fut),
    )
    .await
}

/// Signed-principal scope that marks a turn in a group chat or shared space.
/// The worker's KB resolver clamps every read to the shared tiers when it
/// sees it (tool calls included, not only the injected context), and the
/// personal memory handlers answer nothing. It can only narrow.
pub const SHARED_ROOM_SCOPE: &str = "kb:shared-room";

/// The principal a room turn signs its bus messages with: the account's own,
/// plus [`SHARED_ROOM_SCOPE`] when the reply goes to a room.
pub fn room_principal(
    mut principal: crate::bus_principal::Principal,
    shared: bool,
) -> crate::bus_principal::Principal {
    if shared && !principal.scopes.iter().any(|s| s == SHARED_ROOM_SCOPE) {
        principal.scopes.push(SHARED_ROOM_SCOPE.to_string());
    }
    principal
}

/// Warn when an operator still has a retired engine selector pinned to
/// `python` (`NOO_TELEGRAM_ENGINE`, `NOO_GCHAT_PUBSUB_ENGINE`,
/// `NOO_GCHAT_PIPELINE`). The Python channel engine is gone — the design
/// stage 4 unregistered its handlers and its inbound loops can no longer
/// start — so the value selects nothing. Per the one-implementation rule
/// it must never *silently* fall through, and it must never stand down the
/// only implementation left: warn-and-ignore, never honour.
pub fn warn_if_obsolete_python_selector(var: &str) {
    if selector_is_python(var) {
        tracing::warn!(
            selector = var,
            "obsolete engine selector ignored: the Python channel engine was \
             removed; the Rust transport and pipeline \
             own this channel"
        );
    }
}

/// True when `var` is set to `python` (case-insensitive, whitespace-
/// tolerant — operator whitespace must not change the answer).
fn selector_is_python(var: &str) -> bool {
    std::env::var(var)
        .map(|v| v.trim().eq_ignore_ascii_case("python"))
        .unwrap_or(false)
}

#[cfg(test)]
mod selector_tests {
    use super::selector_is_python;

    #[test]
    fn obsolete_selector_detection_is_forgiving_about_case_and_whitespace() {
        // The selector no longer changes behaviour — but the WARNING must
        // fire for every spelling an operator plausibly left behind, or the
        // leftover flag becomes a silent no-op (the fall-through the
        // one-implementation rule forbids).
        unsafe { std::env::set_var("NOO_TELEGRAM_ENGINE", "Python") };
        assert!(selector_is_python("NOO_TELEGRAM_ENGINE"));
        unsafe { std::env::set_var("NOO_TELEGRAM_ENGINE", "  python  ") };
        assert!(selector_is_python("NOO_TELEGRAM_ENGINE"));
        unsafe { std::env::set_var("NOO_TELEGRAM_ENGINE", "rust") };
        assert!(!selector_is_python("NOO_TELEGRAM_ENGINE"));
        unsafe { std::env::remove_var("NOO_TELEGRAM_ENGINE") };
        assert!(!selector_is_python("NOO_TELEGRAM_ENGINE"));
    }
}

/// Ingress admission and approval binding, against a REAL schema.
///
/// These two rules are pure SQL predicates — "is this sender linked",
/// "what is pending in THIS conversation" — so a mock proves nothing about
/// them. They are the kind of check that passes while the column it reads
/// does not exist.
///
/// Gated on `NOO_BROKER_TEST_DSN` like the broker and layout suites, and
/// like them it builds its own scratch DATABASE and runs the real
/// `mesh_migrate::apply` — so migration 070 is exercised by the same tests
/// that depend on it, rather than hand-copied into a fixture that can drift
/// away from the migration.
#[cfg(test)]
mod ingress_and_approval_binding_tests {
    use super::{approvals, identity, ingress};
    use sqlx::PgPool;

    const DB_NAME: &str = "chat_ingress_test";

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

        // Build the schema first, on a plain connection: `apply` is
        // path-directed and decides the layout itself.
        let build = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&scratch_dsn)
            .await
            .expect("connect scratch");
        // `apply` provisions noo_app and needs a credential for it.
        unsafe { std::env::set_var("NOO_APP_DB_PASSWORD", "ephemeral-not-a-secret") };
        for ext in ["vector", "pg_trgm"] {
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE EXTENSION IF NOT EXISTS {ext}")))
                .execute(&build)
                .await
                .expect("extension");
        }
        crate::mesh_migrate::apply(&build).await.expect("apply migrations");
        build.close().await;

        // THEN the pool under test, pinning the same search_path `state.rs`
        // pins. A fresh install puts the whole mesh schema in `mesh`, not
        // `public` (see mesh_migrate's layout tests), so without this every
        // query below fails with "relation does not exist" — a wrong
        // address, not a wrong query.
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&scratch_dsn)
            .expect("scratch dsn")
            .options([("search_path", "mesh,public")]);
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .expect("connect scratch");

        // NOTHING is done about `noo_security_audit`'s monthly partition here,
        // ON PURPOSE. A fresh database has zero partitions, and an earlier
        // version of this helper created the current month's — which is
        // precisely what hid the live bug: the startup hook asked for
        // `public.noo_ensure_audit_partition` on an install whose functions
        // live in `mesh`, so no partition was ever created and every audit
        // write was discarded in silence. The fixture was quietly supplying
        // what production never had, so the audit assertions below passed
        // against a database that did not resemble the live one.
        //
        // The writer heals its own partition now (`audit::
        // audit_insert`), so leaving this empty is what proves it.

        // Prove the fixture before trusting any assertion made against it.
        // A missing table here would otherwise read as "the rule refused",
        // which is the answer these tests are trying to earn honestly.
        let reachable: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_approval_requests")
            .fetch_one(&db)
            .await
            .expect("the migrated schema must be reachable on the pinned search_path");
        assert_eq!(reachable, 0, "a scratch database starts empty");
        Some(db)
    }

    async fn link(db: &PgPool, username: &str, role: &str, channel: &str, id: &str) {
        sqlx::query(
            "INSERT INTO noo_users (username, hashed_password, role) \
             VALUES ($1, 'x', $2) \
             ON CONFLICT ON CONSTRAINT uq_noo_users_username DO UPDATE SET role = $2",
        )
        .bind(username)
        .bind(role)
        .execute(db)
        .await
        .expect("create user");
        sqlx::query(
            "INSERT INTO noo_user_channel_links (channel, channel_user_id, username) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (channel, channel_user_id) DO UPDATE SET username = $3",
        )
        .bind(channel)
        .bind(id)
        .bind(username)
        .execute(db)
        .await
        .expect("link channel");
    }

    /// One pending exec-approval bound to `conversation_id`, as the gate
    /// writes it.
    async fn pending(db: &PgPool, request_id: &str, requester: &str, conversation_id: &str) {
        sqlx::query(
            "INSERT INTO noo_approval_requests \
               (request_id, tool_name, risk_level, reason, status, created_at, \
                requester, conversation_id, channel, chat_id) \
             VALUES ($1, 'python_exec', 'high', 'test', 'pending', NOW(), $2, $3, 'telegram', '55')",
        )
        .bind(request_id)
        .bind(requester)
        .bind(conversation_id)
        .execute(db)
        .await
        .expect("insert pending request");
    }

    async fn status(db: &PgPool, request_id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM noo_approval_requests WHERE request_id = $1")
            .bind(request_id)
            .fetch_one(db)
            .await
            .expect("read status")
    }

    // ── 1. Ingress is default-deny on BOTH channels ──────────────────────

    #[tokio::test]
    async fn ingress_admits_only_linked_senders_on_both_channels() {
        let Some(db) = scratch().await else { return };

        // An unlinked Telegram sender is refused, WITH a usable reply.
        match ingress::admit(&db, "telegram", "900001").await {
            ingress::Admission::Refused { reply } => {
                let reply = reply.expect("the first refusal must tell them how to link");
                assert!(
                    reply.contains("noo security user link") && reply.contains("telegram 900001"),
                    "refusal must name the link command: {reply}"
                );
            }
            other => panic!("an unlinked Telegram sender must be refused, got {other:?}"),
        }

        // An unlinked Google Chat sender is refused too — this channel had
        // no allow-list at all and answered everyone under their raw id.
        assert!(
            matches!(
                ingress::admit(&db, "google_chat", "users/900002").await,
                ingress::Admission::Refused { .. }
            ),
            "an unlinked Google Chat sender must be refused"
        );

        // A linked sender is admitted AS THE ACCOUNT, not as the raw id.
        link(&db, "ada", "user", "telegram", "900003").await;
        assert_eq!(
            ingress::admit(&db, "telegram", "900003").await,
            ingress::Admission::Admitted("ada".to_string()),
            "a linked sender runs as their account"
        );

        // The refusal was audited, once.
        let audited: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM noo_security_audit \
             WHERE event_type = 'channel_ingress_denied' AND actor = 'telegram:900001'",
        )
        .fetch_one(&db)
        .await
        .expect("count audit rows");
        assert_eq!(audited, 1, "a refusal must leave exactly one audit row");

        // …and a second attempt inside the window does NOT write another.
        let _ = ingress::admit(&db, "telegram", "900001").await;
        let audited: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM noo_security_audit \
             WHERE event_type = 'channel_ingress_denied' AND actor = 'telegram:900001'",
        )
        .fetch_one(&db)
        .await
        .expect("count audit rows");
        assert_eq!(audited, 1, "a stranger must not be able to flood the audit table");
    }

    /// One refusal, one row — on a database with NO audit partition, which
    /// is what every fresh install actually looks like.
    ///
    /// The live symptom on host8: an unlinked sender was
    /// refused and logged, and `mesh.noo_security_audit` stayed empty. The
    /// doc and the runbook both promised an audited refusal. Two silent
    /// layers were stacked — a startup hook that asked for
    /// `public.noo_ensure_audit_partition` on a `mesh`-layout install and
    /// warned once when it was not found, and an `audit::record` that threw
    /// its own insert error away — so the only evidence was an empty table.
    ///
    /// This test starts from zero partitions deliberately. It fails on the
    /// parent commit, where the first refusal writes nothing at all.
    #[tokio::test]
    async fn a_refusal_is_audited_once_even_with_no_partition_yet() {
        let Some(db) = scratch().await else { return };

        // Prove the precondition rather than assuming it: if some future
        // change starts pre-creating partitions, this test would silently
        // stop testing the thing it exists for.
        let partitions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_inherits i              JOIN pg_class c ON c.oid = i.inhrelid              JOIN pg_class p ON p.oid = i.inhparent              WHERE p.relname = 'noo_security_audit'",
        )
        .fetch_one(&db)
        .await
        .expect("count partitions");
        assert_eq!(
            partitions, 0,
            "this test must start with NO audit partition — that is the live              condition it reproduces"
        );

        let sender = "950001";
        let count = |db: sqlx::PgPool| async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM noo_security_audit                  WHERE event_type = 'channel_ingress_denied' AND actor = $1",
            )
            .bind(format!("telegram:{sender}"))
            .fetch_one(&db)
            .await
            .expect("count audit rows")
        };

        // FIRST refusal: exactly one row, and the writer had to create the
        // partition to land it.
        assert!(matches!(
            ingress::admit(&db, "telegram", sender).await,
            ingress::Admission::Refused { .. }
        ));
        assert_eq!(
            count(db.clone()).await,
            1,
            "the first refusal from a new sender must leave exactly one audit row"
        );

        // SECOND refusal inside the window: no new row. The rate limiter is
        // what a stranger's script runs into.
        assert!(matches!(
            ingress::admit(&db, "telegram", sender).await,
            ingress::Admission::Refused { .. }
        ));
        assert_eq!(
            count(db.clone()).await,
            1,
            "a second refusal inside the window must NOT write another row"
        );
    }

    /// The retirement, proven rather than asserted in a comment: the env
    /// allow-list names this sender, and the sender is still refused.
    #[tokio::test]
    async fn the_env_allowlist_no_longer_admits_anyone() {
        let Some(db) = scratch().await else { return };
        unsafe { std::env::set_var("TELEGRAM_ALLOWED_USERS", "900010") };

        let verdict = ingress::admit(&db, "telegram", "900010").await;
        unsafe { std::env::remove_var("TELEGRAM_ALLOWED_USERS") };

        assert!(
            matches!(verdict, ingress::Admission::Refused { .. }),
            "TELEGRAM_ALLOWED_USERS is retired as an identity source — it must not admit"
        );
        // And the link table is still the thing that does admit.
        link(&db, "bob", "user", "telegram", "900010").await;
        assert_eq!(
            ingress::admit(&db, "telegram", "900010").await,
            ingress::Admission::Admitted("bob".to_string())
        );
        assert_eq!(identity::resolve_user(&db, "telegram", "900010").await.as_deref(), Some("bob"));
    }

    // ── 2. Approvals are bound to requester + conversation ───────────────

    #[tokio::test]
    async fn a_bare_decision_only_reaches_requests_from_its_own_conversation() {
        let Some(db) = scratch().await else { return };
        pending(&db, "req-alpha", "ada", "conv-A").await;

        // From ANOTHER conversation, a bare decision finds nothing. This is
        // the bug: it used to resolve the globally newest pending row.
        assert!(
            matches!(
                approvals::resolve_pending_request(&db, None, "conv-B").await,
                Ok(approvals::PendingResolution::None)
            ),
            "a bare decision in conv-B must not reach a request raised in conv-A"
        );

        // From the ORIGINATING conversation it resolves.
        match approvals::resolve_pending_request(&db, None, "conv-A").await {
            Ok(approvals::PendingResolution::One(id)) => assert_eq!(id, "req-alpha"),
            other => panic!("conv-A must resolve its own pending request, got {:?}", other.is_ok()),
        }

        // Two pending HERE is ambiguous — never a guess between two blocked
        // tool calls.
        pending(&db, "req-beta", "ada", "conv-A").await;
        assert!(matches!(
            approvals::resolve_pending_request(&db, None, "conv-A").await,
            Ok(approvals::PendingResolution::Ambiguous)
        ));

        // An explicit id still names a row from anywhere — an operator
        // deciding from elsewhere is a real workflow, and `chat_decider`
        // has already established they are an operator.
        match approvals::resolve_pending_request(&db, Some("req-alpha"), "conv-B").await {
            Ok(approvals::PendingResolution::One(id)) => assert_eq!(id, "req-alpha"),
            _ => panic!("an explicit id must still resolve from another conversation"),
        }

        // A surface with no conversation must NOT fall back to "newest
        // anywhere" — that is precisely the behaviour being removed.
        assert!(matches!(
            approvals::resolve_pending_request(&db, None, "").await,
            Ok(approvals::PendingResolution::None)
        ));
    }

    #[tokio::test]
    async fn only_a_linked_operator_may_decide_from_chat() {
        let Some(db) = scratch().await else { return };

        // An operator, linked → decides, recorded under the canonical name.
        link(&db, "opal", "operator", "telegram", "900020").await;
        let decider = approvals::chat_decider(&db, "telegram", "900020")
            .await
            .expect("a linked operator may decide");
        assert_eq!(decider, "opal", "the canonical username is recorded, not a display name");

        pending(&db, "req-ok", "ada", "conv-A").await;
        let ack = approvals::decide_exec_approval(&db, "req-ok", "approve", &decider).await;
        assert!(ack.contains("Approved"), "{ack}");
        assert_eq!(status(&db, "req-ok").await, "approved");

        // A linked User-tier account may talk, but may not approve.
        link(&db, "ada", "user", "telegram", "900021").await;
        let refusal = approvals::chat_decider(&db, "telegram", "900021")
            .await
            .expect_err("a User-tier account must not decide approvals");
        assert!(refusal.contains("not an operator"), "{refusal}");

        // An UNLINKED sender named in the env allow-list must not decide
        // either: that variable is documented to operators as a talk
        // allow-list, and it used to confer approval authority silently.
        unsafe { std::env::set_var("TELEGRAM_ALLOWED_USERS", "900022") };
        unsafe { std::env::set_var("NOO_APPROVAL_CHAT_SENDERS", "telegram:900022") };
        let refusal = approvals::chat_decider(&db, "telegram", "900022").await;
        unsafe { std::env::remove_var("TELEGRAM_ALLOWED_USERS") };
        unsafe { std::env::remove_var("NOO_APPROVAL_CHAT_SENDERS") };
        let refusal = refusal.expect_err("an env allow-list must not confer approval authority");
        assert!(
            refusal.contains("noo security user link"),
            "the refusal must point at the link, not at the env var: {refusal}"
        );

        // Nothing above decided req-beta.
        pending(&db, "req-beta", "ada", "conv-A").await;
        assert_eq!(status(&db, "req-beta").await, "pending");
    }
}

#[cfg(test)]
mod scoped_turn_tests {
    use super::*;

    fn principal(role: &str, scopes: serde_json::Value) -> crate::bus_principal::Principal {
        crate::bus_principal::principal_from_row("ada", role, &scopes, false).unwrap()
    }

    #[test]
    fn only_private_chats_are_not_rooms() {
        assert!(!is_shared_room("private"));
        for t in ["group", "supergroup", "channel", "space", "", "unknown"] {
            assert!(is_shared_room(t), "{t}");
        }
    }

    /// The bus signs `current()`. A read-scope linked user's turn must sign as
    /// role user, scopes [read] - not the old blanket operator read+write.
    #[tokio::test]
    async fn a_read_scope_users_turn_publishes_as_user_read() {
        let p = scoped_turn(principal("user", serde_json::json!(["read"])), "private", async {
            crate::bus_principal::current()
        })
        .await;
        assert_eq!(p.sub, "ada");
        assert_eq!(p.role, "user");
        assert_eq!(p.scopes, vec!["read".to_string()]);
    }

    #[tokio::test]
    async fn an_operator_users_turn_keeps_write_but_never_admin() {
        let p = scoped_turn(principal("admin", serde_json::json!(["read", "write", "admin"])), "private", async {
            crate::bus_principal::current()
        })
        .await;
        assert_eq!(p.role, "operator");
        assert!(p.scopes.contains(&"write".to_string()) && !p.scopes.contains(&"admin".to_string()));
    }

    #[tokio::test]
    async fn the_turn_knows_whether_it_is_in_a_room() {
        let in_room = scoped_turn(principal("user", serde_json::json!([])), "supergroup", async {
            crate::coordinator::in_shared_room()
        })
        .await;
        let in_dm = scoped_turn(principal("user", serde_json::json!([])), "private", async {
            crate::coordinator::in_shared_room()
        })
        .await;
        assert!(in_room && !in_dm);
    }

    /// Both pipelines resolve the account's principal and run the turn
    /// through `scoped_turn`; neither calls the coordinator bare any more.
    #[test]
    fn both_pipelines_scope_the_turn() {
        for (name, src) in [
            ("telegram", include_str!("telegram.rs")),
            ("google_chat", include_str!("google_chat_pipeline.rs")),
        ] {
            let code = &src[..src.find("#[cfg(test)]").unwrap()];
            assert!(code.contains("account_principal("), "{name} must resolve the account's principal");
            let run = code.find("coordinator::run(").unwrap_or_else(|| panic!("{name}: no coordinator::run"));
            let scoped = code.find("super::scoped_turn(").unwrap_or_else(|| panic!("{name}: no scoped_turn"));
            assert!(scoped < run, "{name}: coordinator::run must sit inside scoped_turn");
            // The room decision is `scoped_turn`'s (`is_shared_room` on the
            // chat type the adapter normalised), so the pipeline must hand it
            // the event's chat type rather than decide on its own.
            let call = &code[scoped..(scoped + 120).min(code.len())];
            assert!(call.contains("chat_type"), "{name} must pass the chat type to scoped_turn so rooms are marked");
        }
    }

    #[test]
    fn a_room_turn_signs_with_the_shared_room_scope_and_a_private_one_does_not() {
        use crate::bus_principal::Principal;
        let base = || Principal::user("ada", crate::auth::Role::Operator, vec!["read".into(), "write".into()]);
        let room = room_principal(base(), true);
        assert!(room.scopes.iter().any(|s| s == SHARED_ROOM_SCOPE));
        assert_eq!(room.sub, "ada", "the account is unchanged");
        assert_eq!(room_principal(room.clone(), true).scopes.iter().filter(|s| *s == SHARED_ROOM_SCOPE).count(), 1, "added once");
        let private = room_principal(base(), false);
        assert!(!private.scopes.iter().any(|s| s == SHARED_ROOM_SCOPE));
    }

    #[test]
    fn scoped_turn_uses_the_room_principal() {
        let src = include_str!("mod.rs");
        let body = src.split("pub async fn scoped_turn").nth(1).unwrap().split("\n}\n").next().unwrap();
        assert!(body.contains("room_principal(principal, shared)"));
    }
}
