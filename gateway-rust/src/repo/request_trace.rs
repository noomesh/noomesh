// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Request traces — `noo_request_trace` (i359). One row per request the
//! gateway served: metadata and sizes, never text. Written by
//! `crate::request_trace` when a request ends, pruned by its daily loop.
//!
//! Runtime queries, not `query!`: the table postdates the offline cache, as
//! `noo_token_usage`'s writer does.

use crate::request_trace::SummaryRow;

/// The account a row's actor belongs to: a connection login
/// (`alice/laptop`) is the account `alice`'s. None for a non-person caller.
pub fn account_for<'a>(actor: Option<&'a str>, actor_kind: Option<&str>) -> Option<&'a str> {
    match (actor, actor_kind) {
        (Some(a), Some("user")) => Some(crate::auth::account_of(a)),
        _ => None,
    }
}

/// Insert one row. The account is resolved by name IN the insert, as the
/// usage writer does: the ACCOUNT of a connection login, so its rows carry
/// the account's `user_uuid` and an erase finds them. A name with no account
/// (a service key, an internal caller) stores NULL rather than a made-up
/// identity.
pub async fn insert(db: &sqlx::PgPool, row: &SummaryRow) -> Result<(), sqlx::Error> {
    let s = &row.summary;
    let username = account_for(s.actor.as_deref(), s.actor_kind.as_deref());
    sqlx::query(
        "INSERT INTO noo_request_trace
             (trace_id, method, route, status, duration_ms, user_uuid, actor, actor_kind,
              model, backend, node_id, prompt_tokens, completion_tokens, span_count,
              request_bytes, response_bytes)
         VALUES ($1, $2, $3, $4, $5,
                 (SELECT u.user_uuid FROM noo_users u WHERE u.username = $6),
                 $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(&row.trace_id)
    .bind(&row.method)
    .bind(&row.route)
    .bind(row.status)
    .bind(row.duration_ms)
    .bind(username)
    .bind(s.actor.as_deref())
    .bind(s.actor_kind.as_deref())
    .bind(s.model.as_deref())
    .bind(s.backend.as_deref())
    .bind(s.node.as_deref())
    .bind(s.prompt_tokens)
    .bind(s.completion_tokens)
    .bind(row.span_count)
    .bind(row.request_bytes)
    .bind(row.response_bytes)
    .execute(db)
    .await
    .map(|_| ())
}

/// Delete every row older than `keep_days`; the number deleted.
pub async fn prune(db: &sqlx::PgPool, keep_days: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query("DELETE FROM noo_request_trace WHERE at < now() - ($1::bigint * interval '1 day')")
        .bind(keep_days)
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only readers and the erase runner: inside the test module, so the
    // gateway binary carries no helper that executes a caller's SQL string.
    /// Every row's actor, sorted. For the erase test; operators read rows
    /// through `routes::traces`.
    async fn actors(db: &sqlx::PgPool) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT actor FROM noo_request_trace WHERE actor IS NOT NULL ORDER BY 1").fetch_all(db).await
    }

    /// The account `user_uuid` a row with this exact actor resolved to.
    async fn user_uuid_of(db: &sqlx::PgPool, actor: &str) -> Result<Option<uuid::Uuid>, sqlx::Error> {
        sqlx::query_scalar("SELECT user_uuid FROM noo_request_trace WHERE actor = $1 LIMIT 1").bind(actor).fetch_one(db).await
    }

    /// Run one erase store's archive and delete statements for `username`.
    async fn run_erase_statements(
        db: &sqlx::PgPool,
        statements: &(String, String, &'static str),
        username: &str,
    ) -> Result<(), sqlx::Error> {
        let (snapshot, delete, label) = statements;
        sqlx::query(sqlx::AssertSqlSafe(snapshot.as_str()))
            .bind(username)
            .bind(uuid::Uuid::new_v4())
            .bind(*label)
            .execute(db)
            .await?;
        sqlx::query(sqlx::AssertSqlSafe(delete.as_str())).bind(username).execute(db).await?;
        Ok(())
    }


    /// RTBF for request traces against the real table: alice's rows go,
    /// her connection login's included (`alice/laptop`, which used to keep
    /// its rows); bob's, `alice_x`'s and an internal caller's stay.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rtbf_erases_a_users_request_traces_including_her_connection_logins() {
        let _serial = crate::ops::tests::DB_LOCK.lock().await;
        let Some(db) = crate::ops::tests::scratch("rtbf_traces").await else { return };
        use crate::auth::Role;
        for who in ["alice", "bob", "alice_x"] {
            let _ = crate::ops::tests::account(&db, who, Role::User).await;
        }
        let row = |actor: &str, kind: &str| SummaryRow {
            trace_id: format!("{:032x}", actor.len()),
            method: "POST".into(),
            route: "/v1/chat/completions".into(),
            status: 200,
            duration_ms: 1,
            summary: crate::request_trace::Summary {
                actor: Some(actor.into()),
                actor_kind: Some(kind.into()),
                ..Default::default()
            },
            span_count: 1,
            request_bytes: None,
            response_bytes: None,
        };
        for (actor, kind) in [("alice", "user"), ("alice/laptop", "user"), ("bob", "user"), ("alice_x", "user"), ("internal:cluster:worker", "internal")] {
            insert(&db, &row(actor, kind)).await.unwrap();
        }
        assert!(user_uuid_of(&db, "alice/laptop").await.unwrap().is_some(), "a connection login's row carries its account's user_uuid");
        let st = crate::routes::users::tests::erase_statements("noo_request_trace").expect("noo_request_trace is an erase target");
        run_erase_statements(&db, &st, "alice").await.unwrap();
        assert_eq!(
            actors(&db).await.unwrap(),
            ["alice_x", "bob", "internal:cluster:worker"],
            "alice's rows are gone, her connection's too, nobody else's"
        );
    }

    #[test]
    fn a_connection_login_resolves_to_its_account() {
        assert_eq!(account_for(Some("alice/laptop"), Some("user")), Some("alice"));
        assert_eq!(account_for(Some("alice"), Some("user")), Some("alice"));
        assert_eq!(account_for(Some("internal:cluster:worker"), Some("internal")), None);
        assert_eq!(account_for(None, Some("user")), None);
    }
}
