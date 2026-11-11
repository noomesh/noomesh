// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo_approval_requests`: statements moved out of the exec-approval gate.
//!
//! Only the "nobody to ask" expiry lives here so far (i658): the insert, the
//! poll and the timeout update still sit in `middleware.rs` under its ratchet
//! pin, and `channels/approvals.rs` and `routes/` keep their own reads.
//!
//! Runtime (string) queries, not `sqlx::query!`: the offline cache stays
//! unchanged, and the DB test below (`NOO_TEST_DSN`, the sqlx-drift lane)
//! runs the statement against the real migrated schema.

/// Expire a request nobody could be asked about. Only a `pending` row moves:
/// an approval or denial already recorded is never overwritten, and an
/// expired row is never acted on later (approve/deny act on pending rows
/// only). Returns whether a row was expired.
pub async fn expire_unreachable(db: impl sqlx::PgExecutor<'_>, request_id: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE noo_approval_requests SET status = 'expired', resolved_at = NOW(), resolved_by = 'nobody to ask' \
         WHERE request_id = $1 AND status = 'pending'",
    )
    .bind(request_id)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use sqlx::Row as _;

    async fn insert(db: &sqlx::PgPool, id: &str, status: &str) {
        sqlx::query(
            "INSERT INTO noo_approval_requests (request_id, tool_name, risk_level, reason, status, created_at) \
             VALUES ($1, 'noo_agent_message', 'high', 'i658 test', $2, NOW())",
        )
        .bind(id)
        .bind(status)
        .execute(db)
        .await
        .expect("insert");
    }

    async fn row(db: &sqlx::PgPool, id: &str) -> (String, Option<String>) {
        let r = sqlx::query("SELECT status, resolved_by FROM noo_approval_requests WHERE request_id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .expect("row");
        (r.get("status"), r.get("resolved_by"))
    }

    /// A pending row expires as "nobody to ask"; a decided row is untouched;
    /// a second expiry is a no-op.
    #[tokio::test]
    async fn only_a_pending_request_expires_and_a_decision_is_never_overwritten() {
        let Some(db) = crate::repo::node_model_set_retry::test_pool().await else {
            eprintln!("NOO_TEST_DSN unset — approval_requests not exercised");
            return;
        };
        let (p, a) = ("i658-unreachable-pending", "i658-unreachable-approved");
        let _ = sqlx::query("DELETE FROM noo_approval_requests WHERE request_id = ANY($1)").bind(vec![p, a]).execute(&db).await;
        insert(&db, p, "pending").await;
        insert(&db, a, "approved").await;

        assert!(super::expire_unreachable(&db, p).await.unwrap());
        assert_eq!(row(&db, p).await, ("expired".into(), Some("nobody to ask".into())));
        assert!(!super::expire_unreachable(&db, p).await.unwrap(), "already expired: no-op");
        assert!(!super::expire_unreachable(&db, a).await.unwrap(), "a decision is never overwritten");
        assert_eq!(row(&db, a).await.0, "approved");
        assert!(!super::expire_unreachable(&db, "i658-no-such-request").await.unwrap());

        let _ = sqlx::query("DELETE FROM noo_approval_requests WHERE request_id = ANY($1)").bind(vec![p, a]).execute(&db).await;
    }
}
