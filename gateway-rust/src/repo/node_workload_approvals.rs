// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo_node_workload_approvals` (migration 114, i596 slice 2): the newest
//! approval set the operator signed for each node, as exact bytes.
//!
//! Runtime (string) queries, not `sqlx::query!`: the offline cache stays
//! unchanged, and the DB test below (`NOO_TEST_DSN`, the sqlx-drift lane) runs
//! every statement here against the real migrated schema instead.
//!
//! The gateway never signs and never re-serializes: `doc` and `sig` are the
//! decoded bytes the operator's CLI sent, and desired-config carries them back
//! out as base64. [`store`] only ever RAISES a node's generation; the database
//! refuses a lower or equal one, so two racing writers cannot roll a node back.

use sqlx::Row as _;

/// One node's stored set.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSet {
    pub node_id: String,
    pub generation: i64,
    pub doc: Vec<u8>,
    pub sig: Vec<u8>,
    pub stored_at: chrono::DateTime<chrono::Utc>,
    pub stored_by: String,
}

/// Store `doc`/`sig` as `node_id`'s set at `generation`, only when no set is
/// stored or the stored one's generation is LOWER. False when the stored one
/// is at `generation` or above (a concurrent writer got there first): nothing
/// was written.
pub async fn store(db: impl sqlx::PgExecutor<'_>, node_id: &str, generation: i64, doc: &[u8], sig: &[u8], stored_by: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO noo_node_workload_approvals (node_id, generation, doc, sig, stored_by) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (node_id) DO UPDATE SET \
           generation = EXCLUDED.generation, doc = EXCLUDED.doc, sig = EXCLUDED.sig, \
           stored_by = EXCLUDED.stored_by, stored_at = now() \
         WHERE noo_node_workload_approvals.generation < EXCLUDED.generation \
         RETURNING node_id",
    )
    .bind(node_id)
    .bind(generation)
    .bind(doc)
    .bind(sig)
    .bind(stored_by)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// `node_id`'s stored set, if any.
pub async fn get(db: impl sqlx::PgExecutor<'_>, node_id: &str) -> Result<Option<StoredSet>, sqlx::Error> {
    let row = sqlx::query("SELECT node_id, generation, doc, sig, stored_at, stored_by FROM noo_node_workload_approvals WHERE node_id = $1")
        .bind(node_id)
        .fetch_optional(db)
        .await?;
    let Some(r) = row else {
        return Ok(None);
    };
    Ok(Some(StoredSet {
        node_id: r.try_get("node_id")?,
        generation: r.try_get("generation")?,
        doc: r.try_get("doc")?,
        sig: r.try_get("sig")?,
        stored_at: r.try_get("stored_at")?,
        stored_by: r.try_get("stored_by")?,
    }))
}

/// Whether `node_id` is an enrolled node (a `cluster_nodes` row): a set is
/// stored only for a node this controller enrolled.
pub async fn node_enrolled(db: impl sqlx::PgExecutor<'_>, node_id: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT EXISTS (SELECT 1 FROM cluster_nodes WHERE node_id = $1) AS enrolled")
        .bind(node_id)
        .fetch_one(db)
        .await?;
    row.try_get("enrolled")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every statement here against the migrated schema: no set, a first
    /// store, a higher generation replacing it, an equal and a lower one
    /// refused (nothing written), and the enrolled-node read. Needs the DB
    /// (`NOO_TEST_DSN`): it runs in the sqlx-drift lane.
    #[tokio::test]
    async fn approval_sets_round_trip_through_postgres() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — node workload approvals round trip not exercised");
            return;
        };
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("connect");
        crate::mesh_migrate::apply_baseline(&admin).await.expect("baseline");
        crate::mesh_migrate::apply(&admin).await.expect("migrations");
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect");
        let node = format!("nwa-{}", std::process::id());
        let _ = sqlx::query("DELETE FROM noo_node_workload_approvals WHERE node_id = $1").bind(&node).execute(&db).await;

        assert_eq!(get(&db, &node).await.expect("get"), None, "no set yet");
        assert!(store(&db, &node, 1, b"doc-one", b"sig-one", "alice").await.expect("first store"));
        let one = get(&db, &node).await.expect("get").expect("stored");
        assert_eq!((one.generation, one.doc.as_slice(), one.sig.as_slice(), one.stored_by.as_str()), (1, &b"doc-one"[..], &b"sig-one"[..], "alice"));

        assert!(store(&db, &node, 3, b"doc-three", b"sig-three", "bob").await.expect("higher"));
        let three = get(&db, &node).await.unwrap().unwrap();
        assert_eq!((three.generation, three.doc.as_slice(), three.stored_by.as_str()), (3, &b"doc-three"[..], "bob"));

        // Equal and lower: refused by the statement itself, nothing changes.
        assert!(!store(&db, &node, 3, b"other", b"other", "mallory").await.expect("equal"));
        assert!(!store(&db, &node, 2, b"older", b"older", "mallory").await.expect("lower"));
        assert_eq!(get(&db, &node).await.unwrap().unwrap(), three, "a refused store wrote nothing");

        // The enrolled-node read: a node with no row is not enrolled.
        assert!(!node_enrolled(&db, &format!("nwa-none-{}", std::process::id())).await.expect("enrolled read"));
        let _ = sqlx::query("DELETE FROM noo_node_workload_approvals WHERE node_id = $1").bind(&node).execute(&db).await;
    }
}
