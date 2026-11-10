// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo_node_model_set_retry` (migration 114, i607b B3): the per-node
//! `retry now` epoch for a refused model-set fetch.
//!
//! One row per node: a monotonic `epoch` and the sets the last bump named
//! (`["<id>@<rev>", ...]`; empty = every refused set). desired-config serves
//! it as the top-level `model_set_retry` and the node agent clears its
//! refused backoff when the epoch moves past the one it last saw. Nothing
//! here reads or writes a placement row.
//!
//! Runtime (string) queries, not `sqlx::query!`: the offline cache stays
//! unchanged, and the DB test below (`NOO_TEST_DSN`, the sqlx-drift lane)
//! runs every statement against the real migrated schema.

use serde_json::Value;
use sqlx::Row as _;

/// A node's retry state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retry {
    pub epoch: u64,
    /// `id@rev` strings; empty = all refused sets.
    pub sets: Vec<String>,
}

/// Add one to the node's epoch (a node with no row starts at 1) and record
/// `set` as the sets this bump names (none = all). Returns the new state.
/// Two bumps inside one agent reconcile interval: the later bump's sets win,
/// while the epoch still moves (a bump with no set clears everything).
pub async fn bump(db: impl sqlx::PgExecutor<'_>, node_id: &str, set: Option<&str>, by: &str) -> Result<Retry, sqlx::Error> {
    let sets: Value = Value::Array(set.map(|s| Value::String(s.to_string())).into_iter().collect());
    let row = sqlx::query(
        "INSERT INTO noo_node_model_set_retry (node_id, epoch, sets, updated_by) VALUES ($1, 1, $2, $3) \
         ON CONFLICT (node_id) DO UPDATE SET epoch = noo_node_model_set_retry.epoch + 1, \
           sets = EXCLUDED.sets, updated_by = EXCLUDED.updated_by, updated_at = now() \
         RETURNING epoch, sets",
    )
    .bind(node_id)
    .bind(&sets)
    .bind(by)
    .fetch_one(db)
    .await?;
    from_row(&row)
}

/// The node's retry state; `None` when it was never bumped (epoch 0).
pub async fn get(db: impl sqlx::PgExecutor<'_>, node_id: &str) -> Result<Option<Retry>, sqlx::Error> {
    let row = sqlx::query("SELECT epoch, sets FROM noo_node_model_set_retry WHERE node_id = $1").bind(node_id).fetch_optional(db).await?;
    row.as_ref().map(from_row).transpose()
}

fn from_row(r: &sqlx::postgres::PgRow) -> Result<Retry, sqlx::Error> {
    let epoch: i64 = r.try_get("epoch")?;
    let sets: Value = r.try_get("sets")?;
    Ok(Retry {
        epoch: u64::try_from(epoch).unwrap_or(0),
        sets: sets.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every statement here against the migrated schema: the first bump
    /// makes epoch 1, each bump adds one, the sets are the last bump's, and
    /// another node's row is untouched.
    #[tokio::test]
    async fn the_epoch_round_trips_and_only_goes_up() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — model-set retry epoch round trip not exercised");
            return;
        };
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("connect");
        crate::mesh_migrate::apply_baseline(&admin).await.expect("baseline");
        crate::mesh_migrate::apply(&admin).await.expect("migrations");
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect");
        let node_a = format!("msr-a-{}", std::process::id());
        let node_b = format!("msr-b-{}", std::process::id());
        let _ = sqlx::query("DELETE FROM noo_node_model_set_retry WHERE node_id = $1 OR node_id = $2").bind(&node_a).bind(&node_b).execute(&db).await;

        assert_eq!(get(&db, &node_a).await.expect("get"), None, "never bumped");
        assert_eq!(bump(&db, &node_a, Some("rh-main@r1"), "alice").await.expect("bump"), Retry { epoch: 1, sets: vec!["rh-main@r1".into()] });
        assert_eq!(bump(&db, &node_a, None, "alice").await.expect("bump"), Retry { epoch: 2, sets: vec![] }, "no set = all");
        assert_eq!(get(&db, &node_a).await.expect("get"), Some(Retry { epoch: 2, sets: vec![] }));
        assert_eq!(get(&db, &node_b).await.expect("get"), None, "another node is untouched");
        let _ = sqlx::query("DELETE FROM noo_node_model_set_retry WHERE node_id = $1").bind(&node_a).execute(&db).await;
    }
}
