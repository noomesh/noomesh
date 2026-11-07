// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo_node_workload_placements` (migration 113, i300 H3b-2): an operator's
//! placement of an add-on node workload on one node.
//!
//! Runtime (string) queries, not `sqlx::query!`: the offline cache stays
//! unchanged, and the DB test below (`NOO_TEST_DSN`, the sqlx-drift lane) runs
//! every statement here against the real migrated schema instead.
//!
//! One row per (addon, workload). [`place`] never MOVES a workload: a row on
//! another node is a [`Placed::OnOtherNode`] refusal, and nothing is written.

use serde_json::Value;
use sqlx::Row as _;

/// One placement row.
#[derive(Debug, Clone, PartialEq)]
pub struct Placement {
    pub addon: String,
    pub workload: String,
    pub node_id: String,
    pub profile: Option<String>,
    /// `{<slot>: [{id, revision}]}`.
    pub sets: Value,
    /// `{<key>: <value>}`, already held to the declaration's bounds.
    pub env: Value,
    pub on_controller: bool,
    pub desired_state: String,
    pub reservation: Option<String>,
}

/// What [`place`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placed {
    /// Written (a new row, or the same node's row updated).
    Written,
    /// The workload is placed on this other node; nothing was written.
    OnOtherNode(String),
    /// Not written, and no row holds it now: another call removed it between
    /// this statement's two reads. Nothing was written; the caller retries.
    Raced,
}

const COLUMNS: &str = "addon, workload, node_id, profile, sets, env, on_controller, desired_state, reservation::text AS reservation";

fn from_row(r: &sqlx::postgres::PgRow) -> Result<Placement, sqlx::Error> {
    Ok(Placement {
        addon: r.try_get("addon")?,
        workload: r.try_get("workload")?,
        node_id: r.try_get("node_id")?,
        profile: r.try_get("profile")?,
        sets: r.try_get("sets")?,
        env: r.try_get("env")?,
        on_controller: r.try_get("on_controller")?,
        desired_state: r.try_get("desired_state")?,
        reservation: r.try_get("reservation")?,
    })
}

/// Write `p` (state `provisioned`) unless the workload is placed on another
/// node. A re-place on the same node replaces profile, sets, env and the
/// opt-in, and keeps its state and reservation (H4 owns those).
pub async fn place(db: impl sqlx::PgExecutor<'_>, p: &Placement) -> Result<Placed, sqlx::Error> {
    let row = sqlx::query(
        "WITH w AS ( \
           INSERT INTO noo_node_workload_placements (addon, workload, node_id, profile, sets, env, on_controller) \
           VALUES ($1, $2, $3, $4, $5, $6, $7) \
           ON CONFLICT (addon, workload) DO UPDATE SET \
             profile = EXCLUDED.profile, sets = EXCLUDED.sets, env = EXCLUDED.env, \
             on_controller = EXCLUDED.on_controller, updated_at = now() \
           RETURNING node_id) \
         SELECT (SELECT node_id FROM w) AS written, \
                (SELECT node_id FROM noo_node_workload_placements WHERE addon = $1 AND workload = $2) AS holder",
    )
    .bind(&p.addon)
    .bind(&p.workload)
    .bind(&p.node_id)
    .bind(&p.profile)
    .bind(&p.sets)
    .bind(&p.env)
    .bind(p.on_controller)
    .fetch_one(db)
    .await?;
    let written: Option<String> = row.try_get("written")?;
    let holder: Option<String> = row.try_get("holder")?;
    Ok(match (written, holder) {
        (Some(_), _) => Placed::Written,
        (None, Some(other)) => Placed::OnOtherNode(other),
        (None, None) => Placed::Raced,
    })
}

/// The placement of `addon`/`workload`, if any.
pub async fn get(db: impl sqlx::PgExecutor<'_>, addon: &str, workload: &str) -> Result<Option<Placement>, sqlx::Error> {
    let q = format!("SELECT {COLUMNS} FROM noo_node_workload_placements WHERE addon = $1 AND workload = $2");
    sqlx::query(sqlx::AssertSqlSafe(q)).bind(addon).bind(workload).fetch_optional(db).await?.as_ref().map(from_row).transpose()
}

/// Every placement on `node_id`, by addon then workload.
pub async fn for_node(db: impl sqlx::PgExecutor<'_>, node_id: &str) -> Result<Vec<Placement>, sqlx::Error> {
    let q = format!("SELECT {COLUMNS} FROM noo_node_workload_placements WHERE node_id = $1 ORDER BY addon, workload");
    sqlx::query(sqlx::AssertSqlSafe(q)).bind(node_id).fetch_all(db).await?.iter().map(from_row).collect()
}

/// Remove the placement of `addon`/`workload` on `node_id`. False when there
/// was none there.
pub async fn remove(db: impl sqlx::PgExecutor<'_>, node_id: &str, addon: &str, workload: &str) -> Result<bool, sqlx::Error> {
    let r = sqlx::query("DELETE FROM noo_node_workload_placements WHERE node_id = $1 AND addon = $2 AND workload = $3")
        .bind(node_id)
        .bind(addon)
        .bind(workload)
        .execute(db)
        .await?;
    Ok(r.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(node: &str) -> Placement {
        Placement {
            addon: "rhaddon".into(),
            workload: "worker".into(),
            node_id: node.into(),
            profile: Some("int8".into()),
            sets: json!({"main": [{"id": "rh-s2s-7b", "revision": "r1"}]}),
            env: json!({"RHADDON_SLOTS": "1"}),
            on_controller: false,
            desired_state: "provisioned".into(),
            reservation: None,
        }
    }

    /// Every statement here against the migrated schema: place, read back
    /// (one and per node), re-place on the same node, the refusal to move it
    /// to another node (which writes nothing), and remove.
    #[tokio::test]
    async fn placements_round_trip_through_postgres() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — node workload placements round trip not exercised");
            return;
        };
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("connect");
        crate::mesh_migrate::apply_baseline(&admin).await.expect("baseline");
        crate::mesh_migrate::apply(&admin).await.expect("migrations");
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect");
        let node_a = format!("nwp-a-{}", std::process::id());
        let node_b = format!("nwp-b-{}", std::process::id());
        let _ = remove(&db, &node_a, "rhaddon", "worker").await;
        let _ = remove(&db, &node_b, "rhaddon", "worker").await;

        assert_eq!(place(&db, &row(&node_a)).await.expect("place"), Placed::Written);
        let got = get(&db, "rhaddon", "worker").await.expect("get").expect("placed");
        assert_eq!(got, row(&node_a), "read back exactly, state provisioned, no reservation");
        assert_eq!(for_node(&db, &node_a).await.expect("for_node"), vec![row(&node_a)]);
        assert!(for_node(&db, &node_b).await.expect("for_node").is_empty());

        // The same node: profile, sets, env and the opt-in are replaced.
        let mut again = row(&node_a);
        again.profile = Some("bf16".into());
        again.env = json!({"RHADDON_SLOTS": "2"});
        again.on_controller = true;
        assert_eq!(place(&db, &again).await.expect("re-place"), Placed::Written);
        assert_eq!(get(&db, "rhaddon", "worker").await.unwrap().unwrap(), again);

        // Another node: refused, and nothing changes.
        assert_eq!(place(&db, &row(&node_b)).await.expect("move"), Placed::OnOtherNode(node_a.clone()));
        assert_eq!(get(&db, "rhaddon", "worker").await.unwrap().unwrap(), again, "the refusal wrote nothing");

        // Remove: only where it is.
        assert!(!remove(&db, &node_b, "rhaddon", "worker").await.expect("remove elsewhere"));
        assert!(remove(&db, &node_a, "rhaddon", "worker").await.expect("remove"));
        assert_eq!(get(&db, "rhaddon", "worker").await.unwrap(), None);
        assert!(!remove(&db, &node_a, "rhaddon", "worker").await.expect("remove twice"));
    }
}
