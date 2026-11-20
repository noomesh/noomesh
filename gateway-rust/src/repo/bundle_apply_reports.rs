// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The node's apply report on its staged bundle (`noo_provision_bundles`,
//! migrations 055 and 126): the applier's exit code, its message and the
//! refusal NAME. The route (`routes/bootstrap.rs` `bundle_apply_report`)
//! checks the proof and the sha; the write and the name's shape live here.

/// The refusal name as the row stores it: the node's `refusal` field when the
/// apply was refused (`rc != 0`) and the field is a name — `[a-z][a-z0-9_]`,
/// at most 48 characters — else `None`. The gateway keeps no table of names:
/// it stores a well-formed token and the CLI judges it (a name only counts
/// there when its code is the reported rc).
pub fn refusal_token(rc: i32, raw: Option<&str>) -> Option<String> {
    let n = raw?;
    let ok = rc != 0
        && (1..=48).contains(&n.len())
        && n.starts_with(|c: char| c.is_ascii_lowercase())
        && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    ok.then(|| n.to_string())
}

/// Record a report on the node's row. `refusal` is ALWAYS written (NULL when
/// the report named none), so a name from an earlier report never survives a
/// later one that carried none.
pub async fn record(
    db: impl sqlx::PgExecutor<'_>,
    node: &str,
    sha: &str,
    rc: i32,
    msg: &str,
    refusal: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE noo_provision_bundles SET applied_at = now(), applied_sha = $2, apply_rc = $3, apply_msg = $4, apply_refusal = $5 \
         WHERE node_name = $1",
    )
    .bind(node)
    .bind(sha)
    .bind(rc)
    .bind(msg)
    .bind(refusal)
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_well_formed_name_on_a_refusal_is_kept() {
        assert_eq!(refusal_token(65, Some("bundle_shape")).as_deref(), Some("bundle_shape"));
        assert_eq!(refusal_token(77, Some("a")).as_deref(), Some("a"));
        let longest = "a".repeat(48);
        assert_eq!(refusal_token(65, Some(longest.as_str())).as_deref(), Some(longest.as_str()));
        assert_eq!(refusal_token(0, Some("bundle_shape")), None, "a success carries no refusal");
        assert_eq!(refusal_token(65, None), None);
        let too_long = "a".repeat(49);
        for bad in ["", "Bundle", "9x", "_x", "bundle-shape", "a b", "x\",\"rc\":0", "bündle", too_long.as_str()] {
            assert_eq!(refusal_token(65, Some(bad)), None, "{bad:?}");
        }
    }

    /// Against the migrated schema: a valid name is stored, an invalid one
    /// and a success store NULL, and a later report without a name clears an
    /// earlier name.
    #[tokio::test]
    async fn the_name_is_stored_and_a_later_report_without_one_clears_it() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — apply report refusal column not exercised");
            return;
        };
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("connect");
        crate::mesh_migrate::apply_baseline(&admin).await.expect("baseline");
        crate::mesh_migrate::apply(&admin).await.expect("migrations");
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect");
        let node = format!("barefusal-{}", std::process::id());
        let _ = sqlx::query("DELETE FROM noo_provision_bundles WHERE node_name = $1").bind(&node).execute(&db).await;
        sqlx::query("INSERT INTO noo_provision_bundles (node_name, blob, created_at) VALUES ($1, $2, now())")
            .bind(&node)
            .bind(&b"bundle"[..])
            .execute(&db)
            .await
            .expect("stage");
        let stored = |db: sqlx::PgPool, node: String| async move {
            let row: (Option<i32>, Option<String>) =
                sqlx::query_as("SELECT apply_rc, apply_refusal FROM noo_provision_bundles WHERE node_name = $1")
                    .bind(&node)
                    .fetch_one(&db)
                    .await
                    .expect("row");
            row
        };
        let sha = "a".repeat(64);

        record(&db, &node, &sha, 65, "m", refusal_token(65, Some("bundle_shape")).as_deref()).await.expect("record");
        assert_eq!(stored(db.clone(), node.clone()).await, (Some(65), Some("bundle_shape".to_string())));

        record(&db, &node, &sha, 65, "m", refusal_token(65, Some("x\",\"rc\":0")).as_deref()).await.expect("record");
        assert_eq!(stored(db.clone(), node.clone()).await, (Some(65), None), "an invalid name is NULL");

        record(&db, &node, &sha, 77, "m", refusal_token(77, Some("signature_invalid")).as_deref()).await.expect("record");
        record(&db, &node, &sha, 77, "m", None).await.expect("record");
        assert_eq!(stored(db.clone(), node.clone()).await, (Some(77), None), "an older fetcher's report clears the name");

        record(&db, &node, &sha, 0, "applied", refusal_token(0, Some("bundle_shape")).as_deref()).await.expect("record");
        assert_eq!(stored(db.clone(), node.clone()).await, (Some(0), None), "a success stores no name");

        let _ = sqlx::query("DELETE FROM noo_provision_bundles WHERE node_name = $1").bind(&node).execute(&db).await;
    }
}
