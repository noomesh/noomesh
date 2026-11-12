// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo_provision_bundles`: the three reads the bundle ETag needs
//! (0.6.24-rc.2, `crate::bundle_etag`).
//!
//! - [`key`]: the staged row's key, `(created_at, octet_length(blob))`,
//!   WITHOUT its bytes. `GET /bootstrap/bundle/<node>` decides a 304 on this
//!   alone, so an unchanged poll never reads the blob.
//! - [`blob`]: the bytes and the key of exactly those bytes, in ONE statement,
//!   so the sha remembered for a key is the sha of what was sent, whatever
//!   was re-staged in between.
//! - [`sha_in_sql`]: the key and `sha256(blob)` hashed in Postgres, in ONE
//!   statement: the fallback when the ETag cache has no entry for the
//!   current row.
//!
//! Runtime (string) queries, not `sqlx::query!`: the offline cache stays
//! unchanged, and the DB test below (`NOO_TEST_DSN`, the sqlx-drift lane)
//! runs every statement against the real migrated schema.

use crate::bundle_etag::Key;

fn key_of(created_at: chrono::DateTime<chrono::Utc>, len: i64) -> Key {
    Key { created_at_micros: created_at.timestamp_micros(), len }
}

/// The staged row's key, without reading its bytes. `None`: nothing staged.
pub async fn key(db: impl sqlx::PgExecutor<'_>, node: &str) -> Result<Option<Key>, sqlx::Error> {
    let row: Option<(chrono::DateTime<chrono::Utc>, i64)> =
        sqlx::query_as("SELECT created_at, octet_length(blob)::bigint FROM noo_provision_bundles WHERE node_name = $1")
            .bind(node)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(created_at, len)| key_of(created_at, len)))
}

/// The staged bytes and the key of exactly those bytes (one statement).
pub async fn blob(db: impl sqlx::PgExecutor<'_>, node: &str) -> Result<Option<(Key, Vec<u8>)>, sqlx::Error> {
    let row: Option<(Vec<u8>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT blob, created_at FROM noo_provision_bundles WHERE node_name = $1")
            .bind(node)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(blob, created_at)| (key_of(created_at, blob.len() as i64), blob)))
}

/// The staged row's key and the lowercase hex sha256 of its bytes, hashed in
/// Postgres (one statement).
pub async fn sha_in_sql(db: impl sqlx::PgExecutor<'_>, node: &str) -> Result<Option<(Key, String)>, sqlx::Error> {
    let row: Option<(chrono::DateTime<chrono::Utc>, i64, String)> = sqlx::query_as(
        "SELECT created_at, octet_length(blob)::bigint, encode(sha256(blob), 'hex') FROM noo_provision_bundles WHERE node_name = $1",
    )
    .bind(node)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(created_at, len, sha)| (key_of(created_at, len), sha)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What each read selects, pinned by text (the route's guards pin the
    /// ORDER of the calls): `key` never selects the bytes, `blob` takes the
    /// bytes and created_at in one statement, `sha_in_sql` the key and the
    /// hash in one statement.
    #[test]
    fn each_read_selects_exactly_what_its_caller_relies_on() {
        let code = crate::test_src::own_code(include_str!("provision_bundles.rs"));
        let key = crate::test_src::fn_body(&code, "pub async fn key(");
        assert!(key.contains("\"SELECT created_at, octet_length(blob)::bigint FROM noo_provision_bundles WHERE node_name = $1\""), "{key}");
        assert!(!key.contains("SELECT blob") && !key.contains("sha256("), "the key read never reads or hashes the bytes: {key}");
        let blob = crate::test_src::fn_body(&code, "pub async fn blob(");
        assert!(blob.contains("\"SELECT blob, created_at FROM noo_provision_bundles WHERE node_name = $1\""), "{blob}");
        assert!(blob.contains("key_of(created_at, blob.len() as i64)"), "the key is of the bytes read: {blob}");
        let sha = crate::test_src::fn_body(&code, "pub async fn sha_in_sql(");
        assert!(sha.contains("\"SELECT created_at, octet_length(blob)::bigint, encode(sha256(blob), 'hex') FROM noo_provision_bundles WHERE node_name = $1\""), "{sha}");
        assert_eq!(code.matches("sqlx::query_as(").count(), 3, "three reads, nothing else");
    }

    /// Every statement against the migrated schema, staged through the same
    /// upsert `provision_bundle_post` runs. The three reads agree on the key;
    /// the SQL hash equals a Rust hash of the bytes `blob` returns; and a
    /// re-stage of the SAME length (immediately, so within the same second)
    /// is a NEW key: the property a 304 relies on to never answer a re-staged
    /// row with the old sha.
    #[tokio::test]
    async fn the_three_reads_agree_and_a_same_length_restage_is_a_new_key() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — provision bundle reads not exercised");
            return;
        };
        use sha2::{Digest, Sha256};
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let admin = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts.clone()).await.expect("connect");
        crate::mesh_migrate::apply_baseline(&admin).await.expect("baseline");
        crate::mesh_migrate::apply(&admin).await.expect("migrations");
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect");
        let node = format!("pbetag-{}", std::process::id());
        let stage = |bytes: &'static [u8]| {
            let db = db.clone();
            let node = node.clone();
            async move {
                sqlx::query(
                    "INSERT INTO noo_provision_bundles (node_name, blob, created_at, fetched_at) \
                     VALUES ($1, $2, now(), NULL) \
                     ON CONFLICT (node_name) DO UPDATE \
                     SET blob = EXCLUDED.blob, created_at = now(), fetched_at = NULL",
                )
                .bind(&node)
                .bind(bytes)
                .execute(&db)
                .await
                .expect("stage");
            }
        };
        let _ = sqlx::query("DELETE FROM noo_provision_bundles WHERE node_name = $1").bind(&node).execute(&db).await;

        assert_eq!(key(&db, &node).await.expect("key"), None, "nothing staged");
        assert!(blob(&db, &node).await.expect("blob").is_none());
        assert!(sha_in_sql(&db, &node).await.expect("sha").is_none());

        stage(b"bundle-one").await;
        let k1 = key(&db, &node).await.expect("key").expect("staged");
        assert_eq!(k1.len, 10);
        let (kb, bytes) = blob(&db, &node).await.expect("blob").expect("staged");
        assert_eq!((kb, bytes.as_slice()), (k1, &b"bundle-one"[..]), "blob's key is the row's key");
        let (ks, sha) = sha_in_sql(&db, &node).await.expect("sha").expect("staged");
        assert_eq!(ks, k1, "sha_in_sql's key is the row's key");
        assert_eq!(sha, hex::encode(Sha256::digest(b"bundle-one")), "the SQL hash is the sha256 of the bytes");

        stage(b"bundle-two").await; // same length, same second
        let k2 = key(&db, &node).await.expect("key").expect("staged");
        assert_eq!(k2.len, k1.len);
        assert_ne!(k2, k1, "a same-length re-stage must be a new key");
        assert!(k2.created_at_micros > k1.created_at_micros);

        let _ = sqlx::query("DELETE FROM noo_provision_bundles WHERE node_name = $1").bind(&node).execute(&db).await;
    }
}
