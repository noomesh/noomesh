// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Kiosk seats bound to their tailnet device, and revoked (i510 part B).
//!
//! A display mints a kiosk token only as an enrolled, unrevoked seat whose
//! bound tailnet name is the device the keyless mint's whois named. The seat
//! reports that name on its own signed rail (its heartbeat); an admin can
//! bind it explicitly. One device belongs to one seat (a partial unique index
//! on `lower(tailnet_name)`), so a second seat's claim is refused, not merged.

use sqlx::PgPool;

/// Why a tailnet name could not be recorded for a seat.
#[derive(Debug)]
pub enum BindError {
    /// No enrolled seat has that name.
    NoSeat,
    /// Another seat already holds this device.
    TakenBy(String),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for BindError {
    fn from(e: sqlx::Error) -> Self {
        BindError::Db(e)
    }
}

/// The enrolled, unrevoked seat bound to this tailnet device, if any.
pub async fn seat_for_tailnet(db: &PgPool, tailnet_name: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT seat_name FROM noo_seats WHERE lower(tailnet_name) = lower($1) AND revoked_at IS NULL",
    )
    .bind(tailnet_name)
    .fetch_optional(db)
    .await
}

/// Bind `seat` to `tailnet_name`. Returns whether the stored name changed.
/// A device another seat holds is refused with that seat's name.
pub async fn bind_tailnet(db: &PgPool, seat: &str, tailnet_name: &str) -> Result<bool, BindError> {
    let holder: Option<String> = sqlx::query_scalar(
        "SELECT seat_name FROM noo_seats WHERE lower(tailnet_name) = lower($1) AND seat_name <> $2",
    )
    .bind(tailnet_name)
    .bind(seat)
    .fetch_optional(db)
    .await?;
    if let Some(other) = holder {
        return Err(BindError::TakenBy(other));
    }
    let changed = sqlx::query(
        "UPDATE noo_seats SET tailnet_name = $2 WHERE seat_name = $1 AND tailnet_name IS DISTINCT FROM $2",
    )
    .bind(seat)
    .bind(tailnet_name)
    .execute(db)
    .await?
    .rows_affected();
    if changed == 0 {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM noo_seats WHERE seat_name = $1)")
            .bind(seat)
            .fetch_one(db)
            .await?;
        if !exists {
            return Err(BindError::NoSeat);
        }
    }
    Ok(changed > 0)
}

/// Revoke `seat`: its rail and its display are refused until it re-enrols.
/// Returns false when no such seat is enrolled. Revoking twice keeps the
/// first time and actor.
pub async fn revoke(db: &PgPool, seat: &str, by: &str) -> Result<bool, sqlx::Error> {
    let n = sqlx::query(
        "UPDATE noo_seats SET revoked_at = COALESCE(revoked_at, now()), revoked_by = COALESCE(revoked_by, $2) \
         WHERE seat_name = $1",
    )
    .bind(seat)
    .bind(by)
    .execute(db)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// The display settings the controller set for the unrevoked seat bound to
/// this tailnet device: `Some({})` when none are set, `None` when the device
/// is no seat's.
pub async fn display_for_tailnet(db: &PgPool, tailnet_name: &str) -> Result<Option<(String, serde_json::Value)>, sqlx::Error> {
    let row: Option<(String, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT seat_name, display FROM noo_seats WHERE lower(tailnet_name) = lower($1) AND revoked_at IS NULL",
    )
    .bind(tailnet_name)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(seat, d)| (seat, d.unwrap_or_else(|| serde_json::json!({})))))
}

/// The display settings stored for `seat` (`{}` when none), or `None` when
/// no such seat is enrolled.
pub async fn display_of(db: &PgPool, seat: &str) -> Result<Option<serde_json::Value>, sqlx::Error> {
    let row: Option<(Option<serde_json::Value>,)> = sqlx::query_as("SELECT display FROM noo_seats WHERE seat_name = $1")
        .bind(seat)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|(d,)| d.unwrap_or_else(|| serde_json::json!({}))))
}

/// Store `display` for `seat`. Returns false when no such seat is enrolled.
pub async fn set_display(db: &PgPool, seat: &str, display: &serde_json::Value, by: &str) -> Result<bool, sqlx::Error> {
    let n = sqlx::query(
        "UPDATE noo_seats SET display = $2, display_set_by = $3, display_set_at = now() WHERE seat_name = $1",
    )
    .bind(seat)
    .bind(display)
    .bind(by)
    .execute(db)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// The staged seat bundle row's key (`created_at`, byte length), without
/// its bytes (i675 F3: the 304 decision). `None`: nothing staged.
pub async fn bundle_key(db: &PgPool, seat: &str) -> Result<Option<crate::bundle_etag::Key>, sqlx::Error> {
    let row: Option<(chrono::DateTime<chrono::Utc>, i64)> =
        sqlx::query_as("SELECT created_at, octet_length(blob)::bigint FROM noo_seat_bundles WHERE seat_name = $1")
            .bind(seat)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(created_at, len)| crate::repo::provision_bundles::key_of(created_at, len)))
}

/// The staged seat bundle's bytes and the key of exactly those bytes (one
/// statement).
pub async fn bundle_blob(db: &PgPool, seat: &str) -> Result<Option<(crate::bundle_etag::Key, Vec<u8>)>, sqlx::Error> {
    let row: Option<(Vec<u8>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT blob, created_at FROM noo_seat_bundles WHERE seat_name = $1")
            .bind(seat)
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(blob, created_at)| (crate::repo::provision_bundles::key_of(created_at, blob.len() as i64), blob)))
}

/// The staged seat bundle's key and the lowercase hex sha256 of its bytes,
/// hashed in Postgres (one statement): only on an ETag-cache miss.
pub async fn bundle_sha_in_sql(db: &PgPool, seat: &str) -> Result<Option<(crate::bundle_etag::Key, String)>, sqlx::Error> {
    let row: Option<(chrono::DateTime<chrono::Utc>, i64, String)> = sqlx::query_as(
        "SELECT created_at, octet_length(blob)::bigint, encode(sha256(blob), 'hex') FROM noo_seat_bundles WHERE seat_name = $1",
    )
    .bind(seat)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(created_at, len, sha)| (crate::repo::provision_bundles::key_of(created_at, len), sha)))
}

#[cfg(test)]
mod db_tests {
    use super::*;

    /// One device belongs to one seat; a revoked seat is not a device's seat;
    /// re-binding the same name changes nothing. Against the migrated schema.
    #[tokio::test]
    async fn a_device_belongs_to_one_unrevoked_seat() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — seat binding not exercised");
            return;
        };
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect scratch db");
        crate::mesh_migrate::apply_baseline(&db).await.expect("baseline");
        crate::mesh_migrate::apply(&db).await.expect("migrations");
        let tag = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        let (a, b, dev) = (format!("sa{tag}"), format!("sb{tag}"), format!("dev{tag}-1"));
        for seat in [&a, &b] {
            sqlx::query("INSERT INTO noo_seats (seat_name, birth_cert) VALUES ($1, 'cert')")
                .bind(seat).execute(&db).await.unwrap();
        }
        assert_eq!(seat_for_tailnet(&db, &dev).await.unwrap(), None, "unbound: no seat");
        assert!(bind_tailnet(&db, &a, &dev).await.unwrap(), "first bind changes the row");
        assert!(!bind_tailnet(&db, &a, &dev).await.unwrap(), "the same bind again changes nothing");
        assert_eq!(seat_for_tailnet(&db, &dev.to_uppercase()).await.unwrap().as_deref(), Some(a.as_str()));
        assert!(matches!(bind_tailnet(&db, &b, &dev).await, Err(BindError::TakenBy(ref s)) if *s == a));
        assert!(matches!(bind_tailnet(&db, "no-such-seat", &format!("x{tag}")).await, Err(BindError::NoSeat)));
        assert!(revoke(&db, &a, "admin-fixture").await.unwrap());
        assert_eq!(seat_for_tailnet(&db, &dev).await.unwrap(), None, "a revoked seat is not the device's seat");
        assert!(!revoke(&db, "no-such-seat", "admin-fixture").await.unwrap());
        sqlx::query("DELETE FROM noo_seats WHERE seat_name = ANY($1)").bind(vec![a, b]).execute(&db).await.unwrap();
    }

    /// i675 F3: the three seat-bundle reads, against the migrated schema.
    /// Nothing staged: all None. Staged: the key is (created_at, length),
    /// the blob read carries the same key, and Postgres's sha is the sha of
    /// those bytes; a re-stage is a new key.
    #[tokio::test]
    async fn the_seat_bundle_reads_agree_on_key_and_sha() {
        let Some(dsn) = std::env::var("NOO_TEST_DSN").ok().filter(|v| !v.trim().is_empty()) else {
            eprintln!("NOO_TEST_DSN unset — seat bundle reads not exercised");
            return;
        };
        use std::str::FromStr as _;
        let opts = sqlx::postgres::PgConnectOptions::from_str(&dsn).expect("dsn").options([("search_path", "mesh,public")]);
        let db = sqlx::postgres::PgPoolOptions::new().max_connections(2).connect_with(opts).await.expect("connect scratch db");
        crate::mesh_migrate::apply_baseline(&db).await.expect("baseline");
        crate::mesh_migrate::apply(&db).await.expect("migrations");
        let seat = format!("sbundle{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        sqlx::query("INSERT INTO noo_seats (seat_name, birth_cert) VALUES ($1, 'cert')").bind(&seat).execute(&db).await.unwrap();
        assert!(bundle_key(&db, &seat).await.unwrap().is_none());
        assert!(bundle_blob(&db, &seat).await.unwrap().is_none());
        assert!(bundle_sha_in_sql(&db, &seat).await.unwrap().is_none());
        let stage = |bytes: &'static [u8]| {
            let (db, seat) = (db.clone(), seat.clone());
            async move {
                sqlx::query(
                    "INSERT INTO noo_seat_bundles (seat_name, blob, created_at, fetched_at) VALUES ($1, $2, clock_timestamp(), NULL) \
                     ON CONFLICT (seat_name) DO UPDATE SET blob = EXCLUDED.blob, created_at = clock_timestamp(), fetched_at = NULL",
                ).bind(&seat).bind(bytes).execute(&db).await.unwrap();
            }
        };
        stage(b"first bundle").await;
        let key = bundle_key(&db, &seat).await.unwrap().expect("staged");
        assert_eq!(key.len, 12);
        let (bkey, blob) = bundle_blob(&db, &seat).await.unwrap().expect("staged");
        assert_eq!((bkey, blob.as_slice()), (key, &b"first bundle"[..]));
        let (skey, sha) = bundle_sha_in_sql(&db, &seat).await.unwrap().expect("staged");
        use sha2::{Digest, Sha256};
        assert_eq!((skey, sha), (key, hex::encode(Sha256::digest(b"first bundle"))));
        stage(b"second bundl").await;
        let key2 = bundle_key(&db, &seat).await.unwrap().expect("re-staged");
        assert_eq!(key2.len, key.len, "same length on purpose");
        assert_ne!(key2, key, "a re-stage of the same length is a new key");
        sqlx::query("DELETE FROM noo_seat_bundles WHERE seat_name = $1").bind(&seat).execute(&db).await.unwrap();
        sqlx::query("DELETE FROM noo_seats WHERE seat_name = $1").bind(&seat).execute(&db).await.unwrap();
    }
}
