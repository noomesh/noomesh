// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

use serde_json::Value;
use uuid::Uuid;

pub async fn owner_uuid(db: &sqlx::PgPool, owner: &str) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT user_uuid FROM noo_users WHERE username = $1")
        .bind(owner)
        .fetch_optional(db)
        .await
}

pub async fn target(
    db: &sqlx::PgPool,
    owner: Uuid,
    id: Uuid,
    provider: &str,
) -> Result<Option<Option<String>>, sqlx::Error> {
    sqlx::query_scalar("SELECT provider_subject FROM noo_connected_accounts WHERE owner_uuid = $1 AND id = $2 AND provider = $3")
        .bind(owner).bind(id).bind(provider).fetch_optional(db).await
}

pub async fn session(
    db: &sqlx::PgPool,
    owner: Uuid,
    id: Uuid,
    provider: &str,
    target: Option<Uuid>,
    completion: &str,
    state: &str,
    sealed: &Value,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query(
        "DELETE FROM noo_integration_oauth_sessions WHERE owner_uuid = $1 AND expires_at < now()",
    )
    .bind(owner)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO noo_integration_oauth_sessions (id, owner_uuid, provider, target_id, completion_hash, state_hash, sealed, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now()+interval '10 minutes')")
        .bind(id).bind(owner).bind(provider).bind(target).bind(completion).bind(state).bind(sealed).execute(&mut *tx).await?;
    tx.commit().await
}

/// Atomic, single-use consumption. A wrong owner/ticket/state does not consume it.
pub async fn take_session(
    db: &sqlx::PgPool,
    owner: Uuid,
    id: Uuid,
    ticket: &str,
    state: &str,
) -> Result<Option<(String, Option<Uuid>, Value)>, sqlx::Error> {
    sqlx::query_as("UPDATE noo_integration_oauth_sessions SET claimed_at=now() WHERE id=$1 AND owner_uuid=$2 AND completion_hash=$3 AND state_hash=$4 AND expires_at > now() AND claimed_at IS NULL RETURNING provider, target_id, sealed")
        .bind(id).bind(owner).bind(ticket).bind(state).fetch_optional(db).await
}

pub async fn cancel(db: &sqlx::PgPool, owner: Uuid, id: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT user_uuid FROM noo_users WHERE user_uuid=$1 FOR UPDATE")
        .bind(owner)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE noo_integration_pairings SET status='cancelled' WHERE session_id=$1 AND owner_uuid=$2 AND status='authorizing'")
        .bind(id).bind(owner).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM noo_integration_oauth_sessions WHERE id=$1 AND owner_uuid=$2")
        .bind(id)
        .bind(owner)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Serializes identity deduplication within one Noomesh account. No provider
/// network call occurs while this transaction is held.
pub async fn connect(
    db: &sqlx::PgPool,
    owner: Uuid,
    provider: &str,
    subject: &str,
    email: &str,
    target: Option<Uuid>,
    scopes: &[String],
    vault: &crate::integrations::crypto::Vault,
    credentials: &crate::integrations::oauth::Credentials,
    session_id: Uuid,
) -> Result<Uuid, crate::integrations::Error> {
    use crate::integrations::Error;
    let mut tx = db.begin().await?;
    // The user row serializes all account links, including the first link of
    // a previously unseen provider identity.
    sqlx::query("SELECT user_uuid FROM noo_users WHERE user_uuid=$1 FOR UPDATE")
        .bind(owner)
        .fetch_one(&mut *tx)
        .await?;
    let pending: Option<Uuid> = sqlx::query_scalar("SELECT id FROM noo_integration_oauth_sessions WHERE id=$1 AND owner_uuid=$2 AND provider=$3 AND claimed_at IS NOT NULL AND expires_at>now() FOR UPDATE")
        .bind(session_id).bind(owner).bind(provider).fetch_optional(&mut *tx).await?;
    if pending.is_none() {
        return Err(Error::Invalid(
            "Sign-in expired or was cancelled. Connect again".into(),
        ));
    }
    // Pairing cancellation/expiry must win even when Google responds while
    // the execution terminal is cancelling. This shares the user-row lock
    // with cancellation and erasure, and commits with credential storage.
    let pairing: Option<(String, bool)> = sqlx::query_as("SELECT status, expires_at>now() FROM noo_integration_pairings WHERE session_id=$1 AND owner_uuid=$2 FOR UPDATE")
        .bind(session_id).bind(owner).fetch_optional(&mut *tx).await?;
    if pairing.is_some_and(|(status, valid)| status != "authorizing" || !valid) {
        return Err(Error::Invalid(
            "Pairing expired or was cancelled. Start again from the terminal".into(),
        ));
    }
    if let Some(target) = target {
        let old: Option<Option<String>> = sqlx::query_scalar("SELECT provider_subject FROM noo_connected_accounts WHERE id=$1 AND owner_uuid=$2 AND provider=$3 FOR UPDATE")
            .bind(target).bind(owner).bind(provider).fetch_optional(&mut *tx).await?;
        match old {
            None => return Err(Error::NotFound),
            Some(Some(ref old)) if old != subject => {
                return Err(Error::Invalid(
                    "Choose the same Google account when reconnecting, or add another account"
                        .into(),
                ))
            }
            _ => {}
        }
    }
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT id FROM noo_connected_accounts WHERE owner_uuid=$1 AND provider=$2 AND provider_subject=$3")
        .bind(owner).bind(provider).bind(subject).fetch_optional(&mut *tx).await?;
    let id = existing.or(target).unwrap_or_else(Uuid::new_v4);
    sqlx::query("INSERT INTO noo_connected_accounts (id,owner_uuid,provider,label,status,provider_subject,email,granted_scopes) VALUES ($1,$2,$3,$4,'connected',$5,$4,$6) ON CONFLICT (id) DO UPDATE SET status='connected',provider_subject=EXCLUDED.provider_subject,email=EXCLUDED.email,granted_scopes=EXCLUDED.granted_scopes,updated_at=now()")
        .bind(id).bind(owner).bind(provider).bind(email).bind(subject).bind(scopes).execute(&mut *tx).await?;
    let sealed = vault.seal(
        credentials,
        &crate::integrations::oauth::credential_context(owner, provider, id),
    )?;
    sqlx::query("INSERT INTO noo_integration_credentials (account_id,owner_uuid,sealed) VALUES ($1,$2,$3) ON CONFLICT (account_id) DO UPDATE SET sealed=EXCLUDED.sealed,updated_at=now()")
        .bind(id).bind(owner).bind(&sealed).execute(&mut *tx).await?;
    if let Some(draft) = target.filter(|d| *d != id) {
        sqlx::query(
            "UPDATE noo_connection_sources SET account_id=$1 WHERE account_id=$2 AND owner_uuid=$3",
        )
        .bind(id)
        .bind(draft)
        .bind(owner)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM noo_connected_accounts WHERE id=$1 AND owner_uuid=$2")
            .bind(draft)
            .bind(owner)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE noo_integration_pairings SET status='connected',account_id=$3 WHERE session_id=$1 AND owner_uuid=$2 AND status='authorizing'")
        .bind(session_id).bind(owner).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM noo_integration_oauth_sessions WHERE id=$1 AND owner_uuid=$2")
        .bind(session_id)
        .bind(owner)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn lock_credential<'a>(
    tx: &mut sqlx::Transaction<'a, sqlx::Postgres>,
    owner: Uuid,
    id: Uuid,
) -> Result<Option<(String, Value)>, sqlx::Error> {
    sqlx::query_as("SELECT a.provider, c.sealed FROM noo_connected_accounts a JOIN noo_integration_credentials c ON c.account_id=a.id AND c.owner_uuid=a.owner_uuid WHERE a.id=$1 AND a.owner_uuid=$2 AND a.status='connected' FOR UPDATE OF a,c")
        .bind(id).bind(owner).fetch_optional(&mut **tx).await
}

pub async fn save_refreshed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    id: Uuid,
    sealed: &Value,
    scopes: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE noo_integration_credentials SET sealed=$3,updated_at=now() WHERE account_id=$1 AND owner_uuid=$2").bind(id).bind(owner).bind(sealed).execute(&mut **tx).await?;
    sqlx::query("UPDATE noo_connected_accounts SET granted_scopes=$3,updated_at=now() WHERE id=$1 AND owner_uuid=$2").bind(id).bind(owner).bind(scopes).execute(&mut **tx).await?;
    Ok(())
}

pub async fn reauth(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE noo_connected_accounts SET status='reauth_required',updated_at=now() WHERE id=$1 AND owner_uuid=$2").bind(id).bind(owner).execute(&mut **tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::{
        crypto::{hash, Vault},
        oauth::Credentials,
    };
    use serde_json::json;

    async fn link(
        db: &sqlx::PgPool,
        owner: Uuid,
        provider: &str,
        subject: &str,
        email: &str,
        target: Option<Uuid>,
        scopes: &[String],
        vault: &Vault,
        credentials: &Credentials,
    ) -> Result<Uuid, crate::integrations::Error> {
        let id = Uuid::new_v4();
        session(db, owner, id, provider, None, "ticket", "state", &json!({})).await?;
        take_session(db, owner, id, "ticket", "state").await?;
        connect(
            db,
            owner,
            provider,
            subject,
            email,
            target,
            scopes,
            vault,
            credentials,
            id,
        )
        .await
    }

    #[tokio::test]
    async fn integration_sessions_and_credentials_are_owner_bound_and_single_use() {
        let Ok(dsn) = std::env::var("NOO_BROKER_TEST_DSN") else {
            return;
        };
        let admin = sqlx::PgPool::connect(&dsn).await.unwrap();
        let schema = format!("integration_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let search_path = schema.clone();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |conn, _| {
                let sql = format!("SET search_path TO {search_path}");
                Box::pin(async move {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                        .execute(conn)
                        .await
                        .map(|_| ())
                })
            })
            .connect(&dsn)
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TABLE noo_users (user_uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text UNIQUE NOT NULL); INSERT INTO noo_users (username) VALUES ('alice'),('bob')").execute(&db).await.unwrap();
        let migration = crate::mesh_migrate::MIGRATIONS
            .iter()
            .find(|m| m.revision == crate::mesh_migrate::CONNECTIONS_REVISION)
            .unwrap();
        sqlx::raw_sql(migration.sql).execute(&db).await.unwrap();
        sqlx::raw_sql(include_str!("../integrations/schema.sql"))
            .execute(&db)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../integrations/pairing.sql"))
            .execute(&db)
            .await
            .unwrap();
        let alice = owner_uuid(&db, "alice").await.unwrap().unwrap();
        let bob = owner_uuid(&db, "bob").await.unwrap().unwrap();
        let vault = Vault::from_secret(&"test-key".repeat(8)).unwrap();
        let scopes = vec!["https://www.googleapis.com/auth/gmail.readonly".to_string()];
        let credentials: Credentials = serde_json::from_value(json!({"access_token":"access-private","refresh_token":"refresh-private","expires_at":100,"scopes":scopes,"client_kind":"desktop","client_id":"test-client"})).unwrap();
        let a = link(
            &db,
            alice,
            "google",
            "subject-a",
            "a@example.test",
            None,
            &scopes,
            &vault,
            &credentials,
        )
        .await
        .unwrap();
        let other = link(
            &db,
            alice,
            "google",
            "subject-b",
            "b@example.test",
            None,
            &scopes,
            &vault,
            &credentials,
        )
        .await
        .unwrap();
        let b = link(
            &db,
            bob,
            "google",
            "subject-a",
            "a@example.test",
            None,
            &scopes,
            &vault,
            &credentials,
        )
        .await
        .unwrap();
        assert_ne!(a, other);
        assert_ne!(a, b);
        assert_eq!(
            link(
                &db,
                alice,
                "google",
                "subject-a",
                "new@example.test",
                None,
                &scopes,
                &vault,
                &credentials
            )
            .await
            .unwrap(),
            a
        );
        assert!(link(
            &db,
            alice,
            "google",
            "subject-wrong",
            "wrong@example.test",
            Some(a),
            &scopes,
            &vault,
            &credentials
        )
        .await
        .is_err());
        assert!(link(
            &db,
            bob,
            "google",
            "subject-a",
            "a@example.test",
            Some(a),
            &scopes,
            &vault,
            &credentials
        )
        .await
        .is_err());
        let mut tx = db.begin().await.unwrap();
        assert!(lock_credential(&mut tx, bob, a).await.unwrap().is_none());
        let (_, sealed) = lock_credential(&mut tx, alice, a).await.unwrap().unwrap();
        assert!(!sealed.to_string().contains("private"));
        assert!(vault
            .open::<Credentials>(
                &sealed,
                &crate::integrations::oauth::credential_context(bob, "google", a)
            )
            .is_err());
        let decoded: Credentials = vault
            .open(
                &sealed,
                &crate::integrations::oauth::credential_context(alice, "google", a),
            )
            .unwrap();
        assert_eq!(decoded.refresh_token, "refresh-private");
        tx.rollback().await.unwrap();
        let id = Uuid::new_v4();
        session(
            &db,
            alice,
            id,
            "google",
            Some(a),
            &hash("ticket"),
            &hash("state"),
            &json!({"encrypted":"pending"}),
        )
        .await
        .unwrap();
        assert!(take_session(&db, bob, id, &hash("ticket"), &hash("state"))
            .await
            .unwrap()
            .is_none());
        assert!(take_session(&db, alice, id, &hash("wrong"), &hash("state"))
            .await
            .unwrap()
            .is_none());
        assert!(
            take_session(&db, alice, id, &hash("ticket"), &hash("wrong"))
                .await
                .unwrap()
                .is_none()
        );
        let ticket_hash = hash("ticket");
        let state_hash = hash("state");
        let (one, two) = tokio::join!(
            take_session(&db, alice, id, &ticket_hash, &state_hash),
            take_session(&db, alice, id, &ticket_hash, &state_hash)
        );
        assert_eq!(
            [one.unwrap(), two.unwrap()]
                .iter()
                .filter(|v| v.is_some())
                .count(),
            1
        );
        cancel(&db, alice, id).await.unwrap();
        assert!(
            connect(
                &db,
                alice,
                "google",
                "cancelled-sub",
                "cancelled@example.test",
                None,
                &scopes,
                &vault,
                &credentials,
                id
            )
            .await
            .is_err(),
            "cancel after code claim must prevent storing credentials"
        );
        session(
            &db,
            alice,
            id,
            "google",
            None,
            &hash("ticket"),
            &hash("state"),
            &json!({}),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE noo_integration_oauth_sessions SET expires_at=now()-interval '1 second' WHERE id=$1").bind(id).execute(&db).await.unwrap();
        assert!(
            take_session(&db, alice, id, &hash("ticket"), &hash("state"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(connect(
            &db,
            alice,
            "google",
            "expired-sub",
            "expired@example.test",
            None,
            &scopes,
            &vault,
            &credentials,
            id
        )
        .await
        .is_err());
        // Pairing uses the existing encrypted grant lifecycle, with atomic
        // completion and cancellation, and never crosses Noomesh owners.
        for mode in ["success", "cancelled", "expired"] {
            let pairing_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            let code = hash("ABCDEFGHJK");
            sqlx::query("INSERT INTO noo_integration_pairings (id,owner_uuid,code_hash,provider,services,device_name,expires_at) VALUES ($1,$2,$3,'google',ARRAY['gmail'],'execution computer',now()+interval '10 minutes')")
                .bind(pairing_id).bind(alice).bind(&code).execute(&db).await.unwrap();
            assert!(
                crate::integrations::pairing::lookup(&db, bob, "ABCDE-FGHJK")
                    .await
                    .is_err()
            );
            assert!(crate::integrations::pairing::status(&db, bob, pairing_id)
                .await
                .is_err());
            let preview = crate::integrations::pairing::lookup(&db, alice, "abcde fghjk")
                .await
                .unwrap();
            assert_eq!(preview["device_name"], "execution computer");
            let mut config = crate::integrations::IntegrationConfig::default();
            config.providers.insert(
                "google".into(),
                crate::integrations::OAuthApps {
                    web_redirect_uri: "https://noomesh.example/api/connections/oauth/callback"
                        .into(),
                    ..Default::default()
                },
            );
            assert!(crate::integrations::pairing::approve(
                &db,
                &config,
                alice,
                "ABCDE-FGHJK",
                Some("https://wrong.example")
            )
            .await
            .is_err());
            assert_eq!(
                crate::integrations::pairing::status(&db, alice, pairing_id)
                    .await
                    .unwrap()["status"],
                "pending"
            );
            session(
                &db,
                alice,
                session_id,
                "google",
                None,
                "ticket",
                "state",
                &json!({}),
            )
            .await
            .unwrap();
            sqlx::query("UPDATE noo_integration_pairings SET status='authorizing',session_id=$2 WHERE id=$1").bind(pairing_id).bind(session_id).execute(&db).await.unwrap();
            take_session(&db, alice, session_id, "ticket", "state")
                .await
                .unwrap()
                .unwrap();
            assert!(
                crate::integrations::pairing::lookup(&db, alice, "ABCDE-FGHJK")
                    .await
                    .is_err()
            );
            crate::integrations::pairing::cancel(&db, bob, pairing_id)
                .await
                .unwrap();
            assert_eq!(
                crate::integrations::pairing::status(&db, alice, pairing_id)
                    .await
                    .unwrap()["status"],
                "authorizing"
            );
            if mode == "cancelled" {
                crate::integrations::pairing::cancel(&db, alice, pairing_id)
                    .await
                    .unwrap();
            } else if mode == "expired" {
                sqlx::query("UPDATE noo_integration_pairings SET expires_at=now()-interval '1 second' WHERE id=$1").bind(pairing_id).execute(&db).await.unwrap();
            }
            let result = connect(
                &db,
                alice,
                "google",
                &format!("pair-{mode}"),
                "paired@example.test",
                None,
                &scopes,
                &vault,
                &credentials,
                session_id,
            )
            .await;
            assert_eq!(result.is_ok(), mode == "success");
            let status = crate::integrations::pairing::status(&db, alice, pairing_id)
                .await
                .unwrap();
            assert_eq!(
                status["status"],
                if mode == "success" { "connected" } else { mode }
            );
            if let Ok(account) = result {
                assert_eq!(status["account_id"], account.to_string());
            }
            sqlx::query("DELETE FROM noo_integration_pairings WHERE id=$1")
                .bind(pairing_id)
                .execute(&db)
                .await
                .unwrap();
        }
        assert!(crate::repo::connections::delete_account(&db, "alice", a)
            .await
            .unwrap());
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM noo_integration_credentials WHERE account_id=$1",
        )
        .bind(a)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(count, 0);
        assert_eq!(
            crate::repo::connections::accounts(&db, "bob")
                .await
                .unwrap()
                .len(),
            1
        );
        // Erasure cascades credentials and pending grants even when other users share Google's subject.
        sqlx::query("DELETE FROM noo_users WHERE user_uuid=$1")
            .bind(alice)
            .execute(&db)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM noo_integration_oauth_sessions WHERE owner_uuid=$1",
        )
        .bind(alice)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(count, 0);
        db.close().await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
            .execute(&admin)
            .await
            .unwrap();
    }
}
