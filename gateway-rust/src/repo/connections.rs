// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Private connection drafts. Every query derives ownership from the
//! authenticated Noomesh account. Operators get the same private view.

use serde_json::Value;
use uuid::Uuid;

pub async fn accounts(db: &sqlx::PgPool, owner: &str) -> Result<Vec<Value>, sqlx::Error> {
    sqlx::query_scalar::<_, Value>(
        r#"SELECT jsonb_build_object('id', a.id, 'provider', a.provider, 'label', a.label,
            'email_hint', a.email_hint, 'status', a.status, 'created_at', a.created_at) AS account
           FROM noo_connected_accounts a JOIN noo_users u ON u.user_uuid = a.owner_uuid
           WHERE u.username = $1 ORDER BY a.created_at, a.id"#,
    )
    .bind(owner)
    .fetch_all(db)
    .await
}

pub async fn create_account(
    db: &sqlx::PgPool,
    owner: &str,
    id: Uuid,
    draft: &crate::connections::AccountDraft,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO noo_connected_accounts (id, owner_uuid, provider, label, email_hint) \
         SELECT $1, user_uuid, 'google', $3, $4 FROM noo_users WHERE username = $2 \
         RETURNING id",
    )
    .bind(id)
    .bind(owner)
    .bind(&draft.label)
    .bind(&draft.email_hint)
    .fetch_optional(db)
    .await
}

/// Also removes its draft sources via the composite foreign key.
pub async fn delete_account(db: &sqlx::PgPool, owner: &str, id: Uuid) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM noo_connected_accounts WHERE id = $1 AND owner_uuid = \
         (SELECT user_uuid FROM noo_users WHERE username = $2) AND status = 'needs_auth'",
    )
    .bind(id)
    .bind(owner)
    .execute(db)
    .await?
    .rows_affected()
        != 0)
}

pub async fn sources(db: &sqlx::PgPool, owner: &str) -> Result<Vec<Value>, sqlx::Error> {
    sqlx::query_scalar::<_, Value>(
        r#"SELECT jsonb_build_object('id', s.id, 'account_id', s.account_id, 'name', s.name,
            'policy', s.policy, 'status', s.status, 'visibility', 'private',
            'access', 'read_only', 'created_at', s.created_at) AS source
           FROM noo_connection_sources s JOIN noo_users u ON u.user_uuid = s.owner_uuid
           WHERE u.username = $1 ORDER BY s.created_at, s.id"#,
    )
    .bind(owner)
    .fetch_all(db)
    .await
}

pub async fn create_source(
    db: &sqlx::PgPool,
    owner: &str,
    id: Uuid,
    draft: &crate::connections::SourceDraft,
    policy: &Value,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO noo_connection_sources (id, owner_uuid, account_id, name, kind, policy) \
         SELECT $1, a.owner_uuid, a.id, $4, $5, $6 FROM noo_connected_accounts a \
         JOIN noo_users u ON u.user_uuid = a.owner_uuid WHERE u.username = $2 AND a.id = $3 \
         RETURNING id",
    )
    .bind(id)
    .bind(owner)
    .bind(draft.account_id)
    .bind(&draft.name)
    .bind(draft.policy.kind())
    .bind(policy)
    .fetch_optional(db)
    .await
}

pub async fn delete_source(db: &sqlx::PgPool, owner: &str, id: Uuid) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM noo_connection_sources WHERE id = $1 AND owner_uuid = \
         (SELECT user_uuid FROM noo_users WHERE username = $2) AND status = 'draft'",
    )
    .bind(id)
    .bind(owner)
    .execute(db)
    .await?
    .rows_affected()
        != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::{AccountDraft, SourceDraft};
    use serde_json::json;

    /// The real migration, not a second hand-written version of the tables.
    /// CI supplies a scratch database, as for the broker's other SQL tests.
    #[tokio::test]
    async fn connections_keep_multiple_accounts_and_sources_private() {
        let Some(dsn) = std::env::var("NOO_BROKER_TEST_DSN")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            return;
        };
        let admin = sqlx::PgPool::connect(&dsn).await.unwrap();
        let schema = format!("connections_{}", Uuid::new_v4().simple());
        // Identifier consists of a fixed prefix and a generated UUID only.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let search_path = schema.clone();
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
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
        sqlx::raw_sql("CREATE TABLE noo_users (user_uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text UNIQUE NOT NULL); INSERT INTO noo_users (username) VALUES ('alice'), ('bob')")
            .execute(&db).await.unwrap();
        let migration = crate::mesh_migrate::MIGRATIONS
            .iter()
            .find(|m| m.revision == crate::mesh_migrate::CONNECTIONS_REVISION)
            .unwrap();
        sqlx::raw_sql(migration.sql).execute(&db).await.unwrap();
        let draft = AccountDraft {
            label: "Work".into(),
            email_hint: Some("person@example.test".into()),
        };
        let a = create_account(&db, "alice", Uuid::new_v4(), &draft)
            .await
            .unwrap()
            .unwrap();
        let a2 = create_account(&db, "alice", Uuid::new_v4(), &draft)
            .await
            .unwrap()
            .unwrap();
        let b = create_account(&db, "bob", Uuid::new_v4(), &draft)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(a, a2);
        assert_eq!(accounts(&db, "alice").await.unwrap().len(), 2);
        assert_eq!(accounts(&db, "bob").await.unwrap().len(), 1);
        assert!(create_account(&db, "missing", Uuid::new_v4(), &draft)
            .await
            .unwrap()
            .is_none());

        for (account, policy) in [
            (
                a,
                json!({"kind":"gmail","exposure":"selected_labels","label_ids":["INBOX"],"lookback_days":30}),
            ),
            (
                a,
                json!({"kind":"gmail","exposure":"selected_labels","label_ids":["Label_work"],"lookback_days":90}),
            ),
            (
                a,
                json!({"kind":"google_drive","exposure":"selected_folders","folder_ids":["folder_1"]}),
            ),
            (
                a2,
                json!({"kind":"gmail","exposure":"mailbox","lookback_days":7}),
            ),
        ] {
            let draft: SourceDraft = serde_json::from_value(
                json!({"account_id":account,"name":"Private source","policy":policy}),
            )
            .unwrap();
            assert!(create_source(&db, "alice", Uuid::new_v4(), &draft, &policy)
                .await
                .unwrap()
                .is_some());
        }
        let foreign: SourceDraft = serde_json::from_value(json!({"account_id":b,"name":"Forbidden","policy":{"kind":"gmail","exposure":"mailbox"}})).unwrap();
        assert!(create_source(
            &db,
            "alice",
            Uuid::new_v4(),
            &foreign,
            &serde_json::to_value(&foreign.policy).unwrap()
        )
        .await
        .unwrap()
        .is_none());
        let rows = sources(&db, "alice").await.unwrap();
        assert_eq!(rows.len(), 4);
        assert!(sources(&db, "bob").await.unwrap().is_empty());
        assert!(rows.iter().all(|s| s["status"] == "draft"
            && s["visibility"] == "private"
            && s["access"] == "read_only"));
        let first = rows.iter().find(|s| s["account_id"] == a.to_string()).unwrap();
        let source_id = Uuid::parse_str(first["id"].as_str().unwrap()).unwrap();
        assert!(!delete_source(&db, "bob", source_id).await.unwrap());
        assert!(!delete_account(&db, "bob", a).await.unwrap());
        assert!(delete_source(&db, "alice", source_id).await.unwrap());
        assert!(sqlx::query("INSERT INTO noo_connection_sources (id, owner_uuid, account_id, name, kind, policy) SELECT $1, user_uuid, $2, 'invalid', 'gmail', '{\"kind\":null}' FROM noo_users WHERE username='bob'")
            .bind(Uuid::new_v4()).bind(b).execute(&db).await.is_err());
        // The composite FK also blocks an accidental cross-owner insert.
        assert!(sqlx::query("INSERT INTO noo_connection_sources (id, owner_uuid, account_id, name, kind, policy) SELECT $1, user_uuid, $2, 'forged', 'gmail', '{\"kind\":\"gmail\"}' FROM noo_users WHERE username='bob'")
            .bind(Uuid::new_v4()).bind(a).execute(&db).await.is_err());
        assert!(delete_account(&db, "alice", a).await.unwrap());
        assert_eq!(
            sources(&db, "alice").await.unwrap().len(),
            1,
            "account removal cascades only that account's sources"
        );
        assert_eq!(accounts(&db, "bob").await.unwrap().len(), 1);
        assert!(
            sqlx::query("UPDATE noo_connected_accounts SET status = 'connected' WHERE id = $1")
                .bind(a2)
                .execute(&db)
                .await
                .is_err(),
            "drafts cannot become connected without a future schema change"
        );
        sqlx::query("DELETE FROM noo_users WHERE username = 'alice'")
            .execute(&db)
            .await
            .unwrap();
        assert!(sources(&db, "alice").await.unwrap().is_empty());
        assert_eq!(accounts(&db, "bob").await.unwrap().len(), 1);
        db.close().await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
