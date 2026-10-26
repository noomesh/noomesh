// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

use super::*;
use crate::bus_principal::{Kind, Principal};
use crate::integrations::sync::{self, Api};

struct FixtureApi;
impl Api for FixtureApi {
    async fn get(
        &self,
        gmail: bool,
        path: &[&str],
        _query: &[(String, String)],
        raw: bool,
    ) -> Result<Option<Vec<u8>>, Error> {
        if raw {
            return Ok(Some(b"Shared bytes, private canary apricot".to_vec()));
        }
        let value = if gmail {
            if path.len() == 1 {
                json!({"messages":[{"id":"sameitem"}]})
            } else {
                use base64::Engine;
                json!({"payload":{"mimeType":"text/plain","headers":[{"name":"Subject","value":"Private Gmail apricot"}],"body":{"data":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("Shared bytes, private canary apricot")}}})
            }
        } else {
            json!({"files":[{"id":"sameitem","name":"Private Drive apricot","mimeType":"text/plain"}]})
        };
        Ok(Some(serde_json::to_vec(&value).unwrap()))
    }
}

struct Db {
    pool: PgPool,
    admin: PgPool,
    schema: String,
}
impl Db {
    async fn new() -> Option<Self> {
        let dsn = std::env::var("NOO_BROKER_TEST_DSN")
            .ok()
            .filter(|s| !s.is_empty())?;
        let admin = PgPool::connect(&dsn).await.unwrap();
        let schema = format!("personal_{}", Uuid::new_v4().simple());
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let search = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |conn, _| {
                let sql = format!("SET search_path TO {search}");
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
        sqlx::raw_sql("CREATE TABLE noo_users (user_uuid uuid PRIMARY KEY,username text UNIQUE NOT NULL,disabled boolean NOT NULL DEFAULT false)").execute(&pool).await.unwrap();
        for revision in [
            crate::mesh_migrate::CONNECTIONS_REVISION,
            crate::mesh_migrate::INTEGRATION_OAUTH_REVISION,
            crate::mesh_migrate::INTEGRATION_PAIRING_REVISION,
            crate::mesh_migrate::INTEGRATION_CONTENT_REVISION,
        ] {
            let m = crate::mesh_migrate::MIGRATIONS
                .iter()
                .find(|m| m.revision == revision)
                .unwrap();
            sqlx::raw_sql(m.sql).execute(&pool).await.unwrap();
        }
        Some(Self {
            pool,
            admin,
            schema,
        })
    }
    async fn user(&self, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO noo_users(user_uuid,username) VALUES ($1,$2)")
            .bind(id)
            .bind(name)
            .execute(&self.pool)
            .await
            .unwrap();
        id
    }
    async fn source(&self, owner: Uuid, gmail: bool) -> Uuid {
        let account = Uuid::new_v4();
        let source = Uuid::new_v4();
        sqlx::query("INSERT INTO noo_connected_accounts(id,owner_uuid,provider,label,status,provider_subject) VALUES ($1,$2,'google','Private test','connected',$3)").bind(account).bind(owner).bind(Uuid::new_v4().to_string()).execute(&self.pool).await.unwrap();
        let policy = if gmail {
            json!({"kind":"gmail","exposure":"mailbox","lookback_days":30})
        } else {
            json!({"kind":"google_drive","exposure":"all_accessible"})
        };
        sqlx::query("INSERT INTO noo_connection_sources(id,owner_uuid,account_id,name,kind,policy) VALUES ($1,$2,$3,'Private test',$4,$5)").bind(source).bind(owner).bind(account).bind(if gmail {"gmail"} else {"google_drive"}).bind(policy).execute(&self.pool).await.unwrap();
        source
    }
    async fn finish(self) {
        self.pool.close().await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}
fn vault() -> Vault {
    Vault::from_secret(&"fixture-only-personal-vault-key-32-characters".repeat(2)).unwrap()
}
fn p(name: &str, admin: bool) -> Principal {
    Principal::user(
        name,
        if admin {
            crate::auth::Role::Admin
        } else {
            crate::auth::Role::User
        },
        vec![if admin { "admin".into() } else { "read".into() }],
    )
}

#[test]
fn personal_authority_ignores_admin_grants_and_denies_internal_and_shared_rooms() {
    assert_eq!(requester_account(&p("alice/laptop", true)), Some("alice"));
    assert_eq!(requester_account(&p("bob", true)), Some("bob"));
    let mut internal = p("alice", true);
    internal.kind = Kind::Internal;
    assert_eq!(requester_account(&internal), None);
    let mut shared = p("alice", true);
    shared.scopes.push("kb:shared-room".into());
    assert_eq!(requester_account(&shared), None);
}

#[tokio::test]
async fn personal_evidence_cannot_enter_persisted_chat_or_tool_histories() {
    let principal=p("alice",true);
    crate::mcp_bridge::CONVERSATION.scope(Some("persisted-conversation".into()),async {
        assert_eq!(requester_account(&principal),None);
    }).await;
    let turn=crate::routes::communication::TurnPrincipal {
        requester:"alice".into(),conversation_id:"persisted-turn".into(),..Default::default()
    };
    crate::routes::communication::with_turn_principal(turn,async {
        assert_eq!(requester_account(&principal),None);
    }).await;
    assert_eq!(requester_account(&principal),Some("alice"));
}

#[tokio::test]
async fn provider_ingest_search_and_identical_content_are_private_across_users_and_admins() {
    let Some(db) = Db::new().await else {
        return;
    };
    let v = vault();
    let alice = db.user("alice").await;
    let bob = db.user("bob").await;
    let admin = db.user("admin").await;
    let mut source_ids = Vec::new();
    // Both services, multiple accounts, byte-identical bodies and the same
    // provider item ID. Every one must remain an independent private row.
    for (owner, gmail) in [(alice, true), (alice, false), (bob, true), (bob, false)] {
        let source = db.source(owner, gmail).await;
        source_ids.push((owner, source));
        enable(&db.pool, owner, source, true).await.unwrap();
        let job = claim(&db.pool, &v).await.unwrap().unwrap();
        assert_eq!(job.owner, owner);
        let page = sync::page(&FixtureApi, &job.policy, None).await.unwrap();
        assert!(commit(&db.pool, &v, &job, &page.docs, None, 0)
            .await
            .unwrap());
    }
    let rows: Vec<Value> = sqlx::query_scalar("SELECT sealed FROM noo_integration_documents")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|r| !r.to_string().contains("apricot")));
    for (who, count) in [(alice, 2), (bob, 2), (admin, 0)] {
        let result = search(&db.pool, &v, who, "apricot", 20).await.unwrap();
        assert_eq!(result["items"].as_array().unwrap().len(), count);
        for doc in result["items"].as_array().unwrap() {
            assert!(source_ids
                .iter()
                .any(|(owner, source)| *owner == who && doc["source_id"] == source.to_string()));
        }
    }
    // Each tier resolves its own account; admin/unrestricted privileges do
    // not create a second path into somebody else's corpus.
    for principal in [p("admin", true), p("bob", true), p("alice/device", false)] {
        let name = requester_account(&principal).unwrap().to_string();
        let owner = crate::bus_principal::with_principal(principal, current_owner(&db.pool))
            .await
            .unwrap()
            .unwrap();
        let result = search(&db.pool, &v, owner, "apricot", 20).await.unwrap();
        assert_eq!(
            result["items"].as_array().unwrap().len(),
            if name == "admin" { 0 } else { 2 }
        );
    }
    let forged = enable(&db.pool, admin, source_ids[0].1, true).await;
    assert!(matches!(forged, Err(Error::NotFound)));
    for mut principal in [p("alice", true), p("admin", true)] {
        principal.scopes.push("kb:shared-room".into());
        assert!(
            crate::bus_principal::with_principal(principal, current_owner(&db.pool))
                .await
                .unwrap()
                .is_none()
        );
    }
    let internal = Principal::internal("private-sync", &["kb:unrestricted"]);
    assert!(
        crate::bus_principal::with_principal(internal, current_owner(&db.pool))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !crate::repo::connections::delete_source(&db.pool, "bob", source_ids[0].1)
            .await
            .unwrap()
    );
    assert!(
        crate::repo::connections::delete_source(&db.pool, "alice", source_ids[0].1)
            .await
            .unwrap()
    );
    assert_eq!(
        search(&db.pool, &v, alice, "apricot", 20).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        search(&db.pool, &v, bob, "apricot", 20).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // No global KB/graph tables are even created in this DB: the entire
    // import/search/retry path succeeds without publishing to those services.
    assert!(
        sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass('docs')::text")
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .is_none()
    );
    db.finish().await;
}

#[tokio::test]
async fn retries_leases_pause_disconnect_and_erasure_cannot_restore_private_data() {
    let Some(db) = Db::new().await else {
        return;
    };
    let v = vault();
    let alice = db.user("alice").await;
    let bob = db.user("bob").await;
    let source = db.source(alice, true).await;
    enable(&db.pool, alice, source, true).await.unwrap();
    let job = claim(&db.pool, &v).await.unwrap().unwrap();
    let page = sync::page(&FixtureApi, &job.policy, None).await.unwrap();
    let cursor = json!({"page":"private-cursor-canary"});
    assert!(commit(&db.pool, &v, &job, &page.docs, Some(&cursor), 0)
        .await
        .unwrap());
    let saved: Value =
        sqlx::query_scalar("SELECT cursor_sealed FROM noo_integration_sync WHERE source_id=$1")
            .bind(source)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(!saved.to_string().contains("private-cursor-canary"));
    let retry = claim(&db.pool, &v).await.unwrap().unwrap();
    assert_eq!(retry.cursor, Some(cursor));
    // A duplicate page after a crash is idempotent, scoped to the same source.
    assert!(commit(
        &db.pool,
        &v,
        &retry,
        &page.docs,
        Some(&json!({"page":"next"})),
        0
    )
    .await
    .unwrap());
    assert_eq!(
        search(&db.pool, &v, alice, "apricot", 20).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let stale = claim(&db.pool, &v).await.unwrap().unwrap();
    sqlx::query(
        "UPDATE noo_integration_sync SET lease_until=now()-interval '1 second' WHERE source_id=$1",
    )
    .bind(source)
    .execute(&db.pool)
    .await
    .unwrap();
    let replacement = claim(&db.pool, &v).await.unwrap().unwrap();
    assert!(!commit(&db.pool, &v, &stale, &page.docs, None, 0)
        .await
        .unwrap());
    enable(&db.pool, alice, source, false).await.unwrap();
    assert!(!commit(&db.pool, &v, &replacement, &page.docs, None, 0)
        .await
        .unwrap());
    assert!(claim(&db.pool, &v).await.unwrap().is_none());
    assert!(matches!(
        enable(&db.pool, bob, source, true).await,
        Err(Error::NotFound)
    ));
    enable(&db.pool, alice, source, true).await.unwrap();
    let deleted = claim(&db.pool, &v).await.unwrap().unwrap();
    // Production disconnect, not a fixture-only delete.
    assert!(
        crate::repo::connections::delete_account(&db.pool, "alice", deleted.account)
            .await
            .unwrap()
    );
    assert!(!commit(&db.pool, &v, &deleted, &page.docs, None, 0)
        .await
        .unwrap());
    assert!(
        search(&db.pool, &v, alice, "apricot", 20).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let source = db.source(alice, false).await;
    enable(&db.pool, alice, source, true).await.unwrap();
    let erased = claim(&db.pool, &v).await.unwrap().unwrap();
    sqlx::query("DELETE FROM noo_users WHERE user_uuid=$1")
        .bind(alice)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(!commit(&db.pool, &v, &erased, &page.docs, None, 0)
        .await
        .unwrap());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_integration_documents")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    db.finish().await;
}

#[tokio::test]
async fn snapshot_deletion_disabled_users_and_aad_fail_closed() {
    let Some(db) = Db::new().await else {
        return;
    };
    let v = vault();
    let owner = db.user("alice").await;
    let source = db.source(owner, true).await;
    enable(&db.pool, owner, source, true).await.unwrap();
    let job = claim(&db.pool, &v).await.unwrap().unwrap();
    let page = sync::page(&FixtureApi, &job.policy, None).await.unwrap();
    commit(&db.pool, &v, &job, &page.docs, None, 0)
        .await
        .unwrap();
    let sealed: Value = sqlx::query_scalar("SELECT sealed FROM noo_integration_documents")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(v
        .open::<Document>(&sealed, &context(Uuid::new_v4(), source, &hash("sameitem")))
        .is_err());
    assert!(v
        .open::<Document>(&sealed, &context(owner, Uuid::new_v4(), &hash("sameitem")))
        .is_err());
    sqlx::query("UPDATE noo_users SET disabled=true WHERE user_uuid=$1")
        .bind(owner)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(
        search(&db.pool, &v, owner, "apricot", 20).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    sqlx::query("UPDATE noo_users SET disabled=false WHERE user_uuid=$1")
        .bind(owner)
        .execute(&db.pool)
        .await
        .unwrap();
    enable(&db.pool, owner, source, true).await.unwrap();
    let next = claim(&db.pool, &v).await.unwrap().unwrap();
    commit(&db.pool, &v, &next, &[], None, 0).await.unwrap();
    assert!(
        search(&db.pool, &v, owner, "apricot", 20).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    db.finish().await;
}

#[tokio::test]
async fn concurrent_workers_and_disconnect_serialize_without_cross_owner_effects() {
    let Some(db) = Db::new().await else {
        return;
    };
    let v = vault();
    let owner = db.user("alice").await;
    let source = db.source(owner, false).await;
    enable(&db.pool, owner, source, true).await.unwrap();
    let (a, b) = tokio::join!(claim(&db.pool, &v), claim(&db.pool, &v));
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
    let job = a.or(b).unwrap();
    let page = sync::page(&FixtureApi, &job.policy, None).await.unwrap();
    let (stored, removed) = tokio::join!(
        commit(&db.pool, &v, &job, &page.docs, None, 0),
        crate::repo::connections::delete_account(&db.pool, "alice", job.account)
    );
    stored.unwrap();
    assert!(removed.unwrap());
    assert!(
        search(&db.pool, &v, owner, "apricot", 20).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!commit(&db.pool, &v, &job, &page.docs, None, 0)
        .await
        .unwrap());
    db.finish().await;
}

#[tokio::test]
async fn provider_failures_keep_cursor_private_back_off_and_stop_until_restarted() {
    let Some(db) = Db::new().await else {
        return;
    };
    let v = vault();
    let owner = db.user("alice").await;
    let source = db.source(owner, true).await;
    enable(&db.pool, owner, source, true).await.unwrap();
    for attempt in 1..=5 {
        let job = claim(&db.pool, &v).await.unwrap().unwrap();
        fail(
            &db.pool,
            &job,
            &Error::Unavailable("provider body must never persist: canary".into()),
        )
        .await
        .unwrap();
        let (tries,status,fault,delayed):(i32,String,String,bool)=sqlx::query_as("SELECT attempts,status,fault,next_run>now() FROM noo_integration_sync WHERE source_id=$1").bind(source).fetch_one(&db.pool).await.unwrap();
        assert_eq!(tries, attempt);
        assert_eq!(fault, "provider");
        assert!(delayed);
        assert_eq!(status, if attempt == 5 { "error" } else { "queued" });
        assert!(claim(&db.pool, &v).await.unwrap().is_none());
        sqlx::query("UPDATE noo_integration_sync SET next_run=now() WHERE source_id=$1")
            .bind(source)
            .execute(&db.pool)
            .await
            .unwrap();
    }
    assert!(claim(&db.pool, &v).await.unwrap().is_none());
    enable(&db.pool, owner, source, true).await.unwrap();
    assert!(claim(&db.pool, &v).await.unwrap().is_some());
    db.finish().await;
}

#[tokio::test]
async fn invalid_page_rolls_back_earlier_items_and_cross_owner_rows_fail_the_fk() {
    let Some(db) = Db::new().await else {
        return;
    };
    let v = vault();
    let owner = db.user("alice").await;
    let bob = db.user("bob").await;
    let source = db.source(owner, true).await;
    enable(&db.pool, owner, source, true).await.unwrap();
    let job = claim(&db.pool, &v).await.unwrap().unwrap();
    let mut page = sync::page(&FixtureApi, &job.policy, None).await.unwrap();
    page.docs.push(Document {
        external_id: "invalid".into(),
        title: "too big".into(),
        text: "x".repeat(MAX_TEXT + 1),
        url: "https://example.invalid".into(),
    });
    assert!(matches!(
        commit(&db.pool, &v, &job, &page.docs, None, 0).await,
        Err(Error::Invalid(_))
    ));
    assert!(
        search(&db.pool, &v, owner, "apricot", 20).await.unwrap()["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let error=sqlx::query("INSERT INTO noo_integration_documents(id,owner_uuid,source_id,item_key,generation,sealed) VALUES ($1,$2,$3,'forged',$4,'{}')")
        .bind(Uuid::new_v4()).bind(bob).bind(source).bind(Uuid::new_v4()).execute(&db.pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    db.finish().await;
}
