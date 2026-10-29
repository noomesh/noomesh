// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

use super::*;
use crate::bus_principal::{Kind, Principal};
use crate::integrations::sync::{self, Api};


async fn commit(db: &PgPool, v: &Vault, job: &Job, docs: &[Document], cursor: Option<&Value>, skipped: usize) -> Result<bool, Error> {
    let mut retained: std::collections::BTreeSet<String> = job.cursor.as_ref()
        .and_then(|c| c.get("retained")).cloned()
        .and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
    retained.extend(docs.iter().map(|d| hash(&d.external_id)));
    super::commit(db, v, job, &sync::Page { docs: docs.to_vec(), cursor: cursor.cloned(), skipped, retained }).await
}

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
                json!({"internalDate":"1700000000000","historyId":"v1","payload":{"mimeType":"text/plain","headers":[{"name":"Subject","value":"Private Gmail apricot"}],"body":{"data":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("Shared bytes, private canary apricot")}}})
            }
        } else {
            json!({"files":[{"id":"sameitem","name":"Private Drive apricot","mimeType":"text/plain","version":"v1"}]})
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
            .filter(|s| !s.is_empty());
        assert!(
            std::env::var_os("NOO_REQUIRE_GOOGLE_REHEARSAL").is_none() || dsn.is_some(),
            "Google rehearsal requires NOO_BROKER_TEST_DSN; refusing a skipped database test"
        );
        let dsn = dsn?;
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
        sqlx::raw_sql("CREATE TABLE noo_users (user_uuid uuid PRIMARY KEY,username text UNIQUE NOT NULL,disabled boolean NOT NULL DEFAULT false,role text NOT NULL DEFAULT 'user')").execute(&pool).await.unwrap();
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

struct SnapshotApi {
    count: usize,
    revision: &'static str,
    body_reads: std::sync::atomic::AtomicUsize,
}
impl SnapshotApi {
    fn new(count: usize, revision: &'static str) -> Self {
        Self { count, revision, body_reads: std::sync::atomic::AtomicUsize::new(0) }
    }
}
impl Api for SnapshotApi {
    async fn get(&self, gmail: bool, path: &[&str], query: &[(String,String)], raw: bool) -> Result<Option<Vec<u8>>, Error> {
        let metadata = query.iter().any(|(k,v)| k == "format" && v == "metadata");
        let result = if path.len() == 1 {
            let start: usize = query.iter().find(|(k,_)| k == "pageToken").map(|(_,v)| v.parse().unwrap()).unwrap_or(0);
            let end = (start+20).min(self.count);
            // Deliberately oldest first: the implementation cannot rely on an
            // undocumented Gmail list ordering to select the newest window.
            let rows: Vec<_> = (start..end).map(|n| if gmail { json!({"id":format!("msg{n:04}")}) }
                else { json!({"id":format!("msg{n:04}"),"name":format!("File {n}"),"mimeType":"text/plain","version":self.revision}) }).collect();
            let mut list = if gmail { json!({"messages":rows}) } else { json!({"files":rows}) };
            if end < self.count { list["nextPageToken"] = json!(end.to_string()); }
            list
        } else if metadata {
            let n: usize = path[1].strip_prefix("msg").unwrap().parse().unwrap();
            json!({"internalDate":(1_700_000_000_000u64+n as u64*1000).to_string(),"historyId":self.revision})
        } else {
            self.body_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if raw { return Ok(Some(format!("Private apricot {}", self.revision).into_bytes())); }
            use base64::Engine;
            json!({"payload":{"mimeType":"text/plain","headers":[{"name":"Subject","value":"Private apricot"}],"body":{"data":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("Private apricot {}",self.revision))}}})
        };
        Ok(Some(serde_json::to_vec(&result).unwrap()))
    }
}

async fn run_snapshot(db: &Db, v: &Vault, owner: Uuid, source: Uuid, api: &SnapshotApi) -> Vec<String> {
    enable(&db.pool, owner, source, true).await.unwrap();
    let mut order = Vec::new();
    for _ in 0..200 {
        let job = claim(&db.pool, v).await.unwrap().expect("scan has another page");
        assert_eq!((job.owner,job.source), (owner,source));
        let known = if job.cursor.is_none() { versions(&db.pool, v, &job).await.unwrap() } else { BTreeMap::new() };
        let page = sync::page(api, &job.policy, job.cursor.clone(), known).await.unwrap();
        order.extend(page.docs.iter().map(|d| d.external_id.clone()));
        assert!(super::commit(&db.pool, v, &job, &page).await.unwrap());
        if page.cursor.is_none() { return order; }
    }
    panic!("snapshot did not complete");
}

#[tokio::test]
async fn unchanged_gmail_and_drive_snapshots_write_zero_document_rows() {
    let Some(db) = Db::new().await else { return; };
    let v = vault();
    let owner = db.user("alice").await;
    for gmail in [true, false] {
        let source = db.source(owner,gmail).await;
        let api = SnapshotApi::new(3,"v1");
        assert_eq!(run_snapshot(&db,&v,owner,source,&api).await.len(),3);
        let before: Vec<(Uuid,String,String,Value)> = sqlx::query_as("SELECT id,xmin::text,updated_at::text,sealed FROM noo_integration_documents WHERE source_id=$1 ORDER BY id")
            .bind(source).fetch_all(&db.pool).await.unwrap();
        let bodies = api.body_reads.load(std::sync::atomic::Ordering::SeqCst);
        assert!(run_snapshot(&db,&v,owner,source,&api).await.is_empty());
        let after: Vec<(Uuid,String,String,Value)> = sqlx::query_as("SELECT id,xmin::text,updated_at::text,sealed FROM noo_integration_documents WHERE source_id=$1 ORDER BY id")
            .bind(source).fetch_all(&db.pool).await.unwrap();
        assert_eq!(before,after,"unchanged rows must retain row version, timestamp and ciphertext");
        assert_eq!(api.body_reads.load(std::sync::atomic::Ordering::SeqCst),bodies,"unchanged bodies must not be downloaded");
        // A revision change imports new bytes; deleted items are pruned.
        let changed = SnapshotApi::new(2,"v2");
        assert_eq!(run_snapshot(&db,&v,owner,source,&changed).await.len(),2);
        let rows: Vec<(String,Value)> = sqlx::query_as("SELECT item_key,sealed FROM noo_integration_documents WHERE source_id=$1")
            .bind(source).fetch_all(&db.pool).await.unwrap();
        assert_eq!(rows.len(),2);
        for (item,sealed) in rows { assert_eq!(v.open::<Document>(&sealed,&context(owner,source,&item)).unwrap().version,"v2"); }
    }
    db.finish().await;
}

#[tokio::test]
async fn mailbox_1001_messages_completes_newest_first_and_prunes_stale_rows() {
    let Some(db) = Db::new().await else { return; };
    let v = vault();
    let owner = db.user("alice").await;
    let bob = db.user("bob").await;
    let other_source = db.source(bob,true).await;
    run_snapshot(&db,&v,bob,other_source,&SnapshotApi::new(1,"v1")).await;
    let other_before: (String,Value) = sqlx::query_as("SELECT xmin::text,sealed FROM noo_integration_documents WHERE source_id=$1")
        .bind(other_source).fetch_one(&db.pool).await.unwrap();
    let source = db.source(owner,true).await;
    enable(&db.pool,owner,source,true).await.unwrap();
    let job = claim(&db.pool,&v).await.unwrap().unwrap();
    let docs: Vec<_> = ["msg0000","deleted"].into_iter().map(|id| Document {
        external_id:id.into(),title:"stale".into(),text:"old".into(),url:"https://mail.google.com/".into(),version:"v1".into(),
    }).collect();
    commit(&db.pool,&v,&job,&docs,None,0).await.unwrap();
    let api = SnapshotApi::new(1001,"v1");
    let order = run_snapshot(&db,&v,owner,source,&api).await;
    assert_eq!(order.len(),1000);
    assert_eq!(order.first().unwrap(),"msg1000");
    assert_eq!(order.last().unwrap(),"msg0001");
    let (status,imported,no_cursor):(String,i32,bool) = sqlx::query_as("SELECT status,imported,cursor_sealed IS NULL FROM noo_integration_sync WHERE source_id=$1")
        .bind(source).fetch_one(&db.pool).await.unwrap();
    assert_eq!((status.as_str(),imported,no_cursor),("idle",1000,true));
    let keys: Vec<String> = sqlx::query_scalar("SELECT item_key FROM noo_integration_documents WHERE source_id=$1")
        .bind(source).fetch_all(&db.pool).await.unwrap();
    assert_eq!(keys.len(),1000);
    assert!(!keys.contains(&hash("msg0000")) && !keys.contains(&hash("deleted")));
    let other_after: (String,Value) = sqlx::query_as("SELECT xmin::text,sealed FROM noo_integration_documents WHERE source_id=$1")
        .bind(other_source).fetch_one(&db.pool).await.unwrap();
    assert_eq!(other_before,other_after,"pruning Alice's identical provider ID must not touch Bob's row");
    db.finish().await;
}

#[tokio::test]
async fn real_auth_middleware_preserves_each_door_delegation_marker() {
    use axum::{middleware, routing::post, Json, Router};
    use base64::Engine;
    let Some(db) = Db::new().await else { return; };
    struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Drop for RestoreEnv {
        fn drop(&mut self) { for (key,value) in &self.0 { match value {
            Some(v) => std::env::set_var(key,v), None => std::env::remove_var(key),
        } } }
    }
    let _restore = RestoreEnv(["NOO_JWT_SECRET","NOO_JWT_SECRET_FILE"].into_iter()
        .map(|k| (k,std::env::var_os(k))).collect());
    const SECRET: &str = "fixture-middleware-google-private-authority-not-a-secret";
    std::env::set_var("NOO_JWT_SECRET",SECRET);
    std::env::remove_var("NOO_JWT_SECRET_FILE");
    let name = format!("door-{}",Uuid::new_v4().simple());
    db.user(&name).await;
    let state = std::sync::Arc::new(crate::state::AppState::for_router_harness(
        &crate::config::AppConfig::default(),db.pool.clone()).await.unwrap());
    // This probe changes only the handler. Both middleware layers are the
    // production functions, in production order. No hand-built RequesterCtx.
    let app = Router::new().route("/api/connections/search",post(|| async {
        let principal = crate::bus_principal::current();
        Json(json!({"allowed":requester_account(&principal).is_some(),
            "actor":principal.act.is_some(),"harness":principal.harness.is_some()}))
    }))
        .layer(middleware::from_fn(crate::bus_principal::principal_layer))
        .layer(middleware::from_fn_with_state(state.clone(),crate::auth::require_any_auth));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener,app).await.unwrap() });
    let http = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(10)).build().unwrap();
    let door = crate::mcp_external::mint_caller_jwt(&name,crate::auth::Role::User,&[],&format!("self:{name}"),None).unwrap();
    crate::auth::verify_token(&door,SECRET).unwrap();
    // Claims is the handler projection; it intentionally omits iss/aud/iat.
    // Preserve the actual minted wire claims when signing marker variants.
    let claims: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(door.split('.').nth(1).unwrap()).unwrap()).unwrap();
    for (actor,harness) in [(true,true),(true,false),(false,true),(false,false)] {
        let mut test_claims = if actor || harness { claims.clone() } else {
            crate::auth::scoped_claims(&name,"user",["read"],600,SECRET).unwrap()
        };
        if !actor { test_claims["act"] = Value::Null; }
        if !harness { test_claims["harness"] = Value::Null; }
        let token = crate::auth::sign_hs256(&test_claims,SECRET).unwrap();
        assert!(crate::auth::verify_token(&token,SECRET).is_ok(),"fixture must retain valid issuer/audience/expiry");
        let response = http.post(format!("http://{addr}/api/connections/search"))
            .bearer_auth(token).send().await.unwrap();
        assert_eq!(response.status(),axum::http::StatusCode::OK,"the real middleware must admit this credential to the probe");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body,json!({"allowed":!actor && !harness,"actor":actor,"harness":harness}));
    }
    server.abort();
    drop(state);
    db.finish().await;
}

#[tokio::test]
async fn unreadable_documents_do_not_hide_healthy_owner_results() {
    let Some(db) = Db::new().await else { return; };
    let v = vault();
    let owner = db.user("alice").await;
    let source = db.source(owner, true).await;
    enable(&db.pool, owner, source, true).await.unwrap();
    let job = claim(&db.pool, &v).await.unwrap().unwrap();
    let docs: Vec<Document> = ["good", "corrupt"].into_iter().map(|id| Document {
        external_id: id.into(), title: "Private apricot".into(),
        text: "Private apricot evidence".into(), url: "https://mail.google.com/".into(), version: String::new(),
    }).collect();
    commit(&db.pool, &v, &job, &docs, None, 0).await.unwrap();
    sqlx::query("UPDATE noo_integration_documents SET sealed='{}' WHERE item_key=$1")
        .bind(hash("corrupt")).execute(&db.pool).await.unwrap();
    let result = search(&db.pool, &v, owner, "apricot", 20).await
        .expect("one unreadable row must not take down the owner's whole search");
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
    assert_eq!(result["unavailable"], true);
    let wrong = Vault::from_secret(&"different-fixture-key".repeat(3)).unwrap();
    let result = search(&db.pool, &wrong, owner, "apricot", 20).await.unwrap();
    assert!(result["items"].as_array().unwrap().is_empty());
    assert_eq!(result["unavailable"], true);
    db.finish().await;
}

#[tokio::test]
async fn poisoned_jobs_are_isolated_and_other_users_continue_syncing() {
    let Some(db) = Db::new().await else { return; };
    let v = vault();
    let alice = db.user("alice").await;
    let bob = db.user("bob").await;
    let bad_cursor = db.source(alice, true).await;
    let bad_policy = db.source(alice, false).await;
    let good = db.source(bob, true).await;
    for (who, source) in [(alice, bad_cursor), (alice, bad_policy), (bob, good)] {
        enable(&db.pool, who, source, true).await.unwrap();
    }
    sqlx::query("UPDATE noo_integration_sync SET cursor_sealed='{}',next_run=now()-interval '2 hours' WHERE source_id=$1")
        .bind(bad_cursor).execute(&db.pool).await.unwrap();
    sqlx::query("UPDATE noo_connection_sources SET policy=$2 WHERE id=$1")
        .bind(bad_policy).bind(json!({"kind":"google_drive","exposure":"invalid"})).execute(&db.pool).await.unwrap();
    sqlx::query("UPDATE noo_integration_sync SET next_run=now()-interval '1 hour' WHERE source_id=$1")
        .bind(bad_policy).execute(&db.pool).await.unwrap();
    let job = claim(&db.pool, &v).await.expect("a poison cursor must not block the queue").unwrap();
    assert_eq!((job.owner, job.source), (bob, good));
    let errors: i64 = sqlx::query_scalar("SELECT count(*) FROM noo_integration_sync WHERE owner_uuid=$1 AND status='error' AND fault='storage' AND lease IS NULL")
        .bind(alice).fetch_one(&db.pool).await.unwrap();
    assert_eq!(errors, 2);
    assert!(claim(&db.pool, &v).await.unwrap().is_none());
    let page = sync::page(&FixtureApi, &job.policy, None, BTreeMap::new()).await.unwrap();
    assert!(commit(&db.pool, &v, &job, &page.docs, None, 0).await.unwrap());
    assert_eq!(search(&db.pool, &v, bob, "apricot", 20).await.unwrap()["items"].as_array().unwrap().len(), 1);
    // The owner can explicitly restart after fixing storage; no auto-retry
    // reads the poison again, and start discards the old encrypted cursor.
    enable(&db.pool, alice, bad_cursor, true).await.unwrap();
    assert_eq!(claim(&db.pool, &v).await.unwrap().unwrap().source, bad_cursor);
    db.finish().await;
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
        let page = sync::page(&FixtureApi, &job.policy, None, BTreeMap::new()).await.unwrap();
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
    let page = sync::page(&FixtureApi, &job.policy, None, BTreeMap::new()).await.unwrap();
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
    let page = sync::page(&FixtureApi, &job.policy, None, BTreeMap::new()).await.unwrap();
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
    let page = sync::page(&FixtureApi, &job.policy, None, BTreeMap::new()).await.unwrap();
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
    let mut page = sync::page(&FixtureApi, &job.policy, None, BTreeMap::new()).await.unwrap();
    page.docs.push(Document {
        external_id: "invalid".into(),
        title: "too big".into(),
        text: "x".repeat(MAX_TEXT + 1),
        url: "https://example.invalid".into(), version: String::new(),
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
