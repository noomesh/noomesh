// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Authenticated transcript-plane imports, independent of inference/augmentation.
//! Source dialogue is never promoted to verified tool evidence by this route.
use super::{AppError, AppResult};
use crate::{
    auth::{account_of, RequesterCtx},
    repo::conversations,
    session::{self, ConversationWrite, ConversationWriteError, MessageWrite},
    state::AppState,
};
use axum::{extract::State, Extension, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImportBody {
    publication: Publication,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    version: u8,
    publisher_id: Uuid,
    event_id: Uuid,
    conversation_id: Uuid,
    operation: String,
    entry: Option<Entry>,
    session_id: Option<String>,
    ended_at: Option<DateTime<Utc>>,
    end_reason: Option<String>,
    transcription: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: Uuid,
    session_id: String,
    role: String,
    content: String,
    created_at: DateTime<Utc>,
    start_ms: i32,
    end_ms: i32,
    source: String,
    voice: String,
}

fn validate(p: &Publication) -> Result<(), AppError> {
    let valid = p.version == 1
        && match p.operation.as_str() {
            "entry" => {
                p.entry.as_ref().is_some_and(|e| {
                    matches!(e.role.as_str(), "user" | "assistant")
                        && !e.content.is_empty()
                        && e.content.len() <= 32768
                        && !e.session_id.is_empty()
                        && e.session_id.len() <= 128
                        && e.start_ms >= 0
                        && e.end_ms >= e.start_ms
                        && e.source.len() <= 128
                        && e.voice.len() <= 128
                }) && p.session_id.is_none()
                    && p.ended_at.is_none()
                    && p.end_reason.is_none()
                    && p.transcription.is_none()
            }
            "session_end" => {
                p.entry.is_none()
                    && p.ended_at.is_some()
                    && p.session_id
                        .as_ref()
                        .is_some_and(|s| !s.is_empty() && s.len() <= 128)
                    && p.end_reason.as_ref().is_some_and(|s| s.len() <= 128)
                    && p.transcription.as_ref().is_some_and(|s| s.len() <= 128)
            }
            "delete" => {
                p.entry.is_none()
                    && p.session_id.is_none()
                    && p.ended_at.is_none()
                    && p.end_reason.is_none()
                    && p.transcription.is_none()
            }
            _ => false,
        };
    if valid {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Invalid conversation publication v1".into(),
        ))
    }
}

pub(super) async fn receive(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    Json(body): Json<ImportBody>,
) -> AppResult {
    // A user-bound credential is mandatory, including for operator callers.
    // Never accept an owner/account supplied in the transcript body.
    let requester = requester.ok_or_else(|| {
        AppError::Forbidden("Conversation publication needs a user-bound credential".into())
    })?;
    // A delegated credential (an agent or a task run acting for the person,
    // `act`) could otherwise file fabricated "user said" lines into that
    // person's memory. Publication is the person's own credential's job: a
    // login, or a key from the MCP door (an add-on's own publisher holds one).
    // Add-on delegated tokens never get here: they are confined to the task
    // routes (addon_delegation::route_allowed).
    if !may_publish(&requester.0) {
        return Err(AppError::Forbidden(
            "A delegated credential cannot publish conversations; use the person's own login or MCP key".into(),
        ));
    }
    let channel = source_channel(&requester.0);
    import(&state.db, account_of(&requester.0.sub), &channel, body.publication)
        .await
        .map(Json)
}

/// Only the person's own credential publishes: a login (no `act`), or the
/// person's own provisioned key, whose tokens carry `act: {sub:
/// "key:<consumer>", iss_user: <the key's account>}`. That is every MCP-door
/// token (`mcp_external::mint_caller_jwt`) and every token exchange. Any
/// other actor is delegation and is refused: an agent or task run, a worker,
/// an add-on's delegated token, or a key bound to ANOTHER account. The first
/// version refused every `act`, so it refused the MCP door, which is how a
/// voice add-on publishes through its MCP-door key.
fn may_publish(r: &RequesterCtx) -> bool {
    let Some(a) = &r.act else { return true };
    // Fail closed: a key actor needs a consumer, an issuing account equal to
    // the token subject's own account (ids, byte for byte), and none of the
    // markers another delegation kind carries (a worker run's `task`, an
    // add-on feature's `feature`).
    let consumer = a.sub.strip_prefix("key:").unwrap_or("");
    !consumer.is_empty()
        && !consumer.chars().any(char::is_whitespace)
        && a.iss_user.as_deref().is_some_and(|u| !u.is_empty() && u == account_of(&r.sub))
        && a.task.is_none()
}

/// The channel label a publication is filed under, from the CREDENTIAL, never
/// the body: the door that minted it, else "external". Core never names an
/// add-on itself.
fn source_channel(r: &RequesterCtx) -> String {
    r.harness
        .clone()
        .filter(|c| !c.trim().is_empty())
        .unwrap_or_else(|| "external".to_string())
}

async fn import(db: &PgPool, account: &str, channel: &str, p: Publication) -> Result<Value, AppError> {
    validate(&p)?;
    let active = crate::repo::users::is_enabled(db, account).await?;
    if !active {
        return Err(AppError::Forbidden(
            "Publication account is unavailable".into(),
        ));
    }
    let conversation = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!(
            "noomesh:conversation:{account}:{}:{}",
            p.publisher_id, p.conversation_id
        )
        .as_bytes(),
    );
    let mut tx = db.begin().await?;
    let new_source = conversations::claim_source(&mut *tx, account, p.publisher_id, p.conversation_id, conversation).await?;
    let mut deleted = conversations::source_deleted_for_update(&mut *tx, account, p.publisher_id, p.conversation_id).await?;
    if !new_source && !deleted {
        // Noomesh may erase its copy independently. A surviving source ledger
        // must suppress old uploads rather than undo a keep-account erasure.
        if !conversations::exists(&mut *tx, conversation).await? {
            deleted = true;
            conversations::tombstone_source(&mut *tx, conversation).await?;
        }
    }
    if p.operation == "delete" {
        // The source tombstone survives the conversation: a late/ambiguous
        // append retry cannot recreate deleted speech.
        conversations::tombstone_source(&mut *tx, conversation).await?;
        session::delete_conversation_in(&mut tx, conversation, account).await?;
    } else if !deleted {
        let metadata = json!({"channel":channel,"source_channel":channel,"dialogue_only":true,"external_source":{
            "publisher_id":p.publisher_id,"conversation_id":p.conversation_id}});
        let source_time = p
            .entry
            .as_ref()
            .map(|e| e.created_at)
            .or(p.ended_at)
            .unwrap_or_else(Utc::now);
        let write = ConversationWrite {
            id: conversation,
            user_id: Some(account),
            metadata: Some(&metadata),
            started_at: Some(source_time),
            require_owner: true,
        };
        if let Some(e) = p.entry {
            let identity = Uuid::new_v5(&conversation, e.id.as_bytes());
            let evidence = if e.role == "assistant" {
                "assistant_dialogue"
            } else {
                "user_statement"
            };
            let meta = json!({"evidence":evidence,"verified_action":false,"verbatim":true,
                "source":{"publisher_id":p.publisher_id,"conversation_id":p.conversation_id,"entry_id":e.id,
                    "session_id":e.session_id,"start_ms":e.start_ms,"end_ms":e.end_ms,"transcription_source":e.source,"voice":e.voice}});
            session::save_message_in(
                &mut tx,
                &write,
                &MessageWrite {
                    id: identity,
                    role: &e.role,
                    content: &e.content,
                    metadata: Some(&meta),
                    created_at: Some(e.created_at),
                },
            )
            .await?;
        } else {
            // Validation above guarantees a session_end with a timestamp.
            session::finish_conversation_in(
                &mut tx,
                &write,
                p.ended_at.expect("validated session ending"),
                &json!({"last_source_session":{
                    "id":p.session_id,"end_reason":p.end_reason,"transcription":p.transcription
                }}),
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(
        json!({"version":1,"event_id":p.event_id,"conversation_id":conversation,
        "status":if p.operation=="delete" {"deleted"} else if deleted {"suppressed"} else {"accepted"},
        "indexing":"asynchronous"}),
    )
}

impl From<ConversationWriteError> for AppError {
    fn from(error: ConversationWriteError) -> Self {
        match error {
            ConversationWriteError::Database(error) => error.into(),
            conflict @ (ConversationWriteError::OwnershipConflict
            | ConversationWriteError::ImmutableEntry) => Self::Conflict(conflict.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::conversations::fixtures;

    fn entry(publisher: Uuid, conversation: Uuid, id: Uuid, role: &str, words: &str) -> Value {
        json!({"version":1,"publisher_id":publisher,"event_id":Uuid::new_v4(),
            "conversation_id":conversation,"operation":"entry","entry":{
                "id":id,"session_id":"voice-session","role":role,"content":words,
                "created_at":"2026-10-18T12:00:00Z","start_ms":80,"end_ms":320,
                "source":"stt","voice":"NATF2.pt"}})
    }

    fn requester(harness: Option<&str>, act: bool) -> RequesterCtx {
        with_actor(harness, act.then(|| json!({"sub": "agent:helper"})))
    }

    fn with_actor(harness: Option<&str>, act: Option<serde_json::Value>) -> RequesterCtx {
        RequesterCtx {
            sub: "ada/claude-voice".into(),
            scopes: vec![],
            role: crate::auth::Role::User,
            harness: harness.map(str::to_string),
            act: act.map(|a| serde_json::from_value(a).expect("an actor")),
        }
    }

    /// A login (no `act`) publishes.
    #[test]
    fn a_login_publishes() {
        assert!(may_publish(&requester(None, false)));
        assert!(may_publish(&requester(Some("mcp-external"), false)));
    }

    /// The requester the auth layer builds from a token's claims (`sub`,
    /// `harness` and `act` copied as they are).
    fn from_claims(c: &Value) -> RequesterCtx {
        RequesterCtx {
            sub: c["sub"].as_str().unwrap().to_string(),
            scopes: vec![],
            role: crate::auth::Role::User,
            harness: c["harness"].as_str().map(str::to_string),
            act: Some(serde_json::from_value(c["act"].clone()).expect("the door's actor parses")),
        }
    }

    fn door_claims(user: &str) -> Value {
        crate::mcp_external::caller_claims(user, crate::auth::Role::User, &[], &format!("self:{user}"), Some("claude-voice"), 0)
    }

    /// The MCP door's own token (its real claims, `caller_claims`, which
    /// `mint_caller_jwt` signs): the person's key, issued by the person's
    /// account. It publishes. That is an add-on's MCP-door key's path; the
    /// first version refused it.
    #[test]
    fn the_doors_own_token_publishes() {
        let r = from_claims(&door_claims("ada"));
        assert_eq!(r.sub, "ada/claude-voice");
        assert!(may_publish(&r), "{:?}", r.act);
        let src = include_str!("../mcp_external.rs");
        assert!(
            src.contains("let claims = caller_claims(user, role, user_scopes, consumer, session_label, now);"),
            "mint_caller_jwt signs caller_claims"
        );
        // The route files the row under the subject's ACCOUNT (the DB test
        // below calls `import` the same way, so this pins the route to it).
        // own_code drops this test module, so the needle cannot match itself.
        let own = crate::test_src::own_code(include_str!("conversation_import.rs"));
        let route = crate::test_src::fn_body(&own, "async fn receive(");
        assert!(
            route.contains(concat!("import(&state.db, account_of(&requester.0.sub)", ", &channel, body.publication)")),
            "the route must own the row by account_of(subject), never the key or the connection"
        );
    }

    /// An agent or task run acting for the person (`agent:…`).
    #[test]
    fn a_delegated_credential_cannot_publish() {
        assert!(!may_publish(&requester(None, true)));
        assert!(!may_publish(&requester(Some("mcp-external"), true)));
    }

    /// The worker's delegated token, even when it also names a run.
    #[test]
    fn a_worker_actor_cannot_publish() {
        let w = json!({"sub": crate::worker_delegation::WORKER_ACTOR, "iss_user": "ada", "task": "run_1"});
        assert!(!may_publish(&with_actor(None, Some(w))));
    }

    /// An add-on's delegated token, even under a feature.
    #[test]
    fn an_addon_actor_cannot_publish() {
        let a = json!({"sub": format!("{}voice", crate::addon_delegation::ACTOR_PREFIX), "iss_user": "ada", "feature": "voice"});
        assert!(!may_publish(&with_actor(None, Some(a))));
    }

    /// A key issued by ANOTHER account, presented under this subject.
    #[test]
    fn another_accounts_key_cannot_publish() {
        let mut c = door_claims("ada");
        c["act"]["iss_user"] = json!("bob");
        assert!(!may_publish(&from_claims(&c)));
        // Ids compare exactly: a display-different spelling is another id.
        c["act"]["iss_user"] = json!("Ada");
        assert!(!may_publish(&from_claims(&c)));
    }

    /// Fail closed on a key actor that is incomplete or carries another
    /// delegation's marker (a second actor riding inside the first).
    #[test]
    fn an_incomplete_or_doubled_key_actor_cannot_publish() {
        for bad in [
            json!({"sub": "key:self:ada"}),
            json!({"sub": "key:self:ada", "iss_user": ""}),
            json!({"sub": "key:", "iss_user": "ada"}),
            json!({"sub": "key: self:ada", "iss_user": "ada"}),
            json!({"sub": "keys:self:ada", "iss_user": "ada"}),
            json!({"sub": "key:self:ada", "iss_user": "ada", "task": "run_1"}),
            json!({"sub": "key:self:ada", "iss_user": "ada", "feature": "voice"}),
        ] {
            assert!(!may_publish(&with_actor(Some("mcp-external:self:ada"), Some(bad.clone()))), "{bad}");
        }
    }

    /// The channel label comes from the credential, never names an add-on of
    /// core's choosing, and an unlabelled credential is "external".
    #[test]
    fn the_channel_comes_from_the_credential() {
        assert_eq!(source_channel(&requester(Some("mcp-external"), false)), "mcp-external");
        assert_eq!(source_channel(&requester(None, false)), "external");
        assert_eq!(source_channel(&requester(Some("  "), false)), "external");
    }

    #[test]
    fn rejects_privileged_roles_owner_overrides_and_bad_versions() {
        let p = Uuid::new_v4();
        let c = Uuid::new_v4();
        let e = Uuid::new_v4();
        for role in ["system", "tool", "tool_result"] {
            assert!(
                validate(&serde_json::from_value(entry(p, c, e, role, "words")).unwrap()).is_err()
            );
        }
        let mut source = entry(p, c, e, "user", "new mash");
        source["owner_id"] = json!("another-account");
        assert!(serde_json::from_value::<Publication>(source).is_err());
        let mut source = entry(p, c, e, "user", "new mash");
        source["version"] = json!(2);
        assert!(validate(&serde_json::from_value(source).unwrap()).is_err());
    }

    // CI's DSN points to the real, migrated mesh+Trellion catalogue. No
    // hand-written replacement tables: that would miss provider schema drift.
    async fn database() -> Option<PgPool> {
        let Ok(dsn) = std::env::var("NOO_BROKER_TEST_DSN") else {
            return None;
        };
        use std::str::FromStr;
        let migration = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&dsn)
            .await
            .unwrap();
        if std::env::var("NOO_APP_DB_PASSWORD").is_err() {
            std::env::set_var("NOO_APP_DB_PASSWORD", Uuid::new_v4().to_string());
        }
        crate::mesh_migrate::apply(&migration)
            .await
            .expect("real mesh migrations");
        migration.close().await;
        let options = sqlx::postgres::PgConnectOptions::from_str(&dsn)
            .unwrap()
            .options([("search_path", "mesh,public,trellion,evolve")]);
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .unwrap();
        Some(db)
    }

    async fn user(db: &PgPool) -> String {
        let user = format!("publication_{}", Uuid::new_v4().simple());
        fixtures::add_user(db, &user, &format!("org_{user}")).await;
        user
    }

    async fn cleanup(db: &PgPool, users: &[&str]) {
        for user in users {
            fixtures::remove_user(db, user).await;
        }
    }

    /// A real door token publishes, and the row it files is owned by the
    /// token subject's ACCOUNT: never the key's consumer name, never the
    /// connection label.
    #[tokio::test]
    async fn the_doors_token_files_the_row_under_the_persons_account() {
        let Some(db) = database().await else {
            return;
        };
        let a = user(&db).await;
        let r = from_claims(&door_claims(&a));
        assert!(may_publish(&r));
        let event = entry(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), "user", "door words");
        let receipt = import(&db, account_of(&r.sub), &source_channel(&r), serde_json::from_value(event).unwrap())
            .await
            .unwrap();
        let conv = Uuid::parse_str(receipt["conversation_id"].as_str().unwrap()).unwrap();
        let owner = fixtures::conversation(&db, conv).await.user_id.unwrap_or_default();
        assert_eq!(owner, a);
        assert_ne!(owner, format!("self:{a}"), "not the key's consumer name");
        assert_ne!(owner, r.sub, "not the connection label");
        cleanup(&db, &[&a]).await;
    }

    #[tokio::test]
    async fn source_roundtrip_is_account_scoped_idempotent_and_forgetful() {
        let Some(db) = database().await else {
            return;
        };
        let a = user(&db).await;
        let b = user(&db).await;
        let publisher = Uuid::new_v4();
        let source = Uuid::new_v4();
        let id = Uuid::new_v4();
        let words = "Query new mash. Keep 42; <b>verbatim</b> 🌍";
        let event = entry(publisher, source, id, "user", words);
        let first = import(&db, &a, "external", serde_json::from_value(event.clone()).unwrap())
            .await
            .unwrap();
        session::update_conversation_metadata(
            &db,
            first["conversation_id"].as_str().unwrap(),
            &json!({"channel":"reviewed-dialogue","operator_label":"project/alpha"}),
        )
        .await
        .unwrap();
        let repeated = import(&db, &a, "external", serde_json::from_value(event.clone()).unwrap())
            .await
            .unwrap();
        assert_eq!(first, repeated);
        let conv = Uuid::parse_str(first["conversation_id"].as_str().unwrap()).unwrap();
        let row = fixtures::conversation(&db, conv).await;
        let actual = (row.user_id.clone().unwrap_or_default(), row.org_id.clone(), row.total_messages);
        assert_eq!(actual, (a.clone(), format!("org_{a}"), 1));
        let rows = fixtures::entries(&db, conv).await;
        assert_eq!(rows.len(), 1, "exactly one entry");
        let raw = rows[0].clone();
        assert_eq!((raw.0.as_str(), raw.1.as_str()), ("user", words));
        assert_eq!(raw.2["source"]["start_ms"], 80);
        let other = import(&db, &b, "external", serde_json::from_value(event.clone()).unwrap())
            .await
            .unwrap();
        assert_ne!(first["conversation_id"], other["conversation_id"]);
        let assistant = entry(
            publisher,
            source,
            Uuid::new_v4(),
            "assistant",
            "I connected!",
        );
        import(&db, &a, "external", serde_json::from_value(assistant).unwrap())
            .await
            .unwrap();
        let verified: Value = fixtures::entries(&db, conv).await.into_iter().find(|e| e.0 == "assistant").expect("an assistant entry").2;
        assert_eq!(verified["evidence"], "assistant_dialogue");
        assert_eq!(verified["verified_action"], false);
        // A native turn uses the same counter and retains adapter provenance.
        session::save_message(
            &db,
            &conv.to_string(),
            "assistant",
            "native turn",
            None,
            Some(&a),
        )
        .await
        .unwrap();
        let before = { let r = fixtures::conversation(&db, conv).await; (r.started_at, r.total_messages, r.metadata) };
        assert_eq!(before.1, 3);
        assert_eq!(before.2["channel"], "reviewed-dialogue");
        assert_eq!(before.2["operator_label"], "project/alpha");
        assert_eq!(
            before.2["external_source"]["publisher_id"],
            publisher.to_string()
        );

        // Failed immutable retries roll back even an attempted earlier start.
        for field in ["content", "created_at", "start_ms"] {
            let mut changed = event.clone();
            changed["entry"][field] = match field {
                "content" => json!("Altered words"),
                "created_at" => json!("2026-10-17T12:00:00Z"),
                _ => json!(0),
            };
            assert!(matches!(
                import(&db, &a, "external", serde_json::from_value(changed).unwrap()).await,
                Err(AppError::Conflict(_))
            ));
        }
        let after = { let r = fixtures::conversation(&db, conv).await; (r.started_at, r.total_messages, r.metadata) };
        assert_eq!(before, after);
        let deletion = json!({"version":1,"publisher_id":publisher,"event_id":Uuid::new_v4(),"conversation_id":source,"operation":"delete"});
        let receipt = import(&db, &a, "external", serde_json::from_value(deletion.clone()).unwrap())
            .await
            .unwrap();
        assert_eq!(receipt["status"], "deleted");
        // The delete itself writes the tombstone: suppression of a late replay
        // must not depend on noticing later that the conversation is gone.
        assert!(fixtures::source_tombstoned(&db, conv).await, "the delete tombstones its source at once");
        import(&db, &a, "external", serde_json::from_value(deletion).unwrap())
            .await
            .unwrap();
        let late = import(&db, &a, "external", serde_json::from_value(event).unwrap())
            .await
            .unwrap();
        assert_eq!(late["status"], "suppressed");
        let remaining = fixtures::entries(&db, conv).await.len();
        assert_eq!(remaining, 0);
        let other_conv = Uuid::parse_str(other["conversation_id"].as_str().unwrap()).unwrap();
        let other_remaining = fixtures::entries(&db, other_conv).await.len();
        assert_eq!(other_remaining, 1);
        fixtures::erase_conversation(&db, other_conv).await;
        let retry = entry(publisher, source, id, "user", words);
        let suppressed = import(&db, &b, "external", serde_json::from_value(retry).unwrap())
            .await
            .unwrap();
        assert_eq!(suppressed["status"], "suppressed");
        cleanup(&db, &[&a, &b]).await;
        db.close().await;
    }

    #[tokio::test]
    async fn native_writer_preserves_anonymous_attribution_and_org_repair() {
        let Some(db) = database().await else {
            return;
        };
        let a = user(&db).await;
        let b = user(&db).await;
        let source = format!("native_{}", Uuid::new_v4());
        let conv = Uuid::parse_str(&session::coerce_conversation_id(&source)).unwrap();
        session::save_message(&db, &source, "user", "system origin", None, None)
            .await
            .unwrap();
        let anonymous = { let r = fixtures::conversation(&db, conv).await; (r.user_id, r.org_id) };
        assert_eq!(anonymous, (None, "default".into()));
        let metadata = json!({"tool_calls": [{"name":"example"}]});
        session::save_message(
            &db,
            &source,
            "assistant",
            "identified",
            Some(&metadata),
            Some(&a),
        )
        .await
        .unwrap();
        session::save_message(&db, &source, "user", "later", None, Some(&b))
            .await
            .unwrap();
        let row = fixtures::conversation(&db, conv).await;
        let owner = (row.user_id.clone().unwrap_or_default(), row.org_id.clone(), row.total_messages);
        assert_eq!(owner, (a.clone(), format!("org_{a}"), 3));
        let stored: Value = fixtures::entries(&db, conv).await.into_iter().find(|e| e.0 == "assistant").expect("an assistant entry").2;
        assert_eq!(stored, metadata);
        cleanup(&db, &[&a, &b]).await;
        db.close().await;
    }

    #[tokio::test]
    async fn source_session_end_before_entries_and_out_of_order_retries() {
        let Some(db) = database().await else {
            return;
        };
        let a = user(&db).await;
        let publisher = Uuid::new_v4();
        let source = Uuid::new_v4();
        let ending = json!({"version":1,"publisher_id":publisher,"event_id":Uuid::new_v4(),
            "conversation_id":source,"operation":"session_end","session_id":"voice-session",
            "ended_at":"2026-10-18T12:01:00Z","end_reason":"user_stop","transcription":"complete"});
        let receipt = import(&db, &a, "external", serde_json::from_value(ending.clone()).unwrap())
            .await
            .unwrap();
        let conv = Uuid::parse_str(receipt["conversation_id"].as_str().unwrap()).unwrap();
        let event = entry(publisher, source, Uuid::new_v4(), "user", "before ending");
        import(&db, &a, "external", serde_json::from_value(event).unwrap())
            .await
            .unwrap();
        import(&db, &a, "external", serde_json::from_value(ending.clone()).unwrap())
            .await
            .unwrap();
        let mut earlier = ending;
        earlier["ended_at"] = json!("2026-10-18T12:00:30Z");
        import(&db, &a, "external", serde_json::from_value(earlier).unwrap())
            .await
            .unwrap();
        let actual = { let r = fixtures::conversation(&db, conv).await; (r.started_at, r.ended_at.expect("ended"), r.total_messages, r.metadata) };
        assert_eq!(actual.0.to_rfc3339(), "2026-10-18T12:00:00+00:00");
        assert_eq!(actual.1.to_rfc3339(), "2026-10-18T12:01:00+00:00");
        assert_eq!(actual.2, 1);
        assert_eq!(actual.3["last_source_session"]["transcription"], "complete");
        cleanup(&db, &[&a]).await;
        db.close().await;
    }

    #[tokio::test]
    async fn source_cannot_adopt_or_delete_another_owners_conversation() {
        let Some(db) = database().await else {
            return;
        };
        let a = user(&db).await;
        let b = user(&db).await;
        let publisher = Uuid::new_v4();
        let source = Uuid::new_v4();
        let conv = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("noomesh:conversation:{a}:{publisher}:{source}").as_bytes(),
        );
        // Simulate a conflicting native record, even though account-namespaced
        // UUIDs make ordinary cross-account source IDs disjoint.
        session::save_message(
            &db,
            &conv.to_string(),
            "user",
            "belongs to b",
            None,
            Some(&b),
        )
        .await
        .unwrap();
        let append = entry(publisher, source, Uuid::new_v4(), "user", "belongs to a");
        let ending = json!({"version":1,"publisher_id":publisher,"event_id":Uuid::new_v4(),
            "conversation_id":source,"operation":"session_end","session_id":"voice-session",
            "ended_at":"2026-10-18T12:01:00Z","end_reason":"user_stop","transcription":"complete"});
        let deletion = json!({"version":1,"publisher_id":publisher,"event_id":Uuid::new_v4(),
            "conversation_id":source,"operation":"delete"});
        for event in [append, ending, deletion] {
            assert!(matches!(
                import(&db, &a, "external", serde_json::from_value(event).unwrap()).await,
                Err(AppError::Conflict(_))
            ));
            let ledger = fixtures::source_rows(&db, conv).await;
            assert_eq!(
                ledger, 0,
                "source bookkeeping must roll back on writer conflicts"
            );
        }
        let actual = { let r = fixtures::conversation(&db, conv).await; (r.user_id.unwrap_or_default(), r.total_messages, r.metadata) };
        assert_eq!(actual, (b.clone(), 1, json!({})));
        fixtures::disable_user(&db, &a).await;
        let event = entry(publisher, source, Uuid::new_v4(), "user", "disabled user");
        for account in [&a, "nonexistent-publication-user"] {
            assert!(matches!(
                import(&db, account, "external", serde_json::from_value(event.clone()).unwrap()).await,
                Err(AppError::Forbidden(_))
            ));
        }
        cleanup(&db, &[&a, &b]).await;
        db.close().await;
    }
}
