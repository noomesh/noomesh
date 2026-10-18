// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Authenticated transcript-plane imports, independent of inference/augmentation.
//! Source dialogue is never promoted to verified tool evidence by this route.
use super::{AppError, AppResult};
use crate::{
    auth::{account_of, RequesterCtx},
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
    import(&state.db, account_of(&requester.0.sub), body.publication)
        .await
        .map(Json)
}

async fn import(db: &PgPool, account: &str, p: Publication) -> Result<Value, AppError> {
    validate(&p)?;
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM noo_users WHERE username=$1 AND disabled=false)",
    )
    .bind(account)
    .fetch_one(db)
    .await?;
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
    let new_source=sqlx::query("INSERT INTO noo_conversation_sources(user_id,publisher_id,source_id,conversation_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(account).bind(p.publisher_id).bind(p.conversation_id).bind(conversation).execute(&mut *tx).await?.rows_affected()==1;
    let mut deleted:bool=sqlx::query_scalar("SELECT deleted FROM noo_conversation_sources WHERE user_id=$1 AND publisher_id=$2 AND source_id=$3 FOR UPDATE")
        .bind(account).bind(p.publisher_id).bind(p.conversation_id).fetch_one(&mut *tx).await?;
    if !new_source && !deleted {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM noo_conversations WHERE id=$1)")
                .bind(conversation)
                .fetch_one(&mut *tx)
                .await?;
        // Noomesh may erase its copy independently. A surviving source ledger
        // must suppress old uploads rather than undo a keep-account erasure.
        if !exists {
            deleted = true;
            sqlx::query(
                "UPDATE noo_conversation_sources SET deleted=true WHERE conversation_id=$1",
            )
            .bind(conversation)
            .execute(&mut *tx)
            .await?;
        }
    }
    if p.operation == "delete" {
        // The source tombstone survives the conversation: a late/ambiguous
        // append retry cannot recreate deleted speech.
        sqlx::query("UPDATE noo_conversation_sources SET deleted=true WHERE conversation_id=$1")
            .bind(conversation)
            .execute(&mut *tx)
            .await?;
        session::delete_conversation_in(&mut tx, conversation, account).await?;
    } else if !deleted {
        let metadata = json!({"channel":"pai-voice","source_channel":"pai-voice","dialogue_only":true,"external_source":{
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

    fn entry(publisher: Uuid, conversation: Uuid, id: Uuid, role: &str, words: &str) -> Value {
        json!({"version":1,"publisher_id":publisher,"event_id":Uuid::new_v4(),
            "conversation_id":conversation,"operation":"entry","entry":{
                "id":id,"session_id":"voice-session","role":role,"content":words,
                "created_at":"2026-10-18T12:00:00Z","start_ms":80,"end_ms":320,
                "source":"stt","voice":"NATF2.pt"}})
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
        sqlx::query("INSERT INTO noo_users(username,hashed_password,org_id) VALUES($1,'unused-test-hash',$2)")
            .bind(&user).bind(format!("org_{user}")).execute(db).await.unwrap();
        user
    }

    async fn cleanup(db: &PgPool, users: &[&str]) {
        for user in users {
            sqlx::query("DELETE FROM noo_entries WHERE conversation_id IN(SELECT id FROM noo_conversations WHERE user_id=$1)").bind(user).execute(db).await.unwrap();
            sqlx::query("DELETE FROM noo_conversations WHERE user_id=$1")
                .bind(user)
                .execute(db)
                .await
                .unwrap();
            sqlx::query("DELETE FROM noo_conversation_sources WHERE user_id=$1")
                .bind(user)
                .execute(db)
                .await
                .unwrap();
            sqlx::query("DELETE FROM noo_users WHERE username=$1")
                .bind(user)
                .execute(db)
                .await
                .unwrap();
        }
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
        let first = import(&db, &a, serde_json::from_value(event.clone()).unwrap())
            .await
            .unwrap();
        session::update_conversation_metadata(
            &db,
            first["conversation_id"].as_str().unwrap(),
            &json!({"channel":"reviewed-dialogue","operator_label":"project/alpha"}),
        )
        .await
        .unwrap();
        let repeated = import(&db, &a, serde_json::from_value(event.clone()).unwrap())
            .await
            .unwrap();
        assert_eq!(first, repeated);
        let conv = Uuid::parse_str(first["conversation_id"].as_str().unwrap()).unwrap();
        let actual: (String, String, i32) = sqlx::query_as(
            "SELECT user_id,org_id,total_messages FROM noo_conversations WHERE id=$1",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(actual, (a.clone(), format!("org_{a}"), 1));
        let raw: (String, String, Value) = sqlx::query_as(
            "SELECT type,content,metadata FROM noo_entries WHERE conversation_id=$1",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!((raw.0.as_str(), raw.1.as_str()), ("user", words));
        assert_eq!(raw.2["source"]["start_ms"], 80);
        let other = import(&db, &b, serde_json::from_value(event.clone()).unwrap())
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
        import(&db, &a, serde_json::from_value(assistant).unwrap())
            .await
            .unwrap();
        let verified: Value = sqlx::query_scalar(
            "SELECT metadata FROM noo_entries WHERE conversation_id=$1 AND type='assistant'",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
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
        let before: (DateTime<Utc>, i32, Value) = sqlx::query_as(
            "SELECT started_at,total_messages,metadata FROM noo_conversations WHERE id=$1",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
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
                import(&db, &a, serde_json::from_value(changed).unwrap()).await,
                Err(AppError::Conflict(_))
            ));
        }
        let after: (DateTime<Utc>, i32, Value) = sqlx::query_as(
            "SELECT started_at,total_messages,metadata FROM noo_conversations WHERE id=$1",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(before, after);
        let deletion = json!({"version":1,"publisher_id":publisher,"event_id":Uuid::new_v4(),"conversation_id":source,"operation":"delete"});
        let receipt = import(&db, &a, serde_json::from_value(deletion.clone()).unwrap())
            .await
            .unwrap();
        assert_eq!(receipt["status"], "deleted");
        import(&db, &a, serde_json::from_value(deletion).unwrap())
            .await
            .unwrap();
        let late = import(&db, &a, serde_json::from_value(event).unwrap())
            .await
            .unwrap();
        assert_eq!(late["status"], "suppressed");
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM noo_entries WHERE conversation_id=$1")
                .bind(conv)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(remaining, 0);
        let other_conv = Uuid::parse_str(other["conversation_id"].as_str().unwrap()).unwrap();
        let other_remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM noo_entries WHERE conversation_id=$1")
                .bind(other_conv)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(other_remaining, 1);
        sqlx::query("DELETE FROM noo_entries WHERE conversation_id=$1")
            .bind(other_conv)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM noo_conversations WHERE id=$1")
            .bind(other_conv)
            .execute(&db)
            .await
            .unwrap();
        let retry = entry(publisher, source, id, "user", words);
        let suppressed = import(&db, &b, serde_json::from_value(retry).unwrap())
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
        let anonymous: (Option<String>, String) =
            sqlx::query_as("SELECT user_id,org_id FROM noo_conversations WHERE id=$1")
                .bind(conv)
                .fetch_one(&db)
                .await
                .unwrap();
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
        let owner: (String, String, i32) = sqlx::query_as(
            "SELECT user_id,org_id,total_messages FROM noo_conversations WHERE id=$1",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(owner, (a.clone(), format!("org_{a}"), 3));
        let stored: Value = sqlx::query_scalar(
            "SELECT metadata FROM noo_entries WHERE conversation_id=$1 AND type='assistant'",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
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
        let receipt = import(&db, &a, serde_json::from_value(ending.clone()).unwrap())
            .await
            .unwrap();
        let conv = Uuid::parse_str(receipt["conversation_id"].as_str().unwrap()).unwrap();
        let event = entry(publisher, source, Uuid::new_v4(), "user", "before ending");
        import(&db, &a, serde_json::from_value(event).unwrap())
            .await
            .unwrap();
        import(&db, &a, serde_json::from_value(ending.clone()).unwrap())
            .await
            .unwrap();
        let mut earlier = ending;
        earlier["ended_at"] = json!("2026-10-18T12:00:30Z");
        import(&db, &a, serde_json::from_value(earlier).unwrap())
            .await
            .unwrap();
        let actual: (DateTime<Utc>, DateTime<Utc>, i32, Value) = sqlx::query_as(
            "SELECT started_at,ended_at,total_messages,metadata FROM noo_conversations WHERE id=$1",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
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
                import(&db, &a, serde_json::from_value(event).unwrap()).await,
                Err(AppError::Conflict(_))
            ));
            let ledger: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM noo_conversation_sources WHERE conversation_id=$1",
            )
            .bind(conv)
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(
                ledger, 0,
                "source bookkeeping must roll back on writer conflicts"
            );
        }
        let actual: (String, i32, Value) = sqlx::query_as(
            "SELECT user_id,total_messages,metadata FROM noo_conversations WHERE id=$1",
        )
        .bind(conv)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(actual, (b.clone(), 1, json!({})));
        sqlx::query("UPDATE noo_users SET disabled=true WHERE username=$1")
            .bind(&a)
            .execute(&db)
            .await
            .unwrap();
        let event = entry(publisher, source, Uuid::new_v4(), "user", "disabled user");
        for account in [&a, "nonexistent-publication-user"] {
            assert!(matches!(
                import(&db, account, serde_json::from_value(event.clone()).unwrap()).await,
                Err(AppError::Forbidden(_))
            ));
        }
        cleanup(&db, &[&a, &b]).await;
        db.close().await;
    }
}
