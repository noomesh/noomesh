// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Communication routes — voice, channels, alerts.
//!
//! Native Rust: saved-recipients CRUD, alerts client count,
//!              channel status (config + env), send/test (HTTP to external APIs),
//!              recipients discovery (SQL), message history (SQL),
//!              inbound channel ingestion (WhatsApp, Google Chat, Telegram)
//!              is pull-only (long-polling / Pub/Sub pull) — there is no
//!              inbound webhook route; see `auth.rs`'s
//!              `channel_webhook_paths_are_no_longer_public` test,
//!              voice voices + voice status (provider inventory + reachability probes),
//!              voice transcribe/transcribe_detailed (generic STT provider layer — stt_client),
//!              voice synthesize (generic TTS provider layer — tts_client).

use std::sync::Arc;
use axum::{
    Router,
    routing::{get, post, put, delete},
    extract::{DefaultBodyLimit, Path, Query, State, Multipart},
    routing::MethodRouter,
    Extension,
    Json,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{scoped_user, ClusterNode, RequesterCtx};
use crate::measured::{put_into, Measured};
use crate::state::AppState;
use super::{AppResult, AppError};

// `worker.channels.send` was the LAST live `worker.channels.*` subject: the
// route below has dispatched natively since 2026-03-31, and the two residual
// escape paths into the Python adapter (`NOO_CHANNEL_FORCE_PYTHON` and the
// auth-failure fallback in `send_google_chat`) were retired in the design
// stage 4 together with the Python handler's registration. Nothing publishes
// `worker.channels.*` any more, on either side.
//
// The flag itself is gone too. After stage 4 it survived only as a warn-and-
// ignore branch in `send_google_chat`, kept for the operator who had set it
// and would otherwise have had their sends silently take the native path.
// That grace period is over: an env var the code reads but never obeys is
// the same lie as one it obeys but never documents, so the read is deleted
// rather than left to imply a working revert lever that no longer exists.
// There is nothing to revert TO — the Python channel engine is deleted, not
// dormant.

/// Body limit for the two transcribe routes: 10 MiB.
///
/// axum's default is 2 MiB, which cuts a recording off after a minute or
/// two. Browser MediaRecorder webm/opus is 32-128 kbit/s (4-16 kB/s); ten
/// minutes at the 128 kbit/s worst case is ~9.6 MB, so 10 MiB covers a
/// ten-minute recording at any bitrate the browser picks.
/// Applied to these two routes only; every other route keeps its own limit.
pub const TRANSCRIBE_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Wrap an audio-upload route in [`TRANSCRIBE_BODY_LIMIT`].
fn audio_upload<S: Clone + Send + Sync + 'static>(r: MethodRouter<S>) -> MethodRouter<S> {
    r.layer(DefaultBodyLimit::max(TRANSCRIBE_BODY_LIMIT))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Voice: Native Rust (HTTP proxy to whisper/TTS services, ported 2026-03-31) ──
        .route("/api/voice/transcribe", audio_upload(post(voice_transcribe)))
        .route("/api/voice/transcribe/detailed", audio_upload(post(voice_transcribe_detailed)))
        .route("/api/voice/synthesize", post(voice_synthesize))
        // ── Voice: Native Rust (config scan + HTTP health checks, ported 2026-03-31) ──
        .route("/api/voice/voices", get(voice_voices))
        .route("/api/voice/status", get(voice_status))

        // ── Alerts: Native Rust (connected WS client count) ──
        .route("/api/alerts/clients", get(alerts_clients))

        // ── Channels: Native Rust (config + env + SQL + HTTP) — ported 2026-03-31 ──
        .route("/api/channels/status", get(channels_status))
        .route("/api/channels/{channel}/recipients", get(channels_recipients))
        .route("/api/channels/send", post(channels_send))
        .route("/api/channels/test", post(channels_test))
        .route("/api/channels/{channel}/messages", get(channels_messages))

        // ── Saved Recipients: Native Rust (pure SQL on noo_channel_recipients) ──
        .route("/api/channels/saved-recipients", get(list_saved_recipients))
        .route("/api/channels/saved-recipients", post(create_saved_recipient))
        .route("/api/channels/saved-recipients/{recipient_db_id}", put(update_saved_recipient))
        .route("/api/channels/saved-recipients/{recipient_db_id}", delete(delete_saved_recipient))
}

// ═══════════════════════════════════════════════════════════════
// Alerts — Native handlers (AlertHub client count)
// ═══════════════════════════════════════════════════════════════

/// GET /api/alerts/clients — return count of connected WebSocket clients.
///
/// Response matches the Python endpoint: `{ connected_clients: N }`.
async fn alerts_clients(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    Ok(Json(json!({
        "connected_clients": state.alert_hub.count(),
    })))
}

// ═══════════════════════════════════════════════════════════════
// Saved Recipients — Native SQL handlers
// ═══════════════════════════════════════════════════════════════

// -- Query parameters / request bodies --

#[derive(Deserialize)]
struct ListRecipientsParams {
    channel: Option<String>,
}

#[derive(Deserialize)]
struct CreateRecipientBody {
    channel: String,
    recipient_id: String,
    display_name: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    is_default: bool,
    #[serde(default = "default_empty_object")]
    metadata: Value,
}

fn default_empty_object() -> Value {
    json!({})
}

#[derive(Deserialize)]
struct UpdateRecipientBody {
    display_name: Option<String>,
    notes: Option<String>,
    is_default: Option<bool>,
    metadata: Option<Value>,
}

// -- Row type for SELECT queries --

/// Matches the noo_channel_recipients table columns.
#[derive(sqlx::FromRow)]
struct RecipientRow {
    id: String,
    channel: String,
    recipient_id: String,
    display_name: String,
    notes: Option<String>,
    is_default: bool,
    metadata: Option<Value>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    /// Migration 071. `None` = the SHARED address book (every row that
    /// existed before 071, and anything an Operator+ creates without
    /// naming itself): readable by everyone, writable by Operator+ only.
    owner: Option<String>,
}

impl RecipientRow {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "channel": self.channel,
            "recipient_id": self.recipient_id,
            "display_name": self.display_name,
            "notes": self.notes.as_deref().unwrap_or(""),
            "is_default": self.is_default,
            "metadata": self.metadata.as_ref().unwrap_or(&json!({})),
            "created_at": self.created_at.to_rfc3339(),
            "updated_at": self.updated_at.to_rfc3339(),
            "owner": self.owner,
        })
    }
}

/// The address book a caller may WRITE to.
///
/// Reads are wider than writes on purpose:
///
/// | caller | reads | writes |
/// |---|---|---|
/// | Operator+, internal cluster services | every row | every row |
/// | `User` tier | its own rows **and** the shared (`owner IS NULL`) ones | its own rows only |
///
/// The shared rows are the ones that already existed when 071 landed. A
/// single-operator install keeps its contacts exactly as they were; a
/// User-tier account can still send to them, and cannot quietly rewrite or
/// delete a contact the whole install depends on.
/// The list query, with the scope as a NULLABLE bind rather than a spliced
/// clause. `$1` is the caller's username or NULL (Operator+ / internal),
/// `$2` is the optional channel filter. One statement, so the predicate
/// under test is the predicate that ships.
pub(crate) const RECIPIENT_LIST_SQL: &str = "SELECT id, channel, recipient_id, display_name, notes, \
        is_default, metadata, created_at, updated_at, owner \
 FROM noo_channel_recipients \
 WHERE ($1::text IS NULL OR owner = $1 OR owner IS NULL) \
   AND ($2::text IS NULL OR channel = $2) \
 ORDER BY channel, display_name";

/// May `scope` rewrite or delete a row owned by `owner`?
///
/// Operator+ and internal services (`scope` is `None`) may write anything.
/// A `User` may write only rows it owns — NOT the shared ones it can read,
/// which is the asymmetry the table above describes.
pub(crate) fn recipient_writable(owner: Option<&str>, scope: Option<&str>) -> bool {
    match scope {
        None => true,
        Some(me) => owner == Some(me),
    }
}

// -- Handlers --

/// GET /api/channels/saved-recipients — List saved channel contacts.
///
/// Optional `?channel=google_chat` filter. Returns all recipients ordered
/// by channel then display_name.
async fn list_saved_recipients(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Query(params): Query<ListRecipientsParams>,
) -> AppResult {
    // this returned every account's contacts — display
    // names, chat ids and free-text notes — to any `read`-scope caller,
    // because the table had no owner to scope by until migration 071.
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;
    let rows = sqlx::query_as::<_, RecipientRow>(RECIPIENT_LIST_SQL)
        .bind(scope.as_deref())
        .bind(params.channel.as_deref())
        .fetch_all(&state.db)
        .await?;

    let recipients: Vec<Value> = rows.iter().map(|r| r.to_json()).collect();
    let count = recipients.len();

    Ok(Json(json!({ "recipients": recipients, "count": count })))
}

/// POST /api/channels/saved-recipients — Create a new saved contact.
///
/// Checks for duplicate (channel + recipient_id). If `is_default` is true,
/// clears other defaults for that channel first.
async fn create_saved_recipient(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Json(body): Json<CreateRecipientBody>,
) -> AppResult {
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;

    // Duplicate check, within the caller's own book. Two people may both
    // save the same chat id under their own names; before ownership existed
    // the second of them got a 409 telling them a contact they could not see
    // already existed, which leaked the first one.
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM noo_channel_recipients \
         WHERE channel = $1 AND recipient_id = $2 \
           AND ($3::text IS NULL OR owner IS NOT DISTINCT FROM $3)"
    )
    .bind(&body.channel)
    .bind(&body.recipient_id)
    .bind(scope.as_deref())
    .fetch_one(&state.db)
    .await?;

    if existing > 0 {
        return Err(AppError::Conflict(
            "Recipient already exists for this channel".into(),
        ));
    }

    // "The default for this channel" is per address book, not per install:
    // clearing every other row's flag would reach into other people's
    // contacts to do it.
    if body.is_default {
        sqlx::query(
            "UPDATE noo_channel_recipients SET is_default = false \
             WHERE channel = $1 AND is_default = true \
               AND ($2::text IS NULL OR owner IS NOT DISTINCT FROM $2)"
        )
        .bind(&body.channel)
        .bind(scope.as_deref())
        .execute(&state.db)
        .await?;
    }

    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO noo_channel_recipients \
             (id, channel, recipient_id, display_name, notes, is_default, metadata, owner, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
    .bind(&id)
    .bind(&body.channel)
    .bind(&body.recipient_id)
    .bind(&body.display_name)
    .bind(&body.notes)
    .bind(body.is_default)
    .bind(&body.metadata)
    // NULL for Operator+ and internal services — they write the shared
    // book, which is what they wrote before 071 existed. A User-tier row is
    // stamped with the account, never with a guess.
    .bind(scope.as_deref())
    // Only a person's own write makes a target "registered" for the task guard: a recipient an agent
    // saved is not one a scheduled task may send to without approval (`task_guard::new_targets`).
    .bind(match crate::task_guard::resolve_origin(&state.db, &requester).await {
        crate::task_guard::Origin::Person { account, .. } => Some(account),
        crate::task_guard::Origin::Agent { .. } => None,
    })
    .execute(&state.db)
    .await?;

    Ok(Json(json!({
        "id": id,
        "channel": body.channel,
        "recipient_id": body.recipient_id,
        "display_name": body.display_name,
        "notes": body.notes,
        "is_default": body.is_default,
        "owner": scope,
    })))
}

/// Load a recipient the caller may WRITE to, or `404`.
///
/// 404 rather than 403 for the same reason `get_job` does it: the id is
/// addressable, so a 403 would confirm that somebody else's contact exists.
/// A User-tier caller gets 404 both for a row that does not exist and for a
/// row it may not touch — including a shared (`owner IS NULL`) row, which it
/// can read but not rewrite.
async fn writable_recipient(
    state: &AppState,
    id: &str,
    scope: Option<&str>,
) -> Result<RecipientRow, AppError> {
    let row = sqlx::query_as::<_, RecipientRow>(
        "SELECT id, channel, recipient_id, display_name, notes, \
                is_default, metadata, created_at, updated_at, owner \
         FROM noo_channel_recipients WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Saved recipient not found".into()))?;
    if recipient_writable(row.owner.as_deref(), scope) {
        Ok(row)
    } else {
        Err(AppError::NotFound("Saved recipient not found".into()))
    }
}

/// PUT /api/channels/saved-recipients/{recipient_db_id} — Update a saved contact.
///
/// Partial update: only provided fields are changed. If `is_default` is set
/// to true, other defaults for that channel are cleared first.
async fn update_saved_recipient(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(recipient_db_id): Path<String>,
    Json(body): Json<UpdateRecipientBody>,
) -> AppResult {
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;
    let row = writable_recipient(&state, &recipient_db_id, scope.as_deref()).await?;

    let new_display_name = body.display_name.as_deref().unwrap_or(&row.display_name);
    let new_notes = body.notes.as_deref()
        .unwrap_or(row.notes.as_deref().unwrap_or(""));
    let new_is_default = body.is_default.unwrap_or(row.is_default);
    let empty_meta = json!({});
    let new_metadata = body.metadata.as_ref()
        .unwrap_or(row.metadata.as_ref().unwrap_or(&empty_meta));

    // If setting as default, clear other defaults for this channel
    if body.is_default == Some(true) {
        sqlx::query(
            "UPDATE noo_channel_recipients SET is_default = false \
             WHERE channel = $1 AND is_default = true AND id != $2 \
               AND ($3::text IS NULL OR owner IS NOT DISTINCT FROM $3)"
        )
        .bind(&row.channel)
        .bind(&recipient_db_id)
        .bind(scope.as_deref())
        .execute(&state.db)
        .await?;
    }

    sqlx::query(
        "UPDATE noo_channel_recipients \
         SET display_name = $1, notes = $2, is_default = $3, \
             metadata = $4, updated_at = NOW() \
         WHERE id = $5"
    )
    .bind(new_display_name)
    .bind(new_notes)
    .bind(new_is_default)
    .bind(new_metadata)
    .bind(&recipient_db_id)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({
        "id": recipient_db_id,
        "channel": row.channel,
        "recipient_id": row.recipient_id,
        "display_name": new_display_name,
        "notes": new_notes,
        "is_default": new_is_default,
    })))
}

/// DELETE /api/channels/saved-recipients/{recipient_db_id} — Delete a saved contact.
async fn delete_saved_recipient(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(recipient_db_id): Path<String>,
) -> AppResult {
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        None,
    )
    .map_err(AppError::Forbidden)?;
    writable_recipient(&state, &recipient_db_id, scope.as_deref()).await?;

    let result = sqlx::query(
        "DELETE FROM noo_channel_recipients WHERE id = $1"
    )
    .bind(&recipient_db_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Saved recipient not found".into()));
    }

    Ok(Json(json!({ "deleted": true, "id": recipient_db_id })))
}

// ═══════════════════════════════════════════════════════════════
// Channels — Native handlers (ported from Python NATS 2026-03-31)
// ═══════════════════════════════════════════════════════════════

/// Known channel types and their required env vars.
pub(crate) const CHANNEL_ENV_KEYS: &[(&str, &[&str])] = &[
    ("whatsapp", &["WHATSAPP_TOKEN", "WHATSAPP_PHONE_ID"]),
    ("telegram", &["TELEGRAM_BOT_TOKEN"]),
    // GOOGLE_CHAT_CREDENTIALS_JSON is the key ITSELF, from the store. It
    // is listed FIRST because it is now the configured signal:
    // GOOGLE_CHAT_CREDENTIALS used to be set to the container path of a
    // materialised file, and that file is gone.
    (
        "google_chat",
        &["GOOGLE_CHAT_CREDENTIALS_JSON", "GOOGLE_CHAT_CREDENTIALS", "GOOGLE_CHAT_BEARER_TOKEN"],
    ),
];

/// GET /api/channels/status
/// Check which channels are configured by reading env vars.
/// Returns status compatible with the frontend (channels_registered, channels map, queue_mode).
async fn channels_status(State(_state): State<Arc<AppState>>) -> AppResult {
    let mut channels = serde_json::Map::new();
    let mut registered = 0u32;

    for &(name, keys) in CHANNEL_ENV_KEYS {
        // `configured` = at least one env var for this channel is set and
        // non-empty; `registered` is null because no channel-API probe is made.
        // Through `secret_env`: the credentials arrive as `/run/secrets`
        // files (`<NAME>_FILE`), so a plain env lookup would say "not
        // configured" for every channel that is.
        let configured = keys.iter().any(|k| crate::config::secret_env::secret_opt(k).is_some());
        if configured {
            registered += 1;
            let mut ch = json!({ "configured": true });
            put_into(&mut ch, "registered", Measured::<bool>::unmeasured(
                "unknown — this endpoint only checks that the channel's \
                 credential env vars are non-empty. No call is made to the \
                 channel API, so a revoked, expired or misscoped token is \
                 indistinguishable from a working one."));
            put_into(&mut ch, "stats", Measured::<Value>::unmeasured(
                "not tracked — per-channel received/sent/error counters do \
                 not exist in the gateway"));
            channels.insert(name.to_string(), ch);
        }
    }

    // `channels_registered` counts channels whose credentials are configured,
    // not channels confirmed registered with their provider.
    let mut body = json!({ "channels": channels, "queue_mode": "native" });
    put_into(&mut body, "channels_registered", Measured::noted(Some(registered),
        "count of channels with non-empty credential env vars; not a \
         confirmation that any adapter is registered with its provider."));
    put_into(&mut body, "active_conversations", Measured::<u32>::unmeasured(
        "not tracked — the gateway holds no per-channel conversation registry"));
    Ok(Json(body))
}

#[derive(Deserialize)]
struct ChannelSendBody {
    channel: String,
    recipient: String,
    message: String,
    thread_id: Option<String>,
    /// Optional absolute path to a local file to attach. For Google Chat
    /// the file is uploaded via `media.upload` and referenced from the
    /// outgoing message; channels without file-send support fall back to
    /// inline `message`. Used for heartbeat reports that exceed per-
    /// message char limits.
    file_path: Option<String>,
    /// Display filename for the attachment. Defaults to basename of
    /// `file_path` when omitted.
    filename: Option<String>,
}

/// POST /api/channels/send
/// Send a message via the specified channel's external API.
async fn channels_send(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<ChannelSendBody>,
) -> AppResult {
    let result = send_channel_message(
        &body.channel,
        &body.recipient,
        &body.message,
        body.thread_id.as_deref(),
        body.file_path.as_deref(),
        body.filename.as_deref(),
    ).await;

    match result {
        Ok(()) => Ok(Json(json!({
            "success": true,
            "channel": body.channel,
            "recipient": body.recipient,
        }))),
        Err(e) => Ok(Json(json!({
            "success": false,
            "channel": body.channel,
            "recipient": body.recipient,
            "error": e,
        }))),
    }
}

#[derive(Deserialize)]
struct ChannelTestBody {
    channel: String,
    recipient: String,
    #[serde(default = "default_test_message")]
    message: String,
}

fn default_test_message() -> String {
    "Hello from PAI!".into()
}

/// POST /api/channels/test
/// Send a test message via channels/send.
async fn channels_test(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<ChannelTestBody>,
) -> AppResult {
    let result = send_channel_message(
        &body.channel,
        &body.recipient,
        &body.message,
        None,
        None,
        None,
    ).await;

    match result {
        Ok(()) => Ok(Json(json!({
            "success": true,
            "channel": body.channel,
            "recipient": body.recipient,
        }))),
        Err(e) => Ok(Json(json!({
            "success": false,
            "channel": body.channel,
            "recipient": body.recipient,
            "error": e,
        }))),
    }
}

/// GET /api/channels/{channel}/recipients
/// Discover known chat contexts for a channel from conversation history (SQL).
async fn channels_recipients(
    State(state): State<Arc<AppState>>,
    Path(channel): Path<String>,
) -> AppResult {
    // Query conversations where metadata->>'source_channel' matches
    let rows = sqlx::query_as::<_, (String, Option<Value>, Option<i32>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT user_id, metadata, total_messages, started_at \
         FROM noo_conversations \
         WHERE metadata->>'source_channel' = $1 \
         ORDER BY started_at DESC"
    )
    .bind(&channel)
    .fetch_all(&state.db)
    .await?;

    // Deduplicate by user_id (keep first seen = most recent)
    let mut seen = std::collections::HashMap::<String, Value>::new();

    for (user_id, metadata, total_messages, started_at) in &rows {
        if seen.contains_key(user_id) {
            // Accumulate total_messages for duplicate user_ids
            if let Some(existing) = seen.get_mut(user_id) {
                if let Some(obj) = existing.as_object_mut() {
                    let prev = obj.get("total_messages").and_then(|v| v.as_i64()).unwrap_or(0);
                    obj.insert("total_messages".into(), json!(prev + total_messages.unwrap_or(0) as i64));
                }
            }
            continue;
        }

        let meta = metadata.as_ref().and_then(|m| m.as_object());
        let space_name = meta.and_then(|m| m.get("space_name")).and_then(|v| v.as_str());
        let chat_id = meta.and_then(|m| m.get("chat_id")).and_then(|v| v.as_str());
        let chat_type = meta.and_then(|m| m.get("chat_type")).and_then(|v| v.as_str()).unwrap_or("private");
        let chat_title = meta.and_then(|m| m.get("chat_title")).and_then(|v| v.as_str());
        let space_display = meta.and_then(|m| m.get("space_display_name")).and_then(|v| v.as_str());

        let recipient = space_name
            .or(chat_id)
            .unwrap_or_else(|| user_id.split(':').next_back().unwrap_or(user_id));

        let display_name = chat_title
            .or(space_display)
            .unwrap_or(user_id);

        seen.insert(user_id.clone(), json!({
            "user_id": user_id,
            "recipient": recipient,
            "chat_type": chat_type,
            "display_name": display_name,
            "total_messages": total_messages.unwrap_or(0),
            "last_active": started_at.map(|dt| dt.to_rfc3339()),
        }));
    }

    let recipients: Vec<Value> = seen.into_values().collect();
    Ok(Json(json!({
        "channel": channel,
        "recipients": recipients,
    })))
}

#[derive(Deserialize)]
struct ChannelMessagesParams {
    recipient: Option<String>,
    limit: Option<i64>,
    since: Option<String>,
}

/// GET /api/channels/{channel}/messages
/// Query channel message history from noo_entries (SQL).
///
/// Scoped. `recipient` used to be the only filter on
/// `c.user_id`, and it was a caller-supplied `LIKE '%…%'` substring: omit it
/// and the predicate short-circuits to true, returning every message on the
/// channel for every user — to any authenticated token, because
/// `scope_allows` admits all GETs. It is now the *requested* user handed to
/// `auth::scoped_user`, matched with `=`, and a User-tier caller is pinned to
/// its own subject whatever it asks for.
async fn channels_messages(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
    cluster: Option<Extension<ClusterNode>>,
    Path(channel): Path<String>,
    Query(params): Query<ChannelMessagesParams>,
) -> AppResult {
    let scope = scoped_user(
        requester.as_ref().map(|Extension(r)| r),
        cluster.as_ref().map(|Extension(c)| c),
        params.recipient.as_deref(),
    )
    .map_err(AppError::Forbidden)?;
    let limit = params.limit.unwrap_or(50).min(500);

    // Build query — filter by channel metadata, optionally by recipient and since timestamp
    let messages = if let Some(ref since) = params.since {
        sqlx::query_as::<_, (String, String, String, Option<Value>, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT e.id::text, e.type, e.content, e.metadata, e.created_at \
             FROM noo_entries e \
             JOIN noo_conversations c ON e.conversation_id = c.id \
             WHERE c.metadata->>'source_channel' = $1 \
               AND ($2::text IS NULL OR c.user_id = $2) \
               AND e.created_at > $3::timestamptz \
             ORDER BY e.created_at DESC \
             LIMIT $4"
        )
        .bind(&channel)
        .bind(&scope)
        .bind(since)
        .bind(limit)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, String, Option<Value>, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT e.id::text, e.type, e.content, e.metadata, e.created_at \
             FROM noo_entries e \
             JOIN noo_conversations c ON e.conversation_id = c.id \
             WHERE c.metadata->>'source_channel' = $1 \
               AND ($2::text IS NULL OR c.user_id = $2) \
             ORDER BY e.created_at DESC \
             LIMIT $3"
        )
        .bind(&channel)
        .bind(&scope)
        .bind(limit)
        .fetch_all(&state.db)
        .await?
    };

    let msg_list: Vec<Value> = messages.iter().map(|(id, typ, content, meta, created_at)| {
        json!({
            "id": id,
            "type": typ,
            "content": content,
            "metadata": meta,
            "created_at": created_at.map(|dt| dt.to_rfc3339()),
        })
    }).collect();

    let count = msg_list.len();
    Ok(Json(json!({
        "channel": channel,
        "recipient": scope,
        "messages": msg_list,
        "count": count,
    })))
}

// ═══════════════════════════════════════════════════════════════
// Channel send helpers — HTTP calls to external platform APIs
// ═══════════════════════════════════════════════════════════════

/// Send a message to the appropriate channel's external API.
/// Returns Ok(()) on success or Err(error_message) on failure.
///
/// `file_path` / `filename` are accepted for API compatibility and
/// carried by NO adapter today: Google Chat ignores them deliberately
/// (see `send_google_chat`), Telegram and WhatsApp never read them.
/// Callers that have a document to deliver put its text in `message`
/// (every adapter chunks) or upload it elsewhere and send a link — see
/// `heartbeat_actions::report_delivery_message`.
pub(crate) async fn send_channel_message(
    channel: &str,
    recipient: &str,
    message: &str,
    thread_id: Option<&str>,
    file_path: Option<&str>,
    filename: Option<&str>,
) -> Result<(), String> {
    match channel {
        "whatsapp" => send_whatsapp(recipient, message).await,
        "telegram" => send_telegram(recipient, message).await,
        "google_chat" => {
            // Generic outbound (heartbeat/cron) has no space-vs-DM signal;
            // pass chat_type=None → no messageReplyOption (unchanged behaviour).
            send_google_chat(recipient, message, thread_id, None, file_path, filename).await
        }
        _ => Err(format!("Channel '{}' not supported", channel)),
    }
}

/// Send a WhatsApp message via the Cloud API.
async fn send_whatsapp(recipient: &str, message: &str) -> Result<(), String> {
    let token = crate::config::secret_env::secret_required("WHATSAPP_TOKEN")?;
    let phone_id = std::env::var("WHATSAPP_PHONE_ID")
        .map_err(|_| "WHATSAPP_PHONE_ID not set".to_string())?;

    let url = format!("https://graph.facebook.com/v19.0/{phone_id}/messages");
    let client = crate::tls::external_client();

    // WhatsApp caps a text body at 4096 CHARACTERS and rejects anything
    // longer outright — so before splitting, a long answer was not truncated,
    // it was lost, with the failure confined to a log line. Agent responses
    // exceed this regularly. Same limit and splitter as Telegram.
    const WA_LIMIT: usize = 4096;
    // THE EGRESS FLOOR (crate::egress): every byte this transport sends has
    // been through `outbound`, whatever tier built it.
    let message = crate::egress::outbound(message);
    for chunk in split_message(message.as_str(), WA_LIMIT) {
        let payload = json!({
            "messaging_product": "whatsapp",
            "to": recipient,
            "type": "text",
            "text": {"body": chunk},
        });

        let resp = client.post(&url)
            .bearer_auth(&token)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("WhatsApp API request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("WhatsApp API error {status}: {body}"));
        }
    }
    Ok(())
}

// Notify the operator that an exec-approval window is open. Best-effort
// on every surface — a failed notification must never block (or fail)
// the gate; the CLI/dashboard can always decide the queue directly.
//
// Google Chat gets a native CARD with Approve/Deny buttons (the click
// lands in channels::approvals via the pubsub pipeline); Telegram gets a
// text notice with the id + CLI hint (inline keyboards are a follow-up).
// Targets mirror the retired Python notifier: NOO_APPROVAL_GCHAT_SPACE
// and NOO_APPROVAL_TELEGRAM_CHAT.
//
// (A stray "Send a Telegram message via the Bot API" line led this block:
// the doc of a function that moved away, left attached to a macro that
// cannot carry docs — so rustc was dropping the whole thing silently.)
tokio::task_local! {
    /// The reply target of the CHANNEL TURN currently being processed,
    /// scoped by the channel pipelines around coordinator::run. Lets the
    /// exec-approval card post into the conversation that ASKED — the
    /// operator's own DM/space in a single-operator install (operator
    /// decision 2026-08-08: "approvals would be a default for them all").
    /// Multi-user note: when chats stop being operator-only, this routing
    /// must become role-aware (card to an operator, not the requester) —
    /// flagged in the design's residuals.
    pub static CHANNEL_APPROVAL_TARGET: Option<ApprovalTarget>;

    /// Writer for the ORIGINATING dashboard chat socket, scoped by
    /// ws_coordinator around the turn. When present it outranks every
    /// other approval target: the request becomes a structured
    /// `approval_request` frame the UI renders as an inline card — the
    /// button transport Google Chat could not give us, the authenticated
    /// WS can. Decisions come back over the existing HTTP routes
    /// (`POST /api/approval/{id}/approve|deny`), NOT a socket frame — the
    /// read half of the socket is busy with the turn, and the HTTP path
    /// already carries auth + audit. Same multi-user caveat as
    /// CHANNEL_APPROVAL_TARGET.
    pub static DASHBOARD_APPROVAL_TX: Option<crate::websocket::WsWriter>;

    /// Gated tool calls that ended denied/expired during this coordinator
    /// turn. The channel pipeline reads this after the turn and prepends a
    /// correction banner when the model's reply would otherwise get the
    /// last word over the gateway — live 2026-08-09 the reply said "I have
    /// created the file" one line under the ⏳ NOT-executed notice.
    /// Entries for a tool are cleared if a later call of it succeeds.
    pub static GATED_TOOL_FAILURES: std::cell::RefCell<Vec<(String, String)>>;

    /// WHO and WHERE the current coordinator turn belongs to, scoped by
    /// `coordinator::run_inner` / `run_streaming_on` so it covers every
    /// entry point (channels, dashboard, `/api/inference`, tasks, harness)
    /// rather than only the two channel pipelines.
    ///
    /// The exec-approval gate stamps this onto the `noo_approval_requests`
    /// row. Without it the row said only "some tool wants to run" — `actor`
    /// was the empty string — and a bare `y` typed in ANY conversation
    /// decided the globally newest pending row: the person approving could
    /// not tell whose call it was, and the person whose call it was never
    /// had to be involved.
    pub static TURN_PRINCIPAL: TurnPrincipal;

    /// Successful HIGH-risk calls this turn, keyed by (tool, args) hash →
    /// their output. A model that re-issues the identical gated call (live
    /// 2026-08-09: gemma wrote the file, then asked to write it again,
    /// which re-prompted the operator) gets the recorded result back
    /// instead of a second approval round.
    pub static COMPLETED_GATED_CALLS: std::cell::RefCell<std::collections::HashMap<u64, String>>;
}

/// Look up a completed identical gated call this turn (None outside a
/// channel turn or on first occurrence).
pub(crate) fn completed_gated_call(key: u64) -> Option<String> {
    COMPLETED_GATED_CALLS
        .try_with(|c| c.borrow().get(&key).cloned())
        .ok()
        .flatten()
}

/// Record a successful gated call so an identical repeat short-circuits.
pub(crate) fn record_completed_gated_call(key: u64, output: &str) {
    let _ = COMPLETED_GATED_CALLS.try_with(|c| {
        c.borrow_mut().insert(key, output.to_string());
    });
}

/// Record a denied/expired gated call (no-op outside a channel turn).
pub(crate) fn record_gated_failure(tool: &str, what: &str) {
    let _ = GATED_TOOL_FAILURES.try_with(|f| {
        f.borrow_mut().push((tool.to_string(), what.to_string()));
    });
}

/// A later successful call supersedes earlier failures of the same tool.
pub(crate) fn clear_gated_failures(tool: &str) {
    let _ = GATED_TOOL_FAILURES.try_with(|f| {
        f.borrow_mut().retain(|(t, _)| t != tool);
    });
}

/// Correction banner for the channel reply, or None if the turn is clean.
pub fn gated_failure_banner() -> Option<String> {
    GATED_TOOL_FAILURES
        .try_with(|f| {
            let failures = f.borrow();
            if failures.is_empty() {
                return None;
            }
            let list: Vec<String> = failures
                .iter()
                .map(|(tool, what)| format!("{tool} ({what})"))
                .collect();
            Some(format!(
                "\u{26A0} Reality check: {} did NOT run. If the reply below \
                 claims otherwise, the reply is wrong.\n\n",
                list.join(", ")
            ))
        })
        .ok()
        .flatten()
}

/// The origin of a turn that is running somewhere else: the
/// dashboard socket and/or the channel target that asked. The task-locals
/// above are per task; a turn handed to a node's harness executes its
/// tools on the RAIL, in a different task, where they are unset — so the
/// dispatcher registers the origin here for the turn's lifetime and the
/// rail scopes them back in around each tool call.
#[derive(Clone, Default)]
pub struct TurnOrigin {
    pub dashboard: Option<crate::websocket::WsWriter>,
    pub channel: Option<ApprovalTarget>,
    /// The gated-call record of the remote turn, shared by every rail call
    /// it makes (the task-locals above are per task; each rail call is a
    /// task of its own). Read back by the dispatcher when the turn ends so
    /// the channel pipeline's "Reality check" banner sees what the loop's
    /// tools did NOT do, exactly as it would have in process.
    pub gated: std::sync::Arc<std::sync::Mutex<GatedRecord>>,
}

/// What the gated-call task-locals hold, in a form that can cross tasks.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct GatedRecord {
    pub failures: Vec<(String, String)>,
    pub completed: std::collections::HashMap<u64, String>,
}

impl GatedRecord {
    /// The current task's gated-call task-locals, as a record.
    pub fn capture() -> Self {
        Self {
            failures: GATED_TOOL_FAILURES.try_with(|f| f.borrow().clone()).unwrap_or_default(),
            completed: COMPLETED_GATED_CALLS.try_with(|c| c.borrow().clone()).unwrap_or_default(),
        }
    }
    /// Replay this record into the current task's task-locals (a no-op
    /// outside a channel turn, like the writers it uses).
    pub fn replay(&self) {
        for (tool, what) in &self.failures {
            record_gated_failure(tool, what);
        }
        for (key, out) in &self.completed {
            record_completed_gated_call(*key, out);
        }
    }
}

impl TurnOrigin {
    /// The origin of the CURRENT task, from its task-locals — what a
    /// dispatcher captures before handing the turn over.
    pub fn capture() -> Self {
        Self {
            dashboard: DASHBOARD_APPROVAL_TX.try_with(|t| t.clone()).ok().flatten(),
            channel: CHANNEL_APPROVAL_TARGET.try_with(|t| t.clone()).ok().flatten(),
            gated: Default::default(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.dashboard.is_none() && self.channel.is_none()
    }
    /// A snapshot of the remote turn's gated-call record so far.
    pub fn gated_record(&self) -> GatedRecord {
        self.gated.lock().map(|g| g.clone()).unwrap_or_default()
    }
    /// Store the record a rail call ended with.
    pub fn store_gated(&self, rec: GatedRecord) {
        if let Ok(mut g) = self.gated.lock() {
            *g = rec;
        }
    }
}

fn live_origins() -> &'static std::sync::RwLock<std::collections::HashMap<String, TurnOrigin>> {
    static O: std::sync::OnceLock<std::sync::RwLock<std::collections::HashMap<String, TurnOrigin>>> = std::sync::OnceLock::new();
    O.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Registers `origin` for `conversation_id` until dropped.
pub struct OriginGuard(String);

impl Drop for OriginGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = live_origins().write() {
            m.remove(&self.0);
        }
    }
}

/// Register where a conversation's in-flight remote turn came from. An
/// empty origin registers nothing (there is nowhere to route to).
pub fn register_origin(conversation_id: &str, origin: TurnOrigin) -> Option<OriginGuard> {
    if origin.is_empty() {
        return None;
    }
    if let Ok(mut m) = live_origins().write() {
        m.insert(conversation_id.to_string(), origin);
    }
    Some(OriginGuard(conversation_id.to_string()))
}

/// The origin of a conversation's in-flight remote turn, if any.
pub fn origin_for(conversation_id: &str) -> Option<TurnOrigin> {
    live_origins().read().ok().and_then(|m| m.get(conversation_id).cloned())
}

/// Who the current turn is FOR and where it is happening.
///
/// Scoped once, in the coordinator, so every surface that can block on an
/// approval gate carries the same binding. Fields are empty rather than
/// optional because they go straight into nullable text columns and an
/// empty string there means exactly what it says: nobody told us.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TurnPrincipal {
    /// Canonical `noo_users` username. Empty for unattended turns
    /// (heartbeat, autonomy) that act as the system rather than a person.
    pub requester: String,
    pub conversation_id: String,
    /// `telegram` | `google_chat` | `dashboard` | `api` | …
    pub channel: String,
    /// A random id minted once per agent run (turn). Every tool call of the run
    /// shares it, different runs (concurrent ones included) never do. It is what
    /// a worker-delegated token's `harness` binds to, so the asynchronous-
    /// operations API shows an agent run only the ops that run started. Empty
    /// outside a coordinator turn.
    pub run_id: String,
}

/// The current turn's principal, or the default outside a coordinator turn.
pub(crate) fn turn_principal() -> TurnPrincipal {
    TURN_PRINCIPAL.try_with(|p| p.clone()).unwrap_or_default()
}

/// Run `fut` with `principal` bound for the whole turn.
pub(crate) async fn with_turn_principal<F: std::future::Future>(
    principal: TurnPrincipal,
    fut: F,
) -> F::Output {
    TURN_PRINCIPAL.scope(principal, fut).await
}

/// Where an approval card for the current channel turn should go.
#[derive(Clone, Debug)]
pub struct ApprovalTarget {
    pub channel: &'static str, // "google_chat" | "telegram"
    pub recipient: String,
    pub thread_id: Option<String>,
    pub chat_type: String,
}

/// Telegram legacy-`Markdown` metacharacters, escaped for interpolation.
///
/// `send_telegram` posts with `parse_mode: Markdown`, and the approval notice
/// uses that deliberately — `*y*` / `*n*` and a code-spanned command. So the
/// notice cannot be sent as plain text, and any value INTERPOLATED into it
/// must not be able to open an entity the notice never closes.
///
/// A tool name can. `python_tool` and `skill_execute` carry exactly ONE
/// underscore, which opens an italic span that is never closed, and Telegram
/// rejects the whole message with HTTP 400 "can't parse entities". Those are
/// the two HIGH-risk tools the gate exists for, so the notice failed for
/// precisely the calls that most needed it — while `noo_config_set` (two
/// underscores) delivered, italicised, and `browser` (none) was fine. That
/// is why it read as intermittent (tracker R48).
///
/// Escaping here at the CALL SITE, not in `send_telegram`: the sender must
/// keep passing the notice's own intentional markup through. PR #141 makes
/// the sender retry as plain text when Telegram still objects; this makes it
/// not objectionable in the first place, and the two compose.
pub(crate) fn escape_markdown_legacy(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        if matches!(c, '_' | '*' | '`' | '[') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The approval-window notice. Pure, so the Markdown it emits can be
/// asserted without a network.
pub(crate) fn exec_approval_notice(tool: &str, request_id: &str, window_secs: u64) -> String {
    let window_mins = window_secs.div_ceil(60);
    // The tool name is the only interpolated value that can carry markup;
    // request_id is a hex uuid slice.
    let tool = escape_markdown_legacy(tool);
    format!(
        "\u{1F510} Approval needed: {tool} (id {request_id})\n\n\
         \u{27A1} Reply *y* / *n* (or approve / deny) within {window_mins} \
         minutes. If nothing is decided, the action will NOT run.\n\n\
         Other ways to decide: dashboard Admin view, or \
         `noo approval approve {request_id}`."
    )
}

/// Why no card was posted, for the fallback log line.
///
/// `None` means there genuinely was no channel origin (a heartbeat or
/// autonomy call). `Some` means there WAS one and delivery to it failed —
/// two very different situations that the old single message conflated, and
/// the conflation cost three wrong diagnoses of R48: the log said "no
/// channel origin" while the origin was present and readable, because the
/// telegram arm had thrown its send error away in a match guard.
fn no_card_reason(origin_failure: Option<(&str, &str)>) -> String {
    match origin_failure {
        None => "exec_approval: no channel origin and NOO_APPROVAL_GCHAT_SPACE \
                 unset — no card posted; decide via noo approval / dashboard"
            .to_string(),
        Some((channel, recipient)) => format!(
            "exec_approval: the originating {channel} chat {recipient} REFUSED the \
             notice (see the error logged above) and NOO_APPROVAL_GCHAT_SPACE is \
             unset — no card posted; decide via noo approval / dashboard"
        ),
    }
}

pub(crate) async fn notify_exec_approval(tool: &str, request_id: &str, window_secs: u64) {
    let text = exec_approval_notice(tool, request_id, window_secs);

    // The ORIGINATING conversation first: if this tool call came from a
    // channel turn, the card/notice goes right where the human is already
    // talking — every Google Chat location gets approvals by default, no
    // per-space configuration. The env targets remain the fallback for
    // calls with no channel context (heartbeat tasks, autonomy actions).
    // Dashboard origin outranks everything: the originating chat socket
    // gets a structured frame the UI renders as an inline Approve/Deny
    // card. Falls through to the channel/env targets only if the
    // socket is already gone.
    let dash = DASHBOARD_APPROVAL_TX.try_with(|t| t.clone()).ok().flatten();
    if let Some(writer) = dash {
        let delivered = writer
            .send_event(
                "approval_request",
                serde_json::json!({
                    "request_id": request_id,
                    "tool": tool,
                    "window_secs": window_secs,
                    "text": text,
                }),
            )
            .await;
        if delivered {
            return;
        }
        tracing::warn!("exec_approval.dashboard_frame_failed");
    }

    let origin = CHANNEL_APPROVAL_TARGET
        .try_with(|t| t.clone())
        .ok()
        .flatten();

    // Remembered so the fallback below can say WHICH of the two happened.
    let mut origin_failure: Option<(&str, String)> = None;

    if let Some(target) = origin {
        // Plain text, deliberately NOT a button card: Google never
        // delivers button clicks to a Pub/Sub-connected app (no
        // synchronous interaction endpoint), so buttons rendered but
        // errored on every press ("MESH is unable to process your
        // request", live 2026-08-09). Text-reply approve/deny is the
        // transport that works; buttons can return if an
        // authenticated HTTPS interaction endpoint is ever added
        // (followup: exec-approval buttons need real ingress).
        //
        // Both arms report their error the SAME way. The telegram arm used
        // to be a match guard — `"telegram" if send(...).is_ok() =>` — so a
        // send failure made the arm not match, fell to `_ => {}`, and
        // discarded the error with no log at all (R48).
        let sent = match target.channel {
            "google_chat" => send_google_chat_reply(
                &target.recipient,
                &format!("\u{1F510} {text}"),
                target.thread_id.as_deref(),
                Some(&target.chat_type),
            )
            .await,
            "telegram" => send_telegram(&target.recipient, &text).await,
            other => Err(format!("no notice transport for channel '{other}'")),
        };
        match sent {
            Ok(()) => return, // delivered where the request came from
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    channel = target.channel,
                    recipient = %target.recipient,
                    "exec_approval.origin_notice_failed"
                );
                origin_failure = Some((target.channel, target.recipient.clone()));
            }
        }
        // fall through to env targets if origin delivery failed
    }

    let gchat_space = std::env::var("NOO_APPROVAL_GCHAT_SPACE").unwrap_or_default();
    let gchat_space = gchat_space.trim();
    if !gchat_space.is_empty() {
        if let Err(e) =
            send_google_chat_reply(gchat_space, &format!("\u{1F510} {text}"), None, None).await
        {
            tracing::warn!(error = %e, "exec_approval.gchat_notice_failed");
        }
    } else {
        tracing::info!(
            "{}",
            no_card_reason(origin_failure.as_ref().map(|(c, r)| (*c, r.as_str())))
        );
    }

    let tg_chat = std::env::var("NOO_APPROVAL_TELEGRAM_CHAT").unwrap_or_default();
    let tg_chat = tg_chat.trim();
    if !tg_chat.is_empty() {
        if let Err(e) = send_telegram(tg_chat, &text).await {
            tracing::warn!(error = %e, "exec_approval.telegram_notice_failed");
        }
    }
}

/// Deterministic outcome notice for a gated tool call that did NOT run
/// (denied or expired). Sent by the gateway itself so the human never has
/// to trust the model's own account of whether a blocked action happened —
/// the first live timeout ended with the model claiming the file was
/// created. Same origin-first targeting as
/// [`notify_exec_approval`]; falls back to the env targets.
pub(crate) async fn notify_exec_outcome(text: &str) {
    // Dashboard origin first — the UI turns this into the card's verdict
    // echo (and it is the gateway's own account, not the model's).
    let dash = DASHBOARD_APPROVAL_TX.try_with(|t| t.clone()).ok().flatten();
    if let Some(writer) = dash {
        if writer
            .send_event("approval_outcome", serde_json::json!({ "text": text }))
            .await
        {
            return;
        }
        tracing::warn!("exec_outcome.dashboard_frame_failed");
    }

    let origin = CHANNEL_APPROVAL_TARGET
        .try_with(|t| t.clone())
        .ok()
        .flatten();

    if let Some(target) = origin {
        let delivered = match target.channel {
            "google_chat" => send_google_chat_reply(
                &target.recipient,
                text,
                target.thread_id.as_deref(),
                Some(&target.chat_type),
            )
            .await
            .is_ok(),
            "telegram" => send_telegram(&target.recipient, text).await.is_ok(),
            _ => false,
        };
        if delivered {
            return;
        }
        tracing::warn!("exec_outcome.origin_notice_failed");
    }

    let gchat_space = std::env::var("NOO_APPROVAL_GCHAT_SPACE").unwrap_or_default();
    let gchat_space = gchat_space.trim();
    if !gchat_space.is_empty() {
        if let Err(e) = send_google_chat_reply(gchat_space, text, None, None).await {
            tracing::warn!(error = %e, "exec_outcome.gchat_notice_failed");
        }
    }
    let tg_chat = std::env::var("NOO_APPROVAL_TELEGRAM_CHAT").unwrap_or_default();
    let tg_chat = tg_chat.trim();
    if !tg_chat.is_empty() {
        if let Err(e) = send_telegram(tg_chat, text).await {
            tracing::warn!(error = %e, "exec_outcome.telegram_notice_failed");
        }
    }
}

pub(crate) async fn send_telegram_reply(recipient: &str, message: &str) -> Result<(), String> {
    send_telegram(recipient, message).await
}

async fn send_telegram(recipient: &str, message: &str) -> Result<(), String> {
    let token = crate::config::secret_env::secret_required("TELEGRAM_BOT_TOKEN")?;
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let client = crate::tls::external_client();
    // Match Python TelegramAdapter parity: agent responses regularly exceed
    // 4096 chars and Telegram silently rejects oversize messages. Split on
    // char boundaries (not bytes — Telegram counts code points), prefer
    // splitting at line breaks when one is within the last ~25% of the
    // window so we don't tear sentences in half.
    const TG_LIMIT: usize = 4096;
    // THE EGRESS FLOOR (crate::egress): every byte this transport sends has
    // been through `outbound`, whatever tier built it.
    let message = crate::egress::outbound(message);
    for chunk in split_message(message.as_str(), TG_LIMIT) {
        // Markdown first: the model's replies use it and Telegram renders it.
        // But Telegram's legacy Markdown parser rejects the WHOLE message on
        // one unbalanced `_`, `*` or backtick ("can't parse entities: Can't
        // find end of the entity starting at byte offset N"), and a model
        // reply hits that regularly — a snake_case name, a stray asterisk.
        // The operator then sees nothing at all (2026-09-12: the first
        // linked-sender reply after the security release bounced this way).
        // A plain-text delivery of the same words beats a perfectly
        // formatted message nobody receives, so on that one error the chunk
        // is resent with no parse_mode.
        let mut payload = json!({
            "chat_id": recipient,
            "text": chunk,
            "parse_mode": "Markdown",
        });
        let mut attempt = 0;
        loop {
            attempt += 1;
            let resp = client
                .post(&url)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| format!("Telegram API request failed: {}", crate::redact::scrub(&e.to_string())))?;
            if resp.status().is_success() {
                break;
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if attempt == 1 && is_entity_parse_error(status.as_u16(), &body) {
                tracing::warn!(
                    "telegram_markdown_rejected — resending this chunk as plain text: {}",
                    body.chars().take(160).collect::<String>()
                );
                if let Some(o) = payload.as_object_mut() {
                    o.remove("parse_mode");
                }
                continue;
            }
            return Err(format!("Telegram API error {status}: {body}"));
        }
    }
    Ok(())
}

/// One Telegram message carrying an inline keyboard (the cluster-proposal
/// Approve/Reject buttons). Lives HERE, beside the other transports, so the
/// egress floor applies to it and no other file builds a Telegram send URL
/// (`tests/test_channel_egress_guard.py`). Markdown, single message: the
/// callers' texts are short and their own.
pub(crate) async fn send_telegram_keyboard(
    recipient: &str,
    message: &str,
    reply_markup: &Value,
) -> Result<(), String> {
    let token = crate::config::secret_env::secret_required("TELEGRAM_BOT_TOKEN")?;
    // THE EGRESS FLOOR (crate::egress).
    let message = crate::egress::outbound(message);
    let markup = reply_markup.to_string();
    let form = [
        ("chat_id", recipient),
        ("text", message.as_str()),
        ("parse_mode", "Markdown"),
        ("reply_markup", markup.as_str()),
    ];
    let resp = crate::tls::external_client()
        .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
        .form(&form)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Telegram API request failed: {}", crate::redact::scrub(&e.to_string())))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Telegram API error {}", resp.status()))
    }
}

/// Telegram's "the text is fine, the MARKUP is not" answer: HTTP 400 with
/// `can't parse entities`. Everything else (bad chat id, blocked bot, rate
/// limit) is a real failure and must not be retried as plain text.
fn is_entity_parse_error(status: u16, body: &str) -> bool {
    status == 400 && body.contains("can't parse entities")
}

/// Split a reply into chunks of at most `limit` CHARACTERS, preferring line
/// boundaries. Platform-agnostic: Telegram and WhatsApp both cap at 4096 and
/// both count code points, not bytes.
fn split_message(message: &str, limit: usize) -> Vec<String> {
    if message.chars().count() <= limit {
        return vec![message.to_string()];
    }
    let mut chunks: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut buf_len = 0usize;
    for line in message.split_inclusive('\n') {
        let line_len = line.chars().count();
        if buf_len + line_len > limit {
            // Flush current buffer (or split the line if it alone exceeds limit)
            if buf_len > 0 {
                chunks.push(std::mem::take(&mut buf));
                buf_len = 0;
            }
            if line_len > limit {
                let mut taken = 0;
                let mut piece = String::new();
                for ch in line.chars() {
                    piece.push(ch);
                    taken += 1;
                    if taken == limit {
                        chunks.push(std::mem::take(&mut piece));
                        taken = 0;
                    }
                }
                if !piece.is_empty() {
                    buf = piece;
                    buf_len = taken;
                }
                continue;
            }
        }
        buf.push_str(line);
        buf_len += line_len;
    }
    if !buf.is_empty() {
        chunks.push(buf);
    }
    chunks
}

/// Send a Google Chat message via the REST API.
///
/// When `file_path` is set, performs the two-step attachment flow:
///   1. `POST /upload/v1/{space}/attachments:upload?uploadType=multipart`
///   2. `POST /v1/{space}/messages` with `attachment` referencing the
///      upload's `attachmentDataRef`.
/// Falls back to plain text on upload failure so the user still gets the
/// inline summary instead of a silent drop.
/// Send a Google Chat reply from the native Rust pipeline.
///
/// Thin `pub(crate)` wrapper over [`send_google_chat`] so the channels
/// pipeline can reach it without exposing the file-upload arguments it
/// never uses. Formatting and the named-space `messageReplyOption` rule
/// live inside `send_google_chat` and are applied here too — callers must
/// pass RAW text, not pre-formatted.
pub(crate) async fn send_google_chat_reply(
    recipient: &str,
    message: &str,
    thread_id: Option<&str>,
    chat_type: Option<&str>,
) -> Result<(), String> {
    send_google_chat(recipient, message, thread_id, chat_type, None, None).await
}

/// Reject a recipient the Chat REST path cannot address.
///
/// Valid targets are space resource names (`spaces/<id>`); a DM is also a
/// space. `users/<id>` is a real Chat resource name but has no
/// `/v1/users/*/messages` collection, so it is called out separately —
/// that shape is a routing mistake, not a typo.
fn validate_chat_recipient(recipient: &str) -> Result<(), String> {
    let name = recipient.trim();
    if name.is_empty() {
        return Err(
            "Google Chat recipient is empty — set it to a space resource name \
             like `spaces/<id>` (operator alerts read \
             NOO_AGENT_ALERT_RECIPIENT)"
                .to_string(),
        );
    }
    if let Some(rest) = name.strip_prefix("spaces/") {
        if rest.is_empty() || rest.contains('/') {
            return Err(format!(
                "Google Chat recipient {name:?} is not a space resource name — \
                 expected `spaces/<id>` with a single segment"
            ));
        }
        return Ok(());
    }
    if name.starts_with("users/") {
        return Err(format!(
            "Google Chat recipient {name:?} addresses a user, but the Chat API \
             has no /v1/users/*/messages collection — send to the space \
             (`spaces/<id>`); a DM is a space too"
        ));
    }
    Err(format!(
        "Google Chat recipient {name:?} is not a Chat resource name — expected \
         `spaces/<id>` (operator alerts read NOO_AGENT_ALERT_RECIPIENT)"
    ))
}

async fn send_google_chat(
    recipient: &str,
    message: &str,
    thread_id: Option<&str>,
    chat_type: Option<&str>,
    file_path: Option<&str>,
    filename: Option<&str>,
) -> Result<(), String> {
    // Native Rust path: SA OAuth2 → access token → chat.googleapis.com.
    // Replaces the broken static-bearer code from the 2026-03-31 Rust
    // port (which used GOOGLE_CHAT_BEARER_TOKEN — the inbound webhook
    // verification token — as if it were the API access token, getting
    // 403 every call). See the design for the parity contract.
    //
    // Auth failure is a hard error now. It used to fall back to the Python
    // adapter, but that adapter did the SAME service-account OAuth2 exchange
    // from the same credentials — a second implementation of the same job,
    // which is the bug class the design exists to remove — so the fallback
    // could only ever mask the misconfiguration, never recover from it.
    let token = crate::google_auth::chat_access_token()
        .await
        .map_err(|e| format!("Google Chat auth failed: {e}"))?;

    let client = crate::tls::external_client();

    // Note: chat-attachment uploads were tried via DWD impersonation but
    // hit a cross-identity wall (bot can't reference user-uploaded
    // attachments in messages.create). Heartbeat dispatch now uploads
    // long-form artifacts to a Shared Drive folder and posts a viewable
    // link instead — see `google_drive::upload_to_folder` and
    // `heartbeat_actions::notify_channels`. The `file_path` / `filename`
    // params on this function are kept for API compatibility but
    // intentionally ignored on the google_chat path.
    let _ = (file_path, filename);

    // Thread routing: carry the thread as `thread.name` in the body, and —
    // for a threaded NAMED SPACE only — add
    // `messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD` as a query
    // param. Without it the create defaults to MESSAGE_REPLY_OPTION_UNSPECIFIED,
    // which the Chat API documents as "Starts a new thread. Using this option
    // ignores any thread ID" — i.e. the space reply lands OUTSIDE the user's
    // thread (the reported bug). The option is "Only supported in named spaces"
    // per the docs, so DMs (chat_type != "space") must NOT send it — mirrors
    // Python `_reply_option` in channels/google_chat.py.
    // The recipient is interpolated straight into the REST path, so it must
    // already be a Chat resource name. Anything else produces a URL that is
    // not a Chat API endpoint at all, and Google answers with an HTML 404 —
    // which reads in the log exactly like a revoked token or a deleted space,
    // sending the reader after a credential that is fine. Refusing here names
    // the actual fault instead. See `google_chat_format::resolve_reply_target`
    // for the same trap on the inbound side (`users/…`, fixed 2026-08-08);
    // this is the outbound half, found 2026-09-20 when every operator alert
    // for an hour 404'd against the literal default `broadcast`.
    validate_chat_recipient(recipient)?;

    let mut url = format!("https://chat.googleapis.com/v1/{recipient}/messages");
    if thread_id.is_some() && chat_type == Some("space") {
        url.push_str("?messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD");
    }
    // Google Chat doesn't render Markdown — `**bold**` shows as raw
    // asterisks, `# Heading` shows the literal `#`. Convert the most
    // common markdown patterns to Google Chat's lightweight format so
    // heartbeat reports look like text instead of source code.
    // THE EGRESS FLOOR (crate::egress): every byte this transport sends has
    // been through `outbound`, whatever tier built it.
    let message = crate::egress::outbound(message);
    let formatted_message = markdown_to_gchat(message.as_str());
    // Chat caps `text` at 4096 characters and rejects a longer create
    // outright (400 INVALID_ARGUMENT), so a full inline report — the only
    // way a report reaches Chat when no Drive folder is configured — must
    // be split like Telegram and WhatsApp already do. Split AFTER the
    // markdown conversion so a `*bold*` pair is never cut in half.
    const GCHAT_LIMIT: usize = 4096;
    for chunk in split_message(&formatted_message, GCHAT_LIMIT) {
        let mut payload = json!({"text": chunk});
        if let Some(tid) = thread_id {
            payload["thread"] = json!({"name": tid});
        }

        let resp = client
            .post(&url)
            .bearer_auth(&token)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Google Chat API request failed: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Google Chat API error {status}: {body}"));
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Voice transcribe / synthesize — Native Rust HTTP proxies
// ═══════════════════════════════════════════════════════════════
//
// voice_transcribe / voice_transcribe_detailed: route through the generic
//   STT provider layer (crate::stt_client — mirror of embedding_client):
//   config picks the provider + wire format (openai-compatible
//   /v1/audio/transcriptions by default, legacy whisper-service shape
//   for pre-provider installs). The response contract the CLI pins
//   ({text, language, confidence, duration, [segments]}) is produced by
//   the client regardless of provider.
//
// voice_synthesize: routes through the generic TTS provider layer
//   (crate::tts_client — twin of stt_client): config picks the provider +
//   wire format (OpenAI-compatible /v1/audio/speech by default, the legacy
//   native /synthesize shape for pre-provider installs). The response
//   contract the CLI pins (audio bytes + content-type + X-TTS-Backend) is
//   produced by the client regardless of provider. edge-tts is deliberately
//   NOT a provider here — it is a signed WebSocket client, not an HTTP
//   service; see the tts_client module docs for the two honest ways to keep
//   edge voices.

/// Resolve the configured STT endpoint, honouring the legacy
/// `voice.whisper_url` YAML key that predates the provider layer (that
/// section never graduated into the typed AppConfig, so the raw YAML is
/// read here and passed in).
async fn stt_endpoint(state: &AppState) -> crate::stt_client::SttEndpoint {
    let legacy = {
        let config = state.config_yaml.read().await;
        config
            .get("voice")
            .and_then(|v| v.get("whisper_url"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
    };
    crate::stt_client::resolve(legacy)
}

/// Resolve the configured TTS endpoint, honouring the legacy
/// `voice.tts_url` YAML key that predates the provider layer (same
/// treatment as `voice.whisper_url` above).
async fn tts_endpoint(state: &AppState) -> crate::tts_client::TtsEndpoint {
    let legacy = {
        let config = state.config_yaml.read().await;
        config
            .get("voice")
            .and_then(|v| v.get("tts_url"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
    };
    crate::tts_client::resolve(legacy)
}

/// POST /api/voice/transcribe — transcribe audio via the configured STT
/// provider (see `crate::stt_client` for providers + config keys).
///
/// Accepts multipart audio upload (field name: "file") and optional form
/// fields "model" and "language" — the contract `noo voice transcribe` pins.
///
/// Response shape (matching Python TranscriptionResponse):
/// ```json
/// { "text": "...", "language": "en", "confidence": 0.95, "duration": 3.2, "language_probability": 0.99 }
/// ```
async fn voice_transcribe(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> axum::response::Response {
    transcribe_via_provider(state, multipart, false).await
}

/// POST /api/voice/transcribe/detailed — transcribe with segment-level timestamps.
///
/// Same as transcribe but additionally returns segments:
/// ```json
/// { "text": "...", "language": "en", "confidence": 0.95, "duration": 3.2,
///   "segments": [{"start": 0.0, "end": 1.5, "text": "...", "avg_logprob": -0.3}] }
/// ```
async fn voice_transcribe_detailed(
    State(state): State<Arc<AppState>>,
    multipart: Multipart,
) -> axum::response::Response {
    transcribe_via_provider(state, multipart, true).await
}

/// A multipart read failure, with the status axum chose: 413 when the body
/// limit was hit, 400 for a malformed upload.
fn multipart_error_response(e: &axum::extract::multipart::MultipartError) -> axum::response::Response {
    (e.status(), Json(json!({"error": format!("Failed to read audio: {e}")}))).into_response()
}

/// Shared handler body: collect the multipart upload, hand it to the STT
/// provider client, relay the contract-shaped reply.
async fn transcribe_via_provider(
    state: Arc<AppState>,
    mut multipart: Multipart,
    detailed: bool,
) -> axum::response::Response {
    let mut audio: Option<(Vec<u8>, String, String)> = None; // bytes, filename, mime
    let mut opts = crate::stt_client::TranscribeOptions { detailed, ..Default::default() };

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => return multipart_error_response(&e),
        };
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                let filename = field.file_name().unwrap_or("audio.wav").to_string();
                let content_type = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                match field.bytes().await {
                    Ok(bytes) => {
                        if bytes.is_empty() {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(json!({"error": "Empty audio file"})),
                            )
                                .into_response();
                        }
                        audio = Some((bytes.to_vec(), filename, content_type));
                    }
                    Err(e) => return multipart_error_response(&e),
                }
            }
            "model" => {
                if let Ok(text) = field.text().await {
                    opts.model = Some(text);
                }
            }
            "language" => {
                if let Ok(text) = field.text().await {
                    opts.language = Some(text);
                }
            }
            // Other fields (e.g. a client-sent "detailed") are dropped: the
            // provider layer owns the wire format, and unknown passthrough
            // fields would leak one provider's dialect into another's.
            _ => {}
        }
    }

    let Some((bytes, filename, mime)) = audio else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "No audio file provided (expected field 'file')"})),
        )
            .into_response();
    };

    let endpoint = stt_endpoint(&state).await;
    match endpoint
        .transcribe(bytes, &filename, &mime, &opts, std::time::Duration::from_secs(120))
        .await
    {
        Ok(data) => (axum::http::StatusCode::OK, Json(data)).into_response(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                stt_url = %endpoint.url,
                provider = %endpoint.api_format,
                "stt_provider_failed"
            );
            (
                e.http_status(),
                Json(json!({
                    "error": e.to_string(),
                    "stt_provider": endpoint.api_format,
                    "stt_url": endpoint.url,
                })),
            )
                .into_response()
        }
    }
}

/// POST /api/voice/synthesize — synthesize speech via the configured TTS
/// provider (see `crate::tts_client` for providers + config keys).
///
/// Accepts JSON body with text, optional voice/backend/speed/stream fields —
/// the contract `noo voice synthesize` / `noo voice speak` pin.
///
/// Request body (matching Python SynthesizeRequest):
/// ```json
/// { "text": "Hello", "voice": "en_US-lessac-medium", "backend": "piper", "speed": 1.0, "stream": false }
/// ```
///
/// Response: audio bytes (audio/wav or audio/mpeg) with X-TTS-Backend header.
async fn voice_synthesize(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
    if text.trim().is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "Text cannot be empty"})),
        ).into_response();
    }

    let speed = body.get("speed").and_then(|v| v.as_f64()).unwrap_or(1.0);
    if !(0.25..=4.0).contains(&speed) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({"error": "Speed must be between 0.25 and 4.0"})),
        ).into_response();
    }

    let opts = crate::tts_client::SynthesizeOptions {
        voice: body
            .get("voice")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        speed,
        backend: body
            .get("backend")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    };

    let endpoint = tts_endpoint(&state).await;
    match endpoint
        .synthesize(text, &opts, std::time::Duration::from_secs(60))
        .await
    {
        Ok(speech) => {
            let ext = if speech.content_type.contains("mpeg") || speech.content_type.contains("mp3")
            {
                "mp3"
            } else {
                "wav"
            };
            tracing::info!(
                text_len = text.len(),
                audio_size = speech.audio.len(),
                backend = %speech.backend,
                provider = %endpoint.api_format,
                "speech_synthesized"
            );
            let disposition = format!("inline; filename=\"speech.{ext}\"");
            (
                axum::http::StatusCode::OK,
                [
                    ("content-type", speech.content_type.as_str()),
                    ("x-tts-backend", speech.backend.as_str()),
                    ("content-disposition", disposition.as_str()),
                ],
                speech.audio,
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                tts_url = %endpoint.url,
                provider = %endpoint.api_format,
                "tts_provider_failed"
            );
            (
                e.http_status(),
                Json(json!({
                    "error": e.to_string(),
                    "tts_provider": endpoint.api_format,
                    "tts_url": endpoint.url,
                })),
            )
                .into_response()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Voice — Native Rust handlers (ported from NATS delegation 2026-03-31)
// ═══════════════════════════════════════════════════════════════
//
// voice_voices: asks the CONFIGURED TTS provider what it serves
//   (crate::tts_client::list_voices). It used to scan local piper voice
//   directories and append a hardcoded edge-tts list — both fictions once
//   synthesis moved out of process: the gateway container has no piper data
//   dir, and nothing in-process speaks edge-tts. An unreachable provider now
//   reports zero voices plus the error, not an invented catalogue.
//
// voice_status: probes the configured STT and TTS providers over HTTP at the
//   health URL appropriate to each wire format, and derives the historical
//   piper_available / edge_tts_available flags (which the CLI prints) from
//   what the TTS provider actually advertises.

/// GET /api/voice/voices — list the TTS voices the configured provider
/// actually serves.
///
/// Response: `{ voices: [{name, language, [quality], [gender], description,
/// backend}], engine, tts_provider, tts_url, [error] }` — the entry shape
/// `noo voice voices` renders (and filters by `--backend`).
async fn voice_voices(
    State(state): State<Arc<AppState>>,
) -> AppResult {
    let endpoint = tts_endpoint(&state).await;
    let (voices, error) = match endpoint.list_voices(std::time::Duration::from_secs(10)).await {
        Ok(v) => (v, None),
        Err(e) => {
            tracing::warn!(
                error = %e,
                tts_url = %endpoint.url,
                provider = %endpoint.api_format,
                "tts_voice_inventory_failed"
            );
            (Vec::new(), Some(e.to_string()))
        }
    };

    let mut body = json!({
        "voices": voices,
        "engine": "rust",
        "tts_provider": endpoint.api_format,
        "tts_url": endpoint.url,
    });
    if let Some(e) = error {
        body["error"] = Value::String(e);
    }
    Ok(Json(body))
}

/// GET /api/voice/status — voice system status.
///
/// Probes the configured STT and TTS providers (whatever they are) and
/// reports honest reachability plus the provider identity/config.
async fn voice_status(
    State(state): State<Arc<AppState>>,
    requester: Option<Extension<RequesterCtx>>,
) -> AppResult {
    let operator = requester
        .as_ref()
        .map(|Extension(r)| r.role >= crate::auth::Role::Operator)
        .unwrap_or(false);
    // STT: probe the CONFIGURED provider (whatever it is) at the health URL
    // appropriate to its wire format — honest reachability, not a hardcoded
    // whisper assumption.
    let stt = stt_endpoint(&state).await;
    let tts = tts_endpoint(&state).await;
    let probe_timeout = std::time::Duration::from_secs(3);
    // Through the STT door: the cluster client for noo-whisper, the public
    // one for a cloud provider, nothing for a refused http:// URL.
    let stt_probe = stt.probe(probe_timeout);
    // The voice inventory doubles as the TTS liveness signal's detail: it is
    // what tells us WHICH backends this provider actually serves.
    let (stt_available, tts_available, tts_voices) = tokio::join!(
        stt_probe,
        tts.probe(probe_timeout),
        tts.list_voices(probe_timeout),
    );
    let tts_voices = tts_voices.unwrap_or_default();

    // The two historical flags the CLI prints, now derived from evidence:
    // a backend counts as available only when the reachable provider serves
    // voices labelled with it (our piper shim labels its own; an
    // openedai-speech style server labels its edge voices).
    let serves = |backend: &str| {
        tts_voices.iter().any(|v| {
            v.get("backend")
                .and_then(Value::as_str)
                .map(|b| b.eq_ignore_ascii_case(backend))
                .unwrap_or(false)
        })
    };
    let piper_available = tts_available && (tts.api_format == "piper" || serves("piper"));
    let edge_tts_available = tts_available && serves("edge-tts");

    let mut tts_backends: Vec<String> = Vec::new();
    if piper_available {
        tts_backends.push("piper".to_string());
    }
    if edge_tts_available {
        tts_backends.push("edge-tts".to_string());
    }
    if tts_available && tts_backends.is_empty() {
        // Reachable provider that labels nothing we recognise — report it
        // under its wire format rather than claiming no backend.
        tts_backends.push(tts.api_format.clone());
    }

    // stt_backend keeps its historical vocabulary ("faster-whisper"/"none")
    // for the legacy whisper wire format; other providers report their
    // format name. stt_provider/stt_url/stt_model are the new honest fields.
    let stt_backend_label = if !stt_available {
        "none".to_string()
    } else if stt.api_format == "whisper" {
        "faster-whisper".to_string()
    } else {
        stt.api_format.clone()
    };

    Ok(Json(redact_service_urls(json!({
        "stt_available": stt_available,
        "stt_backend": stt_backend_label,
        "stt_provider": stt.api_format,
        "stt_url": stt.url,
        "stt_model": if stt.model.is_empty() { Value::Null } else { Value::String(stt.model.clone()) },
        "tts_available": tts_available,
        "tts_backends": tts_backends,
        "tts_provider": tts.api_format,
        "tts_url": tts.url,
        "tts_voice": if tts.voice.is_empty() { Value::Null } else { Value::String(tts.voice.clone()) },
        "tts_voice_count": tts_voices.len(),
        "piper_available": piper_available,
        "edge_tts_available": edge_tts_available,
        "engine": "rust",
    }), operator)))
}

/// `stt_url`/`tts_url` are internal service addresses: only Operator and
/// Admin see them. Everyone keeps the booleans and provider names.
fn redact_service_urls(mut body: Value, operator: bool) -> Value {
    if !operator {
        if let Some(o) = body.as_object_mut() {
            o.remove("stt_url");
            o.remove("tts_url");
        }
    }
    body
}

/// Convert standard Markdown to Google Chat's lightweight format.
///
/// Google Chat doesn't render Markdown — `**bold**` shows literal
/// asterisks, `# Heading` shows the literal `#`, `[text](url)` shows
/// the raw markdown syntax. This converter handles the common patterns
/// our LLM-generated reports produce. Lossy by design: rare/exotic
/// markdown (tables, nested lists, footnotes) passes through as-is
/// rather than being mangled.
///
/// Conversions:
/// - `**bold**` / `__bold__` → `*bold*` (single asterisk = bold in gchat)
/// - `*italic*` / `_italic_` → `_italic_` (gchat italic)
/// - `~~strike~~` → `~strike~`
/// - `# Heading` / `## Sub` / `### SubSub` → `*Heading*` (bold + line break)
/// - `[text](url)` → `<url|text>` (gchat link format)
/// - `- item` / `* item` (line-leading) → `• item`
/// - inline `` `code` `` and triple-backtick code blocks pass through
///   (gchat renders these natively)
fn markdown_to_gchat(s: &str) -> String {
    // One converter, not two. This used to be a regex-based sibling of
    // channels::google_chat_format::md_to_chat with no code-span
    // protection and a smaller pattern set — the operator's first live DM
    // reply arrived with raw Markdown in it. md_to_chat is
    // the tested implementation; every outbound Chat send now goes
    // through it.
    crate::channels::google_chat_format::md_to_chat(s)
}

#[cfg(test)]
mod gchat_format_tests {
    use super::markdown_to_gchat;

    #[test]
    fn bold_double_asterisk() {
        assert_eq!(markdown_to_gchat("hello **world** there"), "hello *world* there");
    }
    #[test]
    fn heading_levels() {
        assert_eq!(markdown_to_gchat("# H1\n## H2\n### H3"), "*H1*\n*H2*\n*H3*");
    }
    #[test]
    fn link_conversion() {
        assert_eq!(
            markdown_to_gchat("see [Anthropic](https://anthropic.com) docs"),
            "see <https://anthropic.com|Anthropic> docs"
        );
    }
    #[test]
    fn dash_list() {
        assert_eq!(markdown_to_gchat("- one\n- two"), "• one\n• two");
    }
    #[test]
    fn star_list_only_at_line_start() {
        // `*italic*` in body text must NOT become `• italic*`
        assert_eq!(
            markdown_to_gchat("intro text *italic phrase* continues\n* list item"),
            "intro text *italic phrase* continues\n• list item"
        );
    }
    #[test]
    fn passes_through_code_blocks() {
        let src = "```rust\nfn main() {}\n```";
        assert_eq!(markdown_to_gchat(src), src);
    }
}

#[cfg(test)]
mod one_implementation_tests {
    /// outbound channel dispatch has exactly ONE
    /// implementation — the native senders in this module. The Python
    /// `worker.channels.send` handler is unregistered, so a reintroduced
    /// NATS delegate here would publish to a subject with no subscriber:
    /// a 30-second hang per message that reads as a network fault, not as
    /// the config mistake it is. Guard against the pattern coming back.
    #[test]
    fn no_nats_delegation_in_this_module() {
        let src = include_str!("communication.rs");
        // Built by concatenation so this test's own source (included in
        // `src`) doesn't match its markers.
        let markers = [
            ["async", "_nats"].concat(),
            ["nc.", "request("].concat(),
            ["worker_client", "::"].concat(),
        ];
        for marker in &markers {
            assert!(
                !src.contains(marker.as_str()),
                "communication.rs references `{marker}` again — outbound \
                 channel sends must stay in-process; \
                 there is no Python subscriber to delegate to"
            );
        }
    }
}

#[cfg(test)]
mod recipient_ownership_tests {
    use super::{recipient_writable, RECIPIENT_LIST_SQL};

    /// reads are wider than writes on the address book.
    #[test]
    fn operator_and_internal_callers_may_write_anything() {
        assert!(recipient_writable(Some("ada"), None));
        assert!(recipient_writable(None, None));
    }

    #[test]
    fn a_user_may_write_only_its_own() {
        assert!(recipient_writable(Some("ada"), Some("ada")));
        assert!(!recipient_writable(Some("bob"), Some("ada")));
    }

    /// The shared book (`owner IS NULL`) is READABLE by a User — the list
    /// query admits it — and NOT writable. A User must not be able to
    /// rewrite or delete a contact the whole install sends to.
    #[test]
    fn a_user_may_read_but_not_write_the_shared_book() {
        assert!(!recipient_writable(None, Some("ada")));
        assert!(
            RECIPIENT_LIST_SQL.contains("owner IS NULL"),
            "the list query must still admit the shared rows: {RECIPIENT_LIST_SQL}"
        );
    }

    /// The scope is a BIND, not a splice, and the unscoped case is the same
    /// statement with a NULL — so the predicate under test is the predicate
    /// that ships.
    #[test]
    fn the_scope_is_a_nullable_bind() {
        assert!(RECIPIENT_LIST_SQL.contains("$1::text IS NULL OR owner = $1"));
        assert!(RECIPIENT_LIST_SQL.contains("$2::text IS NULL OR channel = $2"));
    }
}

#[cfg(test)]
mod telegram_fallback_tests {
    use super::is_entity_parse_error;

    #[test]
    fn only_an_entity_parse_400_is_retried_as_plain_text() {
        let tg = r#"{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities: Can't find end of the entity starting at byte offset 25"}"#;
        assert!(is_entity_parse_error(400, tg));
        assert!(!is_entity_parse_error(400, r#"{"ok":false,"description":"Bad Request: chat not found"}"#));
        assert!(!is_entity_parse_error(403, r#"{"ok":false,"description":"Forbidden: bot was blocked by the user"}"#));
        assert!(!is_entity_parse_error(429, "Too Many Requests"));
    }
}

#[cfg(test)]
mod origin_tests {
    use super::*;

    /// PINNED: a remote turn's origin is findable by its
    /// conversation for exactly as long as the turn is in flight, and an
    /// empty origin registers nothing.
    /// PINNED: the gated-call record of a remote turn
    /// accumulates across rail calls and replays into a task's locals.
    #[tokio::test]
    async fn gated_record_crosses_tasks_and_replays() {
        let origin = TurnOrigin { channel: Some(ApprovalTarget { channel: "telegram", recipient: "1".into(), thread_id: None, chat_type: "private".into() }), ..Default::default() };
        // A rail call: seed from the origin, record a failure, store back.
        let after = GATED_TOOL_FAILURES
            .scope(Default::default(), COMPLETED_GATED_CALLS.scope(Default::default(), async {
                origin.gated_record().replay();
                record_gated_failure("python_tool", "denied");
                record_completed_gated_call(7, "ok");
                GatedRecord::capture()
            }))
            .await;
        origin.store_gated(after);
        // A second rail call sees the first's record.
        let seen = GATED_TOOL_FAILURES
            .scope(Default::default(), COMPLETED_GATED_CALLS.scope(Default::default(), async {
                origin.gated_record().replay();
                (completed_gated_call(7), gated_failure_banner())
            }))
            .await;
        assert_eq!(seen.0.as_deref(), Some("ok"));
        assert!(seen.1.unwrap().contains("python_tool (denied)"));
        // The dispatcher's task, at the end of the turn: replay → banner.
        let banner = GATED_TOOL_FAILURES
            .scope(Default::default(), async {
                origin.gated_record().replay();
                gated_failure_banner()
            })
            .await;
        assert!(banner.unwrap().contains("did NOT run"));
        // Outside a channel turn, replay is a no-op and the banner is None.
        assert!(gated_failure_banner().is_none());
    }

    #[test]
    fn origins_live_for_the_turn() {
        let target = ApprovalTarget { channel: "telegram", recipient: "42".into(), thread_id: None, chat_type: "private".into() };
        assert!(register_origin("c-empty", TurnOrigin::default()).is_none());
        assert!(origin_for("c-empty").is_none());
        let guard = register_origin("c-1", TurnOrigin { dashboard: None, channel: Some(target), ..Default::default() }).expect("registered");
        let found = origin_for("c-1").expect("live");
        assert_eq!(found.channel.as_ref().map(|t| t.recipient.as_str()), Some("42"));
        assert!(origin_for("c-2").is_none());
        drop(guard);
        assert!(origin_for("c-1").is_none(), "gone when the turn ends");
    }
}

/// The approval notice must survive Telegram's Markdown parser, and the
/// fallback log must say which of two very different things happened.
///
/// Live on host8 (R48): a HIGH-risk `python_tool` call on an in-process
/// Telegram turn bound its approval row correctly and posted NO card, while
/// the log said "no channel origin" — which was false. Three diagnoses were
/// tried against that sentence (a missing task-local, a `tokio::spawn`
/// boundary, a placed harness) and all three were wrong, because the message
/// described a state the system was not in.
#[cfg(test)]
mod exec_approval_notice_tests {
    use super::{escape_markdown_legacy, exec_approval_notice, no_card_reason};

    /// Count entity delimiters that are NOT backslash-escaped — what
    /// Telegram's legacy parser actually counts.
    fn unescaped(text: &str, delim: char) -> usize {
        let chars: Vec<char> = text.chars().collect();
        let mut n = 0;
        for i in 0..chars.len() {
            if chars[i] == delim && (i == 0 || chars[i - 1] != '\\') {
                n += 1;
            }
        }
        n
    }

    #[test]
    fn a_tool_name_with_one_underscore_no_longer_breaks_the_notice() {
        // The two HIGH-risk tools the gate exists for are exactly the two
        // that used to fail: ONE underscore each, opening an italic span the
        // notice never closes, so Telegram rejected the whole message with
        // HTTP 400 and the operator was never told a call was waiting.
        for tool in ["python_tool", "skill_execute"] {
            let text = exec_approval_notice(tool, "a1b2c3d4e5f6", 300);
            assert_eq!(
                unescaped(&text, '_') % 2,
                0,
                "unbalanced italic in the notice for {tool}: {text}"
            );
            // The name must still be READABLE — escaping is not redaction.
            assert!(text.contains(tool.replace('_', "\\_").as_str()), "{text}");
            // The notice's own intentional markup is untouched.
            assert_eq!(unescaped(&text, '*') % 2, 0, "unbalanced bold: {text}");
            assert_eq!(unescaped(&text, '`') % 2, 0, "unbalanced code span: {text}");
        }
    }

    #[test]
    fn the_notices_own_markup_still_reaches_telegram() {
        // Escaping the interpolated value must not escape the notice, or the
        // operator reads literal backslashes instead of formatting.
        let text = exec_approval_notice("browser", "abc123", 300);
        assert!(text.contains("*y*"), "{text}");
        assert!(text.contains("`noo approval approve abc123`"), "{text}");
        assert!(!text.contains("\\*"), "the notice's own bold was escaped: {text}");
    }

    #[test]
    fn escaping_covers_every_legacy_metacharacter_and_nothing_else() {
        assert_eq!(escape_markdown_legacy("python_tool"), "python\\_tool");
        assert_eq!(escape_markdown_legacy("a*b`c[d"), "a\\*b\\`c\\[d");
        // A hostile name cannot open an entity at all.
        let nasty = escape_markdown_legacy("_*`[");
        assert_eq!(unescaped(&nasty, '_'), 0);
        assert_eq!(unescaped(&nasty, '*'), 0);
        assert_eq!(unescaped(&nasty, '`'), 0);
        // Ordinary text is untouched.
        assert_eq!(escape_markdown_legacy("browser"), "browser");
        assert_eq!(escape_markdown_legacy(""), "");
    }

    #[test]
    fn the_fallback_line_distinguishes_no_origin_from_a_refused_origin() {
        let absent = no_card_reason(None);
        let refused = no_card_reason(Some(("telegram", "-1001234")));

        assert_ne!(
            absent, refused,
            "these are different failures and must not share one sentence — \
             conflating them is what made R48 unreadable"
        );
        // The honest no-origin case still says so.
        assert!(absent.contains("no channel origin"), "{absent}");
        // The refused case must NOT claim there was no origin, and must name
        // where the notice was actually sent.
        assert!(
            !refused.contains("no channel origin"),
            "the origin was present; saying otherwise is the bug: {refused}"
        );
        assert!(refused.contains("telegram"), "{refused}");
        assert!(refused.contains("-1001234"), "{refused}");
    }
}

#[cfg(test)]
mod chat_recipient_tests {
    use super::validate_chat_recipient;

    #[test]
    fn accepts_a_space_resource_name() {
        assert!(validate_chat_recipient("spaces/AAAAAAAAAAA").is_ok());
    }

    /// The exact value that broke production on 2026-09-20: nothing resolves
    /// `broadcast`, so it used to be interpolated into the REST path and
    /// Google answered with an HTML 404 that named no cause.
    #[test]
    fn refuses_the_broadcast_literal() {
        let err = validate_chat_recipient("broadcast").unwrap_err();
        assert!(err.contains("broadcast"), "{err}");
        assert!(err.contains("spaces/"), "{err}");
    }

    #[test]
    fn refuses_empty_and_whitespace() {
        assert!(validate_chat_recipient("").is_err());
        assert!(validate_chat_recipient("   ").is_err());
    }

    /// `users/…` is a real Chat resource name with no messages collection,
    /// so it earns its own explanation rather than the generic one.
    #[test]
    fn explains_a_user_recipient_specifically() {
        let err = validate_chat_recipient("users/123456").unwrap_err();
        assert!(err.contains("/v1/users/*/messages"), "{err}");
    }

    #[test]
    fn refuses_a_space_with_extra_segments() {
        assert!(validate_chat_recipient("spaces/AAA/messages").is_err());
        assert!(validate_chat_recipient("spaces/").is_err());
    }
}

#[cfg(test)]
mod voice_tests {
    use super::*;

    #[test]
    fn service_urls_are_operator_only() {
        let full = json!({"stt_available": true, "stt_url": "https://noo-whisper:8000",
                          "tts_available": false, "tts_url": "https://noo-piper:5000"});
        let user = redact_service_urls(full.clone(), false);
        assert!(user.get("stt_url").is_none() && user.get("tts_url").is_none());
        assert_eq!(user["stt_available"], true);
        assert_eq!(user["tts_available"], false);
        let op = redact_service_urls(full.clone(), true);
        assert_eq!(op, full);
    }

    #[test]
    fn transcribe_limit_is_ten_mib() {
        assert_eq!(TRANSCRIBE_BODY_LIMIT, 10 * 1024 * 1024);
    }

    // Built outside a `.route("...")` literal so the OpenAPI drift scan does not
    // mistake a test-only path for a registered route.
    const TEST_PATH: &str = "/upload";

    /// Drains the `file` field the way the real handler does.
    async fn drain(mut mp: Multipart) -> axum::response::Response {
        let mut n = 0usize;
        loop {
            match mp.next_field().await {
                Ok(Some(f)) => match f.bytes().await {
                    Ok(b) => n += b.len(),
                    Err(e) => return multipart_error_response(&e),
                },
                Ok(None) => break,
                Err(e) => return multipart_error_response(&e),
            }
        }
        (axum::http::StatusCode::OK, Json(json!({"bytes": n}))).into_response()
    }

    async fn post_audio(app: Router, size: usize) -> reqwest::StatusCode {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(vec![0u8; size]).file_name("a.webm"),
        );
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}{TEST_PATH}"))
            .multipart(form)
            .send()
            .await
            .map(|r| r.status())
            .unwrap_or(reqwest::StatusCode::PAYLOAD_TOO_LARGE)
    }

    #[tokio::test]
    async fn transcribe_accepts_5_mib_and_refuses_20_mib() {
        let mk = || Router::new().route(TEST_PATH, audio_upload(post(drain)));
        assert_eq!(post_audio(mk(), 5 * 1024 * 1024).await, reqwest::StatusCode::OK);
        assert_eq!(post_audio(mk(), 20 * 1024 * 1024).await, reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn other_routes_keep_the_default_limit() {
        let app = Router::new().route(TEST_PATH, post(drain));
        assert_eq!(post_audio(app, 5 * 1024 * 1024).await, reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    }
}
