// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Agent-to-agent messaging over NATS (phase 1 — the spine).
//!
//! One envelope shape, one JetStream stream (`AGENT_MESSAGES`, subjects
//! `agent.msg.>`), and the gateway as the sole recorder: a durable pull
//! consumer writes every envelope to `noo_agent_messages` so any exchange
//! between agents — on this box, on another node, behind HTTP — can be
//! traced and reviewed later (`noo agents messages`, the dashboard).
//!
//! Sending = publishing to the stream. The HTTP route does that for
//! agents that only speak HTTP; node-local agents publish on the bus
//! directly with their node credentials; both land in the same record.
//!
//! Subjects:
//!   agent.msg.direct.<to_agent>       — addressed (agent ids are dotless;
//!                                       `/` → `_` in the subject)
//!   agent.msg.thread.<thread_id>      — everyone following a thread
//!   agent.msg.broadcast               — announcements
//!
//! Encryption: the bus is TLS with node PKI; `enc`/`sig` are carried but
//! not enforced until phase 4 (per-thread E2E to node certs, signed
//! envelopes). Retention prune is phase 3.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::AppState;

pub const STREAM: &str = "AGENT_MESSAGES";
pub const SUBJECT_ROOT: &str = "agent.msg";
pub const DURABLE_RECORDER: &str = "agent_messages_recorder";
/// The cadence the recorder promises loop_health, and the clock that keeps
/// the promise when nothing is published. The idle tick must be shorter
/// than the promised interval, or a quiet bus still trips the stale alarm.
const RECORDER_TICK_SECS: u64 = 60;
const IDLE_TICK_SECS: u64 = 20;
// loop_health flags a loop stale from its declared interval; an idle tick
// slower than the promise would let a quiet bus trip it. Checked at
// compile time, so the pair cannot drift apart.
const _: () = assert!(IDLE_TICK_SECS < RECORDER_TICK_SECS);
/// Stream retention: age-bounded; the DB is the long-lived record.
const STREAM_MAX_AGE_DAYS: u64 = 30;

pub const KINDS: &[&str] = &["message", "task", "result", "ack", "note"];

/// Who, structurally: the person the credential belongs to, the box, the
/// agent instance, the software running it. Every ingress fills what it
/// knows; unknown parts stay `None` rather than guessed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Identity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The software running the agent, DERIVED from the credential class
    /// the message arrived on — `mcp-external:<consumer>`,
    /// `ws:<peer>`, `internal:<actor>`, `node:<node>`, `api`. Never taken
    /// from the caller: the CLI and dashboard print this column as fact, so
    /// a self-asserted value let any sender dress up as any harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// What the caller SAID it was, kept only as a hint. Separate key so a
    /// reader can never mistake it for the derived value above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_claimed: Option<String>,
}

impl Identity {
    pub fn new(user: Option<&str>, node: Option<&str>, agent: Option<&str>, harness: Option<&str>) -> Self {
        let f = |v: Option<&str>| v.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        Identity { user: f(user), node: f(node), agent: f(agent), harness: f(harness), harness_claimed: None }
    }
    /// Attach the caller's own claim about which software it is. Recorded
    /// beside the derived harness, never in place of it.
    pub fn with_claimed_harness(mut self, claimed: Option<&str>) -> Self {
        self.harness_claimed = claimed.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        self
    }
    /// `user@node/agent (harness)` for humans. A claim is rendered with a
    /// `claims:` prefix so it never reads as verified.
    pub fn label(&self) -> String {
        let mut s = String::new();
        if let Some(u) = &self.user { s.push_str(u); }
        if let Some(n) = &self.node { s.push('@'); s.push_str(n); }
        if let Some(a) = &self.agent { s.push('/'); s.push_str(a); }
        match (&self.harness, &self.harness_claimed) {
            (Some(h), Some(c)) => s.push_str(&format!(" ({h}, claims: {c})")),
            (Some(h), None) => s.push_str(&format!(" ({h})")),
            (None, Some(c)) => s.push_str(&format!(" (claims: {c})")),
            (None, None) => {}
        }
        s
    }
}

/// This controller's node name for identities minted here (HTTP, WS, MCP
/// ingress all run on the controller).
pub fn controller_node() -> String {
    if let Some(v) = crate::self_node::self_node_id() {
        return v;
    }
    // HOSTNAME and /etc/hostname come LAST and are rejected when they look
    // like a container id, which inside docker they always do.
    //
    // This name is an IDENTITY, not a label. `tasks::spawn_ready_watcher`
    // resumes "what THIS controller was running" by matching it, so a value
    // that changes on every recreate orphans every in-flight task: after a
    // recreate the resume no longer recognises them and they sit stale
    // forever. Seen with five tasks pinned to `86c47f153ae0` while the live
    // container called itself `90417b3f1220`, and the stale alert then told
    // the operator to restart the harness on a container that no longer
    // existed.
    for candidate in [
        std::env::var("HOSTNAME").ok(),
        std::fs::read_to_string("/etc/hostname").ok(),
    ] {
        let Some(v) = candidate else { continue };
        let v = v.trim();
        if v.is_empty() || is_container_id(v) {
            continue;
        }
        return v.to_string();
    }
    warn_unnamed_controller();
    "controller".into()
}

/// A docker container id: 12 or 64 lowercase hex characters and nothing else.
///
/// Deliberately narrow. A real host may legitimately be called `cafe01` —
/// short, and hex by coincidence — so the length is pinned to the two docker
/// actually emits rather than "looks hexish".
pub fn is_container_id(s: &str) -> bool {
    matches!(s.len(), 12 | 64) && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Once, loudly. An unnamed controller still works — it just cannot recognise
/// its own earlier self, so the operator should know before tasks go missing.
fn warn_unnamed_controller() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tracing::warn!(
            "this controller has no stable name: NOO_CONTROLLER_HOSTNAME and NODE_ID are unset \
             and the hostname is a container id. Falling back to \"controller\". Tasks survive a \
             recreate only while this name does, so set NODE_ID in .env."
        );
    });
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    /// Envelope format. 1 = pre-wave-B (body AAD is the algorithm string,
    /// signature covers six fields). 2 = envelope-bound AAD + canonical
    /// whole-envelope signature. Absent on the wire means 1.
    #[serde(default = "default_v")]
    pub v: u8,
    pub id: String,
    pub thread_id: String,
    pub from: String,
    pub to: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub refs: Vec<String>,
    /// RFC 3339.
    pub ts: String,
    #[serde(default)]
    pub ttl_s: u64,
    #[serde(default = "default_enc")]
    pub enc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// Structured sender / recipient (phase 2). `from`/`to` stay the short
    /// agent ids used for addressing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_id: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_id: Option<Identity>,
    /// Sealing metadata (phase 2b): algorithm, ephemeral key, nonce, wraps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_meta: Option<Value>,
}

fn default_kind() -> String {
    "message".into()
}
fn default_enc() -> String {
    "none".into()
}
fn default_v() -> u8 {
    1
}
/// What this build seals and signs.
pub const ENVELOPE_VERSION: u8 = 2;

pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", &uuid::Uuid::new_v4().simple().to_string()[..20])
}

impl Envelope {
    /// A fresh envelope from the send request; `thread_id` absent = new thread.
    pub fn new(from: &str, to: &str, kind: &str, body: Value, thread_id: Option<&str>, refs: Vec<String>) -> Self {
        Envelope {
            v: ENVELOPE_VERSION,
            id: new_id("msg"),
            thread_id: thread_id.map(str::to_string).unwrap_or_else(|| new_id("thr")),
            from: from.to_string(),
            to: to.to_string(),
            kind: kind.to_string(),
            body,
            refs,
            ts: chrono::Utc::now().to_rfc3339(),
            ttl_s: 0,
            enc: "none".into(),
            sig: None,
            from_id: None,
            to_id: None,
            enc_meta: None,
        }
    }

    pub fn with_from(mut self, id: Identity) -> Self {
        self.from_id = Some(id);
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.from.trim().is_empty() || self.to.trim().is_empty() {
            return Err("from and to are required".into());
        }
        check_id("from", &self.from)?;
        if !matches!(self.to.as_str(), "*" | "broadcast" | "thread") {
            check_id("to", &self.to)?;
        }
        if !KINDS.contains(&self.kind.as_str()) {
            return Err(format!("kind must be one of {}", KINDS.join(", ")));
        }
        if self.thread_id.trim().is_empty() {
            return Err("thread_id is required".into());
        }
        check_id("thread_id", &self.thread_id)?;
        if self.refs.len() > MAX_REFS {
            return Err(format!("at most {MAX_REFS} refs"));
        }
        if self.refs.iter().any(|r| r.len() > MAX_ID_LEN) {
            return Err(format!("each ref is at most {MAX_ID_LEN} chars"));
        }
        let body_len = serde_json::to_vec(&self.body).map(|v| v.len()).unwrap_or(0);
        if body_len > MAX_BODY_BYTES {
            return Err(format!("body is {body_len} bytes; the limit is {MAX_BODY_BYTES}"));
        }
        Ok(())
    }

    /// The subject a message is published on: direct for an addressed
    /// agent, the thread subject for `to == "thread"`, broadcast for `*`.
    pub fn subject(&self) -> String {
        match self.to.as_str() {
            "*" | "broadcast" => format!("{SUBJECT_ROOT}.broadcast"),
            "thread" => format!("{SUBJECT_ROOT}.thread.{}", subject_token(&self.thread_id)),
            to => format!("{SUBJECT_ROOT}.direct.{}", subject_token(to)),
        }
    }
}

/// Longest agent id / thread id / ref accepted anywhere.
pub const MAX_ID_LEN: usize = 128;
pub const MAX_REFS: usize = 32;
/// Serialised body cap — well under NATS `max_payload` (1 MiB) with room
/// for sealing overhead and metadata.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// Stream caps: a flood must not fill the shared
/// JetStream volume or evict the audit trail (`DiscardPolicy::New`).
const STREAM_MAX_BYTES: i64 = 2 * 1024 * 1024 * 1024;
const STREAM_MAX_MESSAGE_SIZE: i32 = 512 * 1024;
/// How many times the recorder lets JetStream redeliver an envelope it
/// could not insert before the message is left in the stream unrecorded
/// (logged each time). Non-envelopes and unverifiable envelopes are
/// terminated on first sight and copied to the dead-letter table.
const RECORDER_MAX_DELIVER: i64 = 5;

/// Is `s` a well-formed agent / thread id: [`crate::auth::valid_name_segment`]
/// segments joined by single `/`, at most [`MAX_ID_LEN`] chars overall.
/// Agent ids are `<node>/<agent>` or `<account>/<connection>`.
///
/// Delegates the character class rather than restating it.
/// It used to be a second copy that happened to agree with the account
/// rule everywhere except `.`, and that one disagreement is what made
/// `first.last` a legal account that could not send a message.
pub fn is_valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.split('/').all(crate::auth::valid_name_segment)
}

pub fn check_id(field: &str, s: &str) -> Result<(), String> {
    if is_valid_id(s) {
        Ok(())
    } else {
        Err(format!("{field} '{s}' is not a valid id: letters, digits, '-', '_' and single '/' separators, up to {MAX_ID_LEN} chars"))
    }
}

/// The NATS subject token for an id. `/` becomes `.` (so `host3/claude-1`
/// is the two-token tail `host3.claude-1` under `agent.msg.direct.`) and
/// nothing else changes — the mapping is injective for every id that
/// passes [`is_valid_id`], so two distinct agents can never share an
/// inbox subject or a key-registry slot. Ids that do not
/// validate are squashed to `_` as before, and rejected upstream.
pub fn subject_token(s: &str) -> String {
    if is_valid_id(s) {
        return s.replace('/', ".");
    }
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn stream_config() -> async_nats::jetstream::stream::Config {
    use async_nats::jetstream::stream::{Config, DiscardPolicy, RetentionPolicy, StorageType};
    Config {
        name: STREAM.to_string(),
        subjects: vec![format!("{SUBJECT_ROOT}.>")],
        retention: RetentionPolicy::Limits,
        max_age: Duration::from_secs(STREAM_MAX_AGE_DAYS * 86_400),
        max_bytes: STREAM_MAX_BYTES,
        max_message_size: STREAM_MAX_MESSAGE_SIZE,
        discard: DiscardPolicy::New,
        storage: StorageType::File,
        ..Default::default()
    }
}

/// Ensure the stream exists with the current limits (idempotent; called
/// at boot). An existing stream is UPDATED — `get_or_create` alone would
/// leave a stream created before the caps unlimited forever.
pub async fn ensure_stream(js: &async_nats::jetstream::Context) {
    let cfg = stream_config();
    let result = match js.get_stream(STREAM).await {
        Ok(_) => js.update_stream(cfg).await.map(|_| ()),
        Err(_) => js.create_stream(cfg).await.map(|_| ()),
    };
    match result {
        Ok(()) => tracing::info!(stream = STREAM, "agent_messages: stream ready"),
        Err(e) => tracing::warn!(error = %e, "agent_messages: could not ensure stream — sends will fail until NATS JetStream is reachable"),
    }
}

/// Check an envelope as it arrived on the bus. With a review key
/// configured the gateway seals and signs everything it publishes, so an
/// envelope that is plaintext or unsigned, or whose signature does not
/// verify under the controller key, did not come through the gateway —
/// it was written straight onto the bus by something holding the NATS
/// credential and must not become part of the record.
/// Without a review key (plaintext mode) there is nothing to check.
pub fn verify_envelope(env: &Envelope) -> Result<bool, String> {
    let Some(keys) = crate::agent_crypto::controller_keys() else {
        return Ok(false);
    };
    if env.enc == "none" || env.enc.is_empty() {
        return Err("plaintext envelope on a sealed bus".into());
    }
    let sig = env.sig.as_deref().ok_or("unsigned envelope")?.to_string();
    let input = if env.v >= 2 {
        let value = serde_json::to_value(env).map_err(|e| e.to_string())?;
        crate::agent_crypto::signing_input_v2(&value)?
    } else {
        // A v1 envelope on the bus today is a replay of a pre-wave-B
        // message: verifiable, but its ciphertext is not envelope-bound.
        crate::agent_crypto::signing_input(&env.id, &env.thread_id, &env.from, &env.to, &env.kind, &env.ts, &env.body)
    };
    if !crate::agent_crypto::verify(&keys.sign_public(), &input, &sig) {
        return Err("signature does not verify under the controller key".into());
    }
    Ok(true)
}

/// Copy a rejected bus message into `noo_nats_dlq` so an operator can see
/// what was refused and why. Best effort.
async fn dead_letter(db: &sqlx::PgPool, subject: &str, payload: &[u8], reason: &str) {
    let payload = serde_json::from_slice::<Value>(payload).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(payload).into()));
    let _ = sqlx::query(
        "INSERT INTO noo_nats_dlq (subject, payload, attempt_count, last_error) VALUES ($1, $2, 1, $3)",
    )
    .bind(subject)
    .bind(payload)
    .bind(reason)
    .execute(db)
    .await;
}

/// The associated data a v2 body is sealed under: the envelope fields that
/// say WHICH message this is and who it is between. Changing any of them
/// makes the ciphertext fail to authenticate, so a sealed body cannot be
/// transplanted into another envelope. `id` is a fresh
/// UUID per message and the table's primary key, so reusing it to keep the
/// AAD is a duplicate the recorder drops.
///
/// `ts` is deliberately NOT in here: it is stored as `timestamptz` and
/// comes back with microsecond precision, so an RFC-3339 round trip is not
/// byte-identical and every sealed row would refuse to open. The whole-
/// envelope signature covers `ts`, so re-timestamping still fails.
pub fn envelope_aad(id: &str, thread_id: &str, from: &str, to: &str, kind: &str) -> Vec<u8> {
    let mut v = b"noomesh-agent-msg/aad/v2:".to_vec();
    for part in [id, thread_id, from, to, kind] {
        v.extend_from_slice(part.as_bytes());
        v.push(0);
    }
    v
}

impl Envelope {
    /// This envelope's sealing AAD.
    pub fn aad(&self) -> Vec<u8> {
        envelope_aad(&self.id, &self.thread_id, &self.from, &self.to, &self.kind)
    }
}

/// Seal + sign an envelope before it travels (phase 2b). With no review
/// key configured the envelope passes through untouched (`enc: none`).
/// `recipient_key` = the addressed agent's registered public key, when it
/// has one (phase 4) — then the wrap set makes it end-to-end.
pub fn seal_envelope(env: &mut Envelope, recipient_key: Option<x25519_dalek::PublicKey>) -> Result<(), String> {
    let Some(keys) = crate::agent_crypto::controller_keys() else {
        return Ok(());
    };
    let mut recipients = vec![crate::agent_crypto::Recipient {
        label: crate::agent_crypto::REVIEW_WRAP,
        key: keys.seal_public(),
    }];
    let to_label = env.to.clone();
    if let Some(k) = recipient_key {
        recipients.push(crate::agent_crypto::Recipient { label: &to_label, key: k });
    }
    env.v = ENVELOPE_VERSION;
    let sealed = crate::agent_crypto::seal(&env.body, &recipients, &env.aad())?;
    env.body = serde_json::json!({ "ct": sealed.ct });
    env.enc_meta = Some(sealed.meta);
    env.enc = if recipient_key.is_some() { "e2e".into() } else { "sealed".into() };
    // Sign LAST and over everything: body, enc, enc_meta (the wrap set),
    // refs, ttl and both identities are inside the signature now.
    env.sig = None;
    let value = serde_json::to_value(&*env).map_err(|e| e.to_string())?;
    let input = crate::agent_crypto::signing_input_v2(&value)?;
    env.sig = Some(crate::agent_crypto::sign(keys, &input));
    Ok(())
}

/// Open a sealed body for an authorised reader (the gateway holds the
/// review wrap). Returns the plaintext body, or the reason it stays
/// closed. `enc: none` bodies pass through.
pub fn open_body(enc: &str, body: &Value, enc_meta: Option<&Value>, aad: &[u8]) -> Result<Value, String> {
    if enc == "none" || enc.is_empty() {
        return Ok(body.clone());
    }
    let keys = crate::agent_crypto::controller_keys().ok_or("no review key on this controller")?;
    let ct = body["ct"].as_str().ok_or("sealed body without ct")?;
    let sealed = crate::agent_crypto::Sealed { ct: ct.to_string(), meta: enc_meta.cloned().unwrap_or(Value::Null) };
    crate::agent_crypto::open(&sealed, crate::agent_crypto::REVIEW_WRAP, &keys.seal, aad)
}

/// Publish an envelope (send). Seals + signs first when a review key is
/// configured. The recorder persists it; subscribers on the subject
/// receive it (sealed — phase 4 gives them keys; until then WS delivery
/// opens it on their behalf).
pub async fn publish(js: &async_nats::jetstream::Context, env: &Envelope) -> Result<Envelope, String> {
    env.validate()?;
    let mut env = env.clone();
    if env.enc == "none" {
        // End-to-end when the recipient has registered a key (phase 4);
        // gateway-sealed otherwise. Broadcast and thread addresses have
        // no single recipient key — review-only wrap.
        let recipient_key = match env.to.as_str() {
            "*" | "broadcast" | "thread" => None,
            to => crate::agent_crypto::registered_keys(js, to).await.map(|(k, _)| k),
        };
        seal_envelope(&mut env, recipient_key)?;
    }
    let payload = serde_json::to_vec(&env).map_err(|e| e.to_string())?;
    let ack = js
        .publish(env.subject(), payload.into())
        .await
        .map_err(|e| format!("publish failed: {e}"))?;
    ack.await.map_err(|e| format!("stream did not ack: {e}"))?;
    Ok(env)
}

/// The recorder: a durable pull consumer on the stream writing every
/// envelope to `noo_agent_messages`. Restarts itself on error.
pub fn spawn_recorder(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_recorder(state.clone()).await {
                tracing::warn!(error = %e, "agent_messages.recorder: exited, retrying in 10s");
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}

async fn run_recorder(state: Arc<AppState>) -> anyhow::Result<()> {
    use async_nats::jetstream::consumer::{pull::Config, AckPolicy, DeliverPolicy};
    use async_nats::jetstream::AckKind;
    use futures::StreamExt;
    let stream = state.js.get_stream(STREAM).await?;
    let consumer_cfg = Config {
        durable_name: Some(DURABLE_RECORDER.to_string()),
        filter_subject: format!("{SUBJECT_ROOT}.>"),
        deliver_policy: DeliverPolicy::All,
        ack_policy: AckPolicy::Explicit,
        ack_wait: Duration::from_secs(30),
        max_deliver: RECORDER_MAX_DELIVER,
        ..Default::default()
    };
    // Like the stream: an existing durable keeps its old (unbounded)
    // redelivery config unless updated.
    let consumer = match stream.create_consumer(consumer_cfg.clone()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "agent_messages.recorder: consumer create/update failed — using the existing durable");
            stream.get_or_create_consumer(DURABLE_RECORDER, consumer_cfg).await?
        }
    };
    tracing::info!(durable = DURABLE_RECORDER, "agent_messages.recorder: consuming");
    let mut messages = consumer.messages().await?;
    // The liveness tick fired only when a message arrived, so a quiet bus
    // read as a dead loop: overnight 2026-09-22 the operator was paged
    // "agent_messages_recorder has not ticked for 32503s … a gateway
    // restart restores it" while the recorder sat healthy on an empty
    // stream, and the alert "recovered" the moment the first task of the
    // morning published. An idle consumer is alive; it says so on a clock.
    let mut idle = tokio::time::interval(Duration::from_secs(IDLE_TICK_SECS));
    idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let msg = tokio::select! {
            next = messages.next() => match next {
                Some(m) => m,
                None => break,
            },
            _ = idle.tick() => {
                crate::loop_health::record_tick("agent_messages_recorder", RECORDER_TICK_SECS);
                continue;
            }
        };
        crate::loop_health::record_tick("agent_messages_recorder", RECORDER_TICK_SECS);
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "agent_messages.recorder.message_error");
                continue;
            }
        };
        let env = match serde_json::from_slice::<Envelope>(&msg.payload) {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(subject = %msg.subject, error = %e, "agent_messages.recorder: not an envelope — dead-lettered");
                dead_letter(&state.db, &msg.subject, &msg.payload, &format!("not an envelope: {e}")).await;
                let _ = msg.ack_with(AckKind::Term).await;
                continue;
            }
        };
        // Reject what the gateway would never have published: bad ids,
        // oversize bodies, and — on a sealed bus — anything unsigned or
        // plaintext. Terminated, not retried: a forgery does not become
        // valid on redelivery.
        let verified = match env.validate().and_then(|()| verify_envelope(&env)) {
            Ok(v) => v,
            Err(reason) => {
                tracing::warn!(id = %env.id, from = %env.from, subject = %msg.subject, %reason, "agent_messages.recorder: envelope rejected — dead-lettered");
                dead_letter(&state.db, &msg.subject, &msg.payload, &reason).await;
                let _ = msg.ack_with(AckKind::Term).await;
                continue;
            }
        };
        if let Err(e) = crate::repo::agent_messages::insert(&state.db, &env, verified).await {
            // Leave it unacked: JetStream redelivers (up to
            // RECORDER_MAX_DELIVER), and the insert is idempotent on id —
            // a DB blip loses nothing; a poison row stops after 5 tries.
            tracing::warn!(id = %env.id, error = %e, "agent_messages.recorder.insert_failed");
            continue;
        }
        let _ = msg.ack().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_follow_the_address() {
        let mut e = Envelope::new("host8/coordinator", "host3/claude-code-1", "message", Value::Null, Some("thr_1"), vec![]);
        assert_eq!(e.subject(), "agent.msg.direct.host3.claude-code-1");
        e.to = "thread".into();
        assert_eq!(e.subject(), "agent.msg.thread.thr_1");
        e.to = "*".into();
        assert_eq!(e.subject(), "agent.msg.broadcast");
    }

    #[test]
    fn ids_are_validated_and_subject_tokens_are_injective() {
        for ok in ["host3/claude-code-1", "host8/coordinator", "thr_abc123", "a", "worker/ingest/2"] {
            assert!(is_valid_id(ok), "{ok}");
        }
        for bad in ["", "/x", "x/", "a//b", "a.b", "a b", "a*b", "a>b", "host3_claude-code-1/", &"x".repeat(129)] {
            assert!(!is_valid_id(bad), "{bad:?}");
        }
        // Distinct valid ids never share a token (the takeover).
        assert_ne!(subject_token("host3/claude-code-1"), subject_token("host3_claude-code-1"));
        assert_eq!(subject_token("host3/claude-code-1"), "host3.claude-code-1");
        let mut e = Envelope::new("host3.claude-code-1", "b", "message", Value::Null, None, vec![]);
        assert!(e.validate().unwrap_err().contains("from"));
        e.from = "a".into();
        e.to = "b*".into();
        assert!(e.validate().unwrap_err().contains("to"));
        e.to = "b".into();
        e.refs = vec!["r".repeat(MAX_ID_LEN + 1)];
        assert!(e.validate().unwrap_err().contains("ref"));
        e.refs.clear();
        e.body = serde_json::json!({ "text": "x".repeat(MAX_BODY_BYTES) });
        assert!(e.validate().unwrap_err().contains("bytes"));
    }

    #[test]
    fn verify_envelope_rejects_plaintext_and_unsigned_when_a_key_is_configured() {
        // Without a review key in the test process, nothing is enforced.
        let e = Envelope::new("a", "b", "message", serde_json::json!({"text": "hi"}), None, vec![]);
        if crate::agent_crypto::controller_keys().is_none() {
            assert_eq!(verify_envelope(&e), Ok(false));
            return;
        }
        assert!(verify_envelope(&e).is_err());
        let mut sealed = e.clone();
        seal_envelope(&mut sealed, None).unwrap();
        assert_eq!(verify_envelope(&sealed), Ok(true));
        sealed.to = "c".into();
        assert!(verify_envelope(&sealed).unwrap_err().contains("signature"));
    }

    #[test]
    fn validation_and_defaults() {
        let e = Envelope::new("a", "b", "message", serde_json::json!({"text": "hi"}), None, vec![]);
        assert!(e.validate().is_ok());
        assert!(e.thread_id.starts_with("thr_") && e.id.starts_with("msg_"));
        let bad = Envelope { kind: "shout".into(), ..e.clone() };
        assert!(bad.validate().unwrap_err().contains("kind"));
        // Wire shape round-trips and tolerates absent optional fields.
        let wire: Envelope = serde_json::from_str(r#"{"id":"msg_x","thread_id":"thr_x","from":"a","to":"b","ts":"2026-09-03T00:00:00Z"}"#).unwrap();
        assert_eq!(wire.kind, "message");
        assert_eq!(wire.enc, "none");
        assert!(wire.sig.is_none());
        assert!(wire.from_id.is_none());
        assert!(wire.enc_meta.is_none());
    }

    #[test]
    fn seal_envelope_is_a_no_op_without_a_review_key_and_seals_with_one() {
        // No key in this test process → untouched.
        let mut e = Envelope::new("a", "b", "message", serde_json::json!({"text": "hi"}), None, vec![]);
        if crate::agent_crypto::controller_keys().is_none() {
            seal_envelope(&mut e, None).unwrap();
            assert_eq!(e.enc, "none");
            assert_eq!(e.body["text"], "hi");
        }
        // The primitive itself, with an explicit key set.
        let ks = crate::agent_crypto::KeySet::from_secret("controller-review-secret-with-enough-entropy-0123").unwrap();
        let aad = e.aad();
        let sealed = crate::agent_crypto::seal(&e.body, &[crate::agent_crypto::Recipient { label: "review", key: ks.seal_public() }], &aad).unwrap();
        let opened = crate::agent_crypto::open(&sealed, "review", &ks.seal, &aad).unwrap();
        assert_eq!(opened["text"], "hi");
    }

    #[test]
    fn identity_labels_and_round_trips() {
        let id = Identity::new(Some("alice"), Some("node-1"), Some("claude-code-1"), Some("claude-code"));
        assert_eq!(id.label(), "alice@node-1/claude-code-1 (claude-code)");
        let e = Envelope::new("claude-code-1", "hermes-1", "message", Value::Null, None, vec![]).with_from(id.clone());
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back.from_id, Some(id));
        assert_eq!(Identity::new(Some(" "), None, None, None), Identity::default());
    }
}

#[cfg(test)]
mod controller_node_tests {
    use super::is_container_id;

    #[test]
    fn docker_ids_are_recognised() {
        assert!(is_container_id("86c47f153ae0"));
        assert!(is_container_id("90417b3f1220"));
        assert!(is_container_id(&"a".repeat(64)));
    }

    #[test]
    fn real_node_names_are_not() {
        for n in ["host8", "host3", "host9", "host2", "host6", "controller"] {
            assert!(!is_container_id(n), "{n} must not read as a container id");
        }
    }

    #[test]
    fn a_short_hex_looking_hostname_is_left_alone() {
        // A host may legitimately be called `cafe01`. The length is pinned to
        // the two docker actually emits rather than "looks hexish", so a real
        // machine is never mistaken for a container.
        assert!(!is_container_id("cafe01"));
        assert!(!is_container_id("deadbeef"));
        assert!(!is_container_id(&"a".repeat(13)));
    }

    #[test]
    fn uppercase_is_not_a_container_id() {
        // Docker emits lowercase. An uppercase hostname is a real machine.
        assert!(!is_container_id("86C47F153AE0"));
    }
}
