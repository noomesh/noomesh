// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Bulk embedding jobs (i179): work that workers CLAIM, with the gateway as
//! the fallback worker.
//!
//! `POST /api/external/embeddings/jobs` takes a batch of texts and answers
//! `202 {job_id, path, model}`. Two paths carry it:
//!
//! - **pull**: the batch is published to `work.embed.<slug>` on the
//!   `WORK_EMBED` JetStream work queue. A node-agent that serves the model
//!   binds the durable consumer `embed_<slug>` (created HERE, never by a
//!   node), fetches only when it has a free embed slot, embeds locally and
//!   reports on the ordinary `events.job.{ack,complete,failed}.<node>`
//!   subjects. JetStream owns redelivery.
//! - **push-run**: when nobody is pulling (no consumer, no live puller, the
//!   stream is missing, the publish is not acknowledged), the gateway embeds
//!   the batch itself through the same mesh balancer the synchronous route
//!   uses, under a global cap of [`PUSH_CONCURRENCY`], so bulk work never
//!   takes the query-time slots.
//!
//! Either way the caller sees one job and one result shape: the vectors are
//! NOT kept in the 24 h job hash. They live in `noo:jobs:<id>:out` for
//! [`VECTORS_TTL_SECS`] and the hash keeps a `{"embed": {v, model, dims, n}}`
//! summary. `GET /api/jobs/{id}?vectors=1` reads them back (410 once gone).
//!
//! # Why the scheduler leaves these jobs alone
//!
//! An `embed_batch` job is never on `noo:jobs:queue` and never published to
//! `tasks.dispatch.<node>`. `scheduler_engine::{reap_timeouts, janitor,
//! recover_from_restart}` skip it ([`is_embed_job`]): their "requeue" is a
//! ZADD onto the node dispatch queue, which would hand the batch to a second
//! mechanism while JetStream (pull) or the push-run task still owns it.
//! [`sweep`] is the one loop that judges these jobs, and every failure it
//! finds ends in a state somebody can see: a push-run, or `dead` with a
//! reason.
//!
//! The wire contract with the node-agent (subject, consumer config, job
//! message, completion payload) is `node-agent-go/internal/jobs/
//! embedpull_subjects.go` plus the proposal `i179-embed-work-claimed-by-
//! workers`; the constants below must stay in step with that file.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::http::StatusCode;
use axum::Json;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::cache::RedisCache;
use crate::scheduler_engine::{self, ACTIVE_SET, JOB_KEY_PREFIX};
use crate::state::AppState;

// ── The contract ─────────────────────────────────────────────────────────

pub const JOB_TYPE: &str = "embed_batch";
pub const STREAM: &str = "WORK_EMBED";
pub const SUBJECT_PREFIX: &str = "work.embed.";
pub const CONSUMER_PREFIX: &str = "embed_";
const CONSUMER_ACK_WAIT_SECS: u64 = 60;
const CONSUMER_MAX_DELIVER: i64 = 3;
const CONSUMER_MAX_ACK_PENDING: i64 = 256;

/// Most texts in one job.
pub const MAX_INPUTS: usize = 64;
/// The encoded result must fit under this (NATS `max_payload` is 1 MiB).
const RESULT_CAP_BYTES: u64 = 600 * 1024;
/// Allowance for the envelope around the base64 vectors.
const RESULT_OVERHEAD_BYTES: u64 = 64 * 1024;
/// A submit is refused (429) while the model's consumer holds more than this.
pub const MAX_PENDING: u64 = 5000;
/// A puller counts as live when its last delivery is this recent.
const LIVE_PULLER_WINDOW_SECS: i64 = 30;
/// Each text is cut to this many characters, as the synchronous route does.
const MAX_TEXT_CHARS: usize = 1500;

// ── Gateway-side knobs ───────────────────────────────────────────────────

/// How long a pull job may sit `queued` with nobody pulling before the
/// gateway runs it itself.
pub const PULL_WAIT_SECS: i64 = 120;
/// A pulled job that has not reported for this long has exhausted its
/// deliveries (3 x `ack_wait`, plus slack) or lost its worker.
const PULL_RUNNING_STALE_SECS: i64 = 240;
/// A push-run that has not finished for this long died with its task (a
/// gateway restart); nothing is going to complete it.
const PUSH_STALE_SECS: i64 = 600;
/// No embed job outlives the stream's own `max_age`.
const JOB_MAX_AGE_SECS: i64 = 6 * 60 * 60;
const VECTORS_TTL_SECS: i64 = 15 * 60;
/// The batch text, kept so a flip to push-run can still embed it.
const INPUT_TTL_SECS: i64 = JOB_MAX_AGE_SECS;
/// Concurrent gateway-run batches, fleet-wide. Below the balancer's four per
/// target, so a bulk run never takes the query-time slots.
const PUSH_CONCURRENCY: usize = 2;
const PUSH_EMBED_TIMEOUT: Duration = Duration::from_secs(30);
/// Retry-After for a full queue.
const BUSY_RETRY_AFTER_SECS: u64 = 10;
/// Open ids of non-terminal embed jobs, so [`sweep`] reads them and not the
/// whole active set.
const JOBS_SET: &str = "noo:embed:jobs";

static PUSH_SLOTS: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(PUSH_CONCURRENCY));

// ── Names ────────────────────────────────────────────────────────────────

/// The model's slug: ASCII `A-Z` lowercased, then every character outside
/// `[a-z0-9_-]` becomes `_`. No trimming, no collapsing. Byte-for-byte what
/// the node-agent computes (`EmbedSlug`, node-agent-go/internal/jobs); the
/// test vectors below are the contract's.
///
/// ASCII only on purpose: Unicode lowercasing differs between Rust and Go
/// (U+0130 is one character in one and two in the other), and a slug that
/// differs by one `_` sends a model's jobs to a subject nobody pulls.
pub fn slug(model: &str) -> String {
    model
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| if matches!(c, 'a'..='z' | '0'..='9' | '_' | '-') { c } else { '_' })
        .collect()
}

pub fn subject(slug: &str) -> String {
    format!("{SUBJECT_PREFIX}{slug}")
}

pub fn consumer_name(slug: &str) -> String {
    format!("{CONSUMER_PREFIX}{slug}")
}

fn out_key(job_id: &str) -> String {
    format!("{JOB_KEY_PREFIX}{job_id}:out")
}

fn in_key(job_id: &str) -> String {
    format!("{JOB_KEY_PREFIX}{job_id}:in")
}

/// The durable consumer the gateway creates for a model. Nodes only bind.
pub fn consumer_config(slug: &str) -> async_nats::jetstream::consumer::pull::Config {
    async_nats::jetstream::consumer::pull::Config {
        durable_name: Some(consumer_name(slug)),
        filter_subject: subject(slug),
        ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
        ack_wait: Duration::from_secs(CONSUMER_ACK_WAIT_SECS),
        max_deliver: CONSUMER_MAX_DELIVER,
        max_ack_pending: CONSUMER_MAX_ACK_PENDING,
        ..Default::default()
    }
}

pub fn is_embed_job(hash: &HashMap<String, String>) -> bool {
    hash.get("type").map(String::as_str) == Some(JOB_TYPE)
}

pub fn wants_vectors(param: Option<&str>) -> bool {
    matches!(param.map(str::trim), Some("1") | Some("true"))
}

// ── Paths and errors ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobPath {
    Pull,
    Push,
}

impl JobPath {
    pub fn as_str(self) -> &'static str {
        match self {
            JobPath::Pull => "pull",
            JobPath::Push => "push",
        }
    }
}

/// Why a submit was refused, in the route's terms.
#[derive(Debug)]
pub enum SubmitError {
    /// 400.
    BadRequest(String),
    /// 409 (a refusal about the state of a space).
    Conflict(String),
    /// 413: over the batch cap. The message names the cap.
    TooLarge(String),
    /// 429 + Retry-After: the model's queue is full.
    Busy { retry_after_secs: u64, detail: String },
    /// 503: no embedder can take it, or the job store is down.
    Unavailable(String),
}

pub struct Submitted {
    pub job_id: String,
    pub path: JobPath,
    pub model: String,
}

// ── What the job embeds with ─────────────────────────────────────────────

/// The space and model a job resolved to at submit. Recorded on the job, so a
/// batch queued across a migration cutover is still embedded, and returned,
/// with the model it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `knowledge`, or `knowledge@next`.
    pub space: String,
    pub model: String,
    /// Expected vector width; `None` = learn it from the answer.
    pub dims: Option<u64>,
    /// `<space>@next`: the model over the mesh pool only.
    pub next: bool,
}

impl Target {
    fn from_hash(hash: &HashMap<String, String>) -> Option<Target> {
        let model = hash.get("model").filter(|m| !m.is_empty())?.clone();
        let space = hash.get("space").cloned().unwrap_or_default();
        let dims = hash.get("dims").and_then(|d| d.trim().parse::<u64>().ok()).filter(|d| *d > 0);
        let next = space.ends_with("@next");
        Some(Target { space, model, dims, next })
    }
}

/// Resolve the caller's space exactly as the synchronous `do_embeddings`
/// does (`routes/external.rs`), so a job and a sync call for the same
/// `model` field mean the same thing.
pub fn resolve_target(requested: Option<&str>) -> Result<Target, SubmitError> {
    let spaces = crate::embedding_spaces::all();
    if let Some(name) = crate::embedding_spaces::parse_next(requested) {
        // `<space>@next` (i150): the space's NEXT model during a migration.
        let s = crate::embedding_spaces::resolve(&spaces, Some(name)).map_err(SubmitError::BadRequest)?;
        let m = s.migration.as_ref().ok_or_else(|| {
            SubmitError::Conflict(format!(
                "embedding space '{}' has no migration: '{}@next' means its next model",
                s.space, s.space
            ))
        })?;
        if let Some(why) = crate::embedding_spaces::trellion_refusal(m) {
            return Err(SubmitError::Conflict(why));
        }
        return Ok(Target {
            space: format!("{}@next", s.space),
            model: m.next_model.clone(),
            dims: m.next_dims.filter(|d| *d > 0),
            next: true,
        });
    }
    let ep = crate::embedding_client::resolve_space(requested).map_err(SubmitError::BadRequest)?;
    let space = crate::embedding_spaces::resolve(&spaces, requested)
        .map(|s| s.space.clone())
        .unwrap_or_else(|_| crate::embedding_spaces::DEFAULT_SPACE.to_string());
    Ok(Target { space, model: ep.model, dims: Some(ep.dims).filter(|d| *d > 0), next: false })
}

// ── Caps ─────────────────────────────────────────────────────────────────

/// The size of the encoded result for `n` vectors of `dims` floats:
/// `n * dims * 4 * 4/3 + 64 KiB`.
pub fn result_bytes(n: usize, dims: u64) -> u64 {
    (n as u64).saturating_mul(dims).saturating_mul(16) / 3 + RESULT_OVERHEAD_BYTES
}

/// `Some(reason)` when a batch of `n` texts is over the cap. The reason names
/// the cap, because it is the 413 body.
pub fn cap_refusal(n: usize, dims: Option<u64>) -> Option<String> {
    if n > MAX_INPUTS {
        return Some(format!("a job takes at most {MAX_INPUTS} texts; got {n}"));
    }
    let dims = dims?;
    if result_bytes(n, dims) > RESULT_CAP_BYTES {
        let room = RESULT_CAP_BYTES.saturating_sub(RESULT_OVERHEAD_BYTES) * 3 / (16 * dims.max(1));
        return Some(format!(
            "{n} texts of {dims} dimensions would return about {} KiB, over the {} KiB cap; send at most {} texts per job at this width",
            result_bytes(n, dims) / 1024,
            RESULT_CAP_BYTES / 1024,
            room.min(MAX_INPUTS as u64),
        ));
    }
    None
}

/// A batch the route can accept: non-empty and under the cap.
pub fn validate_batch(n: usize, dims: Option<u64>) -> Result<(), SubmitError> {
    if n == 0 {
        return Err(SubmitError::BadRequest("'input' is empty".into()));
    }
    match cap_refusal(n, dims) {
        Some(why) => Err(SubmitError::TooLarge(why)),
        None => Ok(()),
    }
}

/// The body's `input` as texts. A single string is a batch of one. Unlike the
/// synchronous route, a non-string element is refused rather than dropped:
/// the vectors come back by position, and a dropped element would shift every
/// one after it.
pub fn parse_inputs(input: Option<&Value>) -> Result<Vec<String>, String> {
    let cut = |s: &str| -> String { s.chars().take(MAX_TEXT_CHARS).collect() };
    match input {
        Some(Value::String(s)) => Ok(vec![cut(s)]),
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(cut(s)),
                    None => return Err(format!("input[{i}] is not a string")),
                }
            }
            Ok(out)
        }
        _ => Err("missing or invalid 'input'".into()),
    }
}

// ── Vectors on the wire ──────────────────────────────────────────────────

/// `n * dims` little-endian f32 values, row-major, as standard padded base64.
pub fn encode_vectors(vectors: &[Vec<f64>]) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(vectors.iter().map(|v| v.len() * 4).sum());
    for v in vectors {
        for x in v {
            bytes.extend_from_slice(&(*x as f32).to_le_bytes());
        }
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode `vectors_b64` and check `n * dims * 4` against the byte length.
/// Anything else is a worker that sent the wrong thing, and its vectors are
/// never stored.
pub fn decode_vectors(b64: &str, n: usize, dims: usize) -> Result<Vec<Vec<f32>>, String> {
    if n == 0 || dims == 0 {
        return Err(format!("n={n} dims={dims}: both must be positive"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("vectors_b64 is not base64: {e}"))?;
    let want = n.checked_mul(dims).and_then(|c| c.checked_mul(4)).ok_or_else(|| "n * dims overflows".to_string())?;
    if bytes.len() != want {
        return Err(format!(
            "vectors_b64 holds {} bytes; n={n} x dims={dims} x 4 is {want}",
            bytes.len()
        ));
    }
    Ok(bytes
        .chunks_exact(dims * 4)
        .map(|row| {
            row.chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        })
        .collect())
}

/// A gateway-run answer is rectangular, the right count, and the expected
/// width. Returns the width.
pub fn check_vectors(vectors: &[Vec<f64>], want_n: usize, want_dims: Option<u64>) -> Result<usize, String> {
    if vectors.len() != want_n {
        return Err(format!("the embedder returned {} vectors for {want_n} texts", vectors.len()));
    }
    let dims = vectors.first().map_or(0, Vec::len);
    if dims == 0 || vectors.iter().any(|v| v.len() != dims) {
        return Err("the embedder returned vectors of differing or zero width".into());
    }
    if let Some(d) = want_dims {
        if d != dims as u64 {
            return Err(format!("the embedder returned {dims}-dimension vectors; the space is {d}"));
        }
    }
    Ok(dims)
}

/// The job's `result` once vectors have moved aside.
pub fn summary_json(model: &str, dims: usize, n: usize) -> String {
    json!({"embed": {"v": 1, "model": model, "dims": dims, "n": n}}).to_string()
}

/// `(n, dims)` out of a stored summary.
fn summary_shape(result: &str) -> Option<(usize, usize)> {
    let v: Value = serde_json::from_str(result).ok()?;
    let e = v.get("embed")?;
    Some((e.get("n")?.as_u64()? as usize, e.get("dims")?.as_u64()? as usize))
}

/// A worker's `complete` result, checked against the job it claims to finish.
#[derive(Debug, PartialEq, Eq)]
pub struct EmbedResult {
    pub model: String,
    pub dims: usize,
    pub n: usize,
    pub vectors_b64: String,
}

/// Parse and check a worker's completion: `{"embed": {v, model, dims, n,
/// vectors_b64}}` as a JSON string (or object). Refuses another model's
/// vectors, a wrong count or width, and a byte length that is not
/// `n * dims * 4`. `Err` carries the reason that goes on the dead job.
pub fn check_complete(hash: &HashMap<String, String>, result: Option<&Value>) -> Result<EmbedResult, String> {
    let raw: Value = match result {
        Some(Value::String(s)) => serde_json::from_str(s).map_err(|e| format!("result is not JSON: {e}"))?,
        Some(v) if v.is_object() => v.clone(),
        _ => return Err("the completion carries no result".into()),
    };
    let e = raw.get("embed").ok_or_else(|| "result has no 'embed' object".to_string())?;
    let v = e.get("v").and_then(Value::as_u64);
    if v != Some(1) {
        return Err(format!("unsupported embed result version {v:?}"));
    }
    let model = e
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| "result has no 'model'".to_string())?
        .to_string();
    let dims = e.get("dims").and_then(Value::as_u64).ok_or_else(|| "result has no 'dims'".to_string())? as usize;
    let n = e.get("n").and_then(Value::as_u64).ok_or_else(|| "result has no 'n'".to_string())? as usize;
    let b64 = e
        .get("vectors_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| "result has no 'vectors_b64'".to_string())?;

    let want_model = hash.get("model").map(String::as_str).unwrap_or("");
    if !crate::embedding_spaces::same_model(&model, want_model) {
        return Err(format!("served model '{model}', not the job's '{want_model}'"));
    }
    let want_n = hash.get("n").and_then(|s| s.trim().parse::<usize>().ok()).unwrap_or(0);
    if n != want_n {
        return Err(format!("the worker returned n={n} for a job of {want_n} texts"));
    }
    if let Some(d) = hash.get("dims").and_then(|s| s.trim().parse::<u64>().ok()).filter(|d| *d > 0) {
        if d != dims as u64 {
            return Err(format!("the worker returned {dims}-dimension vectors; the space is {d}"));
        }
    }
    // Decode to prove the length; the base64 text is what is stored.
    decode_vectors(b64, n, dims)?;
    Ok(EmbedResult { model, dims, n, vectors_b64: b64.to_string() })
}

// ── The queue, as the gateway sees it ────────────────────────────────────

/// What `CONSUMER.INFO` says about a model's consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueInfo {
    pub pending: u64,
    pub ack_pending: u64,
    pub waiting: u64,
    pub last_delivery_unix: Option<i64>,
}

impl QueueInfo {
    pub fn from_info(i: &async_nats::jetstream::consumer::Info) -> Self {
        QueueInfo {
            pending: i.num_pending,
            ack_pending: i.num_ack_pending as u64,
            waiting: i.num_waiting as u64,
            last_delivery_unix: i.delivered.last_active.map(|t| t.unix_timestamp()),
        }
    }

    /// A node is pulling: a fetch is open, or something was delivered
    /// recently. The consumer's own numbers, never the agent's claim.
    pub fn has_live_puller(&self, now_unix: i64) -> bool {
        self.waiting > 0
            || self
                .last_delivery_unix
                .is_some_and(|t| now_unix - t <= LIVE_PULLER_WINDOW_SECS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pull,
    /// Run it in the gateway. The reason is for the log and `status_detail`.
    PushRun(String),
    TooBusy { pending: u64 },
}

/// Where a batch goes, given what the probe found. `Err` from the probe
/// (stream missing, NATS down) is a push-run: a job is never queued with
/// nothing to carry it.
pub fn decide(probe: &Result<Option<QueueInfo>, String>, now_unix: i64) -> Decision {
    match probe {
        Err(why) => Decision::PushRun(format!("work queue unavailable: {why}")),
        Ok(None) => Decision::PushRun("no consumer for the model yet".into()),
        Ok(Some(q)) if q.pending > MAX_PENDING => Decision::TooBusy { pending: q.pending },
        Ok(Some(q)) if q.has_live_puller(now_unix) => Decision::Pull,
        Ok(Some(_)) => Decision::PushRun("no live puller".into()),
    }
}

/// `Ok(None)`: no consumer. `Err`: the stream, or NATS, did not answer.
async fn probe_queue(js: &async_nats::jetstream::Context, slug: &str) -> Result<Option<QueueInfo>, String> {
    use async_nats::jetstream::context::ConsumerInfoErrorKind;
    let stream = js.get_stream(STREAM).await.map_err(|e| format!("stream {STREAM}: {e}"))?;
    let name = consumer_name(slug);
    match stream.consumer_info(&name).await {
        Ok(info) => Ok(Some(QueueInfo::from_info(&info))),
        Err(e) if e.kind() == ConsumerInfoErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("consumer {name}: {e}")),
    }
}

/// Create the model's consumer if it is missing. `get_or_create_consumer`
/// asks first and creates only on a 404, so an existing consumer (and
/// whatever limits an operator gave it) is never updated.
async fn ensure_consumer(js: &async_nats::jetstream::Context, slug: &str) -> Result<(), String> {
    let stream = js.get_stream(STREAM).await.map_err(|e| format!("stream {STREAM}: {e}"))?;
    stream
        .get_or_create_consumer(&consumer_name(slug), consumer_config(slug))
        .await
        .map(|_| ())
        .map_err(|e| format!("create consumer {}: {e}", consumer_name(slug)))
}

/// The probe a submit decides on: the consumer's numbers, creating the
/// consumer first when it does not exist (a fresh one has no puller, so the
/// first job for a model is a push-run, and nodes can bind from now on).
async fn probe_or_create(js: &async_nats::jetstream::Context, slug: &str) -> Result<Option<QueueInfo>, String> {
    match probe_queue(js, slug).await? {
        Some(q) => Ok(Some(q)),
        None => {
            ensure_consumer(js, slug).await?;
            Ok(Some(QueueInfo::default()))
        }
    }
}

enum PublishFailure {
    /// The stream refused: it is full (`DiscardPolicy::New`).
    Full(String),
    Other(String),
}

/// Whether a JetStream publish error says the stream is full, not broken.
/// The server words it "maximum messages exceeded" / "maximum bytes
/// exceeded"; a miss here is safe, it only makes a full queue run in the
/// gateway instead of answering 429.
fn publish_refusal_is_full(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("maximum messages exceeded") || m.contains("maximum bytes exceeded")
}

/// Publish with the JetStream ack and a `Nats-Msg-Id` of the job id. Returns
/// the stream sequence.
async fn publish_work(
    js: &async_nats::jetstream::Context,
    subject: String,
    job_id: &str,
    body: &Value,
) -> Result<u64, PublishFailure> {
    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Nats-Msg-Id", job_id);
    let payload = body.to_string();
    let pending = js
        .publish_with_headers(subject, headers, payload.into())
        .await
        .map_err(|e| PublishFailure::Other(e.to_string()))?;
    match pending.await {
        Ok(ack) => Ok(ack.sequence),
        Err(e) => {
            let msg = e.to_string();
            if publish_refusal_is_full(&msg) {
                Err(PublishFailure::Full(msg))
            } else {
                Err(PublishFailure::Other(msg))
            }
        }
    }
}

// ── Submit ───────────────────────────────────────────────────────────────

struct NewJob<'a> {
    id: &'a str,
    target: &'a Target,
    slug: &'a str,
    n: usize,
    owner: &'a str,
    path: JobPath,
    now: &'a str,
}

/// Write the job hash and register it with the active set and the sweep.
async fn create_job(redis: &RedisCache, job: &NewJob<'_>) -> bool {
    let key = format!("{JOB_KEY_PREFIX}{}", job.id);
    let payload = json!({
        "space": job.target.space,
        "model": job.target.model,
        "dims": job.target.dims,
        "n": job.n,
    })
    .to_string();
    // A pull job is `queued` and unassigned until a worker acks it; a
    // push-run is running in the gateway from the start.
    let (status, node_id, dispatched_at) = match job.path {
        JobPath::Pull => ("queued", "", ""),
        JobPath::Push => ("running", "gateway", job.now),
    };
    let pairs = crate::routes::admin::job_hash_pairs(&crate::routes::admin::JobHashSpec {
        job_id: job.id,
        job_type: JOB_TYPE,
        payload: payload.as_str(),
        priority: 5,
        status,
        now: job.now,
        dispatched_at,
        node_id,
        max_retries: 0,
        timeout_sec: 300,
        force_node: "",
        min_vram_gb: 0.0,
        backend: "",
    });
    let dims_s = job.target.dims.map(|d| d.to_string()).unwrap_or_default();
    let n_s = job.n.to_string();
    let extras: Vec<(&str, &str)> = vec![
        ("owner", job.owner),
        ("path", job.path.as_str()),
        ("model", job.target.model.as_str()),
        ("space", job.target.space.as_str()),
        ("dims", dims_s.as_str()),
        ("n", n_s.as_str()),
        ("slug", job.slug),
    ];
    if !crate::routes::admin::hset_job_hash(redis, &key, &pairs, &extras).await {
        return false;
    }
    redis.sadd(ACTIVE_SET, job.id).await;
    redis.sadd(JOBS_SET, job.id).await;
    true
}

async fn path_counter(state: &AppState, path: JobPath) {
    let mut labels = HashMap::new();
    labels.insert("path".to_string(), path.as_str().to_string());
    state.metrics.inc_counter("noo_embed_pull_jobs_total", Some(&labels), 1).await;
}

/// Compare-and-set a `pull` job over to push-run: only if it is still in the
/// state (and carries the `updated_at`) the caller read, so a worker that acks
/// between the read and the flip wins and the flip does nothing.
const FLIP_SCRIPT: &str = r#"
local st = redis.call('HGET', KEYS[1], 'status')
local pa = redis.call('HGET', KEYS[1], 'path')
local up = redis.call('HGET', KEYS[1], 'updated_at')
if st ~= ARGV[1] or pa ~= 'pull' or up ~= ARGV[2] then return 0 end
redis.call('HSET', KEYS[1],
  'path', 'push',
  'status', 'running',
  'node_id', 'gateway',
  'dispatched_at', ARGV[3],
  'updated_at', ARGV[3],
  'status_detail', ARGV[4])
return 1
"#;

async fn cas_flip(redis: &RedisCache, job_id: &str, expect_status: &str, expect_updated: &str, reason: &str) -> bool {
    let now = chrono::Utc::now().to_rfc3339();
    redis
        .eval_i64(
            FLIP_SCRIPT,
            &[format!("{JOB_KEY_PREFIX}{job_id}")],
            &[
                expect_status.to_string(),
                expect_updated.to_string(),
                now,
                format!("run by the gateway: {reason}"),
            ],
        )
        .await
        == Some(1)
}

/// Would a gateway-run embed find a target at all? The same test
/// `embed_over` applies: some mesh node (or static endpoint) on the model.
/// An empty pool is the 503 the synchronous route would answer.
async fn pool_is_empty(state: &AppState, t: &Target) -> bool {
    use crate::embedding_client::{consistent_candidates, Candidate, EmbeddingEndpoint};
    let mesh = crate::routes::external::mesh_targets(state, "embed", "embed", 5).await;
    let mut cands: Vec<Candidate> = Vec::with_capacity(mesh.len() + 1);
    for m in mesh {
        let declared = crate::model_presence::node_role_models(state, &m.node_id, "embed").await;
        cands.push(Candidate::Mesh(m, declared));
    }
    if !t.next {
        let ep = EmbeddingEndpoint {
            model: t.model.clone(),
            dims: t.dims.unwrap_or(0),
            ..crate::embedding_client::resolve()
        };
        cands.extend(ep.static_endpoints().into_iter().map(Candidate::Static));
    }
    consistent_candidates(cands, &t.model).is_empty()
}

fn unavailable_for(t: &Target) -> SubmitError {
    SubmitError::Unavailable(format!(
        "no embed target serves model '{}' (space '{}')",
        t.model, t.space
    ))
}

/// Accept a batch: resolve the space, enforce the caps, pick the path, and
/// either publish it for a worker or start the gateway's own run.
///
/// Every external call has an answer for "absent, old or failing":
/// - stream or consumer missing, or `CONSUMER.INFO` failing: push-run;
/// - the publish not acknowledged: push-run now (the job was written
///   `queued` first, so a worker that did get it is not orphaned: the flip is
///   a compare-and-set that loses to its ack);
/// - the stream refusing because it is full: 429 + Retry-After;
/// - Redis down: 503, nothing queued.
pub async fn submit(
    state: &Arc<AppState>,
    owner: &str,
    inputs: Vec<String>,
    requested: Option<&str>,
) -> Result<Submitted, SubmitError> {
    let n = inputs.len();
    let target = resolve_target(requested)?;
    validate_batch(n, target.dims)?;
    let Some(redis) = state.redis.as_ref() else {
        return Err(SubmitError::Unavailable("the job store (Redis) is not connected".into()));
    };
    let sl = slug(&target.model);

    let probe = probe_or_create(&state.js, &sl).await;
    if let Err(why) = &probe {
        tracing::warn!(model = %target.model, error = %why, "embed_jobs.queue_probe_failed — running the batch in the gateway");
    }
    let now_unix = chrono::Utc::now().timestamp();
    match decide(&probe, now_unix) {
        Decision::TooBusy { pending } => Err(SubmitError::Busy {
            retry_after_secs: BUSY_RETRY_AFTER_SECS,
            detail: format!("{pending} batches already wait for model '{}' (limit {MAX_PENDING})", target.model),
        }),
        Decision::PushRun(reason) => {
            tracing::info!(model = %target.model, reason = %reason, "embed_jobs.push_run");
            if pool_is_empty(state, &target).await {
                return Err(unavailable_for(&target));
            }
            let job_id = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();
            let job = NewJob { id: &job_id, target: &target, slug: &sl, n, owner, path: JobPath::Push, now: &now };
            if !create_job(redis, &job).await {
                return Err(SubmitError::Unavailable("could not record the job".into()));
            }
            redis
                .hset(&format!("{JOB_KEY_PREFIX}{job_id}"), &[("status_detail", reason.as_str())])
                .await;
            path_counter(state, JobPath::Push).await;
            let model = target.model.clone();
            spawn_push_run(state.clone(), job_id.clone(), target, inputs);
            Ok(Submitted { job_id, path: JobPath::Push, model })
        }
        Decision::Pull => {
            let job_id = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();
            // The text first, then the job, then the message: a worker can
            // ack the moment the message lands, and an event about a job the
            // gateway has not written yet is ignored.
            let text = serde_json::to_string(&inputs).unwrap_or_default();
            if !redis.set_string_ex(&in_key(&job_id), &text, INPUT_TTL_SECS).await {
                return Err(SubmitError::Unavailable("could not store the batch".into()));
            }
            let job = NewJob { id: &job_id, target: &target, slug: &sl, n, owner, path: JobPath::Pull, now: &now };
            if !create_job(redis, &job).await {
                redis.del_key(&in_key(&job_id)).await;
                return Err(SubmitError::Unavailable("could not record the job".into()));
            }
            let body = json!({
                "v": 1,
                "job_id": job_id,
                "model": target.model,
                "space": target.space,
                "dims": target.dims,
                "input": inputs,
            });
            match publish_work(&state.js, subject(&sl), &job_id, &body).await {
                Ok(seq) => {
                    redis
                        .hset(&format!("{JOB_KEY_PREFIX}{job_id}"), &[("stream_seq", seq.to_string().as_str())])
                        .await;
                    path_counter(state, JobPath::Pull).await;
                    Ok(Submitted { job_id, path: JobPath::Pull, model: target.model.clone() })
                }
                Err(PublishFailure::Full(why)) => {
                    scheduler_engine::terminalize(state, &job_id, "dead", "", "refused: the work queue is full").await;
                    redis.del_key(&in_key(&job_id)).await;
                    Err(SubmitError::Busy { retry_after_secs: BUSY_RETRY_AFTER_SECS, detail: why })
                }
                Err(PublishFailure::Other(why)) => {
                    tracing::warn!(job_id = %job_id, error = %why, "embed_jobs.publish_failed — running the batch in the gateway");
                    if pool_is_empty(state, &target).await {
                        scheduler_engine::terminalize(state, &job_id, "dead", "", "no embed target and the work queue refused it").await;
                        redis.del_key(&in_key(&job_id)).await;
                        return Err(unavailable_for(&target));
                    }
                    // The publish may have landed after all; if a worker has
                    // already acked, the flip loses and the pull stands.
                    let flipped = cas_flip(redis, &job_id, "queued", &now, "the work queue did not acknowledge the batch").await;
                    if flipped {
                        path_counter(state, JobPath::Push).await;
                        let model = target.model.clone();
                        spawn_push_run(state.clone(), job_id.clone(), target, inputs);
                        Ok(Submitted { job_id, path: JobPath::Push, model })
                    } else {
                        path_counter(state, JobPath::Pull).await;
                        Ok(Submitted { job_id, path: JobPath::Pull, model: target.model.clone() })
                    }
                }
            }
        }
    }
}

// ── Push-run ─────────────────────────────────────────────────────────────

pub fn spawn_push_run(state: Arc<AppState>, job_id: String, target: Target, texts: Vec<String>) {
    tokio::spawn(async move {
        run_push(&state, &job_id, &target, &texts).await;
    });
}

async fn job_is_terminal(redis: &RedisCache, job_id: &str) -> bool {
    let status = redis.hget(&format!("{JOB_KEY_PREFIX}{job_id}"), "status").await.unwrap_or_default();
    scheduler_engine::TERMINAL_STATES.contains(&status.as_str())
}

/// Embed the batch in the gateway, under the global cap, and write the same
/// two records a worker's completion does.
async fn run_push(state: &Arc<AppState>, job_id: &str, t: &Target, texts: &[String]) {
    let _permit = match PUSH_SLOTS.acquire().await {
        Ok(p) => p,
        Err(_) => {
            fail_job(state, job_id, "the gateway's embed slots are closed").await;
            return;
        }
    };
    if let Some(redis) = state.redis.as_ref() {
        if job_is_terminal(redis, job_id).await {
            return; // cancelled, or a worker finished it first
        }
    }
    let result = if t.next {
        crate::embedding_client::EmbeddingEndpoint::embed_model_over_mesh(
            state,
            &t.model,
            t.dims.unwrap_or(0),
            &crate::embedding_client::NEXT_BALANCER,
            texts,
            PUSH_EMBED_TIMEOUT,
        )
        .await
    } else {
        let ep = crate::embedding_client::EmbeddingEndpoint {
            model: t.model.clone(),
            dims: t.dims.unwrap_or(0),
            ..crate::embedding_client::resolve()
        };
        ep.embed_with_mesh(state, texts, PUSH_EMBED_TIMEOUT).await
    };
    let vectors = match result {
        Ok(v) => v,
        Err(e) => {
            fail_job(state, job_id, &format!("the gateway's embed failed: {e}")).await;
            return;
        }
    };
    let dims = match check_vectors(&vectors, texts.len(), t.dims) {
        Ok(d) => d,
        Err(why) => {
            fail_job(state, job_id, &why).await;
            return;
        }
    };
    let b64 = encode_vectors(&vectors);
    if let Err(why) = store_and_complete(state, job_id, &t.model, dims, texts.len(), &b64).await {
        fail_job(state, job_id, &why).await;
    }
}

/// Move the vectors to `noo:jobs:<id>:out`, then terminalize with the summary
/// only. A second call for a finished job is a no-op in `TERMINAL_SCRIPT`.
async fn store_and_complete(
    state: &AppState,
    job_id: &str,
    model: &str,
    dims: usize,
    n: usize,
    vectors_b64: &str,
) -> Result<(), String> {
    let Some(redis) = state.redis.as_ref() else {
        return Err("the job store (Redis) is not connected".into());
    };
    if !redis.set_string_ex(&out_key(job_id), vectors_b64, VECTORS_TTL_SECS).await {
        return Err("could not store the vectors".into());
    }
    if scheduler_engine::terminalize(state, job_id, "completed", &summary_json(model, dims, n), "").await {
        tracing::info!(job_id, n, dims, "embed_jobs.completed");
    }
    redis.del_key(&in_key(job_id)).await;
    Ok(())
}

async fn fail_job(state: &AppState, job_id: &str, reason: &str) {
    tracing::warn!(job_id, reason, "embed_jobs.failed");
    scheduler_engine::terminalize(state, job_id, "dead", "", reason).await;
    if let Some(redis) = state.redis.as_ref() {
        redis.del_key(&in_key(job_id)).await;
    }
}

// ── Events from workers ──────────────────────────────────────────────────

/// A worker's `complete`. Called from `scheduler_completions` for an
/// `embed_batch` job. A duplicate (the job is already terminal) is dropped
/// before anything is written; a result that does not check out kills the job
/// with the reason and stores nothing.
pub async fn on_complete(
    state: &AppState,
    job_id: &str,
    hash: &HashMap<String, String>,
    event: &Value,
    origin: Option<&str>,
) -> anyhow::Result<()> {
    let status = hash.get("status").map(String::as_str).unwrap_or("");
    if scheduler_engine::TERMINAL_STATES.contains(&status) {
        return Ok(());
    }
    let Some(redis) = state.redis.as_ref() else {
        return Ok(());
    };
    if hash.get("path").map(String::as_str) == Some("pull") {
        if let Some(node) = origin {
            redis.hset(&format!("{JOB_KEY_PREFIX}{job_id}"), &[("node_id", node)]).await;
        }
    }
    match check_complete(hash, event.get("result")) {
        Ok(r) => {
            if let Err(why) = store_and_complete(state, job_id, &r.model, r.dims, r.n, &r.vectors_b64).await {
                fail_job(state, job_id, &why).await;
            }
        }
        Err(why) => {
            tracing::error!(job_id, node = origin.unwrap_or(""), reason = %why, "embed_jobs.result_refused");
            let mut labels = HashMap::new();
            labels.insert("reason".to_string(), "result_refused".to_string());
            state.metrics.inc_counter("noo_embed_pull_failures_total", Some(&labels), 1).await;
            fail_job(state, job_id, &format!("result refused: {why}")).await;
        }
    }
    Ok(())
}

/// A worker's `failed`. A non-retryable one (the worker `Term`ed the message)
/// ends the job. A retryable one is left to JetStream, which redelivers: the
/// retry budget is the consumer's `max_deliver`, so the scheduler's own
/// `max_retries` requeue must not run as well.
pub async fn on_failed(
    state: &AppState,
    job_id: &str,
    hash: &HashMap<String, String>,
    event: &Value,
) -> anyhow::Result<()> {
    let status = hash.get("status").map(String::as_str).unwrap_or("");
    if scheduler_engine::TERMINAL_STATES.contains(&status)
        || hash.get("path").map(String::as_str) != Some("pull")
    {
        return Ok(());
    }
    let error = event.get("error").and_then(Value::as_str).unwrap_or("unknown error").to_string();
    let retryable = event.get("retryable").and_then(Value::as_bool).unwrap_or(true);
    if !retryable {
        scheduler_engine::terminalize(state, job_id, "dead", "", &error).await;
        if let Some(redis) = state.redis.as_ref() {
            redis.del_key(&in_key(job_id)).await;
        }
        return Ok(());
    }
    if let Some(redis) = state.redis.as_ref() {
        let detail = format!("a worker failed it; the queue will redeliver: {error}");
        redis
            .hset(
                &format!("{JOB_KEY_PREFIX}{job_id}"),
                &[("status_detail", detail.as_str()), ("error", error.as_str())],
            )
            .await;
    }
    Ok(())
}

// ── Reading the result ───────────────────────────────────────────────────

#[derive(Debug)]
pub enum VectorsError {
    /// The 15-minute side key is gone: 410.
    Expired,
    /// What is stored does not decode against the summary.
    Corrupt(String),
    /// Redis did not answer.
    Store(String),
}

impl VectorsError {
    pub fn to_response(&self, job_id: &str) -> axum::response::Response {
        use axum::response::IntoResponse;
        match self {
            VectorsError::Expired => (
                StatusCode::GONE,
                Json(json!({
                    "error": "gone",
                    "message": format!("the vectors of job {job_id} expired after {} minutes; resubmit the batch", VECTORS_TTL_SECS / 60),
                    "job_id": job_id,
                })),
            )
                .into_response(),
            VectorsError::Corrupt(why) => {
                tracing::error!(job_id, reason = %why, "embed_jobs.stored_vectors_corrupt");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "corrupt", "message": "the stored vectors could not be read", "job_id": job_id})),
                )
                    .into_response()
            }
            VectorsError::Store(why) => {
                tracing::warn!(job_id, reason = %why, "embed_jobs.vectors_read_failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "unavailable", "message": "the job store did not answer", "job_id": job_id})),
                )
                    .into_response()
            }
        }
    }
}

/// The completed job's vectors as `[[f32]]`, decoded from the side key.
pub async fn read_vectors(
    redis: &RedisCache,
    job_id: &str,
    hash: &HashMap<String, String>,
) -> Result<Vec<Vec<f32>>, VectorsError> {
    let (n, dims) = summary_shape(hash.get("result").map(String::as_str).unwrap_or(""))
        .ok_or_else(|| VectorsError::Corrupt("the job has no embed summary".into()))?;
    match redis.get_string_checked(&out_key(job_id)).await {
        Ok(Some(b64)) => decode_vectors(&b64, n, dims).map_err(VectorsError::Corrupt),
        Ok(None) => Err(VectorsError::Expired),
        Err(e) => Err(VectorsError::Store(e)),
    }
}

/// The owner recorded on a job a consumer submits: the account its key acts
/// for, else the add-on subject its exchanged token carries. The second is
/// what `GET /api/jobs/{id}` compares for that token, so the submitter can
/// also poll there.
pub fn owner_for(user: Option<&str>, consumer_name: &str) -> String {
    match user {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => format!("{}{}", crate::auth::ADDON_SUBJECT_PREFIX, consumer_name),
    }
}

pub enum StatusError {
    NotFound,
    Vectors(VectorsError),
    Store(String),
}

/// One job as its submitter sees it: `GET /api/external/embeddings/jobs/{id}`.
/// A job someone else submitted is `NotFound`, never a 403.
pub async fn status_view(
    redis: &RedisCache,
    job_id: &str,
    owner: &str,
    with_vectors: bool,
) -> Result<Value, StatusError> {
    let hash = redis
        .hgetall(&format!("{JOB_KEY_PREFIX}{job_id}"))
        .await
        .ok_or(StatusError::NotFound)?;
    if !is_embed_job(&hash) || hash.get("owner").map(String::as_str) != Some(owner) {
        return Err(StatusError::NotFound);
    }
    let get = |k: &str| hash.get(k).cloned().unwrap_or_default();
    let mut view = json!({
        "job_id": job_id,
        "status": get("status"),
        "path": get("path"),
        "model": get("model"),
        "space": get("space"),
        "n": get("n").parse::<u64>().ok(),
        "node_id": get("node_id"),
        "error": get("error"),
        "status_detail": get("status_detail"),
        "created_at": get("created_at"),
        "completed_at": get("completed_at"),
    });
    if let Some((n, dims)) = summary_shape(&get("result")) {
        view["n"] = json!(n);
        view["dims"] = json!(dims);
    }
    if with_vectors && get("status") == "completed" {
        match read_vectors(redis, job_id, &hash).await {
            Ok(v) => view["vectors"] = json!(v),
            Err(VectorsError::Store(e)) => return Err(StatusError::Store(e)),
            Err(e) => return Err(StatusError::Vectors(e)),
        }
    }
    Ok(view)
}

// ── The sweep ────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Leave,
    /// Run it in the gateway instead.
    FlipToPush(String),
    /// End it, with this reason.
    Fail(String),
}

fn ts(hash: &HashMap<String, String>, field: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let raw = hash.get(field)?.trim();
    chrono::DateTime::parse_from_rfc3339(raw).ok().map(|dt| dt.with_timezone(&chrono::Utc))
}

/// Does [`verdict`] need the consumer's numbers for this job?
pub fn needs_queue_info(hash: &HashMap<String, String>, now: chrono::DateTime<chrono::Utc>) -> bool {
    hash.get("path").map(String::as_str) == Some("pull")
        && hash.get("status").map(String::as_str) == Some("queued")
        && ts(hash, "created_at").is_some_and(|c| (now - c).num_seconds() >= PULL_WAIT_SECS)
}

/// What to do with one non-terminal embed job. Pure: `queue` is the model's
/// consumer as the probe found it (`None` = no consumer, or no answer, which
/// is treated as "nobody is pulling").
pub fn verdict(
    hash: &HashMap<String, String>,
    now: chrono::DateTime<chrono::Utc>,
    queue: Option<&QueueInfo>,
    now_unix: i64,
) -> Verdict {
    let status = hash.get("status").map(String::as_str).unwrap_or("");
    if scheduler_engine::TERMINAL_STATES.contains(&status) {
        return Verdict::Leave;
    }
    let created = ts(hash, "created_at");
    if let Some(c) = created {
        if (now - c).num_seconds() > JOB_MAX_AGE_SECS {
            return Verdict::Fail(format!("expired: not finished within {}h", JOB_MAX_AGE_SECS / 3600));
        }
    }
    let since_update = ts(hash, "updated_at")
        .or(created)
        .map(|u| (now - u).num_seconds())
        .unwrap_or(0);
    let path = hash.get("path").map(String::as_str).unwrap_or("");
    match (path, status) {
        ("pull", "queued") => {
            let age = created.map(|c| (now - c).num_seconds()).unwrap_or(0);
            if age < PULL_WAIT_SECS {
                return Verdict::Leave;
            }
            match queue {
                None => Verdict::FlipToPush(format!("queued {age}s and the work queue cannot be read")),
                Some(q) if !q.has_live_puller(now_unix) => {
                    Verdict::FlipToPush(format!("queued {age}s with no live puller"))
                }
                // Its message is gone from the consumer, so some worker took
                // it, yet no worker reported on it (a stale events grant).
                Some(q) if q.pending == 0 && q.ack_pending == 0 => {
                    Verdict::FlipToPush(format!("queued {age}s, its message is gone and no worker reported"))
                }
                Some(_) => Verdict::Leave,
            }
        }
        ("pull", "running") if since_update > PULL_RUNNING_STALE_SECS => Verdict::FlipToPush(format!(
            "no worker reported for {since_update}s (deliveries exhausted, or the worker died)"
        )),
        ("push", "running") if since_update > PUSH_STALE_SECS => Verdict::Fail(format!(
            "the gateway's run did not finish in {since_update}s (it was probably restarted)"
        )),
        _ => Verdict::Leave,
    }
}

/// One pass over the open embed jobs. Called from the scheduler's reaper
/// loop (every 30 s).
pub async fn sweep(state: &Arc<AppState>) -> anyhow::Result<()> {
    let Some(redis) = state.redis.as_ref() else {
        return Ok(());
    };
    let now = chrono::Utc::now();
    let now_unix = now.timestamp();
    let mut probes: HashMap<String, Option<QueueInfo>> = HashMap::new();
    for job_id in redis.smembers(JOBS_SET).await {
        let hash = redis
            .hgetall(&format!("{JOB_KEY_PREFIX}{job_id}"))
            .await
            .unwrap_or_default();
        let status = hash.get("status").map(String::as_str).unwrap_or("");
        if hash.is_empty() || scheduler_engine::TERMINAL_STATES.contains(&status) {
            redis.srem(JOBS_SET, &job_id).await;
            continue;
        }
        let queue = if needs_queue_info(&hash, now) {
            let sl = hash.get("slug").cloned().unwrap_or_default();
            if !probes.contains_key(&sl) {
                let found = probe_queue(&state.js, &sl).await.unwrap_or(None);
                probes.insert(sl.clone(), found);
            }
            probes.get(&sl).copied().flatten()
        } else {
            None
        };
        match verdict(&hash, now, queue.as_ref(), now_unix) {
            Verdict::Leave => {}
            Verdict::Fail(reason) => fail_job(state, &job_id, &reason).await,
            Verdict::FlipToPush(reason) => flip_to_push(state, &job_id, &hash, &reason).await,
        }
    }
    Ok(())
}

/// Push-run a pull job once. The CAS is on the `status` and `updated_at` the
/// sweep read; a worker that moved the job meanwhile wins.
async fn flip_to_push(state: &Arc<AppState>, job_id: &str, hash: &HashMap<String, String>, reason: &str) {
    let Some(redis) = state.redis.as_ref() else {
        return;
    };
    let status = hash.get("status").cloned().unwrap_or_default();
    let updated = hash.get("updated_at").cloned().unwrap_or_default();
    if !cas_flip(redis, job_id, &status, &updated, reason).await {
        return;
    }
    tracing::warn!(job_id, reason, "embed_jobs.flipped_to_push_run");
    path_counter(state, JobPath::Push).await;
    let mut labels = HashMap::new();
    labels.insert("reason".to_string(), "flipped_to_push_run".to_string());
    state.metrics.inc_counter("noo_embed_pull_failures_total", Some(&labels), 1).await;

    // Take the message off the queue if it is still there, so a late worker
    // does not repeat the work. Best effort: a duplicate `complete` is a
    // no-op, and embedding is idempotent.
    if let Some(seq) = hash.get("stream_seq").and_then(|s| s.parse::<u64>().ok()) {
        if let Ok(stream) = state.js.get_stream(STREAM).await {
            let _ = stream.delete_message(seq).await;
        }
    }
    let Some(target) = Target::from_hash(hash) else {
        fail_job(state, job_id, "the job record has no model").await;
        return;
    };
    let texts: Option<Vec<String>> = redis
        .get_string(&in_key(job_id))
        .await
        .and_then(|s| serde_json::from_str(&s).ok());
    match texts {
        Some(texts) => spawn_push_run(state.clone(), job_id.to_string(), target, texts),
        None => fail_job(state, job_id, "the batch text expired before the gateway could run it").await,
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// `noo_embed_queue_{pending,ack_pending,waiting}{model}` in Prometheus text,
/// one consumer-info call per embed model, sampled per scrape. A model whose
/// consumer cannot be read is omitted, not zeroed.
pub async fn queue_gauges(state: &AppState) -> String {
    let mut models: Vec<String> = Vec::new();
    for s in crate::embedding_spaces::all() {
        models.push(s.model.clone());
        if let Some(m) = &s.migration {
            models.push(m.next_model.clone());
        }
    }
    models.sort();
    models.dedup();
    let mut rows: Vec<(String, QueueInfo)> = Vec::new();
    for model in models {
        let sl = slug(&model);
        if let Ok(Ok(Some(q))) = tokio::time::timeout(Duration::from_secs(2), probe_queue(&state.js, &sl)).await {
            rows.push((model, q));
        }
    }
    render_queue_gauges(&rows)
}

pub fn render_queue_gauges(rows: &[(String, QueueInfo)]) -> String {
    fn family(out: &mut String, name: &str, rows: &[(String, QueueInfo)], pick: impl Fn(&QueueInfo) -> u64) {
        if rows.is_empty() {
            return;
        }
        out.push_str(&format!("# TYPE {name} gauge\n"));
        for (model, q) in rows {
            out.push_str(&format!(
                "{name}{{model=\"{}\"}} {}\n",
                crate::metrics::escape_label(model),
                pick(q)
            ));
        }
    }
    let mut out = String::new();
    family(&mut out, "noo_embed_queue_pending", rows, |q| q.pending);
    family(&mut out, "noo_embed_queue_ack_pending", rows, |q| q.ack_pending);
    family(&mut out, "noo_embed_queue_waiting", rows, |q| q.waiting);
    out
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    // ── slug: the contract's vectors, which the Go side also carries ──

    #[test]
    fn slug_matches_the_contract_vectors() {
        assert_eq!(slug("nomic-embed-text:v1.5"), "nomic-embed-text_v1_5");
        assert_eq!(slug("Harrier/1024"), "harrier_1024");
        assert_eq!(slug("bge-m3"), "bge-m3");
        assert_eq!(slug("a.b*c>d e"), "a_b_c_d_e");
    }

    #[test]
    fn slug_does_not_trim_or_collapse() {
        assert_eq!(slug("  x  "), "__x__");
        assert_eq!(slug("a::b"), "a__b");
        assert_eq!(slug(""), "");
    }

    #[test]
    fn slug_never_lowercases_outside_ascii() {
        // One `_` per non-ASCII character, whatever its case mapping.
        assert_eq!(slug("\u{130}x"), "_x");
        assert_eq!(slug("\u{212A}elvin"), "_elvin");
        assert_eq!(slug("Émbed"), "_mbed");
    }

    #[test]
    fn slug_is_one_underscore_per_character() {
        // Non-ASCII is never lowercased, so U+0130 (two characters when Go
        // lowercases it) is one `_` here and in EmbedSlug.
        assert_eq!(slug("\u{130}"), "_");
        assert_eq!(slug("é"), "_");
        assert_eq!(slug("日本"), "__");
    }

    #[test]
    fn subject_and_consumer_follow_the_slug() {
        let s = slug("Harrier/1024");
        assert_eq!(subject(&s), "work.embed.harrier_1024");
        assert_eq!(consumer_name(&s), "embed_harrier_1024");
    }

    #[test]
    fn the_consumer_config_is_the_contracts() {
        let c = consumer_config("bge-m3");
        assert_eq!(c.durable_name.as_deref(), Some("embed_bge-m3"));
        assert_eq!(c.filter_subject, "work.embed.bge-m3");
        assert!(matches!(c.ack_policy, async_nats::jetstream::consumer::AckPolicy::Explicit));
        assert_eq!(c.ack_wait, Duration::from_secs(60));
        assert_eq!(c.max_deliver, 3);
        assert_eq!(c.max_ack_pending, 256);
    }

    #[test]
    fn the_constants_match_the_node_agents_file() {
        // The node-agent's constants are the other half of the contract.
        let go = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../node-agent-go/internal/jobs/embedpull_subjects.go"),
        )
        .expect("PR A's constants file is in this tree");
        // The Go file states the stream and the consumer prefix; the subject
        // (`work.embed.<slug>`) is the stream's own `work.embed.>` filter.
        for needle in [STREAM, CONSUMER_PREFIX] {
            assert!(go.contains(&format!("\"{needle}\"")), "{needle} is not in embedpull_subjects.go");
        }
    }

    // ── caps ──

    #[test]
    fn sixty_four_texts_at_1024_dims_fit() {
        assert_eq!(cap_refusal(64, Some(1024)), None);
        assert_eq!(cap_refusal(1, Some(1024)), None);
    }

    #[test]
    fn more_than_sixty_four_texts_is_over_the_cap_and_says_so() {
        let why = cap_refusal(65, Some(1024)).expect("over the cap");
        assert!(why.contains("64"), "{why}");
        assert!(cap_refusal(65, None).is_some(), "the count cap needs no width");
    }

    #[test]
    fn a_wide_batch_is_over_the_byte_cap() {
        // 64 x 4096 x 16/3 = 1.3 MB: over, whatever the count.
        let why = cap_refusal(64, Some(4096)).expect("over the cap");
        assert!(why.contains("600 KiB"), "{why}");
        assert!(why.contains("4096"), "{why}");
    }

    #[test]
    fn the_byte_cap_is_the_contracts_formula() {
        // n * dims * 4 * 4/3 + 64 KiB <= 600 KiB, integer division as written.
        assert_eq!(result_bytes(64, 1024), 64 * 1024 * 16 / 3 + 64 * 1024);
        // At 4096 wide the limit is 25 texts: 25 x 4096 x 16/3 = 546,133 + 65,536
        // = 611,669 <= 614,400, and 26 gives 567,978 + 65,536 > 614,400.
        assert!(cap_refusal(25, Some(4096)).is_none());
        assert!(cap_refusal(26, Some(4096)).is_some());
    }

    #[test]
    fn an_unknown_width_skips_only_the_byte_cap() {
        assert_eq!(cap_refusal(64, None), None);
    }

    #[test]
    fn an_empty_batch_is_a_400_and_an_oversized_one_a_413() {
        assert!(matches!(validate_batch(0, Some(1024)), Err(SubmitError::BadRequest(_))));
        assert!(matches!(validate_batch(65, Some(1024)), Err(SubmitError::TooLarge(_))));
        assert!(validate_batch(3, Some(1024)).is_ok());
    }

    #[test]
    fn inputs_keep_their_positions() {
        let v = json!(["a", "b"]);
        assert_eq!(parse_inputs(Some(&v)), Ok(vec!["a".to_string(), "b".to_string()]));
        let one = json!("solo");
        assert_eq!(parse_inputs(Some(&one)), Ok(vec!["solo".to_string()]));
        // Dropping the middle element would shift the vector of "c".
        let bad = json!(["a", 7, "c"]);
        assert_eq!(parse_inputs(Some(&bad)), Err("input[1] is not a string".to_string()));
        assert!(parse_inputs(None).is_err());
        assert!(parse_inputs(Some(&json!(5))).is_err());
    }

    #[test]
    fn long_texts_are_cut_like_the_sync_route() {
        let long = "x".repeat(MAX_TEXT_CHARS + 50);
        let v = json!([long]);
        assert_eq!(parse_inputs(Some(&v)).unwrap()[0].chars().count(), MAX_TEXT_CHARS);
    }

    // ── base64 ──

    #[test]
    fn vectors_round_trip_through_base64() {
        let vs = vec![vec![1.0_f64, -2.5, 3.25], vec![0.0, 0.5, -0.125]];
        let b64 = encode_vectors(&vs);
        let back = decode_vectors(&b64, 2, 3).expect("decodes");
        assert_eq!(back, vec![vec![1.0_f32, -2.5, 3.25], vec![0.0, 0.5, -0.125]]);
    }

    #[test]
    fn the_bytes_are_little_endian_f32_row_major() {
        let b64 = encode_vectors(&[vec![1.0_f64, 2.0]]);
        let raw = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        let mut want = Vec::new();
        want.extend_from_slice(&1.0_f32.to_le_bytes());
        want.extend_from_slice(&2.0_f32.to_le_bytes());
        assert_eq!(raw, want);
        // Padded, standard alphabet.
        assert!(b64.len() % 4 == 0);
    }

    #[test]
    fn a_length_that_is_not_n_times_dims_times_four_is_refused() {
        let b64 = encode_vectors(&[vec![1.0_f64, 2.0, 3.0]]);
        assert!(decode_vectors(&b64, 1, 3).is_ok());
        assert!(decode_vectors(&b64, 1, 4).is_err(), "too few bytes for dims=4");
        assert!(decode_vectors(&b64, 2, 3).is_err(), "n=2 claims more than is there");
        assert!(decode_vectors(&b64, 1, 2).is_err(), "trailing bytes are not ignored");
        assert!(decode_vectors("not base64!!", 1, 3).is_err());
        assert!(decode_vectors(&b64, 0, 3).is_err());
        assert!(decode_vectors(&b64, 1, 0).is_err());
    }

    #[test]
    fn a_gateway_run_answer_must_be_rectangular_and_counted() {
        let ok = vec![vec![0.1_f64, 0.2], vec![0.3, 0.4]];
        assert_eq!(check_vectors(&ok, 2, Some(2)), Ok(2));
        assert_eq!(check_vectors(&ok, 2, None), Ok(2));
        assert!(check_vectors(&ok, 3, None).is_err());
        assert!(check_vectors(&ok, 2, Some(4)).is_err());
        assert!(check_vectors(&[vec![0.1], vec![0.1, 0.2]], 2, None).is_err());
        assert!(check_vectors(&[vec![]], 1, None).is_err());
    }

    // ── a worker's completion ──

    fn job() -> HashMap<String, String> {
        h(&[("model", "harrier"), ("n", "2"), ("dims", "3"), ("status", "running"), ("path", "pull")])
    }

    fn complete(model: &str, dims: usize, n: usize, b64: &str) -> Value {
        json!({"embed": {"v": 1, "model": model, "dims": dims, "n": n, "vectors_b64": b64}})
    }

    #[test]
    fn a_good_completion_is_accepted_whether_a_string_or_an_object() {
        let b64 = encode_vectors(&[vec![1.0_f64, 2.0, 3.0], vec![4.0, 5.0, 6.0]]);
        let body = complete("harrier", 3, 2, &b64);
        let as_string = Value::String(body.to_string());
        let r = check_complete(&job(), Some(&as_string)).expect("string result");
        assert_eq!((r.dims, r.n, r.model.as_str()), (3, 2, "harrier"));
        assert_eq!(r.vectors_b64, b64);
        assert!(check_complete(&job(), Some(&body)).is_ok());
    }

    #[test]
    fn another_models_vectors_are_refused() {
        let b64 = encode_vectors(&[vec![1.0_f64, 2.0, 3.0], vec![4.0, 5.0, 6.0]]);
        let body = Value::String(complete("nomic-embed-text", 3, 2, &b64).to_string());
        let why = check_complete(&job(), Some(&body)).unwrap_err();
        assert!(why.contains("nomic-embed-text") && why.contains("harrier"), "{why}");
        // Ollama's implicit `:latest` is the same model.
        let ok = Value::String(complete("harrier:latest", 3, 2, &b64).to_string());
        assert!(check_complete(&job(), Some(&ok)).is_ok());
    }

    #[test]
    fn a_wrong_count_width_or_length_is_refused() {
        let b64 = encode_vectors(&[vec![1.0_f64, 2.0, 3.0], vec![4.0, 5.0, 6.0]]);
        let wrong_n = Value::String(complete("harrier", 3, 1, &b64).to_string());
        assert!(check_complete(&job(), Some(&wrong_n)).is_err());
        let wrong_dims = Value::String(complete("harrier", 2, 2, &b64).to_string());
        assert!(check_complete(&job(), Some(&wrong_dims)).is_err());
        let short = encode_vectors(&[vec![1.0_f64, 2.0, 3.0]]);
        let short_body = Value::String(complete("harrier", 3, 2, &short).to_string());
        assert!(check_complete(&job(), Some(&short_body)).is_err());
    }

    #[test]
    fn an_unknown_width_takes_what_the_worker_reports() {
        let b64 = encode_vectors(&[vec![1.0_f64, 2.0], vec![3.0, 4.0]]);
        let mut j = job();
        j.insert("dims".into(), String::new());
        let body = Value::String(complete("harrier", 2, 2, &b64).to_string());
        assert_eq!(check_complete(&j, Some(&body)).unwrap().dims, 2);
    }

    #[test]
    fn a_malformed_completion_is_refused_not_guessed() {
        assert!(check_complete(&job(), None).is_err());
        assert!(check_complete(&job(), Some(&json!("not json"))).is_err());
        assert!(check_complete(&job(), Some(&json!("{}"))).is_err());
        assert!(check_complete(&job(), Some(&json!({"embed": {"v": 2}}))).is_err());
        assert!(check_complete(&job(), Some(&Value::Null)).is_err());
    }

    #[test]
    fn the_summary_carries_no_vectors() {
        let s = summary_json("harrier", 1024, 3);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v, json!({"embed": {"v": 1, "model": "harrier", "dims": 1024, "n": 3}}));
        assert_eq!(summary_shape(&s), Some((3, 1024)));
        assert_eq!(summary_shape("garbage"), None);
    }

    // ── path choice, with the consumer faked ──

    const NOW: i64 = 1_800_000_000;

    fn q(pending: u64, ack_pending: u64, waiting: u64, last: Option<i64>) -> QueueInfo {
        QueueInfo { pending, ack_pending, waiting, last_delivery_unix: last }
    }

    #[test]
    fn a_waiting_fetch_is_a_live_puller() {
        assert_eq!(decide(&Ok(Some(q(0, 0, 1, None))), NOW), Decision::Pull);
    }

    #[test]
    fn a_recent_delivery_is_a_live_puller_an_old_one_is_not() {
        assert_eq!(decide(&Ok(Some(q(0, 0, 0, Some(NOW - 29)))), NOW), Decision::Pull);
        assert_eq!(decide(&Ok(Some(q(0, 0, 0, Some(NOW - 30)))), NOW), Decision::Pull);
        assert!(matches!(decide(&Ok(Some(q(0, 0, 0, Some(NOW - 31)))), NOW), Decision::PushRun(_)));
        assert!(matches!(decide(&Ok(Some(q(0, 0, 0, None))), NOW), Decision::PushRun(_)));
    }

    #[test]
    fn no_consumer_or_no_answer_is_a_push_run_never_a_queued_job() {
        assert!(matches!(decide(&Ok(None), NOW), Decision::PushRun(_)));
        let d = decide(&Err("stream WORK_EMBED: no stream found".into()), NOW);
        match d {
            Decision::PushRun(why) => assert!(why.contains("no stream found"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_deep_queue_is_a_429_even_with_a_live_puller() {
        assert_eq!(decide(&Ok(Some(q(5001, 0, 1, None))), NOW), Decision::TooBusy { pending: 5001 });
        assert_eq!(decide(&Ok(Some(q(5000, 0, 1, None))), NOW), Decision::Pull);
    }

    #[test]
    fn a_full_stream_is_told_from_a_broken_one() {
        assert!(publish_refusal_is_full("publish failed: maximum messages exceeded"));
        assert!(publish_refusal_is_full("Maximum Bytes Exceeded"));
        assert!(!publish_refusal_is_full("no stream found for given subject"));
        assert!(!publish_refusal_is_full("timed out: didn't receive ack in time"));
    }

    // ── the sweep's verdicts ──

    fn at(secs_ago: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::seconds(secs_ago)).to_rfc3339()
    }

    fn pull_job(status: &str, created_ago: i64, updated_ago: i64) -> HashMap<String, String> {
        let mut j = h(&[("type", JOB_TYPE), ("path", "pull"), ("model", "harrier"), ("slug", "harrier"), ("n", "2")]);
        j.insert("status".into(), status.into());
        j.insert("created_at".into(), at(created_ago));
        j.insert("updated_at".into(), at(updated_ago));
        j
    }

    fn judge(j: &HashMap<String, String>, queue: Option<QueueInfo>) -> Verdict {
        verdict(j, chrono::Utc::now(), queue.as_ref(), chrono::Utc::now().timestamp())
    }

    #[test]
    fn a_fresh_queued_pull_job_is_left_alone() {
        assert_eq!(judge(&pull_job("queued", 30, 30), None), Verdict::Leave);
        assert_eq!(judge(&pull_job("queued", 119, 119), Some(q(1, 0, 0, None))), Verdict::Leave);
    }

    #[test]
    fn a_queued_pull_job_with_nobody_pulling_flips_after_120s() {
        let j = pull_job("queued", 121, 121);
        assert!(matches!(judge(&j, Some(q(3, 0, 0, None))), Verdict::FlipToPush(_)));
        assert!(matches!(judge(&j, None), Verdict::FlipToPush(_)), "an unreadable queue counts as nobody");
    }

    #[test]
    fn a_queued_pull_job_waiting_behind_a_busy_live_queue_stays() {
        let live = Some(q(40, 4, 1, None));
        assert_eq!(judge(&pull_job("queued", 600, 600), live), Verdict::Leave);
    }

    #[test]
    fn a_queued_job_whose_message_vanished_without_a_report_flips() {
        let live_but_empty = Some(q(0, 0, 1, None));
        assert!(matches!(judge(&pull_job("queued", 200, 200), live_but_empty), Verdict::FlipToPush(_)));
    }

    #[test]
    fn a_pulled_job_that_went_quiet_flips_once_deliveries_are_spent() {
        assert_eq!(judge(&pull_job("running", 100, 100), None), Verdict::Leave);
        assert!(matches!(judge(&pull_job("running", 400, 300), None), Verdict::FlipToPush(_)));
    }

    #[test]
    fn a_push_run_that_never_finished_fails_it_does_not_flip_again() {
        let mut j = pull_job("running", 900, 700);
        j.insert("path".into(), "push".into());
        assert!(matches!(judge(&j, None), Verdict::Fail(_)));
        let mut young = pull_job("running", 100, 100);
        young.insert("path".into(), "push".into());
        assert_eq!(judge(&young, None), Verdict::Leave);
    }

    #[test]
    fn nothing_outlives_the_streams_max_age() {
        let j = pull_job("queued", JOB_MAX_AGE_SECS + 10, JOB_MAX_AGE_SECS + 10);
        assert!(matches!(judge(&j, Some(q(1, 0, 1, None))), Verdict::Fail(_)));
    }

    #[test]
    fn a_terminal_job_is_left_for_the_cleanup() {
        assert_eq!(judge(&pull_job("completed", 9999, 9999), None), Verdict::Leave);
    }

    #[test]
    fn the_queue_is_read_only_for_a_queued_pull_job_past_the_wait() {
        let now = chrono::Utc::now();
        assert!(needs_queue_info(&pull_job("queued", 130, 130), now));
        assert!(!needs_queue_info(&pull_job("queued", 30, 30), now));
        assert!(!needs_queue_info(&pull_job("running", 130, 130), now));
    }

    // ── the job record ──

    #[test]
    fn the_target_is_read_back_from_the_job() {
        let j = h(&[("model", "harrier"), ("space", "knowledge@next"), ("dims", "1024")]);
        assert_eq!(
            Target::from_hash(&j),
            Some(Target { space: "knowledge@next".into(), model: "harrier".into(), dims: Some(1024), next: true })
        );
        let no_dims = h(&[("model", "m"), ("space", "code"), ("dims", "")]);
        assert_eq!(Target::from_hash(&no_dims).unwrap().dims, None);
        assert_eq!(Target::from_hash(&h(&[("space", "x")])), None);
    }

    #[test]
    fn only_embed_batch_jobs_are_ours() {
        assert!(is_embed_job(&h(&[("type", "embed_batch")])));
        assert!(!is_embed_job(&h(&[("type", "inference")])));
        assert!(!is_embed_job(&h(&[])));
    }

    #[test]
    fn the_vectors_flag_is_one_or_true() {
        assert!(wants_vectors(Some("1")));
        assert!(wants_vectors(Some("true")));
        assert!(!wants_vectors(Some("0")));
        assert!(!wants_vectors(None));
    }

    #[test]
    fn the_owner_is_the_bound_account_else_the_addon_subject() {
        assert_eq!(owner_for(Some("alice"), "svc:trellion"), "alice");
        assert_eq!(owner_for(None, "svc:trellion"), "addon:svc:trellion");
        assert_eq!(owner_for(Some(""), "svc:trellion"), "addon:svc:trellion");
    }

    // ── metrics ──

    #[test]
    fn the_gauges_render_per_model_and_omit_what_they_cannot_read() {
        assert_eq!(render_queue_gauges(&[]), "");
        let out = render_queue_gauges(&[("harrier".into(), q(7, 2, 1, None)), ("a\"b".into(), q(0, 0, 0, None))]);
        assert!(out.contains("# TYPE noo_embed_queue_pending gauge\n"), "{out}");
        assert!(out.contains("noo_embed_queue_pending{model=\"harrier\"} 7\n"), "{out}");
        assert!(out.contains("noo_embed_queue_ack_pending{model=\"harrier\"} 2\n"), "{out}");
        assert!(out.contains("noo_embed_queue_waiting{model=\"harrier\"} 1\n"), "{out}");
        assert!(out.contains("model=\"a\\\"b\""), "labels are escaped: {out}");
    }

    // ── what the scheduler must not do to these jobs ──

    #[test]
    fn the_scheduler_loops_skip_embed_jobs() {
        // Textual, like the other cross-module guards: the three requeueing
        // loops each name `is_embed_job`. Without it a stale pulled job is
        // ZADDed onto the node dispatch queue.
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/scheduler_engine.rs"),
        )
        .unwrap();
        let prod = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(
            prod.matches("crate::embed_jobs::is_embed_job").count() >= 3,
            "reap_timeouts, janitor and recover_from_restart must each skip embed jobs"
        );
    }
}
