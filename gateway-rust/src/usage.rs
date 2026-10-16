// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Token-usage accounting.
//!
//! One row per inference completion into `noo_token_usage` — node, backend,
//! model, source plane, WHO (username and/or consumer), prompt/completion
//! tokens. Two properties are non-negotiable:
//!
//!   * **Fire-and-forget.** Accounting must never affect serving: the write
//!     runs in a spawned task, and every failure ends in a `tracing::warn!`,
//!     never an error surfaced to the caller.
//!   * **Lazy partition healing.** The table is partitioned by month
//!     (048_token_usage) and there is no monthly cron: when an INSERT lands
//!     in a month with no partition, the writer calls
//!     `noo_ensure_usage_partition` for the current and next month and
//!     retries once. The migration seeds the first two months so the heal
//!     path is the exception, not the first insert's tax.
//!
//! Callers are the RESULT-CONSUMPTION sites (where a `CoordinatorResult`
//! becomes a user-visible reply) — never `cloud.rs` or the agent loop
//! itself, which would double-count a completion that both produces and
//! consumes usage.
//!
//! **Attribution** (062_usage_actor, 063_usage_user_uuid). Until 062 every
//! writer passed `user_id: None`, so "usage by user" was unanswerable by
//! construction. A row now carries an [`UsageActor`]: the canonical account
//! when a person is behind the call (JWT subject, WS session, linked channel
//! account, a bound service key, an MCP key), and/or a `consumer` label for
//! the software or credential that made it (a service key's consumer name,
//! a cluster actor such as `mcp-local`, the heartbeat). Both may be set; a
//! heartbeat run has neither person nor key and records only its consumer.
//!
//! Callers know the account by NAME (that is what a JWT subject or a
//! channel link gives them); the row stores `user_uuid`, the account's
//! stable identity (`noo_users.user_uuid`), resolved by a
//! subselect in the INSERT. A name that matches no account records NULL —
//! what a row must never do is invent a person.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use serde_json::Value;

/// Who a completion is charged to. See the module docs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsageActor {
    /// Canonical `noo_users.username`, when a person is behind the call.
    /// Resolved to `user_uuid` at insert; never stored as text.
    pub username: Option<String>,
    /// The credential or subsystem that made the call: a service key's
    /// consumer name, a cluster actor label, `heartbeat`, a channel name.
    pub consumer: Option<String>,
}

impl UsageActor {
    /// A person acting through a named path (`telegram`, `chat`, `api`…).
    pub fn user(username: impl Into<String>, via: impl Into<String>) -> Self {
        Self { username: Some(username.into()), consumer: Some(via.into()) }
    }
    /// Software or a credential with nobody behind it.
    pub fn consumer(label: impl Into<String>) -> Self {
        Self { username: None, consumer: Some(label.into()) }
    }
    /// Nothing known — recorded as such, never guessed.
    pub fn unknown() -> Self {
        Self::default()
    }
    fn normalised(mut self) -> Self {
        let clean = |s: Option<String>| s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        self.username = clean(self.username);
        self.consumer = clean(self.consumer);
        self
    }
}

/// Record one completion's token usage. Skips entirely when both counts are
/// zero (backends that report no usage frame; nothing to account).
///
/// `node_id` arrives as whatever `node_from_backend_url` extracted — for
/// LAN-IP backends that is the raw IP, so it is resolved against the
/// `cluster_nodes` registry (see [`resolve_node_id`]) before the insert.
#[allow(clippy::too_many_arguments)]
pub fn record(
    db: sqlx::PgPool,
    node_id: Option<String>,
    backend: String,
    model: String,
    source: &'static str,
    actor: UsageActor,
    prompt_tokens: u32,
    completion_tokens: u32,
) {
    spawn_record(db, node_id, backend, model, source, actor, None, prompt_tokens, completion_tokens);
}

/// The `source` of a row a task's NATIVE loop spent (i83 G): one row per
/// loop, carrying the task id.
pub const TASK_SOURCE: &str = "task";

/// One loop's tokens, as a task spent them. What [`record_task`] writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskUsage {
    /// The node that served it; `None` for a cloud model (no node did).
    pub node_id: Option<String>,
    /// The backend type: `vllm`, `llamacpp`, `cloud-anthropic`, … or
    /// `harness:<kind>` for a foreign loop.
    pub backend: String,
    pub model: String,
    /// [`TASK_SOURCE`] for a native loop, [`HARNESS_SOURCE`] for a foreign one.
    pub source: &'static str,
    /// The task's owner.
    pub username: String,
    pub harness_kind: Option<String>,
    pub task_id: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

/// Record a task loop's tokens and WAIT for the write, so the loop-boundary
/// budget check that follows sees them (`task_budget`). Still never an error
/// to the caller: a failed write is a warning, exactly as for [`record`].
pub async fn record_task(db: &sqlx::PgPool, u: &TaskUsage) {
    if u.prompt_tokens == 0 && u.completion_tokens == 0 {
        return;
    }
    let actor = UsageActor::user(u.username.clone(), if u.harness_kind.is_some() { "harness" } else { "task" }).normalised();
    let node_id = match &u.node_id {
        Some(host) => Some(resolve_node_id(db, host).await),
        None => None,
    };
    let row = Row {
        node_id: &node_id,
        backend: &u.backend,
        model: &u.model,
        source: u.source,
        actor: &actor,
        harness_kind: u.harness_kind.as_deref(),
        task_id: Some(&u.task_id),
        prompt_tokens: u.prompt_tokens,
        completion_tokens: u.completion_tokens,
    };
    write(db, &row).await;
}

/// The `source` of a row a node harness reported (the `usage` rail op).
pub const HARNESS_SOURCE: &str = "harness";

/// Record the tokens a foreign loop on a node harness used (i83 E1b), as
/// its wire translator counted them and the `usage` rail op reported them.
///
/// The row: `node_id` = the token's node, `source` = [`HARNESS_SOURCE`],
/// `backend` = `harness:<kind>` (so the monthly rollup, which has no
/// `harness_kind` column, still tells kinds apart), the person from the
/// token with consumer `harness`, and `harness_kind` = the kind (089).
pub fn record_harness(
    db: sqlx::PgPool,
    node_id: String,
    model: String,
    kind: String,
    username: String,
    prompt_tokens: u32,
    completion_tokens: u32,
) {
    spawn_record(
        db,
        Some(node_id),
        format!("harness:{kind}"),
        model,
        HARNESS_SOURCE,
        UsageActor::user(username, "harness"),
        Some(kind),
        prompt_tokens,
        completion_tokens,
    );
}

#[allow(clippy::too_many_arguments)]
fn spawn_record(
    db: sqlx::PgPool,
    node_id: Option<String>,
    backend: String,
    model: String,
    source: &'static str,
    actor: UsageActor,
    harness_kind: Option<String>,
    prompt_tokens: u32,
    completion_tokens: u32,
) {
    if prompt_tokens == 0 && completion_tokens == 0 {
        return;
    }
    let actor = actor.normalised();
    tokio::spawn(async move {
        let node_id = match node_id {
            Some(host) => Some(resolve_node_id(&db, &host).await),
            None => None,
        };
        let row = Row {
            node_id: &node_id,
            backend: &backend,
            model: &model,
            source,
            actor: &actor,
            harness_kind: harness_kind.as_deref(),
            task_id: None,
            prompt_tokens,
            completion_tokens,
        };
        write(&db, &row).await;
    });
}

/// Insert one row, healing a missing month partition once. Every failure
/// ends in a warning, never an error.
async fn write(db: &sqlx::PgPool, row: &Row<'_>) {
    match insert(db, row).await {
        Ok(()) => {}
        // The month rolled over onto a partition nobody created yet:
        // ensure current + next month, then retry the insert ONCE.
        Err(e) if e.to_string().contains("no partition of relation") => {
            for months_ahead in ["0 months", "1 month"] {
                if let Err(e2) = sqlx::query(
                    "SELECT noo_ensure_usage_partition(
                         EXTRACT(YEAR FROM now() + $1::interval)::int,
                         EXTRACT(MONTH FROM now() + $1::interval)::int)",
                )
                .bind(months_ahead)
                .execute(db)
                .await
                {
                    tracing::warn!(error = %e2, "usage_partition_ensure_failed");
                }
            }
            if let Err(e2) = insert(db, row).await {
                tracing::warn!(error = %e2, "usage_record_failed_after_heal");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "usage_record_failed");
        }
    }
}

// ─── Node vs cloud (i83 G) ───────────────────────────────────────────────
//
// A report never merges what a node served with what a cloud provider
// billed: rows fall on exactly one side, by what the writer recorded. A
// cloud completion's backend is `cloud-<provider>` (no node served it); a
// foreign loop's is `harness:<kind>` with `harness_kind` set; everything
// else a node served.

/// Which column a usage row is reported in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Side {
    /// A node's own backend served it.
    Node,
    /// A cloud provider served it (`cloud-anthropic`, `cloud-openai`, …).
    Cloud,
    /// A foreign loop on a node harness, by kind.
    Harness(String),
}

/// The one classification, from a row's own columns.
pub fn side_of(backend: &str, harness_kind: Option<&str>) -> Side {
    if let Some(k) = harness_kind.map(str::trim).filter(|k| !k.is_empty()) {
        return Side::Harness(k.to_string());
    }
    if let Some(k) = backend.strip_prefix("harness:") {
        return Side::Harness(k.to_string());
    }
    if backend.starts_with("cloud-") {
        return Side::Cloud;
    }
    Side::Node
}

/// The setting that prices models: a JSON object of model-name prefix →
/// USD per million tokens (prompt + completion), e.g.
/// `{"claude-": 6.0, "gpt-4o": 5.0}`. Reported, never enforced.
pub const COST_SETTING: &str = "NOO_MODEL_COST_USD_PER_MTOK";

/// Parse the price map; anything unreadable is no prices at all.
pub fn parse_cost_map(raw: Option<&str>) -> Vec<(String, f64)> {
    let Some(v) = raw.and_then(|r| serde_json::from_str::<Value>(r).ok()) else { return Vec::new() };
    let Some(obj) = v.as_object() else { return Vec::new() };
    obj.iter().filter_map(|(k, v)| v.as_f64().filter(|p| p.is_finite() && *p >= 0.0).map(|p| (k.clone(), p))).collect()
}

/// The price map in force (`noo_settings` → env).
pub fn cost_map() -> Vec<(String, f64)> {
    parse_cost_map(crate::settings::get(COST_SETTING).as_deref())
}

/// A model's price per million tokens: the LONGEST matching prefix wins.
pub fn usd_per_mtok(model: &str, map: &[(String, f64)]) -> Option<f64> {
    map.iter().filter(|(p, _)| model.starts_with(p.as_str())).max_by_key(|(p, _)| p.len()).map(|(_, v)| *v)
}

// ─── Streamed completions ───────────────────────────────────────────────
//
// The two streaming surfaces (`/api/inference/stream`, `/v1/chat/completions`
// with `stream: true`) proxy the backend's SSE bytes straight through, so
// there is no `CoordinatorResult` to consume. The usage frame is still on
// the wire — OpenAI-style backends send it in the LAST chunk when asked
// (`stream_options.include_usage`), ollama in its final `done` object,
// llama.cpp in its final `stop` object. `UsageTap` watches the bytes go by,
// remembers the last usage frame it can parse, and records it when the
// stream ends. It never buffers the stream and never delays a chunk.

/// Extract (prompt, completion) token counts from one backend JSON object,
/// whichever dialect it speaks. `None` when the object carries no usage.
pub fn usage_from_frame(v: &Value) -> Option<(u32, u32)> {
    let n = |x: Option<&Value>| x.and_then(Value::as_u64).map(|u| u.min(u32::MAX as u64) as u32);
    // OpenAI / vLLM: {"usage": {"prompt_tokens", "completion_tokens"}}
    if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
        if let (Some(p), Some(c)) = (n(u.get("prompt_tokens")), n(u.get("completion_tokens"))) {
            return Some((p, c));
        }
    }
    // Responses API: the `response.completed` event carries
    // {"response": {"usage": {"input_tokens", "output_tokens"}}}.
    if let Some(u) = v.pointer("/response/usage").filter(|u| u.is_object()) {
        if let (Some(p), Some(c)) = (n(u.get("input_tokens")), n(u.get("output_tokens"))) {
            return Some((p, c));
        }
    }
    // ollama: {"done": true, "prompt_eval_count", "eval_count"}
    if let (Some(p), Some(c)) = (n(v.get("prompt_eval_count")), n(v.get("eval_count"))) {
        return Some((p, c));
    }
    // llama.cpp: {"stop": true, "tokens_evaluated", "tokens_predicted"}
    if let (Some(p), Some(c)) = (n(v.get("tokens_evaluated")), n(v.get("tokens_predicted"))) {
        return Some((p, c));
    }
    None
}

/// Scan a chunk of SSE / NDJSON text for the last parseable usage frame.
/// Lines may be `data: {...}` (SSE) or bare `{...}` (ollama NDJSON).
pub fn last_usage_in_text(text: &str) -> Option<(u32, u32)> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        let payload = line.strip_prefix("data:").map(str::trim).unwrap_or(line);
        if !payload.starts_with('{') {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(payload) {
            if let Some(u) = usage_from_frame(&v) {
                found = Some(u);
            }
        }
    }
    found
}

/// Everything the record needs except the token counts, captured up front
/// so the tap owns no borrow of the request.
#[derive(Clone, Debug)]
pub struct StreamUsageCtx {
    pub db: sqlx::PgPool,
    pub node_id: Option<String>,
    pub backend: String,
    pub model: String,
    pub source: &'static str,
    pub actor: UsageActor,
}

/// Wrap a byte stream so the last usage frame seen is recorded when the
/// stream ends (or is dropped by a disconnecting client — whatever was
/// already generated was still generated). Chunks pass through untouched.
pub fn tap_stream<S, E>(inner: S, ctx: StreamUsageCtx) -> impl futures::Stream<Item = Result<Bytes, E>>
where
    S: futures::Stream<Item = Result<Bytes, E>>,
{
    use futures::StreamExt as _;
    let tap = UsageTap { ctx, scanner: FrameScanner::default() };
    inner.scan(tap, |tap, item| {
        if let Ok(chunk) = &item {
            tap.scanner.observe(chunk);
        }
        futures::future::ready(Some(item))
    })
}

/// The parsing half of the tap, with no database in it so it can be tested
/// on bytes alone.
#[derive(Default)]
struct FrameScanner {
    /// A frame can be split across chunks; keep the unterminated tail.
    carry: String,
    last: Option<(u32, u32)>,
}

impl FrameScanner {
    fn observe(&mut self, chunk: &[u8]) {
        self.carry.push_str(&String::from_utf8_lossy(chunk));
        // Scan complete lines; keep the trailing partial one for next time.
        let complete_upto = self.carry.rfind('\n').map(|i| i + 1).unwrap_or(0);
        if complete_upto > 0 {
            if let Some(u) = last_usage_in_text(&self.carry[..complete_upto]) {
                self.last = Some(u);
            }
            self.carry.drain(..complete_upto);
        }
        // Bound the carry: a usage frame is small, a runaway line is not ours.
        if self.carry.len() > 64 * 1024 {
            self.carry.clear();
        }
    }

    /// The final line often has no trailing newline.
    fn finish(&mut self) -> Option<(u32, u32)> {
        if let Some(u) = last_usage_in_text(&self.carry) {
            self.last = Some(u);
        }
        self.carry.clear();
        self.last.take()
    }
}

struct UsageTap {
    ctx: StreamUsageCtx,
    scanner: FrameScanner,
}

impl Drop for UsageTap {
    fn drop(&mut self) {
        if let Some((p, c)) = self.scanner.finish() {
            record(
                self.ctx.db.clone(),
                self.ctx.node_id.clone(),
                self.ctx.backend.clone(),
                self.ctx.model.clone(),
                self.ctx.source,
                self.ctx.actor.clone(),
                p,
                c,
            );
        }
    }
}

// ─── Node attribution (IP → node name) ──────────────────────────────────
//
// `node_from_backend_url` hands us the HOST of the backend URL. For remote
// backends that is usually the node's LAN IP, so usage rows said
// `192.0.2.124` where the operator expects `host8`. The registry the
// gateway already holds (`cluster_nodes`: node_id, ip_address, hostname)
// answers the mapping; snapshot it with the same in-process 60s-TTL cache
// idiom as `service_keys::resolve` so accounting stays a non-event on the
// serving path. An unresolvable host is kept verbatim — attribution may be
// ugly, but it is never dropped.

struct NodeCache {
    /// ip_address | hostname | node_id → node_id.
    map: HashMap<String, String>,
    loaded: Instant,
}

static NODE_CACHE: OnceLock<RwLock<Option<NodeCache>>> = OnceLock::new();
const NODE_TTL: Duration = Duration::from_secs(60);

fn node_cache() -> &'static RwLock<Option<NodeCache>> {
    NODE_CACHE.get_or_init(|| RwLock::new(None))
}

/// The pure mapping half: a host against a registry snapshot. Hits resolve
/// to the node_id; misses (unregistered hosts, cloud endpoints, the
/// "controller" label) come back unchanged.
fn map_host_to_node(map: &HashMap<String, String>, host: &str) -> String {
    map.get(host).cloned().unwrap_or_else(|| host.to_string())
}

/// Resolve a backend host to its registered node_id, refreshing the
/// snapshot from `cluster_nodes` at most once per [`NODE_TTL`]. A failed
/// refresh is not cached: this attempt keeps the raw host and the next
/// record retries the query.
async fn resolve_node_id(db: &sqlx::PgPool, host: &str) -> String {
    if let Ok(guard) = node_cache().read() {
        if let Some(c) = guard.as_ref() {
            if c.loaded.elapsed() < NODE_TTL {
                return map_host_to_node(&c.map, host);
            }
        }
    }

    let rows = match crate::repo::cluster::all_nodes(db).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "usage_node_resolve_query_failed");
            return host.to_string();
        }
    };
    let mut map = HashMap::new();
    for (node_id, ip_address, hostname) in rows {
        // NOT NULL columns, but blank is possible — a blank key would soak
        // up empty hosts that should stay unresolved.
        if !ip_address.is_empty() {
            map.insert(ip_address, node_id.clone());
        }
        if !hostname.is_empty() {
            map.insert(hostname, node_id.clone());
        }
        // node_id keys itself so an already-resolved id is a no-op.
        map.insert(node_id.clone(), node_id);
    }

    let resolved = map_host_to_node(&map, host);
    if let Ok(mut guard) = node_cache().write() {
        *guard = Some(NodeCache { map, loaded: Instant::now() });
    }
    resolved
}

/// One row's columns, borrowed for the insert and its one retry.
struct Row<'a> {
    node_id: &'a Option<String>,
    backend: &'a str,
    model: &'a str,
    source: &'a str,
    actor: &'a UsageActor,
    /// The harness kind, for a row a node harness reported (089); NULL
    /// for every other writer.
    harness_kind: Option<&'a str>,
    /// The task the tokens were spent on (091); NULL outside a task.
    task_id: Option<&'a str>,
    prompt_tokens: u32,
    completion_tokens: u32,
}

/// The INSERT itself. Runtime API, not the `query!` macro — sqlx-drift only
/// prepares macro queries, and this table postdates the offline cache.
async fn insert(db: &sqlx::PgPool, row: &Row<'_>) -> Result<(), sqlx::Error> {
    // The name → uuid resolution happens IN the insert: one round trip, no
    // cache to go stale on a rename, and a name with no account yields NULL
    // rather than a made-up identity.
    sqlx::query(
        "INSERT INTO noo_token_usage
             (node_id, backend, model, source, user_uuid, consumer,
              prompt_tokens, completion_tokens, harness_kind, task_id)
         VALUES ($1, $2, $3, $4,
                 (SELECT u.user_uuid FROM noo_users u WHERE u.username = $5),
                 $6, $7, $8, $9, $10)",
    )
    .bind(row.node_id.as_deref())
    .bind(row.backend)
    .bind(row.model)
    .bind(row.source)
    .bind(row.actor.username.as_deref())
    .bind(row.actor.consumer.as_deref())
    .bind(row.prompt_tokens as i32)
    .bind(row.completion_tokens as i32)
    .bind(row.harness_kind)
    .bind(row.task_id)
    .execute(db)
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn registry() -> HashMap<String, String> {
        let mut m = HashMap::new();
        for k in ["192.0.2.124", "host8", "host8-node"] {
            m.insert(k.to_string(), "host8-node".to_string());
        }
        m
    }

    /// The live symptom: usage rows attributed to `192.0.2.124` instead of
    /// the node name. IP, hostname and node_id all resolve to the node_id.
    #[test]
    fn registered_hosts_resolve_to_the_node_id() {
        let m = registry();
        assert_eq!(map_host_to_node(&m, "192.0.2.124"), "host8-node");
        assert_eq!(map_host_to_node(&m, "host8"), "host8-node");
        // Already a node_id → no-op.
        assert_eq!(map_host_to_node(&m, "host8-node"), "host8-node");
    }

    /// Unresolvable hosts keep the raw value — never drop attribution just
    /// because the registry hasn't caught up (or the backend is a cloud
    /// endpoint / the controller's own label).
    #[test]
    fn unresolvable_hosts_are_kept_verbatim() {
        let m = registry();
        assert_eq!(map_host_to_node(&m, "10.0.0.99"), "10.0.0.99");
        assert_eq!(map_host_to_node(&m, "controller"), "controller");
        assert_eq!(map_host_to_node(&HashMap::new(), "host9"), "host9");
    }

    /// PINNED (i83 G): cloud rows, harness rows and node rows fall on
    /// exactly one side each.
    #[test]
    fn rows_fall_on_exactly_one_side() {
        assert_eq!(side_of("cloud-anthropic", None), Side::Cloud);
        assert_eq!(side_of("cloud-openai", None), Side::Cloud);
        assert_eq!(side_of("cloud-gemini", None), Side::Cloud);
        assert_eq!(side_of("harness:copilot", Some("copilot")), Side::Harness("copilot".into()));
        assert_eq!(side_of("harness:claude-code", None), Side::Harness("claude-code".into()));
        assert_eq!(side_of("vllm", None), Side::Node);
        assert_eq!(side_of("llamacpp", Some("")), Side::Node);
        assert_eq!(side_of("ollama", None), Side::Node);
    }

    #[test]
    fn prices_match_the_longest_prefix_and_ignore_junk() {
        let map = parse_cost_map(Some(r#"{"claude-": 6.0, "claude-opus": 30, "gpt-4o": 5, "bad": "x", "neg": -1}"#));
        assert_eq!(usd_per_mtok("claude-opus-5", &map), Some(30.0));
        assert_eq!(usd_per_mtok("claude-sonnet-5", &map), Some(6.0));
        assert_eq!(usd_per_mtok("gemma-4", &map), None);
        assert_eq!(usd_per_mtok("bad", &map), None);
        assert!(parse_cost_map(Some("not json")).is_empty());
        assert!(parse_cost_map(None).is_empty());
    }

    #[test]
    fn actor_blank_strings_become_none() {
        let a = UsageActor { username: Some("  ".into()), consumer: Some("".into()) }.normalised();
        assert_eq!(a, UsageActor::unknown());
        let a = UsageActor::user(" alice ", "api").normalised();
        assert_eq!(a.username.as_deref(), Some("alice"));
        assert_eq!(a.consumer.as_deref(), Some("api"));
    }

    #[test]
    fn usage_frames_parse_in_all_three_dialects() {
        assert_eq!(
            usage_from_frame(&json!({"usage": {"prompt_tokens": 12, "completion_tokens": 30, "total_tokens": 42}})),
            Some((12, 30))
        );
        assert_eq!(
            usage_from_frame(&json!({"done": true, "prompt_eval_count": 7, "eval_count": 9})),
            Some((7, 9))
        );
        assert_eq!(
            usage_from_frame(&json!({"stop": true, "tokens_evaluated": 3, "tokens_predicted": 4})),
            Some((3, 4))
        );
        // A content chunk with no usage — the common case — is not a frame.
        assert_eq!(
            usage_from_frame(&json!({"type": "response.completed", "response": {"usage": {"input_tokens": 5, "output_tokens": 2}}})),
            Some((5, 2)),
            "Responses API completed event"
        );
        assert_eq!(usage_from_frame(&json!({"choices": [{"delta": {"content": "hi"}}]})), None);
        // OpenAI streams send `usage: null` on every chunk but the last.
        assert_eq!(usage_from_frame(&json!({"choices": [], "usage": null})), None);
    }

    #[test]
    fn the_last_usage_frame_in_an_sse_body_wins() {
        let body = "data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}],\"usage\":null}\n\n\
                    data: {\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1}}\n\n\
                    data: [DONE]\n\n";
        assert_eq!(last_usage_in_text(body), Some((5, 1)));
        // ollama NDJSON, no `data:` prefix.
        let nd = "{\"message\":{\"content\":\"x\"},\"done\":false}\n{\"done\":true,\"prompt_eval_count\":2,\"eval_count\":8}\n";
        assert_eq!(last_usage_in_text(nd), Some((2, 8)));
        assert_eq!(last_usage_in_text("data: [DONE]\n"), None);
    }

    /// A frame split across two chunks must still be seen once whole.
    #[test]
    fn scanner_reassembles_split_frames() {
        let mut sc = FrameScanner::default();
        sc.observe(b"data: {\"usage\":{\"prompt_tok");
        assert_eq!(sc.last, None, "half a frame is not a frame");
        sc.observe(b"ens\":11,\"completion_tokens\":22}}\n\ndata: [DONE]\n");
        assert_eq!(sc.last, Some((11, 22)));
        assert_eq!(sc.finish(), Some((11, 22)));
        // An unterminated final frame is still read at finish.
        let mut sc = FrameScanner::default();
        sc.observe(b"{\"done\":true,\"prompt_eval_count\":1,\"eval_count\":2}");
        assert_eq!(sc.last, None);
        assert_eq!(sc.finish(), Some((1, 2)));
    }
}
