// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The context a chat model runs at on an Ollama, decided once (i802).
//!
//! Until 0.6.25 nothing sent Ollama a chat context, so the daemon ran its
//! default: 4,096 tokens on any box under 23 GiB of VRAM, every CPU box
//! included, whatever the tier profile (16,384) or the placement
//! (`OLLAMA_CONTEXT_LENGTH`) declared. A coordinator turn is larger than that,
//! so Ollama cut it to its last ~2,046 tokens and the model answered without
//! its instructions (fa, run 43621289858).
//!
//! [`decide`] is the ONE rule: the placement's own `OLLAMA_CONTEXT_LENGTH`,
//! else the node's tier profile context, capped by the model's ceiling
//! ([`crate::harness_fit::chat_window`]), then capped by memory ([`fit_cap`]).
//! Every Ollama-bound chat body carries the result as `options.num_ctx`
//! ([`stamp`]), set only when the caller did not set one. A different
//! `num_ctx` reloads the model (~4-7 s, fa run 43621289858), so the decided
//! value is sticky ([`Sticky`]): it changes when the declaration changes, and
//! on memory only past a margin.

use serde_json::Value;

/// The contexts tried below the declared one, largest first.
pub const STEPS: [u64; 3] = [16384, 8192, 4096];
/// The floor: Ollama's own default on a small box. Nothing is decided below it.
pub const FLOOR: u64 = 4096;
/// Memory kept free for everything else: at least 1 GiB, or 10% of RAM.
pub const HEADROOM_MIN_GIB: f64 = 1.0;
pub const HEADROOM_FRACTION: f64 = 0.10;
/// The slots an Ollama allots a model when its placement does not say:
/// the stack's compose default (`OLLAMA_EMBED_NUM_PARALLEL:-4`). Ollama sizes
/// the cache for every slot.
pub const DEFAULT_SLOTS: u64 = 4;
/// A larger context is taken only when it fits with this much to spare, so a
/// node near the line does not flip between two values (each flip reloads).
pub const RAISE_MARGIN: f64 = 0.8;

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// What the fit reads from the node, all of it reported.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FitInputs {
    /// Total RAM (the CPU pool), GiB.
    pub ram_gib: f64,
    /// RAM in use now, GiB (it includes this model's cache at `running`).
    pub used_gib: f64,
    /// Cache bytes per token per slot, and whether that was measured.
    pub kv_bytes_per_token: f64,
    pub kv_measured: bool,
    pub slots: u64,
    /// The context the daemon runs the model at now, when loaded.
    pub running: Option<u64>,
}

/// The fit's verdict, with every number for `noo cluster show`.
#[derive(Debug, Clone, PartialEq)]
pub struct Fit {
    pub tokens: u64,
    /// `None` when the declared context fit; else why it was capped.
    pub capped: Option<String>,
}

fn need_gib(ctx: u64, f: &FitInputs) -> f64 {
    ctx as f64 * f.slots as f64 * f.kv_bytes_per_token / GIB
}

/// The memory available to this model's cache: free RAM, plus what its cache
/// holds now (that is counted in `used`), minus the headroom.
pub fn kv_room_gib(f: &FitInputs) -> f64 {
    let headroom = (f.ram_gib * HEADROOM_FRACTION).max(HEADROOM_MIN_GIB);
    let held = f.running.map(|r| need_gib(r, f)).unwrap_or(0.0);
    (f.ram_gib - f.used_gib + held - headroom).max(0.0)
}

/// The largest of `declared` and [`STEPS`] (never above `declared`) whose
/// cache fits [`kv_room_gib`], never below [`FLOOR`].
pub fn fit_cap(declared: u64, f: &FitInputs) -> Fit {
    let room = kv_room_gib(f);
    let mut tries: Vec<u64> = std::iter::once(declared).chain(STEPS.iter().copied().filter(|s| *s < declared)).collect();
    tries.dedup();
    for ctx in &tries {
        if need_gib(*ctx, f) <= room {
            let capped = (*ctx < declared).then(|| capped_line(declared, f, room));
            return Fit { tokens: (*ctx).max(FLOOR), capped };
        }
    }
    Fit { tokens: FLOOR.min(declared.max(FLOOR)), capped: Some(capped_line(declared, f, room)) }
}

fn capped_line(declared: u64, f: &FitInputs, room: f64) -> String {
    format!(
        "{declared} needs {:.1} GiB of cache at {} slot(s) x {:.1} KiB/token{}, {:.1} GiB is free after the headroom",
        need_gib(declared, f),
        f.slots,
        f.kv_bytes_per_token / 1024.0,
        if f.kv_measured { "" } else { " (an overestimate: this model's cache was never measured)" },
        room
    )
}

/// The cache per token per slot for `model`: measured (config/model-capabilities.json
/// `kv_bytes_per_token`), else placement_fit's conservative fallback from the
/// weights' size.
pub fn kv_per_token(model: &str, weights_bytes: Option<u64>) -> (f64, bool) {
    if let Some(b) = crate::model_capabilities::lookup(model).and_then(|r| r.kv_bytes_per_token).filter(|b| *b > 0) {
        return (b as f64, true);
    }
    let gb = weights_bytes.map(|b| b as f64 / 1e9).unwrap_or(0.0);
    (crate::placement_fit::kv_bytes_per_token(gb), false)
}

/// One model's entry in the node's heartbeat `model_stats`.
fn model_stat<'a>(node: &'a Value, model: &str) -> Option<&'a Value> {
    let latest = |n: &str| if n.contains(':') { n.to_string() } else { format!("{n}:latest") };
    let want = latest(model.trim());
    node.get("model_stats")?.as_array()?.iter().find(|s| s.get("name").and_then(Value::as_str).is_some_and(|n| latest(n.trim()) == want))
}

/// What the daemon runs `model` at now (`model_stats[].running_context`,
/// i802), when the node reports it.
pub fn running_context(node: &Value, model: &str) -> Option<u64> {
    model_stat(node, model)?.get("running_context")?.as_u64().filter(|n| *n > 0)
}

fn slots(env: &Value) -> u64 {
    let n = match env.get("OLLAMA_NUM_PARALLEL") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    };
    n.filter(|n| *n > 0).unwrap_or(DEFAULT_SLOTS)
}

fn gib(v: &Value) -> Option<f64> {
    v.as_f64().filter(|n| *n > 0.0)
}

/// The node's fit inputs for `model` on an Ollama placement with `env`.
pub fn fit_inputs(node: &Value, env: &Value, model: &str) -> FitInputs {
    let caps = node.get("capabilities").cloned().unwrap_or(Value::Null);
    let ram = gib(&node["ram_gb"]).or_else(|| gib(&caps["ram_gb"])).unwrap_or(0.0);
    let used = gib(&node["mem_used_gb"]).unwrap_or(ram);
    let weights = model_stat(node, model).and_then(|s| s.get("size_bytes")?.as_u64());
    let (kv, measured) = kv_per_token(model, weights);
    FitInputs { ram_gib: ram, used_gib: used, kv_bytes_per_token: kv, kv_measured: measured, slots: slots(env), running: running_context(node, model) }
}

/// The slots the stack's own Ollama runs with, from noomesh.yaml
/// `compose_env.OLLAMA_EMBED_NUM_PARALLEL` (the variable compose reads for
/// `ollama-embed`); `None` when unset, which is compose's default (4).
pub fn compose_slots(config: &Value) -> Option<u64> {
    match config.get("compose_env")?.get("OLLAMA_EMBED_NUM_PARALLEL")? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
    .filter(|n| *n > 0)
}

/// The env the fit reads for an Ollama placement. On the controller's own
/// node the chat model runs in the stack's compose Ollama, whose slot count
/// is the stack's compose_env, not the placement: the fit then counts the
/// slots that are (or, after this change, will be) in force there. A
/// placement that sets OLLAMA_NUM_PARALLEL itself is left as it is.
pub fn with_stack_slots(env: &Value, is_self: bool, stack_slots: Option<u64>) -> Value {
    let mut env = env.clone();
    if is_self && env.get("OLLAMA_NUM_PARALLEL").is_none() {
        if let Some(obj) = env.as_object_mut() {
            obj.insert("OLLAMA_NUM_PARALLEL".into(), Value::from(stack_slots.unwrap_or(DEFAULT_SLOTS).to_string()));
        } else {
            env = serde_json::json!({"OLLAMA_NUM_PARALLEL": stack_slots.unwrap_or(DEFAULT_SLOTS).to_string()});
        }
    }
    env
}

/// Whether `node_id` is the controller's own node (its Ollama is the stack's).
pub fn is_self_node(node_id: &str) -> bool {
    crate::self_node::self_node_id().as_deref() == Some(node_id)
}

/// The decided context and everything the operator needs to read it.
#[derive(Debug, Clone, PartialEq)]
pub struct Decided {
    pub tokens: u64,
    /// What the placement or profile asked for, capped by the model's ceiling.
    pub declared: u64,
    pub source: String,
    pub capped: Option<String>,
    pub slots: u64,
}

/// THE rule (i802). `None` for a backend other than Ollama, or when nothing
/// declares a context for it: then nothing is stamped and the daemon keeps
/// its own setting, as before.
pub fn decide(backend: &str, env: &Value, model: &str, node: &Value, profile_context: u64) -> Option<Decided> {
    if backend != "ollama" {
        return None;
    }
    // chat_window falls back to the model's ceiling when nothing declares a
    // context; that is not a declaration (a 131k ceiling is not a setting).
    let placement_sets = env.get("OLLAMA_CONTEXT_LENGTH").is_some_and(|v| match v {
        Value::Number(n) => n.as_u64().is_some_and(|n| n > 0),
        Value::String(s) => s.trim().parse::<u64>().is_ok_and(|n| n > 0),
        _ => false,
    });
    if !placement_sets && profile_context == 0 {
        return None;
    }
    let w = crate::harness_fit::chat_window(backend, env, Some(model), node, profile_context)?;
    let f = fit_inputs(node, env, model);
    let fit = held_at_running(fit_cap(w.tokens, &f), w.tokens, f.running);
    Some(Decided { tokens: fit.tokens, declared: w.tokens, source: w.source, capped: fit.capped, slots: f.slots })
}

/// Never decide below what the daemon already runs the model at (when that
/// is within the declaration): the box holds it today, and an unmeasured
/// model's conservative cache figure must not shrink a working context on
/// the roll (mcmini runs gemma4:12b at its tier's 32768 from the plist).
pub fn held_at_running(fit: Fit, declared: u64, running: Option<u64>) -> Fit {
    match running.filter(|r| *r > fit.tokens && *r <= declared) {
        Some(r) => Fit { tokens: r, capped: Some(format!("kept at the {r} it already runs (the fit alone said {}: {})", fit.tokens, fit.capped.unwrap_or_default())) },
        None => fit,
    }
}

/// Holds a decided value against the memory reading's noise: a smaller
/// value is taken at once (it no longer fits), a larger one only when it
/// fits with [`RAISE_MARGIN`] to spare. A changed declaration is always
/// taken. Each change reloads the model, so it must be rare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sticky {
    pub tokens: u64,
    pub declared: u64,
}

impl Sticky {
    pub fn next(prev: Option<Sticky>, d: &Decided, f: &FitInputs) -> Sticky {
        let now = Sticky { tokens: d.tokens, declared: d.declared };
        match prev {
            Some(p) if p.declared == d.declared && d.tokens > p.tokens => {
                let room = kv_room_gib(f);
                if need_gib(d.tokens, f) <= room * RAISE_MARGIN {
                    now
                } else {
                    p
                }
            }
            _ => now,
        }
    }
}

/// Set `options.num_ctx` on an Ollama-bound chat body when the caller did
/// not set one. A caller's own value stands, as it always has where it
/// reached Ollama.
pub fn stamp(body: &mut Value, num_ctx: u64) {
    let Some(obj) = body.as_object_mut() else { return };
    let options = obj.entry("options").or_insert_with(|| Value::Object(Default::default()));
    if let Some(o) = options.as_object_mut() {
        o.entry("num_ctx").or_insert(Value::from(num_ctx));
    }
}

/// [`stamp`] when there is a value to stamp.
pub fn stamp_opt(body: &mut Value, num_ctx: Option<u64>) {
    if let Some(n) = num_ctx {
        stamp(body, n);
    }
}

// ── the resolver every chat path asks ──────────────────────────────────────
//
// One async read per (node, model), held for [`RECHECK_SECS`]: the node's
// heartbeat record (`mesh_nodes`), its running Ollama chat placement, and its
// harness profile, read as `routes::cluster::harness_kind_fit` reads them. A
// request path pays at most one KV + DB read per key per ten minutes, and a
// chat never fails because of it.

/// How long a decided context is used before the node is read again.
pub const RECHECK_SECS: u64 = 600;
/// After a read that left nothing to use (it failed with nothing held, or
/// the backend's URL named no node), read again this soon rather than run
/// [`RECHECK_SECS`] with nothing stamped.
pub const RETRY_SECS: u64 = 60;

/// Whether a backend's chat bodies take `options.num_ctx` at all. vLLM,
/// llama.cpp and the cloud providers never get `options`.
pub fn takes_num_ctx(backend_type: &str) -> bool {
    backend_type == "ollama"
}

/// What one (node, model) holds between reads.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Held {
    sticky: Option<Sticky>,
    at: std::time::Instant,
    /// The last read failed (and was logged once).
    failed: bool,
}

/// What a read of the node found.
#[derive(Debug, Clone, PartialEq)]
enum Read {
    Decided(Decided, FitInputs),
    /// No node record, or nothing declares a context: nothing is stamped.
    Nothing,
    Failed(String),
}

type HeldMap = std::collections::HashMap<(String, String), Held>;
static HELD: std::sync::LazyLock<std::sync::Mutex<HeldMap>> = std::sync::LazyLock::new(Default::default);
type UrlMap = std::collections::HashMap<String, (Option<String>, std::time::Instant)>;
static NODE_OF_URL: std::sync::LazyLock<std::sync::Mutex<UrlMap>> = std::sync::LazyLock::new(Default::default);

fn held() -> std::sync::MutexGuard<'static, HeldMap> {
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

fn urls() -> std::sync::MutexGuard<'static, UrlMap> {
    NODE_OF_URL.lock().unwrap_or_else(|e| e.into_inner())
}

/// A held value is used without a read while it is younger than its window:
/// [`RETRY_SECS`] when a failed read left nothing, else [`RECHECK_SECS`].
fn fresh(h: &Held, now: std::time::Instant) -> bool {
    let window = if h.failed && h.sticky.is_none() { RETRY_SECS } else { RECHECK_SECS };
    now.saturating_duration_since(h.at) < std::time::Duration::from_secs(window)
}

/// What a read changes: a decision moves the sticky value ([`Sticky::next`]),
/// nothing declared clears it, a failure keeps what was held.
fn after_read(prev: Option<Held>, read: &Read, now: std::time::Instant) -> Held {
    let prev_sticky = prev.and_then(|h| h.sticky);
    match read {
        Read::Decided(d, f) => Held { sticky: Some(Sticky::next(prev_sticky, d, f)), at: now, failed: false },
        Read::Nothing => Held { sticky: None, at: now, failed: false },
        Read::Failed(_) => Held { sticky: prev_sticky, at: now, failed: true },
    }
}

fn same_model(a: &str, b: &str) -> bool {
    let latest = |n: &str| if n.contains(':') { n.trim().to_string() } else { format!("{}:latest", n.trim()) };
    latest(a) == latest(b)
}

/// The env of the running Ollama chat placement that serves `model`: the one
/// naming it, else the node's first running Ollama chat placement (the
/// daemon's env is the daemon's, whatever model it loads), else none.
pub(crate) fn chat_env(placements: &[crate::routes::cluster::StoredPlacement], model: &str) -> Value {
    let chats: Vec<&crate::routes::cluster::StoredPlacement> =
        placements.iter().filter(|p| p.backend == "ollama" && p.role == "chat" && p.desired_state == "running").collect();
    chats
        .iter()
        .find(|p| p.model.as_deref().is_some_and(|m| same_model(m, model)))
        .or_else(|| chats.first())
        .map(|p| p.env.clone())
        .unwrap_or_else(|| Value::Object(Default::default()))
}

/// Read the node as `harness_kind_fit` does, and decide.
async fn read_node(state: &crate::state::AppState, node_id: &str, model: &str) -> Read {
    let kv = match state.js.get_key_value("mesh_nodes").await {
        Ok(kv) => kv,
        Err(e) => return Read::Failed(format!("mesh_nodes: {e}")),
    };
    let record: Value = match kv.get(node_id).await {
        Ok(Some(e)) => match serde_json::from_slice::<Value>(&e) {
            Ok(v) => v,
            Err(e) => return Read::Failed(format!("node record: {e}")),
        },
        // No record: nothing reports this node, so nothing declares a context.
        Ok(None) => return Read::Nothing,
        Err(e) => return Read::Failed(format!("node record: {e}")),
    };
    let placements = match crate::routes::cluster::stored_placements(state, node_id).await {
        Ok(p) => p,
        Err(e) => return Read::Failed(format!("placements: {e}")),
    };
    let stack_slots = compose_slots(&*state.config_yaml.read().await);
    let env = with_stack_slots(&chat_env(&placements, model), is_self_node(node_id), stack_slots);
    let tier = crate::node_tier::derive(&crate::node_tier::facts_from_capabilities(record.get("capabilities").unwrap_or(&serde_json::json!({}))))
        .tier()
        .and_then(|t| u8::try_from(t).ok());
    let overrides = match crate::repo::cluster::node_harness_profile_overrides(&state.db, node_id).await {
        Ok(o) => o,
        Err(e) => return Read::Failed(format!("harness profile: {e}")),
    };
    let profile = crate::harness_profile::resolve(tier, &overrides, None, None);
    match decide("ollama", &env, model, &record, profile.context) {
        Some(d) => {
            let f = fit_inputs(&record, &env, model);
            Read::Decided(d, f)
        }
        None => Read::Nothing,
    }
}

/// The `num_ctx` to stamp on a chat body for `model` on `node_id`'s
/// `backend_type`: `None` for any backend but Ollama, when nothing declares
/// a context, or when the node cannot be read and nothing is held.
pub async fn num_ctx_for_node(state: &crate::state::AppState, node_id: &str, backend_type: &str, model: &str) -> Option<u64> {
    if !takes_num_ctx(backend_type) || node_id.is_empty() || model.trim().is_empty() {
        return None;
    }
    let key = (node_id.to_string(), model.trim().to_string());
    let now = std::time::Instant::now();
    let prev = held().get(&key).copied();
    if let Some(h) = prev.filter(|h| fresh(h, now)) {
        return h.sticky.map(|s| s.tokens);
    }
    let read = read_node(state, node_id, model.trim()).await;
    if let Read::Failed(why) = &read {
        if !prev.is_some_and(|h| h.failed) {
            tracing::debug!(node = node_id, model, error = %why, "chat_context: cannot read the node; the held context stands");
        }
    }
    let next = after_read(prev, &read, now);
    held().insert(key, next);
    next.sticky.map(|s| s.tokens)
}

/// The node a backend URL belongs to, mapped as dispatch maps one
/// (`coordinator::resolve_node_id`), held like the decision.
async fn node_of_url(state: &crate::state::AppState, url: &str) -> Option<String> {
    let now = std::time::Instant::now();
    let prev = urls().get(url).cloned();
    if let Some((node, at)) = prev {
        let window = if node.is_some() { RECHECK_SECS } else { RETRY_SECS };
        if now.saturating_duration_since(at) < std::time::Duration::from_secs(window) {
            return node;
        }
    }
    let node = match crate::coordinator::node_from_backend_url(url) {
        Some(host) => crate::coordinator::resolve_node_id(state, &host).await.ok(),
        None => None,
    };
    urls().insert(url.to_string(), (node.clone(), now));
    node
}

/// [`num_ctx_for_node`] for a backend known only by its URL. An Ollama whose
/// URL names no enrolled node (an agent-less static `OLLAMA_URL`) gets
/// `None`: nothing declares a context there (a known gap).
pub async fn num_ctx_for(state: &crate::state::AppState, backend_type: &str, backend_url: &str, model: &str) -> Option<u64> {
    if !takes_num_ctx(backend_type) {
        return None;
    }
    let node = node_of_url(state, backend_url).await?;
    num_ctx_for_node(state, &node, backend_type, model).await
}

// ── the window a loop fits a turn to (i802 PR-2) ───────────────────────────
//
// The coordinator loop fitted every turn to one global number
// (`VLLM_MAX_MODEL_LEN` less the output reserve, 12,288 by default) whatever
// the backend ran at; a 4,096-token Ollama then cut the prompt. The window
// is now the backend's own: the `num_ctx` an Ollama call is stamped with,
// else the vLLM / llama.cpp placement's engine window ([`window_for`]), else
// the old global value.

/// The most a turn keeps back for the answer.
pub const RESERVE_MAX: u64 = 4096;

/// The tokens kept for the answer in a `ctx`-token window: a quarter of it,
/// at most [`RESERVE_MAX`].
pub fn reserve_for(ctx: u64) -> u64 {
    (ctx / 4).min(RESERVE_MAX)
}

/// The prompt budget in a `ctx`-token window: what the reserve leaves.
pub fn max_input_for(ctx: u64) -> u64 {
    ctx.saturating_sub(reserve_for(ctx))
}

/// Whether [`window_for`] reads an engine window for this backend type.
pub fn reads_window(backend_type: &str) -> bool {
    matches!(backend_type, "vllm" | "vllm-secondary" | "llamacpp")
}

type WindowMap = std::collections::HashMap<(String, String, String), (Option<u64>, std::time::Instant)>;
static WINDOWS: std::sync::LazyLock<std::sync::Mutex<WindowMap>> = std::sync::LazyLock::new(Default::default);

fn windows() -> std::sync::MutexGuard<'static, WindowMap> {
    WINDOWS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The running chat placement of `backend_type` that serves `model`: the one
/// naming it, else the node's first running one of that engine.
pub(crate) fn engine_placement<'a>(
    placements: &'a [crate::routes::cluster::StoredPlacement],
    backend_type: &str,
    model: &str,
) -> Option<&'a crate::routes::cluster::StoredPlacement> {
    let chats: Vec<&crate::routes::cluster::StoredPlacement> =
        placements.iter().filter(|p| p.backend == backend_type && p.role == "chat" && p.desired_state == "running").collect();
    chats.iter().find(|p| p.model.as_deref().is_some_and(|m| same_model(m, model))).or_else(|| chats.first()).copied()
}

/// Read the node and its placement as [`read_node`] does, and take
/// `harness_fit::chat_window` for the engine. `Err` = the read failed.
async fn read_window(state: &crate::state::AppState, node_id: &str, backend_type: &str, model: &str) -> Result<Option<u64>, String> {
    let kv = state.js.get_key_value("mesh_nodes").await.map_err(|e| format!("mesh_nodes: {e}"))?;
    let record: Value = match kv.get(node_id).await.map_err(|e| format!("node record: {e}"))? {
        Some(e) => serde_json::from_slice::<Value>(&e).map_err(|e| format!("node record: {e}"))?,
        None => Value::Null,
    };
    let placements = crate::routes::cluster::stored_placements(state, node_id).await.map_err(|e| format!("placements: {e}"))?;
    let Some(p) = engine_placement(&placements, backend_type, model) else { return Ok(None) };
    let tier = crate::node_tier::derive(&crate::node_tier::facts_from_capabilities(record.get("capabilities").unwrap_or(&serde_json::json!({}))))
        .tier()
        .and_then(|t| u8::try_from(t).ok());
    let overrides = crate::repo::cluster::node_harness_profile_overrides(&state.db, node_id).await.map_err(|e| format!("harness profile: {e}"))?;
    let profile = crate::harness_profile::resolve(tier, &overrides, None, None);
    Ok(crate::harness_fit::chat_window(backend_type, &p.env, Some(model), &record, profile.context).map(|w| w.tokens))
}

/// The window one request gets on a vLLM or llama.cpp backend, from its
/// node's running chat placement (`harness_fit::chat_window`: the engine's
/// key, else the harness profile's context, capped by the model's ceiling).
/// `None` for any other backend, a URL that names no node, a node with no
/// such placement, or a failed read: the loop then keeps its old global
/// window. Held like [`num_ctx_for`]; a chat never fails because of it.
pub async fn window_for(state: &crate::state::AppState, backend_type: &str, backend_url: &str, model: &str) -> Option<u64> {
    if !reads_window(backend_type) || model.trim().is_empty() {
        return None;
    }
    let node = node_of_url(state, backend_url).await?;
    let key = (node.clone(), backend_type.to_string(), model.trim().to_string());
    let now = std::time::Instant::now();
    if let Some((w, at)) = windows().get(&key).copied() {
        let window = if w.is_some() { RECHECK_SECS } else { RETRY_SECS };
        if now.saturating_duration_since(at) < std::time::Duration::from_secs(window) {
            return w;
        }
    }
    let w = match read_window(state, &node, backend_type, model.trim()).await {
        Ok(w) => w,
        Err(why) => {
            tracing::debug!(node = %node, backend_type, model, error = %why, "chat_context: cannot read the engine window; the loop keeps its global one");
            None
        }
    };
    windows().insert(key, (w, now));
    w
}

// ── calibration: the loop's estimate against the backend's count ───────────
//
// The loop estimates tokens at chars×10/25. Measured (fa, i802) that runs
// 1.6× (qwen, English) to ~4.5× (gemma4, JSON tool schemas) the backend's
// real count, so no fixed ratio is safe. Each (backend URL, model) learns its
// own ratio, real/estimate, from calls the backend clearly read whole, in
// this process only. Until it has [`CALIB_TRUSTED_AFTER`] samples the ratio
// in use is 1.0: a fresh box over-trims, which is safe and silent.

/// The ratio is held within these bounds whatever a sample says.
pub const CALIB_MIN: f64 = 0.15;
pub const CALIB_MAX: f64 = 1.25;
/// One sample moves the ratio by at most this fraction of itself.
pub const CALIB_STEP: f64 = 0.20;
/// Samples before the learned ratio is used.
pub const CALIB_TRUSTED_AFTER: u32 = 3;
/// A prompt estimated below this teaches nothing: the per-message overhead
/// in the estimate dominates it.
pub const CALIB_MIN_ESTIMATE: u64 = 256;
/// Ollama keeps this many tokens from the head of a prompt it cuts
/// (`truncating input prompt ... keep=5`).
pub const OLLAMA_CUT_KEEP: u64 = 5;
/// How near the cut length a count must land to be read as one.
pub const CUT_SLACK: u64 = 16;
/// The most favourable ratio measured (gemma4 with JSON tool schemas, ~4.5×
/// the estimate's error): before the ratio is trusted, a turn is refused
/// only when even this ratio leaves its instructions too large.
pub const REFUSE_UNTRUSTED_RATIO: f64 = 0.22;

/// One backend's learned ratio of real tokens to the loop's estimate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Calibration {
    pub ratio: f64,
    pub samples: u32,
}

impl Default for Calibration {
    fn default() -> Self {
        Calibration { ratio: 1.0, samples: 0 }
    }
}

impl Calibration {
    pub fn trusted(&self) -> bool {
        self.samples >= CALIB_TRUSTED_AFTER
    }

    /// The ratio the fit uses: the learned one once trusted, else 1.0.
    pub fn in_use(&self) -> f64 {
        if self.trusted() {
            self.ratio
        } else {
            1.0
        }
    }

    /// The estimate as the backend would count it.
    pub fn calibrated(&self, estimate: u64) -> u64 {
        (estimate as f64 * self.in_use()).ceil() as u64
    }

    /// The raw-estimate budget that calibrates to `max_input`: what the
    /// loop's `estimate_tokens` may reach.
    pub fn estimate_budget(&self, max_input: u64) -> u64 {
        (max_input as f64 / self.in_use()).floor() as u64
    }

    /// One whole read: the first sample sets the ratio (clipped), each later
    /// one moves it at most [`CALIB_STEP`] of itself toward the sample.
    pub fn learn(self, estimate: u64, evaluated: u64) -> Calibration {
        if estimate < CALIB_MIN_ESTIMATE || evaluated == 0 {
            return self;
        }
        let sample = (evaluated as f64 / estimate as f64).clamp(CALIB_MIN, CALIB_MAX);
        let ratio = if self.samples == 0 {
            sample
        } else {
            let most = self.ratio * CALIB_STEP;
            (self.ratio + (sample - self.ratio).clamp(-most, most)).clamp(CALIB_MIN, CALIB_MAX)
        };
        Calibration { ratio, samples: self.samples.saturating_add(1) }
    }
}

type CalibMap = std::collections::HashMap<(String, String), Calibration>;
static CALIBRATION: std::sync::LazyLock<std::sync::Mutex<CalibMap>> = std::sync::LazyLock::new(Default::default);

fn calibrations() -> std::sync::MutexGuard<'static, CalibMap> {
    CALIBRATION.lock().unwrap_or_else(|e| e.into_inner())
}

/// What this process has learned for (backend URL, model).
pub fn calibration(backend_url: &str, model: &str) -> Calibration {
    calibrations().get(&(backend_url.to_string(), model.trim().to_string())).copied().unwrap_or_default()
}

/// Teach (backend URL, model) one whole read; returns the new calibration.
pub fn learn(backend_url: &str, model: &str, estimate: u64, evaluated: u64) -> Calibration {
    let mut map = calibrations();
    let entry = map.entry((backend_url.to_string(), model.trim().to_string())).or_default();
    *entry = entry.learn(estimate, evaluated);
    *entry
}

/// The count Ollama reports for a prompt it cut in a `ctx`-token context:
/// the [`OLLAMA_CUT_KEEP`] head tokens plus the last half.
pub fn cut_length(ctx: u64) -> u64 {
    ctx / 2 + OLLAMA_CUT_KEEP
}

/// What one Ollama call's count says about its prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallRead {
    /// The backend cut the prompt.
    Cut,
    /// The count lands on the cut length but the prompt was small enough to
    /// be read whole: logged, not alerted.
    OnTheLine,
    /// Read whole, and far enough from the cut length to teach the ratio.
    Whole,
    /// Read whole, but too near half the context to teach anything.
    Unclear,
}

/// The cut signature (i802 D): Ollama cut the prompt when the count lands
/// within [`CUT_SLACK`] of [`cut_length`] AND the prompt was larger than the
/// context: by the calibrated estimate once the ratio is trusted, else by
/// the raw estimate past 1.5× the context (the raw estimate runs high).
pub fn read_call(ctx: u64, sent_estimate: u64, evaluated: u64, calib: Calibration) -> CallRead {
    let on_line = evaluated.abs_diff(cut_length(ctx)) <= CUT_SLACK;
    let larger = if calib.trusted() { calib.calibrated(sent_estimate) > ctx } else { sent_estimate.saturating_mul(2) > ctx.saturating_mul(3) };
    if on_line && larger {
        CallRead::Cut
    } else if on_line {
        CallRead::OnTheLine
    } else if evaluated.saturating_add(CUT_SLACK) < ctx / 2 {
        CallRead::Whole
    } else {
        CallRead::Unclear
    }
}

/// Before a turn is sent: do its instructions and question alone (system
/// messages, the person's message, the tool schemas) exceed the prompt
/// budget? Judged with the trusted ratio, else with the most favourable
/// ratio measured ([`REFUSE_UNTRUSTED_RATIO`]), so a fresh box is not
/// refused on its uncalibrated estimate.
pub fn instructions_overflow(need_estimate: u64, max_input: u64, calib: Calibration) -> bool {
    let ratio = if calib.trusted() { calib.ratio } else { REFUSE_UNTRUSTED_RATIO };
    (need_estimate as f64 * ratio).ceil() as u64 > max_input
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// fa's one-box cell (runs 43622936679, 43628426011): 16 GB, ~9.4 GB in
    /// use, gemma4:e2b at 16 KiB/token/slot (the top of the measured 13-16),
    /// 4 slots.
    fn stranger(running: Option<u64>) -> FitInputs {
        FitInputs { ram_gib: 15.6, used_gib: 9.4, kv_bytes_per_token: 16.0 * 1024.0, kv_measured: true, slots: 4, running }
    }

    #[test]
    fn the_strangers_box_gets_the_declared_context() {
        let f = fit_cap(32768, &stranger(Some(4096)));
        assert_eq!(f, Fit { tokens: 32768, capped: None }, "2.0 GiB of cache fits ~4.9 GiB free");
    }

    #[test]
    fn a_context_that_does_not_fit_steps_down_and_says_why() {
        let unmeasured = FitInputs { kv_bytes_per_token: 144.0 * 1024.0, kv_measured: false, ..stranger(None) };
        let f = fit_cap(32768, &unmeasured);
        assert_eq!(f.tokens, 8192, "{f:?}");
        let why = f.capped.expect("capped");
        assert!(why.contains("32768 needs 18.0 GiB") && why.contains("4 slot(s)") && why.contains("never measured"), "{why}");
        let full = FitInputs { used_gib: 15.0, ..unmeasured };
        assert_eq!(fit_cap(32768, &full).tokens, FLOOR, "never below Ollama's own default");
    }

    #[test]
    fn a_raise_needs_a_margin_a_drop_does_not_and_a_new_declaration_always_wins() {
        let d = |tokens, declared| Decided { tokens, declared, source: String::new(), capped: None, slots: 4 };
        let f = stranger(None);
        let held = Sticky { tokens: 8192, declared: 32768 };
        assert_eq!(Sticky::next(Some(held), &d(16384, 32768), &f), Sticky { tokens: 16384, declared: 32768 }, "fits well within the margin");
        let tight = FitInputs { used_gib: 14.0, ..f };
        assert_eq!(Sticky::next(Some(held), &d(16384, 32768), &tight), held, "not within the margin: hold");
        assert_eq!(Sticky::next(Some(held), &d(4096, 32768), &tight), Sticky { tokens: 4096, declared: 32768 }, "a drop is taken at once");
        assert_eq!(Sticky::next(Some(held), &d(16384, 16384), &tight), Sticky { tokens: 16384, declared: 16384 }, "a new declaration");
    }

    /// The room for the cache keeps the headroom back: on fa's box 15.6 GiB
    /// with 9.4 used leaves 6.2, minus 1.56 (10%), so about 4.64.
    #[test]
    fn the_room_keeps_the_headroom_back() {
        let room = kv_room_gib(&stranger(None));
        assert!((4.6..4.7).contains(&room), "{room}");
        let small = FitInputs { ram_gib: 8.0, used_gib: 4.0, ..stranger(None) };
        assert!((2.95..3.05).contains(&kv_room_gib(&small)), "the 1 GiB minimum on a small box");
    }

    /// decide() itself holds a working context: an unmeasured model on a
    /// tight box that already runs its declared 32768 keeps it.
    #[test]
    fn decide_keeps_what_the_daemon_already_runs() {
        let node = json!({"ram_gb": 24.0, "mem_used_gb": 23.0,
            "model_stats": [{"name": "gemma4:12b", "size_bytes": 8_000_000_000u64, "context_length": 131072, "running_context": 32768}]});
        let d = decide("ollama", &json!({"OLLAMA_CONTEXT_LENGTH": "32768", "OLLAMA_NUM_PARALLEL": "2"}), "gemma4:12b", &node, 32768).expect("decided");
        assert_eq!(d.tokens, 32768, "{d:?}");
        assert!(d.capped.as_deref().is_some_and(|c| c.contains("kept at the 32768 it already runs")), "{d:?}");
    }

    #[test]
    fn a_working_context_is_never_shrunk_by_the_fit() {
        let capped = Fit { tokens: 8192, capped: Some("32768 needs 9.0 GiB".into()) };
        let kept = held_at_running(capped.clone(), 32768, Some(32768));
        assert_eq!(kept.tokens, 32768);
        assert!(kept.capped.as_deref().is_some_and(|c| c.contains("kept at the 32768 it already runs") && c.contains("the fit alone said 8192")), "{kept:?}");
        assert_eq!(held_at_running(capped.clone(), 16384, Some(32768)), capped, "above the declaration: the declaration still caps");
        assert_eq!(held_at_running(capped.clone(), 32768, Some(4096)), capped, "a smaller running context is no floor");
        assert_eq!(held_at_running(capped.clone(), 32768, None), capped);
    }

    /// The one-box's chat runs in the stack's compose Ollama: the fit counts
    /// that daemon's slots (compose_env), the slots that will be in force,
    /// and never overrides a placement that says its own.
    #[test]
    fn the_stack_daemon_is_fitted_with_the_stacks_own_slot_count() {
        let cfg = json!({"compose_env": {"OLLAMA_EMBED_NUM_PARALLEL": "1"}});
        assert_eq!(compose_slots(&cfg), Some(1));
        assert_eq!(compose_slots(&json!({"compose_env": {"OLLAMA_EMBED_NUM_PARALLEL": 2}})), Some(2));
        assert_eq!(compose_slots(&json!({})), None, "unset: compose's default");
        let env = json!({"OLLAMA_CONTEXT_LENGTH": "32768"});
        assert_eq!(with_stack_slots(&env, true, Some(1))["OLLAMA_NUM_PARALLEL"], json!("1"));
        assert_eq!(with_stack_slots(&env, true, None)["OLLAMA_NUM_PARALLEL"], json!("4"), "compose's default, said");
        assert!(with_stack_slots(&env, false, Some(1)).get("OLLAMA_NUM_PARALLEL").is_none(), "another node's daemon is its placement's business");
        let own = json!({"OLLAMA_NUM_PARALLEL": "2"});
        assert_eq!(with_stack_slots(&own, true, Some(1))["OLLAMA_NUM_PARALLEL"], json!("2"), "the placement's own value stands");
        assert_eq!(slots(&with_stack_slots(&env, true, Some(1))), 1);
    }

    #[test]
    fn the_stamp_sets_num_ctx_only_when_absent() {
        let mut b = json!({"model": "gemma4:e2b", "messages": []});
        stamp(&mut b, 16384);
        assert_eq!(b["options"]["num_ctx"], json!(16384));
        let mut caller = json!({"model": "m", "options": {"num_ctx": 2048, "temperature": 0.2}});
        stamp(&mut caller, 16384);
        assert_eq!(caller["options"], json!({"num_ctx": 2048, "temperature": 0.2}), "the caller's own value stands");
    }

    #[test]
    fn only_an_ollama_with_a_declared_context_is_decided() {
        let node = json!({"ram_gb": 15.6, "mem_used_gb": 9.4,
            "model_stats": [{"name": "gemma4:e2b", "size_bytes": 4_600_000_000u64, "context_length": 131072, "running_context": 4096}]});
        assert_eq!(running_context(&node, "gemma4:e2b"), Some(4096));
        let env = json!({"OLLAMA_CONTEXT_LENGTH": "32768"});
        assert!(decide("vllm", &env, "gemma4:e2b", &node, 16384).is_none(), "vLLM bodies never get options");
        let d = decide("ollama", &env, "gemma4:e2b", &node, 16384).expect("decided");
        assert_eq!((d.declared, d.slots), (32768, 4));
        assert!(d.source.contains("OLLAMA_CONTEXT_LENGTH"), "{}", d.source);
        let profile_only = decide("ollama", &json!({}), "gemma4:e2b", &node, 16384).expect("the tier profile");
        assert_eq!(profile_only.declared, 16384);
        assert!(decide("ollama", &json!({}), "gemma4:e2b", &node, 0).is_none(), "nothing declared: nothing stamped");
    }

    #[test]
    fn only_an_ollama_takes_num_ctx_and_none_stamps_nothing() {
        assert!(takes_num_ctx("ollama"));
        for b in ["vllm", "llamacpp", "cloud-openai", "cloud-anthropic", "openai", ""] {
            assert!(!takes_num_ctx(b), "{b}");
        }
        let mut b = json!({"model": "m"});
        stamp_opt(&mut b, None);
        assert_eq!(b, json!({"model": "m"}), "no options key at all");
        stamp_opt(&mut b, Some(8192));
        assert_eq!(b["options"]["num_ctx"], json!(8192));
    }

    /// The resolver's own gate comes before any read: a vLLM, llama.cpp or
    /// cloud request never costs a KV or database read, and gets `None`.
    #[test]
    fn the_resolver_returns_none_for_a_non_ollama_before_any_read() {
        let own = crate::test_src::own_code(include_str!("chat_context.rs"));
        for marker in ["pub async fn num_ctx_for_node(", "pub async fn num_ctx_for("] {
            let f = crate::test_src::fn_body(&own, marker);
            let gate = f.find("if !takes_num_ctx(backend_type)").unwrap_or_else(|| panic!("{marker} has no gate: {f}"));
            let ret = f[gate..].find("return None;").map(|i| gate + i).expect("the gate returns None");
            let first_await = f.find(".await").expect("it reads");
            assert!(ret < first_await, "{marker}: the gate must return before the first read:\n{f}");
        }
    }

    #[test]
    fn a_read_moves_the_held_value_a_failure_keeps_it_and_nothing_declared_clears_it() {
        let t0 = std::time::Instant::now();
        let d = |tokens, declared| Decided { tokens, declared, source: String::new(), capped: None, slots: 4 };
        let f = stranger(None);
        let first = after_read(None, &Read::Decided(d(16384, 16384), f), t0);
        assert_eq!(first.sticky, Some(Sticky { tokens: 16384, declared: 16384 }));
        assert!(!first.failed);
        let kept = after_read(Some(first), &Read::Failed("kv down".into()), t0);
        assert_eq!(kept.sticky, first.sticky, "a failed read keeps what was held");
        assert!(kept.failed);
        assert_eq!(after_read(Some(first), &Read::Nothing, t0).sticky, None, "nothing declared: nothing stamped");
        assert_eq!(after_read(None, &Read::Failed("x".into()), t0).sticky, None, "nothing held: None, never an error");
    }

    #[test]
    fn a_held_value_is_reread_after_ten_minutes_and_an_empty_failure_after_one() {
        let t0 = std::time::Instant::now();
        let ok = Held { sticky: Some(Sticky { tokens: 8192, declared: 8192 }), at: t0, failed: false };
        assert!(fresh(&ok, t0 + std::time::Duration::from_secs(RECHECK_SECS - 1)));
        assert!(!fresh(&ok, t0 + std::time::Duration::from_secs(RECHECK_SECS)));
        let held_through_failure = Held { failed: true, ..ok };
        assert!(fresh(&held_through_failure, t0 + std::time::Duration::from_secs(RETRY_SECS + 1)), "a held value rides out a failure");
        let empty = Held { sticky: None, at: t0, failed: true };
        assert!(fresh(&empty, t0 + std::time::Duration::from_secs(RETRY_SECS - 1)));
        assert!(!fresh(&empty, t0 + std::time::Duration::from_secs(RETRY_SECS)));
        const { assert!(RECHECK_SECS == 600 && RETRY_SECS < RECHECK_SECS) };
    }

    #[test]
    fn the_env_is_the_running_ollama_chat_placement_that_serves_the_model() {
        use crate::routes::cluster::StoredPlacement;
        let p = |backend: &str, role: &str, model: Option<&str>, ctx: &str, state: &str| StoredPlacement {
            backend: backend.into(),
            role: role.into(),
            model: model.map(str::to_string),
            env: json!({"OLLAMA_CONTEXT_LENGTH": ctx}),
            desired_state: state.into(),
            target: None,
            keep_warm: false,
        };
        let rows = vec![
            p("vllm", "chat", Some("gemma4"), "1", "running"),
            p("ollama", "embed", Some("gemma4"), "2", "running"),
            p("ollama", "chat", Some("gemma4"), "3", "stopped"),
            p("ollama", "chat", Some("qwen3:4b"), "4", "running"),
            p("ollama", "chat", Some("gemma4:latest"), "5", "running"),
        ];
        assert_eq!(chat_env(&rows, "gemma4")["OLLAMA_CONTEXT_LENGTH"], json!("5"), "the one naming it (`:latest` the same)");
        assert_eq!(chat_env(&rows, "llama3.2:3b")["OLLAMA_CONTEXT_LENGTH"], json!("4"), "else the daemon's first running chat placement");
        assert_eq!(chat_env(&rows[..3], "gemma4"), json!({}), "no running ollama chat placement: no env");
    }

    #[test]
    fn the_reserve_is_a_quarter_at_most_4096() {
        assert_eq!((reserve_for(4096), max_input_for(4096)), (1024, 3072));
        assert_eq!((reserve_for(8192), max_input_for(8192)), (2048, 6144));
        assert_eq!((reserve_for(32768), max_input_for(32768)), (4096, 28_672));
        assert_eq!(max_input_for(0), 0);
    }

    fn near(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// i802 PR-2 step 2: a fresh backend fits at 1.0 (over-trims, silently);
    /// the first whole read sets the ratio, each later one moves it at most
    /// 20%, it is held within [0.15, 1.25] and trusted after three samples.
    #[test]
    fn a_fresh_backend_uses_one_and_learns_within_bounds() {
        let c = Calibration::default();
        assert_eq!((c.in_use(), c.calibrated(1000), c.estimate_budget(3072)), (1.0, 1000, 3072));
        let c = c.learn(1000, 400);
        assert!(near(c.ratio, 0.4) && c.samples == 1 && !c.trusted(), "{c:?}");
        assert_eq!(c.in_use(), 1.0, "not trusted yet");
        let c = c.learn(1000, 50);
        assert!(near(c.ratio, 0.32), "0.05 clips to 0.15, the move to 20% of 0.4: {c:?}");
        let c = c.learn(1000, 2000);
        assert!(near(c.ratio, 0.384) && c.trusted(), "{c:?}");
        assert!(near(c.in_use(), 0.384));
        let half = Calibration { ratio: 0.5, samples: 3 };
        assert_eq!((half.calibrated(1000), half.estimate_budget(3072)), (500, 6144), "the fit compares estimate x ratio with max_input");
        assert_eq!(c.learn(100, 50), c, "a short prompt teaches nothing");
        assert_eq!(c.learn(1000, 0), c, "no count teaches nothing");
        let mut low = Calibration::default().learn(1000, 1);
        let mut high = Calibration::default().learn(1000, 9000);
        assert!(near(low.ratio, CALIB_MIN) && near(high.ratio, CALIB_MAX));
        for _ in 0..50 {
            low = low.learn(1000, 1);
            high = high.learn(1000, 9000);
        }
        assert!(low.ratio >= CALIB_MIN && high.ratio <= CALIB_MAX, "{low:?} {high:?}");
    }

    #[test]
    fn calibration_is_per_backend_and_model() {
        let url = "http://calib-test-only.invalid:11434";
        for _ in 0..3 {
            learn(url, "gemma4:e2b", 1000, 250);
        }
        let c = calibration(url, "gemma4:e2b");
        assert!(c.trusted() && near(c.ratio, 0.25), "{c:?}");
        assert_eq!(calibration(url, "qwen3:4b"), Calibration::default(), "another model learns its own");
        assert_eq!(calibration("http://calib-test-other.invalid:11434", "gemma4:e2b"), Calibration::default());
    }

    /// fa's measured cell: `truncating input prompt limit=2051 prompt=4590
    /// keep=5 new=2051` on a 4,096 daemon. The count lands on ctx/2 + 5.
    #[test]
    fn the_cut_signature_is_the_count_on_the_line_and_a_prompt_past_the_context() {
        let fresh = Calibration::default();
        assert_eq!(cut_length(4096), 2053);
        assert_eq!(read_call(4096, 8800, 2051, fresh), CallRead::Cut, "raw 8,800 > 1.5 x 4,096");
        assert_eq!(read_call(4096, 5000, 2051, fresh), CallRead::OnTheLine, "raw 5,000 may be 2,051 real: not alerted");
        let gemma = Calibration { ratio: 0.25, samples: 3 };
        assert_eq!(read_call(4096, 8800, 2051, gemma), CallRead::OnTheLine, "calibrated 2,200 fits 4,096");
        let qwen = Calibration { ratio: 0.6, samples: 3 };
        assert_eq!(read_call(4096, 8800, 2051, qwen), CallRead::Cut, "calibrated 5,280 does not");
        assert_eq!(read_call(4096, 8800, 2040, fresh), CallRead::Cut, "within 16");
        assert_eq!(read_call(4096, 8800, 2070, fresh), CallRead::Unclear, "off the line, too near half to teach");
        assert_eq!(read_call(4096, 8800, 1500, fresh), CallRead::Whole);
        assert_eq!(read_call(16384, 8800, 3100, fresh), CallRead::Whole, "a big context reads it whole");
    }

    #[test]
    fn instructions_overflow_uses_the_trusted_ratio_else_the_kindest_measured() {
        let fresh = Calibration::default();
        assert!(!instructions_overflow(13_000, 3072, fresh), "13,000 x 0.22 = 2,860");
        assert!(instructions_overflow(14_500, 3072, fresh), "14,500 x 0.22 = 3,190");
        assert!(instructions_overflow(10_000, 3072, Calibration { ratio: 0.4, samples: 3 }));
        assert!(!instructions_overflow(10_000, 3072, Calibration { ratio: 0.4, samples: 2 }), "untrusted: the kindest ratio");
    }

    #[test]
    fn the_engine_window_comes_from_the_running_chat_placement_of_that_engine() {
        use crate::routes::cluster::StoredPlacement;
        let p = |backend: &str, role: &str, model: Option<&str>, len: &str, state: &str| StoredPlacement {
            backend: backend.into(),
            role: role.into(),
            model: model.map(str::to_string),
            env: json!({"VLLM_MAX_MODEL_LEN": len}),
            desired_state: state.into(),
            target: None,
            keep_warm: false,
        };
        let rows = vec![
            p("ollama", "chat", Some("gemma4"), "1", "running"),
            p("vllm", "embed", Some("gemma4"), "2", "running"),
            p("vllm", "chat", Some("gemma4"), "3", "stopped"),
            p("vllm", "chat", Some("qwen3"), "4", "running"),
            p("vllm", "chat", Some("gemma4"), "5", "running"),
        ];
        assert_eq!(engine_placement(&rows, "vllm", "gemma4").map(|p| p.env["VLLM_MAX_MODEL_LEN"].clone()), Some(json!("5")));
        assert_eq!(engine_placement(&rows, "vllm", "llama").map(|p| p.env["VLLM_MAX_MODEL_LEN"].clone()), Some(json!("4")), "else the first running one");
        assert!(engine_placement(&rows, "llamacpp", "gemma4").is_none());
        assert!(reads_window("vllm") && reads_window("llamacpp") && !reads_window("ollama") && !reads_window("cloud-openai"));
    }

    /// Like the num_ctx resolver: an Ollama or cloud backend never costs a read.
    #[test]
    fn the_window_resolver_returns_none_before_any_read() {
        let own = crate::test_src::own_code(include_str!("chat_context.rs"));
        let f = crate::test_src::fn_body(&own, "pub async fn window_for(");
        let gate = f.find("if !reads_window(backend_type)").unwrap_or_else(|| panic!("no gate: {f}"));
        let ret = f[gate..].find("return None;").map(|i| gate + i).expect("the gate returns None");
        assert!(ret < f.find(".await").expect("it reads"), "{f}");
    }
}
