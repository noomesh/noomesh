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
    let env = chat_env(&placements, model);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// fa's one-box cell (run 43622936679): 16 GB, ~9.4 GB in use, gemma4:e2b
    /// at 8.5 KiB/token/slot measured, 4 slots.
    fn stranger(running: Option<u64>) -> FitInputs {
        FitInputs { ram_gib: 15.6, used_gib: 9.4, kv_bytes_per_token: 8.5 * 1024.0, kv_measured: true, slots: 4, running }
    }

    #[test]
    fn the_strangers_box_gets_the_declared_context() {
        let f = fit_cap(32768, &stranger(Some(4096)));
        assert_eq!(f, Fit { tokens: 32768, capped: None }, "1.06 GiB of cache fits ~4.9 GiB free");
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
}
