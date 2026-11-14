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
    let fit = fit_cap(w.tokens, &f);
    Some(Decided { tokens: fit.tokens, declared: w.tokens, source: w.source, capped: fit.capped, slots: f.slots })
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
}
