// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Will these placements FIT on this node's memory? (multi-role placements)
//!
//! One ollama can host a chat model and an embedder, so a node's placements
//! now compete for one pool of memory. This module is the single place that
//! decides whether a set of placements fits - `PUT .../placements`,
//! `POST .../fit` (`noo cluster fit`), and the placement suggestion all call
//! [`evaluate`].
//!
//! ## Budget (where the memory comes from): one pool per hardware target
//!
//! Read from what the node already reports (`vram_gb`, `ram_gb`, `capabilities`
//! on its heartbeat); nothing is probed. A placement runs on a hardware TARGET
//! (`cpu` | `gpu`, `noo cluster place --on`), and each target draws on its own
//! pool:
//!
//! * the GPU pool - `unified` when the node reports
//!   `capabilities.unified_memory` (Apple Silicon, Jetson, GB10): `vram_gb` IS
//!   the usable GPU share of RAM (host6: 18 of 24 GB); else `vram`, a
//!   discrete GPU's `vram_gb`;
//! * the CPU pool - `ram`: `ram_gb`. On a unified-memory node the GPU share is
//!   carved out of the same RAM, so the CPU pool is `ram_gb - vram_gb` (host6:
//!   6 GB).
//!
//! A placement's target is the one it declares (the `target` column); with none
//! declared, `N_GPU_LAYERS=0` in its env means CPU (a llama.cpp placement made
//! with `--env N_GPU_LAYERS=0` before `--on` existed), and a node with no GPU
//! puts everything on CPU. Before this, a CPU placement was budgeted against
//! VRAM ("Budget 6.0 GB vram" for a model that would never touch the GPU).
//!
//! Headroom is reserved from each pool: `max(10% of the pool, 1 GB)`
//! ([`HEADROOM_FRAC`], [`HEADROOM_MIN_GB`]). A node whose usage profile is
//! `shared` (someone also uses it as a desktop: `noo cluster set-config
//! --usage shared`) reserves more of its GPU: `max(20%, 2 GB)`
//! ([`SHARED_GPU_HEADROOM_FRAC`], [`SHARED_GPU_HEADROOM_MIN_GB`]).
//!
//! ## Per-model resident size
//!
//! `weights + KV cache + runtime overhead`, or - preferred - what the node
//! MEASURED for that model (`model_stats[].resident_bytes`, ollama `/api/ps`
//! `size` while the model is loaded), reported with `source = "measured"`.
//!
//! * weights, first that answers: the node's own `model_stats[].size_bytes`
//!   (ollama `/api/tags`); the GGUF file's size in the controller model store
//!   (`model_size_hints`, sent by the CLI, which can see `MODELS_DIR`); any
//!   OTHER node's reported `size_bytes` for the same model
//!   (`fleet_model_stats`); [`KNOWN_WEIGHTS_GB`]; the parameter count parsed
//!   from the tag (`26b` x [`GB_PER_BILLION_PARAMS`]); else unknown;
//! * KV = layers x kv_heads x head_dim x 2 (K and V) x bytes_per_elem x num_ctx
//!   x num_parallel. The architecture comes from `model_stats[].arch` when the
//!   node reports it; otherwise the documented conservative figure
//!   [`KV_BYTES_PER_TOKEN_PER_GB_WEIGHTS`] x weights_gb per token per slot (the
//!   full-attention ratio of a 27B GQA model, so models with sliding-window
//!   attention are over- not under-estimated);
//! * `num_ctx`: embed = `EMBED_NUM_CTX` (the gateway sends it on every embed);
//!   chat = the placement's `OLLAMA_CONTEXT_LENGTH` / `N_CTX`, else
//!   [`DEFAULT_CHAT_CTX`] - the gateway sends NO `num_ctx` for ollama chat, so
//!   the daemon default is what is allocated; rerank = [`RERANK_CTX`];
//! * `num_parallel` is DAEMON-wide: the max `OLLAMA_NUM_PARALLEL` over every
//!   ollama placement on the node (the same merge the node agent applies), so a
//!   4-slot embedder also gives the chat model 4 KV slots;
//! * KV bytes per element follow `OLLAMA_KV_CACHE_TYPE` (f16 2, q8_0 1, q4_0 0.5);
//! * overhead: [`RUNTIME_OVERHEAD_GB`] per loaded model.
//!
//! vLLM reserves a fraction of the GPU: `GPU_MEMORY_UTILIZATION` (default
//! [`VLLM_DEFAULT_UTIL`]) x the GPU pool. vLLM has no CPU target.
//!
//! ## Verdict
//!
//! Per pool: `fits` (sum <= pool - headroom), `tight` (sum <= pool: eats into
//! the headroom; succeeds with a warning), `does_not_fit` (sum > pool; refused
//! with a 409 unless `force`), `unknown` ("can't judge") when the node reports
//! no memory for the pool or a model's size cannot be found anywhere - an
//! unknown is never dressed up as `tight`. The node's verdict is the worst
//! pool's: does_not_fit, then unknown, then tight, then fits.

use serde_json::{json, Map, Value};

pub const HEADROOM_FRAC: f64 = 0.10;
pub const HEADROOM_MIN_GB: f64 = 1.0;
/// GPU headroom on a `shared` node: a desktop session (compositor, browser,
/// a game) holds GPU memory the node agent never sees.
pub const SHARED_GPU_HEADROOM_FRAC: f64 = 0.20;
pub const SHARED_GPU_HEADROOM_MIN_GB: f64 = 2.0;
pub const RUNTIME_OVERHEAD_GB: f64 = 0.6;
/// Conservative KV bytes per token per slot per GB of weights (16 KiB).
pub const KV_BYTES_PER_TOKEN_PER_GB_WEIGHTS: f64 = 16.0 * 1024.0;
pub const DEFAULT_CHAT_CTX: u64 = 4096;
pub const RERANK_CTX: u64 = 512;
pub const GB_PER_BILLION_PARAMS: f64 = 0.6; // Q4_K_M ~ 4.8 bits/param
pub const VLLM_DEFAULT_UTIL: f64 = 0.90;
const GB: f64 = 1_000_000_000.0;

/// The hardware targets a placement may declare (`noo cluster place --on`).
pub const TARGETS: &[&str] = &["cpu", "gpu"];

/// The node usage profiles (`noo cluster set-config --usage`).
pub const USAGE_PROFILES: &[&str] = &["shared", "dedicated"];

/// A node's usage profile and where it came from.
///
/// Unset means: `dedicated` on the controller's own node (the box the
/// operator built to run the stack, already sized for it) and `shared`
/// everywhere else (a worker is often someone's desktop or laptop that joined
/// the fleet). What `shared` costs: a larger GPU headroom here, and fewer
/// threads and parallel slots when `noo cluster place` tunes a placement. The
/// extra headroom can turn `fits` into `tight`, never into `does_not_fit`
/// (that is judged against the whole pool).
pub fn effective_usage(stored: Option<&str>, is_controller: bool) -> (&'static str, &'static str) {
    match stored.map(str::trim) {
        Some("shared") => ("shared", "set"),
        Some("dedicated") => ("dedicated", "set"),
        _ if is_controller => ("dedicated", "default for the controller"),
        _ => ("shared", "default for a worker"),
    }
}

/// Weights sizes (GB) for models whose size is known to the repo when the node
/// has not reported one. `harrier`: measured on host8 (596M params, Q4_K_M).
/// `gemma4:26b-a4b-it-qat`: ASSUMED ~15.8 GB (26B params, int4 QAT) - not
/// verified; any node that holds the model reports the real figure, which
/// then wins.
pub const KNOWN_WEIGHTS_GB: &[(&str, f64)] = &[("harrier", 0.4), ("gemma4:26b-a4b-it-qat", 15.8)];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Fits,
    Tight,
    DoesNotFit,
    Unknown,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Fits => "fits",
            Verdict::Tight => "tight",
            Verdict::DoesNotFit => "does_not_fit",
            Verdict::Unknown => "unknown",
        }
    }

    /// Worse-first order for combining pools.
    fn severity(self) -> u8 {
        match self {
            Verdict::Fits => 0,
            Verdict::Tight => 1,
            Verdict::Unknown => 2,
            Verdict::DoesNotFit => 3,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Budget {
    /// `vram` | `unified` | `ram`
    pub kind: &'static str,
    /// The hardware target this pool serves: `gpu` | `cpu`.
    pub target: &'static str,
    pub total_gb: f64,
    pub headroom_gb: f64,
}

impl Budget {
    pub fn usable_gb(&self) -> f64 {
        self.total_gb - self.headroom_gb
    }
}

/// One placement to judge.
#[derive(Clone, Debug)]
pub struct Spec {
    pub backend: String,
    pub role: String,
    pub model: String,
    pub env: Map<String, Value>,
    /// The declared hardware target (`cpu` | `gpu`), if any.
    pub target: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub backend: String,
    pub role: String,
    pub model: String,
    /// The pool this row is charged to: `gpu` | `cpu`.
    pub target: &'static str,
    pub weights_gb: Option<f64>,
    /// Where the weights figure came from (`node-reported`, `controller-store`,
    /// `fleet-reported`, `known`, `from-name`, `unknown`).
    pub weights_source: &'static str,
    pub kv_gb: f64,
    pub overhead_gb: f64,
    pub total_gb: f64,
    /// `measured` | `estimated`
    pub source: &'static str,
    pub notes: Vec<String>,
}

/// One pool's judgement.
#[derive(Clone, Debug)]
pub struct PoolReport {
    pub budget: Option<Budget>,
    pub target: &'static str,
    pub used_gb: f64,
    pub verdict: Verdict,
    pub shortfall_gb: f64,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub verdict: Verdict,
    /// The pool the report leads with: the GPU pool when anything is charged
    /// to it, else the CPU pool. Kept for clients that read one `budget`.
    pub budget: Option<Budget>,
    pub pools: Vec<PoolReport>,
    pub usage: &'static str,
    pub rows: Vec<Row>,
    pub total_gb: f64,
    pub shortfall_gb: f64,
    pub warnings: Vec<String>,
}

fn reported(v: &Value) -> Option<f64> {
    // A top-level 0 means "not reported", not "no GPU": an Apple Silicon node
    // sends `vram_gb: 0` beside `capabilities.vram_gb: 18` (the unified share),
    // and taking the 0 sized host6 against its 24 GB of RAM (live 2026-10-09).
    v.as_f64().filter(|g| *g > 0.0)
}

fn node_vram_ram(node: &Value) -> (f64, f64, bool) {
    let caps = node.get("capabilities").cloned().unwrap_or_else(|| json!({}));
    let vram = reported(&node["vram_gb"]).or_else(|| reported(&caps["vram_gb"])).unwrap_or(0.0);
    let ram = reported(&node["ram_gb"]).or_else(|| reported(&caps["ram_gb"])).unwrap_or(0.0);
    let unified = caps["unified_memory"].as_bool().unwrap_or(false);
    (vram, ram, unified)
}

/// Does the node report a GPU (discrete VRAM or a unified GPU share)?
pub fn node_has_gpu(node: &Value) -> bool {
    node_vram_ram(node).0 > 0.0
}

/// Does the node report any memory at all? A node that reports nothing is
/// "unknown", never "has no GPU".
pub fn node_reports_memory(node: &Value) -> bool {
    let (v, r, _) = node_vram_ram(node);
    v > 0.0 || r > 0.0
}

fn usage_of(node: &Value) -> &'static str {
    match node["usage_profile"].as_str() {
        Some("shared") => "shared",
        _ => "dedicated",
    }
}

/// The pool a `target` draws on, with the node's usage profile applied.
pub fn pool_for(node: &Value, target: &str) -> Option<Budget> {
    let (vram, ram, unified) = node_vram_ram(node);
    let shared = usage_of(node) == "shared";
    let headroom = |total: f64, frac: f64, min: f64| (total * frac).max(min);
    if target == "gpu" && vram > 0.0 {
        let (frac, min) = if shared { (SHARED_GPU_HEADROOM_FRAC, SHARED_GPU_HEADROOM_MIN_GB) } else { (HEADROOM_FRAC, HEADROOM_MIN_GB) };
        return Some(Budget { kind: if unified { "unified" } else { "vram" }, target: "gpu", total_gb: vram, headroom_gb: headroom(vram, frac, min) });
    }
    if target == "cpu" && ram > 0.0 {
        // Unified memory: the GPU share is carved out of the same RAM.
        let total = if unified && vram > 0.0 { (ram - vram).max(0.0) } else { ram };
        if total <= 0.0 {
            return None;
        }
        return Some(Budget { kind: "ram", target: "cpu", total_gb: total, headroom_gb: headroom(total, HEADROOM_FRAC, HEADROOM_MIN_GB) });
    }
    None
}

/// The llama.cpp container's floor on a GPU placement: the agent's old fixed
/// limit. The resident estimate counts weights + KV + overhead, which on a GPU
/// live in VRAM; the host side (CUDA host buffers, the mmapped file while it
/// loads) is not in it, so a GPU container never gets LESS than it had.
pub const LLAMACPP_GPU_FLOOR_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// A CPU container's floor: a model that small still needs a runtime.
pub const LLAMACPP_CPU_FLOOR_BYTES: u64 = 1024 * 1024 * 1024;
/// Shared nodes: the container may take at most this share of RAM.
pub const SHARED_RAM_CAP_FRAC: f64 = 0.5;
/// Dedicated nodes: RAM minus this much for the OS and the agent.
pub const DEDICATED_RAM_RESERVE_GB: f64 = 4.0;

/// The memory limit for a llama.cpp container, from the same resident
/// estimate `fit` makes for it (`row_total_gb` = weights + KV + overhead, or
/// the measured size), rounded up to a half GB and capped at the node's RAM
/// budget for its usage profile: shared at most half the RAM, dedicated RAM
/// minus 4 GB. `None` when the size is unknown (the agent keeps its default)
/// or the node reports no RAM to cap against.
pub fn llamacpp_memory_limit(node: &Value, row_total_gb: f64, size_known: bool, target: &str) -> Option<(u64, String)> {
    if !size_known || row_total_gb <= 0.0 {
        return None;
    }
    let (_, ram, _) = node_vram_ram(node);
    if ram <= 0.0 {
        return None;
    }
    let half_gb = 500_000_000.0;
    let est = ((row_total_gb * GB) / half_gb).ceil() * half_gb;
    let (cap_gb, cap_why) = if usage_of(node) == "shared" {
        (ram * SHARED_RAM_CAP_FRAC, format!("shared node: at most half of {ram:.0} GB RAM"))
    } else {
        ((ram - DEDICATED_RAM_RESERVE_GB).max(1.0), format!("dedicated node: {ram:.0} GB RAM minus {DEDICATED_RAM_RESERVE_GB:.0} GB"))
    };
    let cap = cap_gb * GB;
    let floor = if target == "gpu" { LLAMACPP_GPU_FLOOR_BYTES } else { LLAMACPP_CPU_FLOOR_BYTES } as f64;
    let wanted = est.max(floor);
    let (bytes, why) = if wanted > cap {
        (cap, format!("{:.1} GB wanted, capped: {cap_why}", wanted / GB))
    } else if wanted > est {
        (wanted, format!("the {} floor ({:.1} GB) over the {:.1} GB estimate", target, floor / GB, est / GB))
    } else {
        (est, format!("model + KV + overhead, {:.1} GB (the fit estimate)", est / GB))
    };
    Some((bytes as u64, why))
}

/// The node's headline budget: its GPU pool, else its RAM. What a single
/// placement with no declared target would be judged against.
pub fn budget_for(node: &Value) -> Option<Budget> {
    pool_for(node, "gpu").or_else(|| pool_for(node, "cpu"))
}

/// The target a placement runs on: the declared one; else `cpu` when its env
/// pins `N_GPU_LAYERS=0`; else `gpu`. A node without a GPU runs everything on
/// CPU, whatever was declared (the place route refuses `gpu` there, so this
/// only reaches rows from before the node lost its GPU).
pub fn resolve_target(spec: &Spec, node: &Value) -> &'static str {
    let has_gpu = node_has_gpu(node);
    if !has_gpu && node_reports_memory(node) {
        return "cpu";
    }
    match spec.target.as_deref() {
        Some("cpu") => "cpu",
        Some("gpu") => "gpu",
        _ if env_str(&spec.env, "N_GPU_LAYERS").is_some_and(|v| v.trim() == "0") => "cpu",
        _ if !has_gpu => "cpu",
        _ => "gpu",
    }
}

fn norm(m: &str) -> String {
    m.trim().strip_suffix(":latest").unwrap_or(m.trim()).to_string()
}

fn stat_in<'a>(list: Option<&'a Value>, model: &str) -> Option<&'a Value> {
    let want = norm(model);
    list?.as_array()?.iter().find(|s| s["name"].as_str().map(norm) == Some(want.clone()))
}

fn stat<'a>(node: &'a Value, model: &str) -> Option<&'a Value> {
    stat_in(node.get("model_stats"), model)
}

fn env_u64(env: &Map<String, Value>, key: &str) -> Option<u64> {
    match env.get(key)? {
        Value::String(s) => s.trim().parse().ok(),
        v => v.as_u64(),
    }
}

fn env_str(env: &Map<String, Value>, key: &str) -> Option<String> {
    env.get(key).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

/// Parameter count (billions) parsed from a tag like `gemma4:26b-a4b-it-qat`
/// or `qwen3:8b`: the first `<n>b` token.
fn params_b(model: &str) -> Option<f64> {
    for tok in model.to_lowercase().split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
        if let Some(n) = tok.strip_suffix('b') {
            if let Ok(v) = n.parse::<f64>() {
                if v > 0.0 {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// The weights size of `model`, and where it came from. The order is the
/// module doc's: this node, the controller store, another node, the registry,
/// the tag's parameter count.
fn weights_gb(node: &Value, model: &str) -> (Option<f64>, &'static str) {
    let size = |s: Option<&Value>| s.and_then(|s| s["size_bytes"].as_u64()).filter(|b| *b > 0);
    if let Some(b) = size(stat(node, model)) {
        return (Some(b as f64 / GB), "node-reported");
    }
    if let Some(b) = size(stat_in(node.get("model_size_hints"), model)) {
        return (Some(b as f64 / GB), "controller-store");
    }
    if let Some(b) = size(stat_in(node.get("fleet_model_stats"), model)) {
        return (Some(b as f64 / GB), "fleet-reported");
    }
    let n = norm(model);
    if let Some((_, g)) = KNOWN_WEIGHTS_GB.iter().find(|(m, _)| norm(m) == n) {
        return (Some(*g), "known");
    }
    if let Some(p) = params_b(model) {
        return (Some(p * GB_PER_BILLION_PARAMS), "from-name");
    }
    (None, "unknown")
}

/// Judge `specs` (every running placement that would exist on the node) against
/// the node's memory. `embed_ctx` is the gateway's `EMBED_NUM_CTX`.
///
/// `node` is the heartbeat record topped up by the route: `usage_profile`
/// (effective), `model_size_hints` and `fleet_model_stats` (lists of
/// `{name, size_bytes}`) are read when present.
pub fn evaluate(node: &Value, specs: &[Spec], embed_ctx: u64) -> Report {
    let usage = usage_of(node);
    let mut warnings: Vec<String> = Vec::new();
    // Daemon-wide parallelism: max OLLAMA_NUM_PARALLEL across ollama placements.
    let parallel = specs
        .iter()
        .filter(|s| s.backend == "ollama")
        .filter_map(|s| env_u64(&s.env, "OLLAMA_NUM_PARALLEL"))
        .max()
        .unwrap_or(1)
        .max(1);
    let gpu_pool = pool_for(node, "gpu");
    let mut rows = Vec::new();
    for s in specs {
        let mut notes = Vec::new();
        let target = resolve_target(s, node);
        if s.backend == "vllm" || s.backend == "vllm-secondary" {
            let util = env_str(&s.env, "GPU_MEMORY_UTILIZATION").and_then(|v| v.parse::<f64>().ok()).unwrap_or(VLLM_DEFAULT_UTIL);
            let total_budget = gpu_pool.as_ref().map(|b| b.total_gb).unwrap_or(0.0);
            rows.push(Row {
                backend: s.backend.clone(), role: s.role.clone(), model: s.model.clone(), target: "gpu",
                weights_gb: None, weights_source: "vllm", kv_gb: 0.0, overhead_gb: 0.0,
                total_gb: util * total_budget, source: "estimated",
                notes: vec![format!("vLLM reserves GPU_MEMORY_UTILIZATION {util} of the GPU")],
            });
            continue;
        }
        let (w, wsrc) = weights_gb(node, &s.model);
        let st = stat(node, &s.model);
        let measured = st.and_then(|x| x["resident_bytes"].as_u64()).filter(|b| *b > 0);
        let ctx = match s.role.as_str() {
            "embed" => embed_ctx,
            "rerank" => RERANK_CTX,
            _ => env_u64(&s.env, "OLLAMA_CONTEXT_LENGTH").or_else(|| env_u64(&s.env, "N_CTX")).unwrap_or(DEFAULT_CHAT_CTX),
        };
        let slots = if s.backend == "ollama" { parallel } else { env_u64(&s.env, "N_PARALLEL").unwrap_or(1).max(1) };
        let elem_bytes = match env_str(&s.env, "OLLAMA_KV_CACHE_TYPE").as_deref() {
            Some("q8_0") => 1.0,
            Some("q4_0") => 0.5,
            _ => 2.0,
        };
        let per_token = match st.and_then(|x| x.get("arch")).filter(|a| a.is_object()) {
            Some(a) => match (a["layers"].as_f64(), a["kv_heads"].as_f64(), a["head_dim"].as_f64()) {
                (Some(l), Some(h), Some(d)) => {
                    notes.push("KV from model architecture".into());
                    Some(l * h * d * 2.0 * elem_bytes)
                }
                _ => None,
            },
            None => None,
        };
        let per_token = per_token.or_else(|| {
            w.map(|w| {
                notes.push("KV from the conservative per-token figure (architecture not reported)".into());
                w * KV_BYTES_PER_TOKEN_PER_GB_WEIGHTS * (elem_bytes / 2.0)
            })
        });
        let kv_gb = per_token.map(|p| p * ctx as f64 * slots as f64 / GB).unwrap_or(0.0);
        let est_total = w.unwrap_or(0.0) + kv_gb + RUNTIME_OVERHEAD_GB;
        if w.is_none() && measured.is_none() {
            warnings.push(format!(
                "can't judge {}: no node reports its size, the controller model store has no file for it, and its tag names no parameter count",
                s.model
            ));
        }
        let (total, source) = match measured {
            Some(b) => {
                notes.push(format!("resident size measured on the node (ollama /api/ps); the estimate would be {est_total:.1} GB"));
                (b as f64 / GB, "measured")
            }
            None => (est_total, "estimated"),
        };
        notes.push(format!("weights {wsrc}; num_ctx {ctx} x {slots} slot(s); on {target}"));
        rows.push(Row {
            backend: s.backend.clone(), role: s.role.clone(), model: s.model.clone(), target,
            weights_gb: w, weights_source: wsrc, kv_gb, overhead_gb: RUNTIME_OVERHEAD_GB, total_gb: total, source, notes,
        });
    }

    // One verdict per pool that has rows charged to it.
    let mut pools = Vec::new();
    for target in ["gpu", "cpu"] {
        let mine: Vec<&Row> = rows.iter().filter(|r| r.target == target).collect();
        if mine.is_empty() {
            continue;
        }
        let used: f64 = mine.iter().map(|r| r.total_gb).sum();
        let unknown_size = mine.iter().any(|r| r.weights_gb.is_none() && r.source == "estimated" && r.weights_source != "vllm");
        let budget = pool_for(node, target);
        let (verdict, shortfall) = match &budget {
            None => {
                warnings.push(format!(
                    "can't judge the {target} placements: the node reports no {} (vram_gb / ram_gb)",
                    if target == "gpu" { "GPU memory" } else { "RAM" }
                ));
                (Verdict::Unknown, 0.0)
            }
            // What is known already does not fit: that stands, unknowns or not.
            Some(b) if used > b.total_gb => (Verdict::DoesNotFit, used - b.total_gb),
            Some(_) if unknown_size => (Verdict::Unknown, 0.0),
            Some(b) if used <= b.usable_gb() => (Verdict::Fits, 0.0),
            Some(b) => {
                warnings.push(format!(
                    "tight: {:.1} GB needed leaves {:.1} GB of the {:.1} GB {} budget, inside the {:.1} GB headroom",
                    used, b.total_gb - used, b.total_gb, b.kind, b.headroom_gb
                ));
                (Verdict::Tight, 0.0)
            }
        };
        pools.push(PoolReport { budget, target, used_gb: used, verdict, shortfall_gb: shortfall });
    }
    let verdict = if pools.is_empty() {
        // Nothing holds memory: judged against nothing, it fits - unless the
        // node reports no memory at all, which is unknown as before.
        if node_reports_memory(node) {
            Verdict::Fits
        } else {
            warnings.push("the node reports no memory (vram_gb / ram_gb): cannot judge the fit".into());
            Verdict::Unknown
        }
    } else {
        pools.iter().map(|p| p.verdict).max_by_key(|v| v.severity()).unwrap_or(Verdict::Fits)
    };
    let budget = pools.first().and_then(|p| p.budget.clone()).or_else(|| budget_for(node));
    let total: f64 = rows.iter().map(|r| r.total_gb).sum();
    let shortfall: f64 = pools.iter().map(|p| p.shortfall_gb).sum();
    Report { verdict, budget, pools, usage, rows, total_gb: total, shortfall_gb: shortfall, warnings }
}

impl Report {
    /// A one-paragraph refusal naming each over-budget pool, its models and
    /// the shortfall.
    pub fn refusal_message(&self, node_id: &str) -> String {
        let over: Vec<String> = self
            .pools
            .iter()
            .filter(|p| p.verdict == Verdict::DoesNotFit)
            .map(|p| {
                let per: Vec<String> = self
                    .rows
                    .iter()
                    .filter(|r| r.target == p.target)
                    .map(|r| format!("{} [{}] {:.1} GB ({})", r.model, r.role, r.total_gb, r.source))
                    .collect();
                let b = p.budget.as_ref();
                format!(
                    "on {}: {} need {:.1} GB, the {} budget is {:.1} GB ({:.1} GB headroom reserved): short by {:.1} GB",
                    p.target,
                    per.join(" + "),
                    p.used_gb,
                    b.map(|b| b.kind).unwrap_or("?"),
                    b.map(|b| b.total_gb).unwrap_or(0.0),
                    b.map(|b| b.headroom_gb).unwrap_or(0.0),
                    p.shortfall_gb
                )
            })
            .collect();
        format!(
            "these placements do not fit on {node_id}: {}. Free memory (unplace a role, a smaller model, \
             fewer OLLAMA_NUM_PARALLEL slots, another --on target) or pass force=true / --force to place anyway.",
            over.join("; ")
        )
    }

    pub fn to_json(&self) -> Value {
        let budget_json = |b: &Budget| json!({
            "kind": b.kind, "target": b.target, "total_gb": b.total_gb, "headroom_gb": b.headroom_gb, "usable_gb": b.usable_gb(),
        });
        json!({
            "verdict": self.verdict.as_str(),
            "budget": self.budget.as_ref().map(budget_json),
            "budgets": self.pools.iter().map(|p| {
                let mut v = p.budget.as_ref().map(budget_json).unwrap_or_else(|| json!({"target": p.target}));
                v["used_gb"] = json!(p.used_gb);
                v["verdict"] = json!(p.verdict.as_str());
                v["shortfall_gb"] = json!(p.shortfall_gb);
                v
            }).collect::<Vec<_>>(),
            "usage_profile": self.usage,
            "total_gb": self.total_gb,
            "shortfall_gb": self.shortfall_gb,
            "warnings": self.warnings,
            "models": self.rows.iter().map(|r| json!({
                "backend": r.backend, "role": r.role, "model": r.model, "target": r.target,
                "weights_gb": r.weights_gb, "weights_source": r.weights_source,
                "kv_gb": r.kv_gb, "overhead_gb": r.overhead_gb,
                "total_gb": r.total_gb, "source": r.source, "notes": r.notes,
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEMMA: &str = "gemma4:26b-a4b-it-qat";

    fn host6() -> Value {
        json!({"vram_gb": 18.0, "ram_gb": 24.0, "capabilities": {"unified_memory": true, "gpu_api": "metal"}})
    }

    fn spec(role: &str, model: &str, parallel: Option<&str>) -> Spec {
        let mut env = Map::new();
        if let Some(p) = parallel {
            env.insert("OLLAMA_NUM_PARALLEL".into(), json!(p));
        }
        Spec { backend: "ollama".into(), role: role.into(), model: model.into(), env, target: None }
    }

    fn llama(model: &str, target: Option<&str>, env: &[(&str, &str)]) -> Spec {
        let env = env.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
        Spec { backend: "llamacpp".into(), role: "chat".into(), model: model.into(), env, target: target.map(str::to_string) }
    }

    /// host8-shaped: a 6 GB discrete GPU and 32 GB of RAM.
    fn gpu6_ram32() -> Value {
        json!({"vram_gb": 6.0, "ram_gb": 32.0, "cpu_cores": 16})
    }

    /// The bug this pins: `noo cluster fit host8 --with llamacpp <26b> --env
    /// N_GPU_LAYERS=0` said "Budget 6.0 GB vram". A CPU placement draws on RAM.
    #[test]
    fn a_cpu_placement_is_budgeted_against_ram_not_vram() {
        let declared = evaluate(&gpu6_ram32(), &[llama(GEMMA, Some("cpu"), &[])], 1024);
        assert_eq!(declared.rows[0].target, "cpu");
        let b = declared.budget.as_ref().expect("a budget");
        assert_eq!((b.kind, b.target, b.total_gb), ("ram", "cpu", 32.0));
        assert_eq!(declared.verdict, Verdict::Fits, "{declared:#?}");
        // The pre-`--on` spelling: N_GPU_LAYERS=0 with no declared target.
        let legacy = evaluate(&gpu6_ram32(), &[llama(GEMMA, None, &[("N_GPU_LAYERS", "0")])], 1024);
        assert_eq!(legacy.rows[0].target, "cpu");
        assert_eq!(legacy.budget.as_ref().unwrap().kind, "ram");
        // The same model on the GPU does not fit 6 GB.
        let gpu = evaluate(&gpu6_ram32(), &[llama(GEMMA, Some("gpu"), &[])], 1024);
        assert_eq!(gpu.verdict, Verdict::DoesNotFit);
        assert!(gpu.refusal_message("host8").contains("on gpu"), "{}", gpu.refusal_message("host8"));
    }

    #[test]
    fn gpu_and_cpu_placements_are_judged_in_their_own_pools() {
        let r = evaluate(&gpu6_ram32(), &[spec("embed", "harrier", None), llama(GEMMA, Some("cpu"), &[])], 1024);
        assert_eq!(r.pools.len(), 2);
        let gpu = r.pools.iter().find(|p| p.target == "gpu").unwrap();
        let cpu = r.pools.iter().find(|p| p.target == "cpu").unwrap();
        assert!(gpu.used_gb < 2.0 && cpu.used_gb > 15.0, "{r:#?}");
        let j = r.to_json();
        assert_eq!(j["budgets"].as_array().unwrap().len(), 2);
        assert_eq!(j["models"][1]["target"], "cpu");
    }

    #[test]
    fn unified_memory_leaves_the_cpu_pool_what_the_gpu_share_does_not_take() {
        let b = pool_for(&host6(), "cpu").unwrap();
        assert_eq!((b.kind, b.total_gb), ("ram", 6.0));
    }

    #[test]
    fn a_node_without_a_gpu_runs_everything_on_cpu() {
        let cpu_only = json!({"ram_gb": 16.0});
        assert_eq!(resolve_target(&llama("m:7b", Some("gpu"), &[]), &cpu_only), "cpu");
        assert!(!node_has_gpu(&cpu_only) && node_reports_memory(&cpu_only));
    }

    #[test]
    fn a_shared_node_reserves_more_gpu_headroom() {
        let mut n = gpu6_ram32();
        assert!((pool_for(&n, "gpu").unwrap().headroom_gb - 1.0).abs() < 1e-9);
        n["usage_profile"] = json!("shared");
        assert!((pool_for(&n, "gpu").unwrap().headroom_gb - 2.0).abs() < 1e-9);
        // RAM headroom is the same either way.
        assert!((pool_for(&n, "cpu").unwrap().headroom_gb - 3.2).abs() < 1e-9);
        // Extra headroom turns fits into tight, never into does-not-fit.
        let mut node = json!({"vram_gb": 24.0, "model_stats": [{"name": "m:x", "size_bytes": 19_000_000_000u64}]});
        assert_eq!(evaluate(&node, &[spec("chat", "m:x", None)], 1024).verdict, Verdict::Fits);
        node["usage_profile"] = json!("shared");
        assert_eq!(evaluate(&node, &[spec("chat", "m:x", None)], 1024).verdict, Verdict::Tight);
    }

    #[test]
    fn the_llamacpp_memory_limit_follows_the_estimate_and_the_usage_cap() {
        let gb = |b: u64| b as f64 / 1e9;
        // 17.46 GB on cpu, dedicated 32 GB: the estimate rounded up to 17.5.
        let n = gpu6_ram32();
        let (b, why) = llamacpp_memory_limit(&n, 17.46, true, "cpu").unwrap();
        assert!((gb(b) - 17.5).abs() < 1e-9 && why.contains("fit estimate"), "{} {why}", gb(b));
        // Shared: at most half of 32 GB.
        let mut shared = n.clone();
        shared["usage_profile"] = json!("shared");
        let (b, why) = llamacpp_memory_limit(&shared, 17.46, true, "cpu").unwrap();
        assert!((gb(b) - 16.0).abs() < 1e-9 && why.contains("capped"), "{} {why}", gb(b));
        // Dedicated: RAM minus 4 GB.
        let (b, _) = llamacpp_memory_limit(&n, 40.0, true, "cpu").unwrap();
        assert!((gb(b) - 28.0).abs() < 1e-9);
        // A GPU placement never gets less than the old fixed 8 GiB.
        let (b, why) = llamacpp_memory_limit(&n, 3.0, true, "gpu").unwrap();
        assert_eq!(b, LLAMACPP_GPU_FLOOR_BYTES, "{why}");
        // A small CPU model gets its estimate.
        let (b, _) = llamacpp_memory_limit(&n, 2.2, true, "cpu").unwrap();
        assert!((gb(b) - 2.5).abs() < 1e-9);
        // Unknown size or unknown RAM: no limit, the agent keeps its default.
        assert!(llamacpp_memory_limit(&n, 0.6, false, "cpu").is_none());
        assert!(llamacpp_memory_limit(&json!({"vram_gb": 6.0}), 5.0, true, "cpu").is_none());
    }

    #[test]
    fn usage_defaults_dedicated_on_the_controller_and_shared_elsewhere() {
        assert_eq!(effective_usage(None, true).0, "dedicated");
        assert_eq!(effective_usage(None, false).0, "shared");
        assert_eq!(effective_usage(Some("shared"), true), ("shared", "set"));
        assert_eq!(effective_usage(Some("dedicated"), false), ("dedicated", "set"));
    }

    /// Weights come from this node, then the controller's store, then another
    /// node, then the name; with none of them the verdict is "can't judge",
    /// not "tight".
    #[test]
    fn weights_sources_in_order_and_an_unknown_size_is_cant_judge() {
        let file = "Mystery-Q4_K_M.gguf";
        let bare = json!({"vram_gb": 24.0});
        let r = evaluate(&bare, &[llama(file, None, &[])], 1024);
        assert_eq!(r.verdict, Verdict::Unknown, "{r:#?}");
        assert!(r.warnings.iter().any(|w| w.contains("can't judge") && w.contains(file)), "{:?}", r.warnings);

        let mut fleet = bare.clone();
        fleet["fleet_model_stats"] = json!([{"name": file, "size_bytes": 5_000_000_000u64}]);
        let r = evaluate(&fleet, &[llama(file, None, &[])], 1024);
        assert_eq!((r.rows[0].weights_source, r.verdict), ("fleet-reported", Verdict::Fits));

        let mut store = fleet.clone();
        store["model_size_hints"] = json!([{"name": file, "size_bytes": 4_000_000_000u64}]);
        let r = evaluate(&store, &[llama(file, None, &[])], 1024);
        assert_eq!(r.rows[0].weights_source, "controller-store");
        assert!((r.rows[0].weights_gb.unwrap() - 4.0).abs() < 1e-9);

        let mut own = store.clone();
        own["model_stats"] = json!([{"name": file, "size_bytes": 3_000_000_000u64}]);
        assert_eq!(evaluate(&own, &[llama(file, None, &[])], 1024).rows[0].weights_source, "node-reported");

        // Known parts that already overflow stay does-not-fit.
        let small = json!({"vram_gb": 6.0});
        let r = evaluate(&small, &[llama(file, Some("gpu"), &[]), spec("chat", GEMMA, None)], 1024);
        assert_eq!(r.verdict, Verdict::DoesNotFit);
    }

    #[test]
    fn a_zero_top_level_vram_falls_back_to_the_reported_unified_share() {
        // the live host6 record: top-level vram_gb 0, the GPU share only in capabilities
        let node = json!({"vram_gb": 0, "ram_gb": 24,
            "capabilities": {"unified_memory": true, "vram_gb": 18, "ram_gb": 24, "gpu_api": "metal"}});
        let b = budget_for(&node).expect("a budget");
        assert_eq!((b.kind, b.total_gb), ("unified", 18.0));
        // a CPU-only node that reports 0 VRAM everywhere still budgets RAM
        let cpu = json!({"vram_gb": 0, "ram_gb": 16, "capabilities": {"vram_gb": 0}});
        assert_eq!(budget_for(&cpu).map(|b| (b.kind, b.total_gb)), Some(("ram", 16.0)));
    }

    #[test]
    fn budget_is_the_unified_gpu_share_with_ten_percent_headroom() {
        let b = budget_for(&host6()).unwrap();
        assert_eq!((b.kind, b.total_gb), ("unified", 18.0));
        assert!((b.headroom_gb - 1.8).abs() < 1e-9);
        let small = budget_for(&json!({"vram_gb": 4.0})).unwrap();
        assert_eq!(small.headroom_gb, 1.0, "headroom floor is 1 GB");
        assert_eq!(budget_for(&json!({"ram_gb": 16.0})).unwrap().kind, "ram");
        assert!(budget_for(&json!({})).is_none());
    }

    #[test]
    fn host6_chat_plus_harrier_does_not_fit_18gb_unified() {
        // The worked example: 15.8 GB (assumed) weights + KV at 4096 ctx + 0.6
        // overhead, plus harrier 0.4 GB + KV at 1024 ctx + 0.6 overhead.
        let r = evaluate(&host6(), &[spec("chat", GEMMA, None), spec("embed", "harrier", None)], 1024);
        assert_eq!(r.verdict, Verdict::DoesNotFit, "{:#?}", r);
        assert!(r.shortfall_gb > 0.0 && r.total_gb > 18.0);
        let msg = r.refusal_message("host6");
        assert!(msg.contains("host6") && msg.contains("18.0 GB") && msg.contains("short by") && msg.contains(GEMMA) && msg.contains("harrier"), "{msg}");
    }

    /// The embed-capacity runbook's table, pinned.
    #[test]
    fn the_host6_worked_example_numbers_are_the_runbooks() {
        let close = |a: f64, b: f64| (a - b).abs() < 0.01;
        let chat_only = evaluate(&host6(), &[spec("chat", GEMMA, None)], 1024);
        assert!(close(chat_only.total_gb, 17.46) && chat_only.verdict == Verdict::Tight, "{chat_only:#?}");
        let one = evaluate(&host6(), &[spec("chat", GEMMA, None), spec("embed", "harrier", None)], 1024);
        assert!(close(one.total_gb, 18.47) && close(one.shortfall_gb, 0.47) && one.verdict == Verdict::DoesNotFit, "{one:#?}");
        let four = evaluate(&host6(), &[spec("chat", GEMMA, None), spec("embed", "harrier", Some("4"))], 1024);
        assert!(close(four.rows[0].total_gb, 20.64) && close(four.total_gb, 21.67) && close(four.shortfall_gb, 3.67), "{four:#?}");
        let mut trimmed = spec("chat", GEMMA, None);
        trimmed.env.insert("OLLAMA_CONTEXT_LENGTH".into(), json!("2048"));
        let t = evaluate(&host6(), &[trimmed, spec("embed", "harrier", None)], 1024);
        assert!(close(t.total_gb, 17.94) && t.verdict == Verdict::Tight, "{t:#?}");
    }

    #[test]
    fn four_embed_slots_charge_the_chat_model_four_kv_slots_too() {
        let one = evaluate(&host6(), &[spec("chat", GEMMA, None)], 1024);
        let four = evaluate(&host6(), &[spec("chat", GEMMA, None), spec("embed", "harrier", Some("4"))], 1024);
        assert!(four.rows[0].kv_gb > one.rows[0].kv_gb * 3.9, "daemon-wide OLLAMA_NUM_PARALLEL");
    }

    #[test]
    fn a_small_pair_fits_a_tight_pair_warns_an_oversized_pair_is_refused() {
        let big = json!({"vram_gb": 24.0});
        let fits = evaluate(&big, &[spec("chat", "qwen3:8b", None), spec("embed", "harrier", None)], 1024);
        assert_eq!(fits.verdict, Verdict::Fits);
        // 7 GB budget, 0.7 headroom: a 5 GB-weights model with KV+overhead lands in the headroom.
        let node = json!({"vram_gb": 7.0, "model_stats": [{"name": "m:1b", "size_bytes": 5_400_000_000u64}]});
        let tight = evaluate(&node, &[spec("chat", "m:1b", None)], 1024);
        assert_eq!(tight.verdict, Verdict::Tight, "{tight:#?}");
        assert!(tight.warnings.iter().any(|w| w.contains("tight")));
        let over = evaluate(&json!({"vram_gb": 6.0}), &[spec("chat", GEMMA, None)], 1024);
        assert_eq!(over.verdict, Verdict::DoesNotFit);
    }

    #[test]
    fn measured_resident_size_beats_the_estimate() {
        let mut node = host6();
        node["model_stats"] = json!([{"name": "harrier:latest", "size_bytes": 400_000_000u64, "resident_bytes": 1_100_000_000u64}]);
        let r = evaluate(&node, &[spec("embed", "harrier", Some("4"))], 1024);
        assert_eq!(r.rows[0].source, "measured");
        assert!((r.rows[0].total_gb - 1.1).abs() < 1e-9);
        let est = evaluate(&host6(), &[spec("embed", "harrier", Some("4"))], 1024);
        assert_eq!(est.rows[0].source, "estimated");
        assert!((est.rows[0].total_gb - 1.1).abs() < 0.15, "harrier estimate {} is near the 1.1 GB measured on host8", est.rows[0].total_gb);
    }

    #[test]
    fn architecture_metadata_replaces_the_conservative_figure() {
        let node = json!({"vram_gb": 24.0, "model_stats": [{"name": "m:7b", "size_bytes": 4_000_000_000u64,
            "arch": {"layers": 32, "kv_heads": 8, "head_dim": 128}}]});
        let r = evaluate(&node, &[spec("chat", "m:7b", None)], 1024);
        // 32 * 8 * 128 * 2 * 2 bytes = 131072 B/token * 4096 ctx = 0.537 GB
        assert!((r.rows[0].kv_gb - 0.536870912).abs() < 1e-6, "{}", r.rows[0].kv_gb);
    }

    #[test]
    fn no_reported_memory_is_unknown_not_refused() {
        let r = evaluate(&json!({}), &[spec("chat", GEMMA, None)], 1024);
        assert_eq!(r.verdict, Verdict::Unknown);
    }
}
