// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster place --on cpu|gpu` and the automatic tuning behind it.
//!
//! Pure: every decision here is made from values the caller fetched (the
//! node's reported hardware, its usage profile, the gateway's fit report), so
//! the mapping, the defaults and the arithmetic are tested without a gateway.
//!
//! ## The hardware target
//!
//! `--on cpu|gpu` is stored with the placement (the `target` column, migration
//! 088) and acted on by the node agent: a `cpu` container gets no GPU device
//! and `CUDA_VISIBLE_DEVICES` emptied. Per backend:
//!
//! * llamacpp: `cpu` also writes `N_GPU_LAYERS=0` into the placement env, so
//!   the choice is visible in `noo cluster desired` and an older agent that
//!   ignores `target` still offloads nothing; `gpu` removes a stored
//!   `N_GPU_LAYERS=0` (the agent's `auto` then offloads every layer);
//! * ollama: no env key - the daemon's device is the agent's to withhold
//!   (`num_gpu` is a per-request option and `CUDA_VISIBLE_DEVICES` is not on
//!   the placement allow-list, deliberately);
//! * vllm: refused on `cpu`.
//!
//! The default, with no `--on`: the target the placement already has (same
//! model); else `cpu` when its env pins `N_GPU_LAYERS=0`; else `gpu` when the
//! node has a GPU, `cpu` when it has none. `gpu` on a node without one is
//! refused.
//!
//! ## Tuning
//!
//! From the node's reported `cpu_cores` and the free memory the fit report
//! leaves in the target's pool, under the node's usage profile:
//!
//! | key | shared | dedicated |
//! |---|---|---|
//! | `N_THREADS` (llamacpp on cpu) | 25% of cores, at least 2 | cores - 2, at least 1 |
//! | `N_PARALLEL` / `OLLAMA_NUM_PARALLEL` | 1 | chat: 2 on gpu, 1 on cpu; embed: 4 |
//! | `N_BATCH` (llamacpp) | 256 cpu / 512 gpu | 512 cpu / 2048 gpu |
//! | `N_CTX` (llamacpp chat) | half the pool's free memory as KV | same |
//!
//! `N_CTX` uses the fit check's conservative KV figure (16 KiB per token per
//! slot per GB of weights) and is rounded down to a power of two in
//! [`MIN_CTX`, `MAX_CTX`]; without a model size or a pool it stays at the
//! backend default. An explicit `--env` always wins, and a key the placement
//! already carries for the same model and target is kept.

use serde_json::Value;

/// Conservative KV bytes per token per slot per GB of weights; the gateway's
/// `placement_fit::KV_BYTES_PER_TOKEN_PER_GB_WEIGHTS`.
pub const KV_BYTES_PER_TOKEN_PER_GB_WEIGHTS: f64 = 16.0 * 1024.0;
pub const MIN_CTX: u64 = 2048;
pub const MAX_CTX: u64 = 32768;
pub const DEFAULT_CTX: u64 = 4096;

/// What the node reports about itself (`GET /api/cluster/nodes`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Hardware {
    pub cpu_cores: Option<u64>,
    pub ram_gb: Option<f64>,
    pub vram_gb: Option<f64>,
}

impl Hardware {
    /// Read from a node record; capabilities first (the live heartbeat), the
    /// top-level fields as the fallback (the registry row of an offline node).
    pub fn of(node: &Value) -> Hardware {
        let caps = &node["capabilities"];
        let pos = |v: &Value| v.as_f64().filter(|x| *x > 0.0);
        Hardware {
            cpu_cores: caps["cpu_cores"].as_u64().or_else(|| node["cpu_cores"].as_u64()).filter(|c| *c > 0),
            ram_gb: pos(&caps["ram_gb"]).or_else(|| pos(&node["ram_gb"])),
            vram_gb: pos(&caps["vram_gb"]).or_else(|| pos(&node["vram_gb"])),
        }
    }

    /// `Some(true|false)` when the node reports memory; `None` when it reports
    /// nothing (unknown is not "no GPU").
    pub fn has_gpu(&self) -> Option<bool> {
        if self.vram_gb.is_some() {
            Some(true)
        } else if self.ram_gb.is_some() {
            Some(false)
        } else {
            None
        }
    }
}

fn is_vllm(backend: &str) -> bool {
    backend == "vllm" || backend == "vllm-secondary"
}

fn env_str(env: &Value, key: &str) -> Option<String> {
    match &env[key] {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The hardware target for a placement, or the refusal.
///
/// `on` is `--on`; `stored` is the target the placement already has for this
/// model; `env` is the env it would carry (stored merged with `--env`).
pub fn resolve_target(
    on: Option<&str>,
    backend: &str,
    hw: &Hardware,
    stored: Option<&str>,
    env: &Value,
) -> Result<&'static str, String> {
    let has_gpu = hw.has_gpu();
    let t = match on {
        Some("cpu") => "cpu",
        Some("gpu") => "gpu",
        Some(other) => return Err(format!("--on must be cpu or gpu, not {other:?}")),
        None => match stored {
            Some("cpu") => "cpu",
            Some("gpu") if has_gpu != Some(false) => "gpu",
            _ if env_str(env, "N_GPU_LAYERS").is_some_and(|v| v.trim() == "0") => "cpu",
            _ if has_gpu == Some(false) => "cpu",
            _ => "gpu",
        },
    };
    if t == "cpu" && is_vllm(backend) {
        return Err("vLLM runs on a GPU only; to run on cpu, place the model on llamacpp or ollama".into());
    }
    if t == "gpu" && has_gpu == Some(false) {
        return Err("this node reports no GPU; place it with --on cpu".into());
    }
    Ok(t)
}

/// The env changes a target implies for a backend (see the module docs).
/// `current` is the env the placement would otherwise carry.
pub fn target_env(backend: &str, target: &str, current: &Value) -> Vec<(String, Option<String>)> {
    if backend != "llamacpp" {
        return Vec::new();
    }
    match target {
        "cpu" => vec![("N_GPU_LAYERS".into(), Some("0".into()))],
        _ if env_str(current, "N_GPU_LAYERS").is_some_and(|v| v.trim() == "0") => vec![("N_GPU_LAYERS".into(), None)],
        _ => Vec::new(),
    }
}

/// Everything a tuning decision reads.
#[derive(Clone, Debug)]
pub struct TuneInput<'a> {
    pub backend: &'a str,
    pub role: &'a str,
    pub target: &'a str,
    /// `shared` | `dedicated`
    pub usage: &'a str,
    pub cpu_cores: Option<u64>,
    /// The model's weights, GB (from the fit report).
    pub weights_gb: Option<f64>,
    /// What the target's pool has left for this placement's KV cache, GB:
    /// usable minus everything else on it, minus the weights and overhead.
    pub free_gb: Option<f64>,
}

/// One tuned value and the reason, printed by `noo cluster place`.
#[derive(Clone, Debug, PartialEq)]
pub struct Choice {
    pub key: &'static str,
    pub value: String,
    pub why: String,
}

/// Threads for a CPU placement under a usage profile.
pub fn threads_for(usage: &str, cores: u64) -> (u64, String) {
    if usage == "shared" {
        let n = (cores / 4).max(2).min(cores.max(1));
        (n, format!("shared node: about 25% of {cores} cores, at least 2"))
    } else {
        let n = cores.saturating_sub(2).max(1);
        (n, format!("dedicated node: {cores} cores minus 2 for the system"))
    }
}

/// Parallel request slots under a usage profile.
pub fn parallel_for(usage: &str, role: &str, target: &str) -> (u64, String) {
    if usage == "shared" {
        return (1, "shared node: one request at a time".into());
    }
    match role {
        "embed" => (4, "dedicated node: embeddings are short; 4 at once".into()),
        "rerank" => (1, "rerank: one request at a time".into()),
        _ if target == "gpu" => (2, "dedicated GPU: 2 requests at once".into()),
        _ => (1, "dedicated CPU: one request at a time (CPU decode is memory-bound)".into()),
    }
}

/// Batch size for llama.cpp.
pub fn batch_for(usage: &str, target: &str) -> u64 {
    match (usage, target) {
        ("shared", "cpu") => 256,
        ("shared", _) => 512,
        (_, "cpu") => 512,
        _ => 2048,
    }
}

/// Context size sized from free memory: half of `free_gb` for KV, at the
/// conservative per-token figure, over `parallel` slots; a power of two in
/// [`MIN_CTX`, `MAX_CTX`].
pub fn ctx_for(weights_gb: Option<f64>, free_gb: Option<f64>, parallel: u64) -> (u64, String) {
    let (Some(w), Some(free)) = (weights_gb.filter(|w| *w > 0.0), free_gb) else {
        return (DEFAULT_CTX, "model size or free memory unknown: the backend default".into());
    };
    let per_token_gb = w * KV_BYTES_PER_TOKEN_PER_GB_WEIGHTS / 1e9;
    let kv_budget = (free * 0.5).max(0.0);
    let raw = kv_budget / (per_token_gb * parallel.max(1) as f64);
    if raw < MIN_CTX as f64 {
        return (MIN_CTX, format!("only {free:.1} GB free after the model: the minimum (fit will say if it is too tight)"));
    }
    let mut ctx = MIN_CTX;
    while ctx * 2 <= MAX_CTX && ((ctx * 2) as f64) <= raw {
        ctx *= 2;
    }
    (ctx, format!("half of the {free:.1} GB left after the model, at ~{:.0} KB/token x {parallel} slot(s)", per_token_gb * 1e6))
}

/// The tuned values for a placement (before `--env` and stored keys are
/// applied - see [`apply_choices`]).
pub fn tune(i: &TuneInput) -> Vec<Choice> {
    let mut out = Vec::new();
    match i.backend {
        "llamacpp" => {
            if i.target == "cpu" {
                if let Some(c) = i.cpu_cores {
                    let (n, why) = threads_for(i.usage, c);
                    out.push(Choice { key: "N_THREADS", value: n.to_string(), why });
                }
            }
            let (p, why) = parallel_for(i.usage, i.role, i.target);
            out.push(Choice { key: "N_PARALLEL", value: p.to_string(), why });
            let mut ctx = None;
            if i.role == "chat" {
                let (c, why) = ctx_for(i.weights_gb, i.free_gb, p);
                out.push(Choice { key: "N_CTX", value: c.to_string(), why });
                ctx = Some(c);
            }
            let b = batch_for(i.usage, i.target).min(ctx.unwrap_or(u64::MAX));
            out.push(Choice { key: "N_BATCH", value: b.to_string(), why: format!("{} node on {}", i.usage, i.target) });
        }
        "ollama" => {
            let (p, why) = parallel_for(i.usage, i.role, i.target);
            out.push(Choice { key: "OLLAMA_NUM_PARALLEL", value: p.to_string(), why: format!("{why} (daemon-wide: the max over the node's ollama roles)") });
        }
        _ => {}
    }
    out
}

/// What happened to one tuned key.
#[derive(Clone, Debug, PartialEq)]
pub enum Applied {
    /// Written into the placement env.
    Set(Choice),
    /// `--env` named the key; the operator's value stands.
    Explicit(&'static str),
    /// The placement already carries it for this model and target.
    Kept(&'static str, String),
}

/// Merge tuned choices under the explicit `--env` changes and the stored env.
/// `retune` is true when the target changed (stored tuning was sized for the
/// other hardware and is replaced).
pub fn apply_choices(
    choices: Vec<Choice>,
    explicit: &[(String, Option<String>)],
    stored: &Value,
    retune: bool,
) -> Vec<Applied> {
    choices
        .into_iter()
        .map(|c| {
            if explicit.iter().any(|(k, _)| k == c.key) {
                Applied::Explicit(c.key)
            } else if let (false, Some(v)) = (retune, env_str(stored, c.key)) {
                Applied::Kept(c.key, v)
            } else {
                Applied::Set(c)
            }
        })
        .collect()
}

/// Free memory, GB, the fit report leaves for this placement's KV cache in
/// `target`'s pool: usable - (everything charged to the pool) + (this row's
/// own KV, which the tuning is about to size). `None` when the report has no
/// such pool or no row for the placement.
pub fn free_for_kv(fit: &Value, backend: &str, role: &str, target: &str) -> Option<f64> {
    let pool = fit["budgets"].as_array()?.iter().find(|b| b["target"] == target)?;
    let usable = pool["usable_gb"].as_f64()?;
    let used = pool["used_gb"].as_f64()?;
    let row = fit["models"].as_array()?.iter().find(|m| m["backend"] == backend && m["role"] == role)?;
    // A measured row has no separable KV; treat its whole size as fixed.
    let kv = if row["source"] == "measured" { 0.0 } else { row["kv_gb"].as_f64().unwrap_or(0.0) };
    Some(usable - used + kv)
}

/// The weights of this placement's row in a fit report.
pub fn weights_in(fit: &Value, backend: &str, role: &str) -> Option<f64> {
    fit["models"].as_array()?.iter().find(|m| m["backend"] == backend && m["role"] == role)?["weights_gb"].as_f64()
}

/// The controller model store: `MODELS_DIR`, else `<NOO_DATA_ROOT>/models`
/// (the resolution `noo cluster sync-model-files` uses).
pub fn model_store() -> std::path::PathBuf {
    let store = std::env::var("MODELS_DIR").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| {
        let root = std::env::var("NOO_DATA_ROOT")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.into());
        format!("{}/models", root.trim_end_matches('/'))
    });
    std::path::PathBuf::from(store)
}

/// The size of `model`'s file in the controller store, if there is one: the
/// GGUF a llama.cpp placement names (`x.gguf` or `/models/x.gguf`), or a
/// published `<name>.gguf` for an ollama import.
pub fn store_size_bytes(store: &std::path::Path, model: &str) -> Option<u64> {
    let base = std::path::Path::new(model).file_name()?.to_str()?;
    if base.is_empty() || base.contains("..") {
        return None;
    }
    let mut candidates = vec![store.join(base)];
    if !base.ends_with(".gguf") {
        candidates.push(store.join(format!("{}.gguf", base.replace(':', "-"))));
    }
    candidates
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .find(|m| m.is_file() && m.len() > 0)
        .map(|m| m.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hw(cores: u64, ram: f64, vram: Option<f64>) -> Hardware {
        Hardware { cpu_cores: Some(cores), ram_gb: Some(ram), vram_gb: vram }
    }

    #[test]
    fn hardware_reads_capabilities_then_the_registry_row() {
        let live = json!({"capabilities": {"cpu_cores": 16, "ram_gb": 32.0, "vram_gb": 6.0}});
        assert_eq!(Hardware::of(&live), hw(16, 32.0, Some(6.0)));
        let offline = json!({"cpu_cores": 4, "ram_gb": 8.0, "vram_gb": 0.0});
        assert_eq!(Hardware::of(&offline), hw(4, 8.0, None));
        assert_eq!(Hardware::of(&offline).has_gpu(), Some(false));
        assert_eq!(Hardware::of(&json!({})).has_gpu(), None, "reports nothing: unknown, not no-GPU");
    }

    #[test]
    fn the_target_defaults_to_gpu_where_there_is_one_and_refuses_the_impossible() {
        let gpu = hw(16, 32.0, Some(6.0));
        let cpu_only = hw(4, 8.0, None);
        let none = json!({});
        assert_eq!(resolve_target(None, "llamacpp", &gpu, None, &none), Ok("gpu"));
        assert_eq!(resolve_target(None, "ollama", &cpu_only, None, &none), Ok("cpu"));
        assert_eq!(resolve_target(Some("cpu"), "llamacpp", &gpu, None, &none), Ok("cpu"));
        assert!(resolve_target(Some("cpu"), "vllm", &gpu, None, &none).unwrap_err().contains("vLLM runs on a GPU only"));
        assert!(resolve_target(Some("gpu"), "ollama", &cpu_only, None, &none).unwrap_err().contains("no GPU"));
        assert!(resolve_target(Some("tpu"), "ollama", &gpu, None, &none).is_err());
        // Unknown hardware is not refused.
        assert_eq!(resolve_target(Some("gpu"), "ollama", &Hardware::default(), None, &none), Ok("gpu"));
    }

    /// A re-place without --on must not flip an existing CPU placement to GPU.
    #[test]
    fn with_no_flag_the_stored_target_or_a_pinned_n_gpu_layers_wins() {
        let gpu = hw(16, 32.0, Some(6.0));
        assert_eq!(resolve_target(None, "llamacpp", &gpu, Some("cpu"), &json!({})), Ok("cpu"));
        assert_eq!(resolve_target(None, "llamacpp", &gpu, None, &json!({"N_GPU_LAYERS": "0"})), Ok("cpu"));
        assert_eq!(resolve_target(None, "llamacpp", &gpu, None, &json!({"N_GPU_LAYERS": "999"})), Ok("gpu"));
    }

    #[test]
    fn cpu_maps_to_backend_settings() {
        assert_eq!(target_env("llamacpp", "cpu", &json!({})), vec![("N_GPU_LAYERS".to_string(), Some("0".to_string()))]);
        assert_eq!(target_env("llamacpp", "gpu", &json!({"N_GPU_LAYERS": "0"})), vec![("N_GPU_LAYERS".to_string(), None)], "gpu clears a stored cpu pin");
        assert!(target_env("llamacpp", "gpu", &json!({"N_GPU_LAYERS": "20"})).is_empty(), "a partial offload is the operator's");
        assert!(target_env("ollama", "cpu", &json!({})).is_empty(), "ollama's device is the agent's to withhold, not an env key");
    }

    #[test]
    fn threads_follow_the_usage_profile() {
        assert_eq!(threads_for("shared", 16).0, 4);
        assert_eq!(threads_for("shared", 4).0, 2, "at least 2");
        assert_eq!(threads_for("shared", 1).0, 1, "never more than the cores");
        assert_eq!(threads_for("dedicated", 16).0, 14);
        assert_eq!(threads_for("dedicated", 2).0, 1);
    }

    #[test]
    fn parallel_and_batch_follow_the_profile_role_and_target() {
        assert_eq!(parallel_for("shared", "embed", "gpu").0, 1);
        assert_eq!(parallel_for("dedicated", "embed", "cpu").0, 4);
        assert_eq!(parallel_for("dedicated", "chat", "gpu").0, 2);
        assert_eq!(parallel_for("dedicated", "chat", "cpu").0, 1);
        assert_eq!(batch_for("shared", "cpu"), 256);
        assert_eq!(batch_for("dedicated", "gpu"), 2048);
    }

    #[test]
    fn context_is_sized_from_free_memory_and_clamped() {
        // 15.8 GB weights: ~259 KB/token. 20 GB free -> 10 GB for KV -> ~38.6k tokens -> 32768.
        assert_eq!(ctx_for(Some(15.8), Some(20.0), 1).0, 32768);
        // Two slots halve it: ~19.3k -> 16384.
        assert_eq!(ctx_for(Some(15.8), Some(20.0), 2).0, 16384);
        // 2 GB free -> 1 GB KV -> ~3.9k -> 2048.
        assert_eq!(ctx_for(Some(15.8), Some(2.0), 1).0, 2048);
        // Nearly full: the minimum, and says so.
        let (c, why) = ctx_for(Some(15.8), Some(0.1), 1);
        assert!(c == MIN_CTX && why.contains("minimum"), "{why}");
        // Unknown: the default.
        assert_eq!(ctx_for(None, Some(20.0), 1).0, DEFAULT_CTX);
        assert_eq!(ctx_for(Some(4.0), None, 1).0, DEFAULT_CTX);
    }

    #[test]
    fn a_shared_16_core_cpu_placement_tunes_threads_slots_ctx_and_batch() {
        let i = TuneInput { backend: "llamacpp", role: "chat", target: "cpu", usage: "shared", cpu_cores: Some(16), weights_gb: Some(15.8), free_gb: Some(10.0) };
        let got: Vec<(&str, String)> = tune(&i).into_iter().map(|c| (c.key, c.value)).collect();
        assert_eq!(got, vec![
            ("N_THREADS", "4".to_string()),
            ("N_PARALLEL", "1".to_string()),
            ("N_CTX", "16384".to_string()),
            ("N_BATCH", "256".to_string()),
        ]);
        // On a GPU no thread count is chosen; ollama only gets its slot count.
        let g = TuneInput { target: "gpu", usage: "dedicated", ..i.clone() };
        assert!(tune(&g).iter().all(|c| c.key != "N_THREADS"));
        let o = TuneInput { backend: "ollama", role: "embed", usage: "dedicated", ..i };
        let keys: Vec<_> = tune(&o).into_iter().map(|c| (c.key, c.value)).collect();
        assert_eq!(keys, vec![("OLLAMA_NUM_PARALLEL", "4".to_string())]);
    }

    #[test]
    fn explicit_env_wins_and_stored_keys_are_kept_unless_the_target_changed() {
        let choices = vec![
            Choice { key: "N_THREADS", value: "4".into(), why: String::new() },
            Choice { key: "N_CTX", value: "8192".into(), why: String::new() },
            Choice { key: "N_BATCH", value: "256".into(), why: String::new() },
        ];
        let explicit = vec![("N_THREADS".to_string(), Some("12".to_string()))];
        let stored = json!({"N_CTX": "4096"});
        let a = apply_choices(choices.clone(), &explicit, &stored, false);
        assert_eq!(a[0], Applied::Explicit("N_THREADS"));
        assert_eq!(a[1], Applied::Kept("N_CTX", "4096".into()));
        assert!(matches!(&a[2], Applied::Set(c) if c.key == "N_BATCH"));
        let retuned = apply_choices(choices, &explicit, &stored, true);
        assert!(matches!(&retuned[1], Applied::Set(c) if c.value == "8192"), "a target change re-tunes");
        assert_eq!(retuned[0], Applied::Explicit("N_THREADS"), "explicit still wins");
    }

    #[test]
    fn free_memory_comes_from_the_fit_reports_pool_and_row() {
        let fit = json!({
            "budgets": [{"target": "cpu", "usable_gb": 28.8, "used_gb": 19.0}],
            "models": [
                {"backend": "ollama", "role": "embed", "target": "cpu", "kv_gb": 0.1, "total_gb": 1.0, "source": "estimated"},
                {"backend": "llamacpp", "role": "chat", "target": "cpu", "weights_gb": 15.8, "kv_gb": 1.06, "total_gb": 18.0, "source": "estimated"}]});
        let free = free_for_kv(&fit, "llamacpp", "chat", "cpu").unwrap();
        assert!((free - (28.8 - 19.0 + 1.06)).abs() < 1e-9, "{free}");
        assert_eq!(weights_in(&fit, "llamacpp", "chat"), Some(15.8));
        assert_eq!(free_for_kv(&fit, "llamacpp", "chat", "gpu"), None);
    }

    #[test]
    fn the_store_size_is_the_gguf_files() {
        let dir = std::env::temp_dir().join(format!("noo-tune-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("m-Q4_K_M.gguf"), vec![0u8; 1234]).unwrap();
        std::fs::write(dir.join("published-1b.gguf"), vec![0u8; 99]).unwrap();
        assert_eq!(store_size_bytes(&dir, "m-Q4_K_M.gguf"), Some(1234));
        assert_eq!(store_size_bytes(&dir, "/models/m-Q4_K_M.gguf"), Some(1234), "the in-container path names the same file");
        assert_eq!(store_size_bytes(&dir, "published:1b"), Some(99), "an ollama name finds its published gguf");
        assert_eq!(store_size_bytes(&dir, "absent.gguf"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
