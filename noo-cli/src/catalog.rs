// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Model catalog — Rust port of `noomesh/cluster/model_catalog.py`.
//!
//! Live-fetching model catalog that queries HuggingFace for current models,
//! classifies them by tier/backend, caches results locally
//! (`~/.config/mesh/model_cache.json`, 24h TTL — the SAME file the Python
//! CLI uses, so the two sides share freshness), and falls back to a minimal
//! offline list when the API is unreachable.
//!
//! HF endpoint override: `HF_ENDPOINT` (the standard huggingface_hub env
//! var) — used by the integration tests to point at a mock server.
//!
//! Approved-vendor / approved-task governance (US-vendor focus) is ported
//! 1:1: `NOO_MODEL_VENDORS`, `NOO_MODEL_TASKS`,
//! `NOO_MODEL_FILTER_MODE` (strict — default — | prefer | off).

use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

pub const CACHE_TTL_HOURS: f64 = 24.0;

// ---------------------------------------------------------------------------
// Approved-vendor / approved-task model governance
// ---------------------------------------------------------------------------

/// family (lowercase) → vendor label. Order matters for first-match labeling.
const DEFAULT_VENDORS: &[(&str, &str)] = &[
    ("gemma-4", "Google"), // gemma-4 series ONLY (not gemma-3/gemma-2)
    ("gemma4", "Google"),  // unhyphenated spelling (Ollama tags, some re-uploads)
    ("phi", "Microsoft"),
    ("harrier", "Microsoft"),
    ("nemotron", "Nvidia"),
    ("minitron", "Nvidia"),
    ("llama", "Meta"),
    ("inkling", "Thinking Machines"),
];

const DEFAULT_TASKS: &[&str] = &[
    "text-generation",
    "image-text-to-text", // Gemma 4 31B/26B, Inkling — vision-capable chat models
    "feature-extraction",
    "sentence-similarity",
    "automatic-speech-recognition", // Nemotron ASR
    "any-to-any",                   // Nemotron Omni, Gemma 4 E2B/E4B/12B (multimodal)
];

/// HF orgs owned by each vendor. Google is intentionally OMITTED (approve
/// only the `gemma-4` family, not every google/ model).
const VENDOR_ORGS: &[(&str, &[&str])] = &[
    ("Microsoft", &["microsoft"]),
    ("Nvidia", &["nvidia"]),
    ("Meta", &["meta-llama", "meta"]),
    ("Thinking Machines", &["thinkingmachines"]),
];

// ---------------------------------------------------------------------------
// Publisher trust — WHO uploaded the repo, independent of WHOSE model it is
// ---------------------------------------------------------------------------
//
// Download count alone ranks a prolific third-party quantizer above the
// vendor's own upload. Three tiers, primary sort key ahead of downloads:
//   1  first-party  — the vendor's own org (google/, nvidia/, microsoft/ …)
//   2  trusted      — well-known quantizer accounts (curated, overridable)
//   3  other        — everyone else (unknown accounts, abliterated forks)
// Ranking, not filtering, is the default: a first-party repo is often the
// unquantized bf16 release, and for some model/backend pairs a third-party
// quant is the only option.

pub const TRUST_FIRST_PARTY: i64 = 1;
pub const TRUST_TRUSTED: i64 = 2;
pub const TRUST_OTHER: i64 = 3;

/// First-party orgs beyond `VENDOR_ORGS` — Google is a first-party
/// PUBLISHER even though it is deliberately not an approved ORG (the vendor
/// axis admits only the gemma-4 family).
const EXTRA_FIRST_PARTY_ORGS: &[&str] = &["google"];

/// Quantizer / re-upload accounts with a track record. `NOO_MODEL_PUBLISHERS`
/// (comma list) replaces this list; first-party orgs never need listing.
const DEFAULT_TRUSTED_PUBLISHERS: &[&str] = &[
    "unsloth",
    "bartowski",
    "lmstudio-community",
    "hugging-quants",
    "ggml-org",
    "redhatai",
    "maziyarpanahi",
    "ista-daslab",
    "mlx-community",
];

fn trusted_publishers() -> Vec<String> {
    let raw = std::env::var("NOO_MODEL_PUBLISHERS").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return DEFAULT_TRUSTED_PUBLISHERS.iter().map(|s| s.to_string()).collect();
    }
    raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_lowercase).collect()
}

fn is_first_party_org(org: &str) -> bool {
    EXTRA_FIRST_PARTY_ORGS.contains(&org) || VENDOR_ORGS.iter().any(|(_, orgs)| orgs.contains(&org))
}

/// (publisher, trust tier) for a model id. Ollama-library style ids with no
/// org (`phi4`, `llama3.1:8b`) are the curated fallback entries — first-party.
pub fn publisher_trust(model_id: &str) -> (String, i64) {
    let mid = model_id.to_lowercase();
    let Some((org, _)) = mid.split_once('/') else {
        return ("library".to_string(), TRUST_FIRST_PARTY);
    };
    let tier = if is_first_party_org(org) {
        TRUST_FIRST_PARTY
    } else if trusted_publishers().iter().any(|p| p == org) {
        TRUST_TRUSTED
    } else {
        TRUST_OTHER
    };
    (org.to_string(), tier)
}

pub fn trust_label(tier: i64) -> &'static str {
    match tier {
        TRUST_FIRST_PARTY => "first-party",
        TRUST_TRUSTED => "trusted",
        _ => "other",
    }
}

/// Annotate `publisher` / `trust` and order by trust tier, then downloads.
/// `NOO_MODEL_PUBLISHER_MODE`: prefer (default) ranks; strict also drops
/// tier-3 repos; off leaves the download order untouched.
fn rank_by_publisher(models: &mut Vec<Value>) {
    let mode = std::env::var("NOO_MODEL_PUBLISHER_MODE")
        .unwrap_or_else(|_| "prefer".into())
        .trim()
        .to_lowercase();
    for m in models.iter_mut() {
        let (publisher, tier) = publisher_trust(m["id"].as_str().unwrap_or(""));
        m["publisher"] = json!(publisher);
        m["trust"] = json!(tier);
    }
    if mode == "off" {
        return;
    }
    if mode == "strict" {
        models.retain(|m| m["trust"].as_i64().unwrap_or(TRUST_OTHER) < TRUST_OTHER);
    }
    // Stable: equal (trust, downloads) keeps the incoming order.
    models.sort_by(|a, b| {
        let ta = a["trust"].as_i64().unwrap_or(TRUST_OTHER);
        let tb = b["trust"].as_i64().unwrap_or(TRUST_OTHER);
        ta.cmp(&tb)
            .then_with(|| b["downloads"].as_i64().unwrap_or(0).cmp(&a["downloads"].as_i64().unwrap_or(0)))
    });
}

/// (family, vendor-label) pairs, honoring `NOO_MODEL_VENDORS`.
fn approved_vendors() -> Vec<(String, String)> {
    let raw = std::env::var("NOO_MODEL_VENDORS").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return DEFAULT_VENDORS.iter().map(|(f, l)| (f.to_string(), l.to_string())).collect();
    }
    raw.split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(|f| {
            let fam = f.to_lowercase();
            let label = DEFAULT_VENDORS
                .iter()
                .find(|(df, _)| *df == fam)
                .map(|(_, l)| l.to_string())
                .unwrap_or_else(|| f.to_string());
            (fam, label)
        })
        .collect()
}

fn approved_tasks() -> Vec<String> {
    let raw = std::env::var("NOO_MODEL_TASKS").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return DEFAULT_TASKS.iter().map(|s| s.to_string()).collect();
    }
    raw.split(',').map(str::trim).filter(|t| !t.is_empty()).map(str::to_string).collect()
}

/// HF org → vendor label, derived from the currently-approved vendors.
fn approved_orgs() -> Vec<(String, String)> {
    let labels: Vec<String> = approved_vendors().into_iter().map(|(_, l)| l).collect();
    let mut out = Vec::new();
    for (label, orgs) in VENDOR_ORGS {
        if labels.iter().any(|l| l == label) {
            for org in *orgs {
                out.push((org.to_string(), label.to_string()));
            }
        }
    }
    out
}

/// True when `fam` occurs in `name` as a family token: followed by the end
/// of the name or a non-letter (`phi-4`, `phi4`, `Phi-3.5`), never as a
/// prefix of a longer word (`philai`, `philbert`).
fn family_in(name: &str, fam: &str) -> bool {
    name.match_indices(fam)
        .any(|(i, _)| name[i + fam.len()..].chars().next().is_none_or(|c| !c.is_ascii_alphabetic()))
}

/// Vendor label for a model id via its HF org or an approved family name in
/// the repo-name part of the id (so quant re-uploads still resolve to their
/// vendor). The org part is only consulted against `VENDOR_ORGS` — a family
/// substring in a user name (`philbert440/Qwen…`) is not a vendor signal.
pub fn model_vendor(model_id: &str) -> Option<String> {
    let mid = model_id.to_lowercase();
    if let Some((org, _)) = mid.split_once('/') {
        if let Some((_, label)) = approved_orgs().iter().find(|(o, _)| o == org) {
            return Some(label.clone());
        }
    }
    let name = mid.rsplit('/').next().unwrap_or(&mid);
    for (fam, label) in approved_vendors() {
        if family_in(name, &fam) {
            return Some(label);
        }
    }
    None
}

fn backend_task(backend: Option<&str>) -> &'static str {
    if backend == Some("embedding") {
        "feature-extraction"
    } else {
        "text-generation"
    }
}

fn is_approved(model: &Value, backend: Option<&str>) -> bool {
    if model_vendor(model["id"].as_str().unwrap_or("")).is_none() {
        return false;
    }
    let task = model["pipeline_tag"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| backend_task(backend).to_string());
    let tasks = approved_tasks();
    !(!task.is_empty() && !tasks.is_empty() && !tasks.contains(&task))
}

/// Apply the vendor+task allow-list, then publisher ranking. strict →
/// approved only; prefer → approved first with the rest tagged unapproved;
/// off → passthrough. Every read path (cache, stale cache, live, offline)
/// goes through here, so this is where the catalog's order is decided.
pub fn filter_approved(models: Vec<Value>, backend: Option<&str>) -> Vec<Value> {
    let mode = std::env::var("NOO_MODEL_FILTER_MODE")
        .unwrap_or_else(|_| "strict".into())
        .trim()
        .to_lowercase();
    if mode == "off" {
        let mut all = models;
        rank_by_publisher(&mut all);
        return all;
    }
    let mut approved = Vec::new();
    let mut rest = Vec::new();
    for mut m in models {
        if is_approved(&m, backend) {
            if let Some(v) = model_vendor(m["id"].as_str().unwrap_or("")) {
                m["vendor"] = Value::String(v);
            }
            approved.push(m);
        } else {
            rest.push(m);
        }
    }
    rank_by_publisher(&mut approved);
    if mode == "prefer" {
        rank_by_publisher(&mut rest);
        for m in &mut rest {
            m["unapproved"] = Value::Bool(true);
        }
        approved.extend(rest);
        return approved;
    }
    approved // strict
}

/// Backends the catalog knows how to search for, in Python dict order.
pub const ALL_SEARCH_BACKENDS: &[&str] = &["vllm", "llamacpp", "ollama", "airllm", "embedding"];

/// Backend-specific HF search strategies — vendor-targeted so the live HF
/// fetch surfaces approved families first.
///
/// The query is family + format only. HF `search` ANDs every token against
/// the repo id, and most approved families do not spell "instruct" in the
/// id (Google uses `-it`, Phi-4 / Nemotron-3 / Inkling carry no suffix at
/// all) — an "instruct" token silently reduced the catalog to Llama plus a
/// couple of Phi minis.
fn backend_searches(backend: &str) -> Vec<String> {
    let fams: Vec<String> = approved_vendors().into_iter().map(|(f, _)| f).collect();
    let mk = |suffix: &str| fams.iter().map(|f| format!("{f} {suffix}")).collect::<Vec<_>>();
    match backend {
        "vllm" => {
            let mut v = mk("AWQ");
            v.extend(mk("GPTQ"));
            v
        }
        "llamacpp" | "ollama" => mk("GGUF"),
        "airllm" => mk("safetensors"),
        "embedding" => {
            // "embed" rather than "embedding": first-party embedders are
            // `NV-Embed-v2`, `Nemotron-3-Embed-1B`, `llama-nemotron-embed-…`.
            // Org-scoped queries catch the ones that carry no family name.
            let mut v = mk("embed");
            v.extend(approved_orgs().into_iter().map(|(org, _)| format!("{org} embed")));
            v
        }
        _ => Vec::new(),
    }
}

/// Pipeline tags that make sense for a backend. HF's `filter=` is an AND
/// over tags, so the task axis is applied client-side instead: a single
/// `filter=text-generation` on the request dropped every vision-capable
/// chat model (Gemma 4 is `image-text-to-text` / `any-to-any`) and, for the
/// embedding backend, every actual embedding model.
fn task_fits_backend(pipeline_tag: Option<&str>, backend: &str) -> bool {
    let Some(tag) = pipeline_tag.filter(|t| !t.is_empty()) else {
        return true; // untagged → the backend default applies in is_approved
    };
    let embed = matches!(tag, "feature-extraction" | "sentence-similarity");
    if backend == "embedding" {
        embed
    } else {
        !embed
    }
}

// ---------------------------------------------------------------------------
// Pattern helpers (hand-rolled ports of the Python regexes)
// ---------------------------------------------------------------------------

/// Port of `_PARAM_RE = (\d+(?:\.\d+)?)\s*[Bb]` — leftmost match wins,
/// with regex-style backtracking (greedy fraction, then without).
fn find_param_count(s: &str) -> Option<f64> {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    for start in 0..n {
        if !chars[start].is_ascii_digit() {
            continue;
        }
        let mut end = start;
        while end < n && chars[end].is_ascii_digit() {
            end += 1;
        }
        // candidate ends: with fractional part first (greedy), then without.
        let mut candidates = Vec::new();
        if end < n && chars[end] == '.' {
            let mut fend = end + 1;
            while fend < n && chars[fend].is_ascii_digit() {
                fend += 1;
            }
            if fend > end + 1 {
                candidates.push(fend);
            }
        }
        candidates.push(end);
        for cand in candidates {
            let mut i = cand;
            while i < n && chars[i].is_whitespace() {
                i += 1;
            }
            if i < n && (chars[i] == 'B' || chars[i] == 'b') {
                let num: String = chars[start..cand].iter().collect();
                if let Ok(v) = num.parse::<f64>() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Extract parameter count (in billions) from model name or tags.
pub fn extract_param_count(model_id: &str, tags: &[String]) -> Option<f64> {
    if let Some(v) = find_param_count(model_id) {
        return Some(v);
    }
    for t in tags {
        if let Some(v) = find_param_count(t) {
            return Some(v);
        }
    }
    None
}

/// Port of `_QUANT_RE` fallback branch: `Q[2-8]_[KSM0-9_]+` (any case) or
/// the literal word "quant" — leftmost alternation, uppercased.
fn find_quant_token(s: &str) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let is_tail = |c: char| matches!(c.to_ascii_uppercase(), 'K' | 'S' | 'M' | '0'..='9' | '_');
    for i in 0..n {
        // Alternative 1: Q[2-8]_[KSM0-9_]+
        if (chars[i] == 'Q' || chars[i] == 'q')
            && i + 2 < n
            && ('2'..='8').contains(&chars[i + 1])
            && chars[i + 2] == '_'
            && i + 3 < n
            && is_tail(chars[i + 3])
        {
            let mut end = i + 3;
            while end < n && is_tail(chars[end]) {
                end += 1;
            }
            let tok: String = chars[i..end].iter().collect();
            return Some(tok.to_uppercase());
        }
        // Alternative 2: [Qq]uant
        if (chars[i] == 'Q' || chars[i] == 'q') && i + 5 <= n {
            let word: String = chars[i + 1..i + 5].iter().collect();
            if word == "uant" {
                return Some("QUANT".to_string());
            }
        }
    }
    None
}

/// Port of `_HEAVY_QUANT_RE = Q[23]_[KSM]` (case-insensitive).
fn is_heavy_quant(quant: &str) -> bool {
    let q = quant.to_lowercase();
    let bytes: Vec<char> = q.chars().collect();
    for i in 0..bytes.len().saturating_sub(3) {
        if bytes[i] == 'q'
            && (bytes[i + 1] == '2' || bytes[i + 1] == '3')
            && bytes[i + 2] == '_'
            && matches!(bytes[i + 3], 'k' | 's' | 'm')
        {
            return true;
        }
    }
    false
}

/// Detect quantization type from model id / tags.
pub fn detect_quant(model_id: &str, tags: &[String]) -> Option<String> {
    let combined = format!("{model_id} {}", tags.join(" "));
    let lower = combined.to_lowercase();
    if lower.contains("awq") {
        return Some("AWQ".into());
    }
    if lower.contains("gptq") {
        return Some("GPTQ".into());
    }
    if lower.contains("exl2") {
        return Some("EXL2".into());
    }
    if lower.contains("gguf") {
        return Some("GGUF".into());
    }
    find_quant_token(&combined)
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

/// Assign a hardware tier (1/2/3) from parameter count and quantization.
pub fn classify_tier(params_b: Option<f64>, quant: Option<&str>) -> i64 {
    let Some(p) = params_b else { return 1 };
    let heavy = quant.map(is_heavy_quant).unwrap_or(false);
    if p <= 3.0 {
        return 3;
    }
    if p <= 7.0 {
        if heavy {
            return 3;
        }
        return 2;
    }
    1 // 7-14B and 14B+ (quantized or not) → tier 1, matching Python
}

/// True for arm/aarch64 CPU architectures (edge boards, Apple silicon).
pub fn is_arm(arch: Option<&str>) -> bool {
    let a = arch.unwrap_or("").to_lowercase();
    a.contains("arm") || a.contains("aarch")
}

/// Inference backends compatible with a node's hardware tier + CPU arch.
/// arm/aarch64 nodes drop GPU/x86-only backends (vllm, airllm).
pub fn backends_for(tier: i64, arch: Option<&str>) -> Vec<&'static str> {
    let base: Vec<&'static str> = if tier <= 1 {
        vec!["vllm", "llamacpp", "ollama", "airllm"]
    } else if tier == 2 {
        vec!["vllm", "llamacpp", "ollama"]
    } else {
        vec!["llamacpp", "ollama"] // 3 CPU, 4 edge, 5 companion — GGUF only
    };
    if is_arm(arch) {
        base.into_iter().filter(|b| *b != "vllm" && *b != "airllm").collect()
    } else {
        base
    }
}

/// Which model size-class (classify_tier value) to recommend for a hardware
/// tier. None = no cap (tier 1 runs anything).
pub fn model_class_for(tier: i64) -> Option<i64> {
    if tier <= 1 {
        None
    } else if tier == 2 {
        Some(2)
    } else {
        Some(3)
    }
}

/// Determine which backends can run this model from HF tags/files.
pub fn detect_backend_compat(tags: &[String], siblings: Option<&Vec<Value>>) -> Vec<String> {
    let tags_lower: Vec<String> = tags.iter().map(|t| t.to_lowercase()).collect();
    let file_names: Vec<String> = siblings
        .map(|sib| {
            sib.iter()
                .map(|s| s["rfilename"].as_str().unwrap_or("").to_lowercase())
                .collect()
        })
        .unwrap_or_default();

    let has_gguf = tags_lower.iter().any(|t| t == "gguf") || file_names.iter().any(|f| f.ends_with(".gguf"));
    let has_awq = tags_lower.iter().any(|t| t.contains("awq"));
    let has_gptq = tags_lower.iter().any(|t| t.contains("gptq"));
    let has_safetensors = tags_lower.iter().any(|t| t == "safetensors")
        || file_names.iter().any(|f| f.ends_with(".safetensors"));

    let mut backends: Vec<String> = Vec::new();
    if has_awq || has_gptq {
        backends.push("vllm".into());
    }
    if has_gguf {
        backends.push("llamacpp".into());
        backends.push("ollama".into());
    }
    if has_safetensors && !(has_awq || has_gptq || has_gguf) {
        backends.push("airllm".into());
        backends.push("vllm".into());
    }
    if backends.is_empty() {
        backends.push("unknown".into());
    }
    backends
}

/// Translate the HF gated field to a human label.
pub fn parse_gated(gated: &Value) -> &'static str {
    if *gated == json!(false) || *gated == json!("false") {
        return "Open";
    }
    if *gated == json!("auto") {
        return "Login";
    }
    if *gated == json!("manual") || *gated == json!(true) || *gated == json!("true") {
        return "Gated";
    }
    "Open"
}

fn fmt_bytes(b: f64) -> String {
    if b >= 1e9 {
        format!("{:.1}GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.0}MB", b / 1e6)
    } else {
        format!("{:.0}KB", b / 1e3)
    }
}

/// Estimate download size as a human string (from safetensors.total,
/// usedStorage, or the param count + quant heuristics).
pub fn estimate_size(safetensors: &Value, used_storage: &Value, params_b: Option<f64>, quant: Option<&str>) -> String {
    if let Some(total) = safetensors["total"].as_f64() {
        if total > 0.0 {
            return fmt_bytes(total);
        }
    }
    if let Some(used) = used_storage.as_f64() {
        if used > 0.0 {
            return fmt_bytes(used);
        }
    }
    if let Some(p) = params_b {
        let q = quant.unwrap_or("").to_uppercase();
        if q == "AWQ" || q == "GPTQ" {
            return fmt_bytes(p * 0.5e9); // ~0.5 bytes/param for 4-bit
        }
        if q.contains("GGUF") {
            return fmt_bytes(p * 0.6e9); // ~Q4-Q5 average
        }
        return fmt_bytes(p * 2e9); // fp16
    }
    "?".to_string()
}

/// Auto-detect the vLLM tool call parser for a model.
pub fn detect_tool_parser(model_id: &str) -> &'static str {
    let mid = model_id.to_lowercase();
    if mid.contains("gemma-4") || mid.contains("gemma4") {
        "gemma4"
    } else if mid.contains("gemma-3") || mid.contains("gemma3") {
        "pythonic"
    } else if mid.contains("llama") {
        "llama3_json"
    } else if mid.contains("mistral") || mid.contains("mixtral") {
        "mistral"
    } else if mid.contains("jamba") {
        "jamba"
    } else {
        "hermes"
    }
}

/// Auto-detect the vLLM reasoning parser (if the model supports thinking).
pub fn detect_reasoning_parser(model_id: &str) -> Option<&'static str> {
    let mid = model_id.to_lowercase();
    if mid.contains("gemma-4") || mid.contains("gemma4") {
        Some("gemma4")
    } else if mid.contains("deepseek-r1") || mid.contains("deepseek_r1") {
        Some("deepseek_r1")
    } else {
        None
    }
}

/// Estimate VRAM usage in GB from param count and quantization.
pub fn estimate_vram_gb(params_b: Option<f64>, quant: Option<&str>) -> Option<f64> {
    let p = params_b?;
    let q = quant.unwrap_or("").to_uppercase();
    let v = if q == "AWQ" || q == "GPTQ" || q == "INT4" {
        p * 0.6 + 1.5
    } else if q == "GGUF" {
        p * 0.65 + 1.0
    } else if q == "INT8" || q == "W8A8" {
        p * 1.1 + 1.5
    } else {
        p * 2.1 + 2.0
    };
    Some((v * 10.0).round() / 10.0)
}

/// Add tool_parser, reasoning_parser, vram_gb to a model entry (in place).
pub fn enrich_model(model: &mut Value) {
    let mid = model["id"].as_str().unwrap_or("").to_string();
    if model.get("tool_parser").is_none() {
        model["tool_parser"] = json!(detect_tool_parser(&mid));
    }
    if model.get("reasoning_parser").is_none() {
        if let Some(rp) = detect_reasoning_parser(&mid) {
            model["reasoning_parser"] = json!(rp);
        }
    }
    if model.get("vram_gb").is_none() {
        let params = model["params_b"].as_f64();
        let quant = model["quant"].as_str().map(str::to_string);
        if let Some(v) = estimate_vram_gb(params, quant.as_deref()) {
            model["vram_gb"] = json!(v);
        }
    }
    if model.get("publisher").is_none() {
        let (publisher, tier) = publisher_trust(&mid);
        model["publisher"] = json!(publisher);
        model["trust"] = json!(tier);
    }
}

// ---------------------------------------------------------------------------
// Fallback catalog (offline, mirrors model_catalog.py FALLBACK_MODELS)
// ---------------------------------------------------------------------------

pub fn fallback_models(backend: &str) -> Vec<Value> {
    let list = match backend {
        "vllm" => json!([
            {"id": "google/gemma-4-12B-it", "params_b": 12, "quant": "none", "gated": "Open", "downloads": 400000, "tool_parser": "gemma4", "reasoning_parser": "gemma4", "desc": "Gemma 4 12B — primary, native tool calling, multimodal"},
            {"id": "google/gemma-4-E4B-it", "params_b": 4, "quant": "none", "gated": "Open", "downloads": 500000, "tool_parser": "gemma4", "reasoning_parser": "gemma4", "desc": "Gemma 4 E4B — native tool calling, ~8 GB"},
            {"id": "google/gemma-4-E2B-it", "params_b": 2, "quant": "none", "gated": "Open", "downloads": 300000, "tool_parser": "gemma4", "reasoning_parser": "gemma4", "desc": "Gemma 4 E2B — edge, ~4 GB"},
            {"id": "microsoft/harrier-oss-v1-0.6b", "params_b": 0.6, "quant": "none", "gated": "Open", "downloads": 100000, "tool_parser": "hermes", "desc": "Microsoft Harrier OSS v1 0.6B — edge (HF→GGUF→Ollama, see MODEL_CONVERSION.md)"},
            {"id": "microsoft/Phi-4", "params_b": 14, "quant": "none", "gated": "Open", "downloads": 500000, "tool_parser": "hermes", "desc": "Phi-4 14B — strong reasoning, dense"},
            {"id": "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4", "params_b": 30, "quant": "NVFP4", "gated": "Open", "downloads": 1580000, "tool_parser": "hermes", "desc": "Nemotron-3 Nano 30B-A3B (NVFP4) — MoE, ~3B active, fits mid GPU"},
            {"id": "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4", "params_b": 120, "quant": "NVFP4", "gated": "Open", "downloads": 385000, "tool_parser": "hermes", "desc": "Nemotron-3 Super 120B-A12B (NVFP4) — MoE flagship"},
            {"id": "nvidia/Nemotron-3-Nano-Omni-30B-A3B-Reasoning-NVFP4", "params_b": 30, "quant": "NVFP4", "gated": "Open", "downloads": 2160000, "pipeline_tag": "any-to-any", "desc": "Nemotron-3 Nano Omni 30B-A3B (NVFP4) — multimodal any-to-any, reasoning"},
            {"id": "nvidia/nemotron-3.5-asr-streaming-0.6b", "params_b": 0.6, "quant": "none", "gated": "Open", "downloads": 276000, "pipeline_tag": "automatic-speech-recognition", "desc": "Nemotron 3.5 ASR streaming 0.6B — speech recognition"},
            {"id": "meta-llama/Llama-3.1-8B-Instruct", "params_b": 8, "quant": "none", "gated": "Gated", "downloads": 3000000, "tool_parser": "llama3_json", "desc": "Llama 3.1 8B — proven, tool calling"}
        ]),
        "llamacpp" => json!([
            {"id": "unsloth/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4", "params_b": 30, "quant": "GGUF", "gated": "Open", "downloads": 20000, "desc": "Nemotron-3 Nano 30B-A3B GGUF/NVFP4 (unsloth) — MoE"},
            {"id": "unsloth/NVIDIA-Nemotron-3-Super-120B-A12B-GGUF", "params_b": 120, "quant": "GGUF", "gated": "Open", "downloads": 11300, "desc": "Nemotron-3 Super 120B-A12B GGUF (unsloth)"},
            {"id": "bartowski/microsoft_Phi-4-GGUF", "params_b": 14, "quant": "GGUF", "gated": "Open", "downloads": 300000, "desc": "Phi-4 14B GGUF"},
            {"id": "harrier-oss-v1-0.6b", "params_b": 0.6, "quant": "GGUF", "gated": "Open", "downloads": 0, "desc": "Microsoft Harrier 0.6B — locally converted GGUF (see MODEL_CONVERSION.md)"},
            {"id": "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF", "params_b": 8, "quant": "GGUF", "gated": "Open", "downloads": 700000, "desc": "Llama 3.1 8B GGUF"},
            {"id": "bartowski/Llama-3.2-3B-Instruct-GGUF", "params_b": 3, "quant": "GGUF", "gated": "Open", "downloads": 500000, "desc": "Llama 3.2 3B GGUF — 4-6 GB"},
            {"id": "bartowski/Llama-3.2-1B-Instruct-GGUF", "params_b": 1, "quant": "GGUF", "gated": "Open", "downloads": 400000, "desc": "Llama 3.2 1B GGUF — RPi / 2 GB"}
        ]),
        "ollama" => json!([
            {"id": "phi4", "params_b": 14, "quant": "GGUF", "gated": "Open", "downloads": 700000, "desc": "Microsoft Phi-4 14B"},
            {"id": "harrier-oss-v1-0.6b", "params_b": 0.6, "quant": "GGUF", "gated": "Open", "downloads": 0, "desc": "Microsoft Harrier 0.6B — locally converted (ollama create)"},
            {"id": "llama3.1:8b", "params_b": 8, "quant": "GGUF", "gated": "Open", "downloads": 5000000, "desc": "Meta Llama 3.1 8B — proven, tool calling"},
            {"id": "llama3.2:3b", "params_b": 3, "quant": "GGUF", "gated": "Open", "downloads": 3000000, "desc": "Meta Llama 3.2 3B — lightweight"},
            {"id": "llama3.2:1b", "params_b": 1, "quant": "GGUF", "gated": "Open", "downloads": 2000000, "desc": "Meta Llama 3.2 1B — RPi / 2 GB"},
            {"id": "nemotron-mini", "params_b": 4, "quant": "GGUF", "gated": "Open", "downloads": 150000, "desc": "Nvidia Nemotron-Mini 4B — edge, tool calling"}
        ]),
        "airllm" => json!([
            {"id": "nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B-BF16", "params_b": 561, "quant": null, "gated": "Open", "downloads": 115000, "desc": "Nemotron-3 Ultra 550B-A55B — flagship MoE, layer-by-layer"},
            {"id": "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16", "params_b": 124, "quant": null, "gated": "Open", "downloads": 1180000, "desc": "Nemotron-3 Super 120B-A12B — layer-by-layer"},
            {"id": "meta-llama/Llama-3.1-405B-Instruct", "params_b": 405, "quant": null, "gated": "Gated", "downloads": 300000, "desc": "Llama 3.1 405B — flagship, layer-by-layer"}
        ]),
        "embedding" => json!([
            {"id": "nvidia/NV-EmbedCode-7b-v1", "params_b": 7, "quant": "none", "gated": "Open", "downloads": 150000, "pipeline_tag": "feature-extraction", "desc": "Nvidia NV-EmbedCode 7B v1 — code retrieval embeddings"},
            {"id": "nvidia/NV-Embed-v2", "params_b": 7, "quant": "none", "gated": "Open", "downloads": 300000, "pipeline_tag": "feature-extraction", "desc": "Nvidia NV-Embed v2 — top MTEB retrieval"},
            {"id": "nvidia/llama-3.2-nv-embedqa-1b-v2", "params_b": 1, "quant": "none", "gated": "Open", "downloads": 100000, "pipeline_tag": "feature-extraction", "desc": "Nvidia Llama-3.2 NV-EmbedQA 1B — light QA retrieval"}
        ]),
        _ => json!([]),
    };
    list.as_array().cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// HF API access
// ---------------------------------------------------------------------------

fn hf_base() -> String {
    let base = std::env::var("HF_ENDPOINT").unwrap_or_default();
    let base = base.trim().trim_end_matches('/');
    if base.is_empty() {
        "https://huggingface.co".to_string()
    } else {
        base.to_string()
    }
}

fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hf_get(url: &str, timeout_secs: u64) -> Result<Value, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = agent.get(url).call().map_err(|e| format!("HF unreachable: {e}"))?;
    let status = resp.status().as_u16();
    if !(200..=299).contains(&status) {
        return Err(format!("HF returned {status}"));
    }
    let text = resp.body_mut().read_to_string().map_err(|e| format!("HF read error: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("HF returned non-JSON: {e}"))
}

/// GET a JSON document from ollama.com (requires an explicit Accept
/// header — without it the endpoint serves the HTML page).
fn ollama_json(url: &str, timeout_secs: u64) -> Option<Value> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = agent
        .get(url)
        .header("Accept", "application/json")
        .call()
        .ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    serde_json::from_str(&resp.body_mut().read_to_string().ok()?).ok()
}

/// Exact download size of `family:tag` from the registry manifest — the
/// sum of layer bytes. None on any failure (missing tag, network, parse).
fn ollama_manifest_size(family: &str, tag: &str, timeout_secs: u64) -> Option<u64> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .http_status_as_error(false)
        .build()
        .into();
    let url = format!("https://registry.ollama.ai/v2/library/{family}/manifests/{tag}");
    let mut resp = agent
        .get(&url)
        .header("Accept", "application/vnd.docker.distribution.manifest.v2+json")
        .call()
        .ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    let v: Value = serde_json::from_str(&resp.body_mut().read_to_string().ok()?).ok()?;
    let total: u64 = v["layers"]
        .as_array()?
        .iter()
        .filter_map(|l| l["size"].as_u64())
        .sum();
    if total == 0 { None } else { Some(total) }
}

/// LIVE Ollama starter recommendations, size-verified against the registry
/// (the goal: use ollama tooling to get a live
/// list, filtered to our setups). Only the FAMILY seed is
/// manual (a handful of names, changes a few times a year); everything
/// else is live:
///   tags:  https://ollama.com/library/<family>/tags   (JSON)
///   size:  registry manifest layer bytes              (exact download)
/// A model is offered when its weights fit ~70% of VRAM (KV-cache +
/// runtime headroom — the lesson of gemma4:e4b, whose 9.6 GB download made
/// a hand-written "fits 8 GB" claim false within the hour). Cached 24h;
/// any failure returns None and the caller uses the static fallback trio.
/// The download budget the starter list verifies against: ~70% of VRAM.
/// One definition, so "does the product default fit" is judged by the same
/// rule as the picks it is judged against.
pub fn ollama_fit_budget_bytes(vram_gb: f64) -> u64 {
    (vram_gb.max(2.0) * 0.70 * 1e9) as u64
}

/// Exact download size of one `family:tag` from the registry manifest, or
/// None when offline or the name has no tag.
pub fn ollama_download_bytes(name: &str, timeout_secs: u64) -> Option<u64> {
    let (fam, tag) = name.split_once(':')?;
    ollama_manifest_size(fam, tag, timeout_secs)
}

pub fn ollama_live_starters(vram_gb: f64) -> Option<Vec<(String, String)>> {
    // (family, lab, origin) — origin powers the NOO_MODEL_ORIGINS scope
    // (favouring specific models, e.g. US-based
    // only). Provenance is a compliance axis for some deployments.
    const FAMILIES: &[(&str, &str, &str)] = &[
        ("gemma4", "Google", "US"),
        ("qwen3", "Alibaba", "CN"),
        ("llama3.2", "Meta", "US"),
        ("deepseek-r1", "DeepSeek", "CN"),
        ("mistral", "Mistral", "EU"),
        ("phi4", "Microsoft", "US"),
    ];
    // Comma list, case-insensitive: NOO_MODEL_ORIGINS=us or us,eu. A scope
    // that matches NO family is ignored (a typo must not empty the list).
    let origins: Vec<String> = std::env::var("NOO_MODEL_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();
    let scoped: Vec<&(&str, &str, &str)> = {
        let hit: Vec<_> =
            FAMILIES.iter().filter(|(_, _, o)| origins.iter().any(|w| w == o)).collect();
        if origins.is_empty() || hit.is_empty() { FAMILIES.iter().collect() } else { hit }
    };
    let scope_key = origins.join(",");
    let home = std::env::var("HOME").ok()?;
    let cache_path = PathBuf::from(&home)
        .join(".config")
        .join("mesh")
        .join("ollama_starters.json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    if let Ok(text) = std::fs::read_to_string(&cache_path) {
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            let fresh = v["ts"].as_i64().is_some_and(|t| now - t < 86_400);
            let same_box = (v["vram_gb"].as_f64().unwrap_or(-1.0) - vram_gb).abs() < 0.5;
            // A cache written under a different origin scope is not ours.
            let same_scope = v["origins"].as_str().unwrap_or("") == scope_key;
            if fresh && same_box && same_scope {
                let picks: Vec<(String, String)> = v["picks"]
                    .as_array()?
                    .iter()
                    .filter_map(|p| {
                        Some((p[0].as_str()?.to_string(), p[1].as_str()?.to_string()))
                    })
                    .collect();
                if !picks.is_empty() {
                    return Some(picks);
                }
            }
        }
    }

    let budget = ollama_fit_budget_bytes(vram_gb);
    let mut picks: Vec<(String, u64, &str, &str)> = Vec::new();
    for (fam, lab, origin) in scoped.iter().copied() {
        // ollama.com content-negotiates: JSON only with an explicit
        // Accept header (plain GET returns the HTML page).
        let Some(tags) = ollama_json(&format!("https://ollama.com/library/{fam}/tags"), 8) else {
            continue;
        };
        // Plain size tags only (8b, 3.8b, e4b) — quant/format variants
        // (q4_K_M, mlx, cloud, latest) are for people who know they want
        // them, not a starter list.
        let mut cands: Vec<(String, f64)> = tags["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str()).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|t| {
                let body = t.strip_prefix('e').unwrap_or(t);
                let num = body.strip_suffix('b')?;
                let params: f64 = num.parse().ok()?;
                Some((t.to_string(), params))
            })
            .collect();
        cands.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        // Largest tag whose ACTUAL download fits the budget; cap the
        // manifest fetches so a long tag list can't stall the wizard.
        let mut fetched = 0;
        for (tag, params) in cands {
            if (params * 0.40e9) as u64 > budget || fetched >= 3 {
                continue;
            }
            fetched += 1;
            if let Some(size) = ollama_manifest_size(fam, &tag, 8) {
                if size <= budget {
                    picks.push((format!("{fam}:{tag}"), size, lab, origin));
                    break;
                }
            }
        }
    }
    if picks.is_empty() {
        return None;
    }
    picks.sort_by_key(|p| std::cmp::Reverse(p.1));
    // One row per family — that IS the full list
    // list?"); the old top-3 truncation silently hid labs.
    let out: Vec<(String, String)> = picks
        .into_iter()
        .map(|(name, size, lab, origin)| {
            (
                name,
                format!(
                    "{:.1} GB download — registry-verified fit · {lab} ({origin})",
                    size as f64 / 1e9
                ),
            )
        })
        .collect();
    let _ = std::fs::create_dir_all(cache_path.parent().unwrap());
    let _ = std::fs::write(
        &cache_path,
        serde_json::json!({
            "ts": now, "vram_gb": vram_gb, "origins": scope_key,
            "picks": out.iter().map(|(a, b)| serde_json::json!([a, b])).collect::<Vec<_>>(),
        })
        .to_string(),
    );
    Some(out)
}

/// Raw HF /api/models search (parity with `_hf_search`).
fn hf_search(query: &str, limit: usize) -> Result<Vec<Value>, String> {
    let url = format!(
        "{}/api/models?search={}&limit={}&sort=downloads&direction=-1&full=true",
        hf_base(),
        urlenc(query),
        limit
    );
    let v = hf_get(&url, 15)?;
    v.as_array().cloned().ok_or_else(|| "HF search returned non-array".to_string())
}

fn tags_of(m: &Value) -> Vec<String> {
    m["tags"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Normalize an HF API model result into the standard catalog schema.
fn normalize(m: &Value) -> Value {
    let model_id = m["modelId"].as_str().or_else(|| m["id"].as_str()).unwrap_or("").to_string();
    let tags = tags_of(m);
    let siblings = m["siblings"].as_array();

    let mut params_b = extract_param_count(&model_id, &tags);
    if params_b.is_none() {
        // Try safetensors parameter counts.
        let st = &m["safetensors"];
        let total = if let Some(map) = st["parameters"].as_object() {
            map.values().filter_map(|v| v.as_f64()).sum::<f64>()
        } else {
            st["parameters"].as_f64().unwrap_or(0.0)
        };
        if total > 0.0 {
            params_b = Some((total / 1e9 * 10.0).round() / 10.0);
        }
    }

    let quant = detect_quant(&model_id, &tags);
    let backends = detect_backend_compat(&tags, siblings);
    let tier = classify_tier(params_b, quant.as_deref());
    let gated = parse_gated(&m["gated"]);
    let mut desc = m["cardData"]["description"].as_str().unwrap_or("").to_string();
    if desc.is_empty() {
        desc = model_id.split('/').next_back().unwrap_or("").replace('-', " ");
    }

    let size = estimate_size(&m["safetensors"], &m["usedStorage"], params_b, quant.as_deref());
    let mut out = json!({
        "id": model_id,
        "params_b": params_b,
        "quant": quant,
        "gated": gated,
        "downloads": m["downloads"].as_i64().unwrap_or(0),
        "likes": m["likes"].as_i64().unwrap_or(0),
        "desc": clip(&desc, 80),
        "backends": backends,
        "tier": tier,
        "size_estimate": size,
    });
    if let Some(tag) = m["pipeline_tag"].as_str().filter(|t| !t.is_empty()) {
        out["pipeline_tag"] = json!(tag);
    }
    enrich_model(&mut out);
    out
}

/// Normalize a full HF model detail response (adds license/author/formats).
fn normalize_detail(m: &Value) -> Value {
    let mut base = normalize(m);
    base["license"] = json!(m["cardData"]["license"].as_str().unwrap_or("unknown"));
    base["author"] = json!(m["author"].as_str().unwrap_or(""));
    base["last_modified"] = json!(m["lastModified"].as_str().unwrap_or(""));
    base["pipeline_tag"] = json!(m["pipeline_tag"].as_str().unwrap_or(""));

    let mut formats: Vec<&str> = Vec::new();
    if let Some(siblings) = m["siblings"].as_array() {
        for s in siblings {
            let fname = s["rfilename"].as_str().unwrap_or("");
            let f = if fname.ends_with(".gguf") {
                "GGUF"
            } else if fname.ends_with(".safetensors") {
                "safetensors"
            } else if fname.ends_with(".bin") {
                "pytorch"
            } else {
                continue;
            };
            if !formats.contains(&f) {
                formats.push(f);
            }
        }
    }
    formats.sort_unstable();
    base["formats"] = json!(formats);
    base
}

// ---------------------------------------------------------------------------
// Catalog with local cache (~/.config/mesh/model_cache.json, shared with
// the Python CLI)
// ---------------------------------------------------------------------------

pub struct Catalog {
    cache_file: PathBuf,
    cache: Option<Value>,
    loaded: bool,
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}

impl Catalog {
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Catalog {
            cache_file: PathBuf::from(home).join(".config").join("mesh").join("model_cache.json"),
            cache: None,
            loaded: false,
        }
    }

    fn load_cache_file(&mut self) -> Option<&Value> {
        if !self.loaded {
            self.loaded = true;
            if let Ok(text) = std::fs::read_to_string(&self.cache_file) {
                self.cache = serde_json::from_str(&text).ok();
            }
        }
        self.cache.as_ref()
    }

    /// Path of the shared cache file (`~/.config/mesh/model_cache.json`).
    pub fn cache_file_path(&self) -> &std::path::Path {
        &self.cache_file
    }

    pub(crate) fn read_cache(&mut self, backend: &str, ignore_ttl: bool) -> Option<Vec<Value>> {
        let cache = self.load_cache_file()?;
        let entry = cache["catalogs"][backend].as_array()?.clone();
        if !ignore_ttl {
            let fetched_at = cache["fetched_at"][backend].as_str()?;
            let dt = time::OffsetDateTime::parse(fetched_at, &time::format_description::well_known::Rfc3339).ok()?;
            let age_hours = (time::OffsetDateTime::now_utc() - dt).as_seconds_f64() / 3600.0;
            if age_hours > CACHE_TTL_HOURS {
                return None;
            }
        }
        Some(entry)
    }

    pub(crate) fn write_cache(&mut self, backend: &str, models: &[Value]) {
        use std::io::Write as _;
        use std::os::unix::io::AsRawFd as _;

        if let Some(parent) = self.cache_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // flock on a sidecar .lock file — same name the Python side uses
        // (model_cache.json.lock), so Python and Rust writers exclude each
        // other. Concurrent refreshes used to whole-file read-modify-write
        // and lose each other's backend entries.
        let lock_path = format!("{}.lock", self.cache_file.display());
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .ok();
        if let Some(lf) = &lock_file {
            unsafe { libc::flock(lf.as_raw_fd(), libc::LOCK_EX) };
        }

        // Re-read FRESH under the lock (never trust the in-memory copy —
        // another process may have written a different backend's entry).
        let mut cache = std::fs::read_to_string(&self.cache_file)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .unwrap_or_else(|| json!({"catalogs": {}, "fetched_at": {}, "ttl_hours": CACHE_TTL_HOURS}));
        cache["catalogs"][backend] = json!(models);
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        cache["fetched_at"][backend] = json!(now);
        cache["ttl_hours"] = json!(CACHE_TTL_HOURS);

        // Atomic write: tmp file in the same dir + rename, so a mid-write
        // crash never leaves truncated JSON. Same byte shape as before
        // (Value::to_string — the Python round-trip tests pin this).
        let tmp_path = format!("{}.tmp.{}", self.cache_file.display(), std::process::id());
        let wrote = std::fs::File::create(&tmp_path)
            .and_then(|mut f| {
                f.write_all(cache.to_string().as_bytes())?;
                f.sync_all()
            })
            .and_then(|_| std::fs::rename(&tmp_path, &self.cache_file));
        if wrote.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        // Lock releases when `lock_file` drops here.
        self.cache = Some(cache);
        self.loaded = true;
    }

    /// Human-readable cache freshness string.
    pub fn cache_age_text(&mut self, backend: &str) -> String {
        let Some(cache) = self.load_cache_file() else { return "No cache".into() };
        if cache["catalogs"][backend].is_null() {
            return "No cache".into();
        }
        let Some(fetched_at) = cache["fetched_at"][backend].as_str() else {
            return "No cache".into();
        };
        let Ok(dt) = time::OffsetDateTime::parse(fetched_at, &time::format_description::well_known::Rfc3339) else {
            return "Unknown".into();
        };
        let secs = (time::OffsetDateTime::now_utc() - dt).as_seconds_f64();
        let hours = (secs / 3600.0) as i64;
        if hours < 1 {
            let mins = (secs / 60.0) as i64;
            return format!("{} minute{} ago", mins, if mins != 1 { "s" } else { "" });
        }
        if hours < 24 {
            return format!("{} hour{} ago", hours, if hours != 1 { "s" } else { "" });
        }
        let days = hours / 24;
        format!("{} day{} ago", days, if days != 1 { "s" } else { "" })
    }

    fn filter_tier(models: Vec<Value>, tier: Option<i64>) -> Vec<Value> {
        match tier {
            None => models,
            Some(t) => models.into_iter().filter(|m| m["tier"].as_i64() == Some(t)).collect(),
        }
    }

    /// Query HF with backend-specific search terms, dedupe, normalize, sort.
    /// pub(crate) for `models refresh` (WP-R), which force-rebuilds the cache
    /// (TTL bypass) and optionally LLM-enriches before writing.
    pub(crate) fn fetch_from_hf(&self, backend: &str, limit: usize) -> Result<Vec<Value>, String> {
        let searches = backend_searches(backend);
        if searches.is_empty() {
            return Ok(Vec::new());
        }
        let mut seen: Vec<String> = Vec::new();
        let mut results: Vec<Value> = Vec::new();
        let mut last_err: Option<String> = None;
        let mut any_ok = false;
        for query in &searches {
            match hf_search(query, limit) {
                Ok(raw) => {
                    any_ok = true;
                    for m in &raw {
                        let mid = m["modelId"].as_str().or_else(|| m["id"].as_str()).unwrap_or("").to_string();
                        if seen.contains(&mid) {
                            continue;
                        }
                        seen.push(mid);
                        if !task_fits_backend(m["pipeline_tag"].as_str(), backend) {
                            continue;
                        }
                        results.push(normalize(m));
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        // Python's version raises on the FIRST failed search; treat total
        // failure as an error so the caller falls back to cache/offline list.
        if !any_ok {
            return Err(last_err.unwrap_or_else(|| "HF unreachable".into()));
        }
        results.sort_by(|a, b| b["downloads"].as_i64().unwrap_or(0).cmp(&a["downloads"].as_i64().unwrap_or(0)));
        Ok(results)
    }

    /// Fetch models for a backend, using cache or the HF API; falls back to
    /// a stale cache and then the offline list. Parity with
    /// `ModelCatalog.fetch_models`.
    pub fn fetch_models(&mut self, backend: &str, tier: Option<i64>, limit: usize, refresh: bool) -> Vec<Value> {
        if !refresh {
            if let Some(cached) = self.read_cache(backend, false) {
                let mut v = Self::filter_tier(filter_approved(cached, Some(backend)), tier);
                v.truncate(limit);
                return v;
            }
        }
        let models = match self.fetch_from_hf(backend, limit * 3) {
            Ok(models) => {
                self.write_cache(backend, &models);
                models
            }
            Err(_) => {
                if let Some(stale) = self.read_cache(backend, true) {
                    let mut v = Self::filter_tier(filter_approved(stale, Some(backend)), tier);
                    v.truncate(limit);
                    return v;
                }
                fallback_models(backend)
            }
        };
        let mut v = Self::filter_tier(filter_approved(models, Some(backend)), tier);
        v.truncate(limit);
        v
    }

    /// Live search of the HF API; falls back to searching cached/offline data.
    pub fn search_models(&mut self, query: &str, backend: Option<&str>, limit: usize) -> Vec<Value> {
        match hf_search(query, limit) {
            Ok(raw) => {
                let normed: Vec<Value> = raw.iter().map(normalize).collect();
                let mut v = filter_approved(normed, backend);
                v.truncate(limit);
                v
            }
            Err(_) => {
                let backends: Vec<&str> = match backend {
                    Some(b) => vec![b],
                    None => ALL_SEARCH_BACKENDS.to_vec(),
                };
                let q = query.to_lowercase();
                let mut results = Vec::new();
                for b in backends {
                    let source = self.read_cache(b, true).unwrap_or_else(|| fallback_models(b));
                    for m in source {
                        let id = m["id"].as_str().unwrap_or("").to_lowercase();
                        let desc = m["desc"].as_str().unwrap_or("").to_lowercase();
                        if id.contains(&q) || desc.contains(&q) {
                            results.push(m);
                        }
                    }
                }
                let mut v = filter_approved(results, backend);
                v.truncate(limit);
                v
            }
        }
    }

    /// Fetch detailed info for a single model from HF. None on any failure.
    pub fn model_info(&self, model_id: &str) -> Option<Value> {
        let url = format!("{}/api/models/{}", hf_base(), model_id);
        let data = hf_get(&url, 10).ok()?;
        Some(normalize_detail(&data))
    }
}

/// Is `model_id` in a node's reported inventory? Tolerant of org prefixes
/// and Ollama `name:tag` forms (port of `model_placement.model_is_cached`).
pub fn model_is_cached(model_id: &str, available: &[String]) -> bool {
    if available.is_empty() {
        return false;
    }
    let mid = model_id.to_lowercase();
    let base = mid.split('/').next_back().unwrap_or("").to_string();
    for a in available {
        let al = a.to_lowercase();
        if al == mid
            || al == base
            || al.starts_with(&format!("{base}:"))
            || al.contains(&base)
            || base.contains(&al)
        {
            return true;
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════════════════
// Tests — model_cache.json write safety (WP-C hazard 2): flock + fresh
// re-read + atomic tmp/rename. Shape stays pinned by the Python round-trip
// tests in tests/gateway_integration.rs (WP-R block).
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod search_scope_tests {
    use super::*;

    // Env-free: NOO_MODEL_* unset in the test process, so defaults apply.

    #[test]
    fn queries_carry_no_instruct_token() {
        for backend in ALL_SEARCH_BACKENDS {
            for q in backend_searches(backend) {
                assert!(!q.to_lowercase().contains("instruct"), "{backend}: {q}");
            }
        }
        assert!(backend_searches("llamacpp").contains(&"gemma-4 GGUF".to_string()));
        assert!(backend_searches("vllm").contains(&"inkling AWQ".to_string()));
    }

    #[test]
    fn multimodal_chat_models_are_approved() {
        for (id, tag) in [
            ("google/gemma-4-31B-it", "image-text-to-text"),
            ("google/gemma-4-E4B-it", "any-to-any"),
            ("unsloth/Inkling-Small-GGUF", "image-text-to-text"),
            ("thinkingmachines/Inkling", "image-text-to-text"),
            ("nvidia/Gemma-4-31B-IT-NVFP4", "text-generation"),
        ] {
            let m = json!({"id": id, "pipeline_tag": tag});
            assert!(is_approved(&m, Some("vllm")), "{id} ({tag})");
        }
        assert_eq!(model_vendor("thinkingmachines/Inkling").as_deref(), Some("Thinking Machines"));
        assert_eq!(model_vendor("ollama/gemma4").as_deref(), Some("Google"));
        assert_eq!(model_vendor("phi4").as_deref(), Some("Microsoft"));
        assert_eq!(model_vendor("bartowski/Phi-3.5-mini-instruct-GGUF").as_deref(), Some("Microsoft"));
        assert!(model_vendor("google/gemma-3-4b-it").is_none());
    }

    #[test]
    fn family_substring_in_a_user_name_is_not_a_vendor() {
        // "phi" inside an org or a longer word must not approve a model.
        assert!(model_vendor("philbert440/Qwen3.8-27B-W4A16-AWQ").is_none());
        assert!(model_vendor("dbourget/philai-embeddings-v1.1").is_none());
        assert!(model_vendor("phi010402/finetune-law-embedding").is_none());
    }

    #[test]
    fn publisher_tiers() {
        assert_eq!(publisher_trust("google/gemma-4-12B-it-qat-q4_0-gguf"), ("google".into(), TRUST_FIRST_PARTY));
        assert_eq!(publisher_trust("nvidia/Gemma-4-31B-IT-NVFP4"), ("nvidia".into(), TRUST_FIRST_PARTY));
        assert_eq!(publisher_trust("thinkingmachines/Inkling"), ("thinkingmachines".into(), TRUST_FIRST_PARTY));
        assert_eq!(publisher_trust("unsloth/gemma-4-12B-it-qat-GGUF"), ("unsloth".into(), TRUST_TRUSTED));
        assert_eq!(publisher_trust("bartowski/Meta-Llama-3.1-8B-Instruct-GGUF"), ("bartowski".into(), TRUST_TRUSTED));
        assert_eq!(publisher_trust("cyankiwi/gemma-4-26B-A4B-it-AWQ-4bit"), ("cyankiwi".into(), TRUST_OTHER));
        // Ollama-library ids (curated fallback entries) count as first-party.
        assert_eq!(publisher_trust("phi4"), ("library".into(), TRUST_FIRST_PARTY));
        assert_eq!(trust_label(TRUST_OTHER), "other");
    }

    #[test]
    fn first_party_outranks_downloads() {
        // Download order: cyankiwi (2.3M) > unsloth (1.2M) > google (0.7M).
        let models = vec![
            json!({"id": "cyankiwi/gemma-4-26B-A4B-it-AWQ-4bit", "downloads": 2_374_050}),
            json!({"id": "unsloth/gemma-4-12B-it-qat-GGUF", "downloads": 1_249_309}),
            json!({"id": "google/gemma-4-12B-it-qat-q4_0-gguf", "downloads": 711_630}),
            json!({"id": "HauhauCS/Gemma-4-E4B-Uncensored", "downloads": 2_562_002}),
        ];
        let out = filter_approved(models, Some("llamacpp"));
        let ids: Vec<&str> = out.iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            [
                "google/gemma-4-12B-it-qat-q4_0-gguf",
                "unsloth/gemma-4-12B-it-qat-GGUF",
                "HauhauCS/Gemma-4-E4B-Uncensored", // tier 3, but more downloads than cyankiwi
                "cyankiwi/gemma-4-26B-A4B-it-AWQ-4bit",
            ]
        );
        assert_eq!(out[0]["publisher"], "google");
        assert_eq!(out[0]["trust"], TRUST_FIRST_PARTY);
        assert_eq!(out[3]["trust"], TRUST_OTHER);
    }

    #[test]
    fn enrich_stamps_publisher() {
        let mut m = json!({"id": "unsloth/Inkling-Small-GGUF"});
        enrich_model(&mut m);
        assert_eq!(m["publisher"], "unsloth");
        assert_eq!(m["trust"], TRUST_TRUSTED);
    }

    #[test]
    fn embedding_queries_target_first_party_embedders() {
        let q = backend_searches("embedding");
        assert!(q.contains(&"nemotron embed".to_string()));
        assert!(q.contains(&"nvidia embed".to_string()));
        assert!(q.contains(&"microsoft embed".to_string()));
    }

    #[test]
    fn task_axis_is_per_backend() {
        assert!(task_fits_backend(Some("image-text-to-text"), "llamacpp"));
        assert!(task_fits_backend(Some("any-to-any"), "vllm"));
        assert!(task_fits_backend(None, "vllm"));
        assert!(!task_fits_backend(Some("feature-extraction"), "vllm"));
        assert!(task_fits_backend(Some("sentence-similarity"), "embedding"));
        assert!(!task_fits_backend(Some("text-generation"), "embedding"));
    }

    #[test]
    fn normalize_keeps_pipeline_tag() {
        let m = json!({"modelId": "google/gemma-4-12B-it", "tags": ["safetensors"], "pipeline_tag": "any-to-any", "downloads": 1});
        assert_eq!(normalize(&m)["pipeline_tag"], "any-to-any");
        let untagged = json!({"modelId": "x/y", "tags": [], "downloads": 1});
        assert!(normalize(&untagged).get("pipeline_tag").is_none());
    }
}

#[cfg(test)]
mod cache_write_tests {
    use super::*;

    fn temp_catalog(name: &str) -> Catalog {
        let dir = std::env::temp_dir().join(format!(
            "noo-catalog-test-{}-{}",
            name,
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cache_file = dir.join("model_cache.json");
        let _ = std::fs::remove_file(&cache_file);
        Catalog { cache_file, cache: None, loaded: false }
    }

    #[test]
    fn out_of_band_entry_survives_write_cache() {
        let mut cat = temp_catalog("oob");
        cat.write_cache("ollama", &[json!({"id": "m1"})]);

        // Another process (e.g. the Python CLI) writes a different backend.
        let mut on_disk: Value = serde_json::from_str(
            &std::fs::read_to_string(&cat.cache_file).unwrap(),
        )
        .unwrap();
        on_disk["catalogs"]["vllm"] = json!([{"id": "other-proc"}]);
        std::fs::write(&cat.cache_file, on_disk.to_string()).unwrap();

        // This Catalog's in-memory copy is now stale; the write must still
        // preserve the out-of-band vllm entry (fresh read under the lock).
        cat.write_cache("llamacpp", &[json!({"id": "m2"})]);

        let final_doc: Value = serde_json::from_str(
            &std::fs::read_to_string(&cat.cache_file).unwrap(),
        )
        .unwrap();
        assert_eq!(final_doc["catalogs"]["ollama"][0]["id"], "m1");
        assert_eq!(final_doc["catalogs"]["vllm"][0]["id"], "other-proc");
        assert_eq!(final_doc["catalogs"]["llamacpp"][0]["id"], "m2");
    }

    #[test]
    fn write_cache_leaves_no_tmp_and_stays_parseable() {
        let mut cat = temp_catalog("tmpclean");
        cat.write_cache("ollama", &[json!({"id": "m1"})]);
        let dir = cat.cache_file.parent().unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "tmp files left behind: {leftovers:?}");
        // Byte-shape: exactly the three Python-compatible top-level keys.
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(&cat.cache_file).unwrap(),
        )
        .unwrap();
        assert_eq!(doc.as_object().unwrap().len(), 3);
        assert!(doc.get("catalogs").is_some());
        assert!(doc.get("fetched_at").is_some());
        assert_eq!(doc["ttl_hours"], CACHE_TTL_HOURS);
    }

    #[test]
    fn concurrent_writers_keep_every_backend() {
        let base = temp_catalog("concurrent");
        let path = base.cache_file.clone();
        let threads: Vec<_> = (0..6)
            .map(|i| {
                let p = path.clone();
                std::thread::spawn(move || {
                    let mut cat = Catalog { cache_file: p, cache: None, loaded: false };
                    cat.write_cache(&format!("backend{i}"), &[json!({"id": i})]);
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for i in 0..6 {
            assert_eq!(
                doc["catalogs"][format!("backend{i}")][0]["id"], i,
                "backend{i} entry lost under concurrency: {doc}"
            );
        }
    }
}

#[cfg(test)]
mod live_starters_tests {
    /// Network smoke — run explicitly: cargo test live_starters_smoke -- --ignored
    #[test]
    #[ignore]
    fn live_starters_smoke() {
        let picks = super::ollama_live_starters(8.0).expect("live fetch failed");
        assert!(!picks.is_empty());
        for (name, desc) in &picks {
            eprintln!("PICK {name} — {desc}");
            assert!(name.contains(':'), "not a model:tag: {name}");
        }
    }
}
