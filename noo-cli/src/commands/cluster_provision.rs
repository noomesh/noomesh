// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster …` provisioning surface — the operator-facing fleet bring-up
//! commands, ported so the static Rust binary is a STANDALONE controller
//! artifact (curl the binary, provision a fleet, zero Python present). These
//! still shell out to external TOOLS (ssh, scp, docker, tailscale via its HTTP
//! API) — that's an inherent dependency of provisioning — but they no longer
//! require the Python CLI runtime.
//!
//! | command          | kind                    | replicates                                   |
//! |------------------|-------------------------|----------------------------------------------|
//! | `auto-place`     | native (HTTP + local)   | `model_placement.plan_model_placements`      |
//! | `place-model`    | native (HTTP + local)   | `model_placement.match_node_for_model`       |
//! | `mint-join-key`  | native (Tailscale API)  | `tailscale.mint_join_key` + one-liner        |
//! | `set-primary`    | native (Tailscale API + ssh) | device rename + Postgres promotion      |
//! | `sync-images`    | subprocess (docker/ssh/scp) | cross-arch save|load orchestration       |
//! | `upgrade-agents` | subprocess (child provision) | serial `cluster provision <n> --wait` (bundle rail; swap retired, prop 58 A3) |
//!
//! Faithful-replication notes / narrowings (honest, per command):
//!   - `add-node` was DELETED 2026-09-03. It drove the
//!     `ansible/` tree removed in 3695e129, so every mode but `--probe-only`
//!     ended in `playbook_failed`. Node birth is the pull rail:
//!     `noo cluster bootstrap-token create` + `noo enroll` on the node, or
//!     `noo cluster provision` from the controller.
//!   - Tailscale API base is overridable with `NOO_TAILSCALE_API_BASE` (for
//!     stub-testing without hitting the real control plane).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use serde_json::{json, Value};

use super::cluster::{fetch_node, online_nodes, spawn_inherited};
use crate::envfile::repo_root;
use crate::http::{get_json, get_json_opt, post_json_try};
use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui::{self, Col, Glyph};

/// Narration line (guide rev 2: stdout, silenced by --quiet/--json).
fn say(s: &str) {
    if !crate::ui::quiet() {
        println!("{s}");
    }
}

// ════════════════════════════════════════════════════════════════════
//  Shared low-level helpers
// ════════════════════════════════════════════════════════════════════

/// Standard base64 (RFC 4648, padded) — for HTTP Basic auth headers.
fn base64_std(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Python `%g`-style number formatting (drop trailing zeros: 8.0→"8", 6.5→"6.5").
fn fmt_g(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        let s = format!("{v:.6}");
        let s = s.trim_end_matches('0').trim_end_matches('.');
        s.to_string()
    }
}

/// round to 1 decimal, matching Python `round(x, 1)` — correct round-half-to-
/// even on the EXACT double (Rust's `{:.1}` formatting is correctly rounded,
/// same as CPython's round; the naive `(x*10).round()/10` diverges on ties
/// like 1.65 → Python 1.6 vs 1.7).
fn round1(x: f64) -> f64 {
    format!("{x:.1}").parse().unwrap_or(x)
}

/// A default-verification ureq agent (real TLS via platform-verifier) for
/// EXTERNAL hosts (the Tailscale API, bootstrap-script HEAD probes) — distinct
/// from `http.rs`'s self-signed-gateway agent.
fn plain_agent(timeout: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Read a value from the process env (`.env` already loaded by
/// `ensure_repo_env`) — parity with Python's `_env_value`.
fn env_value(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

/// Resolve a Tailscale API bearer. Resolution order:
///
/// 1. `NOO_TAILSCALE_API_KEY` in the process env (explicit override);
/// 2. an **OAuth client** in the sops store
///    credential: scoped to `keys`+`acl` at creation, the client secret
///    never expires, and each call mints a short-lived access token, so
///    the 90-day API-key expiry surprise disappears);
/// 3. `NOO_TAILSCALE_API_KEY` in the sops store.
///
/// The result is used as the Basic-auth username exactly like an API key —
/// Tailscale accepts OAuth access tokens through the same header.
fn tailscale_api_key() -> String {
    let from_env = env_value("NOO_TAILSCALE_API_KEY");
    if !from_env.is_empty() {
        return from_env;
    }
    let path = repo_root().join("secrets/env.sops");
    let store = match super::secrets::SecretStore::load_sops(&path) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let val = |k: &str| {
        store
            .value_for_provider_api(k)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    if let (Some(id), Some(secret)) = (
        val("NOO_TAILSCALE_OAUTH_CLIENT_ID"),
        val("NOO_TAILSCALE_OAUTH_CLIENT_SECRET"),
    ) {
        match mint_oauth_token(&id, &secret) {
            Some(tok) => return tok,
            None => ui::warned(
                "Tailscale OAuth client present but token mint failed — \
                 falling back to NOO_TAILSCALE_API_KEY if set.",
            ),
        }
    }
    val("NOO_TAILSCALE_API_KEY").unwrap_or_default()
}

/// Client-credentials mint: POST /oauth/token. Short-lived (~1h) — minted
/// fresh per CLI invocation, never stored.
pub(crate) fn mint_oauth_token(client_id: &str, client_secret: &str) -> Option<String> {
    let url = format!("{}/oauth/token", tailscale_base());
    let mut resp = plain_agent(15)
        .post(&url)
        .send_form([
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("grant_type", "client_credentials"),
        ])
        .ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    let body: Value = serde_json::from_str(&resp.body_mut().read_to_string().ok()?).ok()?;
    body.get("access_token")
        .and_then(|t| t.as_str())
        .map(str::to_string)
}

/// Verify-by-probe (first-contact finding #37): can this OAuth client
/// actually MINT a tag:worker join key? The wizard used to store the
/// client, print "enrollment complete", and the missing grant surfaced
/// days later at the first `bootstrap-token create` with a misleading
/// error. Mints a minimal single-use key and deletes it immediately.
pub(crate) fn probe_worker_key_grant(client_id: &str, client_secret: &str) -> Result<(), String> {
    let token = mint_oauth_token(client_id, client_secret)
        .ok_or("could not exchange the client id/secret for a token — wrong credentials?")?;
    let url = format!("{}/tailnet/{}/keys", tailscale_base(), tailnet());
    let body = serde_json::json!({
        "capabilities": { "devices": { "create": {
            "reusable": false, "ephemeral": true, "preauthorized": false,
            "tags": ["tag:worker"]
        }}},
        "expirySeconds": 300,
        // Tailscale rejects parentheses/most punctuation in key
        // descriptions with a 400 that sank BOTH probes on their first
        // live run (finding #39) — keep this a plain slug.
        "description": "noomesh-onboard-grant-probe"
    });
    let mut resp = plain_agent(15)
        .post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .send_json(&body)
        .map_err(|e| format!("key-mint probe failed: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if status != 200 {
        if text.contains("invalid or not permitted") {
            return Err(
                "this client cannot mint tag:worker keys. Most likely cause (finding #46): the ACL ownership chain — an OAuth client acts AS its tags and can only mint tags one of its own tags OWNS. Fix in the policy editor: \"tag:worker\": [\"autogroup:admin\", \"tag:controller\"]. If the client itself carries no tags, regenerate it with BOTH ticked."
                    .into(),
            );
        }
        return Err(format!("key-mint probe: HTTP {status}: {text}"));
    }
    // Clean up the probe key — best-effort; it expires in 5 min regardless.
    if let Some(id) = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_string))
    {
        let _ = plain_agent(15)
            .delete(&format!("{}/tailnet/{}/keys/{}", tailscale_base(), tailnet(), id))
            .header("Authorization", &format!("Bearer {token}"))
            .call();
    }
    Ok(())
}

const TAILSCALE_KEY_HINT: &str =
    "NOO_TAILSCALE_API_KEY is not set — create one in the Tailscale admin console \
     (Settings → Keys) and store it in the secret store: `sops secrets/env.sops`, \
     add `NOO_TAILSCALE_API_KEY=tskey-api-…`. Never put it in .env.";

/// A hidden-input TTY prompt (no echo). Returns None when stdin is not a TTY
/// (so callers can fall back to env or refuse instead of blocking).
pub(crate) fn read_hidden(prompt: &str) -> Option<String> {
    if unsafe { libc::isatty(0) } != 1 {
        return None;
    }
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut term) } != 0 {
        return None;
    }
    let orig = term;
    term.c_lflag &= !libc::ECHO;
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &term) };
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &orig) };
    eprintln!();
    Some(line.trim_end_matches(['\n', '\r']).to_string())
}

// ════════════════════════════════════════════════════════════════════
//  Model placement (auto-place / place-model) — full local port of
//  cluster/model_placement.py + the catalog VRAM estimator it depends on.
// ════════════════════════════════════════════════════════════════════

/// (id, params_b, quant) rows lifted verbatim from `FALLBACK_MODELS` — the
/// ONLY catalog data `estimate_model_vram` reads (it never hits the live HF
/// API). quant "" == Python None.
const FALLBACK_MODELS: &[(&str, f64, &str)] = &[
    // vllm
    ("google/gemma-4-12B-it", 12.0, "none"),
    ("google/gemma-4-E4B-it", 4.0, "none"),
    ("google/gemma-4-E2B-it", 2.0, "none"),
    ("microsoft/harrier-oss-v1-0.6b", 0.6, "none"),
    ("microsoft/Phi-4", 14.0, "none"),
    ("nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4", 30.0, "NVFP4"),
    ("nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4", 120.0, "NVFP4"),
    ("nvidia/Nemotron-3-Nano-Omni-30B-A3B-Reasoning-NVFP4", 30.0, "NVFP4"),
    ("nvidia/nemotron-3.5-asr-streaming-0.6b", 0.6, "none"),
    ("meta-llama/Llama-3.1-8B-Instruct", 8.0, "none"),
    // llamacpp
    ("unsloth/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4", 30.0, "GGUF"),
    ("unsloth/NVIDIA-Nemotron-3-Super-120B-A12B-GGUF", 120.0, "GGUF"),
    ("bartowski/microsoft_Phi-4-GGUF", 14.0, "GGUF"),
    ("harrier-oss-v1-0.6b", 0.6, "GGUF"),
    ("bartowski/Meta-Llama-3.1-8B-Instruct-GGUF", 8.0, "GGUF"),
    ("bartowski/Llama-3.2-3B-Instruct-GGUF", 3.0, "GGUF"),
    ("bartowski/Llama-3.2-1B-Instruct-GGUF", 1.0, "GGUF"),
    // ollama
    ("phi4", 14.0, "GGUF"),
    ("llama3.1:8b", 8.0, "GGUF"),
    ("llama3.2:3b", 3.0, "GGUF"),
    ("llama3.2:1b", 1.0, "GGUF"),
    ("nemotron-mini", 4.0, "GGUF"),
    // airllm
    ("nvidia/NVIDIA-Nemotron-3-Ultra-550B-A55B-BF16", 561.0, ""),
    ("nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16", 124.0, ""),
    ("meta-llama/Llama-3.1-405B-Instruct", 405.0, ""),
    // embedding
    ("nvidia/NV-EmbedCode-7b-v1", 7.0, "none"),
    ("nvidia/NV-Embed-v2", 7.0, "none"),
    ("nvidia/llama-3.2-nv-embedqa-1b-v2", 1.0, "none"),
];

/// `ModelCatalog.estimate_vram_gb` — VRAM (GB) from param count + quant.
fn estimate_vram_gb(params_b: Option<f64>, quant: &str) -> Option<f64> {
    let p = params_b?;
    let q = quant.to_uppercase();
    Some(match q.as_str() {
        "AWQ" | "GPTQ" | "INT4" => round1(p * 0.6 + 1.5),
        "GGUF" => round1(p * 0.65 + 1.0),
        "INT8" | "W8A8" => round1(p * 1.1 + 1.5),
        _ => round1(p * 2.1 + 2.0), // fp16 / no quant (incl. NVFP4, none)
    })
}

/// `_extract_param_count` — first `(\d+(\.\d+)?)\s*[Bb]` in the id.
fn extract_param_count(model_id: &str) -> Option<f64> {
    let bytes: Vec<char> = model_id.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == '.' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let num: String = bytes[start..i].iter().collect();
            let mut j = i;
            while j < bytes.len() && bytes[j].is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == 'b' || bytes[j] == 'B') {
                if let Ok(v) = num.parse::<f64>() {
                    return Some(v);
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// `estimate_model_vram` — catalog lookup by id, else parse-from-id (fp16).
fn estimate_model_vram(model_id: &str) -> f64 {
    for (id, params, quant) in FALLBACK_MODELS {
        if *id == model_id {
            return estimate_vram_gb(Some(*params), quant).unwrap_or(0.0);
        }
    }
    match extract_param_count(model_id) {
        Some(p) => estimate_vram_gb(Some(p), "").unwrap_or(0.0),
        None => 0.0,
    }
}

/// `model_is_cached` — tolerant match of an id against a node's inventory.
fn model_is_cached(model_id: &str, available: Option<&Vec<Value>>) -> bool {
    let Some(list) = available else { return false };
    if list.is_empty() {
        return false;
    }
    let mid = model_id.to_lowercase();
    let base = mid.rsplit('/').next().unwrap_or(&mid).to_string();
    for a in list {
        let Some(al) = a.as_str() else { continue };
        let al = al.to_lowercase();
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

/// `match_node_for_model` — pick the best node (or an error dict).
fn match_node_for_model(model_id: &str, nodes: &[Value]) -> Value {
    let vram_need = estimate_model_vram(model_id);
    let mut candidates: Vec<(f64, usize, bool, bool)> = Vec::new();
    for (idx, n) in nodes.iter().enumerate() {
        if !n["online"].as_bool().unwrap_or(true) {
            continue;
        }
        let vram = n["vram_gb"].as_f64().unwrap_or(0.0);
        let ram = n["ram_gb"].as_f64().unwrap_or(0.0);
        let on_gpu = vram >= vram_need && vram > 0.0;
        let on_cpu = !on_gpu && ram >= (vram_need * 1.3).max(2.0);
        if !(on_gpu || on_cpu) {
            continue;
        }
        let cached = model_is_cached(model_id, n["available_models"].as_array());
        let load = n["current_load"].as_f64().unwrap_or(0.0);
        let waste = if on_gpu { vram - vram_need } else { 0.0 };
        let score = (if cached { 0.0 } else { 100.0 })
            + (if on_gpu { 0.0 } else { 40.0 })
            + waste
            + load * 10.0;
        candidates.push((score, idx, cached, on_gpu));
    }
    if candidates.is_empty() {
        return json!({
            "error": format!("no online node can run {model_id} (needs ~{}GB)", fmt_g(vram_need)),
            "vram_need": vram_need,
        });
    }
    candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let (_, idx, cached, on_gpu) = candidates[0];
    let node = &nodes[idx];
    let nid = node["node_id"].as_str().or_else(|| node["id"].as_str()).unwrap_or("");
    json!({
        "node_id": nid,
        "needs_pull": !cached,
        "on_gpu": on_gpu,
        "vram_need": vram_need,
        "reason": format!(
            "{} · {} · ~{}GB",
            if cached { "cached" } else { "pull required" },
            if on_gpu { "GPU" } else { "CPU" },
            fmt_g(vram_need)
        ),
    })
}

/// `plan_model_placements` — spread a set of models across the fleet.
fn plan_model_placements(models: &[String], nodes: &[Value]) -> Vec<Value> {
    let mut working: Vec<Value> = nodes.to_vec();
    let mut plan: Vec<Value> = Vec::new();
    for model in models {
        let d = match_node_for_model(model, &working);
        let mut entry = serde_json::Map::new();
        entry.insert("model".into(), json!(model));
        if let Some(obj) = d.as_object() {
            for (k, v) in obj {
                entry.insert(k.clone(), v.clone());
            }
        }
        plan.push(Value::Object(entry));
        if let Some(nid) = d["node_id"].as_str() {
            for n in working.iter_mut() {
                let this = n["node_id"].as_str().or_else(|| n["id"].as_str()).unwrap_or("");
                if this == nid {
                    let cur = n["current_load"].as_f64().unwrap_or(0.0) + 0.25;
                    n["current_load"] = json!(cur);
                    let mut am: Vec<Value> = n["available_models"].as_array().cloned().unwrap_or_default();
                    if !am.iter().any(|x| x.as_str() == Some(model.as_str())) {
                        am.push(json!(model));
                    }
                    n["available_models"] = json!(am);
                    break;
                }
            }
        }
    }
    plan
}

/// Ask the gateway whether `model` fits `node` beside what it already runs -
/// the same memory-fit verdict `noo cluster fit` prints and a desired-state
/// place enforces. `Some(message)` is a reason NOT to place (does not fit);
/// `None` means go ahead (fits, tight, unknown, or the gateway is too old to
/// answer: the placement route itself still enforces).
fn fit_refusal(g: &Globals, node: &str, backend: &str, model: &str) -> Option<String> {
    let resp = post_json_try(
        g,
        &format!("/api/cluster/nodes/{}/fit", super::urlencode(node)),
        &json!({"with": {"backend": backend, "model": model}}),
        true,
        10,
    )
    .ok()?;
    if resp["verdict"] == "does_not_fit" {
        let total = resp["total_gb"].as_f64().unwrap_or(0.0);
        let budget = resp["budget"]["total_gb"].as_f64().unwrap_or(0.0);
        return Some(format!(
            "{model} does not fit {node}: {total:.1} GB needed against a {budget:.1} GB budget (see `noo cluster fit {node} --with {backend} {model}`)"
        ));
    }
    None
}

/// `noo cluster place-model MODEL [--backend/-b B] [--apply]` — pick the best
/// node for MODEL by capability × cache and (with --apply) start it there.
pub fn cluster_place_model(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    const USAGE: &str = "usage: noo cluster place-model <model> [-b|--backend <backend>] [--node <node>] [--apply]\n  \
        picks the best node by capability and cache (or --node pins one); --apply starts it there.\n  \
        desired-state placement the agent keeps running: noo cluster place <node> <backend> <model>";
    let mut model: Option<String> = None;
    let mut backend = "ollama".to_string();
    let mut apply = false;
    let mut pin: Option<String> = None;
    let mut iter = args.iter();
    // Native-only verb: bad arguments print THIS usage. Returning Unhandled
    // fell through to "not available in this standalone binary … set
    // NOO_PY_CLI", which read as a broken install (host8, 2026-09-03).
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-b" | "--backend" => backend = iter.next().cloned().unwrap_or_else(|| fail(g.json, ExitCode::Usage, "usage", "--backend needs a value", Some(USAGE))),
            "--node" | "-n" => pin = iter.next().cloned(),
            "--apply" => apply = true,
            "--help" | "-h" => { println!("{USAGE}"); return Ok(0); }
            t if t.starts_with('-') => fail(g.json, ExitCode::Usage, "usage", &format!("unknown flag {t}"), Some(USAGE)),
            t if model.is_none() => model = Some(t.to_string()),
            t => fail(g.json, ExitCode::Usage, "usage",
                &format!("unexpected argument {t} — the model is the only positional (a node is --node, a backend is --backend)"), Some(USAGE)),
        }
    }
    let Some(model) = model else { fail(g.json, ExitCode::Usage, "usage", "a model is required", Some(USAGE)) };

    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let nodes = body["nodes"].as_array().unwrap_or(&empty);
    let decision = match pin {
        Some(n) => {
            let known = nodes.iter().any(|nd| nd.get("id").and_then(|v| v.as_str())
                .or_else(|| nd.get("node_id").and_then(|v| v.as_str()))
                .or_else(|| nd.get("name").and_then(|v| v.as_str()))
                .is_some_and(|id| id.eq_ignore_ascii_case(&n)));
            if !known {
                fail(g.json, ExitCode::Generic, "unknown_node", &format!("no node named {n} — see noo cluster status"), None);
            }
            json!({"node_id": n, "reason": "pinned with --node", "needs_pull": false})
        }
        None => match_node_for_model(&model, nodes),
    };

    if g.json {
        println!("{}", decision);
        return Ok(0);
    }
    if let Some(err) = decision["error"].as_str() {
        fail(g.json, ExitCode::Generic, "no_candidate", err, None);
    }
    let node = decision["node_id"].as_str().unwrap_or("?");
    ui::step(&format!("place {model} on {node}  ({})", decision["reason"].as_str().unwrap_or("")));
    if decision["needs_pull"].as_bool().unwrap_or(false) {
        say(&format!("  {}", ui::muted(&format!("needs pull: model not cached on {node}"))));
    }
    if !apply {
        say(&format!("  {}", ui::warn("dry-run — pass --apply to place it")));
        return Ok(0);
    }
    if let Some(why) = fit_refusal(g, node, &backend, &model) {
        fail(g.json, ExitCode::Generic, "does_not_fit", &why, None);
    }
    say(&format!("  placing via: {}", ui::cmd(&format!("noo cluster up {backend} {model} --node {node}"))));
    match post_json_try(
        g,
        "/api/cluster/backends/start",
        &json!({"backend": backend, "model": model, "node_id": node}),
        true,
        60,
    ) {
        Ok(_) => {
            ui::done(&format!("placement requested on {node}"));
            Ok(0)
        }
        Err(e) => {
            fail(g.json, ExitCode::Generic, "placement_failed", &format!("placement failed: {e}"), None);
        }
    }
}

/// `noo cluster auto-place MODELS… [--backend/-b B] [--apply]` — spread a SET
/// of models across the fleet (dry-run unless --apply).
pub fn cluster_auto_place(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut models: Vec<String> = Vec::new();
    let mut backend = "ollama".to_string();
    let mut apply = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-b" | "--backend" => backend = iter.next().ok_or(Unhandled)?.clone(),
            "--apply" => apply = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => models.push(t.to_string()),
        }
    }
    if models.is_empty() {
        return Err(Unhandled);
    }

    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let nodes = body["nodes"].as_array().unwrap_or(&empty);
    let plan = plan_model_placements(&models, nodes);

    if g.json {
        println!("{}", Value::Array(plan));
        return Ok(0);
    }

    let mut ok = true;
    for p in &plan {
        if let Some(err) = p["error"].as_str() {
            ui::failed(&format!("{}: {err}", p["model"].as_str().unwrap_or("?")), None);
            ok = false;
            continue;
        }
        let pull = if p["needs_pull"].as_bool().unwrap_or(false) { " (pull)" } else { "" };
        say(&ui::status_line(
                Glyph::Step,
                &format!(
                    "{}  →  {}{pull}  {}",
                    p["model"].as_str().unwrap_or("?"),
                    p["node_id"].as_str().unwrap_or("?"),
                    ui::muted(p["reason"].as_str().unwrap_or(""))
                ),
            ));
    }
    if !apply {
        say(&format!("  {}", ui::warn("dry-run — pass --apply to place them")));
        return Ok(if ok { 0 } else { 1 });
    }
    for p in &plan {
        if p["error"].is_string() {
            continue;
        }
        let model = p["model"].as_str().unwrap_or("");
        let node = p["node_id"].as_str().unwrap_or("");
        if let Some(why) = fit_refusal(g, node, &backend, model) {
            ui::failed(&why, None);
            ok = false;
            continue;
        }
        match post_json_try(
            g,
            "/api/cluster/backends/start",
            &json!({"backend": backend, "model": model, "node_id": node}),
            true,
            60,
        ) {
            Ok(_) => ui::done(&format!("{model} → {node}")),
            Err(e) => {
                ui::failed(&format!("{model} placement failed: {e}"), None);
                ok = false;
            }
        }
    }
    Ok(if ok { 0 } else { 1 })
}

// ════════════════════════════════════════════════════════════════════
//  Tailscale API (mint-join-key / set-primary)
// ════════════════════════════════════════════════════════════════════

fn tailscale_base() -> String {
    std::env::var("NOO_TAILSCALE_API_BASE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.tailscale.com/api/v2".to_string())
}

fn tailnet() -> String {
    let t = env_value("NOO_TAILSCALE_TAILNET");
    if t.is_empty() { "-".to_string() } else { t }
}

/// Call the Tailscale API with Basic auth (api_key as the username, empty
/// password — parity with httpx `auth=(api_key, "")`). Returns (status, body).
fn ts_request(method: &str, path: &str, api_key: &str, body: Option<&Value>) -> Result<(u16, String), String> {
    let url = format!("{}{}", tailscale_base(), path);
    let agent = plain_agent(15);
    let auth = format!("Basic {}", base64_std(format!("{api_key}:").as_bytes()));
    let result = match method {
        "POST" => {
            let req = agent.post(&url).header("Authorization", auth);
            match body {
                Some(b) => req.send_json(b),
                None => req.send_empty(),
            }
        }
        "DELETE" => agent.delete(&url).header("Authorization", auth).call(),
        _ => agent.get(&url).header("Authorization", auth).call(),
    };
    match result {
        Ok(mut r) => {
            let status = r.status().as_u16();
            let text = r.body_mut().read_to_string().unwrap_or_default();
            Ok((status, text))
        }
        Err(e) => Err(format!("{e}")),
    }
}

/// Offboard (finding #66): `tailscale logout` clears the machine's identity
/// but leaves its DEVICE RECORD in the tailnet, so every offboard→onboard
/// cycle re-registers as `<host>-1`, `-2`, … Delete our own record via the
/// API while the OAuth client still exists on disk (the tailnet section of
/// the offboard walk runs before secrets are removed). Matches by tailnet
/// IP first (unambiguous), hostname second; returns the deleted device name.
/// Seconds since the epoch for an RFC 3339 UTC stamp ("2026-09-02T14:03:11Z").
/// Enough for "is this device stale"; anything unparsable counts as stale.
fn rfc3339_to_epoch(ts: &str) -> Option<u64> {
    let (date, time) = ts.split_once('T')?;
    let mut d = date.split('-').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let time = time.trim_end_matches('Z');
    let time = time.split(['+', '.']).next()?;
    let mut t = time.split(':').map(|x| x.parse::<i64>().ok());
    let (hh, mm, ss) = (t.next()??, t.next()??, t.next()??);
    // days from civil (Howard Hinnant)
    let (y2, m2) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + hh * 3600 + mm * 60 + ss).max(0) as u64)
}

/// Remove tailnet device records named `hostname` that are STALE (last seen
/// more than `max_age_secs` ago). A fresh `tailscale up` with a new node key
/// otherwise lands as `<name>-1` beside the dead record (host3 → host3-1,
/// 2026-09-02); an online device with the name is never touched, so
/// re-tokening a live node is safe. Returns the names removed.
pub(crate) fn clear_stale_tailnet_devices(hostname: &str, max_age_secs: u64) -> Result<Vec<String>, String> {
    let key = tailscale_api_key();
    if key.is_empty() {
        return Err("no Tailscale API credential (OAuth client / NOO_TAILSCALE_API_KEY)".into());
    }
    let (code, body) = ts_request("GET", &format!("/tailnet/{}/devices", tailnet()), &key, None)?;
    if code != 200 {
        return Err(format!("device list failed (HTTP {code})"));
    }
    let parsed: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut removed = Vec::new();
    for dev in parsed["devices"].as_array().cloned().unwrap_or_default() {
        if dev["hostname"].as_str() != Some(hostname) {
            continue;
        }
        let seen = dev["lastSeen"].as_str().and_then(rfc3339_to_epoch).unwrap_or(0);
        if now.saturating_sub(seen) < max_age_secs {
            continue; // recently seen — live, leave it
        }
        let Some(id) = dev["nodeId"].as_str().or(dev["id"].as_str()) else { continue };
        let name = dev["name"].as_str().unwrap_or(hostname).to_string();
        let (c, _) = ts_request("DELETE", &format!("/device/{id}"), &key, None)?;
        if matches!(c, 200 | 204) {
            removed.push(name);
        } else {
            return Err(format!("delete of stale record {name} failed (HTTP {c})"));
        }
    }
    Ok(removed)
}

pub(crate) fn delete_tailnet_device(ips: &[String], hostname: &str) -> Result<String, String> {
    let key = tailscale_api_key();
    if key.is_empty() {
        return Err("no Tailscale API credential (OAuth client / NOO_TAILSCALE_API_KEY)".into());
    }
    let (code, body) = ts_request("GET", &format!("/tailnet/{}/devices", tailnet()), &key, None)?;
    if code == 403 {
        return Err("the OAuth client lacks the Devices scope — delete the record in the \
                    admin console, and add \u{201C}Devices \u{2192} Core: write\u{201D} to the client"
            .into());
    }
    if code != 200 {
        return Err(format!("device list failed (HTTP {code})"));
    }
    let parsed: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let devices = parsed["devices"].as_array().cloned().unwrap_or_default();
    let by_ip = |d: &&Value| {
        d["addresses"].as_array().is_some_and(|a| {
            a.iter().any(|x| ips.iter().any(|ip| x.as_str() == Some(ip.as_str())))
        })
    };
    let by_host = |d: &&Value| d["hostname"].as_str() == Some(hostname);
    let Some(dev) = devices.iter().find(by_ip).or_else(|| devices.iter().find(by_host)) else {
        return Err("device not found in the tailnet (already removed?)".into());
    };
    let id = dev["nodeId"]
        .as_str()
        .or(dev["id"].as_str())
        .ok_or("device record has no id")?
        .to_string();
    let name = dev["name"].as_str().unwrap_or(hostname).to_string();
    let (code, _) = ts_request("DELETE", &format!("/device/{id}"), &key, None)?;
    match code {
        200 | 204 => Ok(name),
        403 => Err("delete refused (403) — the OAuth client lacks \u{201C}Devices \u{2192} \
                    Core: write\u{201D}; remove the record in the admin console"
            .into()),
        c => Err(format!("delete failed (HTTP {c}) — remove the record in the admin console")),
    }
}

/// Outcome of the tagOwners ensure — the wizard reports each variant
/// differently (already-there is silent success, added gets the console
/// link, no-credential falls back to the manual stanza).
pub(crate) enum TagOwnerOutcome {
    AlreadyPresent,
    Added,
}

/// Read-only probe: is `tag` already declared in the tailnet ACL? Lets the
/// wizard skip the declare-prompt on converged tailnets (finding #25) —
/// unlike `ensure_tag_owner`, this NEVER writes.
pub(crate) fn tag_owner_present(tag: &str) -> Result<bool, String> {
    let token = tailscale_api_key();
    if token.is_empty() {
        return Err(TAILSCALE_KEY_HINT.to_string());
    }
    let url = format!("{}/tailnet/{}/acl", tailscale_base(), tailnet());
    let auth = format!("Basic {}", base64_std(format!("{token}:").as_bytes()));
    let mut resp = plain_agent(15)
        .get(&url)
        .header("Authorization", &auth)
        .header("Accept", "application/hujson")
        .call()
        .map_err(|e| format!("ACL read failed: {e}"))?;
    if resp.status().as_u16() != 200 {
        return Err(format!("ACL read failed: HTTP {}", resp.status().as_u16()));
    }
    let policy = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("ACL read failed: {e}"))?;
    Ok(policy.contains(&format!("\"{tag}\"")))
}

/// Every tag this CLI may write into the live tailnet policy over the API.
///
/// **Each one must also appear in `config/tailscale-acl.hujson`**, which is
/// the policy this project DECLARES and which `noo security tailnet policy
/// --push` pushes WHOLESALE — replace, not merge (as the retired
/// `bootstrap-controller.sh` did). A tag added over the API alone survives
/// only until the next push, which then deletes it silently.
/// `tag:kiosk` was added that way and had exactly that defect until the
/// declaration caught up.
///
/// The list is not documentation: `ensure_tag_owner` refuses anything not on
/// it, and `the_declared_acl_carries_every_api_tag` fails when an entry is
/// missing from the declared policy. Adding a tag therefore forces both
/// edits, rather than relying on whoever adds the next one remembering this.
pub(crate) const API_DECLARED_TAGS: &[&str] = &["tag:controller", "tag:worker", "tag:kiosk"];

/// Ensure `tag` is declared in the tailnet ACL's `tagOwners`.
///
/// HuJSON permits comments and trailing commas, which is what makes a
/// TEXTUAL insert safe: we never reformat the operator's policy, we add
/// one line after the `tagOwners {` brace (or append a fresh block before
/// the final `}`). The write is guarded with `If-Match` on the GET's ETag
/// so a concurrent console edit loses nothing — we fail and re-read.
///
/// Refuses a tag outside `API_DECLARED_TAGS` before it touches the network,
/// because a live-only tag is deleted by the next bootstrap.
pub(crate) fn ensure_tag_owner(tag: &str) -> Result<TagOwnerOutcome, String> {
    if !API_DECLARED_TAGS.contains(&tag) {
        return Err(format!(
            "{tag} is not declared in config/tailscale-acl.hujson. Writing it over the API \
             alone would work until the next wholesale push of the declared policy, which \
             would delete it — silently, since the host stays reachable \
             and only the port stops answering. Add it there and to API_DECLARED_TAGS."
        ));
    }
    let token = tailscale_api_key();
    if token.is_empty() {
        return Err(TAILSCALE_KEY_HINT.to_string());
    }
    let url = format!("{}/tailnet/{}/acl", tailscale_base(), tailnet());
    let auth = format!("Basic {}", base64_std(format!("{token}:").as_bytes()));

    let mut resp = plain_agent(15)
        .get(&url)
        .header("Authorization", &auth)
        .header("Accept", "application/hujson")
        .call()
        .map_err(|e| format!("ACL read failed: {e}"))?;
    if resp.status().as_u16() != 200 {
        return Err(format!("ACL read failed: HTTP {}", resp.status().as_u16()));
    }
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let policy = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("ACL read failed: {e}"))?;

    let needle = format!("\"{tag}\"");
    if policy.contains(&needle) {
        return Ok(TagOwnerOutcome::AlreadyPresent);
    }

    // tag:worker gets tag:controller as CO-OWNER (finding #46): an OAuth
    // client acts AS its tags and can only mint keys for tags one of its
    // own tags OWNS. autogroup:admin alone authorizes the human console
    // session — every client-side mint 400s "invalid or not permitted".
    let owners = if tag == "tag:worker" || tag == "tag:kiosk" {
        "[\"autogroup:admin\", \"tag:controller\"]"
    } else {
        "[\"autogroup:admin\"]"
    };
    let stanza_line = format!("\t\t\"{tag}\": {owners},\n");
    let updated = if let Some(pos) = policy.find("\"tagOwners\"") {
        // Insert one line right after the block's opening brace.
        let brace = policy[pos..]
            .find('{')
            .map(|i| pos + i + 1)
            .ok_or("malformed tagOwners block")?;
        format!("{}\n{}{}", &policy[..brace], stanza_line, &policy[brace..])
    } else {
        // No tagOwners at all: append a block before the final `}`.
        let end = policy.rfind('}').ok_or("malformed ACL policy")?;
        format!(
            "{},\n\t\"tagOwners\": {{\n{}\t}},\n{}",
            policy[..end].trim_end().trim_end_matches(','),
            stanza_line,
            &policy[end..]
        )
    };

    let mut req = plain_agent(15)
        .post(&url)
        .header("Authorization", &auth)
        .header("Content-Type", "application/hujson");
    if let Some(tag_val) = &etag {
        req = req.header("If-Match", tag_val);
    }
    let resp = req
        .send(updated.as_bytes())
        .map_err(|e| format!("ACL write failed: {e}"))?;
    match resp.status().as_u16() {
        200 => Ok(TagOwnerOutcome::Added),
        412 => Err("ACL changed while editing (concurrent console edit) — re-run to retry".into()),
        code => Err(format!("ACL write rejected: HTTP {code}")),
    }
}

/// Outcome of an ACL-rule ensure, reported like `TagOwnerOutcome`.
pub(crate) enum AclRuleOutcome {
    AlreadyPresent,
    Added,
}

/// Ensure the tailnet policy lets `src_tag` reach `dst_tag` on `port`
/// (the kiosk's `tag:kiosk → tag:controller:443`). Same TEXTUAL, ETag-guarded
/// edit as `ensure_tag_owner`: one rule line inserted at the top of the
/// `acls` array (or `grants`, if that is the dialect the policy uses), and
/// a fresh `acls` block appended when the policy has neither. Never
/// reformats the operator's policy.
///
/// "Present" is judged by the pair of literals, not by parsing HuJSON: a
/// policy mentioning both `"src_tag"` and `"dst_tag:port"` is taken as the
/// rule. That is the same fidelity `tag_owner_present` has, and the
/// failure mode is a duplicate rule, which tailscale accepts.
pub(crate) fn ensure_acl_grant(src_tag: &str, dst_tag: &str, port: u16) -> Result<AclRuleOutcome, String> {
    let token = tailscale_api_key();
    if token.is_empty() {
        return Err(TAILSCALE_KEY_HINT.to_string());
    }
    let url = format!("{}/tailnet/{}/acl", tailscale_base(), tailnet());
    let auth = format!("Basic {}", base64_std(format!("{token}:").as_bytes()));

    let mut resp = plain_agent(15)
        .get(&url)
        .header("Authorization", &auth)
        .header("Accept", "application/hujson")
        .call()
        .map_err(|e| format!("ACL read failed: {e}"))?;
    if resp.status().as_u16() != 200 {
        return Err(format!("ACL read failed: HTTP {}", resp.status().as_u16()));
    }
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let policy = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("ACL read failed: {e}"))?;

    let updated = match acl_grant_insert(&policy, src_tag, dst_tag, port) {
        None => return Ok(AclRuleOutcome::AlreadyPresent),
        Some(u) => u,
    };

    let mut req = plain_agent(15)
        .post(&url)
        .header("Authorization", &auth)
        .header("Content-Type", "application/hujson");
    if let Some(tag_val) = &etag {
        req = req.header("If-Match", tag_val);
    }
    let resp = req
        .send(updated.as_bytes())
        .map_err(|e| format!("ACL write failed: {e}"))?;
    match resp.status().as_u16() {
        200 => Ok(AclRuleOutcome::Added),
        412 => Err("ACL changed while editing (concurrent console edit) — re-run to retry".into()),
        code => Err(format!("ACL write rejected: HTTP {code}")),
    }
}

/// Is `src_tag → dst_tag:port` granted by SOME SINGLE RULE in `policy`?
///
/// The first version asked whether the policy contained `"tag:kiosk"`
/// anywhere and `"tag:controller:443"` anywhere, and took both as the rule.
/// That is a different question, and on 2026-09-13 it cost a live display:
/// `kiosk invite` had just written `tag:kiosk` into `tagOwners`, and
/// `tag:controller:443` was already present in the unrelated
/// `autogroup:member` rule. The check saw both strings, reported "rule
/// already present", and wrote nothing. Tagging the display then REPLACED
/// its member identity, so it lost the 443 it had been reaching the
/// controller on — and the symptom was a mint that TIMED OUT rather than
/// failed, because a denied tailnet port drops the packet.
///
/// So: require one `{…}` fragment to carry both names. Still textual —
/// HuJSON is not JSON and this module refuses to reformat an operator's
/// policy — but a rule IS an object, so "both names inside one object" is
/// the shape of the real question rather than a proxy for it.
///
/// Wrong in the safe direction on purpose: a false "absent" adds a duplicate
/// rule, which tailscale accepts and which grants nothing new. A false
/// "present" is what took the display down.
fn grant_present(policy: &str, src_tag: &str, dst_tag: &str, port: u16) -> bool {
    let dst = format!("\"{dst_tag}:{port}\"");
    let src = format!("\"{src_tag}\"");
    policy.split('{').any(|frag| {
        // Stop at this object's end so a LATER rule's text cannot be read
        // as part of this one.
        let obj = frag.split('}').next().unwrap_or("");
        obj.contains(&src) && obj.contains(&dst)
    })
}

/// The pure half of `ensure_acl_grant`: the edited policy text, or `None`
/// when the rule is already there. Split out so it is testable without a
/// tailnet.
pub(crate) fn acl_grant_insert(policy: &str, src_tag: &str, dst_tag: &str, port: u16) -> Option<String> {
    let dst = format!("{dst_tag}:{port}");
    if grant_present(policy, src_tag, dst_tag, port) {
        return None;
    }
    if let Some(pos) = policy.find("\"grants\"") {
        // grants dialect: {"src": [..], "dst": [..], "ip": ["tcp:443"]}
        let bracket = policy[pos..].find('[').map(|i| pos + i + 1)?;
        let line = format!(
            "\n\t\t{{\"src\": [\"{src_tag}\"], \"dst\": [\"{dst_tag}\"], \"ip\": [\"tcp:{port}\"]}},"
        );
        return Some(format!("{}{}{}", &policy[..bracket], line, &policy[bracket..]));
    }
    let line = format!(
        "\n\t\t{{\"action\": \"accept\", \"src\": [\"{src_tag}\"], \"dst\": [\"{dst}\"]}},"
    );
    if let Some(pos) = policy.find("\"acls\"") {
        let bracket = policy[pos..].find('[').map(|i| pos + i + 1)?;
        return Some(format!("{}{}{}", &policy[..bracket], line, &policy[bracket..]));
    }
    // Neither block: append an acls array before the final `}`.
    let end = policy.rfind('}')?;
    Some(format!(
        "{},\n\t\"acls\": [{}\n\t],\n{}",
        policy[..end].trim_end().trim_end_matches(','),
        line,
        &policy[end..]
    ))
}

/// Mint a pre-authorized, tagged, single-use tailnet auth key (the mint half
/// of `cluster mint-join-key`, without its printing). `expiry_secs` bounds
/// how long the key is usable, not the device.
pub(crate) fn mint_tagged_auth_key(tag: &str, expiry_secs: i64, description: &str) -> Result<String, String> {
    let api_key = tailscale_api_key();
    if api_key.is_empty() {
        return Err(TAILSCALE_KEY_HINT.to_string());
    }
    let payload = json!({
        "capabilities": {"devices": {"create": {
            "reusable": false,
            "ephemeral": false,
            "preauthorized": true,
            "tags": [tag],
        }}},
        "expirySeconds": expiry_secs,
        "description": description,
    });
    let (status, text) = ts_request("POST", &format!("/tailnet/{}/keys", tailnet()), &api_key, Some(&payload))
        .map_err(|e| format!("Could not reach the Tailscale API: {e}"))?;
    if status != 200 {
        let hint = if text.to_lowercase().contains("tag") {
            format!(" (is '{tag}' declared under tagOwners, with tag:controller as a co-owner?)")
        } else {
            String::new()
        };
        return Err(format!("Tailscale API {status}: {}{hint}", text.chars().take(300).collect::<String>()));
    }
    let parsed: Value = serde_json::from_str(&text).unwrap_or(json!({}));
    match parsed["key"].as_str() {
        Some(k) if !k.is_empty() => Ok(k.to_string()),
        _ => Err(format!("Tailscale API returned no key: {}", text.chars().take(200).collect::<String>())),
    }
}

#[cfg(test)]
mod acl_grant_tests {
    use super::acl_grant_insert;

    /// The regression, reproduced from the policy that actually caused it.
    /// `tag:kiosk` is in `tagOwners` and `tag:controller:443` is in the
    /// member rule — two true strings and no rule joining them. The old
    /// check called that "already present" and wrote nothing, and a live
    /// display lost its only grant the moment it was tagged.
    #[test]
    fn a_tag_in_tagowners_plus_the_port_elsewhere_is_not_a_grant() {
        let policy = "{\n\
             \t\"tagOwners\": {\n\
             \t\t\"tag:controller\": [\"autogroup:admin\"],\n\
             \t\t\"tag:kiosk\": [\"autogroup:admin\", \"tag:controller\"],\n\
             \t},\n\
             \t\"acls\": [\n\
             \t\t{\"action\": \"accept\", \"src\": [\"autogroup:member\"], \"dst\": [\"tag:controller:443\", \"tag:controller:8080\"]},\n\
             \t],\n\
             }\n";
        let out = acl_grant_insert(policy, "tag:kiosk", "tag:controller", 443)
            .expect("the grant is NOT present — both names exist but no rule joins them");
        assert!(out.contains("\"src\": [\"tag:kiosk\"], \"dst\": [\"tag:controller:443\"]"));
        // The member rule survives; we add, never rewrite.
        assert!(out.contains("\"src\": [\"autogroup:member\"]"));
    }

    /// The other half: a real rule must still be recognised, or every run
    /// appends another duplicate.
    #[test]
    fn a_real_rule_in_one_object_is_recognised() {
        let policy = "{\"acls\": [\n\
             \t{\"action\": \"accept\", \"src\": [\"autogroup:member\"], \"dst\": [\"tag:controller:443\"]},\n\
             \t{\"action\": \"accept\", \"src\": [\"tag:kiosk\"], \"dst\": [\"tag:controller:443\"]},\n\
             ]}";
        assert!(acl_grant_insert(policy, "tag:kiosk", "tag:controller", 443).is_none());
    }

    /// Adjacent rules must not be read as one. `tag:kiosk` is the source of
    /// the first and `tag:controller:443` the destination of the second —
    /// neighbours, not a grant.
    #[test]
    fn two_adjacent_rules_are_not_read_as_one() {
        let policy = "{\"acls\": [\n\
             \t{\"action\": \"accept\", \"src\": [\"tag:kiosk\"], \"dst\": [\"tag:controller:8099\"]},\n\
             \t{\"action\": \"accept\", \"src\": [\"autogroup:member\"], \"dst\": [\"tag:controller:443\"]},\n\
             ]}";
        assert!(
            acl_grant_insert(policy, "tag:kiosk", "tag:controller", 443).is_some(),
            "two neighbouring rules were read as one grant"
        );
    }

    #[test]
    fn inserts_into_an_existing_acls_array() {
        let policy = "{\n\t\"acls\": [\n\t\t{\"action\": \"accept\", \"src\": [\"tag:worker\"], \"dst\": [\"tag:controller:8080\"]},\n\t],\n}\n";
        let out = acl_grant_insert(policy, "tag:kiosk", "tag:controller", 443).expect("inserted");
        assert!(out.contains("\"src\": [\"tag:kiosk\"], \"dst\": [\"tag:controller:443\"]"));
        assert!(out.find("tag:kiosk").unwrap() < out.find("tag:worker").unwrap());
    }

    #[test]
    fn present_rule_is_left_alone() {
        let policy = "{\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:kiosk\"], \"dst\": [\"tag:controller:443\"]}]}";
        assert!(acl_grant_insert(policy, "tag:kiosk", "tag:controller", 443).is_none());
    }

    #[test]
    fn grants_dialect_uses_ip_field() {
        let policy = "{\n\t\"grants\": [\n\t],\n}\n";
        let out = acl_grant_insert(policy, "tag:kiosk", "tag:controller", 443).expect("inserted");
        assert!(out.contains("\"ip\": [\"tcp:443\"]"));
        assert!(!out.contains("\"action\""));
    }

    #[test]
    fn a_policy_with_neither_block_gets_an_acls_block() {
        let policy = "{\n\t\"tagOwners\": {\"tag:controller\": [\"autogroup:admin\"]},\n}\n";
        let out = acl_grant_insert(policy, "tag:kiosk", "tag:controller", 443).expect("inserted");
        assert!(out.contains("\"acls\": ["));
        assert!(out.contains("tag:controller:443"));
        assert!(out.trim_end().ends_with('}'));
    }
}

/// `noo cluster mint-join-key [--tag T] [--expiry-minutes N] [--reusable]
/// [--ssh-user U] [--script-url URL]` — mint a pre-authorized tagged Tailscale
/// auth key and print the bootstrap one-liner.
pub fn cluster_mint_join_key(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut tag = "tag:worker".to_string();
    let mut expiry_minutes: i64 = 60;
    let mut reusable = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--tag" => tag = iter.next().ok_or(Unhandled)?.clone(),
            "--expiry-minutes" => {
                expiry_minutes = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?
            }
            "--reusable" => reusable = true,
            // --ssh-user / --script-url fed the retired bootstrap-node
            // composition (#114); refuse loudly instead of silently ignoring.
            "--ssh-user" | "--script-url" => {
                fail(g.json, ExitCode::Generic, "retired_flag",
                     &format!("{tok} belonged to the retired bootstrap-node lane — use `noo cluster invite` or the unified paste"),
                     None);
            }
            _ => return Err(Unhandled),
        }
    }
    let api_key = tailscale_api_key();
    if api_key.is_empty() {
        fail(g.json, ExitCode::Generic, "no_api_key", TAILSCALE_KEY_HINT, None);
    }

    // Mint the key (POST /tailnet/{tailnet}/keys).
    let payload = json!({
        "capabilities": {"devices": {"create": {
            "reusable": reusable,
            "ephemeral": false,
            "preauthorized": true,
            "tags": [tag],
        }}},
        "expirySeconds": expiry_minutes * 60,
        "description": format!("noo-join-{}", tag.replace(':', "-")),
    });
    let (status, text) = match ts_request("POST", &format!("/tailnet/{}/keys", tailnet()), &api_key, Some(&payload)) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Generic, "tailscale_unreachable", &format!("Could not reach the Tailscale API: {e}"), None),
    };
    if status != 200 {
        let hint = if text.to_lowercase().contains("tag") {
            format!(" (is '{tag}' declared under tagOwners in the tailnet ACL policy?)")
        } else {
            String::new()
        };
        fail(g.json, ExitCode::Generic, "tailscale_error", &format!("Tailscale API {status}: {}{hint}", &text.chars().take(300).collect::<String>()), None);
    }
    let parsed: Value = serde_json::from_str(&text).unwrap_or(json!({}));
    let auth_key = parsed["key"].as_str().unwrap_or("").to_string();
    if auth_key.is_empty() {
        fail(g.json, ExitCode::Generic, "no_key", &format!("Tailscale API returned no key: {}", &text.chars().take(200).collect::<String>()), None);
    }

    // The bootstrap-node.sh one-liner + `add-node by
    // overlay IP` composition is RETIRED — it pointed at the stale private
    // mirror (HEAD probe already failed on every standalone install) and
    // at the pre-token lane the three enrollment lanes replaced. The raw
    // key mint stays useful (tagged keys have uses beyond enrollment);
    // enrollment guidance now points at the living lanes.
    if g.json {
        println!(
            "{}",
            json!({
                "auth_key": auth_key,
                "tag": tag,
                "expiry_minutes": expiry_minutes,
                "reusable": reusable,
                "note": "bootstrap-node one-liner retired — enroll with `noo cluster invite` (tailnet) or `noo cluster bootstrap-token create --node <n>`",
            })
        );
        return Ok(0);
    }
    ui::done(&format!("join key minted (single-use={}, expires in {expiry_minutes} min, tag={tag})", !reusable));
    ui::value(&auth_key.to_string());
    say(&ui::note("this key alone only joins the tailnet — to enroll a node, prefer the full flows"));
    ui::guide(&[
        ("noo cluster invite", "tailnet-native lane: no shared secrets, admission by whois + dialback"),
        ("noo cluster bootstrap-token create --node <n>", "unified one-paste lane (the default): mints a single-use token bound to the node name"),
    ]);
    Ok(0)

}

const PRIMARY_ALIAS: &str = "noo-controller";

/// minutes since an ISO-8601 lastSeen ("…Z"); None if unparseable.
fn minutes_since(raw: &str) -> Option<f64> {
    use time::{format_description::well_known::Rfc3339, OffsetDateTime};
    let seen = OffsetDateTime::parse(raw, &Rfc3339).ok()?;
    let now = OffsetDateTime::now_utc();
    Some((now - seen).as_seconds_f64() / 60.0)
}

fn last_seen_desc(d: &Value) -> String {
    let raw = d["lastSeen"].as_str().unwrap_or("");
    match minutes_since(raw) {
        Some(mins) if mins < 5.0 => "online".to_string(),
        Some(mins) if mins > 90.0 => format!("last seen {:.1}h ago", mins / 60.0),
        Some(mins) => format!("last seen {mins:.0}m ago"),
        None => "unknown".to_string(),
    }
}

fn short_name(d: &Value) -> String {
    d["name"].as_str().unwrap_or("").split('.').next().unwrap_or("").to_string()
}

/// `noo cluster set-primary [--to TARGET] [--promoted] [--yes/-y]` — cut the
/// primary-controller role over to another controller (Tailscale device
/// rename).
///
/// The Postgres promotion on the target is NOT done from here. It used to be
/// `ssh <user>@<ip> 'cd ~/pai-assistant && ./scripts/bootstrap-standby.sh
/// promote --yes'` — the last `ssh` spawn left in this crate, missed by
/// tests/test_no_controller_ssh.py because that guard greps for
/// `Command::new("ssh")` and this one went through `spawn_inherited`. It also
/// assumed a repo checkout at ~/pai-assistant that enrollment stopped
/// creating. The controller\u{2192}node SSH lane was removed 2026-09-11; the
/// promotion is now an explicit step the operator runs ON the target, and
/// `--promoted` is how they tell this command they have done it.
pub fn cluster_set_primary(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut to: Option<String> = None;
    let mut promoted = false;
    let mut yes = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--to" => to = Some(iter.next().ok_or(Unhandled)?.clone()),
            // `--ssh-user` selected an account for a login this command no
            // longer performs. Refuse it loudly rather than ignore it: a
            // silently-dropped flag is how an operator concludes the
            // promotion happened.
            "--ssh-user" => {
                let _ = iter.next();
                fail(g.json, ExitCode::Usage, "ssh_lane_removed",
                     "`--ssh-user` selected an SSH account; set-primary no longer logs in \
                      anywhere (the controller\u{2192}node SSH lane was removed 2026-09-11). \
                      Run the promotion on the target, then re-run with --promoted.",
                     None);
            }
            // Kept as an alias so an existing runbook/script does not break:
            // it always meant "do not promote from here", which is now the
            // only behaviour.
            "--skip-promote" | "--promoted" => promoted = true,
            "-y" | "--yes" => yes = true,
            _ => return Err(Unhandled),
        }
    }

    let api_key = tailscale_api_key();
    if api_key.is_empty() {
        fail(g.json, ExitCode::Generic, "no_api_key", TAILSCALE_KEY_HINT, None);
    }

    let (status, text) = match ts_request("GET", &format!("/tailnet/{}/devices", tailnet()), &api_key, None) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Generic, "tailscale_unreachable", &format!("Could not reach the Tailscale API: {e}"), None),
    };
    if status != 200 {
        fail(g.json, ExitCode::Generic, "tailscale_error", &format!("Tailscale API error {status} on /devices: {text}"), None);
    }
    let devices_body: Value = serde_json::from_str(&text).unwrap_or(json!({}));
    let empty = Vec::new();
    let controllers: Vec<Value> = devices_body["devices"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|d| {
            d["tags"].as_array().map(|t| t.iter().any(|x| x.as_str() == Some("tag:controller"))).unwrap_or(false)
        })
        .cloned()
        .collect();
    if controllers.is_empty() {
        fail(g.json, ExitCode::Generic, "no_controllers", "No devices tagged tag:controller found on the tailnet.", None);
    }

    let is_current_primary = |d: &Value| short_name(d) == PRIMARY_ALIAS;
    let overlay_ip = |d: &Value| -> Option<String> {
        d["addresses"].as_array().and_then(|a| {
            a.iter().filter_map(|x| x.as_str()).find(|s| s.starts_with("100.")).map(String::from)
        })
    };

    if !g.json {
        say(&ui::section("controller devices"));
        let rows: Vec<Vec<String>> = controllers
            .iter()
            .enumerate()
            .map(|(i, d)| {
                vec![
                    (i + 1).to_string(),
                    short_name(d),
                    d["hostname"].as_str().unwrap_or("?").to_string(),
                    overlay_ip(d).unwrap_or_else(|| "?".into()),
                    last_seen_desc(d),
                    if is_current_primary(d) { ui::state("primary") } else { ui::muted("standby") },
                ]
            })
            .collect();
        say(ui::table(
            &[Col::right("#"), Col::left("tailscale name"), Col::left("identity"), Col::left("overlay ip"), Col::left("status"), Col::left("role")],
            &rows,
        ).trim_end());
    }

    let old_primary = controllers.iter().find(|d| is_current_primary(d)).cloned();

    // Resolve the target.
    let target: Value = if let Some(want) = &to {
        match controllers.iter().find(|d| {
            short_name(d) == *want
                || d["hostname"].as_str() == Some(want.as_str())
                || d["addresses"].as_array().map(|a| a.iter().any(|x| x.as_str() == Some(want.as_str()))).unwrap_or(false)
        }) {
            Some(d) => d.clone(),
            None => fail(g.json, ExitCode::Generic, "no_match", &format!("No controller device matches '{want}'."), None),
        }
    } else {
        // Interactive selection — refuse to block in --json / non-TTY.
        if g.json || unsafe { libc::isatty(0) } != 1 {
            fail(
                g.json,
                ExitCode::Generic,
                "target_required",
                "no target selected: pass --to <name|100.x-ip>",
                Some("interactive selection is refused in --json / non-TTY mode"),
            );
        }
        eprint!("Promote which controller to PRIMARY? (#): ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        match line.trim().parse::<usize>() {
            Ok(n) if n >= 1 && n <= controllers.len() => controllers[n - 1].clone(),
            _ => fail(g.json, ExitCode::Generic, "bad_selection", "Invalid selection.", None),
        }
    };

    if is_current_primary(&target) {
        let msg = format!("{} already holds the {PRIMARY_ALIAS} role — nothing to do.", target["hostname"].as_str().unwrap_or("?"));
        if g.json {
            println!("{}", json!({"status": "noop", "message": msg}));
        } else {
            say(&msg.to_string());
        }
        return Ok(0);
    }

    let target_ip = overlay_ip(&target);
    let target_id = target["hostname"].as_str().unwrap_or_else(|| "").to_string();
    let target_id = if target_id.is_empty() { short_name(&target) } else { target_id };

    // Confirm the cutover plan (agent-first: --yes skips, non-TTY/json refuses).
    if !yes && !g.json {
        say(&ui::phase("Cutover Plan"));
        say(&ui::status_line(Glyph::Bullet, &format!(
            "Postgres promotion on {target_id} ({}) is YOUR step, not this command's",
            target_ip.as_deref().unwrap_or("?")
        )));
        match &old_primary {
            Some(op) => say(&ui::status_line(Glyph::Bullet, &format!("rename old primary → its identity ({})", op["hostname"].as_str().unwrap_or("?")))),
            None => say(&ui::status_line(Glyph::Bullet, "no device currently holds the role")),
        }
        say(&ui::status_line(Glyph::Bullet, &format!("rename {target_id} → {PRIMARY_ALIAS} (tailnet workers re-home via MagicDNS)")));
        say("");
        if let Some(op) = &old_primary {
            if last_seen_desc(op).contains("online") {
                ui::warned(&format!(
                    "old primary '{}' looks ONLINE. Stop its stack (noo stack stop) before cutover — two live primaries diverge.",
                    op["hostname"].as_str().unwrap_or("?")
                ));
            }
        }
    }
    super::confirm_destructive(g, yes, "Proceed with promoting", &format!("{target_id} to {PRIMARY_ALIAS}"));

    // 1. Promotion happens ON the target. This command cannot do it: the
    //    controller has no SSH key, no container mounts one, and every mesh
    //    rail runs through a node-agent that a standby controller's Postgres
    //    does not sit behind. Refusing is the honest outcome — the previous
    //    behaviour (ssh into ~/pai-assistant) broke the day enrollment
    //    stopped leaving a checkout there, and reported the role moved.
    if !promoted {
        let ip = target_ip.as_deref().unwrap_or("<target-ip>");
        fail(
            g.json,
            ExitCode::Generic,
            "promote_is_manual",
            &format!(
                "Promote Postgres on {target_id} FIRST, on that machine:\n\n  \
                 ssh-less, hands-on-the-box:\n    \
                 scripts/bootstrap-standby.sh promote --yes   \
                 (a checkout: ./scripts/…; a binary install: ~/.noo/scripts/…)\n\n\
                 Then re-run:  noo cluster set-primary --to {target_id} --promoted\n\n\
                 ({ip} is the target's overlay address, for your reference. This \
                 command will not log in anywhere \u{2014} the controller\u{2192}node \
                 SSH lane was removed 2026-09-11.)"
            ),
            None,
        );
    }
    if !g.json {
        say(&ui::phase("Promote"));
        ui::done("promotion acknowledged (--promoted) \u{2014} moving the role name");
    }

    // 2+3. Swap the role name (control-plane; works even if old primary is down).
    if !g.json {
        say(&ui::phase("Role"));
    }
    if let Some(op) = &old_primary {
        let identity = op["hostname"].as_str().filter(|s| !s.is_empty()).unwrap_or("controller-old");
        let id = op["id"].as_str().unwrap_or("");
        let _ = ts_request("POST", &format!("/device/{id}/name"), &api_key, Some(&json!({"name": identity})));
        if !g.json {
            ui::done(&format!("old primary renamed → {identity}"));
        }
    }
    let tid = target["id"].as_str().unwrap_or("");
    if let Err(e) = ts_request("POST", &format!("/device/{tid}/name"), &api_key, Some(&json!({"name": PRIMARY_ALIAS}))) {
        fail(g.json, ExitCode::Generic, "rename_failed", &format!("Failed to rename target device: {e}"), None);
    }

    if g.json {
        println!("{}", json!({"status": "ok", "new_primary": target_id, "alias": PRIMARY_ALIAS}));
    } else {
        ui::done(&format!("{target_id} renamed → {PRIMARY_ALIAS}"));
        ui::close_done(&format!("{target_id} is now {PRIMARY_ALIAS} — tailnet workers re-home via MagicDNS"));
        ui::guide(&[
            ("noo stack start", &format!("on {target_id}: bring the full stack up under the new role")),
            ("noo cluster status", "workers re-home within a heartbeat or two; one still carrying a stale noo-controller /etc/hosts entry will not, and must be cleared on that node"),
        ]);
    }
    Ok(0)
}

// ── reconcile-models (idempotent desired-state convergence) ─────────

/// `_norm_model_name` — loose key: strip org + :tag, drop non-alphanumerics.
fn norm_model_name(m: &str) -> String {
    let lower = m.to_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    let base = base.split(':').next().unwrap_or(base);
    base.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

/// `reconcile_models` — plan placement only for desired models NOT already
/// running anywhere (per each node's `running_backends` map).
fn reconcile_models(desired: &[String], nodes: &[Value]) -> Vec<Value> {
    let mut running: std::collections::HashSet<String> = std::collections::HashSet::new();
    for n in nodes {
        if let Some(map) = n["running_backends"].as_object() {
            for v in map.values() {
                if let Some(m) = v.as_str() {
                    if !m.is_empty() {
                        running.insert(norm_model_name(m));
                    }
                }
            }
        }
    }
    let to_place: Vec<String> =
        desired.iter().filter(|m| !running.contains(&norm_model_name(m))).cloned().collect();
    plan_model_placements(&to_place, nodes)
}

/// `noo cluster reconcile-models [MODELS…] [--backend/-b B] [--apply]` —
/// converge the fleet to a desired set (default `NOO_DESIRED_MODELS`),
/// planning placement only for the gap. Dry-run unless --apply.
pub fn cluster_reconcile_models(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut models: Vec<String> = Vec::new();
    let mut backend = "ollama".to_string();
    let mut apply = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-b" | "--backend" => backend = iter.next().ok_or(Unhandled)?.clone(),
            "--apply" => apply = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => models.push(t.to_string()),
        }
    }
    let desired: Vec<String> = if !models.is_empty() {
        models
    } else {
        env_value("NOO_DESIRED_MODELS")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    if desired.is_empty() {
        fail(
            g.json,
            ExitCode::Generic,
            "no_desired",
            "no desired models (pass them as args or set NOO_DESIRED_MODELS)",
            None,
        );
    }

    let body = get_json(g, "/api/cluster/nodes", true, 10);
    let empty = Vec::new();
    let nodes = body["nodes"].as_array().unwrap_or(&empty);
    let plan = reconcile_models(&desired, nodes);

    if g.json {
        println!("{}", json!({"desired": desired, "to_place": plan}));
        return Ok(0);
    }
    if plan.is_empty() {
        ui::done(&format!("fleet already satisfies the desired set ({} models)", desired.len()));
        return Ok(0);
    }
    say(&ui::emph(&format!("{} model(s) need placing", plan.len())));
    let mut ok = true;
    for p in &plan {
        if let Some(err) = p["error"].as_str() {
            ui::failed(&format!("{}: {err}", p["model"].as_str().unwrap_or("?")), None);
            ok = false;
            continue;
        }
        let pull = if p["needs_pull"].as_bool().unwrap_or(false) { " (pull)" } else { "" };
        say(&ui::status_line(
                Glyph::Step,
                &format!(
                    "{}  →  {}{pull}  {}",
                    p["model"].as_str().unwrap_or("?"),
                    p["node_id"].as_str().unwrap_or("?"),
                    ui::muted(p["reason"].as_str().unwrap_or(""))
                ),
            ));
    }
    if !apply {
        say(&format!("  {}", ui::warn("dry-run — pass --apply to converge")));
        return Ok(if ok { 0 } else { 1 });
    }
    for p in &plan {
        if p["error"].is_string() {
            continue;
        }
        let model = p["model"].as_str().unwrap_or("");
        let node = p["node_id"].as_str().unwrap_or("");
        match post_json_try(g, "/api/cluster/backends/start", &json!({"backend": backend, "model": model, "node_id": node}), true, 60) {
            Ok(_) => ui::done(&format!("{model} → {node}")),
            Err(e) => {
                ui::failed(&format!("{model} placement failed: {e}"), None);
                ok = false;
            }
        }
    }
    Ok(if ok { 0 } else { 1 })
}

// ════════════════════════════════════════════════════════════════════
//  Bootstrap-token enrollment — thin over the gateway's
//  /api/security/bootstrap-tokens surface. The gateway mints, hashes and
//  audits; this side only parses flags and prints the one-liner.
// ════════════════════════════════════════════════════════════════════

/// Parse a TTL like `1h`, `30m`, `24h`, `90s`, `1d`, or bare seconds.
pub(crate) fn parse_ttl_seconds(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: i64 = num.trim().parse().ok()?;
    match unit {
        "s" | "S" => Some(n),
        "m" | "M" => Some(n * 60),
        "h" | "H" => Some(n * 3600),
        "d" | "D" => Some(n * 86_400),
        _ => None,
    }
}

/// `noo cluster bootstrap-token create [--ttl 1h|30m|24h|3600] [--role R]
/// [--cidr C]` — mint a single-use enrollment token and print the one-liner.
/// `noo cluster bootstrap-token` with a wrong/missing subaction — a
/// near-miss used to fall through to the Python-CLI passthrough and die in
/// "set NOO_PY_CLI" advice that has nothing to do with the typo (live
/// 2026-08-27: `bootstrap-token --node host5`, missing `create`). A group
/// stub owns the prefix and prints the real usage instead (finding #89).
pub fn cluster_bootstrap_token_usage(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    crate::output::fail(
        g.json,
        crate::output::ExitCode::Usage,
        "usage",
        "noo cluster bootstrap-token needs a subaction",
        Some(
            "create --node <name> [--ttl <secs>]   mint a single-use enrollment token\n  \
             list                                  show outstanding tokens\n  \
             revoke <id>                           revoke one",
        ),
    );
}

/// The installer's home (matches scripts/install-noo.sh REPO).
/// The repo an enrolling node is told to install from. Resolved, not typed:
/// a hardcoded literal here ignores NOO_CLI_REPO and would send new nodes to
/// the old repo after a release move, reporting success.
fn install_repo() -> String { super::upgrade::repo() }

/// Why the tailnet key could not be minted, and what fixes it. The 400
/// "invalid or not permitted" body blames the ACL, but with converged
/// tagOwners the ACTUAL cause is the OAuth client's own grant (created before
/// the tag existed in the ACL) — the misleading layer cost a live debugging
/// round (finding #37).
fn explain_ts_mint_failure(e: &str) {
    say(&ui::muted(&format!("tailscale key mint unavailable ({e}) — printing the enrollment-only paste; the node must already reach the controller (or pass --no-tailscale to silence this)")));
    if e.contains("invalid or not permitted") {
        // #46 corrected the remediation: with both tags on the client and
        // both declared, the missing piece is the OWNERSHIP chain — the
        // client (acting as its tags) must OWN the tag it mints.
        say(&ui::note("an OAuth client can only mint tags one of its OWN tags owns — make tag:controller a co-owner in the ACL:"));
        say(&ui::note("\"tag:worker\": [\"autogroup:admin\", \"tag:controller\"],"));
        ui::guide(&[
            ("https://login.tailscale.com/admin/acls/file", "policy editor — add the co-owner, then re-run this command"),
            ("noo onboard --reconfigure --only enrollment", "if the client itself lacks a tag, regenerate it with both tags and re-paste here"),
        ]);
    }
}

/// Clear a stale tailnet record for this node name before the node joins
/// with a fresh key (otherwise it lands as <name>-1).
fn clear_stale_for(node: Option<&str>) {
    let Some(n) = node else { return };
    match clear_stale_tailnet_devices(n, 10 * 60) {
        Ok(v) if !v.is_empty() => ui::done(&format!("cleared stale tailnet device record(s): {} (last seen > 10 min ago)", v.join(", "))),
        Ok(_) => {}
        Err(e) => say(&ui::muted(&format!("stale-record check skipped: {e}"))),
    }
}

/// The ONE enrollment paste, however it was composed.
struct EnrollPaste<'a> {
    install: &'a str,
    enroll: &'a str,
    /// The controller URL inside the blob — the offline-fleet mirror hint
    /// points at the same address.
    noo_url: &'a str,
    self_node: bool,
    joins_tailnet: bool,
    node: Option<&'a str>,
}

fn print_enroll_paste(p: &EnrollPaste) {
    say(&ui::emph("run AS YOUR USER on the node (one sudo prompt)"));
    say("");
    say(&ui::status_line(Glyph::Step, "step 1 — make sure the noo CLI is on the node (skip if `noo --version` already works):"));
    // The controller-mirror lane used to lead here, fetched with
    // `curl -fsSk` and NOO_CLI_INSECURE=1 — both halves of that one-liner
    // turned certificate verification off, which meant the node's very
    // FIRST command took a shell script, and the binary that script
    // installed, from whoever happened to answer on the wire. The public
    // lane leads now: its TLS verifies against the system store and
    // install.sh checks the release signature against keys printed in its
    // own source. The mirror lane stays for a fleet with no path to
    // GitHub, but it has to be handed the controller's CA explicitly.
    say(&format!("  {}", p.install));
    say(&format!("  {}", ui::muted("Linux and Apple Silicon. Offline fleet? serve it from this controller instead —")));
    say(&format!("  {}", ui::muted("copy the controller's CA to the node first (scp /etc/noo/pki/ca.crt), then:")));
    let noo_url = p.noo_url;
    say(&format!("  {}", ui::muted(&format!("curl -fsSL --cacert ca.crt {noo_url}/bootstrap/cli/install.sh | NOO_CLI_BASE_URL={noo_url}/bootstrap/cli NOO_CLI_CACERT=$PWD/ca.crt sh"))));
    say("");
    say(&ui::status_line(Glyph::Step, if p.self_node {
        "step 2 — enroll (runs host prep, installs the agent; this device stays tag:controller):"
    } else if p.joins_tailnet {
        "step 2 — enroll (joins the tailnet, runs host prep, installs the agent):"
    } else {
        "step 2 — enroll (runs host prep, installs the agent; the node must already reach the controller):"
    }));
    // The enroll line is the captured value: `--quiet` keeps it alone.
    if ui::quiet() {
        ui::value(p.enroll);
    } else {
        say(&format!("  {}", p.enroll));
    }
    say(&format!("  {}", ui::muted("it asks where to keep models/data, defaulting to the largest writable disk;")));
    say(&format!("  {}", ui::muted("add --data-root <dir> to answer that up front for unattended runs")));
    say("");
    if let Some(n) = p.node {
        // #91: the old hint named a repo script that does not exist on a
        // standalone install — the CLI command is the product surface.
        say(&format!("bound to node: {n}. When the paste finishes: {}", ui::cmd(&format!("noo cluster provision {n} --wait"))));
    }
}

pub fn cluster_bootstrap_token_create(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut ttl_seconds: Option<i64> = None;
    let mut role: Option<String> = None;
    let mut cidr: Option<String> = None;
    let mut node: Option<String> = None;
    // Tailscale-unified is the DEFAULT (operator, 2026-08-18): the common
    // fresh-onboard case is a machine not yet on the tailnet. --no-tailscale
    // skips it; a missing TS API key degrades gracefully to the plain
    // enrollment one-liner instead of failing the mint.
    let mut with_ts = true;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--ttl" => {
                let raw = iter.next().ok_or(Unhandled)?;
                ttl_seconds = Some(parse_ttl_seconds(raw).ok_or(Unhandled)?);
            }
            "--role" => role = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--cidr" => cidr = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--node" => node = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--with-tailscale" => with_ts = true, // default; kept for compat
            "--no-tailscale" => with_ts = false,
            _ => return Err(Unhandled),
        }
    }

    let mut body = json!({});
    if let Some(t) = ttl_seconds {
        body["ttl_seconds"] = json!(t);
    }
    if let Some(r) = &role {
        body["role_hint"] = json!(r);
    }
    if let Some(c) = &cidr {
        body["allowed_cidr"] = json!(c);
    }
    let self_node = node.as_deref().is_some_and(crate::role::is_self_node);
    if self_node && with_ts {
        // The controller's device is already on the tailnet as
        // tag:controller; a worker key would re-tag it and cut every
        // remote node off (2026-09-09). Same command, one thing fewer.
        say(&ui::muted("this is the controller's own device — no tailnet key minted (it is already tag:controller)"));
        with_ts = false;
    }
    if let Some(n) = &node {
        // Bind the token to one node name (migration 052): redemption from a
        // host reporting any other hostname is refused, and provision-node
        // resolves the inventory entry from the redemption record.
        body["node_name"] = json!(n);
    }

    // The gateway composes the paste (install, then `noo enroll noo1.<blob>`)
    // so the console, this CLI and the MCP tool hand out the same one; it
    // mints the tailnet key too when asked. An older gateway ignores the
    // field and returns neither command — the local composition below
    // stays for it.
    body["with_tailscale"] = json!(with_ts);
    let resp = match post_json_try(g, "/api/security/bootstrap-tokens", &body, true, 15) {
        Ok(v) => v,
        // The gateway refuses the WHOLE mint when the tailnet key fails (no
        // token is minted), so the graceful degrade the local mint had is
        // one retry away: say why, then ask for the enrollment-only paste.
        Err(e) if with_ts && e.contains("could not mint the tailnet auth key") => {
            if !g.json {
                explain_ts_mint_failure(&e);
            }
            with_ts = false;
            body["with_tailscale"] = json!(false);
            match post_json_try(g, "/api/security/bootstrap-tokens", &body, true, 15) {
                Ok(v) => v,
                Err(e) => fail(g.json, ExitCode::Generic, "mint_failed", &e, None),
            }
        }
        Err(e) => fail(g.json, ExitCode::Generic, "mint_failed", &e, None),
    };
    if g.json {
        println!("{resp}");
        return Ok(0);
    }

    if let (Some(install), Some(enroll)) = (resp["install_command"].as_str(), resp["enroll_command"].as_str()) {
        let joins_tailnet = resp["joins_tailnet"].as_bool().unwrap_or(false);
        if let Some(note) = resp["tailnet_skipped"].as_str() {
            say(&ui::muted(note));
        }
        // The gateway cleared stale records under this name before minting
        // the key (the same check clear_stale_for runs for an older gateway);
        // report what it did rather than doing it twice.
        if joins_tailnet {
            let cleared: Vec<&str> = resp["tailnet_cleared"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
            if !cleared.is_empty() {
                ui::done(&format!("cleared stale tailnet device record(s): {} (last seen > 10 min ago)", cleared.join(", ")));
            }
            if let Some(e) = resp["tailnet_clear_error"].as_str() {
                say(&ui::muted(&format!("stale-record check skipped: {e}")));
            }
        }
        print_enroll_paste(&EnrollPaste {
            install,
            enroll,
            noo_url: resp["controller_url"].as_str().unwrap_or(""),
            self_node,
            joins_tailnet,
            node: resp["node_name"].as_str(),
        });
        let id = resp["id"].as_str().unwrap_or("?");
        let expires = resp["expires_at"].as_str().unwrap_or("?");
        say(&ui::note(&format!("single-use; expires {expires} — if the paste leaks: noo cluster bootstrap-token revoke {id}")));
        return Ok(0);
    }

    // Older gateway (no server-side paste): compose it here. Unified
    // one-paste: mint a tailscale auth key too and compose ONE
    // command that joins the tailnet AND enrolls.
    if with_ts {
        // Graceful degrade: no TS API key configured -> plain enrollment
        // one-liner (the node must already reach the controller), with a note.
        match post_json_try(g, "/api/cluster/mint-join-key", &json!({}), true, 30) {
            Err(e) => explain_ts_mint_failure(&e),
            Ok(ts) => {
                let auth_key = ts["auth_key"].as_str().unwrap_or("");
                let raw = resp["token"].as_str().unwrap_or("");
                // NOO_URL must be an address a FRESH TAILNET NODE can reach.
                // controller_url() is often unset (=> localhost) and
                // `noo-controller` only resolves after prep writes /etc/hosts
                // — both useless in the paste. The controller's own tailscale
                // IP is exactly what the node can reach the moment `up`
                // returns. Both failure modes were caught by operator review,
                // not by a run.
                // Prefer the controller's MagicDNS name (operator, 2026-08-18:
                // "shouldn't that controller already have the magic dns?" —
                // it does, and the DEVICE is named noo-controller, so a fresh
                // node resolves <name>.<tailnet>.ts.net the instant `up`
                // returns). Stabler than an IP across re-addressing, and the
                // ts.net name is what the future LE-cert bootstrap surface
                // verifies against. Raw IP stays as the fallback.
                let ts_addr = std::process::Command::new("tailscale")
                    .args(["status", "--json"])
                    .output()
                    .ok()
                    .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
                    .and_then(|v| v["Self"]["DNSName"].as_str().map(|d| d.trim_end_matches('.').to_string()))
                    .filter(|d| !d.is_empty())
                    .or_else(|| {
                        std::process::Command::new("tailscale")
                            .args(["ip", "-4"])
                            .output()
                            .ok()
                            .and_then(|o| String::from_utf8(o.stdout).ok())
                            .map(|s| s.lines().next().unwrap_or("").trim().to_string())
                            .filter(|s| !s.is_empty())
                    })
                    .unwrap_or_default();
                if auth_key.is_empty() || raw.is_empty() || ts_addr.is_empty() {
                    fail(g.json, ExitCode::Generic, "compose_failed",
                         "missing auth_key/token, or tailscale reported no DNSName/IP on this controller", None);
                }
                let noo_url = format!("https://{ts_addr}:8080");
                // SELF-CONTAINED paste — no hosted script. The previous
                // composition fetched bootstrap-node.sh from the OSS mirror,
                // which is currently PRIVATE and stale (404): the paste would
                // have died at step one. The only external fetch here is
                // tailscale's own installer; everything after comes from the
                // controller over the freshly-joined tailnet.
                // The node has no anchor at the instant it first calls home,
                // so its ONE first-contact request (GET /bootstrap/ca.crt)
                // cannot verify the transport. What makes that safe is the
                // fingerprint below: the paste carries the CA's DER-sha256,
                // so the node VERIFIES the anchor it fetches instead of
                // trusting first use, and a tampered transport cannot
                // substitute its own CA. Everything after that verifies
                // against the pinned anchor. The openssl DER
                // re-encode makes the pin PEM-formatting-proof.
                //
                // The pin is MANDATORY — a paste without one is refused by
                // `noo enroll`, so minting one would just produce a blob that
                // cannot be used. Fail here instead, where the operator can
                // do something about it.
                let ca_hex = std::process::Command::new("openssl")
                    .args(["x509", "-outform", "DER", "-in"])
                    .arg(crate::pki::ClusterCa::new(crate::pki::pki_dir()).ca_cert_path())
                    .output()
                    .ok()
                    .filter(|o| o.status.success() && !o.stdout.is_empty())
                    .map(|o| {
                        use sha2::{Digest, Sha256};
                        hex::encode(Sha256::digest(&o.stdout))
                    });
                // ONE lane (operator 2026-09-02: "should we just try the one
                // approach — noo cli on both devices? since that's going to be
                // the only way?"): install the binary, then `noo enroll`, which
                // joins the tailnet with the blob's key and runs prep itself.
                // The fetched-script paste and the SSH gate lane are retired
                if ca_hex.is_none() {
                    fail(g.json, ExitCode::Generic, "compose_failed",
                         "could not compute the cluster CA's fingerprint, so the enrollment paste \
                          would carry no pin — and a node refuses blind trust-on-first-use. \
                          Check that openssl is installed and that this controller has a cluster \
                          CA (`noo security pki status`).",
                         Some("noo security pki init"));
                }
                let encoded = {
                    let mut blob = serde_json::json!({
                        "v": 1, "url": noo_url, "token": raw, "tsk": auth_key,
                    });
                    if let Some(h) = &ca_hex {
                        blob["ca"] = serde_json::Value::String(h.clone());
                    }
                    if let Some(n) = resp["node_name"].as_str() {
                        blob["node"] = serde_json::Value::String(n.to_string());
                    }
                    use base64::Engine as _;
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob.to_string())
                };
                clear_stale_for(resp["node_name"].as_str());
                let install = format!(
                    "command -v noo >/dev/null || curl -fsSL https://raw.githubusercontent.com/{}/main/noo-cli/install.sh | sh",
                    install_repo()
                );
                print_enroll_paste(&EnrollPaste {
                    install: &install,
                    enroll: &format!("noo enroll noo1.{encoded}"),
                    noo_url: &noo_url,
                    self_node,
                    joins_tailnet: true,
                    node: resp["node_name"].as_str(),
                });
                return Ok(0);
            }
        }
    }

    let one_liner = resp["one_liner"].as_str().unwrap_or("");
    let expires = resp["expires_at"].as_str().unwrap_or("?");
    let id = resp["id"].as_str().unwrap_or("?");
    ui::done(&format!("bootstrap token minted (id {id})"));
    let mut rows: Vec<(&str, String)> = Vec::new();
    if let Some(n) = resp["node_name"].as_str() {
        rows.push(("bound to node", format!("{n}  {}", ui::muted("redemption from any other hostname is refused"))));
    }
    rows.push(("expires", format!("{expires}  {}", ui::muted("single-use; safe to send over chat"))));
    if let Some(r) = resp["role_hint"].as_str() {
        rows.push(("role hint", r.to_string()));
    }
    if let Some(c) = resp["allowed_cidr"].as_str() {
        rows.push(("redeemable from", c.to_string()));
    }
    say(ui::kv(&rows).trim_end());
    say("");
    say(&ui::emph("Run this on the new host:"));
    ui::value(one_liner);
    say("");
    say(&ui::note("the raw token is shown once; the CLI does not store it"));
    ui::guide(&[
        (&format!("noo cluster bootstrap-token revoke {id}"), "if the paste leaks or the host never enrolls"),
        ("noo cluster bootstrap-token list", "see every outstanding token and which node each is bound to"),
        (&format!("noo cluster provision {} --wait", resp["node_name"].as_str().unwrap_or("<node>")), "after the host enrolls: place backends and finish provisioning"),
    ]);
    Ok(0)
}

/// `noo cluster invite` — tailnet-native node invitation.
/// No shared secrets: mints ONE tagged tailscale auth key and
/// prints the single command for the new machine. Identity is proven by
/// the tailnet (whois tag + dialback), transport by the serve URL's real
/// WebPKI certificate — no tokens, no pins, nothing else to carry.
pub fn cluster_invite(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let ts = match post_json_try(g, "/api/cluster/mint-join-key", &json!({}), true, 30) {
        Ok(v) => v,
        Err(e) => fail(
            g.json, ExitCode::Generic, "mint_failed",
            &format!("could not mint a tailscale join key: {e} — tailnet invites need the tailscale OAuth client (noo onboard --reconfigure --only enrollment); the blob flow (`noo cluster bootstrap-token create --node <n>`) works without it"),
            None,
        ),
    };
    let auth_key = ts["auth_key"].as_str().unwrap_or("");
    if auth_key.is_empty() {
        fail(g.json, ExitCode::Generic, "mint_failed", "mint-join-key returned no auth_key", None);
    }
    let dns_name = std::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .ok()
        .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
        .and_then(|v| v["Self"]["DNSName"].as_str().map(|d| d.trim_end_matches('.').to_string()))
        .filter(|d| !d.is_empty());
    let Some(dns_name) = dns_name else {
        fail(g.json, ExitCode::Generic, "no_tailnet",
             "this controller has no tailnet DNS name — tailnet invites need tailscale up here first", None);
    };
    // The serve URL is what makes the transport VERIFIED (real ts.net LE
    // cert). Without serve the flow would silently regress to unverified
    // TLS with no pin — refuse and say how to fix instead.
    let serve_ok = std::process::Command::new("tailscale")
        .args(["serve", "status"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(":8080"))
        .unwrap_or(false);
    if !serve_ok {
        // The VERIFIED mapping onboard writes (tailnet_serve.rs): the
        // gateway's tailnet IP, which its certificate carries as a SAN. Never
        // the `https+insecure` scheme against localhost — that told tailscaled to skip
        // verifying the one hop this hint exists to make trustworthy.
        let fix = crate::tailnet_serve::tailnet_ip()
            .map(|ip| format!("tailscale serve --bg https://{ip}:8080"))
            .unwrap_or_else(|| "noo controller promote".to_string());
        fail(g.json, ExitCode::Generic, "no_serve",
             &format!("tailscale serve is not proxying the gateway — run: {fix}  (then re-run; the serve URL is what gives the invite verified TLS). Paste fallback: noo cluster bootstrap-token create --node <n>"),
             None);
    }
    if g.json {
        println!("{}", json!({"url": format!("https://{dns_name}"), "ts_authkey": auth_key}));
        return Ok(0);
    }
    say(&ui::emph("Tailnet invite — run this on the new machine after installing the noo CLI:"));
    ui::value(&format!("noo enroll --via-tailnet https://{dns_name} --ts-authkey {auth_key}"));
    say("");
    say(&ui::note("the device joins the tailnet with the fleet's worker tag; admission is whois + dialback (the tailnet proves who it is)"));
    say(&ui::note("transport is the serve URL's real certificate; the auth key is the only credential and expires on its own"));
    ui::guide(&[
        ("https://login.tailscale.com/admin/settings/keys", "revoke the auth key here if it leaks"),
        ("noo cluster status", "the new machine appears here once it enrolls"),
        ("noo cluster provision <node> --wait", "then place backends and finish provisioning"),
    ]);
    Ok(0)
}

/// `noo cluster bootstrap-token list` — issuance metadata (never hashes).
pub fn cluster_bootstrap_token_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/security/bootstrap-tokens", true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let tokens = body["tokens"].as_array().unwrap_or(&empty);
    if tokens.is_empty() {
        say(&ui::muted("no bootstrap tokens"));
        return Ok(0);
    }
    say(&ui::header("bootstrap tokens", Some(&format!("{} tokens", tokens.len()))));
    say("");
    let rows: Vec<Vec<String>> = tokens
        .iter()
        .map(|t| {
            vec![
                t["id"].as_str().unwrap_or("?").to_string(),
                ui::state(t["status"].as_str().unwrap_or("?")),
                t["created_by"].as_str().unwrap_or("?").to_string(),
                t["expires_at"].as_str().unwrap_or("?").to_string(),
                t["used_by_ip"].as_str().unwrap_or("").to_string(),
                t["role_hint"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left("id"), Col::left("status"), Col::left("created by"), Col::left("expires"), Col::left("used by"), Col::left("role")],
            &rows,
        )
    );
    Ok(0)
}

/// `noo cluster bootstrap-token revoke <id>` — flip the row.
pub fn cluster_bootstrap_token_revoke(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [id] = args else { return Err(Unhandled) };
    let resp = match post_json_try(
        g,
        &format!("/api/security/bootstrap-tokens/{id}/revoke"),
        &json!({}),
        true,
        15,
    ) {
        Ok(v) => v,
        Err(e) => fail(g.json, ExitCode::Generic, "revoke_failed", &e, None),
    };
    if g.json {
        println!("{resp}");
    } else {
        ui::done(&format!("bootstrap token {id} revoked"));
    }
    Ok(0)
}

#[cfg(test)]
mod bootstrap_token_tests {
    use super::parse_ttl_seconds;

    #[test]
    fn ttl_parses_units_and_bare_seconds() {
        assert_eq!(parse_ttl_seconds("3600"), Some(3600));
        assert_eq!(parse_ttl_seconds("90s"), Some(90));
        assert_eq!(parse_ttl_seconds("30m"), Some(1800));
        assert_eq!(parse_ttl_seconds("1h"), Some(3600));
        assert_eq!(parse_ttl_seconds("24h"), Some(86_400));
        assert_eq!(parse_ttl_seconds("1d"), Some(86_400));
        assert_eq!(parse_ttl_seconds(" 2H "), Some(7200));
    }

    /// Malformed TTLs are a usage error (Unhandled → usage text), never a
    /// silent default: the gateway enforces the <= 24h ceiling, but a value
    /// the user didn't ask for must not be sent on their behalf.
    #[test]
    fn ttl_rejects_garbage() {
        for bad in ["", "h", "1w", "one hour", "1.5h", "--", "1hh"] {
            assert_eq!(parse_ttl_seconds(bad), None, "ttl {bad:?}");
        }
    }
}

// The heavy subprocess commands (sync-images / upgrade-agents / ship-model /
// clean) live in the sibling include below to keep this file navigable.
include!("cluster_provision_subprocess.rs");

/// Read the tailnet's live policy, with its ETag.
///
/// Split out of `ensure_tag_owner` so `noo security tailnet policy` reads the
/// same way the converging writer does — one place that knows the Accept
/// header the HuJSON endpoint wants and what a non-200 means.
pub(crate) fn fetch_live_acl() -> Result<(String, Option<String>), String> {
    let token = tailscale_api_key();
    if token.is_empty() {
        return Err(TAILSCALE_KEY_HINT.to_string());
    }
    let url = format!("{}/tailnet/{}/acl", tailscale_base(), tailnet());
    let auth = format!("Basic {}", base64_std(format!("{token}:").as_bytes()));
    let mut resp = plain_agent(15)
        .get(&url)
        .header("Authorization", &auth)
        .header("Accept", "application/hujson")
        .call()
        .map_err(|e| format!("ACL read failed: {e}"))?;
    if resp.status().as_u16() != 200 {
        return Err(format!("ACL read failed: HTTP {}", resp.status().as_u16()));
    }
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("ACL read failed: {e}"))?;
    Ok((body, etag))
}

/// Replace the tailnet's policy with `policy`, wholesale. Returns the path the
/// PREVIOUS policy was written to.
///
/// Order is the same one `bootstrap-controller.sh` established and it is not
/// negotiable: **validate, then back up, then write.** Tailscale's own
/// `/acl/validate` catches a policy that would lock the operator out of their
/// own tailnet, and it has to run before anything is replaced — a backup taken
/// after a failed push is a backup of the damage. The `If-Match` preserves a
/// concurrent console edit by failing rather than overwriting it.
pub(crate) fn push_acl(policy: &str) -> Result<std::path::PathBuf, String> {
    let token = tailscale_api_key();
    if token.is_empty() {
        return Err(TAILSCALE_KEY_HINT.to_string());
    }
    let base = format!("{}/tailnet/{}", tailscale_base(), tailnet());
    let auth = format!("Basic {}", base64_std(format!("{token}:").as_bytes()));

    // 1. Validate FIRST.
    let mut v = plain_agent(20)
        .post(format!("{base}/acl/validate"))
        .header("Authorization", &auth)
        .header("Content-Type", "application/hujson")
        .send(policy)
        .map_err(|e| format!("ACL validation request failed: {e}"))?;
    let vbody = v.body_mut().read_to_string().unwrap_or_default();
    if v.status().as_u16() != 200 {
        return Err(format!("ACL validation failed (HTTP {}): {vbody}", v.status().as_u16()));
    }
    // A 200 with a `message` is still a rejection — the endpoint reports the
    // problem in the body rather than the status. Treating 200 as success
    // would push a policy Tailscale had just told us was wrong.
    if let Ok(j) = serde_json::from_str::<serde_json::Value>(&vbody) {
        if let Some(msg) = j.get("message").and_then(|m| m.as_str()) {
            if !msg.is_empty() {
                return Err(format!("ACL validation rejected the declared policy: {msg}"));
            }
        }
    }

    // 2. Back up what is live, with its ETag for the guarded write.
    let (live, etag) = fetch_live_acl()?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = std::env::temp_dir().join(format!("tailscale-acl.backup.{stamp}.hujson"));
    std::fs::write(&backup, &live)
        .map_err(|e| format!("refusing to push: could not write the backup to {}: {e}", backup.display()))?;

    // 3. Write.
    let mut req = plain_agent(20)
        .post(format!("{base}/acl"))
        .header("Authorization", &auth)
        .header("Content-Type", "application/hujson");
    if let Some(tag) = etag {
        req = req.header("If-Match", &tag);
    }
    let mut resp = req
        .send(policy)
        .map_err(|e| format!("ACL push failed: {e}"))?;
    let code = resp.status().as_u16();
    if code != 200 {
        let body = resp.body_mut().read_to_string().unwrap_or_default();
        return Err(format!(
            "ACL push failed (HTTP {code}): {body} — the live policy is unchanged, \
             and the copy taken before the attempt is at {}",
            backup.display()
        ));
    }
    Ok(backup)
}
