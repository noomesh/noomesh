// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo models …` — model management (Rust gateway routes in
//! `routes/cluster.rs`; catalog data straight from HuggingFace).
//!
//! Ported: cached, pull, list, search, info, recommended, ollama,
//! huggingface (WP-A2). The catalog commands are not gateway calls in
//! Python either — they query the HuggingFace API through the shared
//! `~/.config/mesh/model_cache.json` catalog cache (see `src/catalog.rs`);
//! `recommended` additionally makes two BEST-EFFORT gateway calls
//! (`/api/cluster/nodes` for tier auto-detect, `/api/models/cached` for
//! LAN-preseedable models), which never fail the command (Python parity:
//! try/except → default).
//!
//! Also ported: `switch` (WP-B2 — local .env/noomesh.yaml edits + docker
//! compose restarts; see `models_switch` at the end of this file) and
//! `refresh` (WP-R — force catalog rebuild from HuggingFace, bypassing the
//! 24h TTL, writing the same shared `model_cache.json` shape Python writes;
//! `--llm` POSTs the coordinator eval prompt to `/api/inference` and stores
//! the enrichment IN THE CACHE FILE, exactly like Python — nothing is stored
//! server-side). Nothing in the `models` group is left in Python.
//!
//! `pull` streaming note: the Rust gateway's /api/terminal/ollama/pull
//! relabels Ollama's raw NDJSON progress stream as text/event-stream WITHOUT
//! adding `data:` prefixes (routes/other.rs terminal_ollama_pull is a plain
//! bytes_stream proxy). The Python CLI only parses `data: ` lines — the old
//! Python-gateway SSE contract — so it silently drops every progress line
//! today. The Rust parser accepts both framings (optional `data: ` prefix)
//! and treats Ollama's terminal `{"status":"success"}` as done alongside
//! the legacy `{"done":true}`.

use crate::catalog::{self, Catalog};
use crate::http::{get_json, get_json_opt, post_json_stream};
use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui::{self, Col, Glyph};
use serde_json::{json, Value};

/// `noo models cached` — GET /api/models/cached (models currently loaded on
/// running node backends, aggregated from the mesh_nodes KV). Not in the
/// Python CLI (MCP/dashboard surface) — the Rust CLI is the terminal
/// surface for it.
pub fn models_cached(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/models/cached", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let models = body["models"].as_array().unwrap_or(&empty);
    if models.is_empty() {
        println!("{}", ui::muted("no models loaded on any running backend"));
        return Ok(0);
    }
    println!("{}", ui::header("cached models", Some(&format!("{} on running backends", models.len()))));
    println!("{}", ui::section("models"));
    let rows: Vec<Vec<String>> = models
        .iter()
        .map(|m| {
            let nodes = m["nodes"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            vec![
                super::truncate(m["name"].as_str().unwrap_or("?"), 56),
                m["backend"].as_str().unwrap_or("?").to_string(),
                m["size"].as_str().unwrap_or("?").to_string(),
                nodes,
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("model"), Col::left("backend"), Col::left("size"), Col::left("nodes")], &rows));
    Ok(0)
}

/// `noo models pull MODEL [--backend/-b ollama]` —
/// POST /api/terminal/ollama/pull {"model": M}, streamed progress (600s cap
/// on the whole download, Python parity). Progress lines go to stderr;
/// stdout gets the final line — the last stream JSON object in `--json`
/// mode, a one-line success message otherwise.
pub fn models_pull(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    use std::io::BufRead as _;

    let mut model: Option<String> = None;
    let mut backend = "ollama".to_string();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--backend" | "-b" => backend = iter.next().ok_or(Unhandled)?.clone(),
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if model.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(model) = model else { return Err(Unhandled) };
    // The voice add-on's models (i105): `whisper:<size>` / `piper:<voice>`
    // are staged into the controller's model store, never pulled by Ollama
    // and never fetched by the voice containers themselves.
    if let Some(parsed) = crate::commands::voice_models::VoiceModel::parse(&model) {
        return match parsed {
            Ok(m) => crate::commands::voice_models::pull(g, m),
            Err(e) => fail(g.json, ExitCode::Usage, "bad_args", &e, Some("noo models pull whisper:base | noo models pull piper:en_US-lessac-medium")),
        };
    }
    if backend != "ollama" {
        // Python parity: only the ollama backend supports pull; exit 1.
        fail(
            g.json,
            ExitCode::Generic,
            "unsupported_backend",
            &format!("Pull not yet supported for backend '{backend}' — only ollama"),
            None,
        );
    }

    let body = serde_json::json!({ "model": model });
    let mut resp = post_json_stream(g, "/api/terminal/ollama/pull", &body, true, 600);
    let status = resp.status().as_u16();
    if !(200..=299).contains(&status) {
        // Non-2xx is a plain JSON error ({"error": …} from the gateway:
        // bad request, Ollama unreachable, or Ollama's own error status).
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        let detail = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or_else(|| format!("HTTP {status}: {text}"));
        match status {
            401 | 403 => fail(
                g.json,
                ExitCode::AuthFailed,
                "auth_failed",
                &format!("gateway rejected credentials ({status}) for /api/terminal/ollama/pull"),
                Some("is NOO_CLUSTER_SECRET set in the repo .env?"),
            ),
            _ => fail(g.json, ExitCode::RemoteError, "pull_failed", &detail, None),
        }
    }

    if !g.json {
        println!("{}", ui::phase("Pull"));
        print!("{}", ui::kv(&[("model", model.clone()), ("backend", backend.clone())]));
    }
    let stderr_tty = ui::stderr_is_tty();
    let mut last: Option<serde_json::Value> = None;
    let mut last_status = String::new();
    let mut progressed = false; // whether a \r progress line is open on stderr
    let reader = std::io::BufReader::new(resp.body_mut().as_reader());
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                if progressed {
                    eprintln!();
                }
                fail(
                    g.json,
                    ExitCode::Generic,
                    "stream_interrupted",
                    &format!("pull stream interrupted: {e}"),
                    None,
                );
            }
        };
        // Accept both framings: `data: {json}` (legacy SSE) and bare NDJSON.
        let payload = line.strip_prefix("data: ").unwrap_or(&line).trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        if let Some(err) = v["error"].as_str() {
            if progressed {
                eprintln!();
            }
            fail(g.json, ExitCode::RemoteError, "pull_failed", err, None);
        }
        let done = v["done"].as_bool() == Some(true) || v["status"].as_str() == Some("success");
        let stat = v["status"].as_str().unwrap_or("").to_string();
        let total = v["total"].as_u64().unwrap_or(0);
        let completed = v["completed"].as_u64().unwrap_or(0);
        // Progress → stderr (stdout stays data-only in both modes).
        if !g.json {
            if stderr_tty && total > 0 && completed > 0 {
                crate::ui::rewrite_line(&format!("  {stat} — {}%", completed * 100 / total));
                progressed = true;
            } else if !stat.is_empty() && stat != last_status {
                if progressed {
                    eprintln!();
                    progressed = false;
                }
                ui::step(&stat);
            }
        } else if g.verbose {
            eprintln!("{payload}");
        }
        if !stat.is_empty() {
            last_status = stat;
        }
        last = Some(v);
        if done {
            break;
        }
    }
    if progressed {
        eprintln!();
    }

    let finished = last
        .as_ref()
        .map(|v| v["done"].as_bool() == Some(true) || v["status"].as_str() == Some("success"))
        .unwrap_or(false);
    if !finished {
        fail(
            g.json,
            ExitCode::Generic,
            "stream_incomplete",
            "pull stream ended without a completion signal",
            Some("check the ollama backend's logs; the download may still be running server-side"),
        );
    }
    if g.json {
        println!("{}", last.unwrap_or(serde_json::json!({"status": "success"})));
    } else {
        ui::close_done(&format!("{model} pulled"));
        let switch = format!("noo models switch {model} --backend ollama");
        ui::guide(&[
            (switch.as_str(), "make it the active model for the ollama backend"),
            ("noo models ollama", "lists what the ollama backend holds now"),
        ]);
    }
    Ok(0)
}

// ═══════════════════════════════════════════════════════════════════════
// WP-A2: catalog commands (list / search / info / recommended / ollama /
// huggingface) — HuggingFace-backed via src/catalog.rs, Python-parity
// flags and output. `recommended` also makes best-effort gateway calls.
// ═══════════════════════════════════════════════════════════════════════

/// Backends the `list` command iterates (Python `ALL_BACKENDS`).
const ALL_BACKENDS: &[&str] = &["vllm", "llamacpp", "ollama", "airllm"];

fn tier_desc(tier: i64) -> &'static str {
    match tier {
        1 => "High-end GPU (RTX 3080+, V100, A100) — >=10GB VRAM",
        2 => "Mid-tier GPU (RTX 2060, 1660 Ti) — 4-10GB VRAM",
        3 => "CPU only (no GPU)",
        4 => "Edge board (Jetson, RPi5, RK3588) — GGUF via llama.cpp",
        5 => "Companion device (phone, tablet) — tiny GGUF only",
        _ => "",
    }
}

/// Python `_fmt_downloads`: 0/None → "0", >=1M → "1.2M", >=1K → "3.4K".
fn fmt_downloads(n: Option<i64>) -> String {
    let n = n.unwrap_or(0);
    if n == 0 {
        return "0".to_string();
    }
    if n >= 1_000_000 {
        return format!("{:.1}M", n as f64 / 1e6);
    }
    if n >= 1_000 {
        return format!("{:.1}K", n as f64 / 1e3);
    }
    n.to_string()
}

fn backends_str(v: &Value) -> String {
    match v.as_array() {
        Some(a) if !a.is_empty() => {
            a.iter().filter_map(|b| b.as_str()).collect::<Vec<_>>().join(", ")
        }
        _ => "?".to_string(),
    }
}

/// "size_estimate"/"tier"-style display: string as-is, number rendered,
/// missing → "?".
fn field_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => "?".to_string(),
    }
}

fn commafy(n: i64) -> String {
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 {
        format!("-{out}")
    } else {
        out
    }
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// A model's gating status as the catalog reported it.
///
/// This used to be `.unwrap_or("Open")` at every call site: a model whose
/// `gated` field was missing (HF lookup failed, older cache entry) was
/// advertised as freely pullable. An access claim must not fail OPEN —
/// unreported gating renders as "?".
fn gated_str(v: &Value) -> &str {
    v["gated"].as_str().unwrap_or("?")
}

/// Publisher trust tier as a short label (`first-party`, `trusted`, `other`).
fn trust_str(v: &Value) -> &'static str {
    v["trust"]
        .as_i64()
        .map(catalog::trust_label)
        .unwrap_or("?")
}

const CATALOG_COLS: [Col; 7] = [
    Col::left("model"),
    Col::right("size"),
    Col::right("downloads"),
    Col::left("gated"),
    Col::right("tier"),
    Col::left("publisher"),
    Col::left("description"),
];

/// Actionable follow-up for gated models (Python `_show_gated_hint`).
fn show_gated_hint(model_id: &str, gated: &str) {
    match gated {
        "Login" => {
            ui::warned("this model requires a HuggingFace token (auto-approved)");
            println!("{}", ui::note(&format!("visit https://huggingface.co/{model_id} to see the model card; any HF account is approved automatically")));
            ui::guide(&[
                ("huggingface-cli login", "stores a token the backends read at pull time"),
                ("export HF_TOKEN=<token>", "alternative: set the token for this shell only"),
            ]);
        }
        "Gated" => {
            ui::warned("this model requires HuggingFace approval");
            println!("{}", ui::note(&format!("visit https://huggingface.co/{model_id} and accept the license; approval can take minutes to days")));
            ui::guide(&[
                ("huggingface-cli login", "once approved: stores a token the backends read at pull time"),
                ("export HF_TOKEN=<token>", "alternative: set the token for this shell only"),
            ]);
        }
        _ => {}
    }
}

/// `noo models list [--backend/-b B] [--tier/-t N] [--limit/-n N] [--refresh]`
/// — popular models per backend from the HuggingFace-backed catalog cache.
pub fn models_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    crate::ui::auto_page(); // long output: $PAGER on a TTY (no-op otherwise)
    let mut backend: Option<String> = None;
    let mut tier: Option<i64> = None;
    let mut limit = 15usize;
    let mut refresh = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--backend" | "-b" => backend = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--tier" | "-t" => tier = Some(iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?),
            "--limit" | "-n" => limit = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            "--refresh" => refresh = true,
            _ => return Err(Unhandled),
        }
    }

    let backends: Vec<String> = match &backend {
        Some(b) => vec![b.clone()],
        None => ALL_BACKENDS.iter().map(|s| s.to_string()).collect(),
    };

    let mut cat = Catalog::new();
    if !g.json {
        println!("{}", ui::header("model catalog", None));
        // Always show which model is ACTIVE and where that came from
        // A declared choice reads as such, an
        // unset one names the launcher default it falls to.
        crate::envfile::ensure_repo_env();
        let active = match std::env::var("OLLAMA_MODEL").ok().filter(|v| !v.is_empty()) {
            Some(m) => format!("{m}  {}", ui::muted("declared in .env")),
            None => format!("gemma4:e2b  {}", ui::muted("launcher default — nothing declared; set OLLAMA_MODEL in .env")),
        };
        print!("{}", ui::kv(&[("active ollama model", active)]));
    }

    for b in &backends {
        if !ALL_BACKENDS.contains(&b.as_str()) {
            ui::warned(&format!("unknown backend {b}"));
            continue;
        }
        let models = cat.fetch_models(b, tier, limit, refresh);
        if models.is_empty() {
            let suffix = tier.map(|t| format!(" tier {t}")).unwrap_or_default();
            ui::warned(&format!("no models found for {b}{suffix}"));
            continue;
        }
        if g.json {
            // Python parity: one JSON document per backend.
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"backend": b, "models": models}))
                    .unwrap_or_default()
            );
            continue;
        }
        println!("{}", ui::section(b));
        let rows: Vec<Vec<String>> = models
            .iter()
            .map(|m| {
                vec![
                    clip(m["id"].as_str().unwrap_or("?"), 50),
                    field_str(&m["size_estimate"]),
                    fmt_downloads(m["downloads"].as_i64()),
                    gated_str(m).to_string(),
                    field_str(&m["tier"]),
                    trust_str(m).to_string(),
                    clip(m["desc"].as_str().unwrap_or(""), 40),
                ]
            })
            .collect();
        print!("{}", ui::table(&CATALOG_COLS, &rows));
    }

    if !g.json {
        let age = cat.cache_age_text(&backends[0]);
        println!();
        println!("  {}", ui::muted(&format!("catalog updated {age} (--refresh to update); ordered by publisher trust, then downloads")));
        println!("{}", ui::hint("noo models search <keyword>"));
    }
    Ok(0)
}

/// `noo models search QUERY [--backend/-b B] [--limit/-n N]` — live
/// HuggingFace search (cached/offline fallback).
pub fn models_search(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut query: Option<String> = None;
    let mut backend: Option<String> = None;
    let mut limit = 15usize;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--backend" | "-b" => backend = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--limit" | "-n" => limit = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if query.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(query) = query else { return Err(Unhandled) };

    let mut cat = Catalog::new();
    if !g.json {
        ui::step(&format!("searching HuggingFace for {query}"));
    }
    let results = cat.search_models(&query, backend.as_deref(), limit);

    if g.json {
        println!("{}", serde_json::to_string_pretty(&results).unwrap_or_default());
        return Ok(0);
    }
    if results.is_empty() {
        println!("{}", ui::muted(&format!("no models matching '{query}'")));
        println!("  {}", ui::muted("try broader terms like: qwen instruct, llama gguf, mistral awq"));
        return Ok(0);
    }
    println!("{}", ui::header("huggingface search", Some(&format!("{query} · {} model(s)", results.len()))));
    println!("{}", ui::section("models"));
    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|m| {
            vec![
                clip(m["id"].as_str().unwrap_or("?"), 55),
                field_str(&m["size_estimate"]),
                fmt_downloads(m["downloads"].as_i64()),
                gated_str(m).to_string(),
                clip(&backends_str(&m["backends"]), 18),
                clip(m["desc"].as_str().unwrap_or(""), 35),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left("model"), Col::right("size"), Col::right("downloads"), Col::left("gated"), Col::left("backends"), Col::left("description")],
            &rows
        )
    );
    ui::guide(&[
        ("noo models info <model>", "tier, size, gating and backends for one result"),
        ("noo models recommended", "the curated picks for this host's tier"),
    ]);
    Ok(0)
}

/// `noo models info MODEL` — detailed HuggingFace model info, with the
/// gated badge + actionable access hint.
pub fn models_info(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut model: Option<String> = None;
    for tok in args {
        if tok.starts_with('-') {
            return Err(Unhandled);
        }
        if model.replace(tok.clone()).is_some() {
            return Err(Unhandled);
        }
    }
    let Some(model) = model else { return Err(Unhandled) };

    if !g.json {
        ui::step(&format!("fetching info for {model}"));
    }
    let cat = Catalog::new();
    let Some(info) = cat.model_info(&model) else {
        fail(
            g.json,
            ExitCode::Generic,
            "model_not_found",
            &format!("Could not find model '{model}' on HuggingFace"),
            Some("use the full model ID (e.g. meta-llama/Llama-3.1-8B-Instruct)"),
        );
    };

    if g.json {
        println!("{}", serde_json::to_string_pretty(&info).unwrap_or_default());
        return Ok(0);
    }

    let gated = gated_str(&info).to_string();
    let params_str = info["params_b"]
        .as_f64()
        .map(|p| {
            if p.fract() == 0.0 {
                format!("{}B", p as i64)
            } else {
                format!("{p}B")
            }
        })
        .unwrap_or_else(|| "Unknown".to_string());
    let tier = info["tier"].as_i64().unwrap_or(0);
    let formats = info["formats"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    let id = info["id"].as_str().unwrap_or(&model).to_string();

    println!("{}", ui::header(&id, None));
    print!(
        "{}",
        ui::kv(&[
            ("author", info["author"].as_str().filter(|s| !s.is_empty()).unwrap_or(ui::dash()).to_string()),
            ("parameters", params_str),
            ("size", field_str(&info["size_estimate"])),
            ("tier", format!("{tier}  {}", ui::muted(tier_desc(tier)))),
            ("gated", gated.clone()),
            ("license", info["license"].as_str().filter(|s| !s.is_empty()).unwrap_or(ui::dash()).to_string()),
            ("backends", backends_str(&info["backends"])),
            ("formats", if formats.is_empty() { ui::dash().to_string() } else { formats }),
            ("downloads", fmt_downloads(info["downloads"].as_i64())),
            ("likes", commafy(info["likes"].as_i64().unwrap_or(0))),
        ])
    );
    show_gated_hint(&id, &gated);
    let first_backend = info["backends"][0].as_str().unwrap_or("unknown");
    let backend = if first_backend != "unknown" { first_backend } else { "vllm" };
    let up = format!("noo cluster up {backend} {id}");
    let place = format!("noo cluster place-model {id} --backend {backend}");
    let mut entries = vec![
        (up.as_str(), "start it now on the scheduler's pick"),
        (place.as_str(), "or pin it as desired state so it survives restarts"),
    ];
    let pull = format!("noo models pull {id} --backend ollama");
    if backends_str(&info["backends"]).contains("ollama") {
        entries.push((pull.as_str(), "fetch it into the ollama store first"));
    }
    ui::guide(&entries);
    Ok(0)
}

/// `noo models recommended [--tier/-t N] [--arch A] [--refresh]` — curated
/// recommendations for a node's hardware tier + arch. Tier auto-detects
/// from the gateway's node list when omitted; models already cached on the
/// cluster are preferred (they preseed over the LAN).
pub fn models_recommended(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut tier: Option<i64> = None;
    let mut arch: Option<String> = None;
    let mut refresh = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--tier" | "-t" => tier = Some(iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?),
            "--arch" => arch = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--refresh" => refresh = true,
            _ => return Err(Unhandled),
        }
    }

    // Auto-detect tier from cluster node capabilities (best-effort: the
    // Python CLI swallows every error here and defaults to tier 1).
    let tier = match tier {
        Some(t) => t,
        None => {
            let detected = get_json_opt(g, "/api/cluster/nodes", true, 5).and_then(|nodes| {
                let arr = nodes.as_array()?.clone();
                // A standalone controller has NO nodes: the box itself is
                // not one. Tier 1 there recommended 35 GB vLLM models to
                // a CPU-only laptop (2026-09-28 newcomer rehearsal); tier
                // 3 (CPU) is the honest floor when nothing reports VRAM.
                let best_vram = arr
                    .iter()
                    .map(|n| n["capabilities"]["vram_gb"].as_f64().unwrap_or(0.0))
                    .fold(0.0f64, f64::max);
                Some(if best_vram >= 10.0 {
                    1
                } else if best_vram >= 4.0 {
                    2
                } else {
                    3
                })
            });
            match detected {
                Some(t) => {
                    if !g.json {
                        ui::done(&format!("auto-detected tier {t} from cluster nodes"));
                    }
                    t
                }
                None => {
                    // Unreachable or refused: say so, and default LOW, not
                    // high — a wrong "tier 1" hands a newcomer models that
                    // cannot run; a wrong "tier 3" hands them small ones
                    // that do. `--tier` overrides either way.
                    if !g.json {
                        ui::warned("could not read /api/cluster/nodes — defaulting to tier 3 (CPU); pass --tier to override");
                    }
                    3
                }
            }
        }
    };

    if !(1..=5).contains(&tier) {
        fail(
            g.json,
            ExitCode::Usage,
            "invalid_tier",
            &format!("Invalid tier: {tier}. Use 1-5"),
            None,
        );
    }

    if !g.json {
        let mut arch_note = String::new();
        if let Some(a) = &arch {
            arch_note = format!(" · {a}");
            if catalog::is_arm(Some(a)) {
                arch_note.push_str(" (arm → GGUF only)");
            }
        }
        println!("{}", ui::header(&format!("recommended models · tier {tier}{arch_note}"), Some(tier_desc(tier))));
    }

    let backends = catalog::backends_for(tier, arch.as_deref());
    let model_class = catalog::model_class_for(tier);

    // Prefer models already in the cluster cache — a cached model preseeds
    // over the LAN instead of a fresh HuggingFace pull. Best-effort.
    let cached_models: Vec<(String, String, String)> = get_json_opt(g, "/api/models/cached", true, 5)
        .and_then(|body| {
            let arr = body["models"].as_array()?.clone();
            Some(
                arr.iter()
                    .filter_map(|m| {
                        let name = m["name"].as_str().unwrap_or("").to_string();
                        let backend = m["backend"].as_str().unwrap_or("").to_string();
                        // Skip degenerate entries where the "name" is just
                        // the backend type (e.g. an idle ollama, no model).
                        if name.is_empty() || name == backend {
                            return None;
                        }
                        let size = m["size"].as_str().unwrap_or("?").to_string();
                        Some((name, backend, size))
                    })
                    .collect(),
            )
        })
        .unwrap_or_default();
    let cached_names: Vec<String> = cached_models.iter().map(|(n, _, _)| n.clone()).collect();

    let mut cat = Catalog::new();
    // Top picks for a backend: the catalog's popular models PLUS any
    // cache-resident model the catalog didn't surface, cached-first, cap 3.
    let mut candidates = |b: &str| -> Vec<Value> {
        let mut fetched = cat.fetch_models(b, model_class, 6, refresh);
        let mut present: Vec<String> = fetched
            .iter()
            .map(|m| m["id"].as_str().unwrap_or("").to_string())
            .collect();
        for (name, backend, size) in &cached_models {
            if backend != b || catalog::model_is_cached(name, &present) {
                continue;
            }
            fetched.insert(
                0,
                json!({
                    "id": name,
                    "size_estimate": size,
                    "downloads": null,
                    "desc": "already cached on the cluster",
                }),
            );
            present.insert(0, name.clone());
        }
        // Cached models first (stable), then original popularity order.
        for m in &mut fetched {
            let id = m["id"].as_str().unwrap_or("").to_string();
            m["cached"] = json!(catalog::model_is_cached(&id, &cached_names));
        }
        fetched.sort_by_key(|m| m["cached"].as_bool() != Some(true));
        fetched.truncate(3);
        fetched
    };

    if g.json {
        let mut result = json!({
            "tier": tier,
            "arch": arch,
            "cached_preferred": !cached_names.is_empty(),
            "backends": {},
        });
        for b in &backends {
            let models = candidates(b);
            if !models.is_empty() {
                result["backends"][*b] = json!(models);
            }
        }
        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        return Ok(0);
    }

    for b in &backends {
        let models = candidates(b);
        if models.is_empty() {
            continue;
        }
        println!("{}", ui::section(b));
        for m in &models {
            let gated = gated_str(m);
            let id = m["id"].as_str().unwrap_or("?");
            let mut notes: Vec<String> = Vec::new();
            match gated {
                "Login" => notes.push(ui::warn("HF login required")),
                "Gated" => notes.push(ui::warn("gated — approval required")),
                _ => {}
            }
            if m["cached"].as_bool() == Some(true) {
                notes.push(ui::ok("in cluster cache — preseeds over LAN"));
            }
            let note = if notes.is_empty() { String::new() } else { format!("  {}", notes.join(" · ")) };
            println!("{}", ui::status_line(Glyph::Bullet, &format!("{}{note}", ui::emph(id))));
            println!(
                "  {}",
                ui::muted(&format!(
                    "size {}  downloads {}",
                    field_str(&m["size_estimate"]),
                    fmt_downloads(m["downloads"].as_i64()),
                ))
            );
            println!("  {}", ui::cmd(&format!("noo cluster up {b} {id}")));
        }
    }
    let age = cat.cache_age_text("vllm");
    println!();
    println!("  {}", ui::muted(&format!("catalog updated {age} (--refresh to update)")));
    Ok(0)
}

/// `noo models ollama [--limit/-n N] [--refresh]` — popular
/// Ollama-compatible models from the catalog.
pub fn models_ollama(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut limit = 20usize;
    let mut refresh = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--limit" | "-n" => limit = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            "--refresh" => refresh = true,
            _ => return Err(Unhandled),
        }
    }

    let mut cat = Catalog::new();
    let models = cat.fetch_models("ollama", None, limit, refresh);

    if g.json {
        println!("{}", serde_json::to_string_pretty(&models).unwrap_or_default());
        return Ok(0);
    }
    if models.is_empty() {
        ui::warned("could not fetch models");
        println!("{}", ui::note("the Ollama library at https://ollama.com/library lists them; the registry may be unreachable from here"));
        ui::guide(&[("ollama pull <model-name>", "pulls directly once you know the name")]);
        return Ok(0);
    }
    println!("{}", ui::header("ollama-compatible models", Some(&format!("{} model(s)", models.len()))));
    println!("{}", ui::section("models"));
    let mut rows: Vec<Vec<String>> = Vec::new();
    for m in &models {
        let params = m["params_b"]
            .as_f64()
            .map(|p| {
                if p.fract() == 0.0 {
                    format!("{}B", p as i64)
                } else {
                    format!("{p}B")
                }
            })
            .unwrap_or_else(|| "?".to_string());
        rows.push(vec![
            clip(m["id"].as_str().unwrap_or("?"), 55),
            field_str(&m["size_estimate"]),
            fmt_downloads(m["downloads"].as_i64()),
            gated_str(m).to_string(),
            params,
        ]);
    }
    print!(
        "{}",
        ui::table(
            &[Col::left("model"), Col::right("size"), Col::right("downloads"), Col::left("gated"), Col::right("params")],
            &rows
        )
    );
    println!();
    println!(
        "  {}",
        ui::muted(&format!("catalog updated {} (--refresh to update); full catalog: https://ollama.com/library", cat.cache_age_text("ollama")))
    );
    println!("{}", ui::hint("ollama pull <model-name>"));
    Ok(0)
}

/// `noo models huggingface [QUERY] [--limit/-n N]` — HuggingFace search
/// (default query "mistral instruct awq", Python parity).
pub fn models_huggingface(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut query: Option<String> = None;
    let mut limit = 10usize;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--limit" | "-n" => limit = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if query.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let query = query.unwrap_or_else(|| "mistral instruct awq".to_string());

    let mut cat = Catalog::new();
    if !g.json {
        ui::step(&format!("searching HuggingFace for {query}"));
    }
    let results = cat.search_models(&query, None, limit);

    if g.json {
        println!("{}", serde_json::to_string_pretty(&results).unwrap_or_default());
        return Ok(0);
    }
    if results.is_empty() {
        println!("{}", ui::muted("no models"));
        return Ok(0);
    }
    println!("{}", ui::header("huggingface", Some(&format!("{query} · {} model(s)", results.len()))));
    println!("{}", ui::section("models"));
    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|m| {
            vec![
                clip(m["id"].as_str().unwrap_or("?"), 55),
                fmt_downloads(m["downloads"].as_i64()),
                m["likes"].as_i64().unwrap_or(0).to_string(),
                gated_str(m).to_string(),
                clip(&backends_str(&m["backends"]), 18),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left("model"), Col::right("downloads"), Col::right("likes"), Col::left("gated"), Col::left("backends")],
            &rows
        )
    );
    println!("{}", ui::note(&format!("view on HuggingFace: https://huggingface.co/models?search={}", query.replace(' ', "%20"))));
    ui::guide(&[
        ("noo models info <model>", "tier, size, gating and the backends that can run one of these"),
        ("noo cluster up <backend> <model>", "start it on the scheduler's pick"),
    ]);
    Ok(0)
}

// ── WP-B2: stack mgmt — `models switch` ─────────────────────────────────
//
// Faithful port of `cluster/models_cli.py::switch_model`: rewrite
// VLLM_MODEL in .env (replacing a commented `# VLLM_MODEL=` line too),
// update noomesh.yaml (backend model/enabled/quantization + terminal
// default_model, dumped with sorted keys like Python's
// `yaml.dump(sort_keys=True)`), then `docker compose up -d
// --force-recreate <backend>` and a best-effort gateway restart.
// Local file + docker surface — no gateway HTTP, works when the venv is
// broken (like the `mesh` group).

/// vLLM tool-call parser for a model (port of
/// `ModelCatalog.detect_tool_parser`).
fn detect_tool_parser(model_id: &str) -> &'static str {
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
        // Qwen, DeepSeek, and most others use Hermes format
        "hermes"
    }
}

/// vLLM reasoning parser, when the model supports thinking (port of
/// `ModelCatalog.detect_reasoning_parser`).
fn detect_reasoning_parser(model_id: &str) -> Option<&'static str> {
    let mid = model_id.to_lowercase();
    if mid.contains("gemma-4") || mid.contains("gemma4") {
        Some("gemma4")
    } else if mid.contains("deepseek-r1") || mid.contains("deepseek_r1") {
        Some("deepseek_r1")
    } else {
        None
    }
}

/// Quantization from the model id (Python: AWQ/GPTQ substring on `.upper()`).
fn detect_quant(model_id: &str) -> &'static str {
    let up = model_id.to_uppercase();
    if up.contains("AWQ") {
        "awq"
    } else if up.contains("GPTQ") {
        "gptq"
    } else {
        ""
    }
}

/// Rewrite `VLLM_MODEL` in the .env content, Python-exact: a line starting
/// with `VLLM_MODEL=` OR `# VLLM_MODEL=` (uncommenting it) is replaced;
/// appended when absent. Output joined with `\n` + trailing newline.
/// (Deliberately NOT `onboard::env::update_env_key` — that helper neither
/// uncomments `# VLLM_MODEL=` nor matches Python's exact startswith rules.)
fn rewrite_env_vllm_model(content: &str, model: &str) -> String {
    let mut new_lines: Vec<String> = Vec::new();
    let mut found = false;
    for line in content.lines() {
        if line.starts_with("VLLM_MODEL=") || line.starts_with("# VLLM_MODEL=") {
            new_lines.push(format!("VLLM_MODEL={model}"));
            found = true;
        } else {
            new_lines.push(line.to_string());
        }
    }
    if !found {
        new_lines.push(format!("VLLM_MODEL={model}"));
    }
    let mut body = new_lines.join("\n");
    body.push('\n');
    body
}

/// Recursively sort mapping keys — parity with Python's
/// `yaml.dump(..., sort_keys=True)`, which sorts at every level.
fn sort_yaml_keys(v: serde_yaml::Value) -> serde_yaml::Value {
    use serde_yaml::Value;
    match v {
        Value::Mapping(m) => {
            let mut entries: Vec<(Value, Value)> =
                m.into_iter().map(|(k, val)| (k, sort_yaml_keys(val))).collect();
            entries.sort_by_key(|(k, _)| yaml_key(k));
            Value::Mapping(entries.into_iter().collect())
        }
        Value::Sequence(s) => Value::Sequence(s.into_iter().map(sort_yaml_keys).collect()),
        other => other,
    }
}

fn yaml_key(v: &serde_yaml::Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_else(|| serde_yaml::to_string(v).unwrap_or_default())
}

/// Whether `.env` declares the standalone profile (`NOO_DEFAULT_PROFILE=standalone`).
fn is_standalone_install(root: &std::path::Path) -> bool {
    std::fs::read_to_string(root.join(".env"))
        .map(|env| env.lines().any(|l| l.trim() == "NOO_DEFAULT_PROFILE=standalone"))
        .unwrap_or(false)
}

/// Apply the switch edits to a parsed noomesh.yaml document:
/// `cluster.backends.<backend>.{model, enabled=true, quantization?}` and
/// `terminal.default_model`. Returns the sorted-keys dump.
/// The compose service that hosts a backend on THIS install. The launcher
/// reads `NOO_DEFAULT_PROFILE` from `.env`; under `standalone` the Ollama
/// backend is the `ollama-embed` service and there is no `ollama` service
/// to recreate.
fn compose_service_for_backend(root: &std::path::Path, backend: &str) -> String {
    if backend == "ollama" && is_standalone_install(root) {
        return "ollama-embed".to_string();
    }
    backend.to_string()
}

/// A stale `noo-ollama` container — left behind by an OLD `switch` that
/// recreated the GPU `ollama` service on a standalone (Ollama-only, no
/// nvidia runtime) install, so it never came up (state `Created`) — makes
/// `noo stack status` red forever and is never the intended backend on
/// this install (2026-09-28 rehearsal). Remove it only on a standalone
/// install switching TO ollama; never when `ollama` (the GPU service) is
/// itself the intended backend, and never for a container that is
/// actually running (someone may be using it deliberately).
fn should_remove_stale_noo_ollama(standalone: bool, backend: &str, container_state: &str) -> bool {
    standalone && backend == "ollama" && matches!(container_state, "created" | "exited" | "dead")
}

fn rewrite_yaml_for_switch(
    text: &str,
    backend: &str,
    model: &str,
    quant: &str,
) -> Result<String, String> {
    use serde_yaml::{Mapping, Value};
    let key = |s: &str| Value::String(s.to_string());
    // yaml.safe_load(f) or {} — an empty/None file becomes an empty mapping.
    let mut config: Value = serde_yaml::from_str(text)
        .map_err(|e| e.to_string())
        .map(|v: Value| if v.is_mapping() { v } else { Value::Mapping(Mapping::new()) })?;
    {
        let root = config.as_mapping_mut().ok_or("not a mapping")?;
        let ensure = |m: &mut Mapping, k: &str| {
            if !m.get(key(k)).map(Value::is_mapping).unwrap_or(false) {
                m.insert(key(k), Value::Mapping(Mapping::new()));
            }
        };
        ensure(root, "cluster");
        let cluster = root.get_mut(key("cluster")).unwrap().as_mapping_mut().unwrap();
        // "Switch the active model" means the gateway should USE it: the
        // resolver reads `cluster.default_backend` first, and a switch that
        // left it on vLLM sent every `noo chat` on a standalone CPU install
        // to a vLLM model that was never there (2026-09-28 rehearsal).
        cluster.insert(key("default_backend"), key(backend));
        ensure(cluster, "backends");
        let backends = cluster.get_mut(key("backends")).unwrap().as_mapping_mut().unwrap();
        ensure(backends, backend);
        let be = backends.get_mut(key(backend)).unwrap().as_mapping_mut().unwrap();
        be.insert(key("model"), key(model));
        be.insert(key("enabled"), Value::Bool(true));
        if !quant.is_empty() {
            be.insert(key("quantization"), key(quant));
        } else {
            be.remove(key("quantization"));
        }
        ensure(root, "terminal");
        let terminal = root.get_mut(key("terminal")).unwrap().as_mapping_mut().unwrap();
        terminal.insert(key("default_model"), key(model));
        // The terminal section carries its own default_backend; leaving it
        // on vLLM while default_model names an Ollama tag is the same
        // contradiction one section up.
        terminal.insert(key("default_backend"), key(backend));
    }
    serde_yaml::to_string(&sort_yaml_keys(config)).map_err(|e| e.to_string())
}

/// `noo models switch MODEL [--backend/-b vllm]` — switch the active model
/// without rebuilding: noomesh.yaml + .env rewrite, then restart only the
/// backend container (plus a best-effort gateway restart for the new YAML).
pub fn models_switch(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    use std::process::Command;

    let mut model: Option<String> = None;
    let mut backend = "vllm".to_string();
    let mut yes = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--backend" | "-b" => backend = iter.next().ok_or(Unhandled)?.clone(),
            "-y" | "--yes" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if model.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(model) = model else { return Err(Unhandled) };
    // Rewrites .env + noomesh.yaml and restarts the backend and gateway.
    super::confirm_destructive(g, yes, "Switch the active model, rewrite .env/noomesh.yaml and restart the backend and gateway, to", &model);

    let root = crate::envfile::repo_root();
    let yaml_path = root.join("noomesh.yaml");
    let env_path = root.join(".env");

    let tool_parser = detect_tool_parser(&model);
    let reasoning_parser = detect_reasoning_parser(&model);
    let quant = detect_quant(&model);

    // Three phases (guide §5 Rhythm): Plan → Apply → Health. Narration is
    // stdout for humans (rev 2); in --json mode it must not pollute the
    // envelope, so the plan goes to stderr there and the ui printers are
    // silent.
    let emit = |msg: &str| {
        if g.json { eprintln!("{}", ui::note(msg)) } else { println!("{}", ui::note(msg)) }
    };
    if !g.json { println!("{}", ui::phase("Plan")); }
    let plan = ui::kv(&[
            ("model", model.to_string()),
            ("backend", backend.to_string()),
            ("tool parser", tool_parser.to_string()),
            ("reasoning parser", reasoning_parser.unwrap_or("none").to_string()),
            ("quantization", if quant.is_empty() { "none (native)".to_string() } else { quant.to_string() }),
        ]);
    if g.json { eprint!("{plan}") } else { print!("{plan}") }

    if !g.json { println!("{}", ui::phase("Apply")); }
    // Update .env
    if env_path.exists() {
        ui::step("rewriting .env");
        match std::fs::read_to_string(&env_path)
            .and_then(|c| std::fs::write(&env_path, rewrite_env_vllm_model(&c, &model)))
        {
            Ok(()) => ui::done("updated .env"),
            Err(e) => ui::warned(&format!("could not update .env: {e}")),
        }
        // Python edits .env silently even under the sops secrets backend,
        // where the launchers inject secrets/env.sops OVER .env (see
        // CLAUDE.md "Configuration"). Python prints no warning; surface the
        // trap in one line rather than replicating the silence.
        crate::envfile::warn_sops_env_edit();
    }

    // Update noomesh.yaml
    if yaml_path.exists() {
        ui::step("rewriting noomesh.yaml");
        let res = std::fs::read_to_string(&yaml_path)
            .map_err(|e| e.to_string())
            .and_then(|t| rewrite_yaml_for_switch(&t, &backend, &model, quant))
            .and_then(|out| std::fs::write(&yaml_path, out).map_err(|e| e.to_string()));
        match res {
            Ok(()) => ui::done("updated noomesh.yaml"),
            Err(e) => ui::warned(&format!("could not update noomesh.yaml: {e}")),
        }
    }

    // Restart the backend container (recreate, not rebuild) THROUGH the
    // dist-aware restart script, not raw compose (#43b): a bare single-file
    // `up` on a dist install renders `pull_policy: build` services
    // (llamacpp, airllm) without the dist overlay and dies building
    // Dockerfiles the install does not ship — the #43 failure. restart.sh
    // owns the overlay/tag/profile logic; --force is its recreate path
    // (--no-deps --no-build).
    let compose_file = root.join("docker-compose.cluster.yml");
    if compose_file.exists() {
        // On a standalone install the only Ollama is the `ollama-embed`
        // service (the `standalone` profile); `ollama` is the GPU-tier
        // service and recreating it here brought up a container that
        // wanted the nvidia runtime and stayed in Created — a red
        // `noo stack status` and no chat, from the command the pull
        // itself suggested (2026-09-28 rehearsal).
        let service = compose_service_for_backend(&root, &backend);

        // Clean up a stale `noo-ollama` left by an OLD switch (before this
        // fix): it wanted the nvidia runtime on a standalone box and has
        // sat in `Created` ever since, turning `noo stack status` red with
        // nothing to fix it (2026-09-28 rehearsal).
        if is_standalone_install(&root) {
            let stale_name = crate::envfile::container("ollama");
            let state_out = Command::new("docker")
                .args(["inspect", "-f", "{{.State.Status}}", &stale_name])
                .output();
            if let Ok(o) = state_out {
                if o.status.success() {
                    let state = String::from_utf8_lossy(&o.stdout).trim().to_ascii_lowercase();
                    if should_remove_stale_noo_ollama(true, &backend, &state) {
                        let removed = Command::new("docker")
                            .args(["rm", "-f", &stale_name])
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false);
                        if removed {
                            emit(&format!(
                                "removed the stale {stale_name} container left by an earlier switch"
                            ));
                        }
                    }
                }
            }
        }

        ui::step(&format!("recreating the {service} container (restart.sh --force)"));
        // Same binary as this process, not whatever else is on PATH — see
        // mesh.rs::run_script for why (NOO_CLI_BIN).
        let cli_bin = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
        let out = Command::new("bash")
            .arg(root.join("scripts").join("noomesh-restart.sh"))
            .args(["--force", &service])
            .current_dir(&root)
            .env("NOO_CLI_BIN", &cli_bin)
            .output();
        let ok = match &out {
            Ok(o) => o.status.success(),
            Err(_) => false,
        };
        if !ok {
            let stderr = out
                .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
                .unwrap_or_else(|e| e.to_string());
            // The launcher's tail is framed, not interleaved (guide §5).
            if !g.json {
                let tail: Vec<&str> = stderr.lines().rev().take(12).collect::<Vec<_>>().into_iter().rev().collect();
                ui::capture("restart.sh stderr (tail)", &tail.join("\n"));
                println!();
            }
            let snippet: String = stderr.lines().last().unwrap_or("").chars().take(200).collect();
            // Python prints the error and returns (exit 0); exit 1 here — a
            // failed restart must not read as success to agents.
            fail(
                g.json,
                ExitCode::Generic,
                "subprocess_failed",
                &format!("Failed to restart: {snippet}"),
                Some("noo stack logs"),
            );
        }
        if g.verbose {
            if let Ok(o) = &out {
                ui::capture("restart.sh output", &String::from_utf8_lossy(&o.stdout));
            }
        }
        ui::done(&format!("{backend} container recreated"));

        // Also restart the gateway to pick up the new YAML (best-effort).
        if !g.json { println!("{}", ui::phase("Health")); }
        ui::step("restarting the gateway so it re-reads the placement");
        let gw_ok = Command::new("docker")
            .args(["compose", "-f"])
            .arg(&compose_file)
            .args(["restart", "gateway"])
            .current_dir(&root)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if gw_ok {
            ui::done("gateway restarted");
        } else {
            ui::warned("could not restart the gateway — restart it manually");
            ui::guide(&[("docker restart noo-gateway", "the gateway re-reads the backend placement on start")]);
        }
        // The backend's own load is minutes long and out of process; say
        // so rather than pretend to wait for it.
        println!("{}", ui::note(&format!("{backend} loads the model in the background (2–5 min for vLLM); the gateway routes to it once it reports healthy")));
    }

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "action": "switch",
                "model": model,
                "backend": backend,
                "tool_parser": tool_parser,
                "reasoning_parser": reasoning_parser,
                "quantization": if quant.is_empty() { serde_json::Value::Null } else { quant.into() },
            })
        );
    } else {
        ui::close_done(&format!("switched to {model}"));
        let _ = &emit;
        let logs = format!("docker logs -f {}", crate::envfile::instanced(&format!("noo-{backend}")));
        ui::guide(&[
            (logs.as_str(), "watch the load; 'Application startup complete' means it is serving"),
            ("noo models list", "confirms the active model once the backend reports healthy"),
            ("noo health", "the gateway's dependency table shows the backend once it is up"),
        ]);
    }
    Ok(0)
}

#[cfg(test)]
mod switch_tests {
    use super::*;

    #[test]
    fn tool_parser_detection_matches_python() {
        assert_eq!(detect_tool_parser("google/gemma-4-E4B-it"), "gemma4");
        assert_eq!(detect_tool_parser("google/Gemma3-9b"), "pythonic");
        assert_eq!(detect_tool_parser("meta-llama/Llama-3.1-8B"), "llama3_json");
        assert_eq!(detect_tool_parser("mistralai/Mixtral-8x7B"), "mistral");
        assert_eq!(detect_tool_parser("ai21labs/Jamba-v0.1"), "jamba");
        assert_eq!(detect_tool_parser("Qwen/Qwen3-8B"), "hermes");
    }

    #[test]
    fn reasoning_parser_detection_matches_python() {
        assert_eq!(detect_reasoning_parser("google/gemma-4-E4B-it"), Some("gemma4"));
        assert_eq!(detect_reasoning_parser("deepseek-ai/DeepSeek-R1"), Some("deepseek_r1"));
        assert_eq!(detect_reasoning_parser("Qwen/Qwen3-8B"), None);
    }

    #[test]
    fn quant_detection_is_case_insensitive() {
        assert_eq!(detect_quant("QuantTrio/Qwen3.5-9B-AWQ"), "awq");
        assert_eq!(detect_quant("x/y-gptq-int4"), "gptq");
        assert_eq!(detect_quant("meta-llama/Llama-3.1-8B"), "");
    }

    #[test]
    fn env_rewrite_replaces_active_and_commented_lines() {
        // Active line replaced in place.
        assert_eq!(rewrite_env_vllm_model("A=1\nVLLM_MODEL=old\nB=2\n", "new/M"),
                   "A=1\nVLLM_MODEL=new/M\nB=2\n");
        // Commented line is UNCOMMENTED (Python parity — `# VLLM_MODEL=`).
        assert_eq!(rewrite_env_vllm_model("# VLLM_MODEL=old\n", "new/M"), "VLLM_MODEL=new/M\n");
        // Absent → appended.
        assert_eq!(rewrite_env_vllm_model("A=1\n", "new/M"), "A=1\nVLLM_MODEL=new/M\n");
        // `#VLLM_MODEL=` (no space) is NOT matched — Python checks `# VLLM_MODEL=`.
        assert_eq!(rewrite_env_vllm_model("#VLLM_MODEL=old\n", "new/M"),
                   "#VLLM_MODEL=old\nVLLM_MODEL=new/M\n");
    }

    #[test]
    fn yaml_rewrite_sets_backend_terminal_and_sorts_keys() {
        let input = "zeta: 1\ncluster:\n  backends:\n    vllm:\n      quantization: gptq\n      model: old\n";
        let out = rewrite_yaml_for_switch(input, "vllm", "org/M-AWQ", "awq").unwrap();
        assert!(out.contains("default_backend: vllm"), "{out}");
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["cluster"]["backends"]["vllm"]["model"].as_str(), Some("org/M-AWQ"));
        assert_eq!(v["cluster"]["backends"]["vllm"]["enabled"].as_bool(), Some(true));
        assert_eq!(v["cluster"]["backends"]["vllm"]["quantization"].as_str(), Some("awq"));
        assert_eq!(v["terminal"]["default_model"].as_str(), Some("org/M-AWQ"));
        // sort_keys=True parity: top-level keys alphabetical (cluster < terminal < zeta).
        let cluster_pos = out.find("cluster:").unwrap();
        let terminal_pos = out.find("terminal:").unwrap();
        let zeta_pos = out.find("zeta:").unwrap();
        assert!(cluster_pos < terminal_pos && terminal_pos < zeta_pos, "keys not sorted: {out}");
    }

    #[test]
    fn yaml_rewrite_drops_quantization_for_native_models() {
        let input = "cluster:\n  backends:\n    vllm:\n      quantization: awq\n";
        let out = rewrite_yaml_for_switch(input, "vllm", "org/M", "").unwrap();
        assert!(!out.contains("quantization"), "quantization should be removed: {out}");
    }

    #[test]
    fn yaml_rewrite_builds_structure_from_empty_file() {
        let out = rewrite_yaml_for_switch("", "vllm", "org/M", "").unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["cluster"]["backends"]["vllm"]["model"].as_str(), Some("org/M"));
        assert_eq!(v["terminal"]["default_model"].as_str(), Some("org/M"));
    }
}

// ── WP-R: models refresh ────────────────────────────────────────────────
//
// Faithful port of `cluster/models_cli.py::refresh` +
// `ModelCatalog.refresh_catalog`/`_llm_enrich_batch`:
//   - per backend (all five search backends, or `--backend`): fetch from
//     HuggingFace UNCONDITIONALLY (limit 40 per search query — the 24h TTL
//     is bypassed; that's the point of refresh) and overwrite that backend's
//     entry in the shared ~/.config/mesh/model_cache.json (same
//     {"catalogs","fetched_at","ttl_hours"} shape Python writes — the two
//     CLIs read each other's cache files).
//   - `--llm`: before writing, POST the coordinator eval prompt (top 10 by
//     downloads) to `POST /api/inference` {"prompt", "max_iterations": 1}
//     and fold the returned JSON array (tool_parser / tool_calling /
//     reasoning / agentic_quality) into the models. Best-effort exactly
//     like Python (`except: pass`) — the enriched result lives in the
//     cache file, never server-side.
// Deviation (documented in NOO_CLI.md): Python always exits 0; here, when
// EVERY backend fails to refresh, the summary is still printed and the
// exit code is 1 so agents don't read total failure as success.

/// Python `m.get('params_b','?')` rendering for the LLM prompt line.
fn prompt_field(v: &Value, missing: &str) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        _ => missing.to_string(),
    }
}

/// Build the coordinator eval prompt — same text as
/// `ModelCatalog._llm_enrich_batch` (top 10 models by downloads).
fn build_llm_prompt(models: &[Value]) -> String {
    let mut top: Vec<&Value> = models.iter().collect();
    top.sort_by(|a, b| {
        b["downloads"].as_i64().unwrap_or(0).cmp(&a["downloads"].as_i64().unwrap_or(0))
    });
    top.truncate(10);
    let model_summaries = top
        .iter()
        .map(|m| {
            format!(
                "- {} ({}B, {}, downloads={}, parser={})",
                m["id"].as_str().unwrap_or(""),
                if m.get("params_b").is_some() { prompt_field(&m["params_b"], "?") } else { "?".into() },
                if m.get("quant").is_some() { prompt_field(&m["quant"], "none") } else { "none".into() },
                m["downloads"].as_i64().unwrap_or(0),
                if m.get("tool_parser").is_some() { prompt_field(&m["tool_parser"], "?") } else { "?".into() },
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "Analyze these AI models for our local inference cluster. For each model, confirm or correct:\n\
         1. tool_parser (hermes/gemma4/pythonic/llama3_json/mistral/jamba)\n\
         2. Does it support tool/function calling? (yes/no)\n\
         3. Does it support reasoning/thinking mode? (yes/no)\n\
         4. Quality assessment for agentic use (good/fair/poor)\n\
         \n\
         Models:\n\
         {model_summaries}\n\
         \n\
         Respond as JSON array: [{{\"id\": \"...\", \"tool_parser\": \"...\", \"tool_calling\": true/false, \"reasoning\": true/false, \"agentic_quality\": \"good/fair/poor\"}}]\n\
         Only return the JSON array, no other text."
    )
}

/// Coordinator LLM enrichment of one backend's models — port of
/// `_llm_enrich_batch`. Best-effort: any transport/status/parse failure
/// leaves the models untouched (Python wraps the whole thing in
/// try/except-pass). Long timeout: the coordinator may need to start a
/// backend first (`--timeout` overrides).
fn llm_enrich_batch(g: &Globals, models: &mut [Value]) {
    let body = json!({ "prompt": build_llm_prompt(models), "max_iterations": 1 });
    let resp = match crate::http::post_json_try(g, "/api/inference", &body, true, 120) {
        Ok(r) => r,
        Err(e) => {
            if g.verbose {
                ui::warned(&format!("LLM enrichment skipped (best-effort): {e}"));
            }
            return;
        }
    };
    // Python reads data["response"]; tolerate the Rust gateway's
    // {"success": true, "data": {…}} wrap like `inference run` does.
    let text = resp["response"]
        .as_str()
        .or_else(|| resp["data"]["response"].as_str())
        .unwrap_or("");
    // Python: re.search(r'\[.*\]', text, DOTALL) — greedy, so first '[' to
    // LAST ']'.
    let (Some(start), Some(end)) = (text.find('['), text.rfind(']')) else { return };
    if end < start {
        return;
    }
    let Ok(enrichments) = serde_json::from_str::<Vec<Value>>(&text[start..=end]) else {
        return;
    };
    for m in models.iter_mut() {
        let mid = m["id"].as_str().unwrap_or("").to_string();
        let Some(e) = enrichments
            .iter()
            .find(|e| e["id"].as_str() == Some(mid.as_str()))
        else {
            continue;
        };
        if e.get("tool_parser").is_some() {
            m["tool_parser"] = e["tool_parser"].clone();
        }
        // These are capability claims users pick models on. The defaults used
        // to be tool_calling=true / reasoning=false / agentic_quality="fair"
        // — invented verdicts for models the enrichment pass did not
        // classify. Carry over only what the classifier actually returned;
        // an unclassified field stays null and renders as "unknown"/"?".
        for key in ["tool_calling", "reasoning", "agentic_quality"] {
            m[key] = e.get(key).cloned().unwrap_or(Value::Null);
        }
    }
}

/// `noo models refresh [--backend/-b B] [--llm]` — rebuild the model catalog
/// from HuggingFace (TTL bypassed), overwriting the shared cache file;
/// `--llm` additionally runs the coordinator eval and stores the result in
/// the cache. Exit 0 when at least one backend refreshed; 1 when all failed.
pub fn models_refresh(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut backend: Option<String> = None;
    let mut use_llm = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--backend" | "-b" => backend = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--llm" => use_llm = true,
            _ => return Err(Unhandled),
        }
    }
    let backends: Vec<String> = match &backend {
        Some(b) => vec![b.clone()],
        None => catalog::ALL_SEARCH_BACKENDS.iter().map(|s| s.to_string()).collect(),
    };

    let mut cat = Catalog::new();
    // Per-backend items with an outcome sub-line each (guide §5 Rhythm);
    // the spinner sits on the phase, not on every backend.
    if !g.json {
        println!("{}", ui::phase("Refresh"));
        print!("{}", ui::kv(&[
            ("source", "HuggingFace (TTL bypassed)".to_string()),
            ("backends", backends.join(", ")),
            ("llm enrichment", if use_llm { "on".to_string() } else { "off".to_string() }),
        ]));
    }
    // (backend, approved count, fetched count, status) in refresh order.
    let mut summary: Vec<(String, usize, usize, String)> = Vec::new();
    for b in &backends {
        if !g.json { println!("{}", ui::item(b)); }
        let step = super::Spinner::start(g, &format!("fetching {b} models"));
        // Python: _fetch_from_hf(backend, limit=40); enrich_model is already
        // applied inside normalize(); the cache is written UNFILTERED
        // (governance filtering happens on read, like Python).
        match cat.fetch_from_hf(b, 40) {
            Ok(mut models) => {
                drop(step);
                if use_llm && !models.is_empty() {
                    let enrich = super::Spinner::start(g, &format!("asking the coordinator to classify {b} models"));
                    llm_enrich_batch(g, &mut models);
                    drop(enrich);
                }
                cat.write_cache(b, &models);
                // Report what an operator will SEE: the cache holds the raw
                // fetch, but list/recommended apply the vendor allow-list on
                // read, so the raw count overstates the catalog.
                let approved = catalog::filter_approved(models.clone(), Some(b)).len();
                if !g.json {
                    println!("{}", ui::sub(&ui::status_line(Glyph::Ok, &format!("{approved} approved of {} fetched", models.len()))));
                }
                summary.push((b.clone(), approved, models.len(), "refreshed".to_string()));
            }
            Err(e) => {
                // The step resolves to its own warning line (Step::warned).
                step.warned(&format!("{b}: fetch failed: {e}"));
                summary.push((b.clone(), 0, 0, format!("error: {e}")));
            }
        }
    }

    let total: usize = summary.iter().map(|(_, c, _, _)| c).sum();
    let fetched: usize = summary.iter().map(|(_, _, f, _)| f).sum();
    let any_refreshed = summary.iter().any(|(_, _, _, s)| s == "refreshed");
    let cache_path = cat.cache_file_path().display().to_string();

    if g.json {
        let mut sm = json!({});
        for (b, c, f, s) in &summary {
            sm[b] = json!({"count": c, "fetched": f, "status": s});
        }
        println!(
            "{}",
            json!({
                "status": if any_refreshed { "ok" } else { "error" },
                "action": "refresh",
                "llm": use_llm,
                "summary": sm,
                "total": total,
                "fetched": fetched,
                "cache": cache_path,
            })
        );
        return Ok(if any_refreshed { 0 } else { 1 });
    }

    let refreshed = summary.iter().filter(|(_, _, _, s)| s == "refreshed").count();
    if any_refreshed {
        ui::close_done(&format!("catalog refreshed: {total} approved across {refreshed} of {} backend(s), {fetched} fetched", summary.len()));
    } else {
        ui::close_warned("catalog refresh fetched nothing — every backend failed");
    }
    print!("{}", ui::kv(&[("cache", cache_path.clone())]));
    println!("{}", ui::note("the vendor allow-list applies on read, so list/recommended show the approved counts"));
    let mut guide: Vec<(&str, &str)> = vec![
        ("noo models list", "the refreshed catalog, per backend"),
        ("noo models recommended", "what fits this box's tier"),
    ];
    if !use_llm {
        guide.push(("noo models refresh --llm", "also asks the coordinator to classify tool-calling and reasoning support"));
    }
    ui::guide(&guide);

    // Show a sample of enriched models (first backend's cache, up to 8).
    if total > 0 {
        println!("{}", ui::section("sample enriched models"));
        let first = &backends[0];
        let cached = catalog::filter_approved(cat.read_cache(first, true).unwrap_or_default(), Some(first));
        let mut rows: Vec<Vec<String>> = Vec::new();
        for m in cached.iter().take(8) {
            let params = m["params_b"]
                .as_f64()
                .map(|p| if p.fract() == 0.0 { format!("{}B", p as i64) } else { format!("{p}B") })
                .unwrap_or_else(|| "?B".to_string());
            let vram = m["vram_gb"]
                .as_f64()
                .map(|v| format!("{v} GB"))
                .unwrap_or_else(|| "?".to_string());
            rows.push(vec![
                clip(m["id"].as_str().unwrap_or("?"), 45),
                params,
                m["quant"].as_str().unwrap_or("none").to_string(),
                m["tool_parser"].as_str().unwrap_or("?").to_string(),
                m["reasoning_parser"].as_str().unwrap_or("").to_string(),
                trust_str(m).to_string(),
                vram,
            ]);
        }
        print!(
            "{}",
            ui::table(
                &[
                    Col::left("model"),
                    Col::right("params"),
                    Col::left("quant"),
                    Col::left("tool parser"),
                    Col::left("reasoning"),
                    Col::left("publisher"),
                    Col::right("vram"),
                ],
                &rows
            )
        );
    }
    Ok(if any_refreshed { 0 } else { 1 })
}

#[cfg(test)]
mod refresh_tests {
    use super::*;

    #[test]
    fn llm_prompt_matches_python_template() {
        let models = vec![
            json!({"id": "meta-llama/Llama-3.1-8B-Instruct", "params_b": 8.0, "quant": null,
                   "downloads": 3000000, "tool_parser": "llama3_json"}),
            json!({"id": "microsoft/Phi-4", "params_b": 14, "quant": "AWQ",
                   "downloads": 500000, "tool_parser": "hermes"}),
        ];
        let p = build_llm_prompt(&models);
        // Python template markers, byte-for-byte.
        assert!(p.starts_with("Analyze these AI models for our local inference cluster."), "{p}");
        assert!(p.contains("1. tool_parser (hermes/gemma4/pythonic/llama3_json/mistral/jamba)"));
        assert!(p.contains("4. Quality assessment for agentic use (good/fair/poor)"));
        assert!(p.ends_with("Only return the JSON array, no other text."), "{p}");
        // Sorted by downloads desc; Python renders float 8.0 as "8.0" and a
        // present-but-null quant as "None" (m.get('quant','none') → None).
        let llama_pos = p.find("- meta-llama/Llama-3.1-8B-Instruct (8.0B, None, downloads=3000000, parser=llama3_json)")
            .expect("llama summary line");
        let phi_pos = p.find("- microsoft/Phi-4 (14B, AWQ, downloads=500000, parser=hermes)")
            .expect("phi summary line");
        assert!(llama_pos < phi_pos, "top-downloads model must come first");
    }

    #[test]
    fn llm_prompt_missing_fields_render_like_python_defaults() {
        let models = vec![json!({"id": "x/y", "downloads": 1})];
        let p = build_llm_prompt(&models);
        assert!(p.contains("- x/y (?B, none, downloads=1, parser=?)"), "{p}");
    }
}

#[cfg(test)]
mod switch_targets_the_installs_backend {
    use super::*;

    #[test]
    fn a_switch_moves_the_default_backend_and_enables_it() {
        let input = "cluster:\n  default_backend: vllm\n  backends:\n    vllm:\n      enabled: true\n      model: Qwen/Qwen3-8B-AWQ\nterminal:\n  default_backend: vllm\n  default_model: Qwen/Qwen3-8B-AWQ\n";
        let out = rewrite_yaml_for_switch(input, "ollama", "qwen2.5:0.5b", "").unwrap();
        assert_eq!(out.matches("default_backend: ollama").count(), 2, "cluster and terminal: {out}");
        assert!(!out.contains("default_backend: vllm"), "{out}");
        assert!(out.contains("model: qwen2.5:0.5b"), "{out}");
    }

    #[test]
    fn standalone_recreates_ollama_embed_not_the_gpu_ollama() {
        let dir = std::env::temp_dir().join(format!("noo-switch-svc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), "NOO_INSTALL_MODE=dist\nNOO_DEFAULT_PROFILE=standalone\n").unwrap();
        assert_eq!(compose_service_for_backend(&dir, "ollama"), "ollama-embed");
        assert_eq!(compose_service_for_backend(&dir, "vllm"), "vllm");
        std::fs::write(dir.join(".env"), "NOO_INSTALL_MODE=dist\n").unwrap();
        assert_eq!(compose_service_for_backend(&dir, "ollama"), "ollama");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removes_stale_noo_ollama_only_on_standalone_switch_to_ollama_when_not_running() {
        // The actual bug: standalone, switching to ollama, the old
        // GPU-runtime container never came up.
        assert!(should_remove_stale_noo_ollama(true, "ollama", "created"));
        assert!(should_remove_stale_noo_ollama(true, "ollama", "exited"));
        assert!(should_remove_stale_noo_ollama(true, "ollama", "dead"));
        // Not standalone: `ollama` IS the intended GPU backend — never touch it.
        assert!(!should_remove_stale_noo_ollama(false, "ollama", "created"));
        // Standalone but switching to a different backend — nothing to clean up here.
        assert!(!should_remove_stale_noo_ollama(true, "vllm", "created"));
        // Running — someone may be using it deliberately; never remove it.
        assert!(!should_remove_stale_noo_ollama(true, "ollama", "running"));
    }
}
