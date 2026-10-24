// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo recall …` — recall memory / System 1 compressed recall (Rust gateway
//! routes in `routes/video.rs`; most are worker-delegated).
//!
//! Ported: status, videos, search, prominent, stats (alias lifecycle-stats),
//! archive, lifecycle (incl. `--dry-run` preview), refresh, and the local
//! `test` stub (no gateway call — reports the v2 architecture, like Python).
//!
//! Note: the Python `recall *` commands send no auth headers (missing
//! cli_auth_headers) and 401 against the auth-enforcing gateway — the Rust
//! versions are the working surface.

use super::truncate;
use crate::http::{get_json, post_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// Worker-delegated routes wrap their payload as {"success": true, "data": …};
/// peel that for the human renderers (`--json` prints the raw wrapper).
fn unwrap_data(body: serde_json::Value) -> serde_json::Value {
    if body.get("data").is_some() && body.get("success").is_some() {
        body["data"].clone()
    } else {
        body
    }
}

/// `noo recall status` — GET /api/v1/recall/status.
pub fn recall_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/v1/recall/status", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    println!("{}", ui::header("recall", None));
    print_flat(&unwrap_data(body));
    Ok(0)
}

/// Compact key/value rendering for status-shaped payloads whose field set
/// varies (legacy MP4 status vs v2 Postgres+FAISS): scalars as `key: value`,
/// nested objects flattened one level, arrays skipped.
fn print_flat(body: &serde_json::Value) {
    let Some(obj) = body.as_object() else { return };
    let mut rows: Vec<(String, String)> = Vec::new();
    for (key, val) in obj {
        let label = key.replace('_', " ");
        match val {
            serde_json::Value::Object(inner) => {
                let parts: Vec<String> = inner.iter().map(|(k, v)| format!("{k}={v}")).collect();
                rows.push((label, ui::muted(&parts.join(" "))));
            }
            serde_json::Value::Array(_) => {}
            serde_json::Value::String(s) => rows.push((label, ui::state(s))),
            serde_json::Value::Null => rows.push((label, ui::state("not reported"))),
            v => rows.push((label, v.to_string())),
        }
    }
    let refs: Vec<(&str, String)> = rows.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    print!("{}", ui::kv(&refs));
}

/// The `archived` row of `recall refresh`: "N conversations", or "not
/// reported" when the gateway sent no count (i191 D5).
fn archived_cell(archive: &serde_json::Value) -> String {
    match &archive["archived"] {
        serde_json::Value::Number(n) => format!("{n} conversations"),
        _ => ui::count(archive, "archived"),
    }
}

/// `noo recall videos` — GET /api/v1/recall/videos.
pub fn recall_videos(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/v1/recall/videos", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let body = unwrap_data(body);
    let empty = Vec::new();
    let vids = body["videos"].as_array().or_else(|| body.as_array()).unwrap_or(&empty);
    if vids.is_empty() {
        println!("{}", ui::muted("no video files"));
        return Ok(0);
    }
    println!("{}", ui::header("recall videos", Some(&format!("{} files", vids.len()))));
    println!();
    let rows: Vec<Vec<String>> = vids
        .iter()
        .map(|v| {
            let size_mb = v["size_bytes"].as_f64().unwrap_or(0.0) / (1024.0 * 1024.0);
            vec![
                truncate(v["path"].as_str().unwrap_or("?"), 60),
                ui::count(v, "records"),
                format!("{size_mb:.1} MB"),
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("file"), Col::right("records"), Col::right("size")], &rows));
    Ok(0)
}

/// `noo recall search QUERY [--top-k K]` — POST /api/v1/recall/search
/// (worker-delegated; Python parity: 30s timeout).
pub fn recall_search(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut query: Option<String> = None;
    let mut top_k = 5u64;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--top-k" | "-k" => top_k = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if query.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(query) = query else { return Err(Unhandled) };
    let body = post_json(
        g,
        "/api/v1/recall/search",
        &serde_json::json!({ "query": query, "top_k": top_k }),
        true,
        30,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let body = unwrap_data(body);
    let empty = Vec::new();
    // The worker returns either a bare result array or {"results": [...]}.
    let results = body.as_array().or_else(|| body["results"].as_array()).unwrap_or(&empty);
    if results.is_empty() {
        println!("{}", ui::muted("no results"));
        return Ok(0);
    }
    println!("{}", ui::header("recall search", Some(&format!("{} results", results.len()))));
    println!();
    let rows: Vec<Vec<String>> = results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            vec![
                (i + 1).to_string(),
                ui::muted(&format!("{:.3}", r["score"].as_f64().unwrap_or(0.0))),
                ui::muted(&format!("{:.3}", r["prominence_score"].as_f64().unwrap_or(0.0))),
                ui::count(r, "access_count"),
                truncate(r["record_type"].as_str().unwrap_or("?"), 14),
                truncate(r["text_preview"].as_str().unwrap_or(""), 70),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::right("#"), Col::right("score"), Col::right("prom"), Col::right("hits"), Col::left("type"), Col::left("preview")],
            &rows,
        )
    );
    Ok(0)
}

/// `noo recall prominent [--top-k K]` — GET /api/v1/recall/prominent.
pub fn recall_prominent(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut top_k = 20u64;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--top-k" | "-k" => top_k = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            _ => return Err(Unhandled),
        }
    }
    let body = get_json(g, &format!("/api/v1/recall/prominent?top_k={top_k}"), true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let body = unwrap_data(body);
    let empty = Vec::new();
    let records = body["records"].as_array().or_else(|| body.as_array()).unwrap_or(&empty);
    if records.is_empty() {
        println!("{}", ui::muted("no prominent records"));
        return Ok(0);
    }
    println!("{}", ui::header("prominent records", Some(&format!("top {}", records.len()))));
    println!();
    let rows: Vec<Vec<String>> = records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let last = r["last_accessed_at"].as_str().unwrap_or("");
            vec![
                (i + 1).to_string(),
                ui::muted(&format!("{:.3}", r["prominence_score"].as_f64().unwrap_or(0.0))),
                ui::count(r, "access_count"),
                ui::muted(&format!("{:.2}", r["avg_relevance"].as_f64().unwrap_or(0.0))),
                if last.is_empty() { ui::warn("never") } else { ui::muted(&last.chars().take(10).collect::<String>()) },
                truncate(r["record_type"].as_str().unwrap_or("?"), 12),
                truncate(r["text_preview"].as_str().unwrap_or(""), 60),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::right("#"), Col::right("prom"), Col::right("hits"), Col::right("avg"), Col::left("last access"), Col::left("type"), Col::left("preview")],
            &rows,
        )
    );
    Ok(0)
}

/// `noo recall stats` (alias `lifecycle-stats`) —
/// GET /api/v1/recall/lifecycle-stats.
pub fn recall_stats(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/v1/recall/lifecycle-stats", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    println!("{}", ui::header("recall lifecycle", None));
    print_flat(&unwrap_data(body));
    Ok(0)
}

/// `noo recall archive` — POST /api/v1/recall/archive
/// (worker-delegated manual conversation archival; Python parity: 120s).
pub fn recall_archive(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = post_json(g, "/api/v1/recall/archive", &serde_json::json!({}), true, 120);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let data = unwrap_data(body);
    let archived = data["archived"].as_u64().unwrap_or(0);
    if archived == 0 {
        ui::done(data["message"].as_str().unwrap_or("no conversations to archive"));
    } else {
        ui::done(&format!(
            "archived {archived} conversation(s) to {}",
            data["video_path"].as_str().unwrap_or("?")
        ));
    }
    ui::guide(&[
        ("noo recall videos", "the archive files, newest first"),
        ("noo recall stats", "what is still live versus archived"),
    ]);
    Ok(0)
}

/// Flags shared by `recall lifecycle` and `recall refresh`: `(dry_run, yes)`.
fn parse_prune_flags(args: &[String]) -> Result<(bool, bool), Unhandled> {
    let (mut dry_run, mut yes) = (false, false);
    for tok in args {
        match tok.as_str() {
            "--dry-run" => dry_run = true,
            "--yes" | "-y" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    Ok((dry_run, yes))
}

/// The one question both prune-capable commands ask before they run.
fn confirm_prune(g: &Globals, yes: bool, what: &str) {
    super::confirm_prompt(
        g,
        yes,
        &format!("{what} permanently prunes stale recall records. Preview with --dry-run first. Continue?"),
    );
}

/// `noo recall lifecycle [--dry-run] [-y]` — prune stale, elevate mature, compact.
/// Mutation: POST /api/v1/recall/lifecycle (120s, Python parity), after a
/// confirmation (`-y` skips; no terminal and no `-y` refuses).
/// `--dry-run`: GET /api/v1/recall/lifecycle-preview (read-only,
/// mirrors Python's `_lifecycle_preview`).
pub fn recall_lifecycle(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (dry_run, yes) = parse_prune_flags(args)?;
    if dry_run {
        return lifecycle_preview(g);
    }
    confirm_prune(g, yes, "The recall lifecycle");
    let body = post_json(g, "/api/v1/recall/lifecycle", &serde_json::json!({}), true, 120);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let data = unwrap_data(body);
    ui::done("lifecycle cycle ran");
    print!(
        "{}",
        ui::kv(&[
            ("prominence updated", ui::count(&data, "prominence_updated")),
            ("pruned", ui::count(&data, "pruned")),
            ("elevated", ui::count(&data, "elevated")),
            ("compacted", ui::count(&data, "compacted")),
        ])
    );
    if let Some(errors) = data["errors"].as_array().filter(|e| !e.is_empty()) {
        for e in errors {
            ui::warned(e.as_str().unwrap_or(&e.to_string()));
        }
    }
    ui::guide(&[
        ("noo recall stats", "prominence distribution after the cycle"),
        ("noo recall prominent", "what the cycle left at the top"),
    ]);
    Ok(0)
}

/// The `--dry-run` half of `recall lifecycle`: read-only preview of what a
/// cycle would prune / elevate / compact.
fn lifecycle_preview(g: &Globals) -> Result<i32, Unhandled> {
    let body = get_json(g, "/api/v1/recall/lifecycle-preview", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let data = unwrap_data(body);
    let empty = Vec::new();
    let prune = data["would_prune"].as_array().unwrap_or(&empty);
    let elevate = data["would_elevate"].as_array().unwrap_or(&empty);
    let compact = data["would_compact"].as_array().unwrap_or(&empty);
    println!("{}", ui::header("recall lifecycle", Some(&ui::warn("dry-run"))));
    if prune.is_empty() && elevate.is_empty() && compact.is_empty() {
        println!("{}", ui::muted("nothing to do — all records are healthy"));
        return Ok(0);
    }
    let cols = [Col::right("#"), Col::right("prom"), Col::right("hits"), Col::left("date"), Col::left("type"), Col::left("preview")];
    let row = |i: usize, r: &serde_json::Value, date: String| -> Vec<String> {
        vec![
            (i + 1).to_string(),
            ui::muted(&format!("{:.3}", r["prominence"].as_f64().unwrap_or(0.0))),
            ui::count(r, "access_count"),
            date,
            truncate(r["record_type"].as_str().unwrap_or("?"), 14),
            truncate(r["text_preview"].as_str().unwrap_or(""), 50),
        ]
    };
    if !prune.is_empty() {
        println!("{}", ui::section(&format!("would prune ({} records, created)", prune.len())));
        let rows: Vec<Vec<String>> = prune
            .iter()
            .take(20)
            .enumerate()
            .map(|(i, r)| row(i, r, ui::muted(&r["created_at"].as_str().unwrap_or("").chars().take(10).collect::<String>())))
            .collect();
        print!("{}", ui::table(&cols, &rows));
    }
    if !elevate.is_empty() {
        println!("{}", ui::section(&format!("would elevate to System 2 ({} records, last access)", elevate.len())));
        let rows: Vec<Vec<String>> = elevate
            .iter()
            .take(20)
            .enumerate()
            .map(|(i, r)| {
                let last = r["last_accessed_at"].as_str().unwrap_or("");
                let date = if last.is_empty() { ui::warn("never") } else { ui::muted(&last.chars().take(10).collect::<String>()) };
                row(i, r, date)
            })
            .collect();
        print!("{}", ui::table(&cols, &rows));
    }
    if !compact.is_empty() {
        println!("{}", ui::section(&format!("would compact {} video(s)", compact.len())));
        for v in compact {
            println!("{}", ui::status_line(Glyph::Bullet, v.as_str().unwrap_or("?")));
        }
    }
    Ok(0)
}

/// `noo recall refresh [--dry-run] [-y]` — POST /api/v1/recall/refresh
/// (archive new conversations, then run lifecycle; Python parity: 180s),
/// after the same confirmation as `recall lifecycle`. `--dry-run` previews
/// what the lifecycle half would prune and archives nothing.
pub fn recall_refresh(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (dry_run, yes) = parse_prune_flags(args)?;
    if dry_run {
        if !g.json {
            println!("{}", ui::muted("dry run: nothing is archived; this is what the lifecycle half would do"));
        }
        return lifecycle_preview(g);
    }
    confirm_prune(g, yes, "Recall refresh (archive, then lifecycle)");
    let body = post_json(g, "/api/v1/recall/refresh", &serde_json::json!({}), true, 180);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let data = unwrap_data(body);
    let archive = &data["archive"];
    let lifecycle = &data["lifecycle"];
    ui::done("recall refreshed");
    print!(
        "{}",
        ui::kv(&[
            ("archived", archived_cell(archive)),
            ("pruned", ui::count(lifecycle, "pruned")),
            ("elevated", ui::count(lifecycle, "elevated")),
            ("compacted", ui::count(lifecycle, "compacted")),
        ])
    );
    ui::guide(&[
        ("noo recall status", "the store after archive + lifecycle"),
        ("noo recall videos", "the archive the refresh wrote to"),
    ]);
    Ok(0)
}

/// `noo recall test` — LOCAL stub, no gateway call. The v1 MP4+QR self-test
/// was removed in trellion v0.0.2; like the Python
/// command, this reports the v2 architecture and its alternatives.
pub fn recall_test(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    const ALTERNATIVES: [(&str, &str); 3] = [
        ("per-persona FAISS health", "noo recall status"),
        ("prominence lifecycle", "noo recall lifecycle"),
        ("end-to-end smoke", "run a traversal + check trellion_traversal_records"),
    ];
    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "status": "info",
                "architecture": "postgres+faiss",
                "message": "recall memory is now Postgres + FAISS (no MP4, no QR); the v1 self-test was removed in trellion v0.0.2",
                "alternatives": ALTERNATIVES
                    .iter()
                    .map(|(what, how)| serde_json::json!({"check": what, "command": how}))
                    .collect::<Vec<_>>(),
            })
        );
        return Ok(0);
    }
    println!("{}", ui::header("recall test", Some("Postgres + FAISS")));
    println!("{}", ui::muted("recall memory is now Postgres + FAISS (no MP4, no QR); the v1 self-test was removed"));
    println!("{}", ui::section("alternatives"));
    for (what, how) in ALTERNATIVES {
        println!("{}", ui::status_line(Glyph::Bullet, &format!("{what}: {}", ui::cmd(how))));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_rows_do_not_invent_zero_for_a_count_the_gateway_omitted() {
        let archive = serde_json::json!({});
        let cell = archived_cell(&archive);
        assert!(cell.contains("Not reported") && !cell.contains('0'), "{cell}");
        assert_eq!(archived_cell(&serde_json::json!({"archived": 0})), "0 conversations");
        assert_eq!(archived_cell(&serde_json::json!({"archived": 12})), "12 conversations");
        let hits = ui::count(&serde_json::json!({"text_preview": "x"}), "access_count");
        assert!(hits.contains("Not reported") && !hits.contains('0'), "{hits}");
    }

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn prune_flags_parse_dry_run_and_yes() {
        assert_eq!(parse_prune_flags(&a(&[])).unwrap(), (false, false));
        assert_eq!(parse_prune_flags(&a(&["--dry-run"])).unwrap(), (true, false));
        assert_eq!(parse_prune_flags(&a(&["-y"])).unwrap(), (false, true));
        assert_eq!(parse_prune_flags(&a(&["--yes", "--dry-run"])).unwrap(), (true, true));
        assert!(parse_prune_flags(&a(&["--force"])).is_err());
    }
}
