// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo memory …` — memory system reads (Rust gateway routes/memory.rs).
//!
//! Ported: search, stats, health, tool-stats, conversations, embed,
//! embed-status, embed-stop — including the `--watch/-w` progress loop
//! (native port of memory_cli.py `_watch_progress`: 1s poll of
//! /api/memory/embed/status, 2s back-off on fetch errors, loop ends when
//! state leaves running/stopping).
//!
//! Embed-worker control on the Rust gateway (routes/memory.rs) is a Redis
//! flag (`noo:embed:state` running/stopped) + SQL counts; `embed/start`
//! takes no body (batch_size etc. come from noomesh.yaml), so the CLI sends
//! none and no longer offers tuning flags.
//!
//! Note: the Python memory commands send NO auth headers and 401 against the
//! auth-enforcing gateway — like `config get`, the Rust versions are the
//! working surface. Python `memory search` also always sends
//! user_id=anonymous (filtering to a user that stores nothing); the Rust
//! version only sends user_id when --user is given.

use super::{truncate, urlencode};
use crate::http::{get_json, get_json_opt, post_json};
use crate::ui::{self, Col};
use crate::{Globals, Unhandled};

/// Watch-loop timing, matching Python's `_watch_progress`: poll every 1s,
/// back off 2s after a failed status fetch.
const WATCH_POLL_SECS: u64 = 1;
const WATCH_RETRY_SECS: u64 = 2;

/// `noo memory search QUERY [--user/-u USER]` —
/// GET /api/memory/search?query=…[&user_id=…] (pgvector similarity).
pub fn memory_search(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut query: Option<String> = None;
    let mut user: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--user" | "-u" => user = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if query.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(q) = query else { return Err(Unhandled) };
    let mut path = format!("/api/memory/search?query={}", urlencode(&q));
    if let Some(u) = &user {
        path.push_str(&format!("&user_id={}", urlencode(u)));
    }
    // Embeds the query via TEI first — allow more than the read default.
    let body = get_json(g, &path, true, 30);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let results = body["results"].as_array().unwrap_or(&empty);
    if results.is_empty() {
        println!("{}", ui::muted("no relevant context"));
        return Ok(0);
    }
    println!("{}", ui::header("memory search", Some(&format!("{} results", results.len()))));
    println!();
    // Hit content is data; score/type/time are the muted context around it.
    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|r| {
            let created: String = r["created_at"].as_str().unwrap_or("").chars().take(19).collect();
            vec![
                ui::muted(&format!("{:.3}", r["score"].as_f64().unwrap_or(0.0))),
                r["type"].as_str().unwrap_or(ui::dash()).to_string(),
                ui::muted(&created),
                r["content"].as_str().unwrap_or("").replace('\n', " "),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(&[Col::right("score"), Col::left("type"), Col::left("created"), Col::left("content")], &rows)
    );
    Ok(0)
}

/// `noo memory stats` — storage + conversation + tool statistics.
/// Composite like the Python command: GET /api/memory/storage-stats
/// (primary), then best-effort /api/conversations/stats/overview and
/// /api/conversations/stats/tools. `--json` prints the same combined
/// {"storage","conversations","tools"} object as the Python CLI.
pub fn memory_stats(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let storage = get_json(g, "/api/memory/storage-stats", true, 10);
    let conv = get_json_opt(g, "/api/conversations/stats/overview", true, 10);
    let tools = get_json_opt(g, "/api/conversations/stats/tools", true, 10);

    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "storage": storage,
                "conversations": conv,
                "tools": tools,
            })
        );
        return Ok(0);
    }

    println!("{}", ui::header("memory", None));
    println!("{}", ui::section("storage"));
    let enabled = storage["embeddings_enabled"].as_bool().unwrap_or(false);
    let mut storage_rows = storage_count_rows(&storage);
    storage_rows.push(("embeddings", if enabled { ui::state("enabled") } else { ui::warn("disabled") }));
    print!("{}", ui::kv(&storage_rows));

    if let Some(c) = &conv {
        println!("{}", ui::section("conversations (30 days)"));
        print!(
            "{}",
            ui::kv(&[
                ("conversations", ui::count(c, "total_conversations")),
                ("messages", ui::count(c, "total_messages")),
                ("tool calls", ui::count(c, "total_tool_calls")),
                (
                    "avg messages/conv",
                    format!("{:.1}", c["avg_messages_per_conversation"].as_f64().unwrap_or(0.0)),
                ),
                (
                    "tokens in/out",
                    format!("{}/{}", ui::count(c, "total_tokens_in"), ui::count(c, "total_tokens_out")),
                ),
            ])
        );
    }

    if let Some(t) = &tools {
        if let Some(list) = t["tools"].as_array().filter(|l| !l.is_empty()) {
            println!("{}", ui::section("top tools (30 days)"));
            print_tool_table(list.iter().take(10));
        }
    }
    Ok(0)
}

/// `noo memory health` — GET /api/memory/health (subsystem health report).
pub fn memory_health(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/memory/health", true, 10);
    if g.json {
        println!("{body}");
    } else {
        // Arbitrary nested health object — pretty JSON, like config get.
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()));
    }
    Ok(0)
}

/// `noo memory conversations [--user/-u U] [--limit/-n N]` —
/// GET /api/conversations/with-preview (the Rust gateway's conversation
/// list route; the Python CLI's bare GET /api/conversations doesn't exist
/// there). `--channel/-c` → Python: the endpoint has no channel filter.
pub fn memory_conversations(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut user: Option<String> = None;
    let mut limit = 20u64;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--user" | "-u" => user = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--limit" | "-n" => limit = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            // No channel column on the with-preview route — Python's
            // /api/conversations surface is the reference for this filter.
            "--channel" | "-c" => return Err(Unhandled),
            _ => return Err(Unhandled),
        }
    }
    let mut path = format!("/api/conversations/with-preview?limit={limit}");
    if let Some(u) = &user {
        path.push_str(&format!("&user_id={}", urlencode(u)));
    }
    let body = get_json(g, &path, true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let convs = body["conversations"].as_array().unwrap_or(&empty);
    if convs.is_empty() {
        println!("{}", ui::muted("no conversations"));
        return Ok(0);
    }
    let total = body["total"].as_u64().unwrap_or(convs.len() as u64);
    println!("{}", ui::header("conversations", Some(&format!("{} of {total}", convs.len()))));
    println!();
    let rows: Vec<Vec<String>> = convs
        .iter()
        .map(|c| {
            let id: String = c["id"].as_str().unwrap_or("?").chars().take(12).collect();
            let started: String = c["started_at"].as_str().unwrap_or("").chars().take(19).collect();
            vec![
                ui::muted(&id),
                truncate(c["user_id"].as_str().unwrap_or(""), 16),
                ui::count(c, "total_messages"),
                ui::muted(&started),
                c["preview"].as_str().unwrap_or("").replace('\n', " "),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left("id"), Col::left("user"), Col::right("msgs"), Col::left("started"), Col::left("preview")],
            &rows,
        )
    );
    Ok(0)
}

/// `noo memory tool-stats [--days/-d N]` — GET /api/conversations/stats/tools.
pub fn memory_tool_stats(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut days = 30u64;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--days" | "-d" => days = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            _ => return Err(Unhandled),
        }
    }
    let body = get_json(g, &format!("/api/conversations/stats/tools?days={days}"), true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let tools = body["tools"].as_array().unwrap_or(&empty);
    if tools.is_empty() {
        println!("{}", ui::muted("no tool usage data"));
        return Ok(0);
    }
    println!("{}", ui::header("tool usage", Some(&format!("{days} days"))));
    println!();
    print_tool_table(tools.iter().take(20));
    Ok(0)
}

/// Tuning flags `memory embed` used to accept. The gateway's `embed_start`
/// takes no request body (batching comes from noomesh.yaml), so each of these
/// was parsed, sent and silently dropped.
const EMBED_REMOVED_FLAGS: [&str; 10] = [
    "--batch-size", "-b", "--delay", "-d", "--max-batches", "-m", "--build-graph", "-g",
    "--threshold", "-t",
];

/// How the gateway answered `POST /api/memory/embed/start`.
#[derive(Debug, PartialEq)]
enum EmbedStart {
    Started,
    AlreadyRunning,
    /// `{"status":"error","error":...}` (e.g. no Redis to hold the flag).
    Refused(String),
}

fn embed_start_outcome(resp: &serde_json::Value) -> EmbedStart {
    match resp["status"].as_str() {
        Some("already_running") => EmbedStart::AlreadyRunning,
        Some("error") => EmbedStart::Refused(
            resp["error"].as_str().unwrap_or("the gateway refused to start the embed worker").to_string(),
        ),
        _ if resp["error"].as_str().is_some_and(|e| !e.is_empty()) => {
            EmbedStart::Refused(resp["error"].as_str().unwrap_or_default().to_string())
        }
        _ => EmbedStart::Started,
    }
}

/// `noo memory embed [-w]` — POST /api/memory/embed/start. The gateway reads
/// no body: batch size and delay come from noomesh.yaml, so the old tuning
/// flags are gone and passing one says so. `--watch/-w` runs the native
/// progress poll loop (see [`watch_embed_progress`]).
pub fn memory_embed(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut watch = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--watch" | "-w" => watch = true,
            "--model" => {
                let _ = iter.next();
                embed_flag_removed(g, "--model");
            }
            t if EMBED_REMOVED_FLAGS.contains(&t) => {
                let _ = iter.next();
                embed_flag_removed(g, t);
            }
            _ => return Err(Unhandled),
        }
    }
    let resp = post_json(g, "/api/memory/embed/start", &serde_json::json!({}), true, 10);
    let outcome = embed_start_outcome(&resp);
    if g.json {
        // With --watch this becomes the first line of an NDJSON event
        // stream (start response, then one status object per poll).
        println!("{resp}");
        if outcome != EmbedStart::Started && outcome != EmbedStart::AlreadyRunning {
            return Ok(crate::output::ExitCode::RemoteError as i32);
        }
        if watch {
            watch_embed_progress(g);
        }
        return Ok(0);
    }
    match outcome {
        EmbedStart::Refused(why) => {
            ui::failed(&format!("embedding worker not started: {why}"), Some("`noo memory embed-status` shows the worker state"));
            return Ok(crate::output::ExitCode::RemoteError as i32);
        }
        EmbedStart::AlreadyRunning => ui::warned("embedding worker is already running"),
        EmbedStart::Started => ui::done("embedding worker started"),
    }
    if let Some(w) = resp["warning"].as_str() {
        ui::warned(w);
    }
    if watch {
        // Python watches unconditionally after start (even if already_running).
        watch_embed_progress(g);
    } else {
        ui::guide(&[
            ("noo memory embed-status --watch", "follows the batches until the worker goes idle"),
            ("noo memory embed-stop", "stops the worker; the next run resumes where it left off"),
        ]);
    }
    Ok(0)
}

fn embed_flag_removed(g: &Globals, flag: &str) -> ! {
    crate::output::fail(
        g.json,
        crate::output::ExitCode::Usage,
        "flag_removed",
        &format!("`noo memory embed` no longer takes {flag}: the gateway ignored it"),
        Some("the embed drain is tuned in noomesh.yaml; `noo memory embed [--watch]` is the whole command"),
    )
}

/// `noo memory embed-status [--watch/-w]` — GET /api/memory/embed/status
/// (Redis flag + SQL embedding counts). With `--watch`, keeps polling while
/// the worker is running (Python parity: only enters the loop when the
/// initial state is "running").
pub fn memory_embed_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut watch = false;
    for tok in args {
        match tok.as_str() {
            "--watch" | "-w" => watch = true,
            _ => return Err(Unhandled),
        }
    }
    let body = get_json(g, "/api/memory/embed/status", true, 10);
    if g.json {
        println!("{body}");
    } else {
        println!("{}", ui::header("embedding", body["state"].as_str()));
        print_embed_state(&body);
    }
    if watch && body["state"].as_str() == Some("running") {
        watch_embed_progress(g);
    } else if !g.json {
        let running = body["state"].as_str() == Some("running");
        ui::guide(&[
            if running {
                ("noo memory embed-status --watch", "follows the batches until the worker goes idle")
            } else {
                ("noo memory embed", "starts the worker on the unembedded records")
            },
            ("noo memory stats", "the memory store totals the worker is filling"),
        ]);
    }
    Ok(0)
}

/// `noo memory embed-stop` — POST /api/memory/embed/stop (30s, Python parity).
pub fn memory_embed_stop(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let resp = post_json(g, "/api/memory/embed/stop", &serde_json::json!({}), true, 30);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done("embedding worker stopped");
    if let Some(w) = resp["warning"].as_str() {
        ui::warned(w);
    }
    ui::guide(&[
        ("noo memory embed-status", "shows how many records are still unembedded"),
        ("noo memory embed", "resumes from the first unembedded record"),
    ]);
    Ok(0)
}

/// Native port of memory_cli.py `_watch_progress`: poll
/// GET /api/memory/embed/status until the worker leaves the
/// running/stopping states, rendering a live progress line.
///
/// - Polls every [`WATCH_POLL_SECS`]; a failed fetch is tolerated and
///   retried after [`WATCH_RETRY_SECS`] (Python's bare `except: sleep(2)`).
/// - Human mode: one `\r`-overwritten progress line on stderr when it's a
///   TTY (the `models pull` idiom), else a plain line per change; then
///   "embedding complete" + the final status block, like Python's
///   print_success + `_print_embed_status`.
/// - `--json` mode: Python doesn't define `--json` for these commands at
///   all (rich output only), so the Rust behavior is newline-delimited
///   JSON — each poll's status object is one line on stdout, ending with
///   the terminal status.
/// - Ctrl+C simply exits; the worker keeps running server-side, same
///   effect as Python's KeyboardInterrupt note.
fn watch_embed_progress(g: &Globals) {

    if !g.json {
        println!("{}", ui::note("watching progress — Ctrl+C stops watching, not the worker"));
    }
    let stderr_tty = ui::stderr_is_tty();
    let mut last_line = String::new();
    let mut progressed = false; // an unterminated \r line is open on stderr

    loop {
        let Some(status) = get_json_opt(g, "/api/memory/embed/status", true, 5) else {
            std::thread::sleep(std::time::Duration::from_secs(WATCH_RETRY_SECS));
            continue;
        };

        if g.json {
            println!("{status}");
        }

        let state = status["state"].as_str().unwrap_or("idle");
        if state != "running" && state != "stopping" {
            if progressed {
                eprintln!();
            }
            if !g.json {
                ui::close_done("embedding complete");
                print_embed_state(&status);
                ui::guide(&[
                    ("noo memory stats", "totals after the run"),
                    ("noo memory search <query>", "try the freshly embedded records"),
                ]);
            }
            return;
        }

        if !g.json {
            let line = progress_line(&status);
            if stderr_tty {
                crate::ui::rewrite_line(&line);
                progressed = true;
            } else if line != last_line {
                // Not a TTY: one narration line per change (stdout).
                println!("{line}");
            }
            last_line = line;
        }
        std::thread::sleep(std::time::Duration::from_secs(WATCH_POLL_SECS));
    }
}

/// One-line progress description. Prefers the Python gateway's batch
/// counters (`Batch X/Y | Embedded: N`, matching `_watch_progress`), and
/// falls back to the Rust gateway's stats shape
/// ({total, embedded, unembedded, progress}) which has no batch counters.
fn progress_line(status: &serde_json::Value) -> String {
    let stats = &status["stats"];
    if let Some(total_batches) = stats["total_batches"].as_u64() {
        return format!(
            "batch {}/{} · embedded {}",
            stats["current_batch"].as_u64().unwrap_or(0),
            total_batches,
            stats["total_embedded"].as_u64().unwrap_or(0),
        );
    }
    format!(
        "embedded {}/{} ({:.1}%)",
        stats["embedded"].as_u64().unwrap_or(0),
        stats["total"].as_u64().unwrap_or(0),
        stats["progress"].as_f64().unwrap_or(0.0) * 100.0,
    )
}

/// The four storage counters of `memory stats`. A counter the gateway did
/// not send reads "not reported", never 0 (i191 D5).
fn storage_count_rows(storage: &serde_json::Value) -> Vec<(&'static str, String)> {
    vec![
        ("total records", ui::count(storage, "total_records")),
        ("embedded", ui::count(storage, "embedded_records")),
        ("unembedded", ui::count(storage, "unembedded_records")),
        ("unique users", ui::count(storage, "unique_users")),
    ]
}

/// Render the Rust gateway's embed-status shape
/// ({state, stats:{total,embedded,unembedded,progress}, config:{…}}).
fn print_embed_state(body: &serde_json::Value) {
    print!("{}", ui::kv(&embed_state_rows(body)));
}

fn embed_state_rows(body: &serde_json::Value) -> Vec<(&'static str, String)> {
    let state = body["state"].as_str().unwrap_or("unknown");
    let mut rows: Vec<(&'static str, String)> = vec![("state", ui::state(state))];
    let stats = &body["stats"];
    if stats.is_object() {
        rows.push((
            "records",
            format!(
                "{} total, {} embedded, {} unembedded ({:.1}%)",
                ui::count(stats, "total"),
                ui::count(stats, "embedded"),
                ui::count(stats, "unembedded"),
                stats["progress"].as_f64().unwrap_or(0.0) * 100.0,
            ),
        ));
    }
    let config = &body["config"];
    if config.is_object() {
        rows.push((
            "config",
            ui::muted(&format!(
                "batch_size={}, build_relationships={}, model={}",
                ui::count(config, "batch_size"),
                config["build_relationships"].as_bool().unwrap_or(false),
                config["embedding_model"].as_str().unwrap_or(ui::dash()),
            )),
        ));
    }
    rows
}

fn print_tool_table<'a>(tools: impl Iterator<Item = &'a serde_json::Value>) {
    let rows: Vec<Vec<String>> = tools
        .map(|tool| {
            let rate = tool["success_rate"].as_f64().unwrap_or(0.0) * 100.0;
            let avg = tool["avg_execution_ms"].as_f64();
            vec![
                truncate(tool["name"].as_str().unwrap_or("?"), 32),
                ui::count(tool, "total_calls"),
                ui::count(tool, "successful"),
                format!("{rate:.0}%"),
                avg.map(|a| format!("{a:.0}ms")).unwrap_or_default(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left("tool"), Col::right("calls"), Col::right("success"), Col::right("rate"), Col::right("avg")],
            &rows,
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_and_embed_rows_say_not_reported_for_missing_counters() {
        let rows = storage_count_rows(&serde_json::json!({"total_records": 0, "embedded_records": 10}));
        let cell = |k: &str| rows.iter().find(|(n, _)| *n == k).unwrap().1.clone();
        assert_eq!(cell("total records"), "0");
        assert_eq!(cell("embedded"), "10");
        for k in ["unembedded", "unique users"] {
            assert!(cell(k).contains("Not reported") && !cell(k).contains('0'), "{k}: {}", cell(k));
        }
        let rows = embed_state_rows(&serde_json::json!({"state": "idle", "stats": {"embedded": 4}, "config": {}}));
        let records = &rows.iter().find(|(n, _)| *n == "records").unwrap().1;
        assert!(records.starts_with("Not reported total, 4 embedded, Not reported unembedded"), "{records}");
        let config = &rows.iter().find(|(n, _)| *n == "config").unwrap().1;
        assert!(config.contains("batch_size=Not reported"), "{config}");
    }

    // Reply shapes from gateway-rust/src/routes/memory.rs `embed_start`.
    #[test]
    fn embed_start_error_reply_is_not_a_start() {
        let real = serde_json::json!({"status": "error", "error": "Redis unavailable: the drain's start/stop flag has nowhere to live"});
        assert_eq!(
            embed_start_outcome(&real),
            EmbedStart::Refused("Redis unavailable: the drain's start/stop flag has nowhere to live".into())
        );
    }

    #[test]
    fn embed_start_distinguishes_started_from_already_running() {
        assert_eq!(embed_start_outcome(&serde_json::json!({"status": "already_running"})), EmbedStart::AlreadyRunning);
        assert_eq!(embed_start_outcome(&serde_json::json!({"status": "started"})), EmbedStart::Started);
    }

    #[test]
    fn the_ignored_tuning_flags_are_all_listed() {
        for f in ["-b", "--batch-size", "-d", "--delay", "-m", "--max-batches", "-g", "--build-graph", "-t", "--threshold"] {
            assert!(EMBED_REMOVED_FLAGS.contains(&f), "{f}");
        }
    }
}
