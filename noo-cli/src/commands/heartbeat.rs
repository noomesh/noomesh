// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo heartbeat …` — heartbeat cron scheduler (Rust gateway routes in
//! `routes/intelligence.rs`).
//!
//! Ported: status, list, run, history, toggle, set-schedule, add, remove (the destructive
//! confirm follows the repo's agent-first contract — `--yes/-y` skips, see
//! `confirm_destructive`; Python's typer.confirm is the interactive
//! reference).

use super::{confirm_destructive, truncate};
use crate::http::{delete_json, get_json, post_json, put_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo heartbeat status` — GET /api/heartbeat/status.
pub fn heartbeat_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/heartbeat/status", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    // `running` is null when the gateway has no tick record — that is "we do
    // not know", not "stopped". Printing "stopped" for it is a lie an operator
    // would act on.
    let enabled = body["enabled"].as_bool().unwrap_or(false);
    let scheduler = match body["running"].as_bool() {
        Some(true) => ui::state("running"),
        Some(false) => ui::state("stopped"),
        None => ui::warn("unknown"),
    };
    let mut scheduler = scheduler;
    if body["running"].is_null() {
        if let Some(d) = body["running_detail"].as_str() {
            scheduler = format!("{scheduler}  {}", ui::muted(d));
        }
    }
    let last_tick = body["loop_last_tick_age_secs"].as_f64().map(|age| format!("{age:.0}s ago"));
    let right = last_tick.as_deref().map(|t| format!("last tick {t}"));
    println!("{}", ui::header("heartbeat", right.as_deref()));
    let mut rows: Vec<(&str, String)> = vec![
        ("scheduler", scheduler),
        ("enabled", if enabled { ui::ok("yes") } else { "no".to_string() }),
        (
            "tasks",
            format!(
                "{} ({} enabled)",
                body["task_count"].as_u64().unwrap_or(0),
                body["enabled_count"].as_u64().unwrap_or(0)
            ),
        ),
        ("recent runs (24h)", body["recent_runs_24h"].as_u64().unwrap_or(0).to_string()),
    ];
    if let Some(t) = last_tick {
        rows.push(("last tick", t));
    }
    if let Some(n) = body["waiting_review"].as_u64().filter(|n| *n > 0) {
        rows.push(("awaiting review", ui::warn(&format!("{n} existing: noo heartbeat review-existing"))));
    }
    print!("{}", ui::kv(&rows));
    Ok(0)
}

/// `noo heartbeat list` — GET /api/heartbeat/tasks.
pub fn heartbeat_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/heartbeat/tasks", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let tasks = body["tasks"].as_array().unwrap_or(&empty);
    if tasks.is_empty() {
        println!("{}", ui::muted("no heartbeat tasks"));
        return Ok(0);
    }
    let enabled = tasks.iter().filter(|t| t["enabled"].as_bool().unwrap_or(false)).count();
    if let Some(n) = body["waiting_review"].as_u64().filter(|n| *n > 0) {
        println!("{}", ui::warn(&format!("{n} existing task(s) or saved recipient(s) waiting for review: run `noo heartbeat review-existing`")));
    }
    println!(
        "{}",
        ui::header("heartbeat tasks", Some(&format!("{} tasks · {enabled} enabled", tasks.len())))
    );
    println!("{}", ui::section("tasks"));
    let rows: Vec<Vec<String>> = tasks
        .iter()
        .map(|t| {
            let ts = |key: &str| -> String {
                t[key].as_str().unwrap_or("").chars().take(19).collect()
            };
            let on = t["enabled"].as_bool().unwrap_or(false);
            vec![
                ui::glyph_cell(if on { Glyph::Ok } else { Glyph::Bullet }),
                ui::muted(&truncate(t["id"].as_str().unwrap_or("?"), 22)),
                truncate(t["name"].as_str().unwrap_or("?"), 26),
                truncate(t["schedule"].as_str().unwrap_or("?"), 14),
                truncate(t["action"].as_str().unwrap_or("?"), 22),
                format!("{}{}", if on { "on".to_string() } else { ui::muted("off") }, guard_suffix(&t["guard"])),
                ts("last_run"),
                ts("next_run"),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("id"),
                Col::left("name"),
                Col::left("schedule"),
                Col::left("action"),
                Col::left("state"),
                Col::left("last run"),
                Col::left("next run"),
            ],
            &rows,
        )
    );
    Ok(0)
}

/// A write the gateway turned into a proposal (a task that deletes data, written without a person's
/// own credential): say so, plainly, instead of "added". True when it was.
fn proposed(resp: &serde_json::Value) -> bool {
    if resp["proposal"].as_bool() != Some(true) {
        return false;
    }
    ui::warned(resp["message"].as_str().unwrap_or("filed as a proposal; nothing was created or changed"));
    ui::guide(&[("noo heartbeat proposals", "the task proposals waiting for a person")]);
    true
}

/// What the list adds to the state cell: a task that destroys data says so and who authorised it
/// (`guard` on the task, from the gateway); an `entity_cleanup` task says preview or apply.
pub(crate) fn guard_suffix(guard: &serde_json::Value) -> String {
    if !guard["destructive"].as_bool().unwrap_or(false) {
        if guard["runs_read_only"].as_bool().unwrap_or(false) {
            // An agent-turn task no person authorised: its runs may call read-only tools only.
            return ui::warn(" read-only (no recorded approver)");
        }
        return if guard["apply"].as_str() == Some("preview") { ui::muted(" preview") } else { String::new() };
    }
    let label = if guard["apply"].as_str() == Some("apply") { "apply" } else { "destructive" };
    match guard["authorised_by"].as_str() {
        Some(by) => ui::warn(&format!(" {label} (by {by})")),
        None => ui::warn(&format!(" {label} (no recorded approver)")),
    }
}

/// The rendering decision for `noo heartbeat run`'s response, factored out
/// of I/O so every branch (queued / success / other status / no status) is
/// unit-testable. Response shapes, per the gateway (routes/intelligence.rs):
/// sub-second native actions answer synchronously with `status: "success"`
/// (or a terminal failure) + `duration_ms` + `result_text`; LLM/delegated
/// actions detach and answer `{"status":"queued","run_id":...,
/// "dispatched_at":...,"poll":...,"message":...}`, running in the
/// background and writing the real outcome to `noo_heartbeat_runs` (visible
/// via `noo heartbeat history`) when they finish.
#[derive(Debug, PartialEq)]
pub(crate) struct Outcome {
    pub(crate) headline: String,
    pub(crate) is_warning: bool,
    /// Supplementary lines printed after the headline. Only the `success`
    /// branch's line is the task's own captured output (printed verbatim,
    /// see `verbatim`); every other branch's lines are gateway-side
    /// diagnostic text and print muted.
    pub(crate) detail_lines: Vec<String>,
    pub(crate) verbatim: bool,
    pub(crate) guide: Vec<(String, String)>,
}

/// Pure decision function behind `heartbeat_run`'s rendering — see `Outcome`.
pub(crate) fn run_outcome(resp: &serde_json::Value, task_id: &str) -> Outcome {
    fn nonempty(v: &serde_json::Value) -> Option<&str> {
        v.as_str().map(str::trim).filter(|s| !s.is_empty())
    }
    match resp["status"].as_str() {
        None => {
            // Older gateway, or an error body: no status at all — do not
            // guess a duration or a result.
            let mut detail_lines = Vec::new();
            if let Some(e) = nonempty(&resp["error"]) {
                detail_lines.push(e.to_string());
            }
            if let Some(m) = nonempty(&resp["message"]) {
                detail_lines.push(m.to_string());
            }
            Outcome {
                headline: "the gateway returned no run status".to_string(),
                is_warning: true,
                detail_lines,
                verbatim: false,
                guide: vec![(format!("noo heartbeat history {task_id}"), String::new())],
            }
        }
        // `running`: the action started work that finishes later (the
        // database backup queues a host dump and a gateway hook records
        // the result). Like `queued`, it is not an outcome yet; it used to
        // fall into the terminal branch below and print as a warning with
        // error hints for a backup that was simply still in progress.
        Some(state @ ("queued" | "running")) => {
            // `run_id` is absent on a queued reply from an older gateway:
            // report the queue without a run id and without the --run hint
            // (a filter with no id to filter by is not a hint, it's a lie).
            let run_id8: Option<String> = resp["run_id"].as_str().map(|r| r.chars().take(8).collect());
            let headline = match &run_id8 {
                Some(id) => format!("task {task_id}: {state} — run {id}"),
                None => format!("task {task_id}: {state}"),
            };
            let mut detail_lines = Vec::new();
            if let Some(m) = nonempty(&resp["message"]) {
                detail_lines.push(m.to_string());
            }
            let mut guide = Vec::new();
            if let Some(id) = &run_id8 {
                guide.push((
                    format!("noo heartbeat history {task_id} --run {id}"),
                    "the outcome of this run, once it finishes".to_string(),
                ));
            }
            guide.push((
                format!("noo heartbeat history {task_id}"),
                "this task's recent runs".to_string(),
            ));
            Outcome { headline, is_warning: false, detail_lines, verbatim: false, guide }
        }
        Some("success") => {
            let duration = resp["duration_ms"].as_u64().unwrap_or(0);
            let mut detail_lines = Vec::new();
            if let Some(t) = nonempty(&resp["result_text"]) {
                detail_lines.push(t.to_string());
            }
            Outcome {
                headline: format!("task {task_id}: success ({duration}ms)"),
                is_warning: false,
                detail_lines,
                verbatim: true,
                guide: vec![
                    (
                        format!("noo heartbeat history {task_id}"),
                        "this run alongside the scheduled ones".to_string(),
                    ),
                    ("noo heartbeat list".to_string(), "when it fires next".to_string()),
                ],
            }
        }
        Some(other) => {
            // failed / skipped / refused / error / anything else terminal.
            let duration = resp["duration_ms"].as_u64().unwrap_or(0);
            let headline = if duration > 0 {
                format!("task {task_id}: {other} ({duration}ms)")
            } else {
                format!("task {task_id}: {other}")
            };
            let mut detail_lines = Vec::new();
            if let Some(t) = nonempty(&resp["result_text"]) {
                detail_lines.push(t.to_string());
            } else if let Some(e) = nonempty(&resp["error"]) {
                detail_lines.push(e.to_string());
            }
            Outcome {
                headline,
                is_warning: true,
                detail_lines,
                verbatim: false,
                guide: vec![
                    (
                        format!("noo heartbeat history {task_id}"),
                        "the recorded reason, and earlier runs".to_string(),
                    ),
                    ("noo logs errors".to_string(), "recent errors across the fleet".to_string()),
                ],
            }
        }
    }
}

/// `noo heartbeat run TASK_ID` — POST /api/heartbeat/tasks/{id}/run.
/// Quick, Rust-native actions run and return synchronously; LLM/delegated
/// actions are queued and finish in the background — see `run_outcome`.
pub fn heartbeat_run(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [task_id] = args else { return Err(Unhandled) };
    if task_id.starts_with('-') {
        return Err(Unhandled);
    }
    let resp = post_json(
        g,
        &format!("/api/heartbeat/tasks/{task_id}/run"),
        &serde_json::json!({}),
        true,
        120,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let outcome = run_outcome(&resp, task_id);
    if outcome.is_warning {
        ui::warned(&outcome.headline);
    } else {
        ui::done(&outcome.headline);
    }
    for line in &outcome.detail_lines {
        if outcome.verbatim {
            // The task's own output is the captured value: stdout, verbatim.
            ui::value(line);
        } else {
            println!("{}", ui::muted(line));
        }
    }
    let guide_refs: Vec<(&str, &str)> =
        outcome.guide.iter().map(|(c, w)| (c.as_str(), w.as_str())).collect();
    ui::guide(&guide_refs);
    Ok(0)
}

/// Parsed, validated arguments for `noo heartbeat history` — factored out
/// of I/O so both the CLI and its tests can exercise the parser directly.
#[derive(Debug, PartialEq, Default)]
pub(crate) struct HistoryArgs {
    pub(crate) task_id: Option<String>,
    pub(crate) run_prefix: Option<String>,
    pub(crate) limit: u64,
}

/// `noo heartbeat history [<task-id>] [--task-id <id>] [--run <run-id>]
/// [--limit <n>]`. The task id may be given positionally, via `--task-id`,
/// or both — but only if they agree (a positional AND a `--task-id` that
/// disagree is a contradiction, not two filters). `--run` takes a run-id
/// prefix of at least 8 characters and filters client-side (the gateway's
/// /api/heartbeat/history has no run_id filter of its own).
pub(crate) fn parse_history_args(args: &[String]) -> Result<HistoryArgs, ()> {
    let mut limit = 20u64;
    let mut task_id: Option<String> = None;
    let mut run_prefix: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--limit" | "-n" => limit = iter.next().and_then(|v| v.parse().ok()).ok_or(())?,
            "--task-id" => {
                let v = iter.next().ok_or(())?.clone();
                match &task_id {
                    Some(existing) if existing != &v => return Err(()),
                    _ => task_id = Some(v),
                }
            }
            "--run" => {
                let v = iter.next().ok_or(())?.clone();
                if v.chars().count() < 8 {
                    return Err(());
                }
                run_prefix = Some(v);
            }
            t if t.starts_with('-') => return Err(()),
            t => match &task_id {
                Some(existing) if existing != t => return Err(()),
                _ => task_id = Some(t.to_string()),
            },
        }
    }
    Ok(HistoryArgs { task_id, run_prefix, limit })
}

/// `noo heartbeat history [<task-id>] [--task-id <id>] [--run <run-id>]
/// [--limit <n>]` — GET /api/heartbeat/history.
pub fn heartbeat_history(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    crate::ui::auto_page(); // long output: $PAGER on a TTY (no-op otherwise)
    let parsed = parse_history_args(args).map_err(|_| Unhandled)?;
    let mut path = format!("/api/heartbeat/history?limit={}", parsed.limit);
    if let Some(t) = &parsed.task_id {
        path.push_str(&format!("&task_id={}", super::urlencode(t)));
    }
    let body = get_json(g, &path, true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let all_runs = body["runs"].as_array().unwrap_or(&empty);
    let runs: Vec<&serde_json::Value> = match &parsed.run_prefix {
        Some(prefix) => all_runs
            .iter()
            .filter(|r| r["run_id"].as_str().is_some_and(|id| id.starts_with(prefix.as_str())))
            .collect(),
        None => all_runs.iter().collect(),
    };
    if runs.is_empty() {
        if let Some(prefix) = &parsed.run_prefix {
            // Distinct from "no run history": the run was just dispatched
            // and its row does not exist yet — this is not an error.
            let id8: String = prefix.chars().take(8).collect();
            println!(
                "{}",
                ui::muted(&format!(
                    "run {id8} has not reported yet — it is still running, or check again shortly"
                ))
            );
        } else {
            println!("{}", ui::muted("no run history"));
        }
        return Ok(0);
    }
    println!("{}", ui::header("heartbeat history", Some(&format!("last {}", runs.len()))));
    println!("{}", ui::section("runs"));
    for line in history_table_lines(&runs) {
        println!("{line}");
    }
    Ok(0)
}

/// The history table as printed lines: the column names, the rule under them,
/// then one line per run, each failed run followed by WHY it did not succeed.
///
/// A run that did not succeed carries WHY in the record (error, or the
/// skipped/refused reason in result_text): a table that shows only "skipped"
/// sent an operator to the DB to learn the tier was unlicensed (host8,
/// 2026-09-02). Rendered one run per table so the reason can follow its row as
/// an indented muted line (first line of text only).
///
/// `ui::table` returns TWO header lines (the names and a rule). This used to
/// take only the first, so the rule was paired with the first run: the LAST run
/// never printed (a single run printed no row at all, as `history --limit 1`
/// showed on 2026-10-10) and every reason sat under the wrong run.
fn history_table_lines(runs: &[&serde_json::Value]) -> Vec<String> {
    let cols = [
        Col::left(""),
        Col::left("run"),
        Col::left("task"),
        Col::left("action"),
        Col::left("status"),
        Col::right("ms"),
        Col::left("started"),
    ];
    let rows: Vec<Vec<String>> = runs
        .iter()
        .map(|r| {
            let status = r["status"].as_str().unwrap_or("?");
            let glyph = match status {
                "success" => Glyph::Ok,
                "running" => Glyph::Step,
                "skipped" => Glyph::Warn,
                _ => Glyph::Err,
            };
            let word = if status == "success" { "ok" } else { status };
            vec![
                ui::glyph_cell(glyph),
                ui::muted(&truncate(r["run_id"].as_str().unwrap_or("?"), 14)),
                truncate(r["task_name"].as_str().unwrap_or("?"), 26),
                truncate(r["action"].as_str().unwrap_or("?"), 22),
                ui::state(word),
                r["duration_ms"].as_u64().unwrap_or(0).to_string(),
                r["started_at"].as_str().unwrap_or("").chars().take(19).collect::<String>(),
            ]
        })
        .collect();
    let rendered = ui::table(&cols, &rows);
    let mut lines = rendered.lines();
    let mut out: Vec<String> = Vec::new();
    for _ in 0..2 {
        if let Some(head) = lines.next() {
            out.push(head.to_string());
        }
    }
    for (line, r) in lines.zip(runs.iter()) {
        out.push(line.to_string());
        let status = r["status"].as_str().unwrap_or("?");
        if status != "success" && status != "running" {
            if let Some(reason) = run_reason(r) {
                out.push(format!("      {}", ui::muted(&truncate(reason, 100))));
            }
        }
    }
    out
}

/// The human reason a run ended the way it did: `error` when set, else the
/// first line of `result_text`. `None` when the record carries neither.
fn run_reason(r: &serde_json::Value) -> Option<&str> {
    fn nonempty(v: &serde_json::Value) -> Option<&str> {
        v.as_str().map(str::trim).filter(|s| !s.is_empty())
    }
    nonempty(&r["error"])
        .or_else(|| nonempty(&r["result_text"]))
        .map(|s| s.lines().next().unwrap_or(s))
}

/// Derive the task id the gateway expects from the task name — matches the
/// gateway's `slugify_for_id` (routes/intelligence.rs) and the shape of live
/// ids (`weekly_research`, `graph_prune`): lowercase, ASCII alphanumerics
/// kept, every other run of characters collapses to one `_`, leading and
/// trailing separators trimmed.
fn derive_task_id(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_underscore = true; // skip leading separators
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    if out.ends_with('_') {
        out.pop();
    }
    out
}

/// `noo heartbeat add NAME SCHEDULE [--action A] [--prompt P] [--channel C]
/// [--recipient R]` — POST /api/heartbeat/tasks. Builds the Python CLI's
/// exact payload plus the `id` the Rust gateway requires (derived from the
/// name, see `derive_task_id`): config carries the prompt, channel/recipient
/// become single-element lists, enabled=true.
pub fn heartbeat_add(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positionals: Vec<String> = Vec::new();
    let mut action = "custom_prompt".to_string();
    let mut prompt: Option<String> = None;
    let mut channel: Option<String> = None;
    let mut recipient: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--action" => action = iter.next().ok_or(Unhandled)?.clone(),
            "--prompt" => prompt = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--channel" => channel = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--recipient" => recipient = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => positionals.push(t.to_string()),
        }
    }
    let [name, schedule] = positionals.as_slice() else { return Err(Unhandled) };
    let mut config = serde_json::Map::new();
    if let Some(p) = &prompt {
        config.insert("prompt".into(), p.as_str().into());
    }
    let id = derive_task_id(name);
    let payload = serde_json::json!({
        "id": id,
        "name": name,
        "schedule": schedule,
        "action": action,
        "config": config,
        "channels": channel.as_deref().map(|c| vec![c]).unwrap_or_default(),
        "recipients": recipient.as_deref().map(|r| vec![r]).unwrap_or_default(),
        "enabled": true,
    });
    let resp = post_json(g, "/api/heartbeat/tasks", &payload, true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    if proposed(&resp) {
        return Ok(0);
    }
    // The gateway echoes the id as `task_id` ({"ok": true, "task_id": ...}).
    // The id is the value a script captures: stdout, plain.
    let task_id = resp["task_id"].as_str().unwrap_or(&id);
    ui::done(&format!("task added: {name} ({task_id})"));
    ui::value(task_id);
    ui::guide(&[
        (&format!("noo heartbeat run {task_id}"), "fire it once now to check the action and its delivery"),
        ("noo heartbeat list", "see it in the schedule with its next run time"),
        (&format!("noo heartbeat toggle {task_id} --off"), "pause it without removing it"),
    ]);
    Ok(0)
}

/// `noo heartbeat remove TASK_ID [--yes/-y]` — DELETE /api/heartbeat/tasks/{id}.
/// Destructive (deletes a scheduled task): agent-first confirm contract
/// (--yes skips, --json requires --yes, non-TTY stdin errors).
pub fn heartbeat_remove(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut task_id: Option<String> = None;
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--yes" | "-y" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if task_id.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(id) = task_id else { return Err(Unhandled) };
    confirm_destructive(g, yes, "remove heartbeat task", &id);
    let resp = delete_json(g, &format!("/api/heartbeat/tasks/{id}"), true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format!("task {id} removed"));
    ui::guide(&[("noo heartbeat list", "the schedule without it")]);
    Ok(0)
}

/// `noo heartbeat toggle TASK_ID [--on|--off]` — PUT /api/heartbeat/tasks/{id}/toggle.
/// Without a flag the gateway flips the current state; --on/--off set it
/// explicitly ({"enabled": bool} body). Not in the Python CLI (dashboard/MCP
/// surface) — the Rust CLI is the terminal surface for it.
pub fn heartbeat_toggle(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut task_id: Option<String> = None;
    let mut enabled: Option<bool> = None;
    for tok in args {
        match tok.as_str() {
            "--on" => enabled = Some(true),
            "--off" => enabled = Some(false),
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if task_id.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(id) = task_id else { return Err(Unhandled) };
    let body = match enabled {
        Some(e) => serde_json::json!({ "enabled": e }),
        None => serde_json::json!({}),
    };
    let resp = put_json(g, &format!("/api/heartbeat/tasks/{id}/toggle"), &body, true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    if proposed(&resp) {
        return Ok(0);
    }
    let now_enabled = resp["enabled"].as_bool().unwrap_or(false);
    ui::done(&format!("task {id}: {}", if now_enabled { "enabled" } else { "disabled" }));
    if now_enabled {
        ui::guide(&[
            ("noo heartbeat list", "its next run time"),
            (&format!("noo heartbeat run {id}"), "fire it now"),
        ]);
    } else {
        ui::guide(&[(&format!("noo heartbeat toggle {id} --on"), "re-enable it")]);
    }
    Ok(0)
}

/// `noo heartbeat set-schedule TASK_ID "<cron>"` — PUT /api/heartbeat/tasks/{id}/schedule.
/// Changes ONLY the schedule. `heartbeat add` upserts the whole row, so using it to
/// move a schedule blanks the channels, recipients and config the caller did not repeat.
pub fn heartbeat_set_schedule(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (id, schedule) = parse_set_schedule_args(args)?;
    let body = serde_json::json!({ "schedule": schedule });
    let resp = put_json(g, &format!("/api/heartbeat/tasks/{id}/schedule"), &body, true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    if proposed(&resp) {
        return Ok(0);
    }
    let (headline, detail) = set_schedule_summary(&resp, &id, &schedule);
    ui::done(&headline);
    println!("{detail}");
    ui::guide(&[
        ("noo heartbeat list", "see it in the schedule with its next run time"),
        (&format!("noo heartbeat run {id}"), "fire it once now"),
    ]);
    Ok(0)
}

/// Exactly `<task-id> <cron>`: the cron is ONE argument (quoted), so a missing or extra
/// word is a usage error rather than a guess at which half was meant.
fn parse_set_schedule_args(args: &[String]) -> Result<(String, String), Unhandled> {
    match args {
        [id, schedule] if !id.starts_with('-') && !schedule.trim().is_empty() => {
            Ok((id.clone(), schedule.clone()))
        }
        _ => Err(Unhandled),
    }
}

/// The headline and the old/new/next-run lines for a successful change.
fn set_schedule_summary(resp: &serde_json::Value, id: &str, requested: &str) -> (String, String) {
    let old = resp["old_schedule"].as_str().unwrap_or("?");
    let new = resp["schedule"].as_str().unwrap_or(requested);
    let changed = resp["changed"].as_bool().unwrap_or(old != new);
    let next = match resp["next_run"].as_str() {
        Some(t) => t.chars().take(19).collect::<String>().replace('T', " "),
        None => "on the next tick (it fires once then, and follows the new schedule after)".to_string(),
    };
    let headline = if changed {
        format!("task {id}: schedule changed")
    } else {
        format!("task {id}: schedule already {new}")
    };
    (headline, format!("  old: {old}\n  new: {new}\n  next run: {next}"))
}

/// `noo heartbeat proposals [<id>]` — the scheduled tasks an agent asked for that destroy data, waiting
/// for a person. They live in the user-proposal queue (`GET /api/security/user-proposals`,
/// action `heartbeat_task`), so `noo security user proposals` lists them too.
///
/// An MCP door or agent run cannot create or change such a task: the gateway files a proposal
/// instead, and nothing changes until a person approves it (`noo heartbeat approve <id>`). With an
/// id this shows the whole proposal: every field of the task as asked for, and a diff against the
/// live task.
pub fn heartbeat_proposals(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let one: Option<i64> = match args {
        [] => None,
        [id] if !id.starts_with('-') => Some(id.parse().map_err(|_| Unhandled)?),
        _ => return Err(Unhandled),
    };
    if let Some(id) = one {
        let p = get_json(g, &format!("/api/security/user-proposals/{id}"), true, 15);
        if p["action"].as_str() != Some("heartbeat_task") {
            crate::output::fail(g.json, crate::output::ExitCode::Usage, "usage", &format!("proposal {id} is not a task proposal; `noo heartbeat proposals` lists them"), None);
        }
        if g.json {
            println!("{}", serde_json::json!({ "proposal": p, "diff": proposal_diff(g, &p) }));
        } else {
            show_proposal(g, &p);
        }
        return Ok(0);
    }
    let body = get_json(g, "/api/security/user-proposals", true, 15);
    let empty = Vec::new();
    let all = body["proposals"].as_array().unwrap_or(&empty);
    let tasks: Vec<&serde_json::Value> = all.iter().filter(|p| p["action"].as_str() == Some("heartbeat_task")).collect();
    if g.json {
        println!("{}", serde_json::json!({ "proposals": tasks, "count": tasks.len() }));
        return Ok(0);
    }
    if tasks.is_empty() {
        println!("{}", ui::muted("no task proposals"));
        return Ok(0);
    }
    println!("{}", ui::header("task proposals", Some(&format!("{} total", tasks.len()))));
    let any_pending = tasks.iter().any(|p| p["status"].as_str() == Some("pending"));
    print!("{}", proposals_table(&tasks, crate::commands::term_width()));
    if any_pending {
        ui::guide(&[
            ("noo heartbeat proposals <id>", "every field of one proposal, and what it changes in the live task"),
            ("noo heartbeat approve <id>", "creates or changes the task, authorised by you"),
            ("noo heartbeat reject <id>", "discards the proposal"),
        ]);
    }
    Ok(0)
}

/// Column caps for the proposals table at `width` columns. Headers are the floor (a header is never
/// cut); the free-text columns give way first, widest first, until the row fits.
fn proposal_caps(width: usize, id_w: usize) -> [usize; 5] {
    // task, action, schedule, why, proposed by
    let mins = [4usize, 6, 8, 3, 11];
    let mut caps = [22usize, 22, 14, 34, 34];
    // indent (2) + 6 gutters (2 each) + id + status ("approved" is the longest, 8)
    let budget = width.saturating_sub(2 + 12 + id_w.max(2) + 8);
    while caps.iter().sum::<usize>() > budget {
        let widest = (0..5).filter(|&i| caps[i] > mins[i]).max_by_key(|&i| caps[i]);
        match widest {
            Some(i) => caps[i] -= 1,
            None => break,
        }
    }
    caps
}

fn proposals_table(tasks: &[&serde_json::Value], width: usize) -> String {
    let id_w = tasks.iter().map(|p| p["id"].to_string().len()).max().unwrap_or(2);
    let caps = proposal_caps(width, id_w);
    let rows: Vec<Vec<String>> = tasks
        .iter()
        .map(|p| {
            let t = &p["payload"]["task"];
            vec![
                p["id"].to_string(),
                ui::state(p["status"].as_str().unwrap_or("?")),
                truncate(t["id"].as_str().unwrap_or("?"), caps[0]),
                truncate(t["action"].as_str().unwrap_or("?"), caps[1]),
                truncate(t["schedule"].as_str().unwrap_or("?"), caps[2]),
                truncate(p["payload"]["why"].as_str().unwrap_or(""), caps[3]),
                truncate(
                    &format!(
                        "{} via {}",
                        p["payload"]["proposed_by"]["account"].as_str().unwrap_or("?"),
                        p["payload"]["proposed_by"]["via"].as_str().unwrap_or("?")
                    ),
                    caps[4],
                ),
            ]
        })
        .collect();
    ui::table(
        &[Col::right("id"), Col::left("status"), Col::left("task"), Col::left("action"), Col::left("schedule"), Col::left("why"), Col::left("proposed by")],
        &rows,
    )
}

/// The fields a task proposal sets, compared with the live task (`None` when there is none).
const TASK_FIELDS: &[&str] = &["name", "schedule", "action", "enabled", "channels", "recipients"];

/// What approving would change: `[{field, old, new}]`. `config` is compared key by key. A task that
/// does not exist yet is all additions (`new: true` at the top).
pub(crate) fn diff_task(live: Option<&serde_json::Value>, proposed: &serde_json::Value) -> Vec<serde_json::Value> {
    let null = serde_json::Value::Null;
    let mut out = Vec::new();
    let live_get = |k: &str| live.map(|l| l[k].clone()).unwrap_or(null.clone());
    for f in TASK_FIELDS {
        let (o, n) = (live_get(f), proposed[*f].clone());
        if o != n {
            out.push(serde_json::json!({ "field": f, "old": o, "new": n }));
        }
    }
    let (oc, nc) = (live_get("config"), proposed["config"].clone());
    let keys: std::collections::BTreeSet<&String> = oc.as_object().into_iter().chain(nc.as_object()).flat_map(|m| m.keys()).collect();
    for k in keys {
        let (o, n) = (oc.get(k.as_str()).cloned().unwrap_or(null.clone()), nc.get(k.as_str()).cloned().unwrap_or(null.clone()));
        if o != n {
            out.push(serde_json::json!({ "field": format!("config.{k}"), "old": o, "new": n }));
        }
    }
    out
}

fn proposal_diff(g: &Globals, p: &serde_json::Value) -> serde_json::Value {
    let task = &p["payload"]["task"];
    let live_list = get_json(g, "/api/heartbeat/tasks", true, 15);
    let empty = Vec::new();
    let live = live_list["tasks"].as_array().unwrap_or(&empty).iter().find(|t| t["id"] == task["id"]);
    serde_json::json!({ "live_task_exists": live.is_some(), "changes": diff_task(live, task) })
}

/// Everything a person decides on: who asked and through what, why it needs a person, every field
/// of the task as asked for (the full config, not a summary), and what it changes.
fn show_proposal(g: &Globals, p: &serde_json::Value) {
    let task = &p["payload"]["task"];
    let pj = |v: &serde_json::Value| serde_json::to_string_pretty(v).unwrap_or_default();
    println!(
        "{}",
        ui::header(&format!("task proposal {}", p["id"]), Some(p["status"].as_str().unwrap_or("?")))
    );
    println!("  {}", ui::muted(&format!(
        "asked by {} via {}; this task {}",
        p["payload"]["proposed_by"]["account"].as_str().unwrap_or("?"),
        p["payload"]["proposed_by"]["via"].as_str().unwrap_or("?"),
        p["payload"]["why"].as_str().unwrap_or("?")
    )));
    println!("{}", ui::section("the task as asked for"));
    for f in ["id", "name", "schedule", "action", "enabled", "channels", "recipients"] {
        println!("  {f:<11} {}", task[f]);
    }
    println!("  config\n{}", pj(&task["config"]).lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
    let d = proposal_diff(g, p);
    println!("{}", ui::section(if d["live_task_exists"].as_bool().unwrap_or(false) { "changes to the live task" } else { "a new task: nothing exists yet" }));
    for c in d["changes"].as_array().unwrap_or(&Vec::new()) {
        println!("  {}", c["field"].as_str().unwrap_or("?"));
        println!("    - {}", c["old"]);
        println!("    + {}", c["new"]);
    }
}

/// `noo heartbeat approve ID` / `reject ID [--reason R]` — POST
/// /api/security/user-proposals/{id}/decide, for a task proposal only.
///
/// Approving is a person's decision: the gateway refuses it for an MCP door, an agent or delegated
/// credential, and for a person below the role the task needs (Admin for a scheduled
/// `entity_cleanup` apply). It creates or updates the task with you as `authorised_by`.
///
/// It shows the whole proposal first and needs a person AT A TERMINAL: stdin and stdout must be a
/// TTY, there is no `--yes`, and you type the task id to confirm. That stops a script, or an AI
/// running commands as you, from approving by accident; it does not stop a determined local process
/// that can drive a terminal.
pub fn heartbeat_approve(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    decide_task_proposal(g, args, true)
}

pub fn heartbeat_reject(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    decide_task_proposal(g, args, false)
}

fn decide_task_proposal(g: &Globals, args: &[String], approve: bool) -> Result<i32, Unhandled> {
    use std::io::{BufRead, IsTerminal, Write};
    let mut id: Option<i64> = None;
    let mut reason: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--reason" if !approve => reason = Some(iter.next().ok_or(Unhandled)?.clone()),
            t if !t.starts_with('-') && id.is_none() => id = Some(t.parse().map_err(|_| Unhandled)?),
            _ => return Err(Unhandled),
        }
    }
    let id = id.ok_or(Unhandled)?;
    let verb = if approve { "approve" } else { "reject" };
    if g.json || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        crate::output::fail(
            g.json,
            crate::output::ExitCode::Usage,
            "usage",
            &format!("`heartbeat {verb}` is a person's decision and needs an interactive terminal (no --json, no pipe, no --yes)"),
            Some(&format!("noo heartbeat proposals {id}")),
        );
    }
    // The decide route is the user-proposal queue's: say what is being decided, and refuse to
    // decide a user-management proposal from here.
    let found = &get_json(g, &format!("/api/security/user-proposals/{id}"), true, 15);
    if found["action"].as_str() != Some("heartbeat_task") {
        crate::output::fail(g.json, crate::output::ExitCode::Usage, "usage", &format!("proposal {id} is not a task proposal; `noo heartbeat proposals` lists them"), None);
    }
    show_proposal(g, found);
    let task_id = found["payload"]["task"]["id"].as_str().unwrap_or("").to_string();
    print!("\nType the task id ({task_id}) to {verb} proposal {id}: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    if line.trim() != task_id || task_id.is_empty() {
        ui::failed("not confirmed; nothing was decided", None);
        return Ok(1);
    }
    let body = post_json(
        g,
        &format!("/api/security/user-proposals/{id}/decide"),
        &serde_json::json!({ "approve": approve, "reason": reason }),
        true,
        30,
    );
    if !approve {
        ui::done(&format!("proposal {id} rejected; nothing was created or changed"));
        return Ok(0);
    }
    let task = body["result"]["task_id"].as_str().unwrap_or("?");
    ui::done(&format!(
        "proposal {id} approved: task {task} {} (authorised by you)",
        body["result"]["task"].as_str().unwrap_or("written")
    ));
    ui::guide(&[("noo heartbeat list", "the schedule, and who authorised each destructive task")]);
    Ok(0)
}

/// `noo heartbeat review-existing` — after an upgrade, the tasks and saved recipients that predate the
/// guard run read-only (and their targets are unregistered) until a person looks at them once.
///
/// Interactive only, like `approve`: stdin and stdout must be a terminal, no `--yes`, no `--json`.
/// Every waiting task is shown with its full config, then every saved recipient; you answer `y`, `n`,
/// `a` (all the remaining ones: you then type APPROVE ALL) or `q`. Approving records you as the person
/// who authorised the task or created the recipient.
pub fn heartbeat_review_existing(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    use std::io::{BufRead, IsTerminal, Write};
    if !args.is_empty() {
        return Err(Unhandled);
    }
    if g.json || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        crate::output::fail(
            g.json,
            crate::output::ExitCode::Usage,
            "usage",
            "`heartbeat review-existing` is a person's decision and needs an interactive terminal (no --json, no pipe, no --yes)",
            Some("noo heartbeat list"),
        );
    }
    let body = get_json(g, "/api/heartbeat/review-existing", true, 20);
    let empty = Vec::new();
    let tasks = body["tasks"].as_array().unwrap_or(&empty);
    let recipients = body["recipients"].as_array().unwrap_or(&empty);
    if tasks.is_empty() && recipients.is_empty() {
        ui::done("nothing is waiting for review");
        return Ok(0);
    }
    println!("{}", ui::header("review existing", Some(&format!("{} task(s), {} recipient(s)", tasks.len(), recipients.len()))));
    println!("  {}", ui::muted("Until you approve them, these tasks run with read-only tools and their targets are not registered."));
    let pj = |v: &serde_json::Value| serde_json::to_string_pretty(v).unwrap_or_default();
    let ask = |prompt: &str| -> String {
        print!("{prompt}");
        let _ = std::io::stdout().flush();
        let mut l = String::new();
        let _ = std::io::stdin().lock().read_line(&mut l);
        l.trim().to_lowercase()
    };
    let mut approve_tasks: Vec<String> = Vec::new();
    let mut approve_recipients: Vec<String> = Vec::new();
    let total = tasks.len() + recipients.len();
    let mut all_rest = false;
    'items: for (n, item) in tasks.iter().map(|t| (t, true)).chain(recipients.iter().map(|r| (r, false))).enumerate() {
        let (v, is_task) = item;
        let id = v["id"].as_str().unwrap_or("").to_string();
        if is_task {
            println!("\n{}", ui::section(&format!("task {}/{}: {}", n + 1, total, id)));
            for f in ["name", "schedule", "action", "enabled", "channels", "recipients"] {
                println!("  {f:<11} {}", v[f]);
            }
            if v["destructive"].as_bool().unwrap_or(false) {
                println!("  {}", ui::warn(&format!("this task {}", v["destructive_why"].as_str().unwrap_or("deletes data"))));
            }
            println!("  config\n{}", pj(&v["config"]).lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
        } else {
            println!("\n{}", ui::section(&format!("saved recipient {}/{}", n + 1, total)));
            for f in ["channel", "recipient_id", "display_name", "notes"] {
                println!("  {f:<13} {}", v[f]);
            }
        }
        let answer = if all_rest { "y".to_string() } else { ask("Approve it? [y]es / [n]o / [a]ll the remaining / [q]uit: ") };
        match answer.as_str() {
            "y" | "yes" => {}
            "a" | "all" => {
                let left = total - n;
                if ask(&format!("Type APPROVE ALL to approve this and the {} after it unseen: ", left - 1)) == "approve all" {
                    all_rest = true;
                } else {
                    println!("  {}", ui::muted("not confirmed; skipped"));
                    continue 'items;
                }
            }
            "q" | "quit" => break 'items,
            _ => continue 'items,
        }
        if is_task { approve_tasks.push(id) } else { approve_recipients.push(id) }
    }
    if approve_tasks.is_empty() && approve_recipients.is_empty() {
        ui::done("nothing approved");
        return Ok(0);
    }
    let resp = post_json(
        g,
        "/api/heartbeat/review-existing/approve",
        &serde_json::json!({ "tasks": approve_tasks, "recipients": approve_recipients }),
        true,
        30,
    );
    ui::done(&format!(
        "approved {} task(s) and {} recipient(s), recorded as you",
        resp["tasks_approved"], resp["recipients_approved"]
    ));
    for s in resp["skipped"].as_array().unwrap_or(&empty) {
        println!("  {}", ui::muted(&format!("skipped: {s}")));
    }
    ui::guide(&[("noo heartbeat list", "what is still waiting")]);
    Ok(0)
}

/// `noo heartbeat export [--output FILE]` — GET /api/heartbeat/tasks, strip
/// the runtime timestamps (`last_run`/`next_run` — the gateway's upsert
/// recomputes `next_run` on import anyway), emit `{"tasks":[...]}`. The
/// portable half of a controller migration: export on the old box, import on
/// the new one — no psql against the noo_heartbeat_tasks table.
pub fn heartbeat_export(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut output: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--output" | "-o" => output = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let body = get_json(g, "/api/heartbeat/tasks", true, 10);
    let empty = Vec::new();
    let tasks: Vec<serde_json::Value> = body["tasks"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|t| {
            let mut t = t.clone();
            if let Some(m) = t.as_object_mut() {
                m.remove("last_run");
                m.remove("next_run");
            }
            t
        })
        .collect();
    let count = tasks.len();
    let doc = serde_json::json!({ "tasks": tasks });
    let text = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| doc.to_string());
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, text + "\n") {
                ui::failed(&format!("could not write {path}: {e}"), None);
                return Ok(1);
            }
            ui::done(&format!("exported {count} task(s) to {path}"));
            ui::value(&path);
            ui::guide(&[(&format!("noo heartbeat import {path}"), "restore these tasks on another controller")]);
        }
        None => ui::value(&text),
    }
    Ok(0)
}

/// `noo heartbeat import FILE` — POST each task from an export file
/// (`{"tasks":[...]}` or a bare array) to /api/heartbeat/tasks (the gateway
/// upserts by id), then POST /api/heartbeat/reload once so the scheduler
/// re-seats without a restart.
pub fn heartbeat_import(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [file] = args else { return Err(Unhandled) };
    if file.starts_with('-') {
        return Err(Unhandled);
    }
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            ui::failed(&format!("could not read {file}: {e}"), None);
            return Ok(1);
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            ui::failed(
                &format!("{file} is not valid JSON: {e}"),
                Some("noo heartbeat export --output <file>  (the expected shape: {\"tasks\": [...]})"),
            );
            return Ok(1);
        }
    };
    let tasks = match doc["tasks"].as_array().or_else(|| doc.as_array()) {
        Some(t) if !t.is_empty() => t.clone(),
        _ => {
            ui::failed(&format!("no tasks found in {file}"), None);
            return Ok(1);
        }
    };
    if !g.json {
        ui::step(&format!("importing {} task(s) from {file}", tasks.len()));
        println!("{}", ui::note("last_run/next_run are dropped; the scheduler recomputes them from each cron"));
    }
    let mut ok = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut proposals: Vec<String> = Vec::new();
    for t in &tasks {
        let label = t["id"]
            .as_str()
            .or_else(|| t["name"].as_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let mut payload = t.clone();
        if let Some(m) = payload.as_object_mut() {
            m.remove("last_run");
            m.remove("next_run");
        }
        match crate::http::post_json_try(g, "/api/heartbeat/tasks", &payload, true, 10) {
            Ok(resp) if resp["proposal"].as_bool() == Some(true) => proposals.push(label.clone()),
            Ok(resp) if resp["ok"].as_bool().unwrap_or(false) => ok += 1,
            Ok(resp) => failed.push(format!("{label}: {resp}")),
            Err(e) => failed.push(format!("{label}: {e}")),
        }
    }
    // One reload after the batch — the scheduler picks up all rows at once.
    let _ = crate::http::post_json_try(g, "/api/heartbeat/reload", &serde_json::json!({}), true, 10);
    // Actions the gateway delegates to the trellion-intel worker fail on
    // every run while that add-on is off (host8 2026-09-02: four of 18
    // imported tasks, every 20 minutes, and nothing said why at import).
    // Say it here, once, with the fix.
    if let Ok(health) = crate::http::get_json_try(g, "/health", true, 5) {
        let intel_on = health["addons"]["trellion_intel"].as_str() == Some("enabled");
        if !intel_on {
            let gated: Vec<String> = tasks
                .iter()
                .filter(|t| {
                    t["action"].as_str().is_some_and(requires_trellion_intel)
                        && t["enabled"].as_bool().unwrap_or(true)
                })
                .filter_map(|t| t["id"].as_str().or(t["name"].as_str()).map(str::to_string))
                .collect();
            if !gated.is_empty() && !g.json {
                ui::warned(&format!(
                    "{} imported task(s) use actions that need the trellion-intel add-on, which is off here — they will error every run",
                    gated.len()
                ));
                for id in &gated {
                    println!("  {}", ui::muted(id));
                }
                ui::guide(&[
                    ("noo onboard --only services", "enable the Intelligent tier so these actions can run"),
                    ("noo heartbeat toggle <id> --off", "or pause each gated task until the add-on is on"),
                ]);
            }
        }
    }
    if g.json {
        println!(
            "{}",
            serde_json::json!({ "imported": ok, "failed": failed.len(), "errors": failed, "proposals": proposals })
        );
    } else if failed.is_empty() {
        ui::close_done(&format!("imported {ok}/{} task(s)", tasks.len()));
        if !proposals.is_empty() {
            // Tasks that delete data, imported without a person's own credential: not created.
            ui::warned(&format!(
                "{} task(s) delete data and were filed as proposals, not created: {}",
                proposals.len(),
                proposals.join(", ")
            ));
            ui::guide(&[("noo heartbeat proposals", "approve them as a person")]);
        }
        ui::guide(&[
            ("noo heartbeat list", "the imported tasks with their next run"),
            ("noo heartbeat run <id>", "fire one now instead of waiting for its schedule"),
        ]);
    } else {
        ui::close_failed(&format!("imported {ok}/{} task(s)", tasks.len()), None);
        for f in &failed {
            eprintln!("  {}", ui::muted(f));
        }
        ui::guide(&[
            ("noo heartbeat list", "what did land"),
            (&format!("noo heartbeat import {file}"), "re-run after fixing the failed entries; existing ids are updated in place"),
        ]);
    }
    Ok(if failed.is_empty() { 0 } else { 1 })
}

/// Mirror of the gateway's dispatch rule (heartbeat_actions.rs
/// `action_path`): anything not Rust-native and not Rust-LLM is delegated
/// to the trellion worker and, for the Intelligent-tier actions, refused
/// while NOO_TRELLION_INTEL_ENABLED is off. Pinned to the gateway lists by
/// tests/test_heartbeat_cli_addon_parity.py.
pub(crate) const RUST_NATIVE_ACTIONS: &[&str] = &[
    "cluster_health", "cost_report", "security_audit", "memory_cleanup", "idle_scaledown",
    "agent_self_check", "disk_cleanup", "write_log", "database_backup", "cert_rotation_check",
    "cert_auto_rotate", "heartbeat_retention", "agent_messages_retention", "usage_rollup", "backup_knowledge", "graph_prune", "entity_cleanup",
    "channel_keepalive", "model_cache_warm", "rag_reindex", "self_benchmark",
];
pub(crate) const RUST_LLM_ACTIONS: &[&str] = &[
    "research_report", "research_and_send", "custom_prompt", "daily_briefing", "chat_digest",
    "conversation_summarize", "news_scan", "channel_message", "goal_review",
];
pub(crate) fn requires_trellion_intel(action: &str) -> bool {
    !RUST_NATIVE_ACTIONS.contains(&action) && !RUST_LLM_ACTIONS.contains(&action)
}

#[cfg(test)]
mod tests {
    use super::{derive_task_id, diff_task, history_table_lines, parse_history_args, parse_set_schedule_args, run_outcome, set_schedule_summary};
    use serde_json::json;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn set_schedule_takes_exactly_a_task_id_and_one_cron_argument() {
        assert_eq!(
            parse_set_schedule_args(&args(&["database_backup", "30 3 * * *"])).ok(),
            Some(("database_backup".to_string(), "30 3 * * *".to_string()))
        );
        for bad in [
            &[][..],
            &["database_backup"],
            &["database_backup", "   "],
            &["database_backup", "30", "3", "*", "*", "*"],
            &["database_backup", "30 3 * * *", "extra"],
            &["--on", "30 3 * * *"],
        ] {
            assert!(parse_set_schedule_args(&args(bad)).is_err(), "{bad:?} must be a usage error");
        }
    }

    #[test]
    fn set_schedule_prints_old_new_and_the_next_run() {
        let moved = json!({"ok": true, "old_schedule": "30 7 * * 0", "schedule": "30 3 * * *", "changed": true, "next_run": null});
        let (head, detail) = set_schedule_summary(&moved, "database_backup", "30 3 * * *");
        assert_eq!(head, "task database_backup: schedule changed");
        assert!(detail.contains("old: 30 7 * * 0") && detail.contains("new: 30 3 * * *"), "{detail}");
        assert!(detail.contains("next run: on the next tick"), "{detail}");
        let kept = json!({"ok": true, "old_schedule": "30 3 * * *", "schedule": "30 3 * * *", "changed": false, "next_run": "2026-10-11T03:30:00+00:00"});
        let (head, detail) = set_schedule_summary(&kept, "database_backup", "30 3 * * *");
        assert_eq!(head, "task database_backup: schedule already 30 3 * * *");
        assert!(detail.contains("next run: 2026-10-11 03:30:00"), "{detail}");
    }

    #[test]
    fn the_proposals_table_prints_every_header_in_full_at_80_columns() {
        let p = json!({"id": 12, "status": "pending", "payload": {
            "task": {"id": "weekly-entity-cleanup-sweep", "action": "entity_cleanup", "schedule": "30 7 * * 0"},
            "why": "the graph has grown stale and an agent wants it pruned every week",
            "proposed_by": {"account": "someone@example.com", "via": "mcp-operator"}}});
        for width in [80usize, 100, 160] {
            let out = super::proposals_table(&[&p], width);
            let header = out.lines().next().unwrap();
            for h in ["ID", "STATUS", "TASK", "ACTION", "SCHEDULE", "WHY", "PROPOSED BY"] {
                assert!(header.contains(h), "{h} missing at {width}: {header:?}");
            }
            assert!(!header.contains("IT"), "{header:?}");
            for line in out.lines() {
                assert!(crate::ui::visible_width(line) <= width, "{line:?} wider than {width}");
            }
        }
    }

    #[test]
    fn a_proposal_diff_names_every_changed_field_and_config_key() {
        let live = json!({"name": "c", "schedule": "30 7 * * 0", "action": "entity_cleanup", "enabled": true,
                          "channels": [], "recipients": [], "config": {"apply": true, "max_delete": 100}});
        let mut new = live.clone();
        new["config"]["max_delete"] = json!(5000);
        new["config"]["examples"] = json!(50);
        new["schedule"] = json!("* * * * *");
        let d = diff_task(Some(&live), &new);
        let fields: Vec<&str> = d.iter().map(|c| c["field"].as_str().unwrap()).collect();
        assert_eq!(fields, ["schedule", "config.examples", "config.max_delete"]);
        assert_eq!(d[2]["old"], 100);
        assert_eq!(d[2]["new"], 5000);
        assert!(diff_task(Some(&live), &live).is_empty());
        assert!(!diff_task(None, &new).is_empty(), "a new task is all additions");
    }

    /// Live task ids are snake_case slugs of the name (`weekly_research`,
    /// `graph_prune`); the derivation must reproduce that shape — and match
    /// the gateway's `slugify_for_id` so a re-`add` with the same name
    /// updates the same row instead of creating a near-duplicate.
    #[test]
    fn derive_task_id_matches_the_live_id_shape() {
        assert_eq!(derive_task_id("Weekly Research"), "weekly_research");
        assert_eq!(derive_task_id("graph_prune"), "graph_prune");
        // Runs of separators collapse; leading/trailing are trimmed.
        assert_eq!(derive_task_id("  Daily -- Briefing! "), "daily_briefing");
        assert_eq!(derive_task_id("AI/ML news, 8am"), "ai_ml_news_8am");
        // Nothing usable in the name → empty (the gateway rejects it).
        assert_eq!(derive_task_id("---"), "");
    }

    // ---- run_outcome ---------------------------------------------------

    #[test]
    fn history_prints_every_run_and_each_reason_under_its_own_run() {
        // `history --limit 1` printed the header and a rule and no row; with
        // several runs the last was dropped and reasons sat under the wrong run.
        let ok = json!({"run_id": "aaaa1111", "task_name": "T", "action": "a", "status": "success",
            "duration_ms": 5, "started_at": "2026-10-10T10:00:00Z"});
        let bad = json!({"run_id": "bbbb2222", "task_name": "T", "action": "a", "status": "error",
            "error": "backup exploded", "duration_ms": 9, "started_at": "2026-10-10T09:00:00Z"});
        let run = json!({"run_id": "cccc3333", "task_name": "T", "action": "a", "status": "running",
            "duration_ms": 0, "started_at": "2026-10-10T08:00:00Z"});

        // One run: its row must be there.
        let one = history_table_lines(&[&run]);
        assert!(one.iter().any(|l| l.contains("cccc3333")), "a lone run printed no row: {one:?}");

        // Several: every run once, the reason on the line right after ITS run.
        let all = history_table_lines(&[&ok, &bad, &run]);
        for id in ["aaaa1111", "bbbb2222", "cccc3333"] {
            assert_eq!(all.iter().filter(|l| l.contains(id)).count(), 1, "{id} in {all:?}");
        }
        let at = all.iter().position(|l| l.contains("bbbb2222")).unwrap();
        assert!(all[at + 1].contains("backup exploded"), "the reason is not under its run: {all:?}");
        assert!(!all[all.iter().position(|l| l.contains("aaaa1111")).unwrap() + 1].contains("backup exploded"));
    }

    #[test]
    fn run_outcome_running_is_in_progress_not_a_warning() {
        // A queued database backup comes back `running`; it is not a failure.
        let resp = json!({"status": "running", "run_id": "0123456789abcdef",
            "message": "Database backup queued; awaiting host result file"});
        let o = run_outcome(&resp, "database_backup");
        assert_eq!(o.headline, "task database_backup: running — run 01234567");
        assert!(!o.is_warning, "a backup in progress was printed as a warning");
        assert!(o.guide.iter().any(|(c, _)| c == "noo heartbeat history database_backup --run 01234567"), "{:?}", o.guide);
    }

    #[test]
    fn run_outcome_queued_with_run_id() {
        let resp = json!({
            "status": "queued",
            "run_id": "abcdef1234567890",
            "dispatched_at": "2026-09-29T00:00:00Z",
            "poll": "/api/heartbeat/history?task_id=weekly_research",
            "message": "Running in the gateway. LLM actions take minutes.",
        });
        let o = run_outcome(&resp, "weekly_research");
        assert_eq!(o.headline, "task weekly_research: queued — run abcdef12");
        assert!(!o.is_warning);
        assert!(!o.headline.contains("ms"));
        assert_eq!(o.detail_lines, vec!["Running in the gateway. LLM actions take minutes.".to_string()]);
        assert!(!o.verbatim);
        assert!(o.guide.iter().any(|(c, _)| c == "noo heartbeat history weekly_research --run abcdef12"));
        assert!(o.guide.iter().any(|(c, _)| c == "noo heartbeat history weekly_research"));
    }

    #[test]
    fn run_outcome_queued_without_run_id_omits_run_hint() {
        // Older gateway: queued but no run_id in the body.
        let resp = json!({"status": "queued"});
        let o = run_outcome(&resp, "weekly_research");
        assert_eq!(o.headline, "task weekly_research: queued");
        assert!(!o.is_warning);
        assert!(o.guide.iter().all(|(c, _)| !c.contains("--run")));
    }

    #[test]
    fn run_outcome_success_has_real_duration_and_verbatim_result() {
        let resp = json!({"status": "success", "duration_ms": 42, "result_text": "did the thing"});
        let o = run_outcome(&resp, "weekly_research");
        assert_eq!(o.headline, "task weekly_research: success (42ms)");
        assert!(!o.is_warning);
        assert_eq!(o.detail_lines, vec!["did the thing".to_string()]);
        assert!(o.verbatim);
        assert!(o.guide.iter().any(|(c, _)| c == "noo heartbeat history weekly_research"));
        assert!(o.guide.iter().any(|(c, _)| c == "noo heartbeat list"));
    }

    #[test]
    fn run_outcome_failed_is_a_warning_with_reason() {
        let resp = json!({"status": "failed", "duration_ms": 10, "error": "boom"});
        let o = run_outcome(&resp, "weekly_research");
        assert_eq!(o.headline, "task weekly_research: failed (10ms)");
        assert!(o.is_warning);
        assert_eq!(o.detail_lines, vec!["boom".to_string()]);
        assert!(!o.verbatim);
        assert!(o.guide.iter().any(|(c, _)| c == "noo heartbeat history weekly_research"));
        assert!(o.guide.iter().any(|(c, _)| c == "noo logs errors"));
    }

    #[test]
    fn run_outcome_no_status_says_so_and_guides_only_to_history() {
        let resp = json!({"message": "gateway hiccup"});
        let o = run_outcome(&resp, "weekly_research");
        assert_eq!(o.headline, "the gateway returned no run status");
        assert!(o.is_warning);
        assert_eq!(o.detail_lines, vec!["gateway hiccup".to_string()]);
        assert_eq!(o.guide.len(), 1);
        assert_eq!(o.guide[0].0, "noo heartbeat history weekly_research");
    }

    /// Every command `run_outcome` puts in a guide must be accepted by the
    /// CLI's own parser: `noo heartbeat history ...` re-parses with
    /// `parse_history_args`, `noo heartbeat list` takes no arguments (see
    /// `heartbeat_list`), and `noo logs errors` is a real usage.rs row that
    /// this module does not own (checked there, not re-parsed here).
    #[test]
    fn every_guide_command_parses() {
        let cases = [
            json!({"status": "queued", "run_id": "abcdef1234567890"}),
            json!({"status": "queued"}),
            json!({"status": "success", "duration_ms": 1, "result_text": "ok"}),
            json!({"status": "failed", "duration_ms": 1, "error": "x"}),
            json!({}),
        ];
        for resp in &cases {
            let o = run_outcome(resp, "weekly_research");
            for (cmd, _why) in &o.guide {
                if let Some(rest) = cmd.strip_prefix("noo heartbeat history ") {
                    let args: Vec<String> = rest.split_whitespace().map(str::to_string).collect();
                    assert!(parse_history_args(&args).is_ok(), "guide command failed to parse: {cmd}");
                } else if cmd == "noo heartbeat list" {
                    // heartbeat_list only accepts zero arguments.
                } else if cmd == "noo logs errors" {
                    // Not owned by this module; existence checked in usage.rs.
                } else {
                    panic!("unexpected guide command not covered by this test: {cmd}");
                }
            }
        }
    }

    // ---- parse_history_args ---------------------------------------------

    #[test]
    fn history_args_positional_task_id() {
        let a = parse_history_args(&["weekly_research".to_string()]).unwrap();
        assert_eq!(a.task_id, Some("weekly_research".to_string()));
        assert_eq!(a.limit, 20);
        assert_eq!(a.run_prefix, None);
    }

    #[test]
    fn history_args_flag_task_id() {
        let a = parse_history_args(&["--task-id".to_string(), "weekly_research".to_string()]).unwrap();
        assert_eq!(a.task_id, Some("weekly_research".to_string()));
    }

    #[test]
    fn history_args_positional_and_flag_same_value_ok() {
        let a = parse_history_args(&[
            "weekly_research".to_string(),
            "--task-id".to_string(),
            "weekly_research".to_string(),
        ])
        .unwrap();
        assert_eq!(a.task_id, Some("weekly_research".to_string()));
    }

    #[test]
    fn history_args_positional_and_flag_different_value_errors() {
        let r = parse_history_args(&[
            "weekly_research".to_string(),
            "--task-id".to_string(),
            "graph_prune".to_string(),
        ]);
        assert!(r.is_err());
    }

    #[test]
    fn history_args_run_prefix() {
        let a = parse_history_args(&["--run".to_string(), "abcdef12".to_string()]).unwrap();
        assert_eq!(a.run_prefix, Some("abcdef12".to_string()));
    }

    #[test]
    fn history_args_run_prefix_too_short_errors() {
        let r = parse_history_args(&["--run".to_string(), "abc".to_string()]);
        assert!(r.is_err());
    }

    #[test]
    fn history_args_limit() {
        let a = parse_history_args(&["--limit".to_string(), "5".to_string()]).unwrap();
        assert_eq!(a.limit, 5);
        let a = parse_history_args(&["-n".to_string(), "7".to_string()]).unwrap();
        assert_eq!(a.limit, 7);
    }

    #[test]
    fn history_args_unknown_flag_errors() {
        let r = parse_history_args(&["--bogus".to_string()]);
        assert!(r.is_err());
    }
}
