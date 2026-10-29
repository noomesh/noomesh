// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo jobs …` — distributed job queue + scheduler control.
//!
//! WP-A1 port of `jobs_cli.py`: run (submit + poll), status (`--wait`),
//! submit, history, cancel, reprioritize, scheduler, pause, resume, drain,
//! undrain — all thin HTTP calls to the gateway. Poll semantics match the
//! Python `_poll_job`: transient HTTP status errors are swallowed and the
//! poll continues; transport failures exit 3.
//!
//! Note on `--timeout`: the global parser consumes `--timeout <secs>`
//! before handlers run, so `jobs run/status/submit --timeout N` arrives via
//! `Globals::timeout_secs` — the handlers use it for the job/poll timeout
//! exactly like the Python flag (default 300). `jobs run -t N` is the same
//! flag and is parsed locally.

use super::confirm_destructive;
use crate::args::{ArgError, Args};
use crate::http::{delete_json, get_json, get_json_poll, post_json, request_status};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};
use std::time::{Duration, Instant};

/// POST a job submission, rendering the gateway's rejection readably.
///
/// The gateway rejects a job type no executor can run with 400 + a message
/// that names the valid types (`gateway-rust/src/job_types.rs`). Through
/// plain `post_json` that arrives as the raw JSON body glued onto "gateway
/// returned 400 for …", which buries the one sentence the user needs. Exit
/// code stays 5 (`remote_error`) — the documented status→exit mapping,
/// which agents branch on, is unchanged.
fn submit_or_fail(g: &Globals, path: &str, body: &serde_json::Value) -> serde_json::Value {
    match request_status(g, "POST", path, Some(body), true, 10) {
        Ok(v) => v,
        Err((status, text)) => {
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| {
                    v["error"]
                        .as_str()
                        .or_else(|| v["detail"].as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| format!("gateway returned {status} for {path}: {text}"));
            fail(g.json, ExitCode::RemoteError, "remote_error", &msg, None)
        }
    }
}

/// `noo jobs list [--limit N] [--status S] [--node ID]`
/// GET /api/jobs — same flags as the Python jobs_cli command.
/// `--watch [SECS]` (default 2): redraw on a TTY until Ctrl-C. Rejected
/// under `--json`/`--quiet` and off a terminal, where it makes no sense.
pub fn jobs_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok((rest, watch)) = crate::ui::take_watch(args) else { return Err(Unhandled) };
    let Some(secs) = watch else { return jobs_list_once(g, &rest) };
    if g.json || g.quiet || !crate::ui::styled() {
        crate::output::fail(g.json, crate::output::ExitCode::Usage, "usage",
            "--watch needs an interactive terminal (not --json/--quiet or a pipe)", None);
    }
    Ok(crate::ui::watch_loop(secs, || jobs_list_once(g, &rest).unwrap_or(2)))
}

pub(crate) fn parse_list_with(a: &mut Args) -> Result<(u64, Option<String>, Option<String>), ArgError> {
    let limit = a.number::<u64>(&["--limit", "-n"])?.unwrap_or(20);
    let status = a.value(&["--status", "-s"])?;
    let node = a.value(&["--node"])?;
    a.finish()?;
    Ok((limit, status, node))
}

fn jobs_list_once(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (limit, status, node) = parse_list_with(&mut Args::new(args))?;
    let mut path = format!("/api/jobs?limit={limit}");
    if let Some(s) = &status {
        path.push_str(&format!("&status={s}"));
    }
    if let Some(n) = &node {
        path.push_str(&format!("&node_id={n}"));
    }

    let body = get_json(g, &path, true, 10);
    if g.json {
        println!("{body}");
        return Ok(super::json_exit(&body));
    }
    // The queue route answers HTTP 200 with {"jobs":[],"count":0,"error":…}
    // when Redis is unreachable. This used to print "no jobs found" — an
    // operator reading that concluded the queue was drained when in fact the
    // CLI had no idea what the queue held. Check `error` before `is_empty`.
    if let Some(err) = body["error"].as_str() {
        ui::failed(&format!("cannot read job queue: {err}"), None);
        return Ok(crate::output::ExitCode::RemoteError as i32);
    }
    let empty = Vec::new();
    let jobs = body["jobs"].as_array().unwrap_or(&empty);
    if jobs.is_empty() {
        println!("{}", ui::muted("no jobs"));
        ui::guide(&[
            ("noo jobs submit --type <type>", "queue a job for the scheduler"),
            ("noo jobs history", "what ran before"),
        ]);
        return Ok(0);
    }
    println!("{}", ui::header("jobs", Some(&format!("{} queued or running", jobs.len()))));
    println!("{}", ui::section("queue"));
    let rows: Vec<Vec<String>> = jobs
        .iter()
        .map(|j| {
            let id = j["id"].as_str().unwrap_or("?");
            let node = j["node_id"].as_str().filter(|s| !s.is_empty()).unwrap_or("");
            let created = j["created_at"].as_str().unwrap_or("");
            let status = j["status"].as_str().unwrap_or("?");
            vec![
                ui::glyph_cell(job_glyph(status)),
                ui::muted(&id[..id.len().min(12)]),
                j["type"].as_str().unwrap_or("?").to_string(),
                ui::state(status),
                j["priority"].as_str().unwrap_or("?").to_string(),
                node[..node.len().min(12)].to_string(),
                created[..created.len().min(19)].to_string(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("id"),
                Col::left("type"),
                Col::left("status"),
                Col::right("pri"),
                Col::left("node"),
                Col::left("created"),
            ],
            &rows,
        )
    );
    ui::guide(&[
        ("noo jobs status <id> --wait", "block until one job finishes and print its record"),
        ("noo jobs cancel <id>", "drop a queued or running job"),
        ("noo jobs history", "finished jobs"),
    ]);
    Ok(0)
}

/// Status glyph for a job/scheduler state word.
fn job_glyph(status: &str) -> Glyph {
    match status {
        "completed" | "running" => Glyph::Ok,
        "failed" | "dead" | "cancelled" => Glyph::Err,
        "queued" | "pending" => Glyph::Bullet,
        _ => Glyph::Warn,
    }
}

/// Terminal job states (parity with `jobs_cli.py` `_TERMINAL_STATES`).
const TERMINAL_STATES: &[&str] = &["completed", "failed", "dead", "cancelled"];

/// Poll GET /api/jobs/{id} every 2s until the job reaches a terminal state.
/// Returns the final record, or `None` if `timeout` seconds elapsed first.
/// Non-2xx responses are swallowed and polling continues (Python parity);
/// transport failures exit 3 inside `get_json_poll`.
pub(crate) fn poll_job(g: &Globals, job_id: &str, timeout: u64) -> Option<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(timeout);
    loop {
        if let Some(job) = get_json_poll(g, &format!("/api/jobs/{job_id}"), true, 10) {
            if TERMINAL_STATES.contains(&job["status"].as_str().unwrap_or("")) {
                return Some(job);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Print a terminal-state job record; exit code 0 only if it completed
/// (parity with `_report_terminal_job`: non-completed → exit 1).
pub(crate) fn report_terminal_job(g: &Globals, job: &serde_json::Value) -> i32 {
    let status = job["status"].as_str().unwrap_or("?");
    if g.json {
        println!("{job}");
    } else if status == "completed" {
        ui::done("job completed");
        // The result is the captured value: stdout, verbatim, kept by --quiet.
        match &job["result"] {
            serde_json::Value::Null => {}
            serde_json::Value::String(s) if s.is_empty() => {}
            serde_json::Value::String(s) => ui::value(s),
            other => ui::value(&other.to_string()),
        }
    } else if status == "cancelled" {
        ui::warned("job cancelled");
    } else {
        ui::failed(
            &format!("job {status}: {}", job["error"].as_str().unwrap_or("unknown")),
            None,
        );
    }
    if status == "completed" {
        0
    } else {
        1
    }
}

/// Shared "timed out waiting" report (run + status --wait), exit 1.
pub(crate) fn report_poll_timeout(g: &Globals, job_id: &str, timeout: u64) -> i32 {
    if g.json {
        eprintln!(
            "{}",
            serde_json::json!({
                "error": format!("timed out after {timeout}s waiting for job {job_id}"),
                "code": "poll_timeout",
                "hint": format!("job is still running; check with: noo jobs status {job_id}"),
            })
        );
    } else {
        ui::failed(
            &format!("timed out after {timeout}s waiting for job {job_id} (it is still running)"),
            Some(&format!("noo jobs status {job_id}")),
        );
    }
    1
}

pub(crate) struct RunArgs {
    pub prompt: String,
    pub async_mode: bool,
    pub priority: i64,
    pub backend: Option<String>,
    pub node: Option<String>,
    pub timeout: u64,
    pub job_type: String,
}

/// `default_timeout` is the global `--timeout` (or 300); `-t` overrides it.
pub(crate) fn parse_run_with(a: &mut Args, default_timeout: u64) -> Result<RunArgs, ArgError> {
    let async_mode = a.flag(&["--async", "-a"]);
    let priority = a.number::<i64>(&["--priority", "-p"])?.unwrap_or(5);
    let backend = a.value(&["--backend", "-b"])?;
    let node = a.value(&["--node", "-n"])?;
    // `--timeout` was consumed by the global parser; `-t` is the same flag.
    let timeout = a.number::<u64>(&["-t"])?.unwrap_or(default_timeout);
    let job_type = a.value(&["--type"])?.unwrap_or_else(|| "inference".to_string());
    let prompt = a.one("<prompt>")?;
    Ok(RunArgs { prompt, async_mode, priority, backend, node, timeout, job_type })
}

/// `noo jobs run PROMPT [--async/-a] [--priority/-p N] [--backend/-b B]
/// [--node/-n ID] [--timeout/-t SECS] [--type TYPE]` —
/// POST /api/jobs/submit, then poll to completion (unless `--async`).
pub fn jobs_run(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let RunArgs { prompt, async_mode, priority, backend, node, timeout, job_type } =
        parse_run_with(&mut Args::new(args), g.timeout_secs.unwrap_or(300))?;
    // Python sends backend/force_node as null when unset — same body here.
    let body = serde_json::json!({
        "type": job_type,
        "payload": {"prompt": prompt},
        "priority": priority,
        "backend": backend,
        "force_node": node,
        "timeout_sec": timeout,
    });
    let data = submit_or_fail(g, "/api/jobs/submit", &body);
    let Some(job_id) = data["job_id"].as_str().map(str::to_string) else {
        fail(
            g.json,
            ExitCode::Generic,
            "bad_response",
            &format!("gateway returned no job_id: {data}"),
            None,
        );
    };

    if async_mode {
        if g.json {
            println!("{}", serde_json::json!({"job_id": job_id}));
        } else {
            // The id is the captured value (kept by --quiet).
            ui::done(&format!("job submitted: {job_id}"));
            ui::value(&job_id);
            ui::guide(&[
                (&format!("noo jobs status {job_id} --wait"), "block until the job finishes and print its result"),
                ("noo jobs list", "see it in the queue alongside everything else running"),
            ]);
        }
        return Ok(0);
    }

    if !g.json {
        ui::step(&format!("job {job_id} submitted, waiting for result"));
    }
    match poll_job(g, &job_id, timeout) {
        Some(job) => Ok(report_terminal_job(g, &job)),
        None => Ok(report_poll_timeout(g, &job_id, timeout)),
    }
}

/// `noo jobs status JOB_ID [--wait/-w] [--timeout SECS]` —
/// GET /api/jobs/{id}; `--wait` polls until a terminal state.
pub fn jobs_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut job_id: Option<String> = None;
    let mut wait = false;
    let timeout = g.timeout_secs.unwrap_or(300); // `--timeout` is global-parsed
    for tok in args {
        match tok.as_str() {
            "--wait" | "-w" => wait = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if job_id.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(job_id) = job_id else { return Err(Unhandled) };
    let data = if wait {
        if !g.json {
            ui::step(&format!("waiting for job {job_id} to finish"));
        }
        match poll_job(g, &job_id, timeout) {
            Some(job) => job,
            None => return Ok(report_poll_timeout(g, &job_id, timeout)),
        }
    } else {
        get_json(g, &format!("/api/jobs/{job_id}"), true, 10)
    };
    if g.json {
        println!("{data}");
    } else {
        println!("{}", serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string()));
        let terminal = matches!(data["status"].as_str(), Some("completed" | "failed" | "cancelled"));
        if terminal {
            ui::guide(&[("noo jobs history", "this record alongside the other finished jobs")]);
        } else {
            ui::guide(&[
                (&format!("noo jobs status {job_id} --wait"), "block until it finishes"),
                (&format!("noo jobs cancel {job_id}"), "drop it"),
            ]);
        }
    }
    Ok(0)
}

pub(crate) fn parse_submit_with(a: &mut Args) -> Result<(String, i64, Option<String>, Option<String>), ArgError> {
    let job_type = a.value(&["--type", "-t"])?.unwrap_or_else(|| "inference".to_string());
    let priority = a.number::<i64>(&["--priority", "-p"])?.unwrap_or(5);
    let backend = a.value(&["--backend", "-b"])?;
    let payload = a.value(&["--payload"])?;
    a.finish()?;
    Ok((job_type, priority, backend, payload))
}

/// `noo jobs submit [--type/-t T] [--priority/-p N] [--backend/-b B]
/// [--timeout SECS] [--payload JSON]` — POST /api/jobs/submit.
pub fn jobs_submit(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (job_type, priority, backend, payload) = parse_submit_with(&mut Args::new(args))?;
    let timeout = g.timeout_secs.unwrap_or(300); // `--timeout` is global-parsed
    let parsed_payload = match &payload {
        None => None,
        Some(raw) => match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(v) => Some(v),
            Err(_) => fail(
                g.json,
                ExitCode::Generic,
                "invalid_payload",
                "Invalid JSON in --payload",
                None,
            ),
        },
    };
    let mut body = serde_json::json!({
        "type": job_type,
        "priority": priority,
        "timeout_sec": timeout,
    });
    if let Some(b) = &backend {
        body["backend"] = serde_json::Value::String(b.clone());
    }
    if let Some(p) = parsed_payload {
        body["payload"] = p;
    }
    let data = submit_or_fail(g, "/api/jobs/submit", &body);
    if g.json {
        println!("{data}");
        return Ok(super::json_exit(&data));
    }
    // The submit route answers HTTP 200 with {"error": …} when Redis is down,
    // so there is no job_id. This used to print "Job submitted: ?" and exit 0
    // — reporting a queued job that does not exist. `jobs run` already
    // treats a missing job_id as a hard failure; do the same here.
    if let Some(err) = data["error"].as_str() {
        ui::failed(&format!("job not submitted: {err}"), None);
        return Ok(crate::output::ExitCode::RemoteError as i32);
    }
    match data["job_id"].as_str() {
        Some(id) => {
            // The id is the captured value (kept by --quiet).
            ui::done(&format!("job submitted: {id}"));
            ui::value(id);
            ui::guide(&[
                (&format!("noo jobs status {id} --wait"), "block until the job finishes and print its result"),
                (&format!("noo jobs cancel {id}"), "withdraw it before a node picks it up"),
                ("noo jobs list", "see the queue"),
            ]);
        }
        None => {
            ui::failed(&format!("job not submitted: gateway returned no job_id: {data}"), None);
            return Ok(crate::output::ExitCode::RemoteError as i32);
        }
    }
    Ok(0)
}

pub(crate) fn parse_history_with(a: &mut Args) -> Result<u64, ArgError> {
    let limit = a.number::<u64>(&["--limit", "-n"])?.unwrap_or(20);
    a.finish()?;
    Ok(limit)
}

/// `noo jobs history [--limit/-n N]` — GET /api/jobs/history.
pub fn jobs_history(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    crate::ui::auto_page(); // long output: $PAGER on a TTY (no-op otherwise)
    let limit = parse_history_with(&mut Args::new(args))?;
    let body = get_json(g, &format!("/api/jobs/history?limit={limit}"), true, 10);
    if g.json {
        println!("{body}");
        return Ok(super::json_exit(&body));
    }
    // The gateway serves job history under `history` (GET /api/jobs/history →
    // {"history": [...], "count": N}). This used to read `jobs`, which the
    // history route has never emitted, so the table was empty no matter what
    // Redis held — while `noo jobs scheduler` happily printed history_size: N
    // from the same list. Accept both keys, but read `history` first.
    let empty = Vec::new();
    let jobs = if body.is_array() {
        body.as_array().unwrap_or(&empty)
    } else {
        body["history"]
            .as_array()
            .or_else(|| body["jobs"].as_array())
            .unwrap_or(&empty)
    };
    // An empty list because the gateway could not reach its store is not the
    // same fact as an empty history. Say which one it is.
    if let Some(err) = body["error"].as_str() {
        ui::failed(&format!("cannot read job history: {err}"), None);
        return Ok(crate::output::ExitCode::RemoteError as i32);
    }
    if jobs.is_empty() {
        println!("{}", ui::muted("no job history"));
        return Ok(0);
    }
    println!("{}", ui::header("job history", Some(&format!("last {}", jobs.len().min(limit as usize)))));
    println!("{}", ui::section("runs"));
    let rows: Vec<Vec<String>> = jobs
        .iter()
        .take(limit as usize)
        .map(|j| {
            let id = j["job_id"].as_str().or_else(|| j["id"].as_str()).unwrap_or("?");
            let status = j["status"].as_str().or_else(|| j["state"].as_str()).unwrap_or("?");
            let dur = j["duration_ms"].as_u64().or_else(|| j["elapsed_ms"].as_u64());
            vec![
                ui::glyph_cell(job_glyph(status)),
                ui::muted(&id[..id.len().min(12)]),
                j["type"].as_str().unwrap_or("?").to_string(),
                ui::state(status),
                dur.map(|d| format!("{d}ms")).unwrap_or_default(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left(""), Col::left("id"), Col::left("type"), Col::left("status"), Col::right("duration")],
            &rows,
        )
    );
    Ok(0)
}

/// `noo jobs cancel JOB_ID [--yes/-y]` — DELETE /api/jobs/{id}.
/// Destructive → agent-first confirm contract (Python uses typer.confirm).
pub fn jobs_cancel(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut job_id: Option<String> = None;
    let mut yes = false;
    for tok in args {
        match tok.as_str() {
            "--yes" | "-y" => yes = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if job_id.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(job_id) = job_id else { return Err(Unhandled) };
    confirm_destructive(g, yes, "Cancel job", &job_id);
    let data = delete_json(g, &format!("/api/jobs/{job_id}"), true, 10);
    if g.json {
        println!("{data}");
        return Ok(0);
    }
    match data["message"].as_str() {
        Some(m) => ui::done(m),
        None => ui::done(&format!("cancelled {job_id}")),
    }
    ui::guide(&[
        ("noo jobs list", "the queue without it"),
        ("noo jobs history", "the cancelled record stays visible here"),
    ]);
    Ok(0)
}

/// `noo jobs reprioritize JOB_ID PRIORITY` — POST /api/jobs/{id}/reprioritize.
pub fn jobs_reprioritize(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positionals: Vec<&String> = Vec::new();
    for tok in args {
        if tok.starts_with('-') {
            return Err(Unhandled);
        }
        positionals.push(tok);
    }
    let &[job_id, priority_raw] = positionals.as_slice() else { return Err(Unhandled) };
    let priority: i64 = priority_raw.parse().map_err(|_| Unhandled)?;
    let data = post_json(
        g,
        &format!("/api/jobs/{job_id}/reprioritize"),
        &serde_json::json!({"priority": priority}),
        true,
        10,
    );
    if g.json {
        println!("{data}");
        return Ok(0);
    }
    ui::done(&format!("job {job_id} reprioritized to {priority}"));
    ui::guide(&[("noo jobs list", "PRI column shows the new order")]);
    Ok(0)
}

/// `noo jobs scheduler` — GET /api/scheduler/status (pretty JSON, like Python).
pub fn jobs_scheduler(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let data = get_json(g, "/api/scheduler/status", true, 10);
    if g.json {
        println!("{data}");
        return Ok(super::json_exit(&data));
    }
    // `/api/scheduler/status` answers 200 with {"error": "Redis not connected"}
    // and no counters at all — printing that object and exiting 0 told a script
    // the scheduler was fine.
    if let Some(err) = data["error"].as_str() {
        ui::failed(&format!("cannot read scheduler status: {err}"), None);
        return Ok(super::json_exit(&data));
    }
    // Arbitrary status object: render its scalars as a kv block (nested
    // values in their JSON form) so the shape survives gateway changes.
    let paused = data["paused"].as_bool();
    let right = paused.map(|p| if p { "paused".to_string() } else { "running".to_string() });
    println!("{}", ui::header("scheduler", right.as_deref()));
    if let Some(obj) = data.as_object() {
        let rows: Vec<(&str, String)> = obj
            .iter()
            .map(|(k, v)| {
                let text = match v {
                    serde_json::Value::String(s) => ui::state(s),
                    serde_json::Value::Null => ui::dash().to_string(),
                    other => other.to_string(),
                };
                (k.as_str(), text)
            })
            .collect();
        print!("{}", ui::kv(&rows));
    }
    Ok(super::json_exit(&data))
}

/// `noo jobs pause` — POST /api/scheduler/pause.
pub fn jobs_pause(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    scheduler_action(g, args, "pause")
}

/// `noo jobs resume` — POST /api/scheduler/resume.
pub fn jobs_resume(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    scheduler_action(g, args, "resume")
}

fn scheduler_action(g: &Globals, args: &[String], action: &str) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let data = post_json(g, &format!("/api/scheduler/{action}"), &serde_json::json!({}), true, 10);
    if g.json {
        println!("{data}");
        return Ok(0);
    }
    // A failed pause/resume answers HTTP 200 with {"error": …} and no
    // `message`, which landed in the None arm below and printed
    // "Scheduler paused" — announcing a state change that never happened.
    if let Some(err) = data["error"].as_str() {
        ui::failed(&format!("scheduler {action} failed: {err}"), None);
        return Ok(crate::output::ExitCode::RemoteError as i32);
    }
    match data["message"].as_str() {
        Some(m) => ui::done(m),
        None => ui::done(&format!("scheduler {action}d")),
    }
    if action == "pause" {
        ui::guide(&[
            ("noo jobs resume", "start dispatching again"),
            ("noo jobs scheduler", "confirms the paused state and what is queued behind it"),
        ]);
    } else {
        ui::guide(&[
            ("noo jobs scheduler", "confirms dispatch is running"),
            ("noo jobs list", "watch the queue drain"),
        ]);
    }
    Ok(0)
}

/// `noo jobs drain NODE_ID` — POST /api/scheduler/drain/{node}.
pub fn jobs_drain(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    drain_action(g, args, "drain")
}

/// `noo jobs undrain NODE_ID` — POST /api/scheduler/undrain/{node}.
pub fn jobs_undrain(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    drain_action(g, args, "undrain")
}

fn drain_action(g: &Globals, args: &[String], action: &str) -> Result<i32, Unhandled> {
    let [node_id] = args else { return Err(Unhandled) };
    if node_id.starts_with('-') {
        return Err(Unhandled);
    }
    let data = post_json(
        g,
        &format!("/api/scheduler/{action}/{node_id}"),
        &serde_json::json!({}),
        true,
        10,
    );
    if g.json {
        println!("{data}");
        return Ok(0);
    }
    // Same trap as scheduler_action: a 200 + {"error": …} with no `message`
    // fell through to "Node X drained", claiming the node had stopped taking
    // work when the drain never took effect.
    if let Some(err) = data["error"].as_str() {
        ui::failed(&format!("{action} of node {node_id} failed: {err}"), None);
        return Ok(crate::output::ExitCode::RemoteError as i32);
    }
    match data["message"].as_str() {
        Some(m) => ui::done(m),
        None => ui::done(&format!("node {node_id} {action}ed")),
    }
    if action == "drain" {
        ui::guide(&[
            (&format!("noo jobs list --node {node_id}"), "jobs still running there finish; nothing new lands"),
            (&format!("noo jobs undrain {node_id}"), "put the node back in rotation"),
        ]);
    } else {
        ui::guide(&[
            ("noo cluster status", "the node takes work again on its next heartbeat"),
            ("noo jobs list", "watch dispatch resume"),
        ]);
    }
    Ok(0)
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    fn a(v: &[&str]) -> Args {
        Args::new(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn run_takes_one_prompt_and_t_overrides_the_default_timeout() {
        let r = parse_run_with(&mut a(&["hello", "-a", "-p", "9", "-t", "30", "--type", "x"]), 300).unwrap();
        assert_eq!((r.prompt.as_str(), r.async_mode, r.priority, r.timeout, r.job_type.as_str()), ("hello", true, 9, 30, "x"));
        assert_eq!(parse_run_with(&mut a(&["hi"]), 300).unwrap().timeout, 300);
        assert!(parse_run_with(&mut a(&["a", "b"]), 300).is_err());
        assert!(parse_run_with(&mut a(&[]), 300).is_err());
        assert!(parse_run_with(&mut a(&["hi", "-p", "high"]), 300).is_err());
    }

    #[test]
    fn list_and_history_refuse_unknown_arguments() {
        assert_eq!(parse_list_with(&mut a(&["-n", "5", "-s", "queued"])).unwrap(), (5, Some("queued".to_string()), None));
        assert!(parse_list_with(&mut a(&["--wat"])).is_err());
        assert!(parse_history_with(&mut a(&["extra"])).is_err());
    }
}
