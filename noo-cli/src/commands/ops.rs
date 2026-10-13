// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo ops …` — asynchronous operations (gateway `ops.rs`, `routes/ops.rs`).
//!
//! A long run (a recluster, a relation extraction, a consolidation, an
//! ingest, a slow graph walk) is not held open as one request: the gateway
//! starts it as an OPERATION, waits a few seconds for it, and answers `200`
//! with the result if it finished or `202` with a handle if it did not. This
//! module is the CLI side of the handle:
//!
//! * `noo ops [list] [--status <s>] [--mine] [--limit <n>]`: your operations;
//! * `noo ops show <id> [--wait]`: one operation; `--wait` blocks until it
//!   finishes and prints its result (exit 1 unless it succeeded);
//! * `noo ops cancel <id>`: stop the gateway-side wait (the worker run itself
//!   may continue, and the answer says what it will do);
//! * `noo ops types`: what can be run this way, and how long each waits.
//!
//! And [`settle`], which every command whose route can answer 202 uses: a body
//! that is not a handle passes through untouched; a handle is followed with
//! long-polls (a spinner on a terminal, one line per minute otherwise) until
//! the operation finishes, so `noo graph recluster` still reads as one
//! foreground command.

use std::time::{Duration, Instant};

use serde_json::Value;

use super::urlencode;
use crate::http::{delete_json_try, get_json, get_json_poll};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col};
use crate::{Globals, Unhandled};

/// Statuses after which an operation no longer changes.
pub(crate) fn is_terminal(status: &str) -> bool {
    matches!(status, "succeeded" | "failed" | "cancelled" | "expired")
}

/// Whether `body` is an operation handle (what a long route answers `202`
/// with): an `op_id` and a `poll` path, not yet finished. A `200` result in
/// the route's old shape never has both.
pub(crate) fn is_handle(body: &Value) -> bool {
    body["op_id"].is_string()
        && body["poll"].is_string()
        && !is_terminal(body["status"].as_str().unwrap_or(""))
}

/// How a followed operation ended.
#[derive(Debug, PartialEq)]
pub(crate) enum Followed {
    /// Finished; the route's own result body.
    Succeeded { result: Value, op: Value },
    /// Failed; `result` is the worker's body when it sent one (else null).
    Failed { error: String, result: Value, op: Value },
    Cancelled(Value),
    Expired(Value),
    /// Still running when the budget ran out (or the gateway stopped
    /// answering): the last view of it.
    Pending(Value),
}

/// Follow an operation to its end. `fetch(wait_secs)` returns the operation's
/// current view (the gateway long-polls for up to `wait_secs`); `None` is a
/// failed fetch. Pure over `fetch`, so the state machine is testable without a
/// gateway. `min_gap` keeps a gateway that ignores `wait` from being hammered.
pub(crate) fn follow_with(
    first: &Value,
    mut fetch: impl FnMut(u64) -> Option<Value>,
    budget: Duration,
    wait_secs: u64,
    min_gap: Duration,
    mut on_tick: impl FnMut(&Value, u64),
) -> Followed {
    let start = Instant::now();
    let mut last = first.clone();
    let mut failures = 0u32;
    loop {
        let elapsed = start.elapsed();
        if elapsed >= budget {
            return Followed::Pending(last);
        }
        // Round UP: 2.99s left is a 3s long-poll, not 2s.
        let remaining = ((budget - elapsed).as_secs_f64().ceil() as u64).max(1);
        let began = Instant::now();
        match fetch(wait_secs.min(remaining).max(1)) {
            Some(op) => {
                failures = 0;
                match op["status"].as_str().unwrap_or("") {
                    "succeeded" => {
                        return Followed::Succeeded { result: op["result"].clone(), op };
                    }
                    "failed" => {
                        let error = op["error"].as_str().unwrap_or("the operation failed").to_string();
                        return Followed::Failed { error, result: op["result"].clone(), op };
                    }
                    "cancelled" => return Followed::Cancelled(op),
                    "expired" => return Followed::Expired(op),
                    _ => {
                        on_tick(&op, start.elapsed().as_secs());
                        last = op;
                    }
                }
            }
            None => {
                failures += 1;
                // Five misses in a row: the gateway has stopped knowing this
                // op (restarted without the row, wrong account). Say so
                // instead of polling to the end of the budget.
                if failures >= 5 {
                    return Followed::Pending(last);
                }
            }
        }
        let took = began.elapsed();
        if took < min_gap {
            std::thread::sleep(min_gap - took);
        }
    }
}

/// Follow `handle` against the live gateway, with a spinner.
pub(crate) fn follow(g: &Globals, handle: &Value, what: &str, budget: Duration) -> Followed {
    let poll = handle["poll"].as_str().unwrap_or("").to_string();
    // A terminal shows a spinner per tick, so poll briefly there; off a
    // terminal one long-poll per request is quieter.
    let wait = if ui::stderr_is_tty() { 3 } else { 20 };
    let mut spinner = if g.json { None } else { Some(ui::Poll::start(what)) };
    let out = follow_with(
        handle,
        |w| get_json_poll(g, &format!("{poll}?wait={w}"), true, w + 20),
        budget,
        wait,
        Duration::from_millis(250),
        |_op, elapsed| {
            if let Some(p) = spinner.as_mut() {
                p.tick(elapsed);
            }
        },
    );
    if let Some(p) = spinner.take() {
        match &out {
            Followed::Succeeded { .. } => p.done(&format!("{what} finished")),
            Followed::Pending(_) => p.warned(&format!("{what} is still running")),
            _ => drop(p),
        }
    }
    out
}

/// What every command whose route may answer `202` does with the body it got.
///
/// * not a handle → `Ok(body)`: the route finished inside its wait and this is
///   the result in the shape the route has always returned;
/// * a handle → followed until it finishes, then `Ok(result)`;
/// * a failure, a cancel, an expiry or running out of time is REPORTED here
///   and returned as `Err(exit_code)`, so the caller just returns it.
///
/// A failed run whose body says `already_running` is handed back as `Ok`: it is
/// the worker's own "nothing was started" answer, which the caller renders.
pub(crate) fn settle(g: &Globals, body: Value, what: &str, budget_secs: u64) -> Result<Value, i32> {
    if !is_handle(&body) {
        return Ok(body);
    }
    let id = body["op_id"].as_str().unwrap_or("").to_string();
    if !g.json {
        ui::step(&format!("{what}: operation {id} started"));
    }
    match follow(g, &body, &format!("waiting for {what}"), Duration::from_secs(budget_secs)) {
        Followed::Succeeded { result, .. } => Ok(result),
        Followed::Failed { error, result, op } => {
            if result["status"].as_str() == Some("already_running") {
                return Ok(result);
            }
            if g.json {
                println!("{op}");
            } else {
                ui::failed(&format!("{what} failed: {error}"), Some(&format!("noo ops show {id}")));
            }
            Err(1)
        }
        Followed::Cancelled(op) => {
            if g.json {
                println!("{op}");
            } else {
                ui::warned(&format!("{what} was cancelled"));
            }
            Err(1)
        }
        Followed::Expired(op) => {
            if g.json {
                println!("{op}");
            } else {
                ui::failed(&format!("the result of {what} has expired"), Some("noo ops list"));
            }
            Err(1)
        }
        Followed::Pending(op) => {
            if g.json {
                println!("{op}");
            } else {
                ui::failed(
                    &format!("{what} is still running after {budget_secs}s; it was not cancelled"),
                    Some(&format!("noo ops show {id} --wait")),
                );
            }
            Err(1)
        }
    }
}

/// The handle as the `--no-wait` form of a command prints it.
pub(crate) fn print_started(g: &Globals, handle: &Value, what: &str) {
    if g.json {
        println!("{handle}");
        return;
    }
    let id = handle["op_id"].as_str().unwrap_or("?");
    ui::done(&format!("{what}: operation started"));
    ui::value(id);
    ui::guide(&[
        (&format!("noo ops show {id} --wait"), "block until it finishes and print the result"),
        (&format!("noo ops cancel {id}"), "stop waiting for it (the worker may carry on)"),
    ]);
}

// ───────────────────────────── rendering ─────────────────────────────

/// The state word the style guide uses for an operation status: its
/// vocabulary has `Done` for "succeeded" and no synonyms (CLI_STYLE_GUIDE §4).
fn status_word(status: &str) -> &str {
    if status == "succeeded" { "done" } else { status }
}

fn short_time(v: &Value) -> String {
    match v.as_str() {
        Some(s) => s.get(..19).unwrap_or(s).replace('T', " "),
        None => ui::dash().to_string(),
    }
}

/// The body of `noo ops show`, from the gateway's view of one operation.
pub(crate) fn render_op(op: &Value) -> String {
    let status = op["status"].as_str().unwrap_or("?");
    let mut rows: Vec<(&str, String)> = vec![
        ("id", op["op_id"].as_str().unwrap_or("?").to_string()),
        ("type", op["type"].as_str().unwrap_or("?").to_string()),
        ("status", ui::state(status_word(status))),
        ("started", short_time(&op["started_at"])),
        ("finished", short_time(&op["finished_at"])),
        ("expires", short_time(&op["expires_at"])),
    ];
    if let Some(e) = op["error"].as_str() {
        rows.push(("error", e.to_string()));
    }
    if let Some(p) = op["progress"].as_object().filter(|p| !p.is_empty()) {
        rows.push(("progress", Value::Object(p.clone()).to_string()));
    }
    if status == "failed" {
        if let Some(safe) = op["retry_safe"].as_bool() {
            rows.push(("retry", if safe { "safe to resubmit".into() } else { "resubmit only if you are sure it did not complete".into() }));
        }
    }
    if let Some(c) = op["cancel"].as_object() {
        let worker = if c.get("worker_stopped").and_then(Value::as_bool) == Some(true) { "stopped" } else { "NOT stopped" };
        rows.push(("cancel", format!("gateway wait stopped; worker run {worker}. {}", c.get("note").and_then(Value::as_str).unwrap_or(""))));
    }
    let mut out = ui::header("operation", Some(status_word(status)));
    out.push('\n');
    out.push_str(&ui::kv(&rows));
    if status == "succeeded" && !op["result"].is_null() {
        out.push_str(&format!("{}\n{}\n", ui::section("result"), serde_json::to_string_pretty(&op["result"]).unwrap_or_default()));
    }
    out
}

/// The `noo ops list` table.
pub(crate) fn render_list(ops: &[Value]) -> String {
    let rows: Vec<Vec<String>> = ops
        .iter()
        .map(|o| {
            vec![
                ui::muted(o["op_id"].as_str().unwrap_or("?").get(..8).unwrap_or("?")),
                o["type"].as_str().unwrap_or("?").to_string(),
                ui::state(status_word(o["status"].as_str().unwrap_or("?"))),
                short_time(&o["created_at"]),
                short_time(&o["finished_at"]),
            ]
        })
        .collect();
    ui::table(&[Col::left("id"), Col::left("type"), Col::left("status"), Col::left("created"), Col::left("finished")], &rows)
}

// ───────────────────────────── commands ─────────────────────────────

/// `noo ops [list] [--status <s>] [--mine] [--limit <n>]` — GET /api/v1/ops.
pub fn ops_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut status: Option<String> = None;
    let mut mine = false;
    let mut limit: Option<u32> = None;
    let mut iter = args.iter().filter(|a| a.as_str() != "list");
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--status" | "-s" => status = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--mine" => mine = true,
            "--limit" | "-n" => limit = Some(iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?),
            _ => return Err(Unhandled),
        }
    }
    let mut path = String::from("/api/v1/ops?");
    if mine {
        path.push_str("mine=1&");
    }
    if let Some(s) = &status {
        path.push_str(&format!("status={}&", urlencode(s)));
    }
    if let Some(n) = limit {
        path.push_str(&format!("limit={n}&"));
    }
    let body = get_json(g, path.trim_end_matches(['?', '&']), true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let ops = body["operations"].as_array().cloned().unwrap_or_default();
    if ops.is_empty() {
        println!("{}", ui::note("no operations"));
        return Ok(0);
    }
    println!("{}", ui::header("operations", Some(&format!("{}", ops.len()))));
    print!("{}", render_list(&ops));
    ui::guide(&[
        ("noo ops show <id> --wait", "block until one finishes and print its result"),
        ("noo ops types", "what can be run this way"),
    ]);
    Ok(0)
}

/// `noo ops show <id> [--wait]` — GET /api/v1/ops/{id}.
pub fn ops_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut id: Option<String> = None;
    let mut wait = false;
    for tok in args {
        match tok.as_str() {
            "--wait" | "-w" => wait = true,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if id.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(id) = id else { return Err(Unhandled) };
    let path = format!("/api/v1/ops/{}", urlencode(&id));
    let mut op = get_json(g, &path, true, 15);
    if wait && !is_terminal(op["status"].as_str().unwrap_or("")) {
        let budget = Duration::from_secs(g.timeout_secs.unwrap_or(900));
        let handle = serde_json::json!({"op_id": id, "poll": path, "status": op["status"]});
        match follow(g, &handle, &format!("waiting for operation {id}"), budget) {
            Followed::Succeeded { op: o, .. } | Followed::Cancelled(o) | Followed::Expired(o) => op = o,
            Followed::Failed { op: o, .. } => op = o,
            Followed::Pending(o) => {
                if g.json {
                    println!("{o}");
                } else {
                    ui::failed(
                        &format!("timed out after {}s waiting for operation {id} (it is still running)", budget.as_secs()),
                        Some(&format!("noo ops show {id} --wait")),
                    );
                }
                return Ok(1);
            }
        }
    }
    if g.json {
        println!("{op}");
    } else {
        print!("{}", render_op(&op));
    }
    let status = op["status"].as_str().unwrap_or("");
    // Reading is not failing; WAITING for an operation that did not succeed is.
    Ok(if wait && status != "succeeded" { 1 } else { 0 })
}

/// `noo ops cancel <id>` — DELETE /api/v1/ops/{id}.
pub fn ops_cancel(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [id] = args else { return Err(Unhandled) };
    if id.starts_with('-') {
        return Err(Unhandled);
    }
    match delete_json_try(g, &format!("/api/v1/ops/{}", urlencode(id)), true, 15) {
        Ok(op) => {
            if g.json {
                println!("{op}");
            } else {
                ui::done(&format!("operation {id} cancelled"));
                let worker = op["cancel"]["worker_stopped"].as_bool() == Some(true);
                if !worker {
                    ui::warned(&format!(
                        "the worker run was not stopped: {}",
                        op["cancel"]["note"].as_str().unwrap_or("it may still complete")
                    ));
                }
            }
            Ok(0)
        }
        Err(detail) => {
            fail(g.json, ExitCode::RemoteError, "remote_error", &format!("could not cancel {id}: {detail}"), Some("noo ops list"));
        }
    }
}

/// `noo ops types` — GET /api/v1/ops/types.
pub fn ops_types(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/v1/ops/types", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let types = body["types"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = types
        .iter()
        .map(|t| {
            vec![
                t["type"].as_str().unwrap_or("?").to_string(),
                format!("{}s", t["default_wait_secs"].as_u64().unwrap_or(0)),
                format!("{}s", t["timeout_secs"].as_u64().unwrap_or(0)),
                t["route"].as_str().unwrap_or("?").to_string(),
            ]
        })
        .collect();
    println!("{}", ui::header("operation types", Some(&format!("{}", types.len()))));
    print!("{}", ui::table(&[Col::left("type"), Col::right("waits"), Col::right("limit"), Col::left("route")], &rows));
    println!(
        "{}",
        ui::note("`waits` is how long the route holds a request before answering with a handle; `limit` is how long a run may take")
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn handle() -> Value {
        json!({"op_id": "0f9c1d2e-0000-4000-8000-000000000001", "poll": "/api/v1/ops/0f9c1d2e-0000-4000-8000-000000000001", "status": "running"})
    }

    fn follow_script(script: Vec<Option<Value>>, budget: Duration) -> (Followed, Vec<u64>) {
        let mut it = script.into_iter();
        let mut waits = Vec::new();
        let out = follow_with(
            &handle(),
            |w| {
                waits.push(w);
                it.next().unwrap_or(None)
            },
            budget,
            20,
            Duration::ZERO,
            |_, _| {},
        );
        (out, waits)
    }

    #[test]
    fn a_handle_is_an_unfinished_op_with_a_poll_path_and_a_result_body_is_not() {
        assert!(is_handle(&handle()));
        // The route's OLD shape (a finished result) is never mistaken for one.
        assert!(!is_handle(&json!({"clusters": 3, "meta_clusters": 1})));
        assert!(!is_handle(&json!({"status": "already_running"})));
        // A finished op view is not a handle: nothing left to follow.
        assert!(!is_handle(&json!({"op_id": "x", "poll": "/p", "status": "succeeded"})));
        assert!(!is_handle(&json!(null)));
    }

    #[test]
    fn following_stops_at_the_first_terminal_status_and_returns_the_result() {
        let (out, waits) = follow_script(
            vec![
                Some(json!({"status": "running"})),
                Some(json!({"status": "running", "progress": {"stage": "x"}})),
                Some(json!({"status": "succeeded", "result": {"clusters": 7}})),
                Some(json!({"status": "failed"})),
            ],
            Duration::from_secs(60),
        );
        assert_eq!(waits.len(), 3, "no fetch after the terminal one");
        assert!(waits.iter().all(|w| *w <= 20), "every poll asks for a bounded long-poll");
        match out {
            Followed::Succeeded { result, .. } => assert_eq!(result, json!({"clusters": 7})),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_failure_carries_its_error_and_the_workers_body() {
        let (out, _) = follow_script(
            vec![Some(json!({"status": "failed", "error": "question required", "result": {"error": "question required"}}))],
            Duration::from_secs(60),
        );
        match out {
            Followed::Failed { error, result, .. } => {
                assert_eq!(error, "question required");
                assert_eq!(result["error"], "question required");
            }
            other => panic!("{other:?}"),
        }
        for (status, want) in [("cancelled", 0), ("expired", 1)] {
            let (out, _) = follow_script(vec![Some(json!({"status": status}))], Duration::from_secs(5));
            assert!(
                matches!((&out, want), (Followed::Cancelled(_), 0) | (Followed::Expired(_), 1)),
                "{status}: {out:?}"
            );
        }
    }

    #[test]
    fn running_out_of_budget_is_pending_never_success() {
        let (out, waits) = follow_script(vec![Some(json!({"status": "running"}))], Duration::ZERO);
        assert!(matches!(out, Followed::Pending(_)));
        assert!(waits.is_empty(), "a spent budget makes no request");
    }

    #[test]
    fn five_failed_fetches_in_a_row_give_up_instead_of_polling_to_the_end_of_the_budget() {
        let (out, waits) = follow_script(vec![None; 20], Duration::from_secs(3600));
        assert!(matches!(out, Followed::Pending(_)));
        assert_eq!(waits.len(), 5);
        // ...but a single miss between answers is forgiven.
        let (out, _) = follow_script(
            vec![None, Some(json!({"status": "running"})), None, Some(json!({"status": "succeeded", "result": {}}))],
            Duration::from_secs(60),
        );
        assert!(matches!(out, Followed::Succeeded { .. }));
    }

    #[test]
    fn a_wait_is_never_longer_than_the_time_left() {
        let (_, waits) = follow_script(vec![None], Duration::from_secs(3));
        assert_eq!(waits.first(), Some(&3), "20s long-poll clamped to the 3s budget");
    }

    #[test]
    fn render_op_names_the_error_the_cancel_note_and_the_result() {
        let failed = render_op(&json!({
            "op_id": "abc", "type": "graph.recluster", "status": "failed",
            "error": "already_running: a run is in flight", "retry_safe": true,
            "started_at": "2026-10-04T10:00:00Z", "finished_at": null, "expires_at": null,
        }));
        assert!(failed.contains("already_running"));
        assert!(failed.contains("safe to resubmit"));
        assert!(!failed.contains("Result"), "no result section on a failure");
        let cancelled = render_op(&json!({
            "op_id": "abc", "type": "graph.recluster", "status": "cancelled",
            "cancel": {"gateway_aborted": true, "worker_stopped": false, "note": "the clustering run keeps going"},
        }));
        assert!(cancelled.contains("NOT stopped") && cancelled.contains("keeps going"), "{cancelled}");
        let done = render_op(&json!({"op_id": "abc", "type": "graph.navigate", "status": "succeeded", "result": {"seeds": 2}}));
        assert!(done.contains("\"seeds\": 2"), "{done}");
        assert!(done.contains("Done") && !done.contains("Succeeded"), "the guide's word for success is Done: {done}");
    }

    #[test]
    fn the_list_has_one_row_per_op_with_a_short_id() {
        let t = render_list(&[
            json!({"op_id": "0f9c1d2e-0000-4000-8000-000000000001", "type": "graph.recluster", "status": "running", "created_at": "2026-10-04T10:00:00Z"}),
            json!({"op_id": "aaaaaaaa-0000-4000-8000-000000000002", "type": "rag.ingest", "status": "succeeded", "created_at": "2026-10-04T10:01:00Z", "finished_at": "2026-10-04T10:02:00Z"}),
        ]);
        assert!(t.contains("0f9c1d2e") && !t.contains("0f9c1d2e-0000"));
        assert!(t.contains("graph.recluster") && t.contains("rag.ingest"));
    }

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_commands_refuse_flags_and_arities_they_do_not_have() {
        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: false };
        assert!(ops_show(&g, &argv(&[])).is_err(), "show needs an id");
        assert!(ops_show(&g, &argv(&["a", "b"])).is_err());
        assert!(ops_show(&g, &argv(&["a", "--bogus"])).is_err());
        assert!(ops_cancel(&g, &argv(&[])).is_err());
        assert!(ops_cancel(&g, &argv(&["--force"])).is_err());
        assert!(ops_list(&g, &argv(&["--bogus"])).is_err());
        assert!(ops_list(&g, &argv(&["--limit", "x"])).is_err());
        assert!(ops_types(&g, &argv(&["x"])).is_err());
    }
}
