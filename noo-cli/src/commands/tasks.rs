// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo tasks …` — an objective the agent loops on until done.
//!
//! `create` starts a task as you, on the harness of the node holding its
//! model or on the controller; `list`/`show` read; `stop` ends one at its
//! next checkpoint (`stop --via addon:<name>` revokes an add-on's background
//! work). A task may carry a token budget (`--token-budget`):
//! when it runs out the task parks between loops, and `resubmit` gives it
//! more; a task that asked you a question waits for `answer`. Progress and the result live in the task's
//! agent-message thread (`noo agents thread <id>`).

use super::truncate;
use crate::http::{get_json, post_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

pub fn tasks_create(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut objective: Vec<String> = Vec::new();
    let mut model: Option<String> = None;
    let mut budget: Option<u64> = None;
    let mut token_budget: Option<u64> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--model" | "-m" => model = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--budget" | "-b" => budget = Some(iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?),
            "--token-budget" | "-t" => token_budget = Some(iter.next().and_then(|v| v.parse().ok()).filter(|n| *n > 0).ok_or(Unhandled)?),
            t if t.starts_with('-') => return Err(Unhandled),
            t => objective.push(t.to_string()),
        }
    }
    let objective = objective.join(" ");
    if objective.trim().is_empty() {
        return Err(Unhandled);
    }
    let mut body = serde_json::json!({ "objective": objective });
    if let Some(m) = &model {
        body["model"] = serde_json::json!(m);
    }
    if let Some(b) = budget {
        body["loop_budget"] = serde_json::json!(b);
    }
    if let Some(t) = token_budget {
        body["token_budget"] = serde_json::json!(t);
    }
    let resp = post_json(g, "/api/tasks", &body, true, 20);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let t = &resp["task"];
    let id = t["id"].as_str().unwrap_or("?");
    let node = resp["node"].as_str().unwrap_or("?");
    // A turn that was NOT dispatched ran here, and "here" is the
    // gateway's container id — a twelve-hex string that reads as a node
    // nobody recognises. Saying so, with the gateway's own reason, is
    // the difference between "my fleet is misconfigured" and "my
    // credentials are broken", which is where an operator landed
    // (2026-09-21).
    ui::done(&format!(
        "task {} started {} ({} loops max{})",
        ui::muted(id),
        where_it_ran(node, resp["dispatched"].as_bool()),
        t["loop_budget"].as_u64().unwrap_or(0),
        t["token_budget"].as_i64().map(|b| format!(", {b} tokens max")).unwrap_or_default()
    ));
    if resp["dispatched"].as_bool() == Some(false) {
        if let Some(why) = resp["why"].as_str().filter(|w| !w.trim().is_empty()) {
            println!("{}", ui::muted(&format!("not on a node: {why}")));
        }
    }
    ui::guide(&[
        (&format!("noo tasks show {id}"), "state, loops, last note, result"),
        (&format!("noo agents thread {}", t["thread_id"].as_str().unwrap_or("?")), "its notes and result as they arrive"),
        (&format!("noo tasks stop {id}"), "end it at the next checkpoint"),
    ]);
    Ok(0)
}

/// Where the turn ran, in words the caller can act on.
///
/// A task the gateway kept carries the CONTAINER ID of the gateway as
/// its node — twelve hex characters that read as a node nobody
/// recognises, and read even worse beside a fleet the operator knows the
/// names of. `dispatched: false` says plainly that no node took it.
/// A gateway too old to send the field falls back to naming whatever it
/// reported, which is what this printed before.
pub(crate) fn where_it_ran(node: &str, dispatched: Option<bool>) -> String {
    match dispatched {
        Some(false) => "on this gateway".to_string(),
        _ => format!("on {node}"),
    }
}

pub fn tasks_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut limit = 50u64;
    let mut state: Option<String> = None;
    let mut user: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--limit" | "-n" => limit = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            "--state" | "-s" => state = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--user" | "-u" => user = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let mut path = format!("/api/tasks?limit={limit}");
    if let Some(s) = &state {
        path.push_str(&format!("&state={}", super::urlencode(s)));
    }
    if let Some(u) = &user {
        path.push_str(&format!("&user={}", super::urlencode(u)));
    }
    let resp = get_json(g, &path, true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let empty = Vec::new();
    let rows = resp["tasks"].as_array().unwrap_or(&empty);
    if rows.is_empty() {
        println!("{}", ui::muted("no tasks"));
        return Ok(0);
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|t| {
            let st = t["state"].as_str().unwrap_or("?");
            let stale = t["stale"].as_bool() == Some(true);
            vec![
                ui::glyph_cell(match st {
                    "done" => Glyph::Ok,
                    "failed" => Glyph::Err,
                    "stopped" => Glyph::Warn,
                    _ if stale => Glyph::Warn,
                    _ => Glyph::Bullet,
                }),
                ui::muted(&truncate(t["id"].as_str().unwrap_or("?"), 8)),
                match (stale, t["budget_state"].as_str()) {
                    (_, Some(b)) => format!("{} {}", ui::state(st), ui::warn(budget_label(b))),
                    (true, None) => format!("{} {}", ui::state(st), ui::warn("stale")),
                    (false, None) => ui::state(st),
                },
                format!("{}/{}", t["loops"].as_u64().unwrap_or(0), t["loop_budget"].as_u64().unwrap_or(0)),
                truncate(t["owner"].as_str().unwrap_or("-"), 12),
                truncate(t["node"].as_str().unwrap_or("-"), 12),
                truncate(t["objective"].as_str().unwrap_or(""), 48),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left(""), Col::left("id"), Col::left("state"), Col::right("loops"), Col::left("owner"), Col::left("node"), Col::left("objective")],
            &table
        )
    );
    Ok(0)
}

/// A parked task's state, in a word or two.
pub(crate) fn budget_label(state: &str) -> &'static str {
    match state {
        "exhausted" => "out of tokens",
        "awaiting_clarification" => "asked you",
        _ => "parked",
    }
}

/// The "tokens" row: spent, of what, and what is left.
pub(crate) fn tokens_line(t: &serde_json::Value) -> String {
    let spent = t["tokens_spent"].as_i64().unwrap_or(0);
    match t["token_budget"].as_i64() {
        Some(b) => format!("{spent} of {b} ({} left)", t["remaining"].as_i64().unwrap_or((b - spent).max(0))),
        None => format!("{spent} (no cap)"),
    }
}

/// The "tools called" row: how many tools the task called and which. A
/// gateway that predates the field sends none: "-", never "0 tools".
pub(crate) fn tools_line(tools: &serde_json::Value) -> String {
    let Some(count) = tools["count"].as_u64() else { return "-".into() };
    let names: Vec<&str> = tools["names"].as_array().map(|a| a.iter().filter_map(|n| n.as_str()).collect()).unwrap_or_default();
    if count == 0 {
        "0 (it answered without looking anything up)".into()
    } else {
        format!("{count} ({})", names.join(", "))
    }
}

pub fn tasks_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [id] = args else { return Err(Unhandled) };
    let resp = get_json(g, &format!("/api/tasks/{}", super::urlencode(id)), true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let t = &resp["task"];
    let dash = "-";
    let rows: Vec<(&str, String)> = vec![
        ("id", t["id"].as_str().unwrap_or(dash).to_string()),
        ("state", if t["stale"].as_bool() == Some(true) {
            format!("{} {}", ui::state(t["state"].as_str().unwrap_or(dash)), ui::warn("stale — no checkpoint within the window; its runner has probably died. `noo tasks stop <id>` ends it"))
        } else {
            ui::state(t["state"].as_str().unwrap_or(dash))
        }),
        ("owner", t["owner"].as_str().unwrap_or(dash).to_string()),
        ("node", t["node"].as_str().unwrap_or(dash).to_string()),
        ("model", t["model"].as_str().unwrap_or("auto").to_string()),
        ("loops", format!("{} of {}", t["loops"].as_u64().unwrap_or(0), t["loop_budget"].as_u64().unwrap_or(0))),
        ("tokens", tokens_line(t)),
        ("allowance", match resp["allowance"].as_object() {
            Some(a) => format!(
                "{} of {} this {} ({} left)",
                a.get("spent").and_then(|v| v.as_i64()).unwrap_or(0),
                a.get("limit").and_then(|v| v.as_i64()).unwrap_or(0),
                a.get("period").and_then(|v| v.as_str()).unwrap_or("month"),
                a.get("remaining").and_then(|v| v.as_i64()).unwrap_or(0)
            ),
            None => "none".to_string(),
        }),
        ("tools called", tools_line(&resp["tools"])),
        ("last checkpoint", t["last_checkpoint"].as_str().unwrap_or(dash).to_string()),
        ("thread", t["thread_id"].as_str().unwrap_or(dash).to_string()),
        ("conversation", t["conversation_id"].as_str().unwrap_or(dash).to_string()),
        ("created", t["created_at"].as_str().unwrap_or(dash).to_string()),
    ];
    println!("{}", ui::kv(&rows));
    println!();
    println!("{}", t["objective"].as_str().unwrap_or(""));
    if let Some(n) = t["last_note"].as_str().filter(|n| !n.is_empty()) {
        println!();
        println!("{} {}", ui::muted("last note:"), n);
    }
    let id = t["id"].as_str().unwrap_or(dash);
    match t["budget_state"].as_str() {
        Some("exhausted") => {
            println!();
            println!("{}", ui::warn("out of tokens: no more loops run until it is resubmitted"));
            ui::guide(&[(&format!("noo tasks resubmit {id} --token-budget <n>"), "raise the budget and resume from the checkpoint")]);
        }
        Some("awaiting_clarification") => {
            println!();
            println!("{}", ui::warn("it asked you the question above and waits for your answer"));
            ui::guide(&[(&format!("noo tasks answer {id} <text>"), "answer it; a new loop starts with your answer")]);
        }
        _ => {}
    }
    if let Some(r) = t["result"].as_str().filter(|r| !r.is_empty()) {
        println!();
        println!("{} {}", ui::muted("result:"), r);
    }
    if let Some(e) = t["error"].as_str().filter(|e| !e.is_empty()) {
        println!();
        println!("{} {}", ui::warn("error:"), e);
    }
    let empty = Vec::new();
    let kids = resp["children"].as_array().unwrap_or(&empty);
    if !kids.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = kids
            .iter()
            .map(|k| {
                vec![
                    ui::muted(&truncate(k["id"].as_str().unwrap_or("?"), 8)),
                    truncate(k["role"].as_str().unwrap_or("-"), 10),
                    ui::state(k["state"].as_str().unwrap_or("?")),
                    format!("{}/{}", k["loops"].as_u64().unwrap_or(0), k["loop_budget"].as_u64().unwrap_or(0)),
                    truncate(k["node"].as_str().unwrap_or("-"), 12),
                    truncate(k["result"].as_str().or(k["last_note"].as_str()).unwrap_or(""), 48),
                ]
            })
            .collect();
        print!("{}", ui::table(&[Col::left("child"), Col::left("role"), Col::left("state"), Col::right("loops"), Col::left("node"), Col::left("result / note")], &rows));
    }
    Ok(0)
}

pub fn tasks_stop(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if args.iter().any(|a| a == "--via") {
        return tasks_stop_via(g, args);
    }
    let [id] = args else { return Err(Unhandled) };
    let resp = post_json(g, &format!("/api/tasks/{}/stop", super::urlencode(id)), &serde_json::json!({}), true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    if resp["stopped"].as_bool() == Some(true) {
        ui::done(&format!("task {id} will stop at its next checkpoint"));
    } else {
        println!("{}", ui::status_line(Glyph::Warn, &format!("task {id} was not running")));
    }
    Ok(0)
}

/// `noo tasks stop --via addon:<name> [--user <u>]`: revoke an add-on's
/// background work. Stops your unfinished tasks that add-on started; an
/// operator names another person with `--user`.
fn tasks_stop_via(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut via: Option<String> = None;
    let mut user: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--via" => via = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--user" | "-u" => user = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let via = via.filter(|v| v.strip_prefix("addon:").is_some_and(|n| !n.is_empty())).ok_or(Unhandled)?;
    let mut body = serde_json::json!({ "via": via });
    if let Some(u) = &user {
        body["user"] = serde_json::json!(u);
    }
    let resp = post_json(g, "/api/tasks/stop", &body, true, 20);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let ids: Vec<&str> = resp["stopped"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
    let owner = resp["owner"].as_str().unwrap_or("you");
    if ids.is_empty() {
        println!("{}", ui::status_line(Glyph::Warn, &format!("no unfinished tasks from {via} for {owner}")));
    } else {
        ui::done(&format!("{} task(s) from {via} for {owner} will stop at their next checkpoint", ids.len()));
        for id in &ids {
            println!("  {}", ui::muted(id));
        }
    }
    Ok(0)
}

pub fn tasks_resubmit(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut id: Option<String> = None;
    let mut token_budget: Option<u64> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--token-budget" | "-t" => token_budget = Some(iter.next().and_then(|v| v.parse().ok()).filter(|n| *n > 0).ok_or(Unhandled)?),
            t if t.starts_with('-') => return Err(Unhandled),
            t if id.is_none() => id = Some(t.to_string()),
            _ => return Err(Unhandled),
        }
    }
    let id = id.ok_or(Unhandled)?;
    let mut body = serde_json::json!({});
    if let Some(t) = token_budget {
        body["token_budget"] = serde_json::json!(t);
    }
    let resp = post_json(g, &format!("/api/tasks/{}/resubmit", super::urlencode(&id)), &body, true, 20);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let t = &resp["task"];
    if resp["resumed"].as_bool() == Some(true) {
        ui::done(&format!(
            "task {} resumed {} — tokens {}",
            ui::muted(&id),
            where_it_ran(resp["node"].as_str().unwrap_or("?"), resp["dispatched"].as_bool()),
            tokens_line(t)
        ));
    } else {
        ui::done(&format!("task {} budget set — tokens {}", ui::muted(&id), tokens_line(t)));
    }
    ui::guide(&[(&format!("noo tasks show {id}"), "state, loops, tokens, last note")]);
    Ok(0)
}

pub fn tasks_answer(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [id, rest @ ..] = args else { return Err(Unhandled) };
    if id.starts_with('-') || rest.is_empty() {
        return Err(Unhandled);
    }
    let text = rest.join(" ");
    let resp = post_json(g, &format!("/api/tasks/{}/answer", super::urlencode(id)), &serde_json::json!({"text": text}), true, 20);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format!(
        "answered; task {} goes on {} with your answer",
        ui::muted(id),
        where_it_ran(resp["node"].as_str().unwrap_or("?"), resp["dispatched"].as_bool())
    ));
    ui::guide(&[(&format!("noo agents thread {}", resp["task"]["thread_id"].as_str().unwrap_or("?")), "its notes and result as they arrive")]);
    Ok(0)
}

#[cfg(test)]
mod budget_line_tests {
    use super::{budget_label, tokens_line};
    use serde_json::json;

    #[test]
    fn tokens_read_spent_of_cap_and_left() {
        assert_eq!(tokens_line(&json!({"tokens_spent": 1200, "token_budget": 1000, "remaining": 0})), "1200 of 1000 (0 left)");
        assert_eq!(tokens_line(&json!({"tokens_spent": 300, "token_budget": 1000, "remaining": 700})), "300 of 1000 (700 left)");
        assert_eq!(tokens_line(&json!({"tokens_spent": 5})), "5 (no cap)");
        assert_eq!(tokens_line(&json!({})), "0 (no cap)", "an older gateway sends no budget");
    }

    #[test]
    fn parked_states_have_words() {
        assert_eq!(budget_label("exhausted"), "out of tokens");
        assert_eq!(budget_label("awaiting_clarification"), "asked you");
    }
}

#[cfg(test)]
mod where_it_ran_tests {
    use super::where_it_ran;

    #[test]
    fn a_turn_no_node_took_is_not_reported_as_a_node() {
        // The shape that misled an operator: the gateway's container id
        // printed as though it were one of their machines.
        assert_eq!(where_it_ran("a1b2c3d4e5f6", Some(false)), "on this gateway");
    }

    #[test]
    fn a_dispatched_turn_names_its_node() {
        assert_eq!(where_it_ran("host3", Some(true)), "on host3");
    }

    #[test]
    fn an_older_gateway_sends_no_verdict_and_is_not_second_guessed() {
        // No field: say what it said. Inferring "this gateway" from a
        // twelve-hex node would be a guess, and a wrong one for any node
        // whose id happens to look like that.
        assert_eq!(where_it_ran("a1b2c3d4e5f6", None), "on a1b2c3d4e5f6");
        assert_eq!(where_it_ran("host3", None), "on host3");
    }
}

#[cfg(test)]
mod tools_line_tests {
    use super::tools_line;
    use serde_json::json;

    #[test]
    fn names_the_tools_and_the_count() {
        assert_eq!(tools_line(&json!({"count": 3, "names": ["noo_rag_status", "web_search"]})), "3 (noo_rag_status, web_search)");
    }

    #[test]
    fn zero_tools_is_visible_at_a_glance() {
        assert!(tools_line(&json!({"count": 0, "names": []})).starts_with("0 "));
    }

    #[test]
    fn an_older_gateway_sends_no_field_and_renders_a_dash() {
        assert_eq!(tools_line(&serde_json::Value::Null), "-");
        assert_eq!(tools_line(&json!({})), "-");
    }
}
