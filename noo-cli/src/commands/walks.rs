// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo walks …` — your own saved graph threads
//! gateway `routes/walks.rs`).
//!
//! A signed-in account's `navigate` / `traverse` / `rag` walks are saved as
//! threads, and recalled here: only YOUR OWN, verbatim, re-checked against the
//! graph today (a walk through something you can no longer read, a removed
//! edge, a deleted document or a superseded fact is dropped, never served
//! stale). Saving is on by default; `noo walks settings --save off` stops NEW
//! saves and deletes nothing.
//!
//! * `noo walks [--q <text>] [--top-k <n>]`: recall (with `--q`) or list recent;
//! * `noo walks show <id>`: one thread, with the three scores that ranked it;
//! * `noo walks settings [--save on|off]`: the per-account switch;
//! * `noo walks stats [--user <account>]`: COUNTS (operator and above);
//! * `noo walks view <account> [--limit <n>]`: an account's threads, verbatim
//!   (admin only; every view is audited).

use serde_json::Value;

use super::{truncate, urlencode};
use crate::args::{ArgError, Args};
use crate::http::{get_json, put_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// What `noo walks` was asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ListArgs {
    pub query: Option<String>,
    pub top_k: u32,
}

/// Parse `[--q <text>] [--top-k <n>]` (aliases `-q`, `--query`, `-k`).
/// Anything else is refused with the reason.
pub(crate) fn parse_list(args: &[String]) -> Result<ListArgs, ArgError> {
    parse_list_with(&mut Args::new(args))
}

pub(crate) fn parse_list_with(a: &mut Args) -> Result<ListArgs, ArgError> {
    let query = a.value(&["--q", "-q", "--query"])?;
    let top_k = a.number::<u32>(&["--top-k", "-k"])?.unwrap_or(5);
    a.finish()?;
    Ok(ListArgs { query, top_k })
}

/// `on` / `off` (and the obvious synonyms) for `--save`.
pub(crate) fn parse_switch(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// `usefulness` for a cell: a number when the gateway sent one, a dash when it
/// did not. Absence is never rendered as a score (CLI_STYLE_GUIDE: absence is
/// never a negative).
pub(crate) fn score_cell(w: &Value) -> String {
    match w["usefulness"].as_f64() {
        Some(u) => format!("{u:.2}"),
        None => ui::dash().to_string(),
    }
}

/// The entity names of a thread's path, in order, as `A → B → C`.
pub(crate) fn path_line(w: &Value) -> String {
    let names: Vec<&str> = w["path"]
        .as_array()
        .map(|p| p.iter().map(|s| s["entity_name"].as_str().filter(|n| !n.is_empty()).unwrap_or("?")).collect())
        .unwrap_or_default();
    names.join(" → ")
}

fn short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

/// `noo walks [--q <text>]` — GET /api/v1/walks.
pub fn walks_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = parse_list(args)?;
    let mut path = format!("/api/v1/walks?top_k={}", a.top_k);
    if let Some(q) = &a.query {
        path.push_str(&format!("&q={}", urlencode(q)));
    }
    let body = get_json(g, &path, true, 30);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let walks = body["walks"].as_array().unwrap_or(&empty);
    let how = match &a.query {
        Some(q) => format!("{} matching {}", walks.len(), truncate(q, 30)),
        None => format!("{} most recent", walks.len()),
    };
    if walks.is_empty() {
        println!("{}", ui::muted("no saved threads"));
        println!(
            "{}",
            ui::muted("a thread is saved by a graph navigate or a RAG answer that walks the graph; entity search never saves one")
        );
        ui::guide(&[
            ("noo graph navigate <question>", "walks the graph and saves the thread"),
            ("noo rag query <question>", "also saved when the answer walks the graph (a plain lookup is not)"),
            ("noo walks settings", "saving is on by default; this shows whether it is on for you"),
        ]);
        return Ok(0);
    }
    println!("{}", ui::header("walks", Some(&how)));
    println!();
    let rows: Vec<Vec<String>> = walks
        .iter()
        .map(|w| {
            vec![
                ui::muted(short(w["id"].as_str().unwrap_or("?"))),
                score_cell(w),
                truncate(w["query"].as_str().unwrap_or("?"), 44),
                truncate(&path_line(w), 48),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(&[Col::left("id"), Col::left("useful"), Col::left("asked"), Col::left("path")], &rows)
    );
    ui::guide(&[("noo walks show <id>", "one thread in full, with why it ranked")]);
    Ok(0)
}

/// `noo walks show <id>` — GET /api/v1/walks/{id}.
pub fn walks_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let id = match args {
        [id] if !id.starts_with('-') => id.clone(),
        _ => return Err(Unhandled),
    };
    let body = get_json(g, &format!("/api/v1/walks/{}", urlencode(&id)), true, 30);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let w = &body["walk"];
    if !w.is_object() {
        eprintln!("{}", ui::status_line(Glyph::Err, &format!("no thread {id} (it may be another account's, or gone)")));
        return Ok(1);
    }
    println!("{}", ui::header("walk", Some(w["id"].as_str().unwrap_or(&id))));
    println!();
    if w["available"].as_bool() == Some(false) {
        let gates: Vec<&str> = w["gates"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        println!("{}", ui::status_line(Glyph::Warn, "this thread no longer holds against the graph, so its path is not shown"));
        let rows = vec![
            ("asked", w["query"].as_str().unwrap_or("?").to_string()),
            ("why", gates.join(", ")),
            ("status", w["status"].as_str().unwrap_or("?").to_string()),
        ];
        print!("{}", ui::kv(&rows));
        return Ok(0);
    }
    let why = &w["why"];
    let part = |k: &str| why[k].as_f64().map(|v| format!("{v:.2}")).unwrap_or_else(|| ui::dash().to_string());
    let rows = vec![
        ("asked", w["query"].as_str().unwrap_or("?").to_string()),
        ("path", path_line(w)),
        ("via", w["via"].as_str().unwrap_or("?").to_string()),
        ("saved", w["created_at"].as_str().unwrap_or("?").to_string()),
        ("status", w["status"].as_str().unwrap_or("?").to_string()),
        (
            "scores",
            format!("accuracy {} · freshness {} · relevance {}", part("accuracy"), part("freshness"), part("relevance")),
        ),
    ];
    print!("{}", ui::kv(&rows));
    Ok(0)
}

/// `noo walks settings [--save on|off]` — GET/PUT /api/v1/walks/settings.
pub fn walks_settings(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut want: Option<bool> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--save" => want = Some(parse_switch(iter.next().ok_or(Unhandled)?).ok_or(Unhandled)?),
            _ => return Err(Unhandled),
        }
    }
    match want {
        None => {
            let body = get_json(g, "/api/v1/walks/settings", true, 10);
            if g.json {
                println!("{body}");
                return Ok(0);
            }
            // No `unwrap_or(true)`: a reply without the field is unknown, not "on".
            let word = match body["save_threads"].as_bool() {
                Some(true) => ui::state("enabled"),
                Some(false) => ui::state("off"),
                None => ui::muted("unknown"),
            };
            println!("{}", ui::header("walks settings", None));
            print!("{}", ui::kv(&[("save threads", word)]));
            ui::guide(&[
                ("noo walks settings --save off", "stop saving new threads (existing ones are kept)"),
                ("noo walks settings --save on", "resume saving"),
            ]);
            Ok(0)
        }
        Some(on) => {
            let resp = put_json(g, "/api/v1/walks/settings", &serde_json::json!({ "save_threads": on }), true, 10);
            if g.json {
                println!("{resp}");
                return Ok(0);
            }
            // Read back what the gateway says it stored; never echo the request as the result.
            match resp["save_threads"].as_bool() {
                Some(now) if now == on => {
                    ui::done(&format!(
                        "Applied: saving threads is {}",
                        if now { "on" } else { "off; threads already saved are kept" }
                    ));
                    Ok(0)
                }
                _ => {
                    ui::failed("the gateway did not confirm the setting", Some("noo walks settings"));
                    Ok(1)
                }
            }
        }
    }
}

/// `noo walks stats [--user <account>]` — GET /api/v1/walks/stats (operator and above): COUNTS only.
pub fn walks_stats(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut user: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--user" | "-u" => user = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let path = match &user {
        Some(u) => format!("/api/v1/walks/stats?user={}", urlencode(u)),
        None => "/api/v1/walks/stats".to_string(),
    };
    let body = get_json(g, &path, true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    println!("{}", ui::header("walks", Some("counts only")));
    println!();
    let empty = Vec::new();
    let by = body["by_kind_status"].as_array().unwrap_or(&empty);
    let rows: Vec<Vec<String>> = by
        .iter()
        .map(|r| {
            vec![
                r["kind"].as_str().unwrap_or("?").to_string(),
                r["status"].as_str().unwrap_or("?").to_string(),
                r["count"].as_i64().map(|n| n.to_string()).unwrap_or_else(|| ui::dash().to_string()),
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("kind"), Col::left("status"), Col::right("count")], &rows));
    let per = body["per_user"].as_array().unwrap_or(&empty);
    if !per.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = per
            .iter()
            .map(|r| {
                vec![
                    r["user"].as_str().unwrap_or("?").to_string(),
                    r["active"].as_i64().map(|n| n.to_string()).unwrap_or_else(|| ui::dash().to_string()),
                    r["total"].as_i64().map(|n| n.to_string()).unwrap_or_else(|| ui::dash().to_string()),
                ]
            })
            .collect();
        print!("{}", ui::table(&[Col::left("account"), Col::right("active"), Col::right("total")], &rows));
    }
    if let Some(n) = body["opted_out_accounts"].as_i64() {
        println!();
        print!("{}", ui::kv(&[("opted out", format!("{n} account(s)"))]));
    }
    ui::guide(&[("noo walks view <account>", "what an account asked: admin only, and every view is audited")]);
    Ok(0)
}

/// `noo walks view <account> [--limit <n>]` — GET /api/v1/admin/walks (admin only; AUDITED).
pub fn walks_view(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut user: Option<String> = None;
    let mut limit = 50u32;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--limit" | "-n" => limit = iter.next().and_then(|v| v.parse().ok()).ok_or(Unhandled)?,
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if user.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(user) = user else { return Err(Unhandled) };
    let body = get_json(g, &format!("/api/v1/admin/walks?user={}&limit={limit}", urlencode(&user)), true, 30);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let threads = body["threads"].as_array().unwrap_or(&empty);
    println!("{}", ui::header("walks", Some(&format!("{} of {user}", threads.len()))));
    println!("{}", ui::muted("audited: this view is recorded in the security audit log"));
    if threads.is_empty() {
        println!("{}", ui::muted("no saved threads"));
        return Ok(0);
    }
    println!();
    let rows: Vec<Vec<String>> = threads
        .iter()
        .map(|w| {
            vec![
                ui::muted(short(w["id"].as_str().unwrap_or("?"))),
                w["status"].as_str().unwrap_or("?").to_string(),
                score_cell(w),
                truncate(w["query"].as_str().unwrap_or("?"), 50),
                truncate(&path_line(w), 44),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[Col::left("id"), Col::left("status"), Col::left("useful"), Col::left("asked"), Col::left("path")],
            &rows
        )
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn list_takes_a_query_and_a_count_and_nothing_else() {
        assert_eq!(parse_list(&s(&[])).unwrap(), ListArgs { query: None, top_k: 5 });
        assert_eq!(
            parse_list(&s(&["--q", "graph walks", "--top-k", "3"])).unwrap(),
            ListArgs { query: Some("graph walks".into()), top_k: 3 }
        );
        assert_eq!(parse_list(&s(&["-q", "x"])).unwrap().query.as_deref(), Some("x"));
        for bad in [&["--q"][..], &["--top-k", "many"], &["--user", "bob"], &["stray"]] {
            assert!(parse_list(&s(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_save_switch_reads_on_and_off_and_refuses_anything_else() {
        for on in ["on", "ON", "true", "yes", "1"] {
            assert_eq!(parse_switch(on), Some(true), "{on}");
        }
        for off in ["off", "Off", "false", "no", "0"] {
            assert_eq!(parse_switch(off), Some(false), "{off}");
        }
        assert_eq!(parse_switch("maybe"), None);
    }

    #[test]
    fn a_missing_score_is_a_dash_never_a_zero() {
        assert_eq!(score_cell(&json!({"usefulness": 0.6234})), "0.62");
        assert_eq!(score_cell(&json!({"usefulness": 0.0})), "0.00");
        assert_eq!(score_cell(&json!({"usefulness": null})), ui::dash());
        assert_eq!(score_cell(&json!({})), ui::dash());
    }

    #[test]
    fn a_path_reads_as_names_and_an_unnamed_step_is_a_question_mark() {
        let w = json!({"path": [{"entity_name": "Alpha"}, {"entity_name": ""}, {"entity_name": "Gamma"}]});
        assert_eq!(path_line(&w), "Alpha → ? → Gamma");
        assert_eq!(path_line(&json!({})), "");
    }

    #[test]
    fn ids_are_shortened_without_splitting_a_character() {
        assert_eq!(short("0123456789abcdef"), "01234567");
        assert_eq!(short("abc"), "abc");
    }

    /// Entity search never saves a walk; the empty-state hint once said it did.
    #[test]
    fn the_empty_hint_does_not_claim_entity_search_saves_a_thread() {
        let src = include_str!("walks.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(
            !body.contains("\"noo graph search"),
            "`noo graph search` is not a way to save a thread"
        );
        assert!(body.contains("(\"noo rag query <question>\""));
    }
}
