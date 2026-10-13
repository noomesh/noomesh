// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster class {list|set|unset}` — model classes and aliases
//! The names an external consumer may send as
//! `model`, each an ORDERED list of `(node, backend, model)` candidates the
//! gateway fails over across.
//!
//! A class never restates a placement: `node/backend` with no `=model`
//! means "whatever `noo cluster place` declared there". `--degraded`
//! candidates are the only ones allowed to answer with a different model,
//! and only after every other candidate has failed.
//! With nothing declared the gateway derives one class per
//! served model — `list` shows those too, marked `derived`.

use crate::http::{delete_json, get_json, put_json};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// One `node/backend[=model]` word. The model is split off FIRST because an
/// HF id carries its own `/` (`host3/vllm=google/gemma-4-12B-it`).
pub(crate) fn parse_candidate(word: &str) -> Option<(String, String, Option<String>)> {
    let (target, model) = match word.split_once('=') {
        Some((t, m)) => (t, Some(m.trim()).filter(|m| !m.is_empty()).map(str::to_string)),
        None => (word, None),
    };
    let (node, backend) = target.split_once('/')?;
    let (node, backend) = (node.trim(), backend.trim());
    if node.is_empty() || backend.is_empty() || backend.contains('/') {
        return None;
    }
    Some((node.to_string(), backend.to_string(), model))
}

/// The PUT body for `class set`: positional candidates first (non-degraded,
/// in order), then every `--degraded` one, then the aliases.
pub(crate) fn set_body(
    candidates: &[(String, String, Option<String>)],
    degraded: &[(String, String, Option<String>)],
    aliases: &[String],
) -> serde_json::Value {
    let mut list = Vec::with_capacity(candidates.len() + degraded.len());
    for (deg, group) in [(false, candidates), (true, degraded)] {
        for (node, backend, model) in group {
            let mut c = serde_json::json!({"node": node, "backend": backend, "degraded": deg});
            if let Some(m) = model {
                c["model"] = serde_json::json!(m);
            }
            list.push(c);
        }
    }
    serde_json::json!({"candidates": list, "aliases": aliases})
}

/// `noo cluster class list`
pub fn cluster_class_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/cluster/model-classes", true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let classes = body["classes"].as_array().unwrap_or(&empty);
    println!("{}", ui::header("model classes", Some("what a consumer may send as `model`")));
    if classes.is_empty() {
        println!("{}", ui::muted("no classes — no node reports a chat backend"));
        ui::guide(&[("noo cluster status", "shows which nodes report backends")]);
        return Ok(0);
    }
    let dash = ui::dash();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut unplaced: Vec<(String, String, String, String)> = Vec::new();
    for c in classes {
        let name = c["name"].as_str().unwrap_or("?");
        let source = if c["declared"].as_bool().unwrap_or(false) { "declared" } else { "derived" };
        let cands = c["candidates"].as_array().unwrap_or(&empty);
        if cands.is_empty() {
            rows.push(vec![name.into(), source.into(), dash.into(), ui::muted("no candidates"), dash.into(), dash.into()]);
            continue;
        }
        for (i, cand) in cands.iter().enumerate() {
            let node = cand["node_id"].as_str().unwrap_or("?");
            let backend = cand["backend"].as_str().unwrap_or("?");
            let model = cand["model"].as_str().unwrap_or("");
            let status = cand["status"].as_str().unwrap_or("?");
            let healthy = cand["healthy"].as_bool().unwrap_or(false);
            let health = cand["health"].as_str().unwrap_or("");
            let degraded = cand["degraded"].as_bool().unwrap_or(false);
            if status == "unplaced" {
                unplaced.push((name.into(), node.into(), backend.into(), model.into()));
            }
            let status_cell = match status {
                "placed" => ui::good("placed"),
                "available" => ui::good("available"),
                _ => ui::bad("unplaced"),
            };
            let health_cell = if status == "unplaced" {
                ui::muted(if health.is_empty() { "skipped at routing" } else { health })
            } else if healthy {
                ui::good("healthy")
            } else {
                ui::warn(if health.is_empty() { "unhealthy" } else { health })
            };
            rows.push(vec![
                if i == 0 { name.to_string() } else { String::new() },
                if i == 0 { source.to_string() } else { String::new() },
                format!("{i}{}", if degraded { " (degraded)" } else { "" }),
                format!("{node}/{backend}={model}"),
                status_cell,
                health_cell,
            ]);
        }
    }
    print!(
        "{}",
        ui::table(
            &[Col::left("class"), Col::left("source"), Col::right("#"), Col::left("candidate"), Col::left("status"), Col::left("health")],
            &rows,
        )
    );
    let aliases = body["aliases"].as_array().unwrap_or(&empty);
    if !aliases.is_empty() {
        println!("{}", ui::section("aliases"));
        print!("{}", alias_rows(aliases));
    }
    if unplaced.is_empty() {
        ui::close_done("every declared candidate is placed or available");
    } else {
        for (class, node, backend, model) in &unplaced {
            println!("{}", ui::status_line(Glyph::Warn, &format!("{class}: {node}/{backend}={model} is neither running nor pulled on {node} — skipped at routing")));
        }
        ui::close_warned(&format!("{} unplaced candidate(s)", unplaced.len()));
        ui::guide(&[("noo cluster place <node> <backend> <model>", "places the model; or pull it on the node and the heartbeat will list it")]);
    }
    Ok(0)
}

/// `noo cluster class set <class> <node>/<backend>[=<model>]... [--degraded ...]... [--alias <name>]...`
pub fn cluster_class_set(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<String> = Vec::new();
    let mut degraded_words: Vec<String> = Vec::new();
    let mut aliases: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--degraded" => degraded_words.push(iter.next().ok_or(Unhandled)?.clone()),
            "--alias" => aliases.push(iter.next().ok_or(Unhandled)?.clone()),
            t if t.starts_with('-') => return Err(Unhandled),
            t => positional.push(t.to_string()),
        }
    }
    let Some((class, words)) = positional.split_first() else { return Err(Unhandled) };
    if words.is_empty() {
        fail(g.json, ExitCode::Usage, "no_candidates",
            "a class needs at least one candidate: noo cluster class set <class> <node>/<backend>[=<model>]...", None);
    }
    let parse_all = |ws: &[String]| -> Vec<(String, String, Option<String>)> {
        ws.iter()
            .map(|w| {
                parse_candidate(w).unwrap_or_else(|| {
                    fail(g.json, ExitCode::Usage, "bad_candidate",
                        &format!("'{w}' is not <node>/<backend>[=<model>] (e.g. host6/ollama=gemma4:12b)"), None)
                })
            })
            .collect()
    };
    let candidates = parse_all(words);
    let degraded = parse_all(&degraded_words);
    let body = set_body(&candidates, &degraded, &aliases);
    let resp = put_json(g, &format!("/api/cluster/model-classes/{}", super::urlencode(class)), &body, true, 15);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format!(
        "{class}: {} candidate(s){}{} declared — routing picks it up within 30 s",
        candidates.len(),
        if degraded.is_empty() { String::new() } else { format!(" + {} degraded", degraded.len()) },
        if aliases.is_empty() { String::new() } else { format!(", aliases {}", aliases.join(", ")) },
    ));
    ui::guide(&[("noo cluster class list", "shows every candidate's placement and health")]);
    Ok(0)
}

/// The alias block of `class list`. An alias is what a consumer sends as
/// `model`, so it prints exactly as declared (`default`, not `Default`):
/// `kv_verbatim`, never the Title-Casing `kv`.
fn alias_rows(aliases: &[serde_json::Value]) -> String {
    let rows: Vec<(&str, String)> = aliases
        .iter()
        .map(|a| {
            (
                a["alias"].as_str().unwrap_or("?"),
                format!(
                    "→ {}{}",
                    a["class"].as_str().unwrap_or("?"),
                    if a["builtin"].as_bool().unwrap_or(false) { "  (built in)" } else { "" }
                ),
            )
        })
        .collect();
    ui::kv_verbatim(&rows)
}

/// `noo cluster class unset <class>`
pub fn cluster_class_unset(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [class] = args else { return Err(Unhandled) };
    if class.starts_with('-') {
        return Err(Unhandled);
    }
    let resp = delete_json(g, &format!("/api/cluster/model-classes/{}", super::urlencode(class)), true, 15);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format!("{class}: declaration removed — the derived class of its model, if any, takes over"));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{alias_rows, parse_candidate, set_body};

    /// `noo cluster class list` printed `Default` / `Auto`; a consumer sends
    /// `default` / `auto`.
    #[test]
    fn aliases_print_exactly_as_declared() {
        let aliases = vec![
            serde_json::json!({"alias": "default", "class": "chat-default", "builtin": true}),
            serde_json::json!({"alias": "auto", "class": "chat-default", "builtin": true}),
            serde_json::json!({"alias": "gemma4:12b-Any", "class": "chat-default", "builtin": false}),
        ];
        let out = alias_rows(&aliases);
        let keys: Vec<&str> = out.lines().map(|l| l.split_whitespace().next().unwrap_or("")).collect();
        // Strip any styling escape the key may carry.
        let plain: Vec<String> = keys.iter().map(|k| {
            let mut s = String::new();
            let mut esc = false;
            for c in k.chars() {
                if esc { if c.is_ascii_alphabetic() { esc = false; } } else if c == '\x1b' { esc = true; } else { s.push(c); }
            }
            s
        }).collect();
        assert_eq!(plain, ["default", "auto", "gemma4:12b-Any"], "{out}");
        assert!(!out.contains("Default") && !out.contains("Auto"), "{out}");
        assert!(out.contains("→ chat-default  (built in)"), "{out}");
    }

    #[test]
    fn a_candidate_word_splits_node_backend_and_an_hf_model_with_its_own_slash() {
        assert_eq!(parse_candidate("host3/vllm"), Some(("host3".into(), "vllm".into(), None)));
        assert_eq!(parse_candidate("host6/ollama=gemma4:12b"), Some(("host6".into(), "ollama".into(), Some("gemma4:12b".into()))));
        assert_eq!(
            parse_candidate("host3/vllm=google/gemma-4-12B-it-qat-w4a16-ct"),
            Some(("host3".into(), "vllm".into(), Some("google/gemma-4-12B-it-qat-w4a16-ct".into())))
        );
        assert_eq!(parse_candidate("host3"), None, "no backend");
        assert_eq!(parse_candidate("/vllm"), None);
        assert_eq!(parse_candidate("host3/vllm="), Some(("host3".into(), "vllm".into(), None)), "an empty model is no model");
    }

    /// The round trip the operator will run: positional candidates in order,
    /// degraded ones after, model only where given.
    #[test]
    fn the_set_body_keeps_order_and_marks_degraded_last() {
        let cands = vec![
            parse_candidate("host3/vllm").unwrap(),
            parse_candidate("host6/ollama=gemma4:12b").unwrap(),
        ];
        let degraded = vec![parse_candidate("host8/ollama").unwrap()];
        let body = set_body(&cands, &degraded, &["gemma4:12b-any".to_string()]);
        let list = body["candidates"].as_array().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0]["node"], "host3");
        assert_eq!(list[0]["backend"], "vllm");
        assert!(list[0].get("model").is_none(), "NULL model = the placement's");
        assert_eq!(list[0]["degraded"], false);
        assert_eq!(list[1]["model"], "gemma4:12b");
        assert_eq!(list[2]["node"], "host8");
        assert_eq!(list[2]["degraded"], true);
        assert_eq!(body["aliases"][0], "gemma4:12b-any");
    }
}
