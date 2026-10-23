// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster embedding-space {list|set|unset|migrate}` — embedding spaces (i145).
//!
//! A space is a purpose bound to ONE embedding model: `knowledge` (seeded
//! with the model the fleet already serves), and e.g. a `code` space with
//! its own embedder. A space's pool is every node whose role=embed placement
//! serves its model; the gateway spreads a space's embeds across that pool
//! and never across models, because vectors from two models are not
//! comparable. Callers name the space as `model` on
//! `/api/external/embeddings`. A space's model does not change by setting
//! (that is a re-embed: `migrate`); a new purpose is a new space.

use crate::http::{delete_json, get_json, post_json, put_json};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo cluster embedding-space list`
pub fn cluster_embedding_space_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/cluster/embedding-spaces", true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    println!("{}", ui::header("embedding spaces", Some("one model per space; callers send the space as `model`")));
    let SpaceRows { rows, no_live: empty_spaces, unmatched, migrations } = space_rows(&body);
    if rows.is_empty() {
        println!("{}", ui::muted("no embedding space recorded yet — the gateway seeds `knowledge` on its next start"));
        return Ok(0);
    }
    print!(
        "{}",
        ui::table(&[Col::left("space"), Col::left("model"), Col::right("dims"), Col::left("node"), Col::left("state")], &rows)
    );
    for line in &migrations {
        println!("{}", ui::status_line(Glyph::Step, line));
    }
    for s in &empty_spaces {
        println!("{}", ui::status_line(Glyph::Warn, &format!("{s}: no node is serving it — its embeds fail until one is placed")));
    }
    for (node, model) in &unmatched {
        println!("{}", ui::status_line(Glyph::Warn, &format!("{node} serves embed model '{model}', which no space uses — it serves nobody")));
    }
    if empty_spaces.is_empty() && unmatched.is_empty() {
        ui::close_done("every space has a live node and every embed node serves a space");
    } else {
        ui::close_warned(&format!("{} space(s) with no live node, {} unmatched embed node(s)", empty_spaces.len(), unmatched.len()));
        ui::guide(&[
            ("noo cluster place <node> ollama <model> --role embed", "puts a space's model on a node"),
            ("noo cluster embedding-space set <space> <model>", "declares a space for a model"),
        ]);
    }
    Ok(0)
}

/// What `list` prints: the table rows, the spaces with no live node, and the
/// embed nodes (`node`, `model`) on a model no space uses.
pub(crate) struct SpaceRows {
    pub rows: Vec<Vec<String>>,
    pub no_live: Vec<String>,
    pub unmatched: Vec<(String, String)>,
    /// One line per space with a re-embed under way (`migration_line`).
    pub migrations: Vec<String>,
}

/// `knowledge: re-embedding into bge-m3 (filling, 120/300 rows)` for one
/// space's `migration` object; `None` when there is none. Rows trellion has
/// no source text for (`unsourced`) get no new vector at the cutover, so the
/// line says how many: text and episode rows keep their old one until the
/// stale sweep heals them, the rest lose it.
pub(crate) fn migration_line(space: &str, m: &serde_json::Value) -> Option<String> {
    let next = m["next_model"].as_str()?;
    let state = m["state"].as_str().unwrap_or("?");
    if state == "pending" {
        let err = m["progress"]["error"].as_str().map(|e| format!(" ({e})")).unwrap_or_default();
        return Some(format!("{space}: re-embedding into {next} pending — waiting for a node serving {next}{err}"));
    }
    let (mut done, mut total, mut unsourced) = (0u64, 0u64, 0u64);
    if let Some(t) = m["progress"]["tables"].as_object() {
        for p in t.values() {
            done += p["done"].as_u64().unwrap_or(0);
            total += p["total"].as_u64().unwrap_or(0);
            unsourced += p["unsourced"].as_u64().unwrap_or(0);
        }
    }
    let progress = if m["progress"].is_null() {
        "no report from trellion yet".to_string()
    } else if unsourced > 0 {
        format!("{done}/{total} rows; {unsourced} with no source text get no new vector at the cutover")
    } else {
        format!("{done}/{total} rows")
    };
    Some(format!("{space}: re-embedding into {next} ({state}, {progress})"))
}

pub(crate) fn space_rows(body: &serde_json::Value) -> SpaceRows {
    let empty = Vec::new();
    let dash = ui::dash();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut no_live: Vec<String> = Vec::new();
    let mut migrations: Vec<String> = Vec::new();
    for s in body["spaces"].as_array().unwrap_or(&empty) {
        let name = s["space"].as_str().unwrap_or("?");
        let label = if s["default"].as_bool() == Some(true) { format!("{name} (default)") } else { name.to_string() };
        let model = s["model"].as_str().unwrap_or("?");
        let dims = s["dims"].as_u64().map(|d| d.to_string()).unwrap_or_else(|| dash.to_string());
        let pool = s["pool"].as_array().unwrap_or(&empty);
        // Static endpoints (the compose embedder) serve the space beside the
        // nodes; the gateway probed each with one embed.
        let statics = s["static"].as_array().unwrap_or(&empty);
        migrations.extend(migration_line(name, &s["migration"]));
        if s["live"].as_u64().unwrap_or(0) + s["static_live"].as_u64().unwrap_or(0) == 0 {
            no_live.push(name.to_string());
        }
        if pool.is_empty() && statics.is_empty() {
            rows.push(vec![label, model.into(), dims, dash.into(), ui::bad("no node")]);
            continue;
        }
        let nodes = pool.iter().map(|n| {
            let node = format!("{}/{}", n["node"].as_str().unwrap_or("?"), n["backend"].as_str().unwrap_or("?"));
            let state = match (n["desired_state"].as_str(), n["advertising"].as_bool()) {
                (Some("running"), Some(true)) => ui::good("serving"),
                (Some("running"), _) => ui::warn("placed, not advertising"),
                (Some(d), _) => ui::muted(d),
                _ => ui::muted("?"),
            };
            (node, state)
        });
        let stat = statics.iter().map(|e| {
            let state = if e["live"].as_bool() == Some(true) { ui::good("serving") } else { ui::warn("not answering") };
            (format!("static {}", e["url"].as_str().unwrap_or("?")), state)
        });
        for (i, (node, state)) in nodes.chain(stat).enumerate() {
            let first = i == 0;
            rows.push(vec![
                if first { label.clone() } else { String::new() },
                if first { model.into() } else { String::new() },
                if first { dims.clone() } else { String::new() },
                node,
                state,
            ]);
        }
    }
    let unmatched = body["unmatched"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|n| (n["node"].as_str().unwrap_or("?").to_string(), n["model"].as_str().unwrap_or("?").to_string()))
        .collect();
    SpaceRows { rows, no_live, unmatched, migrations }
}

/// `noo cluster embedding-space set <space> <model> [--dims <n>]`
pub fn cluster_embedding_space_set(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<&String> = Vec::new();
    let mut dims: Option<u64> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--dims" => {
                let v = iter.next().ok_or(Unhandled)?;
                dims = Some(v.parse().unwrap_or_else(|_| {
                    fail(g.json, ExitCode::Usage, "bad_dims", &format!("--dims takes a vector width (e.g. 1024), not '{v}'"), None)
                }));
            }
            t if t.starts_with('-') => return Err(Unhandled),
            _ => positional.push(tok),
        }
    }
    let [space, model] = positional[..] else { return Err(Unhandled) };
    let mut body = serde_json::json!({"model": model});
    if let Some(d) = dims {
        body["dims"] = serde_json::json!(d);
    }
    let resp = put_json(g, &format!("/api/cluster/embedding-spaces/{}", super::urlencode(space)), &body, true, 15);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    if resp["created"].as_bool() == Some(true) {
        ui::done(&format!("{space}: declared with {model} — callers send `model: {space}`; place {model} on nodes to give it a pool"));
        ui::guide(&[
            ("noo cluster place <node> ollama <model> --role embed", "adds a node to the space's pool"),
            ("noo cluster embedding-space list", "shows every space and its nodes"),
        ]);
    } else {
        ui::done(&format!("{space}: unchanged model ({model})"));
    }
    Ok(0)
}

/// `noo cluster embedding-space unset <space>`
pub fn cluster_embedding_space_unset(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [space] = args else { return Err(Unhandled) };
    if space.starts_with('-') {
        return Err(Unhandled);
    }
    let resp = delete_json(g, &format!("/api/cluster/embedding-spaces/{}", super::urlencode(space)), true, 15);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    ui::done(&format!("{space}: removed — embeds naming it are refused; its nodes now serve no space"));
    Ok(0)
}

/// `noo cluster embedding-space migrate <space> <model> | --complete | --cancel`
pub fn cluster_embedding_space_migrate(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positional: Vec<&String> = Vec::new();
    let (mut complete, mut cancel) = (false, false);
    for tok in args {
        match tok.as_str() {
            "--complete" => complete = true,
            "--cancel" => cancel = true,
            t if t.starts_with('-') => return Err(Unhandled),
            _ => positional.push(tok),
        }
    }
    let base = |space: &str| format!("/api/cluster/embedding-spaces/{}/migration", super::urlencode(space));
    match (&positional[..], complete, cancel) {
        ([space, model], false, false) => {
            // The gateway probes the new model first: allow for its timeout.
            let resp = post_json(g, &base(space), &serde_json::json!({"model": model}), true, 60);
            if g.json {
                println!("{resp}");
                return Ok(0);
            }
            if resp["state"].as_str() == Some("pending") {
                ui::warned(&format!("{space}: no node serves {model} yet — the re-embed is pending and starts by itself once one does"));
                ui::guide(&[
                    ("noo cluster place <node> ollama <model> --role embed", "puts the new model on a node"),
                    ("noo cluster embedding-space migrate <space> --cancel", "abandons the pending re-embed"),
                ]);
                return Ok(0);
            }
            ui::done(&format!(
                "{space}: re-embedding into {model} ({} dims) started — trellion embeds every row beside the live vectors",
                resp["next_dims"].as_u64().unwrap_or(0)
            ));
            ui::guide(&[
                ("noo cluster embedding-space list", "shows trellion's progress per space"),
                ("noo cluster embedding-space migrate <space> --complete", "swaps the space once every row is re-embedded"),
                ("noo cluster embedding-space migrate <space> --cancel", "abandons the re-embed; the live vectors are untouched"),
            ]);
        }
        ([space], true, false) => {
            let resp = post_json(g, &format!("{}/complete", base(space)), &serde_json::json!({}), true, 30);
            if g.json {
                println!("{resp}");
                return Ok(0);
            }
            ui::done(&format!("{space}: cutover begun — trellion swaps its vectors, then the space's model follows"));
        }
        ([space], false, true) => {
            let resp = delete_json(g, &base(space), true, 15);
            if g.json {
                println!("{resp}");
                return Ok(0);
            }
            ui::done(&format!("{space}: re-embed cancelled — the space keeps its model; trellion clears the staged vectors"));
        }
        _ => return Err(Unhandled),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{migration_line, space_rows};

    #[test]
    fn list_shows_a_migration_line_with_progress() {
        let body = serde_json::json!({
            "spaces": [{"space": "knowledge", "model": "harrier", "dims": 1024, "default": true, "live": 1, "pool": [],
                "migration": {"next_model": "bge-m3", "next_dims": 1024, "state": "filling",
                    "progress": {"next_model": "bge-m3", "tables": {"a": {"done": 100, "total": 150}, "b": {"done": 20, "total": 150}}}}},
                {"space": "code", "model": "c", "dims": null, "default": false, "live": 1, "pool": [], "migration": null}],
            "unmatched": []
        });
        let r = space_rows(&body);
        assert_eq!(r.migrations, ["knowledge: re-embedding into bge-m3 (filling, 120/300 rows)"]);
        let fresh = serde_json::json!({"next_model": "x", "state": "filling", "progress": null});
        assert!(migration_line("k", &fresh).unwrap().contains("no report from trellion yet"));
        assert_eq!(migration_line("k", &serde_json::Value::Null), None);
        let pending = serde_json::json!({"next_model": "x", "state": "pending", "progress": null});
        assert_eq!(migration_line("k", &pending).unwrap(), "k: re-embedding into x pending — waiting for a node serving x");
        let wrong = serde_json::json!({"next_model": "x", "state": "pending", "progress": {"error": "width 768"}});
        assert!(migration_line("k", &wrong).unwrap().ends_with("(width 768)"));
        let lossy = serde_json::json!({"next_model": "x", "state": "filling",
            "progress": {"tables": {"concepts": {"done": 0, "total": 0, "unsourced": 12}, "pages": {"done": 5, "total": 9}}}});
        assert_eq!(
            migration_line("k", &lossy).unwrap(),
            "k: re-embedding into x (filling, 5/9 rows; 12 with no source text get no new vector at the cutover)"
        );
    }

    #[test]
    fn rows_flag_a_space_with_no_live_node_and_an_unmatched_embedder() {
        let body = serde_json::json!({
            "spaces": [
                {"space": "knowledge", "model": "harrier", "dims": 1024, "default": true, "live": 1,
                 "pool": [{"node": "host2", "backend": "ollama", "desired_state": "running", "advertising": true},
                          {"node": "host6", "backend": "ollama", "desired_state": "running", "advertising": false}]},
                {"space": "code", "model": "nomic-embed-code", "dims": null, "default": false, "live": 0, "pool": []}
            ],
            "unmatched": [{"node": "host9", "backend": "ollama", "model": "bge-m3"}]
        });
        let super::SpaceRows { rows, no_live, unmatched, .. } = space_rows(&body);
        assert_eq!(rows.len(), 3, "two pool rows for knowledge, one placeholder for code");
        assert!(rows[0][0].contains("knowledge (default)"));
        assert_eq!(rows[1][0], "", "the space name prints once");
        assert_eq!(no_live, ["code"]);
        assert_eq!(unmatched, [("host9".to_string(), "bge-m3".to_string())]);
    }

    /// F1: a space served only by an answering static endpoint is not "no
    /// node"; it prints the endpoint and is not flagged.
    #[test]
    fn a_static_endpoint_serves_a_space_in_list() {
        let body = serde_json::json!({
            "spaces": [{"space": "knowledge", "model": "harrier", "dims": 1024, "default": true, "live": 0, "pool": [],
                        "static": [{"url": "https://stunnel-ollama-embed:11434", "live": true}], "static_live": 1}],
            "unmatched": []
        });
        let super::SpaceRows { rows, no_live, .. } = space_rows(&body);
        assert_eq!(rows.len(), 1);
        assert!(rows[0][3].contains("static https://stunnel-ollama-embed:11434"), "{rows:?}");
        assert!(no_live.is_empty());
    }
}
