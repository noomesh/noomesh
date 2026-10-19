// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster embedding-space {list|set|unset}` — embedding spaces (i145).
//!
//! A space is a purpose bound to ONE embedding model: `knowledge` (seeded
//! with the model the fleet already serves), and e.g. a `code` space with
//! its own embedder. A space's pool is every node whose role=embed placement
//! serves its model; the gateway spreads a space's embeds across that pool
//! and never across models, because vectors from two models are not
//! comparable. Callers name the space as `model` on
//! `/api/external/embeddings`. A space's model does not change by setting
//! (that is a re-embed); a new purpose is a new space.

use crate::http::{delete_json, get_json, put_json};
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
    let SpaceRows { rows, no_live: empty_spaces, unmatched } = space_rows(&body);
    if rows.is_empty() {
        println!("{}", ui::muted("no embedding space recorded yet — the gateway seeds `knowledge` on its next start"));
        return Ok(0);
    }
    print!(
        "{}",
        ui::table(&[Col::left("space"), Col::left("model"), Col::right("dims"), Col::left("node"), Col::left("state")], &rows)
    );
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
}

pub(crate) fn space_rows(body: &serde_json::Value) -> SpaceRows {
    let empty = Vec::new();
    let dash = ui::dash();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut no_live: Vec<String> = Vec::new();
    for s in body["spaces"].as_array().unwrap_or(&empty) {
        let name = s["space"].as_str().unwrap_or("?");
        let label = if s["default"].as_bool() == Some(true) { format!("{name} (default)") } else { name.to_string() };
        let model = s["model"].as_str().unwrap_or("?");
        let dims = s["dims"].as_u64().map(|d| d.to_string()).unwrap_or_else(|| dash.to_string());
        let pool = s["pool"].as_array().unwrap_or(&empty);
        if s["live"].as_u64().unwrap_or(0) == 0 {
            no_live.push(name.to_string());
        }
        if pool.is_empty() {
            rows.push(vec![label, model.into(), dims, dash.into(), ui::bad("no node")]);
            continue;
        }
        for (i, n) in pool.iter().enumerate() {
            let node = format!("{}/{}", n["node"].as_str().unwrap_or("?"), n["backend"].as_str().unwrap_or("?"));
            let state = match (n["desired_state"].as_str(), n["advertising"].as_bool()) {
                (Some("running"), Some(true)) => ui::good("serving"),
                (Some("running"), _) => ui::warn("placed, not advertising"),
                (Some(d), _) => ui::muted(d),
                _ => ui::muted("?"),
            };
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
    SpaceRows { rows, no_live, unmatched }
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

#[cfg(test)]
mod tests {
    use super::space_rows;

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
        let super::SpaceRows { rows, no_live, unmatched } = space_rows(&body);
        assert_eq!(rows.len(), 3, "two pool rows for knowledge, one placeholder for code");
        assert!(rows[0][0].contains("knowledge (default)"));
        assert_eq!(rows[1][0], "", "the space name prints once");
        assert_eq!(no_live, ["code"]);
        assert_eq!(unmatched, [("host9".to_string(), "bge-m3".to_string())]);
    }
}
