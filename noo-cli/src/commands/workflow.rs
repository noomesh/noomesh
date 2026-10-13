// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo workflow …` — workflow automation (Rust gateway routes in
//! `routes/agents.rs`; run is worker-delegated).
//!
//! Ported: list, run.
//! Left in Python: nothing else exists in the group. (Python's list has a
//! local-catalog fallback when the gateway is down; the Rust version exits 3
//! instead — the gateway is the source of truth.)
//!
//! Note: the Python `workflow *` commands send no auth headers (missing
//! cli_auth_headers) and 401 against the auth-enforcing gateway — the Rust
//! versions are the working surface.

use super::truncate;
use crate::http::{get_json, post_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo workflow list` — GET /api/workflows. The Rust gateway wraps the
/// list ({"workflows": [...]}) with full step definitions; accept a bare
/// array with `step_count` too (old Python gateway shape).
pub fn workflow_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/workflows", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let workflows = body["workflows"].as_array().or_else(|| body.as_array()).unwrap_or(&empty);
    if workflows.is_empty() {
        println!("{}", ui::muted("no workflows"));
        return Ok(0);
    }
    println!("{}", ui::header("workflows", Some(&format!("{} available", workflows.len()))));
    println!("{}", ui::section("workflows"));
    let rows: Vec<Vec<String>> = workflows
        .iter()
        .map(|wf| {
            let steps = wf["step_count"]
                .as_u64()
                .unwrap_or_else(|| wf["steps"].as_array().map(|s| s.len() as u64).unwrap_or(0));
            vec![
                truncate(wf["name"].as_str().unwrap_or("?"), 24),
                steps.to_string(),
                truncate(wf["description"].as_str().unwrap_or(""), 80),
            ]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("name"), Col::right("steps"), Col::left("description")], &rows));
    ui::guide(&[
        ("noo workflow run <name> [-i key=value]", "run one with inputs; step output prints as it completes"),
    ]);
    Ok(0)
}

/// `noo workflow run NAME [-i key=value …]` — POST /api/workflows/run.
/// Synchronous: the gateway returns when the workflow finishes (Python
/// parity: 600s timeout).
pub fn workflow_run(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut name: Option<String> = None;
    let mut inputs = serde_json::Map::new();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--input" | "-i" => {
                let kv = iter.next().ok_or(Unhandled)?;
                let (key, value) = kv.split_once('=').ok_or(Unhandled)?;
                inputs.insert(
                    key.trim().to_string(),
                    serde_json::Value::String(value.trim().to_string()),
                );
            }
            t if t.starts_with('-') => return Err(Unhandled),
            t => {
                if name.replace(t.to_string()).is_some() {
                    return Err(Unhandled);
                }
            }
        }
    }
    let Some(name) = name else { return Err(Unhandled) };
    let payload = serde_json::json!({ "workflow_name": name, "inputs": inputs });
    let resp = post_json(g, "/api/workflows/run", &payload, true, 600);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let status = resp["status"].as_str().unwrap_or("unknown");
    let total_ms = resp["total_duration_ms"].as_f64().unwrap_or(0.0);
    // Per-step results are the RESULT of the run: stdout. The final verdict
    // is narration: stderr, with the exit code carrying it for scripts.
    println!("{}", ui::header(&format!("workflow {name}"), Some(&format!("{total_ms:.0}ms"))));
    let empty = Vec::new();
    let steps = resp["steps"].as_array().unwrap_or(&empty);
    if !steps.is_empty() {
        println!("{}", ui::section("steps"));
    }
    for step in steps {
        let step_status = step["status"].as_str().unwrap_or("?");
        let glyph = match step_status {
            "completed" | "success" | "ok" => Glyph::Ok,
            "failed" | "error" => Glyph::Err,
            "skipped" => Glyph::Warn,
            _ => Glyph::Step,
        };
        println!(
            "  {} {}  {}  {}",
            ui::glyph(glyph),
            // The gateway emits each step as {"name": …}; reading `step_name`
            // meant every step in every run printed "?" as its name.
            step["name"].as_str().or_else(|| step["step_name"].as_str()).unwrap_or("?"),
            ui::state(step_status),
            ui::muted(&format!("{:.0}ms", step["duration_ms"].as_f64().unwrap_or(0.0))),
        );
        if let Some(output) = step["output"].as_str() {
            if !output.is_empty() {
                println!("    {}", truncate(output, 500));
            }
        }
        if let Some(err) = step["error"].as_str() {
            if !err.is_empty() {
                println!("    {}", ui::err(&format!("error: {err}")));
            }
        }
    }
    if status == "completed" {
        ui::close_done(&format!("workflow {name} completed in {total_ms:.0}ms"));
        ui::guide(&[("noo workflow list", "every workflow and when each last ran")]);
        Ok(0)
    } else {
        ui::close_failed(&format!("workflow {name} {status}"), None);
        ui::guide(&[
            (&format!("noo workflow run {name}"), "re-run after fixing the failing step"),
            ("noo workflow list", "the other workflows"),
        ]);
        Ok(1)
    }
}
