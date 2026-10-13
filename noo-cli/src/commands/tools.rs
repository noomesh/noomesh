// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo tools …` — cluster tool registry (Rust gateway routes in
//! `routes/ui.rs`; note the bare `/tools/*` prefix, no `/api`).
//!
//! Ported: list (with --node), select, info, export (+ --check).
//! `export` was DEV_ONLY until WP-TE: it needs the FULL @tool registry —
//! tags/speed/nats_subject per tool plus extended_tool_groups — and
//! /tools/list strips exactly that, so a thin-HTTP port against it would
//! have regenerated config/tools.json corrupted (the WP-A5 finding). The
//! Rust gateway now serves the raw registry at GET /api/tools/registry/raw
//! (routes/ui.rs), which is what the native export consumes.
//! (Python's `list --verbose` extra column is folded in: the Rust rendering
//! always includes a truncated description; use --json for full detail.)
//!
//! Note: the Python `tools *` commands send no auth headers (missing
//! cli_auth_headers) — the Rust versions authenticate.

use super::truncate;
use crate::http::get_json;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo tools list [--node NODE_ID]` — GET /tools/list, or
/// GET /api/tools/nodes/{node_id} when filtered to one node.
pub fn tools_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut node: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--node" => node = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let path = match &node {
        Some(n) => format!("/api/tools/nodes/{}", super::urlencode(n)),
        None => "/tools/list".to_string(),
    };
    let body = get_json(g, &path, true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let tools = body["tools"].as_array().unwrap_or(&empty);
    if tools.is_empty() {
        // Node-scoped queries can 200 with an embedded error (e.g. the
        // node-agent has no /tools endpoint) — surface it.
        if let Some(err) = body["error"].as_str() {
            println!("{}", ui::status_line(Glyph::Warn, &format!("no tools available: {err}")));
        } else {
            println!("{}", ui::muted("no tools"));
        }
        return Ok(0);
    }
    if let Some(n) = &node {
        println!("{}", ui::header("tools", Some(&format!("node {n} · {} tools", tools.len()))));
        println!();
        let rows: Vec<Vec<String>> = tools
            .iter()
            .map(|t| {
                vec![
                    t["name"].as_str().unwrap_or("?").to_string(),
                    ui::muted(&truncate(t["description"].as_str().unwrap_or(""), 70)),
                ]
            })
            .collect();
        print!("{}", ui::table(&[Col::left("tool"), Col::left("description")], &rows));
        return Ok(0);
    }
    // The gateway sends `stats: {total}` only. This used to read
    // `total_tools`/`base_tools`/`node_specific_tools` — none of which are
    // ever sent — and print "base: 0 | specialized: 0", inventing a registry
    // breakdown the gateway never measured. Print what actually arrives.
    let stats = &body["stats"];
    let num = |v: &serde_json::Value| match v.as_u64() {
        Some(n) => n.to_string(),
        None => "not reported".to_string(),
    };
    let total = stats["total"]
        .as_u64()
        .or_else(|| stats["total_tools"].as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| tools.len().to_string());
    println!(
        "{}",
        ui::header(
            "tools",
            Some(&format!(
                "{total} total · base {} · specialized {}",
                num(&stats["base_tools"]),
                num(&stats["node_specific_tools"]),
            ))
        )
    );
    println!();
    let rows: Vec<Vec<String>> = tools
        .iter()
        .map(|t| {
            // The gateway hardcodes `available_on_nodes: []`, so this column used
            // to claim "all nodes" for every base tool and "0 node(s)" for the
            // rest — a placement claim the CLI has no data for. Only report a
            // count when the gateway actually sends one.
            let availability = match t["available_on_nodes"].as_array() {
                Some(nodes) if !nodes.is_empty() => format!("{} node(s)", nodes.len()),
                _ => ui::state("not reported"),
            };
            vec![
                truncate(t["name"].as_str().unwrap_or("?"), 36),
                tool_kind(t, "base", "specialized"),
                availability,
                ui::muted(&truncate(t["description"].as_str().unwrap_or(""), 50)),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(&[Col::left("tool"), Col::left("type"), Col::left("availability"), Col::left("description")], &rows)
    );
    Ok(0)
}

/// `noo tools select PROMPT` — retired. The route it called previewed a
/// substring matcher the agent loop never uses (the loop picks its tools from
/// core tools plus keyword groups in the registry), so the preview could
/// disagree with what actually runs. `noo tools list` shows the registry.
pub fn tools_select(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Generic,
        "tools_select_retired",
        "tools select is retired: it previewed a matcher the agent does not use",
        Some("noo tools list"),
    );
}

/// "base" / "specialized" when the gateway says which, else "not reported":
/// `is_base_tool` arrives as null, and null is not "specialized".
fn tool_kind(t: &serde_json::Value, base: &str, specialized: &str) -> String {
    match t["is_base_tool"].as_bool() {
        Some(true) => base.to_string(),
        Some(false) => specialized.to_string(),
        None => ui::state("not reported"),
    }
}

/// `noo tools info TOOL_NAME` — GET /tools/list, then client-side filter
/// (Python parity: there is no per-tool endpoint).
pub fn tools_info(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [name] = args else { return Err(Unhandled) };
    if name.starts_with('-') {
        return Err(Unhandled);
    }
    let body = get_json(g, "/tools/list", true, 10);
    let empty = Vec::new();
    let tools = body["tools"].as_array().unwrap_or(&empty);
    let Some(tool) = tools.iter().find(|t| t["name"].as_str() == Some(name.as_str())) else {
        if g.json {
            eprintln!(
                "{}",
                serde_json::json!({"error": format!("tool '{name}' not found"), "code": "not_found"})
            );
        } else {
            ui::failed(&format!("tool {name} not found"), Some("noo tools list"));
        }
        return Ok(1);
    };
    if g.json {
        println!("{tool}");
        return Ok(0);
    }
    let is_base = tool["is_base_tool"].as_bool();
    println!("{}", ui::header(tool["name"].as_str().unwrap_or(name), None));
    let mut rows: Vec<(&str, String)> = vec![
        ("type", tool_kind(tool, "base (all nodes)", "specialized")),
        ("description", tool["description"].as_str().unwrap_or(ui::dash()).to_string()),
    ];
    if is_base == Some(false) {
        let nodes = tool["available_on_nodes"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        rows.push(("available on", if nodes.is_empty() { ui::state("not reported") } else { nodes }));
    }
    print!("{}", ui::kv(&rows));
    if let Some(props) = tool["parameters"]["properties"].as_object() {
        let required: Vec<&str> = tool["parameters"]["required"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        println!("{}", ui::section("parameters"));
        let rows: Vec<Vec<String>> = props
            .iter()
            .map(|(pname, spec)| {
                vec![
                    pname.clone(),
                    spec["type"].as_str().unwrap_or("any").to_string(),
                    if required.contains(&pname.as_str()) { ui::warn("required") } else { String::new() },
                    ui::muted(&truncate(spec["description"].as_str().unwrap_or(""), 70)),
                ]
            })
            .collect();
        print!("{}", ui::table(&[Col::left("name"), Col::left("type"), Col::left(""), Col::left("")], &rows));
    }
    Ok(0)
}

/// `noo tools export [--output/-o PATH] [--check] [--force]` — regenerate
/// config/tools.json from GET /api/tools/registry/raw (WP-TE, plan §4b).
///
/// Staleness guard (WP-Z): without `--force`, the write is skipped (exit 0,
/// warning printed) when the fetched registry has FEWER core_tools than the
/// file being replaced — the signature of a running gateway built from an
/// older image than the repo. The endpoint also exposes an
/// `x-registry-fingerprint: sha256:<hex>` response header for external
/// change detection.
///
/// Python parity (`tools_cli.py export_tools` / `decl.py`):
/// - default target: /app/config/tools.json → ./config/tools.json →
///   `<repo>/config/tools.json` (first existing wins; repo layout is the
///   fallback when none exist yet) — same candidate order as
///   `decl.default_tools_json_path()`;
/// - the file is written unconditionally, exactly like Python's
///   `target.write_text(...)` (no silent-skip, no confirm — Python has none);
/// - `--check` never writes: parsed deep-equal against the registry (dict
///   key order irrelevant, list order significant — Python's
///   `tools_json_matches`), exit 1 on mismatch or missing file;
/// - output is `serde_json` pretty (2-space indent, raw UTF-8) + trailing
///   newline, matching `json.dumps(..., indent=2, ensure_ascii=False)+"\n"`.
///   One deliberate deviation: object keys serialize in serde_json's sorted
///   order, not Python's insertion order — semantically identical (both the
///   gateway loader and Python's `--check` compare parsed, order-insensitive).
///
/// Round-trip safety (the WP-A5 corruption finding): refuses to write any
/// payload whose `core_tools` is missing/empty or whose
/// `extended_tool_groups` is absent — a stripped registry written to
/// config/tools.json would break NATS tool routing cluster-wide.
pub fn tools_export(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut output: Option<std::path::PathBuf> = None;
    let mut check = false;
    let mut force = false;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--output" | "-o" => {
                output = Some(std::path::PathBuf::from(iter.next().ok_or(Unhandled)?))
            }
            "--check" => check = true,
            "--force" => force = true,
            _ => return Err(Unhandled),
        }
    }

    let registry = get_json(g, "/api/tools/registry/raw", true, 10);
    if !registry_shape_ok(&registry) {
        fail(
            g.json,
            ExitCode::Generic,
            "bad_registry",
            "gateway registry response is missing core_tools/extended_tool_groups — \
             refusing to write a corrupted config/tools.json",
            Some("does this gateway serve GET /api/tools/registry/raw (WP-TE)?"),
        );
    }

    let target = output.unwrap_or_else(default_tools_json_path);

    if check {
        let text = match std::fs::read_to_string(&target) {
            Ok(t) => t,
            Err(_) => fail(
                g.json,
                ExitCode::Generic,
                "missing_file",
                &format!("{} does not exist", target.display()),
                Some("run `noo tools export` to generate it"),
            ),
        };
        let on_disk: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => fail(
                g.json,
                ExitCode::Generic,
                "bad_file",
                &format!("{} is not valid JSON: {e}", target.display()),
                Some("run `noo tools export` to regenerate it"),
            ),
        };
        if on_disk != registry {
            fail(
                g.json,
                ExitCode::Generic,
                "out_of_date",
                &format!("{} is out of date with the tool registry", target.display()),
                Some("run `noo tools export` to regenerate it"),
            );
        }
        if g.json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "ok", "action": "tools_export_check",
                    "path": target.display().to_string(), "matches": true,
                })
            );
        } else {
            ui::done(&format!("{} matches the tool registry", target.display()));
            ui::guide(&[("noo tools export", "rewrites the file when the registry changes")]);
        }
        return Ok(0);
    }

    // Staleness guard (WP-Z): the gateway serves the registry it loaded at
    // ITS startup. If the running gateway image is older than the repo, an
    // export would overwrite a newer config/tools.json with an old registry
    // and silently drop tools from NATS routing. Detect the destructive case
    // — the on-disk file has MORE core_tools than the fetch — and skip the
    // write (exit 0, file untouched) unless --force. Equal/greater fetched
    // counts write as before.
    if !force {
        if let Ok(existing_text) = std::fs::read_to_string(&target) {
            if let Ok(existing) = serde_json::from_str::<serde_json::Value>(&existing_text) {
                let on_disk_n = existing["core_tools"].as_array().map(Vec::len).unwrap_or(0);
                let fetched_n = registry["core_tools"].as_array().map(Vec::len).unwrap_or(0);
                if on_disk_n > fetched_n {
                    let warn = format!(
                        "gateway registry has {fetched_n} tools but {} already has \
                         {on_disk_n} — the running gateway likely started from an \
                         older image than this repo; writing would REMOVE tools",
                        target.display()
                    );
                    if g.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "status": "skipped", "action": "tools_export",
                                "path": target.display().to_string(),
                                "warning": warn,
                                "on_disk_tools": on_disk_n, "fetched_tools": fetched_n,
                                "hint": "restart the gateway from current source, or pass --force",
                            })
                        );
                    } else {
                        ui::close_warned(&warn);
                        println!("{}", ui::note(&format!("skipped: {} left untouched", target.display())));
                        ui::guide(&[
                            ("noo stack restart gateway", "restart from the current image so the registry it serves matches this repo"),
                            ("noo tools export --force", "overwrite anyway, accepting that tools may be removed"),
                        ]);
                    }
                    return Ok(0);
                }
            }
        }
    }

    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "write_failed",
                    &format!("cannot create {}: {e}", parent.display()),
                    None,
                );
            }
        }
    }
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&registry).unwrap_or_default()
    );
    if let Err(e) = std::fs::write(&target, rendered) {
        fail(
            g.json,
            ExitCode::Generic,
            "write_failed",
            &format!("cannot write {}: {e}", target.display()),
            None,
        );
    }
    let n_tools = registry["core_tools"].as_array().map(Vec::len).unwrap_or(0);
    let n_groups = registry["extended_tool_groups"]
        .as_object()
        .map(serde_json::Map::len)
        .unwrap_or(0);
    if g.json {
        println!(
            "{}",
            serde_json::json!({
                "status": "ok", "action": "tools_export",
                "path": target.display().to_string(),
                "tools": n_tools, "groups": n_groups,
            })
        );
    } else {
        // The written path is the captured value; the rest is narration.
        ui::close_done(&format!("wrote {} ({n_tools} tools, {n_groups} groups)", target.display()));
        ui::value(&target.display().to_string());
        ui::guide(&[
            ("noo stack restart gateway", "the gateway reads tools.json at start — restart to pick up schema changes"),
            ("noo tools export --check", "diffs the registry against the file without writing"),
        ]);
    }
    Ok(0)
}

/// The write gate: `core_tools` must be a non-empty array AND
/// `extended_tool_groups` an object (may be empty — Python always emits the
/// key). Anything less is a stripped/foreign payload, not the raw registry.
fn registry_shape_ok(registry: &serde_json::Value) -> bool {
    registry["core_tools"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
        && registry["extended_tool_groups"].is_object()
}

/// Python parity: `decl.default_tools_json_path()` — existing deployment
/// paths first, then the repo layout (final fallback even if absent).
fn default_tools_json_path() -> std::path::PathBuf {
    let candidates = [
        std::path::PathBuf::from("/app/config/tools.json"),
        std::path::PathBuf::from("config/tools.json"),
        crate::envfile::repo_root_static().join("config/tools.json"),
    ];
    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }
    candidates.into_iter().next_back().unwrap()
}

#[cfg(test)]
mod tests {
    use super::registry_shape_ok;
    use serde_json::json;

    // Round-trip safety regression (the WP-A5 finding): the gate that keeps
    // a stripped /tools/list-shaped payload from ever being written over
    // config/tools.json.

    #[test]
    fn full_registry_shape_passes() {
        assert!(registry_shape_ok(&json!({
            "core_tools": [{"type": "function", "function": {"name": "t"},
                            "tags": [], "speed": "fast",
                            "nats_subject": "worker.tool.t"}],
            "extended_tool_groups": {},
        })));
    }

    #[test]
    fn stripped_or_empty_payloads_are_refused() {
        // /tools/list shape ({tools:[...]}), empty registry, missing groups.
        assert!(!registry_shape_ok(&json!({"tools": [], "stats": {"total": 0}})));
        assert!(!registry_shape_ok(&json!({})));
        assert!(!registry_shape_ok(&json!({"core_tools": []})));
        assert!(!registry_shape_ok(&json!({
            "core_tools": [{"type": "function"}]
        })));
    }
}

#[cfg(test)]
mod kind_tests {
    use super::*;

    // /tools/list sends `is_base_tool: null` (routes/ui.rs); null must not
    // read as "specialized".
    #[test]
    fn null_base_flag_is_not_reported() {
        let t = serde_json::json!({"name": "web_search", "is_base_tool": null, "available_on_nodes": null});
        let k = tool_kind(&t, "base", "specialized");
        assert!(k.to_lowercase().contains("not reported"), "{k}");
        assert!(!k.contains("specialized"));
        assert_eq!(tool_kind(&serde_json::json!({"is_base_tool": true}), "base", "specialized"), "base");
        assert_eq!(tool_kind(&serde_json::json!({"is_base_tool": false}), "base", "specialized"), "specialized");
    }
}
