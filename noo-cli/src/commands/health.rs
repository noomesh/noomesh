// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo health` — gateway liveness.

use crate::http::get_json;
use crate::output::ExitCode;
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo health` — gateway liveness. Exit 0 iff reachable AND healthy.
///
/// The gateway's `/health` (gateway-rust `routes/core.rs`) answers HTTP 200
/// with `status: "degraded"` and a per-dependency `dependencies` map when
/// Postgres/NATS/Redis are down. This used to return Ok(0) unconditionally
/// and discard `dependencies` — so `noo health` exited 0 on a gateway that
/// had lost its database, and never said which dependency was down.
pub fn health(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    // AUTHENTICATED. `/health` answers anyone, but it only itemises the
    // dependencies for a credential — the anonymous body is liveness and
    // nothing else. Without this the dependency table silently vanished
    // for a logged-in operator.
    let body = get_json(g, "/health", true, 10);
    let status = body["status"].as_str().unwrap_or("unknown");
    let healthy = matches!(status, "healthy" | "ok");
    if g.json {
        println!("{body}");
    } else {
        let host = crate::role::detect().label();
        println!("{}", ui::header("gateway", Some(&format!("host {host}"))));
        print!("{}", ui::kv(&[("status", ui::state(status))]));
        if body["dependencies"].as_object().is_none() {
            // Say why the table is missing rather than showing status alone
            // and letting the reader wonder what happened to it.
            println!(
                "{}",
                ui::muted("dependencies need a credential — run `noo auth login` to see them")
            );
        }
        if let Some(deps) = body["dependencies"].as_object() {
            println!("{}", ui::section("dependencies"));
            let rows: Vec<Vec<String>> = deps
                .iter()
                .map(|(name, d)| {
                    let (glyph, word) = match d["healthy"].as_bool() {
                        Some(true) => (Glyph::Ok, "ok"),
                        Some(false) => (Glyph::Err, "down"),
                        None => (Glyph::Warn, "not reported"),
                    };
                    let note = if d["optional"].as_bool().unwrap_or(false) { "optional" } else { "" };
                    vec![ui::glyph_cell(glyph), name.clone(), ui::state(word), note.to_string()]
                })
                .collect();
            print!("{}", ui::table(&[Col::left(""), Col::left("dependency"), Col::left("state"), Col::left("")], &rows));
        }
        if !healthy {
            let down: Vec<String> = body["dependencies"]
                .as_object()
                .map(|m| m.iter().filter(|(_, d)| d["healthy"].as_bool() == Some(false)).map(|(n, _)| n.clone()).collect())
                .unwrap_or_default();
            let logs: Vec<String> = down.iter().map(|d| format!("noo stack logs {d}")).collect();
            let mut entries: Vec<(&str, &str)> = vec![("noo stack status", "shows which container is not running")];
            for l in &logs {
                entries.push((l.as_str(), "the dependency's own log usually names the cause"));
            }
            entries.push(("noo doctor docker", "if containers look damaged after an unclean shutdown"));
            ui::guide(&entries);
        }
    }
    Ok(if healthy { 0 } else { ExitCode::RemoteError as i32 })
}
