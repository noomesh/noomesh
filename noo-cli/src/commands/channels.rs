// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo channels …` — channel adapter inspection (Rust gateway route in
//! `routes/communication.rs`).
//!
//! Ported: status, test. `test` sends a REAL outbound message to a live
//! recipient (WhatsApp / Google Chat) — mutating by design, matching the
//! Python command exactly (no confirm in either implementation).

use crate::http::{get_json, post_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo channels status` — GET /api/channels/status.
pub fn channels_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/channels/status", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let Some(channels) = body["channels"].as_object().filter(|c| !c.is_empty()) else {
        println!("{}", ui::muted("no channel adapters"));
        return Ok(0);
    };
    println!("{}", ui::header("channels", Some(&format!("{} adapters", channels.len()))));
    println!("{}", ui::section("adapters"));
    let rows = status_rows(channels);
    print!(
        "{}",
        ui::table(&[Col::left(""), Col::left("channel"), Col::left("configured"), Col::left("traffic")], &rows)
    );
    Ok(0)
}

/// One row per adapter. The gateway keeps no per-channel counters (`stats` is
/// null), so say so rather than printing zeros; render counters only if a
/// future gateway sends them.
fn status_rows(channels: &serde_json::Map<String, serde_json::Value>) -> Vec<Vec<String>> {
    channels
        .iter()
        .map(|(name, info)| {
            let configured = info["configured"].as_bool().unwrap_or(false);
            let stats = &info["stats"];
            let traffic = if stats.is_object() {
                format!(
                    "{} received / {} sent / {} errors",
                    stats["received"].as_u64().unwrap_or(0),
                    stats["sent"].as_u64().unwrap_or(0),
                    stats["errors"].as_u64().unwrap_or(0)
                )
            } else {
                ui::muted("not tracked")
            };
            vec![
                ui::glyph_cell(if configured { Glyph::Ok } else { Glyph::Warn }),
                name.clone(),
                if configured { "yes (credentials set; not probed)".into() } else { "no".into() },
                traffic,
            ]
        })
        .collect()
}

/// `noo channels test CHANNEL RECIPIENT [--message/-m MSG]` —
/// POST /api/channels/test (Python parity: 30s timeout, default message
/// "Hello from PAI!"). A 2xx body with `success: false` renders the
/// embedded error and exits 1 (deliberate improvement over Python's exit 0).
pub fn channels_test(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut positionals: Vec<String> = Vec::new();
    let mut message = "Hello from PAI!".to_string();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--message" | "-m" => message = iter.next().ok_or(Unhandled)?.clone(),
            t if t.starts_with('-') => return Err(Unhandled),
            t => positionals.push(t.to_string()),
        }
    }
    let [channel, recipient] = positionals.as_slice() else { return Err(Unhandled) };
    let payload =
        serde_json::json!({ "channel": channel, "recipient": recipient, "message": message });
    let step = super::Spinner::start(g, &format!("sending test message via {channel}"));
    let body = post_json(g, "/api/channels/test", &payload, true, 30);
    if g.json {
        drop(step);
        println!("{body}");
        return Ok(0);
    }
    if body["success"].as_bool().unwrap_or(false) {
        step.done(Some(&format!("test message sent via {channel}")));
        ui::guide(&[("noo channels status", "delivery counters tick once the adapter confirms")]);
        Ok(0)
    } else {
        step.failed(
            &format!("send failed: {}", body["error"].as_str().unwrap_or("unknown error")),
            Some("noo channels status"),
        );
        Ok(1)
    }
}


// ── export / import ──────────────────────────────────────────────
// Channel STATE lives in three DB tables — user identity links
// (noo_user_channel_links), team ↔ space links (noo_channel_team_links) and
// the saved-recipient address book (noo_channel_recipients). Until this
// pair the only way to carry them across a fresh walk was a full DB
// restore; the 2026-09-01 host8 walk re-linked them by hand. Shaped like
// `noo heartbeat export/import`: one JSON document, idempotent import
// (ON CONFLICT upserts on the gateway side; recipients already present are
// skipped, not errors).

fn take_array(v: &serde_json::Value, key: &str) -> Vec<serde_json::Value> {
    v[key].as_array().cloned().unwrap_or_default()
}

/// `noo channels export [--output FILE]` — links, team spaces, recipients.
pub fn channels_export(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut output: Option<String> = None;
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--output" | "-o" => output = Some(it.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let users_doc = crate::http::get_json(g, "/api/security/users", true, 10);
    let mut users: Vec<serde_json::Value> = Vec::new();
    for u in take_array(&users_doc, "users") {
        let Some(name) = u["username"].as_str() else { continue };
        let links_doc = crate::http::get_json(g, &format!("/api/security/users/{name}/links"), true, 10);
        let links: Vec<serde_json::Value> = take_array(&links_doc, "links")
            .into_iter()
            .map(|l| serde_json::json!({
                "channel": l["channel"], "channel_user_id": l["channel_user_id"],
                "display_name": l["display_name"],
            }))
            .collect();
        if !links.is_empty() {
            users.push(serde_json::json!({ "username": name, "links": links }));
        }
    }
    let teams_doc = crate::http::get_json(g, "/api/security/teams", true, 10);
    let mut teams: Vec<serde_json::Value> = Vec::new();
    for t in take_array(&teams_doc, "teams") {
        let Some(name) = t["name"].as_str() else { continue };
        let spaces_doc = crate::http::get_json(g, &format!("/api/security/teams/{name}/spaces"), true, 10);
        let spaces: Vec<serde_json::Value> = take_array(&spaces_doc, "spaces")
            .into_iter()
            .map(|s| serde_json::json!({ "channel": s["channel"], "space_id": s["space_id"] }))
            .collect();
        teams.push(serde_json::json!({
            "name": name, "description": t["description"], "spaces": spaces,
        }));
    }
    let rec_doc = crate::http::get_json(g, "/api/channels/saved-recipients", true, 10);
    let recipients: Vec<serde_json::Value> = take_array(&rec_doc, "recipients")
        .into_iter()
        .map(|r| serde_json::json!({
            "channel": r["channel"], "recipient_id": r["recipient_id"],
            "display_name": r["display_name"], "notes": r["notes"],
            "is_default": r["is_default"], "metadata": r["metadata"],
        }))
        .collect();
    let doc = serde_json::json!({ "users": users, "teams": teams, "recipients": recipients });
    let text = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| doc.to_string());
    let summary = format!(
        "{} user link set(s), {} team(s), {} recipient(s)",
        users.len(), teams.len(), recipients.len()
    );
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, text + "\n") {
                ui::failed(&format!("could not write {path}: {e}"), None);
                return Ok(1);
            }
            ui::done(&format!("exported {summary} to {path}"));
            ui::value(&path);
            ui::guide(&[(&format!("noo channels import {path}"), "restore these links and recipients on another controller")]);
        }
        None => ui::value(&text),
    }
    Ok(0)
}

/// `noo channels import FILE` — replays an export. Users must already
/// exist (links are identity claims; creating accounts is a security
/// decision, not an import side effect); teams are created when missing.
pub fn channels_import(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [file] = args else { return Err(Unhandled) };
    if file.starts_with('-') {
        return Err(Unhandled);
    }
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            ui::failed(&format!("could not read {file}: {e}"), None);
            return Ok(1);
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            ui::failed(
                &format!("{file} is not valid JSON: {e}"),
                Some("noo channels export --output <file>  (the expected shape: {\"users\": [...], \"teams\": [...], \"recipients\": [...]})"),
            );
            return Ok(1);
        }
    };
    if !g.json {
        ui::step(&format!("importing channel state from {file}"));
    }
    let mut ok = 0usize;
    let mut skipped = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for u in take_array(&doc, "users") {
        let Some(name) = u["username"].as_str() else { continue };
        for l in take_array(&u, "links") {
            let label = format!("link {name} ← {}:{}", l["channel"].as_str().unwrap_or("?"),
                l["channel_user_id"].as_str().unwrap_or("?"));
            match crate::http::post_json_try(g, &format!("/api/security/users/{name}/links"), &l, true, 10) {
                Ok(_) => ok += 1,
                Err(e) if e.contains("404") || e.contains("not found") =>
                    failed.push(format!("{label}: user '{name}' does not exist — noo security user create {name}, then re-import")),
                Err(e) => failed.push(format!("{label}: {e}")),
            }
        }
    }
    for t in take_array(&doc, "teams") {
        let Some(name) = t["name"].as_str() else { continue };
        let create = serde_json::json!({ "name": name, "description": t["description"] });
        // Existing team → conflict/400 from the gateway; that is the idempotent path.
        let _ = crate::http::post_json_try(g, "/api/security/teams", &create, true, 10);
        for s in take_array(&t, "spaces") {
            let label = format!("space {}:{} → team {name}", s["channel"].as_str().unwrap_or("?"),
                s["space_id"].as_str().unwrap_or("?"));
            match crate::http::post_json_try(g, &format!("/api/security/teams/{name}/spaces"), &s, true, 10) {
                Ok(_) => ok += 1,
                Err(e) => failed.push(format!("{label}: {e}")),
            }
        }
    }
    for r in take_array(&doc, "recipients") {
        let label = format!("recipient {}:{}", r["channel"].as_str().unwrap_or("?"),
            r["recipient_id"].as_str().unwrap_or("?"));
        match crate::http::post_json_try(g, "/api/channels/saved-recipients", &r, true, 10) {
            Ok(_) => ok += 1,
            Err(e) if e.contains("409") || e.contains("already exists") => skipped += 1,
            Err(e) => failed.push(format!("{label}: {e}")),
        }
    }
    if g.json {
        println!("{}", serde_json::json!({
            "imported": ok, "skipped": skipped, "failed": failed.len(), "errors": failed,
        }));
    } else if failed.is_empty() {
        ui::done(&format!("imported {ok} item(s), {skipped} already present"));
        ui::guide(&[
            ("noo channels status", "adapters and the links they now carry"),
            ("noo channels test <channel> <recipient>", "prove one imported recipient end to end"),
        ]);
    } else {
        ui::failed(&format!("imported {ok} item(s), {skipped} already present, {} failed", failed.len()), None);
        for f in &failed {
            eprintln!("  {}", ui::muted(f));
        }
        ui::guide(&[("noo channels status", "what did land")]);
    }
    Ok(if failed.is_empty() { 0 } else { 1 })
}

#[cfg(test)]
mod status_tests {
    use super::*;

    // Reply shape from gateway-rust communication.rs channels_status.
    #[test]
    fn null_stats_render_as_not_tracked_not_zeros() {
        let body = serde_json::json!({"channels_registered": 1, "channels": {
            "telegram": {"configured": true, "registered": null, "stats": null,
                         "stats_detail": "not tracked"}},
            "active_conversations": null, "queue_mode": "native"});
        let rows = status_rows(body["channels"].as_object().unwrap());
        let line = rows[0].join(" ");
        assert!(line.contains("not tracked"), "{line}");
        assert!(!line.contains("0 received"), "{line}");
    }
}
