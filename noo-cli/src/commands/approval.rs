// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo approval …` — tool-execution approval queue.
//!
//! Ported: list/pending, stats, status (reads) and approve/deny (writes).
//! The write side goes through POST /api/approval/{id}/decide (WP-4a) —
//! the gateway accepts the CLI's cluster-HMAC bearer there under
//! host-operator trust and audit-logs the decision. This replaced the
//! Python CLI's direct-SQL UPDATE, so no CLI path touches the DB anymore.

use super::truncate;
use crate::args::{ArgError, Args};
use crate::http::{get_json, post_json};
use crate::output::ExitCode;
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo approval list` (alias: `pending`) — GET /api/approval/pending.
pub fn approval_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/approval/pending", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let items = body["pending"]
        .as_array()
        .or_else(|| body["requests"].as_array())
        .or_else(|| body.as_array())
        .unwrap_or(&empty);
    if items.is_empty() {
        println!("{}", ui::muted("no pending approval requests"));
        return Ok(0);
    }
    println!("{}", ui::header("approvals", Some(&format!("{} pending", items.len()))));
    println!("{}", ui::section("pending"));
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|r| {
            let id = r["request_id"].as_str().or_else(|| r["id"].as_str()).unwrap_or("?");
            let risk = r["risk_level"].as_str().unwrap_or("?");
            let (glyph, risk_text) = match risk {
                "high" | "critical" => (Glyph::Err, ui::err(risk)),
                "medium" => (Glyph::Warn, ui::warn(risk)),
                _ => (Glyph::Bullet, risk.to_string()),
            };
            // Unattended turns (heartbeat, autonomy) have no requester and
            // no conversation. Say so rather than printing a blank cell —
            // "who asked for this" is the question the column exists for.
            let requester = r["requester"].as_str().unwrap_or("");
            let requester = if requester.is_empty() {
                ui::muted("unattended")
            } else {
                requester.to_string()
            };
            let conversation = r["conversation_id"].as_str().unwrap_or("");
            let where_ = match (r["channel"].as_str().unwrap_or(""), conversation) {
                ("", "") => ui::muted("—"),
                (ch, "") => ch.to_string(),
                ("", c) => truncate(c, 20),
                (ch, c) => format!("{ch} {}", ui::muted(&truncate(c, 12))),
            };
            vec![
                ui::glyph_cell(glyph),
                ui::muted(&truncate(id, 14)),
                truncate(r["tool_name"].as_str().unwrap_or("?"), 20),
                risk_text,
                requester,
                where_,
                truncate(r["reason"].as_str().unwrap_or(""), 40),
                r["created_at"].as_str().unwrap_or("").chars().take(19).collect::<String>(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("id"),
                Col::left("tool"),
                Col::left("risk"),
                Col::left("requester"),
                Col::left("where"),
                Col::left("reason"),
                Col::left("created"),
            ],
            &rows,
        )
    );
    ui::guide(&[
        ("noo approval approve <id>", "let the waiting tool call proceed"),
        ("noo approval deny <id> --reason <text>", "refuse it; the reason is shown to the agent"),
        ("noo approval pending", "the pending requests with their ids and tool arguments"),
    ]);
    Ok(0)
}

/// `noo approval stats` — GET /api/approval/stats.
pub fn approval_stats(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/approval/stats", true, 10);
    if g.json {
        println!("{body}");
        return Ok(super::json_exit(&body));
    }
    // The gateway now nulls every count and sets `error` when it cannot read
    // the approval queue, rather than answering "pending: 0". Relay that as an
    // error — a silent "0 pending" on a security queue is how a stuck approval
    // goes unnoticed.
    if let Some(err) = body["error"].as_str() {
        ui::failed(&format!("cannot read approval stats: {err}"), None);
        return Ok(ExitCode::RemoteError as i32);
    }
    println!("{}", ui::header("approval stats", None));
    // Same key order as the Python rendering; skip keys the gateway omits.
    let mut rows: Vec<(&str, String)> = Vec::new();
    for key in ["total", "approved", "denied", "pending", "timed_out", "expired"] {
        match body.get(key) {
            None => {}
            Some(serde_json::Value::Null) => rows.push((key, ui::warn("unknown"))),
            Some(v) => rows.push((key, v.to_string())),
        }
    }
    print!("{}", ui::kv(&rows));
    Ok(0)
}

/// `noo approval status` — GET /api/exec-approval/status (system status).
pub fn approval_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/exec-approval/status", true, 10);
    if g.json {
        println!("{body}");
    } else {
        // Parity with Python's console.print_json: arbitrary status object.
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string()));
    }
    Ok(0)
}

/// `noo approval approve REQUEST_ID` — POST /api/approval/{id}/decide.
///
/// Python parity: success prints the "waiting tool call proceeds" line;
/// already-decided / unknown ids surface as the gateway's 404/409 via the
/// standard remote_error exit (5).
pub fn approval_approve(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    decide(g, args, "approve")
}

/// `noo approval deny REQUEST_ID [--reason/-r TEXT]` — POST /api/approval/{id}/decide.
pub fn approval_deny(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    decide(g, args, "deny")
}

/// `--reason/-r` is deny-only, matching the Python flag surface: on approve it
/// stays an unknown flag.
pub(crate) fn parse_decide_with(a: &mut Args, deny: bool) -> Result<(String, Option<String>), ArgError> {
    let reason = if deny { a.value(&["--reason", "-r"])? } else { None };
    let request_id = a.one("<request-id>")?;
    Ok((request_id, reason))
}

fn decide(g: &Globals, args: &[String], decision: &str) -> Result<i32, Unhandled> {
    let (request_id, reason) = parse_decide_with(&mut Args::new(args), decision == "deny")?;

    let mut body = serde_json::json!({ "decision": decision });
    if let Some(r) = &reason {
        body["reason"] = serde_json::json!(r);
    }
    let resp = post_json(
        g,
        &format!("/api/approval/{}/decide", super::urlencode(&request_id)),
        &body,
        true,
        10,
    );
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    match resp["status"].as_str() {
        Some("approved") => ui::done(&format!("approved {request_id} — the waiting tool call proceeds")),
        Some("denied") => ui::done(&format!("denied {request_id} — the caller gets the denial")),
        _ => println!("{resp}"),
    }
    ui::guide(&[
        ("noo approval list", "anything else still waiting"),
        ("noo approval stats", "counts now reflecting this decision"),
    ]);
    Ok(0)
}
