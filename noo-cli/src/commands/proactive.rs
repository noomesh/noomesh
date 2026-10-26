// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo proactive …` — proactive agent loop (Rust gateway routes in
//! `routes/ui.rs`).
//!
//! Ported: status, rules. `history` is a retired stub (i195 D2): nothing
//! records proactive firings; `status` carries the "history: not tracked" row.
//! Left in Python: nothing else exists in the Python group (rule create /
//! delete are dashboard/API surfaces, not CLI commands).

use super::truncate;
use crate::http::get_json;
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

/// `noo proactive status` — GET /api/proactive/status.
pub fn proactive_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/proactive/status", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    // `history_entries` is not a measurement the gateway takes — it is
    // reported as null when no firing history is tracked. `.unwrap_or(0)`
    // rendered that as "history: 0 entries", i.e. "the agent has never
    // fired". Print "not tracked" when the gateway does not report a count.
    let mut history = match body["history_entries"].as_u64() {
        Some(n) => format!("{n} entries"),
        None => ui::warn("not tracked"),
    };
    if let Some(detail) = body["history_detail"].as_str() {
        history = format!("{history}  {}", ui::muted(detail));
    }
    println!(
        "{}",
        ui::header(
            "proactive agent",
            Some(&rules_enabled_text(&body))
        )
    );
    print!(
        "{}",
        ui::kv(&[
            (
                "agent",
                match body["running"].as_bool() {
                    Some(true) => ui::state("running"),
                    Some(false) => ui::state("stopped"),
                    None => ui::warn("unknown"),
                },
            ),
            ("history", history),
        ])
    );
    Ok(0)
}

/// "3/5 rules enabled", or "rules enabled: not reported" when the gateway
/// sent either count as anything but a number (i191 D5: absent is not 0).
fn rules_enabled_text(body: &serde_json::Value) -> String {
    match (body["rules_enabled"].as_u64(), body["rules_total"].as_u64()) {
        (Some(on), Some(total)) => format!("{on}/{total} rules enabled"),
        _ => format!("rules enabled: {}", ui::state("not reported")),
    }
}

/// "30s", or "not reported" for a rule that carries no cooldown figure.
fn cooldown_cell(rule: &serde_json::Value) -> String {
    match rule["cooldown_seconds"].as_u64() {
        Some(n) => format!("{n}s"),
        None => ui::state("not reported"),
    }
}

/// `noo proactive rules` — GET /api/proactive/rules.
pub fn proactive_rules(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/proactive/rules", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let rules = body["rules"].as_array().unwrap_or(&empty);
    if rules.is_empty() {
        println!("{}", ui::muted("no proactive rules"));
        return Ok(0);
    }
    let enabled = rules.iter().filter(|r| r["enabled"].as_bool().unwrap_or(false)).count();
    println!("{}", ui::header("proactive rules", Some(&format!("{} rules · {enabled} enabled", rules.len()))));
    println!("{}", ui::section("rules"));
    let rows: Vec<Vec<String>> = rules
        .iter()
        .map(|r| {
            let trigger = format!(
                "{}:{}",
                r["trigger_type"].as_str().unwrap_or(""),
                r["trigger_pattern"].as_str().unwrap_or("")
            );
            let channels = r["channel_targets"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            let on = r["enabled"].as_bool().unwrap_or(false);
            vec![
                ui::glyph_cell(if on { Glyph::Ok } else { Glyph::Bullet }),
                ui::muted(&truncate(r["id"].as_str().unwrap_or("?"), 14)),
                truncate(r["name"].as_str().unwrap_or("?"), 22),
                truncate(&trigger, 30),
                truncate(r["action_type"].as_str().unwrap_or(""), 14),
                truncate(&channels, 20),
                cooldown_cell(r),
                if on { "on".into() } else { ui::muted("off") },
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("id"),
                Col::left("name"),
                Col::left("trigger"),
                Col::left("action"),
                Col::left("channels"),
                Col::right("cooldown"),
                Col::left("state"),
            ],
            &rows,
        )
    );
    Ok(0)
}

/// `noo proactive history` — RETIRED (i195 D2). Nothing records proactive
/// firings (the route's table has no migration and no writer; the agent keeps
/// firings in process memory), so the verb could only report that. `status`
/// already carries the "history: not tracked" row. (Kept in dispatch for one
/// release so an old runbook gets this answer instead of "unknown command".)
pub fn proactive_history(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Generic,
        "retired_command",
        "history is retired: nothing records proactive firings, so there is no history to show",
        Some("agent state and rule counts:  noo proactive status"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_rule_counts_are_not_reported_not_zero() {
        let t = rules_enabled_text(&serde_json::json!({"rules_total": 4}));
        assert!(t.contains("Not reported") && !t.contains('0') && !t.contains("0/"), "{t}");
        assert_eq!(rules_enabled_text(&serde_json::json!({"rules_enabled": 0, "rules_total": 4})), "0/4 rules enabled");
        let c = cooldown_cell(&serde_json::json!({"id": "r1"}));
        assert!(c.contains("Not reported") && !c.contains('0'), "{c}");
        assert_eq!(cooldown_cell(&serde_json::json!({"cooldown_seconds": 30})), "30s");
    }
}
