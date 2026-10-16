// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo usage` — token-usage summary.
//!
//! Thin HTTP GET over the gateway's `/api/usage/summary`: per-month
//! (default: the current calendar month), all-time, grouped by node /
//! model / backend / source / user / consumer / day. `--json` prints the raw gateway
//! envelope.

use crate::http::get_json;
use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};
use crate::ui::{self, Col};

/// True for the exact `YYYY-MM` shape the gateway accepts. Validated
/// locally so a typo fails with a usage error instead of a remote 400.
fn valid_month(s: &str) -> bool {
    let Some((y, m)) = s.split_once('-') else {
        return false;
    };
    y.len() == 4
        && m.len() == 2
        && y.chars().all(|c| c.is_ascii_digit())
        && matches!(m.parse::<u32>(), Ok(1..=12))
}

/// The gateway's group whitelist, mirrored locally (same reason as
/// `valid_month`): a typo fails with a usage error instead of a remote 400.
/// "day" groups raw rows only — the monthly rollup has no day grain.
fn valid_group(g: &str) -> bool {
    matches!(g, "node" | "model" | "backend" | "source" | "user" | "consumer" | "day")
}

/// Header of the grouping column: the dimension itself.
fn group_col(group: &str) -> &'static str {
    match group {
        "node" => "node",
        "model" => "model",
        "backend" => "backend",
        "source" => "source",
        "user" => "user",
        "consumer" => "consumer",
        _ => "day",
    }
}

/// Build the summary path from parsed flags (pure, for tests).
fn summary_path(month: Option<&str>, all_time: bool, group: &str) -> String {
    let window = match (month, all_time) {
        (Some(m), _) => m,
        (None, true) => "all",
        (None, false) => "month",
    };
    format!("/api/usage/summary?window={window}&group={group}")
}

/// `noo usage [--month YYYY-MM | --all-time] [--group node|model|backend|source|user|consumer|day]`
/// GET /api/usage/summary.
pub fn usage(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut month: Option<String> = None;
    let mut all_time = false;
    let mut group = "node".to_string();
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--month" | "-m" => month = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--all-time" => all_time = true,
            "--group" | "-g" => group = iter.next().ok_or(Unhandled)?.clone(),
            _ => return Err(Unhandled),
        }
    }
    if let Some(m) = &month {
        if !valid_month(m) {
            fail(g.json, ExitCode::Usage, "usage",
                 &format!("invalid --month '{m}' (expected YYYY-MM)"), None);
        }
        if all_time {
            fail(g.json, ExitCode::Usage, "usage",
                 "--month and --all-time are mutually exclusive", None);
        }
    }
    if !valid_group(&group) {
        fail(g.json, ExitCode::Usage, "usage",
             &format!("invalid --group '{group}' (expected node|model|backend|source|user|consumer|day)"), None);
    }

    let body = get_json(g, &summary_path(month.as_deref(), all_time, &group), true, 10);
    if g.json {
        println!("{body}");
        return Ok(super::json_exit(&body));
    }

    let empty = Vec::new();
    let rows = body["rows"].as_array().unwrap_or(&empty);
    if rows.is_empty() {
        println!("{}", ui::muted(&format!("no usage recorded for window '{}'", body["window"].as_str().unwrap_or("?"))));
        return Ok(0);
    }
    let window = body["window"].as_str().unwrap_or("?");
    println!("{}", ui::header("usage", Some(&format!("window {window} · by {group}"))));
    println!("{}", ui::section("tokens"));
    let mut table: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let prompt = r["prompt_tokens"].as_i64().unwrap_or(0);
            let completion = r["completion_tokens"].as_i64().unwrap_or(0);
            let key = r["key"].as_str().unwrap_or("?");
            vec![
                super::truncate(key, 24),
                prompt.to_string(),
                completion.to_string(),
                (prompt + completion).to_string(),
                r["requests"].as_i64().unwrap_or(0).to_string(),
            ]
        })
        .collect();
    let t = &body["totals"];
    let (tp, tc) = (
        t["prompt_tokens"].as_i64().unwrap_or(0),
        t["completion_tokens"].as_i64().unwrap_or(0),
    );
    table.push(vec![
        ui::emph("total"),
        ui::emph(&tp.to_string()),
        ui::emph(&tc.to_string()),
        ui::emph(&(tp + tc).to_string()),
        ui::emph(&t["requests"].as_i64().unwrap_or(0).to_string()),
    ]);
    let group_col = group_col(&group);
    print!(
        "{}",
        ui::table(
            &[Col::left(group_col), Col::right("prompt"), Col::right("completion"), Col::right("total"), Col::right("reqs")],
            &table
        )
    );
    // e.g. "day grain covers the raw retention window only" for
    // --all-time --group day; monthly rollups have no per-day rows.
    if let Some(n) = body["note"].as_str() {
        println!("  {}", ui::muted(n));
    }
    Ok(0)
}

/// The period words the gateway accepts for `usage me` and allowances.
pub(crate) fn valid_period(p: &str) -> bool {
    matches!(p, "day" | "week" | "month")
}

/// One column of `usage me`: label, prompt, completion, total, requests, cost.
fn column_row(label: &str, c: &serde_json::Value) -> Vec<String> {
    let cost = c["cost_usd"].as_f64().unwrap_or(0.0);
    let unpriced = c["unpriced_tokens"].as_i64().unwrap_or(0);
    vec![
        label.to_string(),
        c["prompt_tokens"].as_i64().unwrap_or(0).to_string(),
        c["completion_tokens"].as_i64().unwrap_or(0).to_string(),
        c["total_tokens"].as_i64().unwrap_or(0).to_string(),
        c["requests"].as_i64().unwrap_or(0).to_string(),
        if cost == 0.0 && unpriced > 0 { "-".to_string() } else { format!("${cost:.4}") },
    ]
}

/// The report's columns as table rows: node, cloud, then one per harness
/// kind — each its own row, never summed into another (pure, for tests).
pub(crate) fn me_rows(body: &serde_json::Value) -> Vec<Vec<String>> {
    let mut rows = vec![column_row("node", &body["node"]), column_row("cloud", &body["cloud"])];
    if let Some(h) = body["harness"].as_array() {
        for k in h {
            rows.push(column_row(&format!("harness:{}", k["kind"].as_str().unwrap_or("?")), k));
        }
    }
    rows
}

/// `noo usage me [--period day|week|month] [--user <u>]` — GET /api/usage/me.
pub fn usage_me(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut period: Option<String> = None;
    let mut user: Option<String> = None;
    let mut iter = args.iter();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "--period" | "-p" => period = Some(iter.next().ok_or(Unhandled)?.clone()),
            "--user" | "-u" => user = Some(iter.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    if let Some(p) = &period {
        if !valid_period(p) {
            fail(g.json, ExitCode::Usage, "usage", &format!("invalid --period '{p}' (expected day|week|month)"), None);
        }
    }
    let mut path = "/api/usage/me".to_string();
    let mut sep = '?';
    if let Some(p) = &period {
        path.push_str(&format!("{sep}period={p}"));
        sep = '&';
    }
    if let Some(u) = &user {
        path.push_str(&format!("{sep}user={}", super::urlencode(u)));
    }
    let body = get_json(g, &path, true, 10);
    if g.json {
        println!("{body}");
        return Ok(super::json_exit(&body));
    }
    let who = body["user"].as_str().unwrap_or("?");
    let period = body["period"].as_str().unwrap_or("month");
    println!("{}", ui::header("usage", Some(&format!("{who} · this {period}"))));
    println!("{}", ui::section("tokens by where they ran"));
    print!(
        "{}",
        ui::table(
            &[Col::left("ran on"), Col::right("prompt"), Col::right("completion"), Col::right("total"), Col::right("reqs"), Col::right("cost")],
            &me_rows(&body)
        )
    );
    println!("  {}", ui::muted(&format!("spent {} tokens in all", body["spent"].as_i64().unwrap_or(0))));
    println!("{}", ui::section("allowance"));
    match body["allowance"].as_object() {
        Some(a) => println!(
            "  {} of {} tokens this {} — {} left",
            a.get("spent").and_then(|v| v.as_i64()).unwrap_or(0),
            a.get("limit").and_then(|v| v.as_i64()).unwrap_or(0),
            a.get("period").and_then(|v| v.as_str()).unwrap_or("month"),
            a.get("remaining").and_then(|v| v.as_i64()).unwrap_or(0)
        ),
        None => println!("  {}", ui::muted("none set — no standing cap")),
    }
    Ok(0)
}

#[cfg(test)]
mod me_tests {
    use super::*;
    use serde_json::json;

    /// Node, cloud and each harness kind are separate rows; nothing adds
    /// them into one another.
    #[test]
    fn node_cloud_and_harness_are_separate_rows() {
        let body = json!({
            "node": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110, "requests": 2, "cost_usd": 0.0, "unpriced_tokens": 110},
            "cloud": {"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200, "requests": 1, "cost_usd": 0.012, "unpriced_tokens": 0},
            "harness": [{"kind": "copilot", "prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10, "requests": 1, "cost_usd": 0.0, "unpriced_tokens": 10}],
            "spent": 1320,
        });
        let rows = me_rows(&body);
        let labels: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
        assert_eq!(labels, ["node", "cloud", "harness:copilot"]);
        assert_eq!(rows[0][3], "110");
        assert_eq!(rows[1][3], "1200");
        assert_eq!(rows[1][5], "$0.0120");
        assert_eq!(rows[0][5], "-", "unpriced is not $0");
    }

    #[test]
    fn periods_are_day_week_month() {
        for p in ["day", "week", "month"] {
            assert!(valid_period(p));
        }
        assert!(!valid_period("year") && !valid_period("Month"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_validation_is_strict_yyyy_mm() {
        assert!(valid_month("2026-08"));
        assert!(valid_month("2026-12"));
        // Everything the gateway would 400 on fails locally first.
        assert!(!valid_month("2026-13"));
        assert!(!valid_month("2026-0"));
        assert!(!valid_month("26-08"));
        assert!(!valid_month("2026/08"));
        assert!(!valid_month("august"));
    }

    #[test]
    fn group_validation_matches_the_gateway_whitelist() {
        for ok in ["node", "model", "backend", "source", "user", "consumer", "day"] {
            assert!(valid_group(ok), "{ok} is a gateway-accepted group");
        }
        // Everything the gateway would 400 on fails locally first.
        for bad in ["days", "Day", "users", "ts", "node,model", ""] {
            assert!(!valid_group(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn summary_path_encodes_the_window_precedence() {
        assert_eq!(summary_path(None, false, "node"),
                   "/api/usage/summary?window=month&group=node");
        assert_eq!(summary_path(None, true, "model"),
                   "/api/usage/summary?window=all&group=model");
        assert_eq!(summary_path(Some("2026-07"), false, "backend"),
                   "/api/usage/summary?window=2026-07&group=backend");
    }

    #[test]
    fn unknown_flags_fall_through_to_python() {
        let g = Globals {
            json: false,
            verbose: false,
            gateway_override: None,
            timeout_secs: None,
            token: None,
            quiet: false,
        };
        let args = vec!["--bogus".to_string()];
        assert!(usage(&g, &args).is_err(), "unknown flag must return Unhandled");
    }
}
