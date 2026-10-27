// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo logs …` — log review. `errors`, `tail` and `search` are the three
//! review verbs (POST /api/logs/errors|tail|search in `routes/admin.rs`,
//! Loki-backed with a node-agent scan fallback for the first two, and the
//! answer says which backend spoke); containers/query/status are the
//! native Rust gateway routes in the same file. Every verb needs an
//! Operator or Admin login.

use super::{term_width, truncate, urlencode};
use crate::http::{get_json, post_json};
use crate::ui::{self, Col};
use crate::args::{ArgError, Args};
use crate::{Globals, Unhandled};

/// Set `body[key]` to the flag's value when it was given.
fn put_str(body: &mut serde_json::Value, key: &str, v: Option<String>) {
    if let Some(v) = v {
        body[key] = v.into();
    }
}

/// Set `body[key]` to the flag's number when it was given.
fn put_num(body: &mut serde_json::Value, key: &str, v: Option<u64>) {
    if let Some(v) = v {
        body[key] = v.into();
    }
}

/// The muted last line of every review verb: which backend answered.
/// A node-agent scan is a partial view and must never read as the fleet
/// one, so the fallback is named — with Loki's reason when the gateway
/// gave one.
fn backend_footer(resp: &serde_json::Value) -> String {
    match resp["backend"].as_str() {
        Some("loki") => "via loki".to_string(),
        Some("agent-scan") => match resp["loki_error"].as_str() {
            Some(why) if !why.is_empty() => format!("via agent scan (Loki not reachable: {why})"),
            _ => "via agent scan (Loki not reachable)".to_string(),
        },
        _ => "via agent scan (Loki not reachable)".to_string(),
    }
}

/// Parsed `noo logs errors` flags → the request body.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ErrorsArgs {
    body: serde_json::Value,
}

fn parse_errors_args(args: &[String]) -> Result<ErrorsArgs, ArgError> {
    parse_errors_with(&mut Args::new(args))
}

pub(crate) fn parse_errors_with(a: &mut Args) -> Result<ErrorsArgs, ArgError> {
    let mut body = serde_json::json!({});
    put_str(&mut body, "container", a.value(&["--container", "-c"])?);
    put_num(&mut body, "minutes", a.number::<u64>(&["--minutes", "-m"])?);
    put_num(&mut body, "limit", a.number::<u64>(&["--limit", "-n"])?);
    put_str(&mut body, "node", a.value(&["--node"])?);
    put_str(&mut body, "name", a.value(&["--name"])?);
    put_str(&mut body, "source", a.value(&["--source"])?);
    put_str(&mut body, "since", a.value(&["--since"])?);
    put_str(&mut body, "until", a.value(&["--until"])?);
    a.finish()?;
    Ok(ErrorsArgs { body })
}

/// `noo logs errors [-c C] [-m M] [-n N] [--node ID] [--name N] [--source S] [--since T] [--until T]`
/// POST /api/logs/errors — recent warning/error lines across the fleet.
pub fn logs_errors(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let ErrorsArgs { body } = parse_errors_args(args)?;
    // The fallback scans up to every noomesh container's tail — slow; match the worker chain.
    let resp = post_json(g, "/api/logs/errors", &body, true, 120);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let empty = Vec::new();
    let matches = resp["matches"].as_array().unwrap_or(&empty);
    let window = resp["window_minutes"].as_u64().unwrap_or(0);
    if matches.is_empty() {
        println!("{}", ui::muted(&format!("no errors or warnings in the last {window}m")));
        println!("{}", ui::muted(&backend_footer(&resp)));
        return Ok(0);
    }
    let width = term_width();
    let fleet = body.get("node").is_none();
    for m in matches {
        let container = m["container"].as_str().unwrap_or("?");
        let line = m["line"].as_str().unwrap_or("").trim_end();
        let row = match (m["ts"].as_str(), m["node"].as_str()) {
            // A Loki line carries its time; the scan's lines carry only what the container printed.
            (Some(ts), Some(node)) if fleet => format!("{} {node:<10} {container:<14} {line}", short_ts(ts)),
            (Some(ts), _) => format!("{} {container:<14} {line}", short_ts(ts)),
            _ => format!("{container:<18} {line}"),
        };
        println!("{}", truncate(&row, width));
    }
    let scanned = match resp["scanned"].as_u64() {
        Some(n) => format!(", {n} container(s) scanned"),
        None => String::new(),
    };
    let more = if resp["truncated"].as_bool().unwrap_or(false) { " (limit reached; raise -n or narrow)" } else { "" };
    println!(
        "{}",
        ui::muted(&format!("{} match(es), last {}m{scanned}{more}", matches.len(), window))
    );
    println!("{}", ui::muted(&backend_footer(&resp)));
    Ok(0)
}

/// `2026-09-28T14:02:07.123Z` → `14:02:07` when the day is today's; the
/// full stamp otherwise. A review of "14:02" wants the clock, not the date.
fn short_ts(ts: &str) -> String {
    let today = chrono_free_today();
    match ts.split_once('T') {
        Some((day, rest)) if day == today => rest.split('.').next().unwrap_or(rest).trim_end_matches('Z').to_string(),
        _ => ts.split('.').next().unwrap_or(ts).trim_end_matches('Z').to_string(),
    }
}

/// Today's UTC date as `YYYY-MM-DD`, without a date crate: the CLI has none.
fn chrono_free_today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    civil_from_days((secs / 86_400) as i64)
}

/// Howard Hinnant's days → civil, for the date only.
fn civil_from_days(z: i64) -> String {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Parsed `noo logs tail` surface.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct TailArgs {
    container: Option<String>,
    body: serde_json::Value,
}

fn parse_tail_args(args: &[String]) -> Result<TailArgs, ArgError> {
    parse_tail_with(&mut Args::new(args))
}

pub(crate) fn parse_tail_with(a: &mut Args) -> Result<TailArgs, ArgError> {
    let mut body = serde_json::json!({});
    let flag_container = a.value(&["--container", "-c"])?;
    put_num(&mut body, "lines", a.number::<u64>(&["--lines", "--limit", "-l"])?);
    // `-n` = node, matching the Python `noo logs tail` surface.
    put_str(&mut body, "node", a.value(&["--node", "-n"])?);
    put_str(&mut body, "name", a.value(&["--name"])?);
    put_str(&mut body, "source", a.value(&["--source"])?);
    put_str(&mut body, "since", a.value(&["--since"])?);
    put_str(&mut body, "until", a.value(&["--until"])?);
    put_str(&mut body, "grep", a.value(&["--grep"])?);
    let positional = a.maybe_one("<container>")?;
    if flag_container.is_some() && positional.is_some() {
        return Err(ArgError::new("name the container once: either <container> or --container"));
    }
    let container = flag_container.or(positional);
    // A container or a `--name` label: without either it is a usage error.
    if container.is_none() && body.get("name").is_none() {
        return Err(ArgError::new("name a container (or --name <label>)"));
    }
    Ok(TailArgs { container, body })
}

/// `noo logs tail <CONTAINER|--container C|--name N> [-l N] [-n ID] [--source S] [--since T] [--until T] [--grep RX]`
/// POST /api/logs/tail — the last N lines of one container, oldest first
/// (Loki when it answers, else the container's `docker logs` through its
/// node-agent, located by name when `--node` is not given).
pub fn logs_tail(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let TailArgs { container, mut body } = parse_tail_args(args)?;
    if let Some(c) = container {
        body["container"] = c.into();
    }

    let resp = post_json(g, "/api/logs/tail", &body, true, 60);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let empty = Vec::new();
    let lines = resp["lines"].as_array().unwrap_or(&empty);
    if lines.is_empty() {
        println!("{}", ui::muted("no log output"));
        println!("{}", ui::muted(&backend_footer(&resp)));
        return Ok(0);
    }
    let width = term_width();
    let entries = resp["entries"].as_array().unwrap_or(&empty);
    if entries.len() == lines.len() {
        // Loki lines carry their time and origin; show them when the tail
        // spans more than one stream, else the raw line as docker prints it.
        let many = resp["names"].as_array().map(|n| n.len() > 1).unwrap_or(false) || body.get("node").is_none();
        for e in entries {
            let line = e["line"].as_str().unwrap_or("").trim_end();
            let row = if many {
                format!(
                    "{} {:<10} {:<14} {line}",
                    short_ts(e["ts"].as_str().unwrap_or("")),
                    e["node"].as_str().unwrap_or("?"),
                    e["name"].as_str().unwrap_or("?")
                )
            } else {
                format!("{} {line}", short_ts(e["ts"].as_str().unwrap_or("")))
            };
            println!("{}", truncate(&row, width));
        }
    } else {
        for l in lines {
            println!("{}", truncate(l.as_str().unwrap_or("").trim_end(), width));
        }
    }
    println!("{}", ui::muted(&backend_footer(&resp)));
    Ok(0)
}

/// Parsed `noo logs search` surface.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct SearchArgs {
    body: serde_json::Value,
}

fn parse_search_args(args: &[String]) -> Result<SearchArgs, ArgError> {
    parse_search_with(&mut Args::new(args))
}

pub(crate) fn parse_search_with(a: &mut Args) -> Result<SearchArgs, ArgError> {
    let mut body = serde_json::json!({});
    put_str(&mut body, "node", a.value(&["--node", "-n"])?);
    put_str(&mut body, "name", a.value(&["--name"])?);
    put_str(&mut body, "container", a.value(&["--container", "-c"])?);
    put_str(&mut body, "source", a.value(&["--source"])?);
    put_str(&mut body, "level", a.value(&["--level"])?);
    put_str(&mut body, "since", a.value(&["--since"])?);
    put_str(&mut body, "until", a.value(&["--until"])?);
    put_num(&mut body, "limit", a.number::<u64>(&["--limit", "-l"])?);
    // Oldest first is the natural read of "what happened"; `--newest` flips it.
    if a.flag(&["--newest"]) {
        body["direction"] = "backward".into();
    }
    put_str(&mut body, "query", a.value(&["--query", "-q"])?);
    // Two positionals is an error — quote the phrase.
    if let Some(t) = a.maybe_one("<text> (quote the phrase)")? {
        body["text"] = t.into();
    }
    if body.get("direction").is_none() {
        body["direction"] = "forward".into();
    }
    Ok(SearchArgs { body })
}

/// `noo logs search [<text>] [-n ID] [--name N] [--level L] [--source S] [--since T] [--until T] [-l N]`
/// POST /api/logs/search — the fleet search over Loki. The gateway builds
/// the LogQL from the flags; `<text>` is a line filter; `-q` sends your own
/// LogQL (capped like everything else). Loki down → the gateway's 503 is
/// printed as-is: there is no scan fallback for a fleet question.
pub fn logs_search(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let SearchArgs { body } = parse_search_args(args)?;
    let resp = post_json(g, "/api/logs/search", &body, true, 60);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    let empty = Vec::new();
    let lines = resp["lines"].as_array().unwrap_or(&empty);
    let width = term_width();
    if lines.is_empty() {
        println!("{}", ui::muted("no matching lines"));
    }
    for e in lines {
        let row = format!(
            "{} {:<10} {:<14} {:<5} {}",
            short_ts(e["ts"].as_str().unwrap_or("")),
            e["node"].as_str().unwrap_or("?"),
            e["name"].as_str().unwrap_or("?"),
            e["level"].as_str().unwrap_or("?"),
            e["line"].as_str().unwrap_or("").trim_end()
        );
        println!("{}", truncate(&row, width));
    }
    let more = if resp["truncated"].as_bool().unwrap_or(false) { " (limit reached; raise -l or narrow)" } else { "" };
    let clamped = if resp["range_clamped"].as_bool().unwrap_or(false) { "; range clamped to 7 days" } else { "" };
    println!(
        "{}",
        ui::muted(&format!(
            "{} line(s) {} → {}{more}{clamped}",
            lines.len(),
            resp["start"].as_str().unwrap_or("?"),
            resp["end"].as_str().unwrap_or("?")
        ))
    );
    println!("{}", ui::muted(&format!("query: {}", resp["query"].as_str().unwrap_or("?"))));
    println!("{}", ui::muted(&backend_footer(&resp)));
    Ok(0)
}

pub(crate) fn parse_containers_with(a: &mut Args) -> Result<Option<String>, ArgError> {
    let node = a.value(&["--node", "-n"])?;
    a.finish()?;
    Ok(node)
}

/// `noo logs containers [--node/-n ID]` — GET /api/logs/containers.
/// Lists Docker containers across the cluster (gateway fans out to every
/// node-agent's /logs/containers; Python parity: 15s timeout).
pub fn logs_containers(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let node = parse_containers_with(&mut Args::new(args))?;
    let mut path = String::from("/api/logs/containers");
    if let Some(n) = &node {
        path.push_str(&format!("?node_id={}", urlencode(n)));
    }
    let body = get_json(g, &path, true, 15);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let containers = body["containers"].as_array().unwrap_or(&empty);
    if containers.is_empty() {
        println!("{}", ui::muted("no containers"));
        return Ok(0);
    }
    println!("{}", ui::header("containers", Some(&format!("{} across the cluster", containers.len()))));
    println!("{}", ui::section("containers"));
    let rows: Vec<Vec<String>> = containers
        .iter()
        .map(|c| {
            let node = c["node_hostname"].as_str().filter(|s| !s.is_empty())
                .or_else(|| c["node_id"].as_str())
                .unwrap_or("?");
            vec![
                truncate(node, 18),
                truncate(c["name"].as_str().unwrap_or("?"), 28),
                ui::state(c["status"].as_str().unwrap_or("?")),
                truncate(c["image"].as_str().unwrap_or(""), 50),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(&[Col::left("node"), Col::left("container"), Col::left("status"), Col::left("image")], &rows)
    );
    Ok(0)
}

pub(crate) fn parse_query_with(a: &mut Args) -> Result<(String, u64), ArgError> {
    let limit = a.number::<u64>(&["--limit", "-l"])?.unwrap_or(100);
    let logql = a.one("<logql>")?;
    Ok((logql, limit))
}

/// `noo logs query LOGQL [--limit/-l N]` — GET /api/logs/query (raw LogQL,
/// proxied to Loki's query_range; Python parity: 30s timeout). Human output
/// prints each stream's label set then its log lines, like the Python CLI.
pub fn logs_query(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (q, limit) = parse_query_with(&mut Args::new(args))?;
    let body = get_json(
        g,
        &format!("/api/logs/query?query={}&limit={limit}", urlencode(&q)),
        true,
        30,
    );
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let empty = Vec::new();
    let results = body["data"]["result"].as_array().unwrap_or(&empty);
    if results.is_empty() {
        println!("{}", ui::muted("no results"));
        return Ok(0);
    }
    let width = term_width();
    for stream in results {
        let labels: Vec<String> = stream["stream"]
            .as_object()
            .map(|o| o.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or(""))).collect())
            .unwrap_or_default();
        println!("{}", ui::emph(&format!("{{{}}}", labels.join(", "))));
        for pair in stream["values"].as_array().unwrap_or(&empty) {
            // Loki values are [timestamp, line] pairs.
            let line = pair.get(1).and_then(|v| v.as_str()).unwrap_or("");
            println!("{}", truncate(line.trim_end(), width));
        }
    }
    Ok(0)
}

/// `noo logs status` — GET /api/logs/status (Loki connectivity check).
pub fn logs_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/logs/status", true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    let loki = if body["loki_ready"].as_bool().unwrap_or(false) { "healthy" } else { "unreachable" };
    let url = body["loki_url"].as_str().unwrap_or("");
    let registry = if body["node_registry_available"].as_bool().unwrap_or(false) { "running" } else { "unreachable" };
    println!("{}", ui::header("logs", None));
    print!(
        "{}",
        ui::kv(&[
            ("loki", ui::state(loki)),
            ("loki url", if url.is_empty() { ui::muted("not configured") } else { url.to_string() }),
            ("node registry", ui::state(registry)),
        ])
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    // ── errors ──

    #[test]
    fn errors_parses_the_old_flags_and_the_loki_ones() {
        assert_eq!(parse_errors_args(&[]).unwrap().body, serde_json::json!({}));
        let a = parse_errors_args(&argv(&[
            "-c", "gateway", "-m", "30", "-n", "50", "--node", "host3", "--name", "vllm", "--source",
            "docker", "--since", "2h", "--until", "2026-09-28T14:05:00Z",
        ]))
        .unwrap();
        assert_eq!(a.body["container"], "gateway");
        assert_eq!(a.body["minutes"], 30);
        assert_eq!(a.body["limit"], 50);
        assert_eq!(a.body["node"], "host3");
        assert_eq!(a.body["name"], "vllm");
        assert_eq!(a.body["source"], "docker");
        assert_eq!(a.body["since"], "2h");
        assert_eq!(a.body["until"], "2026-09-28T14:05:00Z");
    }

    #[test]
    fn errors_refuses_a_missing_value_and_an_unknown_flag() {
        assert!(parse_errors_args(&argv(&["--node"])).is_err());
        assert!(parse_errors_args(&argv(&["-m", "soon"])).is_err());
        assert!(parse_errors_args(&argv(&["--follow"])).is_err());
        assert!(parse_errors_args(&argv(&["gateway"])).is_err(), "errors takes no positional");
    }

    // ── tail ──

    #[test]
    fn tail_takes_a_container_or_a_name_and_the_loki_flags() {
        let a = parse_tail_args(&argv(&["noo-gateway", "-l", "50", "-n", "host3", "--since", "30m", "--grep", "502"]))
            .unwrap();
        assert_eq!(a.container.as_deref(), Some("noo-gateway"));
        assert_eq!(a.body["lines"], 50);
        assert_eq!(a.body["node"], "host3");
        assert_eq!(a.body["since"], "30m");
        assert_eq!(a.body["grep"], "502");
        let a = parse_tail_args(&argv(&["--name", "noo-hostd", "--source", "journal", "--until", "1h"])).unwrap();
        assert_eq!(a.container, None);
        assert_eq!(a.body["name"], "noo-hostd");
        assert_eq!(a.body["source"], "journal");
        assert_eq!(a.body["until"], "1h");
    }

    #[test]
    fn tail_without_a_target_or_with_two_is_a_usage_error() {
        assert!(parse_tail_args(&[]).is_err());
        assert!(parse_tail_args(&argv(&["-l", "10"])).is_err());
        assert!(parse_tail_args(&argv(&["a", "b"])).is_err());
        assert!(parse_tail_args(&argv(&["gateway", "--follow"])).is_err());
    }

    // ── search ──

    #[test]
    fn search_builds_the_body_the_gateway_expects() {
        let a = parse_search_args(&argv(&[
            "CUDA error", "-n", "host3", "--name", "vllm", "--level", "error,warn", "--source", "docker", "--since",
            "2026-09-28T14:00:00Z", "--until", "2026-09-28T14:05:00Z", "-l", "500",
        ]))
        .unwrap();
        assert_eq!(a.body["text"], "CUDA error");
        assert_eq!(a.body["node"], "host3");
        assert_eq!(a.body["name"], "vllm");
        assert_eq!(a.body["level"], "error,warn");
        assert_eq!(a.body["source"], "docker");
        assert_eq!(a.body["since"], "2026-09-28T14:00:00Z");
        assert_eq!(a.body["until"], "2026-09-28T14:05:00Z");
        assert_eq!(a.body["limit"], 500);
        assert_eq!(a.body["direction"], "forward", "a review reads oldest first");
        assert!(a.body.get("query").is_none(), "no LogQL unless -q");
    }

    #[test]
    fn search_with_no_text_is_a_window_and_newest_flips_the_order() {
        let a = parse_search_args(&argv(&["--node", "host3", "--since", "14:00"])).unwrap();
        assert!(a.body.get("text").is_none());
        assert_eq!(a.body["node"], "host3");
        let a = parse_search_args(&argv(&["--newest", "-q", "{node=\"host3\"}"])).unwrap();
        assert_eq!(a.body["direction"], "backward");
        assert_eq!(a.body["query"], "{node=\"host3\"}");
    }

    #[test]
    fn search_refuses_two_positionals_and_unknown_flags() {
        assert!(parse_search_args(&argv(&["a", "b"])).is_err(), "quote the phrase");
        assert!(parse_search_args(&argv(&["--grep", "x"])).is_err(), "search has no grep: the text IS the filter");
        assert!(parse_search_args(&argv(&["-l", "many"])).is_err());
    }

    // ── the footer ──

    #[test]
    fn the_footer_names_the_backend_and_never_calls_a_scan_the_fleet_view() {
        assert_eq!(backend_footer(&serde_json::json!({"backend": "loki"})), "via loki");
        assert_eq!(
            backend_footer(&serde_json::json!({"backend": "agent-scan", "loki_error": "Loki unreachable: connect refused"})),
            "via agent scan (Loki not reachable: Loki unreachable: connect refused)"
        );
        // A gateway from before phase 5 sends no `backend`: that IS the scan.
        assert_eq!(backend_footer(&serde_json::json!({})), "via agent scan (Loki not reachable)");
    }

    #[test]
    fn short_ts_keeps_the_clock_for_today_and_the_date_otherwise() {
        assert_eq!(short_ts("2001-01-01T14:02:07.123Z"), "2001-01-01T14:02:07");
        let today = chrono_free_today();
        assert_eq!(short_ts(&format!("{today}T14:02:07.123Z")), "14:02:07");
        assert_eq!(civil_from_days(0), "1970-01-01");
        assert_eq!(civil_from_days(20_724), "2026-09-28");
    }
}
