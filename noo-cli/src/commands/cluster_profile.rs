// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo cluster profile <node>` — a node's harness profile: how long its
//! inference proxy waits for a first byte, how long a stream may idle, the
//! harness's thinking default, its ollama context, the Claude Code launch
//! variant, and which foreign harness kinds it may run.
//!
//! The gateway resolves it per field, override > measured > tier default
//! (`config/harness-profiles.json`), and serves it in the node's
//! desired config; this verb shows each field with where it came from,
//! writes the per-node overrides (`--set`, `--clear`, `--clear-all`: the
//! node config's `harness_profile`), and asks the node to measure its chat
//! model (`--bench`), which is what `first_byte_secs` follows.

use serde_json::{json, Map, Value};

use crate::harness_profiles::{self, Table};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col};
use crate::{Globals, Unhandled};

/// The parsed command line.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ProfileArgs {
    pub node: String,
    /// `key=value` texts, in order.
    pub set: Vec<String>,
    pub clear: Vec<String>,
    pub clear_all: bool,
    pub bench: bool,
}

impl ProfileArgs {
    fn writes(&self) -> bool {
        !self.set.is_empty() || !self.clear.is_empty() || self.clear_all
    }
}

/// `<node> [--set k=v...]... [--clear k...]... [--clear-all] [--bench]`.
/// `--set` and `--clear` take every following word up to the next flag
/// (at least one).
pub(crate) fn parse_profile_args(args: &[String]) -> Result<ProfileArgs, ()> {
    let [node, rest @ ..] = args else { return Err(()) };
    if node.starts_with('-') || node.is_empty() {
        return Err(());
    }
    let mut out = ProfileArgs { node: node.clone(), ..Default::default() };
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            flag @ ("--set" | "--clear") => {
                let start = i + 1;
                let mut j = start;
                while j < rest.len() && !rest[j].starts_with("--") {
                    j += 1;
                }
                if j == start {
                    return Err(());
                }
                let words = rest[start..j].iter().cloned();
                if flag == "--set" { out.set.extend(words) } else { out.clear.extend(words) }
                i = j;
            }
            "--clear-all" => {
                out.clear_all = true;
                i += 1;
            }
            "--bench" => {
                out.bench = true;
                i += 1;
            }
            _ => return Err(()),
        }
    }
    Ok(out)
}

/// The new overrides object: `before`, emptied by `--clear-all`, minus
/// `--clear` keys, plus `--set` assignments (typed by the table). Pure.
pub(crate) fn merged_overrides(table: &Table, before: &Value, a: &ProfileArgs) -> Result<Value, String> {
    let mut m: Map<String, Value> = if a.clear_all { Map::new() } else { before.as_object().cloned().unwrap_or_default() };
    for k in &a.clear {
        for k in k.split(',').map(str::trim).filter(|k| !k.is_empty()) {
            table.check_field(k)?;
            m.remove(k);
        }
    }
    for kv in &a.set {
        let (k, v) = table.parse_assignment(kv)?;
        m.insert(k, v);
    }
    Ok(Value::Object(m))
}

/// A profile value as one cell.
fn cell(v: &Value) -> String {
    match v {
        Value::Array(a) if a.is_empty() => "none".to_string(),
        Value::Array(a) => a.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect::<Vec<_>>().join(", "),
        Value::String(s) => s.clone(),
        Value::Null => ui::dash().to_string(),
        other => other.to_string(),
    }
}

/// The SOURCE cell for one field: `tier N`, `override (tier N: <default>)`,
/// or `measured from <model> at <time>`.
pub(crate) fn source_cell(table: &Table, profile: &Value, field: &str) -> String {
    let tier = profile["tier"].as_u64().map(|t| t.to_string()).unwrap_or_else(|| "?".into());
    let default = table.tiers.get(&tier).and_then(|r| r.get(field)).map(cell);
    match profile["sources"][field].as_str() {
        Some("override") => match default {
            Some(d) => format!("override (tier {tier}: {d})"),
            None => "override".to_string(),
        },
        Some("measured") => {
            let b = &profile["bench"];
            let model = b["model"].as_str().unwrap_or("?");
            match b["at"].as_str() {
                Some(at) => format!("measured from {model} at {at}"),
                None => format!("measured from {model}"),
            }
        }
        Some("tier") => format!("tier {tier}"),
        Some(other) => other.to_string(),
        None => ui::dash().to_string(),
    }
}

/// Why a bench on the record did or did not set `first_byte_secs`.
pub(crate) fn bench_applies(profile: &Value) -> String {
    match profile["sources"]["first_byte_secs"].as_str() {
        Some("measured") => "yes: first_byte_secs follows it".to_string(),
        Some("override") => "no: first_byte_secs is overridden on this node".to_string(),
        _ => "no: it is not of the model the node's chat backend runs now".to_string(),
    }
}

fn num(v: &Value, unit: &str) -> String {
    match v.as_f64() {
        Some(n) => format!("{n:.1} {unit}"),
        None => ui::dash().to_string(),
    }
}

fn print_bench(bench: &Value) {
    let model = bench["model"].as_str().unwrap_or("?");
    let backend = bench["backend"].as_str().map(|b| format!(" ({b})")).unwrap_or_default();
    println!("{}", ui::kv(&[
        ("model", format!("{model}{backend}")),
        ("load", num(&bench["load_secs"], "s")),
        ("prefill", num(&bench["prefill_tps"], "tok/s")),
        ("decode", num(&bench["decode_tps"], "tok/s")),
        ("prompt", bench["prompt_tokens"].as_u64().map(|n| format!("{n} tokens")).unwrap_or_else(|| ui::dash().to_string())),
        ("at", bench["at"].as_str().unwrap_or(ui::dash()).to_string()),
    ]));
}

fn rule_line(table: &Table, profile: &Value) -> String {
    let m = &table.measured;
    let tier = profile["tier"].as_u64().map(|t| t.to_string()).unwrap_or_else(|| "?".into());
    let floor = table.tiers.get(&tier).and_then(|r| r.get("first_byte_secs")).map(cell).unwrap_or_else(|| "?".into());
    format!(
        "first_byte_secs = ceil((load + {} / prefill) × {}), at least tier {tier}'s {floor}, at most {}",
        m.get("reference_prompt_tokens").map(cell).unwrap_or_else(|| "?".into()),
        m.get("headroom").map(cell).unwrap_or_else(|| "?".into()),
        m.get("max_first_byte_secs").map(cell).unwrap_or_else(|| "?".into()),
    )
}

/// The profile block: one row per field, value and source, then the bench.
fn print_profile(table: &Table, node: &str, profile: &Value) {
    let tier = profile["tier"].as_u64().map(|t| format!("tier {t}")).unwrap_or_default();
    println!("{}", ui::header(node, Some(&format!("harness profile · {tier}"))));
    println!("{}", ui::section("Profile"));
    let rows: Vec<Vec<String>> = table
        .fields
        .iter()
        .map(|f| vec![f.clone(), cell(&profile[f.as_str()]), source_cell(table, profile, f)])
        .collect();
    print!("{}", ui::table(&[Col::left("field"), Col::left("value"), Col::left("source")], &rows));
    println!("{}", ui::section("Bench"));
    let bench = &profile["bench"];
    if bench.is_object() {
        print_bench(bench);
        println!("  {}", ui::muted(&format!("applies: {}", bench_applies(profile))));
        println!("  {}", ui::muted(&rule_line(table, profile)));
    } else {
        println!("  {}", ui::muted(&format!("no bench yet: `noo cluster profile {node} --bench` measures the node's chat model")));
    }
}

fn desired_path(node: &str) -> String {
    format!("/api/cluster/nodes/{}/desired-config", super::urlencode(node))
}

/// The gateway's `error` (or `detail`) out of a non-2xx body.
fn error_of(status: u16, text: &str) -> String {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v["error"].as_str().or_else(|| v["detail"].as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}: {}", text.trim()))
}

/// The agent's (or the gateway's) refusal of a bench, as `(code, message,
/// remedy)`. The agent answers 409 `no_chat_backend` / `bench_busy`, 502
/// when the chat backend failed mid-bench, 504 when the bench ran past its
/// 600 s budget; the gateway answers 502 when it cannot reach the agent and
/// 404 when the node is unknown. Pure.
pub(crate) fn bench_failure(node: &str, status: u16, text: &str) -> (&'static str, String, Option<&'static str>) {
    let body = serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
    let says = |code: &str| {
        ["error", "code"].iter().any(|k| body[*k].as_str() == Some(code)) || text.contains(code)
    };
    let why = error_of(status, text);
    match status {
        409 if says("no_chat_backend") => (
            "no_chat_backend",
            format!("{node} runs no chat backend to bench: place one first, then bench again"),
            Some("noo cluster desired <node>"),
        ),
        409 if says("bench_busy") => (
            "bench_busy",
            format!("{node} is already running a bench: wait for it to finish, then read the result"),
            Some("noo cluster profile <node>"),
        ),
        504 => (
            "bench_timeout",
            format!("{node}: the bench ran past the agent's 600 s budget, so this model is too slow to measure that way: set the wait by hand"),
            Some("noo cluster profile <node> --set first_byte_secs=1800"),
        ),
        502 if why.contains("could not reach the node agent") => (
            "node_unreachable",
            format!("{node}: {why}"),
            Some("noo cluster show <node>"),
        ),
        502 => (
            "bench_backend_failed",
            format!("{node}: the chat backend failed during the bench: {why}"),
            Some("noo cluster logs <node>"),
        ),
        404 => (
            "bench_unavailable",
            format!("{node}: {why} (a node not in the mesh, or an agent that predates /bench)"),
            Some("noo cluster show <node>"),
        ),
        _ => ("bench_failed", format!("{node}: the bench did not run: {why}"), Some("noo cluster show <node>")),
    }
}

/// `noo cluster profile <node> [--set k=v...] [--clear k...] [--clear-all] [--bench]`
pub fn cluster_profile(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let Ok(a) = parse_profile_args(args) else { return Err(Unhandled) };
    let table = harness_profiles::shipped();
    let node = a.node.as_str();
    let mut wrote: Option<Value> = None;

    if a.writes() {
        let desired = crate::http::get_json(g, &desired_path(node), true, 10);
        let before = desired["node"]["harness_profile_overrides"].clone();
        let after = match merged_overrides(&table, &before, &a) {
            Ok(v) => v,
            Err(e) => fail(g.json, ExitCode::Usage, "bad_profile_value", &e, None),
        };
        let path = format!("/api/cluster/nodes/{}/config", super::urlencode(node));
        if let Err((status, text)) =
            crate::http::request_status(g, "PUT", &path, Some(&json!({"harness_profile": after})), true, 10)
        {
            let code = if status == 400 { ExitCode::Usage } else { ExitCode::RemoteError };
            fail(g.json, code, "profile_refused", &format!("{node}: {}", error_of(status, &text)), None);
        }
        if !g.json {
            let shown = |v: &Value| match v.as_object() {
                Some(m) if !m.is_empty() => m.iter().map(|(k, v)| format!("{k}={}", cell(v))).collect::<Vec<_>>().join(" "),
                _ => "none".to_string(),
            };
            ui::done(&format!("{node}: profile overrides {} (was: {})", shown(&after), shown(&before)));
        }
        wrote = Some(after);
    }

    let mut bench: Option<Value> = None;
    if a.bench {
        if !g.json {
            println!("{}", ui::muted(&format!("{node}: benching its chat model (a cold load and a long prefill; up to 15 minutes)")));
        }
        let path = format!("/api/cluster/nodes/{}/bench", super::urlencode(node));
        match crate::http::request_status(g, "POST", &path, Some(&json!({})), true, 960) {
            Ok(v) => bench = Some(v),
            Err((status, text)) => {
                let (kind, msg, hint) = bench_failure(node, status, &text);
                fail(g.json, ExitCode::RemoteError, kind, &msg, hint)
            }
        }
        if !g.json {
            println!("{}", ui::section("Measured"));
            print_bench(bench.as_ref().unwrap_or(&Value::Null));
        }
    }

    let desired = crate::http::get_json(g, &desired_path(node), true, 10);
    let profile = desired["harness_profile"].clone();
    if g.json {
        let mut out = json!({"node": node, "profile": profile, "overrides": desired["node"]["harness_profile_overrides"].clone()});
        if let Some(w) = wrote {
            out["wrote"] = w;
        }
        if let Some(b) = bench {
            out["bench"] = b;
        }
        println!("{out}");
        return Ok(0);
    }
    if !profile.is_object() {
        fail(
            g.json,
            ExitCode::RemoteError,
            "no_profile",
            &format!("{node}: the gateway's desired config carries no harness_profile (a gateway that predates harness profiles)"),
            Some("noo upgrade"),
        );
    }
    print_profile(&table, node, &profile);
    ui::guide(&[
        ("noo cluster profile <node> --set thinking=on", "override one field on this node (any of the fields above)"),
        ("noo cluster profile <node> --clear thinking", "drop one override; the tier default (or the measured value) returns"),
        ("noo cluster profile <node> --bench", "measure the node's chat model; first_byte_secs follows it"),
        ("noo cluster profile <node> --clear-all", "back to the tier defaults and the measured speed"),
    ]);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_show_set_clear_and_bench() {
        assert_eq!(parse_profile_args(&a(&["host3"])), Ok(ProfileArgs { node: "host3".into(), ..Default::default() }));
        let p = parse_profile_args(&a(&["host3", "--set", "thinking=on", "first_byte_secs=900", "--clear", "ollama_context", "--bench"])).unwrap();
        assert_eq!(p.set, ["thinking=on", "first_byte_secs=900"]);
        assert_eq!(p.clear, ["ollama_context"]);
        assert!(p.bench && !p.clear_all && p.writes());
        let p = parse_profile_args(&a(&["host3", "--set", "a=1", "--set", "b=2", "--clear-all"])).unwrap();
        assert_eq!(p.set, ["a=1", "b=2"]);
        assert!(p.clear_all);
        assert!(!parse_profile_args(&a(&["host3", "--bench"])).unwrap().writes());
        assert!(parse_profile_args(&a(&[])).is_err());
        assert!(parse_profile_args(&a(&["--bench"])).is_err());
        assert!(parse_profile_args(&a(&["host3", "--set"])).is_err());
        assert!(parse_profile_args(&a(&["host3", "--clear", "--bench"])).is_err());
        assert!(parse_profile_args(&a(&["host3", "--bogus"])).is_err());
        assert!(parse_profile_args(&a(&["host3", "extra"])).is_err());
    }

    #[test]
    fn merges_overrides_in_order_clear_all_then_clear_then_set() {
        let t = harness_profiles::shipped();
        let before = json!({"thinking": "on", "ollama_context": 4096});
        let args = |set: &[&str], clear: &[&str], all: bool| ProfileArgs {
            node: "n".into(),
            set: a(set),
            clear: a(clear),
            clear_all: all,
            bench: false,
        };
        assert_eq!(
            merged_overrides(&t, &before, &args(&["first_byte_secs=900"], &["thinking"], false)).unwrap(),
            json!({"ollama_context": 4096, "first_byte_secs": 900})
        );
        assert_eq!(merged_overrides(&t, &before, &args(&[], &[], true)).unwrap(), json!({}));
        assert_eq!(merged_overrides(&t, &before, &args(&["thinking=off"], &[], true)).unwrap(), json!({"thinking": "off"}));
        assert_eq!(merged_overrides(&t, &Value::Null, &args(&["foreign_kinds=none"], &[], false)).unwrap(), json!({"foreign_kinds": []}));
        // The agent's refusal names exactly this form.
        assert_eq!(merged_overrides(&t, &Value::Null, &args(&["foreign_kinds=codex,copilot"], &[], false)).unwrap(), json!({"foreign_kinds": ["codex", "copilot"]}));
        assert!(merged_overrides(&t, &before, &args(&[], &["bogus"], false)).is_err());
        assert!(merged_overrides(&t, &before, &args(&["bogus=1"], &[], false)).is_err());
    }

    fn profile() -> Value {
        json!({"tier": 2, "first_byte_secs": 907, "stream_idle_secs": 300, "thinking": "on", "ollama_context": 32768,
            "claude_prompt": "slim", "foreign_kinds": ["claude-code", "codex", "copilot"],
            "sources": {"first_byte_secs": "measured", "stream_idle_secs": "tier", "thinking": "override",
                "ollama_context": "tier", "claude_prompt": "tier", "foreign_kinds": "tier"},
            "bench": {"model": "gemma4:12b", "backend": "ollama", "load_secs": 4.2, "prefill_tps": 50.0,
                "decode_tps": 18.3, "prompt_tokens": 8192, "at": "2026-10-19T17:00:00Z"}})
    }

    #[test]
    fn every_field_names_its_source() {
        let t = harness_profiles::shipped();
        let p = profile();
        assert_eq!(source_cell(&t, &p, "first_byte_secs"), "measured from gemma4:12b at 2026-10-19T17:00:00Z");
        assert_eq!(source_cell(&t, &p, "thinking"), "override (tier 2: off)");
        assert_eq!(source_cell(&t, &p, "ollama_context"), "tier 2");
        assert_eq!(cell(&p["foreign_kinds"]), "claude-code, codex, copilot");
        assert_eq!(cell(&json!([])), "none");
        assert_eq!(bench_applies(&p), "yes: first_byte_secs follows it");
        let mut q = p.clone();
        q["sources"]["first_byte_secs"] = json!("tier");
        assert!(bench_applies(&q).contains("not of the model"));
        q["sources"]["first_byte_secs"] = json!("override");
        assert!(bench_applies(&q).contains("overridden"));
        assert!(rule_line(&t, &p).contains("ceil((load + 30000 / prefill) × 1.5), at least tier 2's 600, at most 1800"), "{}", rule_line(&t, &p));
    }

    #[test]
    fn bench_refusals_read_as_what_happened() {
        let k = |status: u16, text: &str| bench_failure("host3", status, text).0;
        assert_eq!(k(409, r#"{"error":"no_chat_backend"}"#), "no_chat_backend");
        assert_eq!(k(409, r#"{"code":"bench_busy","error":"a bench is running"}"#), "bench_busy");
        assert_eq!(k(504, "timeout"), "bench_timeout");
        assert_eq!(k(502, r#"{"error":"could not reach the node agent on host3 for /bench: refused"}"#), "node_unreachable");
        assert_eq!(k(502, r#"{"error":"ollama: 500 out of memory"}"#), "bench_backend_failed");
        assert_eq!(k(404, r#"{"error":"Node 'host3' not found in mesh_nodes"}"#), "bench_unavailable");
        assert_eq!(k(500, "x"), "bench_failed");
        let (_, msg, hint) = bench_failure("host3", 504, "");
        assert!(msg.starts_with("host3: the bench ran past"));
        assert_eq!(hint, Some("noo cluster profile <node> --set first_byte_secs=1800"));
    }

    #[test]
    fn a_gateway_refusal_reads_as_its_reason() {
        assert_eq!(error_of(400, r#"{"error":"thinking must be on, off or auto"}"#), "thinking must be on, off or auto");
        assert_eq!(error_of(502, "boom"), "HTTP 502: boom");
    }
}
