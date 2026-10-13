// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Add-on commands: an enabled add-on brings its own `noo` command groups.
//!
//! The core CLI carries no add-on code. An add-on describes its commands in a
//! "CLI piece" the gateway serves at `GET /api/addons/<id>/cli-piece` (already
//! validated against the add-on's mounted routes), and this module turns each
//! command into a request to the gateway's existing add-on proxy.
//!
//! `noo <group> <cmd> ...`, where `<group>` is not a built-in command:
//!  1. read `/health` `addons` for the enabled add-ons and fetch each one's
//!     piece, cached per controller under the CLI's state dir for ten
//!     minutes; a stale cache is used when the controller is unreachable;
//!  2. find the group, build the request from the command's `args`, confirm
//!     when the piece says to (`-y/--yes` skips it, `--json` demands it),
//!     send it, render the piece's `output`.
//!
//! A group that collides with a built-in command is ignored with a warning.
//! A group of an add-on that is off says so (exit 5); a group nothing offers
//! is the ordinary unknown command (this module returns `None`).
//!
//! Wire shape: `gateway-rust/src/routes/cli_piece.rs`, docs/development/addons.md.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::output::{fail, ExitCode};
use crate::ui::{self, Col};
use crate::Globals;

/// How long a fetched piece is trusted before the next command refetches.
const TTL_SECS: u64 = 600;
/// Add-on commands can run long (a manual loop cycle is a full LLM
/// reflection, 300s at the gateway's proxy): never time out before it does.
const COMMAND_TIMEOUT_SECS: u64 = 310;
/// Fetching `/health` and the pieces: a controller that does not answer
/// quickly is treated as unreachable and the cache is used.
const FETCH_TIMEOUT_SECS: u64 = 10;
const HELP_TIMEOUT_SECS: u64 = 3;

// ── the piece, as the gateway serves it ───────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Group {
    #[serde(default)]
    name: String,
    #[serde(default)]
    summary: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Arg {
    #[serde(default)]
    name: String,
    #[serde(default)]
    flag: Option<String>,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    into: String,
    #[serde(default)]
    help: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct KeyLabel {
    #[serde(default)]
    key: String,
    #[serde(default)]
    label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Output {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    fields: Vec<KeyLabel>,
    #[serde(default)]
    list: Option<String>,
    #[serde(default)]
    columns: Vec<KeyLabel>,
    #[serde(default)]
    hint: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Cmd {
    #[serde(default)]
    group: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    args: Vec<Arg>,
    #[serde(default)]
    confirm: Option<String>,
    #[serde(default)]
    output: Option<Output>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Piece {
    #[serde(default)]
    addon: String,
    #[serde(default)]
    groups: Vec<Group>,
    #[serde(default)]
    commands: Vec<Cmd>,
}

/// What the CLI remembers about one controller.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Cache {
    #[serde(default)]
    fetched_at: u64,
    /// `/health` `addons`: add-on id → enabled | disabled | unlicensed.
    #[serde(default)]
    addons: BTreeMap<String, String>,
    /// The last piece seen per add-on, kept while the add-on is off so its
    /// group stays recognisable ("evolve is not enabled", not "unknown").
    #[serde(default)]
    pieces: BTreeMap<String, Piece>,
}

struct State {
    cache: Cache,
    /// This process fetched it (so asking again would be pointless).
    fetched_now: bool,
}

// ── names ─────────────────────────────────────────────────────────────────

fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 24
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn arg_ok(a: &Arg) -> bool {
    let into_ok = matches!(a.into.split_once(':'), Some((t, d)) if !d.is_empty() && matches!(t, "path" | "query" | "body"));
    let flag_ok = a.flag.as_deref().is_none_or(|f| f.starts_with("--") && f.len() > 2);
    !a.name.is_empty() && matches!(a.kind.as_str(), "string" | "int" | "uuid" | "bool") && into_ok && flag_ok
}

/// A command this client will run. The gateway validated the piece; the cache
/// is a file on disk, so the client does not take it on trust for what it
/// sends: only GET and POST, only gateway API paths.
fn cmd_ok(c: &Cmd) -> bool {
    name_ok(&c.name)
        && name_ok(&c.group)
        && matches!(c.method.as_str(), "GET" | "POST")
        && c.path.starts_with("/api/")
        && !c.path.contains("..")
        && c.args.iter().all(arg_ok)
}

// ── cache ─────────────────────────────────────────────────────────────────

fn cache_path(g: &Globals) -> PathBuf {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let key: String = base.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let dir = crate::credentials::credentials_path()
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join("addon-cli").join(format!("{key}.json"))
}

fn read_cache(g: &Globals) -> Option<Cache> {
    serde_json::from_str(&std::fs::read_to_string(cache_path(g)).ok()?).ok()
}

fn write_cache(g: &Globals, cache: &Cache) {
    let path = cache_path(g);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(text) = serde_json::to_string(cache) {
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Ask the controller what is enabled and fetch each enabled add-on's piece.
/// `None` when the controller does not answer `/health`: the caller keeps the
/// cache it has. A piece that fails to fetch keeps its previous cached copy.
fn fetch(g: &Globals, old: &Cache, timeout: u64) -> Option<Cache> {
    let (status, body) = crate::http::request_try(g, "GET", "/health", None, true, timeout).ok()?;
    if status != 200 {
        return None;
    }
    let health: Value = serde_json::from_str(&body).ok()?;
    let addons: BTreeMap<String, String> = health["addons"]
        .as_object()?
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|w| (k.clone(), w.to_string())))
        .collect();
    let mut pieces = old.pieces.clone();
    for (id, word) in &addons {
        if word != "enabled" {
            continue;
        }
        let path = format!("/api/addons/{}/cli-piece", super::urlencode(id));
        match crate::http::request_try(g, "GET", &path, None, true, timeout) {
            Ok((200, text)) => match serde_json::from_str::<Piece>(&text) {
                Ok(p) if p.addon == *id => {
                    pieces.insert(id.clone(), p);
                }
                _ => {}
            },
            // No CLI piece (404) is a settled answer: forget any old one.
            Ok((404, _)) => {
                pieces.remove(id);
            }
            _ => {}
        }
    }
    Some(Cache { fetched_at: crate::credentials::now_secs(), addons, pieces })
}

fn load_state(g: &Globals, force: bool, timeout: u64) -> State {
    let cached = read_cache(g);
    if let Some(c) = &cached {
        let age = crate::credentials::now_secs().saturating_sub(c.fetched_at);
        if !force && age < TTL_SECS {
            return State { cache: c.clone(), fetched_now: false };
        }
    }
    let old = cached.unwrap_or_default();
    match fetch(g, &old, timeout) {
        Some(fresh) => {
            write_cache(g, &fresh);
            State { cache: fresh, fetched_now: true }
        }
        // Unreachable: the stale cache is the best answer there is.
        None => State { cache: old, fetched_now: false },
    }
}

// ── which groups this CLI will offer ──────────────────────────────────────

struct Offered<'a> {
    addon: &'a str,
    group: &'a Group,
    piece: &'a Piece,
}

/// Every usable group across the cached pieces, plus the warnings for the
/// ones dropped: a name that collides with a built-in command, or with a
/// group an earlier add-on already offered.
fn offered(cache: &Cache) -> (Vec<Offered<'_>>, Vec<String>) {
    offered_with(cache, crate::is_reserved_command_word)
}

fn offered_with<'a>(cache: &'a Cache, is_core: impl Fn(&str) -> bool) -> (Vec<Offered<'a>>, Vec<String>) {
    let mut out: Vec<Offered> = Vec::new();
    let mut warnings = Vec::new();
    for (id, piece) in &cache.pieces {
        for g in &piece.groups {
            if !name_ok(&g.name) {
                continue;
            }
            if is_core(&g.name) {
                warnings.push(format!(
                    "the {id} add-on offers a `{}` command group, which is a built-in command; ignoring the add-on's",
                    g.name
                ));
            } else if let Some(first) = out.iter().find(|o| o.group.name == g.name) {
                warnings.push(format!(
                    "the {id} add-on offers a `{}` command group the {} add-on already has; ignoring it",
                    g.name, first.addon
                ));
            } else {
                out.push(Offered { addon: id, group: g, piece });
            }
        }
    }
    (out, warnings)
}

fn commands_of<'a>(o: &Offered<'a>) -> Vec<&'a Cmd> {
    o.piece.commands.iter().filter(|c| c.group == o.group.name && cmd_ok(c)).collect()
}

fn warn_all(warnings: &[String]) {
    for w in warnings {
        eprintln!("{}", ui::status_line(ui::Glyph::Warn, w));
    }
}

// ── `noo --help` ──────────────────────────────────────────────────────────

/// The add-on groups for the bare `noo --help` banner, marked as coming from
/// an add-on. Nothing is printed when no controller has ever answered.
pub fn print_help_section(g: &Globals, width: usize) {
    let state = load_state(g, false, HELP_TIMEOUT_SECS);
    let (groups, _) = offered(&state.cache);
    if groups.is_empty() {
        return;
    }
    println!("{}", ui::section("add-ons"));
    let width = width.max(groups.iter().map(|o| o.group.name.len()).max().unwrap_or(0));
    for o in groups {
        let on = state.cache.addons.get(o.addon).map(String::as_str) == Some("enabled");
        let tag = if on { format!("{} add-on", o.addon) } else { format!("{} add-on, not enabled", o.addon) };
        println!(
            "  {}  {}  {}",
            ui::cmd(&format!("{:<width$}", o.group.name)),
            o.group.summary,
            ui::muted(&format!("({tag})"))
        );
    }
}

// ── arguments ─────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Built {
    path: String,
    body: Option<Value>,
    yes: bool,
}

fn kind_hint(a: &Arg) -> &str {
    match a.kind.as_str() {
        "bool" => "",
        k => k,
    }
}

fn syntax(c: &Cmd) -> String {
    let mut parts: Vec<String> = Vec::new();
    for a in c.args.iter().filter(|a| a.flag.is_none()) {
        parts.push(format!("<{}>", a.name));
    }
    for a in c.args.iter().filter(|a| a.flag.is_some()) {
        let f = a.flag.as_deref().unwrap_or("");
        let body = if a.kind == "bool" { f.to_string() } else { format!("{f} <{}>", kind_hint(a)) };
        parts.push(if a.required { body } else { format!("[{body}]") });
    }
    if c.confirm.is_some() {
        parts.push("[-y]".into());
    }
    parts.join(" ")
}

fn is_uuid(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5
        && [8, 4, 4, 4, 12].iter().zip(&p).all(|(n, x)| x.len() == *n && x.chars().all(|c| c.is_ascii_hexdigit()))
}

fn convert(a: &Arg, raw: &str) -> Result<Value, String> {
    match a.kind.as_str() {
        "int" => raw
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_| format!("{} must be a whole number, got `{raw}`", display_name(a))),
        "uuid" if is_uuid(raw) => Ok(json!(raw)),
        "uuid" => Err(format!("{} must be a UUID, got `{raw}`", display_name(a))),
        "bool" => match raw {
            "true" | "yes" | "1" => Ok(json!(true)),
            "false" | "no" | "0" => Ok(json!(false)),
            _ => Err(format!("{} must be true or false, got `{raw}`", display_name(a))),
        },
        _ => Ok(json!(raw)),
    }
}

fn display_name(a: &Arg) -> String {
    a.flag.clone().unwrap_or_else(|| format!("<{}>", a.name))
}

fn plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Turn the typed tokens into the request the piece describes.
fn build(c: &Cmd, args: &[String]) -> Result<Built, String> {
    let positional: Vec<&Arg> = c.args.iter().filter(|a| a.flag.is_none()).collect();
    let mut values: HashMap<&str, Value> = HashMap::new();
    let mut yes = false;
    let mut next_pos = 0;
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        i += 1;
        if tok == "-y" || tok == "--yes" {
            yes = true;
        } else if let Some(long) = tok.strip_prefix("--") {
            let (flag, inline) = match long.split_once('=') {
                Some((f, v)) => (format!("--{f}"), Some(v.to_string())),
                None => (tok.to_string(), None),
            };
            let a = c
                .args
                .iter()
                .find(|a| a.flag.as_deref() == Some(flag.as_str()))
                .ok_or_else(|| format!("unknown option `{flag}`"))?;
            let raw = if a.kind == "bool" {
                inline.unwrap_or_else(|| "true".into())
            } else if let Some(v) = inline {
                v
            } else {
                let v = args.get(i).ok_or_else(|| format!("{flag} needs a value"))?;
                i += 1;
                v.clone()
            };
            values.insert(&a.name, convert(a, &raw)?);
        } else if tok.starts_with('-') && tok.len() > 1 && tok.parse::<i64>().is_err() {
            return Err(format!("unknown option `{tok}`"));
        } else {
            let a = positional.get(next_pos).ok_or_else(|| format!("unexpected argument `{tok}`"))?;
            next_pos += 1;
            values.insert(&a.name, convert(a, tok)?);
        }
    }

    let mut path = c.path.clone();
    let mut query: Vec<String> = Vec::new();
    let mut body = Map::new();
    for a in &c.args {
        let Some(v) = values.get(a.name.as_str()) else {
            if a.required {
                return Err(format!("missing {}", display_name(a)));
            }
            continue;
        };
        let (target, dest) = a.into.split_once(':').unwrap_or(("", ""));
        match target {
            "path" => path = path.replace(&format!("{{{dest}}}"), &super::urlencode(&plain(v))),
            "query" => query.push(format!("{}={}", super::urlencode(dest), super::urlencode(&plain(v)))),
            _ => {
                body.insert(dest.to_string(), v.clone());
            }
        }
    }
    if !query.is_empty() {
        path = format!("{path}?{}", query.join("&"));
    }
    // The transport picks POST from the presence of a body.
    let body = (c.method == "POST").then(|| Value::Object(body));
    Ok(Built { path, body, yes })
}

// ── output ────────────────────────────────────────────────────────────────

/// A JSON value for a human: arrays comma-joined, bools yes/no, null and
/// missing a dash, objects compact JSON.
fn show(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => ui::dash().to_string(),
        Some(Value::String(s)) if s.is_empty() => ui::dash().to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => if *b { "yes" } else { "no" }.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Array(a)) if a.is_empty() => ui::dash().to_string(),
        Some(Value::Array(a)) => a.iter().map(|x| show(Some(x))).collect::<Vec<_>>().join(", "),
        Some(o @ Value::Object(_)) => o.to_string(),
    }
}

/// A 2xx that is really a refusal: `{"status":"error","detail":"…"}` or an
/// `error` string. Returns the sentence to show.
fn soft_error(v: &Value) -> Option<String> {
    let said = ["detail", "error", "message"].iter().find_map(|k| v[*k].as_str()).map(str::to_string);
    if v["status"].as_str() == Some("error") {
        return Some(said.unwrap_or_else(|| "the add-on reported an error".into()));
    }
    v["error"].as_str().map(str::to_string)
}

fn render(c: &Cmd, resp: &Value) {
    let out = c.output.clone().unwrap_or_default();
    let title = out.title.clone().unwrap_or_else(|| format!("{} {}", c.group, c.name));
    if out.fields.is_empty() && out.list.is_none() {
        ui::done(&format!("{title} done"));
    } else {
        println!("{}", ui::header(&title, None));
    }
    if !out.fields.is_empty() {
        let rows: Vec<(&str, String)> =
            out.fields.iter().map(|f| (f.label.as_str(), show(resp.pointer(&f.key)))).collect();
        print!("{}", ui::kv(&rows));
    }
    if let Some(list) = &out.list {
        let items = resp.pointer(list).and_then(Value::as_array).cloned().unwrap_or_default();
        if items.is_empty() {
            println!("{}", ui::muted("nothing to list"));
        } else {
            // Column names come from the piece at run time; the table wants
            // 'static ones, and a CLI process is short-lived.
            let cols: Vec<Col> = out
                .columns
                .iter()
                .map(|k| Col::left(Box::leak(k.label.clone().into_boxed_str())))
                .collect();
            let rows: Vec<Vec<String>> = items
                .iter()
                .map(|it| out.columns.iter().map(|k| show(it.pointer(&k.key))).collect())
                .collect();
            print!("{}", ui::table(&cols, &rows));
        }
    }
    if let Some(h) = &out.hint {
        println!("{}", ui::hint(h));
    }
}

// ── help ──────────────────────────────────────────────────────────────────

fn print_group_help(o: &Offered<'_>, on: bool) {
    let note = if on { format!("{} add-on", o.addon) } else { format!("{} add-on, not enabled", o.addon) };
    println!("{}", ui::header_as_is(&format!("noo {}", o.group.name), Some(&o.group.summary)));
    println!("{}", ui::section("commands"));
    let rows: Vec<Vec<String>> = commands_of(o)
        .iter()
        .map(|c| {
            let s = syntax(c);
            let usage = if s.is_empty() { format!("noo {} {}", c.group, c.name) } else { format!("noo {} {} {s}", c.group, c.name) };
            vec![ui::cmd(&usage), c.summary.clone()]
        })
        .collect();
    print!("{}", ui::table(&[Col::left("command"), Col::left("what it does")], &rows));
    println!();
    println!("{}", ui::muted(&format!("These commands come from the {note}. `--json` prints the raw response.")));
}

fn print_command_help(c: &Cmd, addon: &str) {
    let s = syntax(c);
    println!("{}", ui::header_as_is(&format!("noo {} {}", c.group, c.name), Some(&c.summary)));
    println!("{}", ui::section("usage"));
    println!("  {} {s}", ui::cmd(&format!("noo {} {}", c.group, c.name)));
    let described: Vec<&Arg> = c.args.iter().filter(|a| a.help.is_some()).collect();
    if !described.is_empty() {
        println!("{}", ui::section("arguments"));
        let rows: Vec<(&str, String)> = described
            .iter()
            .map(|a| (a.flag.as_deref().unwrap_or(a.name.as_str()), a.help.clone().unwrap_or_default()))
            .collect();
        print!("{}", ui::kv(&rows));
    }
    println!();
    println!("{}", ui::muted(&format!("Provided by the {addon} add-on: {} {}", c.method, c.path)));
}

// ── the entry point ───────────────────────────────────────────────────────

/// Run `noo <group> ...` when an add-on offers the group. `None` means no
/// add-on does (the caller reports the unknown command).
pub fn run(g: &Globals, rest: &[String]) -> Option<i32> {
    let group = rest.first()?.as_str();
    if !name_ok(group) {
        return None;
    }
    let mut state = load_state(g, false, FETCH_TIMEOUT_SECS);
    let mut found = offered(&state.cache).0.iter().any(|o| o.group.name == group);
    if !found && !state.fetched_now {
        // A group enabled since the cache was written.
        state = load_state(g, true, FETCH_TIMEOUT_SECS);
        found = offered(&state.cache).0.iter().any(|o| o.group.name == group);
    }
    let (groups, warnings) = offered(&state.cache);
    warn_all(&warnings);
    if !found {
        return None;
    }
    let o = groups.iter().find(|o| o.group.name == group)?;
    let on = state.cache.addons.get(o.addon).map(String::as_str) == Some("enabled");
    if !on {
        refuse_off(g, o.addon, state.cache.addons.get(o.addon).map(String::as_str));
    }

    let cmds = commands_of(o);
    let wants_help = |t: &String| matches!(t.as_str(), "--help" | "-h");
    let Some(name) = rest.get(1).filter(|t| !wants_help(t) && t.as_str() != "help") else {
        print_group_help(o, on);
        return Some(0);
    };
    let Some(cmd) = cmds.iter().find(|c| c.name == *name) else {
        let known: Vec<String> = cmds.iter().map(|c| c.name.clone()).collect();
        fail(
            g.json,
            ExitCode::Usage,
            "unknown_command",
            &format!("unknown command `{group} {name}`"),
            Some(&format!("{group} offers: {}", known.join(", "))),
        );
    };
    let args = &rest[2..];
    if args.iter().any(wants_help) {
        print_command_help(cmd, o.addon);
        return Some(0);
    }
    let built = match build(cmd, args) {
        Ok(b) => b,
        Err(why) => {
            let s = syntax(cmd);
            let usage = if s.is_empty() { format!("noo {group} {name}") } else { format!("noo {group} {name} {s}") };
            if g.json {
                eprintln!("{}", json!({"error": why, "code": "usage", "hint": usage}));
            } else {
                ui::failed(&why, None);
                eprintln!("{}", ui::note(&format!("usage: {usage}")));
            }
            return Some(ExitCode::Usage as i32);
        }
    };
    if let Some(q) = &cmd.confirm {
        super::confirm_prompt(g, built.yes, q);
    }
    let resp = {
        let _spin = (cmd.method == "POST").then(|| super::Spinner::start(g, &format!("{group} {name}...")));
        crate::http::request_status(g, &cmd.method, &built.path, built.body.as_ref(), true, COMMAND_TIMEOUT_SECS)
    };
    let resp = match resp {
        Ok(v) => v,
        Err((status, text)) => {
            let said = serde_json::from_str::<Value>(&text).ok().and_then(|v| {
                ["error", "detail", "message"].iter().find_map(|k| v[*k].as_str().map(str::to_string))
            });
            if status == 503 {
                fail(
                    g.json,
                    ExitCode::RemoteError,
                    "addon_unavailable",
                    &said.unwrap_or_else(|| format!("the {} add-on is not available", o.addon)),
                    Some("noo addons list"),
                );
            }
            fail(
                g.json,
                ExitCode::RemoteError,
                "remote_error",
                &format!("gateway returned {status} for {}: {}", cmd.path, said.unwrap_or(text)),
                None,
            );
        }
    };
    if let Some(why) = soft_error(&resp) {
        if g.json {
            println!("{resp}");
            return Some(ExitCode::Generic as i32);
        }
        fail(false, ExitCode::Generic, "addon_error", &why, None);
    }
    if g.json {
        println!("{resp}");
        return Some(0);
    }
    render(cmd, &resp);
    Some(0)
}

/// The add-on is off or unlicensed: say so, with the gateway's own sentence
/// (it names the fix) when it will give it.
fn refuse_off(g: &Globals, addon: &str, word: Option<&str>) -> ! {
    let gateway_says = crate::http::request_try(g, "GET", &format!("/api/addons/{}/cli-piece", super::urlencode(addon)), None, true, FETCH_TIMEOUT_SECS)
        .ok()
        .filter(|(s, _)| *s == 503)
        .and_then(|(_, t)| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v["error"].as_str().map(str::to_string));
    let msg = match word {
        Some("unlicensed") => format!("the {addon} add-on is not licensed"),
        _ => format!("the {addon} add-on is not enabled"),
    };
    let hint = gateway_says.unwrap_or_else(|| format!("noo addons enable {addon}"));
    fail(g.json, ExitCode::RemoteError, "addon_disabled", &msg, Some(&hint));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(name: &str, flag: Option<&str>, kind: &str, required: bool, into: &str) -> Arg {
        Arg { name: name.into(), flag: flag.map(String::from), kind: kind.into(), required, into: into.into(), help: None }
    }

    fn rollback() -> Cmd {
        Cmd {
            group: "ga".into(), name: "rollback".into(), summary: "s".into(), method: "POST".into(),
            path: "/api/ga/rollback".into(),
            args: vec![arg("to", Some("--to"), "int", false, "body:genome_id")],
            confirm: Some("Restore?".into()), output: None,
        }
    }

    fn detail() -> Cmd {
        Cmd {
            group: "loop".into(), name: "detail".into(), summary: "s".into(), method: "GET".into(),
            path: "/api/x/cycles/{cycle_id}".into(),
            args: vec![
                arg("cycle-id", None, "uuid", true, "path:cycle_id"),
                arg("limit", Some("--limit"), "int", false, "query:limit"),
                arg("all", Some("--all"), "bool", false, "query:all"),
            ],
            confirm: None, output: None,
        }
    }

    #[test]
    fn a_body_arg_goes_in_the_json_body_as_its_kind() {
        let b = build(&rollback(), &["--to".into(), "3".into(), "-y".into()]).unwrap();
        assert_eq!(b.body, Some(json!({"genome_id": 3})));
        assert!(b.yes);
        let b = build(&rollback(), &["--to=7".into()]).unwrap();
        assert_eq!(b.body, Some(json!({"genome_id": 7})));
        assert!(!b.yes);
        // No body args still sends a body: the transport picks POST from it.
        assert_eq!(build(&rollback(), &[]).unwrap().body, Some(json!({})));
    }

    #[test]
    fn path_and_query_args_are_encoded_into_the_path() {
        let id = "123e4567-e89b-12d3-a456-426614174000";
        let b = build(&detail(), &[id.into(), "--limit".into(), "5".into(), "--all".into()]).unwrap();
        assert_eq!(b.path, format!("/api/x/cycles/{id}?limit=5&all=true"));
        assert_eq!(b.body, None, "a GET has no body");
    }

    #[test]
    fn bad_arguments_are_refused_with_a_reason() {
        let id = "123e4567-e89b-12d3-a456-426614174000";
        assert!(build(&rollback(), &["--to".into(), "x".into()]).unwrap_err().contains("whole number"));
        assert!(build(&rollback(), &["--to".into()]).unwrap_err().contains("needs a value"));
        assert!(build(&rollback(), &["--bogus".into()]).unwrap_err().contains("unknown option"));
        assert!(build(&rollback(), &["stray".into()]).unwrap_err().contains("unexpected"));
        assert!(build(&detail(), &[]).unwrap_err().contains("missing <cycle-id>"));
        assert!(build(&detail(), &["nope".into()]).unwrap_err().contains("UUID"));
        assert!(build(&detail(), &[id.into(), "--limit".into(), "1.5".into()]).is_err());
    }

    #[test]
    fn values_render_for_a_human() {
        assert_eq!(show(Some(&json!(["a", "b"]))), "a, b");
        assert_eq!(show(Some(&json!(true))), "yes");
        assert_eq!(show(Some(&json!(false))), "no");
        assert_eq!(show(Some(&json!(null))), ui::dash());
        assert_eq!(show(None), ui::dash());
        assert_eq!(show(Some(&json!([]))), ui::dash());
        assert_eq!(show(Some(&json!(4))), "4");
        assert_eq!(show(Some(&json!({"a": 1}))), r#"{"a":1}"#);
    }

    #[test]
    fn a_soft_error_is_found_on_a_2xx_body() {
        assert_eq!(soft_error(&json!({"status": "error", "detail": "no such cycle"})).as_deref(), Some("no such cycle"));
        assert_eq!(soft_error(&json!({"error": "nope"})).as_deref(), Some("nope"));
        assert!(soft_error(&json!({"status": "error"})).is_some());
        assert_eq!(soft_error(&json!({"status": "applied"})), None);
        assert_eq!(soft_error(&json!({"enabled": true})), None);
    }

    #[test]
    fn a_core_collision_is_dropped_with_a_warning() {
        let mut cache = Cache::default();
        cache.pieces.insert(
            "evolve".into(),
            Piece {
                addon: "evolve".into(),
                groups: vec![
                    Group { name: "cluster".into(), summary: "x".into() },
                    Group { name: "ga".into(), summary: "y".into() },
                ],
                commands: vec![],
            },
        );
        let (groups, warnings) = offered_with(&cache, |w| w == "cluster");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group.name, "ga");
        assert!(warnings.len() == 1 && warnings[0].contains("cluster"), "{warnings:?}");
    }

    #[test]
    fn a_cached_command_the_client_would_not_send_is_dropped() {
        let mut c = rollback();
        assert!(cmd_ok(&c));
        c.method = "DELETE".into();
        assert!(!cmd_ok(&c));
        let mut c = rollback();
        c.path = "https://elsewhere.example/x".into();
        assert!(!cmd_ok(&c));
        let mut c = rollback();
        c.path = "/api/../admin".into();
        assert!(!cmd_ok(&c));
        let mut c = rollback();
        c.args[0].into = "header:x".into();
        assert!(!cmd_ok(&c));
    }
}
