// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Add-on access from the CLI (noomesh-internal f99, PR 4's CLI half): the
//! same admin routes the console's Access page uses, so there is one write
//! path and one audit row per change.
//!
//! - `noo addons features <name>`: what an add-on declares, every setting,
//!   stale settings, and who the super admins are
//!   (`GET /api/addons/{addon}/access`, operator or above).
//! - `noo addons set-access <name> <feature>... on|off|inherit --role|--team|--user|--key`:
//!   one setting per feature (`PUT /api/addons/{addon}/access`, admin; a
//!   setting that covers an admin is a super admin's, and turning a feature
//!   off for admins takes `--reason`). The gateway refuses what the policy
//!   refuses and the message is printed as it says it.
//! - `noo addons access <user>`: what one account may use, per add-on and
//!   feature, and the setting that decided it
//!   (`GET /api/security/users/{user}/addon-access`, operator or above).
//!
//! `noo security user super-admin` is in `security.rs`, beside the other
//! account verbs.

use serde_json::{json, Value};

use crate::args::{ArgError, Args};
use crate::http::{get_json, get_json_try, put_json, put_json_try};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

const TIMEOUT: u64 = 15;

/// `<name>`.
pub(crate) fn parse_features_with(a: &mut Args) -> Result<String, ArgError> {
    a.one("<name>")
}

/// `<name> <feature>... on|off|inherit (--role <r>|--team <t>|--user <u>|--key <k>) [--reason <text>]`.
/// `subject` is the gateway's form (`role:user`, `team:studio`, `user:alice`,
/// `key:<consumer>`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SetAccess {
    pub addon: String,
    pub features: Vec<String>,
    pub value: String,
    pub subject: String,
    pub reason: Option<String>,
}

pub(crate) fn parse_set_access_with(a: &mut Args) -> Result<SetAccess, ArgError> {
    let role = a.value(&["--role"])?;
    let team = a.value(&["--team"])?;
    let user = a.value(&["--user"])?;
    let key = a.value(&["--key"])?;
    let reason = a.value(&["--reason"])?;
    let subjects: Vec<String> = [("role", role), ("team", team), ("user", user), ("key", key)]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| format!("{k}:{v}")))
        .collect();
    let mut p = a.positionals()?;
    let subject = match subjects.len() {
        1 => subjects[0].clone(),
        0 => return Err(ArgError::new("say who the setting is for: one of --role, --team, --user or --key")),
        _ => return Err(ArgError::new("one subject per setting: give only one of --role, --team, --user or --key")),
    };
    if p.len() < 3 {
        return Err(ArgError::new("missing arguments: <name> <feature>... on|off|inherit"));
    }
    let value = p.pop().unwrap_or_default().to_ascii_lowercase();
    if !matches!(value.as_str(), "on" | "off" | "inherit") {
        return Err(ArgError::new(format!("the last argument is the setting, one of on, off or inherit (got `{value}`)")));
    }
    let addon = p.remove(0);
    Ok(SetAccess { addon, features: p, value, subject, reason: reason.filter(|r| !r.trim().is_empty()) })
}

/// `<user>`.
pub(crate) fn parse_access_with(a: &mut Args) -> Result<String, ArgError> {
    a.one("<user>")
}

/// `noo addons features <name>`.
pub fn addons_features(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let addon = parse_features_with(&mut Args::new(args))?;
    let body = get_json(g, &format!("/api/addons/{}/access", super::urlencode(&addon)), true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    print!("{}", render_features(&body));
    let set = format!("noo addons set-access {addon} <feature> on --role user");
    ui::guide(&[(set.as_str(), "turn a feature on for every user"), ("noo addons access <user>", "what one account may use, and why")]);
    Ok(0)
}

/// The `features` view of `GET /api/addons/{addon}/access`.
pub(crate) fn render_features(body: &Value) -> String {
    let mut out = String::new();
    let addon = body["addon"].as_str().unwrap_or("?");
    out.push_str(&format!("{}\n", ui::header("addon features", Some(addon))));
    if body["legacy"].as_bool() == Some(true) {
        out.push_str(&format!(
            "{}\n",
            ui::status_line(Glyph::Bullet, &format!("{addon} declares no features: each route's own role decides, as before (a legacy manifest)"))
        ));
    } else {
        let rows: Vec<Vec<String>> = body["features"]
            .as_array()
            .map(|a| a.as_slice())
            .unwrap_or_default()
            .iter()
            .map(|f| {
                let routes = f["routes"].as_array().map(|r| r.len()).unwrap_or(0);
                vec![
                    f["name"].as_str().unwrap_or("").to_string(),
                    f["title"].as_str().unwrap_or("").to_string(),
                    f["suggested"].as_str().map(str::to_string).unwrap_or_else(|| cell(&f["suggested"])),
                    format!("{routes}{}", if f["ui"].as_bool() == Some(true) { " + ui" } else { "" }),
                ]
            })
            .collect();
        out.push_str(&format!("{}\n", ui::section("declared")));
        out.push_str(&ui::table(&[Col::left("feature"), Col::left("title"), Col::left("suggested"), Col::left("routes")], &rows));
    }
    out.push_str(&format!("{}\n", ui::section("settings")));
    out.push_str(&render_settings(body["settings"].as_array().map(|a| a.as_slice()).unwrap_or_default()));
    let stale: Vec<&str> = body["stale_features"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    if !stale.is_empty() {
        out.push_str(&format!(
            "{}\n",
            ui::status_line(Glyph::Warn, &format!("set for features it no longer declares (kept, they open nothing): {}", stale.join(", ")))
        ));
    }
    let supers: Vec<&str> = body["super_admins"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    out.push_str(&format!(
        "{}\n",
        ui::kv(&[("super admins", if supers.is_empty() { ui::dash().to_string() } else { supers.join(", ") })])
    ));
    out
}

fn render_settings(settings: &[Value]) -> String {
    if settings.is_empty() {
        return format!("{}\n", ui::status_line(Glyph::Bullet, "none set: every feature is off except for super admins"));
    }
    let rows: Vec<Vec<String>> = settings
        .iter()
        .map(|s| {
            vec![
                s["feature"].as_str().unwrap_or("").to_string(),
                s["subject"].as_str().unwrap_or("").to_string(),
                if s["allowed"].as_bool() == Some(true) { "on".into() } else { "off".into() },
                s["set_by"].as_str().unwrap_or("").to_string(),
                s["reason"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    ui::table(&[Col::left("feature"), Col::left("for"), Col::left("is"), Col::left("set by"), Col::left("reason")], &rows)
}

/// One declared feature and who, below admin, it is on for, read from
/// `GET /api/addons/{addon}/access`. Super admins always hold every feature,
/// and a `role:admin` setting covers admins only, so neither counts here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FeatureGrant {
    pub name: String,
    /// The add-on's suggested audience: `user`, `operator`, `admin` or `none`.
    pub suggested: String,
    /// Subjects it is on for, other than `role:admin` (a `*` setting counts for every feature).
    pub on_for: Vec<String>,
}

impl FeatureGrant {
    /// The add-on suggests it for users or operators and nobody below admin
    /// has it: usually an `enable` that skipped the suggestions. A feature
    /// suggested for admin (or for nobody) may be admin-only on purpose, so it
    /// never counts (proposal f99 section 6).
    pub fn suggestion_unmet(&self) -> bool {
        matches!(self.suggested.as_str(), "user" | "operator") && self.on_for.is_empty()
    }
}

/// Every declared feature of the access body, in declaration order. Empty for
/// a legacy manifest (no features).
pub(crate) fn feature_grants(body: &Value) -> Vec<FeatureGrant> {
    let settings = body["settings"].as_array().map(|a| a.as_slice()).unwrap_or_default();
    body["features"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|f| {
            let name = f["name"].as_str().unwrap_or("").to_string();
            let mut on_for: Vec<String> = settings
                .iter()
                .filter(|s| s["allowed"].as_bool() == Some(true))
                .filter(|s| s["feature"].as_str().is_some_and(|x| x == name || x == "*"))
                .filter_map(|s| s["subject"].as_str())
                .filter(|s| *s != "role:admin")
                .map(str::to_string)
                .collect();
            on_for.sort();
            on_for.dedup();
            let suggested = f["suggested"].as_str().filter(|s| !s.is_empty()).unwrap_or("none").to_string();
            FeatureGrant { name, suggested, on_for }
        })
        .collect()
}

/// The stale settings' features (kept, they open nothing).
pub(crate) fn stale_features(body: &Value) -> Vec<String> {
    let mut v: Vec<String> =
        body["stale_features"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

/// The `features` block of `noo addons show <name>`: per feature, its
/// suggestion and who it is on for, with the suggested-not-granted ones
/// marked, and any stale settings.
pub(crate) fn render_show_features(addon: &str, body: &Value) -> String {
    let mut out = format!("{}\n", ui::section("features"));
    if body["legacy"].as_bool() == Some(true) {
        out.push_str(&format!("{}\n", ui::muted("  none declared: each route's own role decides (a legacy manifest)")));
    } else {
        let grants = feature_grants(body);
        if grants.is_empty() {
            out.push_str(&format!("{}\n", ui::muted("  none declared")));
        }
        let rows: Vec<Vec<String>> = grants
            .iter()
            .map(|f| {
                let on = if f.on_for.is_empty() { ui::muted("admins only") } else { f.on_for.join(", ") };
                let note = if f.suggestion_unmet() { ui::warn("suggested, not granted") } else { String::new() };
                vec![f.name.clone(), f.suggested.clone(), on, note]
            })
            .collect();
        if !rows.is_empty() {
            out.push_str(&ui::table(&[Col::left("feature"), Col::left("suggested"), Col::left("on for"), Col::left("")], &rows));
        }
    }
    let stale = stale_features(body);
    if !stale.is_empty() {
        out.push_str(&format!(
            "{}\n",
            ui::status_line(Glyph::Warn, &format!("set for features {addon} no longer declares (kept, they open nothing): {}", stale.join(", ")))
        ));
    }
    out
}

fn cell(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ── suggestions become grants (f99 3.2) ──────────────────────────────────
//
// An add-on's `suggested` audience grants nothing. It becomes a grant only
// when an admin accepts it, once, here: `noo addons accept-suggestions`, which
// `enable` runs when the gateway already has the add-on loaded. The question
// is asked against the gateway's live feature list, never the bundle on disk,
// and an upgrade never asks it.

/// What the caller said about the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Consent {
    /// `--yes` (`enable --accept-suggested`): accept without asking.
    Yes,
    /// Nothing said: ask on a TTY, otherwise print the command.
    Ask,
    /// `enable --no-grants`: do not ask.
    No,
}

/// What to do about pending suggestions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Act {
    Write,
    Prompt,
    /// `--json` or no TTY: never prompt, write nothing, print the command.
    Hint,
    Skip,
}

pub(crate) fn act_for(consent: Consent, json: bool, tty: bool) -> Act {
    match consent {
        Consent::Yes => Act::Write,
        Consent::No => Act::Skip,
        Consent::Ask if json || !tty => Act::Hint,
        Consent::Ask => Act::Prompt,
    }
}

/// `(feature, role)` for each feature the add-on suggests for `user` or
/// `operator` whose cell for that role is not set yet (on or off: an admin's
/// explicit `off` is a decision, not a gap). Declaration order.
pub(crate) fn pending_suggestions(body: &Value) -> Vec<(String, String)> {
    let settings = body["settings"].as_array().map(|a| a.as_slice()).unwrap_or_default();
    feature_grants(body)
        .into_iter()
        .filter(|f| matches!(f.suggested.as_str(), "user" | "operator"))
        .filter(|f| {
            let cell = format!("role:{}", f.suggested);
            !settings.iter().any(|s| s["feature"].as_str() == Some(f.name.as_str()) && s["subject"].as_str() == Some(cell.as_str()))
        })
        .map(|f| (f.name, f.suggested))
        .collect()
}

/// The command that asks the question.
pub(crate) fn accept_command(addon: &str) -> String {
    format!("noo addons accept-suggestions {addon}")
}

/// What the question came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Suggestions {
    Legacy,
    NothingPending,
    Hinted(Vec<(String, String)>),
    Skipped(Vec<(String, String)>),
    Declined(Vec<(String, String)>),
    Written { on: Vec<(String, String)>, failed: Vec<(String, String, String)> },
}

impl Suggestions {
    pub(crate) fn json(&self) -> Value {
        let pairs = |v: &[(String, String)]| v.iter().map(|(f, r)| json!({"feature": f, "role": r})).collect::<Vec<_>>();
        match self {
            Suggestions::Legacy => json!({"legacy": true}),
            Suggestions::NothingPending => json!({"pending": []}),
            Suggestions::Hinted(p) => json!({"pending": pairs(p), "written": false}),
            Suggestions::Skipped(p) => json!({"pending": pairs(p), "written": false, "skipped": true}),
            Suggestions::Declined(p) => json!({"pending": pairs(p), "written": false, "declined": true}),
            Suggestions::Written { on, failed } => json!({
                "accepted": pairs(on),
                "failed": failed.iter().map(|(f, r, e)| json!({"feature": f, "role": r, "error": e})).collect::<Vec<_>>(),
            }),
        }
    }

    /// Human lines (no trailing newline per line; one per entry).
    pub(crate) fn lines(&self, addon: &str) -> Vec<(Glyph, String)> {
        let list = |v: &[(String, String)]| v.iter().map(|(f, r)| format!("{f} for {r}")).collect::<Vec<_>>().join(", ");
        match self {
            Suggestions::Legacy => vec![(Glyph::Bullet, format!("{addon} declares no features: its routes keep their own roles"))],
            Suggestions::NothingPending => vec![(Glyph::Ok, format!("{addon}: every suggested feature is already set"))],
            Suggestions::Hinted(p) => vec![(
                Glyph::Bullet,
                format!("{addon} suggests {}: not turned on (asked only on a terminal, or with --yes)", list(p)),
            )],
            Suggestions::Skipped(p) => vec![(Glyph::Bullet, format!("{addon} suggests {}: left off (--no-grants)", list(p)))],
            Suggestions::Declined(p) => vec![(Glyph::Bullet, format!("{addon} suggests {}: left off", list(p)))],
            Suggestions::Written { on, failed } => {
                let mut v = Vec::new();
                if !on.is_empty() {
                    v.push((Glyph::Ok, format!("{addon}: turned on as suggested: {}", list(on))));
                }
                for (f, r, e) in failed {
                    v.push((Glyph::Err, format!("{addon}: {f} for {r} not turned on: {e}")));
                }
                v
            }
        }
    }
}

/// Ask the question against the gateway's live feature list. `Err` is the
/// read's error: the gateway has not loaded the add-on (404 until the next
/// `noo stack restart --force`) or could not be reached.
pub(crate) fn run_suggestions(g: &Globals, addon: &str, consent: Consent) -> Result<Suggestions, String> {
    let path = format!("/api/addons/{}/access", super::urlencode(addon));
    let body = get_json_try(g, &path, true, TIMEOUT)?;
    if body["legacy"].as_bool() == Some(true) {
        return Ok(Suggestions::Legacy);
    }
    let pending = pending_suggestions(&body);
    if pending.is_empty() {
        return Ok(Suggestions::NothingPending);
    }
    let tty = unsafe { libc::isatty(0) } == 1;
    match act_for(consent, g.json, tty) {
        Act::Skip => Ok(Suggestions::Skipped(pending)),
        Act::Hint => Ok(Suggestions::Hinted(pending)),
        Act::Prompt => {
            use std::io::{BufRead as _, Write as _};
            println!("{}", ui::section(&format!("{addon} suggests")));
            for (f, r) in &pending {
                let title = body["features"]
                    .as_array()
                    .and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(f.as_str())))
                    .and_then(|x| x["title"].as_str())
                    .unwrap_or("");
                println!("  {f} ({title}): every {r}");
            }
            eprint!("Turn these on as suggested? [y/N]: ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            let _ = std::io::stdin().lock().read_line(&mut line);
            if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                Ok(write_suggestions(g, &path, pending))
            } else {
                Ok(Suggestions::Declined(pending))
            }
        }
        Act::Write => Ok(write_suggestions(g, &path, pending)),
    }
}

fn write_suggestions(g: &Globals, path: &str, pending: Vec<(String, String)>) -> Suggestions {
    let (mut on, mut failed) = (Vec::new(), Vec::new());
    for (f, r) in pending {
        let body = json!({"feature": f, "subject": format!("role:{r}"), "value": "on", "source": "accepted_suggestion"});
        match put_json_try(g, path, &body, true, TIMEOUT) {
            Ok(_) => on.push((f, r)),
            Err(e) => failed.push((f, r, e)),
        }
    }
    Suggestions::Written { on, failed }
}

/// The line that says when to ask, for an add-on the gateway has not loaded.
pub(crate) fn not_loaded_line(addon: &str, why: &str) -> String {
    format!("{addon}: suggested access not asked yet: the gateway loads it on the next `noo stack restart --force` ({why}); then: {}", accept_command(addon))
}

/// `<name> [--yes]`.
pub(crate) fn parse_accept_suggestions_with(a: &mut Args) -> Result<(String, bool), ArgError> {
    let yes = a.flag(&["--yes", "-y"]);
    let addon = a.one("<name>")?;
    Ok((addon, yes))
}

/// `noo addons accept-suggestions <name> [--yes]`: turn each feature on for
/// the audience its add-on suggests, once, as an admin's decision recorded
/// `accepted_suggestion`. Asks on a terminal; `--json` and pipes never
/// prompt and write nothing without `--yes`.
pub fn addons_accept_suggestions(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (addon, yes) = parse_accept_suggestions_with(&mut Args::new(args))?;
    let consent = if yes { Consent::Yes } else { Consent::Ask };
    let s = match run_suggestions(g, &addon, consent) {
        Ok(s) => s,
        Err(e) if e.contains("not registered") => crate::output::fail(
            g.json,
            crate::output::ExitCode::Generic,
            "addon_not_loaded",
            &format!("the gateway has not loaded {addon} yet, so its features cannot be read or set ({e})"),
            Some("noo stack restart --force   # then run this again"),
        ),
        Err(e) => crate::output::fail(g.json, crate::output::ExitCode::Generic, "access_unread", &e, Some(&format!("noo addons features {addon}"))),
    };
    let failed = matches!(&s, Suggestions::Written { failed, .. } if !failed.is_empty());
    if g.json {
        println!("{}", json!({"addon": addon, "suggestions": s.json()}));
    } else {
        for (glyph, line) in s.lines(&addon) {
            println!("{}", ui::status_line(glyph, &line));
        }
        if let Suggestions::Hinted(_) = s {
            let cmd = format!("{} --yes", accept_command(&addon));
            ui::guide(&[(cmd.as_str(), "turn them on as suggested")]);
        }
    }
    Ok(if failed { 1 } else { 0 })
}

/// `noo addons set-access <name> <feature>... on|off|inherit --role|--team|--user|--key [--reason]`.
pub fn addons_set_access(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let SetAccess { addon, features, value, subject, reason } = parse_set_access_with(&mut Args::new(args))?;
    let path = format!("/api/addons/{}/access", super::urlencode(&addon));
    let mut results = Vec::new();
    if !g.json {
        ui::step(&format!("setting {} for {subject} on {addon}: {value}", features.join(", ")));
    }
    for feature in &features {
        let body = set_body(feature, &subject, &value, reason.as_deref());
        // The gateway refuses what the policy refuses (an unknown feature,
        // `*` outside its two cases, a write feature below operator without
        // owner_scoped, an admin setting by a non-super-admin, off for admins
        // without a reason) and put_json prints that refusal and exits.
        let r = put_json(g, &path, &body, true, TIMEOUT);
        if !g.json {
            println!("{}", ui::sub(&ui::status_line(Glyph::Ok, &format!("{feature}: {} -> {}", cell(&r["from"]), cell(&r["to"])))));
        }
        results.push(r);
    }
    if g.json {
        println!("{}", json!({"addon": addon, "subject": subject, "value": value, "changes": results}));
        return Ok(0);
    }
    ui::close_done(&format!("{addon}: {} setting(s) changed for {subject}", results.len()));
    let mut next: Vec<(String, &str)> = vec![(format!("noo addons features {addon}"), "every setting on this add-on")];
    if let Some(u) = subject.strip_prefix("user:") {
        next.push((format!("noo addons access {u}"), "what that account may use now, and why"));
    }
    let next: Vec<(&str, &str)> = next.iter().map(|(c, w)| (c.as_str(), *w)).collect();
    ui::guide(&next);
    Ok(0)
}

/// One PUT body: `inherit` removes the setting; a reason goes only when given.
pub(crate) fn set_body(feature: &str, subject: &str, value: &str, reason: Option<&str>) -> Value {
    let mut b = json!({"feature": feature, "subject": subject, "value": value});
    if let Some(r) = reason {
        b["reason"] = json!(r);
    }
    b
}

/// `noo addons access <user>`.
pub fn addons_access(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let user = parse_access_with(&mut Args::new(args))?;
    let body = get_json(g, &format!("/api/security/users/{}/addon-access", super::urlencode(&user)), true, TIMEOUT);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    print!("{}", render_person(&body));
    let set = format!("noo addons set-access <addon> <feature> on --user {user}");
    ui::guide(&[(set.as_str(), "change one feature for this account (on, off or inherit)")]);
    Ok(0)
}

/// The person view of `GET /api/security/users/{user}/addon-access`.
pub(crate) fn render_person(body: &Value) -> String {
    let mut out = String::new();
    let account = body["account"].as_str().unwrap_or("?");
    out.push_str(&format!("{}\n", ui::header("addon access", Some(account))));
    let teams: Vec<&str> = body["teams"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    out.push_str(&format!(
        "{}\n",
        ui::kv(&[
            ("role", body["role"].as_str().unwrap_or("-").to_string()),
            ("teams", if teams.is_empty() { ui::dash().to_string() } else { teams.join(", ") }),
            ("super admin", if body["super_admin"].as_bool() == Some(true) { "yes (holds every feature)".into() } else { "no".into() }),
        ])
    ));
    let addons = body["addons"].as_array().map(|a| a.as_slice()).unwrap_or_default();
    if addons.is_empty() {
        out.push_str(&format!("{}\n", ui::status_line(Glyph::Bullet, "no add-on is switched on")));
    }
    for a in addons {
        let name = a["addon"].as_str().unwrap_or("?");
        out.push_str(&format!("{}\n", ui::section(name)));
        if a["legacy"].as_bool() == Some(true) {
            out.push_str(&format!("{}\n", ui::status_line(Glyph::Bullet, "declares no features: each route's own role decides")));
            continue;
        }
        let rows: Vec<Vec<String>> = a["features"]
            .as_array()
            .map(|f| f.as_slice())
            .unwrap_or_default()
            .iter()
            .map(|f| {
                vec![
                    f["feature"].as_str().unwrap_or("").to_string(),
                    if f["allowed"].as_bool() == Some(true) { "on".into() } else { "off".into() },
                    cell(&f["decided_by"]),
                    f["title"].as_str().unwrap_or("").to_string(),
                ]
            })
            .collect();
        out.push_str(&ui::table(&[Col::left("feature"), Col::left("is"), Col::left("decided by"), Col::left("title")], &rows));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn show_body() -> Value {
        json!({
            "addon": "rhaddon", "legacy": false,
            "features": [
                {"name": "converse", "title": "Talk", "suggested": "user"},
                {"name": "transcripts", "title": "Read", "suggested": "operator"},
                {"name": "manage", "title": "Manage", "suggested": "admin"},
                {"name": "unlabelled", "title": "No suggestion", "suggested": null}
            ],
            "settings": [
                {"addon": "rhaddon", "feature": "converse", "subject": "role:admin", "allowed": true},
                {"addon": "rhaddon", "feature": "transcripts", "subject": "team:studio", "allowed": true},
                {"addon": "rhaddon", "feature": "transcripts", "subject": "user:bob", "allowed": false},
                {"addon": "rhaddon", "feature": "export", "subject": "role:user", "allowed": true}
            ],
            "stale_features": ["export"],
            "super_admins": ["root"]
        })
    }

    #[test]
    fn feature_grants_read_who_below_admin_holds_each_feature() {
        let g = feature_grants(&show_body());
        let by = |n: &str| g.iter().find(|f| f.name == n).cloned().unwrap();
        assert_eq!(g.len(), 4, "the stale `export` setting is not a declared feature");
        assert!(by("converse").on_for.is_empty(), "role:admin is not below admin");
        assert!(by("converse").suggestion_unmet());
        assert_eq!(by("transcripts").on_for, vec!["team:studio".to_string()], "an off setting grants nothing");
        assert!(!by("transcripts").suggestion_unmet());
        assert!(!by("manage").suggestion_unmet(), "suggested for admin: admin-only may be on purpose");
        assert_eq!(by("unlabelled").suggested, "none");
        assert!(!by("unlabelled").suggestion_unmet());
    }

    #[test]
    fn show_marks_the_suggested_not_granted_and_the_stale() {
        let out = render_show_features("rhaddon", &show_body());
        let line = |n: &str| out.lines().find(|l| l.contains(n)).unwrap_or_default().to_string();
        assert!(line("converse").contains("suggested, not granted"), "{out}");
        assert!(line("converse").contains("admins only"), "{out}");
        assert!(line("transcripts").contains("team:studio") && !line("transcripts").contains("not granted"), "{out}");
        assert!(!line("manage").contains("not granted"), "{out}");
        assert!(out.contains("no longer declares (kept, they open nothing): export"), "{out}");
        let legacy = render_show_features("old", &json!({"addon": "old", "legacy": true, "features": [], "settings": []}));
        assert!(legacy.contains("legacy manifest"), "{legacy}");
    }

    #[test]
    fn json_and_pipes_never_prompt_and_write_only_with_yes() {
        assert_eq!(act_for(Consent::Yes, true, false), Act::Write);
        assert_eq!(act_for(Consent::Yes, false, true), Act::Write);
        assert_eq!(act_for(Consent::Ask, true, true), Act::Hint, "--json never prompts, even on a terminal");
        assert_eq!(act_for(Consent::Ask, false, false), Act::Hint, "a pipe never prompts");
        assert_eq!(act_for(Consent::Ask, false, true), Act::Prompt);
        assert_eq!(act_for(Consent::No, false, true), Act::Skip);
        assert_eq!(act_for(Consent::No, true, false), Act::Skip);
    }

    #[test]
    fn pending_suggestions_are_the_unset_user_or_operator_cells() {
        let body = json!({
            "addon": "rhaddon", "legacy": false,
            "features": [
                {"name": "converse", "title": "Talk", "suggested": "user"},
                {"name": "transcripts", "title": "Read", "suggested": "user"},
                {"name": "review", "title": "Review", "suggested": "operator"},
                {"name": "export", "title": "Export", "suggested": "operator"},
                {"name": "manage", "title": "Manage", "suggested": "admin"},
                {"name": "internal", "title": "Internal", "suggested": "none"}
            ],
            "settings": [
                {"feature": "transcripts", "subject": "role:user", "allowed": false},
                {"feature": "export", "subject": "role:operator", "allowed": true},
                {"feature": "review", "subject": "team:studio", "allowed": true}
            ]
        });
        assert_eq!(
            pending_suggestions(&body),
            vec![("converse".to_string(), "user".to_string()), ("review".to_string(), "operator".to_string())],
            "an explicit off is a decision; a set cell is done; admin and none are never suggestions to accept"
        );
        assert!(pending_suggestions(&json!({"legacy": true, "features": [], "settings": []})).is_empty());
    }

    #[test]
    fn accept_suggestions_parses_name_and_yes() {
        assert_eq!(parse_accept_suggestions_with(&mut args(&["rhaddon"])).unwrap(), ("rhaddon".to_string(), false));
        assert_eq!(parse_accept_suggestions_with(&mut args(&["rhaddon", "--yes"])).unwrap(), ("rhaddon".to_string(), true));
        assert_eq!(parse_accept_suggestions_with(&mut args(&["-y", "rhaddon"])).unwrap(), ("rhaddon".to_string(), true));
        assert!(parse_accept_suggestions_with(&mut args(&[])).is_err());
    }

    #[test]
    fn a_write_records_accepted_suggestion_and_the_outcome_says_what_happened() {
        let src = include_str!("addon_access.rs");
        let body = src.split("fn write_suggestions(").nth(1).unwrap().split("\n\u{7d}\n").next().unwrap();
        assert!(body.contains(r#""source": "accepted_suggestion""#), "the gateway validates this; the CLI must send it");
        assert!(body.contains(r#""value": "on""#));
        let w = Suggestions::Written { on: vec![("converse".into(), "user".into())], failed: vec![("review".into(), "operator".into(), "HTTP 400".into())] };
        assert_eq!(w.json()["accepted"][0]["feature"], "converse");
        assert_eq!(w.json()["failed"][0]["error"], "HTTP 400");
        let h = Suggestions::Hinted(vec![("converse".into(), "user".into())]);
        assert_eq!(h.json()["written"], false);
        assert!(h.lines("rhaddon")[0].1.contains("converse for user"));
    }

    #[test]
    fn enable_refuses_accept_suggested_before_it_changes_anything_and_upgrade_never_asks() {
        let addons = include_str!("addons.rs");
        let set = addons.split("fn set(g: &Globals").nth(1).unwrap().split("\npub fn addons_enable").next().unwrap();
        let refuse = set.find("--accept-suggested needs the gateway to have").expect("the up-front refusal");
        let enable = set.find("addon_enable::enable(").expect("the enable step");
        assert!(refuse < enable, "refused before the switch, the key or the pin is touched");
        let ask = set.find("access::run_suggestions(g, name, consent)").expect("asked after enable");
        assert!(enable < ask, "asked only once the switch is on");
        // The question has exactly two callers: this verb and enable. An
        // upgrade never grants (proposal 3.2).
        let code = |t: &'static str| t.split("\n#[cfg(test)]").next().unwrap();
        let call = ["run_suggestions", "(g,"].concat();
        let callers = code(addons).matches(&call).count() + code(include_str!("addon_access.rs")).matches(&call).count();
        assert_eq!(callers, 2, "run_suggestions is called from enable and accept-suggestions only");
        for upgrade in [include_str!("addon_pins.rs"), include_str!("addon_lock_cmd.rs")] {
            assert!(!upgrade.contains("run_suggestions") && !upgrade.contains("accepted_suggestion"));
        }
    }

    fn args(v: &[&str]) -> Args {
        Args::new(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn set_access_takes_features_then_the_value_and_exactly_one_subject() {
        let s = parse_set_access_with(&mut args(&["rhaddon", "voice", "transcribe", "on", "--role", "user"])).unwrap();
        assert_eq!(
            s,
            SetAccess {
                addon: "rhaddon".into(),
                features: vec!["voice".into(), "transcribe".into()],
                value: "on".into(),
                subject: "role:user".into(),
                reason: None,
            }
        );
        let s = parse_set_access_with(&mut args(&["rhaddon", "voice", "OFF", "--user", "guest", "--reason", "trial ended"])).unwrap();
        assert_eq!((s.value.as_str(), s.subject.as_str(), s.reason.as_deref()), ("off", "user:guest", Some("trial ended")));
        for (bad, why) in [
            (vec!["rhaddon", "voice", "on"], "say who"),
            (vec!["rhaddon", "voice", "on", "--role", "user", "--team", "studio"], "one subject"),
            (vec!["rhaddon", "on", "--role", "user"], "missing arguments"),
            (vec!["rhaddon", "voice", "maybe", "--role", "user"], "on, off or inherit"),
            (vec!["rhaddon", "voice", "on", "--role", "user", "--bogus"], "unknown flag"),
        ] {
            let e = parse_set_access_with(&mut args(&bad)).unwrap_err();
            assert!(e.0.contains(why), "{bad:?}: {e}");
        }
    }

    #[test]
    fn the_put_body_is_the_routes_shape() {
        assert_eq!(set_body("voice", "role:user", "on", None), json!({"feature": "voice", "subject": "role:user", "value": "on"}));
        assert_eq!(
            set_body("voice", "role:admin", "off", Some("cost")),
            json!({"feature": "voice", "subject": "role:admin", "value": "off", "reason": "cost"})
        );
    }

    /// Driven by the route's JSON as `access_get` builds it.
    #[test]
    fn features_shows_declared_settings_stale_and_super_admins() {
        let body = json!({
            "addon": "rhaddon", "legacy": false,
            "features": [{"name": "voice", "title": "Talk to the assistant", "description": "", "suggested": "user",
                          "delegate": false, "routes": ["speak", "listen"], "ui": true, "has_unscoped_write": false}],
            "settings": [{"addon": "rhaddon", "feature": "voice", "subject": "user:guest", "allowed": false,
                          "set_by": "admin", "set_at": "2026-11-02T10:00:00Z", "source": "operator", "reason": "trial ended"}],
            "stale_features": ["old-thing"],
            "super_admins": ["admin"],
        });
        // The ui helpers capitalise section titles and status lines, so the
        // words are compared without case.
        let out = render_features(&body);
        for want in ["voice", "talk to the assistant", "2 + ui", "user:guest", "trial ended", "old-thing", "admin"] {
            assert!(out.to_lowercase().contains(want), "missing {want:?} in:\n{out}");
        }
        let legacy = render_features(&json!({"addon": "rhaddon", "legacy": true, "features": [], "settings": [], "stale_features": [], "super_admins": []}));
        let low = legacy.to_lowercase();
        assert!(low.contains("rhaddon declares no features") && low.contains("none set"), "{legacy}");
    }

    /// Driven by the route's JSON as `person_view` builds it.
    #[test]
    fn access_shows_each_feature_and_what_decided_it() {
        let body = json!({
            "account": "guest", "role": "user", "teams": ["studio"], "super_admin": false,
            "addons": [
                {"addon": "rhaddon", "legacy": false, "features": [
                    {"feature": "voice", "title": "Talk", "allowed": false, "decided_by": "user:guest"},
                    {"feature": "transcribe", "title": "Transcribe", "allowed": true, "decided_by": "team:studio"}]},
                {"addon": "rhaddon", "legacy": true, "features": []},
            ],
        });
        let out = render_person(&body);
        for want in ["guest", "studio", "voice", "user:guest", "transcribe", "team:studio", "rhaddon", "declares no features"] {
            assert!(out.to_lowercase().contains(want), "missing {want:?} in:\n{out}");
        }
    }
}
