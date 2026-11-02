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
use crate::http::{get_json, put_json};
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

fn cell(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
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
