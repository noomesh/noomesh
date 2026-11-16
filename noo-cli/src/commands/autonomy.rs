// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo autonomy …` — autonomy engine monitoring & control (Rust gateway
//! routes in `routes/intelligence.rs`).
//!
//! Ported: status, locations (same fetch/render as status — Python parity),
//! audit, enable, disable.
//! Left in Python: nothing — the whole group is ported.

use super::truncate;
use crate::args::{ArgError, Args};
use crate::http::{get_json, post_json};
use crate::ui::{self, Col, Glyph};
use crate::{Globals, Unhandled};

use super::ago;


/// `noo autonomy status` / `noo autonomy locations` — GET /api/autonomy/status.
/// Python's `locations` command is an alias for the status view.
pub fn autonomy_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let body = get_json(g, "/api/autonomy/status", true, 10);
    if g.json {
        println!("{body}");
        return Ok(super::json_exit(&body));
    }
    // `running` is a NULLABLE bool: null means the autonomy_engine loop has
    // never reported a tick, i.e. the gateway does not know. This used to
    // `.unwrap_or(false)` and print "STOPPED" — asserting the engine was down
    // on no evidence. Same for `audit_entries`, whose null (audit store
    // unreadable) rendered as a confident "audit entries: 0".
    let mut running = match body["running"].as_bool() {
        Some(true) => ui::state("running"),
        Some(false) => ui::state("stopped"),
        None => ui::warn("unknown"),
    };
    if let Some(detail) = body["running_detail"].as_str() {
        running = format!("{running}  {}", ui::muted(detail));
    }
    let mut audit = match body["audit_entries"].as_u64() {
        Some(n) => n.to_string(),
        None => ui::warn("not tracked"),
    };
    if body["audit_entries"].is_null() {
        if let Some(detail) = body["audit_detail"].as_str() {
            audit = format!("{audit}  {}", ui::muted(detail));
        }
    }
    println!(
        "{}",
        ui::header(
            "autonomy",
            Some(&format!(
                "{}/{} locations enabled",
                body["locations_enabled"].as_u64().unwrap_or(0),
                body["locations_total"].as_u64().unwrap_or(0)
            ))
        )
    );
    print!(
        "{}",
        ui::kv(&[
            ("engine", running),
            (
                "enabled",
                match body["enabled"].as_bool() {
                    Some(true) => ui::ok("yes"),
                    Some(false) => "no".into(),
                    None => ui::warn("unknown"),
                },
            ),
            ("audit entries", audit),
        ])
    );
    let empty = Vec::new();
    let locs = body["locations"].as_array().unwrap_or(&empty);
    if locs.is_empty() {
        println!("{}", ui::muted("no locations configured"));
        return Ok(0);
    }
    println!("{}", ui::section("locations"));
    // ARMED is the operator's real question before turning anything on:
    // does this location's action CHANGE the fleet, or only alert? The
    // gateway reports `armed` (the resolved `enabled_action`) and `dry_run`
    // per location. A location with no action gate reports neither, and an
    // older gateway reports nothing at all — both render as a dash. Never
    // print a confident "off" for a field the gateway did not send: that is
    // the same lie `running.unwrap_or(false)` used to tell.
    let mut any_armed = false;
    let reports_arming = locs.iter().any(|l| !l["armed"].is_null());
    let rows: Vec<Vec<String>> = locs
        .iter()
        .map(|l| {
            let on = l["enabled"].as_bool().unwrap_or(false);
            let armed = match (l["armed"].as_bool(), l["dry_run"].as_bool()) {
                // Title Case across the whole column (guide §4 "Case"):
                // Armed / Dry-run / Off, not a mix.
                (Some(true), Some(true)) => ui::state("Dry-run"),
                (Some(true), _) => {
                    any_armed = true;
                    ui::warn("Armed")
                }
                (Some(false), _) => ui::muted("Off").to_string(),
                // No `armed` key: either an alert-only location (correct,
                // it has no gate) or a gateway too old to report the field.
                // Distinguished below by whether ANY location reported it —
                // per-location guessing produced a false warning on every
                // alert location.
                (None, _) => ui::dash().to_string(),
            };
            vec![
                ui::glyph_cell(if on { Glyph::Ok } else { Glyph::Bullet }),
                truncate(l["name"].as_str().unwrap_or("?"), 28),
                truncate(l["type"].as_str().unwrap_or("?"), 10),
                if on { "on".into() } else { ui::muted("off") },
                armed,
                format!("{}s", l["interval"].as_u64().unwrap_or(0)),
                ago(&l["last_check"]),
                ago(&l["last_fired"]),
                l["conditions"].as_u64().unwrap_or(0).to_string(),
                l["actions"].as_u64().unwrap_or(0).to_string(),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::left("name"),
                Col::left("type"),
                Col::left("state"),
                Col::left("armed"),
                Col::right("interval"),
                Col::right("last check"),
                Col::right("last fired"),
                Col::right("conds"),
                Col::right("acts"),
            ],
            &rows,
        )
    );
    if !reports_arming {
        println!(
            "{}",
            ui::note(
                "this gateway does not report whether an action is armed; \
                 the dashes are unknown, not off"
            )
        );
    }
    if any_armed {
        println!(
            "{}",
            ui::note("armed locations change the fleet without asking")
        );
    }
    ui::guide(&[
        ("noo autonomy decisions", "what the disarmed locations would have done"),
        ("noo autonomy audit", "what the engine actually did"),
        ("noo autonomy disable", "stop the whole engine (the global kill switch)"),
    ]);
    Ok(0)
}

pub(crate) fn parse_audit_with(a: &mut Args) -> Result<u64, ArgError> {
    let limit = a.number::<u64>(&["--limit", "-n"])?.unwrap_or(20);
    a.finish()?;
    Ok(limit)
}

/// `noo autonomy audit [--limit N]` — GET /api/autonomy/audit?limit=.
pub fn autonomy_audit(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let limit = parse_audit_with(&mut Args::new(args))?;
    let body = get_json(g, &format!("/api/autonomy/audit?limit={limit}"), true, 10);
    if g.json {
        println!("{body}");
        return Ok(0);
    }
    // The audit route answers HTTP 200 with {"entries": null, "error": …,
    // "detail": …} when no audit store is readable. `.unwrap_or(&empty)`
    // turned that into "no audit entries yet" — reporting that autonomy had
    // never acted, when the truth is that nobody was recording. Only an
    // actual empty array means "nothing fired".
    let Some(entries) = body["entries"].as_array() else {
        let err = body["error"].as_str().unwrap_or("audit entries not reported by the gateway");
        ui::failed(&format!("cannot read autonomy audit log: {err}"), None);
        if let Some(detail) = body["detail"].as_str() {
            eprintln!("  {}", ui::muted(detail));
        }
        return Ok(crate::output::ExitCode::RemoteError as i32);
    };
    if entries.is_empty() {
        println!("{}", ui::muted("no audit entries yet"));
        return Ok(0);
    }
    println!("{}", ui::header("autonomy audit", Some(&format!("last {}", entries.len()))));
    println!("{}", ui::section("entries"));
    // Shape follows migration 058: the old timestamp/condition/action_config
    // columns described a table that never existed. `outcome` leads because
    // it is what separates an action from a decision NOT to act — a reader
    // must never mistake a `would` row for something that happened.
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            let outcome = e["outcome"].as_str().unwrap_or("?");
            let glyph = match outcome {
                "fired" => Glyph::Ok,
                "would" => Glyph::Bullet,
                _ => Glyph::Warn,
            };
            vec![
                ui::glyph_cell(glyph),
                ago(&e["at"]),
                truncate(e["location"].as_str().unwrap_or("?"), 24),
                ui::state(outcome),
                truncate(e["action"].as_str().unwrap_or(""), 14),
                truncate(e["target"].as_str().unwrap_or(""), 18),
                truncate(e["detail"].as_str().unwrap_or(""), 34),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::right("age"),
                Col::left("location"),
                Col::left("outcome"),
                Col::left("action"),
                Col::left("target"),
                Col::left("detail"),
            ],
            &rows,
        )
    );
    if entries.iter().any(|e| e["outcome"].as_str() == Some("would")) {
        println!(
            "{}",
            ui::note("`would` rows did not happen — the location was disarmed")
        );
    }
    ui::guide(&[
        ("noo autonomy decisions", "only the would-have-done rows"),
        ("noo autonomy status", "which locations are enabled and armed"),
    ]);
    Ok(0)
}

/// `noo autonomy enable` — POST /api/autonomy/enable.
pub fn autonomy_enable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    toggle(g, args, true)
}

/// `noo autonomy disable` — POST /api/autonomy/disable.
pub fn autonomy_disable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    toggle(g, args, false)
}

fn toggle(g: &Globals, args: &[String], enable: bool) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let ep = if enable { "enable" } else { "disable" };
    let resp = post_json(g, &format!("/api/autonomy/{ep}"), &serde_json::json!({}), true, 10);
    if g.json {
        println!("{resp}");
        return Ok(0);
    }
    if !toggle_took_effect(&resp, enable) {
        ui::failed(
            &format!("the gateway did not confirm that autonomy is {ep}d"),
            Some("noo autonomy status"),
        );
        return Ok(1);
    }
    ui::done(&format!("autonomy engine {ep}d"));
    if enable {
        ui::guide(&[
            ("noo autonomy status", "the loop's cadence and last tick"),
            ("noo autonomy audit", "what it decides, as it happens"),
        ]);
    } else {
        ui::guide(&[
            ("noo autonomy status", "confirms it is stopped"),
            ("noo autonomy enable", "turn it back on"),
        ]);
    }
    Ok(0)
}

/// The rules with a second opt-in (`dry_run`), and what going live means, in
/// the words the prompt shows. The gateway (`routes/intelligence.rs`
/// `dry_run_gate`) and the console (`AutonomyPanel.tsx` `LIVE_MEANS`) hold the
/// same text; tests/test_autonomy_live_means_parity.py keeps the three equal.
pub(crate) const LIVE_MEANS: &[(&str, &str)] = &[
    (
        "disk_watermark",
        "When a disk is past its watermark, the reclaim ladder will DELETE what it previews today: stopped containers and dangling images, the build cache, unused model weights, and superseded images of noomesh and of the add-ons it runs (only from those images' own repositories; never your other images, never one a container uses), on the controller and on every node.",
    ),
    (
        "cert_auto_rotate",
        "When a certificate nears expiry, the rule will RE-ISSUE it and restart the services that use it, instead of only reporting what it would rotate.",
    ),
];

pub(crate) fn live_means(rule: &str) -> Option<&'static str> {
    LIVE_MEANS.iter().find(|(r, _)| *r == rule).map(|(_, m)| *m)
}

/// `<rule> [--yes]`.
pub(crate) fn parse_dry_run_with(a: &mut Args) -> Result<(String, bool), ArgError> {
    let yes = a.flag(&["--yes", "-y"]);
    let rule = a.one("<rule>")?;
    Ok((rule, yes))
}

/// A gated rule's state as the gateway read it back after a dry-run change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuleState {
    pub(crate) enabled: bool,
    pub(crate) armed: bool,
    pub(crate) dry_run: bool,
}

/// The read-back state from the dry-run route's answer; `None` when any of
/// the three is missing (a refusal, or a gateway that does not report it):
/// never assumed.
pub(crate) fn rule_state(resp: &serde_json::Value) -> Option<RuleState> {
    Some(RuleState {
        enabled: resp["enabled"].as_bool()?,
        armed: resp["armed"].as_bool()?,
        dry_run: resp["dry_run"].as_bool()?,
    })
}

/// Did the stored state become what was asked? Live: switched on, armed and
/// out of preview (it acts). Preview: in preview, armed or not.
pub(crate) fn state_is_what_was_asked(s: RuleState, live: bool) -> bool {
    if live {
        s.enabled && s.armed && !s.dry_run
    } else {
        s.dry_run
    }
}

/// The state in the words `noo autonomy status` uses (Armed / Dry-run / Off).
pub(crate) fn describe_state(rule: &str, s: RuleState) -> String {
    let off = if s.enabled { "" } else { " (the rule is switched off, so it does not run at all)" };
    match (s.armed, s.dry_run) {
        (true, false) => format!("{rule}: Armed, live: from its next tick it acts{off}"),
        (true, true) => format!("{rule}: Dry-run (armed, previewing): it records what it would do and changes nothing{off}"),
        (false, _) => format!("{rule}: Off (not armed, previewing): it records what it would do and changes nothing{off}"),
    }
}

/// The confirm before going live: what one `live` does (arms the rule AND
/// takes it out of preview) and what the rule then does.
pub(crate) fn live_prompt(rule: &str, means: &str) -> String {
    format!("Arm {rule} and take it out of preview? From its next tick it will act. {means}")
}

/// `noo autonomy live <rule> [--yes]` — arm a rule with a dry-run gate and
/// take it out of preview, in one update: it then acts. Asks first (on a
/// terminal; `--yes` for agents and pipes), saying what the rule will delete
/// or change. A switched-off rule is refused by the gateway with the remedy.
/// Operator or admin only (the gateway checks), and audited with who did it.
pub fn autonomy_live(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    set_dry_run(g, args, false)
}

/// `noo autonomy preview <rule>` — put a gated rule back into dry run: it
/// records what it would do and changes nothing. Its arm state stays.
pub fn autonomy_preview(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    set_dry_run(g, args, true)
}

fn set_dry_run(g: &Globals, args: &[String], dry_run: bool) -> Result<i32, Unhandled> {
    let (rule, yes) = parse_dry_run_with(&mut Args::new(args))?;
    let live = !dry_run;
    let Some(means) = live_means(&rule) else {
        crate::output::fail(
            g.json,
            crate::output::ExitCode::Generic,
            "no_dry_run_gate",
            &format!("'{rule}' has no dry-run gate: only disk_watermark and cert_auto_rotate do"),
            Some("noo autonomy status"),
        );
    };
    if live {
        super::confirm_prompt(g, yes, &live_prompt(&rule, means));
    }
    let resp = post_json(g, &format!("/api/autonomy/locations/{rule}/dry-run"), &serde_json::json!({"dry_run": dry_run}), true, 10);
    let state = rule_state(&resp);
    let done = state.is_some_and(|s| state_is_what_was_asked(s, live));
    if g.json {
        println!("{resp}");
        return Ok(if done { 0 } else { 1 });
    }
    let Some(s) = state else {
        ui::failed(
            &format!("the gateway did not report {rule}'s state after the change, so it is not confirmed"),
            Some("noo autonomy status"),
        );
        return Ok(1);
    };
    if !done {
        ui::failed(
            &format!("asked for {}, but the gateway stored: {}", if live { "armed and live" } else { "preview" }, describe_state(&rule, s)),
            Some("noo autonomy status"),
        );
        return Ok(1);
    }
    ui::done(&describe_state(&rule, s));
    if live {
        let back = format!("noo autonomy preview {rule}");
        ui::guide(&[("noo autonomy decisions", "what it decided, as it happens"), (back.as_str(), "back to preview")]);
    }
    Ok(0)
}

/// The gateway confirms with `{"status":"enabled"}` / `{"status":"disabled"}`;
/// anything else (an `error` body, an empty reply) is not a success.
fn toggle_took_effect(resp: &serde_json::Value, enable: bool) -> bool {
    resp["status"].as_str() == Some(if enable { "enabled" } else { "disabled" })
}

pub(crate) fn parse_decisions_with(a: &mut Args) -> Result<(u64, Option<String>), ArgError> {
    let limit = a.number::<u64>(&["--limit", "-n"])?.unwrap_or(20);
    let location = a.value(&["--location", "-l"])?;
    a.finish()?;
    Ok((limit, location))
}

/// `noo autonomy decisions [--limit N] [--location NAME]` — what the
/// DISARMED locations would have done.
///
/// The evidence an operator needs before arming an action: each acting
/// location logs the node, backend and replica count it would have touched.
/// Without this view that lives only in the gateway's log stream, and
/// `backend_availability` does not even alert when disarmed — so the
/// feature is otherwise entirely silent.
pub fn autonomy_decisions(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (limit, location) = parse_decisions_with(&mut Args::new(args))?;
    let mut path = format!("/api/autonomy/decisions?limit={limit}");
    if let Some(l) = &location {
        path.push_str(&format!("&location={}", super::urlencode(l)));
    }
    // A gateway older than this route answers 404. Say that plainly rather
    // than rendering an empty table, which would read as "nothing would have
    // happened" — the opposite of the truth. Any other error is reported as
    // the gateway phrased it; this command never guesses why.
    let body = match crate::http::get_json_try(g, &path, true, 10) {
        Ok(v) => v,
        Err(e) => {
            if g.json {
                eprintln!(
                    "{}",
                    serde_json::json!({"error": e, "code": "remote_error"})
                );
                return Ok(crate::output::ExitCode::RemoteError as i32);
            }
            if e.contains("404") || e.to_ascii_lowercase().contains("not found") {
                ui::failed("this gateway does not serve autonomy decisions", None);
                println!(
                    "{}",
                    ui::note("until it is upgraded the would-do lines are only in its log")
                );
                ui::guide(&[(
                    "docker logs noo-gateway 2>&1 | grep autonomy | grep would_",
                    "the same decisions, unstructured",
                )]);
            } else {
                ui::failed(&format!("cannot read autonomy decisions: {e}"), None);
            }
            return Ok(crate::output::ExitCode::RemoteError as i32);
        }
    };
    if g.json {
        println!("{body}");
        return Ok(super::json_exit(&body));
    }
    let Some(entries) = body["decisions"].as_array() else {
        let err = body["error"]
            .as_str()
            .unwrap_or("decisions not reported by the gateway");
        ui::failed(&format!("cannot read autonomy decisions: {err}"), None);
        return Ok(crate::output::ExitCode::RemoteError as i32);
    };
    println!(
        "{}",
        ui::header(
            "autonomy decisions",
            Some(&match &location {
                Some(l) => format!("{l} · {} shown", entries.len()),
                None => format!("{} shown", entries.len()),
            })
        )
    );
    if entries.is_empty() {
        println!(
            "{}",
            ui::muted("no location has wanted to act — conditions have not fired")
        );
        ui::guide(&[("noo autonomy status", "which locations are enabled and armed")]);
        return Ok(0);
    }
    println!("{}", ui::section("would have done"));
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|d| {
            vec![
                ui::glyph_cell(Glyph::Bullet),
                ago(&d["at"]),
                truncate(d["location"].as_str().unwrap_or("?"), 26),
                truncate(d["action"].as_str().unwrap_or("?"), 14),
                truncate(d["target"].as_str().unwrap_or(""), 22),
                truncate(d["detail"].as_str().unwrap_or(""), 40),
            ]
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                Col::left(""),
                Col::right("age"),
                Col::left("location"),
                Col::left("action"),
                Col::left("target"),
                Col::left("detail"),
            ],
            &rows,
        )
    );
    println!(
        "{}",
        ui::note("these did NOT happen — the locations are disarmed")
    );
    ui::guide(&[
        ("noo autonomy status", "which locations are enabled and armed"),
        ("noo autonomy audit", "what the engine actually did"),
    ]);
    Ok(0)
}

#[cfg(test)]
mod toggle_tests {
    use super::*;

    #[test]
    fn only_the_gateways_confirmation_counts() {
        assert!(toggle_took_effect(&serde_json::json!({"status": "enabled"}), true));
        assert!(toggle_took_effect(&serde_json::json!({"status": "disabled"}), false));
        assert!(!toggle_took_effect(&serde_json::json!({"status": "enabled"}), false));
        assert!(!toggle_took_effect(&serde_json::json!({"error": "Redis is not configured"}), true));
        assert!(!toggle_took_effect(&serde_json::json!({}), true));
    }
}

#[cfg(test)]
mod dry_run_tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_the_gated_rules_have_a_live_switch() {
        assert!(live_means("disk_watermark").unwrap().contains("DELETE"));
        assert!(live_means("cert_auto_rotate").unwrap().contains("RE-ISSUE"));
        assert!(live_means("memory_pressure").is_none());
    }

    #[test]
    fn the_rule_and_yes_are_parsed() {
        assert_eq!(parse_dry_run_with(&mut Args::new(&args(&["disk_watermark", "--yes"]))).unwrap(), ("disk_watermark".to_string(), true));
        assert_eq!(parse_dry_run_with(&mut Args::new(&args(&["cert_auto_rotate"]))).unwrap(), ("cert_auto_rotate".to_string(), false));
        assert!(parse_dry_run_with(&mut Args::new(&args(&[]))).is_err(), "a rule is required");
    }

    fn st(enabled: bool, armed: bool, dry_run: bool) -> RuleState {
        RuleState { enabled, armed, dry_run }
    }

    /// Only the state read back counts: live is done when the rule is on,
    /// armed AND out of preview; preview when it previews. A refusal or an
    /// answer without the state is never done.
    #[test]
    fn only_the_stored_value_counts_as_done() {
        let read = |v: serde_json::Value| rule_state(&v);
        assert_eq!(read(serde_json::json!({"enabled": true, "armed": true, "dry_run": false})), Some(st(true, true, false)));
        assert_eq!(read(serde_json::json!({"dry_run": false})), None, "an old answer without enabled/armed is not assumed");
        assert_eq!(read(serde_json::json!({"error": "forbidden"})), None, "a refusal is not done");
        assert!(state_is_what_was_asked(st(true, true, false), true));
        assert!(!state_is_what_was_asked(st(true, false, false), true), "live but disarmed still only previews");
        assert!(!state_is_what_was_asked(st(false, true, false), true), "a switched-off rule does not run");
        assert!(!state_is_what_was_asked(st(true, true, true), true));
        assert!(state_is_what_was_asked(st(true, true, true), false));
        assert!(state_is_what_was_asked(st(true, false, true), false), "preview leaves the arm state alone");
        assert!(!state_is_what_was_asked(st(true, true, false), false));
    }

    /// The prompt says one `live` arms AND takes out of preview, and the
    /// state line uses `noo autonomy status`'s words.
    #[test]
    fn the_prompt_and_the_state_say_what_live_does() {
        let p = live_prompt("disk_watermark", live_means("disk_watermark").unwrap());
        assert!(p.starts_with("Arm disk_watermark and take it out of preview? From its next tick it will act. ") && p.contains("DELETE"), "{p}");
        assert!(describe_state("x", st(true, true, false)).starts_with("x: Armed, live"));
        assert!(describe_state("x", st(true, true, true)).starts_with("x: Dry-run (armed, previewing)"));
        assert!(describe_state("x", st(true, false, true)).starts_with("x: Off (not armed, previewing)"));
        assert!(describe_state("x", st(false, true, false)).contains("switched off"));
    }
}
