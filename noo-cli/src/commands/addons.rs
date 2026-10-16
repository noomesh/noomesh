// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo addons list|enable|disable` — manage the `addons:` map without
//! opening the file.
//!
//! ## Why this is not a database change
//!
//! The obvious ask is "put add-on switches in the database like posture".
//! It cannot go there, and the reason is bootstrapping rather than taste:
//! `scripts/lib-addons.sh` reads this map to pick compose profiles BEFORE
//! the stack starts. The switch decides whether Postgres runs, so Postgres
//! cannot hold it — the launcher would have to ask the database which
//! containers to start, including the database.
//!
//! Nor is the answer "database with the file as a backup". That is exactly
//! the shape `gateway-rust/src/addons.rs` warns about above `resolve()`:
//! the same boolean once lived in `.env`, this launcher, the wizard, the
//! gateway table and the compose passthrough, and on 2026-08-05 evolve's
//! schema was silently never provisioned because one of the copies never
//! reached the gateway. A value with two homes gets a silent winner.
//!
//! So the home stays the file and the operator stops touching it. Same
//! shape as `noo security posture set`, which does not make anyone edit a
//! database by hand either.
//!
//! ## Why the edit is textual
//!
//! `onboard/yamlcfg.rs` writes this map by load → mutate → write-whole
//! through serde_yaml, which is correct for the wizard and wrong here: a
//! round-trip discards every comment and reorders the document. The
//! shipped `noomesh.yaml.example` is mostly comments explaining what each
//! add-on costs, and an operator who runs `noo addons enable` should not
//! silently lose them. So this edits the text in place, the same
//! discipline `cluster_provision.rs::ensure_tag_owner` uses on HuJSON, and
//! verifies the RESULT still parses before writing it.

use serde_json::json;

use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// One add-on as the operator sees it.
///
/// `licensed` names the entitlement feature it needs and mirrors
/// `gateway-rust/src/addons.rs::ADDONS`. That mirroring is asserted by
/// `every_gateway_addon_is_offered_here`, which reads the gateway's real
/// source — a hand-copied list that drifts is the same two-homes bug in
/// miniature, and this one HAS drifted before.
pub struct AddonRow {
    pub key: &'static str,
    pub title: &'static str,
    pub blurb: &'static [&'static str],
    pub licensed: Option<&'static str>,
    pub default_on: bool,
}

pub const ADDON_ROWS: &[AddonRow] = &[
    AddonRow {
        key: "trellion",
        title: "Trellion knowledge pack",
        blurb: &[
            "RAG over ingested documents, conversation-memory search, the",
            "knowledge graph, episodic recall. ~4-5 GB of images.",
        ],
        licensed: None,
        default_on: true,
    },
    AddonRow {
        key: "voice",
        title: "Voice (speech-to-text + text-to-speech)",
        blurb: &["Local whisper + piper containers; the voice channel and `noo voice`."],
        licensed: None,
        default_on: false,
    },
    AddonRow {
        key: "trellion_intel",
        title: "Intelligent tier (trellion-intel)",
        blurb: &[
            "Graph-guided retrieval, temporal extraction, the self-updating graph:",
            "structured research feeds, the weekly report, thought experiments, graph signals.",
            "A second trellion container, CPU-heavy, no GPU.",
        ],
        licensed: Some("trellion_intel"),
        default_on: false,
    },
    AddonRow {
        key: "identity",
        title: "Agent identity exchange",
        blurb: &[
            "One provisioning key exchanged for short-lived tokens, one per agent",
            "persona or session (RFC 8693). Free, on by default, no container —",
            "it mints nothing until you issue an `identity`-scoped service key.",
        ],
        licensed: None,
        default_on: true,
    },
    AddonRow {
        key: "evolve",
        title: "Evolve (self-tuning engines)",
        blurb: &["The sidecar that evolves prompt skills and tunes the agent from its own runs."],
        licensed: Some("evolve"),
        default_on: false,
    },
];

/// Look an add-on up by the name an operator typed. `trellion-intel` and
/// `trellion_intel` are the same add-on: the config key is underscored, the
/// compose service and image are hyphenated, and the hyphen is the spelling
/// people type. Callers print `r.key`, never the typed name.
pub fn row(name: &str) -> Option<&'static AddonRow> {
    let norm = name.replace('-', "_");
    ADDON_ROWS.iter().find(|r| r.key == norm)
}

fn names() -> String {
    ADDON_ROWS.iter().map(|r| r.key).collect::<Vec<_>>().join(", ")
}

// ── the file ───────────────────────────────────────────────────────────

pub(crate) fn config_path() -> std::path::PathBuf {
    crate::envfile::repo_root().join("noomesh.yaml")
}

/// Every add-on's DECLARED value, or `Err` when the file cannot be read or
/// parsed. Reading is a safe serde round-trip — nothing is written back, so
/// the comment-destroying problem does not apply to this direction.
fn declared_map() -> Result<std::collections::BTreeMap<String, bool>, String> {
    declared_map_at(&config_path())
}

/// [`declared_map`] for a given noomesh.yaml. A missing file declares
/// nothing; an unreadable or unparseable one is an error.
pub(crate) fn declared_map_at(path: &std::path::Path) -> Result<std::collections::BTreeMap<String, bool>, String> {
    if !path.exists() {
        return Ok(Default::default());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(Default::default());
    }
    serde_yaml::from_str::<serde_yaml::Value>(&text)
        .map_err(|e| format!("{} does not parse as YAML: {e}", path.display()))?;
    Ok(declared_in(&text))
}

/// The `addons:` map of a noomesh.yaml TEXT — the parse `declared_map` does,
/// for a caller that already holds the file (the launcher's pre-`up` check
/// reads the file the launcher names, not `repo_root()`'s). Unparseable or
/// silent text declares nothing.
pub(crate) fn declared_in(text: &str) -> std::collections::BTreeMap<String, bool> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(text) else { return out };
    if let Some(m) = doc.get("addons").and_then(|v| v.as_mapping()) {
        for (k, v) in m {
            if let (Some(k), Some(v)) = (k.as_str(), v.as_bool()) {
                out.insert(k.to_string(), v);
            }
        }
    }
    out
}

/// The DECLARED value of one add-on, if noomesh.yaml states it. `None` when
/// the file is absent, unreadable or silent on it — the caller applies the
/// add-on's own default (`resolve`). Shared with `systems`, whose add-on-named
/// entries follow this map rather than a flag of their own.
pub fn effective(name: &str) -> Option<bool> {
    let key = row(name).map_or(name, |r| r.key);
    declared_map().ok().and_then(|m| m.get(key).copied())
}

/// The gateway's polarity contract, restated so `list` can show an
/// effective value: absent means "not stated", which resolves to the
/// add-on's own default. Mirrors `addons::resolve`.
pub fn resolve(declared: Option<bool>, default_on: bool) -> bool {
    declared.unwrap_or(default_on)
}

/// Set `name` to `on` in the `addons:` map of `text`, preserving comments,
/// ordering and every unrelated key.
///
/// Pure, so the cases that matter — an existing key, a missing key, no
/// `addons:` block at all, a trailing comment on the line being changed —
/// are testable without a filesystem.
pub fn set_addon(text: &str, name: &str, on: bool) -> String {
    let val = if on { "true" } else { "false" };
    let lines: Vec<&str> = text.lines().collect();

    // A top-level `addons:` key — column zero, nothing else on the line
    // but an optional comment.
    let head = lines.iter().position(|l| {
        let t = l.trim_end();
        !l.starts_with(char::is_whitespace)
            && (t == "addons:" || t.starts_with("addons:") && t["addons:".len()..].trim_start().starts_with('#'))
    });

    let Some(head) = head else {
        // No block. Append one rather than reformatting anything above it.
        let mut out = text.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("\naddons:\n  {name}: {val}\n"));
        return out;
    };

    // Walk the block: indented lines, blanks and comments belong to it.
    let mut end = head + 1;
    let mut indent = String::new();
    while end < lines.len() {
        let l = lines[end];
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            end += 1;
            continue;
        }
        if !l.starts_with(char::is_whitespace) {
            break;
        }
        if indent.is_empty() {
            indent = l[..l.len() - l.trim_start().len()].to_string();
        }
        end += 1;
    }
    if indent.is_empty() {
        indent = "  ".to_string();
    }

    // An existing entry for this name, inside the block.
    let existing = (head + 1..end).find(|&i| {
        let t = lines[i].trim_start();
        t.starts_with(name)
            && t[name.len()..].trim_start().starts_with(':')
            && !t.starts_with('#')
    });

    let mut out: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    match existing {
        Some(i) => {
            // Keep the line's own indentation and any trailing comment —
            // an operator's "# needs a GPU" note beside the flag is the
            // kind of thing this whole module exists to preserve.
            let l = lines[i];
            let ind = &l[..l.len() - l.trim_start().len()];
            let comment = l.find('#').map(|p| format!("  {}", l[p..].trim())).unwrap_or_default();
            out[i] = format!("{ind}{name}: {val}{comment}");
        }
        None => out.insert(head + 1, format!("{indent}{name}: {val}")),
    }

    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Write the change, refusing if the result would not parse.
///
/// Belt and braces on purpose: a textual edit cannot round-trip a file
/// away, but it CAN produce something YAML rejects if the block was
/// stranger than expected. Refusing to write beats leaving an operator
/// with a config the launcher cannot read.
fn write_addon(name: &str, on: bool) -> Result<std::path::PathBuf, String> {
    write_addon_at(&config_path(), name, on)
}

/// The path-taking half, so the refusal rules are testable against a real
/// file without an env var — `repo_root()` reads `NOO_REPO_ROOT`, and a
/// test that sets it races every other test in the binary.
pub(crate) fn write_addon_at(path: &std::path::Path, name: &str, on: bool) -> Result<std::path::PathBuf, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if !text.trim().is_empty() && serde_yaml::from_str::<serde_yaml::Value>(&text).is_err() {
        return Err(format!(
            "{} does not parse as YAML — refusing to edit it. Fix the file first; \
             a hand-edit that broke it is not something this command should build on",
            path.display()
        ));
    }
    let updated = set_addon(&text, name, on);
    let parsed: serde_yaml::Value = serde_yaml::from_str(&updated)
        .map_err(|e| format!("the edit would leave {} unparseable ({e}) — not writing", path.display()))?;
    if parsed.get("addons").and_then(|v| v.get(name)).and_then(|v| v.as_bool()) != Some(on) {
        return Err(format!(
            "the edit did not take effect in {} — not writing. Report this with the file's \
             `addons:` block",
            path.display()
        ));
    }
    std::fs::write(path, updated).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path.to_path_buf())
}

// ── the entitlement ────────────────────────────────────────────────────

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Which features the installed entitlement grants. `None` = no usable
/// entitlement, which is different from "grants nothing": the first is a
/// missing licence, the second a licence that covers nothing.
pub fn granted_features() -> Option<Vec<String>> {
    let token = crate::entitlement::installed_token()?;
    crate::entitlement::check(&token, now()).ok().map(|e| e.features)
}

fn grants(features: &Option<Vec<String>>, feature: &str) -> bool {
    features.as_ref().is_some_and(|f| f.iter().any(|x| x == feature))
}

// ── commands ───────────────────────────────────────────────────────────

/// `noo addons list`
pub fn addons_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let declared = match declared_map() {
        Ok(d) => d,
        Err(e) => fail(g.json, ExitCode::Generic, "config", &e, None),
    };
    let features = granted_features();
    // Signed-lock pins (licensed add-ons only); an unreadable pins file shows
    // as no pins here — `noo addons verify` is the place that fails on it.
    let pins = crate::addons::pins::read(&crate::envfile::repo_root()).unwrap_or_default();

    if g.json {
        let rows: Vec<_> = ADDON_ROWS
            .iter()
            .map(|r| {
                let d = declared.get(r.key).copied();
                json!({
                    "name": r.key,
                    "declared": d,
                    "effective": resolve(d, r.default_on),
                    "licensed": r.licensed,
                    "granted": r.licensed.is_none_or(|f| grants(&features, f)),
                    "pin": pins.get(r.key),
                })
            })
            .collect();
        println!("{}", json!({"addons": rows, "config": config_path().display().to_string()}));
        return Ok(0);
    }

    println!("{}", ui::header("add-ons", Some(&config_path().display().to_string())));
    let rows: Vec<Vec<String>> = ADDON_ROWS
        .iter()
        .map(|r| {
            let d = declared.get(r.key).copied();
            let eff = resolve(d, r.default_on);
            // "not declared" is NOT "off". The distinction is the whole
            // point of the polarity contract, so it is rendered rather
            // than collapsed into a yes/no.
            let declared_cell = match d {
                Some(true) => ui::good("true"),
                Some(false) => ui::bad("false"),
                None => ui::muted(&format!("not declared → {eff}")),
            };
            let licence_cell = match r.licensed {
                None => ui::muted("not required"),
                Some(f) if grants(&features, f) => ui::good("granted"),
                Some(_) if features.is_none() => ui::bad("no entitlement"),
                Some(_) => ui::bad("not granted"),
            };
            let effective = if eff && r.licensed.is_none_or(|f| grants(&features, f)) {
                ui::good("on")
            } else if eff {
                ui::bad("on, but unlicensed")
            } else {
                ui::muted("off")
            };
            let mut row = vec![r.key.to_string(), declared_cell, effective, licence_cell];
            if r.licensed.is_some() {
                row.extend(crate::commands::addon_pins::pin_cells(pins.get(r.key)));
            }
            row
        })
        .collect();
    print!(
        "{}",
        ui::table(
            &[
                ui::Col::left("add-on"),
                ui::Col::left("declared"),
                ui::Col::left("effective"),
                ui::Col::left("licence"),
                ui::Col::left("version"),
                ui::Col::left("stack"),
                ui::Col::left("digest"),
                ui::Col::left("key"),
            ],
            &rows
        )
    );
    println!();
    ui::guide(&[
        ("noo addons enable <name>", "pins a licensed add-on's signed lock, then declares it on"),
        ("noo addons verify", "re-checks every pin against its signed lock and what runs"),
        ("noo stack restart", "applies it — the switch decides which containers run"),
    ]);
    Ok(0)
}

/// What `enable` does about the licence. `Ok(Some(feature))` = proceed but
/// warn (`--force` over a missing grant); `Ok(None)` = nothing to say;
/// `Err` = refuse before anything is minted.
///
/// Without this gate enabling a licensed add-on "succeeded": it minted
/// database credentials and a gateway key, wrote `true`, and the operator met
/// the registry's denial on the next `noo stack restart` with no mention of
/// the entitlement. `--force` exists for staging a box before the token
/// arrives; it keeps that old path, warning included.
pub(crate) fn enable_gate(
    r: &AddonRow,
    features: &Option<Vec<String>>,
    force: bool,
) -> Result<Option<&'static str>, (String, String)> {
    let Some(f) = r.licensed else { return Ok(None) };
    if grants(features, f) {
        return Ok(None);
    }
    if force {
        return Ok(Some(f));
    }
    let state = match features {
        None => "no entitlement is installed".to_string(),
        Some(_) => "the installed entitlement does not grant it".to_string(),
    };
    let key = r.key;
    let reg = crate::entitlement_terms::ADDON_REGISTER_URL;
    Err((
        format!(
            "{key} not enabled: it is a licensed add-on (feature `{f}`) and {state}. Nothing was \
             minted and noomesh.yaml is unchanged. Install a token with `noo security \
             entitlement install <token>` and re-run — register at {reg}; \
             `noo addons enable {key} --force` declares it on anyway"
        ),
        "noo security entitlement install <token>".to_string(),
    ))
}

fn set(g: &Globals, args: &[String], on: bool) -> Result<i32, Unhandled> {
    let (name, force) = match args {
        [n] => (n, false),
        [n, f] if on && f == "--force" => (n, true),
        _ => return Err(Unhandled),
    };
    let Some(r) = row(name) else {
        fail(
            g.json,
            ExitCode::Usage,
            "unknown_addon",
            &format!("unknown add-on `{name}` — known add-ons: {}", names()),
            None,
        );
    };
    // From here on the canonical key, whatever spelling was typed.
    let name = r.key;
    let features = granted_features();
    let unlicensed = if on {
        match enable_gate(r, &features, force) {
            Ok(u) => u,
            Err((msg, fix)) => fail(g.json, ExitCode::Generic, "licence_required", &msg, Some(&fix)),
        }
    } else {
        None
    };
    let before = declared_map().ok().and_then(|d| d.get(name).copied());
    // ON is not a file edit: the add-on's credentials and
    // gateway key are minted first, and the switch flips only once both
    // exist — see `addon_enable`. OFF stays a file edit: disabling is not a
    // data operation, and nothing it needs can be missing.
    let mut enabled_report = None;
    let path = if on {
        match crate::commands::addon_enable::enable(&config_path(), name, &mut crate::commands::addon_enable::Live { g, force }) {
            Ok(e) => {
                let p = e.config.clone();
                enabled_report = Some(e);
                // Its own NATS principal, when its overlay declares one (i70
                // residue): mint + render + HUP. Best-effort — without it the
                // add-on presents the worker for one release.
                match crate::commands::nats_users::reconcile_addon_principals(g, &crate::envfile::repo_root()) {
                    Ok(Some(out)) => {
                        let reloaded = crate::commands::nats_users::hup_nats();
                        if !g.json {
                            crate::ui::done(&format!("{name}: its own NATS principal rendered ({} principals){}",
                                out.users, if reloaded { "; noo-nats reloaded" } else { "" }));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => if !g.json {
                        crate::ui::warned(&format!("{name}: its NATS principal was not rendered ({e}); run: noo cluster nats-users render"));
                    },
                }
                p
            }
            Err(r) => fail(
                g.json,
                ExitCode::Generic,
                "enable_refused",
                &format!("{name} not enabled: {} — noomesh.yaml is unchanged", r.why),
                Some(&r.fix),
            ),
        }
    } else {
        match write_addon(name, on) {
            Ok(p) => p,
            Err(e) => fail(g.json, ExitCode::Generic, "config", &e, None),
        }
    };

    // `unlicensed` is only ever Some under `--force`: the file now says yes
    // and the gateway will still refuse until a token is installed.

    // Voice: the controller stages the whisper model and piper voice the
    // containers will load read-only and offline (i105). After the flip, and
    // never a refusal: a failed download is reported with its retry line.
    let voice_staged = (on && name == "voice").then(|| crate::commands::voice_models::stage_configured(!g.json));

    if g.json {
        println!(
            "{}",
            json!({
                "addon": name, "declared": on, "was": before,
                "config": path.display().to_string(),
                "licensed_feature": r.licensed, "granted": unlicensed.is_none(),
                "restart_required": true,
                "enable": enabled_report.as_ref().map(|e| crate::commands::addon_enable::report_json(name, e)),
                "voice_models": voice_staged.as_ref().map(|v| v.iter().map(|r| match r {
                    Ok(s) => s.json(),
                    Err((id, e)) => json!({"id": id, "error": e, "retry": format!("noo models pull {id}")}),
                }).collect::<Vec<_>>()),
            })
        );
        return Ok(0);
    }
    if let Some(e) = &enabled_report {
        crate::commands::addon_enable::report(name, e);
    } else {
        ui::done(&format!(
            "{name} declared {} in {}",
            if on { "on" } else { "off" },
            path.display()
        ));
        if before == Some(on) {
            println!("{}", ui::note("it was already declared that way — nothing changed"));
        }
    }
    for r in voice_staged.iter().flatten() {
        match r {
            Ok(_) => ui::done(&crate::commands::voice_models::line(r)),
            Err(_) => ui::warned(&crate::commands::voice_models::line(r)),
        }
    }
    if let Some(f) = unlicensed {
        ui::warned(&format!(
            "the installed entitlement does not grant `{f}`, so the gateway will still refuse \
             this add-on. The switch is on; the licence is the other gate"
        ));
    }
    // Never restart. This changes which containers run, and a command that
    // edits a config file must not bounce a live fleet as a side effect.
    ui::guide(&[
        ("noo stack restart --force", "applies it — until then the running stack is unchanged"),
        ("noo addons list", "shows declared vs effective for every add-on"),
    ]);
    Ok(0)
}

/// `noo addons enable <name>`
pub fn addons_enable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    set(g, args, true)
}

/// `noo addons disable <name>`
pub fn addons_disable(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    set(g, args, false)
}

/// The add-ons a token's features unlock, for `entitlement install`.
/// Features are the only authority — `addons.rs` says tiers are bundle
/// labels, and an operator hit exactly that on 2026-09-14: a token reading
/// `tier: intelligent` with an empty feature list unlocked nothing.
pub fn addons_granted_by(features: &[String]) -> Vec<&'static AddonRow> {
    ADDON_ROWS
        .iter()
        .filter(|r| r.licensed.is_some_and(|f| features.iter().any(|x| x == f)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Runtime config.
version: 1

addons:
  # The knowledge pack. ~4-5 GB of images.
  trellion: true
  evolve: false  # needs a GPU box

compose_env:
  NOO_X: \"1\"
";

    #[test]
    fn an_existing_entry_is_flipped_and_the_comments_survive() {
        let out = set_addon(SAMPLE, "evolve", true);
        assert!(out.contains("evolve: true"), "{out}");
        assert!(!out.contains("evolve: false"), "{out}");
        // The operator's notes are the reason this is textual.
        assert!(out.contains("# The knowledge pack. ~4-5 GB of images."), "block comment lost:\n{out}");
        assert!(out.contains("# Runtime config."), "file comment lost:\n{out}");
        assert!(out.contains("# needs a GPU box"), "trailing comment lost:\n{out}");
        // And nothing unrelated moved.
        assert!(out.contains("compose_env:") && out.contains("NOO_X: \"1\""), "{out}");
        assert!(out.contains("trellion: true"), "{out}");
    }

    #[test]
    fn a_missing_entry_is_added_inside_the_block() {
        let out = set_addon(SAMPLE, "identity", true);
        let doc: serde_yaml::Value = serde_yaml::from_str(&out).expect("still parses");
        assert_eq!(doc["addons"]["identity"].as_bool(), Some(true), "{out}");
        assert_eq!(doc["addons"]["trellion"].as_bool(), Some(true), "{out}");
        assert!(out.contains("# The knowledge pack. ~4-5 GB of images."), "{out}");
    }

    #[test]
    fn a_file_with_no_addons_block_gains_one() {
        let src = "version: 1\ncompose_env:\n  NOO_X: \"1\"\n";
        let out = set_addon(src, "trellion_intel", true);
        let doc: serde_yaml::Value = serde_yaml::from_str(&out).expect("still parses");
        assert_eq!(doc["addons"]["trellion_intel"].as_bool(), Some(true), "{out}");
        assert!(out.contains("NOO_X"), "{out}");
    }

    /// The polarity contract, mirrored from the gateway. Absent is not off.
    #[test]
    fn absent_resolves_to_the_addons_own_polarity() {
        assert!(resolve(None, true));
        assert!(!resolve(None, false));
        assert!(!resolve(Some(false), true));
        assert!(resolve(Some(true), false));
    }

    /// Features are the only authority. A token whose features are empty
    /// unlocks nothing, whatever its tier says.
    #[test]
    fn only_granted_features_unlock_addons() {
        let none: Vec<String> = vec![];
        assert!(addons_granted_by(&none).is_empty());
        let one = vec!["trellion_intel".to_string()];
        let got: Vec<_> = addons_granted_by(&one).iter().map(|r| r.key).collect();
        assert_eq!(got, vec!["trellion_intel"]);
        // An open add-on is never "granted" by a licence — it needs none.
        let odd = vec!["trellion".to_string()];
        assert!(addons_granted_by(&odd).is_empty(), "an unlicensed add-on was treated as licensed");
    }

    fn feats(f: &[&str]) -> Option<Vec<String>> {
        Some(f.iter().map(|s| s.to_string()).collect())
    }

    /// A licensed add-on with no grant is refused BEFORE `enable()` runs —
    /// the gate is the only thing between the command and the minting, so a
    /// refusal here is "nothing minted".
    #[test]
    fn enable_refuses_a_licensed_addon_without_a_grant() {
        let r = row("trellion_intel").unwrap();
        for held in [None, feats(&[]), feats(&["evolve"])] {
            let (msg, fix) = enable_gate(r, &held, false).expect_err("must refuse without a grant");
            assert!(msg.contains("trellion_intel not enabled"), "{msg}");
            assert!(msg.contains("licensed add-on"), "{msg}");
            assert!(msg.contains("`trellion_intel`"), "names the feature: {msg}");
            assert!(msg.contains("noo security entitlement install <token>"), "{msg}");
            assert!(msg.contains("Nothing was minted"), "{msg}");
            assert_eq!(fix, "noo security entitlement install <token>");
        }
        let (msg, _) = enable_gate(r, &None, false).unwrap_err();
        assert!(msg.contains("no entitlement is installed"), "{msg}");
        let (msg, _) = enable_gate(r, &feats(&[]), false).unwrap_err();
        assert!(msg.contains("does not grant it"), "{msg}");
    }

    #[test]
    fn enable_proceeds_when_granted_or_unlicensed() {
        let r = row("evolve").unwrap();
        assert_eq!(enable_gate(r, &feats(&["evolve"]), false), Ok(None));
        for open in ["trellion", "voice", "identity"] {
            assert_eq!(enable_gate(row(open).unwrap(), &None, false), Ok(None), "{open} needs no licence");
        }
    }

    /// `--force` keeps the old warn-and-proceed path for staging a box
    /// before the token arrives.
    #[test]
    fn force_keeps_the_warn_and_proceed_path() {
        let r = row("evolve").unwrap();
        assert_eq!(enable_gate(r, &None, true), Ok(Some("evolve")));
        assert_eq!(enable_gate(r, &feats(&["trellion_intel"]), true), Ok(Some("evolve")));
        // Granted + force: nothing to warn about.
        assert_eq!(enable_gate(r, &feats(&["evolve"]), true), Ok(None));
    }

    #[test]
    fn the_hyphen_spelling_is_the_same_addon() {
        assert_eq!(row("trellion-intel").unwrap().key, "trellion_intel");
        assert_eq!(row("trellion_intel").unwrap().key, "trellion_intel");
        assert!(row("trellion-intelx").is_none());
        assert!(row("nope").is_none());
    }

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("noo-addons-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("noomesh.yaml");
        std::fs::write(&p, body).unwrap();
        p
    }

    /// The write path end to end: the file changes, it still parses, and
    /// the operator's comments are still in it afterwards.
    #[test]
    fn writing_changes_the_file_and_keeps_the_comments() {
        let p = tmp("write", SAMPLE);
        write_addon_at(&p, "trellion_intel", true).expect("write");
        let after = std::fs::read_to_string(&p).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&after).expect("parses");
        assert_eq!(doc["addons"]["trellion_intel"].as_bool(), Some(true));
        assert!(after.contains("# needs a GPU box"), "{after}");
        let _ = std::fs::remove_file(&p);
    }

    /// A file that does not parse is REFUSED, not built on. The wizard's
    /// round-trip writer once replaced an operator's whole config after one
    /// bad hand-edit; this path must not repeat it in a different shape.
    #[test]
    fn an_unparseable_file_is_refused_and_left_alone() {
        let broken = "addons:\n\ttrellion: true\n  evolve: [\n";
        let p = tmp("broken", broken);
        let err = write_addon_at(&p, "evolve", true).expect_err("must refuse");
        assert!(err.contains("does not parse"), "{err}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), broken, "the file was modified anyway");
        let _ = std::fs::remove_file(&p);
    }

    /// The list here mirrors `gateway-rust/src/addons.rs::ADDONS`, and a
    /// hand-copied mirror drifts. Read the gateway's REAL source: a fixture
    /// would agree with itself forever while the shipped table moved.
    ///
    /// One-directional on purpose. Every gateway add-on must be offered
    /// here, because the gateway routes and refuses on it. The reverse is
    /// allowed for any add-on the gateway does not need to name.
    #[test]
    fn every_gateway_addon_is_offered_here() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = repo.join("gateway-rust/src/addons.rs");
        assert!(
            !path.ends_with("noo-cli/src/commands/addons.rs"),
            "the mirror guard is reading its own file — it must read the GATEWAY's table"
        );
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("gateway addons table unreadable at {}: {e}", path.display()));
        // Guard the guard: if the file moves or is gutted, the scan below
        // would find nothing and pass vacuously.
        assert!(
            src.contains("pub const ADDONS: &[Addon]") && src.contains("pub fn resolve("),
            "{} is not the add-on table — the assertions below would be vacuous",
            path.display()
        );

        let table = &src[src.find("pub const ADDONS: &[Addon]").unwrap()..];
        let table = &table[..table.find("\n];").expect("unterminated ADDONS table")];
        let mut seen = 0;
        for chunk in table.split("Addon {").skip(1) {
            let name = chunk
                .split("name:")
                .nth(1)
                .and_then(|s| s.split('"').nth(1))
                .expect("an Addon row with no name");
            seen += 1;
            let r = row(name).unwrap_or_else(|| {
                panic!("gateway declares add-on `{name}` and `noo addons` does not offer it")
            });
            let default_on = chunk.contains("default_on: true");
            assert_eq!(
                r.default_on, default_on,
                "`{name}` polarity disagrees with the gateway: here {}, there {default_on}",
                r.default_on
            );
            let feature = chunk
                .split("requires_feature:")
                .nth(1)
                .and_then(|s| s.lines().next())
                .map(|l| l.trim())
                .unwrap_or("");
            let gateway_feature = feature
                .strip_prefix("Some(")
                .and_then(|s| s.split('"').nth(1))
                .map(|s| s.to_string());
            assert_eq!(
                r.licensed.map(|s| s.to_string()),
                gateway_feature,
                "`{name}` licence feature disagrees with the gateway"
            );
        }
        assert!(seen >= 4, "only found {seen} gateway add-ons — the parse is wrong, not the table");
    }
}
