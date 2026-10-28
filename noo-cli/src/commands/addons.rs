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
//! gateway table and the compose pass-through, and on 2026-08-05 evolve's
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

/// This install's noomesh.yaml text; empty when it is absent or unreadable
/// (`list` already failed on an unreadable file through `declared_map`).
fn config_text() -> String {
    std::fs::read_to_string(config_path()).unwrap_or_default()
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
    // The add-ons that are on but that the launcher leaves out of a start:
    // their pin does not verify for this stack, so they are NOT running.
    let refused = launch_refusals(&crate::envfile::repo_root(), &declared);
    let refusal = |n: &str| refused.iter().find(|(r, _)| r == n).map(|(_, why)| why.clone());

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
                    "launch_refused": refusal(r.key),
                })
            })
            .collect();
        let third: Vec<_> = third_party_rows(&config_text(), crate::addon_lock::now_unix())
            .into_iter()
            .map(|(n, d, signer)| {
                let dev = signer.contains("DEV");
                json!({
                    "name": n, "declared": d, "effective": d == Some(true), "third_party": true,
                    "signer": signer, "dev": dev, "pin": pins.get(&n), "launch_refused": refusal(&n),
                })
            })
            .collect();
        let marks = crate::addons::provisioned::read_all(&crate::envfile::repo_root());
        let prov: Vec<_> = crate::addons::provisioned::only(&marks, &declared).into_iter().collect();
        println!(
            "{}",
            json!({"addons": rows, "third_party": third, "provisioned": prov, "config": config_path().display().to_string()})
        );
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
            let effective = if eff && refusal(r.key).is_some() {
                ui::bad("on, REFUSED: not running")
            } else if eff && r.licensed.is_none_or(|f| grants(&features, f)) {
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
    // Third-party add-ons the operator trusts a key for: who signs them, and
    // a DEV marker with the expiry when it is a development key (i163 A).
    let third = third_party_rows(&config_text(), crate::addon_lock::now_unix());
    if !third.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = third
            .iter()
            .map(|(n, d, signer)| {
                let declared_cell = match d {
                    Some(true) => ui::good("true"),
                    Some(false) => ui::bad("false"),
                    None => ui::muted("not declared → false"),
                };
                let signer_cell = if signer.contains("EXPIRED") {
                    ui::bad(signer)
                } else if signer.contains("DEV") {
                    ui::warn(signer)
                } else {
                    signer.clone()
                };
                let mut row = vec![n.clone(), declared_cell, signer_cell];
                row.extend(crate::commands::addon_pins::pin_cells(pins.get(n)));
                row
            })
            .collect();
        print!(
            "{}",
            ui::table(
                &[
                    ui::Col::left("third-party"),
                    ui::Col::left("declared"),
                    ui::Col::left("signer"),
                    ui::Col::left("version"),
                    ui::Col::left("stack"),
                    ui::Col::left("digest"),
                    ui::Col::left("key"),
                ],
                &rows
            )
        );
    }
    // On, but left out of every start until re-pinned: never silent.
    if !refused.is_empty() {
        println!();
        println!("{}", ui::section("refused at launch"));
        for (n, why) in &refused {
            println!("{}", ui::status_line(ui::Glyph::Err, &format!("{n}: REFUSED, not running: {why}")));
        }
    }
    // Add-ons whose database exists but whose services are not started.
    let marks = crate::addons::provisioned::read_all(&crate::envfile::repo_root());
    let prov = crate::addons::provisioned::only(&marks, &declared);
    if !prov.is_empty() {
        println!();
        let rows: Vec<Vec<String>> = prov
            .iter()
            .map(|m| vec![m.addon.clone(), ui::warn(crate::addons::provisioned::WORDS), m.schema.clone(), format!("{}, {}", m.role, m.ddl_role)])
            .collect();
        print!(
            "{}",
            ui::table(
                &[ui::Col::left("provisioned"), ui::Col::left("state"), ui::Col::left("schema"), ui::Col::left("roles")],
                &rows
            )
        );
    }
    println!();
    print_bundle_decls(&crate::envfile::repo_root());
    if !refused.is_empty() {
        ui::guide(&[
            ("noo addons upgrade <name>", "re-pins a refused add-on for this stack; the next restart starts it"),
            ("noo addons disable <name>", "turns a refused add-on off instead"),
        ]);
    }
    ui::guide(&[
        ("noo addons show <name>", "the database and workloads an add-on's signed bundle declares"),
        ("noo addons enable <name>", "pins a licensed add-on's signed lock, then declares it on"),
        ("noo addons verify", "re-checks every pin against its signed lock and what runs"),
        ("noo stack restart", "applies it — the switch decides which containers run"),
    ]);
    Ok(0)
}

/// Every add-on that is on and that the launcher would leave out of a start
/// (`launch-pins` refuses it for the running stack tag), with why. The same
/// offline check the launcher runs, so `list` and `show` cannot call an add-on
/// on that the launcher refuses. Empty when no stack tag is pinned.
fn launch_refusals(root: &std::path::Path, declared: &std::collections::BTreeMap<String, bool>) -> Vec<(String, String)> {
    let Some(tag) = crate::addons::current_tag(root) else { return Vec::new() };
    let mut names: Vec<String> = ADDON_ROWS
        .iter()
        .filter(|r| r.licensed.is_some() && resolve(declared.get(r.key).copied(), r.default_on))
        .map(|r| r.key.to_string())
        .collect();
    names.extend(
        third_party_rows(&config_text(), crate::addon_lock::now_unix())
            .into_iter()
            .filter(|(_, d, _)| *d == Some(true))
            .map(|(n, _, _)| n),
    );
    names
        .into_iter()
        .filter_map(|n| crate::commands::addon_pins::launch_refusal(root, &tag, &n).map(|why| (n, why)))
        .collect()
}

/// `list`'s "bundle declarations" section: each add-on whose materialised
/// bundle declares a database or workloads (or fails to validate). Nothing
/// is printed when none does. Its JSON form is `noo addons show <name> --json`.
fn print_bundle_decls(root: &std::path::Path) {
    let decls = bundle_decls(root);
    let nothing = crate::addons::decls::Declared::default();
    if decls.iter().any(|(_, d)| !matches!(d, Ok(x) if *x == nothing)) {
        println!("{}", ui::section("bundle declarations"));
        for (name, d) in &decls {
            match d {
                Ok(d) if *d == nothing => {}
                Ok(d) => {
                    let mut parts = Vec::new();
                    if let Some(sys) = &d.system {
                        parts.push(format!("database {}", sys.schema));
                    }
                    if !d.workloads.is_empty() {
                        parts.push(format!(
                            "workloads {}",
                            d.workloads.iter().map(|w| w.name.as_str()).collect::<Vec<_>>().join(", ")
                        ));
                    }
                    println!("{}", ui::status_line(ui::Glyph::Bullet, &format!("{name}: {}", parts.join("; "))));
                }
                Err(e) => println!("{}", ui::status_line(ui::Glyph::Err, &format!("{name}: {e}"))),
            }
        }
        println!();
    }
}

// ── bundle declarations (i163 E/B) ──────────────────────────────────────

/// Every add-on with a materialised bundle under `<root>/addons/`, with what
/// it declares beyond its overlay (or why that does not validate).
fn bundle_decls(root: &std::path::Path) -> Vec<(String, Result<crate::addons::decls::Declared, String>)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root.join(crate::addons::pins::ADDONS_DIR)) else { return out };
    for e in rd.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
        if !crate::addons::trust::name_ok(&name) || !e.path().is_dir() {
            continue;
        }
        out.push((name.clone(), crate::addons::decls::materialised(root, &name)));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn decl_json(d: &Result<crate::addons::decls::Declared, String>) -> serde_json::Value {
    match d {
        Err(e) => json!({"error": e}),
        Ok(d) => json!({
            "system": d.system.as_ref().map(|s| json!({
                "schema": s.schema, "role": s.role, "ddl_role": s.ddl_role, "extensions": s.extensions,
            })),
            "workloads": d.workloads.iter().map(|w| json!({
                "name": w.name, "container": w.container, "gpu": w.gpu, "need_mb": w.need_mb,
                "drain": {"route": w.drain_route, "timeout_secs": w.drain_timeout_secs},
            })).collect::<Vec<_>>(),
            // Names, kinds and destinations only: never a value.
            "resources": d.resources.as_ref().map(|r| json!({
                "uid": r.uid,
                "mounts": r.mounts.iter().map(|m| json!({"name": m.name, "env": m.env, "target": m.target})).collect::<Vec<_>>(),
                "resources": crate::addons::resources::listing(r),
            })),
        }),
    }
}

/// `noo addons show <name>`: one add-on's switch, pin, and what its signed
/// bundle declares (database system, managed workloads). Reads the
/// materialised bundle on this controller; changes nothing.
pub fn addons_show(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [name] = args else { return Err(Unhandled) };
    if name.starts_with('-') {
        return Err(Unhandled);
    }
    let key = row(name).map_or(name.as_str(), |r| r.key);
    if !crate::addons::trust::name_ok(key) {
        fail(g.json, ExitCode::Usage, "unknown_addon", &format!("`{name}` is not an add-on name"), Some("noo addons list"));
    }
    let root = crate::envfile::repo_root();
    let declared = declared_map().ok().and_then(|m| m.get(key).copied());
    let default_on = row(key).is_some_and(|r| r.default_on);
    let pin = crate::addons::pins::read(&root).unwrap_or_default().get(key).cloned();
    let bundle_dir = crate::addons::pins::addon_dir(&root, key);
    let has_bundle = bundle_dir.is_dir();
    let decls = if has_bundle { crate::addons::decls::materialised(&root, key) } else { Ok(Default::default()) };
    let (pw, ddl) = crate::addons::decls::password_envs(key);
    // Provisioned = schema and roles exist, switch not on, no service started.
    let provisioned = crate::addons::provisioned::read_all(&root)
        .remove(key)
        .filter(|_| declared != Some(true));
    // On, but the launcher leaves it out of every start: NOT running.
    let refused = if resolve(declared, default_on) {
        crate::addons::current_tag(&root).and_then(|t| crate::commands::addon_pins::launch_refusal(&root, &t, key))
    } else {
        None
    };

    if g.json {
        println!(
            "{}",
            json!({
                "addon": key,
                "declared": declared,
                "effective": resolve(declared, default_on),
                "state": if provisioned.is_some() {
                    "provisioned"
                } else if refused.is_some() {
                    "refused"
                } else if resolve(declared, default_on) {
                    "on"
                } else {
                    "off"
                },
                "launch_refused": refused,
                "provisioned": provisioned,
                "pin": pin.as_ref().map(|p| json!({"version": p.version, "stack": p.stack})),
                "bundle": has_bundle.then(|| bundle_dir.display().to_string()),
                "declarations": decl_json(&decls),
                "password_env": decls.as_ref().ok().and_then(|d| d.system.as_ref()).map(|_| json!([pw, ddl])),
            })
        );
        return Ok(if decls.is_ok() { 0 } else { 1 });
    }

    println!("{}", ui::header(&format!("add-on {key}"), Some(&config_path().display().to_string())));
    let eff = resolve(declared, default_on);
    println!(
        "{}",
        ui::kv(&[
            ("switch", match declared {
                Some(true) => ui::good("on"),
                Some(false) => ui::bad("off"),
                None => ui::muted(&format!("not declared → {}", if eff { "on" } else { "off" })),
            }),
            ("pin", pin.as_ref().map_or_else(|| ui::muted("none"), |p| format!("{} for {}", p.version, p.stack))),
            ("bundle", if has_bundle { bundle_dir.display().to_string() } else { ui::muted("none on this controller") }),
        ])
    );
    if let Some(why) = &refused {
        println!("{}", ui::kv(&[("state", ui::bad("REFUSED at launch: left out of the stack, NOT running"))]));
        println!("{}", ui::status_line(ui::Glyph::Err, why));
    }
    if let Some(m) = &provisioned {
        println!(
            "{}",
            ui::kv(&[
                ("state", ui::warn(crate::addons::provisioned::WORDS)),
                ("provisioned", format!("schema {}, roles {} and {}", m.schema, m.role, m.ddl_role)),
            ])
        );
    }
    let rc = match &decls {
        Err(e) => {
            println!("{}", ui::status_line(ui::Glyph::Err, e));
            1
        }
        Ok(d) => {
            println!("{}", ui::section("database"));
            match &d.system {
                None => println!("{}", ui::muted("  none declared")),
                Some(sys) => println!(
                    "{}",
                    ui::kv(&[
                        ("schema", sys.schema.clone()),
                        ("runtime role", sys.role.clone()),
                        ("migration role", sys.ddl_role.clone()),
                        ("extensions", if sys.extensions.is_empty() { ui::muted("none") } else { sys.extensions.join(", ") }),
                        ("passwords", format!("{pw}, {ddl} (names only; in the encrypted store)")),
                    ])
                ),
            }
            println!("{}", ui::section("workloads"));
            if d.workloads.is_empty() {
                println!("{}", ui::muted("  none declared"));
            } else {
                let rows: Vec<Vec<String>> = d
                    .workloads
                    .iter()
                    .map(|w| {
                        vec![
                            w.name.clone(),
                            w.container.clone(),
                            if w.gpu { "gpu".into() } else { "cpu".into() },
                            format!("{} MiB", w.need_mb),
                            format!("{} ({}s)", w.drain_route, w.drain_timeout_secs),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    ui::table(
                        &[ui::Col::left("name"), ui::Col::left("container"), ui::Col::left("device"), ui::Col::left("needs"), ui::Col::left("drain")],
                        &rows
                    )
                );
            }
            println!("{}", ui::section("runtime inputs (names and paths; no value is printed)"));
            match &d.resources {
                None => println!("{}", ui::muted("  none declared")),
                Some(res) => {
                    let (rows, generation) = crate::commands::addon_resources::show_rows(key, res);
                    let mounts: Vec<String> = res.mounts.iter().map(|m| format!("{} ({} -> {})", m.name, m.env, m.target)).collect();
                    println!(
                        "{}",
                        ui::kv(&[
                            ("uid", res.uid.to_string()),
                            ("mounts", if mounts.is_empty() { ui::muted("none") } else { mounts.join(", ") }),
                            ("last written", generation.unwrap_or_else(|| ui::muted("not yet: the next start writes it"))),
                        ])
                    );
                    print!("{}", ui::table(&[ui::Col::left("name"), ui::Col::left("kind"), ui::Col::left("delivered to")], &rows));
                }
            }
            0
        }
    };
    println!();
    if refused.is_some() {
        ui::guide(&[
            ("noo addons upgrade <name>", "re-pins it for this stack; the next restart starts it"),
            ("noo addons disable <name>", "turns it off instead"),
        ]);
    }
    ui::guide(&[
        ("noo addons verify", "re-checks the pin and the bundle files against the signed lock"),
        ("noo stack restart --force", "hands the declarations to the gateway (switched on and verified only)"),
    ]);
    Ok(rc)
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
    let (mut name, mut force, mut lock, mut provision_only) = (None, false, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--force" if on => force = true,
            "--provision-only" if on => provision_only = true,
            "--lock" if on => match it.next() {
                Some(v) if !v.starts_with('-') => lock = Some(v.clone()),
                _ => return Err(Unhandled),
            },
            s if !s.starts_with('-') && name.is_none() => name = Some(a),
            _ => return Err(Unhandled),
        }
    }
    let Some(name) = name else { return Err(Unhandled) };
    let r: &'static AddonRow = match row(name) {
        Some(r) => r,
        // Not an add-on the CLI ships. It can still be enabled when the
        // operator trusts a signing key for it (`noo addons trust-key`); turning
        // one OFF is a file edit and needs no trust.
        None if crate::addons::trust::name_ok(name)
            && (!on || matches!(crate::addons::trust::trusted_anchor(name), Ok(Some(_)))) =>
        {
            let key: &'static str = Box::leak(name.clone().into_boxed_str());
            Box::leak(Box::new(AddonRow { key, title: key, blurb: &[], licensed: None, default_on: false }))
        }
        None if crate::addons::trust::name_ok(name) => fail(
            g.json,
            ExitCode::Usage,
            "untrusted_addon",
            &format!(
                "`{name}` is not an add-on this CLI ships, and no signing key is trusted for it. Known add-ons: {}. \
                 To enable a third-party add-on, trust its signer first",
                names()
            ),
            Some(&format!("noo addons trust-key {name} <pubkey> --registry <root>")),
        ),
        None => fail(
            g.json,
            ExitCode::Usage,
            "unknown_addon",
            &format!("unknown add-on `{name}` — known add-ons: {}", names()),
            None,
        ),
    };
    // From here on the canonical key, whatever spelling was typed.
    let name = r.key;
    // `--force` skips the very verification provisioning exists to rely on.
    if provision_only && force {
        fail(
            g.json,
            ExitCode::Usage,
            "provision_only_force",
            "--provision-only verifies the signed lock and bundle; --force skips that, so the two cannot be combined",
            Some(&format!("noo addons enable {name} --lock <path|https-url> --provision-only")),
        );
    }
    let features = granted_features();
    let unlicensed = if on {
        match enable_gate(r, &features, force) {
            Ok(u) => u,
            Err((msg, fix)) => fail(g.json, ExitCode::Generic, "licence_required", &msg, Some(&fix)),
        }
    } else {
        None
    };
    // Schema and roles only: no switch, no key, no restart (`addon_provision`).
    if provision_only {
        return Ok(crate::commands::addon_provision::run(g, name, lock));
    }
    let before = declared_map().ok().and_then(|d| d.get(name).copied());
    // ON is not a file edit: the add-on's credentials and
    // gateway key are minted first, and the switch flips only once both
    // exist — see `addon_enable`. OFF stays a file edit: disabling is not a
    // data operation, and nothing it needs can be missing.
    let mut enabled_report = None;
    let path = if on {
        match crate::commands::addon_enable::enable(&config_path(), name, &mut crate::commands::addon_enable::Live { g, force, lock: lock.clone(), require_system: false }) {
            Ok(e) => {
                let p = e.config.clone();
                // Fully on now: it is no longer merely "provisioned".
                let _ = crate::addons::provisioned::clear(&crate::envfile::repo_root(), name);
                // Provisioned before 0.6.13: its old client leaf
                // (`services/<name>`, CN = its name) is re-issued under the
                // add-on namespace and retired.
                match crate::commands::addon_provision::retire_legacy_leaf_here(name) {
                    Some(Ok(said)) if !g.json => ui::done(&said),
                    Some(Err(e)) if !g.json => ui::warned(&e),
                    _ => {}
                }
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

/// `<bundle-dir> [--name <addon>]`.
pub(crate) fn parse_check_with(a: &mut crate::args::Args) -> Result<(String, Option<String>), crate::args::ArgError> {
    let name = a.value(&["--name"])?;
    let dir = a.one("<bundle-dir>")?;
    a.finish()?;
    Ok((dir, name))
}

/// `noo addons check <bundle-dir> [--name <addon>]`: the checks enable runs
/// on a bundle's files (`addons::check`), on a directory. Installs nothing,
/// asks no network; the core is the one embedded in this binary.
pub fn addons_check(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (dir, name) = parse_check_with(&mut crate::args::Args::new(args))?;
    let path = std::path::Path::new(&dir);
    let name = match name {
        Some(n) if crate::addons::trust::name_ok(&n) => n,
        Some(n) => fail(g.json, ExitCode::Usage, "bad_name", &format!("`{n}` is not an add-on name (lowercase letters, digits, `-`, `_`)"), None),
        None => match crate::addons::check::name_of_dir(path) {
            Ok(n) => n,
            Err(e) => fail(g.json, ExitCode::Usage, "bad_name", &e, Some(&format!("noo addons check {dir} --name <addon>"))),
        },
    };
    let third_party = crate::addons::resolve::third_party(&name);
    match crate::addons::check::check_dir(path, &name) {
        Ok(c) => {
            if g.json {
                println!(
                    "{}",
                    json!({
                        "addon": name, "dir": dir, "ok": true, "third_party": third_party, "core": "embedded",
                        "checked": {"secrets_declared": c.declared, "secret_references": c.referenced, "interpolations": c.interpolated, "mounts": c.mounts},
                    })
                );
            } else {
                ui::done(&format!("{name}: the bundle in {dir} passes the checks `noo addons enable` runs on its files"));
                let who = if third_party { "third-party" } else { "first-party" };
                println!("{}", ui::note(&format!("checked as {who}, against the compose files embedded in this noo; no signature, trust key or image was checked")));
            }
            Ok(0)
        }
        Err(why) => fail(g.json, ExitCode::Generic, "bundle_refused", &why, Some(&format!("noo addons check {dir}"))),
    }
}

// ── third-party trust and delegation ───────────────────────────────────

/// Edit noomesh.yaml TEXT through `f` and write it back only if it still
/// parses. A missing file is an empty one.
fn edit_yaml(f: impl FnOnce(&str) -> Result<String, String>) -> Result<std::path::PathBuf, String> {
    let path = config_path();
    let text = if path.exists() {
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?
    } else {
        String::new()
    };
    let updated = f(&text)?;
    crate::addons::trust::write_checked(&path, &text, &updated)?;
    Ok(path)
}

/// `noo addons trust-key <name> <pubkey> [--registry <root>] [--dev --expires <dur>]`
///
/// `--dev` trusts a temporary DEVELOPMENT key (i163 part A): `--expires`
/// is required with it (at most 30d) and refused without it. Enrolling one
/// is a local operator action: it edits this install's noomesh.yaml.
pub fn addons_trust_key(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let (mut pos, mut registry, mut dev, mut expires) = (Vec::new(), None, false, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--registry" => match it.next() {
                Some(v) if !v.starts_with('-') => registry = Some(v.as_str()),
                _ => return Err(Unhandled),
            },
            "--dev" => dev = true,
            "--expires" => match it.next() {
                Some(v) if !v.starts_with('-') => expires = Some(v.as_str()),
                _ => return Err(Unhandled),
            },
            s if s.starts_with('-') => return Err(Unhandled),
            _ => pos.push(a.as_str()),
        }
    }
    let [name, key] = pos[..] else { return Err(Unhandled) };
    let ttl = match (dev, expires) {
        (false, None) => None,
        (false, Some(_)) => fail(g.json, ExitCode::Usage, "trust_key",
            "--expires applies to a development key only; a release key does not expire here",
            Some("noo addons trust-key <name> <pubkey> --registry <host/path> --dev --expires 14d")),
        (true, None) => fail(g.json, ExitCode::Usage, "trust_key",
            "a development key needs --expires (at most 30d): it is temporary by design",
            Some(&format!("noo addons trust-key {name} {key} --dev --expires 14d"))),
        (true, Some(e)) => match crate::addons::trust::parse_dev_ttl(e) {
            Ok(n) => Some(n),
            Err(why) => fail(g.json, ExitCode::Usage, "trust_key", &why,
                Some(&format!("noo addons trust-key {name} {key} --dev --expires 14d"))),
        },
    };
    let now = crate::addon_lock::now_unix();
    let edited = match ttl {
        Some(ttl) => edit_yaml(|t| crate::addons::trust::add_dev_key(t, name, key, registry, ttl, now)),
        None => edit_yaml(|t| crate::addons::trust::add_key(t, name, key, registry)),
    };
    let path = match edited {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Usage, "trust_key", &e, Some("noo addons trust-key <name> <pubkey> --registry <host/path>")),
    };
    let key = key.to_ascii_lowercase();
    let expires_at = ttl.map(|t| now + t);
    if g.json {
        println!("{}", json!({
            "addon": name, "trusted_key": key, "dev": dev,
            "expires_at": expires_at.map(crate::addon_lock::utc_rfc3339),
            "config": path.display().to_string(),
        }));
    } else if let Some(at) = expires_at {
        ui::done(&format!(
            "{name}: DEVELOPMENT key {key} trusted until {} ({})",
            crate::addon_lock::utc_minute(at),
            path.display()
        ));
        println!("{}", ui::note("this mesh only; a lock it signs is refused after that instant and never ships in a release"));
        ui::guide(&[
            ("noo addons enable <name>", "(add --lock <path|https-url> to hand it the lock) verifies the lock against this key, pins it, then declares it ON"),
            ("noo addons untrust-key <name> --dev", "removes the add-on's development keys"),
        ]);
    } else {
        ui::done(&format!("{name}: signing key {key} trusted ({})", path.display()));
        ui::guide(&[
            ("noo addons enable <name>", "(add --lock <path|https-url> to hand it the lock) verifies the add-on's signed lock against this key, pins it, then declares it ON"),
            ("noo addons untrust-key <name> <pubkey>", "removes the key again"),
        ]);
    }
    Ok(0)
}

/// `noo addons untrust-key <name> [<pubkey>] [--dev]`: a release key by its
/// pubkey; with `--dev`, that development key, or all of the add-on's
/// development keys when no pubkey is given.
pub fn addons_untrust_key(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let dev = args.iter().any(|a| a == "--dev");
    if args.iter().any(|a| a.starts_with('-') && a != "--dev") {
        return Err(Unhandled);
    }
    let pos: Vec<&str> = args.iter().filter(|a| *a != "--dev").map(String::as_str).collect();
    let (name, key) = match (dev, &pos[..]) {
        (_, [name, key]) => (*name, Some(*key)),
        (true, [name]) => (*name, None),
        _ => return Err(Unhandled),
    };
    let edited = if dev {
        edit_yaml(|t| crate::addons::trust::remove_dev_key(t, name, key))
    } else {
        edit_yaml(|t| crate::addons::trust::remove_key(t, name, key.unwrap_or_default()))
    };
    let path = match edited {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Usage, "untrust_key", &e, Some("noo addons list")),
    };
    let what = match (dev, key) {
        (true, None) => "every development key".to_string(),
        (true, Some(k)) => format!("development key {}", k.to_ascii_lowercase()),
        (false, k) => format!("signing key {}", k.unwrap_or_default().to_ascii_lowercase()),
    };
    if g.json {
        println!("{}", json!({
            "addon": name, "dev": dev, "removed_key": key.map(str::to_ascii_lowercase),
            "config": path.display().to_string(),
        }));
    } else {
        ui::done(&format!("{name}: {what} no longer trusted ({})", path.display()));
        println!("{}", ui::note("a pin made under it stays until `noo addons verify` or the next start re-checks it against the remaining keys"));
    }
    Ok(0)
}

/// `addons list` rows for third-party add-ons (trusted with `trust-key`):
/// `(name, declared, signer)`. `signer` reads `release`, `DEV until <date>`,
/// or `DEV EXPIRED <date>` (the launcher refuses it). Pure over the file text.
pub(crate) fn third_party_rows(text: &str, now: i64) -> Vec<(String, Option<bool>, String)> {
    let declared = declared_in(text);
    let trust = crate::addons::trust::read(text).unwrap_or_default();
    trust
        .into_iter()
        .filter(|(n, _)| row(n).is_none())
        .map(|(n, a)| {
            let live = a.dev.iter().filter(|d| d.expires_at > now).map(|d| d.expires_at).max();
            let dead = a.dev.iter().map(|d| d.expires_at).max();
            let signer = match (a.keys.is_empty(), live, dead) {
                (true, Some(at), _) => format!("DEV until {}", crate::addon_lock::utc_minute(at)),
                (true, None, Some(at)) => format!("DEV EXPIRED {}", crate::addon_lock::utc_minute(at)),
                (false, Some(at), _) => format!("release + DEV until {}", crate::addon_lock::utc_minute(at)),
                (false, None, Some(at)) => format!("release (DEV expired {})", crate::addon_lock::utc_minute(at)),
                _ => "release".to_string(),
            };
            let d = declared.get(&n).copied();
            (n, d, signer)
        })
        .collect()
}

/// `noo addons set <name> --delegate tasks|off`
pub fn addons_set(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [name, flag, value] = args else { return Err(Unhandled) };
    if flag != "--delegate" {
        return Err(Unhandled);
    }
    let on = match value.as_str() {
        "tasks" => true,
        "off" => false,
        _ => fail(g.json, ExitCode::Usage, "usage", &format!("--delegate takes `tasks` or `off`, not `{value}`"), Some("noo addons set <name> --delegate tasks|off")),
    };
    let path = match edit_yaml(|t| crate::addons::trust::set_delegation(t, name, on)) {
        Ok(p) => p,
        Err(e) => fail(g.json, ExitCode::Generic, "config", &e, None),
    };
    if g.json {
        println!("{}", json!({"addon": name, "delegate_tasks": on, "config": path.display().to_string(), "restart_required": true}));
    } else {
        ui::done(&format!("{name}: addon_delegation.{name}.tasks = {on} ({})", path.display()));
        println!("{}", ui::note("it takes effect only if the add-on's manifest also declares `delegate: \"tasks\"`"));
        ui::guide(&[("noo stack restart --force", "the gateway reads it at start")]);
    }
    Ok(0)
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

    #[test]
    fn show_and_list_read_the_declarations_of_each_materialised_bundle() {
        let root = std::env::temp_dir().join(format!("noo-addons-decls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ex = root.join("addons").join("example-addon");
        std::fs::create_dir_all(&ex).unwrap();
        std::fs::write(ex.join("docker-compose.yml"), "services: {}\n").unwrap();
        std::fs::write(ex.join("system.json"), r#"{"schema":"example_addon","role":"noo_example_addon","ddl_role":"noo_example_addon_ddl"}"#).unwrap();
        std::fs::write(ex.join("workloads.json"), r#"{"workloads":[{"name":"worker","container":"noo-example-addon-worker","gpu":false,"need_mb":512,"drain":{"route":"drain","timeout_secs":30}}]}"#).unwrap();
        let bad = root.join("addons").join("broken-addon");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("system.json"), r#"{"schema":"public","role":"noo_app","ddl_role":"noo"}"#).unwrap();
        let got = bundle_decls(&root);
        assert_eq!(got.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["broken-addon", "example-addon"]);
        assert!(got[0].1.is_err());
        let j = decl_json(&got[1].1);
        assert_eq!(j["system"]["schema"], "example_addon");
        assert_eq!(j["workloads"][0]["container"], "noo-example-addon-worker");
        assert_eq!(j["workloads"][0]["drain"]["timeout_secs"], 30);
        assert!(decl_json(&got[0].1)["error"].as_str().unwrap().contains("`schema`"));
        let _ = std::fs::remove_dir_all(&root);
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
        let path = crate::test_support::repo_file("gateway-rust/src/addons.rs");
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

    #[test]
    fn list_marks_a_dev_signed_third_party_addon_with_its_expiry() {
        let pk = |seed: &str| crate::release_sig::pubkey_hex(&crate::release_sig::signing_key_from_seed_hex(seed).unwrap());
        let now = 1_790_000_000;
        let root = "ghcr.io/vendor/x";
        let t = "addons:\n  pai-voice: true\n";
        let t = crate::addons::trust::add_dev_key(t, "pai-voice", &pk(&"ab".repeat(32)), Some(root), 86_400, now).unwrap();
        let t = crate::addons::trust::add_key(&t, "other-addon", &pk(&"cd".repeat(32)), Some(root)).unwrap();
        let rows = third_party_rows(&t, now);
        let until = crate::addon_lock::utc_minute(now + 86_400);
        assert_eq!(rows, vec![
            ("other-addon".to_string(), None, "release".to_string()),
            ("pai-voice".to_string(), Some(true), format!("DEV until {until}")),
        ]);
        // After the expiry it reads EXPIRED (the launcher refuses it).
        let rows = third_party_rows(&t, now + 86_400);
        assert_eq!(rows[1].2, format!("DEV EXPIRED {until}"));
        // The add-ons the CLI ships are never listed here.
        assert!(third_party_rows("addons:\n  evolve: true\n", now).is_empty());
    }
}
