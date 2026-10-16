// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The controller stages vendor CLIs (i83 E1e): `noo cluster vendor stage`
//! and `noo cluster vendor status`, and the pure halves the provision bundle
//! and the appliers use.
//!
//! A harness kind whose `cli` the node must have (Copilot CLI, Claude Code,
//! Codex) carries a `distribution` in `config/harness-kinds.json`: where the
//! vendor publishes it, the version, and the sha256 it must hash to. The
//! flow, start to end:
//!
//! 1. the pin lands in the table (reviewed like any change);
//! 2. `noo cluster vendor stage <kind>` fetches each artefact the fleet's
//!    platforms need ON THE CONTROLLER, refuses anything whose sha256 is not
//!    the pinned one, and keeps it in the controller's asset cache;
//! 3. `noo cluster provision <node>` puts it in the node's signed bundle as
//!    `vendor-cli` beside a manifest, when the node's
//!    harness placement names that kind; never downloading during a restage;
//! 4. the node's applier verifies the sha256 again, unpacks it under
//!    `/opt/noo/vendor` (`~/noomesh/vendor` on a Mac) and writes a wrapper
//!    named for the CLI on the harness's PATH.
//!
//! The node never touches the internet for it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::harness_kinds::{self, artifact_url, Format, Pinned, Table, Unpack};
use crate::output::{fail, ExitCode};
use crate::ui::{self, Col};
use crate::{Globals, Unhandled};

/// Where staged vendor artefacts live on the controller: beside the
/// version-keyed release asset cache (`provision::cli_asset_cache_dir`),
/// NOT inside it. A vendor artefact is keyed by its own version and pinned
/// by its own sha256; keying it by this CLI's version would throw every
/// staged CLI away on each `noo upgrade` and refuse the next restage.
pub(crate) fn vendor_cache_dir(root: &Path) -> PathBuf {
    let release = super::provision::cli_asset_cache_dir(root);
    release.parent().unwrap_or(root).join("vendor")
}

/// The cache file name: `<name>-<version>-<os>-<arch>.<ext>`, or
/// `<name>-<version>-any.<ext>` for an artefact every platform shares
/// (stored once).
pub(crate) fn cache_file_name(name: &str, version: &str, platform: Option<(&str, &str)>, unpack: Unpack) -> String {
    match platform {
        Some((os, arch)) => format!("{name}-{version}-{os}-{arch}.{}", unpack.ext()),
        None => format!("{name}-{version}-any.{}", unpack.ext()),
    }
}

/// One artefact a kind needs on one platform.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Need {
    pub kind: String,
    /// The CLI name (`copilot`).
    pub name: String,
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub unpack: Unpack,
    pub file: String,
    /// Shared by every platform.
    pub any: bool,
}

fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with("noo")
}

fn safe_version(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)) && !s.starts_with('.')
}

/// A relative path inside the unpacked tree: no leading `/`, no `..` or
/// `.` component, a conservative charset (the applier interpolates it into
/// a shell wrapper).
fn safe_entry(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('/')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/@+-".contains(&b))
        && s.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// What `kind` needs on `os`/`arch`: its CLI artefact. `Ok(None)` for a kind with no
/// distribution (no CLI, or a manual install). Refused: an unknown kind,
/// a platform with no pin, a value
/// the applier would refuse.
pub(crate) fn needs_for(table: &Table, kind: &str, os: &str, arch: &str) -> Result<Option<Vec<Need>>, String> {
    let row = table.kinds.iter().find(|k| k.kind == kind).ok_or_else(|| {
        format!("'{kind}' is not a harness kind (config/harness-kinds.json declares {})",
            table.kinds.iter().map(|k| k.kind.as_str()).collect::<Vec<_>>().join(", "))
    })?;
    let Some(dist) = row.distribution.as_ref() else { return Ok(None) };
    let cli = row.cli.as_deref().ok_or_else(|| format!("'{kind}' has a distribution but no cli"))?;
    if !safe_name(cli) {
        return Err(format!("'{kind}': cli {cli:?} is not a name the applier installs"));
    }
    if !safe_version(&dist.version) {
        return Err(format!("'{kind}': version {:?} is not a plain version", dist.version));
    }
    if !safe_entry(&dist.entry) {
        return Err(format!("'{kind}': entry {:?} is not a plain relative path", dist.entry));
    }
    if dist.format == Format::Binary && dist.unpack == Unpack::None && dist.entry.contains('/') {
        return Err(format!("'{kind}': a single binary's entry is its file name, not {:?}", dist.entry));
    }
    let (url, sha) = artifact_url(dist, os, arch).map_err(|e| format!("'{kind}' {cli} {}: {e}", dist.version))?;
    let any = dist.is_any();
    Ok(Some(vec![Need {
        kind: kind.to_string(),
        name: cli.to_string(),
        version: dist.version.clone(),
        url,
        sha256: sha,
        unpack: dist.unpack,
        file: cache_file_name(cli, &dist.version, (!any).then_some((os, arch)), dist.unpack),
        any,
    }]))
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Verify `bytes` against the pin, then write them to `dst` atomically.
/// A mismatch writes NOTHING and names the URL and both digests.
pub(crate) fn verify_and_store(dst: &Path, bytes: &[u8], url: &str, want: &str) -> Result<(), String> {
    let got = sha256_hex(bytes);
    if !got.eq_ignore_ascii_case(want) {
        return Err(format!(
            "{url} does not hash to its pin: config/harness-kinds.json pins sha256 {want}, the download is {got} — nothing was written"
        ));
    }
    let dir = dst.parent().ok_or_else(|| format!("{} has no parent", dst.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.{}.part", dst.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, dst).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", dst.display())
    })
}

/// The cached artefact, only when it still hashes to its pin.
pub(crate) fn read_staged(dir: &Path, need: &Need) -> Option<Vec<u8>> {
    std::fs::read(dir.join(&need.file)).ok().filter(|b| sha256_hex(b).eq_ignore_ascii_case(&need.sha256))
}

// ── bundle inclusion ──────────────────────────────────────────────────────

/// The harness kind a node's desired placements name: the `harness`
/// placement's `NOO_HARNESS_KIND` (`noo` when it names none), or None when
/// the node has no harness placement. `desired` is
/// `/api/cluster/nodes/<node>/desired-config`; the node agent reads the
/// same field (`desiredHarnessKind`).
pub(crate) fn desired_harness_kind(desired: &Value) -> Option<String> {
    let p = desired["placements"].as_array()?.iter().find(|p| p["backend"].as_str() == Some("harness"))?;
    Some(
        p["env"]["NOO_HARNESS_KIND"].as_str().map(str::trim).filter(|k| !k.is_empty()).unwrap_or("noo").to_string(),
    )
}

/// The manifest that rides beside a `vendor-cli` payload. One key per line, every value a plain string or `null`: the
/// Linux applier reads it with `sed`, so the layout is part of the contract
/// (`scripts/noo-apply.sh`, vendor_install).
pub(crate) fn manifest_text(fields: &[(&str, Option<&str>)]) -> String {
    let mut s = String::from("{\n");
    for (i, (k, v)) in fields.iter().enumerate() {
        let val = match v {
            Some(v) => serde_json::to_string(v).unwrap_or_else(|_| "null".into()),
            None => "null".into(),
        };
        s.push_str(&format!("  \"{k}\": {val}{}\n", if i + 1 < fields.len() { "," } else { "" }));
    }
    s.push_str("}\n");
    s
}

/// What a vendor CLI adds to a node's bundle. A pure decision over the
/// table, the node's desired kind and platform, and the controller's staged
/// set (`staged` returns the verified bytes of a cached file, or None).
///
/// `Ok(vec![])`: nothing to carry (no harness placement, `noo`, or a kind
/// that is a manual install). `Err`: the kind needs an artefact the
/// controller has not staged, or cannot be staged for this platform — the
/// restage is refused, because a node placed on a CLI it does not have
/// would only be refused by its agent.
pub(crate) fn vendor_bundle_files(
    table: &Table,
    desired_kind: Option<&str>,
    os: &str,
    arch: &str,
    staged: &dyn Fn(&Need) -> Option<Vec<u8>>,
) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let Some(kind) = desired_kind else { return Ok(Vec::new()) };
    let needs = match needs_for(table, kind, os, arch) {
        Ok(Some(n)) => n,
        Ok(None) => return Ok(Vec::new()),
        Err(e) => return Err(format!("the harness placement names {kind}, which cannot be staged for {os}/{arch}: {e}")),
    };
    let missing: Vec<String> = needs.iter().filter(|n| staged(n).is_none())
        .map(|n| format!("{} {}", n.name, n.version)).collect();
    if !missing.is_empty() {
        return Err(format!(
            "the harness placement names {kind}, and the controller has not staged {} for {os}/{arch} — \
             run `noo cluster vendor stage {kind}` first (the restage never downloads)",
            missing.join(" + ")
        ));
    }
    let table_row = table.kinds.iter().find(|k| k.kind == kind).and_then(|k| k.distribution.as_ref());
    let dist = table_row.expect("needs_for found a distribution");
    let cli = &needs[0];
    Ok(vec![
        ("vendor-cli", staged(cli).unwrap_or_default()),
        (
            "vendor-cli-manifest",
            manifest_text(&[
                ("kind", Some(kind)),
                ("name", Some(&cli.name)),
                ("version", Some(&cli.version)),
                ("sha256", Some(&cli.sha256)),
                ("format", Some(dist.format.as_str())),
                ("unpack", Some(cli.unpack.as_str())),
                ("entry", Some(&dist.entry)),
            ])
            .into_bytes(),
        ),
    ])
}

/// The Mac applier learned the vendor kinds in this release; an older Mac
/// CLI would refuse the whole bundle on them (see
/// `provision::applier_knows_harness_kinds`), so it is sent none until its
/// CLI moves. Linux always knows: the applier rides the bundle.
pub(crate) const VENDOR_KINDS_MAC_FLOOR: (u32, u32, u32) = (0, 6, 5);

pub(crate) fn applier_knows_vendor_kinds(darwin: bool, app_version: &str) -> bool {
    !darwin || super::node_leaves::cli_version_triple(app_version).is_none_or(|v| v >= VENDOR_KINDS_MAC_FLOOR)
}

// ── the wrapper ───────────────────────────────────────────────────────────

/// The wrapper written at `<bin>/<cli>`: `vendor_root` is `/opt/noo/vendor`
/// on Linux and `<home>/noomesh/vendor` on a Mac. It executes the entry
/// directly. The Linux applier writes the same text
/// (`scripts/noo-apply.sh` vendor_wrapper; tests/test_vendor_apply_block.py
/// holds the two equal).
pub(crate) fn wrapper_script(vendor_root: &str, name: &str, version: &str, entry: &str) -> String {
    let target = format!("{vendor_root}/{name}/{version}/{entry}");
    format!(
        "#!/bin/sh\n# noomesh vendor wrapper: {name} {version}, staged by the controller; do not edit\nexec \"{target}\" \"$@\"\n"
    )
}

// ── the verbs ─────────────────────────────────────────────────────────────

/// The `(os, arch)` pairs the fleet's enrolled nodes report, in noomesh
/// spelling (companions have no host agent and are left out).
fn fleet_platforms(nodes: &[Value]) -> BTreeSet<(&'static str, &'static str)> {
    nodes.iter().filter(|n| !super::cluster_provision::is_companion(n)).filter_map(node_platform).collect()
}

fn node_platform(n: &Value) -> Option<(&'static str, &'static str)> {
    let caps = &n["capabilities"];
    let os = caps["os"].as_str().or_else(|| n["os"].as_str()).unwrap_or("");
    let arch = caps["arch"].as_str().or_else(|| n["arch"].as_str()).unwrap_or("");
    harness_kinds::normalize_platform(os, arch)
}

/// The platforms a stage run covers: the fleet's, narrowed by `--os` /
/// `--arch`; both flags name exactly one.
pub(crate) fn pick_platforms(
    fleet: &BTreeSet<(&'static str, &'static str)>,
    os: Option<&str>,
    arch: Option<&str>,
) -> Vec<(&'static str, &'static str)> {
    if let (Some(o), Some(a)) = (os, arch) {
        return harness_kinds::normalize_platform(o, a).into_iter().collect();
    }
    fleet.iter().copied()
        .filter(|(o, a)| os.is_none_or(|x| x == *o) && arch.is_none_or(|x| x == *a))
        .collect()
}

#[derive(Debug, Default, PartialEq)]
struct StageArgs {
    kind: Option<String>,
    all: bool,
    os: Option<String>,
    arch: Option<String>,
}

fn parse_stage_args(args: &[String]) -> Result<StageArgs, Unhandled> {
    let mut a = StageArgs::default();
    let mut it = args.iter();
    while let Some(t) = it.next() {
        match t.as_str() {
            "--all" => a.all = true,
            "--os" => a.os = Some(it.next().ok_or(Unhandled)?.clone()),
            "--arch" => a.arch = Some(it.next().ok_or(Unhandled)?.clone()),
            x if x.starts_with('-') => return Err(Unhandled),
            x if a.kind.is_none() => a.kind = Some(x.to_string()),
            _ => return Err(Unhandled),
        }
    }
    if a.all == a.kind.is_some() {
        return Err(Unhandled); // exactly one of <kind> and --all
    }
    if a.os.as_deref().is_some_and(|o| !harness_kinds::OSES.contains(&o))
        || a.arch.as_deref().is_some_and(|x| !harness_kinds::ARCHES.contains(&x))
    {
        return Err(Unhandled);
    }
    Ok(a)
}

/// `noo cluster vendor stage <kind>|--all [--os linux|macos] [--arch x86_64|aarch64]`
pub fn cluster_vendor_stage(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = parse_stage_args(args)?;
    let table = harness_kinds::shipped();
    let kinds: Vec<String> = match &a.kind {
        Some(k) => {
            match table.kinds.iter().find(|r| &r.kind == k) {
                None => fail(g.json, ExitCode::Usage, "unknown_kind",
                    &format!("'{k}' is not a harness kind (one of {})", harness_kinds::names().join(", ")), None),
                Some(r) if r.distribution.is_none() => fail(g.json, ExitCode::Generic, "no_distribution",
                    &format!("'{k}' carries no distribution in config/harness-kinds.json — {}",
                        if r.cli.is_some() { "its CLI is a manual install until a pin lands there" } else { "it has no vendor CLI" }),
                    None),
                Some(_) => vec![k.clone()],
            }
        }
        None => table.kinds.iter().filter(|r| r.distribution.is_some()).map(|r| r.kind.clone()).collect(),
    };
    if kinds.is_empty() {
        if g.json {
            println!("{}", json!({"status": "ok", "staged": [], "skipped": [], "note": "no kind carries a distribution"}));
        } else {
            ui::done("no kind in config/harness-kinds.json carries a distribution yet — nothing to stage");
        }
        return Ok(0);
    }
    let fleet = if a.os.is_some() && a.arch.is_some() {
        BTreeSet::new()
    } else {
        let body = crate::http::get_json(g, "/api/cluster/nodes", true, 10);
        fleet_platforms(body["nodes"].as_array().map(Vec::as_slice).unwrap_or(&[]))
    };
    let platforms = pick_platforms(&fleet, a.os.as_deref(), a.arch.as_deref());
    if platforms.is_empty() {
        fail(g.json, ExitCode::Generic, "no_platforms",
            "no enrolled node reports a platform this filter selects",
            Some("name one: noo cluster vendor stage <kind> --os linux --arch x86_64"));
    }
    let dir = vendor_cache_dir(&crate::envfile::repo_root());
    let mut staged: Vec<Value> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for kind in &kinds {
        for (os, arch) in &platforms {
            let needs = match needs_for(&table, kind, os, arch) {
                Ok(Some(n)) => n,
                Ok(None) => continue,
                Err(e) => {
                    if !g.json { ui::warned(&format!("{kind} on {os}/{arch}: Skipped — {e}")); }
                    skipped.push(json!({"kind": kind, "platform": format!("{os}-{arch}"), "why": e}));
                    continue;
                }
            };
            for n in needs {
                if !seen.insert(n.file.clone()) {
                    continue; // an `any` artefact two kinds share: once
                }
                let platform = if n.any { "any".to_string() } else { format!("{os}-{arch}") };
                let path = dir.join(&n.file);
                let mut row = json!({"kind": kind, "name": n.name, "version": n.version, "platform": platform,
                                     "sha256": n.sha256, "url": n.url, "path": path.display().to_string()});
                if let Some(b) = read_staged(&dir, &n) {
                    row["bytes"] = json!(b.len());
                    row["outcome"] = json!("already-staged");
                    if !g.json { ui::done(&format!("{} {} ({platform}): already staged, sha256 verified ({})", n.name, n.version, human(b.len()))); }
                    staged.push(row);
                    continue;
                }
                if !g.json { ui::step(&format!("fetching {} {} ({platform}) from {}", n.name, n.version, n.url)); }
                let r = super::upgrade::http_get_bytes(&n.url, None).map_err(|e| e.summary())
                    .and_then(|b| verify_and_store(&path, &b, &n.url, &n.sha256).map(|_| b.len()));
                match r {
                    Ok(len) => {
                        row["bytes"] = json!(len);
                        row["outcome"] = json!("staged");
                        if !g.json { ui::done(&format!("{} {} ({platform}): Verified against its pin, staged ({})", n.name, n.version, human(len))); }
                        staged.push(row);
                    }
                    Err(e) => {
                        if !g.json { ui::failed(&format!("{} {} ({platform}): {e}", n.name, n.version), None); }
                        row["error"] = json!(e);
                        failed.push(row);
                    }
                }
            }
        }
    }
    if g.json {
        println!("{}", json!({"status": if failed.is_empty() { "ok" } else { "failed" },
            "cache": dir.display().to_string(), "staged": staged, "skipped": skipped, "failed": failed}));
    } else {
        println!();
        if failed.is_empty() {
            ui::close_done(&format!("{} artefact(s) staged in {}", staged.len(), dir.display()));
            ui::guide(&[
                ("noo cluster vendor status", "which nodes need which artefact, and whether it is staged"),
                ("noo cluster provision <node>", "restage a node whose harness placement names the kind"),
            ]);
        } else {
            ui::close_failed(&format!("{} artefact(s) not staged; nothing unverified was written", failed.len()),
                Some("noo cluster vendor status"));
        }
    }
    Ok(if failed.is_empty() { 0 } else { 1 })
}

fn human(n: usize) -> String {
    if n >= 1_000_000 { format!("{:.1} MB", n as f64 / 1_000_000.0) } else { format!("{:.0} kB", n as f64 / 1_000.0) }
}

/// One node's line in `status`: what its harness placement needs.
pub(crate) fn node_need_cell(table: &Table, kind: Option<&str>, platform: Option<(&str, &str)>, staged: &dyn Fn(&Need) -> bool) -> (String, bool) {
    let Some(kind) = kind else { return ("no harness placement".into(), true) };
    let Some((os, arch)) = platform else { return (format!("{kind}: platform not reported"), true) };
    match needs_for(table, kind, os, arch) {
        Ok(None) => (format!("{kind}: nothing to stage"), true),
        Err(e) => (format!("{kind}: {e}"), false),
        Ok(Some(needs)) => {
            let missing: Vec<String> = needs.iter().filter(|n| !staged(n)).map(|n| format!("{} {}", n.name, n.version)).collect();
            let all: Vec<String> = needs.iter().map(|n| format!("{} {}", n.name, n.version)).collect();
            if missing.is_empty() {
                (format!("{kind}: {} — Ready", all.join(" + ")), true)
            } else {
                (format!("{kind}: {} — Pending (not staged: {})", all.join(" + "), missing.join(", ")), false)
            }
        }
    }
}

/// `noo cluster vendor status`
pub fn cluster_vendor_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let table = harness_kinds::shipped();
    let dir = vendor_cache_dir(&crate::envfile::repo_root());
    let body = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10).unwrap_or(Value::Null);
    let nodes: Vec<Value> = body["nodes"].as_array().cloned().unwrap_or_default()
        .into_iter().filter(|n| !super::cluster_provision::is_companion(n)).collect();
    let fleet = fleet_platforms(&nodes);
    // Platforms to show: the fleet's, or every one noomesh stages for when
    // the gateway did not answer.
    let platforms: Vec<(&str, &str)> = if fleet.is_empty() {
        harness_kinds::OSES.iter().flat_map(|o| harness_kinds::ARCHES.iter().map(move |a| (*o, *a))).collect()
    } else {
        fleet.iter().copied().collect()
    };
    let mut artefacts: Vec<Value> = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut manual: Vec<String> = Vec::new();
    for k in &table.kinds {
        if k.distribution.is_none() {
            if let Some(c) = &k.cli { manual.push(format!("{} ({c})", k.kind)); }
            continue;
        }
        for (os, arch) in &platforms {
            let needs = match needs_for(&table, &k.kind, os, arch) {
                Ok(Some(n)) => n,
                Ok(None) => continue,
                Err(e) => {
                    rows.push(vec![k.kind.clone(), "—".into(), format!("{os}-{arch}"), ui::state("Skipped"), String::new(), e.clone()]);
                    artefacts.push(json!({"kind": k.kind, "platform": format!("{os}-{arch}"), "state": "unavailable", "why": e}));
                    continue;
                }
            };
            for n in needs {
                if !seen.insert((k.kind.clone(), n.file.clone())) {
                    continue;
                }
                let platform = if n.any { "any".to_string() } else { format!("{os}-{arch}") };
                let bytes = read_staged(&dir, &n).map(|b| b.len());
                rows.push(vec![
                    k.kind.clone(),
                    format!("{} {}", n.name, n.version),
                    platform.clone(),
                    ui::state(if bytes.is_some() { "Ready" } else { "Pending" }),
                    bytes.map(human).unwrap_or_default(),
                    n.file.clone(),
                ]);
                artefacts.push(json!({"kind": k.kind, "name": n.name, "version": n.version, "platform": platform,
                    "staged": bytes.is_some(), "bytes": bytes, "file": n.file}));
            }
        }
    }
    let staged_fn = |n: &Need| read_staged(&dir, n).is_some();
    let mut node_rows: Vec<Vec<String>> = Vec::new();
    let mut node_json: Vec<Value> = Vec::new();
    let mut need_stage: BTreeSet<String> = BTreeSet::new();
    for n in &nodes {
        let Some(id) = n["id"].as_str() else { continue };
        let desired = crate::http::get_json_opt(g, &format!("/api/cluster/nodes/{}/desired-config", super::urlencode(id)), true, 10);
        let kind = desired.as_ref().and_then(desired_harness_kind);
        let plat = node_platform(n);
        let (cell, ok) = node_need_cell(&table, kind.as_deref(), plat, &staged_fn);
        if !ok {
            if let Some(k) = &kind { need_stage.insert(k.clone()); }
        }
        node_rows.push(vec![id.to_string(), plat.map(|(o, a)| format!("{o}-{a}")).unwrap_or_else(|| "?".into()), cell.clone()]);
        node_json.push(json!({"node": id, "kind": kind, "platform": plat.map(|(o, a)| format!("{o}-{a}")), "needs": cell, "ready": ok}));
    }
    if g.json {
        println!("{}", json!({"cache": dir.display().to_string(), "artefacts": artefacts, "nodes": node_json, "manual": manual}));
        return Ok(0);
    }
    println!("{}", ui::section("staged vendor artefacts"));
    if rows.is_empty() {
        println!("{}", ui::muted("no kind in config/harness-kinds.json carries a distribution yet"));
    } else {
        print!("{}", ui::table(&[Col::left("kind"), Col::left("artefact"), Col::left("platform"), Col::left("state"), Col::right("size"), Col::left("file")], &rows));
    }
    if !manual.is_empty() {
        println!("{}", ui::muted(&format!("manual install (no distribution pinned): {}", manual.join(", "))));
    }
    println!("{}", ui::section("nodes"));
    if node_rows.is_empty() {
        println!("{}", ui::muted("no enrolled node listed (is the gateway up?)"));
    } else {
        print!("{}", ui::table(&[Col::left("node"), Col::left("platform"), Col::left("harness needs")], &node_rows));
    }
    let cmds: Vec<String> = need_stage.iter().map(|k| format!("noo cluster vendor stage {k}")).collect();
    let mut guide: Vec<(&str, &str)> = cmds.iter().map(|c| (c.as_str(), "fetch and verify what a placed node still needs")).collect();
    guide.push(("noo cluster provision <node>", "restage a node so its bundle carries the staged CLI"));
    ui::guide(&guide);
    Ok(0)
}

/// `noo cluster vendor` with no subaction.
pub fn cluster_vendor_usage(g: &Globals, _args: &[String]) -> Result<i32, Unhandled> {
    fail(
        g.json,
        ExitCode::Usage,
        "usage",
        "noo cluster vendor needs a subaction",
        Some("stage <kind>|--all [--os linux|macos] [--arch x86_64|aarch64]   fetch and verify vendor CLIs on the controller; status   what is staged and who needs it"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness_kinds::{parse, FIXTURE};

    fn t() -> Table {
        parse(FIXTURE).unwrap()
    }

    #[test]
    fn vendor_cache_sits_beside_the_version_keyed_release_cache() {
        let root = Path::new("/tmp/noo-vendor-root");
        assert_eq!(vendor_cache_dir(root), root.join("bin").join("vendor"));
        assert_ne!(vendor_cache_dir(root), super::super::provision::cli_asset_cache_dir(root));
    }

    #[test]
    fn cache_paths_are_name_version_platform_ext_and_any_once() {
        assert_eq!(cache_file_name("claude", "2.0.1", Some(("linux", "x86_64")), Unpack::Zip), "claude-2.0.1-linux-x86_64.zip");
        assert_eq!(cache_file_name("copilot", "0.0.339", None, Unpack::Tgz), "copilot-0.0.339-any.tgz");
        assert_eq!(cache_file_name("codex", "0.46.0", Some(("macos", "aarch64")), Unpack::None), "codex-0.46.0-macos-aarch64.bin");
        let t = t();
        let a = needs_for(&t, "copilot", "linux", "x86_64").unwrap().unwrap();
        let b = needs_for(&t, "copilot", "macos", "aarch64").unwrap().unwrap();
        assert_eq!(a[0].file, b[0].file, "an any artefact is one file for every platform");
        let c = needs_for(&t, "codex", "linux", "x86_64").unwrap().unwrap();
        let d = needs_for(&t, "codex", "macos", "aarch64").unwrap().unwrap();
        assert_ne!(c[0].file, d[0].file, "a per-platform artefact is one file per platform");
    }

    #[test]
    fn needs_follow_the_table() {
        let t = t();
        let n = needs_for(&t, "copilot", "linux", "aarch64").unwrap().unwrap();
        assert_eq!(n.len(), 1, "a kind needs one artefact");
        assert_eq!((n[0].name.as_str(), n[0].version.as_str()), ("copilot", "0.0.339"));
        let c = needs_for(&t, "codex", "linux", "x86_64").unwrap().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].url, "https://example.invalid/codex/0.46.0/codex-x86_64-unknown-linux-musl");
        assert!(needs_for(&t, "noo", "linux", "x86_64").unwrap().is_none());
        assert!(needs_for(&t, "manual", "linux", "x86_64").unwrap().is_none(), "manual install stages nothing");
        assert!(needs_for(&t, "codex", "linux", "aarch64").unwrap_err().contains("no sha256 pin"));
        assert!(needs_for(&t, "nope", "linux", "x86_64").unwrap_err().contains("not a harness kind"));
    }

    #[test]
    fn values_the_applier_would_interpolate_are_held_to_a_charset() {
        let bad = FIXTURE.replace("bin/copilot", "../../etc/passwd");
        assert!(needs_for(&parse(&bad).unwrap(), "copilot", "linux", "x86_64").unwrap_err().contains("entry"));
        let bad = FIXTURE.replace("\"0.0.339\"", "\"1.0;rm\"");
        assert!(needs_for(&parse(&bad).unwrap(), "copilot", "linux", "x86_64").unwrap_err().contains("version"));
        let bad = FIXTURE.replace("\"cli\": \"codex\"", "\"cli\": \"noo-gateway\"");
        assert!(needs_for(&parse(&bad).unwrap(), "codex", "linux", "x86_64").is_err(), "a wrapper may not shadow a noo binary");
    }

    #[test]
    fn a_wrong_download_is_refused_and_nothing_is_written() {
        let d = std::env::temp_dir().join(format!("noo-vendor-sha-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let dst = d.join("copilot-1-any.tgz");
        let want = sha256_hex(b"the real bytes");
        let e = verify_and_store(&dst, b"tampered bytes", "https://example.invalid/x.tgz", &want).unwrap_err();
        assert!(e.contains("https://example.invalid/x.tgz") && e.contains(&want) && e.contains(&sha256_hex(b"tampered bytes")), "{e}");
        assert!(!dst.exists(), "a mismatch writes nothing");
        assert!(!d.exists() || std::fs::read_dir(&d).unwrap().next().is_none(), "no partial file either");
        verify_and_store(&dst, b"the real bytes", "u", &want.to_uppercase()).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"the real bytes");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_staged_file_that_no_longer_hashes_to_its_pin_reads_as_unstaged() {
        let d = std::env::temp_dir().join(format!("noo-vendor-read-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let mut n = needs_for(&t(), "codex", "linux", "x86_64").unwrap().unwrap().remove(0);
        n.sha256 = sha256_hex(b"good");
        std::fs::write(d.join(&n.file), b"bad").unwrap();
        assert!(read_staged(&d, &n).is_none());
        std::fs::write(d.join(&n.file), b"good").unwrap();
        assert_eq!(read_staged(&d, &n).unwrap(), b"good");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_desired_kind_comes_from_the_harness_placement() {
        let d = json!({"placements": [{"backend": "vllm", "env": {}}, {"backend": "harness", "env": {"NOO_HARNESS_KIND": " copilot "}}]});
        assert_eq!(desired_harness_kind(&d).as_deref(), Some("copilot"));
        let d = json!({"placements": [{"backend": "harness", "env": null}]});
        assert_eq!(desired_harness_kind(&d).as_deref(), Some("noo"));
        assert_eq!(desired_harness_kind(&json!({"placements": [{"backend": "vllm"}]})), None);
        assert_eq!(desired_harness_kind(&json!({})), None);
    }

    fn all_staged(n: &Need) -> Option<Vec<u8>> {
        Some(format!("bytes-of-{}", n.file).into_bytes())
    }

    #[test]
    fn bundle_carries_the_cli_and_its_manifest() {
        let f = vendor_bundle_files(&t(), Some("copilot"), "linux", "x86_64", &all_staged).unwrap();
        let kinds: Vec<&str> = f.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, ["vendor-cli", "vendor-cli-manifest"]);
        assert_eq!(f[0].1, b"bytes-of-copilot-0.0.339-any.tgz");
        let m: Value = serde_json::from_slice(&f[1].1).unwrap();
        assert_eq!(m, json!({"kind": "copilot", "name": "copilot", "version": "0.0.339", "sha256": "a".repeat(64),
            "format": "tarball", "unpack": "tgz", "entry": "bin/copilot"}));
        // One key per line: the Linux applier's sed reads this layout.
        let text = String::from_utf8(f[1].1.clone()).unwrap();
        assert!(text.lines().any(|l| l == "  \"entry\": \"bin/copilot\""), "{text}");
        assert!(text.lines().any(|l| l == "  \"unpack\": \"tgz\","), "{text}");
    }

    #[test]
    fn a_binary_kind_carries_its_manifest_too() {
        let f = vendor_bundle_files(&t(), Some("codex"), "macos", "aarch64", &all_staged).unwrap();
        assert_eq!(f.iter().map(|(k, _)| *k).collect::<Vec<_>>(), ["vendor-cli", "vendor-cli-manifest"]);
        let m: Value = serde_json::from_slice(&f[1].1).unwrap();
        assert_eq!(m["format"], "binary");
        assert_eq!(m["unpack"], "none");
    }

    #[test]
    fn nothing_to_carry_for_noo_manual_or_no_placement() {
        for k in [None, Some("noo"), Some("manual")] {
            assert!(vendor_bundle_files(&t(), k, "linux", "x86_64", &all_staged).unwrap().is_empty(), "{k:?}");
        }
    }

    #[test]
    fn an_unstaged_artefact_refuses_the_restage_and_names_the_stage_command() {
        let none = |_: &Need| None;
        let e = vendor_bundle_files(&t(), Some("copilot"), "linux", "x86_64", &none).unwrap_err();
        assert!(e.contains("run `noo cluster vendor stage copilot` first") && e.contains("copilot 0.0.339"), "{e}");
        let e = vendor_bundle_files(&t(), Some("codex"), "linux", "aarch64", &all_staged).unwrap_err();
        assert!(e.contains("cannot be staged for linux/aarch64"), "{e}");
    }

    #[test]
    fn wrapper_for_a_binary_execs_it_directly() {
        let w = wrapper_script("/opt/noo/vendor", "codex", "0.46.0", "codex");
        assert_eq!(w, "#!/bin/sh\n# noomesh vendor wrapper: codex 0.46.0, staged by the controller; do not edit\nexec \"/opt/noo/vendor/codex/0.46.0/codex\" \"$@\"\n");
        assert!(!w.contains("PATH="));
    }

    #[test]
    fn the_mac_floor_withholds_vendor_kinds_from_older_macs_only() {
        assert!(applier_knows_vendor_kinds(false, "noo-cli-v0.5.1"));
        assert!(!applier_knows_vendor_kinds(true, "noo-cli-v0.6.4+abc"));
        assert!(applier_knows_vendor_kinds(true, "noo-cli-v0.6.5"));
        assert!(applier_knows_vendor_kinds(true, ""), "unknown version: assume it can");
    }

    #[test]
    fn platforms_come_from_the_fleet_and_narrow_by_flag() {
        let nodes = vec![
            json!({"id": "a", "capabilities": {"os": "linux", "arch": "amd64"}}),
            json!({"id": "b", "capabilities": {"os": "darwin", "arch": "arm64"}}),
            json!({"id": "c", "capabilities": {"os": "linux", "arch": "x86_64"}}),
            json!({"id": "d"}),
        ];
        let f = fleet_platforms(&nodes);
        assert_eq!(f.iter().copied().collect::<Vec<_>>(), [("linux", "x86_64"), ("macos", "aarch64")]);
        assert_eq!(pick_platforms(&f, Some("macos"), None), [("macos", "aarch64")]);
        assert_eq!(pick_platforms(&f, None, Some("x86_64")), [("linux", "x86_64")]);
        assert_eq!(pick_platforms(&BTreeSet::new(), Some("linux"), Some("aarch64")), [("linux", "aarch64")]);
    }

    #[test]
    fn stage_args_take_one_kind_or_all() {
        let s = |v: &[&str]| parse_stage_args(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        assert_eq!(s(&["copilot"]).unwrap().kind.as_deref(), Some("copilot"));
        assert!(s(&["--all", "--os", "linux", "--arch", "aarch64"]).unwrap().all);
        assert!(s(&[]).is_err() && s(&["copilot", "--all"]).is_err() && s(&["a", "b"]).is_err());
        assert!(s(&["--all", "--os", "windows"]).is_err() && s(&["--all", "--arch", "arm64"]).is_err());
    }

    #[test]
    fn a_node_line_says_ready_or_what_is_missing() {
        let t = t();
        let (c, ok) = node_need_cell(&t, Some("copilot"), Some(("linux", "x86_64")), &|_: &Need| false);
        assert!(!ok && c.contains("Pending (not staged: copilot 0.0.339)"), "{c}");
        let (c, ok) = node_need_cell(&t, Some("copilot"), Some(("linux", "x86_64")), &|_: &Need| true);
        assert!(ok && c.ends_with("Ready"), "{c}");
        assert!(node_need_cell(&t, None, None, &|_: &Need| true).1);
    }
}
