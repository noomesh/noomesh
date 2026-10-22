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
//! 2. `noo cluster vendor stage` fetches each artefact the nodes need (the
//!    kinds their harness placement and `vendor_kinds` name, for their
//!    platforms) ON THE CONTROLLER, refuses anything whose sha256 is not
//!    the pinned one, and keeps it in the controller's asset cache;
//! 3. `noo cluster provision <node>` puts it in the node's signed bundle as
//!    `vendor-cli` beside a manifest, when the node's harness placement
//!    names that kind or its `vendor_kinds` (`noo cluster vendor install`)
//!    lists it — one slot per CLI ([`VENDOR_SLOTS`]); never downloading
//!    during a restage;
//! 4. the node's applier verifies the sha256 again, unpacks it under
//!    `/opt/noo/vendor` (`~/noomesh/vendor` on a Mac) and writes a wrapper
//!    named for the CLI on the harness's PATH.
//!
//! The node never touches the internet for it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::harness_kinds::{self, artifact_url, Format, Pinned, Table, Unpack};
use crate::output::{fail, ExitCode};
use crate::release_fetch::{self, FetchClass, FetchError};
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

/// The `vendor_kinds` a node's config row lists (`noo cluster vendor
/// install`, `noo cluster set-config --vendor-kinds`): the kinds whose CLI
/// the node carries whatever its harness placement names. `desired` is
/// `/api/cluster/nodes/<node>/desired-config`; an older gateway sends none.
pub(crate) fn node_vendor_kinds(desired: &Value) -> Vec<String> {
    desired["node"]["vendor_kinds"].as_array().map(|a| {
        a.iter().filter_map(|k| k.as_str()).map(str::trim).filter(|k| !k.is_empty()).map(str::to_string).collect()
    }).unwrap_or_default()
}

/// The kinds whose CLI a node's bundle carries: the harness placement's
/// kind and the node's `vendor_kinds`, deduplicated, in name order (so a
/// CLI keeps its slot when the placement moves between kinds). `noo` never
/// needs a CLI and is left out; a kind with no distribution (a manual
/// install) is left to [`vendor_bundle_files`], which carries nothing for it.
pub(crate) fn bundle_vendor_kinds(placement: Option<&str>, vendor_kinds: &[String]) -> Vec<String> {
    placement.into_iter().map(str::to_string).chain(vendor_kinds.iter().cloned())
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty() && k != "noo")
        .collect::<BTreeSet<String>>()
        .into_iter().collect()
}

/// The bundle kinds the vendor CLIs ride in, one (payload, manifest) pair
/// per CLI. Slot 1 keeps the names every applier since E1e knows, so a
/// bundle carrying ONE CLI is byte-for-byte the layout it always was; the
/// next slots are new kinds, which a Mac applier older than
/// [`VENDOR_SLOTS_MAC_FLOOR`] would refuse the whole bundle on (the Linux
/// applier rides every bundle and self-updates first). Each slot is
/// verified on its own: the manifest's sha256 against its own payload.
pub(crate) const VENDOR_SLOTS: [(&str, &str); 3] = [
    ("vendor-cli", "vendor-cli-manifest"),
    ("vendor-cli-2", "vendor-cli-2-manifest"),
    ("vendor-cli-3", "vendor-cli-3-manifest"),
];

/// How much of a bundle the vendor CLIs may take, in MiB: the gateway's
/// rail body cap (`routes::bootstrap::MAX_RAIL_BODY`, 768) less room for
/// the rest of the bundle (the harness and agent binaries, ~100).
/// tests/test_rail_body_cap_fits_a_bundle.py holds the two together.
pub(crate) const VENDOR_BUNDLE_BUDGET_MB: usize = 560;

/// Why CLIs of these sizes (kind, bytes) cannot ride one bundle, or None.
fn budget_refusal(sizes: &[(&str, usize)]) -> Option<String> {
    let bytes: usize = sizes.iter().map(|(_, b)| b).sum();
    (bytes > VENDOR_BUNDLE_BUDGET_MB * 1024 * 1024).then(|| format!(
        "this node would carry {} MB of vendor CLIs ({}), past the {VENDOR_BUNDLE_BUDGET_MB} MB a bundle leaves for them \
         under the rail's body cap — drop one from its vendor_kinds",
        bytes / (1024 * 1024),
        sizes.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", ")
    ))
}

/// What the vendor CLIs add to a node's bundle. A pure decision over the
/// table, the kinds the node carries ([`bundle_vendor_kinds`]), its
/// platform, and the controller's staged set (`staged` returns the verified
/// bytes of a cached file, or None).
///
/// `Ok(vec![])`: nothing to carry (no kinds, `noo`, or only manual
/// installs). `Err`: a kind needs an artefact the controller has not
/// staged, or cannot be staged for this platform — the restage is refused,
/// because a node placed on a CLI it does not have would only be refused by
/// its agent. Every kind is judged before the answer, so one refusal names
/// everything missing.
pub(crate) fn vendor_bundle_files(
    table: &Table,
    kinds: &[String],
    os: &str,
    arch: &str,
    staged: &dyn Fn(&Need) -> Option<Vec<u8>>,
) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let mut carried: Vec<(&str, Need)> = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    for kind in kinds {
        let needs = match needs_for(table, kind, os, arch) {
            Ok(Some(n)) => n,
            Ok(None) => continue,
            Err(e) => {
                problems.push(format!("this node carries {kind} (its harness placement or vendor_kinds), which cannot be staged for {os}/{arch}: {e}"));
                continue;
            }
        };
        let missing: Vec<String> = needs.iter().filter(|n| staged(n).is_none())
            .map(|n| format!("{} {}", n.name, n.version)).collect();
        if !missing.is_empty() {
            problems.push(format!(
                "this node carries {kind} (its harness placement or vendor_kinds), and the controller has not staged {} for {os}/{arch} — \
                 run `noo cluster vendor stage {kind}` first (the restage never downloads)",
                missing.join(" + ")
            ));
            continue;
        }
        carried.extend(needs.into_iter().map(|n| (kind.as_str(), n)));
    }
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    if carried.len() > VENDOR_SLOTS.len() {
        return Err(format!(
            "this node would carry {} vendor CLIs ({}), and a bundle has {} slots — drop one from its vendor_kinds",
            carried.len(),
            carried.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(", "),
            VENDOR_SLOTS.len()
        ));
    }
    let sizes: Vec<(&str, usize)> = carried.iter().map(|(k, n)| (*k, staged(n).map_or(0, |b| b.len()))).collect();
    if let Some(e) = budget_refusal(&sizes) {
        return Err(e);
    }
    let mut out = Vec::new();
    for ((kind, cli), (slot, slot_manifest)) in carried.iter().zip(VENDOR_SLOTS) {
        let dist = table.kinds.iter().find(|k| k.kind == *kind).and_then(|k| k.distribution.as_ref())
            .expect("needs_for found a distribution");
        out.push((slot, staged(cli).unwrap_or_default()));
        out.push((
            slot_manifest,
            manifest_text(&[
                ("kind", Some(*kind)),
                ("name", Some(&cli.name)),
                ("version", Some(&cli.version)),
                ("sha256", Some(&cli.sha256)),
                ("format", Some(dist.format.as_str())),
                ("unpack", Some(cli.unpack.as_str())),
                ("entry", Some(&dist.entry)),
            ])
            .into_bytes(),
        ));
    }
    Ok(out)
}

/// The Mac applier learned the vendor kinds in this release; an older Mac
/// CLI would refuse the whole bundle on them (see
/// `provision::applier_knows_harness_kinds`), so it is sent none until its
/// CLI moves. Linux always knows: the applier rides the bundle.
pub(crate) const VENDOR_KINDS_MAC_FLOOR: (u32, u32, u32) = (0, 6, 5);

pub(crate) fn applier_knows_vendor_kinds(darwin: bool, app_version: &str) -> bool {
    !darwin || super::node_leaves::cli_version_triple(app_version).is_none_or(|v| v >= VENDOR_KINDS_MAC_FLOOR)
}

/// The first Mac applier that knows slots 2 and up ([`VENDOR_SLOTS`]).
/// An older one (0.6.5 – this floor) gets slot 1 only — the harness
/// placement's CLI, the layout it already applies — and the restage says
/// so. FLOOR: the release after 0.6.7; if that number ships without this
/// change, bump it.
pub(crate) const VENDOR_SLOTS_MAC_FLOOR: (u32, u32, u32) = (0, 6, 8);

pub(crate) fn applier_knows_vendor_slots(darwin: bool, app_version: &str) -> bool {
    !darwin || super::node_leaves::cli_version_triple(app_version).is_none_or(|v| v >= VENDOR_SLOTS_MAC_FLOOR)
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
    fleet: bool,
    os: Option<String>,
    arch: Option<String>,
}

/// One node as `stage` sees it: its platform and the kinds its bundle
/// carries ([`bundle_vendor_kinds`]).
#[derive(Debug, Clone)]
pub(crate) struct NodeCarry {
    pub id: String,
    pub platform: Option<(&'static str, &'static str)>,
    pub kinds: Vec<String>,
}

/// What the nodes need staged: each (kind, os, arch) some node's bundle
/// carries, with the nodes that carry it, narrowed to `kind` and to
/// `--os` / `--arch`. A node that reports no platform needs nothing here
/// (`status` says so).
pub(crate) fn needed_targets(
    nodes: &[NodeCarry],
    kind: Option<&str>,
    os: Option<&str>,
    arch: Option<&str>,
) -> BTreeMap<(String, &'static str, &'static str), Vec<String>> {
    let mut out: BTreeMap<(String, &'static str, &'static str), Vec<String>> = BTreeMap::new();
    for n in nodes {
        let Some((o, a)) = n.platform else { continue };
        if os.is_some_and(|x| x != o) || arch.is_some_and(|x| x != a) {
            continue;
        }
        for k in n.kinds.iter().filter(|k| kind.is_none_or(|want| want == k.as_str())) {
            out.entry((k.clone(), o, a)).or_default().push(n.id.clone());
        }
    }
    out
}

fn parse_stage_args(args: &[String]) -> Result<StageArgs, Unhandled> {
    let mut a = StageArgs::default();
    let mut it = args.iter();
    while let Some(t) = it.next() {
        match t.as_str() {
            "--all" => a.all = true,
            "--fleet" => a.fleet = true,
            "--os" => a.os = Some(it.next().ok_or(Unhandled)?.clone()),
            "--arch" => a.arch = Some(it.next().ok_or(Unhandled)?.clone()),
            x if x.starts_with('-') => return Err(Unhandled),
            x if a.kind.is_none() => a.kind = Some(x.to_string()),
            _ => return Err(Unhandled),
        }
    }
    if a.all && a.kind.is_some() {
        return Err(Unhandled); // <kind> or --all, not both
    }
    if a.fleet && a.kind.is_none() {
        return Err(Unhandled); // `--all` is every kind fleet-wide
    }
    if a.os.as_deref().is_some_and(|o| !harness_kinds::OSES.contains(&o))
        || a.arch.as_deref().is_some_and(|x| !harness_kinds::ARCHES.contains(&x))
    {
        return Err(Unhandled);
    }
    Ok(a)
}

/// `noo cluster vendor stage [<kind> [--fleet] | --all] [--os linux|macos] [--arch x86_64|aarch64]`
///
/// With no `<kind>` and no `--all` it stages what the nodes need: every kind
/// a node's harness placement or `vendor_kinds` names, for that node's
/// platform — the set `noo cluster provision` will put in their bundles.
/// `<kind>` narrows that to one kind; `--fleet` widens it to every platform
/// the fleet reports, needed or not; `--all` is every kind fleet-wide.
/// `--os` with `--arch` names one platform outright.
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
    let explicit = a.os.is_some() && a.arch.is_some() && (a.all || a.fleet || a.kind.is_some());
    let needed = !(a.all || a.fleet || explicit);
    // (kind, os, arch) → the nodes that carry it; empty for a fleet-wide or
    // named-platform run, which stages whether or not a node needs it.
    let targets: BTreeMap<(String, &'static str, &'static str), Vec<String>> = if needed {
        let body = crate::http::get_json(g, "/api/cluster/nodes", true, 10);
        let mut carries = Vec::new();
        for n in body["nodes"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            if super::cluster_provision::is_companion(n) {
                continue;
            }
            let Some(id) = n["id"].as_str() else { continue };
            let Some(desired) = crate::http::get_json_opt(g, &format!("/api/cluster/nodes/{}/desired-config", super::urlencode(id)), true, 10) else {
                if !g.json { ui::warned(&format!("{id}: Skipped — its desired config did not load")); }
                continue;
            };
            let kinds = bundle_vendor_kinds(desired_harness_kind(&desired).as_deref(), &node_vendor_kinds(&desired));
            let platform = node_platform(n);
            if platform.is_none() && !kinds.is_empty() && !g.json {
                ui::warned(&format!("{id}: Skipped — it reports no platform"));
            }
            carries.push(NodeCarry { id: id.to_string(), platform, kinds });
        }
        let t = needed_targets(&carries, a.kind.as_deref(), a.os.as_deref(), a.arch.as_deref());
        if t.is_empty() {
            let what = a.kind.as_deref().unwrap_or("a vendor CLI");
            if g.json {
                println!("{}", json!({"status": "ok", "staged": [], "skipped": [], "note": format!("no node carries {what}")}));
            } else {
                ui::done(&format!("no node's harness placement or vendor_kinds names {what} — nothing to stage"));
                ui::guide(&[
                    ("noo cluster vendor install <node> <kind>...", "have a node carry a CLI, then stage again"),
                    ("noo cluster vendor stage --all", "stage every CLI for every platform the fleet reports"),
                ]);
            }
            return Ok(0);
        }
        t
    } else {
        let fleet = if explicit {
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
        kinds.iter().flat_map(|k| platforms.iter().map(move |(o, a)| ((k.clone(), *o, *a), Vec::new()))).collect()
    };
    let dir = vendor_cache_dir(&crate::envfile::repo_root());
    let mut staged: Vec<Value> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut restage: BTreeSet<String> = BTreeSet::new();
    for ((kind, os, arch), for_nodes) in &targets {
        let needs = match needs_for(&table, kind, os, arch) {
            Ok(Some(n)) => n,
            Ok(None) => continue,
            Err(e) => {
                if !g.json { ui::warned(&format!("{kind} on {os}/{arch}: Skipped — {e}")); }
                skipped.push(json!({"kind": kind, "platform": format!("{os}-{arch}"), "why": e}));
                continue;
            }
        };
        restage.extend(for_nodes.iter().cloned());
        for n in needs {
            if !seen.insert(n.file.clone()) {
                continue; // an `any` artefact two kinds share: once
            }
            let platform = if n.any { "any".to_string() } else { format!("{os}-{arch}") };
            let path = dir.join(&n.file);
            let mut row = json!({"kind": kind, "name": n.name, "version": n.version, "platform": platform,
                                 "sha256": n.sha256, "url": n.url, "path": path.display().to_string()});
            if needed {
                row["nodes"] = json!(for_nodes);
            }
            if let Some(b) = read_staged(&dir, &n) {
                row["bytes"] = json!(b.len());
                row["outcome"] = json!("already-staged");
                if !g.json { ui::done(&format!("{} {} ({platform}): already staged, sha256 verified ({})", n.name, n.version, human(b.len()))); }
                staged.push(row);
                continue;
            }
            if !g.json { ui::step(&format!("fetching {} {} ({platform}) from {}", n.name, n.version, n.url)); }
            let mut say = |got: u64, total: Option<u64>| if !g.json {
                println!("{}", ui::sub(&match total {
                    Some(t) if t > 0 => format!("{} of {} ({}%)", human(got as usize), human(t as usize), got * 100 / t),
                    _ => format!("{} so far", human(got as usize)),
                }));
            };
            let r = fetch_artifact(&n.url, &mut say).map_err(|e| e.summary())
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
    if g.json {
        println!("{}", json!({"status": if failed.is_empty() { "ok" } else { "failed" },
            "cache": dir.display().to_string(), "staged": staged, "skipped": skipped, "failed": failed}));
    } else {
        println!();
        if failed.is_empty() {
            ui::close_done(&format!("{} artefact(s) staged in {}", staged.len(), dir.display()));
            let cmds: Vec<String> = restage.iter().map(|n| format!("noo cluster provision {n}")).collect();
            let mut guide: Vec<(&str, &str)> = cmds.iter().map(|c| (c.as_str(), "restage it so its bundle carries the staged CLIs")).collect();
            if guide.is_empty() {
                guide.push(("noo cluster provision <node>", "restage a node whose harness placement or vendor_kinds names the kind"));
            }
            guide.push(("noo cluster vendor status", "which nodes need which artefact, and whether it is staged"));
            ui::guide(&guide);
        } else {
            ui::close_failed(&format!("{} artefact(s) not staged; nothing unverified was written", failed.len()),
                Some("noo cluster vendor status"));
        }
    }
    Ok(if failed.is_empty() { 0 } else { 1 })
}

/// A vendor CLI is 150–250 MB, so the release fetch's whole-call cap
/// (120s) refuses one on a slow link, four times over. A vendor download
/// instead fails when no byte arrives for [`STALL`]: a dead socket ends,
/// a slow one finishes. [`CEILING`] still ends a trickle.
const STALL: Duration = Duration::from_secs(60);
const CEILING: Duration = Duration::from_secs(60 * 60);
/// How often a running download says how far it has got.
const PROGRESS_EVERY: Duration = Duration::from_secs(30);

fn vendor_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(STALL))
        .timeout_global(Some(CEILING))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Fetch one vendor artefact (no token: vendors publish them openly),
/// retried like a release asset, each attempt under the stall watch.
fn fetch_artifact(url: &str, say: &mut dyn FnMut(u64, Option<u64>)) -> Result<Vec<u8>, FetchError> {
    release_fetch::with_retry(&release_fetch::DEFAULT_RETRY, &mut release_fetch::real_sleep, || {
        let u = url.to_string();
        watched(url, STALL, PROGRESS_EVERY, move |seen: &mut dyn FnMut(u64, Option<u64>) -> bool| {
            release_fetch::get_once_watched(&vendor_agent(), &u, None, seen)
        }, say)
    })
}

/// Run `work` on its own thread and watch the bytes it reports: a gap of
/// `stall` with no new byte is a `Network` failure (retried), and every
/// `every` `say` hears how far it has got. A stalled worker is told to stop
/// at its next chunk, so a retry does not race it for the link.
fn watched(
    url: &str,
    stall: Duration,
    every: Duration,
    work: impl FnOnce(&mut dyn FnMut(u64, Option<u64>) -> bool) -> Result<Vec<u8>, FetchError> + Send + 'static,
    say: &mut dyn FnMut(u64, Option<u64>),
) -> Result<Vec<u8>, FetchError> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};
    let got = Arc::new(AtomicU64::new(0));
    let total = Arc::new(AtomicU64::new(u64::MAX));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    {
        let (got, total, stop) = (got.clone(), total.clone(), stop.clone());
        std::thread::spawn(move || {
            let r = work(&mut |n, t| {
                got.store(n, Ordering::Relaxed);
                total.store(t.unwrap_or(u64::MAX), Ordering::Relaxed);
                !stop.load(Ordering::Relaxed)
            });
            let _ = tx.send(r);
        });
    }
    let tick = (stall / 10).min(Duration::from_secs(1));
    let (mut last, mut moved, mut said) = (0u64, Instant::now(), Instant::now());
    loop {
        match rx.recv_timeout(tick) {
            Ok(r) => return r,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(FetchError::new(FetchClass::Other, format!("GET {url}: the download ended without a result")))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let n = got.load(Ordering::Relaxed);
        if n != last {
            (last, moved) = (n, Instant::now());
        } else if moved.elapsed() >= stall {
            stop.store(true, Ordering::Relaxed);
            return Err(FetchError::new(FetchClass::Network, format!(
                "GET {url}: stalled, no data for {}s after {}", stall.as_secs(), human(n as usize))));
        }
        if said.elapsed() >= every {
            said = Instant::now();
            let t = total.load(Ordering::Relaxed);
            say(n, (t != u64::MAX).then_some(t));
        }
    }
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

/// One node's line in `status` over every kind its bundle carries
/// ([`bundle_vendor_kinds`]): the cells joined, whether all are ready, and
/// the kinds still to stage.
pub(crate) fn node_carry_cell(
    table: &Table,
    placed: Option<&str>,
    vendor_kinds: &[String],
    platform: Option<(&str, &str)>,
    staged: &dyn Fn(&Need) -> bool,
) -> (String, bool, Vec<String>) {
    let kinds = bundle_vendor_kinds(placed, vendor_kinds);
    if kinds.is_empty() {
        let (c, ok) = node_need_cell(table, placed, platform, staged);
        return (c, ok, Vec::new());
    }
    let mut cells = Vec::new();
    let mut pending = Vec::new();
    for k in &kinds {
        let (c, ok) = node_need_cell(table, Some(k), platform, staged);
        if !ok {
            pending.push(k.clone());
        }
        cells.push(c);
    }
    (cells.join("; "), pending.is_empty(), pending)
}

/// The `vendor_kinds` cell: the list, or a dash for none.
fn vendor_kinds_cell(kinds: &[String]) -> String {
    if kinds.is_empty() { ui::dash().to_string() } else { kinds.join(", ") }
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
        let extra = desired.as_ref().map(node_vendor_kinds).unwrap_or_default();
        let plat = node_platform(n);
        let (cell, ok, pending) = node_carry_cell(&table, kind.as_deref(), &extra, plat, &staged_fn);
        need_stage.extend(pending);
        node_rows.push(vec![
            id.to_string(),
            plat.map(|(o, a)| format!("{o}-{a}")).unwrap_or_else(|| "?".into()),
            kind.clone().unwrap_or_else(|| ui::dash().to_string()),
            vendor_kinds_cell(&extra),
            cell.clone(),
        ]);
        node_json.push(json!({"node": id, "kind": kind, "vendor_kinds": extra,
            "carries": bundle_vendor_kinds(kind.as_deref(), &extra),
            "platform": plat.map(|(o, a)| format!("{o}-{a}")), "needs": cell, "ready": ok}));
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
        print!("{}", ui::table(&[Col::left("node"), Col::left("platform"), Col::left("placed kind"), Col::left("vendor_kinds"), Col::left("bundle carries")], &node_rows));
    }
    let mut guide: Vec<(&str, &str)> = Vec::new();
    if !need_stage.is_empty() {
        guide.push(("noo cluster vendor stage", "fetch and verify what the nodes still need"));
    }
    guide.push(("noo cluster provision <node>", "restage a node so its bundle carries the staged CLI"));
    guide.push(("noo cluster vendor install <node> <kind>...", "carry a CLI whatever the node's placement names"));
    ui::guide(&guide);
    Ok(0)
}

/// `--vendor-kinds` / `vendor install` values: `none` (clears), else kind
/// names, comma-separated. Each must be a kind in the table that runs a
/// vendor CLI; `noo` runs none. Deduplicated, in name order.
pub(crate) fn parse_vendor_kinds(v: &str, table: &Table) -> Result<Vec<String>, String> {
    if v.trim() == "none" {
        return Ok(Vec::new());
    }
    let vendor: Vec<&str> = table.kinds.iter().filter(|k| k.cli.is_some()).map(|k| k.kind.as_str()).collect();
    let mut out = BTreeSet::new();
    for k in v.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        if !vendor.contains(&k) {
            return Err(format!(
                "'{k}' is not a harness kind that runs a vendor CLI (one of {}, or `none`)",
                vendor.join(", ")
            ));
        }
        out.insert(k.to_string());
    }
    if out.is_empty() {
        return Err("name at least one kind, or `none`".into());
    }
    Ok(out.into_iter().collect())
}

/// `noo cluster vendor install <node> <kind>...` — add kinds to the node's
/// `vendor_kinds` (what is already there stays), so its bundle carries those
/// CLIs whatever its harness placement names. It only records the wish: the
/// CLI lands on the node with the next restage, which this verb does NOT
/// run (a restage is the operator's call).
pub fn cluster_vendor_install(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let [node, kinds @ ..] = args else { return Err(Unhandled) };
    if node.starts_with('-') || kinds.is_empty() || kinds.iter().any(|k| k.starts_with('-')) {
        return Err(Unhandled);
    }
    let table = harness_kinds::shipped();
    let asked = match parse_vendor_kinds(&kinds.join(","), &table) {
        Ok(k) if !k.is_empty() => k,
        Ok(_) => fail(g.json, ExitCode::Usage, "bad_vendor_kinds", "`none` clears: use `noo cluster set-config <node> --vendor-kinds none`", None),
        Err(e) => fail(g.json, ExitCode::Usage, "bad_vendor_kinds", &e, None),
    };
    let path = format!("/api/cluster/nodes/{}/desired-config", super::urlencode(node));
    let before = node_vendor_kinds(&crate::http::get_json(g, &path, true, 10));
    let after: Vec<String> = before.iter().chain(asked.iter()).cloned().collect::<BTreeSet<String>>().into_iter().collect();
    let resp = crate::http::put_json(
        g,
        &format!("/api/cluster/nodes/{}/config", super::urlencode(node)),
        &json!({"vendor_kinds": after}),
        true,
        10,
    );
    let stage = vec!["noo cluster vendor stage".to_string()];
    let restage = format!("noo cluster provision {node}");
    if g.json {
        let mut next = stage.clone();
        next.push(restage);
        println!("{}", json!({"status": "ok", "node": node, "vendor_kinds": after, "was": before, "next": next, "gateway": resp}));
        return Ok(0);
    }
    ui::done(&format!("{node}: vendor_kinds = {} (was: {})", vendor_kinds_cell(&after), vendor_kinds_cell(&before)));
    println!("{}", ui::muted("recorded only: nothing reaches the node until it is restaged"));
    let mut guide: Vec<(&str, &str)> = stage.iter().map(|c| (c.as_str(), "fetch and verify what the nodes need on this controller (a no-op when already staged)")).collect();
    guide.push((restage.as_str(), "restage the node so its bundle carries the CLIs"));
    guide.push(("noo cluster vendor status", "what each node carries, and what is still to stage"));
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
        Some("stage [<kind> [--fleet]|--all] [--os linux|macos] [--arch x86_64|aarch64]   fetch and verify the vendor CLIs the nodes need on the controller; status   what is staged and who needs it; install <node> <kind>...   carry CLIs on a node whatever its placement names"),
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
    fn a_download_that_stops_sending_fails_as_stalled_and_is_told_to_stop() {
        let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s2 = stopped.clone();
        let e = watched("https://example.invalid/x.tgz", Duration::from_millis(300), Duration::from_secs(60), move |seen| {
            seen(10, Some(100));
            std::thread::sleep(Duration::from_millis(900));
            s2.store(!seen(11, Some(100)), std::sync::atomic::Ordering::SeqCst);
            Ok(vec![])
        }, &mut |_, _| {}).unwrap_err();
        assert_eq!(e.class, FetchClass::Network, "a stall is retried like any network failure");
        assert!(e.detail.contains("stalled") && e.detail.contains("example.invalid"), "{}", e.detail);
        std::thread::sleep(Duration::from_millis(900));
        assert!(stopped.load(std::sync::atomic::Ordering::SeqCst), "the stalled worker must be told to stop");
    }

    #[test]
    fn a_slow_download_that_keeps_moving_finishes_and_reports_progress() {
        let mut heard = Vec::new();
        let r = watched("https://example.invalid/x.tgz", Duration::from_millis(400), Duration::from_millis(150), |seen| {
            for i in 1..=10u64 {
                std::thread::sleep(Duration::from_millis(100));
                assert!(seen(i * 10, Some(100)));
            }
            Ok(vec![7; 100])
        }, &mut |got, total| heard.push((got, total))).unwrap();
        assert_eq!(r.len(), 100, "1s in all, well past the 400ms stall bound, yet never 400ms without a byte");
        assert!(!heard.is_empty() && heard.iter().all(|&(g, t)| g > 0 && t == Some(100)), "{heard:?}");
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
        let f = vendor_bundle_files(&t(), &ks(&["copilot"]), "linux", "x86_64", &all_staged).unwrap();
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
        let f = vendor_bundle_files(&t(), &ks(&["codex"]), "macos", "aarch64", &all_staged).unwrap();
        assert_eq!(f.iter().map(|(k, _)| *k).collect::<Vec<_>>(), ["vendor-cli", "vendor-cli-manifest"]);
        let m: Value = serde_json::from_slice(&f[1].1).unwrap();
        assert_eq!(m["format"], "binary");
        assert_eq!(m["unpack"], "none");
    }

    #[test]
    fn nothing_to_carry_for_noo_manual_or_no_placement() {
        for k in [None, Some("noo"), Some("manual")] {
            let kinds = bundle_vendor_kinds(k, &[]);
            assert!(vendor_bundle_files(&t(), &kinds, "linux", "x86_64", &all_staged).unwrap().is_empty(), "{k:?}");
        }
    }

    #[test]
    fn an_unstaged_artefact_refuses_the_restage_and_names_the_stage_command() {
        let none = |_: &Need| None;
        let e = vendor_bundle_files(&t(), &ks(&["copilot"]), "linux", "x86_64", &none).unwrap_err();
        assert!(e.contains("run `noo cluster vendor stage copilot` first") && e.contains("copilot 0.0.339"), "{e}");
        let e = vendor_bundle_files(&t(), &ks(&["codex"]), "linux", "aarch64", &all_staged).unwrap_err();
        assert!(e.contains("cannot be staged for linux/aarch64"), "{e}");
        // Two kinds unstaged: ONE refusal names both stage commands.
        let e = vendor_bundle_files(&t(), &ks(&["codex", "copilot"]), "linux", "x86_64", &none).unwrap_err();
        assert!(e.contains("vendor stage codex") && e.contains("vendor stage copilot"), "{e}");
    }

    fn ks(k: &[&str]) -> Vec<String> {
        k.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_bundle_carries_the_placed_kind_and_the_vendor_kinds_once_each() {
        // Union, dedup, name order; noo never needs a CLI.
        assert_eq!(bundle_vendor_kinds(Some("copilot"), &ks(&["codex", "copilot"])), ["codex", "copilot"]);
        assert_eq!(bundle_vendor_kinds(Some("noo"), &ks(&["copilot"])), ["copilot"]);
        assert_eq!(bundle_vendor_kinds(Some("noo"), &[]), Vec::<String>::new());
        assert_eq!(bundle_vendor_kinds(None, &ks(&[" codex ", "noo", ""])), ["codex"]);
        assert_eq!(bundle_vendor_kinds(Some("copilot"), &[]), ["copilot"]);
        // The placement moving between kinds keeps each CLI in its slot.
        assert_eq!(bundle_vendor_kinds(Some("codex"), &ks(&["codex", "copilot"])),
                   bundle_vendor_kinds(Some("copilot"), &ks(&["codex", "copilot"])));
        let d = json!({"node": {"vendor_kinds": ["copilot", " ", "codex"]}});
        assert_eq!(node_vendor_kinds(&d), ["copilot", "codex"]);
        assert!(node_vendor_kinds(&json!({"node": {}})).is_empty(), "an older gateway sends none");
    }

    #[test]
    fn two_clis_ride_in_two_slots_each_with_its_own_manifest() {
        let f = vendor_bundle_files(&t(), &ks(&["codex", "copilot", "manual"]), "linux", "x86_64", &all_staged).unwrap();
        let names: Vec<&str> = f.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, ["vendor-cli", "vendor-cli-manifest", "vendor-cli-2", "vendor-cli-2-manifest"], "manual carries nothing");
        let m1: Value = serde_json::from_slice(&f[1].1).unwrap();
        let m2: Value = serde_json::from_slice(&f[3].1).unwrap();
        assert_eq!((m1["kind"].as_str(), m2["kind"].as_str()), (Some("codex"), Some("copilot")));
        assert_eq!(f[2].1, b"bytes-of-copilot-0.0.339-any.tgz");
        // Slot 1 alone is the layout every applier since E1e reads.
        assert_eq!(VENDOR_SLOTS[0], ("vendor-cli", "vendor-cli-manifest"));
        for (p, m) in VENDOR_SLOTS {
            assert_eq!(m, format!("{p}-manifest"), "the appliers find a slot's manifest as <slot>-manifest");
        }
    }

    #[test]
    fn vendor_clis_past_the_bundle_budget_are_refused() {
        let half = VENDOR_BUNDLE_BUDGET_MB * 1024 * 1024 / 2 + 1;
        let e = budget_refusal(&[("codex", half), ("copilot", half)]).unwrap();
        assert!(e.contains("drop one from its vendor_kinds") && e.contains("codex, copilot"), "{e}");
        assert!(budget_refusal(&[("codex", half)]).is_none());
        assert!(budget_refusal(&[]).is_none());
    }

    #[test]
    fn the_mac_slot_floor_keeps_older_macs_on_one_cli() {
        assert!(applier_knows_vendor_slots(false, "noo-cli-v0.6.5"));
        assert!(!applier_knows_vendor_slots(true, "noo-cli-v0.6.7+abc"));
        assert!(applier_knows_vendor_slots(true, "noo-cli-v0.6.8"));
        assert!(applier_knows_vendor_slots(true, ""), "unknown version: assume it can");
    }

    #[test]
    fn vendor_kinds_values_name_vendor_kinds_or_none() {
        let t = t();
        assert_eq!(parse_vendor_kinds("copilot,codex,copilot", &t).unwrap(), ["codex", "copilot"]);
        assert_eq!(parse_vendor_kinds(" codex ", &t).unwrap(), ["codex"]);
        assert!(parse_vendor_kinds("none", &t).unwrap().is_empty());
        assert!(parse_vendor_kinds("noo", &t).unwrap_err().contains("not a harness kind that runs a vendor CLI"));
        assert!(parse_vendor_kinds("nope", &t).is_err());
        assert!(parse_vendor_kinds(",", &t).is_err());
        // A manual install is still a vendor kind: recorded, carried as nothing.
        assert_eq!(parse_vendor_kinds("manual", &t).unwrap(), ["manual"]);
    }

    #[test]
    fn a_node_line_covers_every_kind_it_carries() {
        let t = t();
        let only = |n: &Need| n.name == "copilot";
        let (c, ok, pending) = node_carry_cell(&t, Some("copilot"), &ks(&["codex"]), Some(("linux", "x86_64")), &only);
        assert!(!ok && pending == ["codex"], "{c}");
        assert!(c.contains("codex: ") && c.contains("copilot: copilot 0.0.339 — Ready"), "{c}");
        let (c, ok, pending) = node_carry_cell(&t, None, &[], None, &only);
        assert!(ok && pending.is_empty() && c == "no harness placement", "{c}");
        let (c, ok, _) = node_carry_cell(&t, Some("noo"), &[], Some(("linux", "x86_64")), &only);
        assert!(ok && c == "noo: nothing to stage", "{c}");
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
    fn stage_args_take_nothing_one_kind_or_all() {
        let s = |v: &[&str]| parse_stage_args(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        assert_eq!(s(&[]).unwrap(), StageArgs::default());
        assert_eq!(s(&["copilot"]).unwrap().kind.as_deref(), Some("copilot"));
        assert!(s(&["copilot", "--fleet"]).unwrap().fleet);
        assert!(s(&["--all", "--os", "linux", "--arch", "aarch64"]).unwrap().all);
        assert_eq!(s(&["--os", "macos"]).unwrap().os.as_deref(), Some("macos"));
        assert!(s(&["copilot", "--all"]).is_err() && s(&["a", "b"]).is_err() && s(&["--fleet"]).is_err());
        assert!(s(&["--all", "--os", "windows"]).is_err() && s(&["--all", "--arch", "arm64"]).is_err());
    }

    #[test]
    fn stage_fetches_what_the_nodes_carry_on_their_own_platform() {
        let n = |id: &str, p: Option<(&'static str, &'static str)>, k: &[&str]| NodeCarry {
            id: id.into(), platform: p, kinds: k.iter().map(|x| x.to_string()).collect(),
        };
        let nodes = [
            n("awolf", Some(("linux", "x86_64")), &["claude-code", "codex"]),
            n("pop-os", Some(("linux", "x86_64")), &["codex"]),
            n("mcmini", Some(("macos", "aarch64")), &["codex"]),
            n("robopi", Some(("linux", "aarch64")), &[]),
            n("nowhere", None, &["codex"]),
        ];
        let t = needed_targets(&nodes, None, None, None);
        let keys: Vec<_> = t.keys().map(|(k, o, a)| format!("{k}/{o}-{a}")).collect();
        // robopi carries nothing, so no linux-aarch64 build is fetched.
        assert_eq!(keys, ["claude-code/linux-x86_64", "codex/linux-x86_64", "codex/macos-aarch64"]);
        assert_eq!(t[&("codex".to_string(), "linux", "x86_64")], ["awolf", "pop-os"]);
        let t = needed_targets(&nodes, Some("codex"), Some("macos"), None);
        assert_eq!(t.into_values().collect::<Vec<_>>(), [vec!["mcmini".to_string()]]);
        assert!(needed_targets(&nodes, Some("copilot"), None, None).is_empty());
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
