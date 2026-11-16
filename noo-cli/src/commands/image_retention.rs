// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Image retention on the controller: which images must stay, written as the
//! keep file hostd's reclaim rung 5 reads (node-agent-go/internal/hostd/
//! image_retention.go), and the previous locks kept for rollback.
//!
//! Every stack image is pulled BY DIGEST, so a superseded one is never
//! "dangling" and every release a controller ever pulled stays (pop-os,
//! 2026-11-13: ~58 GB in the first 60 lines of `docker system df -v`). The
//! keep file names what may NOT go, by exact `repo@sha256:` digest or image
//! ID, never by name pattern:
//!
//! * every row of `stack.lock` (current) and `stack.lock.prev` (previous, for
//!   a rollback that needs no pull);
//! * every image of every pin in `addons.lock` and `addons.lock.prev`, as
//!   docker holds it ([`Pin::local_ref`]). A pin stays in addons.lock when its
//!   add-on is switched off, so a disabled add-on's last pin is kept;
//!   `noo addons remove` is what drops it;
//! * every image ID the artifact rail staged (`staged-images.json`).
//!
//! The namespaces that make an image OURS are the registry roots our images
//! are pulled from ([`crate::registry::rail_roots`]) and, for each pinned
//! add-on image, that image's OWN repository and nothing wider: an add-on
//! pinned at `docker.io/library/redis@sha256:…` must not make every
//! `docker.io/library/*` image the operator pulled look like ours. Local
//! builds and anything else are never named, so hostd never treats them as
//! ours.
//!
//! Docker Hub is never cleaned: Docker reports its images by short name
//! (`redis:7`, `postgres:16`), and hostd matches a namespace only against a
//! registry host, so a short name is never ours and is always kept. An
//! add-on pinned on Docker Hub keeps its superseded images; the operator
//! removes them by hand.
//!
//! A lock names an image by its manifest DIGEST, under whatever name the
//! release wrote (`gateway@sha256:…`): the same digest is held locally as
//! `ghcr.io/noomesh/gateway@sha256:…`, as `ghcr.io/noomesh/dhi/alertmanager@…`
//! (the base images), as a Docker Hub short name (`nats@sha256:…`) or under
//! a mirror prefix. So every lock row is resolved BY DIGEST against the
//! images docker holds ([`holding`]), never by name, and kept by the image
//! ID that holds it. A Docker Hub image a lock pins is therefore kept like
//! any other, although hostd never treats a Hub short name as ours to
//! delete. A row no local image holds (a node-only image on a controller,
//! another platform's) protects nothing on this host: it stays in the keep
//! file under the lock's own name, inert, and says so.
//!
//! The keep file proves it is current by naming its sources with their
//! SHA-256: hostd re-hashes them, and a lock that moved since makes it stale,
//! which skips the rung.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::addons::pins::{self, Pins};

pub(crate) const KEEP_FILE: &str = "image-keep.json";
pub(crate) const REPORT_FILE: &str = "image-retention-report.json";
pub(crate) const STACK_LOCK: &str = "stack.lock";
pub(crate) const PREV_SUFFIX: &str = ".prev";

/// THE default for the step at the end of a successful roll, once the first
/// roll that carries image retention has shown its preview: `true` removes
/// the superseded images that are provably ours, `false` keeps previewing.
/// One constant, so the operator's decision is one line.
pub(crate) const POST_ROLL_DEFAULT_LIVE: bool = true;

/// The marker that the one-time preview ran (its content: the tag).
pub(crate) const PREVIEWED_MARKER: &str = ".noo-image-retention-previewed";

fn is_digest_ref(r: &str) -> bool {
    match r.split_once("@sha256:") {
        Some((name, hex)) => !name.is_empty() && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        None => false,
    }
}

/// The `name@sha256:<64 hex>` rows of a stack lock (comments skipped).
pub(crate) fn stack_lock_refs(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter(|l| is_digest_ref(l))
        .map(str::to_string)
        .collect()
}

/// One image docker holds: its ID and every name it goes by (RepoTags and
/// RepoDigests; the containerd store lists a digest pull among the tags too).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalImage {
    pub id: String,
    pub refs: Vec<String>,
}

/// `docker image inspect --format` for [`parse_local_images`]. JSON lists,
/// because `{{join .RepoTags ","}}` fails on the Docker 27 and 28 CLIs.
pub(crate) const LOCAL_IMAGE_FORMAT: &str = "{{.Id}}|{{json .RepoTags}}|{{json .RepoDigests}}";

/// Lines of [`LOCAL_IMAGE_FORMAT`] (a trailing `|<size>` field is ignored).
/// A line that does not parse is no image, never a guess.
pub(crate) fn parse_local_images(out: &str) -> Vec<LocalImage> {
    out.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.trim().split('|').collect();
            let id = *p.first()?;
            if p.len() < 3 || !(id.len() == 71 && id.starts_with("sha256:")) {
                return None;
            }
            let list = |s: &str| serde_json::from_str::<Option<Vec<String>>>(s).ok().map(Option::unwrap_or_default);
            let refs = list(p[1])?.into_iter().chain(list(p[2])?).filter(|r| !r.contains("<none>")).collect();
            Some(LocalImage { id: id.to_string(), refs })
        })
        .collect()
}

/// The 64-hex digest of a `name@sha256:<hex>` ref.
pub(crate) fn digest_hex(r: &str) -> Option<&str> {
    let (_, hex) = r.split_once("@sha256:")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

/// The local images that hold `reference`'s digest, under ANY name.
pub(crate) fn holding<'a>(reference: &str, local: &'a [LocalImage]) -> Vec<&'a LocalImage> {
    let Some(hex) = digest_hex(reference) else { return Vec::new() };
    let tail = format!("@sha256:{hex}");
    local.iter().filter(|i| i.refs.iter().any(|r| r.ends_with(&tail))).collect()
}

/// Every image docker holds. `Err` carries Docker's own words.
pub(crate) fn local_images() -> Result<Vec<LocalImage>, String> {
    let run = |args: &[&str]| -> Result<String, String> {
        let o = std::process::Command::new("docker")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("docker: {e}"))?;
        if o.status.success() {
            Ok(String::from_utf8_lossy(&o.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("docker failed").to_string())
        }
    };
    let ids = run(&["image", "ls", "-aq", "--no-trunc"])?;
    let mut ids: Vec<&str> = ids.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec!["image", "inspect", "--format", LOCAL_IMAGE_FORMAT];
    args.extend(ids);
    Ok(parse_local_images(&run(&args)?))
}

/// The images docker listed, or why no keep file can be written. A listing
/// that failed proves nothing about what to keep: the keep file is refused,
/// so no keep file is written and the post-roll step removes nothing (hostd's
/// rung needs one). Never an empty list in its place, which would keep each
/// lock row only under its own name and, with a store that lists, leave the
/// previous release's images unnamed (the rc.1 defect, #1219).
pub(crate) fn listed_or_refused(listed: Result<Vec<LocalImage>, String>) -> Result<Vec<LocalImage>, String> {
    listed.map_err(|e| format!("docker did not list the images ({e}): nothing proves what to keep, so nothing is removed"))
}

/// The `# stack <tag>` header of a stack lock (the release writes it).
pub(crate) fn stack_lock_tag(text: &str) -> Option<String> {
    text.lines().find_map(|l| l.trim().strip_prefix("# stack ").map(|t| t.trim().to_string()))
}

/// `ghcr.io/example-vendor/exaddon@sha256:…` -> `ghcr.io/example-vendor/exaddon/`:
/// the namespace a pinned image claims is its own repository, never the
/// vendor's (or Docker Hub's `library/`) whole path.
pub(crate) fn namespace_of(reference: &str) -> Option<String> {
    let name = reference.split('@').next()?;
    let (host, _) = name.split_once('/')?;
    // A namespace must name a registry host: `x/y` alone is a Docker Hub
    // short name, which this never claims.
    (host.contains('.') || host.starts_with("localhost")).then(|| format!("{name}/"))
}

/// What the keep file is built from, read from the install root.
pub(crate) struct KeepInputs {
    pub stack: Option<(PathBuf, Vec<u8>)>,
    pub stack_prev: Option<(PathBuf, Vec<u8>)>,
    pub pins: Option<(PathBuf, Vec<u8>, Pins)>,
    pub pins_prev: Option<(PathBuf, Vec<u8>, Pins)>,
    pub staged: Option<(PathBuf, Vec<u8>, Vec<String>)>,
    pub roots: Vec<String>,
    /// What docker holds, to resolve each lock row by digest.
    pub local: Vec<LocalImage>,
}

fn read_opt(p: PathBuf) -> Option<(PathBuf, Vec<u8>)> {
    std::fs::read(&p).ok().map(|b| (p, b))
}

impl KeepInputs {
    pub(crate) fn read(root: &Path) -> Result<Self, String> {
        let pins_file = pins::pins_path(root);
        let parse_pins = |(p, b): (PathBuf, Vec<u8>)| -> Result<(PathBuf, Vec<u8>, Pins), String> {
            let v: Pins = serde_json::from_slice(&b).map_err(|e| format!("{} is not a pins file: {e}", p.display()))?;
            Ok((p, b, v))
        };
        let staged_dir = crate::commands::image_stage::images_store_dir();
        let staged = read_opt(staged_dir.join(crate::commands::image_stage::STAGED_INDEX)).map(|(p, b)| {
            let ids = serde_json::from_slice::<Value>(&b)
                .ok()
                .and_then(|v| v["images"].as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|i| i["image_id"].as_str().map(str::to_string))
                .filter(|id| id.starts_with("sha256:") && id.len() == 71)
                .collect();
            (p, b, ids)
        });
        Ok(KeepInputs {
            stack: read_opt(root.join(STACK_LOCK)),
            stack_prev: read_opt(root.join(format!("{STACK_LOCK}{PREV_SUFFIX}"))),
            pins: read_opt(pins_file.clone()).map(parse_pins).transpose()?,
            pins_prev: read_opt(PathBuf::from(format!("{}{PREV_SUFFIX}", pins_file.display()))).map(parse_pins).transpose()?,
            staged,
            roots: crate::registry::rail_roots().iter().map(|s| s.to_string()).collect(),
            // Fail closed: without the local images no row can be kept by
            // the ID that holds it, so no keep file is written.
            local: listed_or_refused(local_images())?,
        })
    }
}

/// The keep file, pure over its inputs. `Err` when there is nothing to
/// prove the stack's own images by (no stack.lock): then no keep file is
/// written and hostd's rung skips.
pub(crate) fn keep_file(inp: &KeepInputs, now_rfc3339: &str) -> Result<Value, String> {
    let Some((stack_path, stack_bytes)) = &inp.stack else {
        return Err("no stack.lock in the install root: nothing proves which images the stack runs".into());
    };
    let mut keep: Vec<Value> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut namespaces: BTreeSet<String> = inp
        .roots
        .iter()
        .map(|r| if r.ends_with('/') { r.clone() } else { format!("{r}/") })
        .collect();
    let mut sources = vec![json!({"path": stack_path.display().to_string(), "sha256": pins::sha256_hex(stack_bytes)})];
    // Each lock row: its own ref, and the ID of every local image holding
    // its digest under any name. Kept by ID, so the name docker uses for it
    // (ghcr.io/noomesh/…, …/dhi/…, a Docker Hub short name, a mirror) never
    // matters.
    let local = &inp.local;
    let mut add = |reference: String, why: String, keep: &mut Vec<Value>| {
        let held = holding(&reference, local);
        let why = if held.is_empty() { format!("{why}; not on this host") } else { why };
        if seen.insert(reference.clone()) {
            keep.push(json!({"ref": reference, "why": why}));
        }
        for im in held {
            if seen.insert(im.id.clone()) {
                keep.push(json!({"id": im.id, "why": format!("{why}: holds {reference}")}));
            }
        }
    };
    let text = String::from_utf8_lossy(stack_bytes);
    let tag = stack_lock_tag(&text).unwrap_or_else(|| "?".into());
    for r in stack_lock_refs(&text) {
        add(r, format!("stack.lock ({tag})"), &mut keep);
    }
    if let Some((p, b)) = &inp.stack_prev {
        let text = String::from_utf8_lossy(b);
        let tag = stack_lock_tag(&text).unwrap_or_else(|| "?".into());
        for r in stack_lock_refs(&text) {
            add(r, format!("stack.lock.prev ({tag}, for rollback)"), &mut keep);
        }
        sources.push(json!({"path": p.display().to_string(), "sha256": pins::sha256_hex(b)}));
    }
    for (pins, label) in [(&inp.pins, "addons.lock"), (&inp.pins_prev, "addons.lock.prev")] {
        if let Some((p, b, v)) = pins {
            for (addon, pin) in v {
                for (_, r) in pin.local_images() {
                    if !is_digest_ref(&r) {
                        continue;
                    }
                    if let Some(ns) = namespace_of(&r) {
                        namespaces.insert(ns);
                    }
                    add(r, format!("{label}: {addon} {} (pinned for {})", pin.version, pin.stack), &mut keep);
                }
            }
            sources.push(json!({"path": p.display().to_string(), "sha256": pins::sha256_hex(b)}));
        }
    }
    if let Some((p, b, ids)) = &inp.staged {
        for id in ids {
            if seen.insert(id.clone()) {
                keep.push(json!({"id": id, "why": "staged on the artifact rail for the nodes"}));
            }
        }
        sources.push(json!({"path": p.display().to_string(), "sha256": pins::sha256_hex(b)}));
    }
    if keep.is_empty() {
        return Err("stack.lock names no image digest: nothing proves which images the stack runs".into());
    }
    Ok(json!({
        "version": 1,
        "written_at": now_rfc3339,
        "sources": sources,
        "namespaces": namespaces.into_iter().collect::<Vec<_>>(),
        "keep": keep,
    }))
}

/// Where hostd reads it on a controller: the host spool beside the commands.
pub(crate) fn keep_path(root: &Path) -> PathBuf {
    root.join(".noo-host-spool").join(KEEP_FILE)
}

/// Write the keep file (atomically). `Err` says why none was written.
pub(crate) fn write_keep_file(root: &Path) -> Result<PathBuf, String> {
    let inp = KeepInputs::read(root)?;
    let now = crate::commands::secrets_reveal::now_rfc3339();
    let v = keep_file(&inp, &now)?;
    let p = keep_path(root);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&v).unwrap_or_default()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(p)
}

/// Keep the outgoing `stack.lock` / `addons.lock` as `<file>.prev` before a
/// roll to ANOTHER tag writes the new one (the caller checks the tag), so the
/// previous release's images are kept for a rollback that needs no pull.
/// Best effort: a missing file has nothing to keep.
pub(crate) fn keep_previous_file(path: &Path) {
    if path.is_file() {
        let _ = std::fs::copy(path, PathBuf::from(format!("{}{PREV_SUFFIX}", path.display())));
    }
}

/// How the post-roll step runs: the operator's `cluster.image_retention`
/// in noomesh.yaml (`off`, `preview`, `live`), else the one-time preview,
/// else [`POST_ROLL_DEFAULT_LIVE`]. Never an environment variable: a value
/// left in someone's shell or a unit file would silently change what a roll
/// deletes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    Preview,
    Live,
}

pub(crate) fn mode(setting: Option<&str>, previewed: bool) -> Mode {
    match setting.map(str::trim) {
        Some("off") => Mode::Off,
        Some("preview") => Mode::Preview,
        Some("live") => Mode::Live,
        _ if !previewed => Mode::Preview,
        _ if POST_ROLL_DEFAULT_LIVE => Mode::Live,
        _ => Mode::Preview,
    }
}

/// One summary line from hostd's report file.
pub(crate) fn summary(report: &Value, live: bool) -> String {
    let imgs = report["images"].as_array().cloned().unwrap_or_default();
    let gb = report["bytes"].as_i64().unwrap_or(0) as f64 / 1e9;
    let n_remove = imgs.iter().filter(|i| i["remove"].as_bool() == Some(true)).count();
    let kept = imgs.len() - n_remove;
    if live {
        let removed = imgs.iter().filter(|i| i["result"].as_str() == Some("removed")).count();
        let refused = imgs.iter().filter(|i| i["result"].as_str().is_some_and(|r| r.starts_with("refused"))).count();
        let mut s = format!("images: removed {removed} superseded image(s), {gb:.1} GB reclaimed; kept {kept}");
        if refused > 0 {
            s.push_str(&format!("; {refused} refused by docker (in use)"));
        }
        s
    } else {
        format!("images: would remove {n_remove} superseded image(s), {gb:.1} GB; kept {kept} (preview, nothing removed)")
    }
}

/// The operator's `cluster.image_retention` from `<root>/noomesh.yaml`
/// (`None` when unset or unreadable: the default applies).
pub(crate) fn setting(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("noomesh.yaml")).ok()?;
    setting_in(&text)
}

pub(crate) fn setting_in(yaml: &str) -> Option<String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    doc.get("cluster")?.get("image_retention")?.as_str().map(|s| s.trim().to_string())
}

/// How many images a report would or did remove.
fn removable(report: &Value) -> usize {
    report["images"].as_array().map(|a| a.iter().filter(|i| i["remove"].as_bool() == Some(true)).count()).unwrap_or(0)
}

fn spool_dir(root: &Path) -> PathBuf {
    root.join(".noo-host-spool")
}

fn hostd_up() -> bool {
    std::process::Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "noo-hostd"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Queue hostd's rung 5 alone and wait for its result (bounded).
fn run_rung(root: &Path, keep: &Path, live: bool) -> Result<Value, String> {
    use std::io::Write as _;
    let dir = spool_dir(root);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let name = format!("{nanos}-{:08x}", std::process::id());
    let payload = json!({
        "op": "disk-reclaim",
        "service": "docker",
        "health_check": false,
        "rollback": null,
        "args": [format!("dry_run={}", !live), "only=superseded-images", format!("keep={}", keep.display())],
        "requested_by": "cli:upgrade_post_roll",
        "ts": crate::commands::secrets_reveal::now_rfc3339(),
    });
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(payload.to_string().as_bytes()).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dir.join(format!("{name}.cmd.json"))).map_err(|e| e.to_string())?;
    let result = dir.join(format!("{name}.result.json"));
    for _ in 0..300 {
        if let Ok(b) = std::fs::read(&result) {
            let r: Value = serde_json::from_slice(&b).map_err(|e| format!("hostd's result is not JSON: {e}"))?;
            if r["ok"].as_bool() != Some(true) {
                return Err(format!("hostd: {}", r["stderr"].as_str().unwrap_or("failed")));
            }
            let rep = std::fs::read(keep.with_file_name(REPORT_FILE)).map_err(|e| format!("no report from hostd ({e}): {}", r["stderr"].as_str().unwrap_or("")))?;
            return serde_json::from_slice(&rep).map_err(|e| format!("hostd's report is not JSON: {e}"));
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err("hostd did not answer within 5 minutes; nothing is known to have been removed".into())
}

/// The step at the end of a successful roll: only after the controller's
/// verify passes, write the keep file and have hostd remove (or preview) the
/// superseded images that are provably ours. Never fails the roll; every
/// outcome is one line.
pub(crate) fn post_roll(g: &crate::Globals, root: &Path, tag: &str) {
    let set = setting(root);
    let previewed = root.join(PREVIEWED_MARKER).is_file();
    let mut host = LivePostRoll { g, root };
    post_roll_on(&mut host, set.as_deref(), previewed, tag);
}

/// Where the reason the last roll did not clean is kept, beside the keep
/// file, for the `image retention` verify row to show until a roll cleans.
pub(crate) const BLOCKED_FILE: &str = "image-retention-blocked.json";

/// The post-roll verify's JSON, `None` when it could not be run or read.
/// Its exit code is not the gate (see [`retention_gate`]).
pub(crate) fn verify_json(out: &std::io::Result<std::process::Output>) -> Option<Value> {
    out.as_ref().ok().and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok())
}

/// The gate: the rows that make "superseded" TRUE on this host, and only
/// those. Every stack container runs the image the lock pins (`stack
/// images`), every add-on pin verifies (`add-on pins`), and every enabled
/// add-on's containers run or are held by the launcher's own rule (`add-on
/// containers <a>`). Rows about anything else (certificates, backups, a GPU
/// hold, another node, default chat) never block: on the operator's fleet a
/// standing row of its own would otherwise mean cleanup never ran, silently.
/// Fail-closed: an unreadable verify, a required row missing, or a row in the
/// set at anything but `ok` blocks. `Err` names each blocking row.
pub(crate) fn retention_gate(v: Option<&Value>, addons_on: &[String]) -> Result<(), Vec<String>> {
    let Some(checks) = v.and_then(|v| v["controller"]["checks"].as_array()) else {
        return Err(vec!["the post-roll `noo cluster verify --controller` gave no readable result".into()]);
    };
    let name = |c: &Value| c["name"].as_str().unwrap_or("").to_string();
    let detail = |c: &Value| c["detail"].as_str().unwrap_or("").to_string();
    let in_set = |n: &str| n == "stack images" || n == "add-on pins" || n == "add-on containers";
    let mut blocked = Vec::new();
    if !checks.iter().any(|c| name(c) == "stack images") {
        blocked.push("stack images (not reported)".to_string());
    }
    if !addons_on.is_empty() && !checks.iter().any(|c| name(c) == "add-on pins") {
        blocked.push("add-on pins (not reported)".to_string());
    }
    for a in addons_on {
        let mine = format!("{a}:");
        if !checks.iter().any(|c| name(c) == "add-on containers" && detail(c).starts_with(&mine)) {
            blocked.push(format!("add-on containers {a} (not reported)"));
        }
    }
    for c in checks.iter().filter(|c| in_set(&name(c))) {
        if c["verdict"].as_str() != Some("ok") && !nothing_to_prove(c) {
            blocked.push(format!("{} ({})", name(c), detail(c)));
        }
    }
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(blocked)
    }
}

/// The one WARN in the set that does not block: an add-on whose overlay
/// declares no containers has nothing for `add-on containers` to prove
/// (`cluster_verify::addon_containers_row`'s exact wording); `add-on pins`
/// still covers its images. Any other WARN on that row still blocks.
fn nothing_to_prove(c: &Value) -> bool {
    c["name"] == "add-on containers"
        && c["verdict"] == "warn"
        && c["detail"].as_str().is_some_and(|d| d.ends_with(": declares no containers, so they aren't checked"))
}

/// The roll's line when the gate blocks: what blocked, and that it stays
/// visible.
pub(crate) fn blocked_line(rows: &[String]) -> String {
    format!(
        "images: superseded images were NOT cleaned up: blocked by {}. The `image retention` row of `noo cluster verify --controller` says so until a roll cleans",
        rows.join("; ")
    )
}

/// What the post-roll step does to the machine; [`post_roll_on`] holds every
/// decision, so a test drives it with a fake.
pub(crate) trait PostRollHost {
    /// The post-roll verify's JSON; `None` when it could not be run or read.
    fn verify(&mut self) -> Option<Value>;
    /// The enabled add-ons (the same list verify's add-on rows come from).
    fn addons_on(&mut self) -> Result<Vec<String>, String>;
    fn record_blocked(&mut self, tag: &str, rows: &[String]);
    fn clear_blocked(&mut self);
    fn write_keep(&mut self) -> Result<PathBuf, String>;
    fn hostd_up(&mut self) -> bool;
    fn run_rung(&mut self, keep: &Path, live: bool) -> Result<Value, String>;
    fn mark_previewed(&mut self, tag: &str);
    fn say(&mut self, line: &str);
}

/// The post-roll step's decisions, against any [`PostRollHost`].
pub(crate) fn post_roll_on(h: &mut impl PostRollHost, set: Option<&str>, previewed: bool, tag: &str) {
    let m = mode(set, previewed);
    if m == Mode::Off {
        return h.say("images: superseded-image cleanup is off (cluster.image_retention: off in noomesh.yaml)");
    }
    let addons = match h.addons_on() {
        Ok(a) => a,
        Err(e) => {
            let rows = vec![format!("which add-ons are on is unknown ({e})")];
            h.record_blocked(tag, &rows);
            return h.say(&blocked_line(&rows));
        }
    };
    if let Err(rows) = retention_gate(h.verify().as_ref(), &addons) {
        h.record_blocked(tag, &rows);
        return h.say(&blocked_line(&rows));
    }
    h.clear_blocked();
    let keep = match h.write_keep() {
        Ok(p) => p,
        Err(e) => return h.say(&format!("images: not cleaned up: {e}")),
    };
    if !h.hostd_up() {
        return h.say("images: not cleaned up: noo-hostd is not running (noo onboard --only services installs it)");
    }
    let live = m == Mode::Live;
    match h.run_rung(&keep, live) {
        Ok(rep) => {
            // Nothing superseded (a fresh install, or nothing left since the
            // last roll): say nothing, so a roll is not noisy, and do not
            // spend the one-time preview on an empty list.
            if removable(&rep) == 0 {
                return;
            }
            h.say(&summary(&rep, live));
            if !live && !previewed && set.is_none() {
                h.mark_previewed(tag);
                if POST_ROLL_DEFAULT_LIVE {
                    h.say(&format!("images: from the next roll these are removed (each one is listed in {}); `cluster.image_retention: preview` in noomesh.yaml keeps previewing, `off` stops it", keep.with_file_name(REPORT_FILE).display()));
                }
            }
        }
        Err(e) => h.say(&format!("images: not cleaned up: {e}")),
    }
}

struct LivePostRoll<'a> {
    g: &'a crate::Globals,
    root: &'a Path,
}

impl PostRollHost for LivePostRoll<'_> {
    fn verify(&mut self) -> Option<Value> {
        let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "noo".into());
        let out = std::process::Command::new(&exe)
            .args(["--json", "cluster", "verify", "--controller", "--wait"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        verify_json(&out)
    }
    fn addons_on(&mut self) -> Result<Vec<String>, String> {
        crate::addons::licensed_on(self.root).map(|v| v.into_iter().map(str::to_string).collect())
    }
    fn record_blocked(&mut self, tag: &str, rows: &[String]) {
        let b = json!({"at": crate::commands::secrets_reveal::now_rfc3339(), "tag": tag, "rows": rows});
        let _ = std::fs::write(spool_dir(self.root).join(BLOCKED_FILE), b.to_string());
    }
    fn clear_blocked(&mut self) {
        let _ = std::fs::remove_file(spool_dir(self.root).join(BLOCKED_FILE));
    }
    fn write_keep(&mut self) -> Result<PathBuf, String> {
        write_keep_file(self.root)
    }
    fn hostd_up(&mut self) -> bool {
        hostd_up()
    }
    fn run_rung(&mut self, keep: &Path, live: bool) -> Result<Value, String> {
        run_rung(self.root, keep, live)
    }
    fn mark_previewed(&mut self, tag: &str) {
        let _ = std::fs::write(self.root.join(PREVIEWED_MARKER), format!("{tag}\n"));
    }
    fn say(&mut self, line: &str) {
        if !self.g.json {
            println!("{}", crate::ui::note(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addons::pins::Pin;
    use std::collections::BTreeMap;

    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn pin(images: &[(&str, String)], pulled_from: Option<&str>) -> Pin {
        Pin {
            version: "1.2.0".into(),
            stack: "v0.6.24".into(),
            images: images.iter().map(|(k, v)| (k.to_string(), v.clone())).collect::<BTreeMap<_, _>>(),
            key_index: 0,
            lock_sha256: "x".into(),
            signer: None,
            pulled_from: pulled_from.map(str::to_string),
            dev_expires_at: None,
        }
    }

    fn inputs() -> KeepInputs {
        let stack = format!("# stack v0.6.24\nghcr.io/noomesh/gateway@sha256:{}\nghcr.io/noomesh/ollama@sha256:{}\n", h('1'), h('2'));
        let prev = format!("# stack v0.6.23\nghcr.io/noomesh/gateway@sha256:{}\n", h('3'));
        let mut cur = Pins::new();
        cur.insert("exaddon".into(), pin(&[("worker", format!("ghcr.io/example-vendor/exaddon@sha256:{}", h('4')))], None));
        cur.insert("rhaddon".into(), pin(&[("app", format!("ghcr.io/x/rhaddon@sha256:{}", h('5')))], Some("addons.example.net/proxy/x")));
        let mut old = Pins::new();
        old.insert("exaddon".into(), pin(&[("worker", format!("ghcr.io/example-vendor/exaddon@sha256:{}", h('6')))], None));
        KeepInputs {
            stack: Some((PathBuf::from("/r/stack.lock"), stack.into_bytes())),
            stack_prev: Some((PathBuf::from("/r/stack.lock.prev"), prev.into_bytes())),
            pins: Some((PathBuf::from("/r/addons.lock"), b"cur".to_vec(), cur)),
            pins_prev: Some((PathBuf::from("/r/addons.lock.prev"), b"old".to_vec(), old)),
            staged: Some((PathBuf::from("/s/staged-images.json"), b"idx".to_vec(), vec![format!("sha256:{}", h('7'))])),
            roots: vec!["ghcr.io/noomesh/".into()],
            local: vec![],
        }
    }

    /// Captured fixtures: tests/fixtures/image-retention/README.md.
    fn fx(name: &str) -> &'static str {
        match name {
            "rc1.lock" => include_str!("../../../tests/fixtures/image-retention/stack-v0.6.25-rc.1.lock"),
            "0.6.24.lock" => include_str!("../../../tests/fixtures/image-retention/stack-v0.6.24.lock"),
            "classic.images" => include_str!("../../../tests/fixtures/image-retention/classic-overlay2-27.5.1.images"),
            "containerd-node.images" => include_str!("../../../tests/fixtures/image-retention/containerd-node.images"),
            "27.images" => include_str!("../../../tests/fixtures/image-retention/docker27.images"),
            "28.images" => include_str!("../../../tests/fixtures/image-retention/docker28.images"),
            "29.images" => include_str!("../../../tests/fixtures/image-retention/docker29.images"),
            "golden" => include_str!("../../../tests/fixtures/image-retention/keep-classic.golden.json"),
            _ => panic!("no fixture {name}"),
        }
    }

    fn real_inputs() -> KeepInputs {
        KeepInputs {
            stack: Some((PathBuf::from("/r/stack.lock"), fx("rc1.lock").as_bytes().to_vec())),
            stack_prev: Some((PathBuf::from("/r/stack.lock.prev"), fx("0.6.24.lock").as_bytes().to_vec())),
            pins: None,
            pins_prev: None,
            staged: None,
            roots: vec!["ghcr.io/noomesh/".into()],
            local: parse_local_images(fx("classic.images")),
        }
    }

    /// The defect: the real lock's rows are short names (`gateway@sha256:…`)
    /// that no local image is named by, so hostd's keep-by-ref matched
    /// nothing and the previous release's images (stack.lock.prev, the
    /// rollback set) were unprotected. From the REAL rc.1 lock, the REAL
    /// 0.6.24 lock as .prev and a real image store: every local image that
    /// holds a digest either lock names is kept by its image ID. The golden
    /// file is what hostd's own test classifies (image_retention_test.go
    /// TestTheRealKeepFileProtectsBothLocks), so the chain is tested end to
    /// end.
    #[test]
    fn the_keep_file_from_the_real_locks_keeps_every_image_either_lock_names() {
        let inp = real_inputs();
        let v = keep_file(&inp, "2026-11-14T00:00:00Z").unwrap();
        let golden: Value = serde_json::from_str(fx("golden")).unwrap();
        assert_eq!(v, golden, "the keep file drifted from the golden hostd's test classifies");
        let ids: BTreeSet<&str> = v["keep"].as_array().unwrap().iter().filter_map(|e| e["id"].as_str()).collect();
        let mut held = 0;
        for lock in [fx("rc1.lock"), fx("0.6.24.lock")] {
            for r in stack_lock_refs(lock) {
                for im in holding(&r, &inp.local) {
                    held += 1;
                    assert!(ids.contains(im.id.as_str()), "{r} is held by {} and not kept", im.id);
                }
            }
        }
        assert!(held >= 22, "the fixture resolves {held} rows");
        // 0.6.24's gateway is named ONLY by the previous lock: the rollback.
        assert!(!fx("rc1.lock").contains("e3472a087265"));
        assert!(ids.contains("sha256:cf73b69640a184d41f1b6f6db10d45e47e957e0a1c7e29bbeb552e1c70ebd0d0"), "the previous release's gateway is not kept");
        // A row no local image holds (a node-only image on a controller)
        // stays under the lock's own name, inert, and says so.
        let llama = v["keep"].as_array().unwrap().iter().find(|e| e["ref"].as_str().is_some_and(|r| r.starts_with("llamacpp@sha256:1b1c5388"))).unwrap();
        assert!(llama["why"].as_str().unwrap().ends_with("; not on this host"), "{llama}");
        // The Docker Hub image the lock pins is kept by ID like any other.
        assert!(v["keep"].as_array().unwrap().iter().any(|e| e["why"].as_str().is_some_and(|w| w.ends_with("holds nats@sha256:67ac7866d010e8d83302dd30332eeae1a2b7a8ee051155e2eb5a5485b720cd4b"))));
    }

    /// One digest, every name docker holds it under: the release's
    /// ghcr.io/noomesh/<n>, the base images' ghcr.io/noomesh/dhi/<n>, a Docker
    /// Hub short name, a mirror prefix; classic store (27, 28) and containerd
    /// (29, and a node's store).
    #[test]
    fn a_lock_row_resolves_by_digest_under_any_name() {
        let am = "alertmanager@sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda";
        let nats = "nats@sha256:67ac7866d010e8d83302dd30332eeae1a2b7a8ee051155e2eb5a5485b720cd4b";
        for (v, am_id, nats_id) in [
            ("27.images", "sha256:eaf6a5a4da7b0a6000794c47f629250c98b217310d1a88f7611154ae88ac7f89", "sha256:073ccfa5190b3b463a3fcf96e85c57584707cb0e37e977effc0b13df38ad27da"),
            ("28.images", "sha256:eaf6a5a4da7b0a6000794c47f629250c98b217310d1a88f7611154ae88ac7f89", "sha256:073ccfa5190b3b463a3fcf96e85c57584707cb0e37e977effc0b13df38ad27da"),
            ("29.images", "sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda", "sha256:67ac7866d010e8d83302dd30332eeae1a2b7a8ee051155e2eb5a5485b720cd4b"),
        ] {
            let local = parse_local_images(fx(v));
            assert_eq!(local.len(), 3, "{v}");
            assert_eq!(holding(am, &local).iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec![am_id], "{v}");
            assert_eq!(holding(nats, &local).iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), vec![nats_id], "{v}");
        }
        let node = parse_local_images(fx("containerd-node.images"));
        let w = "whisper@sha256:1337ee87e4113bfd426371f007e20865d9dfb3242a7cb94cb479d50f5492d3fd";
        assert_eq!(holding(w, &node).len(), 1, "a mirror-prefixed image is held by digest");
        assert!(holding(w, &node)[0].refs.iter().all(|r| r.starts_with("registry.example.lan/noomesh/whisper")));
        // A name is never enough: the same name with another digest is not held.
        assert!(holding(&format!("alertmanager@sha256:{}", h('0')), &parse_local_images(fx("27.images"))).is_empty());
        assert!(holding("alertmanager:v1", &parse_local_images(fx("27.images"))).is_empty());
    }

    /// The format the fixtures were captured with, and the only one that
    /// lists images on every supported Docker: `{{join .RepoTags ","}}` fails
    /// for every image on the 27.5.1 and 28.5.2 CLIs (captured: "wrong type
    /// for value; expected []string; got []interface {}"), and its output is
    /// not this parser's either.
    #[test]
    fn the_listing_format_is_the_captured_json_one() {
        assert_eq!(LOCAL_IMAGE_FORMAT, "{{.Id}}|{{json .RepoTags}}|{{json .RepoDigests}}");
        let join_out = "sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda|ghcr.io/noomesh/dhi/alertmanager@sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda|ghcr.io/noomesh/dhi/alertmanager@sha256:01dd89cce4737ec7e44704681b5d6ee561e9b7880f632b4413b0e547e4dabfda|80869556";
        assert!(parse_local_images(join_out).is_empty(), "the join template's output (Docker 29) must not be half-read");
    }

    #[test]
    fn local_images_parse_null_lists_and_refuse_anything_else() {
        let l = parse_local_images(&format!("sha256:{}|[\"ollama/ollama:latest\"]|null\nsha256:{}|[\"<none>:<none>\"]|[\"<none>@<none>\"]|9\n", h('e'), h('f')));
        assert_eq!(l, vec![LocalImage { id: format!("sha256:{}", h('e')), refs: vec!["ollama/ollama:latest".into()] }, LocalImage { id: format!("sha256:{}", h('f')), refs: vec![] }]);
        for junk in [format!("sha256:{}|ollama/ollama:latest|", h('e')), "garbage".into(), format!("sha256:{}|[]", h('e')), "sha256:abc|[]|[]".into()] {
            assert!(parse_local_images(&junk).is_empty(), "{junk}");
        }
        assert_eq!(stack_lock_tag(fx("rc1.lock")).as_deref(), Some("v0.6.25-rc.1"), "the release's own header");
    }

    #[test]
    fn the_keep_file_names_current_previous_pins_and_staged_by_exact_identity() {
        let v = keep_file(&inputs(), "2026-11-13T00:00:00Z").unwrap();
        let keep: Vec<(String, String)> = v["keep"].as_array().unwrap().iter()
            .map(|e| (e["ref"].as_str().or(e["id"].as_str()).unwrap().to_string(), e["why"].as_str().unwrap().to_string()))
            .collect();
        let has = |r: &str, why: &str| keep.iter().any(|(k, w)| k == r && w.starts_with(why));
        assert!(has(&format!("ghcr.io/noomesh/gateway@sha256:{}", h('1')), "stack.lock (v0.6.24)"));
        assert!(has(&format!("ghcr.io/noomesh/gateway@sha256:{}", h('3')), "stack.lock.prev (v0.6.23"));
        assert!(has(&format!("ghcr.io/example-vendor/exaddon@sha256:{}", h('4')), "addons.lock: exaddon"));
        assert!(has(&format!("ghcr.io/example-vendor/exaddon@sha256:{}", h('6')), "addons.lock.prev: exaddon"));
        // As docker holds it: the pull root's host, not the signed one.
        assert!(has(&format!("addons.example.net/x/rhaddon@sha256:{}", h('5')), "addons.lock: rhaddon"));
        assert!(has(&format!("sha256:{}", h('7')), "staged on the artifact rail"));
        // Every entry is an exact digest or an image id: never a bare name.
        assert!(keep.iter().all(|(k, _)| k.contains("@sha256:") || k.starts_with("sha256:")));
        let ns: Vec<&str> = v["namespaces"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(ns, vec!["addons.example.net/x/rhaddon/", "ghcr.io/example-vendor/exaddon/", "ghcr.io/noomesh/"]);
        let srcs: Vec<&str> = v["sources"].as_array().unwrap().iter().filter_map(|s| s["path"].as_str()).collect();
        assert_eq!(srcs, vec!["/r/stack.lock", "/r/stack.lock.prev", "/r/addons.lock", "/r/addons.lock.prev", "/s/staged-images.json"]);
    }

    /// A pin that names its image by TAG is never a keep entry (hostd would
    /// refuse the whole file over one bare name, skipping the rung), and it
    /// claims no namespace: only the digest-pinned image beside it counts.
    #[test]
    fn a_tag_pinned_add_on_image_is_never_an_entry_or_a_namespace() {
        let mut i = inputs();
        let mut cur = Pins::new();
        cur.insert("tagonly".into(), pin(&[("app", "ghcr.io/vendor-t/tagonly:1.4.0".to_string())], None));
        cur.insert("mixed".into(), pin(&[
            ("api", format!("ghcr.io/vendor-m/mixedapi@sha256:{}", h('8'))),
            ("ui", "ghcr.io/vendor-m/mixedui:2.0".to_string()),
        ], None));
        i.pins = Some((PathBuf::from("/r/addons.lock"), b"cur".to_vec(), cur));
        i.pins_prev = None;
        let v = keep_file(&i, "2026-11-13T00:00:00Z").unwrap();
        let refs: Vec<&str> = v["keep"].as_array().unwrap().iter().filter_map(|e| e["ref"].as_str()).collect();
        assert!(refs.contains(&format!("ghcr.io/vendor-m/mixedapi@sha256:{}", h('8')).as_str()), "{refs:?}");
        assert!(!refs.iter().any(|r| r.contains("tagonly") || r.contains("mixedui")), "a tag pin became an entry: {refs:?}");
        assert!(refs.iter().all(|r| r.contains("@sha256:")), "{refs:?}");
        let ns: Vec<&str> = v["namespaces"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(ns.contains(&"ghcr.io/vendor-m/mixedapi/"), "{ns:?}");
        assert!(!ns.iter().any(|n| n.contains("tagonly") || n.contains("mixedui")), "a tag pin claimed a namespace: {ns:?}");
    }

    #[test]
    fn no_stack_lock_or_no_digest_writes_no_keep_file() {
        let mut i = inputs();
        i.stack = None;
        assert!(keep_file(&i, "t").is_err());
        let mut i = inputs();
        i.stack = Some((PathBuf::from("/r/stack.lock"), b"# stack v0.6.24\n".to_vec()));
        i.stack_prev = None;
        i.pins = None;
        i.pins_prev = None;
        i.staged = None;
        assert!(keep_file(&i, "t").is_err(), "a lock naming no digest proves nothing");
    }

    #[test]
    fn a_namespace_needs_a_registry_host() {
        assert_eq!(namespace_of(&format!("ghcr.io/example-vendor/exaddon@sha256:{}", h('a'))).as_deref(), Some("ghcr.io/example-vendor/exaddon/"));
        assert_eq!(namespace_of(&format!("localhost:5000/rh/rhaddon@sha256:{}", h('a'))).as_deref(), Some("localhost:5000/rh/rhaddon/"));
        // The pinned image's own repository, never the shared path it sits in.
        assert_eq!(namespace_of(&format!("docker.io/library/redis@sha256:{}", h('a'))).as_deref(), Some("docker.io/library/redis/"));
        assert_eq!(namespace_of(&format!("someuser/img@sha256:{}", h('a'))), None, "a Docker Hub short name is never claimed");
    }

    #[test]
    fn the_previous_lock_is_copied_aside_and_a_missing_one_is_no_error() {
        let d = std::env::temp_dir().join(format!("noo-ret-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let lock = d.join(STACK_LOCK);
        keep_previous_file(&lock); // nothing there: nothing kept, no panic
        assert!(!d.join("stack.lock.prev").exists());
        std::fs::write(&lock, "# tag v0.6.23\nx\n").unwrap();
        keep_previous_file(&lock);
        assert_eq!(std::fs::read_to_string(d.join("stack.lock.prev")).unwrap(), "# tag v0.6.23\nx\n");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_first_roll_previews_then_the_constant_decides_and_noomesh_yaml_wins() {
        assert_eq!(mode(None, false), Mode::Preview, "the first roll that carries this only previews");
        assert_eq!(mode(None, true), if POST_ROLL_DEFAULT_LIVE { Mode::Live } else { Mode::Preview });
        assert_eq!(mode(Some("off"), true), Mode::Off);
        assert_eq!(mode(Some("preview"), true), Mode::Preview);
        assert_eq!(mode(Some("live"), false), Mode::Live, "an explicit live skips the preview");
        assert_eq!(mode(Some("junk"), true), mode(None, true), "an unknown value is the default");
    }

    #[test]
    fn the_setting_is_cluster_image_retention_in_noomesh_yaml() {
        assert_eq!(setting_in("cluster:\n  image_retention: off\n").as_deref(), Some("off"));
        assert_eq!(setting_in("cluster:\n  default_backend: vllm\n"), None);
        assert_eq!(setting_in("image_retention: off\n"), None, "only under cluster:");
        assert_eq!(setting_in(": not yaml ["), None);
    }

    #[test]
    fn an_environment_variable_never_decides_what_a_roll_deletes() {
        // The operator's control is noomesh.yaml, never the environment: a
        // NOO_IMAGE_RETENTION in a shell or unit file is not read at all.
        let own = crate::test_src::own_code(include_str!("image_retention.rs"));
        assert!(!own.contains("std::env::var("), "image retention reads no environment variable");
        let body = crate::test_src::fn_body(&own, "pub(crate) fn post_roll(");
        assert!(body.contains("let set = setting(root);"));
    }

    /// A fake host: records every effect the post-roll step has.
    #[derive(Default)]
    struct FakeHost {
        verified: Option<Value>,
        addons: Vec<String>,
        addons_err: Option<String>,
        rung: Option<Value>,
        hostd_down: bool,
        verifies: u32,
        keeps: u32,
        rungs: Vec<bool>,
        marked: Vec<String>,
        said: Vec<String>,
        blocked: Vec<Vec<String>>,
        cleared: u32,
        keep_err: Option<String>,
    }

    impl PostRollHost for FakeHost {
        fn verify(&mut self) -> Option<Value> {
            self.verifies += 1;
            self.verified.clone()
        }
        fn addons_on(&mut self) -> Result<Vec<String>, String> {
            match &self.addons_err {
                Some(e) => Err(e.clone()),
                None => Ok(self.addons.clone()),
            }
        }
        fn record_blocked(&mut self, _tag: &str, rows: &[String]) {
            self.blocked.push(rows.to_vec());
        }
        fn clear_blocked(&mut self) {
            self.cleared += 1;
        }
        fn write_keep(&mut self) -> Result<PathBuf, String> {
            self.keeps += 1;
            match &self.keep_err {
                Some(e) => Err(e.clone()),
                None => Ok(PathBuf::from("/r/.noo-host-spool/image-keep.json")),
            }
        }
        fn hostd_up(&mut self) -> bool {
            !self.hostd_down
        }
        fn run_rung(&mut self, _keep: &Path, live: bool) -> Result<Value, String> {
            self.rungs.push(live);
            Ok(self.rung.clone().unwrap_or_else(|| json!({"images": []})))
        }
        fn mark_previewed(&mut self, tag: &str) {
            self.marked.push(tag.into());
        }
        fn say(&mut self, line: &str) {
            self.said.push(line.into());
        }
    }

    /// Docker that cannot list its images (a daemon down, a CLI whose
    /// template fails) proves nothing about what to keep: the keep file is
    /// refused, and the roll removes nothing, saying why. Live mode, gate
    /// passed, hostd up: everything else would run the rung.
    #[test]
    fn a_docker_that_cannot_list_its_images_writes_no_keep_file_and_removes_nothing() {
        let e = listed_or_refused(Err("Cannot connect to the Docker daemon at unix:///var/run/docker.sock".into())).unwrap_err();
        assert!(e.starts_with("docker did not list the images (Cannot connect to the Docker daemon") && e.ends_with("so nothing is removed"), "{e}");
        let one = LocalImage { id: format!("sha256:{}", h('a')), refs: vec![] };
        assert_eq!(listed_or_refused(Ok(vec![one.clone()])).unwrap(), vec![one], "a listing passes through");
        assert_eq!(listed_or_refused(Ok(vec![])).unwrap(), vec![], "an empty store is a listing, not a failure");

        let mut host = passed(&[]);
        host.rung = Some(some_superseded());
        host.keep_err = Some(e.clone());
        post_roll_on(&mut host, Some("live"), true, "v0.6.25");
        assert_eq!(host.keeps, 1, "the keep file was asked for");
        assert!(host.rungs.is_empty(), "no keep file, no rung: nothing removed");
        assert!(host.said.iter().any(|l| l == &format!("images: not cleaned up: {e}")), "{:?}", host.said);
        assert!(host.marked.is_empty());

        // The read takes the listing through this mapping, not around it.
        let read = crate::test_src::fn_body(include_str!("image_retention.rs"), "pub(crate) fn read(root: &Path)");
        assert!(read.contains("local: listed_or_refused(local_images())?,"), "{read}");
    }

    fn some_superseded() -> Value {
        json!({"bytes": 1_000_000_000i64, "images": [{"remove": true}, {"remove": false}]})
    }

    fn row(name: &str, verdict: &str, detail: &str) -> Value {
        json!({"name": name, "verdict": verdict, "detail": detail})
    }

    /// A post-roll verify whose gate rows pass, plus rows OUTSIDE the set
    /// that fail, as on the operator's fleet (a certificate inside 30 days,
    /// default chat, another node).
    fn verify_with(rows: Vec<Value>) -> Value {
        let mut checks = vec![
            row("cert expiry", "warn", "node pop-os in 12 days"),
            row("default chat", "fail", "no chat model"),
            row("backup", "fail", "no backup in 3 days"),
        ];
        checks.extend(rows);
        json!({"ok": false, "controller": {"ok": false, "checks": checks}})
    }

    fn clean_verify() -> Value {
        verify_with(vec![
            row("stack images", "ok", "14 container(s) run the lock's images"),
            row("add-on pins", "ok", "1 verified"),
            row("add-on containers", "ok", "rhaddon: every declared container is running"),
        ])
    }

    fn passed(addons: &[&str]) -> FakeHost {
        FakeHost { verified: Some(clean_verify()), addons: addons.iter().map(|a| a.to_string()).collect(), ..Default::default() }
    }

    /// The gate is the rows that make "superseded" true, and only those:
    /// rows outside the set never block, each row in the set blocks alone,
    /// and fail-closed (unreadable, missing, not `ok`).
    #[test]
    fn the_gate_is_the_stack_and_add_on_rows_only() {
        let on = vec!["rhaddon".to_string()];
        // Rows outside the set fail and warn; the gate still passes.
        assert_eq!(retention_gate(Some(&clean_verify()), &on), Ok(()));
        // Each row in the set blocks alone, named with its detail.
        for (name, detail) in [
            ("stack images", "noo-gateway runs sha256:aaaa, the lock pins ghcr.io/noomesh/gateway@sha256:bbbb"),
            ("add-on pins", "rhaddon: not verified"),
            ("add-on containers", "rhaddon: not running: noo-rhaddon"),
        ] {
            let mut v = clean_verify();
            for c in v["controller"]["checks"].as_array_mut().unwrap() {
                if c["name"] == name {
                    c["verdict"] = json!("fail");
                    c["detail"] = json!(detail);
                }
            }
            let rows = retention_gate(Some(&v), &on).unwrap_err();
            assert_eq!(rows, vec![format!("{name} ({detail})")], "{name} alone must block");
            // Not proven is not a pass: warn and starting block too.
            for verdict in ["warn", "starting"] {
                let mut w = v.clone();
                for c in w["controller"]["checks"].as_array_mut().unwrap() {
                    if c["name"] == name {
                        c["verdict"] = json!(verdict);
                    }
                }
                assert!(retention_gate(Some(&w), &on).is_err(), "{name} at {verdict} must block");
            }
        }
        // A required row that is missing blocks.
        let without = |drop: &str| {
            let mut v = clean_verify();
            v["controller"]["checks"].as_array_mut().unwrap().retain(|c| c["name"] != drop);
            v
        };
        assert_eq!(retention_gate(Some(&without("stack images")), &on).unwrap_err(), vec!["stack images (not reported)".to_string()]);
        assert_eq!(retention_gate(Some(&without("add-on pins")), &on).unwrap_err(), vec!["add-on pins (not reported)".to_string()]);
        assert_eq!(retention_gate(Some(&without("add-on containers")), &on).unwrap_err(), vec!["add-on containers rhaddon (not reported)".to_string()]);
        // With no add-on enabled, no add-on row is required.
        assert_eq!(retention_gate(Some(&without("add-on containers")), &[]), Ok(()));
        // An add-on that declares no containers has nothing to prove: its
        // row's WARN does not block; any other WARN on that row does.
        let mut v = clean_verify();
        for c in v["controller"]["checks"].as_array_mut().unwrap() {
            if c["name"] == "add-on containers" {
                c["verdict"] = json!("warn");
                c["detail"] = json!("rhaddon: declares no containers, so they aren't checked");
            }
        }
        assert_eq!(retention_gate(Some(&v), &on), Ok(()), "nothing to prove is not a block");
        for c in v["controller"]["checks"].as_array_mut().unwrap() {
            if c["name"] == "add-on containers" {
                c["detail"] = json!("rhaddon: whether its containers run could not be read (docker)");
            }
        }
        assert!(retention_gate(Some(&v), &on).is_err(), "another warn on that row still blocks");
        // Unreadable: blocks.
        assert!(retention_gate(None, &on).is_err());
        assert!(retention_gate(Some(&json!({"ok": true})), &on).is_err(), "no controller section is not a pass");
        let unrun: std::io::Result<std::process::Output> = Err(std::io::Error::other("no such file"));
        assert_eq!(verify_json(&unrun), None);
    }

    /// A blocked gate writes no keep file, queues no rung, says which rows
    /// blocked, and records them for the verify row; a passing gate clears
    /// the record.
    #[test]
    fn a_blocked_gate_cleans_nothing_and_says_why() {
        let mut h = passed(&["rhaddon"]);
        h.rung = Some(some_superseded());
        h.verified.as_mut().unwrap()["controller"]["checks"].as_array_mut().unwrap().retain(|c| c["name"] != "stack images");
        post_roll_on(&mut h, Some("live"), true, "v1");
        assert_eq!((h.verifies, h.keeps, h.rungs.len(), h.cleared), (1, 0, 0, 0));
        assert_eq!(h.blocked, vec![vec!["stack images (not reported)".to_string()]]);
        assert!(h.said[0].contains("NOT cleaned up: blocked by stack images (not reported)"), "{:?}", h.said);
        // A verify that could not be read blocks the same way.
        let mut h = FakeHost { rung: Some(some_superseded()), ..Default::default() };
        post_roll_on(&mut h, Some("live"), true, "v1");
        assert_eq!((h.keeps, h.rungs.len(), h.blocked.len()), (0, 0, 1));
        // Not knowing which add-ons are on blocks too.
        let mut h = FakeHost { verified: Some(clean_verify()), addons_err: Some("noomesh.yaml unreadable".into()), ..Default::default() };
        post_roll_on(&mut h, Some("live"), true, "v1");
        assert_eq!((h.verifies, h.keeps, h.blocked.len()), (0, 0, 1));
        // A passing gate (with failing rows OUTSIDE the set) cleans, and
        // clears the record.
        let mut h = passed(&["rhaddon"]);
        h.rung = Some(some_superseded());
        post_roll_on(&mut h, Some("live"), true, "v1");
        assert_eq!((h.keeps, h.rungs.clone(), h.cleared, h.blocked.len()), (1, vec![true], 1, 0));
    }

    #[test]
    fn off_runs_nothing_not_even_the_verify() {
        let mut h = passed(&[]);
        post_roll_on(&mut h, Some("off"), true, "v1");
        assert_eq!((h.verifies, h.keeps, h.rungs.len()), (0, 0, 0));
    }

    #[test]
    fn the_first_roll_previews_and_spends_the_preview_only_on_a_non_empty_list() {
        // Empty: says nothing and keeps the one-time preview.
        let mut h = passed(&[]);
        post_roll_on(&mut h, None, false, "v1");
        assert_eq!(h.rungs, vec![false], "the first roll is a preview");
        assert!(h.marked.is_empty() && h.said.is_empty(), "an empty preview is silent and not spent: {:?}", h.said);
        assert_eq!(removable(&json!({"images": [{"remove": false}]})), 0);
        // Something to remove: previews, says so, and records the preview.
        let mut h = passed(&[]);
        h.rung = Some(some_superseded());
        post_roll_on(&mut h, None, false, "v1");
        assert_eq!((h.rungs.clone(), h.marked.clone()), (vec![false], vec!["v1".to_string()]));
        // The next roll (preview spent): live.
        let mut h = passed(&[]);
        h.rung = Some(some_superseded());
        post_roll_on(&mut h, None, true, "v2");
        assert_eq!(h.rungs, vec![true]);
        // An explicit `preview` keeps previewing and never spends the marker.
        let mut h = passed(&[]);
        h.rung = Some(some_superseded());
        post_roll_on(&mut h, Some("preview"), true, "v3");
        assert_eq!((h.rungs.clone(), h.marked.len()), (vec![false], 0));
    }

    #[test]
    fn hostd_down_queues_no_rung() {
        let mut h = passed(&[]);
        h.hostd_down = true;
        post_roll_on(&mut h, Some("live"), true, "v1");
        assert!(h.rungs.is_empty() && h.said[0].contains("noo-hostd is not running"), "{:?}", h.said);
    }

    #[test]
    fn the_summary_says_removed_or_would_remove_with_bytes() {
        let rep = json!({"bytes": 58_000_000_000i64, "images": [
            {"remove": true, "result": "removed"}, {"remove": true, "result": "refused: in use"}, {"remove": false}]});
        assert_eq!(summary(&rep, true), "images: removed 1 superseded image(s), 58.0 GB reclaimed; kept 1; 1 refused by docker (in use)");
        assert_eq!(summary(&rep, false), "images: would remove 2 superseded image(s), 58.0 GB; kept 1 (preview, nothing removed)");
    }

    #[test]
    fn the_post_roll_default_is_one_constant() {
        // The operator's decision (general, 2026-11-13): live by default once
        // the first roll has previewed. Flip this one line to keep previewing.
        const { assert!(POST_ROLL_DEFAULT_LIVE) };
    }
}
