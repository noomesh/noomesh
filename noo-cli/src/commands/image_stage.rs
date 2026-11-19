// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Staging container images on the controller's artifact rail.
//!
//! By design, the controller pulls everything and stages it on the rail, and
//! nodes pull from there; a node never needs registry credentials.
//!
//! The controller pulls with ITS OWN registry login and exports each image as
//! a `docker save` tar into the image store (`IMAGES_DIR`), which the
//! model-cache serves as `/images/` over mTLS and the gateway describes in its
//! artifact manifest (sha256 of the tar, plus the `<tar>.imageid` the tar
//! loads as). A node's agent pulls the tar for ITS architecture, verifies the
//! digest and `docker load`s it — it never holds a registry credential.
//!
//! What gets staged:
//!   - `noo upgrade` (stack stage) and `noo cluster sync-images --stage-only --lock`: every
//!     node-bound image in the release-signed stack lock, pulled BY DIGEST,
//!     for every architecture the fleet runs (amd64, arm64);
//!   - `noo cluster sync-images -i IMG` (and `--stage-only -i IMG`): any named image
//!     (third-party ones too, so a node needs no internet registry at all).
//!
//! Multi-arch on one daemon. A foreign-architecture pull on Docker's classic
//! image store under a SHARED reference (the release tag, or the lock's
//! index digest that compose runs) would re-point it at the foreign image and
//! leave the controller itself running the wrong architecture on its next
//! recreate. So a foreign stage resolves the per-platform manifest digest
//! from the registry, pulls `repo@sha256:<that>` — a reference nothing else
//! uses — and saves BY IMAGE ID (the node tags the loaded image with the ref
//! it asked for). On the containerd image store platforms coexist under one
//! reference and `docker save --platform` exports just one.
//!
//! The verb is `noo cluster sync-images` (phase 1 here, phase 2 = nodes pull,
//! in cluster_provision_subprocess.rs); `--stage-only` stops after phase 1.
//! The old `stage-images` verb is a retired stub (commands/cluster.rs).
//!
//! Everything recorded goes into `staged-images.json` beside the tars; the
//! gateway reads it (lock digest, release prefix/tag for place-time checks)
//! and so does `noo cluster verify`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Globals;
use crate::ui;

/// The staging index file name — the gateway's twin is
/// `routes/artifacts.rs::STAGED_INDEX`.
pub(crate) const STAGED_INDEX: &str = "staged-images.json";

/// Lock images that only ever run on the controller. Everything else in the
/// lock is node-bound and staged (`--all-images` stages these too). The
/// licensed add-ons (trellion-intel, evolve) are not in the stack lock at all:
/// they carry their own signed lock and the controller pulls them by digest
/// itself (`crate::addons`). Their names stay here so a lock row an older
/// release carried is never staged to a node.
pub(crate) const CONTROLLER_ONLY: &[&str] = &[
    "gateway", "worker", "trellion", "trellion-intel", "trellion-evolve", "evolve", "postgres-pgvector",
];

/// Lock rows that are NOT `<prefix>/<name>:<tag>` release images: third-party
/// images the stack runs straight from their upstream registry by a fixed
/// compose tag, which the lock pins by digest (scripts/stack-lock-third-party.py)
/// so the controller's start pulls them by digest. They are pulled by the
/// controller only and never staged from the lock, `--all-images` included:
/// the release prefix does not carry them, and staging a multi-GB ollama
/// for every architecture would slow every roll. A node that needs one is
/// staged by name (`noo cluster sync-images <node> -i <image>`).
pub(crate) const THIRD_PARTY_LOCK_ROWS: &[&str] = &[
    "nats", "nginx", "redis", "loki", "tempo", "prometheus", "alertmanager", "grafana", "node-exporter", "tei", "tei-cpu", "vllm",
];

/// Backend doors pinned to their own image instead of the release
/// (config/door-images.json; the node agent embeds a byte-equal copy). Each
/// pin is staged on every lock stage under source [`DOOR_PIN_SOURCE`], which
/// release retention never prunes, so a node can fetch it after the
/// controller has rolled past the release it came from.
pub(crate) const DOOR_IMAGES_JSON: &str = include_str!("../../../config/door-images.json");
/// The staged-index source of a door pin.
pub(crate) const DOOR_PIN_SOURCE: &str = "door-pin";

/// `(<prefix>/<image>:<tag>, sha256:…, <tag>)` for each pinned door, in a
/// stable order. Malformed rows are skipped (the agent refuses to start on
/// one, and the shipped file is pinned by tests).
pub(crate) fn door_pin_refs(prefix: &str) -> Vec<(String, String, String)> {
    let prefix = prefix.trim_end_matches('/');
    let v: serde_json::Value = serde_json::from_str(DOOR_IMAGES_JSON).unwrap_or_default();
    let mut out: Vec<(String, String, String)> = v["doors"]
        .as_object()
        .map(|doors| {
            doors
                .values()
                .filter_map(|d| {
                    let (img, tag, dig) = (d["image"].as_str()?, d["tag"].as_str()?, d["digest"].as_str()?);
                    let hex = dig.strip_prefix("sha256:")?;
                    let plain = |x: &str| !x.is_empty() && !x.contains(['/', ':', '@', ' ']);
                    (plain(img) && plain(tag) && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                        .then(|| (format!("{prefix}/{img}:{tag}"), dig.to_string(), tag.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

/// `(backend, <prefix>/<image>:<tag>, sha256:…)` for each pinned door: the
/// backend whose stunnel door is pinned, the ref a node fetches it by, and
/// the digest it must have been staged by. Same parse as [`door_pin_refs`].
pub(crate) fn door_pins_by_backend(prefix: &str) -> Vec<(String, String, String)> {
    let prefix = prefix.trim_end_matches('/');
    let v: serde_json::Value = serde_json::from_str(DOOR_IMAGES_JSON).unwrap_or_default();
    let mut out: Vec<(String, String, String)> = v["doors"]
        .as_object()
        .map(|doors| {
            doors
                .iter()
                .filter_map(|(backend, d)| {
                    let (img, tag, dig) = (d["image"].as_str()?, d["tag"].as_str()?, d["digest"].as_str()?);
                    let hex = dig.strip_prefix("sha256:")?;
                    let plain = |x: &str| !x.is_empty() && !x.contains(['/', ':', '@', ' ']);
                    (plain(img) && plain(tag) && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                        .then(|| (backend.clone(), format!("{prefix}/{img}:{tag}"), dig.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Error prefix for "this image is not published for that architecture" —
/// a skip, not a failure (llama.cpp on ARM uses the upstream image).
pub(crate) const NO_VARIANT: &str = "no variant for";

/// Release images the node agent defaults a backend to, and the architectures
/// the release publishes them for: the `platforms` of the images-release.yml
/// matrix rows (the lock records only index digests). The gateway keeps a twin
/// (`OWN_IMAGE_ARCHES`); tests/test_hardened_images_i323.py holds both equal
/// to the matrix. For these images a missing arch is a FAILURE, never a skip:
/// the node does not fall back to an upstream image.
pub(crate) const OWN_IMAGE_ARCHES: &[(&str, &[&str])] =
    &[("llamacpp", &["amd64", "arm64"]), ("llamacpp-cuda", &["amd64"]), ("ollama", &["amd64", "arm64"])];

/// Release images staged ON DEMAND, never by every lock stage: the GPU
/// llama.cpp build (~3 GB, amd64 only) is staged only when some node runs a
/// llamacpp placement on a GPU it can use ([`on_demand_rows_for`]), or when
/// `noo cluster place` meets the gateway's not-staged refusal for it. A fleet
/// with no such placement never downloads it, the controller included.
pub(crate) const ON_DEMAND_LOCK_ROWS: &[&str] = &["llamacpp-cuda"];

/// Is `image` (a lock row name or a full ref) one the release publishes for `arch`?
pub(crate) fn own_image_published(image: &str, arch: &str) -> bool {
    let repo = image.split('@').next().unwrap_or(image);
    let repo = repo.rsplit_once(':').filter(|(_, t)| !t.contains('/')).map_or(repo, |(r, _)| r);
    let name = repo.rsplit('/').next().unwrap_or(repo);
    OWN_IMAGE_ARCHES.iter().any(|(n, arches)| *n == name && arches.contains(&arch))
}

/// A "no variant" stage error is a SKIP only for an image the release does not
/// publish for `arch`; for llamacpp / ollama on a published arch it is a failure.
pub(crate) fn no_variant_is_skip(image: &str, arch: &str, err: &str) -> bool {
    err.starts_with(NO_VARIANT) && !own_image_published(image, arch)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockRow {
    pub name: String,
    pub digest: String,
}

/// `name@sha256:…` rows of a stack lock; comments, `source:` provenance rows
/// and anything malformed are skipped.
pub(crate) fn parse_lock(text: &str) -> Vec<LockRow> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("source:"))
        .filter_map(|l| {
            let (name, digest) = l.split_once('@')?;
            let hex = digest.strip_prefix("sha256:")?;
            (!name.is_empty() && !name.contains(['/', ':', ' ']) && hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| LockRow { name: name.to_string(), digest: digest.to_string() })
        })
        .collect()
}

pub(crate) fn node_bound(name: &str) -> bool {
    !CONTROLLER_ONLY.contains(&name) && !name.starts_with("deps-") && !THIRD_PARTY_LOCK_ROWS.contains(&name) && !ON_DEMAND_LOCK_ROWS.contains(&name)
}

/// Does `stage_lock` stage this lock row? Node-bound release images, or
/// every release image with `--all-images`; a third-party row never.
pub(crate) fn stages_from_lock(name: &str, all: bool) -> bool {
    !THIRD_PARTY_LOCK_ROWS.contains(&name) && (all || node_bound(name))
}

/// Docker/uname arch spellings → the two the rail serves.
pub(crate) fn normalize_arch(a: &str) -> Option<&'static str> {
    match a.trim() {
        "amd64" | "x86_64" | "x86-64" => Some("amd64"),
        "arm64" | "aarch64" | "arm64/v8" => Some("arm64"),
        _ => None,
    }
}

/// A node record's architecture: the reported `capabilities.arch`, else the
/// ARM hints older agents gave (`is_arm`, tier 4). None = unknown.
pub(crate) fn node_arch(n: &Value) -> Option<&'static str> {
    let reported = n["capabilities"]["arch"].as_str().or_else(|| n["arch"].as_str()).unwrap_or("");
    if let Some(a) = normalize_arch(reported) {
        return Some(a);
    }
    let arm = n["is_arm"].as_bool().unwrap_or(false)
        || n["capabilities"]["is_arm"].as_bool().unwrap_or(false)
        || n["tier"].as_i64().or_else(|| n["capabilities"]["tier"].as_i64()) == Some(4);
    arm.then_some("arm64")
}

/// Every architecture to stage for: the controller's own plus each node's.
pub(crate) fn fleet_arches(nodes: &[Value], host: &str) -> Vec<String> {
    let mut v: Vec<String> = vec![host.to_string()];
    v.extend(nodes.iter().filter_map(node_arch).map(str::to_string));
    v.sort();
    v.dedup();
    v
}

/// `repo:tag` → `repo` (a registry port's ':' is before the last '/').
pub(crate) fn repo_of(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    match image.rfind(':') {
        Some(i) if i > image.rfind('/').unwrap_or(0) => &image[..i],
        _ => image,
    }
}

/// The tar-name convention — the twins are Go `ImageTarName` and the
/// gateway's `image_tar_name`; the convention IS the protocol.
pub(crate) fn image_tar_name(image: &str, arch: &str) -> String {
    format!("{}_{arch}.tar", image.replace(['/', ':'], "_"))
}

/// The compressed artifact's name: the tar name + ".gz" (twins: Go
/// `ImageTarGzName`, the gateway's `image_tar_gz_name`). The controller now
/// exports this; a node asks for it first and falls back to the plain tar.
pub(crate) fn image_tar_gz_name(image: &str, arch: &str) -> String {
    format!("{}.gz", image_tar_name(image, arch))
}

/// The ref a placement's image is staged under: the ref with its digest cut
/// off at the first '@' (never at the last ':', which may be a registry port).
/// A placement may pin `repo:tag@sha256:<index>`, but the rail tar is named by
/// `repo:tag` (stage_image takes the digest separately), and the node agent
/// strips the same way before it asks for the tar. Twin: the gateway's
/// `staged_ref`; `staged_names` in tests/fixtures/own_image_cases.json holds
/// both to one table.
pub(crate) fn staged_ref(image: &str) -> &str {
    image.split_once('@').map_or(image, |(r, _)| r)
}

/// True when the store holds the image for `arch` in either form. An older
/// controller store (plain `.tar`) is still a staged image.
fn image_staged_in(dir: &Path, image: &str, arch: &str) -> bool {
    let image = staged_ref(image);
    dir.join(image_tar_gz_name(image, arch)).is_file() || dir.join(image_tar_name(image, arch)).is_file()
}

/// Where the tars live on this host (`IMAGES_DIR`, else `$NOO_DATA_ROOT/images`).
pub(crate) fn images_store_dir() -> PathBuf {
    let v = |k: &str| std::env::var(k).unwrap_or_default();
    let dir = v("IMAGES_DIR");
    if !dir.is_empty() {
        return PathBuf::from(dir);
    }
    let root = v("NOO_DATA_ROOT");
    let root = if root.is_empty() { crate::commands::data_root::DEFAULT_DATA_ROOT.to_string() } else { root };
    PathBuf::from(root).join("images")
}

// ── the ownership rule (shared with Go and the gateway) ───────────────────

/// Docker's normalisation of a ref's NAME (no tag/digest): `alpine` →
/// `docker.io/library/alpine`, `ollama/ollama` → `docker.io/ollama/ollama`.
/// None when Docker would not parse it (empty, whitespace, upper case).
/// Twin of Go `normalizeName` (distribution/reference) — the shared fixture
/// `tests/fixtures/own_image_cases.json` holds all three to one answer.
pub(crate) fn normalize_name(r: &str) -> Option<String> {
    let r = r.trim();
    if r.is_empty() || r.contains(char::is_whitespace) {
        return None;
    }
    let r = r.split('@').next().unwrap_or(r);
    let name = match r.rfind(':') {
        Some(i) if i > r.rfind('/').unwrap_or(0) => &r[..i],
        _ => r,
    };
    let (domain, path) = match name.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => (first, rest.to_string()),
        _ => ("docker.io", name.to_string()),
    };
    if path.is_empty() || path.contains("//") || path.chars().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let domain = if domain == "index.docker.io" { "docker.io" } else { domain };
    let path = if domain == "docker.io" && !path.contains('/') { format!("library/{path}") } else { path };
    Some(format!("{domain}/{path}"))
}

/// Images that exist in no registry (the controller builds them), as
/// normalised names. Same list as Go `localBuildNamespaces`.
pub(crate) const LOCAL_BUILD_NAMESPACES: [&str; 3] = ["docker.io/noomesh/", "docker.io/pai-assistant/", "docker.io/library/noo-"];

/// THE rule: ours when the normalised name sits under one of `roots` or a
/// local-build namespace; an unparsable ref counts as ours (fail closed).
pub(crate) fn is_own_image_with(r: &str, roots: &[&str]) -> bool {
    let Some(name) = normalize_name(r) else { return true };
    roots
        .iter()
        .map(|x| x.trim().trim_end_matches('/'))
        .filter(|x| !x.is_empty())
        .filter_map(normalize_name)
        .any(|root| name.starts_with(&format!("{root}/")))
        || LOCAL_BUILD_NAMESPACES.iter().any(|p| name.starts_with(p))
}

/// The roots this controller calls ours: the rail roots plus the release
/// prefix in force. Written to the index as `own_roots` for the gateway.
pub(crate) fn own_roots() -> Vec<String> {
    let mut v: Vec<String> = crate::registry::rail_roots().iter().map(|s| s.to_string()).collect();
    let p = crate::commands::provision::release_var("NOO_IMAGE_PREFIX");
    if !p.trim().is_empty() {
        v.push(p.trim().to_string());
    }
    v
}

// ── the index ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Release {
    pub prefix: String,
    pub tag: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedRecord {
    #[serde(rename = "ref")]
    pub image: String,
    pub arch: String,
    pub tar: String,
    #[serde(default)]
    pub image_id: String,
    /// The release-lock digest it was pulled by ("" when staged by name).
    #[serde(default)]
    pub lock_digest: String,
    /// "lock" | "door-pin" | "sync-images" | "place".
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub release_tag: String,
    #[serde(default)]
    pub staged_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct StagedIndex {
    #[serde(default)]
    pub release: Option<Release>,
    /// Registry roots whose images are ours (the gateway's input to the
    /// shared ownership rule — it holds no namespace literal of its own).
    #[serde(default)]
    pub own_roots: Vec<String>,
    /// The last lock stage's outcome — read by `noo upgrade --nodes` so a
    /// node roll never starts on top of a stage that failed.
    #[serde(default)]
    pub lock_stage: Option<LockStage>,
    #[serde(default)]
    pub images: Vec<StagedRecord>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LockStage {
    pub tag: String,
    #[serde(default)]
    pub failed: Vec<String>,
    #[serde(default)]
    pub at: u64,
}

/// The lock-stage failures recorded for `tag` (empty when it staged clean
/// or was never staged — the latter is the roll's own business).
pub(crate) fn lock_stage_failures(tag: &str) -> Vec<String> {
    match read_index(&images_store_dir()).lock_stage {
        Some(ls) if ls.tag == tag => ls.failed,
        _ => Vec::new(),
    }
}

pub(crate) fn read_index(dir: &Path) -> StagedIndex {
    std::fs::read(dir.join(STAGED_INDEX)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn write_index(dir: &Path, idx: &StagedIndex) -> Result<(), String> {
    let tmp = dir.join(format!("{STAGED_INDEX}.tmp"));
    let body = serde_json::to_vec_pretty(idx).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, dir.join(STAGED_INDEX)).map_err(|e| format!("finalize {STAGED_INDEX}: {e}"))
}

/// Insert or replace the record for (ref, arch).
pub(crate) fn upsert(idx: &mut StagedIndex, rec: StagedRecord) {
    idx.images.retain(|r| !(r.image == rec.image && r.arch == rec.arch));
    idx.images.push(rec);
    idx.images.sort_by(|a, b| (&a.image, &a.arch).cmp(&(&b.image, &b.arch)));
}

/// Lock-staged release tags to drop: keep `current` and the newest other one
/// (the rollback target); everything older goes.
pub(crate) fn lock_tags_to_prune(idx: &StagedIndex, current: &str) -> Vec<String> {
    let mut newest: std::collections::BTreeMap<&str, u64> = Default::default();
    for r in idx.images.iter().filter(|r| r.source == "lock" && !r.release_tag.is_empty()) {
        let e = newest.entry(r.release_tag.as_str()).or_default();
        *e = (*e).max(r.staged_at);
    }
    let mut others: Vec<(&str, u64)> = newest.into_iter().filter(|(t, _)| *t != current).collect();
    others.sort_by_key(|o| std::cmp::Reverse(o.1));
    others.into_iter().skip(1).map(|(t, _)| t.to_string()).collect()
}

/// Serialises the index's read-modify-write: `stage_lock` records from several
/// worker threads (a lost update would drop a staged image from the index).
static INDEX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What restages the release's own images by their lock digest.
pub(crate) const RESTAGE_BY_LOCK: &str = "noo cluster sync-images --stage-only --lock";

/// The refusal for a by-name stage of (`image`, `arch`) when the index holds
/// it by a lock digest: the by-name record would replace it, and a node whose
/// backend is pinned to that digest refuses its next start. None when the
/// index holds no digest-staged record for it (a non-release image, or one
/// never staged), so a by-name stage is fine.
pub(crate) fn by_name_over_lock(idx: &StagedIndex, image: &str, arch: &str) -> Option<String> {
    let held = idx.images.iter().find(|r| r.image == image && r.arch == arch && !r.lock_digest.is_empty())?;
    Some(format!(
        "{image} ({arch}) is staged by its release-lock digest {}; a by-name stage would replace it and a node pinned to that digest would refuse its next start. Restage it by digest: {RESTAGE_BY_LOCK}",
        held.lock_digest
    ))
}

/// Record a staged image (read-modify-write of the index). A by-name record
/// never replaces one staged by a lock digest ([`by_name_over_lock`]); a
/// digest-staged record (a newer release, a door pin) replaces anything.
pub(crate) fn record_staged(rec: StagedRecord, release: Option<Release>) -> Result<(), String> {
    let _held = INDEX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = images_store_dir();
    let mut idx = read_index(&dir);
    if rec.lock_digest.is_empty() {
        if let Some(refusal) = by_name_over_lock(&idx, &rec.image, &rec.arch) {
            return Err(refusal);
        }
    }
    if release.is_some() {
        idx.release = release;
    }
    idx.own_roots = own_roots();
    upsert(&mut idx, rec);
    write_index(&dir, &idx)
}

// ── docker ────────────────────────────────────────────────────────────────

#[cfg(test)]
type FakeDocker = Box<dyn FnMut(&[&str]) -> Result<String, String>>;

#[cfg(test)]
thread_local! {
    /// Tests script the daemon here: every `docker` invocation goes to it.
    static FAKE_DOCKER: std::cell::RefCell<Option<FakeDocker>> = const { std::cell::RefCell::new(None) };
    /// Pool size for a test that wants `stage_lock` to run its workers
    /// (default: 1, serial, on the test's own thread).
    static PARALLELISM_OVERRIDE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    /// A scripted daemon the pool's worker threads may all call: `stage_lock`
    /// installs a forwarder to it as each worker's FAKE_DOCKER.
    static SHARED_FAKE: std::cell::RefCell<Option<std::sync::Arc<std::sync::Mutex<SharedFake>>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type SharedFake = Box<dyn FnMut(&[&str]) -> Result<String, String> + Send>;

fn docker(args: &[&str]) -> Result<String, String> {
    #[cfg(test)]
    {
        if let Some(r) = FAKE_DOCKER.with(|f| f.borrow_mut().as_mut().map(|h| h(args))) {
            return r;
        }
    }
    let out = Command::new("docker").args(args).output().map_err(|e| format!("docker: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!("docker {}: {}", args.first().unwrap_or(&""), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// The controller daemon's architecture.
pub(crate) fn host_arch() -> String {
    docker(&["version", "--format", "{{.Server.Arch}}"])
        .ok()
        .and_then(|a| normalize_arch(&a))
        .or_else(|| normalize_arch(std::env::consts::ARCH))
        .unwrap_or("amd64")
        .to_string()
}

/// Is the daemon on the containerd image store (multi-platform per tag)?
fn containerd_store() -> bool {
    docker(&["info", "--format", "{{json .DriverStatus}}"]).map(|s| s.contains("io.containerd.snapshotter")).unwrap_or(false)
}

fn inspect_id_arch(reference: &str) -> Option<(String, String)> {
    let s = docker(&["image", "inspect", "--format", "{{.Id}} {{.Architecture}}", reference]).ok()?;
    let mut it = s.split_whitespace();
    Some((it.next()?.to_string(), it.next().unwrap_or("").to_string()))
}

/// What the registry says `src` holds for linux/<arch>.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PlatformPick {
    /// A multi-platform index: the per-platform manifest digest.
    Manifest(String),
    /// A single-platform manifest (its own digest); its architecture is
    /// checked after the pull.
    Single(String),
    /// Not published for that architecture.
    Missing,
}

/// Read `docker buildx imagetools inspect --format '{{json .Manifest}}'` or
/// `docker manifest inspect -v` output. Pure, so it is tested on both shapes.
pub(crate) fn pick_platform(v: &Value, arch: &str) -> PlatformPick {
    let matches = |p: &Value| p["os"].as_str() == Some("linux") && normalize_arch(p["architecture"].as_str().unwrap_or("")) == Some(arch);
    let sha = |d: &Value| d.as_str().filter(|d| d.starts_with("sha256:")).map(str::to_string);
    if let Some(ms) = v["manifests"].as_array() {
        return ms.iter().find(|m| matches(&m["platform"])).and_then(|m| sha(&m["digest"])).map_or(PlatformPick::Missing, PlatformPick::Manifest);
    }
    if let Some(list) = v.as_array() {
        return list.iter().find(|m| matches(&m["Descriptor"]["platform"])).and_then(|m| sha(&m["Descriptor"]["digest"])).map_or(PlatformPick::Missing, PlatformPick::Manifest);
    }
    if v["Descriptor"].is_object() {
        let p = &v["Descriptor"]["platform"];
        if p.is_object() && !matches(p) {
            return PlatformPick::Missing;
        }
        return sha(&v["Descriptor"]["digest"]).map_or(PlatformPick::Missing, PlatformPick::Single);
    }
    sha(&v["digest"]).map_or(PlatformPick::Missing, PlatformPick::Single)
}

fn resolve_platform(src: &str, arch: &str) -> Result<PlatformPick, String> {
    let raw = docker(&["buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", src])
        .or_else(|e1| docker(&["manifest", "inspect", "-v", src]).map_err(|e2| format!("cannot read {src}'s manifest ({e1}; {e2})")))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("unreadable manifest for {src}: {e}"))?;
    Ok(pick_platform(&v, arch))
}

/// The first of `names` that is an executable file on PATH. ABSENT → None.
fn on_path(names: &[&str]) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    names.iter().find_map(|n| {
        std::env::split_paths(&path)
            .map(|d| d.join(n))
            .find(|p| p.metadata().map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false))
            .map(|_| n.to_string())
    })
}

/// `docker save <save_args> | pigz -1 (else gzip -1) > out`.
///
/// Level 1 on purpose: the controller's CPU time matters more than the last
/// ~10% of size, and layers already shrink about 2:1 at level 1.
///
/// Both ends of the pipe are checked. This repo has been bitten by the
/// pipe-to-tail pattern (`save | gzip && go-on` gates on the LAST command, so
/// a failed `docker save` plus a happy gzip yields a valid-looking, truncated
/// archive that is then staged as good); the two children are spawned
/// directly and each exit status is read, which needs no `set -o pipefail`
/// (dash, a common /bin/sh, only recently learned it).
///
/// Neither pigz nor gzip on PATH → an error, never an uncompressed export:
/// nodes ask for `.tar.gz` first, so a plain tar would not be found by them.
fn docker_save_gz(save_args: &[&str], out: &Path) -> Result<(), String> {
    #[cfg(test)]
    {
        let out_s = out.display().to_string();
        let mut args: Vec<&str> = vec!["save", "-o", &out_s];
        args.extend_from_slice(save_args);
        if let Some(r) = FAKE_DOCKER.with(|f| f.borrow_mut().as_mut().map(|h| h(&args))) {
            return r.map(|_| ());
        }
    }
    let gz = on_path(&["pigz", "gzip"]).ok_or("gzip is required on the controller (apt install gzip)")?;
    let mut save = Command::new("docker");
    save.arg("save").args(save_args);
    pipe_gz(save, "docker save", &gz, out)
}

/// `producer | <gz> -1 > out`, with BOTH exit statuses checked.
fn pipe_gz(mut producer: Command, what: &str, gz: &str, out: &Path) -> Result<(), String> {
    use std::process::Stdio;
    let file = std::fs::File::create(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    let mut prod = producer.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("{what}: {e}"))?;
    let prod_out = prod.stdout.take().ok_or_else(|| format!("{what}: no stdout"))?;
    let mut comp = match Command::new(gz).arg("-1").stdin(Stdio::from(prod_out)).stdout(Stdio::from(file)).spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = prod.kill();
            let _ = prod.wait();
            return Err(format!("{gz}: {e}"));
        }
    };
    let prod_res = prod.wait_with_output().map_err(|e| format!("{what}: {e}"))?;
    let comp_res = comp.wait().map_err(|e| format!("{gz}: {e}"))?;
    if !prod_res.status.success() {
        return Err(format!("{what}: {}", String::from_utf8_lossy(&prod_res.stderr).trim()));
    }
    if !comp_res.success() {
        return Err(format!("{gz} -1 failed ({comp_res})"));
    }
    Ok(())
}

/// Hard-link an existing `.tar.gz` export whose sidecar names `id` to
/// `<tar>.exporting` (the caller finishes with sidecar + rename). False when
/// there is none, or the link fails — then the caller exports normally.
fn link_same_id_export(dir: &Path, tar: &str, id: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(data) = name.strip_suffix(".imageid") else { continue };
        if data == tar || !data.ends_with(".tar.gz") || !dir.join(data).is_file() {
            continue;
        }
        if std::fs::read_to_string(e.path()).unwrap_or_default().trim() != id {
            continue;
        }
        let tmp = dir.join(format!("{tar}.exporting"));
        let _ = std::fs::remove_file(&tmp);
        if std::fs::hard_link(dir.join(data), &tmp).is_ok() {
            return true;
        }
    }
    false
}

/// Export into the store under `tar` (a `.tar.gz` name), tmp+rename (nginx
/// and the gateway's digest cache must never see a half-written file), with
/// the `<tar>.imageid` sidecar. An export whose sidecar already names `id`
/// is kept. Once a `.tar.gz` is in place the same stem's stale uncompressed
/// `.tar` (+ sidecar) is removed: disk, and one name per image.
fn save_tar(dir: &Path, tar: &str, save_args: &[&str], id: &str, g: &Globals) -> Result<(), String> {
    let path = dir.join(tar);
    let sidecar = dir.join(format!("{tar}.imageid"));
    let kept = !id.is_empty() && path.is_file() && std::fs::read_to_string(&sidecar).unwrap_or_default().trim() == id;
    if kept && !g.json && !ui::quiet() {
        emit(Line::Text(format!("  {tar}: already staged (same image id)")));
    }
    if !kept {
        // The file NAME embeds the release tag, so across releases the name
        // above never exists yet even when the image bytes did not change.
        // An export saved BY ID (no RepoTags inside; the node tags it on
        // load) is identical for the same id whatever it is called: reuse
        // the sibling by hard link instead of exporting again. A tar saved
        // by TAG carries its tag in manifest.json, which the node refuses
        // under another ref, so those are never reused.
        let by_id = !id.is_empty() && save_args == [id];
        let reused = by_id && link_same_id_export(dir, tar, id);
        if reused {
            if !g.json && !ui::quiet() {
                emit(Line::Text(format!("  {tar}: already staged (same image id)")));
            }
        } else {
            if !g.json && !ui::quiet() {
                emit(Line::Text(format!("  exporting → {tar}")));
            }
            let tmp = dir.join(format!("{tar}.exporting"));
            if let Err(e) = docker_save_gz(save_args, &tmp) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
            // World-readable before it is visible: newer Docker CLIs create the
            // `-o` file 0600, and the model-cache's nginx (another uid) must read it.
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(|e| format!("chmod {tar}: {e}"))?;
            }
        }
        let tmp = dir.join(format!("{tar}.exporting"));
        // The sidecar first: a reader that sees the new file sees its ID.
        let side_tmp = dir.join(format!("{tar}.imageid.tmp"));
        std::fs::write(&side_tmp, format!("{id}\n")).map_err(|e| e.to_string())?;
        std::fs::rename(&side_tmp, &sidecar).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("finalize {tar}: {e}"))?;
    }
    if let Some(stem) = tar.strip_suffix(".gz") {
        let old = dir.join(stem);
        if old.is_file() {
            let _ = std::fs::remove_file(dir.join(format!("{stem}.imageid")));
            let _ = std::fs::remove_file(&old);
            if !g.json && !ui::quiet() {
                emit(Line::Text(format!("  removed the stale uncompressed {stem} (superseded by {tar})")));
            }
        }
    }
    Ok(())
}

/// u64 view of the one clock (`host_exec::now_unix`); the index fields are unsigned.
fn now_unix() -> u64 {
    crate::host_exec::now_unix().max(0) as u64
}

/// Stage `image` for `arch`: pull with the controller's registry login (by
/// `lock_digest` when given), export to the store, and return the record
/// (the caller writes it). Errors starting with [`NO_VARIANT`] mean "not
/// published for that architecture".
///
/// The controller's OWN references are never moved to another architecture:
///   - host arch: the architecture is checked on the pulled image BEFORE any
///     `docker tag`, and the tar is saved by the release tag;
///   - foreign arch on the classic store: the per-platform manifest digest is
///     resolved from the registry and pulled as `repo@sha256:<platform>` — a
///     reference nothing else uses — then saved BY ID (the node tags it on
///     load). No tag, no shared reference, no restore pull;
///   - foreign arch on the containerd store: platforms coexist under one
///     reference, and `docker save --platform` exports just the one.
pub(crate) fn stage_image(g: &Globals, image: &str, arch: &str, lock_digest: Option<&str>, source: &str) -> Result<StagedRecord, String> {
    let host = host_arch();
    let repo = repo_of(image);
    let src = lock_digest.map(|d| format!("{repo}@{d}")).unwrap_or_else(|| image.to_string());
    let dir = images_store_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tar = image_tar_gz_name(image, arch);
    let platform = format!("linux/{arch}");

    let image_id = if arch == host {
        if inspect_id_arch(&src).is_none() {
            docker(&["pull", "-q", &src])?;
        }
        let (id, a) = inspect_id_arch(&src).ok_or_else(|| format!("{src} is not in the local docker store after the pull"))?;
        if normalize_arch(&a) != Some(arch) {
            return Err(format!("{NO_VARIANT} {arch}: {src} resolves to a {a} image on this {host} controller"));
        }
        if lock_digest.is_some() {
            docker(&["tag", &src, image])?;
        }
        // Classic store: save BY ID so the export holds no RepoTags (the node
        // tags it on load) and the same bytes can serve the next release.
        // On the containerd store the id is an index digest, so keep the tag.
        if containerd_store() {
            save_tar(&dir, &tar, &[image], &id, g)?;
        } else {
            save_tar(&dir, &tar, &[id.as_str()], &id, g)?;
        }
        id
    } else if containerd_store() {
        docker(&["pull", "-q", "--platform", &platform, &src]).map_err(|e| format!("{NO_VARIANT} {arch}? {e}"))?;
        if lock_digest.is_some() {
            docker(&["tag", &src, image])?;
        }
        let id = docker(&["image", "inspect", "--platform", &platform, "--format", "{{.Id}}", image]).unwrap_or_default();
        save_tar(&dir, &tar, &["--platform", &platform, image], &id, g)?;
        id
    } else {
        let digest = match resolve_platform(&src, arch)? {
            PlatformPick::Missing => return Err(format!("{NO_VARIANT} {arch}: {src} publishes no linux/{arch} manifest")),
            PlatformPick::Manifest(d) | PlatformPick::Single(d) => d,
        };
        let pinned = format!("{repo}@{digest}");
        docker(&["pull", "-q", "--platform", &platform, &pinned])?;
        let (id, a) = inspect_id_arch(&pinned).ok_or_else(|| format!("{pinned} did not resolve after the pull"))?;
        if normalize_arch(&a) != Some(arch) {
            return Err(format!("{NO_VARIANT} {arch}: {image} publishes only {a}"));
        }
        save_tar(&dir, &tar, &[id.as_str()], &id, g)?;
        id
    };
    Ok(StagedRecord {
        image: image.to_string(),
        arch: arch.to_string(),
        tar,
        image_id,
        lock_digest: lock_digest.unwrap_or("").to_string(),
        source: source.to_string(),
        release_tag: String::new(),
        staged_at: now_unix(),
    })
}

/// Ask the gateway for the tar's manifest once, with a long timeout, so it
/// hashes now (multi-GB) rather than inside a node's 15 s probe.
pub(crate) fn prewarm(g: &Globals, tar: &str) {
    let _ = crate::http::get_json_opt(g, &format!("/api/artifacts/manifest/image/{}", crate::commands::urlencode(tar)), true, 900);
}

/// Stage one image for one arch end to end (pull, export, index, pre-warm).
/// Every by-name stager (`sync-images -i`, the full `sync-images` push,
/// `place`'s not-staged retry) comes through here: an image the controller's
/// release lock pins is staged by its lock digest, whatever the caller asked.
pub(crate) fn stage_and_record(g: &Globals, image: &str, arch: &str, source: &str) -> Result<StagedRecord, String> {
    let lock = controller_lock_opt()?;
    let rec = stage_record_with(g, image, arch, source, lock.as_ref().map(|(l, p, t)| (l.as_str(), p.as_str(), t.as_str())))?;
    prewarm(g, &rec.tar);
    Ok(rec)
}

/// [`stage_and_record`] without the pre-warm, against `lock` (its text,
/// prefix, tag; None = no lock on this controller). An image the lock pins
/// ([`lock_pin_for`]) is staged by its digest and recorded exactly as
/// `stage_lock` records it (source `lock` or `door-pin`, with its release
/// tag), so retention prunes it with its release and the node's pin check
/// finds the digest. Anything else is staged by name under `source`; that
/// is refused before any pull when the index holds the image by a digest.
fn stage_record_with(g: &Globals, image: &str, arch: &str, source: &str, lock: Option<(&str, &str, &str)>) -> Result<StagedRecord, String> {
    let pin = lock.and_then(|(l, p, t)| lock_pin_for(image, l, p, t));
    let rec = match pin {
        Some((digest, release_tag, pin_source)) => {
            let mut rec = stage_image(g, image, arch, Some(&digest), pin_source)?;
            rec.release_tag = release_tag;
            rec
        }
        None => {
            if let Some(refusal) = by_name_over_lock(&read_index(&images_store_dir()), image, arch) {
                return Err(refusal);
            }
            stage_image(g, image, arch, None, source)?
        }
    };
    record_staged(rec.clone(), None)?;
    Ok(rec)
}

#[derive(Default, Debug)]
pub(crate) struct Summary {
    pub staged: Vec<String>,
    pub skipped: Vec<String>,
    pub failed: Vec<String>,
}

impl Summary {
    fn absorb(&mut self, r: Staged) {
        match r {
            Staged::Done(l) => self.staged.push(l),
            Staged::Skipped(l) => self.skipped.push(l),
            Staged::Failed(l) => self.failed.push(l),
        }
    }
}

/// Images exported at once by [`stage_lock`]. Each job is a registry pull plus
/// a `docker save | gzip`: three overlap network and CPU without starving the
/// controller's own services (it is also the build/roll host).
/// `NOO_STAGE_PARALLELISM` overrides (read once; `1` is the old serial pass;
/// unset, empty, zero or unparsable keeps this default).
#[cfg_attr(test, allow(dead_code))]
const STAGE_PARALLELISM: usize = 3;

// Tests are serial unless one asks for the pool: the scripted daemon is
// thread-local and invisible to worker threads (see SHARED_FAKE).
#[cfg(test)]
fn stage_parallelism() -> usize {
    PARALLELISM_OVERRIDE.with(|p| p.get()).unwrap_or(1)
}

#[cfg(not(test))]
fn stage_parallelism() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("NOO_STAGE_PARALLELISM").ok().and_then(|v| v.trim().parse::<usize>().ok()).filter(|n| *n > 0).unwrap_or(STAGE_PARALLELISM)
    })
}

/// One line a staging job would print.
enum Line {
    Text(String),
    Step(String),
}

thread_local! {
    /// While a pooled job runs, its lines collect here instead of printing, so
    /// the caller prints them in lock order and jobs never interleave. None =
    /// print as they happen (the serial pass, and every other caller).
    static JOB_LOG: std::cell::RefCell<Option<Vec<Line>>> = const { std::cell::RefCell::new(None) };
}

fn emit(line: Line) {
    let line = JOB_LOG.with(|l| match l.borrow_mut().as_mut() {
        Some(buf) => {
            buf.push(line);
            None
        }
        None => Some(line),
    });
    match line {
        Some(Line::Text(t)) => println!("{t}"),
        Some(Line::Step(t)) => ui::step(&t),
        None => {}
    }
}

type JobResult = (Vec<Line>, Vec<Staged>);

enum Staged {
    Done(String),
    Skipped(String),
    Failed(String),
}

/// Every arch of ONE lock image, in order, on the calling thread. An
/// on-demand image ([`ON_DEMAND_LOCK_ROWS`]) is staged only for the arches the
/// release publishes it for (the CUDA llama.cpp: amd64).
fn stage_lock_image(g: &Globals, image: &str, digest: &str, tag: &str, source: &str, arches: &[String], release: &Release) -> Vec<Staged> {
    let mut out = Vec::new();
    let name = repo_of(image).rsplit('/').next().unwrap_or(image);
    for arch in arches {
        if ON_DEMAND_LOCK_ROWS.contains(&name) && !own_image_published(image, arch) {
            continue;
        }
        let label = format!("{image} ({arch})");
        if !g.json {
            emit(Line::Step(format!("staging {label}")));
        }
        out.push(match stage_image(g, image, arch, Some(digest), source) {
            Ok(mut rec) => {
                rec.release_tag = tag.to_string();
                let tar = rec.tar.clone();
                match record_staged(rec, Some(release.clone())) {
                    Ok(()) => {
                        prewarm(g, &tar);
                        Staged::Done(label)
                    }
                    Err(e) => Staged::Failed(format!("{label}: {e}")),
                }
            }
            Err(e) if no_variant_is_skip(image, arch, &e) => Staged::Skipped(format!("{label}: not published for {arch}")),
            Err(e) => Staged::Failed(format!("{label}: {e}")),
        });
    }
    out
}

/// Stage every (node-bound, unless `all`) lock image for every arch.
///
/// Up to [`stage_parallelism`] IMAGES run at once; the arches of one image run
/// in order on one worker. That is deliberate: the same-arch path and the
/// containerd foreign-arch path both `docker tag <digest-ref> <image>:<tag>`
/// under ONE reference per image, so two arches of the same image in flight
/// could race on that tag (and on the platform-specific pull behind it).
/// Different images share no reference, and `save_tar`'s tmp+rename and
/// `.imageid` sidecar are per tar name, so they cannot collide on files. The
/// one shared file is the staged index, written under [`INDEX_LOCK`].
///
/// A failing job never cancels the others. Output of a pooled run is printed
/// in lock order after every job finished (not interleaved); the serial pass
/// (parallelism 1) prints as it goes, as it always did.
///
/// `on_demand`: the [`ON_DEMAND_LOCK_ROWS`] a placement needs now
/// ([`on_demand_from_gateway`]); staged like the node-bound rows. Without it
/// (and without `all`) they are skipped.
pub(crate) fn stage_lock(g: &Globals, lock: &str, prefix: &str, tag: &str, arches: &[String], all: bool, on_demand: &[String]) -> Summary {
    let prefix = prefix.trim_end_matches('/');
    let mut sum = Summary::default();
    let dir = images_store_dir();
    let release = Release { prefix: prefix.to_string(), tag: tag.to_string() };
    // The lock's rows, then each pinned door under its own tag. A lock row
    // that IS a pin's ref (staging the pin's own release) is staged once,
    // as the pin, so retention never prunes it.
    let pins = door_pin_refs(prefix);
    let mut rows: Vec<(String, String, String, &str)> = parse_lock(lock)
        .into_iter()
        .filter(|r| stages_from_lock(&r.name, all) || (ON_DEMAND_LOCK_ROWS.contains(&r.name.as_str()) && on_demand.contains(&r.name)))
        .map(|r| (format!("{prefix}/{}:{tag}", r.name), r.digest, tag.to_string(), "lock"))
        .filter(|(image, ..)| !pins.iter().any(|(p, ..)| p == image))
        .collect();
    rows.extend(pins.into_iter().map(|(image, digest, pin_tag)| (image, digest, pin_tag, DOOR_PIN_SOURCE)));
    let workers = stage_parallelism().min(rows.len());
    if workers <= 1 {
        for (image, digest, rel_tag, source) in &rows {
            for r in stage_lock_image(g, image, digest, rel_tag, source, arches, &release) {
                sum.absorb(r);
            }
        }
    } else {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let done: std::sync::Mutex<Vec<Option<JobResult>>> = std::sync::Mutex::new((0..rows.len()).map(|_| None).collect());
        #[cfg(test)]
        let shared = SHARED_FAKE.with(|s| s.borrow().clone());
        std::thread::scope(|sc| {
            for _ in 0..workers {
                sc.spawn(|| {
                    #[cfg(test)]
                    if let Some(sh) = shared.clone() {
                        FAKE_DOCKER.with(|f| *f.borrow_mut() = Some(Box::new(move |a: &[&str]| (sh.lock().unwrap_or_else(|e| e.into_inner()))(a))));
                    }
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let Some((image, digest, rel_tag, source)) = rows.get(i) else { break };
                        JOB_LOG.with(|l| *l.borrow_mut() = Some(Vec::new()));
                        let res = stage_lock_image(g, image, digest, rel_tag, source, arches, &release);
                        let lines = JOB_LOG.with(|l| l.borrow_mut().take()).unwrap_or_default();
                        done.lock().unwrap_or_else(|e| e.into_inner())[i] = Some((lines, res));
                    }
                });
            }
        });
        for (lines, res) in done.into_inner().unwrap_or_else(|e| e.into_inner()).into_iter().flatten() {
            for l in lines {
                emit(l);
            }
            for r in res {
                sum.absorb(r);
            }
        }
    }
    // Retention: the release before this one stays (rollback); older go.
    let mut idx = read_index(&dir);
    idx.lock_stage = Some(LockStage { tag: tag.to_string(), failed: sum.failed.clone(), at: now_unix() });
    let prune = lock_tags_to_prune(&idx, tag);
    if !prune.is_empty() {
        idx.images.retain(|r| {
            let drop = r.source == "lock" && prune.contains(&r.release_tag);
            if drop {
                let _ = std::fs::remove_file(dir.join(&r.tar));
                let _ = std::fs::remove_file(dir.join(format!("{}.imageid", r.tar)));
            }
            !drop
        });
        if !g.json {
            ui::done(&format!("pruned staged images of {}", prune.join(", ")));
        }
    }
    if let Err(e) = write_index(&dir, &idx) {
        sum.failed.push(format!("{STAGED_INDEX}: {e}"));
    }
    sum
}

/// Does this desired-config placement, on this node, start the CUDA llama.cpp
/// image: a running llamacpp placement naming no image of its own, not on
/// `cpu` (an undeclared target with `N_GPU_LAYERS=0` is cpu, as the agent and
/// the gateway read it), on a node that can use its GPU
/// ([`crate::commands::cluster_tune::llamacpp_gpu_usable`]).
pub(crate) fn placement_starts_cuda_llamacpp(p: &Value, node: &Value) -> bool {
    let target = p["target"].as_str().map(str::trim).filter(|t| !t.is_empty());
    let legacy_cpu = target.is_none() && p["env"]["N_GPU_LAYERS"].as_str().map(str::trim) == Some("0");
    p["backend"].as_str() == Some("llamacpp")
        && p["desired_state"].as_str() == Some("running")
        && p["image"].as_str().map(str::trim).unwrap_or("").is_empty()
        && target != Some("cpu")
        && !legacy_cpu
        && crate::commands::cluster_tune::llamacpp_gpu_usable(node)
}

/// The [`ON_DEMAND_LOCK_ROWS`] the fleet needs: `llamacpp-cuda` when some
/// amd64 node has a placement that [`placement_starts_cuda_llamacpp`]. Only a
/// node that can use its GPU is asked for its placements.
pub(crate) fn on_demand_rows_for(nodes: &[Value], placements_of: &mut dyn FnMut(&str) -> Option<Value>) -> Vec<String> {
    let wants_cuda = nodes
        .iter()
        .filter(|n| node_arch(n) == Some("amd64") && crate::commands::cluster_tune::llamacpp_gpu_usable(n))
        .any(|n| {
            let id = n["id"].as_str().unwrap_or("");
            !id.is_empty()
                && placements_of(id).is_some_and(|ps| ps.as_array().is_some_and(|a| a.iter().any(|p| placement_starts_cuda_llamacpp(p, n))))
        });
    if wants_cuda { vec!["llamacpp-cuda".to_string()] } else { Vec::new() }
}

/// [`on_demand_rows_for`] from the gateway: the node list, and the
/// desired-config of each node that can use its GPU. Unreadable is "none
/// needed": the place-time refusal (`noo cluster place` stages it then) and
/// the agent's not-staged refusal stay the backstop.
pub(crate) fn on_demand_from_gateway(g: &Globals) -> Vec<String> {
    let nodes = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
        .and_then(|b| b["nodes"].as_array().cloned())
        .unwrap_or_default();
    on_demand_rows_for(&nodes, &mut |id: &str| {
        crate::http::get_json_opt(g, &format!("/api/cluster/nodes/{}/desired-config", crate::commands::urlencode(id)), true, 10).map(|d| d["placements"].clone())
    })
}

/// The fleet's architectures, from the gateway (all nodes, not only online:
/// an offline node still needs its images when it comes back).
pub(crate) fn fleet_arches_from_gateway(g: &Globals) -> Vec<String> {
    let nodes = crate::http::get_json_opt(g, "/api/cluster/nodes", true, 10)
        .and_then(|b| b["nodes"].as_array().cloned())
        .unwrap_or_default();
    fleet_arches(&nodes, &host_arch())
}

fn print_summary(g: &Globals, sum: &Summary) {
    if g.json {
        return;
    }
    ui::done(&format!("{} image(s) staged on the artifact rail", sum.staged.len()));
    for s in &sum.skipped {
        println!("{}", ui::note(s));
    }
    for f in &sum.failed {
        ui::warned(f);
    }
}

/// What the staging thread hands back.
enum StageOutcome {
    /// The release publishes no digest lock: nothing to stage.
    NoLock,
    Done(Summary),
}

/// A node-image staging pass running on its own thread, started BEFORE the
/// launcher so the registry pulls and `docker save` exports overlap the
/// compose pull/recreate. The thread prints NOTHING (it would interleave
/// with the launcher's output): it returns a [`Summary`] and
/// [`StageRun::finish`] prints it under one "Node images" step.
pub(crate) struct StageRun {
    handle: Option<std::thread::JoinHandle<StageOutcome>>,
    tag: String,
}

/// Belt and braces: a run dropped without `finish` (an early return the
/// callers did not anticipate) still joins, so no export is cut off by the
/// process exiting. It cannot print the summary (no Globals), so it says so.
impl Drop for StageRun {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            ui::warned("node image staging was not joined by its caller — waiting for it to finish; its summary is not shown (re-run `noo cluster sync-images --stage-only --lock` to see it)");
            let _ = h.join();
        }
    }
}

/// Start staging the release's node-bound images from the release-signed lock
/// the roll already holds (`lock`, the bytes verified for `tag`; None when the
/// release publishes no lock). The lock and tag are passed in, never re-read
/// from `.env` or the process environment, which still name the RUNNING
/// release until the roll rewrites them.
///
/// Docker safety while the launcher shares the daemon (every path staged here
/// was read): same-arch pulls and the foreign-arch pulls on the containerd
/// store are by lock DIGEST, then tagged `<image>:<this tag>` at that same
/// digest, a reference the running stack does not use and the launcher pins
/// to the identical digest; the foreign-arch pull on the classic store is by
/// platform manifest digest and is saved BY ID, never tagged. No path
/// re-points a reference the controller's compose uses. Concurrent pulls of
/// the same digest are safe in Docker.
///
/// Never fails the roll. Already-staged images are skipped by their
/// `.imageid` marker (or hard-linked from a sibling release's identical
/// export), so a same-tag re-apply is near-free.
pub(crate) fn start_stage_release_images(g: &Globals, lock: Option<String>, tag: &str) -> StageRun {
    // json=true silences every per-image line stage_lock/save_tar would print.
    let mut quiet = g.clone();
    quiet.json = true;
    let tag_owned = tag.to_string();
    let t = tag.to_string();
    let handle = std::thread::spawn(move || {
        let Some(lock) = lock else { return StageOutcome::NoLock };
        let prefix = crate::commands::provision::release_var("NOO_IMAGE_PREFIX");
        let prefix = if prefix.is_empty() { crate::registry::IMAGE_NAMESPACE.to_string() } else { prefix };
        StageOutcome::Done(stage_lock(&quiet, &lock, &prefix, &t, &fleet_arches_from_gateway(&quiet), false, &on_demand_from_gateway(&quiet)))
    });
    StageRun { handle: Some(handle), tag: tag_owned }
}

impl StageRun {
    /// Join and report NOW, before the stack moves, and hand back a run that
    /// is already finished (its later `finish` is a no-op). The new gateway
    /// hands every node the new lock's digest-pinned backend refs the moment
    /// it is up; a rail node whose arch tar is not staged yet refuses the
    /// start (0.6.26 roll: node-pi, `node.reconcile_refused` five times in two
    /// minutes and one operator alert, until the arm64 tar landed at
    /// 16:59:55). Staging first costs the roll about the launch's length.
    pub(crate) fn finish_before_launch(self, g: &Globals) -> StageRun {
        let tag = self.tag.clone();
        self.finish(g);
        StageRun { handle: None, tag }
    }

    /// Join the thread (always; never detach, so no `.exporting` tar is cut
    /// off by a process exit) and print what it did. A panic is reported as a
    /// staging failure AND recorded in the staged index, so the nodes stage's
    /// `lock_stage_blocker` still refuses.
    pub(crate) fn finish(mut self, g: &Globals) {
        let Some(handle) = self.handle.take() else { return };
        match handle.join() {
            Ok(StageOutcome::NoLock) => {
                if !g.json {
                    ui::warned("no stack.lock (a release without a digest lock) — node images were not staged; `noo cluster sync-images <node> -i <image>` stages one by name");
                }
            }
            Ok(StageOutcome::Done(sum)) => {
                if !g.json {
                    ui::step("Node images (staged on the artifact rail before the stack moved; nodes pull them from here, never from a registry)");
                }
                print_summary(g, &sum);
                if !sum.failed.is_empty() && !g.json {
                    ui::guide(&[("noo cluster sync-images --stage-only --lock", "retries staging the release images for every fleet architecture")]);
                }
            }
            Err(_) => {
                let dir = images_store_dir();
                let mut idx = read_index(&dir);
                idx.lock_stage = Some(LockStage {
                    tag: self.tag.clone(),
                    failed: vec!["the staging thread panicked".to_string()],
                    at: now_unix(),
                });
                let _ = write_index(&dir, &idx);
                ui::warned("node image staging crashed (the roll itself is unaffected) — the nodes stage will refuse until it is retried");
                if !g.json {
                    ui::guide(&[("noo cluster sync-images --stage-only --lock", "retries staging the release images for every fleet architecture")]);
                }
            }
        }
    }
}

/// The controller's stack lock, its release tag and image prefix — what
/// phase 1 stages from with `--lock`. Exits with a hint when the lock is
/// missing (a controller that never ran `noo upgrade`).
pub(crate) fn read_controller_lock(g: &Globals) -> (String, String, String) {
    let root = crate::envfile::repo_root();
    match std::fs::read_to_string(root.join("stack.lock")) {
        Ok(l) => lock_release(l),
        Err(e) => crate::output::fail(g.json, crate::output::ExitCode::Generic, "no_stack_lock",
            &format!("cannot read {}: {e}", root.join("stack.lock").display()),
            Some("noo upgrade   # verifies and writes the release-signed lock, then stages")),
    }
}

/// A lock's text with the image prefix and release tag it is staged under.
fn lock_release(lock: String) -> (String, String, String) {
    let tag = lock.lines().find_map(|l| l.strip_prefix("# tag ").map(|t| t.trim().to_string()))
        .unwrap_or_else(|| crate::commands::provision::release_var("NOO_IMAGE_TAG"));
    let prefix = crate::commands::provision::release_var("NOO_IMAGE_PREFIX");
    let prefix = if prefix.is_empty() { crate::registry::IMAGE_NAMESPACE.to_string() } else { prefix };
    (lock, prefix, tag)
}

/// [`read_controller_lock`] that never exits: None when this host has no
/// stack lock. Any other read error is an Err (an unreadable lock is not an
/// absent one).
pub(crate) fn controller_lock_opt() -> Result<Option<LockRelease>, String> {
    let path = crate::envfile::repo_root().join("stack.lock");
    lock_opt_from(std::fs::read_to_string(&path)).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// A stack lock's text, image prefix and release tag.
pub(crate) type LockRelease = (String, String, String);

fn lock_opt_from(read: std::io::Result<String>) -> Result<Option<LockRelease>, std::io::Error> {
    match read {
        Ok(l) => Ok(Some(lock_release(l))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// What the release pins `image` to, as `stage_lock` stages it:
/// `(sha256:…, release tag, source)`. A pinned door's ref (`door-pin`, its
/// own tag) first, as `stage_lock` stages a lock row equal to a pin as the
/// pin; else a lock row whose `<prefix>/<name>:<tag>` is exactly `image`
/// (`lock`, the lock's tag; third-party rows are never ours). None for an
/// image the release does not carry.
pub(crate) fn lock_pin_for(image: &str, lock: &str, prefix: &str, tag: &str) -> Option<(String, String, &'static str)> {
    let prefix = prefix.trim_end_matches('/');
    if let Some((_, digest, pin_tag)) = door_pin_refs(prefix).into_iter().find(|(p, ..)| p == image) {
        return Some((digest, pin_tag, DOOR_PIN_SOURCE));
    }
    parse_lock(lock)
        .into_iter()
        .filter(|r| stages_from_lock(&r.name, true))
        .find(|r| format!("{prefix}/{}:{tag}", r.name) == image)
        .map(|r| (r.digest, tag.to_string(), "lock"))
}

/// Every ref [`lock_pin_for`] answers for: the lock's release images and the
/// pinned doors.
pub(crate) fn lock_pinned_refs(lock: &str, prefix: &str, tag: &str) -> Vec<String> {
    let prefix = prefix.trim_end_matches('/');
    let mut refs: Vec<String> = parse_lock(lock).into_iter().filter(|r| stages_from_lock(&r.name, true)).map(|r| format!("{prefix}/{}:{tag}", r.name)).collect();
    for (image, ..) in door_pin_refs(prefix) {
        if !refs.contains(&image) {
            refs.push(image);
        }
    }
    refs
}

/// [`lock_pinned_refs`] of this controller's lock; empty with no readable lock
/// (a node, or a controller that never ran `noo upgrade`).
pub(crate) fn lock_pinned_refs_here() -> Vec<String> {
    match controller_lock_opt() {
        Ok(Some((l, p, t))) => lock_pinned_refs(&l, &p, &t),
        _ => Vec::new(),
    }
}

/// The remedy that stages `image` for `arch`: a release-pinned image by its
/// lock digest (`--stage-only --lock`), anything else by name with `-i`.
pub(crate) fn stage_remedy(image: &str, arch: &str, pinned: bool) -> String {
    if pinned {
        format!("{RESTAGE_BY_LOCK}   # the release pins {image}: it is staged by its lock digest")
    } else {
        format!("noo cluster sync-images --stage-only -i {image} --arch {arch}")
    }
}

/// The `<prefix>/<name>:<tag>` refs of the lock's node-bound release images,
/// and each pinned door's ref — what a node pulls after `--lock` staged them
/// (never `--all-images` rows).
pub(crate) fn lock_node_refs(lock: &str, prefix: &str, tag: &str) -> Vec<String> {
    let prefix = prefix.trim_end_matches('/');
    let mut refs: Vec<String> = parse_lock(lock).into_iter().filter(|r| stages_from_lock(&r.name, false)).map(|r| format!("{prefix}/{}:{tag}", r.name)).collect();
    for (image, ..) in door_pin_refs(prefix) {
        if !refs.contains(&image) {
            refs.push(image);
        }
    }
    refs
}

/// Phase 1 of `noo cluster sync-images`, shared with the verb's
/// `--stage-only`: stage the lock's release images (`from_lock`, with
/// `all` adding the controller-only ones) and/or the named `images`, for
/// each of `arches`, on the artifact rail. Prints each step; the caller
/// prints the summary. `source` is recorded in the staged index.
pub(crate) fn stage_selection(g: &Globals, images: &[String], arches: &[String], from_lock: bool, all: bool, source: &str) -> Summary {
    let mut sum = Summary::default();
    if from_lock {
        let (lock, prefix, tag) = read_controller_lock(g);
        sum = stage_lock(g, &lock, &prefix, &tag, arches, all, &on_demand_from_gateway(g));
    }
    for img in images {
        for arch in arches {
            let label = format!("{img} ({arch})");
            if !g.json {
                ui::step(&format!("staging {label}"));
            }
            match stage_and_record(g, img, arch, source) {
                Ok(_) => sum.staged.push(label),
                Err(e) if no_variant_is_skip(img, arch, &e) => sum.skipped.push(format!("{label}: not published for {arch}")),
                Err(e) => sum.failed.push(format!("{label}: {e}")),
            }
        }
    }
    sum
}

/// `noo cluster sync-images --stage-only`: phase 1 and stop. With no `-i`
/// the lock is staged (`from_lock` is implied). Arches default to the fleet's.
pub(crate) fn run_stage_only(g: &Globals, images: &[String], arches: &[String], from_lock: bool, all: bool) -> i32 {
    let from_lock = from_lock || images.is_empty();
    let arches = if arches.is_empty() { fleet_arches_from_gateway(g) } else { arches.to_vec() };
    let sum = stage_selection(g, images, &arches, from_lock, all, "sync-images");
    if g.json {
        println!("{}", serde_json::json!({"staged": sum.staged, "skipped": sum.skipped, "failed": sum.failed}));
    } else {
        print_summary(g, &sum);
    }
    if sum.failed.is_empty() { 0 } else { 1 }
}

/// The image a placement needs staged, when it can be named — the CLI twin
/// of the gateway's `placement_required_image` (same rule, same tests).
/// `on_gpu`: llamacpp starts the CUDA build there (amd64 only).
pub(crate) fn placement_required_image(backend: &str, image: Option<&str>, arch: &str, release: Option<&Release>, roots: &[&str], on_gpu: bool) -> Option<String> {
    if let Some(img) = image.map(str::trim).filter(|i| !i.is_empty()) {
        let mut all: Vec<&str> = roots.to_vec();
        if let Some(r) = release {
            all.push(r.prefix.as_str());
        }
        return is_own_image_with(img, &all).then(|| img.to_string());
    }
    let r = release?;
    let name = if on_gpu { "llamacpp-cuda" } else { "llamacpp" };
    (backend == "llamacpp" && arch == "amd64").then(|| format!("{}/{name}:{}", r.prefix.trim_end_matches('/'), r.tag))
}

/// Running placements whose image is not staged for the node's arch — the
/// `images staged` verify row's input. Empty when the store is not here.
/// `node` is the node's record: a llamacpp placement on a GPU it can use
/// needs the CUDA build staged, any other the CPU one.
pub(crate) fn unstaged_for(placements: &Value, arch: &str, node: &Value) -> Vec<String> {
    let dir = images_store_dir();
    if !dir.is_dir() {
        return Vec::new();
    }
    let idx = read_index(&dir);
    let mut out: Vec<String> = placements
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["desired_state"].as_str() == Some("running") && p["backend"].as_str() != Some("harness"))
        .filter_map(|p| {
            let roots: Vec<&str> = idx.own_roots.iter().map(String::as_str).collect();
            placement_required_image(p["backend"].as_str().unwrap_or(""), p["image"].as_str(), arch, idx.release.as_ref(), &roots, placement_starts_cuda_llamacpp(p, node))
        })
        .filter(|img| !image_staged_in(&dir, img, arch))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Parse the gateway's place-time refusal: `image <ref> for <arch> is not
/// staged on the controller` → (ref, arch).
pub(crate) fn parse_not_staged(msg: &str) -> Option<(String, String)> {
    let i = msg.find(" is not staged on the controller")?;
    let head = &msg[..i];
    let start = head.rfind("image ")? + "image ".len();
    let (img, arch) = head[start..].rsplit_once(" for ")?;
    let arch = normalize_arch(arch)?;
    // The caller stages what this returns, so hand it the staged name.
    let img = staged_ref(img);
    (!img.is_empty() && !img.contains(' ')).then(|| (img.to_string(), arch.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The roll joins staging before the stack moves: a still-running stage
    /// is finished by the time `finish_before_launch` returns, and what it
    /// hands back is already finished (launch_stack's own finish is a no-op).
    #[test]
    fn finish_before_launch_joins_the_staging_thread_first() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            d.store(true, Ordering::SeqCst);
            StageOutcome::NoLock
        });
        let g = crate::Globals { json: true, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: false };
        let run = StageRun { handle: Some(handle), tag: "v0.6.27".into() };
        let after = run.finish_before_launch(&g);
        assert!(done.load(Ordering::SeqCst), "staging finished before the launch could start");
        assert!(after.handle.is_none(), "the run handed to launch_stack is already finished");
        assert_eq!(after.tag, "v0.6.27");
        after.finish(&g); // a no-op
    }
    use serde_json::json;

    const D: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn lock_rows_parse_and_node_bound_filters_controller_images() {
        // The shapes a real lock carries (stack-v0.2.103): provenance rows
        // `source:` / `protocols:` / `retagged-from:` are not images.
        let lock = format!("# tag v0.2.103\ngateway@{D}\nllamacpp@{D}\nsource:trellion@abc\nprotocols:trellion@personifAI/trellion-protocols#7c17;schema_rev=105\nretagged-from:stack-v0.2.103-rc.1@328374a2\nnode-agent@{D}\nbad@sha256:xyz\n\npostgres-pgvector@{D}\nstunnel@{D}\n");
        let rows = parse_lock(&lock);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["gateway", "llamacpp", "node-agent", "postgres-pgvector", "stunnel"]);
        let bound: Vec<&str> = names.iter().copied().filter(|n| node_bound(n)).collect();
        assert_eq!(bound, ["llamacpp", "node-agent", "stunnel"]);
        assert!(!node_bound("deps-core"));
        assert!(!node_bound("evolve") && !node_bound("trellion-intel"));
    }

    #[test]
    fn a_missing_variant_of_our_published_image_is_a_failure_not_a_skip() {
        let e = format!("{NO_VARIANT} arm64: x publishes only amd64");
        // llamacpp / ollama are published for both arches: a stage that cannot
        // produce one is a FAILURE (the node would otherwise have no image).
        for img in ["llamacpp", "ollama", "ghcr.io/noomesh/ollama:v0.6.16", "ghcr.io/noomesh/llamacpp:v0.6.16@sha256:aa"] {
            for arch in ["amd64", "arm64"] {
                assert!(!no_variant_is_skip(img, arch, &e), "{img} {arch}");
            }
        }
        // An image we genuinely do not publish for that arch, or an arch we do not publish: still a skip.
        assert!(no_variant_is_skip("nvidia-exporter", "arm64", &e));
        assert!(no_variant_is_skip("ollama", "riscv64", &e));
        // Any other error is never a skip.
        assert!(!no_variant_is_skip("nvidia-exporter", "arm64", "boom"));
        assert!(own_image_published("ghcr.io/noomesh/ollama:v1", "arm64") && !own_image_published("ghcr.io/noomesh/stunnel:v1", "arm64"));
    }

    #[test]
    fn a_third_party_lock_row_is_never_staged() {
        // `nats@sha256:` pins docker.io/library/nats:<version> for the
        // controller's own start; it is not `<prefix>/nats:<tag>`, so a
        // stage would ask the release registry for an image it never had.
        // `ollama` is OUR hardened image (docker/Dockerfile.ollama, i323) and
        // IS staged for the nodes.
        let lock = format!("# tag v0.6.5\ngateway@{D}\nnats@{D}\nollama@{D}\nllamacpp@{D}\n");
        let rows = parse_lock(&lock);
        assert!(rows.iter().any(|r| r.name == "nats"), "the row parses like any other");
        for all in [false, true] {
            let staged: Vec<&str> = rows.iter().map(|r| r.name.as_str()).filter(|n| stages_from_lock(n, all)).collect();
            assert!(!staged.contains(&"nats"), "all={all}: {staged:?}");
            assert!(staged.contains(&"llamacpp") && staged.contains(&"ollama"), "all={all}: {staged:?}");
        }
        assert!(stages_from_lock("gateway", true) && !stages_from_lock("gateway", false));
    }

    #[test]
    fn fleet_arches_include_the_pi() {
        let nodes = vec![
            json!({"id": "host8", "capabilities": {"arch": "amd64"}}),
            json!({"id": "host9", "capabilities": {"tier": 4}}),
            json!({"id": "mac", "capabilities": {"arch": "arm64"}}),
            json!({"id": "old"}),
        ];
        assert_eq!(fleet_arches(&nodes, "amd64"), ["amd64", "arm64"]);
        assert_eq!(fleet_arches(&[], "amd64"), ["amd64"]);
        assert_eq!(node_arch(&json!({"is_arm": true})), Some("arm64"));
        assert_eq!(node_arch(&json!({"arch": "x86_64"})), Some("amd64"));
        assert_eq!(node_arch(&json!({})), None);
    }

    #[test]
    fn repo_and_tar_names() {
        assert_eq!(repo_of("ghcr.io/x/llamacpp:v1"), "ghcr.io/x/llamacpp");
        assert_eq!(repo_of("localhost:5000/a/b:t"), "localhost:5000/a/b");
        assert_eq!(repo_of("localhost:5000/a/b"), "localhost:5000/a/b");
        assert_eq!(repo_of("alpine"), "alpine");
        // Same convention as Go ImageTarName and the gateway twin.
        assert_eq!(image_tar_name("ghcr.io/x/y:z", "arm64"), "ghcr.io_x_y_z_arm64.tar");
    }

    fn rec(image: &str, arch: &str, tag: &str, at: u64) -> StagedRecord {
        StagedRecord { image: image.into(), arch: arch.into(), tar: image_tar_name(image, arch), image_id: String::new(),
            lock_digest: D.into(), source: "lock".into(), release_tag: tag.into(), staged_at: at }
    }

    #[test]
    fn upsert_replaces_per_ref_and_arch() {
        let mut idx = StagedIndex::default();
        upsert(&mut idx, rec("p/a:v1", "amd64", "v1", 1));
        upsert(&mut idx, rec("p/a:v1", "arm64", "v1", 1));
        upsert(&mut idx, rec("p/a:v1", "amd64", "v1", 2));
        assert_eq!(idx.images.len(), 2);
        assert_eq!(idx.images[0].staged_at, 2);
        // And the gateway can read what this writes (field names are the contract).
        let s = serde_json::to_value(&idx).unwrap();
        assert_eq!(s["images"][0]["ref"], "p/a:v1");
        assert!(s["images"][0].get("lock_digest").is_some());
    }

    #[test]
    fn retention_keeps_current_and_one_previous_release() {
        let mut idx = StagedIndex::default();
        for (t, at) in [("v1", 10), ("v2", 20), ("v3", 30), ("v4", 40)] {
            upsert(&mut idx, rec(&format!("p/a:{t}"), "amd64", t, at));
        }
        let mut manual = rec("ollama/ollama:latest", "amd64", "", 1);
        manual.source = "sync-images".into();
        upsert(&mut idx, manual);
        // A pinned door from an old release is not a release row.
        let mut pin = rec("p/stunnel:v0", "amd64", "v0", 1);
        pin.source = DOOR_PIN_SOURCE.into();
        upsert(&mut idx, pin);
        let mut p = lock_tags_to_prune(&idx, "v4");
        p.sort();
        assert_eq!(p, ["v1", "v2"], "v4 current, v3 kept for rollback; a by-name stage and a door pin are never pruned");
    }

    /// vLLM's door is pinned to its own stunnel image (config/door-images.json,
    /// the file the node agent embeds): every lock stage stages it under its
    /// own tag, and a node is told to pull it, whatever release is current.
    #[test]
    fn the_pinned_door_is_staged_with_every_release() {
        let pins = door_pin_refs("reg.example/acme/");
        assert_eq!(pins.len(), 1, "{pins:?}");
        let (image, digest, tag) = &pins[0];
        assert_eq!(image, &format!("reg.example/acme/stunnel:{tag}"));
        assert!(tag.starts_with('v') && digest.len() == "sha256:".len() + 64, "{pins:?}");
        // Another release's lock: its own stunnel row AND the pin.
        let lock = format!("# tag v9.9.9
stunnel@{D}
llamacpp@{D}
gateway@{D}
");
        let refs = lock_node_refs(&lock, "reg.example/acme", "v9.9.9");
        assert_eq!(refs, ["reg.example/acme/stunnel:v9.9.9", "reg.example/acme/llamacpp:v9.9.9", image.as_str()]);
        // The pin's own release: one ref, not two.
        let refs = lock_node_refs(&lock, "reg.example/acme", tag);
        assert_eq!(refs.iter().filter(|r| *r == image).count(), 1, "{refs:?}");
        // The digest staged is the file's, as written.
        let v: serde_json::Value = serde_json::from_str(DOOR_IMAGES_JSON).unwrap();
        assert!(v["doors"]["vllm"]["digest"].as_str().is_some_and(|d| d == digest.as_str()));
    }

    /// The CUDA llama.cpp row (~3 GB) is never staged by a lock stage or
    /// pulled by `sync-images --lock`; it is staged only when an amd64 node
    /// that can use its GPU has a running llamacpp placement that starts it.
    #[test]
    fn the_cuda_llamacpp_row_is_staged_only_for_a_node_that_runs_llamacpp_on_its_gpu() {
        assert!(!node_bound("llamacpp-cuda") && node_bound("llamacpp"));
        assert!(!stages_from_lock("llamacpp-cuda", false), "a roll never stages it by default");
        let lock = format!("llamacpp@sha256:{}\nllamacpp-cuda@sha256:{}\n", "a".repeat(64), "b".repeat(64));
        assert!(!lock_node_refs(&lock, "reg.example/acme", "v1").iter().any(|r| r.contains("llamacpp-cuda")), "sync-images --lock never pushes it");
        assert!(own_image_published("llamacpp-cuda", "amd64") && !own_image_published("llamacpp-cuda", "arm64"));

        let gpu = |id: &str, cap: &str| json!({"id": id, "capabilities": {"arch": "x86_64", "vram_gb": 8.0}, "nvidia_runtime": true, "gpu_compute_cap": cap});
        let place = |target: Option<&str>| {
            let mut p = json!({"backend": "llamacpp", "model": "m.gguf", "desired_state": "running"});
            if let Some(t) = target {
                p["target"] = json!(t);
            }
            json!([p])
        };
        fn ask(nodes: &[Value], ps: &Value) -> (Vec<String>, Vec<String>) {
            let mut asked = Vec::new();
            let rows = on_demand_rows_for(nodes, &mut |id: &str| {
                asked.push(id.to_string());
                Some(ps.clone())
            });
            (rows, asked)
        }
        let cuda = vec!["llamacpp-cuda".to_string()];
        assert_eq!(ask(&[gpu("node-a", "6.1")], &place(Some("gpu"))).0, cuda);
        assert_eq!(ask(&[gpu("node-a", "8.6")], &place(None)).0, cuda, "no target on a usable node runs on the GPU");
        assert!(ask(&[gpu("node-a", "8.6")], &place(Some("cpu"))).0.is_empty(), "a cpu placement");
        assert!(ask(&[gpu("node-a", "5.2")], &place(Some("gpu"))).0.is_empty(), "a GPU below the image's lowest arch");
        let cpu_node = json!({"id": "node-b", "capabilities": {"arch": "x86_64", "ram_gb": 16.0}});
        let arm = json!({"id": "node-c", "capabilities": {"arch": "aarch64", "vram_gb": 8.0}, "nvidia_runtime": true, "gpu_compute_cap": "8.7"});
        let (rows, asked) = ask(&[cpu_node, arm], &place(Some("gpu")));
        assert!(rows.is_empty());
        assert!(asked.is_empty(), "only an amd64 node that can use its GPU is asked for its placements: {asked:?}");
        let legacy = json!([{"backend": "llamacpp", "model": "m.gguf", "desired_state": "running", "env": {"N_GPU_LAYERS": "0"}}]);
        assert!(!placement_starts_cuda_llamacpp(&legacy[0], &gpu("node-a", "8.6")), "no target + N_GPU_LAYERS=0 is cpu");
    }

    #[test]
    fn placement_required_image_matches_the_gateway_rule() {
        let rel = Release { prefix: "reg.example/acme".into(), tag: "v0.2.103".into() };
        assert_eq!(placement_required_image("llamacpp", None, "amd64", Some(&rel), &[], false).as_deref(), Some("reg.example/acme/llamacpp:v0.2.103"));
        assert!(placement_required_image("llamacpp", None, "arm64", Some(&rel), &[], false).is_none());
        assert!(placement_required_image("vllm", Some("vllm/vllm-openai:latest"), "amd64", Some(&rel), &[], false).is_none());
        assert_eq!(placement_required_image("x", Some("noo-browser:latest"), "amd64", None, &[], false).as_deref(), Some("noo-browser:latest"));
        assert_eq!(placement_required_image("x", Some("reg.example/acme/vllm:v1"), "amd64", Some(&rel), &[], false).as_deref(), Some("reg.example/acme/vllm:v1"));
        // llamacpp on a node's GPU: the CUDA build (amd64 only).
        assert_eq!(placement_required_image("llamacpp", None, "amd64", Some(&rel), &[], true).as_deref(), Some("reg.example/acme/llamacpp-cuda:v0.2.103"));
        // The old `contains("/noomesh/")` said yes here; the shared rule says no.
        assert!(placement_required_image("x", Some("quay.io/someone/noomesh/x:1"), "amd64", Some(&rel), &[], false).is_none());
    }

    #[test]
    fn the_gateway_refusal_parses() {
        let msg = "HTTP 409: {\"error\":\"image reg.example/acme/llamacpp:v1 for amd64 is not staged on the controller, so host8-ma cannot start it ...\"}";
        assert_eq!(parse_not_staged(msg), Some(("reg.example/acme/llamacpp:v1".into(), "amd64".into())));
        assert_eq!(parse_not_staged("does not fit the node's memory"), None);
    }

    #[test]
    fn staged_names_match_the_shared_fixture() {
        let fx: Value = serde_json::from_str(include_str!("../../../tests/fixtures/own_image_cases.json")).unwrap();
        let rows = fx["staged_names"].as_array().expect("staged_names table");
        assert!(rows.len() >= 4, "fixture parse found {} staged_names rows", rows.len());
        for row in rows {
            let (r, arch) = (row["ref"].as_str().unwrap(), row["arch"].as_str().unwrap());
            assert_eq!(staged_ref(r), row["staged_ref"].as_str().unwrap(), "{r}");
            assert_eq!(image_tar_gz_name(staged_ref(r), arch), row["tar_gz"].as_str().unwrap(), "{r}");
        }
    }

    #[test]
    fn a_digest_pinned_placement_is_staged_under_its_tag() {
        // 2026-11-05, after the 0.6.16 roll: every node's `images staged` row
        // warned that ghcr.io/noomesh/ollama:v0.6.16@sha256:e6def24... was not
        // staged while the rail held its tag-named tars.
        let dir = std::env::temp_dir().join(format!("noo-stage-digest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tag = "registry.local:5000/noomesh/ollama:v0.6.16";
        let pinned = format!("{tag}@{D}");
        assert!(!image_staged_in(&dir, &pinned, "arm64"));
        std::fs::write(dir.join(image_tar_gz_name(tag, "arm64")), b"x").unwrap();
        assert!(image_staged_in(&dir, &pinned, "arm64"), "a digest-pinned ref is staged under its tag");
        assert!(image_staged_in(&dir, tag, "arm64"));
        assert!(!image_staged_in(&dir, &pinned, "amd64"), "the other arch is still unstaged");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_not_staged_refusal_for_a_pinned_ref_stages_the_tag() {
        let msg = ["HTTP 409: image reg.example:5000/acme/llamacpp:v1@", D, " for arm64 is not staged on the controller, so host8-ma cannot start it"].concat();
        assert_eq!(parse_not_staged(&msg), Some(("reg.example:5000/acme/llamacpp:v1".into(), "arm64".into())));
    }

    #[test]
    fn own_image_rule_matches_the_shared_fixture() {
        let fx: Value = serde_json::from_str(include_str!("../../../tests/fixtures/own_image_cases.json")).unwrap();
        let roots: Vec<&str> = fx["roots"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        let cases = fx["cases"].as_array().unwrap();
        assert!(cases.len() >= 10, "fixture parse found {} cases", cases.len());
        for c in cases {
            let r = c["ref"].as_str().unwrap();
            assert_eq!(is_own_image_with(r, &roots), c["own"].as_bool().unwrap(), "{r}");
        }
    }

    #[test]
    fn pick_platform_reads_both_inspect_shapes() {
        let arm = format!("sha256:{}", "b".repeat(64));
        let amd = format!("sha256:{}", "a".repeat(64));
        let buildx = json!({"mediaType": "application/vnd.oci.image.index.v1+json", "digest": D, "manifests": [
            {"digest": amd, "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": arm, "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
            {"digest": D, "platform": {"os": "unknown", "architecture": "unknown"}}]});
        assert_eq!(pick_platform(&buildx, "arm64"), PlatformPick::Manifest(arm.clone()));
        assert_eq!(pick_platform(&buildx, "amd64"), PlatformPick::Manifest(amd.clone()));
        let amd_only = json!({"manifests": [{"digest": amd, "platform": {"os": "linux", "architecture": "amd64"}}]});
        assert_eq!(pick_platform(&amd_only, "arm64"), PlatformPick::Missing);
        let manifest_v = json!([{"Descriptor": {"digest": arm, "platform": {"os": "linux", "architecture": "arm64"}}}]);
        assert_eq!(pick_platform(&manifest_v, "arm64"), PlatformPick::Manifest(arm.clone()));
        let single = json!({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": amd});
        assert_eq!(pick_platform(&single, "arm64"), PlatformPick::Single(amd.clone()));
        let single_v = json!({"Descriptor": {"digest": amd, "platform": {"os": "linux", "architecture": "amd64"}}});
        assert_eq!(pick_platform(&single_v, "arm64"), PlatformPick::Missing);
    }

    // ── stage_image against a scripted daemon ──

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn g() -> Globals {
        Globals { json: true, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: true }
    }

    struct Daemon {
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }

    /// Install a fake daemon. `respond` maps an invocation (joined args) to
    /// its answer; `save -o <tmp>` writes the file like the real one.
    fn daemon(respond: impl Fn(&str) -> Result<String, String> + 'static) -> Daemon {
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let rec = calls.clone();
        FAKE_DOCKER.with(|f| {
            *f.borrow_mut() = Some(Box::new(move |args: &[&str]| {
                let line = args.join(" ");
                rec.borrow_mut().push(line.clone());
                if args.first() == Some(&"save") {
                    std::fs::write(args[2], b"tar").map_err(|e| e.to_string())?;
                    // Like a newer Docker CLI: the -o file is created 0600.
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(args[2], std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
                    return Ok(String::new());
                }
                respond(&line)
            }));
        });
        Daemon { calls }
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            FAKE_DOCKER.with(|f| *f.borrow_mut() = None);
        }
    }

    fn store(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-stage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::env::set_var("IMAGES_DIR", &d);
        d
    }

    const REPO: &str = "reg.example/acme/node-agent";

    fn index_json() -> String {
        json!({"mediaType": "application/vnd.oci.image.index.v1+json", "digest": D, "manifests": [
            {"digest": format!("sha256:{}", "a".repeat(64)), "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": format!("sha256:{}", "b".repeat(64)), "platform": {"os": "linux", "architecture": "arm64"}}]}).to_string()
    }

    /// THE review finding: a foreign stage on the classic store must never
    /// pull under a shared reference (the lock's index digest, the tag) and
    /// never tag — it pulls the per-platform digest and saves by ID.
    #[test]
    fn foreign_arch_on_the_classic_store_never_touches_a_shared_reference() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("foreign");
        let arm_ref = format!("{REPO}@sha256:{}", "b".repeat(64));
        let arm_ref2 = arm_ref.clone();
        let d = daemon(move |l| match l {
            l if l.starts_with("version") => Ok("amd64".into()),
            l if l.starts_with("info") => Ok("[[\"Backing Filesystem\",\"extfs\"]]".into()),
            l if l.starts_with("buildx imagetools inspect") => Ok(index_json()),
            l if l == format!("pull -q --platform linux/arm64 {arm_ref2}") => Ok(String::new()),
            l if l == format!("image inspect --format {{{{.Id}}}} {{{{.Architecture}}}} {arm_ref2}") => Ok("sha256:armid arm64".into()),
            other => Err(format!("unexpected: {other}")),
        });
        let rec = stage_image(&g(), &format!("{REPO}:v1"), "arm64", Some(D), "lock").expect("stage");
        let calls = d.calls.borrow().clone();
        assert!(calls.iter().all(|c| !c.starts_with("tag ")), "no tag on a foreign stage: {calls:?}");
        let index_ref = format!("{REPO}@{D}");
        assert!(calls.iter().all(|c| !(c.starts_with("pull") && c.ends_with(&index_ref))), "never pull the shared index ref: {calls:?}");
        assert!(calls.iter().any(|c| c == &format!("pull -q --platform linux/arm64 {arm_ref}")), "{calls:?}");
        assert_eq!(calls.iter().filter(|c| c.starts_with("pull")).count(), 1, "no restore pull: {calls:?}");
        assert!(calls.iter().any(|c| c.starts_with("save -o") && c.ends_with(" sha256:armid")), "saved by ID: {calls:?}");
        assert_eq!(rec.image_id, "sha256:armid");
        assert_eq!(rec.tar, image_tar_gz_name(&format!("{REPO}:v1"), "arm64"));
        assert!(dir.join(&rec.tar).is_file() && dir.join(format!("{}.imageid", rec.tar)).is_file());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join(&rec.tar)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the model-cache's nginx must be able to read the staged tar");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn foreign_arch_not_published_is_a_skip_without_a_pull() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("missing");
        let only_amd = json!({"manifests": [{"digest": format!("sha256:{}", "a".repeat(64)), "platform": {"os": "linux", "architecture": "amd64"}}]}).to_string();
        let d = daemon(move |l| match l {
            l if l.starts_with("version") => Ok("amd64".into()),
            l if l.starts_with("info") => Ok("[]".into()),
            l if l.starts_with("buildx imagetools inspect") => Ok(only_amd.clone()),
            other => Err(format!("unexpected: {other}")),
        });
        let err = stage_image(&g(), &format!("{REPO}:v1"), "arm64", Some(D), "lock").unwrap_err();
        assert!(err.starts_with(NO_VARIANT), "{err}");
        assert!(d.calls.borrow().iter().all(|c| !c.starts_with("pull") && !c.starts_with("tag")), "{:?}", d.calls.borrow());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Host path: the architecture is checked on the pulled image BEFORE the
    /// release tag is moved; a wrong-arch digest never gets the tag.
    #[test]
    fn host_path_checks_the_architecture_before_tagging() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("host-bad");
        let d = daemon(move |l| match l {
            l if l.starts_with("version") => Ok("amd64".into()),
            l if l.starts_with("image inspect") => Ok("sha256:x arm64".into()),
            other => Err(format!("unexpected: {other}")),
        });
        let err = stage_image(&g(), &format!("{REPO}:v1"), "amd64", Some(D), "lock").unwrap_err();
        assert!(err.starts_with(NO_VARIANT), "{err}");
        assert!(d.calls.borrow().iter().all(|c| !c.starts_with("tag")), "{:?}", d.calls.borrow());
        drop(d);

        let dir2 = store("host-ok");
        let d = daemon(move |l| match l {
            l if l.starts_with("version") => Ok("amd64".into()),
            l if l.starts_with("image inspect") => Ok("sha256:hostid amd64".into()),
            l if l.starts_with("tag ") => Ok(String::new()),
            other => Err(format!("unexpected: {other}")),
        });
        let rec = stage_image(&g(), &format!("{REPO}:v1"), "amd64", Some(D), "lock").expect("stage");
        let calls = d.calls.borrow().clone();
        let tag_at = calls.iter().position(|c| c.starts_with("tag ")).expect("tagged");
        let inspect_at = calls.iter().position(|c| c.starts_with("image inspect")).unwrap();
        assert!(inspect_at < tag_at, "inspect before tag: {calls:?}");
        assert!(calls.iter().any(|c| c.starts_with("save -o") && c.ends_with(" sha256:hostid")), "saved by ID: {calls:?}");
        assert_eq!(rec.image_id, "sha256:hostid");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn a_tar_already_staged_at_the_same_id_is_not_re_exported() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("same-id");
        let tar = image_tar_gz_name(&format!("{REPO}:v1"), "amd64");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(&tar), b"old").unwrap();
        std::fs::write(dir.join(format!("{tar}.imageid")), "sha256:hostid\n").unwrap();
        let d = daemon(move |l| match l {
            l if l.starts_with("version") => Ok("amd64".into()),
            l if l.starts_with("image inspect") => Ok("sha256:hostid amd64".into()),
            l if l.starts_with("tag ") => Ok(String::new()),
            other => Err(format!("unexpected: {other}")),
        });
        stage_image(&g(), &format!("{REPO}:v1"), "amd64", Some(D), "lock").expect("stage");
        assert!(d.calls.borrow().iter().all(|c| !c.starts_with("save")), "{:?}", d.calls.borrow());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE cause of "re-exported though nothing changed": the file name embeds
    /// the release tag, so a new release never found its own sidecar. An
    /// export of the same image id under the PREVIOUS release's name is
    /// linked, not re-saved.
    #[test]
    fn the_same_image_id_under_the_previous_release_name_is_not_re_exported() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("prev-release");
        let old = image_tar_gz_name(&format!("{REPO}:v1"), "amd64");
        let new = image_tar_gz_name(&format!("{REPO}:v2"), "amd64");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(&old), b"bytes").unwrap();
        std::fs::write(dir.join(format!("{old}.imageid")), "sha256:hostid\n").unwrap();
        let d = daemon(move |l| match l {
            l if l.starts_with("version") => Ok("amd64".into()),
            l if l.starts_with("info") => Ok(String::new()),
            l if l.starts_with("image inspect") => Ok("sha256:hostid amd64".into()),
            l if l.starts_with("tag ") => Ok(String::new()),
            other => Err(format!("unexpected: {other}")),
        });
        let rec = stage_image(&g(), &format!("{REPO}:v2"), "amd64", Some(D), "lock").expect("stage");
        assert!(d.calls.borrow().iter().all(|c| !c.starts_with("save")), "{:?}", d.calls.borrow());
        assert_eq!(rec.tar, new);
        assert_eq!(std::fs::read(dir.join(&new)).unwrap(), b"bytes");
        assert_eq!(std::fs::read_to_string(dir.join(format!("{new}.imageid"))).unwrap().trim(), "sha256:hostid");
        assert!(dir.join(&old).is_file(), "the previous release keeps its own name (rollback)");
        // A DIFFERENT id is exported.
        std::fs::write(dir.join(format!("{old}.imageid")), "sha256:other\n").unwrap();
        let _ = std::fs::remove_file(dir.join(&new));
        let _ = std::fs::remove_file(dir.join(format!("{new}.imageid")));
        stage_image(&g(), &format!("{REPO}:v2"), "amd64", Some(D), "lock").expect("stage");
        assert!(d.calls.borrow().iter().any(|c| c.starts_with("save")), "different id must export");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The pipe is only as honest as its first stage: a failing producer with
    /// a happy gzip must be an ERROR (the pipe-to-tail trap), and a good one
    /// must round-trip through gunzip.
    #[test]
    fn a_failing_producer_is_not_masked_by_a_successful_gzip() {
        let Some(gz) = on_path(&["gzip"]) else { return };
        let dir = std::env::temp_dir().join(format!("noo-pipegz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("o.gz");
        let mut bad = Command::new("sh");
        bad.args(["-c", "echo partial; echo boom >&2; exit 3"]);
        let e = pipe_gz(bad, "fake save", &gz, &out).expect_err("must fail");
        assert!(e.contains("boom"), "{e}");
        let mut good = Command::new("sh");
        good.args(["-c", "printf hello"]);
        pipe_gz(good, "fake save", &gz, &out).expect("ok");
        let back = Command::new(&gz).args(["-dc"]).arg(&out).output().unwrap();
        assert_eq!(back.stdout, b"hello");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_gz_name_is_the_tar_name_plus_gz() {
        assert_eq!(image_tar_gz_name("ghcr.io/x/y:z", "arm64"), "ghcr.io_x_y_z_arm64.tar.gz");
        for (i, a) in [("pai-assistant/node-agent:latest", "amd64"), ("noo-sandbox-base:latest", "arm64")] {
            assert_eq!(image_tar_gz_name(i, a), format!("{}.gz", image_tar_name(i, a)));
        }
    }

    /// An uncompressed tar left by an older controller does NOT count as the
    /// gz export (nodes ask for `.tar.gz` first): it is re-exported, and the
    /// stale plain tar and its sidecar are removed once the gz is in place.
    #[test]
    fn a_gz_export_replaces_a_stale_plain_tar() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("stale-plain");
        let plain = image_tar_name(&format!("{REPO}:v1"), "amd64");
        let gz = image_tar_gz_name(&format!("{REPO}:v1"), "amd64");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(&plain), b"old").unwrap();
        std::fs::write(dir.join(format!("{plain}.imageid")), "sha256:hostid\n").unwrap();
        let d = daemon(move |l| match l {
            l if l.starts_with("version") => Ok("amd64".into()),
            l if l.starts_with("image inspect") => Ok("sha256:hostid amd64".into()),
            l if l.starts_with("tag ") => Ok(String::new()),
            other => Err(format!("unexpected: {other}")),
        });
        stage_image(&g(), &format!("{REPO}:v1"), "amd64", Some(D), "lock").expect("stage");
        assert!(d.calls.borrow().iter().any(|c| c.starts_with("save")), "must re-export: {:?}", d.calls.borrow());
        assert!(dir.join(&gz).is_file() && dir.join(format!("{gz}.imageid")).is_file());
        assert!(!dir.join(&plain).exists() && !dir.join(format!("{plain}.imageid")).exists(), "stale plain tar must go");
        assert!(image_staged_in(&dir, &format!("{REPO}:v1"), "amd64"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn either_form_counts_as_staged() {
        let dir = std::env::temp_dir().join(format!("noo-staged-either-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!image_staged_in(&dir, "a/b:c", "arm64"));
        std::fs::write(dir.join(image_tar_name("a/b:c", "arm64")), b"x").unwrap();
        assert!(image_staged_in(&dir, "a/b:c", "arm64"));
        let _ = std::fs::remove_file(dir.join(image_tar_name("a/b:c", "arm64")));
        std::fs::write(dir.join(image_tar_gz_name("a/b:c", "arm64")), b"x").unwrap();
        assert!(image_staged_in(&dir, "a/b:c", "arm64"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── the parallel pool ──

    /// A containerd-store daemon every worker thread can call: records
    /// (thread, args).
    fn shared_daemon() -> std::sync::Arc<std::sync::Mutex<Vec<(std::thread::ThreadId, String)>>> {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let c2 = calls.clone();
        let fake: SharedFake = Box::new(move |args: &[&str]| {
            let line = args.join(" ");
            c2.lock().unwrap().push((std::thread::current().id(), line.clone()));
            match args.first().copied() {
                Some("version") => Ok("amd64".into()),
                Some("info") => Ok("[[\"driver-type\",\"io.containerd.snapshotter.v1\"]]".into()),
                Some("pull") => {
                    std::thread::sleep(std::time::Duration::from_millis(30));
                    Ok(String::new())
                }
                Some("tag") => Ok(String::new()),
                Some("save") if line.contains("bbb") => Err("boom".to_string()), // one image fails; the rest go on
                Some("save") => {
                    std::fs::write(args[2], b"tar").map_err(|e| e.to_string())?;
                    Ok(String::new())
                }
                Some("image") => {
                    let name = line.split('/').next_back().unwrap_or("").split(['@', ':']).next().unwrap_or("").to_string();
                    if line.contains("--platform") {
                        Ok(format!("sha256:{name}"))
                    } else {
                        Ok(format!("sha256:{name} amd64"))
                    }
                }
                _ => Err(format!("unexpected: {line}")),
            }
        });
        SHARED_FAKE.with(|s| *s.borrow_mut() = Some(std::sync::Arc::new(std::sync::Mutex::new(fake))));
        calls
    }

    /// Several images run at once, but all arches of ONE image stay on one
    /// worker thread in order (the `docker tag` race), a failing image does
    /// not cancel the rest, and the summary is in lock order.
    #[test]
    fn stage_lock_pool_parallelises_across_images_not_within_one() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("pool");
        let lock: String = ["aaa", "bbb", "ccc", "ddd"].iter().map(|n| format!("{n}@sha256:{}\n", "c".repeat(64))).collect();
        let calls = shared_daemon();
        PARALLELISM_OVERRIDE.with(|p| p.set(Some(3)));
        let mut gl = g();
        gl.gateway_override = Some("https://127.0.0.1:9".into()); // prewarm is best-effort; refuse fast
        let arches = vec!["amd64".to_string(), "arm64".to_string()];
        let sum = stage_lock(&gl, &lock, "reg.example/acme", "v1", &arches, true, &[]);
        PARALLELISM_OVERRIDE.with(|p| p.set(None));
        SHARED_FAKE.with(|s| *s.borrow_mut() = None);

        let img = |n: &str, a: &str| format!("reg.example/acme/{n}:v1 ({a})");
        // The pinned door (config/door-images.json) is staged after the lock rows, under its own tag.
        let (pin, pin_digest, pin_tag) = door_pin_refs("reg.example/acme").remove(0);
        let pinned = |a: &str| format!("{pin} ({a})");
        assert_eq!(
            sum.staged,
            vec![img("aaa", "amd64"), img("aaa", "arm64"), img("ccc", "amd64"), img("ccc", "arm64"), img("ddd", "amd64"), img("ddd", "arm64"), pinned("amd64"), pinned("arm64")],
            "lock order, whatever order the workers finished in; summary: {sum:?}"
        );
        assert_eq!(sum.failed.len(), 2, "bbb fails for both arches (its export fails): {sum:?}");
        assert!(sum.failed.iter().all(|f| f.contains("/bbb:v1")), "{sum:?}");

        let calls = calls.lock().unwrap();
        // The shared fake serialises its own calls (one Mutex), so overlap
        // itself cannot be timed here; what shows the pool ran is that jobs
        // were spread over several threads (the sleep in `pull` lets the
        // other workers claim images while one holds the daemon).
        let all_threads: std::collections::HashSet<_> = calls.iter().map(|(t, _)| *t).collect();
        assert!(all_threads.len() >= 2, "images must be spread over the pool's workers");
        for n in ["aaa", "ccc", "ddd"] {
            let threads: std::collections::HashSet<_> = calls.iter().filter(|(_, l)| l.contains(&format!("/{n}"))).map(|(t, _)| *t).collect();
            assert_eq!(threads.len(), 1, "all arches of {n} run on one worker");
            // amd64 (the host arch) is already local and only saves; the
            // arm64 pull must come after that save, not interleave with it.
            let pos = |pred: &dyn Fn(&str) -> bool| calls.iter().position(|(_, l)| l.contains(&format!("/{n}")) && pred(l));
            let first_save = pos(&|l| l.starts_with("save")).expect("amd64 saved");
            let arm_pull = pos(&|l| l.starts_with("pull") && l.contains("linux/arm64")).expect("arm64 pulled");
            assert!(first_save < arm_pull, "arches in order for {n}");
        }
        let idx = read_index(&dir);
        assert_eq!(idx.images.len(), 8, "no lost update in the staged index: {:?}", idx.images.iter().map(|r| (&r.image, &r.arch)).collect::<Vec<_>>());
        for r in idx.images.iter().filter(|r| r.image == pin) {
            assert_eq!((r.source.as_str(), r.release_tag.as_str(), r.lock_digest.as_str()), (DOOR_PIN_SOURCE, pin_tag.as_str(), pin_digest.as_str()), "{r:?}");
        }
        assert_eq!(idx.lock_stage.as_ref().map(|l| l.failed.len()), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stage_parallelism_is_serial_in_tests_unless_asked() {
        assert_eq!(stage_parallelism(), 1);
        PARALLELISM_OVERRIDE.with(|p| p.set(Some(3)));
        assert_eq!(stage_parallelism(), 3);
        PARALLELISM_OVERRIDE.with(|p| p.set(None));
        assert_eq!(STAGE_PARALLELISM, 3);
    }

    /// A run dropped without `finish` still joins its thread.
    #[test]
    fn a_dropped_stage_run_still_joins() {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f2 = flag.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            f2.store(true, std::sync::atomic::Ordering::SeqCst);
            StageOutcome::NoLock
        });
        drop(StageRun { handle: Some(handle), tag: "v1".into() });
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst), "drop must have waited for the thread");
    }

    // ── a release-pinned image is staged by its lock digest, whoever asks ──

    const PREFIX: &str = "reg.example/acme";

    fn lock_text() -> String {
        format!("# tag v1\nnode-agent@{D}\nnats@{D}\n")
    }

    /// The host-arch daemon: inspect answers for any ref, tag and save work.
    fn host_daemon() -> Daemon {
        daemon(move |l| match l {
            l if l.starts_with("version") => Ok("amd64".into()),
            l if l.starts_with("image inspect") => Ok("sha256:hostid amd64".into()),
            l if l.starts_with("tag ") => Ok(String::new()),
            other => Err(format!("unexpected: {other}")),
        })
    }

    #[test]
    fn lock_pin_for_matches_the_refs_stage_lock_builds() {
        let lock = lock_text();
        assert_eq!(lock_pin_for(&format!("{PREFIX}/node-agent:v1"), &lock, PREFIX, "v1"), Some((D.to_string(), "v1".to_string(), "lock")));
        assert_eq!(lock_pin_for(&format!("{PREFIX}/node-agent:v1"), &lock, &format!("{PREFIX}/"), "v1").map(|p| p.2), Some("lock"));
        assert_eq!(lock_pin_for(&format!("{PREFIX}/node-agent:v0"), &lock, PREFIX, "v1"), None, "another release's tag");
        assert_eq!(lock_pin_for(&format!("{PREFIX}/nats:v1"), &lock, PREFIX, "v1"), None, "a third-party row is never ours");
        assert_eq!(lock_pin_for(&format!("{PREFIX}/other:v1"), &lock, PREFIX, "v1"), None);
        let (pin, digest, pin_tag) = door_pin_refs(PREFIX).into_iter().next().expect("a pinned door");
        assert_eq!(lock_pin_for(&pin, &lock, PREFIX, "v1"), Some((digest, pin_tag, DOOR_PIN_SOURCE)));
        assert!(lock_pinned_refs(&lock, PREFIX, "v1").contains(&format!("{PREFIX}/node-agent:v1")));
        assert!(lock_pinned_refs(&lock, PREFIX, "v1").contains(&pin));
    }

    /// THE defect: `sync-images -i <a lock image>` re-staged it by name and
    /// blanked the record's lock digest; a node pinned to it refused its next
    /// start. Now it is staged by the digest and recorded as `stage_lock` does.
    #[test]
    fn an_i_stage_of_a_lock_image_keeps_the_lock_digest() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("i-pinned");
        let d = host_daemon();
        let lock = lock_text();
        let image = format!("{PREFIX}/node-agent:v1");
        let rec = stage_record_with(&g(), &image, "amd64", "sync-images", Some((lock.as_str(), PREFIX, "v1"))).expect("stage");
        assert_eq!((rec.lock_digest.as_str(), rec.source.as_str(), rec.release_tag.as_str()), (D, "lock", "v1"), "{rec:?}");
        let calls = d.calls.borrow().clone();
        assert!(calls.iter().any(|c| c == &format!("tag {PREFIX}/node-agent@{D} {image}")), "taken by the digest: {calls:?}");
        let idx = read_index(&dir);
        assert_eq!(idx.images.len(), 1);
        assert_eq!(idx.images[0].lock_digest, D);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_i_stage_of_an_image_the_lock_does_not_pin_is_by_name() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("i-unpinned");
        let d = host_daemon();
        let lock = lock_text();
        let image = format!("{PREFIX}/other:v1");
        let rec = stage_record_with(&g(), &image, "amd64", "sync-images", Some((lock.as_str(), PREFIX, "v1"))).expect("stage");
        assert_eq!((rec.lock_digest.as_str(), rec.source.as_str(), rec.release_tag.as_str()), ("", "sync-images", ""), "{rec:?}");
        assert!(d.calls.borrow().iter().all(|c| !c.starts_with("tag ")), "{:?}", d.calls.borrow());
        // And again by name over its own by-name record: nothing to protect.
        stage_record_with(&g(), &image, "amd64", "sync-images", Some((lock.as_str(), PREFIX, "v1"))).expect("restage by name");
        assert_eq!(read_index(&dir).images.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_no_stack_lock_a_stage_is_by_name() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("no-lock");
        let _d = host_daemon();
        let rec = stage_record_with(&g(), &format!("{PREFIX}/node-agent:v1"), "amd64", "place", None).expect("stage");
        assert_eq!((rec.lock_digest.as_str(), rec.source.as_str()), ("", "place"));
        let _ = std::fs::remove_dir_all(&dir);
        let gone = std::io::Error::new(std::io::ErrorKind::NotFound, "no file");
        assert!(lock_opt_from(Err(gone)).expect("absent is no error").is_none());
        let denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert!(lock_opt_from(Err(denied)).is_err(), "an unreadable lock is not an absent one");
        let (_, _, tag) = lock_opt_from(Ok(lock_text())).unwrap().unwrap();
        assert_eq!(tag, "v1");
    }

    /// The backstop: a by-name record never replaces a digest-staged one; a
    /// newer digest-staged record (the next release) does.
    #[test]
    fn a_by_name_record_never_replaces_a_lock_record() {
        let _l = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = store("backstop");
        std::fs::create_dir_all(&dir).unwrap();
        let image = format!("{PREFIX}/node-agent:v1");
        record_staged(rec(&image, "amd64", "v1", 1), None).expect("lock record");
        let mut by_name = rec(&image, "amd64", "", 2);
        by_name.lock_digest = String::new();
        by_name.source = "sync-images".into();
        let before = std::fs::read(dir.join(STAGED_INDEX)).unwrap();
        let err = record_staged(by_name.clone(), None).expect_err("refused");
        assert!(err.contains(&image) && err.contains("(amd64)") && err.contains(RESTAGE_BY_LOCK), "{err}");
        assert_eq!(std::fs::read(dir.join(STAGED_INDEX)).unwrap(), before, "the index is unchanged");
        // The other arch is a different record: by name is fine there.
        let mut arm = by_name.clone();
        arm.arch = "arm64".into();
        record_staged(arm, None).expect("no lock record for arm64");
        // A newer lock record replaces the old one.
        let mut newer = rec(&image, "amd64", "v2", 3);
        newer.lock_digest = format!("sha256:{}", "c".repeat(64));
        record_staged(newer.clone(), None).expect("digest over digest");
        let idx = read_index(&dir);
        assert_eq!(idx.images.iter().find(|r| r.arch == "amd64").unwrap(), &newer);
        // stage_record_with refuses before any pull.
        let d = host_daemon();
        let err = stage_record_with(&g(), &image, "amd64", "place", None).expect_err("refused");
        assert!(err.contains(RESTAGE_BY_LOCK), "{err}");
        assert!(d.calls.borrow().is_empty(), "nothing pulled or exported: {:?}", d.calls.borrow());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_stage_remedy_restages_a_pinned_image_by_the_lock() {
        let r = stage_remedy("p/llamacpp-cuda:v1", "amd64", true);
        assert!(r.starts_with(RESTAGE_BY_LOCK) && !r.contains(" -i "), "{r}");
        assert_eq!(stage_remedy("p/x:v1", "arm64", false), "noo cluster sync-images --stage-only -i p/x:v1 --arch arm64");
    }

    /// Every by-name stager goes through `stage_and_record`, which re-derives
    /// the lock digest: `-i`, the full `sync-images` push, and `place`.
    #[test]
    fn every_by_name_stager_goes_through_stage_and_record() {
        let own = crate::test_src::own_code(include_str!("image_stage.rs"));
        let sar = crate::test_src::fn_body(&own, "pub(crate) fn stage_and_record(");
        assert!(sar.contains("controller_lock_opt()?") && sar.contains("stage_record_with("), "{sar}");
        assert!(crate::test_src::fn_body(&own, "fn stage_record_with(").contains("lock_pin_for(image, l, p, t)"));
        assert!(crate::test_src::fn_body(&own, "pub(crate) fn stage_selection(").contains("stage_and_record(g, img, arch, source)"));
        let sync = crate::test_src::own_code(include_str!("cluster_provision_subprocess.rs"));
        let pull = crate::test_src::fn_body(&sync, "fn sync_image_via_pull(");
        assert!(pull.contains("image_stage::stage_and_record(g, image, arch, \"sync-images\")") && !pull.contains("stage_image("), "{pull}");
        let cluster = crate::test_src::own_code(include_str!("cluster.rs"));
        assert!(cluster.contains("image_stage::stage_and_record(g, &img, &arch, \"place\")"));
        assert!(!cluster.contains("image_stage::stage_image(") && !sync.contains("image_stage::stage_image("), "no by-name stage around it");
    }
}
