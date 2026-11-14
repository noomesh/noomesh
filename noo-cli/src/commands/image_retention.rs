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

/// The `# tag <tag>` header of a stack lock.
pub(crate) fn stack_lock_tag(text: &str) -> Option<String> {
    text.lines().find_map(|l| l.trim().strip_prefix("# tag ").map(|t| t.trim().to_string()))
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
    let mut add = |reference: String, why: String, keep: &mut Vec<Value>| {
        if seen.insert(reference.clone()) {
            keep.push(json!({"ref": reference, "why": why}));
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

/// The post-roll verify's outcome. A verify that could not be run at all
/// (no `noo` executable, a spawn error) is `Failed`: cleanup runs only on a
/// verify that ran AND passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verified {
    Passed,
    Failed,
}

pub(crate) fn verify_outcome(ran: &std::io::Result<std::process::ExitStatus>) -> Verified {
    match ran {
        Ok(s) if s.success() => Verified::Passed,
        _ => Verified::Failed,
    }
}

/// Whether the post-roll step may write a keep file and queue the rung.
pub(crate) fn may_clean(verified: Verified) -> bool {
    verified == Verified::Passed
}

/// What the post-roll step does to the machine; [`post_roll_on`] holds every
/// decision, so a test drives it with a fake.
pub(crate) trait PostRollHost {
    fn verify(&mut self) -> Verified;
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
    if !may_clean(h.verify()) {
        return h.say("images: superseded images were NOT cleaned up: the post-roll `noo cluster verify --controller --wait` did not pass; the next roll that verifies cleanly does it");
    }
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
    fn verify(&mut self) -> Verified {
        let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "noo".into());
        let ran = std::process::Command::new(&exe)
            .args(["cluster", "verify", "--controller", "--wait", "--json"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        verify_outcome(&ran)
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
        let stack = format!("# tag v0.6.24\nghcr.io/noomesh/gateway@sha256:{}\nghcr.io/noomesh/ollama@sha256:{}\n", h('1'), h('2'));
        let prev = format!("# tag v0.6.23\nghcr.io/noomesh/gateway@sha256:{}\n", h('3'));
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
        }
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
        i.stack = Some((PathBuf::from("/r/stack.lock"), b"# tag v0.6.24\n".to_vec()));
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
        verified: Option<Verified>,
        rung: Option<Value>,
        hostd_down: bool,
        verifies: u32,
        keeps: u32,
        rungs: Vec<bool>,
        marked: Vec<String>,
        said: Vec<String>,
    }

    impl PostRollHost for FakeHost {
        fn verify(&mut self) -> Verified {
            self.verifies += 1;
            self.verified.unwrap_or(Verified::Failed)
        }
        fn write_keep(&mut self) -> Result<PathBuf, String> {
            self.keeps += 1;
            Ok(PathBuf::from("/r/.noo-host-spool/image-keep.json"))
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

    fn some_superseded() -> Value {
        json!({"bytes": 1_000_000_000i64, "images": [{"remove": true}, {"remove": false}]})
    }

    /// Cleanup runs only on a verify that ran AND passed: a failed verify,
    /// and one that could not be run at all, write no keep file and queue no
    /// rung.
    #[test]
    fn a_failed_or_unrun_verify_writes_no_keep_file_and_runs_no_rung() {
        let mut h = FakeHost { verified: Some(Verified::Failed), rung: Some(some_superseded()), ..Default::default() };
        post_roll_on(&mut h, Some("live"), true, "v1");
        assert_eq!((h.verifies, h.keeps, h.rungs.len()), (1, 0, 0), "a failed verify cleans nothing");
        assert!(h.said[0].contains("NOT cleaned up") && h.said[0].contains("did not pass"), "{:?}", h.said);
        // A verify that could not be spawned is a failure, never a pass.
        let unrun: std::io::Result<std::process::ExitStatus> = Err(std::io::Error::other("no such file"));
        assert_eq!(verify_outcome(&unrun), Verified::Failed);
        assert!(!may_clean(verify_outcome(&unrun)));
        assert!(!may_clean(Verified::Failed) && may_clean(Verified::Passed));
        // And a passed one does clean.
        let mut h = FakeHost { verified: Some(Verified::Passed), rung: Some(some_superseded()), ..Default::default() };
        post_roll_on(&mut h, Some("live"), true, "v1");
        assert_eq!((h.keeps, h.rungs.clone()), (1, vec![true]));
    }

    #[test]
    fn off_runs_nothing_not_even_the_verify() {
        let mut h = FakeHost { verified: Some(Verified::Passed), ..Default::default() };
        post_roll_on(&mut h, Some("off"), true, "v1");
        assert_eq!((h.verifies, h.keeps, h.rungs.len()), (0, 0, 0));
    }

    #[test]
    fn the_first_roll_previews_and_spends_the_preview_only_on_a_non_empty_list() {
        // Empty: says nothing and keeps the one-time preview.
        let mut h = FakeHost { verified: Some(Verified::Passed), ..Default::default() };
        post_roll_on(&mut h, None, false, "v1");
        assert_eq!(h.rungs, vec![false], "the first roll is a preview");
        assert!(h.marked.is_empty() && h.said.is_empty(), "an empty preview is silent and not spent: {:?}", h.said);
        assert_eq!(removable(&json!({"images": [{"remove": false}]})), 0);
        // Something to remove: previews, says so, and records the preview.
        let mut h = FakeHost { verified: Some(Verified::Passed), rung: Some(some_superseded()), ..Default::default() };
        post_roll_on(&mut h, None, false, "v1");
        assert_eq!((h.rungs.clone(), h.marked.clone()), (vec![false], vec!["v1".to_string()]));
        // The next roll (preview spent): live.
        let mut h = FakeHost { verified: Some(Verified::Passed), rung: Some(some_superseded()), ..Default::default() };
        post_roll_on(&mut h, None, true, "v2");
        assert_eq!(h.rungs, vec![true]);
        // An explicit `preview` keeps previewing and never spends the marker.
        let mut h = FakeHost { verified: Some(Verified::Passed), rung: Some(some_superseded()), ..Default::default() };
        post_roll_on(&mut h, Some("preview"), true, "v3");
        assert_eq!((h.rungs.clone(), h.marked.len()), (vec![false], 0));
    }

    #[test]
    fn hostd_down_queues_no_rung() {
        let mut h = FakeHost { verified: Some(Verified::Passed), hostd_down: true, ..Default::default() };
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
