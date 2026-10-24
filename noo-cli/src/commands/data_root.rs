// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A node's data root: what a bundle would render against what the node
//! reports it uses.
//!
//! Two names, kept apart on purpose:
//!
//! - the **rendered** roots are what THIS bundle would write to the node's
//!   env file (`noo_data_root`, `hf_cache_dir`, `models_dir`,
//!   `ollama_data_dir`) — the declaration's side;
//! - the **reported** roots are what the node's agent says it resolves now
//!   (`data_roots` on its heartbeat) plus the host paths its managed backend
//!   containers mount — the installation's side.
//!
//! A bundle that would move a node off the root its containers mount is
//! refused (`provision`), and `noo cluster verify` shows the same
//! disagreement as a row. Failure semantics, in one place:
//!
//! - no `data_roots` on the record (an older agent), or a reported
//!   `noo_data_root` that is not an absolute path → NOT REPORTED: the check
//!   is skipped, never guessed;
//! - `noo_data_root_source: "default"` means the agent was never told a
//!   root and fell back to its hardcoded one: the root comparison is skipped
//!   (the bundle is about to tell it), but running mounts still count;
//! - `running_mounts` absent (docker unreachable, `running_mounts_error`) →
//!   the root comparison still runs, the mount comparison has nothing to
//!   compare;
//! - paths are compared after trimming trailing slashes; a mount equal to or
//!   under a rendered root is inside it;
//! - a mount is also inside when the agent says (`running_mounts_resolved`,
//!   its own symlink resolution on the host) that the path resolves to a place
//!   inside a rendered root: host3's vllm mounts `/opt/noo/hf-cache`, a
//!   symlink to `/data/noo/hf-cache`, the same data under another name. And
//!   when the rendered root IS the reported root, a mount under the root's own
//!   resolved target (`noo_data_root_resolved`) is inside too. Inside only by
//!   resolution is NOT a conflict: it is a note ("same data, different path",
//!   it moves on the next recreate). An agent that predates the resolved
//!   fields sends none, so such a mount is a conflict, exactly as before.

use serde_json::Value;
use std::collections::BTreeMap;

/// The data root used when NOO_DATA_ROOT is unset: a neutral Linux path, not
/// any one machine's. The node agent's dataroots.DefaultDataRoot
/// and the Python CLI are held to the same value by
/// tests/test_data_root_default_parity.py; the compose file refuses an unset
/// root outright instead of falling back.
pub(crate) const DEFAULT_DATA_ROOT: &str = "/var/lib/noo";

/// The root of the SENSITIVE state set (postgres, redis, nats, prometheus,
/// grafana, loki, noo-data): `NOO_STATE_ROOT` when it is set and not blank,
/// else the data root itself, so an install that never sets it resolves every
/// path exactly as before (i10a groundwork; a later change points it at the
/// encrypted volume). models / hf-cache / ollama / images are NOT in the set
/// and always stay under the data root. Mirrors compose's
/// `${NOO_STATE_ROOT:-${NOO_DATA_ROOT}}` (an empty value counts as unset) and
/// scripts/lib-instance.sh `noo_state_root`. Pure: the caller supplies the
/// two values it already read.
pub(crate) fn state_root_of(state_root: Option<&str>, data_root: &str) -> String {
    match state_root.map(|s| s.trim().trim_end_matches('/')).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => data_root.to_string(),
    }
}

/// The macOS default: the Mac agent runs as the user, so its data lives under
/// that user's ~/noomesh (where its env, keys and binary already are). The
/// path has NO whitespace: the Mac agent env is sourced by a shell, and the
/// earlier default under "Application Support" was split on its space, which
/// dropped the node's data roots (a Mac node, 2026-10-06).
pub(crate) fn default_for_macos(home: &str) -> String {
    format!("{}/noomesh", home.trim_end_matches('/'))
}

/// The macOS default of #754, kept as a legal root so a Mac that already
/// used it keeps working (the node agent adopts it while it exists).
pub(crate) fn legacy_macos_root(home: &str) -> String {
    format!("{}/Library/Application Support/noo", home.trim_end_matches('/'))
}

/// The roots an agent falls back to when it was never told one. MIRRORS
/// node-agent-go/internal/dataroots/dataroots.go (`LegacyDefaults`,
/// `DefaultFor`, `DarwinLegacySuffix`): keep the two in step. A root on this
/// list is what the node FELL BACK to, so it is never evidence of where the
/// operator wants the declaration (a Mac node, 2026-10-06: it failed to load
/// its env and fell back to the Linux /mnt/d/noo).
pub(crate) fn is_builtin_default_root(root: &str) -> bool {
    let r = norm(root);
    // The pre-#754 Windows-mount fallback is deliberately NOT spelled here
    // (tests/test_data_root_default_parity.py forbids it in shipped code);
    // an agent on it reports `noo_data_root_source: default`, which the
    // caller checks first, so the list only has to cover agents that report
    // no source at all.
    if ["/data/noo", DEFAULT_DATA_ROOT].contains(&r.as_str()) {
        return true;
    }
    // ~/noomesh and ~/Library/Application Support/noo for some user.
    let (macos, home) = infer_os(&r);
    macos && !home.is_empty() && (r == default_for_macos(&home) || r == legacy_macos_root(&home))
}

/// Whether `root` is a path shape the node's OS can hold: macOS roots live
/// under /Users or /Volumes, Linux ones anywhere else.
pub(crate) fn root_fits_os(root: &str, macos: bool) -> bool {
    infer_os(root).0 == macos
}

/// Paths that may never hold a data root on Linux. `/var` is separate: only
/// `/var/lib/noo` is allowed there.
const LINUX_SYSTEM_PREFIXES: &[&str] = &[
    "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/run", "/usr", "/bin", "/sbin", "/lib",
    "/lib32", "/lib64", "/tmp", "/opt", "/snap",
];

/// The data-root SHAPE rule, mirrored from the node agent
/// (node-agent-go/internal/dataroots/policy.go) and held to the same cases
/// (config/data-root-shape-vectors.json). `None` = acceptable; otherwise the
/// first failing rule as (code, explanation). Ownership is checked on the
/// node itself, where the directory lives.
pub(crate) fn shape_problem(path: &str, macos: bool, home: &str) -> Option<(&'static str, String)> {
    let raw = path.trim();
    if !raw.starts_with('/') {
        return Some(("not_absolute", format!("{path:?} is not an absolute path")));
    }
    if let Some(c) = raw.split('/').find(|c| *c == ".." || *c == ".") {
        return Some(("relative_component", format!("{path:?} contains {c:?}")));
    }
    let clean = {
        let parts: Vec<&str> = raw.split('/').filter(|c| !c.is_empty()).collect();
        format!("/{}", parts.join("/"))
    };
    if let Some(c) = clean.split('/').find(|c| c.starts_with('.')) {
        return Some(("hidden", format!("{path:?} contains the hidden component {c:?}")));
    }
    // A named instance keeps its own tree inside the root:
    // <root>/instances/<name>, where <root> is itself a `noo` directory.
    let base = {
        let parts: Vec<&str> = clean.split('/').collect();
        if parts.len() >= 4 && parts[parts.len() - 2] == "instances" {
            parts[..parts.len() - 2].join("/")
        } else {
            clean.clone()
        }
    };
    // The macOS default is ~/noomesh itself, the one root not named `noo`.
    if macos {
        let h = home.trim().trim_end_matches('/');
        if !h.is_empty() && clean == default_for_macos(h) {
            return None;
        }
    }
    if base.rsplit('/').next() != Some("noo") {
        return Some(("not_dedicated", format!("{path:?} is not a dedicated directory named noo (e.g. {DEFAULT_DATA_ROOT})")));
    }
    let under = |p: &str| clean == p || clean.starts_with(&format!("{p}/"));
    if macos {
        let home = home.trim().trim_end_matches('/');
        if !home.is_empty() && base == legacy_macos_root(home) {
            return None;
        }
        if under("/Volumes") && clean.matches('/').count() >= 3 {
            return None;
        }
        return Some(("mac_location", format!("{path:?} is neither ~/noomesh, ~/Library/Application Support/noo nor /Volumes/<disk>/…/noo")));
    }
    if let Some(s) = LINUX_SYSTEM_PREFIXES.iter().find(|s| under(s)) {
        return Some(("system_path", format!("{path:?} is under the system path {s}")));
    }
    if under("/var") && base != DEFAULT_DATA_ROOT {
        return Some(("system_path", format!("{path:?} is under /var; the only data root there is {DEFAULT_DATA_ROOT}")));
    }
    if under("/home") {
        return Some(("home_dir", format!("{path:?} is inside a home directory")));
    }
    let parts: Vec<&str> = clean.split('/').collect();
    if parts.len() > 2 && parts[1] == "mnt" && parts[2].len() == 1 {
        return Some(("windows_drive", format!("{path:?} is on a Windows drive (WSL 9P mount, slow and shared); use {DEFAULT_DATA_ROOT}")));
    }
    None
}

/// Which rule family a path belongs to when the target OS is not known (a
/// `set-config` names a node, not its OS): macOS paths live under /Users or
/// /Volumes. Returns (macos, home).
pub(crate) fn infer_os(path: &str) -> (bool, String) {
    let p = path.trim();
    if p.starts_with("/Volumes/") {
        return (true, String::new());
    }
    if let Some(rest) = p.strip_prefix("/Users/") {
        let user = rest.split('/').next().unwrap_or("");
        return (true, format!("/Users/{user}"));
    }
    (false, String::new())
}

/// The roots one bundle would render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rendered {
    pub noo_data_root: String,
    pub hf_cache_dir: String,
    pub models_dir: String,
    pub ollama_data_dir: String,
}

impl Rendered {
    /// The rendered roots for one data root: the children the template
    /// derives from it.
    pub fn from_root(root: &str) -> Self {
        let r = norm(root);
        Rendered {
            hf_cache_dir: format!("{r}/hf-cache"),
            models_dir: format!("{r}/models"),
            ollama_data_dir: format!("{r}/ollama"),
            noo_data_root: r,
        }
    }
    fn all(&self) -> [&str; 4] {
        [&self.noo_data_root, &self.hf_cache_dir, &self.models_dir, &self.ollama_data_dir]
    }
}

/// What the node's agent reports, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reported {
    pub noo_data_root: String,
    /// `true` when the agent was told the root (env), `false` when it fell
    /// back to its hardcoded default.
    pub root_from_env: bool,
    pub hf_cache_dir: Option<String>,
    pub models_dir: Option<String>,
    pub ollama_data_dir: Option<String>,
    /// (backend, host path), sorted by backend then path.
    pub mounts: Vec<(String, String)>,
    /// The agent's own symlink resolution of the agent's root, when it
    /// differs (`noo_data_root_resolved`).
    pub root_resolved: Option<String>,
    /// mount source -> where it really lives (`running_mounts_resolved`),
    /// only for sources that resolve elsewhere.
    pub resolved: BTreeMap<String, String>,
}

/// Where a mount sits relative to the roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Its literal path is inside a root.
    Inside,
    /// Inside only through a symlink; the text says how, for a note.
    InsideViaLink(String),
    Outside,
}

impl Reported {
    /// Place one mount source against `roots`. `root_is_reported`: the
    /// rendered root is the very root the agent reports, so a mount under the
    /// agent root's resolved target is inside as well.
    pub fn place(&self, path: &str, roots: &[&str], root_is_reported: bool) -> Placement {
        if roots.iter().any(|r| inside(path, r)) {
            return Placement::Inside;
        }
        if let Some(to) = self.resolved.get(path) {
            if roots.iter().any(|r| inside(to, r)) {
                return Placement::InsideViaLink(format!("{path} -> {to}"));
            }
        }
        if root_is_reported {
            if let Some(rr) = &self.root_resolved {
                if inside(path, rr) {
                    return Placement::InsideViaLink(format!("{path}, under the data root's target {} -> {rr}", self.noo_data_root));
                }
            }
        }
        Placement::Outside
    }

    /// The mounts that are inside only through a symlink, as
    /// "noo-<backend> mounts <how>" notes.
    pub fn link_notes(&self, roots: &[&str], root_is_reported: bool) -> Vec<String> {
        self.mounts.iter()
            .filter_map(|(b, p)| match self.place(p, roots, root_is_reported) {
                Placement::InsideViaLink(how) => Some(format!("noo-{b} mounts {how}")),
                _ => None,
            })
            .collect()
    }
}

/// What a comparison found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Conflict {
    pub reported_root: String,
    pub rendered_root: String,
    /// The two roots differ (and the agent was told its root).
    pub root_differs: bool,
    /// (backend, host path) mounts outside every rendered root.
    pub outside: Vec<(String, String)>,
}

/// The outcome of looking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootCheck {
    /// Nothing usable was reported; why.
    NotReported(String),
    Agree,
    Conflict(Conflict),
}

/// Trailing slashes off, `/` kept as `/`.
pub(crate) fn norm(p: &str) -> String {
    let t = p.trim().trim_end_matches('/');
    if t.is_empty() && p.trim().starts_with('/') { "/".into() } else { t.to_string() }
}

/// `p` is `root` or lies under it.
pub(crate) fn inside(p: &str, root: &str) -> bool {
    let (p, root) = (norm(p), norm(root));
    p == root || root == "/" || p.starts_with(&format!("{root}/"))
}

fn abs(v: &Value) -> Option<String> {
    let s = v.as_str()?.trim();
    (s.starts_with('/') && s.len() > 1).then(|| norm(s))
}

/// Parse a node record's `data_roots`. `Err` says why there is nothing
/// usable (the caller treats it as not reported).
pub(crate) fn parse_reported(v: Option<&Value>) -> Result<Reported, String> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Err("the node record carries no data_roots (an older agent, or the record could not be read)".into());
    };
    let Some(root) = abs(&v["noo_data_root"]) else {
        return Err(format!(
            "the agent's reported data root {} is not an absolute path",
            v["noo_data_root"]
        ));
    };
    let mut mounts: Vec<(String, String)> = Vec::new();
    if let Some(m) = v["running_mounts"].as_object() {
        for (backend, paths) in m {
            for p in paths.as_array().into_iter().flatten().filter_map(|p| p.as_str()) {
                mounts.push((backend.clone(), norm(p)));
            }
        }
    }
    mounts.sort();
    let resolved: BTreeMap<String, String> = v["running_mounts_resolved"].as_object().into_iter().flatten()
        .filter_map(|(k, to)| Some((norm(k), abs(to)?)))
        .collect();
    Ok(Reported {
        noo_data_root: root,
        root_from_env: v["noo_data_root_source"].as_str() != Some("default"),
        hf_cache_dir: abs(&v["hf_cache_dir"]),
        models_dir: abs(&v["models_dir"]),
        ollama_data_dir: abs(&v["ollama_data_dir"]),
        mounts,
        root_resolved: abs(&v["noo_data_root_resolved"]),
        resolved,
    })
}

/// Compare what a bundle would render with what the node reports.
pub(crate) fn data_root_check(rendered: &Rendered, reported: Option<&Value>) -> RootCheck {
    let rep = match parse_reported(reported) {
        Ok(r) => r,
        Err(why) => return RootCheck::NotReported(why),
    };
    let root_differs = rep.root_from_env && norm(&rep.noo_data_root) != norm(&rendered.noo_data_root);
    let roots = rendered.all();
    let root_is_reported = norm(&rep.noo_data_root) == norm(&rendered.noo_data_root);
    let outside: Vec<(String, String)> = rep.mounts.iter()
        .filter(|(_, p)| rep.place(p, &roots, root_is_reported) == Placement::Outside)
        .cloned()
        .collect();
    if !root_differs && outside.is_empty() {
        return RootCheck::Agree;
    }
    RootCheck::Conflict(Conflict {
        reported_root: rep.noo_data_root,
        rendered_root: rendered.noo_data_root.clone(),
        root_differs,
        outside,
    })
}

/// [`data_root_check`] reduced to the conflict, for callers that treat
/// "agree" and "not reported" alike (provision matches on the full check, to
/// print the skip note).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn data_root_conflict(rendered: &Rendered, reported: Option<&Value>) -> Option<Conflict> {
    match data_root_check(rendered, reported) {
        RootCheck::Conflict(c) => Some(c),
        _ => None,
    }
}

impl Conflict {
    /// The refusal's first line: both sides, in the node's own words.
    pub fn headline(&self, node: &str) -> String {
        let mounts: Vec<String> = self.outside.iter()
            .map(|(b, p)| format!("noo-{b} mounts {p}"))
            .collect();
        let mounts = mounts.join(", ");
        match (self.root_differs, mounts.is_empty()) {
            (true, true) => format!("this bundle moves {node}'s data root {} -> {}", self.reported_root, self.rendered_root),
            (true, false) => format!("this bundle moves {node}'s data root {} -> {}, and {mounts}", self.reported_root, self.rendered_root),
            (false, _) => format!("this bundle's data root {} does not contain what {node} runs: {mounts}", self.rendered_root),
        }
    }
}

/// The mounts that are inside the rendered roots only through a symlink,
/// for callers that show them informationally (never a conflict).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn link_notes(rendered: &Rendered, reported: Option<&Value>) -> Vec<String> {
    match parse_reported(reported) {
        Ok(rep) => {
            let same = norm(&rep.noo_data_root) == norm(&rendered.noo_data_root);
            rep.link_notes(&rendered.all(), same)
        }
        Err(_) => Vec::new(),
    }
}

/// The verify row name for the data-root mount guard.
pub(crate) const MOUNT_ROW: &str = "data root filesystem";

/// What a `scripts/lib-data-root-mount.sh data_root_mount_report` exit code
/// means for the verify row: 0 on its recorded filesystem (OK), 3 refused
/// (FAIL: the launchers refuse too), 4 nothing recorded yet or not checkable
/// (WARN), anything else the report could not run (WARN).
pub(crate) fn mount_row_from(code: Option<i32>, evidence: &str) -> crate::commands::cluster_verify::Check {
    use crate::commands::cluster_verify::{Check, Verdict};
    let evidence = evidence.trim().to_string();
    let recovery = "findmnt -T <data root>; lsblk -f; docs/operating/runbooks/data-root-recovery.md".to_string();
    let (verdict, detail, remedy) = match code {
        Some(0) => (Verdict::Ok, evidence, None),
        Some(3) => (Verdict::Fail, format!("{evidence} (the launchers refuse to start; postgres would initialise an empty database)"), Some(recovery)),
        Some(4) => (Verdict::Warn, evidence, Some("the next noo stack start records it".to_string())),
        other => (
            Verdict::Warn,
            format!("the data-root mount check could not run (exit {}): {evidence}", other.map(|c| c.to_string()).unwrap_or_else(|| "signal".into())),
            None,
        ),
    };
    Check { name: MOUNT_ROW, verdict, detail, remedy }
}

/// `noo cluster verify --controller` row: is the data root on the filesystem
/// recorded for it? The criterion is `scripts/lib-data-root-mount.sh` (one
/// home; the launchers and hostd run the same code), run read-only here.
pub(crate) fn mount_row(install_root: &std::path::Path) -> crate::commands::cluster_verify::Check {
    let lib = install_root.join("scripts").join("lib-data-root-mount.sh");
    if !lib.is_file() {
        return mount_row_from(None, &format!("{} is missing from this install", lib.display()));
    }
    match std::process::Command::new("bash")
        .arg("-c")
        .arg(". \"$1\" && data_root_mount_report")
        .arg("noo")
        .arg(&lib)
        .current_dir(install_root)
        .output()
    {
        Ok(o) => mount_row_from(o.status.code(), &String::from_utf8_lossy(&o.stdout)),
        Err(e) => mount_row_from(None, &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn state_root_defaults_to_the_data_root_and_a_set_value_wins() {
        assert_eq!(super::state_root_of(None, "/srv/noo"), "/srv/noo", "unset: the data root, unchanged");
        assert_eq!(super::state_root_of(Some(""), "/srv/noo"), "/srv/noo", "empty counts as unset, like compose's :-");
        assert_eq!(super::state_root_of(Some("  "), "/srv/noo"), "/srv/noo");
        assert_eq!(super::state_root_of(Some("/mnt/state/"), "/srv/noo"), "/mnt/state", "set: wins, trailing slash trimmed");
        assert_eq!(super::state_root_of(None, "/srv/noo/"), "/srv/noo/", "the data-root fallback is passed through untouched");
    }

    #[test]
    fn shape_matches_the_shared_vectors() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../../config/data-root-shape-vectors.json")).unwrap();
        let cases = doc["cases"].as_array().unwrap();
        assert!(cases.len() >= 20, "the vectors file is not being read");
        for c in cases {
            let (path, ok) = (c["path"].as_str().unwrap(), c["ok"].as_bool().unwrap());
            let macos = c["os"] == "macos";
            let got = super::shape_problem(path, macos, c["home"].as_str().unwrap_or(""));
            if ok {
                assert!(got.is_none(), "{path}: want ok, got {got:?}");
            } else {
                assert_eq!(got.map(|g| g.0), c["code"].as_str(), "{path}");
            }
        }
    }

    #[test]
    fn defaults_pass_their_own_rule_and_os_is_inferred_from_the_path() {
        assert!(super::shape_problem(super::DEFAULT_DATA_ROOT, false, "").is_none());
        let mac = super::default_for_macos("/Users/alice/");
        assert_eq!(mac, "/Users/alice/noomesh");
        // No whitespace: the Mac agent env is sourced by a shell.
        assert!(!mac.contains(char::is_whitespace), "{mac:?}");
        // The #754 default stays a legal shape for a Mac that already used it.
        let legacy = super::legacy_macos_root("/Users/alice/");
        assert!(super::shape_problem(&legacy, true, "/Users/alice").is_none());
        let (macos, home) = super::infer_os(&mac);
        assert!(macos && home == "/Users/alice");
        assert!(super::shape_problem(&mac, macos, &home).is_none());
        assert_eq!(super::infer_os("/Volumes/T7/noo"), (true, String::new()));
        assert_eq!(super::infer_os("/var/lib/noo"), (false, String::new()));
    }

    use super::*;
    use serde_json::json;

    fn rendered(root: &str) -> Rendered { Rendered::from_root(root) }

    #[test]
    fn agree() {
        let rep = json!({"noo_data_root": "/data/noo", "noo_data_root_source": "env",
            "running_mounts": {"vllm": ["/data/noo/hf-cache"], "ollama": ["/data/noo/ollama/"]}});
        assert_eq!(data_root_check(&rendered("/data/noo"), Some(&rep)), RootCheck::Agree);
        // Trailing slash on either side is the same path.
        assert_eq!(data_root_check(&rendered("/data/noo/"), Some(&rep)), RootCheck::Agree);
    }

    #[test]
    fn differ_names_both_sides_and_the_mount() {
        let rep = json!({"noo_data_root": "/data/noo", "noo_data_root_source": "env",
            "running_mounts": {"vllm": ["/data/noo/hf-cache"]}});
        let c = data_root_conflict(&rendered("/opt/noo"), Some(&rep)).expect("conflict");
        assert!(c.root_differs);
        assert_eq!((c.reported_root.as_str(), c.rendered_root.as_str()), ("/data/noo", "/opt/noo"));
        assert_eq!(c.outside, vec![("vllm".to_string(), "/data/noo/hf-cache".to_string())]);
        assert_eq!(c.headline("host3"),
            "this bundle moves host3's data root /data/noo -> /opt/noo, and noo-vllm mounts /data/noo/hf-cache");
    }

    #[test]
    fn roots_agree_but_a_container_mounts_an_old_path() {
        let rep = json!({"noo_data_root": "/data/noo", "noo_data_root_source": "env",
            "running_mounts": {"vllm": ["/mnt/d/noo/hf-cache"], "ollama": ["/data/noo/ollama"]}});
        let c = data_root_conflict(&rendered("/data/noo"), Some(&rep)).expect("conflict");
        assert!(!c.root_differs);
        assert_eq!(c.outside, vec![("vllm".to_string(), "/mnt/d/noo/hf-cache".to_string())]);
        assert!(c.headline("host3").contains("noo-vllm mounts /mnt/d/noo/hf-cache"));
        // A path that merely shares a prefix string is NOT inside.
        let rep = json!({"noo_data_root": "/data/noo", "running_mounts": {"vllm": ["/data/noo-old/hf-cache"]}});
        assert!(data_root_conflict(&rendered("/data/noo"), Some(&rep)).is_some());
    }

    #[test]
    fn no_report_is_not_a_conflict() {
        assert!(matches!(data_root_check(&rendered("/opt/noo"), None), RootCheck::NotReported(_)));
        assert!(matches!(data_root_check(&rendered("/opt/noo"), Some(&Value::Null)), RootCheck::NotReported(_)));
        assert!(data_root_conflict(&rendered("/opt/noo"), None).is_none());
    }

    #[test]
    fn unusable_root_is_treated_as_not_reported() {
        for bad in [json!("data/noo"), json!(""), json!(null), json!(7), json!("/")] {
            let rep = json!({"noo_data_root": bad, "running_mounts": {"vllm": ["/elsewhere"]}});
            assert!(matches!(data_root_check(&rendered("/opt/noo"), Some(&rep)), RootCheck::NotReported(_)), "{bad}");
        }
    }

    #[test]
    fn a_default_root_skips_the_root_comparison_but_not_the_mounts() {
        let rep = json!({"noo_data_root": "/mnt/d/noo", "noo_data_root_source": "default", "running_mounts": {}});
        assert_eq!(data_root_check(&rendered("/data/noo"), Some(&rep)), RootCheck::Agree);
        let rep = json!({"noo_data_root": "/mnt/d/noo", "noo_data_root_source": "default",
            "running_mounts": {"vllm": ["/mnt/d/noo/hf-cache"]}});
        let c = data_root_conflict(&rendered("/data/noo"), Some(&rep)).expect("conflict");
        assert!(!c.root_differs && c.outside.len() == 1);
    }

    #[test]
    fn mounts_missing_still_compares_roots() {
        let rep = json!({"noo_data_root": "/data/noo", "running_mounts_error": "docker down"});
        assert!(data_root_conflict(&rendered("/opt/noo"), Some(&rep)).is_some());
        assert_eq!(data_root_check(&rendered("/data/noo"), Some(&rep)), RootCheck::Agree);
    }

    #[test]
    fn explicit_child_roots_count_as_rendered_roots() {
        let mut r = rendered("/opt/noo");
        r.hf_cache_dir = "/fast/hf".into();
        let rep = json!({"noo_data_root": "/opt/noo", "running_mounts": {"vllm": ["/fast/hf"]}});
        assert_eq!(data_root_check(&r, Some(&rep)), RootCheck::Agree);
    }

    fn host3(extra: serde_json::Value) -> Value {
        let mut rep = json!({"noo_data_root": "/data/noo", "noo_data_root_source": "env",
            "running_mounts": {"vllm": ["/opt/noo/hf-cache"]}});
        for (k, v) in extra.as_object().unwrap() { rep[k] = v.clone(); }
        rep
    }

    #[test]
    fn a_mount_through_a_symlink_into_the_root_is_not_a_conflict() {
        let rep = host3(json!({"running_mounts_resolved": {"/opt/noo/hf-cache": "/data/noo/hf-cache"}}));
        assert_eq!(data_root_check(&rendered("/data/noo"), Some(&rep)), RootCheck::Agree);
        assert_eq!(link_notes(&rendered("/data/noo"), Some(&rep)),
            vec!["noo-vllm mounts /opt/noo/hf-cache -> /data/noo/hf-cache".to_string()]);
    }

    #[test]
    fn an_older_agent_without_resolution_still_conflicts() {
        let rep = host3(json!({}));
        let c = data_root_conflict(&rendered("/data/noo"), Some(&rep)).expect("conflict");
        assert_eq!(c.outside, vec![("vllm".to_string(), "/opt/noo/hf-cache".to_string())]);
        assert!(link_notes(&rendered("/data/noo"), Some(&rep)).is_empty());
    }

    #[test]
    fn a_symlink_that_resolves_outside_the_root_still_conflicts() {
        let rep = host3(json!({"running_mounts_resolved": {"/opt/noo/hf-cache": "/mnt/d/noo/hf-cache"}}));
        assert!(data_root_conflict(&rendered("/data/noo"), Some(&rep)).is_some());
        assert!(link_notes(&rendered("/data/noo"), Some(&rep)).is_empty());
    }

    #[test]
    fn a_root_that_is_itself_a_symlink() {
        // /data/noo -> /mnt/vol/noo; the container was created against the target.
        let rep = json!({"noo_data_root": "/data/noo", "noo_data_root_source": "env",
            "noo_data_root_resolved": "/mnt/vol/noo",
            "running_mounts": {"vllm": ["/mnt/vol/noo/hf-cache"]}});
        assert_eq!(data_root_check(&rendered("/data/noo"), Some(&rep)), RootCheck::Agree);
        assert_eq!(link_notes(&rendered("/data/noo"), Some(&rep)).len(), 1);
        // The root's target only counts when the bundle renders the reported root.
        assert!(data_root_conflict(&rendered("/opt/noo"), Some(&rep)).is_some());
    }

    #[test]
    fn mount_row_maps_the_report_exit_codes() {
        use crate::commands::cluster_verify::Verdict;
        let ok = mount_row_from(Some(0), "/d is on its recorded filesystem (UUID a)");
        assert_eq!((ok.name, ok.verdict), (MOUNT_ROW, Verdict::Ok));
        let bad = mount_row_from(Some(3), "the data root /d is not on its recorded filesystem");
        assert_eq!(bad.verdict, Verdict::Fail);
        assert!(bad.detail.contains("not on its recorded filesystem") && bad.remedy.is_some());
        assert_eq!(mount_row_from(Some(4), "no filesystem recorded yet").verdict, Verdict::Warn);
        assert_eq!(mount_row_from(None, "boom").verdict, Verdict::Warn);
    }
}
