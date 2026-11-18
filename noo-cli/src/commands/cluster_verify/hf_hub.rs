// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The `hf-cache hub owner` controller row: `<HF cache>/hub` (where HF
//! weights land, node-agent-go MirrorHFRepo) must be owned like the HF cache
//! itself. On a fresh controller the onboard storage step made hub before
//! prep-host created noo-agent, so hub stayed 0:0 under a noo-agent hf-cache
//! and the agent could not write the weights. The self-node's root applier
//! (scripts/noo-apply.sh `hf_hub_reown`) repairs exactly that case at its
//! next apply; this row says whether that is still due.
//!
//! WHICH HF cache: the one the self-node AGENT stages into, never the CLI's
//! own `HF_CACHE_DIR` (that is the controller compose's cache, which vllm/TEI
//! mount and the gateway serves as /hf/; it may be a different directory,
//! ctrl 0.6.26: an operator-owned NFS dir). The agent's cache is, in order:
//! (a) what the self node's heartbeat reports (`data_roots.hf_cache_dir`,
//! node-agent-go dataroots.Resolve over the agent's env); (b) the agent's
//! EnvironmentFile [`AGENT_ENV`] (HF_CACHE_DIR, else NOO_DATA_ROOT/hf-cache);
//! (c) unknown, said as such. When the compose cache is another directory it
//! gets its own advisory row, [`CONTROLLER_ROW`], with no applier claim.
//!
//! [`row`] / [`controller_row`] are pure over what [`read`] saw; [`live`]
//! gathers it.

use super::{ok, warn, Check};
use serde_json::Value;
use std::path::Path;

pub(crate) const ROW: &str = "hf-cache hub owner";
pub(crate) const CONTROLLER_ROW: &str = "controller hf-cache hub owner";

/// The self-node's root applier, as prep-host installs it.
const APPLIER: &str = "/usr/local/bin/noo-apply";
/// The agent unit's EnvironmentFile (node-agent-go/deploy/noo-node-agent.service;
/// noo-apply installs it, root 0600, so a non-root verify usually cannot read it).
const AGENT_ENV: &str = "/etc/noo-node-agent.env";
const AGENT_USER: &str = "noo-agent";

/// (uid, gid)
pub(crate) type Owner = (u32, u32);

/// What was read about hub: absent, a symlink, or a directory with its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hub {
    Absent,
    Symlink,
    Dir(Owner),
}

/// What [`read`] saw at one HF cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    pub cache_owner: Option<Owner>,
    pub hub: Hub,
    /// (fstype, mount point) when the cache sits on a network filesystem,
    /// whose server maps the ids: ownership read here proves nothing.
    pub netfs: Option<(String, String)>,
}

/// The self-node agent's HF cache and where that answer came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentCache {
    pub path: String,
    /// The agent's NOO_DATA_ROOT (the applier repairs only inside it).
    pub root: Option<String>,
    pub from: String,
}

/// The self-node agent's HF cache, in source order: (a) the self node's
/// heartbeat in `fleet` (`/api/cluster/nodes`: `self_node: true`, else the id
/// `is_self` names); (b) the agent's env file text; else None.
pub(crate) fn agent_cache(fleet: Option<&Value>, is_self: &dyn Fn(&str) -> bool, agent_env: Option<&str>) -> Option<AgentCache> {
    let abs = |v: &Value| v.as_str().map(crate::commands::data_root::norm).filter(|s| s.starts_with('/'));
    let nodes = fleet.and_then(|f| f["nodes"].as_array().or_else(|| f.as_array()));
    let me = nodes.and_then(|ns| {
        ns.iter().find(|n| n["self_node"].as_bool() == Some(true))
            .or_else(|| ns.iter().find(|n| n["id"].as_str().is_some_and(is_self)))
    });
    if let Some(n) = me {
        let dr = &n["data_roots"];
        let root = abs(&dr["noo_data_root"]);
        let path = abs(&dr["hf_cache_dir"]).or_else(|| root.as_ref().map(|r| format!("{r}/hf-cache")));
        if let Some(path) = path {
            let id = n["id"].as_str().unwrap_or("?");
            return Some(AgentCache { path, root, from: format!("reported by self node {id}") });
        }
    }
    let text = agent_env?;
    let get = |k: &str| {
        text.lines()
            .filter_map(|l| l.trim().strip_prefix(k)?.strip_prefix('='))
            .next_back()
            .map(|v| v.trim().trim_matches('"').trim_matches('\''))
            .map(crate::commands::data_root::norm)
            .filter(|v| v.starts_with('/'))
    };
    let root = get("NOO_DATA_ROOT").unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.to_string());
    let path = get("HF_CACHE_DIR").unwrap_or_else(|| format!("{root}/hf-cache"));
    Some(AgentCache { path, root: Some(root), from: format!("from {AGENT_ENV}") })
}

/// The network filesystem `path` lives on, from a `/proc/self/mountinfo`
/// table: the longest mount point that holds it, when its type is one whose
/// server maps the ids (nfs, cifs/smb, sshfs, 9p, ceph, gluster).
pub(crate) fn network_fs(mountinfo: &str, path: &str) -> Option<(String, String)> {
    const NET: [&str; 10] = ["nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p", "ceph", "glusterfs", "fuse.glusterfs"];
    let unescape = |s: &str| s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\");
    let mut best: Option<(String, String)> = None;
    for line in mountinfo.lines() {
        let Some((pre, post)) = line.split_once(" - ") else { continue };
        let Some(mp) = pre.split(' ').nth(4).map(unescape) else { continue };
        let Some(fstype) = post.split(' ').next() else { continue };
        let holds = mp == "/" || path == mp || path.starts_with(&format!("{mp}/"));
        if holds && best.as_ref().is_none_or(|(_, b)| mp.len() >= b.len()) {
            best = Some((fstype.to_string(), mp));
        }
    }
    best.filter(|(t, _)| NET.contains(&t.as_str()))
}

/// The agent's row. `agent_uid`: noo-agent's uid on this machine.
/// `applier`: the self-node's root applier is installed AND would act on this
/// cache (physically inside the agent's NOO_DATA_ROOT, no symlink below it:
/// noo-apply.sh hf_hub_reown's own conditions).
pub(crate) fn row(cache: &str, from: &str, seen: &Seen, agent_uid: Option<u32>, applier: bool) -> Check {
    judge(ROW, cache, from, seen, Some((agent_uid, applier)))
}

/// The controller compose's HF cache, when it is not the agent's: the same
/// comparison, the remedy a stated chown, never the applier.
pub(crate) fn controller_row(cache: &str, seen: &Seen) -> Check {
    judge(CONTROLLER_ROW, cache, "the controller compose's HF_CACHE_DIR", seen, None)
}

/// The row when nothing says which HF cache the self-node agent uses.
pub(crate) fn unknown_row() -> Check {
    ok(ROW, format!(
        "cannot tell which HF cache the self-node agent uses (no self node in the gateway's node list, {AGENT_ENV} unreadable): not judged"
    ))
}

fn judge(name: &'static str, cache: &str, from: &str, seen: &Seen, agent: Option<(Option<u32>, bool)>) -> Check {
    let hub_path = format!("{cache}/hub");
    let Some(c) = seen.cache_owner else {
        return ok(name, format!("{cache} ({from}) does not exist yet: nothing to compare"));
    };
    if let Some((fstype, mp)) = &seen.netfs {
        return ok(name, format!("{cache} ({from}): cannot judge ownership on a network filesystem ({fstype} at {mp}); its server maps the ids"));
    }
    let chown = |h: Owner, why: &str| format!(
        "{hub_path} is owned by {}:{}, {cache} ({from}) by {}:{}{why}: once, at a terminal: sudo chown -R -P -h {}:{} {hub_path} \
         (owner only; links are not followed)",
        h.0, h.1, c.0, c.1, c.0, c.1
    );
    match seen.hub {
        Hub::Absent => ok(name, format!("{hub_path} does not exist yet (made with {cache}'s owner, {from})")),
        Hub::Symlink => warn(
            name,
            format!("{hub_path} is a symlink ({from}): the self-node's applier leaves it as it is; give its target {cache}'s owner ({}:{}) by hand", c.0, c.1),
            None,
        ),
        Hub::Dir(h) if h == c => ok(name, format!("{hub_path} and {cache} ({from}) are both owned by {}:{}", h.0, h.1)),
        Hub::Dir(h) if h.0 == c.0 => ok(
            name,
            format!(
                "{hub_path} is owned by {}:{}, {cache} ({from}) by {}:{}: the same user owns both (only the group differs); nothing to repair",
                h.0, h.1, c.0, c.1
            ),
        ),
        Hub::Dir(h) if h.0 == 0 => match agent {
            Some((Some(au), true)) if au == c.0 => warn(
                name,
                format!(
                    "{hub_path} is owned by {}:{}, {cache} ({from}) by {}:{}: the self-node's applier re-owns it at its next apply",
                    h.0, h.1, c.0, c.1
                ),
                None,
            ),
            Some((_, false)) => warn(name, chown(h, ", and this controller has no self-node applier to re-own it"), None),
            _ => warn(name, chown(h, ", and nothing repairs it automatically"), None),
        },
        Hub::Dir(h) => warn(name, chown(h, ", and nothing repairs it automatically"), None),
    }
}

/// Reads the two owners (the link itself for a symlinked hub, never its
/// target) and whether the cache sits on a network filesystem.
pub(crate) fn read(cache: &Path, mountinfo: &str) -> Seen {
    use std::os::unix::fs::MetadataExt;
    let cache_owner = std::fs::metadata(cache).ok().filter(|m| m.is_dir()).map(|m| (m.uid(), m.gid()));
    let hub = match std::fs::symlink_metadata(cache.join("hub")) {
        Err(_) => Hub::Absent,
        Ok(m) if m.file_type().is_symlink() => Hub::Symlink,
        Ok(m) => Hub::Dir((m.uid(), m.gid())),
    };
    let real = std::fs::canonicalize(cache).unwrap_or_else(|_| cache.to_path_buf());
    let netfs = network_fs(mountinfo, &real.to_string_lossy());
    Seen { cache_owner, hub, netfs }
}

/// noo-apply.sh hf_hub_reown's place condition: `cache` resolves strictly
/// inside `root` and no component below the root is a symlink.
fn applier_reaches(cache: &str, root: &str) -> bool {
    let (Ok(rr), Ok(rc)) = (std::fs::canonicalize(root), std::fs::canonicalize(cache)) else { return false };
    let Ok(rel) = Path::new(cache).strip_prefix(root) else { return false };
    !rel.as_os_str().is_empty() && rc == rr.join(rel)
}

fn agent_uid() -> Option<u32> {
    let c = std::ffi::CString::new(AGENT_USER).ok()?;
    // SAFETY: getpwnam reads the password database; the uid is copied out at once.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: pw is non-null and points at the static record getpwnam returned.
    Some(unsafe { (*pw).pw_uid })
}

/// The CLI's own `HF_CACHE_DIR` (envfile::ensure_repo_env): the controller
/// compose's cache.
fn compose_cache() -> String {
    crate::envfile::ensure_repo_env();
    let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().trim_end_matches('/').to_string()).filter(|v| !v.is_empty());
    var("HF_CACHE_DIR").unwrap_or_else(|| {
        let root = var("NOO_DATA_ROOT").unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.trim_end_matches('/').to_string());
        format!("{root}/hf-cache")
    })
}

/// The agent's row, plus the compose cache's own row when that is another
/// directory (or the agent's is unknown). `fleet`: `/api/cluster/nodes`.
pub(crate) fn live(fleet: Option<&Value>) -> Vec<Check> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let env_text = std::fs::read_to_string(AGENT_ENV).ok();
    let agent = agent_cache(fleet, &crate::role::is_self_node, env_text.as_deref());
    let mut out = Vec::new();
    match &agent {
        Some(a) => {
            let seen = read(Path::new(&a.path), &mountinfo);
            let applier = Path::new(APPLIER).is_file() && a.root.as_deref().is_some_and(|r| applier_reaches(&a.path, r));
            out.push(row(&a.path, &a.from, &seen, agent_uid(), applier));
        }
        None => out.push(unknown_row()),
    }
    let ctl = compose_cache();
    let same = |a: &AgentCache| {
        let canon = |p: &str| std::fs::canonicalize(p).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| p.to_string());
        crate::commands::data_root::norm(&a.path) == crate::commands::data_root::norm(&ctl) || canon(&a.path) == canon(&ctl)
    };
    if !agent.as_ref().is_some_and(same) {
        out.push(controller_row(&ctl, &read(Path::new(&ctl), &mountinfo)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;
    use serde_json::json;

    fn local(cache_owner: Option<Owner>, hub: Hub) -> Seen {
        Seen { cache_owner, hub, netfs: None }
    }
    const HB: &str = "reported by self node ctrl";

    /// ctrl since 2026-09-07 (and every fresh controller before the fix):
    /// hub 0:0 under a noo-agent hf-cache.
    #[test]
    fn a_root_owned_hub_under_the_agents_hf_cache_warns_with_both_owners() {
        let c = row("/var/lib/noo/hf-cache", HB, &local(Some((122, 998)), Hub::Dir((0, 0))), Some(122), true);
        assert_eq!(c.verdict, Verdict::Warn);
        assert_eq!(c.name, ROW);
        assert_eq!(
            c.detail,
            "/var/lib/noo/hf-cache/hub is owned by 0:0, /var/lib/noo/hf-cache (reported by self node ctrl) by 122:998: \
             the self-node's applier re-owns it at its next apply"
        );
    }

    #[test]
    fn without_an_applier_the_remedy_is_a_stated_sudo_chown() {
        let s = local(Some((993, 982)), Hub::Dir((0, 0)));
        let c = row("/var/lib/noo/hf-cache", HB, &s, Some(993), false);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("no self-node applier"), "{}", c.detail);
        assert!(c.detail.contains("sudo chown -R -P -h 993:982 /var/lib/noo/hf-cache/hub"), "{}", c.detail);
        assert!(!c.detail.contains("re-owns it at its next apply"), "{}", c.detail);
        let w = row("/var/lib/noo/hf-cache", HB, &s, Some(993), true);
        assert!(w.detail.contains("re-owns it at its next apply") && !w.detail.contains("sudo"), "{}", w.detail);
        // hub 0 under an hf-cache that is NOT noo-agent's: the applier does
        // not act (hf_hub_reown condition d), so no claim that it will.
        let x = row("/var/lib/noo/hf-cache", HB, &s, Some(122), true);
        assert_eq!(x.verdict, Verdict::Warn);
        assert!(!x.detail.contains("re-owns it at its next apply") && x.detail.contains("sudo chown -R -P -h 993:982"), "{}", x.detail);
        assert!(!row("/var/lib/noo/hf-cache", HB, &s, None, true).detail.contains("re-owns"));
    }

    #[test]
    fn the_same_owner_is_ok_and_nothing_to_compare_is_ok() {
        assert_eq!(row("/d/hf-cache", HB, &local(Some((122, 998)), Hub::Dir((122, 998))), Some(122), true).verdict, Verdict::Ok);
        assert_eq!(row("/d/hf-cache", HB, &local(Some((122, 998)), Hub::Absent), Some(122), true).verdict, Verdict::Ok);
        assert_eq!(row("/d/hf-cache", HB, &local(None, Hub::Absent), Some(122), true).verdict, Verdict::Ok);
        let s = row("/d/hf-cache", HB, &local(Some((122, 998)), Hub::Symlink), Some(122), true);
        assert_eq!(s.verdict, Verdict::Warn);
        assert!(s.detail.contains("is a symlink") && s.detail.contains("122:998") && s.detail.contains("/d/hf-cache/hub"), "{}", s.detail);
    }

    /// ctrl after the 0.6.26 roll, the compose cache: hub 1000:1001 under
    /// hf-cache 1000:1000. Same uid: OK, the path printed, no applier text.
    #[test]
    fn the_same_uid_with_another_gid_is_ok_and_names_the_path() {
        let s = local(Some((1000, 1000)), Hub::Dir((1000, 1001)));
        for c in [row("/mnt/fleet/models/hf", HB, &s, Some(993), true), controller_row("/mnt/fleet/models/hf", &s)] {
            assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
            assert!(c.detail.contains("/mnt/fleet/models/hf/hub is owned by 1000:1001"), "{}", c.detail);
            assert!(c.detail.contains("nothing to repair"), "{}", c.detail);
            assert!(!c.detail.contains("re-owns") && !c.detail.contains("applier"), "{}", c.detail);
        }
    }

    #[test]
    fn another_non_root_uid_warns_with_a_stated_chown_never_the_applier() {
        let s = local(Some((993, 982)), Hub::Dir((1000, 1000)));
        for c in [row("/data/noo/hf-cache", HB, &s, Some(993), true), controller_row("/data/noo/hf-cache", &s)] {
            assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
            assert!(c.detail.contains("/data/noo/hf-cache/hub is owned by 1000:1000"), "{}", c.detail);
            assert!(c.detail.contains("sudo chown -R -P -h 993:982 /data/noo/hf-cache/hub"), "{}", c.detail);
            assert!(!c.detail.contains("re-owns"), "{}", c.detail);
        }
        // The controller row never claims the applier, hub 0 included.
        let r = controller_row("/data/noo/hf-cache", &local(Some((993, 982)), Hub::Dir((0, 0))));
        assert_eq!(r.name, CONTROLLER_ROW);
        assert!(r.detail.contains("sudo chown") && !r.detail.contains("re-owns"), "{}", r.detail);
    }

    #[test]
    fn a_network_filesystem_is_not_judged() {
        let mi = "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
                  90 22 0:51 / /mnt/fleet rw,relatime shared:40 - nfs4 192.0.2.10:/srv/storage rw,vers=4.2\n\
                  91 22 0:52 / /mnt/my\\040share rw - cifs //nas/s rw\n\
                  92 90 8:3 / /mnt/fleet/local rw - ext4 /dev/sdb1 rw\n";
        assert_eq!(network_fs(mi, "/mnt/fleet/models/hf"), Some(("nfs4".into(), "/mnt/fleet".into())));
        assert_eq!(network_fs(mi, "/mnt/fleet"), Some(("nfs4".into(), "/mnt/fleet".into())));
        assert_eq!(network_fs(mi, "/mnt/my share/hf"), Some(("cifs".into(), "/mnt/my share".into())));
        assert_eq!(network_fs(mi, "/mnt/fleet/local/hf"), None, "the longest mount point decides");
        assert_eq!(network_fs(mi, "/mnt/fleetx/hf"), None, "a prefix that is not a path component");
        assert_eq!(network_fs(mi, "/var/lib/noo/hf-cache"), None);
        assert_eq!(network_fs("", "/x"), None);
        let s = Seen { cache_owner: Some((1000, 1000)), hub: Hub::Dir((0, 0)), netfs: Some(("nfs4".into(), "/mnt/fleet".into())) };
        let c = controller_row("/mnt/fleet/models/hf", &s);
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("cannot judge ownership on a network filesystem (nfs4 at /mnt/fleet)"), "{}", c.detail);
        assert!(c.detail.contains("/mnt/fleet/models/hf"), "{}", c.detail);
    }

    /// (a) the self node's heartbeat, (b) the agent env file, (c) nothing,
    /// and never the CLI's own HF_CACHE_DIR.
    #[test]
    fn the_agents_cache_comes_from_the_heartbeat_then_the_env_file() {
        let fleet = json!({"nodes": [
            {"id": "node_a", "data_roots": {"noo_data_root": "/data/noo", "hf_cache_dir": "/data/noo/hf-cache"}},
            {"id": "ctrl", "self_node": true, "data_roots": {"noo_data_root": "/srv/noo",
                "hf_cache_dir": "/srv/noo/hf-cache/"}}]});
        let env = "NOO_DATA_ROOT=/env/noo\nHF_CACHE_DIR=\"/env/hf\"\n";
        let a = agent_cache(Some(&fleet), &|_| false, Some(env)).unwrap();
        assert_eq!(a.path, "/srv/noo/hf-cache");
        assert_eq!(a.root.as_deref(), Some("/srv/noo"));
        assert_eq!(a.from, "reported by self node ctrl");
        // No self_node flag: the id the identity names.
        let mut f2 = fleet.clone();
        f2["nodes"][1]["self_node"] = Value::Null;
        assert_eq!(agent_cache(Some(&f2), &|id| id == "node_a", Some(env)).unwrap().path, "/data/noo/hf-cache");
        // A heartbeat with only the root: its hf-cache child.
        let f3 = json!({"nodes": [{"id": "box", "self_node": true, "data_roots": {"noo_data_root": "/r"}}]});
        assert_eq!(agent_cache(Some(&f3), &|_| false, None).unwrap().path, "/r/hf-cache");
        // (b) the env file: HF_CACHE_DIR, else NOO_DATA_ROOT/hf-cache, else the built-in root.
        let b = agent_cache(None, &|_| false, Some(env)).unwrap();
        assert_eq!((b.path.as_str(), b.root.as_deref()), ("/env/hf", Some("/env/noo")));
        assert!(b.from.contains(AGENT_ENV), "{}", b.from);
        assert_eq!(agent_cache(Some(&json!({"nodes": []})), &|_| false, Some("NOO_DATA_ROOT=/e\n")).unwrap().path, "/e/hf-cache");
        assert_eq!(agent_cache(None, &|_| false, Some("")).unwrap().path, "/var/lib/noo/hf-cache");
        // (c) nothing: unknown, said as OK.
        assert_eq!(agent_cache(None, &|_| false, None), None);
        let u = unknown_row();
        assert_eq!((u.name, u.verdict), (ROW, Verdict::Ok));
        assert!(u.detail.contains("cannot tell which HF cache the self-node agent uses"), "{}", u.detail);
    }

    /// `live` never judges the CLI's own HF_CACHE_DIR as the agent's.
    #[test]
    fn live_reads_the_agents_cache_not_the_cli_env() {
        let src = crate::test_src::own_code(include_str!("hf_hub.rs"));
        let live = crate::test_src::fn_body(&src, "pub(crate) fn live(");
        assert!(live.contains("agent_cache(fleet"), "{live}");
        assert!(!live.contains("var(\"HF_CACHE_DIR\")"), "{live}");
        assert!(live.contains("controller_row(&ctl"), "{live}");
    }

    /// Read from a real tree: the same owner (whatever this test runs as) is OK,
    /// a symlinked hub is read as the link, an absent one as absent.
    #[test]
    fn read_takes_both_owners_from_the_tree() {
        use std::os::unix::fs::MetadataExt;
        let b = std::env::temp_dir().join(format!("noo-hfhub-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&b);
        let cache = b.join("hf-cache");
        std::fs::create_dir_all(&cache).unwrap();
        assert_eq!(read(&cache, "").hub, Hub::Absent);
        std::fs::create_dir(cache.join("hub")).unwrap();
        let m = std::fs::metadata(&cache).unwrap();
        let seen = read(&cache, "");
        assert_eq!(seen.cache_owner, Some((m.uid(), m.gid())));
        assert_eq!(seen.hub, Hub::Dir((m.uid(), m.gid())));
        assert_eq!(row(&cache.display().to_string(), HB, &seen, None, true).verdict, Verdict::Ok);
        assert!(applier_reaches(&cache.display().to_string(), &b.display().to_string()));
        assert!(!applier_reaches(&b.display().to_string(), &b.display().to_string()), "the root itself is not inside");
        std::fs::remove_dir(cache.join("hub")).unwrap();
        std::os::unix::fs::symlink(&b, cache.join("hub")).unwrap();
        assert_eq!(read(&cache, "").hub, Hub::Symlink);
        std::os::unix::fs::symlink(&cache, b.join("via")).unwrap();
        assert!(!applier_reaches(&b.join("via").display().to_string(), &b.display().to_string()), "a symlink below the root");
        assert_eq!(read(&b.join("missing"), "").cache_owner, None);
        let _ = std::fs::remove_dir_all(&b);
    }
}
