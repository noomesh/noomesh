// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The `hf-cache hub owner` controller row: `HF_CACHE_DIR/hub` (where HF
//! weights land, node-agent-go MirrorHFRepo) must be owned like
//! `HF_CACHE_DIR`. On a fresh controller the onboard storage step made hub
//! before prep-host created noo-agent, so hub stayed 0:0 under a noo-agent
//! hf-cache and the agent could not write the weights. The self-node's root
//! applier (scripts/noo-apply.sh `hf_hub_reown`) repairs it at its next
//! apply; this row says whether that is still due.
//!
//! [`row`] is a pure function of the two owners read; [`live`] reads them
//! from `HF_CACHE_DIR`, else `<NOO_DATA_ROOT>/hf-cache` (compose's default).

use super::{ok, warn, Check};
use std::path::Path;

pub(crate) const ROW: &str = "hf-cache hub owner";

/// (uid, gid)
pub(crate) type Owner = (u32, u32);

/// What was read about hub: absent, a symlink, or a directory with its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hub {
    Absent,
    Symlink,
    Dir(Owner),
}

pub(crate) fn row(cache: &str, cache_owner: Option<Owner>, hub: Hub) -> Check {
    let Some(c) = cache_owner else {
        return ok(ROW, format!("{cache} does not exist yet: nothing to compare"));
    };
    match hub {
        Hub::Absent => ok(ROW, format!("{cache}/hub does not exist yet (made with hf-cache's owner)")),
        Hub::Symlink => warn(
            ROW,
            format!("{cache}/hub is a symlink: the self-node's applier leaves it as it is; give its target hf-cache's owner ({}:{}) by hand", c.0, c.1),
            None,
        ),
        Hub::Dir(h) if h != c => warn(
            ROW,
            format!(
                "hf-cache/hub is owned by {}:{}, hf-cache by {}:{}: the self-node's applier re-owns it at its next apply",
                h.0, h.1, c.0, c.1
            ),
            None,
        ),
        Hub::Dir(h) => ok(ROW, format!("{cache}/hub and {cache} are both owned by {}:{}", h.0, h.1)),
    }
}

/// Reads the two owners (the link itself for a symlinked hub, never its target).
pub(crate) fn read(cache: &Path) -> (Option<Owner>, Hub) {
    use std::os::unix::fs::MetadataExt;
    let cache_owner = std::fs::metadata(cache).ok().filter(|m| m.is_dir()).map(|m| (m.uid(), m.gid()));
    let hub = match std::fs::symlink_metadata(cache.join("hub")) {
        Err(_) => Hub::Absent,
        Ok(m) if m.file_type().is_symlink() => Hub::Symlink,
        Ok(m) => Hub::Dir((m.uid(), m.gid())),
    };
    (cache_owner, hub)
}

pub(crate) fn live() -> Check {
    crate::envfile::ensure_repo_env();
    let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().trim_end_matches('/').to_string()).filter(|v| !v.is_empty());
    let cache = var("HF_CACHE_DIR").unwrap_or_else(|| {
        let root = var("NOO_DATA_ROOT").unwrap_or_else(|| crate::commands::data_root::DEFAULT_DATA_ROOT.trim_end_matches('/').to_string());
        format!("{root}/hf-cache")
    });
    let (cache_owner, hub) = read(Path::new(&cache));
    row(&cache, cache_owner, hub)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;

    /// pop-os since 2026-09-07 (and every fresh controller before the fix):
    /// hub 0:0 under a noo-agent hf-cache.
    #[test]
    fn a_root_owned_hub_under_the_agents_hf_cache_warns_with_both_owners() {
        let c = row("/var/lib/noo/hf-cache", Some((122, 998)), Hub::Dir((0, 0)));
        assert_eq!(c.verdict, Verdict::Warn);
        assert_eq!(c.name, ROW);
        assert_eq!(
            c.detail,
            "hf-cache/hub is owned by 0:0, hf-cache by 122:998: the self-node's applier re-owns it at its next apply"
        );
    }

    #[test]
    fn the_same_owner_is_ok_and_nothing_to_compare_is_ok() {
        assert_eq!(row("/d/hf-cache", Some((122, 998)), Hub::Dir((122, 998))).verdict, Verdict::Ok);
        assert_eq!(row("/d/hf-cache", Some((122, 998)), Hub::Absent).verdict, Verdict::Ok);
        assert_eq!(row("/d/hf-cache", None, Hub::Absent).verdict, Verdict::Ok);
        let s = row("/d/hf-cache", Some((122, 998)), Hub::Symlink);
        assert_eq!(s.verdict, Verdict::Warn);
        assert!(s.detail.contains("is a symlink") && s.detail.contains("122:998"), "{}", s.detail);
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
        assert_eq!(read(&cache).1, Hub::Absent);
        std::fs::create_dir(cache.join("hub")).unwrap();
        let m = std::fs::metadata(&cache).unwrap();
        let (co, hub) = read(&cache);
        assert_eq!(co, Some((m.uid(), m.gid())));
        assert_eq!(hub, Hub::Dir((m.uid(), m.gid())));
        assert_eq!(row(&cache.display().to_string(), co, hub).verdict, Verdict::Ok);
        std::fs::remove_dir(cache.join("hub")).unwrap();
        std::os::unix::fs::symlink(&b, cache.join("hub")).unwrap();
        assert_eq!(read(&cache).1, Hub::Symlink);
        assert_eq!(read(&b.join("missing")).0, None);
        let _ = std::fs::remove_dir_all(&b);
    }
}
