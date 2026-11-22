// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The `network mount` controller row (i1149): every network mount under the
//! data roots (`NOO_DATA_ROOT`, `MODELS_DIR`, `HF_CACHE_DIR`) answers a
//! bounded `stat` in a child process.
//!
//! After a power cut the controller's hard NFS mount hung, and every call
//! that touched it blocked in D state with no word about why. A hung mount
//! is now one line here. The child process and its deadline live in
//! [`crate::bounded`]; [`judge`] is pure over what [`live`] saw.

use super::{fail, ok, Check};
use crate::bounded::{Mount, STAT_SECS};

pub(crate) const ROW: &str = "network mount";

/// `results`: each probed network mount and whether its stat answered.
pub(crate) fn judge(results: &[(Mount, bool)]) -> Check {
    if results.is_empty() {
        return ok(ROW, "no network mounts under the data roots");
    }
    let hung: Vec<&Mount> = results.iter().filter(|(_, answered)| !answered).map(|(m, _)| m).collect();
    if hung.is_empty() {
        let n = results.len();
        return ok(ROW, format!("{n} network mount{} answered", if n == 1 { "" } else { "s" }));
    }
    let named: Vec<String> = hung.iter().map(|m| m.describe()).collect();
    fail(
        ROW,
        format!(
            "{} did not answer in {STAT_SECS} s: a hung network mount; bring its storage back, do not force-unmount",
            named.join("; ")
        ),
        format!(
            "Bring the storage back (a hard NFS mount resumes by itself once its server answers); do not force-unmount it. \
             `timeout {STAT_SECS} stat {}` shows whether it answers.",
            hung[0].point
        ),
    )
}

pub(crate) fn live() -> Check {
    judge(&crate::bounded::probe_data_roots())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;

    fn nfs() -> Mount {
        Mount { point: "/srv/noo".into(), fstype: "nfs4".into(), source: "filer.example:/export/noo".into() }
    }

    #[test]
    fn a_fresh_cell_with_no_network_mounts_is_ok() {
        let c = judge(&[]);
        assert_eq!(c.verdict, Verdict::Ok);
        assert_eq!(c.name, "network mount");
        assert_eq!(c.detail, "no network mounts under the data roots");
    }

    #[test]
    fn answering_mounts_are_counted() {
        let c = judge(&[(nfs(), true)]);
        assert_eq!(c.verdict, Verdict::Ok);
        assert_eq!(c.detail, "1 network mount answered");
        let c = judge(&[(nfs(), true), (nfs(), true)]);
        assert_eq!(c.detail, "2 network mounts answered");
    }

    #[test]
    fn a_hung_mount_fails_and_names_the_server_and_the_remedy() {
        let c = judge(&[(nfs(), true), (nfs(), false)]);
        assert_eq!(c.verdict, Verdict::Fail);
        assert_eq!(
            c.detail,
            "/srv/noo (nfs4 from filer.example:/export/noo) did not answer in 5 s: a hung network mount; \
             bring its storage back, do not force-unmount"
        );
        let remedy = c.remedy.unwrap_or_default();
        assert!(remedy.contains("do not force-unmount") && remedy.contains("timeout 5 stat /srv/noo"), "{remedy}");
    }
}
