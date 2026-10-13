// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Is the gateway's view of `noomesh.yaml` an orphan?
//!
//! `noomesh.yaml` is bind-mounted into the containers as a single FILE. A
//! writer that replaces the host file by rename (`sed -i`, an editor's
//! save-as-new) leaves every running container bound to the unlinked inode.
//! Reads and writes keep agreeing with each other inside the container, so
//! nothing looks wrong, and the next recreate re-binds the host path and
//! silently discards whatever the container saw.
//!
//! The kernel says so in `/proc/self/mountinfo`: the mount's root column
//! carries a `//deleted` suffix. This module reads that, whoever caused it,
//! and raises one operator alert through the usual funnel.
//!
//! Failure semantics: an unreadable mountinfo, a path that is not a mount
//! target (a directory mount, a plain file in the image) and a path that
//! cannot be resolved are all [`MountState::Unknown`] or
//! [`MountState::NotMounted`] — never an alert, never a pass. The check only
//! speaks when the kernel affirmatively reports `//deleted`.

use crate::operator_alert::{send_operator_alert_with, OperatorAlert};
use crate::state::AppState;

/// One alert per day per condition; the condition is sticky until a recreate.
const ALERT_COOLDOWN_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountState {
    /// The path is a mount target and its source still exists.
    Clean,
    /// The path is a mount target whose source inode was unlinked. Carries the
    /// mount root as reported (`/host/path//deleted`).
    Orphaned(String),
    /// The path is not a mount target here (nothing to orphan).
    NotMounted,
    /// Could not be determined (mountinfo unreadable).
    Unknown,
}

/// Undo mountinfo's octal escapes (`\040` for space, `\011` tab, `\134` `\`).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Pure: classify `target` against the text of a mountinfo file. The LAST
/// entry for a target wins (a later mount covers an earlier one).
pub fn classify(mountinfo: &str, target: &str) -> MountState {
    let mut found: Option<&str> = None;
    let mut root_of: Option<String> = None;
    for line in mountinfo.lines() {
        // id parent major:minor root mountpoint options ...
        let mut f = line.split(' ');
        let (Some(_), Some(_), Some(_), Some(root), Some(mp)) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        if unescape(mp) == target {
            found = Some(line);
            root_of = Some(unescape(root));
        }
    }
    match (found, root_of) {
        (Some(_), Some(root)) if root.ends_with("//deleted") => MountState::Orphaned(root),
        (Some(_), Some(_)) => MountState::Clean,
        _ => MountState::NotMounted,
    }
}

/// Read this process's mountinfo and classify the config path.
pub fn inspect(config_path: &str) -> MountState {
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return MountState::Unknown;
    };
    // mountinfo lists the path as this namespace sees it, symlinks resolved.
    let resolved = std::fs::canonicalize(config_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| config_path.to_string());
    classify(&info, &resolved)
}

/// Check the live config path and, when orphaned, alert the operator.
/// Called at startup and after every config write this process performs.
pub async fn check_and_alert(state: &AppState, config_path: &str, when: &str) {
    let MountState::Orphaned(root) = inspect(config_path) else {
        return;
    };
    tracing::error!(
        path = %config_path, mount_root = %root, when = %when,
        "config bind mount is ORPHANED: the host's noomesh.yaml was replaced by a new file, so \
         this container sees an unlinked inode. Config changes made here or on the host no \
         longer reach each other and a recreate will silently discard the container's view."
    );
    send_operator_alert_with(
        state,
        OperatorAlert::new(
            "config.mount_orphaned",
            "noomesh.yaml",
            "⚠️ The gateway's noomesh.yaml is out of sync with the host file; a restart would discard config changes.",
        )
        .detail(format!("{when}: mount root {root} for {config_path}"))
        .investigate("noo stack restart --force gateway"),
        ALERT_COOLDOWN_SECS,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = "\
1690 1681 0:52 / /app/data rw,relatime - overlay overlay rw\n\
1698 1681 259:3 /home/alice/.noo/noomesh.yaml /app/noomesh.yaml rw,noatime - ext4 /dev/sdc rw\n";
    const DELETED: &str = "\
1690 1681 0:52 / /app/data rw,relatime - overlay overlay rw\n\
1698 1681 259:3 /home/alice/.noo/noomesh.yaml//deleted /app/noomesh.yaml rw,noatime - ext4 /dev/sdc rw\n";

    #[test]
    fn deleted_source_reads_as_orphaned() {
        assert_eq!(
            classify(DELETED, "/app/noomesh.yaml"),
            MountState::Orphaned("/home/alice/.noo/noomesh.yaml//deleted".into())
        );
    }

    #[test]
    fn live_source_reads_as_clean() {
        assert_eq!(classify(CLEAN, "/app/noomesh.yaml"), MountState::Clean);
    }

    #[test]
    fn unmounted_path_is_not_a_verdict() {
        assert_eq!(classify(DELETED, "/etc/other.yaml"), MountState::NotMounted);
        assert_eq!(classify("", "/app/noomesh.yaml"), MountState::NotMounted);
        assert_eq!(classify("garbage line", "/app/noomesh.yaml"), MountState::NotMounted);
    }

    #[test]
    fn later_mount_wins_and_escapes_decode() {
        let both = format!("{DELETED}1700 1681 259:3 /home/x/noomesh.yaml /app/noomesh.yaml rw - ext4 /dev/sdc rw\n");
        assert_eq!(classify(&both, "/app/noomesh.yaml"), MountState::Clean);
        let sp = "5 1 0:1 /a\\040b/n.yaml//deleted /my\\040dir/n.yaml rw - ext4 /d rw\n";
        assert!(matches!(classify(sp, "/my dir/n.yaml"), MountState::Orphaned(r) if r == "/a b/n.yaml//deleted"));
    }

    #[test]
    fn a_name_merely_containing_deleted_is_not_orphaned() {
        let l = "5 1 0:1 /home/u/deleted.yaml /app/noomesh.yaml rw - ext4 /d rw\n";
        assert_eq!(classify(l, "/app/noomesh.yaml"), MountState::Clean);
    }
}
