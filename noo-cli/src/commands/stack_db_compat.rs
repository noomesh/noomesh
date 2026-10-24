// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Can the stack release a roll is moving TO run on the database it will meet?
//!
//! The gateway applies the mesh schema at boot and refuses to start on a stamp
//! it does not know ("database is stamped at revision …, which this binary
//! does not know … Refusing to migrate"). So a stack roll BACKWARDS across a
//! migration is an outage: rehearsal 0.6.7-rc.1 F2 rolled v0.6.7-rc.1 (head
//! `094_audit_chain_append_only`) to v0.6.6 (head `093_model_class_pool`), the
//! images moved, and the 0.6.6 gateway crash-looped. Postgres does not
//! un-migrate; only a restore does.
//!
//! This is the refusal that comes BEFORE anything moves. Two sources say what
//! the target knows, in order:
//!
//! 1. the target's signed lock, from the release that first signs it:
//!    `# mesh-migration-head <revision>` (images-release.yml, computed by
//!    `scripts/mesh-migration-head.sh`). Signed, so a mirror cannot lie.
//! 2. [`BAKED_HEADS`], for every release cut before that line existed
//!    (0.6.7-rc.1 and older ship no metadata).
//!
//! A target in neither is refused: "cannot show it runs on this database" is
//! not "fine". An unreadable database stamp is refused for the same reason.
//! There is no override flag: no switch makes a gateway start on a schema it
//! refuses, and the real remedy (a restore) makes the check pass by itself.

use std::cmp::Ordering;

/// `(stack tag, number of the newest mesh migration that release knows)`,
/// from each tag's `gateway-rust/src/mesh_migrate.rs`. Revision ids are
/// `NNN_name` and the chain is linear, so the number orders them. Frozen: a
/// release cut after the lock line (this change) carries its own head in its
/// signed lock and needs no row here.
pub(crate) const BAKED_HEADS: &[(&str, u32)] = &[
    ("v0.6.0-rc.1", 88), ("v0.6.0-rc.2", 88), ("v0.6.0-rc.3", 88), ("v0.6.0-rc.4", 88), ("v0.6.0", 88),
    ("v0.6.1-rc.1", 88), ("v0.6.1", 88),
    ("v0.6.2-rc.1", 88), ("v0.6.2", 88),
    ("v0.6.3-rc.1", 88), ("v0.6.3-rc.2", 88), ("v0.6.3-rc.3", 88), ("v0.6.3", 88),
    ("v0.6.4-rc.1", 88), ("v0.6.4-rc.2", 88), ("v0.6.4-rc.3", 88), ("v0.6.4", 88),
    ("v0.6.5-rc.1", 90), ("v0.6.5-rc.2", 90), ("v0.6.5", 90),
    ("v0.6.6-rc.1", 92), ("v0.6.6-rc.2", 93), ("v0.6.6", 93),
    ("v0.6.7-rc.1", 94),
];

/// The leading number of a revision id (`094_audit_chain_append_only` -> 94).
pub(crate) fn rev_number(rev: &str) -> Option<u32> {
    let digits: String = rev.trim().chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || !rev.trim()[digits.len()..].starts_with('_') {
        return None;
    }
    digits.parse().ok()
}

/// What the signed lock text says the release's newest migration is:
/// `Ok(None)` = the lock carries no such line (an older release),
/// `Err` = the line is there but is not a revision id (or lines disagree) —
/// signed bytes that cannot be read are never guessed around.
pub(crate) fn lock_head(lock_text: &str) -> Result<Option<(String, u32)>, String> {
    let heads: Vec<&str> = lock_text.lines().filter_map(|l| l.trim().strip_prefix("# mesh-migration-head ")).map(str::trim).collect();
    let Some(first) = heads.first() else { return Ok(None) };
    if heads.iter().any(|h| h != first) {
        return Err(format!("the lock names two different migration heads ({})", heads.join(", ")));
    }
    match rev_number(first) {
        Some(n) => Ok(Some((first.to_string(), n))),
        None => Err(format!("the lock's migration head {first:?} is not a revision id")),
    }
}

/// Order of two stack tags including the rc suffix: a final is newer than
/// every rc of its core; `rc.N` orders by N. `None` when either is not a tag.
fn tag_key(t: &str) -> Option<((u64, u64, u64), u64)> {
    let t = t.trim().trim_start_matches("stack-").trim_start_matches('v');
    let (core, rc) = match t.split_once("-rc.") {
        Some((c, n)) => (c, n.parse::<u64>().ok()?),
        None => (t, u64::MAX),
    };
    let mut it = core.split('.');
    let v = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    if it.next().is_some() {
        return None;
    }
    Some((v, rc))
}

/// Is `to` older than `from`, rc included? (`upgrade.rs::is_downgrade` strips
/// the rc, so v0.6.7-rc.2 -> v0.6.7-rc.1 is not a "downgrade" there; it can
/// still cross a migration, so it is checked here.) Unparseable = not backward.
pub(crate) fn is_backward(from: &str, to: &str) -> bool {
    match (tag_key(from), tag_key(to)) {
        (Some(f), Some(t)) => t.cmp(&f) == Ordering::Less,
        _ => false,
    }
}

/// Where the target's head came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeadSource {
    SignedLock,
    Baked,
}

/// The newest migration number the target release knows.
pub(crate) fn target_head(tag: &str, lock_text: Option<&str>) -> Result<Option<(u32, HeadSource)>, String> {
    if let Some(text) = lock_text {
        if let Some((_, n)) = lock_head(text)? {
            return Ok(Some((n, HeadSource::SignedLock)));
        }
    }
    let want = tag_key(tag);
    Ok(BAKED_HEADS.iter().find(|(t, _)| tag_key(t) == want && want.is_some()).map(|(_, n)| (*n, HeadSource::Baked)))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The database stamp could not be read (postgres and the gateway both silent).
    StampUnreadable,
    /// The stamp is not a `NNN_name` revision id.
    StampUnknown(String),
    /// Neither the lock nor the baked table says what the target knows.
    TargetUnknown { tag: String },
    /// The lock's head line is unreadable.
    LockMalformed(String),
    /// The database is ahead of the target.
    DbAhead { stamp: String, head: u32, source: HeadSource, tag: String },
}

/// The decision, pure. `prev`/`tag` are the pinned and target stack tags;
/// `stamp` is the mesh stamp as read (`Err` = could not be read). A roll that
/// is not backwards is never refused here and never reads the database.
pub(crate) fn judge(prev: &str, tag: &str, lock_text: Option<&str>, stamp: &dyn Fn() -> Result<String, String>) -> Result<(), Refusal> {
    if !is_backward(prev, tag) {
        return Ok(());
    }
    let head = target_head(tag, lock_text).map_err(Refusal::LockMalformed)?;
    let stamp = stamp().map_err(|_| Refusal::StampUnreadable)?;
    let Some(n) = rev_number(&stamp) else { return Err(Refusal::StampUnknown(stamp)) };
    let Some((head, source)) = head else { return Err(Refusal::TargetUnknown { tag: tag.to_string() }) };
    if n > head {
        return Err(Refusal::DbAhead { stamp, head, source, tag: tag.to_string() });
    }
    Ok(())
}

/// `(code, message, fix)` for the CLI's refusal. Every message says nothing
/// was changed; the fix is a command `noo` really has.
pub(crate) fn describe(r: &Refusal, prev: &str) -> (&'static str, String, &'static str) {
    const RESTORE: &str = "noo migrate import <archive>   # restore the controller from a `noo migrate export` archive taken before the newer migration, then re-run this command";
    match r {
        Refusal::DbAhead { stamp, head, source, tag } => (
            "stack_rollback_db_ahead",
            format!(
                "rolling back {prev} -> {tag} is refused: the database is stamped at {stamp:?}, and {tag}'s newest migration is #{head:03} ({}). \
                 Its gateway would refuse to start on that stamp (\"which this binary does not know … Refusing to migrate\") and crash-loop. \
                 Postgres does not un-migrate; a real rollback needs the database restored from a backup taken before that migration. Nothing was changed",
                match source { HeadSource::SignedLock => "from its signed lock", HeadSource::Baked => "from this CLI's table of past releases" }),
            RESTORE,
        ),
        Refusal::StampUnreadable => (
            "stack_rollback_db_unreadable",
            "rolling back to an older stack is refused: the database's migration stamp could not be read (postgres and the gateway both unreachable), \
             so it cannot be shown that the older release can run on it. Nothing was changed".to_string(),
            "noo db status   # start postgres/the gateway so the stamp is readable, then re-run (rolling FORWARD is not affected)",
        ),
        Refusal::StampUnknown(s) => (
            "stack_rollback_db_stamp_unknown",
            format!("rolling back to an older stack is refused: the database stamp {s:?} is not a revision id this CLI can order. Nothing was changed"),
            "noo db status",
        ),
        Refusal::TargetUnknown { tag } => (
            "stack_rollback_target_unknown",
            format!(
                "rolling back {prev} -> {tag} is refused: neither {tag}'s signed lock nor this CLI says which migrations that release knows, \
                 so it cannot be shown to run on the current database. Nothing was changed"),
            "noo upgrade --check --stack   # roll to a release this CLI knows, or restore a backup first: noo migrate import <archive>",
        ),
        Refusal::LockMalformed(why) => (
            "stack_lock_migration_head_invalid",
            format!("the target's signed lock is unreadable for the rollback check: {why}. Nothing was changed"),
            "the release was not produced by the release workflow; do not work around this",
        ),
    }
}

/// The preflight: `Ok(())` to go on, `Err((code, message, fix))` to refuse
/// before anything moves. `read_stamp` is injected so a test supplies the DB.
pub(crate) fn preflight(
    prev: &str,
    tag: &str,
    lock_text: Option<&str>,
    read_stamp: &dyn Fn() -> Result<String, String>,
) -> Result<(), (&'static str, String, &'static str)> {
    judge(prev, tag, lock_text, read_stamp).map_err(|r| describe(&r, prev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const HEAD094: &str = "094_audit_chain_append_only";
    fn stamp(s: &'static str) -> impl Fn() -> Result<String, String> {
        move || Ok(s.to_string())
    }

    /// rehearsal 0.6.7-rc.1 F2, exactly: rc.1 (stamp 094) -> v0.6.6, an older
    /// target with no metadata, answered from the baked table.
    #[test]
    fn rolling_back_below_the_stamp_to_a_release_without_metadata_is_refused() {
        let r = judge("v0.6.7-rc.1", "v0.6.6", None, &stamp(HEAD094)).unwrap_err();
        assert_eq!(r, Refusal::DbAhead { stamp: HEAD094.into(), head: 93, source: HeadSource::Baked, tag: "v0.6.6".into() });
        let (code, msg, fix) = describe(&r, "v0.6.7-rc.1");
        assert_eq!(code, "stack_rollback_db_ahead");
        assert!(msg.contains("094_audit_chain_append_only") && msg.contains("#093") && msg.contains("Nothing was changed"), "{msg}");
        assert!(fix.starts_with("noo migrate import"), "names the restore command the CLI has: {fix}");
    }

    #[test]
    fn a_target_that_ships_the_metadata_is_judged_by_its_signed_lock() {
        let lock = "# stack v0.6.8\n# mesh-migration-head 096_next\nghcr.io/x@sha256:aa\n";
        // The db is at 095: the lock's head (096) covers it.
        assert!(judge("v0.6.9", "v0.6.8", Some(lock), &stamp("095_x")).is_ok());
        // At 097 it does not.
        let r = judge("v0.6.9", "v0.6.8", Some(lock), &stamp("097_y")).unwrap_err();
        assert_eq!(r, Refusal::DbAhead { stamp: "097_y".into(), head: 96, source: HeadSource::SignedLock, tag: "v0.6.8".into() });
        // The lock outranks a baked row for the same tag.
        let lock2 = "# stack v0.6.6\n# mesh-migration-head 099_x\n";
        assert!(judge("v0.6.7", "v0.6.6", Some(lock2), &stamp("095_x")).is_ok());
        // A malformed or contradictory line is refused, never guessed around.
        for bad in ["# mesh-migration-head nope\n", "# mesh-migration-head 094_a\n# mesh-migration-head 095_b\n"] {
            assert!(matches!(judge("v0.6.9", "v0.6.8", Some(bad), &stamp("090_x")), Err(Refusal::LockMalformed(_))), "{bad}");
        }
    }

    #[test]
    fn an_unreadable_stamp_or_an_unknown_target_is_refused_not_waved_through() {
        let down = || Err("no postgres".to_string());
        assert_eq!(judge("v0.6.7-rc.1", "v0.6.6", None, &down).unwrap_err(), Refusal::StampUnreadable);
        let (code, msg, fix) = describe(&Refusal::StampUnreadable, "v0.6.7-rc.1");
        assert_eq!(code, "stack_rollback_db_unreadable");
        assert!(msg.contains("Nothing was changed") && fix.contains("noo db status"));
        assert_eq!(judge("v0.6.7-rc.1", "v0.6.6", None, &stamp("not-a-rev")).unwrap_err(), Refusal::StampUnknown("not-a-rev".into()));
        // A tag nobody recorded (older than the table) with no lock line.
        assert_eq!(judge("v0.6.7-rc.1", "v0.5.9", None, &stamp(HEAD094)).unwrap_err(), Refusal::TargetUnknown { tag: "v0.5.9".into() });
    }

    #[test]
    fn a_rollback_that_crosses_no_migration_is_allowed_including_rc_to_rc() {
        // 0.6.6-rc.2 (93) -> 0.6.6-rc.1 (92) crosses 093: refused.
        assert!(matches!(judge("v0.6.6-rc.2", "v0.6.6-rc.1", None, &stamp("093_model_class_pool")), Err(Refusal::DbAhead { .. })));
        // The same rollback while the db is still at 092: fine.
        assert!(judge("v0.6.6-rc.2", "v0.6.6-rc.1", None, &stamp("092_kiosk_seats")).is_ok());
        // final -> its own rc, same head: fine (rc is older than final).
        assert!(judge("v0.6.6", "v0.6.6-rc.2", None, &stamp("093_model_class_pool")).is_ok());
        // an older release whose head still covers the stamp.
        assert!(judge("v0.6.4", "v0.6.0", None, &stamp("088_placement_target_usage")).is_ok());
    }

    #[test]
    fn a_forward_or_same_tag_roll_never_reads_the_database() {
        let reads = Cell::new(0);
        let probe = || { reads.set(reads.get() + 1); Ok(HEAD094.to_string()) };
        for (from, to) in [("v0.6.6", "v0.6.7-rc.1"), ("v0.6.7-rc.1", "v0.6.7-rc.1"), ("v0.6.7-rc.1", "v0.6.7"), ("", "v0.6.6"), ("v0.6.6", "v0.6.7")] {
            assert!(judge(from, to, None, &probe).is_ok(), "{from} -> {to}");
        }
        assert_eq!(reads.get(), 0);
    }

    #[test]
    fn rev_numbers_and_tag_order() {
        assert_eq!(rev_number(HEAD094), Some(94));
        assert_eq!(rev_number("001_a"), Some(1));
        for bad in ["", "abc", "094", "094x", "_x"] {
            assert_eq!(rev_number(bad), None, "{bad}");
        }
        assert!(is_backward("v0.6.7", "v0.6.7-rc.9") && is_backward("v0.6.7-rc.2", "v0.6.7-rc.1") && is_backward("stack-v0.6.7", "0.6.6"));
        assert!(!is_backward("v0.6.7-rc.1", "v0.6.7") && !is_backward("v0.6.7", "v0.6.7") && !is_backward("", "v0.6.7") && !is_backward("v0.6.7", "main"));
    }

    /// The baked table is the release history: every row ordered, no duplicates.
    #[test]
    fn the_baked_table_is_ordered_and_monotone() {
        type Key = ((u64, u64, u64), u64);
        let mut prev: Option<(Key, u32)> = None;
        for (t, n) in BAKED_HEADS {
            let k = tag_key(t).unwrap_or_else(|| panic!("{t}"));
            if let Some((pk, pn)) = prev {
                assert!(k > pk, "{t} out of order");
                assert!(*n >= pn, "{t}: a later release cannot know fewer migrations");
            }
            prev = Some((k, *n));
        }
    }

    /// In `upgrade_stack` the preflight sits ahead of every stage that mints,
    /// writes or moves anything (and ahead of the service-key check, so a
    /// downed gateway after a failed roll does not hide it).
    #[test]
    fn the_preflight_runs_before_anything_moves() {
        use crate::commands::upgrade::phase_src;
        let list = phase_src::list();
        let at = |n: &str| list.find(n).unwrap_or_else(|| panic!("{n} not in the phase list"));
        let pre = at("preflight_db_compat(");
        for later in ["preflight_service_keys(", "addon_preflight(g, &roll.root, &roll.tag", "mint_audit_key(", "move_pin(",
                      "refresh_deploy_slice(", "launch_stack("] {
            assert!(pre < at(later), "the rollback/DB preflight must run before `{later}`");
        }
        let phase = phase_src::body("preflight_db_compat");
        let preflight = phase.find("stack_db_compat::preflight(").expect("the phase runs the preflight");
        assert!(phase.find("fetch_stack_lock(g, tag)").expect("and fetches the lock") < preflight,
            "it reads the target's signed lock, so the lock is fetched first");
        assert!(!list.contains("allow_downgrade) ||") && !phase.contains("force") && !phase.contains("allow_downgrade")
            && !list[pre..at("preflight_service_keys(")].contains("force"),
            "no flag bypasses it");
    }

    /// The refusal fires BEFORE anything is written: with an install dir on
    /// disk, a refused roll leaves every byte of it as it was.
    #[test]
    fn a_refused_rollback_changes_nothing_on_disk() {
        let dir = std::env::temp_dir().join(format!("noo-rollback-db-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), "NOO_IMAGE_TAG=v0.6.7-rc.1\n").unwrap();
        std::fs::write(dir.join("stack.lock"), "# tag v0.6.7-rc.1\n").unwrap();
        let snap = |d: &std::path::Path| {
            let mut v: Vec<(String, Vec<u8>)> = std::fs::read_dir(d).unwrap()
                .map(|e| { let e = e.unwrap(); (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap()) })
                .collect();
            v.sort();
            v
        };
        let before = snap(&dir);
        let prev = std::fs::read_to_string(dir.join(".env")).unwrap()
            .lines().find_map(|l| l.strip_prefix("NOO_IMAGE_TAG=").map(str::to_string)).unwrap();
        let out = preflight(&prev, "v0.6.6", None, &stamp(HEAD094));
        let (code, msg, _) = out.expect_err("the rollback must be refused");
        assert_eq!(code, "stack_rollback_db_ahead");
        assert!(msg.contains("Nothing was changed"));
        assert_eq!(snap(&dir), before, "no tag, lock or env was written");
        assert_eq!(std::fs::read_to_string(dir.join(".env")).unwrap(), "NOO_IMAGE_TAG=v0.6.7-rc.1\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
