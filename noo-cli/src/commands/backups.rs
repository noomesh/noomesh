// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo backups status|setup` — where the backups go, and whether anyone
//! has actually decided.
//!
//! ## Unset is not "no"
//!
//! A backup on the machine it protects survives nothing. This controller
//! holds the Postgres volume, every dump and the encrypted copy of the age
//! key on one disk, so one disk loss takes the data and the means to read it
//! back, together.
//!
//! `scripts/backup-controller.sh` will copy each new artifact off the box
//! when `NOO_BACKUP_OFFSITE` says where. The failure mode this module exists
//! to close is not a broken copy — that one is loud, and exits non-zero so
//! the heartbeat raises it. It is the copy nobody ever configured. An unset
//! variable reads, from the inside, exactly like a system that is fine:
//! nothing errors, nothing warns, every backup reports success, and the
//! backups are all in one place.
//!
//! So unset is a THIRD state, distinct from both "configured" and "declined".
//! `status` says so, `doctor` reports it, and `setup` is how it stops being
//! true. `none` is a real answer — the risk understood and recorded — and it
//! is deliberately not the same as never having been asked.
//!
//! ## Why `portable` exists
//!
//! The obvious destinations assume a second machine or a network target. A
//! box that has neither is the common case for a single-node install, and
//! offering only options such an operator cannot use is how a prompt teaches
//! people to skip it. `portable` is the honest answer for that box: no
//! automatic copy, and `scripts/noo-backup-export.sh` builds one bundle to
//! carry off by hand.
//!
//! ## The forms live in two places, and a test holds them together
//!
//! This module writes the value; `offsite_copy()` in
//! `scripts/backup-controller.sh` reads it. A form this offers that the
//! script does not handle is a destination the operator configures, is told
//! is fine, and which then fails at 3am — or worse, is silently ignored.
//! `tests/test_backups_leave_the_machine.py` reads BOTH sources and pins
//! them to the same set.

use serde_json::json;

use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

/// The environment key `backup-controller.sh` reads.
pub const OFFSITE_KEY: &str = "NOO_BACKUP_OFFSITE";

/// A destination the operator has chosen.
#[derive(Debug, Clone, PartialEq)]
pub enum Destination {
    /// `scp` each new artifact to `user@host:/path`.
    Ssh(String),
    /// Copy to a mounted directory — an external drive, a NAS.
    Dir(String),
    /// Hand to `aws s3 cp` or `rclone copyto`.
    S3(String),
    /// No automatic copy; the operator runs the export and carries it off.
    Portable,
    /// The risk is understood and accepted, on purpose.
    Declined,
}

impl Destination {
    /// The string written to `.env`, and the one the script parses.
    pub fn as_value(&self) -> String {
        match self {
            Destination::Ssh(t) => format!("ssh:{t}"),
            Destination::Dir(t) => format!("dir:{t}"),
            Destination::S3(t) => format!("s3:{t}"),
            Destination::Portable => "portable".to_string(),
            Destination::Declined => "none".to_string(),
        }
    }

    /// What the operator should understand will happen.
    pub fn explain(&self) -> String {
        match self {
            Destination::Ssh(t) => format!("every new backup is scp'd to {t}"),
            Destination::Dir(t) => format!("every new backup is copied to {t}"),
            Destination::S3(t) => format!("every new backup is uploaded to {t}"),
            Destination::Portable => {
                "nothing is copied automatically — run scripts/noo-backup-export.sh and carry \
                 the bundle off yourself"
                    .to_string()
            }
            Destination::Declined => {
                "nothing leaves this machine, and that is recorded as a decision rather than \
                 an oversight"
                    .to_string()
            }
        }
    }
}

/// Parse a destination, refusing anything the script would not handle.
///
/// Pure, and strict on purpose. A value this accepts but `offsite_copy`
/// rejects becomes a destination the operator was told was fine, which fails
/// in a cron job at 3am — and a prefix with an empty target (`dir:`) is the
/// easy typo that produces exactly that.
pub fn parse_destination(raw: &str) -> Result<Destination, String> {
    let v = raw.trim();
    let target = |prefix: &str| -> Result<String, String> {
        let t = v[prefix.len()..].trim().to_string();
        if t.is_empty() {
            Err(format!("`{prefix}` needs a target after it — `{prefix}…` alone names nowhere"))
        } else {
            Ok(t)
        }
    };
    match v {
        "" => Err("no destination given".to_string()),
        "portable" => Ok(Destination::Portable),
        "none" => Ok(Destination::Declined),
        _ if v.starts_with("ssh:") => target("ssh:").map(Destination::Ssh),
        _ if v.starts_with("dir:") => target("dir:").map(Destination::Dir),
        _ if v.starts_with("s3:") => target("s3:").map(Destination::S3),
        _ => Err(format!(
            "`{v}` is not a destination this backup script can use. Expected one of: \
             ssh:user@host:/path, dir:/mnt/disk, s3:s3://bucket/prefix, portable, none"
        )),
    }
}

/// What is configured right now, if anything.
///
/// `Ok(None)` is the state this module is about: nobody has decided. It is
/// deliberately not folded into `Err`, because an unset destination is not a
/// malformed one and must not be reported as a mistake — it is a question
/// that has never been asked.
///
/// The value comes from the same two places, in the same order, as
/// `scripts/backup-controller.sh`: an exported variable, else the last
/// assignment in the checkout's `.env` (where `setup` writes it). Reading only
/// the process environment is how status said "nobody has decided" about a
/// destination the operator had set, and how the backup, run by hostd, could
/// not see it either (2026-10-24).
pub fn current() -> Result<Option<Destination>, String> {
    let env = std::env::var(OFFSITE_KEY).ok().filter(|v| !v.trim().is_empty());
    let raw = env.or_else(|| {
        let v = crate::onboard::env::read_env_key(&crate::envfile::repo_root().join(".env"), OFFSITE_KEY);
        let v = v.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
        (!v.is_empty()).then_some(v)
    });
    decided(raw.as_deref())
}

/// The three-state read, over a raw value. Pure so the distinction can be
/// tested without a process-wide environment variable — these tests run in
/// parallel with the rest of the crate, and two of them setting the same
/// variable would race each other into a flake.
pub fn decided(raw: Option<&str>) -> Result<Option<Destination>, String> {
    match raw {
        Some(v) if !v.trim().is_empty() => parse_destination(v).map(Some),
        _ => Ok(None),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// How old is the last good backup?
// ─────────────────────────────────────────────────────────────────────────
//
// 2026-10-24, the controller: the data disk failed, Postgres was down for 17
// hours, the 03:30 `database_backup` run never happened — and nothing said so,
// because the only alert was for a backup that RAN and FAILED. This is the
// reader's half of the fix (the scheduler's half is `backup_overdue.rs` in
// the gateway): the age of the last good backup is a line an operator sees in
// `noo backups status` and `noo cluster verify --controller`, with the command
// that fixes it.
//
// Two witnesses, because each fails differently. The FILES are what protects
// the data, and survive a dead database. The task HISTORY is what the
// scheduler believes. When they disagree one of them is wrong, and which one
// is the finding.

/// The `database_backup` schedule is daily (`30 3 * * *`).
pub const BACKUP_INTERVAL_SECS: i64 = 24 * 3600;
/// A dump takes minutes and the scheduler ticks once a minute; two hours is
/// slack that never hides a missed day. Same constant as the gateway's.
pub const BACKUP_GRACE_SECS: i64 = 2 * 3600;

/// What the task history says (`/api/heartbeat/history?...&status=success`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum History {
    /// The gateway could not be asked — itself a reason the backup may be late.
    Unreachable,
    /// Asked, and it has no successful `database_backup` run.
    NoSuccess,
    /// The newest successful run finished at this unix time.
    At(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freshness {
    pub level: Level,
    /// The newer of the two witnesses, unix seconds; `None` when neither knows.
    pub last: Option<i64>,
    /// One line for the row, age included.
    pub detail: String,
    /// Set when the files and the history tell different stories.
    pub disagreement: Option<String>,
}

/// `90000` -> `1d 1h`, `4500` -> `1h 15m`.
pub fn human_age(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86_400 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d {}h", s / 86_400, (s % 86_400) / 3600)
    }
}

/// Judge the last good backup. Pure: the clock and both witnesses are inputs.
///
/// OK under `interval + grace`, WARN over it, FAIL over twice the interval
/// (a whole scheduled run missed and then the next one too). Neither witness
/// knowing of any backup is a WARN, not a FAIL: a controller that was
/// installed this morning has not had its first 03:30 yet.
pub fn freshness(files: Option<i64>, history: History, now: i64, interval: i64) -> Freshness {
    let hist = match history {
        History::At(t) => Some(t),
        _ => None,
    };
    let last = match (files, hist) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let ago = |t: i64| human_age(now - t);

    let disagreement = match (files, history) {
        (Some(f), History::At(h)) if (f - h).abs() > BACKUP_GRACE_SECS => Some(format!(
            "the newest dump file is {} old but task history says the last success was {} ago",
            ago(f),
            ago(h)
        )),
        (Some(f), History::NoSuccess) => Some(format!(
            "the newest dump file is {} old but task history records no successful run",
            ago(f)
        )),
        (None, History::At(h)) => Some(format!(
            "task history records a success {} ago but no dump is visible in the backup directory",
            ago(h)
        )),
        _ => None,
    };

    let (mut level, mut detail) = match last {
        None => (
            Level::Warn,
            "no successful backup on record (no dump file, no successful run)".to_string(),
        ),
        Some(t) => {
            let age = now - t;
            let level = if age > 2 * interval {
                Level::Fail
            } else if age > interval + BACKUP_GRACE_SECS {
                Level::Warn
            } else {
                Level::Ok
            };
            let mut d = format!("last successful backup {} ago", human_age(age));
            if level != Level::Ok {
                d.push_str(&format!(
                    " (a daily backup is due every {})",
                    human_age(interval)
                ));
            }
            (level, d)
        }
    };
    if history == History::Unreachable {
        detail.push_str("; task history unreachable, judged from the backup files");
    }
    if let Some(d) = &disagreement {
        if level == Level::Ok {
            level = Level::Warn;
        }
        detail.push_str(&format!("; DISAGREEMENT: {d}"));
    }
    Freshness { level, last, detail, disagreement }
}

/// The remedy printed under a WARN/FAIL age row.
pub const BACKUP_AGE_REMEDY: &str =
    "noo heartbeat run database_backup   # then: noo heartbeat history database_backup";

/// Unix mtime of the newest `pg_*.sql.gz.enc` in the backup directory.
pub fn newest_dump() -> Option<(String, i64)> {
    let newest = super::secrets::backup_artifacts("pg_*.sql.gz.enc").into_iter().next()?;
    let name = newest.file_name()?.to_string_lossy().into_owned();
    let secs = std::fs::metadata(&newest)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some((name, secs))
}

/// The newest dump as hostd last saw it (`backup.newest_ts` in its heartbeat).
/// The fallback for a CLI that cannot read the backup directory (owned by the
/// hostd user, mode 0700) — the heartbeat is world-readable in the spool.
pub fn hostd_newest_dump(heartbeat_json: &str) -> Option<i64> {
    let v: serde_json::Value = serde_json::from_str(heartbeat_json).ok()?;
    super::cluster_verify::parse_rfc3339_unix(v["backup"]["newest_ts"].as_str()?)
}

/// The dump timestamp the files witness reports: the directory when it can be
/// read, else hostd's heartbeat.
pub fn files_witness() -> Option<i64> {
    if let Some((_, t)) = newest_dump() {
        return Some(t);
    }
    let hb = crate::envfile::repo_root().join(".noo-host-spool").join("hostd.heartbeat.json");
    hostd_newest_dump(&std::fs::read_to_string(hb).ok()?)
}

/// Ask the gateway for the newest successful `database_backup` run.
pub fn history_witness(g: &Globals) -> History {
    let body = crate::http::get_json_opt(
        g,
        "/api/heartbeat/history?task_id=database_backup&status=success&limit=1",
        true,
        10,
    );
    history_from(body.as_ref())
}

/// Pure half of [`history_witness`].
pub fn history_from(body: Option<&serde_json::Value>) -> History {
    let Some(body) = body else { return History::Unreachable };
    let when = body["runs"]
        .as_array()
        .and_then(|r| r.first())
        .and_then(|r| r["completed_at"].as_str().or_else(|| r["started_at"].as_str()))
        .and_then(super::cluster_verify::parse_rfc3339_unix);
    match when {
        Some(t) => History::At(t),
        None => History::NoSuccess,
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The live read: files + history against the clock.
pub fn live_freshness(g: &Globals) -> Freshness {
    freshness(files_witness(), history_witness(g), now_unix(), BACKUP_INTERVAL_SECS)
}

/// The line `noo cluster verify --controller` shows for the off-site decision.
/// Returns (level, detail, remedy). Undecided is a WARN, not a FAIL: it blocks
/// nothing, but it is the state in which every backup shares a fate with the
/// data it protects.
pub fn offsite_row(configured: &Result<Option<Destination>, String>, state: &Offsite) -> (Level, String, Option<&'static str>) {
    match configured {
        Err(e) => (Level::Fail, format!("{OFFSITE_KEY} is unusable: {e}"), Some("noo backups setup")),
        Ok(None) => (
            Level::Warn,
            "every backup is on this machine — off-site has never been decided".to_string(),
            Some("noo backups setup"),
        ),
        Ok(Some(Destination::Declined)) => (
            Level::Ok,
            "declined on purpose — backups stay on this machine (accepted risk)".to_string(),
            None,
        ),
        Ok(Some(Destination::Portable)) => (
            Level::Warn,
            "portable — nothing is copied automatically; run scripts/noo-backup-export.sh and carry it off".to_string(),
            Some("scripts/noo-backup-export.sh --all"),
        ),
        Ok(Some(d)) => match state {
            Offsite::Behind(m) => (Level::Warn, m.clone(), Some("noo backups status")),
            Offsite::Confirmed => (Level::Ok, format!("newest backup confirmed on {}", d.as_value()), None),
            _ => (Level::Ok, format!("copies go to {}", d.as_value()), None),
        },
    }
}

/// Is the newest dump known to have left this machine?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Offsite {
    /// A copy destination is configured and the marker names the newest dump.
    Confirmed,
    /// A copy destination is configured, but the newest dump is not the one
    /// last confirmed copied (or none ever was).
    Behind(String),
    /// No automatic copy (`portable`, `none`, or nobody decided): the newest
    /// dump is on this machine and nowhere else.
    ThisMachineOnly(String),
    /// There is no dump to be on or off a target.
    NoDump,
}

/// Judge the off-site state. `marker` is the content of
/// `<backup dir>/.offsite-last` (`<unix> <dump name>`), written by
/// `backup-controller.sh` after each successful copy.
pub fn offsite_state(dest: Option<&Destination>, marker: Option<&str>, newest: Option<&str>) -> Offsite {
    let Some(newest) = newest else { return Offsite::NoDump };
    match dest {
        None => Offsite::ThisMachineOnly(format!(
            "the newest backup ({newest}) is on this machine only — no off-site target is set"
        )),
        Some(Destination::Portable) => Offsite::ThisMachineOnly(format!(
            "the newest backup ({newest}) is on this machine only until you run the export and carry it off"
        )),
        Some(Destination::Declined) => Offsite::ThisMachineOnly(format!(
            "the newest backup ({newest}) is on this machine only, as you decided"
        )),
        Some(d) => {
            let copied = marker.and_then(|m| m.split_whitespace().nth(1));
            if copied == Some(newest) {
                Offsite::Confirmed
            } else {
                Offsite::Behind(format!(
                    "the newest backup ({newest}) is NOT confirmed on {} — last confirmed copy: {}",
                    d.as_value(),
                    copied.unwrap_or("none yet")
                ))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// `noo backups status`
// ─────────────────────────────────────────────────────────────────────────

pub fn backups_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let dir = super::secrets::backup_dir();
    let dumps = super::secrets::backup_artifacts("pg_*.sql.gz.enc");
    let age_keys = super::secrets::backup_artifacts("age-key_*");
    let configured = current();
    let fresh = live_freshness(g);
    let newest_name = newest_dump().map(|(n, _)| n);
    let marker = std::fs::read_to_string(dir.join(".offsite-last")).ok();
    let offsite = offsite_state(
        configured.as_ref().ok().and_then(|c| c.as_ref()),
        marker.as_deref(),
        newest_name.as_deref(),
    );

    if g.json {
        let (dest, err) = match &configured {
            Ok(Some(d)) => (Some(d.as_value()), None),
            Ok(None) => (None, None),
            Err(e) => (None, Some(e.clone())),
        };
        println!(
            "{}",
            json!({
                "directory": dir.display().to_string(),
                "dumps": dumps.len(),
                "age_key_backups": age_keys.len(),
                "offsite": dest,
                "offsite_decided": matches!(configured, Ok(Some(_))),
                "offsite_error": err,
                "last_backup": {
                    "level": match fresh.level { Level::Ok => "ok", Level::Warn => "warn", Level::Fail => "fail" },
                    "age_secs": fresh.last.map(|t| (now_unix() - t).max(0)),
                    "detail": fresh.detail,
                    "disagreement": fresh.disagreement,
                },
                "offsite_newest": match &offsite {
                    Offsite::Confirmed => "confirmed",
                    Offsite::Behind(_) => "behind",
                    Offsite::ThisMachineOnly(_) => "this_machine_only",
                    Offsite::NoDump => "no_dump",
                },
            })
        );
        return Ok(match configured {
            Ok(Some(_)) if fresh.level == Level::Ok && !matches!(offsite, Offsite::Behind(_)) => 0,
            _ => 1,
        });
    }

    println!("{}", ui::header("Backups", None));
    println!(
        "{}",
        ui::kv(&[
            ("Directory", dir.display().to_string()),
            ("Postgres dumps", dumps.len().to_string()),
            ("Age-key backups", age_keys.len().to_string()),
        ])
    );

    // The age of the last good backup, before anything about where it went:
    // a backup that did not happen has no destination worth discussing.
    match fresh.level {
        Level::Ok => ui::done(&format!("Last backup: {}", fresh.detail)),
        Level::Warn => ui::warned(&format!("Last backup: {}", fresh.detail)),
        Level::Fail => ui::failed(&format!("Last backup: {}", fresh.detail), Some(BACKUP_AGE_REMEDY)),
    }
    if fresh.level == Level::Warn {
        ui::guide(&[(BACKUP_AGE_REMEDY, "take one now and read the result")]);
    }
    let age_clean = fresh.level == Level::Ok;

    // Whether the NEWEST dump left the machine, not just whether a target is set.
    let offsite_clean = match &offsite {
        Offsite::Behind(m) => {
            ui::warned(&format!("Off-site: {m}"));
            false
        }
        Offsite::ThisMachineOnly(m) => {
            ui::warned(&format!("Off-site: {m}"));
            true
        }
        _ => true,
    };

    match configured {
        Ok(Some(d)) => {
            ui::done(&format!("Off-site: {} — {}", d.as_value(), d.explain()));
            Ok(if age_clean && offsite_clean { 0 } else { 1 })
        }
        // Not an error and not a pass. A malformed value means the copy step
        // refuses every run, so it is worth as loud a line as an unset one.
        Err(e) => {
            ui::failed(
                &format!("Off-site: {OFFSITE_KEY} is set to something unusable — {e}"),
                Some("noo backups setup"),
            );
            Ok(1)
        }
        Ok(None) => {
            ui::warned("Off-site: nobody has decided yet");
            println!(
                "{}",
                ui::note(
                    "Every dump, the Postgres volume and the encrypted age key are on this one \
                     disk. Losing it loses the data and the means to read it back, together. \
                     `noo backups setup` takes a minute, and `none` is a valid answer once you \
                     have made it on purpose."
                )
            );
            ui::guide(&[("noo backups setup", "decide where a copy goes")]);
            Ok(1)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// `noo backups setup`
// ─────────────────────────────────────────────────────────────────────────

/// One offered option: what it is called, what it needs, and what it costs.
struct Choice {
    label: &'static str,
    /// The follow-up question, when the form needs a target.
    asks: Option<(&'static str, &'static str)>,
    prefix: &'static str,
}

const CHOICES: &[Choice] = &[
    Choice {
        label: "Another machine over SSH — a copy leaves this box on every backup",
        asks: Some(("Target (user@host:/path)", "ssh:")),
        prefix: "ssh:",
    },
    Choice {
        label: "A mounted disk or NAS — an external drive, a network share",
        asks: Some(("Directory (must be mounted when the backup runs)", "dir:")),
        prefix: "dir:",
    },
    Choice {
        label: "Object storage — handed to `aws s3 cp` or `rclone copyto`",
        asks: Some(("Bucket and prefix (s3://bucket/prefix)", "s3:")),
        prefix: "s3:",
    },
    Choice {
        label: "Portable bundle — no second machine; you carry it off by hand",
        asks: None,
        prefix: "portable",
    },
    Choice {
        label: "Nothing leaves this machine — recorded as a decision, not an oversight",
        asks: None,
        prefix: "none",
    },
];

pub fn backups_setup(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut set: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--set" => {
                i += 1;
                match args.get(i) {
                    Some(v) => set = Some(v.clone()),
                    None => return Err(Unhandled),
                }
            }
            _ => return Err(Unhandled),
        }
        i += 1;
    }

    // Non-interactive path: a script, or an operator who already knows the
    // answer. Validated by the same parser, so `--set` can never record a
    // value the backup script would refuse.
    if let Some(raw) = set {
        let d = match parse_destination(&raw) {
            Ok(d) => d,
            Err(e) => fail(g.json, ExitCode::Usage, "bad_destination", &e, None),
        };
        return write_choice(g, &d);
    }

    if g.json {
        fail(
            g.json,
            ExitCode::Usage,
            "needs_a_choice",
            "this asks a question, so it has no --json form",
            Some("pass the answer instead: noo backups setup --set <destination>"),
        );
    }

    let ui_impl = crate::onboard::prompt::PlainUi;
    let asker = crate::onboard::prompt::Asker {
        // A pipe must never hang waiting for an answer nobody is there to
        // give. With no TTY there is no decision to record, so say what to
        // run instead of writing a default nobody chose.
        non_interactive: !crate::onboard::prompt::stdin_is_tty(),
        ui: &ui_impl,
    };
    if asker.non_interactive {
        fail(
            g.json,
            ExitCode::Usage,
            "not_a_terminal",
            "stdin is not a terminal, so there is nobody to ask",
            Some("noo backups setup --set <destination>"),
        );
    }

    println!("{}", ui::header("Where do backups go?", None));
    println!(
        "{}",
        ui::note(
            "Every dump, the Postgres volume and the encrypted age key are on this one disk \
             today. One disk loss takes the data and the means to read it back, together."
        )
    );
    for (n, c) in CHOICES.iter().enumerate() {
        println!("{}", ui::item(&format!("{}) {}", n + 1, c.label)));
    }

    let pick = asker.ask_choice("Choice", 4, CHOICES.len(), false);
    let choice = &CHOICES[pick - 1];

    let raw = match choice.asks {
        None => choice.prefix.to_string(),
        Some((label, prefix)) => {
            let p = crate::onboard::prompt::Prompt::new(label);
            format!("{prefix}{}", asker.ask(&p).trim())
        }
    };

    match parse_destination(&raw) {
        Ok(d) => write_choice(g, &d),
        Err(e) => fail(g.json, ExitCode::Usage, "bad_destination", &e, Some("noo backups setup")),
    }
}

/// Record the decision, and say what it means in plain words.
fn write_choice(g: &Globals, d: &Destination) -> Result<i32, Unhandled> {
    if let Err(e) = crate::envfile::set_env_value(OFFSITE_KEY, Some(&d.as_value())) {
        fail(g.json, ExitCode::Generic, "write_failed", &e, None);
    }
    if g.json {
        println!("{}", json!({"offsite": d.as_value()}));
        return Ok(0);
    }
    ui::done(&format!("{OFFSITE_KEY}={} — {}", d.as_value(), d.explain()));
    // The value is read by the backup script from the environment, not by a
    // running container, so there is nothing to restart — but say that,
    // because every other `.env` change in this tree does need one.
    println!(
        "{}",
        ui::note("Takes effect on the next backup run. No restart is needed.")
    );
    if matches!(d, Destination::Portable) {
        ui::guide(&[(
            "scripts/noo-backup-export.sh --all",
            "build the bundle to carry off",
        )]);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{decided, parse_destination, Destination, CHOICES};

    use super::{
        freshness, history_from, hostd_newest_dump, human_age, offsite_state, History, Level, Offsite,
        BACKUP_INTERVAL_SECS as DAY,
    };

    const NOW: i64 = 1_792_000_000;
    const H: i64 = 3600;

    #[test]
    fn a_fresh_backup_is_ok_and_names_its_age() {
        let f = freshness(Some(NOW - 5 * H), History::At(NOW - 5 * H), NOW, DAY);
        assert_eq!(f.level, Level::Ok);
        assert!(f.detail.contains("last successful backup 5h 0m ago"), "{}", f.detail);
        assert!(f.disagreement.is_none());
    }

    /// 2026-10-24: last good backup 10-23 03:30, read at 21:00 on 10-24 = 41.5h.
    #[test]
    fn over_the_interval_warns_and_over_twice_the_interval_fails() {
        let warn = freshness(Some(NOW - 30 * H), History::At(NOW - 30 * H), NOW, DAY);
        assert_eq!(warn.level, Level::Warn, "{}", warn.detail);
        let fail = freshness(Some(NOW - 49 * H), History::At(NOW - 49 * H), NOW, DAY);
        assert_eq!(fail.level, Level::Fail, "{}", fail.detail);
        // The grace keeps the minutes after 03:30 from reading as overdue.
        let edge = freshness(Some(NOW - (24 * H + 90 * 60)), History::At(NOW - (24 * H + 90 * 60)), NOW, DAY);
        assert_eq!(edge.level, Level::Ok, "{}", edge.detail);
    }

    #[test]
    fn nothing_on_record_is_a_warning_not_a_failure() {
        let f = freshness(None, History::NoSuccess, NOW, DAY);
        assert_eq!(f.level, Level::Warn);
        assert!(f.last.is_none());
    }

    /// The files are fresh but the history is old (a lost run record): say so,
    /// and do not let a clean age hide it.
    #[test]
    fn files_and_history_that_disagree_are_reported() {
        let f = freshness(Some(NOW - 2 * H), History::At(NOW - 40 * H), NOW, DAY);
        let d = f.disagreement.expect("a 38h gap between the witnesses must be reported");
        assert!(d.contains("2h 0m") && d.contains("1d 16h"), "{d}");
        assert_eq!(f.level, Level::Warn, "a fresh dump with a disagreeing history is not a plain OK");
        assert!(f.detail.contains("DISAGREEMENT"));
        assert_eq!(f.last, Some(NOW - 2 * H), "the newer witness is the age");

        let none = freshness(Some(NOW - 2 * H), History::NoSuccess, NOW, DAY);
        assert!(none.disagreement.unwrap().contains("no successful run"));
        let ghost = freshness(None, History::At(NOW - 2 * H), NOW, DAY);
        assert!(ghost.disagreement.unwrap().contains("no dump is visible"));
        // A dump that took minutes is not a disagreement.
        assert!(freshness(Some(NOW - 5 * H), History::At(NOW - 5 * H - 600), NOW, DAY).disagreement.is_none());
    }

    #[test]
    fn an_unreachable_gateway_is_judged_from_the_files_and_says_so() {
        let f = freshness(Some(NOW - 30 * H), History::Unreachable, NOW, DAY);
        assert_eq!(f.level, Level::Warn);
        assert!(f.detail.contains("task history unreachable"));
        assert!(f.disagreement.is_none(), "unreachable is not a disagreement");
    }

    #[test]
    fn the_history_body_and_the_hostd_heartbeat_parse() {
        let body = serde_json::json!({"runs": [{"completed_at": "2026-10-23T07:31:00+00:00"}]});
        assert!(matches!(history_from(Some(&body)), History::At(_)));
        assert_eq!(history_from(Some(&serde_json::json!({"runs": []}))), History::NoSuccess);
        assert_eq!(history_from(None), History::Unreachable);
        let hb = r#"{"pid":1,"backup":{"dir":"/b","newest_pg":"pg_1.sql.gz.enc","newest_ts":"2026-10-23T07:31:00Z","count":3}}"#;
        assert!(hostd_newest_dump(hb).is_some());
        assert!(hostd_newest_dump(r#"{"pid":1}"#).is_none(), "an older hostd carries no backup facts");
    }

    #[test]
    fn human_age_reads_as_a_person_would() {
        assert_eq!(human_age(41 * H + 1800), "1d 17h");
        assert_eq!(human_age(4500), "1h 15m");
    }

    #[test]
    fn undecided_offsite_is_a_warning_with_the_setup_remedy_and_none_is_quiet() {
        use super::offsite_row;
        let (l, d, r) = offsite_row(&Ok(None), &Offsite::NoDump);
        assert_eq!((l, r), (Level::Warn, Some("noo backups setup")));
        assert!(d.contains("every backup is on this machine"), "{d}");
        let (l, _, r) = offsite_row(&Ok(Some(Destination::Declined)), &Offsite::NoDump);
        assert_eq!((l, r), (Level::Ok, None), "`none` is an accepted decision and stays quiet");
        let (l, _, _) = offsite_row(&Err("bad".into()), &Offsite::NoDump);
        assert_eq!(l, Level::Fail);
        let ssh = Destination::Ssh("u@h:/b".into());
        let (l, _, _) = offsite_row(&Ok(Some(ssh.clone())), &Offsite::Behind("x".into()));
        assert_eq!(l, Level::Warn);
        assert_eq!(offsite_row(&Ok(Some(ssh)), &Offsite::Confirmed).0, Level::Ok);
    }

    #[test]
    fn the_newest_dump_is_flagged_when_it_is_not_on_the_offsite_target() {
        let ssh = Destination::Ssh("u@h:/b".into());
        let newest = Some("pg_20261024_033000.sql.gz.enc");
        // The marker names yesterday's dump: today's has not been confirmed.
        let behind = offsite_state(Some(&ssh), Some("1792000000 pg_20261023_033000.sql.gz.enc"), newest);
        match behind {
            Offsite::Behind(m) => assert!(m.contains("NOT confirmed") && m.contains("20261023"), "{m}"),
            o => panic!("{o:?}"),
        }
        assert!(matches!(offsite_state(Some(&ssh), None, newest), Offsite::Behind(m) if m.contains("none yet")));
        assert_eq!(
            offsite_state(Some(&ssh), Some("1792000000 pg_20261024_033000.sql.gz.enc"), newest),
            Offsite::Confirmed
        );
        // Unset, portable and declined are all "this machine only", with their own words.
        for d in [None, Some(&Destination::Portable), Some(&Destination::Declined)] {
            assert!(matches!(offsite_state(d, None, newest), Offsite::ThisMachineOnly(_)));
        }
        assert_eq!(offsite_state(Some(&ssh), None, None), Offsite::NoDump);
    }

    #[test]
    fn every_offered_form_parses_to_what_it_offered() {
        // The menu and the parser are two lists that must agree. An option an
        // operator can pick and the parser then refuses is a prompt that
        // wastes their time; one the parser accepts but the menu never offers
        // is a form nobody can reach.
        for c in CHOICES {
            let raw = match c.asks {
                None => c.prefix.to_string(),
                Some((_, prefix)) => format!("{prefix}example"),
            };
            let parsed = parse_destination(&raw)
                .unwrap_or_else(|e| panic!("menu offers {raw:?}, parser refuses it: {e}"));
            assert_eq!(
                parsed.as_value(),
                raw,
                "the value written back does not match what was chosen"
            );
        }
    }

    /// The easy typo, and the one worth refusing loudly: a prefix with
    /// nothing after it. `dir:` names nowhere, but it is a non-empty string,
    /// so it would read as "configured" everywhere that only checks for
    /// unset — and then fail on every backup run.
    #[test]
    fn a_prefix_with_no_target_is_refused() {
        for raw in ["ssh:", "dir:", "s3:", "ssh:   ", "dir: "] {
            let e = parse_destination(raw).expect_err(&format!("{raw:?} was accepted"));
            assert!(e.contains("needs a target"), "unhelpful message for {raw:?}: {e}");
        }
    }

    #[test]
    fn an_unknown_form_is_refused_with_the_list() {
        let e = parse_destination("rsync:/tmp").expect_err("accepted");
        for form in ["ssh:", "dir:", "s3:", "portable", "none"] {
            assert!(e.contains(form), "the refusal does not name {form}: {e}");
        }
    }

    /// `none` is an answer. Unset is not. Folding them together is the whole
    /// bug: a box nobody ever asked looks exactly like a box whose operator
    /// weighed the risk and accepted it.
    #[test]
    fn declining_is_a_decision_and_unset_is_not() {
        assert_eq!(parse_destination("none").unwrap(), Destination::Declined);
        assert!(parse_destination("").is_err(), "empty is not a decision");

        assert_eq!(decided(None).unwrap(), None, "unset must not read as decided");
        assert_eq!(decided(Some("   ")).unwrap(), None, "blank must not read as decided");
        assert_eq!(decided(Some("none")).unwrap(), Some(Destination::Declined));
    }

    /// A malformed value is neither decided nor undecided — it is broken, and
    /// the copy step refuses every run. It must not fall back to `None`,
    /// which would report it as "nobody has decided" and hide a setting the
    /// operator believes is working.
    #[test]
    fn a_malformed_value_is_an_error_not_an_absence() {
        assert!(decided(Some("rsync:/tmp")).is_err(), "a broken value read as undecided");
        assert!(decided(Some("dir:")).is_err(), "a targetless prefix read as undecided");
    }

    #[test]
    fn the_explanation_says_what_actually_happens() {
        assert!(Destination::Portable.explain().contains("noo-backup-export.sh"));
        assert!(Destination::Declined.explain().contains("decision"));
        assert!(Destination::Ssh("a@b:/c".into()).explain().contains("a@b:/c"));
    }
}
