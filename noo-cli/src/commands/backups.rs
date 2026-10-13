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
pub fn current() -> Result<Option<Destination>, String> {
    decided(std::env::var(OFFSITE_KEY).ok().as_deref())
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
            })
        );
        return Ok(match configured {
            Ok(Some(_)) => 0,
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

    match configured {
        Ok(Some(d)) => {
            ui::done(&format!("Off-site: {} — {}", d.as_value(), d.explain()));
            Ok(0)
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
