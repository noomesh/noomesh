// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security secrets reveal`, driven through the BUILT binary.
//!
//! The properties under test are all refusals, and a refusal is the thing a
//! unit test of the happy path cannot see. Every case here runs with stdout
//! attached to a pipe, which is the situation the command exists to survive:
//! an agent, a CI job or a `| tee` is exactly how a passphrase ends up in a
//! log. So the suite's normal condition IS the guard condition.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

#[path = "common/scratch_dir.rs"]
mod scratch_dir;
use scratch_dir::ScratchDir;

/// Scratch repo root with `secrets/`; removed when the test ends.
fn scratch(tag: &str) -> ScratchDir {
    let d = ScratchDir::new(&format!("noo-cli-reveal-{tag}"));
    std::fs::create_dir_all(d.join("secrets")).unwrap();
    d
}

/// Run with an isolated repo root. `NOO_NO_COLOR`-style styling is disabled so
/// assertions match plain text.
fn run(repo: &PathBuf, args: &[&str]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("NOO_REPO_ROOT", repo)
        .env("NO_COLOR", "1")
        .env_remove("NOO_BACKUP_PASSPHRASE")
        .env_remove("NOO_AGE_BACKUP_PASSPHRASE");
    cmd.output().expect("run noo")
}

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

const VALUE: &str = "Zq7-not-a-real-passphrase-9xK";

fn repo_with_env() -> ScratchDir {
    let d = scratch("env");
    std::fs::write(
        d.join(".env"),
        format!("NOO_BACKUP_PASSPHRASE={VALUE}\nNOO_JWT_SECRET=other-secret-value\n"),
    )
    .unwrap();
    d
}

// ── the TTY guard ────────────────────────────────────────────────────────

#[test]
fn refuses_when_stdout_is_not_a_terminal() {
    let d = repo_with_env();
    let o = run(&d, &["security", "secrets", "reveal", "NOO_BACKUP_PASSPHRASE"]);
    assert!(!o.status.success(), "a piped reveal must fail:\n{}", out(&o));
    let text = out(&o);
    assert!(
        !text.contains(VALUE),
        "the value was printed into a pipe anyway:\n{text}"
    );
    assert!(text.contains("not a terminal"), "{text}");
    assert!(text.contains("--stdout"), "the refusal must name the override:\n{text}");
}

#[test]
fn explicit_stdout_is_the_only_way_past_the_guard() {
    let d = repo_with_env();
    let o = run(
        &d,
        &["security", "secrets", "reveal", "NOO_BACKUP_PASSPHRASE", "--stdout", "--no-clipboard"],
    );
    assert!(o.status.success(), "{}", out(&o));
    assert!(
        String::from_utf8_lossy(&o.stdout).contains(VALUE),
        "--stdout was passed and the value did not appear:\n{}",
        out(&o)
    );
}

#[test]
fn json_has_no_override_at_all() {
    let d = repo_with_env();
    // Even WITH --stdout, which is the override for the other refusal.
    let o = run(
        &d,
        &["--json", "security", "secrets", "reveal", "NOO_BACKUP_PASSPHRASE", "--stdout"],
    );
    assert!(!o.status.success(), "{}", out(&o));
    let text = out(&o);
    assert!(!text.contains(VALUE), "--json printed the value:\n{text}");
    assert!(text.contains("--json"), "{text}");
}

// ── the allow-list ───────────────────────────────────────────────────────

#[test]
fn a_secret_no_human_holds_is_refused() {
    let d = repo_with_env();
    // NOO_JWT_SECRET is in this .env, so the refusal is about the POLICY, not
    // about the value being absent.
    let o = run(
        &d,
        &["security", "secrets", "reveal", "NOO_JWT_SECRET", "--stdout", "--no-clipboard"],
    );
    assert!(!o.status.success(), "{}", out(&o));
    let text = out(&o);
    assert!(!text.contains("other-secret-value"), "leaked a non-human secret:\n{text}");
    assert!(text.contains("not a secret a human is meant to hold"), "{text}");
    // The refusal lists what IS allowed, or the operator has to read source.
    assert!(text.contains("NOO_AGE_BACKUP_PASSPHRASE"), "{text}");
}

#[test]
fn the_allow_list_check_runs_before_the_store_is_read() {
    // No .env, no env.sops: a name-based refusal must be identical on a box
    // that holds the secret and one that does not, or the error message is an
    // oracle for which secrets exist.
    let empty = scratch("empty");
    let o = run(
        &empty,
        &["security", "secrets", "reveal", "NOO_JWT_SECRET", "--stdout"],
    );
    assert!(!o.status.success());
    assert!(out(&o).contains("not a secret a human is meant to hold"), "{}", out(&o));
}

#[test]
fn the_age_private_key_is_refused_and_points_at_the_backup_path() {
    let d = repo_with_env();
    for name in ["SOPS_AGE_KEY", "SOPS_AGE_KEY_FILE", "NOO_AGE_KEY", "AGE_PRIVATE_KEY"] {
        let o = run(&d, &["security", "secrets", "reveal", name, "--stdout"]);
        assert!(!o.status.success(), "{name} was not refused:\n{}", out(&o));
        let text = out(&o);
        assert!(text.contains("root of trust"), "{name}: {text}");
        // A refusal that does not say what to do instead just gets worked
        // around with `sops -d`.
        assert!(text.contains("NOO_AGE_BACKUP_PASSPHRASE"), "{name}: {text}");
        assert!(text.contains("backup-restore-secrets.md"), "{name}: {text}");
    }
}

#[test]
fn the_passphrase_that_opens_the_age_backup_is_itself_revealable() {
    // The refusal above is only coherent because this one works.
    let d = scratch("agepass");
    std::fs::write(d.join(".env"), format!("NOO_AGE_BACKUP_PASSPHRASE={VALUE}\n")).unwrap();
    let o = run(
        &d,
        &["security", "secrets", "reveal", "NOO_AGE_BACKUP_PASSPHRASE", "--stdout", "--no-clipboard"],
    );
    assert!(o.status.success(), "{}", out(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains(VALUE), "{}", out(&o));
}

// ── the audit line ───────────────────────────────────────────────────────

#[test]
fn a_reveal_writes_an_audit_line_that_does_not_contain_the_value() {
    let d = repo_with_env();
    let o = run(
        &d,
        &["security", "secrets", "reveal", "NOO_BACKUP_PASSPHRASE", "--stdout", "--no-clipboard"],
    );
    assert!(o.status.success(), "{}", out(&o));
    let log = d.join("secrets/reveal-audit.log");
    let text = std::fs::read_to_string(&log)
        .unwrap_or_else(|e| panic!("no audit log at {}: {e}", log.display()));
    assert!(text.contains("NOO_BACKUP_PASSPHRASE"), "{text}");
    assert!(text.contains("reveal"), "{text}");
    assert!(!text.contains(VALUE), "the audit log recorded the value:\n{text}");

    // Mode 600 — an audit log of who read which secret when is not world-
    // readable metadata.
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "audit log mode {mode:o}");
}

#[test]
fn a_refused_reveal_writes_no_audit_line() {
    let d = repo_with_env();
    let o = run(&d, &["security", "secrets", "reveal", "NOO_JWT_SECRET", "--stdout"]);
    assert!(!o.status.success());
    assert!(
        !d.join("secrets/reveal-audit.log").exists(),
        "a refusal logged a reveal that never happened"
    );
}

#[test]
fn repeated_reveals_append_rather_than_replace() {
    let d = repo_with_env();
    for _ in 0..2 {
        let o = run(
            &d,
            &["security", "secrets", "reveal", "NOO_BACKUP_PASSPHRASE", "--stdout", "--no-clipboard"],
        );
        assert!(o.status.success(), "{}", out(&o));
    }
    let text = std::fs::read_to_string(d.join("secrets/reveal-audit.log")).unwrap();
    assert_eq!(text.lines().count(), 2, "audit log did not append:\n{text}");
}

// ── lingering plaintext, and the scan that reports it ────────────────────

#[test]
fn scan_reports_a_lingering_plaintext_passphrase_file_as_critical() {
    let d = repo_with_env();
    std::fs::write(d.join("secrets/age_backup_passphrase.txt"), VALUE).unwrap();
    let o = run(&d, &["--json", "security", "scan"]);
    let text = String::from_utf8_lossy(&o.stdout);
    let v: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|e| panic!("scan --json was not json ({e}):\n{text}"));
    let issues = v["issues"].as_array().expect("issues array");
    let hit = issues
        .iter()
        .find(|i| i["check"] == "Backup Passphrase Plaintext")
        .unwrap_or_else(|| panic!("no plaintext finding in:\n{text}"));
    assert_eq!(hit["severity"], "CRITICAL");
    assert!(
        hit["detail"].as_str().unwrap().contains("secrets/age_backup_passphrase.txt"),
        "{text}"
    );
    assert!(!o.status.success(), "a CRITICAL finding must exit non-zero");
    // And the finding never quotes the value it is complaining about.
    assert!(!text.contains(VALUE), "scan printed the plaintext it found:\n{text}");
}

#[test]
fn scan_is_quiet_when_no_plaintext_passphrase_is_left() {
    let d = repo_with_env();
    let o = run(&d, &["--json", "security", "scan"]);
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(
        !text.contains("Backup Passphrase Plaintext"),
        "finding fired with no file present:\n{text}"
    );
}

// ── the value is not fetchable any other way through this verb ───────────

#[test]
fn an_unset_secret_says_so_without_inventing_one() {
    let empty = scratch("unset");
    let o = run(
        &empty,
        &["security", "secrets", "reveal", "NOO_BACKUP_PASSPHRASE", "--stdout"],
    );
    assert!(!o.status.success());
    assert!(out(&o).contains("is not set"), "{}", out(&o));
}
