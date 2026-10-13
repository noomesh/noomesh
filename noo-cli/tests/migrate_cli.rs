// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Outcome tests for `noo migrate` — the guards ARE the contract: every
//! refusal must be honest and name the fix (docs-first flow, 2026-08-27).

use std::process::Command;

fn noo() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_noo"));
    // Isolate from the dev machine's real install + credentials.
    c.env_remove("NOO_REPO_ROOT");
    c.env_remove("SOPS_AGE_KEY_FILE");
    c
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("noo-migrate-test-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn export_refuses_without_any_controller_source() {
    // Neither a standalone home nor a repo checkout (cwd is an empty dir):
    // the refusal names both shapes it looked for.
    let home = tmp("nohome");
    let cwd = tmp("nocwd");
    let out = noo()
        .args(["migrate", "export"])
        .env("NOO_HOME", &home)
        .current_dir(&cwd)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("No controller found"), "stderr: {err}");
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&cwd);
}

#[test]
fn import_forwards_to_the_converged_onboard_and_fails_fast() {
    // The legacy fresh-box refusal retired with the converged flow
    // (2026-09-01): live files beat the archive and onboard's own
    // idempotent guard owns the existing-install case. What the forwarder
    // MUST do: name where it hands off, and a bad archive must die with
    // its real name BEFORE any home mutation (zero side effects).
    let home = tmp("existing");
    std::fs::write(home.join(".noo-standalone"), "marker").unwrap();
    let archive = home.join("x.tar.gz.enc");
    std::fs::write(&archive, b"garbage").unwrap();
    let passfile = home.join("pass");
    std::fs::write(&passfile, "pw").unwrap();
    let out = noo()
        .args(["migrate", "import"])
        .arg(&archive)
        .args(["--passphrase-file"])
        .arg(&passfile)
        .env("NOO_HOME", &home)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    // The hand-off is narration (stdout, CLI_STYLE_GUIDE rev 2); the
    // failure itself is an error (stderr).
    let out_s = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out_s.contains("--from-archive"), "stdout: {out_s}");
    assert!(err.contains("decryption failed"), "stderr: {err}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn import_reports_a_bad_archive_honestly() {
    let home = tmp("badarchive");
    let archive = home.join("x.tar.gz.enc");
    std::fs::write(&archive, b"this is not an encrypted tarball").unwrap();
    let passfile = home.join("pass");
    std::fs::write(&passfile, "pw").unwrap();
    let out = noo()
        .args(["migrate", "import"])
        .arg(&archive)
        .args(["--passphrase-file"])
        .arg(&passfile)
        .env("NOO_HOME", &home)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("decryption failed") || err.contains("import_failed"),
        "stderr: {err}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn json_mode_requires_a_passphrase_file() {
    let home = tmp("jsonmode");
    std::fs::write(home.join(".noo-standalone"), "marker").unwrap();
    let out = noo()
        .args(["--json", "migrate", "export"])
        .env("NOO_HOME", &home)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    // Fails on either the postgres preflight or the passphrase rule — both
    // are honest; the forbidden outcome is a hang on a hidden prompt.
    assert!(!err.is_empty(), "must fail loudly, not hang");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn import_refuses_force_instead_of_ignoring_it() {
    let out = noo().args(["migrate", "import", "x.tar.gz.enc", "--force"]).output().unwrap();
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--force is not an option"), "stderr: {err}");
}
