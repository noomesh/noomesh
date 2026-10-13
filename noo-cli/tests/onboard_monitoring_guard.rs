// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `--bundle` must apply to standalone onboarding whether standalone was
//! explicit (`--standalone`) or auto-detected (no repo checkout anywhere)
//! — not only when the flag was written out. `--with-monitoring` is a
//! no-op since 2026-09-28 (the monitoring set rides the `standalone`
//! profile itself) and is accepted everywhere, so an old script keeps
//! working; it is the auto-detect probe below because it has no argument
//! and no side effect.
//!
//! Regression for: the guard used to run BEFORE the auto-detect block, so
//! a bare `noo onboard --with-monitoring` on a fresh box (which the code a
//! few lines later auto-detects as standalone) was refused with
//! "--with-monitoring/--bundle only apply to --standalone onboarding"
//! even though the run would have been standalone.

use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

const GUARD_MSG: &str = "only applies to --standalone";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("noo-onboard-monitoring-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create fresh test dir");
    dir
}

/// No repo checkout anywhere, no `--standalone` flag: the auto-detect block
/// must flip `standalone` to true BEFORE the monitoring guard runs, so
/// `--with-monitoring` is accepted. The full wizard reaches out to real
/// docker/tailscale a few steps in, so this only needs the process to
/// survive past the guard — it's killed shortly after spawn and we assert
/// on whatever it printed by then (the guard and auto-detect both run
/// before any I/O with an external service).
#[test]
fn with_monitoring_is_accepted_once_standalone_auto_detects() {
    let dir = fresh_dir("auto");
    let mut child = Command::new(bin())
        .args(["onboard", "--with-monitoring", "--dry-run", "--non-interactive"])
        // env_clear: no NOO_REPO_ROOT, no PATH-derived python fallback, no
        // host-specific repo detection — the fresh-box scenario.
        .env_clear()
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn noo onboard");

    std::thread::sleep(Duration::from_millis(3000)); // generous: a loaded CI runner must still print the auto-detect line
    let _ = child.kill();
    let out = child.wait_with_output().expect("collect output");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(GUARD_MSG),
        "guard fired even though standalone should have auto-detected — stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("STANDALONE mode"),
        "expected auto-detect to announce STANDALONE mode — stdout: {stdout}\nstderr: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Standing inside a repo checkout (this worktree), no `--standalone`
/// flag: onboarding is NOT standalone, so `--bundle` must be refused with
/// the same message and exit code 2 — this guard fires before any side
/// effects, so the process runs to completion. `--with-monitoring` in the
/// same place is accepted with a note and NOT refused (it used to be: it
/// was the standalone monitoring opt-in, and there is no opt-in any more).
#[test]
fn bundle_is_refused_and_with_monitoring_is_a_noop_in_a_repo_checkout() {
    // The crate root of this worktree: has docker-compose.cluster.yml next
    // to noo-cli, so `repo_root()`'s cwd-walk resolves here and auto-detect
    // does NOT flip standalone.
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("noo-cli has a parent dir")
        .to_path_buf();
    assert!(
        repo_root.join("docker-compose.cluster.yml").exists(),
        "test assumption broken: {} has no docker-compose.cluster.yml",
        repo_root.display()
    );

    let out = Command::new(bin())
        .args(["onboard", "--bundle", "/nonexistent/bundle.tgz", "--dry-run", "--non-interactive"])
        .env_clear()
        .current_dir(&repo_root)
        .stdin(Stdio::null())
        .output()
        .expect("run noo onboard");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(GUARD_MSG), "stderr: {stderr}");

    // --with-monitoring: accepted, noted, and the run goes on past the
    // guard (killed shortly after, like the auto-detect probe above).
    let mut child = Command::new(bin())
        .args(["onboard", "--with-monitoring", "--dry-run", "--non-interactive"])
        .env_clear()
        .current_dir(&repo_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn noo onboard");
    std::thread::sleep(Duration::from_millis(3000));
    let _ = child.kill();
    let out = child.wait_with_output().expect("collect output");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains(GUARD_MSG), "--with-monitoring was refused: {stderr}");
    assert!(stderr.contains("no longer needed"), "expected the no-op note — stderr: {stderr}");
}
