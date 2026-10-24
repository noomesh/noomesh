// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `onboard --tui` process-level contract (gateway_integration.rs style:
//! drive the BUILT binary via `CARGO_BIN_EXE_noo`).
//!
//! A full-screen TUI can't be driven from CI, but its guards can: under
//! `cargo test` stdin/stdout are not TTYs, so `--tui` must refuse with a
//! clear hint (exit 2) BEFORE touching the terminal, and the mutually
//! exclusive `--tui --web` combination must refuse deterministically.

use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        // No inherited env: no PATH, no repo
        // detection surprises — the standalone-host scenario.
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .expect("run noo binary")
}

#[test]
fn onboard_tui_without_tty_exits_2_with_guidance() {
    let out = run(&["onboard", "--tui", "--dry-run"]);
    assert_eq!(out.status.code(), Some(2), "non-TTY --tui must exit 2");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("interactive terminal"), "stderr: {err}");
    // Must point at both escape hatches.
    assert!(err.contains("noo onboard"), "stderr: {err}");
    assert!(err.contains("--ci"), "stderr: {err}");
}

#[test]
fn onboard_tui_guard_fires_with_any_flag_combination() {
    // Flag parity: skip flags / --reconfigure combine with --tui; the guard
    // (not a flag error) must still answer.
    let out = run(&["onboard", "--tui", "--reconfigure", "--skip-model", "--skip-channels"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("interactive terminal"), "stderr: {err}");
    assert!(
        !err.contains("requires the Python install"),
        "--tui must be native: {err}"
    );
}

#[test]
fn onboard_tui_and_web_together_is_a_flag_error() {
    // Both frontends are native, but they are mutually exclusive — asking
    // for both must refuse deterministically (before any TTY guard or
    // server bind), not launch one arbitrarily.
    let out = run(&["onboard", "--tui", "--web"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.to_lowercase().contains("choose one frontend"), "stderr: {err}");
}
