// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The generated shell shims, pinned.
//!
//! `noo doctor node <Tab>` used to print the operator's entire home
//! directory (host8, 2026-09-05): the shim asked bash for filename
//! completion whenever the binary offered no candidates, so every leaf
//! command became a directory listing. Filenames are opt-in now, and these
//! tests exist so the fallback cannot quietly come back.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

fn run(args: &[&str]) -> String {
    let out = Command::new(bin()).args(args).output().expect("run noo");
    assert!(out.status.success(), "noo {args:?} failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn the_bash_shim_never_falls_back_to_filenames_on_its_own() {
    let sh = run(&["completions", "bash"]);
    // The only path to file completion is the binary asking for it.
    assert!(sh.contains("__files__"), "no sentinel branch:\n{sh}");
    assert!(sh.contains("compopt -o default"), "sentinel must enable files:\n{sh}");
    // …and every other exit suppresses bash's own fallback.
    assert_eq!(
        sh.matches("compopt -o default").count(),
        1,
        "exactly one branch may turn filenames on:\n{sh}"
    );
    assert!(sh.contains("compopt +o default"), "must suppress the default:\n{sh}");
}

#[test]
fn the_zsh_shim_gates_files_behind_the_same_sentinel() {
    let sh = run(&["completions", "zsh"]);
    assert!(sh.contains("__files__"), "no sentinel branch:\n{sh}");
    // Count the CALL, not the sentinel: "__files__" contains "_files".
    assert!(sh.contains(r#"== "__files__" ]]; then _files"#), "_files must be gated:\n{sh}");
    assert_eq!(sh.matches("; then _files").count(), 1, "one guarded _files only:\n{sh}");
    assert_eq!(sh.matches("\n    _files").count(), 0, "no ungated _files:\n{sh}");
}

#[test]
fn a_leaf_command_offers_no_candidates_at_all() {
    // Empty stdout is the shim's "offer nothing" signal.
    for cmd in [
        ["completions", "candidates", "auth", "status"],
        ["completions", "candidates", "cluster", "status"],
    ] {
        let out = run(&cmd);
        assert!(out.trim().is_empty(), "{cmd:?} offered: {out}");
    }
}

#[test]
fn a_path_taking_command_asks_for_files() {
    let out = run(&["completions", "candidates", "heartbeat", "import"]);
    assert_eq!(out.trim(), "__files__", "heartbeat import must want a file");
}
