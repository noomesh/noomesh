// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! An unknown verb prints usage and exits 2; nothing is ever exec'd.
//!
//! The binary used to hand any verb it did not serve to a Python CLI found
//! through `$NOO_PY_CLI`, a `noo-py` on PATH, or a venv under the repo root
//! (i195 decision 3). Each test plants a tripwire executable at all three
//! places; if the binary ever runs one, it drops a marker file and the test
//! fails.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

#[path = "common/scratch_dir.rs"]
mod scratch_dir;
use scratch_dir::ScratchDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

fn tripwire(path: &Path, marker: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display())).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Run `noo <args>` with a tripwire at every place the old passthrough
/// looked. Returns the output and whether any tripwire fired.
fn run(args: &[&str]) -> (Output, bool) {
    let root = ScratchDir::new("noo-no-exec");
    let marker = root.join("EXECED");
    let py_name = ["noo", "py"].join("-");
    let on_path = root.join("bin");
    tripwire(&on_path.join(&py_name), &marker);
    let explicit = root.join("explicit-cli");
    tripwire(&explicit, &marker);
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    tripwire(&repo.join("venv/bin").join(&py_name), &marker);
    tripwire(&repo.join("venv/bin/noo"), &marker);
    let out = Command::new(bin())
        .args(args)
        .env_clear()
        .env("HOME", &*root)
        .env("PATH", &on_path)
        .env(["NOO", "PY", "CLI"].join("_"), &explicit)
        .env("NOO_REPO_ROOT", &repo)
        .stdin(Stdio::null())
        .output()
        .expect("run noo binary");
    let fired = marker.exists();
    (out, fired)
}

/// Lower-cased: ui.rs sentence-cases the first word of an error line.
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_lowercase()
}

#[test]
fn an_unknown_first_word_is_a_usage_error_and_execs_nothing() {
    let (out, fired) = run(&["definitelynotacommand", "x"]);
    assert!(!fired, "the binary exec'd a Python CLI");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("unknown command `definitelynotacommand`"), "stderr: {}", stderr(&out));
}

#[test]
fn an_unknown_subcommand_names_the_word_and_lists_the_real_ones() {
    let (out, fired) = run(&["security", "keys", "list"]);
    assert!(!fired, "the binary exec'd a Python CLI");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("unknown command `keys` under `noo security`"), "stderr: {err}");
    assert!(err.contains("service-key"), "the real subcommands are listed: {err}");
}

#[test]
fn a_retired_subcommand_of_a_native_group_is_unknown_not_python() {
    let (out, fired) = run(&["db", "revision"]);
    assert!(!fired, "the binary exec'd a Python CLI");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("unknown command `revision` under `noo db`"), "stderr: {}", stderr(&out));
}

#[test]
fn a_bare_group_needs_a_subcommand_and_exits_2() {
    let (out, fired) = run(&["plugins"]);
    assert!(!fired, "the binary exec'd a Python CLI");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("`noo plugins` needs a subcommand"), "stderr: {}", stderr(&out));
}

#[test]
fn json_mode_reports_the_same_error_as_json() {
    let (out, fired) = run(&["--json", "definitelynotacommand"]);
    assert!(!fired, "the binary exec'd a Python CLI");
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown_command"), "stderr: {}", stderr(&out));
}

#[test]
fn the_old_python_name_is_not_a_plugin_either() {
    // `noo py` used to be the Python CLI; a console script of that name on
    // PATH must not become a plugin by default.
    let (out, fired) = run(&["py"]);
    assert!(!fired, "the binary exec'd a Python CLI");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
}
