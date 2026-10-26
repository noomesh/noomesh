// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo test …` — pytest wrapper, a DEV/subprocess surface (like `mesh`,
//! it spawns a child process rather than calling the gateway).
//!
//! Ported (clean pytest subprocess, inherited stdio, exit code propagated):
//!   - `test run` — `python -m pytest [--ignore tests/integration] [-x] …`
//!   - `test coverage` — the same with `--cov=noomesh`.
//!
//! Not ported (a usage error, exit 2 — the Python CLI is gone):
//!   - `test gen-stub` — parses source ASTs and WRITES pytest skeleton files
//!     (with an interactive overwrite confirm) — file authoring, not runnable
//!     natively.
//!   - `test accept` — writes an integration-test template file (interactive
//!     overwrite confirm) — file authoring.
//!   - `test status` — a Python-specific source-tree scan (tested vs untested
//!     modules); no pytest run, no gateway, pure Python reporting logic.
//!
//! Note: the gateway also exposes `POST /api/tests/run`, but it spawns pytest
//! IN the gateway container in the background and returns a job id — different
//! semantics (async, container tests, no live output) from Python's `test run`
//! (foreground host pytest with streamed output + exit code). The native port
//! matches the Python subprocess semantics, not the gateway job.

use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::envfile::repo_root;
use crate::output::{fail, ExitCode};
use crate::{Globals, Unhandled};

/// Resolve the Python interpreter the way `test_cli._find_python` does:
/// `$VIRTUAL_ENV/bin/python`, else the repo `venv/bin/python`, else
/// `python3` on PATH.
fn find_python(root: &PathBuf) -> String {
    if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
        let c = PathBuf::from(&venv).join("bin").join("python");
        if c.is_file() {
            return c.to_string_lossy().into_owned();
        }
    }
    let venv = root.join("venv").join("bin").join("python");
    if venv.is_file() {
        return venv.to_string_lossy().into_owned();
    }
    "python3".to_string()
}

/// Spawn `python -m pytest <args>` at the repo root, mirroring `mesh`'s
/// subprocess contract: human mode → inherited stdio, return the child's exit
/// code; `--json` mode → child stdout redirected to OUR stderr (stdout stays
/// data-only) then a `{"status":"ok"|"error","action":…}` line.
fn run_pytest(g: &Globals, action: &str, pytest_args: &[String]) -> i32 {
    let root = repo_root();
    let python = find_python(&root);
    let mut cmd = Command::new(&python);
    cmd.arg("-m").arg("pytest").args(pytest_args).current_dir(&root);

    if g.verbose {
        eprintln!("$ {python} -m pytest {}", pytest_args.join(" "));
    }

    if g.json {
        // Keep stdout data-only: route pytest's stdout to our stderr.
        let stderr_copy = unsafe { libc::dup(2) };
        if stderr_copy >= 0 {
            cmd.stdout(unsafe { Stdio::from_raw_fd(stderr_copy) });
        }
        let status = match cmd.status() {
            Ok(s) => s,
            Err(e) => fail(
                true,
                ExitCode::Generic,
                "subprocess_failed",
                &format!("failed to run pytest: {e}"),
                Some("is the venv present? (VIRTUAL_ENV / <repo>/venv/bin/python)"),
            ),
        };
        let rc = status.code().unwrap_or(1);
        if status.success() {
            println!("{}", serde_json::json!({"status": "ok", "action": action}));
            return 0;
        }
        eprintln!(
            "{}",
            serde_json::json!({"error": format!("pytest exited with {rc}"), "code": "test_failed"})
        );
        return if rc == 0 { 1 } else { rc };
    }

    match cmd.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => fail(
            false,
            ExitCode::Generic,
            "subprocess_failed",
            &format!("failed to run pytest: {e}"),
            Some("is the venv present? (VIRTUAL_ENV / <repo>/venv/bin/python)"),
        ),
    }
}

/// `noo test run [-x/--failfast|--no-failfast] [-k PATTERN] [--integration]`.
/// (`-v/--verbose` is consumed as the global flag — when set it is forwarded
/// to pytest as `-v`.)
pub fn test_run(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut failfast = true; // Python default: -x on
    let mut pattern: Option<String> = None;
    let mut include_integration = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-x" | "--failfast" => failfast = true,
            "--no-failfast" => failfast = false,
            "-k" => match it.next() {
                Some(p) => pattern = Some(p.clone()),
                None => return Err(Unhandled),
            },
            "--integration" => include_integration = true,
            _ => return Err(Unhandled),
        }
    }

    let root = repo_root();
    let mut pargs: Vec<String> = Vec::new();
    if !include_integration {
        pargs.push("--ignore".into());
        pargs.push(root.join("tests").join("integration").to_string_lossy().into_owned());
    }
    if g.verbose {
        pargs.push("-v".into());
    }
    if failfast {
        pargs.push("-x".into());
    }
    if let Some(p) = pattern {
        pargs.push("-k".into());
        pargs.push(p);
    }
    pargs.push(root.join("tests").to_string_lossy().into_owned());

    Ok(run_pytest(g, "test_run", &pargs))
}

/// `noo test coverage [--html]` — pytest with `--cov=noomesh`.
pub fn test_coverage(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut html = false;
    for a in args {
        match a.as_str() {
            "--html" => html = true,
            _ => return Err(Unhandled),
        }
    }

    let root = repo_root();
    let mut pargs: Vec<String> = vec![
        "--ignore".into(),
        root.join("tests").join("integration").to_string_lossy().into_owned(),
        "--cov=noomesh".into(),
        "--cov-report=term-missing".into(),
    ];
    if html {
        pargs.push("--cov-report=html".into());
    }
    pargs.push(root.join("tests").to_string_lossy().into_owned());

    Ok(run_pytest(g, "test_coverage", &pargs))
}
