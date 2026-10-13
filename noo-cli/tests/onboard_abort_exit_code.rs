// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo onboard --ci` with a missing prerequisite must exit non-zero.
//!
//! Regression for the clean-Ubuntu rehearsal (noo-cli 0.5.78-rc.3): Ubuntu's
//! docker.io answers `docker --version` but has no compose plugin, the
//! wizard printed "Prerequisites missing — aborting (non-interactive)" and
//! exited 0, so any wrapper saw a failed install as a success. A fake
//! `docker` on PATH reproduces exactly that box; HOME is a scratch dir so
//! the run touches nothing real.

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

fn shim(dir: &std::path::Path, name: &str, body: &str) {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn ci_onboard_without_compose_exits_nonzero_and_says_why() {
    let root = std::env::temp_dir().join(format!("noo-onboard-abort-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let bindir = root.join("bin");
    let home = root.join("home");
    std::fs::create_dir_all(&bindir).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    // docker answers --version, errors on `compose version` (rc 125 like Ubuntu's shim).
    shim(&bindir, "docker", "if [ \"$1\" = compose ]; then echo \"unknown shorthand flag: 'f' in -f\" >&2; exit 125; fi\necho 'Docker version 29.1.3'\n");
    // git present, so the ONLY missing prerequisite is compose.
    shim(&bindir, "git", "echo 'git version 2.43.0'\n");

    let out = Command::new(bin())
        .args(["onboard", "--ci", "--dry-run"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", format!("{}:/usr/bin:/bin", bindir.display()))
        .env("NOO_DATA_ROOT", root.join("data"))
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .expect("run noo onboard");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&root);

    assert!(text.contains("Prerequisites missing"), "output: {text}");
    assert!(text.contains("did NOT complete"), "closing line missing: {text}");
    assert_eq!(out.status.code(), Some(1), "an aborted wizard must exit 1: {text}");
}
