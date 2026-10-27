// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Ratchet: each configuration value has ONE reader (i191 D7).
//!
//! The gateway URL, the TLS anchor and the cluster secret used to be read
//! wherever a command needed them, so a new source (a file-backed secret, a
//! new URL rung) had to be threaded through every reader and "two answers"
//! were one edit away. The owners are:
//!
//! | value                              | owner                                  |
//! |------------------------------------|----------------------------------------|
//! | `CONTROLLER_URL`, `NOO_GATEWAY_URL`| `envfile.rs` (`gateway_url*`)          |
//! | `NOO_TLS_CA`                       | `http.rs` (`tls_ca_env`)               |
//! | `NOO_CLUSTER_SECRET`               | `credentials.rs` (`cluster_secret_from_env`) |
//!
//! This test scans the non-test code under `src/` and fails when any other
//! file READS one of those process variables (`std::env::var`, `var_os`, or
//! the crate's own `env_var` / `read_env` / `env_or_dotenv` helpers). Writing
//! a variable (`set_var`, `remove_var`), listing its name in a table, and
//! parsing it out of an env file (including the method form
//! `ctx.read_env(..)`, which reads the install's `.env`) are not reads of the
//! process environment and are left alone.

use std::path::{Path, PathBuf};

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("config_readers: cannot read dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Non-test code with whole-line comments dropped and all whitespace removed,
/// so a call split across lines still matches. Everything from the first bare
/// `#[cfg(test)]` line on is test code in this crate.
fn code_only(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        if line.trim() == "#[cfg(test)]" {
            break;
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.extend(line.chars().filter(|c| !c.is_whitespace()));
    }
    out
}

const READ_CALLS: &[&str] =
    &["var(", "var_os(", "env_var(", "read_env(", "env_or_dotenv(root,"];

/// True when `code` (from [`code_only`]) reads process variable `name`.
fn reads_var(code: &str, name: &str) -> bool {
    for call in READ_CALLS {
        let needle = format!("{call}\"{name}\"");
        let mut from = 0;
        while let Some(i) = code[from..].find(&needle) {
            let at = from + i;
            let before = &code[..at];
            // `set_var(` / `remove_var(` contain `var(` but write; a method
            // call (`ctx.read_env(`) reads an env FILE, not the process.
            if !(before.ends_with("set_") || before.ends_with("remove_") || before.ends_with('.')) {
                return true;
            }
            from = at + needle.len();
        }
    }
    false
}

/// Files (relative to `src/`) other than `owners` that read any of `names`.
/// Also returns how many files were scanned.
fn offenders(names: &[&str], owners: &[&str]) -> (Vec<String>, usize) {
    let root = src_root();
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    let mut bad = Vec::new();
    for f in &files {
        let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if owners.contains(&rel.as_str()) {
            continue;
        }
        let code = code_only(&std::fs::read_to_string(f).expect("read source"));
        for n in names {
            if reads_var(&code, n) {
                bad.push(format!("{rel} reads {n}"));
            }
        }
    }
    (bad, files.len())
}

fn assert_one_owner(names: &[&str], owners: &[&str], hint: &str) {
    let (bad, scanned) = offenders(names, owners);
    assert!(scanned >= 100, "scan found only {scanned} source files — the walk is broken");
    assert!(bad.is_empty(), "{hint}\n  {}", bad.join("\n  "));
}

#[test]
fn scanner_sees_reads_and_ignores_writes() {
    let c = code_only("let a = std::env::var(\n  \"NOO_X\").ok();\nstd::env::set_var(\"NOO_Y\", v);\n// env::var(\"NOO_Z\")\n#[cfg(test)]\nenv::var(\"NOO_W\")\n");
    assert!(reads_var(&c, "NOO_X"));
    assert!(!reads_var(&c, "NOO_Y"));
    assert!(!reads_var(&c, "NOO_Z"));
    assert!(!reads_var(&c, "NOO_W"));
    assert!(reads_var(&code_only("let v = env_var(\"NOO_X\");"), "NOO_X"));
    assert!(!reads_var(&code_only("let v = ctx.read_env(\"NOO_X\");"), "NOO_X"));
}

#[test]
fn config_readers_have_one_owner() {
    assert_one_owner(
        &["CONTROLLER_URL", "NOO_GATEWAY_URL"],
        &["envfile.rs"],
        "the gateway URL has one reader: envfile::gateway_url / gateway_url_from_env",
    );
    assert_one_owner(
        &["NOO_TLS_CA"],
        &["http.rs"],
        "the TLS anchor env var has one reader: http::tls_ca_env",
    );
    assert_one_owner(
        &["NOO_CLUSTER_SECRET"],
        &["credentials.rs"],
        "the CLI must not grow readers of the cluster secret (it never sends it); \
         credentials::cluster_secret_from_env is the one door",
    );
}
