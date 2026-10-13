// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A dist (binary-installed) controller has no source checkout: `scripts/`
//! there holds only what `onboard::standalone` materialises from build.rs's
//! STANDALONE_FILES. Any runtime `scripts/<x>` path the CLI builds must name
//! a file in that set, or be allowlisted below as checkout-only WITH a reason
//! (and refuse with a message, never a raw "No such file").
//!
//! Why this exists: `noo cluster upgrade-applier` read
//! repo_root()/scripts/noo-apply.sh — a file that is compiled in for
//! enrollment (ENROLL_ASSETS) but not materialised — and a dist controller
//! answered "read noo-apply.sh: No such file or directory" (host8,
//! 2026-10-04). prep-host.sh had the same shape and was worse: an
//! `if prep.exists()` skipped host prep silently.
//!
//! Complements tests/test_standalone_asset_parity.py, which counts ANY
//! build.rs mention (including ENROLL_ASSETS) as "embedded" and so could not
//! see that distinction.

use std::path::{Path, PathBuf};

/// (source file suffix, script, why a missing script is acceptable there)
const CHECKOUT_ONLY: &[(&str, &str, &str)] = &[
    ("commands/upgrade.rs", "noo-apply.sh",
     "`noo upgrade --controller` builds binaries from the checkout; it checks for the \
      checkout first and refuses with `not_checkout` (never a raw ENOENT)"),
    ("commands/provision.rs", "prep-host.sh",
     "fallback only when the binary has NO embedded copy (a crate-only build); the \
      normal path stages enroll::asset_prep(), and with neither it errors"),
];

fn standalone_files(build_rs: &str) -> Vec<String> {
    let start = build_rs.find("const STANDALONE_FILES").expect("STANDALONE_FILES in build.rs");
    let body = &build_rs[start..];
    let body = &body[..body.find("];").expect("end of STANDALONE_FILES")];
    body.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter_map(|l| {
            let l = l.trim();
            let q = l.strip_prefix('"')?;
            let rel = &q[..q.find('"')?];
            rel.strip_prefix("scripts/").map(str::to_string)
        })
        .collect()
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() { rs_files(&p, out) } else if p.extension().is_some_and(|x| x == "rs") { out.push(p) }
    }
}

/// Script names a line builds a path to: "scripts/x.sh" literals and
/// .join("scripts").join("x.sh") chains.
fn script_paths(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find("\"scripts/") {
        let after = &rest[i + 9..];
        if let Some(j) = after.find('"') {
            let name = &after[..j];
            if !name.is_empty() && !name.contains(['/', ' ', '{']) { found.push(name.to_string()); }
        }
        rest = &rest[i + 9..];
    }
    let mut rest = line;
    while let Some(i) = rest.find("join(\"scripts\")") {
        let after = &rest[i + 15..];
        if let Some(r) = after.trim_start().strip_prefix(".join(\"") {
            if let Some(j) = r.find('"') { found.push(r[..j].to_string()); }
        }
        rest = after;
    }
    found.sort();
    found.dedup();
    found
}

#[test]
fn runtime_script_reads_are_materialised_or_checkout_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let shipped = standalone_files(&std::fs::read_to_string(root.join("build.rs")).unwrap());
    assert!(shipped.iter().any(|s| s == "noomesh-start.sh"), "parsed no STANDALONE_FILES: {shipped:?}");

    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    let mut bad = Vec::new();
    let mut allowed_used = vec![false; CHECKOUT_ONLY.len()];
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let rel = f.strip_prefix(root.join("src")).unwrap().to_string_lossy().replace('\\', "/");
        // Production code only: by convention the test module ends the file.
        let prod = text.split("#[cfg(test)]").next().unwrap();
        // KNOWN_RETIRED names scripts that are NO LONGER shipped, as data to
        // delete — never reads. Skip the table body.
        let mut in_retired_table = false;
        for (n, line) in prod.lines().enumerate() {
            if line.contains("const KNOWN_RETIRED") { in_retired_table = true; continue; }
            if in_retired_table {
                if line.trim() == "];" { in_retired_table = false; }
                continue;
            }
            if line.trim_start().starts_with("//") { continue; }
            for name in script_paths(line) {
                if shipped.contains(&name) { continue; }
                if let Some(i) = CHECKOUT_ONLY.iter().position(|(f, s, _)| rel.ends_with(f) && *s == name) {
                    allowed_used[i] = true;
                    continue;
                }
                bad.push(format!("{rel}:{} reads scripts/{name}", n + 1));
            }
        }
    }
    assert!(bad.is_empty(),
        "runtime reads of scripts a dist controller does not have (add to build.rs \
         STANDALONE_FILES, embed with include_str!/ENROLL_ASSETS, or allowlist as \
         checkout-only with a refusal message): {bad:#?}");
    // A stale allowlist entry hides the next regression behind it.
    for (i, used) in allowed_used.iter().enumerate() {
        assert!(*used, "CHECKOUT_ONLY entry no longer matches any read: {:?}", CHECKOUT_ONLY[i]);
    }
}

#[test]
fn the_parser_sees_the_known_shapes() {
    assert_eq!(script_paths(r#"let s = root.join("scripts/prep-host.sh");"#), ["prep-host.sh"]);
    assert_eq!(script_paths(r#"repo_root().join("scripts").join("noo-apply.sh")"#), ["noo-apply.sh"]);
    assert!(script_paths(r#"println!("run scripts/x.sh now")"#).is_empty());
}
