// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo plugins …` + git-style `noo-<name>` shim discovery (WP-PL).
//!
//! Two plugin worlds COEXIST and don't overlap:
//!
//! - **Executable shims (this module, native)** — any executable named
//!   `noo-<name>` on PATH or in the user plugins dir
//!   (`~/.config/mesh/plugins/bin/`, created on demand) is a plugin, exactly
//!   like `git-<name>`. `noo plugins list` enumerates them and the dispatcher
//!   (main.rs) exec()s `noo-<word>` when a command word matches no native
//!   entry — builtins → plugins → Python passthrough.
//! - **Python-package plugins (Python CLI)** — directories with a `plugin.py`
//!   under `~/.noo/plugins` (`PluginManager.discover_plugins`), IMPORTED
//!   in-process by the gateway/Python CLI. The static binary can't execute
//!   Python, so those remain the Python CLI's surface (`noo-py plugins list`);
//!   the native list prints a pointer when a Python install is present.
//!
//! Security posture:
//! - only files with the executable bit are considered;
//! - relative PATH entries (including the empty entry, i.e. CWD) are IGNORED —
//!   the dispatcher never resolves a plugin from the current directory;
//! - trusting the directories on PATH is the user's contract, same as git's.
//!
//! De-dup is by name, first hit wins: PATH order first, the user plugins dir
//! is searched LAST (an explicit PATH install overrides a dropped-in shim).
//! `noo-py` is reserved — it is the Python CLI itself (passthrough.rs), never
//! a plugin.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{Globals, Unhandled};
use crate::ui::{self, Col};

/// Shim names that are never plugins: `noo-py` is the side-by-side Python
/// CLI the passthrough execs (see passthrough.rs resolution order).
pub const RESERVED_PLUGIN_NAMES: &[&str] = &["py"];

/// A discovered `noo-<name>` executable.
#[derive(Debug, Clone, PartialEq)]
pub struct PluginShim {
    pub name: String,
    pub path: PathBuf,
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111) != 0,
        Err(_) => false,
    }
}

/// The user plugins dir: `$XDG_CONFIG_HOME|~/.config` + `mesh/plugins/bin`.
/// Created on demand by `plugins list` (not by discovery, which stays
/// read-only so the dispatcher never mutates the filesystem).
pub fn user_plugins_dir() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return PathBuf::from(x).join("mesh").join("plugins").join("bin");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".config").join("mesh").join("plugins").join("bin")
}

/// Directories searched for shims: ABSOLUTE PATH entries in order, then the
/// user plugins dir. Relative/empty PATH entries are dropped (never CWD).
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(path_var) = std::env::var("PATH") {
        for d in std::env::split_paths(&path_var) {
            if d.is_absolute() {
                dirs.push(d);
            }
        }
    }
    dirs.push(user_plugins_dir());
    dirs
}

/// Scan `dirs` in order for `noo-<name>` executables; de-dup by name, first
/// directory wins. Names are sorted within a directory for stable output.
/// Pure over its inputs — unit-testable with temp dirs, no env access.
pub fn discover_in(dirs: &[PathBuf]) -> Vec<PluginShim> {
    let mut out: Vec<PluginShim> = Vec::new();
    for dir in dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut found: Vec<(String, PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().into_owned();
            let name = match fname.strip_prefix("noo-") {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => continue,
            };
            if RESERVED_PLUGIN_NAMES.contains(&name.as_str()) {
                continue;
            }
            let path = entry.path();
            if !is_executable_file(&path) {
                continue;
            }
            found.push((name, path));
        }
        found.sort();
        for (name, path) in found {
            if !out.iter().any(|p| p.name == name) {
                out.push(PluginShim { name, path });
            }
        }
    }
    out
}

/// Discover all shims via the real search dirs (PATH order, user dir last).
pub fn discover() -> Vec<PluginShim> {
    discover_in(&search_dirs())
}

/// Resolve one plugin name to its executable, honoring the same search order
/// and exclusions as [`discover`]. Used by the dispatcher fallback (main.rs).
pub fn find_plugin(name: &str) -> Option<PathBuf> {
    if name.is_empty()
        || name.starts_with('-')
        || name.contains('/')
        || RESERVED_PLUGIN_NAMES.contains(&name)
    {
        return None;
    }
    let fname = format!("noo-{name}");
    search_dirs()
        .into_iter()
        .map(|d| d.join(&fname))
        .find(|c| is_executable_file(c))
}

/// Best-effort one-line description: run `<shim> --noo-plugin-info` with a
/// 500ms budget; nonzero exit, timeout, spawn failure, or empty output all
/// yield None (a shim is NOT required to support the flag).
pub fn probe_description(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(path)
        .arg("--noo-plugin-info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut out = String::new();
                child.stdout.take()?.read_to_string(&mut out).ok()?;
                let line = out.lines().next()?.trim().to_string();
                return if line.is_empty() { None } else { Some(line) };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
}

/// `noo plugins list` — table of executable shim plugins (name, path,
/// optional `--noo-plugin-info` description). Any extra argument →
/// Unhandled (the Python CLI owns whatever surface that is).
pub fn plugins_list(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }

    // Create-on-demand: make the drop-in dir exist so `plugins list` doubles
    // as "where do I put a shim?". Best-effort (read-only FS is fine).
    let plugins_dir = user_plugins_dir();
    let _ = std::fs::create_dir_all(&plugins_dir);

    let shims = discover();
    let described: Vec<(PluginShim, Option<String>)> = shims
        .into_iter()
        .map(|s| {
            let d = probe_description(&s.path);
            (s, d)
        })
        .collect();
    let python_present = crate::passthrough::python_cli_path().is_some();

    if g.json {
        let arr: Vec<serde_json::Value> = described
            .iter()
            .map(|(s, d)| {
                serde_json::json!({
                    "name": s.name,
                    "path": s.path.to_string_lossy(),
                    "description": d,
                })
            })
            .collect();
        let mut obj = serde_json::json!({
            "plugins": arr,
            "plugins_dir": plugins_dir.to_string_lossy(),
        });
        if python_present {
            obj["note"] = serde_json::Value::String(
                "Python-package plugins are separate — list them with `noo-py plugins list`"
                    .into(),
            );
        }
        println!("{obj}");
        return Ok(0);
    }

    if described.is_empty() {
        println!("{}", ui::muted("no plugin shims"));
        println!(
            "  {}",
            ui::muted(&format!(
                "any executable named `noo-<name>` on PATH or in {} is a plugin (invoked as `noo <name> …`)",
                plugins_dir.display()
            ))
        );
    } else {
        println!("{}", ui::header("plugins", Some(&format!("{} shim(s)", described.len()))));
        println!("{}", ui::section("shims"));
        let rows: Vec<Vec<String>> = described
            .iter()
            .map(|(s, d)| {
                vec![
                    ui::cmd(&s.name),
                    s.path.to_string_lossy().into_owned(),
                    d.clone().unwrap_or_default(),
                ]
            })
            .collect();
        print!("{}", ui::table(&[Col::left("name"), Col::left("path"), Col::left("description")], &rows));
    }
    if python_present {
        println!("{}", ui::note("a Python install is present — Python-package plugins (~/.noo/plugins) are listed by `noo-py plugins list`"));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "noo-cli-plugin-tests-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_file(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
        let p = dir.join(name);
        crate::test_exec::write_exec(&p, body, mode);
        p
    }

    #[test]
    fn discovery_dedups_by_name_first_dir_wins() {
        let a = tmpdir("dedup-a");
        let b = tmpdir("dedup-b");
        let foo_a = write_file(&a, "noo-foo", "#!/bin/sh\n", 0o755);
        write_file(&a, "noo-bar", "#!/bin/sh\n", 0o755);
        write_file(&b, "noo-foo", "#!/bin/sh\n", 0o755); // shadowed dup
        write_file(&b, "noo-baz", "#!/bin/sh\n", 0o755);
        let shims = discover_in(&[a.clone(), b.clone()]);
        let names: Vec<&str> = shims.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["bar", "foo", "baz"], "dir order, sorted within dir");
        let foo = shims.iter().find(|s| s.name == "foo").unwrap();
        assert_eq!(foo.path, foo_a, "earlier dir (PATH order) wins the dedup");
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn discovery_requires_exec_bit_prefix_and_skips_reserved() {
        let d = tmpdir("filter");
        write_file(&d, "noo-noexec", "#!/bin/sh\n", 0o644); // no exec bit
        write_file(&d, "notnoo-x", "#!/bin/sh\n", 0o755); // wrong prefix
        write_file(&d, "noo-", "#!/bin/sh\n", 0o755); // empty name
        write_file(&d, "noo-py", "#!/bin/sh\n", 0o755); // reserved (Python CLI)
        std::fs::create_dir_all(d.join("noo-adir")).unwrap(); // a directory
        write_file(&d, "noo-ok", "#!/bin/sh\n", 0o755);
        let shims = discover_in(std::slice::from_ref(&d));
        let names: Vec<&str> = shims.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["ok"]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn discovery_of_missing_dir_is_empty() {
        let d = std::env::temp_dir().join("noo-cli-plugin-tests-does-not-exist");
        assert!(discover_in(&[d]).is_empty());
    }

    #[test]
    fn probe_description_reads_first_line() {
        let d = tmpdir("probe-ok");
        let p = write_file(
            &d,
            "noo-desc",
            "#!/bin/sh\necho \"Does things\"\necho \"second line ignored\"\n",
            0o755,
        );
        // Tests run in parallel; another test's fork can briefly hold this
        // freshly written script's fd, and exec then fails with ETXTBSY
        // (probe returns None). Retry a few times before judging.
        let mut got = None;
        for _ in 0..10 {
            got = probe_description(&p);
            if got.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert_eq!(got.as_deref(), Some("Does things"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn probe_description_ignores_failures() {
        let d = tmpdir("probe-fail");
        let failing = write_file(&d, "noo-f", "#!/bin/sh\necho x\nexit 1\n", 0o755);
        assert_eq!(probe_description(&failing), None, "nonzero exit → None");
        let silent = write_file(&d, "noo-s", "#!/bin/sh\nexit 0\n", 0o755);
        assert_eq!(probe_description(&silent), None, "empty output → None");
        let _ = std::fs::remove_dir_all(&d);
    }
}
