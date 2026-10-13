// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Confining a heartbeat action's file output to its workspace.
//!
//! `write_log` joins `config.workspace_dir` and `config.filename` and truncates the result. With
//! `Path::join` an absolute `filename` replaces the workspace, so a task could aim the write at any
//! file the gateway can write (its config, its prompts). The task's config is data an agent can
//! author, so the action itself refuses: the output path must be a RELATIVE path of plain names, under
//! the resolved workspace, with no symlink on the way out of it.
//!
//! A `workspace_dir` override is honoured only if it is itself inside the default workspace.

use std::path::{Component, Path, PathBuf};

/// Where `filename` may be written: `Ok(path)` inside `default_ws` (an optional `workspace_dir`
/// override must also be inside it), with the directories made as the walk proves each one stays
/// inside. Nothing is created outside the workspace and nothing is written through a symlink.
pub fn confined_output_path(default_ws: &Path, ws_override: Option<&str>, filename: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(default_ws).map_err(|e| format!("workspace {} is not usable: {e}", default_ws.display()))?;
    let root = default_ws
        .canonicalize()
        .map_err(|e| format!("workspace {} is not usable: {e}", default_ws.display()))?;

    // The base directory: the workspace, or an override that stays inside it.
    let base = match ws_override.filter(|s| !s.is_empty()) {
        None => root.clone(),
        Some(d) => {
            let p = Path::new(d);
            let rel = if p.is_absolute() {
                p.strip_prefix(&root)
                    .or_else(|_| p.strip_prefix(default_ws))
                    .map_err(|_| format!("workspace_dir {d:?} is outside the workspace {}", root.display()))?
                    .to_path_buf()
            } else {
                p.to_path_buf()
            };
            walk_into(&root, &root, &rel, d)?
        }
    };

    let rel = Path::new(filename);
    if filename.is_empty() || filename.contains('\0') {
        return Err("filename is empty or contains a NUL".into());
    }
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let name = rel.file_name().ok_or_else(|| format!("filename {filename:?} names no file"))?;
    let dir = walk_into(&root, &base, parent_rel, filename)?;
    let out = dir.join(name);
    // Never write THROUGH a symlink that is already there.
    if let Ok(md) = std::fs::symlink_metadata(&out) {
        if md.file_type().is_symlink() {
            return Err(format!("{} is a symlink; refusing to write through it", out.display()));
        }
    }
    Ok(out)
}

/// Open a confined output path for writing WITHOUT following a symlink: `O_NOFOLLOW` makes the open
/// itself refuse one, so a link swapped in between [`confined_output_path`]'s check and the write
/// cannot carry the write out. The file is not truncated here; the caller truncates the handle.
#[cfg(unix)]
pub fn open_output(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).custom_flags(libc::O_NOFOLLOW).mode(0o644).open(path)
}

/// Walk `rel` (plain names only) down from `from`, creating each missing directory and checking
/// after each step that the real path is still under `root`.
fn walk_into(root: &Path, from: &Path, rel: &Path, shown: &str) -> Result<PathBuf, String> {
    let mut cur = from.to_path_buf();
    for c in rel.components() {
        match c {
            Component::CurDir => {}
            Component::Normal(n) => {
                cur.push(n);
                if cur.exists() {
                    let real = cur.canonicalize().map_err(|e| format!("{}: {e}", cur.display()))?;
                    if !real.starts_with(root) {
                        return Err(format!("{shown:?} leaves the workspace (through {})", cur.display()));
                    }
                    if !real.is_dir() {
                        return Err(format!("{} is not a directory", cur.display()));
                    }
                    cur = real;
                } else {
                    std::fs::create_dir(&cur).map_err(|e| format!("cannot create {}: {e}", cur.display()))?;
                }
            }
            // `..`, a root or a drive prefix: never.
            _ => return Err(format!("{shown:?} must be a relative path of plain names (no `..`, no absolute path)")),
        }
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-confine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_plain_relative_name_lands_in_the_workspace() {
        let d = scratch("ok");
        let ws = d.join("ws");
        let p = confined_output_path(&ws, None, "activity/heartbeat-1.md").unwrap();
        assert!(p.starts_with(ws.canonicalize().unwrap()) && p.ends_with("activity/heartbeat-1.md"), "{p:?}");
        assert!(p.parent().unwrap().is_dir());
        let q = confined_output_path(&ws, Some("sub"), "x.md").unwrap();
        assert!(q.starts_with(ws.canonicalize().unwrap().join("sub")), "{q:?}");
    }

    #[test]
    fn an_absolute_filename_is_refused() {
        let d = scratch("abs");
        let victim = d.join("noomesh.yaml");
        std::fs::write(&victim, "precious").unwrap();
        let ws = d.join("ws");
        for f in [victim.to_str().unwrap(), "/app/noomesh.yaml", "/etc/passwd"] {
            assert!(confined_output_path(&ws, None, f).is_err(), "{f}");
        }
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    }

    #[test]
    fn a_dotdot_path_is_refused() {
        let d = scratch("dotdot");
        let ws = d.join("ws");
        for f in ["../escape.md", "a/../../escape.md", "a/../b.md", ".."] {
            assert!(confined_output_path(&ws, None, f).is_err(), "{f}");
        }
        assert!(confined_output_path(&ws, Some("../other"), "x.md").is_err());
        assert!(!d.join("escape.md").exists());
    }

    #[test]
    fn a_workspace_override_must_stay_inside_the_default_workspace() {
        let d = scratch("override");
        let ws = d.join("ws");
        let outside = d.join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        assert!(confined_output_path(&ws, Some(outside.to_str().unwrap()), "x.md").is_err());
        assert!(confined_output_path(&ws, Some("/app"), "x.md").is_err());
        // an absolute override that IS inside is fine
        let inside = ws.join("reports");
        let p = confined_output_path(&ws, Some(inside.to_str().unwrap()), "x.md").unwrap();
        assert!(p.starts_with(ws.canonicalize().unwrap().join("reports")), "{p:?}");
    }

    #[test]
    fn write_log_opens_through_open_output_before_it_gathers() {
        let src = include_str!("heartbeat_actions.rs");
        let f = &src[src.find("async fn action_write_log(").unwrap()..];
        let f = &f[..f.find("\n}\n").unwrap()];
        let open = f.find("confine::open_output(").expect("write_log opens with O_NOFOLLOW");
        let gather = f.find("gather_section(").expect("gathers");
        assert!(open < gather, "opened before the slow gather, not after");
        assert!(!f.contains("std::fs::write("), "a plain path write would follow a symlink swapped in after the check");
    }

    #[cfg(unix)]
    #[test]
    fn the_open_refuses_a_symlink_swapped_in_after_the_check() {
        use std::os::unix::fs::symlink;
        let d = scratch("swap");
        let ws = d.join("ws");
        let p = confined_output_path(&ws, None, "log.md").unwrap(); // checked: nothing there yet
        let victim = d.join("victim.txt");
        std::fs::write(&victim, "precious").unwrap();
        symlink(&victim, &p).unwrap(); // swapped in before the write
        assert!(open_output(&p).is_err(), "O_NOFOLLOW refuses it");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        // a plain file opens
        let q = confined_output_path(&ws, None, "ok.md").unwrap();
        assert!(open_output(&q).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_cannot_carry_the_write_out() {
        use std::os::unix::fs::symlink;
        let d = scratch("symlink");
        let ws = d.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let outside = d.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        // a directory symlink out of the workspace
        symlink(&outside, ws.join("link")).unwrap();
        assert!(confined_output_path(&ws, None, "link/x.md").is_err(), "through a directory symlink");
        assert!(confined_output_path(&ws, None, "link/new/x.md").is_err());
        assert!(confined_output_path(&ws, Some("link"), "x.md").is_err(), "as the override");
        assert!(!outside.join("new").exists() && !outside.join("x.md").exists(), "nothing was created outside");
        // a file symlink at the target
        let victim = d.join("victim.txt");
        std::fs::write(&victim, "precious").unwrap();
        symlink(&victim, ws.join("log.md")).unwrap();
        assert!(confined_output_path(&ws, None, "log.md").is_err(), "through a file symlink");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
    }
}
