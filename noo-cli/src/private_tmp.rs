// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Private temp work paths (i689). Every scratch directory or file this CLI
//! makes under the system temp dir goes through [`dir`]: an unguessable
//! name, created fresh with mode 0700, never reused.
//!
//! The pattern it replaces, `temp_dir()/noo-<what>-<pid>` with
//! `create_dir_all` (or `std::fs::write` for a single file), was predictable
//! and accepted whatever already stood at that name. Another local user on
//! the controller could pre-create the directory (world-writable, theirs) or
//! a symlink, then swap the files inside before they were CA-signed into a
//! node bundle, run by `bash`, or installed as root by `sudo install`. A pid
//! is guessable; `create_dir_all` succeeds on an existing directory; `write`
//! follows a symlink. `mkdir` of a fresh random name with mode 0700 is what
//! mkdtemp(3) does, and EEXIST is a retry, never a reuse.

use std::path::PathBuf;

/// A fresh, private (0700) directory `<tmp>/<prefix>-<64 random bits>`.
/// The caller removes it when done.
pub(crate) fn dir(prefix: &str) -> Result<PathBuf, String> {
    use std::io::Read as _;
    dir_named(&std::env::temp_dir(), prefix, &mut || {
        let mut raw = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut raw))
            .map_err(|e| format!("cannot read /dev/urandom for a private staging name: {e}"))?;
        Ok(raw)
    })
}

/// [`dir`] with the parent and the random source injected (tests plant the
/// exact next name).
fn dir_named(under: &std::path::Path, prefix: &str, random: &mut dyn FnMut() -> Result<[u8; 8], String>) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt as _;
    for _ in 0..16 {
        let dir = under.join(format!("{prefix}-{}", hex::encode(random()?)));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create the private staging directory {}: {e}", dir.display())),
        }
    }
    Err("could not find an unused private staging directory name".into())
}

/// A [`dir`] removed (with everything in it) when dropped: for a work dir
/// whose function returns early with `?` between making and cleaning it. A
/// path that leaves through `fail()` (process exit) never drops — scrub it
/// explicitly there.
pub(crate) struct Dir(PathBuf);

impl Dir {
    pub(crate) fn new(prefix: &str) -> Result<Self, String> {
        dir(prefix).map(Dir)
    }
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A path for one scratch FILE named `name`, inside a fresh private [`dir`].
/// Returns (the dir, the file path); remove the dir when done.
pub(crate) fn file(prefix: &str, name: &str) -> Result<(PathBuf, PathBuf), String> {
    let d = dir(prefix)?;
    let f = d.join(name);
    Ok((d, f))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn each_dir_is_fresh_private_and_unguessable() {
        let a = super::dir("noo-private-tmp-test").unwrap();
        let b = super::dir("noo-private-tmp-test").unwrap();
        assert_ne!(a, b, "two calls returned the same directory");
        for d in [&a, &b] {
            let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} is {mode:o}", d.display());
            let name = d.file_name().unwrap().to_string_lossy().to_string();
            assert!(!name.contains(&std::process::id().to_string()), "the name carries the pid: {name}");
            let suffix = name.strip_prefix("noo-private-tmp-test-").expect("prefix");
            assert_eq!(suffix.len(), 16, "not 64 random bits: {name}");
        }
        let (d, f) = super::file("noo-private-tmp-test", "x.sh").unwrap();
        assert_eq!(f.parent(), Some(d.as_path()));
        assert!(!f.exists());
        for d in [a, b, d] {
            let _ = std::fs::remove_dir_all(d);
        }
        let g = super::Dir::new("noo-private-tmp-guard").unwrap();
        let kept = g.path().to_path_buf();
        std::fs::write(kept.join("secret"), b"x").unwrap();
        drop(g);
        assert!(!kept.exists(), "a dropped Dir was left behind");
    }

    /// A name that already exists is never reused, whether a directory
    /// (another user's, world-writable) or a symlink: mkdir refuses it with
    /// EEXIST and the next name is drawn. Nothing is created through the link.
    #[test]
    fn an_existing_name_is_never_reused() {
        let under = super::dir("noo-private-tmp-planted").unwrap();
        let target = under.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::create_dir(under.join("w-0000000000000000")).unwrap();
        std::fs::set_permissions(under.join("w-0000000000000000"), std::fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&target, under.join("w-0101010101010101")).unwrap();
        let mut n = 0u8;
        let d = super::dir_named(&under, "w", &mut || { let r = [n; 8]; n += 1; Ok(r) }).unwrap();
        assert_eq!(d, under.join("w-0202020202020202"), "a planted name was reused");
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "something was created through the symlink");
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // Every name taken: a refusal, never a reuse.
        let e = super::dir_named(&under, "w", &mut || Ok([0; 8])).expect_err("a taken name was reused");
        assert!(e.contains("unused"), "{e}");
        let _ = std::fs::remove_dir_all(under);
    }

    /// The ratchet (i689): no production code under noo-cli/src makes a temp
    /// path by NAME any more — `temp_dir()` followed, in the same statement,
    /// by the pid or a literal file name. Every such path goes through this
    /// module. Tests are exempt (own_code drops them); a new site fails here
    /// with its file and the statement.
    #[test]
    fn no_production_code_names_a_temp_path() {
        fn walk(d: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() { walk(&p, out) } else if p.extension().is_some_and(|x| x == "rs") { out.push(p) }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        assert!(files.len() > 50, "the walk found {} files: this guard is stale", files.len());
        let mut found = Vec::new();
        let mut scanned_a_temp_dir = false;
        for f in &files {
            let rel = f.strip_prefix(&src).unwrap().display().to_string();
            if rel == "private_tmp.rs" || rel.starts_with("test_") {
                continue;
            }
            let code = crate::test_src::own_code(&std::fs::read_to_string(f).unwrap());
            for (at, _) in code.match_indices("temp_dir()") {
                scanned_a_temp_dir = true;
                let stmt = &code[at..code[at..].find(';').map_or(code.len(), |e| at + e)];
                let joined_literal = stmt.split(".join(").skip(1).any(|a| a.trim_start().starts_with('"'));
                if stmt.contains("process::id()") || joined_literal {
                    found.push(format!("{rel}: {}", stmt.split_whitespace().collect::<Vec<_>>().join(" ")));
                }
            }
        }
        assert!(scanned_a_temp_dir, "no temp_dir() in production code at all: this guard is stale");
        assert!(found.is_empty(), "temp paths made by name (use crate::private_tmp):\n{}", found.join("\n"));
    }
}
