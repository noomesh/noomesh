//! Test-only access to files that live OUTSIDE this crate.
//!
//! A source-reading guard compares this crate to a file in another language
//! (the gateway, a compose file, a shell script, the web UI). Written as
//! `if !path.exists() { eprintln!("skipped"); return; }`, such a guard
//! passes green by not running: the container harness once mounted only the
//! crate, every cross-language contract test took its skip arm for weeks, and
//! the tick said they had been checked.
//!
//! The rule, in one place: under the build/test harness
//! (`scripts/cargo-docker.sh` sets [`HARNESS_VAR`]; CI and `noo-batch.sh` both
//! run through it) a repo file that is not there is a FAILURE and panics with
//! the path. Outside it (a bare `cargo test` from an unpacked crate) the
//! caller may skip, with the one standard message.
//!
//! Every runtime repo read in a test goes through [`repo_file`],
//! [`repo_file_or_skip`] or [`repo_root`]; the ratchet below fails any file
//! that rebuilds the path from `CARGO_MANIFEST_DIR` by hand.

use std::path::{Path, PathBuf};

/// Set to `1` by `scripts/cargo-docker.sh`: "you are inside the real harness,
/// where the repo root is mounted".
pub const HARNESS_VAR: &str = "NOO_CARGO_DOCKER";

fn under_harness() -> bool {
    std::env::var_os(HARNESS_VAR).is_some()
}

/// The repository root (the parent of this crate). Not checked for any file:
/// use it for an optional file or a directory walk, and [`repo_file`] for a
/// file the test depends on.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("noo-cli has a parent directory")
        .to_path_buf()
}

/// The decision, with the environment taken out so it can be tested without
/// touching process state. `Ok(Some(p))`: present. `Ok(None)`: absent and a
/// skip is legitimate. `Err(msg)`: absent under the harness; a failure.
pub fn lookup(root: &Path, rel: &str, harness: bool) -> Result<Option<PathBuf>, String> {
    let path = root.join(rel);
    if path.exists() {
        return Ok(Some(path));
    }
    if harness {
        return Err(format!(
            "{} is not reachable at {} even though {HARNESS_VAR} is set: the container harness \
             stopped mounting the repo root, and every cross-language contract test that reads \
             it would be silently inert",
            rel,
            path.display()
        ));
    }
    Ok(None)
}

/// `rel` (relative to the repo root) as a path. Panics under the harness when
/// it is missing; outside it the path is returned anyway and the caller's own
/// read fails loudly (use [`repo_file_or_skip`] to skip instead).
pub fn repo_file(rel: &str) -> PathBuf {
    let root = repo_root();
    match lookup(&root, rel, under_harness()) {
        Err(msg) => panic!("{msg}"),
        Ok(Some(p)) => p,
        Ok(None) => root.join(rel),
    }
}

/// Like [`repo_file`], but `None` (after the standard skip message) when the
/// file is absent outside the harness. Under the harness it still panics.
pub fn repo_file_or_skip(rel: &str) -> Option<PathBuf> {
    let root = repo_root();
    match lookup(&root, rel, under_harness()) {
        Err(msg) => panic!("{msg}"),
        Ok(Some(p)) => Some(p),
        Ok(None) => {
            eprintln!("skipped: {rel} is not in this checkout and {HARNESS_VAR} is not set");
            None
        }
    }
}

/// Read a repo file as text, skipping (`None`) only where [`repo_file_or_skip`]
/// allows it. A file that exists but cannot be read is always a panic.
pub fn repo_read_or_skip(rel: &str) -> Option<String> {
    let p = repo_file_or_skip(rel)?;
    Some(std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{} unreadable: {e}", p.display())))
}

/// Line numbers (1-based) at which `src` builds a path OUTSIDE this crate from
/// `CARGO_MANIFEST_DIR` by hand: the macro followed, within the same
/// statement, by `.parent()`, a `".."` segment, or a `../` in a path string.
/// Whitespace is ignored so a chained call split across lines still counts.
pub fn hand_built_repo_reads(src: &str) -> Vec<usize> {
    const NEEDLE: &str = "env!(\"CARGO_MANIFEST_DIR\")";
    let mut hits = Vec::new();
    for (at, _) in src.match_indices(NEEDLE) {
        let rest = &src[at + NEEDLE.len()..];
        let stmt = rest.split(';').next().unwrap_or("");
        let stmt: String = stmt.chars().take(400).filter(|c| !c.is_whitespace()).collect();
        if stmt.contains(".parent()") || stmt.contains("\"..\"") || stmt.contains("../") {
            hits.push(src[..at].matches('\n').count() + 1);
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-test-support-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_present_file_is_found_in_either_mode() {
        let d = scratch("present");
        std::fs::write(d.join("x.txt"), "x").unwrap();
        assert_eq!(lookup(&d, "x.txt", false), Ok(Some(d.join("x.txt"))));
        assert_eq!(lookup(&d, "x.txt", true), Ok(Some(d.join("x.txt"))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_file_may_skip_outside_the_harness() {
        let d = scratch("skip");
        assert_eq!(lookup(&d, "nope.txt", false), Ok(None));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_missing_file_fails_under_the_harness_and_names_the_path() {
        let d = scratch("fail");
        let err = lookup(&d, "nope.txt", true).unwrap_err();
        assert!(err.contains("nope.txt") && err.contains(HARNESS_VAR), "{err}");
        assert!(err.contains(&d.display().to_string()), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_real_repo_root_holds_the_workspace() {
        // Under the harness this is the proof the repo root is mounted; the
        // same check would otherwise be a skip somewhere else.
        let root = repo_root();
        assert!(root.join("noo-cli/Cargo.toml").is_file(), "{} is not the repo root", root.display());
    }

    // The scanner is only worth anything if it matches the shapes the code
    // really has, so each fixture is a verbatim copy of one (real newlines and
    // indentation, not a '\n'-joined approximation).
    #[test]
    fn the_scanner_matches_every_real_shape() {
        let one_line = "let root = std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")).parent().unwrap();\n";
        assert_eq!(hand_built_repo_reads(one_line), vec![1]);

        let multi_line = "fn t() {\n        let main_tsx = std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\"))\n            .parent()\n            .unwrap()\n            .join(\"ui/x.tsx\");\n}\n";
        assert_eq!(hand_built_repo_reads(multi_line), vec![2]);

        let join_dotdot = "    Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"..\").join(\"gateway-rust\")\n";
        assert_eq!(hand_built_repo_reads(join_dotdot), vec![1]);

        let join_path = "let c = std::fs::read_to_string(Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"../docker-compose.cluster.yml\")).unwrap();\n";
        assert_eq!(hand_built_repo_reads(join_path), vec![1]);

        let concat = "let p = concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../docker-compose.cluster.yml\");\n";
        assert_eq!(hand_built_repo_reads(concat), vec![1]);

        let two = format!("{one_line}\n{concat}");
        assert_eq!(hand_built_repo_reads(&two), vec![1, 3]);
    }

    #[test]
    fn the_scanner_leaves_in_crate_reads_alone() {
        let in_crate = "let a = std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\"))\n    .join(\"src/commands/kiosk_assets/noo-kiosk-serve\");\nlet b = x.parent().unwrap();\n";
        assert!(hand_built_repo_reads(in_crate).is_empty());
        assert!(hand_built_repo_reads("let s = Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"src\");").is_empty());
    }

    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                collect(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// Ratchet: no file under src/ outside this one rebuilds a repo path from
    /// `CARGO_MANIFEST_DIR`. Such a read has no harness rule: it skips or
    /// unwraps by accident, and the next author copies whichever they saw.
    #[test]
    fn no_test_builds_a_repo_path_by_hand() {
        let mut files = Vec::new();
        collect(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        assert!(files.len() > 20, "scanner found only {} files under src/", files.len());
        let mut offenders = Vec::new();
        for f in &files {
            if f.file_name().is_some_and(|n| n == "test_support.rs") {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            for line in hand_built_repo_reads(&src) {
                offenders.push(format!("{}:{line}", f.display()));
            }
        }
        assert!(
            offenders.is_empty(),
            "use crate::test_support::{{repo_file, repo_file_or_skip, repo_root}} instead of \
             building a path outside the crate from CARGO_MANIFEST_DIR:\n{}",
            offenders.join("\n")
        );
    }
}
