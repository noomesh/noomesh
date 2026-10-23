// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The ONE owner of three host questions: "is this binary here", "what did
//! it say when I ran it", and "what time is it" (i191 D3).
//!
//! Before this module the crate answered the first question four ways
//! (a file test, an exec-bit test, a symlink-tolerant test, and a shell
//! `command -v` with the name pasted into the script) and the second two
//! ways with opposite rules for a non-zero exit. The second pair produced a
//! live wrong row: a masked systemd unit prints its answer AND exits 1, and
//! a helper that read "non-zero" as "no answer" reported the unit as not
//! masked. So the result type here has THREE arms, not two:
//!
//! * [`Outcome::Absent`]: the binary is not there (not on PATH, or the spawn
//!   failed with NotFound). Nothing ran.
//! * [`Outcome::Failed`]: it ran and exited non-zero (or was killed, `code`
//!   is then None). Its stdout and stderr are kept, because for some tools
//!   (`systemctl is-enabled`, `is-active`) the exit status is part of the
//!   answer and stdout is the rest of it. A spawn that failed for a reason
//!   other than NotFound (permission denied) also lands here with
//!   `code: None` and the OS error in `stderr`.
//! * [`Outcome::Ok`]: exit zero; the payload is stdout, trimmed.
//!
//! A caller that wants "stdout whatever the status" matches `Ok` and
//! `Failed` together; a caller that wants "only a clean run" matches `Ok`
//! alone. Neither is the default, which is the point.

use std::path::PathBuf;
use std::process::Command;

/// What running a command told us. See the module header for the contract.
/// `code` and `stderr` are for callers that need them (and the tests); not
/// every caller reads every field.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The binary is not on PATH / the spawn failed with NotFound.
    Absent,
    /// It ran and exited non-zero (`code: None` = killed by a signal, or a
    /// spawn failure that was not NotFound). Streams are trimmed.
    Failed { code: Option<i32>, stdout: String, stderr: String },
    /// Exit zero; stdout, trimmed.
    Ok(String),
}

impl Outcome {
    /// stdout when the command ran to completion, WHATEVER its exit status;
    /// None only when nothing ran (absent) or it could not be started.
    pub fn any_stdout(&self) -> Option<&str> {
        match self {
            Outcome::Ok(s) => Some(s),
            Outcome::Failed { code: Some(_), stdout, .. } => Some(stdout),
            _ => None,
        }
    }

    /// stdout only for a clean (exit zero) run.
    pub fn ok_stdout(&self) -> Option<&str> {
        match self {
            Outcome::Ok(s) => Some(s),
            _ => None,
        }
    }
}

/// First executable regular file called `bin` on `$PATH`, or None.
///
/// The rule, in one place: PATH is split by the platform's own separator, an
/// EMPTY entry is skipped (it would mean "the current directory", which is
/// not a place to find a tool), a name containing `/` is checked as a path
/// as given, symlinks are followed (a dangling link is not a binary), and
/// the file must have an execute bit. No shell is involved, so the name is
/// never interpreted.
pub fn which(bin: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    if bin.is_empty() {
        return None;
    }
    let is_exec = |p: &std::path::Path| {
        std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    };
    if bin.contains('/') {
        let p = PathBuf::from(bin);
        return if is_exec(&p) { Some(p) } else { None };
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).filter(|d| !d.as_os_str().is_empty()).map(|d| d.join(bin)).find(|p| is_exec(p))
}

/// Run an already-built command and classify the result. The shared core of
/// [`run`] and [`run_sh`]; callers that need an env override or a cwd build
/// the `Command` themselves and hand it here.
pub fn run_cmd(cmd: &mut Command) -> Outcome {
    match cmd.output() {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if o.status.success() {
                Outcome::Ok(stdout)
            } else {
                Outcome::Failed {
                    code: o.status.code(),
                    stdout,
                    stderr: String::from_utf8_lossy(&o.stderr).trim().to_string(),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Absent,
        Err(e) => Outcome::Failed { code: None, stdout: String::new(), stderr: e.to_string() },
    }
}

/// Run `cmd args...` directly (no shell; arguments are never re-parsed).
/// The preferred form for new callers; the existing shell-string callers
/// still go through [`run_sh`].
#[allow(dead_code)]
pub fn run(cmd: &str, args: &[&str]) -> Outcome {
    run_cmd(Command::new(cmd).args(args))
}

/// Run `script` under `bash -c`, for the few callers that need a pipeline or
/// a redirect. A command that is missing INSIDE the script is `Failed` (bash
/// exits 127), not `Absent`: only a missing bash is absent. Prefer [`run`].
pub fn run_sh(script: &str) -> Outcome {
    run_cmd(Command::new("bash").arg("-c").arg(script))
}

/// Seconds since the Unix epoch, now. A clock before 1970 reads 0 rather
/// than panicking.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_a_binary_that_exists_and_not_one_that_does_not() {
        let sh = which("sh").expect("sh is on PATH in any test environment");
        assert!(sh.is_absolute() && sh.is_file(), "{sh:?}");
        assert_eq!(which("noo-definitely-not-a-binary-9f3a"), None);
        assert_eq!(which(""), None);
    }

    #[test]
    fn which_requires_an_exec_bit_and_treats_the_name_as_data() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("noo-hostexec-{}-{}", std::process::id(), now_unix()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plainfile");
        std::fs::write(&plain, "x").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        // A path-shaped name is checked as given: not executable -> None.
        assert_eq!(which(plain.to_str().unwrap()), None);
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(which(plain.to_str().unwrap()), Some(plain.clone()));
        // Shell metacharacters in a name are never interpreted.
        assert_eq!(which("sh; echo pwned"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_tells_ok_failed_and_absent_apart() {
        assert_eq!(run("true", &[]), Outcome::Ok(String::new()));
        match run("false", &[]) {
            Outcome::Failed { code, .. } => assert_eq!(code, Some(1)),
            other => panic!("false must be Failed, got {other:?}"),
        }
        assert_eq!(run("noo-definitely-not-a-binary-9f3a", &[]), Outcome::Absent);
        assert_eq!(run("echo", &["  hi  "]), Outcome::Ok("hi".into()));
    }

    #[test]
    fn a_failed_run_keeps_the_answer_it_printed() {
        // The masked-unit shape: an answer on stdout AND a non-zero exit.
        let o = run_sh("echo masked; echo why >&2; exit 1");
        assert_eq!(
            o,
            Outcome::Failed { code: Some(1), stdout: "masked".into(), stderr: "why".into() }
        );
        assert_eq!(o.any_stdout(), Some("masked"));
        assert_eq!(o.ok_stdout(), None);
        assert_eq!(run_sh("echo fine").ok_stdout(), Some("fine"));
        assert_eq!(Outcome::Absent.any_stdout(), None);
        // A missing command inside a script is a failed run, not an absent bash.
        assert!(matches!(run_sh("noo-definitely-not-a-binary-9f3a"), Outcome::Failed { code: Some(127), .. }));
    }

    #[test]
    fn now_unix_is_recent_and_does_not_go_backwards() {
        let a = now_unix();
        let b = now_unix();
        assert!(a > 1_700_000_000, "{a}");
        assert!(b >= a);
    }
}
