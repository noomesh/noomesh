// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Writing to a CHILD's stdin without dying of SIGPIPE.
//!
//! `main` restores `SIGPIPE` to its default so `noo … | head` ends quietly.
//! The same default makes a write to a child that has already exited (a
//! `docker exec` that failed fast: no such container, no permission) kill
//! THIS process silently — no message, exit status 141 — instead of
//! returning EPIPE. Every writer to a child's stdin goes through
//! [`write_child_stdin`], which ignores SIGPIPE for the duration of the
//! write and treats a broken pipe as "the child went away early": the
//! caller then waits for the child and reports ITS exit status and stderr,
//! which is the real error.

use std::io::{self, ErrorKind, Write};

/// Write `data` to a child's stdin. `Ok(())` also covers a broken pipe (the
/// child exited or closed stdin before reading everything): the child's own
/// exit status is the verdict, so callers must `wait` and report it.
/// Any other I/O error is returned.
pub fn write_child_stdin<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    // SAFETY: signal() with SIG_IGN / a previously-installed disposition.
    let prev = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let res = w.write_all(data).and_then(|()| w.flush());
    unsafe {
        libc::signal(libc::SIGPIPE, prev);
    }
    match res {
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Command;

    const MODE: &str = "NOO_TEST_CHILD_STDIN_MODE";

    /// Runs INSIDE the re-exec'd test binary, with SIGPIPE at SIG_DFL exactly
    /// as `main` leaves it. The libtest harness would otherwise hide the bug
    /// (Rust's runtime ignores SIGPIPE).
    #[test]
    fn child_mode_psql_stdin_against_a_dead_docker() {
        if std::env::var_os(MODE).is_none() {
            return;
        }
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
        // 1 MiB: far beyond the pipe buffer, so the write MUST hit the
        // closed pipe whether or not the fake docker has exited yet.
        let sql = "SELECT 1;\n".repeat(110_000);
        let r = crate::commands::secrets::psql_stdin("c", "u", "d", &sql);
        println!("RESULT: {r:?}");
    }

    #[test]
    fn a_child_that_exits_without_reading_is_an_error_not_a_signal() {
        let dir = std::env::temp_dir().join(format!("noo-child-stdin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let docker = dir.join("docker");
        std::fs::write(&docker, "#!/bin/sh\necho 'Error: No such container' >&2\nexit 1\n").unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap_or_default());
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_stdin::tests::child_mode_psql_stdin_against_a_dead_docker", "--nocapture", "--test-threads=1"])
            .env(MODE, "1")
            .env("PATH", path)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.signal(), None, "killed by a signal (SIGPIPE)?\nstdout: {stdout}");
        assert!(out.status.success(), "{:?}\n{stdout}", out.status);
        assert!(stdout.contains("psql exited 1"), "the child's exit status must be reported: {stdout}");
    }

    #[test]
    fn a_broken_pipe_is_not_an_error_but_a_real_one_is() {
        struct Broken(std::io::ErrorKind);
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(self.0.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(super::write_child_stdin(&mut Broken(std::io::ErrorKind::BrokenPipe), b"x").is_ok());
        assert!(super::write_child_stdin(&mut Broken(std::io::ErrorKind::PermissionDenied), b"x").is_err());
    }
}
