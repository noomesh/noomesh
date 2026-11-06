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
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

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

/// The deadline every production caller gives `nvidia-smi` (i425).
pub const SMI_DEADLINE: Duration = Duration::from_secs(5);

/// What a deadline-bound `nvidia-smi` told us.
#[derive(Debug)]
pub enum SmiAnswer {
    /// It finished within the deadline (any exit status; read `status`).
    Done(Output),
    /// It did not answer in time. On WSL2 a Windows program loading the GPU
    /// blocks `nvidia-smi` in the dxg driver, uninterruptibly (11 minutes
    /// measured). A driver is there; it is not answering now.
    Busy,
    /// No runnable `nvidia-smi` on this host.
    Absent,
}

/// Run `nvidia-smi args...` and stop WAITING after `deadline`. A signal alone
/// is not a deadline: the child can sit in an uninterruptible driver call, and
/// anything that waits for it (GNU `timeout` did, 665 s) is stuck with it.
pub fn nvidia_smi_within(deadline: Duration, args: &[&str]) -> SmiAnswer {
    run_within("nvidia-smi", deadline, args)
}

/// [`nvidia_smi_within`] for any program. Stdin is null; stdout and stderr are
/// drained on threads so a full pipe cannot block the child. On timeout the
/// child is killed and handed to a detached reaper thread, and we return
/// `Busy` WITHOUT calling `wait` or joining the drain threads (the pipes may
/// be held open by a child that never dies).
fn run_within(program: &str, deadline: Duration, args: &[&str]) -> SmiAnswer {
    use std::sync::mpsc;
    fn drain<R: std::io::Read + Send + 'static>(r: Option<R>) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut buf);
            }
            let _ = tx.send(buf);
        });
        rx
    }
    let mut child = match Command::new(program).args(args)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
    {
        Ok(c) => c,
        // NotFound, or present but not runnable: either way nothing answered.
        Err(_) => return SmiAnswer::Absent,
    };
    let out_rx = drain(child.stdout.take());
    let err_rx = drain(child.stderr.take());
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Exited: the pipes close with it unless a grandchild holds
                // them, so give the drains a short, bounded time.
                let grace = Duration::from_secs(1);
                let stdout = out_rx.recv_timeout(grace).unwrap_or_default();
                let stderr = err_rx.recv_timeout(grace).unwrap_or_default();
                return SmiAnswer::Done(Output { status, stdout, stderr });
            }
            Ok(None) if start.elapsed() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                // Reap it if it ever exits; nothing here waits for that.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return SmiAnswer::Busy;
            }
        }
    }
}

/// Is there an NVIDIA GPU here, as far as `nvidia-smi` can say in time?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuProbe {
    Present,
    /// A driver is there and did not answer within the deadline.
    Busy,
    Missing,
}

/// Pure: classify an answer. A tool that ran and failed is "no GPU".
pub fn classify_gpu(a: &SmiAnswer) -> GpuProbe {
    match a {
        SmiAnswer::Done(o) if o.status.success() => GpuProbe::Present,
        SmiAnswer::Done(_) | SmiAnswer::Absent => GpuProbe::Missing,
        SmiAnswer::Busy => GpuProbe::Busy,
    }
}

/// Pure: does the GPU choice stay GPU? Busy keeps it (a stuck driver is not
/// an absent one).
pub fn gpu_kept(p: GpuProbe) -> bool {
    matches!(p, GpuProbe::Present | GpuProbe::Busy)
}

/// Probe with the standard deadline; a Busy answer prints [`busy_line`] once
/// to stderr, ending in `choice` (what the caller does about it).
pub fn probe_gpu(choice: &str) -> GpuProbe {
    let p = classify_gpu(&nvidia_smi_within(SMI_DEADLINE, &[]));
    if p == GpuProbe::Busy {
        eprintln!("  {}", busy_line(choice));
    }
    p
}

/// The one line every site prints when `nvidia-smi` is busy.
pub fn busy_line(choice: &str) -> String {
    format!(
        "nvidia-smi did not answer within {} s (on WSL2 a Windows program using the GPU does this): {choice}",
        SMI_DEADLINE.as_secs()
    )
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

    /// A script `body` under a per-process scratch dir; returns its path. It
    /// is run as `sh <path>` and never exec'd (a just-written file can hit
    /// ETXTBSY when another test forks).
    fn fake(name: &str, body: &str) -> String {
        let dir = std::env::temp_dir().join(format!("noo-host-exec-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("nvidia-smi");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn a_stuck_program_is_busy_within_the_deadline_and_not_waited_for() {
        let p = fake("smi-slow", "sleep 30");
        let t = Instant::now();
        let a = run_within("sh", Duration::from_millis(300), &[p.as_str()]);
        assert!(matches!(a, SmiAnswer::Busy), "{a:?}");
        assert!(t.elapsed() < Duration::from_millis(300) + Duration::from_secs(2), "{:?}", t.elapsed());
    }

    #[test]
    fn a_fast_program_is_done_with_its_output_and_status() {
        let p = fake("smi-fast", "echo GPU 0: fake; echo oops >&2; exit 3");
        match run_within("sh", Duration::from_secs(5), &[p.as_str()]) {
            SmiAnswer::Done(o) => {
                assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "GPU 0: fake");
                assert_eq!(String::from_utf8_lossy(&o.stderr).trim(), "oops");
                assert_eq!(o.status.code(), Some(3));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_large_output_does_not_block_on_a_full_pipe() {
        let p = fake("smi-big", "yes x | head -c 300000");
        match run_within("sh", Duration::from_secs(5), &[p.as_str()]) {
            SmiAnswer::Done(o) => assert_eq!(o.stdout.len(), 300000),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_missing_program_is_absent() {
        let a = run_within("/nonexistent/noo-test-nvidia-smi", Duration::from_secs(1), &[]);
        assert!(matches!(a, SmiAnswer::Absent), "{a:?}");
    }

    #[test]
    fn busy_keeps_the_gpu_choice_and_a_failed_tool_does_not() {
        let slow = run_within("sh", Duration::from_millis(100), &[fake("s", "sleep 30").as_str()]);
        let bad = run_within("sh", Duration::from_secs(5), &[fake("b", "exit 9").as_str()]);
        let ok = run_within("sh", Duration::from_secs(5), &[fake("o", "exit 0").as_str()]);
        assert_eq!(classify_gpu(&slow), GpuProbe::Busy);
        assert_eq!(classify_gpu(&bad), GpuProbe::Missing);
        assert_eq!(classify_gpu(&ok), GpuProbe::Present);
        assert_eq!(classify_gpu(&SmiAnswer::Absent), GpuProbe::Missing);
        assert!(gpu_kept(GpuProbe::Busy) && gpu_kept(GpuProbe::Present) && !gpu_kept(GpuProbe::Missing));
    }

    #[test]
    fn the_busy_line_names_the_cause_and_the_choice() {
        let l = busy_line("taking the GPU as present");
        assert!(l.contains("did not answer within 5 s") && l.contains("Windows program") && l.ends_with("taking the GPU as present"), "{l}");
    }
}
