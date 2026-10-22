//! Test-only: write an executable script that a test is about to exec.
//!
//! `std::fs::write` + `set_permissions` + exec races with every OTHER test
//! thread that forks: a child forked while our write fd was open inherits it
//! until its own exec closes it, and exec'ing our script in that window fails
//! `ETXTBSY` ("Text file busy", os error 26). CI hit exactly that in
//! `present_compose_reports_its_version`.
//!
//! So: write to a unique temp name beside the target, close it, set the mode,
//! rename into place, and then wait until no process still holds the file
//! open for the exec to trip on (bounded; the forks that inherited the fd
//! exec within microseconds).

use std::path::Path;

pub fn write_exec(path: &Path, body: impl AsRef<[u8]>, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let name = path.file_name().expect("script path has a file name").to_string_lossy();
    let tmp = path.with_file_name(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    // `fs::write` closes its fd before it returns; a forked sibling may still
    // hold a copy, which `wait_unopened` outlasts.
    std::fs::write(&tmp, body).expect("write script");
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).expect("chmod script");
    std::fs::rename(&tmp, path).expect("rename script into place");
    wait_unopened(path);
}

/// Block (at most ~5 s) until no process has `path` open. Reads `/proc/*/fd`,
/// which covers our own children; unreadable entries are skipped.
fn wait_unopened(path: &Path) {
    let Ok(want) = std::fs::canonicalize(path) else { return };
    for _ in 0..500 {
        if !held_open(&want) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn held_open(want: &Path) -> bool {
    let Ok(procs) = std::fs::read_dir("/proc") else { return false };
    for p in procs.flatten() {
        let n = p.file_name();
        if !n.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|t| t == want) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_exec_leaves_the_script_executable_and_no_temp_file() {
        let d = std::env::temp_dir().join(format!("noo-test-exec-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("tool");
        write_exec(&p, "#!/bin/sh\necho hi\n", 0o755);
        let out = std::process::Command::new(&p).output().expect("a fresh script execs");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hi\n");
        let left: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left.len(), 1, "only the script remains: {left:?}");
    }
}
