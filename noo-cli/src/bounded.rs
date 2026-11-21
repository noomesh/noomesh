// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! One bounded child-process runner, for the calls that touch storage that
//! can hang (i1149).
//!
//! After a power cut the controller's hard NFS mount stopped answering, and
//! `noo upgrade --all` printed `# Stack` and then sat silent for hours on a
//! bare `docker inspect noo-gateway` whose container binds that mount. A
//! plain `Command::output()` waits as long as the child lives, and a child
//! blocked on a dead hard mount lives until the server comes back. So the
//! calls that can meet such a mount run through [`run`]: spawn, wait with a
//! deadline, kill on expiry, and say which of the three things happened
//! ([`Bounded`]).
//!
//! The same module reads `/proc/self/mountinfo` for the network mounts under
//! the data roots and probes them with a child `stat` (never an in-process
//! `metadata()`, which blocks the calling thread in D state): the upgrade's
//! early refusal and the `network mount` verify row share it.

use std::io;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// What a bounded run came to.
#[derive(Debug)]
pub(crate) enum Bounded {
    /// The child ran to its end inside the bound (its exit status may still
    /// be a failure: that is an answer, not a hang).
    Answered(Output),
    /// The bound passed first; the child was sent SIGKILL.
    TimedOut { secs: u64 },
    /// The program could not be started, or its output could not be read.
    SpawnFailed(io::Error),
}

/// Run `cmd` for at most `limit`. stdin is closed; stdout and stderr are
/// captured. On expiry the child is killed and [`Bounded::TimedOut`] returned.
///
/// A process stuck in D state (blocked in the kernel on a dead hard mount)
/// cannot be killed until the mount answers, so this never waits for the
/// child to go away after the kill: the thread that owns the child does the
/// reaping, detached, whenever the child finally exits. The caller gets its
/// answer at the deadline either way, and the pid is not reused meanwhile
/// because that thread has not reaped it yet.
pub(crate) fn run(cmd: &mut Command, limit: Duration) -> Bounded {
    let child = match cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => return Bounded::SpawnFailed(e),
    };
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // wait_with_output drains both pipes while it waits, so a chatty
        // child never blocks on a full pipe.
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(limit) {
        Ok(Ok(out)) => Bounded::Answered(out),
        Ok(Err(e)) => Bounded::SpawnFailed(e),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // SAFETY: kill(2) on the pid of our own un-reaped child.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            Bounded::TimedOut { secs: limit.as_secs() }
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Bounded::SpawnFailed(io::Error::new(io::ErrorKind::Other, "the waiting thread ended without an answer"))
        }
    }
}

/// `docker <args>` through [`run`].
pub(crate) fn docker(args: &[&str], limit: Duration) -> Bounded {
    run(Command::new("docker").args(args), limit)
}

/// A child `stat <path>` through [`run`]: whether the path answers at all.
/// A missing path is an answer (a failed exit); only a hang is `TimedOut`.
pub(crate) fn stat(path: &str, limit: Duration) -> Bounded {
    run(Command::new("stat").arg(path), limit)
}

/// The bound on a stat of a mount (the upgrade's refusal and the verify row).
pub(crate) const STAT_SECS: u64 = 5;
/// The bound on `docker inspect` of the gateway.
pub(crate) const INSPECT_SECS: u64 = 30;

// ── network mounts ──────

/// Filesystem types served by another machine: a stat of a path on one can
/// block for as long as that machine is away.
const NETWORK_FS: [&str; 6] = ["nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs"];

/// One line of `/proc/self/mountinfo`, reduced to what is judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mount {
    pub point: String,
    pub fstype: String,
    /// The device / server field (`server:/export` for NFS).
    pub source: String,
}

impl Mount {
    pub(crate) fn is_network(&self) -> bool {
        NETWORK_FS.contains(&self.fstype.as_str())
    }

    /// `/srv/noo (nfs4 from server:/export)`.
    pub(crate) fn describe(&self) -> String {
        format!("{} ({} from {})", self.point, self.fstype, self.source)
    }

    fn holds(&self, path: &str) -> bool {
        self.point == "/" || path == self.point || path.starts_with(&format!("{}/", self.point))
    }
}

fn unescape(s: &str) -> String {
    s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
}

/// Every mount in a `/proc/self/mountinfo` table.
pub(crate) fn parse_mounts(mountinfo: &str) -> Vec<Mount> {
    let mut out = Vec::new();
    for line in mountinfo.lines() {
        let Some((pre, post)) = line.split_once(" - ") else { continue };
        let Some(point) = pre.split(' ').nth(4).map(unescape) else { continue };
        let mut tail = post.split(' ');
        let Some(fstype) = tail.next() else { continue };
        let source = tail.next().map(unescape).unwrap_or_default();
        out.push(Mount { point, fstype: fstype.to_string(), source });
    }
    out
}

/// What to stat and which mount it speaks for: each root that lives on a
/// network mount (the longest mount point that holds it), and each network
/// mount below a root (a mount inside the data root). One entry per path.
pub(crate) fn probes(mounts: &[Mount], roots: &[String]) -> Vec<(String, Mount)> {
    let mut out: Vec<(String, Mount)> = Vec::new();
    let mut add = |path: &str, m: &Mount| {
        if !out.iter().any(|(p, _)| p == path) {
            out.push((path.to_string(), m.clone()));
        }
    };
    for root in roots {
        let holder = mounts.iter().filter(|m| m.holds(root)).max_by_key(|m| m.point.len());
        if let Some(m) = holder.filter(|m| m.is_network()) {
            add(root, m);
        }
        for m in mounts.iter().filter(|m| m.is_network() && m.point.starts_with(&format!("{root}/"))) {
            add(&m.point, m);
        }
    }
    out
}

/// The data roots this install uses, from the environment the launcher
/// resolved (`.env` is loaded first): `NOO_DATA_ROOT`, `MODELS_DIR`,
/// `HF_CACHE_DIR`. Unset or relative values are left out.
pub(crate) fn data_roots() -> Vec<String> {
    crate::envfile::ensure_repo_env();
    env_roots()
}

/// [`data_roots`] over the environment as it already stands (a caller that
/// has run past the `.env` load, or a test, that must not load it).
pub(crate) fn env_roots() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for key in ["NOO_DATA_ROOT", "MODELS_DIR", "HF_CACHE_DIR"] {
        let v = std::env::var(key).unwrap_or_default();
        let v = v.trim().trim_end_matches('/').to_string();
        if v.starts_with('/') && !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// Stat every probe at once (so several hung mounts cost one bound, not
/// one each). `(mount, answered)`: `false` only when the stat TIMED OUT; a
/// stat that could not be started, or that failed fast, is not a hang.
pub(crate) fn probe_all(probes: &[(String, Mount)], limit: Duration) -> Vec<(Mount, bool)> {
    std::thread::scope(|s| {
        let handles: Vec<_> = probes
            .iter()
            .map(|(path, m)| {
                let h = s.spawn(move || !matches!(stat(path, limit), Bounded::TimedOut { .. }));
                (m.clone(), h)
            })
            .collect();
        handles.into_iter().map(|(m, h)| (m, h.join().unwrap_or(true))).collect()
    })
}

/// The network mounts under this machine's data roots, probed: `(mount,
/// answered)`, empty when there are none (or `/proc/self/mountinfo` cannot
/// be read, as on macOS).
pub(crate) fn probe_data_roots() -> Vec<(Mount, bool)> {
    let table = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    probe_all(&probes(&parse_mounts(&table), &data_roots()), Duration::from_secs(STAT_SECS))
}

/// The upgrade's refusal, or `None` when every network mount answered.
pub(crate) fn hung_mount_refusal(results: &[(Mount, bool)]) -> Option<String> {
    let hung: Vec<String> = results.iter().filter(|(_, answered)| !answered).map(|(m, _)| m.describe()).collect();
    if hung.is_empty() {
        return None;
    }
    Some(format!(
        "{} did not answer in {STAT_SECS} s: a hung network mount under the data roots. Bring that storage back first \
         (a hard NFS mount resumes by itself once its server answers), then rerun `noo upgrade`. Do not force-unmount it.",
        hung.join("; ")
    ))
}

/// The one line when `docker inspect <container>` itself did not answer.
/// `sources`: the data roots the gateway binds, read from the environment
/// (inspect cannot be asked, it is the call that hung).
pub(crate) fn inspect_hung_message(container: &str, secs: u64, sources: &[String]) -> String {
    let at = if sources.is_empty() { String::new() } else { format!(" ({})", sources.join(", ")) };
    format!(
        "`docker inspect {container}` did not answer in {secs} s: a mount the gateway uses may be hung{at}. Bring that storage \
         back first (a hard NFS mount resumes by itself once its server answers), then rerun `noo upgrade`. Do not force-unmount it."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const MOUNTINFO: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
40 22 0:35 / /srv/noo rw,relatime shared:60 - nfs4 filer.example:/export/noo rw,vers=4.2,hard,proto=tcp
41 22 0:36 / /mnt/share\\040one rw,relatime shared:61 - cifs //nas.example/share rw,vers=3.1.1
42 22 8:2 / /var/lib/docker rw,relatime shared:2 - ext4 /dev/sda2 rw
43 22 0:37 / /mnt/old rw,relatime - nfs filer.example:/old rw,vers=3
";

    #[test]
    fn a_child_that_outlives_its_bound_is_timed_out_and_killed() {
        let dir = std::env::temp_dir().join(format!("noo-bounded-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("pid");
        let script = format!("echo $$ > '{}'; exec sleep 5", pidfile.display());
        let t = Instant::now();
        let got = run(Command::new("sh").args(["-c", &script]), Duration::from_secs(1));
        assert!(matches!(got, Bounded::TimedOut { secs: 1 }), "{got:?}");
        assert!(t.elapsed() < Duration::from_secs(4), "returned at the bound, not when the child ended");
        let pid = std::fs::read_to_string(&pidfile).unwrap().trim().to_string();
        let gone = (0..20).any(|_| {
            std::thread::sleep(Duration::from_millis(100));
            !std::path::Path::new(&format!("/proc/{pid}")).exists()
        });
        assert!(gone, "the child {pid} was killed and reaped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_child_that_ends_in_time_is_answered_whatever_its_status() {
        match run(&mut Command::new("true"), Duration::from_secs(10)) {
            Bounded::Answered(o) => assert!(o.status.success()),
            other => panic!("{other:?}"),
        }
        match run(Command::new("sh").args(["-c", "echo out; echo err >&2; exit 3"]), Duration::from_secs(10)) {
            Bounded::Answered(o) => {
                assert_eq!(o.status.code(), Some(3));
                assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "out");
                assert_eq!(String::from_utf8_lossy(&o.stderr).trim(), "err");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_missing_program_is_a_spawn_failure_not_a_timeout() {
        let got = run(&mut Command::new("noo-no-such-program-i1149"), Duration::from_secs(10));
        assert!(matches!(got, Bounded::SpawnFailed(_)), "{got:?}");
    }

    #[test]
    fn a_stat_that_answers_is_reported_as_answered() {
        let m = Mount { point: "/".into(), fstype: "nfs4".into(), source: "filer.example:/x".into() };
        let got = probe_all(&[("/".to_string(), m.clone())], Duration::from_secs(10));
        assert_eq!(got, vec![(m, true)]);
    }

    #[test]
    fn a_missing_path_is_an_answer_for_stat() {
        let got = stat("/noo-no-such-path-i1149", Duration::from_secs(10));
        assert!(matches!(got, Bounded::Answered(_)), "{got:?}");
    }

    #[test]
    fn mountinfo_names_the_network_mounts_and_their_servers() {
        let mounts = parse_mounts(MOUNTINFO);
        assert_eq!(mounts.len(), 5);
        let nfs4 = mounts.iter().find(|m| m.point == "/srv/noo").unwrap();
        assert_eq!(nfs4.fstype, "nfs4");
        assert_eq!(nfs4.source, "filer.example:/export/noo");
        assert!(nfs4.is_network());
        assert_eq!(nfs4.describe(), "/srv/noo (nfs4 from filer.example:/export/noo)");
        assert!(!mounts.iter().find(|m| m.fstype == "ext4" && m.point == "/").unwrap().is_network());
        let cifs = mounts.iter().find(|m| m.fstype == "cifs").unwrap();
        assert_eq!(cifs.point, "/mnt/share one", "an escaped space is read back");
        assert!(cifs.is_network());
        assert!(mounts.iter().find(|m| m.point == "/mnt/old").unwrap().is_network(), "plain nfs counts too");
    }

    #[test]
    fn probes_cover_roots_on_a_network_mount_and_mounts_below_a_root() {
        let mounts = parse_mounts(MOUNTINFO);
        let roots = vec!["/srv/noo/models".to_string(), "/var/lib/docker/x".to_string()];
        let p = probes(&mounts, &roots);
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!(p[0].0, "/srv/noo/models");
        assert_eq!(p[0].1.fstype, "nfs4");
        // A mount below the root is probed at its own point.
        let p = probes(&mounts, &["/mnt".to_string()]);
        let points: Vec<&str> = p.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(points, vec!["/mnt/share one", "/mnt/old"]);
        // A root on a local filesystem has nothing to probe.
        assert!(probes(&mounts, &["/var/lib/noo".to_string()]).is_empty());
    }

    #[test]
    fn no_network_mounts_means_nothing_to_refuse() {
        let local = parse_mounts("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n");
        assert!(probes(&local, &["/var/lib/noo".to_string()]).is_empty());
        assert_eq!(hung_mount_refusal(&[]), None);
        let nfs = parse_mounts(MOUNTINFO).into_iter().find(|m| m.point == "/srv/noo").unwrap();
        assert_eq!(hung_mount_refusal(&[(nfs, true)]), None, "an answering mount is not refused");
    }

    #[test]
    fn the_refusal_names_the_mount_and_the_remedy() {
        let nfs = parse_mounts(MOUNTINFO).into_iter().find(|m| m.point == "/srv/noo").unwrap();
        let msg = hung_mount_refusal(&[(nfs, false)]).expect("a hung mount is refused");
        assert_eq!(
            msg,
            "/srv/noo (nfs4 from filer.example:/export/noo) did not answer in 5 s: a hung network mount under the data roots. \
             Bring that storage back first (a hard NFS mount resumes by itself once its server answers), then rerun `noo upgrade`. \
             Do not force-unmount it."
        );
    }

    #[test]
    fn the_inspect_timeout_message_is_one_line_with_the_bind_sources() {
        let msg = inspect_hung_message("noo-gateway", 30, &["/srv/noo".to_string(), "/srv/noo/models".to_string()]);
        assert_eq!(
            msg,
            "`docker inspect noo-gateway` did not answer in 30 s: a mount the gateway uses may be hung (/srv/noo, /srv/noo/models). \
             Bring that storage back first (a hard NFS mount resumes by itself once its server answers), then rerun `noo upgrade`. \
             Do not force-unmount it."
        );
        assert!(!msg.contains('\n'));
        assert!(!inspect_hung_message("noo-gateway", 30, &[]).contains("()"));
    }
}
