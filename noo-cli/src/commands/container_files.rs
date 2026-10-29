// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Which of a few named files exist inside a container — a stat, never a
//! read, and bounded in time.
//!
//! `noo security secrets audit` asks one question per delivered secret: is
//! `/run/secrets/<target>` in its consumer? It used to answer with
//! `docker diff`, which walks the container's whole filesystem against its
//! image. Under the containerd image store that walk is not proportional to
//! anything the audit cares about: in the stack-v0.2.81 rehearsal it took the
//! audit from a few seconds to ~111 s, and on host3 a 58 MB redis container
//! with nothing in its writable layer took 122 s. `noo cluster verify
//! --controller` runs the audit as a subprocess, so it paid the same.
//!
//! The answer now comes from the docker API's path stat —
//! `HEAD /containers/<c>/archive?path=<p>` — over the same unix socket the
//! docker CLI uses: a status line per path (200 present, 404 absent), no
//! file content, milliseconds each. It sees the file however it got there
//! (compose's copied-in `environment:` secret or a bind-mounted `file:` one).
//! Distroless containers have no `stat` binary, so `docker exec` cannot ask.
//!
//! When the socket is not a local unix socket (a tcp/ssh `DOCKER_HOST`, or no
//! permission), the old `docker diff` (plus `.Mounts`, for bind-mounted secret
//! files, which a diff never lists) still answers — but in parallel, under
//! one shared deadline. Either way, a container the budget did not reach is
//! [`Probe::Unchecked`], which the audit reports as "not checked", never as a
//! pass.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The whole probe — every container, every path — finishes inside this.
pub(crate) const BUDGET: Duration = Duration::from_secs(20);
/// One API request never waits longer than this, budget permitting.
const PER_REQUEST: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Probe {
    /// No such container here — nothing to judge (an add-on that is off).
    Absent,
    /// Every asked path was judged; these are the ones present.
    Checked(Vec<String>),
    /// Not judged, and why. Never a pass.
    Unchecked(String),
}

/// For each container, which of its `paths` exist — by the docker API's
/// stat when the socket is local, else by a bounded, parallel `docker diff`.
pub(crate) fn probe(wanted: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, Probe> {
    let deadline = Instant::now() + BUDGET;
    if let Some(sock) = docker_socket().filter(|s| UnixStream::connect(s).is_ok()) {
        return probe_via_api(&sock, wanted, deadline);
    }
    probe_via_diff("docker", wanted, deadline)
}

/// The unix socket the docker CLI would talk to, or None when it talks to
/// something else (tcp, ssh) or cannot say.
fn docker_socket() -> Option<PathBuf> {
    let host = match std::env::var("DOCKER_HOST") {
        Ok(h) if !h.trim().is_empty() => h,
        _ => {
            let out = Command::new("docker")
                .args(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"])
                .stderr(Stdio::null())
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
    };
    host.strip_prefix("unix://").map(PathBuf::from)
}

/// Stat each path through `sock`. `/` first: a 404 there means the
/// container is not here, which a 404 on a secret path cannot tell apart
/// from a missing file.
pub(crate) fn probe_via_api(sock: &Path, wanted: &BTreeMap<String, Vec<String>>, deadline: Instant) -> BTreeMap<String, Probe> {
    let mut out = BTreeMap::new();
    for (container, paths) in wanted {
        let stat = |p: &str| head(sock, &format!("/containers/{}/archive?path={}", encode(container), encode(p)), deadline);
        let probe = match stat("/") {
            Ok(404) => Probe::Absent,
            Ok(200) => {
                let mut present = Vec::new();
                let mut failed = None;
                for p in paths {
                    match stat(p) {
                        Ok(200) => present.push(p.clone()),
                        Ok(404) => {}
                        Ok(code) => failed = Some(format!("the docker API answered {code} for a stat")),
                        Err(e) => failed = Some(e),
                    }
                    if failed.is_some() {
                        break;
                    }
                }
                match failed {
                    Some(why) => Probe::Unchecked(why),
                    None => Probe::Checked(present),
                }
            }
            Ok(code) => Probe::Unchecked(format!("the docker API answered {code} for the container")),
            Err(e) => Probe::Unchecked(e),
        };
        out.insert(container.clone(), probe);
    }
    out
}

/// One `HEAD` over the socket; the status code, or why there is none. Only
/// the status line is read — a HEAD carries no body.
fn head(sock: &Path, target: &str, deadline: Instant) -> Result<u16, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(format!("the audit's {}s budget ran out first", BUDGET.as_secs()));
    }
    let t = left.min(PER_REQUEST);
    let mut s = UnixStream::connect(sock).map_err(|e| format!("docker socket: {e}"))?;
    let _ = s.set_read_timeout(Some(t));
    let _ = s.set_write_timeout(Some(t));
    s.write_all(format!("HEAD {target} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| format!("docker socket: {e}"))?;
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while got.len() < 12 {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(format!("the docker API did not answer within {}s", t.as_secs().max(1)))
            }
            Err(e) => return Err(format!("docker socket: {e}")),
        }
    }
    // "HTTP/1.1 200 OK"
    std::str::from_utf8(got.get(9..12).unwrap_or_default())
        .ok()
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| "the docker API sent no status line".to_string())
}

/// Percent-encode a container name or path for the query string.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Destinations of a container's mounts (`docker inspect`), empty when the
/// inspect fails: the caller then falls back to what `docker diff` listed.
fn mount_destinations(docker: &str, container: &str) -> Vec<String> {
    Command::new(docker)
        .args(["inspect", "-f", "{{range .Mounts}}{{println .Destination}}{{end}}", container])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// The fallback: `docker diff` for every container at once, each killed at
/// `deadline`. A diff that fails is a container not here (the old
/// behaviour); one still running at the deadline is Unchecked.
pub(crate) fn probe_via_diff(docker: &str, wanted: &BTreeMap<String, Vec<String>>, deadline: Instant) -> BTreeMap<String, Probe> {
    let mut out = BTreeMap::new();
    let mut running: Vec<(&String, &Vec<String>, Child, JoinHandle<String>)> = Vec::new();
    for (container, paths) in wanted {
        let spawned = Command::new(docker).args(["diff", container]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
        match spawned {
            Ok(mut child) => {
                let mut stdout = child.stdout.take().expect("piped");
                let reader = std::thread::spawn(move || {
                    let mut s = String::new();
                    let _ = stdout.read_to_string(&mut s);
                    s
                });
                running.push((container, paths, child, reader));
            }
            // Could not run `docker diff` at all: nothing was checked, so
            // this is not evidence the file is absent. (A test that writes its
            // fake CLI and execs it at once can also hit ETXTBSY here when a
            // concurrent fork briefly holds the write fd — the old Absent
            // turned that race into a false "file missing".)
            Err(e) => {
                out.insert(container.clone(), Probe::Unchecked(format!("`docker diff` could not be run: {e}")));
            }
        }
    }
    loop {
        let done = running.iter_mut().all(|(_, _, c, _)| matches!(c.try_wait(), Ok(Some(_))));
        if done || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    for (container, paths, mut child, reader) in running {
        let status = match child.try_wait() {
            Ok(Some(st)) => Some(st),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                None
            }
        };
        // A killed diff's reader is left to finish on its own: a grandchild
        // could still hold the pipe, and waiting on it is the unbounded wait.
        let probe = match status {
            None => Probe::Unchecked(format!("`docker diff` did not finish within the audit's {}s budget", BUDGET.as_secs())),
            Some(st) if !st.success() => Probe::Absent,
            Some(_) => {
                let text = reader.join().unwrap_or_default();
                let added: Vec<&str> = text.lines().filter_map(|l| l.strip_prefix("A ")).collect();
                // A secret file the launcher bind-mounts from tmpfs (the
                // `file:` delivery) is a MOUNT, not a layer change: `docker
                // diff` never lists it. Its destination is in `.Mounts`.
                let mounted = mount_destinations(docker, container);
                Probe::Checked(
                    paths
                        .iter()
                        .filter(|p| added.contains(&p.as_str()) || mounted.iter().any(|m| m == p.as_str()))
                        .cloned()
                        .collect(),
                )
            }
        };
        out.insert(container.clone(), probe);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("noo-cfiles-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A fake docker daemon: answers each HEAD .../archive?path=P with 200
    /// when `container` is known and P is `/` or in `files`, else 404.
    /// `stall` holds every answer back (a daemon under load).
    pub(crate) fn fake_daemon(name: &str, containers: &[(&str, &[&str])], stall: Option<Duration>) -> PathBuf {
        let sock = scratch(name).join("docker.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let known: BTreeMap<String, Vec<String>> =
            containers.iter().map(|(c, fs)| (c.to_string(), fs.iter().map(|f| f.to_string()).collect())).collect();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { continue };
                let mut req = Vec::new();
                let mut buf = [0u8; 512];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&req).lines().next().unwrap_or_default().to_string();
                let target = line.split(' ').nth(1).unwrap_or_default();
                let (c, p) = target
                    .strip_prefix("/containers/")
                    .and_then(|r| r.split_once("/archive?path="))
                    .unwrap_or_default();
                let ok = known.get(c).is_some_and(|fs| p == "/" || fs.iter().any(|f| f == p));
                if let Some(d) = stall {
                    std::thread::sleep(d);
                }
                let _ = conn.write_all(if ok { b"HTTP/1.1 200 OK\r\n\r\n" } else { b"HTTP/1.1 404 Not Found\r\n\r\n" });
            }
        });
        sock
    }

    /// A fake `docker` CLI whose `diff` prints `added` after `sleep` seconds.
    pub(crate) fn fake_docker_cli(name: &str, added: &[&str], sleep: u32) -> PathBuf {
        let bin = scratch(name).join("docker");
        let lines: String = added.iter().map(|a| format!("echo 'A {a}'\n")).collect();
        crate::test_exec::write_exec(&bin, format!("#!/bin/sh\n[ \"$1\" = diff ] || exit 1\nsleep {sleep}\n{lines}"), 0o755);
        bin
    }

    /// A bind-mounted secret file is in `.Mounts`, never in `docker diff`: the
    /// fallback must not call it missing.
    #[test]
    fn the_diff_fallback_counts_a_bind_mounted_secret_as_present() {
        let bin = scratch("mounts").join("docker");
        // i277j: a plain write + chmod raced a sibling test's fork (ETXTBSY).
        crate::test_exec::write_exec(
            &bin,
            "#!/bin/sh\ncase \"$1\" in diff) echo 'A /tmp/x';; inspect) echo /run/secrets/redis_password;; *) exit 1;; esac\n",
            0o755,
        );
        let got = probe_via_diff(
            bin.to_str().unwrap(),
            &want("noo-redis", &["/run/secrets/redis_password", "/run/secrets/other"]),
            Instant::now() + BUDGET,
        );
        assert_eq!(got["noo-redis"], Probe::Checked(vec!["/run/secrets/redis_password".to_string()]));
    }

    #[test]
    fn a_docker_cli_that_cannot_be_run_is_unchecked_not_absent() {
        let got = probe_via_diff(
            "/nonexistent/noo-test-docker",
            &want("noo-redis", &["/run/secrets/redis_password"]),
            Instant::now() + BUDGET,
        );
        match &got["noo-redis"] {
            Probe::Unchecked(why) => assert!(why.contains("could not be run"), "{why}"),
            other => panic!("a spawn failure checked nothing, so it must be Unchecked, got {other:?}"),
        }
    }

    fn want(c: &str, paths: &[&str]) -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([(c.to_string(), paths.iter().map(|p| p.to_string()).collect())])
    }

    #[test]
    fn the_api_stat_sees_a_planted_file_and_not_a_missing_one() {
        let sock = fake_daemon("api", &[("noo-gateway", &["/run/secrets/noo_jwt_secret"])], None);
        let got = probe_via_api(
            &sock,
            &want("noo-gateway", &["/run/secrets/noo_jwt_secret", "/run/secrets/redis_password"]),
            Instant::now() + BUDGET,
        );
        assert_eq!(got["noo-gateway"], Probe::Checked(vec!["/run/secrets/noo_jwt_secret".into()]));
        let got = probe_via_api(&sock, &want("noo-evolve", &["/run/secrets/x"]), Instant::now() + BUDGET);
        assert_eq!(got["noo-evolve"], Probe::Absent);
    }

    #[test]
    fn a_daemon_that_does_not_answer_in_time_is_unchecked() {
        let sock = fake_daemon("stall", &[("noo-gateway", &["/run/secrets/noo_jwt_secret"])], Some(Duration::from_secs(3)));
        let t = Instant::now();
        let got = probe_via_api(&sock, &want("noo-gateway", &["/run/secrets/noo_jwt_secret"]), Instant::now() + Duration::from_millis(300));
        assert!(matches!(&got["noo-gateway"], Probe::Unchecked(_)), "{got:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "the deadline was not honoured: {:?}", t.elapsed());
    }

    #[test]
    fn a_diff_that_outlives_the_deadline_is_unchecked_and_killed() {
        let docker = fake_docker_cli("slowdiff", &["/run/secrets/noo_jwt_secret"], 30);
        let t = Instant::now();
        let got = probe_via_diff(
            docker.to_str().unwrap(),
            &want("noo-gateway", &["/run/secrets/noo_jwt_secret"]),
            Instant::now() + Duration::from_millis(300),
        );
        assert!(matches!(&got["noo-gateway"], Probe::Unchecked(why) if why.contains("did not finish")), "{got:?}");
        assert!(t.elapsed() < Duration::from_secs(5), "the diff was waited on: {:?}", t.elapsed());
    }

    #[test]
    fn a_diff_inside_the_deadline_reports_the_planted_file() {
        let docker = fake_docker_cli("fastdiff", &["/run/secrets/noo_jwt_secret", "/tmp/x"], 0);
        let got = probe_via_diff(
            docker.to_str().unwrap(),
            &want("noo-gateway", &["/run/secrets/noo_jwt_secret", "/run/secrets/redis_password"]),
            Instant::now() + BUDGET,
        );
        assert_eq!(got["noo-gateway"], Probe::Checked(vec!["/run/secrets/noo_jwt_secret".into()]));
    }

    #[test]
    fn encode_leaves_names_and_paths_alone_and_escapes_the_rest() {
        assert_eq!(encode("/run/secrets/noo_jwt_secret"), "/run/secrets/noo_jwt_secret");
        assert_eq!(encode("a b&c"), "a%20b%26c");
    }
}
