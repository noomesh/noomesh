// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The one throwaway "helper" container the CLI runs on the user's box
//! (the bind-mount probe, the data-dir chown, `cluster verify`'s `du`).
//!
//! These used to run Docker Hub's `alpine`, by tag. A default install is
//! documented to contact no Docker Hub, and an unpinned tag is a moving
//! target. The helper is now the nginx image a default install pulls anyway
//! (the `model-cache` service, profiles controller + standalone): our
//! ghcr.io mirror, by digest. It is a busybox image, so it has `touch`,
//! `chown` and `du`. Nothing here starts nginx: every run overrides the
//! entrypoint with the one binary the job needs.
//!
//! The reference is the compose file's own: the repository and tag come from
//! the `model-cache` `image:` line, the digest from this host's stack lock
//! (`nginx@sha256:` row, written by scripts/stack-lock-third-party.py) and,
//! on a host with no lock, from the `${NOO_IMAGE_DIGEST_NGINX:-@sha256:…}`
//! default on that same line. A bump of the mirrored nginx moves the stack
//! and the helper together; there is no second copy.

/// The lock row (and compose `NOO_IMAGE_DIGEST_<NAME>` hook) the helper rides.
pub(crate) const HELPER_LOCK_ROW: &str = "nginx";

/// The compose file this binary was built beside: the helper's repository,
/// tag and default digest are read from its `model-cache` service.
const COMPOSE: &str = include_str!("../../docker-compose.cluster.yml");

/// The ONE job -> capability table. Every helper container drops ALL
/// capabilities and adds back exactly the ones listed for its job; nothing
/// is ever `--privileged`. scripts/lib-helper-image.sh `helper_job_caps`
/// mirrors this table row for row (tests/test_helper_image_shell.py parses
/// both and compares). Jobs: the first three are noo-cli's own, the rest are
/// the launcher scripts'.
///
/// Where a row has a DAC_* or FOWNER cap beside CHOWN, WHY: the helper runs
/// as root inside the container, but root WITHOUT these capabilities is an
/// ordinary uid against file modes. The data dirs belong to service uids
/// (postgres 70, redis/prometheus/gateway 65532) or to the wizard's user and
/// are mode 0700/0755, so reading, entering or writing them is a DAC check.
pub(crate) const JOB_CAPS: &[(&str, &[&str], &str)] = &[
    // touch in a dir owned by the wizard's user: creating the file is a write-permission (DAC) check.
    ("touch", &["DAC_OVERRIDE"], "create a file in a dir owned by another uid"),
    // chown of the mount point only needs CHOWN: no file is read or written.
    ("chown", &["CHOWN"], "chown the mounted (empty) dir"),
    // du walks service-owned 0700 subdirs, read-only mount: search+read only.
    ("du", &["DAC_READ_SEARCH"], "read-only walk of a service-owned tree"),
    // secrets: chown each file to its container's uid, reading the manifest.
    ("secrets-chown", &["CHOWN", "DAC_READ_SEARCH"], "chown files, read the manifest they are listed in"),
    // chgrp then chmod the one noomesh.yaml: chmod on a file we do not own is FOWNER.
    ("chgrp-file", &["CHOWN", "FOWNER"], "chgrp + chmod one file owned by another uid"),
    // mkdir in the volume root (DAC write) + chown -R through 0700 dirs.
    ("data-dirs", &["CHOWN", "DAC_OVERRIDE"], "mkdir and chown -R in a volume owned by another uid"),
    // probe (find through 0700 dirs) and chown -R.
    ("reown", &["CHOWN", "DAC_OVERRIDE"], "find and chown -R through service-owned 0700 dirs"),
    // rm -rf of files in service-owned dirs, then chown the dir.
    ("wipe", &["CHOWN", "DAC_OVERRIDE"], "delete files in service-owned dirs, then chown the dir"),
];

/// The capabilities the table gives `job`. Panics on a name that is not in
/// the table: a job with no row has no business running.
fn caps_for(job: &str) -> &'static [&'static str] {
    JOB_CAPS.iter().find(|(n, ..)| *n == job).unwrap_or_else(|| panic!("no capability row for helper job {job}")).1
}

/// What the helper is asked to do. One variant per job, each with the
/// narrowest capability set that job needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Job<'a> {
    /// `touch <dir>/<marker>` in the mounted dir (bind-mount probe).
    Touch { marker: &'a str },
    /// `chown <owner> /d` on the mounted dir.
    Chown { owner: &'a str },
    /// `du -sh /d` on a read-only mount.
    Du,
}

/// `(<repo>:<tag>, default digest)` of the `model-cache` service's image line.
fn compose_ref(compose: &str) -> Option<(String, String)> {
    let line = compose.lines().find(|l| {
        let t = l.trim_start();
        t.starts_with("image: ghcr.io/noomesh/nginx:") && t.contains("${NOO_IMAGE_DIGEST_NGINX:-")
    })?;
    let img = line.trim_start().strip_prefix("image:")?.trim();
    let (repo_tag, rest) = img.split_once("${NOO_IMAGE_DIGEST_NGINX:-")?;
    let digest = rest.strip_suffix('}')?;
    let hex = digest.strip_prefix("@sha256:")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) && !repo_tag.contains('$'))
        .then(|| (repo_tag.to_string(), digest.to_string()))
}

/// The helper reference from a compose text and a stack lock's text:
/// `<repo>:<tag>@sha256:…`, always by digest. The lock's row wins; the
/// compose default is the digest a lock-less (dev) host runs the stack on.
pub(crate) fn helper_ref_from(compose: &str, lock: Option<&str>) -> Result<String, String> {
    let (repo_tag, default_digest) = compose_ref(compose)
        .ok_or_else(|| "the compose file's model-cache image line is not a pinned ghcr.io/noomesh/nginx reference".to_string())?;
    let digest = lock
        .and_then(|l| crate::commands::image_stage::parse_lock(l).into_iter().find(|r| r.name == HELPER_LOCK_ROW))
        .map(|r| format!("@{}", r.digest))
        .unwrap_or(default_digest);
    Ok(format!("{repo_tag}{digest}"))
}

/// This host's helper reference ([`helper_ref_from`] over this binary's
/// compose text and the host's `stack.lock`).
pub(crate) fn helper_ref() -> Result<String, String> {
    let lock = crate::commands::image_stage::controller_lock_opt()?.map(|(text, _, _)| text);
    helper_ref_from(COMPOSE, lock.as_deref())
}

/// The full `docker run` argv (after `docker`) for one job on one mount.
/// Every run: removed after, never pulls (`--pull never`: docker run would
/// otherwise fetch an absent image), no network, read-only root, no
/// privilege escalation, ALL capabilities dropped and only the one the job
/// needs added back, and the entrypoint replaced by the job's binary so the
/// image's own server never starts.
/// The capability set is [`JOB_CAPS`]'s row for the job.
pub(crate) fn run_argv(image: &str, mount_src: &str, job: &Job) -> Vec<String> {
    let (name, mount, bin, args): (&str, String, &str, Vec<String>) = match job {
        Job::Touch { marker } => ("touch", format!("{mount_src}:/test"), "touch", vec![format!("/test/{marker}")]),
        Job::Chown { owner } => ("chown", format!("{mount_src}:/d"), "chown", vec![(*owner).to_string(), "/d".to_string()]),
        Job::Du => ("du", format!("{mount_src}:/d:ro"), "du", vec!["-sh".to_string(), "/d".to_string()]),
    };
    let mut v: Vec<String> = ["run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for cap in caps_for(name) {
        v.push("--cap-add".into());
        v.push((*cap).to_string());
    }
    v.extend(["--security-opt", "no-new-privileges", "--entrypoint", bin, "-v"].iter().map(|s| s.to_string()));
    v.push(mount);
    v.push(image.to_string());
    v.extend(args);
    v
}

/// Is the helper image already on this host? (`docker image inspect`: never a pull.)
pub(crate) fn present(image: &str) -> bool {
    crate::onboard::sh::docker_image_exists(image)
}

/// The helper reference, pulled first if it is absent. For the install
/// path only (onboard's storage step runs before the stack images are
/// pulled; this is one of them, by the same digest, so the later pull is a
/// no-op). `cluster verify` must NOT call this.
pub(crate) fn ensure_present(progress: &mut dyn FnMut(&str)) -> Result<String, String> {
    let image = helper_ref()?;
    if !present(&image) {
        progress("Pulling the helper image (the stack's nginx, by digest)...");
        let (code, out) = crate::onboard::sh::docker(&["pull", &image]);
        if code != 0 {
            return Err(format!("could not pull {image}: {}", out.trim().lines().last().unwrap_or("")));
        }
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "caf4e1e032a20f9c3c5e28fc7f25ffd768ad8677b4975c54193075997b3a97e3";

    fn compose(d: &str) -> String {
        format!("services:\n  model-cache:\n    image: ghcr.io/noomesh/nginx:1.30.7-alpine${{NOO_IMAGE_DIGEST_NGINX:-@sha256:{d}}}\n")
    }

    #[test]
    fn the_shipped_helper_is_the_pinned_ghcr_mirror() {
        let r = helper_ref_from(COMPOSE, None).unwrap();
        assert!(r.starts_with("ghcr.io/noomesh/nginx:"), "{r}");
        let (_, d) = r.split_once("@sha256:").expect("by digest");
        assert!(d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()), "{r}");
        assert!(!r.contains("alpine:") && !r.starts_with("docker.io") && !r.starts_with("alpine"), "{r}");
    }

    #[test]
    fn the_lock_row_wins_over_the_compose_default() {
        let lock = format!("# stack v0.6.29\nnginx@sha256:{}\n", "b".repeat(64));
        assert_eq!(helper_ref_from(&compose(D), Some(&lock)).unwrap(), format!("ghcr.io/noomesh/nginx:1.30.7-alpine@sha256:{}", "b".repeat(64)));
        // a lock with no nginx row (older release) falls back to the compose digest
        assert_eq!(helper_ref_from(&compose(D), Some("# stack v0.6.1\n")).unwrap(), format!("ghcr.io/noomesh/nginx:1.30.7-alpine@sha256:{D}"));
        assert_eq!(helper_ref_from(&compose(D), None).unwrap(), format!("ghcr.io/noomesh/nginx:1.30.7-alpine@sha256:{D}"));
    }

    #[test]
    fn a_compose_without_a_pinned_digest_is_refused() {
        assert!(helper_ref_from("services:\n  model-cache:\n    image: nginx:1.30.7-alpine\n", None).is_err());
        assert!(helper_ref_from(&compose("abc"), None).is_err());
    }

    const IMG: &str = "ghcr.io/noomesh/nginx:1.30.7-alpine@sha256:aa";

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn touch_argv_is_exact() {
        assert_eq!(run_argv(IMG, "/r/noo-data", &Job::Touch { marker: ".bind-mount-ok" }), s(&[
            "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE",
            "--security-opt", "no-new-privileges", "--entrypoint", "touch", "-v", "/r/noo-data:/test", IMG, "/test/.bind-mount-ok"]));
    }

    #[test]
    fn chown_argv_is_exact() {
        assert_eq!(run_argv(IMG, "/r/pg", &Job::Chown { owner: "70:70" }), s(&[
            "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "CHOWN",
            "--security-opt", "no-new-privileges", "--entrypoint", "chown", "-v", "/r/pg:/d", IMG, "70:70", "/d"]));
    }

    #[test]
    fn du_argv_is_exact_and_read_only() {
        assert_eq!(run_argv(IMG, "noomesh_noo-data", &Job::Du), s(&[
            "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_READ_SEARCH",
            "--security-opt", "no-new-privileges", "--entrypoint", "du", "-v", "noomesh_noo-data:/d:ro", IMG, "-sh", "/d"]));
    }

    #[test]
    fn every_job_has_a_row_and_every_row_a_reason() {
        for (n, caps, why) in JOB_CAPS {
            assert!(!caps.is_empty() && !why.is_empty(), "{n}");
            assert!(caps.iter().all(|c| c.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')), "{n}: {caps:?}");
            assert!(!caps.contains(&"ALL") && !caps.contains(&"SYS_ADMIN"), "{n}: never a blanket cap");
        }
        let names: Vec<_> = JOB_CAPS.iter().map(|r| r.0).collect();
        let mut d = names.clone();
        d.dedup();
        assert_eq!(names, d);
    }

    #[test]
    fn no_job_is_privileged_or_has_a_network() {
        for job in [Job::Touch { marker: "m" }, Job::Chown { owner: "1:1" }, Job::Du] {
            let a = run_argv(IMG, "/x", &job);
            assert!(!a.iter().any(|x| x == "--privileged" || x == "host"), "{a:?}");
            assert!(a.iter().any(|x| x == "--cap-add"), "{a:?}");
            assert!(a.windows(2).any(|w| w == ["--cap-drop", "ALL"]), "{a:?}");
        }
    }

    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// No runtime path of the CLI names a Docker Hub helper image: not
    /// `alpine`, `busybox` or `hello-world` literal.
    /// Test-only code and comments are not scanned (`own_code`).
    #[test]
    fn no_runtime_path_names_a_docker_hub_image() {
        let mut files = Vec::new();
        rs_files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        assert!(files.len() > 20, "the scan found the sources");
        let mut hits = Vec::new();
        for f in files {
            let code = crate::test_src::own_code(&std::fs::read_to_string(&f).unwrap());
            for (n, line) in code.lines().enumerate() {
                let bad = ["\"alpine\"", "\"alpine:", "\"busybox", "\"hello-world"]
                    .iter().any(|m| line.contains(m));
                if bad {
                    hits.push(format!("{}:{}: {}", f.display(), n + 1, line.trim()));
                }
            }
        }
        assert!(hits.is_empty(), "a Docker Hub image on a runtime path (use crate::helper_image):\n{}", hits.join("\n"));
    }

    /// The three jobs go through the one builder; none spells its own `docker run`.
    #[test]
    fn the_three_call_sites_use_the_shared_builder() {
        for (src, f) in [(include_str!("onboard/steps.rs"), "fn ensure_dir_ownership("), (include_str!("onboard/steps.rs"), "fn verify_bind_mount("), (include_str!("commands/cluster_verify.rs"), "fn noo_data_bound_row(")] {
            let code = crate::test_src::own_code(src);
            let body = crate::test_src::fn_body(&code, f);
            assert!(body.contains("run_argv("), "{f} builds its argv with helper_image::run_argv");
            assert!(!body.contains("\"run\", \"--rm\""), "{f} spells no docker run of its own");
        }
    }
}
