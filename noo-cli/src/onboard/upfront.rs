// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Up-front refusals: before the wizard installs, pulls or asks anything, a
//! machine that cannot be a controller is told so, with what to do instead.
//!
//! Found by the install matrix (2026-11-12, run 43154825067): on an arm64
//! Ubuntu runner the wizard ran to the end, pulled for minutes, and only then
//! failed with "the stack did not start from released images". Six controller
//! images (gateway, postgres, worker, sandbox, trellion, nvidia-exporter) are
//! published for linux/amd64 only ("no matching manifest for linux/arm64/v8").
//! On amd64 the install grew the disk by 11.5 GB before any chat model, and
//! the default model is 7.2 GB more, so a small disk is refused here too
//! instead of failing half-way through a pull.

use super::Ctx;

/// Free space the controller needs where Docker keeps its images and
/// volumes: the measured 11.5 GB of an amd64 install, the 7.2 GB default
/// model, and room for one image upgrade. `NOO_ONBOARD_MIN_FREE_GB` lowers or
/// raises it for a box whose owner knows better (a smaller model, data on
/// another disk).
pub(crate) const MIN_FREE_GB: u64 = 25;

/// Why this OS/arch cannot be a controller, or None when it can.
pub(crate) fn platform_refusal(os: &str, arch: &str) -> Option<String> {
    if os == "linux" && arch == "x86_64" {
        return None;
    }
    let what = match (os, arch) {
        ("linux", "aarch64") => "a Linux arm64 (aarch64) machine".to_string(),
        ("macos", a) => format!("a Mac ({a})"),
        (o, a) => format!("{o} on {a}"),
    };
    Some(format!(
        "this is {what}: a controller needs Linux on x86_64 (amd64) today. The controller's images \
         (gateway, postgres, worker, sandbox, trellion, nvidia-exporter) are published for amd64 only. \
         This machine can join an amd64 controller as a node instead: see \
         docs/getting-started/supported-hardware.md."
    ))
}

/// Why `free` bytes on the filesystem holding `path` are too few, or None.
/// Unknown free space (`None`) is never a refusal: no guessing.
pub(crate) fn disk_refusal(path: &str, free: Option<u64>, need_gb: u64) -> Option<String> {
    let free = free?;
    if free >= need_gb.saturating_mul(1_000_000_000) {
        return None;
    }
    Some(format!(
        "only {:.1} GB free on the filesystem holding {path}; a controller needs at least {need_gb} GB \
         there (the stack's images and data take about 12 GB, the default model about 7 GB more). Free \
         some space, or move Docker's data-root to a bigger disk, then run `noo onboard` again.",
        free as f64 / 1e9
    ))
}

/// The free-space floor in GB: `NOO_ONBOARD_MIN_FREE_GB` when it is a whole
/// number, else MIN_FREE_GB.
pub(crate) fn need_gb(env: Option<&str>) -> u64 {
    env.and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(MIN_FREE_GB)
}

/// Where Docker keeps images and volumes: its own answer when it runs, else
/// /var/lib (where both Docker's root and the default data root live).
fn docker_root() -> String {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{.DockerRootDir}}"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| s.starts_with('/'))
        .unwrap_or_else(|| "/var/lib".to_string())
}

/// Both checks against this machine. Returns false when onboarding must stop.
/// A source checkout may build the images itself, so there the platform is a
/// warning; a dry run reports and goes on.
pub(crate) fn check(ctx: &mut Ctx) -> bool {
    let in_checkout = crate::envfile::repo_root().join(".git").exists();
    let mut ok = true;
    if let Some(msg) = platform_refusal(std::env::consts::OS, std::env::consts::ARCH) {
        if in_checkout {
            ctx.warn(&format!("{msg} From a source checkout you can still build them: `noo stack start --build`."));
        } else if ctx.dry_run {
            ctx.warn(&msg);
        } else {
            ctx.error(&msg);
            ok = false;
        }
    }
    let root = docker_root();
    let need = need_gb(std::env::var("NOO_ONBOARD_MIN_FREE_GB").ok().as_deref());
    if let Some(msg) = disk_refusal(&root, crate::commands::at_rest_volume::free_bytes(&root), need) {
        if ctx.dry_run {
            ctx.warn(&msg);
        } else {
            ctx.error(&msg);
            ok = false;
        }
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_linux_x86_64_can_be_a_controller_and_the_others_are_told_what_to_do() {
        assert_eq!(platform_refusal("linux", "x86_64"), None);
        let arm = platform_refusal("linux", "aarch64").expect("arm64 is refused");
        assert!(arm.contains("Linux arm64 (aarch64)") && arm.contains("amd64 only"), "{arm}");
        assert!(arm.contains("join an amd64 controller as a node"), "{arm}");
        assert!(platform_refusal("macos", "aarch64").expect("a Mac is refused").contains("a Mac (aarch64)"));
        assert!(platform_refusal("linux", "riscv64").is_some());
    }

    #[test]
    fn too_little_disk_is_refused_with_the_number_and_unknown_disk_never_is() {
        let gb = 1_000_000_000u64;
        assert_eq!(disk_refusal("/var/lib/docker", Some(30 * gb), 25), None);
        assert_eq!(disk_refusal("/var/lib/docker", Some(25 * gb), 25), None, "exactly the floor passes");
        let msg = disk_refusal("/var/lib/docker", Some(14 * gb), 25).expect("14 GB is refused");
        assert!(msg.contains("only 14.0 GB free") && msg.contains("at least 25 GB") && msg.contains("/var/lib/docker"),
                "{msg}");
        assert_eq!(disk_refusal("/var/lib/docker", None, 25), None, "no statvfs answer: no refusal on a guess");
    }

    #[test]
    fn the_floor_takes_a_whole_number_override_only() {
        assert_eq!(need_gb(None), MIN_FREE_GB);
        assert_eq!(need_gb(Some("12")), 12);
        assert_eq!(need_gb(Some(" 40 ")), 40);
        assert_eq!(need_gb(Some("lots")), MIN_FREE_GB);
        assert_eq!(need_gb(Some("-3")), MIN_FREE_GB);
    }
}
