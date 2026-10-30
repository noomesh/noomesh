// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The "GPU services" controller row (i277e).
//!
//! 2026-10-28, controller pop-os: the GPU embed container failed at start
//! with the CDI error "error getting device handle for index '0': Unknown
//! Error". compose aborted the whole `up` and the controller stayed down
//! until a reboot. The launcher now holds such a service by name and starts
//! everything else (scripts/lib-stuck-container.sh); this row is where the
//! hold stays visible after the launcher's output has scrolled away.
//!
//! The rule: a stack container (`<prefix>-*`) that is not running and whose
//! `.State.Error` carries a GPU device error is held by a GPU fault. The row
//! names each one with the daemon's words, and says whether the CPU
//! embedder (`<prefix>-ollama-embed-cpu`) is running to take the embeddings.

use super::restart_loops::{real_docker, service_of, stack_containers, DockerRun};
use super::{fail, ok, warn, Check};

pub(crate) const NAME: &str = "GPU services";

/// The daemon's words for a GPU that did not answer at container start
/// (CDI injection, nvidia-container-cli, NVML). The launcher's
/// `_NOO_GPU_START_ERROR` holds the same list.
const GPU_START_ERRORS: &[&str] = &[
    "error getting device handle",
    "failed to inject CDI devices",
    "unresolvable CDI devices",
    "nvidia-container-cli",
    "could not select device driver \"nvidia\"",
    "NVML",
    "nvidia-container-runtime",
];

/// `{{.State.Status}}` and `{{.State.Error}}`, tab-separated.
const INSPECT: &str = "{{.State.Status}}\t{{.State.Error}}";

/// One container held because the GPU did not answer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Held {
    pub container: String,
    /// The daemon's error, from the first GPU phrase on, bounded.
    pub error: String,
}

/// The GPU phrase in a container's `.State.Error` onwards, or `None` when
/// the error is not a GPU one.
pub(crate) fn gpu_error(state_error: &str) -> Option<String> {
    let at = GPU_START_ERRORS.iter().filter_map(|p| state_error.find(p)).min()?;
    let tail = state_error[at..].trim();
    Some(if tail.chars().count() > 160 { format!("{}…", tail.chars().take(160).collect::<String>()) } else { tail.to_string() })
}

/// One look: the held containers, and whether the CPU embedder runs.
pub(crate) fn scan(docker: DockerRun, prefix: &str) -> Result<(Vec<Held>, bool), String> {
    let mut held = Vec::new();
    let mut cpu_embed_running = false;
    let cpu_embed = format!("{prefix}-ollama-embed-cpu");
    for c in stack_containers(docker, prefix)? {
        let Ok((true, out, _)) = docker(&["inspect", "-f", INSPECT, c.as_str()]) else { continue };
        let (status, error) = out.trim_end_matches('\n').split_once('\t').unwrap_or((out.trim(), ""));
        if c == cpu_embed && status == "running" {
            cpu_embed_running = true;
        }
        if status == "running" {
            continue;
        }
        if let Some(error) = gpu_error(error) {
            held.push(Held { container: c, error });
        }
    }
    Ok((held, cpu_embed_running))
}

/// The `GPU services` row from one [`scan`].
pub(crate) fn row(found: Result<(Vec<Held>, bool), String>, prefix: &str) -> Check {
    match found {
        Err(e) => warn(NAME, format!("not judged — {e}"), None),
        Ok((v, _)) if v.is_empty() => ok(NAME, format!("no {prefix}-* container is held by a GPU fault")),
        Ok((v, cpu_embed)) => {
            let mut detail = v
                .iter()
                .map(|h| format!("{} ({}) is held: the GPU did not answer when it started ({})", h.container, service_of(&h.container, prefix), h.error))
                .collect::<Vec<_>>()
                .join("; ");
            let embedder = v.iter().any(|h| matches!(service_of(&h.container, prefix), "ollama-embed" | "ollama"));
            if embedder {
                detail.push_str(if cpu_embed {
                    "; the CPU embedder (ollama-embed-cpu) takes the embeddings meanwhile"
                } else {
                    "; no CPU embedder runs, so embeddings are on the mesh only (profile embed-cpu adds one)"
                });
            }
            fail(NAME, detail, "reboot this host (a GPU driver fault clears with it), then `noo stack start`")
        }
    }
}

/// `noo cluster verify --controller`'s row.
pub(crate) fn gpu_held_row() -> Check {
    let prefix = crate::envfile::container_prefix();
    row(scan(&real_docker, &prefix), &prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;
    use std::collections::HashMap;

    const CDI: &str = "failed to create task for container: failed to create shim task: OCI runtime create failed: \
                       could not apply required modification to OCI specification: error modifying OCI spec: \
                       failed to inject CDI devices: failed to inject devices: error getting device handle for index '0': Unknown Error";

    fn fake<'a>(inspect: &'a HashMap<&'a str, String>) -> impl Fn(&[&str]) -> Result<(bool, String, String), String> + 'a {
        move |args: &[&str]| match args[0] {
            "ps" => {
                let mut names: Vec<&str> = inspect.keys().copied().collect();
                names.push("other-ollama-embed"); // another stack's container: never judged
                Ok((true, names.join("\n"), String::new()))
            }
            "inspect" => {
                assert_eq!(args[2], INSPECT);
                Ok((true, format!("{}\n", inspect[args[3]]), String::new()))
            }
            _ => panic!("unexpected docker {args:?}"),
        }
    }

    #[test]
    fn a_cdi_fault_names_the_service_and_the_cpu_embedder() {
        let m = HashMap::from([
            ("noo-gateway", "running\t".to_string()),
            ("noo-ollama-embed", format!("created\t{CDI}")),
            ("noo-ollama-embed-cpu", "running\t".to_string()),
        ]);
        let c = row(scan(&fake(&m), "noo"), "noo");
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("noo-ollama-embed (ollama-embed) is held: the GPU did not answer when it started (failed to inject CDI devices"), "{}", c.detail);
        assert!(c.detail.contains("error getting device handle for index '0'"), "{}", c.detail);
        assert!(c.detail.ends_with("the CPU embedder (ollama-embed-cpu) takes the embeddings meanwhile"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().contains("reboot"));
    }

    #[test]
    fn without_a_cpu_embedder_the_row_says_so() {
        let m = HashMap::from([("noo-ollama-embed", format!("created\t{CDI}"))]);
        let c = row(scan(&fake(&m), "noo"), "noo");
        assert!(c.detail.contains("no CPU embedder runs"), "{}", c.detail);
    }

    #[test]
    fn a_held_exporter_is_named_without_the_embed_note() {
        let m = HashMap::from([("noo-nvidia-exporter", "exited\tnvidia-container-cli: initialization error: nvml error: driver not loaded".to_string())]);
        let c = row(scan(&fake(&m), "noo"), "noo");
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("noo-nvidia-exporter (nvidia-exporter) is held"), "{}", c.detail);
        assert!(!c.detail.contains("embedder"), "{}", c.detail);
    }

    #[test]
    fn other_failures_and_running_containers_are_not_gpu_holds() {
        let m = HashMap::from([
            ("noo-gateway", "running\t".to_string()),
            ("noo-redis", "exited\tpermission denied".to_string()),
            ("noo-vllm", format!("running\t{CDI}")), // a stale error on a running container
        ]);
        let c = row(scan(&fake(&m), "noo"), "noo");
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(c.detail, "no noo-* container is held by a GPU fault");
    }

    #[test]
    fn docker_absent_is_not_judged() {
        let c = row(scan(&|_: &[&str]| -> Result<(bool, String, String), String> { Err("No such file or directory".to_string()) }, "noo"), "noo");
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.starts_with("not judged"));
    }

    #[test]
    fn the_launcher_holds_on_the_same_words() {
        let sh = include_str!("../../../../scripts/lib-stuck-container.sh");
        let line = sh.lines().find(|l| l.starts_with("_NOO_GPU_START_ERROR=")).expect("the launcher's list");
        for p in GPU_START_ERRORS {
            assert!(line.contains(p), "launcher list lacks {p:?}: {line}");
        }
        assert_eq!(line.matches('|').count() + 1, GPU_START_ERRORS.len(), "{line}");
    }
}
