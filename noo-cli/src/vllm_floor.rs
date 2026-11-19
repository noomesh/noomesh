// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The GPU compute floor of the vLLM image this release pins.
//!
//! The vLLM image (`docker-compose.cluster.yml`, the agent's `backends.go`) is
//! built on one CUDA, and CUDA 13 dropped compute capability below 7.5
//! (Pascal, Volta): on such a GPU this vLLM cannot start. The floor is a
//! property of the IMAGE, declared here for the CLI (onboarding, `noo cluster
//! verify`), in the gateway (`routes/cluster.rs` `VLLM_MIN_COMPUTE_CAP`) and in
//! the agent (`docker.VllmMinComputeCap`); `tests/test_vllm_compute_floor.py`
//! fails when the image pin moves and these do not.

pub(crate) const VLLM_IMAGE_TAG: &str = "v0.25.0";
pub(crate) const VLLM_IMAGE_CUDA: &str = "13.0";
pub(crate) const VLLM_MIN_COMPUTE_CAP: &str = "7.5";

/// `<major>.<minor>`, one or two digits each, as nvidia-smi and the agent
/// report it. Anything else is unknown.
pub(crate) fn parse_compute_cap(s: &str) -> Option<(u32, u32)> {
    let (maj, min) = s.trim().split_once('.')?;
    let ok = |p: &str| (1..=2).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit());
    if !ok(maj) || !ok(min) {
        return None;
    }
    Some((maj.parse().ok()?, min.parse().ok()?))
}

/// Whether a GPU of compute capability `cap` is KNOWN to run the pinned vLLM.
/// Compared as numbers (`"10.0"` is above `"7.5"`). False for unknown (absent
/// or unparsable) too, so a caller that refuses must first tell unknown from
/// below (`parse_compute_cap`): a refusal rests on a known fact.
pub(crate) fn usable(cap: Option<&str>) -> bool {
    match (cap.and_then(parse_compute_cap), parse_compute_cap(VLLM_MIN_COMPUTE_CAP)) {
        (Some(have), Some(need)) => have >= need,
        _ => false,
    }
}

/// The requirement, in one clause: "vLLM v0.25.0 is built on CUDA 13.0, which
/// needs GPU compute capability 7.5+".
pub(crate) fn needs() -> String {
    format!("vLLM {VLLM_IMAGE_TAG} is built on CUDA {VLLM_IMAGE_CUDA}, which needs GPU compute capability {VLLM_MIN_COMPUTE_CAP}+")
}

#[cfg(test)]
mod tests {
    use super::usable;

    #[test]
    fn a_compute_capability_is_compared_as_numbers_and_unknown_is_not_usable() {
        assert!(!usable(Some("6.1")));
        assert!(!usable(Some("7.0")));
        assert!(usable(Some("7.5")));
        assert!(usable(Some("8.6")));
        assert!(usable(Some("10.0")));
        assert!(!usable(None));
        assert!(!usable(Some("eight")));
        assert!(!usable(Some("")));
    }
}
