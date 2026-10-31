// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! THE declared home of where this project's images and releases live.
//!
//! Two facts, each written once, in this file. Every other reader in noo-cli
//! resolves them from here; `tests/test_image_namespace_declarations.py` and
//! `tests/test_release_repo_declarations.py` fail if a literal of either shows
//! up anywhere else.
//!
//! The pre-move org is NOT recognised anywhere: the move is
//! a full replacement, so an image under the old root is simply not ours.
//!
//! Matchers ("is this one of our images?") are deliberately wider than the
//! default only by the local build names (`noomesh/*`, `pai-assistant/*`). A
//! default says where to PULL from; a matcher says what we OWN.

/// The registry namespace release images are pulled from and pushed to
/// (`<this>/<service>:<tag>`). Seeded into `NOO_IMAGE_PREFIX` /
/// `NOO_BASE_REGISTRY` on a fresh install; an operator's own value wins.
pub(crate) const IMAGE_NAMESPACE: &str = "ghcr.io/noomesh";

/// The registry namespace a fresh install seeds into `NOO_BASE_REGISTRY` (where
/// redis / loki / prometheus / alertmanager / grafana / node-exporter / tempo
/// come from): the DHI runtime mirrors that mirror-images.yml publishes under the
/// NESTED `dhi/` prefix (`dest_org: noomesh/dhi`, list in
/// scripts/dhi-images.txt). Those are the images the stack is built around:
/// every service-key reader in `pki::SERVICE_KEY_READERS` and every
/// data-volume owner is uid 65532 (the DHI runtime images' `nonroot`, and
/// the compose `user:` of the two `-dev` variants, redis and grafana: i64).
///
/// It is NOT `IMAGE_NAMESPACE`. `ghcr.io/noomesh/<name>` (no `dhi/`) holds
/// the UPSTREAM official images under the same names and tags (prom/*,
/// grafana/*, redis), which run as nobody / 10001 / 472 and cannot read a
/// key handed to 65532: 0.6.0 and 0.6.1 seeded that path, and the public
/// fleet's monitoring set restart-looped on `permission denied` after
/// `noo upgrade --channel public` (2026-10-14). The old private org served
/// both families from one path, which is why it never showed there.
pub(crate) const PUBLIC_BASE_REGISTRY: &str = "ghcr.io/noomesh/dhi";

/// The `NOO_BASE_REGISTRY` value 0.6.0 and 0.6.1 wrote on the public channel
/// (the upstream-mirror family, see above). `noo upgrade` corrects exactly
/// this value to `PUBLIC_BASE_REGISTRY` on a public-channel install
/// (`commands::channel::legacy_base_registry_fix`); any other operator value
/// is left alone.
pub(crate) const LEGACY_PUBLIC_BASE_REGISTRY: &str = IMAGE_NAMESPACE;

/// The GitHub repo `noo` self-upgrades and installs from
/// (`NOO_CLI_REPO` overrides it, see `commands::upgrade::repo`).
pub(crate) const RELEASE_REPO: &str = "noomesh/noomesh";

/// The PUBLIC channel: where `noo upgrade --channel public` points an install.
/// Declared here with the other two so no literal of the location lives
/// elsewhere. A private channel is never declared in this tree (the OSS sync's
/// leak check would reject it); an operator supplies those values.
pub(crate) const PUBLIC_RELEASE_REPO: &str = "noomesh/noomesh";
pub(crate) const PUBLIC_IMAGE_NAMESPACE: &str = "ghcr.io/noomesh";

/// Registry roots that make a pulled image ours, for CLEANUP matchers only
/// (offboard, superseded-image prune) — never a pull source or a registry
/// probe. Trailing slash is part of the match (`ghcr.io/noomesh-evil/x` is not ours).
const OWNED_REGISTRY_ROOTS: [&str; 1] = ["ghcr.io/noomesh/"];

/// The registry roots whose images are OURS for the artifact rail: rail-only
/// on a node, never pulled from a registry there (the node holds no
/// credential). Written into `staged-images.json` as `own_roots` so
/// the gateway applies the same rule without a namespace literal of its own.
pub(crate) fn rail_roots() -> [&'static str; 1] {
    OWNED_REGISTRY_ROOTS
}

/// Local build names: `noomesh/*` is what `docker build` here writes,
/// `pai-assistant/*` is what boxes onboarded before the rename still hold
/// (scripts/lib-dist.sh::legacy_image_namespaces maps the same name).
const OWNED_LOCAL_ROOTS: [&str; 2] = ["noomesh/", "pai-assistant/"];

/// A pulled release image under our registry root (cleanup only).
pub(crate) fn is_registry_image(name: &str) -> bool {
    OWNED_REGISTRY_ROOTS.iter().any(|r| name.starts_with(r))
}

/// One of ours by ANY name: a pulled release image or a local/legacy build.
/// This is what offboard uses to decide what it may remove.
pub(crate) fn is_our_image(name: &str) -> bool {
    is_registry_image(name) || OWNED_LOCAL_ROOTS.iter().any(|r| name.starts_with(r))
}

/// `ghcr.io/<owner>/<ns>` -> `<owner>/<ns>`, the path the registry API wants.
pub(crate) fn image_repo_path() -> &'static str {
    IMAGE_NAMESPACE.strip_prefix("ghcr.io/").unwrap_or(IMAGE_NAMESPACE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matchers_accept_our_names_and_not_another_org() {
        for ours in [
            "ghcr.io/noomesh/gateway",
            "noomesh/gateway",
            "pai-assistant/gateway",
        ] {
            assert!(is_our_image(ours), "{ours}");
        }
        for not_ours in [
            "ghcr.io/someone-else/noomesh/gateway",
            "ghcr.io/someone-else/gateway",
            "ghcr.io/noomesh-evil/x",
            "ghcr.io/other/x",
            "docker.io/noomesh/x",
            "postgres",
        ] {
            assert!(!is_our_image(not_ours), "{not_ours}");
        }
    }

    #[test]
    fn registry_matcher_excludes_local_names() {
        assert!(is_registry_image("ghcr.io/noomesh/gateway"));
        assert!(!is_registry_image("noomesh/gateway"));
        assert!(!is_registry_image("pai-assistant/gateway"));
    }

    #[test]
    fn the_base_registry_is_the_dhi_path_under_the_namespace() {
        // The runtime images come from the DHI family, nested under the
        // release namespace; the bare namespace is the upstream family.
        assert_eq!(PUBLIC_BASE_REGISTRY, format!("{IMAGE_NAMESPACE}/dhi"));
        assert_eq!(PUBLIC_BASE_REGISTRY, format!("{PUBLIC_IMAGE_NAMESPACE}/dhi"));
        assert_ne!(PUBLIC_BASE_REGISTRY, IMAGE_NAMESPACE);
        assert_ne!(PUBLIC_BASE_REGISTRY, PUBLIC_IMAGE_NAMESPACE);
        assert!(!PUBLIC_BASE_REGISTRY.ends_with('/'));
        // The value the migration corrects is exactly what 0.6.0/0.6.1 wrote.
        assert_eq!(LEGACY_PUBLIC_BASE_REGISTRY, PUBLIC_IMAGE_NAMESPACE);
        assert_ne!(LEGACY_PUBLIC_BASE_REGISTRY, PUBLIC_BASE_REGISTRY);
        // Still one of ours for cleanup: the dhi path sits under the owned root.
        assert!(is_registry_image(&format!("{PUBLIC_BASE_REGISTRY}/prometheus:3")));
    }

    #[test]
    fn repo_path_is_the_namespace_without_the_host() {
        assert_eq!(image_repo_path(), IMAGE_NAMESPACE.trim_start_matches("ghcr.io/"));
        assert!(!image_repo_path().contains("ghcr.io"));
    }
}
