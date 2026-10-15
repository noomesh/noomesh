// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The "image family" controller row.
//!
//! The six third-party runtime services (redis and the monitoring set) pull
//! `${NOO_BASE_REGISTRY}/<name>:<tag>`. Two image families are published
//! under the SAME names and tags: the DHI mirrors at `ghcr.io/noomesh/dhi/`
//! and the upstream official images at `ghcr.io/noomesh/`. Every service key
//! and data volume is handed to uid 65532 (`pki::SERVICE_KEY_READERS`):
//! the DHI runtime images' `nonroot`, and the compose `user:` of the two
//! `-dev` variants (redis, grafana), whose image USER is root (i64); the
//! upstream ones run as nobody / 10001 / 472. 0.6.0 and 0.6.1 seeded the
//! upstream path on the public channel, and after `noo upgrade --channel
//! public` all five monitoring containers restart-looped on `permission
//! denied` (2026-10-14) with nothing saying why. This row says why: each
//! running container's image must come from the base registry, the base
//! registry must not be the upstream-family path, and the container's
//! `.Config.User` must be the uid its key is handed to AND able to read it.
//! None of them may run as uid 0 (i64, operator 2026-10-15): a redis or
//! grafana container created from a compose that predates the `user:` pin
//! reports `.Config.User` empty (the -dev image's root) and fails here.

use super::{fail, ok, warn, Check};
use std::process::Command;

pub(crate) const NAME: &str = "image family";

/// The compose services that pull through `NOO_BASE_REGISTRY`.
pub(crate) const RUNTIME_SERVICES: [&str; 6] = ["redis", "loki", "prometheus", "alertmanager", "grafana", "node-exporter"];

/// One running runtime container, as `docker inspect` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Running {
    pub svc: &'static str,
    pub image: String,
    pub user: String,
}

/// The uid a `.Config.User` runs as. Empty / `root` is 0; the two names
/// the images in play use are mapped; `uid[:gid]` is parsed. Any other
/// name is `None` (cannot judge from outside the image).
pub(crate) fn user_uid(user: &str) -> Option<u32> {
    match user.split(':').next().unwrap_or("").trim() {
        "" | "root" => Some(0),
        "nonroot" => Some(65532),
        "nobody" => Some(65534),
        n => n.parse().ok(),
    }
}

/// The uid the PKI reader table hands this service's key to.
pub(crate) fn expected_uid(svc: &str) -> Option<u32> {
    use crate::pki::KeyReader;
    match crate::pki::SERVICE_KEY_READERS.iter().find(|(n, _)| *n == svc)?.1 {
        KeyReader::ContainerRoot => Some(0),
        KeyReader::ContainerUid(u) => Some(u),
        KeyReader::Cli | KeyReader::Unknown => None,
    }
}

fn is_dhi_path(base: &str) -> bool {
    base.ends_with("/dhi") || base == "dhi.io"
}

/// Judge the row. `base` is the effective `NOO_BASE_REGISTRY`; `key_readable`
/// answers "can `uid` read this service's key" (`None` when the key is
/// absent: nothing mounted to judge).
pub(crate) fn image_family_check(base: &str, running: &[Running], key_readable: &dyn Fn(&str, u32) -> Option<bool>) -> Check {
    let base = base.trim().trim_end_matches('/');
    let legacy = base == crate::registry::LEGACY_PUBLIC_BASE_REGISTRY;
    let mut problems: Vec<String> = Vec::new();
    // A container running as root, from a compose that predates the
    // `user:` pin: recreating it is the fix, not a registry change.
    let mut as_root = false;
    if legacy {
        problems.push(format!(
            "NOO_BASE_REGISTRY is {base}, the UPSTREAM image family (other uids); the runtime images are the DHI mirrors at {}",
            crate::registry::PUBLIC_BASE_REGISTRY));
    }
    for r in running {
        if !r.image.starts_with(&format!("{base}/")) {
            problems.push(format!("{} runs {}, not an image from {base}/", r.svc, r.image));
        }
        let Some(uid) = user_uid(&r.user) else {
            problems.push(format!("{} runs as user {:?}, which this row cannot map to a uid", r.svc, r.user));
            continue;
        };
        if uid == 0 {
            as_root = true;
            problems.push(format!(
                "{} runs as root ({}): the runtime services run non-root, its key and data are handed to uid {}",
                r.svc, r.image, expected_uid(r.svc).map_or_else(|| "?".to_string(), |u| u.to_string())));
            continue;
        }
        if let Some(want) = expected_uid(r.svc) {
            if uid != want {
                problems.push(format!(
                    "{} runs as uid {uid} ({}), but its key and data are handed to uid {want}: another image family",
                    r.svc, r.image));
                continue;
            }
        }
        if key_readable(r.svc, uid) == Some(false) {
            problems.push(format!("{} (uid {uid}) cannot read services/{}/service.key", r.svc, r.svc));
        }
    }
    if !problems.is_empty() {
        let remedy = if legacy {
            format!("noo upgrade   # corrects NOO_BASE_REGISTRY to {}; then: noo upgrade --stack", crate::registry::PUBLIC_BASE_REGISTRY)
        } else if as_root && problems.iter().all(|p| p.contains("runs as root")) {
            "noo upgrade --stack   # recreates them under the compose `user:` (uid 65532)".to_string()
        } else if problems.iter().all(|p| p.contains("cannot read")) {
            "noo security pki fix-modes   # re-hands each key to its reader; then: noo stack restart".to_string()
        } else {
            format!("set NOO_BASE_REGISTRY={} in ~/.noo/.env (or remove it for that default), then: noo upgrade --stack",
                crate::registry::PUBLIC_BASE_REGISTRY)
        };
        return fail(NAME, problems.join("; "), remedy);
    }
    if running.is_empty() {
        return ok(NAME, format!("no runtime container is running; images resolve under {base}/"));
    }
    let names: Vec<&str> = running.iter().map(|r| r.svc).collect();
    let detail = format!("{} run images from {base}/ as non-root uids, each the uid its key is handed to", names.join(", "));
    if is_dhi_path(base) {
        ok(NAME, detail)
    } else {
        warn(NAME, format!("{detail}; {base} is not a DHI path, so a re-tag there could change the family"), None)
    }
}

/// The effective `NOO_BASE_REGISTRY`, as the launcher resolves it: the
/// process env, else the controller's `.env`, else the compose default.
pub(crate) fn effective_base() -> String {
    std::env::var("NOO_BASE_REGISTRY").ok().filter(|v| !v.trim().is_empty())
        .or_else(|| super::dotenv_value("NOO_BASE_REGISTRY").filter(|v| !v.trim().is_empty()))
        .unwrap_or_else(|| crate::registry::PUBLIC_BASE_REGISTRY.to_string())
}

/// `docker inspect` of each runtime container that exists. `Err` when
/// docker cannot be asked at all.
fn inspect_running() -> Result<Vec<Running>, String> {
    let prefix = crate::envfile::container_prefix();
    let mut out = Vec::new();
    for svc in RUNTIME_SERVICES {
        let name = format!("{prefix}-{svc}");
        let o = Command::new("docker")
            .args(["inspect", "--format", "{{.Config.Image}}|{{.Config.User}}", &name])
            .output()
            .map_err(|e| format!("docker: {e}"))?;
        if !o.status.success() {
            continue; // not created on this box (profile off): nothing to judge
        }
        let text = String::from_utf8_lossy(&o.stdout);
        let (image, user) = text.trim().split_once('|').unwrap_or((text.trim(), ""));
        out.push(Running { svc, image: image.to_string(), user: user.to_string() });
    }
    Ok(out)
}

/// The row, from the live box.
pub(crate) fn image_family_row() -> Check {
    match inspect_running() {
        Ok(running) => {
            let pki = crate::pki::pki_dir();
            image_family_check(&effective_base(), &running, &|svc, uid| {
                crate::pki::readable_by_uid(&pki.join("services").join(svc).join("service.key"), uid)
            })
        }
        Err(e) => warn(NAME, format!("cannot inspect the runtime containers ({e}): not judged"), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;

    const DHI: &str = crate::registry::PUBLIC_BASE_REGISTRY;
    const LEGACY: &str = crate::registry::LEGACY_PUBLIC_BASE_REGISTRY;

    fn run(svc: &'static str, image: String, user: &str) -> Running {
        Running { svc, image, user: user.into() }
    }

    /// The DHI family as it runs: 65532 for the runtime images, and the
    /// compose `user: "65532:65532"` for the -dev variants (redis, grafana).
    fn dhi_fleet(base: &str) -> Vec<Running> {
        vec![
            run("redis", format!("{base}/redis:8.6-debian13-dev"), "65532:65532"),
            run("loki", format!("{base}/loki:3"), "65532"),
            run("prometheus", format!("{base}/prometheus:3"), "65532"),
            run("alertmanager", format!("{base}/alertmanager:0"), "65532:65532"),
            run("grafana", format!("{base}/grafana:12-debian13-dev"), "65532:65532"),
            run("node-exporter", format!("{base}/node-exporter:1"), "nonroot"),
        ]
    }

    #[test]
    fn the_dhi_family_passes() {
        let c = image_family_check(DHI, &dhi_fleet(DHI), &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("prometheus") && c.detail.contains(DHI), "{}", c.detail);
    }

    #[test]
    fn the_upstream_family_the_0_6_1_fleet_ran_fails_loudly() {
        // What `noo upgrade --channel public` produced on 0.6.1.
        let upstream = vec![
            run("loki", format!("{LEGACY}/loki:3"), "10001"),
            run("prometheus", format!("{LEGACY}/prometheus:3"), "nobody"),
            run("alertmanager", format!("{LEGACY}/alertmanager:0"), "nobody"),
            run("grafana", format!("{LEGACY}/grafana:12-debian13-dev"), "472"),
            run("node-exporter", format!("{LEGACY}/node-exporter:1"), "nobody"),
        ];
        let c = image_family_check(LEGACY, &upstream, &|_, _| Some(false));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("UPSTREAM image family"), "{}", c.detail);
        assert!(c.detail.contains("prometheus runs as uid 65534"), "{}", c.detail);
        assert!(c.detail.contains("grafana runs as uid 472"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().starts_with("noo upgrade "), "{:?}", c.remedy);
        // The base alone is enough to fail, before anything restarts.
        assert_eq!(image_family_check(LEGACY, &[], &|_, _| None).verdict, Verdict::Fail);
    }

    #[test]
    fn a_container_from_another_registry_or_an_unreadable_key_fails() {
        let mut fleet = dhi_fleet(DHI);
        fleet[1].image = format!("{LEGACY}/loki:3"); // left over from before the correction
        let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("loki runs ghcr.io/noomesh/loki:3"), "{}", c.detail);

        let c = image_family_check(DHI, &dhi_fleet(DHI), &|svc, _| Some(svc != "prometheus"));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("prometheus (uid 65532) cannot read services/prometheus/service.key"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().contains("fix-modes"), "{:?}", c.remedy);
        // redis and grafana run as 65532 now, so their keys are asked too.
        let c = image_family_check(DHI, &dhi_fleet(DHI), &|svc, _| Some(svc != "redis"));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("redis (uid 65532) cannot read services/redis/service.key"), "{}", c.detail);
        // An absent key is not judged.
        assert_eq!(image_family_check(DHI, &dhi_fleet(DHI), &|_, _| None).verdict, Verdict::Ok);
    }

    /// i64: a redis or grafana container created by a compose without the
    /// `user:` pin runs as the -dev image's root. That fails, names root,
    /// and the remedy is recreating it, not a registry change.
    #[test]
    fn a_runtime_container_running_as_root_fails() {
        for user in ["", "0", "root", "0:0"] {
            let mut fleet = dhi_fleet(DHI);
            fleet[0].user = user.into(); // redis
            fleet[4].user = user.into(); // grafana
            let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
            assert_eq!(c.verdict, Verdict::Fail, "user {user:?}: {}", c.detail);
            assert!(c.detail.contains("redis runs as root") && c.detail.contains("grafana runs as root"), "{}", c.detail);
            assert!(c.remedy.as_deref().unwrap().starts_with("noo upgrade --stack"), "{:?}", c.remedy);
        }
    }

    /// Every runtime service's key is handed to a non-root uid: the table
    /// cannot quietly go back to root for redis or grafana.
    #[test]
    fn every_runtime_service_reader_is_non_root() {
        for svc in RUNTIME_SERVICES {
            let uid = expected_uid(svc).unwrap_or_else(|| panic!("{svc} has no reader"));
            assert_ne!(uid, 0, "{svc} is handed to root");
        }
        assert_eq!(expected_uid("redis"), Some(65532));
        assert_eq!(expected_uid("grafana"), Some(65532));
    }

    /// The compose pins redis and grafana to the uid their keys are handed
    /// to (the -dev images' own USER is root).
    #[test]
    fn compose_pins_the_dev_variants_to_their_reader_uid() {
        let compose = include_str!("../../../../docker-compose.cluster.yml");
        for svc in ["redis", "grafana"] {
            let head = format!("  {svc}:");
            let block: Vec<&str> = compose
                .lines()
                .skip_while(|l| *l != head)
                .skip(1)
                .take_while(|l| !(l.starts_with("  ") && !l.starts_with("   ") && !l.trim_start().starts_with('#')))
                .collect();
            assert!(!block.is_empty(), "no {svc} service in compose");
            let want = format!("user: \"{0}:{0}\"", expected_uid(svc).unwrap());
            assert!(block.iter().any(|l| l.trim() == want), "{svc} has no `{want}` in compose");
        }
    }

    #[test]
    fn an_operator_registry_is_judged_by_its_uids() {
        let base = "registry.example.com/mirror";
        let c = image_family_check(base, &dhi_fleet(base), &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        let c = image_family_check("registry.example.com/mirror/dhi", &dhi_fleet("registry.example.com/mirror/dhi"), &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        let mut odd = dhi_fleet(base);
        odd[2].user = "prometheus".into();
        let c = image_family_check(base, &odd, &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("cannot map"), "{}", c.detail);
    }

    #[test]
    fn users_map_to_uids_and_every_service_has_a_reader() {
        assert_eq!(user_uid(""), Some(0));
        assert_eq!(user_uid("root"), Some(0));
        assert_eq!(user_uid("65532:65532"), Some(65532));
        assert_eq!(user_uid("nonroot"), Some(65532));
        assert_eq!(user_uid("nobody"), Some(65534));
        assert_eq!(user_uid("472"), Some(472));
        assert_eq!(user_uid("grafana"), None);
        for svc in RUNTIME_SERVICES {
            assert!(expected_uid(svc).is_some(), "{svc} has no reader in pki::SERVICE_KEY_READERS");
        }
    }

    #[test]
    fn the_service_list_is_every_compose_base_registry_service() {
        let compose = include_str!("../../../../docker-compose.cluster.yml");
        let mut found = Vec::new();
        let mut svc = "";
        for ln in compose.lines() {
            if ln.starts_with("  ") && !ln.starts_with("   ") && ln.trim_end().ends_with(':') && !ln.trim_start().starts_with('#') {
                svc = ln.trim().trim_end_matches(':');
            }
            if ln.trim_start().starts_with("image: ${NOO_BASE_REGISTRY") {
                found.push(svc.to_string());
            }
        }
        found.sort();
        let mut want: Vec<String> = RUNTIME_SERVICES.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(found, want);
    }
}
