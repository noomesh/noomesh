// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The "image family" controller row.
//!
//! The seven third-party runtime services (redis and the monitoring set) pull
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
//! registry must not be the upstream-family path, and the uid the container
//! RUNS AS must be the uid its key is handed to AND able to read it.
//! None of them may run as uid 0 (i64, operator 2026-10-15): a redis or
//! grafana container created from a compose that predates the `user:` pin
//! runs as the -dev image's root and fails here.
//!
//! The uid judged is the LIVE one (`docker exec <c> id -u`, else `docker top`;
//! BusyBox hosts' `ps` has no `-o uid`), not the `.Config.User` string: compose
//! names redis/grafana's user (`nonroot` / `grafana`, because Docker 27
//! cannot resolve a numeric `user:` when it copies secrets in), and a name
//! means a uid only inside its image (`grafana` is 65532 in the DHI image and
//! 472 upstream). The string is the fallback only when the container is not
//! running; a name it cannot map then is "not judged", a warning.

use super::{fail, ok, warn, Check};
use std::process::Command;

pub(crate) const NAME: &str = "image family";

/// The compose services that pull through `NOO_BASE_REGISTRY`.
pub(crate) const RUNTIME_SERVICES: [&str; 7] =
    ["redis", "loki", "prometheus", "alertmanager", "grafana", "node-exporter", "tempo"];

/// One running runtime container, as `docker inspect` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Running {
    pub svc: &'static str,
    pub image: String,
    /// `.Config.User`, as written in compose (or empty: the image's USER).
    pub user: String,
    /// The uid its processes run as, from `docker top`; `None` when it is
    /// not running (or docker could not say).
    pub live_uid: Option<u32>,
    /// `.State.Running`. A running container whose uid could not be read
    /// is "uid unreadable", never "not running".
    pub running: bool,
    /// Why the live uid could not be read (running containers only).
    pub uid_err: String,
}

/// The uid a `.Config.User` runs as, for a container that is not running
/// (a running one is judged by its live uid). Empty / `root` is 0; the two
/// names that mean one uid in every image in play are mapped; `uid[:gid]` is
/// parsed. Any other name is `None` (cannot judge from outside the image):
/// `grafana` is 65532 in the DHI image but 472 in the upstream one.
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
    let mut unjudged: Vec<String> = Vec::new();
    if legacy {
        problems.push(format!(
            "NOO_BASE_REGISTRY is {base}, the UPSTREAM image family (other uids); the runtime images are the DHI mirrors at {}",
            crate::registry::PUBLIC_BASE_REGISTRY));
    }
    for r in running {
        if !r.image.starts_with(&format!("{base}/")) {
            problems.push(format!("{} runs {}, not an image from {base}/", r.svc, r.image));
        }
        let Some(uid) = r.live_uid.or_else(|| user_uid(&r.user)) else {
            if r.running {
                unjudged.push(format!("{} is running but its live uid could not be read ({}), and its user {:?} cannot be mapped to a uid from outside the image",
                    r.svc, r.uid_err, r.user));
            } else {
                unjudged.push(format!("{} is not running and its user {:?} cannot be mapped to a uid from outside the image", r.svc, r.user));
            }
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
    if !unjudged.is_empty() {
        return warn(NAME, format!("{detail}; not judged: {}", unjudged.join("; ")), None);
    }
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

/// The uid a container's processes run as, from `docker top <c> -o pid,uid`
/// output: root if any process is root, else the first process's (the
/// container's init). `None` when no process row parses.
pub(crate) fn live_uid_from_top(text: &str) -> Option<u32> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: Vec<&str> = lines.next()?.split_whitespace().collect();
    let col = header.iter().position(|h| h.eq_ignore_ascii_case("UID"))?;
    let uids: Vec<u32> = lines.filter_map(|l| l.split_whitespace().nth(col)?.parse().ok()).collect();
    if uids.contains(&0) {
        return Some(0);
    }
    uids.first().copied()
}

/// Run `docker <args>`: stdout on success, else the stderr (or spawn error).
fn docker_text(args: &[&str]) -> Result<String, String> {
    let o = Command::new("docker").args(args).output().map_err(|e| format!("docker: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

/// The live uid of a running container. `docker exec <c> id -u` first (every
/// image with coreutils or busybox `id`; `docker top` shells out to the
/// HOST's `ps`, which on BusyBox hosts (Alpine, dind) has no `-o uid`), then
/// `docker top` parsing. `Err` carries why the exec failed.
pub(crate) fn live_uid_via(docker: &dyn Fn(&[&str]) -> Result<String, String>, name: &str) -> Result<u32, String> {
    let exec_err = match docker(&["exec", name, "id", "-u"]) {
        Ok(t) => match t.trim().parse::<u32>() {
            Ok(u) => return Ok(u),
            Err(_) => format!("docker exec id -u printed {:?}", t.trim()),
        },
        Err(e) => format!("docker exec id -u failed: {e}"),
    };
    if let Ok(t) = docker(&["top", name, "-o", "pid,uid"]) {
        if let Some(u) = live_uid_from_top(&t) {
            return Ok(u);
        }
    }
    Err(exec_err)
}

/// `docker inspect` of each runtime container that exists, with its live
/// uid when it is running. `Err` when docker cannot be asked at all.
fn inspect_running() -> Result<Vec<Running>, String> {
    let prefix = crate::envfile::container_prefix();
    let mut out = Vec::new();
    for svc in RUNTIME_SERVICES {
        let name = format!("{prefix}-{svc}");
        let o = Command::new("docker")
            .args(["inspect", "--format", "{{.Config.Image}}|{{.Config.User}}|{{.State.Running}}", &name])
            .output()
            .map_err(|e| format!("docker: {e}"))?;
        if !o.status.success() {
            continue; // not created on this box (profile off): nothing to judge
        }
        let text = String::from_utf8_lossy(&o.stdout);
        let mut parts = text.trim().splitn(3, '|');
        let image = parts.next().unwrap_or("").to_string();
        let user = parts.next().unwrap_or("").to_string();
        let running = parts.next() == Some("true");
        let (live_uid, uid_err) = if running {
            match live_uid_via(&docker_text, &name) {
                Ok(u) => (Some(u), String::new()),
                Err(e) => (None, e),
            }
        } else {
            (None, String::new())
        };
        out.push(Running { svc, image, user, live_uid, running, uid_err });
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

// ── the voice add-on's images (i105) ─────────────────────────────────

/// The "voice images" row.
///
/// `ghcr.io/noomesh/whisper` and `piper` ran as uid 0 through v0.6.4 (no
/// USER line), so the mTLS leaves their doors gained (#125) went to a root
/// reader. Both Dockerfiles now end `USER nonroot` (65532) and their keys
/// are handed to that uid (`pki::SERVICE_KEY_READERS`). Not in the image
/// family row: they are built from this tree, not pulled through
/// `NOO_BASE_REGISTRY`. Voice is an overlay add-on, so with it off the row
/// says "not checked"; with it on, each door's LIVE uid (the same BusyBox-safe
/// reader as above) must be the uid its key is handed to, non-zero, and able
/// to read the key.
pub(crate) const VOICE_NAME: &str = "voice images";

/// The voice doors, by compose service name.
pub(crate) const VOICE_SERVICES: [&str; 2] = ["whisper", "piper"];

/// What the box says about one voice container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VoiceUid {
    /// No such container (not composed yet on this box).
    Missing,
    /// Created but not running: no live uid to read.
    Stopped,
    /// Running, as this uid.
    Live(u32),
    /// Running, but its uid could not be read (why).
    Unreadable(String),
}

/// Judge the row. `key_readable` answers "can `uid` read this service's
/// key" (`None` when the key is absent: nothing mounted to judge).
pub(crate) fn voice_images_check(voice_on: bool, doors: &[(&'static str, VoiceUid)], key_readable: &dyn Fn(&str, u32) -> Option<bool>) -> Check {
    if !voice_on {
        return ok(VOICE_NAME, "voice off — not checked");
    }
    let mut problems: Vec<String> = Vec::new();
    let mut unjudged: Vec<String> = Vec::new();
    let mut root = 0usize;
    let mut unreadable_key = 0usize;
    for (svc, state) in doors {
        let want = expected_uid(svc);
        let want_s = want.map_or_else(|| "?".to_string(), |u| u.to_string());
        let uid = match state {
            VoiceUid::Live(u) => *u,
            VoiceUid::Missing => {
                unjudged.push(format!("{svc} has no container"));
                continue;
            }
            VoiceUid::Stopped => {
                unjudged.push(format!("{svc} is not running"));
                continue;
            }
            VoiceUid::Unreadable(e) => {
                unjudged.push(format!("{svc} is running but its live uid could not be read ({e})"));
                continue;
            }
        };
        if uid == 0 {
            root += 1;
            problems.push(format!(
                "{svc} runs as root: an image from before i105 (the voice images run as nonroot, and its key is handed to uid {want_s})"));
            continue;
        }
        if let Some(w) = want {
            if uid != w {
                problems.push(format!("{svc} runs as uid {uid}, but its key is handed to uid {w}"));
                continue;
            }
        }
        if key_readable(svc, uid) == Some(false) {
            unreadable_key += 1;
            problems.push(format!("{svc} (uid {uid}) cannot read services/{svc}/service.key"));
        }
    }
    if !problems.is_empty() {
        let remedy = if unreadable_key == problems.len() {
            "noo security pki fix-modes   # re-hands each key to its reader; then: noo stack restart --force whisper piper"
        } else if root == problems.len() {
            "noo upgrade --stack   # pulls the non-root whisper/piper images and recreates both"
        } else {
            "noo upgrade --stack   # the shipped images and key modes; then: noo cluster verify --controller"
        };
        return fail(VOICE_NAME, problems.join("; "), remedy);
    }
    if !unjudged.is_empty() {
        return warn(VOICE_NAME, format!("voice is on; not judged: {}", unjudged.join("; ")), Some("noo stack status".into()));
    }
    ok(VOICE_NAME, "whisper and piper run as non-root uid 65532, the uid their keys are handed to, and can read them")
}

/// Each voice container's state on the live box.
fn inspect_voice() -> Vec<(&'static str, VoiceUid)> {
    let prefix = crate::envfile::container_prefix();
    VOICE_SERVICES
        .iter()
        .map(|svc| {
            let name = format!("{prefix}-{svc}");
            let state = match docker_text(&["inspect", "--format", "{{.State.Running}}", &name]) {
                Err(_) => VoiceUid::Missing,
                Ok(t) if t.trim() != "true" => VoiceUid::Stopped,
                Ok(_) => match live_uid_via(&docker_text, &name) {
                    Ok(u) => VoiceUid::Live(u),
                    Err(e) => VoiceUid::Unreadable(e),
                },
            };
            (*svc, state)
        })
        .collect()
}

/// The row, from the live box. `voice_on` is the `addons.voice` switch.
pub(crate) fn voice_images_row(voice_on: bool) -> Check {
    if !voice_on {
        return voice_images_check(false, &[], &|_, _| None);
    }
    let pki = crate::pki::pki_dir();
    voice_images_check(true, &inspect_voice(), &|svc, uid| {
        crate::pki::readable_by_uid(&pki.join("services").join(svc).join("service.key"), uid)
    })
}

/// The "voice models" row (i105).
///
/// The controller stages the voice models; the containers mount them
/// read-only and run offline (`HF_HUB_OFFLINE=1`), so a model that is not
/// staged is not "downloaded on first use" any more, it is a 404. This row
/// says so before a user finds out: the configured whisper model and piper
/// voice (`WHISPER_MODEL` / `PIPER_VOICE`) are present in the store, and each
/// container's own env (`docker inspect .Config.Env`) is offline.
pub(crate) const VOICE_MODELS_NAME: &str = "voice models";

/// Judge the row. `staged`: (`whisper:<name>` / `piper:<voice>`, present).
/// `offline`: per container, `Some(true)` when its env has
/// `HF_HUB_OFFLINE=1`, `Some(false)` when it does not, `None` when there is
/// no container to read.
pub(crate) fn voice_models_check(voice_on: bool, root: &str, staged: &[(String, bool)], offline: &[(&'static str, Option<bool>)]) -> Check {
    if !voice_on {
        return ok(VOICE_MODELS_NAME, "voice off — not checked");
    }
    let missing: Vec<&str> = staged.iter().filter(|(_, have)| !have).map(|(id, _)| id.as_str()).collect();
    if !missing.is_empty() {
        let pulls: Vec<String> = missing.iter().map(|id| format!("noo models pull {id}")).collect();
        return fail(
            VOICE_MODELS_NAME,
            format!("not staged under {root}: {} — the voice containers never download, so every request for it is a 404", missing.join(", ")),
            pulls.join(" && "),
        );
    }
    let online: Vec<&str> = offline.iter().filter(|(_, o)| *o == Some(false)).map(|(s, _)| *s).collect();
    if !online.is_empty() {
        return fail(
            VOICE_MODELS_NAME,
            format!("{} run(s) without HF_HUB_OFFLINE=1 — a container from before i105 or an edited overlay, free to fetch from Hugging Face", online.join(", ")),
            "noo upgrade --stack   # the shipped overlay (offline, read-only model mounts); then: noo cluster verify --controller",
        );
    }
    let ids: Vec<&str> = staged.iter().map(|(id, _)| id.as_str()).collect();
    let unread: Vec<&str> = offline.iter().filter(|(_, o)| o.is_none()).map(|(s, _)| *s).collect();
    if !unread.is_empty() {
        return warn(
            VOICE_MODELS_NAME,
            format!("{} staged under {root}; not judged offline: no {} container", ids.join(" and "), unread.join(" / ")),
            Some("noo stack status".into()),
        );
    }
    ok(VOICE_MODELS_NAME, format!("{} staged under {root}; whisper and piper run offline (HF_HUB_OFFLINE=1)", ids.join(" and ")))
}

/// `Some(true)` when a `.Config.Env` JSON array carries `HF_HUB_OFFLINE=1`.
pub(crate) fn env_is_offline(env_json: &str) -> Option<bool> {
    let v: Vec<String> = serde_json::from_str(env_json.trim()).ok()?;
    Some(v.iter().any(|e| e.trim() == "HF_HUB_OFFLINE=1"))
}

/// The row, from the live box.
pub(crate) fn voice_models_row(voice_on: bool) -> Check {
    use crate::commands::voice_models as vm;
    if !voice_on {
        return voice_models_check(false, "", &[], &[]);
    }
    let root = vm::voice_root();
    let staged: Vec<(String, bool)> = vm::configured().iter().map(|m| (m.id(), vm::is_staged(&root, m))).collect();
    let prefix = crate::envfile::container_prefix();
    let offline: Vec<(&'static str, Option<bool>)> = VOICE_SERVICES
        .iter()
        .map(|svc| {
            let name = format!("{prefix}-{svc}");
            (*svc, docker_text(&["inspect", "--format", "{{json .Config.Env}}", &name]).ok().and_then(|t| env_is_offline(&t)))
        })
        .collect();
    voice_models_check(true, &root.display().to_string(), &staged, &offline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;

    const DHI: &str = crate::registry::PUBLIC_BASE_REGISTRY;
    const LEGACY: &str = crate::registry::LEGACY_PUBLIC_BASE_REGISTRY;

    /// A stopped container: judged by its `.Config.User` string only.
    fn run(svc: &'static str, image: String, user: &str) -> Running {
        Running { svc, image, user: user.into(), live_uid: None, running: false, uid_err: String::new() }
    }

    /// A running container: judged by the uid it runs as.
    fn live(svc: &'static str, image: String, user: &str, uid: u32) -> Running {
        Running { svc, image, user: user.into(), live_uid: Some(uid), running: true, uid_err: String::new() }
    }

    /// The DHI family as it runs: 65532 for the runtime images, and the
    /// compose `user: nonroot` / `user: grafana` for the -dev variants
    /// (redis, grafana), each that image's name for 65532.
    fn dhi_fleet(base: &str) -> Vec<Running> {
        vec![
            live("redis", format!("{base}/redis:8.6-debian13-dev"), "nonroot", 65532),
            live("loki", format!("{base}/loki:3"), "65532", 65532),
            live("prometheus", format!("{base}/prometheus:3"), "65532", 65532),
            live("alertmanager", format!("{base}/alertmanager:0"), "65532:65532", 65532),
            live("grafana", format!("{base}/grafana:12-debian13-dev"), "grafana", 65532),
            live("node-exporter", format!("{base}/node-exporter:1"), "nonroot", 65532),
            live("tempo", format!("{base}/tempo:2"), "65532", 65532),
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
            live("grafana", format!("{LEGACY}/grafana:12-debian13-dev"), "grafana", 472),
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
            fleet[0] = run("redis", fleet[0].image.clone(), user); // stopped: judged by the string
            fleet[4].user = user.into(); // grafana, running:
            fleet[4].live_uid = Some(0); // judged by its live uid
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

    /// The compose pins redis and grafana to the image's NAME for the uid
    /// their keys are handed to (the -dev images' own USER is root). A name,
    /// not the number: Docker 27 resolves `user:` through the image's passwd
    /// when it copies secrets in, and `getent` fails on "65532:65532".
    /// Measured in each image's /etc/passwd (tests never pull images):
    /// dhi/redis:8.6-debian13-dev `nonroot:x:65532`, dhi/grafana:12-debian13-dev
    /// `grafana:x:65532`.
    #[test]
    fn compose_pins_the_dev_variants_to_their_reader_uid() {
        const NAME_UID: [(&str, &str, u32); 2] = [("redis", "nonroot", 65532), ("grafana", "grafana", 65532)];
        let compose = include_str!("../../../../docker-compose.cluster.yml");
        for (svc, name, uid) in NAME_UID {
            let head = format!("  {svc}:");
            let block: Vec<&str> = compose
                .lines()
                .skip_while(|l| *l != head)
                .skip(1)
                .take_while(|l| !(l.starts_with("  ") && !l.starts_with("   ") && !l.trim_start().starts_with('#')))
                .collect();
            assert!(!block.is_empty(), "no {svc} service in compose");
            assert_eq!(expected_uid(svc), Some(uid), "{svc}: the name's uid is not its key reader's");
            let want = format!("user: {name}");
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
    }

    /// i64 follow-up: compose names the user (`nonroot`, `grafana`), so the
    /// row judges the uid the container RUNS AS, not the string.
    #[test]
    fn a_named_user_is_judged_by_its_live_uid() {
        // The named DHI fleet passes on its live uids.
        let c = image_family_check(DHI, &dhi_fleet(DHI), &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        // The same name at another live uid (the upstream grafana's 472) fails.
        let mut fleet = dhi_fleet(DHI);
        fleet[4].live_uid = Some(472);
        let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("grafana runs as uid 472"), "{}", c.detail);
        // A live root under a non-root name still fails as root.
        let mut fleet = dhi_fleet(DHI);
        fleet[0].live_uid = Some(0);
        let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
        assert!(c.verdict == Verdict::Fail && c.detail.contains("redis runs as root"), "{}", c.detail);
        // A stopped container with a name the row cannot map is not judged:
        // a warning, not a failure, and it says so.
        let mut fleet = dhi_fleet(DHI);
        fleet[4] = run("grafana", fleet[4].image.clone(), "grafana");
        let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("grafana is not running") && c.detail.contains("not judged"), "{}", c.detail);
        // A stopped container with a numeric or mapped user is still judged.
        let mut fleet = dhi_fleet(DHI);
        fleet[2] = run("prometheus", fleet[2].image.clone(), "10001");
        let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
        assert!(c.verdict == Verdict::Fail && c.detail.contains("prometheus runs as uid 10001"), "{}", c.detail);
    }

    #[test]
    fn the_live_uid_is_read_from_docker_top() {
        // `docker top <c> -o pid,uid`, as Docker 29 printed it for a
        // throwaway dhi/grafana:12-debian13-dev run with `--user grafana`.
        assert_eq!(live_uid_from_top("PID                 UID\n4096315             65532\n"), Some(65532));
        // Any root process makes the container root.
        assert_eq!(live_uid_from_top("PID UID\n10 65532\n11 0\n"), Some(0));
        assert_eq!(live_uid_from_top("UID PID\n472 10\n"), Some(472));
        assert_eq!(live_uid_from_top("PID UID\n"), None);
        assert_eq!(live_uid_from_top(""), None);
        assert_eq!(live_uid_from_top("PID UID\n10 grafana\n"), None);
    }

    const BUSYBOX: &str = "ps: bad -o argument 'uid', supported arguments: user,group,comm,args,pid,ppid,pgid,etime,nice,rgroup,ruser,time,tty,vsz,stat,rss";

    #[test]
    fn busybox_ps_does_not_hide_the_live_uid() {
        // docker top fails on a BusyBox host; exec id -u answers.
        let d = |a: &[&str]| -> Result<String, String> {
            if a[0] == "top" { Err(BUSYBOX.into()) } else { Ok("65532\n".into()) }
        };
        assert_eq!(live_uid_via(&d, "c"), Ok(65532));
        // The row then judges it: grafana at 65532 is `+`, not `!`.
        let mut fleet = dhi_fleet(DHI);
        fleet[4].live_uid = live_uid_via(&d, "c").ok();
        let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        // exec fails, top works: top is the fallback.
        let d = |a: &[&str]| -> Result<String, String> {
            if a[0] == "exec" { Err("no id".into()) } else { Ok("PID UID\n9 472\n".into()) }
        };
        assert_eq!(live_uid_via(&d, "c"), Ok(472));
        // root via exec still fails the row.
        let d = |_: &[&str]| -> Result<String, String> { Ok("0\n".into()) };
        let mut fleet = dhi_fleet(DHI);
        fleet[4].live_uid = live_uid_via(&d, "c").ok();
        let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
        assert!(c.verdict == Verdict::Fail && c.detail.contains("grafana runs as root"), "{}", c.detail);
    }

    #[test]
    fn a_running_container_with_an_unreadable_uid_is_not_called_stopped() {
        let d = |a: &[&str]| -> Result<String, String> {
            Err(if a[0] == "top" { BUSYBOX.into() } else { "exec: \"id\": executable file not found".into() })
        };
        let err = live_uid_via(&d, "c").unwrap_err();
        assert!(err.starts_with("docker exec id -u failed:"), "{err}");
        let mut fleet = dhi_fleet(DHI);
        fleet[4] = Running { svc: "grafana", image: fleet[4].image.clone(), user: "grafana".into(), live_uid: None, running: true, uid_err: err };
        let c = image_family_check(DHI, &fleet, &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("its live uid could not be read") || c.detail.contains("live uid could not be read (docker exec id -u failed:"), "{}", c.detail);
        assert!(!c.detail.contains("grafana is not running"), "{}", c.detail);
        // A mappable .Config.User is still the fallback for a running one.
        fleet[4].user = "65532".into();
        assert_eq!(image_family_check(DHI, &fleet, &|_, _| Some(true)).verdict, Verdict::Ok);
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

    // ── voice images (i105) ──

    fn voice(w: VoiceUid, p: VoiceUid) -> Vec<(&'static str, VoiceUid)> {
        vec![("whisper", w), ("piper", p)]
    }

    #[test]
    fn voice_off_is_not_checked() {
        let c = voice_images_check(false, &voice(VoiceUid::Live(0), VoiceUid::Live(0)), &|_, _| Some(false));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(c.detail, "voice off — not checked");
        assert_eq!(c.name, "voice images");
    }

    #[test]
    fn the_voice_keys_are_handed_to_65532() {
        assert_eq!(expected_uid("whisper"), Some(65532));
        assert_eq!(expected_uid("piper"), Some(65532));
        assert_eq!(VOICE_SERVICES, ["whisper", "piper"]);
    }

    #[test]
    fn both_doors_as_nonroot_pass() {
        let c = voice_images_check(true, &voice(VoiceUid::Live(65532), VoiceUid::Live(65532)), &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("65532"), "{}", c.detail);
    }

    #[test]
    fn a_pre_i105_root_image_fails_naming_the_door() {
        // What v0.6.4's images measured: uid=0.
        let c = voice_images_check(true, &voice(VoiceUid::Live(65532), VoiceUid::Live(0)), &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("piper runs as root"), "{}", c.detail);
        assert!(!c.detail.contains("whisper"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().starts_with("noo upgrade --stack"), "{:?}", c.remedy);
    }

    #[test]
    fn root_wins_over_an_unreadable_key_check() {
        // A root process reads anything: the uid is the finding, not the key.
        let c = voice_images_check(true, &voice(VoiceUid::Live(0), VoiceUid::Live(0)), &|_, _| Some(false));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("whisper runs as root") && c.detail.contains("piper runs as root"), "{}", c.detail);
        assert!(!c.detail.contains("cannot read"), "{}", c.detail);
    }

    #[test]
    fn another_uid_fails() {
        let c = voice_images_check(true, &voice(VoiceUid::Live(1000), VoiceUid::Live(65532)), &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("whisper runs as uid 1000, but its key is handed to uid 65532"), "{}", c.detail);
    }

    #[test]
    fn a_key_the_uid_cannot_read_fails_with_fix_modes() {
        let c = voice_images_check(true, &voice(VoiceUid::Live(65532), VoiceUid::Live(65532)), &|svc, _| Some(svc != "whisper"));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("whisper (uid 65532) cannot read services/whisper/service.key"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().starts_with("noo security pki fix-modes"), "{:?}", c.remedy);
    }

    #[test]
    fn an_absent_key_is_not_a_failure() {
        let c = voice_images_check(true, &voice(VoiceUid::Live(65532), VoiceUid::Live(65532)), &|_, _| None);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    #[test]
    fn voice_on_but_not_running_is_a_warning_not_a_pass() {
        for (w, p, want) in [
            (VoiceUid::Missing, VoiceUid::Live(65532), "whisper has no container"),
            (VoiceUid::Live(65532), VoiceUid::Stopped, "piper is not running"),
            (VoiceUid::Unreadable("docker exec id -u failed: x".into()), VoiceUid::Live(65532), "whisper is running but its live uid could not be read"),
        ] {
            let c = voice_images_check(true, &voice(w, p), &|_, _| Some(true));
            assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
            assert!(c.detail.contains(want), "{}", c.detail);
        }
    }

    #[test]
    fn a_root_door_fails_even_when_the_other_is_unjudged() {
        let c = voice_images_check(true, &voice(VoiceUid::Stopped, VoiceUid::Live(0)), &|_, _| Some(true));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
    }

    #[test]
    fn the_voice_live_uid_reader_is_the_busybox_safe_one() {
        // `docker exec id -u` first; `docker top` only when exec fails.
        let calls = std::cell::RefCell::new(Vec::<String>::new());
        let docker = |a: &[&str]| -> Result<String, String> {
            calls.borrow_mut().push(a.join(" "));
            Ok("65532\n".into())
        };
        assert_eq!(live_uid_via(&docker, "noo-piper"), Ok(65532));
        assert_eq!(*calls.borrow(), vec!["exec noo-piper id -u".to_string()]);
    }

    // ── voice models (i105) ──

    fn pair(w: bool, p: bool) -> Vec<(String, bool)> {
        vec![("whisper:base".into(), w), ("piper:en_US-lessac-medium".into(), p)]
    }

    #[test]
    fn voice_models_off_is_not_checked() {
        let c = voice_models_check(false, "/s/voice", &pair(false, false), &[("whisper", Some(false))]);
        assert_eq!((c.verdict, c.detail.as_str(), c.name), (Verdict::Ok, "voice off — not checked", "voice models"));
    }

    #[test]
    fn staged_and_offline_passes() {
        let c = voice_models_check(true, "/s/voice", &pair(true, true), &[("whisper", Some(true)), ("piper", Some(true))]);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("whisper:base and piper:en_US-lessac-medium staged under /s/voice"), "{}", c.detail);
    }

    #[test]
    fn a_model_not_staged_fails_with_the_exact_pull() {
        let c = voice_models_check(true, "/s/voice", &pair(true, false), &[("whisper", Some(true)), ("piper", Some(true))]);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("not staged under /s/voice: piper:en_US-lessac-medium"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo models pull piper:en_US-lessac-medium"));
        let c = voice_models_check(true, "/s/voice", &pair(false, false), &[]);
        assert_eq!(c.remedy.as_deref(), Some("noo models pull whisper:base && noo models pull piper:en_US-lessac-medium"));
    }

    #[test]
    fn a_container_that_may_fetch_fails() {
        let c = voice_models_check(true, "/s/voice", &pair(true, true), &[("whisper", Some(false)), ("piper", Some(true))]);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("whisper run(s) without HF_HUB_OFFLINE=1"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().starts_with("noo upgrade --stack"));
    }

    #[test]
    fn no_container_to_read_is_a_warning() {
        let c = voice_models_check(true, "/s/voice", &pair(true, true), &[("whisper", Some(true)), ("piper", None)]);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("no piper container"), "{}", c.detail);
    }

    #[test]
    fn the_offline_flag_is_read_from_the_container_env() {
        assert_eq!(env_is_offline(r#"["PATH=/usr/bin","HF_HUB_OFFLINE=1","TRANSFORMERS_OFFLINE=1"]"#), Some(true));
        assert_eq!(env_is_offline(r#"["PATH=/usr/bin","HF_HUB_OFFLINE=0"]"#), Some(false));
        assert_eq!(env_is_offline("[]\n"), Some(false));
        assert_eq!(env_is_offline("not json"), None);
    }
}
