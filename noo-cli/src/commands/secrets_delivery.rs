// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Where the stack's secrets actually ARE — checked against the running
//! containers, never assumed from the compose file.
//!
//! Since 2026-09-29 noomesh's own containers (gateway, worker, redis,
//! postgres, grafana, browser) receive every tier-1 secret as a FILE under
//! `/run/secrets` — and, since an earlier release, the tier-2 provider and
//! channel credentials too; since an earlier release the add-on containers
//! (noo-trellion, noo-trellion-intel, noo-evolve) do the same — delivered by
//! compose from the launcher's environment, and nothing else holds a copy. The operator's rule is "always sops, never
//! plaintext", and the worry that goes with it is "something just lying
//! about". Two checks answer it from the live box:
//!
//! * [`secrets_not_in_env_row`] — the `noo cluster verify --controller` row
//!   `secrets not in env`. For every running container of this stack it
//!   reads the NAMES of the non-empty environment variables (the docker
//!   template splits at `=` and drops the value inside the docker CLI — no
//!   value ever reaches this process) and fails on any file-backed name, or any
//!   `*_PASSWORD`/`*_SECRET`/`*_TOKEN`/`*_KEY` name not on the reasoned
//!   allow-list below. The containerised node agent reads `_FILE` since
//!   the file-backed secrets change, and nats has no secret env, so
//!   both FAIL like the rest. It also fails on any
//!   file under `secrets/` other than the encrypted store: the launcher
//!   writes nothing there any more, so anything else is residue.
//! * [`file_delivery_findings`] — appended to `noo security secrets audit`:
//!   every file the compose file delivers is present in its consumer
//!   (`docker diff` lists the added path; the file is never read), and a
//!   `<NAME>_FILE` pointer never names a file that is not there.

use crate::commands::cluster_verify::{Check, Verdict};
use crate::commands::secrets::{Finding, Severity};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// Every file-backed name: the union of the two readers' `FILE_BACKED_SECRETS`
/// (gateway-rust/src/secret_env.rs, src/noomesh/secret_env.py) plus the
/// superuser password postgres reads natively — the tier-1 secrets the stack
/// mints AND, since an earlier release, the tier-2 provider and channel
/// credentials. None of these may be a plain, non-empty environment variable
/// in a noomesh-owned container. tests/test_compose_secret_files.py pins
/// this list to the two manifests. (The name is historical.)
pub(crate) const TIER1: &[&str] = &[
    "NOO_JWT_SECRET",
    "NOO_CLUSTER_SECRET",
    "NOO_CONTROLLER_SECRET",
    // The bus-principal keys: the gateway's three, and the
    // one each verifier reads as NOO_BUS_KEY.
    "NOO_BUS_KEY_WORKER",
    "NOO_BUS_KEY_TRELLION",
    "NOO_BUS_KEY_TRELLION_INTEL",
    "NOO_BUS_KEY",
    // The browser door's own key.
    "NOO_BROWSER_KEY",
    "NOO_NODE_AGENT_TOKEN",
    "NOO_ADMIN_PASSWORD",
    "NOO_AUDIT_HMAC_KEY",
    "REDIS_PASSWORD",
    "NOO_TAILSCALE_OAUTH_CLIENT_SECRET",
    "NOO_TAILSCALE_API_KEY",
    "NOO_AGENT_REVIEW_KEY",
    "NOO_AGENT_SIGNING_KEY",
    "NOO_JWT_SIGNING_KEY",
    "NOO_ENTITLEMENT",
    "NOO_APP_DB_PASSWORD",
    "NOO_EVOLVE_DB_PASSWORD",
    "NOO_EVOLVE_DDL_PASSWORD",
    "NOO_TRELLION_DB_PASSWORD",
    "NOO_TRELLION_DDL_PASSWORD",
    // Declared systems' flags and passwords, one KEY=VALUE file (gateway).
    "NOO_SYSTEMS_SECRETS",
    "NATS_GATEWAY_PASSWORD",
    "NATS_WORKER_PASSWORD",
    // An add-on's own bus password (noo-trellion, noo-trellion-intel).
    "NATS_ADDON_PASSWORD",
    // The Go node agent's own bus password.
    "NATS_NODE_PASSWORD",
    "NOO_GATEWAY_KEY",
    "POSTGRES_PASSWORD",
    // Tier-2: issued by a provider, delivered as files.
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "TAVILY_API_KEY",
    "BRAVE_SEARCH_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "WHATSAPP_TOKEN",
    "GOOGLE_CHAT_BEARER_TOKEN",
    "GOOGLE_CHAT_CREDENTIALS_JSON",
];

/// Credential-SHAPED names that are allowed as plain environment, each with
/// its reason. Anything shaped like a credential and not here is a FAIL.
pub(crate) const ENV_ALLOWED: &[(&str, &str)] = &[
    ("NOO_TLS_KEY", "a PATH to the PEM, not the key"),
    ("NOO_EVOLVE_TLS_KEY", "a PATH to evolve's listener PEM, not the key"),
    ("GF_SERVER_CERT_KEY", "a PATH to the PEM, not the key"),
    ("NOO_GRAFANA_SSO_KEY", "a PATH to the PEM, not the key"),
    ("GF_SECURITY_ADMIN_PASSWORD", "a `$__file{/run/secrets/…}` pointer Grafana expands itself, not the password"),
    ("GPG_KEY", "an upstream image's public release-signing key fingerprint"),
    // The provider/channel keys (ANTHROPIC_API_KEY, TAVILY_API_KEY,
    // TELEGRAM_BOT_TOKEN, …) are NOT here any more: they are file-backed
    // (TIER1 above) and a plain one FAILS. What stays env is the model-hub
    // token, and only in containers that are not noomesh code.
    (
        "HF_TOKEN",
        "model-hub token read natively (huggingface_hub) by third-party images — vllm, tei, reranker, \
         whisper — and handed by the Go node agent to the backends it starts; no noomesh-owned \
         container receives it",
    ),
    (
        "HUGGING_FACE_HUB_TOKEN",
        "the legacy spelling of HF_TOKEN, read natively by the same third-party images",
    ),
];

/// Compose services whose images do not read `_FILE`. None remain: nats
/// left with an earlier release (its server expanded the shared pair only for the
/// retired legacy principal) and the containerised node agent with 1252 §2
/// (the Go agent reads `_FILE`). Their env secrets are
/// WARN — never OK, never silently skipped, never FAIL.
///
/// `nats` left this list with an earlier release: its server expanded
/// `$NATS_USER` / `$NATS_PASSWORD` only for the legacy shared principal, and
/// the renderer no longer emits one. A nats container still carrying
/// `NATS_PASSWORD` is one created from a pre-536 compose — it FAILs, and the
/// recreate is the fix.
///
/// The add-ons (trellion, trellion-intel, noo-evolve) left this list with
/// Their images read `_FILE` since stack-v0.2.80 and the
/// overlays deliver files, so a plain secret on one FAILS like any other.
pub(crate) const DEFERRED_SERVICES: &[&str] = &[];

/// The login signing secret, and the ONE compose service allowed to hold it
/// HS256: whoever can verify a login can forge one, so a
/// copy anywhere else — even as a `/run/secrets` file behind a
/// `NOO_JWT_SECRET_FILE` pointer, which the env-name rule above accepts —
/// is a FAIL. Workers act as a user with the per-dispatch token the gateway
/// mints (gateway-rust/src/worker_delegation.rs).
pub(crate) const JWT_SECRET: &str = "NOO_JWT_SECRET";
pub(crate) const JWT_SECRET_HOLDER: &str = "gateway";

/// Does this container hold the login signing secret it must not?
fn holds_jwt_secret_off_gateway(h: &Holder) -> bool {
    h.service != JWT_SECRET_HOLDER
        && h.env_names.iter().any(|n| n == JWT_SECRET || n.strip_suffix("_FILE") == Some(JWT_SECRET))
}

/// Files the CLI itself writes under `secrets/` and that hold no secret
/// value: the rotation ledger (key names and times) and the reveal audit log
/// (names, times, digests). Taken from the writers' own consts, so a file the
/// CLI writes can never be judged residue — the v0.2.80 rehearsal FAILED this
/// row on `secrets/rotations.json` and told the operator to shred it.
pub(crate) const CLI_WRITTEN_UNDER_SECRETS: &[&str] =
    &[super::secrets::ROTATION_LEDGER, super::secrets_reveal::REVEAL_AUDIT_LOG];

/// Files under `secrets/` that are allowed to exist: the encrypted store, its
/// encrypted `.bak_*` rotations, and the CLI's own value-free records above.
/// Anything else is plaintext residue until shown otherwise.
fn allowed_in_secrets_dir(rel: &str) -> bool {
    let Some(name) = rel.strip_prefix("secrets/") else { return false };
    name == "env.sops"
        || name.starts_with("env.sops.bak_")
        || CLI_WRITTEN_UNDER_SECRETS.contains(&name)
        // The store's re-encrypted copy mid-rotation (`.env.sops.rotating.<pid>`):
        // ciphertext, and gone when the rotation finishes. The `.plain.` and
        // `.verify.` siblings are plaintext and stay residue.
        || (name.starts_with('.') && name.contains(super::secrets::ROTATING_INFIX))
}

/// Is `name` credential-shaped (the four suffixes the rule names)?
pub(crate) fn credential_shaped(name: &str) -> bool {
    ["_PASSWORD", "_SECRET", "_TOKEN", "_KEY"].iter().any(|s| name.ends_with(s))
}

/// One running container: its name, its compose service, and the NAMES of
/// its non-empty environment variables.
#[derive(Debug, Clone)]
pub(crate) struct Holder {
    pub container: String,
    pub service: String,
    pub env_names: Vec<String>,
}

/// The remedy for a FAIL: the recreate when a container carries a secret in
/// env, and a `shred -u` naming ONLY the files judged residue — never a
/// blanket "any file under secrets/", which would take the store's own
/// records with it (rotation ledger, reveal audit log).
fn residue_remedy(env_failed: bool, leftovers: &[&String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    if env_failed {
        parts.push("restore the shipped compose file and recreate (noo stack restart --force)".into());
    }
    if !leftovers.is_empty() {
        parts.push(format!(
            "shred -u {} — only files that hold a plaintext secret (a passphrase, a `.plain.` file); \
             the store, its `.bak_*` copies, `rotations.json` and `reveal-audit.log` belong there",
            leftovers.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")
        ));
    }
    parts.join("; ")
}

/// The judgement, pure. `residue` is every repo-relative file under
/// `secrets/` (the allowed ones are filtered here).
pub(crate) fn judge(holders: &[Holder], residue: &[String]) -> Check {
    const NAME: &str = "secrets not in env";
    let mut fails: Vec<String> = Vec::new();
    let mut deferred: Vec<String> = Vec::new();
    for h in holders {
        let offenders: Vec<&str> = h
            .env_names
            .iter()
            .map(String::as_str)
            .filter(|n| TIER1.contains(n) || (credential_shaped(n) && !ENV_ALLOWED.iter().any(|(a, _)| a == n)))
            .collect();
        if offenders.is_empty() {
            continue;
        }
        let line = format!("{}: {}", h.container, offenders.join(", "));
        if DEFERRED_SERVICES.contains(&h.service.as_str()) {
            deferred.push(line);
        } else {
            fails.push(line);
        }
    }
    let jwt_off_gateway: Vec<&str> =
        holders.iter().filter(|h| holds_jwt_secret_off_gateway(h)).map(|h| h.container.as_str()).collect();
    if !jwt_off_gateway.is_empty() {
        fails.push(format!(
            "{JWT_SECRET} reaches {} — only the gateway may hold the login signing secret",
            jwt_off_gateway.join(", ")
        ));
    }
    let env_failed = !fails.is_empty();
    let leftovers: Vec<&String> = residue.iter().filter(|r| !allowed_in_secrets_dir(r)).collect();
    if !leftovers.is_empty() {
        fails.push(format!(
            "plaintext left under secrets/: {}",
            leftovers.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    if holders.is_empty() && fails.is_empty() {
        return Check {
            name: NAME,
            verdict: Verdict::Warn,
            detail: "no running container of this stack found — nothing to judge, which is not the same as nothing lying about".into(),
            remedy: Some("noo stack status".into()),
        };
    }
    if !fails.is_empty() {
        return Check {
            name: NAME,
            verdict: Verdict::Fail,
            detail: format!("a file-backed secret is a plain environment variable or a file is lying about — {}", fails.join("; ")),
            remedy: Some(residue_remedy(env_failed, &leftovers)),
        };
    }
    if !deferred.is_empty() {
        return Check {
            name: NAME,
            verdict: Verdict::Warn,
            detail: format!(
                "noomesh's own, the add-on and the node-agent containers hold no secret in env — {}",
                deferred.join("; ")
            ),
            remedy: None,
        };
    }
    Check {
        name: NAME,
        verdict: Verdict::Ok,
        detail: format!(
            "{} container(s), add-ons included: no secret — tier-1 or provider/channel key — in any environment, nothing under secrets/ but the store",
            holders.len(),
        ),
        remedy: None,
    }
}

// ── docker access (names only) ─────────────────────────────────────────────

/// The docker template that prints the NAME of every non-empty environment
/// variable, one per line. The value is split off and dropped inside the
/// docker CLI; it never reaches this process.
const ENV_NAMES_TEMPLATE: &str =
    r#"{{range .Config.Env}}{{$p := split . "="}}{{if index $p 1}}{{index $p 0}}{{"\n"}}{{end}}{{end}}"#;

/// Names of `container`'s non-empty environment variables, or None when
/// docker cannot inspect it.
pub(crate) fn env_names(container: &str) -> Option<Vec<String>> {
    let out = Command::new("docker").args(["inspect", "-f", ENV_NAMES_TEMPLATE, container]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// The compose project this stack runs under, read off whichever of its
/// always-on containers exists.
pub(crate) fn stack_project() -> Option<String> {
    for svc in ["gateway", "postgres", "worker", "redis"] {
        let out = Command::new("docker")
            .args(["inspect", "-f", r#"{{index .Config.Labels "com.docker.compose.project"}}"#, &crate::envfile::container(svc)])
            .output()
            .ok()?;
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && !p.is_empty() && p != "<no value>" {
            return Some(p);
        }
    }
    None
}

/// Every RUNNING container of compose project `project`, with the names of
/// its non-empty environment variables.
pub(crate) fn holders_in(project: &str) -> Vec<Holder> {
    let Ok(out) = Command::new("docker")
        .args([
            "ps",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--format",
            r#"{{.Names}}	{{.Label "com.docker.compose.service"}}"#,
        ])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (name, svc) = l.split_once('\t')?;
            Some(Holder { container: name.to_string(), service: svc.to_string(), env_names: env_names(name)? })
        })
        .collect()
}

/// Every file under `<root>/secrets/`, repo-relative — the runtime-residue
/// walk `security_local` already owns for `secrets/.runtime`, widened to the
/// whole directory.
pub(crate) fn secrets_dir_files(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else if let Ok(rel) = p.strip_prefix(root) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
    let mut out = crate::commands::security_local::runtime_residue_files(root);
    walk(&root.join("secrets"), root, &mut out);
    out.sort();
    out.dedup();
    out
}

/// The `secrets not in env` row, against the live box (or a named compose
/// project — the scratch proof points it at one).
pub fn secrets_not_in_env_row() -> Check {
    let project = std::env::var("NOO_VERIFY_COMPOSE_PROJECT").ok().filter(|p| !p.is_empty()).or_else(stack_project);
    let holders = project.as_deref().map(holders_in).unwrap_or_default();
    judge(&holders, &secrets_dir_files(&crate::envfile::repo_root()))
}

// ── shared secrets: every holder its own key ────────────────

/// The bus-principal verifiers and the audience each is, by compose service
/// (`gateway-rust/src/bus_principal.rs` AUDIENCES). worker-extra is
/// noo-worker scaled and is the `worker` audience.
pub(crate) const BUS_VERIFIERS: &[(&str, &str)] = &[
    ("worker", "worker"),
    ("worker-extra", "worker"),
    ("trellion", "trellion"),
    ("trellion-intel", "trellion-intel"),
];

/// The services that hold the fleet secret by design: the gateway (it
/// verifies node tokens) and the containerised node agents (they are nodes).
/// Since an earlier release nothing else may: the browser door has its own key.
pub(crate) const FLEET_HOLDERS_BY_DESIGN: &[&str] = &["gateway", "node-agent", "node-agent-sensors"];

/// The services that hold the browser door's key (`NOO_BROWSER_KEY`): the
/// gateway and the worker sign with it, the browser verifies with it.
pub(crate) const BROWSER_KEY_HOLDERS: &[&str] = &["gateway", "worker", "worker-extra", "browser"];

/// Every per-service key added since, judged distinct in the store.
pub(crate) const STORE_PER_SERVICE_KEYS: &[&str] =
    &["NOO_BUS_KEY_WORKER", "NOO_BUS_KEY_TRELLION", "NOO_BUS_KEY_TRELLION_INTEL", "NOO_BROWSER_KEY"];

/// The bus PASSWORDS judged distinct in the store (i70 residue): each NATS
/// principal on the controller presents its own. Not required to be set —
/// the `nats principals` row owns "is it rendered" — but two that are set
/// and equal are one principal.
pub(crate) const STORE_NATS_PASSWORDS: &[&str] =
    &["NATS_GATEWAY_PASSWORD", "NATS_WORKER_PASSWORD", "NATS_TRELLION_PASSWORD", "NATS_TRELLION_INTEL_PASSWORD"];

/// The `/run/secrets` target an add-on's own NATS password is delivered to
/// (compose `NATS_ADDON_PASSWORD_FILE`). The same target in each add-on:
/// trellion-intel re-sources it from its own password, as it does the bus key.
pub(crate) const ADDON_NATS_TARGET: &str = "nats_addon_password";

/// The store key for one add-on audience's NATS password:
/// `NATS_<AUD>_PASSWORD` (`trellion-intel` → `NATS_TRELLION_INTEL_PASSWORD`).
pub(crate) fn nats_store_key(audience: &str) -> String {
    format!("NATS_{}_PASSWORD", audience.to_ascii_uppercase().replace('-', "_"))
}

/// The store key for one audience: `NOO_BUS_KEY_<AUD>`.
pub(crate) fn bus_store_key(audience: &str) -> String {
    format!("NOO_BUS_KEY_{}", audience.to_ascii_uppercase().replace('-', "_"))
}

/// The gateway's `/run/secrets` target for one audience: `noo_bus_key_<aud>`.
pub(crate) fn gateway_bus_target(audience: &str) -> String {
    bus_store_key(audience).to_ascii_lowercase()
}

/// The gateway's pointer for one audience's key: `NOO_BUS_KEY_<AUD>_FILE`.
pub(crate) fn gateway_bus_pointer(audience: &str) -> String {
    format!("{}_FILE", bus_store_key(audience))
}

/// Everything the `shared secrets` row is judged on for ONE running
/// container. Never a value: env NAMES, the one non-secret value
/// `NOO_BUS_AUDIENCE`, the NAMES under `/run/secrets`, and salted digests of
/// the bus-key files (per-run salt, the same one the store side uses).
#[derive(Debug, Clone, Default)]
pub(crate) struct SecretFacts {
    pub container: String,
    pub service: String,
    pub env_names: Vec<String>,
    pub audience: Option<String>,
    /// `None` = the directory could not be read (that is not a pass).
    pub run_secrets: Option<Vec<String>>,
    /// target → salted digest, for the `noo_bus_key*` files only.
    pub digests: BTreeMap<String, String>,
}

/// The store side: salted digests (same salt) of the bus keys and the two
/// shared secrets they must differ from. `None` = could not be read.
pub(crate) type StoreDigests = Option<BTreeMap<String, String>>;

fn holds_name(f: &SecretFacts, env: &[&str], file: &str) -> bool {
    env.iter().any(|n| f.env_names.iter().any(|e| e == n))
        || f.run_secrets.as_ref().is_some_and(|r| r.iter().any(|x| x == file))
}

/// The `shared secrets` row, pure.
///
/// FAIL when:
/// * the controller secret reaches any container but the gateway — by
///   `NOO_CONTROLLER_SECRET`, its `_FILE` pointer, the `NOO_SECRET_` spelling,
///   or a bare `/run/secrets/noo_controller_secret`;
/// * a running bus verifier has no key of its own (pointer, file, audience),
///   names the wrong audience, holds another audience's key, or holds a file
///   whose digest is not its audience's key in the store;
/// * the gateway lacks, or holds a wrong copy of, a running audience's key;
/// * the store's three bus keys are not set, or are not distinct from each
///   other and from NOO_CONTROLLER_SECRET / NOO_CLUSTER_SECRET;
/// * nothing could be judged (no containers, an unreadable `/run/secrets`,
///   an unreadable store) — this row is never softened into a WARN for
///   lack of evidence.
///
/// * the FLEET secret reaches anything but the gateway and the node agents
///   (the browser door has its own key since the operator's decision on
///   review H1), or the browser door's key reaches anything but its
///   holders, or a copy of it differs from the store's.
pub(crate) fn shared_secrets_check(facts: &[SecretFacts], store: &StoreDigests) -> Check {
    const NAME: &str = "shared secrets";
    let fail = |detail: String| Check {
        name: NAME,
        verdict: Verdict::Fail,
        detail,
        remedy: Some("noo upgrade --stack   # mints any bus key the store lacks and recreates every holder".into()),
    };
    if facts.is_empty() {
        return fail("not judged: no running container of this stack was found — nothing here may read as a pass".into());
    }
    let mut fails: Vec<String> = Vec::new();

    let mut warns: Vec<String> = Vec::new();

    // The store: three distinct bus keys, none equal to a shared secret.
    match store {
        None => fails.push("not judged: the encrypted store could not be read for digests".into()),
        Some(d) => {
            let mut seen: Vec<(&str, &String)> = Vec::new();
            for key in STORE_PER_SERVICE_KEYS {
                let Some(v) = d.get(*key) else {
                    fails.push(format!("{key} is not set in the store"));
                    continue;
                };
                if let Some((other, _)) = seen.iter().find(|(_, dv)| *dv == v) {
                    fails.push(format!("{key} equals {other} in the store — two holders sharing a key are one holder"));
                }
                for shared in ["NOO_CONTROLLER_SECRET", "NOO_CLUSTER_SECRET"] {
                    if d.get(shared) == Some(v) {
                        fails.push(format!("{key} equals {shared} in the store"));
                    }
                }
                seen.push((key, v));
            }
            // Each controller-side NATS principal its own password.
            let mut seen: Vec<(&str, &String)> = Vec::new();
            for key in STORE_NATS_PASSWORDS {
                let Some(v) = d.get(*key) else { continue };
                if let Some((other, _)) = seen.iter().find(|(_, dv)| *dv == v) {
                    fails.push(format!("{key} equals {other} in the store — two bus principals sharing a password are one principal"));
                }
                seen.push((key, v));
            }
        }
    }

    // The controller secret: the gateway alone.
    let ctl: Vec<&str> = facts
        .iter()
        .filter(|f| f.service != "gateway")
        .filter(|f| holds_name(f, &["NOO_CONTROLLER_SECRET", "NOO_CONTROLLER_SECRET_FILE", "NOO_SECRET_NOO_CONTROLLER_SECRET"], "noo_controller_secret"))
        .map(|f| f.container.as_str())
        .collect();
    if !ctl.is_empty() {
        fails.push(format!("NOO_CONTROLLER_SECRET still reaches {} — only the gateway may hold it", ctl.join(", ")));
    }

    // Every running verifier: its own key, its own audience, nothing else.
    let mut audiences: Vec<&str> = Vec::new();
    let mut verifiers = 0usize;
    for f in facts {
        let Some((_, aud)) = BUS_VERIFIERS.iter().find(|(svc, _)| *svc == f.service) else { continue };
        verifiers += 1;
        if !audiences.contains(aud) {
            audiences.push(aud);
        }
        let Some(files) = &f.run_secrets else {
            fails.push(format!("not judged: {}'s /run/secrets could not be read", f.container));
            continue;
        };
        if !f.env_names.iter().any(|e| e == "NOO_BUS_KEY_FILE") || !files.iter().any(|x| x == "noo_bus_key") {
            fails.push(format!("{} holds no bus key of its own (NOO_BUS_KEY_FILE → /run/secrets/noo_bus_key) — it refuses every worker.* message", f.container));
        }
        if f.audience.as_deref() != Some(aud) {
            fails.push(format!("{} names audience {:?}, not `{aud}`", f.container, f.audience.as_deref().unwrap_or("")));
        }
        let foreign: Vec<String> = f.env_names.iter().filter(|n| *n != "NOO_BUS_KEY_FILE" && n.starts_with("NOO_BUS_KEY_")).cloned()
            .chain(files.iter().filter(|x| x.starts_with("noo_bus_key_")).cloned())
            .collect();
        if !foreign.is_empty() {
            fails.push(format!("{} holds another audience's key: {}", f.container, foreign.join(", ")));
        }
        if files.iter().any(|x| x == "noo_bus_key") && !f.digests.contains_key("noo_bus_key") {
            fails.push(format!("not judged: {}'s /run/secrets/noo_bus_key could not be digested", f.container));
        }
        if let (Some(d), Some(Some(want))) = (f.digests.get("noo_bus_key"), store.as_ref().map(|s| s.get(&bus_store_key(aud)))) {
            if d != want {
                fails.push(format!("{}'s /run/secrets/noo_bus_key is not {} from the store (a stale or foreign copy)", f.container, bus_store_key(aud)));
            }
        }
    }

    // Each add-on's OWN bus password (i70 residue): only an add-on holds
    // one, and the one it holds is its own. Absent is the one-release
    // fallback (it presents the worker) — the `nats principals` row warns.
    let mut own_nats: Vec<&str> = Vec::new();
    for f in facts {
        let Some(files) = &f.run_secrets else { continue };
        if !files.iter().any(|x| x == ADDON_NATS_TARGET) {
            continue;
        }
        let aud = BUS_VERIFIERS.iter().find(|(svc, _)| *svc == f.service).map(|(_, a)| *a).filter(|a| *a != "worker");
        let Some(aud) = aud else {
            fails.push(format!("{} holds an add-on's NATS password (/run/secrets/{ADDON_NATS_TARGET}) — only an add-on may", f.container));
            continue;
        };
        let Some(d) = f.digests.get(ADDON_NATS_TARGET) else {
            fails.push(format!("not judged: {}'s /run/secrets/{ADDON_NATS_TARGET} could not be digested", f.container));
            continue;
        };
        let Some(st) = store.as_ref() else { continue };
        let want = nats_store_key(aud);
        if st.get(&want) == Some(d) {
            own_nats.push(aud);
            continue;
        }
        match STORE_NATS_PASSWORDS.iter().find(|k| st.get(**k) == Some(d)) {
            // trellion-intel `extends` trellion: a bundle that predates its own
            // principal inherits trellion's file. Its worker pool refuses to
            // present it (not its audience) — held, never presented.
            Some(k) if aud == "trellion-intel" && *k == "NATS_TRELLION_PASSWORD" => warns.push(format!(
                "{} holds {k}, not {want} — inherited from the trellion service by a bundle that predates \
                 its own principal; it presents the worker instead (`noo addons upgrade trellion_intel`)",
                f.container
            )),
            Some(k) => fails.push(format!("{} holds {k} as its add-on NATS password, not {want}", f.container)),
            None => fails.push(format!("{}'s /run/secrets/{ADDON_NATS_TARGET} is not {want} from the store (a stale or foreign copy)", f.container)),
        }
    }

    // The gateway: a correct copy of every running audience's key.
    match facts.iter().find(|f| f.service == "gateway") {
        None => fails.push("not judged: no running gateway".into()),
        Some(g) => match &g.run_secrets {
            None => fails.push(format!("not judged: {}'s /run/secrets could not be read", g.container)),
            Some(files) => {
                for aud in &audiences {
                    let target = gateway_bus_target(aud);
                    if !files.contains(&target) || !g.env_names.contains(&gateway_bus_pointer(aud)) {
                        fails.push(format!("{} cannot sign for {aud} (no {})", g.container, gateway_bus_pointer(aud)));
                    } else if !g.digests.contains_key(&target) {
                        fails.push(format!("not judged: {}'s /run/secrets/{target} could not be digested", g.container));
                    } else if let (Some(d), Some(Some(want))) = (g.digests.get(&target), store.as_ref().map(|s| s.get(&bus_store_key(aud)))) {
                        if d != want {
                            fails.push(format!("{}'s {target} is not {} from the store", g.container, bus_store_key(aud)));
                        }
                    }
                }
            }
        },
    }

    // The fleet secret: a node's credential, nowhere else
    // operator's decision on review H1 — the browser door has its own key).
    let fleet: Vec<&str> = facts
        .iter()
        .filter(|f| !FLEET_HOLDERS_BY_DESIGN.contains(&f.service.as_str()))
        .filter(|f| {
            // The browser's one-release bridge: NOO_CLUSTER_SECRET_FILE points
            // at its OWN key there (compose), so for the browser the pointer
            // name proves nothing — the fleet secret's FILE is what counts.
            let env: &[&str] = if f.service == "browser" {
                &["NOO_CLUSTER_SECRET", "NOO_SECRET_NOO_CLUSTER_SECRET"]
            } else {
                &["NOO_CLUSTER_SECRET", "NOO_CLUSTER_SECRET_FILE", "NOO_SECRET_NOO_CLUSTER_SECRET"]
            };
            holds_name(f, env, "noo_cluster_secret")
        })
        .map(|f| f.container.as_str())
        .collect();
    if !fleet.is_empty() {
        fails.push(format!("the FLEET secret (every node's credential) still reaches {} — only the gateway and the node agents may hold it", fleet.join(", ")));
    }

    // The browser door's key: its holders only, each a true copy.
    for f in facts {
        let holds = holds_name(f, &["NOO_BROWSER_KEY", "NOO_BROWSER_KEY_FILE", "NOO_SECRET_NOO_BROWSER_KEY"], "noo_browser_key");
        if holds && !BROWSER_KEY_HOLDERS.contains(&f.service.as_str()) {
            fails.push(format!("{} holds the browser door's key — only {} may", f.container, BROWSER_KEY_HOLDERS.join(", ")));
        }
        let has_file = f.run_secrets.as_ref().is_some_and(|r| r.iter().any(|x| x == "noo_browser_key"));
        if has_file && BROWSER_KEY_HOLDERS.contains(&f.service.as_str()) && !f.digests.contains_key("noo_browser_key") {
            fails.push(format!("not judged: {}'s /run/secrets/noo_browser_key could not be digested", f.container));
        }
        if let (Some(d), Some(Some(want))) = (f.digests.get("noo_browser_key"), store.as_ref().map(|s| s.get("NOO_BROWSER_KEY"))) {
            if d != want {
                fails.push(format!("{}'s /run/secrets/noo_browser_key is not NOO_BROWSER_KEY from the store", f.container));
            }
        }
    }
    if let Some(b) = facts.iter().find(|f| f.service == "browser") {
        if !holds_name(b, &["NOO_BROWSER_KEY_FILE"], "noo_browser_key") {
            fails.push(format!("{} holds no browser key — its door answers 503", b.container));
        }
    }

    if !fails.is_empty() {
        return fail(format!("a secret is still shared, or not shown not to be — {}", fails.join("; ")));
    }
    let mine = format!(
        "the controller secret is held by the gateway alone, the fleet secret by the gateway and the node agents \
         alone; {verifiers} bus verifier(s) each hold their own key ({}), each add-on its own bus password ({}), \
         and the browser door its own — digest-checked against four distinct store keys and distinct bus passwords",
        if audiences.is_empty() { "none running".to_string() } else { audiences.join(", ") },
        if own_nats.is_empty() { "none yet: the worker's, the one-release fallback".to_string() } else { own_nats.join(", ") },
    );
    if !warns.is_empty() {
        return Check {
            name: NAME,
            verdict: Verdict::Warn,
            detail: format!("{mine}; but {}", warns.join("; ")),
            remedy: Some("noo addons upgrade trellion_intel   # a bundle that re-sources nats_addon_password from its own key".into()),
        };
    }
    Check { name: NAME, verdict: Verdict::Ok, detail: mine, remedy: None }
}

// ── live probes for the row (names, one non-secret value, digests) ─────────

/// The value of `NOO_BUS_AUDIENCE` — the one non-secret value the row reads.
/// The template prints that variable and nothing else.
fn audience_of(container: &str) -> Option<String> {
    const T: &str = r#"{{range .Config.Env}}{{$p := split . "="}}{{if eq (index $p 0) "NOO_BUS_AUDIENCE"}}{{index $p 1}}{{end}}{{end}}"#;
    let out = Command::new("docker").args(["inspect", "-f", T, container]).output().ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

/// The `/run/secrets` files this row judges — the shared secrets it hunts
/// for and the per-service keys it digests. A FIXED list, so no other
/// secret's file is ever opened: each is stat'ed through the docker API
/// (`container_files::probe`, no content), and only the key files that exist
/// are copied out, ONE per `docker cp`, hashed with the per-run salt and
/// dropped. Values never leave this process.
pub(crate) const JUDGED_FILES: &[&str] = &[
    "noo_controller_secret",
    "noo_cluster_secret",
    "noo_bus_key",
    "noo_bus_key_worker",
    "noo_bus_key_trellion",
    "noo_bus_key_trellion_intel",
    "noo_browser_key",
    "nats_addon_password",
];

/// The judged files present in each container, and the salted digests of
/// the key files among them. A container whose stat could not be made maps
/// to `None` (not judged — never a pass).
/// What one container's probe found: the judged files present, and the
/// salted digests of the key files among them. `None` = not judged.
type ProbedSecrets = Option<(Vec<String>, BTreeMap<String, String>)>;

fn run_secrets_of_all(containers: &[String], salt: &str) -> BTreeMap<String, ProbedSecrets> {
    let wanted: BTreeMap<String, Vec<String>> = containers
        .iter()
        .map(|c| (c.clone(), JUDGED_FILES.iter().map(|f| format!("/run/secrets/{f}")).collect()))
        .collect();
    let probes = super::container_files::probe(&wanted);
    containers
        .iter()
        .map(|c| {
            let present: Option<Vec<String>> = match probes.get(c) {
                Some(super::container_files::Probe::Checked(paths)) => Some(
                    paths.iter().filter_map(|p| p.strip_prefix("/run/secrets/").map(str::to_string)).collect(),
                ),
                Some(super::container_files::Probe::Absent) => Some(Vec::new()),
                _ => None,
            };
            let facts = present.map(|names| {
                let mut digests = BTreeMap::new();
                for n in names.iter().filter(|n| n.starts_with("noo_bus_key") || n.as_str() == "noo_browser_key" || n.as_str() == ADDON_NATS_TARGET) {
                    if let Some(d) = digest_one(c, n, salt) {
                        digests.insert(n.clone(), d);
                    }
                }
                (names, digests)
            });
            (c.clone(), facts)
        })
        .collect()
}

/// `docker cp <c>:/run/secrets/<file> -` — one file's tar stream, hashed
/// with the salt and dropped. `None` when it cannot be read; the row then
/// FAILs "not judged" for that file.
fn digest_one(container: &str, file: &str, salt: &str) -> Option<String> {
    let out = Command::new("docker").args(["cp", &format!("{container}:/run/secrets/{file}"), "-"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    tar_names_and_bus_digests(&out.stdout, salt).1.remove(file)
}

/// Pure tar walk for [`digest_one`] (ustar headers; regular files only). A
/// body shorter than its header's size is skipped — truncated is undigested.
pub(crate) fn tar_names_and_bus_digests(tar: &[u8], salt: &str) -> (Vec<String>, BTreeMap<String, String>) {
    let mut names = Vec::new();
    let mut digests = BTreeMap::new();
    let mut at = 0usize;
    while at + 512 <= tar.len() {
        let h = &tar[at..at + 512];
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let field = |a: usize, b: usize| String::from_utf8_lossy(&h[a..b]).trim_end_matches('\0').trim().to_string();
        let name = field(0, 100);
        let size = usize::from_str_radix(field(124, 136).trim(), 8).unwrap_or(0);
        let kind = h[156];
        let body = at + 512;
        if kind == b'0' || kind == 0 {
            let base = name.rsplit('/').next().unwrap_or(&name).to_string();
            if !base.is_empty() {
                if (base.starts_with("noo_bus_key") || base == "noo_browser_key" || base == ADDON_NATS_TARGET) && body + size <= tar.len() {
                    let v = String::from_utf8_lossy(&tar[body..body + size]);
                    digests.insert(base.clone(), super::cluster_push_secrets::salted_digest(salt, v.trim_end_matches('\n')));
                }
                names.push(base);
            }
        }
        at = body + size.div_ceil(512) * 512;
    }
    names.sort();
    (names, digests)
}

/// Salted digests of the bus keys and the two shared secrets, from the store.
fn store_digests(salt: &str) -> StoreDigests {
    let store = crate::commands::secrets::SecretStore::load_sops(&crate::envfile::repo_root().join("secrets/env.sops")).ok()?;
    let mut out = BTreeMap::new();
    for k in STORE_PER_SERVICE_KEYS.iter().chain(STORE_NATS_PASSWORDS).chain(&["NOO_CONTROLLER_SECRET", "NOO_CLUSTER_SECRET"]) {
        if let Some(d) = store.salted_digest(k, salt) {
            out.insert(k.to_string(), d);
        }
    }
    Some(out)
}

/// The `shared secrets` row against the live box.
pub fn shared_secrets_row() -> Check {
    let project = std::env::var("NOO_VERIFY_COMPOSE_PROJECT").ok().filter(|p| !p.is_empty()).or_else(stack_project);
    let holders = project.as_deref().map(holders_in).unwrap_or_default();
    let salt = format!("{:x}{:x}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    let containers: Vec<String> = holders.iter().map(|h| h.container.clone()).collect();
    let mut probed = run_secrets_of_all(&containers, &salt);
    let facts: Vec<SecretFacts> = holders
        .into_iter()
        .map(|h| {
            let rs = probed.remove(&h.container).flatten();
            SecretFacts {
                audience: audience_of(&h.container),
                run_secrets: rs.as_ref().map(|(n, _)| n.clone()),
                digests: rs.map(|(_, d)| d).unwrap_or_default(),
                container: h.container,
                service: h.service,
                env_names: h.env_names,
            }
        })
        .collect();
    shared_secrets_check(&facts, &store_digests(&salt))
}

// ── secrets audit: every delivered file is present in its consumer ─────────

/// One file the compose file delivers: the consuming container, the target
/// under /run/secrets, and the environment variable that points at it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Delivery {
    pub service: String,
    pub container: String,
    pub target: String,
    pub pointer: Option<String>,
}

/// Every `(service, target, pointer)` in a compose file's text, for services
/// that name a fixed `container_name` (`${NOO_CONTAINER_PREFIX:-noo}-x` →
/// this instance's `container("x")`). The pointer is the environment
/// variable whose value names `/run/secrets/<target>` (e.g.
/// `NOO_JWT_SECRET_FILE`, `PGPASSFILE`).
pub(crate) fn deliveries(compose: &str) -> Vec<Delivery> {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(compose) else { return Vec::new() };
    let Some(services) = doc.get("services").and_then(|v| v.as_mapping()) else { return Vec::new() };
    let mut out = Vec::new();
    for (name, svc) in services {
        let (Some(name), Some(secrets)) = (name.as_str(), svc.get("secrets").and_then(|s| s.as_sequence())) else {
            continue;
        };
        let Some(cname) = svc.get("container_name").and_then(|c| c.as_str()) else { continue };
        let container = match cname.split_once("}-") {
            Some((_, suffix)) => crate::envfile::container(suffix),
            None => cname.to_string(),
        };
        let env: BTreeMap<String, String> = match svc.get("environment") {
            Some(serde_yaml::Value::Sequence(items)) => items
                .iter()
                .filter_map(|i| i.as_str()?.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                .collect(),
            Some(serde_yaml::Value::Mapping(m)) => {
                // A YAML merge key (`<<: *trellion-env`) is NOT resolved by
                // serde_yaml: its value arrives as a nested mapping (or a
                // list of them) under the literal key `<<`. Flatten it,
                // local keys winning, or every pointer the trellion anchor
                // declares reads as "no pointer".
                let mut env = BTreeMap::new();
                let merged: Vec<&serde_yaml::Mapping> = match m.get("<<") {
                    Some(serde_yaml::Value::Mapping(inner)) => vec![inner],
                    Some(serde_yaml::Value::Sequence(items)) => items.iter().filter_map(|i| i.as_mapping()).collect(),
                    _ => Vec::new(),
                };
                for layer in merged.into_iter().chain(std::iter::once(m)) {
                    for (k, v) in layer {
                        if let Some(k) = k.as_str().filter(|k| *k != "<<") {
                            env.insert(k.to_string(), v.as_str().unwrap_or("").to_string());
                        }
                    }
                }
                env
            }
            _ => BTreeMap::new(),
        };
        for s in secrets {
            let target = s
                .get("target")
                .and_then(|t| t.as_str())
                .or_else(|| s.get("source").and_then(|t| t.as_str()))
                .or_else(|| s.as_str());
            let Some(target) = target else { continue };
            let path = format!("/run/secrets/{target}");
            let pointer = env
                .iter()
                .find(|(_, v)| v.contains(&format!("{path}}}")) || v.ends_with(&path) || v.contains(&format!("{path}\"")))
                .map(|(k, _)| k.clone());
            out.push(Delivery { service: name.to_string(), container: container.clone(), target: target.to_string(), pointer });
        }
    }
    out
}

/// The judgement for one delivery, pure. `added` is the delivered paths
/// found present in the container (None = not running here), `set` the
/// names of its non-empty environment variables.
pub(crate) fn delivery_finding(d: &Delivery, added: Option<&[String]>, set: &[String]) -> Option<Finding> {
    let added = added?;
    let path = format!("/run/secrets/{}", d.target);
    let present = added.contains(&path);
    let pointed = d.pointer.as_ref().is_some_and(|p| set.iter().any(|n| n == p));
    match (pointed, present) {
        (true, false) => Some(Finding {
            severity: Severity::Error,
            kind: "secret-file-missing",
            key: d.pointer.clone().unwrap_or_default(),
            message: format!(
                "{} points {} at {path}, and that file is not in the container — the reader refuses to start on it; recreate: noo stack restart --force",
                d.container,
                d.pointer.as_deref().unwrap_or("?")
            ),
        }),
        (false, true) if d.pointer.is_some() => Some(Finding {
            severity: Severity::Warn,
            kind: "secret-file-unpointed",
            key: d.target.clone(),
            message: format!(
                "{} holds {path} but {} is not set — the container predates the store change; recreate: noo stack restart --force",
                d.container,
                d.pointer.as_deref().unwrap_or("?")
            ),
        }),
        _ => None,
    }
}

/// The compose files in this tree whose deliveries the audit checks: the
/// base, then the add-on overlay beside it. An overlay whose add-on is
/// off has no running container, and `delivery_finding` judges nothing for
/// a container that is not running here. Licensed add-ons' overlays are
/// read from where their bundles put them ([`delivering_paths`]).
pub(crate) const DELIVERING_FILES: &[&str] = &["docker-compose.cluster.yml", "docker-compose.trellion.yml"];

/// Every compose file under `root` whose deliveries the audit reads:
/// [`DELIVERING_FILES`], then each licensed add-on's bundled overlay
/// (`addons/<name>/docker-compose.yml`).
pub(crate) fn delivering_paths(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = DELIVERING_FILES.iter().map(|f| root.join(f)).collect();
    for row in crate::commands::addons::ADDON_ROWS.iter().filter(|r| r.licensed.is_some()) {
        let bundled = crate::addons::pins::addon_dir(root, row.key).join(crate::addon_lock::OVERLAY_FILE);
        if bundled.is_file() {
            out.push(bundled);
        }
    }
    out
}

/// The `secrets audit` findings for file delivery, against the running
/// compose files at the repo root. Silent when they deliver nothing.
pub fn file_delivery_findings() -> Vec<Finding> {
    let root = crate::envfile::repo_root();
    let all: Vec<Delivery> = delivering_paths(&root)
        .iter()
        .flat_map(|f| deliveries(&std::fs::read_to_string(f).unwrap_or_default()))
        .collect();
    let mut wanted: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for d in &all {
        wanted.entry(d.container.clone()).or_default().push(format!("/run/secrets/{}", d.target));
    }
    let probes = super::container_files::probe(&wanted);
    findings_from_probes(&all, &probes, &|c| env_names(c).unwrap_or_default())
}

/// The findings, given each container's probe. A container that was not
/// checked gets one WARN naming it — never silence, which would read as a
/// pass.
pub(crate) fn findings_from_probes(
    all: &[Delivery],
    probes: &BTreeMap<String, super::container_files::Probe>,
    env: &dyn Fn(&str) -> Vec<String>,
) -> Vec<Finding> {
    use super::container_files::Probe;
    let mut sets: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut out = Vec::new();
    for d in all {
        // Absent: not running here; Unchecked: reported once, below.
        if let Some(Probe::Checked(present)) = probes.get(&d.container) {
            let set = sets.entry(d.container.as_str()).or_insert_with(|| env(&d.container));
            out.extend(delivery_finding(d, Some(present), set));
        }
    }
    for (container, p) in probes {
        if let Probe::Unchecked(why) = p {
            out.push(Finding {
                severity: Severity::Warn,
                kind: "secret-file-unchecked",
                key: container.clone(),
                message: format!("{container}: its delivered secret files were NOT checked ({why}) — not a pass; re-run: noo security secrets audit"),
            });
        }
    }
    out
}

/// The `noo cluster verify --controller` row for the audit's JSON: a WARN
/// naming each container whose delivered secret files the audit could not
/// check (its time budget, or docker); None when every one was checked (or
/// the audit was not read — its own row says so).
pub(crate) fn unchecked_delivery_check(audit: &serde_json::Value) -> Option<Check> {
    let names: Vec<&str> = audit["findings"]
        .as_array()?
        .iter()
        .filter(|f| f["kind"] == "secret-file-unchecked")
        .filter_map(|f| f["key"].as_str())
        .collect();
    if names.is_empty() {
        return None;
    }
    Some(Check {
        name: "secret files delivered",
        verdict: Verdict::Warn,
        detail: format!("NOT checked in {} — not a pass; the audit says why", names.join(", ")),
        remedy: Some("noo security secrets audit".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(container: &str, service: &str, names: &[&str]) -> Holder {
        Holder { container: container.into(), service: service.into(), env_names: names.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn a_tier1_name_in_an_owned_container_fails_naming_both() {
        let c = judge(&[h("noo-gateway", "gateway", &["PATH", "NOO_JWT_SECRET_FILE", "NOO_JWT_SECRET"])], &[]);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("noo-gateway: NOO_JWT_SECRET"), "{}", c.detail);
    }

    #[test]
    fn a_credential_shaped_name_off_the_allow_list_fails() {
        let c = judge(&[h("noo-worker", "worker", &["SOME_NEW_TOKEN"])], &[]);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("SOME_NEW_TOKEN"));
    }

    #[test]
    fn pointers_paths_and_native_hub_tokens_are_ok() {
        let c = judge(
            &[
                h(
                    "noo-gateway",
                    "gateway",
                    &["NOO_JWT_SECRET_FILE", "PGPASSFILE", "NOO_TLS_KEY", "TAVILY_API_KEY_FILE"],
                ),
                h("noo-worker", "worker", &["TELEGRAM_BOT_TOKEN_FILE", "GOOGLE_CHAT_CREDENTIALS_JSON_FILE"]),
                h("noo-grafana", "grafana", &["GF_SECURITY_ADMIN_PASSWORD", "GF_SERVER_CERT_KEY"]),
                h("noo-vllm", "vllm", &["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"]),
            ],
            &["secrets/env.sops".into(), "secrets/env.sops.bak_1700000000".into(), "secrets/reveal-audit.log".into()],
        );
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    /// The provider and channel keys are file-backed now,
    /// so a plain one in an owned container is the same FAIL as a tier-1
    /// secret — the regression the v0.2.79 rehearsal found (the gateway
    /// still carried TAVILY_API_KEY and TELEGRAM_BOT_TOKEN as env).
    #[test]
    fn a_plain_provider_or_channel_key_in_an_owned_container_fails() {
        for (svc, name) in [
            ("gateway", "TAVILY_API_KEY"),
            ("gateway", "ANTHROPIC_API_KEY"),
            ("gateway", "GOOGLE_CHAT_CREDENTIALS_JSON"),
            ("worker", "TELEGRAM_BOT_TOKEN"),
            ("worker", "WHATSAPP_TOKEN"),
        ] {
            let c = judge(&[h(&format!("noo-{svc}"), svc, &[&format!("{name}_FILE"), name])], &[]);
            assert_eq!(c.verdict, Verdict::Fail, "{svc}/{name}: {}", c.detail);
            assert!(c.detail.contains(&format!("noo-{svc}: {name}")), "{}", c.detail);
        }
        // and none of them is on the allow-list any more
        for n in ["ANTHROPIC_API_KEY", "TAVILY_API_KEY", "TELEGRAM_BOT_TOKEN", "WHATSAPP_TOKEN", "GOOGLE_CHAT_BEARER_TOKEN"] {
            assert!(!ENV_ALLOWED.iter().any(|(a, _)| *a == n), "{n} is still allow-listed as env");
        }
    }

    /// The add-ons read `_FILE` and their overlays deliver
    /// files, so a plain tier-1 / tier-2 name on one is the same FAIL as on
    /// the gateway — a planted `NOO_GATEWAY_KEY=x` on intel above all.
    #[test]
    fn a_plain_secret_on_an_add_on_fails() {
        for (c, svc, name) in [
            ("noo-trellion", "trellion", "NOO_JWT_SECRET"),
            ("noo-trellion", "trellion", "ANTHROPIC_API_KEY"),
            ("noo-trellion-intel", "trellion-intel", "NOO_GATEWAY_KEY"),
            ("noo-evolve", "noo-evolve", "NOO_CONTROLLER_SECRET"),
            ("noo-evolve", "noo-evolve", "NOO_EVOLVE_DB_PASSWORD"),
        ] {
            let got = judge(&[h("noo-gateway", "gateway", &[]), h(c, svc, &[&format!("{name}_FILE"), name])], &[]);
            assert_eq!(got.verdict, Verdict::Fail, "{c}/{name}: {}", got.detail);
            assert!(got.detail.contains(&format!("{c}: {name}")), "{}", got.detail);
        }
        for svc in ["trellion", "trellion-intel", "noo-evolve"] {
            assert!(!DEFERRED_SERVICES.contains(&svc), "{svc} is deferred again");
        }
    }

    /// What the live add-on containers carry after the flip — pointers,
    /// PGPASSFILE, PEM paths, the python image's GPG_KEY — is OK.
    #[test]
    fn add_ons_with_pointers_only_are_ok() {
        let c = judge(
            &[
                h("noo-gateway", "gateway", &["NOO_JWT_SECRET_FILE"]),
                h(
                    "noo-trellion",
                    "trellion",
                    &["NOO_GATEWAY_KEY_FILE", "PGPASSFILE", "NOO_TLS_KEY", "ANTHROPIC_API_KEY_FILE", "NATS_WORKER_USER"],
                ),
                h("noo-trellion-intel", "trellion-intel", &["NOO_GATEWAY_KEY_FILE", "REDIS_PASSWORD_FILE", "PGPASSFILE"]),
                h("noo-evolve", "noo-evolve", &["NOO_GATEWAY_KEY_FILE", "PGPASSFILE", "NOO_EVOLVE_TLS_KEY", "GPG_KEY"]),
            ],
            &[],
        );
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    /// The login signing secret belongs to the gateway alone.
    /// A worker, add-on or node agent holding it — plainly OR as a file
    /// behind its `_FILE` pointer — FAILS, naming the container; the gateway
    /// holding the pointer is the one OK case.
    #[test]
    fn the_jwt_secret_anywhere_but_the_gateway_fails() {
        for (c, svc) in [
            ("noo-worker", "worker"),
            ("noo-worker-extra", "worker-extra"),
            ("noo-trellion", "trellion"),
            ("noo-trellion-intel", "trellion-intel"),
            ("noo-node-agent", "node-agent"),
        ] {
            let got = judge(&[h("noo-gateway", "gateway", &["NOO_JWT_SECRET_FILE"]), h(c, svc, &["NOO_JWT_SECRET_FILE"])], &[]);
            assert_eq!(got.verdict, Verdict::Fail, "{c}: {}", got.detail);
            assert!(got.detail.contains(&format!("NOO_JWT_SECRET reaches {c}")), "{}", got.detail);
        }
        let ok = judge(&[h("noo-gateway", "gateway", &["NOO_JWT_SECRET_FILE"]), h("noo-worker", "worker", &["NOO_GATEWAY_KEY_FILE"])], &[]);
        assert_eq!(ok.verdict, Verdict::Ok, "{}", ok.detail);
        // Not a prefix match: a different secret whose name merely starts
        // the same way is not this one.
        let other = judge(&[h("noo-gateway", "gateway", &[]), h("noo-worker", "worker", &["NOO_JWT_SECRET_ROTATED_AT"])], &[]);
        assert!(!other.detail.contains("NOO_JWT_SECRET reaches"), "{}", other.detail);
    }

    /// The Go agent reads `_FILE`, so a containerised
    /// agent with a plain secret FAILS like any other, and one holding only
    /// pointers is OK.
    #[test]
    fn the_node_agent_fails_on_a_plain_secret_and_passes_on_pointers() {
        for svc in ["node-agent", "node-agent-sensors"] {
            assert!(!DEFERRED_SERVICES.contains(&svc), "{svc} is deferred again");
        }
        let c = judge(&[h("noo-gateway", "gateway", &[]), h("noo-node-agent", "node-agent", &["NOO_CLUSTER_SECRET", "NATS_NODE_PASSWORD"])], &[]);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("noo-node-agent: NOO_CLUSTER_SECRET, NATS_NODE_PASSWORD"), "{}", c.detail);
        let c = judge(
            &[
                h("noo-gateway", "gateway", &[]),
                h("noo-node-agent", "node-agent", &["NOO_CLUSTER_SECRET_FILE", "NOO_NODE_AGENT_TOKEN_FILE", "NATS_NODE_PASSWORD_FILE", "NATS_NODE_USER", "NOO_TLS_KEY", "HF_TOKEN"]),
            ],
            &[],
        );
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    /// Nats is no longer deferred. Its server expanded
    /// $NATS_PASSWORD only for the retired legacy principal, so a noo-nats
    /// still carrying it was created from a pre-536 compose — FAIL, recreate.
    #[test]
    fn nats_carrying_the_retired_password_fails() {
        assert!(!DEFERRED_SERVICES.contains(&"nats"), "nats is deferred again");
        let c = judge(&[h("noo-gateway", "gateway", &[]), h("noo-nats", "nats", &["NATS_USER", "NATS_PASSWORD"])], &[]);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("noo-nats: NATS_PASSWORD"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap_or("").contains("noo stack restart --force"), "{:?}", c.remedy);
        // ...and the per-principal-only nats the new compose creates is clean.
        let c = judge(&[h("noo-gateway", "gateway", &[]), h("noo-nats", "nats", &[])], &[]);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    /// v0.2.80 rehearsal: any install that has rotated a secret has the
    /// ledger beside the store. It is the CLI's own value-free record, not
    /// residue.
    #[test]
    fn the_rotation_ledger_and_reveal_log_are_not_residue() {
        let c = judge(
            &[h("noo-gateway", "gateway", &[])],
            &["secrets/env.sops".into(), "secrets/rotations.json".into(), "secrets/reveal-audit.log".into()],
        );
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    /// Every file the CLI's writers put under secrets/ is allowed — by the
    /// writers' own consts, so a new one cannot be forgotten here.
    #[test]
    fn every_cli_written_file_is_allowed() {
        assert!(!CLI_WRITTEN_UNDER_SECRETS.is_empty());
        for name in CLI_WRITTEN_UNDER_SECRETS {
            assert!(allowed_in_secrets_dir(&format!("secrets/{name}")), "{name} would be judged residue");
        }
    }

    /// The remedy names the residue it found and nothing else: never a
    /// blanket shred of secrets/, never a file the CLI itself writes.
    #[test]
    fn the_remedy_shreds_only_what_was_judged_residue() {
        let c = judge(
            &[h("noo-gateway", "gateway", &[])],
            &[
                "secrets/env.sops".into(),
                "secrets/rotations.json".into(),
                "secrets/reveal-audit.log".into(),
                "secrets/.runtime/pgpass".into(),
            ],
        );
        assert_eq!(c.verdict, Verdict::Fail);
        let remedy = c.remedy.unwrap();
        assert!(remedy.starts_with("shred -u secrets/.runtime/pgpass — "), "{remedy}");
        assert!(!remedy.contains("secrets/rotations.json") && !remedy.contains("secrets/reveal-audit.log"), "{remedy}");
        assert!(!remedy.contains("any file"), "{remedy}");
    }

    /// A container holding a secret in env still gets the recreate remedy,
    /// and no shred when nothing under secrets/ is residue.
    #[test]
    fn an_env_failure_alone_gets_the_recreate_and_no_shred() {
        let c = judge(&[h("noo-gateway", "gateway", &["NOO_JWT_SECRET"])], &["secrets/env.sops".into(), "secrets/rotations.json".into()]);
        assert_eq!(c.verdict, Verdict::Fail);
        let remedy = c.remedy.unwrap();
        assert!(remedy.contains("noo stack restart --force") && !remedy.contains("shred"), "{remedy}");
    }

    /// Every name the CLI can leave under secrets/, judged: value-free records
    /// and ciphertext allowed; plaintext and passphrase files are residue.
    /// (Security review of every file the CLI writes under secrets/.)
    #[test]
    fn each_file_the_cli_can_leave_under_secrets_is_judged() {
        for ok in [
            "secrets/env.sops",
            "secrets/env.sops.bak_1790773245",
            "secrets/env.sops.bak_absorb_1790773245",
            "secrets/reveal-audit.log",
            "secrets/rotations.json",
            "secrets/.env.sops.rotating.4242",
        ] {
            assert!(allowed_in_secrets_dir(ok), "{ok} must be allowed");
        }
        for bad in [
            "secrets/.env.sops.plain.4242",
            "secrets/.env.sops.verify.4242",
            "secrets/backup_passphrase.txt",
            "secrets/age_backup_passphrase.txt",
            "secrets/.runtime/pgpass",
            "rotations.json",
        ] {
            assert!(!allowed_in_secrets_dir(bad), "{bad} must be residue");
        }
    }

    #[test]
    fn a_file_under_secrets_other_than_the_store_fails() {
        let c = judge(&[h("noo-gateway", "gateway", &[])], &["secrets/env.sops".into(), "secrets/.runtime/pgpass".into()]);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("secrets/.runtime/pgpass"));
    }

    /// The real row and the real audit findings against a live compose
    /// project — how the file-backed-secrets PR proved them on a throwaway
    /// stack. `NOO_VERIFY_COMPOSE_PROJECT=<project> NOO_REPO_ROOT=<dir with
    /// that project's compose file as docker-compose.cluster.yml> cargo test
    /// live_row -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs a live compose project (NOO_VERIFY_COMPOSE_PROJECT, NOO_REPO_ROOT)"]
    fn live_row_against_a_named_project() {
        let c = secrets_not_in_env_row();
        println!("ROW secrets not in env: {:?} — {}", c.verdict, c.detail);
        let findings = file_delivery_findings();
        if findings.is_empty() {
            println!("AUDIT file delivery: no findings");
        }
        for f in findings {
            println!("AUDIT {} {}: {}", f.severity.label(), f.kind, f.message);
        }
    }

    #[test]
    fn nothing_running_is_a_warning_not_a_pass() {
        assert_eq!(judge(&[], &[]).verdict, Verdict::Warn);
    }

    #[test]
    fn the_shipped_compose_delivers_to_the_owned_containers_with_pointers() {
        let compose = include_str!("../../../docker-compose.cluster.yml");
        let ds = deliveries(compose);
        for (svc, target, ptr) in [
            ("gateway", "noo_jwt_secret", "NOO_JWT_SECRET_FILE"),
            ("gateway", "pgpass", "PGPASSFILE"),
            ("worker", "noo_gateway_key", "NOO_GATEWAY_KEY_FILE"),
            ("postgres", "postgres_password", "POSTGRES_PASSWORD_FILE"),
            ("redis", "redis_password", "REDIS_PASSWORD_FILE"),
            ("grafana", "grafana_admin_password", "GF_SECURITY_ADMIN_PASSWORD"),
            ("browser", "noo_browser_key", "NOO_BROWSER_KEY_FILE"),
            ("worker", "noo_browser_key", "NOO_BROWSER_KEY_FILE"),
            ("gateway", "noo_browser_key", "NOO_BROWSER_KEY_FILE"),
            ("gateway", "tavily_api_key", "TAVILY_API_KEY_FILE"),
            ("gateway", "anthropic_api_key", "ANTHROPIC_API_KEY_FILE"),
            ("gateway", "google_chat_credentials_json", "GOOGLE_CHAT_CREDENTIALS_JSON_FILE"),
            ("worker", "telegram_bot_token", "TELEGRAM_BOT_TOKEN_FILE"),
        ] {
            let d = ds.iter().find(|d| d.service == svc && d.target == target).unwrap_or_else(|| panic!("{svc}/{target} not delivered"));
            assert_eq!(d.pointer.as_deref(), Some(ptr), "{svc}/{target}");
        }
        // every delivery has a pointer — a file nothing reads is residue too
        let unpointed: Vec<_> = ds.iter().filter(|d| d.pointer.is_none()).collect();
        assert!(unpointed.is_empty(), "{unpointed:?}");
        // and the tier-1 list covers every name a pointer stands for
        for d in &ds {
            let p = d.pointer.as_deref().unwrap();
            if let Some(n) = p.strip_suffix("_FILE") {
                assert!(TIER1.contains(&n), "{n} is delivered as a file but is not in TIER1");
            }
        }
    }

    /// The audit reads the add-on overlay too, and the add-on's key file is
    /// pointed at by its own `NOO_GATEWAY_KEY_FILE`. (The licensed add-ons'
    /// overlays and their delivery guards live in the add-on repositories
    /// now; the audit reads them where their bundles put them.)
    #[test]
    fn the_shipped_add_on_overlays_deliver_with_pointers() {
        let ds = deliveries(include_str!("../../../docker-compose.trellion.yml"));
        for (svc, container, target, ptr) in [
            ("trellion", "noo-trellion", "noo_gateway_key", "NOO_GATEWAY_KEY_FILE"),
            ("trellion", "noo-trellion", "pgpass", "PGPASSFILE"),
        ] {
            let d = ds
                .iter()
                .find(|d| d.service == svc && d.target == target)
                .unwrap_or_else(|| panic!("{svc}/{target} not delivered"));
            // `${NOO_CONTAINER_PREFIX:-noo}-x` resolves per instance.
            assert_eq!(d.container, crate::envfile::container(&container["noo-".len()..]), "{svc}");
            assert_eq!(d.pointer.as_deref(), Some(ptr), "{svc}/{target}");
        }
        assert!(ds.iter().all(|d| d.pointer.is_some()), "{ds:?}");
        for d in &ds {
            let p = d.pointer.as_deref().unwrap();
            if let Some(n) = p.strip_suffix("_FILE") {
                assert!(TIER1.contains(&n), "{n} is delivered as a file but is not in TIER1");
            }
        }
    }

    #[test]
    fn the_audit_reads_a_bundled_overlay_and_ignores_a_root_one() {
        let d = std::env::temp_dir().join(format!("noo-delivering-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let base = delivering_paths(&d);
        assert_eq!(base.len(), DELIVERING_FILES.len());
        let bundled = crate::addons::pins::addon_dir(&d, "evolve").join("docker-compose.yml");
        std::fs::create_dir_all(bundled.parent().unwrap()).unwrap();
        std::fs::write(&bundled, "services: {}\n").unwrap();
        // An overlay left in the install root by an earlier CLI is not read.
        std::fs::write(d.join("docker-compose.trellion-intel.yml"), "services: {}\n").unwrap();
        std::fs::write(d.join("docker-compose.evolve.yml"), "services: {}\n").unwrap();
        let got = delivering_paths(&d);
        assert!(got.contains(&bundled), "{got:?}");
        assert_eq!(got.len(), base.len() + 1, "{got:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_pointer_at_a_missing_file_is_an_error_and_a_present_one_is_quiet() {
        let d = Delivery { service: "gateway".into(), container: "noo-gateway".into(), target: "noo_jwt_secret".into(), pointer: Some("NOO_JWT_SECRET_FILE".into()) };
        let set = vec!["NOO_JWT_SECRET_FILE".to_string()];
        let f = delivery_finding(&d, Some(&[]), &set).expect("finding");
        assert_eq!(f.severity, Severity::Error);
        assert!(delivery_finding(&d, Some(&["/run/secrets/noo_jwt_secret".to_string()]), &set).is_none());
        // optional secret the store does not hold: no pointer, no file — fine
        assert!(delivery_finding(&d, Some(&[]), &[]).is_none());
        // container not running here: no judgement
        assert!(delivery_finding(&d, None, &set).is_none());
    }

    /// The audit end to end against a fake docker daemon: a planted secret
    /// file with no pointer, and a pointer at a file that is not there, each
    /// fire; a container the probe could not finish is reported as not
    /// checked — never as a pass.
    #[test]
    fn the_finding_fires_on_a_planted_file_and_an_unchecked_container_is_not_a_pass() {
        use super::super::container_files::{probe_via_api, probe_via_diff, tests::*, Probe, BUDGET};
        use std::time::{Duration, Instant};
        let d = |c: &str, t: &str, p: &str| Delivery { service: "s".into(), container: c.into(), target: t.into(), pointer: Some(p.into()) };
        let all = vec![
            d("noo-gateway", "noo_jwt_secret", "NOO_JWT_SECRET_FILE"),
            d("noo-worker", "redis_password", "REDIS_PASSWORD_FILE"),
            d("noo-redis", "redis_password", "REDIS_PASSWORD_FILE"),
        ];
        let mut wanted: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for x in &all {
            wanted.entry(x.container.clone()).or_default().push(format!("/run/secrets/{}", x.target));
        }
        // gateway: file planted, pointer unset. worker: pointer set, no file.
        let sock = fake_daemon(
            "audit",
            &[("noo-gateway", &["/run/secrets/noo_jwt_secret"]), ("noo-worker", &[])],
            None,
        );
        let mut probes = probe_via_api(&sock, &wanted, Instant::now() + BUDGET);
        assert_eq!(probes["noo-redis"], Probe::Absent);
        // redis: its probe outlives the deadline (a stalled `docker diff`).
        let slow = fake_docker_cli("audit-slow", &["/run/secrets/redis_password"], 30);
        let slow_probe = probe_via_diff(slow.to_str().unwrap(), &BTreeMap::from([("noo-redis".to_string(), vec!["/run/secrets/redis_password".to_string()])]), Instant::now() + Duration::from_millis(200));
        probes.insert("noo-redis".into(), slow_probe["noo-redis"].clone());
        let env = |c: &str| if c == "noo-worker" || c == "noo-redis" { vec!["REDIS_PASSWORD_FILE".to_string()] } else { vec![] };
        let f = findings_from_probes(&all, &probes, &env);
        let kinds: Vec<(&str, &str)> = f.iter().map(|f| (f.kind, f.key.as_str())).collect();
        assert!(kinds.contains(&("secret-file-unpointed", "noo_jwt_secret")), "{kinds:?}");
        assert!(kinds.contains(&("secret-file-missing", "REDIS_PASSWORD_FILE")), "{kinds:?}");
        let unchecked: Vec<_> = f.iter().filter(|f| f.kind == "secret-file-unchecked").collect();
        assert_eq!(unchecked.len(), 1, "{kinds:?}");
        assert_eq!(unchecked[0].key, "noo-redis");
        assert_eq!(unchecked[0].severity, Severity::Warn);
        assert!(unchecked[0].message.contains("NOT checked"), "{}", unchecked[0].message);
    }

    #[test]
    fn an_unchecked_delivery_in_the_audit_is_a_warn_row_not_silence() {
        // (kinds bound to names: tests/test_pull_kind_parity.py reads a
        // literal `"kind": "..."` as a node-agent pull kind)
        let (unchecked, unpointed) = ("secret-file-unchecked", "secret-file-unpointed");
        let audit = serde_json::json!({ "findings": [
            { "severity": "warn", "kind": unchecked, "key": "noo-gateway", "message": "m" },
            { "severity": "warn", "kind": unpointed, "key": "x", "message": "m" },
        ]});
        let c = unchecked_delivery_check(&audit).expect("a row");
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(c.detail.contains("noo-gateway") && c.detail.contains("NOT checked"), "{}", c.detail);
        assert!(unchecked_delivery_check(&serde_json::json!({ "findings": [] })).is_none());
        assert!(unchecked_delivery_check(&serde_json::Value::Null).is_none());
    }

    // ── shared secrets ──

    const STORE: &[(&str, &str)] = &[
        ("NOO_BUS_KEY_WORKER", "dw"), ("NOO_BUS_KEY_TRELLION", "dt"), ("NOO_BUS_KEY_TRELLION_INTEL", "di"),
        ("NOO_BROWSER_KEY", "db"), ("NOO_CONTROLLER_SECRET", "dc"), ("NOO_CLUSTER_SECRET", "df"),
        ("NATS_GATEWAY_PASSWORD", "ng"), ("NATS_WORKER_PASSWORD", "nw"),
        ("NATS_TRELLION_PASSWORD", "nt"), ("NATS_TRELLION_INTEL_PASSWORD", "ni"),
    ];

    fn store() -> StoreDigests {
        Some(STORE.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }

    fn fact(c: &str, svc: &str, env: &[&str], aud: Option<&str>, files: &[&str], digests: &[(&str, &str)]) -> SecretFacts {
        SecretFacts {
            container: c.into(),
            service: svc.into(),
            env_names: env.iter().map(|s| s.to_string()).collect(),
            audience: aud.map(str::to_string),
            run_secrets: Some(files.iter().map(|s| s.to_string()).collect()),
            digests: digests.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn healthy() -> Vec<SecretFacts> {
        vec![
            fact("noo-gateway", "gateway",
                &["NOO_CONTROLLER_SECRET_FILE", "NOO_CLUSTER_SECRET_FILE", "NOO_BUS_KEY_WORKER_FILE", "NOO_BUS_KEY_TRELLION_FILE", "NOO_BUS_KEY_TRELLION_INTEL_FILE"],
                None, &["noo_controller_secret", "noo_cluster_secret", "noo_bus_key_worker", "noo_bus_key_trellion", "noo_bus_key_trellion_intel"],
                &[("noo_bus_key_worker", "dw"), ("noo_bus_key_trellion", "dt"), ("noo_bus_key_trellion_intel", "di")]),
            fact("noo-worker", "worker", &["NOO_BUS_KEY_FILE", "NOO_BUS_AUDIENCE", "NOO_GATEWAY_KEY_FILE", "NOO_BROWSER_KEY_FILE"], Some("worker"),
                &["noo_bus_key", "noo_gateway_key", "noo_browser_key"], &[("noo_bus_key", "dw"), ("noo_browser_key", "db")]),
            fact("noo-trellion", "trellion", &["NOO_BUS_KEY_FILE", "NOO_BUS_AUDIENCE", "NATS_ADDON_PASSWORD_FILE"], Some("trellion"),
                &["noo_bus_key", "nats_addon_password"], &[("noo_bus_key", "dt"), ("nats_addon_password", "nt")]),
            fact("noo-trellion-intel", "trellion-intel", &["NOO_BUS_KEY_FILE", "NOO_BUS_AUDIENCE", "NATS_ADDON_PASSWORD_FILE"], Some("trellion-intel"),
                &["noo_bus_key", "nats_addon_password"], &[("noo_bus_key", "di"), ("nats_addon_password", "ni")]),
            fact("noo-browser", "browser", &["NOO_BROWSER_KEY_FILE", "NOO_CLUSTER_SECRET_FILE"], None, &["noo_browser_key"], &[("noo_browser_key", "db")]),
        ]
    }

    #[test]
    fn every_holder_on_its_own_key_is_ok() {
        let c = shared_secrets_check(&healthy(), &store());
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("gateway alone") && c.detail.contains("worker, trellion, trellion-intel"), "{}", c.detail);
        assert!(c.detail.contains("browser door its own"), "{}", c.detail);
        assert!(c.detail.contains("each add-on its own bus password (trellion, trellion-intel)"), "{}", c.detail);
    }

    /// i70 residue: each add-on holds its OWN NATS password, nothing else
    /// holds one, and the store's bus passwords are distinct.
    #[test]
    fn each_addon_holds_its_own_bus_password() {
        // The worker holding an add-on's password: FAIL.
        let mut s = healthy();
        s[1].run_secrets.as_mut().unwrap().push("nats_addon_password".into());
        s[1].digests.insert("nats_addon_password".into(), "nt".into());
        let c = shared_secrets_check(&s, &store());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("noo-worker holds an add-on's NATS password"), "{}", c.detail);
        // trellion holding the worker's password as its own: FAIL.
        let mut s = healthy();
        s[2].digests.insert("nats_addon_password".into(), "nw".into());
        let c = shared_secrets_check(&s, &store());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("noo-trellion holds NATS_WORKER_PASSWORD as its add-on NATS password"), "{}", c.detail);
        // A stale copy: FAIL.
        let mut s = healthy();
        s[3].digests.insert("nats_addon_password".into(), "old".into());
        assert!(shared_secrets_check(&s, &store()).detail.contains("noo-trellion-intel's /run/secrets/nats_addon_password is not NATS_TRELLION_INTEL_PASSWORD"));
        // An intel bundle that predates its principal inherits trellion's: WARN, named.
        let mut s = healthy();
        s[3].digests.insert("nats_addon_password".into(), "nt".into());
        let c = shared_secrets_check(&s, &store());
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("noo-trellion-intel holds NATS_TRELLION_PASSWORD"), "{}", c.detail);
        // The fallback (no add-on password delivered yet) is not this row's FAIL.
        let mut s = healthy();
        for f in &mut s[2..4] {
            f.run_secrets.as_mut().unwrap().retain(|x| x != "nats_addon_password");
            f.digests.remove("nats_addon_password");
        }
        let c = shared_secrets_check(&s, &store());
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("none yet: the worker's"), "{}", c.detail);
        // No two principals share a password in the store.
        let mut d = store().unwrap();
        d.insert("NATS_TRELLION_PASSWORD".into(), "nw".into());
        let c = shared_secrets_check(&healthy(), &Some(d));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("NATS_TRELLION_PASSWORD equals NATS_WORKER_PASSWORD"), "{}", c.detail);
        assert_eq!(nats_store_key("trellion-intel"), "NATS_TRELLION_INTEL_PASSWORD");
    }

    /// Review H1, the operator's decision: once the browser door has its
    /// own key, the fleet secret anywhere in the worker plane — or in the
    /// browser — FAILS.
    #[test]
    fn the_fleet_secret_in_the_worker_plane_fails() {
        let mut s = healthy();
        s[1].env_names.push("NOO_CLUSTER_SECRET_FILE".into());
        s[2].run_secrets.as_mut().unwrap().push("noo_cluster_secret".into());
        s[4].env_names.push("NOO_SECRET_NOO_CLUSTER_SECRET".into());
        let c = shared_secrets_check(&s, &store());
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("FLEET secret") && c.detail.contains("noo-worker, noo-trellion, noo-browser"), "{}", c.detail);
    }

    /// The browser door's key: only its holders, only true copies, and the
    /// browser must hold one.
    #[test]
    fn the_browser_key_is_judged_like_the_bus_keys() {
        let mut s = healthy();
        s[2].run_secrets.as_mut().unwrap().push("noo_browser_key".into());
        assert!(shared_secrets_check(&s, &store()).detail.contains("noo-trellion holds the browser door's key"));
        let mut s = healthy();
        s[1].digests.insert("noo_browser_key".into(), "stale".into());
        assert!(shared_secrets_check(&s, &store()).detail.contains("noo-worker's /run/secrets/noo_browser_key is not NOO_BROWSER_KEY"));
        let mut s = healthy();
        s[4] = fact("noo-browser", "browser", &[], None, &[], &[]);
        assert!(shared_secrets_check(&s, &store()).detail.contains("noo-browser holds no browser key"));
        let mut d = store().unwrap();
        d.insert("NOO_BROWSER_KEY".into(), "df".into());
        assert!(shared_secrets_check(&healthy(), &Some(d)).detail.contains("NOO_BROWSER_KEY equals NOO_CLUSTER_SECRET"));
    }

    /// The v0.2.101 shape FAILS.
    #[test]
    fn the_pre_702_worker_plane_fails() {
        let old = vec![
            fact("noo-gateway", "gateway", &["NOO_CONTROLLER_SECRET_FILE"], None, &["noo_controller_secret"], &[]),
            fact("noo-worker", "worker", &["NOO_CONTROLLER_SECRET_FILE", "NOO_GATEWAY_KEY_FILE"], None, &["noo_controller_secret"], &[]),
            fact("noo-trellion", "trellion", &["NOO_CONTROLLER_SECRET_FILE"], None, &["noo_controller_secret"], &[]),
        ];
        let c = shared_secrets_check(&old, &store());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("NOO_CONTROLLER_SECRET still reaches noo-worker, noo-trellion"), "{}", c.detail);
        assert!(c.detail.contains("noo-worker holds no bus key of its own"), "{}", c.detail);
        assert!(c.detail.contains("noo-gateway cannot sign for worker"), "{}", c.detail);
    }

    /// Review M1: every spelling of the controller secret counts — the
    /// `NOO_SECRET_` env name and a bare /run/secrets file with no pointer.
    #[test]
    fn the_controller_secret_is_found_under_every_spelling() {
        for (env, file) in [(Some("NOO_SECRET_NOO_CONTROLLER_SECRET"), None), (None, Some("noo_controller_secret"))] {
            let mut s = healthy();
            if let Some(e) = env { s[1].env_names.push(e.into()); }
            if let Some(f) = file { s[1].run_secrets.as_mut().unwrap().push(f.into()); }
            let c = shared_secrets_check(&s, &store());
            assert_eq!(c.verdict, Verdict::Fail, "{env:?} {file:?}");
            assert!(c.detail.contains("NOO_CONTROLLER_SECRET still reaches noo-worker"), "{}", c.detail);
        }
    }

    /// Review M1: names alone are not enough — a wrong copy, a wrong audience
    /// value and another audience's file all FAIL.
    #[test]
    fn digests_and_the_audience_value_are_judged() {
        let mut s = healthy();
        s[2].digests.insert("noo_bus_key".into(), "dw".into()); // trellion holding the worker's key
        assert!(shared_secrets_check(&s, &store()).detail.contains("noo-trellion's /run/secrets/noo_bus_key is not NOO_BUS_KEY_TRELLION"));
        let mut s = healthy();
        s[3].audience = Some("trellion".into());
        assert!(shared_secrets_check(&s, &store()).detail.contains("noo-trellion-intel names audience \"trellion\""));
        let mut s = healthy();
        s[2].run_secrets.as_mut().unwrap().push("noo_bus_key_worker".into());
        assert!(shared_secrets_check(&s, &store()).detail.contains("noo-trellion holds another audience's key: noo_bus_key_worker"));
        let mut s = healthy();
        s[0].digests.insert("noo_bus_key_trellion".into(), "stale".into());
        assert!(shared_secrets_check(&s, &store()).detail.contains("noo-gateway's noo_bus_key_trellion is not NOO_BUS_KEY_TRELLION"));
    }

    /// Review M1: the store's bus keys are distinct from each other and from
    /// the shared secrets.
    #[test]
    fn the_store_keys_must_be_distinct() {
        let mut d = store().unwrap();
        d.insert("NOO_BUS_KEY_TRELLION".into(), "dw".into());
        let c = shared_secrets_check(&healthy(), &Some(d));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("NOO_BUS_KEY_TRELLION equals NOO_BUS_KEY_WORKER"), "{}", c.detail);
        let mut d = store().unwrap();
        d.insert("NOO_BUS_KEY_WORKER".into(), "dc".into());
        assert!(shared_secrets_check(&healthy(), &Some(d)).detail.contains("NOO_BUS_KEY_WORKER equals NOO_CONTROLLER_SECRET"));
        let mut d = store().unwrap();
        d.remove("NOO_BUS_KEY_TRELLION_INTEL");
        assert!(shared_secrets_check(&healthy(), &Some(d)).detail.contains("NOO_BUS_KEY_TRELLION_INTEL is not set"));
    }

    /// Review L3: nothing to judge is a FAIL that says "not judged", never a WARN.
    #[test]
    fn nothing_judged_is_a_fail_never_a_warn() {
        let c = shared_secrets_check(&[], &store());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.starts_with("not judged"), "{}", c.detail);
        let mut s = healthy();
        s[1].run_secrets = None;
        let c = shared_secrets_check(&s, &store());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("not judged: noo-worker's /run/secrets could not be read"), "{}", c.detail);
        assert_eq!(shared_secrets_check(&healthy(), &None).verdict, Verdict::Fail, "an unreadable store is not a pass");
    }

    #[test]
    fn an_add_on_that_is_off_needs_no_gateway_key_pointer() {
        let s: Vec<SecretFacts> = healthy().into_iter().filter(|f| !f.service.starts_with("trellion")).collect();
        assert_eq!(shared_secrets_check(&s, &store()).verdict, Verdict::Ok);
    }

    /// Second review: a key file that is present but could not be digested
    /// is "not judged" — a FAIL — for a verifier, the gateway and the
    /// browser key alike. Never a silent pass on names alone.
    #[test]
    fn a_present_key_file_with_no_digest_is_not_judged() {
        let mut s = healthy();
        s[1].digests.remove("noo_bus_key");
        assert!(shared_secrets_check(&s, &store()).detail.contains("not judged: noo-worker's /run/secrets/noo_bus_key could not be digested"));
        let mut s = healthy();
        s[0].digests.remove("noo_bus_key_trellion");
        assert!(shared_secrets_check(&s, &store()).detail.contains("not judged: noo-gateway's /run/secrets/noo_bus_key_trellion could not be digested"));
        let mut s = healthy();
        s[4].digests.remove("noo_browser_key");
        let c = shared_secrets_check(&s, &store());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("not judged: noo-browser's /run/secrets/noo_browser_key could not be digested"), "{}", c.detail);
    }

    /// A truncated tar stream (a `docker cp` cut short) yields the name but
    /// no digest — which the row above turns into "not judged".
    #[test]
    fn a_truncated_tar_digests_nothing() {
        let mut h = vec![0u8; 512];
        h[..23].copy_from_slice(b"noo_bus_key\0\0\0\0\0\0\0\0\0\0\0\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", 64).as_bytes());
        h[156] = b'0';
        let mut tar = h;
        tar.extend_from_slice(b"only-ten-b");
        let (names, digests) = tar_names_and_bus_digests(&tar, "salt");
        assert_eq!(names, ["noo_bus_key"]);
        assert!(digests.is_empty(), "a truncated body must not be digested: {digests:?}");
    }

    /// The tar walk the live probe uses: names of every file, digests of the
    /// bus-key files only, other bodies skipped.
    #[test]
    fn the_tar_walk_names_every_file_and_digests_only_bus_keys() {
        fn entry(name: &str, body: &[u8]) -> Vec<u8> {
            let mut h = vec![0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            let size = format!("{:011o}\0", body.len());
            h[124..136].copy_from_slice(size.as_bytes());
            h[156] = b'0';
            let mut out = h;
            out.extend_from_slice(body);
            out.resize(out.len().div_ceil(512) * 512, 0);
            out
        }
        let mut tar = Vec::new();
        tar.extend(entry("secrets/noo_bus_key", b"the-key\n"));
        tar.extend(entry("secrets/redis_password", b"not-hashed"));
        tar.extend(vec![0u8; 1024]);
        let (names, digests) = tar_names_and_bus_digests(&tar, "salt");
        assert_eq!(names, ["noo_bus_key", "redis_password"]);
        assert_eq!(digests.len(), 1);
        assert_eq!(digests["noo_bus_key"], super::super::cluster_push_secrets::salted_digest("salt", "the-key"));
    }
}
