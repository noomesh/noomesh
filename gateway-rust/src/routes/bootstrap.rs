// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Bootstrap-token host enrollment (the Kubernetes kubeadm
//! pattern, NOT the recorded-rejected credentials-vault).
//!
//! Lifecycle: an operator mints a single-use token
//! (`POST /api/security/bootstrap-tokens`); the raw 32-byte value is returned
//! exactly once and only its sha256 hex is stored, beside the ONE enrollment
//! paste composed from it (`install_command`, then `enroll_command` =
//! `noo enroll noo1.<blob>`). `noo enroll` POSTs the token to
//! `POST /api/cluster/bootstrap`. On a valid,
//! unused, unexpired, unrevoked token — from an allowed CIDR when one was set
//! — the gateway marks the token used ATOMICALLY and returns the controller's
//! SSH public key, IF one is configured; a standalone controller advertises
//! none and the host enrols pull-only. From then on
//! `noo cluster provision <node>` stages a bundle the node collects.
//!
//! It also used to return `{user} ALL=(ALL) NOPASSWD:ALL` as a
//! `sudoers_template`, described as "required for hands-off provision".
//! It was not required: `bootstrap-enroll.sh` never read the field, and
//! writes its own narrow grant instead (one binary, `noo-apply`, which
//! validates CA signatures itself). Provisioning is pull-based:
//! the same response's `next_step` says so. So the field bought
//! nothing and handed any OTHER reader of this endpoint a recipe for
//! passwordless root, over a PUBLIC route. Removed 2026-09-05; the fleet
//! doctrine is that the controller has no privileged path into a node.
//!
//! Auth posture, per surface:
//!   - `/api/security/bootstrap-tokens*` (mint/list/revoke) sits behind
//!     `require_any_auth` like the rest of the control plane. In-handler
//!     guards additionally require >= Operator for JWTs — including on GET,
//!     because `scope_allows` waves ALL GETs through and a token list
//!     (issuance metadata, never hashes) is still operator material.
//!     Cluster-HMAC callers (no `RequesterCtx`) pass, recorded as
//!     "cluster-cli" — the same posture as `mint_join_key`, and deliberate:
//!     the design's design goal is onboarding a host from chat, so the
//!     coordinator may mint. A minted token is inert until a human runs the
//!     script on a machine the attacker would already need to control.
//!   - `POST /api/cluster/bootstrap` and `GET /bootstrap` are PUBLIC
//!     (`auth::PUBLIC_PATHS_EXACT`): an unenrolled host has no credential of
//!     any kind. The
//!     token in the body IS the authentication; it carries 256 bits of
//!     entropy, so the global per-IP rate limiter is belt-and-braces, not the
//!     defense.
//!
//! Failure behaviour on the public verifier is deliberately oracle-free: one
//! uniform 403 ([`DENIED_MSG`]) for unknown / expired / used / revoked /
//! wrong-CIDR. The distinction is recorded internally in the
//! `bootstrap_token_denied` audit row, never in the response.

use crate::audit::{AuditEvent, AuditKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post, put},
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::RequesterCtx;
use crate::authz::OperatorOrInternal;
use crate::auth_refresh::{generate_bootstrap_token, hash_token, BOOTSTRAP_TOKEN_PREFIX};
use crate::state::AppState;
use super::{AppError, AppResult};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        // ── Operator surface: mint / list / revoke ──
        // (One route per line: the mechanical audit test below extracts
        // handler names from lines that carry both the path and the verb.)
        .route("/api/security/bootstrap-tokens", get(bootstrap_tokens_list).post(bootstrap_token_create))
        .route("/api/security/bootstrap-tokens/{id}/revoke", post(bootstrap_token_revoke))
        // ── Public enrollment surface (see module docs + PUBLIC_PATHS_EXACT) ──
        .route("/api/cluster/bootstrap", post(cluster_bootstrap))
        .route("/api/cluster/enroll-tailnet", post(enroll_tailnet))
        .route("/bootstrap", get(serve_enroll_script))
        .route("/bootstrap/prep", get(serve_prep_script))
        .route("/bootstrap/apply", get(serve_apply_script))
        .route("/bootstrap/ca.crt", get(serve_cluster_ca))
        .route("/bootstrap/deenroll", get(serve_deenroll_script))
        .route("/bootstrap/fetch", get(serve_fetch_script))
        // Pull provisioning: the CLI stages an END-TO-END
        // ENCRYPTED bundle (CMS to the node's birth cert — the gateway only
        // holds ciphertext); the node's noo-fetch timer collects it. The GET
        // is public like the rest of /bootstrap: the blob is useless without
        // the node's birth key, and the fetch happens before the node has
        // any credential.
        .route("/api/cluster/provision-bundle/{node}",
            post(provision_bundle_put).layer(DefaultBodyLimit::max(MAX_RAIL_BODY)))
        .route("/api/cluster/provision-bundle/{node}/status", get(provision_bundle_status))
        // i67: what the gateway sees as the controller's own node's birth
        // cert — a read of the host file, never a write (no API sets it).
        .route("/api/cluster/self-node", get(self_node_identity))
        .route("/bootstrap/bundle/{node}/applied", post(bundle_apply_report))
        // The node's FETCH receipt. The GET cannot carry a
        // proof over the bundle's sha — at that moment the node has not seen
        // the bytes — so the receipt is a separate, later, SIGNED call, and
        // it is what stamps `fetched_at`.
        .route("/bootstrap/bundle/{node}/fetched", post(bundle_fetch_receipt))
        .route("/bootstrap/bundle/{node}", get(provision_bundle_get))
        // CLI release assets, served from the controller (rail work, 054).
        // Same raised limit as the bundle route: a CLI asset is ~9 MB and the
        // default 2 MB cap surfaced on the client as "Broken pipe" (the
        // server answered 413 before reading the body) on the first rail
        // walk, 2026-09-03.
        .route("/api/cluster/cli-asset/{name}",
            put(cli_asset_put).layer(DefaultBodyLimit::max(MAX_RAIL_BODY)))
        .route("/bootstrap/cli/{name}", get(cli_asset_get))
}

/// The cap on a rail upload: a staged node bundle, or a CLI/harness release
/// asset the controller serves on to nodes.
///
/// It has been outgrown twice by the same mechanism — something new joined
/// the bundle and nobody re-read the number. The default 2 MB cap broke the
/// first rail walk when a ~9 MB CLI asset arrived; 64 MB broke
/// on 2026-09-19 when the design's harness put the GATEWAY BINARY in every
/// remote node's bundle (48-61 MB per target, bundles 74-82 MB), and all
/// four non-controller nodes failed to stage. The controller's own node
/// carries neither CLI nor harness, so its 10 MB bundle passed and the one
/// node an operator watches most closely was again the one that could not
/// fail.
///
/// 256 MB was deliberately far above the largest bundle we shipped. Then the
/// vendor CLIs joined (i83 E1e): a node whose harness placement names
/// Copilot CLI, Claude Code or Codex carries that native binary, 100-250 MB
/// per artefact and often already compressed, beside the ~82 MB it carried
/// before — up to ~330 MB, past 256. 768 MB keeps twice that, and stays
/// under Postgres's 1 GB limit on the bytea the bundle is stored in. The
/// body is buffered in memory, and the CLI stages one node at a time, so
/// the ceiling is one bundle rather than the fleet.
pub(crate) const MAX_RAIL_BODY: usize = 768 * 1024 * 1024;

// ═══════════════════════════════════════════════════════════════
// Guards + shared helpers
// ═══════════════════════════════════════════════════════════════

/// The single response body every failed redemption gets. Unknown, expired,
/// already-used, revoked and out-of-CIDR tokens are indistinguishable to the
/// caller — an attacker probing tokens learns nothing about WHY one failed
/// (in particular, not that a guessed value corresponds to a real token).
const DENIED_MSG: &str = "bootstrap token rejected";

/// TTL validation: default 1h, hard max 24h ("short-lived
/// (default 1h, max 24h) — narrow attack window"). Out-of-range values are
/// REJECTED rather than clamped — silently shortening a requested 7-day
/// token to 24h would hand the caller a credential with different properties
/// than they asked for.
pub(crate) fn validate_ttl(ttl_seconds: Option<i64>) -> Result<i64, String> {
    let ttl = ttl_seconds.unwrap_or(3600);
    if ttl <= 0 {
        return Err("ttl_seconds must be positive".into());
    }
    if ttl > 86_400 {
        return Err("ttl_seconds must be <= 86400 (24h) — bootstrap tokens are short-lived by design".into());
    }
    Ok(ttl)
}

/// Is `ip` inside `cidr`? `cidr` is `a.b.c.d/N`, `x::y/N`, or a bare address
/// (treated as an exact /32 / /128 match). Returns `None` when the string is
/// not a valid CIDR — callers must FAIL CLOSED on `None`. An IPv4-mapped
/// IPv6 peer (`::ffff:a.b.c.d`, dual-stack listener) is unmapped before
/// comparison so a v4 CIDR still matches it.
fn cidr_contains(cidr: &str, ip: IpAddr) -> Option<bool> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    let (net_str, prefix): (&str, u8) = match cidr.trim().split_once('/') {
        Some((n, p)) => (n, p.parse().ok()?),
        None => {
            // Bare address: exact match at full prefix length.
            let net: IpAddr = cidr.trim().parse().ok()?;
            return Some(net == ip);
        }
    };
    let net: IpAddr = net_str.trim().parse().ok()?;
    // Prefix range is validated against the NETWORK's family up front, so an
    // out-of-range prefix is unparseable (None → deny) even when the peer is
    // in the other family — a malformed restriction never "matches false"
    // by luck of the mismatch arm.
    let max_prefix = if net.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return None;
    }
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            Some((u32::from(n) & mask) == (u32::from(a) & mask))
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask: u128 = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            Some((u128::from(n) & mask) == (u128::from(a) & mask))
        }
        // Family mismatch is a definite non-match, not a parse failure.
        _ => Some(false),
    }
}

/// The controller's SSH PUBLIC key, from the sources this container can
/// actually read.
///
/// HONEST GAP, on record: NO container in this stack has a ~/.ssh mount
/// any more — the cluster-executor sidecar that used to hold the operator's
/// `${HOME}/.ssh` was deleted with the controller\u{2192}node SSH lane on
/// 2026-09-11, so the PRIVATE half is nowhere in the deployment. Only the
/// public half is needed here, to be installed on an enrolling node as the
/// forced-command `noo-gate` entry (a lane nothing currently dials \u{2014}
/// retired). It arrives
/// via `NOO_CONTROLLER_SSH_PUBKEY` (config plane — a public key is not a
/// secret), which the compose file passes through to the gateway env. The
/// file candidates below exist for bare-metal / dev runs where the gateway
/// process shares the operator's filesystem; in the container they simply
/// don't resolve. When NO source yields a key, enrollment reports itself
/// unconfigured (503) BEFORE looking at the token — never a fabricated key,
/// and never a burned token.
fn controller_ssh_pubkey() -> Option<String> {
    let looks_like_pubkey =
        |s: &str| s.starts_with("ssh-") || s.starts_with("ecdsa-") || s.starts_with("sk-");
    if let Ok(v) = std::env::var("NOO_CONTROLLER_SSH_PUBKEY") {
        let v = v.trim().to_string();
        if looks_like_pubkey(&v) {
            return Some(v);
        }
        if !v.is_empty() {
            tracing::warn!(
                "NOO_CONTROLLER_SSH_PUBKEY is set but does not look like an \
                 OpenSSH public key (expected 'ssh-…'/'ecdsa-…'/'sk-…') — ignoring it"
            );
        }
    }
    // Same candidate order as noo-cli's `controller_ssh_pubkey()`
    // (cluster_provision.rs): prefer modern key types.
    let home = std::env::var("HOME").unwrap_or_default();
    let mut dirs: Vec<String> = Vec::new();
    if !home.is_empty() {
        dirs.push(format!("{home}/.ssh"));
    }
    dirs.push("/root/.ssh".to_string());
    for dir in dirs {
        for name in ["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"] {
            if let Ok(s) = std::fs::read_to_string(format!("{dir}/{name}")) {
                let s = s.trim().to_string();
                if looks_like_pubkey(&s) {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// The controller URL the enrollment paste and the enrollment hint point at. Same
/// declaration the AgentCard serves (`peers.rs`): env → yaml → default.
pub(crate) fn controller_url() -> String {
    crate::config::env_or_yaml(
        "NOO_GATEWAY_URL",
        |c| c.services.gateway_url.clone(),
        "https://localhost:8080",
    )
    .trim_end_matches('/')
    .to_string()
}

/// Base URL of the controller's SELF-AGENT — the host process beside
/// tailscaled that performs tailnet whois and dialback on the gateway's
/// behalf. `NOO_SELF_AGENT_URL` overrides; otherwise it derives from the
/// controller's own URL (the host tailscale address) on the agent port.
///
/// A localhost controller URL would aim the probe INSIDE this container,
/// where there is no tailscaled, so that is refused with guidance rather
/// than left to fail as a confusing connection error.
///
/// Shared rather than duplicated: both tailnet-authenticated admissions —
/// node enrollment and the keyless kiosk mint — must agree on where the
/// agent is, and two copies of a derivation are two things to keep in
/// step.
pub(crate) fn self_agent_base() -> Result<String, String> {
    let agent_base = std::env::var("NOO_SELF_AGENT_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| {
            let host = controller_url();
            let host = host
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split([':', '/'])
                .next()
                .unwrap_or("")
                .to_string();
            format!("https://{host}:{}", crate::node_link::AGENT_PORT)
        });
    if agent_base.contains("localhost") || agent_base.contains("127.0.0.1") {
        return Err(
            "this needs the controller self-agent: set NOO_GATEWAY_URL to the controller's \
             tailnet address, or NOO_SELF_AGENT_URL to the agent's URL"
                .into(),
        );
    }
    Ok(agent_base)
}

/// The repo a fresh node installs the noo CLI from. `NOO_CLI_REPO` overrides
/// (the same variable `install-noo.sh` and the CLI's `upgrade` read), so a
/// release move is one setting, not a stale literal in two places.
const DEFAULT_CLI_REPO: &str = "noomesh/noomesh";

fn cli_install_repo() -> String {
    std::env::var("NOO_CLI_REPO")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CLI_REPO.to_string())
}

/// Step 1 of the ONE enrollment lane: put the noo CLI on the node. The public
/// lane: TLS verifies against the system store and install.sh checks the
/// release signature against keys printed in its own source. Byte-identical
/// to what `noo cluster bootstrap-token create` printed before the server
/// composed it.
fn compose_install_command(repo: &str) -> String {
    format!(
        "command -v noo >/dev/null || curl -fsSL https://raw.githubusercontent.com/{repo}/main/noo-cli/install.sh | sh"
    )
}

/// Step 2: `noo enroll noo1.<blob>`. The blob is base64url-no-pad JSON in
/// exactly the shape `noo enroll`'s `parse_blob` accepts: `v` 1, the
/// controller `url`, the raw `token`, the tailnet auth key `tsk` (empty when
/// the node is not joining the tailnet), the cluster CA pin `ca` (DER
/// sha256 hex — mandatory: enroll refuses first contact without it), and
/// the bound `node` name when there is one.
fn compose_enroll_command(url: &str, token: &str, tsk: &str, ca_sha256: &str, node: Option<&str>) -> String {
    let mut blob = json!({"v": 1, "url": url, "token": token, "tsk": tsk, "ca": ca_sha256});
    if let Some(n) = node {
        blob["node"] = Value::String(n.to_string());
    }
    use base64::Engine as _;
    format!(
        "noo enroll noo1.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(blob.to_string())
    )
}

/// Where the cluster CA certificate lives, in the order `/bootstrap/ca.crt`
/// serves it: the env override, the compose mount (`${NOO_PKI_DIR}:/app/pki`),
/// the repo-relative dev path. ONE list, because the pin in the paste must be
/// the fingerprint of the very file the node will fetch.
pub(crate) fn cluster_ca_candidates() -> [String; 3] {
    [
        crate::tls::ca_path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
        "/app/pki/ca.crt".to_string(),
        "pki/ca.crt".to_string(),
    ]
}

/// sha256 hex of the FIRST certificate's DER in `pem` — what `noo enroll`
/// computes over the served `/bootstrap/ca.crt` (node_fetch::cert_der_sha256)
/// and `openssl x509 -outform DER | sha256sum` prints. The DER must parse as
/// X.509: a PEM decoder alone accepts any base64 between the markers, and a
/// pin of junk would only fail later, on the node.
fn ca_der_sha256(pem: &[u8]) -> Result<String, String> {
    let mut rd = std::io::BufReader::new(pem);
    let der = rustls_pemfile::certs(&mut rd)
        .next()
        .ok_or("no CERTIFICATE block")?
        .map_err(|e| format!("unreadable PEM: {e}"))?;
    x509_parser::parse_x509_certificate(der.as_ref())
        .map_err(|e| format!("not an X.509 certificate: {e}"))?;
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(der.as_ref())))
}

/// The pin for the enrollment paste, from the CA this gateway serves.
pub(crate) fn cluster_ca_fingerprint_from(candidates: &[String]) -> Result<String, String> {
    for cand in candidates.iter().filter(|c| !c.is_empty()) {
        let Ok(bytes) = std::fs::read(cand) else { continue };
        if !bytes.windows(27).any(|w| w == b"-----BEGIN CERTIFICATE-----") {
            continue;
        }
        return ca_der_sha256(&bytes).map_err(|e| format!("the cluster CA at {cand} is unusable: {e}"));
    }
    Err("no cluster CA certificate is readable here (NOO_TLS_CA, /app/pki/ca.crt), so the \
         enrollment paste would carry no pin — and a node refuses blind trust-on-first-use. \
         Check `noo security pki status` on the controller (`noo security pki init` creates one)."
        .into())
}

/// The controller URL a node dials during enrollment, refused when it is a
/// loopback or docker-internal name no other machine can reach. Onboarding
/// writes the tailnet address to `services.gateway_url`; the example config
/// seeds `https://localhost:8080`, which would poison every join.
pub(crate) fn enroll_url(url: &str) -> Result<String, String> {
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.split(':').next().unwrap_or(""),
    };
    let unreachable = host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || host == "gateway"
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified());
    if unreachable || !url.starts_with("https://") {
        return Err(format!(
            "this controller advertises {url:?}, which a new node cannot reach — set \
             services.gateway_url in noomesh.yaml to its tailnet address \
             (https://<name>.<tailnet>.ts.net:8080; `noo controller promote` writes it), \
             then restart the gateway"
        ));
    }
    Ok(url.to_string())
}

// ═══════════════════════════════════════════════════════════════
// Operator surface — mint / list / revoke
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct CreateTokenBody {
    ttl_seconds: Option<i64>,
    role_hint: Option<String>,
    allowed_cidr: Option<String>,
    /// Bind the token to ONE node name: redemption from a host reporting a
    /// different hostname is refused (before the burn — an operator typo
    /// must not waste the token), and the redemption record then carries
    /// everything the inventory needs.
    node_name: Option<String>,
    /// Put a pre-authorized, `tag:worker` Tailscale auth key in the enrollment
    /// blob so `noo enroll` joins the tailnet first. Minted only on request;
    /// a failed mint is an error, never a blob silently missing the key.
    with_tailscale: Option<bool>,
}

/// POST /api/security/bootstrap-tokens — mint a single-use enrollment token.
///
/// The raw token appears in THIS response and nowhere else: not in the DB
/// (sha256 hex only), not in the audit row (the row carries the id), not in
/// logs. Losing the response means minting a new token, by design.
async fn bootstrap_token_create(
    State(state): State<Arc<AppState>>,
    op: OperatorOrInternal,
    body: Option<Json<Value>>,
) -> AppResult {
    let by = op.actor("cluster-cli");
    // An absent body means "all defaults" (mint_join_key precedent), but a
    // PRESENT body that doesn't deserialize is a 400 — `Option<Json<T>>`
    // would silently swallow `{"ttl_seconds": "1h"}` into the defaults, and
    // a credential minted with properties the caller didn't ask for is worse
    // than an error.
    let body: CreateTokenBody = match body {
        None => CreateTokenBody { ttl_seconds: None, role_hint: None, allowed_cidr: None, node_name: None, with_tailscale: None },
        Some(Json(v)) => serde_json::from_value(v)
            .map_err(|e| AppError::BadRequest(format!("invalid body: {e}")))?,
    };

    let ttl = validate_ttl(body.ttl_seconds).map_err(AppError::BadRequest)?;

    let role_hint = body
        .role_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    if role_hint.as_deref().is_some_and(|s| s.len() > 64) {
        return Err(AppError::BadRequest("role_hint must be <= 64 characters".into()));
    }
    let node_name = body
        .node_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if let Some(ref n) = node_name {
        // Hostname charset only: this value lands in inventory lines, shell
        // hints, and audit rows.
        if n.len() > 64 || !n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
            return Err(AppError::BadRequest(
                "node_name must be <= 64 chars of [a-zA-Z0-9._-]".into(),
            ));
        }
    }

    let allowed_cidr = body
        .allowed_cidr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    if let Some(ref cidr) = allowed_cidr {
        // Probe-parse now so a typo'd CIDR fails at mint time (fixable),
        // not at redemption time (uniform 403, token burned on confusion).
        if cidr_contains(cidr, IpAddr::from([127, 0, 0, 1])).is_none() {
            return Err(AppError::BadRequest(format!(
                "allowed_cidr {cidr:?} is not a valid CIDR (expected e.g. 192.168.1.0/24)"
            )));
        }
    }

    // Everything the paste needs is settled BEFORE the token exists: a
    // token minted into a response that then fails is a live credential
    // nobody holds. The paste is composed here, once, so the console, the
    // CLI and the MCP tool all hand out the same one.
    let gateway = enroll_url(&controller_url()).map_err(AppError::Unavailable)?;
    let ca_sha256 = cluster_ca_fingerprint_from(&cluster_ca_candidates()).map_err(AppError::Unavailable)?;
    // The controller's own device is already on the tailnet as
    // tag:controller; a worker key would re-tag it and cut every remote node
    // off. Same paste, one thing fewer — and said so.
    let wants_tailnet = body.with_tailscale.unwrap_or(false);
    let is_self = node_name.as_deref().is_some_and(crate::self_node::is_self_node);
    // A stale tailnet record under this name would make the node join as
    // `<name>-1`; clear it first, as the CLI always has. Best effort: no
    // credential or an API failure is reported in the response, not fatal —
    // the paste is still valid and the operator can clear the record by hand.
    let mut tailnet_cleared: Vec<String> = Vec::new();
    let mut tailnet_clear_error: Option<String> = None;
    if wants_tailnet && !is_self {
        if let Some(n) = node_name.as_deref() {
            match crate::routes::cluster::clear_stale_tailnet_devices(n, std::time::Duration::from_secs(10 * 60)).await {
                Ok(v) => tailnet_cleared = v,
                Err(e) => tailnet_clear_error = Some(e),
            }
        }
    }
    let tsk = if wants_tailnet && !is_self {
        // The key lives as long as the token (capped by Tailscale's 24h).
        let minutes = ((ttl + 59) / 60).clamp(5, 24 * 60);
        crate::routes::cluster::mint_tailscale_auth_key("tag:worker", minutes, false)
            .await
            .map_err(|e| AppError::Unavailable(format!("could not mint the tailnet auth key: {e}")))?
    } else {
        String::new()
    };

    let raw = generate_bootstrap_token();
    let token_hash = hash_token(&raw);

    let (id, expires_at): (uuid::Uuid, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "INSERT INTO noo_bootstrap_tokens \
             (token_hash, created_by, expires_at, role_hint, allowed_cidr, node_name) \
         VALUES ($1, $2, now() + make_interval(secs => $3), $4, $5, $6) \
         RETURNING id, expires_at",
    )
    .bind(&token_hash)
    .bind(&by)
    .bind(ttl as f64)
    .bind(&role_hint)
    .bind(&allowed_cidr)
    .bind(&node_name)
    .fetch_one(&state.db)
    .await?;

    // Audit the ID, never the raw token or its hash: the raw value is a live
    // credential and the hash is the verifier — an audit reader needs
    // neither to answer "who minted what, when".
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::BootstrapTokenCreate, &by, &format!("bootstrap-token:{id}"))
            .details(json!({
            "token_id": id.to_string(),
            "ttl_seconds": ttl,
            "role_hint": role_hint,
            "allowed_cidr": allowed_cidr,
            "tailnet_key": !tsk.is_empty(),
        })),
    )
    .await;

    // hash the EXACT script /bootstrap serves so the
    // paste can verify it before executing — the CA pin (#80) rode the
    // out-of-band paste, but the script CHECKING that pin arrived over
    // unverified TLS; a substituted script simply ignores the pin. With
    // the script hash in the paste too, both pins share the trusted
    // channel and wholesale substitution dies.
    let bootstrap_sha256 = crate::paths::resolve(crate::paths::BOOTSTRAP_ENROLL_SCRIPT_CANDIDATES)
        .and_then(|p| std::fs::read(p).ok())
        .map(|bytes| {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&bytes))
        });
    Ok(Json(json!({
        "status": "ok",
        "id": id.to_string(),
        "token": raw,
        "expires_at": expires_at.to_rfc3339(),
        "node_name": node_name,
        "role_hint": role_hint,
        "allowed_cidr": allowed_cidr,
        "bootstrap_sha256": bootstrap_sha256,
        // The ONE enrollment paste: install the CLI, then
        // `noo enroll`. The fetched-script `one_liner` that used to ride
        // here is retired; an older CLI falls back to composing
        // the paste itself when these are absent.
        "install_command": compose_install_command(&cli_install_repo()),
        "enroll_command": compose_enroll_command(&gateway, &raw, &tsk, &ca_sha256, node_name.as_deref()),
        "provision_command": format!("noo cluster provision {} --wait", node_name.as_deref().unwrap_or("<node>")),
        "joins_tailnet": !tsk.is_empty(),
        // Stale records under this name that were removed so the node keeps
        // its name (last seen > 10 min ago); `tailnet_clear_error` when the
        // check could not run.
        "tailnet_cleared": tailnet_cleared,
        "tailnet_clear_error": tailnet_clear_error,
        "tailnet_skipped": (wants_tailnet && is_self)
            .then_some("this is the controller's own device — it is already tag:controller, so no tailnet key was minted"),
        "ca_sha256": ca_sha256,
        "controller_url": gateway,
        "note": "single-use; the raw token is shown exactly once and is safe \
                 to send over chat — it expires, burns on first use, and can \
                 be revoked by id",
    })))
}

/// GET /api/security/bootstrap-tokens — issuance metadata, NEVER hashes.
async fn bootstrap_tokens_list(
    State(state): State<Arc<AppState>>,
    _op: OperatorOrInternal,
) -> AppResult {
    let rows: Vec<(
        uuid::Uuid,
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<serde_json::Value>,
    )> = sqlx::query_as(
        "SELECT id, created_by, created_at, expires_at, used_at, used_by_ip, node_name, enroll_user, \
                revoked, role_hint, allowed_cidr, birth_cert, facts \
         FROM noo_bootstrap_tokens ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;

    let now = chrono::Utc::now();
    let tokens: Vec<Value> = rows
        .into_iter()
        .map(
            |(id, created_by, created_at, expires_at, used_at, used_by_ip, node_name, enroll_user, revoked, role_hint, allowed_cidr, birth_cert, facts)| {
                let status = if revoked {
                    "revoked"
                } else if used_at.is_some() {
                    "used"
                } else if expires_at <= now {
                    "expired"
                } else {
                    "active"
                };
                json!({
                    "id": id.to_string(),
                    "status": status,
                    "created_by": created_by,
                    "created_at": created_at.to_rfc3339(),
                    "expires_at": expires_at.to_rfc3339(),
                    "used_at": used_at.map(|t| t.to_rfc3339()),
                    "used_by_ip": used_by_ip,
                    "node_name": node_name,
                    "enroll_user": enroll_user,
                    "revoked": revoked,
                    "role_hint": role_hint,
                    "allowed_cidr": allowed_cidr,
                    // pull-provisioning lane: what `noo cluster provision` needs to
                    // build+encrypt the bundle without an SSH probe.
                    "birth_cert": birth_cert,
                    "facts": facts,
                })
            },
        )
        .collect();
    Ok(Json(json!({ "tokens": tokens, "count": tokens.len() })))
}

/// POST /api/security/bootstrap-tokens/{id}/revoke — flip the row. Idempotent
/// (revoking a used or already-revoked token succeeds; the state is what the
/// operator asked for), 404 only when the id does not exist.
async fn bootstrap_token_revoke(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    op: OperatorOrInternal,
) -> AppResult {
    let by = op.actor("cluster-cli");
    let id: uuid::Uuid = id
        .parse()
        .map_err(|_| AppError::BadRequest("invalid token id (expected a UUID)".into()))?;

    let updated = sqlx::query("UPDATE noo_bootstrap_tokens SET revoked = true WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("bootstrap token {id} not found")));
    }

    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::BootstrapTokenRevoke, &by, &format!("bootstrap-token:{id}"))
            .details(json!({ "token_id": id.to_string() })),
    )
    .await;
    Ok(Json(json!({ "status": "ok", "id": id.to_string(), "revoked": true })))
}

// ═══════════════════════════════════════════════════════════════
// Public enrollment surface
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct BootstrapBody {
    token: String,
    /// Self-reported by the enrolling script; checked against the token's
    /// node_name binding when one was set at mint.
    hostname: Option<String>,
    /// The account the enroll script runs as — recorded on the token row so
    /// provision-node can build the inventory entry without a human edit.
    enroll_user: Option<String>,
    /// The node's own tailnet IPv4, self-reported (finding #52): the socket
    /// peer as seen from inside the gateway container is the DOCKER BRIDGE
    /// (172.18.0.1 — the controller itself), which poisoned the recorded
    /// address. Sanity-shaped (100.64/10) and preferred over the peer.
    tailnet_ip: Option<String>,
    /// PEM of the node's self-signed BIRTH certificate (pull-provisioning lane):
    /// `noo cluster provision` encrypts the provisioning bundle to it, so
    /// secrets cross the rail as ciphertext the gateway cannot read.
    birth_cert: Option<String>,
    /// Machine facts gathered at enrollment (arch, model, gpu_present,
    /// data_root) — lets provision derive tier + binary arch WITHOUT the
    /// push lane's SSH facts probe.
    facts: Option<serde_json::Value>,
}

/// Why a redemption was refused — recorded in the audit row ONLY. The
/// response is always the uniform [`DENIED_MSG`] 403.
#[derive(Debug, Clone, Copy, PartialEq)]
enum DenyReason {
    Unknown,
    Revoked,
    AlreadyUsed,
    Expired,
    CidrMismatch,
    CidrUnparseable,
    /// The guarded UPDATE matched no row: a concurrent redeemer won the
    /// race (or the row changed state between SELECT and UPDATE).
    LostRace,
}

impl DenyReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown_token",
            Self::Revoked => "revoked",
            Self::AlreadyUsed => "already_used",
            Self::Expired => "expired",
            Self::CidrMismatch => "cidr_mismatch",
            Self::CidrUnparseable => "cidr_unparseable",
            Self::LostRace => "lost_race",
        }
    }
}

/// POST /api/cluster/bootstrap — redeem a bootstrap token.
///
/// PUBLIC (see module docs). The peer address comes from `ConnectInfo` — the
/// socket peer, the one value a remote client cannot forge (same source the
/// rate limiter trusts; deliberately NOT X-Forwarded-For, which any direct
/// caller can set). Consequence worth knowing: behind a reverse proxy,
/// `allowed_cidr` constrains the PROXY's address. The supported topology
/// (gateway reached directly / over the tailnet) has no such hop.
async fn cluster_bootstrap(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<BootstrapBody>,
) -> AppResult {
    let peer_ip = peer.ip();

    // Pull-era (first-contact finding #47): the controller SSH key is the
    // GATE lane's prerequisite, not enrollment's — the bundle rides the
    // pull channel and SSH is only the --via-gate fallback. The old hard
    // requirement 500'd EVERY enrollment on a virgin standalone controller
    // (which has no SSH keypair by design; live 2026-08-26, first node of
    // the first standalone fleet). Absent key → enrollment proceeds
    // pull-only; the response omits the key and the enroll script skips
    // the pin step.
    let ssh_pubkey = controller_ssh_pubkey();
    if ssh_pubkey.is_none() {
        tracing::info!(ip = %peer_ip,
            "bootstrap: controller advertises no SSH key — pull-only enrollment (gate lane unavailable)");
    }

    let deny = |reason: DenyReason, token_id: Option<uuid::Uuid>| {
        let db = state.db.clone();
        let ip = peer_ip.to_string();
        async move {
            let resource = token_id
                .map(|id| format!("bootstrap-token:{id}"))
                .unwrap_or_else(|| "bootstrap-token:unknown".to_string());
            crate::audit::record(
                &db,
                AuditEvent::new(AuditKind::BootstrapTokenDenied, "anonymous", &resource)
                    .outcome(crate::audit::Outcome::Denied)
                    .details(json!({ "reason": reason.as_str(), "ip": ip })),
            )
            .await;
            AppError::Forbidden(DENIED_MSG.into())
        }
    };

    let presented_hash = hash_token(body.token.trim());
    let row: Option<(
        uuid::Uuid,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, expires_at, used_at, revoked, role_hint, allowed_cidr, node_name \
         FROM noo_bootstrap_tokens WHERE token_hash = $1",
    )
    .bind(&presented_hash)
    .fetch_optional(&state.db)
    .await?;

    let Some((id, expires_at, used_at, revoked, role_hint, allowed_cidr, node_name)) = row else {
        return Err(deny(DenyReason::Unknown, None).await);
    };
    if revoked {
        return Err(deny(DenyReason::Revoked, Some(id)).await);
    }
    if used_at.is_some() {
        return Err(deny(DenyReason::AlreadyUsed, Some(id)).await);
    }
    if expires_at <= chrono::Utc::now() {
        return Err(deny(DenyReason::Expired, Some(id)).await);
    }
    if let Some(ref cidr) = allowed_cidr {
        match cidr_contains(cidr, peer_ip) {
            Some(true) => {}
            Some(false) => return Err(deny(DenyReason::CidrMismatch, Some(id)).await),
            // Validated at mint time, so this means the row was edited out
            // of band. Fail CLOSED: an unparseable restriction restricts
            // everything, not nothing.
            None => return Err(deny(DenyReason::CidrUnparseable, Some(id)).await),
        }
    }

    // Node binding (052, relaxed 2026-08-19): `--node <name>` DEFINES the
    // node's identity — the enrolling machine ADOPTS it (provision-node
    // writes NODE_ID=<name>), regardless of the box's own hostname. The
    // reported hostname is advisory only: it is recorded, and a mismatch is
    // logged, but it is NOT a refusal. Coupling identity to the self-reported
    // hostname was friction with no security value — the hostname is not
    // authoritative, and the single-use 256-bit token is the real gate.
    // (Found live: token minted `--node host5`, box hostname `host4`,
    // 403 pre-burn — a legitimate onboard blocked.)
    if let Some(ref bound) = node_name {
        let reported = body.hostname.as_deref().map(str::trim).unwrap_or("");
        if !reported.is_empty() && !reported.eq_ignore_ascii_case(bound) {
            tracing::info!(
                bound = %bound, reported = %reported,
                "bootstrap: node adopts bound name; reported hostname differs (advisory)"
            );
        }
    }

    let enroll_user = body.enroll_user.as_deref().map(str::trim).filter(|s| !s.is_empty());
    // Single-use under concurrency: the guarded UPDATE re-checks every
    // condition and the `used_at IS NULL` predicate serializes concurrent
    // redeemers on the row lock — exactly one caller gets `rows_affected = 1`.
    // Birth cert: sanity-shape only (a PEM certificate) — its only use is
    // as an ENCRYPTION target chosen by the enrolling machine for itself.
    let birth_cert = body.birth_cert.as_deref().map(str::trim)
        .filter(|c| c.starts_with("-----BEGIN CERTIFICATE-----") && c.len() < 16_384);
    // Prefer the node's self-reported tailnet address over the socket peer
    // (finding #52b): through docker's published-port plumbing (v6→v4
    // userland proxy, tailscale serve) the peer is the BRIDGE — the
    // controller itself. Shape-checked to the CGNAT range (100.64/10) so a
    // bogus claim cannot plant an arbitrary address.
    let recorded_ip = body
        .tailnet_ip
        .as_deref()
        .map(str::trim)
        .filter(|ip| {
            ip.parse::<std::net::Ipv4Addr>()
                .is_ok_and(|v4| v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        })
        .map(str::to_string)
        .unwrap_or_else(|| peer_ip.to_string());
    // i11a: the bound name must not belong to a DIFFERENT machine. Checked
    // before the token is spent, so a refused enrollee can rename and paste
    // the same line again.
    if let Some(ref bound) = node_name {
        let holder = crate::node_name_claim::holder(&state.db, bound, Some(id)).await?;
        let fp = crate::node_name_claim::machine_fp_of(body.facts.as_ref());
        let claimant = crate::node_name_claim::Claimant { addr: &recorded_ip, machine_fp: fp.as_deref() };
        if let Some(msg) = crate::node_name_claim::conflict(bound, &holder, &claimant) {
            name_conflict_audit(&state.db, bound, &recorded_ip, &holder, "paste").await;
            return Err(AppError::Conflict(format!("{msg} The token was not spent.")));
        }
    }
    let claimed = sqlx::query(
        "UPDATE noo_bootstrap_tokens \
         SET used_at = now(), used_by_ip = $2, enroll_user = $3, \
             birth_cert = $4, facts = $5 \
         WHERE id = $1 AND used_at IS NULL AND NOT revoked AND expires_at > now()",
    )
    .bind(id)
    .bind(&recorded_ip)
    .bind(enroll_user)
    .bind(birth_cert)
    .bind(&body.facts)
    .execute(&state.db)
    .await?;
    if claimed.rows_affected() == 0 {
        return Err(deny(DenyReason::LostRace, Some(id)).await);
    }
    // A re-enrollment mints a NEW birth key: any bundle still staged for
    // this name is ciphertext for the OLD one and would only produce
    // "decrypt failed — re-enroll" on the node. Drop it; provision stages a fresh one.
    sqlx::query("DELETE FROM noo_provision_bundles WHERE node_name = $1")
        .bind(node_name.clone().or_else(|| body.hostname.clone()).unwrap_or_default())
        .execute(&state.db)
        .await?;

    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::BootstrapTokenUsed, "anonymous", &format!("bootstrap-token:{id}"))
            .details(json!({ "token_id": id.to_string(), "ip": peer_ip.to_string(), "role_hint": role_hint })),
    )
    .await;
    tracing::info!(token_id = %id, ip = %peer_ip, "bootstrap_token_used");
    // A token minted before the `noo-bt-` prefix redeemed:
    // the stored hash is of the whole string, so it verifies — count it,
    // the evidence the bare form can be refused. Same family as #585's lanes.
    if !body.token.trim().starts_with(BOOTSTRAP_TOKEN_PREFIX) {
        let labels = std::collections::HashMap::from([("lane".to_string(), "bootstrap_token_unprefixed".to_string())]);
        state.metrics.inc_counter("noo_legacy_lane_uses_total", Some(&labels), 1).await;
    }

    let gateway = controller_url();
    Ok(Json(json!({
        "status": "ok",
        "ssh_public_key": ssh_pubkey,
        // The enrolling script substitutes its own user for {user}.
        "controller_url": gateway,
        "role_hint": role_hint,
        "node_name": node_name,
        "next_step": "on the controller, run: noo cluster provision <this-node-name> --wait (stages the pull bundle this node collects)",
    })))
}

/// POST /api/cluster/enroll-tailnet — tailnet-native enrollment
/// stage 3. No token, no pins: the tailnet IS the authenticated channel.
///
/// Admission = whois + dialback, both performed by the controller's
/// SELF-AGENT (a host process next to tailscaled — the gateway container
/// cannot see real peer addresses through the docker SNAT path, finding
/// #52, and forwarded headers are spoofable so they are never consulted):
///
///   1. whois(claimed tailnet_ip) must carry the required tag
///      (NOO_ENROLL_TAILNET_TAG, default `tag:worker`) — only a device an
///      admin admitted to the tailnet with that tag passes; the node's
///      IDENTITY (name) comes from the tailnet, not self-report.
///   2. dialback: the enrollee publishes a nonce on its own tailnet
///      address; the self-agent fetches it. WireGuard routing guarantees
///      only the address's true owner can answer, so a matching nonce
///      proves the caller IS that device (a LAN caller claiming a real
///      worker's address fails here).
///
/// On success the handler self-mints a PRE-USED bootstrap-token row
/// carrying the same facts/birth-cert payload a paste redemption records,
/// so everything downstream (`noo cluster provision`, the pull rail) works
/// unchanged. Kill switch: NOO_ENROLL_TAILNET=0.
async fn enroll_tailnet(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<EnrollTailnetBody>,
) -> AppResult {
    if std::env::var("NOO_ENROLL_TAILNET")
        .is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("false"))
    {
        return Err(AppError::Forbidden(
            "tailnet enrollment is disabled on this controller (NOO_ENROLL_TAILNET=0)".into(),
        ));
    }
    let ip_ok = body.tailnet_ip.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|v4| v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]));
    if !ip_ok {
        return Err(AppError::BadRequest("tailnet_ip must be a 100.64/10 IPv4 address".into()));
    }
    if body.proof_nonce.len() < 16
        || body.proof_nonce.len() > 128
        || !body.proof_nonce.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Err(AppError::BadRequest("proof_nonce must be 16–128 alphanumeric chars".into()));
    }
    if body.proof_port == 0 {
        return Err(AppError::BadRequest("proof_port required".into()));
    }

    let link = crate::node_link::NodeLink::self_agent().map_err(AppError::Internal)?;
    let agent_base = link.base().to_string();

    // 1. whois: tag + tailnet-authoritative name.
    let who: Value = link
        .request(reqwest::Method::GET, &format!("/tailnet/whois?ip={}", body.tailnet_ip))
    .send()
    .await
    .map_err(|e| {
        // i11a: the TLS cause lives in the source chain, not in Display.
        let chain = crate::addon_proxy::error_chain(&e);
        tracing::warn!(agent = %agent_base, error = %chain, "tailnet enroll: controller self-agent call failed");
        AppError::Upstream(format!(
            "controller self-agent unreachable at {agent_base}: {chain} — is noo-node-agent running on the controller host, and does its cert name this host?"
        ))
    })?
    .json()
    .await
    .map_err(|e| AppError::Upstream(format!("self-agent whois: bad response: {e}")))?;
    let required_tag = std::env::var("NOO_ENROLL_TAILNET_TAG")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| "tag:worker".into());
    let tags: Vec<String> = who["tags"]
        .as_array()
        .map(|a| a.iter().filter_map(|t| t.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let deny_audit = |reason: &'static str| {
        let db = state.db.clone();
        let ip = body.tailnet_ip.clone();
        async move {
            crate::audit::record(
                &db,
                AuditEvent::new(AuditKind::TailnetEnrollDenied, "anonymous", &format!("tailnet-enroll:{ip}"))
                    .outcome(crate::audit::Outcome::Denied)
                    .details(json!({ "reason": reason })),
            ).await;
            AppError::Forbidden("tailnet enrollment denied".into())
        }
    };
    if !tags.iter().any(|t| t == &required_tag) {
        tracing::info!(ip = %body.tailnet_ip, ?tags, %required_tag,
            "tailnet enroll: device lacks the required tag");
        return Err(deny_audit("missing_required_tag").await);
    }
    let node_name = who["name"]
        .as_str()
        .and_then(|n| n.split('.').next())
        .map(str::to_string)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| AppError::Upstream("self-agent whois returned no name".into()))?;

    // 2. dialback: prove the caller OWNS the claimed address.
    let db_resp: Value = link
        .request(reqwest::Method::POST, "/tailnet/dialback")
        .json(&json!({
            "ip": body.tailnet_ip,
            "port": body.proof_port,
            "expect": body.proof_nonce,
        }))
        .send()
        .await
        .map_err(|e| AppError::Upstream(format!("self-agent dialback failed: {e}")))?
        .json()
        .await
        .map_err(|e| AppError::Upstream(format!("self-agent dialback: bad response: {e}")))?;
    if db_resp["ok"].as_bool() != Some(true) {
        tracing::info!(ip = %body.tailnet_ip, reason = %db_resp["reason"],
            "tailnet enroll: dialback did not verify");
        return Err(deny_audit("dialback_failed").await);
    }

    // i11a: the tailnet name is the DEVICE name, and a fresh Pop!_OS box
    // is called `host8` like every other one, the controller included.
    // A name held by a different machine is refused, never merged.
    {
        let holder = crate::node_name_claim::holder(&state.db, &node_name, None).await?;
        let fp = crate::node_name_claim::machine_fp_of(body.facts.as_ref());
        let claimant = crate::node_name_claim::Claimant { addr: &body.tailnet_ip, machine_fp: fp.as_deref() };
        if let Some(msg) = crate::node_name_claim::conflict(&node_name, &holder, &claimant) {
            name_conflict_audit(&state.db, &node_name, &body.tailnet_ip, &holder, "tailnet").await;
            return Err(AppError::Conflict(msg));
        }
    }

    // 3. Admit: self-mint a pre-used token row so provision + pull work
    // unchanged. The raw value is never revealed — the row exists to carry
    // the enrollment payload, not to be redeemed.
    let birth_cert = body.birth_cert.as_deref().map(str::trim)
        .filter(|c| c.starts_with("-----BEGIN CERTIFICATE-----") && c.len() < 16_384);
    let enroll_user = body.enroll_user.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let token_hash = hash_token(&generate_bootstrap_token());
    let row: (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO noo_bootstrap_tokens \
             (token_hash, created_by, expires_at, role_hint, node_name, \
              used_at, used_by_ip, enroll_user, birth_cert, facts) \
         VALUES ($1, 'tailnet-enroll', now(), 'worker', $2, now(), $3, $4, $5, $6) \
         RETURNING id",
    )
    .bind(&token_hash)
    .bind(&node_name)
    .bind(&body.tailnet_ip)
    .bind(enroll_user)
    .bind(birth_cert)
    .bind(&body.facts)
    .fetch_one(&state.db)
    .await?;
    // A re-enrollment mints a NEW birth key: any bundle still staged for
    // this name is ciphertext for the OLD one and would only produce
    // "decrypt failed — re-enroll" on the node. Drop it; provision stages a fresh one.
    sqlx::query("DELETE FROM noo_provision_bundles WHERE node_name = $1")
        .bind(&node_name)
        .execute(&state.db)
        .await?;

    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::TailnetEnrollAdmitted, "anonymous", &format!("bootstrap-token:{}", row.0))
            .details(json!({
            "node_name": node_name, "tailnet_ip": body.tailnet_ip,
            "tag": required_tag, "peer": peer.ip().to_string(),
        })),
    )
    .await;
    tracing::info!(node = %node_name, ip = %body.tailnet_ip, "tailnet_enroll_admitted");

    Ok(Json(json!({
        "status": "ok",
        "ssh_public_key": controller_ssh_pubkey(),
        "controller_url": controller_url(),
        "role_hint": "worker",
        "node_name": node_name,
        "next_step": "on the controller, run: noo cluster provision <this-node-name> --wait",
    })))
}

/// The audit row for a refused name claim (i11a): what was asked, from
/// where, and what already holds the name.
async fn name_conflict_audit(
    db: &sqlx::PgPool,
    name: &str,
    addr: &str,
    holder: &crate::node_name_claim::NameHolder,
    lane: &str,
) {
    crate::audit::record(
        db,
        AuditEvent::new(AuditKind::EnrollNameConflict, "anonymous", &format!("node:{name}"))
            .outcome(crate::audit::Outcome::Denied)
            .details(json!({
            "node_name": name, "claimant": addr, "lane": lane,
            "held_by": holder.addrs, "controller": holder.controller,
        })),
    )
    .await;
    tracing::warn!(node = %name, claimant = %addr, held_by = ?holder.addrs, controller = holder.controller, lane,
        "enrollment refused: the node name is held by a different machine");
}

#[derive(Deserialize)]
struct EnrollTailnetBody {
    /// Advisory only — identity comes from the tailnet (whois name).
    #[allow(dead_code)]
    hostname: Option<String>,
    tailnet_ip: String,
    proof_port: u16,
    proof_nonce: String,
    enroll_user: Option<String>,
    facts: Option<Value>,
    birth_cert: Option<String>,
}

/// GET /bootstrap — the enrollment script (public, because it runs before
/// the host has any credential). The script itself does nothing without a
/// valid TOKEN.
async fn serve_enroll_script() -> impl IntoResponse {
    use crate::paths;
    let Some(path) = paths::resolve(paths::BOOTSTRAP_ENROLL_SCRIPT_CANDIDATES) else {
        return (StatusCode::NOT_FOUND, "bootstrap enrollment script not found").into_response();
    };
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [("content-type", "text/x-shellscript")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "bootstrap enrollment script not found").into_response(),
    }
}

/// GET /bootstrap/prep — the ROOT host-prep phase, fetched by
/// bootstrap-enroll.sh and run under the operator's one attended sudo.
/// Public for the same reason as `/bootstrap`: it is an inert script from
/// the repo; run by nobody but the operator, on a host that has no
/// credential of any kind yet.
async fn serve_deenroll_script() -> impl IntoResponse {
    serve_repo_script(crate::paths::BOOTSTRAP_DEENROLL_SCRIPT_CANDIDATES, "deenroll script not found").await
}

/// GET /bootstrap/fetch — the pull-provisioning fetcher,
/// installed by prep-host.sh as /usr/local/bin/noo-fetch. Public like its
/// siblings: an inert script; the bundle it fetches is ciphertext to anyone
/// without the node's birth key, and noo-apply still verifies the CA
/// signature on the plaintext.
async fn serve_fetch_script() -> impl IntoResponse {
    serve_repo_script(crate::paths::BOOTSTRAP_FETCH_SCRIPT_CANDIDATES, "noo-fetch script not found").await
}

/// `noo-<target-triple>`, or the signed release manifest pair
/// (`sha256sums.txt`, `sha256sums.txt.sig`) — no path characters.
fn valid_asset_name(n: &str) -> bool {
    (n.starts_with("noo-") || n == "sha256sums.txt" || n == "sha256sums.txt.sig" || n == "install.sh")
        && n.len() <= 80
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !n.contains("..")
}

/// PUT /api/cluster/cli-asset/{name}?sha256=<hex>&version=<v> — operator
/// upload of one CLI release asset (bytes verified against the sidecar the
/// CLI downloaded from the release). Upsert.
async fn cli_asset_put(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(name): Path<String>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> AppResult {
    if !valid_asset_name(&name) {
        return Err(AppError::BadRequest("invalid asset name".into()));
    }
    if body.is_empty() {
        return Err(AppError::BadRequest("empty asset".into()));
    }
    let claimed = q.get("sha256").map(|s| s.trim().to_lowercase()).unwrap_or_default();
    let version = q.get("version").cloned().unwrap_or_default();
    let actual = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&body))
    };
    // The claim is mandatory: an upload that names no hash is an upload the
    // uploader did not verify end to end.
    if claimed.is_empty() {
        return Err(AppError::BadRequest("sha256 query parameter is required".into()));
    }
    if claimed != actual {
        return Err(AppError::BadRequest(format!("sha256 mismatch: claimed {claimed}, got {actual}")));
    }
    sqlx::query(
        "INSERT INTO noo_cli_assets (name, blob, sha256, version, created_at) \
         VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (name) DO UPDATE SET blob = EXCLUDED.blob, sha256 = EXCLUDED.sha256, \
         version = EXCLUDED.version, created_at = now()",
    )
    .bind(&name)
    .bind(body.as_ref())
    .bind(&actual)
    .bind(&version)
    .execute(&state.db)
    .await?;
    let actor = ctx.as_ref().map(|Extension(r)| r.sub.clone())
        .unwrap_or_else(|| "gateway".into());
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::CliAssetUploaded, &actor, &format!("cli-asset:{name}"))
            .details(json!({ "name": name, "version": version, "bytes": body.len() })),
    )
    .await;
    Ok(Json(json!({"ok": true, "name": name, "sha256": actual, "version": version, "bytes": body.len()})))
}

/// GET /bootstrap/cli/{name} — the asset bytes, or for `{name}.sha256` the
/// `<hex>  <name>` line `noo upgrade` verifies against. Same trust posture
/// as the other /bootstrap routes: tailnet-reachable, CA-pinned transport.
async fn cli_asset_get(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let (base, want_sha) = match name.strip_suffix(".sha256") {
        Some(b) => (b.to_string(), true),
        None => (name.clone(), false),
    };
    if !valid_asset_name(&base) {
        return (StatusCode::BAD_REQUEST, "invalid asset name").into_response();
    }
    let row: Result<Option<(Vec<u8>, String)>, _> =
        sqlx::query_as("SELECT blob, sha256 FROM noo_cli_assets WHERE name = $1")
            .bind(&base)
            .fetch_optional(&state.db)
            .await;
    match row {
        Ok(Some((blob, sha))) => {
            if want_sha {
                (StatusCode::OK, [("content-type", "text/plain")], format!("{sha}  {base}\n")).into_response()
            } else {
                (StatusCode::OK, [("content-type", "application/octet-stream")], blob).into_response()
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such asset on this controller (noo upgrade --nodes uploads them)").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "asset lookup failed").into_response(),
    }
}

pub(crate) fn valid_node_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// POST /api/cluster/provision-bundle/{node} — stage a node's provisioning
/// bundle (pull-provisioning lane). The body is the CMS CIPHERTEXT `noo cluster
/// provision` produced by encrypting the CA-signed bundle to the node's
/// birth cert — this endpoint (and the DB row) never see plaintext, so a
/// gateway compromise leaks no credentials from here. Upsert: re-provision
/// replaces the staged bundle.
async fn provision_bundle_put(
    State(state): State<Arc<AppState>>,
    ctx: Option<Extension<RequesterCtx>>,
    Path(node): Path<String>,
    body: Bytes,
) -> AppResult {
    if !valid_node_name(&node) {
        return Err(AppError::BadRequest("invalid node name".into()));
    }
    if body.is_empty() {
        return Err(AppError::BadRequest("empty bundle".into()));
    }
    sqlx::query(
        "INSERT INTO noo_provision_bundles (node_name, blob, created_at, fetched_at) \
         VALUES ($1, $2, now(), NULL) \
         ON CONFLICT (node_name) DO UPDATE \
         SET blob = EXCLUDED.blob, created_at = now(), fetched_at = NULL",
    )
    .bind(&node)
    .bind(body.as_ref())
    .execute(&state.db)
    .await?;
    let actor = ctx.as_ref().map(|Extension(r)| r.sub.clone())
        .unwrap_or_else(|| "gateway".into());
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::ProvisionBundleStaged, &actor, &format!("provision-bundle:{node}"))
            .details(json!({ "node": node, "bytes": body.len() })),
    )
    .await;
    Ok(Json(json!({ "status": "staged", "node": node, "bytes": body.len() })))
}

/// GET /api/cluster/provision-bundle/{node}/status — the controller-side
/// view of the pull rail (finding #74): the rail's stage transitions all
/// log on the NODE, so the operator at the controller watched a mute wait
/// while fetch/apply/register happened invisibly. `fetched_at` was already
/// stamped for observability — this surfaces it so `provision --wait` can
/// narrate "staged → fetched → registered" and say WHICH stage a timeout
/// died at.
async fn provision_bundle_status(
    State(state): State<Arc<AppState>>,
    Path(node): Path<String>,
) -> AppResult {
    if !valid_node_name(&node) {
        return Err(AppError::BadRequest("invalid node name".into()));
    }
    type StatusRow = (chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>, i64,
                      Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<i32>, Option<String>, String);
    let row: Option<StatusRow> =
        sqlx::query_as(
            "SELECT created_at, fetched_at, octet_length(blob)::bigint, \
                    applied_at, applied_sha, apply_rc, apply_msg, encode(sha256(blob), 'hex') \
             FROM noo_provision_bundles WHERE node_name = $1",
        )
        .bind(&node)
        .fetch_optional(&state.db)
        .await?;
    match row {
        Some((staged_at, fetched_at, bytes, applied_at, applied_sha, apply_rc, apply_msg, sha)) => Ok(Json(json!({
            "node": node,
            "staged_at": staged_at.to_rfc3339(),
            "fetched_at": fetched_at.map(|t| t.to_rfc3339()),
            "bytes": bytes,
            "sha256": sha,
            // Apply report: the node's fetcher POSTs the
            // applier's exit code after every apply, so the controller no
            // longer infers success from "agent is registered" — which it
            // was even when the applier refused.
            "applied_at": applied_at.map(|t| t.to_rfc3339()),
            "applied_sha": applied_sha,
            "apply_rc": apply_rc,
            "apply_msg": apply_msg,
        }))),
        None => Err(AppError::NotFound("no bundle staged".into())),
    }
}

/// Where the controller's own node's birth cert is visible to the gateway
/// (i67): `<pki>/nodes/<self>/birth.crt` in the certificate-only view the
/// gateway already mounts read-only (`public/nodes` → `/app/pki/nodes`).
/// The CLI copies it there from the host's `/etc/noo/birth.crt` — the cert
/// host prep installed with the key it holds — and the public-view sync
/// mirrors it like every other certificate. The gateway cannot write it, and
/// no API sets it.
///
/// Not a host `/etc/noo` bind: that source does not exist before the self
/// node's identity does, which on a fresh install is after the stack starts,
/// and the launcher's bind-source preflight rightly refuses a missing one.
pub fn self_birth_cert_path(self_id: &str) -> String {
    format!("{}/{}/birth.crt", SELF_NODES_VIEW, self_id.trim())
}

/// The gateway's mount of the PKI's `public/nodes` view.
const SELF_NODES_VIEW: &str = "/app/pki/nodes";

/// Is `node` this controller's own node? Case-insensitive, as node names are;
/// never when the controller does not know its own id.
pub fn is_self_name(node: &str, self_id: Option<&str>) -> bool {
    self_id.is_some_and(|s| !s.trim().is_empty() && s.trim().eq_ignore_ascii_case(node.trim()))
}

/// The self node's birth cert, from the machine (i67).
///
/// `Some(cert)` answers for the controller's own node and is AUTHORITATIVE:
/// the host file or nothing. An enrollment row under that name is never
/// consulted — it may belong to another machine that announced the same name
/// (i11a), and no API can make one stand in for the file. `None` = not the
/// self node; the enrollment record decides. Pure, so the rule is testable.
pub fn self_birth_cert(node: &str, self_id: Option<&str>, read: impl FnOnce() -> Option<String>) -> Option<Option<String>> {
    if !is_self_name(node, self_id) {
        return None;
    }
    Some(read()
        .map(|c| c.trim().to_string())
        .filter(|c| c.starts_with("-----BEGIN CERTIFICATE-----") && c.len() < 16_384))
}

fn read_self_birth_cert() -> Option<String> {
    let id = crate::self_node::self_node_id()?;
    std::fs::read_to_string(self_birth_cert_path(&id)).ok()
}

/// GET /api/cluster/self-node — the controller's own node id and the
/// DER-sha256 fingerprint of the birth cert the gateway verifies its fetch
/// receipts and apply reports against (i67). Read-only: the cert is a host
/// file, and nothing here can change it. `noo cluster provision <self>`
/// compares the fingerprint with `/etc/noo/birth.crt` before staging.
async fn self_node_identity(_op: OperatorOrInternal) -> AppResult {
    let self_id = crate::self_node::self_node_id();
    let cert = self_id.as_deref()
        .and_then(|id| self_birth_cert(id, Some(id), read_self_birth_cert).flatten());
    let fingerprint = cert.as_deref().and_then(|c| ca_der_sha256(c.as_bytes()).ok());
    Ok(Json(json!({
        "node": self_id,
        "birth_cert_path": self_id.as_deref().map(self_birth_cert_path),
        "birth_cert_sha256": fingerprint,
    })))
}

/// POST /bootstrap/bundle/{node}/applied — the node's fetcher reports the
/// applier's outcome for the bundle it just processed: `{sha, rc, msg}`.
///
/// **On the node rail**. This used to be public,
/// inherited from the `/bootstrap/bundle/` prefix on the strength of "the
/// node holds no credential" — true of the GET, false here. By the time a
/// node reports a FULL-bundle apply it has `NOO_CLUSTER_SECRET` in
/// `/etc/noo-node-agent.env`; the bundle it just applied is what delivered
/// it. So the security doc's claim that the apply report is on the node rail
/// is now the code as well as the sentence.
///
/// The route was already on `auth::NODE_ROUTES` as
/// `POST /bootstrap/bundle/{self}/applied` — `{self}` pins the report to the
/// token's own subject, so a node cannot report on its neighbour's behalf.
/// It simply never reached that check, because the public prefix
/// short-circuited the middleware first. `auth::PUBLIC_GET_PATH_PREFIXES`
/// now makes the bundle prefix read-only, so this POST falls through to
/// `require_any_auth` like any other node call.
///
/// The sha equality check below stays: it is a freshness check (this report
/// is about the CURRENTLY staged blob), not an authentication one, and it
/// was never doing the job the auth bypass left vacant.
///
/// **The credential is the node's own birth key, and only that.** The fleet
/// HMAC is one secret every node holds, so `<node>:<ts>:<hmac>` proves "some
/// node" and its `<node>` field is a claim. Since #111 the controller trusts
/// this report's `binary-sha:` line to leave binaries out of the NEXT bundle,
/// so an HMAC-only report would let any node withhold updates from any other
/// by posting a forged "applied" for it. The report is therefore recorded
/// only with a verified `X-Noo-Birth-Proof` over this node and this sha
/// (`ProofStatus::Signed`), whatever the bearer says. Both fetchers
/// (`scripts/noo-fetch.sh`, `noo node fetch`) send it whenever they hold the
/// birth key; the first-phase "applier-only" bundle and a failed apply on a
/// never-provisioned host hold it too, so no legitimate poster is shut out.
/// A node whose fetcher predates the proof gets a 403 naming the fix.
///
/// No internal (controller-secret) poster exists: the controller's own node
/// applies through the same fetcher and signs with its birth cert like any
/// other node (`self_birth_cert`), and no other gateway/worker/CLI code posts
/// here (`noo cluster provision` only READS `/status`). So the old
/// "internal callers are accepted" arm is gone; an internal caller can still
/// post, but only with a proof, like everyone else.
async fn bundle_apply_report(
    State(state): State<Arc<AppState>>,
    Path(node): Path<String>,
    cluster: Option<Extension<crate::auth::ClusterNode>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> AppResult {
    if !valid_node_name(&node) {
        return Err(AppError::BadRequest("invalid node name".into()));
    }
    // Belt and braces on top of `node_route_allowed`'s `{self}` match: that
    // check only runs when `controller_secret()` is set, and an operator
    // JWT reaching here must still not be able to forge a node's report.
    // The bearer no longer PROVES anything on this route (the birth-key
    // proof below is the only credential); this check just keeps a bearer
    // naming another node from being waved through as "close enough".
    if let Some(Extension(c)) = cluster.as_ref() {
        if !c.is_internal() && c.0 != node {
            return Err(AppError::Forbidden(format!(
                "node '{}' may not report an apply for '{node}'",
                c.0
            )));
        }
    }
    let sha = body.get("sha").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    let rc = body.get("rc").and_then(|v| v.as_i64()).unwrap_or(-1) as i32;
    let msg: String = body.get("msg").and_then(|v| v.as_str()).unwrap_or("").chars().take(2000).collect();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("sha must be 64 hex chars".into()));
    }
    match staged_sha(&state.db, &node).await? {
        None => return Err(AppError::NotFound("no bundle staged for this node".into())),
        Some(s) if s != sha => return Err(AppError::BadRequest("sha does not match the staged bundle".into())),
        _ => {}
    }
    // A proof that is present and wrong is a refusal in every mode
    // (check_birth_proof), whatever the bearer says.
    let status = if headers.contains_key(BIRTH_PROOF_HEADER) {
        check_birth_proof(&state.db, &headers, crate::birth_proof::Purpose::Apply, &node, &sha)
            .await?;
        ProofStatus::Signed
    } else {
        ProofStatus::Unsigned(crate::birth_proof::ProofError::Missing)
    };
    let proved_by = match apply_report_decision(&status) {
        Ok(by) => by,
        Err(()) => {
            // No proof. What the operator needs is where to look, and that
            // is the NODE: a Mac that cannot build the proof says why in its
            // own journal rather than posting unsigned.
            tracing::warn!(
                node = %node,
                "bundle_apply_report_refused — no birth-key proof (a fleet bearer alone is not \
                 accepted). On a Mac, `log show --predicate 'process == \"noo\"'` (or the \
                 fetch daemon's stderr) carries the reason it could not sign"
            );
            return Err(AppError::Forbidden(format!(
                "the bundle apply report from '{node}' carried no birth-key proof: this \
                 node's fetcher must sign the report with its birth key (X-Noo-Birth-Proof: \
                 <ts>.<base64 sig> over \"noo-bundle-apply:<node>:<sha>:<ts>\"); restage it \
                 with `noo cluster provision {node} --wait` to install the current fetcher. \
                 A node that HAS a birth key and still sends nothing failed to sign locally: \
                 the reason is in that node's own log, not here"
            )));
        }
    };
    let birth_signed = status == ProofStatus::Signed;
    sqlx::query(
        "UPDATE noo_provision_bundles SET applied_at = now(), applied_sha = $2, apply_rc = $3, apply_msg = $4 \
         WHERE node_name = $1",
    )
    .bind(&node)
    .bind(&sha)
    .bind(rc)
    .bind(&msg)
    .execute(&state.db)
    .await?;
    crate::audit::record(
        &state.db,
        AuditEvent::new(AuditKind::BundleApplyReported, &format!("node:{node}"), &format!("provision-bundle:{node}"))
            .outcome(if rc == 0 { crate::audit::Outcome::Ok } else { crate::audit::Outcome::custom("failed") })
            .severity(if rc == 0 { crate::audit::Severity::Info } else { crate::audit::Severity::Warning })
            .details(json!({ "node": node, "rc": rc, "sha": sha, "msg": msg,
                "proved_by": proved_by })),
    )
    .await;
    Ok(Json(json!({ "recorded": true, "node": node, "rc": rc, "signed": birth_signed })))
}

/// The header a node presents its birth-key proof in: `<ts>.<base64 sig>`.
/// A dedicated header rather than `Authorization`, because the apply report
/// may ALSO carry a cluster-HMAC bearer and the two are different credentials
/// proving different things.
pub const BIRTH_PROOF_HEADER: &str = "x-noo-birth-proof";

// The one-release compatibility window for an UNSIGNED write on the pull
// lane (`NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH`) is RETIRED: every
// write on this lane carries a birth-key proof or the fleet credential. A row
// or env value still holding it open refuses the boot
// (`posture::retired_bridge_refusal`).

/// The birth certificate recorded for this node at enrollment, if any.
///
/// A node may hold several bootstrap-token rows over its life (a re-enroll
/// mints a new one); the most recent row that actually carries a cert is the
/// live identity, so ordering is on `created_at` and rows with no cert are
/// skipped rather than shadowing an older row that has one.
async fn birth_cert_for(db: &sqlx::PgPool, node: &str) -> Option<String> {
    // The controller's own node: the host file, never a row (i67).
    if let Some(cert) = self_birth_cert(node, crate::self_node::self_node_id().as_deref(), read_self_birth_cert) {
        return cert;
    }
    sqlx::query_scalar::<_, String>(
        "SELECT birth_cert FROM noo_bootstrap_tokens \
         WHERE node_name = $1 AND birth_cert IS NOT NULL AND birth_cert <> '' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(node)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}

/// The sha256 of the blob currently staged for this node, if one is staged.
async fn staged_sha(db: &sqlx::PgPool, node: &str) -> Result<Option<String>, AppError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT encode(sha256(blob), 'hex') FROM noo_provision_bundles WHERE node_name = $1",
    )
    .bind(node)
    .fetch_optional(db)
    .await?)
}

/// What a caller proved on the apply report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofStatus {
    /// A birth-key proof verified against the birth cert recorded for this
    /// node.
    Signed,
    /// No proof was offered. On the apply report that is never enough: the
    /// fleet bearer does not substitute for it.
    Unsigned(crate::birth_proof::ProofError),
}

/// Check a birth-key proof. Anything short of a proof that verifies — absent,
/// wrong node, replayed, malformed, or no birth cert on record — is a 403.
/// There is no accept-anyway branch: the compatibility window that accepted
/// an ABSENT proof is retired.
async fn check_birth_proof(
    db: &sqlx::PgPool,
    headers: &axum::http::HeaderMap,
    purpose: crate::birth_proof::Purpose,
    node: &str,
    sha: &str,
) -> Result<(), AppError> {
    let header = headers.get(BIRTH_PROOF_HEADER).and_then(|v| v.to_str().ok());
    let cert = birth_cert_for(db, node).await;
    let now = chrono::Utc::now().timestamp();
    crate::birth_proof::verify(header, purpose, node, sha, cert.as_deref(), now).map_err(|e| {
        tracing::warn!(node = %node, reason = ?e, "bundle_pull_write_proof_rejected");
        AppError::Forbidden(e.message(node))
    })
}

/// The apply report's credential decision, as a pure function.
///
/// Extracted so the one rule that matters can be tested without a database:
/// **only a verified birth-key proof records an apply report.** The fleet
/// HMAC is shared by every node, so it cannot say WHICH node is reporting,
/// and the controller acts on the report (it omits binaries the node says it
/// already has). A request carrying neither, or only the bearer, is refused.
/// A present-and-wrong proof never reaches here: `check_birth_proof` has
/// already returned 403.
pub fn apply_report_decision(proof: &ProofStatus) -> Result<&'static str, ()> {
    match proof {
        ProofStatus::Signed => Ok("birth-key"),
        ProofStatus::Unsigned(_) => Err(()),
    }
}

/// POST /bootstrap/bundle/{node}/fetched — the node's SIGNED receipt for the
/// bundle it just collected: `{sha}` plus an `X-Noo-Birth-Proof` header.
///
/// This exists because `fetched_at` was a state write any anonymous caller
/// could make. It meant "somebody collected
/// this ciphertext", never "the node did" — and a stranger could make
/// `noo cluster provision --wait` believe the applier phase had completed and
/// drive it on to stage the full bundle early.
///
/// Why a separate call rather than a header on the GET: the proof binds the
/// bundle's sha, and at the moment of the GET the node has not yet seen the
/// bytes. Signing only `(node, ts)` on the way IN would prove possession of
/// the birth key but not that this node got THIS blob, which is the thing
/// `fetched_at` is read for. So the node fetches, hashes, and signs.
///
/// The birth key is the one credential the node holds at this moment —
/// `NOO_CLUSTER_SECRET` is rendered into the bundle being fetched, so requiring
/// it here would be a deadlock. See birth_proof.rs.
async fn bundle_fetch_receipt(
    State(state): State<Arc<AppState>>,
    Path(node): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> AppResult {
    if !valid_node_name(&node) {
        return Err(AppError::BadRequest("invalid node name".into()));
    }
    let sha = body.get("sha").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("sha must be 64 hex chars".into()));
    }
    // The sha must be the blob actually staged. This is a freshness check AND
    // half of the replay bound: a proof captured against an older bundle does
    // not verify against the current one's sha.
    match staged_sha(&state.db, &node).await? {
        None => return Err(AppError::NotFound("no bundle staged for this node".into())),
        Some(s) if s != sha => {
            return Err(AppError::BadRequest("sha does not match the staged bundle".into()))
        }
        _ => {}
    }
    // A proof that verifies, or a 403 — there is no unsigned stamp.
    check_birth_proof(&state.db, &headers, crate::birth_proof::Purpose::Fetch, &node, &sha)
        .await?;
    sqlx::query("UPDATE noo_provision_bundles SET fetched_at = now() WHERE node_name = $1")
        .bind(&node)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "recorded": true, "node": node, "signed": true })))
}

/// GET /bootstrap/bundle/{node} — the node's noo-fetch collects its staged
/// bundle. PUBLIC, and it has to be: the blob is end-to-end ciphertext
/// (encrypted to the node's birth key), and the fetch happens BEFORE the
/// node holds any fleet credential — `NOO_CLUSTER_SECRET` is rendered into
/// the `agent-env` member of the very bundle being fetched, so requiring it
/// here would be a chicken-and-egg deadlock. Content authenticity is the CA
/// signature `noo-apply` verifies after decryption. 404 until the operator
/// stages one; the blob stays until re-staged (re-runs are idempotent).
///
/// **The READ is public; the WRITE moved.** (followup
/// 95a.) This handler used to stamp `fetched_at` on the way past, which made
/// it a state write any anonymous caller could make: it meant "somebody
/// collected this ciphertext", never "the node did", and a stranger could make
/// `noo cluster provision --wait` believe the applier phase had completed and
/// drive it on to stage the full bundle early. Three CLI wait-loops read it
/// (`provision --wait`, the applier phase, `security push-secrets`) to narrate
/// progress — none of them makes a security decision on it, and none may start
/// to.
///
/// `fetched_at` is stamped by the node's SIGNED receipt
/// (`POST …/fetched`, birth-key proof over the bundle's sha) and never by
/// this route: it is a pure read. (The one-release window in which a GET
/// still stamped, `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH`, is retired.)
async fn provision_bundle_get(
    State(state): State<Arc<AppState>>,
    Path(node): Path<String>,
) -> impl IntoResponse {
    if !valid_node_name(&node) {
        return (StatusCode::BAD_REQUEST, "invalid node name").into_response();
    }
    let row: Result<Option<(Vec<u8>,)>, _> =
        sqlx::query_as("SELECT blob FROM noo_provision_bundles WHERE node_name = $1")
            .bind(&node)
            .fetch_optional(&state.db)
            .await;
    match row {
        Ok(Some((blob,))) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            blob,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no bundle staged").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "bundle lookup failed").into_response(),
    }
}

// GET /bootstrap/gate (the noo-gate forced-command dispatcher) was removed
// 2026-09-27: prep-host.sh stopped fetching it when the gate lane was
// retired, and it was a public route handing out the entry
// point of an SSH lane nothing dials.

/// GET /bootstrap/apply — the noo-apply root applier. It refuses any
/// bundle not signed by the cluster CA, which is why serving the SCRIPT
/// publicly is harmless: the script is the lock, not the key.
async fn serve_apply_script() -> impl IntoResponse {
    serve_repo_script(crate::paths::BOOTSTRAP_APPLY_SCRIPT_CANDIDATES, "noo-apply script not found").await
}

/// GET /bootstrap/ca.crt — the cluster CA CERTIFICATE (public half only).
/// This is the trust anchor a brand-new node needs BEFORE the first signed
/// bundle can verify: noo-apply refuses everything without it, so birth is
/// the one moment it must arrive out-of-band. Serving it publicly discloses
/// nothing (a certificate is public by construction); the node fetches it
/// during token-authenticated enrollment, which is the sanctioned
/// trust-on-first-use ceremony. The PRIVATE key never leaves noo-cli.
async fn serve_cluster_ca() -> impl IntoResponse {
    // The same list, in the same order, as the pin in the enrollment paste.
    for cand in cluster_ca_candidates() {
        if cand.is_empty() {
            continue;
        }
        if let Ok(content) = tokio::fs::read_to_string(&cand).await {
            if content.contains("BEGIN CERTIFICATE") {
                return (StatusCode::OK, [("content-type", "application/x-pem-file")], content)
                    .into_response();
            }
        }
    }
    (StatusCode::NOT_FOUND, "cluster CA certificate not found").into_response()
}

/// Shared serving shape for the public bootstrap-phase scripts.
async fn serve_repo_script(
    candidates: &'static [&'static str],
    missing: &'static str,
) -> axum::response::Response {
    use crate::paths;
    let Some(path) = paths::resolve(candidates) else {
        return (StatusCode::NOT_FOUND, missing).into_response();
    };
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            (StatusCode::OK, [("content-type", "text/x-shellscript")], content).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, missing).into_response(),
    }
}

async fn serve_prep_script() -> impl IntoResponse {
    use crate::paths;
    let Some(path) = paths::resolve(paths::BOOTSTRAP_PREP_SCRIPT_CANDIDATES) else {
        return (StatusCode::NOT_FOUND, "host prep script not found").into_response();
    };
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [("content-type", "text/x-shellscript")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "host prep script not found").into_response(),
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn role_ctx(role: crate::auth::Role) -> Option<Extension<RequesterCtx>> {
        Some(Extension(RequesterCtx {
            sub: "tester".into(),
            scopes: role.legacy_scopes().iter().map(|s| s.to_string()).collect(),
            role,
            harness: None,
            act: None,
        }))
    }

    // ── Token hash / verify roundtrip ───────────────────────────

    #[test]
    fn token_hash_roundtrip() {
        let raw = generate_bootstrap_token();
        // `noo-bt-` + 32 bytes base64url-no-pad (43 chars), URL-safe alphabet.
        let body = raw.strip_prefix(BOOTSTRAP_TOKEN_PREFIX).expect("a bootstrap token carries noo-bt-");
        assert_eq!(body.len(), 43);
        assert!(!raw.contains(['+', '/', '=']));
        // Deterministic verifier: hashing the presented raw token reproduces
        // the stored hash; any other token does not.
        let stored = hash_token(&raw);
        assert_eq!(stored.len(), 64);
        assert!(stored.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash_token(&raw), stored);
        assert_ne!(hash_token(&generate_bootstrap_token()), stored);
    }

    #[test]
    fn two_mints_never_collide() {
        assert_ne!(generate_bootstrap_token(), generate_bootstrap_token());
    }

    /// a token minted before the `noo-bt-` prefix is stored as
    /// the hash of its bare body and must still redeem, so the redeemer
    /// hashes the WHOLE presented string — never a stripped one, which would
    /// miss every row, bare or prefixed. A pre-prefix token's hash and a
    /// prefixed token's hash are both found by hashing what is presented.
    #[test]
    fn redeemer_hashes_what_is_presented_so_both_forms_redeem() {
        let src = include_str!("bootstrap.rs");
        let start = src.find("async fn cluster_bootstrap(").unwrap();
        let handler = &src[start..src[start..].find("\n}\n").unwrap() + start];
        assert!(handler.contains("hash_token(body.token.trim())"), "the redeemer must hash the presented token");
        assert!(!handler.contains(".strip_prefix(BOOTSTRAP_TOKEN_PREFIX)"), "stripping the prefix orphans every stored token");
        let legacy = "RQm-sKtAHXH6SlzZSlXJp08TMyd2rkAZxb_EwgBRV_8";
        let stored_legacy = hash_token(legacy);
        assert_eq!(hash_token(format!(" {legacy}\n").trim()), stored_legacy);
        let new = generate_bootstrap_token();
        assert_eq!(hash_token(new.trim()), hash_token(&new));
        assert_ne!(hash_token(&new), stored_legacy);
    }

    // ── TTL validation ──────────────────────────────────────────

    #[test]
    fn ttl_default_min_max() {
        assert_eq!(validate_ttl(None), Ok(3600));
        assert_eq!(validate_ttl(Some(1)), Ok(1));
        assert_eq!(validate_ttl(Some(86_400)), Ok(86_400));
        assert!(validate_ttl(Some(0)).is_err());
        assert!(validate_ttl(Some(-5)).is_err());
        // Over-limit is REJECTED, never clamped.
        assert!(validate_ttl(Some(86_401)).is_err());
        assert!(validate_ttl(Some(7 * 86_400)).is_err());
    }

    // ── CIDR matrix ─────────────────────────────────────────────

    #[test]
    fn cidr_v4_matrix() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(cidr_contains("192.168.1.0/24", ip("192.168.1.42")), Some(true));
        assert_eq!(cidr_contains("192.168.1.0/24", ip("192.168.2.42")), Some(false));
        assert_eq!(cidr_contains("10.0.0.0/8", ip("10.255.255.255")), Some(true));
        assert_eq!(cidr_contains("10.0.0.0/8", ip("11.0.0.1")), Some(false));
        // /32 = exact host; bare address means the same thing.
        assert_eq!(cidr_contains("10.1.2.3/32", ip("10.1.2.3")), Some(true));
        assert_eq!(cidr_contains("10.1.2.3/32", ip("10.1.2.4")), Some(false));
        assert_eq!(cidr_contains("10.1.2.3", ip("10.1.2.3")), Some(true));
        assert_eq!(cidr_contains("10.1.2.3", ip("10.1.2.4")), Some(false));
        // /0 matches everything (an operator who writes it gets what it says).
        assert_eq!(cidr_contains("0.0.0.0/0", ip("203.0.113.9")), Some(true));
        // The dual-stack listener case: v4-mapped v6 peer against a v4 CIDR.
        assert_eq!(cidr_contains("192.168.1.0/24", ip("::ffff:192.168.1.7")), Some(true));
    }

    #[test]
    fn cidr_v6_and_family_mismatch() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(cidr_contains("fd00::/8", ip("fd12:3456::1")), Some(true));
        assert_eq!(cidr_contains("fd00::/8", ip("fe80::1")), Some(false));
        assert_eq!(cidr_contains("::1/128", ip("::1")), Some(true));
        // Family mismatch is a definite non-match (deny), not a parse error.
        assert_eq!(cidr_contains("192.168.1.0/24", ip("fd00::1")), Some(false));
        assert_eq!(cidr_contains("fd00::/8", ip("192.168.1.1")), Some(false));
    }

    /// Garbage restrictions must be UNPARSEABLE (None), which the redeemer
    /// treats as deny — a broken restriction restricts everything.
    #[test]
    fn cidr_garbage_is_none_never_true() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        for bad in ["", "/", "banana", "192.168.1.0/33", "192.168.1.0/-1",
                    "fd00::/129", "192.168.1/24", "192.168.1.0/x"] {
            assert_eq!(cidr_contains(bad, ip), None, "cidr {bad:?}");
        }
    }

    // ── Guards ──────────────────────────────────────────────────
    //
    // The operator-or-cluster-HMAC gate is the `OperatorOrInternal` extractor
    // (`authz::tests` drives it through a router); the actor name a call with
    // no user context is recorded under is pinned here.

    #[test]
    fn a_call_with_no_user_is_recorded_as_the_cluster_cli() {
        use crate::auth::Role;
        assert_eq!(OperatorOrInternal(None).actor("cluster-cli"), "cluster-cli");
        assert_eq!(OperatorOrInternal(role_ctx(Role::Operator).map(|e| e.0)).actor("cluster-cli"), "tester");
    }

    // ── Source assertions (no DB harness exists — repo convention) ──

    /// Single-use atomicity: the claim must be a guarded UPDATE whose WHERE
    /// clause re-checks `used_at IS NULL` (the row lock then serializes
    /// concurrent redeemers, so exactly one wins). If someone "simplifies"
    /// this into a bare `SET used_at = now() WHERE id = $1` after the SELECT,
    /// two concurrent redeemers both succeed and single-use is fiction.
    #[test]
    fn the_claim_update_is_guarded_for_single_use() {
        let src = include_str!("bootstrap.rs");
        let claim_start = src
            .find("SET used_at = now(), used_by_ip")
            .expect("claim UPDATE not found");
        // 400, not 300: the window must reach past the bind chain to the
        // rows_affected check; 052 lengthened the UPDATE by one column.
        let claim = &src[claim_start..claim_start + 400];
        assert!(claim.contains("used_at IS NULL"), "claim UPDATE lost its single-use guard");
        assert!(claim.contains("NOT revoked"), "claim UPDATE lost its revocation re-check");
        assert!(claim.contains("expires_at > now()"), "claim UPDATE lost its expiry re-check");
        assert!(claim.contains("rows_affected"), "claim result must be checked, not assumed");
    }

    /// i11a: both enrollment lanes ask who holds the name BEFORE they write
    /// anything. The paste lane before it spends the token (so a refused
    /// machine can rename and re-run the same line), the tailnet lane before
    /// it mints its row. A check placed after the write would refuse the
    /// enrollee and still leave its record under the other machine's name.
    #[test]
    fn both_lanes_check_the_name_before_writing() {
        let src = include_str!("bootstrap.rs");
        let src = src.split("#[cfg(test)]").next().unwrap();
        for (handler, write) in [
            ("async fn cluster_bootstrap(", "UPDATE noo_bootstrap_tokens"),
            ("async fn enroll_tailnet(", "INSERT INTO noo_bootstrap_tokens"),
        ] {
            let start = src.find(handler).unwrap();
            let body = &src[start..start + src[start..].find("\n}\n").unwrap()];
            let check = body.find("node_name_claim::conflict(").unwrap_or_else(|| panic!("{handler} has no name check"));
            let wrote = body.find(write).unwrap_or_else(|| panic!("{handler} has no {write}"));
            assert!(check < wrote, "{handler}: the name check must precede {write}");
            assert!(body[check..wrote].contains("AppError::Conflict("), "{handler}: a conflict must be refused, not logged");
            // Also no delete of the provision bundle before the check: that
            // would drop the HOLDER's staged bundle on a refused claim.
            if let Some(del) = body.find("DELETE FROM noo_provision_bundles") {
                assert!(check < del, "{handler}: bundle delete precedes the name check");
            }
        }
    }

    /// No oracle: every deny path funnels through the single `deny` closure
    /// returning the one uniform message. Assert the uniform constant is the
    /// ONLY Forbidden body in the redemption handler, and that the reason
    /// enum never leaks into a response ("reason" appears only next to
    /// audit::record calls).
    #[test]
    fn redemption_failures_are_uniform() {
        let src = include_str!("bootstrap.rs");
        let handler_start = src.find("async fn cluster_bootstrap(").unwrap();
        let handler = &src[handler_start..src[handler_start..].find("\n}\n").unwrap() + handler_start];
        // Exactly one Forbidden construction inside the handler, and it uses
        // the shared constant.
        assert_eq!(
            handler.matches("AppError::Forbidden").count(),
            1,
            "the redemption handler must have exactly one Forbidden exit (the uniform deny)"
        );
        assert!(handler.contains("AppError::Forbidden(DENIED_MSG.into())"));
        // Every DenyReason variant is exercised by some deny(...) call — a
        // reason that exists but is never audited is a blind spot.
        for reason in ["Unknown", "Revoked", "AlreadyUsed", "Expired",
                       "CidrMismatch", "CidrUnparseable", "LostRace"] {
            assert!(
                handler.contains(&format!("DenyReason::{reason}")),
                "DenyReason::{reason} is never raised by the handler"
            );
        }
    }

    /// The raw token must never be persisted or audited: the INSERT binds the
    /// hash, and no audit details object references the raw value.
    #[test]
    fn raw_token_never_persisted_or_audited() {
        let src = include_str!("bootstrap.rs");
        let create_start = src.find("async fn bootstrap_token_create(").unwrap();
        let create = &src[create_start..src[create_start..].find("\n}\n").unwrap() + create_start];
        assert!(create.contains(".bind(&token_hash)"), "INSERT must bind the hash");
        assert!(!create.contains(".bind(&raw)"), "the raw token must never be bound to SQL");
        // The audit call's arguments (everything up to its `.await`) must not
        // carry the raw token or the hash.
        let audit_start = create.find("audit::record").unwrap();
        let after = &create[audit_start..];
        let audit_call = &after[..after.find(".await").expect("audit call is awaited")];
        assert!(!audit_call.contains("raw"), "audit details must not include the raw token");
        assert!(!audit_call.contains("token_hash"), "audit details must not include the hash");
    }

    /// Mechanical audit coverage, mirroring
    /// `users::tests::every_security_mutation_writes_an_audit_row` for THIS
    /// module (that test scans users.rs only): every mutating route
    /// registered here must write an audit row in its handler body.
    #[test]
    fn every_bootstrap_mutation_writes_an_audit_row() {
        let src = include_str!("bootstrap.rs");
        let mut handlers: Vec<String> = Vec::new();
        for line in src.lines() {
            if !line.contains("\"/api/") {
                continue;
            }
            for verb in ["post(", "put(", "patch(", "delete("] {
                let mut rest = line;
                while let Some(i) = rest.find(verb) {
                    let after = &rest[i + verb.len()..];
                    let name: String = after
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        handlers.push(name);
                    }
                    rest = after;
                }
            }
        }
        assert!(handlers.len() >= 3, "expected create/revoke/bootstrap, found {handlers:?}");
        for name in &handlers {
            let start = src
                .find(&format!("async fn {name}("))
                .unwrap_or_else(|| panic!("{name} not found"));
            let body = &src[start..src[start..].find("\n}\n").unwrap_or(src.len() - start) + start];
            assert!(
                body.contains("audit::record"),
                "mutating bootstrap route handler {name} writes no audit row"
            );
        }
    }

    // ── Enrollment paste composition ────────────────────────────

    /// Decode a composed `noo enroll` line the way `noo enroll`'s
    /// `parse_blob` does (noo-cli/src/commands/enroll.rs): strip `noo1.`,
    /// base64url-no-pad, JSON, `v == 1`.
    fn decode_enroll(cmd: &str) -> Value {
        let blob = cmd.strip_prefix("noo enroll ").expect("an enroll command");
        let b64 = blob.strip_prefix("noo1.").expect("a noo1. blob");
        assert!(!b64.contains('=') && !b64.contains('+') && !b64.contains('/'), "base64url, no padding: {b64}");
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["v"].as_i64(), Some(1));
        v
    }

    #[test]
    fn the_enroll_blob_carries_what_noo_enroll_reads() {
        let cmd = compose_enroll_command("https://ctl.example.ts.net:8080", "RAWTOK", "tskey-auth-x", "ab12", Some("n1"));
        let v = decode_enroll(&cmd);
        assert_eq!(v["url"], "https://ctl.example.ts.net:8080");
        assert_eq!(v["token"], "RAWTOK");
        assert_eq!(v["tsk"], "tskey-auth-x");
        assert_eq!(v["ca"], "ab12");
        assert_eq!(v["node"], "n1");

        // Unbound, off-tailnet: no node key, an empty tsk (parse_blob reads
        // an empty string as "no key"), and the pin is still there.
        let v = decode_enroll(&compose_enroll_command("https://c:8080", "T", "", "ff", None));
        assert!(v.get("node").is_none(), "{v}");
        assert_eq!(v["tsk"], "");
        assert_eq!(v["ca"], "ff");
    }

    #[test]
    fn the_install_line_is_the_public_signed_lane() {
        assert_eq!(
            compose_install_command("org/repo"),
            "command -v noo >/dev/null || curl -fsSL https://raw.githubusercontent.com/org/repo/main/noo-cli/install.sh | sh"
        );
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-bt-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The pin is the DER sha256 of the served CA — the value `noo enroll`
    /// recomputes over `/bootstrap/ca.crt`.
    #[test]
    fn the_pin_is_the_der_sha256_of_the_served_ca() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        let dir = scratch("pin");
        let path = dir.join("ca.crt");
        std::fs::write(&path, cert.pem()).unwrap();
        let got = cluster_ca_fingerprint_from(&[String::new(), path.display().to_string()]).unwrap();
        use sha2::{Digest, Sha256};
        assert_eq!(got, hex::encode(Sha256::digest(cert.der().as_ref())));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// No CA, or a CA that is not a certificate: an error, never a blob
    /// without a pin (the node would refuse it).
    #[test]
    fn no_readable_ca_is_an_error_not_an_unpinned_paste() {
        let dir = scratch("noca");
        let missing = dir.join("absent.crt").display().to_string();
        let e = cluster_ca_fingerprint_from(std::slice::from_ref(&missing)).unwrap_err();
        assert!(e.contains("no cluster CA certificate"), "{e}");

        let junk = dir.join("junk.crt");
        std::fs::write(&junk, "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n").unwrap();
        let e = cluster_ca_fingerprint_from(&[missing, junk.display().to_string()]).unwrap_err();
        assert!(e.contains("unusable"), "{e}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unreachable_controller_url_is_refused() {
        for bad in [
            "https://localhost:8080",
            "https://127.0.0.1:8080",
            "https://[::1]:8080",
            "https://gateway:8080",
            "https://0.0.0.0:8080",
            "http://ctl.example.ts.net:8080",
        ] {
            assert!(enroll_url(bad).is_err(), "{bad} must be refused");
        }
        assert_eq!(enroll_url("https://ctl.example.ts.net:8080").unwrap(), "https://ctl.example.ts.net:8080");
        assert!(enroll_url("https://100.64.0.1:8080").is_ok());
    }

    /// The apply report's rule, pinned: **only a verified birth-key proof
    /// records it.** The fleet HMAC (one secret on every node) never
    /// substitutes, and "no credential at all" stays refused (#95).
    #[test]
    fn only_a_birth_key_proof_records_an_apply_report() {
        use crate::birth_proof::ProofError;
        // Signed: recorded, attributed to the birth key.
        assert_eq!(apply_report_decision(&ProofStatus::Signed), Ok("birth-key"));
        // HMAC-only or nothing at all both arrive as Unsigned(Missing): the
        // bearer is not an input to the decision any more. REFUSED.
        assert_eq!(apply_report_decision(&ProofStatus::Unsigned(ProofError::Missing)), Err(()));
        // And refused for every reason an unsigned report can carry.
        assert_eq!(apply_report_decision(&ProofStatus::Unsigned(ProofError::NoBirthCert)), Err(()));
    }

    /// A present-and-wrong proof is a 403 in `check_birth_proof` before the
    /// decision is reached; pin that the decision has no path that would
    /// turn a non-`Signed` status into an accept.
    #[test]
    fn the_apply_decision_has_no_accept_anyway_branch() {
        let src = include_str!("bootstrap.rs");
        let a = src.find("pub fn apply_report_decision").expect("decision fn");
        let body = &src[a..a + 300];
        assert!(!body.contains("cluster"), "the fleet bearer must not feed the apply decision");
    }

    /// i67: the controller's own node's birth cert is the host file, and
    /// only the host file — an enrollment row under its name is never read,
    /// and a missing or malformed file is "no cert" (refused), not a fallback.
    #[test]
    fn the_self_nodes_birth_cert_is_the_host_file_alone() {
        const PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(self_birth_cert("pop-os", Some("pop-os"), || Some(PEM.into())),
            Some(Some(PEM.trim().to_string())));
        assert_eq!(self_birth_cert("Pop-OS", Some("pop-os"), || Some(PEM.into())),
            Some(Some(PEM.trim().to_string())), "case-insensitive, as node names are");
        assert_eq!(self_birth_cert("pop-os", Some("pop-os"), || None), Some(None),
            "no file: no cert, and the DB is NOT consulted");
        assert_eq!(self_birth_cert("pop-os", Some("pop-os"), || Some("garbage".into())), Some(None));
        // Every other node: the enrollment record decides (the reader is
        // not even called).
        assert_eq!(self_birth_cert("aserve", Some("pop-os"), || panic!("read for a remote node")), None);
        assert_eq!(self_birth_cert("pop-os", None, || panic!("read with no self id")), None);
        assert_eq!(self_birth_cert("pop-os", Some(" "), || panic!("read with a blank self id")), None);
    }

    /// 0.6.3-rc.1 F1: the gateway reads the self node's cert from the PKI's
    /// read-only certificate view it already mounts, not a host /etc bind
    /// (which does not exist before the node identity does).
    #[test]
    fn the_self_nodes_cert_is_read_from_the_pki_view() {
        assert_eq!(self_birth_cert_path("pop-os"), "/app/pki/nodes/pop-os/birth.crt");
        assert_eq!(self_birth_cert_path(" pop-os "), "/app/pki/nodes/pop-os/birth.crt");
        let src = include_str!("bootstrap.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        assert!(!code.contains(&["\"/etc/noo/", "self-node"].concat()), "no host /etc path is read");
    }

    /// No route writes the self node's identity: the only self-node route is
    /// a GET, and `birth_cert_for` asks the host file first.
    #[test]
    fn no_api_writes_the_self_nodes_birth_cert() {
        let src = include_str!("bootstrap.rs");
        let code = src.split("#[cfg(test)]").next().unwrap();
        for line in code.lines().filter(|l| l.contains("\"/api/cluster/self-node")) {
            assert!(line.contains("get(") && !line.contains("post(") && !line.contains("put("), "{line}");
        }
        let f = &code[code.find("async fn birth_cert_for(").unwrap()..];
        let file = f.find("self_birth_cert(").expect("host file first");
        let row = f.find("FROM noo_bootstrap_tokens").expect("then the row");
        assert!(file < row);
    }

    /// The retired unsigned-write window (`NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH`)
    /// must not come back through any of its three doors: the proof checker
    /// accepting an absent proof, the receipt stamping unsigned, or the public
    /// GET stamping on the way past.
    #[test]
    fn no_pull_lane_route_writes_without_a_proof() {
        let src = include_str!("bootstrap.rs");
        let body = |name: &str| -> String {
            let tail = src
                .split(&format!("async fn {name}("))
                .nth(1)
                .unwrap_or_else(|| panic!("{name} must still exist"));
            tail.split("\n}\n").next().unwrap_or_default().to_string()
        };
        let checker = body("check_birth_proof");
        // Assert the parse found the real body before trusting an absence.
        assert!(checker.contains("birth_proof::verify"), "parse missed check_birth_proof");
        assert!(!checker.contains("apply_window") && !checker.contains("Unsigned"),
            "check_birth_proof must have no accept-anyway branch");
        let receipt = body("bundle_fetch_receipt");
        assert!(receipt.contains("check_birth_proof"), "parse missed bundle_fetch_receipt");
        assert!(!receipt.contains("bundle_pull_write_unsigned"),
            "the fetch receipt must not stamp fetched_at without a proof");
        let get = body("provision_bundle_get");
        assert!(get.contains("SELECT blob"), "parse missed provision_bundle_get");
        assert!(!get.contains("UPDATE"), "the public GET must be a pure read");
        assert!(!src.contains(&["\"NOO_BOOTSTRAP_", "ACCEPT_UNSIGNED_FETCH\""].concat()),
            "the retired gate must not be read again");
    }
}
