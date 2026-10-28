// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! TLS configuration — shared across all HTTP clients and the server.
//!
//! All inter-service communication uses TLS:
//!   Gateway ←→ vLLM/Ollama/llamacpp  (HTTPS)
//!   Gateway ←→ Node Agent            (HTTPS) — mesh-routed embed/rerank
//!                                     traffic (default embedder: ollama/
//!                                     harrier; default reranker: hardened
//!                                     llama.cpp) rides this leg, not a
//!                                     dedicated TEI path. TEI is optional/
//!                                     legacy: still reachable as a wire
//!                                     format if an install still runs it
//!                                     (HTTPS via stunnel), but is no longer
//!                                     the deployed default.
//!   Gateway ←→ NATS                  (TLS)
//!   Gateway ←→ Postgres              (TLS)
//!   Dashboard ←→ Gateway             (HTTPS, browser trusts cluster CA)

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Env var overriding how long a gateway → cluster HTTP call may take.
pub const BACKEND_TIMEOUT_ENV: &str = "NOO_BACKEND_TIMEOUT_SECS";

/// The default whole-request bound on gateway → node-agent/backend calls.
const DEFAULT_BACKEND_TIMEOUT_SECS: u64 = 300;

/// How long [`cluster_client`] waits for a complete response.
///
/// This is the OUTER bound on an LLM call. It is a whole-request timeout,
/// not a first-byte one, so on a non-streaming completion it caps the
/// entire generation — and the node-agent's proxy sits inside it with its
/// own `NOO_BACKEND_FIRST_BYTE_TIMEOUT_SECS` (default 290 s). 300 s is
/// ample for a GPU node and not ample for a CPU-only one: a 12B model
/// answering a long prompt on host7 (no discrete GPU) overran it, and
/// persona generation came back as `502 backend_unreachable` — a slow
/// backend wearing a dead backend's error.
///
/// Raise BOTH ends or neither: whichever is lower is the one that fires.
fn backend_timeout() -> std::time::Duration {
    static SECS: OnceLock<u64> = OnceLock::new();
    let secs = *SECS.get_or_init(|| {
        let raw = std::env::var(BACKEND_TIMEOUT_ENV).unwrap_or_default();
        match resolve_backend_timeout_secs(&raw) {
            Ok(secs) => {
                if secs != DEFAULT_BACKEND_TIMEOUT_SECS {
                    tracing::info!(env = BACKEND_TIMEOUT_ENV, seconds = secs, "backend timeout overridden");
                }
                secs
            }
            Err(why) => {
                tracing::warn!(
                    env = BACKEND_TIMEOUT_ENV, value = %raw, %why,
                    default_seconds = DEFAULT_BACKEND_TIMEOUT_SECS,
                    "ignoring an unusable backend timeout override; keeping the default"
                );
                DEFAULT_BACKEND_TIMEOUT_SECS
            }
        }
    });
    std::time::Duration::from_secs(secs)
}

/// Parse the override. Blank means "unset" (the default); anything else must
/// be a positive whole number of seconds. A typo must never disable the
/// bound — an unbounded client turns one hung backend into a leaked
/// connection per request — so every rejection keeps the default.
fn resolve_backend_timeout_secs(raw: &str) -> Result<u64, &'static str> {
    resolve_positive_secs(raw, DEFAULT_BACKEND_TIMEOUT_SECS)
}

/// Blank = `default`; otherwise a positive whole number of seconds, or an
/// error the caller logs before keeping the default.
fn resolve_positive_secs(raw: &str, default: u64) -> Result<u64, &'static str> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(default);
    }
    match raw.parse::<u64>() {
        Ok(0) => Err("zero would disable the timeout"),
        Ok(secs) => Ok(secs),
        Err(_) => Err("not a whole number of seconds"),
    }
}

/// Env var overriding how long a STREAMED response may go silent.
pub const STREAM_IDLE_ENV: &str = "NOO_BACKEND_STREAM_IDLE_SECS";

/// The default idle bound on a streamed response (SSE inference). 300 s,
/// the patience the old WHOLE-request bound gave the first byte: reqwest's
/// read timeout also covers the wait for headers, i.e. a cold model load +
/// prompt prefill, which has taken over a minute on these nodes. It no longer
/// bounds the whole answer; a stream that keeps producing is never cut.
pub const DEFAULT_STREAM_IDLE_SECS: u64 = 300;

/// How long a streamed response may go without a byte before it counts as
/// cut: `NOO_BACKEND_STREAM_IDLE_SECS`, default 120 s, parsed like
/// [`BACKEND_TIMEOUT_ENV`] (blank or unusable = the default, said once).
///
/// A stream has NO total bound. [`backend_timeout`] is a whole-request
/// timeout, and on a streamed body it cut a slow node's answer at exactly
/// 300 s while tokens were still arriving (mcmini, gemma4:12b reasoning for
/// 3-4.5 min per call, 2026-10-17). A stream is alive while bytes arrive;
/// what ends it is silence.
///
/// In reqwest 0.12 the read timeout also bounds the wait for the response
/// HEADERS, and a backend sends nothing until its first token: so this is
/// also the budget for model load + prompt prefill. Raise it on a node whose
/// prefill is slower than that.
pub fn stream_idle() -> std::time::Duration {
    let secs = *STREAM_IDLE_SECS.get_or_init(|| {
        let raw = std::env::var(STREAM_IDLE_ENV).unwrap_or_default();
        match resolve_positive_secs(&raw, DEFAULT_STREAM_IDLE_SECS) {
            Ok(secs) => {
                if secs != DEFAULT_STREAM_IDLE_SECS {
                    tracing::info!(env = STREAM_IDLE_ENV, seconds = secs, "stream idle timeout overridden");
                }
                secs
            }
            Err(why) => {
                tracing::warn!(
                    env = STREAM_IDLE_ENV, value = %raw, %why,
                    default_seconds = DEFAULT_STREAM_IDLE_SECS,
                    "ignoring an unusable stream idle timeout override; keeping the default"
                );
                DEFAULT_STREAM_IDLE_SECS
            }
        }
    });
    std::time::Duration::from_secs(secs)
}

/// The stream idle bound in force for this PROCESS: set once, on the first
/// [`stream_idle`] read or by [`set_stream_idle_override`], whichever comes
/// first, and never changed after (the stream clients bake it in).
static STREAM_IDLE_SECS: OnceLock<u64> = OnceLock::new();

/// Fix the stream idle bound for this process before anything reads it.
///
/// For `noo-gateway harness`: its node's harness profile carries
/// `stream_idle_secs`, which applies when `NOO_BACKEND_STREAM_IDLE_SECS` is
/// not set (process env > profile > [`DEFAULT_STREAM_IDLE_SECS`]). The
/// harness calls this ONCE at start, after reading its placement and before
/// it builds a stream client or starts a translator. Process-wide: every
/// stream client this process builds, and every later [`stream_idle`] read,
/// gets the value. Returns `false` (and changes nothing) when the bound was
/// already fixed, i.e. something read it first; zero is refused likewise.
pub fn set_stream_idle_override(idle: std::time::Duration) -> bool {
    let secs = idle.as_secs();
    if secs == 0 {
        return false;
    }
    let set = STREAM_IDLE_SECS.set(secs).is_ok();
    if set {
        tracing::info!(seconds = secs, "stream idle timeout set from the harness profile");
    }
    set
}

/// The timeouts a client is built with. reqwest does not expose them on a
/// built `Client`, so each shared client is built FROM one of these, and
/// the tests assert on the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientTimeouts {
    /// Whole request, body included (`ClientBuilder::timeout`). `None` on
    /// a stream client.
    pub total: Option<std::time::Duration>,
    /// Longest gap between reads (`ClientBuilder::read_timeout`).
    pub read_idle: Option<std::time::Duration>,
    pub connect: std::time::Duration,
}

impl ClientTimeouts {
    /// The shared unary cluster client's: total [`backend_timeout`], 10 s connect.
    pub fn cluster() -> Self {
        Self { total: Some(backend_timeout()), read_idle: None, connect: std::time::Duration::from_secs(10) }
    }

    /// The cluster STREAM client's: no total, [`stream_idle`] between reads.
    pub fn cluster_stream() -> Self {
        Self::stream_with_idle(stream_idle())
    }

    /// A stream client's timeouts with a caller-chosen idle (tests).
    pub fn stream_with_idle(idle: std::time::Duration) -> Self {
        Self { total: None, read_idle: Some(idle), connect: std::time::Duration::from_secs(10) }
    }

    /// The public-internet unary client's (cloud providers, channels).
    pub fn external() -> Self {
        Self { total: Some(std::time::Duration::from_secs(120)), read_idle: None, connect: std::time::Duration::from_secs(10) }
    }

    /// The public-internet STREAM client's (a cloud provider's SSE).
    pub fn external_stream() -> Self {
        Self::cluster_stream()
    }

    /// Put these timeouts on a builder.
    pub fn apply(self, mut b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        if let Some(t) = self.total {
            b = b.timeout(t);
        }
        if let Some(r) = self.read_idle {
            b = b.read_timeout(r);
        }
        b.connect_timeout(self.connect)
    }
}

/// The Mozilla root set as reqwest certificates, parsed once.
fn bundled_roots() -> &'static [reqwest::Certificate] {
    static ROOTS: OnceLock<Vec<reqwest::Certificate>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter_map(|c| reqwest::Certificate::from_der(c.as_ref()).ok())
            .collect()
    })
}

/// A `reqwest::Client::builder()` that trusts BOTH root stores: the system
/// store (reqwest 0.13's default verifier is rustls-platform-verifier) and
/// the bundled Mozilla roots, merged in with `tls_certs_merge`. reqwest 0.13
/// has no bundled-roots feature, and the platform verifier alone refuses to
/// build a client on an image with no CA bundle ("No CA certificates were
/// loaded from the system"); the merged roots also make that case work.
/// Every public-internet or system-trust client here starts from this. The
/// cluster client does not: it trusts only the cluster CA.
pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().tls_certs_merge(bundled_roots().iter().cloned())
}

/// A plain (system-trust, no client identity) client with `t`. For tests
/// and the fallback when the cluster TLS material cannot be loaded.
pub fn plain_client(t: ClientTimeouts) -> reqwest::Client {
    t.apply(client_builder()).build().unwrap_or_default()
}

/// Shared intra-cluster client: cluster CA + mTLS identity, one connection
/// pool reused across all gateway → node-agent/backend/TEI traffic.
///
/// TLS material is loaded once at first use — after `noo security pki
/// rotate-all` the gateway must be restarted to pick up new leaf certs
/// (already true for the server cert, which loads at startup).
///
/// When the cluster CA is configured this client trusts ONLY the cluster
/// CA — it cannot reach public-internet hosts. Use [`external_client`]
/// for those.
pub fn cluster_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            build_https_client().unwrap_or_else(|e| {
                tracing::warn!(error = %e, "cluster TLS client build failed; falling back to default client");
                plain_client(ClientTimeouts::cluster())
            })
        })
        .clone()
}

/// The cluster client for a response read INCREMENTALLY (SSE inference):
/// same trust, same identity, same connect timeout as [`cluster_client`],
/// but no total timeout, only [`stream_idle`] between reads. A model that
/// reasons for five minutes while tokens keep arriving is not cut; one that
/// goes silent for the idle bound is, with a body error the reader reports
/// as a cut stream.
pub fn cluster_stream_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            build_https_client_with(ClientTimeouts::cluster_stream()).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "cluster TLS stream client build failed; falling back to default client");
                plain_client(ClientTimeouts::cluster_stream())
            })
        })
        .clone()
}

/// Shared client for public-internet APIs (Google, Telegram, WhatsApp, …)
/// using system/webpki trust roots. Never presents the cluster mTLS
/// identity to external hosts.
pub fn external_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| plain_client(ClientTimeouts::external())).clone()
}

/// [`external_client`] for a cloud provider's STREAMED answer: no total
/// timeout (the unary client's 120 s cut a long cloud stream the same way
/// the cluster client cut a node's), [`stream_idle`] between reads.
pub fn external_stream_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| plain_client(ClientTimeouts::external_stream())).clone()
}

/// Shared client for HTTPS self-calls to this gateway.
///
/// It VERIFIES. It used to be built with
/// `danger_accept_invalid_certs(true)`, reasoned as "validating our own
/// cert on a loopback call adds no security" and fenced with a doc comment
/// saying "must never be used for non-loopback URLs". Both halves were
/// wrong in the same way `mcp_external::execute_spec` was, and that site
/// already carries the argument:
///
///   * nothing had to be shipped to verify — the gateway's leaf is
///     cluster-CA signed, the CA is mounted at `NOO_TLS_CA`, and the cert's
///     SANs already include `localhost` and `IP Address:127.0.0.1` (see
///     `noo-cli/src/pki.rs::issue_gateway_cert`);
///   * `danger_accept_invalid_certs` is not scoped to the handshake it was
///     reasoned about. This is a shared `OnceLock` singleton handed to
///     every caller, so the only thing keeping it loopback-only was a
///     comment, and a comment is not a control.
///
/// No anchor configured → system roots, never a bypass.
pub fn loopback_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let mut b = client_builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(5));
            match cluster_ca_certificate() {
                Ok(Some(cert)) => b = b.tls_certs_merge([cert]),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "NOO_TLS_CA is set but unusable; self-calls fall back to the system trust store"
                ),
            }
            b.build().unwrap_or_default()
        })
        .clone()
}

/// Env var naming the cluster CA file.
pub const CA_ENV: &str = "NOO_TLS_CA";
/// Env var naming the PKI directory.
pub const PKI_DIR_ENV: &str = "NOO_PKI_DIR";

/// THE reader of `NOO_TLS_CA`. One documented unset behaviour: `None` when
/// the variable is unset, empty or whitespace. A set value is returned
/// trimmed and unchecked (it may not exist; the caller decides whether that
/// matters). Callers choose the consequence; only startup (`main.rs` /
/// `startup_tasks.rs`) may refuse to boot, and its message must name
/// `NOO_TLS_CA`. A source-scan test pins that no other file reads the var.
pub fn ca_path() -> Option<PathBuf> {
    env_path(CA_ENV)
}

/// THE reader of `NOO_PKI_DIR`; same contract as [`ca_path`] (`None` when
/// unset or blank, otherwise trimmed and unchecked).
pub fn pki_dir() -> Option<PathBuf> {
    env_path(PKI_DIR_ENV)
}

fn env_path(var: &str) -> Option<PathBuf> {
    let v = std::env::var(var).ok()?;
    let v = v.trim();
    (!v.is_empty()).then(|| PathBuf::from(v))
}

/// The cluster CA as a reqwest root, if `NOO_TLS_CA` names a readable PEM.
///
/// `Ok(None)` means no anchor was configured — a public cert (tailscale
/// serve) or plain dev, where the system roots are the right answer.
/// `Err` means one WAS configured and could not be used, which is a
/// misconfiguration the caller should say out loud rather than paper over.
pub fn cluster_ca_certificate() -> Result<Option<reqwest::Certificate>> {
    let Some(path) = ca_path().map(|p| p.to_string_lossy().into_owned()) else {
        return Ok(None);
    };
    let pem = std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("cannot read NOO_TLS_CA at {path}: {e}"))?;
    let cert = certificate_from_pem(&pem)
        .map_err(|e| anyhow::anyhow!("NOO_TLS_CA at {path} is not valid PEM: {e}"))?;
    Ok(Some(cert))
}

/// A CA certificate for reqwest from PEM bytes, REFUSING bytes that carry
/// no CERTIFICATE block.
///
/// Under reqwest's rustls backend `Certificate::from_pem` accepts junk
/// silently — no block found, nothing to add, `Ok` — where the native-tls
/// backend errored. Found 2026-09-18 by the loopback-verification test the
/// moment native-tls left the build: a `NOO_TLS_CA` pointing at a
/// not-a-certificate file would have fallen back to the system roots
/// without a word, which is the exact failure that test exists to forbid.
/// So the block is counted here, with the parser the bus already uses, and
/// absence is an error before reqwest ever sees the bytes.
pub fn certificate_from_pem(pem: &[u8]) -> Result<reqwest::Certificate> {
    let blocks = rustls_pemfile::certs(&mut std::io::BufReader::new(pem))
        .filter(|c| c.is_ok())
        .count();
    if blocks == 0 {
        anyhow::bail!("no CERTIFICATE block found");
    }
    Ok(reqwest::Certificate::from_pem(pem)?)
}

/// Build a reqwest Client that trusts the cluster CA + mTLS identity.
///
/// Uses the lower-level rustls API to ensure EC P-384 client certs
/// are properly configured and presented during TLS handshake.
pub fn build_https_client() -> Result<reqwest::Client> {
    build_https_client_with(ClientTimeouts::cluster())
}

/// The cluster client with a SHORT connect timeout, for the raw-path
/// failover lane: a candidate that does not accept the
/// TCP/TLS handshake within `FAILOVER_CONNECT_SECS` is skipped for the next
/// one instead of holding the request for the shared client's 10 s. Same
/// trust and identity as [`cluster_client`]; only the connect budget differs.
pub fn failover_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let t = ClientTimeouts { connect: std::time::Duration::from_secs(FAILOVER_CONNECT_SECS), ..ClientTimeouts::cluster() };
            build_https_client_with(t).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failover TLS client build failed; falling back to default client");
                plain_client(t)
            })
        })
        .clone()
}

/// Per-attempt connect budget on the failover lane.
pub const FAILOVER_CONNECT_SECS: u64 = 5;

fn build_https_client_with(timeouts: ClientTimeouts) -> Result<reqwest::Client> {
    match cluster_rustls_config()? {
        Some(cfg) => {
            let builder = timeouts.apply(reqwest::Client::builder()).tls_backend_preconfigured((*cfg).clone());
            Ok(builder.build()?)
        }
        None => {
            // No custom TLS — use defaults
            tracing::info!("TLS: using system trust store (no cluster CA)");
            Ok(timeouts.apply(client_builder()).build()?)
        }
    }
}

/// The cluster's rustls client config (the CA in `NOO_TLS_CA`, the mTLS
/// identity in `NOO_TLS_CERT`/`NOO_TLS_KEY`), shared by every HTTPS client
/// here and by the reserved-workload WebSocket relay. `None` when neither is
/// configured (the system trust store applies).
pub fn cluster_rustls_config() -> Result<Option<std::sync::Arc<rustls::ClientConfig>>> {
    let ca_path = ca_path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let cert_path = std::env::var("NOO_TLS_CERT").unwrap_or_default();
    let key_path = std::env::var("NOO_TLS_KEY").unwrap_or_default();

    // Build a custom rustls ClientConfig for full control over mTLS
    let has_ca = !ca_path.is_empty() && Path::new(&ca_path).exists();
    let has_identity = !cert_path.is_empty() && !key_path.is_empty()
        && Path::new(&cert_path).exists() && Path::new(&key_path).exists();

    if !(has_ca || has_identity) {
        return Ok(None);
    }
        // Build root cert store
        let mut root_store = rustls::RootCertStore::empty();

        if has_ca {
            let ca_pem = std::fs::read(&ca_path)?;
            let mut cursor = std::io::Cursor::new(&ca_pem);
            for cert in rustls_pemfile::certs(&mut cursor) {
                match cert {
                    Ok(c) => { root_store.add(c)?; }
                    Err(e) => { tracing::warn!(error = %e, "skipping invalid CA cert"); }
                }
            }
            tracing::info!(ca = %ca_path, "TLS: cluster CA loaded");
        } else {
            // Fall back to webpki roots
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let config_builder = rustls::ClientConfig::builder()
            .with_root_certificates(root_store);

        let tls_config = if has_identity {
            // Load client cert chain
            let cert_pem = std::fs::read(&cert_path)?;
            let mut cert_cursor = std::io::Cursor::new(&cert_pem);
            let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut cert_cursor)
                    .filter_map(|r| r.ok())
                    .collect();

            // Load private key (supports PKCS8, EC, RSA formats)
            let key_pem = std::fs::read(&key_path)?;
            let mut key_cursor = std::io::Cursor::new(&key_pem);
            let key = rustls_pemfile::private_key(&mut key_cursor)?
                .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;

            tracing::info!(
                cert = %cert_path,
                certs_in_chain = certs.len(),
                "TLS: mTLS client identity loaded"
            );

            config_builder.with_client_auth_cert(certs, key)?
        } else {
            config_builder.with_no_client_auth()
        };

    Ok(Some(std::sync::Arc::new(tls_config)))
}

/// The rustls config the gateway dials an add-on's WebSocket with
/// (`addon_ws`): the SAME trust and identity as [`cluster_client`]
/// ([`cluster_rustls_config`]: cluster CA, the gateway's leaf as client
/// certificate), ALPN pinned to `http/1.1` because a WebSocket handshake is
/// an HTTP/1.1 upgrade. Built once, like the shared clients; `None` when the
/// cluster TLS material cannot be loaded, which the caller turns into a
/// refusal (an add-on door is mTLS, there is no plain one to fall back to).
pub fn cluster_ws_tls_config() -> Option<std::sync::Arc<rustls::ClientConfig>> {
    static CONFIG: OnceLock<Option<std::sync::Arc<rustls::ClientConfig>>> = OnceLock::new();
    CONFIG
        .get_or_init(|| match cluster_rustls_config() {
            Ok(Some(c)) => {
                let mut c = (*c).clone();
                c.alpn_protocols = vec![b"http/1.1".to_vec()];
                Some(std::sync::Arc::new(c))
            }
            Ok(None) => {
                tracing::warn!("add-on WebSocket TLS: no cluster TLS material (NOO_TLS_CA/CERT/KEY); add-on sockets are refused");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "add-on WebSocket TLS: cluster TLS config build failed; add-on sockets are refused");
                None
            }
        })
        .clone()
}

/// The three env vars the listener cannot start without.
pub const SERVER_MATERIAL_ENV: [&str; 3] = ["NOO_TLS_CERT", "NOO_TLS_KEY", "NOO_TLS_CA"];

/// The gateway serves HTTPS and nothing else: refuse to start unless the
/// server leaf, its key AND the cluster CA are all set and readable.
///
/// Until 2026-09-29 an unset `NOO_TLS_CERT` fell through to a plain
/// `0.0.0.0:8080` listener behind a `warn!` — every login and every token on
/// the port in the clear, on a container that cannot see which host
/// interface publishes it, and indistinguishable at a glance from a
/// working install (the readiness checklist; the wizard's `--skip-security`
/// got there in silence). The operator's rule is "TLS and https default
/// everywhere, fail loud", so the branch is gone: the ONLY listener is the
/// TLS acceptor, and this is the loud part.
///
/// The CA is required too, not just the leaf: every scheme site in this
/// crate now dials `https://` unconditionally (there is no plain door left
/// on the compose network to dial), the `--health` probe verifies the
/// gateway's own leaf against it, and peer identity (`node_identity.rs`)
/// reads it. A gateway that could not verify anything is not a gateway
/// that should be answering.
///
/// Every failure is named at once — all three, when all three are wrong —
/// so one restart shows the whole gap rather than one line per restart.
pub fn require_server_material() -> Result<()> {
    check_server_material(|var| std::env::var(var).ok())
}

/// [`require_server_material`] over an explicit lookup, so the test can
/// hand it a fake environment instead of mutating the process's.
pub fn check_server_material(lookup: impl Fn(&str) -> Option<String>) -> Result<()> {
    let mut faults: Vec<String> = Vec::new();
    for var in SERVER_MATERIAL_ENV {
        let value = lookup(var).unwrap_or_default();
        let value = value.trim();
        if value.is_empty() {
            faults.push(format!("{var} is unset"));
            continue;
        }
        match std::fs::metadata(value) {
            Ok(m) if m.is_file() => {
                if let Err(e) = std::fs::File::open(value) {
                    faults.push(format!("{var}={value} is not readable ({e})"));
                }
            }
            Ok(_) => faults.push(format!("{var}={value} is not a file")),
            Err(e) => faults.push(format!("{var}={value} is missing ({e})")),
        }
    }
    if faults.is_empty() {
        return Ok(());
    }
    anyhow::bail!("{}", plaintext_refusal(&faults))
}

/// The exact text of the refusal. Kept as a function so the test that
/// proves the refusal and the operator who reads it see the same words.
pub fn plaintext_refusal(faults: &[String]) -> String {
    format!(
        "refusing to start: the gateway serves HTTPS only and has no plaintext listener, \
         but its TLS material is not usable — {}. \
         Mint the cluster PKI and write the NOO_TLS_* keys with \
         `noo onboard --only enrollment` (a fresh box) or `noo upgrade --stack` \
         (an enrolled controller), then restart the gateway.",
        faults.join("; ")
    )
}

/// What `NOO_MTLS_GATEWAY` and the cluster CA add up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtlsMode {
    /// Enforcing: a usable CA and the flag unset, empty, or explicitly on.
    On,
    /// Explicitly on, but `NOO_TLS_CA` is unset or missing. `mtls_enabled()`
    /// stays true so `load_rustls_config` refuses to start, as it always did.
    OnButCaMissing,
    /// Unset or empty and no usable CA: nothing to verify against.
    OffNoCa,
    /// Explicitly switched off (`false/0/no/off`): the operator's choice.
    OffExplicit,
}

/// The pure decision behind [`mtls_enabled`]: the raw env value (`None` =
/// unset) and whether `NOO_TLS_CA` names an existing file.
///
/// * unset or empty → `On` with a usable CA, else `OffNoCa`;
/// * `true/1/yes/on` → `On` (`OnButCaMissing` without a CA: refuse to start);
/// * `false/0/no/off` → `OffExplicit`;
/// * anything else is a typo, not a decision, and fails SECURE: it is read as
///   unset (the caller logs the value).
pub fn mtls_mode_of(raw: Option<&str>, ca_usable: bool) -> MtlsMode {
    match raw.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" if ca_usable => MtlsMode::On,
        "1" | "true" | "yes" | "on" => MtlsMode::OnButCaMissing,
        "0" | "false" | "no" | "off" => MtlsMode::OffExplicit,
        _ if ca_usable => MtlsMode::On,
        _ => MtlsMode::OffNoCa,
    }
}

fn ca_file_usable() -> bool {
    ca_path().is_some_and(|ca| ca.is_file())
}

/// The mode the environment says right now.
pub fn mtls_mode() -> MtlsMode {
    let raw = std::env::var("NOO_MTLS_GATEWAY").ok();
    mtls_mode_of(raw.as_deref(), ca_file_usable())
}

/// Is client-certificate identity ENFORCED? ON BY DEFAULT: with
/// `NOO_MTLS_GATEWAY` unset or empty it is on whenever `NOO_TLS_CA` names an
/// existing file (see [`mtls_mode_of`]). Enforcement means a presented
/// certificate that disagrees with a token's claimed actor is a 403, and a
/// fleet token that arrives with NO node certificate (other than from this
/// host's loopback) is a 403 too (`controller_hmac_refusal`).
///
/// Why default-on: the fleet secret is on every node, so a token's actor is
/// only a claim; without enforcement a node on the tailnet could omit its
/// certificate and name another node. Live, every node presents its leaf
/// (`node_token_no_cert` read 0 for seven days), so enforcing locks nobody
/// out. `NOO_MTLS_GATEWAY=false` is the explicit, loudly-logged opt-out.
pub fn mtls_enabled() -> bool {
    matches!(mtls_mode(), MtlsMode::On | MtlsMode::OnButCaMissing)
}

/// The boot line that says what the mode leaves open. Warn-level for the
/// two OFF modes; the text names the exposure and the way back.
pub fn log_mtls_mode(mode: MtlsMode) {
    match mode {
        MtlsMode::On | MtlsMode::OnButCaMissing => {}
        MtlsMode::OffExplicit => tracing::warn!(
            "mTLS enforcement is OFF (NOO_MTLS_GATEWAY is explicitly false): a node can present \
             a fleet token naming another node, and a forged apply claim is only stopped by the \
             birth-key proof. Remove NOO_MTLS_GATEWAY=false from .env and recreate the gateway"
        ),
        MtlsMode::OffNoCa => tracing::warn!(
            "mTLS enforcement is OFF because NOO_TLS_CA is unset or missing: a node can present \
             a fleet token naming another node. Point NOO_TLS_CA at the cluster CA and recreate \
             the gateway"
        ),
    }
}

/// Load axum-server RustlsConfig from NOO_TLS_CERT + NOO_TLS_KEY.
pub async fn load_rustls_config() -> Result<axum_server::tls_rustls::RustlsConfig> {
    let cert_path = std::env::var("NOO_TLS_CERT")
        .map_err(|_| anyhow::anyhow!("NOO_TLS_CERT not set"))?;
    let key_path = std::env::var("NOO_TLS_KEY")
        .map_err(|_| anyhow::anyhow!("NOO_TLS_KEY not set"))?;

    let mode = mtls_mode();
    if let Ok(raw) = std::env::var("NOO_MTLS_GATEWAY") {
        let r = raw.trim().to_ascii_lowercase();
        if !matches!(r.as_str(), "" | "1" | "true" | "yes" | "on" | "0" | "false" | "no" | "off") {
            tracing::warn!(value = %raw, "NOO_MTLS_GATEWAY is not a boolean; read as UNSET (enforcing when a CA exists)");
        }
    }
    log_mtls_mode(mode);
    if !mtls_enabled() {
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &cert_path, &key_path,
        ).await?;
        tracing::info!(cert = %cert_path, "TLS: server certificate loaded");
        return Ok(config);
    }

    // ── mTLS ─────────────────────────────────────────────────────────────
    //
    // This branch used to load nothing and install nothing: it logged
    // "mTLS requested (client cert verification)" and returned the plain
    // server config. An operator could turn client-certificate enforcement
    // on, watch the boot log acknowledge it, and have no enforcement at
    // all — the worst shape a security signal can take, because it is
    // indistinguishable from working.
    //
    // Verification is OPTIONAL, not required: the same listener serves the
    // dashboard, the CLI and the MCP doors, and requiring a certificate
    // would lock every one of them out. So a client that presents NO
    // certificate connects as before, and a client that presents one must
    // present a valid one signed by the cluster CA — which is what makes
    // a verified certificate usable as an identity.
    let ca_path = ca_path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    if ca_path.is_empty() || !Path::new(&ca_path).exists() {
        anyhow::bail!(
            "NOO_MTLS_GATEWAY is explicitly on but NOO_TLS_CA is unset or missing ({ca_path:?}) — \
             refusing to start, because serving without client verification while the \
             flag says otherwise is worse than not starting"
        );
    }

    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(&cert_path)?))
        .collect::<std::result::Result<_, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(&key_path)?))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {key_path}"))?;

    let mut roots = rustls::RootCertStore::empty();
    for ca in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(&ca_path)?)) {
        roots.add(ca?)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
        // Deliberate: browsers, the CLI and the MCP doors present no leaf and
        // are authenticated per route (JWT / service key / operator key);
        // `NOO_MTLS_GATEWAY` is what gates the NODE routes on the identity a
        // presented certificate carries (node_identity.rs). This is the
        // listener's only concession, and it is not a plaintext one.
        .allow_unauthenticated()
        .build()
        .map_err(|e| anyhow::anyhow!("client verifier: {e}"))?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    // from_pem_file sets these; keep HTTP/2 working on the manual path.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    tracing::info!(
        cert = %cert_path, ca = %ca_path,
        "TLS: server certificate loaded; client certificates are VERIFIED against the cluster CA when presented (optional mTLS)"
    );
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(cfg)))
}

#[cfg(test)]
mod loopback_verification_tests {
    //! the gateway's own self-calls must VERIFY.
    //!
    //! These stand up a real TLS listener with a real certificate and make a
    //! real request through the real client, because the bug being closed
    //! was behavioural: `danger_accept_invalid_certs(true)` disables
    //! validation for every request the client makes, and the only thing
    //! scoping it to loopback was a doc comment.
    //!
    //! `loopback_client()` is a process-wide `OnceLock` built from
    //! `NOO_TLS_CA`, so the anchor has to be in place before the first call.
    //! One `#[test]` drives both directions rather than fighting that.

    use std::sync::Arc;

    /// `NOO_TLS_CA` is process-global; `cargo test` runs these on threads.
    pub(super) static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn issue(ca_cn: &str, san: &str) -> (rcgen::CertifiedKey<rcgen::KeyPair>, rcgen::CertifiedKey<rcgen::KeyPair>) {
        let mut ca_params = rcgen::CertificateParams::new(vec![ca_cn.to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // DISTINCT subject DNs. rcgen defaults every DN to "rcgen self signed
        // cert", and with issuer DN == subject DN openssl reports the leaf as
        // depth-0 self-signed (verify code 18) no matter who actually signed
        // it — which would make the "good" half of the test fail for a reason
        // that has nothing to do with the client being tested.
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, ca_cn);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut leaf_params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        leaf_params.distinguished_name = rcgen::DistinguishedName::new();
        leaf_params.distinguished_name.push(rcgen::DnType::CommonName, san);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        (
            rcgen::CertifiedKey { cert: ca_cert, signing_key: ca_key },
            rcgen::CertifiedKey { cert: leaf_cert, signing_key: leaf_key },
        )
    }

    /// A one-shot HTTPS listener presenting `leaf`. Returns its port.
    async fn serve(leaf: &rcgen::CertifiedKey<rcgen::KeyPair>) -> u16 {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let cert = CertificateDer::from(leaf.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(leaf.signing_key.serialize_der()).unwrap();
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Two accepts: the rejected handshake and the accepted one.
            for _ in 0..2 {
                let Ok((sock, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    if let Ok(mut s) = acceptor.accept(sock).await {
                        // Drain the request line + headers first. Writing a
                        // response before reading makes hyper report
                        // `UnexpectedMessage`, which reads like a TLS
                        // failure and is not one.
                        let mut buf = [0u8; 2048];
                        let _ = s.read(&mut buf).await;
                        let _ = s
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                            .await;
                        let _ = s.flush().await;
                        let _ = s.shutdown().await;
                    }
                });
            }
        });
        port
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_loopback_client_verifies_against_the_cluster_ca() {
        // The guard is dropped before the first `.await`: clippy rightly
        // refuses a MutexGuard held across one, and nothing after this point
        // reads NOO_TLS_CA again — `loopback_client()` is a OnceLock built
        // right here, and the two sibling tests take the same lock, so the
        // env var cannot change under them either.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir = std::env::temp_dir().join(format!("noo-97a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // The cluster CA, and a leaf it signed for localhost — the shape the
        // gateway actually runs with (`noo-cli::pki::issue_gateway_cert`
        // puts `localhost` and `127.0.0.1` in the SANs).
        let (ca, leaf) = issue("test cluster CA", "localhost");
        let ca_pem = dir.join("ca.crt");
        std::fs::write(&ca_pem, ca.cert.pem()).unwrap();

        // A leaf from a CA the gateway has never heard of.
        let (_other_ca, impostor) = issue("somebody else", "localhost");

        let client = {
            let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var("NOO_TLS_CA", &ca_pem);
            super::loopback_client()
        };

        // 1. THE BUG. An impostor on loopback used to be accepted, because
        //    verification was off for every request this client made.
        let bad_port = serve(&impostor).await;
        let bad = client
            .get(format!("https://localhost:{bad_port}/health"))
            .send()
            .await;
        assert!(
            bad.is_err(),
            "loopback_client accepted a certificate the cluster CA did not sign"
        );

        // 2. …and it must still WORK, or the fix is just an outage. Same
        //    client, same anchor, a leaf the CA really signed.
        let good_port = serve(&leaf).await;
        let good = client
            .get(format!("https://localhost:{good_port}/health"))
            .send()
            .await;
        assert!(
            good.is_ok(),
            "loopback_client rejected the cluster CA's own leaf: {:?}",
            good.err()
        );

        std::env::remove_var("NOO_TLS_CA");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unset_anchor_means_system_roots_not_a_bypass() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("NOO_TLS_CA");
        assert!(matches!(super::cluster_ca_certificate(), Ok(None)));
    }

    #[test]
    fn a_configured_but_unusable_anchor_is_an_error_named_by_path() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // Silently falling back would be the worst of both: the operator
        // believes the self-call is anchored, and it is not.
        let missing = std::env::temp_dir().join("noo-97a-does-not-exist.crt");
        std::env::set_var("NOO_TLS_CA", &missing);
        let e = super::cluster_ca_certificate().unwrap_err().to_string();
        std::env::remove_var("NOO_TLS_CA");
        assert!(e.contains("cannot read NOO_TLS_CA"), "{e}");
        assert!(e.contains("noo-97a-does-not-exist.crt"), "the error does not name the file: {e}");

        let junk = std::env::temp_dir().join(format!("noo-97a-junk-{}.crt", std::process::id()));
        std::fs::write(&junk, b"not a certificate").unwrap();
        std::env::set_var("NOO_TLS_CA", &junk);
        let e = super::cluster_ca_certificate().unwrap_err().to_string();
        std::env::remove_var("NOO_TLS_CA");
        let _ = std::fs::remove_file(&junk);
        assert!(e.contains("not valid PEM"), "{e}");
    }

    #[test]
    fn no_client_in_this_module_disables_certificate_validation() {
        // The property the followup is about, pinned at the source: a future
        // "just for loopback" bypass is scoped to nothing.
        let src = include_str!("tls.rs");
        let live: Vec<&str> = src
            .lines()
            .filter(|l| l.contains(".danger_accept_invalid_certs("))
            .filter(|l| !l.trim_start().starts_with("//"))
            // This test's own predicate names the method; skip the scanner.
            .filter(|l| !l.contains(".filter("))
            .collect();
        assert!(live.is_empty(), "certificate validation is disabled at: {live:?}");
    }
}

/// Which client an https door is dialled with (mTLS doors phase 2, i77).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoorTrust {
    /// One of the cluster's own hostnames: [`cluster_client`] — the cluster
    /// CA and this gateway's leaf, which the door's listener requires.
    Cluster,
    /// Any other host (a cloud provider): [`external_client`] — public
    /// roots, NO client certificate. The cluster client could not verify a
    /// public CA, and the gateway's leaf has no business leaving the cluster.
    Public,
}

/// A configurable door the gateway dials whose default is a cluster
/// service but whose URL an operator may point at a public provider — the
/// voice doors (`NOO_STT_URL` → noo-whisper, `NOO_TTS_URL` → noo-piper).
pub struct HttpsDoor {
    /// What the operator sets, named in the refusal.
    pub setting: &'static str,
    /// The cluster default, named in the refusal as the fix.
    pub default_url: &'static str,
    /// Hostnames that are this cluster's: exact matches only, so a
    /// look-alike (`noo-whisper.evil.com`) is a public host.
    pub cluster_hosts: &'static [&'static str],
}

/// The cluster's own voice hostnames (the two leaves' SANs): an https
/// `NOO_STT_URL` / `NOO_TTS_URL` on any of these dials with the cluster
/// client; every other https host is a provider, dialled publicly.
pub const VOICE_CLUSTER_HOSTS: &[&str] = &["noo-whisper", "whisper", "noo-piper", "piper", "localhost"];

impl HttpsDoor {
    /// `http://` is refused everywhere (the cluster door serves mTLS only,
    /// and a cloud provider's key must not cross the wire in the clear); an
    /// https URL on a cluster hostname is [`DoorTrust::Cluster`], any other
    /// https host is [`DoorTrust::Public`].
    pub fn classify(&self, url: &str) -> std::result::Result<DoorTrust, String> {
        let url = url.trim();
        let refuse = || {
            format!(
                "{}={url} is not https — the cluster's voice doors serve mTLS only and a provider \
                 is dialled over TLS only; set {}={} (or an https provider URL), or unset it",
                self.setting, self.setting, self.default_url
            )
        };
        if !url.to_ascii_lowercase().starts_with("https://") {
            return Err(refuse());
        }
        let parsed = reqwest::Url::parse(url).map_err(|e| format!("{}={url} is not a URL: {e}", self.setting))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("{}={url} names no host", self.setting))?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if self.cluster_hosts.iter().any(|h| *h == host) {
            Ok(DoorTrust::Cluster)
        } else {
            Ok(DoorTrust::Public)
        }
    }

    /// The client to dial `url` with, or the refusal (never dialled).
    pub fn client(&self, url: &str) -> std::result::Result<reqwest::Client, String> {
        Ok(match self.classify(url)? {
            DoorTrust::Cluster => cluster_client(),
            DoorTrust::Public => external_client(),
        })
    }
}

#[cfg(test)]
mod door_tests {
    use super::{DoorTrust, HttpsDoor, VOICE_CLUSTER_HOSTS};

    const D: HttpsDoor = HttpsDoor {
        setting: "NOO_STT_URL",
        default_url: "https://noo-whisper:8000",
        cluster_hosts: VOICE_CLUSTER_HOSTS,
    };

    /// The URL classifier: http refused with the fix named; the cluster's
    /// own names get the cluster client; every other https host the public one.
    #[test]
    fn the_door_classifier_picks_cluster_or_public_and_refuses_plaintext() {
        assert_eq!(D.classify("https://noo-whisper:8000"), Ok(DoorTrust::Cluster));
        assert_eq!(D.classify("HTTPS://Whisper:8000/"), Ok(DoorTrust::Cluster));
        for host in ["noo-piper", "piper", "localhost", "LOCALHOST."] {
            assert_eq!(D.classify(&format!("https://{host}:8000")), Ok(DoorTrust::Cluster), "{host}");
        }
        assert_eq!(D.classify("https://api.openai.com"), Ok(DoorTrust::Public));
        assert_eq!(D.classify("https://speaches.example.net:8443/v1"), Ok(DoorTrust::Public));
        // A look-alike is not a cluster name.
        assert_eq!(D.classify("https://noo-whisper.evil.com"), Ok(DoorTrust::Public));
        assert_eq!(D.classify("https://localhost.evil.com"), Ok(DoorTrust::Public));
        assert_eq!(D.classify("https://whisper.noo-cluster"), Ok(DoorTrust::Public));
        for plain in [format!("{}://noo-whisper:8000", "http"), format!("{}://api.openai.com", "http"), "noo-whisper:8000".into()] {
            let e = D.classify(&plain).unwrap_err();
            assert!(e.contains("not https") && e.contains("NOO_STT_URL=https://noo-whisper:8000"), "{e}");
            assert!(D.client(&plain).is_err(), "{plain} must not get a client");
        }
        assert!(D.classify("https://").is_err());
    }
}

#[cfg(test)]
mod stream_idle_override_tests {
    use super::{set_stream_idle_override, stream_idle, DEFAULT_STREAM_IDLE_SECS};
    use std::time::Duration;

    /// The harness fixes the bound once; nothing changes it after, and zero
    /// is never a bound. Process-wide, so this sets only the default value:
    /// another test in this binary may have read it first.
    #[test]
    fn the_stream_idle_override_is_set_once_and_never_zero() {
        assert!(!set_stream_idle_override(Duration::ZERO), "zero would disable the bound");
        let _ = set_stream_idle_override(Duration::from_secs(DEFAULT_STREAM_IDLE_SECS));
        let fixed = stream_idle();
        assert!(fixed > Duration::ZERO);
        assert!(!set_stream_idle_override(Duration::from_secs(1)), "already fixed: refused");
        assert_eq!(stream_idle(), fixed, "never changed once fixed");
    }
}

#[cfg(test)]
mod tests {
    use super::{check_server_material, resolve_backend_timeout_secs, DEFAULT_BACKEND_TIMEOUT_SECS};

    /// The refusal names EVERY missing or unreadable file, and the remedy.
    /// There is no combination of unset material that yields Ok: that is
    /// the plaintext branch, and it is gone.
    #[test]
    fn missing_material_is_a_refusal_naming_each_file() {
        let dir = std::env::temp_dir().join(format!("noo-tls-material-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("gateway.crt");
        std::fs::write(&cert, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let cert_s = cert.to_string_lossy().into_owned();
        let missing = dir.join("nope.key").to_string_lossy().into_owned();

        // Nothing set at all: three faults, one message.
        let err = check_server_material(|_| None).unwrap_err().to_string();
        for var in ["NOO_TLS_CERT is unset", "NOO_TLS_KEY is unset", "NOO_TLS_CA is unset"] {
            assert!(err.contains(var), "{err}");
        }
        assert!(err.contains("no plaintext listener"), "{err}");
        assert!(err.contains("noo onboard --only enrollment"), "{err}");

        // Cert present, key missing on disk, CA pointing at a directory.
        let dir_s = dir.to_string_lossy().into_owned();
        let env = move |var: &str| match var {
            "NOO_TLS_CERT" => Some(cert_s.clone()),
            "NOO_TLS_KEY" => Some(missing.clone()),
            "NOO_TLS_CA" => Some(dir_s.clone()),
            _ => None,
        };
        let err = check_server_material(env).unwrap_err().to_string();
        assert!(!err.contains("NOO_TLS_CERT"), "the readable leaf is not a fault: {err}");
        assert!(err.contains("NOO_TLS_KEY=") && err.contains("is missing"), "{err}");
        assert!(err.contains("NOO_TLS_CA=") && err.contains("is not a file"), "{err}");

        // All three readable: starts.
        let c2 = cert.to_string_lossy().into_owned();
        assert!(check_server_material(|_| Some(c2.clone())).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The override is an operator knob on the inference hot path, so the
    /// parse fails SAFE. `"0"` is the case that matters: reqwest reads a
    /// zero `Duration` as a timeout that fires immediately, and a
    /// permissive parse here would take the gateway from "some calls are
    /// too slow" to "every call fails instantly".
    #[test]
    fn backend_timeout_override_fails_safe() {
        assert_eq!(resolve_backend_timeout_secs(""), Ok(DEFAULT_BACKEND_TIMEOUT_SECS));
        assert_eq!(resolve_backend_timeout_secs("   "), Ok(DEFAULT_BACKEND_TIMEOUT_SECS));
        assert_eq!(resolve_backend_timeout_secs("900"), Ok(900));
        assert_eq!(resolve_backend_timeout_secs(" 900 "), Ok(900));

        assert!(resolve_backend_timeout_secs("0").is_err());
        assert!(resolve_backend_timeout_secs("-30").is_err());
        assert!(resolve_backend_timeout_secs("15m").is_err());
        assert!(resolve_backend_timeout_secs("900.5").is_err());
        assert!(resolve_backend_timeout_secs("abc").is_err());
    }
}

#[cfg(test)]
mod mtls_mode_tests {
    use super::*;

    // `NOO_MTLS_GATEWAY` / `NOO_TLS_CA` are process-global: one mutex with
    // the loopback tests, which also set `NOO_TLS_CA`.
    use super::loopback_verification_tests::ENV;

    #[test]
    fn the_mode_table() {
        use MtlsMode::*;
        for (raw, ca, want) in [
            (None, true, On),
            (Some(""), true, On),
            (Some("  "), true, On),
            (None, false, OffNoCa),
            (Some(""), false, OffNoCa),
            (Some("true"), true, On),
            (Some("1"), true, On),
            (Some("YES"), true, On),
            (Some("on"), true, On),
            (Some("true"), false, OnButCaMissing),
            (Some("on"), false, OnButCaMissing),
            (Some("false"), true, OffExplicit),
            (Some("0"), true, OffExplicit),
            (Some("No"), false, OffExplicit),
            (Some(" off "), true, OffExplicit),
            // A typo is not a decision: fail secure.
            (Some("disabled"), true, On),
            (Some("disabled"), false, OffNoCa),
        ] {
            assert_eq!(mtls_mode_of(raw, ca), want, "raw={raw:?} ca={ca}");
        }
    }

    #[test]
    fn mtls_enabled_reads_the_env_and_the_ca_file() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("noo-mtls-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, "x").unwrap();
        let missing = dir.join("absent.pem");
        let check = |flag: Option<&str>, ca_path: &std::path::Path, want: bool| {
            match flag {
                Some(v) => std::env::set_var("NOO_MTLS_GATEWAY", v),
                None => std::env::remove_var("NOO_MTLS_GATEWAY"),
            }
            std::env::set_var("NOO_TLS_CA", ca_path);
            assert_eq!(mtls_enabled(), want, "flag={flag:?} ca={}", ca_path.display());
        };
        check(None, &ca, true);
        check(Some(""), &ca, true);
        check(None, &missing, false);
        check(Some("true"), &missing, true); // refuses to start in load_rustls_config
        check(Some("false"), &ca, false);
        check(Some("off"), &ca, false);
        std::env::remove_var("NOO_MTLS_GATEWAY");
        std::env::remove_var("NOO_TLS_CA");
        assert!(!mtls_enabled(), "no CA at all: nothing to enforce against");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod one_ca_reader {
    //! Ratchet to zero: `NOO_TLS_CA` is READ in exactly one place, `ca_path()`
    //! above. Every other file asks tls.rs and decides what `None` means. Writers
    //! (`set_var` when staging PKI) and injected env lookups are not reads.

    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).expect("read src dir") {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    #[test]
    fn no_file_outside_tls_rs_reads_noo_tls_ca() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rs_files(&src, &mut files);
        assert!(files.len() > 50, "the scan found {} files; the walk is broken", files.len());
        let reader = concat!("var(\"NOO_TLS", "_CA\")");
        let mut offenders = Vec::new();
        for f in files {
            if f.file_name().is_some_and(|n| n == "tls.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&f).expect("read source");
            for (i, line) in text.lines().enumerate() {
                if line.contains(reader) {
                    offenders.push(format!("{}:{}", f.display(), i + 1));
                }
            }
        }
        assert!(offenders.is_empty(), "NOO_TLS_CA must be read through tls::ca_path(): {offenders:?}");
    }

    #[test]
    fn ca_path_unset_blank_and_set() {
        let _g = super::loopback_verification_tests::ENV.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("NOO_TLS_CA").ok();
        std::env::remove_var("NOO_TLS_CA");
        assert_eq!(super::ca_path(), None);
        std::env::set_var("NOO_TLS_CA", "   ");
        assert_eq!(super::ca_path(), None);
        std::env::set_var("NOO_TLS_CA", " /x/ca.crt ");
        assert_eq!(super::ca_path(), Some(std::path::PathBuf::from("/x/ca.crt")));
        match prev {
            Some(v) => std::env::set_var("NOO_TLS_CA", v),
            None => std::env::remove_var("NOO_TLS_CA"),
        }
    }
}
