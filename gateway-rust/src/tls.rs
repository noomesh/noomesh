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
use std::path::Path;
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
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(DEFAULT_BACKEND_TIMEOUT_SECS);
    }
    match raw.parse::<u64>() {
        Ok(0) => Err("zero would disable the timeout"),
        Ok(secs) => Ok(secs),
        Err(_) => Err("not a whole number of seconds"),
    }
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
                reqwest::Client::builder()
                    .timeout(backend_timeout())
                    .connect_timeout(std::time::Duration::from_secs(10))
                    .build()
                    .unwrap_or_default()
            })
        })
        .clone()
}

/// Shared client for public-internet APIs (Google, Telegram, WhatsApp, …)
/// using system/webpki trust roots. Never presents the cluster mTLS
/// identity to external hosts.
pub fn external_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default()
        })
        .clone()
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
            let mut b = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(5));
            match cluster_ca_certificate() {
                Ok(Some(cert)) => b = b.add_root_certificate(cert),
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

/// The cluster CA as a reqwest root, if `NOO_TLS_CA` names a readable PEM.
///
/// `Ok(None)` means no anchor was configured — a public cert (tailscale
/// serve) or plain dev, where the system roots are the right answer.
/// `Err` means one WAS configured and could not be used, which is a
/// misconfiguration the caller should say out loud rather than paper over.
pub fn cluster_ca_certificate() -> Result<Option<reqwest::Certificate>> {
    let Some(path) = std::env::var("NOO_TLS_CA").ok().filter(|s| !s.trim().is_empty()) else {
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
    build_https_client_with(std::time::Duration::from_secs(10))
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
            build_https_client_with(std::time::Duration::from_secs(FAILOVER_CONNECT_SECS)).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "failover TLS client build failed; falling back to default client");
                reqwest::Client::builder()
                    .timeout(backend_timeout())
                    .connect_timeout(std::time::Duration::from_secs(FAILOVER_CONNECT_SECS))
                    .build()
                    .unwrap_or_default()
            })
        })
        .clone()
}

/// Per-attempt connect budget on the failover lane.
pub const FAILOVER_CONNECT_SECS: u64 = 5;

fn build_https_client_with(connect_timeout: std::time::Duration) -> Result<reqwest::Client> {
    let ca_path = std::env::var("NOO_TLS_CA").unwrap_or_default();
    let cert_path = std::env::var("NOO_TLS_CERT").unwrap_or_default();
    let key_path = std::env::var("NOO_TLS_KEY").unwrap_or_default();

    // Build a custom rustls ClientConfig for full control over mTLS
    let has_ca = !ca_path.is_empty() && Path::new(&ca_path).exists();
    let has_identity = !cert_path.is_empty() && !key_path.is_empty()
        && Path::new(&cert_path).exists() && Path::new(&key_path).exists();

    if has_ca || has_identity {
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

        let builder = reqwest::Client::builder()
            .timeout(backend_timeout())
            .connect_timeout(connect_timeout)
            .use_preconfigured_tls(tls_config);

        Ok(builder.build()?)
    } else {
        // No custom TLS — use defaults
        tracing::info!("TLS: using system trust store (no cluster CA)");
        Ok(reqwest::Client::builder()
            .timeout(backend_timeout())
            .connect_timeout(connect_timeout)
            .build()?)
    }
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

/// Is client-certificate identity ENFORCED (`NOO_MTLS_GATEWAY`)? A
/// mismatch between the presented certificate and a token's claimed actor
/// is a 403 only when this is on.
///
/// Kept as a flag because enforcement can lock out a node whose existing
/// certificate does not name its registered id — drift that
/// `provision` now repairs going forward, but that already-issued certs
/// still carry. A fresh install has no such history, so `noo onboard`
/// turns it on; an upgrade opts in after reading its logs.
pub fn mtls_enabled() -> bool {
    matches!(
        std::env::var("NOO_MTLS_GATEWAY").unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Load axum-server RustlsConfig from NOO_TLS_CERT + NOO_TLS_KEY.
pub async fn load_rustls_config() -> Result<axum_server::tls_rustls::RustlsConfig> {
    let cert_path = std::env::var("NOO_TLS_CERT")
        .map_err(|_| anyhow::anyhow!("NOO_TLS_CERT not set"))?;
    let key_path = std::env::var("NOO_TLS_KEY")
        .map_err(|_| anyhow::anyhow!("NOO_TLS_KEY not set"))?;

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
    let ca_path = std::env::var("NOO_TLS_CA").unwrap_or_default();
    if ca_path.is_empty() || !Path::new(&ca_path).exists() {
        anyhow::bail!(
            "NOO_MTLS_GATEWAY is on but NOO_TLS_CA is unset or missing ({ca_path:?}) — \
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
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn issue(ca_cn: &str, san: &str) -> (rcgen::CertifiedKey, rcgen::CertifiedKey) {
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
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap();
        (
            rcgen::CertifiedKey { cert: ca_cert, key_pair: ca_key },
            rcgen::CertifiedKey { cert: leaf_cert, key_pair: leaf_key },
        )
    }

    /// A one-shot HTTPS listener presenting `leaf`. Returns its port.
    async fn serve(leaf: &rcgen::CertifiedKey) -> u16 {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let cert = CertificateDer::from(leaf.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(leaf.key_pair.serialize_der()).unwrap();
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
