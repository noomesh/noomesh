// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! One way onto the bus.
//!
//! The gateway has always connected to NATS with the cluster CA and, when
//! present, its client certificate; the node-hosted harness needs exactly
//! the same connection under the node's principal. So the block moved
//! here from `state.rs` unchanged, and both callers pass what differs:
//! the credential, the inbox prefix their principal may subscribe to, and
//! the request timeout.

use std::time::Duration;

use anyhow::Result;

use crate::nats_credentials::NatsCredential;

/// Connect to `url`. With `NOO_TLS_CA` set and present, TLS is pinned to
/// the cluster CA and `NOO_TLS_CERT`/`NOO_TLS_KEY` add mTLS when both
/// exist; without a CA, TLS is still required against the system store.
pub async fn connect(
    url: &str,
    cred: Option<NatsCredential>,
    inbox_prefix: &str,
    request_timeout: Duration,
) -> Result<async_nats::Client> {
    let ca_path = std::env::var("NOO_TLS_CA").unwrap_or_default();
    let cert_path = std::env::var("NOO_TLS_CERT").unwrap_or_default();
    let key_path = std::env::var("NOO_TLS_KEY").unwrap_or_default();

    // Hand async-nats the PATHS and let it build the TLS config, rather
    // than building a rustls ClientConfig ourselves.
    //
    // Not a simplification for its own sake. async-nats 0.49.1 loads the
    // platform trust store whenever `tls_client_config` is set —
    //
    //     // load native system certs only if user did not specify them.
    //     if options.tls_client_config.is_some() || options.certificates.is_empty() {
    //         ... if !certs_result.errors.is_empty() { return Err(...) }
    //
    // — which is the opposite of what its own comment says, and it then
    // throws the result away, because a supplied config wins further down.
    // Worse, ANY unreadable file in /etc/ssl/certs is fatal there, though
    // `load_native_certs` returns partial results by design.
    //
    // That bit host3 on 2026-09-20: a stale `noomesh-cluster-ca.crt` left
    // 0640 root:root by an earlier era made the whole store unreadable to
    // an unprivileged process, and the harness — the first component to
    // run as a non-root user — could not reach the bus at all. The
    // gateway never saw it: the file is not in its container.
    //
    // Taking the `certificates` path instead means `tls_client_config` is
    // None and `certificates` is non-empty, so the platform store is never
    // touched. It is also the right posture: this connection trusts the
    // CLUSTER CA and nothing else, so the system store has no business
    // being consulted, readable or not.
    let mut opts = if !ca_path.is_empty() && std::path::Path::new(&ca_path).exists() {
        tracing::info!(url = %crate::redact::scrub_url_userinfo(url), ca = %ca_path, "NATS connecting with TLS (cluster CA only)");
        let mut o = async_nats::ConnectOptions::new()
            .require_tls(true)
            .add_root_certificates(std::path::PathBuf::from(&ca_path));
        if !cert_path.is_empty()
            && !key_path.is_empty()
            && std::path::Path::new(&cert_path).exists()
            && std::path::Path::new(&key_path).exists()
        {
            o = o.add_client_certificate(
                std::path::PathBuf::from(&cert_path),
                std::path::PathBuf::from(&key_path),
            );
        }
        o
    } else {
        tracing::warn!("NATS connecting WITHOUT cluster CA — set NOO_TLS_CA for full TLS");
        async_nats::ConnectOptions::new().require_tls(true)
    };
    opts = opts
        .request_timeout(Some(request_timeout))
        .custom_inbox_prefix(inbox_prefix)
        .event_callback(crate::state::nats_event_logger);
    if let Some(c) = cred {
        opts = opts.user_and_password(c.user, c.password);
    }
    Ok(opts.connect(url).await?)
}
