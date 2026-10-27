// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Gateway HTTP client: TLS trust resolution, HMAC bearer, and uniform
//! error → exit-code mapping.
//!
//! **There is no unverified TLS lane here, and there must never be one.**
//! Until 2026-09-11 this file answered "no CA file / an unparseable one" with
//! `disable_verification(true)` — a silent downgrade, justified in a comment
//! as "parity with the Python CLI". It applied to every `https://` base URL
//! that was not the enrolled controller, and the CLI attached the stored
//! bearer JWT to the request anyway: anyone who could steer the CLI's
//! gateway URL (see `envfile::ensure_repo_env`, which used to read `.env`
//! out of whatever checkout the cwd was inside) collected a live operator
//! credential and got a green exit code. Encryption without verification is
//! not encryption against anybody who matters.

use crate::output::{fail, ExitCode};
use crate::Globals;
use std::path::PathBuf;
use std::time::Duration;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;

/// Which anchor verified this request's TLS — resolved per base URL by
/// [`resolve_trust`], reported by `noo auth status` and `noo security scan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// `http://` to a loopback host. The ONE unencrypted lane, and it never
    /// leaves the machine, and only for a URL passed EXPLICITLY (the CLI's
    /// own default is `https://localhost:<port>` — the gateway has no
    /// plaintext listener): every `--gateway http://127.0.0.1:<port>` in
    /// `noo-cli/tests/gateway_integration.rs`, which drives a mock gateway
    /// on a loopback port. A non-loopback `http://` is refused instead.
    LoopbackPlaintext,
    /// The base URL IS the enrolled controller (`/etc/noo/controller-url`)
    /// and this box holds the anchor enrollment wrote — verify against THAT
    /// FILE. See [`Trust::Enrolled`] for why the file and not the machine.
    EnrolledCa(PathBuf),
    /// The base URL IS the enrolled controller, and the anchor enrollment
    /// wrote cannot be read from here — fall back to the platform verifier,
    /// which works because prep-host also installs the mesh CA into the
    /// system store.
    ///
    /// This is the FALLBACK now, not the rule. Reaching for the machine-wide
    /// store meant every process on the box trusted anything the cluster CA
    /// signed, to solve a problem that only the CLI had; and it made the CLI
    /// depend on a file it does not own, which is how one stale copy at 0640
    /// root:root took the platform store away from every non-root process on
    /// host3 and crash-looped the harness ~1900 times.
    /// Enrollment writes its own anchor at a path it controls. That file is
    /// the declaration; the system store is a copy of it.
    Enrolled,
    /// `$NOO_TLS_CA`, read and parsed.
    EnvCa(PathBuf),
    /// The cluster CA this box already holds — `$NOO_PKI_DIR/ca.crt` (default
    /// `~/.config/mesh/pki/ca.crt`, the same path `noo security pki` uses,
    /// see [`crate::pki::pki_dir`]) or `/etc/noo/pki/ca.crt` on a node.
    ClusterCa(PathBuf),
    /// WebPKI — a gateway behind a public cert (tailscale serve, a real CA).
    Platform,
}

impl Trust {
    /// A phrase completing "TLS verified against …", for display.
    pub fn describe(&self) -> String {
        match self {
            Self::LoopbackPlaintext => "no TLS — plain http:// to a loopback address".into(),
            Self::EnrolledCa(p) => format!(
                "the enrolled cluster CA at {} (named by {})",
                p.display(),
                crate::envfile::ENROLLED_CONTROLLER_URL
            ),
            Self::Enrolled => format!(
                "the system trust store (this box is enrolled through {}, and its own copy of the \
                 cluster CA could not be read from here)",
                crate::envfile::ENROLLED_CONTROLLER_URL
            ),
            Self::EnvCa(p) => format!("$NOO_TLS_CA ({})", p.display()),
            Self::ClusterCa(p) => format!("the cluster CA at {}", p.display()),
            Self::Platform => "the platform verifier (WebPKI)".into(),
        }
    }
    /// Machine-readable tag for `--json`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::LoopbackPlaintext => "loopback_plaintext",
            Self::EnrolledCa(_) => "enrolled_ca",
            Self::Enrolled => "enrolled",
            Self::EnvCa(_) => "env_ca",
            Self::ClusterCa(_) => "cluster_ca",
            Self::Platform => "platform",
        }
    }
}

/// The host part of an `http(s)://host[:port]/…` URL, IPv6 brackets kept.
fn url_host(url: &str) -> &str {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let rest = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip userinfo, then the port — but a bare `[::1]:8080` must keep its
    // brackets' contents, so split the port off AFTER the closing bracket.
    let rest = rest.rsplit('@').next().unwrap_or(rest);
    if let Some(end) = rest.find(']') {
        return &rest[..=end];
    }
    rest.split(':').next().unwrap_or(rest)
}

/// Is this host the machine itself? Only these get the plaintext carve-out.
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h == "::1" || h == "0:0:0:0:0:0:0:1" {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// Is the gateway at `url` this machine? `auth::credential_usable_for`
/// asks the same question about a stored credential's issuer: the
/// controller answers to `localhost` on its own box and to its tailnet
/// name from everywhere else, and that is the same gateway.
pub(crate) fn is_loopback(url: &str) -> bool {
    is_loopback_host(url_host(url))
}

/// Candidate cluster-CA locations, most specific first. `$NOO_PKI_DIR` (or
/// `~/.config/mesh/pki`) is where `noo security pki` keeps `ca.crt` on a
/// controller; `/etc/noo/pki/ca.crt` is where prep-host lands it on a node.
fn cluster_ca_candidates() -> Vec<PathBuf> {
    let mut v = vec![crate::pki::pki_dir().join("ca.crt")];
    let node = PathBuf::from("/etc/noo/pki/ca.crt");
    if !v.contains(&node) {
        v.push(node);
    }
    v
}

/// The anchor for the enrolled controller: the first candidate this process
/// can READ, or the platform verifier when it can read none.
///
/// Pure over `candidates` so it can be tested without depending on whether
/// the machine running the tests happens to be an enrolled node — it is, on
/// host3, and a test that asserted the fallback would have passed in CI and
/// failed on the one box where this code matters most.
fn enrolled_anchor(
    candidates: impl IntoIterator<Item = PathBuf>,
    base: &str,
) -> Result<Trust, String> {
    for cand in candidates {
        // Unreadable is not an error: on a node `/etc/noo/pki` may be
        // tightened to root:noo-agent, and an ordinary user running `noo
        // cluster status` must still work — that is what the system-store
        // copy is for.
        let Ok(pem) = std::fs::read(&cand) else { continue };
        // Readable but not a certificate IS an error, same as rung 4. That
        // is corruption of this box's own declared anchor, and quietly
        // verifying against something else would hide it.
        Certificate::from_pem(&pem).map_err(|e| {
            format!(
                "the enrolled cluster CA at {} is not a PEM certificate: {e}. Re-run enrollment \
                 or replace the file — this CLI will not silently verify {base} against a \
                 different anchor",
                cand.display()
            )
        })?;
        return Ok(Trust::EnrolledCa(cand));
    }
    Ok(Trust::Enrolled)
}

/// The ONE reader of `$NOO_TLS_CA`: the trimmed path, `None` when unset or
/// blank. The source-scan test `config_readers_have_one_owner` in
/// `src/config_readers.rs` fails on any other file that reads it.
pub fn tls_ca_env() -> Option<PathBuf> {
    let v = std::env::var("NOO_TLS_CA").unwrap_or_default();
    let v = v.trim();
    if v.is_empty() { None } else { Some(PathBuf::from(v)) }
}

/// Resolve the trust anchor for `base_url`, or say why there is none.
///
/// Order — the first rung that answers wins:
///   1. `http://` → loopback only ([`Trust::LoopbackPlaintext`]); anything
///      else is an error, because a cleartext gateway on the wire has no
///      integrity at all and the CLI would post a bearer token into it.
///   2. the ENROLLED controller URL → the CA ENROLLMENT ITSELF WROTE, and
///      only the platform verifier when that file cannot be read. This
///      outranks `$NOO_TLS_CA` on purpose: a dev clone's `.env` on an HOST3
///      worker still named the RETIRED controller's CA (2026-09-01) and
///      every request died UnknownIssuer while the node-agent, verifying
///      against /etc/noo/pki, was perfectly happy. Enrollment is the
///      declaration — and the thing enrollment declares is that FILE, which
///      is the very file the node-agent was happy with. Taking the whole
///      machine's trust store instead was a wider answer than the question:
///      it made every process on the box trust anything the cluster CA
///      signed to fix a problem only the CLI had, and it put the CLI at the
///      mercy of a file it does not own. One stale copy of that file, at
///      0640 root:root, took the platform store away from every non-root
///      process.
///
///   3. `$NOO_TLS_CA` when set — and when it is set, it must WORK: an
///      unreadable or unparseable path is a hard error naming the file, not
///      a shrug.
///   4. the cluster CA this box already holds (see [`cluster_ca_candidates`]).
///      Unreadable candidates are skipped (on a node `/etc/noo/pki` is
///      0750 root:noo-agent and an ordinary user cannot read it); a readable
///      file that is not a certificate IS an error — that is corruption, and
///      falling through would silently verify against WebPKI instead.
///   5. the platform verifier.
pub fn resolve_trust(base_url: &str) -> Result<Trust, String> {
    let enrolled = crate::envfile::controller_url_from_file(std::path::Path::new(
        crate::envfile::ENROLLED_CONTROLLER_URL,
    ));
    resolve_trust_with(base_url, enrolled)
}

/// [`resolve_trust`] with the enrollment record passed in.
///
/// The record lives at one absolute path, `/etc/noo/controller-url`, which
/// a test cannot create — so the ladder's most important rung used to be
/// the one rung nothing exercised. Taking it as an argument makes the whole
/// precedence testable, including on a machine that IS enrolled.
fn resolve_trust_with(base_url: &str, enrolled: Option<String>) -> Result<Trust, String> {
    let base = base_url.trim_end_matches('/');

    // NOO_TLS_INSECURE existed for one afternoon (PR #99) as an explicit
    // operator opt-out, warned about on stderr. It is refused now, and the
    // refusal is deliberate rather than a silent no-op: an operator who set
    // it believes verification is off, and letting that belief stand while
    // the CLI quietly verifies is its own kind of lie. There is no escape
    // hatch here because an escape hatch is what the finding WAS — the old
    // code took one on the CLI's own initiative. Anything the variable was
    // reached for (a gateway behind a cert this box cannot chain) is a
    // missing anchor, and the fix is to give the CLI the anchor.
    if let Ok(v) = std::env::var("NOO_TLS_INSECURE") {
        if !v.trim().is_empty() && v != "0" {
            return Err(format!(
                "NOO_TLS_INSECURE is set ({v}), and this CLI has no unverified-TLS lane to \
                 switch on. Unset it. If {base} cannot be verified today, give the CLI the \
                 anchor instead: point $NOO_TLS_CA at the cluster's ca.crt, or run \
                 `noo security trust-ca` so the system store carries it"
            ));
        }
    }

    if let Some(rest) = base.strip_prefix("http://") {
        let host = url_host(base);
        if is_loopback_host(host) {
            return Ok(Trust::LoopbackPlaintext);
        }
        let _ = rest;
        return Err(format!(
            "refusing to talk to {base} over plain http:// — TLS is required for every \
             non-loopback gateway. This CLI sends a bearer credential on almost every \
             request and cleartext gives it away to anyone on the path"
        ));
    }
    if !base.starts_with("https://") {
        return Err(format!(
            "gateway URL {base} has no scheme this CLI can use — it must be https:// \
             (or http:// to a loopback address for local development)"
        ));
    }

    if enrolled.as_deref() == Some(base) {
        // The anchor enrollment wrote, when this process can read it.
        // Unreadable is NOT an error here: on a node /etc/noo/pki may be
        // tightened to root:noo-agent, and an ordinary user running `noo
        // cluster status` must still work — that is what the system-store
        // copy is for. A readable file that is not a certificate IS an
        // error, same as rung 4: that is corruption of this box's own
        // declared anchor, and quietly verifying against something else
        // would hide it.
        return enrolled_anchor(cluster_ca_candidates(), base);
    }

    if let Some(p) = tls_ca_env() {
        let pem = std::fs::read(&p).map_err(|e| {
            format!(
                "$NOO_TLS_CA points at {} but it cannot be read: {e}. Fix the path or unset \
                 NOO_TLS_CA — this CLI will not fall back to an unverified connection",
                p.display()
            )
        })?;
        Certificate::from_pem(&pem).map_err(|e| {
            format!(
                "$NOO_TLS_CA ({}) is not a PEM certificate: {e}. Point it at the cluster CA \
                 (`noo security pki status` prints where ca.crt lives) or unset it",
                p.display()
            )
        })?;
        return Ok(Trust::EnvCa(p));
    }

    for cand in cluster_ca_candidates() {
        let Ok(pem) = std::fs::read(&cand) else { continue };
        Certificate::from_pem(&pem).map_err(|e| {
            format!(
                "the cluster CA at {} is not a PEM certificate: {e}. Re-issue it \
                 (`noo security pki init`) or point $NOO_TLS_CA at a good copy",
                cand.display()
            )
        })?;
        return Ok(Trust::ClusterCa(cand));
    }

    Ok(Trust::Platform)
}

/// [`resolve_trust`] turned into a `TlsConfig`. Infallible only because the
/// caller has already handled the `Err` arm.
fn tls_for(trust: &Trust) -> ureq::tls::TlsConfig {
    tls_for_with(trust, None)
}

/// [`tls_for`] presenting a client certificate (the operator's). Same trust rules; the certificate changes who we ARE, never whom
/// we believe.
fn tls_for_with(trust: &Trust, client: Option<ureq::tls::ClientCert>) -> ureq::tls::TlsConfig {
    let b = TlsConfig::builder().client_cert(client);
    match trust {
        // No TLS is negotiated on a plain-http request, so the config is
        // irrelevant; keep the platform verifier so a redirect to https
        // is still verified rather than silently accepted.
        Trust::LoopbackPlaintext | Trust::Enrolled | Trust::Platform => {
            b.root_certs(RootCerts::PlatformVerifier).build()
        }
        Trust::EnvCa(p) | Trust::ClusterCa(p) | Trust::EnrolledCa(p) => {
            // Both paths were read AND parsed by resolve_trust; a failure
            // here means the file changed underneath us between the two
            // reads, which is not something to paper over.
            match std::fs::read(p).ok().and_then(|pem| Certificate::from_pem(&pem).ok()) {
                Some(cert) => b.root_certs(RootCerts::new_with_certs(&[cert])).build(),
                None => b.root_certs(RootCerts::PlatformVerifier).build(),
            }
        }
    }
}

/// A verifying agent for a one-off fetch outside the `Globals` world
/// (health probes, the release mirror). Same resolution as [`agent`], but it
/// returns the error instead of exiting, because these callers have their own
/// reporting. There is deliberately no "and if that fails, don't verify" arm.
pub fn agent_for(base_url: &str, timeout_secs: u64) -> Result<Agent, String> {
    let trust = resolve_trust(base_url)?;
    Ok(Agent::config_builder()
        .tls_config(tls_for(&trust))
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .http_status_as_error(false)
        .build()
        .into())
}

/// Build the request agent. `pub(crate)` because `auth::refresh_locked`
/// needs the same TLS treatment for its `POST /api/auth/refresh` round-trip.
///
/// Exits (code 3, `tls_untrusted`) rather than downgrading when no anchor
/// can be resolved — see the module header.
pub(crate) fn agent(g: &Globals, base_url: &str, default_timeout: u64) -> Agent {
    let trust = match resolve_trust(base_url) {
        Ok(t) => t,
        Err(msg) => fail(
            g.json,
            ExitCode::GatewayUnreachable,
            "tls_untrusted",
            &msg,
            Some(
                "`noo auth status` prints the gateway URL, where it came from, and which \
                 trust anchor the CLI resolved",
            ),
        ),
    };
    let timeout = g.timeout_secs.unwrap_or(default_timeout);
    Agent::config_builder()
        .tls_config(tls_for(&trust))
        .timeout_global(Some(Duration::from_secs(timeout)))
        .timeout_connect(Some(Duration::from_secs(timeout.min(15))))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Which phase a failed round trip died in. A connect, DNS
/// or TLS failure means nothing answered ("cannot reach"); a timeout after
/// the connection was made means the gateway is up and the answer was slow.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum SendFailure {
    Unreachable,
    SlowAnswer,
}

/// Classify by ureq's typed error, never by message text. `Resolve` and
/// `Connect` timeouts are the only timeouts that precede a connection;
/// `Global`/`PerCall` fire after it because [`agent`] also bounds the
/// connect phase on its own (`timeout_connect`), so they cannot be a hung
/// connect.
pub(crate) fn classify_send_error(e: &ureq::Error) -> SendFailure {
    match e {
        ureq::Error::Timeout(ureq::Timeout::Resolve | ureq::Timeout::Connect) => {
            SendFailure::Unreachable
        }
        ureq::Error::Timeout(_) => SendFailure::SlowAnswer,
        _ => SendFailure::Unreachable,
    }
}

/// The request budget in force: `--timeout` if given, else the call's default.
pub(crate) fn effective_timeout(g: &Globals, default_timeout: u64) -> u64 {
    g.timeout_secs.unwrap_or(default_timeout)
}

fn slow_answer_message(secs: u64) -> String {
    format!(
        "the gateway is up but this answer took longer than {secs}s (the box may be slow, or the work behind it) — retry with --timeout {}",
        secs.saturating_mul(2)
    )
}

/// One-line description of a failed round trip, for callers that return
/// `Result<_, String>`.
pub(crate) fn describe_send_error(base: &str, e: &ureq::Error, secs: u64) -> String {
    match classify_send_error(e) {
        SendFailure::SlowAnswer => slow_answer_message(secs),
        SendFailure::Unreachable => format!("cannot reach gateway at {base}: {e}"),
    }
}

/// Exit for a failed round trip: unreachable stays code 3; a slow answer
/// exits 5 (`gateway_slow`) so scripts do not chase a phantom outage.
pub(crate) fn fail_send(g: &Globals, base: &str, e: &ureq::Error, default_timeout: u64) -> ! {
    match classify_send_error(e) {
        SendFailure::SlowAnswer => fail(
            g.json,
            ExitCode::RemoteError,
            "gateway_slow",
            &slow_answer_message(effective_timeout(g, default_timeout)),
            None,
        ),
        SendFailure::Unreachable => fail(
            g.json,
            ExitCode::GatewayUnreachable,
            "gateway_unreachable",
            &format!("cannot reach gateway at {base}: {e}"),
            Some(unreachable_hint()),
        ),
    }
}

/// Uniform 401/403 exit (code 4), naming the credential the CLI actually
/// sent and what to do about it. The CLI resolves --token → $NOO_TOKEN →
/// the stored credential → nothing, and a rejection that doesn't say WHICH
/// one was used is unactionable.
///
/// When an automatic refresh was attempted and failed, its reason is appended:
/// "revoked", "expired 3 days ago" and "your account was disabled" are three
/// different problems with three different fixes, and a bare 401 is none of
/// them.
fn auth_failed(g: &Globals, status: u16, path: &str) -> ! {
    let src = crate::auth::source(g);
    let mut msg = format!(
        "gateway rejected credentials ({status}) for {path} — sent {}",
        src.describe()
    );
    if let Some(why) = crate::auth::refresh_failure() {
        msg.push_str(&format!("; the automatic refresh also failed: {why}"));
    }
    fail(g.json, ExitCode::AuthFailed, "auth_failed", &msg, Some(src.fix_hint()))
}

/// What a single gateway round trip returns before status handling.
type Sent = Result<ureq::http::Response<ureq::Body>, ureq::Error>;

/// Send a request, and if the gateway answers **401** while a refreshable
/// stored credential is in play, refresh once and send it again — exactly
/// once.
///
/// `send` is the whole request (it is called with the bearer to attach,
/// because `ureq` requests are single-use and cannot be cloned).
///
/// Two rules this encodes, both deliberate:
///
/// - **401 only.** A 403 means the gateway authenticated the caller and then
///   refused the action — a scope answer. Refreshing re-mints the *same*
///   identity with the *same* scopes, so retrying would just burn a
///   single-use refresh token and produce the same 403.
/// - **One retry, never a loop.** [`crate::auth::refresh_after_unauthorized`]
///   is a one-shot per process, so even a gateway that 401s everything can
///   only ever cost one extra round trip.
fn send_with_retry<F>(g: &Globals, with_auth: bool, mut send: F) -> Sent
where
    F: FnMut(Option<&str>) -> Sent,
{
    let bearer = if with_auth { crate::auth::bearer(g) } else { None };
    let first = send(bearer.as_deref());
    if !with_auth || !matches!(&first, Ok(r) if r.status().as_u16() == 401) {
        return first;
    }
    match crate::auth::refresh_after_unauthorized(g) {
        Some(fresh) => {
            if g.verbose {
                eprintln!("401 → refreshed the stored credential, retrying once");
            }
            send(Some(&fresh))
        }
        None => first,
    }
}

/// GET `path` from the gateway; returns the parsed JSON body.
/// Hint for an unreachable gateway. "check docker ps" is wrong advice on a
/// box with no install (fresh/offboarded — finding #97) or an INCOMPLETE
/// one (offboard residue, secrets gone — finding #99's sibling): nothing
/// there could ever start. Detect both shapes and name the real fix.
/// (NB #97's original commit lost this file to concurrent-session
/// interference in the shared tree — the ledger row shipped, the code
/// never did. Re-landed here with the residue refinement.)
fn unreachable_hint() -> &'static str {
    let repo_env = crate::envfile::repo_root().join(".env");
    let standalone = crate::onboard::standalone::default_home();
    if !repo_env.exists() && !standalone.exists() {
        return "no Noomesh install on this machine (fresh box, or offboarded) — set one up: noo onboard";
    }
    let home = if standalone.join(".noo-standalone").is_file() {
        standalone
    } else {
        crate::envfile::repo_root()
    };
    let env_text = std::fs::read_to_string(home.join(".env")).unwrap_or_default();
    let sops_ok = env_text.lines()
        .any(|l| l.trim().strip_prefix("NOO_SECRETS_BACKEND=").is_some_and(|v| v.trim() == "sops"))
        && home.join("secrets/env.sops").is_file();
    let plain_ok = env_text.lines()
        .any(|l| l.trim().strip_prefix("POSTGRES_PASSWORD=").is_some_and(|v| !v.trim().is_empty()));
    if !env_text.is_empty() && !sops_ok && !plain_ok {
        return "this install is INCOMPLETE (offboard residue — no core secrets): \
                noo onboard for a fresh setup, noo migrate import <archive> to restore, \
                noo offboard --check to audit";
    }
    "is the gateway running? check `docker ps` / NOO_GATEWAY_URL"
}

pub fn get_json(g: &Globals, path: &str, with_auth: bool, default_timeout: u64) -> serde_json::Value {
    request(g, "GET", path, None, with_auth, default_timeout)
}

/// POST for posture writes ([`post_posture_try`]), exiting on failure with
/// the operator-specific hint instead of "log in again".
pub fn post_json_operator(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    default_timeout: u64,
) -> serde_json::Value {
    match post_posture_try(g, path, body, default_timeout) {
        Ok(v) => v,
        Err(e) => {
            let (code, kind) = match e.status {
                None if e.unreachable => (ExitCode::GatewayUnreachable, "gateway_unreachable"),
                None | Some(401) | Some(403) => (ExitCode::AuthFailed, "auth_failed"),
                Some(_) => (ExitCode::RemoteError, "remote_error"),
            };
            fail(g.json, code, kind, &e.msg, e.hint.as_deref())
        }
    }
}

/// Tolerant GET: returns `None` on any transport/status/parse failure
/// instead of exiting — for composite commands whose secondary fetches are
/// best-effort (parity with the Python CLI's try/except-pass around them).
pub fn get_json_opt(
    g: &Globals,
    path: &str,
    with_auth: bool,
    default_timeout: u64,
) -> Option<serde_json::Value> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("GET {url} (best-effort)");
    }
    let agent = agent(g, &base, default_timeout);
    let mut resp = send_with_retry(g, with_auth, |b| {
        let mut req = agent.get(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.call()
    })
    .ok()?;
    if !(200..=299).contains(&resp.status().as_u16()) {
        return None;
    }
    let text = resp.body_mut().read_to_string().ok()?;
    serde_json::from_str(&text).ok()
}

/// Tolerant GET that keeps the status: `Some((status, body))` for ANY HTTP
/// answer, `None` only when nothing answered. For a verify row that reads a
/// text body (`/metrics`) or that wants to see a refusal (a probe expecting
/// 401/403 must not exit 4 on it, which `request_status` does).
pub fn get_raw_opt(
    g: &Globals,
    path: &str,
    with_auth: bool,
    default_timeout: u64,
) -> Option<(u16, String)> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("GET {url} (best-effort, {})", if with_auth { "credential" } else { "anonymous" });
    }
    let agent = agent(g, &base, default_timeout);
    let mut resp = send_with_retry(g, with_auth, |b| {
        let mut req = agent.get(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.call()
    })
    .ok()?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    Some((status, text))
}

/// Poll-tolerant GET (`jobs run` / `jobs status --wait`): transport failures
/// exit 3 like `get_json` (parity with Python `_poll_job`, which `http_fail`s
/// on connection errors); non-2xx statuses return `None` so the poll loop
/// retries (Python swallows `HTTPStatusError`); a 2xx non-JSON body exits 1
/// `bad_response`.
pub fn get_json_poll(
    g: &Globals,
    path: &str,
    with_auth: bool,
    default_timeout: u64,
) -> Option<serde_json::Value> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("GET {url} (poll)");
    }
    let agent = agent(g, &base, default_timeout);
    let sent = send_with_retry(g, with_auth, |b| {
        let mut req = agent.get(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.call()
    });
    let mut resp = match sent {
        Ok(r) => r,
        Err(e) => fail_send(g, &base, &e, default_timeout),
    };
    if !(200..=299).contains(&resp.status().as_u16()) {
        return None;
    }
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    match serde_json::from_str(&text) {
        Ok(v) => Some(v),
        Err(_) => fail(
            g.json,
            ExitCode::Generic,
            "bad_response",
            &format!("gateway returned non-JSON body from {path}"),
            None,
        ),
    }
}

/// Tolerant GET returning `Err(detail)` on transport/status/parse failures
/// instead of exiting (parity with `post_json_try`) — for per-item loops that
/// must warn-and-continue AND surface the failure reason, unlike
/// `get_json_opt` which drops it. Used by `cluster seed --export`, where a
/// node whose desired-config fetch fails is skipped with a warning that
/// carries the error (Python parity).
pub fn get_json_try(
    g: &Globals,
    path: &str,
    with_auth: bool,
    default_timeout: u64,
) -> Result<serde_json::Value, String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("GET {url} (tolerant)");
    }
    let agent = agent(g, &base, default_timeout);
    let mut resp = send_with_retry(g, with_auth, |b| {
        let mut req = agent.get(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.call()
    })
    .map_err(|e| describe_send_error(&base, &e, effective_timeout(g, default_timeout)))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if (200..=299).contains(&status) {
        return serde_json::from_str(&text)
            .map_err(|_| format!("gateway returned non-JSON body from {path}"));
    }
    let detail = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["detail"].as_str().map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}: {text}"));
    Err(detail)
}

/// Why a probing GET failed: nothing answered, or something did and the
/// answer was no use. The split `noo upgrade`'s pre-roll key check needs: a
/// stack that is DOWN cannot be asked (fall back to the store check), while
/// a gateway that answers 401/5xx/garbage has told us something (refuse).
///
/// "Answered" means an HTTP status line came back. A crash-looping gateway
/// accepts and then resets, or holds the socket and never writes; neither
/// is an answer, and calling it one made `noo upgrade` (the command that
/// fixes the crash loop) refuse to run.
#[derive(Debug, PartialEq, Eq)]
pub enum ProbeFail {
    /// No HTTP response at all: refused, DNS failure, no route, reset or
    /// closed before the status line (TLS handshake included), or a timeout
    /// before the response headers. Classified from `ureq::Error`, never
    /// from text.
    Down(String),
    /// Something answered: any HTTP status (non-2xx), an unparseable body,
    /// a listener whose TLS certificate this CLI rejects, a peer that spoke
    /// something other than HTTP.
    Unreadable(String),
}

/// True when `e`, returned by a request's `call()` (which returns once the
/// response headers are in), proves that no HTTP response came back.
///
/// Kept strict (NOT nothing-answered): a TLS certificate/protocol failure
/// (`Io(InvalidData)` wrapping a rustls error, `Rustls`, `Tls`) and a
/// non-HTTP reply (`Protocol`). A listener completed enough of a handshake
/// to present something this CLI refused; reading that as "the gateway is
/// down" would wave an upgrade past an impostor or a mis-anchored box.
pub(crate) fn nothing_answered(e: &ureq::Error) -> bool {
    use std::io::ErrorKind as K;
    match e {
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => true,
        // Every phase `call()` can time out in precedes the status line;
        // `RecvBody` is the one that follows it.
        ureq::Error::Timeout(t) => !matches!(t, ureq::Timeout::RecvBody),
        ureq::Error::Io(io) => matches!(
            io.kind(),
            K::ConnectionRefused
                | K::ConnectionReset
                | K::ConnectionAborted
                | K::BrokenPipe
                | K::UnexpectedEof
                | K::TimedOut
                | K::NetworkUnreachable
                | K::HostUnreachable
                | K::AddrNotAvailable
                | K::NotFound
        ),
        _ => false,
    }
}

/// GET `path` and return the parsed 2xx JSON body, or say WHICH kind of
/// failure it was ([`ProbeFail`]). Same auth/trust/timeouts as
/// [`get_json_try`].
pub fn get_json_probe(
    g: &Globals,
    path: &str,
    with_auth: bool,
    default_timeout: u64,
) -> Result<serde_json::Value, ProbeFail> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    let agent = agent(g, &base, default_timeout);
    // A second send only happens after the first one got an HTTP 401, so
    // a transport failure on the retry still follows an answer.
    let mut sends = 0u32;
    let mut resp = send_with_retry(g, with_auth, |b| {
        sends += 1;
        let mut req = agent.get(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.call()
    })
    .map_err(|e| {
        let line = describe_send_error(&base, &e, effective_timeout(g, default_timeout));
        if sends == 1 && nothing_answered(&e) { ProbeFail::Down(line) } else { ProbeFail::Unreadable(line) }
    })?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if (200..=299).contains(&status) {
        return serde_json::from_str(&text)
            .map_err(|_| ProbeFail::Unreadable(format!("gateway returned non-JSON body from {path}")));
    }
    Err(ProbeFail::Unreadable(format!("gateway answered HTTP {status} for {path}")))
}

/// POST `body` as JSON to `path`; returns the parsed JSON response.
pub fn post_json(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    with_auth: bool,
    default_timeout: u64,
) -> serde_json::Value {
    request(g, "POST", path, Some(body), with_auth, default_timeout)
}

/// Tolerant POST for posture WRITES (`/api/security/posture*`) from the
/// operator's own commands (`noo upgrade`'s retired-gate migration, the
/// onboard wizard): [`post_posture_try`], and `Err(detail)` instead of
/// `fail()`/`exit`.
///
/// `post_json_try` is the wrong tool for these routes: it sends the stored
/// per-user JWT, which the posture handlers reject BY DESIGN (an app admin
/// must not be able to weaken posture).
pub fn post_json_operator_try(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    default_timeout: u64,
) -> Result<serde_json::Value, String> {
    post_posture_try(g, path, body, default_timeout).map_err(PostureError::into_line)
}

/// Tolerant POST for multi-step orchestration (`cluster bootstrap-token create`): returns
/// `Err(detail)` on transport/status/parse failures instead of exiting, so
/// callers can warn-and-continue per step exactly like the Python CLI's
/// per-replica try/except. The error string carries the gateway's `detail`
/// field when present (parity with Python's HTTPStatusError handling).
pub fn post_json_try(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    with_auth: bool,
    default_timeout: u64,
) -> Result<serde_json::Value, String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("POST {url} (tolerant)");
    }
    let agent = agent(g, &base, default_timeout);
    let mut resp = send_with_retry(g, with_auth, |b| {
        let mut req = agent.post(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.send_json(body)
    })
    .map_err(|e| describe_send_error(&base, &e, effective_timeout(g, default_timeout)))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if (200..=299).contains(&status) {
        return serde_json::from_str(&text)
            .map_err(|_| format!("gateway returned non-JSON body from {path}"));
    }
    let detail = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["detail"].as_str().map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}: {text}"));
    Err(detail)
}

/// Tolerant PUT (parity with `post_json_try`): returns `Err(detail)` on
/// transport/status/parse failures instead of exiting. Used by `onboard`'s
/// best-effort LLM placement, where a failure is a warning, not a crash.
pub fn put_json_try(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    with_auth: bool,
    default_timeout: u64,
) -> Result<serde_json::Value, String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("PUT {url} (tolerant)");
    }
    let agent = agent(g, &base, default_timeout);
    let mut resp = send_with_retry(g, with_auth, |b| {
        let mut req = agent.put(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.send_json(body)
    })
    .map_err(|e| describe_send_error(&base, &e, effective_timeout(g, default_timeout)))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if (200..=299).contains(&status) {
        return serde_json::from_str(&text)
            .map_err(|_| format!("gateway returned non-JSON body from {path}"));
    }
    let detail = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["detail"].as_str().map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}: {text}"));
    Err(detail)
}

/// POST `body` as JSON and return the raw response for STREAMING bodies
/// (SSE / NDJSON, e.g. `models pull` progress). Transport failures exit 3
/// like `request`; status handling is the caller's job (the error body may
/// itself be part of the stream contract).
pub fn post_json_stream(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    with_auth: bool,
    default_timeout: u64,
) -> ureq::http::Response<ureq::Body> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("POST {url} (streaming)");
    }
    let agent = agent(g, &base, default_timeout);
    let sent = send_with_retry(g, with_auth, |b| {
        let mut req = agent.post(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.send_json(body)
    });
    match sent {
        Ok(resp) => resp,
        Err(e) => fail_send(g, &base, &e, default_timeout),
    }
}

/// Tolerant streaming POST (parity with `post_json_try`): returns the raw
/// response for SSE/NDJSON bodies, or `Err(msg)` on transport failure instead
/// of exiting — for callers that must survive a failed request mid-session
/// (the `chat` REPL prints the error and keeps the loop alive, Python
/// parity). Status handling is the caller's job.
pub fn post_json_stream_try(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    with_auth: bool,
    default_timeout: u64,
) -> Result<ureq::http::Response<ureq::Body>, String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("POST {url} (streaming, tolerant)");
    }
    let agent = agent(g, &base, default_timeout);
    send_with_retry(g, with_auth, |b| {
        let mut req = agent.post(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.send_json(body)
    })
    .map_err(|e| describe_send_error(&base, &e, effective_timeout(g, default_timeout)))
}

/// Tolerant DELETE (parity with `post_json_try`): returns `Err(detail)` on
/// transport/status/parse failures instead of exiting. Used by
/// `cluster clean-node`'s best-effort gateway unregister, where a failure is
/// silently ignored (Python wraps it in try/except-pass).
pub fn delete_json_try(
    g: &Globals,
    path: &str,
    with_auth: bool,
    default_timeout: u64,
) -> Result<serde_json::Value, String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("DELETE {url} (tolerant)");
    }
    let agent = agent(g, &base, default_timeout);
    let mut resp = send_with_retry(g, with_auth, |b| {
        let mut req = agent.delete(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.call()
    })
    .map_err(|e| describe_send_error(&base, &e, effective_timeout(g, default_timeout)))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if (200..=299).contains(&status) {
        return serde_json::from_str(&text)
            .or_else(|_| Ok(serde_json::json!({"status": "ok"})));
    }
    Err(format!("HTTP {status}: {text}"))
}

/// DELETE `path` (no body); returns the parsed JSON response.
pub fn delete_json(
    g: &Globals,
    path: &str,
    with_auth: bool,
    default_timeout: u64,
) -> serde_json::Value {
    request(g, "DELETE", path, None, with_auth, default_timeout)
}

/// PUT `body` as JSON to `path`; returns the parsed JSON response.
pub fn put_json(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    with_auth: bool,
    default_timeout: u64,
) -> serde_json::Value {
    request(g, "PUT", path, Some(body), with_auth, default_timeout)
}

/// POST a raw pre-encoded body (e.g. multipart/form-data for
/// `voice transcribe`) with an explicit Content-Type; returns the parsed
/// JSON response with the standard error → exit-code mapping.
pub fn post_bytes(
    g: &Globals,
    path: &str,
    content_type: &str,
    body: &[u8],
    with_auth: bool,
    default_timeout: u64,
) -> serde_json::Value {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("POST {url} ({content_type}, {} bytes)", body.len());
    }
    let agent = agent(g, &base, default_timeout);
    let sent = send_with_retry(g, with_auth, |b| {
        let mut req = agent.post(&url).header("Content-Type", content_type);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.send(body)
    });
    let mut resp = match sent {
        Ok(r) => r,
        Err(e) => fail_send(g, &base, &e, default_timeout),
    };
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    match status {
        200..=299 => serde_json::from_str(&text).unwrap_or_else(|_| {
            fail(
                g.json,
                ExitCode::Generic,
                "bad_response",
                &format!("gateway returned non-JSON body from {path}"),
                None,
            )
        }),
        401 | 403 => auth_failed(g, status, path),
        _ => fail(
            g.json,
            ExitCode::RemoteError,
            "remote_error",
            &remote_error_message(status, path, &text),
            None,
        ),
    }
}

/// A binary (non-JSON) gateway response — audio bytes from
/// POST /api/voice/synthesize plus the headers the CLI renders.
pub struct BinaryResponse {
    pub bytes: Vec<u8>,
    pub content_type: String,
    /// The gateway's `X-TTS-Backend` header ("piper"/"edge"/"unknown").
    pub tts_backend: String,
}

/// POST `body` as JSON and return the RAW response bytes (audio download).
/// Same error → exit-code mapping as `request`; a non-2xx body is read as
/// text for the error message (the gateway sends JSON errors there).
pub fn post_json_binary(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    with_auth: bool,
    default_timeout: u64,
) -> BinaryResponse {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("POST {url} (binary response)");
    }
    let agent = agent(g, &base, default_timeout);
    let sent = send_with_retry(g, with_auth, |b| {
        let mut req = agent.post(&url);
        if let Some(b) = b {
            req = req.header("Authorization", b);
        }
        req.send_json(body)
    });
    let mut resp = match sent {
        Ok(r) => r,
        Err(e) => fail_send(g, &base, &e, default_timeout),
    };
    let status = resp.status().as_u16();
    match status {
        200..=299 => {
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("audio/wav")
                .to_string();
            let tts_backend = resp
                .headers()
                .get("x-tts-backend")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown")
                .to_string();
            let mut bytes = Vec::new();
            use std::io::Read;
            if let Err(e) = resp.body_mut().as_reader().read_to_end(&mut bytes) {
                fail(
                    g.json,
                    ExitCode::Generic,
                    "bad_response",
                    &format!("failed to read response body from {path}: {e}"),
                    None,
                );
            }
            BinaryResponse { bytes, content_type, tts_backend }
        }
        401 | 403 => auth_failed(g, status, path),
        _ => {
            let text = resp.body_mut().read_to_string().unwrap_or_default();
            fail(
                g.json,
                ExitCode::RemoteError,
                "remote_error",
                &remote_error_message(status, path, &text),
                None,
            )
        }
    }
}

/// Shared request path. Auth/transport failures exit the process with the
/// typed code — handlers only ever see a successful JSON body. Thin wrapper
/// over `request_status` that maps every remaining non-2xx to exit 5.
/// The sentence for a non-2xx answer. A gateway refusal that carries a
/// `detail` (the 503 `redis_reconnecting` shape: `{"error": <code>,
/// "detail": <sentence>, "retry_after_secs": N}`) is shown as that sentence
/// plus the retry hint, never as the raw JSON glued onto the status.
pub(crate) fn remote_error_message(status: u16, path: &str, text: &str) -> String {
    let parsed = serde_json::from_str::<serde_json::Value>(text).ok();
    if let Some(detail) = parsed.as_ref().and_then(|v| v["detail"].as_str()) {
        let retry = parsed
            .as_ref()
            .and_then(|v| v["retry_after_secs"].as_u64())
            .map(|n| format!(" — retry in {n}s"))
            .unwrap_or_default();
        return format!("gateway returned {status} for {path}: {detail}{retry}");
    }
    format!("gateway returned {status} for {path}: {text}")
}

fn request(
    g: &Globals,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    with_auth: bool,
    default_timeout: u64,
) -> serde_json::Value {
    match request_status(g, method, path, body, with_auth, default_timeout) {
        Ok(v) => v,
        Err((status, text)) => fail(
            g.json,
            ExitCode::RemoteError,
            "remote_error",
            &remote_error_message(status, path, &text),
            None,
        ),
    }
}

/// ── WP-L ── Status-aware request: transport failures exit 3 and 401/403
/// exit 4 exactly like `request`, a 2xx JSON body returns `Ok` (2xx +
/// non-JSON still exits 1 `bad_response`) — but any OTHER status returns
/// `Err((status, body_text))` instead of exiting 5, so callers that must
/// distinguish specific statuses (e.g. a 404 meaning "this optional route
/// group is not mounted on this gateway") can render them.
pub fn request_status(
    g: &Globals,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    with_auth: bool,
    default_timeout: u64,
) -> Result<serde_json::Value, (u16, String)> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("{method} {url}");
    }
    let agent = agent(g, &base, default_timeout);

    let result = send_with_retry(g, with_auth, |bearer| match body {
        None => {
            let mut req = if method == "DELETE" { agent.delete(&url) } else { agent.get(&url) };
            if let Some(b) = bearer {
                req = req.header("Authorization", b);
            }
            req.call()
        }
        Some(json_body) => {
            let mut req = if method == "PUT" { agent.put(&url) } else { agent.post(&url) };
            if let Some(b) = bearer {
                req = req.header("Authorization", b);
            }
            req.send_json(json_body)
        }
    });

    let mut resp = match result {
        Ok(r) => r,
        Err(e) => fail_send(g, &base, &e, default_timeout),
    };

    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();

    match status {
        200..=299 => Ok(serde_json::from_str(&text).unwrap_or_else(|_| {
            fail(
                g.json,
                ExitCode::Generic,
                "bad_response",
                &format!("gateway returned non-JSON body from {path}"),
                None,
            )
        })),
        401 | 403 => auth_failed(g, status, path),
        _ => Err((status, text)),
    }
}


/// Tolerant, status-aware request for callers that must survive an
/// unreachable controller (the add-on command cache): never exits.
/// `Ok((status, body_text))` for ANY HTTP status; `Err(why)` only when no
/// response arrived (no TLS anchor, refused, timed out). No 401 handling
/// beyond the one refresh retry every request gets: the caller decides what a
/// refusal means.
pub fn request_try(
    g: &Globals,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    with_auth: bool,
    default_timeout: u64,
) -> Result<(u16, String), String> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    if g.verbose {
        eprintln!("{method} {url} (tolerant)");
    }
    let secs = effective_timeout(g, default_timeout);
    let agent = agent_for(&base, secs)?;
    let mut resp = send_with_retry(g, with_auth, |bearer| match body {
        None => {
            let mut req = agent.get(&url);
            if let Some(b) = bearer {
                req = req.header("Authorization", b);
            }
            req.call()
        }
        Some(json_body) => {
            let mut req = agent.post(&url);
            if let Some(b) = bearer {
                req = req.header("Authorization", b);
            }
            req.send_json(json_body)
        }
    })
    .map_err(|e| describe_send_error(&base, &e, secs))?;
    let status = resp.status().as_u16();
    Ok((status, resp.body_mut().read_to_string().unwrap_or_default()))
}

// ── Posture writes ──────────────────────────────────────
//
// `POST /api/security/posture[/profile]` admits an operator client
// certificate on the connection plus an Admin token BOUND to it (minted by
// `POST /api/security/operator-token` over that connection), and nothing
// else — no shared secret, no break-glass (gateway-rust/src/operator_auth.rs).
// This is the CLI half.

/// The credential a posture write will carry. Pure — see [`posture_route`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PostureRoute {
    /// The operator's certificate and a token bound to it.
    Operator { account: String, pair: crate::operator_cert::OperatorPair },
    /// Nothing usable: the message and the way out.
    Refuse { msg: String, hint: String },
}

/// Decide the credential for a posture write: the operator's certificate
/// (with a bound token), or a refusal that names how to get one. There is
/// no third answer — the shared secret is never chosen.
pub(crate) fn posture_route(
    account: Option<&str>,
    pair: Option<crate::operator_cert::OperatorPair>,
    cert_dir: &std::path::Path,
) -> PostureRoute {
    if let (Some(account), Some(pair)) = (account, pair) {
        return PostureRoute::Operator { account: account.to_string(), pair };
    }
    let who = account.unwrap_or("<you>");
    let missing = match account {
        Some(a) => format!("no operator client certificate for '{a}' at {}", cert_dir.display()),
        None => "no operator account (no `noo auth login`, no $NOO_OPERATOR)".to_string(),
    };
    PostureRoute::Refuse {
        msg: format!(
            "{missing}. Posture writes need your operator client certificate and a token bound to it; \
             a login alone is refused by design"
        ),
        hint: if account.is_some() {
            format!("on the controller: noo security pki issue-client {who} --force")
        } else {
            "noo auth login   # then, on the controller: noo security pki issue-client <you>".to_string()
        },
    }
}

/// A failed posture write. `status` is the gateway's answer when there was
/// one; `None` with `unreachable` is a transport failure, `None` without it
/// is a local refusal (no usable credential).
#[derive(Debug)]
pub(crate) struct PostureError {
    pub status: Option<u16>,
    pub unreachable: bool,
    pub msg: String,
    pub hint: Option<String>,
}

impl PostureError {
    fn local(msg: String, hint: Option<String>) -> Self {
        PostureError { status: None, unreachable: false, msg, hint }
    }
    fn into_line(self) -> String {
        match self.hint {
            Some(h) => format!("{} ({h})", self.msg),
            None => self.msg,
        }
    }
}

/// A request agent presenting `pair` as the client certificate. Refuses a
/// plain-http URL: a client certificate needs TLS, and sending the bound
/// token in clear would defeat the point.
pub(crate) fn agent_with_client_cert(
    g: &Globals,
    base_url: &str,
    default_timeout: u64,
    pair: &crate::operator_cert::OperatorPair,
) -> Result<Agent, String> {
    let trust = resolve_trust(base_url)?;
    if trust == Trust::LoopbackPlaintext {
        return Err(format!(
            "{base_url} is plain http — an operator client certificate is presented only over TLS"
        ));
    }
    let cert = Certificate::from_pem(pair.cert_pem.as_bytes())
        .map_err(|e| format!("operator certificate unreadable: {e}"))?;
    let key = ureq::tls::PrivateKey::from_pem(pair.key_pem.as_bytes())
        .map_err(|e| format!("operator key unreadable: {e}"))?;
    let client = ureq::tls::ClientCert::new_with_certs(&[cert], key);
    let timeout = g.timeout_secs.unwrap_or(default_timeout);
    Ok(Agent::config_builder()
        .tls_config(tls_for_with(&trust, Some(client)))
        .timeout_global(Some(Duration::from_secs(timeout)))
        .timeout_connect(Some(Duration::from_secs(timeout.min(15))))
        .http_status_as_error(false)
        .build()
        .into())
}

/// POST `body` over `agent` with `bearer`; `(status, text)` or a transport error.
pub(crate) fn post_raw(
    agent: &Agent,
    url: &str,
    bearer: Option<&str>,
    body: &serde_json::Value,
) -> Result<(u16, String), ureq::Error> {
    let mut req = agent.post(url);
    if let Some(b) = bearer {
        req = req.header("Authorization", b);
    }
    let mut resp = req.send_json(body)?;
    let status = resp.status().as_u16();
    Ok((status, resp.body_mut().read_to_string().unwrap_or_default()))
}

/// The gateway's `detail` (or the raw text) from an error body.
pub(crate) fn detail_of(status: u16, text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v["detail"].as_str().or_else(|| v["error"].as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}: {text}"))
}

/// The operator's LOGIN, for registering a certificate or minting a bound
/// token.
pub(crate) fn operator_login(g: &Globals) -> Result<String, String> {
    crate::auth::resolve(g).header.ok_or_else(|| {
        "no login — the operator certificate pairs with your own Admin login: run `noo auth login` \
         (lost the password? on the controller: noo security admin-password reset)"
            .into()
    })
}

/// Mint an Admin token bound to the certificate `agent` presents
/// (`POST /api/security/operator-token`). Returns the `Authorization` value.
pub(crate) fn mint_bound_token(g: &Globals, base: &str, agent: &Agent, account: &str) -> Result<String, PostureError> {
    let login = operator_login(g).map_err(|m| PostureError::local(m, None))?;
    let url = format!("{base}/api/security/operator-token");
    let (status, text) = post_raw(agent, &url, Some(&login), &serde_json::json!({})).map_err(|e| PostureError {
        status: None,
        unreachable: true,
        msg: describe_send_error(base, &e, effective_timeout(g, 15)),
        hint: None,
    })?;
    if !(200..=299).contains(&status) {
        let hint = if status == 404 {
            "the gateway predates operator certificates — `noo upgrade --all` first".to_string()
        } else {
            format!("check `noo auth status`; re-register with: noo security pki issue-client {account}")
        };
        return Err(PostureError {
            status: Some(status),
            unreachable: false,
            msg: format!("could not get a token bound to your operator certificate: {}", detail_of(status, &text)),
            hint: Some(hint),
        });
    }
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    v["access_token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .map(|t| format!("Bearer {t}"))
        .ok_or_else(|| PostureError::local("the gateway's operator-token answer carried no token".into(), None))
}

/// POST a posture write with the credential [`posture_route`] picks. The
/// one implementation behind `posture set`, `apply-profile`, `noo upgrade`'s
/// retired-gate migration, `pki revoke-client` and the onboard wizard.
pub(crate) fn post_posture_try(
    g: &Globals,
    path: &str,
    body: &serde_json::Value,
    default_timeout: u64,
) -> Result<serde_json::Value, PostureError> {
    let base = crate::envfile::gateway_url(&g.gateway_override);
    let url = format!("{base}{path}");
    let account = crate::operator_cert::current_account();
    let pair = account.as_deref().and_then(crate::operator_cert::load);
    let cert_dir = account
        .as_deref()
        .map(crate::operator_cert::dir_for)
        .unwrap_or_else(crate::operator_cert::operator_root);
    let route = posture_route(account.as_deref(), pair, &cert_dir);
    if g.verbose {
        eprintln!("POST {url} (posture write)");
    }

    let transport = |e: ureq::Error| PostureError {
        status: None,
        unreachable: true,
        msg: describe_send_error(&base, &e, effective_timeout(g, default_timeout)),
        hint: None,
    };
    let (status, text) = match route {
        PostureRoute::Refuse { msg, hint } => return Err(PostureError::local(msg, Some(hint))),
        PostureRoute::Operator { account, pair } => {
            let agent = agent_with_client_cert(g, &base, default_timeout, &pair)
                .map_err(|m| PostureError::local(m, None))?;
            let bound = mint_bound_token(g, &base, &agent, &account)?;
            post_raw(&agent, &url, Some(&bound), body).map_err(transport)?
        }
    };
    if (200..=299).contains(&status) {
        return serde_json::from_str(&text)
            .map_err(|_| PostureError::local(format!("gateway returned non-JSON body from {path}"), None));
    }
    let hint = (status == 401 || status == 403).then(|| {
        "posture writes take your operator certificate (on the controller: noo security pki issue-client <you> --force)"
            .to_string()
    });
    Err(PostureError { status: Some(status), unreachable: false, msg: format!("{path}: {}", detail_of(status, &text)), hint })
}

#[cfg(test)]
mod posture_route_tests {
    use super::*;
    use crate::operator_cert::OperatorPair;

    fn pair() -> OperatorPair {
        OperatorPair { cert_pem: "c".into(), key_pem: "k".into() }
    }
    fn dir() -> std::path::PathBuf {
        std::path::PathBuf::from("/home/op/.config/mesh/operator/alice")
    }

    #[test]
    fn a_held_certificate_is_the_choice() {
        let r = posture_route(Some("alice"), Some(pair()), &dir());
        assert!(matches!(r, PostureRoute::Operator { ref account, .. } if account == "alice"), "{r:?}");
    }

    /// No certificate: refused before anything is sent, naming the way to
    /// get one — and never offering a shared secret
    /// (no break-glass, no onboard bootstrap). `posture_route`
    /// takes no secret and reads none.
    #[test]
    fn without_a_certificate_the_write_is_refused_and_names_issue_client() {
        match posture_route(Some("alice"), None, &dir()) {
            PostureRoute::Refuse { msg, hint } => {
                assert!(msg.contains("no operator client certificate for 'alice'"), "{msg}");
                assert!(hint.contains("noo security pki issue-client alice"), "{hint}");
                assert!(!hint.contains("break-glass") && !msg.contains("break-glass"), "{msg} / {hint}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        match posture_route(None, None, &dir()) {
            PostureRoute::Refuse { hint, .. } => assert!(hint.contains("noo auth login"), "{hint}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod trust_tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// $NOO_TLS_CA / $NOO_PKI_DIR are process-global; these cases set them.
    fn env_lock() -> MutexGuard<'static, ()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join(format!("noo-trust-{}-{tag}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A syntactically valid self-signed PEM, so `Certificate::from_pem`
    /// has something real to accept. rcgen is already a dependency.
    fn a_real_ca_pem() -> String {
        let kp = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["test-ca".to_string()]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.self_signed(&kp).unwrap().pem()
    }

    /// Isolate from the host: no NOO_TLS_CA, and a PKI dir with no ca.crt.
    fn clean_env(tag: &str) -> PathBuf {
        std::env::remove_var("NOO_TLS_CA");
        std::env::remove_var("NOO_TLS_INSECURE");
        let d = tmpdir(tag);
        std::env::set_var("NOO_PKI_DIR", &d);
        d
    }

    /// An enrolled box verifies against the anchor ENROLLMENT WROTE, not
    /// against everything the machine happens to trust. Before this, the
    /// enrolled lane used the platform verifier, so `noo` on a node could
    /// not talk to its own controller unless the cluster CA had been
    /// installed machine-wide — which meant every process on the box
    /// trusted anything that CA signed, to solve a problem only the CLI
    /// had.
    #[test]
    fn an_enrolled_box_verifies_against_the_file_enrollment_wrote() {
        let _g = env_lock();
        let d = clean_env("enrolled-file");
        let ca = d.join("ca.crt");
        std::fs::write(&ca, a_real_ca_pem()).unwrap();

        let got = enrolled_anchor(vec![ca.clone()], "https://controller:8080").unwrap();
        assert_eq!(got, Trust::EnrolledCa(ca), "the enrolled anchor must be the file");
        assert_eq!(got.label(), "enrolled_ca");
    }

    /// THE WIRING, not just the helper. An enrolled box's request must
    /// resolve to the anchor file — this is the test that fails if the
    /// enrolled rung goes back to handing everything to the platform
    /// verifier.
    #[test]
    fn the_enrolled_rung_resolves_to_the_anchor_file() {
        let _g = env_lock();
        let d = clean_env("enrolled-wiring");
        let ca = d.join("ca.crt");
        std::fs::write(&ca, a_real_ca_pem()).unwrap();
        let url = "https://controller.example:8080";

        let got = resolve_trust_with(url, Some(url.to_string())).unwrap();
        assert_eq!(got, Trust::EnrolledCa(ca), "enrolled must verify against its own CA file");
    }

    /// Enrollment still outranks `$NOO_TLS_CA` — the property the old
    /// platform-verifier rung existed to protect. A stale CA path in a dev
    /// clone's `.env` must not decide how an enrolled box verifies its own
    /// controller (HOST3, 2026-09-01).
    #[test]
    fn a_stale_env_ca_cannot_outrank_enrollment() {
        let _g = env_lock();
        let d = clean_env("enrolled-outranks");
        let good = d.join("ca.crt");
        std::fs::write(&good, a_real_ca_pem()).unwrap();
        let stale = d.join("retired-controller.crt");
        std::fs::write(&stale, a_real_ca_pem()).unwrap();
        std::env::set_var("NOO_TLS_CA", &stale);
        let url = "https://controller.example:8080";

        let got = resolve_trust_with(url, Some(url.to_string()));
        std::env::remove_var("NOO_TLS_CA");
        assert_eq!(
            got.unwrap(),
            Trust::EnrolledCa(good),
            "the enrolled anchor must win over a stale $NOO_TLS_CA"
        );
    }

    /// A box that is NOT enrolled, or is pointed at a different gateway,
    /// takes the ordinary ladder — enrollment answers for its own
    /// controller and nothing else.
    #[test]
    fn a_different_gateway_does_not_borrow_the_enrolled_anchor() {
        let _g = env_lock();
        let d = clean_env("enrolled-other");
        let ca = d.join("ca.crt");
        std::fs::write(&ca, a_real_ca_pem()).unwrap();

        let got = resolve_trust_with("https://somewhere.else:8080", Some("https://controller.example:8080".into()))
            .unwrap();
        assert_eq!(got, Trust::ClusterCa(ca), "a non-enrolled URL uses rung 4, not the enrolled rung");
    }

    /// The fallback that keeps an ordinary user working: on a node
    /// `/etc/noo/pki` may be root-only, and `noo cluster status` must still
    /// run. Unreadable is not an error — the machine store answers instead.
    #[test]
    fn an_unreadable_anchor_falls_back_rather_than_failing() {
        let _g = env_lock();
        let d = clean_env("enrolled-unreadable");
        let missing = d.join("not-there.crt");

        let got = enrolled_anchor(vec![missing], "https://controller:8080").unwrap();
        assert_eq!(got, Trust::Enrolled, "an unreadable anchor must fall back, not fail");
    }

    /// Corruption of the box's OWN declared anchor is named, not stepped
    /// around. Falling through would verify the controller against WebPKI
    /// while the operator believed the cluster CA was in use.
    #[test]
    fn a_corrupt_anchor_is_an_error_naming_the_file() {
        let _g = env_lock();
        let d = clean_env("enrolled-corrupt");
        let ca = d.join("ca.crt");
        std::fs::write(&ca, b"-----BEGIN CERTIFICATE-----\nnot base64\n").unwrap();

        let err = enrolled_anchor(vec![ca.clone()], "https://controller:8080").unwrap_err();
        assert!(err.contains(&ca.display().to_string()), "must name the file: {err}");
        assert!(err.contains("not a PEM certificate"), "must say what is wrong: {err}");
    }

    /// First readable candidate wins, in order — `$NOO_PKI_DIR` before the
    /// node path, so a box with both uses the one it was pointed at.
    #[test]
    fn the_first_readable_candidate_wins() {
        let _g = env_lock();
        let d = clean_env("enrolled-order");
        let first = d.join("first.crt");
        let second = d.join("second.crt");
        std::fs::write(&second, a_real_ca_pem()).unwrap();
        // `first` does not exist, so `second` answers …
        assert_eq!(
            enrolled_anchor(vec![first.clone(), second.clone()], "https://c:8080").unwrap(),
            Trust::EnrolledCa(second.clone())
        );
        // … and once it does, it wins.
        std::fs::write(&first, a_real_ca_pem()).unwrap();
        assert_eq!(
            enrolled_anchor(vec![first.clone(), second], "https://c:8080").unwrap(),
            Trust::EnrolledCa(first)
        );
    }

    #[test]
    fn loopback_http_is_the_only_plaintext_lane() {
        let _g = env_lock();
        clean_env("loopback");
        for ok in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.0.0.53:9090/",
            "http://[::1]:8080",
        ] {
            assert_eq!(
                resolve_trust(ok).unwrap(),
                Trust::LoopbackPlaintext,
                "{ok} should be the loopback carve-out"
            );
        }
    }

    /// THE guard: a cleartext gateway anywhere but this machine is refused.
    /// On the pre-2026-09-11 code this returned an agent and posted the
    /// stored JWT to it.
    #[test]
    fn non_loopback_http_is_refused() {
        let _g = env_lock();
        clean_env("plainhttp");
        for bad in [
            "http://host8.example.ts.net:8080",
            "http://10.0.0.4:8080",
            "http://gateway.internal/",
            // Not loopback however friendly it looks.
            "http://localhost.evil.example.com:8080",
        ] {
            let err = resolve_trust(bad).expect_err("{bad} must be refused");
            assert!(err.contains("TLS is required"), "unhelpful error for {bad}: {err}");
        }
    }

    /// A CA file that is SET must work. Before this change an unreadable or
    /// unparseable NOO_TLS_CA silently became `disable_verification(true)`.
    #[test]
    fn set_but_unusable_ca_is_a_hard_error_naming_the_path() {
        let _g = env_lock();
        let d = clean_env("badca");

        let missing = d.join("nope.crt");
        std::env::set_var("NOO_TLS_CA", &missing);
        let err = resolve_trust("https://gw.example:8080").expect_err("missing CA must fail");
        assert!(err.contains(&missing.display().to_string()), "error must name the path: {err}");
        assert!(err.contains("will not fall back"), "error must say it is fail-closed: {err}");

        let garbage = d.join("garbage.crt");
        std::fs::write(&garbage, b"this is not a certificate\n").unwrap();
        std::env::set_var("NOO_TLS_CA", &garbage);
        let err = resolve_trust("https://gw.example:8080").expect_err("garbage CA must fail");
        assert!(err.contains(&garbage.display().to_string()), "error must name the path: {err}");
        assert!(err.contains("not a PEM certificate"), "error must say why: {err}");

        std::env::remove_var("NOO_TLS_CA");
    }

    #[test]
    fn a_good_env_ca_wins_over_the_pki_dir() {
        let _g = env_lock();
        let d = clean_env("envca");
        let pem = a_real_ca_pem();
        let env_ca = d.join("env-ca.crt");
        std::fs::write(&env_ca, &pem).unwrap();
        std::fs::write(d.join("ca.crt"), &pem).unwrap();
        std::env::set_var("NOO_TLS_CA", &env_ca);
        assert_eq!(resolve_trust("https://gw.example:8080").unwrap(), Trust::EnvCa(env_ca));
        std::env::remove_var("NOO_TLS_CA");
    }

    /// No NOO_TLS_CA → the cluster CA the box already holds, at the SAME
    /// path `noo security pki` uses ($NOO_PKI_DIR, else ~/.config/mesh/pki).
    #[test]
    fn falls_back_to_the_cluster_ca_in_the_pki_dir() {
        let _g = env_lock();
        let d = clean_env("pkica");
        let ca = d.join("ca.crt");
        std::fs::write(&ca, a_real_ca_pem()).unwrap();
        assert_eq!(resolve_trust("https://gw.example:8080").unwrap(), Trust::ClusterCa(ca));
    }

    /// A readable ca.crt that is not a certificate is corruption, not a
    /// reason to quietly verify against WebPKI instead.
    #[test]
    fn a_corrupt_cluster_ca_is_an_error_not_a_fallthrough() {
        let _g = env_lock();
        let d = clean_env("corruptca");
        std::fs::write(d.join("ca.crt"), b"-----BEGIN CERTIFICATE-----\nnope\n").unwrap();
        let err = resolve_trust("https://gw.example:8080").expect_err("corrupt CA must fail");
        assert!(err.contains("ca.crt"), "error must name the file: {err}");
    }

    /// Nothing configured, nothing on disk → WebPKI. Never "no verification".
    #[test]
    fn last_resort_is_the_platform_verifier() {
        let _g = env_lock();
        clean_env("platform");
        assert_eq!(resolve_trust("https://gw.example:8080").unwrap(), Trust::Platform);
    }

    #[test]
    fn url_host_handles_ports_ipv6_and_paths() {
        assert_eq!(url_host("https://a.b:8080/x/y"), "a.b");
        assert_eq!(url_host("http://[::1]:8080/health"), "[::1]");
        assert_eq!(url_host("https://host"), "host");
    }

    /// `is_loopback` is the URL-level predicate `auth::credential_usable_for`
    /// leans on to decide "same box, other name". A hostname that merely
    /// STARTS with a loopback name is a different machine, and treating it
    /// as loopback would hand the stored credential to it.
    #[test]
    fn is_loopback_reads_the_host_not_the_prefix() {
        for yes in [
            "https://localhost:8080",
            "http://127.0.0.1:8080",
            "https://[::1]:8080",
            "https://LOCALHOST:8080/x",
        ] {
            assert!(is_loopback(yes), "{yes} is this machine");
        }
        for no in [
            "https://localhost.evil.example:8080",
            "https://noo.example.ts.net:8080",
            "https://127.0.0.1.evil.example:8080",
        ] {
            assert!(!is_loopback(no), "{no} is NOT this machine");
        }
    }

    /// PINNED. PR #99 shipped `NOO_TLS_INSECURE=1` as an explicit operator
    /// opt-out of verification. The operator's call was "the point is no
    /// escape", so the variable is refused rather than honoured — and
    /// refused LOUDLY rather than ignored, because an operator who sets it
    /// believes verification is off and must be told it is not.
    #[test]
    fn there_is_no_insecure_escape_hatch() {
        let _g = env_lock();
        clean_env("no-escape");
        // Baseline: without the variable this URL resolves fine.
        assert_eq!(resolve_trust("https://gw.example:8080").unwrap(), Trust::Platform);
        for v in ["1", "true", "yes"] {
            std::env::set_var("NOO_TLS_INSECURE", v);
            let err = resolve_trust("https://gw.example:8080")
                .expect_err("NOO_TLS_INSECURE must be refused, not honoured");
            assert!(err.contains("no unverified-TLS lane"), "{v}: {err}");
            assert!(err.contains("NOO_TLS_CA"), "the error must say how to fix it: {err}");
        }
        // It must not become a booby trap for anyone who explicitly turned
        // it OFF, nor for an empty value.
        for v in ["0", "", "  "] {
            std::env::set_var("NOO_TLS_INSECURE", v);
            assert!(
                resolve_trust("https://gw.example:8080").is_ok(),
                "NOO_TLS_INSECURE={v:?} means 'not asking for it' and must not refuse"
            );
        }
        std::env::remove_var("NOO_TLS_INSECURE");
    }

    /// The branches PR #99's `the_client_never_silently_downgrades` pinned,
    /// restated against `resolve_trust`. Two of its cases now resolve
    /// STRICTER than they did there: a remote `http://` URL was `Plain`
    /// (allowed) and is refused here, and an `https://` loopback gateway
    /// with no CA was `InsecureLoopback` (verification off) and now finds
    /// the cluster CA — the gateway cert carries `localhost` and
    /// `127.0.0.1` among its SANs, so there was never anything to gain.
    #[test]
    fn the_client_never_silently_downgrades() {
        let _g = env_lock();
        let dir = clean_env("no-downgrade");
        let remote = "https://noo-controller.example.ts.net:8080";

        // No CA anywhere: WebPKI, never "verify nothing".
        assert_eq!(resolve_trust(remote).unwrap(), Trust::Platform);

        // A pinned CA outranks the platform verifier.
        let ca = dir.join("ca.crt");
        std::fs::write(&ca, a_real_ca_pem()).unwrap();
        assert_eq!(resolve_trust(remote).unwrap(), Trust::ClusterCa(ca.clone()));

        // A CA that does not parse is refused rather than ignored — and it
        // is refused with the opt-in set, too, which is #99's own case.
        let bad = tmpdir("no-downgrade-bad").join("ca.crt");
        std::fs::write(&bad, "not a certificate").unwrap();
        std::env::set_var("NOO_TLS_CA", &bad);
        assert!(resolve_trust(remote).is_err(), "an unparseable $NOO_TLS_CA is refused");
        std::env::set_var("NOO_TLS_INSECURE", "1");
        assert!(resolve_trust(remote).is_err(), "and the refusal survives the retired opt-in");
        std::env::remove_var("NOO_TLS_INSECURE");
        std::env::remove_var("NOO_TLS_CA");

        // An https loopback gateway with no CA does NOT disable verification.
        let empty = clean_env("no-downgrade-loopback");
        let _ = empty;
        assert_eq!(resolve_trust("https://localhost:8080").unwrap(), Trust::Platform);
        assert_eq!(resolve_trust("https://127.0.0.1:9080").unwrap(), Trust::Platform);
        assert_eq!(resolve_trust("https://[::1]:8080").unwrap(), Trust::Platform);

        // A remote cleartext gateway is refused; #99 allowed it as `Plain`.
        assert!(resolve_trust("http://noo-controller.example.ts.net:8080").is_err());
    }
}

#[cfg(test)]
mod send_classify_tests {
    use super::*;

    #[test]
    fn timeouts_after_connect_are_slow_answers() {
        for t in [
            ureq::Timeout::Global,
            ureq::Timeout::PerCall,
            ureq::Timeout::SendRequest,
            ureq::Timeout::SendBody,
            ureq::Timeout::RecvResponse,
            ureq::Timeout::RecvBody,
        ] {
            assert_eq!(classify_send_error(&ureq::Error::Timeout(t)), SendFailure::SlowAnswer, "{t:?}");
        }
    }

    #[test]
    fn connect_phase_failures_stay_unreachable() {
        for e in [
            ureq::Error::Timeout(ureq::Timeout::Connect),
            ureq::Error::Timeout(ureq::Timeout::Resolve),
            ureq::Error::ConnectionFailed,
            ureq::Error::HostNotFound,
            ureq::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
        ] {
            assert_eq!(classify_send_error(&e), SendFailure::Unreachable, "{e}");
        }
    }

    #[test]
    fn slow_message_names_budget_and_doubles_it() {
        let m = describe_send_error("https://x", &ureq::Error::Timeout(ureq::Timeout::Global), 60);
        assert!(m.contains("longer than 60s") && m.contains("--timeout 120"), "{m}");
        assert!(!m.contains("cannot reach"), "{m}");
        let m = describe_send_error("https://x", &ureq::Error::HostNotFound, 60);
        assert!(m.starts_with("cannot reach gateway at https://x"), "{m}");
    }
}

#[cfg(test)]
mod nothing_answered_tests {
    use super::*;
    use std::io::{ErrorKind as K, Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn io(k: K) -> ureq::Error {
        ureq::Error::Io(std::io::Error::new(k, "test"))
    }

    /// What `call()` returns against a peer that does `serve` with each connection.
    fn call_against(scheme: &str, serve: fn(std::net::TcpStream)) -> Result<u16, ureq::Error> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("{scheme}://{}/api/security/service-keys", l.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((c, _)) = l.accept() {
                serve(c);
            }
        });
        test_agent().get(&url).call().map(|r| r.status().as_u16())
    }

    /// The production agent's TLS and status settings, with a 1s budget.
    fn test_agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .tls_config(tls_for(&Trust::Platform))
            .timeout_global(Some(Duration::from_secs(1)))
            .http_status_as_error(false)
            .build()
            .into()
    }

    /// Leave the request unread and close: the kernel answers with RST.
    fn reset(c: std::net::TcpStream) {
        std::thread::sleep(Duration::from_millis(200));
        drop(c);
    }

    #[test]
    fn refused_is_nothing_answered() {
        let port = { let l = TcpListener::bind("127.0.0.1:0").unwrap(); l.local_addr().unwrap().port() };
        let e = test_agent().get(&format!("http://127.0.0.1:{port}/")).call().unwrap_err();
        assert!(nothing_answered(&e), "{e:?}");
        assert!(nothing_answered(&io(K::ConnectionRefused)));
    }

    /// The 0.6.9 rehearsal B5.keycheck case: a crash-looping gateway
    /// accepts and resets. That is not an answer.
    #[test]
    fn reset_before_the_status_line_is_nothing_answered() {
        let e = call_against("http", reset).unwrap_err();
        assert!(nothing_answered(&e), "{e:?}");
        let e = call_against("http", drop::<std::net::TcpStream>).unwrap_err();
        assert!(nothing_answered(&e), "closed with no bytes: {e:?}");
        for k in [K::ConnectionReset, K::ConnectionAborted, K::BrokenPipe, K::UnexpectedEof] {
            assert!(nothing_answered(&io(k)), "{k:?}");
        }
    }

    #[test]
    fn timeout_before_the_headers_is_nothing_answered() {
        let e = call_against("http", |mut c| {
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
            std::thread::sleep(Duration::from_secs(3));
        })
        .unwrap_err();
        assert!(matches!(e, ureq::Error::Timeout(_)), "{e:?}");
        assert!(nothing_answered(&e), "{e:?}");
        for t in [
            ureq::Timeout::Resolve,
            ureq::Timeout::Connect,
            ureq::Timeout::SendRequest,
            ureq::Timeout::SendBody,
            ureq::Timeout::RecvResponse,
            ureq::Timeout::Global,
            ureq::Timeout::PerCall,
        ] {
            assert!(nothing_answered(&ureq::Error::Timeout(t)), "{t:?}");
        }
        assert!(!nothing_answered(&ureq::Error::Timeout(ureq::Timeout::RecvBody)), "the body phase follows an answer");
    }

    #[test]
    fn tls_handshake_reset_is_nothing_answered() {
        let e = call_against("https", reset).unwrap_err();
        assert!(nothing_answered(&e), "{e:?}");
        let e = call_against("https", |mut c| {
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
        })
        .unwrap_err();
        assert!(nothing_answered(&e), "closed mid-handshake: {e:?}");
    }

    /// Kept strict: a certificate this CLI refuses, or a peer that is not
    /// speaking HTTP, came from a listener; that is not a down gateway.
    #[test]
    fn a_refused_certificate_or_garbage_still_counts_as_answered() {
        let cert = std::io::Error::new(K::InvalidData, rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer));
        assert!(!nothing_answered(&ureq::Error::Io(cert)));
        assert!(!nothing_answered(&ureq::Error::Tls("bad")));
        assert!(!nothing_answered(&ureq::Error::Rustls(rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))));
        let e = call_against("http", |mut c| {
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"SSH-2.0-OpenSSH_9.6\r\n\r\n");
        })
        .unwrap_err();
        assert!(!nothing_answered(&e), "a non-HTTP reply: {e:?}");
    }

    #[test]
    fn a_5xx_response_is_an_answer() {
        let status = call_against("http", |mut c| {
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 503 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        })
        .expect("a status line is an answer, not a transport error");
        assert_eq!(status, 503);
    }
}
