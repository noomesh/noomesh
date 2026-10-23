// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The release manager's recovery rehearsal, without break-glass.
//!
//! By design there is no break-glass: recovery uses the way end users will
//! see. The CLI never signs with the controller's shared secret, so
//! every recovery has to work on the ordinary path. This suite drives the
//! BUILT binary through each case against a TLS mock gateway that asks for
//! a client certificate — the only transport an operator certificate is
//! presented on — and records every request:
//!
//! 1. **The operator certificate is lost** (deleted, or expired): the
//!    login still works → `pki issue-client <you> --force` → `pki
//!    revoke-client <you> --others` → a posture write works again.
//! 2. **The admin password is lost, the account locked or disabled, or the
//!    admin row is gone**: `security admin-password reset` on the
//!    controller host writes the account through the database (a fake
//!    `docker` here records the SQL) and logs the CLI in with the new
//!    password → `issue-client` → a posture write works.
//!
//! In every case the controller and fleet secrets — and the old opt-in —
//! are SET in the environment, and the assertion is that not one request
//! the gateway sees carries an HMAC bearer.

#[path = "common/scratch_dir.rs"]
mod scratch_dir;
use scratch_dir::ScratchDir;

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

// ── the TLS mock gateway ────────────────────────────────────────────────

/// Accepts any client certificate (or none) and remembers it: the mock is
/// a recorder, the gateway's own tests judge the leaf.
#[derive(Debug)]
struct AnyClientCert(Arc<rustls::crypto::CryptoProvider>);

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// One request the mock gateway received.
#[derive(Debug, Clone)]
struct Seen {
    /// `METHOD /path`
    line: String,
    auth: Option<String>,
    /// sha256 hex of the client certificate presented on the connection.
    cert: Option<String>,
    body: String,
}

struct Gateway {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Gateway {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(b))
}

/// A server leaf for 127.0.0.1, signed by the CA `noo security pki init`
/// made, so the CLI verifies it against `$NOO_TLS_CA` like a real gateway.
fn server_leaf(pki: &Path) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ca_key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(pki.join("ca.key")).unwrap()).unwrap();
    let ca_issuer = rcgen::Issuer::from_ca_cert_pem(&std::fs::read_to_string(pki.join("ca.crt")).unwrap(), ca_key).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca_issuer).unwrap();
    (cert.der().clone(), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
}

/// The gateway's half of an earlier release, as far as the CLI can see it: a
/// login mints `jwt-<user>`; registering, minting a bound token, writing
/// posture and revoking all need the client certificate on the connection;
/// the bound token is `bound-<cert>` and only it writes posture.
fn start_gateway(pki: &Path) -> Gateway {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (cert, key) = server_leaf(pki);
    let cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(Arc::new(AnyClientCert(provider)))
        .with_single_cert(vec![cert], key)
        .unwrap();
    let cfg = Arc::new(cfg);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (seen2, stop2) = (seen.clone(), stop.clone());
    std::thread::spawn(move || {
        while !stop2.load(Ordering::SeqCst) {
            let Ok((tcp, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            tcp.set_nonblocking(false).ok();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
            let Ok(conn) = rustls::ServerConnection::new(cfg.clone()) else { continue };
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break;
                    }
                }
                match tls.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            if buf.is_empty() {
                continue; // a handshake that went nowhere (a refused client)
            }
            let cert = tls.conn.peer_certificates().and_then(|c| c.first()).map(|c| sha256_hex(c.as_ref()));
            let raw = String::from_utf8_lossy(&buf).to_string();
            let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
            let first = head.lines().next().unwrap_or("");
            let mut parts = first.split(' ');
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").split('?').next().unwrap_or("").to_string();
            let auth = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .map(|l| l[l.find(':').unwrap() + 1..].trim().to_string());
            let login = auth.as_deref().is_some_and(|a| a.starts_with("Bearer jwt-"));
            let bound = match (&cert, auth.as_deref()) {
                (Some(c), Some(a)) => a == format!("Bearer bound-{}", &c[..16]),
                _ => false,
            };
            let user = auth.as_deref().and_then(|a| a.strip_prefix("Bearer jwt-")).unwrap_or("alice").to_string();
            let (status, extra, out): (u16, &str, String) = match (method.as_str(), path.as_str()) {
                ("POST", "/auth/token") => {
                    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
                    let u = v["username"].as_str().unwrap_or("").to_string();
                    (200, "Set-Cookie: noo_refresh=r1; HttpOnly; Path=/api/auth\r\n",
                     format!(r#"{{"access_token":"jwt-{u}","token_type":"bearer","expires_in":900,"refresh_ttl_days":30}}"#))
                }
                ("GET", "/auth/me") => (200, "", format!(r#"{{"sub":"{user}","scopes":["read","write","admin"],"role":"admin"}}"#)),
                ("POST", "/api/security/operator-certs/register") if cert.is_some() && login => {
                    (200, "", format!(r#"{{"status":"registered","operator":"{user}","thumbprint":"{}","already":false}}"#, cert.clone().unwrap()))
                }
                ("POST", "/api/security/operator-token") if cert.is_some() && login => (
                    200,
                    "",
                    format!(r#"{{"access_token":"bound-{}","token_type":"Bearer","expires_in":300}}"#, &cert.clone().unwrap()[..16]),
                ),
                ("POST", "/api/security/posture") if bound => (200, "", body.to_string()),
                ("POST", "/api/security/operator-certs/revoke") if bound => (200, "", r#"{"status":"ok","revoked":1}"#.to_string()),
                ("POST", _) if path.starts_with("/api/security/") => {
                    (403, "", r#"{"detail":"operator certificate + bound token required"}"#.to_string())
                }
                _ => (404, "", r#"{"detail":"not served by this mock"}"#.to_string()),
            };
            seen2.lock().unwrap().push(Seen { line: format!("{method} {path}"), auth, cert, body: body.to_string() });
            let resp = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{out}",
                out.len()
            );
            let _ = tls.write_all(resp.as_bytes());
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    Gateway { url: format!("https://127.0.0.1:{port}"), seen, stop }
}

// ── the operator's box ──────────────────────────────────────────────────

/// The controller as the CLI sees it: a PKI dir with a CA, a config dir for
/// the login and the operator certificate, a repo root with no secrets
/// store, and a fake `docker` that records what the host path runs.
/// Held while a test script is open for writing and while the CLI is
/// spawned (fork until exec).
///
/// Tests in this binary run on parallel threads. A forked child inherits
/// every fd open in the process until it execs, so a child forked while
/// another thread is writing `fakebin/docker` can hold that inode open for
/// writing; when the CLI then execs the script, exec fails with ETXTBSY
/// ("Text file busy"). That flaked the v0.2.89 promotion run with an empty
/// stderr. `Command::spawn` returns only once the child has exec'd (or
/// failed to), so holding this lock across both windows means no child is
/// ever between fork and exec while a script is open for writing.
static FORK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Install an executable test script under [`FORK_LOCK`], via a temp name
/// renamed over the target, so a script is never exec'd while it is open
/// for writing.
fn write_exe(path: &std::path::Path, body: &str) {
    let _held = FORK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::rename(&tmp, path).unwrap();
}

struct Box_ {
    root: ScratchDir,
}

impl Box_ {
    fn new(tag: &str) -> Self {
        let root = ScratchDir::new(&format!("noo-recovery-{tag}"));
        for d in ["pki", "home/creds", "repo", "fakebin"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        // The rehearsal runs on the CONTROLLER (`role::detect`: a checkout
        // with `.env` + `noomesh.yaml`), even when the machine running the
        // test is itself an enrolled node — `security pki` refuses a node.
        std::fs::write(root.join("repo/.env"), "NOO_ADMIN_USER=alice\n").unwrap();
        std::fs::write(root.join("repo/noomesh.yaml"), "{}\n").unwrap();
        // A fake `docker`: records argv and stdin, succeeds. The host path
        // (`docker exec -i <postgres> psql ... -f -`) is exercised up to
        // the SQL it writes; the SQL itself is pinned by host_access tests.
        write_exe(
            &root.join("fakebin/docker"),
            &format!(
                "#!/bin/sh\necho \"$@\" >> '{log}'\ncat >> '{sql}'\necho '-- end' >> '{sql}'\nexit 0\n",
                log = root.join("docker-argv.log").display(),
                sql = root.join("docker-stdin.sql").display()
            ),
        );
        let b = Box_ { root };
        let out = b.run(&["security", "pki", "init"], None);
        assert_eq!(out.status.code(), Some(0), "pki init: {}", String::from_utf8_lossy(&out.stderr));
        b
    }

    fn operator_dir(&self, account: &str) -> std::path::PathBuf {
        self.root.join("home/creds/operator").join(account)
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        self.run_env(args, stdin, &[])
    }

    fn run_env(&self, args: &[&str], stdin: Option<&str>, extra: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(bin());
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        for k in [
            "CONTROLLER_URL", "NOO_GATEWAY_URL", "NOO_TLS_CERT", "NOO_TOKEN", "NOO_OPERATOR", "NOO_OPERATOR_CERT_DIR",
            "NOO_INSTANCE", "XDG_CONFIG_HOME", "PGCONTAINER", "POSTGRES_USER", "POSTGRES_DB",
        ] {
            cmd.env_remove(k);
        }
        let path = format!("{}:{}", self.root.join("fakebin").display(), std::env::var("PATH").unwrap_or_default());
        cmd.env("PATH", path)
            .env("HOME", self.root.join("home"))
            .env("NOO_REPO_ROOT", self.root.join("repo"))
            .env("NOO_PKI_DIR", self.root.join("pki"))
            .env("NOO_TLS_CA", self.root.join("pki/ca.crt"))
            .env("NOO_CREDENTIALS_FILE", self.root.join("home/creds/credentials.json"))
            // The bait. A CLI that reached for any of these would sign with it.
            .env("NOO_CONTROLLER_SECRET", "controller-bait")
            .env("NOO_CLUSTER_SECRET", "fleet-bait")
            .env("NOO_BREAK_GLASS", "1")
            .env("NOO_AUTH_QUIET", "1");
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let mut child = {
            let _held = FORK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            cmd.spawn().expect("spawn noo")
        };
        if let Some(input) = stdin {
            child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        }
        child.wait_with_output().expect("noo exits")
    }
}

fn ok(out: &Output, what: &str) {
    assert_eq!(
        out.status.code(),
        Some(0),
        "{what}: stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `{actor}:{ts}:{32|64 hex}` — the only shape a shared-secret bearer has.
fn is_hmac(auth: &str) -> bool {
    let t = auth.trim().strip_prefix("Bearer ").unwrap_or(auth.trim());
    let parts: Vec<&str> = t.split(':').collect();
    parts.len() == 3
        && parts[1].chars().all(|c| c.is_ascii_digit())
        && matches!(parts[2].len(), 32 | 64)
        && parts[2].chars().all(|c| c.is_ascii_hexdigit())
}

fn assert_no_hmac(seen: &[Seen]) {
    assert!(!seen.is_empty(), "the gateway saw nothing");
    for s in seen {
        if let Some(a) = &s.auth {
            assert!(!is_hmac(a) && !a.contains("bait"), "{} carried a shared secret: {a}", s.line);
        }
    }
}

fn posture_writes(seen: &[Seen]) -> Vec<&Seen> {
    seen.iter().filter(|s| s.line == "POST /api/security/posture").collect()
}

// ── case 1: the operator certificate is lost ───────────────────────────

#[test]
fn a_lost_operator_certificate_is_recovered_without_the_shared_secret() {
    let b = Box_::new("lost-cert");
    let gw = start_gateway(&b.root.join("pki"));
    let g = gw.url.as_str();

    // The operator as they were: logged in, certificate issued, posture writes working.
    ok(&b.run(&["-G", g, "auth", "login", "alice", "--password-stdin"], Some("alices-password\n")), "login");
    ok(&b.run(&["-G", g, "security", "pki", "issue-client", "alice"], None), "issue-client");
    ok(&b.run(&["-G", g, "security", "posture", "set", "NOO_MCP_EXTERNAL_ENABLED", "1"], None), "posture set");
    let before = gw.seen();
    let first_cert = posture_writes(&before)[0].cert.clone().expect("the first write presented the certificate");

    // The rehearsal: the certificate directory is gone.
    std::fs::remove_dir_all(b.operator_dir("alice")).unwrap();

    // A posture write now is refused BEFORE anything is sent, naming the fix.
    let n = gw.seen().len();
    let refused = b.run(&["-G", g, "security", "posture", "set", "NOO_MCP_EXTERNAL_ENABLED", "0"], None);
    assert_eq!(refused.status.code(), Some(4), "{}", String::from_utf8_lossy(&refused.stderr));
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(err.contains("noo security pki issue-client alice"), "{err}");
    assert!(!err.contains("break-glass"), "{err}");
    assert_eq!(gw.seen().len(), n, "nothing may be sent without the certificate");

    // Recovery: a new certificate with the login, then revoke the lost one.
    let issued = b.run(&["-G", g, "security", "pki", "issue-client", "alice", "--force"], None);
    ok(&issued, "issue-client --force");
    assert!(String::from_utf8_lossy(&issued.stdout).contains("revoke-client alice --others"), "the guide names the next step");
    ok(&b.run(&["-G", g, "security", "pki", "revoke-client", "alice", "--others", "--yes"], None), "revoke-client --others");
    let set = b.run(&["-G", g, "security", "posture", "set", "NOO_MCP_EXTERNAL_ENABLED", "0"], None);
    ok(&set, "posture set after recovery");
    let said = format!("{}{}", String::from_utf8_lossy(&set.stdout), String::from_utf8_lossy(&set.stderr));
    assert!(said.to_lowercase().contains("restart the gateway to apply") && said.contains("noo stack restart gateway"), "{said}");

    let seen = gw.seen();
    assert_no_hmac(&seen);
    let writes = posture_writes(&seen);
    assert_eq!(writes.len(), 2, "{seen:#?}");
    let new_cert = writes[1].cert.clone().expect("the recovered write presented a certificate");
    assert_ne!(new_cert, first_cert, "the write after recovery uses the NEW certificate");
    assert_eq!(writes[1].auth.as_deref(), Some(format!("Bearer bound-{}", &new_cert[..16]).as_str()), "a token bound to it");
    // --others kept the new leaf and named the account.
    let revoke = seen.iter().find(|s| s.line == "POST /api/security/operator-certs/revoke").expect("revoke was sent");
    let body: serde_json::Value = serde_json::from_str(&revoke.body).unwrap();
    assert_eq!(body["operator"], "alice");
    assert!(body["keep"].as_str().is_some_and(|k| !k.is_empty()), "{body}");
    assert_eq!(revoke.cert.as_deref(), Some(new_cert.as_str()), "revoked with the new certificate's authority");
    // Every certificate-bearing call presented one.
    for s in &seen {
        if s.line.starts_with("POST /api/security/") {
            assert!(s.cert.is_some(), "{} went without the operator certificate", s.line);
        }
    }
}

// ── case 2: the password is lost (and the account locked, disabled or gone) ──

#[test]
fn a_lost_admin_password_is_recovered_on_the_host_without_a_login_or_the_secret() {
    let b = Box_::new("lost-password");
    let gw = start_gateway(&b.root.join("pki"));
    let g = gw.url.as_str();
    // No login is held: the password is lost.
    assert!(!b.root.join("home/creds/credentials.json").exists());

    let reset = b.run_env(
        &["-G", g, "security", "admin-password", "reset", "--yes", "--stdout"],
        None,
        &[("NOO_ADMIN_USER", "alice"), ("PGCONTAINER", "noo-postgres-rehearsal")],
    );
    ok(&reset, "admin-password reset");
    let stdout = String::from_utf8_lossy(&reset.stdout).to_string();
    // The host path: docker exec into the database container, SQL on stdin.
    let argv = std::fs::read_to_string(b.root.join("docker-argv.log")).expect("the host path ran docker");
    assert!(argv.contains("exec -i noo-postgres-rehearsal psql"), "{argv}");
    let sql = std::fs::read_to_string(b.root.join("docker-stdin.sql")).unwrap();
    for needle in ["INSERT INTO noo_users", "'alice'", "ON CONFLICT (username) DO UPDATE", "disabled = false", "locked_until = NULL", "role = 'admin'", "$2b$"] {
        assert!(sql.contains(needle), "the reset SQL lacks {needle}: {sql}");
    }
    // The new password is shown once, and the CLI logged in with it.
    let password = stdout
        .lines()
        .map(str::trim)
        .find(|l| l.len() >= 20 && !l.contains(' '))
        .expect("the new password is printed")
        .to_string();
    assert!(!sql.contains(&password), "the plaintext password never reaches psql");
    let login = gw.seen().into_iter().find(|s| s.line == "POST /auth/token").expect("the CLI logged in");
    let body: serde_json::Value = serde_json::from_str(&login.body).unwrap();
    assert_eq!(body["username"], "alice");
    assert_eq!(body["password"], password.as_str());
    assert!(b.root.join("home/creds/credentials.json").exists(), "the login is stored");

    // Then the ordinary path: a certificate, and a posture write.
    ok(&b.run(&["-G", g, "security", "pki", "issue-client", "alice"], None), "issue-client");
    ok(&b.run(&["-G", g, "security", "posture", "set", "NOO_MCP_EXTERNAL_ENABLED", "0"], None), "posture set");
    let seen = gw.seen();
    assert_no_hmac(&seen);
    assert_eq!(posture_writes(&seen).len(), 1, "{seen:#?}");
}

/// The reset is a host command: with no database container to reach it
/// fails, says where it must run, and changes nothing — it never falls
/// back to the network or to a secret.
#[test]
fn the_reset_without_host_access_fails_and_names_the_host() {
    let b = Box_::new("no-host");
    // A docker that cannot reach the container.
    write_exe(&b.root.join("fakebin/docker"), "#!/bin/sh\necho 'Error: No such container' >&2\nexit 1\n");
    let out = b.run_env(
        &["-G", "https://127.0.0.1:1", "security", "admin-password", "reset", "--yes", "--stdout"],
        None,
        &[("NOO_ADMIN_USER", "alice")],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // A signal exit (the CLI killed by SIGPIPE when the fake docker exits
    // before the SQL is written) is NEVER acceptable: it has no message.
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(out.status.signal(), None, "killed by a signal\nstdout: {stdout}\nstderr: {err}");
    }
    assert!(out.status.code().is_some_and(|c| c != 0), "status {:?}\nstdout: {stdout}\nstderr: {err}", out.status);
    assert!(
        err.contains("NOT changed") && err.contains("controller"),
        "status {:?}\nstdout: {stdout}\nstderr: {err}",
        out.status
    );
}
