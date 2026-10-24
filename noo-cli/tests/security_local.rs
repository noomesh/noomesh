// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! WP-B1 integration tests — the `security` LOCAL surface, driven through
//! the BUILT binary (`CARGO_BIN_EXE_noo`). No gateway, no docker, no Python:
//! everything here is filesystem + process, isolated under a temp dir via
//! `NOO_REPO_ROOT` (no repo `.env` leaks in) and `NOO_PKI_DIR`.
//!
//! The docker-restart + health-probe + auto-revert half of `rotate-all` is
//! exercised only up to the `--no-reload` boundary here (restarting real
//! containers is not CI material); its pure pieces (consumer mapping,
//! gateway-last ordering, backup/revert copy) are unit-tested in
//! `src/commands/security.rs`. The probe targets the fixed
//! `https://localhost:8080/health` (Python parity), so the mock-gateway
//! harness in gateway_integration.rs does not apply.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

#[path = "common/scratch_dir.rs"]
mod scratch_dir;
use scratch_dir::ScratchDir;

/// Fresh scratch dir per call; removed when the test ends, panicking or not.
fn scratch(tag: &str) -> ScratchDir {
    ScratchDir::new(&format!("noo-cli-secloc-{tag}"))
}

/// A scratch install root: a private (0600) empty `.env` marks it as an
/// install, so the scan reads it as one on every host. Without it the scan
/// would answer "nothing to scan" in CI and scan the node's own surfaces on
/// an enrolled box, and the finding set would depend on the machine.
fn install_repo(tag: &str) -> ScratchDir {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch(tag);
    let env = d.join(".env");
    std::fs::write(&env, "").expect("write .env");
    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).expect("chmod .env");
    d
}

/// Run the binary with an isolated environment: NOO_REPO_ROOT → empty
/// scratch (no .env), NOO_PKI_DIR → `pki`, and the scanned secrets vars
/// removed so the host environment can't leak into assertions.
fn run(pki: &PathBuf, repo: &PathBuf, args: &[&str]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("NOO_REPO_ROOT", repo)
        .env("NOO_PKI_DIR", pki)
        // The scan reads the docker config for inline registry logins; the
        // developer's real ~/.docker/config.json must not decide the
        // finding set, so the scratch repo stands in for it (no file).
        .env("DOCKER_CONFIG", repo);
    for var in [
        "NOO_JWT_SECRET",
        "NOO_CLUSTER_SECRET",
        "REDIS_PASSWORD",
        // Retired, but a developer's shell may still carry
        // them — they would add a LOW "Retired NATS Credential" row.
        "NATS_USER",
        "NATS_PASSWORD",
        "NOO_NATS_LEGACY_SHARED_CREDS",
        "NOO_NODE_AGENT_TOKEN",
        "NOO_TLS_CERT",
        // The scan now reports the gateway's transport, so the URL and the
        // trust anchor have to be deterministic too or the finding set
        // depends on the machine running the suite.
        "NOO_TLS_CA",
        "NOO_GATEWAY_URL",
        "CONTROLLER_URL",
        // Read by the scan's newer checks; a developer's shell must not
        // decide them either.
        "NOO_AUDIT_HMAC_KEY",
        "NOO_CONTROLLER_SECRET",
        "NOO_ADMIN_PASSWORD",
        "NOO_CSP",
        "NOO_MTLS_GATEWAY",
        "NOO_NATS_ALLOW_ANONYMOUS",
        "NOO_ALLOW_LOCAL_PYTHON_EXEC",
        "NOO_SANDBOX_ISOLATION",
        "NOO_NODE_AGENT_PRIVILEGED",
        "NOO_EXEC_APPROVAL_MODE",
    ] {
        cmd.env_remove(var);
    }
    cmd.output().expect("spawn noo")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn is_urlsafe(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ── generate-secret ─────────────────────────────────────────────────────

/// `--quiet` keeps only the captured value (CLI_STYLE_GUIDE rev 2 §7).
#[test]
fn generate_secret_quiet_prints_only_the_secret() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(&pki, &repo, &["--quiet", "security", "generate-secret"]);
    assert!(out.status.success());
    let so = stdout(&out);
    assert_eq!(so.lines().count(), 1, "stdout: {so}");
    assert!(so.trim().len() >= 32);
    assert!(stderr(&out).is_empty(), "stderr: {}", stderr(&out));
}

#[test]
fn generate_secret_default_is_token_urlsafe_32() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(&pki, &repo, &["security", "generate-secret"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    let s = s.trim();
    assert_eq!(s.len(), 43, "token_urlsafe(32) → 43 chars, got {s:?}");
    assert!(is_urlsafe(s));
}

#[test]
fn generate_secret_respects_length_and_type() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(&pki, &repo, &["security", "generate-secret", "jwt", "--length", "16"]);
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim().len(), 22, "token_urlsafe(16) → 22 chars");
}

#[test]
fn generate_secret_fernet_is_padded_44_chars() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(&pki, &repo, &["security", "generate-secret", "fernet"]);
    assert!(out.status.success());
    let s = stdout(&out);
    let s = s.trim();
    assert_eq!(s.len(), 44, "Fernet key is 44 chars, got {s:?}");
    assert!(s.ends_with('='), "Fernet key is PADDED urlsafe base64: {s:?}");
    assert!(is_urlsafe(&s[..43]));
}

#[test]
fn generate_secret_json_envelope() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(&pki, &repo, &["--json", "security", "generate-secret", "cluster"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).expect("json stdout");
    assert_eq!(v["type"], "cluster");
    assert_eq!(v["secret"].as_str().unwrap().len(), 43);
}

// ── scan ────────────────────────────────────────────────────────────────

#[test]
fn scan_reports_full_finding_set_on_bare_env() {
    let repo = install_repo("repo");
    let pki = scratch("pki"); // empty → no ca.crt
    let out = run(&pki, &repo, &["--json", "security", "scan"]);
    // a CRITICAL finding IS a failure. This used to assert
    // `success()` on "Python parity" grounds, which meant `noo security scan`
    // could not gate anything — a CI job or a pre-commit hook written from
    // the banner passed silently on a critical finding.
    assert!(!out.status.success(), "a CRITICAL finding must fail the command");
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).expect("json stdout");
    assert_eq!(v["criticals"], 2);
    let checks: Vec<&str> = v["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["check"].as_str().unwrap())
        .collect();
    // Severity-sorted, stable within a severity (Python's sorted()).
    // No "Gateway Transport" row: with nothing configured the CLI's gateway
    // default is https://localhost (the gateway has no plaintext listener),
    // so the loopback-plaintext carve-out is not reached. It used to be a
    // LOW row here, when the default fell back to http://localhost.
    assert_eq!(
        checks,
        vec![
            "JWT Secret",
            "Audit Key",
            "Cluster Secret",
            "Node Agent Token",
            "Controller Secret",
            "mTLS Enforcement",
            "Redis Password",
            "TLS",
            "Grafana Password",
            "Cluster PKI",
        ]
    );
    assert_eq!(v["issues"][0]["severity"], "CRITICAL");
}

/// End to end through the built binary: a cleartext gateway that
/// is not this machine is a CRITICAL scan finding, and any command that
/// would talk to it refuses instead of sending the bearer token.
#[test]
fn scan_flags_a_cleartext_remote_gateway_as_critical() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(
        &pki,
        &repo,
        &["--json", "--gateway", "http://gateway.example:8080", "security", "scan"],
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).expect("json stdout");
    let transport = v["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["check"] == "Gateway Transport")
        .expect("a Gateway Transport finding");
    assert_eq!(transport["severity"], "CRITICAL", "{transport}");
    assert!(
        transport["detail"].as_str().unwrap().contains("http://gateway.example:8080"),
        "the finding must name the URL: {transport}"
    );
}

/// The other half: the request path itself refuses. Before this change the
/// CLI happily built an agent for a cleartext (or unverifiable) gateway and
/// attached the stored credential to the request.
#[test]
fn a_cleartext_remote_gateway_is_refused_before_any_request() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(
        &pki,
        &repo,
        &["--json", "--gateway", "http://gateway.example:8080", "health"],
    );
    assert!(!out.status.success(), "the command must fail");
    let err = stderr(&out);
    assert!(err.contains("tls_untrusted"), "expected a tls_untrusted error, got: {err}");
    assert!(err.contains("TLS is required"), "the error must say why: {err}");
}

#[test]
fn scan_human_mode_lists_findings_and_flags_criticals_on_stderr() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(&pki, &repo, &["security", "scan"]);
    assert_eq!(out.status.code(), Some(1), "a CRITICAL finding must fail the command");
    let so = stdout(&out);
    // Boxed header (rev 2 §5), plain fallback `| Title |`.
    // The first line names what was scanned; the box follows it.
    assert!(so.lines().next().unwrap_or_default().starts_with("scanning "), "stdout: {so}");
    assert!(so.lines().take(4).any(|l| l.starts_with("| Security Scan")), "stdout: {so}");
    assert!(so.contains("Default or unset — set NOO_JWT_SECRET"));
    // Plain-mode glyph fallback (`x`) + the state word on the finding's row
    // (CLI_STYLE_GUIDE §4: colour is never the only signal).
    let row = so.lines().find(|l| l.contains("NOO_JWT_SECRET")).unwrap_or_default();
    assert!(row.trim_start().starts_with("x ") && row.contains("critical"), "stdout: {so}");
    // The critical count is narration → stdout (rev 2). The exit code says
    // the same thing to a script, which is the R30 half.
    assert!(so.contains("2 critical issue(s) found"), "stdout: {so}");
}

/// Security finding end to end: the exit code is the verdict, and `--strict` widens
/// it. Without this the scan could not gate a hook or a CI job at all.
#[test]
fn scan_exit_code_is_the_verdict_and_strict_widens_it() {
    let repo = install_repo("repo");
    let pki = scratch("pki");

    // A bare env has a CRITICAL (the default JWT secret) → 1.
    assert_eq!(run(&pki, &repo, &["security", "scan"]).status.code(), Some(1));

    // A full-marks host → 0 in BOTH modes. Without this half, `--strict`
    // would be a permanent red and nobody could gate on it. Same setup as
    // `scan_clean_env_reports_no_issues`.
    let clean_repo = install_repo("clean-repo");
    let clean_pki = scratch("clean-pki");
    assert!(run(&clean_pki, &clean_repo, &["security", "pki", "init"]).status.success());
    let clean = |args: &[&str]| {
        let mut cmd = Command::new(bin());
        cmd.args(args)
            .env("NOO_REPO_ROOT", &clean_repo)
            .env("NOO_PKI_DIR", &clean_pki)
            .env("NOO_JWT_SECRET", "not-the-default")
            .env("NOO_CLUSTER_SECRET", "x")
            .env("REDIS_PASSWORD", "x")
            .env("NOO_NODE_AGENT_TOKEN", "x")
            .env("NOO_TLS_CERT", "/tmp/cert.pem")
            // Added on dev while this branch was open. A
            // full-marks host has to satisfy every check there is, or the
            // --strict half of this test measures the newest check rather
            // than the exit code.
            .env("GRAFANA_PASSWORD", "a-generated-value-not-a-word")
        .env("NOO_AUDIT_HMAC_KEY", "a-generated-audit-key-value")
        .env("NOO_CONTROLLER_SECRET", "a-generated-controller-secret")
            .env("NOO_AUDIT_HMAC_KEY", "a-generated-audit-key-value")
            .env("NOO_CONTROLLER_SECRET", "a-generated-controller-secret")
            // Same rule for the 2026-09-28 checks: the registry-login check
            // must read a scratch docker config, not the developer's real
            // ~/.docker/config.json. (No NATS_PASSWORD: retired.)
            .env_remove("NATS_USER")
            .env_remove("NATS_PASSWORD")
            .env_remove("NOO_NATS_LEGACY_SHARED_CREDS")
            .env("DOCKER_CONFIG", &clean_repo);
        cmd.output().unwrap()
    };
    let ok = clean(&["security", "scan"]);
    assert_eq!(ok.status.code(), Some(0), "stdout: {}", stdout(&ok));
    let ok_strict = clean(&["security", "scan", "--strict"]);
    assert_eq!(
        ok_strict.status.code(), Some(0),
        "--strict must still pass a clean host: {}", stdout(&ok_strict)
    );

    // --strict must be a KNOWN flag, not fall through to "unknown command".
    let strict = run(&pki, &repo, &["security", "scan", "--strict"]);
    assert_eq!(strict.status.code(), Some(1));
    assert!(
        !stderr(&strict).contains("Unknown"),
        "--strict is not parsed: {}", stderr(&strict)
    );
}

#[test]
fn scan_clean_env_reports_no_issues() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    // Give the scan a full-marks environment (CA present via pki init).
    let out = run(&pki, &repo, &["security", "pki", "init"]);
    assert!(out.status.success(), "pki init: {}", stderr(&out));
    let mut cmd = Command::new(bin());
    cmd.args(["security", "scan"])
        .env("NOO_REPO_ROOT", &repo)
        .env("NOO_PKI_DIR", &pki)
        .env("NOO_JWT_SECRET", "not-the-default")
        .env("NOO_CLUSTER_SECRET", "x")
        .env("REDIS_PASSWORD", "x")
        .env("NOO_NODE_AGENT_TOKEN", "x")
        .env("NOO_TLS_CERT", "/tmp/cert.pem")
        .env("GRAFANA_PASSWORD", "a-generated-value-not-a-word")
        .env("NOO_AUDIT_HMAC_KEY", "a-generated-audit-key-value")
        .env("NOO_CONTROLLER_SECRET", "a-generated-controller-secret")
        // See scan_exit_code_is_the_verdict_and_strict_widens_it.
        .env_remove("NATS_USER")
        .env_remove("NATS_PASSWORD")
        .env_remove("NOO_NATS_LEGACY_SHARED_CREDS")
        .env("DOCKER_CONFIG", &repo);
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "stdout: {}", stdout(&out));
    // Clean, and honest about what it could not see: with no gateway to ask,
    // the gateway-posture rows are NOT CHECKED rather than counted as fine.
    assert!(stdout(&out).contains("No security issues found in what was checked"), "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("NOT CHECKED: gateway posture"), "stdout: {}", stdout(&out));
}

/// a value published in this repository is not a secret. The scan
/// used to report a clean posture on `changeme`, which is why the
/// placeholder survived in `.env.example`. End-to-end through the real
/// binary, because the unit test proves the rule and this proves the wiring.
///
/// No `pki init` here on purpose — that verb is controller-only, and this
/// assertion has nothing to do with the CA. The LOW "Cluster PKI" finding
/// it leaves behind is ignored; only the Grafana row and the CRITICAL count
/// are under test.
#[test]
fn scan_flags_a_published_grafana_placeholder_as_critical() {
    let repo = install_repo("repo");
    let pki = scratch("pki");

    let scan = |grafana: &str| {
        let mut cmd = Command::new(bin());
        cmd.args(["--json", "security", "scan"])
            .env("NOO_REPO_ROOT", &repo)
            .env("NOO_PKI_DIR", &pki)
            .env("NOO_JWT_SECRET", "not-the-default")
            .env("NOO_CLUSTER_SECRET", "x")
            .env("REDIS_PASSWORD", "x")
            .env("NOO_NODE_AGENT_TOKEN", "x")
            .env("NOO_TLS_CERT", "/tmp/cert.pem")
            .env("NOO_AUDIT_HMAC_KEY", "a-generated-audit-key-value")
            .env("NOO_CONTROLLER_SECRET", "a-generated-controller-secret")
            .env("GRAFANA_PASSWORD", grafana);
        let out = cmd.output().unwrap();
        // a CRITICAL finding now exits 1, so the status depends on
        // what this scan found. Assert it is one of the two verdicts rather
        // than dropping the check — an exit 2 (a crash) must still fail here,
        // and the per-case codes are asserted at the call sites below.
        assert!(
            matches!(out.status.code(), Some(0) | Some(1)),
            "unexpected exit {:?}: {}", out.status.code(), stderr(&out)
        );
        (out.status.code(), serde_json::from_str::<serde_json::Value>(stdout(&out).trim()).expect("json stdout"))
    };
    let grafana_row = |v: &serde_json::Value| -> Option<serde_json::Value> {
        v["issues"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["check"] == "Grafana Password")
            .cloned()
    };

    let (code, v) = scan("changeme");
    let row = grafana_row(&v).unwrap_or_else(|| panic!("no Grafana finding: {v}"));
    assert_eq!(row["severity"], "CRITICAL", "{v}");
    assert!(
        row["detail"].as_str().unwrap().contains("published placeholder"),
        "{v}"
    );
    assert_eq!(v["criticals"], 1, "{v}");
    // and the exit code says so too, so a CI gate sees it.
    assert_eq!(code, Some(1), "a CRITICAL finding must fail the command: {v}");
    assert_eq!(v["ok"], false, "{v}");

    // The complement, so a check that silently stopped running cannot pass
    // this test by producing no findings at all.
    let (code, v) = scan("a-generated-value-not-a-word");
    assert!(grafana_row(&v).is_none(), "a generated password must not be flagged: {v}");
    assert_eq!(v["criticals"], 0, "{v}");
    // Only a LOW "Cluster PKI" is left (no `pki init` here, on purpose), and
    // LOW is not a failure in the default mode.
    assert_eq!(code, Some(0), "{v}");
}

// ── pki rotate-all ──────────────────────────────────────────────────────

/// Full local rotate-all pass: init CA → issue a soon-expiring node cert →
/// rotate-all --no-reload. Asserts the leaf was re-issued (new validity,
/// same subject/SAN profile), the CA was NOT rotated, and a backup of the
/// old cert+key was kept.
#[test]
fn rotate_all_reissues_expiring_leaf_and_keeps_backup() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    assert!(run(&pki, &repo, &["security", "pki", "init"]).status.success());
    assert!(run(
        &pki,
        &repo,
        &["security", "pki", "issue", "n1", "10.0.0.1", "--days", "10"]
    )
    .status
    .success());

    let ca_before = std::fs::read(pki.join("ca.crt")).unwrap();
    let leaf_path = pki.join("nodes/n1/node.crt");
    let leaf_before = std::fs::read(&leaf_path).unwrap();

    // fu72 #2: without --no-deliver a remote node cert now gets a delivery
    // attempt, and an UNDELIVERED result is a nonzero exit — rotated
    // without delivered stopped being a success story. This sandbox has no
    // gateway and no inventory, so --no-deliver is the honest local mode.
    let out = run(
        &pki,
        &repo,
        &["security", "pki", "rotate-all", "--no-reload", "--no-deliver", "--force"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // Terminal first (rev 2): narration and the results table are all stdout.
    let so = stdout(&out);
    assert!(so.contains("1 certificate(s) expiring within 30 days"), "stdout: {so}");
    assert!(so.contains("nodes/n1/node.crt"), "stdout: {so}");
    assert!(so.to_lowercase().contains("rotated"), "stdout: {so}");
    // rev 2.1: the close line is sentence case ("not delivered"), the backup
    // path is a muted note.
    assert!(so.contains("not delivered"), "must say the certs did not reach the node: {so}");
    assert!(so.to_lowercase().contains("backup kept at"), "stdout: {so}");

    // Leaf re-issued in place; CA untouched.
    assert_ne!(std::fs::read(&leaf_path).unwrap(), leaf_before, "leaf must be re-issued");
    assert_eq!(std::fs::read(pki.join("ca.crt")).unwrap(), ca_before, "CA must never rotate");

    // New validity pushes it out of the expiring window (~90 days).
    let status = run(&pki, &repo, &["--json", "security", "pki", "status"]);
    let v: serde_json::Value = serde_json::from_str(stdout(&status).trim()).unwrap();
    let leaf = v["certs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "nodes/n1/node.crt")
        .expect("leaf in status");
    assert!(
        leaf["days_left"].as_i64().unwrap() > 30,
        "rotated leaf should have ~90 days: {leaf}"
    );

    // Backup dir holds the ORIGINAL cert + key.
    let backup = std::fs::read_dir(&pki)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with(".rotate-backup-"))
                .unwrap_or(false)
        })
        .expect("backup dir created");
    assert_eq!(
        std::fs::read(backup.join("nodes/n1/node.crt")).unwrap(),
        leaf_before,
        "backup carries the pre-rotation cert"
    );
    assert!(backup.join("nodes/n1/node.key").exists());
}

#[test]
fn rotate_all_json_without_yes_is_refused() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    assert!(run(&pki, &repo, &["security", "pki", "init"]).status.success());
    assert!(run(
        &pki,
        &repo,
        &["security", "pki", "issue", "n1", "10.0.0.1", "--days", "10"]
    )
    .status
    .success());
    // Agent-first confirm contract: --json never prompts; without --yes /
    // --force it errors out with confirmation_required, exit 1.
    let out = run(&pki, &repo, &["--json", "security", "pki", "rotate-all", "--no-reload"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("confirmation_required"), "stderr: {err}");
    // Nothing rotated.
    let leaf = pki.join("nodes/n1/node.crt");
    let status = run(&pki, &repo, &["--json", "security", "pki", "status"]);
    let v: serde_json::Value = serde_json::from_str(stdout(&status).trim()).unwrap();
    let days = v["certs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "nodes/n1/node.crt")
        .unwrap()["days_left"]
        .as_i64()
        .unwrap();
    assert!(days <= 10, "cert must be untouched, days_left={days}");
    assert!(leaf.exists());
}

#[test]
fn rotate_all_with_nothing_expiring_is_a_noop() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    assert!(run(&pki, &repo, &["security", "pki", "init"]).status.success());
    assert!(run(&pki, &repo, &["security", "pki", "issue", "n1", "10.0.0.1"]) // 90d default
        .status
        .success());
    let out = run(&pki, &repo, &["security", "pki", "rotate-all", "--no-reload", "--force"]);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("+ No certificates expiring within 30 days"),
        "stdout: {}",
        stdout(&out)
    );
    // JSON shape for the no-op path.
    let out = run(
        &pki,
        &repo,
        &["--json", "security", "pki", "rotate-all", "--no-reload", "--yes"],
    );
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["expiring"].as_array().unwrap().len(), 0);
}

#[test]
fn rotate_all_unknown_flag_is_a_usage_error() {
    // Unknown flags → Unhandled → a native USAGE error (exit 2) that
    // prints the command's own usage. It used to fall through to the
    // Python passthrough and complain about a missing `noo-py`, which was
    // never the operator's actual problem (2026-09-03).
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let mut cmd = Command::new(bin());
    cmd.args(["security", "pki", "rotate-all", "--bogus"])
        .env("NOO_REPO_ROOT", &repo)
        .env("NOO_PKI_DIR", &pki)
        .env("NOO_PY_CLI", "/nonexistent/noo-py")
        .env("PATH", "/usr/bin:/bin");
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("did not understand these arguments"), "stderr: {err}");
    assert!(err.contains("usage: noo security pki rotate-all"), "stderr: {err}");
    assert!(!err.contains("Python"), "the Python complaint is gone: {err}");
}

// ── trust-ca ────────────────────────────────────────────────────────────

#[test]
fn trust_ca_missing_file_exits_1_with_hint() {
    let repo = install_repo("repo");
    let pki = scratch("pki"); // no ca.crt
    let out = run(&pki, &repo, &["security", "trust-ca"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("CA cert not found"), "stderr: {err}");
    assert!(err.contains("noo security pki init"), "stderr: {err}");
}

#[test]
fn untrust_ca_json_without_yes_is_refused() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(&pki, &repo, &["--json", "security", "untrust-ca"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("confirmation_required"));
}

#[test]
fn untrust_ca_piped_stdin_without_yes_is_refused() {
    // Non-TTY stdin must error out instead of blocking (the no-hang
    // contract) — this test itself IS the non-TTY caller.
    let repo = install_repo("repo");
    let pki = scratch("pki");
    let out = run(&pki, &repo, &["security", "untrust-ca"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).to_lowercase().contains("confirmation required: pass --yes"));
}

/// fu72 #2: DEFAULT rotate-all attempts delivery for a remote node cert; in
/// an environment with no gateway and no inventory that is an UNDELIVERED
/// outcome, and the exit code says so — the pre-Batch-C behavior (print
/// "rotated", exit 0, node keeps its old cert) was the self-soothing lie.
#[test]
fn rotate_all_without_delivery_rails_exits_nonzero() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    assert!(run(&pki, &repo, &["security", "pki", "init"]).status.success());
    assert!(run(&pki, &repo, &["security", "pki", "issue", "n1", "10.0.0.1", "--days", "10"])
        .status
        .success());
    let out = run(&pki, &repo, &["security", "pki", "rotate-all", "--no-reload", "--force"]);
    assert_eq!(out.status.code(), Some(1), "undelivered must not exit 0; stderr: {}", stderr(&out));
    // Per-node delivery outcome is narration: stdout (rev 2).
    let so = stdout(&out);
    assert!(so.contains("UNDELIVERED"), "stdout: {so}");
}

// ── the signing-key rollout: who it is for, and what it will not claim ────
//
// Both cases below came off a live host8 walk on 2026-09-12.

/// A gateway that cannot be reached must not read as an empty fleet.
///
/// `fleet_nodes_from_registry` returns an empty vec on any transport
/// trouble, so enumerating from the registry — which is the fix for the
/// forgotten-node bug — introduced a second way to be wrong: with no
/// registry there are no targets, no failures, and the command would have
/// closed with "0 node(s) verify bundles against the fleet signing key" and
/// exit 0. That is a clean bill of health for a fleet nobody looked at.
#[test]
fn rotate_signing_key_refuses_to_report_a_rollout_it_could_not_enumerate() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    assert!(run(&pki, &repo, &["security", "pki", "init"]).status.success());

    // Port 1 on loopback: nothing listens, and it is not a hostname lookup,
    // so this is a connection refusal rather than a DNS timeout.
    let mut cmd = Command::new(bin());
    cmd.args(["--json", "--gateway", "http://localhost:1", "security", "pki",
              "rotate-signing-key", "--deliver-only", "--yes"])
        .env("NOO_REPO_ROOT", &repo)
        .env("NOO_PKI_DIR", &pki);
    for var in ["NOO_TLS_CA", "NOO_GATEWAY_URL", "CONTROLLER_URL"] {
        cmd.env_remove(var);
    }
    let out = cmd.output().expect("spawn noo");

    assert!(
        !out.status.success(),
        "an unenumerable fleet reported success:\nstdout: {}\nstderr: {}",
        stdout(&out), stderr(&out)
    );
    let all = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        all.contains("gateway_unreachable") || all.contains("registry"),
        "the failure must name WHY it refused: {all}"
    );
    // And it must not have claimed a rollout in the same breath.
    assert!(
        !all.contains("verify bundles against the fleet signing key"),
        "a refusal must not also report a successful rollout: {all}"
    );
}

/// `noo cluster forget` must not leave key material that later reads as a
/// node.
///
/// This is the ROOT of the host8 finding: `forget` removed the DB row and
/// left `<pki>/nodes/host8` on disk, so every reader that enumerated the
/// directory saw a node the registry had never heard of. The readers are
/// fixed; this closes the source. Archived rather than deleted — `forget`
/// is a registration operation, not a shredder, and this is a private key.
#[test]
fn forgetting_a_node_archives_its_key_material_instead_of_orphaning_it() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    assert!(run(&pki, &repo, &["security", "pki", "init"]).status.success());
    assert!(run(&pki, &repo, &["security", "pki", "issue", "host8", "10.0.0.9"])
        .status.success());
    let node_dir = pki.join("nodes/host8");
    assert!(node_dir.join("node.crt").is_file(), "premise: the cert exists");
    let key_before = std::fs::read(node_dir.join("node.key")).expect("node.key");

    // `forget` calls the gateway first. It is unreachable here, so the
    // command exits non-zero — and the archive must still not happen, or a
    // failed forget would destroy material for a node that is still
    // registered. Assert exactly that, then drive the local half directly.
    let mut cmd = Command::new(bin());
    cmd.args(["--gateway", "http://localhost:1", "cluster", "forget", "host8", "-y"])
        .env("NOO_REPO_ROOT", &repo)
        .env("NOO_PKI_DIR", &pki);
    for var in ["NOO_TLS_CA", "NOO_GATEWAY_URL", "CONTROLLER_URL"] {
        cmd.env_remove(var);
    }
    let out = cmd.output().expect("spawn noo");
    assert!(!out.status.success(), "a forget against a dead gateway must fail");
    assert!(
        node_dir.is_dir(),
        "a FAILED forget archived the key material of a still-registered node"
    );
    assert_eq!(
        std::fs::read(node_dir.join("node.key")).unwrap(), key_before,
        "the key was modified by a failed forget"
    );
}

/// One-shot mock gateway: serve a single canned response, then stop.
/// (`gateway_integration.rs` has the general harness; this suite is
/// otherwise gateway-free and needs exactly one reply.)
fn mock_once(body: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        listener.set_nonblocking(true).ok();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    sock.set_nonblocking(false).ok();
                    sock.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = sock.write_all(resp.as_bytes());
                    let _ = sock.flush();
                    return;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline { return }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    (port, h)
}

/// The success path of the same rule: a forget that the gateway ACCEPTS
/// must move the node's key material out of `<pki>/nodes/`, so nothing that
/// enumerates that directory can see it as a node again.
#[test]
fn a_successful_forget_moves_the_key_material_out_of_the_nodes_directory() {
    let repo = install_repo("repo");
    let pki = scratch("pki");
    assert!(run(&pki, &repo, &["security", "pki", "init"]).status.success());
    assert!(run(&pki, &repo, &["security", "pki", "issue", "host8", "10.0.0.9"])
        .status.success());
    let node_dir = pki.join("nodes/host8");
    assert!(node_dir.join("node.key").is_file(), "premise: material exists");

    let (port, h) = mock_once(r#"{"ok":true,"enrollments_revoked":1}"#);
    let mut cmd = Command::new(bin());
    cmd.args(["--json", "--gateway", &format!("http://localhost:{port}"),
              "cluster", "forget", "host8", "-y"])
        .env("NOO_REPO_ROOT", &repo)
        .env("NOO_PKI_DIR", &pki)
        .env("NOO_CLUSTER_SECRET", "test-secret");
    for var in ["NOO_TLS_CA", "NOO_GATEWAY_URL", "CONTROLLER_URL"] {
        cmd.env_remove(var);
    }
    let out = cmd.output().expect("spawn noo");
    let _ = h.join();
    assert!(out.status.success(), "stdout: {}\nstderr: {}", stdout(&out), stderr(&out));

    // THE POINT: `<pki>/nodes/host8` is gone, so the directory and the
    // registry no longer disagree. This is what turned a forgotten node
    // into a permanent phantom straggler.
    assert!(
        !node_dir.exists(),
        "forget left key material at {} — it will read as a node to anything walking nodes/*",
        node_dir.display()
    );
    // ARCHIVED, not shredded: `forget` is a registration operation, and
    // this is a private key. The archive is dot-prefixed so it cannot be
    // mistaken for a node directory.
    let archives: Vec<String> = std::fs::read_dir(&pki).unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".forgotten-host8-"))
        .collect();
    assert_eq!(archives.len(), 1, "expected one archive, found {archives:?}");
    assert!(
        pki.join(&archives[0]).join("node.key").is_file(),
        "the archive does not contain the key — this was a delete, not a move"
    );
    // And a scripted caller is told where it went.
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).expect("json");
    assert!(
        v["pki_archived"].as_str().is_some_and(|p| p.contains(".forgotten-host8-")),
        "the json envelope does not report the archive path: {v}"
    );
}
