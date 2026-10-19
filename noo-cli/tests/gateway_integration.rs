// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Gateway integration tests — the request/parse/exit seam.
//!
//! The unit tests and `smoke.sh` are gateway-FREE (dispatch, parsing, the
//! standalone contract). This suite closes the one seam they can't reach:
//! driving the BUILT binary against a live HTTP gateway and asserting that
//! `src/http.rs::request` maps (transport / status / body) → the typed exit
//! codes agents branch on, and that `src/auth.rs::bearer` attaches the HMAC
//! bearer.
//!
//! Self-contained: an in-process mock gateway (`std::net::TcpListener`,
//! ephemeral port, canned HTTP/1.1 responses) + the compiled binary via
//! `CARGO_BIN_EXE_noo`. No Python, no external tools, no real stack — so it
//! runs under plain `cargo test` in CI. Deferred
//! breadth: POST/PUT/DELETE, streaming, per-command envelopes.

#[path = "common/scratch_dir.rs"]
mod scratch_dir;
use scratch_dir::ScratchDir;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Path to the compiled `noo` binary (provided by Cargo for integration tests).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_noo")
}

/// A mock gateway that serves `count` requests with one canned response,
/// capturing each raw request. Join the handle to retrieve the captures.
struct Mock {
    port: u16,
    handle: JoinHandle<Vec<String>>,
}

impl Mock {
    /// Bind an ephemeral port and serve `count` connections the same response.
    fn start(status: u16, reason: &str, ctype: &str, body: &str, count: usize) -> Mock {
        Mock::start_seq(vec![http_response(status, reason, ctype, body); count])
    }

    /// Serve one pre-rendered HTTP response per connection, in order —
    /// for poll-loop commands whose successive fetches must differ
    /// (e.g. `memory embed-status --watch`: running → running → idle).
    fn start_seq(responses: Vec<String>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut captured = Vec::new();
            // Bounded accept. A test whose command makes FEWER requests than
            // the mock was primed for used to hang here forever on the next
            // blocking accept() — in CI that is a job-timeout, not a test
            // failure, and it took a bisect to find. Poll instead, and give
            // up after ACCEPT_TIMEOUT so `requests()` returns what actually
            // arrived and the case fails on its own assertion.
            const ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);
            listener.set_nonblocking(true).ok();
            for response in responses {
                let deadline = std::time::Instant::now() + ACCEPT_TIMEOUT;
                let mut stream = loop {
                    match listener.accept() {
                        Ok((s, _)) => break Some(s),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if std::time::Instant::now() >= deadline {
                                break None;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break None,
                    }
                };
                let Some(stream) = stream.as_mut() else { break };
                stream.set_nonblocking(false).ok();
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                captured.push(read_request(stream));
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            captured
        });
        Mock { port, handle }
    }

    fn requests(self) -> Vec<String> {
        self.handle.join().expect("mock thread")
    }

}

/// Render a canned HTTP/1.1 response.
fn http_response(status: u16, reason: &str, ctype: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Canned 200 JSON response (the common case for sequences).
fn ok_json(body: &str) -> String {
    http_response(200, "OK", "application/json", body)
}

/// Read a full HTTP request: headers, then — when a Content-Length header is
/// present (POST/PUT bodies) — the body too, so tests can assert payloads and
/// the client never sees a reset while still writing.
fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut body_expected: Option<usize> = None;
    loop {
        // Do we have the full head yet? If so, how much body follows it?
        if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let len = *body_expected.get_or_insert_with(|| {
                let head = String::from_utf8_lossy(&buf[..head_end]);
                head.lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                    .unwrap_or(0)
            });
            if buf.len() >= head_end + 4 + len {
                break;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Run the binary with args, isolated from the dev machine's gateway env vars.
/// `--gateway` short-circuits URL resolution, so the child never reads `.env`
/// for the target; we still clear the URL/TLS vars for determinism.
fn run(args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for k in [
        "CONTROLLER_URL",
        "NOO_GATEWAY_URL",
        "NOO_TLS_CERT",
        "NOO_TLS_CA",
        "NOO_CLUSTER_SECRET",
        // The controller-local secret outranks the fleet one in every HMAC
        // the CLI signs; a dev box's value must not decide a case.
        "NOO_CONTROLLER_SECRET",
        // models-catalog governance + HF endpoint: the WP-A2 tests pin these
        // via extra_env; clear the dev machine's values for determinism.
        "NOO_MODEL_FILTER_MODE",
        "NOO_MODEL_VENDORS",
        "NOO_MODEL_TASKS",
        "HF_ENDPOINT",
        // skills-run local executor inputs — keep the dev machine's env out.
        "NOO_NODE_AGENT_URL",
        "NOO_NODE_AGENT_TOKEN",
        "NOO_SKILLS_DIR",
        "NOO_SKILLS_HOST_DIR",
        "NOO_REPO_ROOT",
        // Per-user CLI credentials : an explicit token
        // in the dev machine's environment would outrank everything the auth
        // tests set up.
        "NOO_TOKEN",
        // An operator certificate dir or account in the dev
        // machine's environment would decide every posture case.
        "NOO_OPERATOR_CERT_DIR",
        "NOO_OPERATOR",
    ] {
        cmd.env_remove(k);
    }
    // Point credential resolution at a path that does not exist, so a real
    // ~/.config/mesh/credentials.json on the dev machine can never leak into
    // a test run. Set BEFORE extra_env so cases can override it.
    cmd.env("NOO_CREDENTIALS_FILE", "/nonexistent/noo-test/credentials.json");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn noo")
}

/// Like `run`, but with `input` piped to the child's stdin (for
/// `--password-stdin`). Same env isolation as `run`.
fn run_with_stdin(args: &[&str], input: &str) -> Output {
    run_with_stdin_env(args, input, &[])
}

/// [`run_with_stdin`] plus extra environment (the auth-login cases need to
/// redirect `NOO_CREDENTIALS_FILE` at a temp path).
fn run_with_stdin_env(args: &[&str], input: &str, extra_env: &[(&str, &str)]) -> Output {
    use std::process::Stdio;
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for k in [
        "CONTROLLER_URL",
        "NOO_GATEWAY_URL",
        "NOO_TLS_CERT",
        "NOO_TLS_CA",
        "NOO_CLUSTER_SECRET",
        "NOO_CONTROLLER_SECRET",
        "NOO_TOKEN",
    ] {
        cmd.env_remove(k);
    }
    cmd.env("NOO_CREDENTIALS_FILE", "/nonexistent/noo-test/credentials.json");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn noo");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait noo")
}

fn gw(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// The per-command case helper: mock one gateway route (`method` + `path` →
/// `status` + JSON `body`), run the binary with `args`, assert the exit code
/// AND that the request actually hit the route, then return stdout for
/// envelope assertions. Makes adding a mocked-endpoint case per ported
/// command a ~10-line affair — extend the matrix freely.
fn case(method: &str, path: &str, status: u16, body: &str, args: &[&str], want_exit: i32) -> String {
    let mock = Mock::start(status, "Mock", "application/json", body, 1);
    let url = gw(mock.port);
    let mut argv = vec!["--gateway", url.as_str()];
    argv.extend_from_slice(args);
    let out = run(&argv, &[]);
    let reqs = mock.requests();
    assert_eq!(
        out.status.code(),
        Some(want_exit),
        "noo {args:?}: stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let req = reqs.first().expect("one captured request");
    let request_line = req.lines().next().unwrap_or("");
    assert!(
        request_line.starts_with(&format!("{method} {path}")),
        "noo {args:?}: expected `{method} {path}`, request line was: {request_line}"
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A port that is guaranteed closed (bind then drop) — for commands that must
/// fail BEFORE any HTTP request is attempted.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[test]
fn ok_json_body_exits_zero_and_formats() {
    let stdout = case("GET", "/health", 200, r#"{"status":"ok"}"#, &["health"], 0);
    // Plain rendering (a pipe): boxed header, then the kv block
    // (CLI_STYLE_GUIDE rev 2 §5: `+---+` box, Title Case labels/states).
    assert!(stdout.starts_with("+--"), "stdout was: {stdout}");
    assert!(stdout.lines().nth(1).unwrap_or("").starts_with("| Gateway"), "stdout was: {stdout}");
    assert!(stdout.contains("Status  Ok"), "stdout was: {stdout}");
}

#[test]
fn json_flag_passes_raw_body_through() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"healthy"}"#, 1);
    let out = run(&["--json", "--gateway", &gw(mock.port), "health"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("healthy"), "raw JSON expected on stdout, got: {stdout}");
}

#[test]
fn unauthorized_maps_to_exit_4() {
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"nope"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "health"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4), "401 must map to AuthFailed(4)");
}

#[test]
fn server_error_maps_to_exit_5() {
    // 5xx must map to RemoteError(5).
    case("GET", "/health", 503, r#"{"detail":"down"}"#, &["health"], 5);
}

#[test]
fn non_json_success_body_maps_to_exit_1() {
    let mock = Mock::start(200, "OK", "text/plain", "not json at all", 1);
    let out = run(&["--gateway", &gw(mock.port), "health"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(1), "200 + non-JSON must map to Generic(1)");
}

#[test]
fn unreachable_gateway_maps_to_exit_3() {
    // Bind then immediately drop → the port is closed, so connect refuses.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = run(&["--gateway", &gw(port), "health"], &[]);
    assert_eq!(out.status.code(), Some(3), "connection refused must map to GatewayUnreachable(3)");
}

// ── WP-A1: jobs — per-command envelope + exit-code cases ────────────────────

/// `jobs run`: POST /api/jobs/submit, then poll GET /api/jobs/{id}. The mock
/// serves the same body to both requests — it carries job_id (submit reply)
/// AND a terminal status (poll reply), so the run completes on the first poll.
#[test]
fn jobs_run_submits_polls_and_reports_completion() {
    let body = r#"{"job_id":"j1","status":"completed","result":"all done"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 2);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "run", "hello"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/jobs/submit"), "first request: {}", reqs[0]);
    assert!(reqs[1].starts_with("GET /api/jobs/j1"), "second request: {}", reqs[1]);
    // Narration ("job completed") and the result are both stdout (rev 2).
    let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.to_lowercase().contains("job completed"), "stdout: {stdout}");
    assert!(stdout.contains("all done"), "stdout: {stdout}");
}

/// `jobs run`: a terminal non-completed status must exit 1 (Python parity).
#[test]
fn jobs_run_failed_job_exits_one() {
    let body = r#"{"job_id":"j1","status":"failed","error":"boom"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 2);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "run", "hello"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(1), "failed job must exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("job failed: boom"), "stderr: {stderr}");
}

/// `jobs run --async`: submit only, print the job id, no poll.
#[test]
fn jobs_run_async_returns_job_id_without_polling() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"job_id":"j9"}"#, 1);
    let out = run(&["--json", "--gateway", &gw(mock.port), "jobs", "run", "hi", "--async"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(reqs.len(), 1, "async mode must not poll");
    assert!(String::from_utf8_lossy(&out.stdout).contains(r#"{"job_id":"j9"}"#));
}

/// `jobs status` (no --wait): single GET, pretty JSON, exit 0.
#[test]
fn jobs_status_fetches_single_job() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"job_id":"j1","status":"running"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "status", "j1"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(reqs[0].starts_with("GET /api/jobs/j1"), "request: {}", reqs[0]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("running"));
}

/// `jobs status --wait`: polls until terminal (immediately terminal here).
#[test]
fn jobs_status_wait_polls_to_terminal() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"job_id":"j1","status":"completed"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "status", "j1", "--wait"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("completed"));
}

/// `jobs submit`: POST /api/jobs/submit, human success line.
#[test]
fn jobs_submit_posts_and_prints_id() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"job_id":"j2"}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "jobs", "submit", "--type", "inference", "-p", "7"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(reqs[0].starts_with("POST /api/jobs/submit"), "request: {}", reqs[0]);
    // Terminal first (rev 2): confirmation + captured value + guidance on stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.to_lowercase().contains("job submitted: j2"), "stdout: {stdout}");
    assert!(stdout.lines().any(|l| l == "j2"), "captured value line missing: {stdout}");
    assert!(stdout.contains("noo jobs status j2 --wait"), "guidance missing: {stdout}");
}

/// `--quiet` keeps only the captured value: the bare job id, nothing else
/// (CLI_STYLE_GUIDE §7).
#[test]
fn jobs_submit_quiet_prints_only_the_id() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"job_id":"j9"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "--quiet", "jobs", "submit", "--type", "inference"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "j9\n");
    assert!(out.stderr.is_empty(), "stderr must be silent: {}", String::from_utf8_lossy(&out.stderr));
}

/// `jobs submit --type <unexecutable>`: the gateway rejects the type with
/// 400 + a message naming the valid ones. The CLI must surface exactly that
/// sentence (not the raw JSON body glued onto "gateway returned 400") and
/// keep the documented status→exit mapping: any non-2xx/non-auth → 5.
///
/// Regression: `--type test_run` used to be accepted, dispatched to a node
/// with no executor for it, and left to rot until the reaper.
#[test]
fn jobs_submit_unexecutable_type_reports_gateway_reason_and_exits_five() {
    let body = r#"{"error":"unknown job type 'smoke' — no executor can run it. Valid types: background_cache, background_graph, inference, model_download, tool_exec, test_run"}"#;
    let mock = Mock::start(400, "Bad Request", "application/json", body, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "jobs", "submit", "--type", "smoke"],
        &[],
    );
    let reqs = mock.requests();
    assert!(reqs[0].starts_with("POST /api/jobs/submit"), "request: {}", reqs[0]);
    assert_eq!(out.status.code(), Some(5));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.to_lowercase().contains("unknown job type 'smoke'"), "stderr: {err}");
    assert!(err.contains("Valid types:"), "stderr: {err}");
    assert!(!err.to_lowercase().contains("gateway returned 400"), "raw body leaked: {err}");
}

/// Same rejection in `--json` mode: the machine-readable envelope carries
/// the gateway's sentence, still exit 5.
#[test]
fn jobs_submit_rejection_json_envelope() {
    let body = r#"{"error":"unknown job type 'smoke' — no executor can run it. Valid types: inference"}"#;
    let mock = Mock::start(400, "Bad Request", "application/json", body, 1);
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "jobs", "submit", "--type", "smoke"],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5));
    let env: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stderr).trim()).expect("json envelope");
    assert_eq!(env["code"], "remote_error");
    assert!(env["error"].as_str().unwrap().contains("unknown job type"));
}

/// `jobs run --type <unexecutable>`: same gate on the submit-and-poll path,
/// and it must NOT poll a job that was never created.
#[test]
fn jobs_run_unexecutable_type_exits_five_without_polling() {
    let body = r#"{"error":"unknown job type 'smoke' — no executor can run it. Valid types: inference"}"#;
    let mock = Mock::start(400, "Bad Request", "application/json", body, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "jobs", "run", "hello", "--type", "smoke"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 1, "must not poll after a rejected submit");
    assert_eq!(out.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("unknown job type 'smoke'"));
}

/// A gateway-local type is accepted and comes back already running in the
/// gateway — no node, no queue. The CLI reports the id like any submit.
#[test]
fn jobs_submit_gateway_local_type_reports_running() {
    let body = r#"{"job_id":"t1","status":"running","executor":"gateway"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(
        &[
            "--gateway", &gw(mock.port), "jobs", "submit",
            "--type", "test_run", "--payload", r#"{"suite":"smoke"}"#,
        ],
        &[],
    );
    let reqs = mock.requests();
    assert!(reqs[0].contains(r#""type": "test_run""#), "request: {}", reqs[0]);
    assert!(reqs[0].contains(r#""suite": "smoke""#), "request: {}", reqs[0]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().any(|l| l == "t1"), "captured value line missing: {stdout}");
    assert!(stdout.to_lowercase().contains("job submitted: t1"), "stdout: {stdout}");
}

/// `jobs submit --payload` with invalid JSON: local error, exit 1, no request.
#[test]
fn jobs_submit_invalid_payload_exits_one() {
    let out = run(&["--gateway", "http://127.0.0.1:1", "jobs", "submit", "--payload", "{nope"], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Invalid JSON in --payload"));
}

/// `jobs history`: GET /api/jobs/history, table rendering.
#[test]
fn jobs_history_renders_table() {
    let body = r#"{"jobs":[{"job_id":"abc123","type":"inference","status":"completed","duration_ms":42}]}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "history", "-n", "5"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(reqs[0].starts_with("GET /api/jobs/history?limit=5"), "request: {}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("abc123") && stdout.contains("42ms"), "stdout: {stdout}");
}

/// `jobs cancel --yes`: DELETE /api/jobs/{id}.
#[test]
fn jobs_cancel_yes_deletes() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"message":"Cancelled j3"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "cancel", "j3", "--yes"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(reqs[0].starts_with("DELETE /api/jobs/j3"), "request: {}", reqs[0]);
    assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains("cancelled j3"));
}

/// `jobs cancel` without --yes on a non-TTY stdin: refuse to prompt, exit 1,
/// no request made (agent-first confirm contract).
#[test]
fn jobs_cancel_without_yes_refuses_on_pipe() {
    let out = run(&["--gateway", "http://127.0.0.1:1", "jobs", "cancel", "j3"], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("confirmation required"));
}

/// `jobs reprioritize`: POST /api/jobs/{id}/reprioritize.
#[test]
fn jobs_reprioritize_posts() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"ok"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "reprioritize", "j4", "8"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(reqs[0].starts_with("POST /api/jobs/j4/reprioritize"), "request: {}", reqs[0]);
    assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains("job j4 reprioritized to 8"));
}

/// `jobs scheduler`: GET /api/scheduler/status, pretty JSON.
#[test]
fn jobs_scheduler_fetches_status() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"paused":false,"queued":3}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "scheduler"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(reqs[0].starts_with("GET /api/scheduler/status"), "request: {}", reqs[0]);
    assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains("queued"));
}

/// `jobs pause` / `jobs resume`: POST /api/scheduler/{action}.
#[test]
fn jobs_pause_and_resume_post() {
    for action in ["pause", "resume"] {
        let mock = Mock::start(200, "OK", "application/json", r#"{}"#, 1);
        let out = run(&["--gateway", &gw(mock.port), "jobs", action], &[]);
        let reqs = mock.requests();
        assert_eq!(out.status.code(), Some(0), "action {action}");
        assert!(
            reqs[0].starts_with(&format!("POST /api/scheduler/{action}")),
            "request: {}",
            reqs[0]
        );
        assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains(&format!("scheduler {action}d")));
    }
}

/// `jobs drain` / `jobs undrain`: POST /api/scheduler/{action}/{node}.
#[test]
fn jobs_drain_and_undrain_post() {
    for action in ["drain", "undrain"] {
        let mock = Mock::start(200, "OK", "application/json", r#"{}"#, 1);
        let out = run(&["--gateway", &gw(mock.port), "jobs", action, "node-1"], &[]);
        let reqs = mock.requests();
        assert_eq!(out.status.code(), Some(0), "action {action}");
        assert!(
            reqs[0].starts_with(&format!("POST /api/scheduler/{action}/node-1")),
            "request: {}",
            reqs[0]
        );
        assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains(&format!("node node-1 {action}ed")));
    }
}

/// The shared status→exit-code mapping through a WP-A1 command: 401 → 4.
#[test]
fn jobs_history_unauthorized_maps_to_exit_4() {
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"nope"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "history"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4));
}

// ── WP-A6: config export-effective / config show ────────────────────────────

/// `config export-effective` fetches autonomy status + kb rules + kb grants
/// (three GETs, same canned body here) and renders the YAML snapshot.
#[test]
fn config_export_effective_renders_yaml_snapshot() {
    let body = r#"{"running":true,"locations_enabled":3,"locations":[{"name":"node_health"}],"rules":[],"grants":[]}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 3);
    let out = run(&["--gateway", &gw(mock.port), "config", "export-effective"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(reqs.len(), 3, "expected autonomy + kb rules + kb grants fetches");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for needle in ["generated_at:", "enabled: true", "locations_enabled: 3", "source_rules_db:", "role_grants:"] {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }
}

/// Best-effort composite: with the gateway down the Python CLI embeds
/// `{"error": …}` per fetch and still exits 0 — never gateway_unreachable.
#[test]
fn config_export_effective_tolerates_unreachable_gateway() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = run(&["--gateway", &gw(port), "config", "export-effective"], &[]);
    assert_eq!(out.status.code(), Some(0), "tolerant fetches must not exit non-zero");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("error"), "expected embedded error placeholders, got:\n{stdout}");
}

/// `--output/-o` writes the snapshot to a file instead of stdout.
#[test]
fn config_export_effective_writes_output_file() {
    let body = r#"{"running":false,"locations_enabled":0,"locations":[],"rules":[],"grants":[]}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 3);
    let path = std::env::temp_dir().join(format!("noo-test-effective-{}.yaml", std::process::id()));
    let out = run(
        &["--gateway", &gw(mock.port), "config", "export-effective", "-o", path.to_str().unwrap()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let written = std::fs::read_to_string(&path).expect("output file written");
    let _ = std::fs::remove_file(&path);
    assert!(written.contains("generated_at:"), "file content was:\n{written}");
    // Terminal first (CLI_STYLE_GUIDE rev 2 §2): the confirmation is stdout,
    // and the written path is the captured value on its own line.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Effective config written to"), "stdout was:\n{stdout}");
    assert!(stdout.lines().any(|l| l == path.to_str().unwrap()), "stdout was:\n{stdout}");
}

/// `config show` is LOCAL: reads the YAML at --config, no gateway involved.
#[test]
fn config_show_reads_local_yaml() {
    let path = std::env::temp_dir().join(format!("noo-test-show-{}.yaml", std::process::id()));
    std::fs::write(&path, "coordinator:\n  model: qwen3:8b\nrag:\n  top_k: 5\n").unwrap();
    let out = run(&["config", "show", "--config", path.to_str().unwrap()], &[]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.lines().any(|l| l.trim_start().starts_with("Config Path") && l.ends_with(&path.display().to_string())),
        "stdout was:\n{stdout}"
    );
    assert!(stdout.contains("qwen3:8b"), "stdout was:\n{stdout}");

    // --json: Python envelope {"config_path": …, **config}.
    let out = run(&["--json", "config", "show", "--config", path.to_str().unwrap()], &[]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--json stdout must be a JSON object");
    assert_eq!(v["config_path"].as_str(), path.to_str());
    assert_eq!(v["rag"]["top_k"].as_i64(), Some(5));
}

/// Missing explicit config file → clear LOCAL error (exit 1), never
/// gateway_unreachable (3) — `config show` has no gateway leg at all.
#[test]
fn config_show_missing_file_is_local_error() {
    let path = std::env::temp_dir().join(format!("noo-test-missing-{}.yaml", std::process::id()));
    let out = run(&["config", "show", "--config", path.to_str().unwrap()], &[]);
    assert_eq!(out.status.code(), Some(1), "missing local file must exit 1 (Generic)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Config file not found"), "stderr was:\n{stderr}");
}

// ── WP-A5: agents/channels/inference/prompt-skills envelope cases ──────────

#[test]
fn agents_collaborate_posts_and_renders_results() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"results":{"planner":"step plan"}}"#,
        1,
    );
    let out = run(
        &["--gateway", &gw(mock.port), "agents", "collaborate", "do a thing", "--roles", "planner"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        reqs[0].starts_with("POST /api/agents/collaborate "),
        "request was:\n{}",
        reqs[0]
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.to_lowercase().contains("planner"), "stdout was: {stdout}");
    assert!(stdout.contains("step plan"), "stdout was: {stdout}");
    assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains("collaboration complete"));
    assert!(reqs[0].contains("\"planner\""), "request was:\n{}", reqs[0]);
    assert!(!reqs[0].contains("\"mode\"") && !reqs[0].contains("workflow"), "ignored fields must not be sent:\n{}", reqs[0]);
}

#[test]
fn agents_collaborate_refuses_the_flags_the_gateway_ignored() {
    // Closed port: refusing happens before any request.
    for flag in ["-w", "--workflow", "-m", "--mode"] {
        let out = run(&["--gateway", "http://127.0.0.1:1", "agents", "collaborate", "t", flag, "x"], &[]);
        assert_eq!(out.status.code(), Some(2), "{flag}: stderr: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stderr).contains("no longer takes"), "{flag}");
    }
}

#[test]
fn agents_presence_lists_windows_by_addressable_name() {
    let body = r#"{"owner":"owner","idle_ttl_secs":86400,"sessions":[
        {"connection":"owner/claude-code-a1b2","label":"claude-code-a1b2","consumer":"user:laptop","display_name":"claude-code","opened_at":"2026-09-18T10:00:00Z","last_seen":"2026-09-18T10:05:00Z"},
        {"connection":"owner/cursor-9f8e","label":"cursor-9f8e","consumer":"user:laptop","display_name":null,"opened_at":"2026-09-18T09:00:00Z","last_seen":"2026-09-18T09:30:00Z"}]}"#;
    let stdout = case("GET", "/api/agents/presence ", 200, body, &["agents", "presence"], 0);
    // The addressable NAME is what the table is for — both windows, by name.
    assert!(stdout.contains("owner/claude-code-a1b2"), "stdout was: {stdout}");
    assert!(stdout.contains("owner/cursor-9f8e"), "stdout was: {stdout}");
    assert!(stdout.contains("2 window(s)"), "stdout was: {stdout}");
    // A window that did not say what it is shows as unknown (a dash cell),
    // not as a blank that reads as "nothing to say".
    let cursor = stdout.lines().find(|l| l.contains("owner/cursor-9f8e")).expect("cursor row");
    assert!(cursor.split_whitespace().any(|tok| tok == "-" || tok == "\u{2014}"), "row was: {cursor}");
}

#[test]
fn agents_presence_owner_flag_is_the_query_and_empty_is_not_an_error() {
    let stdout = case(
        "GET",
        "/api/agents/presence?owner=someone-else",
        200,
        r#"{"owner":"someone-else","idle_ttl_secs":86400,"sessions":[]}"#,
        &["agents", "presence", "--owner", "someone-else"],
        0,
    );
    assert!(stdout.contains("no live windows under someone-else"), "stdout was: {stdout}");
}

#[test]
fn agents_presence_refused_owner_exits_forbidden_not_empty() {
    // 403 is the gateway saying "not yours to list". It must surface as a
    // refusal, never as "nobody is online".
    let mock = Mock::start(403, "Forbidden", "application/json", r#"{"error":"'me' may list presence for its own account, not for 'them'"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "agents", "presence", "--owner", "them"], &[]);
    let _ = mock.requests();
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(err.contains("403"), "stderr: {err}");
    assert!(!stdout.contains("no live windows"), "a refusal rendered as an empty list:\n{stdout}");
}

#[test]
fn agents_peer_dispatch_posts_to_peer_task_path() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"task_id":"t-1","result_subject":"peer.result.t-1"}"#,
        1,
    );
    let out = run(
        &["--gateway", &gw(mock.port), "agents", "peer", "dispatch", "hermes", "summarize this"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        reqs[0].starts_with("POST /api/agents/peer/hermes/task "),
        "request was:\n{}",
        reqs[0]
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains("task dispatched to hermes"));
    assert!(stdout.contains("t-1"), "stdout was: {stdout}");
}

#[test]
fn channels_test_success_exits_zero() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"success":true}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "channels", "test", "whatsapp", "+1555", "-m", "hi"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/channels/test "), "request was:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains("test message sent via whatsapp"), "stdout was: {stdout}");
}

#[test]
fn channels_test_embedded_failure_exits_one() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"success":false,"error":"no adapter"}"#,
        1,
    );
    let out = run(&["--gateway", &gw(mock.port), "channels", "test", "whatsapp", "+1555"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(1), "2xx + success:false must exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no adapter"), "stderr was: {stderr}");
}

#[test]
fn inference_agent_posts_agent_run_and_renders() {
    // Reply shape from routes/agents.rs agent_run: {response, role}.
    let mock = Mock::start(200, "OK", "application/json", r#"{"response":"42","role":"general"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "inference", "agent", "meaning of life"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/agent/run "), "request was:\n{}", reqs[0]);
    // Only the fields the route reads are sent.
    assert!(!reqs[0].contains("max_iterations") && !reqs[0].contains("tools_enabled"), "request was:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("42"), "stdout was: {stdout}");
}

#[test]
fn inference_agent_refuses_flags_the_route_ignores() {
    for flag in [&["--max-iters", "3"][..], &["--no-tools"][..], &["-m", "x"][..]] {
        let mut args = vec!["--gateway", "http://127.0.0.1:1", "inference", "agent", "hi"];
        args.extend_from_slice(flag);
        let out = run(&args, &[]);
        assert_eq!(out.status.code(), Some(2), "{flag:?} must be refused, not ignored");
        assert!(String::from_utf8_lossy(&out.stderr).contains("no longer accepts"), "{flag:?}");
    }
}

#[test]
fn autonomy_enable_without_redis_is_not_reported_as_success() {
    // The gateway answers 503 {"error":..} when it cannot write the flag.
    let mock = Mock::start(503, "Service Unavailable", "application/json", r#"{"error":"Redis is not configured, so the autonomy flag cannot be set; nothing changed"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "autonomy", "enable"], &[]);
    let _ = mock.requests();
    assert_ne!(out.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("autonomy engine enabled"));
}

#[test]
fn autonomy_enable_with_confirmation_succeeds() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"enabled"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "autonomy", "enable"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn prompt_skills_create_posts_file_content() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("noo-cli-test-skill-{}.md", std::process::id()));
    std::fs::write(&path, "# skill body\n").unwrap();
    // The real reply of gateway-rust routes/settings.rs prompt_skills_create.
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"status":"created","name":"my-skill","path":"/skills/evolved/my-skill.md"}"#,
        1,
    );
    let out = run(
        &[
            "--gateway",
            &gw(mock.port),
            "prompt-skills",
            "create",
            "my-skill",
            "--file",
            path.to_str().unwrap(),
            "--tags",
            "a,b",
        ],
        &[],
    );
    let reqs = mock.requests();
    std::fs::remove_file(&path).ok();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/prompt-skills "), "request was:\n{}", reqs[0]);
    // Confirmation is narration on STDOUT (terminal first), plain glyph `+`.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("+ Created skill my-skill"), "stdout was: {stdout}");
}

#[test]
fn prompt_skills_decide_posts_the_decision_and_needs_exactly_one_verdict() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"id":7,"name":"my-skill","status":"promoted","decided_by":"olive","live":true}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "prompt-skills", "decide", "7", "--promote", "--reason", "read it"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/prompt-skills/proposals/7/decide "), "request was:\n{}", reqs[0]);
    let body: serde_json::Value = serde_json::from_str(reqs[0].split("\r\n\r\n").last().unwrap_or("").split("\n\n").last().unwrap_or("").trim()).unwrap_or_default();
    assert_eq!(body["decision"], "promote", "{}", reqs[0]);
    assert_eq!(body["reason"], "read it", "{}", reqs[0]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("Promoted 'my-skill'"));
    // Neither or both verdicts: a usage error before any request.
    for extra in [&["7"][..], &["7", "--promote", "--reject"]] {
        let mut argv = vec!["--gateway", "http://127.0.0.1:9", "prompt-skills", "decide"];
        argv.extend_from_slice(extra);
        assert_eq!(run(&argv, &[]).status.code(), Some(2));
    }
}

#[test]
fn prompt_skills_create_error_reply_exits_one() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"error":"Failed to write skill file: denied"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "prompt-skills", "create", "s", "--file", "/dev/null"], &[]);
    assert_eq!(out.status.code(), Some(1));
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(all.contains("Failed to write skill file"), "{all}");
    assert!(!all.contains("Created skill"), "{all}");
}

#[test]
fn prompt_skills_info_unknown_name_fails_instead_of_a_fake_card() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"error":"Prompt skill 'nope' not found"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "prompt-skills", "info", "nope"], &[]);
    assert_eq!(out.status.code(), Some(5), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("fitness"), "no fake card");
}

#[test]
fn prompt_skills_get_is_a_working_hidden_alias() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"name":"s1","priority":7,"fitness":1.5,"content":"body text"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "prompt-skills", "get", "s1"], &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("body text"));
}

#[test]
fn prompt_skills_create_missing_file_exits_one() {
    let out = run(
        &[
            "--gateway",
            "http://127.0.0.1:1", // never contacted — the file check fails first
            "prompt-skills",
            "create",
            "my-skill",
            "--file",
            "/nonexistent/skill.md",
        ],
        &[],
    );
    assert_eq!(out.status.code(), Some(1), "missing --file must exit 1 before any request");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("file not found"), "stderr was: {stderr}");
}

#[test]
fn prompt_skills_evolve_renders_action() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"result":{"action":"mutated","skill":"x"}}"#,
        1,
    );
    let out = run(
        &["--gateway", &gw(mock.port), "prompt-skills", "evolve", "-o", "slow tool loops"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        reqs[0].starts_with("POST /api/prompt-skills/evolve "),
        "request was:\n{}",
        reqs[0]
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Boxed header (plain `+---+`), Title-cased title, then the action.
    assert!(stdout.starts_with("+-") && stdout.contains("| Skill Evolution") && stdout.contains("mutated"), "stdout was: {stdout}");
}

#[test]
fn prompt_skills_evolve_sends_apply_and_skill_and_renders_the_verdict() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"action":"mutate","name":"rag-tips","applied":true,"generation":3,"rationale":"loops were slow","moderation":{"passed":true}}"#,
        1,
    );
    let out = run(
        &[
            "--gateway", &gw(mock.port), "prompt-skills", "evolve",
            "-o", "slow loops", "--skill", "rag-tips", "--apply",
        ],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let body: serde_json::Value =
        serde_json::from_str(reqs[0].split("\r\n\r\n").nth(1).or_else(|| reqs[0].split("\n\n").nth(1)).unwrap_or(""))
            .unwrap_or_else(|e| panic!("request body is not JSON ({e}):\n{}", reqs[0]));
    assert_eq!(body["apply"], true, "request was:\n{}", reqs[0]);
    assert_eq!(body["skill"], "rag-tips", "request was:\n{}", reqs[0]);
    assert_eq!(body["observation"], "slow loops");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rag-tips") && stdout.contains("loops were slow"), "stdout was: {stdout}");
    assert!(stdout.contains("moderation: passed") && stdout.contains("applied: generation 3"), "stdout was: {stdout}");
}

#[test]
fn wp_a5_commands_map_auth_failure_to_exit_4() {
    // One representative POST command through the shared request() mapping.
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"nope"}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "inference", "agent", "hello"],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4), "401 must map to AuthFailed(4)");
}

// ── WP-A4: observability commands (logs / memory conversations / recall /
// heartbeat add+remove) — per-command envelope + exit-code cases. ──────────

#[test]
fn cluster_logs_reads_the_mesh_rail_not_ssh() {
    // An earlier change retired the controller's SSH lane, so `cluster logs`
    // must go through the gateway's node-agent proxy. Two round-trips:
    // resolve the node, then fetch its container log.
    let mock = Mock::start_seq(vec![
        http_response(200, "OK", "application/json",
            r#"{"nodes":[{"id":"n1","hostname":"n1","status":"online"}]}"#),
        http_response(200, "OK", "application/json",
            r#"{"logs":["first line","second line"]}"#),
    ]);
    let out = run(&["--gateway", &gw(mock.port), "cluster", "logs", "n1"], &[]);
    let reqs = mock.requests();
    assert!(
        reqs[1].contains("/api/logs/node/n1/noo-node-agent?tail=50"),
        "second request was not the log rail: {}",
        reqs[1]
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("first line"), "stdout: {stdout}");
    assert!(stdout.contains("second line"), "stdout: {stdout}");
}

#[test]
fn cluster_logs_refuses_the_ssh_only_flags() {
    // `-u` picked an SSH account and `-f` held an SSH pipe open. Both are
    // gone; neither may silently no-op.
    for flag in [["-u", "root"], ["-f", "n1"]] {
        let out = run(&["cluster", "logs", "n1", flag[0], flag[1]], &[]);
        assert!(!out.status.success(), "{flag:?} should fail");
    }
}

#[test]
fn logs_containers_renders_table() {
    let body = r#"{"containers":[{"node_id":"n1","node_hostname":"host8","name":"noo-gateway","status":"running","image":"ghcr.io/x/gw:1"}]}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "logs", "containers"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("GET /api/logs/containers"), "request was:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("host8") && stdout.contains("noo-gateway"), "stdout: {stdout}");
}

#[test]
fn logs_containers_node_filter_becomes_query_param() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"containers":[]}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "logs", "containers", "-n", "n1"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(reqs[0].starts_with("GET /api/logs/containers?node_id=n1"), "request was:\n{}", reqs[0]);
}

#[test]
fn logs_query_prints_loki_streams() {
    let body = r#"{"status":"success","data":{"resultType":"streams","result":[{"stream":{"container":"noo-gateway"},"values":[["1722400000000000000","line one"],["1722400000000000001","line two"]]}]}}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "logs", "query", "{container=\"noo-gateway\"}", "-l", "50"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].contains("GET /api/logs/query?query=") && reqs[0].contains("limit=50"), "request was:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("container=noo-gateway") && stdout.contains("line two"), "stdout: {stdout}");
}

#[test]
fn logs_status_renders_loki_health() {
    let body = r#"{"loki_url":"http://loki:3101","loki_ready":true,"node_registry_available":true}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "logs", "status"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().any(|l| l.trim_start().starts_with("Loki ") && l.ends_with("Healthy")), "stdout: {stdout}");
}

#[test]
fn memory_conversations_hits_with_preview_route() {
    let body = r#"{"conversations":[{"id":"abcdef1234567890","user_id":"alice","total_messages":4,"started_at":"2026-07-30T10:00:00Z","preview":"hello there"}],"total":1}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "memory", "conversations", "-u", "alice", "-n", "5"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        reqs[0].starts_with("GET /api/conversations/with-preview?limit=5&user_id=alice"),
        "request was:\n{}", reqs[0]
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("abcdef123456") && stdout.contains("hello there"), "stdout: {stdout}");
}

#[test]
fn recall_archive_posts_and_reports_count() {
    let body = r#"{"success":true,"data":{"archived":3,"video_path":"/data/vm/2026-07.bin"}}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "recall", "archive"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/v1/recall/archive"), "request was:\n{}", reqs[0]);
    // Confirmation is narration on stdout (terminal first), capitalised.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("+ Archived 3 conversation(s)"), "stdout: {stdout}");
}

#[test]
fn recall_lifecycle_posts_mutation() {
    let body = r#"{"success":true,"data":{"prominence_updated":10,"pruned":2,"elevated":1,"compacted":0,"errors":[]}}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "recall", "lifecycle", "--yes"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/v1/recall/lifecycle "), "request was:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // kv rows: two-space indent, Title Case label, padded, value.
    let has = |k: &str, v: &str| stdout.lines().any(|l| l.trim_start().starts_with(k) && l.trim_end().ends_with(v));
    assert!(has("Pruned", "2") && has("Elevated", "1"), "stdout: {stdout}");
}

#[test]
fn recall_lifecycle_dry_run_gets_preview() {
    let body = r#"{"success":true,"data":{"would_prune":[],"would_elevate":[],"would_compact":[]}}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "recall", "lifecycle", "--dry-run"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        reqs[0].starts_with("GET /api/v1/recall/lifecycle-preview"),
        "dry-run must be the read-only preview GET, request was:\n{}", reqs[0]
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nothing to do"), "stdout: {stdout}");
}

#[test]
fn recall_prune_commands_refuse_without_yes_and_send_nothing() {
    for verb in ["lifecycle", "refresh"] {
        // Closed port: a request would exit 3; stdin is not a terminal here.
        let out = run(&["--gateway", "http://127.0.0.1:1", "recall", verb], &[]);
        assert_eq!(out.status.code(), Some(1), "{verb}: stderr: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("confirmation required"), "{verb}");
    }
}

#[test]
fn recall_refresh_dry_run_previews_without_archiving() {
    let body = r#"{"success":true,"data":{"would_prune":[],"would_elevate":[],"would_compact":[]}}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "recall", "refresh", "--dry-run"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("GET /api/v1/recall/lifecycle-preview"), "request was:\n{}", reqs[0]);
}

#[test]
fn recall_lifecycle_stats_is_a_working_hidden_alias() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"success":true,"data":{}}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "recall", "lifecycle-stats"], &[]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(mock.requests()[0].starts_with("GET /api/v1/recall/lifecycle-stats"));
}

#[test]
fn rag_deduplicate_confirms_and_dry_run_sends_nothing() {
    let out = run(&["--gateway", "http://127.0.0.1:1", "rag", "deduplicate"], &[]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("confirmation required"));
    let out = run(&["--gateway", "http://127.0.0.1:1", "rag", "deduplicate", "--dry-run"], &[]);
    assert_eq!(out.status.code(), Some(0), "dry-run must not contact the gateway");
    let mock = Mock::start(200, "OK", "application/json", r#"{"removed":4}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "rag", "deduplicate", "-y"], &[]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(mock.requests()[0].starts_with("POST /api/v1/rag/deduplicate"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("emoved 4"));
}

#[test]
fn memory_embed_error_reply_is_not_started_and_tuning_flags_are_refused() {
    // The real error reply of routes/memory.rs embed_start.
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"error","error":"Redis unavailable: the drain's start/stop flag has nowhere to live"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "memory", "embed"], &[]);
    assert_eq!(out.status.code(), Some(5));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("started"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Redis unavailable"));
    for flag in ["-b", "--batch-size", "-g", "--model"] {
        let out = run(&["--gateway", "http://127.0.0.1:1", "memory", "embed", flag, "5"], &[]);
        assert_eq!(out.status.code(), Some(2), "{flag}");
    }
}

#[test]
fn recall_refresh_posts_and_summarizes() {
    let body = r#"{"success":true,"data":{"archive":{"archived":2},"lifecycle":{"pruned":1,"elevated":0,"compacted":0}}}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "recall", "refresh", "-y"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/v1/recall/refresh"), "request was:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let has = |k: &str, v: &str| stdout.lines().any(|l| l.trim_start().starts_with(k) && l.trim_end().ends_with(v));
    assert!(has("Archived", "2 conversations") && has("Pruned", "1"), "stdout: {stdout}");
}

#[test]
fn recall_test_is_local_and_never_calls_the_gateway() {
    // Closed port: any HTTP attempt would exit 3 — success proves no request.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = run(&["--gateway", &gw(port), "recall", "test"], &[]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Postgres + FAISS"), "stdout: {stdout}");
}

#[test]
fn heartbeat_add_posts_python_payload() {
    // Real gateway response shape: heartbeat_create_task echoes the id as
    // `task_id` ({"ok": true, "task_id": ...}), not `id`.
    let mock = Mock::start(200, "OK", "application/json", r#"{"ok":true,"task_id":"brief"}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "add", "brief", "0 8 * * *",
          "--action", "daily_briefing", "--channel", "telegram", "--recipient", "42"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let req = &reqs[0];
    assert!(req.starts_with("POST /api/heartbeat/tasks "), "request was:\n{req}");
    // Parse the captured body — serialization layout (pretty vs compact) is
    // not part of the contract, the field values are.
    let body_start = req.find("\r\n\r\n").expect("end of headers") + 4;
    let payload: serde_json::Value =
        serde_json::from_str(req[body_start..].trim()).expect("JSON request body");
    // The gateway requires an id; the CLI derives it from the name (drift
    // fix 2026-08-07 — the payload without it 400'd with "Missing field: id").
    assert_eq!(payload["id"], "brief");
    assert_eq!(payload["name"], "brief");
    assert_eq!(payload["schedule"], "0 8 * * *");
    assert_eq!(payload["action"], "daily_briefing");
    assert_eq!(payload["channels"], serde_json::json!(["telegram"]));
    assert_eq!(payload["recipients"], serde_json::json!(["42"]));
    assert_eq!(payload["enabled"], true);
    // Terminal first (rev 2): confirmation, the captured value on its own
    // line, and guidance all on stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.to_lowercase().contains("task added: brief (brief)"), "stdout: {stdout}");
    assert!(stdout.lines().any(|l| l == "brief"), "captured value line missing: {stdout}");
    assert!(stdout.contains("noo heartbeat run brief"), "guidance missing: {stdout}");
}

#[test]
fn heartbeat_remove_with_yes_deletes() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"deleted"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "heartbeat", "remove", "task-9", "--yes"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("DELETE /api/heartbeat/tasks/task-9 "), "request was:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(stdout.contains("task task-9 removed"), "stdout: {stdout}");
}

#[test]
fn heartbeat_remove_json_without_yes_refuses_before_any_request() {
    // Closed port: reaching HTTP would exit 3 — exit 1 proves the confirm
    // gate fired first (--json must never prompt).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = run(&["--json", "--gateway", &gw(port), "heartbeat", "remove", "task-9"], &[]);
    assert_eq!(out.status.code(), Some(1), "confirm gate must exit 1 in --json mode without --yes");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("confirmation_required"), "stderr: {stderr}");
}

#[test]
fn heartbeat_remove_non_tty_without_yes_errors_instead_of_hanging() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    // Command::output pipes stdin → not a TTY → the confirm must error out.
    let out = run(&["--gateway", &gw(port), "heartbeat", "remove", "task-9"], &[]);
    assert_eq!(out.status.code(), Some(1), "non-TTY confirm must exit 1, not block");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("confirmation required"), "stderr: {stderr}");
}

// ---------------------------------------------------------------------------
// WP-C2: `memory embed[-status] --watch` — the native progress poll loop.
// ---------------------------------------------------------------------------

#[test]
fn embed_status_watch_polls_until_terminal_state() {
    // Initial status fetch + two watch polls: running → running → idle.
    let running =
        r#"{"state":"running","stats":{"total":10,"embedded":5,"unembedded":5,"progress":0.5}}"#;
    let idle =
        r#"{"state":"idle","stats":{"total":10,"embedded":10,"unembedded":0,"progress":1.0}}"#;
    let mock = Mock::start_seq(vec![ok_json(running), ok_json(running), ok_json(idle)]);
    let out = run(&["--gateway", &gw(mock.port), "memory", "embed-status", "--watch"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(reqs.len(), 3, "initial fetch + 2 polls expected");
    // "Embedding complete" is narration (stdout, terminal first) followed by
    // the final status block.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("+ Embedding complete"), "stdout was: {stdout}");
    assert!(stdout.contains("10 embedded"), "final status render expected, got: {stdout}");
}

#[test]
fn embed_status_watch_skips_loop_when_not_running() {
    // Python parity: embed-status only enters the watch loop when the
    // initial state is "running" — a stopped worker renders once and exits.
    let idle =
        r#"{"state":"idle","stats":{"total":4,"embedded":4,"unembedded":0,"progress":1.0}}"#;
    let mock = Mock::start_seq(vec![ok_json(idle)]);
    let out = run(&["--gateway", &gw(mock.port), "memory", "embed-status", "--watch"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(reqs.len(), 1, "no watch polls for a non-running worker");
}

#[test]
fn embed_watch_json_emits_ndjson_progress_events() {
    // POST /embed/start, then status polls running → stopped. In --json
    // mode the watch loop emits one status object per poll (NDJSON) after
    // the start response — Python defines no --json behavior here at all.
    let start = r#"{"status":"started","state":"running"}"#;
    let running =
        r#"{"state":"running","stats":{"total":8,"embedded":2,"unembedded":6,"progress":0.25}}"#;
    let stopped =
        r#"{"state":"stopped","stats":{"total":8,"embedded":8,"unembedded":0,"progress":1.0}}"#;
    let mock = Mock::start_seq(vec![ok_json(start), ok_json(running), ok_json(stopped)]);
    let out = run(&["--json", "--gateway", &gw(mock.port), "memory", "embed", "--watch"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(reqs.len(), 3, "start POST + 2 polls expected");
    assert!(reqs[0].starts_with("POST /api/memory/embed/start"), "first request: {}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3, "start + 2 progress events, got: {stdout}");
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line).expect("each line is a JSON object");
    }
    assert!(lines[2].contains(r#""state":"stopped""#), "last event is terminal: {stdout}");
}

// ---------------------------------------------------------------------------
// `skills run` goes through the gateway, never to a node agent.
// The old local executor posted the spec to NOO_NODE_AGENT_URL with the
// static NOO_NODE_AGENT_TOKEN; these pin that neither is used any more.
// ---------------------------------------------------------------------------

const PLANTED_AGENT_TOKEN: &str = "planted-static-agent-token-1264";

#[test]
fn skills_run_posts_to_the_gateway_and_sends_no_agent_token() {
    let resp = r#"{"success":true,"output":{"answer":42},"duration_ms":5.0,"container_id":"cid-1","node_id":"host3"}"#;
    let mock = Mock::start_seq(vec![ok_json(resp)]);
    let out = run(
        &["--gateway", &gw(mock.port), "skills", "run", "itest-skill", r#"{"x":1}"#, "-n", "host3"],
        &[
            // A dead agent address and a planted token: if either were
            // used, the run would fail or the token would show on the wire.
            ("NOO_NODE_AGENT_URL", "http://127.0.0.1:1"),
            ("NOO_NODE_AGENT_TOKEN", PLANTED_AGENT_TOKEN),
        ],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("42"));
    assert_eq!(reqs.len(), 1, "one gateway request: {reqs:?}");
    let req = &reqs[0];
    assert!(req.starts_with("POST /api/skills/itest-skill/run"), "request was: {req}");
    assert!(!req.contains(PLANTED_AGENT_TOKEN), "the static agent token reached the wire: {req}");
    let body: serde_json::Value =
        serde_json::from_str(req.split("\r\n\r\n").nth(1).expect("request body")).expect("JSON body");
    assert_eq!(body["inputs"]["x"], 1);
    assert_eq!(body["node_id"], "host3");
}

#[test]
fn skills_run_gateway_failure_exits_one() {
    let resp = r#"{"success":false,"error":"Container exited with code 3: boom","duration_ms":5.0}"#;
    let mock = Mock::start_seq(vec![ok_json(resp)]);
    // `-g` is still accepted and changes nothing.
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "skills", "run", "itest-skill", r#"{"x":1}"#, "-g"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(1), "a failed run exits 1");
    assert!(reqs[0].starts_with("POST /api/skills/itest-skill/run"), "request was: {}", reqs[0]);
    let envelope: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("JSON on stdout");
    assert_eq!(envelope["success"], false);
}

// ── WP-C1: chat — health probe + SSE streaming exchange ────────────────────
// (stdin is closed under `Command::output()`, so these also prove the
// non-TTY contract: one-shot works without a terminal, the REPL refuses.)

fn health_ok() -> String { http_response(200, "OK", "application/json", r#"{"status":"ok"}"#) }

/// OpenAI-chunk SSE body as gateway-rust proxies it from a vLLM backend.
const CHAT_SSE: &str = concat!(
    "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":null}]}\n\n",
    "data: [DONE]\n\n",
);

#[test]
fn chat_one_shot_streams_tokens_and_exits_zero() {
    let mock = Mock::start_seq(vec![health_ok(), http_response(200, "OK", "text/event-stream", CHAT_SSE)]);
    let out = run(&["--gateway", &gw(mock.port), "chat", "--message", "hi"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Hello"), "assembled tokens expected on stdout, got: {stdout}");
    // Request order: the health probe, then the streaming POST.
    assert!(reqs[0].starts_with("GET /health"), "first request was:\n{}", reqs[0]);
    assert!(
        reqs[1].starts_with("POST /api/inference/stream"),
        "second request was:\n{}",
        reqs[1]
    );
}

#[test]
fn chat_one_shot_json_emits_machine_envelope() {
    let mock = Mock::start_seq(vec![health_ok(), http_response(200, "OK", "text/event-stream", CHAT_SSE)]);
    let out = run(&["--json", "--gateway", &gw(mock.port), "chat", "--message", "hi"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be a single JSON object");
    assert_eq!(v["response"].as_str(), Some("Hello"));
    assert!(v["conversation_id"].as_str().unwrap_or("").starts_with("cli-"));
}

#[test]
fn chat_in_stream_error_envelope_maps_to_exit_5() {
    let sse = "data: {\"error\":\"No backend available: none\"}\n\ndata: [DONE]\n\n";
    let mock = Mock::start_seq(vec![health_ok(), http_response(200, "OK", "text/event-stream", sse)]);
    let out = run(&["--gateway", &gw(mock.port), "chat", "--message", "hi"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5), "in-stream error must map to RemoteError(5)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("No backend available"), "stderr was: {stderr}");
}

#[test]
fn chat_unreachable_gateway_points_at_mesh_start_and_exits_3() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = run(&["--gateway", &gw(port), "chat", "--message", "hi"], &[]);
    assert_eq!(out.status.code(), Some(3), "failed health probe must map to GatewayUnreachable(3)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("noo stack start"), "actionable hint expected, stderr was: {stderr}");
}

/// The Python CLI's `--no-use-cluster` fallback is offered only where a
/// Python CLI exists; a standalone host has none and gets `noo health`.
#[test]
fn chat_unreachable_gateway_offers_the_python_fallback_only_when_present() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let empty = std::env::temp_dir().join(format!("noo-no-py-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    let fake_py = empty.join("noo-py-shim");
    std::fs::write(&fake_py, "#!/bin/sh\nexit 0\n").unwrap();

    // No Python CLI: NOO_PY_CLI points nowhere and PATH holds nothing.
    let out = run(
        &["--gateway", &gw(port), "chat", "--message", "hi"],
        &[("NOO_PY_CLI", ""), ("PATH", empty.to_str().unwrap())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("--no-use-cluster"), "no Python CLI, no fallback pointer: {stderr}");
    assert!(stderr.contains("noo health"), "standalone hint expected: {stderr}");

    // A Python CLI present: the fallback is offered.
    let out = run(
        &["--gateway", &gw(port), "chat", "--message", "hi"],
        &[("NOO_PY_CLI", fake_py.to_str().unwrap())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--no-use-cluster"), "Python-fallback pointer expected: {stderr}");
    let _ = std::fs::remove_dir_all(&empty);
}

#[test]
fn chat_repl_without_tty_errors_instead_of_hanging() {
    // No --message and stdin closed (Command::output()) → refuse pre-probe:
    // no gateway is contacted, so a dead port proves the ordering too.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = run(&["--gateway", &gw(port), "chat"], &[]);
    assert_eq!(out.status.code(), Some(2), "non-TTY REPL must be a usage error (2)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--message"), "hint must name the one-shot escape, stderr: {stderr}");
}

/// By design, no break-glass. The flag is refused BY
/// NAME — before any request — with the ordinary recovery path, so a script
/// that still passes it learns why instead of sending an anonymous request.
/// A box holding every shared secret plus the old opt-in sends NOTHING
/// signed with one.
#[test]
fn break_glass_is_refused_by_name_and_no_secret_is_ever_sent() {
    let out = run(
        &["--gateway", "http://127.0.0.1:1", "--break-glass", "heartbeat", "status"],
        &[("NOO_CLUSTER_SECRET", "s"), ("NOO_CONTROLLER_SECRET", "c")],
    );
    assert_eq!(out.status.code(), Some(2), "a removed flag is a usage error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("removed"), "{stderr}");
    assert!(stderr.contains("noo auth login") && stderr.contains("noo security admin-password reset"), "{stderr}");

    let mock = Mock::start(200, "OK", "application/json", r#"{"running":true,"enabled":true}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_CLUSTER_SECRET", "s"), ("NOO_CONTROLLER_SECRET", "c"), ("NOO_BREAK_GLASS", "1")],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(auth_header(&reqs[0]).is_none(), "no shared secret may be sent: {}", reqs[0]);
}

/// `--break-glass` is gone from the usage text and from every help screen.
#[test]
fn break_glass_is_gone_from_usage() {
    for args in [vec!["security", "--help"], vec!["auth", "--help"], vec!["security", "pki", "--help"], vec!["security", "admin-password", "--help"]] {
        let out = run(&args, &[]);
        let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!all.contains("break-glass") && !all.contains("NOO_BREAK_GLASS"), "{args:?}: {all}");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// WP-A2: models catalog commands. These talk to HuggingFace (mocked via
// HF_ENDPOINT) rather than the gateway, except `recommended`, whose two
// gateway calls are best-effort. HOME is pointed at a per-test temp dir so
// the shared ~/.config/mesh/model_cache.json never leaks into a test.
// ═══════════════════════════════════════════════════════════════════════

/// Fresh, empty HOME for one test (isolates the model-catalog cache file).
/// Removed when the test ends, panicking or not.
fn temp_home(tag: &str) -> ScratchDir {
    ScratchDir::new(&format!("noo-cli-test-home-{tag}"))
}

/// A URL that refuses connections (bind an ephemeral port, then drop it).
fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

#[test]
fn models_list_offline_falls_back_to_curated_catalog() {
    // HF unreachable + empty cache → the curated offline list, exit 0.
    let home_dir = temp_home("list");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["--json", "models", "list", "--backend", "ollama"],
        &[("HOME", &home), ("HF_ENDPOINT", &dead_url())],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON doc per backend");
    assert_eq!(v["backend"], "ollama");
    let ids: Vec<&str> = v["models"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"llama3.1:8b"), "curated fallback expected, got: {ids:?}");
    assert!(ids.contains(&"phi4"), "curated fallback expected, got: {ids:?}");
}

#[test]
fn models_search_queries_hf_and_normalizes() {
    let hf_body = r#"[{"modelId":"meta-llama/Llama-3.1-8B-Instruct","tags":["awq","text-generation"],"downloads":3000000,"likes":120,"gated":false}]"#;
    let mock = Mock::start(200, "OK", "application/json", hf_body, 1);
    let home_dir = temp_home("search");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["--json", "models", "search", "llama"],
        &[("HOME", &home), ("HF_ENDPOINT", &gw(mock.port))],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let req = reqs.first().expect("one HF request");
    assert!(
        req.contains("GET /api/models?search=llama"),
        "HF search request expected, got:\n{req}"
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let m = &v.as_array().expect("array envelope")[0];
    assert_eq!(m["id"], "meta-llama/Llama-3.1-8B-Instruct");
    assert_eq!(m["gated"], "Open");
    assert_eq!(m["params_b"], 8.0);
    // awq tag → vllm-compatible.
    assert!(m["backends"].as_array().unwrap().iter().any(|b| b == "vllm"));
}

#[test]
fn models_info_renders_gated_badge_and_hint() {
    let hf_body = r#"{"id":"meta-llama/Llama-3.1-8B-Instruct","author":"meta-llama","gated":"manual","downloads":3000000,"likes":12345,"tags":["safetensors"],"siblings":[{"rfilename":"model.safetensors"}],"cardData":{"license":"llama3.1"}}"#;
    let mock = Mock::start(200, "OK", "application/json", hf_body, 1);
    let home_dir = temp_home("info");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["models", "info", "meta-llama/Llama-3.1-8B-Instruct"],
        &[("HOME", &home), ("HF_ENDPOINT", &gw(mock.port))],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.lines().any(|l| l.trim_start().starts_with("Gated") && l.ends_with("Gated")),
        "gated badge expected, got:\n{stdout}"
    );
    // The gated guidance is narration → stdout (CLI_STYLE_GUIDE rev 2 §2),
    // with the login command as a `>` guidance line in plain mode.
    assert!(
        stdout.contains("requires HuggingFace approval"),
        "gated guidance expected on stdout, got:\n{stdout}"
    );
    assert!(stdout.contains("> huggingface-cli login"), "guidance command expected, got:\n{stdout}");
    assert!(stderr.trim().is_empty(), "nothing on stderr for a successful query, got:\n{stderr}");
    assert!(
        stdout.lines().any(|l| l.trim_start().starts_with("License") && l.ends_with("llama3.1")),
        "license expected, got:\n{stdout}"
    );
}

#[test]
fn models_info_not_found_exits_1() {
    let mock = Mock::start(404, "Not Found", "application/json", r#"{"error":"unknown"}"#, 1);
    let home_dir = temp_home("info404");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["models", "info", "nope/not-a-model"],
        &[("HOME", &home), ("HF_ENDPOINT", &gw(mock.port))],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(1), "HF 404 must map to Generic(1)");
}

#[test]
fn models_recommended_prefers_cluster_cached_models() {
    // Gateway serves /api/models/cached (the one gateway call when --tier is
    // given); HF is down, so the injected cache-resident model is the only
    // candidate for its backend.
    let gw_body = r#"{"models":[{"name":"llama3.2:3b","backend":"ollama","size":"2.0GB"}]}"#;
    let mock = Mock::start(200, "OK", "application/json", gw_body, 1);
    let home_dir = temp_home("recommended");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "models", "recommended", "--tier", "4"],
        &[("HOME", &home), ("HF_ENDPOINT", &dead_url())],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let req = reqs.first().expect("one gateway request");
    assert!(req.contains("GET /api/models/cached"), "cached-models fetch expected, got:\n{req}");
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["tier"], 4);
    assert_eq!(v["cached_preferred"], true);
    let ollama = v["backends"]["ollama"].as_array().expect("ollama recommendations");
    assert_eq!(ollama[0]["id"], "llama3.2:3b");
    assert_eq!(ollama[0]["cached"], true);
    assert_eq!(ollama[0]["desc"], "already cached on the cluster");
}

#[test]
fn models_recommended_rejects_invalid_tier() {
    let home_dir = temp_home("badtier");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["models", "recommended", "--tier", "9"],
        &[("HOME", &home), ("HF_ENDPOINT", &dead_url())],
    );
    assert_eq!(out.status.code(), Some(2), "tier outside 1-5 must map to Usage(2)");
}

#[test]
fn models_huggingface_uses_default_query() {
    let mock = Mock::start(200, "OK", "application/json", "[]", 1);
    let home_dir = temp_home("hf");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["--json", "models", "huggingface"],
        &[("HOME", &home), ("HF_ENDPOINT", &gw(mock.port))],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let req = reqs.first().expect("one HF request");
    assert!(
        req.contains("search=mistral%20instruct%20awq"),
        "default query expected, got:\n{req}"
    );
    // Live search returned nothing and the offline fallback has no
    // 'mistral instruct awq' match → empty machine envelope.
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.as_array().unwrap().is_empty());
}

#[test]
fn models_ollama_offline_json_envelope() {
    let home_dir = temp_home("ollama");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["--json", "models", "ollama", "--limit", "3"],
        &[("HOME", &home), ("HF_ENDPOINT", &dead_url())],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let arr = v.as_array().expect("array envelope");
    assert_eq!(arr.len(), 3, "--limit must cap the list");
}

// ── WP-A3: security HTTP surface (users / teams / orgs / posture / keys) ────
// One case per command group + the sensitive-input and destructive-confirm
// contracts. Envelope shaping only — the shared status→exit mapping is
// already covered by the `health` matrix above.

#[test]
fn security_user_list_renders_table() {
    let body = r#"{"users":[{"username":"alice","disabled":false,"scopes":["read","write"],"created_at":"2026-07-31T00:00:00Z","last_login_at":null,"failed_login_count":2}]}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "security", "user", "list"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("alice"), "stdout was: {stdout}");
    assert!(
        reqs[0].starts_with("GET /api/security/users "),
        "request was:\n{}",
        reqs[0]
    );
}

#[test]
fn security_user_list_401_maps_to_exit_4() {
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"nope"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "security", "user", "list"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4));
}

#[test]
fn security_user_create_reads_password_from_stdin() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"username":"alice"}"#, 1);
    let out = run_with_stdin(
        &["--gateway", &gw(mock.port), "security", "user", "create", "alice", "--password-stdin"],
        "supersecretpw\n",
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Terminal first (CLI_STYLE_GUIDE rev 2 §2): confirmations are stdout.
    assert!(stdout.contains("'alice' created"), "stdout was: {stdout}");
    // The password must reach the gateway (request body) and NEVER the terminal.
    assert!(reqs[0].starts_with("POST /api/security/users "), "request:\n{}", reqs[0]);
    assert!(reqs[0].contains("supersecretpw"), "password missing from body:\n{}", reqs[0]);
    assert!(!stdout.contains("supersecretpw"), "password echoed to stdout");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("supersecretpw"), "password echoed to stderr");
}

#[test]
fn security_user_create_stdin_password_too_short_exits_1() {
    // Fails locally (< 12 chars) — must never reach the gateway.
    let out = run_with_stdin(
        &["--gateway", &gw(closed_port()), "security", "user", "create", "alice", "--password-stdin"],
        "short\n",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least 12 characters"));
}

#[test]
fn security_user_set_scopes_posts_full_list() {
    let mock = Mock::start(200, "OK", "application/json",
        r#"{"username":"alice","scopes":["read","write"]}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "security", "user", "set-scopes", "alice",
          "--scope", "read", "--scope", "write"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        reqs[0].starts_with("POST /api/security/users/alice/scopes "),
        "request:\n{}",
        reqs[0]
    );
    // Both scopes must reach the gateway: the endpoint REPLACES rather than
    // merges, so a dropped one silently demotes the account.
    assert!(reqs[0].contains("\"read\""), "request:\n{}", reqs[0]);
    assert!(reqs[0].contains("\"write\""), "request:\n{}", reqs[0]);
}

#[test]
fn security_user_set_scopes_without_a_scope_never_calls_the_gateway() {
    // An empty list would wipe the account's scopes if the gateway took it.
    // Refused locally, so a typo'd flag cannot become a lockout.
    let out = run(
        &["--gateway", &gw(closed_port()), "security", "user", "set-scopes", "alice"],
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("replaces"), "stderr was: {stderr}");
}

#[test]
fn security_set_password_json_mode_refuses_to_prompt() {
    // --json without --password-stdin must error out, not hang on a prompt.
    let out = run(
        &["--json", "--gateway", &gw(closed_port()), "security", "user", "set-password", "alice"],
        &[],
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("password_required"), "stderr was: {stderr}");
}

#[test]
fn security_set_password_non_tty_refuses_to_prompt() {
    // stdin is closed (not a TTY) and no --password-stdin → clear error, no hang.
    let out = run(
        &["--gateway", &gw(closed_port()), "security", "user", "set-password", "alice"],
        &[],
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--password-stdin"), "stderr was: {stderr}");
}

#[test]
fn security_set_password_stdin_puts_to_gateway() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"ok"}"#, 1);
    let out = run_with_stdin(
        &["--gateway", &gw(mock.port), "security", "user", "set-password", "alice", "--password-stdin"],
        "supersecretpw\n",
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        reqs[0].starts_with("PUT /api/security/users/alice/password "),
        "request:\n{}",
        reqs[0]
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("assword updated for 'alice'"));
}

#[test]
fn security_user_erase_defaults_to_dry_run() {
    let body = r#"{"dry_run":true,"plan":[{"store":"noo_conversations","rows":3}],"total_rows":3}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "security", "user", "erase", "alice"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    // Without --yes the request must carry dry_run: true (nothing deleted).
    // ureq pretty-prints the JSON body — match the key/value pair loosely.
    assert!(reqs[0].contains("\"dry_run\": true"), "request:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Dry-run ends with the full guidance block naming the real command.
    assert!(stdout.contains("noo security user erase alice --yes"), "stdout was: {stdout}");
}

#[test]
fn security_team_create_posts_and_renders() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"name":"research","role":"team:research"}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "security", "team", "create", "research", "-d", "R&D"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/kb/teams/create "), "request:\n{}", reqs[0]);
    // The grant guidance names the role; narration is stdout (rev 2).
    assert!(String::from_utf8_lossy(&out.stdout).contains("team:research"));
}

#[test]
fn security_team_api_error_field_maps_to_exit_1() {
    // _team_api parity: 200 + {"error": …} is a failure (exit 1).
    let mock = Mock::start(200, "OK", "application/json", r#"{"error":"registry unavailable"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "security", "team", "list"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(1));
    // Errors stay on stderr; status lines are sentence-cased by ui.
    assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("registry unavailable"));
}

#[test]
fn security_team_delete_requires_confirmation_on_non_tty() {
    // Destructive + no --yes + stdin not a TTY → error, no hang, no request.
    let out = run(&["--gateway", &gw(closed_port()), "security", "team", "delete", "research"], &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("confirmation required"));
}

#[test]
fn security_team_delete_json_requires_yes() {
    let out = run(
        &["--json", "--gateway", &gw(closed_port()), "security", "team", "delete", "research"],
        &[],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("confirmation_required"));
}

#[test]
fn security_team_delete_with_yes_executes() {
    let body = r#"{"deleted":"research","members_stripped":1,"docs_orphaned":2}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "security", "team", "delete", "research", "--yes"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("DELETE /api/security/teams/research "), "request:\n{}", reqs[0]);
    assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains("team 'research' deleted"));
}

/// The JSON body of a captured request (the part after the blank line).
fn req_body(req: &str) -> serde_json::Value {
    let body = req.split_once("\r\n\r\n").or_else(|| req.split_once("\n\n")).map(|(_, b)| b).unwrap_or("");
    serde_json::from_str(body.trim()).unwrap_or_else(|e| panic!("request body is not JSON ({e}):\n{req}"))
}

#[test]
fn security_team_delete_force_rides_the_query_string() {
    let body = r#"{"deleted":"research","members_stripped":1,"docs_orphaned":2}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "security", "team", "delete", "research", "--force", "-y"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("DELETE /api/security/teams/research?force=true "), "request:\n{}", reqs[0]);
}

#[test]
fn security_user_enable_posts_disabled_false_to_the_toggle_route() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"username":"alice","disabled":false}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "security", "user", "enable", "alice"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/users/disable "), "request:\n{}", reqs[0]);
    assert_eq!(req_body(&reqs[0]), serde_json::json!({"username": "alice", "disabled": false}), "request:\n{}", reqs[0]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("enabled"));
}

#[test]
fn security_user_disable_and_service_key_revoke_refuse_without_yes_and_send_nothing() {
    // No terminal, no -y: one-line refusal, and the (closed) port proves no request was made
    // (a request would exit 3, unreachable, not 1 with this message).
    for args in [
        &["security", "user", "disable", "alice"][..],
        &["security", "service-key", "revoke", "ci-bot"][..],
        &["security", "service-key", "revoke", "ci-bot", "--disable-account"][..],
        &["security", "pki", "revoke-client", "ana"][..],
        &["security", "secrets", "tidy"][..],
        &["security", "secrets", "absorb-files"][..],
    ] {
        let mut full = vec!["--gateway".to_string(), gw(closed_port())];
        full.extend(args.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        let out = run(&refs, &[]);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(
            String::from_utf8_lossy(&out.stderr).to_lowercase().contains("confirmation required"),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn security_user_disable_with_yes_posts_the_per_user_route() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"ok","username":"alice","disabled":true}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "security", "user", "disable", "alice", "-y"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/security/users/alice/disable "), "request:\n{}", reqs[0]);
}

/// One body that is BOTH the real `service_keys_list` reply (keys oldest
/// first, scopes as an array) and the real `service_key_rotate` reply, so
/// the same canned answer serves the GET and the POST.
#[test]
fn service_key_rotate_keeps_the_current_scopes_and_does_not_say_revoked() {
    let body = r#"{"keys":[
        {"consumer":"ci","scopes":["chat"],"retired_scopes":[],"active":false,"created_at":"2026-09-01T00:00:00Z","last_used_at":null,"note":null,"rpm_limit":null,"user_id":null,"superseded_at":null},
        {"consumer":"ci","scopes":["chat","mcp:operator"],"retired_scopes":[],"active":true,"created_at":"2026-09-02T00:00:00Z","last_used_at":null,"note":null,"rpm_limit":30,"user_id":"ops","superseded_at":null}],
        "count":2,"status":"ok","consumer":"ci","scopes":["chat","mcp:operator"],"rpm_limit":30,"user_id":"ops","key":"noo_rawkey","note":"x"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 2);
    let out = run(&["--gateway", &gw(mock.port), "security", "service-key", "rotate", "ci"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("GET /api/security/service-keys "), "request:\n{}", reqs[0]);
    assert!(reqs[1].starts_with("POST /api/security/service-keys/ci/rotate "), "request:\n{}", reqs[1]);
    assert_eq!(req_body(&reqs[1])["scopes"], serde_json::json!(["chat", "mcp:operator"]), "the current scopes must be sent:\n{}", reqs[1]);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)).to_lowercase();
    assert!(!text.contains("revoked"), "the old key is only superseded:\n{text}");
    assert!(text.contains("still live") && text.contains("service-key retire ci"), "{text}");
}

#[test]
fn service_key_rotate_with_explicit_scopes_asks_for_no_listing() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"ok","consumer":"ci","scopes":["rerank"],"rpm_limit":null,"key":"k"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "security", "service-key", "rotate", "ci", "--scopes", "rerank"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(reqs.len(), 1);
    assert!(reqs[0].starts_with("POST /api/security/service-keys/ci/rotate "), "{}", reqs[0]);
    assert_eq!(req_body(&reqs[0])["scopes"], serde_json::json!(["rerank"]));
}

#[test]
fn generate_secret_refuses_an_unknown_type_and_untrust_ca_refuses_a_path() {
    let out = run(&["security", "generate-secret", "fernat"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("unknown secret type"), "{}", String::from_utf8_lossy(&out.stderr));
    let out = run(&["security", "generate-secret", "fernet", "--length", "8"], &[]);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&["security", "generate-secret", "jwt"], &[]);
    assert_eq!(out.status.code(), Some(0));
    let out = run(&["security", "untrust-ca", "/tmp/ca.crt", "--yes"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("takes no CA path"), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn security_org_create_json_passthrough() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"id":"acme","created":true}"#, 1);
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "security", "org", "create", "acme"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/security/orgs "), "request:\n{}", reqs[0]);
    assert!(String::from_utf8_lossy(&out.stdout).contains(r#""created":true"#));
}

// `security posture set` against a gateway — the request, the rendering and
// the credential (operator certificate + bound token, over TLS) — is pinned in
// tests/recovery_rehearsal.rs, which runs a TLS mock. Plain http here can
// carry no client certificate, and there is no other lane any more.

#[test]
fn security_service_key_issue_defaults_full_scopes() {
    let body = r#"{"consumer":"noo-trading","scopes":["chat","embeddings","rerank","classify","mcp"],"rpm_limit":null,"key":"raw-key-abc123"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "security", "service-key", "issue", "noo-trading"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/security/service-keys "), "request:\n{}", reqs[0]);
    // Default scope set goes in the payload (SERVICE_KEY_SCOPES parity).
    assert!(reqs[0].contains("embeddings"), "request:\n{}", reqs[0]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("raw-key-abc123"), "raw key must print once: {stdout}");
    assert!(stdout.contains("uncapped"), "stdout was: {stdout}");
}

#[test]
fn security_unported_sibling_commands_still_pass_through() {
    // `security scan` / `generate-secret` are Phase-2: with no Python present
    // the passthrough error surfaces (exit 2) — they must NOT be swallowed by
    // the native security block.
    let out = run(&["--gateway", &gw(closed_port()), "security", "scan"], &[]);
    // Either Python serves it (dev box) or the passthrough error fires — but
    // it must not hit the mock/native path. Native handlers would exit 0/3/4/5.
    let code = out.status.code();
    assert!(
        code == Some(2) || code == Some(0) || code == Some(1),
        "unexpected exit {code:?}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── WP-B2: stack mgmt ───────────────────────────────────────────────────
//
// `stack reset` / `stack ollama` / `stack install-watcher` (retired stub) / `models switch`
// are exercised against SANDBOXED fakes only — a temp NOO_REPO_ROOT with a
// stub reset script, a stubbed `docker`/`systemctl`/`pgrep` on PATH, and a
// temp HOME for the systemd unit — never the live stack. `cluster seed`
// talks to the in-process mock gateway.

/// A mock gateway that routes each connection's response by a substring of
/// the request line (path-based), serving `count` connections total.
/// Routes are matched in order — put the more specific path first.
struct RouterMock {
    port: u16,
    handle: JoinHandle<Vec<String>>,
}

impl RouterMock {
    fn start(routes: Vec<(&'static str, u16, &'static str)>, count: usize) -> RouterMock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut captured = Vec::new();
            for _ in 0..count {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(_) => break,
                };
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let req = read_request(&mut stream);
                let first_line = req.lines().next().unwrap_or("").to_string();
                let (status, body) = routes
                    .iter()
                    .find(|(path, _, _)| first_line.contains(path))
                    .map(|(_, s, b)| (*s, *b))
                    .unwrap_or((404, r#"{"detail":"no route"}"#));
                captured.push(req);
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
            captured
        });
        RouterMock { port, handle }
    }

    fn requests(self) -> Vec<String> {
        self.handle.join().expect("mock thread")
    }
}

/// Fresh temp dir for a test sandbox (repo root / HOME / PATH stubs).
fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "noo-wpb2-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write an executable stub script into `dir` (for PATH interception).
fn stub(dir: &std::path::Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// PATH with `stub_dir` first (stubs win over the real binaries).
fn stub_path(stub_dir: &std::path::Path) -> String {
    format!("{}:{}", stub_dir.display(), std::env::var("PATH").unwrap_or_default())
}

/// Like `run` but also scrubs the repo/secret-backend env the WP-B2 local
/// commands read, so the dev machine's real repo can never be touched.
fn run_local(args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for k in [
        "CONTROLLER_URL", "NOO_GATEWAY_URL", "NOO_TLS_CERT", "NOO_TLS_CA",
        "NOO_CLUSTER_SECRET", "NOO_REPO_ROOT", "NOO_SECRETS_BACKEND", "NOO_PY_CLI",
    ] {
        cmd.env_remove(k);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn noo")
}

#[test]
fn mesh_reset_json_without_yes_refuses() {
    // --json must NEVER prompt: without --yes it errors before any script runs
    // (the sandbox root has no scripts dir, so reaching the script would fail
    // differently — the assertion pins the confirm gate specifically).
    let root = tmpdir("reset-json");
    let out = run_local(
        &["--json", "stack", "reset"],
        &[("NOO_REPO_ROOT", &root.display().to_string())],
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("confirmation_required"), "stderr: {stderr}");
}

#[test]
fn mesh_reset_non_tty_without_yes_refuses() {
    // stdin is a pipe under Command::output() → the non-TTY guard fires
    // instead of letting the reset script block on its `read` prompt.
    let root = tmpdir("reset-notty");
    let out = run_local(
        &["stack", "reset"],
        &[("NOO_REPO_ROOT", &root.display().to_string())],
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("stdin is not a TTY"), "stderr: {stderr}");
}

#[test]
fn mesh_reset_tag_requires_dist() {
    let root = tmpdir("reset-tag");
    let out = run_local(
        &["stack", "reset", "--tag", "v1.2.3", "--yes"],
        &[("NOO_REPO_ROOT", &root.display().to_string())],
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--tag only applies with --dist"), "stderr: {stderr}");
}

#[test]
fn mesh_reset_spawns_stub_script_with_python_flag_order() {
    // Stub reset script in a sandbox repo root — proves flag mapping and the
    // exit-code propagation without touching the real (destructive) script.
    let root = tmpdir("reset-stub");
    std::fs::create_dir_all(root.join("scripts")).unwrap();
    std::fs::write(root.join("scripts/noomesh-reset.sh"), "echo \"ARGS:$*\"\n").unwrap();
    let out = run_local(
        &["stack", "reset", "--dist", "--tag", "v1.2.3", "--ci", "--keep-env", "--yes"],
        &[("NOO_REPO_ROOT", &root.display().to_string())],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ARGS:--dist --tag v1.2.3 --ci --keep-env --yes"),
        "stdout: {stdout}"
    );
}

#[test]
fn mesh_reset_json_contract_with_yes() {
    // --json + --yes: the script's stdout is rerouted to stderr; stdout gets
    // exactly the {"status":"ok","action":"reset"} envelope.
    let root = tmpdir("reset-json-ok");
    std::fs::create_dir_all(root.join("scripts")).unwrap();
    std::fs::write(root.join("scripts/noomesh-reset.sh"), "echo \"ARGS:$*\"\n").unwrap();
    let out = run_local(
        &["--json", "stack", "reset", "--yes"],
        &[("NOO_REPO_ROOT", &root.display().to_string())],
    );
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be JSON");
    assert_eq!(v["status"].as_str(), Some("ok"));
    assert_eq!(v["action"].as_str(), Some("reset"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ARGS:--yes"));
}

#[test]
fn mesh_ollama_execs_docker_passthrough() {
    let stubs = tmpdir("ollama-stubs");
    stub(&stubs, "docker", "echo \"DOCKER:$*\"");
    let path = stub_path(&stubs);

    // Default action is `list` in the default container.
    let out = run_local(&["stack", "ollama"], &[("PATH", &path)]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("DOCKER:exec noo-ollama ollama list"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Args + --container override pass through verbatim.
    let out = run_local(
        &["stack", "ollama", "show", "qwen3:8b", "-c", "my-ollama"],
        &[("PATH", &path)],
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("DOCKER:exec my-ollama ollama show qwen3:8b"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Exit code propagates from the container command.
    let stubs_fail = tmpdir("ollama-fail");
    stub(&stubs_fail, "docker", "exit 7");
    let out = run_local(&["stack", "ollama", "ps"], &[("PATH", &stub_path(&stubs_fail))]);
    assert_eq!(out.status.code(), Some(7));
}

/// `stack install-watcher` is a retired stub (the bash watcher is gone;
/// noo-hostd runs host commands). With or without the old `--legacy` flag it
/// refuses, names the replacement, and installs nothing — an operator
/// following an old runbook must not get a second host executor.
#[test]
fn mesh_install_watcher_is_a_retired_stub_that_installs_nothing() {
    let root = tmpdir("watcher-retired-root");
    let home = tmpdir("watcher-retired-home");
    let stubs = tmpdir("watcher-retired-stubs");
    std::fs::create_dir_all(root.join("scripts")).unwrap();
    // Reads as a checkout controller (role::detect), so the node-only guard
    // does not answer first on a dev box that is also an enrolled node.
    std::fs::write(root.join(".env"), "").unwrap();
    std::fs::write(root.join("noomesh.yaml"), "").unwrap();
    // Even with the old files present (a stale checkout), nothing installs.
    std::fs::write(root.join("scripts/noo-host-watcher.service"), "[Unit]\nDescription=x\n").unwrap();
    std::fs::write(root.join("scripts/noo-host-watcher.sh"), "sleep 0\n").unwrap();
    stub(&stubs, "systemctl", "exit 0");
    stub(&stubs, "pgrep", "exit 1");
    stub(&stubs, "loginctl", "exit 0");
    for args in [&["stack", "install-watcher"][..], &["stack", "install-watcher", "--legacy"][..]] {
        let out = run_local(
            args,
            &[
                ("NOO_REPO_ROOT", &root.display().to_string()),
                ("HOME", &home.display().to_string()),
                ("PATH", &stub_path(&stubs)),
            ],
        );
        assert_eq!(out.status.code(), Some(1), "{args:?}: the retired verb must refuse");
        let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(all.contains("retired") && all.contains("noo-hostd"), "{args:?}: {all}");
        assert!(all.contains("noo onboard --only services"), "{args:?}: {all}");
        assert!(!all.contains("--legacy"), "{args:?}: still offers the removed rollback: {all}");
        assert!(!home.join(".config/systemd/user/noo-host-watcher.service").exists(), "{args:?}: installed anyway");
    }
}

#[test]
fn models_switch_rewrites_env_yaml_and_recreates_backend() {
    // Sandbox repo root + a recording docker stub: proves the .env rewrite
    // (uncommenting `# VLLM_MODEL=`), the YAML edits, the sops warning, and
    // the exact compose invocations — without touching the live stack.
    let root = tmpdir("switch-root");
    let stubs = tmpdir("switch-stubs");
    let log = root.join("docker.log");
    std::fs::write(
        root.join(".env"),
        "# VLLM_MODEL=old/model\nNOO_SECRETS_BACKEND=sops\n",
    )
    .unwrap();
    std::fs::write(root.join("noomesh.yaml"), "cluster:\n  backends:\n    vllm:\n      model: old/model\n").unwrap();
    std::fs::write(root.join("docker-compose.cluster.yml"), "services: {}\n").unwrap();
    // #43b: the backend recreate goes through the dist-aware restart script,
    // not raw compose — stub it recording its argv alongside the docker stub.
    std::fs::create_dir_all(root.join("scripts")).unwrap();
    std::fs::write(
        root.join("scripts/noomesh-restart.sh"),
        "#!/bin/bash\necho \"restart.sh $*\" >> \"$DOCKER_LOG\"\n",
    )
    .unwrap();
    stub(&stubs, "docker", "echo \"$*\" >> \"$DOCKER_LOG\"");
    let out = run_local(
        &["models", "switch", "QuantTrio/Qwen3.5-9B-AWQ", "-y"],
        &[
            ("NOO_REPO_ROOT", &root.display().to_string()),
            ("PATH", &stub_path(&stubs)),
            ("DOCKER_LOG", &log.display().to_string()),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    // Terminal first (CLI_STYLE_GUIDE rev 2 §2): the confirmation is stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Switched to QuantTrio/Qwen3.5-9B-AWQ"), "stdout: {stdout}");

    // .env: the commented line was replaced by the active assignment.
    let env = std::fs::read_to_string(root.join(".env")).unwrap();
    assert!(env.contains("VLLM_MODEL=QuantTrio/Qwen3.5-9B-AWQ"), ".env: {env}");
    assert!(!env.contains("# VLLM_MODEL="), ".env: {env}");

    // YAML: model + enabled + quantization + terminal.default_model.
    let yaml = std::fs::read_to_string(root.join("noomesh.yaml")).unwrap();
    assert!(yaml.contains("model: QuantTrio/Qwen3.5-9B-AWQ"), "yaml: {yaml}");
    assert!(yaml.contains("enabled: true"), "yaml: {yaml}");
    assert!(yaml.contains("quantization: awq"), "yaml: {yaml}");
    assert!(yaml.contains("default_model: QuantTrio/Qwen3.5-9B-AWQ"), "yaml: {yaml}");

    // sops trap warning (Python is silent here — deliberate one-liner).
    // A warning is narration → stdout (CLI_STYLE_GUIDE rev 2 §2).
    assert!(stdout.contains("NOO_SECRETS_BACKEND=sops"), "stdout: {stdout}");

    // Compose invocations: recreate the backend, then restart the gateway.
    let calls = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = calls.lines().collect();
    assert_eq!(lines.len(), 2, "docker calls: {calls}");
    // #43b: recreate rides the dist-aware script; only the gateway restart
    // is a raw compose call (restart never builds).
    assert!(lines[0].contains("restart.sh --force vllm"), "calls: {calls}");
    assert!(lines[1].contains("restart gateway"), "calls: {calls}");
}

#[test]
fn cluster_seed_applies_config_and_placements() {
    let dir = tmpdir("seed-apply");
    let seed = dir.join("seed.yaml");
    std::fs::write(
        &seed,
        "nodes:\n  nodeA:\n    ip: 10.0.0.5\n    tier: 1\nplacements:\n  - node: nodeA\n    backend: vllm\n    model: org/M\n    port: 8000\n",
    )
    .unwrap();
    let mock = Mock::start(200, "OK", "application/json", r#"{"status":"ok"}"#, 2);
    let out = run(
        &["--gateway", &gw(mock.port), "cluster", "seed", "-f", &seed.display().to_string()],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    // Terminal first (CLI_STYLE_GUIDE rev 2 §2): narration is stdout, plain
    // single-char glyphs, sentence case; stderr is silent on success.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("+ nodeA: config applied"), "stdout: {stdout}");
    assert!(stdout.contains("+ nodeA: vllm → org/M placed"), "stdout: {stdout}");
    assert!(stdout.contains("node-agents reconcile within 5 min"), "stdout: {stdout}");
    assert!(out.stderr.is_empty(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(reqs.len(), 2);
    assert!(reqs[0].starts_with("PUT /api/cluster/nodes/nodeA/config"), "req: {}", reqs[0]);
    assert!(
        reqs[1].starts_with("PUT /api/cluster/nodes/nodeA/placements/vllm"),
        "req: {}",
        reqs[1]
    );
}

#[test]
fn cluster_seed_dry_run_makes_no_requests() {
    let dir = tmpdir("seed-dry");
    let seed = dir.join("seed.yaml");
    std::fs::write(&seed, "nodes:\n  nodeA:\n    ip: 10.0.0.5\nplacements:\n  - node: nodeA\n    backend: vllm\n").unwrap();
    // Closed port: any accidental HTTP call would exit 3, failing the test.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = run(
        &["--gateway", &gw(port), "cluster", "seed", "--dry-run", "-f", &seed.display().to_string()],
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("> Would set-config nodeA:"), "stdout: {stdout}");
    assert!(stdout.contains("> Would place nodeA/vllm:"), "stdout: {stdout}");
}

#[test]
fn cluster_seed_missing_file_errors() {
    let out = run(
        &["--gateway", "http://127.0.0.1:1", "cluster", "seed", "-f", "/nonexistent/seed.yaml"],
        &[],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Seed file not found"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── ACTUAL beside DESIRED ────────────────────────────
//
// The failure these cover: `desired_state: running` was read as "it is
// running" for half an hour while the harness failed to start every five
// minutes. The desired column alone cannot say that, and the node's own
// report was on a different screen.

/// Two calls: the desired-config, then the node list the ACTUAL column reads.
fn desired_mock(desired: &str, nodes: &str) -> Mock {
    Mock::start_seq(vec![ok_json(desired), ok_json(nodes)])
}

#[test]
fn cluster_desired_prints_actual_beside_desired() {
    let desired = r#"{"node":{"data_root":"/opt/noo"},"placements":[
        {"backend":"vllm","model":"gemma","desired_state":"running"},
        {"backend":"harness","model":"auto","desired_state":"running","synthesized":true}]}"#;
    // The node says vllm runs and the harness does NOT, with a reason.
    let nodes = r#"{"nodes":[{"id":"n1","running_backends":{"vllm":"gemma"},
        "host_services":{"harness":{"state":"stopped","runtime":"systemd"}},
        "reconcile_refusals":[{"scope":"backend_start","target":"harness",
        "reason":"the node's privileged helper (noo-hostd) is not running"}]}]}"#;
    let mock = desired_mock(desired, nodes);
    let out = run(&["--gateway", &gw(mock.port), "cluster", "desired", "n1"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.to_lowercase().contains("actual"), "no ACTUAL column:\n{stdout}");
    // The harness row must NOT read as running just because it is desired.
    // The PLACEMENT row, not the node-config `Harness  <policy>` line: both
    // contain the word, and matching the wrong one is how this assertion
    // passes while proving nothing.
    let harness_row = stdout
        .lines()
        .find(|l| l.contains("harness") && l.contains("auto"))
        .unwrap_or_else(|| panic!("no harness placement row in:\n{stdout}"));
    assert!(
        harness_row.to_lowercase().contains("stopped"),
        "the harness is desired-running and actually stopped; the row must say so:\n{harness_row}"
    );
    // And the reason must appear, because "stopped" alone is not actionable.
    assert!(
        stdout.contains("noo-hostd"),
        "the standing refusal names the cause and it must be shown:\n{stdout}"
    );
}

#[test]
fn cluster_desired_shows_a_dash_when_the_node_has_not_reported() {
    // Absence is never a negative (CLI_STYLE_GUIDE §4): a node that has
    // said nothing must not render as "not running".
    let desired = r#"{"node":{"data_root":"/opt/noo"},"placements":[
        {"backend":"vllm","model":"gemma","desired_state":"running"}]}"#;
    let nodes = r#"{"nodes":[]}"#;
    let mock = desired_mock(desired, nodes);
    let out = run(&["--gateway", &gw(mock.port), "cluster", "desired", "n1"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let row = stdout.lines().find(|l| l.contains("vllm")).expect("vllm row");
    assert!(
        !row.to_lowercase().contains("not running"),
        "an unreported node must not render as absence-of-backend:\n{row}"
    );
}

// ── the harness column on `noo cluster status` ──────────────
#[test]
fn cluster_status_shows_harness_state_and_the_reason_it_is_not_running() {
    let body = r#"{"nodes":[
      {"id":"n1","status":"online","nats_state":"connected","nats_role":"node","current_load":0.1,
       "running_backends":{"vllm":"gemma"},"capabilities":{"backends":["vllm"]},
       "host_services":{"harness":{"state":"stopped","runtime":"systemd"}},
       "reconcile_refusals":[{"scope":"backend_start","target":"harness","reason":"the harness keeps exiting (12 restarts)"}]},
      {"id":"n2","status":"online","nats_state":"connected","nats_role":"node","current_load":0.0,
       "running_backends":{"ollama":"x"},"capabilities":{"backends":["ollama"]}}]}"#;
    let stdout = case("GET", "/api/cluster/nodes", 200, body, &["cluster", "status"], 0);
    assert!(stdout.to_lowercase().contains("harness"), "no harness column:\n{stdout}");
    let n1 = stdout.lines().find(|l| l.contains("n1")).expect("n1 row");
    assert!(n1.to_lowercase().contains("stopped"), "n1's harness is stopped and the row must say so:\n{n1}");
    // The reason is what an operator acts on; the cell alone cannot carry it.
    assert!(stdout.contains("12 restarts"), "the standing refusal must be shown:\n{stdout}");
    // Absence is never a negative: n2 reported nothing and must not read as stopped.
    let n2 = stdout.lines().find(|l| l.contains("n2")).expect("n2 row");
    assert!(!n2.to_lowercase().contains("stopped"), "an unreported harness must not render as stopped:\n{n2}");
}

#[test]
fn cluster_seed_export_snapshots_desired_state() {
    let dir = tmpdir("seed-export");
    let seed = dir.join("out/seed.yaml"); // exercises the mkdir(parents) path
    let mock = RouterMock::start(
        vec![
            (
                "/api/cluster/nodes/n1/desired-config",
                200,
                r#"{"node":{"ip_address":"10.0.0.5","tier":1,"data_root":"/data"},"placements":[{"backend":"vllm","model":"org/M","port":8000,"tls":true,"env":{},"desired_state":"running"}]}"#,
            ),
            ("/api/cluster/nodes", 200, r#"{"nodes":[{"id":"n1"}]}"#),
        ],
        2,
    );
    let out = run(
        &["--gateway", &gw(mock.port), "cluster", "seed", "--export", "-f", &seed.display().to_string()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("+ Exported desired state for 1 node(s)"), "stdout: {stdout}");
    // The written path is the captured value: its own plain line.
    assert!(stdout.lines().any(|l| l == seed.display().to_string()), "stdout: {stdout}");
    let text = std::fs::read_to_string(&seed).expect("seed file written");
    assert!(text.contains("n1:"), "yaml: {text}");
    assert!(text.contains("ip: 10.0.0.5"), "yaml: {text}");
    assert!(text.contains("backend: vllm"), "yaml: {text}");
    assert!(text.contains("tls: true"), "yaml: {text}");
    assert!(text.contains("state: running"), "yaml: {text}");
    assert!(!text.contains("env:"), "empty env must be omitted: {text}");
}

// ── WP-4a: approval decide (POST /api/approval/{id}/decide) ──────────────

/// Parse the JSON body out of a captured request (after the header
/// terminator). Panics with the raw request on malformed/missing JSON so
/// assertion failures stay debuggable.
fn body_json(req: &str) -> serde_json::Value {
    let body = req
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or_default();
    serde_json::from_str(body).unwrap_or_else(|e| panic!("bad JSON body ({e}):\n{req}"))
}

#[test]
fn approval_approve_posts_decide_and_exits_zero() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"status":"approved","request_id":"req-1","resolved_by":"cli-operator"}"#,
        1,
    );
    let out = run(&["--gateway", &gw(mock.port), "approval", "approve", "req-1"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(stdout.contains("approved req-1"), "stdout was: {stdout}");
    let req = reqs.first().expect("one captured request");
    assert!(
        req.starts_with("POST /api/approval/req-1/decide"),
        "request was:\n{req}"
    );
    assert_eq!(body_json(req)["decision"], "approve", "request was:\n{req}");
}

#[test]
fn approval_deny_sends_reason_in_body() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"status":"denied","request_id":"req-2","resolved_by":"cli-operator"}"#,
        1,
    );
    let out = run(
        &["--gateway", &gw(mock.port), "approval", "deny", "req-2", "--reason", "not allowed"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).to_lowercase().contains("denied req-2"));
    let req = reqs.first().expect("one captured request");
    assert!(req.starts_with("POST /api/approval/req-2/decide"), "request was:\n{req}");
    let body = body_json(req);
    assert_eq!(body["decision"], "deny", "request was:\n{req}");
    assert_eq!(body["reason"], "not allowed", "request was:\n{req}");
}

#[test]
fn approval_decide_conflict_maps_to_exit_5() {
    // Double-decide: the gateway 409s (already decided) → remote_error (5).
    let mock = Mock::start(
        409,
        "Conflict",
        "application/json",
        r#"{"error":"approval request 'req-3' already approved"}"#,
        1,
    );
    let out = run(&["--gateway", &gw(mock.port), "approval", "approve", "req-3"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5), "409 must map to RemoteError(5)");
}

#[test]
fn approval_decide_missing_id_maps_to_exit_5() {
    let mock = Mock::start(
        404,
        "Not Found",
        "application/json",
        r#"{"error":"approval request 'nope' not found"}"#,
        1,
    );
    let out = run(&["--gateway", &gw(mock.port), "approval", "deny", "nope"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5), "404 must map to RemoteError(5)");
}

#[test]
fn approval_decide_json_mode_passes_raw_body() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"status":"approved","request_id":"req-4","resolved_by":"cli-operator"}"#,
        1,
    );
    let out = run(&["--json", "--gateway", &gw(mock.port), "approval", "approve", "req-4"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(r#""resolved_by""#), "raw JSON expected, got: {stdout}");
}

// ── WP-V: voice — thin HTTP to the gateway voice routes ────────────────────

/// A unique temp file seeded with fake audio bytes; removed on drop.
struct TempAudio(std::path::PathBuf);
impl TempAudio {
    fn new(tag: &str, bytes: &[u8]) -> TempAudio {
        let p = std::env::temp_dir().join(format!(
            "noo-voice-it-{tag}-{}-{:?}.wav",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&p, bytes).expect("write temp audio");
        TempAudio(p)
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}
impl Drop for TempAudio {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn voice_transcribe_uploads_multipart_and_renders_text() {
    let audio = TempAudio::new("tr", b"RIFFfakewavbytes");
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"text":"hello world","language":"en","confidence":0.97,"duration":1.2,"language_probability":0.99}"#,
        1,
    );
    let out = run(&["--gateway", &gw(mock.port), "voice", "transcribe", audio.path()], &[]);
    let reqs = mock.requests();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("hello world"), "text render expected, got: {stdout}");
    // The language line is narration on stdout (terminal first); the
    // transcript is the captured value.
    assert!(stdout.contains("language en"), "info line expected, got: {stdout}");

    // The upload must be multipart/form-data with the audio in a `file` part
    // and the whisper model as a text field (the gateway forwards both).
    let req = reqs.first().expect("captured request");
    let line = req.lines().next().unwrap_or("");
    assert!(
        line.starts_with("POST /api/voice/transcribe "),
        "request line: {line}"
    );
    assert!(req.contains("multipart/form-data; boundary="), "not multipart: {req}");
    assert!(req.contains("name=\"file\""), "file part missing: {req}");
    assert!(req.contains("RIFFfakewavbytes"), "audio bytes missing from body");
    assert!(req.contains("name=\"model\""), "model field missing: {req}");
}

#[test]
fn voice_transcribe_json_emits_python_parity_envelope() {
    let audio = TempAudio::new("trj", b"RIFFx");
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"text":"hi","language":"en","confidence":0.9,"duration":0.5}"#,
        1,
    );
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "voice", "transcribe", audio.path()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON stdout");
    assert_eq!(v["text"], "hi");
    assert_eq!(v["language"], "en");
}

#[test]
fn voice_transcribe_401_maps_to_auth_failed() {
    let audio = TempAudio::new("tr401", b"RIFFx");
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"nope"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "voice", "transcribe", audio.path()], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4), "401 must map to AuthFailed(4)");
}

#[test]
fn voice_synthesize_writes_audio_bytes_to_file() {
    let mock = Mock::start(200, "OK", "audio/wav", "RIFFFAKEAUDIO", 1);
    let out_base = std::env::temp_dir().join(format!("noo-voice-it-syn-{}", std::process::id()));
    let out = run(
        &[
            "--gateway",
            &gw(mock.port),
            "voice",
            "synthesize",
            "hi there",
            "-o",
            out_base.to_str().unwrap(),
        ],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // No extension given → Python's suffix rule appends one from the
    // response content-type (audio/wav → .wav).
    let written = out_base.with_extension("wav");
    let bytes = std::fs::read(&written).expect("synthesized file written");
    let _ = std::fs::remove_file(&written);
    assert_eq!(bytes, b"RIFFFAKEAUDIO");
    // The summary is narration on stdout (terminal first); the path is the value.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("+ Saved 13 bytes"), "human envelope, got: {stdout}");

    // The request is a JSON POST carrying the text.
    let req = reqs.first().expect("captured request");
    assert!(
        req.lines().next().unwrap_or("").starts_with("POST /api/voice/synthesize "),
        "request line: {req}"
    );
    // ureq serializes the JSON body pretty-printed — assert key and value
    // separately rather than a compact `"text":"hi there"` substring.
    assert!(
        req.contains(r#""text""#) && req.contains("hi there"),
        "text payload missing: {req}"
    );
}

#[test]
fn voice_synthesize_401_maps_to_auth_failed() {
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"nope"}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "voice", "synthesize", "hi", "-o", "/tmp/unused-noo-voice"],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4), "401 must map to AuthFailed(4)");
}

#[test]
fn voice_status_renders_gateway_probe() {
    let stdout = case(
        "GET",
        "/api/voice/status",
        200,
        r#"{"stt_available":true,"stt_backend":"faster-whisper","tts_available":true,"tts_backends":["piper","edge-tts"],"piper_available":true,"edge_tts_available":true,"engine":"rust"}"#,
        &["voice", "status"],
        0,
    );
    assert!(stdout.contains("faster-whisper"), "stdout: {stdout}");
    assert!(stdout.contains("available"), "stdout: {stdout}");
    // Plain-mode glyph column (`+`) carries the state without colour.
    assert!(stdout.lines().any(|l| l.trim_start().starts_with('+') && l.contains("faster-whisper")), "stdout: {stdout}");
}

#[test]
fn voice_voices_json_filters_by_backend_with_count() {
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"voices":[{"name":"en_US-lessac-medium","language":"en-US","backend":"piper"},{"name":"en-US-AriaNeural","language":"en-US","gender":"Female","backend":"edge-tts"}],"engine":"rust"}"#,
        1,
    );
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "voice", "voices", "--backend", "piper"],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("JSON stdout");
    assert_eq!(v["count"], 1, "client-side backend filter (Python parity)");
    assert_eq!(v["voices"][0]["name"], "en_US-lessac-medium");
}

// ── WP-TE: tools export (GET /api/tools/registry/raw) ────────────────────
//
// The round-trip safety suite for the WP-A5 finding: `tools export`
// regenerates config/tools.json, and the artifact MUST retain the
// `nats_subject` routing metadata and `extended_tool_groups` that
// /tools/list strips — a stripped write would break NATS tool routing
// cluster-wide.

/// A raw-registry payload in the exact config/tools.json shape, including
/// the two fields the corrupted-regeneration bug would drop.
const RAW_REGISTRY: &str = r#"{
  "_version": 3,
  "_description": "generated",
  "core_tools": [
    {"type": "function",
     "function": {"name": "noo_rag_query", "description": "Search the KB.",
                  "parameters": {"type": "object", "properties": {}}},
     "tags": ["rag"], "speed": "fast", "nats_subject": "worker.rag.query"},
    {"type": "function",
     "function": {"name": "web_search", "description": "Search the web.",
                  "parameters": {"type": "object", "properties": {}}},
     "tags": [], "speed": "slow"}
  ],
  "extended_tool_groups": {
    "research": {"tools": ["web_search"], "keywords": ["research", "look up"]}
  }
}"#;

#[test]
fn tools_export_round_trip_keeps_routing_metadata() {
    let target = std::env::temp_dir().join(format!(
        "noo-cli-tools-export-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&target);
    let mock = Mock::start(200, "OK", "application/json", RAW_REGISTRY, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "tools", "export",
          "-o", target.to_str().unwrap()],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        reqs[0].starts_with("GET /api/tools/registry/raw"),
        "request line: {}",
        reqs[0].lines().next().unwrap_or("")
    );

    let written = std::fs::read_to_string(&target).expect("export file written");
    assert!(written.ends_with('\n'), "trailing newline (Python parity)");
    let parsed: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
    // THE regression assertions (WP-A5): routing metadata survives the
    // fetch → write round trip byte-for-parse.
    assert_eq!(
        parsed["core_tools"][0]["nats_subject"].as_str(),
        Some("worker.rag.query"),
        "nats_subject must survive export"
    );
    assert_eq!(
        parsed["extended_tool_groups"]["research"]["keywords"][1].as_str(),
        Some("look up"),
        "extended_tool_groups must survive export"
    );
    // Deep-equal with the gateway payload: nothing stripped, nothing added
    // (dict key order irrelevant — same contract as Python tools_json_matches).
    let sent: serde_json::Value = serde_json::from_str(RAW_REGISTRY).unwrap();
    assert_eq!(parsed, sent, "export must be a lossless render of the registry");
    // A tool without nats_subject stays without one (no key invented).
    assert!(parsed["core_tools"][1].get("nats_subject").is_none());

    // Terminal first: the write summary, the path (the captured value) and
    // the guidance are all on stdout; the path is on its own line.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("2 tools"), "stdout: {stdout}");
    assert!(stdout.lines().any(|l| l == target.to_str().unwrap()), "stdout: {stdout}");
    assert!(stdout.contains("> noo tools export --check"), "guidance expected: {stdout}");
    assert!(out.stderr.is_empty(), "stderr must be empty on success: {}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_file(&target);

    // --quiet keeps only the captured value.
    let mock = Mock::start(200, "OK", "application/json", RAW_REGISTRY, 1);
    let out = run(
        &["--quiet", "--gateway", &gw(mock.port), "tools", "export",
          "-o", target.to_str().unwrap()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim_end(), target.to_str().unwrap(), "--quiet prints only the path");
    let _ = std::fs::remove_file(&target);
}

#[test]
fn tools_export_refuses_stripped_payload() {
    // A /tools/list-shaped body (what the corrupted thin-HTTP port would
    // have consumed) must be REFUSED, and no file written.
    let target = std::env::temp_dir().join(format!(
        "noo-cli-tools-export-stripped-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&target);
    let mock = Mock::start(
        200,
        "OK",
        "application/json",
        r#"{"tools": [{"name": "noo_rag_query"}], "stats": {"total": 1}}"#,
        1,
    );
    let out = run(
        &["--gateway", &gw(mock.port), "tools", "export",
          "-o", target.to_str().unwrap()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(1), "stripped payload must exit 1");
    assert!(!target.exists(), "no file may be written from a stripped payload");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing"), "stderr: {stderr}");
}

#[test]
fn tools_export_check_matches_and_mismatches() {
    let target = std::env::temp_dir().join(format!(
        "noo-cli-tools-export-check-{}.json",
        std::process::id()
    ));
    // Seed the file via a real export, then --check must pass…
    let mock = Mock::start(200, "OK", "application/json", RAW_REGISTRY, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "tools", "export",
          "-o", target.to_str().unwrap()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));

    let mock = Mock::start(200, "OK", "application/json", RAW_REGISTRY, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "tools", "export", "--check",
          "-o", target.to_str().unwrap()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "check after export must pass");

    // …and after the registry changes (a nats_subject retarget — the exact
    // metadata class at stake), --check must fail WITHOUT touching the file.
    let changed = RAW_REGISTRY.replace("worker.rag.query", "worker.rag.query2");
    let before = std::fs::read_to_string(&target).unwrap();
    let mock = Mock::start(200, "OK", "application/json", &changed, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "tools", "export", "--check",
          "-o", target.to_str().unwrap()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(1), "out-of-date check must exit 1");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        before,
        "--check must never write"
    );
    let _ = std::fs::remove_file(&target);
}

#[test]
fn tools_export_auth_failure_maps_to_exit_4() {
    let target = std::env::temp_dir().join(format!(
        "noo-cli-tools-export-401-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&target);
    let mock = Mock::start(
        401,
        "Unauthorized",
        "application/json",
        r#"{"detail":"Not authenticated"}"#,
        1,
    );
    let out = run(
        &["--gateway", &gw(mock.port), "tools", "export",
          "-o", target.to_str().unwrap()],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4), "401 must map to AuthFailed(4)");
    assert!(!target.exists(), "no file may be written on auth failure");
}

// ═══════════════════════════════════════════════════════════════════════
// WP-R: models refresh — HF-mocked catalog rebuild (TTL bypass), the shared
// model_cache.json shape (round-trip compatible with the Python CLI), and
// the --llm coordinator eval (mock gateway). Same isolation pattern as the
// WP-A2 block: per-test temp HOME + HF_ENDPOINT, vendors pinned via
// NOO_MODEL_VENDORS to keep the HF request count deterministic
// (vendors=llama → exactly ONE search query for the llamacpp backend).
// ═══════════════════════════════════════════════════════════════════════

/// One HF /api/models search result for a llama GGUF model (approved vendor).
const HF_LLAMA_GGUF: &str = r#"[{"modelId":"bartowski/Llama-3.2-3B-Instruct-GGUF","tags":["gguf","text-generation"],"downloads":500000,"likes":77,"gated":false}]"#;

fn read_cache_file(home: &str) -> serde_json::Value {
    let path = std::path::Path::new(home).join(".config/mesh/model_cache.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cache file missing at {}: {e}", path.display()));
    serde_json::from_str(&text).expect("cache file is JSON")
}

#[test]
fn models_refresh_bypasses_ttl_and_writes_python_shaped_cache() {
    let home_dir = temp_home("refresh");
    let home = home_dir.to_string_lossy().into_owned();
    // Pre-seed a FRESH cache (now-timestamp, well inside the 24h TTL) with a
    // stale entry: `models list` would serve it, but `refresh` must ignore
    // the TTL, hit HF, and overwrite the backend's entry.
    let cfg = std::path::Path::new(&home).join(".config/mesh");
    std::fs::create_dir_all(&cfg).unwrap();
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    std::fs::write(
        cfg.join("model_cache.json"),
        format!(
            r#"{{"catalogs":{{"llamacpp":[{{"id":"stale/model"}}]}},"fetched_at":{{"llamacpp":"{now}"}},"ttl_hours":24}}"#
        ),
    )
    .unwrap();

    let mock = Mock::start(200, "OK", "application/json", HF_LLAMA_GGUF, 1);
    let out = run(
        &["--json", "models", "refresh", "--backend", "llamacpp"],
        &[
            ("HOME", &home),
            ("HF_ENDPOINT", &gw(mock.port)),
            ("NOO_MODEL_VENDORS", "llama"),
        ],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    // TTL bypass proven: HF was queried despite the fresh cache.
    let req = reqs.first().expect("refresh must hit HF even with a fresh cache");
    assert!(
        req.contains("GET /api/models?search=llama%20GGUF&"),
        "vendor-targeted search expected, got:\n{req}"
    );
    // The task axis is applied client-side — a server-side
    // `filter=text-generation` used to drop every multimodal chat model.
    assert!(!req.contains("filter="), "no server-side pipeline filter expected, got:\n{req}");

    // Envelope contract.
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["action"], "refresh");
    assert_eq!(v["llm"], false);
    assert_eq!(v["summary"]["llamacpp"]["count"], 1);
    assert_eq!(v["summary"]["llamacpp"]["status"], "refreshed");
    assert_eq!(v["total"], 1);
    assert!(v["cache"].as_str().unwrap().ends_with(".config/mesh/model_cache.json"));

    // Cache file shape: EXACTLY what Python's ModelCatalog._write_cache
    // produces — {"catalogs": {be: [entry…]}, "fetched_at": {be: iso},
    // "ttl_hours": 24} with the normalized per-model schema. Python reads
    // this file back via datetime.fromisoformat + dict lookups.
    let cache = read_cache_file(&home);
    assert_eq!(
        cache.as_object().unwrap().keys().collect::<Vec<_>>().len(),
        3,
        "top-level keys must be exactly catalogs/fetched_at/ttl_hours: {cache}"
    );
    assert_eq!(cache["ttl_hours"], 24.0);
    let entry = &cache["catalogs"]["llamacpp"][0];
    assert_eq!(entry["id"], "bartowski/Llama-3.2-3B-Instruct-GGUF", "stale entry must be overwritten");
    for key in [
        "id", "params_b", "quant", "gated", "downloads", "likes", "desc",
        "backends", "tier", "size_estimate", "tool_parser", "vram_gb",
    ] {
        assert!(entry.get(key).is_some(), "normalized entry missing `{key}`: {entry}");
    }
    assert_eq!(entry["quant"], "GGUF");
    assert_eq!(entry["gated"], "Open");
    // fetched_at must be RFC3339 with an offset — the form BOTH sides parse
    // (Rust: time::Rfc3339; Python: datetime.fromisoformat, which accepts
    // 'Z'/offset + any fractional-second length on 3.11+).
    let fetched = cache["fetched_at"]["llamacpp"].as_str().unwrap();
    time::OffsetDateTime::parse(fetched, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|e| panic!("fetched_at not RFC3339 ({fetched}): {e}"));
}

#[test]
fn models_refresh_reads_python_written_cache_back() {
    // Round-trip, Python→Rust direction: a cache file written the way
    // Python writes it (microsecond "+00:00" isoformat timestamps) must be
    // served by the Rust side within TTL (`models list`, no --refresh, HF
    // dead → the cached entry, NOT the offline fallback).
    let home_dir = temp_home("pycache");
    let home = home_dir.to_string_lossy().into_owned();
    let cfg = std::path::Path::new(&home).join(".config/mesh");
    std::fs::create_dir_all(&cfg).unwrap();
    let now = time::OffsetDateTime::now_utc();
    // Python: datetime.now(timezone.utc).isoformat() → "…T…:SS.ffffff+00:00".
    let py_iso = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.123456+00:00",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    std::fs::write(
        cfg.join("model_cache.json"),
        format!(
            r#"{{"catalogs":{{"ollama":[{{"id":"llama3.2:3b","params_b":3,"quant":"GGUF","gated":"Open","downloads":3000000,"likes":0,"desc":"from python cache","backends":["ollama"],"tier":3,"size_estimate":"1.8GB","tool_parser":"llama3_json","vram_gb":3.0}}]}},"fetched_at":{{"ollama":"{py_iso}"}},"ttl_hours":24}}"#
        ),
    )
    .unwrap();

    let out = run(
        &["--json", "models", "ollama", "--limit", "5"],
        &[("HOME", &home), ("HF_ENDPOINT", &dead_url())],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let arr = v.as_array().expect("array envelope");
    assert_eq!(arr.len(), 1, "the Python-written cache entry must be served: {v}");
    assert_eq!(arr[0]["id"], "llama3.2:3b");
    assert_eq!(arr[0]["desc"], "from python cache");
}

#[test]
fn models_refresh_llm_posts_coordinator_eval_and_stores_in_cache() {
    let home_dir = temp_home("refreshllm");
    let home = home_dir.to_string_lossy().into_owned();
    let hf = Mock::start(200, "OK", "application/json", HF_LLAMA_GGUF, 1);
    // The coordinator's reply embeds the JSON array in prose — the parser
    // must take first-'['..last-']' (Python's greedy `\[.*\]` DOTALL).
    let gw_body = r#"{"response":"Here is my analysis:\n[{\"id\": \"bartowski/Llama-3.2-3B-Instruct-GGUF\", \"tool_parser\": \"llama3_json\", \"tool_calling\": true, \"reasoning\": false, \"agentic_quality\": \"good\"}]\nDone."}"#;
    let gateway = Mock::start(200, "OK", "application/json", gw_body, 1);
    let out = run(
        &[
            "--json",
            "--gateway",
            &gw(gateway.port),
            "models",
            "refresh",
            "--backend",
            "llamacpp",
            "--llm",
        ],
        &[
            ("HOME", &home),
            ("HF_ENDPOINT", &gw(hf.port)),
            ("NOO_MODEL_VENDORS", "llama"),
        ],
    );
    let _ = hf.requests();
    let gw_reqs = gateway.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // The coordinator request: POST /api/inference with the eval prompt and
    // max_iterations 1 (the exact body Python sends).
    let req = gw_reqs.first().expect("one coordinator request");
    assert!(req.starts_with("POST /api/inference "), "request line:\n{req}");
    // ureq pretty-prints the JSON body — compare whitespace-insensitively.
    let compact: String = req.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains(r#""max_iterations":1"#), "max_iterations missing:\n{req}");
    assert!(
        req.contains("Analyze these AI models for our local inference cluster"),
        "eval prompt missing:\n{req}"
    );
    assert!(
        req.contains("bartowski/Llama-3.2-3B-Instruct-GGUF"),
        "model summary line missing:\n{req}"
    );

    // Envelope reflects the LLM pass…
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["llm"], true);
    assert_eq!(v["summary"]["llamacpp"]["status"], "refreshed");

    // …and the enrichment is stored IN THE CACHE FILE (Python parity: the
    // eval result lives client-side in model_cache.json, not on the server).
    let cache = read_cache_file(&home);
    let entry = &cache["catalogs"]["llamacpp"][0];
    assert_eq!(entry["agentic_quality"], "good");
    assert_eq!(entry["tool_calling"], true);
    assert_eq!(entry["reasoning"], false);
    assert_eq!(entry["tool_parser"], "llama3_json");
}

#[test]
fn models_refresh_llm_gateway_down_is_best_effort() {
    // Coordinator unreachable → the refresh itself must still succeed and
    // write the un-enriched catalog (Python wraps the LLM call in
    // try/except-pass).
    let home_dir = temp_home("refreshllmdown");
    let home = home_dir.to_string_lossy().into_owned();
    let hf = Mock::start(200, "OK", "application/json", HF_LLAMA_GGUF, 1);
    let dead = dead_url();
    let out = run(
        &[
            "--json",
            "--gateway",
            &dead,
            "models",
            "refresh",
            "--backend",
            "llamacpp",
            "--llm",
        ],
        &[
            ("HOME", &home),
            ("HF_ENDPOINT", &gw(hf.port)),
            ("NOO_MODEL_VENDORS", "llama"),
        ],
    );
    let _ = hf.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["summary"]["llamacpp"]["count"], 1);
    let cache = read_cache_file(&home);
    let entry = &cache["catalogs"]["llamacpp"][0];
    assert!(entry.get("agentic_quality").is_none(), "no enrichment expected: {entry}");
}

#[test]
fn models_refresh_all_backends_failed_exits_1() {
    // HF unreachable for every backend → summary full of errors, exit 1
    // (documented deviation: Python exits 0 even on total failure).
    let home_dir = temp_home("refreshdead");
    let home = home_dir.to_string_lossy().into_owned();
    let out = run(
        &["--json", "models", "refresh", "--backend", "vllm"],
        &[("HOME", &home), ("HF_ENDPOINT", &dead_url())],
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["status"], "error");
    assert_eq!(v["summary"]["vllm"]["count"], 0);
    assert!(
        v["summary"]["vllm"]["status"].as_str().unwrap().starts_with("error:"),
        "error status expected: {v}"
    );
}

// ───────────────────────────────────────────────────────────────────────
// WP-M: `mcp tools` (hub streamable-http JSON-RPC) + `mcp external-setup`
// ───────────────────────────────────────────────────────────────────────

/// SSE-framed streamable-http response carrying one JSON-RPC message, with
/// an optional Mcp-Session-Id header (the initialize response sets it).
fn sse_response(session: Option<&str>, rpc: &str) -> String {
    let body = format!("event: message\r\ndata: {rpc}\r\n\r\n");
    let sid = session
        .map(|s| format!("Mcp-Session-Id: {s}\r\n"))
        .unwrap_or_default();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{sid}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// The mock hub's canned exchange: initialize → 202 initialized →
/// tools/list (one PAI-native + one external tool) → session DELETE.
fn mock_hub_exchange() -> Vec<String> {
    vec![
        sse_response(
            Some("sess-42"),
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"mesh-hub","version":"1"}}}"#,
        ),
        http_response(202, "Accepted", "application/json", ""),
        sse_response(
            None,
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"noo_inference","description":"Run a prompt on the cluster","inputSchema":{"type":"object"}},{"name":"mcp_github_create_issue","description":"Create a GitHub issue","inputSchema":{"type":"object"}}]}}"#,
        ),
        http_response(200, "OK", "application/json", "{}"),
    ]
}

/// `noo mcp tools` dials the operator door on the GATEWAY URL (the
/// dedicated hub host/port pair went with the 3100 listener in
/// stack-v0.2.40), so the mock stands in for the gateway.
fn mcp_env(port: u16, token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("NOO_GATEWAY_URL", format!("http://127.0.0.1:{port}")),
        ("NOO_MCP_KEY", token.to_string()),
    ]
}

#[test]
fn mcp_tools_lists_hub_catalog_with_sources() {
    let mock = Mock::start_seq(mock_hub_exchange());
    let env = mcp_env(mock.port, "hub-tok");
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let out = run(&["mcp", "tools"], &env);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("noo_inference"), "missing native tool: {stdout}");
    assert!(stdout.contains("mcp_github_create_issue"), "missing external tool: {stdout}");
    assert!(stdout.contains("external"), "source column expected: {stdout}");
    // The wire exchange: initialize with bearer, initialized + tools/list
    // rides the session id, DELETE cleans up.
    // (bodies are serialized with whitespace — assert on the quoted method
    // names, not exact compact JSON)
    assert!(reqs[0].starts_with("POST /mcp/operator "), "the operator door on the gateway, not a hub path: {}", reqs[0]);
    assert!(reqs[0].contains("\"initialize\""), "req0: {}", reqs[0]);
    assert!(reqs[0].contains("Bearer hub-tok"), "bearer expected: {}", reqs[0]);
    assert!(reqs[1].contains("notifications/initialized"), "req1: {}", reqs[1]);
    assert!(reqs[1].to_lowercase().contains("mcp-session-id: sess-42"), "session id expected: {}", reqs[1]);
    assert!(reqs[2].contains("\"tools/list\""), "req2: {}", reqs[2]);
    assert!(reqs[3].starts_with("DELETE "), "session DELETE expected: {}", reqs[3]);
}

#[test]
fn mcp_tools_json_prints_raw_tools_list_result() {
    let mock = Mock::start_seq(mock_hub_exchange());
    let env = mcp_env(mock.port, "");
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let out = run(&["--json", "mcp", "tools"], &env);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("stdout must be pure JSON");
    assert_eq!(v["tools"].as_array().map(Vec::len), Some(2), "raw result envelope: {stdout}");
    // No NOO_MCP_KEY → no Authorization header on the hub exchange.
    assert!(!reqs[0].contains("Authorization:"), "no bearer expected: {}", reqs[0]);
}

/// The shared NOO_MCP_TOKEN is retired: a client that still has it set and
/// no key sends NO bearer (the door would refuse the token anyway) and is
/// told, on stderr, what replaces it.
#[test]
fn mcp_tools_never_sends_the_retired_shared_token() {
    let mock = Mock::start_seq(mock_hub_exchange());
    let env = [
        ("NOO_GATEWAY_URL", format!("http://127.0.0.1:{}", mock.port)),
        ("NOO_MCP_KEY", String::new()),
        ("NOO_MCP_TOKEN", "legacy-shared-tok".to_string()),
    ];
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let out = run(&["mcp", "tools"], &env);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!reqs[0].contains("legacy-shared-tok"), "the retired token went on the wire: {}", reqs[0]);
    assert!(!reqs[0].contains("Authorization:"), "no bearer expected: {}", reqs[0]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("NOO_MCP_TOKEN is retired"), "stderr: {stderr}");
    assert!(stderr.contains("service-key issue"), "stderr: {stderr}");
}

#[test]
fn mcp_tools_unreachable_hub_maps_to_exit_3() {
    let port = closed_port();
    let env = mcp_env(port, "");
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let out = run(&["mcp", "tools"], &env);
    assert_eq!(out.status.code(), Some(3), "unreachable hub must exit 3");
}

#[test]
fn mcp_tools_auth_rejection_maps_to_exit_4() {
    let mock = Mock::start(401, "Unauthorized", "text/plain", "Unauthorized", 1);
    let env = mcp_env(mock.port, "wrong");
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let out = run(&["mcp", "tools"], &env);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4), "401 from the hub must exit 4");
}

/// Temp repo root for the external-setup tests (it must not write one).
fn temp_repo(name: &str, env_content: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("noo-wpm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".env"), env_content).unwrap();
    dir
}

/// `mcp external-setup` was a token minter until 2026-08-03. It printed a
/// fresh NOO_MCP_EXTERNAL_TOKEN and, with `--save`, appended it to `.env`.
/// That variable is retired and no door accepts it, so the command must now
/// mint NOTHING, write NOTHING, and say what to do instead. Exit 2, because
/// it did not do what the operator asked.
#[test]
fn mcp_external_setup_mints_nothing_and_points_at_service_keys() {
    let dir = temp_repo("retired", "EXISTING=1\n");
    let out = run(
        &["mcp", "external-setup"],
        &[
            ("NOO_REPO_ROOT", dir.to_str().unwrap()),
            ("NOO_SECRETS_BACKEND", ""),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The runbook prints in full on stdout (CLI_STYLE_GUIDE rev 2 §5).
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `service-key self` is the only verb that yields a door-usable key:
    // the door refuses any key not bound to an account and `issue` cannot
    // name one, so the runbook must point at `self`.
    assert!(
        stdout.contains("noo security service-key self"),
        "must name the replacement: {stdout}"
    );
    assert!(
        stdout.contains("NOO_MCP_EXTERNAL_ENABLED"),
        "must name the switch that opens the door: {stdout}"
    );
    // The credential must not reappear anywhere in the output.
    assert!(
        !stdout.contains("NOO_MCP_EXTERNAL_TOKEN="),
        "no token is minted: {stdout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// `--save` used to append the token to `.env`. It is now accepted and
/// ignored — an operator with the old invocation in their history reaches the
/// explanation instead of an argument error, and the file is untouched.
#[test]
fn mcp_external_setup_save_no_longer_writes_env() {
    let dir = temp_repo("retired-save", "EXISTING=1");
    let out = run(
        &["mcp", "external-setup", "--save"],
        &[
            ("NOO_REPO_ROOT", dir.to_str().unwrap()),
            ("NOO_SECRETS_BACKEND", ""),
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        std::fs::read_to_string(dir.join(".env")).unwrap(),
        "EXISTING=1",
        ".env must be byte-identical"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mcp_external_setup_json_envelope_reports_retirement() {
    let dir = temp_repo("retired-json", "");
    let out = run(
        &["--json", "mcp", "external-setup"],
        &[
            ("NOO_REPO_ROOT", dir.to_str().unwrap()),
            ("NOO_SECRETS_BACKEND", ""),
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("pure JSON stdout");
    assert_eq!(v["retired"], true, "{v}");
    assert!(v["token"].is_null(), "no token field: {v}");
    assert!(
        v["door"].as_str().unwrap_or("").ends_with("/mcp/user"),
        "{v}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ═══════════════════════════════════════════════════════════════════════
// CLI per-user auth.
//
// The contract under test is credential RESOLUTION — --token → $NOO_TOKEN →
// the stored credential file → nothing (the shared-secret lane was removed
// 2026-10-03) — plus the storage permissions, the 401 message naming which
// of those was actually sent, and the `auth login/status/logout` round
// trip. Gateway-side auth is untouched by this work, so every case here is
// the CLI driven against the same mock harness.
// ═══════════════════════════════════════════════════════════════════════

/// Write a credential file for one test and return its path. `expires_at` is
/// absolute unix seconds so cases can make a token look fresh or stale.
fn temp_credentials(tag: &str, access: &str, expires_at: u64, refresh: Option<&str>) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("noo-cli-cred-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create cred dir");
    let path = dir.join("credentials.json");
    let body = serde_json::json!({
        "version": 1,
        "gateway": "http://127.0.0.1:1",
        "subject": "alice",
        "scopes": ["read", "write"],
        "access_token": access,
        "expires_at": expires_at,
        "refresh_token": refresh,
        // The refresh lifetime is INDEPENDENT of the access lifetime (30 days
        // vs 15 minutes) — that asymmetry is the whole point of refresh, so a
        // stale access token here must still have a live refresh beside it.
        "refresh_expires_at": far_future() + 86_400,
    });
    std::fs::write(&path, serde_json::to_string(&body).unwrap()).expect("write creds");
    path
}

fn far_future() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600
}

/// Extract the `Authorization:` header value from a captured raw request.
fn auth_header(req: &str) -> Option<String> {
    req.lines()
        .find(|l| l.to_lowercase().starts_with("authorization:"))
        .map(|l| l[l.find(':').unwrap() + 1..].trim().to_string())
}

#[test]
fn explicit_token_flag_outranks_env_file_and_hmac() {
    let creds = temp_credentials("flag", "file-token", far_future(), None);
    let mock = Mock::start(200, "OK", "application/json", r#"{"running":true}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "--token", "flag-token", "heartbeat", "status"],
        &[
            ("NOO_TOKEN", "env-token"),
            ("NOO_CLUSTER_SECRET", "hmac-secret"),
            ("NOO_CREDENTIALS_FILE", creds.to_str().unwrap()),
        ],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(auth_header(&reqs[0]).as_deref(), Some("Bearer flag-token"));
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn env_token_outranks_the_credential_file_and_hmac() {
    let creds = temp_credentials("env", "file-token", far_future(), None);
    let mock = Mock::start(200, "OK", "application/json", r#"{"running":true}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[
            ("NOO_TOKEN", "env-token"),
            ("NOO_CLUSTER_SECRET", "hmac-secret"),
            ("NOO_CREDENTIALS_FILE", creds.to_str().unwrap()),
        ],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(auth_header(&reqs[0]).as_deref(), Some("Bearer env-token"));
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn stored_credential_is_sent_and_no_secret_with_it() {
    let creds = temp_credentials("file", "file-token", far_future(), None);
    let mock = Mock::start(200, "OK", "application/json", r#"{"running":true}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[
            ("NOO_CLUSTER_SECRET", "hmac-secret"),
            ("NOO_CREDENTIALS_FILE", creds.to_str().unwrap()),
        ],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(auth_header(&reqs[0]).as_deref(), Some("Bearer file-token"));
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn a_configured_secret_sends_no_header() {
    // A configured NOO_CLUSTER_SECRET is never sent — the shared secret is
    // not a CLI credential at all (2026-10-03).
    let mock = Mock::start(200, "OK", "application/json", r#"{"running":true}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_CLUSTER_SECRET", "hmac-secret")],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(auth_header(&reqs[0]).is_none(), "secret must not be sent implicitly");
}

#[test]
fn no_credential_at_all_sends_no_authorization_header() {
    let mock = Mock::start(200, "OK", "application/json", r#"{"running":true}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "heartbeat", "status"], &[]);
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    assert!(auth_header(&reqs[0]).is_none(), "expected no bearer, got: {}", reqs[0]);
}

#[test]
fn a_401_names_the_credential_that_was_sent() {
    // Each source must produce a DIFFERENT, specific message — the old text
    // always said "is NOO_CLUSTER_SECRET set in the repo .env?" regardless.
    let creds = temp_credentials("401", "file-token", far_future(), None);
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (vec![("NOO_TOKEN", "env-token")], "$NOO_TOKEN"),
        (
            vec![("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
            "stored credential",
        ),
        // A secret plus the old opt-in is still "no credential".
        (vec![("NOO_CLUSTER_SECRET", "s"), ("NOO_BREAK_GLASS", "1")], "no credential"),
        (vec![], "no credential"),
    ];
    for (env, expect) in cases {
        let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"nope"}"#, 1);
        let out = run(&["--gateway", &gw(mock.port), "heartbeat", "status"], &env);
        let _ = mock.requests();
        assert_eq!(out.status.code(), Some(4), "401 must still exit 4");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expect), "expected {expect:?} in: {stderr}");
        assert!(stderr.contains("noo auth login"), "expected a fix hint in: {stderr}");
    }
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn a_401_in_json_mode_keeps_the_typed_envelope() {
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"nope"}"#, 1);
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_TOKEN", "env-token")],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).expect("JSON error envelope");
    assert_eq!(v["code"], "auth_failed");
    assert!(v["error"].as_str().unwrap().contains("$NOO_TOKEN"));
    assert!(v["hint"].as_str().unwrap().contains("noo auth login"));
}

#[test]
fn expired_stored_credential_is_refreshed_before_the_request() {
    // Access tokens are 15 min by design; without transparent refresh the CLI
    // would be unusable. Sequence: POST /api/auth/refresh → the real command.
    let creds = temp_credentials("refresh", "stale-token", 1, Some("raw-refresh"));
    let refresh_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Set-Cookie: noo_refresh=rotated-refresh; HttpOnly; Path=/api/auth\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        r#"{"access_token":"fresh-token","expires_in":900}"#.len(),
        r#"{"access_token":"fresh-token","expires_in":900}"#
    );
    let mock = Mock::start_seq(vec![refresh_resp, ok_json(r#"{"running":true}"#)]);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/auth/refresh"), "first call must refresh: {}", reqs[0]);
    assert!(
        reqs[0].contains("noo_refresh=raw-refresh"),
        "refresh must replay the stored cookie: {}",
        reqs[0]
    );
    assert_eq!(auth_header(&reqs[1]).as_deref(), Some("Bearer fresh-token"));
    // The rotated refresh + new access token are persisted for next time.
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&creds).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "fresh-token");
    assert_eq!(stored["refresh_token"], "rotated-refresh");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn a_rejected_refresh_sends_no_credential_rather_than_a_dead_token_or_a_secret() {
    let creds = temp_credentials("deadref", "stale-token", 1, Some("raw-refresh"));
    let mock = Mock::start_seq(vec![
        http_response(401, "Unauthorized", "application/json", r#"{"detail":"expired"}"#),
        ok_json(r#"{"running":true}"#),
    ]);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[
            ("NOO_CREDENTIALS_FILE", creds.to_str().unwrap()),
            ("NOO_CLUSTER_SECRET", "hmac-secret"),
            ("NOO_BREAK_GLASS", "1"),
        ],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/auth/refresh"));
    assert!(
        auth_header(&reqs[1]).is_none(),
        "a dead stored token must not be sent, and no secret takes its place: {}",
        reqs[1]
    );
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

// ── phase 2: refresh-on-401 ────────────────────────────────────────────────
//
// Refresh-on-expiry (above) covers the normal path. These cases cover the
// gateway rejecting a token the CLI still believes is live — early
// revocation, a rotated JWT secret, clock skew. The contract is narrow on
// purpose: ONE refresh, ONE retry, only on 401, never a loop.
//
// Harness note: the mock serves exactly as many responses as it is primed
// with, so every case here states the exact request count it expects. A case
// primed for MORE requests than the command makes waits out ACCEPT_TIMEOUT.

/// A 200-with-rotation refresh response, as the gateway sends it.
fn refresh_ok(access: &str, rotated: &str) -> String {
    let body = format!(r#"{{"access_token":"{access}","token_type":"bearer","expires_in":900}}"#);
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Set-Cookie: noo_refresh={rotated}; HttpOnly; Path=/api/auth\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn a_401_triggers_exactly_one_refresh_and_one_retry() {
    // The stored access token is NOT expired — only the gateway's 401 can
    // trigger this refresh, which is the whole point of the case.
    let creds = temp_credentials("retry401", "revoked-token", far_future(), Some("raw-refresh"));
    let mock = Mock::start_seq(vec![
        http_response(401, "Unauthorized", "application/json", r#"{"detail":"Invalid token"}"#),
        refresh_ok("fresh-token", "rotated-refresh"),
        ok_json(r#"{"running":true}"#),
    ]);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(reqs.len(), 3, "expected request → refresh → retry, got {} requests", reqs.len());
    assert_eq!(auth_header(&reqs[0]).as_deref(), Some("Bearer revoked-token"));
    assert!(reqs[1].starts_with("POST /api/auth/refresh"), "second call must refresh: {}", reqs[1]);
    assert!(reqs[1].contains("noo_refresh=raw-refresh"), "{}", reqs[1]);
    assert!(reqs[2].starts_with("GET /api/heartbeat/status"), "retry the SAME request: {}", reqs[2]);
    assert_eq!(auth_header(&reqs[2]).as_deref(), Some("Bearer fresh-token"));

    // The rotated pair is persisted, at the same permissions, so the next
    // invocation starts from the refreshed credential.
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&creds).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "fresh-token");
    assert_eq!(stored["refresh_token"], "rotated-refresh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&creds).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a refresh must not widen the credential's permissions");
        let dmode = std::fs::metadata(creds.parent().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "the credential dir must stay owner-only");
    }
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn a_401_after_the_retry_exits_4_without_looping() {
    // The gateway rejects the freshly-minted token too (disabled account,
    // rotated JWT secret). That is a real answer: stop, do not refresh again.
    let creds = temp_credentials("noloop", "revoked-token", far_future(), Some("raw-refresh"));
    let mock = Mock::start_seq(vec![
        http_response(401, "Unauthorized", "application/json", r#"{"detail":"Invalid token"}"#),
        refresh_ok("fresh-token", "rotated-refresh"),
        http_response(401, "Unauthorized", "application/json", r#"{"detail":"Invalid token"}"#),
    ]);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(4), "a second 401 keeps the exit-4 contract");
    assert_eq!(reqs.len(), 3, "exactly one retry — no loop; got {} requests", reqs.len());
    let refreshes = reqs.iter().filter(|r| r.starts_with("POST /api/auth/refresh")).count();
    assert_eq!(refreshes, 1, "exactly one refresh may be attempted per process");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn a_403_never_triggers_a_refresh() {
    // 403 is an AUTHORISATION answer about a credential the gateway accepted.
    // Re-minting the same identity cannot change it, and burning a single-use
    // refresh token to learn that costs the operator their session.
    let creds = temp_credentials("forbidden", "read-only-token", far_future(), Some("raw-refresh"));
    let mock = Mock::start_seq(vec![http_response(
        403,
        "Forbidden",
        "application/json",
        r#"{"detail":"Insufficient scope"}"#,
    )]);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(4), "403 keeps the documented exit-4 mapping");
    assert_eq!(reqs.len(), 1, "a 403 must produce no refresh and no retry: {reqs:?}");
    assert!(!reqs[0].starts_with("POST /api/auth/refresh"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("automatic refresh"),
        "no refresh was attempted, so none may be reported: {stderr}"
    );
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn a_failed_refresh_after_a_401_says_exactly_what_broke() {
    // The gateway's own words ("already used (suspected reuse)" — the theft
    // sweep in routes/core.rs) are the difference between "log in again" and
    // "someone else has your refresh token". A bare 401 says neither.
    let creds = temp_credentials("reffail", "revoked-token", far_future(), Some("raw-refresh"));
    let mock = Mock::start_seq(vec![
        http_response(401, "Unauthorized", "application/json", r#"{"detail":"Invalid token"}"#),
        http_response(
            401,
            "Unauthorized",
            "application/json",
            r#"{"detail":"Refresh token already used (suspected reuse)"}"#,
        ),
    ]);
    let out = run(
        &["--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(reqs.len(), 2, "one request + one failed refresh, then stop: {reqs:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("stored credential"), "name the credential: {stderr}");
    assert!(
        stderr.contains("suspected reuse"),
        "the gateway's refusal must reach the operator verbatim: {stderr}"
    );
    assert!(stderr.contains("noo auth login"), "and the fix: {stderr}");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn a_failed_refresh_keeps_the_typed_json_envelope() {
    let creds = temp_credentials("reffailjson", "revoked-token", far_future(), Some("raw-refresh"));
    let mock = Mock::start_seq(vec![
        http_response(401, "Unauthorized", "application/json", r#"{"detail":"Invalid token"}"#),
        http_response(401, "Unauthorized", "application/json", r#"{"detail":"User disabled"}"#),
    ]);
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "heartbeat", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4));
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stderr).trim()).expect("JSON envelope");
    assert_eq!(v["code"], "auth_failed");
    assert!(v["error"].as_str().unwrap().contains("User disabled"), "{}", v["error"]);
    assert!(v["hint"].as_str().unwrap().contains("noo auth login"));
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn an_explicit_token_is_never_refreshed_on_401() {
    // `--token` / `$NOO_TOKEN` are the caller's to manage. Silently swapping
    // in the stored credential would authenticate as somebody else.
    let creds = temp_credentials("overridden", "file-token", far_future(), Some("raw-refresh"));
    let mock = Mock::start_seq(vec![http_response(
        401,
        "Unauthorized",
        "application/json",
        r#"{"detail":"nope"}"#,
    )]);
    let out = run(
        &["--gateway", &gw(mock.port), "--token", "flag-token", "heartbeat", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(reqs.len(), 1, "no refresh for an explicitly supplied token: {reqs:?}");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

/// Concurrency: the gateway ROTATES refresh tokens on use and revokes the
/// user's whole chain when a revoked one is replayed, so two `noo` processes
/// must never spend the same refresh token. The CLI serialises on an advisory
/// `flock` beside the credential file and re-reads under it.
///
/// This case plays the OTHER process: it holds the lock, writes the credential
/// a winner would have written, and releases. The `noo` under test must then
/// adopt that credential and make **no** refresh call of its own.
#[cfg(unix)]
#[test]
fn a_concurrent_refresh_is_not_spent_twice() {
    use std::os::unix::io::AsRawFd;

    let creds = temp_credentials("concurrent", "stale-token", 1, Some("raw-refresh"));
    let lock_path = creds.with_extension("lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .expect("open lock");
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) },
        0,
        "hold the refresh lock as the competing process"
    );

    // Primed for ONE response: if the CLI refreshes despite the winner's
    // rotation, the command's own request never gets served and the request
    // count below fails (rather than hanging — see the harness note).
    let mock = Mock::start_seq(vec![ok_json(r#"{"running":true}"#)]);
    let url = gw(mock.port);
    let child = std::process::Command::new(bin())
        .args(["--gateway", &url, "heartbeat", "status"])
        .env_remove("NOO_TOKEN")
        .env_remove("NOO_CLUSTER_SECRET")
        .env_remove("NOO_GATEWAY_URL")
        .env("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn noo");

    // Give the child time to reach the lock, then publish the rotated pair
    // exactly as a winning refresh would have, and let it through.
    thread::sleep(Duration::from_millis(400));
    let rotated = serde_json::json!({
        "version": 1,
        "gateway": "http://127.0.0.1:1",
        "subject": "alice",
        "scopes": ["read", "write"],
        "access_token": "winner-token",
        "expires_at": far_future(),
        "refresh_token": "rotated-refresh",
        "refresh_expires_at": far_future() + 86_400,
    });
    std::fs::write(&creds, serde_json::to_string(&rotated).unwrap()).expect("write rotated creds");
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
    drop(lock);

    let out = child.wait_with_output().expect("wait noo");
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        reqs.len(),
        1,
        "the loser must not spend the refresh token a second time: {reqs:?}"
    );
    assert!(!reqs[0].starts_with("POST /api/auth/refresh"), "{}", reqs[0]);
    assert_eq!(
        auth_header(&reqs[0]).as_deref(),
        Some("Bearer winner-token"),
        "the loser must adopt the winner's token: {}",
        reqs[0]
    );
    // And it must not have clobbered the winner's file.
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&creds).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "winner-token");
    assert_eq!(stored["refresh_token"], "rotated-refresh");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn auth_login_stores_a_0600_credential_and_never_sends_a_bearer() {
    let dir = std::env::temp_dir().join(format!("noo-cli-login-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("credentials.json");
    let login = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Set-Cookie: noo_refresh=raw-refresh; HttpOnly; Path=/api/auth; Max-Age=2592000\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        r#"{"access_token":"jwt-abc","token_type":"bearer","expires_in":900,"refresh_ttl_days":30}"#.len(),
        r#"{"access_token":"jwt-abc","token_type":"bearer","expires_in":900,"refresh_ttl_days":30}"#
    );
    let mock = Mock::start_seq(vec![
        login,
        ok_json(r#"{"username":"alice","disabled":false,"scopes":["read","write","admin"]}"#),
    ]);
    let url = gw(mock.port);
    let out = run_with_stdin_env(
        &["--json", "--gateway", &url, "auth", "login", "alice", "--password-stdin"],
        "hunter2hunter2\n",
        &[
            ("NOO_CREDENTIALS_FILE", path.to_str().unwrap()),
            // A cluster secret in the environment must NOT be attached to the
            // login itself — /auth/ is public and using it would defeat the point.
            ("NOO_CLUSTER_SECRET", "hmac-secret"),
        ],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /auth/token"), "{}", reqs[0]);
    assert!(auth_header(&reqs[0]).is_none(), "login must be unauthenticated: {}", reqs[0]);
    assert!(reqs[0].contains("hunter2hunter2"), "credentials go in the body: {}", reqs[0]);
    assert!(reqs[1].starts_with("GET /auth/me"), "{}", reqs[1]);

    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("JSON stdout");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["subject"], "alice");
    assert_eq!(v["scopes"][2], "admin");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "credential file must be owner-only");
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "credential dir must be owner-only");
    }
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "jwt-abc");
    assert_eq!(stored["refresh_token"], "raw-refresh");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn auth_login_maps_bad_credentials_to_exit_4() {
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"Incorrect username or password"}"#, 1);
    let url = gw(mock.port);
    let out = run_with_stdin_env(
        &["--gateway", &url, "auth", "login", "alice", "--password-stdin"],
        "wrong\n",
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("alice"), "message names the account: {stderr}");
}

#[test]
fn auth_login_refuses_to_prompt_in_json_mode() {
    // Agent-first contract, same as `security user create`: never block a
    // machine caller on an interactive prompt.
    let out = run(&["--json", "auth", "login", "alice"], &[]);
    assert_eq!(out.status.code(), Some(2));
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stderr).trim()).expect("JSON envelope");
    assert_eq!(v["code"], "password_required");
}

#[test]
fn auth_status_reports_the_resolved_source_offline() {
    // `auth status` must explain itself with the gateway DOWN — that is
    // exactly when an operator runs it.
    let creds = temp_credentials("status", "file-token", far_future(), Some("r"));
    let port = closed_port().to_string();
    let out = run(
        &["--json", "--gateway", &format!("http://127.0.0.1:{port}"), "auth", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("JSON stdout");
    assert_eq!(v["source"], "file");
    assert_eq!(v["authenticated"], false);
    assert_eq!(v["stored"]["subject"], "alice");
    assert_eq!(v["stored"]["expired"], false);
    assert_eq!(v["stored"]["has_refresh"], true);
    let shown = v["stored"]["access_token"].as_str().unwrap();
    assert!(!shown.contains("file-token"), "status must redact the token: {shown}");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn auth_status_reports_expiry_and_whether_it_will_auto_refresh() {
    // Phase 2 honest-status contract: say when the access token dies, whether
    // the CLI will renew it by itself, and when the refresh itself dies.
    let creds = temp_credentials("statusexp", "file-token", far_future(), Some("r"));
    let port = closed_port().to_string();
    let out = run(
        &["--json", "--gateway", &format!("http://127.0.0.1:{port}"), "auth", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("JSON stdout");
    let s = &v["stored"];
    assert!(s["expires_at"].is_u64(), "a known expiry is reported as a number: {s}");
    assert!(s["expires_in_secs"].as_u64().unwrap() > 0);
    assert!(s["expires_detail"].is_null(), "no detail is needed when the value is known");
    assert_eq!(s["auto_refresh"], true);
    assert!(s["auto_refresh_detail"].as_str().unwrap().contains("valid until"));
    assert!(s["refresh_expires_at"].is_u64(), "the refresh lifetime is known here: {s}");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn auth_status_reports_an_unknown_expiry_as_unknown() {
    // `expires_at: 0` is the file admitting it does not know. It must NOT be
    // rendered as "expired at the epoch", and a credential with no refresh
    // token must not claim it will auto-refresh.
    let creds = temp_credentials("statusunknown", "file-token", 0, None);
    let port = closed_port().to_string();
    let out = run(
        &["--json", "--gateway", &format!("http://127.0.0.1:{port}"), "auth", "status"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("JSON stdout");
    let s = &v["stored"];
    assert!(s["expires_at"].is_null(), "unknown must read as null: {s}");
    assert!(s["expires_in_secs"].is_null());
    assert!(s["expires_detail"].as_str().unwrap().contains("unknown"));
    assert_eq!(s["auto_refresh"], false);
    assert!(s["auto_refresh_detail"].as_str().unwrap().contains("noo auth login"));
    assert_eq!(s["has_refresh"], false);
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn auth_status_with_only_a_secret_is_no_credential() {
    // A configured secret (and the old opt-in) resolves to nothing: the
    // shared secret is not a CLI credential.
    let port = closed_port().to_string();
    let none = run(
        &["--json", "--gateway", &format!("http://127.0.0.1:{port}"), "auth", "status"],
        &[("NOO_CLUSTER_SECRET", "s"), ("NOO_CONTROLLER_SECRET", "c"), ("NOO_BREAK_GLASS", "1")],
    );
    let nv: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&none.stdout).trim()).expect("JSON stdout");
    assert_eq!(nv["source"], "none", "a secret must never resolve: {nv}");
}

#[test]
fn auth_logout_revokes_server_side_then_removes_the_file() {
    let creds = temp_credentials("logout", "file-token", far_future(), Some("raw-refresh"));
    let mock = Mock::start(200, "OK", "application/json", r#"{"ok":true}"#, 1);
    let out = run(
        &["--json", "--gateway", &gw(mock.port), "auth", "logout"],
        &[("NOO_CREDENTIALS_FILE", creds.to_str().unwrap())],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(reqs[0].starts_with("POST /api/auth/logout"), "{}", reqs[0]);
    assert!(reqs[0].contains("noo_refresh=raw-refresh"), "{}", reqs[0]);
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("JSON stdout");
    assert_eq!(v["removed"], true);
    assert_eq!(v["refresh_revoked"], true);
    assert!(!creds.exists(), "credential file must be gone");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}

#[test]
fn auth_logout_with_nothing_stored_is_a_clean_no_op() {
    let port = closed_port().to_string();
    let out = run(
        &["--json", "--gateway", &format!("http://127.0.0.1:{port}"), "auth", "logout"],
        &[],
    );
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("JSON stdout");
    assert_eq!(v["removed"], false);
}

// ── "the system must not lie": 200-with-error bodies and unknown values ─────
//
// The gateway answers HTTP 200 with an embedded `error` on several routes
// (Redis down, audit store missing). These cases pin that such a body can
// never render as a benign empty list / success line with exit 0.

/// `jobs submit` against a 200 + {"error": …}: the job was NOT queued.
#[test]
fn jobs_submit_error_body_exits_remote_error() {
    let body = r#"{"error":"Redis not connected"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "submit", "--type", "inference"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5), "200+error must not exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("Job submitted"), "must not claim a submit: {stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Redis not connected"), "stderr: {stderr}");
}

/// `jobs list` against a 200 + {"jobs":[],"error": …}: an unreadable queue is
/// not an empty queue.
#[test]
fn jobs_list_error_body_is_not_no_jobs_found() {
    let body = r#"{"jobs":[],"count":0,"error":"Redis not connected"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "list"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("no jobs found"), "stdout: {stdout}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Redis not connected"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `jobs history` reads the `history` key the route actually sends (it has
/// never sent `jobs`, so the table used to be empty no matter what Redis held).
#[test]
fn jobs_history_renders_history_key() {
    let body = r#"{"history":[{"job_id":"h9","type":"embed","status":"completed","duration_ms":7}],"count":1}"#;
    let stdout = case("GET", "/api/jobs/history", 200, body, &["jobs", "history"], 0);
    assert!(stdout.contains("h9") && stdout.contains("7ms"), "stdout: {stdout}");
}

/// `jobs pause` against a 200 + {"error": …}: no `message`, so this used to
/// print "Scheduler paused" for a pause that never happened.
#[test]
fn jobs_pause_error_body_does_not_claim_success() {
    let body = r#"{"error":"scheduler unavailable"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "pause"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Scheduler paused"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("scheduler unavailable"));
}

/// `jobs drain` against a 200 + {"error": …}: same trap as pause.
#[test]
fn jobs_drain_error_body_does_not_claim_success() {
    let body = r#"{"error":"unknown node"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "jobs", "drain", "node-1"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("drained"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown node"));
}

/// `autonomy status` with a null `running`: the gateway does not know whether
/// the engine loop is alive — the CLI must say UNKNOWN, not STOPPED.
#[test]
fn autonomy_status_null_running_renders_unknown() {
    let body = r#"{"enabled":true,"running":null,"running_detail":"unknown — the autonomy_engine loop has never reported a tick","locations_total":16,"locations_enabled":1,"audit_entries":null,"audit_detail":"not tracked — no autonomy audit store is readable","locations":[]}"#;
    let stdout = case("GET", "/api/autonomy/status", 200, body, &["autonomy", "status"], 0);
    assert!(stdout.contains("unknown"), "stdout: {stdout}");
    assert!(!stdout.contains("stopped"), "must not assert stopped: {stdout}");
    assert!(stdout.contains("not tracked"), "null audit count: {stdout}");
    assert!(stdout.contains("never reported a tick"), "running_detail: {stdout}");
}

/// The ARMED column is the operator's decision-making fact: does this
/// location change the fleet, or only alert? A gateway that does not report
/// `armed` must render a dash and SAY the dash means unknown — printing a
/// confident "off" for a fact nobody sent is the lie `running.unwrap_or(false)`
/// used to tell.
#[test]
fn autonomy_status_armed_column_never_guesses() {
    let body = r#"{"enabled":true,"running":true,"locations_total":2,"locations_enabled":2,"audit_entries":0,"locations":[{"name":"backend_scaling","type":"cluster","enabled":true,"armed":true,"dry_run":false,"interval":300,"cooldown":300,"conditions":1,"actions":1},{"name":"node_health","type":"cluster","enabled":true,"interval":60,"cooldown":300,"conditions":1,"actions":1}]}"#;
    let stdout = case("GET", "/api/autonomy/status", 200, body, &["autonomy", "status"], 0);
    assert!(stdout.contains("ARMED"), "armed column: {stdout}");
    assert!(stdout.contains("Armed"), "armed location: {stdout}");
    assert!(
        stdout.contains("armed locations change the fleet"),
        "an armed location must be called out: {stdout}"
    );
    // node_health reports no `armed` key (alert-only). Some location DID
    // report it, so this is a real "no gate", not an old gateway — the
    // unknown-arming note must NOT fire.
    assert!(
        !stdout.contains("does not report whether an action is armed"),
        "false unknown-arming warning: {stdout}"
    );
}

/// A gateway too old to report `armed` at all: every dash is unknown, and
/// the CLI says so rather than letting them read as "off".
#[test]
fn autonomy_status_old_gateway_says_arming_is_unknown() {
    let body = r#"{"enabled":true,"running":true,"locations_total":1,"locations_enabled":1,"audit_entries":0,"locations":[{"name":"backend_scaling","type":"cluster","enabled":true,"interval":300,"cooldown":300,"conditions":1,"actions":1}]}"#;
    let stdout = case("GET", "/api/autonomy/status", 200, body, &["autonomy", "status"], 0);
    assert!(
        stdout.contains("does not report whether an action is armed"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("unknown, not off"), "stdout: {stdout}");
}

/// `autonomy decisions` renders the would-do evidence and states plainly
/// that none of it happened.
#[test]
fn autonomy_decisions_says_the_actions_did_not_happen() {
    let body = r#"{"decisions":[{"at":null,"location":"backend_idle_scaledown","action":"would_stop","target":"nodeA","detail":"llamacpp (idle 5 checks)"}]}"#;
    let stdout = case(
        "GET",
        "/api/autonomy/decisions?limit=20",
        200,
        body,
        &["autonomy", "decisions"],
        0,
    );
    assert!(stdout.contains("would_stop"), "stdout: {stdout}");
    assert!(stdout.contains("nodeA"), "stdout: {stdout}");
    assert!(stdout.contains("did NOT happen"), "stdout: {stdout}");
}

/// A gateway without the decisions route answers 404. Rendering an empty
/// table would read as "nothing would have happened", the opposite of the
/// truth, so the CLI names the cause and points at the log instead.
#[test]
fn autonomy_decisions_404_is_not_an_empty_result() {
    let mock = Mock::start(404, "Not Found", "application/json", r#"{"detail":"Not Found"}"#, 1);
    let out = run(&["--gateway", &gw(mock.port), "autonomy", "decisions"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(all.contains("does not serve autonomy decisions"), "out: {all}");
    assert!(all.contains("grep would_"), "log fallback: {all}");
    assert!(!all.to_lowercase().contains("no location has wanted to act"), "must not read as empty: {all}");
}

/// `autonomy audit` renders migration 058's shape and never lets a `would`
/// row read as something that happened.
#[test]
fn autonomy_audit_distinguishes_would_from_fired() {
    let body = r#"{"entries":[{"at":null,"location":"backend_scaling","action":"scale_backend","outcome":"would","target":"nodeA","detail":"to 2 replicas"},{"at":null,"location":"backend_availability","action":"auto_start","outcome":"fired","target":"nodeB","detail":"ollama"}],"count":2}"#;
    let stdout = case("GET", "/api/autonomy/audit?limit=20", 200, body, &["autonomy", "audit"], 0);
    assert!(stdout.contains("OUTCOME"), "outcome column: {stdout}");
    assert!(stdout.contains("Would") && stdout.contains("Fired"), "both states: {stdout}");
    assert!(
        stdout.contains("did not happen"),
        "a would row must be disclaimed: {stdout}"
    );
}

/// `autonomy audit` with `entries: null`: an unreadable audit store is not
/// "no audit entries yet".
#[test]
fn autonomy_audit_null_entries_reports_error() {
    let body = r#"{"entries":null,"count":null,"error":"autonomy audit log is not available: relation does not exist","detail":"no noo_autonomy_audit store is readable"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(&["--gateway", &gw(mock.port), "autonomy", "audit"], &[]);
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(5));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("no audit entries yet"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not available"));
}

/// `health` on a degraded gateway: exit non-zero AND name the dead dependency.
#[test]
fn health_degraded_exits_nonzero_and_names_dependency() {
    let body = r#"{"status":"degraded","engine":"rust","dependencies":{"postgresql":{"healthy":false},"nats":{"healthy":true},"redis":{"healthy":true,"optional":false}}}"#;
    let stdout = case("GET", "/health", 200, body, &["health"], 5);
    assert!(stdout.contains("Degraded"), "stdout: {stdout}");
    // Plain-mode glyph fallback (`x`) plus the Title-cased state word, on
    // the row that names the dependency (CLI_STYLE_GUIDE rev 2 §4: colour
    // is never the only signal). Guidance names every next command.
    let row = stdout.lines().find(|l| l.contains("postgresql")).unwrap_or_default();
    assert!(row.trim_start().starts_with("x ") && row.contains("Down"), "stdout: {stdout}");
    assert!(stdout.contains("> noo stack status"), "stdout: {stdout}");
    assert!(stdout.contains("> noo stack logs postgresql"), "stdout: {stdout}");
}

/// `--quiet` keeps only the captured value (CLI_STYLE_GUIDE rev 2 §7): for
/// `config export-effective -o`, that is the written path and nothing else.
#[test]
fn config_export_effective_quiet_prints_only_the_path() {
    let body = r#"{"running":false,"locations_enabled":0,"locations":[],"rules":[],"grants":[]}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 3);
    let path = std::env::temp_dir().join(format!("noo-test-effective-quiet-{}.yaml", std::process::id()));
    let out = run(
        &["--quiet", "--gateway", &gw(mock.port), "config", "export-effective", "-o", path.to_str().unwrap()],
        &[],
    );
    let _ = mock.requests();
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), path.to_str().unwrap());
    assert!(String::from_utf8_lossy(&out.stderr).trim().is_empty());
}

/// `proactive status` with a null `history_entries`: "not tracked", not 0.
#[test]
fn proactive_status_null_history_is_not_zero() {
    let body = r#"{"running":true,"rules_enabled":2,"rules_total":3,"history_entries":null,"history_detail":"not tracked — no firing history store"}"#;
    let stdout = case("GET", "/api/proactive/status", 200, body, &["proactive", "status"], 0);
    assert!(stdout.contains("not tracked"), "stdout: {stdout}");
    assert!(!stdout.contains("0 entries"), "must not report a zero count: {stdout}");
}

/// `tools list`: the gateway sends `stats: {total}` and an empty
/// `available_on_nodes` — no "base: 0 | specialized: 0", no "all nodes".
#[test]
fn tools_list_does_not_invent_stats_or_placement() {
    let body = r#"{"tools":[{"name":"web_search","description":"search","is_base_tool":true,"available_on_nodes":[]}],"stats":{"total":1}}"#;
    let stdout = case("GET", "/tools/list", 200, body, &["tools", "list"], 0);
    assert!(stdout.contains("1 total"), "stdout: {stdout}");
    assert!(!stdout.contains("base 0"), "invented breakdown: {stdout}");
    assert!(!stdout.contains("all nodes"), "invented placement: {stdout}");
    assert!(stdout.contains("not reported"), "stdout: {stdout}");
}

/// `voice status`: absent `stt_backend` must not name a backend, and the TTS
/// rows come from the gateway's `tts_backends`, not a hardcoded pair.
#[test]
fn voice_status_reports_only_what_gateway_sends() {
    let body = r#"{"stt_available":false,"tts_available":true,"tts_backends":["piper"]}"#;
    let stdout = case("GET", "/api/voice/status", 200, body, &["voice", "status"], 0);
    assert!(stdout.contains("unknown"), "absent stt_backend: {stdout}");
    assert!(!stdout.contains("faster-whisper"), "invented STT backend: {stdout}");
    assert!(stdout.contains("piper"), "stdout: {stdout}");
    assert!(!stdout.contains("edge-tts"), "invented TTS backend: {stdout}");
}

/// `cluster down`: the stop route sends {status, backend, node_id} — never
/// `stopped_count`, which used to print as "on null node(s)".
#[test]
fn cluster_down_reports_node_not_null_count() {
    let body = r#"{"status":"stopped","backend":"ollama","node_id":"node-1"}"#;
    let mock = Mock::start(200, "OK", "application/json", body, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "cluster", "down", "ollama", "--node", "node-1", "-y"],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0));
    // Mutation confirmation is stdout narration (CLI_STYLE_GUIDE rev 2 §2).
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("null"), "stdout: {stdout}");
    assert!(stdout.contains("node-1") && stdout.to_lowercase().contains("stopped"), "stdout: {stdout}");
}

/// `--quiet` keeps only the captured value (CLI_STYLE_GUIDE rev 2 §7):
/// `cluster init-secret` is local, so this needs no gateway.
#[test]
fn cluster_init_secret_quiet_prints_only_the_secret() {
    let out = run(&["--quiet", "cluster", "init-secret"], &[]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "stdout: {stdout}");
    assert!(lines[0].len() >= 32 && !lines[0].contains(' '), "stdout: {stdout}");
    assert!(out.stderr.is_empty(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    // Default mode: header box, the value, and guidance — all on stdout.
    let out = run(&["cluster", "init-secret"], &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("| Cluster Secret"), "stdout: {stdout}");
    assert!(stdout.contains("> noo cluster push-secrets"), "stdout: {stdout}");
}

/// `workflow run`: steps arrive as {"name": …}; every step used to print "?".
#[test]
fn workflow_run_renders_step_name() {
    let body = r#"{"status":"completed","total_duration_ms":12,"steps":[{"name":"fetch_docs","status":"completed","duration_ms":5}]}"#;
    let stdout = case("POST", "/api/workflows/run", 200, body, &["workflow", "run", "wf1"], 0);
    assert!(stdout.contains("fetch_docs"), "stdout: {stdout}");
}

/// Guide rev 2 §2/§7: `cluster bootstrap-token create` narrates on stdout
/// (confirmation, kv block, guidance) and the one-liner is the CAPTURED
/// VALUE — under `--quiet` it is the only line, so `paste=$(noo --quiet …)`
/// works.
#[test]
fn bootstrap_token_create_quiet_prints_only_the_one_liner() {
    let body = r#"{"id":"tok-1","one_liner":"curl -fsSL https://ctl/bootstrap.sh | sh -s -- noo1.abc","expires_at":"2026-09-04T00:00:00Z","node_name":"n1"}"#;
    let mock = RouterMock::start(vec![("/api/security/bootstrap-tokens", 200, body)], 1);
    let out = run(
        &["--quiet", "--gateway", &gw(mock.port), "cluster", "bootstrap-token", "create", "--node", "n1", "--no-tailscale"],
        &[],
    );
    let _ = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "curl -fsSL https://ctl/bootstrap.sh | sh -s -- noo1.abc\n"
    );

    // Default mode: everything a person needs, on stdout, plain (pipe).
    let mock = RouterMock::start(vec![("/api/security/bootstrap-tokens", 200, body)], 1);
    let out = run(
        &["--gateway", &gw(mock.port), "cluster", "bootstrap-token", "create", "--node", "n1", "--no-tailscale"],
        &[],
    );
    let _ = mock.requests();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("+ Bootstrap token minted (id tok-1)"), "stdout: {stdout}");
    assert!(stdout.contains("Bound To Node  n1"), "stdout: {stdout}");
    assert!(stdout.contains("\ncurl -fsSL https://ctl/bootstrap.sh | sh -s -- noo1.abc\n"), "stdout: {stdout}");
    assert!(stdout.contains("> noo cluster bootstrap-token revoke tok-1"), "stdout: {stdout}");
    assert!(stdout.contains("> noo cluster provision n1 --wait"), "stdout: {stdout}");
    assert!(String::from_utf8_lossy(&out.stderr).is_empty(), "stderr must be empty on success");
}

/// A current gateway composes the ONE enrollment paste itself (install, then
/// `noo enroll noo1.<blob>`), and the CLI prints the server's commands rather
/// than composing its own — one composition for console, CLI and MCP. The
/// request asks for the tailnet key only when the operator did.
#[test]
fn bootstrap_token_create_prints_the_servers_enroll_paste() {
    let body = r#"{"id":"tok-2","token":"RAW","expires_at":"2026-09-04T00:00:00Z","node_name":"n1","controller_url":"https://ctl.example.ts.net:8080","install_command":"command -v noo >/dev/null || curl -fsSL https://raw.githubusercontent.com/o/r/main/noo-cli/install.sh | sh","enroll_command":"noo enroll noo1.SERVERBLOB","provision_command":"noo cluster provision n1 --wait","joins_tailnet":false}"#;
    let mock = RouterMock::start(vec![("/api/security/bootstrap-tokens", 200, body)], 1);
    let out = run(
        &["--quiet", "--gateway", &gw(mock.port), "cluster", "bootstrap-token", "create", "--node", "n1", "--no-tailscale"],
        &[],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "noo enroll noo1.SERVERBLOB\n");
    let sent = reqs.join("\n");
    let body_json: serde_json::Value = sent
        .split_once("\r\n\r\n")
        .or_else(|| sent.split_once("\n\n"))
        .and_then(|(_, b)| serde_json::from_str(b.trim()).ok())
        .unwrap_or_else(|| panic!("no JSON body in request: {sent}"));
    assert_eq!(body_json["with_tailscale"], serde_json::json!(false), "request body: {sent}");
    assert_eq!(body_json["node_name"], "n1", "request body: {sent}");

    let mock = RouterMock::start(vec![("/api/security/bootstrap-tokens", 200, body)], 1);
    let out = run(
        &["--gateway", &gw(mock.port), "cluster", "bootstrap-token", "create", "--node", "n1", "--no-tailscale"],
        &[],
    );
    let _ = mock.requests();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("  command -v noo >/dev/null || curl -fsSL https://raw.githubusercontent.com/o/r/main/noo-cli/install.sh | sh\n"), "stdout: {stdout}");
    assert!(stdout.contains("  noo enroll noo1.SERVERBLOB\n"), "stdout: {stdout}");
    assert!(stdout.contains("the node must already reach the controller"), "stdout: {stdout}");
    assert!(stdout.contains("https://ctl.example.ts.net:8080/bootstrap/cli/install.sh"), "stdout: {stdout}");
    assert!(stdout.contains("noo cluster provision n1 --wait"), "stdout: {stdout}");
    assert!(stdout.contains("noo cluster bootstrap-token revoke tok-2"), "stdout: {stdout}");
    assert!(!stdout.contains("curl -fsSL https://ctl"), "no fetched-script paste: {stdout}");
    assert!(String::from_utf8_lossy(&out.stderr).is_empty(), "stderr must be empty on success");
}

// The Mac applier must not refuse the very bundle that would update it.
//
// host6 sat on noo-cli-v0.5.35 from the day `harness-binary` joined the
// bundle kinds (2026-09-19): every tick it fetched a bundle, found a kind
// its KNOWN_KINDS did not list, and refused the whole thing — including the
// `cli-binary` payload that would have taught it the kind. A deadlock the
// Linux lane never had, because `noo-apply.sh` installs a bundled applier
// and re-execs on the SAME bundle before validating anything.
#[test]
fn the_mac_applier_self_updates_before_refusing_an_unknown_kind() {
    let src = include_str!("../src/commands/node_fetch.rs");

    // The refusal must be preceded by the self-update attempt, not the
    // other way round — ordering IS the fix.
    let refusal = src.find("unknown kind '{kind}'").expect("the refusal is gone");
    let update = src.find("self_update_and_reexec(").expect("no self-update before the refusal");
    assert!(update < refusal, "the self-update must be attempted BEFORE refusing");

    let helper = src
        .split("fn self_update_and_reexec")
        .nth(1)
        .expect("helper missing");
    // Verified against the SIGNED manifest before anything is written —
    // the same discipline noo-apply.sh applies to a bundled applier.
    assert!(helper.contains("does not match the signed manifest"),
        "the payload must be checked against the signed manifest");
    // Loop guard and privilege check, both of which noo-apply.sh has.
    assert!(helper.contains("NOO_FETCH_REEXEC"), "no loop guard");
    // The REAL uid: the poll runs with its effective uid lowered to the
    // user, and resumes root only to install.
    assert!(helper.contains("privs::is_root_process()"), "only the root daemon may swap /usr/local/bin/noo");
    // An identical binary is not a reason to re-exec: then the kind really
    // is unknown to the newest CLI, which is a genuine refusal.
    assert!(helper.contains("running.as_deref() == Some(have.as_str())"),
        "must not re-exec into the same binary");
    // Atomic swap, never a truncated binary in place.
    // Through root_install: a `.noo-next` file renamed over the target.
    assert!(helper.contains("root_install(&payload, Path::new(\"/usr/local/bin/noo\")"),
        "the swap must go through root_install");
    // root_install checks the directory and delegates to root_install_with,
    // which writes the temp file (O_EXCL|O_NOFOLLOW) and renames it.
    let install = src.split("fn root_install_with").nth(1).expect("root_install_with missing");
    let install = &install[..install.find("\n}\n").unwrap()];
    assert!(install.contains("noo-next") && install.contains("rename"),
        "the swap must be write-then-rename");
    let outer = src.split("fn root_install(").nth(1).expect("root_install missing");
    let outer = &outer[..outer.find("\n}\n").unwrap()];
    assert!(outer.contains("root_dir_trustworthy"), "root_install must refuse a directory that is not root's alone");
}


// ═══════════════════════════════════════════════════════════════════════
// The operator's CLI authenticates as the operator.
//
// `cluster_hmac_non_inference` counted 7 uses from caller `cli` in the
// stack-v0.2.82 rehearsal: `cluster verify` runs `security posture list` and
// `security audit verify` as subprocesses, and both signed with the
// controller's shared secret even for a logged-in operator. Both routes take
// an Operator-role login. Posture WRITES carry the operator's client
// certificate and a token bound to it, and nothing else:
// the shared secret is not a CLI credential at all (2026-10-03).
// ═══════════════════════════════════════════════════════════════════════

/// Every case here has BOTH credentials available, so the assertion is about
/// which one the CLI chose, not about which one happened to exist.
fn both_credentials(tag: &str) -> std::path::PathBuf {
    temp_credentials(tag, "operator-jwt", far_future(), None)
}

#[test]
fn operator_reads_carry_the_operators_login_not_the_shared_secret() {
    for (tag, args, route, body) in [
        ("lc-posture-list", &["security", "posture", "list"][..], "GET /api/security/posture ",
         r#"{"posture":[],"count":0,"retired":[]}"#),
        ("lc-audit-verify", &["security", "audit", "verify"][..], "GET /api/security/audit/verify ",
         r#"{"verdict":"ok","checked":0,"key_present":true,"breaks":[],"problems":[]}"#),
    ] {
        let creds = both_credentials(tag);
        let mock = Mock::start(200, "OK", "application/json", body, 1);
        let port = gw(mock.port);
        let mut full = vec!["--json", "--gateway", port.as_str()];
        full.extend_from_slice(args);
        let out = run(
            &full,
            &[
                ("NOO_CONTROLLER_SECRET", "controller-secret"),
                ("NOO_CLUSTER_SECRET", "fleet-secret"),
                ("NOO_CREDENTIALS_FILE", creds.to_str().unwrap()),
            ],
        );
        let reqs = mock.requests();
        assert_eq!(out.status.code(), Some(0), "{tag}: stderr: {}", String::from_utf8_lossy(&out.stderr));
        let req = reqs.first().unwrap_or_else(|| panic!("{tag}: no request reached the mock"));
        assert!(req.starts_with(route), "{tag}: request:\n{req}");
        assert_eq!(
            auth_header(req).as_deref(),
            Some("Bearer operator-jwt"),
            "{tag}: an operator read must carry the operator's own login, never an HMAC"
        );
        let _ = std::fs::remove_dir_all(creds.parent().unwrap());
    }
}

/// With no login, an operator read sends NO credential (and 401s with the
/// login hint) — the shared secret is not a silent fallback for it.
#[test]
fn operator_read_without_a_login_sends_no_shared_secret() {
    let mock = Mock::start(401, "Unauthorized", "application/json", r#"{"detail":"unauthorized"}"#, 1);
    let out = run(
        &["--gateway", &gw(mock.port), "security", "posture", "list"],
        &[("NOO_CONTROLLER_SECRET", "controller-secret"), ("NOO_CLUSTER_SECRET", "fleet-secret")],
    );
    let reqs = mock.requests();
    assert_eq!(out.status.code(), Some(4), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let req = reqs.first().expect("one request");
    assert_eq!(auth_header(req), None, "no login: nothing is sent, request:\n{req}");
}

/// A posture write never signs with the shared secret. With
/// no operator certificate the CLI refuses BEFORE sending anything, and
/// names the way to get one — even with a login, the controller secret and
/// the old break-glass opt-in all at hand.
#[test]
fn posture_write_without_an_operator_cert_refuses_and_sends_nothing() {
    let creds = both_credentials("lc-posture-refuse");
    let mock = Mock::start_seq(vec![]);
    let out = run(
        &["--gateway", &gw(mock.port), "security", "posture", "set", "NOO_MCP_EXTERNAL_ENABLED", "0"],
        &[
            ("NOO_CONTROLLER_SECRET", "controller-secret"),
            ("NOO_BREAK_GLASS", "1"),
            ("NOO_CREDENTIALS_FILE", creds.to_str().unwrap()),
        ],
    );
    assert!(mock.requests().is_empty(), "nothing may be sent without a usable posture credential");
    assert_eq!(out.status.code(), Some(4), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(err.contains("no operator client certificate for 'alice'"), "stderr: {err}");
    assert!(err.contains("noo security pki issue-client alice"), "stderr: {err}");
    assert!(!err.contains("break-glass"), "no refusal may offer a removed flag: {err}");
    let _ = std::fs::remove_dir_all(creds.parent().unwrap());
}


// ── a failed graph write is a failure: non-zero, the gateway's words, no success text ──
//
// 2026-10 rehearsal: `noo graph entity-cleanup --apply --yes` announced "staged
// first, then deleted", the op failed (the worker's staging insert hit 42P01), and
// the operator was left to find out that nothing had changed. A command that
// writes must end in the gateway's own error and a non-zero exit, and must never
// print success wording the response did not earn.

const CLEANUP_PREVIEW: &str = r#"{"status":"dry-run","dry_run":true,"scanned":100,"junk":2,"with_edges":1,"edge_rows":3,"with_mentions":1,"mention_rows":2,"in_clusters":0,"cluster_rows":0,"by_reason":{"math_symbol":2},"by_type":{"variable":2},"examples":[{"name":"x_t","type":"variable","reason":"math_symbol","edges":3,"mentions":2,"clusters":0}],"staged":0,"skipped_over_cap":0,"run_id":null}"#;
const FAILED_MSG: &str = "entity cleanup failed (ProgrammingError); batches already committed are staged and restorable, and a re-run continues; see the worker log";

/// Words that claim a write happened.
const SUCCESS_WORDS: [&str; 5] = ["staged and removed", "staged first", "restored ", "clustered", "then deleted"];

fn assert_failed_without_success_text(out: &Output, want_in_stderr: &str) {
    let (so, se) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(!out.status.success(), "a failed write must exit non-zero.\nstdout: {so}\nstderr: {se}");
    assert!(se.to_lowercase().contains(&want_in_stderr.to_lowercase()), "the gateway's message must be shown.\nstdout: {so}\nstderr: {se}");
    let all = format!("{so}{se}").to_lowercase();
    for w in SUCCESS_WORDS {
        assert!(!all.contains(w), "success wording {w:?} printed for a failed write.\nstdout: {so}\nstderr: {se}");
    }
}

#[test]
fn entity_cleanup_apply_refused_with_a_400_exits_nonzero_with_the_gateways_message() {
    let body = format!(r#"{{"error":"{FAILED_MSG}","status":"failed"}}"#);
    let mock = Mock::start_seq(vec![
        ok_json(CLEANUP_PREVIEW),
        http_response(400, "Bad Request", "application/json", &body),
    ]);
    let out = run(&["--gateway", &gw(mock.port), "graph", "entity-cleanup", "--apply", "--yes"], &[]);
    mock.requests();
    assert_failed_without_success_text(&out, "ProgrammingError");
    assert!(String::from_utf8_lossy(&out.stderr).contains("400"), "the status is named");
}

#[test]
fn entity_cleanup_apply_whose_op_ends_failed_exits_nonzero_with_the_error() {
    let handle = r#"{"op_id":"op-1","poll":"/api/v1/ops/op-1","status":"running"}"#;
    let failed = format!(r#"{{"op_id":"op-1","status":"failed","error":"{FAILED_MSG}","result":null}}"#);
    let mock = Mock::start_seq(vec![
        ok_json(CLEANUP_PREVIEW),
        http_response(202, "Accepted", "application/json", handle),
        ok_json(&failed),
    ]);
    let out = run(&["--gateway", &gw(mock.port), "graph", "entity-cleanup", "--apply", "--yes"], &[]);
    mock.requests();
    assert_failed_without_success_text(&out, "ProgrammingError");
}

#[test]
fn entity_cleanup_apply_answered_200_with_an_error_body_is_still_a_failure() {
    // a worker error that reached the CLI as a 200 body must not read as "staged and removed 0"
    let body = format!(r#"{{"error":"{FAILED_MSG}"}}"#);
    let mock = Mock::start_seq(vec![ok_json(CLEANUP_PREVIEW), ok_json(&body)]);
    let out = run(&["--gateway", &gw(mock.port), "graph", "entity-cleanup", "--apply", "--yes"], &[]);
    mock.requests();
    assert_failed_without_success_text(&out, "ProgrammingError");
}

#[test]
fn entity_cleanup_apply_that_succeeded_says_so_and_names_the_run() {
    let done = r#"{"status":"applied","dry_run":false,"scanned":100,"junk":2,"staged":2,"skipped_over_cap":0,"run_id":"entq-1a2b3c4d"}"#;
    let mock = Mock::start_seq(vec![ok_json(CLEANUP_PREVIEW), ok_json(done)]);
    let out = run(&["--gateway", &gw(mock.port), "graph", "entity-cleanup", "--apply", "--yes"], &[]);
    mock.requests();
    let so = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(so.contains("staged and removed 2") && so.contains("entq-1a2b3c4d"), "stdout: {so}");
}

#[test]
fn recluster_that_fails_or_answers_an_error_exits_nonzero_and_never_says_clustered() {
    for (status, reason, body) in [
        (400u16, "Bad Request", r#"{"error":"clustering exploded"}"#),
        (200, "OK", r#"{"error":"clustering exploded"}"#),
    ] {
        let mock = Mock::start_seq(vec![http_response(status, reason, "application/json", body)]);
        let out = run(&["--gateway", &gw(mock.port), "graph", "recluster"], &[]);
        mock.requests();
        assert_failed_without_success_text(&out, "clustering exploded");
    }
}

#[test]
fn prune_restore_that_fails_or_answers_an_error_exits_nonzero_and_never_says_restored() {
    for (status, reason, body) in [
        (400u16, "Bad Request", r#"{"error":"restore refused"}"#),
        (200, "OK", r#"{"error":"restore refused"}"#),
    ] {
        let mock = Mock::start_seq(vec![http_response(status, reason, "application/json", body)]);
        let out = run(&["--gateway", &gw(mock.port), "graph", "prune", "restore", "--run", "entq-1a2b3c4d"], &[]);
        mock.requests();
        assert_failed_without_success_text(&out, "restore refused");
    }
}

/// A sandbox root whose `scripts/<name>` records its arguments in `ran.log`.
fn recording_script_root(tag: &str, script: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = tmpdir(tag);
    std::fs::create_dir_all(root.join("scripts")).unwrap();
    let log = root.join("ran.log");
    let path = root.join("scripts").join(script);
    std::fs::write(&path, format!("#!/bin/bash\necho \"$*\" >> \"{}\"\n", log.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    (root, log)
}

#[test]
fn stack_stop_volumes_refuses_without_a_terminal_and_runs_nothing() {
    let (root, log) = recording_script_root("stop-vol", "noomesh-stop.sh");
    let env = [("NOO_REPO_ROOT", root.display().to_string())];
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    for args in [&["stack", "stop", "--volumes"][..], &["--json", "stack", "stop", "--volumes"][..]] {
        let out = run_local(args, &env);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(!log.exists(), "the stop script ran without confirmation: {args:?}");
    }
    // -y skips the prompt; the script gets -v.
    let out = run_local(&["stack", "stop", "--volumes", "-y"], &env);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "-v");
    // A plain stop never asks.
    std::fs::remove_file(&log).unwrap();
    let out = run_local(&["stack", "stop"], &env);
    assert_eq!(out.status.code(), Some(0));
    assert!(log.exists());
}

#[test]
fn stack_clean_confirms_every_destructive_flag_and_forwards_yes() {
    let (root, log) = recording_script_root("clean-yes", "noomesh-clean.sh");
    let env = [("NOO_REPO_ROOT", root.display().to_string())];
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    for flag in ["--images", "--cache", "--hf-cache"] {
        let out = run_local(&["stack", "clean", flag], &env);
        assert_eq!(out.status.code(), Some(1), "{flag} ran without confirmation");
        assert!(!log.exists(), "{flag}: script ran");
    }
    let out = run_local(&["stack", "clean", "--images", "-y"], &env);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "--images --yes");
}

#[test]
fn models_switch_refuses_without_yes_when_there_is_no_terminal() {
    let root = tmpdir("switch-noyes");
    std::fs::write(root.join(".env"), "VLLM_MODEL=old\n").unwrap();
    let out = run_local(
        &["models", "switch", "QuantTrio/Qwen3.5-9B-AWQ"],
        &[("NOO_REPO_ROOT", &root.display().to_string())],
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(std::fs::read_to_string(root.join(".env")).unwrap(), "VLLM_MODEL=old\n");
}

#[test]
fn stack_stop_and_clean_short_v_never_reach_the_passthrough() {
    let (root, log) = recording_script_root("stop-shortv", "noomesh-stop.sh");
    let env = [("NOO_REPO_ROOT", root.display().to_string())];
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    for args in [&["stack", "stop", "-v"][..], &["stack", "stop", "-v", "-y"][..], &["stack", "clean", "-v", "-y"][..]] {
        let out = run_local(args, &env);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("use --volumes"), "{args:?}: {err}");
        assert!(!log.exists());
    }
}
