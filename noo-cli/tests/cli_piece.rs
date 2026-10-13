// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Add-on commands (`commands/addon_cli.rs`): a generic `noo <group> <cmd>`
//! driven entirely by a CLI piece the add-on serves. The fixture piece below
//! is this suite's own; nothing here depends on any real add-on.
//!
//! A mock gateway answers `/health`, the piece route and the commands' own
//! routes, and records every request, so each case can assert exactly what
//! was (and was not) sent.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{json, Value};

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    body: String,
}

type Routes = HashMap<(String, String), (u16, Value)>;

struct Mock {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Mock {
    /// `routes`: (method, path-with-query) → (status, JSON body). Anything
    /// else answers 404.
    fn start(routes: Routes) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, st2) = (seen.clone(), stop.clone());
        let handle = thread::spawn(move || {
            for conn in listener.incoming() {
                if st2.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = conn else { continue };
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let req = read_request(&mut stream);
                let mut lines = req.lines();
                let mut first = lines.next().unwrap_or("").split_whitespace();
                let (method, path) = (first.next().unwrap_or("").to_string(), first.next().unwrap_or("").to_string());
                let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                let (status, payload) = routes
                    .get(&(method.clone(), path.clone()))
                    .cloned()
                    .unwrap_or((404, json!({"error": "not mocked"})));
                s2.lock().unwrap().push(Seen { method, path, body });
                let text = payload.to_string();
                let resp = format!(
                    "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        Mock { port, seen, stop, handle: Some(handle) }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn sent(&self, method: &str, path: &str) -> Vec<Seen> {
        self.seen().into_iter().filter(|s| s.method == method && s.path == path).collect()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut want: Option<usize> = None;
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let len = *want.get_or_insert_with(|| {
                String::from_utf8_lossy(&buf[..end])
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                    .unwrap_or(0)
            });
            if buf.len() >= end + 4 + len {
                break;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// The fixture piece: a `ga` and a `loop` group in the contract's shape.
fn piece() -> Value {
    json!({
        "version": 1, "addon": "evolve",
        "groups": [
            {"name": "loop", "summary": "Reflect, propose, approve"},
            {"name": "ga", "summary": "Tune the identity over generations"}
        ],
        "commands": [
            {"group": "ga", "name": "rollback", "summary": "Restore the pre-GA identity",
             "method": "POST", "path": "/api/ga/rollback",
             "args": [{"name": "to", "flag": "--to", "kind": "int", "required": false,
                       "into": "body:genome_id", "help": "genome id to restore"}],
             "confirm": "Restore the assistant's pre-GA identity (or genome N) and pause the GA?",
             "output": {"title": "ga rollback",
                        "fields": [{"key": "/restored", "label": "restored"}, {"key": "/ga_enabled", "label": "ga running"}],
                        "hint": "noo ga resume"}},
            {"group": "ga", "name": "status", "summary": "Show the GA",
             "method": "GET", "path": "/api/ga/status", "args": [],
             "output": {"title": "ga", "fields": [{"key": "/generation", "label": "generation"},
                                                  {"key": "/sections", "label": "sections"},
                                                  {"key": "/enabled", "label": "enabled"}]}},
            {"group": "loop", "name": "cycles", "summary": "List recent cycles",
             "method": "GET", "path": "/api/loop/cycles",
             "args": [{"name": "limit", "flag": "--limit", "kind": "int", "required": false, "into": "query:limit"}],
             "output": {"title": "cycles", "list": "/cycles",
                        "columns": [{"key": "/id", "label": "id"}, {"key": "/score", "label": "score"}]}},
            {"group": "loop", "name": "approve", "summary": "Approve a cycle",
             "method": "POST", "path": "/api/loop/approve/{cycle_id}",
             "args": [{"name": "cycle-id", "kind": "string", "required": true, "into": "path:cycle_id"}],
             "output": {"title": "approved", "fields": [{"key": "/status", "label": "status"}]}}
        ]
    })
}

fn health(evolve: &str) -> Value {
    json!({"status": "ok", "addons": {"trellion": "enabled", "evolve": evolve}})
}

fn gateway_routes(evolve: &str) -> Routes {
    let mut r: Routes = HashMap::new();
    r.insert(("GET".into(), "/health".into()), (200, health(evolve)));
    r.insert(("GET".into(), "/api/addons/trellion/cli-piece".into()), (404, json!({"error": "no_cli_piece"})));
    r.insert(("GET".into(), "/api/addons/evolve/cli-piece".into()), (200, piece()));
    r.insert(("POST".into(), "/api/ga/rollback".into()), (200, json!({"restored": 3, "ga_enabled": false})));
    r.insert(
        ("GET".into(), "/api/ga/status".into()),
        (200, json!({"generation": 12, "sections": ["identity", "tone"], "enabled": true})),
    );
    r.insert(
        ("GET".into(), "/api/loop/cycles?limit=5".into()),
        (200, json!({"cycles": [{"id": "c1", "score": 0.5}, {"id": "c2", "score": null}]})),
    );
    r
}

struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("noo-cli-piece-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Home(dir)
    }

    fn cache_file(&self, port: u16) -> PathBuf {
        self.0.join("addon-cli").join(format!("http___127_0_0_1_{port}.json"))
    }

    /// Pre-seed the per-controller cache, as an earlier run would have.
    fn seed(&self, port: u16, fetched_at: u64, evolve_word: &str) {
        let f = self.cache_file(port);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        let cache = json!({"fetched_at": fetched_at, "addons": {"evolve": evolve_word}, "pieces": {"evolve": piece()}});
        std::fs::write(f, cache.to_string()).unwrap();
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(home: &Path, url: &str, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_noo"));
    cmd.args(["--gateway", url]).args(args);
    for k in ["CONTROLLER_URL", "NOO_GATEWAY_URL", "NOO_TLS_CERT", "NOO_TLS_CA", "NOO_CLUSTER_SECRET", "NOO_INSTANCE", "XDG_CONFIG_HOME"] {
        cmd.env_remove(k);
    }
    cmd.env("HOME", home)
        .env("NOO_CREDENTIALS_FILE", home.join("creds.json"))
        .stdin(Stdio::null());
    cmd.output().expect("spawn noo")
}

/// Lower-cased: the UI sentence-cases its messages ("The evolve add-on ...").
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_lowercase()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_lowercase()
}

#[test]
fn ga_rollback_sends_the_body_the_piece_describes() {
    let home = Home::new("rollback");
    let mock = Mock::start(gateway_routes("enabled"));
    let o = run(&home.0, &mock.url(), &["ga", "rollback", "--to", "3", "-y"]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", err(&o));
    let sent = mock.sent("POST", "/api/ga/rollback");
    assert_eq!(sent.len(), 1, "{:?}", mock.seen());
    assert_eq!(serde_json::from_str::<Value>(&sent[0].body).unwrap(), json!({"genome_id": 3}));
    let text = out(&o);
    assert!(text.contains("restored") && text.contains('3'), "{text}");
    assert!(text.contains("noo ga resume"), "the piece's hint is shown: {text}");
}

#[test]
fn a_flag_with_no_value_is_a_usage_error_that_sends_nothing() {
    let home = Home::new("usage");
    let mock = Mock::start(gateway_routes("enabled"));
    let o = run(&home.0, &mock.url(), &["ga", "rollback", "--to", "x", "-y"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(mock.sent("POST", "/api/ga/rollback").is_empty());
}

#[test]
fn loop_cycles_puts_the_limit_in_the_query_and_renders_a_table() {
    let home = Home::new("cycles");
    let mock = Mock::start(gateway_routes("enabled"));
    let o = run(&home.0, &mock.url(), &["loop", "cycles", "--limit", "5"]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", err(&o));
    assert_eq!(mock.sent("GET", "/api/loop/cycles?limit=5").len(), 1, "{:?}", mock.seen());
    let text = out(&o);
    assert!(text.contains("id") && text.contains("score") && text.contains("c1") && text.contains("0.5"), "{text}");
    assert!(text.contains("c2"), "a null cell does not drop the row: {text}");
}

#[test]
fn a_path_arg_is_substituted_and_encoded() {
    let home = Home::new("path");
    let mut routes = gateway_routes("enabled");
    routes.insert(("POST".into(), "/api/loop/approve/a%2Fb".into()), (200, json!({"status": "applied"})));
    let mock = Mock::start(routes);
    let o = run(&home.0, &mock.url(), &["loop", "approve", "a/b"]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", err(&o));
    assert_eq!(mock.sent("POST", "/api/loop/approve/a%2Fb").len(), 1, "{:?}", mock.seen());
}

#[test]
fn confirm_refuses_without_yes_and_sends_nothing() {
    let home = Home::new("confirm");
    let mock = Mock::start(gateway_routes("enabled"));
    let o = run(&home.0, &mock.url(), &["ga", "rollback", "--to", "3"]);
    assert_eq!(o.status.code(), Some(1), "stdout: {} stderr: {}", out(&o), err(&o));
    assert!(err(&o).contains("confirmation required"), "{}", err(&o));
    assert!(mock.sent("POST", "/api/ga/rollback").is_empty(), "nothing is sent before the answer");
    // --json never prompts either.
    let o = run(&home.0, &mock.url(), &["--json", "ga", "rollback", "--to", "3"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(mock.sent("POST", "/api/ga/rollback").is_empty());
}

#[test]
fn json_prints_the_raw_response() {
    let home = Home::new("json");
    let mock = Mock::start(gateway_routes("enabled"));
    let o = run(&home.0, &mock.url(), &["--json", "ga", "status"]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", err(&o));
    let v: Value = serde_json::from_str(out(&o).trim()).expect("stdout is the response JSON");
    assert_eq!(v, json!({"generation": 12, "sections": ["identity", "tone"], "enabled": true}));
}

#[test]
fn non_scalar_values_render_for_a_human() {
    let home = Home::new("render");
    let mock = Mock::start(gateway_routes("enabled"));
    let o = run(&home.0, &mock.url(), &["ga", "status"]);
    let text = out(&o);
    assert!(text.contains("identity, tone"), "arrays are comma-joined: {text}");
    assert!(text.contains("yes"), "bools are yes/no: {text}");
}

#[test]
fn a_2xx_that_says_error_is_an_error() {
    let home = Home::new("soft");
    let mut routes = gateway_routes("enabled");
    routes.insert(
        ("POST".into(), "/api/loop/approve/c9".into()),
        (200, json!({"status": "error", "detail": "cycle c9 is not pending"})),
    );
    let mock = Mock::start(routes);
    let o = run(&home.0, &mock.url(), &["loop", "approve", "c9"]);
    assert_eq!(o.status.code(), Some(1), "stdout: {}", out(&o));
    assert!(err(&o).contains("cycle c9 is not pending"), "{}", err(&o));
    assert!(!out(&o).contains("approved"), "no success rendering: {}", out(&o));
}

#[test]
fn a_group_that_collides_with_a_core_command_is_ignored_with_a_warning() {
    let home = Home::new("collide");
    let mut p = piece();
    p["groups"].as_array_mut().unwrap().push(json!({"name": "cluster", "summary": "hijack"}));
    p["commands"].as_array_mut().unwrap().push(json!({
        "group": "cluster", "name": "status", "summary": "x", "method": "GET", "path": "/api/ga/status", "args": []
    }));
    let mut routes = gateway_routes("enabled");
    routes.insert(("GET".into(), "/api/addons/evolve/cli-piece".into()), (200, p));
    let mock = Mock::start(routes);
    let o = run(&home.0, &mock.url(), &["ga", "status"]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", err(&o));
    assert!(err(&o).contains("`cluster`") && err(&o).contains("built-in"), "{}", err(&o));
    // The built-in stays the built-in, and the help does not list the add-on's.
    let o = run(&home.0, &mock.url(), &["--help"]);
    let text = out(&o);
    assert!(!text.contains("hijack"), "{text}");
}

#[test]
fn a_disabled_addon_says_so_and_sends_nothing() {
    let home = Home::new("disabled");
    let mut routes = gateway_routes("disabled");
    routes.insert(
        ("GET".into(), "/api/addons/evolve/cli-piece".into()),
        (503, json!({"error": "the evolve add-on is switched off on this install"})),
    );
    let mock = Mock::start(routes);
    // The group is known from an earlier run, when the add-on was on.
    home.seed(mock.port, 0, "enabled");
    let o = run(&home.0, &mock.url(), &["ga", "status"]);
    assert_eq!(o.status.code(), Some(5), "stdout: {} stderr: {}", out(&o), err(&o));
    let e = err(&o);
    assert!(e.contains("the evolve add-on is not enabled"), "{e}");
    assert!(e.contains("switched off on this install"), "the gateway's own sentence: {e}");
    assert!(mock.sent("GET", "/api/ga/status").is_empty());
}

#[test]
fn a_group_nothing_offers_is_the_unknown_command() {
    let home = Home::new("unknown");
    let mock = Mock::start(gateway_routes("enabled"));
    let o = run(&home.0, &mock.url(), &["frobnicate"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(err(&o).contains("unknown command `frobnicate`"), "{}", err(&o));
    // A known group, unknown command: the group's commands are named.
    let o = run(&home.0, &mock.url(), &["ga", "frobnicate"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("status"), "{}", err(&o));
}

#[test]
fn the_stale_cache_is_used_when_the_controller_does_not_answer_health() {
    let home = Home::new("stale");
    let mut routes = gateway_routes("enabled");
    routes.insert(("GET".into(), "/health".into()), (500, json!({"error": "boom"})));
    let mock = Mock::start(routes);
    home.seed(mock.port, 0, "enabled"); // fetched_at 0: long past the TTL
    let o = run(&home.0, &mock.url(), &["ga", "status"]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", err(&o));
    assert_eq!(mock.sent("GET", "/api/ga/status").len(), 1);
}

#[test]
fn help_works_offline_from_the_cache() {
    let home = Home::new("offline");
    // A port nothing listens on.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    home.seed(port, 0, "enabled");
    let url = format!("http://127.0.0.1:{port}");
    let o = run(&home.0, &url, &["ga", "--help"]);
    assert_eq!(o.status.code(), Some(0), "stderr: {}", err(&o));
    let text = out(&o);
    assert!(text.contains("noo ga rollback") && text.contains("noo ga status"), "{text}");
    assert!(text.contains("evolve add-on"), "marked as the add-on's: {text}");
    // A command needs the controller: that failure is the gateway's, not "unknown command".
    let o = run(&home.0, &url, &["ga", "status"]);
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));
}

#[test]
fn the_banner_lists_add_on_groups_marked_as_such() {
    let home = Home::new("banner");
    let mock = Mock::start(gateway_routes("enabled"));
    let o = run(&home.0, &mock.url(), &["--help"]);
    let text = out(&o);
    assert!(text.contains("ga") && text.contains("tune the identity"), "{text}");
    assert!(text.contains("evolve add-on"), "{text}");
}

#[test]
fn the_cache_is_reused_within_the_ttl() {
    let home = Home::new("ttl");
    let mock = Mock::start(gateway_routes("enabled"));
    let _ = run(&home.0, &mock.url(), &["ga", "status"]);
    let _ = run(&home.0, &mock.url(), &["ga", "status"]);
    assert_eq!(mock.sent("GET", "/health").len(), 1, "{:?}", mock.seen());
    assert_eq!(mock.sent("GET", "/api/ga/status").len(), 2);
}
