// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! A nats reload `noo` has CONFIRMED, recorded for the next `noo stack start`.
//!
//! `noo stack start` recreates a service when its `noo.inputs` label changes,
//! and nats's label counts `monitoring/nats/users.conf`
//! (scripts/noo-start-inputs.py). Every provision, enrollment and onboard
//! re-renders that file and HUPs nats, which re-reads it live — so without a
//! record the NEXT plain start recreated nats anyway and every node's NATS
//! link dropped once.
//!
//! After a HUP, [`hup_and_record`] waits for nats-server's own verdict in the
//! container log: a reload that applied logs `Reloaded server configuration`
//! (nats-server server/reload.go, `ReloadOptions` end), one that did not logs
//! `Failed to reload server configuration: <err>` (server/signal.go) and
//! applies NOTHING — a reload is all or nothing, and any change to an option
//! that cannot be hot-swapped (a port, `server_name`, `https_port`, jetstream
//! limits or store dir) fails the whole reload (`diffOptions`). So a
//! confirmed reload means the server runs exactly the file it read.
//!
//! The record goes into the start-inputs state file, under the running
//! container's id, as a KEYED value of the file content the server loaded
//! (the same HMAC key as the labels; never a raw digest):
//!   "reloaded": {"nats": {"container": ID, "paths": {REALPATH: VALUE}}}
//! The value is `null` when a HUP was delivered but not confirmed, or the
//! file moved while it was read: the next start then treats the container as
//! running something unknown and recreates it on any difference.
//! Nothing is written when the state file is missing or was made with
//! another key: that start labels from scratch anyway.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The compose service whose container the record is for.
pub const SERVICE: &str = "nats";
const KEY_BYTES: usize = 32;
const STATE_VERSION: u64 = 1;

/// What nats-server said about a reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Confirmed,
    Failed,
    Unknown,
}

/// nats-server's verdict in the log lines written since the HUP. A failure
/// wins over a success in the same window (two HUPs racing): the record is
/// then not trusted.
pub fn outcome_from_logs(logs: &str) -> Option<Outcome> {
    if logs.contains("Failed to reload server configuration") {
        return Some(Outcome::Failed);
    }
    if logs.contains("Reloaded server configuration") {
        return Some(Outcome::Confirmed);
    }
    None
}

/// HMAC-SHA256 (RFC 2104), hex. Python's `hmac.new(key, msg, sha256)`.
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(Sha256::digest(key).as_slice());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for ((i, o), kb) in ipad.iter_mut().zip(opad.iter_mut()).zip(k.iter()) {
        *i ^= kb;
        *o ^= kb;
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    hex::encode(Sha256::new().chain_update(opad).chain_update(inner).finalize())
}

/// noo-start-inputs.py `key_id`: which key made a state file.
pub fn key_id(key: &[u8]) -> String {
    hmac_sha256_hex(key, b"key-id")[..16].to_string()
}

/// noo-start-inputs.py `reload_value`.
pub fn reload_value(key: &[u8], real: &str, content_sha: &str) -> String {
    hmac_sha256_hex(key, format!("reloaded\0{real}\0{content_sha}").as_bytes())
}

/// The state text with this reload recorded, or `None` when the state must
/// not be written (missing, not ours, another key).
pub fn record_in_state(state: &str, key: &[u8], container: &str, real: &str, value: Option<String>) -> Option<String> {
    let mut doc: serde_json::Value = serde_json::from_str(state).ok()?;
    let obj = doc.as_object_mut()?;
    if obj.get("version").and_then(|v| v.as_u64()) != Some(STATE_VERSION)
        || obj.get("key_id").and_then(|v| v.as_str()) != Some(key_id(key).as_str())
    {
        return None;
    }
    let reloaded = obj.entry("reloaded").or_insert_with(|| serde_json::json!({}));
    if !reloaded.is_object() {
        *reloaded = serde_json::json!({});
    }
    let map = reloaded.as_object_mut()?;
    let same = map.get(SERVICE).and_then(|r| r.get("container")).and_then(|c| c.as_str()) == Some(container);
    let mut paths = if same {
        map.get(SERVICE).and_then(|r| r.get("paths")).and_then(|p| p.as_object()).cloned().unwrap_or_default()
    } else {
        serde_json::Map::new()
    };
    paths.insert(real.to_string(), value.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null));
    map.insert(SERVICE.to_string(), serde_json::json!({"container": container, "paths": paths}));
    serde_json::to_string_pretty(&doc).ok().map(|s| s + "\n")
}

/// The docker side of a reload, behind a trait so the decision is testable.
pub trait NatsCtl {
    fn container_id(&self) -> Option<String>;
    fn hup(&self) -> bool;
    fn logs_since(&self, since: &str) -> Option<String>;
}

pub struct DockerNats {
    pub name: String,
}

impl NatsCtl for DockerNats {
    fn container_id(&self) -> Option<String> {
        let out = std::process::Command::new("docker")
            .args(["inspect", "-f", "{{.Id}}", &self.name])
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !id.is_empty()).then_some(id)
    }

    fn hup(&self) -> bool {
        std::process::Command::new("docker")
            .args(["kill", "-s", "HUP", &self.name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn logs_since(&self, since: &str) -> Option<String> {
        // nats logs to stderr; take both streams.
        let out = std::process::Command::new("docker")
            .args(["logs", "--since", since, &self.name])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&out.stderr));
        Some(s)
    }
}

/// Where the record goes, for one install.
pub struct Paths {
    pub conf: PathBuf,
    pub key: PathBuf,
    pub state: PathBuf,
}

impl Paths {
    /// The launcher's own locations (scripts/lib-start-inputs.sh): the key
    /// in the operator's config dir, the state in the install root (the
    /// launcher runs there; `noo stack start` sets its cwd to the root).
    pub fn for_install(root: &Path, conf: PathBuf) -> Paths {
        let key = match std::env::var("NOO_START_INPUTS_KEY_FILE") {
            Ok(k) if !k.is_empty() => PathBuf::from(k),
            _ => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config/noo/start-inputs.key"),
        };
        let state = match std::env::var("NOO_START_INPUTS_STATE") {
            Ok(s) if !s.is_empty() => root.join(s),
            _ => root.join(".noo-start-inputs.json"),
        };
        Paths { conf, key, state }
    }
}

fn file_sha(p: &Path) -> Option<String> {
    std::fs::read(p).ok().map(|b| hex::encode(Sha256::digest(b)))
}

/// `docker logs --since` takes a Unix timestamp with a fraction.
fn unix_now() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("{}.{:09}", d.as_secs(), d.subsec_nanos())
}

/// HUP nats; when the signal was delivered, wait (`polls` x `pause`) for the
/// server's verdict and record it. Returns whether the signal was delivered
/// (what every caller reports as "reloaded").
pub fn hup_and_record(ctl: &dyn NatsCtl, p: &Paths, polls: u32, pause: Duration) -> bool {
    let id = ctl.container_id();
    let before = file_sha(&p.conf);
    let since = unix_now();
    if !ctl.hup() {
        return false;
    }
    let mut outcome = Outcome::Unknown;
    for n in 0..polls {
        if let Some(o) = ctl.logs_since(&since).as_deref().and_then(outcome_from_logs) {
            outcome = o;
            break;
        }
        if n + 1 < polls {
            std::thread::sleep(pause);
        }
    }
    // The container we signalled must still be the one running.
    let Some(id) = id.filter(|i| ctl.container_id().as_deref() == Some(i.as_str())) else {
        return true;
    };
    let after = file_sha(&p.conf);
    let loaded = match (outcome, before, after) {
        (_, Some(b), Some(a)) if a == b => Some(b),
        _ => None,
    };
    record(p, &id, loaded.as_deref());
    true
}

fn record(p: &Paths, container: &str, content_sha: Option<&str>) {
    let Ok(key) = std::fs::read(&p.key) else { return };
    if key.len() < KEY_BYTES {
        return;
    }
    let Some(real) = std::fs::canonicalize(&p.conf).ok().and_then(|r| r.to_str().map(str::to_string)) else {
        return;
    };
    let Ok(state) = std::fs::read_to_string(&p.state) else { return };
    let value = content_sha.map(|s| reload_value(&key, &real, s));
    if let Some(text) = record_in_state(&state, &key, container, &real, value) {
        let _ = write_private(&p.state, text.as_bytes());
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(data))
        .and_then(|_| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn hmac_matches_python() {
        // RFC 2104 / Python hmac.new(b"key", ..., sha256).
        assert_eq!(
            hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        // A key longer than the block is hashed first.
        assert_eq!(hmac_sha256_hex(&[b'k'; 100], b"m"), "0482265a92ce176b0374f2192380b21e2d40126432c52f865cc0957053ae7a14");
        // noo-start-inputs.py key_id and reload_value, same key and inputs.
        let key = [7u8; 32];
        assert_eq!(key_id(&key), "4980c225bd87eabd");
        assert_eq!(
            reload_value(&key, "/srv/noo/monitoring/nats/users.conf", &"ab".repeat(32)),
            "c1346c75ac87beeb5e57664933a5748b79ad86c10e5a5634036e265f085ed52e"
        );
    }

    #[test]
    fn the_log_verdict() {
        assert_eq!(outcome_from_logs("[1] [INF] Reloaded: accounts\n[1] [INF] Reloaded server configuration (abc)\n"),
                   Some(Outcome::Confirmed));
        assert_eq!(outcome_from_logs("[1] [ERR] Failed to reload server configuration: config reload not supported for Port"),
                   Some(Outcome::Failed));
        // Two HUPs racing: the failure wins.
        assert_eq!(outcome_from_logs("Reloaded server configuration\nFailed to reload server configuration: x"),
                   Some(Outcome::Failed));
        assert_eq!(outcome_from_logs("[1] [INF] Reloaded: accounts\n"), None);
        assert_eq!(outcome_from_logs(""), None);
    }

    struct Fake {
        ids: Vec<&'static str>,
        calls: Cell<usize>,
        hup_ok: bool,
        logs: Option<&'static str>,
    }

    impl NatsCtl for Fake {
        fn container_id(&self) -> Option<String> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            self.ids.get(n).or(self.ids.last()).map(|s| s.to_string())
        }
        fn hup(&self) -> bool {
            self.hup_ok
        }
        fn logs_since(&self, _since: &str) -> Option<String> {
            self.logs.map(str::to_string)
        }
    }

    fn install(tag: &str) -> (PathBuf, Paths, Vec<u8>) {
        let d = std::env::temp_dir().join(format!("noo-nats-reload-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let key = vec![9u8; 32];
        std::fs::write(d.join("key"), &key).unwrap();
        std::fs::write(d.join("users.conf"), "accounts { NOO: { users: [] } }\n").unwrap();
        let state = serde_json::json!({"version": 1, "key_id": key_id(&key), "services": {"nats": {"inputs": {}}}});
        std::fs::write(d.join("state.json"), state.to_string()).unwrap();
        let p = Paths { conf: d.join("users.conf"), key: d.join("key"), state: d.join("state.json") };
        (d, p, key)
    }

    fn recorded(p: &Paths) -> serde_json::Value {
        let s: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p.state).unwrap()).unwrap();
        s["reloaded"][SERVICE].clone()
    }

    fn fake(logs: Option<&'static str>) -> Fake {
        Fake { ids: vec!["c1"], calls: Cell::new(0), hup_ok: true, logs }
    }

    #[test]
    fn hup_records_only_a_confirmed_reload() {
        // Confirmed: the keyed value of the content nats read, for this container.
        let (d, p, key) = install("ok");
        assert!(hup_and_record(&fake(Some("[INF] Reloaded server configuration (x)")), &p, 3, Duration::ZERO));
        let real = std::fs::canonicalize(&p.conf).unwrap().to_str().unwrap().to_string();
        let want = reload_value(&key, &real, &file_sha(&p.conf).unwrap());
        let r = recorded(&p);
        assert_eq!(r["container"], "c1");
        assert_eq!(r["paths"][&real], serde_json::Value::String(want));
        let _ = std::fs::remove_dir_all(d);

        // A failed reload, or no verdict at all: null for this container.
        for (tag, logs) in [("fail", Some("[ERR] Failed to reload server configuration: bad")), ("none", Some("")),
                            ("nologs", None)] {
            let (d, p, _) = install(tag);
            assert!(hup_and_record(&fake(logs), &p, 3, Duration::ZERO));
            let r = recorded(&p);
            assert_eq!(r["container"], "c1", "{tag}");
            assert!(r["paths"].as_object().unwrap().values().all(|v| v.is_null()), "{tag}: {r}");
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn nothing_is_recorded_when_the_signal_or_the_container_moved() {
        // The signal was not delivered: no record, and the caller is told.
        let (d, p, _) = install("nohup");
        let f = Fake { hup_ok: false, ..fake(Some("Reloaded server configuration")) };
        assert!(!hup_and_record(&f, &p, 3, Duration::ZERO));
        assert!(recorded(&p).is_null());
        let _ = std::fs::remove_dir_all(d);
        // nats was recreated meanwhile: the record would name the wrong one.
        let (d, p, _) = install("moved");
        let f = Fake { ids: vec!["c1", "c2"], ..fake(Some("Reloaded server configuration")) };
        assert!(hup_and_record(&f, &p, 3, Duration::ZERO));
        assert!(recorded(&p).is_null());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_state_is_written_only_when_it_is_ours() {
        let key = [3u8; 32];
        let ok = serde_json::json!({"version": 1, "key_id": key_id(&key), "services": {}}).to_string();
        let out = record_in_state(&ok, &key, "c1", "/a/users.conf", Some("v".into())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["reloaded"]["nats"], serde_json::json!({"container": "c1", "paths": {"/a/users.conf": "v"}}));
        assert_eq!(v["services"], serde_json::json!({}), "the rest of the state is kept");
        // A new container replaces the old record; the same one updates it.
        let out2 = record_in_state(&out, &key, "c2", "/a/users.conf", None).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&out2).unwrap();
        assert_eq!(v2["reloaded"]["nats"], serde_json::json!({"container": "c2", "paths": {"/a/users.conf": null}}));
        // Another key, another version, or no JSON: not written.
        let other = serde_json::json!({"version": 1, "key_id": "0000000000000000", "services": {}}).to_string();
        assert!(record_in_state(&other, &key, "c1", "/a", None).is_none());
        let v9 = serde_json::json!({"version": 9, "key_id": key_id(&key)}).to_string();
        assert!(record_in_state(&v9, &key, "c1", "/a", None).is_none());
        assert!(record_in_state("", &key, "c1", "/a", None).is_none());
    }
}
