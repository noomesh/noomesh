// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `.env` read / update / sectioned-write — the load-bearing, pure part of the
//! wizard. Faithful port of `onboard/helpers.py::_update_env`/`_read_env_key`
//! and `step_environment.py`'s sectioned writer so re-runs stay idempotent and
//! the key names + file format match Python byte-for-byte.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Read the whole `.env` into an ordered list of `(key, value)` pairs,
/// skipping comments/blanks. Mirrors step_environment.py's parse loop
/// (`k, _, v = line.partition("=")`, both trimmed). Later duplicate keys win
/// on lookup but order of first appearance is preserved.
pub fn read_env_pairs(path: &Path) -> Vec<(String, String)> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let (k, v) = line.split_once('=').unwrap();
        out.push((k.trim().to_string(), v.trim().to_string()));
    }
    out
}

/// Merge existing pairs into a map keyed by name (last value wins), preserving
/// first-seen order for the "Other" section of the sectioned writer.
pub fn env_map(path: &Path) -> (BTreeMap<String, String>, Vec<String>) {
    let mut map = BTreeMap::new();
    let mut order = Vec::new();
    for (k, v) in read_env_pairs(path) {
        if !map.contains_key(&k) {
            order.push(k.clone());
        }
        map.insert(k, v);
    }
    (map, order)
}

/// Read a single key. `''` when absent. Parity with `_read_env_key`.
pub fn read_env_key(path: &Path, key: &str) -> String {
    let Ok(content) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let prefix = format!("{key}=");
    for line in content.lines() {
        let stripped = line.trim();
        if let Some(rest) = stripped.strip_prefix(&prefix) {
            return rest.trim().to_string();
        }
    }
    String::new()
}

/// Update or append `key=value` in place, preserving all other lines. Exact
/// port of `helpers._update_env`: matches `key=` OR `key =` at line start;
/// appends if not found; writes joined with `\n` + a trailing newline.
/// Delete every `KEY=…` line. A BLANKED slot is not enough for a retired
/// flag: the launcher's refusal greps `^KEY=` and matches `KEY=` too.
/// Returns whether anything was removed.
pub fn remove_env_key(path: &Path, key: &str) -> std::io::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(path)?;
    let eq = format!("{key}=");
    let sp = format!("{key} =");
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| { let s = l.trim_start(); !(s.starts_with(&eq) || s.starts_with(&sp)) })
        .collect();
    let removed = kept.len() != content.lines().count();
    if removed {
        let mut out = kept.join("\n");
        out.push('\n');
        std::fs::write(path, out)?;
    }
    Ok(removed)
}

/// The retired-.env-key list: `KEY|what replaced it`, `#` comments. One
/// file, `scripts/retired-env-keys`, read by the launcher's WARN and by
/// `noo onboard --only env`.
pub fn parse_retired_keys(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('|'))
        .map(|(k, n)| (k.trim().to_string(), n.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// The list as shipped: the copy embedded in this binary, else the checkout's.
pub fn retired_env_keys() -> Vec<(String, String)> {
    let embedded = crate::onboard::standalone::STANDALONE_ASSETS.iter()
        .find(|(rel, _, _)| *rel == "scripts/retired-env-keys")
        .and_then(|(_, bytes, _)| std::str::from_utf8(bytes).ok().map(str::to_string));
    let text = embedded
        .or_else(|| std::fs::read_to_string(crate::envfile::repo_root().join("scripts/retired-env-keys")).ok())
        .unwrap_or_default();
    parse_retired_keys(&text)
}

/// Which of `retired` the `.env` at `path` still sets (a `KEY=` line).
pub fn retired_keys_set(path: &Path, retired: &[(String, String)]) -> Vec<(String, String)> {
    let Ok(content) = std::fs::read_to_string(path) else { return Vec::new() };
    retired.iter()
        .filter(|(k, _)| content.lines().any(|l| {
            let s = l.trim_start();
            s.starts_with(&format!("{k}=")) || s.starts_with(&format!("{k} ="))
        }))
        .cloned()
        .collect()
}

/// Back `.env` up as `.env.bak_<ts>` (same directory, same permissions), then
/// delete every line of the given keys. Returns the backup path. Touches
/// nothing else — never `secrets/env.sops`.
pub fn remove_retired_keys(path: &Path, keys: &[String], ts: &str) -> std::io::Result<PathBuf> {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| ".env".into());
    let backup = path.with_file_name(format!("{name}.bak_{ts}"));
    std::fs::copy(path, &backup)?;
    for k in keys {
        remove_env_key(path, k)?;
    }
    Ok(backup)
}

pub fn update_env_key(path: &Path, key: &str, value: &str) -> std::io::Result<()> {
    if !path.exists() {
        return std::fs::write(path, format!("{key}={value}\n"));
    }
    let content = std::fs::read_to_string(path)?;
    let eq = format!("{key}=");
    let sp = format!("{key} =");
    let mut found = false;
    let mut new_lines: Vec<String> = Vec::new();
    for line in content.lines() {
        let stripped = line.trim_start();
        if stripped.starts_with(&eq) || stripped.starts_with(&sp) {
            new_lines.push(format!("{key}={value}"));
            found = true;
        } else {
            new_lines.push(line.to_string());
        }
    }
    if !found {
        new_lines.push(format!("{key}={value}"));
    }
    let mut body = new_lines.join("\n");
    body.push('\n');
    std::fs::write(path, body)
}

/// Section layout matching `step_environment.py`'s `sections` list exactly.
const SECTIONS: &[(&str, &[&str])] = &[
    (
        "Node identity",
        &[
            "NODE_ID", "NODE_IP", "CLUSTER_MODE", "NODE_TIER", "GPU_MODEL", "VRAM_GB",
            "CONTROLLER_URL", "IS_ARM",
        ],
    ),
    ("Storage", &["NOO_DATA_ROOT"]),
    (
        "Backend settings",
        &[
            "VLLM_MODEL", "GPU_MEM_UTIL", "LLAMACPP_MODEL", "N_GPU_LAYERS", "N_CTX",
            "AIRLLM_MODEL", "MAX_VRAM_GB",
        ],
    ),
    ("Monitoring", &["GRAFANA_PASSWORD", "NOO_GRAFANA_BIND_ADDR"]),
    (
        "API keys",
        &["HF_TOKEN", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
    ),
    (
        "Channels",
        &[
            "TELEGRAM_BOT_TOKEN", "WHATSAPP_TOKEN",
            "WHATSAPP_PHONE_ID", "WHATSAPP_VERIFY_TOKEN", "WHATSAPP_APP_SECRET",
            "NGROK_DOMAIN", "GOOGLE_CHAT_KEY_FILE",
            "GOOGLE_CHAT_CREDENTIALS", "GOOGLE_CHAT_PROJECT_ID",
            "GOOGLE_CHAT_BEARER_TOKEN",
        ],
    ),
];

/// Render the sectioned `.env` body from a merged key→value map, matching
/// `step_environment.py`'s writer: header with a timestamp, grouped sections
/// (only non-empty keys emitted), then an "Other" block for anything left, in
/// first-seen order. `now` is the `%Y-%m-%d %H:%M:%S` stamp (injectable for
/// deterministic tests).
pub fn render_sectioned(
    merged: &BTreeMap<String, String>,
    order: &[String],
    now: &str,
) -> String {
    let mut lines: Vec<String> = vec![
        "# Noomesh Node Configuration".to_string(),
        format!("# Generated by 'noo onboard' on {now}"),
        String::new(),
    ];
    let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (section_name, keys) in SECTIONS {
        let mut section_lines: Vec<String> = Vec::new();
        for k in *keys {
            if let Some(v) = merged.get(*k) {
                if !v.is_empty() {
                    section_lines.push(format!("{k}={v}"));
                    written.insert((*k).to_string());
                }
            }
        }
        if !section_lines.is_empty() {
            lines.push(format!("# {section_name}"));
            lines.extend(section_lines);
            lines.push(String::new());
        }
    }
    // Remaining keys not placed in a section, in first-seen order.
    let mut remaining: Vec<String> = Vec::new();
    for k in order {
        if written.contains(k) {
            continue;
        }
        if let Some(v) = merged.get(k) {
            if !v.is_empty() {
                remaining.push(format!("{k}={v}"));
            }
        }
    }
    if !remaining.is_empty() {
        lines.push("# Other".to_string());
        lines.extend(remaining);
        lines.push(String::new());
    }
    let mut body = lines.join("\n");
    body.push('\n');
    body
}

#[cfg(test)]
mod tests {
    #[test]
    fn remove_env_key_deletes_set_and_blank_lines() {
        let d = std::env::temp_dir().join(format!("noo-rek-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let f = d.join(".env");
        std::fs::write(&f, "A=1\nNOO_TRELLION_ENABLED=1\nB=2\nNOO_TRELLION_ENABLED=\n").unwrap();
        assert!(super::remove_env_key(&f, "NOO_TRELLION_ENABLED").unwrap());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "A=1\nB=2\n");
        assert!(!super::remove_env_key(&f, "NOO_TRELLION_ENABLED").unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    use super::*;

    #[test]
    fn retired_keys_are_listed_offered_and_removed_with_a_backup() {
        let list = parse_retired_keys("# c\nTELEGRAM_ALLOWED_USERS|it admits nobody\n\nOLD_KEY|gone\n");
        assert_eq!(list.len(), 2);
        // The shipped file parses and names the launcher's known key.
        let shipped = parse_retired_keys(include_str!("../../../scripts/retired-env-keys"));
        assert!(shipped.iter().any(|(k, n)| k == "TELEGRAM_ALLOWED_USERS" && n.contains("noo security user link")));

        let p = tmp();
        std::fs::write(&p, "A=1\nTELEGRAM_ALLOWED_USERS=123\n# OLD_KEY=commented\nB=2\n").unwrap();
        let set = retired_keys_set(&p, &list);
        assert_eq!(set.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["TELEGRAM_ALLOWED_USERS"]);
        let bak = remove_retired_keys(&p, &["TELEGRAM_ALLOWED_USERS".to_string()], "1790000000").unwrap();
        assert!(bak.file_name().unwrap().to_string_lossy() == ".env.bak_1790000000", "{bak:?}");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "A=1\nTELEGRAM_ALLOWED_USERS=123\n# OLD_KEY=commented\nB=2\n");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "A=1\n# OLD_KEY=commented\nB=2\n");
        assert!(retired_keys_set(&p, &list).is_empty());
    }

    fn tmp() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("paienv-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&p).unwrap();
        p.join(".env")
    }
    fn rand_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn update_creates_when_missing() {
        let p = tmp();
        update_env_key(&p, "FOO", "bar").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "FOO=bar\n");
    }

    #[test]
    fn update_is_idempotent_inplace() {
        let p = tmp();
        std::fs::write(&p, "A=1\nFOO=old\nB=2\n").unwrap();
        update_env_key(&p, "FOO", "new").unwrap();
        // FOO replaced in place, A/B untouched, order preserved.
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "A=1\nFOO=new\nB=2\n");
        // Running again with the same value is a no-op on content.
        update_env_key(&p, "FOO", "new").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "A=1\nFOO=new\nB=2\n");
    }

    #[test]
    fn update_appends_new_key() {
        let p = tmp();
        std::fs::write(&p, "A=1\n").unwrap();
        update_env_key(&p, "B", "2").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "A=1\nB=2\n");
    }

    #[test]
    fn update_matches_spaced_form() {
        let p = tmp();
        std::fs::write(&p, "FOO = x\n").unwrap();
        update_env_key(&p, "FOO", "y").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "FOO=y\n");
    }

    #[test]
    fn read_key_and_pairs() {
        let p = tmp();
        std::fs::write(&p, "# c\nA=1\n\nB=two \n").unwrap();
        assert_eq!(read_env_key(&p, "A"), "1");
        assert_eq!(read_env_key(&p, "B"), "two");
        assert_eq!(read_env_key(&p, "MISSING"), "");
        let pairs = read_env_pairs(&p);
        assert_eq!(pairs, vec![("A".into(), "1".into()), ("B".into(), "two".into())]);
    }

    #[test]
    fn read_key_ignores_spaced_form_like_python() {
        // Parity: `_read_env_key` only matches `KEY=` (not `KEY =`); the
        // spaced form is readable only via read_env_pairs' partition.
        let p = tmp();
        std::fs::write(&p, "B = two\n").unwrap();
        assert_eq!(read_env_key(&p, "B"), "");
        assert_eq!(read_env_pairs(&p), vec![("B".into(), "two".into())]);
    }

    #[test]
    fn sectioned_groups_and_other() {
        let mut m = BTreeMap::new();
        m.insert("NODE_ID".to_string(), "n1".to_string());
        m.insert("NODE_TIER".to_string(), "1".to_string());
        m.insert("NOO_JWT_SECRET".to_string(), "sek".to_string());
        m.insert("EMPTY".to_string(), "".to_string());
        let order = vec![
            "NODE_ID".to_string(),
            "NODE_TIER".to_string(),
            "NOO_JWT_SECRET".to_string(),
            "EMPTY".to_string(),
        ];
        let out = render_sectioned(&m, &order, "2026-01-01 00:00:00");
        assert!(out.starts_with("# Noomesh Node Configuration\n# Generated by 'noo onboard' on 2026-01-01 00:00:00\n\n"));
        assert!(out.contains("# Node identity\nNODE_ID=n1\nNODE_TIER=1\n"));
        // Unsectioned key lands in Other; empty value is dropped.
        assert!(out.contains("# Other\nNOO_JWT_SECRET=sek\n"));
        assert!(!out.contains("EMPTY="));
        assert!(out.ends_with('\n'));
    }
}
