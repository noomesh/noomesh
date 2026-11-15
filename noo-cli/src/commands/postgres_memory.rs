// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `cluster.postgres_memory: standard | auto`: how much memory Postgres asks
//! for on this install.
//!
//! The ONE declaration is `cluster.postgres_memory` in the install's
//! noomesh.yaml, beside `cluster.monitoring` and, like it, never an
//! environment variable. UNSET MEANS STANDARD: the compose defaults of the
//! postgres service (shared_buffers 512MB, effective_cache_size 2GB,
//! work_mem 32MB, maintenance_work_mem 256MB, /dev/shm 1g), byte for byte
//! what every install ran before the setting existed. Only the literal
//! `auto` sizes Postgres to the memory Docker gives containers on this
//! machine ([`tier_for`]); a typo keeps standard.
//!
//! An explicit `NOO_PG_*` value (the environment, noomesh.yaml
//! `compose_env`, `.env`) always wins over `auto`: the declaration beats the
//! derived value, and nothing the operator set is ever silently replaced.
//! `auto` only fills the keys nobody set; `standard` fills none, so the
//! compose defaults apply exactly as before.
//!
//! Three readers share this rule: the launcher (`scripts/lib-config.sh`
//! `postgres_memory_derive_env`, through `noo config launch-render
//! postgres-memory`), `noo onboard`'s own compose calls ([`derived_env_live`])
//! and the `postgres memory` row of `noo cluster verify`. The shell copy of
//! the table is pinned to this one by tests/test_postgres_memory_launcher.py.
//!
//! A changed value takes effect only when noo-postgres is recreated: the
//! values are arguments of its command and its shm size.

use std::path::Path;

/// The compose variables `auto` sizes, in table order.
pub(crate) const KEYS: [&str; 5] = [
    "NOO_PG_SHARED_BUFFERS",
    "NOO_PG_EFFECTIVE_CACHE_SIZE",
    "NOO_PG_WORK_MEM",
    "NOO_PG_MAINTENANCE_WORK_MEM",
    "NOO_PG_SHM_SIZE",
];

/// What each key sets, in words (the verify row's labels).
pub(crate) const LABELS: [&str; 5] = ["shared_buffers", "effective_cache_size", "work_mem", "maintenance_work_mem", "/dev/shm"];

/// The compose defaults of docker-compose.cluster.yml's postgres service:
/// `standard`, and `auto` on a machine with 12 GiB or more.
pub(crate) const STANDARD: [&str; 5] = ["512MB", "2GB", "32MB", "256MB", "1g"];
/// `auto` below 6 GiB (the 4 GB tier).
pub(crate) const SMALL: [&str; 5] = ["128MB", "512MB", "8MB", "64MB", "256m"];
/// `auto` from 6 GiB to below 12 GiB (the 8 GB tier).
pub(crate) const MEDIUM: [&str; 5] = ["256MB", "1GB", "16MB", "128MB", "512m"];

const GIB: u64 = 1 << 30;
/// Below this, the 4 GB tier. A 4 GB machine reports about 3.7 GiB.
pub(crate) const SMALL_BELOW: u64 = 6 * GIB;
/// Below this, the 8 GB tier. A 16 GB machine reports about 15.5 GiB (the
/// kernel keeps some), so the line sits between the two tiers, not at 16.
pub(crate) const MEDIUM_BELOW: u64 = 12 * GIB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Standard,
    Auto,
}

/// The raw `cluster.postgres_memory` of a noomesh.yaml text, trimmed. `None`
/// when the key is absent, not a string, or the text does not parse.
pub(crate) fn declared_in(yaml: &str) -> Option<String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    doc.get("cluster")?.get("postgres_memory")?.as_str().map(|s| s.trim().to_string())
}

/// Unset = standard. Only the literal `auto` is auto; a typo keeps standard.
pub(crate) fn mode_of(declared: Option<&str>) -> Mode {
    match declared.map(str::trim) {
        Some("auto") => Mode::Auto,
        _ => Mode::Standard,
    }
}

/// The `auto` values for a machine whose containers can use `ram_bytes`.
pub(crate) fn tier_for(ram_bytes: u64) -> [&'static str; 5] {
    if ram_bytes < SMALL_BELOW {
        SMALL
    } else if ram_bytes < MEDIUM_BELOW {
        MEDIUM
    } else {
        STANDARD
    }
}

/// Where one value in effect comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// A `NOO_PG_*` the operator set (environment, compose_env, `.env`).
    Explicit,
    /// Derived by `auto` from this machine's memory.
    Auto,
    /// The compose default.
    Standard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Setting {
    pub key: &'static str,
    pub value: String,
    pub source: Source,
}

/// The value of every key Postgres will be created with. `explicit` answers
/// a key the operator set (non-empty), `None` otherwise. `auto` with an
/// unknown `ram` keeps the standard values.
pub(crate) fn effective(mode: Mode, ram: Option<u64>, explicit: &dyn Fn(&str) -> Option<String>) -> Vec<Setting> {
    let derived = match (mode, ram) {
        (Mode::Auto, Some(r)) => Some(tier_for(r)),
        _ => None,
    };
    KEYS.iter()
        .enumerate()
        .map(|(i, &key)| match explicit(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
            Some(v) => Setting { key, value: v, source: Source::Explicit },
            None => match derived {
                Some(t) => Setting { key, value: t[i].to_string(), source: Source::Auto },
                None => Setting { key, value: STANDARD[i].to_string(), source: Source::Standard },
            },
        })
        .collect()
}

/// What a launcher exports for compose: the `auto` values of the keys
/// nobody set. Empty for `standard` (the compose defaults apply as ever)
/// and for every key with an explicit value.
pub(crate) fn derived_env(mode: Mode, ram: Option<u64>, explicit: &dyn Fn(&str) -> Option<String>) -> Vec<(&'static str, String)> {
    effective(mode, ram, explicit)
        .into_iter()
        .filter(|s| s.source == Source::Auto)
        .map(|s| (s.key, s.value))
        .collect()
}

/// A key the operator set: the process environment (which holds compose_env
/// and `.env` once `envfile::ensure_repo_env` ran), else the `.env` text.
/// An empty value is unset, as compose's `${VAR:-default}` treats it.
pub(crate) fn explicit_in(key: &str, dotenv: &str) -> Option<String> {
    let nonempty = |v: String| Some(v.trim().to_string()).filter(|v| !v.is_empty());
    std::env::var(key)
        .ok()
        .and_then(nonempty)
        .or_else(|| crate::envfile::dotenv_last(dotenv, key).and_then(nonempty))
}

/// Memory containers can use on this machine, in bytes: Docker's MemTotal
/// (the WSL2 or Docker Desktop VM where there is one), else /proc/meminfo,
/// else macOS `hw.memsize`. `None` when none answers.
pub(crate) fn host_ram_live() -> Option<u64> {
    let run = |cmd: &str, args: &[&str]| {
        std::process::Command::new(cmd)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
    };
    run("docker", &["info", "--format", "{{.MemTotal}}"])
        .or_else(|| std::fs::read_to_string("/proc/meminfo").ok().and_then(|m| meminfo_total(&m)))
        .or_else(|| run("sysctl", &["-n", "hw.memsize"]))
}

/// MemTotal of a /proc/meminfo body, in bytes.
pub(crate) fn meminfo_total(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

/// The env `noo onboard`'s compose calls carry, read the way the launcher
/// reads it: `root`/noomesh.yaml's mode, this machine's memory, the
/// operator's explicit values (`dotenv` is the install's `.env` text).
/// Docker is asked for its memory only when the mode is `auto`.
pub(crate) fn derived_env_live(root: &Path, dotenv: &str) -> Vec<(&'static str, String)> {
    let yaml = std::fs::read_to_string(root.join("noomesh.yaml")).unwrap_or_default();
    let mode = mode_of(declared_in(&yaml).as_deref());
    if mode == Mode::Standard {
        return Vec::new();
    }
    derived_env(mode, host_ram_live(), &|k| explicit_in(k, dotenv))
}

/// Bytes of a Postgres memory value (`512MB`, `1GB`, `8kB`, a bare number
/// in `base` bytes). Units as Postgres takes them, case-insensitive.
pub(crate) fn pg_bytes(v: &str, base: u64) -> Option<u64> {
    let v = v.trim();
    let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let n: u64 = v[..split].parse().ok()?;
    let mult = match v[split..].trim().to_ascii_lowercase().as_str() {
        "" => base,
        "b" => 1,
        "kb" => 1 << 10,
        "mb" => 1 << 20,
        "gb" => 1 << 30,
        "tb" => 1 << 40,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// Bytes of a Docker size (`1g`, `512m`, `256mb`, a bare number of bytes).
pub(crate) fn docker_bytes(v: &str) -> Option<u64> {
    let v = v.trim();
    let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let n: u64 = v[..split].parse().ok()?;
    let mult = match v[split..].trim().to_ascii_lowercase().trim_end_matches('b') {
        "" => 1,
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// Bytes of one key's value: Docker units for the shm size, Postgres units
/// (bare number = the GUC's own unit) for the rest.
pub(crate) fn key_bytes(key: &str, v: &str) -> Option<u64> {
    match key {
        "NOO_PG_SHM_SIZE" => docker_bytes(v),
        // shared_buffers and effective_cache_size count 8 kB pages.
        "NOO_PG_SHARED_BUFFERS" | "NOO_PG_EFFECTIVE_CACHE_SIZE" => pg_bytes(v, 8 << 10),
        _ => pg_bytes(v, 1 << 10),
    }
}

/// Bytes of one `pg_settings` row: `setting` times `unit` (`8kB`, `kB`).
pub(crate) fn pg_setting_bytes(setting: &str, unit: &str) -> Option<u64> {
    let n: u64 = setting.trim().parse().ok()?;
    let unit = unit.trim();
    let split = unit.find(|c: char| !c.is_ascii_digit()).unwrap_or(unit.len());
    let count: u64 = if split == 0 { 1 } else { unit[..split].parse().ok()? };
    n.checked_mul(pg_bytes(&format!("{count}{}", &unit[split..]), 1)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> Option<String> {
        None
    }

    fn values(s: &[Setting]) -> Vec<&str> {
        s.iter().map(|s| s.value.as_str()).collect()
    }

    #[test]
    fn unset_and_typos_are_standard_and_only_auto_is_auto() {
        assert_eq!(mode_of(None), Mode::Standard);
        assert_eq!(mode_of(Some("standard")), Mode::Standard);
        assert_eq!(mode_of(Some("Auto")), Mode::Standard, "a typo keeps today's values");
        assert_eq!(mode_of(Some(" auto ")), Mode::Auto);
        assert_eq!(declared_in("cluster:\n  postgres_memory: auto\n").as_deref(), Some("auto"));
        assert_eq!(declared_in("postgres_memory: auto\n"), None, "only the cluster key counts");
        assert_eq!(declared_in("cluster:\n  monitoring: lean\n"), None);
    }

    #[test]
    fn standard_is_the_compose_defaults_and_exports_nothing() {
        let compose = std::fs::read_to_string(crate::test_support::repo_file("docker-compose.cluster.yml")).unwrap();
        for (k, v) in KEYS.iter().zip(STANDARD) {
            assert!(compose.contains(&format!("${{{k}:-{v}}}")), "{k} default in compose is not {v}");
        }
        let got = effective(Mode::Standard, Some(4 * GIB), &none);
        assert_eq!(values(&got), STANDARD.to_vec());
        assert!(got.iter().all(|s| s.source == Source::Standard));
        assert!(derived_env(Mode::Standard, Some(4 * GIB), &none).is_empty(), "standard must leave compose's defaults alone");
    }

    #[test]
    fn auto_picks_the_tier_for_the_memory() {
        let mib = 1u64 << 20;
        // What 4, 8 and 16 GB machines report (MemTotal under-reads).
        assert_eq!(values(&effective(Mode::Auto, Some(3_800 * mib), &none)), SMALL.to_vec());
        assert_eq!(values(&effective(Mode::Auto, Some(7_800 * mib), &none)), MEDIUM.to_vec());
        assert_eq!(values(&effective(Mode::Auto, Some(15_600 * mib), &none)), STANDARD.to_vec());
        assert_eq!(values(&effective(Mode::Auto, Some(64 * GIB), &none)), STANDARD.to_vec());
        assert_eq!(tier_for(SMALL_BELOW - 1), SMALL);
        assert_eq!(tier_for(SMALL_BELOW), MEDIUM);
        assert_eq!(tier_for(MEDIUM_BELOW - 1), MEDIUM);
        assert_eq!(tier_for(MEDIUM_BELOW), STANDARD);
        assert_eq!(SMALL, ["128MB", "512MB", "8MB", "64MB", "256m"]);
        assert_eq!(MEDIUM, ["256MB", "1GB", "16MB", "128MB", "512m"]);
        assert_eq!(derived_env(Mode::Auto, Some(4 * GIB), &none).len(), 5);
    }

    #[test]
    fn auto_with_unknown_memory_keeps_standard() {
        assert_eq!(values(&effective(Mode::Auto, None, &none)), STANDARD.to_vec());
        assert!(derived_env(Mode::Auto, None, &none).is_empty());
    }

    #[test]
    fn an_explicit_value_wins_over_auto() {
        let explicit = |k: &str| match k {
            "NOO_PG_WORK_MEM" => Some("64MB".to_string()),
            "NOO_PG_SHM_SIZE" => Some("  ".to_string()),
            _ => None,
        };
        let got = effective(Mode::Auto, Some(4 * GIB), &explicit);
        let wm = got.iter().find(|s| s.key == "NOO_PG_WORK_MEM").unwrap();
        assert_eq!((wm.value.as_str(), wm.source), ("64MB", Source::Explicit));
        let shm = got.iter().find(|s| s.key == "NOO_PG_SHM_SIZE").unwrap();
        assert_eq!((shm.value.as_str(), shm.source), ("256m", Source::Auto), "an empty value is unset");
        let env = derived_env(Mode::Auto, Some(4 * GIB), &explicit);
        assert!(env.iter().all(|(k, _)| *k != "NOO_PG_WORK_MEM"), "never exported over the operator's value: {env:?}");
        assert_eq!(env.len(), 4);
    }

    #[test]
    fn sizes_compare_in_bytes() {
        assert_eq!(key_bytes("NOO_PG_SHARED_BUFFERS", "1GB"), key_bytes("NOO_PG_SHARED_BUFFERS", "1024MB"));
        assert_eq!(key_bytes("NOO_PG_SHARED_BUFFERS", "65536"), Some(512 << 20), "bare = 8 kB pages");
        assert_eq!(key_bytes("NOO_PG_WORK_MEM", "32768"), Some(32 << 20), "bare = kB");
        assert_eq!(key_bytes("NOO_PG_SHM_SIZE", "1g"), Some(1 << 30));
        assert_eq!(key_bytes("NOO_PG_SHM_SIZE", "512mb"), Some(512 << 20));
        assert_eq!(key_bytes("NOO_PG_WORK_MEM", "lots"), None);
        assert_eq!(pg_setting_bytes("65536", "8kB"), Some(512 << 20));
        assert_eq!(pg_setting_bytes("32768", "kB"), Some(32 << 20));
        assert_eq!(meminfo_total("MemTotal:       16303432 kB\nMemFree: 1 kB\n"), Some(16_303_432 * 1024));
    }
}
