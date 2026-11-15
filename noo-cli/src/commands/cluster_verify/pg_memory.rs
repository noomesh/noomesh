// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The `postgres memory` row: which `cluster.postgres_memory` mode this
//! install declares, the sizes that mode and the operator's explicit
//! `NOO_PG_*` values ask for, and whether the running noo-postgres was
//! created with them. A changed value takes effect only when postgres is
//! recreated, so a difference is "recreate needed" (a warning, with the
//! command), never a failure. The temp-spill figure of the noomesh database
//! (`pg_stat_database`) rides along as information.
//!
//! The decision is [`row`], a pure function of what was read; [`live`]
//! gathers it. Mode, table and precedence are
//! [`crate::commands::postgres_memory`], the same rule the launcher applies.

use super::{ok, warn, Check};
use crate::commands::postgres_memory::{self as pm, Mode, Setting, Source};
use std::path::Path;

pub(crate) const ROW: &str = "postgres memory";

/// The `pg_settings` names of the first four keys, in [`pm::KEYS`] order.
const GUCS: [&str; 4] = ["shared_buffers", "effective_cache_size", "work_mem", "maintenance_work_mem"];

/// What the running container was created with, per key in [`pm::KEYS`]
/// order, in bytes (`None` = not reported).
pub(crate) type Running = [Option<u64>; 5];

fn fmt_bytes(b: u64) -> String {
    const K: u64 = 1 << 10;
    match b {
        0 => "0".into(),
        b if b % (K * K * K) == 0 => format!("{}GB", b / (K * K * K)),
        b if b % (K * K) == 0 => format!("{}MB", b / (K * K)),
        b if b % K == 0 => format!("{}kB", b / K),
        b => format!("{b}B"),
    }
}

fn head(mode: Mode, declared: Option<&str>, ram: Option<u64>) -> String {
    match (mode, declared, ram) {
        (Mode::Auto, _, Some(r)) => format!("auto for {:.1} GiB", r as f64 / (1u64 << 30) as f64),
        (Mode::Auto, _, None) => "auto, but this machine's memory could not be read, so standard".into(),
        (Mode::Standard, None, _) => "standard (cluster.postgres_memory unset)".into(),
        (Mode::Standard, Some("standard"), _) => "standard".into(),
        (Mode::Standard, Some(v), _) => format!("standard ('{v}' is neither standard nor auto)"),
    }
}

fn values(want: &[Setting]) -> String {
    want.iter()
        .zip(pm::LABELS)
        .map(|(s, label)| match s.source {
            Source::Explicit => format!("{label} {} ({}, set by you)", s.value, s.key),
            _ => format!("{label} {}", s.value),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn spill_words(spill: Option<(u64, u64)>) -> String {
    match spill {
        Some((files, bytes)) => format!(
            "; temp spill since the stats reset: {files} file(s), {:.0} MiB",
            bytes as f64 / (1u64 << 20) as f64
        ),
        None => String::new(),
    }
}

/// The row. `want` is [`pm::effective`]; `running` is what the container
/// was created with (`None` when it could not be read); `spill` is
/// `(temp_files, temp_bytes)` of the noomesh database.
pub(crate) fn row(mode: Mode, declared: Option<&str>, ram: Option<u64>, want: &[Setting], running: Option<&Running>, spill: Option<(u64, u64)>) -> Check {
    let head = head(mode, declared, ram);
    let Some(running) = running else {
        return warn(
            ROW,
            format!("{head}: {}; the running postgres was not read (container not running)", values(want)),
            Some("noo stack status".into()),
        );
    };
    let differ: Vec<String> = want
        .iter()
        .zip(pm::LABELS)
        .zip(running.iter())
        .filter_map(|((s, label), got)| {
            let wanted = pm::key_bytes(s.key, &s.value)?;
            let got = (*got)?;
            (wanted != got).then(|| format!("{label} {} (runs {})", s.value, fmt_bytes(got)))
        })
        .collect();
    if !differ.is_empty() {
        return warn(
            ROW,
            format!(
                "recreate needed: {head} asks for {}; a changed value takes effect only when postgres is recreated{}",
                differ.join(", "),
                spill_words(spill)
            ),
            Some("noo stack restart --force postgres".into()),
        );
    }
    ok(ROW, format!("{head}: {}; the running postgres matches{}", values(want), spill_words(spill)))
}

/// `name|setting|unit` lines of `pg_settings` and the container's
/// `HostConfig.ShmSize` (bytes) into [`Running`]. `None` when neither
/// says anything.
pub(crate) fn parse_running(pg_settings: &str, shm: Option<&str>) -> Option<Running> {
    let mut out: Running = [None; 5];
    for line in pg_settings.lines() {
        let mut f = line.trim().split('|');
        let (Some(name), Some(setting)) = (f.next(), f.next()) else { continue };
        let unit = f.next().unwrap_or("");
        if let Some(i) = GUCS.iter().position(|g| *g == name.trim()) {
            out[i] = pm::pg_setting_bytes(setting, unit);
        }
    }
    out[4] = shm.and_then(|s| s.trim().parse::<u64>().ok()).filter(|n| *n > 0);
    out.iter().any(Option::is_some).then_some(out)
}

/// `temp_files|temp_bytes` of one `pg_stat_database` row.
pub(crate) fn parse_spill(line: &str) -> Option<(u64, u64)> {
    let mut f = line.trim().split('|');
    Some((f.next()?.trim().parse().ok()?, f.next()?.trim().parse().ok()?))
}

fn psql(container: &str, sql: &str) -> Option<String> {
    let db = std::env::var("POSTGRES_DB").unwrap_or_else(|_| "noomesh".into());
    let user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "noo".into());
    let out = std::process::Command::new("docker")
        .args(["exec", container, "psql", "-X", "-w", "-U", user.as_str(), "-d", db.as_str(), "-tAc", sql])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Read everything and judge. Docker is asked for this machine's memory
/// only on `auto`.
pub(crate) fn live(root: &Path) -> Check {
    crate::envfile::ensure_repo_env();
    let yaml = std::fs::read_to_string(root.join("noomesh.yaml")).unwrap_or_default();
    let dotenv = std::fs::read_to_string(root.join(".env")).unwrap_or_default();
    let declared = pm::declared_in(&yaml);
    let mode = pm::mode_of(declared.as_deref());
    let ram = if mode == Mode::Auto { pm::host_ram_live() } else { None };
    let want = pm::effective(mode, ram, &|k| pm::explicit_in(k, &dotenv));
    let container = crate::envfile::container("postgres");
    let (running, spill) = if crate::commands::secrets::container_running(&container) {
        let settings = psql(
            &container,
            "SELECT name, setting, coalesce(unit, '') FROM pg_settings WHERE name IN ('shared_buffers', 'effective_cache_size', 'work_mem', 'maintenance_work_mem')",
        )
        .unwrap_or_default();
        let shm = std::process::Command::new("docker")
            .args(["inspect", "-f", "{{.HostConfig.ShmSize}}", container.as_str()])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
        let spill = psql(&container, "SELECT temp_files, temp_bytes FROM pg_stat_database WHERE datname = current_database()")
            .and_then(|s| parse_spill(&s));
        (parse_running(&settings, shm.as_deref()), spill)
    } else {
        (None, None)
    };
    row(mode, declared.as_deref(), ram, &want, running.as_ref(), spill)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    /// What a container created with the standard sizes reports.
    const STANDARD_PG: &str = "effective_cache_size|262144|8kB\nmaintenance_work_mem|262144|kB\nshared_buffers|65536|8kB\nwork_mem|32768|kB\n";
    const STANDARD_SHM: &str = "1073741824\n";

    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn standard_on_a_standard_container_matches() {
        let want = pm::effective(Mode::Standard, None, &none);
        let running = parse_running(STANDARD_PG, Some(STANDARD_SHM)).unwrap();
        let c = row(Mode::Standard, None, None, &want, Some(&running), Some((3, 120 * MIB)));
        assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
        assert!(!c.detail.contains("recreate needed"), "{}", c.detail);
        assert!(c.detail.starts_with("standard (cluster.postgres_memory unset): shared_buffers 512MB, effective_cache_size 2GB, work_mem 32MB, maintenance_work_mem 256MB, /dev/shm 1g"), "{}", c.detail);
        assert!(c.detail.contains("temp spill since the stats reset: 3 file(s), 120 MiB"), "{}", c.detail);
    }

    #[test]
    fn auto_on_a_standard_container_needs_a_recreate() {
        let want = pm::effective(Mode::Auto, Some(4 * GIB), &none);
        let running = parse_running(STANDARD_PG, Some(STANDARD_SHM)).unwrap();
        let c = row(Mode::Auto, Some("auto"), Some(4 * GIB), &want, Some(&running), None);
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(c.detail.starts_with("recreate needed: auto for 4.0 GiB asks for shared_buffers 128MB (runs 512MB)"), "{}", c.detail);
        assert!(c.detail.contains("/dev/shm 256m (runs 1GB)"), "{}", c.detail);
        assert_eq!(c.remedy.as_deref(), Some("noo stack restart --force postgres"));
    }

    #[test]
    fn auto_on_a_container_made_by_auto_matches() {
        let want = pm::effective(Mode::Auto, Some(7 * GIB), &none);
        let pg = "shared_buffers|32768|8kB\neffective_cache_size|131072|8kB\nwork_mem|16384|kB\nmaintenance_work_mem|131072|kB\n";
        let running = parse_running(pg, Some("536870912")).unwrap();
        let c = row(Mode::Auto, Some("auto"), Some(7 * GIB), &want, Some(&running), None);
        assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
        assert!(!c.detail.contains("recreate needed"), "{}", c.detail);
    }

    #[test]
    fn an_explicit_value_is_named_and_compared() {
        let explicit = |k: &str| (k == "NOO_PG_WORK_MEM").then(|| "64MB".to_string());
        let want = pm::effective(Mode::Auto, Some(20 * GIB), &explicit);
        let running = parse_running(STANDARD_PG, Some(STANDARD_SHM)).unwrap();
        let c = row(Mode::Auto, Some("auto"), Some(20 * GIB), &want, Some(&running), None);
        assert_eq!(c.verdict, Verdict::Warn, "{c:?}");
        assert!(c.detail.contains("work_mem 64MB (runs 32MB)"), "{}", c.detail);
        let pg64 = STANDARD_PG.replace("work_mem|32768|kB", "work_mem|65536|kB");
        let c = row(Mode::Auto, Some("auto"), Some(20 * GIB), &want, Some(&parse_running(&pg64, Some(STANDARD_SHM)).unwrap()), None);
        assert_eq!(c.verdict, Verdict::Ok, "{c:?}");
        assert!(c.detail.contains("work_mem 64MB (NOO_PG_WORK_MEM, set by you)"), "{}", c.detail);
    }

    #[test]
    fn an_unread_container_is_a_warning_not_a_recreate() {
        let want = pm::effective(Mode::Standard, None, &none);
        let c = row(Mode::Standard, None, None, &want, None, None);
        assert_eq!(c.verdict, Verdict::Warn);
        assert!(!c.detail.contains("recreate needed") && c.detail.contains("not read"), "{}", c.detail);
        assert_eq!(parse_running("", None), None);
        assert_eq!(parse_spill("7|1048576\n"), Some((7, MIB)));
        assert_eq!(parse_spill("\n"), None);
    }
}
