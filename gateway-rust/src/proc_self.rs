// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The process's own resident memory and CPU time, for `/metrics`.
//!
//! The 2026-11-11 efficiency survey (noomesh-internal i658) could not
//! measure the gateway at all: Prometheus scrapes it, but it exported no
//! `process_resident_memory_bytes` or `process_cpu_seconds_total`, and the
//! controller runs no container exporter. These are the standard names the
//! Prometheus client libraries use, so dashboards and alerts written for
//! any service read them unchanged.
//!
//! Read from `/proc/self` on Linux (the gateway runs in a Linux container).
//! Elsewhere, or when a file cannot be read or parsed, the lines are
//! omitted: an absent series is what alerting expects, and a made-up zero
//! would read as an idle process.

/// What `/proc/self` says about this process.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProcSelf {
    pub resident_bytes: u64,
    pub cpu_seconds: f64,
    /// Unix seconds; `None` when `/proc/stat`'s `btime` is unreadable.
    pub start_time_seconds: Option<f64>,
}

/// Resident pages from `/proc/self/statm` (its second field).
pub fn parse_statm_resident_pages(statm: &str) -> Option<u64> {
    statm.split_whitespace().nth(1)?.parse().ok()
}

/// `(utime + stime, starttime)` in clock ticks from `/proc/self/stat`. The
/// command name (field 2) is in parentheses and may itself contain spaces
/// or parentheses, so the fields are counted from after the LAST `)`.
pub fn parse_stat_ticks(stat: &str) -> Option<(u64, u64)> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // After the name: field 3 (state) is index 0, so field N is N - 3.
    let f: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = f.get(14 - 3)?.parse().ok()?;
    let stime: u64 = f.get(15 - 3)?.parse().ok()?;
    let start: u64 = f.get(22 - 3)?.parse().ok()?;
    Some((utime.saturating_add(stime), start))
}

/// The boot time (`btime`, Unix seconds) from `/proc/stat`.
pub fn parse_btime(proc_stat: &str) -> Option<u64> {
    proc_stat.lines().find_map(|l| l.strip_prefix("btime ")).and_then(|v| v.trim().parse().ok())
}

/// Combine the three files, given the page size and clock-tick rate.
pub fn from_files(statm: &str, stat: &str, proc_stat: Option<&str>, page_size: u64, ticks_per_sec: u64) -> Option<ProcSelf> {
    if page_size == 0 || ticks_per_sec == 0 {
        return None;
    }
    let pages = parse_statm_resident_pages(statm)?;
    let (cpu_ticks, start_ticks) = parse_stat_ticks(stat)?;
    let tps = ticks_per_sec as f64;
    Some(ProcSelf {
        resident_bytes: pages.saturating_mul(page_size),
        cpu_seconds: cpu_ticks as f64 / tps,
        start_time_seconds: proc_stat.and_then(parse_btime).map(|b| b as f64 + start_ticks as f64 / tps),
    })
}

/// Read this process's figures; `None` off Linux or when anything is unreadable.
pub fn read() -> Option<ProcSelf> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let proc_stat = std::fs::read_to_string("/proc/stat").ok();
    // SAFETY: sysconf reads a configuration value and has no side effects.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    // SAFETY: as above.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if page <= 0 || ticks <= 0 {
        return None;
    }
    from_files(&statm, &stat, proc_stat.as_deref(), page as u64, ticks as u64)
}

/// The `/metrics` lines; nothing when the figures are unknown.
pub fn metrics_text(p: Option<ProcSelf>) -> String {
    let Some(p) = p else { return String::new() };
    let mut out = format!(
        "# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes {}\n\
         # TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total {}\n",
        p.resident_bytes, p.cpu_seconds
    );
    if let Some(s) = p.start_time_seconds {
        out.push_str(&format!("# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds {s}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real /proc/self/stat shape, with a command name holding a space and
    // a parenthesis to prove the fields are counted from the last ')'.
    const STAT: &str = "4242 (noo gw (x)) S 1 4242 4242 0 -1 4194560 2981 0 0 0 150 50 0 0 20 0 9 0 12345 123456789 5000 18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 3 0 0 0 0 0";
    const STATM: &str = "30000 5000 1200 300 0 9000 0\n";
    const PROC_STAT: &str = "cpu  1 2 3 4\nintr 99\nbtime 1794400000\nprocesses 7\n";

    #[test]
    fn the_figures_come_from_the_right_fields() {
        assert_eq!(parse_statm_resident_pages(STATM), Some(5000));
        assert_eq!(parse_stat_ticks(STAT), Some((200, 12345)), "utime 150 + stime 50; starttime 12345");
        assert_eq!(parse_btime(PROC_STAT), Some(1_794_400_000));
        let p = from_files(STATM, STAT, Some(PROC_STAT), 4096, 100).expect("parsed");
        assert_eq!(p.resident_bytes, 5000 * 4096);
        assert!((p.cpu_seconds - 2.0).abs() < 1e-9, "{}", p.cpu_seconds);
        assert_eq!(p.start_time_seconds, Some(1_794_400_000.0 + 123.45));
    }

    #[test]
    fn the_standard_names_are_exported_and_unknown_is_absent_not_zero() {
        let text = metrics_text(from_files(STATM, STAT, Some(PROC_STAT), 4096, 100));
        assert!(text.contains("\nprocess_resident_memory_bytes 20480000\n"), "{text}");
        assert!(text.contains("# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 2\n"), "{text}");
        assert!(text.contains("process_start_time_seconds 1794400123.45"), "{text}");
        assert_eq!(metrics_text(None), "", "unknown is omitted, never 0");
        let no_btime = metrics_text(from_files(STATM, STAT, None, 4096, 100));
        assert!(no_btime.contains("process_resident_memory_bytes") && !no_btime.contains("process_start_time_seconds"), "{no_btime}");
    }

    #[test]
    fn a_malformed_file_is_unknown_not_a_guess() {
        assert_eq!(from_files("", STAT, None, 4096, 100), None);
        assert_eq!(from_files(STATM, "no parenthesis here", None, 4096, 100), None);
        assert_eq!(from_files(STATM, "1 (x) S 1", None, 4096, 100), None, "too few fields");
        assert_eq!(from_files(STATM, STAT, None, 0, 100), None);
    }

    /// On the Linux the gateway runs on, the live read works and is sane.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_live_read_is_sane_on_linux() {
        let p = read().expect("/proc/self is readable on linux");
        assert!(p.resident_bytes > 1 << 20, "a running test binary holds over 1 MiB: {}", p.resident_bytes);
        assert!(p.cpu_seconds >= 0.0);
    }
}
