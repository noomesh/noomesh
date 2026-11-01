// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The declared one-shot compose services (noomesh-internal i64a):
//! `config/oneshot-services.txt`. The ONE list `noo stack status` and the
//! roll summary read, so a finished one-shot and a dead container are told
//! apart the same way in both.

use std::sync::OnceLock;

const FILE: &str = "config/oneshot-services.txt";

/// Parse the list: the first word of each line, whole-line `#` comments and
/// blank lines ignored.
pub(crate) fn parse(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

/// The list as this install has it: the file under the install root (what
/// the launcher ships), else the copy embedded in this binary. Read once.
/// A list that cannot be read is EMPTY, so nothing is excused: every Exited
/// container then fails, which is loud, never a silent pass.
pub(crate) fn declared() -> &'static [String] {
    static LIST: OnceLock<Vec<String>> = OnceLock::new();
    LIST.get_or_init(|| {
        let path = crate::envfile::repo_root().join(FILE);
        let text = std::fs::read_to_string(&path).ok().or_else(|| {
            crate::onboard::standalone::STANDALONE_ASSETS
                .iter()
                .find(|(rel, _, _)| *rel == FILE)
                .and_then(|(_, bytes, _)| std::str::from_utf8(bytes).ok().map(str::to_string))
        });
        text.map(|t| parse(&t)).unwrap_or_default()
    })
}

/// Is `name` (a compose service, or a container `<prefix>-<service>`) on
/// `list`?
pub(crate) fn is_oneshot_in(name: &str, list: &[String]) -> bool {
    list.iter().any(|s| name == s || name.ends_with(&format!("-{s}")))
}

/// [`is_oneshot_in`] against this install's list.
pub(crate) fn is_oneshot(name: &str) -> bool {
    is_oneshot_in(name, declared())
}

/// The exit code in docker's `Status` (`Exited (1) 3 hours ago`), if any.
pub(crate) fn exit_code(status: &str) -> Option<i32> {
    let rest = status.trim().strip_prefix("Exited (")?;
    rest.split(')').next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_list_parses_and_names_evolve_routes() {
        let got = parse(include_str!("../../config/oneshot-services.txt"));
        assert!(got.iter().any(|s| s == "noo-evolve-routes"), "{got:?}");
        assert!(got.iter().any(|s| s == "deps-core"), "{got:?}");
        assert!(got.iter().all(|s| !s.starts_with('#')), "{got:?}");
    }

    #[test]
    fn a_service_or_its_container_name_matches() {
        let list = vec!["deps-core".to_string(), "noo-evolve-routes".to_string()];
        assert!(is_oneshot_in("deps-core", &list));
        assert!(is_oneshot_in("noo-deps-core", &list), "the container <prefix>-<service>");
        assert!(is_oneshot_in("acme-deps-core", &list), "any prefix");
        assert!(is_oneshot_in("noo-evolve-routes", &list));
        assert!(!is_oneshot_in("noo-gateway", &list));
        assert!(!is_oneshot_in("noo-deps-core-x", &list));
    }

    #[test]
    fn the_exit_code_is_read_from_dockers_status() {
        assert_eq!(exit_code("Exited (0) 2 hours ago"), Some(0));
        assert_eq!(exit_code("Exited (137) About a minute ago"), Some(137));
        assert_eq!(exit_code("Up 3 days (healthy)"), None);
        assert_eq!(exit_code("Exited"), None);
    }
}
