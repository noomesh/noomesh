//! Bounded retry for a pull from the Ollama registry, and the ONE
//! classifier that says whether a failed pull is worth another try.
//!
//! The public registry has blips (a 503 from its edge, a connect timeout).
//! A stranger's first model must not fail on one. A 404, an auth refusal or
//! an unknown manifest never gets better by waiting, so those fail at once
//! with the reason. Used by the onboard First Model step and `noo models
//! pull`.

use std::time::Duration;

/// Tries in all: the first plus two retries.
pub const TRIES: usize = 3;
/// Seconds to wait before try 2 and before try 3.
pub const DELAYS_SECS: [u64; 2] = [10, 30];
/// The total wait across all retries never exceeds this.
pub const MAX_TOTAL_WAIT_SECS: u64 = 45;

/// Why a failed pull is worth retrying, or `None` when it is not. Pure: it
/// reads only the pull's output text. Only the last `Error…` line counts
/// (`ollama pull` prints its failure that way), so a layer hash in the
/// progress lines can never pass for a status code.
pub fn classify_pull_failure(output: &str) -> Option<String> {
    let line = output
        .lines()
        .rev()
        .map(|l| l.trim().to_ascii_lowercase())
        .find(|l| l.starts_with("error"))?;
    // Permanent: waiting changes nothing.
    const PERMANENT: [&str; 7] = [
        "not found",
        "manifest unknown",
        "file does not exist",
        "unauthorized",
        "pull access denied",
        "denied",
        "forbidden",
    ];
    if PERMANENT.iter().any(|p| line.contains(p)) {
        return None;
    }
    let status = line
        .split_whitespace()
        .map(|t| t.trim_end_matches(':'))
        .find(|t| t.len() == 3 && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse::<u16>().ok());
    match status {
        Some(401 | 403 | 404) => return None,
        Some(s @ 500..=599) => return Some(format!("registry answered {s} (a registry-side problem)")),
        _ => {}
    }
    const NETWORK: [&str; 10] = [
        "connection refused",
        "connection reset",
        "connection timeout",
        "i/o timeout",
        "timed out",
        "timeout",
        "deadline exceeded",
        "tls handshake",
        "unexpected eof",
        "dial tcp",
    ];
    if NETWORK.iter().any(|p| line.contains(p)) {
        return Some("the registry could not be reached (a network problem)".to_string());
    }
    None
}

/// The last `Error…` line of a failed pull's output, for the reason shown
/// when it is not retried.
pub fn last_error_line(output: &str) -> Option<String> {
    output
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| l.to_ascii_lowercase().starts_with("error"))
        .map(str::to_string)
}

/// Seconds to wait before try `tried + 1`, or `None` when the tries or the
/// total-wait cap are spent. `tried` counts the tries made so far.
pub fn next_delay(tried: usize, waited_secs: u64) -> Option<u64> {
    if tried >= TRIES {
        return None;
    }
    let d = *DELAYS_SECS.get(tried - 1)?;
    if waited_secs + d > MAX_TOTAL_WAIT_SECS {
        return None;
    }
    Some(d)
}

/// The line printed before each wait.
pub fn retry_line(reason: &str, delay_secs: u64, next_try: usize) -> String {
    format!("{reason}: retrying in {delay_secs} s (try {next_try} of {TRIES})")
}

/// Run `attempt` (one pull, `(exit code, captured output)`) up to [`TRIES`]
/// times, retrying only what [`classify_pull_failure`] allows. Each retry is
/// announced through `say` before `sleep`. Returns the last attempt's result.
pub fn pull_with_retry(
    mut attempt: impl FnMut() -> (i32, String),
    mut say: impl FnMut(&str),
    mut sleep: impl FnMut(Duration),
) -> (i32, String) {
    let mut waited = 0u64;
    let mut tried = 0usize;
    loop {
        let (code, out) = attempt();
        tried += 1;
        if code == 0 {
            return (code, out);
        }
        let Some(reason) = classify_pull_failure(&out) else {
            return (code, out);
        };
        let Some(delay) = next_delay(tried, waited) else {
            return (code, out);
        };
        say(&retry_line(&reason, delay, tried + 1));
        sleep(Duration::from_secs(delay));
        waited += delay;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retry(out: &str) -> bool {
        classify_pull_failure(out).is_some()
    }

    #[test]
    fn registry_5xx_is_retried() {
        let manifest = "pulling manifest\nError: pull model manifest: 503: upstream connect error or disconnect/reset before headers. reset reason: connection timeout";
        assert!(classify_pull_failure(manifest).unwrap().contains("503"));
        assert!(retry("Error: 503: "));
        assert!(retry("Error: pull model manifest: 500: internal"));
        assert!(retry("Error: pull model manifest: 502: bad gateway"));
    }

    #[test]
    fn connect_and_timeout_errors_are_retried() {
        for e in [
            "Error: pull model manifest: Get \"https://registry.example/v2/x\": dial tcp 192.0.2.1:443: connect: connection refused",
            "Error: max retries exceeded: read tcp 100.64.0.2:5000->192.0.2.1:443: i/o timeout",
            "Error: context deadline exceeded",
            "Error: net/http: TLS handshake timeout",
            "Error: read: connection reset by peer",
        ] {
            assert!(retry(e), "{e}");
        }
    }

    #[test]
    fn permanent_failures_are_not_retried() {
        for e in [
            "Error: pull model manifest: file does not exist",
            "Error: pull model manifest: 404: not found",
            "Error: pull model manifest: 401: unauthorized",
            "Error: pull model manifest: 403: forbidden",
            "Error: 404: ",
            "Error: pull model manifest: 401: ",
            "Error: 403: ",
            "Error: pull access denied for x",
            "Error: pull model manifest: manifest unknown",
        ] {
            assert!(!retry(e), "{e}");
        }
    }

    #[test]
    fn permanent_wins_over_a_transient_word() {
        assert!(!retry("Error: pull model manifest: 404: not found (after a connection timeout)"));
    }

    #[test]
    fn unknown_errors_and_progress_are_not_retried() {
        assert!(!retry("Error: something nobody has seen"));
        assert!(!retry("Error response from daemon: container is not running"));
        assert!(!retry(""));
        // A layer hash ending in digits is progress, not a status code.
        assert!(!retry("pulling 970aa74c0c503: 12%\nverifying sha256 digest"));
    }

    #[test]
    fn delays_are_bounded() {
        assert_eq!(next_delay(1, 0), Some(10));
        assert_eq!(next_delay(2, 10), Some(30));
        assert_eq!(next_delay(3, 40), None);
        assert_eq!(next_delay(2, 20), None, "total wait is capped");
    }

    #[test]
    fn a_blip_is_retried_then_succeeds_with_each_retry_said() {
        let mut calls = 0;
        let mut said = Vec::new();
        let mut slept = Vec::new();
        let (code, _) = pull_with_retry(
            || {
                calls += 1;
                if calls < 3 { (1, "Error: 503: ".to_string()) } else { (0, String::new()) }
            },
            |l| said.push(l.to_string()),
            |d| slept.push(d.as_secs()),
        );
        assert_eq!(code, 0);
        assert_eq!(calls, 3);
        assert_eq!(slept, vec![10, 30]);
        assert_eq!(said.len(), 2);
        assert!(said[0].contains("503") && said[0].contains("retrying in 10 s (try 2 of 3)"), "{said:?}");
        assert!(said[1].contains("(try 3 of 3)"), "{said:?}");
    }

    #[test]
    fn a_404_fails_at_once() {
        let mut calls = 0;
        let (code, out) = pull_with_retry(
            || {
                calls += 1;
                (1, "Error: pull model manifest: file does not exist".to_string())
            },
            |_| panic!("nothing to say"),
            |_| panic!("no waiting"),
        );
        assert_eq!((code, calls), (1, 1));
        assert!(last_error_line(&out).unwrap().contains("file does not exist"));
    }

    #[test]
    fn a_registry_that_stays_down_is_tried_three_times_only() {
        let mut calls = 0;
        let (code, _) = pull_with_retry(
            || {
                calls += 1;
                (1, "Error: 503: ".to_string())
            },
            |_| {},
            |_| {},
        );
        assert_eq!((code, calls), (1, 3));
    }
}
