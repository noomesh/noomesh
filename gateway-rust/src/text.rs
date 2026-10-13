// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Cutting untrusted text without panicking.
//!
//! `&s[..n]` panics when byte `n` falls inside a multi-byte character, and
//! the places that cut text are exactly the places that hold text the
//! gateway did not write: tool output from a worker, a path a caller
//! typed, an error body from a backend. A panic there aborts the turn or
//! the task mid-run with no audit row and no "did NOT run" notice. Every
//! such cut goes through [`clip`].

/// At most `max_bytes` of `s`, ending on a character boundary. Never
/// panics; never allocates.
pub fn clip(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// [`clip`] as an owned string with an ellipsis when something was cut.
pub fn clip_with_ellipsis(s: &str, max_bytes: usize) -> String {
    let cut = clip(s, max_bytes);
    if cut.len() == s.len() {
        s.to_string()
    } else {
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PINNED: a cut inside a multi-byte character moves
    /// back to the boundary instead of panicking.
    #[test]
    fn clip_never_splits_a_character() {
        let s = "ab€cd"; // € is 3 bytes at [2..5]
        assert_eq!(clip(s, 2), "ab");
        assert_eq!(clip(s, 3), "ab");
        assert_eq!(clip(s, 4), "ab");
        assert_eq!(clip(s, 5), "ab€");
        assert_eq!(clip(s, 99), s);
        assert_eq!(clip("", 5), "");
        assert_eq!(clip("€", 1), "");
        assert_eq!(clip_with_ellipsis("héllo wörld", 3), "hé…");
        assert_eq!(clip_with_ellipsis("short", 50), "short");
        // The exact shape that panicked: 4000 bytes ending mid-character.
        let long = "é".repeat(3000);
        let _ = clip(&long, 4000);
    }
}
