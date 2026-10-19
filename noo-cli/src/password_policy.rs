// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The password policy for NEW and CHANGED passwords: one rule, used by the
//! gateway (`routes/users.rs`: create, set-password), the `noo` CLI
//! (`noo security user create|set-password`) and the onboarding wizard.
//!
//! This file exists byte-for-byte in `gateway-rust/src/password_policy.rs` and
//! `noo-cli/src/password_policy.rs` (the two crates build in separate
//! contexts and share no crate); `tests/test_password_policy_parity.py` fails
//! if the copies drift. Edit both together.
//!
//! Only passwords being SET are checked. An account created under the old
//! 8-character rule keeps logging in: login never consults this.

/// Why a password is refused, or None. The login faces whatever interface the
/// cluster plane binds to — on a LAN or VPS install that is the network —
/// behind a 10/min/user + 20/min/IP limit, ~14k guesses a day. An 8-character
/// floor with no blocklist loses that race to a dictionary; 12 characters and
/// the top of the list do not.
pub fn weak_password(pw: &str, username: &str) -> Option<&'static str> {
    const FLOOR: usize = 12;
    // The shapes a dictionary tries first: the most-used passwords, plus the
    // product's own words. Matched case-insensitively against the whole
    // password, so `Password123!` is refused as surely as `password123`.
    const COMMON: &[&str] = &[
        "password", "password1", "password12", "password123", "password1234", "password123!",
        "123456789012", "1234567890123", "qwertyuiop12", "qwerty123456", "letmein12345",
        "iloveyou1234", "welcome12345", "welcome123!", "admin1234567", "administrator",
        "changeme1234", "changemenow!", "trustno1trustno1", "sunshine1234", "princess1234",
        "football1234", "baseball1234", "dragon123456", "monkey123456", "master123456",
        "abc123456789", "abcd12345678", "111111111111", "000000000000", "123123123123",
        "noomesh12345", "noomeshadmin", "noo-controller", "controller12",
    ];
    if pw.chars().count() < FLOOR {
        return Some("Password must be at least 12 characters (this login faces the network).");
    }
    let lower = pw.to_lowercase();
    if COMMON.contains(&lower.as_str()) {
        return Some("That password is on every attacker's first list — choose another.");
    }
    if !username.is_empty() && lower.contains(&username.to_lowercase()) {
        return Some("Password must not contain the username.");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::weak_password;

    #[test]
    fn a_long_unusual_password_passes() {
        assert_eq!(weak_password("correct-horse-battery", "admin"), None);
    }

    #[test]
    fn eight_to_eleven_characters_are_refused() {
        assert!(weak_password("elevenchars", "admin").unwrap().contains("12 characters"));
        assert!(weak_password("12345678", "admin").is_some());
    }

    #[test]
    fn the_common_list_is_matched_case_insensitively() {
        assert!(weak_password("Password123!", "admin").is_some());
        assert!(weak_password("Administrator", "someone").is_some());
    }

    #[test]
    fn a_password_containing_the_username_is_refused() {
        assert!(weak_password("alice-is-the-admin", "alice").unwrap().contains("username"));
        assert_eq!(weak_password("alice-is-the-admin", ""), None);
    }
}
