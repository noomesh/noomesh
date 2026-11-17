// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The wire forms of a UTC instant, byte for byte as chrono wrote them
//! (i923: the move off chrono and chrono-tz, wave 1).
//!
//! The gateway prints a time two ways, and both must survive the swap
//! unchanged, because API callers, stored rows and one MAC'd file carry them:
//! - [`rfc3339_offset`]: what `DateTime<Utc>::to_rfc3339()` printed, the
//!   offset spelled `+00:00` (125 call sites, and the time inside the audit
//!   log's signed heads, `audit_head_export::SignedHead`);
//! - [`rfc3339_z`]: what chrono's serde printed for a `DateTime<Utc>` field,
//!   the offset spelled `Z`.
//!
//! Both write the sub-second part the way chrono's `SecondsFormat::AutoSi`
//! does: nothing for a whole second, else 3, 6 or 9 digits, the fewest of
//! those that hold it exactly. Postgres keeps microseconds, so a value read
//! back ending in `.120000` prints `.120`, never jiff's own shortest `.12`.
//! [`parse_rfc3339`] reads what chrono's `parse_from_rfc3339` read.
//!
//! The tests run chrono and these functions on the same instants and inputs,
//! so any difference fails here before a call site moves.

use jiff::Timestamp;

/// `DateTime<Utc>::to_rfc3339()`, byte for byte: `+00:00`, AutoSi digits.
pub fn rfc3339_offset(ts: Timestamp) -> String {
    format_utc(ts, "+00:00")
}

/// chrono's serde form of a `DateTime<Utc>`, byte for byte: `Z`, AutoSi.
pub fn rfc3339_z(ts: Timestamp) -> String {
    format_utc(ts, "Z")
}

/// An RFC 3339 time with any offset, as `DateTime::parse_from_rfc3339` read it.
pub fn parse_rfc3339(s: &str) -> Result<Timestamp, jiff::Error> {
    s.parse::<Timestamp>()
}

fn format_utc(ts: Timestamp, offset: &str) -> String {
    let dt = jiff::tz::Offset::UTC.to_datetime(ts);
    let nanos = dt.subsec_nanosecond();
    let frac = if nanos == 0 {
        String::new()
    } else if nanos % 1_000_000 == 0 {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos % 1_000 == 0 {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{frac}{offset}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, SecondsFormat, Utc};

    fn jiff_of(c: DateTime<Utc>) -> Timestamp {
        Timestamp::from_nanosecond(i128::from(c.timestamp_nanos_opt().expect("in range"))).expect("in range")
    }

    /// Instants on every path: whole seconds; 3, 6 and 9 digits; Postgres
    /// micros with trailing zeros; the epoch and before it; a leap day; the
    /// last instant chrono's four-digit year prints.
    fn instants() -> Vec<DateTime<Utc>> {
        let at = |secs: i64, nanos: u32| DateTime::from_timestamp(secs, nanos).expect("in range");
        vec![
            at(1_763_400_000, 0),
            at(1_763_400_000, 120_000_000),
            at(1_763_400_000, 123_000_000),
            at(1_763_400_000, 120_000),
            at(1_763_400_000, 123_456_000),
            at(1_763_400_000, 1_000),
            at(1_763_400_000, 1),
            at(1_763_400_000, 123_456_789),
            at(1_763_400_000, 999_999_999),
            at(0, 0),
            at(0, 500_000_000),
            at(-1, 0),
            at(-1, 999_000_000),
            at(951_782_400, 0),
            at(253_402_300_799, 999_999_999),
            at(1_709_208_000, 7_000),
        ]
    }

    #[test]
    fn the_offset_form_is_chronos_to_rfc3339_byte_for_byte() {
        for c in instants() {
            assert_eq!(rfc3339_offset(jiff_of(c)), c.to_rfc3339(), "{c:?}");
            assert_eq!(c.to_rfc3339(), c.to_rfc3339_opts(SecondsFormat::AutoSi, false), "the form this pins");
        }
    }

    #[test]
    fn the_z_form_is_chronos_serde_byte_for_byte() {
        for c in instants() {
            let serde = serde_json::to_value(c).expect("serialises");
            assert_eq!(serde_json::Value::String(rfc3339_z(jiff_of(c))), serde, "{c:?}");
        }
    }

    /// Postgres `timestamptz` holds microseconds: the read-back value prints
    /// 3 or 6 digits, never jiff's shortest form.
    #[test]
    fn postgres_micros_print_three_or_six_digits() {
        let micros = |us: i64| Timestamp::from_microsecond(us).expect("in range");
        assert_eq!(rfc3339_offset(micros(1_763_400_000_120_000)), "2025-11-17T17:20:00.120+00:00");
        assert_eq!(rfc3339_z(micros(1_763_400_000_123_456)), "2025-11-17T17:20:00.123456Z");
        assert_eq!(rfc3339_z(micros(1_763_400_000_000_000)), "2025-11-17T17:20:00Z");
    }

    /// Whatever chrono accepted, read to the same instant; whatever it
    /// refused, refused. A difference is listed, not hidden.
    #[test]
    fn the_parser_reads_what_chrono_read() {
        let inputs = [
            "2025-11-17T17:20:00Z",
            "2025-11-17T17:20:00+00:00",
            "2025-11-17T17:20:00.120+00:00",
            "2025-11-17T17:20:00.123456Z",
            "2025-11-17T17:20:00.123456789Z",
            "2025-11-17T12:20:00-05:00",
            "2025-11-17T22:50:00+05:30",
            "2025-11-17t17:20:00z",
            "2025-11-17 17:20:00Z",
            "1969-12-31T23:59:59.999Z",
            "2024-02-29T00:00:00Z",
            "2025-11-17T17:20:00",
            "2025-11-17",
            "not a time",
            "",
        ];
        let mut differ = Vec::new();
        for s in inputs {
            let c = DateTime::parse_from_rfc3339(s).ok().map(|d| i128::from(d.timestamp_nanos_opt().expect("in range")));
            let j = parse_rfc3339(s).ok().map(|t| t.as_nanosecond());
            if c != j {
                differ.push(format!("{s:?}: chrono {c:?}, jiff {j:?}"));
            }
        }
        assert!(differ.is_empty(), "the parsers differ:\n{}", differ.join("\n"));
    }

    /// The one time inside MAC'd bytes (i923): the audit log's signed head.
    /// The swap must hand `SignedHead::sign` the same string, so the same MAC.
    #[test]
    fn a_signed_audit_head_carries_the_same_bytes() {
        let key = [7u8; 32];
        for c in instants() {
            let before = crate::audit_head_export::SignedHead::sign(&key, 42, "h", &c.to_rfc3339());
            let after = crate::audit_head_export::SignedHead::sign(&key, 42, "h", &rfc3339_offset(jiff_of(c)));
            assert_eq!(after.mac, before.mac, "{c:?}");
            assert!(after.verifies(&key));
        }
    }
}
