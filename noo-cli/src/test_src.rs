// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! What a source-reading test guard reads (followup 215).
//!
//! Some properties are an absence (no second place that mints, no call
//! before another), and a test can only show an absence by reading the
//! source. Read naively, such a guard passed while the bug was present in
//! five ways: it matched its own docstring, read past the function into the
//! test module and found itself, grepped one spelling, bounded its window by
//! a byte count, or cut the file at the FIRST `#[cfg(test)]`, so a test-only
//! item above the code under guard hid everything after it (2026-11-04).
//!
//! This module makes three of those impossible by construction:
//! - [`own_code`] blanks every comment (strings stay, since guards match
//!   string literals) and drops each `#[cfg(test)]` ITEM by brace matching.
//! - [`fn_body`] is bounded by the function's own matching brace, and panics
//!   "stale" when its marker is gone, so a guard that cannot find its subject
//!   fails instead of passing.
//!
//! Matching one spelling, and reading source where behaviour could be run,
//! remain the author's judgement.

/// What a byte of Rust source is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Code,
    Comment,
    /// A string, byte-string, raw-string or char literal, quotes included.
    Literal,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Classify every byte of `src`. Delimiters are ASCII, so UTF-8
/// continuation bytes never look like one.
fn classify(src: &str) -> Vec<Class> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = vec![Class::Code; n];
    let mut i = 0;
    let mark = |out: &mut Vec<Class>, from: usize, to: usize, c: Class| {
        for x in out.iter_mut().take(to.min(n)).skip(from) {
            *x = c;
        }
    };
    while i < n {
        match b[i] {
            b'/' if i + 1 < n && b[i + 1] == b'/' => {
                let end = src[i..].find('\n').map_or(n, |e| i + e);
                mark(&mut out, i, end, Class::Comment);
                i = end;
            }
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                let (mut j, mut depth) = (i + 2, 1usize);
                while j < n && depth > 0 {
                    if b[j] == b'/' && j + 1 < n && b[j + 1] == b'*' {
                        depth += 1;
                        j += 2;
                    } else if b[j] == b'*' && j + 1 < n && b[j + 1] == b'/' {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                mark(&mut out, i, j, Class::Comment);
                i = j;
            }
            b'"' => {
                let mut j = i + 1;
                while j < n && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                let end = (j + 1).min(n);
                mark(&mut out, i, end, Class::Literal);
                i = end;
            }
            b'r' if (i == 0 || !is_ident(b[i - 1])) || (i >= 1 && b[i - 1] == b'b' && (i < 2 || !is_ident(b[i - 2]))) => {
                // A raw string: r"…", r#"…"#, br"…".
                let mut j = i + 1;
                while j < n && b[j] == b'#' {
                    j += 1;
                }
                if j < n && b[j] == b'"' {
                    let hashes = j - i - 1;
                    let close: String = std::iter::once('"').chain(std::iter::repeat_n('#', hashes)).collect();
                    let end = src[j + 1..].find(&close).map_or(n, |e| j + 1 + e + close.len());
                    mark(&mut out, i, end, Class::Literal);
                    i = end;
                } else {
                    i += 1;
                }
            }
            b'\'' => {
                // A char literal ('x', '\n', '\u{7d}', '—'), or a lifetime.
                if i + 2 < n && b[i + 1] == b'\\' {
                    // Skip the escaped character itself, so '\'' closes right.
                    let end = src[i + 3..].find('\'').map_or(n, |e| i + 3 + e + 1);
                    mark(&mut out, i, end, Class::Literal);
                    i = end;
                } else if let Some(c) = src[i + 1..].chars().next() {
                    let after = i + 1 + c.len_utf8();
                    if after < n && b[after] == b'\'' {
                        mark(&mut out, i, after + 1, Class::Literal);
                        i = after + 1;
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// The byte index of the brace closing the one at `open`, counting only
/// braces that are code.
fn matching_brace(src: &str, class: &[Class], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, &c) in src.as_bytes().iter().enumerate().skip(open) {
        if class[i] != Class::Code {
            continue;
        }
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// `src` with every comment replaced by spaces (newlines kept), so a guard
/// matches code, never prose about the code. String literals are kept, and
/// byte positions do not move.
pub(crate) fn strip_comments(src: &str) -> String {
    let class = classify(src);
    let bytes: Vec<u8> = src.bytes().zip(class.iter())
        .map(|(b, c)| if *c == Class::Comment && b != b'\n' { b' ' } else { b })
        .collect();
    // A comment is whole characters (it ends at a newline or `*/`), so
    // blanking its bytes to ASCII spaces keeps the text valid UTF-8.
    String::from_utf8(bytes).expect("blanking whole comment bytes keeps UTF-8")
}

/// `src` as the code a guard should read: comments blanked, and every
/// `#[cfg(test)]` item (a module, fn, impl, use, const…) removed whole, up
/// to its own closing brace or `;`. Nothing after a test-only item is lost.
pub(crate) fn own_code(src: &str) -> String {
    let code = strip_comments(src);
    let class = classify(&code);
    let attr = "#[cfg(test)]";
    let mut out = String::with_capacity(code.len());
    let mut at = 0;
    let mut search = 0;
    while let Some(rel) = code[search..].find(attr) {
        let start = search + rel;
        if class[start] != Class::Code {
            search = start + attr.len();
            continue;
        }
        // The item ends at the first code `;` or at the brace matching the
        // first code `{`, whichever comes first after the attribute.
        let bytes = code.as_bytes();
        let mut end = None;
        // A `;` inside `(...)` or `[...]` (an array type `[u8; 2]`) does
        // not end the item.
        let mut nest = 0i32;
        for (i, &b) in bytes.iter().enumerate().skip(start + attr.len()) {
            if class[i] != Class::Code {
                continue;
            }
            match b {
                b'(' | b'[' => nest += 1,
                b')' | b']' => nest -= 1,
                _ => {}
            }
            if b == b';' && nest == 0 {
                end = Some(i + 1);
                break;
            }
            if b == b'{' {
                end = matching_brace(&code, &class, i).map(|c| c + 1);
                break;
            }
        }
        let end = end.unwrap_or(code.len());
        out.push_str(&code[at..start]);
        at = end;
        search = end;
    }
    out.push_str(&code[at..]);
    out
}

/// The function that `marker` (e.g. `"fn upgrade_stack("`) introduces in
/// `code`, from the marker through its own closing brace. Panics when the
/// marker or the body is missing: a guard whose subject is gone is stale and
/// must fail, never pass on an empty slice.
pub(crate) fn fn_body<'a>(code: &'a str, marker: &str) -> &'a str {
    let class = classify(code);
    let start = code.find(marker).unwrap_or_else(|| panic!("this guard is stale: `{marker}` is not in the code"));
    let open = (start..code.len())
        .find(|&i| class[i] == Class::Code && code.as_bytes()[i] == b'{')
        .unwrap_or_else(|| panic!("this guard is stale: `{marker}` has no body"));
    let close = matching_brace(code, &class, open).unwrap_or_else(|| panic!("this guard is stale: `{marker}` never closes"));
    &code[start..=close]
}

#[cfg(test)]
mod tests {
    use super::{fn_body, own_code, strip_comments};

    /// A fixture file: a doc comment naming the call, a test-only fn ABOVE
    /// the code under guard, a function followed by a test module, braces
    /// inside strings, raw strings, char literals and lifetimes.
    fn fixture() -> String {
        [
            "/// Explains why `danger()` must come after `setup()`.",
            "fn run<'a>(x: &'a str) -> usize \u{7b}",
            "    // danger(); was here once",
            "    setup();",
            "    let s = \"a \u{7d} in a string\";",
            "    let r = r#\"raw \u{7b} \"quoted\" \u{7d}\"#;",
            "    let c = '\u{7d}';",
            "    let d = '\\\\';",
            "    let q = '\\'';",
            "    danger();",
            "    s.len() + r.len() + x.len() + c.len_utf8() + d.len_utf8() + q.len_utf8()",
            "\u{7d}",
            "",
            "#[cfg(test)]",
            "fn only_in_tests() -> [u8; 2] \u{7b} setup(); [0; 2] \u{7d}",
            "",
            "fn later() \u{7b}",
            "    /* block \u{7b} comment */ finish();",
            "\u{7d}",
            "",
            "#[cfg(test)]",
            "mod tests \u{7b}",
            "    fn t() \u{7b} assert!(src.contains(\"later_marker\")); \u{7d}",
            "\u{7d}",
            "",
            "fn after_tests() \u{7b} tail(); \u{7d}",
        ]
        .join("\n")
    }

    /// Failure mode 1: a guard matched the docstring explaining the bug.
    #[test]
    fn comments_are_blanked_so_prose_never_matches() {
        let code = own_code(&fixture());
        let run = fn_body(&code, "fn run<");
        assert_eq!(run.matches("danger()").count(), 1, "only the call, not the doc or the comment: {run}");
        assert!(!code.contains("Explains why"));
        assert!(!code.contains("block"), "block comments too");
        assert!(code.contains("\"a \u{7d} in a string\""), "string literals stay");
        assert_eq!(strip_comments("a // b\nc").len(), "a // b\nc".len(), "blanking keeps byte positions");
    }

    /// Failure mode: the cut at the FIRST `#[cfg(test)]` hid everything
    /// after a test-only item (upgrade.rs, 2026-11-04). Only the item goes.
    #[test]
    fn a_test_only_item_is_removed_alone() {
        let code = own_code(&fixture());
        assert!(!code.contains("only_in_tests"), "the test-only fn is gone");
        assert!(code.contains("fn later("), "code after a test-only fn is kept");
        assert!(code.contains("fn after_tests("), "code after a test module is kept");
        assert!(!code.contains("later_marker"), "the test module is gone");
    }

    /// Failure mode 2: a slice ran past its function into the test module
    /// and matched the test's own text. The body ends at its own brace,
    /// whatever braces strings, raw strings and chars hold.
    #[test]
    fn a_body_ends_at_its_own_brace() {
        let code = own_code(&fixture());
        let run = fn_body(&code, "fn run<");
        assert!(run.ends_with('\u{7d}') && run.contains("danger();"), "{run}");
        assert!(!run.contains("fn later("), "{run}");
        let later = fn_body(&code, "fn later(");
        assert!(later.contains("finish();") && !later.contains("tail()"), "{later}");
    }

    /// A guard whose subject is gone fails; it never passes on nothing.
    #[test]
    #[should_panic(expected = "this guard is stale")]
    fn a_missing_marker_is_stale() {
        let code = own_code(&fixture());
        let _ = fn_body(&code, "fn renamed_away(");
    }

    /// Non-ASCII in comments and code survives blanking.
    #[test]
    fn multibyte_text_survives() {
        let src = "fn f() \u{7b} let _ = \"—\"; \u{7d} // a — dash";
        let code = own_code(src);
        assert!(code.contains("\"—\""));
        assert!(!code.contains("dash"));
    }
}
