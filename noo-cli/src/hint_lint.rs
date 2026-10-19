// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Hint-honesty lint. `noo-cli` tells an operator what to run next in three
//! shapes: `ui::guide(&[(cmd, why), ...])` tuples, `` `noo …` ``/`` `pai …` ``
//! backtick mentions inside any message string, and `Some("noo …")` /
//! `Some(&format!("noo …", ..))` remedies handed to `ui::failed`,
//! `ui::close_failed` or `output::fail`. Nothing checked that a suggested
//! command is one the CLI actually accepts — an operator hit `noo heartbeat
//! run` suggesting `noo heartbeat history weekly_research`, and `history`
//! rejects a positional. This module walks the crate's own source text at
//! test time, extracts every such suggestion, and checks it against
//! [`usage::USAGE`] — the same table `usage_table_matches_registry_exactly`
//! (main.rs) pins 1:1 to the dispatch registry, so it is the parser's own
//! truth about what each command accepts.
//!
//! Declared `#[cfg(test)] mod hint_lint;` in `main.rs`: this whole module
//! (and therefore this whole file) compiles for `cargo test` only.
//!
//! ## Extraction heuristic
//! - Comment-only lines (`//`, `///`, `//!`) are blanked before scanning —
//!   an inline trailing comment on a code line is NOT stripped, so a stray
//!   quote or backtick in one could, in principle, corrupt the rest of that
//!   file's scan; none do today (checked by hand against every `cfg(test)`
//!   boundary — see below).
//! - Every `#[cfg(test)]` module in this crate is, without exception, the
//!   LAST top-level item in its file (verified across all ~65 files that
//!   declare one, 2026-09-29). So rather than brace-matching a `mod … { … }`
//!   body, this lint truncates each file's source at the first line that is
//!   *exactly* `#[cfg(test)]` (after trimming) and scans nothing past it.
//!   That line shape is deliberately narrow: it does NOT match a
//!   `#[cfg(test)]` that appears mid-line as a string literal (several
//!   files' own tests search their post-truncation source for that literal
//!   to prove the truncation point — see `commands/kiosk.rs`,
//!   `commands/provision.rs`, `commands/cluster_verify.rs` — those all sit
//!   AFTER the real boundary anyway, so this is belt-and-suspenders).
//! - This file (`hint_lint.rs`) is skipped entirely when walking `src/`: it
//!   is itself test-only (via the `#[cfg(test)]` on its `mod` declaration in
//!   main.rs, not visible from inside this file's own text), and its unit
//!   tests and `ALLOWED` list legitimately contain command-shaped strings
//!   that are fixtures, not suggestions to an operator.
//! - String literals are found with a small hand-rolled scanner (no `regex`
//!   dependency in this crate) that also recognizes Rust char literals
//!   (`'"'`, `'\''`, …) so an embedded quote character never fakes the start
//!   of a string.
//! - A literal (or a `format!(...)` call's format string) counts as a
//!   top-level hint (shape a/c) only when it starts with `noo ` or `pai `
//!   AND sits immediately after an opening `(` (a tuple element or a
//!   `Some(...)` argument — shape a) or after `hint(`/`::hint(` (the
//!   single-arg `ui::hint` helper — shape c, the only such helper in
//!   `ui.rs`). Backtick spans (shape b) are pulled out of EVERY string
//!   literal's content regardless of call context.
//!
//! ## Caveats (see the generated report for the running list)
//! - Multi-token format placeholders (`{args}`) are treated as ONE opaque
//!   value slot; if the real substitution can expand to several tokens, the
//!   arity check below it may be more lenient than reality.
//! - An inline trailing `//` comment on an otherwise-live code line is not
//!   stripped (see above).
//! - A hint's own string literal must be single-line; a `format!(` call
//!   whose format-string literal itself wraps mid-quote (not just before the
//!   opening quote) is not extracted. In practice every hint in this crate
//!   keeps its literal on one line.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::usage;

// ── extraction shapes ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// First element of a `ui::guide` tuple, or a `Some(...)` /
    /// `Some(&format!(...))` remedy/hint argument.
    TupleOrSome,
    /// `ui::hint("noo …")` / `ui::hint(&format!("noo …", ..))`.
    Helper,
    /// A `` `noo …` ``/`` `pai …` `` span inside any string literal.
    Backtick,
}

#[derive(Debug, Clone)]
struct Hint {
    file: String,
    line: usize,
    /// Raw extracted text, starting at `noo`/`pai`.
    text: String,
    shape: Shape,
}

// ── mismatch/warn kinds ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    UnknownCommand,
    UnknownFlag,
    MissingValue,
    TooManyPositionals,
    MissingRequired,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::UnknownCommand => "unknown-command",
            Kind::UnknownFlag => "unknown-flag",
            Kind::MissingValue => "missing-value",
            Kind::TooManyPositionals => "too-many-positionals",
            Kind::MissingRequired => "missing-required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Ok,
    /// A bare `noo`/`pai`, or a valid command GROUP prefix (e.g. `noo
    /// cluster`, `noo cluster --help`) — help, not a real invocation.
    GroupOk,
    /// The synopsis grammar for the resolved command could not be parsed by
    /// [`classify_synopsis`]; recorded separately, never a failure.
    Unparsed,
    /// A hard failure — asserted empty (minus `ALLOWED`).
    Mismatch(Kind),
    /// A soft `missing-required` — reported, never asserted.
    Warn(Kind),
}

#[derive(Debug, Clone)]
struct Finding {
    file: String,
    line: usize,
    kind: Kind,
    text: String,
    synopsis: String,
}

/// Hints that are deliberately not literal, checkable commands. Every entry
/// needs a reason; `every_suggested_command_parses` fails if an entry
/// matches nothing (a stale allow-list hides real drift).
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "commands/chat.rs",
        "noo chat --no-use-cluster",
        "offered only when passthrough::python_cli_path() finds a Python CLI; the flag is that CLI's, not the native parser's",
    ),
];

// ── global flags (see main.rs `resolve_with`) ────────────────────────────

/// Flags `resolve_with` consumes before command words are even looked at —
/// they may appear anywhere in a real invocation and are never part of a
/// command's own synopsis.
const GLOBAL_FLAGS: &[&str] = &[
    "--json", "--quiet", "-q", "--verbose", "-v", "--gateway", "-G", "--timeout", "--token",
    "--instance", "--color", "--help", "-h", "--version", "-V",
];
/// The subset of `GLOBAL_FLAGS` that consumes the following token as a
/// value (`--color=value` is handled separately as one token).
const GLOBAL_FLAGS_WITH_VALUE: &[&str] =
    &["--gateway", "-G", "--timeout", "--token", "--instance", "--color"];

// ── walking src/ ─────────────────────────────────────────────────────────

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("hint_lint: cannot read dir {}: {e}", dir.display()));
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("hint_lint: bad dir entry under {}: {e}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Blank whole-line comments (keeps line numbers stable) and drop everything
/// from the first bare `#[cfg(test)]` line onward. See the module doc for
/// why this is exact, not an approximation, for this crate.
fn sanitize(src: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for line in src.lines() {
        if line.trim() == "#[cfg(test)]" {
            break;
        }
        if line.trim_start().starts_with("//") {
            out.push("");
        } else {
            out.push(line);
        }
    }
    out.join("\n")
}

struct Lit {
    start: usize, // char index of the opening quote
    content: String,
    line: usize,
}

/// Find every `"..."` string literal in `text`, recognizing (and skipping
/// over) char literals like `'"'`/`'\''` so an embedded quote character
/// never fakes the start of a string. Operates on `char`s, not bytes, so
/// multi-byte glyphs (this crate's `▸`/`✓`/`…` prose) never desync offsets.
fn find_string_literals(text: &str) -> Vec<Lit> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    while i < n {
        let c = chars[i];
        if c == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c == '\'' {
            // Char literal shapes: 'x', '\x' (single escaped char). A
            // lifetime like 'a or 'static has no closing quote nearby and
            // falls through untouched.
            if i + 2 < n && chars[i + 1] == '\\' && chars[i + 3.min(n - 1)] == '\'' && i + 3 < n {
                i += 4;
                continue;
            }
            if i + 2 < n && chars[i + 2] == '\'' {
                i += 3;
                continue;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            let lit_line = line;
            let mut j = i + 1;
            let mut content = String::new();
            while j < n {
                let cj = chars[j];
                if cj == '\\' && j + 1 < n && chars[j + 1] == '\n' {
                    // Rust string continuation (`"foo \` + newline +
                    // indentation + `bar"` == `"foo bar"`): the backslash,
                    // the newline, and all leading whitespace on the next
                    // line disappear — nothing is inserted, so this must
                    // NOT become a stray token boundary later.
                    line += 1;
                    j += 2;
                    while j < n && (chars[j] == ' ' || chars[j] == '\t') {
                        j += 1;
                    }
                    continue;
                }
                if cj == '\\' && j + 1 < n {
                    content.push(cj);
                    content.push(chars[j + 1]);
                    j += 2;
                    continue;
                }
                if cj == '\n' {
                    line += 1;
                }
                if cj == '"' {
                    j += 1;
                    break;
                }
                content.push(cj);
                j += 1;
            }
            out.push(Lit { start: i, content, line: lit_line });
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

fn preceding_text(chars: &[char], start: usize, max: usize) -> String {
    let from = start.saturating_sub(max);
    chars[from..start].iter().collect()
}

/// Does `hay` end with the literal `word`, with a non-identifier character
/// (or nothing) before it? Used so `"hint("`/`"Some("` only match the real
/// call/constructor, never a stray suffix like `"warn_hint("`.
fn ends_with_word(hay: &str, word: &str) -> bool {
    if !hay.ends_with(word) {
        return false;
    }
    let idx = hay.len() - word.len();
    match hay[..idx].chars().next_back() {
        None => true,
        Some(c) => !(c.is_alphanumeric() || c == '_'),
    }
}

/// Classify the call context immediately before a literal that starts with
/// `noo `/`pai `. `None` means "not a hint-shaped call site" (the literal is
/// still scanned for backtick mentions elsewhere). Anything preceded by a
/// plain identifier or a macro bang (`println!(`, `ui::warned(`,
/// `ui::muted(`, `ui::done(`, ...) is a regular call argument, not a
/// guide/next-step tuple or a `Some(...)` remedy, and is rejected here even
/// though its own literal starts with `noo `/`pai `.
fn context_shape(chars: &[char], lit_start: usize) -> Option<Shape> {
    let pre = preceding_text(chars, lit_start, 80);
    let mut p = pre.trim_end().to_string();
    if p.ends_with("format!(") {
        let cut = p.len() - "format!(".len();
        p = p[..cut].trim_end().to_string();
    }
    if let Some(stripped) = p.strip_suffix('&') {
        p = stripped.trim_end().to_string();
    }
    if ends_with_word(&p, "hint(") {
        return Some(Shape::Helper);
    }
    if ends_with_word(&p, "Some(") {
        return Some(Shape::TupleOrSome);
    }
    if !p.ends_with('(') {
        return None;
    }
    let before = &p[..p.len() - 1];
    match before.trim_end().chars().next_back() {
        None => Some(Shape::TupleOrSome), // "(" at the very start of an expr/array
        Some(c) if c.is_alphanumeric() || c == '_' || c == ':' || c == '!' => None,
        Some(_) => Some(Shape::TupleOrSome), // preceded by `[`, `,`, `(`, …: a tuple element
    }
}

fn starts_with_cmd(s: &str) -> bool {
    let s = s.trim_start();
    s.starts_with("noo ") || s.starts_with("pai ") || s == "noo" || s == "pai"
}

fn backtick_commands(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = content;
    while let Some(i) = rest.find('`') {
        let after = &rest[i + 1..];
        let Some(j) = after.find('`') else { break };
        let inner = after[..j].trim();
        if starts_with_cmd(inner) {
            out.push(inner.to_string());
        }
        rest = &after[j + 1..];
    }
    out
}

fn extract_file(path: &Path, root: &Path) -> Vec<Hint> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("hint_lint: cannot read {}: {e}", path.display()));
    let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().to_string();
    let text = sanitize(&raw);
    let chars: Vec<char> = text.chars().collect();
    let mut hints = Vec::new();
    for lit in find_string_literals(&text) {
        for bt in backtick_commands(&lit.content) {
            hints.push(Hint { file: rel.clone(), line: lit.line, text: bt, shape: Shape::Backtick });
        }
        let trimmed = lit.content.trim_start();
        if starts_with_cmd(trimmed) {
            if let Some(shape) = context_shape(&chars, lit.start) {
                hints.push(Hint { file: rel.clone(), line: lit.line, text: trimmed.to_string(), shape });
            }
        }
    }
    hints
}

fn all_hints() -> Vec<Hint> {
    let root = src_root();
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    let mut hints = Vec::new();
    for f in &files {
        // This lint's own file is test-only (declared `#[cfg(test)] mod
        // hint_lint;` in main.rs) and its ALLOWED list / unit-test fixtures
        // legitimately contain bad or non-literal commands.
        if f.file_name().and_then(|n| n.to_str()) == Some("hint_lint.rs") {
            continue;
        }
        hints.extend(extract_file(f, &root));
    }
    hints
}

// ── the gateway's operator-facing commands ──────────────

/// The gateway tells an operator what to run too: every operator alert
/// carries one `investigate` command (`gateway-rust/src/egress.rs` renders
/// it as `Next: …`), and alert summaries, enrollment notices and error
/// bodies name commands in backticks. Those reach a phone, not this
/// crate's source, so the lint above never saw them — and one shipped with
/// a flag (`noo logs search --source`) the parser's usage table does not
/// list. This walks `gateway-rust/src` (a sibling in the monorepo) with the
/// same checker.
/// Gateway hints known not to parse, each with the reason it is not fixed
/// here and where it is tracked. `every_gateway_suggested_command_parses`
/// fails when an entry matches nothing, like [`ALLOWED`].
const GATEWAY_ALLOWED: &[(&str, &str, &str)] = &[(
    "gateway-rust/src/autonomy_evaluators.rs",
    "noo test run",
    "a dev-checkout hint on the test-suite alert; the verb is hidden from help (dev-only) but dispatches",
)];

fn gateway_src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("gateway-rust").join("src")
}

/// Blank comment-only lines and every top-level `#[cfg(test)]` item, which
/// in the gateway is NOT always the last one in its file. A test module
/// ends at the first line that is exactly `}` at column 0 — the gateway's
/// top-level items all close that way. Line numbers are kept.
fn sanitize_gateway(src: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut in_test = false;
    for line in src.lines() {
        if in_test {
            out.push("");
            if line == "}" {
                in_test = false;
            }
            continue;
        }
        if line.trim() == "#[cfg(test)]" && !line.starts_with(char::is_whitespace) {
            in_test = true;
            out.push("");
            continue;
        }
        out.push(if line.trim_start().starts_with("//") { "" } else { line });
    }
    out.join("\n")
}

/// Hints in one gateway file: the argument of every `.investigate(…)`
/// (a literal or a `format!` string) and every backtick `noo …` span.
fn extract_gateway_file(path: &Path, root: &Path) -> Vec<Hint> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("hint_lint: cannot read {}: {e}", path.display()));
    let rel = format!("gateway-rust/src/{}", path.strip_prefix(root).unwrap_or(path).to_string_lossy());
    let text = sanitize_gateway(&raw);
    let chars: Vec<char> = text.chars().collect();
    let mut hints = Vec::new();
    for lit in find_string_literals(&text) {
        for bt in backtick_commands(&lit.content) {
            hints.push(Hint { file: rel.clone(), line: lit.line, text: bt, shape: Shape::Backtick });
        }
        let pre = preceding_text(&chars, lit.start, 80);
        let mut p = pre.trim_end().to_string();
        if let Some(stripped) = p.strip_suffix("format!(") {
            p = stripped.trim_end().to_string();
        }
        if ends_with_word(&p, "investigate(") || p.ends_with(".investigate(") {
            hints.push(Hint { file: rel.clone(), line: lit.line, text: lit.content.trim().to_string(), shape: Shape::Helper });
        }
    }
    hints
}

fn gateway_hints() -> Vec<Hint> {
    let root = gateway_src_root();
    let mut files = Vec::new();
    collect_rs_files(&root, &mut files);
    let mut hints = Vec::new();
    for f in &files {
        hints.extend(extract_gateway_file(f, &root));
    }
    hints
}

/// Every command in `hints` that the usage table refuses, formatted —
/// minus those `allowed` names, whose hits are recorded in `hit`.
fn mismatches(hints: &[Hint], allowed: &[(&str, &str, &str)], hit: &mut [bool]) -> Vec<String> {
    let mut bad = Vec::new();
    for h in hints {
        for cmd in normalize_hint(&h.text) {
            if let (Verdict::Mismatch(k), syntax) = check_one(&cmd) {
                if let Some(i) = allowed.iter().position(|(f, sub, _)| *f == h.file && h.text.contains(sub)) {
                    hit[i] = true;
                    continue;
                }
                bad.push(format!("{}:{}  {}  \"{}\"  — synopsis: {}", h.file, h.line, k.label(), h.text, syntax.unwrap_or("")));
            }
        }
    }
    bad.sort();
    bad.dedup();
    bad
}

// ── normalizing a raw hint into one or more command token lists ─────────

/// Split `text` on whitespace, first collapsing every `{...}`/`<...>`/`[...]`
/// span (first matching close, no nesting) into one token even if it holds
/// internal spaces — `{args}`/`<node|harness>` must never be split, and a
/// hint that shows an optional flag documentation-style inline
/// (`noo workflow run <name> [-i key=value]`) must not have its bracketed
/// part treated as extra bare tokens either.
fn tokenize_collapsing_placeholders(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut i = 0usize;
    while i < n {
        let c = chars[i];
        if c == '{' || c == '<' || c == '[' {
            let close = match c {
                '{' => '}',
                '[' => ']',
                _ => '>',
            };
            let mut j = i + 1;
            while j < n && chars[j] != close {
                j += 1;
            }
            if j < n {
                cur.extend(&chars[i..=j]);
                i = j + 1;
                continue;
            }
            cur.push(c);
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

fn is_cut_marker(t: &str) -> bool {
    matches!(t, "#" | ";" | "&&" | "|" | ">" | "(") || t.starts_with('#') || t.starts_with('(')
}

fn find_next_cmd_start(s: &str) -> Option<usize> {
    let mut pos = 0usize;
    for part in s.split_whitespace() {
        if let Some(rel) = s[pos..].find(part) {
            let abs = pos + rel;
            if part == "noo" || part == "pai" {
                return Some(abs);
            }
            pos = abs + part.len();
        }
    }
    None
}

/// Normalize a raw hint (starting at `noo`/`pai`) into one command-word list
/// per compound sub-command (`noo a && noo b` yields two). Each cut marker
/// (`#`, `;`, `&&`, `|`, `>`, or a `then`/`, then` continuation) ends the
/// current command; the text after it is searched for the next `noo`/`pai`
/// to start a following one. A trailing `…`/`...` token is dropped.
fn normalize_hint(raw: &str) -> Vec<Vec<String>> {
    let mut results = Vec::new();
    let mut remaining = raw.trim().to_string();
    loop {
        let toks = tokenize_collapsing_placeholders(&remaining);
        if toks.is_empty() {
            break;
        }
        let mut cmd_toks: Vec<String> = Vec::new();
        let mut cut_at: Option<usize> = None;
        for (idx, t) in toks.iter().enumerate() {
            if idx == 0 {
                continue; // the leading "noo"/"pai" itself
            }
            if is_cut_marker(t) {
                cut_at = Some(idx);
                break;
            }
            if t.trim_end_matches(',').eq_ignore_ascii_case("then") {
                cut_at = Some(idx);
                break;
            }
            cmd_toks.push(t.clone());
        }
        if matches!(cmd_toks.last().map(String::as_str), Some("…") | Some("...")) {
            cmd_toks.pop();
        }
        results.push(cmd_toks);
        let Some(idx) = cut_at else { break };
        let after = toks[idx + 1..].join(" ");
        match find_next_cmd_start(&after) {
            Some(pos) => remaining = after[pos..].to_string(),
            None => break,
        }
    }
    results
}

fn strip_globals(tokens: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        if t.starts_with("--color=") {
            i += 1;
            continue;
        }
        if GLOBAL_FLAGS.contains(&t) {
            i += if GLOBAL_FLAGS_WITH_VALUE.contains(&t) { 2 } else { 1 };
            continue;
        }
        out.push(tokens[i].clone());
        i += 1;
    }
    out
}

// ── resolving a token list against usage::USAGE ──────────────────────────

fn resolve_path(tokens: &[String]) -> Option<(usize, &'static str)> {
    let max_len = tokens.len().min(4);
    for l in (1..=max_len).rev() {
        let words: Vec<&str> = tokens[..l].iter().map(String::as_str).collect();
        if let Some((syntax, _desc)) = usage::lookup(&words) {
            return Some((l, syntax));
        }
    }
    None
}

/// Is `tokens` a strict prefix of some longer USAGE path (a valid command
/// GROUP, e.g. `["cluster"]` or `["security", "pki"]`)? An empty slice
/// (bare `noo`/`pai`) is trivially a group.
fn is_group_prefix(tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return true;
    }
    usage::USAGE.iter().any(|(w, _, _)| {
        w.len() > tokens.len() && w[..tokens.len()].iter().zip(tokens.iter()).all(|(a, b)| a == b)
    })
}

// ── parsing a usage synopsis grammar ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    No,
    /// The value itself sits in a further bracket, e.g. `[--wait [<secs>]]`
    /// — the flag may stand alone OR take one value.
    Optional,
    Required,
}

#[derive(Debug, Clone)]
enum ArgSpec {
    Positional { required: bool, variadic: bool },
    Flag { names: Vec<String>, value: ValueKind },
}

/// Top-level whitespace split of a synopsis, treating any `[...]`/`<...>`/
/// `(...)` span (even nested, even holding spaces) as one token. A single
/// depth counter over all six bracket/paren chars is enough to protect
/// internal whitespace without tracking which kind opened which close.
fn synopsis_tokens(syntax: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in syntax.chars() {
        match c {
            '[' | '<' | '(' => {
                depth += 1;
                cur.push(c);
            }
            ']' | '>' | ')' => {
                depth -= 1;
                cur.push(c);
            }
            c if c.is_whitespace() && depth <= 0 => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Insert spaces around a top-level `|` that sits immediately after a
/// closing `>` — the compact alternation shapes `<node>|all` (`cluster
/// clean`) and `--match <glob>|--doc-id <id>` (`rag retag`) glue a
/// placeholder's close directly onto the next branch with no whitespace,
/// which would otherwise fuse into one unparseable token. Only a `|`
/// directly preceded by `>` is touched: a compact FLAG alias like
/// `-r|--replicas` has no `>` before its `|` and is left alone, and a `|`
/// already surrounded by whitespace (`<node> | --all`) needs no help — plain
/// whitespace splitting already isolates it.
fn space_out_placeholder_pipes(syntax: &str) -> String {
    let chars: Vec<char> = syntax.chars().collect();
    let mut out = String::new();
    let mut depth = 0i32;
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '[' | '<' | '(' => {
                depth += 1;
                out.push(c);
            }
            ']' | '>' | ')' => {
                depth -= 1;
                out.push(c);
            }
            '|' if depth <= 0 && i > 0 && chars[i - 1] == '>' => {
                out.push(' ');
                out.push('|');
                out.push(' ');
            }
            c => out.push(c),
        }
    }
    out
}

/// A `<name>` interior must be a plain identifier (possibly with `|`
/// alternatives) — no nested brackets, no spaces. `stack sandbox`'s
/// `<up [--fresh]|status|...>` fails this and the row goes to
/// `unparsed-synopsis` instead of being mis-modeled.
fn is_simple_placeholder(name: &str) -> bool {
    !name.contains('[') && !name.contains('<') && !name.contains(' ')
}

enum RawTok {
    BareFlag { names: Vec<String> },
    BarePositional { variadic: bool },
    Bracketed(Vec<ArgSpec>),
}

/// `<r>[,<r>]` — a value that may be repeated as a comma-joined list, same
/// placeholder name inside both spans (`rag retag`'s `--role <r>[,<r>]`).
/// Treated as one opaque positional slot: an operator types `--role a,b` as
/// a single token anyway, so there is nothing further to check.
fn is_comma_repeat_placeholder(t: &str) -> bool {
    let Some(rest) = t.strip_prefix('<') else { return false };
    let Some(close) = rest.find('>') else { return false };
    let name = &rest[..close];
    if !is_simple_placeholder(name) {
        return false;
    }
    rest[close + 1..] == format!("[,<{name}>]")
}

fn classify_one(tok: &str) -> Option<RawTok> {
    let t = tok.trim();
    if t.is_empty() {
        return None;
    }
    if is_comma_repeat_placeholder(t) {
        return Some(RawTok::BarePositional { variadic: false });
    }
    // `(--approve | --deny)`: a required alternation between whole flags.
    // Treated leniently as ONE flag spec covering every name — this system
    // never enforces that a "required" (unbracketed) flag actually be given
    // (see the module doc above `ArgSpec::Flag`), so collapsing the group
    // this way changes nothing about what already isn't checked.
    if let Some(inner) = t.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        let branches: Vec<&str> = inner.split('|').map(str::trim).collect();
        if !branches.is_empty() && branches.iter().all(|b| b.starts_with('-') && b.len() > 1) {
            return Some(RawTok::BareFlag { names: branches.iter().map(|s| s.to_string()).collect() });
        }
        return None;
    }
    if t.starts_with('[') {
        // Find the bracket's OWN matching `]` by depth (not a naive
        // suffix-strip): whatever follows it is a trailing repeat marker
        // (`...` or the single-glyph `…`, `[--ref <msg-id>]…`) or nothing —
        // anything else is junk this lint won't guess at.
        let chars: Vec<char> = t.chars().collect();
        let mut depth = 0i32;
        let mut close_idx = None;
        for (i, c) in chars.iter().enumerate() {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        close_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close_idx = close_idx?;
        let body: String = chars[1..close_idx].iter().collect();
        let trailing: String = chars[close_idx + 1..].iter().collect();
        let repeatable = trailing == "..." || trailing == "…";
        if !repeatable && !trailing.is_empty() {
            return None;
        }
        let mut specs = classify_bracket_inner(&body)?;
        if repeatable {
            for s in &mut specs {
                if let ArgSpec::Positional { variadic, .. } = s {
                    *variadic = true;
                }
            }
        }
        return Some(RawTok::Bracketed(specs));
    }
    if let Some(t) = t.strip_prefix('<') {
        let variadic = t.ends_with("...");
        let core = if variadic { &t[..t.len() - 3] } else { t };
        let name = core.strip_suffix('>')?;
        if !is_simple_placeholder(name) {
            return None;
        }
        return Some(RawTok::BarePositional { variadic });
    }
    if t.starts_with('-') || t.contains('|') {
        let parts: Vec<&str> = t.split('|').collect();
        if parts.iter().all(|p| p.starts_with('-') && p.len() > 1) {
            return Some(RawTok::BareFlag { names: parts.iter().map(|s| s.to_string()).collect() });
        }
        if !t.starts_with('-') {
            // An enumerated bare-word value spelled at top level, e.g.
            // `--mode dedicated|shared`'s value token: not a flag
            // alternation (no branch starts with `-`), just one opaque
            // value slot for the preceding flag to consume.
            return Some(RawTok::BarePositional { variadic: false });
        }
        return None;
    }
    // A bare literal word with no special shape (`--transport http`'s
    // `http`; `cluster clean <node>|all`'s `all` once split out by
    // `space_out_placeholder_pipes`) — one opaque required value/positional
    // slot. This is the LAST resort: every more specific shape above has
    // already had its chance.
    Some(RawTok::BarePositional { variadic: false })
}

/// Classify the content of one `[...]` optional group. May itself hold an
/// optional positional (`[<x>]`), a boolean flag (`[--a]`), a flag
/// alternation (`[--merge | --push]`), a flag with a value
/// (`[--task-id <id>]`, `[--role chat|embed|rerank]`), or a bare literal
/// (`[heads]`).
fn classify_bracket_inner(inner: &str) -> Option<Vec<ArgSpec>> {
    let inner = inner.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    if let Some(rest) = inner.strip_prefix('<') {
        let variadic = rest.ends_with("...");
        let core = if variadic { &rest[..rest.len() - 3] } else { rest };
        let name = core.strip_suffix('>')?;
        if !is_simple_placeholder(name) {
            return None;
        }
        return Some(vec![ArgSpec::Positional { required: false, variadic }]);
    }
    let subtoks = synopsis_tokens(inner);
    if subtoks.is_empty() {
        return None;
    }
    // "--merge | --push", "--reload | --no-reload": alternation with spaces.
    if subtoks.len() >= 3
        && subtoks.iter().skip(1).step_by(2).all(|t| t == "|")
        && subtoks.iter().step_by(2).all(|t| t.starts_with('-'))
    {
        let names = subtoks.iter().step_by(2).map(|s| s.to_string()).collect();
        return Some(vec![ArgSpec::Flag { names, value: ValueKind::No }]);
    }
    if subtoks.len() == 1 {
        let t = &subtoks[0];
        if t.starts_with('-') || t.contains('|') {
            let parts: Vec<&str> = t.split('|').collect();
            if parts.iter().all(|p| p.starts_with('-') && p.len() > 1) {
                let names = parts.iter().map(|s| s.to_string()).collect();
                return Some(vec![ArgSpec::Flag { names, value: ValueKind::No }]);
            }
            if !t.starts_with('-') {
                // An enumerated bare-word literal, e.g. `[dedicated|shared]`
                // on its own — one optional value slot.
                return Some(vec![ArgSpec::Positional { required: false, variadic: false }]);
            }
            return None;
        }
        // A bare literal, e.g. `[heads]` — one optional value slot.
        return Some(vec![ArgSpec::Positional { required: false, variadic: false }]);
    }
    if subtoks.len() == 2 {
        let flag = &subtoks[0];
        let value = &subtoks[1];
        let flag_ok = (flag.starts_with('-') || flag.contains('|'))
            && flag.split('|').all(|p| p.starts_with('-') && p.len() > 1);
        if !flag_ok {
            return None;
        }
        let names: Vec<String> = flag.split('|').map(|s| s.to_string()).collect();
        if value.starts_with('[') && value.ends_with(']') {
            // Distinguish a nested VALUE placeholder (`[--wait [<secs>]]` —
            // the flag may stand alone or take one value) from a nested FLAG
            // spec (`[--web [--port <n>]]` — a genuinely separate,
            // independently-optional flag that only makes sense alongside
            // the outer one, but is not itself the outer flag's value).
            let inner_body = &value[1..value.len() - 1];
            let nested = classify_bracket_inner(inner_body)?;
            return if nested.iter().all(|s| matches!(s, ArgSpec::Positional { .. })) {
                Some(vec![ArgSpec::Flag { names, value: ValueKind::Optional }])
            } else {
                let mut out = vec![ArgSpec::Flag { names, value: ValueKind::No }];
                out.extend(nested);
                Some(out)
            };
        }
        let value_kind = if (value.starts_with('<') && value.ends_with('>')) || !value.starts_with('-') {
            ValueKind::Required
        } else {
            return None;
        };
        return Some(vec![ArgSpec::Flag { names, value: value_kind }]);
    }
    if subtoks.len() == 3 {
        // `[--from-archive <f> [--passphrase-file <f>]]`: a flag with its
        // OWN required value, plus a further nested flag that only makes
        // sense alongside it. Same nested-spec handling as the 2-subtok
        // case, just with a value in between instead of the flag standing
        // bare.
        let (flag, value, nested) = (&subtoks[0], &subtoks[1], &subtoks[2]);
        let flag_ok = (flag.starts_with('-') || flag.contains('|'))
            && flag.split('|').all(|p| p.starts_with('-') && p.len() > 1);
        if !flag_ok || !(nested.starts_with('[') && nested.ends_with(']')) {
            return None;
        }
        let value_kind = if (value.starts_with('<') && value.ends_with('>')) || !value.starts_with('-') {
            ValueKind::Required
        } else {
            return None;
        };
        let names: Vec<String> = flag.split('|').map(|s| s.to_string()).collect();
        let nested_specs = classify_bracket_inner(&nested[1..nested.len() - 1])?;
        let mut out = vec![ArgSpec::Flag { names, value: value_kind }];
        out.extend(nested_specs);
        return Some(out);
    }
    None
}

/// Classify an already-split token sequence (no top-level alternation left
/// to resolve) into an ordered list of arg specs, or `None` if any token
/// fails to classify at all.
fn classify_tokens(toks: &[String]) -> Option<Vec<ArgSpec>> {
    let mut raw = Vec::with_capacity(toks.len());
    for t in toks {
        raw.push(classify_one(t)?);
    }
    let mut specs = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        match &raw[i] {
            RawTok::BareFlag { names } => {
                // A bare (unbracketed) flag directly followed by a bare
                // positional is a required flag WITH a value:
                // `-r|--replicas <n>`, `--role <role>...`.
                if let Some(RawTok::BarePositional { .. }) = raw.get(i + 1) {
                    specs.push(ArgSpec::Flag { names: names.clone(), value: ValueKind::Required });
                    i += 2;
                    continue;
                }
                specs.push(ArgSpec::Flag { names: names.clone(), value: ValueKind::No });
                i += 1;
            }
            RawTok::BarePositional { variadic } => {
                specs.push(ArgSpec::Positional { required: true, variadic: *variadic });
                i += 1;
            }
            RawTok::Bracketed(inner) => {
                specs.extend(inner.clone());
                i += 1;
            }
        }
    }
    Some(specs)
}

/// Split top-level synopsis tokens at bare `|` tokens into alternative
/// branches, plus a shared suffix of bracketed (optional) tokens that
/// follows the LAST branch and applies to every branch alike:
/// `<blob> | --url <u> --token <t> | --via-tailnet <u> [--ca-sha256 <hex>]
/// ...` — three branches, one shared trailing run of optional flags. With no
/// top-level `|` at all this is just the one branch and an empty suffix.
fn split_top_level(tokens: &[String]) -> (Vec<Vec<String>>, Vec<String>) {
    let pipe_positions: Vec<usize> =
        tokens.iter().enumerate().filter(|(_, t)| t.as_str() == "|").map(|(i, _)| i).collect();
    if pipe_positions.is_empty() {
        return (vec![tokens.to_vec()], Vec::new());
    }
    let last_pipe = *pipe_positions.last().unwrap();
    let mut suffix_start = tokens.len();
    for (i, t) in tokens.iter().enumerate().skip(last_pipe + 1) {
        if t.starts_with('[') || t.starts_with('(') {
            suffix_start = i;
            break;
        }
    }
    let common = tokens[suffix_start..].to_vec();
    let mut branches = Vec::new();
    let mut start = 0usize;
    for &p in &pipe_positions {
        branches.push(tokens[start..p].to_vec());
        start = p + 1;
    }
    branches.push(tokens[start..suffix_start].to_vec());
    (branches, common)
}

/// Find a top-level `(...)` group in `syntax` — one NOT itself nested inside
/// a `[...]`/`<...>` span — and split the string into what comes before it,
/// its own interior, and what comes after. Two independent depth counters
/// (one for `[]`/`<>`, one for `()`) so a bracket inside the group's own
/// interior (there are none today, but nothing stops one) doesn't confuse
/// the paren match. `security user decide`'s `(--approve | --deny)` and `rag
/// retag`'s `(--match <glob> | --doc-id <id>)` are the two real examples.
fn split_paren_group(syntax: &str) -> Option<(&str, &str, &str)> {
    let mut bracket_depth = 0i32;
    let mut paren_depth = 0i32;
    let mut open_byte = None;
    let mut close_byte = None;
    for (i, c) in syntax.char_indices() {
        match c {
            '[' | '<' => bracket_depth += 1,
            ']' | '>' => bracket_depth -= 1,
            '(' => {
                if paren_depth == 0 && bracket_depth == 0 && open_byte.is_none() {
                    open_byte = Some(i);
                }
                paren_depth += 1;
            }
            ')' => {
                paren_depth -= 1;
                if paren_depth == 0 && open_byte.is_some() {
                    close_byte = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let (o, c) = (open_byte?, close_byte?);
    Some((&syntax[..o], &syntax[o + 1..c], &syntax[c + 1..]))
}

/// Split an already-tokenized run at bare `|` tokens — used for a
/// PARENTHESIZED group's own interior, which has no shared suffix to worry
/// about (that's the text outside the parens, handled by the caller).
fn split_on_bare_pipes(tokens: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for t in tokens {
        if t == "|" {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(t.clone());
        }
    }
    out.push(cur);
    out
}

/// Parse a whole usage synopsis into one or more ALTERNATIVE ordered
/// arg-spec sequences. More than one only when the synopsis has a top-level
/// `|` alternation:
/// - a parenthesized group (`(--match <glob> | --doc-id <id>) --role ...`) —
///   each branch shares whatever comes before AND after the group, which is
///   what lets a required flag like `--role` sit right after the group
///   without being swallowed into just the last branch;
/// - or a bare one, either spaced (`<node> | --all`) or a compact shape
///   glued straight onto a placeholder's close (`<node>|all`,
///   `<glob>|--doc-id <id>`; `space_out_placeholder_pipes` inserts the
///   spaces those need before tokenizing) — everything from the first
///   bracketed/optional token after the LAST branch onward is the shared
///   suffix instead, since there is no closing paren to mark where the
///   alternation itself ends.
/// A hint's args are accepted when ANY alternative accepts them (see
/// `check_args`). `None` means every branch failed to classify at all
/// (recorded as `unparsed-synopsis`, never a failure) — `stack sandbox`'s
/// fully-nested `<up [--fresh]|status|run <cmd>...|...>` is the one real
/// example: an entire alternation of full sub-shapes packed inside a single
/// `<...>`, which `is_simple_placeholder` rejects outright.
fn classify_synopsis(syntax: &str) -> Option<Vec<Vec<ArgSpec>>> {
    if syntax.trim().is_empty() {
        return Some(vec![Vec::new()]);
    }
    if let Some((prefix, inner, suffix)) = split_paren_group(syntax) {
        let inner_toks = synopsis_tokens(inner);
        let mut out = Vec::new();
        for branch_toks in split_on_bare_pipes(&inner_toks) {
            let full = format!("{prefix} {} {suffix}", branch_toks.join(" "));
            if let Some(mut alts) = classify_synopsis_flat(&full) {
                out.append(&mut alts);
            }
        }
        return if out.is_empty() { None } else { Some(out) };
    }
    classify_synopsis_flat(syntax)
}

/// The non-parenthesized case: a bare top-level `|` alternation (or none at
/// all — the overwhelmingly common case, a single branch).
fn classify_synopsis_flat(syntax: &str) -> Option<Vec<Vec<ArgSpec>>> {
    let spaced = space_out_placeholder_pipes(syntax);
    let toks = synopsis_tokens(&spaced);
    let (branches, common) = split_top_level(&toks);
    let mut out = Vec::new();
    for branch in branches {
        if branch.is_empty() && !common.is_empty() {
            continue; // a stray empty branch from malformed input; skip it
        }
        let mut full = branch;
        full.extend(common.iter().cloned());
        if let Some(specs) = classify_tokens(&full) {
            out.push(specs);
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

// ── checking a hint's arguments against a parsed synopsis ────────────────

fn is_placeholder(t: &str) -> bool {
    t.starts_with('{') || t.starts_with('<')
}

fn split_flag_eq(a: &str) -> (&str, Option<&str>) {
    match a.find('=') {
        Some(i) => (&a[..i], Some(&a[i + 1..])),
        None => (a, None),
    }
}

/// Try every alternative the synopsis parsed into (see `classify_synopsis`)
/// and accept the hint's args if ANY of them do. On failure, prefer a
/// `Warn` over a `Mismatch` if any alternative produced one, and otherwise
/// report the first alternative's mismatch kind (stable, deterministic).
fn check_args(args: &[String], syntax: &str) -> Verdict {
    let Some(alts) = classify_synopsis(syntax) else {
        return Verdict::Unparsed;
    };
    let mut best_warn: Option<Verdict> = None;
    let mut first_mismatch: Option<Verdict> = None;
    for specs in &alts {
        match check_args_against(args, specs) {
            v @ (Verdict::Ok | Verdict::GroupOk) => return v,
            v @ Verdict::Warn(_) => {
                if best_warn.is_none() {
                    best_warn = Some(v);
                }
            }
            v @ Verdict::Mismatch(_) => {
                if first_mismatch.is_none() {
                    first_mismatch = Some(v);
                }
            }
            Verdict::Unparsed => {}
        }
    }
    best_warn.or(first_mismatch).unwrap_or(Verdict::Unparsed)
}

fn check_args_against(args: &[String], specs: &[ArgSpec]) -> Verdict {
    let mut flag_names: Vec<&str> = Vec::new();
    let mut flag_value: HashMap<&str, ValueKind> = HashMap::new();
    let mut has_variadic_positional = false;
    let mut required_positionals = 0usize;
    let mut optional_positional_slots = 0usize;
    for s in specs {
        match s {
            ArgSpec::Positional { required, variadic } => {
                if *variadic {
                    has_variadic_positional = true;
                } else if *required {
                    required_positionals += 1;
                } else {
                    optional_positional_slots += 1;
                }
            }
            ArgSpec::Flag { names, value } => {
                for n in names {
                    flag_names.push(n.as_str());
                    flag_value.insert(n.as_str(), *value);
                }
            }
        }
    }

    let mut n_positional = 0usize;
    let mut had_placeholder = false;
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        // A hint occasionally shows an optional part documentation-style,
        // inline, in its OWN text (`[-i key=value]`) — not checkable, and
        // not counted toward arity either way.
        if a.starts_with('[') {
            i += 1;
            continue;
        }
        if is_placeholder(a) {
            had_placeholder = true;
        }
        if a.starts_with('-') && a != "-" && !is_placeholder(a) {
            let (name, inline_value) = split_flag_eq(a);
            if name == "--help" || name == "-h" {
                i += 1;
                continue;
            }
            if !flag_names.contains(&name) {
                return Verdict::Mismatch(Kind::UnknownFlag);
            }
            let value_kind = *flag_value.get(name).unwrap_or(&ValueKind::No);
            let wants_value = value_kind != ValueKind::No && inline_value.is_none();
            if wants_value {
                match args.get(i + 1) {
                    Some(next) if !next.starts_with('-') || is_placeholder(next) => {
                        i += 2;
                        continue;
                    }
                    _ if value_kind == ValueKind::Optional => {
                        // The value itself is optional — fine standing alone.
                    }
                    _ => return Verdict::Mismatch(Kind::MissingValue),
                }
            }
            i += 1;
            continue;
        }
        n_positional += 1;
        i += 1;
    }
    if !has_variadic_positional && n_positional > required_positionals + optional_positional_slots {
        return Verdict::Mismatch(Kind::TooManyPositionals);
    }
    if n_positional < required_positionals {
        if n_positional == 0 && !had_placeholder {
            return Verdict::Mismatch(Kind::MissingRequired);
        }
        return Verdict::Warn(Kind::MissingRequired);
    }
    Verdict::Ok
}

fn check_one(cmd_tokens: &[String]) -> (Verdict, Option<&'static str>) {
    // `noo completions <shell>` is native (main.rs `Resolution::Completions`,
    // matched on the literal word before the registry is even consulted —
    // see `resolve_with` step 4) but, deliberately, has no `usage::USAGE`
    // row: it is a shell-bootstrap command, not one users tab through, and
    // isn't rendered in `--help`. `usage::lookup`/`is_group_prefix` can
    // never see it, so it needs its own pass here.
    if cmd_tokens.first().map(String::as_str) == Some("completions") {
        return (Verdict::GroupOk, None);
    }
    // The command word itself is a runtime placeholder (`noo {}`, `noo
    // {verb}`, `noo <name> …`): this is an echo of whatever the operator
    // actually typed, or a documentation pattern for "any command", not a
    // literal suggestion — there is nothing to check it against.
    if cmd_tokens.first().is_some_and(|t| is_placeholder(t)) {
        return (Verdict::GroupOk, None);
    }
    let stripped = strip_globals(cmd_tokens);
    if stripped.is_empty() {
        return (Verdict::GroupOk, None);
    }
    if let Some((l, syntax)) = resolve_path(&stripped) {
        return (check_args(&stripped[l..], syntax), Some(syntax));
    }
    if is_group_prefix(&stripped) {
        return (Verdict::GroupOk, None);
    }
    (Verdict::Mismatch(Kind::UnknownCommand), None)
}

/// Test-facing convenience: resolve `hint` (starting `noo `/`pai `) against
/// `usage::USAGE` for its command PATH only, then check its remaining
/// tokens against the caller-supplied `synopsis` (which need not be the
/// live one — this lets unit tests exercise grammar shapes directly while
/// still using a real command path to anchor where the args start).
fn check(hint: &str, synopsis: &str) -> Verdict {
    let toks = tokenize_collapsing_placeholders(hint.trim());
    let rest: Vec<String> = toks.into_iter().skip(1).collect();
    let stripped = strip_globals(&rest);
    let Some((l, _)) = resolve_path(&stripped) else {
        return Verdict::Mismatch(Kind::UnknownCommand);
    };
    check_args(&stripped[l..], synopsis)
}

fn is_allowed(file: &str, text: &str, hit: &mut [bool]) -> bool {
    for (i, (f, sub, _why)) in ALLOWED.iter().enumerate() {
        if *f == file && text.contains(sub) {
            hit[i] = true;
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── matcher unit tests ────────────────────────────────────────────

    #[test]
    fn synopsis_grammar_forms() {
        // required + optional positionals
        let s = classify_synopsis("<a> [<b>]").unwrap();
        assert!(matches!(s[0][0], ArgSpec::Positional { required: true, variadic: false }));
        assert!(matches!(s[0][1], ArgSpec::Positional { required: false, variadic: false }));
        // variadic positional
        let s = classify_synopsis("<node>...").unwrap();
        assert!(matches!(s[0][0], ArgSpec::Positional { required: true, variadic: true }));
        // optional variadic
        let s = classify_synopsis("[<node>...]").unwrap();
        assert!(matches!(s[0][0], ArgSpec::Positional { required: false, variadic: true }));
        // boolean flag
        let s = classify_synopsis("[--force]").unwrap();
        assert!(matches!(&s[0][0], ArgSpec::Flag { value: ValueKind::No, .. }));
        // flag with value
        let s = classify_synopsis("[--task-id <id>]").unwrap();
        assert!(matches!(&s[0][0], ArgSpec::Flag { value: ValueKind::Required, .. }));
        // required flag with value, no brackets
        let s = classify_synopsis("-r|--replicas <n>").unwrap();
        match &s[0][0] {
            ArgSpec::Flag { names, value } => {
                assert_eq!(*value, ValueKind::Required);
                assert!(names.contains(&"-r".to_string()));
                assert!(names.contains(&"--replicas".to_string()));
            }
            _ => panic!("expected a flag"),
        }
        // short-form alternation, bracketed
        let s = classify_synopsis("[-y|--yes]").unwrap();
        assert!(matches!(&s[0][0], ArgSpec::Flag { value: ValueKind::No, .. }));
        // spaced flag alternation
        let s = classify_synopsis("[--merge | --push]").unwrap();
        match &s[0][0] {
            ArgSpec::Flag { names, .. } => assert_eq!(names.len(), 2),
            _ => panic!("expected a flag"),
        }
        // value enum (no spaces around |)
        let s = classify_synopsis("[--role chat|embed|rerank]").unwrap();
        assert!(matches!(&s[0][0], ArgSpec::Flag { value: ValueKind::Required, .. }));
        // repeatable optional flag group
        let s = classify_synopsis("[--san <name>]...").unwrap();
        match &s[0][0] {
            ArgSpec::Flag { .. } => {}
            _ => panic!("expected a flag"),
        }
        // bare optional literal
        let s = classify_synopsis("[heads]").unwrap();
        assert!(matches!(s[0][0], ArgSpec::Positional { required: false, .. }));
        // empty synopsis
        assert!(classify_synopsis("").unwrap()[0].is_empty());
    }

    #[test]
    fn comma_repeat_placeholder_is_one_value_slot() {
        // `rag retag`'s `--role <r>[,<r>]` — a flag whose value may itself be
        // a comma-joined list, but is still ONE token to an operator.
        let s = classify_synopsis("--role <r>[,<r>]").unwrap();
        assert_eq!(s.len(), 1);
        match &s[0][0] {
            ArgSpec::Flag { names, value } => {
                assert_eq!(*value, ValueKind::Required);
                assert!(names.contains(&"--role".to_string()));
            }
            other => panic!("expected a flag, got {other:?}"),
        }
    }

    #[test]
    fn grouped_alternation_is_a_flag_set() {
        // `security user decide <id> (--approve | --deny) [--reason <text>]`
        // — a parenthesized group splits into one alternative branch PER
        // option, each sharing the `<id>` prefix and `[--reason]` suffix.
        let s = classify_synopsis("<id> (--approve | --deny) [--reason <text>]").unwrap();
        assert_eq!(s.len(), 2);
        for branch in &s {
            assert!(matches!(branch[0], ArgSpec::Positional { required: true, .. }));
        }
        let flag_names: Vec<&str> = s
            .iter()
            .filter_map(|b| b.iter().find_map(|s| match s {
                ArgSpec::Flag { names, .. } => Some(names[0].as_str()),
                _ => None,
            }))
            .collect();
        assert!(flag_names.contains(&"--approve"));
        assert!(flag_names.contains(&"--deny"));
        // Both real invocations pass.
        assert_eq!(
            check("noo security user decide req-1 --approve", "<id> (--approve | --deny) [--reason <text>]"),
            Verdict::Ok
        );
        assert_eq!(
            check("noo security user decide req-1 --deny --reason why", "<id> (--approve | --deny) [--reason <text>]"),
            Verdict::Ok
        );
    }

    #[test]
    fn bracket_repeat_marker_accepts_ellipsis_glyph() {
        // `agents send`'s `[--ref <msg-id>]…` — the single-glyph ellipsis,
        // not ASCII `...`, right after the closing `]`.
        let s = classify_synopsis("[--ref <msg-id>]…").unwrap();
        match &s[0][0] {
            ArgSpec::Flag { .. } => {}
            other => panic!("expected a flag, got {other:?}"),
        }
        // junk after the bracket (neither marker) stays unparsed rather than
        // being guessed at.
        assert!(classify_synopsis("[--ref <msg-id>]x").is_none());
    }

    #[test]
    fn nested_bracket_distinguishes_value_from_flag() {
        // `[--wait [<secs>]]`: the value itself is optional — the outer flag
        // may stand alone OR take one value.
        let s = classify_synopsis("[--wait [<secs>]]").unwrap();
        assert_eq!(s[0].len(), 1);
        assert!(matches!(&s[0][0], ArgSpec::Flag { value: ValueKind::Optional, .. }));
        // `[--web [--port <n>]]`: the nested bracket is a SEPARATE flag, not
        // a value for the outer one — two independent optional flags.
        let s = classify_synopsis("[--web [--port <n>]]").unwrap();
        assert_eq!(s[0].len(), 2);
        assert!(matches!(&s[0][0], ArgSpec::Flag { value: ValueKind::No, .. }));
        assert!(matches!(&s[0][1], ArgSpec::Flag { value: ValueKind::Required, .. }));
    }

    #[test]
    fn enumerated_bare_value_is_one_positional_slot() {
        // `kiosk setup`'s `--mode dedicated|shared` — an enumerated VALUE,
        // not a flag alternation (neither branch starts with `-`).
        let s = classify_synopsis("--mode dedicated|shared --url <u>").unwrap();
        match &s[0][0] {
            ArgSpec::Flag { names, value } => {
                assert_eq!(*value, ValueKind::Required);
                assert!(names.contains(&"--mode".to_string()));
            }
            other => panic!("expected a flag, got {other:?}"),
        }
    }

    #[test]
    fn top_level_alternation_spaced_and_compact() {
        // Spaced: `cluster teardown-node`'s `<node> | --all [...]` — two
        // branches sharing the trailing optional flags.
        let alts = classify_synopsis("<node> | --all [--purge-data]").unwrap();
        assert_eq!(alts.len(), 2);
        assert_eq!(check_args_against(&["n1".into()], &alts[0]), Verdict::Ok);
        assert_eq!(check_args_against(&["--all".into()], &alts[1]), Verdict::Ok);

        // Compact, no spaces: `cluster clean`'s `<node>|all [...]`.
        let alts = classify_synopsis("<node>|all [--deep]").unwrap();
        assert_eq!(alts.len(), 2);
        assert_eq!(check("noo cluster clean <node>", "<node>|all [--deep]"), Verdict::Ok);
        assert_eq!(check("noo cluster clean all", "<node>|all [--deep]"), Verdict::Ok);

        // Compact against a placeholder's close, on the OTHER side of the
        // pipe: `rag retag`'s `--match <glob>|--doc-id <id> --role <r>`.
        let alts = classify_synopsis("--match <glob>|--doc-id <id> --role <r>").unwrap();
        assert_eq!(alts.len(), 2);

        // Three-way, `enroll`'s shape: a bare positional, then two
        // multi-token flag branches, all sharing a trailing optional suffix.
        let alts = classify_synopsis(
            "<blob> | --url <u> --token <t> | --via-tailnet <u> [--resume]",
        )
        .unwrap();
        assert_eq!(alts.len(), 3);
        // `--resume` alone gives no `<blob>`, so branch 0 alone rejects it —
        // but the flag-only branches (`--url`/`--token`, `--via-tailnet`)
        // never enforce their own flags as "required" either (this system
        // doesn't model that), so trying every alternative accepts it.
        assert_eq!(
            check_args_against(&["--resume".into()], &alts[0]),
            Verdict::Mismatch(Kind::MissingRequired)
        );
        assert_eq!(
            check_args(&["--resume".into()], "<blob> | --url <u> --token <t> | --via-tailnet <u> [--resume]"),
            Verdict::Ok
        );
    }

    #[test]
    fn irregular_synopsis_is_unparsed() {
        // stack sandbox's nested alternation-of-full-shapes: an entire `|`
        // alternation of full sub-grammars packed inside ONE `<...>`, which
        // `is_simple_placeholder` rejects outright — genuinely irregular,
        // unlike the top-level-alternation shapes above.
        assert!(classify_synopsis(
            "<up [--fresh]|status|run <cmd>...|rehearse|down [--keep-data]>"
        )
        .is_none());
    }

    #[test]
    fn check_args_every_kind() {
        assert_eq!(check_args(&[], "<a>"), Verdict::Mismatch(Kind::MissingRequired));
        assert_eq!(
            check_args(&["{x}".into()], "<a> <b>"),
            Verdict::Warn(Kind::MissingRequired)
        );
        assert_eq!(check_args(&["a".into(), "b".into()], "<a>"), Verdict::Mismatch(Kind::TooManyPositionals));
        assert_eq!(check_args(&["--nope".into()], "[--force]"), Verdict::Mismatch(Kind::UnknownFlag));
        assert_eq!(check_args(&["--task-id".into()], "[--task-id <id>]"), Verdict::Mismatch(Kind::MissingValue));
        assert_eq!(check_args(&["--task-id".into(), "x".into()], "[--task-id <id>]"), Verdict::Ok);
        assert_eq!(check_args(&[], "[--force]"), Verdict::Ok);
        assert_eq!(check_args(&["a".into(), "b".into(), "c".into()], "<x>..."), Verdict::Ok);
        // `--help` reaching `check_args` directly (bypassing the
        // `strip_globals` real callers apply first) is consumed as help,
        // not counted as a positional — so a required positional is still
        // unmet with no placeholder in sight: a hard miss.
        assert_eq!(check_args(&["--help".into()], "<a>"), Verdict::Mismatch(Kind::MissingRequired));
    }

    /// The finding that started this lint: `noo heartbeat history
    /// {task_id}` in `commands/heartbeat.rs` — `heartbeat history` takes
    /// only `[--task-id <id>] [--limit <n>]`, no positional. Checked
    /// directly against the matcher (per the task's own fallback) so this
    /// stays true regardless of whether another change has since touched
    /// `heartbeat.rs`.
    #[test]
    fn heartbeat_history_positional_overreach_is_caught() {
        assert_eq!(
            check("noo heartbeat history weekly_research", "[--task-id <id>] [--limit <n>]"),
            Verdict::Mismatch(Kind::TooManyPositionals)
        );
    }

    #[test]
    fn resolve_and_group_semantics() {
        let w = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(is_group_prefix(&[]));
        assert!(is_group_prefix(&w(&["cluster"])));
        assert!(is_group_prefix(&w(&["security", "pki"])));
        assert!(!is_group_prefix(&w(&["cluster", "status"]))); // exact command, not a group
        assert!(!is_group_prefix(&w(&["cluster", "not-a-thing"])));
        assert_eq!(resolve_path(&w(&["cluster", "status"])), Some((2, "")));
        assert_eq!(
            resolve_path(&w(&["cluster", "bootstrap-token", "create", "extra"])).map(|(l, _)| l),
            Some(3)
        );
    }

    #[test]
    fn normalize_splits_compound_hints() {
        let cmds = normalize_hint("noo stack start && noo stack status");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], vec!["stack".to_string(), "start".to_string()]);
        assert_eq!(cmds[1], vec!["stack".to_string(), "status".to_string()]);
        let cmds = normalize_hint("noo cluster status # then check logs");
        assert_eq!(cmds[0], vec!["cluster".to_string(), "status".to_string()]);
        let cmds = normalize_hint("noo heartbeat run <task-id>...");
        assert_eq!(cmds[0], vec!["heartbeat".to_string(), "run".to_string(), "<task-id>...".to_string()]);
    }

    // ── extraction sanity ─────────────────────────────────────────────

    /// A broken extractor (e.g. one that never matches a call context)
    /// could make `every_suggested_command_parses` pass vacuously. Pin a
    /// floor so that can't happen silently.
    #[test]
    fn extraction_is_not_vacuous() {
        // The ~860 figure floating around for backtick mentions counts
        // EVERY `` `noo …` ``/`` `pai …` `` in the tree, including doc
        // comments (`///`/`//!`); measured directly, 704 of those 860 sit on
        // a comment-only line. Point 1 of the extraction heuristic (module
        // doc above) explicitly skips comment lines — a doc comment is
        // developer documentation, not something the CLI prints to an
        // operator — so this lint's real, correctly-scoped backtick count
        // is ~200, not ~860. That lowers the achievable floor for TOTAL
        // hints; the shape-(a) floor (tuple/`Some` — always live code, never
        // a comment) is unaffected and kept at the task's own number.
        let hints = all_hints();
        assert!(hints.len() >= 500, "extracted only {} hints (want >= 500)", hints.len());
        let shape_a = hints.iter().filter(|h| h.shape == Shape::TupleOrSome).count();
        assert!(shape_a >= 400, "extracted only {shape_a} shape-(a) hints (want >= 400)");
    }

    // ── the lint itself ────────────────────────────────────────────────

    /// Every `noo …`/`pai …` command this crate suggests to an operator
    /// must be one `usage::USAGE` actually accepts. This MUST fail before
    /// any fix lands (that failure is the point of this task) — do not
    /// weaken it to pass.
    /// The operator's rule (2026-10-02): never `tailnet policy --push`. It
    /// REPLACES the live policy, and the operator keeps rules of their own
    /// there; `--merge` is the sanctioned, additive path. No hint, remedy or
    /// alert in the CLI or the gateway may suggest the push — the `cluster
    /// verify` row's remedy did ("read the diff, then --push"), and so did
    /// the policy verb's own guide. The flag stays (usage.rs documents it);
    /// only suggesting it is refused. Vacuity: the `--merge` hints exist.
    #[test]
    fn no_hint_suggests_a_wholesale_tailnet_push() {
        let mut hints = all_hints();
        hints.extend(gateway_hints());
        let tailnet: Vec<&Hint> = hints.iter().filter(|h| h.text.contains("tailnet policy")).collect();
        assert!(
            tailnet.iter().any(|h| h.text.contains("--merge")),
            "no `tailnet policy --merge` hint found — reading the wrong tree?"
        );
        let push: Vec<String> = tailnet
            .iter()
            .filter(|h| h.text.contains("--push"))
            .map(|h| format!("{}:{}  {}", h.file, h.line, h.text))
            .collect();
        assert!(push.is_empty(), "hints that suggest a wholesale tailnet push:\n{}", push.join("\n"));

        // A remedy passed as a later argument (`fail(name, detail, "noo …")`)
        // is not in a hint-extraction shape, so scan every live string
        // literal too. usage.rs only DESCRIBES the flag.
        let root = src_root();
        let mut files = Vec::new();
        collect_rs_files(&root, &mut files);
        let mut raw: Vec<String> = Vec::new();
        for f in &files {
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "hint_lint.rs" || name == "usage.rs" {
                continue;
            }
            let text = sanitize(&std::fs::read_to_string(f).unwrap());
            for lit in find_string_literals(&text) {
                if lit.content.contains("tailnet policy") && lit.content.contains("--push") {
                    raw.push(format!("{}:{}  {}", f.display(), lit.line, lit.content));
                }
            }
        }
        assert!(raw.is_empty(), "string literals that suggest a wholesale tailnet push:\n{}", raw.join("\n"));
    }

    #[test]
    fn every_suggested_command_parses() {
        let hints = all_hints();
        let mut allow_hit = vec![false; ALLOWED.len()];
        let mut bad: Vec<String> = Vec::new();
        for h in &hints {
            for cmd in normalize_hint(&h.text) {
                if cmd.is_empty() && h.text.trim() != "noo" && h.text.trim() != "pai" {
                    continue;
                }
                let (verdict, syntax) = check_one(&cmd);
                let kind = match verdict {
                    Verdict::Ok | Verdict::GroupOk | Verdict::Unparsed | Verdict::Warn(_) => continue,
                    Verdict::Mismatch(k) => k,
                };
                if is_allowed(&h.file, &h.text, &mut allow_hit) {
                    continue;
                }
                bad.push(format!(
                    "{}:{}  {}  \"{}\"  — synopsis: {}",
                    h.file,
                    h.line,
                    kind.label(),
                    h.text,
                    syntax.unwrap_or("")
                ));
            }
        }
        for (i, (file, sub, why)) in ALLOWED.iter().enumerate() {
            assert!(allow_hit[i], "stale ALLOWED entry ({file}, {sub:?}): {why} — matched nothing");
        }
        bad.sort();
        bad.dedup();
        assert!(bad.is_empty(), "hint/usage drift ({} findings):\n{}", bad.len(), bad.join("\n"));
    }

    /// The gateway's commands pass the same check: every
    /// alert's `investigate` command and every backtick `noo …` the gateway
    /// writes. An alert's `Next:` line is the one thing on the operator's
    /// phone that is meant to be typed.
    #[test]
    fn every_gateway_suggested_command_parses() {
        let hints = gateway_hints();
        let investigate = hints.iter().filter(|h| h.shape == Shape::Helper).count();
        // Vacuity: the gateway has ~50 operator alerts, each with a command.
        assert!(investigate >= 40, "found only {investigate} gateway investigate commands — reading the wrong tree?");
        let mut hit = vec![false; GATEWAY_ALLOWED.len()];
        let bad = mismatches(&hints, GATEWAY_ALLOWED, &mut hit);
        for (i, (file, sub, why)) in GATEWAY_ALLOWED.iter().enumerate() {
            assert!(hit[i], "stale GATEWAY_ALLOWED entry ({file}, {sub:?}): {why} — matched nothing");
        }
        assert!(bad.is_empty(), "gateway hint/usage drift ({} findings):\n{}", bad.len(), bad.join("\n"));
    }

    /// The gateway sanitizer drops a test module in the MIDDLE of a file
    /// and keeps scanning after it.
    #[test]
    fn gateway_sanitizer_skips_mid_file_test_modules_only() {
        let src = "fn a() { x.investigate(\"noo one\") }\n#[cfg(test)]\nmod t {\n    fn f() { \"`noo bogus`\"; }\n}\nfn b() { x.investigate(\"noo two\") }\n";
        let clean = sanitize_gateway(src);
        assert!(clean.contains("noo one") && clean.contains("noo two"), "{clean}");
        assert!(!clean.contains("noo bogus"), "{clean}");
        assert_eq!(clean.lines().count(), src.lines().count(), "line numbers are kept");
    }

    /// Writes the full report to the scratchpad path the task asked for.
    /// Run with:
    ///   cargo test --offline --bin noo hint_lint -- --ignored --nocapture
    #[test]
    #[ignore]
    fn write_hint_report() {
        let hints = all_hints();
        let mut shape_counts: std::collections::BTreeMap<&str, usize> = Default::default();
        for h in &hints {
            let s = match h.shape {
                Shape::TupleOrSome => "a (tuple/Some)",
                Shape::Helper => "c (ui::hint helper)",
                Shape::Backtick => "b (backtick mention)",
            };
            *shape_counts.entry(s).or_default() += 1;
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut warns: Vec<Finding> = Vec::new();
        let mut unparsed: std::collections::BTreeSet<(String, String)> = Default::default();
        let mut allow_hit = vec![false; ALLOWED.len()];
        for h in &hints {
            for cmd in normalize_hint(&h.text) {
                let (verdict, syntax) = check_one(&cmd);
                match verdict {
                    Verdict::Ok | Verdict::GroupOk => {}
                    Verdict::Unparsed => {
                        unparsed.insert((cmd.join(" "), syntax.unwrap_or("").to_string()));
                    }
                    Verdict::Warn(k) => warns.push(Finding {
                        file: h.file.clone(),
                        line: h.line,
                        kind: k,
                        text: h.text.clone(),
                        synopsis: syntax.unwrap_or("").to_string(),
                    }),
                    Verdict::Mismatch(k) => {
                        if is_allowed(&h.file, &h.text, &mut allow_hit) {
                            continue;
                        }
                        findings.push(Finding {
                            file: h.file.clone(),
                            line: h.line,
                            kind: k,
                            text: h.text.clone(),
                            synopsis: syntax.unwrap_or("").to_string(),
                        });
                    }
                }
            }
        }

        let mut by_kind: std::collections::BTreeMap<&str, usize> = Default::default();
        for f in &findings {
            *by_kind.entry(f.kind.label()).or_default() += 1;
        }
        let mut by_file: std::collections::BTreeMap<&str, usize> = Default::default();
        for f in &findings {
            *by_file.entry(f.file.as_str()).or_default() += 1;
        }
        let mut top_files: Vec<(&str, usize)> = by_file.into_iter().collect();
        top_files.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

        let mut out = String::new();
        out.push_str("# Hint/usage mismatch report\n\n");
        out.push_str("Generated by `noo-cli/src/hint_lint.rs::write_hint_report`.\n\n");
        out.push_str("## Extraction counts by shape\n\n");
        for (k, v) in &shape_counts {
            out.push_str(&format!("- shape {k}: {v}\n"));
        }
        out.push_str(&format!("- total hints extracted: {}\n\n", hints.len()));

        out.push_str("## Mismatches by kind (asserted empty by `every_suggested_command_parses`)\n\n");
        if by_kind.is_empty() {
            out.push_str("(none)\n\n");
        }
        for (k, v) in &by_kind {
            out.push_str(&format!("- {k}: {v}\n"));
        }
        out.push('\n');

        out.push_str("## Top files by mismatch count\n\n");
        for (f, n) in top_files.iter().take(20) {
            out.push_str(&format!("- {f}: {n}\n"));
        }
        out.push('\n');

        out.push_str("## All mismatches\n\n");
        let mut sorted = findings.clone();
        sorted.sort_by(|a, b| (a.file.as_str(), a.line).cmp(&(b.file.as_str(), b.line)));
        for f in &sorted {
            out.push_str(&format!(
                "- {}:{}  {}  \"{}\"  — synopsis: {}\n",
                f.file,
                f.line,
                f.kind.label(),
                f.text,
                f.synopsis
            ));
        }
        out.push('\n');

        out.push_str(&format!(
            "## Soft `missing-required` warnings ({}; not asserted)\n\n",
            warns.len()
        ));
        let mut wsorted = warns.clone();
        wsorted.sort_by(|a, b| (a.file.as_str(), a.line).cmp(&(b.file.as_str(), b.line)));
        for w in wsorted.iter().take(200) {
            out.push_str(&format!("- {}:{}  \"{}\"  — synopsis: {}\n", w.file, w.line, w.text, w.synopsis));
        }
        out.push('\n');

        out.push_str(&format!("## `unparsed-synopsis` rows ({})\n\n", unparsed.len()));
        for (words, syn) in &unparsed {
            out.push_str(&format!("- `{words}` — synopsis: `{syn}`\n"));
        }
        out.push('\n');

        out.push_str("## Caveats\n\n");
        out.push_str("- A format placeholder (`{args}`, `<node>`) counts as exactly ONE value slot; a placeholder that can expand to several real tokens (e.g. `{args}` standing in for a whole flag list) may make a hint look correct when the expansion would not be.\n");
        out.push_str("- Inline trailing `//` comments on live code lines are not stripped (only whole-line comments are); none observed to matter in this crate today.\n");
        out.push_str("- Multi-line string literals (a `format!(` call whose literal itself wraps mid-quote) are not extracted; every hint literal in this crate is single-line.\n");
        out.push_str(&format!("- {} ALLOWED entries; all currently unused (empty list).\n", ALLOWED.len()));

        // `HINT_LINT_REPORT_PATH` lets a caller (or an agent's own
        // session-scoped scratchpad) pick where this lands; the fallback is
        // a fixed, non-session-specific path so this test-only tool never
        // bakes a particular run's temp directory into the source tree.
        let path = std::env::var("HINT_LINT_REPORT_PATH")
            .unwrap_or_else(|_| std::env::temp_dir().join("hint-mismatches.md").to_string_lossy().to_string());
        if let Some(parent) = Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, &out).unwrap_or_else(|e| panic!("hint_lint: cannot write report to {path}: {e}"));
        println!("wrote report to {path} ({} findings, {} warnings, {} unparsed rows)", findings.len(), warns.len(), unparsed.len());
    }
}


