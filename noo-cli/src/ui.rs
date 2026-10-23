// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Human-facing output: the ONE place in the crate that emits an escape
//! sequence or a box-drawing character. Implements `CLI_STYLE_GUIDE.md`
//! (revision 2) — read that first; this file follows it, never the other
//! way round.
//!
//! Terminal first: narration (steps, confirmations, guidance) prints to
//! STDOUT so a redirect captures everything a person saw. `--quiet` keeps
//! only captured values; `--json` keeps only the JSON. Errors are STDERR
//! in every mode. Progress rewriting is stderr and TTY-only.
//!
//! Case is applied here (headers/sections/labels Title Case, columns
//! UPPERCASE, state words Title Case) so callers pass natural text.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

// ── mode ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Auto,
    Always,
    Never,
}

impl Mode {
    /// Parse a `--color` value. Anything unrecognised is `None` so the
    /// caller can report a usage error instead of guessing.
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "auto" => Some(Mode::Auto),
            "always" | "yes" | "force" => Some(Mode::Always),
            "never" | "no" | "none" => Some(Mode::Never),
            _ => None,
        }
    }
}

const REQ_AUTO: u8 = 0;
const REQ_ALWAYS: u8 = 1;
const REQ_NEVER: u8 = 2;

static REQUESTED: AtomicU8 = AtomicU8::new(REQ_AUTO);
static QUIET: AtomicBool = AtomicBool::new(false);
/// Under `--quiet`, fd 1 is pointed at /dev/null and the ORIGINAL stdout
/// is kept here so `value()` can still reach it. Plain `println!` sites
/// across the crate are silenced without touching them.
static VALUE_FD: OnceLock<i32> = OnceLock::new();
static RESOLVED: OnceLock<bool> = OnceLock::new();
static TRUECOLOR: OnceLock<bool> = OnceLock::new();

/// Record the caller's request (`--color`, or `--json`/`--quiet` → `Never`).
/// Must run before the first styled byte; the decision is cached.
pub fn set_mode(m: Mode) {
    let v = match m {
        Mode::Auto => REQ_AUTO,
        Mode::Always => REQ_ALWAYS,
        Mode::Never => REQ_NEVER,
    };
    REQUESTED.store(v, Ordering::Relaxed);
}

/// `--json`: narration printers become no-ops and styling is off. The
/// caller still owns stdout for its JSON value.
pub fn set_silent(on: bool) {
    QUIET.store(on, Ordering::Relaxed);
    if on {
        set_mode(Mode::Never);
    }
}

/// `--quiet`: everything `set_silent` does, PLUS fd 1 is redirected to
/// /dev/null so every plain `println!` in the crate is silenced centrally;
/// the original stdout is saved for `value()`. Errors (stderr) untouched.
pub fn set_quiet(on: bool) {
    set_silent(on);
    if !on || VALUE_FD.get().is_some() {
        return;
    }
    // SAFETY: plain fd juggling on our own process; failures leave stdout
    // as it was (narration then leaks through, which is the lesser evil).
    unsafe {
        let saved = libc::dup(1);
        if saved < 0 {
            return;
        }
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if devnull >= 0 {
            libc::dup2(devnull, 1);
            libc::close(devnull);
        }
        let _ = VALUE_FD.set(saved);
    }
}

pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

fn resolve_from_env() -> bool {
    match REQUESTED.load(Ordering::Relaxed) {
        REQ_ALWAYS => return true,
        REQ_NEVER => return false,
        _ => {}
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if let Some(v) = std::env::var_os("CLICOLOR_FORCE") {
        if v != "0" {
            return true;
        }
    }
    // Persisted preference (`noo config set cli '{"color":"never"}'`), below
    // the explicit env signals and above the terminal probe.
    if let Some(m) = pref_color() {
        match m {
            Mode::Always => return true,
            Mode::Never => return false,
            Mode::Auto => {}
        }
    }
    if std::env::var_os("TERM").map(|t| t == "dumb").unwrap_or(false) {
        return false;
    }
    std::io::stdout().is_terminal()
}

/// `~/.config/mesh/cli.json` — per-user CLI preferences. Only `color` so
/// far. Read once; a missing or malformed file is "no preference".
pub fn prefs_path() -> std::path::PathBuf {
    crate::credentials::credentials_path().with_file_name("cli.json")
}

pub fn read_prefs() -> serde_json::Value {
    std::fs::read_to_string(prefs_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(serde_json::Value::Null)
}

fn pref_color() -> Option<Mode> {
    read_prefs()["color"].as_str().and_then(Mode::parse)
}

/// Is styling on for this process? Resolved once, then cached.
pub fn styled() -> bool {
    *RESOLVED.get_or_init(resolve_from_env)
}

/// Brand truecolour, or the 16-colour mapping? `COLORTERM` is the
/// advertised capability (Windows Terminal, iTerm, VS Code, GNOME
/// Terminal, Alacritty, kitty all set it). `--color=always` alone does not
/// imply truecolour.
pub fn truecolor() -> bool {
    *TRUECOLOR.get_or_init(|| {
        std::env::var("COLORTERM")
            .map(|v| v == "truecolor" || v == "24bit")
            .unwrap_or(false)
    })
}

// ── tokens (§4) ─────────────────────────────────────────────────────────

/// Slate palette, dark-theme values (pai-mesh-ui `packages/tokens`).
const BRAND_RGB: (u8, u8, u8) = (0x5f, 0x8f, 0xd0);
const GOOD_RGB: (u8, u8, u8) = (0x46, 0xc0, 0x8a);
const WARN_RGB: (u8, u8, u8) = (0xe0, 0xa2, 0x4a);
const BAD_RGB: (u8, u8, u8) = (0xe5, 0x67, 0x5a);
const MUTED_RGB: (u8, u8, u8) = (0x89, 0x93, 0xa6);

/// Crate-visible for the onboarding console frontend, which keeps its own
/// finer-grained palette. Command code uses the named tokens below.
pub(crate) fn paint(code: &str, s: &str) -> String {
    if styled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn colour(rgb: (u8, u8, u8), basic: &str, s: &str) -> String {
    if truecolor() {
        paint(&format!("38;2;{};{};{}", rgb.0, rgb.1, rgb.2), s)
    } else {
        paint(basic, s)
    }
}

/// header title, section markers, step/hint glyphs, command names, wordmark
pub fn brand(s: &str) -> String {
    colour(BRAND_RGB, "34", s)
}
/// healthy state, success glyph, `Running`, `Verified`
pub fn good(s: &str) -> String {
    colour(GOOD_RGB, "32", s)
}
/// degraded state, warning glyph, `Stale`, `Pending`, dry-run
pub fn warn(s: &str) -> String {
    colour(WARN_RGB, "33", s)
}
/// failed state, error glyph, `Down`, `Unreachable`
pub fn bad(s: &str) -> String {
    colour(BAD_RGB, "31", s)
}
/// the one value the eye should land on, key-value labels
pub fn emph(s: &str) -> String {
    paint("1", s)
}
/// secondary detail, ids, timestamps, explanations, rules and box lines
pub fn muted(s: &str) -> String {
    if truecolor() {
        colour(MUTED_RGB, "2", s)
    } else {
        paint("2", s)
    }
}
/// command names and flags quoted in prose or hints — brand colour
pub fn cmd(s: &str) -> String {
    brand(s)
}
/// Revision-1 names, kept so call sites read naturally.
pub fn ok(s: &str) -> String {
    good(s)
}
pub fn err(s: &str) -> String {
    bad(s)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glyph {
    Ok,
    Err,
    Warn,
    Step,
    Bullet,
    Section,
    Hint,
    /// A risk the person has accepted on the record: not a pass, not a warning.
    Accepted,
}

impl Glyph {
    fn raw(self) -> &'static str {
        if styled() {
            match self {
                Glyph::Ok => "✓",
                Glyph::Err => "✗",
                Glyph::Warn => "!",
                Glyph::Step => "→",
                Glyph::Bullet => "•",
                Glyph::Section => "◆",
                Glyph::Hint => "▸",
                Glyph::Accepted => "◇",
            }
        } else {
            match self {
                Glyph::Ok => "+",
                Glyph::Err => "x",
                Glyph::Warn => "!",
                Glyph::Step => ">",
                Glyph::Bullet => "-",
                Glyph::Section => "#",
                Glyph::Hint => ">",
                Glyph::Accepted => "~",
            }
        }
    }
}

/// The glyph, coloured per its meaning.
pub fn glyph(g: Glyph) -> String {
    let s = g.raw();
    match g {
        Glyph::Ok => good(s),
        Glyph::Err => bad(s),
        Glyph::Warn => warn(s),
        Glyph::Step | Glyph::Section | Glyph::Hint => brand(s),
        Glyph::Bullet => s.to_string(),
        Glyph::Accepted => warn(s),
    }
}

/// Glyph as a table cell. Every glyph is one column wide in both modes
/// (single-character fallbacks), so this is `glyph` — kept as a named
/// function because table rows read better with it.
pub fn glyph_cell(g: Glyph) -> String {
    glyph(g)
}

/// Missing value: `—` styled, `-` plain. Never empty, never `null`.
pub fn dash() -> &'static str {
    if styled() { "—" } else { "-" }
}

// ── case helpers (§4 "Case") ────────────────────────────────────────────

fn capitalize_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Title Case: first letter of each word upper, the rest untouched (so
/// `paired CLI` → `Paired CLI`, `docker host plane` → `Docker Host Plane`).
fn title_case(s: &str) -> String {
    s.split(' ')
        .map(capitalize_first)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Colour a state word per the guide's state table (§4), Title-cased.
/// Unknown words are capitalised but unstyled — add new states here.
pub fn state(word: &str) -> String {
    let w = capitalize_first(word);
    match word.to_ascii_lowercase().as_str() {
        "running" | "healthy" | "ok" | "done" | "verified" | "connected" | "online" | "up to date"
        | "fired"
        | "no change" | "ready" | "active" | "enabled" | "applied" | "in-sync" | "in sync" => {
            good(&w)
        }
        "degraded" | "stale" | "pending" | "skipped" | "dry-run" | "warning" | "not reported"
        | "queued" | "paused" | "expiring soon" | "unknown" | "would" => warn(&w),
        "stopped" | "unreachable" | "down" | "failed" | "error" | "offline" | "damaged"
        | "expired" | "cancelled" | "dead" | "exited" | "disabled" | "revoked" => bad(&w),
        _ => w,
    }
}

/// A count from a gateway payload, for a status/stat row or table cell.
///
/// Three answers, not one: a JSON number renders as itself; a key that is
/// MISSING, null, or not a number (a string, a bool, an object) renders as
/// "not reported". A gateway that omits or renames a field must not print
/// "documents 0" with exit 0 (i191 D5): absence is what an older or
/// diverged peer looks like, and zero is a claim. Use this for rendering
/// only; arithmetic, paging and exit-code decisions keep their own handling.
pub fn count(v: &serde_json::Value, key: &str) -> String {
    match &v[key] {
        serde_json::Value::Number(n) => n.to_string(),
        _ => state("not reported"),
    }
}

// ── layout (§5) ─────────────────────────────────────────────────────────

/// Layout width: the terminal width, capped so a very wide terminal does
/// not stretch the header box across the whole screen.
fn layout_width() -> usize {
    crate::commands::term_width().min(100)
}

fn hline(n: usize) -> String {
    if styled() { "─".repeat(n) } else { "-".repeat(n) }
}

/// A muted rule the layout width.
pub fn rule() -> String {
    muted(&hline(layout_width()))
}

/// The wordmark for interactive entry points (§5). Empty string unless
/// styling is on, so callers can `print!` it unconditionally.
pub fn wordmark(version: &str) -> String {
    if !styled() {
        return String::new();
    }
    const ART: [&str; 6] = [
        " ███╗   ██╗ ██████╗  ██████╗ ███╗   ███╗███████╗███████╗██╗  ██╗",
        " ████╗  ██║██╔═══██╗██╔═══██╗████╗ ████║██╔════╝██╔════╝██║  ██║",
        " ██╔██╗ ██║██║   ██║██║   ██║██╔████╔██║█████╗  ███████╗███████║",
        " ██║╚██╗██║██║   ██║██║   ██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║",
        " ██║ ╚████║╚██████╔╝╚██████╔╝██║ ╚═╝ ██║███████╗███████║██║  ██║",
        " ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝",
    ];
    let mut out = String::new();
    for l in ART {
        out.push_str(&brand(l));
        out.push('\n');
    }
    out.push_str(&muted(&format!(" local-first AI agent mesh · noo {version}")));
    out.push('\n');
    out
}

/// First block of a query command: a light box the layout width, title
/// in brand bold on the left, muted detail on the right.
pub fn header(title: &str, right: Option<&str>) -> String {
    header_box(&title_case(title), right)
}

/// `header` with the title used verbatim — for titles that ARE a command
/// (`noo cluster`) or an acronym, where Title Case would be wrong.
pub fn header_as_is(title: &str, right: Option<&str>) -> String {
    header_box(title, right)
}

fn header_box(title: &str, right: Option<&str>) -> String {
    let w = layout_width();
    let inner = w.saturating_sub(2); // between the two verticals
    let title = title.to_string();
    // " Title" ... "right " — the right side yields to the box: truncate
    // it with an ellipsis rather than overflow the frame.
    let room = inner.saturating_sub(1 + title.chars().count() + 1 + 2);
    let right = match right {
        Some(r) if r.chars().count() > room => crate::commands::truncate(r, room),
        Some(r) => r.to_string(),
        None => String::new(),
    };
    let used = 1 + title.chars().count() + right.chars().count() + 1;
    let gap = if used + 1 > inner { 1 } else { inner - used };
    let (tl, tr, bl, br, v) = if styled() {
        ("┌", "┐", "└", "┘", "│")
    } else {
        ("+", "+", "+", "+", "|")
    };
    let top = muted(&format!("{tl}{}{tr}", hline(inner)));
    let bottom = muted(&format!("{bl}{}{br}", hline(inner)));
    let mid = format!(
        "{} {}{}{} {}",
        muted(v),
        emph(&brand(&title)),
        " ".repeat(gap),
        muted(&right),
        muted(v)
    );
    format!("{top}\n{mid}\n{bottom}")
}

/// `◆ Label` in bold Title Case on its own line, preceded by one blank
/// line, followed by a muted rule.
pub fn section(label: &str) -> String {
    format!("\n{} {}\n{}", glyph(Glyph::Section), emph(&title_case(label)), rule())
}

/// Key-value block: bold Title Case labels padded to the longest, two-space
/// gutter, two-space indent.
pub fn kv(rows: &[(&str, String)]) -> String {
    kv_block(rows.iter().map(|(k, _)| title_case(k)).collect(), rows)
}

/// `kv` with the keys printed exactly as given: for keys that are DATA — an
/// identifier the operator typed or will type back (a class alias, a node id,
/// a model name) — not a label. `default` must read `default`, not `Default`.
pub fn kv_verbatim(rows: &[(&str, String)]) -> String {
    kv_block(rows.iter().map(|(k, _)| k.to_string()).collect(), rows)
}

fn kv_block(labels: Vec<String>, rows: &[(&str, String)]) -> String {
    let w = labels.iter().map(|k| k.chars().count()).max().unwrap_or(0);
    let mut out = String::new();
    for (label, (_, v)) in labels.iter().zip(rows) {
        let pad = w - label.chars().count();
        out.push_str(&format!("  {}{}  {v}\n", emph(label), " ".repeat(pad)));
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

pub struct Col {
    pub name: &'static str,
    pub align: Align,
}

impl Col {
    pub const fn left(name: &'static str) -> Col {
        Col { name, align: Align::Left }
    }
    pub const fn right(name: &'static str) -> Col {
        Col { name, align: Align::Right }
    }
}

/// Visible width of a cell, ignoring escape sequences.
pub(crate) fn visible_width(s: &str) -> usize {
    let mut w = 0;
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c.is_ascii_alphabetic() {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            w += 1;
        }
    }
    w
}

/// Padded table: two-space indent, UPPERCASE muted column names, a muted
/// rule under them, two-space gutters, right-aligned numeric columns. The
/// last column truncates to the terminal width; rows never wrap. Empty
/// cells print as `dash()`.
pub fn table(cols: &[Col], rows: &[Vec<String>]) -> String {
    let n = cols.len();
    let dash = dash().to_string();
    let cell = |r: &Vec<String>, i: usize| -> String {
        match r.get(i) {
            Some(s) if !s.is_empty() => s.clone(),
            _ => dash.clone(),
        }
    };
    let names: Vec<String> = cols.iter().map(|c| c.name.to_ascii_uppercase()).collect();
    let mut widths: Vec<usize> = names.iter().map(|c| c.chars().count()).collect();
    for r in rows {
        for (i, w) in widths.iter_mut().enumerate() {
            *w = (*w).max(visible_width(&cell(r, i)));
        }
    }
    let indent = "  ";
    let gutter = "  ";
    let max_w = crate::commands::term_width();
    let fmt_row = |cells: Vec<String>, header: bool| -> String {
        let mut line = String::from(indent);
        for (i, c) in cells.iter().enumerate() {
            let last = i + 1 == n;
            let pad = widths[i].saturating_sub(visible_width(c));
            let text = if header { muted(c) } else { c.clone() };
            match cols[i].align {
                Align::Left => {
                    line.push_str(&text);
                    if !last {
                        line.push_str(&" ".repeat(pad));
                    }
                }
                Align::Right => {
                    line.push_str(&" ".repeat(pad));
                    line.push_str(&text);
                }
            }
            if !last {
                line.push_str(gutter);
            }
        }
        if !line.contains('\x1b') {
            line = crate::commands::truncate(&line, max_w);
        }
        line
    };
    let table_w = widths.iter().sum::<usize>() + gutter.len() * n.saturating_sub(1);
    let mut out = fmt_row(names, true);
    out.push('\n');
    out.push_str(indent);
    out.push_str(&muted(&hline(table_w.min(max_w.saturating_sub(indent.len())))));
    out.push('\n');
    for r in rows {
        out.push_str(&fmt_row((0..n).map(|i| cell(r, i)).collect(), false));
        out.push('\n');
    }
    out
}

/// Sentence-case a message unless it opens with a name: the CLI's own
/// name (`noo …`), a node/host/user id (`node-1: …`, `user@node-1`), a path,
/// a version, or anything with digits or punctuation in its first word.
/// Those are identifiers and must print as typed (`Node-1:` and `Noo
/// cluster` both appeared in operator transcripts, 2026-09-03).
fn sentence_case(msg: &str) -> String {
    let first = msg.split(' ').next().unwrap_or("");
    let is_identifier = first == "noo"
        || first.chars().any(|c| c.is_ascii_digit() || matches!(c, ':' | '@' | '/' | '.' | '_' | '=' | '-' | '\''));
    if is_identifier { msg.to_string() } else { capitalize_first(msg) }
}

/// `✓ Message` — glyph, space, sentence-cased message (names kept as is).
pub fn status_line(g: Glyph, msg: &str) -> String {
    format!("{} {}", glyph(g), sentence_case(msg))
}

/// `▸ <command>` — one guidance line.
pub fn hint(command: &str) -> String {
    format!("{} {}", glyph(Glyph::Hint), cmd(command))
}

/// OSC 8 hyperlink: clickable in styled mode on terminals that support it
/// (Windows Terminal, iTerm, VS Code, GNOME Terminal, kitty, WezTerm);
/// plain text otherwise. Terminals without OSC 8 ignore the sequence.
pub fn link(url: &str, label: &str) -> String {
    if styled() {
        format!("\x1b]8;;{url}\x1b\\{label}\x1b]8;;\x1b\\")
    } else if label == url {
        url.to_string()
    } else {
        format!("{label} ({url})")
    }
}

/// Wrap every `http(s)://…` token in a line as a hyperlink.
fn autolink(text: &str) -> String {
    text.split(' ')
        .map(|w| {
            let trimmed = w.trim_end_matches([',', '.', ')', ';']);
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                let tail = &w[trimmed.len()..];
                format!("{}{tail}", link(trimmed, trimmed))
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A muted explanation line, indented under a hint or bullet. URLs in it
/// are clickable in styled mode.
pub fn note(text: &str) -> String {
    format!("    {}", muted(&autolink(text)))
}

// ── rhythm (§5 "Rhythm") ────────────────────────────────────────────────

/// `◆ Phase` for a multi-phase mutation — a section, named for intent.
pub fn phase(label: &str) -> String {
    section(label)
}

/// Muted per-item label (`  node-1`) that the item's sub-steps sit under.
pub fn item(label: &str) -> String {
    format!("  {}", muted(label))
}

/// Indent an already-rendered line two spaces (sub-step under a parent).
pub fn sub(line: &str) -> String {
    format!("  {line}")
}

/// Blank line, then `✓ msg` — closes a phase or the whole mutation.
pub fn close_done(msg: &str) {
    if !quiet() {
        println!();
        done(msg);
    }
}
/// Blank line, then `! msg`.
pub fn close_warned(msg: &str) {
    if !quiet() {
        println!();
        warned(msg);
    }
}
/// Blank line (stdout), then `✗ msg` on stderr — the mutation failed.
pub fn close_failed(msg: &str, hint_cmd: Option<&str>) {
    if !quiet() {
        println!();
    }
    failed(msg, hint_cmd);
}

/// Frame a child process's output: a muted `label` line, then each line
/// indented four spaces in muted. Empty output prints nothing.
pub fn capture(label: &str, text: &str) {
    if quiet() || text.trim().is_empty() {
        return;
    }
    println!("    {}", muted(label));
    for l in text.lines() {
        println!("      {}", muted(l.trim_end()));
    }
}

/// A poll with one live line. On a TTY the `→` line rewrites in place
/// with a spinner and the elapsed time; off a TTY it prints the `→` line
/// once and then one `still waiting (Nm)` line per minute. `tick()` is
/// called from the caller's own loop with the elapsed seconds.
pub struct Poll {
    msg: String,
    live: bool,
    last_minute: u64,
    frame: usize,
    /// Two-space indent when the poll sits under an `item` label.
    indent: &'static str,
}

impl Poll {
    pub fn start(msg: &str) -> Poll {
        Poll::begin(msg, "")
    }

    /// A poll under an `item` label: the `→` line and its outcome are
    /// indented like the item's other sub-steps.
    pub fn start_under(msg: &str) -> Poll {
        Poll::begin(msg, "  ")
    }

    fn begin(msg: &str, indent: &'static str) -> Poll {
        let live = !quiet() && styled() && stderr_is_tty();
        if !live && !quiet() {
            println!("{indent}{}", status_line(Glyph::Step, msg));
        }
        Poll { msg: msg.to_string(), live, last_minute: 0, frame: 0, indent }
    }

    pub fn tick(&mut self, elapsed_secs: u64) {
        if quiet() {
            return;
        }
        if self.live {
            const FRAMES: [&str; 4] = ["⠋", "⠙", "⠸", "⠴"];
            let f = FRAMES[self.frame % FRAMES.len()];
            self.frame += 1;
            let clock = format!("{}:{:02}", elapsed_secs / 60, elapsed_secs % 60);
            rewrite_line(&format!(
                "{}{} {} {}  {}",
                self.indent,
                brand(f),
                glyph(Glyph::Step),
                sentence_case(&self.msg),
                muted(&clock)
            ));
        } else {
            let minute = elapsed_secs / 60;
            if minute > self.last_minute {
                self.last_minute = minute;
                println!("{}  {}", self.indent, muted(&format!("still waiting ({minute}m)")));
            }
        }
    }

    fn end(&mut self) {
        if self.live {
            clear_line();
            self.live = false;
        }
    }

    pub fn done(mut self, msg: &str) {
        self.end();
        if !quiet() {
            println!("{}{}", self.indent, status_line(Glyph::Ok, msg));
        }
    }
    pub fn warned(mut self, msg: &str) {
        self.end();
        if !quiet() {
            println!("{}{}", self.indent, status_line(Glyph::Warn, msg));
        }
    }
    /// Documented outcome (guide §8); callers so far end a poll with
    /// `close_failed` after dropping it, hence the allow.
    #[allow(dead_code)]
    pub fn failed(mut self, msg: &str, hint_cmd: Option<&str>) {
        self.end();
        failed(msg, hint_cmd);
    }
}

impl Drop for Poll {
    fn drop(&mut self) {
        self.end();
    }
}

// ── interactive-only line rewriting (stderr, TTY only) ──────────────────

const CLEAR_EOL: &str = "\x1b[K";

/// Is stderr a TTY? Progress rewriting requires it.
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Rewrite the current stderr line in place (progress, spinner frames).
/// Caller has checked `stderr_is_tty()`.
///
/// The frame is cut to one row short of the terminal width: `\r` only
/// returns to the start of the row the cursor is on, so a frame that wraps
/// leaves every earlier frame's first row behind (a long "waiting for <node>
/// to pull, apply and report …" line repeated across an 80-column terminal).
pub fn rewrite_line(s: &str) {
    use std::io::Write as _;
    let fitted = fit_line(s, crate::commands::term_width().saturating_sub(1));
    eprint!("\r{fitted}{CLEAR_EOL}");
    let _ = std::io::stderr().flush();
}

/// `s` cut to at most `max` visible columns, escape sequences kept and not
/// counted. A cut line ends in `…` and a colour reset, so a style opened
/// before the cut does not bleed into the next line.
pub(crate) fn fit_line(s: &str, max: usize) -> String {
    if visible_width(s) <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out = String::with_capacity(s.len());
    let (mut w, mut in_esc) = (0usize, false);
    for c in s.chars() {
        if in_esc {
            out.push(c);
            if c.is_ascii_alphabetic() {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
            out.push(c);
        } else if w < keep {
            out.push(c);
            w += 1;
        }
    }
    if max > 0 {
        out.push('…');
    }
    if out.contains('\x1b') {
        out.push_str("\x1b[0m");
    }
    out
}

/// Clear the in-place line so the next normal print starts clean.
pub fn clear_line() {
    use std::io::Write as _;
    eprint!("\r{CLEAR_EOL}");
    let _ = std::io::stderr().flush();
}

// ── printers ────────────────────────────────────────────────────────────
// Narration → stdout, suppressed by --quiet/--json. Errors → stderr, always.

/// `→ msg` — a step is starting.
pub fn step(msg: &str) {
    if !quiet() {
        println!("{}", status_line(Glyph::Step, msg));
    }
}
/// `✓ msg` — a step or the whole mutation succeeded.
pub fn done(msg: &str) {
    if !quiet() {
        println!("{}", status_line(Glyph::Ok, msg));
    }
}
/// `! msg` — degraded but continuing.
pub fn warned(msg: &str) {
    if !quiet() {
        println!("{}", status_line(Glyph::Warn, msg));
    }
}
/// Guidance block: a rule, then `▸ cmd` + muted why for each entry.
/// Empty `why` prints just the command line.
pub fn guide(entries: &[(&str, &str)]) {
    if quiet() || entries.is_empty() {
        return;
    }
    println!("{}", rule());
    for (c, why) in entries {
        println!("{}", hint(c));
        if !why.is_empty() {
            println!("{}", note(why));
        }
    }
}
/// The captured value: printed plain on stdout in every mode except
/// `--json` (the caller owns the JSON path). This is what `--quiet` keeps.
pub fn value(text: &str) {
    use std::io::Write as _;
    match VALUE_FD.get() {
        Some(&fd) => {
            let line = format!("{text}\n");
            let bytes = line.as_bytes();
            let mut off = 0usize;
            while off < bytes.len() {
                // SAFETY: fd is a dup of our original stdout, kept open for
                // the process lifetime.
                let n = unsafe { libc::write(fd, bytes[off..].as_ptr() as *const _, bytes.len() - off) };
                if n <= 0 {
                    break;
                }
                off += n as usize;
            }
        }
        None => {
            println!("{text}");
            let _ = std::io::stdout().flush();
        }
    }
}
/// `✗ msg` on stderr, then an optional `▸ hint` line. Never suppressed.
/// Does not exit — `output::fail` does that and calls this.
pub fn failed(msg: &str, hint_cmd: Option<&str>) {
    eprintln!("{}", status_line(Glyph::Err, msg));
    if let Some(h) = hint_cmd {
        eprintln!("{}", hint(h));
    }
}

// ── live steps (§5 "Steps") ─────────────────────────────────────────────

/// A step that is in progress. On an interactive terminal the `→` line is
/// drawn on stderr with a spinner and erased when the step ends, so the
/// stdout record only carries the outcome (`✓`/`✗`). Off a TTY it prints
/// the `→` line on stdout at start, like `step()`. Dropping it without an
/// outcome just stops the spinner.
pub struct Step {
    stop: std::sync::Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    msg: String,
}

impl Step {
    pub fn start(msg: &str) -> Step {
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        if quiet() {
            return Step { stop, handle: None, msg: msg.to_string() };
        }
        if !(styled() && stderr_is_tty()) {
            step(msg);
            return Step { stop, handle: None, msg: msg.to_string() };
        }
        let flag = stop.clone();
        let line = format!("{} {}", glyph(Glyph::Step), sentence_case(msg));
        let handle = std::thread::spawn(move || {
            const FRAMES: [&str; 4] = ["⠋", "⠙", "⠸", "⠴"];
            let mut i = 0usize;
            while !flag.load(Ordering::Relaxed) {
                rewrite_line(&format!("{} {}", brand(FRAMES[i % FRAMES.len()]), line));
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
            clear_line();
        });
        Step { stop, handle: Some(handle), msg: msg.to_string() }
    }

    fn finish(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// `✓ msg` (defaults to the start message).
    pub fn done(mut self, msg: Option<&str>) {
        self.finish();
        done(msg.unwrap_or(&self.msg));
    }
    /// `! msg`.
    pub fn warned(mut self, msg: &str) {
        self.finish();
        warned(msg);
    }
    /// `✗ msg` on stderr (plus optional hint).
    pub fn failed(mut self, msg: &str, hint_cmd: Option<&str>) {
        self.finish();
        failed(msg, hint_cmd);
    }
}

impl Drop for Step {
    fn drop(&mut self) {
        self.finish();
    }
}

// ── multi-line live region (§5 "Rhythm") ────────────────────────────────

/// A block of lines that updates in place, for work over a KNOWN set —
/// four nodes provisioning, seven keys pushing. Every item's state is
/// visible at once instead of one at a time, which is the difference
/// between watching a fleet and watching whichever node happens to be
/// first.
///
/// Off a TTY it degrades to one printed line per state CHANGE, so a log
/// carries the same transitions without any redraw noise. Under `--quiet`
/// it prints nothing at all.
///
/// Cursor discipline, which is why this is safe:
///   - RELATIVE movement only (`\x1b[{n}A`). Absolute positioning breaks
///     the moment the terminal scrolls or is resized.
///   - The cursor is never hidden. Hiding would need signal-proof restore
///     to avoid stranding the operator with an invisible cursor, and the
///     flicker it saves is not worth that.
///   - Width is re-read every frame (`term_width` asks the tty each time),
///     so a resize mid-render reflows instead of corrupting.
pub struct Live {
    labels: Vec<String>,
    states: Vec<String>,
    live: bool,
    drawn: usize,
}

impl Live {
    /// `labels` is the fixed set, in display order. Nothing is drawn until
    /// the first `set`.
    pub fn new(labels: Vec<String>) -> Live {
        let n = labels.len();
        Live {
            labels,
            states: vec![String::new(); n],
            live: !quiet() && styled() && std::io::stdout().is_terminal(),
            drawn: 0,
        }
    }

    /// Update one row. `state` is already-rendered content (glyph, state
    /// word, detail) — this only owns layout and redraw.
    pub fn set(&mut self, index: usize, state: &str) {
        if quiet() || index >= self.states.len() {
            return;
        }
        if self.states[index] == state {
            return; // no transition, nothing to say
        }
        self.states[index] = state.to_string();
        if self.live {
            self.redraw();
        } else {
            // Off a TTY: one line per transition, in the order they happen.
            println!("  {}  {}", self.labels[index], state);
        }
    }

    fn redraw(&mut self) {
        use std::io::Write as _;
        let w = crate::commands::term_width();
        let label_w = self.labels.iter().map(|l| l.chars().count()).max().unwrap_or(0);
        print!("{}", cursor_up(self.drawn));
        for (label, state) in self.labels.iter().zip(&self.states) {
            let pad = label_w - label.chars().count();
            let line = format!("  {label}{}  {state}", " ".repeat(pad));
            // Clear the whole line first: a shorter state must not leave
            // the tail of a longer one behind, which would read as a
            // still-true fragment of a state that has since changed.
            println!("\x1b[2K{}", crate::commands::truncate(&line, w));
        }
        self.drawn = self.labels.len();
        let _ = std::io::stdout().flush();
    }

    /// Leave the final frame on screen and stop owning it.
    pub fn finish(mut self) {
        self.drawn = 0;
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        // The rendered rows stay where they are; we simply stop tracking
        // them. Nothing to restore — the cursor was never hidden and is
        // already below the block.
        self.drawn = 0;
    }
}

/// Move the cursor up `n` lines, or nothing at all for zero.
///
/// Pure and tested because it is the one piece of this that corrupts the
/// display when wrong: emitting `\x1b[0A` moves up one line on some
/// terminals rather than none, so the first frame would overwrite the
/// caller's last line, and an off-by-one on later frames walks the block
/// up the screen a row per update.
fn cursor_up(n: usize) -> String {
    if n == 0 {
        String::new()
    } else {
        format!("\x1b[{n}A")
    }
}

/// A bar for work with a known denominator: `[####----] 3/7`.
///
/// Only for a real count. A bar over an unknown total is a lie the eye
/// reads as progress, which is worse than the spinner it replaced —
/// `Step` and `Poll` remain the honest answer when the end is unknown.
pub fn bar(done: usize, total: usize, width: usize) -> String {
    if total == 0 {
        return String::new();
    }
    let width = width.clamp(4, 40);
    let filled = (done.min(total) * width) / total;
    let (full, empty) = if styled() { ("█", "░") } else { ("#", "-") };
    format!(
        "{}{} {}",
        good(&full.repeat(filled)),
        muted(&empty.repeat(width - filled)),
        muted(&format!("{done}/{total}")),
    )
}

// ── --watch (§5) ────────────────────────────────────────────────────────

/// Redraw `render` every `secs` seconds until Ctrl-C. Interactive only:
/// the caller rejects `--watch` under `--json`/`--quiet` or off a TTY.
///
/// Runs in the ALTERNATE SCREEN, like `less` and `htop`: the watch owns a
/// scratch screen and the terminal's scrollback is restored untouched on
/// exit. The first cut cleared the real screen every tick, which both
/// flickered and destroyed whatever the operator had above it — for a
/// command they run to glance at a fleet, eating their scrollback is a
/// poor trade.
///
/// Each frame homes the cursor and clears to end-of-screen rather than
/// clearing first and drawing into the blank, which is what caused the
/// flash: with `2J` the terminal shows an empty screen for the duration of
/// the render.
pub fn watch_loop(secs: u64, mut render: impl FnMut() -> i32) -> i32 {
    let secs = secs.max(1);
    let _screen = AltScreen::enter();
    loop {
        if styled() {
            // Home, then clear from the cursor down as we go.
            print!("\x1b[H");
        }
        let rc = render();
        if styled() {
            // Erase anything the previous frame left below this one — a
            // shorter frame must not leave the tail of a longer one on
            // screen, which reads as stale rows that are still true.
            print!("\x1b[J");
        }
        println!();
        println!("{}", muted(&format!("every {secs}s · Ctrl-C to stop")));
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        if rc != 0 {
            return rc;
        }
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

/// Alternate-screen guard. Entering is a no-op when not styled, so piped
/// and `--json` runs are unaffected.
///
/// Restores on Drop, which covers a normal return and a panic. It does NOT
/// cover SIGINT, whose default action terminates without unwinding — and
/// Ctrl-C is the documented way to leave a watch. `install_restore_hooks`
/// handles that case, and is why this guard alone is not enough.
pub struct AltScreen {
    active: bool,
}

impl AltScreen {
    pub fn enter() -> AltScreen {
        if !styled() {
            return AltScreen { active: false };
        }
        install_restore_hooks();
        ALT_SCREEN_ON.store(true, Ordering::SeqCst);
        print!("\x1b[?1049h");
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        AltScreen { active: true }
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        if self.active {
            leave_alt_screen();
        }
    }
}

static ALT_SCREEN_ON: AtomicBool = AtomicBool::new(false);
static HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);

fn leave_alt_screen() {
    if ALT_SCREEN_ON.swap(false, Ordering::SeqCst) {
        print!("\x1b[?1049l");
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
    }
}

/// Restore terminal state on the paths Drop cannot reach.
///
/// Two of them, and both are ordinary rather than exotic: Ctrl-C out of a
/// `--watch` (SIGINT terminates without unwinding, so no destructor runs)
/// and a kill of a long provisioning run (SIGTERM, same). Leaving the
/// alternate screen active strands the operator on a scratch buffer with
/// their scrollback apparently gone.
///
/// Deliberately does NOT hide the cursor anywhere in this module. Hiding
/// would need this same machinery to be airtight, and the failure — an
/// invisible cursor until the operator types `reset` — is worse than the
/// slight flicker of leaving it visible.
pub fn install_restore_hooks() {
    if HOOKS_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    extern "C" fn restore_and_die(sig: libc::c_int) {
        leave_alt_screen();
        // Re-raise with the default handler so the exit status is the
        // signal's, not a fabricated one: a caller that inspects why we
        // died must still see SIGINT.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
    // SAFETY: installing a handler for two signals on our own process.
    unsafe {
        let handler = restore_and_die as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

/// Parse and strip `--watch [SECS]` / `--watch=SECS` from a command's
/// args. Returns the interval if present. `Err(())` means a bad value.
pub fn take_watch(args: &[String]) -> Result<(Vec<String>, Option<u64>), ()> {
    let mut out = Vec::new();
    let mut watch = None;
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a == "--watch" || a == "-w" {
            let secs = match iter.peek() {
                Some(n) if n.chars().all(|c| c.is_ascii_digit()) => {
                    iter.next().unwrap().parse().map_err(|_| ())?
                }
                _ => 2,
            };
            watch = Some(secs);
        } else if let Some(v) = a.strip_prefix("--watch=") {
            watch = Some(v.parse().map_err(|_| ())?);
        } else {
            out.push(a.clone());
        }
    }
    Ok((out, watch))
}

// ── pager (§5 long output) ──────────────────────────────────────────────

/// The thread draining captured stdout, and its join handle. `None` when no
/// command asked to page.
#[allow(clippy::type_complexity)]
static CAPTURE: std::sync::Mutex<Option<std::thread::JoinHandle<Vec<u8>>>> =
    std::sync::Mutex::new(None);
static PAGER_SAVED_FD: OnceLock<i32> = OnceLock::new();

/// Collect the rest of this process's stdout and, at `pager_finish`, either
/// print it directly or hand it to `$PAGER` — whichever the SIZE calls for.
///
/// It used to dup fd 1 straight onto a running `less -R -F -X` and rely on
/// `-F` ("quit if it fits") to keep a short result from blocking. That cannot
/// work: `-F` only quits when `less` reaches EOF before it paints, and the
/// command holds the pipe open for as long as it runs. So `less` painted two
/// lines, showed `(END)`, and waited for a keypress — which reads as a frozen
/// command, not as a pager. `noo security scan` printing one line of good news
/// looked like a hang on the live controller (2026-09-13), and the operator
/// reported it as one.
///
/// So the decision moves to where the size is actually known: after the output
/// exists. Under the screen height it goes straight to the terminal and no
/// pager is involved at all; over it, `$PAGER` gets the whole text at once and
/// `-F` becomes true again rather than aspirational.
///
/// No-op off a TTY, under --json/--quiet, or when `NOO_PAGER=` / `PAGER=cat`.
/// Called at the top of commands whose output routinely exceeds a screen;
/// `main` calls `pager_finish` after dispatch.
pub fn auto_page() {
    if quiet() || !styled() || !std::io::stdout().is_terminal() {
        return;
    }
    if pager_command().is_none() {
        return;
    }
    // A pipe we own: fd 1 becomes its write end, and a thread drains the read
    // end so a command producing more than a pipe buffer cannot deadlock
    // against a pager that has not started yet.
    let mut fds = [0i32; 2];
    // SAFETY: pipe() writes two fds into an array we own.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return;
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);
    // SAFETY: dup fd 1 to restore later, then point it at the pipe.
    let saved = unsafe { libc::dup(1) };
    if saved < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return;
    }
    // SAFETY: dup2 onto our own fd 1.
    if unsafe { libc::dup2(write_fd, 1) } < 0 {
        unsafe {
            libc::close(saved);
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return;
    }
    // SAFETY: fd 1 is the write end now; this duplicate is not needed.
    unsafe { libc::close(write_fd) };
    let handle = std::thread::spawn(move || {
        use std::io::Read as _;
        // SAFETY: we own read_fd and the File takes ownership of it.
        let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(read_fd) };
        let mut buf = Vec::new();
        let _ = f.read_to_end(&mut buf);
        buf
    });
    let _ = PAGER_SAVED_FD.set(saved);
    *CAPTURE.lock().unwrap() = Some(handle);
}

/// `$PAGER` as a command line, or `None` when the caller asked for no pager.
fn pager_command() -> Option<Vec<String>> {
    let pager = std::env::var("NOO_PAGER")
        .or_else(|_| std::env::var("PAGER"))
        .unwrap_or_else(|_| "less -R -F -X".to_string());
    let pager = pager.trim();
    if pager.is_empty() || pager == "cat" {
        return None;
    }
    Some(pager.split_whitespace().map(str::to_string).collect())
}

/// Does this output need a pager at all?
///
/// Counting RENDERED lines, not bytes: a wide table wraps, and a result that
/// fits on the screen must never be handed to something that waits for a
/// keypress. One line short of the height keeps a prompt visible.
pub(crate) fn needs_pager(text: &str, rows: usize, cols: usize) -> bool {
    let budget = rows.saturating_sub(1).max(1);
    let cols = cols.max(1);
    let mut used = 0usize;
    // A trailing newline ends the last line; it does not begin an empty one.
    // Counting it cost a row and pushed an exactly-fitting result into a pager.
    let body = text.strip_suffix('\n').unwrap_or(text);
    for line in body.split('\n') {
        let width = visible_width(line).max(1);
        used += width.div_ceil(cols);
        if used > budget {
            return true;
        }
    }
    false
}

/// Restore stdout, then emit what was captured: straight to the terminal when
/// it fits, through `$PAGER` when it does not. Safe to call when nothing was
/// captured.
pub fn pager_finish() {
    use std::io::Write as _;
    let Some(handle) = CAPTURE.lock().unwrap().take() else { return };
    let _ = std::io::stdout().flush();
    // Closing fd 1 is what gives the draining thread its EOF; restoring the
    // saved fd does both at once.
    if let Some(&saved) = PAGER_SAVED_FD.get() {
        // SAFETY: restoring our own fd 1 from the dup taken in auto_page.
        unsafe { libc::dup2(saved, 1) };
    }
    let text = handle.join().unwrap_or_default();
    let text = String::from_utf8_lossy(&text).into_owned();
    if text.is_empty() {
        return;
    }
    let (cols, rows) = crate::commands::term_size();
    if !needs_pager(&text, rows, cols) {
        print!("{text}");
        let _ = std::io::stdout().flush();
        return;
    }
    let Some(argv) = pager_command() else {
        print!("{text}");
        let _ = std::io::stdout().flush();
        return;
    };
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).stdin(std::process::Stdio::piped());
    if argv[0] == "less" && std::env::var_os("LESS").is_none() {
        cmd.env("LESS", "-R -F -X");
    }
    let Ok(mut child) = cmd.spawn() else {
        print!("{text}");
        let _ = std::io::stdout().flush();
        return;
    };
    if let Some(mut sin) = child.stdin.take() {
        // The pager gets the WHOLE text and then EOF, which is the condition
        // `-F` needs and never had. A pager that exits early (q on a long
        // listing) closes the pipe, so the write failing is normal.
        let _ = crate::child_stdin::write_child_stdin(&mut sin, text.as_bytes());
    }
    let _ = child.wait();
}

// ── tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn count_renders_numbers_and_calls_everything_else_not_reported() {
        let v = serde_json::json!({"zero": 0, "n": 42, "f": 1.5, "s": "7", "nul": null, "b": true, "o": {"a": 1}});
        assert_eq!(super::count(&v, "zero"), "0", "a real zero is a zero");
        assert_eq!(super::count(&v, "n"), "42");
        assert_eq!(super::count(&v, "f"), "1.5");
        for key in ["missing", "s", "nul", "b", "o"] {
            let c = super::count(&v, key);
            assert_eq!(c, super::state("not reported"), "{key}");
            assert!(c.contains("Not reported") && !c.contains('0'), "{key}: {c}");
        }
        // Not an object at all: still a clean answer, no panic.
        assert_eq!(super::count(&serde_json::json!(null), "x"), super::state("not reported"));
    }

    #[test]
    fn a_progress_frame_never_wraps_the_terminal() {
        let long = "⠙ → Staged — waiting for host3 to pull, apply and report (poked over the bus; its 5-min timer is the fallback)";
        let fitted = super::fit_line(long, 79);
        assert_eq!(super::visible_width(&fitted), 79, "{fitted}");
        assert!(fitted.ends_with('…'));
        assert_eq!(super::fit_line("short", 79), "short");
        let styled = "\x1b[2mwaiting for a very long node name to report back\x1b[0m";
        let cut = super::fit_line(styled, 20);
        assert_eq!(super::visible_width(&cut), 20, "{cut:?}");
        assert!(cut.ends_with("\x1b[0m"), "{cut:?}");
    }

    // ── the pager decision (§5) ─────────────────────────────────────────
    //
    // `less -F` was trusted to keep a short result from blocking and could
    // not: it only quits when it reaches EOF before painting, and the command
    // held the pipe open while it ran. So one line of good news from
    // `noo security scan` sat at `(END)` waiting for a keypress and the
    // operator reported the command as frozen (2026-09-13).

    #[test]
    fn a_one_line_result_never_reaches_a_pager() {
        assert!(!super::needs_pager("✓ No security issues found\n", 40, 120));
    }

    #[test]
    fn output_taller_than_the_screen_does() {
        let long = "row\n".repeat(100);
        assert!(super::needs_pager(&long, 40, 120));
    }

    #[test]
    fn wrapping_counts_as_height_because_the_screen_does_not_care_why() {
        // Ten lines of 400 columns is 40 screen rows at width 100. Counting
        // newlines alone would call this short and then scroll the result off.
        let wide = (0..10).map(|_| "x".repeat(400)).collect::<Vec<_>>().join("\n");
        assert!(super::needs_pager(&wide, 20, 100));
        // The same text on a wide enough terminal fits.
        assert!(!super::needs_pager(&wide, 20, 4000));
    }

    #[test]
    fn colour_codes_do_not_count_towards_the_height() {
        // A coloured short table must not be pushed into a pager by its escape
        // sequences, which occupy no columns.
        let coloured: String = (0..5)
            .map(|_| format!("\x1b[32m{}\x1b[0m\n", "ok".repeat(3)))
            .collect();
        assert!(!super::needs_pager(&coloured, 20, 40));
    }

    #[test]
    fn exactly_one_screen_still_fits_with_a_line_to_spare_for_the_prompt() {
        let rows = 10;
        let nine = "l\n".repeat(rows - 1);
        assert!(!super::needs_pager(&nine, rows, 80));
        let eleven = "l\n".repeat(rows + 1);
        assert!(super::needs_pager(&eleven, rows, 80));
    }

    #[test]
    fn an_absurd_terminal_size_does_not_divide_by_zero() {
        assert!(super::needs_pager("a\nb\nc\n", 0, 0));
    }

    #[test]
    fn asking_for_no_pager_is_honoured() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("NOO_PAGER", "cat");
        assert!(super::pager_command().is_none(), "PAGER=cat means no pager");
        std::env::set_var("NOO_PAGER", "");
        assert!(super::pager_command().is_none(), "an empty pager means no pager");
        std::env::remove_var("NOO_PAGER");
    }

    use super::*;

    /// Width comes from the live environment (`COLUMNS`), which tests set;
    /// cargo runs tests in parallel, so every test that sets it holds this
    /// lock for its duration.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn with_columns(n: &str) -> std::sync::MutexGuard<'static, ()> {
        let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("COLUMNS", n);
        g
    }

    // Mode is process-global and cached; cargo test's stdout is a pipe, so
    // every test here asserts the PLAIN rendering. Escape shapes are
    // covered by `escape_shapes`, which bypasses the cache.

    #[test]
    fn plain_mode_under_cargo_test() {
        assert!(!styled());
        assert_eq!(good("x"), "x");
        assert_eq!(glyph(Glyph::Ok), "+");
        assert_eq!(glyph(Glyph::Err), "x");
        assert_eq!(glyph(Glyph::Warn), "!");
        assert_eq!(glyph(Glyph::Section), "#");
        assert_eq!(glyph(Glyph::Hint), ">");
        assert_eq!(glyph(Glyph::Accepted), "~");
        assert_eq!(dash(), "-");
        assert_eq!(wordmark("0.0.0"), "");
    }

    #[test]
    fn escape_shapes() {
        let basic = format!("\x1b[{}m{}\x1b[0m", "34", "x");
        assert_eq!(basic, "\x1b[34mx\x1b[0m");
        let tc = format!("\x1b[38;2;{};{};{}m{}\x1b[0m", BRAND_RGB.0, BRAND_RGB.1, BRAND_RGB.2, "x");
        assert_eq!(tc, "\x1b[38;2;95;143;208mx\x1b[0m");
        assert_eq!(visible_width(&tc), 1);
        assert_eq!(visible_width("plain"), 5);
    }

    #[test]
    fn mode_parse() {
        assert_eq!(Mode::parse("auto"), Some(Mode::Auto));
        assert_eq!(Mode::parse("always"), Some(Mode::Always));
        assert_eq!(Mode::parse("never"), Some(Mode::Never));
        assert_eq!(Mode::parse("rainbow"), None);
    }

    #[test]
    fn case_helpers() {
        assert_eq!(title_case("docker host plane"), "Docker Host Plane");
        assert_eq!(title_case("paired CLI"), "Paired CLI");
        assert_eq!(capitalize_first("join key minted"), "Join key minted");
        assert_eq!(state("running"), "Running");
        assert_eq!(state("up to date"), "Up to date");
        assert_eq!(state("whatever"), "Whatever");
    }

    #[test]
    fn header_is_a_box() {
        let _g = with_columns("60");
        let h = header("stack", Some("v1 · host8"));
        let lines: Vec<&str> = h.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], format!("+{}+", "-".repeat(58)));
        assert_eq!(lines[2], lines[0]);
        assert!(lines[1].starts_with("| Stack"));
        assert!(lines[1].ends_with("v1 · host8 |"));
        assert_eq!(lines[1].chars().count(), 60);
        assert!(header("x", None).lines().nth(1).unwrap().starts_with("| X"));
    }

    #[test]
    fn header_truncates_long_right_side() {
        let _g = with_columns("40");
        let h = header("x", Some(&"y".repeat(80)));
        for l in h.lines() {
            assert_eq!(l.chars().count(), 40, "{l}");
        }
        assert!(h.contains('…'));
    }

    #[test]
    fn section_has_marker_and_rule() {
        let _g = with_columns("40");
        assert_eq!(section("nodes"), format!("\n# Nodes\n{}", "-".repeat(40)));
    }

    #[test]
    fn kv_title_cases_and_pads() {
        let s = kv(&[("gateway", "x".into()), ("stack tag", "y".into())]);
        assert_eq!(s, "  Gateway    x\n  Stack Tag  y\n");
    }

    #[test]
    fn kv_verbatim_keeps_the_keys_as_given_and_pads() {
        let s = kv_verbatim(&[("default", "x".into()), ("gemma4:12b-any", "y".into())]);
        assert_eq!(s, "  default         x\n  gemma4:12b-any  y\n");
    }

    #[test]
    fn table_uppercases_underlines_aligns() {
        let _g = with_columns("120");
        let cols = [Col::left("id"), Col::right("n"), Col::left("note")];
        let rows = vec![
            vec!["a".into(), "5".into(), "".into()],
            vec!["bbb".into(), "12".into(), "hi".into()],
        ];
        let t = table(&cols, &rows);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "  ID    N  NOTE");
        assert_eq!(lines[1], format!("  {}", "-".repeat(13)));
        assert_eq!(lines[2], "  a     5  -");
        assert_eq!(lines[3], "  bbb  12  hi");
    }

    #[test]
    fn link_and_autolink_plain() {
        assert_eq!(link("https://x.y", "https://x.y"), "https://x.y");
        assert_eq!(link("https://x.y", "docs"), "docs (https://x.y)");
        assert_eq!(autolink("see https://x.y/p, then go"), "see https://x.y/p, then go");
    }

    #[test]
    fn take_watch_parses_forms() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(take_watch(&a(&["--watch"])).unwrap(), (vec![], Some(2)));
        assert_eq!(take_watch(&a(&["--watch", "5", "x"])).unwrap(), (a(&["x"]), Some(5)));
        assert_eq!(take_watch(&a(&["--watch=7"])).unwrap(), (vec![], Some(7)));
        assert_eq!(take_watch(&a(&["x"])).unwrap(), (a(&["x"]), None));
        assert!(take_watch(&a(&["--watch=lots"])).is_err());
    }

    #[test]
    fn rhythm_shapes_plain() {
        let _g = with_columns("40");
        assert_eq!(phase("nodes"), format!("\n# Nodes\n{}", "-".repeat(40)));
        assert_eq!(item("node-1"), "  node-1");
        assert_eq!(sub("> x"), "  > x");
    }

    #[test]
    fn cursor_up_emits_nothing_for_the_first_frame() {
        // The first frame has drawn nothing, so it must not move at all.
        // `\x1b[0A` is NOT a no-op on every terminal — some read it as 1 —
        // and moving up before the first draw would overwrite the line the
        // caller printed above the block.
        assert_eq!(cursor_up(0), "");
        assert_eq!(cursor_up(1), "\x1b[1A");
        assert_eq!(cursor_up(4), "\x1b[4A");
    }

    #[test]
    fn bar_is_only_drawn_for_a_real_denominator() {
        // A bar over an unknown total reads as progress the code cannot
        // actually claim — worse than the spinner it would replace.
        assert_eq!(bar(3, 0, 10), "");
        // plain mode: # filled, - empty, count appended
        assert_eq!(bar(0, 4, 8), "-------- 0/4");
        assert_eq!(bar(2, 4, 8), "####---- 2/4");
        assert_eq!(bar(4, 4, 8), "######## 4/4");
        // done > total cannot overflow the bar
        assert_eq!(bar(9, 4, 8), "######## 9/4");
    }

    #[test]
    fn live_off_a_tty_prints_one_line_per_transition() {
        // cargo test's stdout is a pipe, so Live is in its degraded mode:
        // no redraw, no cursor movement, one line per state CHANGE. A
        // repeated state prints nothing — a log should carry transitions,
        // not a heartbeat.
        let mut l = Live::new(vec!["nodeA".into(), "nodeB".into()]);
        assert!(!l.live, "a pipe must not get the live renderer");
        l.set(0, "delivering");
        l.set(0, "delivering"); // no transition
        assert_eq!(l.states[0], "delivering");
        l.set(1, "done");
        assert_eq!(l.states[1], "done");
        // out-of-range is ignored rather than panicking mid-render
        l.set(99, "nowhere");
    }

    #[test]
    fn status_hint_note_shapes() {
        assert_eq!(status_line(Glyph::Err, "boom happened"), "x Boom happened");
        // identifiers stay as typed
        assert_eq!(status_line(Glyph::Err, "noo cluster place-model did not understand"), "x noo cluster place-model did not understand");
        assert_eq!(status_line(Glyph::Err, "node-1: bundle staged but never fetched"), "x node-1: bundle staged but never fetched");
        assert_eq!(status_line(Glyph::Ok, "user@node-1 reachable"), "+ user@node-1 reachable");
        assert_eq!(status_line(Glyph::Ok, "v0.2.18 pinned"), "+ v0.2.18 pinned");
        assert_eq!(hint("noo health"), "> noo health");
        assert_eq!(note("why"), "    why");
    }

    /// §9 enforcement: only this file may emit an escape sequence or a
    /// box-drawing/marker character inside a string literal, and the
    /// retired ad-hoc markers may not reappear. No allow-list.
    #[test]
    fn nothing_outside_ui_draws() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        assert!(files.len() > 20);

        const RETIRED: &[&str] = &["!(\"== ", "!(\"-- ", "!(\"--- ", "⚠", "🚚", "📦", "⚙", "↻", "🔌", "🧠", "🖥"];
        const DRAWN: &[char] = &['◆', '▸', '┌', '┐', '└', '┘', '│', '─', '█', '╗', '╝'];

        let mut hits = Vec::new();
        for f in &files {
            let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            if rel == "ui.rs" || rel.starts_with("onboard/tui") {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            if src.contains("\\x1b[") || src.contains("\\u{1b}[") {
                hits.push(format!("{rel}: escape sequence"));
            }
            for m in RETIRED {
                if src.contains(m) {
                    hits.push(format!("{rel}: retired marker {m:?}"));
                }
            }
            for (i, line) in src.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") || !t.contains('"') {
                    continue; // comments and non-literal lines may draw rules
                }
                if let Some(c) = DRAWN.iter().find(|c| t.contains(**c)) {
                    hits.push(format!("{rel}:{}: box/marker char {c:?} in a literal", i + 1));
                }
            }
        }
        assert!(hits.is_empty(), "output drawn outside ui.rs:\n{}", hits.join("\n"));
    }

    fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_rs(&p, out);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                out.push(p);
            }
        }
    }
}
