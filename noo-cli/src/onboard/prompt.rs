// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Prompting: the frontend-agnostic [`Asker`] (default application, required
//! re-prompt, y/n parsing, numeric-choice loop) over the [`WizardUi`] prompt
//! seam, plus [`PlainUi`] — the classic console frontend, hand-rolled (no
//! dialoguer dep). PlainUi matches the wizard's historical question style
//! byte-for-byte: default shown in `[brackets]`, empty input takes the
//! default, invalid choices loop. Non-interactive and non-TTY contracts
//! mirror `commands::confirm_destructive`: never block on a pipe, and a
//! required value (no default, no env) with a non-TTY stdin is a hard error.

use std::io::{BufRead as _, Write as _};

use super::event::{PromptKind, PromptRequest, UiEvent, WizardUi};

/// Is stdin a TTY? (agents/pipes are not).
pub fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

/// Is stdout a TTY? (the TUI also needs somewhere to draw).
pub fn stdout_is_tty() -> bool {
    unsafe { libc::isatty(1) == 1 }
}

fn read_line() -> Option<String> {
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).ok()?;
    if n == 0 {
        return None; // EOF
    }
    Some(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Read a line with terminal echo disabled (for secrets). Falls back to a
/// plain read if termios is unavailable.
fn read_line_secret() -> Option<String> {
    let fd = 0;
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let have_termios = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let saved = term;
    if have_termios {
        term.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let out = read_line();
    if have_termios {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        eprintln!(); // the user's Enter wasn't echoed
    }
    out
}

/// A single prompt configuration.
pub struct Prompt<'a> {
    pub label: &'a str,
    pub default: Option<String>,
    pub secret: bool,
    /// If false, the value is required: on a non-TTY with no default this errors.
    pub required: bool,
}

impl<'a> Prompt<'a> {
    pub fn new(label: &'a str) -> Self {
        Prompt { label, default: None, secret: false, required: false }
    }
    pub fn default(mut self, d: impl Into<String>) -> Self {
        let d = d.into();
        self.default = Some(d);
        self
    }
    pub fn secret(mut self) -> Self {
        self.secret = true;
        self
    }
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
}

/// Runtime context for prompting. Frontend-agnostic: the raw read/render is
/// delegated to the [`WizardUi`]; this layer applies defaults, re-prompts on
/// required-but-empty, and parses confirms/choices.
pub struct Asker<'a> {
    pub non_interactive: bool,
    pub ui: &'a dyn WizardUi,
}

impl Asker<'_> {
    /// Ask for a string. Non-interactive → default (or ""). Otherwise the
    /// frontend supplies a raw answer; "" takes the default, and a required
    /// value with no default re-prompts.
    pub fn ask(&self, p: &Prompt) -> String {
        if self.non_interactive {
            return p.default.clone().unwrap_or_default();
        }
        let req = PromptRequest {
            label: p.label.to_string(),
            kind: PromptKind::Text {
                default: p.default.clone(),
                secret: p.secret,
                required: p.required,
            },
        };
        loop {
            let raw = self.ui.prompt(&req);
            if !raw.is_empty() {
                return raw;
            }
            if let Some(d) = &p.default {
                return d.clone();
            }
            if p.required {
                self.ui.emit(UiEvent::Note("(a value is required)".to_string()));
                continue;
            }
            return String::new();
        }
    }

    /// Yes/no confirm. Non-interactive → the default (never blocks).
    pub fn confirm(&self, label: &str, default: bool) -> bool {
        if self.non_interactive {
            return default;
        }
        let req = PromptRequest {
            label: label.to_string(),
            kind: PromptKind::Confirm { default },
        };
        loop {
            let raw = self.ui.prompt(&req);
            let v = raw.trim().to_ascii_lowercase();
            if v.is_empty() {
                return default;
            }
            match v.as_str() {
                "y" | "yes" | "true" | "1" => return true,
                "n" | "no" | "false" | "0" => return false,
                _ => self.ui.emit(UiEvent::Note("please answer y or n".to_string())),
            }
        }
    }

    /// Ask for an integer in `1..=max` (or 0 when `allow_zero`), looping on
    /// invalid input. Returns the parsed choice; default applies on empty.
    pub fn ask_choice(&self, label: &str, default: usize, max: usize, allow_zero: bool) -> usize {
        let p = Prompt::new(label).default(default.to_string());
        loop {
            let raw = self.ask(&p);
            match raw.trim().parse::<usize>() {
                Ok(n) if (allow_zero && n == 0) || (1..=max).contains(&n) => return n,
                _ => {
                    // Frontends that can re-present the question (TUI input
                    // box, web browser) loop; the console falls back to the
                    // default on a non-TTY stdin so a pipe can never hang.
                    if self.non_interactive || !self.ui.can_reprompt() {
                        return default;
                    }
                    self.ui.emit(UiEvent::Note(format!(
                        "enter a number between {} and {max}",
                        if allow_zero { 0 } else { 1 }
                    )));
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// PlainUi — the classic console frontend
// ─────────────────────────────────────────────────────────────────────────

/// The plain-console frontend: wizard output → stdout, prompts/diagnostics →
/// stderr. Renders the event stream in the CLI's own vocabulary
/// (CLI_STYLE_GUIDE.md rev 2.1): each wizard step is a `◆` phase, outcomes
/// are the guide's glyphs indented under it, commands the steps suggest
/// are `▸` hints. Prompt behaviour (defaults, validation, non-TTY rules)
/// is unchanged.
pub struct PlainUi;

/// Consecutive identical progress lines collapse to one — a retry loop
/// that reports "not accepted yet — retrying" every 5s prints it once.
static LAST_PROGRESS: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

impl WizardUi for PlainUi {
    fn run_inherited(&self, argv: &[String]) -> Option<i32> {
        let (cmd, args) = argv.split_first()?;
        std::process::Command::new(cmd)
            .args(args)
            .status()
            .ok()
            .map(|s| s.code().unwrap_or(-1))
    }

    /// The console can only re-present a failed choice on a real TTY.
    fn can_reprompt(&self) -> bool {
        stdin_is_tty()
    }

    /// Print one secret to the terminal the operator is sitting at.
    ///
    /// Same guard as `noo security secrets reveal`, for the same reason:
    /// `noo onboard | tee onboard.log` is a thing people do, and a value
    /// printed into that pipe is in a log file forever. With no terminal this
    /// refuses, and the caller prints the reveal command instead. There is no
    /// `--stdout` equivalent here — nobody deliberately pipes a wizard in
    /// order to capture a passphrase.
    fn reveal_secret(&self, name: &str, value: &str) -> bool {
        if !stdout_is_tty() {
            return false;
        }
        println!();
        println!("  {}", crate::ui::emph(name));
        crate::ui::value(value);
        println!();
        true
    }

    fn emit(&self, ev: UiEvent) {
        use crate::ui::{self, Glyph};
        // Steps author their own case ("Docker: MISSING", "nvidia-smi:
        // missing"), so the glyph is added without `status_line`'s
        // sentence-casing, which would turn tool names into "Nvidia-smi".
        let sub = |g: Glyph, m: &str| println!("  {} {m}", ui::glyph(g));
        match ev {
            UiEvent::StepStart { step, total, title } => {
                *LAST_PROGRESS.lock().unwrap_or_else(|e| e.into_inner()) = String::new();
                println!("{}", ui::phase(&format!("step {step}/{total} · {title}")));
            }
            // Step boundaries are silent on the console: the next phase's
            // leading blank line is the separator.
            UiEvent::StepDone { .. } => {}
            // A step's suggested command ("noo stack status — why") is a
            // guidance line; anything else is plain information.
            UiEvent::Info(m) => match m.strip_prefix("noo ").map(|_| m.split_once(" — ")) {
                Some(Some((cmd, why))) => {
                    println!("  {}", ui::hint(cmd));
                    println!("  {}", ui::note(why));
                }
                Some(None) => println!("  {}", ui::hint(&m)),
                None => println!("  {m}"),
            },
            UiEvent::Success(m) => sub(Glyph::Ok, &m),
            UiEvent::Warning(m) => sub(Glyph::Warn, &m),
            // Step-level failures are part of the transcript (the wizard
            // continues), so they stay on stdout with the rest of the step.
            UiEvent::Error(m) => sub(Glyph::Err, &m),
            UiEvent::Progress(m) => {
                let mut last = LAST_PROGRESS.lock().unwrap_or_else(|e| e.into_inner());
                if *last != m {
                    *last = m.clone();
                    sub(Glyph::Step, &m);
                }
            }
            UiEvent::Dry(m) => sub(Glyph::Bullet, &format!("would {m}")),
            UiEvent::Line(m) => println!("{m}"),
            UiEvent::Note(m) => eprintln!("  {}", ui::muted(&m)),
        }
    }

    fn prompt(&self, req: &PromptRequest) -> String {
        match &req.kind {
            PromptKind::Text { default, secret, required } => {
                if !stdin_is_tty() {
                    // Never block on a pipe: with a default the Asker applies
                    // it; a required value with no default is a hard error.
                    if default.is_none() && *required {
                        fail_required(&req.label);
                    }
                    return String::new();
                }
                // A secret prompt must tell STORED apart from UNSET — the
                // old arm matched Some("") too, so every secret prompt
                // claimed a "[hidden default]" whether one existed or not,
                // and the operator re-pasted tokens on every reconfigure
                // (and suspected phantom keys) (first-contact finding #38).
                let suffix = match default {
                    Some(d) if !*secret && !d.is_empty() => format!(" [{d}]"),
                    Some(d) if *secret && !d.is_empty() => {
                        " [stored — enter keeps it, type to replace]".to_string()
                    }
                    _ => String::new(),
                };
                if *secret {
                    eprint!("  {}{}: ", req.label, suffix);
                    let _ = std::io::stderr().flush();
                    return read_line_secret().unwrap_or_default();
                }
                // Line-edited input
                // printed ^[[D and tab did nothing): cursor movement,
                // in-line editing, and filename tab-completion on every
                // text prompt. Falls back to the plain reader when the
                // editor cannot initialise (odd TTYs).
                read_line_edited(&format!("  {}{}: ", req.label, suffix))
                    .unwrap_or_else(|| {
                        eprint!("  {}{}: ", req.label, suffix);
                        let _ = std::io::stderr().flush();
                        read_line().unwrap_or_default()
                    })
            }
            PromptKind::Confirm { default } => {
                if !stdin_is_tty() {
                    return String::new(); // Asker → default, never blocks
                }
                let hint = if *default { "[Y/n]" } else { "[y/N]" };
                eprint!("  {} {hint}: ", req.label);
                let _ = std::io::stderr().flush();
                read_line().unwrap_or_default()
            }
        }
    }
}

fn fail_required(label: &str) -> ! {
    crate::ui::failed(
        &format!("'{label}' has no default and stdin is not a TTY — cannot prompt"),
        Some("run interactively, use --non-interactive with env defaults, or set the value in .env first"),
    );
    std::process::exit(1);
}

/// rustyline-backed single prompt: arrows/home/end editing + filename tab
/// completion. Returns None when the editor cannot run (fallback path).
pub(crate) fn read_line_edited(prompt: &str) -> Option<String> {
    use rustyline::completion::{Completer, FilenameCompleter, Pair};
    use rustyline::highlight::Highlighter;
    use rustyline::hint::Hinter;
    use rustyline::validate::Validator;
    use rustyline::{Editor, Helper};

    struct PathHelper(FilenameCompleter);
    impl Completer for PathHelper {
        type Candidate = Pair;
        fn complete(
            &self,
            line: &str,
            pos: usize,
            ctx: &rustyline::Context<'_>,
        ) -> rustyline::Result<(usize, Vec<Pair>)> {
            self.0.complete(line, pos, ctx)
        }
    }
    impl Hinter for PathHelper {
        type Hint = String;
    }
    impl Highlighter for PathHelper {}
    impl Validator for PathHelper {}
    impl Helper for PathHelper {}

    let mut ed: Editor<PathHelper, rustyline::history::DefaultHistory> = Editor::new().ok()?;
    ed.set_helper(Some(PathHelper(FilenameCompleter::new())));
    match ed.readline(prompt) {
        Ok(line) => Some(line.trim().to_string()),
        Err(rustyline::error::ReadlineError::Interrupted) => {
            // Preserve pre-editor semantics: an un-handled SIGINT killed
            // the process mid-read; the editor catches it, so re-raise the
            // conventional exit instead of silently answering "".
            std::process::exit(130);
        }
        Err(_) => Some(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records prompts and plays back canned answers — the Asker's contract
    /// (default application, required re-prompt, confirm parsing, choice
    /// range looping) tested with no terminal.
    struct FakeUi {
        answers: Mutex<Vec<String>>, // popped front-first
        prompts: Mutex<Vec<PromptRequest>>,
        notes: Mutex<Vec<String>>,
    }

    impl FakeUi {
        fn new(answers: &[&str]) -> Self {
            FakeUi {
                answers: Mutex::new(answers.iter().map(|s| s.to_string()).collect()),
                prompts: Mutex::new(Vec::new()),
                notes: Mutex::new(Vec::new()),
            }
        }
    }

    impl WizardUi for FakeUi {
        fn emit(&self, ev: UiEvent) {
            if let UiEvent::Note(n) = ev {
                self.notes.lock().unwrap().push(n);
            }
        }
        fn prompt(&self, req: &PromptRequest) -> String {
            self.prompts.lock().unwrap().push(req.clone());
            let mut a = self.answers.lock().unwrap();
            if a.is_empty() { String::new() } else { a.remove(0) }
        }
        fn inherit_stdio(&self) -> bool {
            false
        }
    }

    fn asker(ui: &FakeUi) -> Asker<'_> {
        Asker { non_interactive: false, ui }
    }

    #[test]
    fn ask_returns_typed_value() {
        let ui = FakeUi::new(&["hello"]);
        let v = asker(&ui).ask(&Prompt::new("Name").default("d"));
        assert_eq!(v, "hello");
    }

    #[test]
    fn ask_empty_takes_default() {
        let ui = FakeUi::new(&[""]);
        let v = asker(&ui).ask(&Prompt::new("Name").default("fallback"));
        assert_eq!(v, "fallback");
    }

    #[test]
    fn ask_required_reprompts_until_nonempty() {
        let ui = FakeUi::new(&["", "", "third"]);
        let v = asker(&ui).ask(&Prompt::new("Password").secret().required());
        assert_eq!(v, "third");
        assert_eq!(ui.prompts.lock().unwrap().len(), 3);
        assert_eq!(
            ui.notes.lock().unwrap().as_slice(),
            ["(a value is required)", "(a value is required)"]
        );
    }

    #[test]
    fn ask_non_interactive_never_prompts() {
        let ui = FakeUi::new(&["never used"]);
        let a = Asker { non_interactive: true, ui: &ui };
        assert_eq!(a.ask(&Prompt::new("X").default("d")), "d");
        assert_eq!(a.ask(&Prompt::new("Y")), "");
        assert!(ui.prompts.lock().unwrap().is_empty());
    }

    #[test]
    fn ask_carries_secret_and_default_in_request() {
        let ui = FakeUi::new(&["v"]);
        asker(&ui).ask(&Prompt::new("Token").default("t0").secret());
        let reqs = ui.prompts.lock().unwrap();
        assert_eq!(
            reqs[0].kind,
            PromptKind::Text { default: Some("t0".into()), secret: true, required: false }
        );
    }

    #[test]
    fn confirm_parses_yes_no_and_defaults() {
        let ui = FakeUi::new(&["y"]);
        assert!(asker(&ui).confirm("Proceed?", false));
        let ui = FakeUi::new(&["NO"]);
        assert!(!asker(&ui).confirm("Proceed?", true));
        let ui = FakeUi::new(&[""]);
        assert!(asker(&ui).confirm("Proceed?", true));
        let ui = FakeUi::new(&[""]);
        assert!(!asker(&ui).confirm("Proceed?", false));
    }

    #[test]
    fn confirm_loops_on_garbage_with_note() {
        let ui = FakeUi::new(&["maybe", "y"]);
        assert!(asker(&ui).confirm("Proceed?", false));
        assert_eq!(ui.notes.lock().unwrap().as_slice(), ["please answer y or n"]);
    }

    #[test]
    fn ask_choice_maps_number_and_default() {
        let ui = FakeUi::new(&["2"]);
        assert_eq!(asker(&ui).ask_choice("Pick", 1, 3, false), 2);
        // Empty answer → the numeric default string → parsed.
        let ui = FakeUi::new(&[""]);
        assert_eq!(asker(&ui).ask_choice("Pick", 3, 3, false), 3);
        // allow_zero accepts 0.
        let ui = FakeUi::new(&["0"]);
        assert_eq!(asker(&ui).ask_choice("Pick", 1, 3, true), 0);
    }
}

