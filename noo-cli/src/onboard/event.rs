// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Wizard event/prompt protocol — the Rust mirror of Python's `StepRunner`
//! (`src/noomesh/onboard/runner.py`): steps emit [`UiEvent`]s and block on
//! [`WizardUi::prompt`] answers, so the SAME step code drives any frontend.
//!
//! Frontends implement [`WizardUi`]:
//!   - `PlainUi` (prompt.rs) — the classic console path. Its output/prompt
//!     behaviour is byte-identical to the pre-abstraction wizard.
//!   - `TuiUi` (tui.rs) — channels events to a ratatui event loop and blocks
//!     prompts on an answer channel (the `threading.Event` analogue).
//!   - a future web frontend (WP-W2) can implement the same trait over SSE.
//!
//! Abort contract: only interactive frontends abort. When the user confirms
//! an abort, the frontend makes the NEXT `emit`/`prompt` call unwind the
//! worker thread via `panic_any(AbortPanic)` — the same shape as Python's
//! `WizardAborted` exception. The plain path never aborts this way (Ctrl-C is
//! a plain SIGINT there), so step code needs no `Result` plumbing.

/// One wizard output event. Text payloads carry NO prefix/indent — each
/// frontend renders its own glyphs (the plain frontend reproduces the
/// historical `  ✓ …` console format exactly).
#[derive(Debug, Clone, PartialEq)]
pub enum UiEvent {
    /// A step is starting (1-based `step` of `total`).
    StepStart { step: u8, total: u8, title: String },
    /// A step finished (emitted by `Ctx::pause`). The web frontend forwards
    /// this as its `step_done` SSE event; the console prints nothing.
    StepDone { step: u8, ok: bool },
    Info(String),
    Success(String),
    Warning(String),
    Error(String),
    Progress(String),
    /// Dry-run "would do" line.
    Dry(String),
    /// Raw line, printed verbatim by the plain frontend (summary blocks,
    /// forwarded subprocess output). May contain embedded newlines.
    Line(String),
    /// Prompt-side hint ("please answer y or n") — stderr on the plain path.
    Note(String),
}

/// What kind of answer a prompt wants.
#[derive(Debug, Clone, PartialEq)]
pub enum PromptKind {
    /// Free text. `secret` masks input; `required` means an empty answer with
    /// no default is not acceptable (the Asker re-prompts).
    Text { default: Option<String>, secret: bool, required: bool },
    /// Yes/no. The frontend returns "y"/"n" (or "" for the default).
    Confirm { default: bool },
}

/// A single prompt to the user. The frontend returns the raw answer string;
/// "" means "take the default" (the [`super::prompt::Asker`] applies it).
#[derive(Debug, Clone, PartialEq)]
pub struct PromptRequest {
    pub label: String,
    pub kind: PromptKind,
}

/// Panic payload used to unwind the wizard worker thread on user abort
/// (caught by the frontend; never crosses the process boundary).
pub struct AbortPanic;

/// A wizard frontend. `Send + Sync` so streamed-subprocess reader threads can
/// forward output lines through the same sink.
pub trait WizardUi: Send + Sync {
    fn emit(&self, ev: UiEvent);
    /// Present a prompt and block until the user answers. Returns the raw
    /// answer ("" = take the default). May unwind with [`AbortPanic`].
    fn prompt(&self, req: &PromptRequest) -> String;
    /// True when steps may hand the real terminal to subprocesses (inherited
    /// stdio: `docker login`, streamed compose builds, sudo password prompts).
    /// Full-screen frontends return false — output is captured and forwarded
    /// as [`UiEvent::Line`]s instead, and sudo runs non-interactive (`-n`).
    fn inherit_stdio(&self) -> bool {
        true
    }
    /// Can an invalid choice be re-presented? True for frontends with their
    /// own input surface (TUI, web); the console returns `stdin_is_tty()` so
    /// a pipe can never hang in the choice loop.
    fn can_reprompt(&self) -> bool {
        true
    }
    /// Block until the user advances past a finished step (the web wizard's
    /// per-step Next button). Default: no pause (console, TUI).
    fn wait_next(&self, _step: u8, _total: u8) {}

    /// Run an interactive subprocess with the REAL terminal (sudo prompts,
    /// `tailscale up` login flows). Returns the exit code, or None when
    /// this frontend has no terminal to hand over (web) — callers fall
    /// back to printing the manual command. The console runs it directly;
    /// the TUI suspends the alternate screen, runs it, and resumes —
    /// which is what makes `noo onboard --tui` able to install/join
    /// Tailscale instead of dead-ending into manual instructions.
    fn run_passthrough(&self, _argv: &[String]) -> Option<i32> {
        None
    }

    /// Show ONE secret value to the person running the wizard, and report
    /// whether it was actually shown (the backup passphrases, which
    /// have no consumer on this box and must be carried off it by a human).
    ///
    /// The default is `false` — "this frontend cannot show a secret" — and it
    /// is a refusal, not a silent no-op, precisely so that a frontend which
    /// displays nothing cannot be mistaken for one that handed the value
    /// over. The caller falls back to printing the `noo security secrets
    /// reveal <NAME>` command.
    ///
    /// Only [`super::prompt::PlainUi`] overrides it. The TUI draws on an
    /// alternate screen that redraws over anything printed into it, and the
    /// web wizard's events cross an HTTP response — the key to the key goes
    /// on neither. Deliberately NOT a [`UiEvent`]: an event is broadcast to
    /// whatever frontend is attached, and broadcast is the one thing this
    /// value must never be.
    fn reveal_secret(&self, _name: &str, _value: &str) -> bool {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Step-status model (frontend-side): folds the event stream into per-step
// states for the TUI's step list. Pure data — unit-testable without a
// terminal.
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Pending,
    Active,
    /// Completed with no Error events.
    Done,
    /// Completed, but at least one Error event fired during it.
    Failed,
}

impl StepState {
    pub fn glyph(self) -> &'static str {
        match self {
            StepState::Pending => "○",
            StepState::Active => "▶",
            StepState::Done => "✓",
            StepState::Failed => "✗",
        }
    }
}

/// Per-step status board: seeded with the known step titles, updated by
/// folding [`UiEvent`]s.
pub struct StepBoard {
    pub titles: Vec<String>,
    pub states: Vec<StepState>,
    /// 1-based index of the active step (0 = none started yet).
    pub current: usize,
    current_errored: bool,
}

impl StepBoard {
    pub fn new(titles: &[&str]) -> Self {
        StepBoard {
            titles: titles.iter().map(|s| s.to_string()).collect(),
            states: vec![StepState::Pending; titles.len()],
            current: 0,
            current_errored: false,
        }
    }

    /// Fold one event into the board.
    pub fn apply(&mut self, ev: &UiEvent) {
        match ev {
            UiEvent::StepStart { step, title, .. } => {
                self.close_current();
                let idx = (*step as usize).saturating_sub(1);
                if idx >= self.states.len() {
                    self.titles.resize(idx + 1, String::new());
                    self.states.resize(idx + 1, StepState::Pending);
                }
                if !title.is_empty() {
                    self.titles[idx] = title.clone();
                }
                self.states[idx] = StepState::Active;
                self.current = idx + 1;
                self.current_errored = false;
            }
            UiEvent::StepDone { step, ok } => {
                let idx = (*step as usize).saturating_sub(1);
                if idx < self.states.len() {
                    self.states[idx] = if *ok && !self.current_errored {
                        StepState::Done
                    } else {
                        StepState::Failed
                    };
                    if self.current == idx + 1 {
                        self.current = 0;
                        self.current_errored = false;
                    }
                }
            }
            UiEvent::Error(_) => self.current_errored = true,
            _ => {}
        }
    }

    /// Close the active step (wizard finished or aborted mid-step).
    pub fn close_current(&mut self) {
        if self.current > 0 {
            let idx = self.current - 1;
            self.states[idx] = if self.current_errored { StepState::Failed } else { StepState::Done };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key to the key must not be broadcast. `reveal_secret` defaults to
    /// a REFUSAL, and exactly one frontend — the plain console, which has a
    /// private terminal — is allowed to override it. The TUI redraws over
    /// anything printed into it; the web wizard's output crosses an HTTP
    /// response. Asserted against the sources, because the property is "no
    /// other impl exists", and a new frontend that added one would pass every
    /// behavioural test in the suite.
    #[test]
    fn only_the_plain_console_may_show_a_secret() {
        let impls: &[(&str, &str)] = &[
            ("prompt.rs", include_str!("prompt.rs")),
            ("tui.rs", include_str!("tui.rs")),
            ("web.rs", include_str!("web.rs")),
        ];
        let overriding: Vec<&str> = impls
            .iter()
            .filter(|(_, src)| src.contains("fn reveal_secret("))
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(
            overriding,
            vec!["prompt.rs"],
            "a frontend other than the plain console overrides reveal_secret"
        );
    }

    fn start(step: u8, title: &str) -> UiEvent {
        UiEvent::StepStart { step, total: 8, title: title.to_string(), }
    }

    #[test]
    fn board_progresses_pending_active_done() {
        let mut b = StepBoard::new(&["One", "Two", "Three"]);
        assert_eq!(b.states, vec![StepState::Pending; 3]);

        b.apply(&start(1, "One"));
        assert_eq!(b.states[0], StepState::Active);
        assert_eq!(b.current, 1);

        b.apply(&UiEvent::Success("ok".into()));
        b.apply(&start(2, "Two"));
        assert_eq!(b.states[0], StepState::Done);
        assert_eq!(b.states[1], StepState::Active);
        assert_eq!(b.states[2], StepState::Pending);
    }

    #[test]
    fn board_marks_errored_step_failed_on_next_start() {
        let mut b = StepBoard::new(&["One", "Two"]);
        b.apply(&start(1, "One"));
        b.apply(&UiEvent::Error("boom".into()));
        // Warnings/infos after the error don't clear the failure.
        b.apply(&UiEvent::Warning("meh".into()));
        b.apply(&start(2, "Two"));
        assert_eq!(b.states[0], StepState::Failed);
        assert_eq!(b.states[1], StepState::Active);
    }

    #[test]
    fn close_current_finishes_the_last_step() {
        let mut b = StepBoard::new(&["One", "Two"]);
        b.apply(&start(1, "One"));
        b.apply(&start(2, "Two"));
        b.close_current();
        assert_eq!(b.states, vec![StepState::Done, StepState::Done]);

        let mut b = StepBoard::new(&["One"]);
        b.apply(&start(1, "One"));
        b.apply(&UiEvent::Error("x".into()));
        b.close_current();
        assert_eq!(b.states[0], StepState::Failed);
    }

    #[test]
    fn error_reset_per_step() {
        let mut b = StepBoard::new(&["One", "Two"]);
        b.apply(&start(1, "One"));
        b.apply(&UiEvent::Error("x".into()));
        b.apply(&start(2, "Two"));
        b.close_current();
        // Step 2 had no error — Done even though step 1 failed.
        assert_eq!(b.states, vec![StepState::Failed, StepState::Done]);
    }

    #[test]
    fn step_done_event_closes_the_step() {
        let mut b = StepBoard::new(&["One", "Two"]);
        b.apply(&start(1, "One"));
        b.apply(&UiEvent::StepDone { step: 1, ok: true });
        assert_eq!(b.states[0], StepState::Done);
        assert_eq!(b.current, 0);
        // A step that errored closes as Failed even with ok=true.
        b.apply(&start(2, "Two"));
        b.apply(&UiEvent::Error("boom".into()));
        b.apply(&UiEvent::StepDone { step: 2, ok: true });
        assert_eq!(b.states[1], StepState::Failed);
    }

    #[test]
    fn step_start_beyond_seed_grows_the_board() {
        let mut b = StepBoard::new(&["One"]);
        b.apply(&start(3, "Surprise"));
        assert_eq!(b.states.len(), 3);
        assert_eq!(b.states[2], StepState::Active);
        assert_eq!(b.titles[2], "Surprise");
    }

    #[test]
    fn glyphs() {
        assert_eq!(StepState::Pending.glyph(), "○");
        assert_eq!(StepState::Active.glyph(), "▶");
        assert_eq!(StepState::Done.glyph(), "✓");
        assert_eq!(StepState::Failed.glyph(), "✗");
    }
}
