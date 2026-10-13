// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo onboard --tui` — the native full-screen onboarding frontend
//! (ratatui + crossterm), replacing the Python Textual wizard for the TUI
//! path. A frontend ONLY: all step logic lives in steps.rs and runs
//! unchanged on a worker thread, talking to this UI through the `WizardUi`
//! seam (event.rs) — the Rust analogue of Python's StepRunner/WizardEvent
//! protocol.
//!
//! Layout:
//!   left   — the 8-step list with status glyphs (○ pending, ▶ active,
//!            ✓ done, ✗ failed)
//!   main   — scrolling step output (the same lines the console prints)
//!   bottom — input area: text / password / confirm / choice prompts
//!   footer — key hints
//!
//! Threading (mirrors tui_wizard.py's `@work(thread=True)` + threading.Event):
//!   worker thread: run_wizard(ctx) → blocks inside TuiUi::prompt on the
//!                  answer channel; sends UiEvents + Finished over `msgs`.
//!   main thread:   crossterm event loop + ratatui draw; answers prompts,
//!                  handles scroll and abort.
//!
//! Abort: q (when idle) / Esc / Ctrl-C opens a confirm modal; confirming
//! makes the worker's next prompt/emit unwind with `AbortPanic` (the
//! WizardAborted analogue), the terminal is restored, and the process exits
//! 130 without waiting on any in-flight subprocess.

use std::io::Write as _;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::Frame;

use super::event::{AbortPanic, PromptKind, PromptRequest, StepBoard, StepState, UiEvent, WizardUi};
use super::{build_ctx, drive, Skip, STEP_TITLES};
use crate::Globals;

pub(crate) struct TuiOptions {
    pub non_interactive: bool,
    pub dry_run: bool,
    pub reconfigure: bool,
    pub skip: Skip,
}

/// Worker → UI messages.
enum Msg {
    Event(UiEvent),
    Prompt(PromptRequest),
    /// Suspend the TUI, run this argv with the real terminal, resume.
    /// The exit code comes back on the answers channel as a string.
    RunCommand(Vec<String>),
    Finished(i32),
}

/// The channel-backed `WizardUi` handed to the worker thread.
pub(crate) struct TuiUi {
    msgs: Mutex<Sender<Msg>>,
    answers: Mutex<Receiver<String>>,
    aborted: AtomicBool,
}

impl TuiUi {
    fn abort_check(&self) {
        if self.aborted.load(Ordering::SeqCst) {
            std::panic::panic_any(AbortPanic);
        }
    }
}

impl WizardUi for TuiUi {
    fn emit(&self, ev: UiEvent) {
        self.abort_check();
        // A closed channel means the UI is gone — unwind like an abort.
        if self.msgs.lock().map(|tx| tx.send(Msg::Event(ev)).is_err()).unwrap_or(true) {
            std::panic::panic_any(AbortPanic);
        }
    }

    fn prompt(&self, req: &PromptRequest) -> String {
        self.abort_check();
        if self.msgs.lock().map(|tx| tx.send(Msg::Prompt(req.clone())).is_err()).unwrap_or(true) {
            std::panic::panic_any(AbortPanic);
        }
        let answer = self.answers.lock().ok().and_then(|rx| rx.recv().ok());
        self.abort_check();
        match answer {
            Some(a) => a,
            None => std::panic::panic_any(AbortPanic),
        }
    }

    /// The TUI owns the terminal: subprocess output is captured and forwarded
    /// as `Line` events, and sudo runs non-interactive (`-n`).
    fn inherit_stdio(&self) -> bool {
        false
    }

    /// Suspend/resume passthrough (the `$EDITOR`-from-a-TUI pattern): the
    /// event loop leaves the alternate screen, hands the terminal to the
    /// subprocess (sudo prompts and login URLs render normally), and
    /// re-enters ratatui when it exits.
    fn run_passthrough(&self, argv: &[String]) -> Option<i32> {
        self.abort_check();
        if self
            .msgs
            .lock()
            .map(|tx| tx.send(Msg::RunCommand(argv.to_vec())).is_err())
            .unwrap_or(true)
        {
            std::panic::panic_any(AbortPanic);
        }
        let answer = self.answers.lock().ok().and_then(|rx| rx.recv().ok());
        self.abort_check();
        match answer {
            Some(code) => code.parse::<i32>().ok(),
            None => std::panic::panic_any(AbortPanic),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// App state
// ─────────────────────────────────────────────────────────────────────────

struct LogLine {
    text: String,
    style: Style,
}

/// A pending prompt plus the input buffer being edited.
struct InputState {
    req: PromptRequest,
    buffer: String,
}

impl InputState {
    fn is_secret(&self) -> bool {
        matches!(self.req.kind, PromptKind::Text { secret: true, .. })
    }

    fn is_confirm(&self) -> bool {
        matches!(self.req.kind, PromptKind::Confirm { .. })
    }

    /// What the input line shows (secrets masked).
    fn display_value(&self) -> String {
        if self.is_secret() {
            "\u{2022}".repeat(self.buffer.chars().count())
        } else {
            self.buffer.clone()
        }
    }

    /// The hint rendered after the label.
    fn hint(&self) -> String {
        match &self.req.kind {
            PromptKind::Confirm { default } => {
                (if *default { " [Y/n]" } else { " [y/N]" }).to_string()
            }
            PromptKind::Text { default: Some(d), secret, .. } if !d.is_empty() => {
                if *secret {
                    " [hidden default]".to_string()
                } else {
                    format!(" [{d}]")
                }
            }
            _ => String::new(),
        }
    }
}

struct App {
    board: StepBoard,
    log: Vec<LogLine>,
    /// Manual scroll offset from the BOTTOM (0 = follow latest output).
    scroll_up: usize,
    input: Option<InputState>,
    confirm_abort: bool,
    finished: Option<i32>,
    working: String,
}

enum Action {
    None,
    Answer(String),
    AbortConfirmed,
    Exit(i32),
}

impl App {
    fn new() -> Self {
        App {
            board: StepBoard::new(&STEP_TITLES),
            log: Vec::new(),
            scroll_up: 0,
            input: None,
            confirm_abort: false,
            finished: None,
            working: "Working...".to_string(),
        }
    }

    fn push(&mut self, text: String, style: Style) {
        for part in text.split('\n') {
            self.log.push(LogLine { text: part.to_string(), style });
        }
    }

    /// Fold a worker message into the UI state.
    fn apply(&mut self, msg: Msg) {
        match msg {
            Msg::Event(ev) => {
                self.board.apply(&ev);
                match &ev {
                    UiEvent::StepStart { step, total, title } => {
                        self.push(String::new(), Style::default());
                        self.push(
                            format!("Step {step}/{total}: {title}"),
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                        );
                        self.working = format!("Running: {title}");
                    }
                    // Step closure is reflected in the board glyphs only.
                    UiEvent::StepDone { .. } => {}
                    UiEvent::Info(m) => self.push(format!("  {m}"), Style::default()),
                    UiEvent::Success(m) => {
                        self.push(format!("  ✓ {m}"), Style::default().fg(Color::Green))
                    }
                    UiEvent::Warning(m) => {
                        self.push(format!("  ! {m}"), Style::default().fg(Color::Yellow))
                    }
                    UiEvent::Error(m) => {
                        self.push(format!("  ✗ {m}"), Style::default().fg(Color::Red))
                    }
                    UiEvent::Progress(m) => {
                        self.working = m.clone();
                        self.push(format!("  … {m}"), Style::default().fg(Color::Cyan));
                    }
                    UiEvent::Dry(m) => self.push(
                        format!("  [dry-run] would: {m}"),
                        Style::default().fg(Color::Magenta),
                    ),
                    UiEvent::Line(m) => self.push(m.clone(), Style::default()),
                    UiEvent::Note(m) => {
                        self.push(format!("  {m}"), Style::default().fg(Color::Yellow))
                    }
                }
            }
            Msg::Prompt(req) => {
                self.input = Some(InputState { req, buffer: String::new() });
            }
            // Handled by the event loop BEFORE apply (needs the terminal);
            // a RunCommand that reaches apply is a bug, but must not crash.
            Msg::RunCommand(_) => {}
            Msg::Finished(code) => {
                self.board.close_current();
                self.finished = Some(code);
                self.push(String::new(), Style::default());
                self.push(
                    "Wizard finished — press Enter or q to close.".to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                );
            }
        }
    }

    /// Handle a key press; returns what the event loop should do.
    fn handle_key(&mut self, key: KeyEvent) -> Action {
        // Ctrl-C always requests an abort (confirm first), like the Textual TUI.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            if self.finished.is_some() {
                return Action::Exit(self.finished.unwrap_or(130));
            }
            self.confirm_abort = true;
            return Action::None;
        }

        if self.confirm_abort {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => return Action::AbortConfirmed,
                _ => {
                    self.confirm_abort = false;
                    return Action::None;
                }
            }
        }

        if let Some(code) = self.finished {
            return match key.code {
                KeyCode::Enter | KeyCode::Char('q') | KeyCode::Esc => Action::Exit(code),
                _ => self.handle_scroll(key),
            };
        }

        if self.input.is_some() {
            return self.handle_prompt_key(key);
        }

        // Idle (a step is working): q / Esc ask to abort; arrows scroll.
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.confirm_abort = true;
                Action::None
            }
            _ => self.handle_scroll(key),
        }
    }

    fn handle_prompt_key(&mut self, key: KeyEvent) -> Action {
        let input = self.input.as_mut().expect("prompt key without input");
        if input.is_confirm() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => return self.submit("y".to_string()),
                KeyCode::Char('n') | KeyCode::Char('N') => return self.submit("n".to_string()),
                KeyCode::Enter => return self.submit(String::new()),
                KeyCode::Esc => {
                    self.confirm_abort = true;
                    return Action::None;
                }
                _ => return self.handle_scroll(key),
            }
        }
        match key.code {
            KeyCode::Enter => {
                let value = input.buffer.clone();
                self.submit(value)
            }
            KeyCode::Esc => {
                self.confirm_abort = true;
                Action::None
            }
            KeyCode::Backspace => {
                input.buffer.pop();
                Action::None
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                input.buffer.clear();
                Action::None
            }
            KeyCode::Char(c) => {
                input.buffer.push(c);
                Action::None
            }
            KeyCode::PageUp | KeyCode::PageDown => self.handle_scroll(key),
            _ => Action::None,
        }
    }

    /// Echo + hand the answer back to the worker.
    fn submit(&mut self, value: String) -> Action {
        let input = self.input.take().expect("submit without input");
        let echo = if value.is_empty() {
            "(default)".to_string()
        } else if input.is_secret() {
            "********".to_string()
        } else {
            value.clone()
        };
        self.push(
            format!("  → {}: {echo}", input.req.label),
            Style::default().fg(Color::DarkGray),
        );
        self.scroll_up = 0;
        Action::Answer(value)
    }

    fn handle_scroll(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Up => self.scroll_up = self.scroll_up.saturating_add(1),
            KeyCode::Down => self.scroll_up = self.scroll_up.saturating_sub(1),
            KeyCode::PageUp => self.scroll_up = self.scroll_up.saturating_add(10),
            KeyCode::PageDown => self.scroll_up = self.scroll_up.saturating_sub(10),
            KeyCode::Home => self.scroll_up = usize::MAX / 2,
            KeyCode::End => self.scroll_up = 0,
            _ => {}
        }
        Action::None
    }

    // ── rendering ────────────────────────────────────────────────────────

    fn render(&mut self, f: &mut Frame) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Min(20)])
            .split(f.area());

        self.render_steps(f, cols[0]);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(4), Constraint::Length(1)])
            .split(cols[1]);

        self.render_log(f, rows[0]);
        self.render_input(f, rows[1]);
        self.render_footer(f, rows[2]);

        if self.confirm_abort {
            self.render_abort_modal(f);
        }
    }

    fn render_steps(&self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .board
            .states
            .iter()
            .zip(&self.board.titles)
            .enumerate()
            .map(|(i, (state, title))| {
                let style = match state {
                    StepState::Pending => Style::default().fg(Color::DarkGray),
                    StepState::Active => Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    StepState::Done => Style::default().fg(Color::Green),
                    StepState::Failed => Style::default().fg(Color::Red),
                };
                ListItem::new(Line::from(Span::styled(
                    format!(" {} {}. {}", state.glyph(), i + 1, title),
                    style,
                )))
            })
            .collect();
        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Noomesh Setup ")
                .title_style(Style::default().add_modifier(Modifier::BOLD)),
        );
        f.render_widget(list, area);
    }

    fn render_log(&mut self, f: &mut Frame, area: Rect) {
        let inner_h = area.height.saturating_sub(2) as usize;
        let total = self.log.len();
        let max_up = total.saturating_sub(inner_h);
        if self.scroll_up > max_up {
            self.scroll_up = max_up;
        }
        let offset = max_up - self.scroll_up;
        let lines: Vec<Line> = self
            .log
            .iter()
            .skip(offset)
            .take(inner_h)
            .map(|l| Line::from(Span::styled(l.text.clone(), l.style)))
            .collect();
        let title = if self.scroll_up > 0 {
            format!(" Output (scrolled ↑{}) ", self.scroll_up)
        } else {
            " Output ".to_string()
        };
        let para = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(para, area);
    }

    fn render_input(&self, f: &mut Frame, area: Rect) {
        let (title, lines, style) = if let Some(input) = &self.input {
            let label = format!("{}{}", input.req.label, input.hint());
            let value = if input.is_confirm() {
                "press y / n, or Enter for the default".to_string()
            } else {
                format!("> {}\u{258f}", input.display_value())
            };
            (
                " Input required ",
                vec![Line::from(label), Line::from(value)],
                Style::default().fg(Color::Cyan),
            )
        } else if self.finished.is_some() {
            (
                " Done ",
                vec![Line::from("Press Enter to close.")],
                Style::default().fg(Color::Green),
            )
        } else {
            (
                " Status ",
                vec![Line::from(Span::styled(
                    self.working.clone(),
                    Style::default().fg(Color::DarkGray),
                ))],
                Style::default().fg(Color::DarkGray),
            )
        };
        let para = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title).border_style(style));
        f.render_widget(para, area);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let hint = if self.confirm_abort {
            "y confirm abort · any other key cancel"
        } else if self.input.is_some() {
            "Enter submit · Esc abort · PgUp/PgDn scroll"
        } else if self.finished.is_some() {
            "Enter/q close · ↑/↓ PgUp/PgDn scroll"
        } else {
            "q/Esc abort · ↑/↓ PgUp/PgDn scroll"
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {hint}"),
                Style::default().fg(Color::DarkGray),
            ))),
            area,
        );
    }

    fn render_abort_modal(&self, f: &mut Frame) {
        let area = f.area();
        let w = 46.min(area.width);
        let h = 5.min(area.height);
        let modal = Rect {
            x: area.x + (area.width.saturating_sub(w)) / 2,
            y: area.y + (area.height.saturating_sub(h)) / 2,
            width: w,
            height: h,
        };
        f.render_widget(Clear, modal);
        let para = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Abort setup? (y/N)",
                Style::default().add_modifier(Modifier::BOLD),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Confirm ")
                .border_style(Style::default().fg(Color::Red)),
        );
        f.render_widget(para, modal);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────

pub(crate) fn run(g: &Globals, opts: TuiOptions) -> i32 {
    let (msg_tx, msg_rx) = channel::<Msg>();
    let (ans_tx, ans_rx) = channel::<String>();
    let ui = Arc::new(TuiUi {
        msgs: Mutex::new(msg_tx),
        answers: Mutex::new(ans_rx),
        aborted: AtomicBool::new(false),
    });

    // Silence the default panic printer for our controlled AbortPanic unwind
    // (it would scribble over the alternate screen); real panics still print.
    let prev_hook = std::panic::take_hook();
    let hook_prev = Arc::new(prev_hook);
    let hook_prev2 = hook_prev.clone();
    std::panic::set_hook(Box::new(move |info| {
        if info.payload().downcast_ref::<AbortPanic>().is_none() {
            hook_prev2(info);
        }
    }));

    // Worker thread: the unchanged wizard flow over the TuiUi frontend.
    let worker_ui = ui.clone();
    let g_owned = g.clone();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let ui_ref: &dyn WizardUi = worker_ui.as_ref();
            let mut ctx = build_ctx(
                &g_owned,
                ui_ref,
                opts.non_interactive,
                opts.dry_run,
                opts.skip.clone(),
            );
            drive(&mut ctx, opts.reconfigure)
        }));
        match result {
            Ok(code) => {
                if let Ok(tx) = worker_ui.msgs.lock() {
                    let _ = tx.send(Msg::Finished(code));
                }
            }
            Err(payload) if payload.downcast_ref::<AbortPanic>().is_some() => {}
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "wizard worker panicked".to_string());
                if let Ok(tx) = worker_ui.msgs.lock() {
                    let _ = tx.send(Msg::Event(UiEvent::Error(format!("wizard crashed: {msg}"))));
                    let _ = tx.send(Msg::Finished(1));
                }
            }
        }
    });

    let code = run_event_loop(msg_rx, ans_tx, ui.clone());

    // Restore the default panic hook.
    let _ = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| hook_prev(info)));

    match code {
        Ok(c) => {
            let _ = worker.join();
            c
        }
        Err(()) => {
            // Aborted: the worker may be blocked in a subprocess — exit now
            // (Textual's app.exit() analogue); 130 = interrupted.
            eprintln!("Setup aborted.");
            let _ = std::io::stderr().flush();
            std::process::exit(130);
        }
    }
}

/// Terminal session + event loop. `Ok(code)` = finished, `Err(())` = aborted.
fn run_event_loop(msg_rx: Receiver<Msg>, ans_tx: Sender<String>, ui: Arc<TuiUi>) -> Result<i32, ()> {
    let mut terminal = ratatui::init();
    let mut app = App::new();
    let outcome = loop {
        // Drain worker messages (scroll_up == 0 keeps following the tail).
        while let Ok(msg) = msg_rx.try_recv() {
            if let Msg::RunCommand(argv) = msg {
                // Passthrough: leave the alternate screen, hand the real
                // terminal to the subprocess (sudo password prompts and
                // `tailscale up` login URLs render normally), re-enter
                // ratatui when it exits. The worker thread is blocked on
                // the answers channel until the code is sent.
                ratatui::restore();
                println!();
                println!("\u{2500}\u{2500} wizard passthrough: {} \u{2500}\u{2500}", argv.join(" "));
                let code = match argv.split_first() {
                    Some((cmd, args)) => std::process::Command::new(cmd)
                        .args(args)
                        .status()
                        .ok()
                        .and_then(|st| st.code())
                        .unwrap_or(-1),
                    None => -1,
                };
                println!("\u{2500}\u{2500} returning to the wizard \u{2500}\u{2500}");
                terminal = ratatui::init();
                let _ = ans_tx.send(code.to_string());
                continue;
            }
            app.apply(msg);
        }

        if terminal.draw(|f| app.render(f)).is_err() {
            break Err(());
        }

        match crossterm::event::poll(Duration::from_millis(50)) {
            Ok(true) => {
                if let Ok(Event::Key(key)) = crossterm::event::read() {
                    if !key.is_press() {
                        continue;
                    }
                    match app.handle_key(key) {
                        Action::None => {}
                        Action::Answer(v) => {
                            let _ = ans_tx.send(v);
                        }
                        Action::AbortConfirmed => {
                            ui.aborted.store(true, Ordering::SeqCst);
                            // Unblock a worker waiting inside prompt().
                            let _ = ans_tx.send(String::new());
                            break Err(());
                        }
                        Action::Exit(code) => break Ok(code),
                    }
                }
            }
            Ok(false) => {}
            Err(_) => break Err(()),
        }
    };
    ratatui::restore();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn text_prompt(label: &str, default: Option<&str>, secret: bool) -> PromptRequest {
        PromptRequest {
            label: label.to_string(),
            kind: PromptKind::Text {
                default: default.map(|s| s.to_string()),
                secret,
                required: false,
            },
        }
    }

    #[test]
    fn typing_and_submitting_a_text_prompt_answers() {
        let mut app = App::new();
        app.apply(Msg::Prompt(text_prompt("Node ID", Some("host-1"), false)));
        assert!(app.input.is_some());
        for c in ['a', 'b', 'c'] {
            assert!(matches!(app.handle_key(key(KeyCode::Char(c))), Action::None));
        }
        match app.handle_key(key(KeyCode::Enter)) {
            Action::Answer(v) => assert_eq!(v, "abc"),
            _ => panic!("expected Answer"),
        }
        assert!(app.input.is_none());
    }

    #[test]
    fn empty_submit_sends_empty_answer_for_default() {
        let mut app = App::new();
        app.apply(Msg::Prompt(text_prompt("Node ID", Some("host-1"), false)));
        match app.handle_key(key(KeyCode::Enter)) {
            Action::Answer(v) => assert_eq!(v, ""),
            _ => panic!("expected Answer"),
        }
    }

    #[test]
    fn secret_input_is_masked_in_display_and_echo() {
        let mut app = App::new();
        app.apply(Msg::Prompt(text_prompt("Password", None, true)));
        for c in "hunter2".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.input.as_ref().unwrap().display_value(), "•••••••");
        match app.handle_key(key(KeyCode::Enter)) {
            Action::Answer(v) => assert_eq!(v, "hunter2"),
            _ => panic!("expected Answer"),
        }
        // The echoed log line never contains the secret.
        assert!(app.log.iter().all(|l| !l.text.contains("hunter2")));
        assert!(app.log.iter().any(|l| l.text.contains("********")));
    }

    #[test]
    fn confirm_prompt_takes_y_n_and_enter_default() {
        let confirm = PromptRequest {
            label: "Proceed?".to_string(),
            kind: PromptKind::Confirm { default: true },
        };
        let mut app = App::new();
        app.apply(Msg::Prompt(confirm.clone()));
        match app.handle_key(key(KeyCode::Char('n'))) {
            Action::Answer(v) => assert_eq!(v, "n"),
            _ => panic!("expected Answer"),
        }
        let mut app = App::new();
        app.apply(Msg::Prompt(confirm));
        match app.handle_key(key(KeyCode::Enter)) {
            Action::Answer(v) => assert_eq!(v, ""),
            _ => panic!("expected Answer(default)"),
        }
    }

    #[test]
    fn esc_opens_abort_modal_then_y_confirms_other_cancels() {
        let mut app = App::new();
        assert!(matches!(app.handle_key(key(KeyCode::Esc)), Action::None));
        assert!(app.confirm_abort);
        // Any non-y key cancels.
        assert!(matches!(app.handle_key(key(KeyCode::Char('x'))), Action::None));
        assert!(!app.confirm_abort);
        // q re-opens; y confirms.
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.confirm_abort);
        assert!(matches!(app.handle_key(key(KeyCode::Char('y'))), Action::AbortConfirmed));
    }

    #[test]
    fn q_types_into_a_text_prompt_instead_of_aborting() {
        let mut app = App::new();
        app.apply(Msg::Prompt(text_prompt("Name", None, false)));
        app.handle_key(key(KeyCode::Char('q')));
        assert!(!app.confirm_abort);
        assert_eq!(app.input.as_ref().unwrap().buffer, "q");
    }

    #[test]
    fn finished_state_exits_on_enter_with_worker_code() {
        let mut app = App::new();
        app.apply(Msg::Finished(0));
        match app.handle_key(key(KeyCode::Enter)) {
            Action::Exit(0) => {}
            _ => panic!("expected Exit(0)"),
        }
    }

    #[test]
    fn events_land_in_log_and_step_board() {
        let mut app = App::new();
        app.apply(Msg::Event(UiEvent::StepStart {
            step: 1,
            total: 8,
            title: STEP_TITLES[0].to_string(),
        }));
        app.apply(Msg::Event(UiEvent::Success("docker: ok".to_string())));
        assert_eq!(app.board.states[0], StepState::Active);
        assert!(app.log.iter().any(|l| l.text.contains("Step 1/8")));
        assert!(app.log.iter().any(|l| l.text.contains("✓ docker: ok")));
    }

    #[test]
    fn multiline_line_events_split() {
        let mut app = App::new();
        app.apply(Msg::Event(UiEvent::Line("a\nb".to_string())));
        let texts: Vec<_> = app.log.iter().map(|l| l.text.as_str()).collect();
        assert!(texts.contains(&"a") && texts.contains(&"b"));
    }

    #[test]
    fn prompt_hints_render_default_and_confirm_forms() {
        let i = InputState { req: text_prompt("X", Some("d1"), false), buffer: String::new() };
        assert_eq!(i.hint(), " [d1]");
        let i = InputState { req: text_prompt("X", Some("s"), true), buffer: String::new() };
        assert_eq!(i.hint(), " [hidden default]");
        let i = InputState {
            req: PromptRequest {
                label: "P?".into(),
                kind: PromptKind::Confirm { default: false },
            },
            buffer: String::new(),
        };
        assert_eq!(i.hint(), " [y/N]");
    }
}
